"""
==============================================================================
 train.py
 SentinalFlow AI — Anomaly Detection Training Pipeline
 Author  : Expert AI Security Engineer
 Version : 1.0.0

 Purpose
 -------
 Ingests the synthetic banking telemetry dataset produced by mock_generator.py,
 applies domain-aware risk-footprint feature engineering across all categorical
 columns, trains an unsupervised Isolation Forest anomaly detector, evaluates
 its performance against ground-truth labels, and serialises both the trained
 model and the encoding artefacts for downstream inference.

 Pipeline Stages
 ---------------
 1. Data Ingestion & Validation       -- load CSV, enforce schema, type-cast
 2. Categorical Risk Encoding         -- manually-authored risk-footprint maps
    a. actor_role       -> ordinal risk score [1-10]
    b. target_resource  -> ordinal criticality score [1-10]
    c. action_executed  -> ordinal danger score [1-10]
 3. Continuous Feature Isolation      -- execution_time_delta, data_volume_kb,
                                        temporal_hour (raw + engineered)
 4. Feature Matrix Assembly & Scaling -- StandardScaler on all features
 5. Isolation Forest Training          -- contamination = 0.005 (50/10 050)
 6. Prediction Mapping                 -- IsoForest: -1 -> 1 (anomaly),
                                                      1 -> 0 (normal)
 7. Evaluation                         -- sklearn classification_report +
                                         confusion matrix + per-class AUC
 8. Artefact Serialisation             -- sentinel_model.pkl  (pipeline)
                                         feature_mappings.joblib (encoders)

 Output Directory
 ----------------
 ./sentinel_artefacts/
     sentinel_model.pkl          -- full sklearn Pipeline (scaler + IsoForest)
     feature_mappings.joblib     -- dict containing all encoding maps + scaler
                                    params for external reference

==============================================================================
"""

from __future__ import annotations

import os
import sys
import time
import logging
import warnings
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score,
)
import joblib

# Suppress sklearn version-mismatch FutureWarnings in production
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s  [%(levelname)-8s]  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("sentinalflow.train")

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------

BASE_DIR: Path = Path(__file__).resolve().parent
DATASET_PATH: Path = BASE_DIR / "banking_telemetry_dataset.csv"
ARTEFACT_DIR: Path = BASE_DIR / "sentinel_artefacts"
MODEL_PATH: Path = ARTEFACT_DIR / "sentinel_model.pkl"
MAPPINGS_PATH: Path = ARTEFACT_DIR / "feature_mappings.joblib"

# ---------------------------------------------------------------------------
# Hyper-parameters
# ---------------------------------------------------------------------------

RANDOM_SEED: int = 42
# contamination = 50 anomalies / 10 050 total ~= 0.004975 -> rounded to 0.005
CONTAMINATION: float = 0.005
N_ESTIMATORS: int = 200          # more trees -> more stable anomaly scores
MAX_SAMPLES: str = "auto"        # default: min(256, n_samples)
MAX_FEATURES: float = 1.0        # fraction of features per tree
BOOTSTRAP: bool = False          # IsoForest paper recommends no bootstrap

# ---------------------------------------------------------------------------
# Schema Constants
# ---------------------------------------------------------------------------

DROP_COLUMNS: List[str] = [
    "event_id",
    "timestamp",
    "threat_vector",
    "actor_id",
    "associated_ticket_id",
]

CATEGORICAL_COLUMNS: List[str] = [
    "actor_role",
    "target_resource",
    "action_executed",
]

CONTINUOUS_COLUMNS: List[str] = [
    "execution_time_delta",
    "data_volume_kb",
    "temporal_hour",
]

LABEL_COLUMN: str = "is_anomaly"

# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 1 -- RISK-FOOTPRINT ENCODING DICTIONARIES
# ============================================================================
# Design Rationale
# ----------------
# Each categorical value is mapped to an ordinal integer [1, 10] where:
#   1  = lowest observable risk in baseline banking operations
#   10 = highest attacker-controlled or inherently privileged risk footprint
#
# These scores are domain-authored by a threat intelligence practitioner and
# encode semantic knowledge that a pure frequency encoder would miss -- e.g.,
# an "intern_developer" acting on "libcrypto-core" should surface as a
# compound high-risk signal even before the continuous features are examined.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 1a. actor_role -> Risk Score [1-10]
#     Reasoning:
#       Low-privilege read-only analysts sit at 1-2.
#       Automated service accounts and external connectors sit at 5-7.
#       Privileged DB admins, unverified bots, and external fintech partners
#       that can execute DDL or bulk data extraction sit at 8-10.
# ---------------------------------------------------------------------------

ACTOR_ROLE_RISK_MAP: Dict[str, int] = {
    # --- Normal Baseline Roles (low-medium risk) ---
    "analyst"                    : 1,   # read-only, low blast radius
    "compliance_officer"         : 2,   # read + flag, controlled scope
    "product_manager"            : 2,   # no system-level access
    "business_analyst"           : 2,   # reporting-only persona
    "support_engineer"           : 3,   # limited write on customer records
    "qa_engineer"                : 3,   # CI/CD read + test execution
    "network_engineer"           : 4,   # infra-level but not data-plane
    "data_engineer"              : 4,   # pipeline builder, data access
    "developer"                  : 4,   # code write, bounded by PR process
    "operations_engineer"        : 5,   # deployment + ops runbooks

    # --- Threat Vector Roles (elevated risk) ---
    # TV2 -- Poisoned CI/CD: low-privilege actors touching crypto code
    "intern_developer"           : 7,   # low seniority + crypto access = high risk
    "contractor_developer"       : 7,   # untrusted third-party + code write
    "build_bot_unverified"       : 8,   # unverified automation = supply chain risk

    # TV1 -- Fintech API Abuse: external data-plane actors
    "fintech_partner"            : 8,   # external entity with bulk data access
    "api_integration"            : 7,   # programmatic access, hard to audit
    "third_party_connector"      : 8,   # external integration with data push/pull

    # TV3 -- Transaction Fraud: privileged service accounts
    "payment_processor"          : 7,   # high-value transaction authority
    "automated_clearing_bot"     : 8,   # bulk payment automation
    "transaction_service_account": 8,   # system identity with settlement rights
    "settlement_daemon"          : 8,   # autonomous settlement = no human check

    # TV4 -- Rogue DBA: highest-privilege database identities
    "dba"                        : 10,  # full schema + data access
    "db_admin"                   : 10,  # production database superuser
    "database_administrator"     : 10,  # synonym -- maximum risk score
    "db_superuser"               : 10,  # unrestricted DDL/DML rights
}

# ---------------------------------------------------------------------------
# 1b. target_resource -> Criticality Score [1-10]
#     Reasoning:
#       Internal dashboards and notification services sit at 1-3.
#       Core APIs and KYC services sit at 4-6.
#       Payment gateways, cryptographic modules, and production databases
#       with PII or financial settlement data sit at 8-10.
# ---------------------------------------------------------------------------

TARGET_RESOURCE_CRITICALITY_MAP: Dict[str, int] = {
    # --- Normal Baseline Resources (low-medium criticality) ---
    "notification-service"               : 1,   # no financial/PII data
    "batch-scheduler"                    : 2,   # job orchestration only
    "reporting-dashboard"                : 2,   # read-only analytics UI
    "config-service"                     : 3,   # configuration store
    "audit-log-service"                  : 3,   # logs only (still sensitive)
    "customer-portal"                    : 3,   # end-user interface
    "auth-service"                       : 5,   # authentication -- important
    "identity-provider"                  : 5,   # IdP -- credential issuance
    "kyc-verification-service"           : 5,   # regulatory compliance
    "risk-scoring-api"                   : 5,   # fraud scoring engine
    "compliance-db"                      : 5,   # regulatory data store
    "fraud-detection-engine"             : 5,   # fraud signal processor
    "data-warehouse"                     : 5,   # analytical data lake
    "account-ledger-api"                 : 6,   # account balance API
    "transaction-db"                     : 6,   # transaction records

    # --- TV4 Rogue DBA Resources (high criticality -- production DBs) ---
    "core-banking-db-prod"               : 10,  # crown jewel -- all accounts
    "customer-pii-store-prod"            : 10,  # GDPR/PCI regulated PII
    "transaction-ledger-db-prod"         : 10,  # immutable financial record
    "card-vault-db-prod"                 : 10,  # PAN data -- PCI DSS scope
    "audit-trail-db-prod"                : 9,   # evidence chain -- tampering risk
    "compliance-reporting-db-prod"       : 9,   # regulatory reporting
    "settlement-db-prod"                 : 9,   # real-money settlement
    "fraud-analytics-db-prod"            : 8,   # model data + signals

    # --- TV2 CI/CD Poison Resources (high criticality -- crypto modules) ---
    "libcrypto-core"                     : 10,  # root cryptographic library
    "jwt-signing-service"                : 9,   # token forgery if compromised
    "hsm-key-rotation-service"           : 10,  # hardware security module ops
    "tls-certificate-manager"            : 9,   # TLS termination + cert store
    "password-hashing-module"            : 9,   # credential protection
    "encryption-utils-lib"              : 9,   # shared crypto primitives
    "oauth2-token-service"               : 9,   # OAuth2 authority
    "digital-signature-validator"        : 8,   # signature verification

    # --- TV1 API Abuse Resources (high criticality -- bulk data endpoints) ---
    "open-banking-api"                   : 8,   # PSD2 bulk account access
    "fintech-bridge-service"             : 8,   # external data bridge
    "payment-initiation-api"             : 9,   # payment instruction issuance
    "account-aggregation-endpoint"       : 8,   # multi-account bulk read
    "psd2-consent-api"                   : 7,   # consent token management
    "data-export-service"                : 9,   # bulk data egress service

    # --- TV3 Transaction Fraud Resources ---
    "payment-gateway"                    : 10,  # real-money payment processing
    "transaction-approval-engine"        : 10,  # approval authority
    "real-time-gross-settlement"         : 10,  # central bank settlement
    "card-authorization-service"         : 9,   # card network authorization
    "ach-batch-processor"                : 8,   # ACH batch execution
    "wire-transfer-service"              : 9,   # high-value wire initiation
    "instant-payment-switch"             : 9,   # ISO 20022 payment switch
    "settlement-engine"                  : 9,   # net settlement computation
}

# ---------------------------------------------------------------------------
# 1c. action_executed -> Danger Score [1-10]
#     Reasoning:
#       Standard GET/read operations score 1-2.
#       Standard POST/write/auth operations score 3-4.
#       Bulk operations, DDL, and cryptographic modifications score 7-10.
#       Explicit bypass flags (skip_fraud_check, skip_2fa, force-settle) = 10.
# ---------------------------------------------------------------------------

ACTION_DANGER_MAP: Dict[str, int] = {
    # --- Normal read operations (minimal danger) ---
    "GET /api/v2/accounts"                                           : 1,
    "GET /api/v2/audit/logs"                                         : 1,
    "GET /api/v2/customers/{id}"                                     : 1,
    "GET /api/v2/fraud/alerts"                                       : 2,
    "GET /api/v2/reports/daily"                                      : 1,
    "GET /api/v2/risk/score/{id}"                                    : 1,
    "GET /api/v2/settlements/pending"                                : 2,
    "SELECT * FROM accounts WHERE account_id = ?"                    : 2,

    # --- Normal write/auth operations (low-medium danger) ---
    "DELETE /api/v2/sessions/{id}"                                   : 2,
    "POST /api/v2/auth/login"                                        : 2,
    "POST /api/v2/kyc/verify"                                        : 3,
    "POST /api/v2/transactions"                                      : 3,
    "PATCH /api/v2/settings"                                         : 3,
    "PUT /api/v2/customers/{id}/profile"                             : 3,
    "INSERT INTO audit_log VALUES (?)"                               : 2,
    "UPDATE customer SET status = ? WHERE id = ?"                    : 3,

    # --- Normal CI/CD operations (controlled risk) ---
    "BUILD pipeline:app-service #412"                                : 3,
    "DEPLOY application-service v2.1.3"                              : 4,
    "MERGE PR #338 feature/rate-limiter"                             : 3,
    "RUN test-suite:integration"                                     : 2,

    # --- TV1 Bulk Data Extraction (high danger) ---
    "GET /api/v3/open-banking/bulk-accounts?limit=5000"              : 8,
    "GET /api/v3/customers/export?format=csv&fields=ALL"             : 9,
    "GET /api/v3/transactions/bulk?from=2020-01-01&to=2025-01-01"    : 8,
    "GET /api/v3/account-aggregation/all-accounts?include_closed=true": 8,
    "POST /api/v3/data-export/initiate?records=ALL"                  : 9,
    "POST /api/v3/fintech/sync?mode=full&compress=false"             : 8,

    # --- TV2 Crypto Library Modifications (very high danger) ---
    "COMMIT src/crypto/aes_gcm.py -- modify key derivation logic"    : 10,
    "COMMIT src/auth/jwt_validator.py -- remove signature expiry check": 10,
    "COMMIT utils/hash_util.py -- replace bcrypt with MD5 for performance": 10,
    "EDIT lib/security/rsa_encrypt.py -- change padding scheme to PKCS1v15": 10,
    "EDIT lib/crypto/ecdsa_sign.py -- stub out nonce generation"     : 10,
    "PUSH config/tls.yaml -- downgrade TLS minimum version to 1.0"   : 10,

    # --- TV3 Transaction Fraud -- Explicit Bypass Flags (maximum danger) ---
    "POST /api/v2/transactions/approve?bypass_limit=true"            : 10,
    "POST /api/v2/payments/bulk-authorize -- 8500 transactions"      : 10,
    "EXECUTE sp_approve_transaction_batch @skip_fraud_check=1"       : 10,
    "PUT /api/v2/payments/{id}/force-settle"                         : 10,
    "POST /api/v2/transactions/override-velocity-limit"              : 10,
    "EXECUTE approve_wire_transfer(amount=4750000, skip_2fa=TRUE)"   : 10,
    "POST /api/v2/ach/submit-batch?records=12000&priority=URGENT"    : 9,

    # --- TV4 DDL Schema Modification (very high danger) ---
    "ALTER TABLE customers DROP COLUMN ssn_hash"                     : 10,
    "ALTER TABLE transactions ADD COLUMN shadow_copy TEXT"           : 10,
    "ALTER TABLE compliance_flags ADD COLUMN is_suppressed BOOLEAN DEFAULT TRUE": 10,
    "ALTER TABLE users ADD COLUMN bypass_2fa TINYINT(1) DEFAULT 1"   : 10,
    "CREATE TABLE shadow_accounts AS SELECT * FROM accounts"         : 10,
    "DELETE FROM compliance_rules WHERE rule_id BETWEEN 1 AND 500"   : 10,
    "DROP CONSTRAINT fk_account_customer ON transactions"            : 9,
    "DROP INDEX idx_audit_timestamp ON audit_log"                    : 8,
    "RENAME TABLE audit_log TO audit_log_bkp_2025"                   : 9,
    "TRUNCATE TABLE fraud_event_log"                                 : 10,
    "CREATE INDEX CONCURRENTLY idx_ssn ON customers(ssn_hash)"       : 7,
}

# Bundle all three maps together for serialisation
FEATURE_MAPPINGS: Dict[str, Dict] = {
    "actor_role_risk_map"              : ACTOR_ROLE_RISK_MAP,
    "target_resource_criticality_map"  : TARGET_RESOURCE_CRITICALITY_MAP,
    "action_danger_map"                : ACTION_DANGER_MAP,
    "schema": {
        "drop_columns"        : DROP_COLUMNS,
        "categorical_columns" : CATEGORICAL_COLUMNS,
        "continuous_columns"  : CONTINUOUS_COLUMNS,
        "label_column"        : LABEL_COLUMN,
        "engineered_features" : [
            "actor_role_risk",
            "target_criticality",
            "action_danger",
            "execution_time_delta",
            "data_volume_kb",
            "temporal_hour",
            "off_hours_flag",
            "risk_x_criticality",
        ],
    },
    "hyperparameters": {
        "contamination"   : CONTAMINATION,
        "n_estimators"    : N_ESTIMATORS,
        "max_samples"     : MAX_SAMPLES,
        "max_features"    : MAX_FEATURES,
        "bootstrap"       : BOOTSTRAP,
        "random_state"    : RANDOM_SEED,
    },
    "default_risk_score"         : 5,   # fallback for unseen actors
    "default_criticality_score"  : 5,   # fallback for unseen resources
    "default_action_danger_score": 5,   # fallback for unseen actions
}


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 2 -- DATA INGESTION & VALIDATION
# ============================================================================

def load_and_validate(path: Path) -> pd.DataFrame:
    """
    Load the CSV dataset, enforce expected schema, and cast column types.

    Raises
    ------
    FileNotFoundError : if the dataset CSV does not exist at the given path.
    ValueError        : if required columns are absent from the loaded file.
    """
    log.info("Loading dataset from: %s", path)
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at '{path}'. "
            "Run mock_generator.py first to generate it."
        )

    df = pd.read_csv(path, dtype=str)   # load everything as str initially

    required_cols = (
        DROP_COLUMNS + CATEGORICAL_COLUMNS + CONTINUOUS_COLUMNS + [LABEL_COLUMN]
    )
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    # Type coercion
    df["execution_time_delta"] = pd.to_numeric(df["execution_time_delta"],
                                               errors="coerce")
    df["data_volume_kb"]       = pd.to_numeric(df["data_volume_kb"],
                                               errors="coerce")
    df["temporal_hour"]        = pd.to_numeric(df["temporal_hour"],
                                               errors="coerce").astype(int)
    df["is_anomaly"]           = pd.to_numeric(df["is_anomaly"],
                                               errors="coerce").astype(int)

    # Reject rows with NaN in critical numeric columns
    initial_len = len(df)
    df.dropna(subset=["execution_time_delta", "data_volume_kb", "temporal_hour"],
              inplace=True)
    dropped = initial_len - len(df)
    if dropped:
        log.warning("Dropped %d rows with NaN in continuous features.", dropped)

    log.info("Dataset loaded: %d rows, %d columns.", len(df), len(df.columns))
    log.info(
        "Label distribution: %s",
        df["is_anomaly"].value_counts().to_dict(),
    )
    return df


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 3 -- FEATURE ENGINEERING
# ============================================================================

def apply_risk_encoding(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply domain-authored risk-footprint maps to all three categorical columns.

    Produces three new integer columns:
        actor_role_risk      -- ordinal risk of the acting identity [1-10]
        target_criticality   -- ordinal criticality of the target asset [1-10]
        action_danger        -- ordinal danger of the executed action  [1-10]

    Unseen values fall back to the configured default (5 = medium risk).
    """
    log.info("Applying categorical risk-footprint encoding ...")

    df = df.copy()

    # Trim whitespace from categorical columns (defensive)
    for col in CATEGORICAL_COLUMNS:
        df[col] = df[col].astype(str).str.strip()

    # Map with fallback defaults
    df["actor_role_risk"] = (
        df["actor_role"]
        .map(ACTOR_ROLE_RISK_MAP)
        .fillna(FEATURE_MAPPINGS["default_risk_score"])
        .astype(int)
    )

    df["target_criticality"] = (
        df["target_resource"]
        .map(TARGET_RESOURCE_CRITICALITY_MAP)
        .fillna(FEATURE_MAPPINGS["default_criticality_score"])
        .astype(int)
    )

    df["action_danger"] = (
        df["action_executed"]
        .map(ACTION_DANGER_MAP)
        .fillna(FEATURE_MAPPINGS["default_action_danger_score"])
        .astype(int)
    )

    # Log encoding coverage (warn on unmapped values)
    for src_col, mapped_col, ref_map in [
        ("actor_role",      "actor_role_risk",    ACTOR_ROLE_RISK_MAP),
        ("target_resource", "target_criticality", TARGET_RESOURCE_CRITICALITY_MAP),
        ("action_executed", "action_danger",       ACTION_DANGER_MAP),
    ]:
        unmapped = df[~df[src_col].isin(ref_map)][src_col].unique()
        if len(unmapped) > 0:
            log.warning(
                "Column '%s': %d unseen value(s) -> default score applied: %s",
                src_col, len(unmapped), list(unmapped[:5]),
            )
        else:
            log.info(
                "Column '%s': 100%% coverage in risk map (%d unique values).",
                src_col, df[src_col].nunique(),
            )

    return df


def engineer_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """
    Construct the full feature matrix from encoded categoricals and
    raw continuous columns, plus two composite interaction features:

        off_hours_flag      -- binary: 1 if temporal_hour in {22,23,0,1,2,3,4,5}
        risk_x_criticality  -- multiplicative interaction between actor_role_risk
                               and target_criticality to surface high-risk compound
                               events (rogue DBA hitting production DB = 10 x 10 = 100)

    Returns
    -------
    X          : pd.DataFrame  -- feature matrix (model input only)
    feat_cols  : List[str]     -- ordered list of feature column names
    """
    log.info("Engineering feature matrix ...")

    OFF_HOURS: set = set(range(22, 24)) | set(range(0, 6))

    df = df.copy()
    df["off_hours_flag"]     = df["temporal_hour"].apply(
        lambda h: 1 if h in OFF_HOURS else 0
    )
    df["risk_x_criticality"] = df["actor_role_risk"] * df["target_criticality"]

    feature_cols = [
        "actor_role_risk",       # categorical -> ordinal risk [1-10]
        "target_criticality",    # categorical -> ordinal criticality [1-10]
        "action_danger",         # categorical -> ordinal danger [1-10]
        "execution_time_delta",  # ms: low=fraud/API abuse; high=DDL
        "data_volume_kb",        # KB: very high=API abuse; normal=baseline
        "temporal_hour",         # raw hour [0-23] for pattern capture
        "off_hours_flag",        # engineered: captures DBA/CI-CD off-hours
        "risk_x_criticality",    # compound: actor x resource risk interaction
    ]

    X = df[feature_cols].copy()
    log.info(
        "Feature matrix assembled: shape=%s, features=%s",
        X.shape, feature_cols,
    )
    return X, feature_cols


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 4 -- MODEL TRAINING
# ============================================================================

def build_pipeline() -> Pipeline:
    """
    Construct a two-stage sklearn Pipeline:
        Stage 1 -- StandardScaler   : zero-mean, unit-variance normalisation
        Stage 2 -- IsolationForest  : unsupervised anomaly scorer

    The Pipeline ensures the scaler is always fitted alongside the model and
    applied consistently at inference time without data leakage.
    """
    scaler = StandardScaler()

    isoforest = IsolationForest(
        n_estimators    = N_ESTIMATORS,
        max_samples     = MAX_SAMPLES,
        contamination   = CONTAMINATION,
        max_features    = MAX_FEATURES,
        bootstrap       = BOOTSTRAP,
        random_state    = RANDOM_SEED,
        n_jobs          = -1,       # use all available CPU cores
        verbose         = 0,
    )

    pipeline = Pipeline(
        steps=[
            ("scaler",    scaler),
            ("isoforest", isoforest),
        ],
        verbose=False,
    )
    return pipeline


def train(pipeline: Pipeline, X: pd.DataFrame) -> Pipeline:
    """Fit the full pipeline on the feature matrix."""
    log.info(
        "Training Isolation Forest: n_estimators=%d, contamination=%.4f, "
        "max_features=%.1f, random_state=%d ...",
        N_ESTIMATORS, CONTAMINATION, MAX_FEATURES, RANDOM_SEED,
    )
    t0 = time.perf_counter()
    pipeline.fit(X)
    elapsed = time.perf_counter() - t0
    log.info("Training completed in %.3f seconds.", elapsed)
    return pipeline


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 5 -- PREDICTION & LABEL MAPPING
# ============================================================================

def predict_and_map(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray:
    """
    Generate predictions from the fitted pipeline and remap IsolationForest's
    native output convention to the dataset's binary label convention:

        IsoForest output  ->  Dataset label
        -1 (anomaly)      ->  1
         1 (normal)       ->  0
    """
    raw_preds    = pipeline.predict(X)          # array of {-1, +1}
    mapped_preds = np.where(raw_preds == -1, 1, 0)
    n_flagged    = int(mapped_preds.sum())
    log.info(
        "Prediction complete: %d samples flagged as anomalies (%.4f%% of total).",
        n_flagged, 100.0 * n_flagged / len(mapped_preds),
    )
    return mapped_preds


def get_anomaly_scores(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray:
    """
    Extract decision function scores. IsolationForest.decision_function()
    returns negative anomaly scores; we negate them so higher = more anomalous,
    matching the sklearn convention for AUC computation.
    """
    return -pipeline.decision_function(X)


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 6 -- EVALUATION & REPORTING
# ============================================================================

def evaluate(
    y_true   : np.ndarray,
    y_pred   : np.ndarray,
    scores   : np.ndarray,
    df       : pd.DataFrame,
    feat_cols: List[str],
) -> None:
    """
    Produce a comprehensive evaluation report including:
      [1] Full sklearn classification_report (precision, recall, F1, support)
      [2] Confusion matrix with labeled axes
      [3] Per-class ROC-AUC with qualitative assessment
      [4] Per-threat-vector detection breakdown table
      [5] Anomaly score distribution statistics by true label
      [6] Summary metrics table
    """
    divider = "=" * 72
    subdiv  = "-" * 72

    print()
    print(divider)
    print("  SENTINALFLOW AI -- ISOLATION FOREST EVALUATION REPORT")
    print(divider)

    # ── [1] Classification Report ─────────────────────────────────────────
    print()
    print("  [1]  CLASSIFICATION REPORT")
    print(subdiv)
    report = classification_report(
        y_true,
        y_pred,
        target_names=["Normal (0)", "Anomaly (1)"],
        digits=4,
    )
    for line in report.splitlines():
        print("  " + line)

    # ── [2] Confusion Matrix ──────────────────────────────────────────────
    print()
    print("  [2]  CONFUSION MATRIX")
    print(subdiv)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print()
    print("                         Predicted")
    print("                    Normal      Anomaly")
    print(f"  Actual  Normal  |  {tn:<10}  {fp:<10}  |")
    print(f"          Anomaly |  {fn:<10}  {tp:<10}  |")
    print()
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr         = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    print(f"  True  Negatives (TN) : {tn:>6}   (normal events correctly cleared)")
    print(f"  False Positives (FP) : {fp:>6}   (normal events flagged -- alert fatigue)")
    print(f"  False Negatives (FN) : {fn:>6}   (missed anomalies -- critical detection gap)")
    print(f"  True  Positives (TP) : {tp:>6}   (confirmed threat detections)")
    print()
    print(f"  Sensitivity (Recall) : {sensitivity:.4f}  ({sensitivity*100:.2f}% of anomalies caught)")
    print(f"  Specificity          : {specificity:.4f}  ({specificity*100:.2f}% of normals cleared)")
    print(f"  FPR (Alert Fatigue)  : {fpr:.4f}  ({fpr*100:.2f}% of normal events false-flagged)")

    # ── [3] ROC-AUC ───────────────────────────────────────────────────────
    print()
    print("  [3]  ROC-AUC SCORE")
    print(subdiv)
    auc = 0.0
    try:
        auc = roc_auc_score(y_true, scores)
        print(f"\n  ROC-AUC (decision function): {auc:.6f}")
        if auc >= 0.95:
            quality = "EXCELLENT -- Model cleanly separates anomaly distributions."
        elif auc >= 0.85:
            quality = "GOOD -- Strong separation with minor overlap in feature space."
        elif auc >= 0.70:
            quality = "MODERATE -- Review feature engineering for weak signal columns."
        else:
            quality = "POOR -- Significant feature overlap; reconsider encoding strategy."
        print(f"  Assessment: {quality}")
    except Exception as exc:
        log.warning("Could not compute ROC-AUC: %s", exc)

    # ── [4] Per-Threat-Vector Detection Breakdown ─────────────────────────
    print()
    print("  [4]  PER-THREAT-VECTOR DETECTION BREAKDOWN")
    print(subdiv)

    if "threat_vector" in df.columns:
        df_eval = df.copy()
        df_eval["y_pred"] = y_pred
        df_eval["score"]  = scores

        anomaly_df = df_eval[df_eval["is_anomaly"] == 1].copy()

        print()
        print(
            f"  {'Threat Vector':<42}  {'n':>4}  {'Detected':>8}  "
            f"{'Missed':>6}  {'Recall':>7}  {'Avg Score':>9}"
        )
        print("  " + "-" * 72)

        for vec in sorted(anomaly_df["threat_vector"].unique()):
            vec_rows  = anomaly_df[anomaly_df["threat_vector"] == vec]
            total     = len(vec_rows)
            detected  = int((vec_rows["y_pred"] == 1).sum())
            missed    = total - detected
            recall    = detected / total if total > 0 else 0.0
            avg_score = vec_rows["score"].mean()
            print(
                f"  {vec:<42}  {total:>4}  {detected:>8}  "
                f"{missed:>6}  {recall:>7.4f}  {avg_score:>9.4f}"
            )
    else:
        print("  (threat_vector column unavailable -- skipping breakdown.)")

    # ── [5] Anomaly Score Distribution ────────────────────────────────────
    print()
    print("  [5]  ANOMALY SCORE STATISTICS  (higher score = more anomalous)")
    print(subdiv)
    print()
    for label_val, label_name in [(0, "Normal Baseline"), (1, "True Anomalies")]:
        mask = y_true == label_val
        grp  = scores[mask]
        print(f"  [{label_name}] (n={mask.sum():,})")
        print(f"    Min    : {grp.min():.6f}")
        print(f"    Max    : {grp.max():.6f}")
        print(f"    Mean   : {grp.mean():.6f}")
        print(f"    Median : {np.median(grp):.6f}")
        print(f"    Std    : {grp.std():.6f}")
        print(f"    P95    : {np.percentile(grp, 95):.6f}")
        print()

    # ── [6] Summary Metrics Table ──────────────────────────────────────────
    print()
    print("  [6]  SUMMARY METRICS TABLE")
    print(subdiv)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    print()
    print(f"  {'Metric':<34}  {'Value':>12}")
    print("  " + "-" * 48)
    print(f"  {'Precision  (Anomaly class)':<34}  {prec:>12.6f}")
    print(f"  {'Recall     (Anomaly class)':<34}  {rec:>12.6f}")
    print(f"  {'F1-Score   (Anomaly class)':<34}  {f1:>12.6f}")
    print(f"  {'Specificity':<34}  {specificity:>12.6f}")
    print(f"  {'Sensitivity':<34}  {sensitivity:>12.6f}")
    print(f"  {'ROC-AUC    (decision fn)':<34}  {auc:>12.6f}")
    print(f"  {'True  Positives  (TP)':<34}  {tp:>12}")
    print(f"  {'False Positives  (FP)':<34}  {fp:>12}")
    print(f"  {'False Negatives  (FN)':<34}  {fn:>12}")
    print(f"  {'True  Negatives  (TN)':<34}  {tn:>12}")
    print()
    print(divider)


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 7 -- ARTEFACT SERIALISATION
# ============================================================================

def serialise_artefacts(
    pipeline     : Pipeline,
    feature_cols : List[str],
    scaler_stats : Dict,
) -> None:
    """
    Persist the trained pipeline and all encoding metadata to disk under
    the ARTEFACT_DIR directory using joblib's compressed pickle format.

    sentinel_model.pkl
        Full sklearn Pipeline (StandardScaler + IsolationForest).
        Ready for .predict() and .decision_function() calls at inference time.

    feature_mappings.joblib
        Dictionary containing all three risk maps, schema metadata,
        training hyperparameters, and fitted scaler statistics.
    """
    ARTEFACT_DIR.mkdir(parents=True, exist_ok=True)

    # Embed scaler statistics and feature column order into the mappings dict
    FEATURE_MAPPINGS["scaler_stats"]    = scaler_stats
    FEATURE_MAPPINGS["feature_columns"] = feature_cols

    # --- Serialise Pipeline ---
    log.info("Serialising trained pipeline -> %s", MODEL_PATH)
    joblib.dump(pipeline, MODEL_PATH, compress=3)
    model_size_kb = MODEL_PATH.stat().st_size / 1024
    log.info("  sentinel_model.pkl saved  (%.1f KB)", model_size_kb)

    # --- Serialise Feature Mappings ---
    log.info("Serialising feature mappings -> %s", MAPPINGS_PATH)
    joblib.dump(FEATURE_MAPPINGS, MAPPINGS_PATH, compress=3)
    maps_size_kb = MAPPINGS_PATH.stat().st_size / 1024
    log.info("  feature_mappings.joblib saved  (%.1f KB)", maps_size_kb)

    log.info("All artefacts written to: %s", ARTEFACT_DIR)


# ---------------------------------------------------------------------------
# ============================================================================
# SECTION 8 -- ARTEFACT VERIFICATION (ROUND-TRIP CHECK)
# ============================================================================

def verify_artefacts(X_sample: pd.DataFrame) -> None:
    """
    Reload the serialised artefacts from disk and execute a forward pass on
    a small sample to confirm integrity and round-trip consistency.
    """
    log.info("Verifying serialised artefacts (round-trip check) ...")

    loaded_pipeline = joblib.load(MODEL_PATH)
    loaded_mappings = joblib.load(MAPPINGS_PATH)

    # Smoke-test: predict on first 10 rows
    sample_preds = loaded_pipeline.predict(X_sample.iloc[:10])
    log.info("  Round-trip predictions (10 samples): %s", sample_preds.tolist())

    # Verify all required mapping keys are present
    expected_keys = [
        "actor_role_risk_map",
        "target_resource_criticality_map",
        "action_danger_map",
        "schema",
        "hyperparameters",
        "scaler_stats",
        "feature_columns",
    ]
    for key in expected_keys:
        assert key in loaded_mappings, (
            f"Round-trip verification FAILED: missing key '{key}' in loaded mappings."
        )

    # Confirm feature column order is preserved
    assert loaded_mappings["feature_columns"] == X_sample.columns.tolist(), (
        "Round-trip verification FAILED: feature column order mismatch."
    )

    log.info("  All %d mapping keys verified.", len(expected_keys))
    log.info("  Round-trip verification PASSED.")


# ---------------------------------------------------------------------------
# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

def main() -> None:
    divider = "=" * 72
    print(divider)
    print("  SENTINALFLOW AI -- TRAINING PIPELINE")
    print(f"  Dataset          : {DATASET_PATH}")
    print(f"  Artefact Dir     : {ARTEFACT_DIR}")
    print(f"  Contamination    : {CONTAMINATION}")
    print(f"  N Estimators     : {N_ESTIMATORS}")
    print(f"  Random Seed      : {RANDOM_SEED}")
    print(divider)
    print()

    # Stage 1: Ingest and validate
    df = load_and_validate(DATASET_PATH)

    # Stage 2: Risk-footprint categorical encoding
    df_encoded = apply_risk_encoding(df)

    # Stage 3: Feature matrix assembly + interaction features
    X, feature_cols = engineer_features(df_encoded)
    y_true = df_encoded[LABEL_COLUMN].values

    # Stage 4: Build and fit the sklearn Pipeline
    pipeline = build_pipeline()
    pipeline = train(pipeline, X)

    # Stage 5: Capture scaler statistics for artefact metadata
    fitted_scaler = pipeline.named_steps["scaler"]
    scaler_stats = {
        "mean_"  : dict(zip(feature_cols, fitted_scaler.mean_.tolist())),
        "scale_" : dict(zip(feature_cols, fitted_scaler.scale_.tolist())),
        "var_"   : dict(zip(feature_cols, fitted_scaler.var_.tolist())),
    }
    log.info("Scaler stats captured for %d features.", len(feature_cols))

    # Stage 6: Predict and remap to binary labels
    y_pred = predict_and_map(pipeline, X)
    scores = get_anomaly_scores(pipeline, X)

    # Stage 7: Comprehensive evaluation report
    evaluate(y_true, y_pred, scores, df_encoded, feature_cols)

    # Stage 8: Serialise pipeline and mappings
    serialise_artefacts(pipeline, feature_cols, scaler_stats)

    # Stage 9: Round-trip verification
    verify_artefacts(X)

    print()
    log.info("Pipeline complete. Artefacts ready in: %s", ARTEFACT_DIR)
    print(divider)


if __name__ == "__main__":
    main()
