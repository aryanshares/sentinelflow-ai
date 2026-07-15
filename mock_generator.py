"""
==============================================================================
 mock_generator.py
 Synthetic Banking Infrastructure Telemetry Dataset Generator
 Author  : Senior Cyber Threat Intelligence Data Scientist
 Version : 1.0.0
 Purpose : Generate a reproducible, production-quality synthetic CSV dataset
           containing 10,000 normal baseline banking infrastructure logs and
           50 injected adversarial anomaly records representing four distinct
           threat vectors used for ML-based anomaly detection pipelines.

 Threat Vectors Modelled
 -----------------------
 1. Third-Party Fintech API Abuse         â€” High query velocity + anomalous
                                            data extraction volumes via
                                            external API actors.
 2. Poisoned CI/CD Code Pipelines         â€” Cryptographic library modifications
                                            by non-senior roles without peer
                                            review tickets during off-hours.
 3. High-Volume Transaction Fraud         â€” Sub-second approval timestamps
                                            indicating rule-engine bypass or
                                            automated injection attacks.
 4. Rogue Internal DBAs                   â€” Direct schema DDL executed off-hours
                                            with no associated IT ticket IDs.

 Output  : banking_telemetry_dataset.csv  (shuffled, reproducible)
==============================================================================
"""

import csv
import math
import random
import string
import uuid
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Global Configuration
# ---------------------------------------------------------------------------

RANDOM_SEED: int = 42
NUM_NORMAL_ROWS: int = 10_000
NUM_ANOMALY_ROWS: int = 50          # 50 injected adversarial records
ANOMALY_PER_VECTOR: int = 12        # 12 per vector = 48 + 2 spillover to TV-1
OUTPUT_FILE: str = "banking_telemetry_dataset.csv"

CSV_COLUMNS = [
    "event_id",
    "timestamp",
    "threat_vector",
    "actor_id",
    "actor_role",
    "target_resource",
    "action_executed",
    "associated_ticket_id",
    "execution_time_delta",
    "data_volume_kb",
    "temporal_hour",
    "is_anomaly",
]

# ---------------------------------------------------------------------------
# Seeded RNG â€” ensures full reproducibility
# ---------------------------------------------------------------------------

rng = random.Random(RANDOM_SEED)

# ---------------------------------------------------------------------------
# Helper Utilities
# ---------------------------------------------------------------------------

BASELINE_START: datetime = datetime(2025, 1, 1, 0, 0, 0)
BASELINE_END:   datetime = datetime(2025, 12, 31, 23, 59, 59)

TOTAL_SECONDS: int = int((BASELINE_END - BASELINE_START).total_seconds())


def random_timestamp(
    start: datetime = BASELINE_START,
    end:   datetime = BASELINE_END,
) -> datetime:
    """Return a uniformly distributed random timestamp between start and end."""
    delta_secs = int((end - start).total_seconds())
    return start + timedelta(seconds=rng.randint(0, delta_secs))


def random_timestamp_offhours(start: datetime, end: datetime) -> datetime:
    """Return a timestamp guaranteed to fall between 22:00â€“05:59 (off-hours)."""
    ts = random_timestamp(start, end)
    # Bias hour to off-hours range [22, 23, 0, 1, 2, 3, 4, 5]
    off_hours = list(range(22, 24)) + list(range(0, 6))
    ts = ts.replace(hour=rng.choice(off_hours),
                    minute=rng.randint(0, 59),
                    second=rng.randint(0, 59))
    return ts


def random_business_hours_timestamp(start: datetime, end: datetime) -> datetime:
    """Return a timestamp falling in business hours 08:00â€“17:59."""
    ts = random_timestamp(start, end)
    ts = ts.replace(hour=rng.randint(8, 17),
                    minute=rng.randint(0, 59),
                    second=rng.randint(0, 59))
    return ts


def format_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def gen_event_id() -> str:
    """Generate a UUID4-based event identifier."""
    # Use rng-seeded bytes to keep determinism
    hex_str = "".join(rng.choices(string.hexdigits[:16], k=32))
    return (
        f"{hex_str[0:8]}-{hex_str[8:12]}-4{hex_str[13:16]}"
        f"-{hex_str[16:20]}-{hex_str[20:32]}"
    )


def gen_actor_id(prefix: str = "USR") -> str:
    return f"{prefix}-{rng.randint(1000, 9999)}"


def gen_ticket_id() -> str:
    return f"INC-{rng.randint(100000, 999999)}"


def null_ticket() -> str:
    return "NULL"


# ---------------------------------------------------------------------------
# Normal Baseline Profile Pools
# ---------------------------------------------------------------------------

NORMAL_ACTOR_ROLES = [
    "analyst", "developer", "qa_engineer", "business_analyst",
    "operations_engineer", "support_engineer", "data_engineer",
    "compliance_officer", "product_manager", "network_engineer",
]

NORMAL_RESOURCES = [
    "auth-service", "payment-gateway", "account-ledger-api",
    "reporting-dashboard", "kyc-verification-service",
    "fraud-detection-engine", "customer-portal", "transaction-db",
    "config-service", "audit-log-service", "notification-service",
    "settlement-engine", "risk-scoring-api", "compliance-db",
    "identity-provider", "data-warehouse", "batch-scheduler",
]

NORMAL_ACTIONS = [
    "GET /api/v2/accounts",
    "POST /api/v2/transactions",
    "GET /api/v2/customers/{id}",
    "PUT /api/v2/customers/{id}/profile",
    "GET /api/v2/reports/daily",
    "POST /api/v2/auth/login",
    "DELETE /api/v2/sessions/{id}",
    "GET /api/v2/fraud/alerts",
    "PATCH /api/v2/settings",
    "GET /api/v2/audit/logs",
    "POST /api/v2/kyc/verify",
    "GET /api/v2/risk/score/{id}",
    "SELECT * FROM accounts WHERE account_id = ?",
    "INSERT INTO audit_log VALUES (?)",
    "UPDATE customer SET status = ? WHERE id = ?",
    "DEPLOY application-service v2.1.3",
    "BUILD pipeline:app-service #412",
    "RUN test-suite:integration",
    "MERGE PR #338 feature/rate-limiter",
    "GET /api/v2/settlements/pending",
]

NORMAL_THREAT_VECTOR = "NONE"

# Normal baseline statistical parameters
NORMAL_EXEC_TIME_MEAN:   float = 320.0    # ms
NORMAL_EXEC_TIME_STD:    float = 110.0    # ms
NORMAL_EXEC_TIME_MIN:    float = 50.0     # ms
NORMAL_EXEC_TIME_MAX:    float = 2500.0   # ms

NORMAL_DATA_VOL_MEAN:    float = 85.0     # KB
NORMAL_DATA_VOL_STD:     float = 42.0     # KB
NORMAL_DATA_VOL_MIN:     float = 1.0      # KB
NORMAL_DATA_VOL_MAX:     float = 512.0    # KB

# ---------------------------------------------------------------------------
# Threat Vector 1 â€” Third-Party Fintech API Abuse
# ---------------------------------------------------------------------------
# Indicators:
#   â€¢ External/partner actor IDs (EXT- prefix)
#   â€¢ Targets fintech integration endpoints
#   â€¢ Very high query velocity â†’ very low execution_time_delta (near 0 ms)
#     combined with anomalously large data_volume_kb (bulk extraction)
#   â€¢ Ticket IDs may exist (legitimate-looking integrations) but volumes betray
# ---------------------------------------------------------------------------

TV1_ACTOR_ROLES = ["fintech_partner", "api_integration", "third_party_connector"]
TV1_RESOURCES   = [
    "open-banking-api", "fintech-bridge-service", "payment-initiation-api",
    "account-aggregation-endpoint", "psd2-consent-api", "data-export-service",
]
TV1_ACTIONS = [
    "GET /api/v3/open-banking/bulk-accounts?limit=5000",
    "POST /api/v3/data-export/initiate?records=ALL",
    "GET /api/v3/transactions/bulk?from=2020-01-01&to=2025-01-01",
    "GET /api/v3/customers/export?format=csv&fields=ALL",
    "POST /api/v3/fintech/sync?mode=full&compress=false",
    "GET /api/v3/account-aggregation/all-accounts?include_closed=true",
]

def generate_tv1_anomaly() -> dict:
    """Generate one Third-Party Fintech API Abuse anomaly record."""
    ts = random_timestamp()
    return {
        "event_id"            : gen_event_id(),
        "timestamp"           : format_ts(ts),
        "threat_vector"       : "THIRD_PARTY_FINTECH_API_ABUSE",
        "actor_id"            : gen_actor_id("EXT"),
        "actor_role"          : rng.choice(TV1_ACTOR_ROLES),
        "target_resource"     : rng.choice(TV1_RESOURCES),
        "action_executed"     : rng.choice(TV1_ACTIONS),
        # Tickets exist but are recycled/generic â€” sometimes absent
        "associated_ticket_id": rng.choice(
            [gen_ticket_id(), gen_ticket_id(), "NULL"]
        ),
        # Extremely fast execution = automated bulk scraper (< 25 ms)
        "execution_time_delta": round(rng.uniform(2.0, 24.9), 3),
        # Anomalously large bulk data extraction (10 MB â€“ 150 MB)
        "data_volume_kb"      : round(rng.uniform(10_240.0, 153_600.0), 2),
        "temporal_hour"       : ts.hour,
        "is_anomaly"          : 1,
    }


# ---------------------------------------------------------------------------
# Threat Vector 2 â€” Poisoned CI/CD Code Pipelines
# ---------------------------------------------------------------------------
# Indicators:
#   â€¢ Actor role is NOT senior_engineer / principal_engineer / security_lead
#   â€¢ Target is a cryptographic library or core security component
#   â€¢ Action involves direct code modification to crypto modules
#   â€¢ No associated ticket (bypassed change control)
#   â€¢ Execution during off-hours (22:00â€“05:59)
# ---------------------------------------------------------------------------

TV2_NON_SENIOR_ROLES = [
    "junior_developer", "intern_developer", "contractor_developer",
    "qa_engineer", "build_bot_unverified",
]
TV2_CRYPTO_RESOURCES = [
    "libcrypto-core", "jwt-signing-service", "tls-certificate-manager",
    "hsm-key-rotation-service", "password-hashing-module",
    "encryption-utils-lib", "oauth2-token-service",
    "digital-signature-validator",
]
TV2_ACTIONS = [
    "COMMIT src/crypto/aes_gcm.py -- modify key derivation logic",
    "PUSH branch:hotfix/crypto-patch -- alter HMAC validation",
    "MERGE PR#9911 -- disable certificate pinning for test env",
    "EDIT lib/security/rsa_encrypt.py -- change padding scheme to PKCS1v15",
    "COMMIT src/auth/jwt_validator.py -- remove signature expiry check",
    "PUSH config/tls.yaml -- downgrade TLS minimum version to 1.0",
    "COMMIT utils/hash_util.py -- replace bcrypt with MD5 for performance",
    "EDIT lib/crypto/ecdsa_sign.py -- stub out nonce generation",
]

def generate_tv2_anomaly() -> dict:
    """Generate one Poisoned CI/CD Code Pipeline anomaly record."""
    ts = random_timestamp_offhours(BASELINE_START, BASELINE_END)
    return {
        "event_id"            : gen_event_id(),
        "timestamp"           : format_ts(ts),
        "threat_vector"       : "POISONED_CICD_PIPELINE",
        "actor_id"            : gen_actor_id("DEV"),
        "actor_role"          : rng.choice(TV2_NON_SENIOR_ROLES),
        "target_resource"     : rng.choice(TV2_CRYPTO_RESOURCES),
        "action_executed"     : rng.choice(TV2_ACTIONS),
        # No peer review ticket â€” bypassed change control
        "associated_ticket_id": "NULL",
        # Normal-ish execution time (doesn't stand out on its own)
        "execution_time_delta": round(rng.uniform(150.0, 900.0), 3),
        # Small commit payload â€” obfuscates the attack surface
        "data_volume_kb"      : round(rng.uniform(2.0, 48.0), 2),
        "temporal_hour"       : ts.hour,
        "is_anomaly"          : 1,
    }


# ---------------------------------------------------------------------------
# Threat Vector 3 â€” High-Volume Transaction Fraud
# ---------------------------------------------------------------------------
# Indicators:
#   â€¢ Targets payment gateway or transaction approval engine
#   â€¢ Action is a transaction approval / authorization
#   â€¢ execution_time_delta is sub-second (< 1000 ms, specifically < 50 ms)
#     representing automated rule-engine bypass or middleware injection
#   â€¢ data_volume_kb is moderately elevated (transaction batch payloads)
#   â€¢ Can occur at any hour, slightly biased toward business hours (camouflage)
# ---------------------------------------------------------------------------

TV3_ACTOR_ROLES = [
    "payment_processor", "transaction_service_account",
    "automated_clearing_bot", "settlement_daemon",
]
TV3_RESOURCES = [
    "payment-gateway", "transaction-approval-engine",
    "real-time-gross-settlement", "card-authorization-service",
    "ach-batch-processor", "wire-transfer-service",
    "instant-payment-switch",
]
TV3_ACTIONS = [
    "POST /api/v2/transactions/approve?bypass_limit=true",
    "POST /api/v2/payments/bulk-authorize -- 8500 transactions",
    "EXECUTE sp_approve_transaction_batch @skip_fraud_check=1",
    "PUT /api/v2/payments/{id}/force-settle",
    "POST /api/v2/transactions/override-velocity-limit",
    "EXECUTE approve_wire_transfer(amount=4750000, skip_2fa=TRUE)",
    "POST /api/v2/ach/submit-batch?records=12000&priority=URGENT",
]

def generate_tv3_anomaly() -> dict:
    """Generate one High-Volume Transaction Fraud anomaly record."""
    ts = random_timestamp()
    return {
        "event_id"            : gen_event_id(),
        "timestamp"           : format_ts(ts),
        "threat_vector"       : "HIGH_VOLUME_TRANSACTION_FRAUD",
        "actor_id"            : gen_actor_id("SVC"),
        "actor_role"          : rng.choice(TV3_ACTOR_ROLES),
        "target_resource"     : rng.choice(TV3_RESOURCES),
        "action_executed"     : rng.choice(TV3_ACTIONS),
        # Ticket may be fabricated to pass initial triage
        "associated_ticket_id": rng.choice(
            [gen_ticket_id(), "NULL", "AUTO-GENERATED"]
        ),
        # Sub-50 ms approvals â€” hallmark of rule-engine bypass
        "execution_time_delta": round(rng.uniform(0.5, 49.9), 3),
        # High-volume batch payload (1 MB â€“ 20 MB range)
        "data_volume_kb"      : round(rng.uniform(1_024.0, 20_480.0), 2),
        "temporal_hour"       : ts.hour,
        "is_anomaly"          : 1,
    }


# ---------------------------------------------------------------------------
# Threat Vector 4 â€” Rogue Internal DBA
# ---------------------------------------------------------------------------
# Indicators:
#   â€¢ Actor role is dba or db_admin
#   â€¢ Target is a production database
#   â€¢ Action involves DDL (schema modification): ALTER TABLE, DROP COLUMN,
#     CREATE INDEX CONCURRENTLY (data exfil via side-channel), TRUNCATE, etc.
#   â€¢ No associated IT ticket (outside change management window)
#   â€¢ Execution strictly during off-hours (22:00â€“05:59)
# ---------------------------------------------------------------------------

TV4_DBA_ROLES = ["dba", "db_admin", "database_administrator", "db_superuser"]
TV4_DB_RESOURCES = [
    "core-banking-db-prod", "customer-pii-store-prod",
    "transaction-ledger-db-prod", "audit-trail-db-prod",
    "compliance-reporting-db-prod", "card-vault-db-prod",
    "settlement-db-prod", "fraud-analytics-db-prod",
]
TV4_DDL_ACTIONS = [
    "ALTER TABLE customers DROP COLUMN ssn_hash",
    "ALTER TABLE transactions ADD COLUMN shadow_copy TEXT",
    "DROP INDEX idx_audit_timestamp ON audit_log",
    "TRUNCATE TABLE fraud_event_log",
    "CREATE TABLE shadow_accounts AS SELECT * FROM accounts",
    "ALTER TABLE card_vault MODIFY COLUMN pan_encrypted VARCHAR(4000)",
    "DROP CONSTRAINT fk_account_customer ON transactions",
    "ALTER TABLE compliance_flags ADD COLUMN is_suppressed BOOLEAN DEFAULT TRUE",
    "CREATE INDEX CONCURRENTLY idx_ssn ON customers(ssn_hash)",
    "RENAME TABLE audit_log TO audit_log_bkp_2025",
    "ALTER TABLE users ADD COLUMN bypass_2fa TINYINT(1) DEFAULT 1",
    "DELETE FROM compliance_rules WHERE rule_id BETWEEN 1 AND 500",
]

def generate_tv4_anomaly() -> dict:
    """Generate one Rogue Internal DBA anomaly record."""
    ts = random_timestamp_offhours(BASELINE_START, BASELINE_END)
    return {
        "event_id"            : gen_event_id(),
        "timestamp"           : format_ts(ts),
        "threat_vector"       : "ROGUE_INTERNAL_DBA",
        "actor_id"            : gen_actor_id("DBA"),
        "actor_role"          : rng.choice(TV4_DBA_ROLES),
        "target_resource"     : rng.choice(TV4_DB_RESOURCES),
        "action_executed"     : rng.choice(TV4_DDL_ACTIONS),
        # Critical indicator: zero ticket association
        "associated_ticket_id": "NULL",
        # DDL operations take 100 ms â€“ 8 s on production databases
        "execution_time_delta": round(rng.uniform(100.0, 8_000.0), 3),
        # Schema changes carry low-medium data volume on their own
        "data_volume_kb"      : round(rng.uniform(0.5, 512.0), 2),
        "temporal_hour"       : ts.hour,
        "is_anomaly"          : 1,
    }


# ---------------------------------------------------------------------------
# Normal Baseline Row Generator
# ---------------------------------------------------------------------------

def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def gaussian(mean: float, std: float) -> float:
    """Box-Muller transform using seeded RNG for reproducibility."""
    u1 = rng.random()
    u2 = rng.random()
    z  = math.sqrt(-2.0 * math.log(max(u1, 1e-10))) * math.cos(2.0 * math.pi * u2)
    return mean + std * z


def generate_normal_row() -> dict:
    """Generate a single normal baseline banking infrastructure log record."""
    ts       = random_timestamp()
    exec_ms  = clamp(gaussian(NORMAL_EXEC_TIME_MEAN, NORMAL_EXEC_TIME_STD),
                     NORMAL_EXEC_TIME_MIN, NORMAL_EXEC_TIME_MAX)
    data_kb  = clamp(gaussian(NORMAL_DATA_VOL_MEAN, NORMAL_DATA_VOL_STD),
                     NORMAL_DATA_VOL_MIN, NORMAL_DATA_VOL_MAX)

    # ~85% of normal records carry a valid IT ticket
    has_ticket = rng.random() < 0.85
    ticket     = gen_ticket_id() if has_ticket else "NULL"

    return {
        "event_id"            : gen_event_id(),
        "timestamp"           : format_ts(ts),
        "threat_vector"       : NORMAL_THREAT_VECTOR,
        "actor_id"            : gen_actor_id("USR"),
        "actor_role"          : rng.choice(NORMAL_ACTOR_ROLES),
        "target_resource"     : rng.choice(NORMAL_RESOURCES),
        "action_executed"     : rng.choice(NORMAL_ACTIONS),
        "associated_ticket_id": ticket,
        "execution_time_delta": round(exec_ms, 3),
        "data_volume_kb"      : round(data_kb, 2),
        "temporal_hour"       : ts.hour,
        "is_anomaly"          : 0,
    }


# ---------------------------------------------------------------------------
# Dataset Assembly
# ---------------------------------------------------------------------------

def build_dataset() -> list[dict]:
    """
    Assemble the full synthetic dataset:
      â€¢ 10,000 normal baseline records
      â€¢ 50 adversarial anomaly records (across 4 threat vectors)
    Returns a shuffled list of row dicts.
    """
    print("[*] Generating normal baseline records â€¦")
    rows: list[dict] = [generate_normal_row() for _ in range(NUM_NORMAL_ROWS)]

    print("[*] Injecting adversarial anomalies â€¦")

    # Distribute 50 anomalies as: TV1=14, TV2=12, TV3=12, TV4=12
    tv1_count = NUM_ANOMALY_ROWS - (ANOMALY_PER_VECTOR * 3)  # 50 - 36 = 14

    for _ in range(tv1_count):
        rows.append(generate_tv1_anomaly())

    for _ in range(ANOMALY_PER_VECTOR):
        rows.append(generate_tv2_anomaly())

    for _ in range(ANOMALY_PER_VECTOR):
        rows.append(generate_tv3_anomaly())

    for _ in range(ANOMALY_PER_VECTOR):
        rows.append(generate_tv4_anomaly())

    print(f"[*] Total records assembled : {len(rows):,}")
    print(f"    +-- Normal (is_anomaly=0) : {NUM_NORMAL_ROWS:,}")
    print(f"    +-- Anomaly (is_anomaly=1): {NUM_ANOMALY_ROWS:,}")
    print(f"        +-- TV1 (API Abuse)    : {tv1_count}")
    print(f"        +-- TV2 (CI/CD Poison) : {ANOMALY_PER_VECTOR}")
    print(f"        +-- TV3 (Txn Fraud)    : {ANOMALY_PER_VECTOR}")
    print(f"        +-- TV4 (Rogue DBA)    : {ANOMALY_PER_VECTOR}")

    # Shuffle so anomalies are not clustered at the tail
    rng.shuffle(rows)
    return rows


# ---------------------------------------------------------------------------
# CSV Writer
# ---------------------------------------------------------------------------

def write_csv(rows: list[dict], filepath: str) -> None:
    """Write the dataset rows to a CSV file at the given path."""
    print(f"\n[*] Writing dataset to '{filepath}' â€¦")
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[âœ“] File saved successfully: {filepath}")


# ---------------------------------------------------------------------------
# Validation â€” Quick Sanity Check
# ---------------------------------------------------------------------------

def validate_dataset(rows: list[dict]) -> None:
    """Run lightweight post-generation assertions."""
    print("\n[*] Running dataset validation â€¦")

    total       = len(rows)
    anomalies   = [r for r in rows if r["is_anomaly"] == 1]
    normals     = [r for r in rows if r["is_anomaly"] == 0]

    assert total == NUM_NORMAL_ROWS + NUM_ANOMALY_ROWS, \
        f"Row count mismatch: expected {NUM_NORMAL_ROWS + NUM_ANOMALY_ROWS}, got {total}"

    assert len(anomalies) == NUM_ANOMALY_ROWS, \
        f"Anomaly count mismatch: expected {NUM_ANOMALY_ROWS}, got {len(anomalies)}"

    assert len(normals) == NUM_NORMAL_ROWS, \
        f"Normal count mismatch: expected {NUM_NORMAL_ROWS}, got {len(normals)}"

    # Verify all required columns are present in every row
    for col in CSV_COLUMNS:
        missing = sum(1 for r in rows if col not in r)
        assert missing == 0, f"Column '{col}' missing from {missing} rows"

    # Verify threat vectors are represented
    vectors_found = {r["threat_vector"] for r in anomalies}
    expected_vectors = {
        "THIRD_PARTY_FINTECH_API_ABUSE",
        "POISONED_CICD_PIPELINE",
        "HIGH_VOLUME_TRANSACTION_FRAUD",
        "ROGUE_INTERNAL_DBA",
    }
    assert expected_vectors.issubset(vectors_found), \
        f"Missing threat vectors: {expected_vectors - vectors_found}"

    # Verify TV1 anomalies have extreme data volumes (>= 10,000 KB)
    tv1_rows = [r for r in anomalies if r["threat_vector"] == "THIRD_PARTY_FINTECH_API_ABUSE"]
    assert all(r["data_volume_kb"] >= 10_000 for r in tv1_rows), \
        "TV1 anomaly data volume below expected threshold"

    # Verify TV2 anomalies are all off-hours and have NULL tickets
    tv2_rows = [r for r in anomalies if r["threat_vector"] == "POISONED_CICD_PIPELINE"]
    off_hours_set = set(list(range(22, 24)) + list(range(0, 6)))
    assert all(r["temporal_hour"] in off_hours_set for r in tv2_rows), \
        "TV2 anomaly found during business hours"
    assert all(r["associated_ticket_id"] == "NULL" for r in tv2_rows), \
        "TV2 anomaly has unexpected ticket ID"

    # Verify TV3 anomalies have sub-50 ms execution time
    tv3_rows = [r for r in anomalies if r["threat_vector"] == "HIGH_VOLUME_TRANSACTION_FRAUD"]
    assert all(r["execution_time_delta"] < 50.0 for r in tv3_rows), \
        "TV3 anomaly execution time exceeds sub-50 ms threshold"

    # Verify TV4 anomalies are all off-hours and have NULL tickets
    tv4_rows = [r for r in anomalies if r["threat_vector"] == "ROGUE_INTERNAL_DBA"]
    assert all(r["temporal_hour"] in off_hours_set for r in tv4_rows), \
        "TV4 anomaly found during business hours"
    assert all(r["associated_ticket_id"] == "NULL" for r in tv4_rows), \
        "TV4 anomaly has unexpected ticket ID"

    # Verify temporal_hour is consistent with the timestamp for all rows
    for r in rows:
        ts_hour = datetime.strptime(r["timestamp"], "%Y-%m-%dT%H:%M:%S").hour
        assert r["temporal_hour"] == ts_hour, \
            f"temporal_hour mismatch for event {r['event_id']}"

    print("[âœ“] All validation assertions passed.")

    # Print descriptive statistics for anomaly features
    print("\n-- Anomaly Feature Statistics ------------------------------------------")
    for vec in sorted(expected_vectors):
        vec_rows = [r for r in anomalies if r["threat_vector"] == vec]
        exec_times = [r["execution_time_delta"] for r in vec_rows]
        data_vols  = [r["data_volume_kb"]       for r in vec_rows]
        hours      = [r["temporal_hour"]         for r in vec_rows]
        print(f"\n  [{vec}]  (n={len(vec_rows)})")
        print(f"    execution_time_delta : min={min(exec_times):.3f} ms  "
              f"max={max(exec_times):.3f} ms  "
              f"mean={sum(exec_times)/len(exec_times):.3f} ms")
        print(f"    data_volume_kb       : min={min(data_vols):.2f} KB  "
              f"max={max(data_vols):.2f} KB  "
              f"mean={sum(data_vols)/len(data_vols):.2f} KB")
        print(f"    temporal_hour range  : {min(hours):02d}:xx â€“ {max(hours):02d}:xx")

    # Normal baseline stats
    n_exec = [r["execution_time_delta"] for r in normals]
    n_data = [r["data_volume_kb"]       for r in normals]
    print(f"\n  [NONE â€” Baseline]  (n={len(normals):,})")
    print(f"    execution_time_delta : min={min(n_exec):.3f} ms  "
          f"max={max(n_exec):.3f} ms  "
          f"mean={sum(n_exec)/len(n_exec):.3f} ms")
    print(f"    data_volume_kb       : min={min(n_data):.2f} KB  "
          f"max={max(n_data):.2f} KB  "
          f"mean={sum(n_data)/len(n_data):.2f} KB")
    print("------------------------------------------------------------------------")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 68)
    print("  Banking Infrastructure Telemetry â€” Synthetic Dataset Generator")
    print(f"  Random Seed      : {RANDOM_SEED}")
    print(f"  Normal Records   : {NUM_NORMAL_ROWS:,}")
    print(f"  Anomaly Records  : {NUM_ANOMALY_ROWS}")
    print(f"  Output File      : {OUTPUT_FILE}")
    print("=" * 68)
    print()

    rows = build_dataset()
    validate_dataset(rows)
    write_csv(rows, OUTPUT_FILE)

    print("\n[âœ“] Dataset generation complete.")
    print(f"    Output â†’ {OUTPUT_FILE}")
    print("=" * 68)


if __name__ == "__main__":
    main()

