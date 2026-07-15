"""
==============================================================================
 main.py
 SentinalFlow AI — FastAPI Core Engine
 Author  : Enterprise Security Software Architect
 Version : 1.0.0

 Purpose
 -------
 Production-grade REST + WebSocket server that acts as the runtime inference
 core of SentinalFlow AI.  On startup it loads the pre-trained Isolation
 Forest pipeline and feature-mapping artefacts produced by train.py, then
 exposes two primary endpoints:

   POST /api/v1/analyze
       Accepts a raw telemetry event JSON payload, engineers the 8-feature
       vector, runs the Isolation Forest pipeline, returns a structured
       enriched response with anomaly_score + action_blocked, and
       simultaneously broadcasts the result to all live WebSocket clients.

   WS   /ws/stream
       Persistent WebSocket channel consumed by the React frontend.  Every
       analyze call pushes the enriched event payload here in real-time.

 Additional endpoints
 --------------------
   GET  /health                 -- liveness + model-readiness check
   GET  /api/v1/model/info      -- artefact metadata (hyperparams, schema)
   GET  /api/v1/stats           -- rolling session statistics
   GET  /docs                   -- interactive Swagger UI (auto-generated)

 Architecture Notes
 ------------------
   * Artefacts are loaded once at startup into module-level singletons and
     shared across all requests with zero I/O overhead at inference time.
   * The ConnectionManager is thread-safe for asyncio's single-threaded
     event loop; broadcasting is done with asyncio.gather() over all live
     WebSocket connections so a single slow client cannot block others.
   * Anomaly scores are normalised to [0.0, 1.0] using the decision
     function threshold boundary so downstream consumers receive a
     human-interpretable confidence value rather than a raw IsoForest score.
   * CORS is fully open for localhost origins on any port to support hot-
     reloading React dev servers during development while keeping the header
     surface explicit.

==============================================================================
"""

from __future__ import annotations

import asyncio
import csv
import logging
import math
import os
import random
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import uvicorn
from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s  [%(levelname)-8s]  %(name)s  —  %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("sentinalflow.api")

# ---------------------------------------------------------------------------
# Artefact Paths  (resolved relative to this file so the server can be
# invoked from any working directory)
# ---------------------------------------------------------------------------

from pathlib import Path

BASE_DIR: Path      = Path(__file__).resolve().parent
ARTEFACT_DIR: Path  = BASE_DIR / "sentinel_artefacts"
MODEL_PATH: Path    = ARTEFACT_DIR / "sentinel_model.pkl"
MAPPINGS_PATH: Path = ARTEFACT_DIR / "feature_mappings.joblib"
DATASET_PATH: Path  = BASE_DIR / "banking_telemetry_dataset.csv"

# ---------------------------------------------------------------------------
# Module-level Singletons  (populated at startup, read-only during serving)
# ---------------------------------------------------------------------------

_pipeline: Any = None          # sklearn Pipeline (StandardScaler + IsoForest)
_mappings: Dict = {}           # feature_mappings.joblib contents

# ---------------------------------------------------------------------------
# Off-hours definition (must match train.py exactly)
# ---------------------------------------------------------------------------

OFF_HOURS: frozenset = frozenset(range(22, 24)) | frozenset(range(0, 6))

# ---------------------------------------------------------------------------
# Anomaly-score normalisation constants
# ---------------------------------------------------------------------------
# IsolationForest.decision_function() returns values centred near 0.
# Normal samples cluster around –0.15 to –0.05; strong anomalies push
# toward +0.05 to +0.15.  We use a sigmoid scaled to map:
#   score <= –0.26  ->  normalised ~0.0  (very normal)
#   score == 0.0    ->  normalised ~0.5  (uncertain)
#   score >= +0.11  ->  normalised ~1.0  (strong anomaly)
# The sigmoid steepness k=30 gives a sharp but smooth boundary.

SIGMOID_STEEPNESS: float = 30.0
SIGMOID_MIDPOINT: float = -0.05    # raw score at which normalised = 0.5

# ---------------------------------------------------------------------------
# Action-block threshold  (normalised score >= this -> action_blocked = True)
# ---------------------------------------------------------------------------

BLOCK_THRESHOLD: float = 0.55

# ---------------------------------------------------------------------------
# Session-level rolling statistics  (in-memory, reset on server restart)
# ---------------------------------------------------------------------------

_session_stats: Dict[str, Any] = {
    "total_events_processed"   : 0,
    "total_anomalies_detected" : 0,
    "total_actions_blocked"    : 0,
    "anomalies_by_vector"      : {},   # populated from threat_vector field if present
    "server_start_utc"         : None,
}

# ---------------------------------------------------------------------------
# Simulation task registry
# Tracks in-flight asyncio Tasks spawned by /api/v1/trigger-simulation so
# that duplicate runs can be cancelled and the frontend notified on stop.
# ---------------------------------------------------------------------------

_sim_tasks: Dict[str, asyncio.Task] = {}   # key: sim_id -> asyncio.Task
_sim_active: bool = False                  # True while any simulation loop runs


# ===========================================================================
# SECTION 1 — APPLICATION LIFESPAN  (startup / shutdown)
# ===========================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    Runs startup logic before yield, shutdown logic after yield.
    """
    global _pipeline, _mappings, _session_stats

    log.info("=" * 64)
    log.info("  SentinalFlow AI — Starting up ...")
    log.info("=" * 64)

    # ── Load model artefacts ──────────────────────────────────────────────
    missing = [p for p in (MODEL_PATH, MAPPINGS_PATH) if not p.exists()]
    if missing:
        for p in missing:
            log.error("CRITICAL — Artefact not found: %s", p)
        log.error(
            "Run train.py to generate the artefacts before starting the server."
        )
        log.error("Server cannot start without trained artefacts. Halting.")
        # Raise SystemExit so uvicorn exits with a non-zero code
        raise SystemExit(1)

    log.info("Loading sentinel_model.pkl ...")
    _pipeline = joblib.load(MODEL_PATH)
    log.info(
        "  Pipeline loaded: %s",
        " -> ".join(name for name, _ in _pipeline.steps),
    )

    log.info("Loading feature_mappings.joblib ...")
    _mappings = joblib.load(MAPPINGS_PATH)
    log.info(
        "  Mappings loaded: %d actor roles, %d resources, %d actions",
        len(_mappings["actor_role_risk_map"]),
        len(_mappings["target_resource_criticality_map"]),
        len(_mappings["action_danger_map"]),
    )

    _session_stats["server_start_utc"] = datetime.now(timezone.utc).isoformat()
    log.info("Artefacts ready. Server accepting requests.")
    log.info("=" * 64)

    yield  # ── application runs here ──────────────────────────────────────

    log.info("SentinalFlow AI shutting down. Bye.")


# ===========================================================================
# SECTION 2 — FASTAPI APPLICATION INSTANCE
# ===========================================================================

app = FastAPI(
    title="SentinalFlow AI",
    description=(
        "Real-time banking infrastructure telemetry anomaly detection engine. "
        "Powered by an Isolation Forest trained on synthetic adversarial threat "
        "vectors: Fintech API Abuse, CI/CD Poisoning, Transaction Fraud, and "
        "Rogue DBA activity."
    ),
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS Middleware
# ---------------------------------------------------------------------------
# Resolution order (first match wins):
#   1. CORS_ALLOW_ALL=true  env-var  → wildcard "*" (safest for Render/preview)
#   2. CORS_ORIGINS         env-var  → comma-separated list of allowed origins
#   3. Hardcoded defaults   → localhost ports + any *.vercel.app domain
#
# For Render + Vercel deployment set TWO env-vars on the Render dashboard:
#   CORS_ORIGINS=https://your-app.vercel.app,https://custom-domain.com
# Or to allow every origin during early development:
#   CORS_ALLOW_ALL=true
# ---------------------------------------------------------------------------

_CORS_ALLOW_ALL: bool = os.getenv("CORS_ALLOW_ALL", "true").lower() == "true"

if _CORS_ALLOW_ALL:
    # Wildcard — allow every origin (use only during development / preview)
    CORS_ORIGINS: List[str] = ["*"]
    _cors_credentials = False          # credentials cannot be used with "*"
else:
    # Build origin list from env-var, falling back to safe localhost defaults
    _env_origins: str = os.getenv(
        "CORS_ORIGINS",
        ",".join([
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8080",
        ])
    )
    CORS_ORIGINS = [o.strip() for o in _env_origins.split(",") if o.strip()]
    _cors_credentials = True

log.info(
    "CORS policy: allow_all=%s  origins=%s",
    _CORS_ALLOW_ALL,
    CORS_ORIGINS if not _CORS_ALLOW_ALL else ["*"],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = CORS_ORIGINS,
    allow_credentials = _cors_credentials,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
    expose_headers    = ["*"],
)


# ===========================================================================
# SECTION 3 — WEBSOCKET CONNECTION MANAGER
# ===========================================================================

class ConnectionManager:
    """
    Manages a registry of active WebSocket connections.

    Design
    ------
    * Connections are stored in a plain list guarded by an asyncio.Lock so
      that concurrent connect / disconnect events during a broadcast do not
      corrupt the list.
    * broadcast() uses asyncio.gather() with return_exceptions=True so that
      a single broken client (network drop mid-send) does not raise and
      abort delivery to the remaining healthy connections.
    * Stale / closed connections are pruned after each broadcast cycle.
    """

    def __init__(self) -> None:
        self._connections: List[WebSocket] = []
        self._lock: asyncio.Lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        log.info(
            "WebSocket client connected. Active connections: %d",
            len(self._connections),
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            try:
                self._connections.remove(websocket)
            except ValueError:
                pass  # already removed during a broadcast prune
        log.info(
            "WebSocket client disconnected. Active connections: %d",
            len(self._connections),
        )

    async def broadcast(self, payload: Dict[str, Any]) -> None:
        """
        Send a JSON payload to every currently connected WebSocket client.
        Prunes clients that fail to receive the message.
        """
        if not self._connections:
            return  # fast path — no clients, skip serialisation

        import json
        message = json.dumps(payload, default=str)
        dead_sockets: List[WebSocket] = []

        async with self._lock:
            snapshot = list(self._connections)  # iterate a copy under lock

        results = await asyncio.gather(
            *[ws.send_text(message) for ws in snapshot],
            return_exceptions=True,
        )

        for ws, result in zip(snapshot, results):
            if isinstance(result, Exception):
                log.warning(
                    "WebSocket send failed (%s) — removing dead connection.",
                    type(result).__name__,
                )
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                for ws in dead_sockets:
                    try:
                        self._connections.remove(ws)
                    except ValueError:
                        pass

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Singleton manager shared across all routes
manager = ConnectionManager()


# ===========================================================================
# SECTION 4 — PYDANTIC REQUEST / RESPONSE SCHEMAS
# ===========================================================================

class TelemetryEvent(BaseModel):
    """
    Incoming telemetry event payload — mirrors the CSV columns generated by
    mock_generator.py, minus the label (`is_anomaly`) and any derived fields
    that are computed server-side.

    All string fields are stripped of leading/trailing whitespace before
    validation to handle minor formatting differences from upstream sources.
    """

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique event identifier. Auto-generated if omitted.",
        examples=["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S"
        ),
        description="ISO-8601 event timestamp. Auto-generated if omitted.",
        examples=["2025-06-15T03:47:22"],
    )
    actor_id: str = Field(
        ...,
        description="Unique identifier of the acting entity (user/service/bot).",
        examples=["USR-4821", "EXT-9913", "DBA-3071"],
    )
    actor_role: str = Field(
        ...,
        description="Role or job function of the acting entity.",
        examples=["analyst", "dba", "fintech_partner"],
    )
    target_resource: str = Field(
        ...,
        description="The infrastructure resource being accessed or modified.",
        examples=["payment-gateway", "core-banking-db-prod", "libcrypto-core"],
    )
    action_executed: str = Field(
        ...,
        description="The specific operation performed on the target resource.",
        examples=[
            "GET /api/v2/accounts",
            "ALTER TABLE customers DROP COLUMN ssn_hash",
            "COMMIT src/crypto/aes_gcm.py -- modify key derivation logic",
        ],
    )
    associated_ticket_id: str = Field(
        default="NULL",
        description="ITSM change/incident ticket ID. 'NULL' if absent.",
        examples=["INC-482910", "NULL"],
    )
    execution_time_delta: float = Field(
        ...,
        ge=0.0,
        description="Operation duration in milliseconds.",
        examples=[312.5, 4.2, 7200.0],
    )
    data_volume_kb: float = Field(
        ...,
        ge=0.0,
        description="Data transferred/accessed in kilobytes.",
        examples=[84.3, 102400.0, 2.1],
    )
    temporal_hour: int = Field(
        ...,
        ge=0,
        le=23,
        description="Hour of day (0–23) extracted from the event timestamp.",
        examples=[9, 2, 23],
    )

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator("actor_role", "target_resource", "action_executed",
                     "actor_id", "associated_ticket_id", mode="before")
    @classmethod
    def strip_whitespace(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.strip()
        return v

    @field_validator("temporal_hour", mode="before")
    @classmethod
    def coerce_temporal_hour(cls, v: Any) -> int:
        return int(v)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "event_id"             : "f3a12bc0-1234-4abc-def0-000000000001",
                    "timestamp"            : "2025-09-04T02:11:44",
                    "actor_id"             : "DBA-7731",
                    "actor_role"           : "dba",
                    "target_resource"      : "core-banking-db-prod",
                    "action_executed"      : "ALTER TABLE customers DROP COLUMN ssn_hash",
                    "associated_ticket_id" : "NULL",
                    "execution_time_delta" : 5820.0,
                    "data_volume_kb"       : 128.4,
                    "temporal_hour"        : 2,
                },
                {
                    "event_id"             : "a9b8c7d6-5432-4fed-cba9-000000000002",
                    "timestamp"            : "2025-03-11T10:05:30",
                    "actor_id"             : "USR-3344",
                    "actor_role"           : "analyst",
                    "target_resource"      : "reporting-dashboard",
                    "action_executed"      : "GET /api/v2/reports/daily",
                    "associated_ticket_id" : "INC-224819",
                    "execution_time_delta" : 280.0,
                    "data_volume_kb"       : 62.0,
                    "temporal_hour"        : 10,
                },
            ]
        }
    }


class AnalysisResponse(BaseModel):
    """
    Enriched response returned by POST /api/v1/analyze.
    Contains the original event metadata plus model-computed fields.
    """

    # ── Original metadata passthrough ─────────────────────────────────────
    event_id              : str
    timestamp             : str
    actor_id              : str
    actor_role            : str
    target_resource       : str
    action_executed       : str
    associated_ticket_id  : str
    execution_time_delta  : float
    data_volume_kb        : float
    temporal_hour         : int

    # ── Engineered features (exposed for frontend visualisation) ──────────
    actor_role_risk       : int   = Field(description="Risk score [1-10] for actor_role")
    target_criticality    : int   = Field(description="Criticality score [1-10] for target_resource")
    action_danger         : int   = Field(description="Danger score [1-10] for action_executed")
    off_hours_flag        : int   = Field(description="1 if event occurred during off-hours (22:00–05:59)")
    risk_x_criticality    : int   = Field(description="Compound actor × resource risk score [1-100]")

    # ── Model outputs ─────────────────────────────────────────────────────
    anomaly_score         : float = Field(
        description="Normalised anomaly confidence [0.0=normal, 1.0=anomalous]"
    )
    action_blocked        : bool  = Field(
        description="True if anomaly_score exceeds the block threshold"
    )
    raw_decision_score    : float = Field(
        description="Raw IsolationForest decision_function output (unnormalised)"
    )
    model_prediction      : int   = Field(
        description="Model label: 1=anomaly, 0=normal"
    )

    # ── Server-side metadata ──────────────────────────────────────────────
    processed_at_utc      : str   = Field(
        description="Server-side UTC timestamp when this event was processed"
    )
    sentinalflow_version  : str   = "1.1.0"


class HealthResponse(BaseModel):
    status            : str
    model_loaded      : bool
    mappings_loaded   : bool
    active_ws_clients : int
    server_start_utc  : Optional[str]
    uptime_seconds    : Optional[float]


class ModelInfoResponse(BaseModel):
    pipeline_steps    : List[str]
    feature_columns   : List[str]
    hyperparameters   : Dict[str, Any]
    scaler_stats      : Dict[str, Any]
    schema            : Dict[str, Any]
    artefact_paths    : Dict[str, str]


class StatsResponse(BaseModel):
    total_events_processed   : int
    total_anomalies_detected : int
    total_actions_blocked    : int
    detection_rate_pct       : float
    block_rate_pct           : float
    active_ws_clients        : int
    server_start_utc         : Optional[str]


# ---------------------------------------------------------------------------
# Simulation schemas
# ---------------------------------------------------------------------------

class SimulationRequest(BaseModel):
    """
    Payload for POST /api/v1/trigger-simulation.

    Fields
    ------
    state : 'normal' | 'attack' | 'stop'
        * normal — stream randomly sampled baseline rows at `interval_seconds`
        * attack — stream curated high-severity anomaly rows
        * stop   — cancel any running simulation immediately
    count : int (default 30)
        Number of events to emit before the loop self-terminates.
        Pass 0 for an indefinite stream (stop it with state='stop').
    interval_seconds : float (default 0.5)
        Pause between each broadcast, in seconds.
    """
    state            : str   = Field(..., pattern="^(normal|attack|stop)$",
                                      description="'normal', 'attack', or 'stop'")
    count            : int   = Field(default=30, ge=0, le=500,
                                      description="Events to emit (0 = indefinite)")
    interval_seconds : float = Field(default=0.5, ge=0.05, le=10.0,
                                      description="Seconds between broadcasts")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"state": "normal",  "count": 30, "interval_seconds": 0.5},
                {"state": "attack",  "count": 5,  "interval_seconds": 1.2},
                {"state": "stop",    "count": 0,  "interval_seconds": 0.5},
            ]
        }
    }


class SimulationResponse(BaseModel):
    sim_id           : str
    state            : str
    events_scheduled : int
    interval_seconds : float
    message          : str


# ===========================================================================
# SECTION 5 — FEATURE ENGINEERING HELPER
# ===========================================================================

def _build_feature_vector(event: TelemetryEvent) -> tuple[np.ndarray, dict]:
    """
    Transform a validated TelemetryEvent into the 8-dimensional feature
    vector expected by the trained Isolation Forest pipeline.

    Feature order must exactly match `feature_columns` in feature_mappings:
        [actor_role_risk, target_criticality, action_danger,
         execution_time_delta, data_volume_kb, temporal_hour,
         off_hours_flag, risk_x_criticality]

    Parameters
    ----------
    event : TelemetryEvent
        Validated Pydantic model instance from the incoming JSON payload.

    Returns
    -------
    X : np.ndarray of shape (1, 8)
        Ready-to-score feature array.
    feature_dict : dict
        Human-readable mapping of feature names to computed values,
        included in the API response for frontend visualisation.
    """
    # ── Categorical risk-footprint encoding ───────────────────────────────
    actor_role_risk: int = _mappings["actor_role_risk_map"].get(
        event.actor_role,
        _mappings["default_risk_score"],
    )
    target_criticality: int = _mappings["target_resource_criticality_map"].get(
        event.target_resource,
        _mappings["default_criticality_score"],
    )
    action_danger: int = _mappings["action_danger_map"].get(
        event.action_executed,
        _mappings["default_action_danger_score"],
    )

    # ── Continuous features ───────────────────────────────────────────────
    execution_time_delta: float = event.execution_time_delta
    data_volume_kb: float = event.data_volume_kb
    temporal_hour: int = event.temporal_hour

    # ── Engineered interaction features ───────────────────────────────────
    off_hours_flag: int = 1 if temporal_hour in OFF_HOURS else 0
    risk_x_criticality: int = actor_role_risk * target_criticality

    # ── Assemble in the exact column order used during training ───────────
    feature_values: List[float] = [
        float(actor_role_risk),
        float(target_criticality),
        float(action_danger),
        float(execution_time_delta),
        float(data_volume_kb),
        float(temporal_hour),
        float(off_hours_flag),
        float(risk_x_criticality),
    ]

    X: np.ndarray = np.array(feature_values, dtype=np.float64).reshape(1, -1)

    feature_dict: dict = {
        "actor_role_risk"     : actor_role_risk,
        "target_criticality"  : target_criticality,
        "action_danger"       : action_danger,
        "off_hours_flag"      : off_hours_flag,
        "risk_x_criticality"  : risk_x_criticality,
    }

    return X, feature_dict


def _normalise_score(raw_decision_score: float) -> float:
    """
    Map a raw IsolationForest decision_function output to [0.0, 1.0].

    IsolationForest.decision_function() is NEGATED in the pipeline
    (train.py calls -pipeline.decision_function(X)), so:
        * Higher raw_decision_score → more anomalous.

    We apply a sigmoid:
        normalised = 1 / (1 + exp(-k * (x - midpoint)))

    where k=30 provides a crisp but smooth transition around the midpoint.
    """
    exponent = -SIGMOID_STEEPNESS * (raw_decision_score - SIGMOID_MIDPOINT)
    # Clamp exponent to avoid math overflow for extreme inputs
    exponent = max(-500.0, min(500.0, exponent))
    normalised = 1.0 / (1.0 + math.exp(exponent))
    return round(float(normalised), 6)


# ===========================================================================
# SECTION 6 — ROUTES
# ===========================================================================

# ---------------------------------------------------------------------------
# 6.1  Health Check
# ---------------------------------------------------------------------------

_server_start_monotonic: float = 0.0

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness and model-readiness check",
    tags=["Infrastructure"],
)
async def health_check() -> HealthResponse:
    """
    Returns HTTP 200 with model readiness flags.
    Used by load balancers and container orchestrators.
    """
    import time
    uptime = (
        time.monotonic() - _server_start_monotonic
        if _server_start_monotonic
        else None
    )
    return HealthResponse(
        status="healthy" if _pipeline is not None else "degraded",
        model_loaded=_pipeline is not None,
        mappings_loaded=bool(_mappings),
        active_ws_clients=manager.active_count,
        server_start_utc=_session_stats.get("server_start_utc"),
        uptime_seconds=round(uptime, 2) if uptime is not None else None,
    )


# ---------------------------------------------------------------------------
# 6.2  Model Metadata
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/model/info",
    response_model=ModelInfoResponse,
    summary="Loaded artefact metadata and feature schema",
    tags=["Model"],
)
async def model_info() -> ModelInfoResponse:
    """
    Returns the training hyperparameters, feature column order, scaler
    statistics, and artefact file paths so frontend dashboards can display
    a live model provenance card.
    """
    if not _pipeline or not _mappings:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model artefacts are not loaded. Server may be starting up.",
        )
    return ModelInfoResponse(
        pipeline_steps=[name for name, _ in _pipeline.steps],
        feature_columns=_mappings.get("feature_columns", []),
        hyperparameters=_mappings.get("hyperparameters", {}),
        scaler_stats=_mappings.get("scaler_stats", {}),
        schema=_mappings.get("schema", {}),
        artefact_paths={
            "model"    : str(MODEL_PATH),
            "mappings" : str(MAPPINGS_PATH),
        },
    )


# ---------------------------------------------------------------------------
# 6.3  Session Statistics
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/stats",
    response_model=StatsResponse,
    summary="Rolling session statistics",
    tags=["Analytics"],
)
async def session_stats() -> StatsResponse:
    """
    Returns in-memory counters for events processed, anomalies detected,
    and actions blocked since server startup.  Resets on restart.
    """
    total  = _session_stats["total_events_processed"]
    anoms  = _session_stats["total_anomalies_detected"]
    blocks = _session_stats["total_actions_blocked"]

    return StatsResponse(
        total_events_processed   = total,
        total_anomalies_detected = anoms,
        total_actions_blocked    = blocks,
        detection_rate_pct       = round(100.0 * anoms / total, 4) if total else 0.0,
        block_rate_pct           = round(100.0 * blocks / total, 4) if total else 0.0,
        active_ws_clients        = manager.active_count,
        server_start_utc         = _session_stats.get("server_start_utc"),
    )


# ---------------------------------------------------------------------------
# 6.4  Core Analysis Endpoint  POST /api/v1/analyze
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a telemetry event for anomalous behaviour",
    tags=["Detection"],
    responses={
        200: {"description": "Event analyzed successfully."},
        503: {"description": "Model not loaded — server is starting up."},
        422: {"description": "Payload validation error."},
    },
)
async def analyze_event(event: TelemetryEvent) -> AnalysisResponse:
    """
    ## Primary Inference Endpoint

    Accepts a raw telemetry event, runs it through the full feature
    engineering + Isolation Forest pipeline, and returns:

    - **anomaly_score** `[0.0 – 1.0]`  — normalised anomaly confidence
    - **action_blocked** `bool`          — `true` if score ≥ block threshold
    - All original event metadata for frontend passthrough
    - Engineered feature values for visualisation and audit

    Simultaneously broadcasts the enriched result to all connected
    `/ws/stream` WebSocket clients.

    ### Score Interpretation
    | Score Range | Interpretation |
    |---|---|
    | 0.00 – 0.40 | Normal baseline behaviour |
    | 0.40 – 0.55 | Low-suspicion, monitor |
    | 0.55 – 0.75 | Elevated risk — action blocked |
    | 0.75 – 1.00 | High-confidence adversarial anomaly |
    """
    # ── Guard: ensure model is ready ─────────────────────────────────────
    if _pipeline is None or not _mappings:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model artefacts are not loaded. Retry after startup completes.",
        )

    # ── Feature engineering ───────────────────────────────────────────────
    X, feature_dict = _build_feature_vector(event)

    # ── Inference ─────────────────────────────────────────────────────────
    # pipeline.predict() returns {-1, +1}; remap to {1, 0}
    raw_pred: int = int(_pipeline.predict(X)[0])
    model_prediction: int = 1 if raw_pred == -1 else 0

    # decision_function(): lower (more negative) = more normal in sklearn's
    # convention.  We negate to match train.py's convention (higher = anomalous).
    raw_decision_score: float = float(-_pipeline.decision_function(X)[0])

    # ── Score normalisation ───────────────────────────────────────────────
    anomaly_score: float = _normalise_score(raw_decision_score)
    action_blocked: bool = anomaly_score >= BLOCK_THRESHOLD

    # ── Server-side timestamp ─────────────────────────────────────────────
    processed_at_utc: str = datetime.now(timezone.utc).isoformat()

    # ── Log the decision ──────────────────────────────────────────────────
    log.info(
        "event_id=%-38s  actor=%-28s  score=%.4f  blocked=%s",
        event.event_id,
        f"{event.actor_role}@{event.target_resource}",
        anomaly_score,
        action_blocked,
    )

    # ── Assemble response ─────────────────────────────────────────────────
    response_payload = AnalysisResponse(
        # Original metadata
        event_id              = event.event_id,
        timestamp             = event.timestamp,
        actor_id              = event.actor_id,
        actor_role            = event.actor_role,
        target_resource       = event.target_resource,
        action_executed       = event.action_executed,
        associated_ticket_id  = event.associated_ticket_id,
        execution_time_delta  = event.execution_time_delta,
        data_volume_kb        = event.data_volume_kb,
        temporal_hour         = event.temporal_hour,
        # Engineered features
        actor_role_risk       = feature_dict["actor_role_risk"],
        target_criticality    = feature_dict["target_criticality"],
        action_danger         = feature_dict["action_danger"],
        off_hours_flag        = feature_dict["off_hours_flag"],
        risk_x_criticality    = feature_dict["risk_x_criticality"],
        # Model outputs
        anomaly_score         = anomaly_score,
        action_blocked        = action_blocked,
        raw_decision_score    = round(raw_decision_score, 8),
        model_prediction      = model_prediction,
        # Server metadata
        processed_at_utc      = processed_at_utc,
    )

    # ── Update session statistics ─────────────────────────────────────────
    _session_stats["total_events_processed"] += 1
    if model_prediction == 1:
        _session_stats["total_anomalies_detected"] += 1
    if action_blocked:
        _session_stats["total_actions_blocked"] += 1

    # ── Broadcast to all live WebSocket clients (fire-and-forget) ────────
    broadcast_payload = response_payload.model_dump()
    asyncio.create_task(manager.broadcast(broadcast_payload))

    return response_payload


# ---------------------------------------------------------------------------
# 6.5  Simulation Engine — internal helpers
# ---------------------------------------------------------------------------

def _load_dataset_rows() -> tuple[List[Dict], List[Dict]]:
    """
    Read banking_telemetry_dataset.csv and split into normal / anomaly pools.
    Returns (normals, anomalies) — both are lists of raw CSV dicts.
    Raises RuntimeError if the file is missing or malformed.
    """
    if not DATASET_PATH.exists():
        raise RuntimeError(
            f"Dataset not found at {DATASET_PATH}. "
            "Run mock_generator.py first."
        )
    normals:   List[Dict] = []
    anomalies: List[Dict] = []
    with open(DATASET_PATH, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("is_anomaly") == "0":
                normals.append(row)
            elif row.get("is_anomaly") == "1":
                anomalies.append(row)
    return normals, anomalies


def _csv_row_to_event(row: Dict) -> TelemetryEvent:
    """Convert a raw CSV row dict into a validated TelemetryEvent."""
    return TelemetryEvent(
        event_id             = row.get("event_id", str(uuid.uuid4())),
        timestamp            = row.get("timestamp", ""),
        actor_id             = row.get("actor_id", "SIM-0000"),
        actor_role           = row.get("actor_role", "analyst"),
        target_resource      = row.get("target_resource", "reporting-dashboard"),
        action_executed      = row.get("action_executed", "GET /api/v2/reports"),
        associated_ticket_id = row.get("associated_ticket_id", "NULL"),
        execution_time_delta = float(row.get("execution_time_delta", 0.0)),
        data_volume_kb       = float(row.get("data_volume_kb", 0.0)),
        temporal_hour        = int(row.get("temporal_hour", 9)),
    )


async def _run_simulation_loop(
    sim_id           : str,
    pool             : List[Dict],
    count            : int,
    interval_seconds : float,
    threat_vector    : str,
) -> None:
    """
    Background coroutine — the actual simulation engine.

    Iterates `pool` in random order (shuffled once per run), scores each row
    through the Isolation Forest pipeline, and broadcasts the enriched
    AnalysisResponse payload to every connected WebSocket client.

    Terminates when:
      * `count` events have been emitted  (if count > 0)
      * the task is externally cancelled  (via state='stop' request)
      * the WebSocket hub has no clients  (optional early-exit guard)

    Parameters
    ----------
    sim_id           : unique identifier echoed back in broadcast frames
    pool             : list of CSV row dicts to draw events from
    count            : max events to emit (0 = run until cancelled)
    interval_seconds : asyncio.sleep duration between events
    threat_vector    : label injected into broadcast for frontend display
    """
    global _sim_active
    _sim_active = True

    # Shuffle pool so each run feels fresh
    shuffled = pool.copy()
    random.shuffle(shuffled)

    # Cycle through pool repeatedly if count > len(pool)
    def _pool_iter():
        idx = 0
        while True:
            yield shuffled[idx % len(shuffled)]
            idx += 1

    emitted = 0
    log.info(
        "[SIM %s] Starting simulation: state=%s  count=%d  interval=%.2fs  pool=%d rows",
        sim_id, threat_vector, count, interval_seconds, len(pool),
    )

    # Notify WebSocket clients that a simulation started
    await manager.broadcast({
        "type"           : "simulation_started",
        "sim_id"         : sim_id,
        "state"          : threat_vector,
        "count"          : count,
        "interval"       : interval_seconds,
        "server_time_utc": datetime.now(timezone.utc).isoformat(),
    })

    try:
        for row in _pool_iter():
            # Honour count limit (0 = indefinite)
            if count > 0 and emitted >= count:
                break

            # Build and score the event
            try:
                event = _csv_row_to_event(row)
            except Exception as parse_err:
                log.warning("[SIM %s] Row parse error: %s", sim_id, parse_err)
                continue

            X, feature_dict = _build_feature_vector(event)

            raw_pred          = int(_pipeline.predict(X)[0])
            model_prediction  = 1 if raw_pred == -1 else 0
            raw_decision_score = float(-_pipeline.decision_function(X)[0])
            anomaly_score     = _normalise_score(raw_decision_score)
            action_blocked    = anomaly_score >= BLOCK_THRESHOLD
            processed_at_utc  = datetime.now(timezone.utc).isoformat()

            # Build the enriched payload (same shape as AnalysisResponse)
            payload = {
                # ── Original metadata ──────────────────────────────────
                "event_id"             : event.event_id,
                "timestamp"            : event.timestamp,
                "actor_id"             : event.actor_id,
                "actor_role"           : event.actor_role,
                "target_resource"      : event.target_resource,
                "action_executed"      : event.action_executed,
                "associated_ticket_id" : event.associated_ticket_id,
                "execution_time_delta" : event.execution_time_delta,
                "data_volume_kb"       : event.data_volume_kb,
                "temporal_hour"        : event.temporal_hour,
                # ── Engineered features ────────────────────────────────
                "actor_role_risk"      : feature_dict["actor_role_risk"],
                "target_criticality"   : feature_dict["target_criticality"],
                "action_danger"        : feature_dict["action_danger"],
                "off_hours_flag"       : feature_dict["off_hours_flag"],
                "risk_x_criticality"   : feature_dict["risk_x_criticality"],
                # ── Model outputs ──────────────────────────────────────
                "anomaly_score"        : anomaly_score,
                "action_blocked"       : action_blocked,
                "raw_decision_score"   : round(raw_decision_score, 8),
                "model_prediction"     : model_prediction,
                # ── Server metadata ────────────────────────────────────
                "processed_at_utc"     : processed_at_utc,
                "sentinalflow_version" : "1.1.0",
                # ── Simulation metadata ────────────────────────────────
                "sim_id"               : sim_id,
                "threat_vector"        : row.get("threat_vector", "NONE"),
            }

            # Update session stats
            _session_stats["total_events_processed"] += 1
            if model_prediction == 1:
                _session_stats["total_anomalies_detected"] += 1
            if action_blocked:
                _session_stats["total_actions_blocked"] += 1

            # Broadcast to all connected WebSocket clients
            await manager.broadcast(payload)

            log.info(
                "[SIM %s] #%04d  score=%.4f  blocked=%s  actor=%s@%s",
                sim_id, emitted + 1, anomaly_score, action_blocked,
                event.actor_role, event.target_resource,
            )

            emitted += 1
            await asyncio.sleep(interval_seconds)

    except asyncio.CancelledError:
        log.info("[SIM %s] Simulation cancelled after %d events.", sim_id, emitted)
    except Exception as exc:
        log.error("[SIM %s] Simulation error: %s", sim_id, exc)
    finally:
        _sim_active = False
        _sim_tasks.pop(sim_id, None)
        # Notify WebSocket clients that the simulation ended
        await manager.broadcast({
            "type"           : "simulation_ended",
            "sim_id"         : sim_id,
            "events_emitted" : emitted,
            "server_time_utc": datetime.now(timezone.utc).isoformat(),
        })
        log.info("[SIM %s] Simulation ended. Events emitted: %d", sim_id, emitted)


# ---------------------------------------------------------------------------
# 6.6  Trigger Simulation  POST /api/v1/trigger-simulation
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/trigger-simulation",
    response_model=SimulationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger an internal self-contained telemetry simulation",
    tags=["Simulation"],
    responses={
        202: {"description": "Simulation started or stopped successfully."},
        503: {"description": "Model not loaded or dataset unavailable."},
        409: {"description": "A simulation is already running (use state='stop' first)."},
    },
)
async def trigger_simulation(req: SimulationRequest) -> SimulationResponse:
    """
    ## Self-Contained Simulation Engine

    Starts an internal asyncio background task that:
    1. Reads rows from `banking_telemetry_dataset.csv` on disk.
    2. Scores each row through the live Isolation Forest pipeline.
    3. Broadcasts the full enriched `AnalysisResponse`-shaped payload
       to every connected `/ws/stream` WebSocket client every
       `interval_seconds` seconds.

    This makes the backend completely self-contained for cloud deployment —
    no external `run_demo.py` process is needed.

    ### States
    | state    | Behaviour |
    |---|---|
    | `normal` | Streams baseline rows (is_anomaly == 0). Dashboard stays green. |
    | `attack` | Streams curated anomaly rows (is_anomaly == 1). Dashboard turns red. |
    | `stop`   | Cancels any in-flight simulation immediately. |

    ### Concurrency
    Only one simulation runs at a time.  Sending a second request while a
    simulation is active returns **HTTP 409** unless `state='stop'` is used.
    """
    global _sim_active

    # ── Guard: model ready ────────────────────────────────────────────────
    if _pipeline is None or not _mappings:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model artefacts are not loaded.",
        )

    # ── Handle stop request ───────────────────────────────────────────────
    if req.state == "stop":
        cancelled = 0
        for task in list(_sim_tasks.values()):
            if not task.done():
                task.cancel()
                cancelled += 1
        _sim_tasks.clear()
        _sim_active = False
        return SimulationResponse(
            sim_id           = "none",
            state            = "stop",
            events_scheduled = 0,
            interval_seconds = req.interval_seconds,
            message          = f"Stopped {cancelled} running simulation(s).",
        )

    # ── Guard: reject concurrent simulations ─────────────────────────────
    if _sim_active or any(not t.done() for t in _sim_tasks.values()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "A simulation is already running. "
                "POST {state: 'stop'} to cancel it first."
            ),
        )

    # ── Load dataset ──────────────────────────────────────────────────────
    try:
        normals, anomalies = _load_dataset_rows()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )

    if not normals and req.state == "normal":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dataset has no normal rows. Re-run mock_generator.py.",
        )
    if not anomalies and req.state == "attack":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dataset has no anomaly rows. Re-run mock_generator.py.",
        )

    # ── Select pool based on state ────────────────────────────────────────
    pool          = normals if req.state == "normal" else anomalies
    threat_vector = "BASELINE" if req.state == "normal" else "ATTACK_SIMULATION"

    # ── Launch background asyncio task ────────────────────────────────────
    sim_id = str(uuid.uuid4())[:8].upper()
    task   = asyncio.create_task(
        _run_simulation_loop(
            sim_id           = sim_id,
            pool             = pool,
            count            = req.count,
            interval_seconds = req.interval_seconds,
            threat_vector    = threat_vector,
        ),
        name=f"sim-{sim_id}",
    )
    _sim_tasks[sim_id] = task

    log.info(
        "Simulation %s launched: state=%s  count=%d  interval=%.2fs",
        sim_id, req.state, req.count, req.interval_seconds,
    )

    return SimulationResponse(
        sim_id           = sim_id,
        state            = req.state,
        events_scheduled = req.count,
        interval_seconds = req.interval_seconds,
        message          = (
            f"Simulation '{req.state}' started (id={sim_id}). "
            f"Broadcasting {req.count if req.count else 'unlimited'} events "
            f"every {req.interval_seconds}s over WebSocket."
        ),
    )


# ---------------------------------------------------------------------------
# 6.7  WebSocket Stream  WS /ws/stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket) -> None:
    """
    ## Real-Time Event Stream

    Persistent WebSocket channel that pushes every enriched analysis result
    to connected frontend clients immediately after `/api/v1/analyze` fires.

    ### Connection lifecycle
    1. Client connects → accepted, welcome frame sent.
    2. Server processes analyze calls → enriched JSON pushed to all clients.
    3. Client disconnects → removed from active registry without error.
    4. Client may send `{"type": "ping"}` frames; server echoes a pong to
       verify bi-directional health.

    ### Message format
    Every broadcast message is a JSON object conforming to `AnalysisResponse`.
    """
    await manager.connect(websocket)
    client_host = websocket.client.host if websocket.client else "unknown"
    log.info("WebSocket client accepted from %s", client_host)

    # Send a welcome handshake frame immediately upon connection
    welcome = {
        "type"               : "connected",
        "message"            : "SentinalFlow AI stream connected.",
        "active_connections" : manager.active_count,
        "server_time_utc"    : datetime.now(timezone.utc).isoformat(),
    }
    await websocket.send_json(welcome)

    try:
        while True:
            # Keep the connection alive by listening for client frames.
            # Clients may send pings; unrecognised frames are silently ignored.
            try:
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=30.0,     # 30 s read timeout — sends pong then loops
                )
                if isinstance(data, dict) and data.get("type") == "ping":
                    await websocket.send_json({
                        "type"           : "pong",
                        "server_time_utc": datetime.now(timezone.utc).isoformat(),
                    })
            except asyncio.TimeoutError:
                # No frame received in 30 s — send a keepalive ping
                try:
                    await websocket.send_json({
                        "type"           : "keepalive",
                        "server_time_utc": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    break  # socket is dead — exit loop
            except WebSocketDisconnect:
                break
            except Exception as exc:
                log.warning("WebSocket receive error: %s", exc)
                break

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)


# ===========================================================================
# SECTION 7 — GLOBAL EXCEPTION HANDLERS
# ===========================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception) -> JSONResponse:
    """
    Catch-all handler that prevents raw Python tracebacks from leaking to
    API consumers.  Logs the full traceback server-side.
    """
    import traceback
    log.error(
        "Unhandled exception on %s %s:\n%s",
        request.method,
        request.url.path,
        traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "error"  : "internal_server_error",
            "detail" : "An unexpected error occurred. Check server logs.",
        },
    )


# ===========================================================================
# SECTION 8 — ROOT REDIRECT & FAVICON SUPPRESSION
# ===========================================================================

@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse(content={
        "service"            : "SentinalFlow AI",
        "version"            : "1.1.0",
        "status"             : "online",
        "docs"               : "/docs",
        "health"             : "/health",
        "analyze"            : "POST /api/v1/analyze",
        "trigger_simulation" : "POST /api/v1/trigger-simulation",
        "ws_stream"          : "WS /ws/stream",
        "model_info"         : "/api/v1/model/info",
        "stats"              : "/api/v1/stats",
    })


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return JSONResponse(content={}, status_code=204)


# ===========================================================================
# SECTION 9 — STARTUP MONOTONIC REFERENCE
# ===========================================================================

@app.on_event("startup")
async def record_start_time() -> None:
    """Record the monotonic start time for uptime computation in /health."""
    import time
    global _server_start_monotonic
    _server_start_monotonic = time.monotonic()


# ===========================================================================
# SECTION 10 — ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,          # set True for development hot-reload
        log_level="info",
        access_log=True,
        workers=1,             # single worker — model state is in-process
    )
