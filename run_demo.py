"""
==============================================================================
 run_demo.py
 SentinalFlow AI — Adversary Emulation & Live Presentation Demo Runner
 Author  : Adversary Emulation QA Engineer
 Version : 1.0.0

 Purpose
 -------
 A standalone adversary-emulation automation script that stress-tests and
 live-showcases the SentinalFlow AI detection engine during presentations.

 It orchestrates a scripted attack scenario in three acts:

   ACT I   — Steady-State Baseline
             Fire 30 normal banking transactions at 0.5-second intervals so
             the SOC dashboard fills with healthy green PASSED cards.

   ACT II  — Attack Injection (configurable burst of 3-5 anomalies)
             Suddenly inject a curated sequence of adversarial events
             representing all four threat vectors — Rogue DBA DDL, massive
             Third-Party API bulk extraction, Transaction Fraud bypass, and
             CI/CD crypto-library poisoning — with a short pause between each
             so the audience can watch the dashboard cards flip to red.

   ACT III — System Recovery / Background Noise
             Resume normal transactions to show the model correctly reverts
             to green baseline, demonstrating low false-positive rate.

 Terminal Telemetry
 ------------------
 Every dispatched event prints a rich colour-coded status line containing:
   - Dispatch sequence number and act label
   - Event UUID
   - Threat vector classification
   - Actor role + target resource
   - Server HTTP status code
   - Returned anomaly_score + action_blocked flag
   - Running session totals (sent / anomalies detected / blocked)

 Usage
 -----
   python run_demo.py                    # default settings
   python run_demo.py --act1 50          # 50 normal events in Act I
   python run_demo.py --burst 5          # inject 5 anomalies in Act II
   python run_demo.py --act1 20 --act3 15 --burst 4 --delay 0.3
   python run_demo.py --no-color         # disable ANSI colors (CI/logging)

==============================================================================
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Optional dependency: requests ──────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[FATAL] 'requests' library is not installed.")
    print("        Run:  pip install requests")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR: Path = Path(__file__).resolve().parent
DATASET_PATH: Path = BASE_DIR / "banking_telemetry_dataset.csv"

API_BASE: str       = "http://localhost:8000"
ANALYZE_ENDPOINT    = f"{API_BASE}/api/v1/analyze"
HEALTH_ENDPOINT     = f"{API_BASE}/health"
STATS_ENDPOINT      = f"{API_BASE}/api/v1/stats"

# Default scenario pacing
DEFAULT_ACT1_COUNT: int   = 30      # normal events in Act I
DEFAULT_ACT3_COUNT: int   = 20      # normal events in Act III
DEFAULT_BURST_SIZE: int   = 4       # anomalies injected in Act II
DEFAULT_NORMAL_DELAY: float = 0.50  # seconds between normal events
DEFAULT_ATTACK_DELAY: float = 1.20  # seconds between attack events (dramatic pause)
DEFAULT_ACT_PAUSE: float    = 2.50  # seconds between acts

# HTTP session config
REQUEST_TIMEOUT: int = 10           # seconds per request
MAX_RETRIES: int     = 2

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour codes
# ─────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI colour/style helpers. Set USE_COLOR=False to disable globally."""
    USE_COLOR: bool = True

    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    BLINK   = "\033[5m"

    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"

    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_BLACK   = "\033[40m"

    @classmethod
    def apply(cls, text: str, *codes: str) -> str:
        if not cls.USE_COLOR:
            return text
        return "".join(codes) + text + cls.RESET

    @classmethod
    def strip_all(cls) -> None:
        cls.USE_COLOR = False


def col(text: str, *codes: str) -> str:
    return C.apply(text, *codes)


# ─────────────────────────────────────────────────────────────────────────────
# Threat Vector metadata (for display)
# ─────────────────────────────────────────────────────────────────────────────

VECTOR_DISPLAY: Dict[str, Dict] = {
    "NONE": {
        "label" : "Baseline",
        "icon"  : "[--]",
        "color" : (C.DIM, C.WHITE),
    },
    "ROGUE_INTERNAL_DBA": {
        "label" : "Rogue DBA",
        "icon"  : "[DB]",
        "color" : (C.BRIGHT_RED, C.BOLD),
    },
    "THIRD_PARTY_FINTECH_API_ABUSE": {
        "label" : "API Abuse",
        "icon"  : "[AP]",
        "color" : (C.BRIGHT_MAGENTA, C.BOLD),
    },
    "HIGH_VOLUME_TRANSACTION_FRAUD": {
        "label" : "Txn Fraud",
        "icon"  : "[TF]",
        "color" : (C.BRIGHT_RED, C.BOLD),
    },
    "POISONED_CICD_PIPELINE": {
        "label" : "CI/CD Poison",
        "icon"  : "[CI]",
        "color" : (C.BRIGHT_YELLOW, C.BOLD),
    },
}

def vector_display(vec: str) -> str:
    meta = VECTOR_DISPLAY.get(vec, {"label": vec[:12], "icon": "[??]", "color": (C.WHITE,)})
    return col(f"{meta['icon']} {meta['label']:<14}", *meta["color"])


# ─────────────────────────────────────────────────────────────────────────────
# Score colouring
# ─────────────────────────────────────────────────────────────────────────────

def score_color(score: float) -> str:
    pct = f"{score * 100:5.1f}%"
    if score < 0.60:
        return col(pct, C.BRIGHT_GREEN)
    elif score < 0.75:
        return col(pct, C.BRIGHT_YELLOW, C.BOLD)
    else:
        return col(pct, C.BRIGHT_RED, C.BOLD, C.BLINK)


def blocked_tag(blocked: bool) -> str:
    if blocked:
        return col(" [BLOCKED] ", C.BG_RED, C.BRIGHT_WHITE, C.BOLD)
    return col(" [  PASS  ] ", C.BG_GREEN, C.BLACK, C.BOLD)


def http_status_color(code: int) -> str:
    s = str(code)
    if code == 200:
        return col(s, C.BRIGHT_GREEN)
    elif code == 422:
        return col(s, C.BRIGHT_YELLOW)
    else:
        return col(s, C.BRIGHT_RED)


# ─────────────────────────────────────────────────────────────────────────────
# Print helpers
# ─────────────────────────────────────────────────────────────────────────────

DIVIDER   = col("=" * 76, C.DIM, C.BLUE)
SUBDIV    = col("-" * 76, C.DIM)
ACT_LINE  = col("*" * 76, C.BOLD, C.CYAN)


def banner() -> None:
    print()
    print(col("=" * 76, C.BOLD, C.BLUE))
    print(col("  SentinalFlow AI -- Adversary Emulation Demo Runner", C.BOLD, C.BRIGHT_CYAN))
    print(col("  Live Presentation Stress Test & Attack Scenario Playback", C.DIM, C.CYAN))
    print(col("=" * 76, C.BOLD, C.BLUE))
    print()


def act_header(act_num: int, title: str, description: str) -> None:
    print()
    print(ACT_LINE)
    print(col(f"  ACT {act_num} — {title}", C.BOLD, C.BRIGHT_CYAN))
    print(col(f"  {description}", C.DIM, C.CYAN))
    print(ACT_LINE)
    print()


def section(title: str) -> None:
    print()
    print(DIVIDER)
    print(col(f"  {title}", C.BOLD, C.WHITE))
    print(DIVIDER)


def event_log(
    seq         : int,
    act_label   : str,
    event_id    : str,
    vector      : str,
    actor_role  : str,
    target      : str,
    http_code   : int,
    score       : Optional[float],
    blocked     : Optional[bool],
    counters    : Dict[str, int],
    elapsed_ms  : float,
) -> None:
    """Print one richly-formatted event dispatch line."""

    # Sequence number + act label
    seq_tag   = col(f"#{seq:04d}", C.DIM, C.WHITE)
    act_tag   = col(f"[{act_label:^5}]", C.BOLD, C.BRIGHT_BLUE)

    # Event ID (first 8 chars)
    eid_short = col(event_id[:8] + "…", C.DIM, C.WHITE)

    # Vector
    vec_str   = vector_display(vector)

    # Actor → Target
    actor_str = col(f"{actor_role[:22]:<22}", C.BRIGHT_BLUE)
    arrow     = col("->", C.DIM)
    tgt_str   = col(f"{target[:30]:<30}", C.BRIGHT_CYAN)

    # HTTP status
    http_str  = http_status_color(http_code)

    # Score + block badge (may be None on error)
    if score is not None:
        score_str = score_color(score)
        block_str = blocked_tag(blocked)
    else:
        score_str = col("  ERR  ", C.BRIGHT_RED)
        block_str = col(" [ ??? ] ", C.BRIGHT_RED)

    # Elapsed
    elapsed_str = col(f"{elapsed_ms:6.0f}ms", C.DIM)

    # Session counters
    counter_str = col(
        f"sent={counters['sent']:4d}  detected={counters['detected']:3d}  blocked={counters['blocked']:3d}",
        C.DIM, C.WHITE,
    )

    line = (
        f"  {seq_tag} {act_tag} {eid_short}  "
        f"{vec_str}  "
        f"{actor_str} {arrow} {tgt_str}  "
        f"HTTP {http_str}  score={score_str} {block_str}  "
        f"{elapsed_str}  | {counter_str}"
    )
    print(line)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Session (with retry + connection pooling)
# ─────────────────────────────────────────────────────────────────────────────

def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total             = MAX_RETRIES,
        backoff_factor    = 0.5,
        status_forcelist  = [500, 502, 503, 504],
        allowed_methods   = ["POST", "GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ─────────────────────────────────────────────────────────────────────────────
# Dataset I/O
# ─────────────────────────────────────────────────────────────────────────────

def load_dataset(path: Path) -> Tuple[List[Dict], List[Dict]]:
    """
    Parse the CSV dataset and return two lists:
        normals   — rows where is_anomaly == '0'
        anomalies — rows where is_anomaly == '1'
    """
    if not path.exists():
        print(col(f"[FATAL] Dataset not found: {path}", C.BRIGHT_RED, C.BOLD))
        print(col("        Run mock_generator.py first.", C.DIM))
        sys.exit(1)

    normals:   List[Dict] = []
    anomalies: List[Dict] = []

    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if row.get("is_anomaly") == "0":
                normals.append(row)
            elif row.get("is_anomaly") == "1":
                anomalies.append(row)

    return normals, anomalies


def row_to_payload(row: Dict) -> Dict:
    """
    Convert a raw CSV row dict to the JSON payload schema expected by
    POST /api/v1/analyze  (strips 'is_anomaly', 'threat_vector'; casts types).
    """
    return {
        "event_id"             : row.get("event_id", ""),
        "timestamp"            : row.get("timestamp", ""),
        "actor_id"             : row.get("actor_id", ""),
        "actor_role"           : row.get("actor_role", ""),
        "target_resource"      : row.get("target_resource", ""),
        "action_executed"      : row.get("action_executed", ""),
        "associated_ticket_id" : row.get("associated_ticket_id", "NULL"),
        "execution_time_delta" : float(row.get("execution_time_delta", 0)),
        "data_volume_kb"       : float(row.get("data_volume_kb", 0)),
        "temporal_hour"        : int(row.get("temporal_hour", 0)),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Health check — verify FastAPI backend is reachable before starting
# ─────────────────────────────────────────────────────────────────────────────

def check_server_health(session: requests.Session) -> bool:
    """
    Hit GET /health and confirm model_loaded=True before the demo begins.
    Retries up to 3 times with increasing backoff.
    """
    print(col("  Checking FastAPI backend health...", C.DIM))
    for attempt in range(1, 4):
        try:
            r = session.get(HEALTH_ENDPOINT, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                model_ok    = data.get("model_loaded", False)
                mappings_ok = data.get("mappings_loaded", False)
                ws_clients  = data.get("active_ws_clients", 0)
                status_str  = data.get("status", "unknown")

                print(
                    f"  {col('Backend', C.BOLD)} : {col(API_BASE, C.BRIGHT_CYAN)}"
                    f"  status={col(status_str, C.BRIGHT_GREEN if status_str == 'healthy' else C.BRIGHT_RED)}"
                    f"  model={col(str(model_ok), C.BRIGHT_GREEN if model_ok else C.BRIGHT_RED)}"
                    f"  mappings={col(str(mappings_ok), C.BRIGHT_GREEN if mappings_ok else C.BRIGHT_RED)}"
                    f"  ws_clients={col(str(ws_clients), C.BRIGHT_BLUE)}"
                )
                if not model_ok or not mappings_ok:
                    print(col("  [WARN] Model or mappings not loaded — train.py may not have run.", C.BRIGHT_YELLOW))
                    return False
                return True
            else:
                print(col(f"  [Attempt {attempt}] HTTP {r.status_code} from health endpoint.", C.YELLOW))
        except requests.exceptions.ConnectionError:
            print(col(
                f"  [Attempt {attempt}] Cannot reach {API_BASE}. "
                f"Is main.py running? Retrying in {attempt * 2}s...",
                C.BRIGHT_YELLOW,
            ))
        except Exception as exc:
            print(col(f"  [Attempt {attempt}] Health check error: {exc}", C.BRIGHT_YELLOW))

        time.sleep(attempt * 2)

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Single event dispatch
# ─────────────────────────────────────────────────────────────────────────────

def dispatch_event(
    session   : requests.Session,
    row       : Dict,
    seq       : int,
    act_label : str,
    counters  : Dict[str, int],
) -> Optional[Dict]:
    """
    POST one telemetry event to /api/v1/analyze, print the telemetry line,
    and return the parsed JSON response (or None on error).
    """
    payload   = row_to_payload(row)
    vector    = row.get("threat_vector", "NONE")
    event_id  = row.get("event_id", "???")
    actor     = row.get("actor_role", "?")
    target    = row.get("target_resource", "?")

    t0 = time.perf_counter()
    http_code = 0
    score:   Optional[float] = None
    blocked: Optional[bool]  = None
    response_body: Optional[Dict] = None

    try:
        response = session.post(
            ANALYZE_ENDPOINT,
            json    = payload,
            timeout = REQUEST_TIMEOUT,
            headers = {"Content-Type": "application/json"},
        )
        http_code = response.status_code
        elapsed_ms = (time.perf_counter() - t0) * 1000

        if http_code == 200:
            response_body = response.json()
            score   = response_body.get("anomaly_score")
            blocked = response_body.get("action_blocked", False)

            # Update counters
            counters["sent"]     += 1
            if score is not None and score >= 0.60:
                counters["detected"] += 1
            if blocked:
                counters["blocked"] += 1
        else:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            counters["sent"] += 1
            counters["errors"] += 1

    except requests.exceptions.ConnectionError:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        http_code  = 0
        counters["errors"] += 1
        print(col(
            f"\n  [ERROR] Connection refused on event #{seq}. "
            "Is the FastAPI server still running?\n",
            C.BRIGHT_RED, C.BOLD,
        ))

    except requests.exceptions.Timeout:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        http_code  = 408
        counters["errors"] += 1
        print(col(f"\n  [TIMEOUT] Request #{seq} exceeded {REQUEST_TIMEOUT}s.\n", C.YELLOW))

    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        http_code  = -1
        counters["errors"] += 1
        print(col(f"\n  [EXCEPTION] #{seq}: {exc}\n", C.BRIGHT_RED))

    event_log(
        seq        = seq,
        act_label  = act_label,
        event_id   = event_id,
        vector     = vector,
        actor_role = actor,
        target     = target,
        http_code  = http_code,
        score      = score,
        blocked    = blocked,
        counters   = counters,
        elapsed_ms = elapsed_ms,
    )

    return response_body


# ─────────────────────────────────────────────────────────────────────────────
# Attack-burst selector — curated for maximum visual impact
# ─────────────────────────────────────────────────────────────────────────────

# Preferred attack ordering for Act II — covers all 4 threat vectors with
# the most visually distinctive examples first
PREFERRED_VECTOR_ORDER = [
    "ROGUE_INTERNAL_DBA",
    "THIRD_PARTY_FINTECH_API_ABUSE",
    "HIGH_VOLUME_TRANSACTION_FRAUD",
    "POISONED_CICD_PIPELINE",
    "ROGUE_INTERNAL_DBA",            # second DBA hit for dramatic re-emphasis
]

def select_attack_burst(
    anomalies     : List[Dict],
    burst_size    : int,
    random_seed   : int = 99,
) -> List[Dict]:
    """
    Select `burst_size` anomaly rows for Act II, prioritising diversity
    across all four threat vectors in the preferred dramatic order.

    Falls back to random selection if a preferred vector has no rows.
    """
    rng = random.Random(random_seed)

    # Group anomalies by threat vector
    by_vector: Dict[str, List[Dict]] = {}
    for row in anomalies:
        v = row.get("threat_vector", "NONE")
        by_vector.setdefault(v, []).append(row)

    selected: List[Dict] = []
    for vec in PREFERRED_VECTOR_ORDER:
        if len(selected) >= burst_size:
            break
        pool = by_vector.get(vec, [])
        if pool:
            # Pick the most "extreme" row by data_volume_kb or lowest exec_time
            if vec in ("THIRD_PARTY_FINTECH_API_ABUSE",):
                # Highest data volume for maximum visual impact
                pick = max(pool, key=lambda r: float(r.get("data_volume_kb", 0)))
            elif vec in ("HIGH_VOLUME_TRANSACTION_FRAUD",):
                # Lowest execution time — sub-second bypass
                pick = min(pool, key=lambda r: float(r.get("execution_time_delta", 9999)))
            elif vec == "ROGUE_INTERNAL_DBA":
                # Highest risk_x_criticality proxy: db_admin on core-banking
                prio = [r for r in pool if "DROP" in r.get("action_executed", "") or
                                           "TRUNCATE" in r.get("action_executed", "") or
                                           "shadow" in r.get("action_executed", "")]
                pick = prio[0] if prio else rng.choice(pool)
            else:
                # POISONED_CICD: bcrypt->MD5 or AES modification
                prio = [r for r in pool if "bcrypt" in r.get("action_executed", "") or
                                           "aes_gcm" in r.get("action_executed", "")]
                pick = prio[0] if prio else rng.choice(pool)
            selected.append(pick)

    # Pad with random anomalies if we still need more
    if len(selected) < burst_size:
        remaining = [r for r in anomalies if r not in selected]
        rng.shuffle(remaining)
        selected.extend(remaining[:burst_size - len(selected)])

    return selected[:burst_size]


# ─────────────────────────────────────────────────────────────────────────────
# Summary printer
# ─────────────────────────────────────────────────────────────────────────────

def print_session_summary(
    counters    : Dict[str, int],
    start_time  : float,
    server_stats: Optional[Dict],
) -> None:
    """Print a final session summary table after all acts complete."""
    elapsed  = time.perf_counter() - start_time
    mins, s  = divmod(int(elapsed), 60)

    section("DEMO SESSION SUMMARY")
    print()

    rows = [
        ("Events Dispatched",        counters["sent"],     C.BRIGHT_BLUE),
        ("Anomalies Detected",        counters["detected"], C.BRIGHT_YELLOW),
        ("Actions Blocked",           counters["blocked"],  C.BRIGHT_RED),
        ("Request Errors",            counters["errors"],   C.BRIGHT_RED if counters["errors"] else C.DIM),
        ("Session Duration",          f"{mins}m {s:02d}s",  C.WHITE),
    ]

    if counters["sent"] > 0:
        det_rate  = 100.0 * counters["detected"] / counters["sent"]
        blk_rate  = 100.0 * counters["blocked"]  / counters["sent"]
        rows += [
            ("Detection Rate",  f"{det_rate:.1f}%", C.BRIGHT_YELLOW),
            ("Block Rate",      f"{blk_rate:.1f}%", C.BRIGHT_RED),
        ]

    col_w = max(len(r[0]) for r in rows) + 2
    for label, value, color in rows:
        print(
            f"  {col(label + ':', C.DIM, C.WHITE):<{col_w + 10}}"
            f"  {col(str(value), color, C.BOLD)}"
        )

    if server_stats:
        print()
        print(col("  Server-side stats (from GET /api/v1/stats):", C.DIM))
        print(f"    total_events_processed   : {col(str(server_stats.get('total_events_processed', '?')), C.BRIGHT_BLUE)}")
        print(f"    total_anomalies_detected : {col(str(server_stats.get('total_anomalies_detected', '?')), C.BRIGHT_YELLOW)}")
        print(f"    total_actions_blocked    : {col(str(server_stats.get('total_actions_blocked', '?')), C.BRIGHT_RED)}")
        print(f"    detection_rate_pct       : {col(str(server_stats.get('detection_rate_pct', '?')) + '%', C.BRIGHT_YELLOW)}")

    print()
    print(DIVIDER)


# ─────────────────────────────────────────────────────────────────────────────
# Countdown printer (shows audience what's coming)
# ─────────────────────────────────────────────────────────────────────────────

def countdown(seconds: float, message: str) -> None:
    """Display a live countdown bar for dramatic pauses between acts."""
    if seconds <= 0:
        return
    steps    = max(int(seconds * 4), 1)  # ~4 ticks per second
    interval = seconds / steps
    bar_w    = 30

    for i in range(steps + 1):
        filled = int(bar_w * i / steps)
        bar    = "#" * filled + "." * (bar_w - filled)
        remain = seconds - (i * interval)
        line   = f"\r  {col(message, C.DIM, C.CYAN)}  [{col(bar, C.BRIGHT_BLUE)}]  {remain:.1f}s  "
        sys.stdout.write(line)
        sys.stdout.flush()
        if i < steps:
            time.sleep(interval)

    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Column header
# ─────────────────────────────────────────────────────────────────────────────

def print_feed_header() -> None:
    """Print the column label row above the event feed."""
    print(col(
        f"  {'#SEQ':>6}  {'ACT':^7}  {'EVENT-ID':^10}  "
        f"{'VECTOR':^20}  {'ACTOR':^22}    {'TARGET':^30}  "
        f"{'HTTP':^4}  {'SCORE':^7}  {'STATUS':^20}  "
        f"{'ELAPSED':>8}  | SESSION COUNTERS",
        C.DIM, C.BLUE,
    ))
    print(SUBDIV)


# ─────────────────────────────────────────────────────────────────────────────
# Demo run sequence
# ─────────────────────────────────────────────────────────────────────────────

def run_demo(
    normals     : List[Dict],
    anomalies   : List[Dict],
    act1_count  : int,
    act3_count  : int,
    burst_size  : int,
    normal_delay: float,
    attack_delay: float,
    act_pause   : float,
    random_seed : int,
) -> Dict[str, int]:
    """
    Orchestrate the three-act demo sequence and return final counters.

    Act I   — Steady green baseline (act1_count normal events)
    Act II  — Attack burst          (burst_size curated anomalies)
    Act III — Recovery baseline     (act3_count normal events)
    """
    rng = random.Random(random_seed)

    # Shuffle normal pool and pick enough for Act I + Act III
    normal_pool = normals.copy()
    rng.shuffle(normal_pool)
    act1_normals = normal_pool[:act1_count]
    act3_normals = normal_pool[act1_count : act1_count + act3_count]

    # Curate the attack burst
    attack_burst = select_attack_burst(anomalies, burst_size, random_seed)

    session    = build_session()
    counters   = {"sent": 0, "detected": 0, "blocked": 0, "errors": 0}
    global_seq = 0

    # ──────────────────────────────────────────────────────────────────────
    # ACT I — Steady-State Baseline
    # ──────────────────────────────────────────────────────────────────────
    act_header(
        1,
        "STEADY-STATE BASELINE",
        f"Firing {act1_count} normal banking transactions at {normal_delay}s intervals. "
        "Watch the dashboard fill with green PASSED cards.",
    )
    print_feed_header()

    for row in act1_normals:
        global_seq += 1
        dispatch_event(session, row, global_seq, "ACT-I", counters)
        time.sleep(normal_delay)

    # ──────────────────────────────────────────────────────────────────────
    # Transition pause before attack
    # ──────────────────────────────────────────────────────────────────────
    print()
    print(col(
        "  >> Baseline established. Initiating adversary emulation sequence...",
        C.BOLD, C.BRIGHT_YELLOW,
    ))
    countdown(act_pause, "Attack imminent")

    # ──────────────────────────────────────────────────────────────────────
    # ACT II — Attack Injection
    # ──────────────────────────────────────────────────────────────────────
    act_header(
        2,
        "ADVERSARY EMULATION — ATTACK BURST",
        f"Injecting {burst_size} curated adversarial events across all 4 threat vectors. "
        "Watch the dashboard cards flip to red with ATTACK MITIGATED badges.",
    )

    # Print the attack plan before execution
    print(col("  Attack sequence loaded:", C.BOLD, C.BRIGHT_RED))
    for i, atk in enumerate(attack_burst, 1):
        vec    = atk.get("threat_vector", "NONE")
        actor  = atk.get("actor_role", "?")
        target = atk.get("target_resource", "?")
        action = atk.get("action_executed", "?")[:55]
        print(
            f"  {col(f'  [{i}]', C.BOLD, C.BRIGHT_RED)}  "
            f"{vector_display(vec)}  "
            f"{col(actor, C.BRIGHT_BLUE)} -> {col(target, C.BRIGHT_CYAN)}"
        )
        print(f"       {col('ACTION:', C.DIM)} {col(action, C.DIM, C.WHITE)}")
    print()
    print_feed_header()

    for row in attack_burst:
        global_seq += 1
        dispatch_event(session, row, global_seq, "ATK", counters)

        # Alert print for high-severity detection
        vec = row.get("threat_vector", "NONE")
        if vec != "NONE":
            print(col(
                f"  !! THREAT VECTOR ACTIVE: {vec} !!",
                C.BG_RED, C.BRIGHT_WHITE, C.BOLD,
            ))

        time.sleep(attack_delay)

    # ──────────────────────────────────────────────────────────────────────
    # Transition — show attack summary
    # ──────────────────────────────────────────────────────────────────────
    print()
    print(col(
        f"  >> Attack burst complete. {counters['blocked']} action(s) blocked. "
        "Resuming normal background traffic...",
        C.BOLD, C.BRIGHT_CYAN,
    ))
    countdown(act_pause, "System stabilising")

    # ──────────────────────────────────────────────────────────────────────
    # ACT III — System Recovery
    # ──────────────────────────────────────────────────────────────────────
    act_header(
        3,
        "SYSTEM RECOVERY — BACKGROUND NOISE",
        f"Resuming {act3_count} normal transactions. "
        "Dashboard reverts to green, demonstrating near-zero false-positive rate.",
    )
    print_feed_header()

    for row in act3_normals:
        global_seq += 1
        dispatch_event(session, row, global_seq, "ACT-3", counters)
        time.sleep(normal_delay)

    return counters


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SentinalFlow AI — Live Demo Runner & Adversary Emulation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_demo.py                       # default settings
  python run_demo.py --act1 50             # 50 normal events in Act I
  python run_demo.py --burst 5             # 5 attack events in Act II
  python run_demo.py --act1 20 --act3 15 --burst 4 --delay 0.3
  python run_demo.py --no-color            # plain text output (for logging)
  python run_demo.py --seed 7 --burst 3   # different random selection seed
        """,
    )

    parser.add_argument(
        "--act1", type=int, default=DEFAULT_ACT1_COUNT,
        metavar="N",
        help=f"Number of normal events in Act I (default: {DEFAULT_ACT1_COUNT})",
    )
    parser.add_argument(
        "--act3", type=int, default=DEFAULT_ACT3_COUNT,
        metavar="N",
        help=f"Number of normal events in Act III (default: {DEFAULT_ACT3_COUNT})",
    )
    parser.add_argument(
        "--burst", type=int, default=DEFAULT_BURST_SIZE,
        metavar="N",
        help=f"Number of attack events in Act II (default: {DEFAULT_BURST_SIZE}, range: 3-5)",
    )
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_NORMAL_DELAY,
        metavar="SEC",
        help=f"Seconds between normal events (default: {DEFAULT_NORMAL_DELAY})",
    )
    parser.add_argument(
        "--attack-delay", type=float, default=DEFAULT_ATTACK_DELAY,
        metavar="SEC",
        help=f"Seconds between attack events (default: {DEFAULT_ATTACK_DELAY})",
    )
    parser.add_argument(
        "--act-pause", type=float, default=DEFAULT_ACT_PAUSE,
        metavar="SEC",
        help=f"Seconds of pause between acts (default: {DEFAULT_ACT_PAUSE})",
    )
    parser.add_argument(
        "--seed", type=int, default=99,
        help="Random seed for event selection (default: 99)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color codes (useful for log redirection)",
    )
    parser.add_argument(
        "--dataset", type=str, default=str(DATASET_PATH),
        metavar="PATH",
        help=f"Path to the dataset CSV (default: {DATASET_PATH})",
    )
    parser.add_argument(
        "--api", type=str, default=API_BASE,
        metavar="URL",
        help=f"Base URL of the FastAPI backend (default: {API_BASE})",
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # Apply color setting globally
    if args.no_color:
        C.strip_all()

    # Clamp burst size to valid range
    burst = max(3, min(args.burst, len([
        "ROGUE_INTERNAL_DBA",
        "THIRD_PARTY_FINTECH_API_ABUSE",
        "HIGH_VOLUME_TRANSACTION_FRAUD",
        "POISONED_CICD_PIPELINE",
        "ROGUE_INTERNAL_DBA",
    ])))

    # Override global API base if --api was supplied
    global ANALYZE_ENDPOINT, HEALTH_ENDPOINT, STATS_ENDPOINT
    ANALYZE_ENDPOINT = f"{args.api}/api/v1/analyze"
    HEALTH_ENDPOINT  = f"{args.api}/health"
    STATS_ENDPOINT   = f"{args.api}/api/v1/stats"

    banner()

    # ── Environment check + configuration printout ────────────────────────
    section("ENVIRONMENT CHECK & CONFIGURATION")
    print()
    dataset_path = Path(args.dataset)

    cfg_rows = [
        ("Dataset path",     str(dataset_path),      dataset_path.exists()),
        ("API base URL",     args.api,                True),
        ("Act I events",     str(args.act1),          True),
        ("Act II burst",     str(burst),              True),
        ("Act III events",   str(args.act3),          True),
        ("Normal delay",     f"{args.delay}s",        True),
        ("Attack delay",     f"{args.attack_delay}s", True),
        ("Act pause",        f"{args.act_pause}s",    True),
        ("Random seed",      str(args.seed),          True),
        ("ANSI colors",      str(not args.no_color),  True),
    ]
    for label, value, ok in cfg_rows:
        status_icon = col("[OK]", C.BRIGHT_GREEN) if ok else col("[MISSING]", C.BRIGHT_RED)
        print(f"  {col(label + ':', C.DIM):<26} {col(value, C.WHITE)}  {status_icon}")

    if not dataset_path.exists():
        print()
        print(col(
            f"  [FATAL] Cannot open dataset at '{dataset_path}'.\n"
            "          Run mock_generator.py first to generate it.",
            C.BRIGHT_RED, C.BOLD,
        ))
        sys.exit(1)

    # ── Load and split dataset ─────────────────────────────────────────────
    print()
    print(col("  Loading and splitting dataset...", C.DIM))
    normals, anomalies = load_dataset(dataset_path)
    total_rows = len(normals) + len(anomalies)

    from collections import Counter
    vector_counts = Counter(r.get("threat_vector") for r in anomalies)

    print(f"  {col('Total rows loaded:', C.DIM):<26} {col(str(total_rows), C.BRIGHT_WHITE, C.BOLD)}")
    print(f"  {col('Normal baseline:', C.DIM):<26} {col(str(len(normals)), C.BRIGHT_GREEN, C.BOLD)}")
    print(f"  {col('Adversarial anomalies:', C.DIM):<26} {col(str(len(anomalies)), C.BRIGHT_RED, C.BOLD)}")
    print()
    print(col("  Anomaly breakdown by threat vector:", C.DIM))
    for vec, cnt in sorted(vector_counts.items()):
        print(f"    {vector_display(vec)}  {col(str(cnt), C.BRIGHT_WHITE)}")

    if len(normals) < args.act1 + args.act3:
        print(col(
            f"\n  [WARN] Requested {args.act1 + args.act3} normal events but only "
            f"{len(normals)} available. Capping counts.",
            C.BRIGHT_YELLOW,
        ))
        cap          = len(normals) // 2
        args.act1    = min(args.act1, cap)
        args.act3    = min(args.act3, len(normals) - args.act1)

    if len(anomalies) == 0:
        print(col("\n  [FATAL] No anomaly rows found in dataset.", C.BRIGHT_RED, C.BOLD))
        sys.exit(1)

    # ── Server health check ────────────────────────────────────────────────
    print()
    session = build_session()
    if not check_server_health(session):
        print()
        print(col(
            "  [FATAL] FastAPI backend is not healthy. Start main.py before running the demo.",
            C.BRIGHT_RED, C.BOLD,
        ))
        print(col("          Command:  python main.py", C.DIM))
        sys.exit(1)

    print(col("  [OK] All systems nominal. Starting demo in 3 seconds...", C.BRIGHT_GREEN, C.BOLD))
    countdown(3.0, "Demo starting")

    # ── Run the three-act sequence ─────────────────────────────────────────
    start_time = time.perf_counter()

    counters = run_demo(
        normals      = normals,
        anomalies    = anomalies,
        act1_count   = args.act1,
        act3_count   = args.act3,
        burst_size   = burst,
        normal_delay = args.delay,
        attack_delay = args.attack_delay,
        act_pause    = args.act_pause,
        random_seed  = args.seed,
    )

    # ── Fetch server-side stats for the summary ────────────────────────────
    server_stats: Optional[Dict] = None
    try:
        r = session.get(STATS_ENDPOINT, timeout=5)
        if r.status_code == 200:
            server_stats = r.json()
    except Exception:
        pass

    # ── Final summary ──────────────────────────────────────────────────────
    print_session_summary(counters, start_time, server_stats)

    print(col(
        "  Demo complete. SentinalFlow AI successfully detected and blocked adversarial events.",
        C.BOLD, C.BRIGHT_GREEN,
    ))
    print(col(
        "  SOC Dashboard: http://localhost:5173  |  API: http://localhost:8000/docs",
        C.DIM, C.CYAN,
    ))
    print()


if __name__ == "__main__":
    main()
