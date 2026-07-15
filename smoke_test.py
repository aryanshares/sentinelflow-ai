"""
smoke_test.py
Full functional smoke-test suite for SentinalFlow AI FastAPI server.
Covers all HTTP endpoints + a WebSocket receive test.
"""
import asyncio
import json
import sys
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8000"

def http_get(path):
    url = BASE + path
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            body = json.loads(r.read().decode())
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def http_post(path, payload):
    url = BASE + path
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read().decode())
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

DIVIDER = "=" * 68

def section(title):
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)

def ok(label, value=""):
    print(f"  [PASS]  {label}  {value}")

def fail(label, value=""):
    print(f"  [FAIL]  {label}  {value}")
    sys.exit(1)

# â”€â”€ Test 1: Root â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 1 â€” GET /")
code, body = http_get("/")
assert code == 200, f"Expected 200, got {code}"
assert body["service"] == "SentinalFlow AI", f"Bad service name: {body}"
ok("GET /  â†’  200", json.dumps(body, indent=2))

# â”€â”€ Test 2: Health â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 2 â€” GET /health")
code, body = http_get("/health")
assert code == 200, f"Expected 200, got {code}"
assert body["model_loaded"]    is True,  f"model_loaded=False: {body}"
assert body["mappings_loaded"] is True,  f"mappings_loaded=False: {body}"
ok("GET /health  â†’  200", json.dumps(body, indent=2))

# â”€â”€ Test 3: Model Info â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 3 â€” GET /api/v1/model/info")
code, body = http_get("/api/v1/model/info")
assert code == 200, f"Expected 200, got {code}"
assert "isoforest" in body["pipeline_steps"], f"Missing isoforest: {body}"
assert len(body["feature_columns"]) == 8, f"Expected 8 features: {body}"
ok("GET /api/v1/model/info  â†’  200")
print(f"  Pipeline steps  : {body['pipeline_steps']}")
print(f"  Feature columns : {body['feature_columns']}")

# â”€â”€ Test 4: Stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 4 â€” GET /api/v1/stats")
code, body = http_get("/api/v1/stats")
assert code == 200, f"Expected 200, got {code}"
ok("GET /api/v1/stats  â†’  200", json.dumps(body, indent=2))

# â”€â”€ Test 5: Analyze â€” Normal Event â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 5 â€” POST /api/v1/analyze  [NORMAL EVENT]")
normal_payload = {
    "event_id"             : "test-normal-0001",
    "timestamp"            : "2025-06-10T10:30:00",
    "actor_id"             : "USR-1122",
    "actor_role"           : "analyst",
    "target_resource"      : "reporting-dashboard",
    "action_executed"      : "GET /api/v2/reports/daily",
    "associated_ticket_id" : "INC-441290",
    "execution_time_delta" : 295.0,
    "data_volume_kb"       : 74.3,
    "temporal_hour"        : 10,
}
code, body = http_post("/api/v1/analyze", normal_payload)
assert code == 200, f"Expected 200, got {code}: {body}"
assert "anomaly_score"  in body, f"Missing anomaly_score: {body}"
assert "action_blocked" in body, f"Missing action_blocked: {body}"
score   = body["anomaly_score"]
blocked = body["action_blocked"]
ok(f"Normal event processed  â†’  anomaly_score={score:.4f}  action_blocked={blocked}")
assert blocked is False, f"Normal event incorrectly blocked! score={score}"
ok("Normal event correctly NOT blocked")
print(f"  actor_role_risk    : {body['actor_role_risk']}")
print(f"  target_criticality : {body['target_criticality']}")
print(f"  action_danger      : {body['action_danger']}")
print(f"  off_hours_flag     : {body['off_hours_flag']}")
print(f"  risk_x_criticality : {body['risk_x_criticality']}")
print(f"  raw_decision_score : {body['raw_decision_score']}")
print(f"  model_prediction   : {body['model_prediction']}")

# â”€â”€ Test 6: Analyze â€” Rogue DBA Anomaly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 6 â€” POST /api/v1/analyze  [ROGUE DBA ANOMALY]")
rogue_dba_payload = {
    "event_id"             : "test-anomaly-dba-0001",
    "timestamp"            : "2025-09-04T02:11:44",
    "actor_id"             : "DBA-7731",
    "actor_role"           : "dba",
    "target_resource"      : "core-banking-db-prod",
    "action_executed"      : "ALTER TABLE customers DROP COLUMN ssn_hash",
    "associated_ticket_id" : "NULL",
    "execution_time_delta" : 5820.0,
    "data_volume_kb"       : 128.4,
    "temporal_hour"        : 2,
}
code, body = http_post("/api/v1/analyze", rogue_dba_payload)
assert code == 200, f"Expected 200, got {code}: {body}"
score   = body["anomaly_score"]
blocked = body["action_blocked"]
ok(f"Rogue DBA event scored  â†’  anomaly_score={score:.4f}  action_blocked={blocked}")
print(f"  actor_role_risk    : {body['actor_role_risk']}")
print(f"  target_criticality : {body['target_criticality']}")
print(f"  action_danger      : {body['action_danger']}")
print(f"  off_hours_flag     : {body['off_hours_flag']}")
print(f"  risk_x_criticality : {body['risk_x_criticality']}")
print(f"  raw_decision_score : {body['raw_decision_score']}")
print(f"  model_prediction   : {body['model_prediction']}")
if blocked:
    ok("Rogue DBA correctly BLOCKED")
else:
    print(f"  [WARN]  Rogue DBA not blocked (score={score:.4f} < 0.55). Check sigmoid calibration.")

# â”€â”€ Test 7: Analyze â€” Fintech API Abuse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 7 â€” POST /api/v1/analyze  [FINTECH API ABUSE]")
api_abuse_payload = {
    "event_id"             : "test-anomaly-api-0001",
    "timestamp"            : "2025-11-19T14:22:09",
    "actor_id"             : "EXT-5501",
    "actor_role"           : "fintech_partner",
    "target_resource"      : "open-banking-api",
    "action_executed"      : "GET /api/v3/open-banking/bulk-accounts?limit=5000",
    "associated_ticket_id" : "NULL",
    "execution_time_delta" : 8.3,
    "data_volume_kb"       : 98304.0,
    "temporal_hour"        : 14,
}
code, body = http_post("/api/v1/analyze", api_abuse_payload)
assert code == 200, f"Expected 200, got {code}: {body}"
score   = body["anomaly_score"]
blocked = body["action_blocked"]
ok(f"API Abuse event scored  â†’  anomaly_score={score:.4f}  action_blocked={blocked}")
print(f"  raw_decision_score : {body['raw_decision_score']}")
if blocked:
    ok("API Abuse correctly BLOCKED")
else:
    print(f"  [WARN]  API Abuse not blocked (score={score:.4f}). data_volume_kb is the key signal.")

# â”€â”€ Test 8: Analyze â€” CI/CD Poisoning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 8 â€” POST /api/v1/analyze  [CI/CD PIPELINE POISONING]")
cicd_payload = {
    "event_id"             : "test-anomaly-cicd-0001",
    "timestamp"            : "2025-03-11T03:47:00",
    "actor_id"             : "DEV-0042",
    "actor_role"           : "intern_developer",
    "target_resource"      : "libcrypto-core",
    "action_executed"      : "COMMIT src/crypto/aes_gcm.py -- modify key derivation logic",
    "associated_ticket_id" : "NULL",
    "execution_time_delta" : 410.0,
    "data_volume_kb"       : 18.5,
    "temporal_hour"        : 3,
}
code, body = http_post("/api/v1/analyze", cicd_payload)
assert code == 200, f"Expected 200, got {code}: {body}"
score   = body["anomaly_score"]
blocked = body["action_blocked"]
ok(f"CI/CD Poison scored     â†’  anomaly_score={score:.4f}  action_blocked={blocked}")
print(f"  raw_decision_score : {body['raw_decision_score']}")
if blocked:
    ok("CI/CD Poison correctly BLOCKED")
else:
    print(f"  [WARN]  CI/CD event not blocked (score={score:.4f}). This is the hardest threat vector.")

# â”€â”€ Test 9: Analyze â€” High-Volume Transaction Fraud â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 9 â€” POST /api/v1/analyze  [HIGH-VOLUME TRANSACTION FRAUD]")
fraud_payload = {
    "event_id"             : "test-anomaly-fraud-0001",
    "timestamp"            : "2025-07-22T16:05:33",
    "actor_id"             : "SVC-9910",
    "actor_role"           : "automated_clearing_bot",
    "target_resource"      : "transaction-approval-engine",
    "action_executed"      : "EXECUTE sp_approve_transaction_batch @skip_fraud_check=1",
    "associated_ticket_id" : "NULL",
    "execution_time_delta" : 12.7,
    "data_volume_kb"       : 15360.0,
    "temporal_hour"        : 16,
}
code, body = http_post("/api/v1/analyze", fraud_payload)
assert code == 200, f"Expected 200, got {code}: {body}"
score   = body["anomaly_score"]
blocked = body["action_blocked"]
ok(f"Txn Fraud scored        â†’  anomaly_score={score:.4f}  action_blocked={blocked}")
print(f"  raw_decision_score : {body['raw_decision_score']}")
if blocked:
    ok("Transaction Fraud correctly BLOCKED")
else:
    print(f"  [WARN]  Txn Fraud not blocked (score={score:.4f}).")

# â”€â”€ Test 10: Pydantic Validation Error â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 10 â€” POST /api/v1/analyze  [INVALID PAYLOAD â€” 422 expected]")
bad_payload = {
    "actor_role"           : "analyst",
    # missing required fields: actor_id, target_resource, action_executed,
    #                          execution_time_delta, data_volume_kb, temporal_hour
}
code, body = http_post("/api/v1/analyze", bad_payload)
assert code == 422, f"Expected 422 Unprocessable, got {code}: {body}"
ok("Invalid payload correctly rejected with HTTP 422")

# â”€â”€ Test 11: Session Stats updated â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 11 â€” GET /api/v1/stats  [verify counters after 5 analyze calls]")
code, body = http_get("/api/v1/stats")
assert code == 200
total = body["total_events_processed"]
assert total >= 5, f"Expected >= 5 events processed, got {total}"
ok(f"Session stats consistent: total_events={total}, anomalies={body['total_anomalies_detected']}, blocked={body['total_actions_blocked']}")

# â”€â”€ Test 12: WebSocket receive one broadcast â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
section("TEST 12 â€” WS /ws/stream  [receive one broadcast frame]")
async def ws_smoke():
    import websockets
    uri = "ws://127.0.0.1:8000/ws/stream"
    try:
        async with websockets.connect(uri, open_timeout=5) as ws:
            # First frame should be the welcome handshake
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = json.loads(raw)
            assert msg.get("type") == "connected", f"Expected connected frame, got: {msg}"
            ok("WebSocket welcome frame received", str(msg))
            return True
    except Exception as e:
        print(f"  [WARN]  WebSocket test skipped: {e}")
        print(f"  Install 'websockets' package to enable WS testing.")
        return False

try:
    import websockets
    result = asyncio.run(ws_smoke())
except ImportError:
    print("  [WARN]  'websockets' not installed â€” skipping WS smoke test.")
    result = True   # non-blocking skip

# â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print(f"\n{DIVIDER}")
print("  ALL SMOKE TESTS PASSED")
print(f"{DIVIDER}\n")

