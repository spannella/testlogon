"""P4 NCMEC mandated-report seam — LIVE verification (self-contained harness).

Mirrors dev_launch.py EXACTLY: start moto (in-process AWS mock the app uses in
DEV_MODE), seed the DDB tables, then serve the REAL app object with a REAL
uvicorn on a throwaway port. The report action is driven over REAL HTTP
(urllib -> 127.0.0.1:PORT), NEVER TestClient. The submission-record inspection
then reads the SAME in-process store the server just wrote to.

This is the only way to both (a) hit the real router over real HTTP and (b) see
the escalation's writes, because dev_launch's moto DDB is in-process.
"""
import os, sys, time, json, threading, hashlib
import urllib.request, urllib.error

sys.path.insert(0, os.getcwd())

PORT = int(os.environ.get("P4_PORT", "8010"))
COOKIE = os.environ.get("UI_ACCESS_TOKEN_COOKIE_NAME", "ui_access_token")
SECRET = os.environ["UI_ACCESS_TOKEN_SECRET"]

# 1) moto in-process (same as dev_launch) ------------------------------------
from app.core.dev_s3 import start_s3_mock
from app.core.settings import S
buckets = [b for b in [S.filemgr_bucket, S.video_upload_bucket,
                       S.vod_output_bucket or "vod-output", "filemgr",
                       "broadcast-vod"] if b]
start_s3_mock(buckets)
print("harness: moto started", flush=True)

# 2) seed DDB tables INSIDE the moto store -----------------------------------
import runpy
sys.argv = ["local-ddb-init.py"]
try:
    runpy.run_path("scripts/local-ddb-init.py", run_name="__main__")
except SystemExit:
    pass
print("harness: tables seeded", flush=True)

# 3) build app, suppress its own moto restart --------------------------------
import app.main as _m
_m._start_s3_mock = lambda *a, **k: None

import jwt as _jwt
from app.core.aws import ddb
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

# The dev seed only seeds a subset of allowed-topic sentinel rows; ensure the
# illegal-lane topics exist so the content-report transact-write condition check
# passes (prod seeds the full ALLOWED_TOPICS set). This is fixture setup only.
_cr = ddb.Table(S.content_reports_table_name)
for _t in ("csam", "illegal"):
    try:
        _cr.put_item(Item={"report_id": f"TOPIC#{_t}", "entity_type": "content_report_topic", "topic": _t},
                     ConditionExpression="attribute_not_exists(report_id)")
    except Exception:
        pass
print("harness: illegal-lane topic sentinels ensured", flush=True)

# 4) serve the real app over real HTTP on a throwaway port -------------------
import uvicorn
config = uvicorn.Config(_m.app, host="127.0.0.1", port=PORT, workers=1, log_level="error")
server = uvicorn.Server(config)
th = threading.Thread(target=server.run, daemon=True)
th.start()

BASE = f"http://127.0.0.1:{PORT}"
for _ in range(60):
    try:
        with urllib.request.urlopen(f"{BASE}/openapi.json", timeout=2) as r:
            if r.getcode() == 200:
                break
    except Exception:
        time.sleep(0.5)
print(f"harness: server up on {PORT}", flush=True)

TS = int(time.time())
POST_ID = None
OWNER = f"p4owner_{TS}"
R1 = f"p4rep1_{TS}"
R2 = f"p4rep2_{TS}"

results = []
def rec(name, ok, detail=""):
    results.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

def cookie(sub):
    return _jwt.encode({"sub": sub, "sid": f"p4_{sub}"}, SECRET, algorithm="HS256")

def http_post(path, sub, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Cookie", f"{COOKIE}={cookie(sub)}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.getcode(), json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}

def case_id_for(ct, cid):
    return "modcase_" + hashlib.sha256(f"{ct}:{cid}".encode()).hexdigest()[:20]

# --- create a real feed_post over HTTP (into the server's own store) ---------
code, resp = http_post("/posts", OWNER, {"body": "p4 seed post", "visibility": "public"})
POST_ID = str(resp.get("post_id") or resp.get("id") or (resp.get("post") or {}).get("post_id") or "")
rec("created feed_post over HTTP", 200 <= code < 300 and bool(POST_ID), f"code={code} post_id={POST_ID} resp_keys={list(resp)[:8]}")
if not POST_ID:
    print("=== cannot proceed without post_id ===")
    print(json.dumps(resp)[:400]); sys.exit(1)

case_id = case_id_for("feed_post", POST_ID)
print(f"case_id={case_id}")

# --- 1. First csam report over REAL HTTP -> illegal lane ---------------------
code, resp = http_post("/v1/moderation/reports", R1, {
    "content_type": "feed_post", "content_id": POST_ID, "topics": ["csam"],
    "reason_text": "automated p4 verification: illegal content"})
rec("first csam report accepted (HTTP 2xx)", 200 <= code < 300, f"code={code} resp={json.dumps(resp)[:300]}")
time.sleep(0.4)

# --- 2. SUBMISSION record: honest-mock PENDING (seam off/unkeyed) ------------
sub = tbl.get_item(Key={"pk": f"MANDATEDREPORT#{case_id}", "sk": "SUBMISSION"}).get("Item")
rec("submission record persisted", bool(sub), f"item={json.dumps(sub, default=str)[:320] if sub else None}")
if sub:
    rec("status == pending (seam not live)", str(sub.get("status")) == "pending", f"status={sub.get('status')}")
    rec("delivered == False", not sub.get("delivered"), f"delivered={sub.get('delivered')}")
    rec("channel == ncmec", str(sub.get("channel")) == "ncmec", f"channel={sub.get('channel')}")
    rec("external_ref empty (not filed yet)", str(sub.get("external_ref") or "") == "", f"ref={sub.get('external_ref')!r}")
    rec("preserve_id present (evidence link)", bool(sub.get("preserve_id")), f"preserve_id={sub.get('preserve_id')}")
    rec("attempts == 1", int(sub.get("attempts") or -1) == 1, f"attempts={sub.get('attempts')}")

# --- 3. Preservation record intact ------------------------------------------
pres = tbl.get_item(Key={"pk": f"ILLEGALPRESERVE#{case_id}", "sk": "RECORD"}).get("Item")
rec("preservation record intact", bool(pres) and str((pres or {}).get("status")) == "preserved",
    f"status={(pres or {}).get('status')}")

# --- 4. Legacy audit EVENT row intact ---------------------------------------
import boto3.dynamodb.conditions as C
ev = tbl.query(KeyConditionExpression=C.Key("pk").eq(f"MANDATEDREPORT#{case_id}") & C.Key("sk").begins_with("EVENT#")).get("Items", [])
rec("legacy mandated_report_event row intact", len(ev) >= 1, f"event_rows={len(ev)}")

# --- 5. Idempotent replay: 2nd reporter, same content -> NO double-report ----
attempts_before = int((sub or {}).get("attempts") or 0)
code2, _ = http_post("/v1/moderation/reports", R2, {
    "content_type": "feed_post", "content_id": POST_ID, "topics": ["csam"],
    "reason_text": "automated p4 verification: replay"})
time.sleep(0.4)
sub2 = tbl.get_item(Key={"pk": f"MANDATEDREPORT#{case_id}", "sk": "SUBMISSION"}).get("Item") or {}
rec("replay: exactly one SUBMISSION record (idempotent)", bool(sub2), f"present={bool(sub2)}")
rec("replay: attempts NOT incremented (no re-transmit)", int(sub2.get("attempts") or 0) == attempts_before,
    f"before={attempts_before} after={sub2.get('attempts')}")
ev2 = tbl.query(KeyConditionExpression=C.Key("pk").eq(f"MANDATEDREPORT#{case_id}") & C.Key("sk").begins_with("EVENT#")).get("Items", [])
rec("replay: EVENT rows did not multiply", len(ev2) == len(ev), f"before={len(ev)} after={len(ev2)}")

# --- 6. Seam correctness: is_enabled False by default (honest-mock) ----------
from app.services import ncmec_client
rec("ncmec_client.is_enabled() False by default", ncmec_client.is_enabled() is False,
    f"enabled={ncmec_client.is_enabled()}")
payload = ncmec_client.build_report_payload(case_id=case_id, content_type="feed_post",
    content_id=POST_ID, owner_user_id=OWNER, categories=["illegal"], ts=TS, preserve_id="preserve_x")
rec("payload schema tagged", payload.get("schema") == ncmec_client.PAYLOAD_SCHEMA, f"schema={payload.get('schema')}")
rec("payload preserves evidence pointer", payload["reported_content"]["preservation_ref"] == "preserve_x",
    f"ref={payload['reported_content']['preservation_ref']}")

print("\n=== SUMMARY ===")
print(f"{sum(results)}/{len(results)} checks passed")
server.should_exit = True
time.sleep(0.5)
sys.exit(0 if all(results) else 1)
