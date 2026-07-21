"""P4 seam KEYED-path verification: when NCMEC flags are set, submit_report POSTs
to the configured endpoint and the submission record becomes 'submitted' with an
external_ref. Uses a real local HTTP receiver (stands in for the ESP endpoint).

This proves the go-live branch works end-to-end; the ONLY remaining real-go-live
step is pointing api_base/api_key at NCMEC's actual ESP endpoint + legal sign-off.
"""
import os, sys, json, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.getcwd())

RECEIVED = []

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        RECEIVED.append({"path": self.path, "auth": self.headers.get("Authorization"),
                         "body": json.loads(body or b"{}")})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"report_id": "NCMEC-TEST-REF-99887"}).encode())
    def log_message(self, *a):
        pass

srv = HTTPServer(("127.0.0.1", 8021), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# Point the seam at the mock endpoint + key BEFORE importing settings/client.
os.environ["NCMEC_REPORTING_ENABLED"] = "1"
os.environ["NCMEC_API_BASE"] = "http://127.0.0.1:8021"
os.environ["NCMEC_API_KEY"] = "esp-test-key-abc"
os.environ["NCMEC_ORG_ID"] = "ORG-TESTLOGON"

# Re-load settings so the env is picked up (frozen dataclass reads env at import).
import importlib
import app.core.settings as _s
importlib.reload(_s)
import app.services.ncmec_client as ncmec
importlib.reload(ncmec)

results = []
def rec(n, ok, d=""):
    results.append(bool(ok)); print(f"[{'PASS' if ok else 'FAIL'}] {n} :: {d}")

rec("is_enabled() True when flag+base+key set", ncmec.is_enabled() is True, f"enabled={ncmec.is_enabled()}")

payload = ncmec.build_report_payload(case_id="modcase_keyedtest", content_type="feed_post",
    content_id="post_keyed", owner_user_id="ownerX", categories=["csam"], ts=int(time.time()),
    preserve_id="preserve_keyed", reporter_user_id="rep1")
res = ncmec.submit_report(payload)
rec("submit_report delivered", res.get("delivered") is True, f"res={json.dumps({k:v for k,v in res.items() if k!='raw'})}")
rec("status == submitted", res.get("status") == "submitted", f"status={res.get('status')}")
rec("external_ref captured from endpoint", res.get("external_ref") == "NCMEC-TEST-REF-99887", f"ref={res.get('external_ref')}")
rec("endpoint actually received the POST", len(RECEIVED) == 1, f"received={len(RECEIVED)}")
if RECEIVED:
    r = RECEIVED[0]
    rec("POSTed to /reports", r["path"] == "/reports", f"path={r['path']}")
    rec("auth header carried the key", r["auth"] == "Bearer esp-test-key-abc", f"auth={r['auth']}")
    rec("payload carried org_id", r["body"].get("esp", {}).get("org_id") == "ORG-TESTLOGON",
        f"org_id={r['body'].get('esp',{}).get('org_id')}")
    rec("payload carried preservation ref", r["body"]["reported_content"]["preservation_ref"] == "preserve_keyed",
        f"ref={r['body']['reported_content']['preservation_ref']}")

# Failure path: endpoint down / bad base -> status 'failed', never raises.
os.environ["NCMEC_API_BASE"] = "http://127.0.0.1:59999"  # nothing listening
importlib.reload(_s); importlib.reload(ncmec)
res2 = ncmec.submit_report(payload)
rec("unreachable endpoint -> status failed (retry-safe, no raise)", res2.get("status") == "failed",
    f"res={json.dumps(res2)}")

print("\n=== SUMMARY (keyed) ===")
print(f"{sum(results)}/{len(results)} checks passed")
srv.shutdown()
sys.exit(0 if all(results) else 1)
