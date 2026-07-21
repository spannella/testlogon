#!/usr/bin/env python3
"""Contacts Feature 2 — restart prod backend + run backfill + verify. SSM.

Restart uses the ABSOLUTE /home/ubuntu/restart_backend.sh (it self-detaches via
setsid/nohup/disown). We do NOT pkill inside the SSM shell (self-kill footgun).
Then runs the backfill on prod, and verifies openapi 200 + single worker +
/ui/contacts/match present + index populated.
"""
import time
import boto3

REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
ssm = boto3.client("ssm", region_name=REGION)

def run(cmd, timeout="300"):
    r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [cmd], "executionTimeout": [timeout]})
    cid = r["Command"]["CommandId"]
    while True:
        time.sleep(3)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    return inv

# 1) Restart via the absolute self-detaching script.
inv = run("sudo /home/ubuntu/restart_backend.sh || /home/ubuntu/restart_backend.sh; echo RESTART_INVOKED")
print("RESTART", inv["Status"], inv.get("StandardOutputContent","").strip()[:300])

# 2) Poll for openapi 200 + single worker + route present.
time.sleep(8)
inv = run(
    "for i in $(seq 1 20); do "
    "code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json); "
    "if [ \"$code\" = \"200\" ]; then break; fi; sleep 2; done; "
    "echo OPENAPI=$code; "
    "echo WORKERS=$(ps aux | grep -c '[u]vicorn'); "
    "echo ROUTE=$(curl -s http://127.0.0.1:8000/openapi.json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(1 if \"/ui/contacts/match\" in d[\"paths\"] else 0)')"
)
print("VERIFY", inv["Status"])
print(inv.get("StandardOutputContent","").strip())

# 3) Run the backfill on prod (idempotent).
inv = run("cd /home/ubuntu/testlogon && (set -a; [ -f .env ] && . ./.env; set +a; PYTHONPATH=. python3 ops/backfill_contact_match.py)")
print("BACKFILL", inv["Status"])
print(inv.get("StandardOutputContent","").strip()[:400])
print("ERR", inv.get("StandardErrorContent","")[:500])

# 4) Index population sanity.
inv = run("cd /home/ubuntu/testlogon && (set -a; [ -f .env ] && . ./.env; set +a; python3 -c 'from app.core.tables import T; print(\"INDEX_ITEMS\", T.contact_match_index.scan(Select=\"COUNT\")[\"Count\"])')")
print("INDEX", inv["Status"], inv.get("StandardOutputContent","").strip()[:200])
