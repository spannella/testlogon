import time
import boto3
REGION="us-east-2"; IID="i-08f937fc705ebea75"
ssm=boto3.client("ssm", region_name=REGION)
def run(cmd, timeout="300"):
    r=ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
        Parameters={"commands":["bash -lc " + repr(cmd)],"executionTimeout":[timeout]})
    cid=r["Command"]["CommandId"]
    while True:
        time.sleep(3)
        inv=ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success","Failed","Cancelled","TimedOut"): break
    return inv
env=("cd /home/ubuntu/testlogon && set -a; for f in .env .env.local .env.prod .env.mock; do [ -f $f ] && . ./$f; done; set +a; ")
PY=".venv/bin/python"
inv=run(env + f"PYTHONPATH=. {PY} ops/backfill_contact_match.py --dry-run 2>&1 | tail -3")
print("DRYRUN", inv["Status"]); print(inv.get("StandardOutputContent","").strip()); print("E:",inv.get("StandardErrorContent","")[:300])
inv=run(env + f"PYTHONPATH=. {PY} ops/backfill_contact_match.py 2>&1 | tail -3")
print("APPLY", inv["Status"]); print(inv.get("StandardOutputContent","").strip()); print("E:",inv.get("StandardErrorContent","")[:300])
inv=run(env + f"{PY} -c 'from app.core.tables import T; print(\"INDEX_ITEMS\", T.contact_match_index.scan(Select=\"COUNT\")[\"Count\"])' 2>&1 | tail -2")
print("INDEX", inv["Status"]); print(inv.get("StandardOutputContent","").strip())
