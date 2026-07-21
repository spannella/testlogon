import boto3, time, base64
REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
ssm = boto3.client("ssm", region_name=REGION)

verify = r'''
import time
from app.services import moderation_illegal_lane as ill
from app.services import ncmec_client as nc
from app.core.aws import ddb
import os
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)

TS = int(time.time())
CASE = f"prodp4_{TS}"

# Directly exercise the mandated-report record-keeping seam (the P4 unit under
# test). This proves the LIVE prod code persists a submission record + is
# idempotent, against prod's real DDB.
ev1 = ill._mandated_report_event(CASE, content_type="feed_post", content_id="x1",
    owner_user_id="owner1", categories=["csam"], ts=TS, preserve_id=f"preserve_{CASE}",
    reporter_user_id="rep1")
sub = tbl.get_item(Key={"pk": f"MANDATEDREPORT#{CASE}", "sk": "SUBMISSION"}).get("Item") or {}
print("SUB_STATUS", sub.get("status"), "DELIVERED", sub.get("delivered"),
      "CHANNEL", sub.get("channel"), "ATTEMPTS", sub.get("attempts"),
      "PRESERVE", sub.get("preserve_id"), "REF", repr(sub.get("external_ref")))
print("IS_ENABLED", nc.is_enabled())

# Idempotent replay -> no re-transmit, attempts unchanged, one record.
ev2 = ill._mandated_report_event(CASE, content_type="feed_post", content_id="x1",
    owner_user_id="owner1", categories=["csam"], ts=TS+1, preserve_id=f"preserve_{CASE}",
    reporter_user_id="rep2")
sub2 = tbl.get_item(Key={"pk": f"MANDATEDREPORT#{CASE}", "sk": "SUBMISSION"}).get("Item") or {}
import boto3.dynamodb.conditions as C
evs = tbl.query(KeyConditionExpression=C.Key("pk").eq(f"MANDATEDREPORT#{CASE}") & C.Key("sk").begins_with("EVENT#")).get("Items", [])
print("REPLAY_ATTEMPTS", sub2.get("attempts"), "EVENT_ROWS", len(evs), "EV_IDS_MATCH", ev1 == ev2)
ok = (sub.get("status") == "pending" and not sub.get("delivered") and sub.get("channel") == "ncmec"
      and int(sub.get("attempts") or 0) == 1 and bool(sub.get("preserve_id"))
      and int(sub2.get("attempts") or 0) == 1 and len(evs) == 1 and nc.is_enabled() is False)
print("PROD_P4_VERIFY", "PASS" if ok else "FAIL")
# cleanup the test rows
try:
    tbl.delete_item(Key={"pk": f"MANDATEDREPORT#{CASE}", "sk": "SUBMISSION"})
    for e in evs:
        tbl.delete_item(Key={"pk": e["pk"], "sk": e["sk"]})
    print("CLEANUP_OK")
except Exception as ex:
    print("CLEANUP_WARN", ex)
'''
vb64 = base64.b64encode(verify.encode()).decode()

cmd = (
    "sudo -u ubuntu bash -lc '\n"
    "cd /home/ubuntu/testlogon\n"
    "echo " + vb64 + " | base64 -d > /tmp/p4_prod_verify.py\n"
    "set -a; . .env.local 2>/dev/null; set +a\n"
    "PYTHONPATH=/home/ubuntu/testlogon .venv/bin/python /tmp/p4_prod_verify.py\n"
    "rm -f /tmp/p4_prod_verify.py\n"
    "'\n"
)
r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
                     Parameters={"commands": [cmd], "executionTimeout": ["120"]})
cid = r["Command"]["CommandId"]
while True:
    time.sleep(3)
    inv = ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
    if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
        break
print("STATUS", inv["Status"])
print(inv.get("StandardOutputContent", ""))
e = inv.get("StandardErrorContent", "")
if e.strip():
    print("--STDERR--", e[:1500])
