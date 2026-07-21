import boto3, time, os, base64
REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
ssm = boto3.client("ssm", region_name=REGION)
home = os.path.expanduser("~/close_work")
ncmec_b64 = open(f"{home}/p4_ncmec.b64").read().strip()
ill_b64 = open(f"{home}/p4_illlane.b64").read().strip()
DEV_NCMEC_MD5 = "80eec2ef916ec9b66233dccc2269e602"
DEV_ILL_MD5 = "a3dac921f5fdc65d3734d7fea1b916a0"

# --- settings.py idempotent anchor patch (a real Python program, b64'd) ------
patch_src = r'''
p = "app/core/settings.py"
s = open(p).read()
anchor = '    easypost_api_base: str = os.environ.get("EASYPOST_API_BASE", "https://api.easypost.com/v2")\n'
assert anchor in s, "settings anchor missing"
if "ncmec_reporting_enabled" in s:
    print("PROD settings.py: ncmec already present (skip)")
else:
    block = (
        "    # NCMEC / CyberTipline mandated-reporting seam (P4). Config-gated like the\n"
        "    # EasyPost seam: when ncmec_reporting_enabled AND api_base AND api_key are\n"
        "    # all set the real CyberTipline submission endpoint is POSTed; otherwise the\n"
        "    # mandated report is persisted as PENDING (honest-mock-that-records, never\n"
        "    # dropped) for the ops runbook to file. Real endpoint/creds + legal sign-off\n"
        "    # are the go-live step (see app/services/ncmec_client.py).\n"
        '    ncmec_reporting_enabled: bool = os.environ.get("NCMEC_REPORTING_ENABLED", "false").lower() in ("1", "true", "yes", "on")\n'
        '    ncmec_api_base: str = os.environ.get("NCMEC_API_BASE", "")\n'
        '    ncmec_api_key: str = os.environ.get("NCMEC_API_KEY", "")\n'
        '    ncmec_org_id: str = os.environ.get("NCMEC_ORG_ID", "")\n'
        '    ncmec_report_timeout_seconds: int = int(os.environ.get("NCMEC_REPORT_TIMEOUT_SECONDS", "20"))\n'
    )
    s = s.replace(anchor, anchor + block, 1)
    open(p, "w").write(s)
    print("PROD settings.py: ncmec block inserted")
'''
patch_b64 = base64.b64encode(patch_src.encode()).decode()

# --- verifier program to run on prod after restart (b64'd) -------------------
verify_src = r'''
import app.services.ncmec_client as n
import app.services.moderation_illegal_lane as m
from app.core.settings import S
print("IMPORT_OK ncmec_enabled=", S.ncmec_reporting_enabled, "is_enabled=", n.is_enabled())
p = n.build_report_payload(case_id="c", content_type="feed_post", content_id="x",
                           owner_user_id="o", categories=["csam"], ts=1, preserve_id="pr")
print("PAYLOAD_SCHEMA_OK", p.get("schema") == n.PAYLOAD_SCHEMA,
      "preserve_ref_ok", p["reported_content"]["preservation_ref"] == "pr")
assert hasattr(m, "_submission_record_exists"), "idempotency helper missing"
print("IDEMPOTENCY_HELPER_OK")
'''
verify_b64 = base64.b64encode(verify_src.encode()).decode()

# --- apply shell (single quoted sudo -u ubuntu block) ------------------------
apply = (
    "sudo -u ubuntu bash -lc '\n"
    "set -e\n"
    "cd /home/ubuntu/testlogon\n"
    "TS=$(date +%s)\n"
    "cp app/core/settings.py app/core/settings.py.bak_ncmec_p4_$TS\n"
    "cp app/services/moderation_illegal_lane.py app/services/moderation_illegal_lane.py.bak_ncmec_p4_$TS\n"
    "echo " + ncmec_b64 + " | base64 -d > app/services/ncmec_client.py\n"
    "echo " + ill_b64 + " | base64 -d > app/services/moderation_illegal_lane.py\n"
    "echo " + patch_b64 + " | base64 -d > /tmp/p4_settings_patch.py\n"
    ".venv/bin/python /tmp/p4_settings_patch.py\n"
    "rm -f /tmp/p4_settings_patch.py\n"
    "echo MD5_NCMEC=$(md5sum app/services/ncmec_client.py | cut -d\" \" -f1)\n"
    "echo MD5_ILL=$(md5sum app/services/moderation_illegal_lane.py | cut -d\" \" -f1)\n"
    "echo EXPECT_NCMEC=" + DEV_NCMEC_MD5 + "\n"
    "echo EXPECT_ILL=" + DEV_ILL_MD5 + "\n"
    "echo " + verify_b64 + " | base64 -d > /tmp/p4_verify_import.py\n"
    "set -a; . .env.local 2>/dev/null; set +a\n"
    "PYTHONPATH=/home/ubuntu/testlogon .venv/bin/python /tmp/p4_verify_import.py\n"
    "rm -f /tmp/p4_verify_import.py\n"
    "echo APPLY_DONE\n"
    "'\n"
)

r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
                     Parameters={"commands": [apply], "executionTimeout": ["180"]})
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
    print("--STDERR--", e[:2500])
