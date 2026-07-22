#!/usr/bin/env python3
"""Contacts Feature 2 — prod mirror (SSM). Runs ON the dev host (has AWS creds).

Strategy:
  - contacts.py           : byte-identical mirror (prod == Phase-1 baseline; md5 verified).
  - contact_match.py      : new file, byte-identical upload.
  - ops/backfill_...py     : new file, byte-identical upload.
  - settings/tables/registration/profile/rate_limit : TARGETED idempotent Python
    patches applied IN PLACE on prod (those files carry prod-only divergence, so we
    never byte-clobber them). Each patch is a no-op if already applied.
Keeps .bak of every touched file. Verifies AST + expected markers after.
"""
import base64, hashlib, sys, time
import boto3

REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
DEV = "/home/sean/dev/testlogon"

# Dev md5s for the two byte-mirrored source files (drift guard).
CONTACTS_MD5 = "f50b07792542db463cc8f84d7e676f0c"

ssm = boto3.client("ssm", region_name=REGION)

def run(cmd, timeout="180"):
    r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [cmd], "executionTimeout": [timeout]})
    cid = r["Command"]["CommandId"]
    while True:
        time.sleep(2)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    return inv

def must(inv, label):
    if inv["Status"] != "Success":
        print(f"FAIL {label}: {inv['Status']}")
        print(inv.get("StandardErrorContent", "")[:1200])
        sys.exit(1)
    print(f"OK {label}: {inv.get('StandardOutputContent','').strip()[:600]}")

def stream_file(local_path, remote_tmp, remote_dest, expect_md5=None):
    data = open(local_path, "rb").read()
    md5 = hashlib.md5(data).hexdigest()
    if expect_md5 and md5 != expect_md5:
        print(f"DEV MD5 DRIFT {local_path}: {md5} != {expect_md5}"); sys.exit(1)
    b64 = base64.b64encode(data).decode()
    run(f"rm -f {remote_tmp}")
    CH = 6000
    for i in range(0, len(b64), CH):
        inv = run(f"printf '%s' '{b64[i:i+CH]}' >> {remote_tmp}")
        if inv["Status"] != "Success":
            print("chunk fail", i, inv.get("StandardErrorContent","")[:300]); sys.exit(1)
    inv = run(
        f"cd {DEV.replace('/home/sean/dev/testlogon','/home/ubuntu/testlogon')} && "
        f"[ -f {remote_dest} ] && cp {remote_dest} {remote_dest}.bak_contactsync_$(date +%s) || true; "
        f"base64 -d {remote_tmp} > {remote_dest} && "
        f"echo MD5=$(md5sum {remote_dest} | cut -d' ' -f1) && "
        f"python3 -c 'import ast; ast.parse(open(\"{remote_dest}\").read()); print(\"AST_OK\")'"
    )
    must(inv, f"stream {remote_dest}")
    if md5 not in inv.get("StandardOutputContent", ""):
        print(f"MD5 MISMATCH on {remote_dest} (dev={md5})"); sys.exit(1)

# ── 1) Byte-mirror contacts.py + upload the two new files ────────────────────
stream_file(f"{DEV}/app/routers/contacts.py", "/tmp/cs_contacts.b64",
            "app/routers/contacts.py", expect_md5=CONTACTS_MD5)
stream_file(f"{DEV}/app/services/contact_match.py", "/tmp/cs_cm.b64",
            "app/services/contact_match.py")
stream_file(f"{DEV}/ops/backfill_contact_match.py", "/tmp/cs_bf.b64",
            "ops/backfill_contact_match.py")

# ── 2) Upload the idempotent prod-patcher and run it ─────────────────────────
patcher = open(f"{DEV}/../prod_patch_shared.py", "rb").read() \
    if False else open("/home/sean/close_work/prod_patch_shared.py", "rb").read()
b64 = base64.b64encode(patcher).decode()
run("rm -f /tmp/cs_patch.b64")
for i in range(0, len(b64), 6000):
    run(f"printf '%s' '{b64[i:i+6000]}' >> /tmp/cs_patch.b64")
inv = run("cd /home/ubuntu/testlogon && base64 -d /tmp/cs_patch.b64 > /tmp/prod_patch_shared.py && "
          "python3 -c 'import ast; ast.parse(open(\"/tmp/prod_patch_shared.py\").read()); print(\"PATCHER_AST_OK\")'")
must(inv, "upload patcher")

inv = run("cd /home/ubuntu/testlogon && python3 /tmp/prod_patch_shared.py")
must(inv, "apply shared patches")

# ── 3) Post-apply verification: AST + markers on every shared file ───────────
inv = run(
    "cd /home/ubuntu/testlogon && "
    "for f in app/core/settings.py app/core/tables.py app/services/registration.py "
    "app/services/profile.py app/services/rate_limit.py app/routers/contacts.py "
    "app/services/contact_match.py; do "
    "python3 -c \"import ast; ast.parse(open('$f').read())\" && echo \"AST_OK $f\" || echo \"AST_FAIL $f\"; done; "
    "echo salt=$(grep -c contact_match_salt app/core/settings.py); "
    "echo tbl=$(grep -c contact_match_index app/core/tables.py); "
    "echo reg=$(grep -c index_user_email app/services/registration.py); "
    "echo prof=$(grep -c index_user_phone app/services/profile.py); "
    "echo rl=$(grep -c rate_limit_contact_match app/services/rate_limit.py); "
    "echo route=$(grep -c match_contacts app/routers/contacts.py)"
)
must(inv, "post-apply verify")
print("\nAPPLY COMPLETE")
