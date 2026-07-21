import boto3, time, base64, hashlib, subprocess, sys

REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
DEV_PATH = "/home/sean/dev/testlogon/app/routers/contacts.py"
DEV_MD5 = "148410fecd6c8e8a3677fe131ea3bc1e"

# Read the exact dev file bytes locally (this script runs ON the dev host).
data = open(DEV_PATH, "rb").read()
local_md5 = hashlib.md5(data).hexdigest()
assert local_md5 == DEV_MD5, f"dev md5 drift: {local_md5} != {DEV_MD5}"
b64 = base64.b64encode(data).decode()
print("LOCAL_MD5", local_md5, "bytes", len(data), "b64len", len(b64))

ssm = boto3.client("ssm", region_name=REGION)

# Chunk the base64 to stay well under SSM's per-command limits; append on prod.
CHUNK = 6000
chunks = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]

def run(cmd, timeout="120"):
    r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
                         Parameters={"commands": [cmd], "executionTimeout": [timeout]})
    cid = r["Command"]["CommandId"]
    while True:
        time.sleep(2)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    return inv

# 1) backup + start a fresh staging b64 file.
inv = run(
    "cd /home/ubuntu/testlogon && "
    "cp -n app/routers/contacts.py app/routers/contacts.py.bak_contactshub_$(date +%s) 2>/dev/null; "
    "cp app/routers/contacts.py app/routers/contacts.py.bak_contactshub_latest && "
    "rm -f /tmp/contacts_hub.b64 && echo STAGED_RESET_OK"
)
print("BACKUP", inv["Status"], inv.get("StandardOutputContent", "").strip())
if inv["Status"] != "Success":
    print("ERR", inv.get("StandardErrorContent", "")[:800]); sys.exit(1)

# 2) stream the b64 chunks.
for i, c in enumerate(chunks):
    inv = run(f"printf '%s' '{c}' >> /tmp/contacts_hub.b64 && echo CHUNK_{i}_OK")
    if inv["Status"] != "Success":
        print("CHUNK FAIL", i, inv.get("StandardErrorContent", "")[:400]); sys.exit(1)
print(f"STREAMED {len(chunks)} chunks")

# 3) decode into place, verify md5 == dev.
inv = run(
    "cd /home/ubuntu/testlogon && "
    "base64 -d /tmp/contacts_hub.b64 > app/routers/contacts.py && "
    "echo NEW_MD5=$(md5sum app/routers/contacts.py | cut -d' ' -f1) && "
    "echo HAS_SUGG=$(grep -c contact_suggestions app/routers/contacts.py) && "
    "python3 -c 'import ast; ast.parse(open(\"app/routers/contacts.py\").read()); print(\"AST_OK\")'"
)
print("DECODE", inv["Status"])
print(inv.get("StandardOutputContent", "").strip())
if inv["Status"] != "Success" or DEV_MD5 not in inv.get("StandardOutputContent", ""):
    print("MD5 MISMATCH / FAIL"); print(inv.get("StandardErrorContent", "")[:800]); sys.exit(1)
print("APPLY_OK md5 byte-identical to dev")
