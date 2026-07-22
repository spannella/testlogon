import boto3, time
REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
ssm = boto3.client("ssm", region_name=REGION)
cmd = (
    "cd /home/ubuntu/testlogon && "
    "echo MD5=$(md5sum app/routers/contacts.py | cut -d' ' -f1) && "
    "echo HAS_SUGG=$(grep -c contact_suggestions app/routers/contacts.py) && "
    "echo OPENAPI=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json) && "
    "echo ROUTE=$(curl -s http://127.0.0.1:8000/openapi.json | grep -c 'contacts/suggestions') && "
    "echo WORKERS=$(pgrep -fc 'uvicorn app.main') && "
    "ls -la /home/ubuntu/restart_backend.sh 2>&1"
)
r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
                     Parameters={"commands": [cmd], "executionTimeout": ["60"]})
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
    print("--STDERR--", e[:800])
