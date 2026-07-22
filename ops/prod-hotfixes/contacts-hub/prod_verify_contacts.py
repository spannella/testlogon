import boto3, time
REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
ssm = boto3.client("ssm", region_name=REGION)

def run(cmd, timeout="90"):
    r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
                         Parameters={"commands": [cmd], "executionTimeout": [timeout]})
    cid = r["Command"]["CommandId"]
    while True:
        time.sleep(3)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    return inv

inv = run(
    "for i in $(seq 1 40); do "
    "c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json); "
    "if [ \"$c\" = 200 ]; then echo READY_AFTER=${i}x3s; break; fi; sleep 3; done; "
    "echo OPENAPI=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json) && "
    "echo ROUTE_SUGG=$(curl -s http://127.0.0.1:8000/openapi.json | grep -c 'contacts/suggestions') && "
    "echo WORKERS=$(pgrep -fc 'uvicorn app.main') && "
    "echo BAK=$(ls -1 /home/ubuntu/testlogon/app/routers/contacts.py.bak_contactshub_latest 2>&1) && "
    "echo NEW_MD5=$(md5sum /home/ubuntu/testlogon/app/routers/contacts.py | cut -d' ' -f1)",
    timeout="180",
)
print("STATUS", inv["Status"])
print(inv.get("StandardOutputContent", ""))
e = inv.get("StandardErrorContent", "")
if e.strip():
    print("--STDERR--", e[:600])
