import boto3, time
REGION = "us-east-2"; IID = "i-08f937fc705ebea75"
ssm = boto3.client("ssm", region_name=REGION)

def run(cmd, timeout="120"):
    r = ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
                         Parameters={"commands": [cmd], "executionTimeout": [timeout]})
    cid = r["Command"]["CommandId"]
    while True:
        time.sleep(3)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            break
    return inv

# Show the restart script so we know it self-detaches (task warns: do NOT pkill inside SSM).
inv = run("cat /home/ubuntu/restart_backend.sh")
print("=== restart_backend.sh ===")
print(inv.get("StandardOutputContent", ""))

# Invoke the absolute self-detaching restarter as ubuntu; it handles the swap safely.
inv = run(
    "sudo -u ubuntu bash /home/ubuntu/restart_backend.sh >/tmp/contactshub_restart.log 2>&1; "
    "echo INVOKED",
    timeout="90",
)
print("RESTART_INVOKE", inv["Status"], inv.get("StandardOutputContent", "").strip())

# Give it a beat to rebind, then verify.
time.sleep(10)
inv = run(
    "echo OPENAPI=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json) && "
    "echo ROUTE=$(curl -s http://127.0.0.1:8000/openapi.json | grep -c 'contacts/suggestions') && "
    "echo WORKERS=$(pgrep -fc 'uvicorn app.main') && "
    "ps -eo pid,user,cmd | grep 'uvicorn app.main' | grep -v grep | head"
)
print("=== VERIFY ===")
print(inv.get("StandardOutputContent", ""))
e = inv.get("StandardErrorContent", "")
if e.strip():
    print("--STDERR--", e[:600])
