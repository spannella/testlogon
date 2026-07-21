import time, boto3
ssm=boto3.client("ssm", region_name="us-east-2"); IID="i-08f937fc705ebea75"
def run(cmd, t="120"):
    r=ssm.send_command(InstanceIds=[IID],DocumentName="AWS-RunShellScript",Parameters={"commands":[cmd],"executionTimeout":[t]})
    cid=r["Command"]["CommandId"]
    while True:
        time.sleep(3); inv=ssm.get_command_invocation(CommandId=cid,InstanceId=IID)
        if inv["Status"] in ("Success","Failed","Cancelled","TimedOut"): break
    return inv
cmd=("echo OPENAPI=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json); "
     "echo WORKERS=$(ps aux | grep -c '[u]vicorn'); "
     "echo ROUTE=$(curl -s http://127.0.0.1:8000/openapi.json | python3 -c 'import sys,json; print(1 if \"/ui/contacts/match\" in json.load(sys.stdin)[\"paths\"] else 0)'); "
     "echo SUGG=$(curl -s http://127.0.0.1:8000/openapi.json | python3 -c 'import sys,json; print(1 if \"/ui/contacts/suggestions\" in json.load(sys.stdin)[\"paths\"] else 0)')")
inv=run(cmd)
print(inv["Status"]); print(inv.get("StandardOutputContent","").strip())
