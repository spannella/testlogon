import boto3, time
REGION="us-east-2"; IID="i-08f937fc705ebea75"
ssm=boto3.client("ssm", region_name=REGION)
def run(cmd, timeout="120"):
    r=ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
        Parameters={"commands":[cmd],"executionTimeout":[timeout]})
    cid=r["Command"]["CommandId"]
    while True:
        time.sleep(2)
        inv=ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success","Failed","Cancelled","TimedOut"): break
    return inv
inv=run(
  "cd /home/ubuntu/testlogon && "
  "for f in app/routers/contacts.py app/services/contact_match.py app/core/settings.py "
  "app/services/profile.py app/services/registration.py app/services/rate_limit.py "
  "app/core/tables.py scripts/local-ddb-init.py ops/backfill_contact_match.py; do "
  "if [ -f $f ]; then echo \"$(md5sum $f)\"; else echo \"MISSING $f\"; fi; done; "
  "echo '--- workers ---'; ps aux | grep -c '[u]vicorn'; "
  "echo '--- openapi ---'; curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json; echo; "
  "echo '--- has match route ---'; grep -c 'contacts/match\|match_contacts' app/routers/contacts.py 2>/dev/null || echo 0"
)
print("STATUS", inv["Status"])
print(inv.get("StandardOutputContent",""))
print("ERR", inv.get("StandardErrorContent","")[:500])
