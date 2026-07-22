import base64, time, boto3
ssm=boto3.client("ssm", region_name="us-east-2"); IID="i-08f937fc705ebea75"
def run(cmd, t="180"):
    r=ssm.send_command(InstanceIds=[IID],DocumentName="AWS-RunShellScript",Parameters={"commands":[cmd],"executionTimeout":[t]})
    cid=r["Command"]["CommandId"]
    while True:
        time.sleep(3); inv=ssm.get_command_invocation(CommandId=cid,InstanceId=IID)
        if inv["Status"] in ("Success","Failed","Cancelled","TimedOut"): break
    return inv
b64=base64.b64encode(open("/home/sean/close_work/prod_verify_local.py","rb").read()).decode()
run("rm -f /tmp/cs_ver.b64")
for i in range(0,len(b64),6000): run("printf '%%s' '%s' >> /tmp/cs_ver.b64" % b64[i:i+6000])
run("base64 -d /tmp/cs_ver.b64 > /tmp/cs_ver.py")
env="cd /home/ubuntu/testlogon && set -a; . ./.env.local; set +a; PYTHONPATH=. .venv/bin/python /tmp/cs_ver.py"
inv=run("bash -c "+repr(env))
print(inv["Status"]); print(inv.get("StandardOutputContent","")); print("ERR", inv.get("StandardErrorContent","")[:500])
