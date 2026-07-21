import time, json
import boto3
REGION="us-east-2"; IID="i-08f937fc705ebea75"
ssm=boto3.client("ssm", region_name=REGION)
def run(cmd, timeout="200"):
    r=ssm.send_command(InstanceIds=[IID], DocumentName="AWS-RunShellScript",
        Parameters={"commands":["bash -lc " + repr(cmd)],"executionTimeout":[timeout]})
    cid=r["Command"]["CommandId"]
    while True:
        time.sleep(3)
        inv=ssm.get_command_invocation(CommandId=cid, InstanceId=IID)
        if inv["Status"] in ("Success","Failed","Cancelled","TimedOut"): break
    return inv
env=("cd /home/ubuntu/testlogon && set -a; for f in .env .env.local .env.prod .env.mock; do [ -f $f ] && . ./$f; done; set +a; ")
PY=".venv/bin/python"
# Index count + a REAL live match: pick an existing user, compute their email hash the
# same way the client would, POST /ui/contacts/match over live HTTP with a minted cookie.
script = env + PY + " - <<'PYEOF2'\n" + '''
import hashlib, json, time, urllib.request, urllib.error
from app.core.settings import S
from app.core.tables import T
from app.core.normalize import normalize_email
# index count
cnt = T.contact_match_index.scan(Select="COUNT")["Count"]
print("INDEX_ITEMS", cnt)
# pick a sample existing user
u = T.users.scan(Limit=5).get("Items", [])
sub = None
for it in u:
    s = it.get("user_sub") or it.get("email")
    if s and "@" in s:
        sub = s; break
print("SAMPLE_USER", sub)
SALT = S.contact_match_salt
def he(e): return hashlib.sha256(f"{SALT}:{normalize_email(e)}".encode()).hexdigest()
# confirm that user's email hash is indexed
item = T.contact_match_index.get_item(Key={"id_hash": he(sub)}).get("Item")
print("SAMPLE_INDEXED", bool(item), item.get("user_id") if item else None)
# mint a UI cookie for a DIFFERENT viewer and match the sample user's email hash
import jwt
viewer = "contactsync_probe_"+str(int(time.time()))+"@example.com"
tok = jwt.encode({"sub": viewer, "role":"user", "exp": int(time.time())+600}, S.ui_access_token_secret, algorithm="HS256")
body = json.dumps({"email_hashes":[he(sub)], "phone_hashes":[]}).encode()
req = urllib.request.Request("http://127.0.0.1:8000/ui/contacts/match", data=body,
    headers={"content-type":"application/json","Cookie":f"ui_access_token={tok}"}, method="POST")
try:
    r = urllib.request.urlopen(req); st=r.status; out=json.loads(r.read())
except urllib.error.HTTPError as e:
    st=e.code; out=json.loads(e.read() or b"{}")
print("LIVE_MATCH_HTTP", st)
print("LIVE_MATCH_RESULT", json.dumps(out))
PYEOF2'''
inv=run(script)
print("STATUS", inv["Status"])
print(inv.get("StandardOutputContent",""))
print("ERR", inv.get("StandardErrorContent","")[:600])
