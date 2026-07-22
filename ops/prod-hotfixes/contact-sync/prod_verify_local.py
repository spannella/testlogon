import os, time, json, hashlib, urllib.request, urllib.error
import boto3
from botocore.config import Config
ep = os.environ["DDB_ENDPOINT_URL"]
c = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION","us-east-1"),
                 endpoint_url=ep, aws_access_key_id="test", aws_secret_access_key="test",
                 config=Config(retries={"max_attempts":5}))
idx = os.environ.get("DDB_CONTACT_MATCH_INDEX_TABLE","ContactMatchIndex")
cnt = c.scan(TableName=idx, Select="COUNT")["Count"]
print("INDEX_ITEMS", cnt)
# sample items: prove only hashes stored (no '@'/'+')
s = c.scan(TableName=idx, Limit=3)["Items"]
for it in s:
    row = {k: list(v.values())[0] for k, v in it.items()}
    print("ITEM", row)

# Live match over prod HTTP: pick a real user, hash their email like the client, POST.
from app.core.settings import S
from app.core.tables import T
from app.core.normalize import normalize_email
import jwt
sub=None
for it in T.users.scan(Limit=15).get("Items",[]):
    ss=it.get("user_sub") or it.get("email")
    if ss and "@" in ss: sub=ss; break
SALT=S.contact_match_salt
def he(e): return hashlib.sha256(("%s:%s"%(SALT,normalize_email(e))).encode()).hexdigest()
print("SAMPLE_USER", sub, "hash_indexed", bool(T.contact_match_index.get_item(Key={"id_hash":he(sub)}).get("Item")))
viewer="cs_probe_%d@example.com"%int(time.time())
tok=jwt.encode({"sub":viewer,"role":"user","exp":int(time.time())+600}, S.ui_access_token_secret, algorithm="HS256")
body=json.dumps({"email_hashes":[he(sub)],"phone_hashes":[]}).encode()
req=urllib.request.Request("http://127.0.0.1:8000/ui/contacts/match",data=body,
    headers={"content-type":"application/json","Cookie":"ui_access_token=%s"%tok},method="POST")
try:
    r=urllib.request.urlopen(req); st=r.status; out=json.loads(r.read())
except urllib.error.HTTPError as e:
    st=e.code; out=json.loads(e.read() or b"{}")
print("LIVE_MATCH_HTTP", st)
print("LIVE_MATCH_RESULT", json.dumps(out))
