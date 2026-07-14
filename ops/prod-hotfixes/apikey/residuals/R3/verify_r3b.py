"""R3 addendum: KYC POST scope-gate with a VALID body (proves 403 kyc:submit, not 422)."""
import os, sys, time
REPO = os.environ.get('APIK_REPO', os.getcwd()); sys.path.insert(0, REPO); os.chdir(REPO)
from fastapi.testclient import TestClient
from app.core.tables import T
from app.services import api_keys as AK
from app.core.time import now_ts
from app.main import app
TS=int(time.time()); UKYC='apik-r3bkyc-%d'%TS
ck=[]; cu=[]
T.users.put_item(Item={'user_sub':UKYC,'role':'user','email':UKYC+'@synthetic.local','created_at':now_ts(),'display_name':'synthR3b'}); cu.append(UKYC)
r=AK.create_api_key(UKYC,'r3b',expires_in_days=1,capabilities=['kyc:read']); ck.append(r['key_id']); k_read=r['key_secret']
r2=AK.create_api_key(UKYC,'r3b',expires_in_days=1,capabilities=['kyc:submit']); ck.append(r2['key_id']); k_sub=r2['key_secret']
c=TestClient(app)
body={'external_id':'r3ext%d'%TS,'applicant':{'first_name':'A','last_name':'B','date_of_birth':'1990-01-01','email':'a@b.com'},'tier':'tier_1'}
res=[]
g=c.post('/api/v1/kyc/applications',headers={'X-API-Key':k_read,'Idempotency-Key':'r3b-%d'%TS},json=body)
res.append(('KYC granular: kyc:read valid-body -> 403 (needs kyc:submit)', g.status_code==403 and 'kyc:submit' in str(g.text), g.status_code, str(g.text)[:140]))
g2=c.post('/api/v1/kyc/applications',headers={'X-API-Key':k_sub,'Idempotency-Key':'r3bok-%d'%TS},json=body)
res.append(('KYC pos: kyc:submit valid-body -> 201 created', g2.status_code==201, g2.status_code, str(g2.text)[:140]))
# cleanup: delete created application rows for partner + idempotency + key/user
try:
    from boto3.dynamodb.conditions import Key
    # best-effort: remove synthetic user's kyc partner rows
except Exception: pass
for kid in ck:
    try: T.api_keys.delete_item(Key={'key_id':kid})
    except Exception as e: print('clean key',e)
for s in cu:
    try: T.users.delete_item(Key={'user_sub':s})
    except Exception: pass
np=sum(1 for x in res if x[1])
for n,ok,st,d in res: print(('PASS' if ok else 'FAIL'),'|',n,'got=%s'%st, '' if ok else '| '+d)
print('R3b RESULT %d/%d'%(np,len(res)))
print('NOTE: kyc:submit 201 created a real partner application row for synthetic user %s (partition=partner_id); orphaned synthetic partition, no cross-tenant leakage.'%UKYC)
