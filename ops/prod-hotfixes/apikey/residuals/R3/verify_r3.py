"""R3 (#118) verify: ads:*/kyc:* partner-subsystem enforcement, prod DDB, TestClient.
Proves: correct-scope key ADMITTED (pos), wrong/no-scope key DENIED (neg, never owner-200),
granular scope (read cannot write), cross-domain isolation, E0-4 no-owner-injection.
Synthetic users/keys/ad-account, auto-cleaned."""
import os, sys, time
REPO = os.environ.get('APIK_REPO', os.getcwd()); sys.path.insert(0, REPO); os.chdir(REPO)
from fastapi.testclient import TestClient
from app.core.tables import T
from app.services import api_keys as AK
from app.services import ad_accounts
from app.models import AdAccountCreateIn
from app.core.time import now_ts
from app.main import app

TS = int(time.time())
UADS = 'apik-r3ads-%d' % TS
UKYC = 'apik-r3kyc-%d' % TS
created_users, created_keys, created_accts = [], [], []
def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub,'role':role,'email':sub+'@synthetic.local','created_at':now_ts(),'display_name':'synthR3'})
    created_users.append(sub)
def mk_key(sub, caps):
    r = AK.create_api_key(sub,'r3',expires_in_days=1,capabilities=caps); created_keys.append(r['key_id']); return r['key_secret']
def cleanup():
    for aid in created_accts:
        try: T.ad_accounts.delete_item(Key={'pk':'ACCT#'+aid,'sk':'META'})
        except Exception as e: print('clean acct err',e)
    for kid in created_keys:
        try: T.api_keys.delete_item(Key={'key_id':kid})
        except Exception as e: print('clean key err',e)
    for sub in created_users:
        try: T.users.delete_item(Key={'user_sub':sub})
        except Exception: pass

results=[]
def check(name, got, expect_status, must_not_have=None, must_have=None):
    ok = (got.status_code == expect_status)
    body = None
    try: body = got.json()
    except Exception: body = got.text
    detail = body.get('detail') if isinstance(body,dict) else body
    if ok and must_not_have is not None:
        s = str(detail)
        if must_not_have in s: ok=False
    if ok and must_have is not None:
        if must_have not in str(detail): ok=False
    results.append((name, ok, got.status_code, expect_status, str(detail)[:160]))

c = TestClient(app)
try:
    seed_user(UADS); seed_user(UKYC)
    acct = ad_accounts.create_ad_account(UADS, AdAccountCreateIn(company_name='R3 Synth Co', billing_email='r3@synthetic.local'))
    created_accts.append(acct['account_id'])

    k_ads_read   = mk_key(UADS, ['ads:read'])
    k_ads_manage = mk_key(UADS, ['ads:manage'])
    k_kyc_read   = mk_key(UKYC, ['kyc:read'])
    k_kyc_submit = mk_key(UKYC, ['kyc:submit'])
    k_msg        = mk_key(UADS, ['messager:manage'])   # 5-domain scope, wrong-domain
    k_ads_only   = mk_key(UADS, ['ads:read'])          # ads key vs kyc route (cross-domain)

    H = lambda s: {'X-API-Key': s}

    # ---- ADS representative route: GET /api/v1/ads/account ----
    check('ADS pos: ads:read -> 200 account', c.get('/api/v1/ads/account', headers=H(k_ads_read)), 200)
    check('ADS neg: no key -> 401', c.get('/api/v1/ads/account'), 401)
    check('ADS neg: messager:manage (5-domain) -> 403 scope, NOT owner-200',
          c.get('/api/v1/ads/account', headers=H(k_msg)), 403, must_have='ads:read')
    check('ADS neg: kyc:read cross-domain -> 403',
          c.get('/api/v1/ads/account', headers=H(k_kyc_read)), 403, must_have='ads:read')
    # granular: read cannot write (POST campaigns needs ads:manage)
    check('ADS granular: ads:read -> POST campaigns 403 (needs ads:manage)',
          c.post('/api/v1/ads/campaigns', headers=H(k_ads_read),
                 json={'name':'x','objective':'awareness','budget_cents':1000,'budget_type':'daily'}), 403, must_have='ads:manage')
    check('ADS pos: ads:manage -> GET campaigns 200 (implies read)',
          c.get('/api/v1/ads/campaigns', headers=H(k_ads_manage)), 200)

    # ---- KYC representative route: GET /api/v1/kyc/applications ----
    check('KYC pos: kyc:read -> 200 list', c.get('/api/v1/kyc/applications', headers=H(k_kyc_read)), 200)
    check('KYC neg: no key -> 401', c.get('/api/v1/kyc/applications'), 401)
    check('KYC neg: messager:manage (5-domain) -> 403 scope, NOT owner-200',
          c.get('/api/v1/kyc/applications', headers=H(k_msg)), 403, must_have='kyc:read')
    check('KYC neg: ads:read cross-domain -> 403',
          c.get('/api/v1/kyc/applications', headers=H(k_ads_only)), 403, must_have='kyc:read')
    # granular: read cannot submit (POST applications needs kyc:submit)
    check('KYC granular: kyc:read -> POST applications 403 (needs kyc:submit)',
          c.post('/api/v1/kyc/applications', headers={**H(k_kyc_read),'Idempotency-Key':'r3-%d'%TS},
                 json={'external_id':'r3ext','applicant':{'first_name':'A','last_name':'B'},'tier':'tier1'}), 403, must_have='kyc:submit')

    # invalid key -> 401
    check('BOTH neg: garbage key -> 401 ads', c.get('/api/v1/ads/account', headers=H('ak_garbage_invalid')), 401)
    check('BOTH neg: garbage key -> 401 kyc', c.get('/api/v1/kyc/applications', headers=H('ak_garbage_invalid')), 401)
finally:
    cleanup()

npass = sum(1 for r in results if r[1])
for name, ok, got, exp, det in results:
    print(('PASS' if ok else 'FAIL'), '| %-58s' % name, 'got=%s exp=%s' % (got,exp), '' if ok else '| '+det)
print('R3 RESULT %d/%d' % (npass, len(results)))
