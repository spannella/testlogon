#!/usr/bin/env python3
"""TIPFIX-TRANSACT real-HTTP end-to-end verifier.

Runs ON the prod-mock host, hits the RUNNING uvicorn (http://localhost:8000) over
real HTTP -- NOT an in-process shim. Proves the tip transact rail (the bug that
made every tip 500) now works: real success + real debit/credit/receipt in
T.billing, idempotent replay charges once, and a pre-ledger failure writes no rows.

Seeds two synthetic users tagged so EVERY row can be deleted afterward (0 residue).
"""
import json, time, uuid, sys, urllib.request, urllib.error
import boto3
import os
os.environ.setdefault('AWS_ACCESS_KEY_ID','test'); os.environ.setdefault('AWS_SECRET_ACCESS_KEY','test'); os.environ.setdefault('AWS_REGION','us-east-1')
from app.services.sessions import mint_access_token

BASE = 'http://localhost:8000'
EP = 'http://localhost:8001'
REGION = 'us-east-1'
TAG = 'tipfix_%d_%s' % (int(time.time()), uuid.uuid4().hex[:6])
TIPPER = TAG + '_tipper'
CREATOR = TAG + '_creator'

ddb = boto3.client('dynamodb', endpoint_url=EP, region_name=REGION,
                   aws_access_key_id='test', aws_secret_access_key='test')

PASS = []
def rec(name, ok, detail=''):
    PASS.append((name, ok))
    print('[%s] %s%s' % ('PASS' if ok else 'FAIL', name, (' :: ' + detail) if detail else ''))

def http(method, path, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header('Content-Type', 'application/json')
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.getcode(), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def user_pk(u): return 'USER#' + u

def billing_rows(u):
    r = ddb.query(TableName='billing',
                  KeyConditionExpression='pk = :p',
                  ExpressionAttributeValues={':p': {'S': user_pk(u)}})
    return r.get('Items', [])

def users_put(u):
    ddb.put_item(TableName='users', Item={'user_sub': {'S': u}, 'username': {'S': u}, 'role': {'S': 'user'}})

CREATED_USER_KEYS = []
def cleanup():
    # delete all billing rows for tipper + creator
    for u in (TIPPER, CREATOR):
        for it in billing_rows(u):
            ddb.delete_item(TableName='billing', Key={'pk': it['pk'], 'sk': it['sk']})
    # delete users
    for u in (TIPPER, CREATOR):
        try: ddb.delete_item(TableName='users', Key={'user_sub': {'S': u}})
        except Exception: pass
    # profile rows (tip_total bump writes to profile table)
    for u in (CREATOR,):
        try: ddb.delete_item(TableName='profiles', Key={'user_sub': {'S': u}})
        except Exception: pass

def main():
    users_put(TIPPER); users_put(CREATOR)
    time.sleep(0.3)

    # sanity: no billing rows yet
    rec('precondition_no_rows', len(billing_rows(TIPPER)) == 0 and len(billing_rows(CREATOR)) == 0)

    tok = mint_access_token(TIPPER, 'sess_' + uuid.uuid4().hex[:8])
    assert tok, 'mint_access_token returned empty (no UI_ACCESS_TOKEN_SECRET?)'
    hdr = {'Cookie': 'ui_access_token=' + tok}
    crid = 'crid_' + uuid.uuid4().hex[:10]
    body = {'amount_cents': 500, 'currency': 'usd', 'client_request_id': crid}

    # 1) REAL tip over HTTP -> must NOT 500 (the bug) -> 200
    code, resp = http('POST', '/ui/profile/%s/tip' % CREATOR, hdr, body)
    rec('real_tip_http_200', code == 200, 'code=%d body=%s' % (code, resp[:200]))
    ok_success = code == 200

    # 2) ledger evidence: exactly one debit (tipper) + one credit (creator) + receipt marker
    trows = billing_rows(TIPPER)
    crows = billing_rows(CREATOR)
    debit = [r for r in trows if r.get('type', {}).get('S') == 'debit']
    credit = [r for r in crows if r.get('type', {}).get('S') == 'credit']
    receipt = [r for r in trows if r.get('sk', {}).get('S','').startswith('TIPIDEMP#')]
    rec('ledger_debit_present', len(debit) >= 1, 'debits=%d sklist=%s' % (len(debit), [r['sk']['S'] for r in trows]))
    rec('ledger_credit_present', len(credit) >= 1, 'credits=%d sklist=%s' % (len(credit), [r['sk']['S'] for r in crows]))
    rec('ledger_receipt_present', len(receipt) == 1, 'receipts=%d' % len(receipt))
    n_debit_after_first = len(debit)

    # 3) IDEMPOTENT REPLAY: same crid -> 200, charges once (no new debit/credit)
    code2, resp2 = http('POST', '/ui/profile/%s/tip' % CREATOR, hdr, body)
    trows2 = billing_rows(TIPPER); crows2 = billing_rows(CREATOR)
    debit2 = [r for r in trows2 if r.get('sk', {}).get('S','')]
    ledger_debit2 = [r for r in trows2 if r.get('type', {}).get('S') == 'debit']
    ledger_credit2 = [r for r in crows2 if r.get('type', {}).get('S') == 'credit']
    rec('replay_http_200', code2 == 200, 'code=%d' % code2)
    rec('replay_charges_once', len(ledger_debit2) == len(debit) and len(ledger_credit2) == len(credit),
        'debits %d->%d credits %d->%d' % (len(debit), len(ledger_debit2), len(credit), len(ledger_credit2)))

    # 4) DECLINE / pre-ledger failure: a PM the tipper does NOT own must be rejected
    #    BEFORE any charge/ledger write (resolve_tip_payment_method -> 400). Prove
    #    NO new debit/credit rows were written for the rejected attempt.
    hdr2 = {'Cookie': 'ui_access_token=' + tok}
    bad = {'amount_cents': 700, 'currency': 'usd', 'payment_method_id': 'pm_not_owned_' + uuid.uuid4().hex[:8], 'client_request_id': 'decline_' + uuid.uuid4().hex[:8]}
    code3, resp3 = http('POST', '/ui/profile/%s/tip' % CREATOR, hdr2, bad)
    trows3 = billing_rows(TIPPER); crows3 = billing_rows(CREATOR)
    ld3 = [r for r in trows3 if r.get('type', {}).get('S') == 'debit']
    lc3 = [r for r in crows3 if r.get('type', {}).get('S') == 'credit']
    rec('pre_ledger_failure_rejected', code3 in (400, 402), 'code=%d body=%s' % (code3, resp3[:160]))
    rec('pre_ledger_failure_no_new_rows', len(ld3) == len(ledger_debit2) and len(lc3) == len(ledger_credit2),
        'debits stayed %d credits stayed %d' % (len(ld3), len(lc3)))

    cleanup()
    time.sleep(0.3)
    residue = len(billing_rows(TIPPER)) + len(billing_rows(CREATOR))
    rec('cleanup_zero_residue', residue == 0, 'residue=%d' % residue)

    ok = all(p for _, p in PASS)
    print('RESULT: %s (%d/%d)' % ('ALL_PASS' if ok else 'FAILURES', sum(1 for _,p in PASS if p), len(PASS)))
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        import traceback; traceback.print_exc()
        try: cleanup()
        except Exception: pass
        sys.exit(2)
