import time
from app.core.tables import T
from app.services import creator_earnings as CE
try:
    from app.services.creator_payouts import get_available_balance
except Exception as e:
    get_available_balance = None
    print('WARN no get_available_balance', e)

uid = 'e2e_fix1_verify_user'
now = int(time.time())
sk = f'LEDGER#{now}#fix1test'
pk = f'USER#{uid}'
row = {
    'pk': pk, 'sk': sk, 'type': 'credit', 'amount_cents': 400,
    'ts': now, 'currency': 'USD', 'content_type': 'tip', 'reason': 'tip',
    'entry_id': 'fix1test', 'net_amount_cents': 400,
}
T.billing.put_item(Item=row)
try:
    s1 = CE.get_earnings_summary(uid)
    b1 = get_available_balance(uid) if get_available_balance else {}
    print('PRE  gross_total_cents =', s1['total_cents'], 'tips=', s1['breakdown'].get('tips'), 'txns=', s1['transaction_count'])
    print('PRE  available =', b1)
    # reverse it
    T.billing.update_item(Key={'pk': pk, 'sk': sk},
        UpdateExpression='SET #s = :r', ExpressionAttributeNames={'#s':'state'},
        ExpressionAttributeValues={':r':'reversed'})
    s2 = CE.get_earnings_summary(uid)
    b2 = get_available_balance(uid) if get_available_balance else {}
    print('POST gross_total_cents =', s2['total_cents'], 'tips=', s2['breakdown'].get('tips'), 'txns=', s2['transaction_count'])
    print('POST available =', b2)
    ok_gross = (s1['total_cents'] == 400 and s2['total_cents'] == 0 and s2['transaction_count'] == 0)
    avail_post = (b2.get('available_cents', b2.get('available', 0)) if isinstance(b2, dict) else 0)
    ok_avail = (avail_post == 0)
    print('RESULT FIX1_GROSS_EXCLUDES_REVERSED =', ok_gross)
    print('RESULT FIX1_AVAILABLE_STAYS_0 =', ok_avail)
    print('OVERALL', 'PASS' if (ok_gross and ok_avail) else 'FAIL')
finally:
    T.billing.delete_item(Key={'pk': pk, 'sk': sk})
    print('cleanup: deleted test row')
