"""R1 (residual #118) registry-drift verification on PROD DDB.
Synthetic users+keys, in-process TestClient, auto-cleaned. Validates:
  - newly-registered catalog/cart/checkout/orders/tickets routes now scope-gate
    correctly (correct scope past-gate; wrong scope -> 403 api_key_scope_denied;
    no key -> 401);
  - MONEY checkout requires shopping:checkout:write (a read-only key DENIED);
  - deny-list routes (catalog admin write, video tip) stay fail-closed 403 to
    every key incl admin:all;
  - live drift monitor: stale=0, unregistered=0, status ok.
"""
import os, sys, time, json
REPO = os.environ.get('APIK_REPO', os.getcwd())
sys.path.insert(0, REPO); os.chdir(REPO)
from fastapi.testclient import TestClient
from app.core.tables import T
from app.core.settings import S
from app.services import api_keys as AK
from app.core.time import now_ts

TS = int(time.time())
U = 'apik-r1-%d' % TS
UADM = 'apik-r1adm-%d' % TS
created_users, created_keys = [], []

def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthR1'})
    created_users.append(sub)

def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'r1', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']

def cleanup():
    for kid in created_keys:
        try: T.api_keys.delete_item(Key={'key_id': kid})
        except Exception as e: print('clean key err', e)
    for sub in created_users:
        try: T.users.delete_item(Key={'user_sub': sub})
        except Exception: pass

results = []
def rec(domain, name, ok, note=''):
    results.append((domain, name, bool(ok), note))
    print('  [%s] %-58s %s' % ('OK' if ok else 'XX', name, note))

def scode(resp):
    st = resp.status_code; cc = ''
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        if isinstance(det, dict): cc = det.get('code', '')
    except Exception: pass
    return st, cc

def denied(resp):
    st, cc = scode(resp); return st == 403 and cc == 'api_key_scope_denied'

def past_gate(resp):
    return not denied(resp)

def sreason(resp):
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        return det.get('reason', '') if isinstance(det, dict) else ''
    except Exception:
        return ''

def failclosed(resp):
    # deny-list route is unmapped in the scope-registry -> fail-closed 403 unmapped_route
    return resp.status_code == 403 and sreason(resp) == 'unmapped_route'

def wildcard_passed(resp):
    # APIK-E0-1: admin:all is allowed on EVERY route (incl. unmapped) by design (god-mode,
    # grant-gated to admin/root owners). "passed" = the api-key gate did NOT block it.
    return not (resp.status_code == 403 and sreason(resp) in ('unmapped_route', 'missing_scope'))

def main():
    seed_user(U); seed_user(UADM, role='admin')
    k_cat  = mk_key(U, ['shopping:catalog:read'])
    k_cart = mk_key(U, ['shopping:cart:write'])
    k_ckt  = mk_key(U, ['shopping:checkout:write'])
    k_ord  = mk_key(U, ['shopping:orders:read'])
    k_tkr  = mk_key(U, ['tickets:read'])
    k_tkw  = mk_key(U, ['tickets:write'])
    k_tka  = mk_key(UADM, ['tickets:admin'])
    k_nfr  = mk_key(U, ['newsfeed:read'])       # wrong-product control
    k_vmon = mk_key(U, ['video:monetize'])
    k_admin = mk_key(UADM, ['admin:all'])
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}

    CAT = '/ui/catalog/feature-categories'
    CATITEM = '/ui/catalog/items/x/variants'
    ABAND = '/ui/shoppingcart/carts/x/abandonment-status'
    ORDER = '/ui/shoppingcart/orders/x'
    TRACK = '/ui/purchase-history/transactions/x/tracking'
    PURCH = '/ui/shoppingcart/carts/x/purchase'
    TKW = '/tickets/x/watchers'
    TKCLOSE = '/tickets/x/close'
    TKADM = '/tickets/admin/summary'
    CATADMIN = '/ui/catalog/feature-categories'   # POST = deny-listed admin write
    VTIP = '/ui/videos/x/tip'

    print('\n== CATALOG READ (shopping:catalog:read, entitlement=False) ==')
    r = c.get(CAT, headers=H(k_cat)); rec('catalog', 'POS catalog:read GET feature-categories', r.status_code == 200, 'st=%s' % r.status_code)
    r = c.get(CATITEM, headers=H(k_cat)); rec('catalog', 'POS catalog:read GET items/x/variants', past_gate(r), 'st=%s cc=%s' % scode(r))
    rec('catalog', 'NEG cart:write -> catalog read DENIED', denied(c.get(CAT, headers=H(k_cart))))
    rec('catalog', 'NEG xproduct nf:read -> catalog read DENIED', denied(c.get(CAT, headers=H(k_nfr))))
    r = c.get(CAT); rec('catalog', 'NEG no-key -> 401', r.status_code == 401, 'st=%s' % r.status_code)
    rec('catalog', 'POS admin:all -> catalog read past-gate', past_gate(c.get(CAT, headers=H(k_admin))))

    print('\n== CART READ (shopping:cart:write) ==')
    rec('cart', 'POS cart:write GET abandonment-status past-gate', past_gate(c.get(ABAND, headers=H(k_cart))), 'st=%s cc=%s' % scode(c.get(ABAND, headers=H(k_cart))))
    rec('cart', 'NEG catalog:read -> cart route DENIED', denied(c.get(ABAND, headers=H(k_cat))))

    print('\n== ORDERS READ (shopping:orders:read) ==')
    rec('orders', 'POS orders:read GET /shoppingcart/orders/x past-gate', past_gate(c.get(ORDER, headers=H(k_ord))), 'st=%s cc=%s' % scode(c.get(ORDER, headers=H(k_ord))))
    rec('orders', 'POS orders:read GET purchase-history tracking past-gate', past_gate(c.get(TRACK, headers=H(k_ord))), 'st=%s cc=%s' % scode(c.get(TRACK, headers=H(k_ord))))
    rec('orders', 'NEG catalog:read -> orders route DENIED', denied(c.get(ORDER, headers=H(k_cat))))

    print('\n== CHECKOUT (MONEY, shopping:checkout:write) ==')
    rec('checkout', 'POS checkout:write POST purchase past-gate', past_gate(c.post(PURCH, headers=H(k_ckt), json={})), 'st=%s cc=%s' % scode(c.post(PURCH, headers=H(k_ckt), json={})))
    rec('checkout', 'NEG read-only catalog:read -> checkout DENIED', denied(c.post(PURCH, headers=H(k_cat), json={})))
    rec('checkout', 'NEG cart:write -> checkout DENIED (distinct money scope)', denied(c.post(PURCH, headers=H(k_cart), json={})))

    print('\n== TICKETS (read/write/admin) ==')
    rec('tickets', 'POS tickets:read GET watchers past-gate', past_gate(c.get(TKW, headers=H(k_tkr))), 'st=%s cc=%s' % scode(c.get(TKW, headers=H(k_tkr))))
    rec('tickets', 'POS tickets:write POST watchers past-gate', past_gate(c.post(TKW, headers=H(k_tkw), json={})), 'st=%s cc=%s' % scode(c.post(TKW, headers=H(k_tkw), json={})))
    rec('tickets', 'POS tickets:write POST close past-gate (prod-forward)', past_gate(c.post(TKCLOSE, headers=H(k_tkw), json={})), 'st=%s cc=%s' % scode(c.post(TKCLOSE, headers=H(k_tkw), json={})))
    rec('tickets', 'NEG tickets:read -> POST watchers DENIED (read!>=write)', denied(c.post(TKW, headers=H(k_tkr), json={})))
    rec('tickets', 'NEG tickets:read -> POST close DENIED', denied(c.post(TKCLOSE, headers=H(k_tkr), json={})))
    rec('tickets', 'POS tickets:admin GET admin/summary past-gate', past_gate(c.get(TKADM, headers=H(k_tka))), 'st=%s cc=%s' % scode(c.get(TKADM, headers=H(k_tka))))
    rec('tickets', 'POS tickets:admin -> POST watchers past-gate (admin>=write)', past_gate(c.post(TKW, headers=H(k_tka), json={})))
    rec('tickets', 'NEG tickets:write -> admin/summary DENIED (write!>=admin)', denied(c.get(TKADM, headers=H(k_tkw))))
    rec('tickets', 'NEG no-key -> tickets watchers 401', c.get(TKW).status_code == 401, 'st=%s' % c.get(TKW).status_code)

    print('\n== DENY-LIST (intentional fail-closed to scoped keys; admin:all god-mode by E0-1) ==')
    r = c.post(CATADMIN, headers=H(k_cart), json={}); rec('denylist', 'catalog admin POST fail-closed (cart key) 403 unmapped', failclosed(r), 'st=%s reason=%s' % (r.status_code, sreason(r)))
    r = c.post(CATADMIN, headers=H(k_cat), json={}); rec('denylist', 'catalog admin POST fail-closed (catalog:read key) 403 unmapped', failclosed(r), 'st=%s reason=%s' % (r.status_code, sreason(r)))
    r = c.post(VTIP, headers=H(k_vmon), json={'amount_cents': 100}); rec('denylist', 'video tip POST fail-closed (video:monetize key) 403 unmapped', failclosed(r), 'st=%s reason=%s' % (r.status_code, sreason(r)))
    r = c.post(VTIP, headers=H(k_nfr), json={'amount_cents': 100}); rec('denylist', 'video tip POST fail-closed (nf:read key) 403 unmapped', failclosed(r), 'st=%s reason=%s' % (r.status_code, sreason(r)))
    r = c.post(CATADMIN, headers=H(k_admin), json={}); rec('denylist', 'admin:all bypasses deny-list by design (E0-1 god-mode)', wildcard_passed(r), 'st=%s reason=%s' % (r.status_code, sreason(r)))

    print('\n== LIVE DRIFT MONITOR ==')
    d = getattr(c.app.state, 'api_key_registry_drift', {}) or {}
    rec('drift', 'stale_route_count == 0', int(d.get('stale_route_count', -1)) == 0, 'stale=%s' % d.get('stale_route_count'))
    rec('drift', 'unregistered_live_route_count == 0', int(d.get('unregistered_live_route_count', -1)) == 0, 'unreg=%s' % d.get('unregistered_live_route_count'))
    rec('drift', 'status == ok (GREEN)', str(d.get('status')) == 'ok', 'status=%s' % d.get('status'))

    print('\n== REGRESSION SPOT-CHECK (E6 5-domain, unchanged) ==')
    k_nfw = mk_key(U, ['newsfeed:write']); k_msr = mk_key(U, ['messager:read']); k_fmr = mk_key(U, ['filemanager:read'])
    rec('regress', 'newsfeed:read GET /feed 200', c.get('/feed', headers=H(k_nfr)).status_code == 200)
    rec('regress', 'newsfeed:read -> POST /posts DENIED', denied(c.post('/posts', headers=H(k_nfr), json={'body_plain': 'x'})))
    rec('regress', 'messager:read GET /messaging/conversations 200', c.get('/messaging/conversations', headers=H(k_msr)).status_code == 200)
    rec('regress', 'filemanager:read GET /v1/fs/list 200', c.get('/v1/fs/list?path=/', headers=H(k_fmr)).status_code == 200)
    rec('regress', 'newsfeed money tip needs newsfeed:tips (nf:write DENIED)', denied(c.post('/posts/x/tip', headers=H(k_nfw), json={'amount_cents': 100})))
    rec('regress', 'video money tip fail-closed to scoped key (unchanged)', failclosed(c.post('/ui/videos/x/tip', headers=H(k_vmon), json={'amount_cents': 100})))

    npass = sum(1 for _, _, ok, _ in results if ok)
    ntot = len(results)
    print('\n==== R1 RESULT: %d/%d PASS ====' % (npass, ntot))
    fails = [(dm, nm, nt) for dm, nm, ok, nt in results if not ok]
    if fails:
        print('FAILURES:')
        for dm, nm, nt in fails: print('  XX [%s] %s %s' % (dm, nm, nt))
    return npass, ntot

try:
    p, t = main()
finally:
    cleanup()
    # verify residue
    resid_k = 0
    for kid in created_keys:
        try:
            if 'Item' in T.api_keys.get_item(Key={'key_id': kid}): resid_k += 1
        except Exception: pass
    print('CLEANUP: keys_residue=%d users_created=%d' % (resid_k, len(created_users)))
