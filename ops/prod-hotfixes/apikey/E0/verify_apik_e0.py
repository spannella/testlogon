import os, sys, time, traceback
sys.path.insert(0, '/home/ubuntu/testlogon')
os.chdir('/home/ubuntu/testlogon')
PHASE = os.environ.get('APIK_PHASE', 'BEFORE')
from fastapi.testclient import TestClient
from app.core.tables import T
from app.core.settings import S
from app.services import api_keys as AK
from app.services.sessions import mint_access_token
from app.core.time import now_ts

TS = int(time.time())
U  = 'apik-e0-synth-%d' % TS     # non-admin owner
UA = 'apik-e0-admin-%d' % TS     # admin owner
created_users, created_keys = [], []

def seed_user(sub, role):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE0'})
    created_users.append(sub)

def mk_key(sub, caps, label='e0'):
    r = AK.create_api_key(sub, label, expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id'])
    return r['key_secret']

def cleanup():
    for kid in created_keys:
        try: T.api_keys.delete_item(Key={'key_id': kid})
        except Exception as e: print('cleanup key err', kid, e)
    for sub in created_users:
        try: T.users.delete_item(Key={'user_sub': sub})
        except Exception as e: print('cleanup user err', sub, e)

results = []
def check(name, got, expect_set, note=''):
    ok = got in expect_set
    results.append((name, got, ok))
    print('%-54s got=%-9s expect=%-16s %s %s' % (name, got, '/'.join(map(str, sorted(expect_set))), 'OK' if ok else 'XX', note))

try:
    seed_user(U, 'user'); seed_user(UA, 'admin')
    k_msgr = mk_key(U, ['messager:read'])
    k_fm   = mk_key(U, ['filemanager:read'])
    k_nf   = mk_key(U, ['newsfeed:read'])
    k_admin_all = None
    if PHASE == 'AFTER':
        try:
            r = AK.create_api_key(UA, 'wild', expires_in_days=1, capabilities=['admin:all'])
            created_keys.append(r['key_id']); k_admin_all = r['key_secret']
        except Exception as e:
            print('admin:all create for admin owner FAILED', getattr(e, 'status_code', None), getattr(e, 'detail', ''))

    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}
    print('==== PHASE=%s ts=%d ====' % (PHASE, TS))

    hole_exp = {200} if PHASE == 'BEFORE' else {401, 403}
    check('HOLE  groups GET /ui/groups [messager:read]', c.get('/ui/groups', headers=H(k_msgr)).status_code, hole_exp, 'BEFORE=200 owner(hole)/AFTER=fail-closed')
    check('HOLE  video  GET /ui/videos [messager:read]', c.get('/ui/videos', headers=H(k_msgr)).status_code, hole_exp, 'BEFORE=200 owner(hole)/AFTER=fail-closed')
    check('KEYED msg    GET /messaging/conversations [msgr:read]', c.get('/messaging/conversations', headers=H(k_msgr)).status_code, {200}, 'keyed route unaffected')
    check('KEYED fm     GET /v1/fs/list?path=/ [fm:read]', c.get('/v1/fs/list?path=/', headers=H(k_fm)).status_code, {200}, 'keyed route unaffected')
    check('NEG   scope  GET /v1/fs/list?path=/ [msgr:read]', c.get('/v1/fs/list?path=/', headers=H(k_msgr)).status_code, {403}, 'wrong scope 403')
    check('NF    phantom GET /feed [nf:read]', c.get('/feed', headers=H(k_nf)).status_code, {403}, 'unmapped (E1 re-points)')

    # UI session unaffected (cookie via header; require_ui_session falls back to authed context)
    tok = mint_access_token(U, 'synthsess-%d' % TS)
    ck_hdr = {'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok)}
    check('SESSION groups GET /ui/groups [cookie]', c.get('/ui/groups', headers=ck_hdr).status_code, {200}, 'UI session unaffected')

    # dak_ delegation Bearer path intact (bogus key -> clean 401, never 500/200)
    dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization': 'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
    check('DAK   bogus GET /ui/delegation-api/v1/conversations', dsc, {401, 403}, 'delegation path intact (untouched)')

    # admin:all wildcard behaviour
    if PHASE == 'AFTER' and k_admin_all:
        check('WILD  gated msg  [admin:all]', c.get('/messaging/conversations', headers=H(k_admin_all)).status_code, {200}, 'wildcard works on gated router')
        check('WILD  gated fs   [admin:all]', c.get('/v1/fs/list?path=/', headers=H(k_admin_all)).status_code, {200}, 'wildcard cross-product on gated')
        check('WILD  ungated groups [admin:all]', c.get('/ui/groups', headers=H(k_admin_all)).status_code, {401, 403}, 'even wildcard fail-closed on un-modeled router')

    # admin:all create gate (E0-1)
    try:
        AK.create_api_key(U, 'wild-nonadmin', expires_in_days=1, capabilities=['admin:all'])
        check('GATE  non-admin admin:all create', 'CREATED', {'DENIED403'}, 'must be denied')
    except Exception as e:
        code = getattr(e, 'status_code', None); det = getattr(e, 'detail', {})
        cc = det.get('code') if isinstance(det, dict) else str(det)
        check('GATE  non-admin admin:all create', 'DENIED403' if code == 403 else 'code%s' % code, {'DENIED403'}, 'code=%s' % cc)
    if PHASE == 'AFTER':
        check('GATE  admin admin:all create', 'CREATED' if k_admin_all else 'FAILED', {'CREATED'}, 'admin owner allowed')

    # E0-5 stale drift == 0 (phantom rows deleted)
    from app.services.api_key_route_scope_registry import summarize_registry_drift
    live = set()
    for route in c.app.routes:
        path = str(getattr(route, 'path', '') or '').strip()
        for m in (getattr(route, 'methods', set()) or set()):
            m = str(m or '').upper().strip()
            if path and m and m not in ('HEAD', 'OPTIONS'):
                live.add('%s:%s' % (m, path))
    drift = summarize_registry_drift(live)
    check('E0-5  stale_route_count', drift['stale_route_count'], {0} if PHASE == 'AFTER' else {0, 7}, 'phantom rows gone')
    print('       (unregistered_live_route_count=%d — worked down by E1-E5 domain epics)' % drift['unregistered_live_route_count'])

    npass = sum(1 for _, _, ok in results if ok); nfail = len(results) - npass
    print('SUMMARY phase=%s pass=%d fail=%d' % (PHASE, npass, nfail))
except Exception as e:
    print('FATAL', e); traceback.print_exc()
finally:
    cleanup()
    print('CLEANUP done: keys=%d users=%d removed' % (len(created_keys), len(created_users)))
