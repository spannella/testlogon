import os, sys, time, traceback
REPO = os.environ.get('APIK_REPO', os.getcwd())
sys.path.insert(0, REPO); os.chdir(REPO)
PHASE = os.environ.get('APIK_PHASE', 'AFTER')
from fastapi.testclient import TestClient
from app.core.tables import T
from app.core.settings import S
from app.services import api_keys as AK
from app.services.sessions import mint_access_token
from app.core.time import now_ts

TS = int(time.time())
U = 'apik-e4-synth-%d' % TS          # group owner/admin (role user)
U2 = 'apik-e4-synth2-%d' % TS        # second member/target (role user)
UADM = 'apik-e4-admin-%d' % TS       # admin owner for admin:all wildcard key
created_users, created_keys, created_groups = [], [], []


def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE4'})
    created_users.append(sub)


def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'e4', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']


def cleanup():
    try:
        from app.services import user_groups as ug
        for gid in created_groups:
            try: ug.dissolve_group(group_id=gid, admin_id=U)
            except Exception: pass
    except Exception as e:
        print('grp cleanup warn', e)
    for kid in created_keys:
        try: T.api_keys.delete_item(Key={'key_id': kid})
        except Exception as e: print('clean key err', e)
    for sub in created_users:
        try: T.users.delete_item(Key={'user_sub': sub})
        except Exception: pass


results = []
def check(name, got, expect_set, note=''):
    ok = got in expect_set
    results.append((name, got, ok))
    print('%-62s got=%-22s expect=%-20s %s %s' % (name, got, '/'.join(map(str, sorted(map(str, expect_set)))), 'OK' if ok else 'XX', note))


def scode(resp):
    code = ''
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        if isinstance(det, dict):
            code = det.get('code', '')
    except Exception: pass
    return resp.status_code, code


def is_scope_denied(resp):
    st, cc = scode(resp)
    return st == 403 and cc == 'api_key_scope_denied'


def pg(resp):
    # 'passed' if the request got past the api-key scope gate (not a scope denial)
    return 'passed' if not is_scope_denied(resp) else 'scope_denied'


try:
    seed_user(U); seed_user(U2); seed_user(UADM, role='admin')
    k_read = mk_key(U, ['groups:read'])
    k_write = mk_key(U, ['groups:write'])
    k_manage = mk_key(U, ['groups:manage'])
    k_treasury = mk_key(U, ['groups:treasury'])
    k_fund = mk_key(U, ['fundraising:write'])
    k_wrong = mk_key(U, ['messager:read'])
    k_fm = mk_key(U, ['filemanager:read'])
    k_admin = mk_key(UADM, ['admin:all'])
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}
    print('==== PHASE=%s ts=%d repo=%s dev_mode=%s groups_phase=%s ====' % (PHASE, TS, REPO, getattr(S, 'dev_mode', None), S.api_key_groups_phase))

    if PHASE == 'BEFORE':
        # Pre-E4: group routers are un-gated -> keys fall through -> require_ui_session
        # sees an injected principal WITHOUT the route-authorized marker (E0-4) -> session
        # auth -> 401 fail-closed. Groups (incl. money) are fully closed to every key.
        check('BEFORE groups:read -> GET /ui/groups (un-gated)', c.get('/ui/groups', headers=H(k_read)).status_code, {401}, 'fail-closed (E0)')
        check('BEFORE groups:treasury -> POST treasury/spend (un-gated)', c.post('/ui/groups/g_x/treasury/spend', headers=H(k_treasury), json={'amount_cents': 100, 'reason': 'x'}).status_code, {401}, 'money fail-closed')
        check('BEFORE groups:write -> POST /ui/groups create (un-gated)', c.post('/ui/groups', headers=H(k_write), json={'name': 'x'}).status_code, {401}, 'closed to keys')
        check('BEFORE no-regression messager:read -> /messaging/conversations', c.get('/messaging/conversations', headers=H(k_wrong)).status_code, {200}, 'already-keyed')
    else:
        # ===================== E4-2 CRUD / membership / feed =====================
        rc = c.post('/ui/groups', headers=H(k_write), json={'name': 'E4 grp %d' % TS, 'description': 'synthetic', 'visibility': 'public'})
        gid = rc.json().get('group_id', '') if rc.status_code in (200, 201) else ''
        if gid: created_groups.append(gid)
        check('E4-2 write POST /ui/groups (create)', rc.status_code, {201}, 'gid=%s' % gid[:18])
        check('E4-2 read  GET /ui/groups (list)', c.get('/ui/groups', headers=H(k_read)).status_code, {200}, '')
        check('E4-2 read  GET /ui/groups/{gid}', c.get('/ui/groups/%s' % gid, headers=H(k_read)).status_code, {200}, '')
        check('E4-2 read  GET /ui/groups/{gid}/members', c.get('/ui/groups/%s/members' % gid, headers=H(k_read)).status_code, {200}, '')
        rp = c.post('/ui/groups/%s/posts' % gid, headers=H(k_write), json={'text': 'hello E4 feed'})
        check('E4-2 write POST /ui/groups/{gid}/posts (feed)', rp.status_code, {201}, scode(rp)[1])
        check('E4-2 read  GET /ui/groups/{gid}/feed', c.get('/ui/groups/%s/feed' % gid, headers=H(k_read)).status_code, {200}, '')
        check('E4-2 write POST /ui/groups/{gid}/invite (membership)', pg(c.post('/ui/groups/%s/invite' % gid, headers=H(k_write), json={'user_id': U2})), {'passed'}, 'write manages membership')
        # settings requires groups:manage
        check('E4-2 manage PATCH /ui/groups/{gid} (settings)', c.patch('/ui/groups/%s' % gid, headers=H(k_manage), json={'description': 'renamed'}).status_code, {200}, '')
        check('E4-2 manage PATCH members/{u}/role', pg(c.patch('/ui/groups/%s/members/%s/role' % (gid, U2), headers=H(k_manage), json={'role': 'moderator'})), {'passed'}, '')
        check('E4-2 read  GET /ui/calls/group/history/{cid}', pg(c.get('/ui/calls/group/history/conv_%s' % TS, headers=H(k_read))), {'passed'}, 'calls read')
        check('E4-2 write POST /ui/calls/group/create', pg(c.post('/ui/calls/group/create', headers=H(k_write), json={'conversation_id': 'conv_%s' % TS})), {'passed'}, 'calls write')

        # ===================== E4-3 MONEY: treasury + fundraiser =================
        check('E4-3 treasury POST contribute', pg(c.post('/ui/groups/%s/treasury/contribute' % gid, headers=H(k_treasury), json={'amount_cents': 500})), {'passed'}, 'groups:treasury')
        check('E4-3 treasury POST spend', pg(c.post('/ui/groups/%s/treasury/spend' % gid, headers=H(k_treasury), json={'amount_cents': 100, 'reason': 'supplies'})), {'passed'}, 'groups:treasury')
        check('E4-3 treasury PATCH goal', pg(c.patch('/ui/groups/%s/treasury/goal' % gid, headers=H(k_treasury), json={'goal_cents': 10000})), {'passed'}, 'groups:treasury')
        check('E4-3 read  GET /ui/groups/{gid}/treasury (balance)', c.get('/ui/groups/%s/treasury' % gid, headers=H(k_read)).status_code, {200}, 'groups:read')
        check('E4-3 fundraise POST fundraisers', pg(c.post('/ui/groups/fundraising/%s/fundraisers' % gid, headers=H(k_fund), json={'title': 'Save the servers'})), {'passed'}, 'fundraising:write')
        check('E4-3 fundraise POST campaigns', pg(c.post('/ui/groups/fundraising/%s/campaigns' % gid, headers=H(k_fund), json={'name': 'camp', 'daily_budget_cents': 100, 'lifetime_budget_cents': 1000})), {'passed'}, 'fundraising:write')
        check('E4-3 read  GET fundraisers list', c.get('/ui/groups/fundraising/%s/fundraisers' % gid, headers=H(k_read)).status_code, {200}, 'groups:read')

        # ===================== NEGATIVE / SECURITY matrix =======================
        check('NEG read  -> POST /ui/groups create', is_scope_denied(c.post('/ui/groups', headers=H(k_read), json={'name': 'no'})), {True}, 'read!=write')
        check('NEG read  -> POST feed post', is_scope_denied(c.post('/ui/groups/%s/posts' % gid, headers=H(k_read), json={'text': 'no'})), {True}, '')
        check('NEG write -> PATCH settings (needs manage)', is_scope_denied(c.patch('/ui/groups/%s' % gid, headers=H(k_write), json={'description': 'no'})), {True}, '')
        check('NEG write -> PATCH role (needs manage)', is_scope_denied(c.patch('/ui/groups/%s/members/%s/role' % (gid, U2), headers=H(k_write), json={'role': 'moderator'})), {True}, '')
        check('NEG write -> DELETE member (needs manage)', is_scope_denied(c.delete('/ui/groups/%s/members/%s' % (gid, U2), headers=H(k_write))), {True}, '')
        check('NEG write -> DELETE group dissolve (needs manage)', is_scope_denied(c.delete('/ui/groups/%s' % gid, headers=H(k_write))), {True}, '')
        # *** headline: E0 hole stays closed — a plain groups:write key CANNOT move money ***
        check('SEC  write -> POST treasury/spend (MONEY)', is_scope_denied(c.post('/ui/groups/%s/treasury/spend' % gid, headers=H(k_write), json={'amount_cents': 100, 'reason': 'x'})), {True}, 'write CANNOT move money')
        check('SEC  write -> POST treasury/contribute', is_scope_denied(c.post('/ui/groups/%s/treasury/contribute' % gid, headers=H(k_write), json={'amount_cents': 100})), {True}, '')
        check('SEC  write -> PATCH treasury/goal', is_scope_denied(c.patch('/ui/groups/%s/treasury/goal' % gid, headers=H(k_write), json={'goal_cents': 5})), {True}, '')
        # manage does NOT inherit treasury (standalone high-priv money scope)
        check('SEC  manage -> POST treasury/spend (no treasury inherit)', is_scope_denied(c.post('/ui/groups/%s/treasury/spend' % gid, headers=H(k_manage), json={'amount_cents': 100, 'reason': 'x'})), {True}, 'manage!=treasury')
        check('SEC  manage -> POST fundraisers (needs fundraising:write)', is_scope_denied(c.post('/ui/groups/fundraising/%s/fundraisers' % gid, headers=H(k_manage), json={'title': 'no'})), {True}, 'manage!=fundraise')
        check('SEC  write -> POST campaigns (needs fundraising:write)', is_scope_denied(c.post('/ui/groups/fundraising/%s/campaigns' % gid, headers=H(k_write), json={'name': 'no', 'daily_budget_cents': 1, 'lifetime_budget_cents': 1})), {True}, '')
        check('NEG wrong-scope messager:read -> GET /ui/groups', is_scope_denied(c.get('/ui/groups', headers=H(k_wrong))), {True}, '')
        check('NEG wrong-scope messager:read -> POST treasury/spend', is_scope_denied(c.post('/ui/groups/%s/treasury/spend' % gid, headers=H(k_wrong), json={'amount_cents': 1, 'reason': 'x'})), {True}, '')

        # confirm-donation: UNREGISTERED -> fail-closed to keys; stays require_root for sessions
        st, cc = scode(c.post('/ui/groups/fundraising/%s/fundraisers/f_x/donations/d_x/confirm' % gid, headers=H(k_treasury), json={}))
        check('SEC  key -> confirm-donation UNMAPPED 403', st, {403}, 'code=%s (fail-closed)' % cc)
        # wildcard passes scope even on unmapped, but require_root still blocks a non-root owner
        check('SEC  admin:all -> confirm-donation still root-gated', c.post('/ui/groups/fundraising/%s/fundraisers/f_x/donations/d_x/confirm' % gid, headers=H(k_admin), json={}).status_code, {403}, 'require_root intact')
        # non-root SESSION -> confirm -> require_root 403 (cookie-based UI session; prod has
        # Cognito enabled so x-user-sub isn't honored -> use the real HMAC access-token cookie)
        sid = 'synthsess-%d' % TS
        tok = mint_access_token(U, sid)
        sess_hdrs = ({'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok)} if tok else {'x-user-sub': U})
        check('SEC  session(non-root) -> confirm-donation 403', c.post('/ui/groups/fundraising/%s/fundraisers/f_x/donations/d_x/confirm' % gid, headers=sess_hdrs, json={}).status_code, {403}, 'root-only')

        # ===================== REGRESSION =======================================
        check('REG  session(no key) -> GET /ui/groups', c.get('/ui/groups', headers=sess_hdrs).status_code, {200}, 'UI session unaffected')
        check('REG  no-cred -> GET /ui/groups', c.get('/ui/groups').status_code, {401}, 'session required')
        check('REG  invalid key -> GET /ui/groups', c.get('/ui/groups', headers={'X-API-Key': 'ak_bogus.deadbeef'}).status_code, {401}, 'bad principal')
        check('REG  admin:all wildcard -> GET /ui/groups', c.get('/ui/groups', headers=H(k_admin)).status_code, {200}, 'wildcard works')
        check('REG  no-regression messager:read -> /messaging/conversations', c.get('/messaging/conversations', headers=H(k_wrong)).status_code, {200}, 'E2 keyed intact')
        check('REG  no-regression filemanager:read -> /v1/fs/list', c.get('/v1/fs/list?path=/', headers=H(k_fm)).status_code, {200}, 'E3 keyed intact')
        dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization': 'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
        check('REG  dak_ bogus delegation 401/403', dsc, {401, 403}, 'delegation intact')

    npass = sum(1 for _, _, ok in results if ok); nfail = len(results) - npass
    print('SUMMARY phase=%s pass=%d fail=%d' % (PHASE, npass, nfail))
except Exception as e:
    print('FATAL', e); traceback.print_exc()
finally:
    cleanup()
    print('CLEANUP done: keys=%d users=%d groups=%d' % (len(created_keys), len(created_users), len(created_groups)))
