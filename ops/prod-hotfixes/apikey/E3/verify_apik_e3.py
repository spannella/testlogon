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
from app.core.aws_clients import s3_client

TS = int(time.time())
U = 'apik-e3-synth-%d' % TS
U2 = 'apik-e3-synth2-%d' % TS
ROOT = '/e3verify-%d/' % TS
created_users, created_keys = [], []


def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE3'})
    created_users.append(sub)


def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'e3', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']


def cleanup():
    try:
        from app.services.filemanager import remove_folder as _rf
        for owner in (U, U2):
            try: _rf(owner, ROOT)
            except Exception: pass
    except Exception as e:
        print('fs cleanup warn', e)
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
    print('%-58s got=%-24s expect=%-22s %s %s' % (name, got, '/'.join(map(str, sorted(map(str, expect_set)))), 'OK' if ok else 'XX', note))


def scode(resp):
    code = ''
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        if isinstance(det, dict):
            code = det.get('code', '')
    except Exception: pass
    return resp.status_code, code


def past_gate(resp):
    st, cc = scode(resp)
    return not (st == 403 and cc == 'api_key_scope_denied')


try:
    seed_user(U); seed_user(U2)
    k_read = mk_key(U, ['filemanager:read'])
    k_write = mk_key(U, ['filemanager:write'])
    k_share = mk_key(U, ['filemanager:share'])
    k_admin = mk_key(U, ['filemanager:admin'])
    k_wrong = mk_key(U, ['newsfeed:read'])
    k_u2 = mk_key(U2, ['filemanager:admin'])
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}
    P = lambda leaf: ROOT + leaf
    print('==== PHASE=%s ts=%d repo=%s dev_mode=%s ====' % (PHASE, TS, REPO, getattr(S, 'dev_mode', None)))

    if PHASE == 'BEFORE':
        check('BEFORE baseline GET /v1/fs/list [read]', c.get('/v1/fs/list?path=/', headers=H(k_read)).status_code, {200}, 'already-keyed')
        st, cc = scode(c.post('/v1/fs/presign-upload', headers=H(k_write), json={'path': P('a.txt'), 'content_type': 'text/plain'}))
        check('BEFORE POST /presign-upload unmapped', st, {403}, 'code=%s' % cc)
        st, cc = scode(c.post('/v1/fs/copy', headers=H(k_write), json={'src': P('a.txt'), 'dst': P('b.txt')}))
        check('BEFORE POST /copy unmapped(drift)', st, {403}, 'code=%s' % cc)
        check('BEFORE GET /info [read] unmapped', c.get('/v1/fs/info?path=%s' % P('a.txt'), headers=H(k_read)).status_code, {403}, '')
        st, cc = scode(c.post('/v1/fs/unshare', headers=H(k_share), json={'path': P('a.txt'), 'to_user': U2}))
        check('BEFORE POST /unshare [share] unmapped', st, {403}, 'code=%s' % cc)
    else:
        # ===== E3-1 FLAGSHIP: presign -> PUT -> complete -> appears in list =====
        rp = c.post('/v1/fs/presign-upload', headers=H(k_write), json={'path': P('up.txt'), 'content_type': 'text/plain'})
        pj = rp.json() if rp.status_code == 200 else {}
        check('E3-1 write POST /presign-upload', rp.status_code, {200}, 'key=%s' % (str(pj.get('key', ''))[:28]))
        put_ok = 'n/a'
        if pj:
            try:
                s3_client().put_object(Bucket=pj['bucket'], Key=pj['key'], Body=b'hello-e3-flagship',
                                       ContentType='text/plain', Metadata={'filemgr-ticket': pj['ticket_id'], 'filemgr-user': U})
                put_ok = 'PUT_OK'
            except Exception as e:
                put_ok = 'PUT_ERR:%s' % (str(e)[:60])
        check('E3-1 PUT bytes -> s3 (presigned key)', put_ok, {'PUT_OK'}, '')
        rc = c.post('/v1/fs/complete-upload', headers=H(k_write),
                    json={'path': P('up.txt'), 'key': pj.get('key', ''), 'ticket_id': pj.get('ticket_id', ''), 'content_type': 'text/plain'})
        check('E3-1 write POST /complete-upload', rc.status_code, {200}, scode(rc)[1])
        rl = c.get('/v1/fs/list?path=%s' % ROOT, headers=H(k_read))
        names = [i.get('name') for i in rl.json().get('items', [])] if rl.status_code == 200 else []
        check('E3-1 read GET /list shows uploaded file', 'up.txt' in names, {True}, 'names=%s' % names)
        check('REG read GET /download up.txt (already-keyed)', c.get('/v1/fs/download?path=%s' % P('up.txt'), headers=H(k_read)).status_code, {200}, 'no regression (pre-rename fresh obj)')

        # ===== E3-2 core mutations (write) =====
        check('E3-2 write POST /folder', c.post('/v1/fs/folder', headers=H(k_write), json={'path': P('sub/')}).status_code, {200}, '')
        check('E3-2 write POST /rename-file', c.post('/v1/fs/rename-file', headers=H(k_write), json={'path': P('up.txt'), 'new_name': 'up2.txt'}).status_code, {200}, 'up.txt->up2.txt')
        rcopy = c.post('/v1/fs/copy', headers=H(k_write), json={'src': P('up2.txt'), 'dst': P('up2_copy.txt')})
        check('E3-2 write POST /copy (drift cleared)', rcopy.status_code, {200}, scode(rcopy)[1])
        check('E3-2 write POST /move', c.post('/v1/fs/move', headers=H(k_write), json={'src': P('up2_copy.txt'), 'dst': P('sub/up2_copy.txt')}).status_code, {200}, '')
        check('E3-2 write DELETE /file', c.delete('/v1/fs/file?path=%s' % P('sub/up2_copy.txt'), headers=H(k_write)).status_code, {200}, '')
        c.post('/v1/fs/folder', headers=H(k_write), json={'path': P('gen/')})
        check('E3-2 write DELETE "" generic (folder)', c.delete('/v1/fs?path=%s' % P('gen/'), headers=H(k_write)).status_code, {200}, '')
        check('E3-2 write DELETE /folder', c.delete('/v1/fs/folder?path=%s' % P('sub/'), headers=H(k_write)).status_code, {200}, '')

        # ===== E3-4 read-side (read) =====
        check('E3-4 read GET /info', c.get('/v1/fs/info?path=%s' % P('up2.txt'), headers=H(k_read)).status_code, {200}, '')
        check('E3-4 read GET /search', c.get('/v1/fs/search?prefix=up2', headers=H(k_read)).status_code, {200}, '')
        check('E3-4 read GET /crm-search past-gate', 'passed' if past_gate(c.get('/v1/fs/crm-search?linked_record_type=deal&linked_record_id=x1', headers=H(k_read))) else 'scope_denied', {'passed'}, 'feature-gated ok')
        check('E3-4 read GET /preview past-gate', 'passed' if past_gate(c.get('/v1/fs/preview?path=%s' % P('up2.txt'), headers=H(k_read))) else 'scope_denied', {'passed'}, '')

        # ===== E3-3 sharing symmetry (share/read) =====
        check('E3-3 share POST /share -> U2', c.post('/v1/fs/share', headers=H(k_share), json={'path': P('up2.txt'), 'to_user': U2, 'permission': 'read'}).status_code, {200}, '')
        rsw = c.get('/v1/fs/shared-with?path=%s' % P('up2.txt'), headers=H(k_read))
        sw = rsw.json().get('shared_with', []) if rsw.status_code == 200 else []
        check('E3-3 read GET /shared-with lists U2', (U2 in [(x.get('to_user') if isinstance(x, dict) else x) for x in sw]) or (U2 in str(sw)), {True}, 'sw=%s' % str(sw)[:80])
        rswm = c.get('/v1/fs/shared-with-me', headers=H(k_u2))
        items = rswm.json().get('items', []) if rswm.status_code == 200 else []
        check('E3-3 read(U2) GET /shared-with-me consume', rswm.status_code == 200 and len(items) >= 1, {True}, 'n=%d' % len(items))
        check('E3-3 share POST /unshare revoke', c.post('/v1/fs/unshare', headers=H(k_share), json={'path': P('up2.txt'), 'to_user': U2}).status_code, {200}, '')
        rsw2 = c.get('/v1/fs/shared-with?path=%s' % P('up2.txt'), headers=H(k_read))
        sw2 = rsw2.json().get('shared_with', []) if rsw2.status_code == 200 else []
        check('E3-3 read GET /shared-with empty after revoke', U2 not in str(sw2), {True}, 'sw=%s' % str(sw2)[:60])

        # ===== cross-user isolation =====
        check('ISO U2-admin GET /info on U file -> denied/not-found', c.get('/v1/fs/info?path=%s' % P('up2.txt'), headers=H(k_u2)).status_code, {403, 404}, 'namespace isolation')
        rl2 = c.get('/v1/fs/list?path=%s' % ROOT, headers=H(k_u2))
        n2 = len(rl2.json().get('items', [])) if rl2.status_code == 200 else -1
        check('ISO U2-admin GET /list own-namespace empty', n2, {0}, 'sees only own tree')

        # ===== NEGATIVE scope matrix (per-scope; only admin cross-inherits) =====
        st, cc = scode(c.post('/v1/fs/folder', headers=H(k_read), json={'path': P('x/')}))
        check('NEG read->POST /folder scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc = scode(c.post('/v1/fs/presign-upload', headers=H(k_read), json={'path': P('x.txt')}))
        check('NEG read->POST /presign-upload scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc = scode(c.get('/v1/fs/list?path=/', headers=H(k_write)))
        check('NEG write->GET /list scope_denied (no write>=read)', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc = scode(c.post('/v1/fs/share', headers=H(k_write), json={'path': P('up2.txt'), 'to_user': U2}))
        check('NEG write->POST /share scope_denied (no write>=share)', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc = scode(c.post('/v1/fs/folder', headers=H(k_share), json={'path': P('y/')}))
        check('NEG share->POST /folder scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc = scode(c.patch('/v1/fs/crm-metadata?path=%s' % P('up2.txt'), headers=H(k_read), json={'crm_category': 'x'}))
        check('NEG read->PATCH /crm-metadata scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc = scode(c.get('/v1/fs/list?path=/', headers=H(k_wrong)))
        check('NEG newsfeed:read->GET /list scope_denied (wrong product)', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        check('NEG no-key GET /list 401', c.get('/v1/fs/list?path=/').status_code, {401}, 'fail-closed')

        # ===== INTENTIONAL blocks stay fail-closed even with admin key =====
        st, cc = scode(c.post('/v1/fs/mounts/sftp', headers=H(k_admin), json={}))
        check('BLOCK admin->POST /mounts/sftp 403', st, {403}, 'mount-credential (code=%s)' % cc)
        st, cc = scode(c.get('/v1/fs/admin/read?path=%s' % P('up2.txt'), headers=H(k_admin)))
        check('BLOCK admin->GET /admin/read 403', st, {403}, 'admin/* (code=%s)' % cc)
        st, cc = scode(c.post('/v1/fs/mounts/m123/rotate-credential', headers=H(k_admin), json={}))
        check('BLOCK admin->POST /mounts/{id}/rotate-credential 403', st, {403}, 'mount-credential')
        st, cc = scode(c.post('/v1/fs/purge-deleted', headers=H(k_admin), json={}))
        check('BLOCK admin->POST /purge-deleted 403', st, {403}, 'intentional fail-closed')
        st, cc = scode(c.get('/v1/fs/usage/summary', headers=H(k_admin)))
        check('BLOCK admin->GET /usage/summary 403', st, {403}, 'intentional')

        # ===== no regression: UI session + dak_ delegation =====
        sid = 'synthsess-%d' % TS
        tok = mint_access_token(U, sid)
        sess_hdrs = {'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok), 'X-SESSION-ID': sid}
        check('SESSION GET /v1/fs/list [cookie+X-SESSION-ID]', c.get('/v1/fs/list?path=/', headers=sess_hdrs).status_code, {200}, 'UI session unaffected')
        dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization': 'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
        check('DAK bogus delegation 401/403', dsc, {401, 403}, 'delegation intact')

    npass = sum(1 for _, _, ok in results if ok); nfail = len(results) - npass
    print('SUMMARY phase=%s pass=%d fail=%d' % (PHASE, npass, nfail))
except Exception as e:
    print('FATAL', e); traceback.print_exc()
finally:
    cleanup()
    print('CLEANUP done: keys=%d users=%d tree=%s' % (len(created_keys), len(created_users), ROOT))
