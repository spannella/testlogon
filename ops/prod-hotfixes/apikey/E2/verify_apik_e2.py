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
from app.routers.messaging import tbl_convos, tbl_parts, tbl_msgs, tbl_users, tbl_receipts
from boto3.dynamodb.conditions import Key as _K

TS = int(time.time())
U = 'apik-e2-synth-%d' % TS
U2 = 'apik-e2-synth2-%d' % TS
U3 = 'apik-e2-synth3-%d' % TS
created_users, created_keys, created_convos, created_msgs, created_receipts = [], [], [], [], []


def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE2'})
    try:
        tbl_users.put_item(Item={'user_id': sub, 'display_name': 'synthE2', 'email': sub + '@synthetic.local'})
    except Exception as e:
        print('seed msg-user warn', e)
    created_users.append(sub)


def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'e2', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']


def cleanup():
    for cid in set(created_convos):
        try:
            r = tbl_msgs.query(KeyConditionExpression=_K('conversation_id').eq(cid))
            for it in r.get('Items', []):
                try: tbl_msgs.delete_item(Key={'conversation_id': cid, 'message_id': it['message_id']})
                except Exception as e: print('clean msg err', e)
        except Exception as e: print('clean msgq err', e)
        for u in (U, U2, U3):
            try: tbl_parts.delete_item(Key={'user_id': u, 'conversation_id': cid})
            except Exception as e: print('clean part err', e)
        try: tbl_convos.delete_item(Key={'conversation_id': cid})
        except Exception as e: print('clean convo err', e)
    for cid, mu in created_receipts:
        try: tbl_receipts.delete_item(Key={'conversation_id': cid, 'message_user': mu})
        except Exception: pass
    for kid in created_keys:
        try: T.api_keys.delete_item(Key={'key_id': kid})
        except Exception as e: print('clean key err', e)
    for sub in created_users:
        try: T.users.delete_item(Key={'user_sub': sub})
        except Exception: pass
        try: tbl_users.delete_item(Key={'user_id': sub})
        except Exception: pass


results = []
def check(name, got, expect_set, note=''):
    ok = got in expect_set
    results.append((name, got, ok))
    print('%-56s got=%-22s expect=%-22s %s %s' % (name, got, '/'.join(map(str, sorted(map(str, expect_set)))), 'OK' if ok else 'XX', note))


def scode(resp):
    code = ''; req = []
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        if isinstance(det, dict):
            code = det.get('code', ''); req = det.get('required_scopes') or det.get('missing_scopes') or []
    except Exception: pass
    return resp.status_code, code, req


def past_gate(resp):
    # True if the request passed the API-key scope gate (not a scope denial)
    st, cc, _ = scode(resp)
    return not (st == 403 and cc == 'api_key_scope_denied')


try:
    seed_user(U); seed_user(U2); seed_user(U3)
    k_read = mk_key(U, ['messager:read'])
    k_write = mk_key(U, ['messager:write'])
    k_manage = mk_key(U, ['messager:manage'])
    k_wrong = mk_key(U, ['newsfeed:read'])
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}
    print('==== PHASE=%s ts=%d repo=%s ====' % (PHASE, TS, REPO))

    if PHASE == 'BEFORE':
        check('BEFORE baseline GET /messaging/conversations [read]', c.get('/messaging/conversations', headers=H(k_read)).status_code, {200}, 'already-keyed baseline')
        st, cc, _ = scode(c.post('/messaging/conversations', headers=H(k_write), json={'type': 'group', 'participant_ids': [U2]}))
        check('BEFORE POST /conversations [write] unmapped', st, {403}, 'code=%s' % cc)
        st, cc, _ = scode(c.post('/messaging/conversations/dm/find-or-create', headers=H(k_write), json={'user_id': U2}))
        check('BEFORE POST /conversations/dm/find-or-create unmapped', st, {403}, 'code=%s' % cc)
        check('BEFORE GET /events/poll [read] unmapped', c.get('/messaging/events/poll', headers=H(k_read)).status_code, {403}, '')
        st, cc, _ = scode(c.post('/messaging/mass-messages', headers=H(k_manage), json={}))
        check('BEFORE POST /mass-messages [manage] unmapped', st, {403}, 'code=%s' % cc)
    else:
        # ---- E2-1 conversation bootstrap (group needs >=3 unique participants) ----
        r = c.post('/messaging/conversations', headers=H(k_write), json={'type': 'group', 'participant_ids': [U2, U3], 'title': 'e2'})
        cid = ''
        try: cid = r.json().get('conversation_id', '')
        except Exception: pass
        if cid: created_convos.append(cid)
        check('E2-1 write POST /conversations create', r.status_code, {200, 201}, 'cid=%s' % cid)
        check('E2-1 read  GET /conversations', c.get('/messaging/conversations', headers=H(k_read)).status_code, {200}, '')
        rd = c.post('/messaging/conversations/dm/find-or-create', headers=H(k_write), json={'user_id': U2})
        dmid = ''
        try: dmid = rd.json().get('conversation_id', '')
        except Exception: pass
        if dmid: created_convos.append(dmid)
        check('E2-1 write POST /conversations/dm/find-or-create', rd.status_code, {200, 201}, 'dm=%s' % dmid)

        # ---- core send (regression) ----
        rm = c.post('/messaging/conversations/%s/messages' % cid, headers=H(k_write), json={'text': 'hello e2'})
        mid = ''
        try: mid = rm.json().get('message_id', '')
        except Exception: pass
        if mid: created_msgs.append(mid)
        check('CORE write POST /messages text (regression)', rm.status_code, {200, 201}, 'mid=%s' % mid)
        check('CORE read  GET /messages (regression)', c.get('/messaging/conversations/%s/messages' % cid, headers=H(k_read)).status_code, {200}, '')

        # ---- E2-3 reactions / read receipt / realtime ----
        check('E2-3 write POST /messages/{id}/reactions', c.post('/messaging/conversations/%s/messages/%s/reactions' % (cid, mid), headers=H(k_write), json={'emoji': '\U0001F44D', 'action': 'add'}).status_code, {200, 201}, '')
        rv = c.post('/messaging/conversations/%s/messages/%s/view' % (cid, mid), headers=H(k_write), json={})
        if rv.status_code in (200, 201):
            created_receipts.append((cid, '%s#%s' % (mid, U)))
        check('E2-3 write POST /messages/{id}/view (delivery receipt)', rv.status_code, {200, 201}, '')
        check('E2-3 write POST /read (read receipt)', c.post('/messaging/conversations/%s/read' % cid, headers=H(k_write), json={'last_read_at': now_ts()}).status_code, {200, 201, 204}, '')
        check('E2-3 read  GET /events/poll (realtime)', c.get('/messaging/events/poll', headers=H(k_read)).status_code, {200}, '')

        # ---- E2-2 rich sends + image presign contract fix ----
        rp = c.post('/messaging/conversations/%s/images/presign' % cid, headers=H(k_write), json={'content_type': 'image/jpeg', 'filename': 'e2.jpg'})
        pj = {}
        try: pj = rp.json()
        except Exception: pass
        check('E2-2 write POST /images/presign (CONTRACT FIX)', rp.status_code, {200, 201}, 'key=%s' % (pj.get('key', '')[:24]))
        ri = c.post('/messaging/conversations/%s/messages/image' % cid, headers=H(k_write),
                    json={'bucket': pj.get('bucket', ''), 'key': pj.get('key', ''), 'content_type': 'image/jpeg', 'kind': 'image', 'caption': 'e2 img'})
        imid = ''
        try: imid = ri.json().get('message_id', '')
        except Exception: pass
        if imid: created_msgs.append(imid)
        check('E2-2 write POST /messages/image end-to-end(presign->send)', ri.status_code, {200, 201}, 'mid=%s code=%s' % (imid, scode(ri)[1]))
        for path, body, label in [
            ('gif', {'gif_url': 'https://x/g.gif', 'gif_id': 'g1', 'provider': 'giphy', 'width': 1, 'height': 1}, 'gif'),
            ('sticker', {'sticker_id': 's1', 'pack_id': 'p1', 'url': 'https://x/s.png'}, 'sticker'),
            ('countdown', {'title': 'cd', 'target_at': now_ts() + 3600}, 'countdown'),
        ]:
            rr = c.post('/messaging/conversations/%s/messages/%s' % (cid, path), headers=H(k_write), json=body)
            try:
                _m = rr.json().get('message_id', '')
                if _m: created_msgs.append(_m)
            except Exception: pass
            check('E2-2 write POST /messages/%s past-gate' % label, 'passed' if past_gate(rr) else 'scope_denied', {'passed'}, 'st=%s' % rr.status_code)

        # ---- E2-4 scheduled-send manage (create via write, retract via manage) ----
        rs = c.post('/messaging/conversations/%s/messages' % cid, headers=H(k_write), json={'text': 'scheduled e2', 'send_at': now_ts() + 86400})
        sid = ''
        try: sid = rs.json().get('message_id', '')
        except Exception: pass
        if sid: created_msgs.append(sid)
        check('E2-4 write create scheduled send', rs.status_code, {200, 201}, 'sid=%s' % sid)
        st, cc, _ = scode(c.delete('/messaging/conversations/%s/messages/%s/schedule' % (cid, sid), headers=H(k_write)))
        check('E2-4 NEG write->cancel scheduled scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, 'needs manage')
        rc2 = c.delete('/messaging/conversations/%s/messages/%s/schedule' % (cid, sid), headers=H(k_manage))
        check('E2-4 POS manage->cancel scheduled (retract)', rc2.status_code, {200, 204}, '')

        # ---- E2-4 organize reads (pins/search/gallery/threads) ----
        check('E2-4 read  GET /messages/search', c.get('/messaging/conversations/%s/messages/search?q=e2' % cid, headers=H(k_read)).status_code, {200}, '')
        check('E2-4 read  GET /gallery', c.get('/messaging/conversations/%s/gallery?type=image' % cid, headers=H(k_read)).status_code, {200}, '')

        # ---- E2-5 mass-message (manage + entitlement) ----
        check('E2-5 POS manage->POST /mass-messages past-gate', 'passed' if past_gate(c.post('/messaging/mass-messages', headers=H(k_manage), json={})) else 'scope_denied', {'passed'}, '')
        st, cc, _ = scode(c.post('/messaging/mass-messages', headers=H(k_write), json={}))
        check('E2-5 NEG write->POST /mass-messages scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')

        # ---- regression edit/delete (manage) ----
        check('REG manage PATCH /messages/{id} edit', c.patch('/messaging/conversations/%s/messages/%s' % (cid, mid), headers=H(k_manage), json={'text': 'edited e2'}).status_code, {200}, '')
        check('REG manage DELETE /messages/{id}', c.delete('/messaging/conversations/%s/messages/%s' % (cid, mid), headers=H(k_manage)).status_code, {200, 204}, 'owner delete')

        # ---- NEGATIVE scope matrix ----
        st, cc, _ = scode(c.post('/messaging/conversations', headers=H(k_read), json={'type': 'group', 'participant_ids': [U2]}))
        check('NEG read->POST /conversations scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc, _ = scode(c.get('/messaging/conversations', headers=H(k_wrong)))
        check('NEG newsfeed:read->GET /conversations scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        st, cc, _ = scode(c.post('/messaging/conversations/%s/messages/%s/reactions' % (cid, mid), headers=H(k_read), json={'emoji': '\U0001F44D'}))
        check('NEG read->POST reactions scope_denied', '%s/%s' % (st, cc), {'403/api_key_scope_denied'}, '')
        check('NEG no-key GET /conversations 401', c.get('/messaging/conversations').status_code, {401}, 'fail-closed')

        # ---- INTENTIONAL blocks stay closed even with manage ----
        st, cc, _ = scode(c.post('/messaging/conversations/%s/mute' % cid, headers=H(k_manage), json={'muted': True}))
        check('BLOCK manage->POST /mute stays 403', st, {403}, 'code=%s (intentional)' % cc)
        st, cc, _ = scode(c.post('/messaging/conversations/%s/drafts' % cid, headers=H(k_manage), json={'text': 'x'}))
        check('BLOCK manage->POST /drafts stays 403', st, {403}, 'code=%s (intentional)' % cc)
        st, cc, _ = scode(c.get('/messaging/compliance/archive/exports', headers=H(k_manage)))
        check('BLOCK manage->GET /compliance/exports 403', st, {403}, 'code=%s (intentional)' % cc)

        # ---- MONEY routes stay fail-closed (no messager money scope) ----
        st, cc, _ = scode(c.post('/messaging/conversations/%s/messages/%s/tip' % (cid, mid), headers=H(k_manage), json={'amount_cents': 100}))
        check('MONEY manage->POST message tip 403', st, {403}, 'code=%s fail-closed' % cc)
        st, cc, _ = scode(c.post('/messaging/messages/lottery', headers=H(k_manage), json={}))
        check('MONEY manage->POST lottery 403', st, {403}, 'code=%s fail-closed' % cc)

        # ---- no regression: UI session + dak_ delegation ----
        sid = 'synthsess-%d' % TS
        tok = mint_access_token(U, sid)
        # messaging's get_messaging_user_id only enters the session branch on X-SESSION-ID / session cookie
        sess_hdrs = {'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok), 'X-SESSION-ID': sid}
        check('SESSION GET /messaging/conversations [cookie+X-SESSION-ID]', c.get('/messaging/conversations', headers=sess_hdrs).status_code, {200}, 'UI session unaffected')
        dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization': 'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
        check('DAK bogus delegation 401/403', dsc, {401, 403}, 'delegation intact')

    npass = sum(1 for _, _, ok in results if ok); nfail = len(results) - npass
    print('SUMMARY phase=%s pass=%d fail=%d' % (PHASE, npass, nfail))
except Exception as e:
    print('FATAL', e); traceback.print_exc()
finally:
    cleanup()
    print('CLEANUP done: keys=%d users=%d convos=%d msgs=%d receipts=%d' % (
        len(created_keys), len(created_users), len(set(created_convos)), len(created_msgs), len(created_receipts)))
