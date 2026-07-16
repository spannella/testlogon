import os, sys, time, json, traceback
REPO = os.environ.get('APIK_REPO', os.getcwd())
sys.path.insert(0, REPO); os.chdir(REPO)
PHASE = os.environ.get('APIK_PHASE', 'AFTER')
from fastapi.testclient import TestClient
from app.core.tables import T
from app.core.settings import S
from app.services import api_keys as AK
from app.services.sessions import mint_access_token
from app.core.time import now_ts
from app.routers.newsfeed import tbl as NF_TBL, pk_post, sk_post, pk_post_comments, pk_notif

TS = int(time.time())
U  = 'apik-e1-synth-%d' % TS
U2 = 'apik-e1-synth2-%d' % TS
created_users, created_keys, created_posts = [], [], []

def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub+'@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE1'})
    created_users.append(sub)

def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'e1', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']

def _del_by_pk(pk):
    from boto3.dynamodb.conditions import Key as _K
    try:
        r = NF_TBL.query(KeyConditionExpression=_K('pk').eq(pk))
        for it in r.get('Items', []):
            try: NF_TBL.delete_item(Key={'pk': it['pk'], 'sk': it['sk']})
            except Exception as e: print('cleanup row err', pk, e)
    except Exception as e:
        print('cleanup query err', pk, e)

def cleanup():
    for pid in created_posts:
        _del_by_pk(pk_post(pid)); _del_by_pk(pk_post_comments(pid))
    for sub in (U, U2):
        _del_by_pk(pk_notif(sub))
        try: T.profile.delete_item(Key={'user_sub': sub})
        except Exception: pass
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
    print('%-52s got=%-12s expect=%-16s %s %s' % (name, got, '/'.join(map(str, sorted(map(str, expect_set)))), 'OK' if ok else 'XX', note))

def scode(resp):
    code=''; req=[]
    try:
        d = resp.json()
        det = d.get('detail', d) if isinstance(d, dict) else {}
        if isinstance(det, dict):
            code = det.get('code',''); req = det.get('required_scopes') or det.get('missing_scopes') or []
    except Exception: pass
    return resp.status_code, code, req

try:
    seed_user(U); seed_user(U2)
    k_read  = mk_key(U, ['newsfeed:read'])
    k_write = mk_key(U, ['newsfeed:write'])
    k_tips  = mk_key(U, ['newsfeed:tips'])
    k_msgr  = mk_key(U, ['messager:read'])
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}
    print('==== PHASE=%s ts=%d repo=%s ====' % (PHASE, TS, REPO))

    if PHASE == 'BEFORE':
        check('BEFORE read  GET /feed [nf:read] unmapped', c.get('/feed', headers=H(k_read)).status_code, {403}, 'unmapped_route pre-E1')
        st,cc,_ = scode(c.post('/posts', headers=H(k_write), json={'body_plain':'x'}))
        check('BEFORE write POST /posts [nf:write] unmapped', st, {403}, 'code=%s' % cc)
    else:
        check('read  GET /feed [nf:read]', c.get('/feed', headers=H(k_read)).status_code, {200}, 'read scope ok')
        r = c.post('/posts', headers=H(k_write), json={'body_plain':'e1 verify post'})
        pid = ''
        try: pid = r.json().get('post_id','')
        except Exception: pass
        if pid: created_posts.append(pid)
        check('write POST /posts create [nf:write]', r.status_code, {200,201}, 'post_id=%s' % pid)
        check('read  GET /posts/{id} [nf:read]', c.get('/posts/%s'%pid, headers=H(k_read)).status_code, {200}, '')
        check('write PATCH /posts/{id} edit [nf:write]', c.patch('/posts/%s'%pid, headers=H(k_write), json={'body_plain':'edited e1'}).status_code, {200}, '')
        rc = c.post('/posts/%s/comments'%pid, headers=H(k_write), json={'body_plain':'e1 comment'})
        cid=''
        try: cid = rc.json().get('comment_id') or rc.json().get('id','')
        except Exception: pass
        check('write POST /posts/{id}/comments [nf:write]', rc.status_code, {200,201}, 'comment_id=%s'%cid)
        check('write POST /posts/{id}/reactions [nf:write]', c.post('/posts/%s/reactions'%pid, headers=H(k_write), json={'emoji':'\U0001F44D'}).status_code, {200,201}, '')
        rp = c.post('/posts', headers=H(k_write), json={'body_plain':'e1 poll','post_type':'poll','poll_data':{'questions':[{'text':'Q?','choice_mode':'single','options':[{'text':'A'},{'text':'B'}]}]}})
        ppid=''
        try: ppid = rp.json().get('post_id','')
        except Exception: pass
        if ppid: created_posts.append(ppid)
        check('write POST /posts poll-create [nf:write]', rp.status_code, {200,201}, 'poll_post=%s'%ppid)
        st,cc,_ = scode(c.post('/posts', headers=H(k_read), json={'body_plain':'y'}))
        check('NEG  read->POST /posts scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, '')
        st,cc,_ = scode(c.get('/feed', headers=H(k_msgr)))
        check('NEG  msgr->GET /feed scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, '')
        st,cc,req = scode(c.post('/posts/%s/tip'%pid, headers=H(k_write), json={'amount_cents':100}))
        check('MONEY NEG write->tip scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, 'req=%s'%req)
        st,cc,_ = scode(c.post('/posts/unlock', headers=H(k_write), json={'post_id':pid}))
        check('MONEY NEG write->unlock scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, '')
        st,cc,_ = scode(c.post('/posts/%s/reactions/tip'%pid, headers=H(k_write), json={'emoji':'\U0001F44D','amount_cents':100}))
        check('MONEY NEG write->reactions/tip scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, '')
        st,cc,_ = scode(c.post('/posts/%s/comments/%s/tip'%(pid,cid or 'x'), headers=H(k_write), json={'amount_cents':100}))
        check('MONEY NEG write->comment/tip scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, '')
        st,cc,_ = scode(c.post('/posts/%s/tip'%pid, headers=H(k_tips), json={'amount_cents':100}))
        check('MONEY POS tips->tip past-gate', 'scopedenied' if (st==403 and cc=='api_key_scope_denied') else 'passed', {'passed'}, 'st=%s cc=%s'%(st,cc))
        st,cc,_ = scode(c.post('/posts/unlock', headers=H(k_tips), json={'post_id':pid}))
        check('MONEY POS tips->unlock past-gate', 'scopedenied' if (st==403 and cc=='api_key_scope_denied') else 'passed', {'passed'}, 'st=%s cc=%s'%(st,cc))
        st,cc,_ = scode(c.post('/posts', headers=H(k_tips), json={'body_plain':'z'}))
        check('NEG  tips->POST /posts scope_denied', '%s/%s'%(st,cc), {'403/api_key_scope_denied'}, 'tips standalone')
        tok = mint_access_token(U, 'synthsess-%d'%TS)
        ck = {'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok)}
        check('SESSION GET /feed [cookie]', c.get('/feed', headers=ck).status_code, {200}, 'UI session unaffected')
        check('XREG msgr GET /messaging/conversations', c.get('/messaging/conversations', headers=H(k_msgr)).status_code, {200}, 'other keyed ok')
        dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization':'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
        check('DAK bogus delegation 401/403', dsc, {401,403}, 'delegation intact')
        check('write DELETE /posts/{id} [nf:write]', c.delete('/posts/%s'%pid, headers=H(k_write)).status_code, {200}, 'owner delete')

    npass = sum(1 for _,_,ok in results if ok); nfail = len(results)-npass
    print('SUMMARY phase=%s pass=%d fail=%d' % (PHASE, npass, nfail))
except Exception as e:
    print('FATAL', e); traceback.print_exc()
finally:
    cleanup()
    print('CLEANUP done: keys=%d users=%d posts=%d' % (len(created_keys), len(created_users), len(created_posts)))
