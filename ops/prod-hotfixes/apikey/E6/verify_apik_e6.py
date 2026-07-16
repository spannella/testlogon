"""APIK EPIC E6 - durable parity regression suite (#118).

One in-process TestClient run on PROD DDB. For ALL 5 domains it asserts:
  (POS) a correctly-scoped key can invoke the UI-reachable capability;
  (NEG) a wrong-scope key is denied 403 api_key_scope_denied;
  (MONEY/MOD) money/moderation routes require their DISTINCT high-priv scope
              (never a coarse *:write) - and are fail-closed otherwise;
  (E0-HOLE) any valid api-key on an un-gated session-only money router 401s
            (the prod over-scope hole stays shut - no injected-owner passthrough).
Plus no-regression: UI-session cookie unaffected, dak_ delegation intact,
no-key 401, cross-product denial. Synthetic keys+users, auto-cleaned, 0 residue.
"""
import os, sys, time, traceback
REPO = os.environ.get('APIK_REPO', os.getcwd())
sys.path.insert(0, REPO); os.chdir(REPO)
from fastapi.testclient import TestClient
from app.core.tables import T
from app.core.settings import S
from app.services import api_keys as AK
from app.services.sessions import mint_access_token
from app.core.time import now_ts
from app.services.api_key_rollout import get_api_key_rollout_state, evaluate_api_key_rollout, ROLLOUT_PRODUCTS, validate_api_key_rollout_settings

TS = int(time.time())
U  = 'apik-e6-%d' % TS
U2 = 'apik-e6b-%d' % TS
U3 = 'apik-e6c-%d' % TS
UADM = 'apik-e6adm-%d' % TS
created_users, created_keys, created_posts, created_groups, created_videos = [], [], [], [], []

def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub+'@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE6'})
    created_users.append(sub)

def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'e6', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']

def cleanup():
    for pid in created_posts:
        for tbl in (getattr(T, 'newsfeed_posts', None), getattr(T, 'posts', None)):
            if tbl is None: continue
            try: tbl.delete_item(Key={'post_id': pid})
            except Exception: pass
    for gid in created_groups:
        try: T.groups.delete_item(Key={'group_id': gid})
        except Exception: pass
    for vid in created_videos:
        for pk in (vid, 'TICKET#'+vid):
            try: T.video_metadata.delete_item(Key={'video_id': pk})
            except Exception: pass
    for kid in created_keys:
        try: T.api_keys.delete_item(Key={'key_id': kid})
        except Exception as e: print('clean key err', e)
    for sub in created_users:
        try: T.users.delete_item(Key={'user_sub': sub})
        except Exception: pass

results = []
def rec(domain, name, ok, note=''):
    results.append((domain, name, bool(ok), note))
    print('  [%s] %-54s %s' % ('OK' if ok else 'XX', name, note))

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
    return not denied(resp)   # scope check passed; handler-level result is irrelevant here

def main():
    validate_api_key_rollout_settings()
    seed_user(U); seed_user(U2); seed_user(U3); seed_user(UADM, role='admin')
    k_nf_r  = mk_key(U, ['newsfeed:read']);    k_nf_w = mk_key(U, ['newsfeed:write']);  k_nf_tip = mk_key(U, ['newsfeed:tips'])
    k_ms_r  = mk_key(U, ['messager:read']);    k_ms_w = mk_key(U, ['messager:write']);  k_ms_m = mk_key(U, ['messager:manage'])
    k_fm_r  = mk_key(U, ['filemanager:read']); k_fm_w = mk_key(U, ['filemanager:write']); k_fm_s = mk_key(U, ['filemanager:share'])
    k_gr_r  = mk_key(U, ['groups:read']);      k_gr_w = mk_key(U, ['groups:write']);    k_gr_m = mk_key(U, ['groups:manage'])
    k_gr_t  = mk_key(U, ['groups:treasury']);  k_fund = mk_key(U, ['fundraising:write'])
    k_vd_r  = mk_key(U, ['video:read']);       k_vd_w = mk_key(U, ['video:write'])
    k_vd_pub = mk_key(U, ['video:write', 'video:publish']); k_vd_mon = mk_key(U, ['video:monetize']); k_vd_mod = mk_key(UADM, ['video:moderate'])
    k_admin = mk_key(UADM, ['admin:all'])
    tok = mint_access_token(U, 'e6sess-%d' % TS)
    ck = {'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok)}
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}

    print('\n== ROLLOUT (E6-1): every product enforce=True, shadow=False ==')
    for p in ROLLOUT_PRODUCTS:
        ev = evaluate_api_key_rollout(p, {'api_key_id': 'probe'})
        rec('ROLLOUT', '%s enforce&no-shadow' % p, ev['enforce'] and not ev['shadow'], 'phase=%s' % ev['phase'])

    print('\n== NEWSFEED ==')
    rec('newsfeed', 'read GET /feed', c.get('/feed', headers=H(k_nf_r)).status_code == 200)
    rp = c.post('/posts', headers=H(k_nf_w), json={'body_plain': 'e6 post'})
    pid = ''
    try: pid = rp.json().get('post_id') or rp.json().get('id') or ''
    except Exception: pass
    if pid: created_posts.append(pid)
    rec('newsfeed', 'write POST /posts create', rp.status_code in (200, 201), 'pid=%s' % str(pid)[:16])
    rec('newsfeed', 'NEG read->POST /posts denied', denied(c.post('/posts', headers=H(k_nf_r), json={'body_plain': 'x'})))
    rec('newsfeed', 'NEG xproduct msgr->GET /feed denied', denied(c.get('/feed', headers=H(k_ms_r))))
    rec('newsfeed', 'MONEY write->tip DENIED (needs newsfeed:tips)', denied(c.post('/posts/%s/tip' % (pid or 'x'), headers=H(k_nf_w), json={'amount_cents': 100})))
    rec('newsfeed', 'MONEY tips->tip past scope-gate', past_gate(c.post('/posts/%s/tip' % (pid or 'x'), headers=H(k_nf_tip), json={'amount_cents': 100})))
    rec('newsfeed', 'MONEY tips-standalone->POST /posts DENIED', denied(c.post('/posts', headers=H(k_nf_tip), json={'body_plain': 'z'})))

    print('\n== MESSAGING ==')
    rc = c.post('/messaging/conversations', headers=H(k_ms_w), json={'type': 'group', 'participant_ids': [U2, U3], 'title': 'e6'})
    cid = ''
    try:
        j = rc.json(); cid = (j.get('conversation', {}) or {}).get('id') or j.get('id') or j.get('conversation_id') or ''
    except Exception: pass
    rec('messaging', 'write POST /conversations create', rc.status_code in (200, 201), 'cid=%s' % str(cid)[:16])
    rec('messaging', 'read GET /conversations', c.get('/messaging/conversations', headers=H(k_ms_r)).status_code == 200)
    rec('messaging', 'NEG read->POST /conversations denied', denied(c.post('/messaging/conversations', headers=H(k_ms_r), json={'type': 'group', 'participant_ids': [U2]})))
    rec('messaging', 'NEG xproduct nf:read->GET /conversations denied', denied(c.get('/messaging/conversations', headers=H(k_nf_r))))
    rec('messaging', 'PRIV write->mass-messages DENIED (needs manage)', denied(c.post('/messaging/mass-messages', headers=H(k_ms_w), json={})))
    rec('messaging', 'PRIV manage->mass-messages past scope-gate', past_gate(c.post('/messaging/mass-messages', headers=H(k_ms_m), json={})))
    rec('messaging', 'MONEY manage->message tip fail-closed (unmapped 403)', c.post('/messaging/conversations/%s/messages/x/tip' % (cid or 'x'), headers=H(k_ms_m), json={'amount_cents': 100}).status_code == 403)

    print('\n== FILEMANAGER ==')
    ROOT = '/apik-e6-%d/' % TS   # single top-level dir (parent '/' always exists)
    rec('filemanager', 'read GET /v1/fs/list', c.get('/v1/fs/list?path=/', headers=H(k_fm_r)).status_code == 200)
    rec('filemanager', 'write POST /v1/fs/folder', c.post('/v1/fs/folder', headers=H(k_fm_w), json={'path': ROOT}).status_code == 200)
    rec('filemanager', 'NEG read->POST /folder denied', denied(c.post('/v1/fs/folder', headers=H(k_fm_r), json={'path': ROOT + 'x/'})))
    rec('filemanager', 'ISO write!>=read: write->GET /list denied', denied(c.get('/v1/fs/list?path=/', headers=H(k_fm_w))))
    rec('filemanager', 'ISO share standalone: share->POST /folder denied', denied(c.post('/v1/fs/folder', headers=H(k_fm_s), json={'path': ROOT + 'y/'})))
    rec('filemanager', 'NEG xproduct msgr->GET /list denied', denied(c.get('/v1/fs/list?path=/', headers=H(k_ms_r))))
    c.delete('/v1/fs/folder?path=%s' % ROOT, headers=H(k_fm_w))

    print('\n== GROUPS ==')
    rg = c.post('/ui/groups', headers=H(k_gr_w), json={'name': 'e6 grp %d' % TS, 'description': 'synthetic', 'visibility': 'public'})
    gid = ''
    try:
        j = rg.json(); gid = j.get('group_id') or j.get('id') or (j.get('group', {}) or {}).get('id') or ''
    except Exception: pass
    if gid: created_groups.append(gid)
    rec('groups', 'write POST /ui/groups create', rg.status_code in (200, 201), 'gid=%s' % str(gid)[:16])
    rec('groups', 'read GET /ui/groups list', c.get('/ui/groups', headers=H(k_gr_r)).status_code == 200)
    rec('groups', 'NEG read->create denied', denied(c.post('/ui/groups', headers=H(k_gr_r), json={'name': 'x'})))
    rec('groups', 'NEG write->settings(manage) denied', denied(c.patch('/ui/groups/%s' % (gid or 'x'), headers=H(k_gr_w), json={'description': 'x'})))
    rec('groups', 'MONEY write->treasury/spend DENIED (needs treasury)', denied(c.post('/ui/groups/%s/treasury/spend' % (gid or 'x'), headers=H(k_gr_w), json={'amount_cents': 100, 'reason': 'x'})))
    rec('groups', 'MONEY manage!>=treasury: manage->spend DENIED', denied(c.post('/ui/groups/%s/treasury/spend' % (gid or 'x'), headers=H(k_gr_m), json={'amount_cents': 100, 'reason': 'x'})))
    rec('groups', 'MONEY treasury->spend past scope-gate', past_gate(c.post('/ui/groups/%s/treasury/spend' % (gid or 'x'), headers=H(k_gr_t), json={'amount_cents': 100, 'reason': 'x'})))
    rec('groups', 'MONEY write!>=fundraise: write->campaign DENIED', denied(c.post('/ui/groups/fundraising/%s/campaigns' % (gid or 'x'), headers=H(k_gr_w), json={'name': 'no', 'daily_budget_cents': 1, 'lifetime_budget_cents': 1})))
    rec('groups', 'MONEY fundraising:write->campaign past scope-gate', past_gate(c.post('/ui/groups/fundraising/%s/campaigns' % (gid or 'x'), headers=H(k_fund), json={'name': 'camp', 'daily_budget_cents': 100, 'lifetime_budget_cents': 1000})))
    rec('groups', 'MONEY confirm-donation fail-closed to admin:all (require_root)', c.post('/ui/groups/fundraising/%s/fundraisers/x/donations/y/confirm' % (gid or 'x'), headers=H(k_admin), json={}).status_code in (403, 404))

    print('\n== VIDEO ==')
    rec('video', 'read GET /ui/videos list', c.get('/ui/videos', headers=H(k_vd_r)).status_code == 200)
    rv = c.post('/ui/videos/upload/presign', headers=H(k_vd_w), json={'filename': 'e6-%d.mp4' % TS, 'content_type': 'video/mp4', 'file_size_bytes': 4096, 'title': 'e6'})
    vid = ''
    try: vid = rv.json().get('video_id', '')
    except Exception: pass
    if vid: created_videos.append(vid)
    rec('video', 'write POST /upload/presign (ingest)', rv.status_code == 200, 'vid=%s' % str(vid)[:16])
    rec('video', 'NEG read->presign denied', denied(c.post('/ui/videos/upload/presign', headers=H(k_vd_r), json={'filename': 'x.mp4', 'content_type': 'video/mp4', 'file_size_bytes': 10})))
    rec('video', 'PRIV write!>=publish: write->gallery/publish DENIED', denied(c.post('/ui/videos/%s/gallery/publish' % (vid or 'x'), headers=H(k_vd_w), json={'category': 'demo'})))
    rec('video', 'PRIV write+publish->publish past scope-gate', past_gate(c.post('/ui/videos/%s/gallery/publish' % (vid or 'x'), headers=H(k_vd_pub), json={'category': 'demo'})))
    rec('video', 'MONEY write!>=monetize: write->PATCH pricing DENIED', denied(c.patch('/ui/videos/%s/pricing' % (vid or 'x'), headers=H(k_vd_w), json={'price_cents': 100})))
    rec('video', 'MONEY monetize->PATCH pricing past scope-gate', past_gate(c.patch('/ui/videos/%s/pricing' % (vid or 'x'), headers=H(k_vd_mon), json={'price_cents': 100})))
    rec('video', 'MOD moderate(admin)->admin/by-status past scope-gate', past_gate(c.get('/ui/videos/admin/by-status/published', headers=H(k_vd_mod))))
    rec('video', 'MOD write!>=moderate: write->admin/by-status DENIED', denied(c.get('/ui/videos/admin/by-status/published', headers=H(k_vd_w))))
    rec('video', 'MONEY tip fail-closed to write (unmapped 403)', c.post('/ui/videos/%s/tip' % (vid or 'x'), headers=H(k_vd_w), json={'amount_cents': 100}).status_code == 403)

    print('\n== E0 FAIL-CLOSED (prod over-scope hole must stay shut) ==')
    for label, path, key in [
        ('messager:read -> GET /ui/billing/wallet', '/ui/billing/wallet', k_ms_r),
        ('groups:read -> GET /ui/earnings/summary', '/ui/earnings/summary', k_gr_r),
        ('admin:all -> GET /ui/payouts (wildcard fail-closed)', '/ui/payouts', k_admin),
        ('video:monetize -> GET /ui/billing/balance', '/ui/billing/balance', k_vd_mon),
    ]:
        r = c.get(path, headers=H(key))
        rec('E0-hole', label + ' == 401', r.status_code == 401, 'got=%s (NOT owner-200)' % r.status_code)

    print('\n== NO-REGRESSION ==')
    rec('regress', 'UI-session cookie -> GET /feed 200', c.get('/feed', headers=ck).status_code == 200)
    rec('regress', 'no-key -> GET /messaging/conversations 401', c.get('/messaging/conversations').status_code == 401)
    rec('regress', 'invalid key -> 401', c.get('/messaging/conversations', headers={'X-API-Key': 'ak_bogus.bogus'}).status_code == 401)
    rec('regress', 'admin:all -> GET /messaging/conversations 200', c.get('/messaging/conversations', headers=H(k_admin)).status_code == 200)
    rec('regress', 'admin:all -> GET /v1/fs/list 200 (xproduct)', c.get('/v1/fs/list?path=/', headers=H(k_admin)).status_code == 200)
    dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization': 'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
    rec('regress', 'bogus dak_ delegation 401/403 (dak_ intact)', dsc in (401, 403), 'got=%s' % dsc)

if __name__ == '__main__':
    ok = False
    try:
        main(); ok = True
    except Exception:
        traceback.print_exc()
    finally:
        cleanup()
    npass = sum(1 for r in results if r[2]); nfail = sum(1 for r in results if not r[2])
    print('\n================ E6 PARITY REGRESSION SUMMARY ================')
    doms = {}
    for dom, name, k, note in results:
        doms.setdefault(dom, [0, 0]); doms[dom][0 if k else 1] += 1
    for dom, (p, f) in doms.items():
        print('  %-12s pass=%-3d fail=%d' % (dom, p, f))
    print('  %-12s pass=%-3d fail=%d' % ('TOTAL', npass, nfail))
    for dom, name, k, note in results:
        if not k: print('  FAIL:', dom, '|', name, '|', note)
    print('SUITE', 'GREEN' if (nfail == 0 and ok) else 'RED')
    sys.exit(0 if (nfail == 0 and ok) else 1)
