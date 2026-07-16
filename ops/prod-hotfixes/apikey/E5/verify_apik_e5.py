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
U = 'apik-e5-synth-%d' % TS       # video owner (role user)
U2 = 'apik-e5-synth2-%d' % TS     # secondary
UADM = 'apik-e5-admin-%d' % TS    # admin owner (moderation + wildcard)
created_users, created_keys, created_videos = [], [], []


def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthE5'})
    created_users.append(sub)


def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'e5', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']


def cleanup():
    for vid in created_videos:
        for pk in (vid, 'TICKET#' + vid):
            try: T.video_metadata.delete_item(Key={'video_id': pk})
            except Exception: pass
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
    print('%-64s got=%-20s expect=%-18s %s %s' % (name, got, '/'.join(map(str, sorted(map(str, expect_set)))), 'OK' if ok else 'XX', note))


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


def reason(resp):
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        return det.get('reason', '') if isinstance(det, dict) else ''
    except Exception:
        return ''


def pg(resp):
    return 'passed' if not is_scope_denied(resp) else 'scope_denied'


try:
    seed_user(U); seed_user(U2); seed_user(UADM, role='admin')
    k_read = mk_key(U, ['video:read'])
    k_write = mk_key(U, ['video:write'])
    k_pub = mk_key(U, ['video:write', 'video:publish'])   # task "video:write/publish key"
    k_pubonly = mk_key(U, ['video:publish'])
    k_manage = mk_key(U, ['video:manage'])                # inherits write+publish+read
    k_monetize = mk_key(U, ['video:monetize'])            # standalone money scope
    k_mod_adm = mk_key(UADM, ['video:moderate'])
    k_mod_usr = mk_key(U, ['video:moderate'])
    k_wrong = mk_key(U, ['messager:read'])
    k_fm = mk_key(U, ['filemanager:read'])
    k_groups = mk_key(U, ['groups:read'])
    k_admin = mk_key(UADM, ['admin:all'])
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)
    H = lambda k: {'X-API-Key': k}
    print('==== PHASE=%s ts=%d dev_mode=%s video_phase=%s ====' % (PHASE, TS, getattr(S, 'dev_mode', None), S.api_key_video_phase))

    if PHASE == 'BEFORE':
        # Pre-E5: video routers un-gated -> injected principal lacks route-authorized marker
        # (E0-4) -> require_ui_session falls through -> 401 fail-closed to every key.
        check('BEFORE video:read -> GET /ui/videos (un-gated)', c.get('/ui/videos', headers=H(k_read)).status_code, {401}, 'fail-closed (E0)')
        check('BEFORE video:write -> POST upload/presign (un-gated)', c.post('/ui/videos/upload/presign', headers=H(k_write), json={'filename': 'x.mp4', 'content_type': 'video/mp4', 'file_size_bytes': 1024}).status_code, {401}, 'ingest closed')
        check('BEFORE video:monetize -> PATCH pricing (un-gated)', c.patch('/ui/videos/v_x/pricing', headers=H(k_monetize), json={'price_cents': 100}).status_code, {401}, 'money fail-closed')
        check('BEFORE no-regression messager:read -> /messaging/conversations', c.get('/messaging/conversations', headers=H(k_wrong)).status_code, {200}, 'already-keyed')
    else:
        # ============== E5-2 INGEST -> ... -> PUBLISH (video:write/publish) ==============
        rp = c.post('/ui/videos/upload/presign', headers=H(k_write), json={'filename': 'e5-%d.mp4' % TS, 'content_type': 'video/mp4', 'file_size_bytes': 4096, 'title': 'E5 synth'})
        vid = rp.json().get('video_id', '') if rp.status_code == 200 else ''
        s3key = rp.json().get('s3_key', '') if rp.status_code == 200 else ''
        tkt = rp.json().get('ticket_id', '') if rp.status_code == 200 else ''
        if vid: created_videos.append(vid)
        check('E5-2 write POST upload/presign (ingest)', rp.status_code, {200}, 'vid=%s' % vid[:16])
        check('E5-2 write POST upload/complete', pg(c.post('/ui/videos/upload/complete', headers=H(k_write), json={'ticket_id': tkt, 'key': s3key})), {'passed'}, 'past-gate (S3 head)')
        check('E5-2 write POST {vid}/transcode (seam)', pg(c.post('/ui/videos/%s/transcode' % vid, headers=H(k_write), json={'video_id': vid, 'rendition_profiles': []})), {'passed'}, 'transcode submit')
        check('E5-2 read  GET {vid}/transcode/status', pg(c.get('/ui/videos/%s/transcode/status' % vid, headers=H(k_read))), {'passed'}, '')
        check('E5-2 write PATCH {vid} (metadata/visibility)', c.patch('/ui/videos/%s' % vid, headers=H(k_write), json={'description': 'edited', 'visibility': 'unlisted'}).status_code, {200}, 'owner edit')
        check('E5-2 pub   POST {vid}/gallery/publish (video:publish)', pg(c.post('/ui/videos/%s/gallery/publish' % vid, headers=H(k_pub), json={'category': 'demo', 'tags': ['x']})), {'passed'}, 'write+publish key')
        check('E5-2 read  GET /ui/videos/{vid} (detail)', c.get('/ui/videos/%s' % vid, headers=H(k_read)).status_code, {200}, '')
        check('E5-2 read  GET /ui/videos (list)', c.get('/ui/videos', headers=H(k_read)).status_code, {200}, '')
        check('E5-2 write POST {vid}/clip', pg(c.post('/ui/videos/%s/clip' % vid, headers=H(k_write), json={'start_seconds': 0, 'end_seconds': 5})), {'passed'}, '')
        check('E5-2 write POST /ui/videos/combine', pg(c.post('/ui/videos/combine', headers=H(k_write), json={'source_video_ids': [vid, vid], 'title': 'combo'})), {'passed'}, '')
        check('E5-2 write POST {vid}/subtitles', pg(c.post('/ui/videos/%s/subtitles' % vid, headers=H(k_write), data={'language': 'en'})), {'passed'}, 'multipart past-gate')
        check('E5-2 read  GET {vid}/subtitles', pg(c.get('/ui/videos/%s/subtitles' % vid, headers=H(k_read))), {'passed'}, '')
        check('E5-2 write POST /ui/transcode-jobs', pg(c.post('/ui/transcode-jobs', headers=H(k_write), json={'video_id': vid, 'rendition_profiles': []})), {'passed'}, '')
        check('E5-2 read  GET /ui/transcode-jobs', pg(c.get('/ui/transcode-jobs', headers=H(k_read))), {'passed'}, '')
        check('E5-2 write POST /ui/vod-bridge/import', pg(c.post('/ui/vod-bridge/import', headers=H(k_write), json={'file_path': '/x.mp4'})), {'passed'}, '')
        check('E5-2 read  GET /ui/vod-bridge/status/{vid}', pg(c.get('/ui/vod-bridge/status/%s' % vid, headers=H(k_read))), {'passed'}, '')
        check('E5-2 manage PATCH {vid} (manage>=write)', pg(c.patch('/ui/videos/%s' % vid, headers=H(k_manage), json={'description': 'm'})), {'passed'}, '')
        check('E5-2 manage POST {vid}/gallery/unpublish (manage>=publish)', pg(c.post('/ui/videos/%s/gallery/unpublish' % vid, headers=H(k_manage))), {'passed'}, '')
        check('E5-2 manage GET /ui/videos (manage>=read)', c.get('/ui/videos', headers=H(k_manage)).status_code, {200}, '')

        # ============== E5-3 MONEY (monetize) + MODERATION (moderate) POSITIVE ==============
        check('E5-3 monetize PATCH {vid}/pricing', c.patch('/ui/videos/%s/pricing' % vid, headers=H(k_monetize), json={'price_cents': 500, 'access_mode': 'ppv'}).status_code, {200}, 'video:monetize')
        check('E5-3 monetize PATCH {vid}/ad-config', pg(c.patch('/ui/videos/%s/ad-config' % vid, headers=H(k_monetize), json={'pre_roll': True})), {'passed'}, 'video:monetize')
        # moderate+admin must PASS the scope gate AND require_admin_or_root (reach the handler).
        # NB: a valid status enum is used; a pre-existing prod data bug (rows with status='ready',
        # not in VideoMetadataModel enum) 500s the handler identically for BOTH api-key AND
        # UI-session admin -> auth-independent, so we assert past-auth, not the handler's status.
        rmod = c.get('/ui/videos/admin/by-status/published', headers=H(k_mod_adm))
        check('E5-3 moderate(admin) admin/by-status PAST scope+admin gate', (not is_scope_denied(rmod)) and rmod.status_code != 403, {True}, 'video:moderate+admin owner; http=%s' % rmod.status_code)

        # ============== NEGATIVE / SECURITY matrix ==============
        check('NEG read -> PATCH {vid} metadata', is_scope_denied(c.patch('/ui/videos/%s' % vid, headers=H(k_read), json={'description': 'no'})), {True}, 'read!=write')
        check('NEG read -> POST {vid}/clip', is_scope_denied(c.post('/ui/videos/%s/clip' % vid, headers=H(k_read), json={'start_seconds': 0, 'end_seconds': 1})), {True}, '')
        check('NEG read -> POST gallery/publish', is_scope_denied(c.post('/ui/videos/%s/gallery/publish' % vid, headers=H(k_read), json={'category': 'x'})), {True}, 'read!=publish')
        check('SEC write -> POST gallery/publish (distinct publish)', is_scope_denied(c.post('/ui/videos/%s/gallery/publish' % vid, headers=H(k_write), json={'category': 'x'})), {True}, 'write!=publish')
        check('SEC pubonly -> PATCH {vid} metadata', is_scope_denied(c.patch('/ui/videos/%s' % vid, headers=H(k_pubonly), json={'description': 'no'})), {True}, 'publish!=write')
        # *** headline: a plain video:write key CANNOT re-price (money) ***
        check('SEC write -> PATCH {vid}/pricing (MONEY)', is_scope_denied(c.patch('/ui/videos/%s/pricing' % vid, headers=H(k_write), json={'price_cents': 1})), {True}, 'write CANNOT re-price')
        check('SEC write -> PATCH {vid}/ad-config (MONEY)', is_scope_denied(c.patch('/ui/videos/%s/ad-config' % vid, headers=H(k_write), json={'pre_roll': False})), {True}, '')
        check('SEC manage -> PATCH {vid}/pricing (manage!=monetize)', is_scope_denied(c.patch('/ui/videos/%s/pricing' % vid, headers=H(k_manage), json={'price_cents': 1})), {True}, 'no monetize inherit')
        check('SEC manage -> GET admin/by-status (manage!=moderate)', is_scope_denied(c.get('/ui/videos/admin/by-status/ready', headers=H(k_manage))), {True}, 'no moderate inherit')
        check('SEC write -> GET admin/by-status (moderation)', is_scope_denied(c.get('/ui/videos/admin/by-status/ready', headers=H(k_write))), {True}, 'write!=moderate')
        check('SEC moderate(admin) -> PATCH {vid}/pricing (moderate!=monetize)', is_scope_denied(c.patch('/ui/videos/%s/pricing' % vid, headers=H(k_mod_adm), json={'price_cents': 1})), {True}, '')
        check('SEC monetize -> GET /ui/videos (monetize!=read)', is_scope_denied(c.get('/ui/videos', headers=H(k_monetize))), {True}, '')
        check('SEC monetize -> PATCH {vid} metadata (monetize!=write)', is_scope_denied(c.patch('/ui/videos/%s' % vid, headers=H(k_monetize), json={'description': 'no'})), {True}, '')
        check('NEG wrong messager:read -> GET /ui/videos', is_scope_denied(c.get('/ui/videos', headers=H(k_wrong))), {True}, '')
        check('NEG wrong messager:read -> PATCH pricing', is_scope_denied(c.patch('/ui/videos/%s/pricing' % vid, headers=H(k_wrong), json={'price_cents': 1})), {True}, '')
        # non-admin OWNER holding video:moderate -> past scope gate but require_admin_or_root 403
        rmu = c.get('/ui/videos/admin/by-status/ready', headers=H(k_mod_usr))
        check('SEC moderate(non-admin owner) -> admin/by-status 403', rmu.status_code, {403}, 'admin-owner create-gated (not scope=%s)' % scode(rmu)[1])

        # ============== INTENTIONAL fail-closed (unmapped money/social/ad-serve) ==============
        rt = c.post('/ui/videos/%s/tip' % vid, headers=H(k_write), json={'amount_cents': 100})
        check('BLOCK write -> POST {vid}/tip UNMAPPED 403', rt.status_code, {403}, 'reason=%s (money fail-closed)' % reason(rt))
        rpur = c.post('/ui/videos/%s/purchase' % vid, headers=H(k_write), json={'purchase_type': 'permanent'})
        check('BLOCK write -> POST {vid}/purchase UNMAPPED 403', rpur.status_code, {403}, 'reason=%s' % reason(rpur))
        rst = c.get('/ui/videos/%s/ad-stats' % vid, headers=H(k_monetize))
        check('BLOCK monetize -> GET {vid}/ad-stats UNMAPPED 403', rst.status_code, {403}, 'reason=%s (ad analytics)' % reason(rst))
        # DRM key-serve router NOT wired -> api-key policy never runs (public serve intact)
        rdrm = c.get('/v1/vod/drm/key/k_x?asset=a_x&token=bogus')
        check('BLOCK DRM key-serve (no key) untouched by policy', is_scope_denied(rdrm), {False}, 'st=%s (DRM own auth, not api-key)' % rdrm.status_code)

        # ============== REGRESSION ==============
        sid = 'synthsess-%d' % TS
        tok = mint_access_token(U, sid)
        sess = ({'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok)} if tok else {'x-user-sub': U})
        check('REG session(no key) -> GET /ui/videos', c.get('/ui/videos', headers=sess).status_code, {200}, 'UI session unaffected')
        check('REG session -> GET /ui/videos/{vid} (unmapped-but-session)', c.get('/ui/videos/%s' % vid, headers=sess).status_code, {200}, 'session bypasses policy')
        check('REG no-cred -> GET /ui/videos', c.get('/ui/videos').status_code, {401}, 'auth required')
        check('REG invalid key -> GET /ui/videos', c.get('/ui/videos', headers={'X-API-Key': 'ak_bogus.deadbeef'}).status_code, {401}, 'bad principal')
        check('REG admin:all wildcard -> GET /ui/videos', c.get('/ui/videos', headers=H(k_admin)).status_code, {200}, 'wildcard works')
        # wildcard bypasses the SCOPE gate even on the money route; the handler's own owner
        # check (UADM wildcard owner != video owner U) then returns "not your video" 403 --
        # a handler 403, NOT api_key_scope_denied. We assert the scope gate was bypassed.
        rwild = c.patch('/ui/videos/%s/pricing' % vid, headers=H(k_admin), json={'price_cents': 700})
        check('REG admin:all wildcard -> PATCH pricing PAST scope-gate', not is_scope_denied(rwild), {True}, 'wildcard bypasses scope; handler http=%s (ownership)' % rwild.status_code)
        check('REG messager:read -> /messaging/conversations (E2)', c.get('/messaging/conversations', headers=H(k_wrong)).status_code, {200}, '')
        check('REG filemanager:read -> /v1/fs/list (E3)', c.get('/v1/fs/list?path=/', headers=H(k_fm)).status_code, {200}, '')
        check('REG groups:read -> GET /ui/groups (E4)', c.get('/ui/groups', headers=H(k_groups)).status_code, {200}, '')
        dsc = c.get('/ui/delegation-api/v1/conversations', headers={'Authorization': 'Bearer dak_deadbeefdeadbeef.badsecret'}).status_code
        check('REG dak_ bogus delegation 401/403', dsc, {401, 403}, 'delegation intact')

    npass = sum(1 for _, _, ok in results if ok); nfail = len(results) - npass
    print('SUMMARY phase=%s pass=%d fail=%d' % (PHASE, npass, nfail))
except Exception as e:
    print('FATAL', e); traceback.print_exc()
finally:
    cleanup()
    print('CLEANUP done: keys=%d users=%d videos=%d' % (len(created_keys), len(created_users), len(created_videos)))
