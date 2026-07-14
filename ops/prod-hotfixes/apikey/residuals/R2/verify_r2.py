"""R2 (residual #118) - GET /ui/videos/admin/by-status/{status} legacy-status 500 fix.

In-process TestClient on PROD DDB; synthetic user/key/video/entitlement, auto-cleaned.
Proves the metadata store tolerates unknown/legacy status values (e.g. "ready", a
seed artifact carried by real v_ rows) so admin listings never 500, for BOTH a
UI-session admin and an admin api-key (video:moderate); valid enum values still work;
wrong scope / no key still gated. Unit-level before/after included.
"""
import os, sys, time
REPO = os.environ.get('APIK_REPO', os.getcwd())
sys.path.insert(0, REPO); os.chdir(REPO)
from fastapi.testclient import TestClient
from boto3.dynamodb.conditions import Key
from pydantic import ValidationError
from app.core.tables import T
from app.core.settings import S
from app.services import api_keys as AK
from app.services.sessions import mint_access_token
from app.core.time import now_ts
from app.models_video import VideoMetadataModel
from app.services.video_metadata_store import video_from_item, _coerce_video_status

TS = int(time.time())
UADM = 'apik-r2adm-%d' % TS
SYNTH_VID = 'v_r2synth_%d' % TS
created_users, created_keys, created_videos, created_ents = [], [], [], []


def seed_user(sub, role='user'):
    T.users.put_item(Item={'user_sub': sub, 'role': role, 'email': sub + '@synthetic.local',
                           'created_at': now_ts(), 'display_name': 'synthR2'})
    created_users.append(sub)


def mk_key(sub, caps):
    r = AK.create_api_key(sub, 'r2', expires_in_days=1, capabilities=caps)
    created_keys.append(r['key_id']); return r['key_secret']


def seed_ready_video():
    now = now_ts()
    T.video_metadata.put_item(Item={'video_id': SYNTH_VID, 'owner_user_id': UADM,
        'title': 'r2 synthetic ready', 'status': 'ready', 'created_at': now,
        'updated_at': now, 'source_type': 'upload'})
    created_videos.append(SYNTH_VID)


def seed_entitlement():
    eid = 'ent_r2_%d' % TS
    T.entitlements.put_item(Item={'user_id': UADM, 'entitlement_id': eid,
        'product_type': 'api_package', 'status': 'active', 'sku': 'r2-verify',
        'usage_limit': 0, 'created_at': now_ts(), 'updated_at': now_ts()})
    created_ents.append((UADM, eid)); return eid


def cleanup():
    for (uid, eid) in created_ents:
        try:
            r = T.entitlement_usage_events.query(KeyConditionExpression=Key('entitlement_id').eq(eid))
            for it in r.get('Items', []):
                T.entitlement_usage_events.delete_item(Key={'entitlement_id': eid, 'event_id': it['event_id']})
        except Exception as e:
            print('clean uevt err', e)
        try:
            T.entitlements.delete_item(Key={'user_id': uid, 'entitlement_id': eid})
        except Exception:
            pass
    for vid in created_videos:
        try:
            T.video_metadata.delete_item(Key={'video_id': vid})
        except Exception:
            pass
    for kid in created_keys:
        try:
            T.api_keys.delete_item(Key={'key_id': kid})
        except Exception as e:
            print('clean key err', e)
    for sub in created_users:
        try:
            T.users.delete_item(Key={'user_sub': sub})
        except Exception:
            pass


results = []


def rec(domain, name, ok, note=''):
    results.append((domain, name, bool(ok), note))
    print('  [%s] %-62s %s' % ('OK' if ok else 'XX', name, note))


def scode(resp):
    st = resp.status_code; cc = ''
    try:
        d = resp.json(); det = d.get('detail', d) if isinstance(d, dict) else {}
        if isinstance(det, dict):
            cc = det.get('code', '')
    except Exception:
        pass
    return st, cc


def denied(resp):
    st, cc = scode(resp); return st == 403 and cc == 'api_key_scope_denied'


def ids_of(resp):
    try:
        return [it.get('video_id') for it in resp.json().get('items', [])]
    except Exception:
        return []


def main():
    seed_user(UADM, role='admin')
    seed_ready_video()
    seed_entitlement()
    c = TestClient(__import__('app.main', fromlist=['app']).app, raise_server_exceptions=False)

    print('\n== UNIT before/after (deserialization) ==')
    old_raised = False
    try:
        VideoMetadataModel(id=SYNTH_VID, owner_user_id=UADM, title='x', status='ready')
    except ValidationError:
        old_raised = True
    rec('unit', 'BEFORE: VideoMetadataModel(status="ready") raised ValidationError', old_raised)
    m = video_from_item({'video_id': SYNTH_VID, 'owner_user_id': UADM, 'title': 'x',
                         'status': 'ready', 'created_at': 1, 'updated_at': 1})
    rec('unit', 'AFTER: video_from_item(status="ready") coerces (no raise)', m.status == 'created', 'status=%s' % m.status)
    rec('unit', '_coerce_video_status("ready")->created', _coerce_video_status('ready') == 'created')
    rec('unit', '_coerce_video_status("published") preserved', _coerce_video_status('published') == 'published')
    rec('unit', '_coerce_video_status(None)->created default', _coerce_video_status(None) == 'created')

    print('\n== UI-SESSION ADMIN ==')
    tok = mint_access_token(UADM, 'r2sess-%d' % TS)
    ck = {'Cookie': '%s=%s' % (S.ui_access_token_cookie_name, tok)}
    r = c.get('/ui/videos/admin/by-status/ready?limit=200', headers=ck)
    rec('session', 'by-status/ready -> 200 (not 500)', r.status_code == 200, 'st=%d' % r.status_code)
    rec('session', 'by-status/ready includes synthetic ready row', SYNTH_VID in ids_of(r), 'n=%d' % len(ids_of(r)))
    rp = c.get('/ui/videos/admin/by-status/published?limit=5', headers=ck)
    rec('session', 'valid by-status/published still 200', rp.status_code == 200, 'st=%d' % rp.status_code)
    rc0 = c.get('/ui/videos/admin/by-status/created?limit=5', headers=ck)
    rec('session', 'valid by-status/created still 200', rc0.status_code == 200, 'st=%d' % rc0.status_code)

    print('\n== ADMIN API-KEY (video:moderate + entitlement) ==')
    k_mod = mk_key(UADM, ['video:moderate'])
    ra = c.get('/ui/videos/admin/by-status/ready?limit=200', headers={'X-API-Key': k_mod})
    rec('apikey', 'video:moderate by-status/ready -> 200 (not 500/denied)', ra.status_code == 200, 'st=%d cc=%s' % scode(ra))
    rec('apikey', 'api-key by-status/ready includes synthetic ready row', SYNTH_VID in ids_of(ra), 'n=%d' % len(ids_of(ra)))
    rav = c.get('/ui/videos/admin/by-status/published?limit=5', headers={'X-API-Key': k_mod})
    rec('apikey', 'video:moderate by-status/published -> 200', rav.status_code == 200, 'st=%d cc=%s' % scode(rav))

    print('\n== NEG (scope/auth unchanged) ==')
    k_w = mk_key(UADM, ['video:write'])
    rec('apikey', 'NEG video:write->by-status/ready DENIED (moderate required)', denied(c.get('/ui/videos/admin/by-status/ready', headers={'X-API-Key': k_w})))
    rec('apikey', 'NEG no-key->by-status/ready 401', c.get('/ui/videos/admin/by-status/ready').status_code == 401)

    npass = sum(1 for _, _, ok, _ in results if ok)
    ntot = len(results)
    print('\nRESULT verify_r2 = %d/%d %s' % (npass, ntot, 'PASS' if npass == ntot else 'FAIL'))
    return npass == ntot


if __name__ == '__main__':
    ok = False
    try:
        ok = main()
    finally:
        cleanup()
        print('CLEANUP done: users/keys/videos/entitlements removed')
    sys.exit(0 if ok else 1)
