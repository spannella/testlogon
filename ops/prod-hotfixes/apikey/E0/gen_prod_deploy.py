import gzip, base64, io, os, sys, json
DEV = '/home/sean/dev/testlogon'
OVERWRITE = [
    'app/services/api_key_capabilities.py',
    'app/services/api_key_authorization.py',
    'app/services/api_keys.py',
    'app/services/api_key_rollout.py',
    'app/services/api_key_policy_enforcement.py',
    'app/auth/deps.py',
    'app/services/sessions.py',
    'app/main.py',
    'app/services/api_key_route_scope_registry.py',
]
# settings.py: targeted patch (prod == dev-original for this file; small change only)
SETTINGS_OLD = '''    api_key_messager_canary_subjects: str = os.environ.get("API_KEY_MESSAGER_CANARY_SUBJECTS", "")
    api_key_dual_credential_mode: str = os.environ.get("API_KEY_DUAL_CREDENTIAL_MODE", "prefer_api_key")'''
SETTINGS_NEW = '''    api_key_messager_canary_subjects: str = os.environ.get("API_KEY_MESSAGER_CANARY_SUBJECTS", "")

    # APIK-E0-3: groups rollout product (default shadow until E4 canary->GA)
    api_key_groups: bool = os.environ.get("API_KEY_GROUPS", "1") not in ("0", "false", "False")
    api_key_groups_phase: str = os.environ.get("API_KEY_GROUPS_PHASE", "shadow")
    api_key_groups_canary_percent: int = int(os.environ.get("API_KEY_GROUPS_CANARY_PERCENT", "0"))
    api_key_groups_canary_subjects: str = os.environ.get("API_KEY_GROUPS_CANARY_SUBJECTS", "")

    # APIK-E0-3: video rollout product (default shadow until E5 canary->GA)
    api_key_video: bool = os.environ.get("API_KEY_VIDEO", "1") not in ("0", "false", "False")
    api_key_video_phase: str = os.environ.get("API_KEY_VIDEO_PHASE", "shadow")
    api_key_video_canary_percent: int = int(os.environ.get("API_KEY_VIDEO_CANARY_PERCENT", "0"))
    api_key_video_canary_subjects: str = os.environ.get("API_KEY_VIDEO_CANARY_SUBJECTS", "")

    api_key_dual_credential_mode: str = os.environ.get("API_KEY_DUAL_CREDENTIAL_MODE", "prefer_api_key")'''

blobs = {}
for rel in OVERWRITE:
    with io.open(os.path.join(DEV, rel), 'rb') as f:
        raw = f.read()
    blobs[rel] = base64.b64encode(gzip.compress(raw)).decode()

payload = {'blobs': blobs, 'settings_old': SETTINGS_OLD, 'settings_new': SETTINGS_NEW}

DEPLOY = r'''# APIK-E0 prod deploy: mirror dev android-impl byte-for-byte (folds prod hotfix).
import gzip, base64, io, os, sys, time, py_compile
PROD = '/home/ubuntu/testlogon'
TS = str(int(time.time()))
PAYLOAD = __PAYLOAD__
baks = []
changed = []
for rel, b64 in PAYLOAD['blobs'].items():
    p = os.path.join(PROD, rel)
    new = gzip.decompress(base64.b64decode(b64))
    if os.path.exists(p):
        with io.open(p, 'rb') as f: cur = f.read()
        if cur == new:
            print('UNCHANGED', rel); changed.append(p); continue
        bak = p + '.bak_apik_e0_' + TS
        with io.open(bak, 'wb') as f: f.write(cur)
        baks.append(bak)
    with io.open(p, 'wb') as f: f.write(new)
    print('OVERWROTE', rel)
    changed.append(p)
# settings.py targeted patch
sp = os.path.join(PROD, 'app/core/settings.py')
with io.open(sp, 'r', encoding='utf-8') as f: sc = f.read()
if PAYLOAD['settings_new'].split(chr(10))[2].strip() in sc:
    print('SETTINGS already patched (groups flag present)')
elif sc.count(PAYLOAD['settings_old']) == 1:
    bak = sp + '.bak_apik_e0_' + TS
    with io.open(bak, 'w', encoding='utf-8') as f: f.write(sc)
    baks.append(bak)
    sc = sc.replace(PAYLOAD['settings_old'], PAYLOAD['settings_new'])
    with io.open(sp, 'w', encoding='utf-8') as f: f.write(sc)
    print('SETTINGS patched')
else:
    print('SETTINGS ANCHOR FAIL count=', sc.count(PAYLOAD['settings_old'])); sys.exit(4)
changed.append(sp)
# chown + byte-compile
os.system('chown ubuntu:ubuntu ' + ' '.join(changed) + ' ' + ' '.join(baks) + ' 2>/dev/null')
ok = True
for p in changed:
    try: py_compile.compile(p, doraise=True)
    except Exception as e: ok = False; print('PYCOMPILE FAIL', p, e)
print('PYCOMPILE', 'OK' if ok else 'FAILED')
print('BAKS ' + ' '.join(os.path.basename(b) for b in baks))
print('DEPLOY_TS ' + TS)
'''
DEPLOY = DEPLOY.replace('__PAYLOAD__', repr(payload))
with io.open('/tmp/prod_deploy.py', 'w', encoding='utf-8') as f:
    f.write(DEPLOY)
print('generated /tmp/prod_deploy.py bytes=', len(DEPLOY))
