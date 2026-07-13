#!/usr/bin/env python3
"""Generate self-contained prod SSM probes for APIK E4 from the dev artifacts.
Run on the dev host (inside the venv):
  python gen_prod_deploy_e4.py place        > /tmp/prod_e4_place.py     # write artifacts + verify BEFORE
  python gen_prod_deploy_e4.py apply        > /tmp/prod_e4_apply.py     # backup 7 files + run idempotent patcher
  python gen_prod_deploy_e4.py verify_after > /tmp/prod_e4_after.py     # verify AFTER
Each emitted probe is run in-process on PROD via /tmp/ssm_run.py.
"""
import base64, os, sys

BASE = '/home/sean/dev/testlogon/ops/prod-hotfixes/apikey/E4'
FILES = ['apply_apik_e4_patch.py', 'verify_apik_e4.py', 'README.md']
enc = {}
for f in FILES:
    p = os.path.join(BASE, f)
    enc[f] = base64.b64encode(open(p, 'rb').read()).decode() if os.path.exists(p) else ''

MODE = sys.argv[1] if len(sys.argv) > 1 else 'place'

TARGETS = [
    'app/routers/user_groups.py', 'app/routers/group_feed.py', 'app/routers/group_calls.py',
    'app/routers/group_treasury.py', 'app/routers/group_fundraising.py',
    'app/services/api_key_route_scope_registry.py', 'app/core/settings.py',
]

HEAD = '''import base64, os, time, shutil, importlib.util, sys, ast
PROD = "/home/ubuntu/testlogon"
BASE = os.path.join(PROD, "ops/prod-hotfixes/apikey/E4")
FILES = %r
TARGETS = %r
os.makedirs(BASE, exist_ok=True)
''' % (enc, TARGETS)

WRITE_ARTIFACTS = '''
for name, b in FILES.items():
    if not b:
        continue
    with open(os.path.join(BASE, name), "wb") as fh:
        fh.write(base64.b64decode(b))
    try:
        import subprocess; subprocess.run(["chown", "ubuntu:ubuntu", os.path.join(BASE, name)], check=False)
    except Exception:
        pass
    print("WROTE", os.path.join(BASE, name))
'''

PLACE = HEAD + WRITE_ARTIFACTS + '''
os.environ["APIK_PHASE"] = "BEFORE"
os.environ["APIK_REPO"] = PROD
sys.argv = ["verify"]
spec = importlib.util.spec_from_file_location("verifymod", os.path.join(BASE, "verify_apik_e4.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
'''

APPLY = HEAD + '''
ts = int(time.time())
for rel in TARGETS:
    p = os.path.join(PROD, rel)
    bak = p + ".bak_apik_e4_%d" % ts
    shutil.copy(p, bak); print("BACKUP", bak)
os.environ["APIK_ROOT"] = PROD
os.environ["APIK_ROUTERS_DIR"] = os.path.join(PROD, "app/routers")
os.environ["APIK_REG"] = os.path.join(PROD, "app/services/api_key_route_scope_registry.py")
os.environ["APIK_SETTINGS"] = os.path.join(PROD, "app/core/settings.py")
spec = importlib.util.spec_from_file_location("applymod", os.path.join(BASE, "apply_apik_e4_patch.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); m.main()
import subprocess
for rel in TARGETS:
    p = os.path.join(PROD, rel)
    subprocess.run(["chown", "ubuntu:ubuntu", p], check=False)
    ast.parse(open(p).read())
print("AST_OK all %d targets" % len(TARGETS))
'''

AFTER = HEAD + WRITE_ARTIFACTS + '''
os.environ["APIK_PHASE"] = "AFTER"
os.environ["APIK_REPO"] = PROD
sys.argv = ["verify"]
spec = importlib.util.spec_from_file_location("verifymod", os.path.join(BASE, "verify_apik_e4.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
'''

print({"place": PLACE, "apply": APPLY, "verify_after": AFTER}[MODE])
