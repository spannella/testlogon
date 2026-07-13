#!/usr/bin/env python3
"""Generate self-contained prod SSM probes for APIK E2 from the dev artifacts.
Run on the dev host:
  python gen_prod_deploy_e2.py place        > /tmp/prod_e2_place.py     # write artifacts + verify BEFORE
  python gen_prod_deploy_e2.py apply        > /tmp/prod_e2_apply.py     # backup + apply patch on prod
  python gen_prod_deploy_e2.py verify_after > /tmp/prod_e2_after.py     # verify AFTER
Each emitted probe is run in-process on PROD via /tmp/ssm_run.py.
"""
import base64, os, sys

BASE = "/home/sean/dev/testlogon/ops/prod-hotfixes/apikey/E2"
FILES = ["apply_apik_e2_patch.py", "verify_apik_e2.py", "README.md"]
enc = {}
for f in FILES:
    p = os.path.join(BASE, f)
    enc[f] = base64.b64encode(open(p, "rb").read()).decode() if os.path.exists(p) else ""

MODE = sys.argv[1] if len(sys.argv) > 1 else "place"

HEAD = '''import base64, os, time, shutil, importlib.util, sys
PROD = "/home/ubuntu/testlogon"
BASE = os.path.join(PROD, "ops/prod-hotfixes/apikey/E2")
REG = os.path.join(PROD, "app/services/api_key_route_scope_registry.py")
FILES = %r
os.makedirs(BASE, exist_ok=True)
''' % (enc,)

PLACE = HEAD + '''
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
os.environ["APIK_PHASE"] = "BEFORE"
os.environ["APIK_REPO"] = PROD
sys.argv = ["verify"]
spec = importlib.util.spec_from_file_location("verifymod", os.path.join(BASE, "verify_apik_e2.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
'''

APPLY = HEAD + '''
ts = int(time.time())
bak = REG + ".bak_apik_e2_%d" % ts
shutil.copy(REG, bak); print("BACKUP", bak)
spec = importlib.util.spec_from_file_location("applymod", os.path.join(BASE, "apply_apik_e2_patch.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
sys.argv = ["apply", REG]; m.main()
import subprocess; subprocess.run(["chown", "ubuntu:ubuntu", REG], check=False)
import ast; ast.parse(open(REG).read()); print("AST_OK APPLIED_TO", REG)
'''

AFTER = HEAD + '''
for name, b in FILES.items():
    if not b:
        continue
    with open(os.path.join(BASE, name), "wb") as fh:
        fh.write(base64.b64decode(b))
    try:
        import subprocess; subprocess.run(["chown", "ubuntu:ubuntu", os.path.join(BASE, name)], check=False)
    except Exception:
        pass
os.environ["APIK_PHASE"] = "AFTER"
os.environ["APIK_REPO"] = PROD
sys.argv = ["verify"]
spec = importlib.util.spec_from_file_location("verifymod", os.path.join(BASE, "verify_apik_e2.py"))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
'''

print({"place": PLACE, "apply": APPLY, "verify_after": AFTER}[MODE])
