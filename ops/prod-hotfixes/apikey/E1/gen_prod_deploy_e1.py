#!/usr/bin/env python3
"""Generate a self-contained prod deploy probe for APIK E1 from the dev artifacts.
Run on the dev host: python gen_prod_deploy_e1.py > /tmp/prod_deploy_e1.py
The emitted probe (run in-process on PROD via ssm_run.py) writes the E1 artifact
files into the prod repo, backs up the prod registry, and applies the patch.
"""
import base64, os
BASE = "/home/sean/dev/testlogon/ops/prod-hotfixes/apikey/E1"
FILES = ["apply_apik_e1_patch.py", "verify_apik_e1.py", "README.md"]
enc = {}
for f in FILES:
    enc[f] = base64.b64encode(open(os.path.join(BASE, f), "rb").read()).decode()

TEMPLATE = '''import base64, os, time, shutil, importlib.util, sys
PROD = "/home/ubuntu/testlogon"
BASE = os.path.join(PROD, "ops/prod-hotfixes/apikey/E1")
os.makedirs(BASE, exist_ok=True)
FILES = %r
for name, b in FILES.items():
    with open(os.path.join(BASE, name), "wb") as fh:
        fh.write(base64.b64decode(b))
    print("WROTE", os.path.join(BASE, name))
reg = os.path.join(PROD, "app/services/api_key_route_scope_registry.py")
MODE = os.environ.get("E1_DEPLOY_MODE", "place")
if MODE == "apply":
    ts = int(time.time())
    bak = reg + ".bak_apik_e1_%%d" %% ts
    shutil.copy(reg, bak)
    print("BACKUP", bak)
    spec = importlib.util.spec_from_file_location("applymod", os.path.join(BASE, "apply_apik_e1_patch.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    sys.argv = ["apply", reg]
    m.main()
    import subprocess
    subprocess.run(["chown", "ubuntu:ubuntu", reg], check=False)
    print("APPLIED_TO", reg)
else:
    print("PLACED_ARTIFACTS_ONLY")
'''
print(TEMPLATE % (enc,))
