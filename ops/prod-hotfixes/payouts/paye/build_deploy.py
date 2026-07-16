"""Runs on the DEV host: embeds the two source files (base64) into a prod deploy
python script at /tmp/deploy_paye.py (executed on prod via ssm_run.py)."""
import base64

REPO = "/home/sean/dev/testlogon"
svc = open(f"{REPO}/app/services/tax_1099.py", "rb").read()
rtr = open(f"{REPO}/app/routers/tax_1099.py", "rb").read()
svc_b64 = base64.b64encode(svc).decode()
rtr_b64 = base64.b64encode(rtr).decode()

deploy = f'''import base64, os, sys, hashlib
ROOT = "/home/ubuntu/testlogon"
sys.path.insert(0, ROOT)
FILES = {{
    "app/services/tax_1099.py": "{svc_b64}",
    "app/routers/tax_1099.py": "{rtr_b64}",
}}
for rel, b64 in FILES.items():
    data = base64.b64decode(b64)
    path = os.path.join(ROOT, rel)
    open(path, "wb").write(data)
    print("WROTE", rel, hashlib.md5(data).hexdigest(), len(data), "bytes")

# Patch main.py (idempotent, with .bak).
mp = os.path.join(ROOT, "app/main.py")
s = open(mp).read()
anchor = "    app.include_router(tax_form_1099_router)\\n"
if "tax_1099_router" in s:
    print("MAIN already patched")
elif anchor in s:
    import time
    bak = mp + ".bak_paye_" + time.strftime("%Y%m%d_%H%M%S")
    open(bak, "w").write(s)
    ins = "    from app.routers.tax_1099 import tax_1099_router  # PAY-E (PAY-40)\\n    app.include_router(tax_1099_router)\\n"
    open(mp, "w").write(s.replace(anchor, anchor + ins, 1))
    print("MAIN patched, bak=", os.path.basename(bak))
else:
    print("MAIN anchor NOT FOUND"); sys.exit(2)

import ast
ast.parse(open(os.path.join(ROOT, "app/services/tax_1099.py")).read())
ast.parse(open(os.path.join(ROOT, "app/routers/tax_1099.py")).read())
ast.parse(open(mp).read())
print("SYNTAX OK")
'''
open("/tmp/deploy_paye.py", "w").write(deploy)
print("built /tmp/deploy_paye.py", len(deploy), "bytes")
