#!/usr/bin/env python3
"""Generate the prod-apply shell script (to feed ssm_send.py stdin)."""
import base64, os

HERE = os.path.dirname(os.path.abspath(__file__))


def b64(p):
    return base64.b64encode(open(os.path.join(HERE, p), "rb").read()).decode()


gl = b64("erp_gl.py")
ar = b64("erp_ar.py")
pr = b64("erp_pricing.py")
patch = b64("patch_main_erp.py")

L = []
L.append("cd /home/ubuntu/testlogon")
L.append("TS=$(date +%s)")
L.append("echo PROD_ERP_FOLD_$TS")
for name, payload in [("erp_gl", gl), ("erp_ar", ar), ("erp_pricing", pr)]:
    L.append("echo %s | base64 -d > app/routers/%s.py" % (payload, name))
    L.append("chown ubuntu:ubuntu app/routers/%s.py" % name)
L.append("cp app/main.py app/main.py.bak_erp_$TS")
L.append("echo %s | base64 -d > /home/ubuntu/close_patch_main_erp.py" % patch)
L.append("python3 /home/ubuntu/close_patch_main_erp.py")
L.append("chown ubuntu:ubuntu app/main.py")
L.append("echo === ROUTER_MD5 ===")
L.append("md5sum app/routers/erp_gl.py app/routers/erp_ar.py app/routers/erp_pricing.py")
L.append("echo === IMPORT_SANITY ===")
L.append("sudo -u ubuntu bash -lc 'cd /home/ubuntu/testlogon; set -a; . .env.local 2>/dev/null; set +a; .venv/bin/python -c \"import app.main; print(chr(73)+chr(77)+chr(80)+chr(79)+chr(82)+chr(84)+chr(95)+chr(79)+chr(75))\"' 2>&1 | tail -3")
L.append("echo === RESTART ===")
L.append("pkill -f 'uvicorn app.main' || true")
L.append("sleep 3")
L.append("sudo -u ubuntu bash /home/ubuntu/restart_backend.sh || true")
L.append("sleep 6")
L.append("for i in $(seq 1 30); do c=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/openapi.json); [ \"$c\" = \"200\" ] && { echo OPENAPI_200; break; }; sleep 2; done")
L.append("echo === WORKERS ===")
L.append("ps aux | grep '[u]vicorn app.main' | wc -l")
L.append("echo === NEW_ROUTES ===")
L.append("curl -s http://localhost:8000/openapi.json | python3 -c \"import sys,json; d=json.load(sys.stdin); ps=[p for p in d['paths'] if p.startswith('/v1/admin/gl') or p.startswith('/v1/admin/ar') or p.startswith('/v1/admin/pricing-rules')]; print(len(ps),'erp routes'); print(chr(10).join(sorted(ps)))\"")

open(os.path.join(HERE, "apply_erp_prod.sh"), "w", newline="\n").write("\n".join(L) + "\n")
print("wrote apply_erp_prod.sh")
