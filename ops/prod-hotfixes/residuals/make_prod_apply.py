#!/usr/bin/env python3
"""Emit a shell script (to stdout) that pushes the residual patch files to prod
/tmp/resid and applies them AS ubuntu with .bak_resid_<ts> backups + py_compile.
Pipe into ssm_send.py. Run on the dev host: python make_prod_apply.py | python ssm_send.py
"""
import base64, os
D = os.path.expanduser("~/resid")
def b64(name):
    return base64.b64encode(open(os.path.join(D, name), "rb").read()).decode()

files = {
    "apply_mod1.py": b64("apply_mod1.py"),
    "apply_mod2.py": b64("apply_mod2.py"),
    "apply_advsign.py": b64("apply_advsign.py"),
    "dmca_content_operations.py": b64("dmca_content_operations.py"),
}
lines = ["set -e", "mkdir -p /tmp/resid"]
for name, data in files.items():
    lines.append("echo %s | base64 -d > /tmp/resid/%s" % (data, name))
lines.append("chmod 644 /tmp/resid/*.py")
body = r'''
set -e
cd /home/ubuntu/testlogon
TS=$(date +%s)
for f in app/routers/admin_moderation.py app/routers/messaging.py app/services/dmca_content_operations.py app/services/billing_shared.py; do cp -p "$f" "$f.bak_resid_$TS"; done
echo "BACKUPS_TS=$TS"
.venv/bin/python /tmp/resid/apply_mod1.py /home/ubuntu/testlogon
.venv/bin/python /tmp/resid/apply_mod2.py /home/ubuntu/testlogon
.venv/bin/python /tmp/resid/apply_advsign.py /home/ubuntu/testlogon
cp /tmp/resid/dmca_content_operations.py app/services/dmca_content_operations.py
.venv/bin/python -m py_compile app/routers/admin_moderation.py app/routers/messaging.py app/services/dmca_content_operations.py app/services/billing_shared.py && echo COMPILE_OK
'''
lines.append("su - ubuntu -c '%s'" % body.replace("'", "'\\''"))
print("\n".join(lines))
