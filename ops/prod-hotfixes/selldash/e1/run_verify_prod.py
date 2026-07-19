#!/usr/bin/env python3
"""Run verify_selldash_e1.py ON prod against prod's own localhost:8000 (real
HTTP). gzip+base64 the verifier, decode on prod, run it as ubuntu with the prod
.env.local + venv loaded."""
import base64, gzip, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SSM = "/tmp/ssm_send.py"

src = open(os.path.join(HERE, "verify_selldash_e1.py")).read()
# Retarget the dev repo path to the prod repo path.
src = src.replace('os.path.expanduser("~/dev/testlogon")', '"/home/ubuntu/testlogon"')
payload = base64.b64encode(gzip.compress(src.encode(), 9)).decode()

DST = "/home/ubuntu/vse1_prod.py"
script = "\n".join([
    "cd /home/ubuntu/testlogon",
    f'echo "{payload}" | base64 -d | gunzip > {DST}',
    f"chown ubuntu:ubuntu {DST}",
    "sudo -u ubuntu bash -lc 'cd /home/ubuntu/testlogon && set -a; "
    ". .env.local 2>/dev/null; . .venv/bin/activate 2>/dev/null; "
    f"python3 {DST} 2>&1 | grep -vE \"^\\{{|Created session\"'",
    f"rm -f {DST}",
])

p = subprocess.run(["python3", SSM], input=script, capture_output=True, text=True)
sys.stdout.write(p.stdout)
if p.stderr.strip():
    sys.stderr.write(p.stderr)
