#!/usr/bin/env python3
"""Regenerate apply_watchparty_prod.sh — the SSM shell script that folds the
watch-party realtime playback backend onto prod byte-identically."""
import base64, os

HERE = os.path.dirname(os.path.abspath(__file__))

def b64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()

events_b64 = b64(os.path.join(HERE, "watch_party_events.py"))
patcher_b64 = b64(os.path.join(HERE, "patch_wp_service.py"))

script = f"""cd /home/ubuntu/testlogon
TS=$(date +%s)
echo PROD_WATCHPARTY_FOLD_$TS
# 1. New fan-out service (verbatim from dev, md5 must match 2d2c8811...).
echo {events_b64} | base64 -d > app/services/watch_party_events.py
chown ubuntu:ubuntu app/services/watch_party_events.py
# 2. Anchor-patch control_playback (idempotent). Back up first.
cp app/services/watch_party.py app/services/watch_party.py.bak_wpsync_$TS
echo {patcher_b64} | base64 -d > /home/ubuntu/close_patch_wp_service.py
python3 /home/ubuntu/close_patch_wp_service.py
chown ubuntu:ubuntu app/services/watch_party.py
echo === MD5 (expect events=2d2c8811... service=5cacc6fa...) ===
md5sum app/services/watch_party_events.py app/services/watch_party.py
echo === IMPORT_SANITY ===
sudo -u ubuntu bash -lc 'cd /home/ubuntu/testlogon; set -a; . .env.local 2>/dev/null; set +a; .venv/bin/python -c "import app.services.watch_party_events, app.services.watch_party; print(chr(73)+chr(77)+chr(80)+chr(79)+chr(82)+chr(84)+chr(95)+chr(79)+chr(75))"' 2>&1 | tail -3
echo === RESTART ===
pkill -f 'uvicorn app.main' || true
sleep 3
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh || true
sleep 6
for i in $(seq 1 30); do c=$(curl -s -o /dev/null -w '%{{http_code}}' http://localhost:8000/openapi.json); [ "$c" = "200" ] && {{ echo OPENAPI_200; break; }}; sleep 2; done
echo === WORKERS ===
ps aux | grep '[u]vicorn app.main' | wc -l
echo === WATCHPARTY_ROUTE_PRESENT ===
curl -s http://localhost:8000/openapi.json | python3 -c "import sys,json; d=json.load(sys.stdin); print('control_route' if '/ui/watch-parties/{{party_id}}/control' in d['paths'] else 'MISSING')"
"""

out = os.path.join(HERE, "apply_watchparty_prod.sh")
with open(out, "w") as f:
    f.write(script)
print("wrote", out)
