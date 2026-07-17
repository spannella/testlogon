#!/usr/bin/env bash
# TIPX-C apply: fold the 3 backend files onto a target testlogon checkout, restart, check openapi.
# Usage: bash apply.sh [TARGET_REPO]   (default /home/ubuntu/testlogon)
set -euo pipefail
TARGET="${1:-/home/ubuntu/testlogon}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%s)"
for rel in app/services/tips.py app/services/tip_ledger.py app/routers/profile.py; do
  if [[ -f "$TARGET/$rel" ]]; then cp -a "$TARGET/$rel" "$TARGET/${rel}.bak_tipxc_${TS}"; fi
  cp -a "$HERE/files/$rel" "$TARGET/$rel"
  chown ubuntu:ubuntu "$TARGET/$rel" 2>/dev/null || true
  echo "applied $rel"
done
"$TARGET/.venv/bin/python" -m py_compile "$TARGET/app/routers/profile.py" && echo "compile OK"
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh || true
for i in $(seq 1 15); do sleep 2; code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json || true)"; [[ "$code" == "200" ]] && break; done
echo "openapi=$code"
curl -s http://127.0.0.1:8000/openapi.json | python3 -c 'import sys,json;print("profile_tip_route", "/ui/profile/{identifier}/tip" in json.load(sys.stdin).get("paths",{}))'
