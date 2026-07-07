#!/usr/bin/env bash
# TIP-B0 (TIP-001..004) re-appliable fold: the centralized tip charge service.
# Prod diverges from the dev clone and is redeployed from a base that may lack
# app/services/tips.py; this script re-materializes it on prod. It is a NEW file
# (no .bak needed). Safe to re-run (idempotent overwrite).
set -euo pipefail
DEST="${1:-/home/ubuntu/testlogon}"
SRC="$(cd "$(dirname "$0")" && pwd)/app_services_tips.py"
cp "$SRC" "$DEST/app/services/tips.py"
chown ubuntu:ubuntu "$DEST/app/services/tips.py" 2>/dev/null || true
"$DEST/.venv/bin/python" -m py_compile "$DEST/app/services/tips.py"
echo "TIP-B0 tips.py applied to $DEST"
