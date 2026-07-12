#!/usr/bin/env bash
# TIP-B0 (TIP-001..013) re-appliable fold.
#   1. re-materializes app/services/tips.py (the centralized charge_tip seam).
#   2. migrates the 6 tip call sites onto charge_tip + fixes the text-path
#      orphan-credit ordering (migrate_shared_surfaces.py).
#   3. migrates the prod video-tip endpoint onto charge_tip (migrate_video_prod.py).
# The migration patchers are anchored on exact source blocks and FAIL LOUDLY if a
# block is missing (already applied, or prod drifted) -- so this is safe to inspect
# but NOT blindly re-run after a partial apply. Back up first: cp <file> <file>.bak.
set -euo pipefail
DEST="${1:-/home/ubuntu/testlogon}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$DEST/.venv/bin/python"

# 1. tips.py (new file, no .bak needed)
cp "$HERE/app_services_tips.py" "$DEST/app/services/tips.py"
chown ubuntu:ubuntu "$DEST/app/services/tips.py" 2>/dev/null || true

# 2. + 3. migrate the call sites (comment out any already-applied step)
"$PY" "$HERE/migrate_shared_surfaces.py" "$DEST"
"$PY" "$HERE/migrate_video_prod.py" "$DEST"

# py_compile everything touched
"$PY" -m py_compile \
  "$DEST/app/services/tips.py" \
  "$DEST/app/routers/messaging.py" \
  "$DEST/app/routers/newsfeed.py" \
  "$DEST/app/services/broadcast_tip_store.py" \
  "$DEST/app/routers/video_listing.py"
echo "TIP-B0 applied to $DEST (restart: su - ubuntu -c 'bash /home/ubuntu/restart_backend.sh')"
