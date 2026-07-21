# Group-call SFU seam (GAP-0017-sfu) — prod mirror

Mirrors commit `ddc24fe2` (feat: wire group-call SFU seam to the existing
LiveKit deployment) onto prod (i-08f937fc705ebea75, us-east-2).

## What changed on prod
Two files were byte-identical between dev-pre-change and prod, so they were
mirrored logically-identically via the SAME dev patch scripts:
- `app/routers/group_calls.py`  (patch_router1.py + patch_router2.py) -> md5 b4053dfc5f457471b9c6beacd690dccc (== dev)
- `app/services/api_key_route_scope_registry.py` (patch_registry.py) -> md5 ff7ce277e28b825f1e34c265c2995e6a (== dev)

Two files had DIVERGED from dev (prod already carries the audio-room LiveKit
fields, different line layout), so they were patched SURGICALLY to the same
logical content rather than byte-copied:
- `app/core/settings.py` (prod_patch_settings.py) — adds ONLY
  `group_call_sfu_provider` (prod already had livekit_url/api_key/api_secret/
  control_url from the audio-room hotfix).
- `app/models.py` (prod_patch_models.py) — extends `GroupCallSignalingInfo`
  with sfu_provider/livekit_url/room_name.

Backups on prod: `*.bak_gap0017` next to each file.

## Verify-after (prod)
- `.venv/bin/python -c "import app.main"` -> OK
- restart: root `pkill -f "uvicorn app.main"` then `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh`
- openapi 200, single `--workers 1` uvicorn
- `/ui/calls/group/{call_id}/livekit-token` registered
- prod LiveKit creds currently unset -> group calls advertise mode=mesh and the
  token endpoint returns 503 LIVEKIT_NOT_CONFIGURED (honest default). Setting
  LIVEKIT_URL/API_KEY/API_SECRET (same as audio rooms) flips it to the SFU path.

## Honest status
Backend SFU token seam is COMPLETE + live-verified (real LiveKit JWT grant on
dev with creds set). Web browser media over LiveKit is SEAM-NOT-LIVE: it needs
the `livekit-client` npm dep + a Room-connect in the call surface. Android
already connects to the same LiveKit deployment for audio rooms.
