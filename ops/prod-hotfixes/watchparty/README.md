# Watch-party realtime playback sync — prod fold (P2)

Wires host-authoritative watch-party playback state onto PROD
(i-08f937fc705ebea75, us-east-2) via SSM, REUSING the existing per-user event
queue that backs `GET /messaging/events/poll` (no new realtime infra).

## What
- Adds `app/services/watch_party_events.py` (new; md5 `2d2c8811…`, byte-identical
  to dev). `publish_playback_state()` fans a `watch_party:playback` event to each
  ACTIVE participant's `UserEvents` queue — the same channel the Android
  `SseMessagingEventStream` already polls, and the same fan-out pattern as
  `messaging_call_signaling`. `position` is stored as `Decimal` (DDB rejects float).
- Anchor-patches `app/services/watch_party.py` `control_playback()` to call the
  fan-out right after the existing in-process SSE broadcast (`patch_wp_service.py`,
  idempotent). Post-patch md5 `5cacc6fa…` (== dev). The in-process SSE still serves
  the web `/ui/watch-parties/{id}/stream` endpoint; the durable queue serves mobile.

Anchor byte-identical dev==prod confirmed before patch (prod pre-patch md5
`2d852013…` == dev `.bak_wpsync`).

## Apply
    python3 gen_apply_wp.py                       # regenerate apply_watchparty_prod.sh
    .venv/bin/python /tmp/ssm_send.py < apply_watchparty_prod.sh

Then restart: force-kill the drain-stuck worker if a graceful shutdown hangs on
long-lived poll/SSE connections, then `sudo -u ubuntu bash restart_backend.sh`
(self-detaches via `setsid nohup`, `--workers 1`). Verify openapi 200 + a single
`.venv/bin/uvicorn app.main:app … --workers 1` master.

⚠ GOTCHA: do NOT put the literal string `uvicorn app.main` in the SSM wrapper
shell — `pkill -f`/`ps | grep` will match the SSM shell itself and self-kill the
command. Match `.venv/bin/uvicorn app.main:app` or use `restart_backend.sh`
directly (which self-detaches).

## LIVE verify (prod)
`verify_wpsync.py` over real HTTP, two authed sessions: host publishes play@123.5
→ guest `/messaging/events/poll` delivers the frame (action/status/position/
controlled_by/position_updated_at), second control (pause@200) delivered, and a
non-participant control → 403. **11/11 PASS on prod** (and on dev).

## Rollback
Prod backup at `app/services/watch_party.py.bak_wpsync_<TS>`. To revert:
`cp app/services/watch_party.py.bak_wpsync_<TS> app/services/watch_party.py &&
rm app/services/watch_party_events.py` then restart. The fan-out is wrapped in a
best-effort try/except, so even a fan-out failure never breaks the authoritative
`control_playback` REST call.
