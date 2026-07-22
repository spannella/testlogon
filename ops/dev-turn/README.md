# DEV TURN relay (coturn) — LAN 1:1 WebRTC video-call HOLD

Stands up a TURN relay on the **dev host** (`192.168.0.249`, LAN) so dev-backend
1:1 WebRTC calls stop dropping at ~30-50 s (they were failing because there was no
TURN relay to traverse NAT / carry media). Mirrors the prod coturn scheme in
`ops/prod-hotfixes/coturn/` but adapted for the LAN. This is **host/system config**,
not a code change — the repo only carries this runbook.

## Backend TURN scheme (what coturn must match)
`app/services/messaging_turn_credentials.py` issues **coturn TURN-REST (`use-auth-secret`)**
time-limited HMAC credentials:

    username   = "{expires_at}:{user_id}"
    credential = base64( HMAC-SHA1( secret, username ) )

So coturn MUST run with `use-auth-secret` + `static-auth-secret=<secret>` where
`<secret>` **equals** the backend `MESSAGING_WEBRTC_TURN_SECRET`, or creds will not validate.

Endpoint: `POST /messaging/messages/calls/{call_id}/turn-credentials`

Gating (all read from env at process start):
- `MESSAGING_WEBRTC_TURN_ENABLED=true`      (else 403 feature_disabled)
- `MESSAGING_WEBRTC_TURN_URLS=turn:192.168.0.249:3478?transport=udp`
- `MESSAGING_WEBRTC_TURN_SECRET=<secret>`   (== coturn static-auth-secret)
- `MESSAGING_WEBRTC_TURN_TTL_SECONDS=600`
- `MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`  (gates /signal + invite/accept; needed for calls to ring)

## What was deployed on dev (2026-07)
coturn 4.6.1 is installed but the systemd unit needs root to configure
(`/etc/turnserver.conf`, `/etc/default/coturn`). The dev agent had **no sudo password**,
so coturn runs **in userspace** (port 3478 >= 1024 needs no root):

    ~/close_work/dev-turn/turnserver.conf    # config (secret = tlturnsecret123)
    ~/close_work/dev-turn/start_turn.sh      # idempotent launcher
    crontab @reboot -> start_turn.sh         # survives reboot (user cron)

Key differences from prod config: `no-tls`/`no-dtls` (LAN dev), and — critically —
`allowed-peer-ip=192.168.0.0-192.168.0.255` because on the LAN the **phones are
RFC1918 peers**; prod denies all RFC1918. Relay range 49160-49200, `no-cli`, `fingerprint`.

### Start / check / stop coturn (userspace, no sudo)
    ~/close_work/dev-turn/start_turn.sh          # start (idempotent)
    ss -lun | grep 3478                          # confirm listening
    pgrep -af turnserver                         # confirm process
    pkill -f "turnserver -c /home/sean/close_work/dev-turn/turnserver.conf"   # stop

### If you get sudo later — preferred: run it as a system service
    sudo cp ops/prod-hotfixes/coturn/turnserver.conf /etc/turnserver.conf   # then edit:
    #   static-auth-secret=tlturnsecret123, realm=dev.testlogon.lan,
    #   external-ip=192.168.0.249, relay-ip=192.168.0.249, listening-ip=0.0.0.0,
    #   ADD allowed-peer-ip=192.168.0.0-192.168.0.255 (LAN phones), no-tls/no-dtls
    echo TURNSERVER_ENABLED=1 | sudo tee /etc/default/coturn
    sudo systemctl enable --now coturn
    # then remove the userspace launcher + @reboot cron above.

## Backend wiring (dev)
`.env.local` already carries the 5 keys above (TURN_ENABLED/URLS/SECRET/TTL +
DIRECT_CALL_ENABLED=true). A backup is at `.env.local.bak`. Because settings read
`os.environ` at import, the backend MUST be (re)started with `.env.local` loaded:

    cd ~/dev/testlogon
    set -a; source ./.env.local; set +a
    export DDB_ENDPOINT_URL=http://localhost:8001 AWS_ENDPOINT_URL=http://localhost:4566 \
           AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test DEV_MODE=1
    nohup .venv/bin/python .venv/bin/uvicorn app.main:create_app --host 0.0.0.0 --port 8000 --factory \
          >> logs/backend.log 2>&1 & echo $! > .backend.pid
    curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/openapi.json   # expect 200

## VERIFY coturn allocates a relay (no phones)
Generate an HMAC cred exactly like the backend and run the TURN test client:

    SECRET=tlturnsecret123; EXPIRY=$(( $(date +%s) + 600 )); U="${EXPIRY}:test"
    P=$(printf "%s" "$U" | openssl dgst -sha1 -hmac "$SECRET" -binary | openssl base64)
    turnutils_uclient -v -y -u "$U" -w "$P" -p 3478 -n 2 -c 192.168.0.249
    # PASS = "Received relay addr: 192.168.0.249:491xx" + "success" + 0 lost packets.
    # Wrong secret => "ERROR: Cannot complete Allocation" (proves it is not an open relay).

## VERIFY the backend hands out coturn (no phones)
Seed a connected call session (empty conversation_id is rejected by the sessions GSI,
so use a real conv + seed both participants), then, in DEV, auth is
`Authorization: Bearer <user_id>`:

    curl -s -X POST http://localhost:8000/messaging/messages/calls/<call_id>/turn-credentials \
         -H "Authorization: Bearer <participant_user_id>"
    # PASS = HTTP 200 with ice_servers[0].{urls,username,credential}; feed that exact
    # username/credential back into turnutils_uclient -> coturn allocates a relay (full round-trip).
    # No bearer -> 401; non-participant -> 403 forbidden.

Seed snippet (run in the venv with .env.local + DDB endpoint env loaded, PYTHONPATH=repo root):

    from app.core.aws import ddb
    from app.services.messaging_call_sessions import create_call_session
    import os
    CONV="turnverify-conv-001"; CALL="turnverify-devcall-001"
    A="turnverify-caller"; B="turnverify-callee"
    t=ddb.Table(os.getenv("DDB_PARTICIPANTS","Participants"))
    for pid in (A,B):
        t.put_item(Item={"user_id":pid,"conversation_id":CONV,"status":"active",
            "role":"member","muted_until":0,"last_read_at":0,"unread_count":0,
            "joined_at":0,"left_at":0,"GSI1PK":CONV,"GSI1SK":pid})
    create_call_session(call_id=CALL,conversation_id=CONV,caller_user_id=A,
        callee_user_id=B,initial_mode="video",state="connected")

## FOLLOW-UP: full 2-device "call holds >2 min" (needs the phones, busy on prod)
1. Free a test phone and point the app at the dev backend
   (`http://192.168.0.249:8000`; phones share the LAN, so the relay is reachable).
2. Log in as two seeded users who share a conversation.
3. Place a 1:1 VIDEO call A -> B, accept on B.
4. Confirm both clients fetch TURN (`.../turn-credentials` -> 200) and the ICE relay
   candidate `192.168.0.249:491xx` is used.
5. Leave the call up **> 2 minutes** and confirm it stays **Connected** with
   bidirectional video (prod parity showed ~24 fps both ways). Previously it dropped at 30-50 s.
6. On the dev host during the call: `ss -tunp | grep 491` should show live relay flows.

## Teardown / reversibility
- Stop coturn: `pkill -f "turnserver -c /home/sean/close_work/dev-turn/turnserver.conf"`
- Remove @reboot cron: `crontab -e` (delete the start_turn.sh line)
- No system files were changed (userspace only). `.env.local.bak` preserved.
- Rotate `tlturnsecret123` in both `~/close_work/dev-turn/turnserver.conf` and `.env.local`
  together if it is ever shared beyond the LAN.
