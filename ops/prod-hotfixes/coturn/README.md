# coturn TURN server — 1:1 WebRTC video-call connect (FIX B / #97)

Deployed **live** to the prod EC2 (`i-08f937fc705ebea75`, public `18.222.237.167`,
private `172.31.25.6`) via AWS SSM as root during the #97 video-call-connect QA session
(2026-07). Recorded here so it is not lost on the next prod rebuild. Like the `golive/`
MediaMTX infra, this is **standing prod infra**, not a code patch.

## Why
`POST /messaging/messages/calls/{id}/turn-credentials` was returning 403 because
`messaging_webrtc_turn_enabled` was off and no TURN server existed → the app got no ICE
servers → 1:1 calls could not traverse NAT and media never connected. FIX B stands up a
coturn TURN server behind TURN-REST auth and enables the backend to issue matching
time-limited HMAC credentials.

## What was installed
1. `apt-get install coturn` (coturn **4.6.1**). `systemctl enable --now coturn` (survives reboot).
2. `/etc/turnserver.conf` — see `turnserver.conf` in this dir (secret redacted).
   - `use-auth-secret` + `static-auth-secret=<64-hex>` → TURN-REST (ephemeral) auth, **NOT an open relay**.
   - `realm=tl-api.bitbazaar.cc`, `listening-port=3478`, relay range `min-port=49160`/`max-port=49200`.
   - `external-ip=18.222.237.167/172.31.25.6` (advertise public IP, bind private — the EC2 is NAT'd).
   - Hardening: `denied-peer-ip` for all RFC1918 + link-local + loopback, `allowed-peer-ip=172.31.25.6`,
     `no-tlsv1/1_1`, `no-multicast-peers`, `fingerprint`, `no-cli`.
3. `/etc/default/coturn` → `TURNSERVER_ENABLED=1` (see `default-coturn`).
4. Shared secret also stored at `/etc/coturn_shared_secret` (mode 0600).

## Backend wiring (also a live `.env.local` hotfix on prod `/home/ubuntu/testlogon/.env.local`)
Appended these 4 keys (consumed by `app/services/messaging_turn_credentials.py`, which builds
standard coturn TURN-REST creds: username = `{expires_at}:{user_sub}`,
credential = `base64(HMAC-SHA1(secret, username))`):

```
MESSAGING_WEBRTC_TURN_ENABLED=true
MESSAGING_WEBRTC_TURN_URLS=turn:tl-api.bitbazaar.cc:3478,turn:tl-api.bitbazaar.cc:3478?transport=tcp
MESSAGING_WEBRTC_TURN_SECRET=<REDACTED — same value as static-auth-secret>
MESSAGING_WEBRTC_TURN_TTL_SECONDS=600
```
Then restarted the backend. `MESSAGING_WEBRTC_TURN_SECRET` **must equal** the coturn
`static-auth-secret` or credentials will not validate.

## Security Group (`sg-00ab51618117e537d`, us-east-2) ingress added — 0.0.0.0/0
- `udp/3478`  (STUN/TURN)
- `tcp/3478`  (TURN over TCP)
- `udp/49160-49200` (relay port range)
5349/TLS not configured.

## Verification (2026-07)
- `POST .../turn-credentials` for both call participants → **HTTP 200** with
  `ice_servers:[{urls:[turn:tl-api.bitbazaar.cc:3478, ...?transport=tcp], username, credential}]`.
- External STUN binding from outside AWS → reflexive address returned (SG open, external-ip advertised).
- External `turnutils_uclient` full Allocate + relay from outside AWS → RC=0, 2 packets relayed,
  0 lost, RTT 31–81 ms.
- On two physical phones: a real 1:1 VIDEO call connected with **bidirectional video ~24 fps both ways**
  (both `org.webrtc EglRenderer` sustained ~95–96 frames/4 s; VP8 hardware encode confirmed).

## Standing cleanup (security) — owed at teardown
- Revoke the SG ingress: `udp/3478`, `tcp/3478`, `udp/49160-49200`.
- Rotate the shared secret (lives in `/etc/coturn_shared_secret`, `/etc/turnserver.conf`,
  and `/home/ubuntu/testlogon/.env.local`) together with the other prod secrets.
- coturn is TURN-REST gated (not an open relay), but leaving 3478 + the relay range world-open
  is a standing exposure — close when the call demo is done.
