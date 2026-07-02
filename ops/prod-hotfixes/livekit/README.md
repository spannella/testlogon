# LiveKit SFU — audio-rooms infra (thousands of listeners, server-enforced mute/promote)

Deployed **live** to the prod EC2 (`i-08f937fc705ebea75`, public `18.222.237.167`,
private `172.31.25.6`, us-east-2) via AWS SSM as root on 2026-07-02. Recorded here so it
is not lost on the next prod rebuild. Like the `coturn/` and `golive/` (MediaMTX) infra,
this is **standing prod infra**, not a code patch. Deployed infra-only — the app repo /
Gradle / broadcast.py were NOT touched.

## Why
Upcoming audio-room feature needs a real SFU: fan-out to thousands of listeners plus
server-enforced participant permissions (mute / promote-to-speaker). LiveKit's RoomService
(server-side `UpdateParticipant` / `MutePublishedTrack`) provides exactly that.

## What was installed
1. Official install script `curl -sSL https://get.livekit.io | bash` → `livekit-server`
   **v1.13.2** to `/usr/local/bin/livekit-server`.
2. **Single node, in-memory** — NO Redis (not needed for one node).
3. `/etc/livekit/livekit.yaml` (mode 0600) — see `livekit.yaml` in this dir (secret redacted):
   - `port: 7880` (HTTP + WebSocket signaling; also serves the Twirp RoomService API + `/` health).
   - `rtc.tcp_port: 7881` (RTC/TCP fallback), `rtc.port_range_start/end: 50000-50200` (RTC/UDP media).
   - `rtc.use_external_ip: true` → server discovered `externalIP=18.222.237.167` via STUN and set
     it as the NAT1To1 nodeIP (EC2 is 1:1 NAT'd; advertised host candidate = the public IP).
   - `keys:` one API key/secret pair (generated on-box: key `openssl rand -hex`, secret `openssl rand -base64`).
   - `logging.level: info`.
4. systemd unit `/etc/systemd/system/livekit-server.service` (see `livekit-server.service`);
   `systemctl enable --now` → survives reboot. `LimitNOFILE=500000` for many concurrent conns.

## API key / secret
- **API key:** `API03cbfc10f882`
- **Secret:** stored ONLY in `/etc/livekit/livekit.yaml` on the box (mode 0600, redacted in the
  committed `livekit.yaml`). Value handed to the backend token-minting phase out-of-band.
- The backend mints room JWTs with this key/secret (HS256, `video` grants: roomJoin/roomAdmin/
  canPublish/canSubscribe + per-room mute/promote via server-side RoomService).
- **ADD TO THE STANDING SECRETS-ROTATION LIST** alongside the coturn shared secret: rotate the
  LiveKit secret in `/etc/livekit/livekit.yaml` (then `systemctl restart livekit-server`) together
  with the other prod secrets.

## Signaling / connection URL
- `ws://18.222.237.167:7880` (plain WS — dev/QA only).
- **RELEASE NEEDS TLS**: front with a domain + wss (e.g. `wss://livekit.bitbazaar.cc`) via the
  existing reverse proxy / ACM cert. Browsers on https pages will refuse plain `ws://`.

## Security Group (`sg-00ab51618117e537d`, us-east-2) ingress added — 0.0.0.0/0
- `tcp/7880`         (signaling: HTTP/WS + RoomService API)
- `tcp/7881`         (RTC/TCP fallback)
- `udp/50000-50200`  (RTC media)

## TURN
Not wired as an external TURN in LiveKit config. The box has a public IP and the RTC UDP range
is open, so LiveKit's own host/ICE candidate (NAT1To1 → 18.222.237.167) works. The existing
coturn (`turn:tl-api.bitbazaar.cc:3478`) can be added later as a LiveKit external TURN if needed
(not required for connectivity here).

## Verification (2026-07-02)
- `systemctl is-active livekit-server` → **active** (enabled; started clean, single-node routing).
- `ss -ltnup` → `livekit-server` LISTEN on `*:7880` and `*:7881`.
- Health `GET http://127.0.0.1:7880/` → `OK` (HTTP 200); `GET http://18.222.237.167:7880/`
  from OUTSIDE AWS (dev host) → `OK` (HTTP 200); `tcp/7881` reachable from outside AWS.
- **Token/RoomService test** (minted a JWT with `livekit-api` using the key/secret above,
  `room_admin+room_list+room_create+room_join` grants, then Twirp `/twirp/livekit.RoomService/*`):
  - `CreateRoom {name:verify-room}` → **200** (sid `RM_3YxxUQjpxF6D`, opus/VP8/H264/VP9/AV1 codecs).
  - `ListRooms {}` → **200** (returns verify-room).
  - `DeleteRoom {room:verify-room}` → **200** (cleaned up).
  → confirms the server accepts JWTs signed with the deployed key/secret and the control-plane works.

## Install / config method recap (for a rebuild)
```
curl -sSL https://get.livekit.io | bash                # installs livekit-server 1.13.x
mkdir -p /etc/livekit && cat > /etc/livekit/livekit.yaml   # (see livekit.yaml, add real secret)
cat > /etc/systemd/system/livekit-server.service           # (see livekit-server.service)
systemctl daemon-reload && systemctl enable --now livekit-server
# open SG sg-00ab51618117e537d: tcp/7880, tcp/7881, udp/50000-50200 (0.0.0.0/0)
```

## Standing cleanup (security) — owed at teardown
- Revoke the SG ingress: `tcp/7880`, `tcp/7881`, `udp/50000-50200`.
- Rotate the LiveKit API secret (lives in `/etc/livekit/livekit.yaml`) with the other prod secrets.
- Leaving 7880/7881 + the 50000-50200 UDP range world-open is a standing exposure — close when
  the audio-room demo is done. Front with TLS (wss) before any real release.
