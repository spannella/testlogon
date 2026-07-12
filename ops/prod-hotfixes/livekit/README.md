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
   - `rtc.tcp_port: 7881` (RTC/TCP fallback), `rtc.udp_port: 7882` (SINGLE UDP MUX for RTC/UDP
     media — was the `50000-50200` range until the 2026-07-07 scale fix; see "Scale fix" below).
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
- `udp/7882`         (RTC media — SINGLE UDP MUX; replaced the revoked `udp/50000-50200` range on 2026-07-07)

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
# open SG sg-00ab51618117e537d: tcp/7880, tcp/7881, udp/7882 (0.0.0.0/0)   # single UDP mux (was udp/50000-50200)
```

## Standing cleanup (security) — owed at teardown
- Revoke the SG ingress: `tcp/7880`, `tcp/7881`, `udp/7882` (the old `udp/50000-50200` range was already revoked in the 2026-07-07 mux fix).
- Rotate the LiveKit API secret (lives in `/etc/livekit/livekit.yaml`) with the other prod secrets.
- Leaving 7880/7881 + the `udp/7882` mux port world-open is a standing exposure — close when
  the audio-room demo is done. Front with TLS (wss) before any real release.

## Scale fix — UDP mux (2026-07-07): lifts the ~100-participant cap
Single-node LiveKit v1.13.2 hard-capped at **~100 concurrent MEDIA participants** because rtc
used the udp port **RANGE `50000-50200`** (201 ports, ~2 ports/participant) — UDP **port
exhaustion**, NOT CPU (CPU/RAM had huge headroom at the cap). Fix = a **single UDP mux port**
(`rtc.udp_port: 7882`; `port_range_start/end` removed) — LiveKit demuxes all participants'
media over the one port. **livekit-server restart only** — the app-backend uvicorn
(`app.main:app` :8000, pid unchanged) was NOT touched; `https://tl-api.bitbazaar.cc/openapi.json`
stayed 200 across the change.

Config: `/etc/livekit/livekit.yaml` rtc — removed `port_range_start: 50000` + `port_range_end:
50200`, added `udp_port: 7882` (kept `tcp_port: 7881`, `use_external_ip: true`, `port: 7880`,
keys). On-box backup: `livekit.yaml.bak_udpmux_<ts>`.
SG `sg-00ab51618117e537d`: **added** `udp/7882` 0.0.0.0/0, **revoked** `udp/50000-50200`.

Re-verified with `lk load-test` (livekit-cli 2.4.0) from the dev host `.249` against
`ws://18.222.237.167:7880`:

| test (audio-pub + sub) | BEFORE (port-range 50000-50200) | AFTER (udp mux 7882) |
|---|---|---|
| 20 + 150 (170) | ~101 connected; **69 subs ICE-timeout** ("could not connect after timeout"); connected subs got only 6/20 tracks; 486/3000 track-stats; livekit CPU ~60%, RSS ~495MB | **all 170 connected, 0 failures, 0% pkt loss**; 900/3000 track-stats; CPU ~63%, RSS ~419MB |
| 20 + 300 (320) | (not run — 170 already over the cap) | **all 320 connected, 0 failures, 0% pkt loss**; 1800/6000 track-stats, ~30mbps; livekit CPU ~120% of 400% (65% idle overall), RSS ~948MB |

Throughout the AFTER runs `ss -lunp` showed exactly **ONE** livekit udp socket (`:7882`), not a
saturating range. **New ceiling: >320 participants with server headroom to spare; the bound is
now CPU (single 4-vCPU node) + the single-host load-generator, NOT UDP ports.** For
thousands-of-listeners, scale the node vertically or go multi-node + Redis.
