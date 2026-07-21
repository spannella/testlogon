# Prod EC2 security-group posture — WebRTC / media / app ports

Instance: `i-08f937fc705ebea75` (public `18.222.237.167`, us-east-2).
Security group: **`sg-00ab51618117e537d`** (name `launch-wizard-24`, `vpc-876cfbee`).

This note is the standing analysis of *which ingress ports must stay world-open for
WebRTC / live-media to keep working* vs. *which can be safely tightened*, with the exact
reversible `aws ec2` commands. It consolidates the "standing cleanup owed" sections of the
`livekit/`, `coturn/`, and `golive/` READMEs.

> **Guiding rule (why so much is legitimately open):** WebRTC / TURN / WHIP clients connect
> **from arbitrary public IPs and behind arbitrary NATs**. The *media* planes (UDP relay/mux)
> and the *client signaling* planes therefore cannot be locked to a CIDR allow-list without
> breaking real users. Only **operator/admin/duplicate/stale** planes can be tightened.

## Current ingress (captured 2026-07-21 via `describe_security_groups`)

| proto/port | CIDR | service | verdict |
|---|---|---|---|
| tcp/80 | 0.0.0.0/0 | Caddy HTTP (ACME + redirect) | **KEEP open** |
| tcp/443 | 0.0.0.0/0 | Caddy HTTPS (API + SPA + `/hls-live`) | **KEEP open** |
| tcp/22 | 0.0.0.0/0 **+** 72.85.22.169/32, 139.60.191.198/32 | SSH | **RESTRICT** — revoke the 0.0.0.0/0, keep the /32s |
| udp/3478 | 0.0.0.0/0 | coturn STUN/TURN | **KEEP open** (clients from any IP) |
| tcp/3478 | 0.0.0.0/0 | coturn TURN-over-TCP | **KEEP open** (UDP-blocked clients) |
| udp/49160-49200 | 0.0.0.0/0 | coturn relay range | **KEEP open** (relay to any peer IP) |
| tcp/7880 | 0.0.0.0/0 | LiveKit signaling WS **+ RoomService admin API** | **KEEP open, FLAG** (client signaling shares the port with admin API; front with wss + split admin to close) |
| tcp/7881 | 0.0.0.0/0 | LiveKit RTC/TCP fallback | **KEEP open** (UDP-blocked clients) |
| udp/7882 | 0.0.0.0/0 | LiveKit RTC UDP mux (single-port media) | **KEEP open** (media from any client IP) |
| udp/8189 | 0.0.0.0/0 | MediaMTX WebRTC/WHIP media (UDP) | **KEEP open** (broadcaster media from any IP) |
| tcp/8889 | 0.0.0.0/0 | MediaMTX WHIP ingest (SDP signaling) | **KEEP open** (broadcasters from any IP) |
| tcp/8888 | 0.0.0.0/0 | MediaMTX HLS playback (cleartext origin) | **RESTRICT-CANDIDATE** — now frontable via Caddy `https://…/hls-live`; keep until the debug-APK cleartext base is retired, then revoke |
| tcp/8000 | 0.0.0.0/0 | uvicorn API (binds 0.0.0.0, **plaintext, bypasses Caddy TLS**) | **RESTRICT** — Caddy proxies via localhost; world-open plaintext API is an exposure |
| tcp/3000 | 0.0.0.0/0 | SPA node server (binds 0.0.0.0, plaintext) | **RESTRICT** — Caddy proxies via localhost |
| tcp/5173 | 0.0.0.0/0 | Vite dev server | **REVOKE** — nothing listening (stale rule) |

## What MUST stay world-open (do NOT restrict — would break live)

- **coturn** `udp/3478`, `tcp/3478`, `udp/49160-49200` — TURN relays media between two clients
  whose IPs are unknown ahead of time; TURN-REST-gated (not an open relay), so the exposure is
  bounded. Restricting to a CIDR breaks 1:1 calls behind symmetric NAT.
- **LiveKit** `udp/7882` (media mux) and `tcp/7881` (TCP fallback) — audio-room listeners
  connect from anywhere; UDP mux carries all media, TCP fallback rescues UDP-blocked clients.
- **MediaMTX** `udp/8189` (WebRTC media) and `tcp/8889` (WHIP SDP) — a broadcaster's phone
  publishes from an arbitrary cellular/Wi-Fi IP.
- **Caddy** `tcp/80`+`tcp/443` — public web + ACME.

Verified live at write time: audio rooms (LiveKit) load-tested to 320 participants over
`udp/7882` (see `livekit/README.md`); 1:1 video verified over the coturn relay (see
`coturn/README.md`); WHIP publish + HLS playback verified over MediaMTX (see `golive/` +
`README.md`). Tightening any media/signaling plane above risks these.

## What CAN be tightened (reversible commands)

All commands are **idempotent revokes/authorizes**; each has its exact inverse. Run from a host
with AWS creds + `ec2:AuthorizeSecurityGroupIngress`/`RevokeSecurityGroupIngress` on
`sg-00ab51618117e537d` (us-east-2). **APPLY ONLY THE ONES YOU INTEND** — read the rationale.

### 1. SSH — remove the world-open rule, keep the two admin /32s (SAFE, recommended)

```
# REVOKE world-open SSH (the /32 rules remain and keep your access):
aws ec2 revoke-security-group-ingress --region us-east-2 \
  --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]'
# INVERSE (re-open if locked out — but prefer adding your current /32 instead):
aws ec2 authorize-security-group-ingress --region us-east-2 \
  --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]'
```

> Before revoking, confirm your admin IP is one of 72.85.22.169/32 or 139.60.191.198/32,
> or add it first: `...authorize...IpRanges='[{CidrIp=<YOUR_IP>/32}]'`.
> The dev host public IP at write time is **69.201.163.58** — add it as a /32 if SSH from
> the dev host is needed.

### 2. Vite `tcp/5173` — revoke (stale, nothing listening) (SAFE)

```
aws ec2 revoke-security-group-ingress --region us-east-2 \
  --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=5173,ToPort=5173,IpRanges='[{CidrIp=0.0.0.0/0}]'
# INVERSE:
aws ec2 authorize-security-group-ingress --region us-east-2 \
  --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=5173,ToPort=5173,IpRanges='[{CidrIp=0.0.0.0/0}]'
```

### 3. API `tcp/8000` + SPA `tcp/3000` — revoke world-open plaintext (front via Caddy 443)

**Rationale:** Caddy already serves the API at `https://tl-api.bitbazaar.cc` and the SPA at
`https://tl.bitbazaar.cc` by proxying to `localhost:8000`/`localhost:3000`. The raw
`0.0.0.0:8000`/`:3000` rules expose the same services as **plaintext HTTP bypassing TLS**
(confirmed externally reachable: `http://18.222.237.167:8000/openapi.json` -> 200).
**CAVEAT — do NOT apply blindly:** any debug/QA client or Android debug build that hits
`http://18.222.237.167:8000` or `:3000` directly will break. Confirm no client uses the raw
IP:port before revoking. Prefer restricting to the dev-host /32 rather than a full revoke:

```
# Option A (restrict to dev host only) — RECOMMENDED first step:
aws ec2 revoke-security-group-ingress --region us-east-2 --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=8000,ToPort=8000,IpRanges='[{CidrIp=0.0.0.0/0}]'
aws ec2 authorize-security-group-ingress --region us-east-2 --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=8000,ToPort=8000,IpRanges='[{CidrIp=69.201.163.58/32,Description="dev host"}]'
# (repeat for 3000). INVERSE of each: swap revoke<->authorize with CidrIp=0.0.0.0/0.
```

### 4. MediaMTX HLS `tcp/8888` — revoke AFTER the release base URL moves to `/hls-live`

**Rationale:** the release HLS playback URL should move to `https://tl-api.bitbazaar.cc/hls-live/…`
(fronted by Caddy → `localhost:8888`; the `/hls-live` route was added + verified — see
`README.md` "HLS HTTPS"). Once no client uses the cleartext `:8888` origin, the world-open
`tcp/8888` can be revoked (Caddy reaches MediaMTX via localhost, not the SG).
**Do NOT revoke while the debug APK still uses `http://tl-api.bitbazaar.cc:8888`.**

```
aws ec2 revoke-security-group-ingress --region us-east-2 --group-id sg-00ab51618117e537d \
  --ip-permissions IpProtocol=tcp,FromPort=8888,ToPort=8888,IpRanges='[{CidrIp=0.0.0.0/0}]'
# INVERSE: same line with authorize-security-group-ingress.
```

### 5. LiveKit `tcp/7880` — cannot safely restrict yet (FLAG for owner)

`tcp/7880` carries **both** client signaling (WS) **and** the Twirp RoomService **admin** API.
The admin API being world-reachable is undesirable, but the port is also the client signaling
plane, so a blanket CIDR restrict would break audio-room join. The correct fix is infra work,
**not** an SG change: front signaling with `wss://livekit.bitbazaar.cc` via Caddy (needs a DNS
record + cert) and bind/split the RoomService API to localhost. Until then, leave `7880` open
and treat it as a known exposure. Do NOT restrict at the SG.

## Applied vs. documented (as of this commit)

- **APPLIED:** none of the SG revokes above were applied by automation — they are all left
  **for the owner to click**, because every one has a real "breaks a live client" caveat that
  cannot be verified from the repo host without risking live audio/video/broadcast. The SSH
  and Vite revokes (#1, #2) are the safest and are the recommended first actions.
- Verified-safe-to-apply reasoning is included per item so the owner can act with confidence.

## Teardown (when the media demos are fully retired)

Revoke, in this order: `5173`, `8888`, `3000`, `8000`, then the LiveKit/coturn/MediaMTX
media ports (`7880`, `7881`, `udp/7882`, `3478` tcp+udp, `49160-49200`, `8189`, `8889`), and
rotate the coturn + LiveKit secrets. Keep `22` (/32s), `80`, `443`.
