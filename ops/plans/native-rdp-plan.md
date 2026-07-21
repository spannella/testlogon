# Native RDP (Guacamole gateway) — honest build plan

**Status:** SCOPE ONLY — not built. VNC + SSH already cover the browser-remote-desktop need;
native in-browser RDP is a deferred, separately-budgeted milestone.

**Where it plugs in:** `app/services/rdp_sessions.py:create_session` currently raises
`501 RDP_NATIVE_NOT_IMPLEMENTED` (behind the default-off `RDP_REMOTE_DESKTOP_ENABLED` gate).
The fallback path (`get_fallback_details`) already ships: it returns secret-free host:port/username
+ "use mstsc / Microsoft Remote Desktop / FreeRDP, or VNC if the host exposes it" guidance. This
plan is the work to turn that 501 into a live Guacamole-backed session **without changing the
FE contract or the ownership/token model**, which are already locked by ADR-004.

**Prerequisite reading:** `docs/adr/ADR-004-rdp-transport.md` — it already fixes the decision
(Option A = Guacamole is the designated native path), the `/api/rdp/session` broker contract, the
dormant flags (`RDP_GATEWAY_WS_URL`, `RDP_SESSION_TOKEN_SECRET`, TTL/idle/max/rate-limit), and the
security invariants. This file is the concrete deploy + wiring plan for that Phase 2; it does not
re-decide anything in the ADR.

---

## 1. Architecture (what actually gets deployed)

```
browser (guacamole-common-js canvas)
   │  wss://<gateway>/rdp-tunnel?token=<single-use HS256>
   ▼
Guacamole tunnel shim  ── validates token (aud="rdp-bridge", jti one-shot, exp<=300s) ──┐
   │  guacd protocol (localhost:4822)                                                    │
   ▼                                                                                     │
guacd (Apache Guacamole proxy daemon) ── RDP :3389 ──▶ target Windows host              │
                                                                                         │
backend app (/api/rdp/session) mints the token + resolves user:{host_id} owner-scoped ──┘
```

Two new server-side components:

1. **`guacd`** — the Apache Guacamole native proxy daemon. Speaks RDP (also VNC/SSH) to the
   target and the Guacamole protocol to a tunnel client. Ships as a Debian package
   (`apt-get install guacd`) or the official `guacamole/guacd` container. Listens on
   `127.0.0.1:4822` (never world-exposed).
2. **A tunnel shim** — the WS↔guacd bridge that the browser connects to. Two viable forms:
   - **(a) The stock Guacamole Java webapp** (`guacamole.war` in Tomcat) — full-featured but
     drags in Tomcat + Java, contrary to the project's dependency-light posture (ADR §Cons).
   - **(b) A thin Python tunnel** beside `app/services/vnc_bridge_lifecycle.py` that terminates
     the browser WS, verifies our HS256 token, opens a guacd connection, performs the guacd
     handshake (`select`/`size`/`audio`/`video`/`image`/`connect` opcodes) with the
     server-resolved host/port/username/credential, then pipes guacd instructions to the browser.
     **Recommended** — it keeps "one code path, dev differs only in target URL" (SECOPS-007), reuses
     our token/ownership/GC/audit wiring, and avoids Tomcat/Java. Cost: implement the guacd
     handshake protocol (documented, ~a few hundred lines; the on-the-wire RDP stays inside guacd).

This plan assumes **(b)**.

## 2. Build steps (mapped to the reserved contract)

| # | Work | Where | Effort |
|---|---|---|---|
| A | Deploy `guacd` (package or container) bound to `127.0.0.1:4822` on the prod EC2; systemd unit + survives reboot; document under `ops/prod-hotfixes/guacd/` exactly like `livekit/`,`coturn/`,`golive/`. **No new SG port** (loopback only). | prod infra | ~1d |
| B | Python tunnel shim: WS route `/rdp-tunnel`, verify `verify_connect_token` (reuse VNC's), open guacd socket, do the guacd handshake with server-resolved params, bidirectional pipe, wire into `BridgeLifecycleManager` (idle/max GC). | `app/services/rdp_bridge.py` (new, beside `vnc_bridge_lifecycle.py`) | ~1.5w |
| C | Implement `rdp_sessions.create_session` for real: resolve `user:{host_id}` owner-scoped (already stubbed in `_resolve_fallback_target`), mint single-use HS256 token (`aud="rdp-bridge"`), return the `{session_id, ws_url, connect_params:{token}, capabilities, timeout_policy}` envelope — mirror `vnc_sessions.create_session` line-for-line. Add `DELETE /api/rdp/session/{id}` teardown. | `app/services/rdp_sessions.py`, `app/routers/rdp_sessions.py` | ~2d |
| D | RDP credential handling: resolve the target credential server-side via the existing KMS abstraction (same as SSH `stored_key`), hand it to guacd in the handshake, **never** to the browser. If no credential is stored, guacd surfaces the RDP login screen (NLA/CredSSP consideration below). | `app/services/rdp_sessions.py` + KMS seam | ~3d |
| E | FE: add `guacamole-common-js`, render its canvas client in (or beside) `RemoteDesktopPage.tsx` next to the existing noVNC `RFB`; flip the `/remote/rdp` flag-on branch to call `POST /api/rdp/session` and connect `withConnectParams(ws_url, connect_params)`. | `frontend/src/pages/remote/RemoteDesktopPage.tsx` | ~1w |
| F | Dev parity: a local mock guacd (or a recorded-handshake stub) behind `RDP_GATEWAY_WS_URL=ws://localhost:6090/rdp-tunnel`, so tests + local dev exercise the same code path with no live Windows host. Extend the CTI-010/011 suite with native-session token/replay/TLS tests mirroring the VNC suite. | tests + dev harness | ~3d |
| G | Prod TLS: front the tunnel with `wss://` via the existing **Caddy** (add a `/rdp-tunnel` reverse_proxy handle under `tl-api.bitbazaar.cc`, same pattern as the `/hls-live` HLS route already added). No new public port — rides 443. Enforce `_validate_secure_transport` (`wss://` outside dev). | Caddy + backend | ~0.5d |

## 3. Effort / risk

- **Total effort: ~L (multi-week, ~4–5 weeks one engineer).** The heavy items are the guacd
  handshake tunnel (B) and the FE Guacamole client (E). Matches the ADR's "~L (multi-week)".
- **Risk — MEDIUM-HIGH:**
  - **New native daemon + supply-chain surface** (`guacd` + FreeRDP under it): CVE tracking, patching,
    a deploy artifact the project otherwise avoids. This is the ADR's main "con" for Option A.
  - **guacd handshake protocol** in the Python shim is the trickiest code (opcode framing, base64
    element lengths, keepalive) — well-documented but easy to get subtly wrong; budget for it.
  - **NLA / CredSSP**: modern Windows RDP defaults to NLA. guacd supports it but needs correct
    `security=nla`/`ignore-cert` params and valid credentials up front (can't defer to the RDP
    login screen under NLA). Credential resolution (item D) is on the critical path.
  - **Dev parity**: guacd is awkward to run in-process; the mock (F) must be faithful enough that
    the same session/token/GC code runs in dev and prod (no `dev_mode` fork in the session logic).
  - **Reversibility**: the whole feature stays behind `RDP_REMOTE_DESKTOP_ENABLED` (default off) —
    flipping it off instantly reverts to the shipped fallback UX, zero risk to VNC/SSH.

## 4. What is NOT in scope / why deferred

- VNC + SSH already provide working browser remote desktop for the hosts that matter; a Windows
  host today gets a clear fallback (native-client instructions + VNC-if-available), not a broken
  connect. So native RDP is a **capability upgrade, not a gap-closer** — correctly deferred.
- No SG change is needed to *build* this (guacd is loopback; the tunnel rides Caddy 443). The only
  standing-infra cost is the guacd daemon itself, documented for teardown like the other media infra.

## 5. Go-live checklist (when greenlit)

1. Deploy guacd (loopback), systemd + `ops/prod-hotfixes/guacd/README.md`.
2. Land the tunnel shim + real `create_session` + `DELETE` teardown behind the flag (still off).
3. Add the Caddy `/rdp-tunnel` wss route (mirror the `/hls-live` handle; reversible).
4. Wire the FE Guacamole canvas; keep the fallback branch for flag-off.
5. Set `RDP_SESSION_TOKEN_SECRET` (prod secret, add to the rotation list next to coturn/LiveKit),
   `RDP_GATEWAY_WS_URL=wss://tl-api.bitbazaar.cc/rdp-tunnel`, then flip `RDP_REMOTE_DESKTOP_ENABLED=true`.
6. Verify: owner-scoped resolve, cross-user `host_id` denied, single-use token replay rejected,
   `wss://` enforced, idle/max GC fires, a real Windows host renders in-browser.
