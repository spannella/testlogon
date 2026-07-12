# ADR-004: RDP Browser Transport (CTI-004 spike)

## Status

Proposed

## Context

The compute surfaces (EC2/K8s launchers, instance monitoring) auto-register launched
instances into the host inventory, and Windows EC2 AMIs are correctly tagged
`protocol="rdp"`, `port=3389`:

- `app/services/ec2_launcher.py:328-329` — `protocol = "rdp" if ami_info.get("os_type") == "windows" else "ssh"` / `port = 3389 if protocol == "rdp" else 22`. The AMI catalog at `app/services/ec2_launcher.py:57-61` includes `ami-windows-2022` (`os_type="windows"`).
- `app/services/host_inventory.py:54` — `VALID_PROTOCOLS = {"ssh", "vnc", "rdp"}`; `DEFAULT_PORTS` at `:56` maps `rdp → 3389`.
- `rdp` is accepted across the stack: `app/models.py` host protocol enum, FE `HostProtocol` in `frontend/src/api/types.ts`.

**The gap:** there is no actual RDP terminal. `host_inventory.quick_connect`
(`app/services/host_inventory.py:509-549`) shoves RDP into the SSH connect form:

```python
# app/services/host_inventory.py:537-542
else:
    # SSH/RDP: frontend pre-fills the terminal connect form.
    params = f"host={host['hostname']}&port={host['port']}"
    if host["username"]:
        params += f"&username={host['username']}"
    out["connect_path"] = f"/remote/ssh?{params}"
```

The Browser SSH terminal (`app/routers/browser_ssh_terminal.py`) cannot speak RDP — it is a
Paramiko PTY bridge (`ParamikoSshBridge`, `:63`). A Windows host's "Open terminal" therefore
lands on a connect form that will fail at the protocol layer. CTI-001 already rejects
non-`ssh` hosts on the SSH WS endpoint with an `unsupported_protocol` error, so today a
Windows host has **no working path at all**. The roadmap flags this
(`docs/feature-roadmap.md` §3d, "EC2/K8s Open SSH/VNC/RDP terminal deep-link", status 🟡).

### What we can reuse — the VNC session/token scheme

The VNC subsystem is the closest existing analogue and is the intended template
(CTI-004 / CTI-005 explicitly call for reusing `app/services/vnc_sessions.py:298-373`):

- **Brokered session + short-lived token.** `POST /api/vnc/session` (`app/routers/vnc_sessions.py:96`) takes a `target_id`, resolves it owner-scoped, mints a single-use HS256 JWT (`mint_connect_token`, `app/services/vnc_sessions.py:325-339`; `aud="vnc-bridge"`, `jti`, `exp`), and returns `{session_id, ws_url, connect_params:{token}, capabilities, timeout_policy}`. The token TTL is clamped to 60–300s (`_token_ttl_seconds`, `:120-126`).
- **Replay protection.** `verify_connect_token` (`:342-399`) consumes the `jti` exactly once via `STORE.consume_jti_once` (`:69-79`).
- **Ownership enforcement.** `_resolve_target` (`:237-274`) already resolves the inventory-backed `user:{host_id}` target (CTI-002, DONE), looking the host up owner-scoped via `host_inventory.get_host(user_sub, host_id)` and pinning `allowed_users=(user_sub,)`; `_ensure_authorized` (`:281-297`) double-checks.
- **Transport TLS guard.** `_validate_secure_transport` (`:300-309`) requires `wss://` outside dev/test.
- **Bridge lifecycle + idle/max-duration GC.** `BridgeLifecycleManager` (`app/services/vnc_bridge_lifecycle.py`) with `idle_timeout_seconds`/`max_duration_seconds` and a `validate_target_ws_url` reachability check (`:126-128`).
- **Rate limiting, metrics, audit, observability** — all wired (`_enforce_bootstrap_rate_limit` `:312`, `record_vnc_session_event`, `audit_event("vnc_session_bootstrap")`).
- **FE rendering surface.** `frontend/src/pages/remote/RemoteDesktopPage.tsx` dynamically loads a noVNC `RFB` constructor (`:160-166`, `:250-253`) and connects to `withConnectParams(created.ws_url, created.connect_params)`.

The VNC dev/prod parity model is the SECOPS-007 reference: the same code path runs in dev and
prod; the only difference is the **target `ws_url`** (dev points at a local websockify, e.g.
`VNC_DEMO_WS_URL=ws://localhost:6080/websockify`, `:204`) and the `wss://` TLS guard that
short-circuits in dev (`_is_dev_environment`, `:111-113`). There is no `if dev_mode:` branch in
the session logic itself.

## Decision drivers

1. **Reuse over reinvention.** CTI-004/005 mandate reusing the VNC token/session scheme. The closer the RDP path tracks VNC, the smaller the build and the audit surface.
2. **Dev/prod parity (SECOPS-007).** One code path; dev differs only in target URL + TLS guard, mockable in-process. No `dev_mode` fork in the connect/session logic.
3. **Security.** Server-side ownership scoping (no client-supplied host/port), single-use short-lived token, `wss://` in prod, idle/max-duration GC — all inherited from VNC.
4. **Effort / risk for CTI-005 (budgeted 3 days).** RDP protocol implementation in Python is heavy; a from-scratch FreeRDP bridge does not fit a 3-day feature ticket.
5. **Operational footprint.** New system binaries / sidecars (FreeRDP, guacd) add deploy + supply-chain surface. Prefer a transport that rides the existing websockify-style `ws_url` broker shape.
6. **Honest fallback.** If native RDP is deferred, the UI must surface a clear "RDP not available — use VNC/SSH" state, never a broken SSH form (CTI-005 AC).

## Options considered

### Option A — Guacamole-style WebSocket gateway (`guacd` + guacamole-common-js)

Run Apache Guacamole's `guacd` proxy server-side; it speaks RDP to the target and the Guacamole
protocol over WebSocket to a `guacamole-common-js` client canvas in the browser.

- **Pros**
  - Mature, battle-tested RDP (also VNC/SSH) implementation; full feature set (clipboard, drive redirect, audio).
  - Browser side is a JS canvas client, parallel to noVNC; fits `RemoteDesktopPage`-style rendering.
  - The broker shape maps cleanly onto the VNC scheme: mint a token, hand the FE a `ws_url` (`ws(s)://.../rdp-tunnel?token=...`) + `connect_params`.
- **Cons**
  - Introduces a **new native daemon (`guacd`)** + the Guacamole protocol tunnel servlet/shim — a non-trivial new deploy + supply-chain + ops surface, contrary to the project's dependency-free leanings (cf. PDF writer / receipts avoiding `reportlab`).
  - Connection parameters (host/port/username, and crucially **RDP credentials**) flow through the gateway; secure handling of those (KMS-backed, server-resolved like SSH `stored_key`) is extra work.
  - `guacd` is hard to "mock in dev" in-process; dev parity would need a stub tunnel, diverging from "same code path."
  - Heaviest of the three; does not fit CTI-005's 3-day budget without scope cuts.

### Option B — FreeRDP-to-canvas bridge (custom Python/FreeRDP → framebuffer → WS)

Wrap FreeRDP (e.g. via a Python binding or subprocess) server-side, decode the RDP graphics into
a framebuffer, and stream pixels/updates over a custom WS protocol to a `<canvas>`.

- **Pros**
  - No Java/`guacd`; could live as a Python bridge module beside `vnc_bridge_lifecycle.py`.
  - Full control over the WS protocol shape; can mirror the SSH WS envelope conventions.
- **Cons**
  - **Highest implementation risk by far.** RDP graphics (RemoteFX, NSCodec, bitmap caches, pointer/cursor, input encoding) is a large protocol; a hand-rolled framebuffer bridge is a multi-week effort, not 3 days.
  - FreeRDP is a native dependency (build/security/CVE surface) and awkward to mock in-process for dev parity.
  - Reinvents what Guacamole already does, with worse coverage.
  - Effort wildly exceeds the CTI-005 budget; would block the milestone.

### Option C — Documented "no native RDP — fall back to VNC/SSH + instructions" (recommended)

Ship **no RDP protocol code now.** Add the `RDP_REMOTE_DESKTOP_ENABLED` flag (default **off**),
fix `quick_connect` so RDP no longer routes to the SSH form, and have the FE surface a clear,
actionable fallback: connect via VNC if the Windows host also exposes a VNC/websockify endpoint,
otherwise show copy-ready RDP connection details (host:port, username) + instructions to use a
native RDP client (`mstsc` / Microsoft Remote Desktop / FreeRDP) over the appropriate
tunnel/VPN. Reserve the flag + a stubbed `/api/rdp/session` endpoint shape so a future native
build (Option A) can slot in behind the same broker contract without re-plumbing the FE.

- **Pros**
  - **Fits the CTI-005 3-day budget** and is honest about current capability (CTI-005 AC: "with the RDP flag off, the UI shows a clear unavailable message and no broken connect attempt").
  - **Zero new native dependencies / daemons**; no supply-chain or deploy surface added now.
  - **Trivial, real dev/prod parity** — the fallback path is pure metadata + UI; identical dev and prod.
  - Stops the active bug (Windows hosts dead-ending in the SSH form) immediately.
  - Defines the broker contract (flag, endpoint shape, ownership scoping) so the eventual native build is additive, not a rewrite. Keeps the door open for Option A as a later, separately-budgeted milestone.
- **Cons**
  - No in-browser RDP rendering — users on a Windows host must drop to a native client or use VNC.
  - Defers, rather than solves, the "full parity with SSH/VNC" goal.

## Decision

**Adopt Option C now**, with the broker contract shaped so that **Option A (Guacamole gateway)
is the designated future native path.**

### Rationale

- Options A and B both require a new native server-side component (`guacd` or FreeRDP) that is
  hard to run in-process and therefore hard to keep on the "one code path, dev differs only in
  target URL" SECOPS-007 model the VNC subsystem follows. Neither fits CTI-005's 3-day estimate.
- Option C eliminates the live bug (Windows → broken SSH form) in days, with no new
  dependencies and trivially honest dev/prod parity.
- By reserving `RDP_REMOTE_DESKTOP_ENABLED` and a `/api/rdp/session` contract that **mirrors the
  VNC session/token scheme** (owner-scoped `target_id=user:{host_id}` resolution, single-use
  HS256 token, `connect_params`, idle/max-duration GC), the future native build is a drop-in:
  flip the flag on, resolve the target to a Guacamole tunnel `ws_url` instead of a fallback
  payload, and render with `guacamole-common-js` next to noVNC's `RFB` in `RemoteDesktopPage`.
- If/when native RDP is greenlit, **Option A (Guacamole)** is preferred over B: it is mature,
  covers the protocol fully, and its tunnel-over-WS shape maps onto the existing broker contract,
  whereas a hand-rolled FreeRDP framebuffer bridge (B) is multi-week and high-risk.

## Consequences

- **Immediate:** the active defect (Windows EC2 "Open terminal" → SSH form) is fixed; RDP hosts get a deterministic, non-broken destination.
- **No new runtime dependencies** added now (no `guacd`, no FreeRDP, no Java). The dependency-free posture is preserved.
- **Deferred capability:** no browser-native RDP rendering until a future milestone enables Option A. Users connect to Windows hosts via VNC (if exposed) or a native RDP client per the surfaced instructions.
- **Contract lock-in (intentional):** future native work is constrained to the `RDP_REMOTE_DESKTOP_ENABLED` flag + `/api/rdp/session` broker shape, so the FE deep-link, ownership model, and token scheme don't change when native lands.
- **CTI-007** (EC2 "Open terminal") routes Windows hosts to the RDP fallback surface; **CTI-003** protocol auto-selection (windows→rdp) is honored at the FE resolver. **CTI-009** (unified connect helper) gains a third branch (`rdp → /remote/rdp?host_id=...`).
- **CTI-010 / CTI-011** ownership/regression coverage must include the RDP branch (owner-scoped resolution, flag-off behavior), even though it's a fallback today.

## Security & dev/prod-parity model

Even in the fallback (Option C) shape, the RDP path adopts the VNC security invariants so the
future native build inherits them unchanged:

- **Server-side, owner-scoped resolution only.** RDP targets resolve as `user:{host_id}` via
  `host_inventory.get_host(user_sub, host_id)` (same pattern as VNC `_resolve_target`,
  `app/services/vnc_sessions.py:247-267`). Host/port/username come from the stored record;
  **client-supplied host/port are never trusted** (mirrors CTI-001 for SSH and CTI-002 for VNC).
  A `host_id` owned by another user fails closed (the `Key={user_sub, sk}` access pattern at
  `host_inventory.py:256` returns nothing) → structured `RDP_TARGET_NOT_FOUND` /
  `RDP_AUTH_UNAUTHORIZED`.
- **Single-use, short-lived token (native phase).** Reuse `mint_connect_token` /
  `verify_connect_token` shape: HS256, `aud="rdp-bridge"`, `jti` one-shot consume, `exp` clamped
  to ≤300s. In the fallback phase no live token is minted (there is no live bridge), but the
  endpoint shape reserves `connect_params`.
- **TLS in prod, mock in dev (native phase).** Reuse `_validate_secure_transport` semantics:
  the tunnel `ws_url` must be `wss://` outside dev/test; in dev it points at a local mock tunnel
  (e.g. `RDP_GATEWAY_WS_URL=ws://localhost:6090/rdp-tunnel`), exactly as `VNC_DEMO_WS_URL` works.
  No `dev_mode` branch in the resolution logic — dev parity is achieved purely by target URL +
  the dev TLS short-circuit (`_is_dev_environment`, `vnc_sessions.py:111-113`).
- **Credentials never reach the browser.** As with SSH `stored_key` (KMS-decrypted server-side,
  PEM never sent to the client), any future RDP credential handling resolves server-side via the
  existing KMS abstraction; the browser only ever holds the opaque session token.
- **Idle / max-duration GC + rate limiting + audit** reuse `BridgeLifecycleManager` and the
  `audit_event` / metrics / observability wiring already present in the VNC subsystem.
- **Flag-gated, fail-safe.** With `RDP_REMOTE_DESKTOP_ENABLED=false` (default), the native session
  endpoint returns `503 RDP_FEATURE_DISABLED` (mirroring `_ensure_vnc_feature_enabled`,
  `vnc_sessions.py:167-176`) and the FE shows the fallback/instructions surface — never a broken
  connect attempt.

## New settings / flags

| Flag / env | Default | Purpose |
|---|---|---|
| `RDP_REMOTE_DESKTOP_ENABLED` | `false` | Master gate. `false` → fallback/instructions UI only; the native `/api/rdp/session` endpoint returns `503 RDP_FEATURE_DISABLED`. Mirrors `VNC_FEATURE_ENABLED`. |
| `RDP_GATEWAY_WS_URL` | `ws://localhost:6090/rdp-tunnel` (dev) | Native-phase target tunnel base (Guacamole/guacd). Dev points at a local mock; prod must be `wss://`. Mirrors `VNC_DEMO_WS_URL`. |
| `RDP_SESSION_TOKEN_SECRET` | `dev-rdp-session-secret` (dev) | HS256 signing secret for the connect token. Mirrors `VNC_SESSION_TOKEN_SECRET`. |
| `RDP_SESSION_TOKEN_TTL_SECONDS` | `300` (clamp 60–300) | Connect-token TTL. Mirrors `VNC_SESSION_TOKEN_TTL_SECONDS`. |
| `RDP_SESSION_IDLE_TIMEOUT_SECONDS` | `300` | Idle GC (native phase). Mirrors VNC. |
| `RDP_SESSION_MAX_DURATION_SECONDS` | `3600` | Hard cap (native phase). Mirrors VNC. |
| `RDP_BOOTSTRAP_RATE_LIMIT_COUNT` / `_WINDOW_SECONDS` | `10` / `60` | Per-user bootstrap rate limit. Mirrors VNC. |

All flags read via the same `Settings` (`S`) singleton + env conventions used elsewhere
(frozen `S`, flipped in tests via `object.__setattr__`). Native-phase flags ship dormant in
Option C; only `RDP_REMOTE_DESKTOP_ENABLED` is functionally consumed (to choose
fallback-vs-disabled UX).

## WS protocol shape (native phase, reserved)

Mirror the VNC broker contract so the FE deep-link and renderer are stable across the
fallback→native transition:

1. `POST /api/rdp/session` (cookie auth, `require_ui_session`), body `{ "target_id": "user:{host_id}" }`.
   - On success: `{ session_id, ws_url, connect_params: { token }, created_at, expires_at, capabilities, timeout_policy }` — same envelope as `CreateVncSessionResp` (`app/routers/vnc_sessions.py:46-53`).
   - `ws_url` = the Guacamole tunnel endpoint (`wss://…/rdp-tunnel`); `connect_params.token` = single-use HS256 token verified by the gateway shim.
   - Flag off → `503 RDP_FEATURE_DISABLED`. Foreign/unknown `host_id` → `404 RDP_TARGET_NOT_FOUND` / `403 RDP_AUTH_UNAUTHORIZED`.
2. `DELETE /api/rdp/session/{session_id}` — teardown, owner-scoped (mirrors `vnc_sessions.py:164`).
3. **Browser → gateway WS** speaks the Guacamole tunnel protocol via `guacamole-common-js`
   (canvas), exactly as `RemoteDesktopPage` does noVNC `RFB` over `ws_url + connect_params`
   (`RemoteDesktopPage.tsx:250-253`). No bespoke message envelope is invented — the gateway owns
   the on-the-wire RDP protocol.

For the **fallback phase**, `quick_connect` (and a thin FE resolver) emit
`connect_path = "/remote/rdp?host_id=..."`; `/remote/rdp` renders the instructions surface
(copy-ready host:port/username + native-client guidance, plus a "Connect via VNC" affordance if
the host has a VNC sibling). No session/token is minted.

## High-level implementation plan (mapped to ticket IDs)

**Phase 1 — Option C fallback (this milestone, CTI-005, budgeted 3d):**

1. **CTI-005a** — Add `RDP_REMOTE_DESKTOP_ENABLED` (+ dormant native flags above) to `app/core/settings.py` and `.env.local.example`. *(0.25d)*
2. **CTI-005b** — Fix `quick_connect` (`app/services/host_inventory.py:537-542`): split RDP out of the SSH branch; emit `connect_path = "/remote/rdp?host_id={host_id}"` (carry hostname/port/username metadata, no secrets). *(0.5d)*
3. **CTI-005c** — FE `/remote/rdp` route + a fallback `RemoteRdpPage` (instructions + copy host:port/username; offer VNC fallback when a VNC sibling host exists). With the flag off, this is the only surface; reserve a flag-on branch that will later call `/api/rdp/session`. *(1d)*
4. **CTI-007/CTI-009** — Windows EC2 "Open terminal" + the unified connect resolver route `protocol=="rdp"` → `/remote/rdp?host_id=...` (never `/remote/ssh`). *(0.5d, shared with CTI-007/009)*
5. **CTI-010/CTI-011** — Ownership + flag-state regression tests for the RDP branch: owner-scoped `quick_connect` for an `rdp` host, cross-user `host_id` denied, flag-off UX. Hermetic style per `tests/test_gap_0223_0224_ec2_host_inventory.py` (moto/in-memory DDB bound to frozen `T.host_inventory`, frozen `S` flag flipped via `object.__setattr__`). *(0.5d)*
6. Stop CTI-001 from being the only Windows path: SSH endpoint continues to reject `rdp` hosts with `unsupported_protocol`; the FE now routes them to `/remote/rdp` before reaching the SSH WS. *(covered by 4)*

**Phase 2 — Option A native gateway (FUTURE, separately budgeted ~L, not CTI-005):**

7. Deploy `guacd` + a Guacamole tunnel shim; back the dormant native flags.
8. Implement `app/services/rdp_sessions.py` mirroring `vnc_sessions.py` (resolve `user:{host_id}` owner-scoped, mint/verify single-use token, `BridgeLifecycleManager`, rate limit, audit, metrics) + `app/routers/rdp_sessions.py` (`/api/rdp/session`).
9. FE: add `guacamole-common-js` and a canvas surface in (or beside) `RemoteDesktopPage`; flip the `/remote/rdp` flag-on branch to broker a live session.
10. Extend CTI-010/CTI-011 with native-session token/replay/TLS tests mirroring the VNC suite.

## Effort estimate

- **CTI-005 (Option C fallback, this milestone): ~3 days** — matches the ticket budget (settings + `quick_connect` fix + `/remote/rdp` fallback page + resolver wiring + ownership/flag tests).
- **Future native RDP (Option A, Guacamole): ~L (multi-week)** — `guacd`/tunnel deploy + supply-chain review, backend session service + router, FE Guacamole client canvas, and security/regression tests. Tracked as a separate milestone, unblocked by the contract this ADR fixes.
