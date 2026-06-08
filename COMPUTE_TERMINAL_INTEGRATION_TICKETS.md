# Compute ↔ Remote Terminal Integration — Implementation Tickets

This backlog wires the compute surfaces (EC2 launcher, K8s launcher, instance monitoring) to the remote-terminal surfaces (Browser SSH terminal, VNC remote desktop) so a user can launch an instance and open a prefilled SSH/VNC/RDP terminal to it directly from the instance row/detail — instead of today's disconnected surfaces. Instances already auto-register into host inventory (`app/services/ec2_launcher.py:324-352`, `app/services/k8s_launcher.py:387-409` write `host_id`), but there is no "Open terminal" action on the instance UI, the `/remote/ssh` deep-link target route does not exist, VNC `quick_connect` emits an unresolvable `user:{host_id}` target, and RDP has no real terminal path.

## Milestone 1 — Backend connection resolution

### CTI-001: Server-side host_id → connection-param resolution for the SSH terminal
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Today the Browser SSH terminal accepts `host_id` in the connect payload (`app/routers/browser_ssh_terminal.py:742`) but only uses it post-connect to resolve the per-host recording flag (`app/routers/browser_ssh_terminal.py:1125-1145`). The browser must still supply `host`, `port`, `username` itself — there is no server-side resolution of `host_id` into connection params.
- Add a resolution step in the `connect` handler (`app/routers/browser_ssh_terminal.py:951-995`): when `host_id` is present, load the host via `host_inventory.get_host(user_sub, host_id)` (`app/services/host_inventory.py:254`) and authoritatively derive `host`/`port`/`username` from the stored record, ignoring any client-supplied overrides for those fields (the client may still supply credentials / `keyId`).
- Reject `host_id` values not owned by the caller with a structured `key_not_found`-style error (ownership is enforced by the `Key={user_sub, sk}` access pattern, mirroring the stored-key path at `app/routers/browser_ssh_terminal.py:1015-1032`).
- Only `protocol == "ssh"` hosts are accepted on this WS endpoint; `vnc`/`rdp` hosts must be rejected with a clear error so the FE routes them elsewhere (see CTI-002, CTI-005).

**Acceptance Criteria**
- A `connect` payload with only `{host_id, authType, ...credentials}` connects using the stored hostname/port/username.
- A `host_id` belonging to another user yields a structured error and no connection.
- A `host_id` whose `protocol` is `vnc` or `rdp` yields a structured `unsupported_protocol` error.
- Client-supplied `host`/`port` are ignored when a valid `host_id` is present.

**Dependencies**
- None.

---

### CTI-002: Resolve inventory-backed VNC targets (`user:{host_id}`) — replace hardcoded targets
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- `host_inventory.quick_connect` already emits `target_id = "user:{host_id}"` and `connect_path = "/remote?target_id=user:{host_id}"` for VNC hosts (`app/services/host_inventory.py:532-536`), but `vnc_sessions._resolve_target` only knows the hardcoded `demo` / `ops-admin` targets (`app/services/vnc_sessions.py:200-247`). A `user:`-prefixed target therefore 404s with `VNC_TARGET_NOT_FOUND`.
- Extend `_resolve_target` (`app/services/vnc_sessions.py:237`) so that when `target_id` starts with `user:`, it loads the host via `host_inventory.get_host(user_sub, host_id)` and builds a `TargetConfig` dynamically: `ws_url` from `ws://{hostname}:{port}/websockify` (matching `quick_connect`'s shape at `host_inventory.py:535`), `allowed_users=(user_sub,)` so only the owner connects, and default capabilities.
- Thread `user_sub` into `_resolve_target` / the session-create path (`app/services/vnc_sessions.py:414`, `:518`) so ownership can be enforced via `_ensure_authorized` (`app/services/vnc_sessions.py:254-269`).
- Keep the static `demo`/`ops-admin` targets working unchanged (backward compatible).

**Acceptance Criteria**
- Creating a VNC session with `target_id=user:{host_id}` for an owned VNC host succeeds and resolves the correct `ws_url`.
- A `user:{host_id}` for a host owned by another user is rejected via the existing authorization path (`VNC_AUTH_UNAUTHORIZED`).
- The legacy `demo` and `ops-admin` targets still resolve and authorize exactly as before.

**Dependencies**
- None.

---

### CTI-003: Protocol/port auto-selection parity check for launched instances
**Type:** Chore  
**Priority:** P1  
**Estimate:** 0.5 day

**Description**
- EC2 launch already derives protocol/port from the AMI `os_type` (`app/services/ec2_launcher.py:328-329`: windows → `rdp`/3389, else `ssh`/22, from `AMIS` at `app/services/ec2_launcher.py:57-62`) and writes it onto the host record. K8s pods always register as `ssh`/22 (`app/services/k8s_launcher.py:391-392`).
- Confirm `quick_connect` (`app/services/host_inventory.py:519`) and the new resolution paths (CTI-001, CTI-002, CTI-005) honor the stored protocol so a Windows EC2 host routes to RDP and a Linux host to SSH automatically, with no client protocol selection required.
- Document the auto-selection mapping in `docs/file-reference.md` / the host-inventory ticket so future AMIs/images inherit it.

**Acceptance Criteria**
- A Windows AMI EC2 host resolves to `protocol=rdp`, `port=3389`; a Linux AMI to `protocol=ssh`, `port=22`; a K8s pod to `protocol=ssh`, `port=22`.
- No regression test relies on the client choosing protocol for a `host_id`-backed connect.
- Mapping is documented in one canonical place.

**Dependencies**
- CTI-001, CTI-002.

---

## Milestone 2 — RDP path

### CTI-004: Spike — RDP terminal transport (bridge/gateway) decision
**Type:** Spike  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- RDP is accepted as a host protocol everywhere (`app/services/host_inventory.py:54` `VALID_PROTOCOLS`, `app/models.py:13398`, FE `HostProtocol` at `frontend/src/api/types.ts:11692`) and EC2 Windows instances register as `rdp` (`app/services/ec2_launcher.py:328`), but there is NO actual RDP terminal: `quick_connect` shoves RDP into the SSH connect form (`app/services/host_inventory.py:537-542`, comment "SSH/RDP: frontend pre-fills the terminal connect form"), which cannot speak RDP. The roadmap flags this gap (`docs/feature-roadmap.md:68`).
- Evaluate a browser RDP transport: a Guacamole-style WebSocket gateway vs. an FreeRDP-to-canvas bridge vs. a documented "no native RDP, fall back to VNC/instructions" stance. Mirror the dev/prod parity model used by the SSH/VNC bridges (mock in dev, real in prod — SECOPS-007).
- Produce a short ADR recommending one option, the new env flag (e.g. `RDP_REMOTE_DESKTOP_ENABLED`), and the WS protocol shape (reuse the VNC session/token pattern in `app/services/vnc_sessions.py:298-373` where possible).

**Acceptance Criteria**
- ADR committed under `docs/` covering transport choice, security model, dev/prod parity, and effort estimate for CTI-005.
- Decision explicitly states the fallback behavior if native RDP is deferred.

**Dependencies**
- None.

---

### CTI-005: RDP connect path (or explicit fallback) wired to `host_id`
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Implement the transport chosen in CTI-004. If native RDP: add a backend session/token endpoint (reusing the VNC token scheme at `app/services/vnc_sessions.py:298`) and a FE RDP canvas surface, resolving the target from `host_id` (ownership-checked like CTI-002).
- Fix `quick_connect` so RDP no longer falls into the SSH form (`app/services/host_inventory.py:537-542`): emit a dedicated `connect_path` (e.g. `/remote/rdp?host_id=...` or a VNC-fallback path) instead of `/remote/ssh?...`.
- Gate behind the new feature flag; when disabled, surface a clear "RDP not available — use VNC/SSH" message rather than a broken SSH form.

**Acceptance Criteria**
- A Windows EC2 host's "Open terminal" routes to the RDP surface (or documented fallback), never to the SSH connect form.
- With the RDP flag off, the UI shows a clear unavailable message and no broken connect attempt.
- RDP connections enforce host ownership identically to SSH/VNC.

**Dependencies**
- CTI-004, CTI-001.

---

## Milestone 3 — Frontend deep-link + unified Connect UX

### CTI-006: Build the Browser SSH terminal page (xterm) + the missing `/remote/ssh` route
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- ⚠️ **(Verified 2026-06-08) The Browser SSH terminal FRONTEND was never built.** The backend WS is live (`app/routers/browser_ssh_terminal.py:800` `@router.websocket("/ws")`, prefix `/api/browser-ssh`) and there are SSH key-manager / recordings / bastion pages + a recording *player* (`SshRecordingPlayer.tsx`), but there is **no interactive terminal**: no `xterm`/`@xterm/xterm` dependency in `frontend/package.json` (or any branch), no `*Terminal*.tsx`, no `new Terminal(`/`FitAddon`/`.onData(` usage. The xterm terminal was only ever *planned* (ticket `SSH-003` "xterm.js terminal component + resize fit" in `SSH_BROWSER_TERMINAL_TICKETS.md`). So this is a build, not a route one-liner.
- Implement `SSH-003`/`SSH-005`: add `@xterm/xterm` + `@xterm/addon-fit`, create a `RemoteSshTerminalPage` that opens a WebSocket to `/api/browser-ssh/ws`, speaks the connect/input/resize/output/status/error protocol (`browser_ssh_terminal.py:42-53`), and renders an xterm view with the fit addon (PTY `xterm-256color`, propagate resize).
- Read `host`, `port`, `username`, and `host_id` from `useSearchParams` and prefill the connect form; when `host_id` is present, send it in the connect payload so the server resolves params authoritatively (CTI-001).
- Add the `remote/ssh` route to `frontend/src/App.tsx` (~line 376-386) behind the same auth shell as the other `remote/*` routes. Today `quick_connect`/HostInventoryPage navigate to `/remote/ssh?...` (`app/services/host_inventory.py:542`; `frontend/src/pages/remote/HostInventoryPage.tsx:398-406`) but **no such route exists** (only `remote/ssh-keys` at line 377) → the deep-link 404s.

**Acceptance Criteria**
- A live xterm terminal connects to `/api/browser-ssh/ws`, accepts keyboard input, and resizes (fit addon → resize event).
- Navigating to `/remote/ssh?host_id=...` (or `?host=&port=&username=`) loads the terminal with the form prefilled.
- Clicking "Connect" in HostInventoryPage for an SSH host opens a working terminal (no 404).

**Dependencies**
- CTI-001.

---

### CTI-007: "Open terminal" action on EC2 instance rows + detail
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- `Ec2LauncherPage.tsx` renders running instances with Stop/Reboot/Terminate actions (`frontend/src/pages/remote/Ec2LauncherPage.tsx:207-230` row, public IP at `:212`) but has NO connect action. The `Ec2InstanceOut` type carries `host_id` and `public_ip` (`frontend/src/api/types.ts:5709-5710`, used by `frontend/src/api/endpoints/ec2.ts`).
- Add an "Open terminal" / "Connect" button to each running EC2 row (and the monitoring detail page `frontend/src/pages/remote/InstanceMonitoringPage.tsx`) that deep-links by `host_id`: SSH hosts → `/remote/ssh?host_id=...` (CTI-006), VNC → `/remote?target_id=user:{host_id}` (CTI-002), RDP → the CTI-005 path. Protocol is auto-selected from the host record (CTI-003), so the button can derive the destination from the instance's `host_id` host lookup or a thin resolver.
- Disable/hide the button when the instance is not `running` or has no `host_id` yet (e.g., no public IP at launch — `host_id` is only written when `public_ip` is non-empty, `app/services/ec2_launcher.py:324`).

**Acceptance Criteria**
- A running Linux EC2 instance shows "Open terminal" that opens a prefilled SSH terminal.
- A running Windows EC2 instance opens the RDP surface (or fallback per CTI-005).
- The action is disabled for non-running instances and instances without a `host_id`.

**Dependencies**
- CTI-006, CTI-002, CTI-003.

---

### CTI-008: "Open terminal" action on K8s pod rows + detail
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1.5 days

**Description**
- K8s pods register as SSH hosts with `host_id` + `service_hostname` + `ssh_port` (`frontend/src/api/types.ts:5601-5604`; `app/services/k8s_launcher.py:387-406`), but `K8sLauncherPage.tsx` has no connect action.
- Add an "Open terminal" button to each running pod row in `frontend/src/pages/remote/K8sLauncherPage.tsx` that deep-links to `/remote/ssh?host_id=...` (pods are always SSH, `app/services/k8s_launcher.py:391`).
- Disable when the pod is not running or has no `host_id`.

**Acceptance Criteria**
- A running pod shows "Open terminal" that opens a prefilled SSH terminal to the pod's service hostname/port.
- The action is disabled for non-running pods or pods without a `host_id`.

**Dependencies**
- CTI-006.

---

### CTI-009: Unified "Connect" component/resolver shared across compute + remote
**Type:** Chore  
**Priority:** P1  
**Estimate:** 1.5 days

**Description**
- The SSH (`/remote/ssh`), VNC (`/remote?target_id=...`), and RDP destinations are derived in at least three places: `host_inventory.quick_connect` (`app/services/host_inventory.py:519-542`), HostInventoryPage's `quickConnectMut` (`frontend/src/pages/remote/HostInventoryPage.tsx:398-406`), and the new EC2/K8s buttons (CTI-007/008). Extract a single FE helper (e.g. `connectPathForHost(host)` / `<OpenTerminalButton host_id protocol />`) so all surfaces produce identical, protocol-correct links.
- Reuse the helper in HostInventoryPage, Ec2LauncherPage, K8sLauncherPage, and InstanceMonitoringPage so the "Connect" UX (label, icon, disabled rules, protocol routing) is consistent.

**Acceptance Criteria**
- One shared FE helper/component produces all SSH/VNC/RDP connect links.
- HostInventoryPage, EC2, and K8s pages all use it; removing it breaks all four surfaces (proves single source of truth).
- Connect UX (icon, label, disabled state) is visually consistent across surfaces.

**Dependencies**
- CTI-006, CTI-007, CTI-008.

---

## Milestone 4 — Security & tests

### CTI-010: Ownership / permission enforcement audit across connect paths
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Verify that every connect entry point enforces host ownership server-side and never trusts client-supplied identity: SSH `host_id` resolution (CTI-001), VNC `user:{host_id}` (CTI-002, via `_ensure_authorized` at `app/services/vnc_sessions.py:254-269`), and RDP (CTI-005). The terminal WS already authorizes the session (`app/routers/browser_ssh_terminal.py:806` `_authorize_terminal_access`); host resolution must additionally scope to the authenticated `user_sub` via the `Key={user_sub, sk}` access pattern (`app/services/host_inventory.py:256`).
- Confirm `host_id` from another user, or a `host_id` referencing a stale/terminated instance, fails closed with a structured error (mirroring the stored-key `key_not_found` handling).
- Confirm the destination-policy guard (`app/routers/browser_ssh_terminal.py:996` `_enforce_destination_policy`) still runs after server-side host resolution.

**Acceptance Criteria**
- Cross-user `host_id` / `user:{host_id}` connect attempts are denied on every protocol path.
- Server-resolved host/port is still subject to the existing destination policy.
- No connect path can be driven to an arbitrary host/port via client overrides when `host_id` is supplied.

**Dependencies**
- CTI-001, CTI-002, CTI-005.

---

### CTI-011: Backend regression tests — host resolution, VNC inventory targets, ownership
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1.5 days

**Description**
- Add offline/hermetic pytest coverage mirroring the existing INFRA test style (e.g. `tests/test_gap_0223_0224_ec2_host_inventory.py`, `tests/test_gap_0233_0234_ssh_session_recording.py`): moto/in-memory DDB bound to the frozen `T.host_inventory` handle, `ParamikoSshBridge` stubbed, WS handler driven on a fresh `asyncio` loop.
- Cover: SSH connect resolves params from `host_id` (CTI-001); cross-user `host_id` denied (CTI-010); VNC `user:{host_id}` resolves and authorizes the owner / rejects non-owner (CTI-002); protocol auto-selection (windows→rdp, linux→ssh) from a launched-instance host record (CTI-003); RDP path or fallback (CTI-005).

**Acceptance Criteria**
- New test file(s) pass offline with no real AWS/SSH/network.
- Each acceptance criterion of CTI-001/002/003/005/010 has at least one assertion.
- Tests run under `just test`.

**Dependencies**
- CTI-001, CTI-002, CTI-003, CTI-005, CTI-010.

---

### CTI-012: E2E tests — deep-link & "Open terminal" from compute UI
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add a Playwright spec (new section, following `frontend/e2e/` conventions in CLAUDE.md) that launches/seeds an EC2 instance and a K8s pod, then drives the new "Open terminal" buttons (CTI-007, CTI-008) and asserts the deep-linked terminal/VNC surface loads with prefilled host/port/username.
- Cover the `/remote/ssh?host_id=...` route loading prefilled (CTI-006), the protocol routing (Linux→SSH, Windows→RDP/fallback), and the disabled-state rules (non-running / no `host_id`).
- Seed instance records directly via DynamoDB where launch is awkward in E2E (pattern per CLAUDE.md "Stripe mock … seed … directly via DynamoDB").

**Acceptance Criteria**
- E2E spec passes under `just e2e` (1 worker, Chromium).
- Asserts prefilled fields and correct protocol surface for at least one Linux and one Windows/RDP path.
- Asserts the button is disabled for a non-running instance.

**Dependencies**
- CTI-006, CTI-007, CTI-008.

---
