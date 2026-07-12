# ADR-002: Interactive Registered Claude Code Sessions via PTY-Wrapped CLI and Two-Way Terminal Wiring

- **Status:** Proposed
- **Date:** 2026-06-09
- **Tickets:** ACS-001 … ACS-012 (`AGENT_CLAUDE_CODE_SESSION_TICKETS.md`)
- **Owners:** Agents Platform, Terminal/Remote Access

## Context

Today an agent worker is *durable compute + an installed CLI tool + an LLM key*, but the `claude` CLI is only ever run **headless** by job scripts — there is no long-lived interactive process a human can drive. The pieces that exist:

- **Worker provisioner** (`app/services/agent_worker_provisioner.py`): `create_worker` (`:205-250`) writes a DDB item under `pk=USER#{user_id}`, `sk=WORKER#{worker_id}` with `worker_status`, `compute_instance_id`, `public_ip`, `host_id`, `llm_key_id`/`llm_provider`. In dev (`S.dev_mode`) provisioning completes synchronously and instantly (`_provision_worker_dev`, `:247-248`, `:253-331`). `claude` is installed via `TOOL_INSTALL_SCRIPTS["claude_code"]` whose `env_var` is `ANTHROPIC_API_KEY` (`:34-44`). Ownership is enforced structurally because the PK is `USER#{user_id}` (`get_worker_raw`, `:334-339`); `stop_worker`/`terminate_worker` reject illegal state transitions (`:376-383`).
- **Browser SSH terminal** (`app/routers/browser_ssh_terminal.py`): a single WebSocket endpoint `@router.websocket("/ws")` (`:836-837`) implementing Protocol v1 `{type, payload}` with client `connect`/`input`/`resize` and server `status`/`output`/`error` (`:42-53`). `ParamikoSshBridge` exposes the canonical bridge surface `poll_output` / `send_input` / `resize` / `close` (`:167-202`). The loop polls `ssh_bridge.poll_output()` and forwards `output` to the browser (`:899-903`); browser `input` calls `ssh_bridge.send_input(...)` (`:1255-1257`). Auth is cookie/role via `_authorize_terminal_access` (`:233-280`, role-gated by `BROWSER_SSH_TERMINAL_ALLOWED_ROLES`); connect rate-limit and per-user concurrent-session caps come from `_consume_connect_rate_limit` (`:359`), `_try_acquire_user_session_slot`/`_release_user_session_slot` (`:333-357`); stored-key PEM is resolved server-side via `get_decrypted_private_key` and never sent to the browser (`:1046-1068`), with `_redact_connect_payload` (`:591`) keeping secrets out of logs.
- **The one-way tap (the crux).** When the Worker Fleet UI opens an *agent-tracked* SSH terminal it includes a `worker_id` in the connect payload (`:999-1003`). The loop then feeds bridge **output** into `terminal_monitor.process_terminal_output(worker_id, output)` and dispatches signals via `_dispatch_terminal_signal` (`:927-937`). That dispatcher (`:782-833`) turns a `feedback_needed` signal into a `terminal_monitor.create_feedback_request` plus a browser `feedback_request` message; `complete`/`error` map to `agent_complete`/`agent_error`. **But there is no Claude process behind this stream** — for an agent session, browser `input` has nothing meaningful to drive. The wiring is effectively **output-only**.
- **Terminal monitor** (`app/services/terminal_monitor.py`): ring buffer per `worker_id` (`get_or_create_buffer`, `process_terminal_output` `:232-257`), `DEFAULT_PATTERNS` / `DEFAULT_FEEDBACK_PATTERNS` (`:55-84`) including `[AGENT_FEEDBACK_NEEDED]`, feedback CRUD (`create_feedback_request` `:263`, `respond_to_feedback` `:326-381`, which appends `[User response]: …` back into the buffer).
- **REST + flags.** Worker CRUD lives on `app/routers/agent_workers.py` (`prefix=/ui/agent/workers`, all `Depends(require_ui_session)`). `S.browser_ssh_terminal_enabled` and friends live in `app/core/settings.py:124-134`. There is currently **no SSH-terminal frontend** — the agent terminal would be net-new xterm.js wiring (remote pages live under `frontend/src/pages/remote/`).

**The shift this ADR decides:** reverse the agent-terminal wiring from one-way (output → monitor) to **two-way** (browser input → a real PTY-wrapped `claude` CLI on the worker), while *preserving the monitor tap*, adding a first-class session state model, and shipping a dedicated agent-terminal frontend distinct from raw SSH.

## Decision drivers

1. **Reuse over reinvention.** The bridge surface, Protocol v1 envelope, auth, rate-limit, and monitor tap already exist and are battle-tested. Maximize reuse; minimize new attack surface.
2. **SECOPS-007 dev/prod parity.** One code path for dev and prod, forked only at the *bridge construction* boundary (mock PTY vs real SSH-to-worker), never branching the protocol, auth, or monitor logic on `S.dev_mode`.
3. **Secret containment.** The LLM key must be resolved server-side and never reach the browser or logs — identical to the stored-key PEM handling at `:1046-1068`.
4. **Session ≠ WS connection.** A user must be able to detach (close the tab) and reattach without killing the live `claude` process — unlike raw SSH which closes the bridge unconditionally in `finally` (`:1356-1357`).
5. **Monitor continuity.** Signal detection / feedback creation must keep working whether or not a human is watching.
6. **Hermetic, offline tests.** Mirror the established pattern (frozen `T`/`S` via `object.__setattr__`, stubbed Paramiko/PTY, WS handler on a fresh asyncio loop).

## Options considered

### Option A — Extend the existing `/ws` SSH endpoint with a `worker_id`-only connect mode
Add a branch to `browser_ssh_terminal_ws` so a connect carrying `worker_id` (and no host/port/auth) builds a Claude PTY bridge instead of `ParamikoSshBridge`.

- **Pros:** Maximum reuse — auth, rate-limit, monitor tap, loop, resize all inherited for free; smallest diff.
- **Cons:** Conflates two protocols in one ~600-line handler; `_validate_connect_payload` already allowlists SSH auth types and would need a second shape; raw-SSH regression risk is high; session-survives-detach semantics collide with the unconditional `finally` close; harder to reason about security review. Violates driver #4 cleanly.

### Option B — Dedicated agent-session WS endpoint + a Claude PTY bridge that reuses the bridge *surface* and helpers
New endpoint `/api/agent-session/ws` in its own router (peer to `browser_ssh_terminal_ws`). New `ClaudeCodePtyBridge` mirroring the `poll_output/send_input/resize/close` surface, constructed via a factory that forks on `S.dev_mode` (mock PTY in dev, real SSH-to-worker + PTY in prod). The agent loop reuses the monitor tap and the input→`send_input` call verbatim but adds: session state model, detach-without-kill, reattach+replay, and a process-local bridge registry. Auth/rate-limit/redaction helpers are imported and reused.

- **Pros:** Clean separation (raw SSH untouched → regression-safe, driver #5); session lifecycle decoupled from WS (driver #4); reuses every security-relevant helper; one protocol per endpoint; matches the ticket decomposition 1:1.
- **Cons:** Some duplication of the loop scaffolding; a process-local registry only works under single-worker uvicorn (already the dev/prod constraint per CLAUDE.md, `--workers 1`).

### Option C — Run an out-of-band PTY supervisor process per worker (e.g. tmux/agent daemon on the worker), WS only attaches
Push the PTY lifetime entirely onto the worker (a supervisor owns `claude`); the backend WS is a thin attach/detach proxy.

- **Pros:** Truest "session survives everything" model; survives backend restarts; natural multi-attach.
- **Cons:** Large new surface (a worker-side daemon, its own protocol, install/version management, health); the monitor tap would have to move or duplicate; far more than the ~22 estimated days; no parity story for dev mock. Over-engineered for the current single-uvicorn deployment.

## Decision

**Adopt Option B.** Build a dedicated agent-session WebSocket endpoint and a `ClaudeCodePtyBridge` that mirrors the existing bridge surface, reusing the auth/rate-limit/redaction/monitor helpers while keeping the raw SSH `/ws` path untouched. Fork dev vs prod **only** at bridge construction (mock PTY echo bridge vs real SSH-to-worker PTY), never in the protocol, auth, or monitor logic.

**Rationale.** Option B is the only one that simultaneously satisfies regression safety for raw SSH (driver #5), session-survives-detach (driver #4), secret containment by reusing the proven server-side key-resolution pattern (driver #3), and SECOPS-007 parity with a single forked construction point (driver #2). It reuses ~all security-relevant helpers (driver #1) and maps cleanly onto the existing ACS ticket decomposition. Option A is cheaper but pollutes a security-sensitive handler and fights the detach semantics; Option C is correct in the limit but unjustified for a single-worker uvicorn deployment and blows the effort budget.

## Consequences

**Positive**
- Raw SSH `/ws` is byte-for-byte unchanged → existing regression tests stay green.
- The monitor tap, feedback pipeline, and `_dispatch_terminal_signal` are reused as-is; signal detection works with or without a viewer.
- Sessions become first-class, queryable objects with a state machine the UI can render.
- Secret-handling reuses the audited stored-key pattern — no new key-exposure paths.

**Negative / trade-offs**
- A process-local bridge registry (`{session_id → bridge}`) ties session liveness to a single uvicorn process; a backend restart drops live PTYs (acceptable: matches today's `_ACTIVE_SSH_SESSIONS_BY_USER` model at `:37`, and reattach simply restarts the CLI). Multi-worker scale-out is explicitly out of scope and would require Option C later.
- Some loop scaffolding is duplicated between the two endpoints; mitigated by extracting shared helpers (auth, rate-limit, timeout, redaction) rather than copying them.
- Detach-without-kill introduces an idle/abandoned-session reaper requirement (a session with no attached WS still consumes a PTY + LLM tokens) — handled by an idle timeout that ends the session and closes the bridge.

## Security & dev/prod-parity model

- **Authorization & ownership.** Reuse `_authorize_terminal_access` (cookie/role, `:233-280`) gated behind the new `AGENT_CLAUDE_CODE_SESSION_ENABLED` flag. After auth, enforce that `user_sub` **owns** `worker_id` via `get_worker_raw(user_sub, worker_id)` (PK is `USER#{user_id}`, `:336-338`) — a foreign/unknown worker yields a structured `forbidden`/`not_found` error before any bridge is built; a reattach to a `session_id` must verify the session belongs to that user+worker, never attaching to another user's PTY.
- **Secret containment.** The connect payload is `{worker_id, session_id?, cols, rows}` — **no host/port/auth/key fields**. The LLM key is resolved server-side via `llm_provider_keys.get_key` (decrypted form), injected as the CLI env var (`TOOL_INSTALL_SCRIPTS["claude_code"]["env_var"]` = `ANTHROPIC_API_KEY`), and **never** placed in any browser-bound message or log — identical principle to the stored-key PEM resolution at `:1046-1068` and redaction at `_redact_connect_payload` (`:591`). Worker SSH auth (how the launcher reaches the worker's compute) reuses `ssh_key_manager.get_decrypted_private_key` over the worker's `host_id`/`public_ip`; the PEM stays server-side.
- **Rate-limit & caps.** Reuse `_consume_connect_rate_limit` and the user session-slot helpers (`:333-359`) verbatim, so abuse limits are shared across SSH and agent sessions.
- **Audit.** Emit `audit_event` on start / attach / detach / stop (same call sites/style as `:264`, `:1376-1385`).
- **Parity (SECOPS-007).** The **only** dev/prod fork is the bridge factory: `S.dev_mode` → a mock PTY bridge that echoes input and emits scripted Claude-style output (including an `[AGENT_FEEDBACK_NEEDED]` line so the monitor + feedback path is exercised offline); prod → a real SSH-to-worker PTY bridge. Protocol, auth, ownership, rate-limit, monitor tap, state machine, and DDB access are a single shared code path in both environments — no `dev_mode` branches in any of those.

## New settings / flags

| Setting (env) | Default | Purpose |
|---|---|---|
| `AGENT_CLAUDE_CODE_SESSION_ENABLED` | `false` | Master gate for the feature; mirrors `browser_ssh_terminal_enabled` (`settings.py:124`). |
| `AGENT_CLAUDE_CODE_SESSION_ALLOWED_ROLES` | `admin,root` | Role allowlist; mirrors `BROWSER_SSH_TERMINAL_ALLOWED_ROLES`. |
| `AGENT_CLAUDE_CODE_SESSION_MAX_PER_USER` | `2` | Concurrent-session cap (reuses slot helpers). |
| `AGENT_CLAUDE_CODE_SESSION_IDLE_TIMEOUT_SECONDS` | `1800` | Reaper for detached/abandoned sessions (close PTY, end session). |
| `AGENT_CLAUDE_CODE_SESSION_REPLAY_BYTES` | `65536` | Bounded scrollback replayed on reattach (reuses the monitor ring buffer). |

Connect rate-limit reuses the existing `BROWSER_SSH_CONNECT_RATE_LIMIT_*` knobs unless a session-specific override proves necessary.

## High-level implementation plan (mapped to tickets)

- **ACS-001** — Add `S.agent_claude_code_session_enabled` (env `AGENT_CLAUDE_CODE_SESSION_ENABLED`, default `false`) to `app/core/settings.py`. Add an `agent_sessions` `TableDef` to `scripts/local-ddb-init.py` (PK `pk=USER#{user_id}`, SK `sk=SESSION#{session_id}`, `ByWorker` GSI on `worker_id`; declare numeric GSI sort keys with `attr_types` per the repo gotcha). Add `T.agent_sessions` to `app/core/tables.py`.
- **ACS-002** — New `app/services/agent_session_manager.py`: session record + state enum `starting → ready → awaiting_input ⇆ running → ended` (+ `error`); `create_session`/`get_session`/`list_sessions_for_worker`/`transition_state`/`end_session`; coerce `Decimal` like `_item_to_worker` (`provisioner:107-123`); validate worker exists and is `ready`/`running` via `get_worker_raw`; reject illegal transitions with `ValueError` like `stop_worker` (`:381-383`).
- **ACS-003** — `ClaudeCodePtyBridge` mirroring the `ParamikoSshBridge` surface (`:167-202`): real path opens a Paramiko channel to the worker (`public_ip`/`host_id`) and starts `env ANTHROPIC_API_KEY=… claude` under a PTY; key from `llm_provider_keys.get_key`; worker SSH auth via `get_decrypted_private_key`. Dev path = mock echo+scripted bridge emitting an `[AGENT_FEEDBACK_NEEDED]` line. Bridge factory is the single `S.dev_mode` fork point.
- **ACS-004** — New endpoint `/api/agent-session/ws` (own router). Reuse Protocol v1; connect payload `{worker_id, session_id?, cols, rows}`. Reject raw-SSH host/port payloads with a structured error. Emit `status {phase:"ready"/"connected"}`.
- **ACS-005** — *The one-way → two-way change.* In the agent loop: (a) `bridge.poll_output()` → send `output` to browser **and** feed `terminal_monitor.process_terminal_output(session.worker_id, output)` + `_dispatch_terminal_signal` (preserve `:927-937`); (b) browser `input` → `bridge.send_input(payload["data"])` (the same call as `:1255-1257`, now driving the Claude PTY). Document the `respond_to_feedback` interaction (`:359-381`) to avoid double-injecting buffer context.
- **ACS-006** — Decouple session from WS: starting creates the bridge server-side; **detach** (WS close) must **not** close the bridge (unlike `:1356-1357`); reattach re-binds the live bridge and replays a bounded scrollback (`get_or_create_buffer`, `terminal_monitor:246`). Explicit **stop** terminates CLI+bridge → `ended`; `stop_worker`/`terminate_worker` (`provisioner:376-444`) also end live sessions. Hold bridges in a process-local registry keyed by `session_id` (analogous to `_ACTIVE_SSH_SESSIONS_BY_USER`, `:37`).
- **ACS-007** — Reuse `_authorize_terminal_access`, enforce worker ownership, reuse `_consume_connect_rate_limit` + session-slot helpers, audit start/attach/stop.
- **ACS-008** — Map monitor signals to state: `feedback_needed → awaiting_input`; new input/output → `running`; `complete`/`error → ended`/`error`, driven via `transition_state` from the loop where `_dispatch_terminal_signal` fires.
- **ACS-009** — Nested REST routes under `/ui/agent/workers/{worker_id}/sessions` (`POST`/`GET`/`GET {id}`/`POST {id}/stop`), all `Depends(require_ui_session)`. Add `SessionOut`/`CreateSessionIn`/`SessionListOut` to `app/models.py` + TS types + `frontend/src/api/endpoints/agentSessions.ts`.
- **ACS-010** — Net-new xterm.js agent-terminal page (distinct from raw SSH): no host/port/auth form — pick a worker, "Open Claude Session". Surface the state badge (incl. `awaiting_input`), handle `feedback_request`, detach on tab close, offer Stop/Reconnect; launch from `WorkersPage.tsx`; route in `App.tsx`.
- **ACS-011 / ACS-012** — Hermetic backend tests (`tests/test_agent_claude_code_session.py`, mirroring `test_gap_0233_0234_ssh_session_recording.py`: frozen `T`/`S` via `object.__setattr__`, stubbed PTY, WS on a fresh asyncio loop) including an explicit **before (output-only) vs after (bidirectional)** assertion; plus an E2E spec against the dev mock bridge.

## Effort estimate

Sum of the ticket estimates: **~22 engineer-days** (ACS-001 1, ACS-002 2, ACS-003 3, ACS-004 2, ACS-005 2, ACS-006 2, ACS-007 1, ACS-008 1, ACS-009 1, ACS-010 3, ACS-011 2, ACS-012 1). Critical path runs ACS-001 → 002 → 003 → 004 → 005 → 006 → 008 (backend), with ACS-007 parallelizable and ACS-009/010 (REST+UI) plus ACS-011/012 (tests) trailing. Realistic calendar with one engineer and review overhead: **~4–5 weeks**.
