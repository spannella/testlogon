# Claude Code Session Terminal (Agents) — Implementation Tickets

This backlog turns an agent worker from "a headless CLI driven by job scripts + an API key" into a **registered, interactive Claude Code session** the user drives live through a dedicated browser terminal (peer to the Browser SSH/VNC terminals), while still feeding `terminal_monitor` for signal detection. The core technical shift is reversing the agent-terminal WebSocket wiring from **output-only** (today, browser output is tapped INTO `terminal_monitor` at `app/routers/browser_ssh_terminal.py:887-901`, with no agent-CLI process to receive input) to **two-way** (browser `input` reaches a PTY-wrapped `claude` CLI on the worker's compute) so a human can type into the session.

## Milestone 1 — Session model & lifecycle backend

### ACS-001: Feature flag, settings, and DDB table for Claude Code sessions
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `AGENT_CLAUDE_CODE_SESSION_ENABLED` setting to `app/core/settings.py` (singleton `S`), defaulting `false`, mirroring `browser_ssh_terminal_enabled` (`app/routers/browser_ssh_terminal.py:219-223`).
- Add a single-table `agent_sessions` `TableDef` to `scripts/local-ddb-init.py`: PK `pk=USER#{user_id}`, SK `sk=SESSION#{session_id}`, plus a `ByWorker` GSI (`pk`, `worker_id`) — declare any numeric sort keys with `attr_types` per the repo gotcha.
- Add table handle `T.agent_sessions` to `app/core/tables.py`.
- A "Claude Code session" is distinct from the AGENT-002 worker (`app/services/agent_worker_provisioner.py:210-238`): a worker is durable compute+tool+key; a session is one interactive `claude` PTY attached to that worker.

**Acceptance Criteria**
- `S.agent_claude_code_session_enabled` resolves from env and defaults `false`.
- `just restart` creates the `agent_sessions` table with the `ByWorker` GSI; querying by `worker_id` returns sessions without a `ValidationException`.
- `T.agent_sessions` is importable and usable in a unit test.

**Dependencies**
- None.

---

### ACS-002: Session state machine + service CRUD
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Create `app/services/agent_session_manager.py` defining the session record (`session_id`, `worker_id`, `user_id`, `state`, `created_at`, `started_at`, `ended_at`, `last_activity_at`, `cols`, `rows`, `claude_pid`, `error_message`) and a state enum: `starting → ready → awaiting_input ⇆ running → ended` (plus `error`).
- Implement `create_session`, `get_session`, `list_sessions_for_worker`, `transition_state`, `end_session`, coercing `Decimal` like `_item_to_worker` (`app/services/agent_worker_provisioner.py:107-123`).
- Validate the worker exists and is `ready`/`running` via `get_worker_raw` (`app/services/agent_worker_provisioner.py:334-339`) before allowing session creation; reject illegal transitions (e.g. `ended → running`) the way `stop_worker`/`start_worker` reject bad states (`app/services/agent_worker_provisioner.py:381-383`).
- `transition_state` to `awaiting_input`/`running` is driven later by `terminal_monitor` signals (ACS-008) and by browser input — no orchestrator coupling required for the interactive path.

**Acceptance Criteria**
- Creating a session against a non-existent or terminated worker raises a typed error.
- Legal transitions succeed; illegal ones raise `ValueError`; unit tests cover the full state table.
- `list_sessions_for_worker` returns sessions newest-first.

**Dependencies**
- ACS-001.

---

### ACS-003: PTY-wrap the claude-code CLI on the worker's compute
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Today `claude` is installed on the worker (`TOOL_INSTALL_SCRIPTS["claude_code"]`, `app/services/agent_worker_provisioner.py:34-44`) but only ever run headless by job scripts — there is no long-lived interactive process. Add a server-side launcher that starts `claude` under a PTY on the worker's compute and exposes `poll_output` / `send_input` / `resize` / `close`, mirroring the `ParamikoSshBridge` surface (`app/routers/browser_ssh_terminal.py:167-202`).
- Reach the worker's compute over SSH using the worker's `public_ip` / `host_id` (`app/services/agent_worker_provisioner.py:224-225`, back-written at `:293-297`): open a Paramiko channel (reuse `ParamikoSshBridge`) and start the CLI under a PTY, e.g. `env ANTHROPIC_API_KEY=… claude` (env var name from `TOOL_INSTALL_SCRIPTS[...]['env_var']`, `app/services/agent_worker_provisioner.py:41`). The LLM key must be resolved server-side via `app/services/llm_provider_keys.get_key` and never sent to the browser (same principle as stored-key PEM handling, `app/routers/browser_ssh_terminal.py:1006-1034`).
- In dev mode (`S.dev_mode`, where provisioning is mocked at `app/services/agent_worker_provisioner.py:247-248`), provide a mock PTY bridge that echoes input and emits scripted Claude-style output (including a `[AGENT_FEEDBACK_NEEDED]`-style line, `app/services/terminal_monitor.py:56`) so the loop and monitor are exercised without real compute.
- Worker SSH auth: define how the launcher authenticates to the worker (provision an injected agent keypair at worker-create time, or reuse a stored key via `ssh_key_manager.get_decrypted_private_key`, `app/routers/browser_ssh_terminal.py:1015`). Document the chosen scheme; it must work in both mock and real modes (SECOPS-007 parity).

**Acceptance Criteria**
- Starting a session spawns a PTY-wrapped `claude` process on the worker (real) or the mock bridge (dev) and transitions the session to `ready`.
- `poll_output` returns CLI output; `send_input` is delivered to CLI stdin; `resize` adjusts the PTY.
- The LLM key never appears in any browser-bound message or log (redacted like `_redact_connect_payload`, `app/routers/browser_ssh_terminal.py:1049`).
- Closing the session terminates the CLI process; no orphan PTYs remain.

**Dependencies**
- ACS-002.

---

## Milestone 2 — Two-way WebSocket wiring

### ACS-004: Agent-session WS endpoint (separate from raw SSH /ws)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add a dedicated WebSocket endpoint `/api/agent-session/ws` (new router, or alongside `browser_ssh_terminal_ws` at `app/routers/browser_ssh_terminal.py:800-801`) so agent sessions are not conflated with raw SSH connect payloads (`_validate_connect_payload`, `app/routers/browser_ssh_terminal.py:651`).
- Reuse Protocol v1 envelope `{type, payload}` and message types `connect`/`input`/`resize` ⇄ `status`/`output`/`error` (documented `app/routers/browser_ssh_terminal.py:42-53`), but the `connect` payload is `{worker_id, session_id?, cols, rows}` — no host/port/auth fields, since the destination is the worker's own compute and credentials are resolved server-side.
- On `connect`: authorize (ACS-007), resolve/attach the session (ACS-006), and start or reattach the ACS-003 PTY bridge. Emit `status {phase:"ready"/"connected"}` like `:836-845` and `:1175-1186`.

**Acceptance Criteria**
- The agent-session endpoint accepts a `worker_id`-based connect and rejects raw-SSH host/port payloads with a structured error.
- A unit/integration test drives a full `connect → output → input → output → close` exchange against the mock bridge.
- Raw SSH `/ws` behavior is unchanged (regression test still passes).

---

### ACS-005: Reverse the wiring — browser INPUT reaches the session AND still feeds terminal_monitor (one-way → two-way)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- **This is the central one-way → two-way change.** Today, for agent-tracked SSH sessions, the loop only taps bridge OUTPUT into `terminal_monitor.process_terminal_output(...)` (`app/routers/browser_ssh_terminal.py:887-901`); there is no Claude CLI process, so browser `input` for an *agent* session has nothing meaningful to drive. With the ACS-003 PTY bridge in place, the agent-session loop must: (a) poll bridge output → send `output` to browser **and** feed `terminal_monitor.process_terminal_output(session.worker_id, output)` (preserve the existing monitor tap and `_dispatch_terminal_signal` call, `app/routers/browser_ssh_terminal.py:892-901`), and (b) on browser `input`, call `bridge.send_input(payload["data"])` — the same call the raw-SSH path already makes at `app/routers/browser_ssh_terminal.py:1215-1217`, now wired to the Claude PTY instead of a remote shell.
- Keep `terminal_monitor` integration intact: output is fed to the monitor **before/independent of** browser delivery so signal detection (`app/services/terminal_monitor.py:232-257`) and feedback creation (`create_feedback_request`, `:263`) continue to work whether or not a human is watching.
- Browser input that answers a pending feedback request should also flow through `respond_to_feedback` / buffer injection (`app/services/terminal_monitor.py:359-381`) so the monitor's view stays consistent; document the interaction so we don't double-inject.

**Acceptance Criteria**
- Typing in the browser reaches the Claude CLI stdin and produces a visible response (mock bridge in dev).
- The same output stream still triggers `terminal_monitor` signals and `_dispatch_terminal_signal` (test asserts a `[AGENT_FEEDBACK_NEEDED]` line yields a `feedback_request` message, as at `app/routers/browser_ssh_terminal.py:767-783`).
- An explicit test documents the before (output-only) vs after (bidirectional) behavior for agent sessions.

**Dependencies**
- ACS-003, ACS-004.

---

### ACS-006: Session lifecycle — start / attach / detach / stop + reconnect with output replay
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Decouple session lifetime from the WS connection: starting a session creates the PTY bridge server-side; **detach** (browser closes WS) must NOT kill the CLI — only the `finally` cleanup of compute should differ from raw SSH, which closes the bridge unconditionally (`app/routers/browser_ssh_terminal.py:1315-1317`). Keep the bridge alive on detach so the user can reattach.
- **Attach/reattach**: a second `connect` with an existing `session_id` re-binds the live bridge and replays a bounded scrollback buffer (reuse the monitor ring-buffer pattern, `get_or_create_buffer`, `app/services/terminal_monitor.py:246`, `:359-361`) so the terminal repaints on reconnect.
- **Stop**: an explicit stop terminates the CLI + bridge and transitions the session to `ended`; wire it so worker `stop_worker`/`terminate_worker` (`app/services/agent_worker_provisioner.py:376-444`) also ends any live sessions for that worker.
- Hold live bridges in a process-local registry keyed by `session_id` (single-worker uvicorn in dev, `--workers 1`, per CLAUDE.md), analogous to `_ACTIVE_SSH_SESSIONS_BY_USER` (`app/routers/browser_ssh_terminal.py:37`).

**Acceptance Criteria**
- Closing the browser tab (detach) leaves the session `running`/`awaiting_input`; reconnecting with the `session_id` resumes and replays recent output.
- Explicit stop ends the session and reaping the worker ends its sessions.
- Reconnect after a transient network drop works without losing the CLI process.

**Dependencies**
- ACS-005.

---

### ACS-007: Auth, ownership, and session/rate limits
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Reuse the cookie/role authorization used by the SSH terminal (`_authorize_terminal_access`, `app/routers/browser_ssh_terminal.py:233-280`) gated behind the new flag from ACS-001.
- Enforce **ownership**: the authenticated `user_sub` must own the `worker_id` (worker PK is `USER#{user_id}`, `app/services/agent_worker_provisioner.py:336-338`); a foreign or unknown worker → structured `forbidden`/`not_found` error, never attaching to another user's session.
- Apply connect rate-limiting and per-user concurrent-session caps, reusing the existing helpers (`_consume_connect_rate_limit`, `_try_acquire_user_session_slot`, `_release_user_session_slot`, `app/routers/browser_ssh_terminal.py:965-1003`).
- Emit audit events on start/attach/stop via `audit_event` (`app/routers/browser_ssh_terminal.py:1093-1101`).

**Acceptance Criteria**
- Unauthenticated / wrong-role connect is rejected before the bridge starts (test).
- A user cannot attach to another user's worker/session (ownership test).
- Concurrent-session and connect-rate limits are enforced with structured errors and audited.

**Dependencies**
- ACS-004.

---

### ACS-008: Session state reflects terminal_monitor signals
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Map `terminal_monitor` signals (`app/services/terminal_monitor.py:55-59`, `DEFAULT_FEEDBACK_PATTERNS` `:61-84`) to session-state transitions: `feedback_needed` → `awaiting_input`; resumed input / new output → `running`; `complete`/`error` signals → terminal/`error` states.
- Drive these via `transition_state` (ACS-002) from the agent-session loop where `_dispatch_terminal_signal` already fires (`app/routers/browser_ssh_terminal.py:892-901`), and clear `awaiting_input` when the user submits input (so the UI badge updates promptly).

**Acceptance Criteria**
- A `[AGENT_FEEDBACK_NEEDED]` line moves the session to `awaiting_input`; subsequent user input returns it to `running` (test).
- Session state is queryable via the ACS-009 API and matches what the UI shows.

**Dependencies**
- ACS-005, ACS-008 depends on ACS-002.

---

## Milestone 3 — REST API & UI

### ACS-009: REST endpoints for sessions on the agent-workers router
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add nested routes under the existing worker router (`app/routers/agent_workers.py:24`, prefix `/ui/agent/workers`): `POST /{worker_id}/sessions` (create), `GET /{worker_id}/sessions` (list), `GET /{worker_id}/sessions/{session_id}` (state), `POST /{worker_id}/sessions/{session_id}/stop`. All use `Depends(require_ui_session)` like the sibling endpoints (`app/routers/agent_workers.py:56-155`).
- Add Pydantic models (`SessionOut`, `CreateSessionIn`, `SessionListOut`) to `app/models.py` and TS types to `frontend/src/api/types.ts`; add endpoint wrappers in `frontend/src/api/endpoints/` (new `agentSessions.ts`).

**Acceptance Criteria**
- Create returns a `SessionOut` with `state` and a WS URL for the ACS-004 endpoint.
- List/get reflect live state including `awaiting_input`.
- Stop transitions the session to `ended` and is idempotent on an already-ended session.

**Dependencies**
- ACS-002, ACS-007.

---

### ACS-010: Dedicated Agent Session terminal UI (distinct from raw SSH)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Build a dedicated xterm.js terminal page/component for agent sessions, visually distinct from the raw SSH/VNC terminals (the existing remote pages live under `frontend/src/pages/remote/`, e.g. `RemoteDesktopPage.tsx`; there is currently no SSH-terminal frontend, so this is net-new xterm wiring): no host/port/auth form — the user picks a worker and clicks "Open Claude Session".
- Surface session state (`starting/ready/awaiting_input/running/ended`) as a prominent badge, with an `awaiting_input` affordance that focuses the input. Connect to the ACS-004 WS using the v1 `{type,payload}` protocol; send `input`/`resize`, render `output`, and handle `feedback_request` messages (`app/routers/browser_ssh_terminal.py:773-783`).
- Launch entry point from the Worker Fleet UI (`frontend/src/pages/agents/WorkersPage.tsx`) — an "Open Session" action on each `ready`/`running` worker. Add the route to `frontend/src/App.tsx`.
- Detach on tab close without stopping the session (ACS-006); offer explicit Stop and Reconnect controls.

**Acceptance Criteria**
- Selecting a `ready` worker opens a live Claude Code terminal; typing produces responses.
- The state badge updates to `awaiting_input` when the agent asks for input and back to `running` after the user answers.
- Closing and reopening the page reattaches to the same session and replays recent output.
- The UI is clearly distinguished from the raw SSH terminal (separate route, labeling, no host/port fields).

**Dependencies**
- ACS-009.

---

## Milestone 4 — Tests & hardening

### ACS-011: Backend tests — session manager, PTY bridge, two-way loop, ownership
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `tests/test_agent_claude_code_session.py` (offline/hermetic, following the repo pattern: moto or `_FakeTable` bound to frozen `T.agent_sessions`/`T.agent_workers` via `object.__setattr__`, `S` flags flipped the same way, the WS handler driven on a fresh `asyncio` loop, and `ParamikoSshBridge`/PTY stubbed — mirroring `tests/test_gap_0233_0234_ssh_session_recording.py` and `tests/test_gap_0220_0221_ssh_stored_key.py`).
- Cover: state machine transitions (legal/illegal), mock PTY bridge `input→output`, the **one-way→two-way** assertion (output both reaches the browser and feeds `terminal_monitor`; input reaches the CLI), feedback-signal → `awaiting_input`, ownership enforcement, and reconnect/replay.

**Acceptance Criteria**
- `just test` passes with the new suite; no real AWS/SSH/network.
- A dedicated test explicitly verifies the before (output-only) vs after (bidirectional) agent-session wiring.

**Dependencies**
- ACS-005, ACS-006, ACS-007, ACS-008.

---

### ACS-012: E2E test for the agent session terminal
**Type:** Chore  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- Add `frontend/e2e/agent-session-terminal.spec.ts` using `injectAuth` + the dev mock bridge: create a worker (dev provisioning is instant, `app/services/agent_worker_provisioner.py:247-248`), open a session from `WorkersPage`, type input, assert scripted output renders, assert the `awaiting_input` badge appears on a feedback line, then detach/reconnect and assert replay.
- Follow E2E conventions in CLAUDE.md (session-auth `page.request` with CSRF, scoped locators to avoid strict-mode violations).

**Acceptance Criteria**
- The spec passes under `just e2e` against the dev mock bridge.
- Covers start, type/respond, `awaiting_input` badge, detach, reconnect+replay, and stop.

**Dependencies**
- ACS-010, ACS-011.

---
