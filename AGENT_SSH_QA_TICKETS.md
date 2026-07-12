# Agent SSH/VNC QA — Implementation Tickets

This backlog adds an outbound, agent-driven SSH (and optional VNC) QA capability: an LLM agent worker can open an SSH connection to a registered host, run a test suite or command, capture stdout/stderr/exit-code, and stream structured results back into the existing terminal-monitoring / feedback loop. Today there is **no** API for an agent to initiate an outbound SSH connection — `app/routers/browser_ssh_terminal.py` only serves an interactive browser-driven WebSocket, and worker compute is never guaranteed to have an SSH client (`TOOL_INSTALL_SCRIPTS` in `app/services/agent_worker_provisioner.py:34-61` installs Node/git + the coding CLI, never `openssh-client`/Paramiko).

## Milestone 1 — Worker SSH client provisioning

### AQA-001: Install SSH client + Paramiko on worker compute during provisioning
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- `TOOL_INSTALL_SCRIPTS` (`app/services/agent_worker_provisioner.py:34-61`) installs only Node/git and the coding CLI; no `openssh-client` and no Python `paramiko`. Add a base provisioning step (independent of `tool`) that installs `openssh-client` and a Python venv with `paramiko` + `cryptography` (the latter is already a backend dep — see imports in `app/services/ssh_key_manager.py:12-17`).
- Add the step to the dev fast-path simulation in `_provision_worker_dev` (`app/services/agent_worker_provisioner.py:253-331`) as a new `_append_provision_step(..., "ssh_client_install", ...)` between `compute_launch` and `tool_install`, and to the real provisioning path when it lands.
- Record the installed client version on the worker record (`agent_workers` table) for the `verify` step (`agent_worker_provisioner.py:312-322`).

**Acceptance Criteria**
- A newly provisioned worker reports an `ssh_client_install` step with status `done` and a captured version string.
- The step runs regardless of `tool` (claude_code / codex / custom).
- Dev mode completes the step in-memory without real shell execution (parity with existing dev steps).

**Dependencies**
- None.

---

### AQA-002: Persist SSH connection context (host_id / ssh_key_id) on the worker record
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Workers already carry `compute_instance_id`, `public_ip`, and `host_id` (`app/services/agent_worker_provisioner.py:290-297`); EC2/K8s instances auto-register into host inventory with `source="ec2_auto"`/`"k8s_auto"` (GAP-0223/0226). Ensure the worker's `host_id` always points at the auto-registered `host_inventory` record so the QA API can resolve credentials by `host_id` rather than raw IP.
- Persist the `ssh_key_id` that was injected during provisioning (the `key_inject` step is a no-op today — `agent_worker_provisioner.py:308-310`) so the QA path can resolve the matching KMS-encrypted key via `app/services/ssh_key_manager.py:293` (`get_decrypted_private_key`).
- Expose `host_id` + `ssh_key_id` in the cleaned worker output (`_item_to_worker`, `agent_worker_provisioner.py:107-123`).

**Acceptance Criteria**
- `get_worker` returns both `host_id` and `ssh_key_id` when set.
- The `host_id` resolves to a real `host_inventory` record via `host_inventory.get_host(user_sub, host_id)` (`app/services/host_inventory.py:254-260`).
- A worker provisioned without a key (custom tool) leaves `ssh_key_id` empty without erroring.

**Dependencies**
- AQA-001.

---

## Milestone 2 — Agent QA action API + execution engine

### AQA-003: `agent_actions` data model + DynamoDB table
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- There is no `agent_actions` table today (absent from `app/core/tables.py`; only `agent_workers`/`agent_feedback`/`agent_runs` exist — `app/core/tables.py:265-513`). Add an `agent_actions` table handle plus a `TableDef` in `scripts/local-ddb-init.py` for QA action records.
- Schema: PK `pk=WORKER#{worker_id}`, SK `ACTION#{action_id}`, with `action_type` (`run_command` | `run_test_suite`), `host_id`, `command`, `status` (`pending`|`running`|`completed`|`failed`|`timed_out`), `exit_code`, `stdout_tail`, `stderr_tail`, `started_at`, `finished_at`, `timeout_seconds`. Add a `ByStatus` GSI for the runner to claim pending actions.
- Add Pydantic request/response models to `app/models.py` (`RunAgentActionIn`, `AgentActionOut`) mirroring the existing model conventions.
- Cap stored `stdout_tail`/`stderr_tail` (reuse the tail cap pattern from `app/services/agent_qa.py:51`, `_OUTPUT_TAIL_MAX = 5000`).

**Acceptance Criteria**
- `agent_actions` table is created by `scripts/local-ddb-init.py` with numeric sort/GSI keys declared via `attr_types` where applicable.
- Action records round-trip through DynamoDB with Decimal coercion handled.
- Output fields are truncated to the configured cap before persistence.

**Dependencies**
- AQA-002.

---

### AQA-004: SSH command execution engine (single-host, non-interactive)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add an `app/services/agent_ssh_exec.py` service that opens a one-shot SSH connection and runs a command via Paramiko `exec_command` (NOT `invoke_shell` — the interactive PTY path in `ParamikoSshBridge.connect`, `app/routers/browser_ssh_terminal.py:114-149`, is for live terminals). Reuse the key-loading approach from `ParamikoSshBridge._load_private_key` (`browser_ssh_terminal.py:93-112`) and `ssh_key_manager._load_private_key` (`app/services/ssh_key_manager.py:73-107`).
- Capture stdout, stderr, and exit status (`channel.recv_exit_status()`); enforce a hard wall-clock timeout and kill the channel on expiry.
- Resolve the target from `host_id` via `host_inventory.get_host` (`app/services/host_inventory.py:254-260`) → hostname/port/username; never accept a raw hostname from the agent (see AQA-006 allowlist).
- Reuse `host_inventory.record_connection` (`app/services/host_inventory.py:447-481`) on a successful connect so the host's `last_connected_at`/history stays accurate.

**Acceptance Criteria**
- Running `echo hello` against a test host returns `exit_code=0`, `stdout` containing `hello`, empty `stderr`.
- A command exceeding `timeout_seconds` yields `status=timed_out` and the channel/client is closed.
- A non-zero exit (`exit 3`) is captured as `exit_code=3`, `status=failed` (action succeeded, command failed — distinguish from transport failure).
- Connection/auth failure returns a structured error code (mirror `BrowserSshError` codes, `browser_ssh_terminal.py:56-61`) without leaking credentials.

**Dependencies**
- AQA-003.

---

### AQA-005: Server-side credential injection from host_inventory / ssh_key_manager
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- The agent must NEVER receive plaintext key material. The QA API accepts only `host_id` + (optional) `ssh_key_id`; the execution engine resolves the KMS-encrypted key server-side via `ssh_key_manager.get_decrypted_private_key(user_sub, key_id)` (`app/services/ssh_key_manager.py:293-319`) — the same pattern the stored-key terminal path uses (`browser_ssh_terminal.py:1006-1034`).
- Default the key from the worker's persisted `ssh_key_id` (AQA-002) when the request omits one. Enforce ownership: `get_decrypted_private_key` keys on `{user_sub, sk}` so a foreign/unknown key returns `None` → `key_not_found` (mirror `browser_ssh_terminal.py:1016-1032`).
- For multi-hop targets, resolve via `ssh_bastion.resolve_connection_chain(user_sub, path_id, include_keys=True)` (`app/services/ssh_bastion.py:465-517`) and run through `MultiHopSshBridge` (`app/services/ssh_bastion.py:524`); ensure the resolved plaintext PEM never serializes to any API/log (security note at `ssh_bastion.py:486-490`).
- Redact `keyId`, `password`, and PEM in all logs (reuse the redaction approach in `_redact_connect_payload`, `browser_ssh_terminal.py:591-603`).

**Acceptance Criteria**
- An action request body never contains key/PEM material; only `host_id`/`ssh_key_id`/`path_id`.
- A foreign or non-existent `ssh_key_id` returns `key_not_found` and performs no connection.
- No plaintext PEM, password, or `keyId` appears in any log line emitted by the QA path.
- Multi-hop actions resolve and connect via `resolve_connection_chain` + `MultiHopSshBridge`.

**Dependencies**
- AQA-004.

---

### AQA-006: Agent QA API endpoints (open/run/poll/cancel)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `app/routers/agent_actions.py` (registered in `app/main.py`) exposing: `POST /ui/agents/{worker_id}/actions` (submit a `run_command` / `run_test_suite` action), `GET /ui/agents/{worker_id}/actions/{action_id}` (poll status + captured output), `GET /ui/agents/{worker_id}/actions` (list), `POST /ui/agents/{worker_id}/actions/{action_id}/cancel`.
- Use `Depends(require_ui_session)` for auth, matching the existing worker/feedback routers; the action runs **as** the owning user (`user_sub`), and the engine resolves credentials for that user only.
- Synchronous-or-async: submit creates a `pending` record (AQA-003) and a background runner (claim via `ByStatus` GSI compare-and-swap, mirroring `audit_export_worker`) executes it; the poll endpoint returns terminal status + truncated output. Accept an optional `worker_id` linkage so output also flows to `terminal_monitor` (AQA-007).

**Acceptance Criteria**
- Submitting an action returns `action_id` + `status=pending`/`running`.
- Polling returns `exit_code`, `stdout_tail`, `stderr_tail`, and terminal `status`.
- Cancel transitions a running action to `cancelled` and closes the SSH channel.
- A request targeting a `host_id` not owned by the caller returns 404 (owner isolation via `host_inventory` partition key).

**Dependencies**
- AQA-005, AQA-009.

---

## Milestone 3 — Results streaming into the feedback loop

### AQA-007: Stream QA output into terminal_monitor + structured QA result signal
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Feed captured stdout chunks (or final output) into `terminal_monitor.process_terminal_output(worker_id, chunk)` (`app/services/terminal_monitor.py:232-257`) so the existing AGENT-006 pattern detection (completion/feedback/error) fires on QA output — the `qa` agent type already has tuned patterns (`terminal_monitor.py:99-110`, e.g. `\d+ tests? passed, 0 failed`).
- On a detected `feedback_needed`/`completion`/`error` signal, dispatch through the same path the live terminal uses (`_dispatch_terminal_signal`, `browser_ssh_terminal.py:746-797`) — create a feedback request via `terminal_monitor.create_feedback_request` (`terminal_monitor.py:263-323`) or mark completion.
- Persist a structured QA summary (exit code, pass/fail counts parsed from output, action_id) onto the `agent_runs` record so it surfaces in the existing QA reporting (`app/services/agent_qa.py` qa_output storage).

**Acceptance Criteria**
- QA output that contains `All tests passed` produces a `completion` signal and an `agent_complete` notification.
- A non-zero exit / traceback produces an `error` signal routed through the existing dispatcher.
- The structured summary (exit_code + parsed counts) is queryable from the worker's run record.

**Dependencies**
- AQA-004, AQA-006.

---

### AQA-008: Optional VNC screenshot capture for visual QA
**Type:** Feature  
**Priority:** P2  
**Estimate:** 3 days

**Description**
- `app/services/vnc_sessions.py` brokers interactive VNC sessions but has **no** framebuffer/screenshot capability (no `screenshot`/`png`/`capture` symbols in the file). Add a server-side capture: open a VNC RFB connection to the resolved target, request a framebuffer update, and encode the framebuffer to PNG.
- Resolve the VNC target from `host_id` (protocol `vnc`) via `host_inventory.get_host`; reuse `vnc_sessions` token/authorization gating (`mint_connect_token`/`_ensure_authorized`, `vnc_sessions.py:254-298`) rather than re-implementing auth.
- Store the screenshot to S3 (via `app.core.aws_clients.s3_client`, dev = in-process moto) and attach a presigned/mock URL to the `agent_actions` record (`action_type="vnc_screenshot"`).

**Acceptance Criteria**
- A `vnc_screenshot` action against a registered VNC host produces a PNG stored in S3 and a retrievable URL on the action record.
- Capture honours the same ownership/authorization checks as interactive VNC sessions.
- Feature gated behind a flag (default off) and degrades gracefully (`vnc_unavailable`) when the dependency/target is absent.

**Dependencies**
- AQA-006.

---

## Milestone 4 — Guardrails, audit, and tests

### AQA-009: Host allowlist + command policy guardrails
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Restrict agent SSH targets to host-inventory records the agent's user owns AND that carry an explicit "agent QA allowed" flag — add an `agent_qa_allowed: bool` field to the host record (extend `_item_to_host`/`create_host`/`update_host`, `app/services/host_inventory.py:150,254-260,288`, defaulting `False` so pre-existing hosts are never auto-targetable — mirror the `record_sessions` rollout, GAP-0234).
- Reuse the destination policy machinery from the browser terminal (`_enforce_destination_policy` + allow/deny host/port helpers, `browser_ssh_terminal.py:455-491`) so env-level host/port allowlists also apply to the agent path.
- Add command guardrails: a configurable command/length cap and an optional denylist of destructive prefixes; reject before connecting. Add per-worker concurrent-action and per-window rate limits (mirror the connect rate-limit deque in `browser_ssh_terminal.py:359-373`).

**Acceptance Criteria**
- An action targeting a host without `agent_qa_allowed=True` is rejected (`policy_denied_host`) before any SSH dial.
- Env host/port denylist (`BROWSER_SSH_DENIED_HOSTS`/`_PORTS`) blocks the agent path identically to the browser path.
- Exceeding the per-worker concurrent-action or rate limit returns a structured `rate_limited` error.

**Dependencies**
- AQA-003.

---

### AQA-010: Audit trail for every agent SSH/VNC action
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Emit `audit_event` records for every agent action lifecycle event (`agent_action.submit`, `.connect`, `.complete`, `.failed`, `.timeout`, `.denied`) via `app/services/alerts.audit_event` — reuse the fire-and-forget `_audit` wrapper pattern from `ssh_key_manager._audit` (`app/services/ssh_key_manager.py:29-42`) and the session-event helper in `browser_ssh_terminal.py:615-637`.
- Include `worker_id`, `host_id`, `action_id`, `outcome`, and a command hash/length — never the resolved credential, never full output.
- Mirror the SSH key audit events already emitted (`ssh_key.decrypt`, `ssh_key_manager.py:318`) so credential resolution for an agent action is traceable end-to-end.

**Acceptance Criteria**
- Each action lifecycle transition writes exactly one audit event to the alerts/audit store.
- Audit records contain no plaintext credential and no untruncated command output.
- A denied action (allowlist/rate-limit) still emits a `.denied` audit event.

**Dependencies**
- AQA-006, AQA-009.

---

### AQA-011: Backend test suite (exec engine, credential injection, guardrails)
**Type:** Test  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Offline/hermetic pytest coverage following the repo convention (moto-backed tables patched onto frozen `T` via `object.__setattr__`, Paramiko stubbed via `patch.dict(sys.modules, ...)` — see `tests/test_gap_0235_0236_ssh_bastion_multihop.py` referenced in CLAUDE.md, and the stored-key test `tests/test_gap_0220_0221_ssh_stored_key.py`).
- Cover: `exec_command` happy path / non-zero exit / timeout (AQA-004); credential injection resolving via patched `get_decrypted_private_key` with `key_not_found` for foreign keys (AQA-005); allowlist + rate-limit rejection (AQA-009); audit emission spy (AQA-010); terminal_monitor signal routing (AQA-007).
- Frozen `S` flags toggled via `object.__setattr__`; no real AWS/SSH/network.

**Acceptance Criteria**
- All new tests run under `just test` with no live dev stack and no network.
- Coverage includes the failure paths (timeout, auth failure, foreign key, denied host).
- Tests assert no plaintext credential appears in captured log output.

**Dependencies**
- AQA-007, AQA-010.

---

### AQA-012: E2E + integration test for the agent QA round-trip
**Type:** Test  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add an integration test that submits a `run_command`/`run_test_suite` action via the API (AQA-006), polls to terminal status, and asserts the structured result + a `completion`/`error` signal landed in the feedback loop (AQA-007).
- Use a fixture SSH server/container (per the SSH browser-terminal test guidance, `SSH_BROWSER_TERMINAL_TICKETS.md` SSH-016) or a stubbed bridge for determinism; gate any real-exec test behind `S.agent_qa_execute_commands` (default off — `app/services/agent_qa.py:17-21`).

**Acceptance Criteria**
- The round-trip test passes deterministically in CI without external hosts when exec is disabled.
- When exec is enabled against the fixture host, the captured `exit_code`/output match the run command.
- The feedback request / completion notification is observable from the worker's feedback list.

**Dependencies**
- AQA-011.

---

## Cross-cutting dependencies

- **EC2 ↔ remote-terminal integration** (`COMPUTE_TERMINAL_INTEGRATION_TICKETS.md`, esp. CTI-001 server-side `host_id` → connection-param resolution and CTI-010 ownership enforcement): the agent QA path depends on `host_id` resolving to connection params and on owner-isolation being enforced uniformly. AQA-002/AQA-004/AQA-005 build directly on that resolution layer.
- **Worker provisioning / Claude-Code-session work** (`app/services/agent_worker_provisioner.py`): AQA-001/AQA-002 extend the provisioning pipeline; the agent must be running its coding/QA session on a worker that has been provisioned with the SSH client and a known `host_id`/`ssh_key_id`.
- **AGENT-006 terminal monitoring** (`app/services/terminal_monitor.py`) and the existing `qa` agent type (`app/services/agent_qa.py`) are reused, not rebuilt — AQA-007 is an integration, not a new detection engine.

## Definition of Done (cross-ticket)
- No plaintext SSH key, password, or PEM is ever returned to the agent, logged, or stored unencrypted.
- Every agent SSH/VNC action is owner-isolated, allowlist-gated, rate-limited, and audited.
- Dev (moto/mock KMS) and prod paths share one code path — no `dev_mode` security divergence (SECOPS-007 parity).
- Captured output is truncated before persistence and the exec channel is always closed on completion/timeout/cancel.
