# ADR-003: Agents Performing QA over SSH/VNC

## Status

Proposed

## Context

Today an LLM agent worker provisioned through the Worker Agent Framework
(AGENT-002/003/008/009) can run a coding/QA session **on** a worker, but it has
**no** server-mediated way to reach *another* host to actually exercise a system
under test. Two structural gaps exist:

1. **No outbound SSH from an agent.** The only SSH path in the codebase is the
   interactive, browser-driven WebSocket terminal
   (`app/routers/browser_ssh_terminal.py`). `ParamikoSshBridge.connect`
   (`browser_ssh_terminal.py:114-149`) deliberately opens an *interactive PTY*
   (`client.invoke_shell(...)`, `browser_ssh_terminal.py:138`) and streams it to
   a human at a `xterm.js` front-end. There is no one-shot, non-interactive
   `exec_command` path, and no API an agent can call to initiate a connection.

2. **Workers cannot speak SSH.** `TOOL_INSTALL_SCRIPTS`
   (`app/services/agent_worker_provisioner.py:34-61`) installs only Node/git +
   the coding CLI (`claude_code`/`codex`). It never installs `openssh-client`
   or Python `paramiko`. The dev provisioning fast-path
   (`_provision_worker_dev`, `agent_worker_provisioner.py:253-331`) runs
   `compute_launch → tool_install → key_inject → verify`, and the `key_inject`
   step is a **no-op** today (`agent_worker_provisioner.py:308-310`).

What *does* exist and is directly reusable:

- **Server-side credential injection.** `ssh_key_manager.get_decrypted_private_key(user_sub, key_id)`
  (`app/services/ssh_key_manager.py:293-319`) resolves a KMS-encrypted key by
  the `{user_sub, sk}` access pattern, so ownership is intrinsic; an unknown or
  foreign key returns `None`. It is explicitly documented "INTERNAL USE ONLY ...
  never exposed via API" and emits an `ssh_key.decrypt` audit event
  (`ssh_key_manager.py:318`). The stored-key terminal path
  (`browser_ssh_terminal.py:1006-1034`) already resolves PEM server-side and
  normalises `authType` to `private_key` so the PEM never reaches the client.
- **Multi-hop resolution.** `ssh_bastion.resolve_connection_chain(user_sub, path_id, include_keys=True)`
  (`app/services/ssh_bastion.py:465-517`) returns an ordered hop list with
  decrypted PEM per keyed hop (with a strong "server-internal only, never
  serialise" security note at `ssh_bastion.py:486-490`), and
  `MultiHopSshBridge` (`ssh_bastion.py:524`) tunnels through it via Paramiko
  `direct-tcpip`.
- **Host resolution + ownership.** `host_inventory.get_host(user_sub, host_id)`
  (`app/services/host_inventory.py:254-260`) resolves a `host_id` to
  hostname/port/username and is owner-isolated by partition key. EC2/K8s
  instances already auto-register a `host_id` (GAP-0223/0226), and workers
  persist `compute_instance_id`/`public_ip`/`host_id`
  (`agent_worker_provisioner.py:290-297`). **CTI-001 is already DONE**
  (`_resolve_host_id_into_payload`, commit 730380f6): the browser terminal now
  authoritatively derives host/port/username from the owner's inventory record,
  anti-spoofing client overrides — the exact resolution layer AQA-002/004/005
  build on.
- **Destination policy + rate limiting.** `_enforce_destination_policy`
  (`browser_ssh_terminal.py:455-491`) applies env host/port allow/deny lists
  (`BROWSER_SSH_ALLOWED_HOSTS`/`_DENIED_HOSTS`/`_PORTS`); the connect rate-limit
  deque is at `browser_ssh_terminal.py:359-373`. Credentials are redacted in
  logs via `_redact_connect_payload` (`browser_ssh_terminal.py:591-603`).
- **Feedback loop (AGENT-006).** `terminal_monitor.process_terminal_output(worker_id, chunk)`
  (`app/services/terminal_monitor.py:232-257`) runs the pattern matcher; the
  `qa` agent type already has tuned patterns (`terminal_monitor.py:99-110`,
  e.g. `\d+ tests? passed, 0 failed`). The live terminal dispatches detected
  signals via `_dispatch_terminal_signal` (`browser_ssh_terminal.py:746-797`)
  and `terminal_monitor.create_feedback_request` (`terminal_monitor.py:263-323`).
- **QA output cap + exec gate.** `agent_qa.py` defines `_OUTPUT_TAIL_MAX = 5000`
  (`agent_qa.py:51`) and gates real execution behind `S.agent_qa_execute_commands`
  (`agent_qa.py:17-21`, default off).
- **VNC.** `app/services/vnc_sessions.py` brokers interactive VNC with
  `mint_connect_token`/`_ensure_authorized` (`vnc_sessions.py:254-298`) but has
  **no** framebuffer/screenshot capability.

There is no `agent_actions` table — `app/core/tables.py` only declares
`agent_workers`/`agent_feedback`/`agent_runs` (`tables.py:266-273, 512-519`).

The full backlog is captured in `AGENT_SSH_QA_TICKETS.md` (AQA-001..AQA-012).

## Decision drivers

- **No plaintext credential ever reaches the agent, a log line, or unencrypted
  storage** (Definition of Done, `AGENT_SSH_QA_TICKETS.md:265`). This is the
  hard security boundary.
- **SECOPS-007 dev/prod parity** — one code path through moto/mock-KMS in dev
  and real AWS/KMS in prod, no `dev_mode` security divergence.
- **Reuse, don't rebuild** — the credential, host-resolution, policy, audit,
  and feedback-detection machinery already exist and are tested; the agent path
  should be a thin orchestration over them.
- **Owner isolation** — every action runs *as* the owning `user_sub`, and
  credential/host resolution is keyed on that sub so cross-tenant access is
  structurally impossible.
- **Determinism in tests/CI** — must run hermetically (no live SSH/AWS/network),
  gated by a flag so the default is non-executing.
- **Build on CTI** — the agent path is meaningless without `host_id → connection
  params` resolution (CTI-001, done) and uniform ownership enforcement
  (CTI-010).

## Options considered

### Option A — Reuse the browser terminal WS as the agent transport

Have the agent connect to the existing `/api/browser-ssh` WebSocket and drive
the interactive PTY programmatically.

- **Pros:** No new transport; reuses `_resolve_host_id_into_payload`, policy,
  audit-session helpers verbatim.
- **Cons:** The PTY model is wrong for QA — you cannot reliably capture a
  discrete `exit_code` from `invoke_shell`; you must screen-scrape a prompt.
  WebSocket framing, idle/max-duration timeouts (`_session_timeout_error`,
  `browser_ssh_terminal.py:376-389`), and resize semantics are all human-UX
  concerns. Output is `xterm`-encoded (ANSI), not clean stdout/stderr. No
  natural place to persist a structured action record. Forces the agent to hold
  a long-lived socket.

### Option B — New non-interactive exec engine + `agent_actions` API + background runner (recommended)

A dedicated `app/services/agent_ssh_exec.py` opens a one-shot Paramiko
`exec_command` connection (not `invoke_shell`), captures stdout/stderr/exit
status, and persists a structured `agent_actions` record. A thin
`app/routers/agent_actions.py` submits/polls/cancels; a background runner claims
`pending` actions via a `ByStatus` GSI compare-and-swap (mirroring
`audit_export_worker`). Credentials are resolved server-side from
`host_id`/`ssh_key_id`; output is streamed into `terminal_monitor`.

- **Pros:** Clean `recv_exit_status()` capture; structured, queryable records;
  natural fit for `_OUTPUT_TAIL_MAX` truncation; submit/poll API matches the
  existing worker/feedback router conventions and the agent's request/response
  model; reuses `get_decrypted_private_key`, `resolve_connection_chain`,
  `get_host`, `_enforce_destination_policy`, `process_terminal_output`,
  `audit_event` unchanged; the async runner keeps the agent from holding a
  socket and centralises rate/concurrency limits. Single code path, easily
  hermetic-testable by stubbing Paramiko.
- **Cons:** New table + runner + router to build and gate; more moving parts
  than A.

### Option C — Synchronous in-request exec (no runner)

`POST /actions` blocks until the command finishes and returns the result inline.

- **Pros:** Simplest control flow; no GSI/claim logic; no poll endpoint needed.
- **Cons:** Long QA suites exceed request timeouts; no cancel; concurrency/rate
  limiting must live in the request path; couples the HTTP worker to SSH I/O.
  Does not match the agent's fire-and-poll usage. Still needs the table for
  audit/result history anyway.

## Decision

Adopt **Option B**. Build a dedicated non-interactive exec engine
(`agent_ssh_exec.py`) behind an `agent_actions` submit/poll/cancel API with a
background runner, reusing the existing credential-injection, host-resolution,
destination-policy, audit, and terminal-monitor machinery wholesale.

**Rationale:** QA fundamentally needs a discrete exit code and clean
stdout/stderr — only `exec_command` gives that cleanly; the interactive PTY of
Option A is structurally unsuited (no reliable exit code, ANSI-encoded output).
Option C cannot survive a real test suite's wall-clock and offers no cancel. The
async record-based model in B mirrors the proven `audit_export_worker`
claim-via-GSI pattern, fits the agent's submit-then-poll interaction, and lets
every guardrail (allowlist, rate limit, concurrency cap, audit) live in one
orchestration layer over already-tested primitives — the smallest net-new
security surface for the most capability.

## Consequences

**Positive**

- Agents gain a safe, auditable QA-over-SSH capability with structured results
  flowing into the existing AGENT-006 feedback loop (`terminal_monitor`) and QA
  reporting (`agent_runs`).
- The plaintext-credential boundary is enforced structurally: the API surface
  only ever accepts `host_id`/`ssh_key_id`/`path_id`; PEM is resolved and used
  entirely server-side, identical to the stored-key terminal path.
- Multi-hop QA "just works" by delegating to `resolve_connection_chain` +
  `MultiHopSshBridge`.

**Negative / costs**

- New `agent_actions` table (+ `ByStatus` GSI), a background runner registered in
  `main.py`, and a new router — more surface to maintain and gate.
- Workers must be re-provisioned to carry `openssh-client`/`paramiko`
  (AQA-001); pre-existing workers won't have the client until reprovisioned.
- VNC screenshot (AQA-008) requires a real RFB framebuffer decoder — a genuinely
  new dependency/capability, hence P2 and flag-gated-off.

**Risks**

- The runner's claim/timeout/channel-close discipline must be airtight: a leaked
  channel or un-truncated output violates the DoD. Mitigated by always closing
  in a `finally` and truncating before persistence (mirrors the bastion bridge
  and `_OUTPUT_TAIL_MAX` patterns).

## Security & dev/prod-parity model

- **One code path (SECOPS-007).** Credential resolution goes through
  `get_decrypted_private_key` → `app/core/crypto.kms_decrypt`, which already
  abstracts dev (mock KMS, port 7999) vs prod transparently. Host/action records
  live in DynamoDB regardless of mode. There is **no** `dev_mode` branch in the
  security path; `S.agent_qa_execute_commands` (default off) gates only whether a
  real SSH dial occurs vs. an in-memory simulation, exactly like the existing
  QA agent (`agent_qa.py:17-21`).
- **Plaintext boundary.** Request/response models (`RunAgentActionIn`,
  `AgentActionOut`) carry only `host_id`/`ssh_key_id`/`path_id` — never key,
  PEM, or password. The resolved PEM lives only inside the engine call frame and
  the `MultiHopSshBridge`/`ParamikoSshBridge`-style bridge; it is never written
  to the `agent_actions` record nor logged. All log lines reuse
  `_redact_connect_payload`-style redaction (`browser_ssh_terminal.py:591-603`).
- **Owner isolation.** Every resolution (`get_host`, `get_decrypted_private_key`,
  `resolve_connection_chain`) is keyed on the caller's `user_sub`; a foreign
  `host_id`/`ssh_key_id` returns `None`/404 with `key_not_found` —
  cross-tenant access is structurally impossible (mirrors CTI-010).
- **Guardrails.** Host allowlist via a new `agent_qa_allowed: bool` host flag
  (default `False`, mirroring the `record_sessions` rollout, GAP-0234) plus the
  env host/port allow/deny machinery; command length cap + destructive-prefix
  denylist checked *before* dialing; per-worker concurrency + window rate limit
  (deque pattern, `browser_ssh_terminal.py:359-373`).
- **Audit.** Every lifecycle transition (`agent_action.submit|connect|complete|
  failed|timeout|denied`) emits exactly one `audit_event` via the
  fire-and-forget `_audit` wrapper (`ssh_key_manager.py:29-42`), carrying
  `worker_id`/`host_id`/`action_id`/`outcome` + a command hash/length — never
  the credential, never untruncated output. Chains end-to-end with the existing
  `ssh_key.decrypt` event.
- **Tests.** Hermetic pytest: moto-backed tables patched onto frozen `T` via
  `object.__setattr__`, `S` flags toggled the same way, Paramiko stubbed via
  `patch.dict(sys.modules, ...)` — following `tests/test_gap_0235_0236_ssh_bastion_multihop.py`
  and `tests/test_gap_0220_0221_ssh_stored_key.py`. No real AWS/SSH/network.

## New settings / flags

All default to the safe (off / restrictive) value; symmetric naming with the
existing SSH/QA settings.

| Setting (env) | Default | Purpose |
|---|---|---|
| `AGENT_SSH_QA_ENABLED` | `false` | Master flag for the agent-actions API + runner; gates router registration in `main.py` (mirrors `AUDIT_EXPORT_WORKER_ENABLED`). |
| `S.agent_qa_execute_commands` (`AGENT_QA_EXECUTE_COMMANDS`) | `false` | **Reuses the existing** gate (`agent_qa.py:17-21`): off → simulate in-memory, on → real SSH dial. |
| `AGENT_SSH_QA_ACTION_TIMEOUT_SECONDS` | `300` | Hard wall-clock cap per action; channel killed on expiry. |
| `AGENT_SSH_QA_MAX_CONCURRENT_PER_WORKER` | `1` | Concurrent in-flight actions per worker. |
| `AGENT_SSH_QA_RATE_LIMIT_COUNT` / `_WINDOW_SECONDS` | `10` / `60` | Per-worker submit rate limit (deque). |
| `AGENT_SSH_QA_COMMAND_MAX_LENGTH` | `4096` | Reject longer commands before dialing. |
| `AGENT_SSH_QA_COMMAND_DENYLIST` | `""` | CSV of destructive command prefixes to reject. |
| `AGENT_VNC_SCREENSHOT_ENABLED` | `false` | Gates AQA-008 VNC capture; `vnc_unavailable` when off/absent. |
| `agent_actions_table_name` | — | Table handle in `tables.py` / settings, like `agent_runs_table_name`. |

The env host/port allow/deny lists (`BROWSER_SSH_ALLOWED_HOSTS`/`_DENIED_HOSTS`/
`_PORTS`) are **reused as-is** so the agent path enforces the same destination
policy as the browser path.

## High-level implementation plan (mapped to ticket IDs)

**Milestone 1 — Worker SSH client provisioning**
- **AQA-001** — Add an `openssh-client` + `paramiko`/`cryptography` venv install
  step to `TOOL_INSTALL_SCRIPTS` base provisioning; add `ssh_client_install`
  between `compute_launch` and `tool_install` in `_provision_worker_dev`
  (`agent_worker_provisioner.py:253-331`); record client version for `verify`.
- **AQA-002** — Persist `host_id` (point at the auto-registered inventory record)
  and the injected `ssh_key_id` (replace the `key_inject` no-op,
  `agent_worker_provisioner.py:308-310`); expose both in `_item_to_worker`
  (`agent_worker_provisioner.py:107-123`).

**Milestone 2 — Action API + execution engine**
- **AQA-003** — `agent_actions` table handle in `tables.py` + `TableDef` in
  `scripts/local-ddb-init.py` (PK `WORKER#{worker_id}`, SK `ACTION#{action_id}`,
  `ByStatus` GSI; numeric keys via `attr_types`); `RunAgentActionIn`/
  `AgentActionOut` in `models.py`; truncate to `_OUTPUT_TAIL_MAX`.
- **AQA-004** — `app/services/agent_ssh_exec.py`: one-shot `exec_command` with
  stdout/stderr + `recv_exit_status()`, hard timeout, structured error codes
  mirroring `BrowserSshError` (`browser_ssh_terminal.py:56-61`); resolve target
  via `host_inventory.get_host`; `record_connection` on success.
- **AQA-005** — Server-side credential injection: `get_decrypted_private_key`
  (default from worker's `ssh_key_id`), `key_not_found` for foreign keys;
  multi-hop via `resolve_connection_chain` + `MultiHopSshBridge`; redact in logs.
- **AQA-006** — `app/routers/agent_actions.py` (registered in `main.py`):
  `POST/GET /ui/agents/{worker_id}/actions`, `GET .../{action_id}`,
  `POST .../{action_id}/cancel`; `Depends(require_ui_session)`; background runner
  claims `pending` via `ByStatus` CAS (audit_export_worker pattern).

**Milestone 3 — Results streaming**
- **AQA-007** — Feed output through `terminal_monitor.process_terminal_output`;
  dispatch detected signals via the `_dispatch_terminal_signal` /
  `create_feedback_request` path; persist a structured QA summary on `agent_runs`.
- **AQA-008** (P2) — VNC framebuffer→PNG capture in `vnc_sessions.py`, reusing
  `mint_connect_token`/`_ensure_authorized`; store to S3; flag-gated off.

**Milestone 4 — Guardrails, audit, tests**
- **AQA-009** — `agent_qa_allowed` host flag (default `False`); reuse
  `_enforce_destination_policy`; command cap/denylist; per-worker concurrency +
  rate limit.
- **AQA-010** — `audit_event` for every lifecycle transition via the `_audit`
  wrapper; command hash/length only, never credential/full output.
- **AQA-011** — Hermetic backend tests (frozen `T`/`S`, stubbed Paramiko).
- **AQA-012** — Integration round-trip test, gated by `S.agent_qa_execute_commands`.

**Dependency on CTI:** AQA-002/004/005 build directly on **CTI-001**
(`host_id → connection-param` resolution, **already DONE**, commit 730380f6) and
**CTI-010** (uniform ownership enforcement). The CTI **deep-link** work
(**CTI-006** `/remote/ssh` route, **CTI-007/008** "Open terminal" buttons,
**already DONE** 2026-06-09) is *adjacent* — it gives humans a UI to the same
resolved hosts; the agent path is a non-interactive sibling that reuses the same
resolution layer but never touches the browser WS/UI. No hard dependency on the
UI deep-link, only on the resolution + ownership layers it shares.

## Effort estimate

Summing the ticket estimates in `AGENT_SSH_QA_TICKETS.md`:

| Milestone | Tickets | Days |
|---|---|---|
| M1 — Worker provisioning | AQA-001, 002 | 3 |
| M2 — Action API + exec engine | AQA-003, 004, 005, 006 | 9 |
| M3 — Results streaming (+ optional VNC) | AQA-007 (2), AQA-008 (3, P2) | 2 (+3) |
| M4 — Guardrails, audit, tests | AQA-009, 010, 011, 012 | 8 |

**Core (P0/P1, excluding the P2 VNC screenshot): ~22 engineer-days (~4.5 weeks
for one engineer).** Including AQA-008: **~25 days.** The estimate assumes the
CTI resolution/ownership layer is in place (it is — CTI-001/010), so no
host-resolution work is re-counted here.
