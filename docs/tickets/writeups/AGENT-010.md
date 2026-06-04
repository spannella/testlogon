# AGENT-010: DevOps/SRE Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-010 defines the DevOps/SRE Agent type — a configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously execute infrastructure operations. The agent picks up tickets labeled `type:deployment`, `type:infrastructure`, or `type:incident`; generates a deployment plan; enforces a mandatory human-approval gate for production environments before execution; runs configurable deploy commands on a provisioned terminal session; verifies success via HTTP health checks and optional smoke tests; stores a per-command audit log in a dedicated `deployment_log` DynamoDB table; automatically rolls back within a configurable window on health check failure; and files structured incident tickets on unrecoverable failures. Alert-triggered incidents are supported via reactive ticket pickup. A deployment mutex prevents concurrent deployments to the same environment.

- **Type**: Feature (specialized agent type configuration)
- **Priority**: High
- **Status**: Implemented — `app/services/agent_devops.py` (1306 lines), `app/routers/agent_devops.py` (294 lines), frontend `DevOpsAgentConfigPage.tsx` + `DevOpsRunOutputPanel.tsx` + `DeploymentApprovalPanel.tsx`, E2E spec `frontend/e2e/agent-devops.spec.ts` (sections 659–664)
- **Owning area**: Agent platform / infrastructure automation
- **Who is affected**: Platform admins and SREs managing deployment automation; AGENT-009 (QA approval triggers auto-deploy to staging); developers whose code gets deployed
- **Cross-references**: SEC-021 (command injection — deploy commands, health check URLs in curl commands), SECOPS-007 (dev/prod parity — `DEVOPS_AGENT_EXECUTE_COMMANDS` gate, mock deployment in dev, real AWS/k8s/Terraform in prod), AGENT-009 (QA approval → `qa_approved` status triggers DevOps agent via `auto_deploy_on_qa_approved` flag)

---

## 2. Current-State Investigation (what exists today)

### Service layer: `app/services/agent_devops.py` (1306 lines)

**Table bootstrap** (`agent_devops.py:66–111`): `ensure_tables()` calls `coder_svc.ensure_tables()` for the shared `agent_types`/`agent_runs` tables, then creates the `deployment_log` table (`S.deployment_log_table_name`, default `"deployment_log"`) with a GSI named `ByEnv` (PK=`gsi_env_pk:S`, SK=`gsi_env_sk:N`). Per CLAUDE.md gotcha: `gsi_env_sk` is numeric and declared `AttributeType: "N"` in the `AttributeDefinitions` (line 91) — correct handling for the numeric sort key issue described in the codebase docs.

**Config validation** (`agent_devops.py:148–191`): `validate_devops_config(config)` enforces:
- At least one environment, unique names
- Each environment has `deploy_commands` non-empty
- Health check URLs start with `http://` or `https://`
- Production environments (name contains "prod") must have `rollback_commands` and `requires_approval=True`

This check is applied in the router at `agent_devops.py:80` before persisting. A config with a production environment missing rollback commands is rejected with 422.

**Deployment mutex** (`agent_devops.py:135–140`): `_mutex_pk(environment)` returns `MUTEX#ENV#{environment}`. A mutex item is written to `T.agent_workers` at deployment start with TTL `_MUTEX_TTL_SECONDS = 3600`. On cleanup or rollback, the item is deleted. Prevents two agent runs deploying to the same environment simultaneously.

**Deployment plan generation** (`agent_devops.py:490–540`): `build_deployment_plan(config, ticket, environment)` returns a dict with `environment`, `deploy_commands` list, `health_check_urls`, `rollback_commands`, `smoke_test_command`, `rollback_window_seconds`, `requires_approval`, and `version` (derived from ticket metadata). Also generates a Markdown plan summary rendered by `_render_plan_markdown()` (line 512–530). The plan is stored on the agent_runs META item before approval is requested.

**Approval gate** (`agent_devops.py:540–640`): `request_approval(run_id, plan, user_id)` stores an `approval_requested_at` timestamp and `approval_status="pending"` on the run META item. The approval timeout is `_APPROVAL_TIMEOUT_SECONDS = 86400` (24h) — a pending approval auto-expires after 24h per the security notes. `process_approval(run_id, approved, approver_sub, reason)` checks for expiry, then sets `approval_status` to `"approved"` or `"rejected"`.

In the router, `POST /ui/agents/runs/{run_id}/approve` and `POST /ui/agents/runs/{run_id}/reject` both call `process_approval()` and are gated by `require_admin_or_root_csrf`.

**Deployment execution** (`agent_devops.py:640–780`): `execute_deployment(run_id, config, deployment_id, environment)` iterates `deploy_commands`, writing each to `T.deployment_log` at PK `DEPLOY#{deployment_id}` / SK `STEP#{step_number:04d}` (line ~575). Secret scrubbing is applied via `_SECRET_KEYS` regex patterns (line 549) before writing to the log — values matching `password`, `secret`, `token`, `api_key`, `apikey`, `aws_secret` are replaced with `[REDACTED]`. The GSI item for environment history uses `gsi_env_pk = ENV#{environment}`, `gsi_env_sk = created_at` (numeric).

In dev mode (`S.agent_devops_execute_commands = False`), the execution step runs as an in-memory mock: each step is recorded with `exit_code=0` and `duration_seconds` randomly assigned.

**Health checks and rollback** (`agent_devops.py:780–900`): `run_health_checks(config, environment)` issues `curl -sf {url}` commands (in real mode) or returns mock `{healthy: True}` dicts (in dev). If any health check returns `exit_code != 0` within the `rollback_window_seconds`, `trigger_rollback(run_id, deployment_id, environment, config)` executes `rollback_commands` in order and files an incident ticket via `file_incident_ticket()`.

The curl command is built at line ~1217:
```python
"command": f"curl -sf {h['url']}"
```
`h['url']` is the health check URL from config, validated to start with `http://` or `https://`. However, after the scheme check, the URL is not further validated — a URL containing shell metacharacters (e.g., spaces, semicolons) would be unsafe when executed via a shell. This is the SEC-021 adjacency for this service.

**Incident auto-filing** (`agent_devops.py:720–780`): `file_incident_ticket(deployment_id, environment, reason, logs)` calls `tickets_svc.STORE.create_ticket()` with labels `["type:incident", "source:devops_agent", "severity:critical"]` and stores the timeline, log tail, and affected services in `metadata`. Optionally creates the ticket in `devops_config.incident_space_id`.

**Deployment audit log retrieval** (`agent_devops.py:940–1010`): `get_deployment_log(deployment_id, limit)` queries `T.deployment_log` at PK `DEPLOY#{deployment_id}`, SK ascending. Returns all steps with command, output, exit_code, duration, and redacted flag.

**Metrics** (`agent_devops.py:1020–1100`): `get_devops_metrics(agent_type_id, period_days)` queries the `gsi_type_date` rollup items on `agent_runs` filtered by `pk = DEVOPS#{agent_type_id}`. Aggregates `deployment_count`, `success_rate`, `mean_time_to_recovery_seconds`, `rollback_count`, `incident_count`. The GSI rollup pattern writes a daily snapshot item at deployment completion.

**Runbook matching** (`agent_devops.py:1100–1150`): `match_runbook(ticket, runbooks)` iterates configured runbooks and matches `trigger_label` against ticket labels. Returns the matching runbook's `steps` list if found.

**Execution gate** (`app/core/settings.py:2214`): `S.agent_devops_execute_commands` defaults to `False`. Same in-memory mock pattern as AGENT-008/009.

### Router: `app/routers/agent_devops.py` (294 lines)

Registered in `app/main.py:769–770`. All under `/ui/agents`, gated by `require_admin_or_root`. Key endpoints:
- `PUT /ui/agents/types/{type_id}/devops-config` — save config (calls `validate_devops_config()` before saving)
- `POST /ui/agents/types/{type_id}/devops-config/validate` — validation without save
- `GET /ui/agents/types/{type_id}/devops-eligible-tickets` — preview filter
- `POST /ui/agents/runs/{run_id}/approve` — approve production deployment
- `POST /ui/agents/runs/{run_id}/reject` — reject deployment
- `GET /ui/agents/runs/{run_id}/deployment-log` — per-command audit log
- `POST /ui/agents/types/{type_id}/test-devops-workflow` — dry-run
- `GET /ui/agents/devops/metrics` — frequency/MTTR metrics

### Frontend

`DevOpsAgentConfigPage.tsx` (route `/agents/types/:typeId/devops`) has Config, Eligible Tickets, and Metrics tabs. `DeploymentApprovalPanel.tsx` renders the pending approval interface with plan Markdown, approve/reject buttons, and approver identity capture.

### E2E spec: `frontend/e2e/agent-devops.spec.ts`

Six sections: 659 (DevOps Config API), 660 (Deployment & Health Check API), 661 (Approval & Rollback API), 662 (DevOps Config UI), 663 (Edge Cases), 664 (Negative Tests).

---

## 3. Gap / Threat Analysis

### SEC-021: Health check URL shell injection (latent)

`run_health_checks()` at line ~1217 builds `f"curl -sf {h['url']}"`. While the config validator rejects URLs not starting with `http(s)://`, it does not prevent URLs like `https://example.com;evil_cmd` or `https://example.com && rm -rf /`. This is a latent injection that becomes exploitable when `DEVOPS_AGENT_EXECUTE_COMMANDS=1`. Additionally, `deploy_commands` are stored as free-form strings in the config (validated only for non-empty) — an admin could set `deploy_commands=["terraform apply; rm -rf /"]`. Since these are admin-configured, the threat model is privilege escalation or misconfiguration; lateral movement within the worker session.

### Secret scrubbing completeness

`_SECRET_KEYS = ("password", "secret", "token", "api_key", "apikey", "aws_secret")` covers common cases but misses `access_key`, `private_key`, `bearer`, `credential`, `cert`. The regex pattern `rf"({key}[=:\s]+)\S+"` is case-insensitive but only scrubs the value immediately following the key — multi-line environment variable blocks may not be fully scrubbed.

### Approval expiry race condition

`process_approval()` checks `now_ts() - requested_at > _APPROVAL_TIMEOUT_SECONDS` in Python. A concurrent request at the exact expiry boundary could slip through if two workers check simultaneously. A DynamoDB conditional update with TTL-based expiry would be more reliable for production.

### Auto-deploy on QA approval: missing trigger

`auto_deploy_on_qa_approved` (config field, default `False`) is stored in the config map but the actual polling/trigger logic that watches for `qa_approved` tickets and kicks off the DevOps workflow is not yet wired. The Worker Agent Framework's (AGENT-003) polling loop would need to filter on `qa_approved` status when this flag is set. Currently the only trigger is manual ticket creation with the appropriate labels.

---

## 4. Proposed Design / Fix

### SEC-021 fix for health check commands

Replace shell-string construction with argv:
```python
# In dev/mock mode: return mock result
# In real mode: use subprocess.run(["curl", "-sf", url], ...)
import subprocess
result = subprocess.run(
    ["curl", "--silent", "--fail", url],
    capture_output=True, timeout=timeout, shell=False
)
```
For deploy commands stored as free strings, add a `shlex.split()` parse step (fail on parse error) and execute as argv, OR enforce an allowlist of safe command prefixes (e.g., `["terraform", "kubectl", "aws", "docker", "helm"]`). Document that deploy commands must be whitespace-separated tokens with no shell metacharacters.

### Auto-deploy trigger

In the AGENT-003 Worker Agent Framework's polling loop, add:
```python
if devops_config.get("auto_deploy_on_qa_approved"):
    eligible += find_devops_eligible_tickets(
        status_filter="qa_approved",
        label_filter=devops_config.get("deploy_ticket_labels", ["type:deployment"]),
    )
```
File this as a follow-up task on AGENT-003 with a reference to `auto_deploy_on_qa_approved`.

### Dev/Prod parity (SECOPS-007)

Current parity is correct and exemplary:
- `S.agent_devops_execute_commands = False` (dev default): `execute_deployment()` runs in-memory mock; no subprocess, no real AWS CLI/Terraform, no outbound HTTP to health check URLs.
- `S.agent_devops_execute_commands = True` (prod): real subprocess execution via Worker Agent Framework terminal sessions (AGENT-002).
- `T.deployment_log` → DDB Local (dev, port 8001) / AWS DynamoDB (prod): same boto3 code path, endpoint_url from `S`.
- S3 for log artifacts → in-process moto (dev) / real S3 (prod): same `boto3` calls via `app/core/aws`.

No changes to the parity design needed.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_agent_devops.py`)

Key cases:
- `test_validate_config_no_environments`: empty environments list → errors["At least one environment required"]
- `test_validate_config_prod_no_approval`: production env with `requires_approval=False` → error
- `test_validate_config_invalid_health_url`: `health_check_urls=["ftp://bad"]` → error
- `test_secret_scrubbing`: deploy log step output containing `AWS_SECRET_ACCESS_KEY=abc123` → stored with `[REDACTED]`
- `test_build_deployment_plan`: returns dict with `deploy_commands`, `health_check_urls`, `rollback_commands`, `requires_approval`, `version`
- `test_request_approval_stores_pending`: after `request_approval()`, run META has `approval_status="pending"`, `approval_requested_at > 0`
- `test_process_approval_approved`: `process_approval(run_id, approved=True, approver="root")` → META has `approval_status="approved"`
- `test_process_approval_expired`: set `approval_requested_at = now_ts() - 90000` → `process_approval()` raises or returns `expired`
- `test_deployment_mutex_prevents_concurrent`: acquire mutex, try acquire again → second attempt fails with appropriate error
- `test_deployment_log_steps`: `execute_deployment()` in mock mode → `get_deployment_log()` returns N step records
- `test_file_incident_ticket`: health check fails → `file_incident_ticket()` creates ticket with `type:incident` label and `metadata.timeline`
- `test_match_runbook`: ticket with `trigger_label="cert-renewal"` → returns matching runbook steps
- `test_get_devops_metrics_empty`: no completed runs → returns zeros without error

### Playwright E2E

Existing `frontend/e2e/agent-devops.spec.ts` sections 659–664. Key:
- Section 661.1: approval endpoint returns `approval_status="approved"` after POST approve
- Section 661.2: reject endpoint returns `approval_status="rejected"`
- Section 663: mutex prevents concurrent deployments (second deploy returns 409 or queues)

Run: `cd frontend && npx playwright test e2e/agent-devops.spec.ts`

### Manual QA steps

1. Create DevOps agent type; set config with staging (no approval) and production (requires approval) environments
2. Create a `type:deployment`-labeled ticket → verify appears in `devops-eligible-tickets`
3. Dry-run workflow → verify states include `planned → approval_pending → executing → health_checking → monitoring`
4. Navigate `/agents/types/{typeId}/devops` → Config tab shows environment cards; approval badge on production env
5. Trigger a staging deployment (no approval needed) → deployment log shows step records
6. Trigger a production deployment → approval panel shows; approve → deployment proceeds

### Rollout

- Ship with `DEVOPS_AGENT_EXECUTE_COMMANDS=0` (current default). No prod impact.
- SEC-021 fix (argv execution for health checks, deploy command allowlist) is required before enabling execution.
- `auto_deploy_on_qa_approved` trigger wiring: file as AGENT-003 follow-up.
- Production readiness checklist: EC2/k8s worker image has Terraform, kubectl, aws CLI installed; deployment secrets injected via terminal environment (not stored in devops_config).

**Effort estimate**: M (service implemented; SEC-021 health-check argv fix ~0.5 days; auto-deploy trigger ~1 day on AGENT-003 side; missing unit tests ~1.5 days).
