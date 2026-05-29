# AGENT-010: DevOps/SRE Agent

**Ticket**: AGENT-010
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-14 days
**Dependencies**: AGENT-001 (LLM Provider Key Management), AGENT-002 (Terminal Worker Provisioning), AGENT-003 (Worker Agent Framework & Lifecycle), AGENT-004 (Worker Fleet Management UI), AGENT-005 (Agent Memory & Context Injection), AGENT-006 (Terminal Monitoring & Feedback Loop)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-010 defines the DevOps/SRE Agent type -- an agent configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously execute infrastructure operations. The DevOps Agent picks up tickets labeled `type:deployment` or `type:infrastructure`, reads the deployment or infrastructure change specification, executes the required commands (Terraform, kubectl, AWS CLI, shell scripts), verifies the result via health checks and smoke tests, and produces a structured deployment report. If any operation fails, the agent automatically rolls back within a configurable window and files an incident ticket with logs and diagnostic data. The agent can also be triggered reactively by monitoring alerts to investigate and remediate production issues.

DevOps Agents are configured with target environments (staging, production), deployment scripts and runbooks, health check endpoints, rollback procedures, monitoring integrations, and incident escalation policies. The agent enforces a strict approval gate for production deployments: it prepares the deployment plan and waits for human approval before executing against production environments.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Platform Admin | As an admin, I want to register a DevOps Agent with environment-specific config. | Agent type created with environments, deployment scripts, health checks; appears in registry. |
| Platform Admin | As an admin, I want automatic deployment to staging after QA approval. | Agent picks up `qa_approved` tickets with `type:deployment` label; deploys to staging. |
| Platform Admin | As an admin, I want production deployments to require human approval. | Agent generates deployment plan; blocks execution until admin approves via feedback loop. |
| Platform Admin | As an admin, I want automatic rollback if health checks fail. | Health check failure within rollback window triggers automatic revert; incident ticket filed. |
| Platform Admin | As an admin, I want the agent to respond to monitoring alerts. | Alert-triggered tickets with `type:incident` label are picked up; agent investigates. |
| Platform Admin | As an admin, I want infrastructure changes tracked as code. | Agent creates audit trail: commands executed, outputs, duration, success/failure. |
| Ticket Author | As a ticket author, I want to see deployment status on my ticket. | Ticket updated with deployment log: environment, version, health status. |
| Ticket Author | As a ticket author, I want incidents auto-filed with diagnostic data. | Incident ticket has logs, metrics snapshot, timeline, affected services. |
| SRE | As an SRE, I want the agent to handle routine operations autonomously. | Certificate renewals, scaling events, config changes execute without human intervention. |
| Project Manager | As a PM, I want deployment frequency and failure rate metrics. | Dashboard shows deployments per day, success rate, mean time to recovery. |

### 1.3 Why This Is Needed

Infrastructure operations are error-prone, time-sensitive, and repetitive. Manual deployments require context-switching by skilled engineers, introduce human error, and create bottlenecks during off-hours. The DevOps Agent automates the routine operations (deploy, verify, rollback) while preserving human oversight for high-risk changes (production deployments). By capturing every command and output in a structured deployment log, the agent also creates an audit trail that simplifies post-incident reviews. Alert-triggered investigation reduces mean time to detection (MTTD) and mean time to recovery (MTTR) by having the agent begin diagnosis immediately when anomalies are detected.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **LLM Provider Key Management** (AGENT-001): API key management for coding tools used in incident investigation.
- **Terminal Worker Provisioning** (AGENT-002): SSH terminals with AWS CLI, Terraform, kubectl pre-installed.
- **Worker Agent Framework & Lifecycle** (AGENT-003): Generic worker loop. DevOps Agent plugs in with deployment-specific behavior.
- **Worker Fleet Management UI** (AGENT-004): Fleet overview for DevOps agent instances.
- **Agent Memory & Context Injection** (AGENT-005): Injects runbook context and infrastructure documentation into agent sessions.
- **Terminal Monitoring & Feedback Loop** (AGENT-006): Terminal output capture, approval gates for production deployments, and escalation for failed rollbacks. Cloud provider credentials injected via terminal environment.
- **Ticket System** (`app/services/tickets.py`): `TicketStore` for deployment and incident tickets.
- **EC2 Launcher** (INFRA-003): Instance provisioning with health monitoring.
- **K8s Launcher** (INFRA-004): Container provisioning and lifecycle.
- **Instance Monitoring** (INFRA-008): Health check infrastructure.
- **Compute Cost Tracking** (INFRA-005): Resource cost data.

### 2.2 Gaps

1. No agent type configuration for deployment workflows (environments, scripts, health checks).
2. No deployment plan generation and approval gate mechanism.
3. No health check execution and automated rollback pipeline.
4. No incident ticket auto-filing with diagnostic data (logs, metrics, timeline).
5. No monitoring alert-to-ticket bridge for reactive agent triggering.
6. No deployment audit log with command-level granularity.
7. No environment-specific configuration (staging vs production) with different approval requirements.
8. No certificate renewal, scaling, or config change automation workflows.
9. No mean-time-to-recovery (MTTR) tracking or deployment frequency metrics.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentTypes Table Extension (DevOps Config)

Additional fields on the `agent_types` table when `agent_type = "devops"`:

| Field | Type | Description |
|-------|------|-------------|
| `devops_config` | M (map) | DevOps-specific configuration |
| `devops_config.environments` | L (list of M) | List of target environments |
| `devops_config.environments[].name` | S | Environment name (`staging`, `production`, `dev`) |
| `devops_config.environments[].requires_approval` | BOOL | Whether human approval is required before execution |
| `devops_config.environments[].deploy_commands` | L (list of S) | Ordered deployment commands |
| `devops_config.environments[].rollback_commands` | L (list of S) | Rollback commands (executed in order on failure) |
| `devops_config.environments[].health_check_urls` | L (list of S) | URLs to GET after deployment; expect 200 |
| `devops_config.environments[].health_check_timeout_seconds` | N | Time to wait for health checks (default 120) |
| `devops_config.environments[].smoke_test_command` | S (optional) | Command to run after health checks pass |
| `devops_config.environments[].rollback_window_seconds` | N | Auto-rollback if health degrades within this window (default 300) |
| `devops_config.environments[].env_vars` | M (map of S) | Environment variables to set before deployment |
| `devops_config.deploy_ticket_labels` | L (list of S) | Labels that trigger deployment pickup (default `["type:deployment"]`) |
| `devops_config.infra_ticket_labels` | L (list of S) | Labels for infra tasks (default `["type:infrastructure"]`) |
| `devops_config.incident_ticket_labels` | L (list of S) | Labels for alert-triggered investigation (default `["type:incident"]`) |
| `devops_config.auto_deploy_on_qa_approved` | BOOL | Auto-deploy to staging when ticket reaches `qa_approved` (default false) |
| `devops_config.coding_tool` | S | `claude_code` or `codex` for investigation tasks (default `claude_code`) |
| `devops_config.max_operation_time_seconds` | N | Max time for any single operation (default 1800) |
| `devops_config.incident_space_id` | S (optional) | Ticket space for auto-filed incidents |
| `devops_config.monitoring_endpoints` | L (list of M) | `{name, url, metric_type, threshold}` for post-deploy monitoring |
| `devops_config.runbooks` | L (list of M) | `{trigger_label, name, steps}` -- predefined operation sequences |

#### 3.1.2 DeploymentLog Table

Stores per-deployment audit trail with command-level granularity.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `DEPLOY#{deployment_id}` |
| `sk` | S | `STEP#{step_number:04d}` |
| `deployment_id` | S | UUID hex |
| `agent_run_id` | S | Parent agent run |
| `ticket_id` | S | Source ticket |
| `environment` | S | Target environment name |
| `step_number` | N | Execution order (0-based) |
| `step_type` | S | `command`, `health_check`, `smoke_test`, `rollback`, `approval_wait` |
| `command` | S | Command executed |
| `exit_code` | N | Exit code (null if pending) |
| `stdout_tail` | S | Last 500 lines of stdout |
| `stderr_tail` | S | Last 200 lines of stderr |
| `started_at` | N | Unix timestamp |
| `completed_at` | N | Unix timestamp |
| `duration_seconds` | N | Execution duration |
| `status` | S | `pending`, `running`, `success`, `failed`, `skipped`, `rolled_back` |

```python
TableDef(
    "deployment_log", "pk", "sk",
    attr_types={"step_number": "N", "exit_code": "N", "started_at": "N",
                "completed_at": "N", "duration_seconds": "N"},
),
```

#### 3.1.3 AgentRuns Table Extension (DevOps Output)

| Field | Type | Description |
|-------|------|-------------|
| `devops_output` | M (map) | Structured output from the DevOps Agent run |
| `devops_output.deployment_id` | S | Deployment log ID |
| `devops_output.environment` | S | Target environment |
| `devops_output.operation_type` | S | `deployment`, `infrastructure`, `incident_response`, `runbook` |
| `devops_output.status` | S | `success`, `failed`, `rolled_back`, `awaiting_approval` |
| `devops_output.version_deployed` | S | Git SHA or version tag deployed |
| `devops_output.steps_total` | N | Total workflow steps |
| `devops_output.steps_completed` | N | Steps successfully completed |
| `devops_output.health_check_results` | L (list of M) | `{url, status_code, response_time_ms, healthy}` |
| `devops_output.smoke_test_result` | M | `{command, exit_code, passed}` |
| `devops_output.rollback_executed` | BOOL | Whether rollback was triggered |
| `devops_output.rollback_success` | BOOL | Whether rollback succeeded |
| `devops_output.incident_ticket_id` | S (optional) | Auto-filed incident ticket |
| `devops_output.total_duration_seconds` | N | Wall-clock time |
| `devops_output.approval_received_at` | N (optional) | When human approved (if applicable) |
| `devops_output.monitoring_snapshot` | M | Post-deploy metrics snapshot |

#### 3.1.4 Incident Ticket Template

Auto-filed incident tickets use structured `metadata`:

| Field | Type | Description |
|-------|------|-------------|
| `incident_source` | S | `devops_agent` |
| `severity` | S | `P0`, `P1`, `P2`, `P3` |
| `affected_environment` | S | Environment name |
| `affected_services` | L (list of S) | Services impacted |
| `timeline` | S | Markdown timeline of events |
| `deployment_id` | S | Associated deployment (if any) |
| `agent_run_id` | S | DevOps Agent run |
| `error_logs` | S | Relevant error logs (truncated to 10KB) |
| `metrics_snapshot` | S | JSON snapshot of key metrics at incident time |
| `rollback_status` | S | `not_needed`, `success`, `failed` |
| `remediation_steps` | S | Steps taken by agent before escalating |

### 3.2 Backend Service (`app/services/agent_devops.py`)

```python
# --- Configuration ---
def get_devops_config(*, agent_type_id: str) -> dict:
def update_devops_config(*, agent_type_id: str, owner_sub: str, config: dict) -> dict:
def validate_devops_config(config: dict) -> list[str]:
    """Validate: at least one environment, health check URLs are valid,
    rollback commands present for production, approval required for prod."""

# --- Ticket Filtering ---
def find_devops_eligible_tickets(*, agent_type_id: str, label_sets: dict,
                                   auto_deploy_on_qa: bool,
                                   limit: int = 10) -> list[dict]:
    """Query tickets matching deployment, infrastructure, or incident labels.
    If auto_deploy_on_qa, also include qa_approved tickets."""

def claim_devops_ticket(*, agent_run_id: str, ticket_id: str, agent_sub: str) -> dict | None:
    """Assign ticket. Set status to deploying (deployment) or investigating (incident)."""

# --- Deployment Plan ---
def generate_deployment_plan(*, ticket: dict, environment: dict,
                               version: str | None) -> dict:
    """Generate structured deployment plan: pre-checks, deploy commands,
    health checks, smoke tests, rollback plan. Returns plan dict for
    human review (if approval required) or direct execution."""

def request_deployment_approval(*, agent_run_id: str, plan: dict,
                                  environment_name: str) -> str:
    """Create feedback request (AGENT-004) with deployment plan details.
    Return feedback_request_id. Agent blocks until approval received."""

# --- Deployment Execution ---
def create_deployment_log(*, deployment_id: str, agent_run_id: str,
                           ticket_id: str, environment: str) -> None:
    """Initialize deployment log record."""

def log_deployment_step(*, deployment_id: str, step_number: int, step_type: str,
                         command: str, exit_code: int | None, stdout_tail: str,
                         stderr_tail: str, started_at: int, completed_at: int,
                         status: str) -> None:

def execute_deployment(*, deployment_id: str, environment: dict,
                        pre_commands: list[str]) -> dict:
    """Execute deploy commands in sequence. Log each step.
    Stop on first failure. Return {success, failed_step, exit_code}."""

# --- Health Checks ---
def run_health_checks(*, health_check_urls: list[str],
                       timeout_seconds: int) -> list[dict]:
    """GET each URL, expect 200. Retry with exponential backoff.
    Return [{url, status_code, response_time_ms, healthy}]."""

def run_smoke_test(*, command: str, timeout_seconds: int) -> dict:
    """Execute smoke test command. Return {command, exit_code, stdout_tail, passed}."""

def monitor_post_deployment(*, monitoring_endpoints: list[dict],
                              window_seconds: int) -> dict:
    """Poll monitoring endpoints during rollback window.
    Return {healthy, anomalies: [{endpoint, metric, value, threshold}]}."""

# --- Rollback ---
def execute_rollback(*, deployment_id: str, environment: dict) -> dict:
    """Execute rollback commands in sequence. Log each step.
    Return {success, failed_step}."""

def should_auto_rollback(*, health_results: list[dict],
                          smoke_result: dict | None,
                          monitoring: dict | None) -> bool:
    """Return True if any health check failed, smoke test failed,
    or monitoring detected anomaly within rollback window."""

# --- Incident Management ---
def investigate_incident(*, ticket: dict, coding_tool: str) -> dict:
    """Use Claude Code / Codex to analyze logs, metrics, and recent changes.
    Return {diagnosis, affected_services, severity, remediation_steps}."""

def build_incident_ticket(*, source_ticket: dict | None, deployment_id: str | None,
                           agent_run_id: str, diagnosis: dict,
                           error_logs: str, metrics_snapshot: dict) -> dict:
    """Construct incident ticket with structured metadata."""

def file_incident_ticket(*, incident_data: dict, space_id: str | None,
                          agent_sub: str) -> str:
    """Create incident ticket. Return ticket ID."""

# --- Runbook Execution ---
def match_runbook(*, ticket: dict, runbooks: list[dict]) -> dict | None:
    """Match ticket labels against runbook triggers. Return matching runbook or None."""

def execute_runbook(*, runbook: dict, deployment_id: str,
                     environment: dict) -> dict:
    """Execute runbook steps sequentially. Log each step.
    Return {completed_steps, failed_step, success}."""

# --- Workflow Orchestrator ---
def build_devops_workflow(*, agent_run_id: str, agent_type_id: str,
                            ticket: dict, operation_type: str) -> list[dict]:
    """Return ordered workflow steps based on operation type:

    For 'deployment':
    1. resolve_environment: determine target environment from ticket
    2. generate_plan: build deployment plan
    3. request_approval: if environment requires it, wait for human approval
    4. execute_deployment: run deploy commands
    5. run_health_checks: verify endpoints are healthy
    6. run_smoke_test: execute smoke test if configured
    7. start_monitoring: begin post-deploy monitoring window
    8. evaluate_health: check for anomalies during rollback window
    9. auto_rollback: if unhealthy, execute rollback + file incident
    10. update_ticket: mark as deployed or rolled_back

    For 'incident_response':
    1. gather_context: collect logs, metrics, recent deployments
    2. investigate: use coding tool to analyze
    3. attempt_remediation: execute safe remediation steps
    4. file_incident: create/update incident ticket
    5. escalate: trigger feedback loop if unresolved

    For 'infrastructure' / 'runbook':
    1. match_runbook: find applicable runbook
    2. execute_runbook: run steps
    3. verify: health checks
    4. update_ticket: mark complete or failed
    """

# --- Metrics ---
def get_devops_metrics(*, period_days: int = 30) -> dict:
    """Aggregate: deployment frequency, success rate, mean time to deploy,
    mean time to recovery, rollback rate, incidents filed."""
```

### 3.3 Backend Router (`app/routers/agent_devops.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/ui/agents/types/{type_id}/devops-config` | `require_admin_session` | Set or update devops_config |
| GET | `/ui/agents/types/{type_id}/devops-config` | `require_admin_session` | Get current devops_config |
| POST | `/ui/agents/types/{type_id}/devops-config/validate` | `require_admin_session` | Validate config |
| GET | `/ui/agents/types/{type_id}/devops-eligible-tickets` | `require_admin_session` | Preview eligible tickets |
| GET | `/ui/agents/runs/{run_id}/devops-output` | `require_admin_session` | Get deployment output |
| GET | `/ui/agents/runs/{run_id}/deployment-log` | `require_admin_session` | Get full deployment audit log |
| POST | `/ui/agents/runs/{run_id}/approve-deployment` | `require_admin_session` | Approve a pending production deployment |
| POST | `/ui/agents/runs/{run_id}/reject-deployment` | `require_admin_session` | Reject a pending deployment |
| GET | `/ui/agents/devops/metrics` | `require_admin_session` | Deployment metrics |
| GET | `/ui/agents/devops/deployments` | `require_admin_session` | List recent deployments across all agents |
| POST | `/ui/agents/types/{type_id}/test-devops-workflow` | `require_admin_session` | Dry-run: preview workflow steps |

**Key request models**:

```python
class EnvironmentConfigIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    requires_approval: bool = False
    deploy_commands: List[str] = Field(..., min_length=1, max_length=50)
    rollback_commands: List[str] = Field(default_factory=list, max_length=50)
    health_check_urls: List[str] = Field(default_factory=list, max_length=20)
    health_check_timeout_seconds: int = Field(default=120, ge=10, le=600)
    smoke_test_command: Optional[str] = Field(default=None, max_length=1000)
    rollback_window_seconds: int = Field(default=300, ge=0, le=3600)
    env_vars: Optional[Dict[str, str]] = None

class DevOpsConfigIn(BaseModel):
    environments: List[EnvironmentConfigIn] = Field(..., min_length=1, max_length=10)
    deploy_ticket_labels: List[str] = Field(default=["type:deployment"], max_length=20)
    infra_ticket_labels: List[str] = Field(default=["type:infrastructure"], max_length=20)
    incident_ticket_labels: List[str] = Field(default=["type:incident"], max_length=20)
    auto_deploy_on_qa_approved: bool = False
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    max_operation_time_seconds: int = Field(default=1800, ge=300, le=14400)
    incident_space_id: Optional[str] = None
    monitoring_endpoints: Optional[List[Dict[str, Any]]] = None
    runbooks: Optional[List[Dict[str, Any]]] = None

class DeploymentApprovalIn(BaseModel):
    approved: bool
    approver_notes: Optional[str] = Field(default=None, max_length=2000)
```

Response models: `DevOpsConfigOut`, `DevOpsOutputOut`, `DeploymentLogOut` (list of step records), `DeploymentApprovalOut` (approval status + plan details), `DevOpsMetricsOut` (deployment_frequency, success_rate, mttr_seconds, rollback_rate, incidents_count), `DeploymentListOut` (recent deployments with status/environment/duration).

Register in `app/main.py`:

```python
from app.routers.agent_devops import router as agent_devops_router
app.include_router(agent_devops_router, prefix="/ui")
```

### 3.4 Deployment Approval Flow

For environments with `requires_approval = true` (typically production):

1. Agent generates deployment plan (commands, health checks, rollback procedure).
2. Agent creates a feedback request (AGENT-004) with the plan rendered as Markdown.
3. Agent enters `awaiting_approval` state -- the Worker Agent Framework pauses the workflow.
4. Admin reviews the plan in the Worker Fleet Management UI (AGENT-004) or via the feedback loop (AGENT-006).
5. Admin calls `POST /approve-deployment` or `POST /reject-deployment`.
6. On approval: agent resumes execution. On rejection: agent marks ticket as `blocked` with rejection notes.

### 3.5 Rollback Decision Logic

After deployment, the agent enters a monitoring phase lasting `rollback_window_seconds`:

1. **Health checks**: GET each URL; all must return 200 within `health_check_timeout_seconds`.
2. **Smoke test**: If configured, execute and expect exit code 0.
3. **Post-deploy monitoring**: Poll `monitoring_endpoints` for anomalies (latency spikes, error rate increase, CPU/memory exceeding thresholds).
4. **Decision**: If any check fails, `should_auto_rollback()` returns `True`. Agent executes rollback commands, files incident ticket, and sets deployment status to `rolled_back`.
5. **Rollback failure**: If rollback commands also fail, agent escalates via feedback loop with full logs. This is a critical escalation requiring immediate human attention.

### 3.6 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface EnvironmentConfig {
  name: string;
  requires_approval: boolean;
  deploy_commands: string[];
  rollback_commands: string[];
  health_check_urls: string[];
  health_check_timeout_seconds: number;
  smoke_test_command?: string;
  rollback_window_seconds: number;
  env_vars?: Record<string, string>;
}

export interface DevOpsConfig {
  environments: EnvironmentConfig[];
  deploy_ticket_labels: string[];
  infra_ticket_labels: string[];
  incident_ticket_labels: string[];
  auto_deploy_on_qa_approved: boolean;
  coding_tool: "claude_code" | "codex";
  max_operation_time_seconds: number;
  incident_space_id?: string;
  monitoring_endpoints?: Array<{ name: string; url: string; metric_type: string; threshold: number }>;
  runbooks?: Array<{ trigger_label: string; name: string; steps: string[] }>;
}

export interface DevOpsOutput {
  deployment_id: string;
  environment: string;
  operation_type: "deployment" | "infrastructure" | "incident_response" | "runbook";
  status: "success" | "failed" | "rolled_back" | "awaiting_approval";
  version_deployed?: string;
  steps_total: number;
  steps_completed: number;
  health_check_results: Array<{ url: string; status_code: number; response_time_ms: number; healthy: boolean }>;
  smoke_test_result?: { command: string; exit_code: number; passed: boolean };
  rollback_executed: boolean;
  rollback_success?: boolean;
  incident_ticket_id?: string;
  total_duration_seconds: number;
  approval_received_at?: number;
}

export interface DeploymentLogStep {
  step_number: number;
  step_type: string;
  command: string;
  exit_code?: number;
  stdout_tail: string;
  stderr_tail: string;
  started_at: number;
  completed_at: number;
  duration_seconds: number;
  status: "pending" | "running" | "success" | "failed" | "skipped" | "rolled_back";
}

export interface DevOpsMetrics {
  deployment_frequency: number;
  success_rate: number;
  mttr_seconds: number;
  rollback_rate: number;
  incidents_count: number;
  period_start: number;
  period_end: number;
}
```

### 3.7 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Add DevOps Agent API functions: `getDevOpsConfig`, `updateDevOpsConfig`, `validateDevOpsConfig`, `getDevOpsEligibleTickets`, `getDevOpsOutput`, `getDeploymentLog`, `approveDeployment`, `rejectDeployment`, `getDevOpsMetrics`, `listDeployments`, `testDevOpsWorkflow`.

### 3.8 Frontend Pages

- **DevOpsAgentConfigPage** (`frontend/src/pages/agents/DevOpsAgentConfigPage.tsx`): Route `/agents/types/:typeId/devops`. Tabbed layout: Config | Environments | Runbooks | Deployments | Metrics. `data-testid="devops-config-page"`.
  - **Config tab**: Global settings (ticket labels, auto-deploy toggle, coding tool, operation timeout, incident space). `data-testid="devops-config-tab"`.
  - **Environments tab**: Accordion for each environment with: name, approval toggle, deploy commands editor, rollback commands editor, health check URLs, smoke test command, rollback window slider, env vars editor. Add/remove environment buttons. `data-testid="devops-environments-tab"`.
  - **Runbooks tab**: List of runbooks with trigger label, name, steps editor. Add/remove runbook. `data-testid="devops-runbooks-tab"`.
  - **Deployments tab**: Table of recent deployments with: ticket ID, environment, status badge, version, duration, agent name. Click to expand deployment log. `data-testid="devops-deployments-tab"`.
  - **Metrics tab**: Deployment frequency chart, success rate gauge, MTTR trend, rollback rate, incidents count. `data-testid="devops-metrics-tab"`.

- **DeploymentApprovalPanel** (`frontend/src/pages/agents/DeploymentApprovalPanel.tsx`): Shown when a deployment is `awaiting_approval`. Displays: deployment plan (commands, environment, version), health check config, rollback plan. Approve/Reject buttons with notes field. `data-testid="deployment-approval-panel"`.

- **DevOpsRunOutputPanel** (`frontend/src/pages/agents/DevOpsRunOutputPanel.tsx`): Embedded in Agent Run detail page. Shows: deployment timeline (step-by-step with status icons), health check results (green/red badges), smoke test result, monitoring snapshot, rollback status, incident ticket link. `data-testid="devops-output-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_devops.py` | DevOps Agent config, deployment execution, health checks, rollback, incident management |
| `app/routers/agent_devops.py` | DevOps config CRUD, deployment log, approval, metrics endpoints |
| `frontend/src/pages/agents/DevOpsAgentConfigPage.tsx` | DevOps Agent configuration + environments + metrics UI |
| `frontend/src/pages/agents/DeploymentApprovalPanel.tsx` | Production deployment approval UI |
| `frontend/src/pages/agents/DevOpsRunOutputPanel.tsx` | DevOps run output detail panel |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `deployment_log` TableDef |
| `app/core/settings.py` | Add `deployment_log_table_name` setting |
| `app/core/tables.py` | Add `deployment_log` table handle |
| `app/services/tickets.py` | Add `deploying`, `deployed`, `investigating` to `_TICKET_STATUSES` |
| `app/main.py` | Register `agent_devops_router` |
| `app/models.py` | Add `DevOpsConfigIn`, `EnvironmentConfigIn`, `DevOpsOutputOut`, `DeploymentLogOut`, `DeploymentApprovalIn`, `DevOpsMetricsOut` models |
| `frontend/src/api/types.ts` | Add `DevOpsConfig`, `EnvironmentConfig`, `DevOpsOutput`, `DeploymentLogStep`, `DevOpsMetrics` types |
| `frontend/src/api/endpoints/agents.ts` | Add DevOps Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/devops` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-devops.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let ticketId: string;
let runId: string;
let deploymentId: string;
// Root = admin who configures agents
```

### 5.3 Section 659: DevOps Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 659.1 | Create DevOps Agent type with environments | POST agent type `agent_type=devops`; PUT devops-config with 2 environments (staging + production); 200 |
| 659.2 | Get devops config | GET devops-config; 200; `environments` array has 2 entries; production has `requires_approval=true` |
| 659.3 | Validate config missing rollback for production | POST validate with production env having empty `rollback_commands`; validation errors returned |
| 659.4 | Update with runbook and monitoring | PUT with runbooks array and monitoring_endpoints; 200; values persisted |

### 5.4 Section 660: Deployment & Health Check API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 660.1 | Create deployment ticket | Create ticket with `labels=["type:deployment"]`; status = `open` |
| 660.2 | Eligible tickets returns deployment ticket | GET devops-eligible-tickets; array includes the ticket |
| 660.3 | Get deployment log from completed run | GET deployment-log for a run; 200; array of steps with `step_type`, `status`, `duration_seconds` |
| 660.4 | DevOps output shows health check results | GET devops-output; 200; `health_check_results` array present; each has `url`, `healthy` |

### 5.5 Section 661: Approval & Rollback API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 661.1 | Pending production deployment requires approval | DevOps output `status = "awaiting_approval"` for production environment |
| 661.2 | Approve deployment advances execution | POST approve-deployment; 200; devops output status changes from `awaiting_approval` |
| 661.3 | Reject deployment blocks ticket | POST reject-deployment with notes; 200; ticket status = `blocked` |
| 661.4 | Rollback creates incident ticket | When health check fails, devops output has `rollback_executed=true` and `incident_ticket_id` set |

### 5.6 Section 662: DevOps Config UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 662.1 | DevOps config page loads | Navigate `/agents/types/{typeId}/devops`; `[data-testid="devops-config-page"]` visible |
| 662.2 | Environments tab shows configured envs | Click "Environments" tab; `[data-testid="devops-environments-tab"]` visible; 2 environment accordions |
| 662.3 | Deployments tab lists recent deployments | Click "Deployments" tab; `[data-testid="devops-deployments-tab"]` visible; table has rows |
| 662.4 | Metrics tab shows deployment frequency | Click "Metrics" tab; `[data-testid="devops-metrics-tab"]` visible; deployment frequency chart present |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Agent type not found | 404 | "Agent type not found" |
| Agent type is not devops | 409 | "Agent type is not configured as devops" |
| No environments configured | 422 | "At least one environment is required" |
| Duplicate environment names | 422 | "Environment names must be unique" |
| Health check URL not valid HTTP(S) | 422 | "Health check URLs must be valid HTTP or HTTPS URLs" |
| Production env without rollback commands | 422 | "Production environment must have rollback commands" |
| Deployment already in progress for this ticket | 409 | "A deployment is already in progress for this ticket" |
| Approval timeout (no response within 24h) | 200 | Agent auto-rejects and marks ticket as `blocked` |
| All health checks failed | 200 | Auto-rollback triggered; incident ticket filed |
| Rollback commands also failed | 200 | Critical escalation via feedback loop |
| Run not found | 404 | "Agent run not found" |
| Not admin | 403 | "Admin access required" |

---

## 7. Security Considerations

- **Admin-only access**: All DevOps Agent endpoints require `require_admin_session`.
- **Credential isolation**: Cloud provider credentials are stored in the Agent Secrets Vault (AGENT-006), never in devops_config. Credentials are injected into the terminal environment at provisioning time and scrubbed from deployment logs.
- **Production approval gate**: Production deployments always require human approval. The agent cannot bypass this requirement. Approval is logged with the approver's identity and timestamp.
- **Command sanitization**: Deploy and rollback commands in the config are validated against an allowlist of safe command prefixes (terraform, kubectl, aws, docker, npm, etc.). Raw shell commands require explicit admin opt-in.
- **Log scrubbing**: Deployment log stdout/stderr are scanned for secrets (API keys, passwords, tokens) before storage. Matches are replaced with `[REDACTED]`.
- **Rollback isolation**: Rollback commands run in the same terminal session as the deployment to ensure the same environment state. No cross-environment rollback is possible.
- **Incident data retention**: Incident ticket metadata (logs, metrics snapshots) is retained for 180 days for compliance. Older data is archived to S3.
- **Monitoring endpoint authentication**: Monitoring URLs support Bearer token authentication via secrets stored in AGENT-006.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Health check polling during rollback window | Poll every 10 seconds; exponential backoff on transient failures |
| Large deployment logs (50+ steps) | Paginated query on deployment_log table; SK sort ensures order |
| Concurrent deployments to same environment | Mutex via conditional update: only one active deployment per environment |
| Monitoring endpoint latency | 5-second timeout per endpoint; parallel requests |
| Deployment log storage growth | DDB TTL on log entries (90 days); older logs archived |
| Approval wait blocking agent instance | Agent enters idle state during approval; terminal kept alive but releases CPU |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (LLM Provider Key Management) | AGENT-001 | Required |
| AGENT-002 (Terminal Worker Provisioning) | AGENT-002 | Required |
| AGENT-003 (Worker Agent Framework & Lifecycle) | AGENT-003 | Required |
| AGENT-004 (Worker Fleet Management UI) | AGENT-004 | Required |
| AGENT-005 (Agent Memory & Context Injection) | AGENT-005 | Required |
| AGENT-006 (Terminal Monitoring & Feedback Loop) | AGENT-006 | Required (approval gates, rollback escalation, terminal output) |
| INFRA-003 (EC2 Launcher) | INFRA-003 | Optional (infrastructure provisioning tasks) |
| INFRA-004 (K8s Launcher) | INFRA-004 | Optional (container provisioning tasks) |
| INFRA-008 (Instance Monitoring) | INFRA-008 | Optional (health check infrastructure) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-012 (Project Manager) | Uses deployment metrics for project reporting |
