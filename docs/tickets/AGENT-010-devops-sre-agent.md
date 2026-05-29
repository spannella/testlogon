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

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DevOps/SRE Agent System Architecture                   │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ Ticket System│   │ Monitoring   │   │ AGENT-009    │
  │ (DynamoDB)   │   │ Alerts       │   │ QA Agent     │
  │              │   │              │   │              │
  │ type:deploy  │   │ P0/P1/P2/P3 │   │ qa_approved  │
  │ type:infra   │   │ alert events │   │ tickets      │
  │ type:incident│   │              │   │              │
  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
         │                  │                   │
         └──────────────────┼───────────────────┘
                            │ poll / SSE event
                            ▼
  ┌─────────────────┐  ┌────────────────────────────┐  ┌──────────────────┐
  │ Worker Agent    │─▶│   DevOps Agent Core         │─▶│ Terminal Worker  │
  │ Framework       │  │   (agent_devops.py)          │  │ (SSH session)    │
  │ (AGENT-003)     │  │                              │  │                  │
  │                 │  │ ┌──────────────────────────┐ │  │ terraform apply  │
  │ lifecycle mgmt  │  │ │ Deployment Workflow:     │ │  │ kubectl apply    │
  │ polling loop    │  │ │ 1. claim_ticket          │ │  │ aws cli          │
  │ heartbeat       │  │ │ 2. generate_plan         │ │  │ docker commands  │
  │                 │  │ │ 3. request_approval*     │ │  │ health checks    │
  └─────────────────┘  │ │ 4. execute_deployment    │ │  └────────┬─────────┘
                       │ │ 5. run_health_checks     │ │           │
                       │ │ 6. run_smoke_test        │ │           │ terminal output
                       │ │ 7. monitor_post_deploy   │ │           ▼
                       │ │ 8. auto_rollback?        │ │  ┌──────────────────┐
                       │ │ 9. update_ticket         │ │  │ Terminal Monitor  │
                       │ │ *production only         │ │  │ (AGENT-006)      │
                       │ └──────────────────────────┘ │  │                  │
                       │                              │  │ output capture   │
                       │ ┌──────────────────────────┐ │  │ approval gates   │
                       │ │ Incident Workflow:       │ │  │ escalation       │
                       │ │ 1. gather_context        │ │  └──────────────────┘
                       │ │ 2. investigate (LLM)     │ │
                       │ │ 3. attempt_remediation   │ │
                       │ │ 4. file_incident         │ │
                       │ │ 5. escalate              │ │
                       │ └──────────────────────────┘ │
                       └──────────┬───────────────────┘
                                  │
              ┌───────────────────┼──────────────────┐
              │                   │                  │
              ▼                   ▼                  ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │ Deployment   │   │ S3           │   │ Feedback Loop│
    │ Log Table    │   │              │   │ (AGENT-006)  │
    │ (DynamoDB)   │   │ logs/        │   │              │
    │              │   │ artifacts/   │   │ approval     │
    │ pk=DEPLOY#id │   │ snapshots/   │   │ request      │
    │ sk=STEP#0001 │   │              │   │ escalation   │
    │              │   └──────────────┘   └──────────────┘
    └──────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │                     Deployment State Machine                         │
  │                                                                      │
  │  ┌─────────┐    ┌───────────┐    ┌────────────────┐                │
  │  │ planned │───▶│ approval  │───▶│ executing      │                │
  │  └─────────┘    │ _pending  │    └────────┬───────┘                │
  │                 └───────────┘             │                         │
  │       ┌────────────────────┐             │                         │
  │       │ rejected           │◀────────────┤ (approval rejected)     │
  │       └────────────────────┘             │                         │
  │                                          ▼                         │
  │                              ┌───────────────────┐                 │
  │                              │ health_checking    │                 │
  │                              └────────┬──────────┘                 │
  │                                       │                            │
  │                            ┌──────────┴──────────┐                 │
  │                            │                     │                 │
  │                            ▼                     ▼                 │
  │                  ┌──────────────┐      ┌──────────────┐           │
  │                  │ monitoring   │      │ rolling_back │           │
  │                  └──────┬───────┘      └──────┬───────┘           │
  │                         │                     │                    │
  │                         ▼                     ▼                    │
  │                  ┌──────────────┐      ┌──────────────┐           │
  │                  │ success      │      │ rolled_back  │           │
  │                  └──────────────┘      └──────────────┘           │
  │                                                                    │
  │  Any step can transition to: ┌─────────┐ on unrecoverable error   │
  │                               │  error  │                         │
  │                               └─────────┘                         │
  └──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

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

### 3.2 Gaps

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

## 4. Technical Design

### 4.1 Data Model

#### 4.1.1 AgentTypes Table Extension (DevOps Config)

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

#### 4.1.2 DeploymentLog Table

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

### 4.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get DevOps config | `agent_types` | `ATYPE#{type_id}` | `CONFIG` | -- | devops_config map on config item |
| List deployment-eligible tickets | `tickets` | -- | -- | `GSI2PK=SPACE#{id}, GSI2SK=STATUS#qa_approved` | Filter by deploy labels |
| List incident tickets | `tickets` | -- | -- | `GSI3PK=LABEL#type:incident` | Alert-triggered tickets |
| Claim deployment ticket | `tickets` | `TICKET#{id}` | `META` | -- | ConditionExpression: status in (qa_approved, code_complete) AND no active deployment |
| Create deployment log entry | `deployment_log` | `DEPLOY#{id}` | `STEP#{nnnn}` | -- | One item per step |
| Get full deployment log | `deployment_log` | `DEPLOY#{id}` | begins_with `STEP#` | -- | Query all steps, sorted by SK |
| Store DevOps output on run | `agent_runs` | `RUN#{run_id}` | `META` | -- | UpdateExpression: SET devops_output = :out |
| List deployments by environment | `deployment_log` | -- | -- | `GSI1PK=ENV#{env_name}, GSI1SK=started_at` | Recent deployments per env |
| Get incident tickets for deployment | `tickets` | -- | -- | `GSI4PK=DEPLOY#{deployment_id}` | Incidents linked to deployment |
| Deployment mutex (one per env) | `deployment_log` | `MUTEX#ENV#{env}` | `ACTIVE` | -- | Conditional put; delete on completion |
| Metrics aggregation | `agent_runs` | -- | -- | `GSI1PK=AGENT_TYPE#{id}` | Scan completed runs for type |

**Example DynamoDB item -- Deployment log step:**

```json
{
  "pk": {"S": "DEPLOY#dep-abc-123"},
  "sk": {"S": "STEP#0003"},
  "deployment_id": {"S": "dep-abc-123"},
  "agent_run_id": {"S": "run-xyz-456"},
  "ticket_id": {"S": "TICKET-100"},
  "environment": {"S": "staging"},
  "step_number": {"N": "3"},
  "step_type": {"S": "health_check"},
  "command": {"S": "curl -sf https://staging.example.com/health"},
  "exit_code": {"N": "0"},
  "stdout_tail": {"S": "{\"status\":\"ok\",\"version\":\"1.5.2\"}"},
  "stderr_tail": {"S": ""},
  "started_at": {"N": "1748534520"},
  "completed_at": {"N": "1748534521"},
  "duration_seconds": {"N": "1"},
  "status": {"S": "success"}
}
```

**Example DynamoDB item -- Deployment mutex:**

```json
{
  "pk": {"S": "MUTEX#ENV#production"},
  "sk": {"S": "ACTIVE"},
  "deployment_id": {"S": "dep-abc-123"},
  "agent_run_id": {"S": "run-xyz-456"},
  "started_at": {"N": "1748534400"},
  "ttl": {"N": "1748538000"}
}
```

#### 4.1.3 AgentRuns Table Extension (DevOps Output)

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

#### 4.1.4 Incident Ticket Template

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

### 4.3 Backend Service (`app/services/agent_devops.py`)

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
def log_deployment_step(*, deployment_id: str, step_number: int, step_type: str,
                         command: str, exit_code: int | None, stdout_tail: str,
                         stderr_tail: str, started_at: int, completed_at: int,
                         status: str) -> None:
def execute_deployment(*, deployment_id: str, environment: dict,
                        pre_commands: list[str]) -> dict:

# --- Health Checks ---
def run_health_checks(*, health_check_urls: list[str],
                       timeout_seconds: int) -> list[dict]:
def run_smoke_test(*, command: str, timeout_seconds: int) -> dict:
def monitor_post_deployment(*, monitoring_endpoints: list[dict],
                              window_seconds: int) -> dict:

# --- Rollback ---
def execute_rollback(*, deployment_id: str, environment: dict) -> dict:
def should_auto_rollback(*, health_results: list[dict],
                          smoke_result: dict | None,
                          monitoring: dict | None) -> bool:

# --- Incident Management ---
def investigate_incident(*, ticket: dict, coding_tool: str) -> dict:
def build_incident_ticket(*, source_ticket: dict | None, deployment_id: str | None,
                           agent_run_id: str, diagnosis: dict,
                           error_logs: str, metrics_snapshot: dict) -> dict:
def file_incident_ticket(*, incident_data: dict, space_id: str | None,
                          agent_sub: str) -> str:

# --- Runbook Execution ---
def match_runbook(*, ticket: dict, runbooks: list[dict]) -> dict | None:
def execute_runbook(*, runbook: dict, deployment_id: str,
                     environment: dict) -> dict:

# --- Workflow Orchestrator ---
def build_devops_workflow(*, agent_run_id: str, agent_type_id: str,
                            ticket: dict, operation_type: str) -> list[dict]:

# --- Metrics ---
def get_devops_metrics(*, period_days: int = 30) -> dict:
```

### 4.4 API Request/Response Examples

```bash
# --- PUT /ui/agents/types/{type_id}/devops-config ---
curl -X PUT http://localhost:8000/ui/agents/types/devops-agent-001/devops-config \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{
    "environments": [
      {
        "name": "staging",
        "requires_approval": false,
        "deploy_commands": [
          "cd /opt/app && git pull origin main",
          "cd /opt/app && pip install -r requirements.txt",
          "sudo systemctl restart app"
        ],
        "rollback_commands": ["cd /opt/app && git checkout HEAD~1", "sudo systemctl restart app"],
        "health_check_urls": ["https://staging.example.com/health"],
        "health_check_timeout_seconds": 60,
        "smoke_test_command": "curl -sf https://staging.example.com/api/v1/status",
        "rollback_window_seconds": 300
      },
      {
        "name": "production",
        "requires_approval": true,
        "deploy_commands": [
          "kubectl set image deployment/app app=registry.example.com/app:${VERSION}",
          "kubectl rollout status deployment/app --timeout=120s"
        ],
        "rollback_commands": ["kubectl rollout undo deployment/app"],
        "health_check_urls": [
          "https://api.example.com/health",
          "https://api.example.com/readiness"
        ],
        "health_check_timeout_seconds": 120,
        "smoke_test_command": "npx playwright test e2e/smoke.spec.ts",
        "rollback_window_seconds": 600
      }
    ],
    "deploy_ticket_labels": ["type:deployment"],
    "auto_deploy_on_qa_approved": true,
    "coding_tool": "claude_code",
    "max_operation_time_seconds": 1800,
    "incident_space_id": "space-incidents-001"
  }'

# Response 200:
{
  "type_id": "devops-agent-001",
  "devops_config": {
    "environments": [
      {"name": "staging", "requires_approval": false, "deploy_commands": ["..."], "...": "..."},
      {"name": "production", "requires_approval": true, "deploy_commands": ["..."], "...": "..."}
    ],
    "deploy_ticket_labels": ["type:deployment"],
    "infra_ticket_labels": ["type:infrastructure"],
    "incident_ticket_labels": ["type:incident"],
    "auto_deploy_on_qa_approved": true,
    "coding_tool": "claude_code",
    "max_operation_time_seconds": 1800,
    "incident_space_id": "space-incidents-001"
  },
  "updated_at": 1748534400
}

# --- GET /ui/agents/runs/{run_id}/deployment-log ---
curl http://localhost:8000/ui/agents/runs/run-xyz-456/deployment-log \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "deployment_id": "dep-abc-123",
  "environment": "staging",
  "steps": [
    {
      "step_number": 0,
      "step_type": "command",
      "command": "cd /opt/app && git pull origin main",
      "exit_code": 0,
      "stdout_tail": "Already up to date.\n",
      "stderr_tail": "",
      "started_at": 1748534400,
      "completed_at": 1748534402,
      "duration_seconds": 2,
      "status": "success"
    },
    {
      "step_number": 1,
      "step_type": "command",
      "command": "cd /opt/app && pip install -r requirements.txt",
      "exit_code": 0,
      "stdout_tail": "Successfully installed 3 packages\n",
      "stderr_tail": "",
      "started_at": 1748534402,
      "completed_at": 1748534415,
      "duration_seconds": 13,
      "status": "success"
    },
    {
      "step_number": 2,
      "step_type": "command",
      "command": "sudo systemctl restart app",
      "exit_code": 0,
      "stdout_tail": "",
      "stderr_tail": "",
      "started_at": 1748534415,
      "completed_at": 1748534418,
      "duration_seconds": 3,
      "status": "success"
    },
    {
      "step_number": 3,
      "step_type": "health_check",
      "command": "curl -sf https://staging.example.com/health",
      "exit_code": 0,
      "stdout_tail": "{\"status\":\"ok\",\"version\":\"1.5.2\"}",
      "stderr_tail": "",
      "started_at": 1748534420,
      "completed_at": 1748534421,
      "duration_seconds": 1,
      "status": "success"
    }
  ]
}

# --- POST /ui/agents/runs/{run_id}/approve-deployment ---
curl -X POST http://localhost:8000/ui/agents/runs/run-xyz-456/approve-deployment \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{"approved": true, "approver_notes": "Reviewed deployment plan. LGTM."}'

# Response 200:
{
  "run_id": "run-xyz-456",
  "deployment_id": "dep-abc-123",
  "approval_status": "approved",
  "approved_by": "root.admin@testdev.local",
  "approved_at": 1748534500,
  "notes": "Reviewed deployment plan. LGTM."
}

# --- GET /ui/agents/devops/metrics?period_days=30 ---
curl http://localhost:8000/ui/agents/devops/metrics?period_days=30 \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "deployment_frequency": 3.2,
  "success_rate": 0.875,
  "mttr_seconds": 420,
  "rollback_rate": 0.0625,
  "incidents_count": 4,
  "period_start": 1745942400,
  "period_end": 1748534400
}
```

### 4.5 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, Dict, List, Any
from enum import Enum


class DeploymentStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    REJECTED = "rejected"


class OperationType(str, Enum):
    DEPLOYMENT = "deployment"
    INFRASTRUCTURE = "infrastructure"
    INCIDENT_RESPONSE = "incident_response"
    RUNBOOK = "runbook"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class StepType(str, Enum):
    COMMAND = "command"
    HEALTH_CHECK = "health_check"
    SMOKE_TEST = "smoke_test"
    ROLLBACK = "rollback"
    APPROVAL_WAIT = "approval_wait"


class IncidentSeverity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


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

    class Config:
        json_schema_extra = {
            "example": {
                "name": "staging",
                "requires_approval": False,
                "deploy_commands": ["git pull origin main", "pip install -r requirements.txt", "systemctl restart app"],
                "rollback_commands": ["git checkout HEAD~1", "systemctl restart app"],
                "health_check_urls": ["https://staging.example.com/health"],
                "health_check_timeout_seconds": 60,
                "rollback_window_seconds": 300
            }
        }


class MonitoringEndpointIn(BaseModel):
    name: str = Field(..., max_length=100)
    url: str = Field(..., max_length=500)
    metric_type: str = Field(..., max_length=50)
    threshold: float = Field(ge=0)


class RunbookIn(BaseModel):
    trigger_label: str = Field(..., max_length=100)
    name: str = Field(..., max_length=200)
    steps: List[str] = Field(..., min_length=1, max_length=50)


class DevOpsConfigIn(BaseModel):
    environments: List[EnvironmentConfigIn] = Field(..., min_length=1, max_length=10)
    deploy_ticket_labels: List[str] = Field(default=["type:deployment"], max_length=20)
    infra_ticket_labels: List[str] = Field(default=["type:infrastructure"], max_length=20)
    incident_ticket_labels: List[str] = Field(default=["type:incident"], max_length=20)
    auto_deploy_on_qa_approved: bool = False
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    max_operation_time_seconds: int = Field(default=1800, ge=300, le=14400)
    incident_space_id: Optional[str] = None
    monitoring_endpoints: Optional[List[MonitoringEndpointIn]] = None
    runbooks: Optional[List[RunbookIn]] = None


class DevOpsConfigOut(BaseModel):
    type_id: str
    devops_config: DevOpsConfigIn
    updated_at: int


class DeploymentApprovalIn(BaseModel):
    approved: bool
    approver_notes: Optional[str] = Field(default=None, max_length=2000)


class DeploymentApprovalOut(BaseModel):
    run_id: str
    deployment_id: str
    approval_status: Literal["approved", "rejected"]
    approved_by: str
    approved_at: int
    notes: Optional[str] = None


class HealthCheckResult(BaseModel):
    url: str
    status_code: int
    response_time_ms: int
    healthy: bool


class SmokeTestResult(BaseModel):
    command: str
    exit_code: int
    passed: bool


class DeploymentLogStepOut(BaseModel):
    step_number: int
    step_type: StepType
    command: str
    exit_code: Optional[int] = None
    stdout_tail: str
    stderr_tail: str
    started_at: int
    completed_at: int
    duration_seconds: int
    status: StepStatus


class DeploymentLogOut(BaseModel):
    deployment_id: str
    environment: str
    steps: List[DeploymentLogStepOut]


class DevOpsOutputOut(BaseModel):
    deployment_id: str
    environment: str
    operation_type: OperationType
    status: DeploymentStatus
    version_deployed: Optional[str] = None
    steps_total: int = Field(ge=0)
    steps_completed: int = Field(ge=0)
    health_check_results: List[HealthCheckResult] = Field(default_factory=list)
    smoke_test_result: Optional[SmokeTestResult] = None
    rollback_executed: bool = False
    rollback_success: Optional[bool] = None
    incident_ticket_id: Optional[str] = None
    total_duration_seconds: int = Field(ge=0)
    approval_received_at: Optional[int] = None
    monitoring_snapshot: Optional[dict] = None


class DevOpsMetricsOut(BaseModel):
    deployment_frequency: float = Field(ge=0)
    success_rate: float = Field(ge=0.0, le=1.0)
    mttr_seconds: float = Field(ge=0)
    rollback_rate: float = Field(ge=0.0, le=1.0)
    incidents_count: int = Field(ge=0)
    period_start: int
    period_end: int


class IncidentMetadata(BaseModel):
    incident_source: Literal["devops_agent"] = "devops_agent"
    severity: IncidentSeverity
    affected_environment: str
    affected_services: List[str] = Field(default_factory=list)
    timeline: str
    deployment_id: Optional[str] = None
    agent_run_id: str
    error_logs: str = Field(max_length=10000)
    metrics_snapshot: str
    rollback_status: Literal["not_needed", "success", "failed"]
    remediation_steps: str
```

### 4.6 Backend Router (`app/routers/agent_devops.py`)

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

Register in `app/main.py`:

```python
from app.routers.agent_devops import router as agent_devops_router
app.include_router(agent_devops_router, prefix="/ui")
```

### 4.7 Deployment Approval Flow

For environments with `requires_approval = true` (typically production):

1. Agent generates deployment plan (commands, health checks, rollback procedure).
2. Agent creates a feedback request (AGENT-004) with the plan rendered as Markdown.
3. Agent enters `awaiting_approval` state -- the Worker Agent Framework pauses the workflow.
4. Admin reviews the plan in the Worker Fleet Management UI (AGENT-004) or via the feedback loop (AGENT-006).
5. Admin calls `POST /approve-deployment` or `POST /reject-deployment`.
6. On approval: agent resumes execution. On rejection: agent marks ticket as `blocked` with rejection notes.

### 4.8 Rollback Decision Logic

After deployment, the agent enters a monitoring phase lasting `rollback_window_seconds`:

1. **Health checks**: GET each URL; all must return 200 within `health_check_timeout_seconds`.
2. **Smoke test**: If configured, execute and expect exit code 0.
3. **Post-deploy monitoring**: Poll `monitoring_endpoints` for anomalies (latency spikes, error rate increase, CPU/memory exceeding thresholds).
4. **Decision**: If any check fails, `should_auto_rollback()` returns `True`. Agent executes rollback commands, files incident ticket, and sets deployment status to `rolled_back`.
5. **Rollback failure**: If rollback commands also fail, agent escalates via feedback loop with full logs. This is a critical escalation requiring immediate human attention.

### 4.9 Frontend Component Tree

```
DevOpsAgentConfigPage                  data-testid="devops-config-page"
├── Tabs
│   ├── TabsList
│   │   ├── TabsTrigger "Config"
│   │   ├── TabsTrigger "Environments"
│   │   ├── TabsTrigger "Runbooks"
│   │   ├── TabsTrigger "Deployments"
│   │   └── TabsTrigger "Metrics"
│   │
│   ├── TabsContent "config"             data-testid="devops-config-tab"
│   │   ├── Card "Ticket Labels"
│   │   │   ├── Input (deploy_ticket_labels)    comma-separated tags
│   │   │   ├── Input (infra_ticket_labels)
│   │   │   └── Input (incident_ticket_labels)
│   │   ├── Card "Automation Settings"
│   │   │   ├── Switch (auto_deploy_on_qa_approved)
│   │   │   ├── Select (coding_tool)             "claude_code" | "codex"
│   │   │   ├── Input (max_operation_time_seconds) type="number"
│   │   │   └── Select (incident_space_id)       ticket space dropdown
│   │   └── div.flex.gap-2
│   │       ├── Button "Validate"
│   │       └── Button "Save"
│   │
│   ├── TabsContent "environments"       data-testid="devops-environments-tab"
│   │   ├── Button "Add Environment"
│   │   └── Accordion (per environment)
│   │       ├── AccordionItem (env.name)
│   │       │   ├── Input (name)
│   │       │   ├── Switch (requires_approval)
│   │       │   ├── Textarea (deploy_commands)     one per line
│   │       │   ├── Textarea (rollback_commands)   one per line
│   │       │   ├── Input[] (health_check_urls)    add/remove URLs
│   │       │   ├── Input (health_check_timeout_seconds)
│   │       │   ├── Input (smoke_test_command)
│   │       │   ├── Slider (rollback_window_seconds) 0-3600
│   │       │   └── KeyValueEditor (env_vars)
│   │       └── Button "Remove Environment"       destructive
│   │
│   ├── TabsContent "runbooks"           data-testid="devops-runbooks-tab"
│   │   ├── Button "Add Runbook"
│   │   └── Card[] (per runbook)
│   │       ├── Input (trigger_label)
│   │       ├── Input (name)
│   │       ├── Textarea (steps)                one per line
│   │       └── Button "Remove"
│   │
│   ├── TabsContent "deployments"        data-testid="devops-deployments-tab"
│   │   └── DataTable
│   │       ├── columns: [ticket_id, environment, status, version, duration, agent, created_at]
│   │       ├── status renders as Badge (green=success, red=failed, yellow=rolled_back)
│   │       └── row click → expands deployment log timeline
│   │
│   └── TabsContent "metrics"            data-testid="devops-metrics-tab"
│       ├── div.grid.grid-cols-2.lg:grid-cols-4
│       │   ├── StatCard "Deploy Frequency" → deployment_frequency/day
│       │   ├── StatCard "Success Rate" → success_rate as %
│       │   ├── StatCard "MTTR" → mttr_seconds formatted
│       │   └── StatCard "Incidents" → incidents_count
│       ├── Card "Rollback Rate"
│       │   └── Progress bar (rollback_rate as %)
│       └── Select "Period" → 7d / 30d / 90d

DeploymentApprovalPanel                data-testid="deployment-approval-panel"
├── Alert "Production Deployment Pending Approval"
├── Card "Deployment Plan"
│   ├── pre (environment, version, commands)
│   └── pre (health checks, rollback plan)
├── Textarea "Approver Notes"
├── div.flex.gap-2
│   ├── Button "Approve" variant="default"
│   └── Button "Reject" variant="destructive"

DevOpsRunOutputPanel                   data-testid="devops-output-panel"
├── div.flex.items-center.gap-2
│   ├── Badge (status)
│   ├── span "Environment: {environment}"
│   └── span "Duration: {total_duration_seconds}s"
├── Card "Deployment Timeline"
│   └── Timeline (step-by-step)
│       └── steps.map(s =>
│           ├── TimelineItem
│           │   ├── icon (check=success, x=failed, clock=pending)
│           │   ├── span (step_type + command)
│           │   └── span (duration_seconds + status)
│       )
├── Card "Health Check Results"
│   └── Table
│       └── health_check_results.map(h =>
│           ├── td (url)
│           ├── td (status_code) with color
│           ├── td (response_time_ms)
│           └── td (healthy badge)
│       )
├── Card "Rollback Status" (if rollback_executed)
│   ├── Badge (rollback_success ? "Rollback Succeeded" : "Rollback Failed")
│   └── Link to incident ticket (if incident_ticket_id)
└── Card "Monitoring Snapshot" (if monitoring_snapshot)
    └── pre (JSON.stringify(monitoring_snapshot, null, 2))
```

### 4.10 Frontend Types (`frontend/src/api/types.ts`)

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

### 4.11 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Add DevOps Agent API functions: `getDevOpsConfig`, `updateDevOpsConfig`, `validateDevOpsConfig`, `getDevOpsEligibleTickets`, `getDevOpsOutput`, `getDeploymentLog`, `approveDeployment`, `rejectDeployment`, `getDevOpsMetrics`, `listDeployments`, `testDevOpsWorkflow`.

### 4.12 Frontend Pages

- **DevOpsAgentConfigPage** (`frontend/src/pages/agents/DevOpsAgentConfigPage.tsx`): Route `/agents/types/:typeId/devops`. Tabbed layout: Config | Environments | Runbooks | Deployments | Metrics. `data-testid="devops-config-page"`.
- **DeploymentApprovalPanel** (`frontend/src/pages/agents/DeploymentApprovalPanel.tsx`): Shown when a deployment is `awaiting_approval`. Displays deployment plan, health check config, rollback plan. Approve/Reject buttons with notes field. `data-testid="deployment-approval-panel"`.
- **DevOpsRunOutputPanel** (`frontend/src/pages/agents/DevOpsRunOutputPanel.tsx`): Embedded in Agent Run detail page. Deployment timeline, health check results, rollback status, incident ticket link. `data-testid="devops-output-panel"`.

---

## 5. Implementation Plan

### 5.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_devops.py` | DevOps Agent config, deployment execution, health checks, rollback, incident management |
| `app/routers/agent_devops.py` | DevOps config CRUD, deployment log, approval, metrics endpoints |
| `frontend/src/pages/agents/DevOpsAgentConfigPage.tsx` | DevOps Agent configuration + environments + metrics UI |
| `frontend/src/pages/agents/DeploymentApprovalPanel.tsx` | Production deployment approval UI |
| `frontend/src/pages/agents/DevOpsRunOutputPanel.tsx` | DevOps run output detail panel |

### 5.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `deployment_log` TableDef |
| `app/core/settings.py` | Add `deployment_log_table_name` setting |
| `app/core/tables.py` | Add `deployment_log` table handle |
| `app/services/tickets.py` | Add `deploying`, `deployed`, `investigating` to `_TICKET_STATUSES` |
| `app/main.py` | Register `agent_devops_router` |
| `app/models.py` | Add DevOps-related Pydantic models |
| `frontend/src/api/types.ts` | Add DevOps TypeScript types |
| `frontend/src/api/endpoints/agents.ts` | Add DevOps Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/devops` route |

---

## 6. E2E Test Plan

### 6.1 Test File

`frontend/e2e/agent-devops.spec.ts` -- 16 tests across 4 sections.

### 6.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let ticketId: string;
let runId: string;
let deploymentId: string;
// Root = admin who configures agents
```

### 6.3 Section 659: DevOps Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 659.1 | Create DevOps Agent type with environments | POST agent type `agent_type=devops`; PUT devops-config with 2 environments (staging + production); 200 |
| 659.2 | Get devops config | GET devops-config; 200; `environments` array has 2 entries; production has `requires_approval=true` |
| 659.3 | Validate config missing rollback for production | POST validate with production env having empty `rollback_commands`; validation errors returned |
| 659.4 | Update with runbook and monitoring | PUT with runbooks array and monitoring_endpoints; 200; values persisted |

### 6.4 Section 660: Deployment & Health Check API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 660.1 | Create deployment ticket | Create ticket with `labels=["type:deployment"]`; status = `open` |
| 660.2 | Eligible tickets returns deployment ticket | GET devops-eligible-tickets; array includes the ticket |
| 660.3 | Get deployment log from completed run | GET deployment-log for a run; 200; array of steps with `step_type`, `status`, `duration_seconds` |
| 660.4 | DevOps output shows health check results | GET devops-output; 200; `health_check_results` array present; each has `url`, `healthy` |

### 6.5 Section 661: Approval & Rollback API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 661.1 | Pending production deployment requires approval | DevOps output `status = "awaiting_approval"` for production environment |
| 661.2 | Approve deployment advances execution | POST approve-deployment; 200; devops output status changes from `awaiting_approval` |
| 661.3 | Reject deployment blocks ticket | POST reject-deployment with notes; 200; ticket status = `blocked` |
| 661.4 | Rollback creates incident ticket | When health check fails, devops output has `rollback_executed=true` and `incident_ticket_id` set |

### 6.6 Section 662: DevOps Config UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 662.1 | DevOps config page loads | Navigate `/agents/types/{typeId}/devops`; `[data-testid="devops-config-page"]` visible |
| 662.2 | Environments tab shows configured envs | Click "Environments" tab; `[data-testid="devops-environments-tab"]` visible; 2 environment accordions |
| 662.3 | Deployments tab lists recent deployments | Click "Deployments" tab; `[data-testid="devops-deployments-tab"]` visible; table has rows |
| 662.4 | Metrics tab shows deployment frequency | Click "Metrics" tab; `[data-testid="devops-metrics-tab"]` visible; deployment frequency chart present |

### 6.7 Expanded E2E Test Details

#### Section 663: Edge Cases (6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 663.1 | Concurrent deployment to same environment blocked | Two agents try to deploy to staging simultaneously; second gets 409 "deployment already in progress" |
| 663.2 | Deployment with no health check URLs | Config with empty health_check_urls; deployment succeeds without health check step |
| 663.3 | Approval timeout after 24 hours | Pending approval auto-rejects after 24h; ticket status = blocked |
| 663.4 | Rollback command failure escalates | Rollback commands return non-zero; critical escalation triggered via feedback loop |
| 663.5 | Runbook matches ticket label and executes | Create ticket with label matching runbook trigger; runbook steps execute in order |
| 663.6 | Environment variable injection | Config env_vars set; deployment commands can reference ${VAR}; verify in stdout |

#### Section 664: Negative Tests (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 664.1 | Non-admin cannot access DevOps config | Alice (USER role) GETs devops-config; 403 |
| 664.2 | Config with duplicate environment names | PUT with two envs named "staging"; 422 "Environment names must be unique" |
| 664.3 | Config with no environments | PUT with empty environments array; 422 "At least one environment is required" |
| 664.4 | Approve non-existent deployment | POST approve-deployment with fake run_id; 404 |
| 664.5 | Health check URL not HTTP(S) | Config with health_check_urls: ["ftp://bad"]; 422 validation error |

---

## 7. Error Handling

### 7.1 Error Table

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

### 7.2 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Agent type not in DDB | 404 | `AGENT_TYPE_NOT_FOUND` | "The specified agent type does not exist." | Verify type_id; check registry |
| devops_config missing | 404 | `DEVOPS_CONFIG_NOT_FOUND` | "No DevOps config found for this agent type." | PUT devops-config first |
| Wrong agent type | 409 | `AGENT_TYPE_MISMATCH` | "This agent type is not configured as devops." | Use correct type_id |
| No environments | 422 | `NO_ENVIRONMENTS` | "At least one environment is required." | Add environment to config |
| Duplicate env names | 422 | `DUPLICATE_ENV_NAMES` | "Environment names must be unique." | Rename duplicate environments |
| Invalid health check URL | 422 | `INVALID_HEALTH_URL` | "Health check URL must be HTTP or HTTPS." | Fix URL format |
| Prod without rollback | 422 | `NO_ROLLBACK_FOR_PROD` | "Production must have rollback commands." | Add rollback commands |
| Env mutex conflict | 409 | `DEPLOY_IN_PROGRESS` | "Deployment in progress for this environment." | Wait for current deployment |
| Ticket already deploying | 409 | `TICKET_ALREADY_DEPLOYING` | "This ticket already has an active deployment." | Wait or cancel existing |
| Approval timeout | 200 | (auto-rejected) | "Deployment auto-rejected after 24h." | Re-trigger and approve faster |
| Health check failure | 200 | (auto-rollback) | "Health checks failed; automatic rollback executed." | Fix issue and re-deploy |
| Rollback failure | 200 | (critical escalation) | "Rollback failed; manual intervention required." | SRE must intervene manually |
| Terminal unavailable | 503 | `TERMINAL_UNAVAILABLE` | "No terminal worker available." | Check fleet provisioning |
| Command timeout | 504 | `COMMAND_TIMEOUT` | "Command exceeded time limit." | Increase max_operation_time or optimize command |
| Git clone/pull failed | 500 | `GIT_FAILED` | "Failed to clone/pull repository." | Check git access and credentials |
| Run not found | 404 | `RUN_NOT_FOUND` | "Agent run not found." | Verify run_id |
| Not admin | 403 | `ADMIN_REQUIRED` | "Admin access required." | Use admin account |

---

## 8. Observability & Monitoring

### 8.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `devops_deployments_total` | Counter | `environment`, `status={success,failed,rolled_back}` | Total deployments by env and result |
| `devops_deployment_duration_seconds` | Histogram | `environment` | Time from start to health check pass |
| `devops_rollbacks_total` | Counter | `environment`, `success={true,false}` | Rollback count and success |
| `devops_health_checks_total` | Counter | `url`, `result={healthy,unhealthy}` | Health check outcomes |
| `devops_health_check_latency_seconds` | Histogram | `url` | Health check response time |
| `devops_incidents_filed_total` | Counter | `severity={P0,P1,P2,P3}` | Auto-filed incidents |
| `devops_approval_wait_seconds` | Histogram | `environment` | Time spent waiting for approval |
| `devops_runbook_executions_total` | Counter | `runbook_name`, `result` | Runbook runs |
| `devops_step_duration_seconds` | Histogram | `step_type` | Per-step execution time |
| `devops_eligible_tickets_gauge` | Gauge | -- | Current backlog of eligible tickets |
| `devops_mttr_seconds` | Gauge | -- | Mean time to recovery (rolling 30d) |

### 8.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `deploy_started` | INFO | deployment_id, environment, ticket_id, version | Deployment begins |
| `deploy_step_completed` | INFO | deployment_id, step_number, step_type, status, duration | Each step completes |
| `deploy_step_failed` | ERROR | deployment_id, step_number, command, exit_code, stderr | Step fails |
| `deploy_health_check` | INFO | deployment_id, url, status_code, healthy | Health check result |
| `deploy_smoke_test` | INFO | deployment_id, command, passed | Smoke test result |
| `deploy_approval_requested` | INFO | deployment_id, environment | Approval gate reached |
| `deploy_approved` | INFO | deployment_id, approved_by, notes | Human approved |
| `deploy_rejected` | WARN | deployment_id, rejected_by, notes | Human rejected |
| `deploy_rollback_started` | WARN | deployment_id, reason | Rollback initiated |
| `deploy_rollback_completed` | INFO | deployment_id, success | Rollback finished |
| `deploy_rollback_failed` | ERROR | deployment_id, step, error | Rollback step failed |
| `deploy_incident_filed` | WARN | deployment_id, incident_ticket_id, severity | Incident created |
| `deploy_completed` | INFO | deployment_id, status, total_duration | Deployment finished |

### 8.3 Alert Thresholds

| Alert | Condition | Severity | Channel |
|-------|-----------|----------|---------|
| Deployment failure rate high | success_rate < 70% over 24h | P1 | PagerDuty |
| Rollback rate spike | rollback_rate > 25% over 7d | P2 | Slack #sre |
| MTTR above SLA | mttr > 30 min (rolling 7d) | P2 | Slack #sre |
| Approval pending > 4h | approval_wait > 14400s | P3 | Slack #deployments |
| Critical rollback failure | rollback_success=false | P0 | PagerDuty + Slack #incidents |
| Deployment backlog | eligible_tickets_gauge > 10 | P3 | Slack #agents |
| Health check degradation | health_check_latency p99 > 5s | P3 | Slack #monitoring |

### 8.4 Dashboard Queries (Prometheus/Grafana)

```promql
# Deployment success rate (last 7d)
sum(rate(devops_deployments_total{status="success"}[7d]))
/ sum(rate(devops_deployments_total[7d]))

# Mean time to recovery
avg(devops_mttr_seconds)

# Deployment frequency (deploys per day)
sum(rate(devops_deployments_total[24h])) * 86400

# Rollback rate
sum(rate(devops_rollbacks_total[7d]))
/ sum(rate(devops_deployments_total[7d]))

# Average approval wait time
histogram_quantile(0.50, rate(devops_approval_wait_seconds_bucket[7d]))

# Health check failure rate by URL
sum(rate(devops_health_checks_total{result="unhealthy"}[24h])) by (url)
/ sum(rate(devops_health_checks_total[24h])) by (url)
```

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `DEVOPS_AGENT_ENABLED` | `false` | Master kill switch |
| `DEVOPS_AUTO_DEPLOY_ENABLED` | `false` | Allow auto-deploy on qa_approved |
| `DEVOPS_PROD_DEPLOY_ENABLED` | `false` | Allow production deployments (staging only at first) |
| `DEVOPS_INCIDENT_FILING_ENABLED` | `false` | Enable auto-filing incident tickets |
| `DEVOPS_ROLLBACK_ENABLED` | `true` | Enable automatic rollback (disable = manual only) |
| `DEVOPS_RUNBOOK_ENABLED` | `false` | Enable runbook execution |

### 9.2 Migration Steps

1. **DynamoDB table**: Create `deployment_log` table with PK/SK and GSI for environment queries. Add to `local-ddb-init.py`.
2. **Settings**: Add `deployment_log_table_name` to `app/core/settings.py` and `tables.py`.
3. **Ticket statuses**: Add `deploying`, `deployed`, `investigating` to `_TICKET_STATUSES`.
4. **No data backfill**: New table, no existing data.

### 9.3 Canary Deployment

1. **Week 1 (staging only)**: `DEVOPS_AGENT_ENABLED=true`, `DEVOPS_PROD_DEPLOY_ENABLED=false`. Agent deploys to staging only. Monitor success rate.
2. **Week 2 (staging + auto-deploy)**: Enable `DEVOPS_AUTO_DEPLOY_ENABLED=true`. QA-approved tickets auto-deploy to staging.
3. **Week 3 (production with approval)**: Enable `DEVOPS_PROD_DEPLOY_ENABLED=true`. All prod deployments require manual approval.
4. **Week 4 (incident filing)**: Enable `DEVOPS_INCIDENT_FILING_ENABLED=true`. Monitor false positive incident rate.
5. **Week 5 (runbooks)**: Enable `DEVOPS_RUNBOOK_ENABLED=true`. Start with low-risk runbooks (cert renewal, log rotation).

### 9.4 Rollback Procedure

1. **Immediate**: Set `DEVOPS_AGENT_ENABLED=false`. In-progress deployments complete but no new ones start.
2. **Per-feature rollback**: Disable individual flags (prod deploy, incident filing, runbooks) without killing the entire agent.
3. **Deployment mutex cleanup**: If an agent crashes mid-deployment, the mutex TTL (1 hour) auto-expires. Admin can also manually delete the mutex item.
4. **Stuck tickets**: Reset `deploying`/`investigating` tickets to previous status via admin API.

---

## 10. Security Considerations

- **Admin-only access**: All DevOps Agent endpoints require `require_admin_session`.
- **Credential isolation**: Cloud provider credentials are stored in the Agent Secrets Vault (AGENT-006), never in devops_config. Credentials are injected into the terminal environment at provisioning time and scrubbed from deployment logs.
- **Production approval gate**: Production deployments always require human approval. The agent cannot bypass this requirement. Approval is logged with the approver's identity and timestamp.
- **Command sanitization**: Deploy and rollback commands in the config are validated against an allowlist of safe command prefixes (terraform, kubectl, aws, docker, npm, etc.). Raw shell commands require explicit admin opt-in.
- **Log scrubbing**: Deployment log stdout/stderr are scanned for secrets (API keys, passwords, tokens) before storage. Matches are replaced with `[REDACTED]`.
- **Rollback isolation**: Rollback commands run in the same terminal session as the deployment to ensure the same environment state. No cross-environment rollback is possible.
- **Incident data retention**: Incident ticket metadata (logs, metrics snapshots) is retained for 180 days for compliance. Older data is archived to S3.
- **Monitoring endpoint authentication**: Monitoring URLs support Bearer token authentication via secrets stored in AGENT-006.

---

## 11. Performance Considerations

### 11.1 Query Cost Analysis

| Operation | Read/Write | Cost Estimate | Notes |
|-----------|-----------|---------------|-------|
| Get DevOps config | 1 RCU | Minimal | Single item read |
| List eligible tickets | 5-20 RCU | Moderate | GSI query with label filter |
| Claim ticket (conditional) | 5 WCU | Low | Single conditional update |
| Create deployment log entry | 1 WCU per step | Low per step | 5-20 steps typical |
| Get full deployment log | 5-20 RCU | Moderate | Query all steps for deployment |
| Deployment mutex (conditional put) | 5 WCU | Low | Single conditional write |
| Store DevOps output | 10 WCU | Moderate | Large map with health results |
| Metrics aggregation | 50-200 RCU | High | Scan completed runs; cache heavily |

### 11.2 Caching Strategy

| Data | TTL | Invalidation | Storage |
|------|-----|-------------|---------|
| DevOps config | 5 min | On PUT update | In-memory |
| Eligible tickets | 30 sec | On ticket status change | React Query |
| Deployment log | No cache | Real-time during deploy | None |
| DevOps metrics | 10 min | On deployment completion | In-memory + React Query |
| Environment mutex | TTL on DDB item | Auto-expire 1h | DynamoDB TTL |

### 11.3 Rate Limiting

| Operation | Limit | Window | Scope |
|-----------|-------|--------|-------|
| Config updates | 10 | 1 min | Per admin |
| Approval/rejection | 5 | 1 min | Per admin |
| Metrics queries | 10 | 1 min | Global |
| Deployment list queries | 30 | 1 min | Per admin |

### 11.4 Performance Constraints

| Concern | Mitigation |
|---------|-----------|
| Health check polling during rollback window | Poll every 10 seconds; exponential backoff on transient failures |
| Large deployment logs (50+ steps) | Paginated query on deployment_log table; SK sort ensures order |
| Concurrent deployments to same environment | Mutex via conditional update: only one active deployment per environment |
| Monitoring endpoint latency | 5-second timeout per endpoint; parallel requests |
| Deployment log storage growth | DDB TTL on log entries (90 days); older logs archived |
| Approval wait blocking agent instance | Agent enters idle state during approval; terminal kept alive but releases CPU |
| Metrics aggregation on large datasets | Pre-compute daily aggregates; 10-min cache TTL |

---

## 12. Dependencies

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
