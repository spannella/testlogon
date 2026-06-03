# AGENT-018: Accountant / Cost Tracking Agent

**Ticket**: AGENT-018
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-14 days
**Dependencies**: AGENT-001 (Agent Registry), AGENT-002 (Terminal Provisioning), AGENT-003 (Worker Agent Framework), AGENT-004 (Ticket Lifecycle Bridge), AGENT-005 (Context Injection & Output Parsing), AGENT-006 (Agent Monitoring & Health), AGENT-007 (Orchestration Dashboard)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-018 defines the Accountant / Cost Tracking Agent type -- a schedule-driven agent that monitors, allocates, and reports on all costs across the autonomous agent infrastructure. It queries LLM provider APIs (Anthropic, OpenAI) for token usage and billing data per API key, queries cloud provider (AWS) cost APIs for EC2 and K8s compute costs, and aggregates costs per worker, per agent type, and per ticket. The agent produces periodic cost summaries (daily, weekly, monthly) for the platform owner, generates budget alerts when spending exceeds configurable thresholds, recommends cost optimizations (idle workers, expensive models used for simple tasks), and can auto-pause workers when budget caps are exceeded. A cost dashboard provides overview charts, per-agent breakdowns, and trend analysis.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a platform owner, I want to know how much each agent costs per day. | Daily cost breakdown per agent type with LLM + compute components. |
| Owner | As a platform owner, I want to track cost per ticket completed. | Each ticket shows its total cost (LLM tokens + compute time). |
| Owner | As a platform owner, I want budget alerts when spending is high. | Alert when daily/weekly/monthly spend exceeds configurable threshold. |
| Owner | As a platform owner, I want to set budget caps per agent and overall. | Budget caps configurable per agent type, per day, per month. |
| Owner | As a platform owner, I want workers auto-paused when budget is exceeded. | Optional: workers pause when their agent type's budget cap is hit. |
| Owner | As a platform owner, I want cost optimization recommendations. | Agent identifies idle workers, suggests cheaper models for simple tasks. |
| Owner | As a platform owner, I want periodic cost reports (daily/weekly/monthly). | Report summarizes spend, compares to budget, highlights anomalies. |
| Owner | As a platform owner, I want a cost dashboard with charts and breakdowns. | Dashboard shows cost over time, per-agent pie chart, trend analysis. |
| Owner | As a platform owner, I want to see LLM token usage per agent. | Token breakdown: input tokens, output tokens, cached tokens, total cost. |

### 1.3 Why This Is Needed

Autonomous AI agents consume significant resources -- both LLM API credits (potentially hundreds of dollars per day for active teams) and cloud compute costs (EC2 instances running 24/7). Without granular cost tracking and attribution, spending can spiral uncontrollably. The Accountant Agent provides the financial visibility and controls needed to run an agent fleet responsibly: per-ticket cost attribution enables ROI analysis, budget caps prevent runaway spending, idle worker detection reduces waste, and optimization recommendations help select the right model tier for each task type. This agent is essential for any production deployment of the agent orchestration system.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Agent Registry** (AGENT-001): Agent type definitions, worker assignments. <!-- NOTE: AGENT-001 spec exists at docs/tickets/AGENT-001-llm-provider-key-management.md but NO code has been implemented yet — no agent registry tables, services, or routers exist in the codebase -->
- **Worker Agent Framework** (AGENT-003): Task execution with duration tracking. <!-- NOTE: AGENT-003 spec exists at docs/tickets/AGENT-003-worker-agent-framework-lifecycle.md but NO code has been implemented yet -->
- **Agent Monitoring** (AGENT-006): Worker health, uptime, task completion metrics. <!-- NOTE: AGENT-006 spec exists at docs/tickets/AGENT-006-terminal-monitoring-feedback-loop.md but NO code has been implemented yet -->
- **Ticket Lifecycle Bridge** (AGENT-004): Ticket assignment and completion tracking. <!-- NOTE: AGENT-004 spec exists at docs/tickets/AGENT-004-worker-fleet-management-ui.md but NO code has been implemented yet -->
- **Billing system** (`app/services/billing_shared.py`): Existing billing infrastructure for platform payments. <!-- NOTE: There is no `app/services/billing.py` — the billing logic lives in `app/services/billing_shared.py` (helpers: `new_ledger_entry`, `user_pk`, `ddb_get`, etc.) -->
- **AWS SDK** (`app/core/aws.py`): boto3 helpers for AWS API calls. (see `app/core/aws.py` — 41 lines, wraps `ddb_resource`, `kms_client`, `secretsmanager_client`, `sqs_client` from `app/core/aws_clients.py`)

### 2.2 Gaps

1. No agent type profile for cost tracking and financial monitoring.
2. No LLM usage and cost data collection from provider APIs.
3. No compute cost collection from cloud provider APIs.
4. No per-ticket cost attribution model.
5. No budget cap and alert system for agent spending.
6. No cost optimization recommendation engine.
7. No cost reporting with periodic summaries.
8. No cost dashboard with breakdowns and trend charts.
9. No auto-pause mechanism tied to budget limits.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentCosts Table
<!-- NOTE: The `agent_costs` table does NOT exist yet in `scripts/local-ddb-init.py` — new TableDef required -->

Primary cost tracking table. Each record represents a cost entry for a specific worker on a specific date.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `COST#{date}#{worker_id}` (date = YYYY-MM-DD) |
| `user_id` | S | Platform owner |
| `worker_id` | S | Worker instance identifier |
| `agent_type` | S | Agent type (e.g., `coder`, `pm`, `security`, `docs`) |
| `agent_id` | S | Agent instance ID |
| `date` | S | YYYY-MM-DD |
| `llm_input_tokens` | N | Total input tokens consumed |
| `llm_output_tokens` | N | Total output tokens consumed |
| `llm_cached_tokens` | N | Tokens served from cache |
| `llm_cost_cents` | N | LLM API cost in cents |
| `llm_provider` | S | `anthropic`, `openai`, etc. |
| `llm_model` | S | Model identifier (e.g., `claude-sonnet-4-20250514`) |
| `compute_hours` | N | Compute hours consumed (decimal) |
| `compute_cost_cents` | N | Compute cost in cents |
| `total_cost_cents` | N | `llm_cost_cents + compute_cost_cents` |
| `tickets_worked` | N | Number of tickets worked on this day |
| `tickets_completed` | N | Number of tickets completed this day |
| `updated_at` | N | Unix timestamp of last update |
| `GSI1PK` | S | `USER#{user_id}#DATE#{date}` |
| `GSI1SK` | S | `TYPE#{agent_type}#WORKER#{worker_id}` |
| `GSI2PK` | S | `USER#{user_id}#TYPE#{agent_type}` |
| `GSI2SK` | S | `DATE#{date}` |

```python
TableDef(
    "agent_costs", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={
        "llm_input_tokens": "N", "llm_output_tokens": "N", "llm_cached_tokens": "N",
        "llm_cost_cents": "N", "compute_hours": "N", "compute_cost_cents": "N",
        "total_cost_cents": "N", "tickets_worked": "N", "tickets_completed": "N",
        "updated_at": "N",
    },
),
```

#### 3.1.2 TicketCosts Table
<!-- NOTE: The `agent_ticket_costs` table does NOT exist yet in `scripts/local-ddb-init.py` — new TableDef required -->

Attributes costs to individual tickets.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `TCOST#{ticket_id}` |
| `ticket_id` | S | Ticket identifier |
| `user_id` | S | Platform owner |
| `agent_type` | S | Primary agent type that worked the ticket |
| `total_llm_tokens` | N | Total tokens across all sessions |
| `total_llm_cost_cents` | N | Total LLM cost |
| `total_compute_hours` | N | Total compute time |
| `total_compute_cost_cents` | N | Total compute cost |
| `total_cost_cents` | N | Grand total cost |
| `worker_sessions` | N | Number of worker sessions involved |
| `status` | S | `in_progress`, `completed` |
| `started_at` | N | Unix timestamp of first cost entry |
| `completed_at` | N (optional) | Unix timestamp when ticket completed |
| `GSI1PK` | S | `USER#{user_id}#TICKET_COSTS` |
| `GSI1SK` | N | `total_cost_cents` (for sorting by cost) |

```python
TableDef(
    "agent_ticket_costs", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={
        "total_llm_tokens": "N", "total_llm_cost_cents": "N",
        "total_compute_hours": "N", "total_compute_cost_cents": "N",
        "total_cost_cents": "N", "worker_sessions": "N",
        "started_at": "N", "completed_at": "N", "GSI1SK": "N",
    },
),
```

#### 3.1.3 CostBudgets Table
<!-- NOTE: The `agent_cost_budgets` table does NOT exist yet in `scripts/local-ddb-init.py` — new TableDef required -->

Stores budget caps and alert thresholds.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `BUDGET#{budget_id}` |
| `budget_id` | S | UUID hex |
| `name` | S | Budget name (e.g., "Overall Daily", "Coder Agent Monthly") |
| `scope` | S | `overall`, `agent_type`, `agent_instance` |
| `scope_ref` | S (optional) | Agent type or agent ID for scoped budgets |
| `period` | S | `daily`, `weekly`, `monthly` |
| `limit_cents` | N | Budget limit in cents |
| `alert_threshold_pct` | N | Percentage threshold for alert (e.g., 80 = alert at 80%) |
| `auto_pause_on_exceed` | BOOL | Whether to auto-pause workers when exceeded |
| `enabled` | BOOL | Whether budget is active |
| `created_at` | N | Unix timestamp |

```python
TableDef(
    "agent_cost_budgets", "pk", "sk",
    attr_types={
        "limit_cents": "N", "alert_threshold_pct": "N", "created_at": "N",
    },
),
```

#### 3.1.4 CostAlerts Table
<!-- NOTE: The `agent_cost_alerts` table does NOT exist yet in `scripts/local-ddb-init.py` — new TableDef required -->

Stores triggered budget alerts and spending anomaly notifications.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `ALERT#{alert_id}` |
| `alert_id` | S | UUID hex |
| `budget_id` | S (optional) | Budget that triggered the alert |
| `alert_type` | S | `budget_threshold`, `budget_exceeded`, `spending_anomaly`, `idle_worker`, `optimization` |
| `severity` | S | `info`, `warning`, `critical` |
| `title` | S | Alert title |
| `message` | S | Detailed alert message |
| `current_spend_cents` | N | Current spending when alert triggered |
| `budget_limit_cents` | N (optional) | Budget limit for context |
| `acknowledged` | BOOL | Whether owner acknowledged the alert |
| `auto_action_taken` | S (optional) | Auto-action taken (e.g., "Workers paused") |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `USER#{user_id}#ALERTS` |
| `GSI1SK` | N | `created_at` |

```python
TableDef(
    "agent_cost_alerts", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={
        "current_spend_cents": "N", "budget_limit_cents": "N",
        "created_at": "N", "GSI1SK": "N",
    },
),
```

#### 3.1.5 Accountant Agent Configuration (on Agent Registry Record)

Stored as a DDB map on the agent registry entry (`accountant_config` field):

```json
{
  "collection_frequency": "hourly",
  "report_frequency": "daily",
  "report_hour_utc": 8,
  "report_recipients": ["owner"],
  "llm_providers": [
    {
      "provider": "anthropic",
      "api_key_ref": "secrets/anthropic-key",
      "pricing": {
        "claude-sonnet-4-20250514": {"input_per_mtok": 300, "output_per_mtok": 1500},
        "claude-haiku-4-20250514": {"input_per_mtok": 80, "output_per_mtok": 400}
      }
    }
  ],
  "compute_pricing": {
    "ec2_per_hour_cents": 10,
    "k8s_per_hour_cents": 5
  },
  "anomaly_detection_enabled": true,
  "anomaly_threshold_pct": 200,
  "idle_worker_threshold_minutes": 60,
  "optimization_suggestions_enabled": true
}
```

### 3.2 Backend Service (`app/services/agent_accountant.py`)
<!-- NOTE: `app/services/agent_accountant.py` does NOT exist yet — new implementation required. No agent service files exist in the codebase. -->

```python
def record_cost_entry(*, user_id, worker_id, agent_type, agent_id, date,
                       llm_input_tokens, llm_output_tokens, llm_cached_tokens,
                       llm_cost_cents, llm_provider, llm_model,
                       compute_hours, compute_cost_cents) -> dict:
    """Record/update daily cost entry. Upsert with atomic adds. Check budgets."""

def attribute_cost_to_ticket(*, user_id, ticket_id, agent_type,
                               llm_tokens, llm_cost_cents,
                               compute_hours, compute_cost_cents) -> dict:
    """Attribute cost increment to a ticket. Upsert TicketCosts with atomic add."""

def get_daily_summary(*, user_id, date) -> dict:
    """Query GSI1 for date, aggregate by agent_type. Return total + breakdown."""

def get_period_summary(*, user_id, period, start_date, end_date) -> dict:
    """Aggregate costs over range, compare to budgets, return utilization."""

def get_agent_type_costs(*, user_id, agent_type, days=30) -> dict:
    """Query GSI2 for agent_type cost entries in date range."""

def get_ticket_cost(*, user_id, ticket_id) -> dict:
    """Get total cost attributed to a ticket."""

def list_ticket_costs(*, user_id, sort_by="total_cost", limit=25, cursor=None) -> dict:
    """List ticket costs sorted by total_cost desc via GSI1."""

def create_budget(*, user_id, name, scope, scope_ref, period,
                   limit_cents, alert_threshold_pct=80, auto_pause_on_exceed=False) -> dict:
    """Create a budget cap."""

def list_budgets(*, user_id) -> list[dict]:
def update_budget(*, user_id, budget_id, **fields) -> dict:
def delete_budget(*, user_id, budget_id) -> dict:

def check_budgets(*, user_id) -> list[dict]:
    """Check all budgets vs current spending. Create alerts, auto-pause if configured."""

def list_alerts(*, user_id, acknowledged=None, limit=25, cursor=None) -> dict:
def acknowledge_alert(*, user_id, alert_id) -> dict:

def get_cost_trends(*, user_id, days=90) -> dict:
    """Weekly aggregates of LLM vs compute costs for charting."""

def get_optimization_recommendations(*, user_id) -> list[dict]:
    """Identify idle workers, expensive models for simple tasks, high cost-per-ticket agents."""
```

### 3.3 Backend Router (`app/routers/agent_accountant.py`)
<!-- NOTE: `app/routers/agent_accountant.py` does NOT exist yet — new implementation required. No agent router files exist in the codebase. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/costs/summary/daily` | `require_ui_session` | Get daily summary (`?date=YYYY-MM-DD`) |
| GET | `/ui/agents/costs/summary/period` | `require_ui_session` | Get period summary (`?start=`, `?end=`, `?period=`) |
| GET | `/ui/agents/costs/by-agent-type` | `require_ui_session` | Get costs by agent type (`?type=`, `?days=`) |
| GET | `/ui/agents/costs/by-ticket` | `require_ui_session` | List ticket costs (sorted by cost) |
| GET | `/ui/agents/costs/by-ticket/{ticket_id}` | `require_ui_session` | Get cost for a specific ticket |
| GET | `/ui/agents/costs/trends` | `require_ui_session` | Get cost trends (`?days=`) |
| GET | `/ui/agents/costs/optimizations` | `require_ui_session` | Get optimization recommendations |
| GET | `/ui/agents/costs/budgets` | `require_ui_session` | List budgets |
| POST | `/ui/agents/costs/budgets` | `require_ui_session` | Create budget |
| PUT | `/ui/agents/costs/budgets/{budget_id}` | `require_ui_session` | Update budget |
| DELETE | `/ui/agents/costs/budgets/{budget_id}` | `require_ui_session` | Delete budget |
| GET | `/ui/agents/costs/alerts` | `require_ui_session` | List alerts (`?acknowledged=`) |
| POST | `/ui/agents/costs/alerts/{alert_id}/acknowledge` | `require_ui_session` | Acknowledge alert |
| PUT | `/ui/agents/costs/config` | `require_ui_session` | Update Accountant Agent config |
| POST | `/ui/agents/costs/collect` | `require_ui_session` | Manually trigger cost collection |

**Key request models**:

```python
class CreateBudgetIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    scope: Literal["overall", "agent_type", "agent_instance"]
    scope_ref: Optional[str] = None
    period: Literal["daily", "weekly", "monthly"]
    limit_cents: int = Field(..., ge=100)  # minimum $1
    alert_threshold_pct: int = Field(default=80, ge=10, le=100)
    auto_pause_on_exceed: bool = False

class UpdateBudgetIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    limit_cents: Optional[int] = Field(default=None, ge=100)
    alert_threshold_pct: Optional[int] = Field(default=None, ge=10, le=100)
    auto_pause_on_exceed: Optional[bool] = None
    enabled: Optional[bool] = None

class UpdateAccountantConfigIn(BaseModel):
    collection_frequency: Optional[Literal["hourly", "every_6h", "daily"]] = None
    report_frequency: Optional[Literal["daily", "weekly", "monthly"]] = None
    report_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    compute_pricing: Optional[Dict[str, int]] = None
    anomaly_detection_enabled: Optional[bool] = None
    anomaly_threshold_pct: Optional[int] = Field(default=None, ge=100, le=1000)
    idle_worker_threshold_minutes: Optional[int] = Field(default=None, ge=10, le=1440)
    optimization_suggestions_enabled: Optional[bool] = None
```

Register in `app/main.py`:
<!-- NOTE: `agent_accountant_router` is NOT currently registered in `app/main.py` — new registration required. See existing pattern at `app/main.py:396` for `broadcast_router` or `app/main.py:432` for `creator_analytics_router`. -->

```python
from app.routers.agent_accountant import router as agent_accountant_router
app.include_router(agent_accountant_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)
<!-- NOTE: None of the listed TypeScript interfaces exist yet in `frontend/src/api/types.ts` — new types required -->

Key TypeScript interfaces (mirroring DDB fields):

- **`AgentCostEntry`**: worker_id, agent_type, date, llm_input/output/cached_tokens, llm_cost_cents, llm_provider, llm_model, compute_hours, compute_cost_cents, total_cost_cents, tickets_worked, tickets_completed.
- **`CostDailySummary`**: date, total_cents, llm_cents, compute_cents, by_agent_type (Record), by_worker (AgentCostEntry[]).
- **`CostPeriodSummary`**: period, start/end_date, total/llm/compute_cents, by_agent_type, budget_utilization array.
- **`TicketCost`**: ticket_id, agent_type, total_llm_tokens, total_llm/compute_cost_cents, total_cost_cents, worker_sessions, status, started_at, completed_at.
- **`CostBudget`**: budget_id, name, scope, scope_ref, period, limit_cents, alert_threshold_pct, auto_pause_on_exceed, enabled.
- **`CostAlert`**: alert_id, budget_id, alert_type, severity, title, message, current_spend_cents, budget_limit_cents, acknowledged, auto_action_taken, created_at.
- **`CostTrends`**: weeks array with week_start, total/llm/compute_cents, by_agent_type.
- **`OptimizationRecommendation`**: type (idle_worker|model_downgrade|high_cost_ticket|underutilized_agent), title, description, potential_savings_cents, action.
- **`AccountantConfig`**: collection_frequency, report_frequency, report_hour_utc, anomaly_detection_enabled, anomaly_threshold_pct, idle_worker_threshold_minutes, optimization_suggestions_enabled.

### 3.5 Frontend API (`frontend/src/api/endpoints/agents.ts`)
<!-- NOTE: `frontend/src/api/endpoints/agents.ts` does NOT exist yet — new file required -->

Standard wrappers: `getDailyCostSummary(date)`, `getPeriodCostSummary(start, end, period)`, `getAgentTypeCosts(agentType, days?)`, `listTicketCosts(limit?)`, `getTicketCost(ticketId)`, `getCostTrends(days?)`, `getOptimizations()`, `listBudgets()`, `createBudget(data)`, `updateBudget(budgetId, data)`, `deleteBudget(budgetId)`, `listAlerts(acknowledged?)`, `acknowledgeAlert(alertId)`, `updateAccountantConfig(config)`, `triggerCostCollection()`.

### 3.6 Frontend Pages

<!-- NOTE: The `frontend/src/pages/agents/` directory does NOT exist yet — all 5 page files below are new implementations required. No `/agents/*` routes exist in `frontend/src/App.tsx`. -->
- **CostOverviewPage** (`frontend/src/pages/agents/CostOverviewPage.tsx`): Route `/agents/costs`. Top summary: today's spend, this week, this month (with budget progress bars). Stacked area chart of daily costs (LLM vs compute). Per-agent-type pie chart. Active alerts banner. `data-testid="cost-overview-page"`.
- **CostBreakdownPage** (`frontend/src/pages/agents/CostBreakdownPage.tsx`): Route `/agents/costs/breakdown`. Tab bar: By Agent Type / By Worker / By Ticket. Sortable table with cost columns. Drill-down to per-day entries. Date range picker. `data-testid="cost-breakdown-page"`.
- **BudgetManagerPage** (`frontend/src/pages/agents/BudgetManagerPage.tsx`): Route `/agents/costs/budgets`. List of budgets with progress bars (spent vs limit). Create/edit budget dialog. Toggle auto-pause. `data-testid="budget-manager-page"`.
- **CostAlertsPage** (`frontend/src/pages/agents/CostAlertsPage.tsx`): Route `/agents/costs/alerts`. Alert cards with severity badges, message, spend context. Acknowledge button. Filter: unacknowledged / all. `data-testid="cost-alerts-page"`.
- **OptimizationsPanel** (`frontend/src/pages/agents/OptimizationsPanel.tsx`): Panel within CostOverviewPage or separate route. Cards with recommendation title, description, potential savings amount, and action button. `data-testid="optimizations-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_accountant.py` | Cost recording, aggregation, budgets, alerts, optimizations |
| `app/routers/agent_accountant.py` | Cost tracking API endpoints |
| `frontend/src/pages/agents/CostOverviewPage.tsx` | Cost dashboard with charts |
| `frontend/src/pages/agents/CostBreakdownPage.tsx` | Detailed cost breakdowns |
| `frontend/src/pages/agents/BudgetManagerPage.tsx` | Budget CRUD |
| `frontend/src/pages/agents/CostAlertsPage.tsx` | Alert management |
| `frontend/src/pages/agents/OptimizationsPanel.tsx` | Optimization recommendations |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `agent_costs`, `agent_ticket_costs`, `agent_cost_budgets`, `agent_cost_alerts` TableDefs (see existing tables at line 513+ for pattern) |
| `app/core/settings.py` | Add table name settings + feature flags (see existing broadcast settings at line 452+ for pattern) |
| `app/core/tables.py` | Add table handles (see existing broadcast handles at line 39-43 for pattern) |
| `app/main.py` | Register `agent_accountant_router` (see existing registrations at line 396+ for pattern) |
| `app/models.py` | Add `CostEntryOut`, `CostSummaryOut`, `TicketCostOut`, `BudgetOut`, `AlertOut` models (see existing Pydantic models — file is ~2000 lines) |
| `frontend/src/api/types.ts` | Add cost, budget, alert, optimization types (see existing TypeScript interfaces in this file) |
| `frontend/src/api/endpoints/agents.ts` | Add Accountant Agent API functions (new file; see `frontend/src/api/endpoints/analytics.ts` for pattern) |
| `frontend/src/App.tsx` | Add `/agents/costs`, `/agents/costs/breakdown`, `/agents/costs/budgets`, `/agents/costs/alerts` routes (no `/agents` routes exist yet) |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-accountant.spec.ts` -- 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
const TODAY = new Date().toISOString().slice(0, 10);  // YYYY-MM-DD
let budgetId: string;
let alertId: string;
// Alice = platform owner
```

### 5.3 Section 691: Cost Recording & Summary API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 691.1 | Record cost entry for worker | POST cost entry with `worker_id`, `agent_type="coder"`, `llm_cost_cents=500`, `compute_cost_cents=100`; 201; `total_cost_cents=600` |
| 691.2 | Record cost entry for second agent type | POST cost entry with `agent_type="security"`, `llm_cost_cents=200`; 201 |
| 691.3 | Get daily summary | GET `/ui/agents/costs/summary/daily?date=${TODAY}`; 200; `total_cents >= 800`, `by_agent_type` has entries for `coder` and `security` |
| 691.4 | Attribute cost to ticket | POST ticket cost attribution with `ticket_id="TEST-001"`, `llm_cost_cents=300`; 200; `total_cost_cents=300` |
| 691.5 | Get ticket cost | GET `/ui/agents/costs/by-ticket/TEST-001`; 200; `total_cost_cents >= 300` |

### 5.4 Section 692: Budget Management API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 692.1 | Create daily budget | POST `/ui/agents/costs/budgets` with `scope=overall`, `period=daily`, `limit_cents=5000`, `alert_threshold_pct=80`; 201; returns `budget_id` |
| 692.2 | List budgets | GET `/ui/agents/costs/budgets`; array includes created budget |
| 692.3 | Update budget limit | PUT `budgets/{budgetId}` with `limit_cents=10000`; 200; limit updated |
| 692.4 | Create agent-type budget | POST with `scope=agent_type`, `scope_ref=coder`, `period=monthly`, `limit_cents=100000`; 201 |
| 692.5 | Delete budget | DELETE `budgets/{budgetId}`; 200; list no longer includes budget |

### 5.5 Section 693: Alerts & Trends API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 693.1 | List alerts | GET `/ui/agents/costs/alerts`; 200; array returned (may include budget alerts from 691+692 if thresholds crossed) |
| 693.2 | Acknowledge alert | POST `alerts/{alertId}/acknowledge` (if alert exists); 200; `acknowledged=true` |
| 693.3 | Get cost trends | GET `/ui/agents/costs/trends?days=30`; 200; `weeks` array with `total_cents`, `llm_cents`, `compute_cents` |
| 693.4 | Get optimization recommendations | GET `/ui/agents/costs/optimizations`; 200; array returned (may be empty if no optimizations identified) |

### 5.6 Section 694: Cost Dashboard UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 694.1 | Cost overview page loads | Navigate `/agents/costs`; `[data-testid="cost-overview-page"]` visible; summary cards show cost figures |
| 694.2 | Cost breakdown page loads | Navigate `/agents/costs/breakdown`; `[data-testid="cost-breakdown-page"]` visible; table rows present |
| 694.3 | Budget manager page CRUD | Navigate `/agents/costs/budgets`; `[data-testid="budget-manager-page"]` visible; create budget via form; budget appears with progress bar |
| 694.4 | Alerts page shows alerts | Navigate `/agents/costs/alerts`; `[data-testid="cost-alerts-page"]` visible; alert cards rendered (if any) |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Budget not found | 404 | "Budget not found" |
| Alert not found | 404 | "Cost alert not found" |
| Ticket cost not found | 404 | "No cost data for ticket: {ticket_id}" |
| Invalid date format | 422 | "Date must be in YYYY-MM-DD format" |
| Invalid period | 422 | "Invalid period: {value}" |
| Budget limit too low | 422 | "Budget limit must be at least $1.00 (100 cents)" |
| Invalid scope without scope_ref | 422 | "scope_ref required when scope is agent_type or agent_instance" |
| Duplicate budget | 409 | "A {period} budget already exists for this scope" |
| Config validation error | 422 | Specific field error |
| Agent not configured | 404 | "No Accountant Agent configured for this user" |
| Cost collection already running | 409 | "Cost collection is already in progress" |

---

## 7. Security Considerations

- **Ownership enforcement**: All cost data scoped to authenticated `user_id`. Cross-tenant access blocked.
- **API key protection**: LLM provider API keys are referenced by secrets manager ARN (`api_key_ref`), never stored in DDB config or exposed via API.
- **AWS credential isolation**: Cloud cost queries use the agent's IAM role (scoped to Cost Explorer read-only). No direct access to other AWS resources.
- **Budget auto-pause authorization**: Auto-pause modifies worker state; requires the budget `auto_pause_on_exceed` flag to be explicitly enabled by the owner. Workers resume only via manual action.
- **Financial data accuracy**: Cost entries are idempotent (upsert per worker per day). Duplicate submissions do not double-count costs.
- **Alert rate limiting**: Maximum 10 alerts per budget per day to prevent alert fatigue from flapping thresholds.
- **Cost data retention**: Daily cost entries retained for 2 years. Older data aggregated into monthly summaries. DDB TTL on daily entries after 730 days.
- **No PII in cost data**: Cost records contain only worker IDs, agent types, and numerical amounts. No user content or personal data.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Daily cost entry updates | Atomic counter increments; no read-before-write; O(1) per update |
| Period summary aggregation | Pre-computed daily summaries; period queries scan at most 90 daily entries |
| Ticket cost list | GSI1 sorted by total_cost; no full table scan needed |
| Budget check frequency | Budget checks run only during cost collection (hourly max); cached budget state |
| Trend chart data | Weekly aggregates computed on collection; at most 13 weeks of data for 90-day view |
| Optimization analysis | Runs on collection schedule; results cached; analyzes at most 100 workers |

---

## 9. Dependencies
<!-- NOTE: ALL AGENT-001 through AGENT-007 dependencies exist as ticket specs in `docs/tickets/` but NONE have any code implementation yet — no agent services, routers, tables, or frontend pages exist in the codebase. This ticket cannot be implemented until at least AGENT-001, AGENT-003, AGENT-004, and AGENT-006 are built. -->

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, worker assignments) — spec only, no code |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (compute cost tracking per instance) — spec only, no code |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (task duration tracking, token usage reporting) — spec only, no code |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (ticket-to-cost attribution) — spec only, no code |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting provider API credentials into agent terminal) — spec only, no code |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (worker health data for idle detection) — spec only, no code |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (cost widgets on orchestration dashboard) — spec only, no code |
| LLM Provider APIs | External | Required (Anthropic/OpenAI usage/billing endpoints) |
| AWS Cost Explorer | External | Required (EC2/K8s compute cost data) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| All other AGENT types | Cost data attributed to each agent type's operations |
| AGENT-013 (PM Agent) | PM Agent reviews may reference cost data when prioritizing features |

---

## 10. Architecture & Data Flow

```
                    Cost Ingestion Pipeline
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ LLM Providers  │────>│ Cost Ingestion     │────>│  DynamoDB     │
  │ (Anthropic,    │     │ Worker             │     │  agent_costs  │
  │  OpenAI)       │     │ (accountant_agent  │     │  table        │
  │                │     │  _service.py)       │     │               │
  │ Usage APIs     │     │                    │     │ PK=AGENT#id   │
  │ token counts   │     │ 1. poll provider   │     │ SK=COST#ts    │
  │ billing data   │     │ 2. normalize costs │     │               │
  └───────────────┘     │ 3. attribute to    │     │ Per-call cost │
                         │    agent/task      │     │ entries       │
  ┌───────────────┐     │ 4. store entry     │     └──────────────┘
  │ AWS Cost       │────>│ 5. check budgets   │
  │ Explorer       │     │ 6. fire alerts     │            │
  │                │     │                    │            v
  │ EC2 / Lambda   │     └────────────────────┘     ┌──────────────┐
  │ compute costs  │                                │  Budget       │
  └───────────────┘                                 │  Alerts       │
                                                    │               │
                                                    │  PK=BUDGET#id │
                                                    │  threshold_pct│
                                                    │  notify_email │
                                                    └──────────────┘
```

---

## 11. Observability

### 11.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `accountant_cost_ingested_total` | Counter | `provider`, `cost_type` | Total cost entries ingested |
| `accountant_total_cost_cents` | Counter | `agent_type`, `provider` | Running total cost in cents |
| `accountant_budget_utilization_pct` | Gauge | `budget_id` | Current budget utilization percentage |
| `accountant_budget_alert_fired_total` | Counter | `budget_id`, `threshold` | Budget alert notifications |
| `accountant_ingestion_latency_ms` | Histogram | `provider` | Time to fetch and process cost data |
| `accountant_idle_compute_cost_cents` | Counter | `agent_type` | Cost attributed to idle compute resources |

### 11.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Cost entry created | INFO | `agent_id`, `provider`, `cost_cents`, `tokens`, `task_id` |
| Budget threshold reached | WARN | `budget_id`, `current_pct`, `threshold_pct`, `period` |
| Budget exceeded | ERROR | `budget_id`, `budget_cents`, `actual_cents`, `overage_pct` |
| Provider API error | ERROR | `provider`, `error`, `retry_count` |
| Cost reconciliation mismatch | WARN | `provider`, `expected_cents`, `actual_cents`, `delta_pct` |

### 11.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Budget 80% threshold | Any budget > 80% utilization | Medium |
| Budget exceeded | Any budget > 100% utilization | High |
| Cost ingestion stalled | No new entries in 1 hour during business hours | High |
| Cost anomaly detected | Hourly cost > 3x rolling average | High |
| Provider API unreachable | 3+ consecutive failures | Medium |

---

## 12. Rollout Plan

### 12.1 Feature Flag

<!-- NOTE: Neither `accountant_agent_enabled` nor `accountant_agent_auto_alert` exist in `app/core/settings.py` yet — new settings required. See existing feature flag pattern, e.g., `broadcast_tipping_enabled` at settings.py:507. -->
```python
# app/core/settings.py
accountant_agent_enabled: bool = os.environ.get("ACCOUNTANT_AGENT_ENABLED", "false").lower() == "true"
accountant_agent_auto_alert: bool = os.environ.get("ACCOUNTANT_AGENT_AUTO_ALERT", "false").lower() == "true"
```

### 12.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Ingestion only | Collect cost data without alerts | 1 week | Data accuracy verified against provider dashboards |
| Phase 2: Dashboard | Enable cost dashboard widgets | 3 days | Dashboard shows correct totals and breakdowns |
| Phase 3: Budget alerts | Enable budget threshold alerts | 3 days | Alerts fire correctly; no false positives |
| Phase 4: Recommendations | Enable idle detection and optimization suggestions | Permanent | Recommendations are actionable and accurate |

---

## 13. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Provider API polling latency | < 5s per provider | Async concurrent polling; 5-minute intervals |
| Cost aggregation query | < 200ms p95 | DDB query with date range on GSI; pre-aggregated daily totals |
| Budget check latency | < 50ms | Cache current budget state in memory; refresh on cost write |
| Dashboard widget load | < 500ms | Pre-computed daily/weekly/monthly rollups |
| Historical cost query (90 days) | < 1s | GSI query with pagination; client-side aggregation for charts |
| Cost entry write throughput | 100+ entries/sec | DDB on-demand capacity; batch writes for bulk ingestion |

---

## 14. Error Handling Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Provider API unreachable | 503 | `provider_unavailable` | "Cost provider temporarily unavailable" | Retry in 5 minutes; use cached data |
| Invalid cost data format | 422 | `invalid_cost_data` | "Unrecognized cost data format from provider" | Log and skip; alert team |
| Budget not found | 404 | `budget_not_found` | "Budget configuration not found" | Create default budget |
| Agent not found for attribution | 404 | `agent_not_found` | "Agent not found for cost attribution" | Attribute to "unattributed" bucket |
| Cost reconciliation failure | 500 | `reconciliation_error` | "Cost reconciliation failed" | Manual investigation required |
| Budget update conflict | 409 | `budget_conflict` | "Budget was updated by another request" | Retry with fresh version |

---

## 15. API Request/Response Examples

**Get cost summary for an agent**:

```
GET /ui/agents/accountant/costs?agent_id=agent_mktg_001&period=7d
```

**Response (200)**:
```json
{
  "agent_id": "agent_mktg_001",
  "period": "7d",
  "total_cost_cents": 4250,
  "breakdown": {
    "llm_tokens": {"cost_cents": 3800, "input_tokens": 125000, "output_tokens": 45000},
    "compute": {"cost_cents": 450, "instance_hours": 12.5}
  },
  "daily_costs": [
    {"date": "2026-05-23", "cost_cents": 620},
    {"date": "2026-05-24", "cost_cents": 580},
    {"date": "2026-05-25", "cost_cents": 710}
  ]
}
```

**Get budget status**:

```
GET /ui/agents/accountant/budgets/budget_monthly_001
```

**Response (200)**:
```json
{
  "budget_id": "budget_monthly_001",
  "name": "Monthly Agent Budget",
  "period": "monthly",
  "budget_cents": 50000,
  "spent_cents": 32500,
  "utilization_pct": 65.0,
  "alerts": [
    {"threshold_pct": 80, "status": "not_triggered"},
    {"threshold_pct": 100, "status": "not_triggered"}
  ],
  "period_start": "2026-05-01",
  "period_end": "2026-05-31"
}
```

**Create budget with alert thresholds**:

```
POST /ui/agents/accountant/budgets
Content-Type: application/json
x-csrf-token: <csrf>

{
  "name": "Weekly LLM Budget",
  "period": "weekly",
  "budget_cents": 10000,
  "alert_thresholds": [50, 80, 100],
  "notify_emails": ["admin@test.local"]
}
```

**Response (201)**:
```json
{
  "budget_id": "budget_weekly_002",
  "name": "Weekly LLM Budget",
  "period": "weekly",
  "budget_cents": 10000,
  "spent_cents": 0,
  "utilization_pct": 0.0
}
```

---

## 16. Architecture Diagram

```
                    Accountant Agent — System Architecture
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                          External Data Sources                              │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
  │  │ Anthropic API     │  │ OpenAI API       │  │ AWS Cost Explorer        │  │
  │  │ Usage & Billing   │  │ Usage & Billing  │  │ EC2 / Lambda / K8s      │  │
  │  │ Endpoints         │  │ Endpoints        │  │ Compute Cost Data        │  │
  │  └────────┬─────────┘  └────────┬─────────┘  └─────────────┬────────────┘  │
  └───────────┼──────────────────────┼──────────────────────────┼───────────────┘
              │                      │                          │
              └──────────────────────┼──────────────────────────┘
                                     │ HTTP / AWS SDK
  ┌──────────────────────────────────┼──────────────────────────────────────────┐
  │                       FastAPI Backend                                        │
  │  ┌───────────────────────────────┴──────────────────────────────────────┐   │
  │  │                  Cost Ingestion Worker (background task)              │   │
  │  │   ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐     │   │
  │  │   │ LLM Provider  │  │ Compute Cost │  │ Budget Checker        │     │   │
  │  │   │ Poller        │  │ Poller       │  │                       │     │   │
  │  │   │               │  │              │  │ check_budgets()       │     │   │
  │  │   │ poll per key  │  │ query Cost   │  │ fire alerts if >     │     │   │
  │  │   │ normalize to  │  │ Explorer     │  │   threshold_pct      │     │   │
  │  │   │ cost_cents    │  │ per worker   │  │ auto-pause workers   │     │   │
  │  │   └──────┬───────┘  └──────┬───────┘  │   if auto_pause=true │     │   │
  │  │          │                  │           └──────────┬────────────┘     │   │
  │  │          └──────────────────┼──────────────────────┘                  │   │
  │  │                             │                                         │   │
  │  │   record_cost_entry() + attribute_cost_to_ticket()                    │   │
  │  └─────────────────────────────┼────────────────────────────────────────┘   │
  │                                │                                            │
  │  ┌─────────────────────────────┴────────────────────────────────────────┐   │
  │  │              app/routers/agent_accountant.py (API Layer)              │   │
  │  │   GET /costs/summary/daily   GET /costs/by-agent-type                │   │
  │  │   GET /costs/by-ticket       GET /costs/trends                       │   │
  │  │   POST /costs/budgets        GET /costs/alerts                       │   │
  │  │   PUT /costs/config          GET /costs/optimizations                │   │
  │  └─────────────────────────────┬────────────────────────────────────────┘   │
  │                                │                                            │
  │  ┌─────────────────────────────┴────────────────────────────────────────┐   │
  │  │              app/services/agent_accountant.py (Business Logic)        │   │
  │  │                                                                       │   │
  │  │   get_daily_summary()     get_period_summary()                        │   │
  │  │   get_agent_type_costs()  get_ticket_cost()  list_ticket_costs()      │   │
  │  │   create_budget()         check_budgets()    list_alerts()            │   │
  │  │   get_cost_trends()       get_optimization_recommendations()          │   │
  │  └─────────────────────────────┬────────────────────────────────────────┘   │
  │                                │                                            │
  │  ┌─────────────────────────────┴────────────────────────────────────────┐   │
  │  │                          DynamoDB Tables                              │   │
  │  │   ┌────────────────┐ ┌────────────────┐ ┌─────────────┐ ┌────────┐  │   │
  │  │   │ agent_costs    │ │ agent_ticket_  │ │ agent_cost_ │ │ agent_ │  │   │
  │  │   │                │ │ costs          │ │ budgets     │ │ cost_  │  │   │
  │  │   │ PK=USER#id    │ │ PK=USER#id    │ │ PK=USER#id  │ │ alerts │  │   │
  │  │   │ SK=COST#date  │ │ SK=TCOST#tid  │ │ SK=BUDGET#  │ │        │  │   │
  │  │   │   #worker     │ │               │ │   bid       │ │ PK=    │  │   │
  │  │   │               │ │ GSI1: by cost │ │             │ │ USER#  │  │   │
  │  │   │ GSI1: by date │ │   (sorted)    │ │             │ │ SK=    │  │   │
  │  │   │ GSI2: by type │ │               │ │             │ │ ALERT# │  │   │
  │  │   └────────────────┘ └────────────────┘ └─────────────┘ └────────┘  │   │
  │  └──────────────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────────────┘
                                     │
  ┌──────────────────────────────────┼──────────────────────────────────────────┐
  │                          Platform Frontend                                  │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
  │  │ CostOverviewPage │  │ CostBreakdown    │  │ BudgetManagerPage        │  │
  │  │                   │  │ Page             │  │                          │  │
  │  │ summary cards,    │  │ by agent type,   │  │ budget list, progress    │  │
  │  │ stacked area      │  │ by worker,       │  │ bars, create/edit,       │  │
  │  │ chart, pie chart, │  │ by ticket,       │  │ toggle auto-pause        │  │
  │  │ alert banner      │  │ date range       │  │                          │  │
  │  └──────────────────┘  └──────────────────┘  └──────────────────────────┘  │
  │                                                                             │
  │  ┌──────────────────┐  ┌──────────────────────────────────────────────┐    │
  │  │ CostAlertsPage   │  │ OptimizationsPanel                          │    │
  │  │                   │  │                                              │    │
  │  │ alert cards,      │  │ idle workers, model downgrade suggestions,  │    │
  │  │ severity badges,  │  │ high cost-per-ticket agents, savings est.   │    │
  │  │ acknowledge btn   │  │                                              │    │
  │  └──────────────────┘  └──────────────────────────────────────────────┘    │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Example |
|---|---------------|-------|---------------|-----|---------|
| 1 | Record/upsert daily cost entry | `agent_costs` | `PK=USER#{user_id}, SK=COST#{date}#{worker_id}` | -- | `update_item` ADD to atomic counters |
| 2 | Get daily summary by date | `agent_costs` | `GSI1PK=USER#{user_id}#DATE#{date}` | GSI1 | All worker entries for a specific day |
| 3 | Get costs by agent type | `agent_costs` | `GSI2PK=USER#{user_id}#TYPE#{agent_type}, GSI2SK between(start, end)` | GSI2 | Last 30 days for the "coder" agent type |
| 4 | Attribute cost to ticket | `agent_ticket_costs` | `PK=USER#{user_id}, SK=TCOST#{ticket_id}` | -- | `update_item` ADD to atomic counters |
| 5 | Get ticket cost | `agent_ticket_costs` | `PK=USER#{user_id}, SK=TCOST#{ticket_id}` | -- | `get_item` |
| 6 | List tickets by cost | `agent_ticket_costs` | `GSI1PK=USER#{user_id}#TICKET_COSTS` | GSI1 | Sorted by `total_cost_cents` desc |
| 7 | Create budget | `agent_cost_budgets` | `PK=USER#{user_id}, SK=BUDGET#{budget_id}` | -- | `put_item` |
| 8 | List budgets | `agent_cost_budgets` | `PK=USER#{user_id}, SK begins_with("BUDGET#")` | -- | All budgets for user |
| 9 | Create alert | `agent_cost_alerts` | `PK=USER#{user_id}, SK=ALERT#{alert_id}` | -- | `put_item` |
| 10 | List alerts by date | `agent_cost_alerts` | `GSI1PK=USER#{user_id}#ALERTS` | GSI1 | Sorted by `created_at` desc |
| 11 | Acknowledge alert | `agent_cost_alerts` | `PK=USER#{user_id}, SK=ALERT#{alert_id}` | -- | `update_item` set `acknowledged=true` |

**Example DynamoDB item (AgentCosts)**:

```json
{
  "pk": {"S": "USER#alice_sub_123"},
  "sk": {"S": "COST#2026-05-29#worker_coder_001"},
  "user_id": {"S": "alice_sub_123"},
  "worker_id": {"S": "worker_coder_001"},
  "agent_type": {"S": "coder"},
  "agent_id": {"S": "agent_coder_primary"},
  "date": {"S": "2026-05-29"},
  "llm_input_tokens": {"N": "85000"},
  "llm_output_tokens": {"N": "32000"},
  "llm_cached_tokens": {"N": "15000"},
  "llm_cost_cents": {"N": "520"},
  "llm_provider": {"S": "anthropic"},
  "llm_model": {"S": "claude-sonnet-4-20250514"},
  "compute_hours": {"N": "4.5"},
  "compute_cost_cents": {"N": "45"},
  "total_cost_cents": {"N": "565"},
  "tickets_worked": {"N": "3"},
  "tickets_completed": {"N": "1"},
  "updated_at": {"N": "1748520200"},
  "GSI1PK": {"S": "USER#alice_sub_123#DATE#2026-05-29"},
  "GSI1SK": {"S": "TYPE#coder#WORKER#worker_coder_001"},
  "GSI2PK": {"S": "USER#alice_sub_123#TYPE#coder"},
  "GSI2SK": {"S": "DATE#2026-05-29"}
}
```

**Example DynamoDB item (TicketCosts)**:

```json
{
  "pk": {"S": "USER#alice_sub_123"},
  "sk": {"S": "TCOST#AGENT-017"},
  "ticket_id": {"S": "AGENT-017"},
  "user_id": {"S": "alice_sub_123"},
  "agent_type": {"S": "coder"},
  "total_llm_tokens": {"N": "210000"},
  "total_llm_cost_cents": {"N": "1480"},
  "total_compute_hours": {"N": "12.0"},
  "total_compute_cost_cents": {"N": "120"},
  "total_cost_cents": {"N": "1600"},
  "worker_sessions": {"N": "8"},
  "status": {"S": "completed"},
  "started_at": {"N": "1748100000"},
  "completed_at": {"N": "1748520000"},
  "GSI1PK": {"S": "USER#alice_sub_123#TICKET_COSTS"},
  "GSI1SK": {"N": "1600"}
}
```

---

## 18. Pydantic Models
<!-- NOTE: None of these Pydantic models exist yet in `app/models.py` — all are new implementations required. The file is currently ~2000 lines of existing models. -->

```python
# In app/models.py

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal


class RecordCostEntryIn(BaseModel):
    """Request model for recording a cost entry (internal use by ingestion worker)."""
    worker_id: str = Field(..., min_length=1, max_length=100)
    agent_type: str = Field(..., min_length=1, max_length=50)
    agent_id: str = Field(..., min_length=1, max_length=100)
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    llm_input_tokens: int = Field(default=0, ge=0)
    llm_output_tokens: int = Field(default=0, ge=0)
    llm_cached_tokens: int = Field(default=0, ge=0)
    llm_cost_cents: int = Field(default=0, ge=0)
    llm_provider: str = Field(default="anthropic", max_length=50)
    llm_model: str = Field(default="unknown", max_length=100)
    compute_hours: float = Field(default=0.0, ge=0.0)
    compute_cost_cents: int = Field(default=0, ge=0)


class AttributeTicketCostIn(BaseModel):
    """Request model for attributing cost to a ticket."""
    ticket_id: str = Field(..., min_length=1, max_length=100)
    agent_type: str = Field(..., min_length=1, max_length=50)
    llm_tokens: int = Field(default=0, ge=0)
    llm_cost_cents: int = Field(default=0, ge=0)
    compute_hours: float = Field(default=0.0, ge=0.0)
    compute_cost_cents: int = Field(default=0, ge=0)


class CreateBudgetIn(BaseModel):
    """Request model for creating a cost budget."""
    name: str = Field(..., min_length=1, max_length=200)
    scope: Literal["overall", "agent_type", "agent_instance"]
    scope_ref: Optional[str] = Field(
        default=None, max_length=100,
        description="Agent type or agent ID for scoped budgets"
    )
    period: Literal["daily", "weekly", "monthly"]
    limit_cents: int = Field(..., ge=100, description="Minimum $1.00")
    alert_threshold_pct: int = Field(default=80, ge=10, le=100)
    auto_pause_on_exceed: bool = False

    @model_validator(mode="after")
    def validate_scope_ref(self):
        if self.scope in ("agent_type", "agent_instance") and not self.scope_ref:
            raise ValueError("scope_ref is required when scope is agent_type or agent_instance")
        return self


class UpdateBudgetIn(BaseModel):
    """Request model for updating a cost budget."""
    name: Optional[str] = Field(default=None, max_length=200)
    limit_cents: Optional[int] = Field(default=None, ge=100)
    alert_threshold_pct: Optional[int] = Field(default=None, ge=10, le=100)
    auto_pause_on_exceed: Optional[bool] = None
    enabled: Optional[bool] = None


class CostEntryOut(BaseModel):
    """Response model for a cost entry."""
    worker_id: str
    agent_type: str
    agent_id: str
    date: str
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    llm_cached_tokens: int = 0
    llm_cost_cents: int = 0
    llm_provider: str = ""
    llm_model: str = ""
    compute_hours: float = 0.0
    compute_cost_cents: int = 0
    total_cost_cents: int = 0
    tickets_worked: int = 0
    tickets_completed: int = 0


class CostDailySummaryOut(BaseModel):
    """Response model for daily cost summary."""
    date: str
    total_cents: int = 0
    llm_cents: int = 0
    compute_cents: int = 0
    by_agent_type: Dict[str, int] = Field(default_factory=dict)
    by_worker: List[CostEntryOut] = Field(default_factory=list)


class CostPeriodSummaryOut(BaseModel):
    """Response model for period cost summary."""
    period: str
    start_date: str
    end_date: str
    total_cents: int = 0
    llm_cents: int = 0
    compute_cents: int = 0
    by_agent_type: Dict[str, int] = Field(default_factory=dict)
    budget_utilization: List[Dict[str, Any]] = Field(default_factory=list)


class TicketCostOut(BaseModel):
    """Response model for ticket cost data."""
    ticket_id: str
    agent_type: str = ""
    total_llm_tokens: int = 0
    total_llm_cost_cents: int = 0
    total_compute_hours: float = 0.0
    total_compute_cost_cents: int = 0
    total_cost_cents: int = 0
    worker_sessions: int = 0
    status: str = "in_progress"
    started_at: Optional[int] = None
    completed_at: Optional[int] = None


class BudgetOut(BaseModel):
    """Response model for a cost budget."""
    budget_id: str
    name: str
    scope: str
    scope_ref: Optional[str] = None
    period: str
    limit_cents: int
    alert_threshold_pct: int = 80
    auto_pause_on_exceed: bool = False
    enabled: bool = True
    created_at: int = 0


class CostAlertOut(BaseModel):
    """Response model for a cost alert."""
    alert_id: str
    budget_id: Optional[str] = None
    alert_type: str
    severity: str
    title: str
    message: str
    current_spend_cents: int = 0
    budget_limit_cents: Optional[int] = None
    acknowledged: bool = False
    auto_action_taken: Optional[str] = None
    created_at: int = 0


class CostTrendsOut(BaseModel):
    """Response model for cost trends data."""
    weeks: List[Dict[str, Any]] = Field(default_factory=list)


class OptimizationRecommendationOut(BaseModel):
    """Response model for a cost optimization recommendation."""
    type: Literal["idle_worker", "model_downgrade", "high_cost_ticket", "underutilized_agent"]
    title: str
    description: str
    potential_savings_cents: int = 0
    action: str


class UpdateAccountantConfigIn(BaseModel):
    """Request model for updating accountant agent configuration."""
    collection_frequency: Optional[Literal["hourly", "every_6h", "daily"]] = None
    report_frequency: Optional[Literal["daily", "weekly", "monthly"]] = None
    report_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    compute_pricing: Optional[Dict[str, int]] = None
    anomaly_detection_enabled: Optional[bool] = None
    anomaly_threshold_pct: Optional[int] = Field(default=None, ge=100, le=1000)
    idle_worker_threshold_minutes: Optional[int] = Field(default=None, ge=10, le=1440)
    optimization_suggestions_enabled: Optional[bool] = None
```

---

## 19. Frontend Component Tree

```
/agents/costs — CostOverviewPage
├── AlertBanner (if unacknowledged alerts exist)
│   ├── Alert icon + severity color
│   ├── Alert title + message summary
│   └── "View Alerts" link → CostAlertsPage
├── SummaryCardsRow
│   ├── TodaySpendCard
│   │   ├── Amount (formatted as $XX.XX)
│   │   ├── TrendArrow (vs yesterday)
│   │   └── BudgetProgressBar (if daily budget set)
│   ├── WeekSpendCard (same structure)
│   ├── MonthSpendCard (same structure)
│   └── ProjectedMonthCard (extrapolated from daily average)
├── CostStackedAreaChart
│   ├── x-axis: dates (last 30 days)
│   ├── StackedArea: LLM cost (blue)
│   ├── StackedArea: Compute cost (green)
│   └── BudgetLine (horizontal dashed line at daily budget limit)
├── PerAgentTypePieChart
│   ├── Slices: coder, security, pm, docs, marketing, etc.
│   ├── Legend with percentages
│   └── CenterLabel: total spend
├── OptimizationsPanel (inline or as collapsible section)
│   └── RecommendationCard (one per recommendation)
│       ├── TypeIcon (idle, downgrade, high-cost, underutilized)
│       ├── Title
│       ├── Description
│       ├── SavingsBadge ("Save $X.XX/month")
│       └── ActionButton ("Pause Worker" / "Switch Model" / etc.)
└── QuickLinksRow
    ├── "View Breakdown" → CostBreakdownPage
    ├── "Manage Budgets" → BudgetManagerPage
    └── "View Alerts" → CostAlertsPage

/agents/costs/breakdown — CostBreakdownPage
├── DateRangePicker (start date, end date)
├── ViewTabs
│   ├── Tab: "By Agent Type"
│   ├── Tab: "By Worker"
│   └── Tab: "By Ticket"
├── BreakdownTable (content changes per active tab)
│   ├── ByAgentType view
│   │   ├── Columns: Agent Type | LLM Tokens | LLM Cost | Compute Hours | Compute Cost | Total | % of Total
│   │   ├── Rows sorted by total desc
│   │   └── ExpandableRow → daily entries for that agent type
│   ├── ByWorker view
│   │   ├── Columns: Worker ID | Agent Type | Date | LLM Cost | Compute Cost | Total | Tickets
│   │   └── Rows sorted by date desc
│   └── ByTicket view
│       ├── Columns: Ticket ID | Agent Type | LLM Tokens | LLM Cost | Compute Cost | Total | Sessions | Status
│       ├── Rows sorted by total_cost desc (via GSI1)
│       └── StatusBadge (in_progress / completed)
└── ExportButton ("Download CSV")

/agents/costs/budgets — BudgetManagerPage
├── PageHeader
│   ├── <h1> "Budget Manager"
│   └── CreateBudgetButton → BudgetFormDialog
├── BudgetList
│   └── BudgetCard (one per budget)
│       ├── NameAndScope (e.g., "Overall Daily" or "Coder Agent Monthly")
│       ├── ProgressBar (spent / limit, color: green < 80%, yellow 80-100%, red > 100%)
│       ├── SpendLabel ("$32.50 / $50.00")
│       ├── ThresholdMarker (vertical line at alert_threshold_pct)
│       ├── AutoPauseToggle (switch for auto_pause_on_exceed)
│       ├── EnabledToggle (switch for enabled)
│       └── ActionsDropdown (Edit, Delete)
├── BudgetFormDialog
│   ├── NameInput
│   ├── ScopeSelect (Overall / Agent Type / Agent Instance)
│   ├── ScopeRefSelect (conditional, agent type or instance picker)
│   ├── PeriodSelect (Daily / Weekly / Monthly)
│   ├── LimitInput (dollar amount, converts to cents)
│   ├── ThresholdSlider (10-100%)
│   ├── AutoPauseCheckbox
│   └── SaveButton
└── BudgetSummary (totals: active budgets, total limits, total utilization)

/agents/costs/alerts — CostAlertsPage
├── FilterBar
│   ├── StatusFilter: "Unacknowledged" | "All"
│   └── SeverityFilter: "All" | "Critical" | "Warning" | "Info"
├── AlertList
│   └── AlertCard (one per alert)
│       ├── SeverityBadge (critical=red, warning=yellow, info=blue)
│       ├── AlertTypeIcon (budget_threshold, budget_exceeded, spending_anomaly, etc.)
│       ├── Title
│       ├── Message (detailed description)
│       ├── SpendContext ("Spent $42.50 of $50.00 daily budget")
│       ├── AutoActionTag (if auto_action_taken, e.g., "Workers paused")
│       ├── Timestamp (created_at formatted)
│       └── AcknowledgeButton (if not acknowledged)
└── EmptyState ("No alerts — your budgets are on track")

---

## Codebase References

### Verified Existing Files
| File | Line(s) | What |
|------|---------|------|
| `app/services/billing_shared.py` | 16, 20, 217 | `user_pk()`, `ddb_get()`, `new_ledger_entry()` — billing helpers referenced by this ticket |
| `app/core/aws.py` | 1-41 | boto3 client wrappers (`ddb_resource`, `kms_client`, `secretsmanager_client`, `sqs_client`) |
| `app/core/settings.py` | 452-511 | Existing broadcast/analytics settings — pattern for new `accountant_agent_*` settings |
| `app/core/tables.py` | 39-43, 163-167 | Existing broadcast table handles — pattern for new `agent_costs`/`agent_cost_*` handles |
| `app/main.py` | 396-435 | Existing router registrations (broadcast, analytics) — pattern for `agent_accountant_router` |
| `scripts/local-ddb-init.py` | 513-578 | Existing broadcast `TableDef` entries — pattern for new agent cost tables |
| `app/models.py` | (entire file) | Existing Pydantic models (~2000 lines) — `CostEntryOut`, `BudgetOut`, etc. go here |
| `frontend/src/api/types.ts` | (entire file) | Existing TypeScript interfaces — pattern for agent cost types |
| `frontend/src/api/endpoints/analytics.ts` | (entire file) | Existing API endpoint wrappers — pattern for `agents.ts` |
| `docs/tickets/AGENT-001-llm-provider-key-management.md` | — | Dependency ticket spec (no code yet) |
| `docs/tickets/AGENT-002-terminal-worker-provisioning.md` | — | Dependency ticket spec (no code yet) |
| `docs/tickets/AGENT-003-worker-agent-framework-lifecycle.md` | — | Dependency ticket spec (no code yet) |
| `docs/tickets/AGENT-004-worker-fleet-management-ui.md` | — | Dependency ticket spec (no code yet) |
| `docs/tickets/AGENT-005-agent-memory-context-injection.md` | — | Dependency ticket spec (no code yet) |
| `docs/tickets/AGENT-006-terminal-monitoring-feedback-loop.md` | — | Dependency ticket spec (no code yet) |
| `docs/tickets/AGENT-007-agent-pr-ticket-integration.md` | — | Dependency ticket spec (no code yet) |

### Files That Do NOT Exist Yet (New Implementation Required)
| File | Purpose |
|------|---------|
| `app/services/agent_accountant.py` | Cost recording, aggregation, budgets, alerts, optimizations service |
| `app/routers/agent_accountant.py` | Cost tracking API endpoints router |
| `frontend/src/api/endpoints/agents.ts` | Frontend API wrappers for agent cost endpoints |
| `frontend/src/pages/agents/CostOverviewPage.tsx` | Cost dashboard page |
| `frontend/src/pages/agents/CostBreakdownPage.tsx` | Detailed cost breakdown page |
| `frontend/src/pages/agents/BudgetManagerPage.tsx` | Budget CRUD page |
| `frontend/src/pages/agents/CostAlertsPage.tsx` | Alert management page |
| `frontend/src/pages/agents/OptimizationsPanel.tsx` | Optimization recommendations panel |

### DynamoDB Tables That Do NOT Exist Yet
| Table Name | Notes |
|------------|-------|
| `agent_costs` | Not in `scripts/local-ddb-init.py`; no setting in `settings.py`; no handle in `tables.py` |
| `agent_ticket_costs` | Not in `scripts/local-ddb-init.py`; no setting in `settings.py`; no handle in `tables.py` |
| `agent_cost_budgets` | Not in `scripts/local-ddb-init.py`; no setting in `settings.py`; no handle in `tables.py` |
| `agent_cost_alerts` | Not in `scripts/local-ddb-init.py`; no setting in `settings.py`; no handle in `tables.py` |

### Settings That Do NOT Exist Yet
| Setting | Notes |
|---------|-------|
| `accountant_agent_enabled` | Feature flag — not in `app/core/settings.py` |
| `accountant_agent_auto_alert` | Feature flag — not in `app/core/settings.py` |
| `agent_costs_table_name` | Table name setting — not in `app/core/settings.py` |
| `agent_ticket_costs_table_name` | Table name setting — not in `app/core/settings.py` |
| `agent_cost_budgets_table_name` | Table name setting — not in `app/core/settings.py` |
| `agent_cost_alerts_table_name` | Table name setting — not in `app/core/settings.py` |

### Router Registration
- `agent_accountant_router` is NOT registered in `app/main.py` — new registration required
- No `/agents/*` routes exist in `frontend/src/App.tsx`
```

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_accountant_agent.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_accountant_agent` | Creates record with correct fields and generated ID |
| `test_create_accountant_agent_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_accountant_agent_found` | Returns correct record by ID |
| `test_get_accountant_agent_not_found` | Returns None for non-existent ID |
| `test_list_accountant_agent` | Returns all records for the given scope/owner |
| `test_update_accountant_agent` | Updates mutable fields and sets updated_at |
| `test_delete_accountant_agent` | Removes record; subsequent get returns None |
| `test_accountant_agent_owner_check` | Rejects operations from non-owner users |
| `test_accountant_agent_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_accountant_agent_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-accountant.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**: Uses existing tables; no new tables required. See DDB access patterns in technical design section.


### CI/Pipeline


- **Feature flags**: None required for dev/test
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| AGENT-001 | LLM provider keys | Pending | No |
| AGENT-002 | Terminal provisioning | Pending | No |
| AGENT-003 | Agent framework | Pending | No |
| AGENT-004 | Fleet UI | Pending | No |
| AGENT-005 | Context injection | Pending | No |
| AGENT-006 | Monitoring | Pending | No |
| AGENT-007 | PR/ticket integration | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| (none currently identified) | -- |

### Merge Strategy


**Sequential (after AGENT-007)**


- Must merge after: AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/agents/accountant`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
