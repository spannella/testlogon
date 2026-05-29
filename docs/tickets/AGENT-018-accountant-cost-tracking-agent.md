# AGENT-018: Accountant / Cost Tracking Agent

**Ticket**: AGENT-018
**Author**: Engineering
**Status**: Design
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

- **Agent Registry** (AGENT-001): Agent type definitions, worker assignments.
- **Worker Agent Framework** (AGENT-003): Task execution with duration tracking.
- **Agent Monitoring** (AGENT-006): Worker health, uptime, task completion metrics.
- **Ticket Lifecycle Bridge** (AGENT-004): Ticket assignment and completion tracking.
- **Billing system** (`app/services/billing.py`): Existing billing infrastructure for platform payments.
- **AWS SDK** (`app/core/aws.py`): boto3 helpers for AWS API calls.

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

```python
from app.routers.agent_accountant import router as agent_accountant_router
app.include_router(agent_accountant_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

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

Standard wrappers: `getDailyCostSummary(date)`, `getPeriodCostSummary(start, end, period)`, `getAgentTypeCosts(agentType, days?)`, `listTicketCosts(limit?)`, `getTicketCost(ticketId)`, `getCostTrends(days?)`, `getOptimizations()`, `listBudgets()`, `createBudget(data)`, `updateBudget(budgetId, data)`, `deleteBudget(budgetId)`, `listAlerts(acknowledged?)`, `acknowledgeAlert(alertId)`, `updateAccountantConfig(config)`, `triggerCostCollection()`.

### 3.6 Frontend Pages

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
| `scripts/local-ddb-init.py` | Add `agent_costs`, `agent_ticket_costs`, `agent_cost_budgets`, `agent_cost_alerts` TableDefs |
| `app/core/settings.py` | Add table name settings |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `agent_accountant_router` |
| `app/models.py` | Add `CostEntryOut`, `CostSummaryOut`, `TicketCostOut`, `BudgetOut`, `AlertOut` models |
| `frontend/src/api/types.ts` | Add cost, budget, alert, optimization types |
| `frontend/src/api/endpoints/agents.ts` | Add Accountant Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/costs`, `/agents/costs/breakdown`, `/agents/costs/budgets`, `/agents/costs/alerts` routes |

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

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, worker assignments) |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (compute cost tracking per instance) |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (task duration tracking, token usage reporting) |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (ticket-to-cost attribution) |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting provider API credentials into agent terminal) |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (worker health data for idle detection) |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (cost widgets on orchestration dashboard) |
| LLM Provider APIs | External | Required (Anthropic/OpenAI usage/billing endpoints) |
| AWS Cost Explorer | External | Required (EC2/K8s compute cost data) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| All other AGENT types | Cost data attributed to each agent type's operations |
| AGENT-013 (PM Agent) | PM Agent reviews may reference cost data when prioritizing features |
