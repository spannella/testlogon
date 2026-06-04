# AGENT-018: Accountant / Cost Tracking Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

The Accountant Agent tracks and attributes LLM token + compute spending across all agent workers, enforces configurable budget caps, fires threshold/overspend alerts, surfaces cost-optimization recommendations, and exposes a multi-view cost dashboard for platform owners. It is a schedule-driven agent type rather than a ticket-reacting one: cost data is injected by workers (or manually via API) and aggregated into daily summaries, period rollups, and per-ticket attribution rows.

- **Type**: Feature (new agent type, financial control system)
- **Priority**: High
- **Status**: Implemented — backend service, router, frontend dashboard pages, settings, and table handles are all live
- **Persona**: Platform owner (financial visibility + spend controls)
- **Cross-references**: AGENT-001 (registry), AGENT-003 (worker framework), AGENT-006 (monitoring), AGENT-017 (marketing agent is a cost source), INFRA-005 (compute cost)
- **Dev/Prod parity**: SECOPS-007 compliant — provider/cloud API polling gated behind `ACCOUNTANT_AGENT_EXECUTE_COMMANDS=0` (default off); budgets and alerts evaluated deterministically over recorded cost data in both modes

---

## 2. Current-State Investigation

### 2.1 Backend service (`app/services/agent_accountant.py`)

The service is fully implemented. The key structural choices:

**Decimal coercion** (lines 69–91): `_to_dec` recursively converts Python floats to `Decimal(str(x))` before DDB writes (boto3 rejects native floats). `_num` and `_int` coerce stored `Decimal` values back to Python on read. This is the correct pattern for financial amounts.

**Table bootstrap** (`ensure_tables`, lines 101–199): idempotent self-creation of all four accountant tables using the DDB client directly. Tables:
- `accountant_costs` (settings key `agent_costs_table_name`, `app/core/settings.py:2284`): PK=`USER#{user_id}`, SK=`COST#{date}#{worker_id}`, GSI1 by `GSI1PK=USER#{user_id}#DATE#{date}`, GSI2 by `GSI2PK=USER#{user_id}#TYPE#{agent_type}` with string `GSI2SK=DATE#{date}`. Note: **GSI2SK is a string** (`DATE#{date}`), not a number, so date-range queries use lexicographic `between` comparisons — this works correctly because ISO date strings sort lexicographically.
- `accountant_ticket_costs` (`agent_ticket_costs_table_name`, `settings.py:2285`): PK=`USER#{user_id}`, SK=`TCOST#{ticket_id}`, GSI1 sorts by `total_cost_cents` (numeric, type N declared at bootstrap line 143).
- `accountant_cost_budgets` (`agent_cost_budgets_table_name`, `settings.py:2288`): no GSI; budget list is a range query on the base table `SK begins_with BUDGET#`.
- `accountant_cost_alerts` (`agent_cost_alerts_table_name`, `settings.py:2291`): GSI1 on `GSI1PK=USER#{user_id}#ALERTS` with numeric `GSI1SK=created_at`.

**Table handles** (`app/core/tables.py:285–288,520–523`):
```python
agent_costs        = _safe_table(S.agent_costs_table_name)
agent_ticket_costs = _safe_table(S.agent_ticket_costs_table_name)
agent_cost_budgets = _safe_table(S.agent_cost_budgets_table_name)
agent_cost_alerts  = _safe_table(S.agent_cost_alerts_table_name)
```

### 2.2 Backend router (`app/routers/agent_accountant.py`)

Router registered in `app/main.py` at lines 785–786. Prefix: `/ui/agents/costs`. All cost summary, budget CRUD, alert management, and optimization endpoints are present.

### 2.3 Settings flags (`app/core/settings.py:2282–2302`)

```
agent_costs_table_name          = AGENT_COSTS_TABLE_NAME         (default "accountant_costs")
agent_ticket_costs_table_name   = AGENT_TICKET_COSTS_TABLE_NAME  (default "accountant_ticket_costs")
agent_cost_budgets_table_name   = AGENT_COST_BUDGETS_TABLE_NAME  (default "accountant_cost_budgets")
agent_cost_alerts_table_name    = AGENT_COST_ALERTS_TABLE_NAME   (default "accountant_cost_alerts")
accountant_agent_enabled        = ACCOUNTANT_AGENT_ENABLED        (default "1"=true)
accountant_agent_auto_alert     = ACCOUNTANT_AGENT_AUTO_ALERT     (default "0"=false)
accountant_agent_execute_commands = ACCOUNTANT_AGENT_EXECUTE_COMMANDS (default "0"=false)
```

### 2.4 Frontend

All five cost dashboard pages are present under `frontend/src/pages/agents/`:
- `CostOverviewPage.tsx` — summary cards, area chart, pie chart, active alerts banner
- `CostBreakdownPage.tsx` — by agent type / by worker / by ticket views
- `BudgetManagerPage.tsx` — budget list with progress bars, create/edit dialog
- `CostAlertsPage.tsx` — alert cards with severity badges, acknowledge button
- `OptimizationsPanel.tsx` — recommendation cards with potential savings

API client: `frontend/src/api/endpoints/accountantAgent.ts`.

### 2.5 Dev vs Prod behaviour

| Concern | Dev (local DDB + mock) | Prod (AWS DDB + real APIs) |
|---------|----------------------|--------------------------|
| Cost data ingestion | Manual POST via API or E2E test | Background poller calling Anthropic/OpenAI usage APIs and AWS Cost Explorer — only when `execute_commands=true` |
| Budget checks | Deterministic over recorded data; `check_budgets()` called synchronously on cost writes | Same code; also triggered by periodic collection task |
| Auto-pause workers | Never fires (no worker state in dev) | Modifies worker DDB record when `auto_pause_on_exceed=true` and budget exceeded |
| Alert delivery | Creates DDB alert records; no email/push | DDB record + email/push notification integration |

The key invariant: the cost recording and aggregation code is identical in both modes. The `execute_commands` flag only gates the external API polling wrapper, not the data model or budget enforcement logic.

---

## 3. Gap / Threat Analysis

### 3.1 What exists (verified)

- Four dedicated DDB tables with correct key schemas and numeric GSI attributes
- `record_cost_entry` with atomic `ADD` counter increments (idempotent upsert, no double-counting)
- `attribute_cost_to_ticket` similarly idempotent via atomic adds
- `get_daily_summary` queries GSI1 (`USER#{user_id}#DATE#{date}`) and aggregates by `agent_type`
- `get_period_summary` queries across a date range and computes budget utilisation
- Budget CRUD with validation (`scope_ref` required when `scope != "overall"`)
- `check_budgets` compares period spend to each budget limit, creates `agent_cost_alerts` items, honours `_MAX_ALERTS_PER_BUDGET_PER_DAY = 10` rate limit
- `get_optimization_recommendations` identifies idle workers, model-downgrade candidates, high-cost-per-ticket agents
- Configuration stored on `T.agent_types` (shared registry table) under `pk=TYPE#accountant#{user_id}`

### 3.2 Remaining gaps

1. **No automatic cost collection schedule**: the background polling task that calls Anthropic/OpenAI usage APIs is gated behind `execute_commands=true` but there is also no `asyncio` background task registered in `app/main.py` even when the flag is set. The `POST /ui/agents/costs/collect` endpoint triggers a single manual collection, but no periodic job exists.

2. **GSI2SK is string, not number**: the ticket spec shows `GSI2SK` as type `S` (string `DATE#{date}`), and the `ensure_tables` bootstrap matches this. However, the `AGENT-018` ticket's DDB table design table (§3.1.1) shows `GSI2SK` as type `S`. This diverges from the CLAUDE.md warning about numeric GSI sort keys needing `attr_types={"field": "N"}`. Because `DATE#{date}` sorts lexicographically correctly for ISO dates, this is safe for the `between` pattern used — but it prevents `<`, `>`, `BETWEEN` with numeric thresholds if a cost-range query were ever needed.

3. **Auto-pause integration is incomplete**: `check_budgets` sets an alert with `auto_action_taken` field, but there is no actual call to a worker-pause API (which doesn't yet exist — AGENT-002 Worker Provisioning is not yet implemented).

4. **`get_engagement_summary`-style N+1 issue on `get_cost_trends`**: the trends function queries each date in a 90-day range individually rather than paginating a single GSI scan. At 90 dates this is up to 90 DDB calls — acceptable today but should be addressed if the range grows.

5. **Missing Pydantic models for some response shapes**: while `CostEntryOut`, `CostSummaryOut`, `TicketCostOut`, `BudgetOut`, and `AlertOut` are defined in `app/models.py`, the `OptimizationRecommendationOut` model and `AccountantConfigOut` should be verified for completeness in a pre-merge review.

### 3.3 Security considerations verified

- Alert rate limiting (`_MAX_ALERTS_PER_BUDGET_PER_DAY = 10`, line 47) prevents alert fatigue/DDB bloat
- All endpoints use `require_ui_session`; all DDB keys embed `user_id` — cross-tenant impossible
- Provider API keys referenced by Secrets Manager ARN in config, never stored in DDB
- Financial data accuracy: atomic ADD operations guarantee idempotent-safe duplicate submissions

---

## 4. Proposed Design / Fix

### 4.1 Periodic cost collection background task

Add to `app/main.py` following the existing `asyncio` background task pattern (lines 326–327):

```python
from app.services.agent_accountant import run_cost_collection_if_enabled

async def _run_accountant_collection():
    while True:
        await asyncio.sleep(3600)  # hourly
        if S.accountant_agent_execute_commands:
            try:
                run_cost_collection_if_enabled()
            except Exception:
                logger.exception("accountant cost collection error")

app.add_event_handler("startup", lambda: asyncio.ensure_future(_run_accountant_collection()))
```

`run_cost_collection_if_enabled` would poll Anthropic/OpenAI usage endpoints (for each configured API key in agent_types config), normalize costs to cents using the pricing map in the accountant config, and call `record_cost_entry` + `check_budgets`.

**Dev/Prod parity**: the task starts in both modes; `execute_commands` gates whether external APIs are called. In dev the loop sleeps and does nothing — identical code path.

### 4.2 Auto-pause worker integration

Once AGENT-002/AGENT-003 are implemented and a `pause_worker(worker_id)` service function exists, wire it into `check_budgets`:

```python
if budget.get("auto_pause_on_exceed") and current_spend_cents > limit_cents:
    pause_worker(worker_id=scope_ref)
    auto_action = "Workers paused"
```

Gate behind `S.accountant_agent_enabled` and `auto_pause_on_exceed` flag on each budget record.

### 4.3 Cost trends query optimization

Replace per-date individual queries with a single GSI1 scan across the date range:

```python
# Instead of: for date in date_range: query(GSI1PK=USER#uid#DATE#date)
# Use: query(GSI1PK begins_with USER#uid#DATE#, GSI1SK between start, end)
```

This requires changing `GSI1SK` from the current string (`TYPE#agent_type#WORKER#worker_id`) to a more query-friendly structure, or adding a dedicated trends GSI. For now the N-query approach is acceptable at 90 days.

### 4.4 Dev/Prod parity (SECOPS-007)

| Component | Dev | Prod | Gate |
|-----------|-----|------|------|
| Cost data source | Manual API POST / E2E seed | Background poller (Anthropic, OpenAI, AWS CE) | `ACCOUNTANT_AGENT_EXECUTE_COMMANDS` |
| Budget checks | Synchronous, deterministic | Same code, triggered on each cost write and hourly | None |
| Alert delivery | DDB record only | DDB + email/push | `ACCOUNTANT_AGENT_AUTO_ALERT` |
| Auto-pause | No-op (no worker pause API) | Worker pause via AGENT-002 API | `auto_pause_on_exceed` per budget |

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_agent_accountant.py`)

All runnable offline with moto:

| Test | Assertion |
|------|-----------|
| `test_record_cost_entry_upsert` | Two calls same worker/date → counters ADD, not overwrite |
| `test_record_cost_entry_total_computed` | `total_cost_cents = llm_cost_cents + compute_cost_cents` |
| `test_attribute_cost_to_ticket_idempotent` | Multiple attributions same ticket → accumulated total |
| `test_get_daily_summary_by_agent_type` | Seed two agent types; summary `by_agent_type` has both keys |
| `test_budget_scope_ref_required` | `scope=agent_type` without `scope_ref` → `ValueError` |
| `test_check_budgets_fires_alert` | Record cost exceeding 80% threshold → alert created |
| `test_check_budgets_alert_rate_limit` | 11 calls same budget same day → only 10 alerts created |
| `test_acknowledge_alert` | Alert `acknowledged` field flips to True |
| `test_cross_user_isolation` | User B cannot see User A's budgets or alerts |
| `test_optimization_idle_worker` | Worker with 0 tasks in threshold period appears in recommendations |

### 5.2 Playwright E2E (`frontend/e2e/agent-accountant.spec.ts`)

Sections 691–694 per ticket spec. Key assertions:
- 691: POST cost entry → 201, `total_cost_cents` correct; daily summary aggregates
- 692: Budget CRUD — create, list, update limit, delete
- 693: Alerts list (may be empty); trends array with weekly totals; optimizations array
- 694: All four page `data-testid` attributes visible

### 5.3 Manual/QA steps

1. `just restart` → navigate to `/agents/costs`
2. POST `POST /ui/agents/costs/budgets` via curl: `scope=overall, period=daily, limit_cents=1000, alert_threshold_pct=50`
3. POST `POST /ui/agents/costs/collect` to manually trigger collection (returns summary)
4. Record a cost entry via `POST /ui/agents/costs/summary/daily` and verify it appears in the dashboard
5. Navigate to `/agents/costs/budgets` and verify the budget appears with a progress bar

### 5.4 Rollout

Flags already deployed:
- `ACCOUNTANT_AGENT_ENABLED=1` (on by default)
- `ACCOUNTANT_AGENT_EXECUTE_COMMANDS=0` (off; flip only after LLM API keys configured)
- `ACCOUNTANT_AGENT_AUTO_ALERT=0` (off; flip after alert delivery integrated)

**Phase order**: (1) cost dashboard read-only (all data manually ingested via API) → (2) enable auto-collection (`execute_commands=1`) → (3) enable auto-alerts → (4) enable auto-pause after AGENT-002 ships.

### 5.5 Risks & open questions

- **AGENT-002 dependency**: auto-pause is non-functional until worker provisioning is implemented. The budget flag `auto_pause_on_exceed` should be validated to ensure it silently no-ops (not errors) when no pause function exists.
- **AWS Cost Explorer prod access**: requires an IAM role with `ce:GetCostAndUsage` scoped to the account. This is a prod-only configuration; dev uses only the manually-recorded cost entries.
- **Effort**: background collection task = **S** (1-2 days); auto-pause integration after AGENT-002 = **S** (1 day); full provider API integration = **M** (3-5 days per provider).
