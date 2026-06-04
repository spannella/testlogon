# AGENT-012: Project Manager Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-012 defines the Project Manager Agent, a high-level orchestration agent type that sits at the top of the agent pipeline. It converts raw user-submitted product ideas into prioritized feature request tickets, manages sprint planning and velocity tracking, detects blockers in the development backlog, and generates daily/weekly progress reports. Unlike the task-driven coder or QA agents, the PM Agent drives the entire downstream agent pipeline: ideas → architect decomposition → coder implementation → QA verification → DevOps deployment.

**Type**: Feature (new agent type + orchestration layer). **Priority**: High. **Status**: Implemented (service + router + frontend exist; DDB tables created; router registered in `app/main.py`). **Persona**: Platform admin / product owner.

**Dependencies**: Requires AGENT-001 through AGENT-011 (agent framework, worker provisioning, monitoring, all downstream agent types). LLM key usage for idea triage is cross-referenced with **SEC-022** (credential exposure) and **SEC-021** (command injection when `PM_AGENT_EXECUTE_COMMANDS` is enabled). Dev/prod parity governed by **SECOPS-007**.

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend Service

`app/services/agent_project.py` (1734 lines) is fully implemented. Key sections:

- **Table bootstrap** (`ensure_tables`, line 107): Creates `product_ideas`, `project_sprints`, and `project_reports` tables in-process on first call. Tables are also defined in `scripts/local-ddb-init.py` (lines 2039–2062). Table name settings live at `app/core/settings.py:2244–2246` (`product_ideas_table_name`, `project_sprints_table_name`, `project_reports_table_name`). Table handles wired in `app/core/tables.py:277–279` and `app/core/tables.py:512–514`.

- **PM config** (`get_pm_config`, `update_pm_config`, `validate_pm_config`, lines 230–350): Config stored as `PM_CONFIG` item on the reused `agent_types` table, keyed by `TYPE#{agent_type_id}`. Validation enforces P0-P3 priority framework, weights summing to 1.0, sprint duration > 0, `capacity_per_agent_type` must include `coder` key, and `blocker_stale_hours` in range 1–720.

- **Idea intake** (`submit_idea`, `get_idea`, `list_ideas`, `update_idea_status`, lines 390–522): Ideas stored in `product_ideas` table with `pk=IDEA#{idea_id}`. GSI1 on `STATUS#{status}` and GSI2 on `USER#{user_sub}` for filtered queries. Pagination via `app/core/cursor.py`. Status machine: `submitted → triaging → accepted | rejected → converted`.

- **Idea triage** (`triage_idea`, `_deterministic_scores`, lines 524–642): Deterministic scorer (lines 524–569) computes `user_impact`, `revenue_impact`, `technical_debt`, `effort_inverse` from idea title/description length heuristics — no LLM call. Real LLM-based triage is gated by `S.pm_execute_commands` (`app/core/settings.py:2249`). `build_feature_request_from_idea` (line 613) constructs a ticket payload. `convert_idea_to_feature_request` (line 643) calls `tickets_svc.STORE.create_ticket` with labels `type:feature_request` + `priority:{P0-P3}`.

- **Backlog prioritization** (`get_backlog`, `prioritize_backlog`, `apply_priorities`, `backlog_view`, lines 685–837): `_scan_backlog_tickets` (line 685) queries the ticket system across statuses. Formula: `weighted_score = user_impact*0.4 + revenue_impact*0.3 + tech_debt*0.15 + (100-effort)*0.15`. P0 ≥ 80, P1 ≥ 60, P2 ≥ 40, P3 < 40. `apply_priorities` (line 767) writes labels back to tickets.

- **Blocker detection** (`detect_blockers`, `escalate_blockers`, lines 865–956): Scans tickets for `blocked` status, stale `in_progress` (no update in `stale_hours`), and agent-error states. `escalate_blockers` calls `T.agent_types.update_item` to add a feedback note.

- **Sprint management** (`create_sprint`, `activate_sprint`, `close_sprint`, `get_sprint_burndown`, lines 1013–1180): Sprints stored in `project_sprints` table with `pk=PROJECT#{space_id}`, `sk=SPRINT#{sprint_id}`. `close_sprint` computes velocity from completed ticket hours. `get_sprint_burndown` returns daily snapshots.

- **Velocity tracking** (`calculate_velocity`, `get_velocity_trend`, lines 1140–1210): `get_velocity_trend` compares last N sprints and classifies trend as `increasing`, `stable`, or `decreasing`.

- **Capacity planning** (`get_agent_utilization`, `check_capacity_fit`, lines 1182–1255): Computes hours used vs available per agent type. `check_capacity_fit` flags overflow.

- **Reporting** (`generate_daily_report`, `generate_weekly_report`, `save_report`, `list_reports`, `get_report`, lines 1269–1410): Reports stored in `project_reports` with `pk=PROJECT#{space_id}`, `sk=REPORT#{created_at}#{report_id}`. Content is Markdown. `send_report_notifications` at line 1406 fires notifications to `stakeholder_subs` via the notification system.

- **Operation workflows** (`run_idea_triage`, `run_backlog_prioritize`, `run_report_generate`, `run_blocker_detect`, lines 1512–1658): Orchestrated multi-step sequences that combine the above functions.

- **Dashboard/metrics** (`get_pm_metrics`, `get_project_dashboard`, lines 1659–1734): Aggregates ideas, velocity, blockers, pipeline funnel, utilization.

### 2.2 Backend Router

`app/routers/agent_project.py` (450 lines). Router prefix: `/ui/agents`. Registered in `app/main.py:777` inside the agent-enabled block.

Admin endpoints use `require_admin_or_root` from `app/auth/policy.py`. Idea submission/listing uses `require_ui_session` with ownership enforcement (users see only their own ideas, admins see all — `_is_admin` check at line 71).

Key endpoint-to-auth mapping:
- `PUT /ui/agents/types/{type_id}/pm-config` → `require_admin_or_root` (line 91)
- `POST /ui/agents/ideas` → `require_ui_session` (line 116), any authenticated user
- `GET /ui/agents/ideas` → `require_ui_session` + ownership filter (line 124)
- `PATCH /ui/agents/ideas/{idea_id}` → `require_admin_or_root` (line 155), accept/reject
- `POST /ui/agents/backlog/reprioritize` → `require_admin_or_root` (line 201)
- `GET /ui/agents/pm/dashboard` → `require_admin_or_root` (line 434)

### 2.3 Frontend

Routes in `frontend/src/App.tsx`:
- `agents/types/:typeId/pm` → `PmAgentConfigPage` (lazy, line 224, 484)
- `agents/project-dashboard` → `ProjectDashboardPage` (line 225, 485)
- `ideas/submit` → `IdeaSubmissionPage` (line 226, 501)

Frontend pages at:
- `frontend/src/pages/agents/PmAgentConfigPage.tsx`
- `frontend/src/pages/agents/ProjectDashboardPage.tsx`
- `frontend/src/pages/agents/IdeaSubmissionPage.tsx`
- `frontend/src/pages/agents/PmRunOutputPanel.tsx`

### 2.4 Dev/Prod Parity

`S.pm_execute_commands` (`app/core/settings.py:2249`, alias for `PM_AGENT_EXECUTE_COMMANDS`, default `"0"`) gates real LLM-based idea triage. When `False` (dev/E2E), `triage_idea` (line 571) uses `_deterministic_scores` — a fully offline formula. When `True` (prod), it would dispatch to the Worker Agent Framework with a coding tool (Claude Code / Codex). In both cases the same function signature and DDB write path is used, satisfying SECOPS-007's same-code-path requirement.

`S.pm_agent_enabled` (`settings.py:2236`, default `"1"`) is the master kill switch gating the router registration block in `main.py`.

---

## 3. Gap / Threat Analysis

### 3.1 What Is Implemented

All core functions specified in the ticket are present:
- Idea intake, triage, feature request conversion, backlog prioritization, blocker detection, sprint CRUD, velocity tracking, daily/weekly report generation, capacity planning, dashboard aggregation.
- All 21 endpoints from the ticket's §3.3 table are implemented in the router.
- DDB tables (`product_ideas`, `project_sprints`, `project_reports`) are defined in `scripts/local-ddb-init.py` and in `app/core/tables.py`.
- Frontend pages: `PmAgentConfigPage`, `ProjectDashboardPage`, `IdeaSubmissionPage`.
- Pydantic models for all request/response types are in `app/models.py` (`PmConfigIn`, `PmConfigOut`, `SubmitIdeaIn`, `IdeaOut`, `IdeaListOut`, `BacklogOut`, `SprintOut`, `ReportOut`, `PmMetricsOut`, `ProjectDashboardOut`, etc.).

### 3.2 Gaps and Risks

1. **Notification delivery for reports** (`send_report_notifications`, line 1406): The function calls the notification system but assumes it resolves `stakeholder_subs` to valid user notification channels. No validation of `stakeholder_subs` against existing users at config-save time (the ticket spec §7 says to validate at config save — currently not enforced by `validate_pm_config`).

2. **Sprint overlap prevention**: `create_sprint` (line 1013) does not check for date overlap with existing sprints before writing. The ticket §6 specifies a 409 for overlapping sprints. A query against `list_sprints` could catch this, but the current implementation does not perform this check.

3. **SEC-021 (command injection)**: When `S.pm_execute_commands` is `True`, `triage_idea` at line 571 would pass `coding_tool` and `coding_tool_model` from config into the Worker Agent Framework. The `pm_config.coding_tool_model` field has no sanitization beyond Pydantic `max_length=100`. If the framework ever interpolates this into a shell string, SEC-021 applies.

4. **SEC-022 (credential exposure)**: The `pm_config` stored in DDB includes `coding_tool_model` but no LLM keys directly (keys are in AGENT-001's `llm_provider_keys` table, encrypted at rest). GET `/ui/agents/types/{type_id}/pm-config` returns the full config. The config itself has no secret fields, so direct SEC-022 risk is low for AGENT-012.

5. **Backlog scan scalability**: `_scan_backlog_tickets` (line 685) uses `ScanIndexForward=False` on the tickets table. For ticket spaces with >10,000 items, the DDB filter-after-read pattern (documented in CLAUDE.md gotchas) means multiple pages must be fetched. The current implementation uses `Limit=500` but does not loop via `LastEvaluatedKey` for filtered queries — sparse statuses may silently miss tickets on a busy table.

---

## 4. Proposed Design / Fix

### 4.1 Stakeholder Validation at Config Save

In `validate_pm_config` (`agent_project.py:230`), add a check: for each sub in `stakeholder_subs`, perform a lightweight DDB lookup against the sessions/account table to confirm the user exists. Reject with `422 "Unknown stakeholder: {sub}"` for any invalid entry.

```python
# Proposed addition to validate_pm_config (agent_project.py:275 area)
stakeholders = config.get("stakeholder_subs") or []
for sub in stakeholders:
    if not _user_exists(sub):  # thin DDB/sessions lookup
        errors.append(f"Unknown stakeholder: {sub}")
```

### 4.2 Sprint Overlap Check

In `create_sprint` (line 1013), before `T.project_sprints.put_item`, call `list_sprints(space_id=space_id)` and verify no existing sprint's `[start_date, end_date]` range overlaps with the requested range. Return 409 on overlap.

### 4.3 Backlog Pagination Loop

Refactor `_scan_backlog_tickets` to loop via `LastEvaluatedKey` when a `FilterExpression` is in use, collecting up to `limit` matching results. Match the pattern used by `list_conversations` in messaging, which already handles this DDB gotcha.

### 4.4 Dev/Prod Parity (SECOPS-007)

Current state already satisfies SECOPS-007:
- DDB: DynamoDB Local (:8001) in dev, real DDB in prod — both via `app/core/aws.py` boto3 client.
- LLM execution: Gated by `S.pm_execute_commands` (default off). In dev, `_deterministic_scores` runs offline with no AWS/LLM calls.
- Notifications: Use the existing notification system which itself has a dev mock path.
- No `subprocess` or shell execution in the current `agent_project.py` service — execution paths are all deferred to the Worker Agent Framework (AGENT-003).

---

## 5. Testing, Verification & Rollout

### 5.1 E2E Tests

Ticket spec: `frontend/e2e/agent-pm.spec.ts`, sections 667–670 (18 tests). Test setup uses `injectAuth` for root/alice, CSRF headers for session-auth POST requests, and global `request` fixture for Bearer-auth API calls.

Key scenarios:
- **667.1**: Create PM agent type + PUT pm-config; verify `priority_framework` has P0-P3, `sprint_duration_days=14`.
- **667.3**: Alice (USER) POSTs to `/ui/agents/ideas`; verify 201 + `status=submitted`.
- **668.1**: GET `/ui/agents/backlog`; verify `priority_score` descending order.
- **669.1**: POST sprint with `start_date`/`end_date`; verify `status=planned`, `sprint_id` present.
- **670.3**: Navigate `/agents/project-dashboard`; `[data-testid="project-dashboard-page"]` visible.

### 5.2 Unit Tests

File: `tests/test_pm_agent.py`. Uses moto for DDB tables. Key cases:
- `test_create_pm_agent`: Creates idea, verifies `pk=IDEA#...`, `status=submitted`.
- `test_triage_idea_deterministic`: With `pm_execute_commands=False`, verifies `_deterministic_scores` returns a dict with expected keys without any boto3/LLM call.
- `test_convert_idea_creates_ticket`: `convert_idea_to_feature_request` calls `tickets_svc.STORE.create_ticket` with `labels=["type:feature_request", "priority:P1"]`.
- `test_sprint_close_calculates_velocity`: Seed sprint + completed tickets; `close_sprint` returns `velocity > 0`.
- `test_daily_report_markdown`: `generate_daily_report` returns string starting with `#`.
- `test_get_pm_config_defaults`: Before any config write, `get_pm_config` returns a dict with `sprint_duration_days=14`, `reporting_cadence="both"`, `capacity_per_agent_type` contains `"coder"`.
- `test_validate_pm_config_weights_sum`: Config with `priority_weights={"user_impact": 0.5, "revenue_impact": 0.5, "technical_debt": 0.1, "effort_inverse": 0.1}` (sum 1.2) should fail validation.
- `test_build_feature_request_labels`: `build_feature_request_from_idea(idea={...}, triage_result={...}, priority="P0")` returns ticket data with `labels` including both `"type:feature_request"` and `"priority:P0"`.
- `test_list_ideas_pagination_by_status`: Submit 5 ideas; `list_ideas(status="submitted", limit=3)` returns 3 + cursor; next page returns 2.

### 5.3 Observability

No Prometheus metrics added specifically for AGENT-012. Recommended additions: `pm_ideas_submitted_total`, `pm_ideas_converted_total`, `pm_sprint_velocity_gauge` — following the pattern in `app/metrics.py`.

Logging: `agent_project.py` uses `logger = logging.getLogger("app.agent_project")` (line 48). Key log events to add: `pm_idea_submitted` (INFO, with `idea_id`, `user_sub`), `pm_sprint_created` (INFO, with `sprint_id`, `space_id`), `pm_blocker_escalated` (WARNING, with `ticket_id`, `blocker_type`), `pm_report_generated` (INFO, with `report_id`, `report_type`).

### 5.4 Additional Unit Tests

Beyond the basic cases, additional tests are needed for:
- `test_prioritize_backlog_p0_cap`: Verify that P0 assignment is capped at `capacity.coder * 0.3` — no more than 30% of sprint capacity on critical items.
- `test_velocity_trend_increasing`: Three sprints with velocities [20, 30, 40] → `trend="increasing"`.
- `test_velocity_trend_decreasing`: Three sprints with [40, 30, 20] → `trend="decreasing"`.
- `test_detect_blockers_stale_ticket`: Ticket in `in_progress` with `updated_at` more than `stale_hours` ago → appears in blockers list with `blocker_type="stale"`.
- `test_detect_blockers_agent_error`: Ticket assigned to an agent in `error` state → `blocker_type="agent_error"`.
- `test_capacity_fit_overflow`: P0+P1 ticket hours exceed capacity → `fits=False`, `overflow_hours > 0`.
- `test_project_dashboard_structure`: `get_project_dashboard` returns dict with keys `sprint`, `velocity_trend`, `backlog_by_priority`, `pipeline_funnel`, `agent_utilization`, `blockers`, `recent_completions`.

### 5.5 Rollout

Feature flags:
- `PM_AGENT_ENABLED=1` (default on in dev) — controls router registration in `main.py:760`–800 agent block.
- `PM_AGENT_EXECUTE_COMMANDS=0` (default off) — controls real LLM-based idea triage vs deterministic `_deterministic_scores`. Alias `pm_execute_commands` at `settings.py:2249`.

Deployment order: requires AGENT-001 through AGENT-011 to be merged first (agent framework, all downstream agents). Tables are additive — `just restart` after merging will create `product_ideas`, `project_sprints`, `project_reports` via `scripts/local-ddb-init.py`. The `agent_types` table (reused) is created by AGENT-001.

Security checklist before enabling `PM_AGENT_EXECUTE_COMMANDS=1` in production:
1. Validate `coding_tool_model` field against an allowlist of known model strings (SEC-021 adjacent).
2. Ensure `stakeholder_subs` validation is in place (§4.1 fix above).
3. Review LLM provider key retrieval path for compliance with SEC-022 (no key material in API responses).

**Effort**: L (most code already implemented; gaps are small targeted fixes — sprint overlap check, backlog pagination loop, stakeholder validation). The densest implementation work is `agent_project.py` which at 1734 lines covers the full PM Agent lifecycle including five distinct operation types (`idea_triage`, `backlog_prioritize`, `report_generate`, `blocker_detect`, `sprint_plan`) each with multiple sub-steps.

**Risks**: 
- Backlog scan pagination gap: `_scan_backlog_tickets` may silently miss tickets on a busy table (CLAUDE.md DDB FilterExpression gotcha). Fix: add `LastEvaluatedKey` loop.
- Sprint overlap not validated: Two overlapping sprints can be created simultaneously, corrupting velocity metrics. Fix: pre-creation overlap check.
- Stakeholder sub validation missing: Config save accepts non-existent user subs; report delivery fails silently.
- All three gaps are low severity in dev with small data volumes but must be addressed before production scale.
