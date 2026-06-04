# AGENT-013: Product Manager Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-013 defines the Product Manager Agent, a schedule-driven autonomous agent that periodically reviews the live application and generates feature ideas for the platform owner to approve or reject. Unlike task-triggered agents (coder, QA), the PM Agent runs on a configurable cadence (daily/weekly), uses Playwright in its terminal session to browse the live app and optionally competitor URLs, and synthesizes feature proposals with rationale and evidence. Approved ideas automatically convert to `type:product_request` tickets for the Project Manager Agent (AGENT-012) to pick up. A per-category preference learning model adapts future suggestions based on approval/rejection history.

**Type**: Feature (new agent type with approval workflow + preference learning). **Priority**: Medium. **Status**: Implemented (service + router + frontend + DDB tables all exist). **Persona**: Platform owner.

**Note on naming collision**: Both AGENT-012 ("Project Manager") and AGENT-013 ("Product Manager") use similar file prefixes. Critically, `app/services/agent_pm.py` implements **AGENT-013** (Product Manager), while `app/services/agent_project.py` implements **AGENT-012** (Project Manager). The router file `app/routers/agent_pm.py` corresponds to AGENT-013 with prefix `/ui/agents/pm`.

Cross-references: **SEC-021** (command injection risk when `PM_AGENT_EXECUTE_COMMANDS` enabled for live-app Playwright browsing). **SECOPS-007** (dev/prod parity for mock vs real Playwright execution and competitor URL fetching).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend Service

`app/services/agent_pm.py` (817 lines). Module docstring at line 1–20 explicitly identifies this as the AGENT-013 Product Manager Agent.

- **Table bootstrap** (`ensure_tables`, line 76): Creates `agent_types` (reused), `agent_feature_ideas`, and `agent_preference_learning` tables in-process. Inline DDL with proper GSI definitions for both `agent_feature_ideas` indexes (GSI1: status-based, GSI2: agent-based). Table names from settings: `app/core/settings.py:2229–2233` (`agent_feature_ideas_table_name`, `agent_preference_learning_table_name`). Table handles in `app/core/tables.py:275–276`, `510–511`.

- **PM config** (`get_pm_config`, `update_pm_config`, line 300–333): Config stored as item `PM_CONFIG` on `agent_types` table with key `TYPE#{pm_{user_id}}`. Merges with `_DEFAULT_PM_CONFIG` (lines 275–285). SSRF protection in `validate_pm_config` (line 237): competitor URLs validated as HTTPS, localhost/127.0.0.1/10.x blocked at lines 263–266. Cap at 10 competitor URLs (line 258).

- **Feature idea CRUD** (`create_feature_idea`, `get_feature_idea`, `list_feature_ideas`, lines 368–480): Ideas stored in `agent_feature_ideas` with `pk=USER#{user_id}`, `sk=IDEA#{idea_id}`. `enforce_max` parameter (line 393) checks pending ideas vs `max_ideas_per_review` config before writing. GSI1 query by status (line 467), fallback to PK scan with `begins_with(sk, 'IDEA#')` for all statuses.

- **Idea lifecycle state machine** (`approve_idea`, `reject_idea`, `archive_idea`, lines 488–599):
  - `approve_idea` (line 488): Validates `status == "pending"`, conditionally calls `tickets_svc.STORE.create_ticket` gated by `S.pm_auto_ticket_creation` (`settings.py:2242`). Ticket created with `category="product_request"`, labels `["type:product_request", "category:{category}", "priority:{priority}"]`. DDB update sets `status=approved`, `GSI1PK` transitions to `USER#{user_id}#STATUS#approved`.
  - `reject_idea` (line 541): Validates non-empty reason, transitions to `rejected`, appends to preference learning.
  - `archive_idea` (line 576): Accepts `pending`, `approved`, or `rejected` statuses (all three can be archived).

- **Preference learning** (`_bump_preference`, `get_preference_summary`, lines 607–677): Atomic DDB ADD for `total_suggested`, `total_approved`, `total_rejected`. Read-modify-write to recompute `approval_rate` after each bump. Common rejection reasons stored as JSON array (last 20, line 641). `get_preference_summary` returns categories sorted by `approval_rate` descending.

- **Review context** (`get_review_context`, line 686): Assembles config, preferences, recent rejections, and optionally support ticket subjects (when `S.pm_support_analysis_enabled` is true, `settings.py:2241`). Returns context dict for agent terminal injection. Competitor analysis flag exposed as `competitor_analysis_enabled` (gate: `settings.py:2240`).

- **Mock review trigger** (`trigger_review`, line 721): Module-level `_RUNNING_REVIEWS: set[str]` tracks in-flight reviews (per `user_id:agent_id`) to prevent double-runs. When a key is in the set, raises `PmValidationError("REVIEW_IN_PROGRESS", ...)`. Creates `count` ideas deterministically (cycling through categories/priorities). Real Playwright browsing gated by `S.pm_agent_execute_commands` (lines 724–726 docstring, `settings.py:2239`).

- **Review session artifacts** (`list_review_sessions`, `get_review_screenshots`, lines 770–817): Groups ideas by `agent_id` to reconstruct review sessions. Screenshot evidence from `evidence` JSON field items with `type=screenshot`.

### 2.2 Backend Router

`app/routers/agent_pm.py` (202 lines). Router prefix: `/ui/agents/pm`. Registered in `app/main.py:775`.

All endpoints use `require_ui_session` — no admin-gating. Ownership enforced implicitly: all queries scoped to `session["user_sub"]`. Error mapping in `_err` function (line 37): `IDEA_NOT_FOUND → 404`, `INVALID_STATUS_TRANSITION → 409`, `REVIEW_IN_PROGRESS → 409`, `REASON_REQUIRED → 422`, etc.

Endpoints implemented (matching ticket §3.3):
- `POST /ui/agents/pm/ideas` → `create_idea` (line 62), 201
- `GET /ui/agents/pm/ideas` → `list_ideas` (line 86), paginated with `?status=`, `?limit=`, `?cursor=`
- `GET /ui/agents/pm/ideas/{idea_id}` → `get_idea` (line 102)
- `POST /ui/agents/pm/ideas/{idea_id}/approve` → `approve_idea` (line 113)
- `POST /ui/agents/pm/ideas/{idea_id}/reject` → `reject_idea` (line 122), body: `RejectIdeaIn`
- `POST /ui/agents/pm/ideas/{idea_id}/archive` → `archive_idea` (line 133)
- `GET /ui/agents/pm/preferences` → `get_preferences` (line 147)
- `GET /ui/agents/pm/reviews` → `list_reviews` (line 158)
- `GET /ui/agents/pm/reviews/{review_id}/screenshots` → `get_review_screenshots` (line 164)
- `GET /ui/agents/pm/config` → `get_config` (line 175)
- `PUT /ui/agents/pm/config` → `put_config` (line 181)
- `POST /ui/agents/pm/trigger-review` → `trigger_review` endpoint (line 191)

### 2.3 Frontend

Routes in `frontend/src/App.tsx`:
- `agents/pm/ideas` → `FeatureIdeasPage` (line 223, 483)

Frontend pages at:
- `frontend/src/pages/agents/FeatureIdeasPage.tsx`
- `frontend/src/pages/agents/IdeaDetailDialog.tsx`
- `frontend/src/pages/agents/PmConfigPanel.tsx`
- `frontend/src/pages/agents/PreferenceDashboard.tsx`

Note: The ticket spec also mentions `PmAgentConfigPage` at `/agents/types/:typeId/pm` (line 484) — this page serves double duty between AGENT-012 and AGENT-013 config.

### 2.4 Dev/Prod Parity

Three flags govern the Product Manager Agent's environment behavior (all in `app/core/settings.py`):

| Flag | Setting key | Default | Purpose |
|------|-------------|---------|---------|
| `PM_AGENT_ENABLED` | `pm_agent_enabled` (line 2236) | `"1"` (on) | Master kill switch |
| `PM_AGENT_EXECUTE_COMMANDS` | `pm_agent_execute_commands` (line 2239) | `"0"` (off) | Real Playwright browsing vs mock |
| `PM_COMPETITOR_ANALYSIS_ENABLED` | `pm_competitor_analysis_enabled` (line 2240) | `"0"` (off) | Enable competitor URL fetching |
| `PM_SUPPORT_ANALYSIS_ENABLED` | `pm_support_analysis_enabled` (line 2241) | `"1"` (on) | Read support tickets for context |
| `PM_AUTO_TICKET_CREATION` | `pm_auto_ticket_creation` (line 2242) | `"1"` (on) | Auto-create ticket on approve |

In dev, `pm_agent_execute_commands=False` means `trigger_review` (line 721) produces ideas deterministically in-memory with no outbound calls. DDB tables use DynamoDB Local via `app/core/aws.py`. Satisfies SECOPS-007's offline/no-AWS requirement for the test suite.

---

## 3. Gap / Threat Analysis

### 3.1 What Is Implemented

All seven core functions from the ticket's §3.3 service spec are present:
- `create_feature_idea`, `list_feature_ideas`, `approve_idea`, `reject_idea`, `archive_idea`, `get_preference_summary`, `get_review_context`, `store_review_artifacts` (via `list_review_sessions`/`get_review_screenshots`).

State machine transitions match the ticket diagram: `pending → approved | rejected → archived`.

### 3.2 Gaps and Risks

1. **Screenshot/trace S3 storage not implemented**: `store_review_artifacts` from the ticket spec (§3.3) is not present. `get_review_screenshots` (line 796) extracts screenshot evidence from the `evidence` JSON field of ideas — this works for mock mode but does not upload Playwright screenshots to S3. The ticket spec §9 describes `s3://bucket/agent-artifacts/{user_id}/pm/` with presigned URLs. Currently, screenshots are only text descriptions in `evidence[].description`.

2. **Cross-tenant idea access via GSI2** (SEC-021 adjacent): `get_review_screenshots` (line 803) queries `GSI2` by `GSI2PK=AGENT#{review_id}` and then filters `item.get("user_id") != user_id` at Python level (line 808). DDB does not enforce this at the index level. A malicious user who knows another user's `agent_id` could query `GSI2` directly via a raw DDB call — though this cannot happen through the API since `review_id` must come from `list_review_sessions` which is already scoped to the caller's `user_sub`.

3. **`trigger_review` in-memory lock is not distributed** (`_RUNNING_REVIEWS`, line 714): The set is module-level, not distributed across uvicorn workers. With `--workers 1` (dev mode), this is fine. In production with multiple workers, two concurrent POST requests could both pass the check and both execute. The CLAUDE.md notes: "moto S3 workers: Run uvicorn with --workers 1 in dev mode." For production, this requires a DDB-backed lock or process-level coordination.

4. **SEC-021 (command injection)**: When `pm_agent_execute_commands=True`, the review cycle dispatches to the Worker Agent Framework. `pm_config.competitor_urls[].url` values (validated to HTTPS, not localhost) are passed to a Playwright session. If the Worker Agent Framework naively interpolates these URLs into a shell command (e.g., `playwright screenshot --url "{url}"`), SSRF/injection is possible. The SSRF validation in `validate_pm_config` (lines 263–266) blocks localhost and RFC-1918 /8 prefix (`://10.`) but does not block DNS rebinding or other SSRF bypasses.

5. **`approval_rate` computed as float stored as Decimal**: `_to_decimal` (line 651) converts the float to a DynamoDB-compatible Decimal. When read back, `float(item.get("approval_rate") or 0.0)` (line 673) converts it back. This is correct but worth noting for any code that compares `approval_rate == 0.5` exactly.

---

## 4. Proposed Design / Fix

### 4.1 S3 Screenshot Storage

Add `store_review_artifacts` in `agent_pm.py`:

```python
def store_review_artifacts(*, user_id: str, agent_id: str, worker_id: str,
                            screenshots: list[dict], trace_url: str | None = None) -> dict:
    """Store Playwright screenshots from a review session in S3 (moto in dev, S3 in prod)."""
    # Use app/core/dev_s3.py pattern: boto3 S3 client via app/core/aws.py
    # key prefix: f"agent-artifacts/{user_id}/pm/{agent_id}/"
    # Return {"screenshots": [{"url": presigned_url, ...}], "trace_url": ...}
```

This follows the existing `app/core/dev_s3.py` in-process moto pattern (SECOPS-007 §3): in dev, moto intercepts boto3 S3 calls; in prod, real S3 is used. The same code path handles both environments.

### 4.2 Distributed Review Lock

Replace `_RUNNING_REVIEWS` set with a DDB conditional write:

```python
# In trigger_review(), before creating ideas:
try:
    T.agent_types.put_item(
        Item={"pk": f"LOCK#pm_review#{user_id}", "sk": agent_id, "ttl": now_ts() + 3600},
        ConditionExpression="attribute_not_exists(pk)",
    )
except T.agent_types.meta.client.exceptions.ConditionalCheckFailedException:
    raise PmValidationError("REVIEW_IN_PROGRESS", "A review session is already running")
```

On completion (in `finally`), delete the lock item. This works correctly with multiple uvicorn workers.

### 4.3 SSRF Enhancement

Extend `validate_pm_config` to block additional SSRF vectors:
- RFC-1918: `169.254.` (link-local), `172.16.`–`172.31.`, `192.168.`
- DNS rebinding mitigation: after URL validation, optionally resolve hostname and check result is not RFC-1918 (prod only; dev skips for offline testing).
- Block `file://`, `ftp://`, and any non-HTTPS scheme.

### 4.4 Dev/Prod Parity (SECOPS-007)

Current architecture already satisfies SECOPS-007 for AGENT-013:
- DDB: DynamoDB Local (:8001) via `app/core/aws.py` in dev, real DDB in prod.
- `trigger_review`: Mock path (in-memory ideas) when `pm_agent_execute_commands=False`; real Playwright dispatch when `True`. Same function signature and DDB writes in both paths.
- Competitor analysis: `pm_competitor_analysis_enabled=False` (default) means no outbound URL fetching in dev/test; `True` in prod enables it.
- Ticket creation: `pm_auto_ticket_creation=True` by default; calls `tickets_svc.STORE.create_ticket` which uses DDB Local in dev, DDB in prod — no environment branching needed.

---

## 5. Testing, Verification & Rollout

### 5.1 E2E Tests

Ticket spec: `frontend/e2e/agent-product-manager.spec.ts` (the ticket mentions `agent-pm.spec.ts` as well — there is a naming conflict with AGENT-012's spec file). Sections 671–676 (16+ tests).

Key scenarios to verify:
- **671.1**: `POST /ui/agents/pm/ideas` as Alice, `category="feature"`, `priority_suggestion="high"`; 201; `status=pending`.
- **672.1**: `POST /ui/agents/pm/ideas/{id}/approve`; `status=approved`, `created_ticket_id` present (non-empty string if `PM_AUTO_TICKET_CREATION=1`).
- **672.2**: `POST /ui/agents/pm/ideas/{id}/reject` with `reason="..."` (non-empty); `status=rejected`, `rejection_reason` matches.
- **673.1**: `GET /ui/agents/pm/preferences`; `preferences` array includes entry for approved category with `total_approved >= 1`.
- **675.4**: `POST /ui/agents/pm/trigger-review` twice in rapid succession; second returns 409.
- **676.1**: Bob tries `GET /ui/agents/pm/ideas/{alice_idea_id}`; 404 (idea not found for Bob's `user_sub`).

### 5.2 Unit Tests

File: `tests/test_product_manager_agent.py`. Key cases:
- `test_create_feature_idea_valid_category`: Creates idea with each of the 6 valid categories; verifies storage.
- `test_create_feature_idea_invalid_category`: Raises `PmValidationError("INVALID_CATEGORY", ...)`.
- `test_approve_idea_creates_ticket`: With `S.pm_auto_ticket_creation=True`, `approve_idea` result has non-empty `created_ticket_id`.
- `test_reject_idea_requires_reason`: `reject_idea(..., reason="")` raises `REASON_REQUIRED`.
- `test_cannot_approve_rejected_idea`: `approve_idea` on rejected idea raises `INVALID_STATUS_TRANSITION`.
- `test_preference_bump_approval_rate`: After 2 approvals and 1 rejection, `get_preference_summary` returns `approval_rate ≈ 0.667`.
- `test_trigger_review_double_run`: Two concurrent `trigger_review` calls; second raises `REVIEW_IN_PROGRESS`.

### 5.3 Additional Unit Test Cases

Beyond the basic cases:
- `test_list_feature_ideas_pagination`: Create 30 ideas; `list_feature_ideas(limit=10)` returns 10 items + `next_cursor`; fetching with cursor returns next 10.
- `test_list_feature_ideas_status_filter`: Create 2 pending + 1 approved idea; `list_feature_ideas(status="pending")` returns exactly 2.
- `test_archive_pending_idea`: `archive_idea` on a pending idea succeeds (all three non-archived statuses allowed); `status="archived"`.
- `test_archive_archived_idea`: `archive_idea` on an already-archived idea raises `INVALID_STATUS_TRANSITION`.
- `test_preference_learning_total_suggested`: `create_feature_idea` increments `total_suggested` for the idea's category via `_bump_preference`.
- `test_max_ideas_per_review_enforced`: Create `max_ideas_per_review` ideas for the same `agent_id`; next create with `enforce_max=True` raises `MAX_IDEAS_EXCEEDED`.
- `test_competitor_url_ssrf_rejection`: `update_pm_config(config={"competitor_urls": [{"url": "http://169.254.169.254/latest"}]})` fails validation.

### 5.4 Observability

The ticket §7.1 defines seven Prometheus metrics: `pm_ideas_created_total`, `pm_ideas_approved_total`, `pm_ideas_rejected_total`, `pm_review_duration_seconds`, `pm_review_ideas_count`, `pm_approval_rate`, `pm_pending_ideas_gauge`. None are currently wired into `app/metrics.py`. Adding them requires hooks in `create_feature_idea`, `approve_idea`, `reject_idea`, and `trigger_review`. Follow the existing pattern in `app/metrics.py` for counter/gauge definitions.

The ticket §7.2 log events (`pm_review_started`, `pm_idea_created`, etc.) should use structured logging at the `logger = logging.getLogger("app.agent_pm")` (line 38) level, consistent with the existing `app.agent_*` logger naming convention.

### 5.5 Rollout

Feature flags defaulting to safe values for incremental rollout:
- `PM_COMPETITOR_ANALYSIS_ENABLED=0` (Week 1 and 2): No external URL browsing.
- `PM_AGENT_EXECUTE_COMMANDS=0` (Week 1): Mock mode only. Validate idea quality.
- `PM_AGENT_EXECUTE_COMMANDS=1` (Week 3+): Enable real Playwright. Monitor for SSRF, compute cost.

DDB tables (`agent_feature_ideas`, `agent_preference_learning`) are defined in `scripts/local-ddb-init.py` and created by `just restart`. They are additive — no migration required.

**Effort**: M (service and router complete; S3 artifact storage and distributed lock are incremental additions).

**Open questions**: The ticket spec mentions `app_auth_credentials_secret` (PM Agent's credentials for browsing the live app) stored in a secrets manager reference — this is not present in `agent_pm.py` and would need to be wired when `pm_agent_execute_commands=True` is used in production.
