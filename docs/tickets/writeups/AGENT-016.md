# AGENT-016: Stylist / UI Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-016 defines the Stylist / UI Agent, a visual design review agent that captures screenshots of the live application across three responsive viewports (mobile, tablet, desktop) using Playwright, then analyzes them for design consistency, spacing, color harmony, typography, accessibility (WCAG contrast ratios, ARIA labels, keyboard navigation), and responsive layout compliance against the project's shadcn/ui + Tailwind design system. It creates `type:ui_review` tickets for discovered issues, tracks per-page design and accessibility scores over time, and manages a configurable set of design rules. The agent activates on UI-related PR merges, manually-triggered reviews, or a configurable periodic schedule.

**Type**: Feature (new agent type + design review / scoring system). **Priority**: Medium. **Status**: Implemented (service + router + frontend + DDB tables all present). **Persona**: Platform owner / frontend developer.

Cross-references: **SEC-021** (command injection — Playwright execution via `stylist_agent_execute_commands` dispatches browser automation; app credentials for browsing the live app must be isolated from the config). **SECOPS-007** (dev/prod parity — real Playwright screenshots gated; mock review path deterministic and offline). **AGENT-015** (WCAG accessibility findings overlap with Stylist's `accessibility_score`; coordination required to avoid duplicate findings).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend Service

`app/services/agent_stylist.py` (839 lines). Module docstring (lines 1–21) identifies this as AGENT-016 and explicitly documents the Tailwind v4 deviation: "NOTE: `frontend/tailwind.config.js` does NOT exist — Tailwind v4 uses the Vite plugin and CSS-based configuration, not a JS config file."

- **Table bootstrap** (`ensure_tables`, line 86): Creates `agent_types` (reused), `stylist_ui_reviews`, and `agent_design_rules` tables. The `stylist_ui_reviews` table has two GSIs: GSI1 on `USER#{user_id}#PAGE#{page_url_hash}` (reviews per page, line 92), GSI2 on `USER#{user_id}#TYPE#{review_type}` (reviews by type). Table names at `settings.py:2180–2181`. Table handles at `app/core/tables.py:271–272`.

- **Viewport validation** (`validate_viewports`, line 215): Enforces `width` in [320, 3840] and `height` in [320, 2160]. Accumulates error strings for all invalid entries.

- **Issue normalization** (`_normalize_issue`, line 237): Ensures issues have required fields with defaults: `issue_id`, `category` (default `"design"`), `severity` (default `"warning"`), `title` (truncated to 200), `description` (truncated to 1000), `suggestion` (truncated to 500). Preserves optional fields: `page_element`, `screenshot_index`, `annotation_rect`, `created_ticket_id`.

- **Review creation** (`create_review`, line 254): Validates `page_url` starts with `/`, normalizes issues, computes `issues_found` count, writes to DDB. GSI1PK uses `_page_hash(page_url)` (line 183) — md5 hex of the URL to avoid DDB key length limits. Optionally calls `_create_issue_ticket_inner` for issues meeting `auto_create_tickets` + `ticket_min_severity` criteria.

- **Review queries** (`get_review`, `list_reviews`, `_iter_all_reviews`, lines 361–435): `list_reviews` routes to GSI1 when `page_url` filter is provided (lookup by page hash), GSI2 when `review_type` filter, or PK scan for all reviews. `_iter_all_reviews` scans the full `USER#{user_id}` partition.

- **Score aggregation** (`get_page_scores`, `get_overall_score`, lines 437–492): `get_page_scores` groups all reviews by `page_url`, returns the most recent review's `design_score` and `accessibility_score` per page, sorted worst-first. `get_overall_score` averages page scores, returns `overall_design_score` and `overall_accessibility_score`.

- **Issue ticket creation** (`_create_issue_ticket_inner`, `create_issue_ticket`, lines 494–568): `_create_issue_ticket_inner` (line 494) searches for the issue by `issue_id` in the review's stored `issues` JSON. Calls `tickets_svc.STORE.create_ticket` with `category="ui_review"`, labels `["type:ui_review", f"severity:{severity}", f"page:{page_url}"]`. Updates the issue's `created_ticket_id` field in DDB via `update_item`. `create_issue_ticket` (line 533) enforces de-duplication: if `issue["created_ticket_id"]` is already set, raises `StylistValidationError("TICKET_ALREADY_EXISTS", "Ticket already created for this issue")` (409).

- **Design rule CRUD** (`create_design_rule`, `list_design_rules`, `get_design_rule`, `update_design_rule`, `delete_design_rule`, lines 582–703): Standard CRUD on `agent_design_rules` table. `list_design_rules` supports `?category=` filter and `enabled_only` parameter. `update_design_rule` uses `ExpressionAttributeNames` for reserved words. `delete_design_rule` returns `False` if rule not found (not-found is not an error at DDB level — checked by verifying item exists first).

- **Stylist config** (`get_stylist_config`, `update_stylist_config`, lines 709–763): Config stored on `agent_types` table as `STYLIST_CONFIG` item (not `STYLIST_CONFIG#...` — flat key `_config_pk(user_id)` at line 705). `update_stylist_config` merges with existing config, validates viewports via `validate_viewports`.

- **Mock review trigger** (`_mock_screenshot`, `trigger_review`, lines 765–839): `_mock_screenshot` (line 765) generates a deterministic screenshot dict with mock S3 URL for a given viewport + page. `trigger_review` (line 777) accepts `pages`, `review_type`, and `viewports` params. Gated by `S.stylist_agent_execute_commands` (`settings.py:2186`): when `False`, creates one `create_review` result per page with synthetic issues and mock screenshots. When `True`, would dispatch to the Worker Agent Framework with real Playwright.

### 2.2 Backend Router

`app/routers/agent_stylist.py` (205 lines). Router exported as `agent_stylist_router`. Registered in `app/main.py:779`.

All endpoints use `require_ui_session`. No admin-gating — all operations scoped to authenticated `user_sub`. Error map includes `REVIEW_NOT_FOUND → 404`, `ISSUE_NOT_FOUND → 404`, `TICKET_ALREADY_EXISTS → 409`, `RULE_NOT_FOUND → 404`, `AGENT_NOT_CONFIGURED → 404`.

Endpoints (matching ticket §3.3):
- `GET /ui/agents/stylist/reviews` → list with `?page_url=`, `?review_type=`
- `GET /ui/agents/stylist/reviews/{review_id}` → full review with issues + screenshots
- `GET /ui/agents/stylist/scores` → per-page design scores
- `GET /ui/agents/stylist/scores/overall` → overall design + accessibility scores
- `POST /ui/agents/stylist/reviews/{review_id}/issues/{issue_id}/ticket` → create ticket for issue
- `GET /ui/agents/stylist/rules` → list rules (with `?category=`, `?enabled_only=`)
- `POST /ui/agents/stylist/rules` → create design rule
- `PUT /ui/agents/stylist/rules/{rule_id}` → update design rule
- `DELETE /ui/agents/stylist/rules/{rule_id}` → delete design rule
- `PUT /ui/agents/stylist/config` → update stylist config
- `POST /ui/agents/stylist/trigger-review` → trigger mock/real review

### 2.3 Frontend

Routes in `frontend/src/App.tsx`:
- `agents/stylist` → `StylistDesignOverviewPage` (lazy, line 227, 488)
- `agents/stylist/rules` → `StylistDesignRulesPage` (line 229, 486)
- `agents/stylist/reviews/:reviewId` → `StylistReviewDetailPage` (line 228, 487)

Frontend pages at:
- `frontend/src/pages/agents/StylistDesignOverviewPage.tsx`
- `frontend/src/pages/agents/StylistReviewDetailPage.tsx`
- `frontend/src/pages/agents/StylistDesignRulesPage.tsx`

Note: The ticket spec used `DesignOverviewPage`, `ReviewDetailPage`, and `DesignRulesPage` as names. The implementation uses `StylistDesignOverviewPage`, `StylistReviewDetailPage`, `StylistDesignRulesPage` — prefixed with `Stylist` for disambiguation. The `data-testid` attributes should be updated in the test specs accordingly.

### 2.4 Dev/Prod Parity

Feature flags in `app/core/settings.py`:

| Flag | Setting key | Default | Purpose |
|------|-------------|---------|---------|
| `STYLIST_AGENT_ENABLED` | `stylist_agent_enabled` (line 2182) | `"1"` (on) | Router registration gate |
| `STYLIST_AGENT_EXECUTE_COMMANDS` | `stylist_agent_execute_commands` (line 2186) | `"0"` (off) | Real Playwright vs mock |
| `STYLIST_PR_TRIGGER_ENABLED` | (no dedicated flag) | controlled by `review_on_pr_merge` config | PR merge trigger |
| `STYLIST_TICKET_CREATION_ENABLED` | (no dedicated flag) | controlled by `auto_create_tickets` config | Auto-file tickets |

The rollout flags from the ticket spec (`STYLIST_PR_TRIGGER_ENABLED`, `STYLIST_TICKET_CREATION_ENABLED`) are not separate `settings.py` entries — they are per-user config fields in the DDB `STYLIST_CONFIG` record. This is a design choice that lets different users have different settings, but means there is no single environment-level kill switch for these sub-features.

In dev (mock mode), `trigger_review` (line 777) creates reviews with `_mock_screenshot` (line 765) using synthetic `s3://mock-bucket/...` URLs. No outbound network, no subprocess. DDB via DynamoDB Local. Satisfies SECOPS-007.

---

## 3. Gap / Threat Analysis

### 3.1 What Is Implemented

All core service functions are present: `create_review`, `get_review`, `list_reviews`, `get_page_scores`, `get_overall_score`, `create_issue_ticket` (with de-dup), `create_design_rule`, `list_design_rules`, CRUD for rules, `get_stylist_config`, `update_stylist_config`, `trigger_review` (mock and gated-real). Router, DDB tables, and frontend pages are all wired up.

### 3.2 Gaps and Risks

1. **`data-testid` name mismatch**: The ticket spec E2E tests (§5.6) reference `[data-testid="design-overview-page"]`, `[data-testid="review-detail-page"]`, `[data-testid="design-rules-page"]`. The frontend file names are `StylistDesignOverviewPage.tsx`, `StylistReviewDetailPage.tsx`, `StylistDesignRulesPage.tsx`. If the `data-testid` values in these components match the file-naming pattern (`stylist-design-overview-page`), the E2E test selectors will fail. The negative test suite section (ticket §18: `data-testid="stylist-dashboard"`) references yet another name. This must be verified and made consistent before running E2E tests.

2. **`_page_hash` uses MD5** (`_page_hash`, line 183): `hashlib.md5(page_url.encode()).hexdigest()` produces a 32-character GSI key component. MD5 is not a security-sensitive hash here (it is only used as a URL-to-key mapping, not for integrity or authentication), but the use of MD5 may trigger security scanners. SHA-256 truncated to 16 chars is equivalent and avoids false positives.

3. **SEC-021 (Playwright app credentials)**: When `stylist_agent_execute_commands=True`, the agent browses the live app. The ticket spec §7 says "app credentials stored in secrets manager, not in DDB." The current `update_stylist_config` (line 721) and its validator do not accept or store `app_auth_credentials_secret`. There is no mechanism to inject credentials into the review trigger path. This must be added before real Playwright browsing is enabled.

4. **`trigger_review` rate limiting not enforced**: The ticket spec §7 says "trigger-review endpoint rate-limited to 5 per hour per user." No rate limiting exists in the current router endpoint. The Stylist service has no equivalent to the PM Agent's `_RUNNING_REVIEWS` in-memory lock — two concurrent `trigger_review` requests can both execute.

5. **Screenshot URL authenticity**: Mock screenshots use `s3://mock-bucket/...` URLs. In production, presigned S3 URLs with 15-minute expiry are needed (ticket spec §7). The current `_mock_screenshot` at line 765 does not use `app/core/dev_s3.py` to upload actual content — it just generates a placeholder string. A real Playwright screenshot capture + S3 upload is deferred to when `stylist_agent_execute_commands=True`.

6. **`get_page_scores` loads all reviews into memory** (`_iter_all_reviews`, line 413): Scans the full `USER#{user_id}` DDB partition, loads all reviews, then Python-groups by `page_url`. For users with 1000+ review records (periodic weekly reviews of 20 pages over months), this is expensive. A DDB summary item (latest score per page stored at creation time) would avoid full scans.

7. **Tailwind v4 config path deviation**: The ticket spec `stylist_config.tailwind_config_path` defaults to `"frontend/tailwind.config.js"` in the DDB default. The ticket's codebase reference note (§11) correctly identifies that `frontend/tailwind.config.js` does not exist — theme tokens are in `frontend/src/globals.css`. The module docstring at line 47–48 acknowledges this. The `_DEFAULT_STYLIST_CONFIG` in `agent_stylist.py` should default `tailwind_config_path` to `"frontend/src/globals.css"`.

---

## 4. Proposed Design / Fix

### 4.1 Rate Limiting for trigger-review

Add an in-memory (or DDB-backed for multi-worker safety) rate limiter. Following the pattern in `agent_pm.py` but with a count:

```python
# In agent_stylist.py
import collections, time
_TRIGGER_COUNTS: dict[str, list[float]] = collections.defaultdict(list)
_TRIGGER_RATE_LIMIT = 5  # per hour

def _check_rate_limit(user_id: str) -> None:
    now = time.time()
    window_start = now - 3600
    _TRIGGER_COUNTS[user_id] = [t for t in _TRIGGER_COUNTS[user_id] if t > window_start]
    if len(_TRIGGER_COUNTS[user_id]) >= _TRIGGER_RATE_LIMIT:
        raise StylistValidationError("RATE_LIMITED", "Manual trigger limited to 5 per hour")
    _TRIGGER_COUNTS[user_id].append(now)
```

For multi-worker production, use a DDB counter with TTL or Redis.

### 4.2 App Credentials Injection

Add `app_auth_credentials_secret: str | None` to the stylist config schema. At `trigger_review` execution (when `stylist_agent_execute_commands=True`), resolve the secret via `app/core/crypto.py` KMS decrypt (mock KMS in dev at `:7999`, real KMS in prod). Pass as environment variable to the Worker Agent Framework terminal. Never return the secret in API responses — expose only `has_app_credentials: bool`.

### 4.3 Page Score Summary Cache

Add a `SCORE_SUMMARY` item per user in `stylist_ui_reviews`:

```python
# Updated by create_review after writing the review record
def _update_score_summary(*, user_id: str, page_url: str,
                           design_score: float, accessibility_score: float) -> None:
    T.stylist_ui_reviews.update_item(
        Key={"pk": _user_pk(user_id), "sk": f"SCORE#{page_url}"},
        UpdateExpression="SET design_score = :ds, accessibility_score = :as, last_reviewed = :ts",
        ExpressionAttributeValues={":ds": _to_dec(design_score), ":as": _to_dec(accessibility_score), ":ts": now_ts()},
    )
```

`get_page_scores` then queries `begins_with(sk, 'SCORE#')` — O(pages count) instead of O(all reviews).

### 4.4 Tailwind v4 Config Path Fix

In `agent_stylist.py` default config:

```python
_DEFAULT_STYLIST_CONFIG = {
    ...
    "tailwind_config_path": "frontend/src/globals.css",  # Tailwind v4: CSS @theme block
    ...
}
```

### 4.5 Dev/Prod Parity (SECOPS-007)

Current architecture satisfies SECOPS-007:
- `stylist_agent_execute_commands=False` → mock path only; `_mock_screenshot` generates placeholder URLs; no outbound Playwright calls.
- `stylist_agent_execute_commands=True` → would dispatch to Worker Agent Framework. Same service function, behavior selected at dispatch point.
- DDB: DynamoDB Local in dev, real DDB in prod via `app/core/aws.py`.
- S3 for screenshots: in dev, mock path returns synthetic URLs; in prod with execution enabled, real S3 uploads via `app/core/dev_s3.py` pattern (moto in dev, S3 in prod).

Tailwind config path flag gap: `tailwind_config_path` defaults to the wrong file. This needs the fix in §4.4 above to ensure the agent reads the correct design system definition in both dev and prod.

---

## 5. Testing, Verification & Rollout

### 5.1 E2E Tests

Ticket spec: `frontend/e2e/agent-stylist.spec.ts`, sections 683–686 (15 tests).

Key scenarios to verify (with correct `data-testid` references):
- **683.1**: `POST /ui/agents/stylist/reviews` with `design_score=82.5`, `issues` array (2 entries); 201; `review_id` and `issues_found=2` returned.
- **683.2**: Review with `review_type="responsive"`, 3 viewports in `screenshots`; 201; `screenshots.length = 3`.
- **684.3**: `POST .../reviews/{id}/issues/{issue_id}/ticket`; 200; `ticket_id` in response; `GET` the review confirms issue's `created_ticket_id` is set.
- **684.4**: Same endpoint again for the same issue; 409 `TICKET_ALREADY_EXISTS`.
- **685.4**: `DELETE /ui/agents/stylist/rules/{rule_id}`; 200; subsequent `GET` list does not include the rule.
- **686.1**: Navigate `/agents/stylist`; verify `StylistDesignOverviewPage` renders (whatever `data-testid` the component uses).

Auth: `trigger_review` should be admin-gated per ticket spec negative test N1. Current router implementation does not enforce admin for `trigger_review` — this needs to be verified and corrected if required.

### 5.2 Unit Tests

File: `tests/test_stylist_agent.py`. Key cases:
- `test_create_review_valid`: Creates review, verifies DDB item has `design_score`, `issues_found`, `GSI1PK` set.
- `test_create_review_invalid_page_url`: URL not starting with `/` raises `StylistValidationError("INVALID_PAGE_URL", ...)`.
- `test_create_issue_ticket_dedup`: Create ticket for issue; second call raises `TICKET_ALREADY_EXISTS`.
- `test_design_rule_crud`: Create → list → update severity → delete; list empty after delete.
- `test_get_page_scores_worst_first`: Create 2 reviews with different scores; `get_page_scores` returns lower score first.
- `test_trigger_review_mock`: `trigger_review(pages=["/messages"], ...)` with `stylist_agent_execute_commands=False` creates a review with mock screenshot URL; no outbound calls.
- `test_validate_viewports_out_of_range`: Width=5000 returns error list; width=1280 returns empty list.

### 5.3 Rollout

Incremental rollout (ticket §17):
- **Week 1**: `STYLIST_AGENT_ENABLED=1`, `stylist_agent_execute_commands=0`. Manual trigger only (mock). Review scoring accuracy.
- **Week 2**: Set `review_on_pr_merge=true` in per-user config. PR-triggered reviews (still mock).
- **Week 3**: `stylist_agent_execute_commands=1`. Real Playwright screenshots. Monitor compute cost and app credential security.

Tables (`stylist_ui_reviews`, `agent_design_rules`) defined in `scripts/local-ddb-init.py:1999–2016`. Additive.

**Effort**: M (core implementation complete; rate limiting, credentials injection, score cache, and Tailwind config path fix are targeted additions).

**Risks**:
- `data-testid` name mismatches between ticket spec and implementation will cause E2E failures until aligned.
- `_page_hash` uses MD5 — flagged by static analysis tools; easy to replace with SHA-256 prefix.
- No concurrent trigger prevention — two simultaneous reviews for the same user/page can both execute.
- App credentials injection not yet implemented — blocks production use of real Playwright mode.
- Tailwind v4 config path default is wrong — agent would look for a non-existent `tailwind.config.js`.
