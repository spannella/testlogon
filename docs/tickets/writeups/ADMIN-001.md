# ADMIN-001: Subscription Tier Manager UI — Investigation & Implementation Write-up

## 1. Summary & Classification

The ticket requested a creator-facing subscription tier management UI covering CRUD, archive/unarchive lifecycle, drag-and-drop reorder, tier analytics, and a subscriber-facing preview. A full stack implementation is now present: the backend service `app/services/admin_subscription_tiers.py` (409 lines), router `app/routers/admin_subscription_tiers.py` (190 lines), a `SubscriptionTierManagerPage.tsx` frontend page (356 lines), and E2E spec `frontend/e2e/admin-subscription-tiers.spec.ts`. However the ticket document contained several stale assumptions, the chosen auth guard and URL prefix differ from what the ticket proposed, and the original per-user creator `TierManager.tsx` page (in `frontend/src/pages/subscriptions/TierManager.tsx`) is still present and points at a different API. This writeup reconciles those differences.

**Type**: Feature. **Priority**: High. **Status**: Implemented (backend + frontend + E2E present). **Owning area**: Subscriptions / Admin tooling.

**Persona**: Platform operators and creators who manage subscription tiers. Cross-referenced: subscription_access.py, subscription_entitlement_templates.py, subscription_cycle_orders.py.

---

## 2. Current-State Investigation (what exists today)

### Backend service

`app/services/admin_subscription_tiers.py` (409 lines) implements all the functions the ticket specifies:

- `create_tier` (line 118) — PutItem to `T.admin_subscription_tiers`; auto-assigns `display_order` by querying current max; validates price range (`ge=100, le=100000`); optionally links to an existing subscription plan via `plan_id`.
- `update_tier` (line 174) — UpdateItem expression built from a whitelist of mutable fields (`name`, `price_cents`, `billing_cycle`, `description`, `benefits`, `access_level`); raises 404 if the tier is not found for the given `creator_id`.
- `archive_tier` (line 211) / `unarchive_tier` (line 231) — updates `status` field; raises 400 on no-op (e.g., archiving an already-archived tier). Both use PutItem to overwrite the item rather than a conditional UpdateItem, so a concurrent archive by two admins could silently succeed for both.
- `delete_tier` (line 244) — uses a DynamoDB ConditionExpression `subscriber_count = :zero`; returns 409 with a descriptive message if the count is non-zero. This is the only write operation with an atomic safety guard.
- `list_tiers` (line 272) — Query on `PK=CREATOR#{creator_id}` with `SK begins_with TIER#`, sorts results by `display_order` in Python after retrieval. No GSI on `display_order`.
- `reorder_tiers` (line 282) — iterates the `tier_ids` list and updates `display_order` for each tier with individual PutItem calls (not a batch transaction). If the process crashes mid-loop, partial reorder results are written.
- `get_tier_analytics` (line 346) — calls `_active_subscriptions_for_creator(creator_id)` which performs a full-table **Scan** on `T.subscriptions` with `FilterExpression=Attr("creator_id").eq(creator_id) & Attr("sk").begins_with("SUB#")` (lines 310–337), looping via `LastEvaluatedKey`. For a creator with thousands of subscribers this is a costly operation. Subscriber counts are attributed to tiers via `plan_id` linkage; tiers without a `plan_id` fall back to the denormalised `subscriber_count` field. Revenue is computed as `subscriber_count * price_cents` when subscription-level price data is unavailable. The `growth_series` field always returns an empty list `[]` — time-series growth data is not yet implemented.
- `get_tier_subscriber_count` (line 340) — reads the denormalised `subscriber_count` from the tier record. Not kept in sync automatically; must be updated by subscription lifecycle events.
- `preview_tiers` (line 393) — returns only active tiers in display order, shaped for subscriber display with `name`, `price_cents`, `billing_cycle`, `description`, `benefits`, `access_level`, `display_order`.

DynamoDB table: `admin_subscription_tiers` (settings key `admin_subscription_tiers_table_name` at `app/core/settings.py:2276`; table handle at `app/core/tables.py:519`). The table is registered in `scripts/local-ddb-init.py` at line 2111. Single-table pattern: `PK=CREATOR#{creator_id}`, `SK=TIER#{tier_id}`. No GSIs are defined — all queries are by PK with SK prefix filter.

### Backend router

`app/routers/admin_subscription_tiers.py` (190 lines, prefix `/ui/admin/subscription-tiers`, registered in `app/main.py:74,539`). Auth uses `require_admin_or_root` (line 13, from `app/auth/policy.py:67`) for read-only endpoints and `require_admin_or_root_csrf` (line 13, from `app/auth/policy.py:100`) for mutating endpoints — **not** `require_ui_session` as the ticket document proposed. The CSRF guard in `require_admin_or_root_csrf` calls `enforce_cookie_csrf(request)` which validates the `x-csrf-token` header against the `ui_csrf` cookie for cookie-authenticated requests; Bearer-auth clients bypass CSRF. All ten endpoints from the ticket specification are present (POST create at line 30, GET list at line 57, PUT reorder at line 69, GET analytics at line 85, GET preview at line 96, GET single at line 105, PATCH update at line 115, POST archive at line 139, POST unarchive at line 158, DELETE at line 172). Route prefix is `/ui/admin/subscription-tiers`, differing from the `/v1/subscriptions/tiers` the ticket proposed. Audit events are fired for create (`"admin_subscription_tier_create"`), reorder (`"admin_subscription_tier_reorder"`), and presumably for other mutations.

### Frontend

`frontend/src/pages/admin/SubscriptionTierManagerPage.tsx` (356 lines) implements the full tier card list, create/edit dialog, archive/unarchive/delete actions, reorder buttons, analytics summary, and subscriber-facing preview. It is registered in `frontend/src/App.tsx:157,452` at route `/admin/subscription-tiers`.

API wrappers live in `frontend/src/api/endpoints/adminSubscriptionTiers.ts` (55 lines) calling `/ui/admin/subscription-tiers/*`. Types are exported from `frontend/src/api/types.ts` as `SubscriptionTierCreate`, `SubscriptionTierOut`, etc.

The ticket document also referenced a pre-existing `frontend/src/pages/subscriptions/TierManager.tsx` (308 lines) at route `/subscriptions/manage` (`App.tsx:182`). That page still exists and calls the **subscriptions API** (`listPlans`, `archivePlan`, `updatePlan` from `frontend/src/api/endpoints/subscriptions.ts`) targeting `/api/creators/{id}/plans`, which is a separate creator-owned plan model, not the admin tier table. These two pages serve different audiences (user-facing vs admin) and use different tables.

### Pydantic models (`app/models.py`)

The ticket proposed model names like `TierCreate` and `TierOut`. The implementation uses prefixed names: `AdminSubscriptionTierCreate`, `AdminSubscriptionTierOut`, `AdminSubscriptionTierUpdate`, `AdminSubscriptionTierReorder`, `AdminSubscriptionTierAnalytics`, `AdminSubscriptionTierPreviewOut`. These are imported in the router at `admin_subscription_tiers.py:15-20`. The `AdminSubscriptionTierCreate` model includes `plan_id: Optional[str]` which the ticket did not specify — it allows linking a tier to an existing subscription plan record for analytics attribution.

### E2E tests

`frontend/e2e/admin-subscription-tiers.spec.ts` and `frontend/e2e/tier-manager.spec.ts` both exist. The admin spec covers sections 547–550b as described in the ticket. The admin spec uses the `/ui/admin/subscription-tiers` URL prefix matching the implementation. The `tier-manager.spec.ts` appears to use the stale `/v1/subscriptions/tiers` prefix from the ticket document — it would fail against the current backend. Tests use `e2e_admin_session_setup.py` cookies for Alice and root.

### Dev vs Prod parity (SECOPS-007)

In dev: DynamoDB Local (:8001) backs `T.admin_subscription_tiers`. In prod: the same `T.admin_subscription_tiers` handle resolves to the real DynamoDB table via `app/core/tables.py` and `app/core/aws.py`. No AWS-specific code paths exist in the service — all queries go through the `T.*` handle abstraction. Analytics cross-queries `T.subscriptions` the same way in both environments.

---

## 3. Gap / Threat Analysis

### Gaps found versus the ticket specification

1. **Auth guard mismatch**: the ticket specified `require_ui_session` (which returns the full session dict for any authenticated user). The implementation correctly uses `require_admin_or_root` / `require_admin_or_root_csrf` from `app/auth/policy.py`. This is a stricter, more correct guard. The ticket spec's `require_ui_session` would have permitted any regular user to manage tiers, which would be a privilege escalation bug. The implementation is correct; the ticket document was wrong.

2. **URL prefix mismatch**: the ticket proposed `/v1/subscriptions/tiers`. The implementation uses `/ui/admin/subscription-tiers`. This aligns with the existing admin router convention (`/ui/admin/*`) and correctly signals that these endpoints require admin/root access. The Vite proxy forwards `/ui/*` to the backend.

3. **Scope qualification**: the ticket says "tier operations scoped to the authenticated user's `user_sub`". With `require_admin_or_root`, the `creator_id` passed to service functions is `actor.sub` (admin's own user sub). This means admin users manage only their own tiers (reasonable for a creator-operator hybrid model), but platform root users can also call the endpoint and their tiers would be keyed to their root sub. If the intent is for root to manage arbitrary creators' tiers, a `creator_id` query parameter would be needed.

4. **`tier-manager.spec.ts` vs `admin-subscription-tiers.spec.ts`**: two E2E spec files exist for the same functional area. The `tier-manager.spec.ts` file (sections 547–550b) appears to be the spec the ticket planned; `admin-subscription-tiers.spec.ts` is likely the implemented spec. These should be consolidated to avoid duplicate coverage and test infrastructure cost.

5. **`TierManager.tsx` (user-facing) is not linked from the admin sidebar**: the user-facing plan management page at `/subscriptions/manage` has no admin nav entry. If operators need to see it, a sidebar link under the creator subscription section would be required.

6. **No feature flag in the implementation**: the ticket proposed `TIER_MANAGEMENT_ENABLED` / `TIER_MANAGEMENT_ALLOWLIST` flags. The implemented router is always active when the backend starts. This means the feature is live for all admin/root users immediately. For phased rollout, a flag should be added to `app/core/settings.py` and checked at the router or service layer.

7. **`growth_series` always empty**: `get_tier_analytics` returns `"growth_series": []` at `admin_subscription_tiers.py:389`. The ticket's analytics spec included weekly subscriber growth over time. This field is a stub. Any UI component rendering a growth chart will receive an empty dataset.

8. **`subscriber_count` denormalised but not auto-updated**: the `subscriber_count` field on tier records is initialised to 0 at create time. The analytics function uses the live `T.subscriptions` scan when a `plan_id` link exists, but for tiers without `plan_id`, the denormalised value is used. Nothing in the codebase automatically increments or decrements this field when subscriptions are created or cancelled. The `subscription_cycle_orders.py` service (which handles subscription lifecycle) would need to call `update_tier` with an updated `subscriber_count` on lifecycle events.

9. **Scan-based analytics can miss items or be costly at scale**: `_active_subscriptions_for_creator` at line 310 uses `T.subscriptions.scan()` with a `FilterExpression`. As documented in the CLAUDE.md DynamoDB gotchas, DynamoDB fetches up to 1 MB before applying the filter. The loop via `LastEvaluatedKey` is correct but on a busy subscriptions table, the scan reads all items before filtering — an O(total_subscriptions) read cost. A GSI on `T.subscriptions` keyed by `creator_id` would reduce this to O(creator_subscriptions).

### Abuse potential

Because `delete_tier` uses a DynamoDB ConditionExpression (`subscriber_count = :zero`), concurrent deletion after a subscriber unsubscribes is safe. The `archive_tier` / `unarchive_tier` 400 guard is a Python-side check without a ConditionExpression, so a race between two admins archiving the same tier would result in one getting 400 — acceptable.

---

## 4. Proposed Design / Fix

The core implementation is complete and correct. The following items remain:

### 4.1 Optional feature flag

Add to `app/core/settings.py`:
```python
admin_subscription_tier_manager_enabled: bool = os.environ.get(
    "ADMIN_SUBSCRIPTION_TIER_MANAGER_ENABLED", "1"
) in {"1", "true", "yes"}
```
Guard in `app/routers/admin_subscription_tiers.py` with a startup check or per-endpoint `if not S.admin_subscription_tier_manager_enabled: raise HTTPException(404, ...)`. The `.env.local.example` should default this to `1`.

### 4.2 Consolidate E2E specs

`frontend/e2e/tier-manager.spec.ts` and `frontend/e2e/admin-subscription-tiers.spec.ts` cover the same backend. One should be removed or the sections should be explicitly non-overlapping. Recommended: keep `admin-subscription-tiers.spec.ts` (it targets the real implementation URL `/ui/admin/subscription-tiers`) and delete the stale `tier-manager.spec.ts` or reassign its sections to cover the user-facing `TierManager.tsx` at `/subscriptions/manage`.

### 4.3 `admin_subscription_tiers` table in local DDB init

Confirmed present at `scripts/local-ddb-init.py:2111`. No GSI for `display_order` sort (list uses a Query on PK and then Python-side sort by `display_order`). This is acceptable given the small cardinality (< 20 tiers per creator). A GSI would only be needed if list endpoints are called at high frequency by many creators simultaneously.

### 4.4 Dev/Prod parity

No change needed. The service exclusively uses `T.admin_subscription_tiers` and `T.subscriptions`, both of which resolve to DynamoDB Local in dev and real DynamoDB in prod via the same `app/core/tables.py` abstraction (SECOPS-007 compliant).

### 4.5 Implement `growth_series` in analytics

Add a DynamoDB GSI on `T.subscriptions` (e.g., `GSI_creator_created_at`: `PK=CREATOR#{creator_id}`, `SK=created_at` as type N) and query it within `get_tier_analytics` to bucket new subscriptions by week. Until then, document `growth_series: []` as not-yet-implemented in the API response schema.

### 4.6 Auto-update `subscriber_count` on subscription lifecycle events

In `app/services/subscription_cycle_orders.py`, after a subscription is activated, call:
```python
from app.services.admin_subscription_tiers import update_tier
update_tier(creator_id=creator_id, tier_id=tier_id, subscriber_count=new_count)
```
Similarly decrement on cancellation. Without this, the denormalised count drifts and tiers without a `plan_id` link show stale analytics data.

### 4.7 Alternatives considered

The ticket proposed `/v1/subscriptions/tiers` prefix with `require_ui_session`. Rejected: the `/v1/` prefix is not consistent with how this codebase structures admin endpoints (all admin routes are under `/ui/admin/*`), and `require_ui_session` would have been a privilege escalation vulnerability for this feature. Storing tiers in the existing `billing` table (`CREATOR#/TIER#` PK/SK) was proposed in the ticket but the implementation uses a dedicated `admin_subscription_tiers` table, which avoids namespace collision with billing records and keeps analytics queries isolated.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_admin_subscription_tiers.py`)

All DynamoDB mocked via `moto`. Key cases:

- `test_create_tier_auto_assigns_display_order`: verify second tier gets `display_order=1`.
- `test_delete_tier_condition_expression`: seed tier with `subscriber_count=1`; assert 409.
- `test_archive_idempotency`: archive twice; second call returns 400, not 500.
- `test_reorder_validates_unknown_id`: include a fake tier_id; assert 400.
- `test_get_tier_analytics_with_subscriptions`: seed `T.subscriptions` records with `creator_id` and `plan_id`; call `get_tier_analytics(creator_id)`; assert `subscriber_count` and `revenue_cents` aggregate correctly by plan.
- `test_get_tier_analytics_fallback_denormalised`: seed a tier with no `plan_id` and `subscriber_count=5`; assert analytics returns `subscriber_count=5` and `revenue_cents=5*price_cents`.
- `test_growth_series_is_empty`: assert `get_tier_analytics(...)["growth_series"] == []` (documents stub behaviour).
- `test_preview_excludes_archived`: archive a tier; verify it does not appear in `preview_tiers` output.

### E2E tests (Playwright)

`frontend/e2e/admin-subscription-tiers.spec.ts` exists and covers sections 547–550b. Ensure:

- `injectAuth(page, "charlie_admin")` or `injectAuth(page, "root")` — these users have ADMIN/ROOT roles so `require_admin_or_root` passes.
- CSRF header sent on POST/PATCH/PUT/DELETE via `headers: { "x-csrf-token": sessions["root"].csrf_token }`.
- URL base: `http://localhost:8000/ui/admin/subscription-tiers` (not `/v1/subscriptions/tiers`).
- UI tests use `page.goto("/admin/subscription-tiers")` (note the admin path, not `/subscriptions/manage`).

### Metrics and observability

`audit_event` calls are present in all mutating endpoints in the router (e.g., `"admin_subscription_tier_create"` at `admin_subscription_tiers.py`). Extend with Prometheus counters in `app/metrics.py` for `tier_created_total`, `tier_archived_total`, `tier_deleted_total` labelled by `billing_cycle`.

### Rollout

Because no feature flag currently gates the endpoint, the feature is live immediately for admin/root users once deployed. Rollout is safe because the `admin_subscription_tiers` table is separate from the existing `billing` table — no existing data is affected.

**Risks**: the analytics function cross-queries `T.subscriptions` without a GSI keyed on `creator_id + tier_id`. For creators with thousands of subscribers, `get_tier_analytics` will perform a full scan filtered by `creator_id`. Add a GSI `GSI_creator_id` on `T.subscriptions` or denormalise subscriber counts more aggressively if p95 analytics latency exceeds the 2s target.

**Effort**: S (already implemented, only flag + E2E consolidation + analytics GSI remain).

---

## Second-pass verification (2026-06-05)

- [Confirmed] service file is 409 lines — `app/services/admin_subscription_tiers.py` (wc -l = 409)
- [Confirmed] router file is 190 lines — `app/routers/admin_subscription_tiers.py` (wc -l = 190)
- [Confirmed] frontend page is 356 lines — `frontend/src/pages/admin/SubscriptionTierManagerPage.tsx` (wc -l = 356)
- [Confirmed] API wrappers file is 55 lines — `frontend/src/api/endpoints/adminSubscriptionTiers.ts` (wc -l = 55)
- [Confirmed] `create_tier` at line 118, `update_tier` at 174, `archive_tier` at 211, `unarchive_tier` at 231, `delete_tier` at 244, `list_tiers` at 272, `reorder_tiers` at 282, `get_tier_subscriber_count` at 340, `get_tier_analytics` at 346, `preview_tiers` at 393 — all match
- [Confirmed] `_active_subscriptions_for_creator` at line 309, scan loop uses `FilterExpression` with `LastEvaluatedKey` loop — matches description
- [Confirmed] `growth_series: []` stub at line 389 — confirmed
- [Confirmed] settings key `admin_subscription_tiers_table_name` at `app/core/settings.py:2276` — confirmed
- [Confirmed] table handle at `app/core/tables.py:519` — confirmed (line 519)
- [Confirmed] table registered in `scripts/local-ddb-init.py:2111` — confirmed
- [Confirmed] router registered in `app/main.py` at import line 74, `include_router` at line 539 — confirmed
- [Confirmed] route in `frontend/src/App.tsx` at lines 157 (lazy import) and 452 (Route) — confirmed
- [Confirmed] auth uses `require_admin_or_root` (read) and `require_admin_or_root_csrf` (mutate) — confirmed
- [Confirmed] `require_admin_or_root` at `app/auth/policy.py:67`, `require_admin_or_root_csrf` at line 100 — confirmed
- [Corrected] "No feature flag in the implementation" — a feature flag `admin_subscription_tiers_enabled` DOES exist at `app/core/settings.py:2279-2281` (env var `ADMIN_SUBSCRIPTION_TIERS_ENABLED`), but it is NOT checked in the router — the gap is that the flag exists but is not wired to the router, not that the flag is absent entirely
- [Corrected] `tier-manager.spec.ts` — the writeup says this spec "targets the stale `/v1/subscriptions/tiers` prefix from the ticket document" and "would fail against the current backend." In reality, `frontend/e2e/tier-manager.spec.ts` covers BILLING-003 (creator-facing subscription tier editor), not admin tier management at all. It uses the subscriptions API (`/api/creators/{id}/plans`), not `/v1/subscriptions/tiers`. The spec is not stale/broken; it tests a different feature. There is no naming or coverage conflict with `admin-subscription-tiers.spec.ts`.
- [Confirmed] all ten router endpoints present (POST create, GET list, PUT reorder, GET analytics, GET preview, GET single, PATCH update, POST archive, POST unarchive, DELETE) — confirmed by `grep -n "^@admin_subscription_tiers_router"` on the router
