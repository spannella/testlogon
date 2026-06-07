# BILLING-003: Subscription Tier Management UI (Creator-Facing) — Investigation & Implementation Write-up

> Type: feature | Priority: High | Status: Implemented | Area: subscriptions / creator-monetization

## 1. Summary & Classification

BILLING-003 adds a complete creator-facing Subscription Tier Management interface at `/subscriptions/manage`. Before this ticket, the platform had a fully functional backend for subscription plan CRUD and discount code management, but no frontend surface for creators to use it. Creators could not create tiers, set pricing, manage assets, or configure discount codes without making raw API calls with `X-User-Id` headers — a hard ceiling on creator monetization.

**Type**: Frontend feature with minor backend API client additions. **Priority**: High — subscription revenue is the primary creator monetization model. **User persona**: Content creators managing their subscription offering.

**Cross-references**: The backend plan CRUD endpoints at `app/routers/subscription_server.py:706-812` are pre-existing. The subscriber-facing `PlanBrowser.tsx` is reused as a preview tab. No SEC or SECOPS tickets are directly implicated; the `X-User-Id` ownership model is the existing auth pattern for the subscription system. SECOPS-007 is not directly relevant since no new server-side capabilities are added.

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend — fully implemented before this ticket

**Plan CRUD** (`app/routers/subscription_server.py:706-812`):

- `create_plan` at line 706: `POST /api/creators/{creator_id}/plans`. Validates `require_user(x_user_id, creator_id)` at line 713 (raises 403 if IDs differ). Calls `normalize_asset_paths()` + `resolve_plan_assets()` at lines 714-715 to convert `asset_paths` strings to resolved file metadata. Always sets `status="active"` on creation. Writes `audit_event("subscription_plan_created", ...)`.
- `list_plans` at line 746: `GET /api/creators/{creator_id}/plans` — public endpoint, no auth required. Filters and returns all plans for a creator.
- `update_plan` at line 756: `PATCH /api/plans/{plan_id}`. Validates `require_user(x_user_id, plan["creator_id"])` at line 766. Supports partial updates — only non-None fields are applied. `PlanUpdateIn` at line 300 has all fields optional. `asset_paths: Optional[conlist(str, max_length=50)]` limits to 50 paths.
- `archive_plan` at line 792: `POST /api/plans/{plan_id}/archive`. Validates ownership at line 801. Sets `status="archived"` and saves.

**Pydantic models** (`app/routers/subscription_server.py`):
- `PlanCreateIn` at line 289: `name` (min=2, max=128), `description` (max=1000), `price_cents: conint(gt=0)`, `currency` (default "usd"), `interval: Literal["month", "year"]`, `annual_price_cents: Optional[conint(gt=0)]`, `metadata: Dict`, `asset_paths: List[str]`.
- `PlanUpdateIn` at line 300: all fields optional, `asset_paths: Optional[conlist(str, max_length=50)]`.
- `PlanOut` at line 312: `plan_id`, `creator_id`, `name`, `description`, `price_cents`, `currency`, `interval`, `annual_price_cents`, `status`, `metadata`, `assets`, `created_at`, `updated_at`, `creator_profile`.

**Discount code endpoints** (`subscription_server.py:1573-1669`):
- `create_discount_code` at line 1573: `POST /api/creators/{creator_id}/discounts`. Auto-uppercases code at line 1581 via `.strip().upper()`. Validates that `"repeating"` duration requires `duration_months` (lines 1582-1585). Stores with SK `_discount_sk(code)` = `"DISCOUNT#{code}"` at line 1589. Uses `ddb_put_item` (unconditional) — duplicate codes silently overwrite.
- `list_discount_codes` at line 1620: `GET /api/creators/{creator_id}/discounts`. Queries entire creator partition, filters `sk.startswith("DISCOUNT#")`, sorts by `created_at` descending.
- `disable_discount_code` at line 1640: `POST /api/creators/{creator_id}/discounts/{code}/disable`. Sets `active=False` + updates `updated_at`.

**Discount models** (`subscription_server.py:466-481`):
- `DiscountCodeCreateIn` at 466: `code` (min=3, max=32), `percent_off: conint(ge=1, le=100)`, `duration: Literal["once", "repeating", "forever"]`, `duration_months: Optional[conint(ge=1, le=36)]`, `active: bool = True`.
- `DiscountCodeOut` at 474: `code`, `percent_off`, `duration`, `duration_months`, `active`, `created_at`, `updated_at`.

**Auth model**: All plan and discount endpoints use `X-User-Id` header auth with `require_user(x_user_id, creator_id)`. This is the subscription server's own auth pattern — distinct from the main app's `require_ui_session` cookie-based auth. The frontend sends `X-User-Id: {userId}` from `useAuthStore.getState().userId` via the `userIdHeader()` helper at `frontend/src/api/endpoints/subscriptions.ts:17`.

### 2.2 Frontend — state at implementation

**Pre-existing**: `frontend/src/pages/subscriptions/PlanBrowser.tsx` (subscriber-facing, 187 lines) renders plan cards for subscribers. Filters `status === "active"` at line 66. Has discount code input and subscribe mutation. Read-only — no create/edit/archive.

**Pre-existing API client**: `frontend/src/api/endpoints/subscriptions.ts:17-31` provides `userIdHeader()`, `subGet()`, `subPost()` helpers plus subscriber-facing functions `listPlans`, `subscribe`, `listSubscriptions`, `cancelSubscription`, `resumeSubscription`, `changePlan`, `updateRenewal`.

**Now implemented** (this ticket):
- Route `/subscriptions/manage` at `frontend/src/App.tsx:396`.
- Lazy import at `App.tsx:64`: `const TierManager = lazy(() => import("@/pages/subscriptions/TierManager"))`.
- Sidebar entry at `frontend/src/components/layout/Sidebar.tsx:126`: `"Tier Manager"` with `Layers` icon, path `/subscriptions/manage`.
- Components: `TierManager.tsx` (308 lines), `PlanEditor.tsx` (328 lines), `DiscountCodeManager.tsx` (339 lines).
- API functions: `createPlan`, `updatePlan`, `archivePlan`, `createDiscount`, `listDiscounts`, `disableDiscount` at `subscriptions.ts:94-112`.

---

## 3. Gap / Threat Analysis

### 3.1 Functional gaps resolved

The gap was entirely at the frontend layer. Every backend endpoint existed and was tested. Creators needed:
1. A page listing their plans with status badges, edit/archive/reactivate actions.
2. A dialog form for creating/editing plans with dollar-to-cent conversion, optional annual price, and asset path management.
3. A discount code table with create form and disable action.
4. A preview tab reusing `PlanBrowser.tsx` to show the subscriber view.

### 3.2 Auth pattern mismatch risk

The subscription server uses `X-User-Id` header auth (not cookie+CSRF). The existing `subPost()` helper in `subscriptions.ts` sends `X-User-Id` from `useAuthStore.getState().userId`. This bypasses CSRF protection on plan mutations. This is the established pattern for the subscription API and is documented — the subscription server has no cookie/CSRF enforcement. The `userIdHeader()` function must always use `useAuthStore.getState().userId` (not `useAuthStore((s) => s.userId)` which is reactive) to avoid React hook rule violations in non-component contexts.

### 3.3 Discount code overwrite behavior

`ddb_put_item` at `subscription_server.py:1287` (called from `create_discount_code` line 1607) is an unconditional write. If a creator submits a code that already exists, the existing record is silently overwritten — this resets `created_at`, `percent_off`, and other fields. The frontend should query the existing codes list (via `listDiscounts()`) before submitting and warn if the code already exists. The backend does not return a 409 conflict.

### 3.4 Plan status and subscriber impact

`archive_plan` sets `status="archived"` but does not cancel or migrate existing subscriptions. The `PlanBrowser` subscriber view filters `status === "active"` (line 66 of `PlanBrowser.tsx`), so archived plans stop appearing to new subscribers, but existing subscribers' subscriptions remain active until they cancel. The archive confirmation dialog should communicate this clearly.

`update_plan` allows changing `price_cents`. The backend does not apply price changes to existing subscribers (no subscription update call to Stripe). Price changes only affect new subscribers. The editor should include a note: "Price changes apply to new subscribers only."

### 3.5 Asset path resolution

`resolve_plan_assets()` at `subscription_server.py:714-715` looks up file metadata from the creator's file manager. If a path no longer exists in the file system (file deleted), the resolved `assets` array may return an empty entry or fail silently. The frontend should treat `assets` as display-only and not assume every `asset_paths` entry resolves to a valid file.

---

## 4. Proposed Design / Fix

### 4.1 Component architecture (as implemented)

**`TierManager.tsx`** (308 lines): Top-level page component with three tabs using shadcn `Tabs`. 
- "Plans" tab: queries `listPlans(userId)` with React Query key `["creator-plans", userId]`. Renders plan cards with edit/archive/reactivate buttons. Archive uses shadcn `AlertDialog` for confirmation. Reactivate calls `updatePlan(planId, { status: "active" })`.
- "Discount Codes" tab: renders `<DiscountCodeManager />`.
- "Preview" tab: renders `<PlanBrowser creatorId={userId} />`.

Local state: `editorOpen: boolean`, `editingPlan: SubscriptionPlan | null` (null = create mode).

**`PlanEditor.tsx`** (328 lines): Dialog form with React Hook Form + Zod. Dollar-to-cent conversion on submit: `Math.round(values.price_dollars * 100)`. Annual price only shown when `interval === "month"`. Dynamic asset path list with add/remove. On success, invalidates `["creator-plans", userId]` and `["plans", userId]` (for the PlanBrowser preview).

Zod schema:
```typescript
const planSchema = z.object({
  name: z.string().min(2).max(128),
  description: z.string().max(1000).optional().or(z.literal("")),
  price_dollars: z.number().positive(),
  interval: z.enum(["month", "year"]),
  annual_price_dollars: z.number().positive().optional().nullable(),
  currency: z.string().min(3).max(10).default("usd"),
  asset_paths: z.array(z.string()).default([]),
});
```

**`DiscountCodeManager.tsx`** (339 lines): Table of discount codes with create form. Code input auto-uppercased via `value.toUpperCase()` on change (mirrors `subscription_server.py:1581`). Duration cross-validation: `"repeating"` requires `duration_months` — enforced both in Zod refine and backend 400 response. Disable action calls `disableDiscount(userId, code)` with confirmation dialog.

### 4.2 API client extensions (`subscriptions.ts:94-112`)

```typescript
export const createPlan = (creatorId: string, body: PlanCreateReq) =>
  subPost<SubscriptionPlan>(`/api/creators/${creatorId}/plans`, body);

export const updatePlan = (planId: string, body: PlanUpdateReq) =>
  // uses subPatch or api.patch with X-User-Id header
  ...

export const archivePlan = (planId: string) =>
  subPost<SubscriptionPlan>(`/api/plans/${planId}/archive`, {});

export const createDiscount = (creatorId: string, body: DiscountCodeCreateReq) =>
  subPost<DiscountCode>(`/api/creators/${creatorId}/discounts`, body);

export const listDiscounts = (creatorId: string) =>
  subGet<DiscountCode[]>(`/api/creators/${creatorId}/discounts`);

export const disableDiscount = (creatorId: string, code: string) =>
  subPost<DiscountCode>(`/api/creators/${creatorId}/discounts/${encodeURIComponent(code)}/disable`, {});
```

### 4.3 TypeScript types

Added to `frontend/src/api/types.ts`: `PlanCreateReq`, `PlanUpdateReq`, `DiscountCodeCreateReq`, `DiscountCode`. These mirror the backend Pydantic model field names and types.

### 4.4 Dev/Prod parity (SECOPS-007)

The subscription server endpoints use `X-User-Id` header auth and DynamoDB. In dev, `DDB_ENDPOINT_URL=http://localhost:8001` routes all DDB operations to DDB Local. In prod, real DynamoDB is used. The `ddb_put_item`, `ddb_query`, `ddb_get_item` functions in the subscription server use the boto3 client configured with `endpoint_url` from settings via `app/core/aws.py` (rule 1 of SECOPS-007). No new AWS services are introduced. `resolve_plan_assets()` reads from the file manager (which uses S3/moto via `app/core/dev_s3.py` in dev) — no changes needed there.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_subscription_tier_editor.py`)

Tests use moto DynamoDB and the FastAPI test client. The subscription server uses its own DDB helper functions (`ddb_put_item`, `ddb_query`) which are configured via settings. No Stripe mock needed.

| Test | Coverage |
|------|----------|
| `test_create_plan_with_valid_data` | POST 200, `plan_id` returned, DDB item stored |
| `test_create_plan_requires_ownership` | Wrong X-User-Id → 403 |
| `test_create_plan_validation` | name < 2 chars → 422, price_cents ≤ 0 → 422 |
| `test_update_plan_partial_fields` | PATCH with only `name` → only name changes |
| `test_archive_plan_sets_status` | POST archive → `status="archived"` |
| `test_reactivate_plan_via_patch` | PATCH `status="active"` → reactivated |
| `test_list_plans_returns_all_statuses` | GET list returns both active and archived |
| `test_create_discount_auto_uppercase` | "save20" → stored as "SAVE20" |
| `test_discount_repeating_requires_months` | `duration="repeating"` without `duration_months` → 400 |
| `test_disable_discount_sets_active_false` | POST disable → `active=false` |
| `test_discount_overwrite_silently` | Create same code twice → second overwrites first |

### 5.2 E2E tests (`frontend/e2e/subscription-tier-editor.spec.ts`)

Auth: `injectAuth(page, "alice")` for creator operations (Alice's `userId` is used as `X-User-Id`). The subscription server validates `X-User-Id == creator_id`, so Alice can only manage her own plans.

Key scenarios:
1. Alice navigates to `/subscriptions/manage`, sees "Plans" tab heading.
2. Alice clicks "Create Plan", fills the PlanEditor form (name, price, interval), submits.
3. Plan appears in the list with "active" badge.
4. Alice edits the plan, changes description, saves.
5. Alice archives the plan; confirmation dialog appears, status changes to "archived".
6. Preview tab shows only active plans (using `PlanBrowser`).
7. Alice creates a discount code "PROMO10", 10% off, "once" duration.
8. Discount appears in table with active badge.
9. Alice disables the code; badge changes to disabled.
10. Attempt to create discount "PROMO10" again — overwrite warning shown.

Note: The subscription API uses `X-User-Id` auth, not cookie CSRF. In E2E tests, use `page.request.post(url, { headers: { "X-User-Id": aliceId }, ... })` for direct API calls, not the CSRF-injecting helper `apiPost`. The subscription server routes (`/api/*`) are proxied by Vite without CSRF enforcement.

### 5.3 Manual verification

1. `just restart`. 
2. Log in as Alice at `http://localhost:3000`.
3. Navigate to Sidebar → "Tier Manager".
4. Verify the three tabs: Plans, Discount Codes, Preview.
5. Create a plan: name "Test Tier", $9.99/month, annual $99.99/year.
6. Verify plan card shows monthly and annual price with savings percentage.
7. Navigate to Preview tab: plan appears in `PlanBrowser` with subscribe button.
8. Archive the plan: confirm it disappears from Preview tab (subscriber view).
9. Create discount code "SUMMER20" (20% off, once). Verify auto-uppercase.
10. Disable the code; verify badge turns red.

### 5.4 Rollout

No feature flag needed. The route and sidebar link are available to all authenticated users. No new backend tables or settings are introduced — all data goes into the existing subscriptions table under `CREATOR#{creator_id}` prefix. No migration needed.

One open question: should non-creator users see the "Tier Manager" sidebar link? Currently it appears for all authenticated users. A creator check (e.g., `hasActiveSubscriptionPlan`) could conditionally show/hide the link, but this would require an additional API call on every page load. For v1, showing the link to all users and having the page show an empty state ("No subscription tiers yet") is acceptable.

**Effort estimate**: Implemented (~975 lines across three components plus API client additions). Remaining gap: Playwright E2E spec for the full UI flow. Backend plan/discount API is already tested by the existing subscription E2E specs (`frontend/e2e/catalog-subscriptions.spec.ts`).
