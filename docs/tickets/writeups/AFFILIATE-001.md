# AFFILIATE-001: Referral & Affiliate System — Investigation & Implementation Write-up

## 1. Summary & Classification

AFFILIATE-001 implements a complete referral and affiliate commission system: users generate shareable referral codes, new signups via those links are attributed via a 30-day cookie, and referrers earn a configurable commission percentage (5% standard, 10% premium) on referred users' qualifying purchases for 12 months. Commissions accumulate in an affiliate wallet and are withdrawable through the existing MON-004 payout system.

- **Type**: Feature
- **Priority**: Medium (12–14 days estimate)
- **Status**: Substantially Implemented — `app/services/referrals.py` and `app/routers/referrals.py` both exist and are registered in `app/main.py` (lines 166, 635–636). Settings entries exist at `app/core/settings.py:1270–1277`. The core data flows (code generation, attribution, commission recording, dashboard) are all implemented. Gaps exist in the withdrawal endpoint, the registration hook, and the billing hook integration.
- **Owning area**: Growth / Monetization
- **User persona**: Creators and power users who have external audiences and want to earn by driving signups
- **Cross-references**: [[SEC-013]] (commission replay vulnerability at `referrals.py:289`), [[MON-004]] (payout system for withdrawal), [[SECOPS-007]] (DDB via `app_single_table` backed by DDB Local in dev)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service Layer: `app/services/referrals.py`

**DDB strategy**: All referral entities live in `app_single_table` (verified at `scripts/local-ddb-init.py:221–233` with GSI1–GSI5). The service lazily resolves the table handle via `_tbl()` (`referrals.py:36–47`), constructing a `boto3.resource("dynamodb")` client using `DDB_ENDPOINT_URL` from env. This deviates from the `T.*` pattern used elsewhere in the codebase — it replicates the same DDB Local / prod selection logic but independently rather than reusing `app/core/tables.py` wiring.

**`create_referral_code(user_id)`** (`referrals.py:72–108`): Queries GSI1 (`REFCODES#{user_id}`) to count active codes, enforces `S.referral_max_codes_per_user` limit (raises `ValueError` → HTTP 429 in router). Generates 8-char alphanumeric code via `secrets.choice`. Uses `ConditionExpression="attribute_not_exists(pk)"` on `put_item` (`line 102`) for collision safety.

**`attribute_referral(referred_user_id, referral_code, ip_address, source)`** (`referrals.py:156–204`): Validates code is active, blocks self-referral, checks for existing attribution (get-then-put). **Critical gap**: The attribution `put_item` at line 203 has no `ConditionExpression`. A race condition with two concurrent signups using the same code and the same `referred_user_id` can both pass the `existing` check and both write attributions. This is documented as a vulnerability in [[SEC-013]] under "Referral attribution race" at `referrals.py:179–203`.

**`record_affiliate_commission(referred_user_id, transaction_id, source_type, gross_amount_cents, platform_fee_cents)`** (`referrals.py:238–290`): Fetches attribution, checks `status != "revoked"`, checks commission window expiry, looks up referral code tier, calculates `commission_cents = max(1, (net_amount * rate_bps) // 10000)`. Writes the commission entry to `AFFILIATE#{referrer_id}` PK with SK `COMMISSION#{ts}#{transaction_id}`. **Critical gap per SEC-013**: The `put_item` at line 289 has no `ConditionExpression`. Since the SK includes `ts = now_ts()` (re-evaluated on each call), two calls with the same `transaction_id` at different seconds produce different SKs and both succeed — double commission.

**`list_commissions(referrer_user_id, limit, cursor)`** (`referrals.py:293–329`): Paginated query by `pk = AFFILIATE#{user_id}`, sorted descending. Cursor is base64-encoded `LastEvaluatedKey`.

**`get_referral_dashboard(user_id)`** (`referrals.py:343–414`): Aggregates codes, referrals, and commissions from three DDB queries. Computes `available_for_withdrawal_cents = max(0, confirmed_commission - paid_commission)` where `confirmed_commission` includes both `"confirmed"` and `"pending"` statuses (`line 384`). This means pending commissions (not yet confirmed after the 7-day holdback) are included in "available" — a potential over-reporting issue.

**`list_referral_codes`, `disable_referral_code`, `lookup_referral_code`** (`referrals.py:111–148`): Standard CRUD, correctly scoped by `owner_user_id` check on disable.

**Missing from service**: No `withdraw` function. No `confirm_referral` (the 7-day holdback status transition from `pending` → `confirmed`). No `revoke_attribution` function (needed for ban-and-revoke per the fraud spec).

### 2.2 Router: `app/routers/referrals.py`

**User-facing router** (`/ui/referrals`): Implements `POST /code` (201), `GET /codes`, `DELETE /codes/{code}`, `GET /dashboard`, `GET /commissions`, `GET /attribution`, `GET /referrals`. All use `require_ui_session` and check `S.referral_enabled`. Feature flag check via `_require_referral_enabled()` raises HTTP 503 when disabled.

**Internal router** (`/internal/referrals`): `POST /attribute` and `POST /commission`. Both are unauthenticated internal endpoints — no auth middleware. These must be called only from the registration flow and billing hooks respectively.

**Missing from router**: No `POST /withdraw` endpoint. The ticket spec defines this as `POST /ui/referrals/withdraw` with `amount_cents` body, delegating to the MON-004 payout system.

### 2.3 Settings: `app/core/settings.py:1270–1277`

Verified settings (line numbers per ticket appendix):
- `referral_enabled: bool` (feature flag)
- `referral_cookie_max_age_days: int`
- `referral_standard_rate_bps: int` (500 = 5%)
- `referral_premium_rate_bps: int` (1000 = 10%)
- `referral_max_codes_per_user: int` (5)
- `referral_commission_window_days: int` (365)
- `referral_holdback_days: int` (7)
- `referral_min_withdrawal_cents: int` (1000 = $10)

`S.public_base_url` used in `create_referral_code` (`referrals.py:105`) is verified at `app/core/settings.py:301`.

### 2.4 Registration Hook Status

The ticket specifies hooking into `app/routers/register.py` to call `attribute_referral` when a `ref_attribution` cookie is present at signup. **No such hook exists** in `app/routers/register.py`. The `/internal/referrals/attribute` endpoint exists and is the intended call target, but no code in `register.py` reads the `ref_attribution` cookie or calls the internal endpoint.

### 2.5 Billing Hook Status

The ticket specifies adding a `record_affiliate_commission` call in `app/services/billing_shared.py` for qualifying purchases. **No such hook exists** in `billing_shared.py`. The `/internal/referrals/commission` endpoint exists but no billing path calls it.

### 2.6 Frontend Status

No `frontend/src/pages/referrals/ReferralDashboard.tsx` exists. No `frontend/src/api/endpoints/referrals.ts`. The E2E spec `frontend/e2e/referrals.spec.ts` exists (verified in directory listing). TypeScript types for referral entities are absent from `frontend/src/api/types.ts`. No route entry for `/referrals` in `frontend/src/App.tsx`. No attribution cookie capture in `frontend/src/main.tsx`.

### 2.7 Dev/Prod Parity

The service uses `_tbl()` which constructs a DDB client from `DDB_ENDPOINT_URL` env var — in dev, `DDB_ENDPOINT_URL=http://localhost:8001`, in prod the env var is absent and boto3 uses the real DynamoDB regional endpoint. This is functionally correct but deviates from the canonical `T.*` pattern. The same `app_single_table` table works in both environments.

---

## 3. Gap / Threat Analysis

### 3.1 Commission Replay (SEC-013 Cross-Reference)

**File**: `app/services/referrals.py:289`
```python
tbl.put_item(Item=entry)
```
The sort key is `COMMISSION#{ts}#{transaction_id}`. `ts = now_ts()` is evaluated at call time — two calls with the same `transaction_id` at different seconds produce different PKs and both succeed. A compromised billing webhook or a retry loop replaying the same `transaction_id` pays the referrer twice (or more).

**Fix** (per SEC-013 recommendation): Add a separate DDB item with PK `COMMISSION_DEDUP#{transaction_id}` SK `META` written with `ConditionExpression="attribute_not_exists(pk)"` before the commission entry write. On `ConditionalCheckFailedException`, return `None` (silently deduplicated). Alternatively, include `transaction_id` alone (without `ts`) in the sort key and use `ConditionExpression="attribute_not_exists(pk)"` on the commission put. The second approach is simpler but changes the SK structure for all commissions.

### 3.2 Attribution Race (SEC-013 Cross-Reference)

**File**: `app/services/referrals.py:179–203`

Get-then-put with no conditional write. Two concurrent registrations with the same `referred_user_id` can both pass `if existing: return None` and both write `REFERRAL#{referred_user_id}`. Only one attribution record is semantically valid.

**Fix**: Add `ConditionExpression="attribute_not_exists(pk)"` to the `put_item` at line 203. On `ConditionalCheckFailedException`, return `None`. This converts the race window to a safe idempotent operation.

### 3.3 Available Balance Over-Reporting

`get_referral_dashboard` includes `pending` commissions (not yet confirmed after the 7-day holdback) in `confirmed_commission` (`referrals.py:384`). The variable is named `confirmed_commission` but includes `pending`. A referrer seeing `available_for_withdrawal_cents` based on pending commissions may attempt a withdrawal that the holdback logic should block. The withdrawal endpoint (once built) must re-validate against confirmed-only balance.

### 3.4 Missing Registration and Billing Hooks

The entire value proposition of the system depends on two hooks that do not exist:
1. Registration hook: Without it, referral codes can be generated and the dashboard is visible, but no new signup ever gets attributed regardless of which referral link they clicked.
2. Billing hook: Without it, no commissions are ever recorded. The affiliate wallet is permanently empty.

These are not optional enhancements — they are required for the feature to function.

### 3.5 Withdrawal Not Implemented

The withdrawal flow (route `POST /ui/referrals/withdraw`, service function, MON-004 payout integration) is entirely absent. Users can see their commission balance but cannot access it.

---

## 4. Proposed Design / Fix

### 4.1 Commission Replay Fix (SEC-013 Fix)

In `record_affiliate_commission` (`referrals.py:238–290`), before writing the commission entry, attempt to write a deduplication sentinel:
```python
dedup_pk = f"COMMISSION_DEDUP#{transaction_id}"
try:
    tbl.put_item(
        Item={"pk": dedup_pk, "sk": "META", "created_at": _now_iso()},
        ConditionExpression="attribute_not_exists(pk)",
    )
except tbl.meta.client.exceptions.ConditionalCheckFailedException:
    logger.info("commission_dedup_blocked: tx_id=%s", transaction_id)
    return None
```
Then write the commission entry unconditionally. This makes the dedup check the atomic guard. The `COMMISSION_DEDUP#` items consume minimal DDB space and should have a TTL set (commission window + buffer) if a DDB TTL is configured on `app_single_table`.

### 4.2 Attribution Race Fix (SEC-013 Fix)

Change `tbl.put_item(Item=item)` at `referrals.py:203` to:
```python
try:
    tbl.put_item(Item=item, ConditionExpression="attribute_not_exists(pk)")
except tbl.meta.client.exceptions.ConditionalCheckFailedException:
    logger.info("attribution_dedup_blocked: referred_user_id=%s", referred_user_id)
    return None
```
This eliminates the TOCTOU window entirely.

### 4.3 Available Balance Fix

In `get_referral_dashboard`, separate `confirmed_commission` from `pending_commission`:
```python
confirmed_commission = sum(
    _to_int(c.get("commission_cents", 0))
    for c in commissions if c.get("status") == "confirmed"
)
# pending_commission already computed separately
available = confirmed_commission - paid_commission
```
This ensures `available_for_withdrawal_cents` reflects only confirmed commissions.

### 4.4 Registration Hook

In `app/routers/register.py`, in the `register_confirm` function (line 188), after successful user creation, check for the `ref_attribution` cookie:
```python
ref_code = request.cookies.get("ref_attribution")
if ref_code and S.referral_enabled:
    from app.services.referrals import attribute_referral
    client_ip = request.client.host if request.client else ""
    attribute_referral(new_user_sub, ref_code, client_ip, source="cookie")
```
This is a best-effort call — attribution failure must not block registration. Use `try/except` around the `attribute_referral` call.

### 4.5 Billing Hook

In `app/services/billing_shared.py`, in the `new_ledger_entry` function (line 217) or the specific purchase handlers, add after a qualifying purchase ledger entry is written:
```python
if S.referral_enabled and source_type in ("subscription", "ppv", "tip", "shop_purchase", "unlock"):
    from app.services.referrals import record_affiliate_commission
    try:
        record_affiliate_commission(
            referred_user_id=user_id,
            transaction_id=ledger_sk,  # the unique ledger entry sort key
            source_type=source_type,
            gross_amount_cents=amount_cents,
            platform_fee_cents=platform_fee_cents,
        )
    except Exception as exc:
        logger.warning("affiliate_commission_error: %s", exc)
```
The `transaction_id` must be the unique ledger SK to ensure dedup works correctly.

### 4.6 Withdrawal Endpoint

Add `withdraw(user_id, amount_cents)` to `app/services/referrals.py`:
```python
def withdraw(user_id: str, amount_cents: int) -> dict:
    if amount_cents < S.referral_min_withdrawal_cents:
        raise ValueError("below_minimum")
    dashboard = get_referral_dashboard(user_id)
    available = dashboard["available_for_withdrawal_cents"]
    if amount_cents > available:
        raise ValueError("insufficient_balance")
    # Call MON-004 payout system
    from app.services.creator_payouts import create_payout_request
    result = create_payout_request(user_id, amount_cents, source="affiliate_commission")
    # Mark commissions as "paid" up to amount_cents (scan and mark)
    _mark_commissions_paid(user_id, amount_cents)
    return {"ok": True, "payout_request_id": result["payout_request_id"],
            "amount_cents": amount_cents, "status": "pending"}
```

Add router endpoint `POST /ui/referrals/withdraw` with `WithdrawBody(amount_cents: int = Field(ge=1))`.

### 4.7 Frontend

Four new files per spec:
- `frontend/src/pages/referrals/ReferralDashboard.tsx` — stats cards, code cards, commission history, withdraw section
- `frontend/src/pages/referrals/ReferralCodeCard.tsx` — code display with clipboard copy
- `frontend/src/pages/referrals/CommissionHistory.tsx` — paginated table
- `frontend/src/api/endpoints/referrals.ts` — React Query hooks per section 8.3 of the ticket spec

Attribution cookie in `frontend/src/main.tsx`:
```tsx
const params = new URLSearchParams(window.location.search);
const refCode = params.get("ref");
if (refCode && /^[A-Za-z0-9]{8}$/.test(refCode)) {
  document.cookie = `ref_attribution=${refCode}; path=/; max-age=${30 * 86400}; SameSite=Lax`;
}
```

Add `/referrals` route to `frontend/src/App.tsx`. Add "Referrals" sidebar link under Growth group.

### 4.8 Dev/Prod Parity (SECOPS-007)

All DDB writes via `_tbl()` which reads `DDB_ENDPOINT_URL` from env — DDB Local in dev, real DynamoDB in prod. No direct AWS credential injection needed beyond the existing `AWS_ACCESS_KEY_ID=test` dev setting. Feature flag `S.referral_enabled` selects behavior identically in both environments. Attribution cookie is handled purely in the browser — no server-side env difference.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest Unit Tests (`tests/test_referrals.py`)

Requires `@mock_aws` and creating `app_single_table` with GSI1:

| Test | Verified behavior |
|------|-------------------|
| `test_create_code_unique_alphanumeric` | Code is 8 chars, alphanumeric, unique |
| `test_max_codes_enforced` | 6th create raises `ValueError` |
| `test_self_referral_blocked` | `attribute_referral(alice, alice_code)` → `None` |
| `test_duplicate_attribution_ignored` | Second `attribute_referral` for same user → `None` |
| `test_attribution_race_conditional` | After fix: concurrent calls both return, second returns `None` |
| `test_commission_5pct_standard` | 500 bps × $10 = $0.50 commission on $10 net |
| `test_commission_dedup` | Same `transaction_id` twice → second call returns `None` (after fix) |
| `test_commission_blocked_after_window` | `commission_window_ends_at` in past → `None` |
| `test_commission_blocked_revoked` | `status="revoked"` attribution → `None` |
| `test_dashboard_available_balance_confirmed_only` | After fix: pending commissions excluded from available balance |
| `test_max_5_active_codes` | Verified via count-based check |
| `test_disable_code_blocks_attribution` | Disabled code → `attribute_referral` returns `None` |

### 5.2 Playwright E2E (`frontend/e2e/referrals.spec.ts`)

The spec file exists. Tests use Alice (referrer) and Bob (referred) sessions. Key scenarios per the ticket spec:
- Alice generates code → 201, code 8 chars, link has `ref=` param
- 6th code → 429
- Bob signs up via internal attribute endpoint with Alice's code → GET attribution returns Alice's user_id
- Self-attribution → `ok: false`
- Commission recorded on Bob's qualifying purchase → GET commissions shows entry with correct rate
- Same transaction_id twice → only one commission entry (after dedup fix)
- Dashboard shows correct referral counts and earnings
- Withdraw $10+ from confirmed balance → 200 (after withdrawal endpoint built)

### 5.3 Integration Order

1. **Immediate** (SEC-013 fixes, S ~0.5 day): Add `ConditionExpression` to `attribute_referral` and commission dedup sentinel to `record_affiliate_commission`. These are safety fixes that should land before any production traffic.
2. **Phase 1** (~2 days): Registration hook in `register.py`. This activates attribution without any UI.
3. **Phase 2** (~2 days): Billing hook in `billing_shared.py`. This activates commission recording.
4. **Phase 3** (~2 days): Withdrawal endpoint + MON-004 integration.
5. **Phase 4** (~3 days): Frontend dashboard, attribution cookie in `main.tsx`, routing.
6. **Phase 5** (~2 days): E2E test coverage for all sections.

### 5.4 Observability

Existing service logs `Self-referral blocked` at WARNING. Add counters at `app/metrics.py`:
- `referral_attribution_total` (labels: `status` — recorded/blocked/self_referral/race_blocked)
- `referral_commission_total` (labels: `source_type`, `status` — recorded/dedup_blocked/no_attribution)
- `referral_withdrawal_total` (labels: `status` — success/insufficient/below_min)

### 5.5 Rollback

Set `REFERRAL_ENABLED=false` → `S.referral_enabled=False` → all endpoints return 503, registration and billing hooks no-op. Existing data in `app_single_table` is preserved for reactivation. No DDB schema changes needed for the SEC-013 fixes (dedup sentinel uses same table with new PK prefix).

- **Risk**: The billing hook adds 2–3 DDB reads + 1 write per qualifying purchase. On a high-volume purchase path this adds ~20ms latency. Use `try/except` to ensure hook failure never blocks purchase completion.
- **Effort**: Core backend (with SEC-013 fixes and hooks): M (~5 days). Frontend: M (~3 days). Total: L (10–12 days, consistent with estimate).
