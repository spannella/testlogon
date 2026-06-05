# BILLING-004: Dev-Mode Wallet Deposit Direct-Credit Bypass — Investigation & Implementation Write-up

> Type: infra / dev-environment hardening | Priority: Medium | Status: Open | Area: billing / dev-parity

## 1. Summary & Classification

The wallet deposit endpoint (`POST /billing/wallet/deposit` at `app/routers/billing.py:2315`) uses a Stripe off-session PaymentIntent with `confirm=True` to charge a card and credit the wallet. In dev, the local stripe-mock service (port 12111) **always returns `requires_payment_method` for off-session PaymentIntents** — a documented limitation in CLAUDE.md. As a result, every deposit attempt in dev leaves the wallet balance at 0 while returning HTTP 200, and the frontend shows a success toast ("Deposited $X") for an operation that silently failed to credit the wallet. This is a developer experience and test isolation problem, not a production bug.

**Type**: infra / dev-environment fix. **Priority**: Medium. **Status**: Open (not yet implemented).

**Cross-references**: SEC-004 identifies `wallet_deposit` and `wallet_withdraw` as having an **IDOR vulnerability** — the optional `user_sub` parameter allows a `billing_support` admin to credit or drain any user's wallet. BILLING-004 must be designed to coexist with the SEC-004 fix (which removes the `user_sub` override from those endpoints). BILLING-004 is also adjacent to BILLING-002 (payout dashboard) because developers testing payout flows need funded wallets. See SECOPS-007 for the governing dev/prod parity principle.

**Attacker class (for context)**: N/A — this is a dev-only bypass, strictly guarded by `S.dev_mode`. The SEC-004 IDOR is the security issue; BILLING-004 is a dev-experience fix.

---

## 2. Current-State Investigation (what exists today)

### 2.1 The deposit endpoint (`billing.py:2315-2394`)

The `wallet_deposit` handler at line 2315 has the following code path:

```python
ensure_stripe_configured()                          # line 2317 — raises 501 if no Stripe key
user_id, admin_tags = _billing_write_user_context(ctx, user_sub, actor)  # line 2318
...
pi = stripe.PaymentIntent.create(                  # line 2331
    amount=int(body.amount_cents),
    currency=currency,
    customer=customer_id,
    payment_method=payment_method_id,
    off_session=True,
    confirm=True,
    ...
)
state = "settled" if pi.get("status") == "succeeded" else "pending"  # line 2345
led_sk, led_item = new_ledger_entry(...)           # line 2346
ddb_put(T.billing, led_item)                       # line 2356

wallet_balance_cents = 0
if pi.get("status") == "succeeded":               # line 2359 — NEVER true in dev
    wallet_balance_cents = apply_wallet_delta(...)  # line 2360
    settle_or_reverse_ledger(...)                  # line 2361
    create_invoice_safe(...)                       # lines 2363-2380 (best-effort)

return {"status": pi.get("status"), "payment_intent_id": pi["id"],
        "wallet_balance_cents": wallet_balance_cents}  # line 2394
```

In dev, `stripe.PaymentIntent.create(off_session=True, confirm=True)` against `http://localhost:12111` returns a PaymentIntent object with `status: "requires_payment_method"`. The `if pi.get("status") == "succeeded"` branch at line 2359 is never entered. The ledger entry is written with `state="pending"` (line 2345), but `apply_wallet_delta()` is never called, so `wallet_balance_cents` remains 0. The response is `{"status": "requires_payment_method", "payment_intent_id": "pi_mock_...", "wallet_balance_cents": 0}`.

**`ensure_stripe_configured()` at line 513** raises `HTTPException(501)` if `S.stripe_secret_key` is empty. In dev, `.env.local` sets `STRIPE_SECRET_KEY` to any non-empty string and `STRIPE_API_BASE=http://localhost:12111`. The function also sets `stripe.api_base = S.stripe_api_base` (line 520), routing all Stripe SDK calls to stripe-mock.

**`_billing_write_user_context()` at line 468**: Extracts `user_id` from the session context. If `user_sub` (the optional override parameter) is non-empty and differs from the session's `user_sub`, it calls `_require_billing_support_actor()` at line 475 to enforce the `billing_support` scope. This is the IDOR vulnerability documented in SEC-004 at `billing.py:2316-2318`.

### 2.2 Frontend behavior (`frontend/src/pages/billing/Wallet.tsx`)

The deposit mutation at `Wallet.tsx:46-60`:

```typescript
const depositMut = useMutation({
  mutationFn: ({ amount_cents, payment_method_id }) =>
    depositToWallet({ amount_cents, payment_method_id }),
  onSuccess: (data) => {
    toast.success(`Deposited ${formatCents(
      data.wallet_balance_cents > 0
        ? Math.round(parseFloat(depositDollars) * 100)
        : 0
    )} to wallet`);
  },
```

The toast at line 54 checks `data.wallet_balance_cents > 0`. In dev, `wallet_balance_cents` is 0, so the toast shows "Deposited $0.00" — misleading but technically accurate. However, the `data.wallet_balance_cents > 0` guard means the condition `0 > 0` is false, so the `formatCents(...)` branch uses `0` as its argument. The displayed amount in the toast is "$0.00" rather than the intended amount. This is a UX defect that masks the dev-environment failure.

### 2.3 E2E workaround (`frontend/e2e/billing-wallet.spec.ts`)

The spec (section 69) documents the problem explicitly at lines 13-16:

> "The Stripe mock (localhost:12111) does not simulate `succeeded` status for off_session PaymentIntents — it returns `requires_payment_method`. Therefore wallet balance is NOT credited via the deposit endpoint in tests. Balance seeding for withdraw tests is done via DDB injection."

The `injectWalletBalance()` function at line 151 writes directly to DDB:

```typescript
function injectWalletBalance(userSub: string, balanceCents: number): void {
  execSync(`python3 -c "
import boto3, os
...
table.put_item(Item={
  'pk': 'USER#${userSub}',
  'sk': 'BILLING',
  'wallet_balance_cents': ${balanceCents},
  ...
})"`)
}
```

This bypass is used at lines 301 and 382 to seed a balance of 500 cents before withdraw tests. It confirms the business logic of `apply_wallet_delta()` and `wallet_withdraw` work correctly — only the deposit path is broken.

---

## 3. Gap / Threat Analysis

### 3.1 Developer experience impact

Every dev/QA flow that requires a funded wallet is affected:
- Testing tips requires Alice to have a wallet balance. Currently seeded via `injectWalletBalance`.
- Testing content unlocks (paid messages, locked newsfeed posts) requires wallet balance.
- Testing pay-per-minute calls requires wallet balance.
- Manual QA testing of wallet UX is impossible via the UI — the success toast shows "$0.00".

The deposit endpoint tests in `billing-wallet.spec.ts:254-265` assert `wallet_balance_cents` is a number (type check only) because the value is always 0. The test comment at line 263 says "Note: Stripe mock returns requires_payment_method, so wallet_balance_cents is 0" — this comment should be removed once BILLING-004 is implemented.

### 3.2 Relationship to SEC-004 IDOR

SEC-004 documents that `wallet_deposit` at `billing.py:2316` and `wallet_withdraw` at `billing.py:2398` accept an optional `user_sub` parameter that allows a `billing_support` admin to operate on any user's wallet. The SEC-004 fix removes this override.

BILLING-004 must be implemented **after or alongside** the SEC-004 fix to avoid conflicts:
- SEC-004 removes `user_sub: Optional[str] = None` from the function signature.
- BILLING-004 adds a `if S.dev_mode:` branch before the Stripe call.
- These are non-overlapping changes on different lines.

The BILLING-004 dev bypass operates on the authenticated user's own wallet (derived from `ctx["user_sub"]` directly, not the admin override). It does not introduce a new authorization bypass: `ensure_stripe_configured()` is not called in the dev path, so no Stripe API key check occurs, but the session auth (`require_ui_session` dependency) still validates the caller's identity. The dev bypass is strictly `if S.dev_mode:` — guarded by the runtime flag, not by caller role.

### 3.3 `dev_add_charge` comparison (SEC-004)

`dev_add_charge` at `billing.py:2238` writes a `settled` debit ledger entry directly without any payment confirmation. SEC-004 flags this as a security concern because it can fabricate debt records. The BILLING-004 dev deposit bypass is similar in spirit — it writes a `settled` credit directly — but is guarded by `S.dev_mode` and operates only on the authenticated user's own wallet (no `user_sub` override after SEC-004 fix). The key distinction is that `dev_add_charge` is accessible to `billing_support` admins in any environment where the flag is set, while the BILLING-004 bypass is unconditionally off in production.

### 3.4 Dev/Prod parity analysis (SECOPS-007)

SECOPS-007 requires that dev and prod use the **same code path** with only the injected backend differing. A `if S.dev_mode: return early` branch in business logic violates this principle if it bypasses significant logic (e.g., skips fraud checks, skips idempotency key tracking).

The BILLING-004 bypass is acceptable under SECOPS-007 for the following reasons:
1. It is strictly limited to a known stripe-mock limitation — a mock infrastructure gap, not a business logic shortcut.
2. The bypass still writes the same ledger entry shape (`settled` credit with `reason="wallet_deposit"`).
3. The bypass still calls `apply_wallet_delta()` — the same balance update function used by the production succeeded branch.
4. The bypass still writes `audit_event("billing_wallet_deposit", ..., dev_bypass=True)` — making dev deposits distinguishable in audit logs.
5. Production is entirely unaffected: the `if S.dev_mode:` guard is never entered when `DEV_MODE` is unset or `"0"`.

The pattern is consistent with `list_subscriptions` at `billing.py:2293-2295`:
```python
if S.dev_mode:
    return {"items": []}
```
That existing dev-mode short-circuit is already in the codebase, demonstrating that tactical `if S.dev_mode:` branches are permitted for mock infrastructure limitations.

---

## 4. Proposed Design / Fix

### 4.1 Backend change (`app/routers/billing.py`)

In `wallet_deposit()` at line 2315, add a dev-mode bypass block **after** the session auth, amount validation, and payment-method check, but **before** the `ensure_stripe_configured()` call and `stripe.PaymentIntent.create()` call:

```python
@dual_route("POST", "/billing/wallet/deposit")
def wallet_deposit(body: WalletDepositReq, req: Request = None,
                   ctx=Depends(require_ui_session),
                   actor: AuthenticatedUser = Depends(get_authenticated_user)) -> Dict[str, Any]:
    # After SEC-004 fix: no user_sub override parameter
    user_id = ctx["user_sub"]
    pk = user_pk(user_id)
    billing = ddb_get(T.billing, pk, "BILLING") or {"currency": "usd", "default_payment_method_id": None}
    payment_method_id = body.payment_method_id or billing.get("default_payment_method_id")
    if not payment_method_id:
        raise HTTPException(400, "No payment method provided")
    currency = billing.get("currency", "usd")

    # BILLING-004: dev-mode bypass — stripe-mock cannot confirm off-session intents
    if S.dev_mode:
        ensure_balance_row(T.billing, pk, currency)
        synthetic_pi_id = f"pi_dev_{uuid.uuid4().hex}"
        led_sk, led_item = new_ledger_entry(
            key_name="pk",
            key_value=pk,
            entry_type="credit",
            amount_cents=int(body.amount_cents),
            state="settled",
            reason="wallet_deposit",
            meta={"idempotency_key": body.idempotency_key or synthetic_pi_id,
                  "payment_method_id": payment_method_id},
            extra={"stripe_payment_intent_id": synthetic_pi_id},
        )
        ddb_put(T.billing, led_item)
        wallet_balance_cents = apply_wallet_delta(T.billing, pk, int(body.amount_cents), currency=currency)
        settle_or_reverse_ledger(T.billing, "pk", pk, led_sk, "settled")
        audit_event("billing_wallet_deposit", user_id, req, outcome="success",
                    amount_cents=int(body.amount_cents), currency=currency,
                    payment_intent_id=synthetic_pi_id, status="succeeded",
                    dev_bypass=True)
        return {"status": "succeeded", "payment_intent_id": synthetic_pi_id,
                "wallet_balance_cents": wallet_balance_cents}

    # Production path (unchanged)
    ensure_stripe_configured()
    customer_id = get_or_create_customer(user_id)
    ...
```

Key design decisions:
- `ensure_stripe_configured()` is skipped in the dev path — no Stripe API key or stripe-mock connection required.
- `ensure_balance_row()` is called to initialize the `BILLING` row if absent (same as the dispute handler at `billing.py:1488`).
- The ledger entry uses the same `billing_shared.py` helpers (`new_ledger_entry` at line 224, `apply_wallet_delta` at line 185, `settle_or_reverse_ledger` at line 248) as the production succeeded branch.
- The synthetic `payment_intent_id` uses the `pi_dev_` prefix to make dev deposits identifiable in audit logs.
- `dev_bypass=True` is passed to `audit_event()` as an extra tag.
- The response shape is identical: `{"status": "succeeded", "payment_intent_id": ..., "wallet_balance_cents": ...}`.
- `body.idempotency_key` from `WalletDepositReq` at `app/models.py:1633` is respected in the metadata if provided.

### 4.2 Frontend (`frontend/src/pages/billing/Wallet.tsx`)

No changes required. The existing `onSuccess` handler at line 54 uses `data.wallet_balance_cents > 0` to render the deposit amount. After BILLING-004, `wallet_balance_cents` will be the new balance (> 0 after a successful deposit), so the toast will correctly display "Deposited $X.XX".

The `formatCents` call at line 54 uses the request amount (`Math.round(parseFloat(depositDollars) * 100)`) rather than `data.wallet_balance_cents` for the formatted dollar amount, because `wallet_balance_cents` is the new total balance, not the incremental deposit. This is correct behavior and requires no change.

### 4.3 Dev/Prod parity compliance (SECOPS-007)

The `S.dev_mode` flag is read from `DEV_MODE` env var at `app/core/settings.py`. In dev, `DEV_MODE=1` in `.env.local`. In prod, `DEV_MODE` is unset (defaults to false). The bypass block is strictly gated on `S.dev_mode` and the production Stripe code path is completely unchanged. The response contract (`status`, `payment_intent_id`, `wallet_balance_cents`) is identical in both paths.

Imports: `uuid` is already imported in `billing.py:10`. `ensure_balance_row`, `new_ledger_entry`, `apply_wallet_delta`, `settle_or_reverse_ledger` are already imported from `billing_shared.py`. No new dependencies.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests

Two new test cases added to the existing billing test suite:

**`test_wallet_deposit_dev_mode_credits_balance`**:
- Set `S.dev_mode = True` in test.
- Seed a `PM#test_pm` payment method row for Alice in the moto DDB.
- POST `/ui/billing/wallet/deposit` with `amount_cents=500, payment_method_id="PM#test_pm"`.
- Assert response: `{"status": "succeeded", "payment_intent_id": "pi_dev_...", "wallet_balance_cents": 500}`.
- Assert DDB `BILLING` row has `wallet_balance_cents: 500`.
- Assert DDB ledger entry `state == "settled"` and `reason == "wallet_deposit"`.
- Assert no Stripe API call made (stripe mock client not invoked).

**`test_wallet_deposit_prod_mode_uses_stripe`**:
- Set `S.dev_mode = False`, mock `stripe.PaymentIntent.create` to return `{"status": "succeeded", "id": "pi_test_123"}`.
- Assert `apply_wallet_delta()` is called.
- Assert no `pi_dev_` prefix in the `payment_intent_id`.

### 5.2 E2E tests (updates to `frontend/e2e/billing-wallet.spec.ts`)

**Section 69 modifications**:

Replace test `69.2` ("deposits returns 200 with payment_intent_id but wallet_balance_cents is 0"):
```typescript
// NEW: After BILLING-004, deposit in dev mode credits the wallet
test("69.2 POST /billing/wallet/deposit → wallet_balance_cents credited in dev", async () => {
  const resp = await apiPost(alicePage, "/ui/billing/wallet/deposit", {
    amount_cents: 500,
    payment_method_id: PM_ID,
  });
  expect(resp.status()).toBe(200);
  const data = await resp.json() as { status: string; payment_intent_id: string; wallet_balance_cents: number };
  expect(data.status).toBe("succeeded");
  expect(data.payment_intent_id).toMatch(/^pi_dev_/);
  expect(data.wallet_balance_cents).toBe(500);
});
```

Remove the comment at line 263 ("Note: Stripe mock returns requires_payment_method, so wallet_balance_cents is 0").

The `injectWalletBalance()` helper at line 151 can be retained for tests that need a precise starting balance (e.g., tests that deposit, then add more, then withdraw exact amounts). It is no longer needed for the basic "fund Alice's wallet" setup case.

**UI test (section 70 addition)**:
```typescript
test("70.X Wallet deposit UI shows correct amount in toast", async () => {
  await alicePage.goto("/billing/wallet");
  await alicePage.fill("#deposit-amount", "5.00");
  // Select payment method from dropdown
  await alicePage.click("[data-testid='deposit-submit']");
  await expect(alicePage.getByText("Deposited $5.00")).toBeVisible();
});
```

### 5.3 Manual verification

1. `just restart`.
2. Log in as Alice.
3. Navigate to `/billing/wallet`.
4. Select a payment method (seed one via DDB `injectWalletBalance` or use the Dev Tools seeder).
5. Enter "$5.00" and click Deposit.
6. Verify: response toast shows "Deposited $5.00" (not "$0.00").
7. Verify: wallet balance card updates to show $5.00 available.
8. Navigate to `/billing/ledger`; verify a `wallet_deposit` entry with `state=settled` exists.

### 5.4 Rollout

**Implementation order**: Implement SEC-004 fix (remove `user_sub` override from `wallet_deposit`) first. Then add the BILLING-004 dev bypass block. The two changes are on adjacent lines but do not conflict. The SEC-004 change removes lines 2318/2399; the BILLING-004 change adds the `if S.dev_mode:` block at the top of the function body.

No feature flag needed for BILLING-004 itself — it is guarded by `S.dev_mode` which is already the environment differentiator. No DynamoDB table changes. No frontend changes.

**Rollback**: Remove the `if S.dev_mode:` block. Zero production risk — the block only executes when `DEV_MODE=1`.

**Risks**:
1. If `S.dev_mode` is inadvertently set in a staging environment, deposits would succeed without real Stripe authorization. Mitigation: ensure `DEV_MODE` is never set in any environment that processes real payment methods. The existing CLAUDE.md documentation of `DEV_MODE` and the audit tag `dev_bypass=True` in the ledger provide traceability.
2. The synthetic `pi_dev_{uuid}` IDs will not exist in Stripe's dashboard. If dev ledger entries are ever inspected by Stripe tooling, these IDs will appear invalid. This is expected and acceptable for a dev-only environment.

**Effort estimate**: S (2-3 hours — the change is approximately 20 lines in `billing.py` plus test updates).

---

## Second-pass verification (2026-06-05)

- [Confirmed] Feature still unimplemented — `wallet_deposit` at `billing.py:2315` has no `if S.dev_mode:` bypass block; always calls Stripe and always returns `wallet_balance_cents=0` in dev
- [Confirmed] `wallet_deposit` function at `billing.py:2316`; `ensure_stripe_configured()` first line at 2317; `_billing_write_user_context()` at 2318 ✓
- [Confirmed] `_billing_write_user_context()` defined at `billing.py:468`; calls `_require_billing_support_actor()` at line 475 ✓
- [Confirmed] `ensure_stripe_configured()` defined at `billing.py:513` ✓
- [Confirmed] `pi.get("status") == "succeeded"` branch at `billing.py:2359`; `apply_wallet_delta` at 2360; `settle_or_reverse_ledger` at 2361 ✓
- [Confirmed] `list_subscriptions` dev_mode short-circuit at `billing.py:2293-2295` ✓
- [Confirmed] `billing_shared.py` — `new_ledger_entry` at line 224 ✓, `apply_wallet_delta` at line 185 ✓, `ensure_balance_row` at line 69 ✓
- [Corrected] `billing_shared.py` — `settle_or_reverse_ledger` is at line **258** (not 248 as cited in design §4.1)
- [Corrected] `WalletDepositReq` is at `app/models.py:1630` (not 1633 as cited)
- [Confirmed] `Wallet.tsx` deposit mutation at lines 46-60; toast check `data.wallet_balance_cents > 0` at line 54 ✓
- [Confirmed] `billing-wallet.spec.ts` — Stripe mock comment at lines 11-14 (not 13-16 as cited); `injectWalletBalance()` at line 151 ✓; note comment at line 263 ✓; `injectWalletBalance` calls at lines 301 and 382 ✓
- [Confirmed] `ensure_balance_row` is used at `billing.py:1488` (dispute handler) ✓
