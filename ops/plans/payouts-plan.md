# TestLogon — Creator PAYOUTS / WITHDRAWALS / KYC (money-OUT) Implementation Plan

Status: PLAN (no code changed). Repo `~/dev/testlogon` @ `2207a939` (android-impl == main).
Backend prod EC2 `i-08f937fc705ebea75` probed READ-ONLY via SSM — the payout subsystem
(`creator_payouts.py` 779 lines, `admin_payouts.py`, `bulk_payout_tools.py`) is
**byte-identical to the dev clone**, so every finding and cite below holds on prod.
Sibling plans: `subscriptions-plan.md`, `advertising-v2-implementation-plan.md`,
`tipping-implementation-plan.md`.

---

## 1. VERDICT

**The money-IN side is real and rich; the money-OUT side is a record-keeping shell that
moves no money and — critically — never debits the balance, so earnings are infinitely
re-withdrawable.** TestLogon credits a creator's withdrawable balance from a real
`type:"credit"` ledger across tips/ads/subs/ecom/commissions, and it has a genuinely deep
user-side KYC suite, real W-9 KMS-encrypted collection, and real 1099 generation. But the
actual withdrawal path is a manual, admin-clicked status machine with **four load-bearing
holes**:

1. **DOUBLE-SPEND / infinite withdrawal (P0, correctness).** `complete_payout`
   (`app/services/creator_payouts.py:530-577`) writes **no offsetting `type:"debit"` ledger
   row**, and `get_available_balance` only subtracts payouts while they sit in
   `ACTIVE_PAYOUT_STATES = {requested,approved,processing}` (`creator_payouts.py:25`,
   `_get_active_payout_total :151-178`). The moment a payout completes it stops being
   subtracted and the original credits are still fully present → the same balance becomes
   withdrawable again, unbounded. The platform liability ledger is never reduced.
2. **No real (or honest-mock) transfer (P0).** `complete_payout` just stamps
   `status="completed"`; in `dev_mode` it auto-jumps `approved→completed`
   (`creator_payouts.py:544-560`). The bulk path is an explicit stub —
   `bulk_payout_tools.py:341-342` (`if S.bulk_payout_use_real_provider: pass`). Zero
   `payouts.create` / `Transfer.create` / PayPal-payout hits anywhere in `app/`.
3. **No KYC / tax gate on the money-out path (P0, compliance).** `request_payout`
   (`creator_payouts.py:282-378`) has no `require_kyc_tier` dependency and no W-9
   certification check; the tier-gate that exists (`app/auth/deps.py:412-441`) is inert
   (`kyc_tier_enforcement_enabled` defaults FALSE, `settings.py:1448`) and is wired only to
   `billing.add_card/add_bank` + `newsfeed.tip_post`, never to payouts. A fully unverified,
   tax-uncertified creator can request a payout.
4. **Not routable + no lifecycle automation (P1).** Payout "methods" persist last-4 only
   (`creator_payouts.py` `add_payout_method`, `models.py:2735-2742` `pattern=^\d{0,4}$`) — no
   Stripe Connect / debit-card / tokenized destination. No scheduled runner (`main.py` has
   renewal/dunning/hold sweepers but no `start_payout_*`), no failure/`returned` path
   (`processing`/`failed` are dead states), no notifications on any transition, no
   statement/export, no reserve, no max/schedule.

**Bottom line:** the payout *record* lifecycle is real and race-safe (atomic single-active
sentinel, reversal-aware balance, 7-day hold window), but **no money moves and the balance
never decreases**. This plan makes a withdrawal (a) debit the balance via a real
`type:"debit"` ledger row on the same rail that credits it, (b) move funds through a
funds-guarded mock/real transfer that is honest about what it does, (c) be gated on KYC +
tax, and (d) run on a scheduled sweeper with real states, notifications, holds, and history.

---

## 2. COVERAGE MATRIX (10 requirements)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | **Withdrawable balance** (earned − paid − held) | **PARTIAL** | Computed from credit ledger w/ 7-day hold `creator_payouts.py:84-148`, `GET /balance` router `:44-57`; **integrity broken** — completed payouts never subtracted (Req 4). App: `PayoutSetupScreen.kt:182-205`, `EarningsScreen.kt:288`. |
| 2 | **Payout methods** (bank/PayPal/Connect/debit) | **PARTIAL** | CRUD exists `creator_payouts.py:369-441`, router `:117-180`, but **last-4 only, not routable** (`models.py:2735-2742`); no Connect/debit/tokenization. App: only 2 free-string chips `PayoutSetupScreen.kt:240-243`. |
| 3 | **Withdrawal request** (threshold/fees/confirm) | **PARTIAL** | Real `request_payout` `creator_payouts.py:282-378`, min-threshold `:305-315`, atomic single-active sentinel; **no fee, no KYC gate**. App gated to no-op in release (`StubBillingAuthorizer` `BillingAuthorizer.kt:54-68`). |
| 4 | **Payout processing** (real transfer, debits balance) | **MISSING** | `complete_payout` status-stamp only `creator_payouts.py:530-577`; **no debit ledger row**, bulk stub `bulk_payout_tools.py:341-342`. → infinite re-withdrawal. |
| 5 | **KYC / identity gate** on payouts | **EXISTS (flow) / MISSING (gate)** | Deep user KYC suite `kyc_cases.py`, tiers `kyc_tiers.py:11-25`, shares B6 admin; gate dep `deps.py:412-441` **inert (flag off) + not on payouts**. App flow deep (`feature/kyc/*`) but payout "Verify" is no-op `PayoutsNavigation.kt:76-78`. |
| 6 | **Tax** (W-9/W-8, 1099, withholding) | **PARTIAL** | W-9 KMS-encrypted `tax_info_w9.py:52`, 1099 gen `tax_form_1099.py`; **no backup withholding, not linked to payouts**. App read-only `TaxDocsScreen.kt`, `Form1099ListScreen.kt`. |
| 7 | **Holds / rolling reserve** | **PARTIAL** | Flat 7-day time hold `settings.py:1790` + `get_available_balance`; **no reserve %, no release schedule, no manual/risk hold**. |
| 8 | **Payout lifecycle** (states/retries/notifs) | **PARTIAL** | States `creator_payouts.py:24`, admin-driven transitions; `processing`/`failed` **dead**, `returned` **absent**; no retries/webhook/reconciler. |
| — | **Scheduled payout runner** | **MISSING** | `main.py:768-769` renewal/dunning tasks exist; **no `start_payout_*`**. |
| 9 | **History / statements / export** | **PARTIAL** | List `list_user_payouts` `GET /ui/payouts`; admin list/stats; **no CSV/PDF export/statement**. App `PayoutHistoryScreen.kt:66`, `PayoutDetailScreen.kt`. |
| 10 | **Schedule / limits** | **PARTIAL** | Min $10 `settings.py:1794`; **no max, no instant/weekly/monthly schedule, no per-period velocity** (only 1-active sentinel). |
| — | **Payout/KYC notifications + deep-links** | **MISSING** | Zero `write_alert`/`send_push` on any transition; not in `ALERT_EVENT_TYPES`; no FCM category/deep-link. |

---

## 3. TARGET DESIGN — a complete payout system (reusing existing infra)

The design is **subtractive-first**: fix the balance-integrity bug before adding any rail,
because every downstream feature (methods, schedule, reserve) is meaningless if a completed
payout doesn't reduce the balance. Everything reuses infra already in the repo.

### 3.1 Accurate withdrawable balance — `available = earned − paid − held − reserved`
- Keep `get_available_balance` reading the `type:"credit"` ledger (`creator_payouts.py:84-148`).
- **Add the missing subtrahend:** on payout *completion* (or, safer, at *request* time as a
  pending debit that finalizes on completion and reverses on failure/cancel), write a
  `type:"debit"` row to `T.billing` `pk=USER#{user_id}`, `sk=LEDGER#...`, `amount_cents<0`
  (mirror the tips reversal `entry_type != "credit"` pattern `tips.py:20-22`,
  `billing_shared.py:16`). `get_available_balance` already nets credits; extend the filter to
  net matured debits so `earned − paid` is intrinsic to the ledger, not derived from live
  payout state. This makes the balance correct even if the payout-state cache drifts.
- Definition of terms: **earned** = Σ matured credits; **paid** = Σ completed-payout debits;
  **held** = credits younger than `payout_hold_period_seconds` (`settings.py:1790`);
  **reserved** = rolling-reserve balance (3.6); **in-flight** = active-payout amounts
  (`_get_active_payout_total`) as today.

### 3.2 Payout methods — routable destinations
- Extend the method record (`record_kind="payout_method"`) to store a **processor token /
  external-account id** alongside the display last-4, never the raw PAN/account (keep the
  SEC-004 last-4-only display contract in `_method_to_dict`). Add types
  `stripe_connect`, `debit_card` to the existing `{bank_ach, bank_wire, paypal, check}`.
- **Stripe Connect** path: store `connect_account_id` + onboarding/capability status; the
  method is "routable" only when the processor returns `payouts_enabled`. **PayPal Payouts**
  path: store verified receiver email + a `verified` flag. Bank ACH (mock rail) keeps last-4
  + a processor bank token. `request_payout` resolves a **routable** default method (reject if
  the chosen method is unverified/not routable).

### 3.3 Withdrawal request — threshold / fee / confirm
- Keep min-threshold + atomic single-active sentinel (`creator_payouts.py:225-378`).
- **Fee:** compute `fee_cents` at request time from config (`payout_fee_flat_cents`,
  `payout_fee_pct_bps`, per-method override e.g. instant vs standard). Persist
  `gross_cents`, `fee_cents`, `net_cents` on the payout record; the **debit ledger row is
  `gross_cents`** (platform keeps the fee), the transfer moves `net_cents`.
- **Confirm** returns gross/fee/net/method/ETA so the app can show a real confirmation.
- Enforce `net_cents >= min` and `gross_cents <= available` **after** claiming the slot.

### 3.4 REAL payout processing on the funds-guarded rail (honest mock-vs-real)
- Introduce `payout_rail.execute_transfer(payout)` mirroring the money-IN mock PaymentIntent
  pattern (`tips.py` "real stripe-mock charge (TIP-101)", `newsfeed.create_payment_intent`
  `newsfeed.py:1035`) but in the *outbound* direction. Behavior:
  - **Mock mode (`payout_use_real_provider=false`, default):** simulate a transfer, generate a
    mock `transfer_id`, and **still write the `type:"debit"` ledger row** so the platform
    balance actually drops. The record is stamped `provider="mock"` — *honest about the fact
    that no external money moved, but the internal ledger is real.*
  - **Real mode (`=true`):** call Stripe Connect `Transfer`/`payouts.create` or PayPal
    Payouts off-session (fold the `bulk_payout_tools.py:341` stub into this one rail), store
    the real `transfer_id`/`batch_id`, and move `processing → completed` on the provider
    webhook, `→ failed`/`returned` on decline/ACH-return.
- **Idempotency:** derive an idempotency key from `payout_id` on both the ledger debit and the
  transfer call; a retried complete must not double-debit or double-transfer (reuse the
  sentinel + a `debit_entry_id` marker on the record, like the tip `TIPREVERSAL#` marker
  `tips.py:22`).

### 3.5 KYC gating — reuse the existing suite, flip enforcement on the payout path
- Add `require_kyc_tier(min_tier)` (`deps.py:412-441`) as a dependency on `request_payout`'s
  router (`creator_payouts.py:59-90`), gated by a **payout-specific** enforcement flag so it
  can be turned on independently of the global `kyc_tier_enforcement_enabled`.
- The gate reads the **real** tier (`kyc_tiers.get_user_kyc_tier`) already fed by the deep
  user-side flow (`kyc_cases.py`) and the B6 admin review — one integrated system, no new KYC
  build. Blocked → structured 403 telling the app which tier/requirement is missing.
- App: wire `PayoutsNavigation.onNavigateToKyc` (`PayoutsNavigation.kt:76-78`) to the existing
  `KycWizardDest.ROUTE` (one-line fix) so a blocked creator can verify in-place.

### 3.6 Holds / rolling reserve
- Keep the flat time hold (`payout_hold_period_seconds`). **Add a rolling reserve:** hold back
  `reserve_pct_bps` of each credit for `reserve_hold_days`, tracked as a `reserved_cents`
  bucket in `get_available_balance` and released on a schedule by the sweeper. Add an
  admin **manual hold / release** on a specific creator or payout (risk/chargeback), stored as
  a hold record that `get_available_balance` subtracts.

### 3.7 Lifecycle + scheduled runner
- Make `processing`/`failed`/`returned` **live**: `request→approved→processing→completed`,
  with `failed`/`returned` reachable from the rail/webhook, plus retry-with-backoff.
- **Scheduled sweeper** `payout_processor.start_payout_processor_task()` registered in
  `main.py` next to `start_subscription_renewal_task` (`main.py:769`), following the
  `subscription_renewal.py` asyncio pattern (`while True … await asyncio.sleep(interval)`
  `subscription_renewal.py:566-593`). It: drains approved payouts → calls the rail → advances
  states, ages holds/reserve, retries `failed`, reconciles provider status.

### 3.8 Tax
- Gate `request_payout` on **W-9 certification** when YTD earnings cross the reporting
  threshold (US creators) using the real `tax_info_w9` record; block or apply **backup
  withholding** (`payout_backup_withholding_bps`, default 2400 = 24%) when TIN is
  missing/uncertified — persist `withheld_cents` on the payout and as a ledger row.
- 1099 generation already reads the credit ledger (`tax_form_1099.py`); ensure payout debits
  don't corrupt the earnings basis (1099 = gross earnings, not net-of-payout).

### 3.9 History / statements + notifications + schedule/limits
- **Export:** creator statement (CSV + PDF) of payouts for a period/tax-year, reusing the
  1099 PDF generator plumbing (`tax_form_1099.py`).
- **Notifications:** register payout event types in `ALERT_EVENT_TYPES` and add to
  `DEFAULT_PUSH_EVENT_TYPES` (`alerts.py:172`) — `payout_requested`, `payout_approved`,
  `payout_paid`, `payout_failed`, `payout_returned` — default-on transactional push, same
  mechanism as `subscription_renewed`/`shop_item_sold`; add FCM category + `testlogon://`
  deep-links in the app.
- **Schedule/limits:** add `payout_max_cents`, per-period velocity cap, and an instant
  (fee) vs standard (free, batched by the sweeper) schedule choice.

---

## 4. EPIC PLAN — dependency-ordered PAY-* tickets

Effort: S ≈ ½-1 d, M ≈ 1-2 d, L ≈ 3-5 d. Backend unless marked (app).
All acceptance criteria are **money-path**: a withdrawal must actually debit the withdrawable
balance, must not over-withdraw, must be KYC-gated, must be idempotent, and must be honest
about mock-vs-real transfer.

### EPIC A — Foundation: accurate balance + a withdrawal that debits (P0)
- **PAY-01 (M) — Debit the balance on payout.** Write a `type:"debit"` ledger row to
  `T.billing` on payout finalization (reuse tips reversal pattern `tips.py:20-22`,
  `billing_shared.py:16`); make `get_available_balance` net matured debits
  (`creator_payouts.py:84-148`). *Dep: none.* **AC:** after a payout completes, `GET /balance`
  `available` drops by `gross_cents` and **stays down**; re-requesting the same amount is
  rejected as insufficient (the double-spend at `creator_payouts.py:530-577` is closed).
- **PAY-02 (S) — Idempotent finalize.** Add `debit_entry_id` marker + `payout_id`-derived
  idempotency key so retried `complete_payout` never double-debits (mirror `TIPREVERSAL#`
  marker `tips.py:22`). *Dep: PAY-01.* **AC:** calling complete twice yields one debit.
- **PAY-03 (S) — Over-withdraw guard hardening.** Re-check `gross <= available` inside the
  sentinel-claimed critical section (`creator_payouts.py:331-333`) against the *ledger-derived*
  balance. *Dep: PAY-01.* **AC:** two sequential requests summing > balance → second rejected.

### EPIC B — Payout methods: routable destinations (P1)
- **PAY-10 (L) — Routable method model.** Add processor-token/external-account fields +
  `stripe_connect`/`debit_card` types to the method record (`creator_payouts.py:369-441`,
  `models.py:2735-2742`); keep last-4-only display (SEC-004). *Dep: EPIC A.* **AC:** a payout
  to an unverified/unroutable method is rejected.
- **PAY-11 (M) — Stripe Connect onboarding (backend).** Create/link Connect account, store
  `payouts_enabled` capability. *Dep: PAY-10.*
- **PAY-12 (M) — PayPal Payouts destination.** Verified receiver email + flag. *Dep: PAY-10.*
- **PAY-13 (M, app) — Payout-destination management UI.** Replace the free-string chips
  (`PayoutSetupScreen.kt:240-243`) with real add/verify/default bank/PayPal/Connect flows.
  *Dep: PAY-10.*

### EPIC C — KYC + tax gating on the money-out path (P0 compliance)
- **PAY-20 (M) — KYC gate on `request_payout`.** Apply `require_kyc_tier` (`deps.py:412-441`)
  to the payout router (`creator_payouts.py:59-90`) behind a payout-specific enforcement flag;
  read real tier (`kyc_tiers.py`). *Dep: EPIC A.* **AC:** below-tier creator gets 403 with the
  missing requirement; no bypass via API.
- **PAY-21 (S, app) — Wire payout→KYC nav.** Fix `PayoutsNavigation.onNavigateToKyc`
  (`PayoutsNavigation.kt:76-78`) to `KycWizardDest.ROUTE`. *Dep: PAY-20.*
- **PAY-22 (M) — W-9 gate + backup withholding.** Block or apply 24% withholding when TIN
  uncertified above threshold (`tax_info_w9.py`); persist `withheld_cents` + ledger row.
  *Dep: PAY-20.*

### EPIC D — Processing + lifecycle + holds + scheduled runner (P0/P1)
- **PAY-30 (L) — The payout rail.** `payout_rail.execute_transfer` — mock mode writes the real
  debit + mock `transfer_id` (honest `provider="mock"`), real mode does Stripe Connect/PayPal
  off-session; fold the `bulk_payout_tools.py:341-342` stub in. *Dep: PAY-01, PAY-10.* **AC:**
  mock payout debits balance + records `provider=mock`; real payout records a provider id;
  record never claims real movement in mock mode.
- **PAY-31 (M) — Live states + retries.** Make `processing`/`failed`/`returned` reachable
  (`creator_payouts.py:24`), add retry/backoff. *Dep: PAY-30.*
- **PAY-32 (M) — Scheduled payout runner.** `start_payout_processor_task` registered in
  `main.py:769` following `subscription_renewal.py:566-593`. *Dep: PAY-30, PAY-31.* **AC:**
  approved payouts drain to completed without an admin click; failures retry.
- **PAY-33 (M) — Provider webhook + reconciler.** Consume Stripe/PayPal payout webhooks →
  advance/settle. *Dep: PAY-30.*
- **PAY-34 (M) — Rolling reserve + manual hold.** `reserve_pct_bps` bucket + admin
  hold/release, subtracted in `get_available_balance`. *Dep: EPIC A.*

### EPIC E — Tax reporting integrity (P2)
- **PAY-40 (S) — 1099 basis correctness.** Ensure payout debits don't corrupt the gross
  earnings basis in `tax_form_1099.py`. *Dep: PAY-01, PAY-22.*

### EPIC F — History, notifications, schedule, app polish (P1/P2)
- **PAY-50 (M) — Notifications.** Register `payout_requested/approved/paid/failed/returned` in
  `ALERT_EVENT_TYPES` + `DEFAULT_PUSH_EVENT_TYPES` (`alerts.py:172`); emit on every transition.
  *Dep: PAY-31.* **AC:** creator gets a push on approve/paid/failed.
- **PAY-51 (S, app) — FCM category + deep-links** for payout lifecycle. *Dep: PAY-50.*
- **PAY-52 (M) — Statement export.** CSV + PDF payout statement (reuse `tax_form_1099.py` PDF
  plumbing). *Dep: EPIC A.*
- **PAY-53 (S) — Schedule/limits.** `payout_max_cents`, per-period velocity, instant-vs-standard.
  *Dep: PAY-30.*
- **PAY-54 (S, app) — Withdraw authorization + Earnings CTA.** Replace `StubBillingAuthorizer`
  (`BillingAuthorizer.kt:54-68`) so release builds can request; add an Earnings→Withdraw CTA
  (`EarningsNavigation.kt:38-44`). *Dep: EPIC A.*

**Ticket count: 24 PAY-* tickets across 6 epics.**

---

## 5. OPEN DECISIONS (user must decide)

1. **Real rail vs honest mock.** Ship the mock-transfer-that-truly-debits-the-balance first
   (`provider="mock"`, internal ledger real), or go straight to real Stripe Connect / PayPal
   Payouts? (Real needs Connect onboarding + platform-balance funding + webhooks.)
2. **Processor choice** for payout destinations: Stripe Connect, PayPal Payouts, raw ACH, or
   all three — and which is the default routable method.
3. **Payout fee** model: flat, %, per-method (free standard vs paid instant), or none — and
   who eats it.
4. **Min / max / schedule:** keep $10 min; set a max-per-payout and per-period velocity cap;
   offer instant vs weekly/monthly batched, or on-demand only.
5. **KYC strictness:** which tier gates payouts, at what dollar threshold, and turn on the
   payout-specific enforcement flag now or later. Vendor SDK (Stripe Identity/Persona/Onfido)
   for on-device capture, or keep admin/backend-advanced tiers.
6. **Hold + reserve:** keep the flat 7-day hold; add a rolling reserve % and for how long;
   allow admin manual holds.
7. **Tax scope:** US-only W-9 + 1099 + 24% backup withholding, or also W-8/international; hard
   block vs withhold when TIN uncertified.
8. **Notifications default-on** for payout lifecycle (recommended, matches subs/ecom) vs opt-in.
