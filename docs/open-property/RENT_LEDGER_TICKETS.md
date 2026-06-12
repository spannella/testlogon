# Rent Ledger & Collections — Implementation Tickets (prefix `RNT`)

Source gap analysis: `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §B
("Tenants + Leases + Rent Ledger"). This is the **highest-reuse** cluster in the
property-management vertical (gap analysis Headline: *"Rent ledger & collections
(~80% reuse)"*). The gap matrix marks the rent capabilities as **PARTIAL / HAVE
(primitive)**:
- *"Rent — automated monthly charge per active lease … clone `compute_billing.py`
  rent-run → `new_ledger_entry`"* (row 57)
- *"Rent — period totals (charged/collected/outstanding/overdue) … reuse `compute_due`
  + planned OFB-015 aging"* (row 58)
- *"Rent — record payment (amount/method/date/ref) … thin wrapper over
  `new_ledger_entry`"* (row 59)
- *"Rent — auto status updates on payment … derive from ledger `state` + due_day"* (row 60)
- *"Rent — payment history + void … ledger query + `settle_or_reverse_ledger`"* (row 61)

open-property **deliberately excludes online payment processing** (gap analysis
Headline). Payments are therefore **manually RECORDED** against a lease — this cluster
never touches Stripe/PayPal/CCBill and never moves real money; it writes ledger rows
that *represent* what the landlord recorded as received.

This cluster builds **on top of LSE active leases** (which it iterates) and **PROP/TEN**
(property/tenant FKs carried on each ledger row for scoping). LSE *consumes nothing* from
RNT; RNT *consumes* LSE's `status=active` query surface.

---

## Cross-cutting constraints (apply to every RNT ticket)

1. **Additive + flag-gated, default OFF.** All work is gated behind a new
   `RENT_LEDGER_ENABLED` setting. Follow the **default-OFF negation polarity** used by
   LSE / QUO-004 and by `compute_billing_enabled` (`app/core/settings.py:2385`):
   ```python
   rent_ledger_enabled: bool = os.environ.get("RENT_LEDGER_ENABLED", "0") not in ("0", "false", "False")
   ```
   With the flag off: every new endpoint returns 404, the rent-run background loop does
   not start, and no existing surface changes by a single byte.

2. **MONEY-SAFETY — reuse the single-entry ledger; never fork billing.** Every monetary
   row is written through `new_ledger_entry` (`app/services/billing_shared.py:224`) and
   persisted to `T.billing` (`pk = "USER#{user_sub}"`, `sk = "LEDGER#{ts}#{entry_id}"` —
   `billing_shared.py:220–221`). RNT introduces **two ledger `type` values**: `rent_charge`
   (the monthly rent posting, `state="settled"` — the rent is *owed/recognized*) and
   `rent_payment` (a recorded collection). RNT must **never** compute its own balance
   deltas or write a bespoke deduction path — `new_ledger_entry` + the existing balance
   counters are the only money primitives used. (compute_billing's `_deduct_from_wallet`
   path is explicitly **NOT** reused — that is wallet money for compute; rent is a
   landlord↔tenant ledger, not a platform wallet deduction.)

3. **MONEY-SAFETY — void = reversal, never delete.** A voided rent charge or payment is
   reversed via `settle_or_reverse_ledger(T.billing, "pk", pk, ledger_sk, "reversed")`
   (`app/services/billing_shared.py:262`) — it flips the row's `state` to `"reversed"`,
   leaving the original row intact for audit. **No `delete_item` is ever called on a
   ledger row.** This mirrors the billing-refund path (`app/routers/billing.py:1323–1324`).

4. **MONEY-SAFETY — balance counters via the existing helpers only.** Where RNT updates
   the per-landlord `owed_*` / `payments_*` counters (so `compute_due` works on rent
   totals), it uses `apply_balance_delta` (`app/services/billing_shared.py:83`) — the same
   `if_not_exists`-guarded atomic `ADD` the billing module uses. `compute_due`
   (`billing_shared.py:158`) is read **unmodified** for period outstanding.

5. **No `dev_mode` branch (SECOPS-007 parity).** Services call `T.billing` / `T.leases`
   (boto3 → DDB Local via moto in dev, real DynamoDB in prod — one code path). There is
   **no online charge** to mock, so there is no dev/prod payment divergence at all. No RNT
   service or router contains an `if S.dev_mode:` branch.

6. **`FilterExpression` does not reduce page size** — the rent-run cross-user lease sweep
   and any rent-ledger filter scan must loop on `LastEvaluatedKey` (CLAUDE.md gotcha;
   `compute_billing.py:_scan_all_running_instances` `:507–522` is the canonical loop and
   the clone target).

7. **Idempotency per (lease, period).** The rent-run must post **at most one**
   `rent_charge` per `(lease_id, period)` where `period = "YYYY-MM"`. This is enforced by a
   marker row written under a `ConditionExpression="attribute_not_exists(pk)"` (the same
   conditional-put idempotency pattern used by the cart-recovery consume row and the
   audit-export claim CAS, CLAUDE.md). A re-run of the timer (or a manual trigger) for an
   already-charged period is a silent no-op — never a double charge.

8. **Ownership isolation.** All ledger rows are keyed under `USER#{user_sub}` (the
   landlord). A `lease_id` belonging to another landlord is not in that partition → 404,
   leaking nothing (LSE constraint 7 / QUO-004 §7). The `lease_id`, `property_id`,
   `tenant_id`, `unit_id` are denormalized onto each rent ledger row (via `new_ledger_entry`
   `extra=`/`meta=`) so per-lease queries and the period summary can scope without joins.

9. **Reuse, never fork.** Primitives reused verbatim (all verified present):
   | Primitive | Location | Used for |
   |---|---|---|
   | `new_ledger_entry(key_name, key_value, entry_type, amount_cents, state, reason, meta=, extra=)` | `billing_shared.py:224` | every `rent_charge` / `rent_payment` row |
   | `settle_or_reverse_ledger(table, key_name, key_value, ledger_sk, new_state)` | `billing_shared.py:262` | void (→ `"reversed"`) |
   | `compute_due(balance_item)` | `billing_shared.py:158` | period outstanding totals |
   | `apply_balance_delta(table, pk, delta, currency=)` | `billing_shared.py:83` | bump `owed_*` / `payments_*` counters |
   | `user_pk(user_id)` / `ledger_sk(ts, entry_id)` / `ddb_query_pk` | `billing_shared.py:23`, `:220`, `:43` | keys + per-landlord ledger scan |
   | `run_compute_billing_timer` / `start_compute_billing_timer_task` (`asyncio.ensure_future`, gated) | `compute_billing.py:653`, `:669` | rent-run background loop |
   | `_scan_all_running_instances` `LastEvaluatedKey` loop | `compute_billing.py:507` | cross-user active-lease sweep |
   | `encode_cursor` / `decode_cursor` | `app/core/cursor.py:94`, `:103` | payment-history pagination |
   | `audit_event(event, user_sub, request=None, **fields)` | `app/services/alerts.py:644` | every charge/payment/void event |
   | `list_leases(status="active")` / `admin_list_leases` (GSI2/GSI1) | `app/services/leases.py` (LSE-002) | the active-lease iteration source |
   | OFB-015 `compute_ar_aging(user_sub=, as_of_ts=)` | `app/services/ar_subledger.py` (planned) | overdue/aging running totals in the period summary |
   | `GET /billing/ledger` per-user scan + sort | `app/routers/billing.py:2448–2454` | model for the per-lease rent-ledger query |

10. **DynamoDB numeric GSI sort keys MUST declare `attr_types={...: "N"}`** in any new
    `TableDef`, or DynamoDB stores them as strings → `ValidationException` at query time
    (CLAUDE.md gotcha; LSE constraint 4).

---

### RNT-001: Rent-run background timer — monthly `rent_charge` per active lease (idempotent per lease+period)

**Type:** Feature
**Priority:** P1
**Estimate:** 3 d

**Description**

The automated monthly charge engine. A background timer iterates **active leases** and
posts exactly one `rent_charge` ledger row per `(lease, period)`, cloning the
`compute_billing.py` rent-run shape (gap matrix §B row 57: *"clone `compute_billing.py`
rent-run → `new_ledger_entry`"*). This is the rent-domain analogue of
`_tick_all_running_resources` (`compute_billing.py:616`), but instead of per-minute wallet
deduction it posts a **monthly rent recognition** through the ledger.

**Feature flag & settings** (`app/core/settings.py`, default-OFF polarity per constraint 1):
```python
rent_ledger_enabled: bool = os.environ.get("RENT_LEDGER_ENABLED", "0") not in ("0", "false", "False")
# Background rent-run sub-flag (default OFF even when the cluster is on, so the
# automatic charge engine is opt-in — mirrors LEASES_RENEWAL_NOTIFICATIONS_ENABLED).
rent_run_enabled: bool = os.environ.get("RENT_RUN_ENABLED", "0") not in ("0", "false", "False")
rent_run_poll_interval: int = int(os.environ.get("RENT_RUN_POLL_INTERVAL", "3600"))  # seconds
```
`.env.local.example`: `RENT_LEDGER_ENABLED=0`, `RENT_RUN_ENABLED=0`.

**DDB — no new table.** Rent rows live in the existing `T.billing` table (constraint 2).
Two row kinds are introduced:
- **Rent ledger rows** via `new_ledger_entry` — `pk="USER#{user_sub}"`,
  `sk="LEDGER#{ts}#{entry_id}"`, `type="rent_charge"`, `state="settled"`,
  `amount_cents=monthly_rent_cents`, `reason=f"Rent {period} — lease {lease_number}"`,
  and `extra={"lease_id", "property_id", "unit_id", "tenant_id", "period", "rent_kind": "charge", "currency"}` so per-lease/period scoping needs no join (constraint 8).
- **Idempotency marker row** (constraint 7): `pk="RENT_PERIOD#{user_sub}"`,
  `sk="LEASE#{lease_id}#PERIOD#{period}"`, written with
  `ConditionExpression="attribute_not_exists(pk)"`. A `ConditionalCheckFailedException`
  means this lease was already charged for this period → skip (no second `rent_charge`).
  The marker stores `{ledger_sk, charged_at, amount_cents}` for traceability.

**Service `app/services/rent_ledger.py`** (every public fn short-circuits on
`if not S.rent_ledger_enabled: return None`):
- `_current_period() -> str` — `datetime.now(timezone.utc).strftime("%Y-%m")` (clone of
  `compute_billing._current_month_key`, `compute_billing.py:54`).
- `post_rent_charge(user_sub, lease, *, period=None) -> dict | None` — the single-lease
  charge primitive:
  1. `period = period or _current_period()`.
  2. Claim the idempotency marker (`put_item` + `attribute_not_exists(pk)`); on
     `ConditionalCheckFailedException` return `{"skipped": True, "reason": "already_charged"}`.
  3. `sk, item = new_ledger_entry(key_name="pk", key_value=user_pk(user_sub),
     entry_type="rent_charge", amount_cents=int(lease["monthly_rent_cents"]),
     state="settled", reason=..., extra={... per above ...})` then `ddb_put(T.billing, item)`.
  4. `apply_balance_delta(T.billing, user_pk(user_sub), {"owed_settled_cents": amount},
     currency=lease.get("currency","usd"))` (constraint 4 — so `compute_due` reflects rent
     owed). Back-write `ledger_sk` onto the marker row.
  5. `audit_event("rent.charge_posted", user_sub, lease_id=..., period=..., amount_cents=..., ledger_sk=...)`.
  Returns the created ledger entry dict (or the skip sentinel).
- `_scan_active_leases() -> list[dict]` — cross-user active-lease sweep, the
  `compute_billing.py:507–522` `LastEvaluatedKey` loop cloned against LSE's **GSI1**
  (`Key("GSI1PK").eq("LEASES#ALL")`, `FilterExpression=Attr("status").eq("active")`),
  looping until `LastEvaluatedKey` is exhausted (constraint 6). Skips leases whose
  `rent_due_day` has not yet occurred in the current period only if a "charge on due day"
  policy is desired; **default policy: charge once at the start of the period** (post on the
  first run of the calendar month), so a mid-month deploy still bills the month exactly once
  thanks to the idempotency marker.
- `run_rent_charges(*, period=None) -> int` — enumerate `_scan_active_leases()`, call
  `post_rent_charge` for each, count non-skipped postings (clone of
  `_tick_all_running_resources`, `compute_billing.py:616`). Logs
  `rent_run period=%s charged=%d skipped=%d`.
- `run_rent_run_loop(*, poll_interval=None)` + `start_rent_run_task()` — exact clone of
  `compute_billing.py:653`/`:669` (`asyncio.ensure_future`, gated on
  `S.rent_ledger_enabled and S.rent_run_enabled`), registered via
  `app.add_event_handler("startup", start_rent_run_task)` in `app/main.py` alongside the
  existing `start_compute_billing_timer_task` hook (`app/main.py:302` import pattern).

**Acceptance Criteria**
- With `RENT_LEDGER_ENABLED=0` every rent_ledger service fn returns `None`; the loop never
  starts; `T.billing` is untouched.
- `post_rent_charge` writes exactly one `type="rent_charge"`, `state="settled"` ledger row
  with the lease/property/tenant/period denormalized in `extra`, and bumps
  `owed_settled_cents` by `monthly_rent_cents`.
- Calling `post_rent_charge` (or `run_rent_charges`) twice for the same `(lease, period)`
  posts **one** charge total — the second call returns the `already_charged` skip sentinel
  via the conditional-put marker; no duplicate ledger row exists.
- `run_rent_charges` posts one charge per active lease across multiple landlords (GSI1
  sweep loops past a 1MB page boundary) and ignores `upcoming`/`ended` leases.
- The rent-run loop starts only when **both** `RENT_LEDGER_ENABLED` and `RENT_RUN_ENABLED`
  are `1`; reuses `new_ledger_entry` / `apply_balance_delta` (no bespoke money math); no
  `if S.dev_mode` branch.

**Dependencies**
- **LSE** (active-lease entity + `status=active` GSI1/GSI2 query surface — RNT-001 iterates
  it; `monthly_rent_cents`, `rent_due_day`, `currency` come from the lease item).
- **PROP / TEN** — `property_id` / `unit_id` / `tenant_id` carried opaquely from the lease
  onto each ledger row.
- Reuses `billing_shared` + `compute_billing` timer patterns (constraint 9).

---

### RNT-002: Record-payment service + charge-status derivation (open/paid/partial/overdue)

**Type:** Feature
**Priority:** P1
**Estimate:** 2 d

**Description**

The manual-collection primitive (open-property **excludes online processing** — payments
are *recorded*, gap analysis Headline; gap matrix §B row 59: *"thin wrapper over
`new_ledger_entry`"*) plus the per-charge status derivation (row 60: *"derive from ledger
`state` + due_day"*). No provider SDK is ever touched.

**Service additions (`app/services/rent_ledger.py`):**
- `record_payment(user_sub, *, lease_id, amount_cents, method, paid_on=None, reference="", period=None, notes="") -> dict | None` —
  the thin `new_ledger_entry` wrapper:
  1. `get_lease(user_sub, lease_id)` (LSE-001) first → 404 if not owned (constraint 8).
  2. `amount_cents` validated `> 0`.
  3. `sk, item = new_ledger_entry(key_name="pk", key_value=user_pk(user_sub),
     entry_type="rent_payment", amount_cents=amount_cents, state="settled",
     reason=f"Rent payment — lease {lease_number}",
     extra={"lease_id", "property_id", "tenant_id", "unit_id", "period", "rent_kind": "payment",
            "method", "reference", "paid_on": paid_on or now_ts(), "currency"},
     meta={"notes": notes})` then `ddb_put(T.billing, item)`. `method` is a free enum
     (`cash | check | bank_transfer | card_external | other`) — informational only, **never**
     an instruction to charge anything.
  4. `apply_balance_delta(T.billing, user_pk(user_sub), {"payments_settled_cents": amount_cents}, currency=...)`
     (constraint 4 — so `compute_due` nets payments against rent owed).
  5. `audit_event("rent.payment_recorded", user_sub, lease_id=..., amount_cents=..., method=..., reference=..., ledger_sk=...)`.
  Returns the created ledger entry dict.
- `derive_charge_status(charge_row, *, payments, lease, as_of_ts=None) -> str` — pure,
  deterministic status from ledger state + lease `rent_due_day` + grace (gap matrix row 60):
  - `"reversed"` → status `"voided"` (the charge was voided, RNT-003).
  - Sum the **settled, non-reversed** `rent_payment` rows allocated to this charge's
    `period` (allocation = same `(lease_id, period)`); compare to the charge `amount_cents`:
    - paid_total `>=` amount → `"paid"`.
    - `0 < paid_total < amount` → `"partial"`.
    - `paid_total == 0` → either `"open"` or `"overdue"`: compute the charge's **due
      timestamp** = the `rent_due_day` of the charge's `period` month + `late_fee_grace_days`
      (both off the lease, mirroring LSE-001's `rent_due_day` `1–28` / `late_fee_grace_days`
      fields); if `as_of_ts (default now_ts()) > due_ts_plus_grace` → `"overdue"`, else `"open"`.
  - `rent_due_day` clamped to the month length (lease already constrains `1–28`, so no
    short-month gap — LSE-001 note).
- `list_rent_ledger_for_lease(user_sub, lease_id) -> list[dict]` — per-lease rent rows: scan
  the landlord partition (`ddb_query_pk(T.billing, user_pk(user_sub))`, the
  `GET /billing/ledger` model at `billing.py:2451`), filter
  `sk.startswith("LEDGER#") and extra.lease_id == lease_id and rent_kind in {"charge","payment"}`,
  sort by `ts` desc. (Used by RNT-002's status join and RNT-004/RNT-005.)

**Pydantic models** (`app/models.py`, additive): `RentPaymentIn`
(`amount_cents ge=1`, `method`, `paid_on` optional, `reference`, `period`, `notes`),
`RentLedgerRowOut` (ledger fields + `rent_kind`, `period`, derived `status` for charge rows,
`method`/`reference` for payment rows), `RentChargeStatusOut`.

**Router `app/routers/rent_ledger.py`**, prefix `/ui/rent`, registered in `app/main.py`
near the billing/leases routers. Every handler begins with the flag-guard:
```python
if not S.rent_ledger_enabled:
    raise HTTPException(status_code=404, detail="rent ledger not enabled")
```
- `POST /ui/rent/leases/{lease_id}/payments` → `record_payment` (`require_ui_session`,
  CSRF on this non-GET cookie request per CLAUDE.md). Returns the created row + recomputed
  charge status for the period.
- `GET  /ui/rent/leases/{lease_id}/charges` → per-period charges each annotated with
  `derive_charge_status` (joins `list_rent_ledger_for_lease`).

**Acceptance Criteria**
- `record_payment` writes one `type="rent_payment"`, `state="settled"` row carrying
  `method`/`reference`/`paid_on`/`period` in `extra`, bumps `payments_settled_cents`, and
  **never** calls a payment provider.
- `derive_charge_status` returns `paid` when payments ≥ charge, `partial` for a smaller
  payment, `open` before due-day+grace with no payment, `overdue` after, and `voided` for a
  reversed charge — deterministic for a fixed `as_of_ts`.
- The overdue boundary respects the lease `rent_due_day` + `late_fee_grace_days`; a payment
  recorded before the boundary flips the status to `paid`/`partial`.
- `record_payment` 404s for a `lease_id` owned by another landlord; endpoints 404 when
  `RENT_LEDGER_ENABLED=0`.
- No bespoke balance math — only `new_ledger_entry` + `apply_balance_delta`.

**Dependencies**
- **RNT-001** (the `rent_charge` rows + `extra` shape this status derivation reads).
- **LSE** (`get_lease`, `rent_due_day`, `late_fee_grace_days`, `currency`).

---

### RNT-003: Payment & charge history + void via `settle_or_reverse_ledger`

**Type:** Feature
**Priority:** P1
**Estimate:** 2 d

**Description**

The per-lease rent-row listing and the **void** operation (gap matrix §B row 61: *"ledger
query + `settle_or_reverse_ledger`"*). MONEY-SAFETY: a void is a **reversal, never a
delete** (constraint 3) — the original ledger row is preserved and its `state` flipped to
`"reversed"`, exactly as the billing refund path does (`billing.py:1323–1324`).

**Service additions (`app/services/rent_ledger.py`):**
- `list_rent_history(user_sub, lease_id, *, kind=None, limit=50, cursor=None) -> dict` —
  paginated per-lease rent ledger (charges + payments), newest-first. Built on
  `list_rent_ledger_for_lease` (RNT-002) with optional `kind` filter
  (`charge | payment`); pages via `encode_cursor`/`decode_cursor`
  (`app/core/cursor.py:94`,`:103`) over the sorted row list (offset-style cursor carrying
  the last `sk`, mirroring the billing list cap of `min(limit, 200)` at `billing.py:2454`).
  Returns `{"rows":[...], "count":int, "next_cursor":str|None}`. Each charge row is
  annotated with `derive_charge_status` (RNT-002).
- `void_rent_row(user_sub, lease_id, ledger_sk, *, reason="") -> dict | None` — the void
  primitive:
  1. `get_lease(user_sub, lease_id)` ownership check → 404; fetch the target row
     (`ddb_get(T.billing, user_pk(user_sub), ledger_sk)`) → 404 if absent or its
     `extra.lease_id` ≠ `lease_id` (constraint 8) or `rent_kind` not in
     `{"charge","payment"}`.
  2. If the row is already `state="reversed"` → 409 `already_voided` (idempotent guard; no
     second reversal, no double balance adjustment).
  3. `settle_or_reverse_ledger(T.billing, "pk", user_pk(user_sub), ledger_sk, "reversed")`
     (`billing_shared.py:262`) — **the only mutation; no `delete_item`** (constraint 3).
  4. **Reverse the balance counter** so `compute_due` stays correct: a voided `rent_charge`
     applies `apply_balance_delta({"owed_settled_cents": -amount})`; a voided `rent_payment`
     applies `apply_balance_delta({"payments_settled_cents": -amount})` (constraint 4 — the
     inverse of the original delta).
  5. If the voided row is a `rent_charge`, **release the idempotency marker** so a corrected
     charge can be re-posted for that period: delete `RENT_PERIOD#{user_sub}` /
     `LEASE#{lease_id}#PERIOD#{period}` (constraint 7 — the marker, not the ledger row, is
     the only deletable artifact, and only on charge-void).
  6. `audit_event("rent.row_voided", user_sub, lease_id=..., ledger_sk=..., rent_kind=..., amount_cents=..., reason=...)`.
  Returns `{"ok": True, "ledger_sk": ..., "state": "reversed"}`.

**Router (`app/routers/rent_ledger.py`):**
- `GET  /ui/rent/leases/{lease_id}/ledger?kind=&limit=&cursor=` → `list_rent_history`
  (`limit` `Query(ge=1, le=200)`).
- `POST /ui/rent/leases/{lease_id}/ledger/{ledger_sk}/void` (`{"reason": "..."}`) →
  `void_rent_row` (`require_ui_session` + CSRF). Surfaces 409 `already_voided` /
  404 not-found as JSON errors.

**Acceptance Criteria**
- `list_rent_history` returns a lease's charges + payments newest-first, filters by `kind`,
  and paginates via an HMAC-signed cursor with no overlap/omission across pages.
- `void_rent_row` flips the target row's `state` to `"reversed"` **without deleting it**
  (the row is still present in `list_rent_history` flagged `voided`), and reverses the
  matching balance counter so `compute_due` returns the pre-charge/pre-payment outstanding.
- Voiding a `rent_charge` releases its period idempotency marker, allowing a corrected
  charge to be posted for that period; voiding a `rent_payment` does **not** touch any
  marker.
- A second void of the same row → 409 `already_voided` (no double balance reversal); a row
  from another lease/landlord → 404.
- No `delete_item` is ever called on a `LEDGER#` row; endpoints 404 when
  `RENT_LEDGER_ENABLED=0`.

**Dependencies**
- **RNT-001** (charges + markers), **RNT-002** (`derive_charge_status`,
  `list_rent_ledger_for_lease`, `record_payment` balance deltas to invert).
- Reuses `settle_or_reverse_ledger` + `apply_balance_delta` + cursor helpers (constraint 9).

---

### RNT-004: Period summary — charged/collected/outstanding/overdue running totals + period navigation

**Type:** Feature
**Priority:** P2
**Estimate:** 2 d

**Description**

The portfolio-facing rollup (gap matrix §B row 58: *"period totals
(charged/collected/outstanding/overdue) … reuse `compute_due` + planned OFB-015 aging"*).
Reuses **`compute_due`** (`billing_shared.py:158`) for the net-outstanding and the planned
**OFB-015 AR-aging engine** (`docs/ofbiz/specs/OFB-015.md` — `compute_ar_aging`) for the
overdue/aging buckets. Supports period navigation (prev/next month).

**Service additions (`app/services/rent_ledger.py`):**
- `period_summary(user_sub, *, period=None, lease_id=None) -> dict | None` — for a
  `period="YYYY-MM"` (default current), scoped to one lease or all of the landlord's leases:
  - **Charged** = Σ `amount_cents` of non-reversed `rent_charge` rows whose `extra.period`
    matches (from `list_rent_ledger_for_lease` over the scope, or a period-filtered partition
    scan when `lease_id` is None — looping on `LastEvaluatedKey`, constraint 6).
  - **Collected** = Σ `amount_cents` of non-reversed `rent_payment` rows for the period.
  - **Outstanding** = `charged - collected` for the period **and** a cross-check against
    `compute_due(balance_item)` (`billing_shared.py:158`): the landlord-level
    `due_settled_cents` is surfaced as `due_settled_cents_all_time` for reconciliation
    (rent charges/payments both post `*_settled_*` counters, so `compute_due` nets them).
  - **Overdue** = when OFB-015 is available (`S.ar_ap_subledgers_enabled`), call
    `compute_ar_aging(user_sub=user_sub, as_of_ts=now_ts())` and surface
    `days_30/60/90_plus` aging buckets; **graceful fallback** when OFB-015 is absent/off:
    overdue = Σ charges in this/earlier periods whose `derive_charge_status` (RNT-002) is
    `"overdue"`, wrapped in `try/except` so a missing OFB-015 never errors the summary
    (OFB-015 §10 Q1 graceful-absence precedent).
  - Returns `{"period", "scope": lease_id|"all", "charged_cents", "collected_cents",
    "outstanding_cents", "overdue_cents", "aging": {...}|None, "charge_count", "paid_count",
    "lease_count"}`.
- `list_periods(user_sub, *, lease_id=None, count=12) -> list[str]` — the period-navigation
  helper: the trailing `count` `"YYYY-MM"` strings ending at the current month (pure date
  math; no DDB). The FE uses it to drive prev/next without scanning.

**Pydantic models** (`app/models.py`, additive): `RentPeriodSummaryOut`
(the fields above; `aging` is an optional nested `RentAgingOut` mirroring OFB-015's
`AgingOut` shape so the two reconcile).

**Router (`app/routers/rent_ledger.py`):**
- `GET /ui/rent/summary?period=&lease_id=` → `period_summary` (omit `lease_id` for the
  whole-portfolio rollup). `period` defaults to current month; arbitrary past periods
  supported for navigation.
- `GET /ui/rent/periods?lease_id=&count=` → `list_periods`.

**Acceptance Criteria**
- `period_summary` returns `charged = Σ rent_charge`, `collected = Σ rent_payment`,
  `outstanding = charged − collected` for the requested period, excluding `reversed` rows.
- A recorded payment increases `collected_cents` and decreases `outstanding_cents`; a void
  reverses both (consistency with RNT-003).
- `overdue_cents`/`aging` is populated from `compute_ar_aging` when OFB-015 is enabled, and
  falls back to the `derive_charge_status=="overdue"` sum (never raising) when OFB-015 is
  absent/off.
- `outstanding_cents` for the all-leases scope reconciles with `compute_due`'s
  `due_settled_cents` (rent-only counters); period navigation via `list_periods` yields the
  trailing N months and the summary recomputes per selected period.
- Endpoints 404 when `RENT_LEDGER_ENABLED=0`.

**Dependencies**
- **RNT-001/002/003** (charges, payments, void, `derive_charge_status`).
- **`compute_due`** (`billing_shared.py:158`, unmodified) + **OFB-015** AR-aging
  (`compute_ar_aging`, soft dependency — graceful fallback when off, OFB-015 §10 Q1).
- **LSE** (`lease_count` / per-lease scope).

---

### RNT-005: Manual rent-run trigger + per-lease charge-now (admin/landlord on-demand posting)

**Type:** Feature
**Priority:** P2
**Estimate:** 1 d

**Description**

On-demand counterparts to the RNT-001 background timer so a landlord can post rent without
waiting for the loop (and admins can backfill a period). This is the rent analogue of the
manual `POST /ui/remote/billing/tick` endpoint that sits alongside the
`compute_billing` timer (`compute_billing.py:495` comment). All postings go through the
**same idempotent `post_rent_charge`** (constraint 7) — the manual path can never produce a
duplicate the loop wouldn't.

**Service additions (`app/services/rent_ledger.py`):**
- `charge_lease_now(user_sub, lease_id, *, period=None) -> dict | None` — `get_lease`
  ownership check → 404; requires `lease["status"] == "active"` (else 409
  `lease_not_active`); delegates to `post_rent_charge(user_sub, lease, period=period)`.
  Returns the created row or the `already_charged` skip sentinel.
- `run_rent_charges_for_owner(user_sub, *, period=None) -> int` — landlord-scoped variant of
  `run_rent_charges`: iterate the owner's `active` leases via LSE `list_leases(status="active")`
  (GSI2, single-partition — no cross-user scan) and `post_rent_charge` each.

**Router (`app/routers/rent_ledger.py`):**
- `POST /ui/rent/leases/{lease_id}/charge` (`{"period": "YYYY-MM"?}`) → `charge_lease_now`
  (`require_ui_session` + CSRF).
- `POST /ui/rent/run` (`{"period": "YYYY-MM"?}`) → `run_rent_charges_for_owner` for the
  caller's leases (`require_ui_session`).
- `POST /ui/admin/rent/run` (`{"period": "YYYY-MM"?}`) → system-wide `run_rent_charges`
  (`Depends(require_root_session)`, OFB-015 §4.3 root-only precedent) — the manual trigger
  for the cross-user sweep.

**Acceptance Criteria**
- `charge_lease_now` posts one `rent_charge` for an active lease, returns the
  `already_charged` sentinel on a repeat call for the same period (shares RNT-001's marker),
  and 409s for an `upcoming`/`ended` lease.
- `POST /ui/rent/run` charges only the caller's active leases (single-partition GSI2, no
  cross-user leak); `POST /ui/admin/rent/run` runs the system-wide sweep and is 403 for a
  non-root session.
- A manual charge for a period the timer already billed is a no-op (single idempotency
  marker shared by both paths); endpoints 404 when `RENT_LEDGER_ENABLED=0`.

**Dependencies**
- **RNT-001** (`post_rent_charge`, marker, `run_rent_charges`), **LSE** (`get_lease`,
  `list_leases(status="active")`).

---

### RNT-006: Frontend rent-ledger page (charges, record-payment, void, period navigation) + tests

**Type:** Feature
**Priority:** P2
**Estimate:** 3 d

**Description**

The React surface for rent collections, following repo frontend conventions (CLAUDE.md
"Frontend conventions": React Query for server state, axios via `api/client.ts`, shadcn/ui,
React Hook Form + Zod) plus the hermetic-pytest + Playwright E2E test suite for the whole
RNT cluster.

**API layer:**
- `frontend/src/api/types.ts` — `RentLedgerRow`, `RentPaymentInput`, `RentChargeStatus`,
  `RentPeriodSummary`, `RentAging` (mirror the RNT-002/003/004 Pydantic models).
- `frontend/src/api/endpoints/rent.ts` — wrappers: `recordPayment(leaseId, body)`,
  `listLeaseCharges(leaseId)`, `listRentLedger(leaseId, {kind?, cursor?})`,
  `voidRentRow(leaseId, ledgerSk, reason)`, `getRentSummary({period?, leaseId?})`,
  `listRentPeriods({leaseId?, count?})`, `chargeLeaseNow(leaseId, period?)`,
  `runRentForOwner(period?)`.

**Pages/components** (`frontend/src/pages/rent/`):
- **`RentLedgerPage.tsx`** — a **period navigator** (prev/next month via `listRentPeriods`)
  with a portfolio **summary bar** (charged / collected / outstanding / overdue from
  `getRentSummary`) and a per-lease rent table: lease, tenant/unit, period charge, paid,
  status badge (`open | partial | paid | overdue | voided` from `derive_charge_status`),
  next-due day. Cursor pagination via `useInfiniteQuery` over `next_cursor`.
- **Record-payment dialog** — React Hook Form + Zod (`amount_cents`, `method` select,
  `paid_on` date, `reference`, `notes`) → `recordPayment`, invalidating
  `["rent","ledger",leaseId]` + `["rent","summary"]`. (No payment-method/card selector —
  payments are *recorded*, not charged; constraint 2 / gap analysis Headline.)
- **Void control** — a confirm dialog on a charge/payment row → `voidRentRow`, surfacing the
  409 `already_voided` as a toast; the voided row stays visible flagged `voided` (constraint 3).
- **Charge-now / run** — a per-lease "Charge rent" action (`chargeLeaseNow`) and a
  landlord-level "Run rent for this period" button (`runRentForOwner`), each toasting the
  `already_charged` skip outcome rather than erroring.

**Routing:** add `/rent` (lazy-loaded) to `frontend/src/App.tsx`, behind the same flag
awareness used by other gated pages (degrades to a "not enabled" state on a 404).

**Tests:**
- **Pytest** `tests/test_rent_ledger.py` (hermetic/offline, the
  `tests/test_gap_0223_0224_*` pattern: moto in-memory `billing` + `leases` tables bound to
  the frozen `T.billing`/`T.leases` via `object.__setattr__`, `now_ts` patched, frozen `S`
  flags flipped via `object.__setattr__`, route handlers called directly — no real
  AWS/network): rent-run idempotency (single charge per lease+period), record-payment +
  balance delta, `derive_charge_status` boundary table (open/partial/paid/overdue/voided),
  void = reversal-not-delete + balance inversion + marker release, period-summary
  charged/collected/outstanding (+ OFB-015 aging on, graceful fallback off), manual
  charge-now / owner-run / admin-run authz, and the `RENT_LEDGER_ENABLED=0` flag-off
  404/None guards.
- **E2E** `frontend/e2e/rent-ledger.spec.ts` (`injectAuth(page, "alice")` + `x-csrf-token`
  header per CLAUDE.md; root via `e2e_admin_session_setup.py`): sections for (1) record-payment
  API + status flip, (2) charge-now idempotency, (3) void → row flagged voided + summary
  reverses, (4) period summary + navigation, (5) admin run authz (403 for user / 200 for
  root), (6) flag-off 404 guard, (7) RentLedgerPage UI: summary bar, record-payment dialog,
  void confirm, status badges.

**Acceptance Criteria**
- RentLedgerPage renders the period navigator + summary bar (charged/collected/outstanding/
  overdue) and the per-lease rent table with correct status badges; period navigation
  refetches the summary and ledger.
- The record-payment dialog posts a payment (no card/payment-method selector), refetches,
  and flips the charge status to `paid`/`partial`; the void control reverses a row (stays
  visible flagged `voided`) and updates the summary.
- Charge-now / run actions toast the `already_charged` skip outcome on a repeat instead of
  erroring.
- `tests/test_rent_ledger.py` passes hermetically (no AWS); `rent-ledger.spec.ts` passes for
  record-payment + status flip, idempotency, void, period summary/navigation, admin-run
  authz, flag-off 404, and the UI surfaces.

**Dependencies**
- **RNT-002** (record-payment, charge status), **RNT-003** (history + void), **RNT-004**
  (period summary + navigation), **RNT-005** (charge-now / run).
- **LSE** frontend (lease/tenant context for the rent table); **PROP/TEN** for the
  unit/tenant labels — degrade to plain ids if those surfaces aren't yet available.

---

## Dependency order (build sequence)

```
RNT-001  (rent-run timer: monthly rent_charge per active lease, idempotent per lease+period)   ← depends on LSE, PROP, TEN
   └─ RNT-002  (record-payment wrapper + charge-status derivation)
         ├─ RNT-003  (payment/charge history + void via settle_or_reverse_ledger)
         │     └─ RNT-004  (period summary: charged/collected/outstanding/overdue + navigation)   → reuses compute_due + OFB-015 aging
         │           └─ RNT-005  (manual rent-run trigger + per-lease charge-now)
         │                 └─ RNT-006  (frontend rent-ledger page + pytest + E2E)
```

**External (hard):** **LSE** (active-lease entity + `status=active` GSI query surface the
rent-run iterates; `monthly_rent_cents` / `rent_due_day` / `late_fee_grace_days` / `currency`
fields), **PROP** (property/unit FKs), **TEN** (tenant FK). **External (soft):** **OFB-015**
AR-aging (`compute_ar_aging`) for the overdue/aging buckets in RNT-004 — graceful fallback
when off. **MONEY-SAFETY core:** every monetary row goes through
`billing_shared.new_ledger_entry`; void is `settle_or_reverse_ledger` (reversal, never
delete); balance counters via `apply_balance_delta`; `compute_due` read unmodified — RNT
never forks billing and never touches an online payment provider (open-property records
payments, it does not process them).

ticket_count: 6
