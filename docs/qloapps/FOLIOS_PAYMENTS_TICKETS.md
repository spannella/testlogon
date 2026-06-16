# HTL — Guest folios + add-ons + deposit/partial payments (Tier 3)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §D ("Folios/Taxes/Fees/
Add-ons + Payments/Deposits") and the **Tier 3** cluster
(`QLOAPPS_GAP_ANALYSIS.md:150-156`). QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) is an open-source hotel
property-management system; a **guest folio** is the running stay balance for a
reservation — room-nights + ancillary add-ons + taxes/fees on one side, payments
(deposits + partials + balance) on the other, settled at check-out and rendered as
an invoice/PDF.

This cluster (**HTL-029 .. HTL-032**) covers ONLY the folio entity, add-on line
items, deposit/partial-payment policy + folio payment recording, and the router +
frontend + tests. It is the **lowest-net-new** Tier-3 work because every money
movement reuses primitives that already exist:

- **Invoices** — `app/services/invoices.py` (FIN-001): monotonic invoice numbers,
  line items, tax (`tax_cents`/`S.invoices_tax_bps`, `invoices.py:306`), an S3 PDF
  rendered by the dependency-free `_render_pdf`/`_render_invoice_lines`
  (`invoices.py:103,150`), and a **`deposit`** invoice type already in
  `VALID_TYPES` (`invoices.py:33`). The folio PDF is an invoice render.
- **The single-entry ledger + wallet** — `app/services/billing_shared.py`:
  `new_ledger_entry` (`:224`), `apply_wallet_delta` (`:185`), `compute_due` (`:158`),
  `apply_balance_delta` (`:83`), `settle_or_reverse_ledger` (`:262`). Every folio
  payment is a ledger row; **the cluster never forks billing**.
- **The escrow atomic hold** for the advance deposit —
  `docs/ticket-bounty/specs/TBT-001.md` §3 (escrow sentinel row on `T.billing`,
  `pk=BOUNTY#…`/`sk=ESCROW`) + TBT-003's `_escrow_transact_items` →
  `transact_write_items` atomic (wallet debit + escrow put + ledger put,
  `attribute_not_exists(pk)` idempotency guard, TBT-003 §"Atomic transact_write_items").
- **The `record_payment` wrapper pattern** —
  `docs/open-property/specs/RNT-002.md` §4.1 (thin `new_ledger_entry` wrapper that
  records a payment + bumps `payments_settled_cents` via `apply_balance_delta`, no
  online provider).
- **Catalog add-on SKUs** — `app/routers/catalog.py`: `_find_item_by_id`
  (`:702`, O(1) `ByItemId` GSI lookup) + `_catalog_item_out`/`ddb_to_int`
  (`:107,71`) resolve a breakfast/pickup/extra-bed SKU's `price_cents`.

This cluster **consumes the reservation entity HTL-018** (the room-night
reservation: `hotel_id`/`room_type_id`/`check_in`/`check_out`/`occupancy`/
`assigned_rooms`/`total_cents`/`guest_sub`), a **forward dependency** owned by the
Tier-2 reservation-lifecycle cluster (referenced by `reservation_id` only — this
cluster never defines the reservation table). The reservation lifecycle, front-desk
console, cancellation/no-show policy, hotel KPI reports, and tax/multi-currency
wiring are **out of scope here** (separate Tier-2/Tier-3 clusters per the gap
analysis).

---

## Cross-cutting constraints (apply to every HTL-029..032 ticket)

- **Additive + flag-gated, default OFF.** The whole hotel vertical is gated by the
  master flag `S.hotel_pms_enabled` (env `HOTEL_PMS_ENABLED`, default `false`),
  introduced by HTL-001 (`docs/qloapps/HOTELS_AMENITIES_TICKETS.md` §HTL-001,
  `settings.py:130-131`) and shared across **all** HTL clusters. This cluster adds
  **no new master flag** — it reuses `hotel_pms_enabled`. Mirror the inventory
  404-contract: `_flag_on()` / `_require_enabled()` raising **404** when off,
  exactly like `app/services/inventory.py:50-56`. Routers are always mounted; every
  handler is a 404 no-op until opt-in. With the flag off the platform is
  byte-for-byte unchanged and **no folio/ledger/escrow rows are ever written**.
- **Single-table DynamoDB.** New `hotel_folios` table (PK=`reservation_id`,
  SK=`META` for the folio header + `LINE#{line_id}` child rows for line items),
  co-locating a folio and its lines on one partition — the FAC/PROP header+child
  idiom (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002,
  `docs/ofbiz/specs/FAC-001.md` §3). Payment/deposit money rows live on the
  **existing `T.billing`** partition (`pk=USER#{guest_sub}`, `sk=LEDGER#…`) — never
  a new money table (TBT-001 §3.2 rationale).
- **Money-as-cents.** Every monetary attribute is an integer cents
  (`charges_total_cents`, `payments_total_cents`, `balance_due_cents`,
  `amount_cents`, `price_cents`), matching `invoices.py` (`_money`, `:146`) and
  `billing_shared.py`. Decimal→int coercion via a local `_to_int`/`ddb_to_int`
  helper (`inventory.py:67`, `catalog.py:71`).
- **ONE refund/ledger mechanism — never fork billing.** Every payment is a
  `new_ledger_entry` (`billing_shared.py:224`) on `T.billing`; every wallet move is
  `apply_wallet_delta` (`:185`); the deposit hold is the TBT `transact_write_items`
  escrow. No bespoke `put_item` ever constructs a ledger row, and no `delete_item`
  is ever called on one. A refund (out of scope here — cancellation cluster) would
  reuse `refund_payment` (`billing.py:1287`) / `settle_or_reverse_ledger`.
- **Reuse primitives, never re-implement.** `now_ts()` (`app/core/time.py:2`),
  cursor pagination (`app/core/cursor.py:94,103`), the `_audit()` lazy-import
  wrapper (`inventory.py:92-98`), table handles via `T.*` (`tables.py`).
- **Auth split.** Reads → `require_ui_session` (`app/services/sessions.py:330`);
  mutations → `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
  `app/routers/inventory.py:48,65,81` and the PROP-004 router. Hotel staff
  (admin/root) manage folios; the guest reads their own.
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key (`created_at`)
  MUST be declared in the `TableDef` `attr_types` map per the CLAUDE.md DynamoDB
  numeric-GSI gotcha — omitting it stores the value as String →
  `ValidationException`. Pattern: `scripts/local-ddb-init.py:44+` `TableDef(...)`.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business
  logic; the same `T.*` handles, same escrow `transact_write_items`, same S3 PDF
  path in both environments (moto intercepts boto3 in dev, real DynamoDB/S3 in
  prod). The folio PDF reuses the dependency-free `invoices._render_pdf` — no
  `reportlab`/system deps (SECOPS-007 parity, mirrors `receipts.py`).
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via
  `object.__setattr__`), frozen `S` flags toggled via `object.__setattr__`, route
  coroutines called directly on a fresh `asyncio.new_event_loop()` — no
  `TestClient`, no real AWS (escrow `transact_write_items` runs against moto; S3 via
  moto in-process or an in-memory fake).

---

### HTL-029: Guest folio entity — model, table, flag, open/add-line/get/close service

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Land the guest-folio data model, its DynamoDB table, and the core folio service.
A folio is the running stay balance for one reservation: it accumulates line items
(room-nights from HTL-018, add-ons from HTL-030, taxes/fees) and tracks a derived
`balance_due_cents = charges_total_cents - payments_total_cents`. Net-new domain;
the `invoices.py` line-item shape (`invoices.py:218-245`) is the structural model
for a folio line, and the PROP/FAC header+child partition is the storage idiom.

DDB table `hotel_folios` (PK=`reservation_id`, SK=`META` for the folio header;
child `LINE#{line_id}` rows co-located on the same partition — same idiom as
`UNIT#{unit_id}` in `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002):

**Folio header row** (SK=`META`):

| Attribute | Type | Notes |
|---|---|---|
| `reservation_id` | S | PK. The HTL-018 reservation id (forward dep — referenced, not defined here). One folio per reservation. |
| `sk` | S | `META` (folio header) |
| `folio_id` | S | Convenience id `"fol_" + uuid4().hex` |
| `hotel_id` | S | Denormalized from the reservation for scoping/auth (HTL-001 hotel). |
| `guest_sub` | S | The guest's `user_sub` (the `pk=USER#{guest_sub}` billing partition all folio money rows land on). |
| `currency` | S | e.g. `"usd"` (from the reservation; money-as-cents). |
| `status` | S | `open` → `closed` (folio lifecycle; default `open`). |
| `charges_total_cents` | N | Denormalized running sum of all `LINE#` `amount_cents` (maintained on add-line; **also** recomputed authoritatively by `get_folio`). |
| `payments_total_cents` | N | Denormalized running sum of payments recorded against the folio (maintained by HTL-031 `record_payment`). |
| `deposit_held_cents` | N | Amount currently held in escrow (HTL-031; `0` until a deposit is taken). |
| `closed_at` | N | `now_ts()` when closed (absent while open). |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |

**Folio line row** (SK=`LINE#{line_id}`, `line_id = uuid4().hex` — non-deterministic;
a folio may hold many identically-priced lines, e.g. three nights):

| Attribute | Type | Notes |
|---|---|---|
| `reservation_id` | S | PK (same partition as the `META` row) |
| `sk` | S | `LINE#{line_id}` |
| `line_id` | S | Convenience copy of the id |
| `line_type` | S | `room_night` \| `addon` \| `tax` \| `fee` (constrained literal) |
| `description` | S | Human-readable, e.g. `"Deluxe King — 2026-07-04"` or `"Breakfast x2"`. |
| `quantity` | N | Defaults `1`. |
| `unit_price_cents` | N | Per-unit price in cents. |
| `amount_cents` | N | `quantity * unit_price_cents` (computed at add time; the canonical line total). |
| `sku` | S | Catalog `item_id` for `addon` lines (HTL-030; `""` for non-addon lines). |
| `created_at` | N | `now_ts()` |

GSIs (declared in `scripts/local-ddb-init.py`, `attr_types={"created_at": "N"}` —
numeric sort key):
- `GSI_FOLIO_HOTEL` — PK=`hotel_id`, SK=`created_at` — list a hotel's folios
  newest-first (front-desk folio list / HTL-032 read path). Sparse: only the `META`
  row carries `hotel_id`, so `LINE#` rows never pollute the index.

> Note: per-folio line rows stay queryable by the `hotel_folios` PK
> (`Key={"reservation_id": rid}` + `begins_with(sk, "LINE#")`) for the folio detail
> view; the GSI above is the hotel-scoped folio-list fast path.

`TableDef` follows `scripts/local-ddb-init.py:44+` exactly:
```python
TableDef(
    _resolve_table_name(S.hotel_folios_table_name, "hotel_folios"),
    "reservation_id",
    "sk",
    gsi=[
        {"index_name": "GSI_FOLIO_HOTEL", "partition_key": "hotel_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings (add to `app/core/settings.py` next to the HTL block introduced by
HTL-001, same idiom — **no new flag**, only a table name):
```python
hotel_folios_table_name: str = os.environ.get("HOTEL_FOLIOS_TABLE_NAME", "hotel_folios")
```

Table handle: add `hotel_folios: Any` to the `T` dataclass (`app/core/tables.py`,
next to `hotels` from HTL-001) and wire
`hotel_folios=_safe_table(S.hotel_folios_table_name)` in the initializer.

Pydantic models in `app/models.py`: `FolioLineIn` (line_type, description,
quantity, unit_price_cents, sku?), `FolioLineOut` (all persisted line fields),
`FolioOut` (header fields + a computed `balance_due_cents` + the resolved
`line_items: list[FolioLineOut]`). `line_type`/`status` constrained to the literals
above.

Service `app/services/hotel_folios.py` (new), modeled on `app/services/inventory.py`
+ `invoices.py`:
- `_flag_on()` → `bool(getattr(S, "hotel_pms_enabled", False))` (copy
  `inventory.py:50-56`); `_require_enabled()` → 404 when off.
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy `inventory.py:92-98`).
- `_to_int(value, default=0)` Decimal-safe coercion (copy `inventory.py:67`).
- `open_folio(reservation: dict, *, user_sub) -> dict` — derives `folio_id`,
  denormalizes `hotel_id`/`guest_sub`/`currency` from the **HTL-018 reservation
  dict** passed in (this cluster does not read the reservation table directly — the
  HTL-032 router resolves the reservation via the Tier-2 service and passes it),
  writes the `META` row with a conditional `attribute_not_exists(sk)` put →
  **idempotent** on `reservation_id` (a second `open_folio` returns the existing
  folio, never a duplicate). `charges_total_cents`/`payments_total_cents`/
  `deposit_held_cents` start at `0`. Emits `_audit("hotel.folio.opened", ...)`.
- `add_line_item(reservation_id, *, line_type, description, quantity, unit_price_cents, sku="", user_sub) -> dict`
  — validates the folio exists + is `open` (404/409 otherwise); `uuid4().hex`
  `line_id`; computes `amount_cents = quantity * unit_price_cents`; `put_item` the
  `LINE#` row; **atomically** bumps the header `charges_total_cents` via an
  `ADD`-style `if_not_exists`-guarded `update_item` on the `META` row (no read-
  modify-write race); stamps `updated_at`; `_audit("hotel.folio.line_added", ...)`.
  Returns the created line dict.
- `get_folio(reservation_id) -> dict | None` — single partition query
  (`Key={"reservation_id": rid}`), splits `META` + `LINE#` rows, **authoritatively
  recomputes** `charges_total_cents = sum(line.amount_cents)` from the line rows
  (the denormalized header counter is a fast path; `get_folio` is the source of
  truth), and derives `balance_due_cents = charges_total_cents -
  payments_total_cents`. Returns the assembled folio dict (header + `line_items`).
- `close_folio(reservation_id, *, user_sub) -> dict` — guards `status == "open"`
  (conditional `update_item`, idempotent under replay), sets `status="closed"` +
  `closed_at=now_ts()`; **does not** require a zero balance here (a zero-balance
  guard is a HTL-031/cancellation-policy concern — close is an admin action).
  Emits `_audit("hotel.folio.closed", ...)`. Returns the updated folio via
  `get_folio`.

All entrypoints call `_require_enabled()` first.

**Acceptance Criteria**
- `hotel_folios` `TableDef` present with `GSI_FOLIO_HOTEL` and
  `attr_types={"created_at": "N"}`; `just restart` creates the table without
  `ValidationException`.
- `HOTEL_PMS_ENABLED` (existing flag) off → every `hotel_folios` service entrypoint
  raises HTTP 404 via `_require_enabled()`; no rows written.
- `open_folio` is idempotent on `reservation_id`: two calls return the same
  `folio_id` and the second does not error.
- `add_line_item` rejects (404) an unknown folio and (409) a `closed` folio;
  `amount_cents == quantity * unit_price_cents`; header `charges_total_cents` reflects
  the new line.
- `get_folio` returns only this reservation's `META`+`LINE#` rows, recomputes
  `charges_total_cents` from line rows, and returns
  `balance_due_cents = charges_total - payments_total`.
- `close_folio` flips `open → closed` exactly once (idempotent under replay).
- `T.hotel_folios` resolves; `FolioIn/Out/LineIn/LineOut` import cleanly. No
  `if S.dev_mode` branch in `hotel_folios.py` (SECOPS-007).

**Dependencies**: HTL-001 (master flag `hotel_pms_enabled` + HTL settings/`T`
block) — and the HTL-018 reservation entity as a **forward dep** (the reservation
dict is passed into `open_folio`; never read here). Reuses:
`app/services/inventory.py:50-56,67,92-98` (flag/coerce/audit),
`app/services/invoices.py:218-245` (line-item shape),
`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002 (header+child partition),
`scripts/local-ddb-init.py:44+` (`TableDef`), `app/core/time.py:2`,
`app/core/tables.py`.

---

### HTL-030: Add-on / ancillary-service line items (catalog SKU → folio line)

**Type**: Feature
**Priority**: P1
**Estimate**: 1d

**Description**

Add the ability to attach a catalog add-on SKU (breakfast, airport pickup,
extra bed) to a folio as a priced line item — the gap-analysis "service / ancillary
add-ons on a booking" row (`QLOAPPS_GAP_ANALYSIS.md:102`, PARTIAL: catalog provides
products, no "attach add-on to a booking" link). This is a thin layer over HTL-029's
`add_line_item` that resolves the SKU price from the **existing catalog** rather
than trusting a client-supplied price.

No new table, no new model fields — it reuses `hotel_folios` (`LINE#` rows with
`line_type="addon"` and `sku` set) and the catalog item store.

Service addition in `app/services/hotel_folios.py`:
- `add_addon_to_folio(reservation_id, *, sku, quantity=1, user_sub) -> dict`:
  1. `_require_enabled()`.
  2. Resolve the catalog item via `catalog._find_item_by_id(sku)`
     (`app/routers/catalog.py:702`, O(1) `ByItemId` GSI lookup) — 404
     `"Add-on SKU not found"` if absent.
  3. Read `unit_price_cents = ddb_to_int(item["price_cents"])`
     (`catalog.py:71,115`) and `description = item["name"]` — **server-resolved**
     price; the client never supplies the price (anti-tamper; mirrors the
     `unlock_post` PM-validation posture).
  4. Validate `quantity >= 1` (422 otherwise).
  5. Delegate to `add_line_item(reservation_id, line_type="addon",
     description=f"{item['name']} x{quantity}", quantity=quantity,
     unit_price_cents=unit_price_cents, sku=sku, user_sub=user_sub)` — so the
     `amount_cents` math, header `charges_total_cents` bump, open-folio guard, and
     audit all flow through the **single** HTL-029 write path (no duplicated
     ledger/total logic).
  6. Emit `_audit("hotel.folio.addon_added", user_sub, reservation_id=...,
     sku=sku, quantity=quantity, amount_cents=...)`.

> Reuse note: the lazy import of `app.routers.catalog._find_item_by_id` avoids a
> hard module-level dependency (catalog imports nothing from hotel_folios → no
> cycle); a thin local `_resolve_addon(sku) -> (price_cents, name)` wrapper keeps
> the catalog coupling in one place and makes the test patch point obvious.

Pydantic model in `app/models.py`: `FolioAddonIn` (sku: str, quantity: int =
Field(default=1, ge=1)).

**Acceptance Criteria**
- `add_addon_to_folio` resolves `price_cents`/`name` from the catalog via
  `_find_item_by_id` and ignores any client-supplied price.
- An unknown `sku` → 404; `quantity < 1` → 422.
- The created line has `line_type="addon"`, `sku` set, `amount_cents = price_cents *
  quantity`; the folio's `charges_total_cents` increases accordingly (via the shared
  HTL-029 `add_line_item` path — no separate total logic).
- Flag off → 404.
- A second add-on call adds a second line (add-ons are not deduped — each is a
  distinct charge).

**Dependencies**: HTL-029 (folio service + `add_line_item` + table). Reuses:
`app/routers/catalog.py:702` (`_find_item_by_id`), `:71,115` (`ddb_to_int`/
`price_cents`), the `unlock_post` server-side-price posture (CLAUDE.md / MEMORY).
Consumes the catalog add-on SKUs created via the existing
`POST /ui/catalog/.../items` (no new catalog ticket).

---

### HTL-031: Deposit / partial payment policy + folio payment recording + folio PDF

**Type**: Feature
**Priority**: P1
**Estimate**: 2.5d

**Description**

Add the money-movement layer for folios: a **deposit policy** on a reservation, an
**atomic deposit hold**, a **`record_payment` wrapper**, a **balance-due-on-arrival**
derivation, and the **folio PDF**. Every money primitive is reused — **never
forked** (gap analysis: deposit = PLANNED via escrow TBT-001/003; payment = RNT-002
`record_payment` pattern; PDF = FIN-001 invoices).

**(1) Deposit policy** — stored as additive attributes on the **folio `META` row**
(no new table). Set at folio-open time or via a dedicated setter:
- `deposit_policy_kind` ∈ `none` | `pct` | `fixed` (default `none`).
- `deposit_pct_bps` (N, basis points; used when kind=`pct`) — the bps idiom matches
  `ticket_bounty_fee_bps` (TBT-001 §4.1) and `S.invoices_tax_bps`.
- `deposit_fixed_cents` (N; used when kind=`fixed`).
- `compute_deposit_amount(folio) -> int`: `pct` → `charges_total_cents *
  deposit_pct_bps // 10_000`; `fixed` → `deposit_fixed_cents`; `none` → `0`. Pure
  function (mirrors the FIN-001 tax computation `amount * bps // 10_000`,
  `invoices.py:306`).

**(2) Atomic deposit hold** — `take_deposit(reservation_id, *, amount_cents=None,
user_sub) -> dict`:
- `_require_enabled()`; load folio (404 if absent, 409 if `closed`).
- Resolve `amount_cents = amount_cents or compute_deposit_amount(folio)`; reject
  `<= 0` (422) and `> balance_due_cents` (422 — never hold more than owed).
- **Atomic hold via the TBT escrow `transact_write_items` pattern**
  (`docs/ticket-bounty/specs/TBT-001.md` §3, TBT-003 `_escrow_transact_items`):
  one `transact_write_items` (≤ 25 items, well within) doing, atomically:
  1. **Wallet debit** of the guest — the `apply_wallet_delta`-equivalent
     conditional `update_item` on `T.billing` `pk=USER#{guest_sub}`/`sk=WALLET`
     with `ConditionExpression="wallet_balance_cents >= :amt"` (the same
     insufficient-balance guard as `apply_wallet_delta`, `billing_shared.py:203-212`)
     — **insufficient balance → the whole transact fails, nothing is written**.
  2. **Escrow put** — a sentinel row `pk=FOLIO_DEPOSIT#{reservation_id}`,
     `sk=ESCROW`, `status="held"`, `amount_cents`, `currency`, `guest_sub`,
     `created_at`, `ledger_sk`, **with `ConditionExpression="attribute_not_exists(pk)"`
     (idempotency guard — replay-safe; a second `take_deposit` for the same
     reservation fails the condition → already-held)**. Co-located on `T.billing`
     (TBT-001 §3.2 — no new money table). Sparse to `GSI_LEDGER_DATE` (sets no
     `ledger_date`), so it never appears in the platform financial scan.
  3. **Ledger put** — a `new_ledger_entry` (`billing_shared.py:224`)
     `entry_type="hotel_deposit"`, `state="held"`, `amount_cents`,
     `reason=f"Hotel deposit — reservation {reservation_id}"`,
     `extra={"reservation_id": ..., "hotel_id": ..., "provider": "wallet"}` (the
     paired audit row; carries `ledger_date` so it *does* show in the dashboard).
- After the transact succeeds, best-effort bump the folio `META`
  `deposit_held_cents` (+amount) and create a **`deposit`-type invoice** via
  `invoices.create_invoice_safe(invoice_type="deposit", ...)` (the `deposit` type
  already in `VALID_TYPES`, `invoices.py:33`) for the deposit receipt PDF.
- `_audit("hotel.folio.deposit_held", ...)`. Returns the updated folio.

> **Why escrow, not a plain debit:** a deposit is *held*, not yet *earned* — the
> escrow sentinel makes release/refund-at-checkout (a cancellation-cluster concern)
> a `status`-guarded flip (`settle_or_reverse_ledger`, `billing_shared.py:262`),
> exactly the TBT-006/007 model. The cluster picks the escrow option over a bare
> ledger debit because it preserves the held/earned distinction without forking
> billing.

**(3) `record_payment`** — `record_folio_payment(reservation_id, *, amount_cents,
method, reference="", user_sub) -> dict` — the RNT-002 thin wrapper
(`docs/open-property/specs/RNT-002.md` §4.1) over `new_ledger_entry`:
- `_require_enabled()`; load folio (404/409 as above); validate `amount_cents >= 1`
  (422); `method ∈ {wallet, card_external, cash, check, bank_transfer, deposit_applied}`.
- One `new_ledger_entry` (`billing_shared.py:224`) on `pk=USER#{guest_sub}`:
  `entry_type="hotel_payment"`, `state="settled"`, `amount_cents`,
  `reason=f"Hotel payment — reservation {reservation_id}"`,
  `extra={"reservation_id": ..., "hotel_id": ..., "method": method,
  "reference": reference, "provider": "wallet" if method=="wallet" else method}`
  (`provider` per FIN-013/GAP-0203 so the dashboard attributes it).
- For `method == "wallet"`: deduct via `apply_wallet_delta(T.billing,
  user_pk(guest_sub), -amount_cents)` (`billing_shared.py:185`) — the **only**
  wallet write path; raises on insufficient balance. For external/cash/etc. methods
  the ledger row is informational (no wallet move — RNT-002 §5.10 posture).
- Bump folio `META` `payments_total_cents` (+amount) atomically + bump the BALANCE
  counter via `apply_balance_delta(T.billing, user_pk(guest_sub),
  {"payments_settled_cents": amount_cents})` (`billing_shared.py:83`).
- `_audit("hotel.folio.payment_recorded", ...)`. Returns the updated folio (with the
  new `balance_due_cents`).
- **No double-charge / idempotent:** `record_folio_payment` is **not** dedup-keyed
  by design (each call is a distinct payment event, RNT-002 §7.5) — but the
  **wallet deduction is exactly the recorded amount, once**, because there is a
  single `apply_wallet_delta` per call and the conditional guard prevents
  over-deduction. The deposit hold (which *is* idempotent via
  `attribute_not_exists(pk)`) can never be taken twice. A test asserts the wallet
  balance drops by exactly `amount_cents` per call (no double-debit).

**(4) Balance-due-on-arrival** — `balance_due_on_arrival(folio) -> int`: pure
derivation `= charges_total_cents - payments_total_cents - deposit_held_cents`
(the held deposit is credited against the arrival balance even though it is not yet
settled). Surfaced on `FolioOut` as `balance_due_on_arrival_cents`.

**(5) Folio PDF** — `render_folio_pdf(reservation_id) -> bytes | None`: assembles
the folio into the `invoices._render_invoice_lines` record shape (line items →
`line_items`, `charges_total_cents` → `amount_cents`, derived tax →
`tax_cents`, `payments_total_cents`/`balance_due_cents` appended as trailing lines)
and renders via the **dependency-free** `invoices._render_pdf`
(`invoices.py:103,150`) — no new PDF dep (SECOPS-007 parity). Stored/served via the
same S3 path the invoice PDF uses (`invoices._store_pdf`/`download_invoice_pdf`,
`:195,442`). Returns `None` when the flag is off or the folio is absent.

Pydantic models in `app/models.py`: `DepositPolicyIn` (kind, pct_bps?,
fixed_cents?), `TakeDepositIn` (amount_cents?: optional override),
`FolioPaymentIn` (amount_cents, method, reference?). `FolioOut` gains
`deposit_held_cents`, `deposit_policy_kind`, `balance_due_on_arrival_cents`.

**Acceptance Criteria**
- `compute_deposit_amount` returns `0`/`pct`/`fixed` correctly (`pct` =
  `charges_total * bps // 10_000`).
- `take_deposit` debits the guest wallet **and** writes the escrow row **and** the
  paired ledger row **atomically** (`transact_write_items`); insufficient wallet
  balance → nothing written (transact fails); a second `take_deposit` for the same
  reservation → already-held (the `attribute_not_exists(pk)` guard, no double-hold).
- A `deposit`-type invoice is created for the deposit receipt.
- `record_folio_payment` writes exactly one `hotel_payment` ledger row, bumps
  `payments_total_cents` + the BALANCE counter, and (for `method="wallet"`)
  deducts exactly `amount_cents` from the wallet **once** (no double-charge).
- `balance_due_on_arrival_cents = charges - payments - deposit_held`.
- `render_folio_pdf` returns non-empty PDF bytes (valid `%PDF` header) reusing
  `invoices._render_pdf`; flag off / unknown folio → `None`.
- No bespoke ledger `put_item` and no `delete_item` on a ledger row anywhere in the
  path; every money move is `new_ledger_entry` / `apply_wallet_delta` /
  `transact_write_items` (the single mechanism). No `if S.dev_mode` branch.

**Dependencies**: HTL-029 (folio + table), HTL-030 (add-on lines feed
`charges_total`). Reuses: `app/services/billing_shared.py:83,158,185,224,262`
(ledger/wallet/balance), `app/services/invoices.py:33,103,150,195,306,442`
(deposit type, PDF, tax, S3), `docs/ticket-bounty/specs/TBT-001.md` §3 +
TBT-003 `_escrow_transact_items` (atomic hold), `docs/open-property/specs/RNT-002.md`
§4.1 (`record_payment` wrapper), `refund_payment` (`billing.py:1287`, not called
here — cancellation cluster). Consumes the HTL-018 reservation (currency/guest).

---

### HTL-032: Router `/ui/hotels/{hotel_id}/reservations/{rid}/folio` + frontend FolioPanel + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2.5d

**Description**

Expose the folio services over HTTP via a new `hotel_folios_router`, register it in
`app/main.py`, build the FolioPanel frontend inside the reservation detail page, and
add the hermetic backend + E2E tests. Router modeled exactly on
`app/routers/inventory.py` (auth split + `_require_enabled()` short-circuit) and the
PROP-004 plan (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-004).

```python
hotel_folios_router = APIRouter(prefix="/ui/hotels", tags=["hotel-folios"])
```
Every handler calls `hotel_folios._require_enabled()` first (404 when the
`HOTEL_PMS_ENABLED` flag is off). `create_*`/mutation handlers resolve the HTL-018
reservation via the Tier-2 reservation service (forward dep), enforce that the
reservation belongs to `{hotel_id}`, and pass the reservation dict into `open_folio`.

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/reservations/{rid}/folio` | `require_ui_session` | `get_folio` (auto-`open_folio` on first read, or 404 if reservation absent) |
| POST | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/open` | `require_admin_or_root_csrf` | `open_folio` (idempotent) |
| POST | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/lines` | `require_admin_or_root_csrf` | `add_line_item` |
| POST | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/addons` | `require_admin_or_root_csrf` | `add_addon_to_folio` |
| POST | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/deposit` | `require_admin_or_root_csrf` | `take_deposit` |
| POST | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/payments` | `require_admin_or_root_csrf` | `record_folio_payment` |
| POST | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/close` | `require_admin_or_root_csrf` | `close_folio` |
| GET | `/ui/hotels/{hotel_id}/reservations/{rid}/folio/pdf` | `require_ui_session` | `render_folio_pdf` → binary-safe `Response(media_type="application/pdf")` |

> **Declaration order (literal-before-dynamic).** All folio sub-routes are literal
> suffixes (`/open`, `/lines`, `/addons`, `/deposit`, `/payments`, `/close`, `/pdf`)
> under the `/{rid}/folio` prefix, so there is no dynamic-segment capture ambiguity
> *within* the folio routes. The cluster nonetheless declares the bare
> `GET .../folio` route and each literal-suffix route explicitly (no catch-all
> `/{action}` param) — same gotcha discipline as the KYC `/templates`-before-
> `/{case_id}` and audit-export `/schedules`-before-`/{export_id}` ordering
> (CLAUDE.md). The **PDF** route returns a binary-safe `Response(...,
> media_type="application/pdf")`, **NOT** `PlainTextResponse` (which would UTF-8
> re-encode and corrupt the bytes — same lesson as the audit-export PDF download,
> CLAUDE.md GAP-0209).

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py:48,65,81`. Register the router in `app/main.py` next to
the other HTL routers (HTL-001/HTL-018 mounts) — import + `include_router`.

**Frontend** (`frontend/src/`):
- **Types** — add `Folio`, `FolioLine`, `DepositPolicy`, `FolioPayment` and the
  in/update shapes to `frontend/src/api/types.ts` (mirror `app/models.py` folio
  models).
- **API endpoints** — `frontend/src/api/endpoints/hotelFolios.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`): `getFolio`, `openFolio`, `addLine`,
  `addAddon`, `takeDeposit`, `recordPayment`, `closeFolio`, `downloadFolioPdf`.
- **Component** — `FolioPanel.tsx` under `frontend/src/pages/hotels/` (rendered
  **inside the reservation detail page** — the HTL-018/Tier-2 reservation view):
  - a **line-item table** (description, type badge, qty, unit price, amount —
    cents→currency formatted),
  - a **balance summary** (charges total, payments total, deposit held, balance due,
    balance-due-on-arrival),
  - an **add-addon dialog** (React Hook Form + Zod; SKU select + quantity →
    `addAddon`),
  - a **record-payment dialog** (amount + method select → `recordPayment`),
  - a **deposit badge** (shows held deposit; a "Take deposit" action →
    `takeDeposit`),
  - a **download-PDF** button → `downloadFolioPdf` (blob download).
  React Query `useQuery` on `getFolio` + `useMutation` for each action (invalidates
  `["folio", reservationId]` on success). shadcn/ui primitives (`Card`, `Dialog`,
  `Badge`, `Table`, `Button`, `components/ui/`).
- No new top-level route/sidebar entry — FolioPanel mounts inside the existing
  reservation detail page (Tier-2). The panel is rendered unconditionally; the
  endpoints 404 server-side when `HOTEL_PMS_ENABLED` is off.

**Tests**:
- **Hermetic pytest** `tests/test_htl_folios_payments.py` — moto-bound
  `hotel_folios` + `billing` + `shopping_catalog` tables on the **frozen** `T`
  handles (`object.__setattr__(T, "hotel_folios", moto_folios)`, etc., restored in
  teardown), frozen `S` with `hotel_pms_enabled`/`invoices_enabled` toggled via
  `object.__setattr__`, `now_ts` patched for determinism, route coroutines called
  directly on a fresh `asyncio.new_event_loop()` (no `TestClient`). S3 PDF path via
  moto in-process or an in-memory fake `s3_client`. Cover:
  - `open_folio` idempotency + flag-off 404,
  - `add_line_item` (room-night) + `add_addon_to_folio` (catalog SKU price
    resolution; unknown SKU 404),
  - **balance math**: `charges_total` from line rows; `balance_due = charges -
    payments`; `balance_due_on_arrival = charges - payments - deposit_held`,
  - **deposit hold**: atomic `transact_write_items` debits wallet + writes escrow +
    ledger; insufficient balance → nothing written; second `take_deposit` →
    already-held (`attribute_not_exists` guard),
  - `record_folio_payment`: one ledger row + `payments_total` bump + wallet deduct,
  - **no double-charge**: wallet drops by exactly `amount_cents` per payment call,
  - **PDF**: `render_folio_pdf` returns valid `%PDF` bytes,
  - **flag-off 404** on every router handler.
- **E2E** `frontend/e2e/hotel-folios.spec.ts` — cookie-auth (`injectAuth`) admin
  opens a folio on a seeded reservation, adds an add-on, records a payment, asserts
  the line-item table + balance summary + deposit badge render and the PDF downloads;
  `x-csrf-token` header on POSTs. Requires `HOTEL_PMS_ENABLED=1` in the E2E backend
  env (and a seeded HTL-018 reservation).

**Acceptance Criteria**
- All 8 endpoints respond; flag off → every endpoint 404s (handler-level no-op,
  router still mounted, platform byte-for-byte unchanged).
- Read endpoints (`GET .../folio`, `.../folio/pdf`) accept a UI session; mutation
  endpoints reject non-admin / missing-CSRF requests (403) per
  `require_admin_or_root_csrf`.
- The `.../folio/pdf` route serves binary PDF via `Response(media_type=
  "application/pdf")` (not `PlainTextResponse`); bytes are uncorrupted.
- `hotel_folios_router` imported and `include_router`'d in `app/main.py` adjacent to
  the HTL routers.
- FolioPanel renders the line-item table, balance summary, deposit badge,
  add-addon + record-payment dialogs, and the download-PDF button inside the
  reservation detail page; money displays cents→currency formatted.
- `tests/test_htl_folios_payments.py` passes offline (no AWS, no live stack).
- `frontend/e2e/hotel-folios.spec.ts` passes with the flag on.

**Dependencies**: HTL-029, HTL-030, HTL-031 (all folio services) — and the HTL-018
reservation entity + its Tier-2 reservation-detail page (**forward deps**: the
router resolves the reservation; FolioPanel mounts in the reservation view).
Reuses: `app/routers/inventory.py:32-38,48,65,81` (router idiom),
`app/auth/policy.py:100`, `app/services/sessions.py:330`, `app/main.py`
(registration), `app/services/invoices.py` binary PDF `Response` lesson
(CLAUDE.md GAP-0209), `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-004/005
(router + FE + hermetic/E2E test recipe), `frontend/src/api/client.ts`,
shadcn/ui (`components/ui/`).

---

## Dependency order

HTL-029 (folio entity: model + table + flag + open/add-line/get/close service) →
HTL-030 (add-on line items via catalog SKU resolution; extends HTL-029
`add_line_item`) → HTL-031 (deposit policy + atomic escrow hold + `record_payment`
wrapper + balance-due-on-arrival + folio PDF) → HTL-032 (router + `main.py`
registration + FolioPanel frontend + hermetic pytest + E2E).

**Forward deps across clusters:** all four tickets consume the **HTL-018**
reservation entity (Tier-2 reservation-lifecycle cluster) by `reservation_id`
only — the reservation table is never defined here. The master flag
`HOTEL_PMS_ENABLED` + the HTL settings/`T` block come from **HTL-001** (Tier-1
hotel-entity cluster). Catalog add-on SKUs are consumed from the existing catalog
(no new catalog ticket). Refund / release-at-checkout of the held deposit is a
**cancellation/no-show policy** cluster concern (reuses `refund_payment` /
`settle_or_reverse_ledger`), out of scope here.
