# HTL — Cancellation/no-show policy engine + Hotel KPI reports + tax/currency wiring (gap analysis Tier 3)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §D
("Folios/Taxes/Fees/Add-ons + Payments/Deposits + Refunds/Cancellation + Reviews +
Reports"), Tier 3 cluster "Cancellation/no-show policy engine + Hotel KPI reports +
tax/currency wiring". QloApps ([Qloapps/QloApps](https://github.com/Qloapps/QloApps))
ships a hotel cancellation/no-show policy engine (free-until-N-days + % penalty + no-show
fee), occupancy/ADR/RevPAR KPI reports, and per-booking tax + multi-currency folios —
none of which exist in testlogon today.

These four tickets cover ONLY: (HTL-033) the cancellation/no-show refund computation +
side-effect engine; (HTL-034) the cancellation-policy entity CRUD + reservation cancel/
no-show wiring; (HTL-035) the hotel KPI report service (occupancy %, ADR, RevPAR, revenue,
arrivals/departures) surfaced as RPT-006/PMD-003-style dashlets; (HTL-036) tax +
multi-currency wiring into folio/invoice computation, the cancellation-policy editor +
KPI dashboard frontend, and the hermetic pytest + E2E test suites.

This cluster **consumes** (does not own) the reservation entity + lifecycle (HTL-018
reservation model, HTL-019 lifecycle/state-machine — Tier 2; referenced by id as a forward
dep) and the guest folio (HTL-029 folio entity, HTL-031 folio invoice — Tier 3 folio
cluster; referenced by id). It **reuses** the platform refund mechanism (`refund_payment`
`app/routers/billing.py:1287`; RMA `refund_return` `docs/ofbiz/specs/OFB-010.md`), the
per-date availability release (HTL-011 block/hold/overbooking,
`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`), the report-builder/dashlet framework
(`docs/suitecrm/specs/RPT-006.md` + PMD-003 property KPIs,
`docs/open-property/specs/`), the tax registry specs (`docs/suitecrm/specs/INV-005.md` /
INV-006), and the multi-currency registry specs (`docs/suitecrm/specs/INV-002.md` /
INV-003 / INV-004). Reservation creation (HTL-018/019), front-desk console, booking-engine
storefront, deposit/partial-payment policy, the OTA channel manager (de-scoped), and the
folio entity itself (HTL-029/031) are out of scope here.

## Cross-cutting constraints (apply to every HTL ticket in this cluster)

- **Additive + flag-gated, default OFF.** The whole hotel-PMS vertical is gated by the
  existing master flag `HOTEL_PMS_ENABLED` (default `false`, introduced by HTL-001 at
  `app/core/settings.py` next to the inventory block `:839-841`). Every service entrypoint
  in this cluster goes through `_flag_on()` / `_require_enabled()` raising **404** when off,
  exactly like `app/services/inventory.py:51-58` and `app/routers/inventory.py:32-38`.
  Routers are always mounted; every handler is a 404 no-op until opt-in. With the flag off
  the platform is byte-for-byte unchanged. No new master flag is introduced by this cluster
  (sub-features that depend on currently-unimplemented specs carry their own narrow
  sub-flags — see HTL-036).
- **ONE refund mechanism — never fork.** All cancellation/no-show refunds and fees go
  through the existing billing-ledger primitives used by both `refund_payment`
  (`app/routers/billing.py:1287`, `new_ledger_entry`+`apply_balance_delta`+
  `settle_or_reverse_ledger` at `:1306-1324`) and RMA `refund_return`
  (`docs/ofbiz/specs/OFB-010.md` §4) — exactly one `type="adjustment", reason="refund"`
  ledger entry with a `provider` field for FIN-013 attribution. No parallel hotel refund
  path is minted. The no-show fee is a normal charge/debit ledger entry, not a new payment
  rail.
- **Money-as-cents.** All amounts (`penalty_cents`, `refundable_cents`, `no_show_fee_cents`,
  `room_revenue_cents`, `adr_cents`, `revpar_cents`) are integer cents. Tax bps are integer
  basis points (`docs/suitecrm/specs/INV-005.md`). FX uses `Decimal` `rate_to_usd`
  (`docs/suitecrm/specs/INV-002.md`) and rounds to integer cents at the boundary.
- **Single-table DynamoDB header+child idiom.** Follow the FAC/PROP/HTL header+child
  pattern: a PK + SK=`META` header co-located with `CHILD#{id}` rows on the same partition
  (`docs/ofbiz/specs/FAC-001.md` §3; `docs/open-property/specs/PROP-001.md`; HTL-001). The
  cancellation policy is a `CANCELPOLICY#{policy_id}` child row on the `hotels` partition
  (HTL-034) — no new table. KPI reports are pure aggregation over existing reservation +
  availability GSIs (HTL-035) — no new table.
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key MUST be declared in the
  `TableDef` `attr_types` map (CLAUDE.md DynamoDB numeric-GSI gotcha — omitting it stores
  the value as String → `ValidationException`). Pattern: `scripts/local-ddb-init.py`
  `TableDef(...)` calls (`facilities`/`inventory` style, FAC-001 §3). This cluster adds no
  new tables, so no new `attr_types`.
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor pagination
  (`encode_cursor`/`decode_cursor`, `app/core/cursor.py:94,103`), the `_audit()` lazy-import
  wrapper (`app/services/inventory.py:92-98`), table handles via `T.*`
  (`app/core/tables.py:317-319,569-571`), the billing primitives
  (`new_ledger_entry`/`apply_balance_delta`/`settle_or_reverse_ledger`,
  `app/services/billing_shared.py:224,83,262`).
- **Auth split.** Reads → `require_ui_session` (`app/services/sessions.py:330`); mutations →
  `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical split to
  `app/routers/inventory.py:48,65,81`.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (DynamoDB Local on port 8001 via `DDB_ENDPOINT_URL`
  in dev, real DynamoDB in prod). The billing/refund path is identical dev↔prod
  (OFB-010 §7). Mirrors `inventory.py:27-28`.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`),
  frozen `S` flags toggled via `object.__setattr__`, route coroutines called directly on a
  fresh `asyncio.new_event_loop()` — no `TestClient`, no real AWS / network / Stripe.
  Billing primitives bound to the same moto handles (OFB-010 §9 pattern). Mirrors PROP-005 /
  FAC-001 §9.

---

### HTL-033: Cancellation / no-show policy engine — refund computation + side-effect engine

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Land the pure-computation + side-effect engine in a new service
`app/services/hotel_cancellation.py`. This ticket owns the *math* and the *orchestration*
of cancellation/no-show outcomes; the policy CRUD + reservation-transition wiring lands in
HTL-034. No new DynamoDB table — the engine reads an already-resolved policy dict + an
already-loaded reservation dict (both supplied by the HTL-034 caller) and drives existing
primitives.

A cancellation policy is a dict with the following fields (persisted shape owned by
HTL-034; the engine treats it as input):

| Field | Type | Notes |
|---|---|---|
| `free_until_days_before` | int | Cancellation ≥ this many days before check-in → full refund, zero penalty (default `0` = no free window) |
| `penalty_pct` | int | Penalty as integer percent `[0,100]` of the refundable base, applied inside the penalty window |
| `penalty_fixed_cents` | int | Alternative fixed penalty in cents; when `> 0` it takes precedence over `penalty_pct` |
| `no_show_fee_cents` | int | Charge applied on no-show (default `0`) |

Pure computation:

```python
def compute_cancellation_refund(reservation: dict, policy: dict, now: int | None = None) -> dict:
    """Pure, deterministic. now defaults to now_ts(). No DDB, no side effects.

    base = int(reservation.get("total_cents") or 0)   # the paid/owed room-night base
    check_in_ts = int(reservation["check_in_ts"])
    days_to_checkin = max(0, (check_in_ts - (now or now_ts())) // 86400)

    if days_to_checkin >= policy["free_until_days_before"]:
        penalty = 0
    elif policy.get("penalty_fixed_cents", 0) > 0:
        penalty = min(base, policy["penalty_fixed_cents"])
    else:
        penalty = (base * clamp(policy["penalty_pct"], 0, 100)) // 100

    refundable = max(0, base - penalty)
    return {"base_cents": base, "penalty_cents": penalty,
            "refundable_cents": refundable, "days_to_checkin": days_to_checkin}
    """
```

Side-effect orchestration (idempotent):

```python
def apply_cancellation(reservation: dict, policy: dict, *, actor_sub: str,
                       provider: str = "stripe", now: int | None = None) -> dict:
    """Cancel a reservation: compute refund, release inventory, drive refund.

    1. _require_enabled() (404 when HOTEL_PMS_ENABLED off).
    2. Idempotency guard: if reservation.get("cancellation_ledger_sk") is set, return the
       stored outcome without re-refunding (single-write token, OFB-010 §5 pattern).
    3. quote = compute_cancellation_refund(reservation, policy, now).
    4. Release per-date availability for the stay span via HTL-011 release path
       (hotel_availability.release_hold(... ) for each night in
       [check_in_ts, check_out_ts)) — best-effort try/except (release failure must NOT
       block the refund).
    5. If quote["refundable_cents"] > 0: post EXACTLY ONE refund ledger entry via the
       shared path — new_ledger_entry(key_name="pk", key_value=user_pk(reservation["user_sub"]),
       entry_type="adjustment", amount_cents=refundable, state="settled", reason="refund",
       meta={"reason": "hotel_cancellation", "reservation_id": ...},
       extra={"provider": provider, "reservation_id": ..., "hotel_id": ...}) then
       ddb_put(T.billing, led_item) + apply_balance_delta(T.billing, pk,
       {"payments_settled_cents": -refundable}, currency=reservation.get("currency","usd")).
       If reservation.get("ledger_sk") is present, settle_or_reverse_ledger(... "reversed")
       on the original charge (best-effort, OFB-010 §5 "missing order linkage" pattern).
       This is the same sequence as refund_payment app/routers/billing.py:1306-1324 and
       refund_return OFB-010 §4 — never re-implemented.
    6. _audit("hotel.reservation.cancelled", actor_sub, reservation_id=..., penalty_cents=...,
       refundable_cents=..., provider=provider).
    7. Return {"reservation_id", "penalty_cents", "refundable_cents", "refund_ledger_sk",
       "released_nights": int}.
    """
```

```python
def apply_no_show(reservation: dict, policy: dict, *, actor_sub: str,
                  provider: str = "stripe", now: int | None = None) -> dict:
    """Mark no-show: charge the no_show_fee, no inventory release (the night was held).

    1. _require_enabled().
    2. Idempotency guard: if reservation.get("no_show_ledger_sk") set, return stored outcome.
    3. fee = int(policy.get("no_show_fee_cents", 0)).
    4. If fee > 0: post EXACTLY ONE charge/debit ledger entry via new_ledger_entry(
       entry_type="charge", amount_cents=fee, state="settled", reason="no_show_fee",
       extra={"provider": provider, "reservation_id": ...}) + ddb_put(T.billing, led_item) +
       apply_balance_delta(T.billing, pk, {"payments_settled_cents": +fee}, currency=...).
       (No Stripe SDK call — internal ledger only, OFB-010 §7. A real off-session capture is
       a separate concern behind a future sub-flag, OFB-010 Open-Q #1.)
    5. _audit("hotel.reservation.no_show", actor_sub, reservation_id=..., no_show_fee_cents=fee).
    6. Return {"reservation_id", "no_show_fee_cents", "no_show_ledger_sk"}.
    """
```

The engine does NOT mutate reservation status — that is the FSM transition owned by HTL-019,
driven by the HTL-034 router (which calls the HTL-019 transition AND this engine, then
back-writes `cancellation_ledger_sk`/`no_show_ledger_sk` onto the reservation header). The
engine returns the ledger SK so HTL-034 can persist the idempotency token.

Helpers (copy from `inventory.py`): `_flag_on()` → `bool(getattr(S, "hotel_pms_enabled", False))`,
`_require_enabled()` → 404 (`inventory.py:51-58`), `_audit(...)` lazy-import wrapper
(`inventory.py:92-98`). `user_pk` from `app/services/billing_shared.py` (the `USER#{sub}`
key used by `refund_payment`).

**Acceptance Criteria**
- `compute_cancellation_refund` is pure/deterministic: a cancel `>= free_until_days_before`
  days out returns `penalty_cents=0, refundable_cents=base`; inside the window returns the
  `penalty_pct`-or-`penalty_fixed_cents` penalty and `refundable = base - penalty`.
- `penalty_fixed_cents > 0` takes precedence over `penalty_pct`; penalty is clamped to
  `[0, base]`; `penalty_pct` clamped to `[0,100]`.
- `apply_cancellation` posts **exactly one** `type="adjustment", reason="refund"` billing
  ledger entry with `provider`, decrements `payments_settled_cents` by `refundable_cents`,
  releases the per-date holds for every night in the span, and is idempotent (a second call
  re-using the stored `cancellation_ledger_sk` posts no second ledger row).
- `apply_no_show` posts exactly one `reason="no_show_fee"` charge entry of
  `no_show_fee_cents` (and none when the fee is 0); idempotent on replay.
- Zero `refundable_cents` posts no ledger row (no zero-credit pollution, OFB-010 §5).
- Inventory-release failure and audit failure never abort the refund (best-effort
  try/except).
- No `if S.dev_mode` branch; flag off → every entrypoint 404s.

**Dependencies**: HTL-018/019 (reservation entity + lifecycle — forward dep, reservation
dict shape: `total_cents`, `check_in_ts`, `check_out_ts`, `user_sub`, `currency`,
`ledger_sk`), HTL-011 (per-date availability release path,
`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`). Reuses: `refund_payment`
(`app/routers/billing.py:1287,1306-1324`), `new_ledger_entry`/`apply_balance_delta`/
`settle_or_reverse_ledger`/`user_pk` (`app/services/billing_shared.py:224,83,262`), RMA
refund pattern (`docs/ofbiz/specs/OFB-010.md` §4-§5), `inventory.py:51-58,92-98`
(flag/audit), `now_ts()` (`app/core/time.py:2`).

---

### HTL-034: Cancellation policy CRUD + reservation cancel/no-show router wiring

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Persist the cancellation policy as a per-hotel (default) or per-rate-plan child entity, add
its CRUD, and wire `apply_cancellation`/`apply_no_show` (HTL-033) into the reservation
cancel + no-show router transitions (HTL-019).

**Policy entity** — a `CANCELPOLICY#{policy_id}` child row on the existing `hotels`
partition (HTL-001; no new table, header+child idiom):

| Attribute | Type | Notes |
|---|---|---|
| `hotel_id` | S | PK (same partition as the hotel `META` row) |
| `sk` | S | `CANCELPOLICY#{policy_id}`; `policy_id = "default"` for the per-hotel policy, or `RATE#{rate_plan_id}` to scope to a rate plan (HTL-014) |
| `policy_id` | S | Convenience copy |
| `free_until_days_before` | N | default `0` |
| `penalty_pct` | N | `[0,100]`, default `0` |
| `penalty_fixed_cents` | N | default `0`; precedence over `penalty_pct` when `>0` |
| `no_show_fee_cents` | N | default `0` |
| `created_at` / `updated_at` | N | `now_ts()` |

Single-policy-per-scope: `policy_id` is deterministic (`"default"` or `RATE#{id}`), so a
conditional `put_item` / `update_item` upserts in place — no GSI needed (read via
`Key={hotel_id, sk="CANCELPOLICY#default"}`).

Service additions in `app/services/hotel_cancellation.py`:
- `upsert_cancellation_policy(hotel_id, *, scope="default", free_until_days_before,
  penalty_pct, penalty_fixed_cents, no_show_fee_cents, user_sub) -> dict` — validates parent
  hotel exists + caller owns it (404 if missing), validates `0<=penalty_pct<=100` &
  non-negative cents (422 otherwise), stamps `updated_at`, `_audit("hotel.cancel_policy.upsert", ...)`.
- `get_cancellation_policy(hotel_id, scope="default") -> dict | None` — reads the child row;
  returns `None` (caller falls back to a zero-penalty default policy) if absent.
- `resolve_policy_for_reservation(reservation) -> dict` — resolves `RATE#{rate_plan_id}` if
  the reservation carries one and that scoped policy exists, else the hotel `default`, else
  the implicit zero-penalty default. Used by the cancel/no-show transitions.

**Router** — endpoints added to the existing hotels router family (HTL-003/HTL-008 own the
`/ui/hotels` prefix); declare the literal `/cancellation-policy` sub-route under the hotel,
and the reservation actions under the reservation router (HTL-019). Literal segments are
declared BEFORE dynamic `/{...}` params (KYC `/templates` / audit-export `/schedules`
ordering gotcha, CLAUDE.md):

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/cancellation-policy` | `require_ui_session` | `get_cancellation_policy` (query `scope`, default `default`) |
| PUT | `/ui/hotels/{hotel_id}/cancellation-policy` | `require_admin_or_root_csrf` | `upsert_cancellation_policy` |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/cancel` | `require_admin_or_root_csrf` | HTL-019 `confirmed→cancelled` transition + `apply_cancellation` |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/no-show` | `require_admin_or_root_csrf` | HTL-019 `confirmed→no_show` transition + `apply_no_show` |

**Cancel/no-show wiring** (in the reservation router, HTL-019): the handler (1) loads the
reservation, (2) runs the HTL-019 conditional FSM transition (single-writer
`ConditionExpression`, OFB-010 §5 — the status field is the idempotency token), (3) on a
successful transition (not a replay) resolves the policy via `resolve_policy_for_reservation`
and calls the matching HTL-033 engine function, (4) back-writes the returned
`cancellation_ledger_sk` / `no_show_ledger_sk` onto the reservation header via a best-effort
`update_item`, (5) returns the updated reservation. A replayed transition (status already
terminal) skips the engine entirely — no double refund (idempotency is enforced at BOTH the
FSM layer and the HTL-033 engine's stored-SK guard).

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`). The cancel/no-show handlers pass
`provider = reservation.get("provider", "stripe")` (OFB-010 Open-Q #2) and `actor_sub=user.sub`.

**Acceptance Criteria**
- `upsert_cancellation_policy` rejects (404) a policy under a non-existent/non-owned hotel
  and (422) an out-of-range `penalty_pct` or negative cents; it upserts in place (a second
  call to the same scope overwrites, not duplicates).
- `get_cancellation_policy` returns the per-scope policy or `None`;
  `resolve_policy_for_reservation` prefers the rate-plan-scoped policy over the hotel default
  over the implicit zero-penalty default.
- `POST .../cancel` runs the FSM transition then `apply_cancellation`, persists
  `cancellation_ledger_sk` on the reservation, and is idempotent (replay → terminal status →
  no second refund row).
- `POST .../no-show` runs the FSM transition then `apply_no_show`, persists
  `no_show_ledger_sk`, idempotent on replay.
- Reads accept a UI session; mutations reject non-admin / missing-CSRF (403).
- Flag off → every endpoint 404s; router still mounted (byte-for-byte unchanged platform).

**Dependencies**: HTL-033 (engine), HTL-001 (`hotels` partition + ownership check), HTL-018/019
(reservation entity + FSM transitions — forward dep), HTL-014 (rate-plan id for `RATE#`-scoped
policies — forward dep, optional). Reuses: `app/routers/inventory.py:32-38,48,65,81` (router
idiom), `app/auth/policy.py:100`, `app/services/sessions.py:330`, OFB-010 §5 (single-writer
transition + back-write), CLAUDE.md route-ordering gotcha.

---

### HTL-035: Hotel KPI reports — occupancy / ADR / RevPAR / revenue / arrivals-departures

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add a hotel KPI report service in `app/services/hotel_reports.py` (new) computing the
standard hospitality metrics over a date range, backed by the existing
`hotel_reservations` (HTL-018) + `hotel_availability` (HTL-010) GSIs — pure aggregation, no
new table. Surface the metrics as RPT-006 / PMD-003-style dashlets by REFERENCING the
report-builder/dashlet framework (`docs/suitecrm/specs/RPT-006.md`, property KPIs PMD-003
`docs/open-property/specs/`) — this ticket does NOT re-build the dashlet framework; it
provides a `hotel_kpis` data provider and a single `/reports/kpis` endpoint the frontend
consumes directly (HTL-036), with the dashlet registration as a thin forward-compatible
hook.

KPI definitions (the four hospitality canon metrics + counts):

| Metric | Formula | Notes |
|---|---|---|
| `rooms_available` | sum over [from,to) nights of total bookable rooms (from `hotel_availability` per-date capacity, HTL-010) | denominator for occupancy & RevPAR |
| `rooms_sold` | count of occupied room-nights in [from,to) across all reservations whose nights intersect the range | room-night basis, not reservation count |
| `occupancy_pct` | `rooms_sold / max(rooms_available, 1) * 100` | integer percent (or 1-decimal); never divides by zero |
| `room_revenue_cents` | sum of room-night revenue settled/owed in [from,to) | room revenue only (excludes add-ons/tax — folio-level, HTL-029) |
| `adr_cents` | `room_revenue_cents // max(rooms_sold, 1)` | Average Daily Rate = room revenue / rooms sold |
| `revpar_cents` | `room_revenue_cents // max(rooms_available, 1)` | Revenue Per Available Room; equivalently `adr_cents * occupancy` |
| `arrivals` | count of reservations with `check_in_ts` in [from,to) | front-desk arrivals |
| `departures` | count of reservations with `check_out_ts` in [from,to) | front-desk departures |

Service:

```python
def compute_hotel_kpis(hotel_id: str, *, from_ts: int, to_ts: int) -> dict:
    """_require_enabled() (404 when HOTEL_PMS_ENABLED off).

    Reads reservations for the hotel via the HTL-018 GSI (e.g. GSI_HOTEL_CHECKIN keyed on
    hotel_id / check_in_ts) and the per-date availability rows via the HTL-010 GSI, looping
    on LastEvaluatedKey (DDB FilterExpression doesn't reduce page size, CLAUDE.md gotcha) so
    busy hotels don't silently truncate. Computes the table above. Returns:
      {"hotel_id", "from_ts", "to_ts", "rooms_available", "rooms_sold", "occupancy_pct",
       "room_revenue_cents", "adr_cents", "revpar_cents", "arrivals", "departures",
       "currency"}.
    Pure aggregation over GSIs — no scan, no new table.
    """
```

Cancelled/no-show reservations are excluded from `rooms_sold`/`room_revenue_cents` but
no-show fees are NOT counted as room revenue (they are a penalty, not a room-night sale).
`currency` is the hotel's default currency (carried for the FE; HTL-036 may convert via the
INV-002 FX accessor when multi-currency is on).

Endpoint:

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/reports/kpis?from=&to=` | `require_ui_session` | `compute_hotel_kpis` (404 on unknown hotel; 422 on `to <= from` or range > a sane cap, e.g. 366 days) |

Declared under the hotels router; the literal `/reports/kpis` sub-route is declared before
any dynamic `/{...}` sibling (route-ordering gotcha). The dashlet hook: register a
`hotel_kpis` dashlet `dashlet_type` in the RPT-006 registry (`VALID_DASHLET_TYPES`,
`docs/suitecrm/specs/RPT-006.md` §4.1) whose `config` carries `{hotel_id}` and whose data
provider calls `compute_hotel_kpis` over a configurable `period_days` window — mirroring the
PMD-003 property-KPI dashlet. This is additive to the RPT registry and only active when both
`HOTEL_PMS_ENABLED` and the RPT flag are on; it is a thin reference, not a re-implementation
of RPT-006/RPT-007.

**Acceptance Criteria**
- `compute_hotel_kpis` returns correct ADR (`room_revenue // rooms_sold`), RevPAR
  (`room_revenue // rooms_available`), and occupancy (`rooms_sold / rooms_available * 100`)
  on a seeded fixture; none divides by zero on an empty range.
- `rooms_sold` is a room-night count (a 3-night stay = 3 sold room-nights), not a reservation
  count; cancelled/no-show reservations are excluded.
- `arrivals`/`departures` count reservations by `check_in_ts`/`check_out_ts` falling in
  [from,to).
- All reads go through the HTL-018/HTL-010 GSIs with `LastEvaluatedKey` looping (no scan, no
  page truncation).
- Endpoint 404s an unknown hotel, 422s an inverted/oversized range; flag off → 404.
- A `hotel_kpis` dashlet type is registered in the RPT-006 registry (forward-compatible hook,
  not a framework fork).

**Dependencies**: HTL-018 (reservation entity + GSIs — forward dep), HTL-010 (per-date
availability capacity GSI, `docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`), HTL-033/034
(cancel/no-show status, to exclude cancelled room-nights). Reuses: report-builder/dashlet
framework (`docs/suitecrm/specs/RPT-006.md` §4.1 dashlet registry; PMD-003 property KPIs
`docs/open-property/specs/`), `now_ts()` (`app/core/time.py:2`), `inventory.py:51-58,92-98`
(flag/audit), `app/services/sessions.py:330` / `app/auth/policy.py:100` (auth), CLAUDE.md
FilterExpression-paging + route-ordering gotchas. Contrasts: `platform_financial_dashboard.py`
(GMV/revenue, not hotel ADR/RevPAR).

---

### HTL-036: Tax + multi-currency folio/invoice wiring + frontend + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2.5d

**Description**

Wire tax + multi-currency into the folio/invoice computation, build the cancellation-policy
editor + KPI dashboard frontend, and ship the hermetic pytest + E2E suites for the whole
cluster.

**Tax + currency wiring (consume-or-implement-minimally).** The tax registry
(`docs/suitecrm/specs/INV-005.md` named tax groups + INV-006 per-line tax) and the currency
registry (`docs/suitecrm/specs/INV-002.md` registry + INV-003 FX + INV-004 invoice currency)
are **unimplemented design specs** at the time of this cluster. This ticket therefore
*depends-on, wires-in* their service accessors and explicitly flags the dependency rather
than re-implementing them:

- **Tax**: when computing a folio/invoice total (HTL-029/031), resolve the applicable tax
  via `crm_tax_rates.get_tax_rate(tax_rate_id)` / `get_tax_rate_by_name(name)` (INV-005 §4.1)
  behind the INV-006 sub-flag `AOS_PER_LINE_TAX_ENABLED` AND the INV-005 flag
  `CRM_TAX_RATES_ENABLED`; when either is off OR the accessor raises (registry not enabled /
  not implemented), fall back to the existing flat `S.invoices_tax_bps`
  (`app/core/settings.py:2569`) exactly as `create_invoice` does today
  (`app/services/invoices.py:306`). The wiring is a narrow flag-gated block, never a hard
  dependency on the unbuilt registry (INV-005 §5.7 double-guard pattern).
- **Currency**: when the folio currency differs from the platform default, convert via the
  INV-002/INV-003 FX accessor `crm_currencies.get_exchange_rate(from_iso, to_iso)` (INV-002 §4)
  behind `CRM_CURRENCIES_ENABLED` + the INV-003 conversion sub-flag; when off OR the accessor
  raises, store the folio currency as an opaque string (today's behavior,
  `app/services/invoices.py:334`) with no conversion. Amounts round to integer cents at the
  boundary.

Both wirings live in the folio/invoice computation path owned by HTL-029/031 and are
no-ops with the INV flags off (which is their default) — so this ticket can ship and pass
its tests with the INV registries absent, and lights up automatically when those tickets
land (the `getattr`/`try-except` consume pattern, OFB-010 §5 / INV-005 §5.6-§5.7). The
dependency on the unimplemented INV specs is recorded in §Dependencies below.

**Frontend** (`frontend/src/pages/hotels/`):
- **Types** — add `CancellationPolicy`, `CancellationPolicyIn`, `HotelKpis` (+ the cancel/
  no-show action shapes) to `frontend/src/api/types.ts` (mirror the HTL-034/035 models).
- **API endpoints** — `frontend/src/api/endpoints/hotelReports.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`): `getCancellationPolicy`, `putCancellationPolicy`,
  `cancelReservation`, `markNoShow`, `getHotelKpis`.
- **Pages**:
  - `CancellationPolicyEditor.tsx` — a form (React Hook Form + Zod) for
    `free_until_days_before`, `penalty_pct` / `penalty_fixed_cents` (mutually-exclusive
    toggle), `no_show_fee_cents` (cents↔currency display), wired to `getCancellationPolicy`
    /`putCancellationPolicy`. Surfaced as a tab/section on the existing HotelDetailPage
    (HTL-004) — admin-only edit.
  - `HotelReportsPage.tsx` — KPI dashboard under `/hotels/:hotelId/reports`: a date-range
    picker (from/to) + occupancy/ADR/RevPAR/revenue summary **cards** and recharts charts
    (occupancy over time, ADR/RevPAR bars) reusing the recharts dependency already present
    (`frontend/src/pages/earnings/EarningsPage.tsx:17-19`). Uses React Query `useQuery` on
    `getHotelKpis`. Money cards format cents→currency.
- **Route** — lazy-load `HotelReportsPage` in `frontend/src/App.tsx` (cf. lazy imports):
  `/hotels/:hotelId/reports`.
- **Sidebar** — the existing "Hotels" nav item (HTL-004) covers entry; the KPI dashboard is
  reachable from HotelDetailPage. No new top-level nav item required (add a "Reports" link on
  the hotel detail header).

**Tests**:
- **Hermetic pytest** `tests/test_htl_cancellation_reports.py` — moto-bound `hotels` +
  `hotel_reservations` + `hotel_availability` + `billing` tables on frozen `T`
  (`object.__setattr__`, restored on cleanup), frozen `S` with `hotel_pms_enabled` toggled,
  billing primitives bound to the same moto handles (OFB-010 §9), route coroutines called
  directly on a fresh `asyncio.new_event_loop()` (no `TestClient`). Cover:
  - **Refund tiers by days-to-checkin** — cancel `>= free_until_days_before` out → full
    refund / zero penalty; inside window → `penalty_pct` penalty; `penalty_fixed_cents`
    precedence; penalty clamped to `[0, base]`.
  - **No-show fee** — `apply_no_show` posts exactly one `reason="no_show_fee"` charge of
    `no_show_fee_cents`; zero fee posts nothing.
  - **Idempotency** — second `apply_cancellation` / `apply_no_show` (replay with stored SK)
    posts no second ledger row; single billing entry.
  - **Inventory release** — cancel releases per-date holds for every night in the span
    (HTL-011 release called per night); release failure doesn't abort the refund.
  - **KPI math** — ADR (`room_revenue // rooms_sold`), RevPAR (`room_revenue //
    rooms_available`), occupancy (`rooms_sold / rooms_available * 100`) on a seeded fixture;
    cancelled/no-show excluded from `rooms_sold`; arrivals/departures counts; zero-division
    safety on empty range.
  - **Tax/currency wiring** — with INV flags OFF, folio total uses flat `invoices_tax_bps`
    and opaque currency (fallback path); the INV-accessor consume block is exercised via a
    patched accessor stub to prove the wire-in (no dependency on the unbuilt registry).
  - **Flag-off 404** — every cancel/no-show/policy/KPI entrypoint 404s when
    `hotel_pms_enabled` is False.
- **E2E** `frontend/e2e/hotel-reports.spec.ts` — cookie-auth (`injectAuth`) admin upserts a
  cancellation policy via PUT (CSRF `x-csrf-token`), cancels a seeded reservation and asserts
  the refund outcome + status, marks a no-show and asserts the fee, then loads the KPI
  dashboard and asserts occupancy/ADR/RevPAR cards + charts render. Requires
  `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- Folio/invoice computation resolves tax via the INV-005/006 accessors when their flags are
  on, else falls back to flat `invoices_tax_bps`; currency converts via the INV-002/003 FX
  accessor when on, else stores opaque currency — both flag-gated no-ops by default, with
  zero hard dependency on the unbuilt INV tables.
- `/hotels/:hotelId/reports` renders date-range KPI cards (occupancy/ADR/RevPAR/revenue) +
  charts; the cancellation-policy editor saves and round-trips on HotelDetailPage; money
  displays cents→currency.
- `tests/test_htl_cancellation_reports.py` passes offline (no AWS / Stripe / live stack).
- `frontend/e2e/hotel-reports.spec.ts` passes with the flag on.
- The forward dependency on the unimplemented INV-005/006/002/003/004 specs is documented
  (this ticket consumes-or-implements-minimally and does not block on them).

**Dependencies**: HTL-033 (engine), HTL-034 (policy CRUD + cancel/no-show routes), HTL-035
(KPI service + endpoint) — and transitively HTL-018/019 (reservations), HTL-029/031 (folio/
invoice — forward dep, the tax/currency wire-in target). Reuses: tax specs
`docs/suitecrm/specs/INV-005.md` (`get_tax_rate`/`get_tax_rate_by_name`) + INV-006 (per-line
tax), currency specs `docs/suitecrm/specs/INV-002.md` (`get_exchange_rate`) + INV-003/INV-004
(FX + invoice currency) — **all unimplemented design specs: consumed via flag-gated
accessor blocks with flat-`invoices_tax_bps` / opaque-currency fallback (`app/services/
invoices.py:306,334`, `app/core/settings.py:2569`), never a hard dep**; `frontend/src/api/
client.ts`, `frontend/src/App.tsx` (lazy routes), recharts
(`frontend/src/pages/earnings/EarningsPage.tsx:17-19`), shadcn/ui (`components/ui/`), React
Query + RHF/Zod conventions (CLAUDE.md), hermetic-test + E2E patterns (OFB-010 §9, PROP-005,
CLAUDE.md E2E section).

---

## Dependency order

HTL-033 (cancellation/no-show engine — refund computation + side effects, reusing
`refund_payment`/RMA + HTL-011 release) → HTL-034 (policy entity CRUD + cancel/no-show router
wiring into the HTL-019 FSM) → HTL-035 (hotel KPI report service + `/reports/kpis` endpoint +
RPT-006/PMD-003 dashlet hook) → HTL-036 (tax + multi-currency folio/invoice wire-in +
cancellation-policy editor + KPI dashboard frontend + hermetic pytest + E2E).

Forward dependencies consumed (referenced by id, not owned here): HTL-018/019 (reservation
entity + lifecycle, Tier 2), HTL-029/031 (guest folio + folio invoice, Tier 3 folio cluster),
HTL-011 (per-date availability block/hold/release, `docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`),
and the unimplemented INV-005/006 (tax) + INV-002/003/004 (currency) design specs
(`docs/suitecrm/specs/`).
