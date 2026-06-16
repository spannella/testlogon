# HTL — Stay-search engine + Reservation entity + lifecycle (Hotel PMS, Tier 2)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` — the QloApps hotel-PMS
vertical ([Qloapps/QloApps](https://github.com/Qloapps/QloApps)). This file owns the
**Stay-search engine + Reservation entity + lifecycle** cluster (gap analysis Tier 2,
"Booking + reservations + front desk" — the `stay-search` and `reservation entity +
lifecycle` rows, §C). It covers tickets **HTL-017 .. HTL-021**.

A **reservation** is a genuinely net-new entity: a multi-night room-night booking
(hotel + room type + check-in→check-out span + occupancy + assigned physical rooms +
total). It does not exist anywhere in code — the closest *patterns* (not entities) are
the OFBiz **ORD** order-lifecycle state machine (statuses + append-only history +
version-gated conditional `update_item`, `docs/ofbiz/specs/ORD-001.md` §3.1–3.3,
`docs/ofbiz/specs/ORD-005.md` §4.1.6) and the open-property **LSE** lease date-range +
state-machine pattern (`docs/open-property/specs/LSE-001.md` §3–4). We clone those
patterns; we do NOT reuse their tables (an order is a cart total; a lease is a tenancy —
neither is a room-night reservation).

This cluster is the **consumer** of two forward-deps in sibling cluster files:
- **HTL-012** `check_availability(hotel_id, room_type_id, checkin, checkout, rooms_needed)`
  — the per-date availability intersection across a span
  (`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`, HTL-012).
- **HTL-011** `hold_rooms(...)` / `release_hold(...)` — the date-keyed atomic room hold
  (`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`, HTL-011).
- **HTL-015** `compute_stay_price(hotel_id, room_type_id, checkin, checkout, adults,
  children, rooms, advance_days=None) -> StayPriceResult` — the deterministic multi-night
  price engine (`docs/qloapps/RATE_PLANS_TICKETS.md`, HTL-015).

Stay-search (HTL-017) intersects HTL-012 availability with the HTL-015 price engine, per
the gap analysis line "available room types + summed multi-night price"
(`docs/qloapps/QLOAPPS_GAP_ANALYSIS.md:87,138`). All three forward-deps are referenced by
id; this cluster never re-implements them.

Out of scope here (separate clusters): the front-desk console (arrivals/departures/in-house
queries, room-move), the booking-engine public storefront, guest folios, deposits, and the
cancellation/no-show **refund** policy engine — **HTL-033** owns the refund/penalty
machinery (forward ref; this cluster only *releases held inventory* on cancel/no-show and
records the state transition, never issuing a refund).

---

## Cross-cutting constraints (apply to every HTL ticket in this file)

- **Additive + flag-gated, default OFF.** The master flag `HOTEL_PMS_ENABLED`
  (`S.hotel_pms_enabled`, env `HOTEL_PMS_ENABLED`, default `false`) — already landed in the
  HTL-001 hotels cluster (`docs/qloapps/HOTELS_AMENITIES_TICKETS.md`) — gates the entire
  vertical. Every service entrypoint and router handler short-circuits via the
  `INVENTORY_RESERVATIONS_ENABLED` 404 contract: `_flag_on()` → `bool(getattr(S,
  "hotel_pms_enabled", False))` and `_require_enabled()` raising **HTTP 404** when off,
  copied verbatim from `app/services/inventory.py:51-58`. Routers are always mounted; every
  handler is a 404 no-op until opt-in. With the flag off the platform is byte-for-byte
  unchanged.
- **Single-table DynamoDB.** One `hotel_reservations` table (PK=`reservation_id`,
  SK=`META` for the reservation header; SK=`HIST#{ts:020d}#{event_id}` for append-only
  status-history rows) co-locating a reservation and its history on one partition — the
  ORD `ORDER`/`HIST#` header+child idiom (`docs/ofbiz/specs/ORD-001.md` §3.2).
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key MUST be declared in the
  `TableDef` `attr_types` map, per the CLAUDE.md DynamoDB numeric-GSI gotcha — omitting it
  stores the value as String → `ValidationException` at query time. Pattern:
  `scripts/local-ddb-init.py` `TableDef(...)` calls (cf. ORD-001 §3.4 numeric SK example,
  LSE-001 §3.4).
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor pagination
  (`encode_cursor`/`decode_cursor`, `app/core/cursor.py:94,103`), `_audit()` lazy-import
  wrapper (`app/services/inventory.py:92-98`), table handles via `T.*`. State transitions
  use a **version-gated conditional `update_item`** — the ORD `ConditionExpression`
  optimistic-concurrency pattern (`docs/ofbiz/specs/ORD-005.md` §4.1.6, modeled on
  `app/services/kyc_cases.py:228` `version = :expected_version`), bumping `version` on each
  transition (a `version` field, unlike LSE which CASes on `status`).
- **Auth split.** Reads → `require_ui_session` (`app/services/sessions.py:330`); mutations
  → `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical split to
  `app/routers/inventory.py:48,65,81`.
- **Guests reuse the person model.** `guest_party_id` is an opaque FK to an existing person
  — Contacts (`app/routers/contacts.py`) / OBP `CUS` customer / open-property `TEN` tenant.
  This cluster does NOT re-model a guest/person; `guest_party_id` is stored as an opaque
  string with no FK validation (the QUO-004 / LSE-001 §5.6 opaque-string precedent).
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). The forward-dep HTL-011/012/015 services already own any mock/real divergence
  internally — this cluster calls them identically in both envs.
- **No money fork.** This cluster issues no Stripe/PayPal/CCBill call and writes no ledger
  entry. Cancel/no-show releases held inventory only; refunds + penalties are HTL-033
  (forward ref), which must route through `refund_payment` (`app/routers/billing.py:1287`)
  / `settle_or_reverse_ledger` — never a parallel mechanism (ORD-001 §5.6 invariant).
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`,
  restored on cleanup), frozen `S` flags, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` — no `TestClient`, no real AWS (mirrors LSE-001 §9,
  ORD-005 §9, CLAUDE.md).

---

### HTL-017: Stay-search engine — service (read-only, no booking)

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add the **stay-search engine**: the function the gap analysis flags as the core net-new
booking primitive — "date-range + occupancy → available room types (per-date availability
intersection across span) + summed multi-night/occupancy price"
(`docs/qloapps/QLOAPPS_GAP_ANALYSIS.md:138`, §C "Stay-search engine"). This ticket is
**read-only**: it answers "which room types can I book for this stay, and what does each
cost" — it does NOT hold inventory or create a reservation (that is HTL-018).

Service `app/services/hotel_reservations.py` (new — the home of HTL-017..HTL-019 logic).
`_require_enabled()` first on every entrypoint (copy `inventory.py:54-58`).

```python
def search_stays(
    *,
    hotel_id: str | None = None,
    city: str | None = None,        # one of hotel_id | city is required (else 422)
    checkin: str,                   # "YYYY-MM-DD" (inclusive — first night)
    checkout: str,                  # "YYYY-MM-DD" (exclusive — departure day, not a night)
    adults: int,
    children: int = 0,
    rooms: int = 1,
) -> StaySearchResult:
    """Read-only stay search. Pure composition over HTL-012 + HTL-015 — no DDB writes."""
```

Flow:
1. `_require_enabled()`.
2. Validate the span: nights = count of dates in `[checkin, checkout)`; `checkout` must be
   strictly after `checkin` (≥ 1 night) else `HTTPException(422, "checkout must be after
   checkin")`. Validate `adults >= 1`, `children >= 0`, `rooms >= 1`.
3. Resolve the candidate hotels + their room types:
   - If `hotel_id` is given → that one hotel's room types via the HTL-005 room-type lister
     (`hotel_pms.list_room_types(hotel_id)`, `docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md`,
     forward ref) — opaque call.
   - If `city` is given → resolve hotels in that city via the HTL-001 hotels lister
     (`hotel_pms.list_hotels(city=...)`, `docs/qloapps/HOTELS_AMENITIES_TICKETS.md`,
     forward ref), then their room types. Both `hotel_id` and `city` absent → 422.
4. For EACH candidate room type, compose the two forward-deps:
   - **availability** → `check_availability(hotel_id, room_type_id, checkin, checkout,
     rooms_needed=rooms)` (HTL-012). Skip the room type when `result["available"]` is
     `False` (some night of the span is sold out — the intersection-across-the-span check,
     the distinction the OFBiz scalar counter cannot express, gap analysis §B).
   - **price** → `compute_stay_price(hotel_id, room_type_id, checkin, checkout, adults,
     children, rooms)` (HTL-015). On a LOS `HTTPException(422 "stay too short/long")` from
     the price engine, that room type is excluded (caught + skipped, not propagated — a
     room type with an incompatible min/max-nights rule is simply not a search result),
     but the call NEVER mutates state.
5. Build a `StayRoomTypeResult` per surviving room type:
   `{hotel_id, room_type_id, name, available: True, min_remaining, rooms,
   per_night: [...from compute_stay_price...], total_cents, currency, applied_rule_ids}`.
6. Sort results by `total_cents` ascending (cheapest first; deterministic tiebreak by
   `room_type_id`). Return `StaySearchResult{checkin, checkout, nights, adults, children,
   rooms, results: [StayRoomTypeResult...], result_count}`.

Pure composition: no DDB writes, no `hold_rooms`, no holds. `search_stays` is the function
HTL-020's `/ui/hotel-search` endpoint wraps and HTL-021's results page renders.

Pydantic/dataclass models in `app/models.py`: `StaySearchIn` (`hotel_id?`, `city?`,
`checkin`, `checkout`, `adults`, `children`, `rooms`), `StayRoomTypeResult`,
`StaySearchResult`. `per_night` reuses the HTL-015 `NightLineOut` shape
(`docs/qloapps/RATE_PLANS_TICKETS.md` HTL-015).

**Acceptance Criteria**
- `search_stays` returns only room types whose `check_availability(...)["available"]` is
  `True` for the FULL span (a room type sold out on any single night is excluded).
- Each result's `total_cents`/`per_night` equals the HTL-015 `compute_stay_price(...)`
  output for the same inputs (search does not re-compute price independently — it composes).
- Results are sorted cheapest-first; `result_count == len(results)`.
- A LOS-rule rejection from `compute_stay_price` excludes that room type without erroring
  the whole search; a room type with no rate plan still prices off `base_nightly_rate_cents`
  (HTL-015 contract).
- `hotel_id` and `city` both absent → 422; `checkout <= checkin` → 422.
- `search_stays` performs zero DDB writes (read-only) — no `hold_rooms`, no `put_item`.
- Flag off → `search_stays` 404s via `_require_enabled()`.

**Dependencies**: HTL-012 `check_availability` (availability intersection, forward ref —
`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`), HTL-015 `compute_stay_price` (price
engine, forward ref — `docs/qloapps/RATE_PLANS_TICKETS.md`), HTL-005 `list_room_types` +
HTL-001 `list_hotels` (forward refs — `docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md`,
`docs/qloapps/HOTELS_AMENITIES_TICKETS.md`). Reuses: `_require_enabled()`
(`app/services/inventory.py:54-58`), `now_ts()` (`app/core/time.py:2`). Contrasts: the
OFBiz cart total is a naive line-item sum with no span (gap analysis §B,
`docs/qloapps/QLOAPPS_GAP_ANALYSIS.md:60`).

---

### HTL-018: Reservation entity — model, table, `create_reservation`

**Type**: Feature
**Priority**: P0
**Estimate**: 2.5d

**Description**

Land the **Reservation** data model, its DynamoDB table, and `create_reservation` — the
foundational net-new entity (gap analysis §C row 1, MISSING). The reservation header is the
ORD `ORDER`-SK header analogue (`docs/ofbiz/specs/ORD-001.md` §3.2) carrying a `version`
field for the ORD optimistic-concurrency state machine (HTL-019) and a check-in→check-out
date span (the LSE date-range idea, `docs/open-property/specs/LSE-001.md` §3.2 — adapted to
`YYYY-MM-DD` date strings to match the HTL availability/price date convention).

DDB table `hotel_reservations` (PK=`reservation_id`, SK=`META` for the header; child
`HIST#{ts:020d}#{event_id}` rows added by HTL-019, co-located on the same partition — the
ORD header+history idiom, `docs/ofbiz/specs/ORD-001.md` §3.2):

| Attribute | Type | Notes |
|---|---|---|
| `reservation_id` | S | PK. `"res_" + uuid4().hex[:16]` (non-deterministic — a guest may book the same span twice; mirrors LSE `lease_id` and the FAC `create_location` non-determinism, contrast the ORD deterministic sha256 id which is keyed on a cart correlation that does not apply to a fresh booking) |
| `sk` | S | `META` (reservation header) |
| `hotel_id` | S | Owning hotel (FK → HTL-001 hotel, opaque) |
| `guest_party_id` | S | Opaque FK → Contacts / OBP `CUS` / open-property `TEN` (the person; NOT re-modeled here — see cross-cutting) |
| `room_type_id` | S | FK → HTL-005 room type (opaque) |
| `assigned_room_ids` | L | List of physical room ids (HTL-006 rooms); empty `[]` until check-in assigns them (HTL-019) |
| `checkin` | S | `"YYYY-MM-DD"` (inclusive — first night) |
| `checkout` | S | `"YYYY-MM-DD"` (exclusive — departure day, not a billable night) |
| `nights` | N | Count of dates in `[checkin, checkout)` (denormalized for display/reports) |
| `adults` | N | `ge=1` |
| `children` | N | `ge=0`, default 0 |
| `rooms` | N | `ge=1`, default 1 — number of rooms of this type held |
| `total_cents` | N | From `compute_stay_price(...).total_cents` (HTL-015) at create time |
| `deposit_cents` | N | Required-deposit amount in cents; default 0 (deposit *policy* + actual hold is HTL-033/Tier-3 — this field is informational here) |
| `currency` | S | ISO 4217 lowercase; from the price result; default `"usd"` |
| `status` | S | Lifecycle status (HTL-019): `confirmed` \| `checked_in` \| `checked_out` \| `cancelled` \| `no_show` (initial = `confirmed`) |
| `hold_id` | S | The HTL-011 `hold_id` returned by `hold_rooms` (so cancel/no-show can `release_hold`) |
| `version` | N | Optimistic-concurrency counter; `1` at create, `+1` on each transition (ORD/KYC `version = :expected_version` CAS) |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |

GSIs (declared in `scripts/local-ddb-init.py`; numeric SKs in `attr_types`):
- `GSI_HOTEL_ARRIVALS` — PK=`hotel_id`, SK=`checkin` (S, `YYYY-MM-DD`) — the arrivals board
  (a hotel's reservations by check-in date; the front-desk-console data source, separate
  cluster, but the index lands here). No `attr_types` (string SK).
- `GSI_GUEST` — PK=`guest_party_id`, SK=`created_at` (N) — a guest's booking history
  newest-first. `attr_types={"created_at": "N"}`.
- `GSI_HOTEL_STATUS` — PK=`hotel_id`, SK=`status` (S) — a hotel's reservations bucketed by
  lifecycle status (in-house / confirmed / departed). No `attr_types` (string SK).

`TableDef` follows the LSE-001 §3.4 / ORD-001 §3.4 shape:
```python
TableDef(
    _resolve_table_name(S.hotel_reservations_table_name, "hotel_reservations"),
    "reservation_id",
    "sk",
    gsi=[
        {"index_name": "GSI_HOTEL_ARRIVALS", "partition_key": "hotel_id",       "sort_key": "checkin"},
        {"index_name": "GSI_GUEST",          "partition_key": "guest_party_id", "sort_key": "created_at"},
        {"index_name": "GSI_HOTEL_STATUS",   "partition_key": "hotel_id",       "sort_key": "status"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings (add next to the existing hotel block from HTL-001, same idiom):
```python
hotel_reservations_table_name: str = os.environ.get("HOTEL_RESERVATIONS_TABLE_NAME", "hotel_reservations")
```
(`hotel_pms_enabled` already exists from HTL-001 — `docs/qloapps/HOTELS_AMENITIES_TICKETS.md`.)

Table handle: add `hotel_reservations: Any` to the `T` dataclass and wire
`hotel_reservations=_safe_table(S.hotel_reservations_table_name)` in the initializer
(cf. LSE-001 §3.6, `app/core/tables.py`).

Service `create_reservation` in `app/services/hotel_reservations.py`:
```python
def create_reservation(
    *,
    hotel_id: str,
    guest_party_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    adults: int,
    children: int = 0,
    rooms: int = 1,
    deposit_cents: int = 0,
    user_sub: str,
) -> dict:
```
1. `_require_enabled()`.
2. Validate the span (nights ≥ 1; `checkout > checkin`) — same as HTL-017.
3. **Re-check availability** at book time: `check_availability(hotel_id, room_type_id,
   checkin, checkout, rooms_needed=rooms)` (HTL-012); if `not available` → `HTTPException(409,
   detail={"code": "no_availability"})` (a search result can go stale between search and
   book — the binding check is here, not in HTL-017).
4. **Compute price**: `compute_stay_price(hotel_id, room_type_id, checkin, checkout, adults,
   children, rooms)` (HTL-015) → `total_cents`, `currency`.
5. **Atomically hold inventory across the span**: `hold_rooms(hotel_id, room_type_id,
   checkin, checkout, quantity=rooms, user_sub=user_sub)` (HTL-011) → `hold_id`. HTL-011's
   `hold_rooms` is itself all-or-nothing across the span (compensating per-night rollback on
   a sold-out night → 409); if it raises 409 the reservation is NOT created (no header row
   written). The hold MUST succeed before the header `put_item` so the room-nights are
   committed to this booking.
6. Mint `reservation_id = "res_" + uuid4().hex[:16]`; build the header item with
   `status="confirmed"`, `version=1`, `assigned_room_ids=[]`, `nights`, `total_cents`,
   `currency`, `hold_id`, the three GSI partitions/sort keys, `created_at`/`updated_at`.
7. `T.hotel_reservations.put_item(Item=item)`. If the put fails after the hold succeeded,
   best-effort `release_hold(hold_id, ...)` to avoid orphaning the held rooms (try/except).
8. Append the initial `HIST#...` row for the `None → confirmed` event (HTL-019 helper) —
   best-effort.
9. `_audit("hotel.reservation.created", user_sub, reservation_id=..., hotel_id=...,
   total_cents=..., hold_id=...)`.
10. Return the header dict.

`get_reservation(reservation_id) -> dict | None` — reads SK=`META`; returns `None` (→ 404)
for a missing row.

Pydantic models in `app/models.py`: `ReservationCreateIn` (hotel_id, guest_party_id,
room_type_id, checkin, checkout, adults, children, rooms, deposit_cents), `ReservationOut`
(all persisted fields). `status` constrained to the five lifecycle literals.

**Acceptance Criteria**
- `create_reservation` writes a `META` header with `status="confirmed"`, `version=1`,
  `assigned_room_ids=[]`, `nights == len([checkin, checkout))`, `total_cents` equal to
  `compute_stay_price(...).total_cents`.
- `create_reservation` calls `hold_rooms` (HTL-011) BEFORE the header `put_item`; a 409 from
  `hold_rooms` (sold-out span) leaves NO reservation header written.
- A failed `check_availability` (sold out at book time) raises 409 `no_availability` before
  any hold or write.
- The stored `hold_id` is the value returned by `hold_rooms` (so HTL-019 cancel can release).
- `hotel_reservations` `TableDef` present with all three GSIs and `attr_types={"created_at":
  "N"}`; `just restart` creates the table without `ValidationException`.
- `T.hotel_reservations` resolves; `ReservationCreateIn`/`ReservationOut` import cleanly.
- No `if S.dev_mode` branch in `hotel_reservations.py` (SECOPS-007).
- Flag off → `create_reservation` / `get_reservation` 404 via `_require_enabled()`.

**Dependencies**: HTL-011 `hold_rooms`/`release_hold` (forward ref —
`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`), HTL-012 `check_availability` (forward
ref), HTL-015 `compute_stay_price` (forward ref — `docs/qloapps/RATE_PLANS_TICKETS.md`),
HTL-001 `hotel_pms_enabled` flag (`docs/qloapps/HOTELS_AMENITIES_TICKETS.md`), HTL-017
(shares `app/services/hotel_reservations.py` + span validation). Reuses: ORD `ORDER`/`HIST#`
header+child + `version` CAS (`docs/ofbiz/specs/ORD-001.md` §3.2,
`docs/ofbiz/specs/ORD-005.md` §4.1.6), `uuid4().hex` id + LSE date-range
(`docs/open-property/specs/LSE-001.md` §3.2), `now_ts()` (`app/core/time.py:2`), `_audit`
(`app/services/inventory.py:92-98`), `_safe_table` (`app/core/tables.py`). Contrasts: ORD
order = cart total with no date span; LSE lease = tenancy with informational rent (neither
is a room-night reservation).

---

### HTL-019: Reservation lifecycle state machine + modify

**Type**: Feature
**Priority**: P0
**Estimate**: 3d

**Description**

Add the **reservation lifecycle state machine** + append-only history + `modify_reservation`
— a verbatim clone of the ORD state-machine pattern (`docs/ofbiz/specs/ORD-005.md` §4.1.6,
append-only HIST rows `docs/ofbiz/specs/ORD-001.md` §3.2) and the LSE transition-allowlist
shape (`docs/open-property/specs/LSE-001.md` §4.1 `_LEASE_TRANSITIONS`), specialized to the
hotel reservation domain.

**States + transitions** (`_RESERVATION_TRANSITIONS: dict[str, set[str]]` — the LSE
allowlist + ORD terminal-empty-set idea):
```python
_RESERVATION_TRANSITIONS: dict[str, set[str]] = {
    "confirmed":   {"checked_in", "cancelled", "no_show"},
    "checked_in":  {"checked_out"},
    "checked_out": set(),   # terminal
    "cancelled":   set(),   # terminal
    "no_show":     set(),   # terminal
}
```
- `confirmed → checked_in`: guest arrived (assign physical rooms).
- `confirmed → cancelled`: guest cancelled before arrival (release held inventory).
- `confirmed → no_show`: guest never arrived by end of arrival day (release held inventory;
  no-show *fee* is HTL-033, forward ref).
- `checked_in → checked_out`: departure (release physical rooms back to housekeeping).
- `checked_out` / `cancelled` / `no_show` are terminal (empty sets → any outbound attempt
  is rejected by the empty-set membership check, correct-by-construction, ORD-005 §5.8).

**`transition_reservation`** — the single transition entry point, mirroring ORD-005 §4.1.6:
```python
def transition_reservation(
    reservation_id: str,
    target_status: str,
    *,
    actor: str,
    reason: str = "",
    assigned_room_ids: list[str] | None = None,   # required on → checked_in
) -> dict:
```
1. `_require_enabled()`.
2. `get_reservation(reservation_id)` → 404 if missing. Read `current = item["status"]`,
   `expected_version = int(item["version"])`.
3. Validate edge: `target not in _RESERVATION_TRANSITIONS.get(current, set())` →
   `HTTPException(409, detail={"code": "invalid_status_transition", "from": current, "to":
   target})` (validated in Python before any DDB call — ORD-005 §5.2).
4. **Side-effects per target** (computed before the conditional write, applied within it):
   - `→ checked_in`: **assign physical rooms** — `assigned_room_ids` is required (else
     `HTTPException(422, "assigned_room_ids required for check-in")`); `len(assigned_room_ids)`
     must equal `rooms`. Sets `assigned_room_ids` on the header; best-effort marks each room
     `occupied` via the HTL-006 room service (`hotel_pms.set_room_status(room_id, "occupied")`,
     forward ref — try/except, never rolls back the transition; the EC2/K8s host-inventory
     best-effort pattern, CLAUDE.md).
   - `→ checked_out`: **release physical rooms** — best-effort marks each assigned room
     `dirty`/`vacant` for housekeeping via HTL-006 (forward ref, try/except). The held
     room-night inventory was already consumed by the stay; checkout does not call
     `release_hold` (the hold is the booking; it is released only on cancel/no-show).
   - `→ cancelled` **or** `→ no_show`: **release held inventory** — call
     `release_hold(item["hold_id"], reason=target, user_sub=actor, terminal_status="released")`
     (HTL-011, forward ref) so the date-keyed `held` counts are decremented back across the
     span and the room-nights become sellable again. Best-effort (try/except) — a
     release failure must NOT block the cancel/no-show transition; the expiry sweep
     (HTL-011 `expire_due_holds`) is the backstop. **Refund / penalty is HTL-033 (forward
     ref) — this cluster releases inventory and records the transition; it issues no refund
     and writes no ledger entry** (cross-cutting "no money fork", ORD-001 §5.6).
5. **Version-gated conditional `update_item`** on the `META` header (the ORD/KYC CAS,
   `docs/ofbiz/specs/ORD-005.md` §4.1.6, `app/services/kyc_cases.py:228`):
   `ConditionExpression="version = :expected_version"`, `SET status=:target,
   version=version+1, updated_at=:now` (+ `assigned_room_ids` on check-in). Catch
   `ConditionalCheckFailedException` → `HTTPException(409, detail={"code":
   "concurrent_update"})` (a concurrent writer bumped `version` first — exactly one winner).
6. **Append-only history**: write `HIST#{ts:020d}#{event_id}` child row on the same
   partition (the ORD HIST idiom, `docs/ofbiz/specs/ORD-001.md` §3.2):
   `event_id = sha256(f"{reservation_id}|{current}|{target}|{actor}")[:16]`,
   `{from_status, to_status, actor, reason, ts}`, written with
   `ConditionExpression="attribute_not_exists(sk)"` — best-effort, never rolls back the
   transition (ORD-005 §5 best-effort ordering). `list_reservation_history(reservation_id)`
   reads `begins_with(sk, "HIST#")` newest-first.
7. `_audit("hotel.reservation.status_changed", actor, reservation_id=..., from_status=current,
   to_status=target)` (best-effort).
8. Return the updated header (re-read or `ReturnValues="ALL_NEW"`).

**`modify_reservation`** — change dates and/or room type → re-check availability + re-price:
```python
def modify_reservation(
    reservation_id: str,
    *,
    checkin: str | None = None,
    checkout: str | None = None,
    room_type_id: str | None = None,
    adults: int | None = None,
    children: int | None = None,
    rooms: int | None = None,
    actor: str,
) -> dict:
```
1. `_require_enabled()`; `get_reservation` → 404; reject if `status != "confirmed"`
   (`HTTPException(409, "only confirmed reservations may be modified")` — a checked-in/out or
   terminal reservation cannot be re-dated).
2. Compute the new effective span/occupancy/room-type (fields default to the current values).
3. **Re-check availability** for the NEW span via `check_availability` (HTL-012); release the
   OLD hold (`release_hold(old_hold_id, ...)`, HTL-011) and place a NEW `hold_rooms` for the
   new span — order: place new hold first; on success release old hold; on new-hold 409 keep
   the old hold and raise 409 (never leave the reservation un-held).
4. **Re-price** via `compute_stay_price` (HTL-015) → new `total_cents`.
5. Version-gated conditional `update_item` (same `version = :expected_version` CAS) writing
   the new span/occupancy/room_type/nights/total_cents/hold_id, bumping `version`; append a
   `HIST#...` `"modified"` event; audit. (No money movement — any price *delta* settlement is
   HTL-033, forward ref.)

Pydantic models in `app/models.py`: `ReservationTransitionIn` (`target_status`, `reason?`,
`assigned_room_ids?`), `ReservationModifyIn` (all-optional partial), `ReservationHistoryEntry`
(`event_id`, `from_status`, `to_status`, `actor`, `reason`, `ts`).

**Acceptance Criteria**
- Legal transitions (`confirmed→checked_in`, `confirmed→cancelled`, `confirmed→no_show`,
  `checked_in→checked_out`) succeed, bump `version` by 1, and write a `HIST#` row; the
  legacy snapshot is the header `status` field.
- Illegal transitions (e.g. `checked_out→confirmed`, any outbound from a terminal state)
  raise 409 `invalid_status_transition` with zero DDB writes.
- `→ checked_in` requires `assigned_room_ids` with `len == rooms` (422 otherwise) and writes
  them onto the header; `→ checked_out` releases physical rooms (best-effort, never blocks).
- `→ cancelled` and `→ no_show` call `release_hold(hold_id, ...)` (HTL-011) — held inventory
  is decremented back across the span — and write NO ledger entry / issue NO refund (HTL-033
  owns refunds).
- Concurrent transitions race on the `version = :expected_version` CAS: exactly one winner;
  the loser gets 409 `concurrent_update`; exactly one HIST row.
- `modify_reservation` re-checks availability + re-prices the new span, swaps the hold
  (new-hold-before-old-release, no un-held window), bumps `version`, and refuses a
  non-`confirmed` reservation (409).
- `list_reservation_history` returns events newest-first.
- Flag off → every entrypoint 404s.

**Dependencies**: HTL-018 (`hotel_reservations` table + `version` header + `hold_id` +
`get_reservation`), HTL-011 `release_hold`/`hold_rooms` (forward ref —
`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`), HTL-012 `check_availability` + HTL-015
`compute_stay_price` (forward refs — modify re-check/re-price), HTL-006 `set_room_status`
(forward ref — physical room assignment/release, `docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md`).
Reuses: ORD state machine + version CAS + HIST rows (`docs/ofbiz/specs/ORD-005.md` §4.1.6,
§5.8, `docs/ofbiz/specs/ORD-001.md` §3.2), LSE `_LEASE_TRANSITIONS` allowlist shape
(`docs/open-property/specs/LSE-001.md` §4.1), `kyc_cases.py:228` conditional update,
best-effort side-effect pattern (CLAUDE.md EC2/K8s host-inventory), `now_ts()`
(`app/core/time.py:2`), `_audit` (`app/services/inventory.py:92-98`). Forward ref: HTL-033
(cancellation/no-show refund + penalty cluster) — this ticket releases inventory only.

---

### HTL-020: Routers — `/ui/hotel-search` + `/ui/hotels/{hotel_id}/reservations` + lifecycle sub-routes + registration

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Expose the HTL-017/018/019 services over HTTP via a new `hotel_reservations_router`,
modeled exactly on `app/routers/inventory.py` (auth split + `_require_enabled()`
short-circuit). Register it in `app/main.py` next to the other hotel routers (HTL-008
hotels router, HTL-012 availability router, HTL-016 rate-plans router — forward refs).

```python
hotel_reservations_router = APIRouter(prefix="/ui", tags=["hotel-reservations"])
```
Every handler calls `_require_enabled()` first (delegating to
`hotel_reservations._require_enabled()`, exactly like `app/routers/inventory.py:32-38`).

| Method | Path | Auth | Service |
|---|---|---|---|
| POST | `/ui/hotel-search` | `require_ui_session` | `search_stays` (body `StaySearchIn`; read-only, hence POST-with-body but session-read auth — the search funnel) |
| POST | `/ui/hotels/{hotel_id}/reservations` | `require_admin_or_root_csrf` | `create_reservation` (`hotel_id` from path, body `ReservationCreateIn`) |
| GET | `/ui/hotels/{hotel_id}/reservations` | `require_ui_session` | `list_reservations` (by hotel; query params `status`, `checkin_from`, `checkin_to`, `cursor`, `limit` — paginates `GSI_HOTEL_ARRIVALS` / `GSI_HOTEL_STATUS`) |
| GET | `/ui/hotels/{hotel_id}/reservations/{reservation_id}` | `require_ui_session` | `get_reservation` (404 if none / wrong hotel) |
| GET | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/history` | `require_ui_session` | `list_reservation_history` (newest-first) |
| PUT | `/ui/hotels/{hotel_id}/reservations/{reservation_id}` | `require_admin_or_root_csrf` | `modify_reservation` (body `ReservationModifyIn`) |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/confirm` | `require_admin_or_root_csrf` | (no-op/idempotent confirm — a `confirmed` reservation is already confirmed; returns the header. Reserved for a future `draft → confirmed` step) |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/check-in` | `require_admin_or_root_csrf` | `transition_reservation(..., "checked_in", assigned_room_ids=...)` |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/check-out` | `require_admin_or_root_csrf` | `transition_reservation(..., "checked_out")` |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/cancel` | `require_admin_or_root_csrf` | `transition_reservation(..., "cancelled")` (releases held inventory; NO refund — HTL-033) |
| POST | `/ui/hotels/{hotel_id}/reservations/{reservation_id}/no-show` | `require_admin_or_root_csrf` | `transition_reservation(..., "no_show")` (releases held inventory; NO penalty — HTL-033) |

> **Declaration order (literal-before-dynamic):** declare the literal `/ui/hotel-search`
> route and the literal lifecycle sub-routes (`.../confirm`, `.../check-in`, `.../check-out`,
> `.../cancel`, `.../no-show`, `.../history`) BEFORE the bare dynamic
> `/ui/hotels/{hotel_id}/reservations/{reservation_id}` GET/PUT so FastAPI does not capture
> `check-in` etc. as a `{reservation_id}` path param (the same gotcha as the KYC
> `/templates`-before-`/{case_id}` and audit-export `/schedules`-before-`/{export_id}`
> ordering noted in CLAUDE.md).

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py:48,65,81`. Mutation handlers derive `actor`/`user_sub` from the
authenticated session context. `list_reservations` uses `encode_cursor`/`decode_cursor`
(`app/core/cursor.py:94,103`) and returns the `{reservations, count, cursor}` shape (the
`host_inventory.list_hosts` `{items, count, cursor}` convention, CLAUDE.md).

`transition_reservation`'s typed errors map to HTTP: invalid edge / terminal / concurrent →
409; missing → 404; missing `assigned_room_ids` → 422 (ORD-005 §4.1.1 error→HTTP mapping).

**Acceptance Criteria**
- All 11 endpoints respond; flag off → every endpoint 404s (handler-level no-op via
  `_require_enabled()`, router still mounted, byte-for-byte unchanged platform).
- Read endpoints accept a UI session; mutation/lifecycle endpoints reject non-admin /
  missing-CSRF requests (403) per `require_admin_or_root_csrf`.
- The literal `/ui/hotel-search` and the lifecycle sub-routes resolve to their own handlers,
  NOT captured by `/{reservation_id}` (literals declared first).
- `check-in` without `assigned_room_ids` → 422; an illegal lifecycle action (e.g. `check-out`
  on a `confirmed` reservation) → 409; a concurrent action → 409.
- `cancel` / `no-show` return 200 and the released-hold is reflected by availability; no
  ledger entry is written (HTL-033 owns money).
- `hotel_reservations_router` imported and `include_router`'d in `app/main.py` adjacent to
  the other hotel routers.

**Dependencies**: HTL-017 (`search_stays`), HTL-018 (`create_reservation`/`get_reservation`
/`list_reservations`), HTL-019 (`transition_reservation`/`modify_reservation`/
`list_reservation_history`). Reuses: `app/routers/inventory.py:32-38,48,65,81` (router idiom
+ auth split), `app/auth/policy.py:100` (`require_admin_or_root_csrf`),
`app/services/sessions.py:330` (`require_ui_session`), `app/core/cursor.py:94,103`
(pagination), `app/main.py` registration (cf. ORD-001 §4.2 router-gate, LSE router plan).
Forward refs: HTL-008/012/016 routers (sibling clusters) for the `app/main.py` adjacency.

---

### HTL-021: Frontend (stay-search results + reservation create + reservation detail w/ lifecycle actions) + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 3d

**Description**

Build the booking/reservation UI and the hermetic backend + E2E tests. Follow the
established frontend feature recipe (CLAUDE.md "Adding a new feature" steps 5–9).

Frontend (`frontend/src/`):
- **Types** — add `StaySearchIn`, `StayRoomTypeResult`, `StaySearchResult`, `Reservation`,
  `ReservationCreateIn`, `ReservationModifyIn`, `ReservationHistoryEntry`,
  `ReservationTransitionIn` (and the per-night line shape from HTL-015) to
  `frontend/src/api/types.ts` (mirror the `app/models.py` HTL models).
- **API endpoints** — `frontend/src/api/endpoints/hotelReservations.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`): `searchStays`, `createReservation`,
  `listReservations`, `getReservation`, `getReservationHistory`, `modifyReservation`,
  `confirmReservation`, `checkInReservation`, `checkOutReservation`, `cancelReservation`,
  `noShowReservation`.
- **Pages** under `frontend/src/pages/hotels/`:
  - `StaySearchPage.tsx` — a **search form** (hotel or city, check-in/check-out date
    pickers, adults/children/rooms steppers) → a **results list** (one card per available
    room type: name, per-night breakdown, total formatted from cents, "Book" button). Uses
    React Query `useQuery`/`useMutation` on `searchStays`; "Book" opens a confirm dialog →
    `createReservation`.
  - `ReservationsPage.tsx` — a hotel's **reservations list** (filterable by status / arrival
    date window) driven by `listReservations`, each row linking to detail.
  - `ReservationDetailPage.tsx` — header (hotel, guest, room type, span, occupancy, total,
    status badge), a **lifecycle action bar** with role-gated buttons (Check-in — opens a
    room-assignment picker, Check-out, Cancel, No-show, Modify) calling the lifecycle
    endpoints, a **status-history timeline** from `getReservationHistory`, and a Modify
    dialog (re-date / re-occupancy → re-priced quote preview before submit). shadcn/ui
    primitives (`Card`, `Dialog`, `Badge`, `Button`, `components/ui/`); React Hook Form +
    Zod for the search + create + modify forms.
- **Routes** — lazy-load the three pages in `frontend/src/App.tsx` (cf. the lazy-import
  block): `/hotel-search` → `StaySearchPage`, `/hotels/:hotelId/reservations` →
  `ReservationsPage`, `/hotels/:hotelId/reservations/:reservationId` →
  `ReservationDetailPage`.
- **Sidebar** — add a "Reservations" (or "Hotel Booking") nav item to
  `frontend/src/components/layout/Sidebar.tsx` (lucide `BedDouble`/`CalendarCheck` icon,
  `path: "/hotel-search"`). Gate on a `hotelPmsEnabled` flag if the sidebar reads feature
  flags; otherwise show unconditionally (routes 404 server-side when off).

Tests:
- **Hermetic pytest** `tests/test_htl_reservations.py` — moto-bound `hotel_reservations`
  table on frozen `T` (`object.__setattr__`, restored on cleanup), frozen `S` with
  `hotel_pms_enabled` toggled, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` (no `TestClient`). The forward-dep HTL-011/012/015 service
  functions (`hold_rooms`, `release_hold`, `check_availability`, `compute_stay_price`) and
  HTL-001/005/006 listers are **patched at the `hotel_reservations` module namespace** (the
  hermetic patch-collaborators pattern, cf. KYC GAP-0262 tests) so the suite is offline and
  does not require those clusters to be merged. Cover:
  - **search**: `search_stays` returns only available room types, cheapest-first, prices
    from the patched `compute_stay_price`; LOS-reject excludes a room type; `hotel_id`+`city`
    both absent → 422.
  - **create + hold**: `create_reservation` calls `hold_rooms` BEFORE the header `put_item`,
    writes `status="confirmed"`/`version=1`/`hold_id`; a 409 from `hold_rooms` leaves no
    header; a failed `check_availability` → 409 with no hold.
  - **each transition**: `confirmed→checked_in` (requires `assigned_room_ids` == `rooms`,
    422 otherwise), `confirmed→cancelled`, `confirmed→no_show`, `checked_in→checked_out` —
    each bumps `version` and writes a HIST row.
  - **version-conflict**: a stale `expected_version` (simulate by patching `update_item` to
    raise `ConditionalCheckFailedException`) → 409 `concurrent_update`.
  - **cancel-releases-inventory**: `cancel` (and `no_show`) call `release_hold(hold_id, ...)`
    and write NO ledger entry.
  - **modify re-price**: `modify_reservation` on a `confirmed` reservation re-checks
    availability, swaps the hold (new-before-old), re-prices, bumps `version`; a
    non-`confirmed` reservation → 409.
  - **flag-off 404**: with `hotel_pms_enabled=False`, every service entrypoint + every route
    handler 404s.
- **E2E** `frontend/e2e/hotel-reservations.spec.ts` — cookie-auth (`injectAuth`) admin runs
  a stay search, books a reservation, drives the check-in → check-out lifecycle (with room
  assignment), cancels another reservation, and asserts the results list, detail status
  badge, history timeline, and lifecycle-button enable/disable states render; CSRF header on
  POSTs (`x-csrf-token`). Requires `HOTEL_PMS_ENABLED=1` (and the HTL-001..HTL-016 clusters
  enabled) in the E2E backend env.

**Acceptance Criteria**
- `/hotel-search` renders a search form + available-room-type results with per-night
  breakdown + total; "Book" creates a reservation. `/hotels/:id/reservations` lists
  reservations; `/hotels/:id/reservations/:rid` renders detail + lifecycle action bar +
  history timeline; all reachable via the new sidebar nav item.
- Lifecycle buttons reflect the state machine (only legal next actions enabled; terminal
  reservation shows no actions); check-in opens a room-assignment picker.
- Money displays as currency (cents → formatted); status badges reflect `status`.
- `tests/test_htl_reservations.py` passes offline (no AWS, no live stack, forward-dep
  collaborators patched).
- `frontend/e2e/hotel-reservations.spec.ts` passes with the flag on.

**Dependencies**: HTL-020 (router/endpoints) — transitively HTL-017/018/019. Reuses:
`frontend/src/api/client.ts`, `frontend/src/App.tsx` (lazy routes),
`frontend/src/components/layout/Sidebar.tsx` (nav items), shadcn/ui (`components/ui/`),
React Query + RHF/Zod conventions (CLAUDE.md frontend conventions), hermetic-test pattern
(LSE-001 §9, ORD-005 §9, KYC GAP-0262 patch-collaborators) + E2E patterns (CLAUDE.md E2E
section).

---

## Dependency order

```
HTL-017 (stay-search engine — read-only, composes HTL-012 + HTL-015)
   │   (shares app/services/hotel_reservations.py with ↓)
HTL-018 (reservation entity + table + create_reservation — holds via HTL-011, prices via HTL-015)
   ↓
HTL-019 (lifecycle state machine + history + modify — ORD version-CAS; cancel/no-show release HTL-011 hold)
   ↓
HTL-020 (routers: /ui/hotel-search + /ui/hotels/{id}/reservations + lifecycle sub-routes + main.py registration)
   ↓
HTL-021 (frontend + hermetic pytest + E2E)
```

HTL-017 and HTL-018 both create/extend `app/services/hotel_reservations.py` and share the
span-validation helper; HTL-017 (read-only search) can land first or alongside HTL-018.
HTL-018 must precede HTL-019 (the lifecycle needs the `version` header + `hold_id`). All
five depend on the forward-dep clusters by id: **HTL-011** (`hold_rooms`/`release_hold`) +
**HTL-012** (`check_availability`) — `docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`;
**HTL-015** (`compute_stay_price`) — `docs/qloapps/RATE_PLANS_TICKETS.md`; **HTL-001/005/006**
(hotels/room-types/rooms) — `docs/qloapps/HOTELS_AMENITIES_TICKETS.md`,
`docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md`. The cancellation/no-show **refund +
penalty** engine is **HTL-033** (Tier-3, forward ref) — this cluster releases held inventory
and records the transition, but issues no refund and writes no ledger entry.
