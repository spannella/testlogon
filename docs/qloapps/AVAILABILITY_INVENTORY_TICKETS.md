# HTL — Per-date availability inventory calendar (Hotel-PMS spine, gap analysis §B)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §B ("Rate Plans / Pricing +
Availability Calendar / Inventory"). QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) is an open-source hotel
property-management system + booking engine whose **per-room-type per-date
available-rooms inventory calendar** is the gap analysis's flagship **MISSING**
primitive (gap analysis §B rows "Per-room-type per-date available-rooms inventory",
"Availability calendar", "Blocking/holding rooms for dates", "Overbooking controls +
min/max availability per date", "Booking-time availability check").

The closest structural analogue is the OFBiz **inventory + soft-reservation** pair
(`app/services/inventory.py`, OFB-003/004) — a SKU stock record with a
conditional-decrement reserve/commit/release lifecycle. **We reuse that
conditional-decrement idiom and the flag/audit/table scaffolding but NOT the data
model**: OFBiz inventory is a single **SCALAR** stock counter keyed `(sku,
location)` with `on_hand`/`reserved`/`available` and **NO date dimension**
(`docs/ofbiz/specs/OFB-003.md`; the gap analysis says it bluntly — "inventory
(OFB-003) is `(sku, location)` scalar `on_hand`/`reserved` — no date dimension; the
distinctive hotel primitive", §B). A hotel needs a **per-room-type, per-DATE**
remaining-rooms count: one row per `(room_type, calendar_date)` so the same room type
can be sold-out on 2026-07-04 and wide-open on 2026-07-05. That date key is the
net-new dimension OFBiz has no concept of, and availability across a stay is the
**intersection of every night's remaining count** — not a single scalar read.

These four tickets cover ONLY the per-date availability inventory model + block/hold +
overbooking/min-max controls + read/calendar API + booking-time availability check + FE
(gap analysis §B inventory rows). Hotel/Room-Type/Room entities, housekeeping, nightly
rate plans, the stay-search engine, reservations, folios, and KPI reports are out of
scope here (separate ticket clusters in the gap analysis Tier-1/Tier-2/Tier-3). HTL-012
explicitly **feeds** the stay-search engine (HTL-017, a separate Tier-2 cluster — a
forward reference, not built here).

## Cross-cutting constraints (apply to every HTL ticket)

- **Additive + flag-gated, default OFF.** A master flag `HOTEL_PMS_ENABLED` (default
  `false`) gates the whole hotel vertical. Mirror the `INVENTORY_RESERVATIONS_ENABLED`
  contract exactly: `_flag_on()` / `_require_enabled()` raising **404** when off, the
  same 404 no-op idiom as `app/services/inventory.py:50-56` (cf. the 404 contract at
  `app/services/inventory.py:51-58`) and `app/routers/inventory.py:31-33`. Routers are
  always mounted; every handler is a 404 no-op until opt-in. With the flag off the
  platform is byte-for-byte unchanged.
- **Single-table DynamoDB.** One `hotel_availability` table holding one row per
  `(room_type, date)`. Composite partition key `availability_pk =
  "{hotel_id}#{room_type_id}"` co-locates all of a room type's date-rows on one
  partition for a cheap `begins_with(sk, "DATE#")` per-room-type date-range scan
  (mirrors the `properties` header+child idiom in
  `docs/open-property/PROPERTY_UNITS_TICKETS.md` and the FAC `LOC#`-child pattern,
  `docs/ofbiz/specs/OFB-003.md`).
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key MUST be declared in
  the `TableDef` `attr_types` map per the CLAUDE.md DynamoDB numeric-GSI gotcha —
  omitting it stores the value as String → `ValidationException` at query time. Pattern:
  `scripts/local-ddb-init.py` `TableDef(...)` calls (the `inventory`/`reservations`
  style, `docs/ofbiz/specs/OFB-004.md` §3.1).
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor pagination
  (`app/core/cursor.py`), the `_audit()` lazy-import wrapper
  (`app/services/inventory.py:92-98`), table handles via `T.*`
  (`app/core/tables.py:317-319,569-571`). The block/hold conditional-decrement REUSES
  the `inventory.reserve` idiom — a single-writer `update_item` with
  `ConditionExpression="available >= :q"` (`app/services/inventory.py:362-372`) — but
  adds the DATE key. Auth: reads → `require_ui_session` (`app/services/sessions.py:330`);
  mutations → `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical split
  to `app/routers/inventory.py` (reads on `require_ui_session`, mutations on
  `require_admin_or_root_csrf`).
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). Mirrors `app/services/inventory.py:27-29`.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`,
  restored on cleanup), frozen `S` flags toggled via `object.__setattr__`, route
  coroutines called directly on a fresh `asyncio.new_event_loop()` — no `TestClient`, no
  real AWS. Mirrors `docs/ofbiz/specs/OFB-004.md` §9.1 and the
  `docs/open-property/PROPERTY_UNITS_TICKETS.md` test recipe.

---

### HTL-010: Per-date availability inventory — model, table, flag, seed/set

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Land the per-date availability data model, its DynamoDB table, the master `HOTEL_PMS_ENABLED`
feature flag, and the seed/set service — the foundation every other HTL availability
ticket depends on. Net-new; the OFBiz scalar inventory row is the structural analogue we
**contrast**, not reuse: that row is one scalar counter per `(sku, location)` with no
date (`docs/ofbiz/specs/OFB-003.md`); this row is one counter per `(room_type, date)`.

**DDB table** `hotel_availability` (PK=`availability_pk` = composite
`"{hotel_id}#{room_type_id}"`, SK=`DATE#{YYYY-MM-DD}`) — all of a room type's calendar
days on one partition for a cheap `begins_with(sk, "DATE#")` range scan:

| Attribute | Type | Notes |
|---|---|---|
| `availability_pk` | S | PK = `"{hotel_id}#{room_type_id}"` composite (one partition per room type) |
| `sk` | S | `DATE#{YYYY-MM-DD}` (ISO calendar date; lexical order == chronological order → range queries with `between`/`begins_with` are date-ordered for free) |
| `hotel_id` | S | Owning hotel id (convenience copy for projections/filters) |
| `room_type_id` | S | Owning room type id (convenience copy) |
| `date` | S | `YYYY-MM-DD` (convenience copy of the SK date) |
| `total_rooms` | N | Physical rooms of this type sellable on this date |
| `booked` | N | Rooms consumed by confirmed reservations (default 0; advanced by the reservation cluster HTL-018, forward ref) |
| `held` | N | Rooms held by active (TTL) holds (default 0; managed by HTL-011) |
| `overbooking_allowance` | N | Extra rooms sellable beyond `total_rooms` (default 0; HTL-011) |
| `min_availability` | N | Optional floor: stop selling once `available` drops to this (default 0; HTL-011) |
| `max_availability` | N | Optional cap on sellable rooms for this date (optional; HTL-011) |
| `updated_at` | N | `now_ts()` |

Derived (computed, not a stored authority — recomputed on every mutation like
`available` in `app/services/inventory.py:16-18,131`):
`available = total_rooms + overbooking_allowance - booked - held`, clamped at the
`min_availability` floor for sell decisions (the raw value may be persisted for the
calendar projection; the sellable count is `max(0, available - min_availability)` where
`min_availability` reserves a hold-back).

**GSI** (declared in `scripts/local-ddb-init.py`, `attr_types={"updated_at": "N"}` —
numeric sort key):
- `GSI_HOTEL_DATE` — PK=`hotel_id`, SK=`date` (both `S`) — the hotel-wide availability
  calendar across ALL room types for a date range (HTL-012 `availability_calendar`),
  without scanning each room type's partition separately. (`date` is `S` so no numeric
  `attr_types` entry is needed for this index; `updated_at` is declared numeric for any
  freshness/admin sort path.)

`TableDef` follows the `inventory`/`reservations` style in `scripts/local-ddb-init.py`
(cf. `docs/ofbiz/specs/OFB-004.md` §3.1):
```python
TableDef(
    _resolve_table_name(S.hotel_availability_table_name, "hotel_availability"),
    "availability_pk",
    "sk",
    gsi=[
        {"index_name": "GSI_HOTEL_DATE", "partition_key": "hotel_id", "sort_key": "date"},
    ],
    attr_types={"updated_at": "N"},
),
```

Settings (add to `app/core/settings.py` next to the inventory block at
`inventory_reservations_enabled` / `inventory_table_name`, same
`os.environ.get(...).lower() == "true"` idiom):
```python
hotel_pms_enabled: bool = os.environ.get("HOTEL_PMS_ENABLED", "false").lower() == "true"
hotel_availability_table_name: str = os.environ.get("HOTEL_AVAILABILITY_TABLE_NAME", "hotel_availability")
hotel_hold_ttl_seconds: int = int(os.environ.get("HOTEL_HOLD_TTL_SECONDS", "900"))  # used by HTL-011
```

Table handle: add `hotel_availability: Any` to the `T` dataclass (next to `inventory`,
`app/core/tables.py:317-319`) and wire
`hotel_availability=_safe_table(S.hotel_availability_table_name)` in the initializer
(next to `inventory=...`, `app/core/tables.py:569-571`).

Pydantic models in `app/models.py`: `AvailabilityDayOut` (all persisted fields +
derived `available`), `AvailabilitySetIn` (`hotel_id`, `room_type_id`, `start_date`,
`end_date`, `total_rooms`), `AvailabilityDayIn` (single-date set). Dates constrained to
`YYYY-MM-DD` (regex/`date` validation).

Service `app/services/hotel_availability.py` (new), modeled on
`app/services/inventory.py`:
- `_flag_on()` / `_require_enabled()` → 404 when off (copy the idiom at
  `app/services/inventory.py:50-56`; checks `getattr(S, "hotel_pms_enabled", False)`).
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy
  `app/services/inventory.py:92-98`).
- `_availability_pk(hotel_id, room_type_id) -> str` → `"{hotel_id}#{room_type_id}"`;
  `_date_sk(date) -> str` → `"DATE#{date}"`; `_date_range(start, end) -> list[str]` →
  inclusive list of `YYYY-MM-DD` strings (helper used by seed + read).
- `_available(item) -> int` → `total_rooms + overbooking_allowance - booked - held`
  (the date-keyed analogue of `inventory._record_out`'s `on_hand - reserved`,
  `app/services/inventory.py:101-115`).
- `set_total_rooms(hotel_id, room_type_id, start_date, end_date, total_rooms, *, user_sub)
  -> list[dict]` — seeds/sets one row per date in `[start_date, end_date]`; preserves
  existing `booked`/`held`/`overbooking_allowance`/`min`/`max` on overwrite (read-merge
  per date, like `set_on_hand` preserving `reserved`, `app/services/inventory.py:185-206`);
  stamps `updated_at`; one `_audit("hotel.availability.set_total", ...)` per range.
- `get_day(hotel_id, room_type_id, date) -> dict | None` — single date row.
- `get_availability(hotel_id, room_type_id, checkin, checkout) -> list[dict]` — returns
  the per-date rows for the **stay span** `[checkin, checkout)` (checkout exclusive — the
  guest does not occupy a room the night of departure), via a `Key` query
  `between(DATE#checkin, DATE#checkout-1day)`; missing dates surface as zeroed virtual
  rows (`available = 0`, like `inventory.get_or_zero`, `app/services/inventory.py:158-173`)
  so a never-seeded date reads as sold-out, not as an error.

All entrypoints call `_require_enabled()` first.

**Acceptance Criteria**
- `hotel_availability` `TableDef` present with `GSI_HOTEL_DATE` and
  `attr_types={"updated_at": "N"}`; `just restart` creates the table without
  `ValidationException`.
- `HOTEL_PMS_ENABLED` defaults to `false`; with it off, every `hotel_availability`
  service entrypoint raises HTTP 404 via `_require_enabled()`.
- `set_total_rooms` over a 3-day range writes exactly 3 `DATE#`-keyed rows on one
  partition; re-setting `total_rooms` preserves existing `booked`/`held`/
  `overbooking_allowance` per date.
- `_available` computes `total_rooms + overbooking_allowance - booked - held`; a
  never-seeded date reads back as a zeroed virtual row (`available = 0`).
- `get_availability` returns the span `[checkin, checkout)` (departure night excluded).
- `T.hotel_availability` resolves; `AvailabilityDayOut/SetIn/DayIn` import cleanly.
- No `if S.dev_mode` branch in `hotel_availability.py` (SECOPS-007).

**Dependencies**: none (foundational). Reuses: `app/services/inventory.py:50-56,92-98,101-115,158-173,185-206`
(flag/audit/derived-counter/zeroed-virtual/preserve-on-set idioms),
`scripts/local-ddb-init.py` (`inventory` `TableDef` style), `app/core/tables.py:317-319,569-571`,
`app/core/settings.py` (inventory settings block), `app/core/time.py:2`. Contrasts:
`docs/ofbiz/specs/OFB-003.md` (scalar `(sku, location)` inventory — NO date dimension).

---

### HTL-011: Block/hold + overbooking + min/max availability controls

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add the block/hold lifecycle and the per-date overbooking/min-max controls — the
date-keyed reuse of the OFBiz soft-reservation pattern. `hold_rooms` REUSES the
`inventory.reserve` conditional-decrement idiom (single-writer `update_item` with
`ConditionExpression="available >= :q"`, `app/services/inventory.py:362-372`) but
applies it across EVERY night of a date span and increments `held` on each per-date row
rather than a single scalar `reserved`. Holds carry a TTL (like OFB-004 soft
reservations, `app/services/inventory.py:383-401`) so they self-release.

**DDB**: reuses the `hotel_availability` table from HTL-010 for the per-date `held`
increment; hold ledger rows are co-located on the **same** table with a distinct SK
prefix so a hold and the date-rows it touches share scan locality:

| Attribute | Type | Notes |
|---|---|---|
| `availability_pk` | S | `HOLD#{hold_id}` (own partition for the hold meta — `hold_id = uuid4().hex`, mirrors `inventory._reservation_pk`, `app/services/inventory.py:63-64`) |
| `sk` | S | `META` |
| `hold_id` | S | Convenience copy |
| `hotel_id` / `room_type_id` | S | The room type held |
| `checkin` / `checkout` | S | `YYYY-MM-DD` span (checkout exclusive) |
| `dates` | L | The list of `YYYY-MM-DD` nights this hold incremented (so `release_hold` knows exactly which date-rows to decrement, even if `total_rooms` shifted) |
| `quantity` | N | Rooms held per night |
| `status` | S | `active` / `released` / `expired` (terminal flip guarded by `status = active`, `app/services/inventory.py:440-453`) |
| `user_sub` | S | Holder |
| `created_at` | N | `now_ts()` |
| `expires_at` | N | `created_at + ttl`; GSI sort key |
| `gsi_expiry_pk` | S | `HOLD#ACTIVE` while active; `REMOVE`d on terminal transition (mirrors `app/services/inventory.py:399,443`) |

**GSI** on the `hotel_availability` table (add to the same `TableDef`):
- `GSI_HOLD_EXPIRY` — PK=`gsi_expiry_pk`, SK=`expires_at` (N) —
  `attr_types={"expires_at": "N"}` (numeric sort key) — drives the TTL sweep, exactly
  the `GSI_EXPIRY` pattern on the reservations table (`docs/ofbiz/specs/OFB-004.md` §3.1,
  `app/services/inventory.py:547-552`).

Pydantic models in `app/models.py`: `HoldRoomsIn` (`hotel_id`, `room_type_id`, `checkin`,
`checkout`, `quantity`, optional `ttl_seconds`), `HoldOut` (all hold fields),
`OverbookingSetIn` (`hotel_id`, `room_type_id`, `start_date`, `end_date`, `allowance`),
`MinMaxSetIn` (`hotel_id`, `room_type_id`, `start_date`, `end_date`, `min_availability`,
`max_availability`).

Service additions in `app/services/hotel_availability.py`:
- `hold_rooms(hotel_id, room_type_id, checkin, checkout, quantity, *, user_sub,
  ttl_seconds=None) -> dict` — for EACH night in `[checkin, checkout)`, a single-writer
  conditional `update_item` `SET held = held + :q, updated_at = :now` guarded by
  `ConditionExpression="total_rooms + overbooking_allowance - booked - held >= :q + min_availability"`
  (the date-keyed, min-floor-aware analogue of `inventory.reserve`'s
  `ConditionExpression="available >= :q"`, `app/services/inventory.py:362-372`). All
  nights must succeed; on the FIRST `ConditionalCheckFailedException` (a sold-out night)
  the already-incremented earlier nights are decremented back (compensating rollback —
  the holds are atomic per night but not across the span, so the span is made
  all-or-nothing by manual unwind, the same shape as the legacy multi-row decrement
  rollback in `shoppingcart.py` noted in `docs/ofbiz/specs/OFB-004.md` §2.2) and the
  call raises **409**. On full success, writes the `HOLD#{hold_id}` meta row (active,
  TTL) and `_audit("hotel.hold.created", ...)`.
- `release_hold(hold_id, *, reason="released", user_sub, terminal_status="released") ->
  dict` — flips the hold meta `active → terminal` via the `status = active` CAS
  (idempotent double-release no-op, `app/services/inventory.py:434-453`); for each date
  in the stored `dates` list decrements `held` back; `REMOVE gsi_expiry_pk`; audits.
- `expire_due_holds(*, now=None, limit=200) -> int` — queries `GSI_HOLD_EXPIRY`
  (`gsi_expiry_pk == "HOLD#ACTIVE"` AND `expires_at <= now`) and calls
  `release_hold(..., terminal_status="expired")` per overdue hold — a clone of
  `inventory.expire_due_reservations` (`app/services/inventory.py:538-562`). Driven by a
  background sweep (registered alongside the other startup loops in `app/main.py`, gated
  on `hotel_pms_enabled`, interval ~60s — same shape as `start_reservation_expiry_task`,
  `docs/ofbiz/specs/OFB-004.md` §4.2).
- `set_overbooking_allowance(hotel_id, room_type_id, start_date, end_date, allowance, *,
  user_sub) -> list[dict]` — per-date `SET overbooking_allowance = :a` over the range;
  audits. (Lifts the hard `available >= qty` stop OFBiz can never exceed — the gap
  analysis "Overbooking controls" MISSING row.)
- `set_min_max_availability(hotel_id, room_type_id, start_date, end_date, *,
  min_availability=None, max_availability=None, user_sub) -> list[dict]` — per-date set
  of the optional floor/cap; audits.

All entrypoints call `_require_enabled()` first.

**Acceptance Criteria**
- `hold_rooms` over a 3-night span increments `held` by `quantity` on all 3 date-rows;
  a hold that exceeds `available` on ANY night raises 409 and leaves `held` unchanged on
  EVERY night (compensating rollback — no partial hold persists).
- `hold_rooms` respects `overbooking_allowance` (a hold that fits only because of the
  allowance succeeds) and `min_availability` (a hold is rejected once it would drop
  sellable below the floor).
- `release_hold` decrements `held` back exactly for the stored `dates`; double-release is
  an idempotent no-op (CAS guard).
- `expire_due_holds(now=expires_at+1)` flips an overdue hold to `expired` and restores
  `held`; concurrent sweeps are safe (status-CAS one-winner).
- `set_overbooking_allowance` / `set_min_max_availability` persist per-date and are
  reflected by the derived `available`.
- `GSI_HOLD_EXPIRY` declared with `attr_types={"expires_at": "N"}`.
- Flag off → every entrypoint 404s.

**Dependencies**: HTL-010 (table + flag + per-date rows + `_available`). Reuses:
`app/services/inventory.py:362-372` (conditional `available >= qty` reserve idiom),
`:383-401` (TTL hold row), `:434-453` (status-CAS idempotent terminal flip), `:538-562`
(expiry sweep), `:399,443` (`gsi_expiry_pk` add/REMOVE), `docs/ofbiz/specs/OFB-004.md`
§3.1,§4.2 (reservation table + expiry-task pattern). Contrasts: OFBiz holds a single
scalar `reserved` with no date span (`docs/ofbiz/specs/OFB-003.md`).

---

### HTL-012: Availability read/calendar API + booking-time availability check + router

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add the availability calendar read + the booking-time availability check (the core
net-new hotel primitive the gap analysis calls "the heart of a hotel PMS", §B), and
expose the HTL services over HTTP via a new `hotel_availability_router`, modeled exactly
on `app/routers/inventory.py` (auth split + `_require_enabled()` short-circuit).

Service additions in `app/services/hotel_availability.py`:
- `availability_calendar(hotel_id, start_date, end_date) -> dict` — the hotel-wide
  calendar across ALL room types for a date range. Queries `GSI_HOTEL_DATE`
  (PK=`hotel_id`, SK=`date` `between(start, end)`), groups rows by `room_type_id`, and
  returns `{"hotel_id": ..., "start_date": ..., "end_date": ...,
  "room_types": {room_type_id: [AvailabilityDayOut...]}}` — per-date remaining per room
  type, the data source for the FE grid (HTL-013). Pure GSI aggregation — no scan.
- `check_availability(hotel_id, room_type_id, checkin, checkout, rooms_needed) -> dict`
  — the booking-time check. Calls `get_availability(...)` (HTL-010) for the stay span
  `[checkin, checkout)` and asks: is `available >= rooms_needed` on **EVERY** night? The
  answer is the **intersection across the whole span** — a room type is bookable for a
  stay iff every single night of that stay has enough rooms (this is the distinction the
  OFBiz scalar counter cannot express: there is no "every night" — there is one number).
  Returns `{"available": bool, "rooms_needed": int,
  "per_night": [{"date": ..., "remaining": int, "sufficient": bool}...],
  "min_remaining": int}` where `min_remaining = min(per-night remaining)` (the binding
  constraint). A missing/zeroed night ⇒ `available = False`.

> The intersection-across-the-span check is what HTL-017 (the stay-search engine, a
> separate Tier-2 cluster — forward ref) calls per candidate room type to filter
> search results; `check_availability` is the reusable primitive it composes. The
> summed multi-night PRICE half lives in the rate-plan cluster (also separate) — HTL-012
> answers only "are there rooms?", not "what does it cost".

**Router** `app/routers/hotel_availability.py` (new):
```python
hotel_availability_router = APIRouter(prefix="/ui/hotels", tags=["hotel-availability"])
```
Every handler calls `_require_enabled()` first (delegating to
`hotel_availability._require_enabled()`, exactly like `app/routers/inventory.py:31-33`).
Register in `app/main.py` next to `inventory_router` (import + `include_router`).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/availability/calendar` | `require_ui_session` | `availability_calendar` (query `start_date`, `end_date`) |
| GET | `/ui/hotels/{hotel_id}/availability/check` | `require_ui_session` | `check_availability` (query `room_type_id`, `checkin`, `checkout`, `rooms_needed`) |
| GET | `/ui/hotels/{hotel_id}/availability/{room_type_id}` | `require_ui_session` | `get_availability` (query `checkin`, `checkout`) |
| PUT | `/ui/hotels/{hotel_id}/availability/{room_type_id}/total-rooms` | `require_admin_or_root_csrf` | `set_total_rooms` |
| POST | `/ui/hotels/{hotel_id}/availability/{room_type_id}/hold` | `require_admin_or_root_csrf` | `hold_rooms` |
| POST | `/ui/hotels/{hotel_id}/availability/holds/{hold_id}/release` | `require_admin_or_root_csrf` | `release_hold` |
| PUT | `/ui/hotels/{hotel_id}/availability/{room_type_id}/overbooking` | `require_admin_or_root_csrf` | `set_overbooking_allowance` |
| PUT | `/ui/hotels/{hotel_id}/availability/{room_type_id}/min-max` | `require_admin_or_root_csrf` | `set_min_max_availability` |

> **Declaration order (literal-before-dynamic).** Declare the literal-segment routes
> `/availability/calendar`, `/availability/check`, and `/availability/holds/{hold_id}/release`
> BEFORE the dynamic `/availability/{room_type_id}` route so FastAPI does not capture
> `calendar` / `check` / `holds` as a `room_type_id` path param — the same gotcha as the
> KYC `/templates`-before-`/{case_id}` and audit-export `/schedules`-before-`/{export_id}`
> ordering noted in CLAUDE.md, and the open-property
> `/portfolio/occupancy`-before-`/{property_id}` ordering
> (`docs/open-property/PROPERTY_UNITS_TICKETS.md` PROP-004).

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py`. Add `GET:/ui/hotels/...` read routes to any API-key route
exemptions only if a public booking surface needs them (deferred to the storefront
cluster).

**Acceptance Criteria**
- `availability_calendar` returns per-room-type per-date rows for a hotel over a range,
  grouped by `room_type_id`, sourced from `GSI_HOTEL_DATE` (no full scan).
- `check_availability` returns `available = True` only when EVERY night of
  `[checkin, checkout)` has `remaining >= rooms_needed`; a single insufficient night ⇒
  `available = False`; `min_remaining` equals the binding (smallest) night.
- A stay whose checkout date is itself sold-out is STILL bookable (checkout night
  excluded from the span).
- All 8 endpoints respond; flag off → every endpoint 404s (router still mounted,
  byte-for-byte unchanged platform).
- Read endpoints accept a UI session; mutation endpoints reject non-admin / missing-CSRF
  (per `require_admin_or_root_csrf`).
- `/availability/calendar` and `/availability/check` resolve to their own handlers, NOT
  captured by `/availability/{room_type_id}` (literal routes declared first).
- `hotel_availability_router` imported + `include_router`'d in `app/main.py` adjacent to
  `inventory_router`.

**Dependencies**: HTL-010 (`get_availability`, `GSI_HOTEL_DATE`), HTL-011 (hold/overbooking/
min-max services). Reuses: `app/routers/inventory.py:31-33` (router `_require_enabled`
idiom + auth split), `app/auth/policy.py:100`, `app/services/sessions.py:330`,
`app/core/cursor.py` (if calendar paginates), `app/main.py` (`inventory_router`
registration). Contrasts: OFBiz `check`-equivalent is a single scalar read with no span
intersection (`docs/ofbiz/specs/OFB-003.md`).

---

### HTL-013: Frontend availability calendar grid + hermetic + E2E tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2.5d

**Description**

Build the availability calendar UI (a per-room-type × per-date grid showing remaining
rooms, with admin controls to set `total_rooms`, block/hold dates, and set overbooking)
and the hermetic backend + E2E tests. Gap analysis §B ("Availability calendar (bookable
dates + remaining room counts)" — MISSING). Follow the established frontend feature recipe
(CLAUDE.md "Adding a new feature" steps 5–9).

Frontend (`frontend/src/`):
- **Types** — add `AvailabilityDay`, `AvailabilityCalendar`, `AvailabilityCheck`, `Hold`
  and the in/set shapes to `frontend/src/api/types.ts` (mirror the `app/models.py` HTL
  models).
- **API endpoints** — `frontend/src/api/endpoints/hotelAvailability.ts` wrapping the
  axios instance (`frontend/src/api/client.ts`): `getCalendar`, `checkAvailability`,
  `getAvailability`, `setTotalRooms`, `holdRooms`, `releaseHold`, `setOverbooking`,
  `setMinMax`.
- **Pages** under `frontend/src/pages/hotels/`:
  - `AvailabilityCalendarPage.tsx` — a **grid**: **room-type rows × date columns**, each
    cell showing the remaining count for that `(room_type, date)` (color-coded:
    sold-out / low / open; held/overbooked badges). A date-range picker drives
    `getCalendar`; React Query `useQuery`. Admin-only controls (gated by role): a
    "Set total rooms" dialog (room type + date range + count → `setTotalRooms`), a
    "Block / hold dates" dialog (→ `holdRooms`), and an "Overbooking" dialog (→
    `setOverbooking`), each React Hook Form + Zod. shadcn/ui primitives (`Card`,
    `Dialog`, `Badge`, `Button`, `Table`, `components/ui/`).
- **Route** — lazy-load the page in `frontend/src/App.tsx` (cf. the lazy-import block):
  `/hotels/:hotelId/availability` → `AvailabilityCalendarPage`.
- **Sidebar** — add an "Availability" nav item (lucide `CalendarRange`/`Grid` icon,
  `path` to the hotel availability route) to
  `frontend/src/components/layout/Sidebar.tsx` (cf. the nav-item array). Show
  unconditionally (the routes 404 server-side when `HOTEL_PMS_ENABLED` is off) or gate on
  a `hotelPmsEnabled` flag if the sidebar already reads feature flags.

Tests:
- **Hermetic pytest** `tests/test_htl_availability.py` — moto-bound `hotel_availability`
  table on frozen `T` (`object.__setattr__`, restored on cleanup), frozen `S` with
  `hotel_pms_enabled` toggled via `object.__setattr__`, route coroutines called directly
  on a fresh `asyncio.new_event_loop()` (no `TestClient`); `_audit`/`alerts.audit_event`
  patched to no-ops. Cover:
  - **date-range seeding** — `set_total_rooms` over a range writes one row per date;
    re-set preserves `booked`/`held`/`overbooking`.
  - **conditional decrement** — `hold_rooms` increments `held` across the span; an
    over-capacity hold 409s and leaves `held` unchanged on every night (rollback).
  - **span-intersection check** — `check_availability` is `False` when ANY single night
    is short, `True` only when all nights satisfy `rooms_needed`; `min_remaining`
    correct; checkout-night exclusion verified.
  - **overbooking** — a hold/check that fits only because of `overbooking_allowance`
    succeeds; `min_availability` floor rejects a hold that would breach it.
  - **flag-off 404** — every service entrypoint + route handler 404s when
    `hotel_pms_enabled` is false.
  - **route ordering** — `/availability/calendar` + `/availability/check` not captured by
    `/availability/{room_type_id}`.
  - **hold TTL** — `expire_due_holds(now=expires_at+1)` expires + restores `held`.
- **E2E** `frontend/e2e/hotel-availability.spec.ts` — cookie-auth (`injectAuth`) admin
  sets `total_rooms` for a room type over a date range, asserts the calendar grid renders
  the remaining counts; holds dates and asserts the cell count drops; runs an availability
  check across a span and asserts the result; CSRF header on mutations (`x-csrf-token`).
  Requires `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- `/hotels/:hotelId/availability` renders a room-type × date grid with per-cell remaining
  counts, reachable via the new sidebar nav item.
- Admin "set total rooms", "block/hold", and "overbooking" flows work end-to-end against
  the HTL-012 router; the grid reflects the change after refetch.
- Sold-out / low / open cells are visually distinguished; held/overbooked badges shown.
- `tests/test_htl_availability.py` passes offline (no AWS, no live stack), covering
  date-range seeding, conditional decrement, span-intersection check, overbooking, and
  flag-off 404.
- `frontend/e2e/hotel-availability.spec.ts` passes with the flag on.

**Dependencies**: HTL-012 (router/endpoints) — and transitively HTL-010/011. Reuses:
`frontend/src/api/client.ts`, `frontend/src/App.tsx` (lazy routes),
`frontend/src/components/layout/Sidebar.tsx` (nav items), shadcn/ui (`components/ui/`),
React Query + RHF/Zod conventions (CLAUDE.md frontend conventions), hermetic-test recipe
(`docs/ofbiz/specs/OFB-004.md` §9.1, `docs/open-property/PROPERTY_UNITS_TICKETS.md`
PROP-005), CLAUDE.md E2E patterns. Contrasts: OFBiz inventory has no calendar surface —
its UI is a single per-SKU stock number (`docs/ofbiz/specs/OFB-003.md`).

---

## Dependency order

HTL-010 (model + table + flag + seed/set) → HTL-011 (block/hold + overbooking + min/max
controls) → HTL-012 (read/calendar API + booking-time check + router + `main.py`
registration) → HTL-013 (frontend calendar grid + hermetic + E2E tests).
