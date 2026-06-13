# HTL — Front-desk / back-office console (Hotel-PMS spine, gap analysis §C)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §C ("Reservation Lifecycle +
Front Desk + Booking Engine + Guests"). QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) is an open-source hotel
property-management system + booking engine whose **front-desk / back-office console** is
the gap analysis's **MISSING** operational surface (gap analysis §C row "Front desk
(arrivals/departures/in-house, walk-in, assign room, check-in/out, room-move)" — "no
front-desk console; calendar admin views + PROP occupancy roll-up are adjacent, no
room-assignment/check-in actions").

This is a **net-new operational layer over the reservation entity** — it owns NO new
durable record. It is a thin console of **queries and actions over the existing
`hotel_reservations` reservation entity (HTL-018) and its lifecycle / check-in transitions
(HTL-019)** and the `hotel_rooms` physical-room table (HTL-006/007). HTL-018/019 are a
**forward dependency in a separate Tier-2 reservations cluster file** (not built here —
referenced by id throughout); this cluster assumes their table + GSIs + create/check-in
services exist and composes them. The closest structural analogue for the *views* is the
OFBiz **order-management console** state buckets and the existing **ticket boards**
(`app/services/tickets.py` — default-column board pattern, `app/services/tickets.py:56-70`)
which the front-desk FE tabs (arrivals / departures / in-house) re-skin: each tab is a
status-bucketed column list, exactly the board-column idiom (`default_board_columns`,
`app/services/tickets.py:69-70`). **We reuse the board column shape and the
`{items, count, cursor}` list contract but NOT the ticket entity** — front-desk rows are
reservations, not tickets.

These three tickets cover ONLY the front-desk query service, the front-desk action service
(walk-in / assign-room / room-move, each wrapping the HTL-018/019 reservation+room
services), the router, and the FE console + tests (gap analysis §C front-desk row). The
reservation entity + lifecycle itself (HTL-018/019), the stay-search engine (HTL-017), the
booking-engine storefront, folios, deposits, cancellation policy, and KPI reports are out
of scope here (separate clusters in the gap analysis Tier-2/Tier-3).

## Cross-cutting constraints (apply to every HTL ticket)

- **Additive + flag-gated, default OFF.** The master flag `HOTEL_PMS_ENABLED` (default
  `false`, added in HTL-010) gates the whole hotel vertical. Mirror the
  `INVENTORY_RESERVATIONS_ENABLED` contract exactly: `_flag_on()` / `_require_enabled()`
  raising **404** when off — the same 404 no-op idiom as the 404 contract at
  `app/services/inventory.py:51-58` and `app/routers/inventory.py:31-33`. Routers are
  always mounted; every handler is a 404 no-op until opt-in. With the flag off the platform
  is byte-for-byte unchanged.
- **No NEW table.** This cluster adds NO DynamoDB table — every operation is a query or an
  action over the existing `hotel_reservations` (HTL-018) and `hotel_rooms` (HTL-006)
  tables via their GSIs. Single-table reuse only.
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor pagination
  (`app/core/cursor.py`), the `_audit()` lazy-import wrapper
  (`app/services/inventory.py:92-98`), table handles via `T.*`
  (`app/core/tables.py:317-319,569-571`), the HTL-018 hotel+checkin GSIs and HTL-019
  check-in transition. The FE tabs reuse the ticket-board column shape
  (`app/services/tickets.py:56-70`). Auth: reads → `require_ui_session`
  (`app/services/sessions.py:330`); mutations → `require_admin_or_root_csrf`
  (`app/auth/policy.py:100`) — identical split to `app/routers/inventory.py` (reads on
  `require_ui_session`, mutations on `require_admin_or_root_csrf`).
- **GSI-backed, no scans.** Every arrivals/in-house query MUST use an HTL-018
  GSI (`GSI_HOTEL_ARRIVALS` — the hotel+checkin-date index — for arrivals;
  `GSI_HOTEL_STATUS` — hotel+status — for in-house) — never a table scan. **Departures have
  no dedicated index**: HTL-018 exposes NO checkout GSI, so departures are derived from
  `GSI_HOTEL_STATUS` (`status == "checked_in"`) with an in-memory `checkout == date` filter.
  Pagination via cursor where a result set can exceed one page.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). Mirrors `app/services/inventory.py:27-29`.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`,
  restored on cleanup), frozen `S` flags toggled via `object.__setattr__`, route coroutines
  called directly on a fresh `asyncio.new_event_loop()` — no `TestClient`, no real AWS.
  Mirrors the `docs/open-property/PROPERTY_UNITS_TICKETS.md` and
  `docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md` test recipes.

---

### HTL-022: Front-desk query service — arrivals / departures / in-house / occupancy snapshot

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add the read-only front-desk query service: the four operational "today" views every hotel
front desk needs — who is arriving, who is departing, who is currently in-house, and the
live occupancy snapshot. Net-new operational layer; it owns no record and adds no table —
it composes GSI queries over the HTL-018 `hotel_reservations` entity (forward dep) and the
HTL-006 `hotel_rooms` table. The OFBiz order-console status buckets are the conceptual
analogue we re-skin (status-bucketed lists), but these are reservations, not orders.

**DDB**: NO new table. Queries the HTL-018 `hotel_reservations` table via its GSIs (forward
dep — assumed to exist exactly as specified in the Tier-2 reservations cluster):
- `GSI_HOTEL_ARRIVALS` — PK=`hotel_id`, SK=`checkin` (`YYYY-MM-DD`, `S`; lexical ==
  chronological) — arrivals-by-date. (HTL-018; authoritative name per the audit below — the
  earlier `GSI_HOTEL_CHECKIN` label is non-canonical.)
- **No checkout index.** HTL-018 exposes NO `GSI_HOTEL_CHECKOUT`. Departures-by-date are
  derived from `GSI_HOTEL_STATUS` (`status == "checked_in"`) filtered in-memory to
  `checkout == date` — there is no checkout-keyed GSI. (HTL-018.)
- `GSI_HOTEL_STATUS` — PK=`hotel_id`, SK=`status` (`S`; `confirmed`/`checked_in`/
  `checked_out`/`no_show`/`cancelled`) — in-house = `status == "checked_in"`; also the source
  for departures (status=="checked_in" + in-memory `checkout == date`). (HTL-018.)
- `hotel_rooms` `GSI_HK_STATUS` (PK=`hotel_id`, SK=`housekeeping_status`,
  `docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md` HTL-006) for the room side of the
  occupancy snapshot.

Pydantic models in `app/models.py`: `FrontDeskRow` (a reservation projection for a console
row: `reservation_id`, `hotel_id`, `room_type_id`, `guest_name`, `guest_sub`, `checkin`,
`checkout`, `status`, `nights`, `occupancy_adults`, `occupancy_children`,
`assigned_room_ids`, `total_cents`), `FrontDeskListOut` (`{rows: [FrontDeskRow], count,
cursor}`), `OccupancySnapshotOut` (`hotel_id`, `date`, `rooms_total`, `rooms_occupied`,
`rooms_available`, `rooms_out_of_service`, `occupancy_rate`, `arrivals_count`,
`departures_count`, `in_house_count`).

Service `app/services/hotel_front_desk.py` (new), modeled on the read paths in
`app/services/inventory.py` + the list-shape contract used across the codebase:
- `_flag_on()` / `_require_enabled()` → 404 when off (copy the idiom at
  `app/services/inventory.py:51-58`; checks `getattr(S, "hotel_pms_enabled", False)`).
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy
  `app/services/inventory.py:92-98`) — used by HTL-023; the queries themselves are
  read-only and need not audit.
- `_row_from_reservation(item) -> dict` — projects a `hotel_reservations` META item into a
  `FrontDeskRow` shape (computes `nights = days_between(checkin, checkout)`).
- `arrivals_today(hotel_id, *, date=None, cursor=None, limit=50) -> dict` — `date` defaults
  to today (derived from `now_ts()`, `app/core/time.py:2`); queries `GSI_HOTEL_ARRIVALS`
  (PK=`hotel_id`, SK `checkin == date`) filtered to `status == "confirmed"` (a reservation
  arriving today that is not yet checked in). Returns `{rows, count, cursor}` (the
  `{items, count, cursor}` contract used by `host_inventory.list_hosts`, per CLAUDE.md —
  here keyed `rows`). GSI-backed, no scan.
- `departures_today(hotel_id, *, date=None, cursor=None, limit=50) -> dict` — there is **no
  checkout GSI** (HTL-018 exposes none), so departures derive from `GSI_HOTEL_STATUS`
  (PK=`hotel_id`, SK `status == "checked_in"`) with an **in-memory `checkout == date`
  filter** (still in-house, due to depart today). Returns `{rows, count, cursor}`. GSI-backed
  (no scan; the `checkout == date` predicate is applied in-memory over the checked-in page).
- `in_house(hotel_id, *, cursor=None, limit=50) -> dict` — queries `GSI_HOTEL_STATUS`
  (PK=`hotel_id`, SK `status == "checked_in"`) — every guest currently checked in
  regardless of date. Returns `{rows, count, cursor}`. GSI-backed, no scan.
- `occupancy_snapshot(hotel_id, *, date=None) -> dict` — the live snapshot for `date`
  (default today): tallies physical rooms from `hotel_rooms` `GSI_HK_STATUS`
  (`rooms_out_of_service` = `housekeeping_status == "out_of_service"` count; `rooms_total` =
  all non-archived rooms) and occupied rooms from the in-house reservations'
  `assigned_room_ids` (`rooms_occupied` = distinct assigned room ids across `checked_in`
  reservations; `rooms_available = rooms_total - rooms_occupied - rooms_out_of_service`,
  clamped ≥ 0). Computes `occupancy_rate = rooms_occupied / max(rooms_total, 1)` (0..1,
  never divides by zero — mirrors `portfolio_occupancy_rollup`'s
  `occupied / max(unit_count, 1)`, `docs/open-property/PROPERTY_UNITS_TICKETS.md` PROP-003)
  and `arrivals_count` / `departures_count` / `in_house_count` from the three queries
  above. Pure GSI aggregation — no scan.

All entrypoints call `_require_enabled()` first.

**DDB table**: NONE (this cluster adds no table — queries over HTL-018 `hotel_reservations`
+ HTL-006 `hotel_rooms` via their existing GSIs only).

**Acceptance Criteria**
- `arrivals_today` returns only `confirmed` reservations whose `checkin == date`, sourced
  from `GSI_HOTEL_ARRIVALS` (no scan); `departures_today` returns only `checked_in`
  reservations whose `checkout == date`, sourced from `GSI_HOTEL_STATUS`
  (`status == "checked_in"`) + an in-memory `checkout == date` filter (there is **no**
  `GSI_HOTEL_CHECKOUT`); `in_house` returns every `checked_in` reservation via
  `GSI_HOTEL_STATUS`.
- All three list queries return the `{rows, count, cursor}` shape and paginate via cursor.
- `date` defaults to today (derived from `now_ts()`); an explicit `date` overrides it.
- `occupancy_snapshot` computes `rooms_occupied` from distinct in-house `assigned_room_ids`,
  `rooms_out_of_service` from `GSI_HK_STATUS`, `occupancy_rate` in 0..1 with no
  divide-by-zero on a hotel with zero rooms.
- Every query goes through a GSI — no full table scan anywhere.
- `HOTEL_PMS_ENABLED` off → every `hotel_front_desk` service entrypoint raises HTTP 404 via
  `_require_enabled()`.
- No `if S.dev_mode` branch in `hotel_front_desk.py` (SECOPS-007).

**Dependencies**: HTL-018 (`hotel_reservations` table + `GSI_HOTEL_ARRIVALS` /
`GSI_HOTEL_STATUS` / `GSI_GUEST` + reservation entity — forward dep, separate
Tier-2 cluster; note there is NO `GSI_HOTEL_CHECKOUT` — departures derive from
`GSI_HOTEL_STATUS` + in-memory `checkout == date`), HTL-006 (`hotel_rooms` table + `GSI_HK_STATUS`,
`docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md`), HTL-010 (`HOTEL_PMS_ENABLED`
flag + settings block, `docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`). Reuses:
`app/services/inventory.py:51-58,92-98` (flag/audit idioms), `app/core/time.py:2`
(`now_ts`), `app/core/cursor.py` (pagination), `{items,count,cursor}` list contract
(CLAUDE.md `host_inventory.list_hosts`), `portfolio_occupancy_rollup` `max(.,1)` guard
(`docs/open-property/PROPERTY_UNITS_TICKETS.md` PROP-003). Contrasts: OFBiz order console
buckets orders, not reservations; no occupancy/room dimension.

---

### HTL-023: Front-desk action service — walk-in / assign-room / change-room / room-move

**Type**: Feature
**Priority**: P1
**Estimate**: 2.5d

**Description**

Add the front-desk action service: the mutating operations a front-desk agent performs.
Each action **wraps existing reservation (HTL-018/019) and room (HTL-006/007) services** —
it adds no new record and no new table, only orchestration + version-gating + audit over
the existing entities. Net-new operational layer (gap analysis §C "walk-in, assign room,
room-move").

**DDB**: NO new table. Mutates the HTL-018 `hotel_reservations` META item (`assigned_room_ids`,
`status`, `version`) and the HTL-006 `hotel_rooms` room row (`housekeeping_status` /
occupancy flip) via their existing services.

Pydantic models in `app/models.py`: `WalkInBookingIn` (`hotel_id`, `room_type_id`,
`checkin`, `checkout`, `occupancy_adults`, `occupancy_children`, `guest_name`,
optional `guest_sub`, optional `assigned_room_ids`, optional `total_cents` /
rate-plan inputs as HTL-018 `create` expects), `AssignRoomIn` (`assigned_room_ids: list[str]`,
`version: int`), `RoomMoveIn` (`from_room_id`, `to_room_id`, `version: int`),
`FrontDeskActionOut` (the updated `FrontDeskRow` + the affected room rows). `version` is the
HTL-018 reservation optimistic-concurrency field (mirrors the ORD/LSE state-machine
`version` bump the reservation entity clones — gap analysis §C).

Service additions in `app/services/hotel_front_desk.py`:
- `walk_in_booking(hotel_id, *, room_type_id, checkin, checkout, occupancy_adults,
  occupancy_children, guest_name, guest_sub=None, assigned_room_ids=None, user_sub, **rate)
  -> dict` — creates a reservation AND immediately checks it in, in one front-desk action.
  Delegates to the HTL-018 `reservations.create_reservation(...)` (the same create path the
  booking storefront uses — never re-implemented; reuses its availability decrement + total
  computation) then to the HTL-019 `reservations.check_in(reservation_id, *, version,
  assigned_room_ids, user_sub)` transition. If `assigned_room_ids` are supplied they flow
  into check-in (and each room is flipped per `assign_room` below); otherwise the
  reservation is checked in unassigned (assign later via `assign_room`). One
  `_audit("hotel.frontdesk.walk_in", ...)`. Wraps existing services — no duplicated
  reservation/availability logic.
- `assign_room(hotel_id, reservation_id, *, assigned_room_ids, version, user_sub) -> dict` —
  sets `assigned_room_ids` on the reservation via a version-gated `update_item`
  (`ConditionExpression="version = :v"` → 409 on stale version, the optimistic-concurrency
  guard the reservation entity carries from the ORD/LSE clone) and, for each newly assigned
  room, flips the `hotel_rooms` room row's occupancy/housekeeping via the HTL-007
  `room_inventory.set_room_housekeeping_status(hotel_id, room_id, housekeeping_status="...",
  user_sub=...)` (`docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md` HTL-007 — the room
  flips to an occupied/dirty-on-departure posture; the exact target enum lives with HTL-007,
  this action calls its setter, never writes the room row directly). Audits
  `hotel.frontdesk.assign_room`.
- `change_room(hotel_id, reservation_id, *, assigned_room_ids, version, user_sub) -> dict` —
  the same shape as `assign_room` but for a reservation that already has assignments:
  computes the symmetric difference, frees the rooms being dropped (flip their
  `housekeeping_status` back via the HTL-007 setter) and occupies the rooms being added,
  then version-gated-writes the new `assigned_room_ids`. Audits
  `hotel.frontdesk.change_room`.
- `room_move(hotel_id, reservation_id, *, from_room_id, to_room_id, version, user_sub) ->
  dict` — moves a single checked-in guest from `from_room_id` to `to_room_id`: validates the
  reservation is `checked_in` (else 409) and `from_room_id` is in its `assigned_room_ids`
  (else 404), swaps the id in `assigned_room_ids` (version-gated write), frees `from_room_id`
  and occupies `to_room_id` via the HTL-007 setter. Audits `hotel.frontdesk.room_move`.

Every mutation is version-gated (optimistic-concurrency `version = :v` CAS → 409 on
conflict, the same one-winner guard as `inventory`'s status-CAS,
`app/services/inventory.py:434-453`), audited, and calls `_require_enabled()` first. All
room-side flips route through the HTL-007 setter — this service never writes a `hotel_rooms`
row directly (one owner per table).

**DDB table**: NONE (wraps HTL-018 `hotel_reservations` + HTL-006 `hotel_rooms`; no new
table).

**Acceptance Criteria**
- `walk_in_booking` creates a reservation via the HTL-018 create service and immediately
  transitions it to `checked_in` via the HTL-019 check-in service — one call, status ends
  `checked_in`; it reuses (does not re-implement) the reservation create + availability
  decrement.
- `assign_room` writes `assigned_room_ids` only when `version` matches (stale version →
  409) and flips each assigned room via the HTL-007 housekeeping setter (never writes the
  room row directly).
- `change_room` frees dropped rooms and occupies added rooms (symmetric diff) and writes the
  new assignment version-gated.
- `room_move` swaps one room id in `assigned_room_ids`, rejects a move whose `from_room_id`
  is not assigned (404) or whose reservation is not `checked_in` (409), and flips both the
  freed and occupied rooms.
- Every action emits an `_audit(...)` event and 404s when `HOTEL_PMS_ENABLED` is off.
- No `if S.dev_mode` branch (SECOPS-007); no `hotel_rooms` row written outside the HTL-007
  setter.

**Dependencies**: HTL-022 (`hotel_front_desk` module + flag/audit + `_row_from_reservation`),
HTL-018 (`reservations.create_reservation` + the `version`-gated reservation META,
forward dep), HTL-019 (`reservations.check_in` transition, forward dep), HTL-007
(`room_inventory.set_room_housekeeping_status` room flip,
`docs/qloapps/ROOMTYPES_ROOMS_HOUSEKEEPING_TICKETS.md`). Reuses:
`app/services/inventory.py:51-58,92-98` (flag/audit), `:434-453` (status/version CAS
one-winner idiom), `app/core/time.py:2`. Contrasts: OFBiz order edits mutate an order, not a
room↔reservation assignment; there is no physical-room dimension to flip.

---

### HTL-024: Router `/ui/hotels/{hotel_id}/front-desk` + FrontDeskPage FE + tests

**Type**: Feature
**Priority**: P1
**Estimate**: 3d

**Description**

Expose the front-desk services over HTTP via a new `hotel_front_desk_router`, modeled
exactly on `app/routers/inventory.py` (auth split + `_require_enabled()` short-circuit),
and build the FrontDeskPage console + hermetic backend + E2E tests. Gap analysis §C
("Front desk — MISSING"). Follow the established frontend feature recipe (CLAUDE.md "Adding
a new feature" steps 3–9).

**Router** `app/routers/hotel_front_desk.py` (new):
```python
hotel_front_desk_router = APIRouter(prefix="/ui/hotels", tags=["hotel-front-desk"])
```
Every handler calls `_require_enabled()` first (delegating to
`hotel_front_desk._require_enabled()`, exactly like `app/routers/inventory.py:31-33`).
Register in `app/main.py` next to `inventory_router` (import + `include_router`,
`app/main.py` `inventory_router` registration site).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/front-desk/arrivals` | `require_ui_session` | `arrivals_today` (query `date`, `cursor`, `limit`) |
| GET | `/ui/hotels/{hotel_id}/front-desk/departures` | `require_ui_session` | `departures_today` (query `date`, `cursor`, `limit`) |
| GET | `/ui/hotels/{hotel_id}/front-desk/in-house` | `require_ui_session` | `in_house` (query `cursor`, `limit`) |
| GET | `/ui/hotels/{hotel_id}/front-desk/occupancy` | `require_ui_session` | `occupancy_snapshot` (query `date`) |
| POST | `/ui/hotels/{hotel_id}/front-desk/walk-in` | `require_admin_or_root_csrf` | `walk_in_booking` |
| POST | `/ui/hotels/{hotel_id}/front-desk/reservations/{reservation_id}/assign-room` | `require_admin_or_root_csrf` | `assign_room` |
| POST | `/ui/hotels/{hotel_id}/front-desk/reservations/{reservation_id}/change-room` | `require_admin_or_root_csrf` | `change_room` |
| POST | `/ui/hotels/{hotel_id}/front-desk/reservations/{reservation_id}/room-move` | `require_admin_or_root_csrf` | `room_move` |

> **Declaration order (literal-before-dynamic).** All front-desk paths sit under the static
> `/front-desk/...` segment, and the literal sub-routes (`arrivals`, `departures`,
> `in-house`, `occupancy`, `walk-in`) are declared BEFORE the dynamic
> `/front-desk/reservations/{reservation_id}/...` routes so FastAPI does not capture a
> literal as a path param — the same gotcha as the KYC `/templates`-before-`/{case_id}`,
> audit-export `/schedules`-before-`/{export_id}` (CLAUDE.md), open-property
> `/portfolio/occupancy`-before-`/{property_id}`
> (`docs/open-property/PROPERTY_UNITS_TICKETS.md` PROP-004), and HTL-012
> `/availability/calendar`-before-`/availability/{room_type_id}`
> (`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md`) ordering. Because this router shares the
> `/ui/hotels` prefix with the HTL-012 `hotel_availability_router`, the `/front-desk/`
> segment keeps the two route trees disjoint.

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py`. Mutation handlers pass `user_sub=user.sub`.

**Frontend** (`frontend/src/`):
- **Types** — add `FrontDeskRow`, `FrontDeskList`, `OccupancySnapshot`, `WalkInBookingIn`,
  `AssignRoomIn`, `RoomMoveIn` to `frontend/src/api/types.ts` (mirror the `app/models.py`
  HTL front-desk models).
- **API endpoints** — `frontend/src/api/endpoints/hotelFrontDesk.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`): `getArrivals`, `getDepartures`, `getInHouse`,
  `getOccupancy`, `walkIn`, `assignRoom`, `changeRoom`, `roomMove`.
- **Page** under `frontend/src/pages/hotels/`:
  - `FrontDeskPage.tsx` — a console with **arrivals / departures / in-house tabs built on
    the ticket-board pattern** (each tab is a status-bucketed column of reservation cards —
    re-skins the `default_board_columns` shape from `app/services/tickets.py:56-70`,
    rendered with the same Card/column layout used by the tickets board FE). An
    occupancy-snapshot summary strip at the top driven by `getOccupancy` (rooms occupied /
    available / out-of-service, occupancy rate, arrivals/departures/in-house counts). A
    **walk-in dialog** (React Hook Form + Zod → `walkIn`), and per-reservation-card
    **assign-room / change-room / room-move actions** (dialogs picking from the hotel's
    `hotel_rooms` → `assignRoom` / `changeRoom` / `roomMove`, each passing the reservation
    `version` for optimistic-concurrency). React Query `useQuery` per tab; mutations
    `invalidateQueries` the affected tab(s) + the occupancy strip. shadcn/ui primitives
    (`Card`, `Dialog`, `Tabs`, `Badge`, `Button`, `Table`, `components/ui/`).
- **Route** — lazy-load the page in `frontend/src/App.tsx` (cf. the lazy-import block):
  `/hotels/:hotelId/front-desk` → `FrontDeskPage`.
- **Sidebar** — add a "Front Desk" nav item (lucide `ConciergeBell`/`Hotel` icon, `path` to
  the front-desk route) to `frontend/src/components/layout/Sidebar.tsx` (cf. the nav-item
  array). Show unconditionally (routes 404 server-side when `HOTEL_PMS_ENABLED` is off) or
  gate on a `hotelPmsEnabled` flag if the sidebar already reads feature flags.

**Tests**:
- **Hermetic pytest** `tests/test_htl_front_desk.py` — moto-bound `hotel_reservations` +
  `hotel_rooms` tables on frozen `T` (`object.__setattr__`, restored on cleanup), frozen `S`
  with `hotel_pms_enabled` toggled via `object.__setattr__`, route coroutines called
  directly on a fresh `asyncio.new_event_loop()` (no `TestClient`); `_audit` /
  `alerts.audit_event` patched to no-ops; the HTL-018 `create_reservation` / HTL-019
  `check_in` / HTL-007 `set_room_housekeeping_status` collaborators patched at the
  `hotel_front_desk` module namespace (the reservation/room services are forward deps —
  patch, don't re-test). Cover:
  - **arrivals query** — only `confirmed` reservations with `checkin == date` via
    `GSI_HOTEL_ARRIVALS`; `date` defaults to today; `{rows, count, cursor}` shape.
  - **departures query** — only `checked_in` reservations with `checkout == date`, sourced
    from `GSI_HOTEL_STATUS` (`status == "checked_in"`) + an in-memory `checkout == date`
    filter (there is **no** `GSI_HOTEL_CHECKOUT`).
  - **in-house query** — every `checked_in` reservation via `GSI_HOTEL_STATUS`.
  - **occupancy snapshot** — `rooms_occupied` from distinct in-house `assigned_room_ids`,
    `rooms_out_of_service` from `GSI_HK_STATUS`, `occupancy_rate` 0..1, no divide-by-zero on
    a zero-room hotel.
  - **walk-in** — calls the patched create + check-in collaborators in order; result ends
    `checked_in`.
  - **assign / change / room-move** — version-gated write (stale `version` → 409); room
    flips route through the patched HTL-007 setter; `room_move` rejects an unassigned
    `from_room_id` (404) / non-`checked_in` reservation (409).
  - **flag-off 404** — every service entrypoint + route handler 404s when
    `hotel_pms_enabled` is false.
  - **route ordering** — `/front-desk/arrivals` + `/front-desk/walk-in` not captured by
    `/front-desk/reservations/{reservation_id}/...`.
- **E2E** `frontend/e2e/hotel-front-desk.spec.ts` — cookie-auth (`injectAuth`) admin opens
  the front-desk console, asserts the arrivals/departures/in-house tabs and the occupancy
  strip render; performs a walk-in (dialog → `walkIn`) and asserts the guest appears in the
  in-house tab and the occupancy count updates; assigns a room and performs a room-move,
  asserting the assignment reflects after refetch; CSRF header on mutations
  (`x-csrf-token`). Requires `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- All 8 endpoints respond; flag off → every endpoint 404s (router still mounted,
  byte-for-byte unchanged platform).
- Read endpoints accept a UI session; mutation endpoints reject non-admin / missing-CSRF
  requests (403) per `require_admin_or_root_csrf`.
- `/front-desk/arrivals` / `/departures` / `/in-house` / `/occupancy` / `/walk-in` resolve
  to their own handlers, NOT captured by `/front-desk/reservations/{reservation_id}/...`
  (literal routes declared first).
- `hotel_front_desk_router` imported + `include_router`'d in `app/main.py` adjacent to
  `inventory_router`.
- `/hotels/:hotelId/front-desk` renders arrivals/departures/in-house tabs (ticket-board
  pattern) + an occupancy strip, reachable via the new sidebar nav item; walk-in and
  assign/change/room-move flows work end-to-end against the router.
- `tests/test_htl_front_desk.py` passes offline (no AWS, no live stack), covering the three
  queries, occupancy snapshot, walk-in, assign/move, version-conflict 409, route ordering,
  and flag-off 404.
- `frontend/e2e/hotel-front-desk.spec.ts` passes with the flag on.

**Dependencies**: HTL-022 (query service), HTL-023 (action service) — and transitively
HTL-018/019 (reservation entity + check-in, forward dep), HTL-007 (housekeeping setter),
HTL-010 (`HOTEL_PMS_ENABLED` flag). Reuses: `app/routers/inventory.py:31-33` (router
`_require_enabled` idiom + auth split), `app/auth/policy.py:100`,
`app/services/sessions.py:330`, `app/main.py` (`inventory_router` registration),
`app/services/tickets.py:56-70` (board-column shape for the FE tabs),
`frontend/src/api/client.ts`, `frontend/src/App.tsx` (lazy routes),
`frontend/src/components/layout/Sidebar.tsx` (nav items), shadcn/ui (`components/ui/`),
React Query + RHF/Zod conventions (CLAUDE.md frontend conventions), hermetic-test + E2E
recipes (`docs/open-property/PROPERTY_UNITS_TICKETS.md` PROP-005,
`docs/qloapps/AVAILABILITY_INVENTORY_TICKETS.md` HTL-013, CLAUDE.md E2E patterns).
Contrasts: OFBiz order console has no room-assignment / check-in / room-move actions; the
ticket board carries tickets, not reservations.

---

## Dependency order

HTL-022 (front-desk query service: arrivals/departures/in-house/occupancy over HTL-018/006
GSIs) → HTL-023 (front-desk action service: walk-in/assign-room/change-room/room-move
wrapping HTL-018/019/007) → HTL-024 (router + `main.py` registration + FrontDeskPage FE +
hermetic + E2E tests).

Forward dependency (separate Tier-2 reservations cluster, referenced by id, NOT built here):
HTL-018 (`hotel_reservations` entity + `GSI_HOTEL_ARRIVALS` / `GSI_HOTEL_STATUS` / `GSI_GUEST`
+ `create_reservation`; there is NO `GSI_HOTEL_CHECKOUT` — departures derive from
`GSI_HOTEL_STATUS` + in-memory `checkout == date`) and HTL-019 (reservation lifecycle /
`check_in` transition + optimistic-concurrency `version`).

---

### Cross-ticket reconciliation (audit 2026-06-13)

Per `docs/CROSS_TICKET_AUDIT.md §B4` (row 2): this ticket's earlier prose named the
reservation GSIs `GSI_HOTEL_CHECKIN` / `GSI_HOTEL_CHECKOUT`. The **authoritative** HTL-018
index names are `GSI_HOTEL_ARRIVALS` / `GSI_HOTEL_STATUS` / `GSI_GUEST`, and **there is no
checkout index**. Reconciled throughout this file:

- **Arrivals** → `GSI_HOTEL_ARRIVALS` (PK=`hotel_id`, SK=`checkin`); the old `GSI_HOTEL_CHECKIN`
  label was the non-canonical name for the same index.
- **Departures** → derived from `GSI_HOTEL_STATUS` (`status == "checked_in"`) + an in-memory
  `checkout == date` filter. The `GSI_HOTEL_CHECKOUT` index does **not** exist (HTL-018
  exposes none); `departures_today` must NOT query a checkout-keyed GSI.
- **In-house** → `GSI_HOTEL_STATUS` (`status == "checked_in"`), unchanged.

This aligns the FRONT_DESK prose with the HTL-018-owned GSI contract; no schema or behavior
change beyond the departures derivation (which was already GSI-backed, just over the status
index rather than a non-existent checkout index).
