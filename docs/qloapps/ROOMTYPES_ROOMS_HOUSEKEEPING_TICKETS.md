# HTL — Room Types + Rooms + Housekeeping (Hotel-PMS spine, gap analysis §A)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §A
("Hotels + Room Types + Rooms + Housekeeping"). QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) is an open-source hotel
property-management system + booking engine whose **Room Type** (the bookable nightly
"product" per hotel), individual **Room** (physical instance), and **Housekeeping**
(clean/dirty/inspected/out-of-service + task assignment) entities are flagged as the
genuinely net-new hospitality spine:

- A **Room Type** is the bookable nightly product per hotel. The generic catalog item
  (`app/services/catalog.py` — `name`/`price_cents`/`image_urls` + free-form
  `attributes`, gap analysis §A row 2) is a **PARTIAL** analogue but carries **no
  occupancy/bed-type/per-hotel semantics**, so Room Type is modeled fresh (occupancy
  adults/children + max, bed type, size, base nightly rate, photos).
- A **Room** is the physical instance and is structurally **≈ an open-property PROP-002
  Unit** (`docs/open-property/specs/PROP-002.md`) — we reuse that header/child table
  idiom and CRUD service shape, NOT the rental-dwelling field set.
- **Housekeeping** is net-new; the only weak overlap is the PROP-002 Unit
  `occupancy_status` (vacant/occupied/turnover), which is a **rental flag, not a cleaning
  workflow** (gap analysis §A row 5). We add a per-physical-room `housekeeping_status`
  enum + a housekeeping task entity (assignment to a staff user, lifecycle).

These five tickets cover ONLY Room Types, Rooms, and Housekeeping + their router + FE
(gap analysis §A rows 2, 3, 5). Per-date availability inventory, nightly rate plans,
reservations, front desk, the booking-engine storefront, folios, and KPI reports are
out of scope here (separate HTL clusters in the gap analysis Tier 1/2/3). The **Hotel**
entity + amenities (HTL-001..HTL-004, gap analysis §A rows 1, 4) is a sibling cluster
that lands the `hotels` table + master flag this cluster depends on.

## Cross-cutting constraints (apply to every HTL ticket)

- **Additive + flag-gated, default OFF.** The whole Hotel-PMS vertical is gated by the
  master flag `HOTEL_PMS_ENABLED` (default `false`), landed in the HTL-001 hotels
  cluster. Mirror the `INVENTORY_RESERVATIONS_ENABLED` contract exactly: `_flag_on()` /
  `_require_enabled()` raising **404** when off, per `app/services/inventory.py:50-56`
  and `app/routers/inventory.py:32-34`. Routers are always mounted; every handler is a
  404 no-op until opt-in. With the flag off the platform is byte-for-byte unchanged.
- **Single-table DynamoDB header+child idiom.** Room Types are child rows
  (`ROOMTYPE#{id}`) co-located with the hotel `META` header on the `hotels` partition —
  the FAC header+child pattern (`docs/ofbiz/specs/FAC-001.md` §3 "Table: `facilities`",
  SK=`META` header + SK=`LOC#{id}` child rows). Rooms get their own per-hotel table
  (`hotel_rooms`, PK=`hotel_id`) so a hotel's room grid is one cheap partition query,
  structurally the PROP-002 Unit child-row pattern (`docs/open-property/specs/PROP-002.md`
  — a Room ≈ a PROP Unit) but keyed by hotel rather than nested under the room-type.
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key (e.g. `created_at`)
  MUST be declared in the `TableDef` `attr_types` map per the CLAUDE.md DynamoDB
  numeric-GSI gotcha — omitting it stores the value as String → `ValidationException`.
  Pattern: `scripts/local-ddb-init.py:29-48` `TableDef(...)` calls.
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor
  pagination (`app/core/cursor.py:94,103`), the `_audit()` lazy-import wrapper
  (`app/services/inventory.py:92-98`), table handles via `T.*` (`app/core/tables.py`).
  Auth: reads → `require_ui_session` (`app/services/sessions.py:330`); mutations →
  `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical split to
  `app/routers/inventory.py:37,46,63,79`.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). Mirrors `app/services/inventory.py:27-29`.
- **No-raise delete contract.** Room delete returns `False` (never raises) for an unknown
  room, mirroring `host_inventory.delete_host` (`app/services/host_inventory.py:360`,
  CLAUDE.md K8s/EC2 host-inventory notes).
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`),
  frozen `S` flags toggled the same way, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` — no `TestClient`, no real AWS. Mirrors the FAC-001 §9 and
  PROP-005 hermetic recipe.

---

### HTL-005: Room Type entity — child rows on the `hotels` partition

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Add the Room Type entity — the bookable nightly "product" per hotel — as
`ROOMTYPE#{room_type_id}` child rows co-located with the hotel `META` header on the
`hotels` partition (the FAC header+child idiom, `docs/ofbiz/specs/FAC-001.md` §3). Room
Type is net-new: the generic catalog item (`app/services/catalog.py`) is a PARTIAL
analogue but carries no occupancy/bed-type/per-hotel semantics (gap analysis §A row 2),
so the field set is modeled fresh.

Child row on `hotels` (PK=`hotel_id`, SK=`ROOMTYPE#{room_type_id}`):

| Attribute | Type | Notes |
|---|---|---|
| `hotel_id` | S | PK (same partition as the parent `META` row from HTL-001) |
| `sk` | S | `ROOMTYPE#{room_type_id}`, `room_type_id = uuid4().hex` (non-deterministic — a hotel may hold several types with the same name, mirroring the PROP-002 Unit id contract) |
| `room_type_id` | S | Convenience copy of the id |
| `name` | S | Room-type name (e.g. `"Deluxe King"`) |
| `description` | S | Free-text description |
| `base_occupancy_adults` | N | Included adult capacity |
| `base_occupancy_children` | N | Included child capacity |
| `max_occupancy` | N | Hard max guests (adults + children) |
| `bed_type` | S | `single` \| `twin` \| `double` \| `queen` \| `king` \| `suite` |
| `size_sqft` | N | Room size in square feet |
| `base_nightly_rate_cents` | N | Base nightly rate in cents (integer, money-as-cents convention) |
| `photo_urls` | L | List of photo URL strings |
| `status` | S | `active` \| `archived` |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |

GSI to list a hotel's room types — add to the **same** `hotels` `TableDef`:
- `GSI_HOTEL_ROOMTYPES` — PK=`hotel_id`, SK=`created_at` (numeric) — list a hotel's room
  types newest-first. Declared with `attr_types={"created_at": "N"}`.

> Note: child Room Type rows are also queryable by the existing `hotels` PK
> (`Key={"hotel_id": hid}` + `begins_with(sk, "ROOMTYPE#")`) for a per-hotel scan that
> co-reads the `META` header; the GSI above is the ordered/paginated fast path.

Pydantic models in `app/models.py`: `RoomTypeIn` (name, description,
base_occupancy_adults, base_occupancy_children, max_occupancy, bed_type, size_sqft,
base_nightly_rate_cents, photo_urls), `RoomTypeOut` (all persisted fields),
`RoomTypeUpdateIn` (partial). `bed_type`/`status` constrained to the literals above;
`max_occupancy >= base_occupancy_adults + base_occupancy_children` validated.

Service additions in `app/services/hotel_pms.py` (the cluster service landed in HTL-001),
modeled on `app/services/inventory.py` + the PROP-002 unit-CRUD shape:
- `_require_enabled()` (already present from HTL-001 → 404 when `HOTEL_PMS_ENABLED` off).
- `create_room_type(hotel_id, *, name, description, base_occupancy_adults,
  base_occupancy_children, max_occupancy, bed_type, size_sqft, base_nightly_rate_cents,
  photo_urls, user_sub) -> dict` — validates parent hotel exists + caller owns it (404 if
  missing); `uuid4().hex` room_type_id; `put_item`; `_audit("hotel.room_type.created",
  ...)`.
- `get_room_type(hotel_id, room_type_id) -> dict | None` — reads
  SK=`ROOMTYPE#{room_type_id}`.
- `list_room_types(hotel_id, *, status="active", cursor=None, limit=50) -> dict` — queries
  `GSI_HOTEL_ROOMTYPES`, optional `status` filter, paginates via
  `encode_cursor`/`decode_cursor` (`app/core/cursor.py:94,103`). Returns
  `{"room_types": [...], "count": int, "cursor": str | None}` (the `{items, count,
  cursor}` shape, per CLAUDE.md `host_inventory.list_hosts`).
- `update_room_type(hotel_id, room_type_id, *, user_sub, **kwargs) -> dict` — stamps
  `updated_at`.
- `archive_room_type(hotel_id, room_type_id, *, user_sub) -> dict` — sets
  `status="archived"`.

All entrypoints call `_require_enabled()` first.

**Acceptance Criteria**
- `GSI_HOTEL_ROOMTYPES` declared on the `hotels` `TableDef` with
  `attr_types={"created_at": "N"}`; `just restart` creates/updates the table without
  `ValidationException`.
- `create_room_type` rejects (404) a room type under a non-existent or non-owned hotel.
- Room Types co-locate on the parent `hotels` partition; `list_room_types` returns only
  `ROOMTYPE#`-prefixed rows (never the hotel `META` row) and paginates correctly.
- `base_occupancy_*`, `max_occupancy`, `size_sqft`, `base_nightly_rate_cents` round-trip
  as numerics (Decimal→int coercion handled); `max_occupancy <` sum-of-base is rejected.
- Flag off → every room-type entrypoint 404s.
- No `if S.dev_mode` branch in the room-type service code (SECOPS-007).

**Dependencies**: HTL-001 (hotels table + `HOTEL_PMS_ENABLED` flag + `hotel_pms.py`
service + parent ownership check). Reuses: FAC `ROOMTYPE#`-style child-row pattern
(`docs/ofbiz/specs/FAC-001.md` §3), `uuid4().hex` id, `now_ts()` (`app/core/time.py:2`),
`_audit` (`app/services/inventory.py:92-98`), cursor pagination (`app/core/cursor.py:94,103`),
`{items, count, cursor}` shape (CLAUDE.md). Contrasts: generic catalog item
(`app/services/catalog.py`) lacks occupancy/bed semantics.

---

### HTL-006: Individual Room entity — `hotel_rooms` table

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Add the individual Room (physical instance) entity. A Room is structurally ≈ an
open-property PROP-002 Unit (`docs/open-property/specs/PROP-002.md`) but is keyed by
hotel rather than nested under the room-type, so a hotel's room grid is one cheap
partition query. New table `hotel_rooms` (PK=`hotel_id`, SK=`ROOM#{room_id}`) — the
PROP-002 child-row idiom promoted to its own table.

DDB table `hotel_rooms` (PK=`hotel_id`, SK=`ROOM#{room_id}`):

| Attribute | Type | Notes |
|---|---|---|
| `hotel_id` | S | PK — all of a hotel's rooms on one partition |
| `sk` | S | `ROOM#{room_id}`, `room_id = uuid4().hex` (non-deterministic; a hotel may renumber rooms) |
| `room_id` | S | Convenience copy of the id |
| `room_type_id` | S | FK to the HTL-005 Room Type (validated at create) |
| `room_number` | S | Physical room number / label (e.g. `"214"`) |
| `floor` | N | Floor number |
| `status` | S | `available` \| `out_of_service` (default `available`) |
| `housekeeping_status` | S | `clean` \| `dirty` \| `inspected` \| `out_of_service` (default `clean`; the HTL-007 cleaning-workflow field, persisted on the room row) |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |

GSIs (declared in `scripts/local-ddb-init.py`, `attr_types={"created_at": "N"}`):
- `GSI_ROOMTYPE` — PK=`room_type_id`, SK=`created_at` (numeric) — list every physical room
  of a given type (across the hotel) newest-first.
- `GSI_HK_STATUS` — PK=`hotel_id`, SK=`housekeeping_status` (both `S`, no `attr_types`
  change) — query a hotel's rooms bucketed by housekeeping status (the HTL-007 board fast
  path) without scanning.

`TableDef` follows `scripts/local-ddb-init.py:29-48` exactly:
```python
TableDef(
    _resolve_table_name(S.hotel_rooms_table_name, "hotel_rooms"),
    "hotel_id",
    "sk",
    gsi=[
        {"index_name": "GSI_ROOMTYPE",  "partition_key": "room_type_id", "sort_key": "created_at"},
        {"index_name": "GSI_HK_STATUS", "partition_key": "hotel_id",     "sort_key": "housekeeping_status"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings (add to `app/core/settings.py` next to the HTL-001 hotels block, same
`os.environ.get(...)` idiom as `app/core/settings.py:841`):
```python
hotel_rooms_table_name: str = os.environ.get("HOTEL_ROOMS_TABLE_NAME", "hotel_rooms")
```
Table handle: add `hotel_rooms: Any` to the `T` dataclass (`app/core/tables.py`) and wire
`hotel_rooms=_safe_table(S.hotel_rooms_table_name)` in the initializer
(`app/core/tables.py`, alongside the existing `_safe_table(...)` calls at `:322+`).

Pydantic models in `app/models.py`: `RoomIn` (room_type_id, room_number, floor, status),
`RoomOut` (all persisted fields incl. `housekeeping_status`), `RoomUpdateIn` (partial).
`status`/`housekeeping_status` constrained to the literals above.

Service additions in `app/services/hotel_pms.py`:
- `create_room(hotel_id, *, room_type_id, room_number, floor, status, user_sub) -> dict`
  — validates parent hotel exists + caller owns it AND the `room_type_id` resolves to a
  Room Type on that hotel (404 otherwise); `uuid4().hex` room_id; `housekeeping_status`
  defaults `clean`; `put_item`; `_audit("hotel.room.created", ...)`.
- `get_room(hotel_id, room_id) -> dict | None`.
- `list_rooms(hotel_id, *, room_type_id=None, status=None, cursor=None, limit=50) -> dict`
  — by-hotel: `Key` query on the `hotel_rooms` PK with `begins_with(sk, "ROOM#")`;
  by-room-type: queries `GSI_ROOMTYPE` (PK=`room_type_id`). Optional `status` filter,
  cursor pagination. Returns `{"rooms": [...], "count": int, "cursor": str | None}`.
- `update_room(hotel_id, room_id, *, user_sub, **kwargs) -> dict` — stamps `updated_at`
  (`housekeeping_status` mutation routes through HTL-007's `set_room_housekeeping_status`,
  not this generic update).
- `delete_room(hotel_id, room_id, *, user_sub) -> bool` — deletes the row; returns `False`
  (never raises) for an unknown room (mirrors `host_inventory.delete_host`,
  `app/services/host_inventory.py:360`).

All entrypoints call `_require_enabled()` first.

**Acceptance Criteria**
- `hotel_rooms` `TableDef` present with both GSIs and `attr_types={"created_at": "N"}`;
  `just restart` creates the table without `ValidationException`.
- `T.hotel_rooms` resolves; `RoomIn/Out/UpdateIn` models import cleanly.
- `create_room` rejects (404) a room under a non-existent/non-owned hotel OR an
  unknown/foreign `room_type_id`.
- `list_rooms(hotel_id)` returns only that hotel's `ROOM#`-prefixed rows; `list_rooms(...,
  room_type_id=)` returns every room of that type via `GSI_ROOMTYPE`; both paginate.
- `delete_room` returns `False` (no exception) for an unknown room.
- Flag off → every room entrypoint 404s; no `if S.dev_mode` branch (SECOPS-007).

**Dependencies**: HTL-001 (hotels table + flag + ownership check), HTL-005 (Room Type FK
validation). Reuses: PROP-002 Unit child-row pattern (`docs/open-property/specs/PROP-002.md`),
`scripts/local-ddb-init.py:29-48` (`TableDef`), `app/core/tables.py` (handle wiring),
`app/core/settings.py:841` (settings idiom), `uuid4().hex`, `now_ts()`
(`app/core/time.py:2`), `_audit` (`app/services/inventory.py:92-98`), cursor
(`app/core/cursor.py:94,103`), `host_inventory.delete_host` no-raise contract
(`app/services/host_inventory.py:360`).

---

### HTL-007: Housekeeping status + tasks

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Add the housekeeping workflow — net-new (gap analysis §A row 5; the only weak overlap is
the PROP-002 Unit `occupancy_status`, a rental flag, NOT a cleaning workflow). Two parts:
(1) the per-physical-room `housekeeping_status` enum (clean | dirty | inspected |
out_of_service), persisted on the `hotel_rooms` room row (added in HTL-006) and mutated
through a dedicated transition function; (2) a housekeeping **task** entity (assignment to
a staff user + lifecycle), stored as `HKTASK#{task_id}` child rows on the `hotel_rooms`
partition (single-table, co-located with the room rows — the FAC header+child idiom).

Housekeeping task child row on `hotel_rooms` (PK=`hotel_id`, SK=`HKTASK#{task_id}`):

| Attribute | Type | Notes |
|---|---|---|
| `hotel_id` | S | PK (same partition as the `ROOM#` rows) |
| `sk` | S | `HKTASK#{task_id}`, `task_id = uuid4().hex` |
| `task_id` | S | Convenience copy of the id |
| `room_id` | S | The physical room this task targets |
| `assignee_sub` | S | Staff user_sub the task is assigned to (`""` until assigned) |
| `status` | S | `open` \| `in_progress` \| `done` (default `open`) |
| `due_at` | N | Due timestamp (`now_ts()`-scale; `0` if none) |
| `notes` | S | Free-text instructions |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |
| `completed_at` | N | Set on transition to `done` (`0` otherwise) |

GSIs (declared in `scripts/local-ddb-init.py`, on the **same** `hotel_rooms` `TableDef`):
- `GSI_HK_TASK_STATUS` — PK=`hotel_id`, SK=`status` (both `S`) — list a hotel's tasks
  bucketed by `open`/`in_progress`/`done` for the housekeeping board (HTL-009 FE).
- `GSI_HK_ASSIGNEE` — PK=`assignee_sub`, SK=`created_at` (numeric,
  `attr_types={"created_at": "N"}`) — list a staff member's assigned tasks newest-first.

Pydantic models in `app/models.py`: `HousekeepingStatusIn` (`housekeeping_status` literal),
`HkTaskIn` (room_id, assignee_sub?, due_at?, notes?), `HkTaskOut` (all persisted fields),
`HkTaskAssignIn` (assignee_sub), `HkTaskUpdateIn` (partial: status, notes, due_at).
`status`/`housekeeping_status` constrained to the literals above.

Service additions in `app/services/hotel_pms.py`:
- `set_room_housekeeping_status(hotel_id, room_id, *, housekeeping_status, user_sub) ->
  dict` — validates the room exists + ownership; `update_item` on the `ROOM#` row stamping
  `housekeeping_status` + `updated_at`; `_audit("hotel.room.housekeeping_status", ...)`.
  Keeps `GSI_HK_STATUS` (HTL-006) current.
- `create_hk_task(hotel_id, *, room_id, assignee_sub="", due_at=0, notes="", user_sub) ->
  dict` — validates room exists; `uuid4().hex` task_id; `status="open"`; `put_item`;
  `_audit("hotel.hk_task.created", ...)`.
- `assign_hk_task(hotel_id, task_id, *, assignee_sub, user_sub) -> dict` — sets
  `assignee_sub` (updates `GSI_HK_ASSIGNEE`) + `updated_at`; idempotent re-assign;
  `_audit`.
- `list_hk_tasks(hotel_id=None, *, status=None, assignee_sub=None, cursor=None, limit=50)
  -> dict` — by hotel+status via `GSI_HK_TASK_STATUS`; by assignee via `GSI_HK_ASSIGNEE`;
  by hotel-all via the `hotel_rooms` PK + `begins_with(sk, "HKTASK#")`. Cursor pagination.
  Returns `{"tasks": [...], "count": int, "cursor": str | None}`.
- `complete_hk_task(hotel_id, task_id, *, user_sub) -> dict` — conditional `update_item`
  flipping `status` to `done` with a `status <> done` guard (idempotent under replay),
  stamps `completed_at = now_ts()`; `_audit("hotel.hk_task.completed", ...)`.

All entrypoints call `_require_enabled()` first.

> Note: the ticket-board service (`app/services/tickets.py:56-148`, default board columns
> `open`/`in_progress`/`done`) is the **frontend** analogue for the HTL-009 housekeeping
> board UI — NOT the backend store. Housekeeping tasks persist to `hotel_rooms` here, not
> to the tickets/spaces tables.

**Acceptance Criteria**
- `set_room_housekeeping_status` transitions the `housekeeping_status` enum on the room row
  and the room re-buckets under `GSI_HK_STATUS` (HTL-006); invalid enum → 422.
- `create_hk_task` rejects (404) a task for an unknown room; tasks co-locate on the
  `hotel_rooms` partition (`HKTASK#` rows, never returned by `list_rooms`).
- `assign_hk_task` re-keys the task under `GSI_HK_ASSIGNEE`; `list_hk_tasks(assignee_sub=)`
  returns that staffer's tasks; `list_hk_tasks(hotel_id=, status=)` buckets via
  `GSI_HK_TASK_STATUS`; both paginate.
- `complete_hk_task` is idempotent (second call is a no-op via the `status <> done` guard)
  and stamps `completed_at`.
- `GSI_HK_TASK_STATUS` + `GSI_HK_ASSIGNEE` declared with the correct `attr_types` (numeric
  `created_at`); `just restart` creates them without `ValidationException`.
- Flag off → every housekeeping entrypoint 404s; no `if S.dev_mode` branch (SECOPS-007).

**Dependencies**: HTL-006 (`hotel_rooms` table + room rows + ownership check). Reuses:
FAC `HKTASK#`-style child-row pattern (`docs/ofbiz/specs/FAC-001.md` §3), conditional
`update_item` idempotency guard (`app/services/inventory.py:24` reservation-status idiom),
`uuid4().hex`, `now_ts()` (`app/core/time.py:2`), `_audit`
(`app/services/inventory.py:92-98`), cursor (`app/core/cursor.py:94,103`). FE analogue:
ticket-board columns (`app/services/tickets.py:56-148`) — board UI only, not the store.

---

### HTL-008: Router — room-types / rooms / housekeeping sub-routes + registration

**Type**: Feature
**Priority**: P1
**Estimate**: 1d

**Description**

Expose the HTL-005/006/007 services over HTTP. Extend the HTL hotels router
(`hotels_router`, prefix `/ui/hotels`, landed in the HTL-001 cluster) with the
room-types / rooms / housekeeping sub-routes, modeled exactly on `app/routers/inventory.py`
(auth split + `_require_enabled()` short-circuit) and the PROP-004 router plan. If the
hotels router is owned by a different cluster ticket, mount these on a sibling
`hotel_rooms_router` (prefix `/ui/hotels`) registered in `app/main.py` next to it —
either way the public path tree is `/ui/hotels/{hotel_id}/...`.

Every handler calls `_require_enabled()` first (delegating to `hotel_pms._require_enabled()`,
exactly like `app/routers/inventory.py:32-34`).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/room-types` | `require_ui_session` | `list_room_types` (query `status`, `cursor`, `limit`) |
| POST | `/ui/hotels/{hotel_id}/room-types` | `require_admin_or_root_csrf` | `create_room_type` |
| GET | `/ui/hotels/{hotel_id}/room-types/{room_type_id}` | `require_ui_session` | `get_room_type` (404 if none) |
| PUT | `/ui/hotels/{hotel_id}/room-types/{room_type_id}` | `require_admin_or_root_csrf` | `update_room_type` |
| DELETE | `/ui/hotels/{hotel_id}/room-types/{room_type_id}` | `require_admin_or_root_csrf` | `archive_room_type` |
| GET | `/ui/hotels/{hotel_id}/rooms` | `require_ui_session` | `list_rooms` (query `room_type_id`, `status`, `cursor`, `limit`) |
| POST | `/ui/hotels/{hotel_id}/rooms` | `require_admin_or_root_csrf` | `create_room` |
| GET | `/ui/hotels/{hotel_id}/rooms/{room_id}` | `require_ui_session` | `get_room` (404 if none) |
| PUT | `/ui/hotels/{hotel_id}/rooms/{room_id}` | `require_admin_or_root_csrf` | `update_room` |
| DELETE | `/ui/hotels/{hotel_id}/rooms/{room_id}` | `require_admin_or_root_csrf` | `delete_room` |
| PUT | `/ui/hotels/{hotel_id}/rooms/{room_id}/housekeeping` | `require_admin_or_root_csrf` | `set_room_housekeeping_status` |
| GET | `/ui/hotels/{hotel_id}/housekeeping/tasks` | `require_ui_session` | `list_hk_tasks` (query `status`, `assignee_sub`, `cursor`, `limit`) |
| POST | `/ui/hotels/{hotel_id}/housekeeping/tasks` | `require_admin_or_root_csrf` | `create_hk_task` |
| PUT | `/ui/hotels/{hotel_id}/housekeeping/tasks/{task_id}/assign` | `require_admin_or_root_csrf` | `assign_hk_task` |
| PUT | `/ui/hotels/{hotel_id}/housekeeping/tasks/{task_id}/complete` | `require_admin_or_root_csrf` | `complete_hk_task` |

> Declaration order: declare the literal `/room-types`, `/rooms`, `/housekeeping`
> sub-trees and their literal trailing segments (`/assign`, `/complete`, `/housekeeping`)
> in the correct order so FastAPI does not capture a literal as a path param — the
> `/{room_type_id}` and `/{task_id}` dynamic routes are declared AFTER their sibling
> literals (same literal-before-dynamic gotcha as the KYC `/templates`-before-`/{case_id}`
> and audit-export `/schedules`-before-`/{export_id}` ordering noted in CLAUDE.md).

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py:37,46,63,79`. `create_*` handlers pass `user_sub=user.sub` for
ownership validation.

**Acceptance Criteria**
- All 15 endpoints respond; flag off → every endpoint 404s (handler-level no-op, router
  still mounted, byte-for-byte unchanged platform).
- Read endpoints accept a UI session; mutation endpoints reject non-admin / missing-CSRF
  requests (403) per `require_admin_or_root_csrf`.
- Literal sub-trees resolve correctly: `/housekeeping/tasks` is NOT captured by
  `/rooms/{room_id}`, and `/{task_id}/complete` is NOT captured by a bare `/{task_id}`
  (routes declared in the correct order).
- The router is imported and `include_router`'d in `app/main.py` adjacent to the HTL
  hotels router (or the existing `inventory_router`).

**Dependencies**: HTL-005, HTL-006, HTL-007 (all service functions); HTL-001 (hotels
router + flag). Reuses: `app/routers/inventory.py:32-34,37,46,63,79` (router idiom),
`app/auth/policy.py:100`, `app/services/sessions.py:330`, `app/main.py` (registration
next to `inventory_router`), PROP-004 router plan (`docs/open-property/specs/PROP-002.md`
sibling — `/ui/properties` split).

---

### HTL-009: Frontend — room-type manager + room grid + housekeeping board + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2.5d

**Description**

Build the room-type / room / housekeeping UI and the hermetic backend + E2E tests. Gap
analysis §A ("FE: room grid + housekeeping board on the ticket-board pattern"). Follow the
established frontend feature recipe (CLAUDE.md "Adding a new feature" steps 5–9) and the
PROP-005 page structure.

Frontend (`frontend/src/`):
- **Types** — add `RoomType`, `Room`, `HkTask`, the `HousekeepingStatus` enum, and the
  in/update shapes to `frontend/src/api/types.ts` (mirror `app/models.py` HTL models).
- **API endpoints** — `frontend/src/api/endpoints/hotelRooms.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`): `listRoomTypes`, `createRoomType`,
  `getRoomType`, `updateRoomType`, `archiveRoomType`, `listRooms`, `createRoom`, `getRoom`,
  `updateRoom`, `deleteRoom`, `setRoomHousekeepingStatus`, `listHkTasks`, `createHkTask`,
  `assignHkTask`, `completeHkTask`.
- **Pages** under `frontend/src/pages/hotels/` (co-located with the HTL-001 hotel pages):
  - `RoomTypesPage.tsx` (or a tab on the hotel-detail page) — a **room-type manager**: card
    list of a hotel's room types (name, bed-type badge, occupancy `adults+children / max`,
    size, base nightly rate formatted from cents, photo thumb). React Query `useQuery` on
    `listRoomTypes`; "New Room Type" dialog (React Hook Form + Zod) → `createRoomType`;
    edit/archive actions.
  - `RoomsPage.tsx` (or tab) — a **room grid per hotel**: each room shows room_number,
    floor, room-type name, status badge, and a `housekeeping_status` badge. Filter by
    room-type / status. Add/edit/delete room dialogs; an inline housekeeping-status setter
    calling `setRoomHousekeepingStatus`.
  - `HousekeepingBoard.tsx` — a **housekeeping board on the ticket-board pattern** (mirror
    the `open`/`in_progress`/`done` columns of `app/services/tickets.py:56-148`): three
    columns of task cards (room_number, assignee, due, notes), driven by
    `listHkTasks(status=)`. Assign dialog → `assignHkTask`; "Mark done" → `completeHkTask`.
    shadcn/ui primitives (`Card`, `Dialog`, `Badge`, `Button`, `Select`,
    `components/ui/`).
- **Routes** — lazy-load the pages in `frontend/src/App.tsx` (cf. the lazy-import block at
  `:14-37`): e.g. `/hotels/:hotelId/room-types`, `/hotels/:hotelId/rooms`,
  `/hotels/:hotelId/housekeeping` (or as tabs on the HTL-001 hotel-detail route).
- **Sidebar** — extend the HTL hotels nav entry in
  `frontend/src/components/layout/Sidebar.tsx` (cf. the nav-item array, e.g.
  `BedDouble`/`Sparkles` lucide icons). Gate visibility on a `hotelPmsEnabled` flag if the
  sidebar reads feature flags; otherwise show unconditionally (routes 404 server-side when
  off).

Tests:
- **Hermetic pytest** `tests/test_htl_rooms_housekeeping.py` — moto-bound `hotels` +
  `hotel_rooms` tables on frozen `T` (`object.__setattr__`), frozen `S` with
  `hotel_pms_enabled` toggled, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` (no `TestClient`). Cover: room-type create + parent-ownership
  404, flag-off 404, room CRUD + room-type FK validation + `delete_room` no-raise,
  `housekeeping_status` transition + `GSI_HK_STATUS` re-bucketing, HK-task create/assign/
  list-by-status/list-by-assignee/complete idempotency, list/filter pagination,
  route-ordering (literal sub-trees not captured by `/{room_id}` / `/{task_id}`).
- **E2E** `frontend/e2e/hotel-rooms.spec.ts` — cookie-auth (`injectAuth`) admin creates a
  hotel (HTL-001), adds room types + rooms, sets a room dirty, creates + assigns +
  completes a housekeeping task, asserts the room-type cards, room grid, and the
  three-column housekeeping board render. CSRF header on POSTs (`x-csrf-token`). Requires
  `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- The room-type manager, per-hotel room grid, and three-column housekeeping board all
  render and are reachable via the sidebar / hotel-detail tabs.
- Create/edit/archive room type, create/edit/delete room, set housekeeping status, and
  create/assign/complete housekeeping task flows work end-to-end against the HTL-008 router.
- Base nightly rate displays as currency (cents → formatted); bed-type, occupancy,
  status, and housekeeping-status badges reflect the persisted enums.
- `tests/test_htl_rooms_housekeeping.py` passes offline (no AWS, no live stack).
- `frontend/e2e/hotel-rooms.spec.ts` passes with the flag on.

**Dependencies**: HTL-008 (router/endpoints) — and transitively HTL-005/006/007 and
HTL-001 (hotel create + flag). Reuses: `frontend/src/api/client.ts`,
`frontend/src/App.tsx:14-37` (lazy routes), `frontend/src/components/layout/Sidebar.tsx`
(nav items), the ticket-board column model (`app/services/tickets.py:56-148`) as the
board-UI analogue, shadcn/ui (`components/ui/`), React Query + RHF/Zod conventions
(CLAUDE.md frontend conventions), hermetic-test + E2E patterns (PROP-005, CLAUDE.md E2E
section).

---

## Dependency order

HTL-001..HTL-004 (hotels table + `HOTEL_PMS_ENABLED` flag + `hotel_pms.py` service +
hotels router — sibling cluster) → **HTL-005** (Room Type child rows on the `hotels`
partition) → **HTL-006** (`hotel_rooms` table + Room entity + Room Type FK) → **HTL-007**
(housekeeping status on the room row + HK-task child rows) → **HTL-008** (router sub-routes
+ `main.py` registration) → **HTL-009** (frontend room-type manager + room grid +
housekeeping board + hermetic pytest + E2E).
