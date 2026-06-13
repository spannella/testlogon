# HTL — Hotels + Amenities catalog (hospitality spine, Tier 1, gap analysis §A)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §A
("Hotels + Room Types + Rooms + Housekeeping") + the "Recommended new tickets" Tier-1
"Hotel + amenities" cluster. QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) is an open-source hotel
property-management system + booking engine whose **Hotel** (property/branch) and
**amenity/feature** entities are the genuinely net-new hospitality spine the gap analysis
flags as **MISSING** (§A rows 1, 4): testlogon has *no hospitality domain at all*.

The closest structural shadow is the open-property **Property** entity
(`docs/open-property/specs/PROP-001.md`) and behind it the OFBiz **Facility** header
(`docs/ofbiz/specs/FAC-001.md` §3, `facilities`) — a header entity (`*_id`, SK=`META`)
co-located with child rows on the same partition. **We reuse that table-shape and service
idiom but NOT the semantics**: PROP-001 Property carries only `address`/`status`/
`property_type` (a rental building); a Hotel carries hospitality fields — `star_rating`,
`check_in_time`/`check_out_time`, `policies` (cancellation/pet/smoking/children), `contact`,
`photo_urls` — that no existing model has. The amenity catalog has *no* implemented
analogue at all; the generic catalog `attributes` map is free-form (`catalog.py`), and
PRD-006 feature/feature-category is the *unimplemented* generic shadow (we contrast it, we
do not reuse it).

These four tickets cover ONLY the **Hotel** entity and the reusable **amenity/feature
catalog** with its many-to-many attach to hotels AND room types (gap analysis §A rows 1 &
4). Room Type, individual Rooms, housekeeping, per-date availability inventory, nightly
rate plans, the stay-search engine, reservations, front desk, the booking storefront,
folios, deposits, cancellation policy, and KPI reports are out of scope here (the rest of
Tier 1, plus Tiers 2 & 3 in the gap analysis). The amenity attach to room types (HTL-002)
deliberately allows `target_type="room_type"` so the *future* Room Type cluster can attach
amenities with zero schema change, but no room-type entity ships here.

## Cross-cutting constraints (apply to every HTL ticket)

- **Additive + flag-gated, default OFF.** A new master flag `HOTEL_PMS_ENABLED`
  (default `false`) gates the whole hotel-PMS vertical. Mirror the
  `INVENTORY_RESERVATIONS_ENABLED` contract: `_flag_on()` / `_require_enabled()` raising
  **404** when off, exactly like `app/services/inventory.py:51-58` and
  `app/routers/inventory.py:32-38`. Routers are always mounted; every handler is a 404
  no-op until opt-in. With the flag off the platform is byte-for-byte unchanged.
- **Single-table DynamoDB header+child idiom.** Follow the FAC/PROP header+child pattern:
  a PK + SK=`META` header row co-located with SK=`CHILD#{id}` child rows on the same
  partition for cheap per-parent scans (`docs/ofbiz/specs/FAC-001.md` §3 "Table:
  `facilities`"; `docs/open-property/specs/PROP-001.md`). For HTL the amenity associations
  are `AMEN#{amenity_id}` child rows on the target's partition (HTL-002).
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key (e.g. `created_at`) MUST
  be declared in the `TableDef` `attr_types` map per the CLAUDE.md DynamoDB numeric-GSI
  gotcha — omitting it stores the value as String → `ValidationException`. Pattern:
  `scripts/local-ddb-init.py` `TableDef(...)` calls (`facilities`/`inventory` style,
  FAC-001 §3).
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor pagination
  (`encode_cursor`/`decode_cursor`, `app/core/cursor.py:94,103`), the `_audit()`
  lazy-import wrapper (`app/services/inventory.py:92-98`), table handles via `T.*`
  (`app/core/tables.py:317-319,569-571`), the settings idiom
  (`app/core/settings.py:839-841`, `os.environ.get(...).lower() == "true"`). Deterministic
  id derivation `sha256(f"{owner}|{name}")[:32]` per `docs/ofbiz/specs/FAC-001.md` §3.
  Auth: reads → `require_ui_session` (`app/services/sessions.py:330`); mutations →
  `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical split to
  `app/routers/inventory.py:48,65,81`.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). Mirrors FAC-001 §7 / `inventory.py:27-28`.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`),
  frozen `S` flags, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` — no `TestClient`, no real AWS. Mirrors PROP-005 / FAC-001 §9.

---

### HTL-001: Hotel entity — model, table, master flag

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Land the Hotel data model, its DynamoDB table, and the master `HOTEL_PMS_ENABLED` flag —
the foundation every downstream HTL ticket (and the whole hospitality vertical) depends
on. Net-new; PROP-001 Property is the structural analogue but its field set is rental
real-estate (`address`/`property_type`/`occupancy_status`), not the hospitality fields a
hotel carries.

DDB table `hotels` (PK=`hotel_id`, SK=`META` for the hotel header; amenity-association
`AMEN#{amenity_id}` child rows are added in HTL-002, co-located on the same partition —
same header+child idiom as `facilities`/`properties`, `docs/ofbiz/specs/FAC-001.md` §3):

| Attribute | Type | Notes |
|---|---|---|
| `hotel_id` | S | PK. Deterministic `sha256(f"{owner_sub}\|{name}".encode()).hexdigest()[:32]` (mirrors `docs/ofbiz/specs/FAC-001.md` §3 facility-id derivation / `commerce_order_service.py` order-id derivation → idempotent per owner+name) |
| `sk` | S | `META` (hotel header) |
| `owner_sub` | S | Owning user_sub (hotelier) |
| `name` | S | Human-readable hotel name |
| `description` | S | Free-text description |
| `star_rating` | N | Integer 1–5 (validated in the Pydantic model) |
| `address` | M | Address map `{line1, line2, city, region, postal_code, country}` |
| `check_in_time` | S | `"HH:MM"` 24h string (default `"15:00"`) |
| `check_out_time` | S | `"HH:MM"` 24h string (default `"11:00"`) |
| `policies` | M | `{cancellation_text: S, pet_policy: S, smoking: bool, children: bool}` |
| `contact` | M | `{phone: S, email: S, website: S}` |
| `photo_urls` | L | List of photo URL strings |
| `status` | S | `active` \| `archived` (default `active`) |
| `created_at` | N | `now_ts()` (`app/core/time.py:2`) |
| `updated_at` | N | `now_ts()` |

GSIs (declared in `scripts/local-ddb-init.py`, `attr_types={"created_at": "N"}` — numeric
sort key, CLAUDE.md numeric-GSI gotcha):
- `GSI_OWNER` — PK=`owner_sub`, SK=`created_at` — list a hotelier's hotels newest-first
  (the primary list path, HTL-003 `list_hotels`).
- `GSI_STATUS` — PK=`status`, SK=`created_at` — admin listing by active/archived.

`TableDef` follows the existing `inventory`/`facilities` style in
`scripts/local-ddb-init.py` (cf. FAC-001 §3, PROP-001 §HTL-table):
```python
TableDef(
    _resolve_table_name(S.hotels_table_name, "hotels"),
    "hotel_id",
    "sk",
    gsi=[
        {"index_name": "GSI_OWNER",  "partition_key": "owner_sub", "sort_key": "created_at"},
        {"index_name": "GSI_STATUS", "partition_key": "status",    "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings (add to `app/core/settings.py` immediately after the inventory block at
`:839-841`, same `os.environ.get(...).lower() == "true"` idiom):
```python
# QloApps hotel-PMS vertical (HTL) — master flag, default OFF; with it off the
# hotel routers are mounted but every handler 404s and the platform is unchanged.
hotel_pms_enabled: bool = os.environ.get("HOTEL_PMS_ENABLED", "false").lower() == "true"
hotels_table_name: str = os.environ.get("HOTELS_TABLE_NAME", "hotels")
```

Table handle: add `hotels: Any` to the `T` dataclass next to `inventory`
(`app/core/tables.py:317-319`) and wire `hotels=_safe_table(S.hotels_table_name)` in the
initializer next to `inventory=...` (`app/core/tables.py:569-571`).

Pydantic models in `app/models.py`: reuse `Address` if one already exists else add one;
`HotelPolicies` (cancellation_text, pet_policy, smoking, children), `HotelContact`
(phone, email, website), `HotelIn` (name, description, star_rating, address,
check_in_time, check_out_time, policies, contact, photo_urls), `HotelOut` (all persisted
fields), `HotelUpdateIn` (partial). `star_rating` constrained `ge=1, le=5`; `status`
constrained to the two literals; `check_in_time`/`check_out_time` validated against an
`^([01]\d|2[0-3]):[0-5]\d$` pattern.

Service `app/services/hotel_pms.py` (new), modeled on `app/services/inventory.py` +
the PROP-001 `property_mgmt.py` plan:
- `_flag_on()` → `bool(getattr(S, "hotel_pms_enabled", False))` (copy
  `inventory.py:50-51`).
- `_require_enabled()` → raises HTTP 404 when off (copy `inventory.py:54-56`).
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy `inventory.py:92-98`).
- `_meta_key(hotel_id)` → `{"hotel_id": hotel_id, "sk": "META"}`.
- `create_hotel(owner_sub, *, name, description, star_rating, address, check_in_time, check_out_time, policies, contact, photo_urls) -> dict`
  — derives `hotel_id = sha256(f"{owner_sub}|{name}")[:32]`, stamps
  `created_at`/`updated_at` via `now_ts()`, conditional
  `attribute_not_exists(hotel_id)` put → idempotent on owner+name collision (a
  `ConditionalCheckFailedException` returns the existing row, mirroring FAC facility
  create); `_audit("hotel.created", owner_sub, hotel_id=...)`.
- `get_hotel(hotel_id) -> dict | None` — reads SK=`META`.
- `update_hotel(hotel_id, *, user_sub, **kwargs) -> dict` — `update_item` over supplied
  fields, stamps `updated_at`; `_audit("hotel.updated", ...)`.
- `archive_hotel(hotel_id, *, user_sub) -> dict` — sets `status="archived"`, stamps
  `updated_at`; `_audit("hotel.archived", ...)`.

**Acceptance Criteria**
- `hotels` `TableDef` present with both GSIs and `attr_types={"created_at": "N"}`;
  `just restart` creates the table without `ValidationException`.
- `HOTEL_PMS_ENABLED` defaults to `false`; with it off, every `hotel_pms` service
  entrypoint raises HTTP 404 via `_require_enabled()`.
- `create_hotel` is idempotent on (owner_sub, name): two calls return the same `hotel_id`
  and the second does not error (existing row returned).
- `star_rating` outside 1–5 and a malformed `check_in_time`/`check_out_time` are rejected
  by the Pydantic model (422).
- `T.hotels` resolves; `HotelIn/Out/UpdateIn` import cleanly.
- No `if S.dev_mode` branch in `hotel_pms.py` (SECOPS-007).

**Dependencies**: none (foundational). Reuses: `app/services/inventory.py:50-56,92-98`
(flag/audit), `scripts/local-ddb-init.py` `TableDef` (`facilities`/`inventory` style),
`app/core/tables.py:317-319,569-571`, `app/core/settings.py:839-841`,
`app/core/time.py:2`, `docs/ofbiz/specs/FAC-001.md` §3 (id derivation + header+child
shape). Contrasts: `docs/open-property/specs/PROP-001.md` Property (rental, no hospitality
fields).

---

### HTL-002: Amenity/feature catalog — reusable dictionary + many-to-many attach

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Add the reusable amenity/feature catalog (wifi/pool/parking/gym/breakfast…) and the
many-to-many association so an amenity can attach to **hotels** AND, ahead of the future
Room Type cluster, **room types** — gap analysis §A row 4 ("Hotel features / amenities
catalog … attached to hotels+room types — MISSING"). The generic catalog `attributes` map
is free-form and PRD-006 feature/feature-category is the *unimplemented* generic analogue
— **we contrast that pattern, we do not reuse it**: PRD-006's features are product-variant
attributes; an amenity is a hotel/room-type facility dictionary entry with its own
category taxonomy and a true many-to-many attach, neither of which PRD-006 ships.

**Storage decision (justified): a small global `hotel_amenities` table for the
dictionary + association rows co-located on the *target's* partition.**

Why a separate global table for the dictionary (not child rows on a hotel): amenities are
*shared across all hotels and room types* — "WiFi" is one canonical dictionary entry, not
a per-hotel row. Co-locating the dictionary under a hotel would force duplication and make
"rename the amenity globally" impossible. The dictionary therefore lives in its own tiny
table.

Why the *associations* are child rows on the target partition (not rows in the amenity
table): the dominant read is "list amenities for this hotel/room type" (HTL-004 detail
page renders amenity chips), which must be a single-partition query. So an attach writes an
`AMEN#{amenity_id}` child row onto the *target's* META partition — the exact FAC
`LOC#{location_id}` / PROP `UNIT#{unit_id}` co-located child-row idiom
(`docs/ofbiz/specs/FAC-001.md` §3). For a hotel target this row lands on the existing
`hotels` partition (HTL-001), so no new attach table is needed for hotels; room-type
targets land on the future room-types partition (same code, zero change here).

DDB table `hotel_amenities` (PK=`amenity_id`, SK=`META` — the dictionary entry; global,
not owner-scoped, since amenities are platform-shared):

| Attribute | Type | Notes |
|---|---|---|
| `amenity_id` | S | PK. Deterministic `sha256(f"amenity\|{name}".encode()).hexdigest()[:32]` → idempotent per name, dedupes "WiFi" across callers |
| `sk` | S | `META` |
| `name` | S | Display name (e.g. `"Free WiFi"`) |
| `category` | S | `connectivity` \| `wellness` \| `parking` \| `dining` \| `family` \| `accessibility` \| `general` |
| `icon` | S | Optional lucide icon name for the FE chip |
| `created_at` | N | `now_ts()` |

GSI on `hotel_amenities` (declared in `scripts/local-ddb-init.py`,
`attr_types={"created_at": "N"}`):
- `GSI_CATEGORY` — PK=`category`, SK=`created_at` — list amenities grouped by category for
  the FE picker (HTL-004); falls back to a `Scan` only when listing *all* categories.

Association **child row** written onto the target's partition (no new table for hotels —
reuses the `hotels` partition from HTL-001; PK is the target's PK, e.g. `hotel_id`):

| Attribute | Type | Notes |
|---|---|---|
| `<target_pk>` | S | The target's PK (e.g. `hotel_id`), same partition as the target `META` row |
| `sk` | S | `AMEN#{amenity_id}` (co-located child row) |
| `amenity_id` | S | Convenience copy |
| `target_type` | S | `hotel` \| `room_type` (forward-compat; room_type partition resolved by the future cluster) |
| `created_at` | N | `now_ts()` |

> Note: `list_amenities_for(target)` is a single-partition query
> `Key(target_pk).eq(target_id) & Key("sk").begins_with("AMEN#")` then a batched read of
> the referenced `hotel_amenities` `META` rows to hydrate name/category/icon — never a
> scan of the target partition's other children.

Settings (add next to HTL-001's block in `app/core/settings.py`):
```python
hotel_amenities_table_name: str = os.environ.get("HOTEL_AMENITIES_TABLE_NAME", "hotel_amenities")
```
Table handle: add `hotel_amenities: Any` to the `T` dataclass
(`app/core/tables.py:317-319`) and wire
`hotel_amenities=_safe_table(S.hotel_amenities_table_name)`
(`app/core/tables.py:569-571`).

Pydantic models in `app/models.py`: `AmenityIn` (name, category, icon), `AmenityOut`
(all dictionary fields), `AmenityAttachIn` (target_type, target_id, amenity_id),
`AmenityAssociationOut` (amenity hydrated + target_type). `category`/`target_type`
constrained to the literals above.

Service additions in `app/services/hotel_pms.py`:
- `create_amenity(*, name, category, icon, user_sub) -> dict` — derives
  `amenity_id = sha256(f"amenity|{name}")[:32]`, conditional
  `attribute_not_exists(amenity_id)` put → idempotent on name (returns existing on
  collision); `_audit("hotel.amenity.created", ...)`. All entrypoints call
  `_require_enabled()` first.
- `list_amenities(*, category=None) -> list[dict]` — queries `GSI_CATEGORY` when
  `category` given, else lists the dictionary; sorted by `name`.
- `_target_partition(target_type, target_id) -> tuple[Any, str, str]` — resolves the
  target table handle + PK attr name + PK value: `hotel` → `(T.hotels, "hotel_id",
  target_id)` (room_type wired by the future cluster; raises 422 for an unknown
  `target_type` until then).
- `attach_amenity(*, target_type, target_id, amenity_id, user_sub) -> dict` — validates
  the amenity dictionary entry exists (404 if not) and the target exists (404 if not),
  then `put_item` the `AMEN#{amenity_id}` child row on the target partition (conditional
  `attribute_not_exists(sk)` → idempotent re-attach); `_audit("hotel.amenity.attached",
  ...)`.
- `detach_amenity(*, target_type, target_id, amenity_id, user_sub) -> bool` — deletes the
  child row; returns `False` (never raises) for a missing association (mirrors
  `host_inventory.delete_host` no-raise contract, CLAUDE.md); `_audit(
  "hotel.amenity.detached", ...)`.
- `list_amenities_for(*, target_type, target_id) -> list[dict]` — single-partition query
  for `AMEN#`-prefixed child rows, batched-hydrate each from `hotel_amenities` `META`,
  returns `AmenityAssociationOut`-shaped dicts.

**Acceptance Criteria**
- `hotel_amenities` `TableDef` present with `GSI_CATEGORY` +
  `attr_types={"created_at": "N"}`; `just restart` creates it without `ValidationException`.
- `create_amenity` is idempotent on `name`; `list_amenities(category=...)` queries the GSI,
  not a scan.
- `attach_amenity` 404s an unknown amenity or unknown target; re-attaching the same
  amenity to the same target is idempotent (no duplicate child row, no error).
- `list_amenities_for` returns only the target's `AMEN#`-prefixed associations (never the
  target `META` row), each hydrated with name/category/icon.
- `detach_amenity` returns `False` for a missing association (no raise).
- `target_type="room_type"` is accepted by the model/service surface (forward-compat) even
  though no room-type entity ships here.
- Flag off → every amenity entrypoint 404s.

**Dependencies**: HTL-001 (`hotels` partition for hotel associations + flag + service
module). Reuses: FAC/PROP `CHILD#{id}` co-located child-row pattern
(`docs/ofbiz/specs/FAC-001.md` §3), deterministic id derivation, `now_ts()`
(`app/core/time.py:2`), `_audit` (`app/services/inventory.py:92-98`),
`host_inventory.delete_host` no-raise contract (CLAUDE.md). Contrasts: PRD-006
feature/feature-category (unimplemented product-variant pattern, not a facility dictionary)
and the free-form catalog `attributes` map (`catalog.py`).

---

### HTL-003: Router — `/ui/hotels` + amenities sub-routes + registration in `app/main.py`

**Type**: Feature
**Priority**: P1
**Estimate**: 1d

**Description**

Expose the HTL services over HTTP via a new `hotels_router`, modeled exactly on
`app/routers/inventory.py` (auth split + `_require_enabled()` short-circuit) and the
PROP-004 router plan. Register it in `app/main.py` next to `inventory_router`
(`app/main.py:311` import, `:877` include).

```python
hotels_router = APIRouter(prefix="/ui/hotels", tags=["hotels"])
```
Every handler calls a module-level `_require_enabled()` that delegates to
`hotel_pms._require_enabled()`, exactly like `app/routers/inventory.py:32-38`.

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py:48,65,81`. `create_hotel` passes `owner_sub=user.sub`; amenity
mutations pass `user_sub=user.sub`.

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels` | `require_ui_session` | `list_hotels` (HTL-001 list path over `GSI_OWNER`; query params `status`, `cursor`, `limit`) |
| POST | `/ui/hotels` | `require_admin_or_root_csrf` | `create_hotel` (`owner_sub=user.sub`) |
| GET | `/ui/hotels/amenities` | `require_ui_session` | `list_amenities` (query param `category`) — **literal, declared before `/{hotel_id}`** |
| POST | `/ui/hotels/amenities` | `require_admin_or_root_csrf` | `create_amenity` |
| POST | `/ui/hotels/amenities/attach` | `require_admin_or_root_csrf` | `attach_amenity` (body: target_type, target_id, amenity_id) |
| POST | `/ui/hotels/amenities/detach` | `require_admin_or_root_csrf` | `detach_amenity` |
| GET | `/ui/hotels/{hotel_id}` | `require_ui_session` | `get_hotel` (404 if none) |
| PUT | `/ui/hotels/{hotel_id}` | `require_admin_or_root_csrf` | `update_hotel` |
| DELETE | `/ui/hotels/{hotel_id}` | `require_admin_or_root_csrf` | `archive_hotel` |
| GET | `/ui/hotels/{hotel_id}/amenities` | `require_ui_session` | `list_amenities_for(target_type="hotel", target_id=hotel_id)` |

> Declaration order: declare the literal `/amenities` (and its `/amenities/attach`,
> `/amenities/detach`) routes **before** the dynamic `/{hotel_id}` routes so FastAPI does
> not capture the literal `amenities` as a `hotel_id` path param — the same gotcha as the
> KYC `/templates`-before-`/{case_id}` and audit-export `/schedules`-before-`/{export_id}`
> ordering noted in CLAUDE.md.

`list_hotels` (a thin HTL-001 service addition, returns the `{items, count, cursor}` shape
used by `host_inventory.list_hosts` per CLAUDE.md) queries `GSI_OWNER`
(PK=`owner_sub=user.sub`, SK=`created_at`, newest-first) and paginates via
`encode_cursor`/`decode_cursor` (`app/core/cursor.py:94,103`).

Register in `app/main.py`: add `from app.routers.hotels import hotels_router` next to the
`inventory_router` import (`app/main.py:311`) and `app.include_router(hotels_router)` next
to `app.include_router(inventory_router)` (`app/main.py:877`).

**Acceptance Criteria**
- All 10 endpoints respond; flag off → every endpoint 404s (handler-level no-op, router
  still mounted, byte-for-byte unchanged platform).
- Read endpoints accept a UI session; mutation endpoints reject non-admin / missing-CSRF
  requests (403) per `require_admin_or_root_csrf`.
- `GET /ui/hotels/amenities` resolves to the amenity-list handler, NOT captured by
  `/{hotel_id}` (literal route declared first).
- `hotels_router` imported and `include_router`'d in `app/main.py` adjacent to
  `inventory_router`.

**Dependencies**: HTL-001, HTL-002 (all service functions + `list_hotels`). Reuses:
`app/routers/inventory.py:32-38,48,65,81` (router idiom + auth split),
`app/auth/policy.py:100`, `app/services/sessions.py:330`, `app/core/cursor.py:94,103`,
`app/main.py:311,877` (registration), `host_inventory.list_hosts` `{items, count, cursor}`
shape (CLAUDE.md), PROP-004 router plan.

---

### HTL-004: Frontend — HotelsPage card grid + HotelDetailPage (amenity chips + photo gallery + edit dialogs) + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2d

**Description**

Build the hotel-management UI and the hermetic backend + E2E tests. Gap analysis §A
("FE: hotel cards + detail + amenity chips"). Follow the established frontend feature
recipe (CLAUDE.md "Adding a new feature" steps 5–9) and the PROP-005 FE plan.

Frontend (`frontend/src/`):
- **Types** — add `Hotel`, `HotelPolicies`, `HotelContact`, `Amenity`,
  `AmenityAssociation` and the in/update shapes to `frontend/src/api/types.ts` (mirror the
  `app/models.py` HTL models).
- **API endpoints** — `frontend/src/api/endpoints/hotels.ts` wrapping the axios instance
  (`frontend/src/api/client.ts`): `listHotels`, `createHotel`, `getHotel`, `updateHotel`,
  `archiveHotel`, `listAmenities`, `createAmenity`, `attachAmenity`, `detachAmenity`,
  `listAmenitiesForHotel`.
- **Pages** under `frontend/src/pages/hotels/`:
  - `HotelsPage.tsx` — responsive **hotel card grid** (one card per hotel: name,
    star-rating display, address, a thumbnail from `photo_urls[0]`, status badge). Uses
    React Query `useQuery` on `listHotels`; "New Hotel" dialog (React Hook Form + Zod,
    `components/ui/Dialog`) calling `createHotel` (star_rating 1–5 selector,
    check-in/out time inputs, address fields, policy toggles).
  - `HotelDetailPage.tsx` — header (name, star rating, address, archive action),
    check-in/out times + policy summary, a **photo gallery** (carousel/grid over
    `photo_urls`), an **amenity-chips** section rendering `listAmenitiesForHotel` as
    `Badge` chips grouped by category with an attach/detach amenity dialog (driven by
    `listAmenities` + `attachAmenity`/`detachAmenity`), and an **edit-hotel dialog**
    (`updateHotel`). shadcn/ui primitives (`Card`, `Dialog`, `Badge`, `Button`,
    `components/ui/`).
- **Routes** — lazy-load both pages in `frontend/src/App.tsx` (cf. the existing
  lazy-imports block): `/hotels` → `HotelsPage`, `/hotels/:hotelId` → `HotelDetailPage`.
- **Sidebar** — add a "Hotels" nav item to
  `frontend/src/components/layout/Sidebar.tsx` (the nav-item array; a `Hotel`/`Building`
  lucide icon, `path: "/hotels"`). Gate visibility on a `hotelPmsEnabled` flag if the
  sidebar already reads feature flags; otherwise show unconditionally (the routes 404
  server-side when off).

Tests:
- **Hermetic pytest** `tests/test_htl_hotels_amenities.py` — moto-bound `hotels` +
  `hotel_amenities` tables on frozen `T` (`object.__setattr__`), frozen `S` with
  `hotel_pms_enabled` toggled via `object.__setattr__`, route coroutines called directly
  on a fresh `asyncio.new_event_loop()` (no `TestClient`). Cover: hotel create idempotency
  (same owner+name → same id), flag-off 404 across service + route handlers,
  `star_rating`/time validation, amenity create idempotency, attach/detach (incl.
  idempotent re-attach + no-raise detach of a missing association),
  `list_amenities_for` hydration, `list_hotels` GSI pagination/`{items,count,cursor}`
  shape, and route-ordering (`/ui/hotels/amenities` not captured by `/{hotel_id}`).
- **E2E** `frontend/e2e/hotels.spec.ts` — cookie-auth (`injectAuth`) admin creates a
  hotel, creates + attaches an amenity, asserts the card grid, detail header, amenity
  chips, and photo gallery render; CSRF header on POSTs (`x-csrf-token`). Requires
  `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- `/hotels` renders a hotel card grid; `/hotels/:id` renders header, photo gallery,
  policy summary, and amenity chips; both reachable via the new sidebar nav item.
- Create/edit/archive hotel + create/attach/detach amenity flows work end-to-end against
  the HTL-003 router.
- Star rating renders as stars; check-in/out times and policies display; amenity chips are
  grouped by category.
- `tests/test_htl_hotels_amenities.py` passes offline (no AWS, no live stack).
- `frontend/e2e/hotels.spec.ts` passes with the flag on.

**Dependencies**: HTL-003 (router/endpoints) — and transitively HTL-001/002. Reuses:
`frontend/src/api/client.ts`, `frontend/src/App.tsx` (lazy routes),
`frontend/src/components/layout/Sidebar.tsx` (nav items), shadcn/ui (`components/ui/`),
React Query + RHF/Zod conventions (CLAUDE.md frontend conventions), hermetic-test + E2E
patterns (PROP-005, FAC-001 §9, CLAUDE.md E2E section).

---

## Dependency order

HTL-001 (Hotel model + table + master flag) → HTL-002 (amenity catalog + many-to-many
attach) → HTL-003 (router `/ui/hotels` + amenities sub-routes + `main.py` registration) →
HTL-004 (frontend + hermetic pytest + E2E tests).
