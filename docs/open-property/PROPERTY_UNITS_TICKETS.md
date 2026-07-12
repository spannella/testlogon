# PROP — Property & Unit entities (real-estate spine, gap analysis §A)

Source gap analysis: `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A
("Properties & Units + Portfolio Dashboard"). open-property
([clawnify/open-property](https://github.com/clawnify/open-property)) provides a
self-hosted property-management platform whose **Property** and **Unit** entities are
the genuinely net-new real-estate spine the gap analysis flags as **MISSING**:
testlogon has no rental-property model. The closest structural analogue is the OFBiz
**Facility / FacilityLocation** pair (`docs/ofbiz/specs/FAC-001.md` §3, FAC-003, FAC-004)
— a header entity (`facilities`, SK=`META`) co-located with child rows (SK=`LOC#{id}`)
on the same partition. **We reuse that table-shape and service idiom but NOT the
warehouse semantics**: a Facility models a warehouse with bins (aisle/bay/bin) for
inventory stock, whereas a Property models a rental building with dwelling Units
(beds/baths/sqft/market-rent). The two never overlap — this is a parallel domain, not
an extension of FAC.

These five tickets cover ONLY the Property + Unit entities and their list/occupancy
roll-up + FE (gap analysis §A rows 1–3). Tenant, Lease, rent-ledger, work-orders,
vendors, policy, documents, and the portfolio KPI dashboard are out of scope here
(separate ticket clusters in the gap analysis §B/§C; the property dashlet is an
RPT-006/007 follow-up — `docs/suitecrm/specs/RPT-006.md`).

## Cross-cutting constraints (apply to every PROP ticket)

- **Additive + flag-gated, default OFF.** A new master flag
  `PROPERTY_MGMT_ENABLED` (default `false`) gates the whole vertical. Mirror the
  `INVENTORY_RESERVATIONS_ENABLED` contract: `_flag_on()` /
  `_require_enabled()` raising **404** when off, exactly like
  `app/services/inventory.py:51-58` and `app/routers/inventory.py:32-38`. Routers are
  always mounted; every handler is a 404 no-op until opt-in. With the flag off the
  platform is byte-for-byte unchanged.
- **Single-table DynamoDB.** Follow the FAC header+child pattern: one `properties`
  table (PK=`property_id`, SK=`META` for the property header, SK=`UNIT#{unit_id}` for
  units) co-locating a property and its units on one partition for cheap per-property
  scans (`docs/ofbiz/specs/FAC-001.md` §3 "Table: `facilities`").
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key (e.g. `created_at`)
  MUST be declared in the `TableDef` `attr_types` map per the CLAUDE.md DynamoDB
  numeric-GSI gotcha — omitting it stores the value as String → `ValidationException`.
  Pattern: `scripts/local-ddb-init.py:44+` `TableDef(...)` calls (`facilities` style,
  FAC-001 §3).
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor
  pagination (`app/core/cursor.py:94,103`), `_audit()` lazy-import wrapper
  (`app/services/inventory.py:92-98`), table handles via `T.*`
  (`app/core/tables.py:317-319,569-571`). Auth: reads → `require_ui_session`
  (`app/services/sessions.py:330`); mutations → `require_admin_or_root_csrf`
  (`app/auth/policy.py:100`) — identical split to `app/routers/inventory.py:48,65,81`.
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic;
  the same `T.*` handles in both environments (moto intercepts boto3 in dev, real
  DynamoDB in prod). Mirrors FAC-001 §7.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__`),
  frozen `S` flags, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` — no `TestClient`, no real AWS. Mirrors FAC-001 §9.

---

### PROP-001: Property entity — model, table, flag

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Land the Property data model, its DynamoDB table, and the master feature flag — the
foundation every other PROP ticket depends on. Net-new; the FAC facility header is the
structural analogue but the field set is rental real-estate, not warehouse.

DDB table `properties` (PK=`property_id`, SK=`META` for the property header; child
`UNIT#{unit_id}` rows are added in PROP-002, co-located on the same partition — same
header+child idiom as `facilities` in `docs/ofbiz/specs/FAC-001.md` §3):

| Attribute | Type | Notes |
|---|---|---|
| `property_id` | S | PK. Deterministic `sha256(f"{owner_sub}\|{name}".encode()).hexdigest()[:32]` (mirrors `commerce_order_service.py:67` / FAC-001 §3 facility-id derivation → idempotent per owner+name) |
| `sk` | S | `META` (property header) |
| `owner_sub` | S | Owning user_sub / landlord |
| `name` | S | Human-readable property name |
| `property_type` | S | `single_family` \| `multi_family` \| `apartment` \| `commercial` |
| `address` | M | Address map `{line1, line2, city, region, postal_code, country}` |
| `color_tags` | L | List of free-text/color label strings |
| `occupancy_status` | S | Property-level roll-up: `vacant` \| `partial` \| `occupied` (default `vacant`; recomputed in PROP-003 from unit states) |
| `unit_count` | N | Denormalized count of child units (0 at create; maintained by PROP-002) |
| `status` | S | `active` \| `archived` |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |

GSIs (declared in `scripts/local-ddb-init.py`, `attr_types={"created_at": "N"}` — numeric sort key):
- `GSI_OWNER` — PK=`owner_sub`, SK=`created_at` — list a landlord's properties newest-first (the primary list path, PROP-003).
- `GSI_STATUS` — PK=`status`, SK=`created_at` — admin listing by active/archived.

`TableDef` follows `scripts/local-ddb-init.py:44+` exactly (cf. FAC-001 §3 `facilities`):
```python
TableDef(
    _resolve_table_name(S.properties_table_name, "properties"),
    "property_id",
    "sk",
    gsi=[
        {"index_name": "GSI_OWNER",  "partition_key": "owner_sub", "sort_key": "created_at"},
        {"index_name": "GSI_STATUS", "partition_key": "status",    "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings (add to `app/core/settings.py` next to the inventory block at `:839-847`,
same `os.environ.get(...).lower() == "true"` idiom):
```python
property_mgmt_enabled: bool = os.environ.get("PROPERTY_MGMT_ENABLED", "false").lower() == "true"
properties_table_name: str = os.environ.get("PROPERTIES_TABLE_NAME", "properties")
```

Table handle: add `properties: Any` to the `T` dataclass (`app/core/tables.py:317`)
and wire `properties=_safe_table(S.properties_table_name)` in the initializer
(`app/core/tables.py:569`).

Pydantic models in `app/models.py`: `Address` (reuse if one already exists, else add),
`PropertyIn` (name, property_type, address, color_tags), `PropertyOut` (all persisted
fields), `PropertyUpdateIn` (partial). `property_type`/`occupancy_status`/`status`
constrained to the literals above.

Service `app/services/property_mgmt.py` (new), modeled on `app/services/facilities.py`
(FAC-004) and `app/services/inventory.py`:
- `_flag_on()` / `_require_enabled()` → 404 when off (copy `inventory.py:51-58`).
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy `inventory.py:92-98`).
- `create_property(owner_sub, name, property_type, address, color_tags) -> dict` —
  derives `property_id`, conditional `attribute_not_exists(property_id)` put → idempotent
  on owner+name collision (returns existing).
- `get_property(property_id) -> dict | None` — reads SK=`META`.
- `update_property(property_id, *, user_sub, **kwargs) -> dict`, stamps `updated_at`.
- `archive_property(property_id, *, user_sub) -> dict` — sets `status="archived"`.

**Acceptance Criteria**
- `properties` `TableDef` present with both GSIs and `attr_types={"created_at": "N"}`;
  `just restart` creates the table without `ValidationException`.
- `PROPERTY_MGMT_ENABLED` defaults to `false`; with it off, every `property_mgmt`
  service entrypoint raises HTTP 404 via `_require_enabled()`.
- `create_property` is idempotent on (owner_sub, name): two calls return the same
  `property_id` and the second does not error.
- `T.properties` resolves; `PropertyIn/Out/UpdateIn` models import cleanly.
- No `if S.dev_mode` branch in `property_mgmt.py` (SECOPS-007).

**Dependencies**: none (foundational). Reuses: `app/services/inventory.py:51-58,92-98`
(flag/audit), `app/services/facilities.py` (FAC-004 service idiom),
`scripts/local-ddb-init.py:44+` (`TableDef`), `app/core/tables.py:317,569`,
`app/core/settings.py:839-847`, `app/core/time.py:2`, `commerce_order_service.py:67`
(id derivation). Contrasts: `docs/ofbiz/specs/FAC-001.md` §3 (facility = warehouse, not
rental).

---

### PROP-002: Unit entity nested under a Property — model + CRUD service

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Add the Unit (dwelling) entity nested under a property as `UNIT#{unit_id}` child rows
on the same `properties` partition — the FAC `LOC#{location_id}` child-row pattern
(`docs/ofbiz/specs/FAC-001.md` §3), but a Unit models a rentable dwelling, NOT a
warehouse bin (the analogue we contrast, not reuse).

Child row on `properties` (PK=`property_id`, SK=`UNIT#{unit_id}`):

| Attribute | Type | Notes |
|---|---|---|
| `property_id` | S | PK (same partition as the parent `META` row) |
| `sk` | S | `UNIT#{unit_id}`, `unit_id = uuid4().hex` (non-deterministic — a property may hold many units with the same label/number, mirroring FAC `create_location` Open-Q #3) |
| `unit_id` | S | Convenience copy of the id |
| `label` | S | Unit label / number (e.g. `"Apt 2B"`) |
| `bedrooms` | N | Bedroom count |
| `bathrooms` | N | Bathroom count (allow halves → store as decimal/`N`) |
| `square_footage` | N | Square footage |
| `market_rent_cents` | N | Market rent in cents (integer, money-as-cents convention) |
| `occupancy_status` | S | `vacant` \| `occupied` \| `turnover` \| `unavailable` (default `vacant`) |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |

GSI for the occupancy roll-up (PROP-003) — add to the **same** `properties` `TableDef`:
- `GSI_UNIT_OCCUPANCY` — PK=`property_id`, SK=`occupancy_status` (both `S`, no
  `attr_types` change) — query a property's units bucketed by occupancy without scanning.

> Note: keep child Unit rows queryable by the existing `properties` PK
> (`Key={"property_id": pid}` + `begins_with(sk, "UNIT#")`) for the per-property unit
> grid; the GSI above is the occupancy-count fast path.

Pydantic models in `app/models.py`: `UnitIn` (label, bedrooms, bathrooms,
square_footage, market_rent_cents, occupancy_status), `UnitOut` (all fields),
`UnitUpdateIn` (partial). `occupancy_status` constrained to the four literals.

Service additions in `app/services/property_mgmt.py`:
- `create_unit(property_id, *, label, bedrooms, bathrooms, square_footage, market_rent_cents, occupancy_status, user_sub) -> dict`
  — validates parent property exists + caller owns it (404 if missing); `uuid4().hex`
  unit_id; `put_item`; increments parent `unit_count` via an `ADD` `update_item` on the
  `META` row; `_audit("property.unit.created", ...)`.
- `get_unit(property_id, unit_id) -> dict | None`.
- `list_units(property_id) -> list[dict]` — `Key` query `begins_with(sk, "UNIT#")`,
  sorted by `label`.
- `update_unit(property_id, unit_id, *, user_sub, **kwargs) -> dict` — stamps
  `updated_at`; on `occupancy_status` change, best-effort recompute parent
  `occupancy_status` roll-up (delegates to the PROP-003 helper).
- `delete_unit(property_id, unit_id, *, user_sub) -> bool` — deletes the child row,
  decrements parent `unit_count`; returns `False` (never raises) for an unknown unit
  (mirrors `host_inventory.delete_host` contract noted in CLAUDE.md).

All entrypoints call `_require_enabled()` first.

**Acceptance Criteria**
- `create_unit` rejects (404) a unit under a non-existent or non-owned property.
- Units co-locate on the parent partition; `list_units(property_id)` returns only
  `UNIT#`-prefixed rows (never the `META` row).
- `market_rent_cents`, `bedrooms`, `bathrooms`, `square_footage` round-trip as numerics
  (Decimal→int/float coercion handled).
- Creating/deleting a unit maintains parent `unit_count` accurately.
- `GSI_UNIT_OCCUPANCY` is declared on the `properties` `TableDef`; querying it returns
  units bucketed by `occupancy_status`.
- Flag off → every unit entrypoint 404s.

**Dependencies**: PROP-001 (table + flag + property service + parent ownership check).
Reuses: FAC `LOC#` child-row pattern (`docs/ofbiz/specs/FAC-001.md` §3), `uuid4().hex`
id, `now_ts()` (`app/core/time.py:2`), `_audit` (`app/services/inventory.py:92-98`),
`host_inventory.delete_host` no-raise contract (CLAUDE.md). Contrasts: FAC
FacilityLocation models bins, not dwellings.

---

### PROP-003: List/filter endpoints + occupancy roll-up

**Type**: Feature
**Priority**: P1
**Estimate**: 1d

**Description**

Add the property/unit listing + filtering service functions and the per-property +
portfolio occupancy roll-up (occupied vs vacant counts via GSIs). Gap analysis §A row 3
("Property/unit list/filter + occupancy roll-up" — MISSING). This is rent-roll occupancy,
distinct from `platform_financial_dashboard.py` which is GMV/revenue (gap analysis §A
row 4).

Service additions in `app/services/property_mgmt.py`:
- `list_properties(owner_sub, *, status="active", property_type=None, cursor=None, limit=50) -> dict`
  — queries `GSI_OWNER` (PK=`owner_sub`, SK=`created_at`, newest-first), optionally
  filters `status` / `property_type`, paginates via `encode_cursor`/`decode_cursor`
  (`app/core/cursor.py:94,103`). Returns `{"properties": [...], "count": int, "cursor": str | None}`
  (the `{items, count, cursor}` shape used by `host_inventory.list_hosts`, per CLAUDE.md).
- `compute_property_occupancy(property_id) -> dict` — queries `GSI_UNIT_OCCUPANCY`
  (PK=`property_id`) and tallies per-status counts:
  `{"total": N, "occupied": N, "vacant": N, "turnover": N, "unavailable": N}`.
  Derives a property-level `occupancy_status`: `occupied` if all units occupied,
  `vacant` if none occupied, else `partial`; best-effort writes it back onto the parent
  `META` row (called by `create_unit`/`update_unit` on occupancy change — PROP-002).
- `portfolio_occupancy_rollup(owner_sub) -> dict` — iterates the owner's properties
  (via `list_properties`), sums `compute_property_occupancy` per property:
  `{"property_count", "unit_count", "occupied", "vacant", "occupancy_rate"}`
  (`occupancy_rate = occupied / max(unit_count, 1)`).

These are pure aggregation over GSIs — no new table. The roll-up is the data source for
the PROP-005 property-detail summary metrics and a future RPT-006/007 dashlet
(`docs/suitecrm/specs/RPT-006.md`, `docs/suitecrm/specs/RPT-007.md`) once the portfolio
dashboard cluster (gap analysis §C) is ticketed — not in scope here.

**Acceptance Criteria**
- `list_properties` paginates correctly and honors `status` + `property_type` filters;
  returns the `{properties, count, cursor}` shape.
- `compute_property_occupancy` returns correct per-status counts and matches the units
  written via PROP-002; derived property `occupancy_status` is `vacant`/`partial`/`occupied`.
- `portfolio_occupancy_rollup` sums correctly across multiple properties; `occupancy_rate`
  is 0..1 and never divides by zero on an empty portfolio.
- All roll-up reads go through GSIs (`GSI_OWNER`, `GSI_UNIT_OCCUPANCY`), not full scans.
- Flag off → 404.

**Dependencies**: PROP-001 (`GSI_OWNER`), PROP-002 (`GSI_UNIT_OCCUPANCY` + units).
Reuses: `app/core/cursor.py:94,103` (pagination), `host_inventory.list_hosts`
`{items, count, cursor}` shape (CLAUDE.md). Contrasts:
`app/services/platform_financial_dashboard.py` (revenue dashboard, not rent-roll).

---

### PROP-004: Router — `/ui/properties` + registration in `app/main.py`

**Type**: Feature
**Priority**: P1
**Estimate**: 1d

**Description**

Expose the PROP services over HTTP via a new `properties_router`, modeled exactly on
`app/routers/inventory.py` (auth split + `_require_enabled()` short-circuit) and the
FAC-005 router plan (`docs/ofbiz/specs/FAC-001.md` §4.2). Register it in `app/main.py`
next to `inventory_router` (`app/main.py:311` import, `:877` include).

```python
properties_router = APIRouter(prefix="/ui/properties", tags=["properties"])
```
Every handler calls `_require_enabled()` first (delegating to
`property_mgmt._require_enabled()`, exactly like `app/routers/inventory.py:32-38`).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/properties` | `require_ui_session` | `list_properties` (query params `status`, `property_type`, `cursor`, `limit`) |
| POST | `/ui/properties` | `require_admin_or_root_csrf` | `create_property` |
| GET | `/ui/properties/{property_id}` | `require_ui_session` | `get_property` (404 if none) |
| PUT | `/ui/properties/{property_id}` | `require_admin_or_root_csrf` | `update_property` |
| DELETE | `/ui/properties/{property_id}` | `require_admin_or_root_csrf` | `archive_property` |
| GET | `/ui/properties/{property_id}/occupancy` | `require_ui_session` | `compute_property_occupancy` |
| GET | `/ui/properties/{property_id}/units` | `require_ui_session` | `list_units` |
| POST | `/ui/properties/{property_id}/units` | `require_admin_or_root_csrf` | `create_unit` |
| GET | `/ui/properties/{property_id}/units/{unit_id}` | `require_ui_session` | `get_unit` (404 if none) |
| PUT | `/ui/properties/{property_id}/units/{unit_id}` | `require_admin_or_root_csrf` | `update_unit` |
| DELETE | `/ui/properties/{property_id}/units/{unit_id}` | `require_admin_or_root_csrf` | `delete_unit` |
| GET | `/ui/properties/portfolio/occupancy` | `require_ui_session` | `portfolio_occupancy_rollup` (caller's `user.sub`) |

> Declaration order: declare the literal `/portfolio/occupancy` route BEFORE the
> dynamic `/{property_id}` routes so FastAPI does not capture `portfolio` as a path
> param (same gotcha as the KYC `/templates`-before-`/{case_id}` and audit-export
> `/schedules`-before-`/{export_id}` ordering noted in CLAUDE.md).

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py:48,65,81`. `create_*` handlers pass `owner_sub=user.sub`.

**Acceptance Criteria**
- All 12 endpoints respond; flag off → every endpoint 404s (handler-level no-op, router
  still mounted, byte-for-byte unchanged platform).
- Read endpoints accept a UI session; mutation endpoints reject non-admin / missing-CSRF
  requests (403) per `require_admin_or_root_csrf`.
- `/ui/properties/portfolio/occupancy` resolves to the roll-up handler, NOT captured by
  `/{property_id}` (route declared first).
- `properties_router` imported and `include_router`'d in `app/main.py` adjacent to
  `inventory_router`.

**Dependencies**: PROP-001, PROP-002, PROP-003 (all service functions). Reuses:
`app/routers/inventory.py:32-38,48,65,81` (router idiom), `app/auth/policy.py:100`,
`app/services/sessions.py:330`, `app/main.py:311,877` (registration),
`docs/ofbiz/specs/FAC-001.md` §4.2 (FAC-005 router plan).

---

### PROP-005: Frontend — property cards list + property detail page (summary metrics + unit grid) + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2d

**Description**

Build the property-management UI and the hermetic backend + E2E tests. Gap analysis §A
("FE: property cards + detail + unit grid"). Follow the established frontend feature
recipe (CLAUDE.md "Adding a new feature" steps 5–9).

Frontend (`frontend/src/`):
- **Types** — add `Property`, `Unit`, `PropertyOccupancy`, `PortfolioOccupancy` and the
  in/update shapes to `frontend/src/api/types.ts` (mirror `app/models.py` PROP models).
- **API endpoints** — `frontend/src/api/endpoints/properties.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`): `listProperties`, `createProperty`,
  `getProperty`, `updateProperty`, `archiveProperty`, `getOccupancy`, `listUnits`,
  `createUnit`, `updateUnit`, `deleteUnit`, `getPortfolioOccupancy`.
- **Pages** under `frontend/src/pages/properties/`:
  - `PropertiesPage.tsx` — responsive **property card grid** (one card per property:
    name, type badge, address, color_tags chips, occupancy badge derived from
    `occupancy_status`, unit_count). Uses React Query `useQuery` on `listProperties`;
    "New Property" dialog (React Hook Form + Zod) calling `createProperty`. A small
    portfolio-occupancy summary strip at the top driven by `getPortfolioOccupancy`.
  - `PropertyDetailPage.tsx` — header (name/type/address/tags/archive action), a
    **summary-metrics row** (total units, occupied, vacant, turnover, occupancy rate
    from `getOccupancy`), and a **unit grid** listing each unit (label, beds/baths,
    sqft, market rent formatted from cents, occupancy badge) with add/edit/delete unit
    dialogs. shadcn/ui primitives (`Card`, `Dialog`, `Badge`, `Button`,
    `components/ui/`).
- **Routes** — lazy-load both pages in `frontend/src/App.tsx` (cf. `:14-37` lazy
  imports): `/properties` → `PropertiesPage`, `/properties/:propertyId` →
  `PropertyDetailPage`.
- **Sidebar** — add a "Properties" nav item to `frontend/src/components/layout/Sidebar.tsx`
  (cf. the nav-item array at `:104-121`, e.g. a `Building`/`Home` lucide icon,
  `path: "/properties"`). Gate visibility on a `propertyMgmtEnabled` flag if the
  sidebar already reads feature flags; otherwise show unconditionally (the routes 404
  server-side when off).

Tests:
- **Hermetic pytest** `tests/test_prop_property_units.py` — moto-bound `properties`
  table on frozen `T` (`object.__setattr__`), frozen `S` with `property_mgmt_enabled`
  toggled, route coroutines called directly on a fresh `asyncio.new_event_loop()`
  (no `TestClient`). Cover: property create idempotency, flag-off 404, unit CRUD +
  `unit_count` maintenance, occupancy roll-up math, portfolio roll-up, list/filter
  pagination, route-ordering (`/portfolio/occupancy` not captured by `/{property_id}`).
- **E2E** `frontend/e2e/properties.spec.ts` — cookie-auth (`injectAuth`) admin creates a
  property, adds units, asserts the card grid, detail summary metrics, and unit grid
  render; CSRF header on POSTs (`x-csrf-token`). Requires `PROPERTY_MGMT_ENABLED=1` in
  the E2E backend env.

**Acceptance Criteria**
- `/properties` renders a property card grid + portfolio summary; `/properties/:id`
  renders summary metrics + a unit grid; both reachable via the new sidebar nav item.
- Create/edit/delete property + unit flows work end-to-end against the PROP-004 router.
- Market rent displays as currency (cents → formatted); occupancy badges reflect
  `occupancy_status`.
- `tests/test_prop_property_units.py` passes offline (no AWS, no live stack).
- `frontend/e2e/properties.spec.ts` passes with the flag on.

**Dependencies**: PROP-004 (router/endpoints) — and transitively PROP-001/002/003.
Reuses: `frontend/src/api/client.ts`, `frontend/src/App.tsx:14-37` (lazy routes),
`frontend/src/components/layout/Sidebar.tsx:104-121` (nav items), shadcn/ui
(`components/ui/`), React Query + RHF/Zod conventions (CLAUDE.md frontend conventions),
hermetic-test + E2E patterns (FAC-001 §9, CLAUDE.md E2E section).

---

## Dependency order

PROP-001 (model + table + flag) → PROP-002 (unit entity + CRUD) → PROP-003
(list/filter + occupancy roll-up) → PROP-004 (router + `main.py` registration) →
PROP-005 (frontend + hermetic + E2E tests).
