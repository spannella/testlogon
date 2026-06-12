# PROP-002 — Unit entity nested under a Property — model + CRUD service

**Type**: Feature | **Priority**: P1 | **Estimate**: 1.5d
**Source**: `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002 + `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A

---

## 1. Summary & Goal

PROP-002 adds the Unit (dwelling) entity to the open-property vertical. A Unit is a rentable dwelling nested inside a Property — a `UNIT#{unit_id}` child row that co-locates on the same DynamoDB partition as the parent Property's `META` row. The deliverables are:

1. **Data model** — `UNIT#{unit_id}` child rows on the `properties` table, one new GSI (`GSI_UNIT_OCCUPANCY`) added to the existing `TableDef`, and Pydantic models `UnitIn` / `UnitOut` / `UnitUpdateIn`.
2. **Service functions** in `app/services/property_mgmt.py` — `create_unit`, `get_unit`, `list_units`, `update_unit`, `delete_unit`.
3. **Parent bookkeeping** — atomic `unit_count` maintenance on the parent `META` row on every create and delete; best-effort occupancy roll-up call on `update_unit` occupancy-status changes.

PROP-002 has no standalone router (that is PROP-004's deliverable) and no frontend (PROP-005). With `PROPERTY_MGMT_ENABLED=false` (the default) the ticket is a byte-for-byte no-op. With the flag on, the `properties` table already exists (PROP-001 precondition) and unit rows are co-located there — no second table is created.

The structural analogue is the FAC `LOC#{location_id}` child-row pattern (`docs/ofbiz/specs/FAC-001.md` §3), but a Unit models a rentable dwelling (beds/baths/sqft/market-rent/occupancy) — not a warehouse bin. The two domains never overlap.

---

## 2. Context & Current State

### 2.1 No Unit entity exists today

`docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A row 2 records **Unit entity — MISSING**. A `grep -rn "unit_id\|UNIT#\|market_rent" app/` returns no property-management results. The closest structural artefact is `app/services/inventory.py`, which uses `LOC#{location_id}` child rows on the `inventory` table — a warehouse-bin pattern, not a rental unit.

### 2.2 The `properties` table and flag are PROP-001's deliverable

PROP-002 depends entirely on PROP-001. Before PROP-002 can be merged, PROP-001 must have:
- Created the `properties` DynamoDB table (PK=`property_id`, SK=`META` + child rows) via the `TableDef` in `scripts/local-ddb-init.py`.
- Added `S.property_mgmt_enabled` and `S.properties_table_name` to `app/core/settings.py` (adjacent to the `returns_rma_enabled` block at `:846–847`).
- Wired `T.properties` in `app/core/tables.py` (dataclass field at `:317+`, initializer wire at `:569+`).
- Defined `_flag_on()`, `_require_enabled()`, `_audit()`, `_property_id()`, and the four property service functions in `app/services/property_mgmt.py`.

PROP-002 extends `property_mgmt.py` in-place, adds unit-related Pydantic models to `app/models.py`, and amends the `TableDef` in `scripts/local-ddb-init.py` to include `GSI_UNIT_OCCUPANCY`.

### 2.3 Flag gate pattern (reused from PROP-001 / inventory.py)

The `_require_enabled()` / `_flag_on()` pattern is defined at `app/services/inventory.py:50–57` and carried verbatim into `property_mgmt.py` by PROP-001. Every unit service function must call `_require_enabled()` as its first statement — identical to how `app/routers/inventory.py:38` delegates to `inv._require_enabled()` at the top of every handler.

### 2.4 Audit wrapper (reused from inventory.py:92–98)

`app/services/inventory.py:92–98` provides the lazy-import `_audit()` wrapper that calls `app.services.alerts.audit_event` and swallows all exceptions. PROP-001 already copies this into `property_mgmt.py`. Unit service functions reuse the same `_audit()` already present in the file.

### 2.5 `delete_unit` no-raise contract (analogous to host_inventory.delete_host)

`app/services/host_inventory.py:360–367` defines `delete_host` which returns `False` (never raises) for an unknown host:

```python
def delete_host(user_sub: str, host_id: str) -> bool:
    raw = _get_raw(user_sub, host_id)
    if not raw:
        return False
    ...
    return True
```

CLAUDE.md documents this contract explicitly: "delete_host returns False (never raises HostNotFound) for an unknown host." `delete_unit` mirrors this contract: returns `False` on unknown unit, `True` on successful deletion — never raises.

### 2.6 `unit_count` atomic maintenance

The parent `META` row carries a denormalized `unit_count` (introduced by PROP-001, initialized to `0`). PROP-002 must maintain it via DynamoDB `ADD` expressions — not read-modify-write — to prevent race conditions under concurrent unit creation or deletion. The pattern is used throughout the codebase for denormalized counters, e.g. `app/routers/messaging.py:4996` (`ADD unread_count :one`) and `app/routers/newsfeed.py:3714` (`ADD post_count :one`). NOTE: `app/services/inventory.py` uses optimistic-concurrency `SET` (not `ADD`) for its stock counters — it is NOT the source of the `ADD` counter pattern.

```python
# atomic increment on create
T.properties.update_item(
    Key={"property_id": property_id, "sk": "META"},
    UpdateExpression="ADD unit_count :one SET updated_at = :ts",
    ExpressionAttributeValues={":one": 1, ":ts": now_ts()},
)
# atomic decrement on delete
T.properties.update_item(
    Key={"property_id": property_id, "sk": "META"},
    UpdateExpression="ADD unit_count :neg SET updated_at = :ts",
    ExpressionAttributeValues={":neg": -1, ":ts": now_ts()},
)
```

### 2.7 Decimal coercion for numeric DynamoDB attributes

DynamoDB returns numeric attributes as `decimal.Decimal` via the boto3 resource API. `market_rent_cents`, `bedrooms`, `bathrooms`, `square_footage`, `created_at`, `updated_at` are stored as `N` and must be coerced to `int` (or `float` for `bathrooms`) before returning. This is the same coercion requirement noted in PROP-001 §5.4 and the CLAUDE.md `MessageEncryptionEnvelope Decimal coercion` pattern.

### 2.8 `bathrooms` as decimal

A property may have 1.5 or 2.5 bathrooms (half-bath = toilet + sink, no tub/shower). DynamoDB `N` stores arbitrary precision decimals. `bathrooms` is stored as `N` and coerced to `float` on read. The Pydantic model accepts `float` (e.g., `1.5`). `market_rent_cents` and `bedrooms` are always `int`.

### 2.9 Occupancy roll-up dependency on PROP-003

`update_unit` triggers a best-effort call to `compute_property_occupancy(property_id)` when `occupancy_status` changes. `compute_property_occupancy` is PROP-003's deliverable and lands in the **same** `property_mgmt.py` file. Because both functions are in the same module, a `from app.services.property_mgmt import compute_property_occupancy` self-import is always resolvable and never raises `ImportError` — the `try/except ImportError` idiom does NOT work for same-module forward references. The correct approach is a bare call inside `try/except Exception`, which catches `NameError` before PROP-003 ships and becomes a normal call afterward (see §4.1.4 step 8).

### 2.10 `list_units` sort by label

DynamoDB query results are ordered by SK (`UNIT#{unit_id}` where `unit_id` is a random hex UUID). Natural DynamoDB ordering is therefore non-deterministic for label display. `list_units` must sort the fetched items by `label` in Python after retrieval — the same pattern used by `app/routers/messaging.py` which sorts messages by `created_at` after a DynamoDB query (noted in CLAUDE.md `list_messages sort by created_at`).

### 2.11 `GSI_UNIT_OCCUPANCY` merging with PROP-001's TableDef

PROP-001 defines the `properties` `TableDef` with two GSIs (`GSI_OWNER`, `GSI_STATUS`). PROP-002 adds a third: `GSI_UNIT_OCCUPANCY` (PK=`property_id`, SK=`occupancy_status`). The two tickets must reconcile to produce a single `TableDef` with all three GSIs. If PROP-001 merges first, PROP-002 amends the `TableDef` in `scripts/local-ddb-init.py`; if they are implemented together, a single `TableDef` with all three is written at once. `just restart` recreates the table — no incremental `UpdateTable` migration needed in dev.

---

## 3. Data Model

### 3.1 Child row on the `properties` table

Units are stored as child rows on the same DynamoDB partition as the parent Property. No second table is created. The PK/SK design follows the FAC `LOC#{location_id}` idiom (`docs/ofbiz/specs/FAC-001.md` §3), applied to rental dwellings.

**Primary key**

| Key | Type | Value |
|---|---|---|
| `property_id` | S (PK) | Same partition as parent `META` row |
| `sk` | S (SK) | `"UNIT#{unit_id}"` — `unit_id = uuid4().hex` (non-deterministic; a property may hold many units with the same label) |

**Unit row attributes**

| Attribute | DDB Type | Constraints / Notes |
|---|---|---|
| `property_id` | S | PK; FK to parent Property |
| `sk` | S | `"UNIT#{unit_id}"` |
| `unit_id` | S | Convenience copy of the unit id; `uuid4().hex` (32-char hex string) |
| `label` | S | Human-readable unit label / number (e.g., `"Apt 2B"`, `"Unit 1"`); non-empty string |
| `bedrooms` | N | Bedroom count; non-negative integer |
| `bathrooms` | N | Bathroom count; non-negative float (allow halves: `1.5`, `2.5`) |
| `square_footage` | N | Square footage; non-negative integer |
| `market_rent_cents` | N | Market rent in cents; non-negative integer; money-as-cents convention — never store fractional dollars |
| `occupancy_status` | S | Literal: `vacant` \| `occupied` \| `turnover` \| `unavailable`; default `"vacant"` on create |
| `created_at` | N | `now_ts()` — integer Unix seconds (`app/core/time.py:2`) |
| `updated_at` | N | `now_ts()` — stamped on every `update_unit` call |

**Rationale for non-deterministic `unit_id`**: A property may contain multiple units with the same label over time (e.g., two `"Apt 1"` units from a renovation that split one unit into two). Using `uuid4().hex` avoids collisions. This mirrors the FAC `create_location` approach documented in the PROP-002 ticket (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002 Open-Q #3). The trade-off is that creation is not idempotent on (property_id, label) — callers must not retry creates without deduplication.

### 3.2 GSI — `GSI_UNIT_OCCUPANCY`

Added to the **same** `properties` `TableDef` as the existing `GSI_OWNER` and `GSI_STATUS`. Purpose: query all units under a property bucketed by `occupancy_status` without a full partition scan. Used by PROP-003's `compute_property_occupancy`.

| Index name | PK | SK | `attr_types` |
|---|---|---|---|
| `GSI_UNIT_OCCUPANCY` | `property_id` (S) | `occupancy_status` (S) | none needed — both keys are `S` |

Note: both attributes are already `S`, so no `attr_types` addition is required for this GSI. The existing `attr_types={"created_at": "N"}` from PROP-001 is preserved unchanged.

**Complete `TableDef` after PROP-002** (all three GSIs):

```python
TableDef(
    _resolve_table_name(S.properties_table_name, "properties"),
    "property_id",
    "sk",
    gsi=[
        {"index_name": "GSI_OWNER",            "partition_key": "owner_sub",         "sort_key": "created_at"},
        {"index_name": "GSI_STATUS",           "partition_key": "status",            "sort_key": "created_at"},
        {"index_name": "GSI_UNIT_OCCUPANCY",   "partition_key": "property_id",       "sort_key": "occupancy_status"},
    ],
    attr_types={"created_at": "N"},
),
```

`just restart` will recreate the `properties` table with all three GSIs. In production, `GSI_UNIT_OCCUPANCY` is added via `UpdateTable` + async backfill before PROP-002 code is deployed (the backfill populates the index from existing rows; during backfill `compute_property_occupancy` may return incomplete counts — acceptable since the whole vertical defaults to flag-off).

### 3.3 Pydantic models (`app/models.py`)

Add adjacent to the `PropertyIn` / `PropertyOut` / `PropertyUpdateIn` models introduced by PROP-001.

**`UnitIn`** — creation payload:

```python
class UnitIn(BaseModel):
    label: str
    bedrooms: int = Field(ge=0)
    bathrooms: float = Field(ge=0)
    square_footage: int = Field(ge=0)
    market_rent_cents: int = Field(ge=0)
    occupancy_status: Literal["vacant", "occupied", "turnover", "unavailable"] = "vacant"
```

**`UnitOut`** — full read response:

```python
class UnitOut(BaseModel):
    property_id: str
    unit_id: str
    label: str
    bedrooms: int
    bathrooms: float
    square_footage: int
    market_rent_cents: int
    occupancy_status: Literal["vacant", "occupied", "turnover", "unavailable"]
    created_at: int
    updated_at: int
```

**`UnitUpdateIn`** — partial update; all fields optional:

```python
class UnitUpdateIn(BaseModel):
    label: Optional[str] = None
    bedrooms: Optional[int] = Field(default=None, ge=0)
    bathrooms: Optional[float] = Field(default=None, ge=0)
    square_footage: Optional[int] = Field(default=None, ge=0)
    market_rent_cents: Optional[int] = Field(default=None, ge=0)
    occupancy_status: Optional[Literal["vacant", "occupied", "turnover", "unavailable"]] = None
```

No new `Address` model is needed in PROP-002 — that is PROP-001's model.

---

## 4. API / Service Design

### 4.1 Service additions: `app/services/property_mgmt.py`

All five functions are added to the existing `property_mgmt.py` file created by PROP-001. No second service file is created.

#### 4.1.1 `create_unit`

```python
def create_unit(
    property_id: str,
    *,
    label: str,
    bedrooms: int,
    bathrooms: float,
    square_footage: int,
    market_rent_cents: int,
    occupancy_status: str = "vacant",
    user_sub: str,
) -> dict:
```

**Behavior**:
1. Calls `_require_enabled()`.
2. Reads the parent property via `T.properties.get_item(Key={"property_id": property_id, "sk": "META"})`. Raises `HTTPException(404, "Property not found")` if absent.
3. Asserts caller ownership: if `item["owner_sub"] != user_sub` raise `HTTPException(403, "Not the property owner")`. (Admin users who own the property will have `owner_sub == user_sub`; ROOT users may bypass this check — see §5.5.)
4. Generates `unit_id = uuid4().hex`.
5. Builds unit item dict: all unit attributes, `sk=f"UNIT#{unit_id}"`, `created_at=now_ts()`, `updated_at=now_ts()`.
6. `T.properties.put_item(Item=unit_item)` — unconditional put (units are non-deterministic by UUID, no collision possible).
7. Atomically increments `unit_count` on the `META` row via `ADD`:
   ```python
   T.properties.update_item(
       Key={"property_id": property_id, "sk": "META"},
       UpdateExpression="ADD unit_count :one SET updated_at = :ts",
       ExpressionAttributeValues={":one": 1, ":ts": now_ts()},
   )
   ```
8. Emits `_audit("property.unit.created", user_sub, property_id=property_id, unit_id=unit_id, label=label)`.
9. Returns the unit item dict (with Decimal fields coerced to `int`/`float`).

#### 4.1.2 `get_unit`

```python
def get_unit(property_id: str, unit_id: str) -> dict | None:
```

**Behavior**:
1. Calls `_require_enabled()`.
2. `T.properties.get_item(Key={"property_id": property_id, "sk": f"UNIT#{unit_id}"})`.
3. Returns the item dict (with numeric fields coerced) or `None` if absent.

#### 4.1.3 `list_units`

```python
def list_units(property_id: str) -> list[dict]:
```

**Behavior**:
1. Calls `_require_enabled()`.
2. Queries the `properties` table using `KeyConditionExpression=Key("property_id").eq(property_id) & Key("sk").begins_with("UNIT#")`. Loops `LastEvaluatedKey` until exhausted (CLAUDE.md: "FilterExpression doesn't reduce page size" — must loop even when no filter is applied, to handle large unit counts).
3. Coerces Decimal numeric fields on each item.
4. Sorts the result list by `label` (case-insensitive, ascending) in Python after retrieval — DynamoDB's SK ordering on `UNIT#{uuid4().hex}` is not meaningful for display.
5. Returns the sorted list. Empty list is valid for a property with no units.

#### 4.1.4 `update_unit`

```python
def update_unit(
    property_id: str,
    unit_id: str,
    *,
    user_sub: str,
    **kwargs,
) -> dict:
```

Accepted `kwargs` keys: `label`, `bedrooms`, `bathrooms`, `square_footage`, `market_rent_cents`, `occupancy_status`.

**Behavior**:
1. Calls `_require_enabled()`.
2. Reads the existing unit via `get_unit(property_id, unit_id)`. Raises `HTTPException(404)` if absent.
3. Verifies parent property existence by reading the `META` row; raises `HTTPException(404, "Property not found")` if the parent is gone (orphaned unit scenario).
4. Verifies caller ownership (`META` row `owner_sub` check, same as `create_unit` step 3).
5. Builds `UpdateExpression` from `kwargs` plus mandatory `updated_at = :ts`. Only keys present in `kwargs` are included (partial update).
6. Calls `T.properties.update_item(Key={"property_id": property_id, "sk": f"UNIT#{unit_id}"}, ...)`.
7. Emits `_audit("property.unit.updated", user_sub, property_id=property_id, unit_id=unit_id, fields=list(kwargs.keys()))`.
8. **If `occupancy_status` is among the updated keys**: triggers a best-effort roll-up call:
   ```python
   try:
       compute_property_occupancy(property_id)  # type: ignore[name-defined]
   except Exception:
       pass
   ```
   `compute_property_occupancy` is PROP-003's deliverable and is added to the **same** `app/services/property_mgmt.py` file. Before PROP-003 merges the name does not exist in the module, so a bare `compute_property_occupancy(...)` call raises `NameError`, which the `except Exception` guard absorbs. After PROP-003 merges, the call resolves normally. Do NOT use a self-import (`from app.services.property_mgmt import compute_property_occupancy`) — a `from`-import within the same module is always resolvable (Python re-reads the already-loaded module), so `ImportError` never fires and the guard is ineffective before PROP-003 ships. A bare call with `except Exception` is the correct pattern for a same-module forward reference.
9. Reads and returns the updated item.

#### 4.1.5 `delete_unit`

```python
def delete_unit(property_id: str, unit_id: str, *, user_sub: str) -> bool:
```

**Behavior**:
1. Calls `_require_enabled()`.
2. Reads the existing unit via `get_unit(property_id, unit_id)`. If absent, returns `False` immediately — **never raises** (mirrors `host_inventory.delete_host:360–367`).
3. Verifies parent property existence and caller ownership (reads `META` row). If the parent is missing, proceeds to delete the orphaned row anyway (best-effort cleanup) without ownership check — parent-absent means no owner to verify.
4. `T.properties.delete_item(Key={"property_id": property_id, "sk": f"UNIT#{unit_id}"})`.
5. Atomically decrements `unit_count` on the `META` row via `ADD unit_count -1`. Uses a guard to prevent going below 0:
   ```python
   T.properties.update_item(
       Key={"property_id": property_id, "sk": "META"},
       UpdateExpression="ADD unit_count :neg SET updated_at = :ts",
       ConditionExpression="unit_count > :z",
       ExpressionAttributeValues={":neg": -1, ":z": 0, ":ts": now_ts()},
   )
   ```
   `ConditionalCheckFailedException` (already at 0) is swallowed — `unit_count` cannot go negative.
6. Emits `_audit("property.unit.deleted", user_sub, property_id=property_id, unit_id=unit_id)`.
7. Returns `True`.

### 4.2 Router endpoints (PROP-004 preview)

PROP-002 ships only the service layer. The router (PROP-004) exposes these service functions over HTTP. The relevant subset for unit operations:

| Method | Path | Auth dep | Service call |
|---|---|---|---|
| `GET` | `/ui/properties/{property_id}/units` | `require_ui_session` | `list_units(property_id)` |
| `POST` | `/ui/properties/{property_id}/units` | `require_admin_or_root_csrf` | `create_unit(property_id, **body, user_sub=user.sub)` |
| `GET` | `/ui/properties/{property_id}/units/{unit_id}` | `require_ui_session` | `get_unit(property_id, unit_id)` → 404 if None |
| `PUT` | `/ui/properties/{property_id}/units/{unit_id}` | `require_admin_or_root_csrf` | `update_unit(property_id, unit_id, user_sub=user.sub, **body.model_dump(exclude_none=True))` |
| `DELETE` | `/ui/properties/{property_id}/units/{unit_id}` | `require_admin_or_root_csrf` | `delete_unit(property_id, unit_id, user_sub=user.sub)` |

Auth split is identical to the property-level split in `app/routers/inventory.py:36–81`: reads → `require_ui_session` (`app/services/sessions.py:330`), mutations → `require_admin_or_root_csrf` (`app/auth/policy.py:100`).

### 4.3 Response shapes

**`list_units` response**:
```json
{"units": [...UnitOut...], "count": N}
```
(No cursor pagination on units — a property is unlikely to exceed hundreds of units. If needed in the future, `app/core/cursor.py:94,103` provides `encode_cursor`/`decode_cursor`.)

**`create_unit` / `get_unit` / `update_unit` response**: `UnitOut` (single object, HTTP 200/201).

**`delete_unit` response**: `{"ok": true, "unit_id": "..."}` (HTTP 200) or `{"ok": false, "unit_id": "..."}` (HTTP 404 from the router when the service returns `False`).

---

## 5. Detailed Behavior & Edge Cases

### 5.1 Parent property not found on `create_unit`

If `property_id` does not exist in the `properties` table (no `META` row), `create_unit` raises `HTTPException(404, "Property not found")` before writing anything. The unit row is never created for an orphaned `property_id`. This check is a DynamoDB `get_item` — not a GSI query — so it is strongly consistent.

### 5.2 `list_units` returns only `UNIT#` rows, never `META`

The `begins_with(sk, "UNIT#")` KeyConditionExpression ensures the parent `META` row is excluded from unit listings. The `META` SK is `"META"`, which does not start with `"UNIT#"`.

### 5.3 `unit_count` accuracy under concurrent mutations

`create_unit` uses `ADD unit_count 1` and `delete_unit` uses `ADD unit_count -1` — DynamoDB atomic operations that prevent lost-update races. However, if a unit `put_item` succeeds but the subsequent `unit_count` `update_item` fails (e.g., transient network error), the count is under-reported. This is an accepted eventual-consistency trade-off. A reconciliation function (outside PROP-002 scope) can re-derive `unit_count` by counting `UNIT#`-prefixed rows and writing it back. The floor guard in `delete_unit` (`unit_count > :z` condition) prevents the count from going negative even if inconsistency occurs.

### 5.4 `bathrooms` stored as `N` — float round-trip

DynamoDB `N` stores `1.5` as the string `"1.5"` internally and returns it as `Decimal("1.5")` via boto3. The service coerces to `float(item["bathrooms"])`. `UnitOut.bathrooms` is typed `float`. Callers sending integer values (e.g., `bathrooms=2`) receive `2.0` back — this is intentional.

### 5.5 Ownership enforcement — ADMIN vs ROOT

`create_unit` and `update_unit` check that `META["owner_sub"] == user_sub`. This is correct for the single-platform deployment assumption (PROP-001 §10 item 2 — no cross-landlord isolation needed). ROOT users may own properties (i.e., `owner_sub == root_user_sub`) and can therefore pass this check. A ROOT user who does not own the property would be blocked. If ROOT bypass is required (administrative override), the check should be conditioned: `if user.role != Role.ROOT and item["owner_sub"] != user_sub: raise 403`. This is documented as an open question (§10 item 1).

### 5.6 `occupancy_status` transition semantics

The four statuses are:
- `vacant` — no tenant, available for leasing.
- `occupied` — currently leased; set when a Lease entity is activated (PROP §B cluster, out of scope here).
- `turnover` — previous tenant departed; cleaning/repairs in progress.
- `unavailable` — off-market (renovation, owner-occupied, etc.).

PROP-002 does not enforce transition rules (any status → any status is allowed). Transition enforcement (e.g., `occupied → turnover` only when a lease ends) is the Lease cluster's responsibility.

### 5.7 `delete_unit` with an active lease (future guard)

Currently, `delete_unit` hard-deletes the unit row regardless of lease state. Once the Lease cluster (PROP §B) is implemented, `delete_unit` should check for active leases on the unit and return `HTTPException(409, "Unit has an active lease")`. This guard is **out of PROP-002 scope** — it requires the Lease service, which does not yet exist. Document this as a known follow-up in §10.

### 5.8 `market_rent_cents` is informational at this layer

PROP-002 stores `market_rent_cents` as the asking/market rent on the unit. It is not wired into any billing ledger or payment primitive at this layer. The rent ledger (`billing_shared.new_ledger_entry` at `:224`, `settle_or_reverse_ledger` at `:262`, `apply_balance_delta` at `:83`, `compute_due` at `:158`) is used only by the Rent Ledger cluster (PROP §B). PROP-002 stores the value as an informational field for display and for the Lease entity to copy into the lease's contracted rent on creation.

### 5.9 `list_units` for a property with no units

Returns `{"units": [], "count": 0}`. The DynamoDB query with `begins_with(sk, "UNIT#")` legitimately returns zero items for a newly created property. This is not an error condition.

### 5.10 Unit rows are hard-deleted (not soft-deleted)

Unlike Properties (which are archived, not deleted — PROP-001 §5.7), Unit rows are hard-deleted by `delete_unit`. The rationale: a unit that no longer physically exists has no historical significance at the unit-entity level. Historical financial records (ledger entries, rent payments) are attached to lease rows (PROP §B), not unit rows. If audit of unit deletions is needed, it is captured via the `_audit("property.unit.deleted", ...)` call.

### 5.11 `GSI_UNIT_OCCUPANCY` query semantics

The GSI has `property_id` as PK and `occupancy_status` as SK. A query for a specific occupancy bucket:

```python
T.properties.query(
    IndexName="GSI_UNIT_OCCUPANCY",
    KeyConditionExpression=Key("property_id").eq(pid) & Key("occupancy_status").eq("vacant"),
)
```

This is how PROP-003's `compute_property_occupancy` counts units per status. The GSI only indexes rows that have both `property_id` and `occupancy_status` attributes — `META` rows have `occupancy_status` (the property-level roll-up field) which could appear in this index. To exclude them: filter `begins_with(sk, "UNIT#")` as a `FilterExpression` on the GSI query, or (preferred) rely on the fact that `compute_property_occupancy` counts units, not properties — it will add a `FilterExpression` for `begins_with(sk, "UNIT#")`.

---

## 6. Feature Flag & Config

### 6.1 Master flag (unchanged from PROP-001)

| Setting key | Env var | Default | Effect when off |
|---|---|---|---|
| `property_mgmt_enabled` | `PROPERTY_MGMT_ENABLED` | `false` | Every `property_mgmt.py` function (including all five unit functions) raises HTTP 404; platform byte-for-byte unchanged |

PROP-002 does not introduce any new feature flags. The master `PROPERTY_MGMT_ENABLED` flag gates the entire vertical including units.

### 6.2 Table name config (unchanged from PROP-001)

| Setting key | Env var | Default |
|---|---|---|
| `properties_table_name` | `PROPERTIES_TABLE_NAME` | `"properties"` |

Units co-locate on this same table — no second table name config is needed.

### 6.3 `.env.local.example` update

No new variables beyond what PROP-001 added. To enable units in dev, set `PROPERTY_MGMT_ENABLED=true` in `.env.local` and run `just restart`. The `properties` table will be recreated with all three GSIs (including `GSI_UNIT_OCCUPANCY` from PROP-002's amended `TableDef`).

### 6.4 E2E environment

The E2E spec (`frontend/e2e/properties.spec.ts`, delivered by PROP-005) requires `PROPERTY_MGMT_ENABLED=1`. Unit-specific E2E tests are part of PROP-005 and inherit the same environment requirement.

---

## 7. Dev/Prod Parity (SECOPS-007), Idempotency, Security & Money-safety

### 7.1 SECOPS-007 — zero `dev_mode` branches

`app/services/property_mgmt.py` must contain **no** `if S.dev_mode` branches across all five unit functions. The same DynamoDB code path (`T.properties.*`) runs in dev (boto3 intercepted by moto in-process via `app/core/dev_s3.py` pattern) and prod (real DynamoDB). This matches the contract in `docs/open-property/PROPERTY_UNITS_TICKETS.md` §"Cross-cutting constraints": "Zero `if S.dev_mode` branches in business logic; the same `T.*` handles in both environments." The precedent is `app/services/inventory.py` — grep it for `dev_mode` → no results.

### 7.2 Idempotency

`create_unit` is **not** idempotent on (property_id, label) by design — the non-deterministic `uuid4().hex` unit_id means each call creates a new row. Callers must handle deduplication at the application level (e.g., check existing units by label before creating). `get_unit`, `list_units` are read-only and trivially idempotent. `update_unit` is idempotent in result (re-applying same kwargs produces same final state, differing only in `updated_at`). `delete_unit` is idempotent in effect — calling it twice returns `True` then `False`, with no error raised on the second call.

### 7.3 Security — ownership and authorization

- **Ownership check**: `create_unit` and `update_unit` read the parent `META` row and compare `owner_sub` to `user_sub`. A non-owning ADMIN cannot create or update units under another landlord's property.
- **Auth boundary**: mutations require `require_admin_or_root_csrf` at the router layer (`app/auth/policy.py:100`), which enforces `role ∈ {ADMIN, ROOT}` and CSRF validation for cookie-auth. Bearer-auth requests skip CSRF per CLAUDE.md.
- **Read access**: `get_unit` and `list_units` use `require_ui_session` — no ownership check at the service layer for reads (consistent with PROP-001 §7.3 rationale for single-platform deployment).
- **CSRF**: cookie-auth POSTs/PUTs/DELETEs require `x-csrf-token` header matching the `ui_csrf` cookie value, enforced by `require_admin_or_root_csrf` via `enforce_cookie_csrf` (defined at `app/auth/policy.py:71`; called from `require_admin_or_root_csrf` at `:105`).

### 7.4 Money-safety — rent ledger not touched

PROP-002 stores `market_rent_cents` as an informational integer. It does **not** call `billing_shared.new_ledger_entry`, `settle_or_reverse_ledger`, `apply_balance_delta`, or `compute_due`. No Stripe/PayPal/CCBill provider SDK is invoked. The billing table (`T.billing`) is not accessed. All billing primitives remain dormant until the Rent Ledger cluster. When the rent ledger is implemented:

- Every rent charge row goes through `new_ledger_entry` (`billing_shared.py:224`) — never a raw `put_item` on the billing table.
- Voiding a charge uses `settle_or_reverse_ledger` (`billing_shared.py:262`) — never a `delete_item`.
- Balance tracking uses `apply_balance_delta` (`billing_shared.py:83`) — never a read-modify-write.
- Outstanding amounts are read via `compute_due` (`billing_shared.py:158`) — no new calculation logic.
- No online payment provider is used for rent; payments are manually recorded.

These rules are stated here as constraints for the Rent Ledger implementer.

### 7.5 Audit trail

Every unit mutation emits a best-effort `_audit()` call:

| Event | When |
|---|---|
| `property.unit.created` | `create_unit` success |
| `property.unit.updated` | `update_unit` success |
| `property.unit.deleted` | `delete_unit` success (when unit existed) |

Audit failure (exception from `audit_event`) is swallowed per the `_audit()` wrapper. The audit trail enables the future EVT-011 record-link and RPT-006/007 dashlet audit queries without additional instrumentation.

---

## 8. Backward Compatibility & Migration

### 8.1 Additive-only changes

PROP-002 adds:
- Three Pydantic models to `app/models.py`: `UnitIn`, `UnitOut`, `UnitUpdateIn` (additive; no existing model is modified).
- Five functions to `app/services/property_mgmt.py` (additive; no existing function is modified).
- `GSI_UNIT_OCCUPANCY` to the `properties` `TableDef` in `scripts/local-ddb-init.py` (amends the PROP-001 `TableDef` entry; the change is backward-compatible because `just restart` recreates the table).

No existing endpoint, service function, DynamoDB table schema, or Pydantic model is altered.

### 8.2 `TableDef` reconciliation with PROP-001

The `properties` `TableDef` introduced by PROP-001 must be updated by PROP-002 to include `GSI_UNIT_OCCUPANCY`. In a sequential merge:

1. PROP-001 merges first: `TableDef` has `GSI_OWNER` + `GSI_STATUS`.
2. PROP-002 amends the same `TableDef` entry to add `GSI_UNIT_OCCUPANCY`.
3. `just restart` recreates the table with all three GSIs.

If merged together, a single `TableDef` with all three GSIs is written at once (preferred).

### 8.3 Dev table recreation

In dev, `just restart` calls `scripts/local-ddb-init.py` which calls `CreateTable` for every `TableDef`. Because the `properties` table is dropped and recreated, all existing test data is wiped on each restart — consistent with the dev workflow.

### 8.4 Production deployment

1. Add `GSI_UNIT_OCCUPANCY` to the `properties` table via `UpdateTable`. DynamoDB creates the GSI asynchronously (backfill from existing items). During backfill `GSI_UNIT_OCCUPANCY` queries may be incomplete — acceptable since `PROPERTY_MGMT_ENABLED` defaults to `false`.
2. Deploy PROP-002 code (new unit service functions; zero existing behavior changes).
3. Enable `PROPERTY_MGMT_ENABLED=true` once table and GSI are verified.

### 8.5 Rollback

With `PROPERTY_MGMT_ENABLED=false`, the unit service functions are dormant. Rolling back PROP-002 requires reverting the three file changes (`models.py`, `property_mgmt.py`, `local-ddb-init.py`). In production, the `GSI_UNIT_OCCUPANCY` GSI can be left on the table (it is inert with the flag off) or removed via `UpdateTable` with `GlobalSecondaryIndexUpdates: [{Delete: {IndexName: "GSI_UNIT_OCCUPANCY"}}]`.

---

## 9. Test Plan

### 9.1 Hermetic pytest — `tests/test_prop_002_unit_entity.py`

All tests run **offline**: no live stack, no real AWS calls. Pattern: moto-backed `properties` table bound to a frozen `T.properties` handle via `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`. Route coroutines (once PROP-004 ships them) called directly on a fresh `asyncio.new_event_loop()` — no `TestClient` (broken per CLAUDE.md). Same hermetic approach as `tests/test_gap_0220_0221_ssh_stored_key.py`, `tests/test_gap_0233_0234_ssh_session_recording.py`, `tests/test_gap_0265_0266_kyc_risk_scoring.py`.

**Fixture setup** (creates `properties` table with all three GSIs, binds to `T.properties`, enables the flag):

```python
import asyncio, uuid
import boto3, pytest
from moto import mock_aws
from unittest.mock import patch

@pytest.fixture(autouse=True)
def setup(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="properties",
            KeySchema=[
                {"AttributeName": "property_id", "KeyType": "HASH"},
                {"AttributeName": "sk",           "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "property_id",    "AttributeType": "S"},
                {"AttributeName": "sk",              "AttributeType": "S"},
                {"AttributeName": "owner_sub",       "AttributeType": "S"},
                {"AttributeName": "status",          "AttributeType": "S"},
                {"AttributeName": "created_at",      "AttributeType": "N"},
                {"AttributeName": "occupancy_status","AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {"IndexName": "GSI_OWNER",
                 "KeySchema": [{"AttributeName": "owner_sub", "KeyType": "HASH"},
                                {"AttributeName": "created_at", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI_STATUS",
                 "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"},
                                {"AttributeName": "created_at", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI_UNIT_OCCUPANCY",
                 "KeySchema": [{"AttributeName": "property_id", "KeyType": "HASH"},
                                {"AttributeName": "occupancy_status", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        from app.core import tables as T_mod
        from app.services import property_mgmt as svc
        object.__setattr__(T_mod.T, "properties", table)
        object.__setattr__(svc.S, "property_mgmt_enabled", True)
        object.__setattr__(svc.S, "properties_table_name", "properties")
        yield table, svc
```

**Test cases (minimum required; ~20 tests)**:

1. **Flag-off 404 on all unit functions**: toggle `property_mgmt_enabled=False`; call each of the five unit functions; assert each raises `HTTPException(status_code=404)` before any DDB access.

2. **`create_unit` success — full field round-trip**: create a parent property, then call `create_unit` with all fields including `bathrooms=1.5`; assert returned dict contains `unit_id` (32-char hex), `sk=f"UNIT#{unit_id}"`, `occupancy_status="vacant"`, `market_rent_cents=150000`, `bathrooms=1.5` (float), `bedrooms=2` (int).

3. **`create_unit` increments `unit_count` on parent**: read `META` row before and after `create_unit`; assert `unit_count` increases by 1.

4. **`create_unit` rejects non-existent property**: call with a random `property_id`; assert `HTTPException(404)`.

5. **`create_unit` rejects wrong owner**: create property as `owner1`; call `create_unit` with `user_sub="owner2"`; assert `HTTPException(403)`.

6. **`get_unit` hit and miss**: create a unit, `get_unit` returns the item; `get_unit` with unknown `unit_id` returns `None`.

7. **`list_units` returns only `UNIT#` rows**: create a property, create two units, call `list_units`; assert returned list has exactly 2 items; assert no item has `sk="META"`.

8. **`list_units` sorted by label**: create units with labels `"Unit C"`, `"Unit A"`, `"Unit B"` (creation order); assert `list_units` returns them in alphabetical order.

9. **`list_units` empty**: create a property with no units; assert `list_units` returns `[]`.

10. **`update_unit` partial update**: create a unit, call `update_unit` with only `market_rent_cents=200000`; assert returned item has `market_rent_cents=200000` and all other fields unchanged; assert `updated_at >= original`.

11. **`update_unit` 404 on unknown unit**: call with unknown `unit_id`; assert `HTTPException(404)`.

12. **`update_unit` occupancy change triggers roll-up (best-effort)**: call `update_unit` with `occupancy_status="occupied"` while `compute_property_occupancy` is not yet implemented; assert no exception is raised (the `except Exception: pass` guard absorbs the missing function error).

13. **`delete_unit` success returns True and decrements `unit_count`**: create a unit, delete it; assert return value `True`; assert `unit_count` on `META` row is back to 0; assert `get_unit` returns `None`.

14. **`delete_unit` unknown unit returns False without raising**: call `delete_unit` with unknown `unit_id`; assert returns `False`, no exception raised.

15. **`delete_unit` idempotency**: create and delete a unit (returns `True`); call `delete_unit` again on same `unit_id` (returns `False`); no exception.

16. **`unit_count` floor guard**: create then delete a unit; call `delete_unit` a second time; assert `unit_count` on `META` remains at `0` (not `-1`).

17. **Numeric Decimal coercion**: after creation, read the raw DDB item and verify `market_rent_cents`, `bedrooms`, `created_at` are `Decimal`; then call `get_unit` and verify they are `int`; call `get_unit` for `bathrooms=1.5` and verify it is `float`.

18. **`GSI_UNIT_OCCUPANCY` query**: create two `vacant` units and one `occupied` unit; query the GSI for `property_id=X, occupancy_status="vacant"`; assert 2 items returned. Query for `"occupied"`; assert 1 item. Confirm no `META` row in results (add `FilterExpression` to exclude `sk` not starting with `"UNIT#"`).

19. **`list_units` does not return `META` row**: explicitly verify by checking all returned items have `sk.startswith("UNIT#")`.

20. **Audit event emission**: patch `app.services.alerts.audit_event`; call `create_unit`, `update_unit`, `delete_unit`; assert the mock was called with the correct event names (`property.unit.created`, `property.unit.updated`, `property.unit.deleted`).

### 9.2 E2E tests (PROP-005 deliverable)

Full E2E tests are PROP-005's scope. The unit-related E2E flow to cover in `frontend/e2e/properties.spec.ts`:

- Admin creates a property, then adds a unit via `POST /ui/properties/{pid}/units` with CSRF header (`x-csrf-token`).
- `GET /ui/properties/{pid}/units` returns the created unit.
- Admin updates the unit's `market_rent_cents` and `occupancy_status`.
- Admin deletes the unit; subsequent GET returns 404.
- `GET /ui/properties/{pid}` after unit operations shows correct `unit_count`.
- Flag-off: with `PROPERTY_MGMT_ENABLED` unset, every unit endpoint returns 404.

Auth: `injectAuth(page, "charlie_admin")` for cookie-based admin session (pattern from CLAUDE.md E2E section, `e2e_admin_session_setup.py`).

---

## 10. Open Questions / Assumptions

1. **ROOT bypass for ownership check.** `create_unit` and `update_unit` check `owner_sub == user_sub`. A ROOT user who does not own the property is blocked. If ROOT users must be able to manage any property's units (platform admin override), add `if user.role == Role.ROOT: pass` before the ownership check. **Assumption**: ROOT users will own properties on a single-platform deployment; no bypass needed for MVP.

2. **`delete_unit` with active lease.** When the Lease cluster (PROP §B) lands, `delete_unit` should refuse to delete a unit with an active lease. Currently it hard-deletes unconditionally. **Assumption**: enforce at the Lease cluster layer, not in PROP-002.

3. **`create_unit` idempotency.** Non-deterministic `uuid4().hex` means no idempotency on (property_id, label) collision. The product may need a "create-or-get-by-label" path. **Assumption**: callers handle deduplication; the API creates a new row on each call. A future `GET /units?label=X` search endpoint can be added without schema changes.

4. **`list_units` pagination.** Currently returns all units sorted by label — no cursor pagination. Properties with 50+ units are uncommon in the MVP scenario. **Assumption**: no cursor needed for MVP; add `app/core/cursor.py:94,103` pagination as a follow-up if needed.

5. **`bathrooms` precision.** Stored as DynamoDB `N`; values like `1.5`, `2.5` are valid. Values like `1.333` are technically allowed but have no physical meaning. **Assumption**: caller responsibility; no server-side validation beyond `ge=0`.

6. **`occupancy_status` transitions.** No transition enforcement in PROP-002; any → any is allowed. Enforcing transitions (e.g., `occupied → turnover` only on lease termination) is a Lease cluster concern. **Assumption**: free transitions at the unit level for MVP.

7. **`META` row in `GSI_UNIT_OCCUPANCY`.** The parent `META` row has `occupancy_status` (the property-level roll-up), which means it will appear in `GSI_UNIT_OCCUPANCY` queries. PROP-003's `compute_property_occupancy` must add a `FilterExpression=Attr("sk").begins_with("UNIT#")` to exclude the `META` row. **Assumption**: PROP-003 implementer is responsible for this filter; PROP-002 does not add any marker to distinguish unit rows from `META` in the GSI beyond the SK prefix.

---

## 11. Dependencies

### 11.1 Hard upstream dependency

| Ticket | Dependency |
|---|---|
| **PROP-001** | `T.properties` table handle; `_require_enabled()` / `_flag_on()` flag gate; `_audit()` wrapper; `S.property_mgmt_enabled` + `S.properties_table_name` settings; `property_mgmt.py` file; `PropertyIn/Out/UpdateIn` models; `create_property`/`get_property` service functions |

PROP-002 cannot be implemented without PROP-001 in place (the `properties` table and its DDB handle must exist).

### 11.2 Downstream tickets that depend on PROP-002

| Ticket | What it needs from PROP-002 |
|---|---|
| **PROP-003** (list/filter + occupancy roll-up) | `GSI_UNIT_OCCUPANCY` for `compute_property_occupancy`; unit rows co-located on `properties` partition; `list_units` for per-property unit grid data |
| **PROP-004** (Router) | All five unit service functions; `UnitIn`/`UnitOut`/`UnitUpdateIn` Pydantic models; `_require_enabled()` delegation |
| **PROP-005** (Frontend + E2E) | PROP-004 unit endpoints; `UnitOut` response shape |
| **Lease cluster (PROP §B)** | `property_id` + `unit_id` FKs on lease rows; `market_rent_cents` as base rent to copy into lease; `occupancy_status` transition from `vacant` → `occupied` on lease activation |
| **Rent Ledger cluster** | `unit_id` as a `meta` field on `new_ledger_entry` calls (informational context for the charge); `billing_shared.py:224,262,83,158` primitives consume the FK but are not called from PROP-002 |
| **Work Orders (PROP §C)** | `property_id` + `unit_id` FK fields on work-order rows (extending `tickets.py` per FXA-012/013 spec) |

### 11.3 Reused primitives (no forking)

| Primitive | Source (path:line) | Reuse in PROP-002 |
|---|---|---|
| `_require_enabled()` | `app/services/inventory.py:54–57` (copied to `property_mgmt.py` by PROP-001) | Called as first statement in all five unit functions |
| `_audit()` lazy-import wrapper | `app/services/inventory.py:92–98` (copied to `property_mgmt.py` by PROP-001) | `property.unit.created/updated/deleted` events |
| `now_ts()` | `app/core/time.py:2` | `created_at`, `updated_at` on unit rows |
| `uuid4().hex` | stdlib `uuid` | `unit_id` generation |
| `T.properties` table handle | `app/core/tables.py` (wired by PROP-001) | All unit DDB operations |
| `FAC LOC#{id}` child-row pattern | `docs/ofbiz/specs/FAC-001.md` §3 | SK prefix idiom `UNIT#{unit_id}` — structural analogue, not the same table |
| `delete_host` no-raise contract | `app/services/host_inventory.py:360–367` | `delete_unit` returns `False` for unknown unit, never raises |
| `ADD unit_count :one` atomic counter | `app/routers/messaging.py:4996`, `app/routers/newsfeed.py:3714` (real `ADD` counter precedents; `inventory.py` uses `SET`+optimistic-CAS, not `ADD`) | `unit_count` maintenance on `META` row |
| `begins_with(sk, "UNIT#")` key condition | `boto3.dynamodb.conditions.Key` | `list_units` query filter |
| `encode_cursor` / `decode_cursor` | `app/core/cursor.py:94,103` | Not used in PROP-002; available for pagination follow-up |
| `require_ui_session` | `app/services/sessions.py:330` | PROP-004 router read endpoints |
| `require_admin_or_root_csrf` | `app/auth/policy.py:100` | PROP-004 router mutation endpoints |
| `billing_shared.new_ledger_entry` | `app/services/billing_shared.py:224` | **Not called in PROP-002** — documented as future constraint for Rent Ledger cluster |
| `billing_shared.settle_or_reverse_ledger` | `app/services/billing_shared.py:262` | **Not called in PROP-002** — Rent Ledger cluster only |
| `billing_shared.apply_balance_delta` | `app/services/billing_shared.py:83` | **Not called in PROP-002** — Rent Ledger cluster only |
| `billing_shared.compute_due` | `app/services/billing_shared.py:158` | **Not called in PROP-002** — Rent Ledger cluster only |
| `compute_billing.run_compute_billing_timer` | `app/services/compute_billing.py:653` | Pattern to clone for property-scoped rent-run timer — Rent Ledger cluster only |

### 11.4 Contrasted (similar structure, different domain — do not reuse)

| Artefact | Why contrasted |
|---|---|
| `facilities` / `FacilityLocation` (FAC-001) | Warehouse bins, not dwelling units; field sets are rental-specific (`market_rent_cents`, `bedrooms`, `bathrooms`, `occupancy_status`) |
| `tickets.py:_DEFAULT_BOARD_COLUMNS` / `_STATUS_TRANSITIONS` | Work-order boards (PROP §C), not unit occupancy; unit occupancy transitions are simpler (no board needed) |
| `billing_shared` payment primitives | Rent ledger will use them; unit entity is informational only |
| `platform_financial_dashboard.py` | GMV / revenue dashboard, not rent-roll occupancy; `portfolio_occupancy_rollup` (PROP-003) is the rent-roll equivalent |
| `RPT-006.md` / `RPT-007.md` dashlets | Portfolio dashboard follow-up; PROP-002 supplies the underlying unit data that dashlets will aggregate |
| PTY-004 PERSON party | Tenant profile (PROP §B); unit entity is the dwelling, not the person |
| QUO-004 CRM contract | Lease entity scaffold (PROP §B); unit entity is the dwelling that a lease references |
| EVT-011 record-link / EVT-012 revisions | Document linking to property/unit (PROP §C); PROP-002 stores no documents |
| TBT-003/006/007 bounty escrow | Paid maintenance escrow (PROP §C work orders); PROP-002 has no payment |
| PUR-003 supplier | Vendor directory (PROP §C); PROP-002 has no vendor reference |
| OFB-015 AR aging | Rent aging (Rent Ledger cluster); PROP-002 has no ledger |

---

## 12. Verification Log

Every assumption in this spec was checked against the live codebase at `/home/ubuntu/testlogon` on the `main` branch (commit `d23bd5d5`). Results below.

### VERIFIED (claims confirmed exact against source)

| Claim | Evidence |
|---|---|
| `app/services/inventory.py:50–57` — `_flag_on()` / `_require_enabled()` flag-gate template | Confirmed: `_flag_on` at line 50, `_require_enabled` at lines 54–57; raises `HTTPException(status_code=404)` |
| `app/services/inventory.py:92–98` — `_audit()` lazy-import wrapper | Confirmed: exact match lines 92–98 |
| `app/services/host_inventory.py:360–367` — `delete_host` no-raise contract, returns `False` for unknown host | Confirmed: `delete_host` defined at line 360, `return False` at line 364 |
| `app/core/time.py:2` — `now_ts()` | Confirmed: `def now_ts() -> int:` at line 2 |
| `app/core/cursor.py:94,103` — `encode_cursor` / `decode_cursor` | Confirmed: `encode_cursor` at line 94, `decode_cursor` at line 103 |
| `app/services/sessions.py:330` — `require_ui_session` | Confirmed: `async def require_ui_session` at line 330 |
| `app/auth/policy.py:100` — `require_admin_or_root_csrf` | Confirmed: `async def require_admin_or_root_csrf` at line 100 |
| `app/services/billing_shared.py:83` — `apply_balance_delta` | Confirmed |
| `app/services/billing_shared.py:158` — `compute_due` | Confirmed |
| `app/services/billing_shared.py:224` — `new_ledger_entry` | Confirmed |
| `app/services/billing_shared.py:262` — `settle_or_reverse_ledger` | Confirmed |
| `app/services/compute_billing.py:653` — `run_compute_billing_timer` | Confirmed |
| `app/core/settings.py:846–847` — `returns_rma_enabled` / `returns_table_name` insertion point | Confirmed: lines 846–847 are exactly these two settings |
| `scripts/local-ddb-init.py:28–36` — `TableDef` dataclass; `:44+` — first `TableDef` entry in `_table_defs()` | Confirmed |
| `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A row 2 — Unit entity MISSING | Confirmed: line 42 records "Unit entity (beds/baths/sqft/market-rent/occupancy) — MISSING" |
| `docs/ofbiz/specs/FAC-001.md` §3 — `LOC#{location_id}` child-row pattern | Confirmed: §3 (line 73) describes the `META` + `LOC#{id}` co-location idiom |
| `property_mgmt.py` does NOT exist yet | Confirmed: `app/services/property_mgmt.py` absent from the codebase |
| `T.properties` does NOT exist in `tables.py` | Confirmed: no `properties` field in `Tables` dataclass; file ends at line 572 |
| `S.property_mgmt_enabled` does NOT exist in `settings.py` | Confirmed: `grep property_mgmt_enabled app/core/settings.py` → no results |
| `compute_property_occupancy` does NOT exist (PROP-003 deliverable, same file) | Confirmed: grep across `app/` returns no results for this function |
| `unit_id`, `UNIT#`, `market_rent` absent from `app/` | Confirmed: grep returns no property-management results |
| `no dev_mode branches` in `inventory.py` | Confirmed: only reference is a module-level docstring comment |
| `RPT-006.md`, `RPT-007.md`, `EVT-011.md`, `EVT-012.md`, `PTY-004.md`, `QUO-004.md`, `PUR-003.md`, `TBT-003.md`, `TBT-006.md`, `TBT-007.md`, `OFB-015.md` all exist | Confirmed: all found via `find` |
| `tables.py` dataclass field insertion point "around `:317–319`, after `returns`" | Confirmed: `returns: Any` is at line 319; `properties: Any` should follow it |
| `tables.py` initializer insertion point "around `:569–571`, after `returns=...`" | Confirmed: `returns=_safe_table(...)` is at line 571; `properties=...` should follow |

### CORRECTED (inaccuracies fixed in this document)

| Claim (original) | Correction | Location fixed |
|---|---|---|
| "The pattern mirrors how `app/services/inventory.py` uses `ADD` on numeric counters" (§2.6) | `inventory.py` uses optimistic-concurrency `SET` + `ConditionExpression`, NOT `ADD`. The real `ADD` counter precedents are `app/routers/messaging.py:4996` and `app/routers/newsfeed.py:3714`. | §2.6 prose and §11.3 table row corrected |
| §11.3 table: "`ADD unit_count :one` atomic counter" source cited as `app/services/inventory.py` (ADR-001) | Corrected to cite `messaging.py:4996` and `newsfeed.py:3714` as real `ADD` precedents | §11.3 table |
| §7.3: "enforced... via `enforce_cookie_csrf` at `app/auth/policy.py:95`" | `enforce_cookie_csrf` is **defined** at line 71; line 95 is an `HTTPException` raise inside the function body. Corrected to "defined at `:71`; called from `:105`". | §7.3 bullet |
| §2.9 and §4.1.4: "import `compute_property_occupancy` inside the `update_unit` body with `try/except ImportError`" — uses `from app.services.property_mgmt import compute_property_occupancy` (self-import) | Since `compute_property_occupancy` lands in the **same** `property_mgmt.py` module (PROP-003), a `from module import name` self-import is always resolvable and never raises `ImportError`. The correct guard is a bare call inside `try/except Exception`, which catches `NameError` before PROP-003 ships. | §2.9 prose and §4.1.4 code block corrected |

### UNCONFIRMED (cannot verify without PROP-001 being implemented)

| Claim | Status | Risk |
|---|---|---|
| PROP-001 creates `property_mgmt.py` with `_flag_on()`, `_require_enabled()`, `_audit()`, `_property_id()`, and four property service functions | UNCONFIRMED — PROP-001 is a future deliverable, not yet in the codebase | LOW RISK: PROP-001's own verified spec defines all these exactly; the dependency is clearly documented |
| PROP-001 adds `S.property_mgmt_enabled` / `S.properties_table_name` to `settings.py` and `T.properties` to `tables.py` | UNCONFIRMED — same reason | LOW RISK: PROP-001 spec §4.1–4.2 specifies these exactly with correct insertion points confirmed above |
| `compute_property_occupancy` (PROP-003) will be in `property_mgmt.py` | CONFIRMED by PROP-003 spec §4.1 line: "The functions live in `app/services/property_mgmt.py`" | No risk |

### MONEY-SAFETY VERDICT

The PROP-002 spec correctly states that `market_rent_cents` is informational only — no billing ledger interaction in this ticket. The future invariants are correctly specified: `new_ledger_entry` at `billing_shared.py:224` (not raw `put_item`); `settle_or_reverse_ledger` at `:262` (not `delete_item`); `apply_balance_delta` at `:83` (not read-modify-write); `compute_due` at `:158`. All four line numbers VERIFIED. No online payment provider call is present or proposed for rent recording (rent is manually recorded). The billing table is never accessed in PROP-002. Money-safety constraints are correctly stated.
