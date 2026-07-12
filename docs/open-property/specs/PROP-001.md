# PROP-001 — Property entity — model, table, flag

**Type**: Feature | **Priority**: P1 | **Estimate**: 1.5d
**Source**: `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-001 + `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A

---

## 1. Summary & Goal

PROP-001 is the P1 foundational ticket for the open-property vertical. It lands exactly three deliverables: (1) the `properties` DynamoDB table with its two GSIs and correct `attr_types`, (2) the `PROPERTY_MGMT_ENABLED` master feature flag with a `_flag_on()` / `_require_enabled()` contract, and (3) the four service functions — `create_property`, `get_property`, `update_property`, `archive_property` — plus the Pydantic I/O models (`PropertyIn`, `PropertyOut`, `PropertyUpdateIn`) and a `PropertyAddress` model.

Without PROP-001 in place, no other PROP ticket (units, list/filter, router, frontend) can be implemented. With PROP-001 merged but `PROPERTY_MGMT_ENABLED=false` (the default), the platform is byte-for-byte unchanged: no new HTTP surface is exposed and existing behavior is entirely unaffected.

---

## 2. Context & Current State

### 2.1 Gap — no rental-property entity exists today

The gap analysis (`docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A row 1) records **Property entity — MISSING**. The codebase has no `properties` table, no property service file, and no property-related Pydantic models. The closest structural artefact is the `facilities` table described in `docs/ofbiz/specs/FAC-001.md` §3 — a `facility_id`/`sk` primary key with a `META` header row and child `LOC#{id}` rows co-located on one partition. **The table shape is reused; the field set is not.** A `facilities` Facility models a warehouse with aisle/bay/bin inventory bins; a `properties` Property models a rental building with dwelling Units. The domains never overlap and the `facilities` table is not yet implemented in the running codebase (neither `S.facilities_table_name` nor `T.facilities` exists in `app/core/settings.py` or `app/core/tables.py` as of this writing).

### 2.2 Feature-flag pattern to reuse

`app/services/inventory.py:50–57` is the canonical flag-gate template:

```python
# inventory.py:50-57
def _flag_on() -> bool:
    return bool(getattr(S, "inventory_reservations_enabled", False))

def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Inventory reservations are not enabled")
```

The settings block that drives this flag lives at `app/core/settings.py:839`:
```python
inventory_reservations_enabled: bool = os.environ.get("INVENTORY_RESERVATIONS_ENABLED", "false").lower() == "true"
```

PROP-001 copies this pattern verbatim, with `property_mgmt_enabled` / `PROPERTY_MGMT_ENABLED`.

### 2.3 Audit wrapper to reuse

`app/services/inventory.py:92–98` defines a lazy-import `_audit()` wrapper:

```python
def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass
```

All `property_mgmt.py` service calls emit audit events via a copy of this wrapper.

### 2.4 ID derivation pattern to reuse

`app/services/commerce_order_service.py:67` derives a deterministic order ID:
```python
order_id = hashlib.sha256(corr.encode("utf-8")).hexdigest()[:32]
```

PROP-001 uses the same pattern for `property_id = sha256(f"{owner_sub}|{name}".encode()).hexdigest()[:32]`, making creation idempotent on (owner_sub, name). The FAC-001 spec (`docs/ofbiz/specs/FAC-001.md` §3) establishes the same derivation for `facility_id`.

### 2.5 Router and auth pattern to reuse

`app/routers/inventory.py:29–65` establishes the router idiom:
- `APIRouter(prefix="/ui/inventory", tags=["inventory"])`
- Reads use `require_ui_session` (imported from `app/services/sessions`; the dependency is defined at `app/services/sessions.py:330`)
- Mutations use `require_admin_or_root_csrf` (defined at `app/auth/policy.py:100–106`), which enforces both role (`ADMIN | ROOT`) and cookie-based CSRF

The `properties_router` (PROP-004) will mirror this split identically. PROP-001 itself does not ship a router — that is PROP-004's deliverable.

### 2.6 TableDef pattern and `attr_types` requirement

`scripts/local-ddb-init.py:28–36` defines the `TableDef` dataclass. The file-level comment at `:34` reads: "Override attribute types (default 'S'). Use for numeric keys, e.g. `{'created_at': 'N'}`". CLAUDE.md "DynamoDB numeric GSI sort keys" documents that omitting `attr_types` for a numeric GSI sort key causes DynamoDB to store the value as String, leading to `ValidationException` on integer queries at runtime. The `created_at` field is `N` (Unix integer from `app/core/time.py:2`) and must be declared in `attr_types`.

### 2.7 What does NOT exist yet

Running `grep -rn "property_mgmt\|PROPERTY_MGMT\|properties_table" app/core/settings.py` returns nothing. Running `grep -n "facilities\|facility" app/core/settings.py` also returns nothing. Neither the property management block nor the unrelated facility block has been applied to the live settings file. PROP-001 introduces both `property_mgmt_enabled` and `properties_table_name` as the first entries in a new `# Property management` settings group.

---

## 3. Data Model

### 3.1 Table: `properties`

Single DynamoDB table. The PK/SK design follows the FAC-001 `facilities` header+child idiom (`docs/ofbiz/specs/FAC-001.md` §3): a `META` row holds the property header and child `UNIT#{unit_id}` rows (added by PROP-002) co-locate on the same partition, enabling a cheap single-partition query for all rows of a property.

**Primary key**

| Key | Type | Value |
|---|---|---|
| `property_id` | S (PK) | `sha256(f"{owner_sub}|{name}".encode()).hexdigest()[:32]` |
| `sk` | S (SK) | `"META"` (property header row) |

**Header row attributes**

| Attribute | DDB Type | Constraints / Notes |
|---|---|---|
| `property_id` | S | PK; derived deterministically (see §2.4) |
| `sk` | S | Always `"META"` for the property header |
| `owner_sub` | S | `user_sub` of the owning landlord/admin |
| `name` | S | Human-readable property name; non-empty |
| `property_type` | S | Literal: `single_family` \| `multi_family` \| `apartment` \| `commercial` |
| `address` | M | Map: `{line1, line2?, city, region, postal_code, country}` |
| `color_tags` | L | List of free-text label strings (e.g., `["urgent", "blue"]`); may be empty list |
| `occupancy_status` | S | Roll-up: `vacant` \| `partial` \| `occupied` — defaults `"vacant"` at create; recomputed by PROP-003 |
| `unit_count` | N | Denormalized count of child `UNIT#` rows; 0 at create; maintained by PROP-002 `create_unit` / `delete_unit` via atomic `ADD` |
| `status` | S | `active` \| `archived` |
| `created_at` | N | `now_ts()` — integer Unix seconds (`app/core/time.py:2`) |
| `updated_at` | N | `now_ts()` — updated on every `update_property` / `archive_property` call |

**GSIs**

| Index name | PK | SK | Purpose |
|---|---|---|---|
| `GSI_OWNER` | `owner_sub` (S) | `created_at` (N) | List a landlord's properties newest-first — primary list path (PROP-003) |
| `GSI_STATUS` | `status` (S) | `created_at` (N) | Admin listing by active/archived state |

Both GSIs project all attributes (`ALL`).

**`attr_types`**: `{"created_at": "N"}` — mandatory per CLAUDE.md DynamoDB numeric GSI sort key rule; omitting causes `ValidationException` at runtime when `GSI_OWNER` or `GSI_STATUS` is queried with an integer `created_at` value.

**TableDef** (to be appended in `scripts/local-ddb-init.py` inside `_table_defs()`, after the last existing entry, following the pattern at `:44+`):

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

Note: PROP-002 adds a third GSI `GSI_UNIT_OCCUPANCY` to this same `TableDef` entry. The two tickets must be merged or their `local-ddb-init.py` changes reconciled to produce a single `TableDef` with all three GSIs.

### 3.2 Pydantic models (`app/models.py`)

**`PropertyAddress`** — committed new model. `app/models.py` has no bare `class Address` (only the `AddressBase`/`AddressIn`/`AddressOut` family at `:1411+`, which uses `state` not `region`), so this is namespaced as `PropertyAddress` to avoid colliding with HTL-001's `HotelAddress` (HTL-001 independently adds a same-shape address model; see `docs/CROSS_TICKET_AUDIT.md §A6`). Add:

```python
class PropertyAddress(BaseModel):
    line1: str
    line2: Optional[str] = None
    city: str
    region: str
    postal_code: str
    country: str
```

**`PropertyIn`** — creation payload:

```python
class PropertyIn(BaseModel):
    name: str
    property_type: Literal["single_family", "multi_family", "apartment", "commercial"]
    address: PropertyAddress
    color_tags: List[str] = []
```

**`PropertyOut`** — full read response:

```python
class PropertyOut(BaseModel):
    property_id: str
    owner_sub: str
    name: str
    property_type: str
    address: PropertyAddress
    color_tags: List[str]
    occupancy_status: Literal["vacant", "partial", "occupied"]
    unit_count: int
    status: Literal["active", "archived"]
    created_at: int
    updated_at: int
```

**`PropertyUpdateIn`** — partial update; all fields optional:

```python
class PropertyUpdateIn(BaseModel):
    name: Optional[str] = None
    property_type: Optional[Literal["single_family","multi_family","apartment","commercial"]] = None
    address: Optional[PropertyAddress] = None
    color_tags: Optional[List[str]] = None
```

---

## 4. API / Service Design

### 4.1 Settings additions (`app/core/settings.py`)

Insert immediately after the `returns_rma_enabled` / `returns_table_name` block at `:846–847`, following the same `os.environ.get(...).lower() == "true"` idiom:

```python
# Property management (open-property vertical, PROP-001..PROP-005). Default OFF.
property_mgmt_enabled: bool = os.environ.get("PROPERTY_MGMT_ENABLED", "false").lower() == "true"
properties_table_name: str = os.environ.get("PROPERTIES_TABLE_NAME", "properties")
```

### 4.2 Table handle additions

**`app/core/tables.py`** — add to the `Tables` dataclass (around `:317–319`, after `returns`):

```python
properties: Any
```

Wire in the `T = Tables(...)` initializer (around `:569–571`, after `returns=...`):

```python
properties=_safe_table(S.properties_table_name),
```

### 4.3 Service: `app/services/property_mgmt.py` (new file)

The service is modeled on `app/services/inventory.py` (flag/audit patterns) and the FAC-004 facility service idiom (`docs/ofbiz/specs/FAC-001.md`). No `if S.dev_mode` branch anywhere — SECOPS-007.

**Module-level helpers**

```python
def _flag_on() -> bool:
    return bool(getattr(S, "property_mgmt_enabled", False))

def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Property management is not enabled")

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass

def _property_id(owner_sub: str, name: str) -> str:
    import hashlib
    return hashlib.sha256(f"{owner_sub}|{name}".encode()).hexdigest()[:32]
```

**`create_property`**

```python
def create_property(
    owner_sub: str,
    name: str,
    property_type: str,
    address: dict,
    color_tags: list[str] | None = None,
) -> dict:
```

- Calls `_require_enabled()`.
- Derives `property_id = _property_id(owner_sub, name)`.
- Builds the full item dict: all header attributes, `occupancy_status="vacant"`, `unit_count=0`, `status="active"`, `created_at=now_ts()`, `updated_at=now_ts()`.
- Calls `T.properties.put_item(Item=item, ConditionExpression="attribute_not_exists(property_id)")`. On `ConditionalCheckFailedException`, reads and returns the existing item via `get_property(property_id)` — **idempotent** on (owner_sub, name).
- Emits `_audit("property.created", owner_sub, property_id=property_id, name=name)`.
- Returns the item dict.

**`get_property`**

```python
def get_property(property_id: str) -> dict | None:
```

- Calls `_require_enabled()`.
- `T.properties.get_item(Key={"property_id": property_id, "sk": "META"})`.
- Returns `item` or `None` if absent.

**`update_property`**

```python
def update_property(property_id: str, *, user_sub: str, **kwargs) -> dict:
```

- Calls `_require_enabled()`.
- Reads existing item; raises `HTTPException(404)` if absent.
- Builds an `UpdateExpression` from `kwargs` (name, property_type, address, color_tags) plus mandatory `updated_at=now_ts()`.
- Calls `T.properties.update_item(...)` with `Key={"property_id": property_id, "sk": "META"}`.
- Emits `_audit("property.updated", user_sub, property_id=property_id, fields=list(kwargs.keys()))`.
- Re-reads and returns the updated item.

**`archive_property`**

```python
def archive_property(property_id: str, *, user_sub: str) -> dict:
```

- Calls `_require_enabled()`.
- Sets `status="archived"`, `updated_at=now_ts()` via `update_item`.
- Emits `_audit("property.archived", user_sub, property_id=property_id)`.
- Returns the updated item.

---

## 5. Detailed Behavior & Edge Cases

### 5.1 Idempotent creation (owner+name collision)

`create_property` uses a DynamoDB conditional put (`attribute_not_exists(property_id)`). If two concurrent callers race for the same (owner_sub, name), exactly one write wins. The loser catches `ConditionalCheckFailedException` and reads back the existing row — returning the same `property_id` as the winner. This is identical to the FAC-001 facility creation contract. A caller may call `create_property` twice with the same arguments and receive the same `PropertyOut` both times with no error.

### 5.2 `address` stored as DynamoDB Map (`M`)

The `address` dict is stored as a nested DynamoDB Map. When reading back, DynamoDB returns it as a Python dict with the same keys. `PropertyOut.address` serializes it as a `PropertyAddress` object. Callers should not pass the `address` dict with None values for optional fields — either omit the key or pass an empty string — because DynamoDB cannot store `None` as a Map value.

### 5.3 `color_tags` as List (`L`)

Stored as a DynamoDB List of strings. An empty list `[]` is a valid stored value and should be round-tripped correctly. DynamoDB stores `[]` as an empty `L` attribute.

### 5.4 Numeric fields and Decimal coercion

`unit_count`, `created_at`, `updated_at` are stored as DynamoDB `N` and are returned by boto3 as `Decimal`. Service functions must coerce them with `int(item["created_at"])` etc. before returning. `PropertyOut` integer fields typed as `int` will coerce automatically if the incoming value is `Decimal`.

### 5.5 `occupancy_status` default and ownership

`occupancy_status` is always `"vacant"` at create (no units exist). It is a denormalized roll-up field. In PROP-001, it is written once at create and never updated — the PROP-003 service function `compute_property_occupancy` will overwrite it on unit occupancy changes (PROP-002/003). PROP-001 must not set it to any value other than `"vacant"` at create.

### 5.6 `unit_count` ownership

`unit_count=0` at create. PROP-002's `create_unit` and `delete_unit` functions maintain it via `ADD unit_count 1` / `ADD unit_count -1` in DynamoDB `update_item` calls on the `META` row. PROP-001 does not write `unit_count` after creation.

### 5.7 `archive_property` is not a hard delete

`archive_property` sets `status="archived"`. No DynamoDB `delete_item` is issued. The property remains queryable via `get_property(property_id)` and will appear in `GSI_STATUS` queries for `status="archived"`. Hard deletion is explicitly out of scope — it would require cascading to PROP-002 unit rows, PROP-003 occupancy roll-ups, and (eventually) Lease and Ledger rows from later PROP clusters.

### 5.8 Flag-off behavior

When `PROPERTY_MGMT_ENABLED=false` (default), every call to any `property_mgmt.py` function raises `HTTPException(404, "Property management is not enabled")` before touching DynamoDB. The `properties` table may or may not exist in DynamoDB — the flag check runs before any table access.

### 5.9 `update_property` with no changed fields

If `kwargs` is empty (caller passes nothing to update), the service still stamps `updated_at=now_ts()`. This is intentional — it gives callers a way to force a refresh of the `updated_at` timestamp without changing data. An alternative is to raise 422 on empty `kwargs`; the decision is documented in §10.

### 5.10 `name` uniqueness scope

`property_id` is derived from (owner_sub, name). Two different landlords may have properties with the same name — the owner_sub disambiguates. A single landlord cannot have two active properties with the same name; the second `create_property` call returns the existing property (idempotent).

---

## 6. Feature Flag & Config

### 6.1 Master flag

| Setting key | Env var | Default | Effect when off |
|---|---|---|---|
| `property_mgmt_enabled` | `PROPERTY_MGMT_ENABLED` | `false` | Every `property_mgmt.py` function raises HTTP 404; platform byte-for-byte unchanged |

### 6.2 Table name config

| Setting key | Env var | Default |
|---|---|---|
| `properties_table_name` | `PROPERTIES_TABLE_NAME` | `"properties"` |

### 6.3 `.env.local.example`

Add to `.env.local.example` (and to the local dev `.env.local` to enable in development):

```
PROPERTY_MGMT_ENABLED=false
PROPERTIES_TABLE_NAME=properties
```

To enable in a dev environment: `PROPERTY_MGMT_ENABLED=true` in `.env.local`, then `just restart` to recreate the DynamoDB table and restart the backend.

### 6.4 E2E environment

E2E tests that exercise property endpoints (PROP-005) must set `PROPERTY_MGMT_ENABLED=1` in the backend environment. Tests that verify the flag-off 404 behavior run with the default (`false`) and do not need this variable set.

---

## 7. Dev/Prod Parity (SECOPS-007), Idempotency, Security & Money-safety

### 7.1 SECOPS-007 — zero `dev_mode` branches

`app/services/property_mgmt.py` must contain **no** `if S.dev_mode` branches. The same DynamoDB code path runs in dev (boto3 intercepted by moto in-process) and prod (real DynamoDB). This mirrors the contract stated in `docs/open-property/PROPERTY_UNITS_TICKETS.md` §"Cross-cutting constraints" and the precedent set by `app/services/inventory.py` (no `dev_mode` branches anywhere in that file).

### 7.2 Idempotency

`create_property` is idempotent on (owner_sub, name) via the conditional put + read-back-on-collision pattern. `update_property` and `archive_property` are unconditional — re-running them with the same payload produces the same final state (idempotent in result, not in `updated_at`). The service does not expose a `delete_property` function to prevent accidental data loss.

### 7.3 Security — ownership enforcement

`get_property` does not enforce that the caller owns the property (admin reads are unrestricted at the service layer). The PROP-004 router restricts mutations (`create`, `update`, `archive`) to `require_admin_or_root_csrf` at `app/auth/policy.py:100–106`, which requires `role ∈ {ADMIN, ROOT}`. This is appropriate for the initial vertical, where landlords are admins of their own platform instance. If multi-tenant landlord isolation is needed (a different landlord cannot read another's properties), an ownership check (`item["owner_sub"] != caller_sub → 403`) should be added in the router layer — see §10.

### 7.4 Money-safety

PROP-001 does **not** touch any billing table, ledger entry, or payment primitive. The `billing_shared` module (`new_ledger_entry` at `:224`, `settle_or_reverse_ledger` at `:262`, `apply_balance_delta` at `:83`) is not imported or called. Money paths become relevant only in the Lease + Rent Ledger cluster (later PROP tickets). This ticket is purely a data-model + service foundation — no financial invariants to enforce here.

### 7.5 Audit trail

Every service mutation emits a best-effort audit event via the `_audit()` wrapper (copied from `app/services/inventory.py:92–98`). Events: `property.created`, `property.updated`, `property.archived`. Audit failure (exception from `audit_event`) is swallowed and never propagates to the caller.

---

## 8. Backward Compatibility & Migration

### 8.1 Additive-only changes

PROP-001 adds:
- Two new settings keys to `app/core/settings.py` (additive; existing settings block is unchanged)
- One new attribute to the `Tables` dataclass (`app/core/tables.py`) and one new wire in `T = Tables(...)` (additive; existing handles are unchanged)
- One new `TableDef` in `scripts/local-ddb-init.py` (additive; existing table defs are unchanged)
- One new file `app/services/property_mgmt.py` (additive)
- One new model `PropertyAddress` plus three new models (`PropertyIn`/`PropertyOut`/`PropertyUpdateIn`) to `app/models.py` (additive; no bare `Address` exists today — see `docs/CROSS_TICKET_AUDIT.md §A6`)

No existing file is modified in a breaking way. No existing endpoint, service function, DynamoDB table, or Pydantic model is altered.

### 8.2 Table creation in dev

`just restart` calls `scripts/local-ddb-init.py` which calls `_table_defs()` and creates all tables. After merging PROP-001, `just restart` creates the `properties` table automatically. No manual migration step is needed in dev.

### 8.3 Production deployment

In production, the `properties` table must be created via `UpdateTable` / `CreateTable` before the new code is deployed. Since `PROPERTY_MGMT_ENABLED` defaults to `false`, the new code can be deployed first (all handlers return 404) and the flag enabled afterwards once the table is verified. No data migration is required — the table is empty at creation.

### 8.4 Rollback

Rolling back PROP-001 requires: reverting the four file changes (settings, tables, local-ddb-init, property_mgmt.py, models.py), and (in production) dropping the `properties` table. Because the flag defaults to `false`, a partial rollback is also safe: keep the code deployed but ensure `PROPERTY_MGMT_ENABLED` is `false` — all handlers return 404 and no data is read or written.

---

## 9. Test Plan

### 9.1 Hermetic pytest — `tests/test_prop_001_property_entity.py`

Tests run **offline** — no live stack, no real AWS. Pattern: moto-backed `properties` table bound to a frozen `T.properties` handle via `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`. Route coroutines called directly on a fresh `asyncio.new_event_loop()` (no `TestClient` — broken pattern per CLAUDE.md). Same hermetic approach as `tests/test_gap_0220_0221_ssh_stored_key.py`, `tests/test_gap_0233_0234_ssh_session_recording.py`, and `tests/test_gap_0265_0266_kyc_risk_scoring.py`.

**Setup block**

```python
import asyncio, boto3, pytest
from moto import mock_aws
from types import SimpleNamespace
from unittest.mock import patch

@pytest.fixture(autouse=True)
def setup_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="properties",
            KeySchema=[
                {"AttributeName": "property_id", "KeyType": "HASH"},
                {"AttributeName": "sk",           "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "property_id", "AttributeType": "S"},
                {"AttributeName": "sk",           "AttributeType": "S"},
                {"AttributeName": "owner_sub",    "AttributeType": "S"},
                {"AttributeName": "status",       "AttributeType": "S"},
                {"AttributeName": "created_at",   "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_OWNER",
                    "KeySchema": [
                        {"AttributeName": "owner_sub",  "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_STATUS",
                    "KeySchema": [
                        {"AttributeName": "status",     "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        from app.core import tables as T_mod
        from app.services import property_mgmt as svc
        object.__setattr__(T_mod.T, "properties", table)
        object.__setattr__(svc.S, "property_mgmt_enabled", True)
        object.__setattr__(svc.S, "properties_table_name", "properties")
        yield table
```

**Test cases**

1. **Flag-off 404**: set `property_mgmt_enabled=False`, call `create_property(...)`, assert `HTTPException(404)` is raised before any DDB write.

2. **`create_property` success**: call with valid args, assert returned dict contains `property_id`, `sk="META"`, `status="active"`, `occupancy_status="vacant"`, `unit_count=0`, numeric `created_at` and `updated_at`.

3. **Idempotency — duplicate (owner_sub, name)**: call `create_property` twice with same args, assert both return same `property_id` and no exception is raised.

4. **`get_property` hit**: after create, `get_property(property_id)` returns the item.

5. **`get_property` miss**: `get_property("nonexistent")` returns `None`.

6. **`update_property` changes fields**: call `update_property(..., name="New Name")`, assert returned dict has `name="New Name"` and `updated_at >= original updated_at`.

7. **`update_property` missing property**: call with unknown `property_id`, assert `HTTPException(404)`.

8. **`archive_property`**: call, assert `status="archived"` in returned dict.

9. **`property_id` derivation determinism**: verify that `_property_id("alice", "Maple House") == _property_id("alice", "Maple House")` and differs from `_property_id("bob", "Maple House")`.

10. **`address` round-trip**: create with a full `PropertyAddress` dict, `get_property` and assert all address sub-fields are present.

11. **`color_tags` round-trip**: create with `color_tags=["urgent", "blue"]`, get and assert both tags present; create with `color_tags=[]`, get and assert empty list.

12. **Decimal coercion**: after creation, raw DDB item has `Decimal` numeric fields; service must return plain `int` for `created_at`, `updated_at`, `unit_count`.

### 9.2 E2E tests — `frontend/e2e/properties.spec.ts`

E2E tests are PROP-005's deliverable and are **not** part of PROP-001. However, PROP-001's acceptance criteria must hold before PROP-005 tests can pass. The E2E tests require `PROPERTY_MGMT_ENABLED=1` in the backend environment and use `injectAuth(page, "charlie_admin")` for cookie-auth admin sessions with CSRF headers on mutations.

---

## 10. Open Questions / Assumptions

1. **`PropertyAddress` namespacing (RESOLVED).** `app/models.py` has no bare `class Address` — only the `AddressBase`/`AddressIn`/`AddressOut` family at `:1411+`, which uses `state` (not `region`) and is structurally incompatible. Per `docs/CROSS_TICKET_AUDIT.md §A6`, PROP-001 commits to a new `PropertyAddress` model (rather than a bare `Address`) so it does not collide with HTL-001's `HotelAddress` — both verticals independently add a same-shape address model, so each is namespaced to its domain. No "reuse if present" hedge remains.

2. **Multi-tenant landlord isolation.** The current design allows any admin/root to read any property via `get_property(property_id)`. The router (PROP-004) does not enforce that the caller's `user.sub` matches `item["owner_sub"]`. For a single-platform deployment (one operator = one landlord), this is fine. For a multi-landlord SaaS scenario, an ownership check in the router is required. **Assumption**: single-platform deployment; no cross-landlord isolation needed for the initial vertical.

3. **`update_property` with empty kwargs.** If `kwargs` is empty, the function stamps `updated_at` without touching other fields. An alternative is to raise `HTTPException(422, "No fields to update")`. **Assumption**: stamp `updated_at` silently — callers driving the router send at least one field via `PropertyUpdateIn` anyway.

4. **`color_tags` type.** Stored as a DynamoDB `L` (List). DynamoDB's `L` type preserves order but does not deduplicate. If the product requires uniqueness (e.g., a property cannot have the same tag twice), deduplicate in the service before writing. **Assumption**: no deduplication enforced at this layer; callers are responsible.

5. **`property_type` extensibility.** The literal set `{single_family, multi_family, apartment, commercial}` is hardcoded. Future types (e.g., `mixed_use`, `storage`) require a model and migration. **Assumption**: the four literals are sufficient for MVP; new literals are a non-breaking additive change.

---

## 11. Dependencies

### 11.1 PROP-001 dependencies (none — foundational)

PROP-001 has no upstream PROP-ticket dependency. It is the foundation all other PROP tickets require.

### 11.2 Downstream PROP tickets depending on PROP-001

| Ticket | Depends on PROP-001 for |
|---|---|
| **PROP-002** (Unit entity) | `T.properties` table handle; `_require_enabled()`; parent property existence + ownership check via `get_property`; `unit_count` `ADD` on `META` row |
| **PROP-003** (List/filter + occupancy roll-up) | `GSI_OWNER`, `GSI_STATUS`; `list_properties` service base; `compute_property_occupancy` writes back to `META` row |
| **PROP-004** (Router + `main.py` registration) | All service functions; `_require_enabled()` delegation; `T.properties` + `S.property_mgmt_enabled` |
| **PROP-005** (Frontend + E2E tests) | PROP-004 router endpoints; `PropertyIn/Out/UpdateIn` Pydantic models |

### 11.3 Reused primitives (no forking)

| Primitive | Source | Reuse in PROP-001 |
|---|---|---|
| `_flag_on()` / `_require_enabled()` pattern | `app/services/inventory.py:50–57` | Copied verbatim with `property_mgmt_enabled` |
| `_audit()` lazy-import wrapper | `app/services/inventory.py:92–98` | Copied verbatim |
| `now_ts()` | `app/core/time.py:2` | `created_at`, `updated_at` |
| `sha256(...)[:32]` deterministic ID | `app/services/commerce_order_service.py:67` | `property_id` derivation |
| `TableDef(...)` pattern + `attr_types` | `scripts/local-ddb-init.py:28–36,44+` | `properties` table definition |
| `_safe_table(...)` | `app/core/tables.py` | `T.properties` wire |
| `os.environ.get(...).lower() == "true"` settings idiom | `app/core/settings.py:839` | `property_mgmt_enabled` setting |
| `encode_cursor` / `decode_cursor` | `app/core/cursor.py:94,103` | Used in PROP-003 (not PROP-001 directly) |
| `require_ui_session` | `app/services/sessions.py:330` | Used in PROP-004 router reads |
| `require_admin_or_root_csrf` | `app/auth/policy.py:100` | Used in PROP-004 router mutations |
| `audit_event` | `app/services/alerts` (lazy import) | Via `_audit()` wrapper |
| FAC header+child table shape | `docs/ofbiz/specs/FAC-001.md` §3 | Table shape analogue (contrasted: rental vs warehouse) |

### 11.4 Later PROP cluster dependencies (not PROP-001 scope)

| Future cluster | Reuses from PROP-001 |
|---|---|
| Tenant + Lease (§B) | `T.properties` + `property_id` FK on lease rows; flag check |
| Rent ledger — `new_ledger_entry` | `billing_shared.py:224` — every rent charge row goes through `new_ledger_entry`; void via `settle_or_reverse_ledger:262`; balance via `apply_balance_delta:83`; `compute_due:158` for outstanding calculation — no online payment provider, manually recorded only; never fork billing |
| Rent-run timer | Clone `app/services/compute_billing.py` (GAP-0228) for a property-scoped monthly charge loop — same pattern, different domain |
| Work orders | Extend `app/services/tickets.py` (`_DEFAULT_BOARD_COLUMNS`, `_STATUS_TRANSITIONS`) with property/unit FK fields; add `scheduled_for` and `cost_cents` per FXA-012/013 spec (`docs/ofbiz/specs/FXA-012.md:116,115`). NOTE: FXA-012/013 do **not** define a `priority` field; a work-order priority is an optional additive extension owned by the WOV cluster, not inherited from the FXA maintenance-order analogue |
| Portfolio dashboard | `compute_property_occupancy` (PROP-003) + `platform_financial_dashboard.py` pattern for KPI aggregation; surface as RPT-006/007 dashlet |
| Documents | EVT-011 record-link fields attach files to `property_id`; EVT-012 revisions for lease versions |

---

## 12. Verification Log

Each assumption in PROP-001 was cross-checked against the live codebase. Evidence lines are cited as `file:line`.

| # | Claim | Status | Evidence |
|---|---|---|---|
| 1 | Gap analysis row 1: "Property entity — MISSING" | **VERIFIED** | `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md:41` |
| 2 | No `properties` table, service, or Pydantic models exist | **VERIFIED** | `grep -rn "property_mgmt\|PROPERTY_MGMT\|properties_table" app/core/settings.py` → empty |
| 3 | No `S.facilities_table_name` or `T.facilities` exists | **VERIFIED** | `grep -n "facilities" app/core/settings.py` → empty; `grep -n "facilities" app/core/tables.py` → empty |
| 4 | `_flag_on()` / `_require_enabled()` pattern at `inventory.py:50–57` | **VERIFIED** | `_flag_on` at `:50`, `_require_enabled` at `:54–57` (exact) |
| 5 | `inventory_reservations_enabled` setting at `settings.py:839` | **VERIFIED** | `app/core/settings.py:839` (exact line) |
| 6 | `_audit()` wrapper at `inventory.py:92–98` | **VERIFIED** | `_audit` at `:92–98` (exact), lazy-imports `audit_event` at `:94` |
| 7 | `sha256(corr.encode(...)).hexdigest()[:32]` ID derivation at `commerce_order_service.py:67` | **VERIFIED** | `:67` exact |
| 8 | FAC-001 `facility_id` uses same sha256 derivation | **VERIFIED** | `docs/ofbiz/specs/FAC-001.md:83` — `sha256(owner_sub + "\|" + name)[:32]` |
| 9 | `require_ui_session` at `app/services/sessions.py:330` | **VERIFIED** | `:330` exact |
| 10 | `require_admin_or_root_csrf` at `app/auth/policy.py:100–106` | **VERIFIED** | `:100–106` exact |
| 11 | Inventory router at `app/routers/inventory.py:29–65`, prefix `/ui/inventory` | **VERIFIED** | Router declared at `:29`, endpoints at `:36–65` |
| 12 | `TableDef` class at `scripts/local-ddb-init.py:28–36`, comment at `:34` | **VERIFIED** | Class at `:29–35`, comment at `:34` (exact) |
| 13 | `_table_defs()` at `:42`, entries start at `:44+` | **VERIFIED** | Function at `:42`, first entry at `:44` |
| 14 | `returns_rma_enabled` / `returns_table_name` at `settings.py:846–847` | **VERIFIED** | `:846–847` exact |
| 15 | Last `TableDef` entry in `_table_defs()` is `returns` (ends at `:2492`) | **VERIFIED** | `]` closes `_table_defs()` at `:2493`; `returns` entry at `:2483–2492` |
| 16 | `Tables` dataclass is `frozen=True`; `returns` field at `:319`; wire at `:571` | **VERIFIED** | `@dataclass(frozen=True)` at `tables.py:68`; `returns: Any` at `:319`; `returns=_safe_table(...)` at `:571` |
| 17 | `now_ts()` at `app/core/time.py:2` | **VERIFIED** | `:2` exact |
| 18 | `encode_cursor` / `decode_cursor` at `cursor.py:94,103` | **VERIFIED** | `:94` and `:103` exact |
| 19 | `billing_shared.py` function lines: `apply_balance_delta:83`, `compute_due:158`, `new_ledger_entry:224`, `settle_or_reverse_ledger:262` | **VERIFIED** | All four lines confirmed exact |
| 20 | `compute_billing.py` timer functions: `run_compute_billing_timer:653`, `start_compute_billing_timer_task:669`, `_tick_all_running_resources:616` | **VERIFIED** | All confirmed (GAP-0228) |
| 21 | `tickets.py` constants `_DEFAULT_BOARD_COLUMNS` and `_STATUS_TRANSITIONS` | **VERIFIED** | `:30` (`_STATUS_TRANSITIONS`) and `:61` (`_DEFAULT_BOARD_COLUMNS`) |
| 22 | `platform_financial_dashboard.py` exists | **VERIFIED** | `app/services/platform_financial_dashboard.py` present |
| 23 | EVT-011, EVT-012 specs exist | **VERIFIED** | `docs/suitecrm/specs/EVT-011.md`, `docs/suitecrm/specs/EVT-012.md` |
| 24 | QUO-004 spec exists | **VERIFIED** | `docs/suitecrm/specs/QUO-004.md` |
| 25 | RPT-006, RPT-007 specs exist | **VERIFIED** | `docs/suitecrm/specs/RPT-006.md`, `docs/suitecrm/specs/RPT-007.md` |
| 26 | PTY-006 spec exists | **VERIFIED** | `docs/ofbiz/specs/PTY-006.md` |
| 27 | PUR-003 spec exists | **VERIFIED** | `docs/ofbiz/specs/PUR-003.md` |
| 28 | FXA-012 / FXA-013 specs exist; `scheduled_for`, `cost` (`cost_cents`) fields present | **CORRECTED** | `docs/ofbiz/specs/FXA-012.md` — `cost_cents` at `:14,:115`, `scheduled_for` at `:116`; FXA-013 mirrors (`:108,:109`). The `priority` field is **absent** from both FXA-012/013 AND from `app/services/tickets.py` (no `priority` constant or column). The §11.4 "Work orders" row claimed "add `priority`, `scheduled_for`, `cost` per FXA-012/013 spec" — corrected: `priority` is NOT defined by the FXA analogue and is not inherited; only `scheduled_for` + `cost_cents` come from FXA-012/013. §11.4 body edited to drop the unsupported `priority` inheritance and mark it as an optional WOV-owned additive extension. |
| 29 | No existing `Address` class (plain name) in `app/models.py` | **VERIFIED** | Only `AddressBase`, `MailingAddress`, `KycPartnerApplicantAddress`, etc. exist; none named `Address`. `AddressBase` uses `state` not `region` — not structurally compatible. New model required; committed as `PropertyAddress` (see cross-ticket reconciliation below). |
| 30 | `moto.mock_dynamodb()` in §9.1 test fixture | **CORRECTED** | Installed moto has no `mock_dynamodb` attribute (`hasattr(moto, "mock_dynamodb") == False`). All existing tests use `from moto import mock_aws`. Fixed to `from moto import mock_aws` / `with mock_aws():` (see §9.1 edit). |
| 31 | `S` (`Settings`) is `@dataclass(frozen=True)` — `object.__setattr__` required | **VERIFIED** | `app/core/settings.py:6–7` |
| 32 | Rent ledger: "no online payment provider, manually recorded only; never fork billing" | **VERIFIED** (design intent) | `billing_shared.new_ledger_entry` is provider-agnostic (takes `extra=` dict); no `stripe`/`paypal` SDK call inside it. Spec correctly states rent is manually recorded — no live payment provider. Not yet implemented; claim is forward-looking design guidance, consistent with billing architecture. |
| 33 | FAC-001 `facilities` table not implemented in running codebase | **VERIFIED** | Neither `S.facilities_table_name` nor `T.facilities` exists in `settings.py` or `tables.py` |

**Summary**: 2 corrections applied (item 30 — deprecated `moto.mock_dynamodb()` API; item 28 — §11.4 over-claimed a `priority` field inherited from FXA-012/013, which neither those specs nor `tickets.py` define; `cost_cents` and `scheduled_for` confirmed and retained). All other 31 claims verified exact against codebase. No UNCONFIRMED/RISK rows remain.

### Cross-ticket reconciliation (audit 2026-06-13)

Per `docs/CROSS_TICKET_AUDIT.md §A6` (and Part C item 5): the shared `Address` model was a latent
collision — both PROP-001 and HTL-001 independently added a byte-identical, same-shape bare `class Address`
to `app/models.py` (each verified no live `Address`, but neither cross-checked the other). Resolution:
PROP-001's address model is committed as **`PropertyAddress`** (and HTL-001's as `HotelAddress`), dropping
the "reuse if a live `Address` exists else add" hedge. Confirmed `app/models.py` has NO bare `class Address`
— only the `AddressBase`/`AddressIn`/`AddressOut` family at `:1411+`. All definition/field-ref/example/test
occurrences in this spec updated to `PropertyAddress`.
