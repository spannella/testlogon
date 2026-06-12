# PROP-004 — Router — /ui/properties + registration in app/main.py

**Type**: Feature | **Priority**: P1 | **Estimate**: 1d
**Source**: `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-004 + `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A

---

## 1. Summary & Goal

PROP-004 exposes the entire open-property service layer over HTTP by introducing `app/routers/properties.py` — a new `properties_router` (prefix `/ui/properties`) — and registering it in `app/main.py` immediately after `inventory_router` at `:877`. The ticket delivers exactly **12 endpoints** covering property CRUD, unit CRUD, per-property occupancy, and the portfolio roll-up. No new DynamoDB tables, GSIs, or Pydantic models are introduced here; every endpoint delegates directly to service functions already defined in `app/services/property_mgmt.py` (PROP-001/002/003).

The design goal is a thin, policy-correct HTTP façade over an already-complete service layer. The router contributes three non-trivial concerns beyond simple delegation:

1. **Auth split** — reads use `require_ui_session`; mutations use `require_admin_or_root_csrf` (role `∈ {ADMIN, ROOT}` + cookie CSRF).
2. **Route-declaration order** — the static `/portfolio/occupancy` path must be declared before the dynamic `/{property_id}` path to prevent FastAPI from capturing the literal `portfolio` segment as a path parameter.
3. **Feature-flag short-circuit** — every handler calls `_require_enabled()` first; when `PROPERTY_MGMT_ENABLED=false` the entire surface returns HTTP 404 and the platform is byte-for-byte unchanged.

With the flag off the router is still mounted (just as `inventory_router` is always mounted — `app/main.py:877`) but every handler is a silent 404 no-op. No existing endpoint, table, or behavioral contract is modified.

---

## 2. Context & Current State

### 2.1 Service layer is fully implemented by PROP-001/002/003

PROP-004 assumes all three predecessor tickets have been merged:

- **PROP-001** (`docs/open-property/specs/PROP-001.md`) — `T.properties` table handle (`app/core/tables.py:317-319`), `S.property_mgmt_enabled` and `S.properties_table_name` settings (`app/core/settings.py:847+`, adjacent to `returns_rma_enabled`), `_flag_on()` / `_require_enabled()` / `_audit()` helpers, and `create_property` / `get_property` / `update_property` / `archive_property` service functions, all in `app/services/property_mgmt.py`.
- **PROP-002** (`docs/open-property/specs/PROP-002.md`) — `create_unit` / `get_unit` / `list_units` / `update_unit` / `delete_unit` service functions in the same module; `UnitIn` / `UnitOut` / `UnitUpdateIn` Pydantic models in `app/models.py`.
- **PROP-003** (`docs/open-property/specs/PROP-003.md`) — `list_properties` / `compute_property_occupancy` / `portfolio_occupancy_rollup` service functions; `PropertyListOut` / `PropertyOccupancyOut` / `PortfolioOccupancyOut` Pydantic models.

No property router of any kind exists today. Running `grep -rn "properties_router\|ui/properties" app/` returns no results. The `app/routers/` directory has no `properties.py` file. The service functions listed above are not yet reachable over HTTP.

### 2.2 Canonical router idiom — `app/routers/inventory.py`

`app/routers/inventory.py` is the exact template to follow:

- **Router declaration** (`:29`): `inventory_router = APIRouter(prefix="/ui/inventory", tags=["inventory"])` — a single `APIRouter` with a `/ui/` prefix and a single tag.
- **Local `_require_enabled()` wrapper** (`:32-34`): a module-level function that delegates to `inv._require_enabled()`. Every handler calls this as its first statement (`:38`, `:50`, `:67`, `:83`). [CORRECTED: original said `:63, :81`; actual calls in the file are at `:67` and `:83`.]
- **Auth split** (`:37,48,65,81`): GET endpoints use `session=Depends(require_ui_session)`; mutation endpoints use `user: AuthenticatedUser = Depends(require_admin_or_root_csrf)`.
- **`main.py` import and registration** (`:311`, `:877`): imported as `from app.routers.inventory import inventory_router`; included via `app.include_router(inventory_router)` in `create_app()`.

`properties_router` mirrors this pattern at every level.

### 2.3 Auth dependencies

- **`require_ui_session`** (`app/services/sessions.py:330`) — FastAPI `Depends`; validates cookie-based UI session or Bearer JWT; returns a `dict` with `user_sub`, `role`, etc. Used for read (GET) endpoints.
- **`require_admin_or_root_csrf`** (`app/auth/policy.py:100-106`) — async FastAPI dependency; calls `enforce_cookie_csrf(request)` then `require_roles(user, {Role.ADMIN, Role.ROOT})`; raises HTTP 403 on CSRF failure, on missing role, or on role mismatch. Used for mutation (POST/PUT/DELETE) endpoints.
- **`AuthenticatedUser`** dataclass (`app/auth/deps.py:126`) — the type returned by `require_admin_or_root_csrf`; carries `.sub` (the `user_sub`), `.role`, `.admin_profile`.

### 2.4 Route-ordering constraint (FastAPI path-param capture)

FastAPI matches routes in declaration order. If the dynamic route `/{property_id}` is declared before `/portfolio/occupancy`, the literal segment `portfolio` is silently captured as a `property_id` path parameter and routed to the `get_property` handler, which then 404s because no property with `property_id="portfolio"` exists. CLAUDE.md documents this exact class of bug for two existing cases:

- KYC: `/templates` declared before `/{case_id}` (CLAUDE.md §"KYC template-signature endpoints").
- Audit export: `/schedules` declared before `/{export_id}` (CLAUDE.md §"Scheduled audit export reports").

The `PROP-004` router must declare `/portfolio/occupancy` **before** `/{property_id}` in the FastAPI router instantiation. The PROP-003 spec (`docs/open-property/specs/PROP-003.md` §4.2) documents this requirement. This is the single most important implementation detail of this ticket — a wrong declaration order would appear to work for all other endpoints but silently break `/portfolio/occupancy` with a misleading 404 error message.

### 2.5 `main.py` registration adjacent to `inventory_router`

`app/main.py:311` imports `inventory_router`; `:877` includes it. `properties_router` is imported at `:312` (directly after `inventory_router`) and included at `:878` (directly after `inventory_router`). This placement keeps the commerce/ERP/property vertical routers grouped together, mirrors the `returns_rma_router` placement at `:878`/`:312`, and follows the established pattern for flag-gated additive routers.

### 2.6 No existing `AddressBase` conflict

`app/models.py:1411` defines `AddressBase` (and its children `AddressIn`/`AddressOut`) for the shipping/postal address domain (street address for delivery profiles). PROP-001 introduces a new `Address` model for property addresses; the two are structurally similar but `AddressBase.state` versus `Address.region` differ in naming. `PropertyIn` and `PropertyOut` use the `Address` model defined by PROP-001, not `AddressBase` — they are different domains and must not be conflated.

---

## 3. Data Model

PROP-004 introduces **no new DynamoDB tables, no new GSIs, and no new DynamoDB attributes**. The `properties` table (PK=`property_id`, SK variable) and all its GSIs were declared by PROP-001/002 in `scripts/local-ddb-init.py`. The Pydantic request/response models were defined by PROP-001/002/003 in `app/models.py`. This section documents which models flow through each endpoint.

### 3.1 Models flowing through the router

| Endpoint | Request body model | Response model |
|---|---|---|
| `POST /ui/properties` | `PropertyIn` | `PropertyOut` |
| `GET /ui/properties` | — | `PropertyListOut` |
| `GET /ui/properties/portfolio/occupancy` | — | `PortfolioOccupancyOut` |
| `GET /ui/properties/{property_id}` | — | `PropertyOut` |
| `PUT /ui/properties/{property_id}` | `PropertyUpdateIn` | `PropertyOut` |
| `DELETE /ui/properties/{property_id}` | — | `PropertyOut` |
| `GET /ui/properties/{property_id}/occupancy` | — | `PropertyOccupancyOut` |
| `GET /ui/properties/{property_id}/units` | — | `List[UnitOut]` |
| `POST /ui/properties/{property_id}/units` | `UnitIn` | `UnitOut` |
| `GET /ui/properties/{property_id}/units/{unit_id}` | — | `UnitOut` |
| `PUT /ui/properties/{property_id}/units/{unit_id}` | `UnitUpdateIn` | `UnitOut` |
| `DELETE /ui/properties/{property_id}/units/{unit_id}` | — | `{"ok": bool}` |

All models are defined in `app/models.py` by PROP-001/002/003. The `delete_unit` response is a simple `{"ok": True}` dict (not a Pydantic model) — consistent with how `app/routers/host_inventory.py` returns `{"ok": True}` for `delete_host` (the actual delete handler is at `:168-176`, not `:198`, and returns `{"ok": True}` on success or raises 404 on miss — the 404-on-miss behaviour differs from `delete_unit`'s no-raise `{"ok": False}` contract). [CORRECTED: original said `:198` returns `{"deleted": True}`; actual handler is ~`:168-176` and returns `{"ok": True}`.]

### 3.2 Query parameters

`GET /ui/properties` accepts:
- `status: str = "active"` — one of `"active"`, `"archived"`, `"all"`; 422 if invalid.
- `property_type: Optional[str] = None` — one of `"single_family"`, `"multi_family"`, `"apartment"`, `"commercial"`, or omitted; 422 if an unrecognized value is supplied.
- `cursor: Optional[str] = None` — opaque HMAC-signed pagination token from `encode_cursor` (`app/core/cursor.py:94`); silently restarts from the beginning if tampered (per `decode_cursor` at `:103-131`).
- `limit: int = 50` — page size; capped at 200 server-side by the service function.

No query parameters for the `GET .../occupancy` and `GET .../portfolio/occupancy` endpoints. No query parameters for unit endpoints.

---

## 4. API / Service Design

### 4.1 Router file: `app/routers/properties.py` (new file)

```python
"""Property management router (open-property vertical, PROP-004).

Additive + flag-gated (``PROPERTY_MGMT_ENABLED``, default OFF). Every
handler calls ``_require_enabled()`` first; when the flag is off all
endpoints return 404 and the platform is byte-for-byte unchanged.

Auth split (mirrors app/routers/inventory.py:37,48,65,81):
  * Read endpoints  → ``require_ui_session``     (any authenticated user)
  * Write endpoints → ``require_admin_or_root_csrf`` (ADMIN | ROOT + CSRF)
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    PropertyIn, PropertyListOut, PropertyOccupancyOut, PropertyOut,
    PropertyUpdateIn, PortfolioOccupancyOut, UnitIn, UnitOut, UnitUpdateIn,
)
from app.services import property_mgmt as prop
from app.services.sessions import require_ui_session

properties_router = APIRouter(prefix="/ui/properties", tags=["properties"])


def _require_enabled() -> None:
    prop._require_enabled()
```

### 4.2 Endpoint specifications

All 12 endpoints are listed below in declaration order. **The declaration order within the router is non-negotiable**: `/portfolio/occupancy` (a static path) must appear before `/{property_id}` (a dynamic path capture) to prevent FastAPI matching `portfolio` as a `property_id` value.

---

#### `GET /ui/properties/portfolio/occupancy`
*(declared first — before any `/{property_id}` routes)*

```python
@properties_router.get("/portfolio/occupancy", response_model=PortfolioOccupancyOut)
async def get_portfolio_occupancy(
    session=Depends(require_ui_session),
) -> PortfolioOccupancyOut:
    _require_enabled()
    result = prop.portfolio_occupancy_rollup(owner_sub=session["user_sub"])
    return PortfolioOccupancyOut(**result)
```

- Auth: `require_ui_session` — owner_sub is the caller's session user_sub, so a landlord automatically sees only their own portfolio.
- Service: `portfolio_occupancy_rollup(owner_sub)` (`app/services/property_mgmt.py`, PROP-003).
- Response: `PortfolioOccupancyOut` — `{property_count, unit_count, occupied, vacant, turnover, unavailable, occupancy_rate}`.

---

#### `GET /ui/properties`

```python
@properties_router.get("", response_model=PropertyListOut)
async def list_properties(
    status: str = "active",
    property_type: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> PropertyListOut:
    _require_enabled()
    result = prop.list_properties(
        owner_sub=session["user_sub"],
        status=status,
        property_type=property_type,
        cursor=cursor,
        limit=limit,
    )
    return PropertyListOut(**result)
```

- Auth: `require_ui_session`.
- Service: `list_properties` (`app/services/property_mgmt.py`, PROP-003) — queries `GSI_OWNER` (PK=`owner_sub`, SK=`created_at` newest-first), paginated via `encode_cursor`/`decode_cursor` (`app/core/cursor.py:94,103`). Raises `HTTPException(422)` for invalid `status` or `property_type` values — the handler propagates these naturally (no extra try/except).
- Response: `PropertyListOut` — `{properties: List[PropertyOut], count: int, cursor: str | None}`.

---

#### `POST /ui/properties`

```python
@properties_router.post("", response_model=PropertyOut, status_code=201)
async def create_property(
    body: PropertyIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PropertyOut:
    _require_enabled()
    item = prop.create_property(
        owner_sub=user.sub,
        name=body.name,
        property_type=body.property_type,
        address=body.address.model_dump(),
        color_tags=body.color_tags,
    )
    return PropertyOut(**item)
```

- Auth: `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — requires `role ∈ {ADMIN, ROOT}` + valid CSRF header for cookie-auth clients.
- Service: `create_property` — deterministic `property_id = sha256(f"{owner_sub}|{name}")[:32]`; conditional put (idempotent on owner+name); returns existing item on collision.
- HTTP status: `201 Created` on first creation. On idempotent replay the service returns the same item; the handler returns `201` again (acceptable — callers should treat 201 idempotently).
- Response: `PropertyOut`.

---

#### `GET /ui/properties/{property_id}`

```python
@properties_router.get("/{property_id}", response_model=PropertyOut)
async def get_property(
    property_id: str,
    session=Depends(require_ui_session),
) -> PropertyOut:
    _require_enabled()
    item = prop.get_property(property_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Property not found")
    return PropertyOut(**item)
```

- Auth: `require_ui_session` — any authenticated user may read a property by ID (single-platform deployment assumption; see §10.1 on multi-tenant isolation).
- 404 if `get_property` returns `None` (unknown `property_id`).

---

#### `PUT /ui/properties/{property_id}`

```python
@properties_router.put("/{property_id}", response_model=PropertyOut)
async def update_property(
    property_id: str,
    body: PropertyUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PropertyOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    if "address" in kwargs and hasattr(kwargs["address"], "model_dump"):
        kwargs["address"] = kwargs["address"].model_dump()
    item = prop.update_property(property_id, user_sub=user.sub, **kwargs)
    return PropertyOut(**item)
```

- Auth: `require_admin_or_root_csrf`.
- Service: `update_property` raises `HTTPException(404)` if the property does not exist — propagates naturally.
- `PropertyUpdateIn` is fully optional; passing an empty body stamps only `updated_at`. The `address` field, if present, is serialized to a plain dict before passing to the service (the service layer works with dicts, not Pydantic models).

---

#### `DELETE /ui/properties/{property_id}`

```python
@properties_router.delete("/{property_id}", response_model=PropertyOut)
async def archive_property(
    property_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PropertyOut:
    _require_enabled()
    item = prop.archive_property(property_id, user_sub=user.sub)
    return PropertyOut(**item)
```

- Auth: `require_admin_or_root_csrf`.
- `DELETE` semantics are **soft-archive** (sets `status="archived"`), not hard delete — consistent with the property vertical's no-hard-delete contract (see §5.4).
- `archive_property` raises `HTTPException(404)` if the property does not exist.

---

#### `GET /ui/properties/{property_id}/occupancy`

```python
@properties_router.get("/{property_id}/occupancy", response_model=PropertyOccupancyOut)
async def get_property_occupancy(
    property_id: str,
    session=Depends(require_ui_session),
) -> PropertyOccupancyOut:
    _require_enabled()
    result = prop.compute_property_occupancy(property_id)
    return PropertyOccupancyOut(**result)
```

- Auth: `require_ui_session`.
- Service: `compute_property_occupancy` (PROP-003) — queries `GSI_UNIT_OCCUPANCY`, tallies per-status unit counts, best-effort writes back derived `occupancy_status` to the `META` row.
- No 404 for an unknown `property_id` (service returns a zero-count response; see PROP-003 §5.4). This is intentional: the occupancy endpoint is a live aggregate query over unit rows; a property with no units returns the same zero shape as a non-existent property. Callers who need existence confirmation should call `GET /{property_id}` first.

---

#### `GET /ui/properties/{property_id}/units`

```python
@properties_router.get("/{property_id}/units", response_model=list[UnitOut])
async def list_units(
    property_id: str,
    session=Depends(require_ui_session),
) -> list[UnitOut]:
    _require_enabled()
    units = prop.list_units(property_id)
    return [UnitOut(**u) for u in units]
```

- Auth: `require_ui_session`.
- Service: `list_units` — queries `Key={"property_id": property_id}` with `begins_with(sk, "UNIT#")` on the main table; sorted by `label` in the service layer.
- Returns an empty list if the property has no units (no 404).

---

#### `POST /ui/properties/{property_id}/units`

```python
@properties_router.post("/{property_id}/units", response_model=UnitOut, status_code=201)
async def create_unit(
    property_id: str,
    body: UnitIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> UnitOut:
    _require_enabled()
    item = prop.create_unit(
        property_id,
        label=body.label,
        bedrooms=body.bedrooms,
        bathrooms=body.bathrooms,
        square_footage=body.square_footage,
        market_rent_cents=body.market_rent_cents,
        occupancy_status=body.occupancy_status,
        user_sub=user.sub,
    )
    return UnitOut(**item)
```

- Auth: `require_admin_or_root_csrf`.
- Service: `create_unit` — validates parent property existence and caller ownership (404 if not owned by `user.sub`); generates `unit_id = uuid4().hex`; atomically increments parent `unit_count`.
- HTTP status: `201 Created`.

---

#### `GET /ui/properties/{property_id}/units/{unit_id}`

```python
@properties_router.get("/{property_id}/units/{unit_id}", response_model=UnitOut)
async def get_unit(
    property_id: str,
    unit_id: str,
    session=Depends(require_ui_session),
) -> UnitOut:
    _require_enabled()
    item = prop.get_unit(property_id, unit_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Unit not found")
    return UnitOut(**item)
```

- Auth: `require_ui_session`.
- 404 if `get_unit` returns `None`.

---

#### `PUT /ui/properties/{property_id}/units/{unit_id}`

```python
@properties_router.put("/{property_id}/units/{unit_id}", response_model=UnitOut)
async def update_unit(
    property_id: str,
    unit_id: str,
    body: UnitUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> UnitOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    item = prop.update_unit(property_id, unit_id, user_sub=user.sub, **kwargs)
    return UnitOut(**item)
```

- Auth: `require_admin_or_root_csrf`.
- Service: `update_unit` — on `occupancy_status` change, best-effort calls `compute_property_occupancy` to refresh the parent `META` roll-up. Raises `HTTPException(404)` if the unit does not exist.

---

#### `DELETE /ui/properties/{property_id}/units/{unit_id}`

```python
@properties_router.delete("/{property_id}/units/{unit_id}")
async def delete_unit(
    property_id: str,
    unit_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_enabled()
    ok = prop.delete_unit(property_id, unit_id, user_sub=user.sub)
    return {"ok": ok}
```

- Auth: `require_admin_or_root_csrf`.
- Service: `delete_unit` returns `False` (never raises) for an unknown unit — mirrors the `host_inventory.delete_host` no-raise contract (`app/services/host_inventory.py:360-367`, CLAUDE.md). The response `{"ok": False}` signals a no-op deletion without a 404 error, giving idempotent DELETE semantics to callers.
- On success: atomically decrements parent `unit_count` and returns `{"ok": True}`.

---

### 4.3 `main.py` changes

Two additive lines in `app/main.py`:

**Import** (line `:312`, immediately after the existing `inventory_router` import at `:311`):
```python
from app.routers.properties import properties_router
```

**Registration** (line `:878`, immediately after the existing `app.include_router(inventory_router)` at `:877`, inside `create_app()`):
```python
app.include_router(properties_router)
```

The surrounding context is:
```python
# app/main.py:876-879 (after change)
app.include_router(host_inventory_router)    # :876 — unchanged
app.include_router(inventory_router)         # :877 — unchanged
app.include_router(properties_router)        # :878 — NEW
app.include_router(returns_rma_router)       # :879 — shifted +1
```

No other changes to `main.py` are required. No startup event handler is needed — PROP-004 has no background task.

---

## 5. Detailed Behavior & Edge Cases

### 5.1 Route-ordering correctness — `/portfolio/occupancy` vs `/{property_id}`

The router registers `GET /portfolio/occupancy` **before** `GET /{property_id}`. FastAPI's routing is order-sensitive: routes are matched against incoming paths in the order they were added to the router. Because `/portfolio/occupancy` is a two-segment static path under the `/ui/properties` prefix and `/{property_id}` is a one-segment dynamic capture, they do not actually conflict at the FastAPI level (two-segment paths are longer than one-segment paths). However, `/{property_id}/occupancy` (one dynamic segment + one static segment) *does* conflict with `/portfolio/occupancy` if `portfolio` is used as a `property_id` value. The safe and documented practice is declaration order: static before dynamic, always.

In practice: the router file must list `get_portfolio_occupancy` before `get_property`, and `get_property_occupancy` before `get_property` (both are in the `/{property_id}/*` sub-group and pose no conflict with each other — they differ in path length). The PROP-003 spec documents this as the "same gotcha as KYC `/templates`-before-`/{case_id}`" (CLAUDE.md, `docs/open-property/specs/PROP-003.md` §4.2).

### 5.2 `POST /ui/properties` idempotency

`create_property` uses a DynamoDB conditional put (`attribute_not_exists(property_id)`) and returns the existing item on collision. Two HTTP `POST` calls with identical `name` and `address` by the same admin user return `201` with the same `PropertyOut` both times. This is safe and intentional — idempotent creation is a property of the service layer, not the router.

### 5.3 `DELETE /ui/properties/{property_id}` is soft-archive, not hard delete

Sending `DELETE /ui/properties/{property_id}` calls `archive_property`, which sets `status="archived"` via a DynamoDB `update_item`. The response is a `PropertyOut` with `status="archived"`. The row remains in DynamoDB. Subsequent `GET /ui/properties/{property_id}` calls return the archived property. Calling `GET /ui/properties?status=active` excludes it; `GET /ui/properties?status=archived` includes it. This matches the `archive_property` contract from PROP-001 §5.7, which explicitly excludes hard deletion to avoid cascading effects on future Lease and Rent Ledger rows.

### 5.4 `DELETE /ui/properties/{property_id}/units/{unit_id}` idempotency

`delete_unit` returns `False` (never raises) for an unknown unit. The HTTP response is `{"ok": False}` with status 200 — not 404. Callers that DELETE an already-deleted unit receive `{"ok": False}` and can treat the operation as a no-op. Note: `host_inventory.delete_host` (CLAUDE.md) actually raises 404 on an unknown host (`app/routers/host_inventory.py:172-173`) rather than returning `{"ok": False}`. The `delete_unit` contract is intentionally more idempotent (no-raise) — it is inspired by but not identical to the host-inventory pattern. [CORRECTED: original said `delete_host` mirrors the no-raise contract; actual `delete_host` endpoint raises 404 on miss.]

### 5.5 CSRF enforcement on mutation endpoints

`require_admin_or_root_csrf` (`app/auth/policy.py:100-106`) calls `enforce_cookie_csrf(request)` (`:71-97`) before the role check. For cookie-authenticated (browser) requests: validates that both `x-csrf-token` header and `ui_csrf` cookie are present and match. For Bearer-token API clients (no `ui_session` cookie): CSRF is not applicable and `enforce_cookie_csrf` returns early (`:86-89`). This means mutation endpoints are accessible via Bearer-auth API clients without a CSRF header — consistent with every other admin endpoint in the platform.

### 5.6 `GET /ui/properties/{property_id}/occupancy` — no 404 on unknown property

The `/occupancy` endpoint does not 404 for an unknown `property_id`. `compute_property_occupancy` queries `GSI_UNIT_OCCUPANCY` and returns a zero-unit response if no matching rows exist. The best-effort write-back in the service layer guards against phantom-row creation via `ConditionExpression="attribute_exists(property_id)"` on the `update_item` (PROP-003 §5.4). Callers wanting to verify property existence before reading occupancy should call `GET /{property_id}` first.

### 5.7 Flag-off behavior

When `PROPERTY_MGMT_ENABLED=false` (the default), every handler calls `_require_enabled()` which delegates to `prop._require_enabled()` (PROP-001), raising `HTTPException(404, "Property management is not enabled")`. The router is still mounted in `app.include_router(properties_router)` — the flag check is at the handler level, not the mount level (same pattern as `inventory_router`). With the flag off the platform is byte-for-byte unchanged; no DynamoDB reads or writes occur.

### 5.8 Decimal coercion in response models

All `PropertyOut` and `UnitOut` fields with integer semantics (`created_at`, `updated_at`, `unit_count`, `market_rent_cents`, `bedrooms`, `square_footage`) must be plain `int` in the response, not `Decimal`. The service-layer helpers `_property_out()` and `_unit_out()` (defined in PROP-001/002) handle Decimal → int coercion before returning dicts to the router. The Pydantic models additionally coerce on field assignment. No additional coercion is needed in the router.

### 5.9 `list_units` — no pagination

`list_units` returns a plain list (no cursor). This is intentional: a single property is expected to have at most a few hundred units; a full page scan of `UNIT#`-prefixed rows on a single partition is cheap and unlikely to exceed the 1MB DynamoDB read limit. If a property with thousands of units is anticipated, pagination can be added to `list_units` in a follow-up — additive, no breaking change to the router.

### 5.10 Ownership enforcement on unit mutation

`create_unit` (`app/services/property_mgmt.py`, PROP-002) validates that the parent property exists and that `user.sub == item["owner_sub"]`, raising `HTTPException(404)` if the caller does not own the property. The router passes `user.sub` as `user_sub` to every mutation service function; the ownership check lives in the service, not the router. This is consistent with the inventory pattern where service functions validate preconditions.

---

## 6. Feature Flag & Config

### 6.1 Master flag (inherited from PROP-001)

| Setting key | Env var | Default | Effect when off |
|---|---|---|---|
| `property_mgmt_enabled` | `PROPERTY_MGMT_ENABLED` | `false` | Every handler returns HTTP 404; router still mounted; no DDB access |

The flag is read via `prop._flag_on()` → `bool(getattr(S, "property_mgmt_enabled", False))`, consistent with `app/services/inventory.py:50-51`.

### 6.2 No new settings keys

PROP-004 introduces **no new settings keys or environment variables**. All configuration (`PROPERTY_MGMT_ENABLED`, `PROPERTIES_TABLE_NAME`) was introduced by PROP-001. The `.env.local.example` entry from PROP-001 (`PROPERTY_MGMT_ENABLED=false`) governs PROP-004 as well.

### 6.3 Enabling in development

```bash
# In .env.local:
PROPERTY_MGMT_ENABLED=true

# Then:
just restart   # recreates DDB tables + restarts backend
```

### 6.4 E2E environment

E2E tests (`frontend/e2e/properties.spec.ts`, delivered by PROP-005) require `PROPERTY_MGMT_ENABLED=1` in the backend environment. Tests that verify flag-off 404 behavior run with the default (`false`) and do not require the variable to be set.

---

## 7. Dev/Prod Parity (SECOPS-007), Idempotency, Security & Money-safety

### 7.1 SECOPS-007 — zero `dev_mode` branches

`app/routers/properties.py` must contain **no** `if S.dev_mode` branches. The router file imports no dev-mode helpers and calls no mock paths. The same handler code runs in dev (moto-intercepted DynamoDB) and prod (real DynamoDB). This mirrors the contract in `docs/open-property/PROPERTY_UNITS_TICKETS.md` §"Cross-cutting constraints" and the precedent set by `app/routers/inventory.py` (zero `dev_mode` branches in that file). The `app/core/dev_s3.py` in-process moto interception is transparent to the router — no special casing is needed.

### 7.2 Idempotency

- `POST /ui/properties` — idempotent on (owner_sub, name): second call returns same `property_id`, same `PropertyOut`, HTTP 201. No error, no data duplication.
- `PUT /ui/properties/{property_id}` — idempotent in final state (deterministic fields update); `updated_at` advances on each call (not idempotent in timestamp, acceptable).
- `DELETE /ui/properties/{property_id}` (archive) — idempotent: archiving an already-archived property returns `status="archived"` again with no error.
- `DELETE /ui/properties/{property_id}/units/{unit_id}` — idempotent: deleting an already-deleted unit returns `{"ok": False}` with no error (§5.4).

### 7.3 Security

- **Mutation auth**: all POST/PUT/DELETE endpoints require `require_admin_or_root_csrf` — role `ADMIN` or `ROOT` plus CSRF for cookie-auth clients.
- **Read auth**: GET endpoints require `require_ui_session` — any authenticated user (USER, ADMIN, ROOT); no ownership enforcement at the router layer for reads. See §10.1 for multi-tenant considerations.
- **Ownership enforcement on writes**: service-layer ownership checks in `create_unit` (caller must own the parent property) prevent cross-landlord unit injection. Property-level mutations (`update_property`, `archive_property`) do not enforce ownership at the service layer in PROP-001 — they rely on the ADMIN/ROOT role gate at the router level (only admins can reach these endpoints). For a single-platform deployment where all admins are operators of the same landlord entity, this is correct.
- **CSRF**: `enforce_cookie_csrf` (`app/auth/policy.py:71`) validates `x-csrf-token` header == `ui_csrf` cookie for all non-GET cookie-auth requests. Bearer-auth clients (API keys) are exempt.
- **Path traversal**: `property_id` and `unit_id` are FastAPI path parameters, constrained by URL encoding. No filesystem paths or shell commands are involved — no traversal risk.

### 7.4 Money-safety

PROP-004 does **not** touch any billing table, billing service, or payment provider. The imports in `app/routers/properties.py` include only `property_mgmt`, the Pydantic models from `app/models.py`, and the auth dependencies. No import of `billing_shared`, `compute_due`, `new_ledger_entry`, `settle_or_reverse_ledger`, `apply_balance_delta`, or any Stripe/PayPal/CCBill client. The property vertical's monetary paths (rent charges, payment recording, ledger voids) are a separate future ticket cluster (gap analysis §B) — those will use `billing_shared.new_ledger_entry` (`:224`) for every monetary row, `settle_or_reverse_ledger` (`:262`) for voids (never delete), and `compute_due` (`:158`) for outstanding balance computation, with no online payment provider (rent is manually recorded). PROP-004 has zero financial invariants to enforce.

### 7.5 Audit trail

The router does not call `_audit()` directly — audit events are emitted by the service functions (`property.created`, `property.updated`, `property.archived`, `property.unit.created`, `property.unit.updated`, `property.unit.deleted`, `property.occupancy_recomputed`). All are best-effort via the `_audit()` lazy-import wrapper (modeled on `app/services/inventory.py:92-99`). Audit failure never propagates to the HTTP caller. [CORRECTED: original said `:92-98`; the function body runs through `:99`.]

---

## 8. Backward Compatibility & Migration

### 8.1 Additive-only changes

PROP-004 adds:
- **One new file**: `app/routers/properties.py` — additive; no existing router file is modified.
- **Two lines in `app/main.py`**: one import (`:312`) and one `include_router` (`:878`) — additive; the `returns_rma_router` include shifts from `:878` to `:879` (a line-number shift, not a behavioral change).

No existing endpoint, service function, DynamoDB table, Pydantic model, or configuration key is modified. With `PROPERTY_MGMT_ENABLED=false` (the default), the new router's handlers all return 404 and produce zero DynamoDB traffic.

### 8.2 No DynamoDB migration

PROP-004 uses the `properties` table declared by PROP-001/002 in `scripts/local-ddb-init.py`. No new `TableDef`, no new GSI, no `attr_types` change. `just restart` in dev recreates the `properties` table from the existing PROP-001/002 `TableDef` automatically.

### 8.3 Production deployment sequence

1. Deploy PROP-001 code with `PROPERTY_MGMT_ENABLED=false` (default) — creates the `properties` table via infra provisioning; all handlers 404.
2. Deploy PROP-002/003 code with flag still `false` — service functions available, still unreachable.
3. Deploy PROP-004 code with flag still `false` — router mounted, handlers 404.
4. Enable `PROPERTY_MGMT_ENABLED=true` after verifying the `properties` table is healthy — all 12 endpoints become live.

This sequence allows safe, incremental rollout with zero-downtime and full rollback at any step by toggling the flag.

### 8.4 Rollback

Reverting PROP-004 requires removing `app/routers/properties.py`, reverting the two lines in `app/main.py`. Because the router is always flag-gated, a quicker operational rollback is setting `PROPERTY_MGMT_ENABLED=false` — the router remains mounted but all handlers return 404, effectively disabling the feature without redeployment.

---

## 9. Test Plan

### 9.1 Hermetic pytest — `tests/test_prop_004_router.py`

Tests run **offline** — no live stack, no real AWS. The hermetic pattern follows `tests/test_gap_0265_0266_kyc_risk_scoring.py` and `tests/test_gap_0233_0234_ssh_session_recording.py`: moto-backed `properties` table bound to frozen `T.properties` via `object.__setattr__`, frozen `S` flags toggled via `object.__setattr__`, route coroutines called directly on a fresh `asyncio.new_event_loop()`. No `TestClient` (broken pattern per CLAUDE.md).

**Setup fixture**:

```python
import asyncio, boto3, pytest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from moto import mock_aws  # CORRECTED: project uses mock_aws (moto 4+), not the deprecated mock_dynamodb

OWNER_SUB = "test-admin-sub"
MOCK_SESSION = {"user_sub": OWNER_SUB, "role": "ADMIN"}

def _make_auth_user(sub=OWNER_SUB):
    from app.auth.deps import AuthenticatedUser
    from app.auth.roles import Role
    return AuthenticatedUser(sub=sub, role=Role.ADMIN)

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
                {"AttributeName": "property_id",      "AttributeType": "S"},
                {"AttributeName": "sk",               "AttributeType": "S"},
                {"AttributeName": "owner_sub",        "AttributeType": "S"},
                {"AttributeName": "status",           "AttributeType": "S"},
                {"AttributeName": "created_at",       "AttributeType": "N"},
                {"AttributeName": "occupancy_status", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {"IndexName": "GSI_OWNER",
                 "KeySchema": [{"AttributeName": "owner_sub",  "KeyType": "HASH"},
                               {"AttributeName": "created_at", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI_STATUS",
                 "KeySchema": [{"AttributeName": "status",     "KeyType": "HASH"},
                               {"AttributeName": "created_at", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI_UNIT_OCCUPANCY",
                 "KeySchema": [{"AttributeName": "property_id",      "KeyType": "HASH"},
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
        yield table
```

For handler invocation, import the handler function directly and call it in an event loop:

```python
def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
```

**Test cases**

1. **Flag-off — every handler returns 404**: set `property_mgmt_enabled=False`; call each of the 12 handler coroutines; assert `HTTPException(404)` raised from `_require_enabled()` in every case.

2. **`POST /ui/properties` — create succeeds**: call `create_property` handler with a valid `PropertyIn` body and a mock `AuthenticatedUser`; assert `status_code` would be 201, response has `property_id`, `status="active"`, `occupancy_status="vacant"`, `unit_count=0`.

3. **`POST /ui/properties` — idempotency**: call the handler twice with identical body; assert both return the same `property_id` without error.

4. **`GET /ui/properties` — returns list**: create two properties via the service; call `list_properties` handler with default params; assert both properties in response, `cursor=None`.

5. **`GET /ui/properties` — status filter**: create 1 active + 1 archived (via service + `archive_property`); call handler with `status="active"`; assert only 1 returned.

6. **`GET /ui/properties` — invalid status 422**: call handler with `status="unknown"`; assert `HTTPException(422)`.

7. **`GET /ui/properties/{property_id}` — hit**: create a property; call handler; assert `PropertyOut` returned with correct `property_id`.

8. **`GET /ui/properties/{property_id}` — miss → 404**: call handler with random `property_id`; assert `HTTPException(404, "Property not found")`.

9. **`PUT /ui/properties/{property_id}` — update name**: create property; call `update_property` handler with `PropertyUpdateIn(name="New Name")`; assert `name="New Name"` in response.

10. **`DELETE /ui/properties/{property_id}` — archive**: create property; call `archive_property` handler; assert `status="archived"` in response; subsequent `GET` still returns the item with `status="archived"`.

11. **`GET /ui/properties/{property_id}/occupancy` — zero units**: create property with no units; call occupancy handler; assert `{"total": 0, "occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0, "occupancy_status": "vacant", "occupancy_rate": 0.0}`.

12. **`GET /ui/properties/{property_id}/occupancy` — non-existent property_id**: call handler with unknown ID; assert no exception, zero-count response returned (service does not 404).

13. **`GET /ui/properties/portfolio/occupancy` — route not captured by `/{property_id}`**: call the `get_portfolio_occupancy` handler directly (not via FastAPI routing); assert it reaches `portfolio_occupancy_rollup`, not `get_property`. Additionally, verify in the router object that the route `/portfolio/occupancy` has an earlier position in `properties_router.routes` than `/{property_id}`.

14. **`POST /ui/properties/{property_id}/units` — create succeeds**: create property; call `create_unit` handler; assert `UnitOut` returned with `unit_id`, `property_id`, correct numeric fields.

15. **`POST /ui/properties/{property_id}/units` — unknown property → 404**: call `create_unit` with a random `property_id`; assert `HTTPException(404)` from ownership check.

16. **`GET /ui/properties/{property_id}/units` — returns list**: create 2 units; call `list_units` handler; assert 2 items returned, sorted by `label`.

17. **`GET /ui/properties/{property_id}/units/{unit_id}` — miss → 404**: call with valid `property_id` but random `unit_id`; assert `HTTPException(404, "Unit not found")`.

18. **`PUT /ui/properties/{property_id}/units/{unit_id}` — update occupancy triggers roll-up**: create property + unit with `occupancy_status="vacant"`; call `update_unit` handler with `occupancy_status="occupied"`; assert returned `UnitOut.occupancy_status="occupied"`; read parent `META` row directly and assert `occupancy_status` updated.

19. **`DELETE /ui/properties/{property_id}/units/{unit_id}` — success → `{"ok": True}`**: create + delete; assert `{"ok": True}`; verify `unit_count` decremented on parent `META`.

20. **`DELETE /ui/properties/{property_id}/units/{unit_id}` — unknown unit → `{"ok": False}`**: call with random `unit_id`; assert `{"ok": False}` with no exception.

21. **`GET /ui/properties/{property_id}/units` — empty list (no units)**: call on a property with no units; assert `[]` returned, no error.

22. **`GET /ui/properties/portfolio/occupancy` — empty portfolio**: call for a user with no properties; assert `{"property_count": 0, "unit_count": 0, "occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0, "occupancy_rate": 0.0}`.

23. **`main.py` registration**: import `create_app` from `app.main`; assert `properties_router` is present in the application's routes; assert the `/ui/properties/portfolio/occupancy` route is reachable (i.e., exists in the router's route list and precedes `/{property_id}`).

24. **Mutation endpoint rejects non-admin (role check)**: call `create_property` handler with a `USER`-role `AuthenticatedUser`; assert `HTTPException(403)` raised by `require_admin_or_root_csrf`.

### 9.2 Combined PROP test file

The PROP-005 ticket (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-005) specifies a combined `tests/test_prop_property_units.py` that covers PROP-001 through PROP-004 together. PROP-004 test cases above may be merged into that combined file; the standalone `tests/test_prop_004_router.py` is also acceptable. Either approach is valid as long as all 24 cases above are present somewhere in the test suite.

### 9.3 E2E — `frontend/e2e/properties.spec.ts` (PROP-005 deliverable)

The E2E spec is PROP-005's deliverable. PROP-004's acceptance criteria are transitively verified by the E2E suite:

- `POST /ui/properties` creates a property; `GET /ui/properties` returns it in the card grid.
- `GET /ui/properties/{property_id}/occupancy` returns correct counts after unit operations.
- `GET /ui/properties/portfolio/occupancy` provides data for the portfolio summary strip.
- CSRF header (`x-csrf-token`) on all POSTs/PUTs/DELETEs via `injectAuth(page, "charlie_admin")` cookie session.
- Flag off → all endpoints 404; flag on → full CRUD works.

---

## 10. Open Questions / Assumptions

### 10.1 Multi-tenant landlord isolation on GET endpoints

Read endpoints (`GET /ui/properties/{property_id}`, `GET /{property_id}/occupancy`, `GET /{property_id}/units`, `GET /{property_id}/units/{unit_id}`) do not enforce that the caller's `user.sub` matches `item["owner_sub"]`. Any authenticated user with a valid session can read any property by ID.

**Assumption**: single-platform deployment where admins/root are operators of the same landlord entity. If multi-tenant isolation is required (a landlord on tenant A cannot read tenant B's properties), an ownership check must be added to the read handlers: fetch the property, compare `item["owner_sub"]` to `session["user_sub"]`, and raise 403 or 404 if they differ. This is a non-breaking additive change to the router.

### 10.2 `GET /ui/properties/{property_id}/occupancy` — no 404 for unknown property

The occupancy endpoint silently returns a zero response for a non-existent `property_id` (§5.6). If the product requires a 404 for unknown properties here, the handler can call `get_property(property_id)` first and 404 if absent, then call `compute_property_occupancy`. The current design avoids the extra DDB read.

**Assumption**: callers use `GET /{property_id}` to verify existence; the occupancy endpoint is a pure aggregation query. A 404 guard can be added in a follow-up without breaking clients.

### 10.3 `list_units` pagination

`list_units` returns a flat list with no cursor. For properties with large unit counts (hundreds or thousands of units), this may return a large payload.

**Assumption**: typical residential/small-commercial properties have < 200 units per property; a flat list is acceptable for MVP. Pagination (adding `cursor`/`limit` query params and `encode_cursor` to the response) is an additive follow-up.

### 10.4 `DELETE /ui/properties/{property_id}/units/{unit_id}` — `{"ok": False}` vs 404

The current design returns HTTP 200 with `{"ok": False}` for an unknown unit deletion, not 404. This gives idempotent DELETE semantics. Some callers may expect 404 for "unit not found" to distinguish between "already deleted" and "never existed."

**Assumption**: idempotent DELETE is the preferred contract. Note: `host_inventory.delete_host` actually raises 404 on miss (not the no-raise pattern) — `delete_unit`'s `{"ok": False}` idempotent contract is a deliberate divergence. If 404 is required, the handler can check the return value of `delete_unit` and raise `HTTPException(404)` — a one-line change. [CORRECTED: original said "consistent with `host_inventory.delete_host`"; actual `delete_host` router raises 404 on miss.]

### 10.5 `POST /ui/properties` response status on idempotent replay

On idempotent replay (same owner+name creates), the handler returns HTTP 201 both times. HTTP 200 might be more semantically correct for "found existing." This is consistent with how `create_property` is specified in PROP-001 (return existing item on collision) and has no behavioral impact on the service.

**Assumption**: HTTP 201 on idempotent replay is acceptable. Callers should treat 201 idempotently.

---

## 11. Dependencies

### 11.1 Direct upstream PROP dependencies

| Ticket | Provides for PROP-004 |
|---|---|
| **PROP-001** (`docs/open-property/specs/PROP-001.md`) | `T.properties` table handle; `S.property_mgmt_enabled` flag; `_require_enabled()` + `_flag_on()` + `_audit()` helpers; `create_property`, `get_property`, `update_property`, `archive_property` service functions; `PropertyIn`, `PropertyOut`, `PropertyUpdateIn` Pydantic models |
| **PROP-002** (`docs/open-property/specs/PROP-002.md`) | `create_unit`, `get_unit`, `list_units`, `update_unit`, `delete_unit` service functions; `UnitIn`, `UnitOut`, `UnitUpdateIn` Pydantic models; `GSI_UNIT_OCCUPANCY` on the `properties` table |
| **PROP-003** (`docs/open-property/specs/PROP-003.md`) | `list_properties`, `compute_property_occupancy`, `portfolio_occupancy_rollup` service functions; `PropertyListOut`, `PropertyOccupancyOut`, `PortfolioOccupancyOut` Pydantic models |

### 11.2 Reused platform primitives (no forking)

| Primitive | Source location | Reuse in PROP-004 |
|---|---|---|
| `APIRouter(prefix=..., tags=...)` idiom | `app/routers/inventory.py:29` | `properties_router = APIRouter(prefix="/ui/properties", tags=["properties"])` |
| Local `_require_enabled()` wrapper | `app/routers/inventory.py:32-34` | Module-level function in `properties.py` delegating to `prop._require_enabled()` |
| `require_ui_session` | `app/services/sessions.py:330` | Auth dependency for all GET endpoints |
| `require_admin_or_root_csrf` | `app/auth/policy.py:100-106` | Auth dependency for all POST/PUT/DELETE endpoints |
| `AuthenticatedUser` dataclass | `app/auth/deps.py:126` | Type annotation for mutation handler `user` parameter; `.sub` used as `user_sub` |
| `app.include_router(...)` registration | `app/main.py:877` (inventory) | PROP-004 registered at `:878`, immediately after |
| `encode_cursor` / `decode_cursor` | `app/core/cursor.py:94,103` | Used by `list_properties` service (PROP-003); transparent to router |
| Flag-off 404 pattern | `app/services/inventory.py:50-57` + `app/routers/inventory.py:32-38` | `_require_enabled()` + `prop._require_enabled()` chain |

### 11.3 Downstream consumers

| Ticket | Consumes PROP-004 for |
|---|---|
| **PROP-005** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-005) | All 12 HTTP endpoints as the backend for `PropertiesPage.tsx`, `PropertyDetailPage.tsx`, and `frontend/e2e/properties.spec.ts` |
| **Lease cluster** (gap analysis §B) | Inherits `/ui/properties/{property_id}` and `/units/{unit_id}` as FK anchors for lease records; will add lease-related endpoints to a separate `app/routers/leases.py` — not PROP-004 |
| **Rent-run timer** (gap analysis §B) | `list_properties` endpoint or service function used by the property-scoped rent-run timer (clone of `app/services/compute_billing.py`, GAP-0228 pattern) to enumerate active properties |
| **RPT-006/007 portfolio dashlet** (`docs/suitecrm/specs/RPT-006.md`, `RPT-007.md`) | `GET /ui/properties/portfolio/occupancy` as the data source for the portfolio KPI dashlet (gap analysis §A "Portfolio KPIs — MISSING") — not in scope here |

### 11.4 Contrasts (analogues, not dependencies)

| Analogue | Relationship |
|---|---|
| `app/routers/inventory.py` | Direct structural template: auth split, `_require_enabled()` wrapper, `main.py` import/include pattern. Field set is unrelated (inventory ≠ real estate). |
| `docs/ofbiz/specs/FAC-001.md` §4.2 (FAC-005 router plan) | Facility router plan: same conceptual router design for the warehouse domain. The PROP router mirrors the FAC-005 design for the property domain. |
| `app/routers/host_inventory.py` | `delete_host` response shape: returns `{"ok": True}` on success, raises `HTTPException(404)` on miss (actual code ~`:168-176`). The `delete_unit` design uses the same `{"ok": bool}` key but is more idempotent (returns `{"ok": False}` on miss rather than raising 404). [CORRECTED: original said `{"deleted": True}` and claimed no-raise parity; actual `delete_host` endpoint raises 404 on miss and returns `{"ok": True}` not `{"deleted": True}`.]  |
| `app/services/platform_financial_dashboard.py` | Revenue/GMV dashboard — different domain. PROP-004 never imports billing or financial dashboard services. |
| `app/services/billing_shared.py` (`new_ledger_entry:224`, `settle_or_reverse_ledger:262`, `compute_due:158`, `apply_balance_delta:83`) | Future rent-ledger cluster dependency — not touched by PROP-004. Every monetary row in future rent tickets goes through `new_ledger_entry`; void via `settle_or_reverse_ledger` (never delete); balance via `apply_balance_delta`; outstanding via `compute_due`. No online payment provider — rent is manually recorded. Never fork billing. |

---

## 12. Verification Log

Every assumption checked against the live codebase (`git rev HEAD = d23bd5d5`). PROP-001/002/003 are not yet merged — all PROP service/model/settings additions are unconfirmed forward-dependencies and noted accordingly.

| # | Claim | Status | Evidence |
|---|---|---|---|
| 1 | No `app/routers/properties.py` exists | **VERIFIED** | `ls app/routers/properties.py` → NOT FOUND |
| 2 | `grep -rn "properties_router\|ui/properties" app/` returns no results | **VERIFIED** | grep returns empty |
| 3 | `inventory_router` import at `main.py:311`, include at `main.py:877` | **VERIFIED** | grep confirms both lines |
| 4 | `returns_rma_router` import at `main.py:312`, include at `main.py:878` | **VERIFIED** | grep confirms both lines; proposed `properties_router` inserts between them |
| 5 | `host_inventory_router` include at `main.py:876` | **VERIFIED** | grep confirms |
| 6 | `inventory_router = APIRouter(prefix="/ui/inventory", tags=["inventory"])` at `inventory.py:29` | **VERIFIED** | confirmed |
| 7 | `_require_enabled()` wrapper at `inventory.py:32-34` | **VERIFIED** | confirmed |
| 8 | `_require_enabled()` handler calls at `inventory.py:38,50,63,81` | **CORRECTED** | Actual calls are `:38, :50, :67, :83`; original said `:63, :81` |
| 9 | `require_ui_session` at `sessions.py:330` | **VERIFIED** | grep confirms `async def require_ui_session` at `:330` |
| 10 | `require_admin_or_root_csrf` at `policy.py:100-106` | **VERIFIED** | function at `:100`, body through `:106` confirmed |
| 11 | `enforce_cookie_csrf` at `policy.py:71-97` | **VERIFIED** | function at `:71`, bearer early-return path at `:87-89` |
| 12 | `AuthenticatedUser` dataclass at `deps.py:126` | **VERIFIED** | `class AuthenticatedUser` at `:126` |
| 13 | `encode_cursor` at `cursor.py:94`, `decode_cursor` at `cursor.py:103` | **VERIFIED** | both confirmed exactly |
| 14 | `AddressBase.state` (not `region`) at `models.py:1411` | **VERIFIED** | `state: Optional[str]` at `:1416`; `AddressBase` at `:1411` |
| 15 | No `PropertyIn`, `PropertyOut`, `UnitIn`, `UnitOut`, etc. in `app/models.py` | **VERIFIED** | grep returns no results; these are PROP-001/002/003 deliverables not yet merged |
| 16 | No `app/services/property_mgmt.py` | **VERIFIED** | file does not exist; prerequisite of PROP-001 |
| 17 | No `T.properties` in `app/core/tables.py` | **VERIFIED** | grep returns no results; prerequisite of PROP-001 |
| 18 | No `S.property_mgmt_enabled` or `S.properties_table_name` in `app/core/settings.py` | **VERIFIED** | grep returns no results; prerequisite of PROP-001 |
| 19 | `returns` field in `Tables` dataclass at `tables.py:319`, wire at `:571` | **VERIFIED** | confirmed; PROP-001 spec correctly targets `~:317-319` as insertion point |
| 20 | `returns_rma_enabled` at `settings.py:846`, adjacent to insertion point for `property_mgmt_enabled` | **VERIFIED** | confirmed at `:846-847` |
| 21 | `delete_host` in `host_inventory.py` at `:360` (service), response shape `{"ok": True}` (router) | **VERIFIED (with correction)** | `delete_host` service at `:360`; router handler at ~`:168-176` returns `{"ok": True}` on success, raises 404 on miss — NOT `{"deleted": True}` as originally claimed; §3.1, §5.4, §10.4, §11.2 corrected |
| 22 | `billing_shared.new_ledger_entry:224`, `settle_or_reverse_ledger:262`, `compute_due:158`, `apply_balance_delta:83` | **VERIFIED** | all four line numbers confirmed exactly; `settle_or_reverse_ledger` uses `update_item` (state flip, never delete) — money-safety invariant confirmed |
| 23 | `_audit()` at `inventory.py:92` | **VERIFIED (minor correction)** | function at `:92`; body runs through `:99`, not `:98`; corrected in §7.5 |
| 24 | `app/services/compute_billing.py` exists (GAP-0228 pattern reference) | **VERIFIED** | file confirmed present |
| 25 | `docs/suitecrm/specs/RPT-006.md` and `RPT-007.md` exist | **VERIFIED** | files present; RPT-006 = per-user configurable home dashboard; RPT-007 = pre-built dashlet catalogue — neither currently references `/ui/properties/portfolio/occupancy` directly (forward dependency only) |
| 26 | `docs/ofbiz/specs/FAC-001.md` and `FAC-005.md` exist | **VERIFIED** | both files present |
| 27 | `FAC-001.md §4.2` discusses router design | **VERIFIED** | §4.2 "Router: `app/routers/facilities.py`" confirmed |
| 28 | PROP-003 §4.2 documents `/portfolio/occupancy` must be declared before `/{property_id}` | **VERIFIED** | PROP-003 §4.2 "Declaration order" section confirmed |
| 29 | PROP-005 spec exists, delivers `PropertiesPage.tsx`, `PropertyDetailPage.tsx`, `properties.spec.ts` | **VERIFIED** | PROP-005.md confirmed with all three deliverables |
| 30 | Gap analysis §B covers "Tenants + Leases + Rent Ledger" | **VERIFIED** | `OPEN_PROPERTY_GAP_ANALYSIS.md` "### B. Tenants + Leases + Rent Ledger" confirmed |
| 31 | Test fixture uses `from moto import mock_dynamodb` | **CORRECTED** | Project's moto version uses `mock_aws`, not the deprecated `mock_dynamodb` (confirmed against `tests/test_gap_0265_0266_kyc_risk_scoring.py` and `tests/test_gap_0233_0234_ssh_session_recording.py`); fixture corrected to `mock_aws` |
| 32 | `require_admin_or_root_csrf` returns `AuthenticatedUser` with `.sub`, `.role`, `.admin_profile` | **VERIFIED** | `AuthenticatedUser` dataclass at `deps.py:126` has `sub`, `role`, `admin_profile`, `tenant_id` fields |
| 33 | No `if S.dev_mode` branches in `app/routers/inventory.py` | **VERIFIED** | grep returns no `dev_mode` branch in that file |
