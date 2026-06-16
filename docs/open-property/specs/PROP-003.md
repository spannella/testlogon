# PROP-003 — List/filter endpoints + occupancy roll-up

**Type**: Feature | **Priority**: P1 | **Estimate**: 1d
**Source**: `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-003 + `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A row 3

---

## 1. Summary & Goal

PROP-003 delivers the three aggregation and listing service functions that turn the raw `properties` table (landed by PROP-001) and its unit rows (landed by PROP-002) into a queryable, filterable portfolio view with real-time occupancy numbers:

1. **`list_properties`** — paginated, filtered listing of a landlord's properties via `GSI_OWNER` (newest-first), with optional `status` and `property_type` filters.
2. **`compute_property_occupancy`** — per-property occupancy tally (occupied/vacant/turnover/unavailable counts + total + occupancy rate) via `GSI_UNIT_OCCUPANCY`, with a best-effort write-back of the derived `occupancy_status` onto the parent `META` row.
3. **`portfolio_occupancy_rollup`** — cross-property roll-up for an owner: sums per-property tallies into a single `{property_count, unit_count, occupied, vacant, occupancy_rate}` response for the portfolio summary strip (PROP-005 frontend).

PROP-003 introduces **no new DynamoDB tables** and **no new GSIs**. All reads go through the two GSIs declared in PROP-001 (`GSI_OWNER`) and PROP-002 (`GSI_UNIT_OCCUPANCY`) — never a full scan. The functions live in `app/services/property_mgmt.py` (the new file from PROP-001) and are consumed by the PROP-004 router. They are the data source for both the PROP-005 property-card grid and, in a later ticket cluster, the RPT-006/007 portfolio dashlet.

Gap analysis row: `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A "Property/unit list/filter + occupancy roll-up — **MISSING**".

---

## 2. Context & Current State

### 2.1 What PROP-001 and PROP-002 land (prerequisite state)

PROP-003 builds on top of two merged tickets:

- **PROP-001** (`docs/open-property/specs/PROP-001.md`): establishes `T.properties` table handle (`app/core/tables.py:317-319`), `S.property_mgmt_enabled` flag (`app/core/settings.py:839` pattern, new property-management block), `_flag_on()` / `_require_enabled()` / `_audit()` helpers (`app/services/property_mgmt.py`), and `GSI_OWNER` (PK=`owner_sub`, SK=`created_at` **N**) + `GSI_STATUS` (PK=`status`, SK=`created_at` **N**) declared in `scripts/local-ddb-init.py` with `attr_types={"created_at": "N"}`.

- **PROP-002** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002): adds child `UNIT#{unit_id}` rows on the same partition, with `occupancy_status ∈ {vacant, occupied, turnover, unavailable}`, and adds `GSI_UNIT_OCCUPANCY` (PK=`property_id`, SK=`occupancy_status`, both **S**) to the same `properties` `TableDef`. PROP-002 also maintains the parent `unit_count` counter via `ADD unit_count 1/-1` on each `create_unit`/`delete_unit` call, and calls the PROP-003 `compute_property_occupancy` helper on every `update_unit` that changes `occupancy_status`.

### 2.2 Why no new table or GSI is needed

The two existing GSIs are sufficient:

- `GSI_OWNER` (PROP-001) answers "give me all properties for owner X, newest first" — the primary list path. Filtering by `status` or `property_type` is applied in-memory after the GSI query, since both are low-cardinality attributes on a per-owner partition that is never large.
- `GSI_UNIT_OCCUPANCY` (PROP-002) answers "for property P, how many units are in each occupancy state?" by projecting on `(property_id, occupancy_status)` — a count without fetching full unit bodies is achieved by querying the index with `Count=True` per occupancy bucket, or fetching all items and tallying.

Neither operation requires a scan of the full `properties` table.

### 2.3 The platform financial dashboard contrast

`app/services/platform_financial_dashboard.py:1–20` tracks GMV/revenue/take-rate from the `billing` table (`billing_shared.new_ledger_entry` at `:224`). That dashboard is entirely about *money flowing through the platform* (tip debits, subscription charges, catalog purchases, etc.). PROP-003's occupancy roll-up is *real-estate rent-roll* data (unit-level occupancy states) — the two domains never share a table and the functions do not touch `billing_shared.py`. Rent payments are a later ticket cluster (§11).

### 2.4 Pagination primitive to reuse

`app/core/cursor.py:94` (`encode_cursor`) and `:103` (`decode_cursor`) implement a v2 HMAC-signed cursor over DynamoDB `LastEvaluatedKey`. All paginated queries in the platform use these functions — the same pattern appears in the host-inventory service and every GSI-backed paginated listing. `list_properties` uses them for its `GSI_OWNER` query.

`decode_cursor` returns `None` for a missing or malformed cursor token (`:103-131`), so passing `cursor=None` starts a fresh page. `encode_cursor` returns `None` when DynamoDB returns no `LastEvaluatedKey` (end of results) (`:94-101`).

### 2.5 The `{items, count, cursor}` response shape

`app/services/host_inventory.list_hosts` (`:391-438`) returns `{"hosts": page, "count": total, "cursor": next_cursor}` where `total` is the count of **all** filtered items across all pages (it does a full in-memory load before slicing). PROP-003 uses the same envelope shape: `{"properties": [...], "count": int, "cursor": str | None}`. However, because `list_properties` uses a true DynamoDB GSI cursor (`ExclusiveStartKey`) rather than an in-memory slice, there is no cheap way to compute a global total without exhausting all pages. Therefore `count` here represents the number of items returned **in the current page** (after in-memory filtering) — not the global total. This diverges from `list_hosts`'s total-count convention. See §5.2 for the authoritative definition and the implications for callers.

### 2.6 Nothing else exists today

Running `grep -rn "list_properties\|compute_property_occupancy\|portfolio_occupancy_rollup" /home/ubuntu/testlogon/app/` returns no results. These are entirely new service functions. No existing service has a rental-property concept.

---

## 3. Data Model

PROP-003 introduces **no new tables, no new GSIs, and no new DynamoDB attributes**. It reads from the schema declared by PROP-001 and PROP-002. This section documents which GSIs are exercised and the read patterns.

### 3.1 Table: `properties` (reused from PROP-001 + PROP-002)

**Primary key**: `property_id` (S, PK) / `sk` (S, SK)

**Row shapes consumed by PROP-003**

| `sk` value | Row type | Relevant attributes |
|---|---|---|
| `META` | Property header | `owner_sub`, `status`, `property_type`, `occupancy_status` (write-back target), `unit_count` |
| `UNIT#{unit_id}` | Unit child | `property_id`, `occupancy_status ∈ {vacant, occupied, turnover, unavailable}` |

**GSIs exercised**

| Index | PK | SK | Used by |
|---|---|---|---|
| `GSI_OWNER` | `owner_sub` (S) | `created_at` (N) | `list_properties` — per-owner listing newest-first |
| `GSI_UNIT_OCCUPANCY` | `property_id` (S) | `occupancy_status` (S) | `compute_property_occupancy` — per-property bucket counts |

**`attr_types` requirement (already declared in PROP-001/002)**: `{"created_at": "N"}` for `GSI_OWNER` and `GSI_STATUS`; `GSI_UNIT_OCCUPANCY` uses string SK so no additional `attr_types` entry is needed. Both were declared in the single `TableDef` entry in `scripts/local-ddb-init.py` per CLAUDE.md's numeric-GSI-key rule (`scripts/local-ddb-init.py:34-36`).

### 3.2 New Pydantic models (`app/models.py`)

Three new read-only response models. All are additive — no existing model is modified.

**`PropertyOccupancyOut`** — per-property occupancy tally:
```python
class PropertyOccupancyOut(BaseModel):
    property_id: str
    total: int
    occupied: int
    vacant: int
    turnover: int
    unavailable: int
    occupancy_status: Literal["vacant", "partial", "occupied"]
    occupancy_rate: float  # occupied / max(total, 1), range 0.0..1.0
```

**`PortfolioOccupancyOut`** — cross-property roll-up for the portfolio summary strip:
```python
class PortfolioOccupancyOut(BaseModel):
    property_count: int
    unit_count: int
    occupied: int
    vacant: int
    turnover: int
    unavailable: int
    occupancy_rate: float  # occupied / max(unit_count, 1)
```

**`PropertyListOut`** — paginated listing envelope (mirrors `host_inventory.list_hosts` shape):
```python
class PropertyListOut(BaseModel):
    properties: List[PropertyOut]   # PropertyOut from PROP-001
    count: int
    cursor: Optional[str] = None
```

---

## 4. API / Service Design

### 4.1 Service functions (`app/services/property_mgmt.py`)

All three functions are added to the existing `property_mgmt.py` module (created by PROP-001). Each calls `_require_enabled()` as its first statement. No `if S.dev_mode` branch anywhere (SECOPS-007).

---

#### `list_properties`

```python
def list_properties(
    owner_sub: str,
    *,
    status: str = "active",
    property_type: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
```

**Behavior**:
1. `_require_enabled()`.
2. `exclusive_start_key = decode_cursor(cursor)` — `None` on first page (`app/core/cursor.py:103`).
3. Build a `T.properties.query(...)` call against `GSI_OWNER`:
   - `IndexName="GSI_OWNER"`
   - `KeyConditionExpression=Key("owner_sub").eq(owner_sub)`
   - `ScanIndexForward=False` (newest-first via `created_at` SK desc)
   - `Limit=limit` (capped at 200 internally: `limit = max(1, min(int(limit), 200))`)
   - `ExclusiveStartKey=exclusive_start_key` if not None
   - `FilterExpression`: add `Attr("sk").eq("META")` to exclude unit rows that might share the partition projection. Note: `GSI_OWNER` PK is `owner_sub` — only `META` rows have this attribute (unit rows do not have an `owner_sub` attribute). However, to be explicit and safe, filter `sk = META` so a future schema change never leaks unit rows.
4. After the query, apply in-memory secondary filters:
   - If `status` is not `"all"`: `items = [i for i in items if i.get("status") == status]`
   - If `property_type` is not None: `items = [i for i in items if i.get("property_type") == property_type]`
5. `next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))` (`app/core/cursor.py:94`).
6. `count = len(items)` — use the post-in-memory-filter length as the page count. Do **not** use `resp.get("Count", ...)` which is the pre-filter DynamoDB count and will over-count when status/property_type filters eliminate items. The `count` field represents items on the current page after all filtering (see §5.2).
7. Return `{"properties": [_property_out(i) for i in items], "count": len(items), "cursor": next_cursor}`.

`_property_out(item)` is a private helper that coerces `Decimal` numerics to `int`/`float` and returns a dict matching `PropertyOut`.

**Validation**: `status` must be one of `{"active", "archived", "all"}` — raise `HTTPException(422)` otherwise. `property_type`, if provided, must be one of `{"single_family", "multi_family", "apartment", "commercial"}` — raise `HTTPException(422)` otherwise.

---

#### `compute_property_occupancy`

```python
def compute_property_occupancy(property_id: str) -> dict:
```

**Behavior**:
1. `_require_enabled()`.
2. Query `GSI_UNIT_OCCUPANCY` for all unit rows of this property:
   - `IndexName="GSI_UNIT_OCCUPANCY"`
   - `KeyConditionExpression=Key("property_id").eq(property_id)`
   - Loop via `LastEvaluatedKey` until exhausted (DynamoDB `FilterExpression` does not reduce page size per CLAUDE.md gotcha — but here there is no filter expression, so a single query suffices for typical property sizes < 500 units; add a loop for safety).
3. Filter to unit rows only: `items = [i for i in items if i["sk"].startswith("UNIT#")]`.
4. Tally by status:
   ```python
   counts = {"occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0}
   for item in items:
       s = item.get("occupancy_status", "vacant")
       counts[s] = counts.get(s, 0) + 1
   total = sum(counts.values())
   ```
5. Derive roll-up `occupancy_status`:
   - `"occupied"` if `total > 0` and `counts["occupied"] == total`
   - `"vacant"` if `counts["occupied"] == 0`
   - `"partial"` otherwise
6. **Best-effort write-back** to parent `META` row:
   ```python
   try:
       T.properties.update_item(
           Key={"property_id": property_id, "sk": "META"},
           UpdateExpression="SET occupancy_status = :s, updated_at = :t",
           ExpressionAttributeValues={":s": derived_status, ":t": now_ts()},
       )
   except Exception:
       pass  # best-effort; never blocks the response
   ```
7. `occupancy_rate = counts["occupied"] / max(total, 1)`.
8. Return `{"property_id": property_id, "total": total, "occupied": ..., "vacant": ..., "turnover": ..., "unavailable": ..., "occupancy_status": derived_status, "occupancy_rate": occupancy_rate}`.

This function is called by PROP-002's `update_unit` on every `occupancy_status` change, and is also exposed directly as a GET endpoint in PROP-004 for on-demand refresh.

---

#### `portfolio_occupancy_rollup`

```python
def portfolio_occupancy_rollup(owner_sub: str) -> dict:
```

**Behavior**:
1. `_require_enabled()`.
2. Collect all active properties via a loop over `list_properties(owner_sub, status="active", limit=200)` pages until `cursor` is None. Accumulate a flat list of property dicts (no filter on `property_type` — portfolio includes all types).
3. For each property, call `compute_property_occupancy(property["property_id"])`.
4. Aggregate:
   ```python
   totals = {"property_count": len(properties), "unit_count": 0,
             "occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0}
   for occ in occupancies:
       totals["unit_count"] += occ["total"]
       totals["occupied"]   += occ["occupied"]
       totals["vacant"]     += occ["vacant"]
       totals["turnover"]   += occ["turnover"]
       totals["unavailable"] += occ["unavailable"]
   totals["occupancy_rate"] = totals["occupied"] / max(totals["unit_count"], 1)
   ```
5. Return `totals`.

**Zero-portfolio safety**: if the owner has no properties, `list_properties` returns `{"properties": [], "count": 0, "cursor": None}`. The loop adds zero properties; `unit_count=0`; `occupancy_rate = 0 / max(0, 1) = 0.0`. No division by zero.

### 4.2 Router endpoints (PROP-004 preview)

These endpoints are registered in `app/routers/properties.py` (PROP-004's deliverable). They are specified here for completeness; PROP-004 owns the actual implementation.

| Method | Path | Auth dep | Service call |
|---|---|---|---|
| `GET` | `/ui/properties` | `require_ui_session` | `list_properties(user.sub, status=, property_type=, cursor=, limit=)` |
| `GET` | `/ui/properties/{property_id}/occupancy` | `require_ui_session` | `compute_property_occupancy(property_id)` |
| `GET` | `/ui/properties/portfolio/occupancy` | `require_ui_session` | `portfolio_occupancy_rollup(user.sub)` |

> **Declaration order**: `/ui/properties/portfolio/occupancy` MUST be declared before `/{property_id}` in the FastAPI router. FastAPI matches in declaration order; if `/{property_id}` is declared first, the literal segment `portfolio` is captured as a `property_id` path parameter and the roll-up handler is never reached. This is the same gotcha documented in CLAUDE.md for the KYC `/templates`-before-`/{case_id}` ordering and the audit-export `/schedules`-before-`/{export_id}` ordering.

**Query parameters for `GET /ui/properties`**:
- `status: str = "active"` — `"active"` | `"archived"` | `"all"`
- `property_type: Optional[str] = None` — `"single_family"` | `"multi_family"` | `"apartment"` | `"commercial"`
- `cursor: Optional[str] = None` — opaque pagination token from `encode_cursor`
- `limit: int = 50` — page size, capped at 200 server-side

**Response models** (from `app/models.py`):
- `GET /ui/properties` → `PropertyListOut`
- `GET /ui/properties/{property_id}/occupancy` → `PropertyOccupancyOut`
- `GET /ui/properties/portfolio/occupancy` → `PortfolioOccupancyOut`

Auth: all three endpoints use `require_ui_session` (`app/services/sessions.py:330`) — matching the read/write split of `app/routers/inventory.py:48,65,81` where reads are session-only and mutations require `require_admin_or_root_csrf` (`app/auth/policy.py:100`).

---

## 5. Detailed Behavior & Edge Cases

### 5.1 `list_properties` — `FilterExpression` does not shrink page size

DynamoDB's `FilterExpression` is applied after fetching up to `Limit` items, meaning a page of `Limit=50` may return fewer than 50 items after filtering. This is the CLAUDE.md gotcha: "DDB FilterExpression doesn't reduce page size." The in-memory `status` / `property_type` filter in `list_properties` means the caller may receive pages with fewer than `limit` results even when there are more pages. The caller should loop until `cursor is None` to collect all results, not stop on a short page.

### 5.2 `count` semantics in `PropertyListOut`

`count` reflects the number of items in the current response page (after in-memory filtering), not the total across all pages. This **differs** from `host_inventory.list_hosts` (`app/services/host_inventory.py:438`), which returns the global total of all filtered items because it performs a full in-memory load before pagination. `list_properties` uses a real DynamoDB `ExclusiveStartKey` cursor and cannot know the global total without exhausting all pages, so a page-level count is the correct and honest value. A global total would require a separate scan-and-count loop; since portfolios are small (typically < 100 properties per landlord), this is not added at this stage. Callers wanting a global total should exhaust all pages.

### 5.3 `compute_property_occupancy` — empty property (zero units)

If a property has no `UNIT#` rows (just created, or all units deleted), the `GSI_UNIT_OCCUPANCY` query returns zero items. `total=0`, all counts are zero, `occupancy_status="vacant"` (since `counts["occupied"] == 0`), `occupancy_rate=0.0`. The write-back sets `occupancy_status="vacant"` on the `META` row — same as the initial value at creation.

### 5.4 `compute_property_occupancy` — unknown property_id

If `property_id` does not exist, the `GSI_UNIT_OCCUPANCY` query returns zero items. The function returns the same zero-unit response as §5.3 — it does not 404. The best-effort write-back will silently no-op (DynamoDB `update_item` on a non-existent key creates a new item with only the updated attributes — this is a known DynamoDB behavior). To avoid phantom rows, the write-back should be conditioned: add `ConditionExpression="attribute_exists(property_id)"` to the `update_item` call. If the condition fails (property doesn't exist), the `except Exception: pass` swallows the `ConditionalCheckFailedException`.

### 5.5 `portfolio_occupancy_rollup` — large portfolios

For portfolios with many properties (e.g., a commercial operator with 50+ buildings), `portfolio_occupancy_rollup` makes O(N) calls to `compute_property_occupancy` — one per property. Each call issues a `GSI_UNIT_OCCUPANCY` query. For small portfolios (< 20 properties) this is acceptable (< 20 DDB reads). For large portfolios, a future optimization is to cache the per-property tally on the `META` row (already done via the write-back in §4.1) and read the cache instead of querying the GSI. This is a follow-up; PROP-003 uses the direct query path for correctness.

### 5.6 `compute_property_occupancy` write-back race with `update_unit`

PROP-002's `update_unit` calls `compute_property_occupancy` after changing a unit's `occupancy_status`. If two units are updated concurrently, two `compute_property_occupancy` calls run concurrently, each reading the GSI and writing back to `META`. Because the write-back uses an unconditional `update_item` (no version guard), the last writer wins. Since the write-back value is derived from a consistent GSI read, both writers derive the same `occupancy_status` for most concurrent patterns; the worst case is a brief stale `occupancy_status` on the `META` row until the next call to `compute_property_occupancy`. The write-back is explicitly documented as best-effort. For authoritative real-time data, callers use `GET /ui/properties/{id}/occupancy` directly.

### 5.7 `property_type` filter — in-memory vs index

`property_type` is not a GSI key in PROP-001. The `GSI_OWNER` index only sorts by `created_at`. Filtering by `property_type` is done in-memory after the per-page GSI fetch. Given the maximum limit of 200 per page and the typical small portfolio size, this is acceptable. If `property_type` filtering becomes a hot path on large portfolios, a `GSI_TYPE` (PK=`property_type`, SK=`created_at`) can be added to the `properties` `TableDef` in a later ticket — additive, no migration needed.

### 5.8 Decimal coercion

DynamoDB returns numeric attributes as `boto3.dynamodb.types.Decimal`. The `_property_out()` helper must coerce `created_at`, `updated_at`, and `unit_count` to `int` before returning. `occupancy_rate` in `PropertyOccupancyOut` is a Python `float` computed in the service layer — it never comes from DynamoDB directly.

### 5.9 `status="all"` sentinel

Passing `status="all"` to `list_properties` skips the in-memory status filter and returns both active and archived properties. This is needed for admin listing endpoints. The value `"all"` is not a DynamoDB-stored value; it is a service-layer sentinel only.

### 5.10 Cursor tampering

`decode_cursor` returns `None` for an invalid or tampered cursor token (HMAC verification fails — `app/core/cursor.py:110-113`). `list_properties` treats a `None` decoded cursor the same as the start of pagination: a fresh query from the beginning of the GSI. No 422 is raised for a bad cursor; pagination silently restarts. This matches the established platform pattern.

---

## 6. Feature Flag & Config

### 6.1 Master flag (inherited from PROP-001)

All three new service functions call `_require_enabled()` as their first line. When `PROPERTY_MGMT_ENABLED=false` (the default), the call raises `HTTPException(404, "Property management is not enabled")` before any DynamoDB access.

| Setting key | Env var | Default | Effect when off |
|---|---|---|---|
| `property_mgmt_enabled` | `PROPERTY_MGMT_ENABLED` | `false` | Every `property_mgmt.py` entrypoint raises HTTP 404 |

The flag check is the same `_flag_on()` / `_require_enabled()` pair introduced in PROP-001 (modeled on `app/services/inventory.py:50–57`). PROP-003 adds no new flag settings.

### 6.2 Pagination config (optional tuning knobs, not required)

The default page size (50) and maximum page size (200) are currently hardcoded constants in `list_properties`. If operator tuning is needed, they can be promoted to settings:

```python
# Optional — not required for MVP
property_list_default_limit: int = int(os.environ.get("PROPERTY_LIST_DEFAULT_LIMIT", "50"))
property_list_max_limit:     int = int(os.environ.get("PROPERTY_LIST_MAX_LIMIT", "200"))
```

These are not required for PROP-003; they are documented here as a follow-up option. The hardcoded constants are sufficient for MVP.

### 6.3 No new env var required

PROP-003 adds no new environment variables beyond what PROP-001 (`PROPERTY_MGMT_ENABLED`, `PROPERTIES_TABLE_NAME`) already introduced. The `.env.local.example` entry from PROP-001 (`PROPERTY_MGMT_ENABLED=false`) governs this ticket as well.

---

## 7. Dev/Prod Parity (SECOPS-007), Idempotency, Security & Money-safety

### 7.1 SECOPS-007 — zero `dev_mode` branches

`list_properties`, `compute_property_occupancy`, and `portfolio_occupancy_rollup` must contain **no** `if S.dev_mode` branch. The same DynamoDB GSI queries run in dev (boto3 intercepted by moto in-process at startup via `app/core/dev_s3.py`) and in prod (real DynamoDB). This mirrors the explicit contract in `docs/open-property/PROPERTY_UNITS_TICKETS.md` §"Cross-cutting constraints" and the precedent set by `app/services/inventory.py` (zero `dev_mode` branches in that file).

### 7.2 Idempotency

All three functions are pure read/aggregate operations. `compute_property_occupancy` additionally issues a best-effort write-back of `occupancy_status` onto the `META` row — this write is idempotent (writing the same derived value multiple times has the same final state). `list_properties` and `portfolio_occupancy_rollup` have no side effects. Re-running any function with the same inputs produces the same (or equivalent) output.

### 7.3 Security — ownership scoping

`list_properties` is scoped to `owner_sub` (the GSI partition key), so a landlord can only list their own properties. `compute_property_occupancy` is scoped to `property_id` — it does not check whether the caller owns the property. The PROP-004 router will enforce this via the authenticated user's `user.sub` compared to `item["owner_sub"]` (see PROP-001 §10 Open Question #2: multi-tenant isolation). For the initial single-platform deployment, admin/root callers own all properties; the service layer trusts the router's ownership check.

`portfolio_occupancy_rollup` uses `owner_sub` directly from the authenticated session, so a landlord cannot retrieve another landlord's portfolio summary.

### 7.4 Money-safety

PROP-003 is a pure read/aggregation ticket. It does **not** touch the billing ledger, `billing_shared.new_ledger_entry` (`app/services/billing_shared.py:224`), `settle_or_reverse_ledger` (`:262`), `apply_balance_delta` (`:83`), `compute_due` (`:158`), or any payment provider. Occupancy states (`vacant`/`occupied`/`turnover`/`unavailable`) are property-management data only. Rent charges and payment recording are a separate future ticket cluster (gap analysis §B "Rent ledger & collections") — those will use `new_ledger_entry` for every monetary row, void via `settle_or_reverse_ledger` (never delete), and `compute_due` for outstanding balance computation, with no online payment provider (rent is manually recorded). PROP-003 has zero financial invariants to enforce.

### 7.5 Audit trail

`compute_property_occupancy` emits a best-effort audit event when it writes back a changed `occupancy_status`:
```python
_audit("property.occupancy_recomputed", "system",
       property_id=property_id, occupancy_status=derived_status)
```
`list_properties` and `portfolio_occupancy_rollup` are read-only and emit no audit events. The `_audit()` lazy-import wrapper (copied from `app/services/inventory.py:92–98`) swallows all exceptions so audit failure never propagates.

---

## 8. Backward Compatibility & Migration

### 8.1 Additive-only changes

PROP-003 adds:
- Three new service functions to `app/services/property_mgmt.py` — additive to the module created by PROP-001.
- Three new Pydantic models (`PropertyOccupancyOut`, `PortfolioOccupancyOut`, `PropertyListOut`) to `app/models.py` — additive; no existing model is modified.
- Three new read endpoints to `app/routers/properties.py` (PROP-004) — not part of PROP-003 directly, but specified here as the consumer surface.

No existing file is modified in a breaking way. No existing endpoint, service function, DynamoDB table, GSI, or Pydantic model is altered.

### 8.2 No DynamoDB migration required

PROP-003 consumes GSIs declared by PROP-001 and PROP-002. No new `TableDef` entry, no new GSI, no `attr_types` change. In dev, `just restart` runs `scripts/local-ddb-init.py` which re-creates the `properties` table from the PROP-001/002 `TableDef`. In prod, no schema change is required — the `properties` table's GSIs were deployed with PROP-001/002.

### 8.3 Existing `occupancy_status` on `META` rows

`compute_property_occupancy` writes back a derived `occupancy_status` to `META` rows. The initial value written by `create_property` (PROP-001) is `"vacant"`. After PROP-003 is deployed, any call to `compute_property_occupancy` re-derives and re-writes the value based on actual unit states. On a fresh deployment with no units, this is a no-op (writes `"vacant"` back). Existing `META` rows with stale `occupancy_status` values (if any were manually set to `"partial"` or `"occupied"` before PROP-003's write-back logic existed) will be corrected on the next `compute_property_occupancy` call.

### 8.4 Rollback

Rolling back PROP-003 requires reverting the three new service functions and three new Pydantic models. Because the flag defaults to `false`, no rollback of DynamoDB schema is needed — the `properties` table is not modified by PROP-003 at the schema level. A partial rollback (keep PROP-001/002 deployed, revert only PROP-003) is safe: PROP-002's `update_unit` call to `compute_property_occupancy` can be removed or wrapped in a `try/except` to avoid import errors.

---

## 9. Test Plan

### 9.1 Hermetic pytest — `tests/test_prop_003_list_filter_occupancy.py`

Tests run **offline** — no live stack, no real AWS. Pattern: moto-backed `properties` table with all three GSIs (`GSI_OWNER`, `GSI_STATUS`, `GSI_UNIT_OCCUPANCY`) bound to a frozen `T.properties` handle via `object.__setattr__`, frozen `S.property_mgmt_enabled` toggled via `object.__setattr__`. Route coroutines (PROP-004) called directly on a fresh `asyncio.new_event_loop()` — no `TestClient` (broken pattern per CLAUDE.md). Same hermetic approach as `tests/test_gap_0265_0266_kyc_risk_scoring.py`, `tests/test_gap_0233_0234_ssh_session_recording.py`.

**Setup fixture**:
```python
@pytest.fixture(autouse=True)
def setup_table(monkeypatch):
    from moto import mock_aws
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
                {"AttributeName": "sk",             "AttributeType": "S"},
                {"AttributeName": "owner_sub",      "AttributeType": "S"},
                {"AttributeName": "status",         "AttributeType": "S"},
                {"AttributeName": "created_at",     "AttributeType": "N"},
                {"AttributeName": "occupancy_status","AttributeType": "S"},
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
        yield table
```

**Test cases**

1. **Flag-off 404 — `list_properties`**: set `property_mgmt_enabled=False`, call `list_properties("alice")`, assert `HTTPException(404)`.

2. **Flag-off 404 — `compute_property_occupancy`**: same; assert `HTTPException(404)`.

3. **Flag-off 404 — `portfolio_occupancy_rollup`**: same; assert `HTTPException(404)`.

4. **`list_properties` empty portfolio**: call for an owner with no properties; assert `{"properties": [], "count": 0, "cursor": None}`.

5. **`list_properties` basic listing**: insert 3 `META` rows for `owner_sub="alice"` with different `created_at` values; call `list_properties("alice")`; assert all 3 returned, newest-first by `created_at`, `cursor=None`.

6. **`list_properties` status filter — active only**: insert 2 active + 1 archived; call with `status="active"`; assert only 2 returned.

7. **`list_properties` status filter — archived**: call with `status="archived"`; assert only 1 returned.

8. **`list_properties` status filter — all**: call with `status="all"`; assert all 3 returned.

9. **`list_properties` property_type filter**: insert 2 `apartment` + 1 `commercial`; call with `property_type="apartment"`; assert 2 returned.

10. **`list_properties` combined filters**: `status="active"` + `property_type="apartment"`; assert correct intersection.

11. **`list_properties` pagination — cursor round-trip**: insert 5 properties, call with `limit=2`; assert 2 returned and `cursor` is not None; call again with the cursor and `limit=2`; assert next 2 returned; call with new cursor; assert final 1 returned and `cursor=None`.

12. **`list_properties` invalid status value**: call with `status="unknown"`; assert `HTTPException(422)`.

13. **`list_properties` invalid property_type value**: call with `property_type="castle"`; assert `HTTPException(422)`.

14. **`compute_property_occupancy` zero units**: call for a `property_id` with no `UNIT#` rows; assert `{"total": 0, "occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0, "occupancy_status": "vacant", "occupancy_rate": 0.0}`.

15. **`compute_property_occupancy` all occupied**: insert 3 `UNIT#` rows all with `occupancy_status="occupied"`; assert `{"total": 3, "occupied": 3, "occupancy_status": "occupied", "occupancy_rate": 1.0}`.

16. **`compute_property_occupancy` all vacant**: 3 units, all `"vacant"`; assert `occupancy_status="vacant"`, `occupancy_rate=0.0`.

17. **`compute_property_occupancy` partial**: 2 occupied + 1 vacant; assert `occupancy_status="partial"`, `occupancy_rate ≈ 0.667`.

18. **`compute_property_occupancy` mixed four states**: 1 occupied + 1 vacant + 1 turnover + 1 unavailable; assert `total=4`, all counts correct, `occupancy_status="partial"`.

19. **`compute_property_occupancy` write-back**: after calling, read the `META` row directly from moto; assert `occupancy_status` matches the derived value.

20. **`compute_property_occupancy` write-back best-effort on unknown property**: call with a `property_id` that has no `META` row; assert no exception raised and response returned with `total=0`.

21. **`portfolio_occupancy_rollup` empty**: call for an owner with no properties; assert `{"property_count": 0, "unit_count": 0, "occupied": 0, "vacant": 0, "turnover": 0, "unavailable": 0, "occupancy_rate": 0.0}`.

22. **`portfolio_occupancy_rollup` single property**: 1 property, 2 occupied + 1 vacant; assert `property_count=1`, `unit_count=3`, `occupied=2`, `occupancy_rate ≈ 0.667`.

23. **`portfolio_occupancy_rollup` multiple properties**: 2 properties with different unit mixes; assert sums across properties are correct and `occupancy_rate` is global (not per-property average).

24. **`portfolio_occupancy_rollup` no division by zero**: zero-unit portfolio; assert `occupancy_rate=0.0`, no `ZeroDivisionError`.

25. **Route ordering — `/portfolio/occupancy` not captured by `/{property_id}`**: call `GET /ui/properties/portfolio/occupancy` in the PROP-004 router test; assert the roll-up handler is reached, not a 404-property-not-found response.

26. **`_property_out` Decimal coercion**: put a property directly with `Decimal` numeric fields; call `list_properties`; assert `created_at` and `updated_at` in response are plain `int`, not `Decimal`.

### 9.2 Integration with PROP-002 tests

The combined `tests/test_prop_property_units.py` referenced in the PROP-005 ticket (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-005) covers PROP-001/002/003/004 together. PROP-003-specific cases above can be a standalone file or merged into the combined file — either is acceptable as long as all cases are present.

### 9.3 E2E — `frontend/e2e/properties.spec.ts` (PROP-005 deliverable)

The E2E spec is PROP-005's deliverable. PROP-003 acceptance criteria are transitively required by PROP-005's E2E tests:
- `GET /ui/properties` with `status=active` filter returns the correct subset.
- `GET /ui/properties/{id}/occupancy` returns correct counts after unit operations.
- `GET /ui/properties/portfolio/occupancy` renders the portfolio summary strip in `PropertiesPage.tsx`.

E2E tests require `PROPERTY_MGMT_ENABLED=1` in the backend env and use `injectAuth(page, "charlie_admin")` for cookie-auth admin sessions with `x-csrf-token` headers on mutations.

---

## 10. Open Questions / Assumptions

1. **In-memory vs. index filter for `property_type`.** Currently `property_type` is filtered in-memory after the `GSI_OWNER` query. If portfolios grow large (> 500 active properties per landlord), adding `GSI_TYPE` (PK=`property_type`, SK=`created_at`) would make this a DDB-side filter. **Assumption**: single-landlord portfolios are < 200 properties; in-memory filtering is acceptable for MVP.

2. **`portfolio_occupancy_rollup` N+1 DDB reads.** The function makes one `GSI_UNIT_OCCUPANCY` query per property. For a 50-property portfolio this is 50 DDB reads per call. An optimization is to cache the per-property tally on the `META` row (written by `compute_property_occupancy`'s write-back) and read the cache in `portfolio_occupancy_rollup`. **Assumption**: cache read-back is a follow-up optimization; direct GSI queries are used in PROP-003 for simplicity and correctness.

3. **`count` semantics.** `PropertyListOut.count` is the page count (after in-memory filtering), not a global total. If the PROP-005 UI needs a global count for display (e.g., "12 properties"), a separate count query or a full pagination loop is required. **Assumption**: `count` is page-level; PROP-005 can display the paginated total by exhausting all pages (acceptable for small portfolios) or by reading `unit_count` from the `META` roll-up.

4. **`compute_property_occupancy` called on every `update_unit`.** PROP-002 calls `compute_property_occupancy` synchronously inside `update_unit` on every `occupancy_status` change. For properties with many units, a high update rate could cause contention on the `META` row write-back. **Assumption**: synchronous call is acceptable for MVP; if contention becomes a problem, the write-back can be made async (fire-and-forget in a background task).

5. **`occupancy_rate` precision.** The `occupancy_rate` float is computed as `occupied / max(total, 1)`. Python float division gives full IEEE 754 precision. If the API contract requires a specific precision (e.g., two decimal places), the service should round: `round(occupied / max(total, 1), 4)`. **Assumption**: full float precision is acceptable; rounding is a frontend concern.

6. **Tenant-linked occupancy.** In the future Lease ticket cluster (gap analysis §B), a unit's `occupancy_status` will be derived from the Lease entity (active lease → occupied; no active lease → vacant). At that point, `compute_property_occupancy` may need to query the lease table instead of (or in addition to) the `occupancy_status` attribute on the unit row. **Assumption**: for PROP-003, the ground truth is the `occupancy_status` attribute on each `UNIT#` row, manually set via `update_unit`.

---

## 11. Dependencies

### 11.1 Direct upstream dependencies

| Ticket | Provides for PROP-003 |
|---|---|
| **PROP-001** (`docs/open-property/specs/PROP-001.md`) | `T.properties` table handle; `_flag_on()` / `_require_enabled()` / `_audit()` helpers in `property_mgmt.py`; `GSI_OWNER` GSI (PK=`owner_sub`, SK=`created_at` N); `S.property_mgmt_enabled` flag; `PropertyOut` model |
| **PROP-002** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-002) | `GSI_UNIT_OCCUPANCY` GSI (PK=`property_id`, SK=`occupancy_status` S); `UNIT#{unit_id}` child rows with `occupancy_status` attribute; the `update_unit` call-site that invokes `compute_property_occupancy` |

### 11.2 Reused platform primitives (no forking)

| Primitive | Source location | Reuse in PROP-003 |
|---|---|---|
| `encode_cursor` | `app/core/cursor.py:94` | `list_properties` pagination — encodes `LastEvaluatedKey` |
| `decode_cursor` | `app/core/cursor.py:103` | `list_properties` pagination — decodes incoming cursor token |
| `now_ts()` | `app/core/time.py:2` | Timestamp for `compute_property_occupancy` write-back `updated_at` |
| `_flag_on()` / `_require_enabled()` | `app/services/property_mgmt.py` (from PROP-001, modeled on `app/services/inventory.py:50–57`) | First call in every PROP-003 function |
| `_audit()` lazy-import wrapper | `app/services/property_mgmt.py` (from PROP-001, modeled on `app/services/inventory.py:92–98`) | `compute_property_occupancy` write-back audit event |
| `{items, count, cursor}` response shape | `app/services/host_inventory.list_hosts` (`:391-438`) | `PropertyListOut` envelope shape |
| `require_ui_session` | `app/services/sessions.py:330` | Auth dependency for all three read endpoints (PROP-004) |
| `require_admin_or_root_csrf` | `app/auth/policy.py:100` | Auth dependency for mutation endpoints in PROP-004 (not PROP-003 directly) |

### 11.3 Downstream consumers

| Ticket | Consumes PROP-003 for |
|---|---|
| **PROP-004** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-004) | Exposes `list_properties`, `compute_property_occupancy`, `portfolio_occupancy_rollup` as HTTP endpoints (`GET /ui/properties`, `/occupancy`, `/portfolio/occupancy`) |
| **PROP-005** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-005) | `PropertiesPage.tsx` portfolio summary strip (from `getPortfolioOccupancy`); `PropertyDetailPage.tsx` summary-metrics row (from `getOccupancy`); `listProperties` for the card grid |
| **RPT-006/007 portfolio dashlet** (`docs/suitecrm/specs/RPT-006.md`, `RPT-007.md`) | `portfolio_occupancy_rollup` is the data source for the future portfolio KPI dashlet (gap analysis §A "Portfolio KPIs — MISSING") — not in scope here |
| **Rent ledger cluster** (gap analysis §B) | `list_properties` used to enumerate active properties for the rent-run timer (clone of `app/services/compute_billing.py`, GAP-0228 pattern); `compute_property_occupancy` drives occupancy status updates when a Lease becomes active/ended |

### 11.4 Contrasts (analogues, not dependencies)

| Analogue | Relationship |
|---|---|
| `app/services/platform_financial_dashboard.py` | Revenue/GMV dashboard — different domain (billing ledger). PROP-003 is rent-roll occupancy only. Never import `billing_shared` from `property_mgmt.py`. |
| `app/services/tickets.py` (`_DEFAULT_BOARD_COLUMNS`, `_STATUS_TRANSITIONS`) | Work-order status/boards — future PROP cluster; not in scope for PROP-003 |
| `docs/ofbiz/specs/FAC-001.md` §3 | FAC facility header+child table shape (structural analogue for the `properties` table design) — contrasted: warehouse bins vs rental units |
| `docs/suitecrm/specs/RPT-006.md`, `RPT-007.md` | Dashlet framework — future consumer of `portfolio_occupancy_rollup` data |

---

## 12. Verification Log

Each assumption in PROP-003 was cross-checked against the live codebase. Evidence lines are cited as `file:line`.

| # | Claim | Status | Evidence |
|---|---|---|---|
| 1 | `list_properties`, `compute_property_occupancy`, `portfolio_occupancy_rollup` do not yet exist in `app/` | **VERIFIED** | `grep -rn "list_properties\|compute_property_occupancy\|portfolio_occupancy_rollup" app/` → empty (PROP-001 and property_mgmt.py itself also not yet implemented) |
| 2 | `app/services/property_mgmt.py` does not yet exist | **VERIFIED** | `ls app/services/property_mgmt.py` → NOT FOUND |
| 3 | `T.properties` not in `app/core/tables.py` and `S.property_mgmt_enabled` not in `app/core/settings.py` | **VERIFIED** | No match on `grep -n "property_mgmt\|T\.properties" app/core/tables.py app/core/settings.py` |
| 4 | No `properties` GSIs (`GSI_OWNER`, `GSI_UNIT_OCCUPANCY`) in `scripts/local-ddb-init.py` | **VERIFIED** | Search returns only pre-existing unrelated `GSI_OWNER_PK` / `GSI_STATUS` on other tables |
| 5 | `encode_cursor` at `app/core/cursor.py:94`, `decode_cursor` at `:103` | **VERIFIED** | Exact lines confirmed |
| 6 | `encode_cursor` returns `None` when `last_evaluated_key` is falsy (`:94-101`) | **VERIFIED** | `if not last_evaluated_key: return None` at `:95-96` |
| 7 | `decode_cursor` returns `None` for missing/tampered cursor; HMAC check at `:110-113` | **VERIFIED** | `key_source` check at `:110-112`, `return None` at `:113` |
| 8 | `decode_cursor` returns `None` for missing cursor at `:103-131` | **VERIFIED** | `if not cursor: return None` at `:104-105`; full function spans `:103-131` |
| 9 | `list_hosts` at `app/services/host_inventory.py:391-438` returns `{"hosts": page, "count": total, "cursor": next_cursor}` | **VERIFIED** | `def list_hosts` at `:391`; `return {...}` at `:438`; `total = len(items)` before pagination slice |
| 10 | `list_hosts` `count` = total across all items (not page count) | **VERIFIED** | `total = len(items)` (line ~418) computed BEFORE the offset/limit slice; returned as `"count": total` — it is the global filtered total, not the page size. **CORRECTED in §2.5, §4.1 step 6, and §5.2**: spec originally claimed `count` matched `list_hosts`'s contract while simultaneously defining it as page-level count. The two are inconsistent because `list_hosts` does a full in-memory load and can return total, while `list_properties` uses real DDB cursor pagination and cannot. §5.2 now correctly notes the divergence. |
| 11 | `app/services/platform_financial_dashboard.py` exists and is billing-domain only | **VERIFIED** | File exists; module docstring: "Computes platform-wide GMV, net revenue…from the existing billing ledger" — no property/rent concept |
| 12 | `billing_shared.new_ledger_entry` at `:224`, `settle_or_reverse_ledger` at `:262`, `apply_balance_delta` at `:83`, `compute_due` at `:158` | **VERIFIED** | All four lines confirmed exact |
| 13 | Rent ledger will use `new_ledger_entry` / `settle_or_reverse_ledger` (void = update state, not delete) / no online payment provider | **VERIFIED** (design intent) | `settle_or_reverse_ledger` uses `update_item` to change `state` field — no `delete_item`. `new_ledger_entry` is provider-agnostic. Consistent with CLAUDE.md and billing_shared architecture |
| 14 | `_flag_on()` / `_require_enabled()` at `app/services/inventory.py:50-57` | **VERIFIED** | `_flag_on` at `:50`, `_require_enabled` at `:54-56` |
| 15 | `_audit()` lazy-import wrapper at `app/services/inventory.py:92-98` | **VERIFIED** | Exact; lazy-imports `audit_event` at `:94`, swallows exceptions |
| 16 | `now_ts()` at `app/core/time.py:2` | **VERIFIED** | Exact |
| 17 | `require_ui_session` at `app/services/sessions.py:330` | **VERIFIED** | `async def require_ui_session` at `:330` |
| 18 | `require_admin_or_root_csrf` at `app/auth/policy.py:100` | **VERIFIED** | `async def require_admin_or_root_csrf` at `:100` |
| 19 | `app/routers/inventory.py` reads use `require_ui_session`, mutations use `require_admin_or_root_csrf`; prefix `/ui/inventory` | **VERIFIED** | Router at `:29`; imports at `:18`, `:27`; reads at `:37`, `:92`, `:107`, `:118`; mutations use `require_admin_or_root_csrf` |
| 20 | `TableDef` class at `scripts/local-ddb-init.py:29-35`; `attr_types` comment at `:34`, field at `:35` | **VERIFIED** | Class at `:29`; comment at `:34` ("Override attribute types…"); `attr_types` field at `:35` — spec cites `:34-36`, minor (±1 line) |
| 21 | `_table_defs()` at `:42`, first entry at `:44` | **VERIFIED** | Exact |
| 22 | `returns: Any` in `Tables` dataclass at `tables.py:319`; `returns=_safe_table(...)` wire at `:571` | **VERIFIED** | Both exact |
| 23 | `S.inventory_reservations_enabled` at `settings.py:839` (pattern for new property_mgmt_enabled) | **VERIFIED** | `:839` exact |
| 24 | `S.returns_rma_enabled` at `settings.py:846`, `S.returns_table_name` at `:847` (insertion point for new settings) | **VERIFIED** | Both exact |
| 25 | `compute_billing.py` timer: `_tick_all_running_resources` at `:616`, `run_compute_billing_timer` at `:653`, `start_compute_billing_timer_task` at `:669` | **VERIFIED** | All three lines confirmed exact |
| 26 | `tickets.py` constants `_STATUS_TRANSITIONS` at `:30`, `_DEFAULT_BOARD_COLUMNS` at `:61` | **VERIFIED** | Both exact |
| 27 | RPT-006 (`docs/suitecrm/specs/RPT-006.md`) and RPT-007 (`docs/suitecrm/specs/RPT-007.md`) specs exist | **VERIFIED** | Both files present; neither currently mentions PROP-003 (consistent with "future consumer, not in scope") |
| 28 | Gap analysis §A row 3: "Property/unit list/filter + occupancy roll-up — MISSING" | **VERIFIED** | `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A table, row 3: "Property/unit list/filter + occupancy roll-up \| **MISSING**" |
| 29 | PROP-002 source in `PROPERTY_UNITS_TICKETS.md` §PROP-002; adds `GSI_UNIT_OCCUPANCY`; calls `compute_property_occupancy` from `update_unit` | **VERIFIED** | `PROPERTY_UNITS_TICKETS.md:151` opens §PROP-002; `:180` defines `GSI_UNIT_OCCUPANCY` in same `TableDef`; `:202` specifies `update_unit` calls occupancy roll-up |
| 30 | PROP-001 source in `docs/open-property/specs/PROP-001.md`; establishes `T.properties`, `S.property_mgmt_enabled`, `GSI_OWNER`, `GSI_STATUS`, helpers | **VERIFIED** | PROP-001.md confirmed; its §12 Verification Log has 33 verified items confirming all PROP-001 prerequisites |
| 31 | Test fixture uses `moto.mock_dynamodb()` | **CORRECTED** | moto 5.2.1 (installed) does not expose `mock_dynamodb` (`hasattr(moto, "mock_dynamodb") == False`). All real tests use `from moto import mock_aws` / `with mock_aws():`. Fixed in §9.1 test fixture. |
| 32 | Referenced test files (`test_gap_0265_0266_kyc_risk_scoring.py`, `test_gap_0233_0234_ssh_session_recording.py`) exist and use `mock_aws` + `object.__setattr__` pattern | **VERIFIED** | Both files confirmed present; pattern confirmed |
| 33 | `dev_s3.py` exists and intercepts S3 in-process | **VERIFIED** | `app/core/dev_s3.py` exists |
| 34 | SECOPS-007 zero `dev_mode` branches claim — consistent with `inventory.py` having no `dev_mode` branches | **VERIFIED** | `grep -n "dev_mode" app/services/inventory.py` → no results |
| 35 | KYC `/templates`-before-`/{case_id}` and audit-export `/schedules`-before-`/{export_id}` ordering gotchas cited in CLAUDE.md | **VERIFIED** | Both documented in CLAUDE.md |

**Summary**: 2 corrections applied. 33 claims verified. 0 UNCONFIRMED.

- **CORRECTED-1** (§9.1 test fixture, line 404): `moto.mock_dynamodb()` → `from moto import mock_aws` + `with mock_aws():`. The `mock_dynamodb` symbol does not exist in moto 5.x.
- **CORRECTED-2** (§2.5, §4.1 step 6, §5.2): `count` semantics were internally contradictory and incorrectly described as matching `list_hosts`. `list_hosts` returns a global total (full in-memory load before slicing); `list_properties` uses true DDB cursor pagination and cannot cheaply produce a global total. All three sections now consistently define `count` as the page-level count and correctly note the divergence from `list_hosts`'s convention.
