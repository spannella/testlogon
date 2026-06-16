# HTL — Nightly rate plans + multi-night price computation (Hotel-PMS spine, gap analysis §B)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §B ("Rate Plans /
Pricing + Availability Calendar / Inventory") and the Tier-1 cluster
"**Nightly rate plans**: seasonal/date-range rates, occupancy surcharges
(extra-adult/child), LOS (min/max nights + discounts), advance/last-minute,
weekend-vs-weekday; multi-night + occupancy price computation"
(`docs/qloapps/QLOAPPS_GAP_ANALYSIS.md:134-136`). QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) is an open-source hotel
PMS + booking engine whose **nightly rate plan** and **multi-night price
computation** are the genuinely net-new pricing primitives the gap analysis flags
as **MISSING**: testlogon's pricing today is **SKU-level**, not stay-level.

These three tickets cover ONLY the rate-plan model + rule rows (HTL-014), the
deterministic multi-night/occupancy **price computation engine** (HTL-015), and
the router + frontend rate-plan editor + price-preview + tests (HTL-016). They are
the **price half** of the Tier-1 spine; the **availability half** (per-room-type
per-date remaining-rooms inventory) is the sibling cluster (HTL-009..HTL-013,
referenced here, owned there), and the **stay-search engine** (HTL-017, gap
analysis §B last row + Tier-2) is the consumer that intersects HTL-012/013
availability with the HTL-015 price engine — a forward reference, out of scope
here.

## Why this is net-new — contrast with existing pricing

testlogon already has two pricing layers, and **neither** has a per-night-of-stay
or guest-occupancy dimension:

- **OFB-019/020 pricing rules** (`app/services/pricing_rules.py`,
  `docs/ofbiz/specs/OFB-019.md` §3.2/§5): `tiered` / `bulk` / `conditional`
  discount strategies keyed on **cart quantity** and **cart total** — they
  discount a *shopping-cart line-item sum*, not a stay. There is no "night",
  "check-in", "occupancy", or "length-of-stay" concept anywhere in the rule
  config (`docs/ofbiz/specs/OFB-019.md:128-158`).
- **PRD-012 price components** (`docs/ofbiz/specs/PRD-012.md` §4.1.6
  `resolve_effective_price`): per-product, per-type, **date-windowed** rows that
  return **ONE effective price as-of a single instant** (`as_of`) — a SKU's
  current price, not a per-night rate **summed across a check-in→check-out span**
  (`docs/ofbiz/specs/PRD-012.md:319-362`).

A hotel needs nightly rates that vary by **season** (date-range override/delta),
**occupancy** (extra-adult / extra-child surcharge above the room type's base
occupancy), **length-of-stay** (min/max nights + stay discount), **advance /
last-minute** (lead-time delta), and **weekend-vs-weekday** (day-of-week delta) —
then **SUMMED across every night** of a check-in→check-out span. That summation +
the occupancy dimension is the primitive that defeats both existing layers.

**We reuse the *ideas*, not the code**: the **rule-evaluation-ordering** idea
(deterministic precedence, like OFB-019 §5.4 stacking) and the
**money-as-cents** integer convention (OFB-019 `discount_value`/`cents`
throughout; PRD-012 `amount_cents`) are carried over. The
`pricing_rules.compute_discount` / `apply_stacking` functions themselves are NOT
called — they operate on a cart, not a stay.

## Cross-cutting constraints (apply to every HTL ticket in this file)

- **Additive + flag-gated, default OFF.** A master flag `HOTEL_PMS_ENABLED`
  (default `false`, shared across the whole Hotel-PMS vertical) gates everything.
  Mirror the `INVENTORY_RESERVATIONS_ENABLED` contract: `_flag_on()` /
  `_require_enabled()` raising **404** when off, exactly like
  `app/services/inventory.py:50-56` (`_flag_on` at `:50`, `_require_enabled`
  raising `HTTPException(status_code=404, ...)` at `:54-56`) and the router-level
  delegate `app/routers/inventory.py:32-38`. Routers are always mounted; every
  handler is a 404 no-op until opt-in. With the flag off the platform is
  byte-for-byte unchanged.
- **Single-table DynamoDB.** One `hotel_rate_plans` table, PK=`hotel_id#room_type_id`
  (the room-type a rate plan binds to), SK=`META` for the plan header and
  SK=`RULE#{kind}#{rule_id}` for per-rule rows — header + child rows co-located on
  one partition for cheap per-room-type scans (same header+child idiom as
  `app/services/inventory.py` location rows `LOC#{location_id}` at `:59-60`).
- **`attr_types` for numeric GSI keys.** Any numeric GSI sort key (e.g.
  `created_at`) MUST be declared in the `TableDef` `attr_types` map per the
  CLAUDE.md DynamoDB numeric-GSI gotcha — omitting it stores the value as String
  → `ValidationException`. Pattern: existing `TableDef(...)` calls in
  `scripts/local-ddb-init.py`.
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py:2`), cursor
  pagination (`encode_cursor`/`decode_cursor`, `app/core/cursor.py:94,103`),
  `_audit()` lazy-import wrapper (copy `app/services/inventory.py:92-98`), table
  handles via `T.*` (`app/core/tables.py`). Money is **always integer cents**
  (OFB-019 / PRD-012 convention).
- **Auth split.** Reads → `require_ui_session` (`app/services/sessions.py:330`);
  mutations → `require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical
  split to `app/routers/inventory.py:38,48,65,81` (reads via `require_ui_session`,
  mutations via `require_admin_or_root_csrf`).
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business
  logic; the same `T.*` handles in both environments (moto intercepts boto3 in
  dev, real DynamoDB in prod). The price engine (HTL-015) is **pure deterministic
  arithmetic** — no randomness, no time-of-day non-determinism beyond the
  caller-supplied `checkin`/`checkout`/`advance_days`.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via
  `object.__setattr__`), frozen `S` flags toggled via `object.__setattr__` and
  restored on cleanup, route coroutines called directly on a fresh
  `asyncio.new_event_loop()` — no `TestClient`, no real AWS (mirrors the
  established hermetic pattern in the GAP-test suite, CLAUDE.md).

---

### HTL-014: Rate-plan model + table + flag

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Land the nightly rate-plan data model, its DynamoDB table, the master Hotel-PMS
feature flag, and the CRUD service for rate plans and their rule rows. Net-new;
the OFB-019 `PricingRules` table is the structural analogue (header + rule
config) but a rate plan binds to a **room type** and holds **stay-dimension** rule
kinds (season / occupancy / los / advance / weekend), NOT cart-quantity tiers
(`docs/ofbiz/specs/OFB-019.md:128-158` — the layer we contrast, not reuse).

A rate plan binds to exactly one room type (`hotel_id#room_type_id`) and holds a
`base_nightly_rate_cents` (defaults from the room type's base rate, set by the
HTL room-type cluster — referenced, not owned here) plus a set of **rule rows**.

DDB table `hotel_rate_plans` (PK=`hotel_id#room_type_id`, SK=`META` for the plan
header; SK=`RULE#{kind}#{rule_id}` child rows co-located on the same partition —
same header+child idiom as inventory `LOC#` rows, `app/services/inventory.py:59-60`):

**META item (plan header):**

| Attribute | Type | Notes |
|---|---|---|
| `hotel_id#room_type_id` | S | PK. Composite of the bound hotel + room type |
| `sk` | S | `META` |
| `rate_plan_id` | S | `rp_` + `uuid4().hex[:12]` (convenience copy) |
| `hotel_id` | S | Denormalized for projections |
| `room_type_id` | S | Denormalized; the bound bookable room type |
| `name` | S | Human label (e.g. `"Standard Flexible"`), max 200 chars |
| `base_nightly_rate_cents` | N | Plan base nightly rate in cents; defaults from the room type's base rate at create time |
| `base_occupancy` | N | Adults included in base rate before extra-adult surcharge (default 2) |
| `currency` | S | ISO 4217, default `"USD"` |
| `active` | BOOL | Default `true` |
| `created_at` | N | `now_ts()` |
| `updated_at` | N | `now_ts()` |
| `created_by` | S | `user_sub` of the creating admin |

**RULE item (per-rule row, SK=`RULE#{kind}#{rule_id}`):** `rule_id = uuid4().hex`,
`kind` ∈ {`season`,`occupancy`,`los`,`advance`,`weekend`}, plus `rule_config` (M)
and `priority` (N, default 500; lower evaluated first — the **ordering idea**
borrowed from OFB-019 §5.4, `docs/ofbiz/specs/OFB-019.md:484-489`):

| `kind` | `rule_config` shape | Semantics |
|---|---|---|
| `season` | `{start_date:"YYYY-MM-DD", end_date:"YYYY-MM-DD", mode:"absolute"\|"delta", value_cents:int}` | For nights whose date ∈ [start,end]: `absolute` → override the nightly rate to `value_cents`; `delta` → add `value_cents` (may be negative) |
| `occupancy` | `{extra_adult_cents:int, extra_child_cents:int}` | Per-night surcharge: `max(0, adults - base_occupancy) * extra_adult_cents + children * extra_child_cents` |
| `los` | `{min_nights:int, max_nights:int\|null, discount_type:"percentage"\|"fixed_cents", discount_value:int}` | Whole-stay: rejects stays shorter than `min_nights` / longer than `max_nights`; applies discount to the stay subtotal when nights ∈ [min,max] |
| `advance` | `{days_before_checkin:int, comparator:"gte"\|"lte", mode:"percentage"\|"fixed_cents", value:int}` | Whole-stay: when `advance_days` satisfies the comparator vs `days_before_checkin`, modify the stay subtotal (advance-purchase = `gte` discount; last-minute = `lte` delta) |
| `weekend` | `{dow:[int,...], mode:"absolute"\|"delta", value_cents:int}` | Per-night: for nights whose ISO weekday (Mon=1..Sun=7) ∈ `dow`, override (`absolute`) or add (`delta`) `value_cents` |

GSIs (declared in `scripts/local-ddb-init.py`, `attr_types={"created_at": "N"}` —
numeric sort key):
- `GSI_HOTEL` — PK=`hotel_id`, SK=`created_at` — list a hotel's rate plans
  newest-first (admin rate-plan listing).
- `GSI_ROOM_TYPE` — PK=`room_type_id`, SK=`created_at` — fetch the rate plan(s)
  for a room type (the path HTL-015's quote / HTL-017's stay-search calls).

`TableDef` follows the existing `scripts/local-ddb-init.py` `TableDef(...)` form
(cf. OFB-019 `PricingRules` def, `docs/ofbiz/specs/OFB-019.md:580-593`):
```python
TableDef(
    _resolve_table_name(S.hotel_rate_plans_table_name, "hotel_rate_plans"),
    "hotel_id#room_type_id",
    "sk",
    gsi=[
        {"index_name": "GSI_HOTEL",     "partition_key": "hotel_id",     "sort_key": "created_at"},
        {"index_name": "GSI_ROOM_TYPE", "partition_key": "room_type_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings (add to `app/core/settings.py` next to the inventory block at
`:839-840`, same `os.environ.get(...).lower() == "true"` idiom):
```python
hotel_pms_enabled: bool = os.environ.get("HOTEL_PMS_ENABLED", "false").lower() == "true"
hotel_rate_plans_table_name: str = os.environ.get("HOTEL_RATE_PLANS_TABLE_NAME", "hotel_rate_plans")
```

Table handle: add `hotel_rate_plans: Any` to the `T` dataclass
(`app/core/tables.py`) and wire
`hotel_rate_plans=_safe_table(S.hotel_rate_plans_table_name)` in the initializer
(same `_safe_table(...)` pattern as the existing handles).

Pydantic models in `app/models.py`: `RatePlanIn` (name, base_nightly_rate_cents
optional → defaults from room type, base_occupancy, currency), `RatePlanOut` (all
persisted header fields), `RatePlanUpdateIn` (partial), and `RatePlanRuleIn`
(kind + the per-kind `rule_config` discriminated payload + priority) /
`RatePlanRuleOut`. `kind`, `season.mode`, `los.discount_type`, `advance.mode`,
`advance.comparator`, `weekend.mode` constrained to the literals above. Money
fields are `int` cents (`ge=0` for rates; `value_cents`/`discount_value` allow
negatives only for `delta` modes — validated in the service per-kind validator).

Service `app/services/hotel_rate_plans.py` (new), modeled on
`app/services/inventory.py`:
- `_flag_on()` / `_require_enabled()` → 404 when off (copy `inventory.py:50-56`,
  reading `S.hotel_pms_enabled`).
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy
  `inventory.py:92-98`).
- `create_rate_plan(hotel_id, room_type_id, *, name, base_nightly_rate_cents,
  base_occupancy, currency, user_sub) -> dict` — derives `rate_plan_id`,
  conditional `attribute_not_exists` put on the `META` SK → idempotent on
  re-create of the same (hotel, room_type) META; `_audit("hotel.rate_plan.created", ...)`.
- `get_rate_plan(hotel_id, room_type_id) -> dict | None` — reads SK=`META`.
- `add_rule(hotel_id, room_type_id, *, kind, rule_config, priority, user_sub) -> dict`
  — validates parent plan exists (404 if missing); per-kind config validator
  (`_validate_season_config`, `_validate_occupancy_config`, `_validate_los_config`,
  `_validate_advance_config`, `_validate_weekend_config` — pure, deterministic;
  reject bad date ranges, `min_nights >= 1`, `max_nights >= min_nights` or null,
  dow ∈ 1..7, valid mode/comparator); `uuid4().hex` rule_id; `put_item` on
  SK=`RULE#{kind}#{rule_id}`; `_audit("hotel.rate_plan.rule.added", ...)`.
- `list_rules(hotel_id, room_type_id) -> list[dict]` — `Key` query
  `begins_with(sk, "RULE#")`, sorted by (`priority`, `kind`, `rule_id`).
- `update_rule(hotel_id, room_type_id, rule_id, kind, *, rule_config, priority,
  user_sub) -> dict` — re-validates config; stamps `updated_at`.
- `delete_rule(hotel_id, room_type_id, rule_id, kind, *, user_sub) -> bool` —
  deletes the child row; returns `False` (never raises) for an unknown rule
  (mirrors `host_inventory.delete_host` no-raise contract noted in CLAUDE.md).
- `update_rate_plan(hotel_id, room_type_id, *, user_sub, **kwargs) -> dict` /
  `deactivate_rate_plan(...)` — header mutation, stamps `updated_at`.

All entrypoints call `_require_enabled()` first. **Nothing random; nothing
env-tunable** in the math (rate values live in DDB rule rows, not settings).

**Acceptance Criteria**
- `hotel_rate_plans` `TableDef` present with both GSIs and
  `attr_types={"created_at": "N"}`; `just restart` creates the table without
  `ValidationException`.
- `HOTEL_PMS_ENABLED` defaults to `false`; with it off, every
  `hotel_rate_plans` service entrypoint raises HTTP 404 via `_require_enabled()`.
- `create_rate_plan` is idempotent on (hotel_id, room_type_id): two calls return
  the same `rate_plan_id` and the second does not error (conditional put).
- META and RULE rows co-locate on the parent partition; `list_rules` returns only
  `RULE#`-prefixed rows (never the `META` row), sorted by `priority`.
- Each `_validate_*_config` rejects malformed configs (bad date range, `dow`
  outside 1..7, `max_nights < min_nights`, unknown mode/comparator) before any
  write.
- `delete_rule` returns `False` for an unknown rule and never raises.
- `T.hotel_rate_plans` resolves; `RatePlanIn/Out/UpdateIn` + `RatePlanRuleIn/Out`
  import cleanly.
- No `if S.dev_mode` branch in `hotel_rate_plans.py` (SECOPS-007).

**Dependencies**: none in this file (foundational for the cluster). Reuses:
`app/services/inventory.py:50-56,59-60,92-98` (flag/child-row/audit idioms),
`scripts/local-ddb-init.py` (`TableDef`), `app/core/tables.py` (`_safe_table`
handle), `app/core/settings.py:839-840` (flag block neighbor),
`app/core/time.py:2` (`now_ts`), `uuid4().hex` id, `host_inventory.delete_host`
no-raise contract (CLAUDE.md). Forward-ref: the HTL room-type cluster supplies the
room type's base nightly rate that `base_nightly_rate_cents` defaults from.
Contrasts: `docs/ofbiz/specs/OFB-019.md:128-158` (cart-quantity tiers, not
stay-dimension rates).

---

### HTL-015: Multi-night price computation engine

**Type**: Feature
**Priority**: P1
**Estimate**: 2d

**Description**

Add the deterministic **multi-night / occupancy price computation engine** — the
core net-new hotel pricing primitive. This is the function the gap analysis flags
as MISSING: "nothing computes availability across a date range or sums per-night
prices" (`docs/qloapps/QLOAPPS_GAP_ANALYSIS.md:87`). It is the **price half** of
the Tier-1 spine and the function HTL-017's stay-search engine consumes alongside
HTL-012/013 availability (forward ref).

Service function in `app/services/hotel_rate_plans.py`:

```python
def compute_stay_price(
    hotel_id: str,
    room_type_id: str,
    checkin: str,          # "YYYY-MM-DD" (inclusive — first night)
    checkout: str,         # "YYYY-MM-DD" (exclusive — departure day, not a night)
    adults: int,
    children: int,
    rooms: int = 1,
    advance_days: int | None = None,   # lead time; default = days between now_ts() and checkin
) -> StayPriceResult:
    """
    Deterministic per-night breakdown + summed total for one room type over a
    check-in→check-out span. Pure arithmetic; no DDB writes, no randomness.
    """
```

`_require_enabled()` first. Loads the rate plan + rules once via
`get_rate_plan` + `list_rules`. The number of nights is the count of dates in
`[checkin, checkout)` (checkout is the departure day, NOT a billable night —
the standard hotel convention; a 1-night stay is checkin→checkin+1).

**Per-night computation** (deterministic, fixed order — the **ordering idea**
borrowed from OFB-019 §5.4, applied to nights rather than a cart):
for EACH night `d` in the span, starting from `base_nightly_rate_cents`:
1. **season** override → if a `season` rule's date range contains `d`,
   `absolute` mode replaces the night rate; `delta` mode adds `value_cents`.
   (If multiple season rules match, lowest `priority` wins for `absolute`; deltas
   sum — deterministic tiebreak by `rule_id`.)
2. **weekend** delta → if `d`'s ISO weekday ∈ a `weekend` rule's `dow`,
   `absolute` overrides the (post-season) night rate; `delta` adds `value_cents`.
3. **occupancy** surcharge → add
   `max(0, adults - base_occupancy) * extra_adult_cents + children * extra_child_cents`
   to the night (from the single `occupancy` rule if present).
4. Floor each night at 0 (a delta can never drive a night negative).

Collect a per-night line `{date, base_cents, season_delta_cents,
weekend_delta_cents, occupancy_cents, night_total_cents}`. Sum the nights →
`stay_subtotal_cents`.

**Whole-stay modifiers** (applied AFTER per-night summation, deterministic order):
5. **LOS validation + discount** → if a `los` rule exists, reject when
   `nights < min_nights` (raise `HTTPException(422, "stay too short")`) or
   `max_nights is not None and nights > max_nights` (`HTTPException(422, "stay
   too long")`); otherwise apply its discount (`percentage` → `floor(subtotal *
   value / 100)`; `fixed_cents` → `min(value, subtotal)`) to `stay_subtotal_cents`.
6. **advance modifier** → if an `advance` rule's comparator on
   `advance_days` vs `days_before_checkin` holds, apply its modifier
   (`percentage`/`fixed_cents`, same arithmetic, may be a surcharge or discount).
7. Multiply the post-modifier per-room total by `rooms`.
8. Cap total discount so `total_cents >= 0` (never negative — the
   negative-total guard idea from OFB-019 §7.4,
   `docs/ofbiz/specs/OFB-019.md:635-637`).

Return a `StayPriceResult` dataclass / model:
```
nights: int
per_night: list[NightLineOut]          # itemized {date, base_cents, season_delta_cents,
                                        #           weekend_delta_cents, occupancy_cents,
                                        #           night_total_cents}
stay_subtotal_cents: int               # sum of per-night totals (one room, pre whole-stay mods)
los_discount_cents: int
advance_modifier_cents: int            # signed (negative = discount)
rooms: int
total_cents: int                       # final, all rules applied, × rooms, floored ≥ 0
currency: str
applied_rule_ids: list[str]            # observability
```

**Determinism**: identical inputs (same dates/occupancy/advance_days + same rule
rows) always yield the same breakdown — no `now_ts()` inside the math except the
`advance_days` default derivation, which the caller can pin for reproducible
tests. No env-tunable weights (contrast OFB-019's `NEWSFEED_RECSYS_WEIGHT_*`-style
knobs — here every value lives in a DDB rule row).

**Contrast with existing pricing**: this SUMS a per-night rate across a span with
an occupancy dimension. `pricing_rules.compute_discount`
(`docs/ofbiz/specs/OFB-019.md:216-233`) discounts a cart and has no night/date
loop; `product_price_components.resolve_effective_price`
(`docs/ofbiz/specs/PRD-012.md:319-362`) returns ONE price as-of ONE instant and
never iterates dates. Neither is called.

**Acceptance Criteria**
- `compute_stay_price` returns an itemized `per_night` list whose length equals
  the night count of `[checkin, checkout)` (checkout day excluded), and
  `stay_subtotal_cents == sum(night_total_cents)`.
- **season**: a night inside a `season` `absolute` window uses the season rate;
  a `delta` window adds the delta; a night outside uses the base rate.
- **weekend**: nights whose ISO weekday ∈ `dow` get the weekend override/delta;
  weekday nights do not.
- **occupancy**: `adults > base_occupancy` and/or `children > 0` add the correct
  per-night surcharge; `adults <= base_occupancy, children == 0` adds 0.
- **LOS**: `nights < min_nights` → 422 "too short"; `nights > max_nights` → 422
  "too long"; in-range stay gets the LOS discount applied to the subtotal.
- **advance**: comparator (`gte`/`lte`) on `advance_days` toggles the advance
  modifier; the modifier is signed in `advance_modifier_cents`.
- **span summation + rooms**: `total_cents` = (subtotal − LOS − advance) × rooms,
  floored at ≥ 0; a discount larger than the subtotal yields `total_cents == 0`,
  never negative.
- Pure / deterministic: same inputs + same rule rows → identical result; no
  randomness; no `if S.dev_mode` branch (SECOPS-007).
- Flag off → 404 (`_require_enabled()` first line).

**Dependencies**: HTL-014 (rate-plan + rule rows + `get_rate_plan`/`list_rules`).
Reuses: `app/core/time.py:2` (`now_ts` for `advance_days` default only),
money-as-cents convention + negative-total guard idea
(`docs/ofbiz/specs/OFB-019.md:635-637`), rule-ordering idea
(`docs/ofbiz/specs/OFB-019.md:484-489`). Forward-ref: consumed by HTL-017
stay-search alongside HTL-012/013 per-date availability. Contrasts:
`docs/ofbiz/specs/OFB-019.md:216-233` (cart discount, no span) and
`docs/ofbiz/specs/PRD-012.md:319-362` (single-instant price, no span).

---

### HTL-016: Router + price-quote endpoint + frontend rate-plan editor + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 2.5d

**Description**

Expose the rate-plan services over HTTP via a new `hotel_rate_plans_router`,
modeled exactly on `app/routers/inventory.py` (auth split + `_require_enabled()`
short-circuit), add a **price-quote endpoint** wrapping HTL-015, register the
router in `app/main.py`, build the frontend rate-plan editor + price-preview
widget, and ship the hermetic pytest + E2E specs.

**Router** `app/routers/hotel_rate_plans.py`:
```python
hotel_rate_plans_router = APIRouter(prefix="/ui/hotels", tags=["hotel-rate-plans"])
```
Every handler calls `_require_enabled()` first (delegating to
`hotel_rate_plans._require_enabled()`, exactly like `app/routers/inventory.py:32-38`).

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/ui/hotels/{hotel_id}/rate-plans` | `require_ui_session` | list rate plans for the hotel (via `GSI_HOTEL`) |
| POST | `/ui/hotels/{hotel_id}/rate-plans` | `require_admin_or_root_csrf` | `create_rate_plan` (body carries `room_type_id`) |
| GET | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan` | `require_ui_session` | `get_rate_plan` (404 if none) |
| PUT | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan` | `require_admin_or_root_csrf` | `update_rate_plan` |
| DELETE | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan` | `require_admin_or_root_csrf` | `deactivate_rate_plan` |
| GET | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan/rules` | `require_ui_session` | `list_rules` |
| POST | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan/rules` | `require_admin_or_root_csrf` | `add_rule` |
| PUT | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan/rules/{rule_id}` | `require_admin_or_root_csrf` | `update_rule` (body carries `kind`) |
| DELETE | `/ui/hotels/{hotel_id}/room-types/{rt}/rate-plan/rules/{rule_id}` | `require_admin_or_root_csrf` | `delete_rule` (query `kind`) |
| POST | `/ui/hotels/{hotel_id}/room-types/{rt}/quote` | `require_ui_session` | `compute_stay_price` (the price-preview / quote endpoint) |

> **Declaration order — literal before dynamic.** Declare the static
> `/rate-plans` collection route(s) BEFORE the dynamic
> `/room-types/{rt}/...` routes, and the literal `/quote` segment is the LAST
> path segment under a `{rt}` param so it cannot be captured as a sub-resource id.
> FastAPI matches in declaration order — same gotcha as the KYC
> `/templates`-before-`/{case_id}` and audit-export
> `/schedules`-before-`/{export_id}` ordering noted in CLAUDE.md.

Reads use `require_ui_session` (`app/services/sessions.py:330`); mutations use
`require_admin_or_root_csrf` (`app/auth/policy.py:100`) — identical to
`app/routers/inventory.py:38,48,65,81`. The quote endpoint is a `require_ui_session`
**read** (it computes but does not persist — a price preview a storefront/admin
can call). `create_*`/`add_rule` handlers stamp `user_sub=user.sub`.

Register in `app/main.py` next to `inventory_router`
(`app/main.py:311` import, `:877` `include_router`):
```python
from app.routers.hotel_rate_plans import hotel_rate_plans_router
...
app.include_router(hotel_rate_plans_router)
```

Pydantic quote models in `app/models.py`: `StayQuoteIn` (checkin, checkout,
adults, children, rooms, advance_days?), `NightLineOut`, `StayPriceResult` /
`StayQuoteOut` (the breakdown from HTL-015).

**Frontend** (`frontend/src/`), following the CLAUDE.md "Adding a new feature"
recipe (steps 5–9):
- **Types** — add `RatePlan`, `RatePlanRule` (discriminated on `kind`),
  `NightLine`, `StayQuote`, and the in/update shapes to
  `frontend/src/api/types.ts` (mirror the `app/models.py` HTL models).
- **API endpoints** — `frontend/src/api/endpoints/hotelRatePlans.ts` wrapping the
  axios instance (`frontend/src/api/client.ts`): `listRatePlans`,
  `createRatePlan`, `getRatePlan`, `updateRatePlan`, `deactivateRatePlan`,
  `listRules`, `addRule`, `updateRule`, `deleteRule`, `quoteStay`.
- **Pages** under `frontend/src/pages/hotels/`:
  - `RatePlanEditorPage.tsx` — the rate-plan editor for one room type: header
    (name, base nightly rate from cents, base occupancy, currency, active
    toggle), a **rules list** grouped by `kind`, and per-kind **add-rule forms**
    (season date-range + mode + value; occupancy extra-adult/child cents; LOS
    min/max + discount; advance days/comparator/mode/value; weekend dow
    multi-select + mode/value) using React Hook Form + Zod, each calling
    `addRule`/`updateRule`/`deleteRule`. shadcn/ui primitives (`Card`, `Dialog`,
    `Badge`, `Button`, `Select`, `components/ui/`).
  - A **price-preview widget** (component on the editor page, e.g.
    `StayPricePreview.tsx`) — date-range + adults/children/rooms/advance_days
    inputs that call the `quote` endpoint via `quoteStay` and render the
    per-night breakdown table + total (cents → formatted currency). Driven by
    React Query `useMutation` / `useQuery` so an admin sees the live effect of a
    rule edit.
- **Routes** — lazy-load the editor in `frontend/src/App.tsx` (cf. the lazy
  imports at `:14+`): `/hotels/:hotelId/room-types/:rt/rate-plan` →
  `RatePlanEditorPage`.
- **Sidebar** — optionally surface under a "Hotels" nav group in
  `frontend/src/components/layout/Sidebar.tsx` (cf. nav-item array at `:104+`);
  routes 404 server-side when the flag is off, so unconditional visibility is
  safe.

**Tests:**
- **Hermetic pytest** `tests/test_htl_rate_plans.py` — moto-bound
  `hotel_rate_plans` table on frozen `T` (`object.__setattr__`), frozen `S` with
  `hotel_pms_enabled` toggled via `object.__setattr__` (restored on cleanup),
  route coroutines called directly on a fresh `asyncio.new_event_loop()` (no
  `TestClient`). Cover, at minimum:
  - **season math** — a night inside an `absolute` window uses the season rate; a
    `delta` window adds; an outside night uses base.
  - **occupancy math** — extra-adult + extra-child surcharge applied per night;
    base-occupancy stay adds 0.
  - **los math + rejection** — in-range stay gets the discount; `nights <
    min_nights` → 422 "too short"; `nights > max_nights` → 422 "too long".
  - **advance math** — `gte`/`lte` comparator toggles the modifier; signed in the
    breakdown.
  - **weekend math** — `dow`-matching nights get the override/delta; weekday
    nights do not.
  - **span summation** — `stay_subtotal_cents == sum(night_total_cents)`;
    `total_cents == subtotal × rooms` (no whole-stay mods) and floored ≥ 0 when a
    discount exceeds the subtotal.
  - **create idempotency** — two `create_rate_plan` calls on the same (hotel,
    room_type) return the same `rate_plan_id`.
  - **rule CRUD** — `add_rule` → `list_rules` (priority-sorted, only `RULE#`
    rows) → `update_rule` → `delete_rule` (returns `False` for unknown, never
    raises).
  - **flag-off 404** — every service entrypoint AND every route handler raises
    HTTP 404 when `hotel_pms_enabled=False`.
  - **route ordering** — `/quote` and `/rate-plans` resolve to their handlers,
    not captured by a `{rt}`/`{rule_id}` dynamic param.
- **E2E** `frontend/e2e/hotel-rate-plans.spec.ts` — cookie-auth (`injectAuth`)
  admin creates a rate plan, adds one rule of each `kind`, asserts the rules list
  renders, then drives the price-preview widget (enter a date range + occupancy)
  and asserts the per-night breakdown + total render; CSRF header on POSTs
  (`x-csrf-token`). Requires `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- All 10 endpoints respond; flag off → every endpoint 404s (handler-level no-op,
  router still mounted, platform byte-for-byte unchanged).
- Read + quote endpoints accept a UI session; mutation endpoints reject
  non-admin / missing-CSRF requests (403) per `require_admin_or_root_csrf`.
- `/quote` and `/rate-plans` resolve to their handlers, NOT captured by a dynamic
  param (literal-before-dynamic / last-segment ordering).
- `hotel_rate_plans_router` imported and `include_router`'d in `app/main.py`
  adjacent to `inventory_router`.
- `/hotels/:hotelId/room-types/:rt/rate-plan` renders the editor (rules list +
  per-kind add-rule forms) and the price-preview widget shows a live per-night
  breakdown + total (cents → formatted currency) by calling `quote`.
- `tests/test_htl_rate_plans.py` passes offline (no AWS, no live stack) and
  covers season/occupancy/los/advance/weekend math, span summation, LOS
  rejection, and flag-off 404.
- `frontend/e2e/hotel-rate-plans.spec.ts` passes with the flag on.

**Dependencies**: HTL-014 (table + flag + rate-plan/rule service), HTL-015
(`compute_stay_price` for the quote endpoint). Reuses:
`app/routers/inventory.py:32-38,48,65,81` (router/auth/flag idiom),
`app/auth/policy.py:100` (`require_admin_or_root_csrf`),
`app/services/sessions.py:330` (`require_ui_session`), `app/main.py:311,877`
(registration), `frontend/src/api/client.ts`, `frontend/src/App.tsx:14+` (lazy
routes), `frontend/src/components/layout/Sidebar.tsx:104+` (nav items), shadcn/ui
(`components/ui/`), React Query + RHF/Zod conventions (CLAUDE.md), hermetic-test +
E2E patterns (CLAUDE.md). Forward-ref: the quote endpoint + `compute_stay_price`
are reused by HTL-017 stay-search.

---

## Dependency order

HTL-014 (rate-plan model + table + flag + rule CRUD) → HTL-015 (multi-night price
computation engine, consumes `get_rate_plan`/`list_rules`) → HTL-016 (router +
`/quote` endpoint + `main.py` registration + frontend editor/preview + hermetic
pytest + E2E).

Forward references (owned by sibling clusters, NOT in this file): the HTL
room-type cluster supplies the room type's base nightly rate that HTL-014's
`base_nightly_rate_cents` defaults from; HTL-012/013 supply per-date availability;
HTL-017 (stay-search engine) intersects that availability with HTL-015's
`compute_stay_price` to produce "available room types + summed multi-night price"
(`docs/qloapps/QLOAPPS_GAP_ANALYSIS.md:138-140`).
