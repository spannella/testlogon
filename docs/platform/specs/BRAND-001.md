# BRAND-001 — Platform branding entity — root-admin-configurable name/logo/support-email

**Type**: Feature (platform infra) | **Priority**: P2 | **Estimate**: 0.5d
**Source**: `docs/CROSS_TICKET_AUDIT.md §D6` (resolved product decision, 2026-06-13) + §B1 row 2 + §A "B1-2"

---

## 1. Summary & Goal

BRAND-001 formalizes resolved decision **D6** (`docs/CROSS_TICKET_AUDIT.md §D6`, §C item, Part D): a single, platform-wide, root-admin-configurable **branding entity** holding `{name, logo_url, support_email}`. It lands exactly four deliverables:

1. Three env-default settings keys in `app/core/settings.py` — `PLATFORM_NAME` (default `"testlogon"`), `PLATFORM_LOGO_URL`, `PLATFORM_SUPPORT_EMAIL` — plus a `platform_settings_table_name` + `branding_cache_ttl_seconds` config.
2. A new single-row DynamoDB settings entity (`PK="PLATFORM"`, `SK="BRANDING"`) holding `{name, logo_url, support_email, updated_at, updated_by}`, stored in a new small generic `platform_settings` table (PK=`pk`, SK=`sk`).
3. A new service `app/services/branding.py` with `get_branding() -> dict` (cached, env-fallback, **never raises**) and `set_branding(*, name?, logo_url?, support_email?, actor_sub) -> dict`.
4. A router exposing `GET /ui/admin/branding` (admin-readable) and `PUT /ui/admin/branding` (**ROOT only**), registered in `app/main.py`.

The motivating problem (`docs/CROSS_TICKET_AUDIT.md §B1` row 2): notification templates reference `{{platform_name}}` (`app/services/notification_templates.py:38,41,50,72`) but **no `S.platform_name` setting exists** — `grep -n "platform_name" app/core/settings.py` returns nothing. Before BRAND-001, that merge-tag has no value source. After BRAND-001, every `{{platform_name}}` resolves via `get_branding()["name"]`, which falls back to the `PLATFORM_NAME` env default and therefore **can never `AttributeError`** even with an empty table. CMP-006 and CMP-008 are already written to consume this entity (`docs/suitecrm/specs/CMP-006.md:266`, `docs/suitecrm/specs/CMP-008.md:165`).

Branding is **platform infrastructure, not a vertical feature** — it is therefore **NOT** behind a vertical master flag (no `BRANDING_ENABLED`). It is always available and safe-by-default via the env fallback. This is the one intentional departure from the `_require_enabled()` 404-gate convention (`docs/CROSS_TICKET_AUDIT.md §A5`), justified in §6.

---

## 2. Context & Current State

### 2.1 Gap — `{{platform_name}}` has no value source today

`app/services/notification_templates.py` (ADMIN-002) seeds default email/SMS templates that use `{{platform_name}}` as a merge variable:

```python
# notification_templates.py:38
"subject": "Welcome to {{platform_name}}!",
# :41  "<p>Thanks for joining {{platform_name}}. "
# :50  "subject": "Reset your {{platform_name}} password",
# :72  "body": "{{platform_name}} alert: {{message}}",
```

Rendering goes through `_render(text, sample_vars)` (`notification_templates.py:245`), which substitutes `{{var}}` from a caller-supplied `sample_vars` dict and **records any unresolved var as `missing`** (`:255–257`) — it does NOT pull a default. There is no code anywhere that supplies a value for `platform_name`; `grep -n "platform_name" app/core/settings.py` (2772-line file) returns nothing — confirmed in `docs/suitecrm/specs/CMP-006.md:655` (verification item 30). The cross-ticket audit (`docs/CROSS_TICKET_AUDIT.md §B1` row 2) flags this as an **unowned artifact**: "`{{platform_name}}` injected but `S.platform_name` doesn't exist; siblings diverge (CMP-006 has its own `web_to_lead_platform_name`)."

### 2.2 Decision D6 — the canonical resolution

`docs/CROSS_TICKET_AUDIT.md §D6` (and Part C, resolved 2026-06-13):

> Canonical: a **`PLATFORM#BRANDING`** settings row `{name, logo_url, support_email}` with `GET/PUT /ui/admin/branding` (**root** only); env values (`PLATFORM_NAME`, …) are the defaults; a cached `get_branding()` helper resolves it. Templates read `{{platform_name}}` from `get_branding()`. **CMP-006** (`web_to_lead_platform_name`) and **CMP-008** migrate to `get_branding().platform_name`. A small dedicated branding ticket should formalize the entity when this is built.

BRAND-001 **is** that "small dedicated branding ticket." Note the D6 prose says `PK="PLATFORM#BRANDING"` informally; the concrete data model below uses `PK="PLATFORM"`, `SK="BRANDING"` (two-attribute key, matching every other generic settings table in the codebase) so the entity sits cleanly in a single-table layout and leaves room for future `SK` values (e.g. `SK="THEME"`). The logical name `PLATFORM#BRANDING` is preserved in prose as the row's identity.

### 2.3 Downstream consumers are already written against this entity

Both consumer specs reference `get_branding()` and the `from app.services.branding import get_branding` import as a committed dependency:

- **CMP-006** (`docs/suitecrm/specs/CMP-006.md:266–276,428–433,671–680`): the web-to-lead auto-responder sources `{{platform_name}}` from `get_branding().platform_name`; the bespoke `web_to_lead_platform_name` setting is **SUPERSEDED** (`:426`) and must NOT be added.
- **CMP-008** (`docs/suitecrm/specs/CMP-008.md:25–34,152,165`): `from app.services.branding import get_branding  # canonical branding entity (decision D6)` (`:165`); sources `{{platform_name}}` from `get_branding().platform_name`, NOT from `getattr(S, "platform_name", "")`.

Both specs use attribute-access syntax `get_branding().platform_name`. To honor that, `get_branding()` returns a plain `dict` **and** the spec also exposes a `BrandingOut` Pydantic model so router responses are attribute-accessible; the `.platform_name` accessor in the consumer specs is satisfied either by `BrandingOut` or by mapping the dict `["name"]` → `platform_name` (see §3.3 — the dict carries a `platform_name` alias key so `get_branding()["platform_name"]` and `get_branding().platform_name` via the model both work, and consumers needn't change to dict-subscript syntax).

### 2.4 Cached settings-row pattern to reuse — `billing_config.py`

`app/services/billing_config.py` (FIN-018) is the exact precedent for "a single DDB settings row, env-default fallback, short-TTL in-memory cache, root-editable." BRAND-001 mirrors it structurally:

- Module-level cache: `_config_cache: Optional[Dict] = None`, `_cache_ts: int = 0` (`billing_config.py:46–47`).
- TTL helper reading a setting (`billing_config.py:50–51`).
- `get_billing_config()` (`:236–278`): cache-hit short-circuit (`:245–246`), DDB `get_item(Key={"pk": _PK, "sk": _SK_CURRENT})` wrapped in `try/except` that **falls back to env defaults on any error** (`:250–255`), merges stored item over defaults, repopulates cache.
- `invalidate_cache()` (`:54–58`): nulls the cache; called by `set_*`.

BRAND-001 copies this shape verbatim with `_PK="PLATFORM"`, `_SK="BRANDING"`, and the three branding keys.

### 2.5 Generic settings-table shape to reuse

The codebase has several generic `pk`/`sk` settings/config tables already: `billing_config` (`scripts/local-ddb-init.py:78`, PK=`pk`/SK=`sk`), `cart_reminder_config` (`:110`), `role_audit` (`:55`). The `TableDef` idiom is at `scripts/local-ddb-init.py:28–36`. BRAND-001 defines a **new** `platform_settings` table on the same `pk`/`sk` shape (table-choice justified in §3.1).

### 2.6 Root-auth dependency to reuse

Two equivalent root gates exist:
- `require_root` (`app/auth/policy.py:63–64`) — `require_roles(user, {Role.ROOT})`, raises `role_required_error` (403).
- `require_root_session` (`app/auth/deps.py:308–313`) — raises `HTTPException(403, "Root access required")`.

PUT uses **`require_root`** (the policy-layer dependency, which composes with `enforce_cookie_csrf` the same way `require_admin_or_root_csrf` does — `policy.py:100–106`). GET uses `require_admin_or_root` (`policy.py:67–68`) so admins can read branding for display without root. The router additionally calls `enforce_cookie_csrf(request)` on the PUT (`policy.py:71–97`) to enforce cookie CSRF, matching the platform mutation convention.

### 2.7 What does NOT exist yet

- `grep -n "platform_name\|PLATFORM_NAME" app/core/settings.py` → empty (no env default).
- `grep -in "platform_settings\|branding" app/core/tables.py scripts/local-ddb-init.py` → empty (no table).
- `app/services/branding.py` does not exist.
- No `/ui/admin/branding` route is registered in `app/main.py`.

---

## 3. Data Model

### 3.1 Table choice (justified): new `platform_settings` table

**Decision: define a new small `platform_settings` table** (PK=`pk`, SK=`sk`), NOT reuse an existing config table.

Candidates evaluated against the live codebase:

| Candidate table | Shape | Why rejected |
|---|---|---|
| `billing_config` (`local-ddb-init.py:78`) | `pk`/`sk` | Semantically billing-scoped (FIN-018: platform fee bps, payout minimum, currency, tax rate — `settings.py:2622–2624`). Branding is not billing config; co-locating would couple unrelated cache invalidation (`billing_config.invalidate_cache`) and obscure ownership. |
| `cart_reminder_config` (`:110`) | `pk`/`sk` | Cart-domain scoped (FIN-003). Same coupling objection. |
| `admin_messaging_templates` (`:1431`) | `TEMPLATE#{id}`/`sk` | Template store, different PK convention; branding is not a template. |
| `users` / `sessions` | per-user keyed | Wrong cardinality — branding is a singleton, not per-user. |

A dedicated `platform_settings` table is correct because (a) branding is **platform-singleton** (one row), (b) it is the natural home for *future* platform-wide singleton settings (theme, locale defaults, feature toggles surfaced to UI) under additional `SK` values, and (c) it keeps cache lifecycles independent. The table is tiny (a handful of rows) and adds negligible cost. This mirrors how `billing_config` is its own table rather than crammed into `billing`.

### 3.2 Table: `platform_settings`

Single DynamoDB table, generic `pk`/`sk` shape (identical idiom to `billing_config`).

**Primary key**

| Key | Type | Value |
|---|---|---|
| `pk` | S (PK) | `"PLATFORM"` |
| `sk` | S (SK) | `"BRANDING"` (the branding row; logical identity `PLATFORM#BRANDING` per D6) |

**Branding row attributes** (`pk="PLATFORM"`, `sk="BRANDING"`)

| Attribute | DDB Type | Constraints / Notes |
|---|---|---|
| `pk` | S | Always `"PLATFORM"` |
| `sk` | S | Always `"BRANDING"` |
| `name` | S | Platform display name; non-empty when set; falls back to `PLATFORM_NAME` env default |
| `logo_url` | S | Absolute URL to the logo asset; may be empty string; falls back to `PLATFORM_LOGO_URL` |
| `support_email` | S | Support contact email; may be empty string; falls back to `PLATFORM_SUPPORT_EMAIL` |
| `updated_at` | N | `now_ts()` — integer Unix seconds (`app/core/time.py:2`); set on every `set_branding` |
| `updated_by` | S | `actor_sub` of the root user who last wrote the row |

**No GSIs.** The entity is a singleton fetched by exact key (`get_item(Key={"pk":"PLATFORM","sk":"BRANDING"})`) — there is no list/query access pattern. No numeric GSI sort key, so the CLAUDE.md `attr_types` rule does not apply here (it only matters for numeric **GSI** keys; `updated_at` is a plain numeric attribute on the item, not a key).

**TableDef** (to be appended in `scripts/local-ddb-init.py` inside `_table_defs()`, following the `billing_config` entry pattern at `:78`):

```python
TableDef(_resolve_table_name(S.platform_settings_table_name, "platform_settings"), "pk", "sk"),
```

### 3.3 Pydantic models (`app/models.py`)

**`BrandingOut`** — read/update response (attribute-accessible; satisfies CMP-006/008 `.platform_name`):

```python
class BrandingOut(BaseModel):
    platform_name: str            # mapped from row "name" (alias for {{platform_name}})
    logo_url: str = ""
    support_email: str = ""
    updated_at: Optional[int] = None
    updated_by: Optional[str] = None
```

Note the field is named `platform_name` (not `name`) so `BrandingOut.platform_name` matches the merge-tag and the consumer specs' `get_branding().platform_name` accessor. The service maps the stored DDB `name` attribute → `platform_name`.

**`BrandingUpdateIn`** — PUT payload; all fields optional (partial update):

```python
class BrandingUpdateIn(BaseModel):
    name: Optional[str] = None            # writes the row "name" attribute
    logo_url: Optional[str] = None
    support_email: Optional[str] = None
```

`name` is the input key (matches the stored attribute and the D6 `{name, logo_url, support_email}` shape); the output key is `platform_name` (the merge-tag name). This asymmetry is intentional and documented in §10.

---

## 4. API / Service Design

### 4.1 Settings additions (`app/core/settings.py`)

Add a new `# Platform branding (BRAND-001)` group, following the `os.environ.get(...)` idiom used throughout the file (e.g. `public_base_url` at `:349`, the `billing_config_*` block at `:2625–2631`):

```python
# Platform branding (BRAND-001 / decision D6). Env values are the DEFAULTS;
# the PLATFORM#BRANDING settings row overrides them at runtime when set.
platform_name: str = os.environ.get("PLATFORM_NAME", "testlogon")
platform_logo_url: str = os.environ.get("PLATFORM_LOGO_URL", "")
platform_support_email: str = os.environ.get("PLATFORM_SUPPORT_EMAIL", "")
platform_settings_table_name: str = os.environ.get("PLATFORM_SETTINGS_TABLE_NAME", "platform_settings")
branding_cache_ttl_seconds: int = int(os.environ.get("BRANDING_CACHE_TTL_SECONDS", "60"))
```

`S` (`Settings`) is `@dataclass(frozen=True)` (`app/core/settings.py:6`), so tests toggle these via `object.__setattr__` (§9.1).

### 4.2 Table handle additions

**`app/core/tables.py`** — add to the `Tables` dataclass (`@dataclass(frozen=True)` at `:68`), after the last existing field:

```python
platform_settings: Any
```

Wire in the `T = Tables(...)` initializer (after the last existing wire, e.g. near `:542`), using the `_safe_table(...)` helper (`tables.py:65`):

```python
platform_settings=_safe_table(S.platform_settings_table_name),
```

### 4.3 Service: `app/services/branding.py` (new file)

Modeled directly on `app/services/billing_config.py:46–278` (cache + env-fallback + DDB read). **No `if S.dev_mode` branch anywhere** — SECOPS-007.

**Module-level constants + cache**

```python
from typing import Any, Dict, Optional
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_PK = "PLATFORM"
_SK = "BRANDING"

_cache: Optional[Dict[str, Any]] = None
_cache_ts: int = 0


def _cache_ttl() -> int:
    return int(getattr(S, "branding_cache_ttl_seconds", 60) or 60)


def _defaults() -> Dict[str, Any]:
    return {
        "platform_name": getattr(S, "platform_name", "") or "testlogon",
        "name": getattr(S, "platform_name", "") or "testlogon",   # alias for callers using ["name"]
        "logo_url": getattr(S, "platform_logo_url", "") or "",
        "support_email": getattr(S, "platform_support_email", "") or "",
        "updated_at": None,
        "updated_by": None,
    }


def invalidate_cache() -> None:
    global _cache, _cache_ts
    _cache = None
    _cache_ts = 0
```

**`get_branding`** — never raises; always returns at least the env defaults:

```python
def get_branding() -> Dict[str, Any]:
    """Return effective branding (DDB override-or-env-default). Cached, never raises."""
    global _cache, _cache_ts
    now = now_ts()
    if _cache is not None and (now - _cache_ts) < _cache_ttl():
        return dict(_cache)

    out = _defaults()
    try:
        resp = T.platform_settings.get_item(Key={"pk": _PK, "sk": _SK})
        item = resp.get("Item")
    except Exception:
        item = None  # defensive: any DDB error → env defaults, no raise

    if item:
        nm = item.get("name")
        if nm:
            out["name"] = nm
            out["platform_name"] = nm
        if item.get("logo_url") is not None:
            out["logo_url"] = item["logo_url"]
        if item.get("support_email") is not None:
            out["support_email"] = item["support_email"]
        if item.get("updated_at") is not None:
            out["updated_at"] = int(item["updated_at"])
        out["updated_by"] = item.get("updated_by")

    _cache = dict(out)
    _cache_ts = now
    return out
```

Contract: `get_branding()` **NEVER raises** — a missing table, a DDB outage, or a malformed row all collapse to the env defaults. This guarantees `{{platform_name}}` always resolves and `_send_autoresponder` / template rendering can never `AttributeError` (the explicit requirement in `docs/suitecrm/specs/CMP-006.md:272`).

**`set_branding`** — partial update, root-actor-attributed:

```python
def set_branding(
    *,
    name: Optional[str] = None,
    logo_url: Optional[str] = None,
    support_email: Optional[str] = None,
    actor_sub: str,
) -> Dict[str, Any]:
    """Upsert the PLATFORM#BRANDING row with only the provided fields. Returns get_branding()."""
    expr_set = ["updated_at = :ua", "updated_by = :ub"]
    vals: Dict[str, Any] = {":ua": now_ts(), ":ub": actor_sub or "system"}
    if name is not None:
        expr_set.append("#nm = :nm"); vals[":nm"] = name
    if logo_url is not None:
        expr_set.append("logo_url = :lu"); vals[":lu"] = logo_url
    if support_email is not None:
        expr_set.append("support_email = :se"); vals[":se"] = support_email

    T.platform_settings.update_item(
        Key={"pk": _PK, "sk": _SK},
        UpdateExpression="SET " + ", ".join(expr_set),
        ExpressionAttributeNames={"#nm": "name"},     # 'name' is a DDB reserved word
        ExpressionAttributeValues=vals,
    )
    invalidate_cache()
    _audit("branding.updated", actor_sub, fields=[k for k in ("name","logo_url","support_email")
                                                  if locals().get(k) is not None])
    return get_branding()
```

`update_item` performs an upsert (creates the row if absent). `name` is a DynamoDB reserved word, so it is aliased via `ExpressionAttributeNames` (`#nm`). After write, the cache is invalidated so the next `get_branding()` reflects the change immediately. A best-effort `_audit(...)` wrapper (lazy-import of `app.services.alerts.audit_event`, `try/except` swallow — same shape as `app/services/inventory.py:92–98`) records `branding.updated`.

### 4.4 Router: `app/routers/branding.py` (new file)

```python
from fastapi import APIRouter, Depends, Request
from app.auth.policy import require_admin_or_root, require_root, enforce_cookie_csrf
from app.auth.deps import AuthenticatedUser  # type hint
from app.models import BrandingOut, BrandingUpdateIn
from app.services import branding as branding_svc

router = APIRouter(prefix="/ui/admin", tags=["branding"])


@router.get("/branding", response_model=BrandingOut)
async def get_branding_endpoint(user=Depends(require_admin_or_root)):
    b = branding_svc.get_branding()
    return BrandingOut(
        platform_name=b["platform_name"], logo_url=b["logo_url"],
        support_email=b["support_email"], updated_at=b["updated_at"], updated_by=b["updated_by"],
    )


@router.put("/branding", response_model=BrandingOut)
async def put_branding_endpoint(
    body: BrandingUpdateIn, request: Request, user=Depends(require_root),
):
    enforce_cookie_csrf(request)
    b = branding_svc.set_branding(
        name=body.name, logo_url=body.logo_url,
        support_email=body.support_email, actor_sub=user.sub,
    )
    return BrandingOut(
        platform_name=b["platform_name"], logo_url=b["logo_url"],
        support_email=b["support_email"], updated_at=b["updated_at"], updated_by=b["updated_by"],
    )
```

- **GET** uses `require_admin_or_root` (`app/auth/policy.py:67`) — admins may read branding (e.g. to render it in the admin shell). No CSRF (safe method).
- **PUT** uses `require_root` (`app/auth/policy.py:63`) — **ROOT only** per D6 — plus an explicit `enforce_cookie_csrf(request)` (`app/auth/policy.py:71–97`) for cookie-auth mutation CSRF, mirroring `require_admin_or_root_csrf` (`:100–106`).

### 4.5 Registration (`app/main.py`)

Add the import next to the other admin router imports (near `app/main.py:74–77`):

```python
from app.routers.branding import router as branding_router
```

Register it inside `create_app()` next to the other `include_router` calls (e.g. near the admin block at `app/main.py:962`):

```python
app.include_router(branding_router)
```

### 4.6 Consumer migration (referenced, not owned by BRAND-001)

CMP-006 and CMP-008 already specify their own migration to `get_branding()` (`docs/suitecrm/specs/CMP-006.md:266`, `docs/suitecrm/specs/CMP-008.md:165`). BRAND-001 ships the entity + helper they import; it does **not** modify `notification_templates.py` itself (that service supplies merge-vars from caller-passed `sample_vars` — the caller is responsible for injecting `platform_name=get_branding()["platform_name"]`). A one-line follow-up in any template-send call site that wants live branding is `sample_vars.setdefault("platform_name", get_branding()["platform_name"])`; this is enumerated in §11 as a downstream consumer task, not a BRAND-001 deliverable.

---

## 5. Detailed Behavior & Edge Cases

### 5.1 Empty table → env defaults

When the `platform_settings` table has no `PLATFORM#BRANDING` row (fresh install, or never edited), `get_branding()` returns the env-default-backed dict: `{"platform_name": "testlogon", "name": "testlogon", "logo_url": "", "support_email": "", "updated_at": None, "updated_by": None}`. No error.

### 5.2 DDB outage / missing table → env defaults (never raises)

The `get_item` is wrapped in `try/except Exception` that sets `item = None`. A throttle, a deleted table, or a credentials error all collapse to env defaults. This is the load-bearing guarantee for `{{platform_name}}` rendering — see `docs/suitecrm/specs/CMP-006.md:272` ("`get_branding()` falls back to the env default, so `_send_autoresponder` never raises").

### 5.3 Partial update preserves untouched fields

`set_branding(name="Acme")` writes only `name` (+ `updated_at`/`updated_by`); `logo_url` and `support_email` on the row are untouched. `update_item` is an upsert, so the first `set_branding` ever called creates the row with just the provided field(s); unset fields fall through to env defaults on read.

### 5.4 `name` is a DDB reserved word

`name` collides with a DynamoDB reserved keyword in `UpdateExpression`. `set_branding` aliases it via `ExpressionAttributeNames={"#nm": "name"}`. Omitting this raises `ValidationException: Attribute name is a reserved keyword` at runtime — covered by test case 6 (§9.1).

### 5.5 Cache TTL and read-your-writes

`get_branding()` caches for `branding_cache_ttl_seconds` (default 60s). `set_branding` calls `invalidate_cache()` after a successful write, so a `get_branding()` immediately after a `PUT` within the same process reflects the change (read-your-writes). Across processes (multi-instance prod), other instances see the change after their cache TTL expires (≤60s) — acceptable for branding, which changes rarely. The cache is process-local module state (same as `billing_config._config_cache`).

### 5.6 Numeric `updated_at` Decimal coercion

`updated_at` is stored as DDB `N` and returned by boto3 as `Decimal`. `get_branding` coerces with `int(item["updated_at"])` before returning. `BrandingOut.updated_at: Optional[int]` would coerce a `Decimal` automatically, but the service coerces eagerly so dict consumers get a plain `int`.

### 5.7 Empty-string vs None for `logo_url` / `support_email`

A caller may set `logo_url=""` to deliberately clear the logo. `set_branding` writes the empty string (since `logo_url is not None`); `get_branding` returns `""`. To leave a field unchanged, the caller passes `None` (the field is omitted from the `UpdateExpression`). DynamoDB **can** store an empty string (unlike empty Map values), so `""` round-trips correctly.

### 5.8 PUT with empty body

`BrandingUpdateIn()` with all `None` fields still bumps `updated_at`/`updated_by` (the two unconditional `SET` clauses). This is intentional — it lets a root user "touch" the branding row. An alternative (422 on empty body) is documented in §10.

### 5.9 Authorization boundaries

- A USER calling `GET /ui/admin/branding` → 403 (`require_admin_or_root`).
- An ADMIN calling `GET` → 200 (admins may read).
- An ADMIN calling `PUT` → 403 (`require_root` — root only).
- A ROOT calling `PUT` without a CSRF token (cookie auth) → 403 (`enforce_cookie_csrf`).
- A ROOT calling `PUT` with a valid Bearer token (no session cookie) → CSRF skipped (`enforce_cookie_csrf` returns early when no session cookie — `policy.py:87–89`).

### 5.10 `platform_name` vs `name` key parity

The dict returned by `get_branding()` carries **both** `name` and `platform_name` keys with the same value, so consumers using either `get_branding()["name"]` or `get_branding()["platform_name"]` (or the `BrandingOut.platform_name` attribute) all work. This is the bridge between the D6 storage shape (`{name, ...}`) and the merge-tag name (`{{platform_name}}`).

---

## 6. Feature Flag & Config

### 6.1 No vertical master flag — by design

Unlike vertical features (PROP `PROPERTY_MGMT_ENABLED`, QloApps `HOTEL_PMS_ENABLED`, etc. — `docs/CROSS_TICKET_AUDIT.md §A5`), branding is **platform infrastructure** and has **no `BRANDING_ENABLED` flag** and no `_require_enabled()` 404 gate. Rationale:

1. Branding must **always** be available — `{{platform_name}}` rendering happens on the welcome email, password-reset, and SMS alert paths (`notification_templates.py:38,50,72`), which are core platform flows that exist regardless of any vertical.
2. Safe-by-default is achieved through the **env fallback**, not a kill switch: with no DDB row, `get_branding()` returns the `PLATFORM_NAME` env default. There is nothing to "disable."
3. This is the single intentional departure from the §A5 404-gate convention; it is consistent with how `billing_config` (also platform-core config) has no master flag — it has a `billing_config_ddb_enabled` toggle for the *DDB read* only, not a feature gate. BRAND-001 could optionally add an analogous `branding_ddb_enabled` toggle, but the `try/except` env-fallback already makes the DDB read non-load-bearing, so it is omitted (§10).

### 6.2 Config keys

| Setting key | Env var | Default | Purpose |
|---|---|---|---|
| `platform_name` | `PLATFORM_NAME` | `"testlogon"` | Default platform display name; `{{platform_name}}` source |
| `platform_logo_url` | `PLATFORM_LOGO_URL` | `""` | Default logo URL |
| `platform_support_email` | `PLATFORM_SUPPORT_EMAIL` | `""` | Default support contact email |
| `platform_settings_table_name` | `PLATFORM_SETTINGS_TABLE_NAME` | `"platform_settings"` | Table name |
| `branding_cache_ttl_seconds` | `BRANDING_CACHE_TTL_SECONDS` | `60` | In-memory cache TTL |

### 6.3 `.env.local.example`

Add:

```
PLATFORM_NAME=testlogon
PLATFORM_LOGO_URL=
PLATFORM_SUPPORT_EMAIL=
PLATFORM_SETTINGS_TABLE_NAME=platform_settings
BRANDING_CACHE_TTL_SECONDS=60
```

---

## 7. Dev/Prod Parity (SECOPS-007), Idempotency, Security & Money-safety

### 7.1 SECOPS-007 — zero `dev_mode` branches

`app/services/branding.py` and `app/routers/branding.py` contain **no** `if S.dev_mode` branches. The same `T.platform_settings.get_item` / `update_item` code path runs in dev (boto3 intercepted by moto in-process) and prod (real DynamoDB), exactly like `billing_config.py`. The env fallback is not a dev/prod fork — it is the same fallback in both environments.

### 7.2 Idempotency

`set_branding` is idempotent in result: calling it twice with the same payload produces the same final row state (the only diff is `updated_at`). It is an `update_item` upsert, so it is safe to retry. `get_branding` is a pure read (cache + DDB), trivially idempotent.

### 7.3 Security — root-only writes, admin-read

- **Writes** are gated by `require_root` (`policy.py:63`) — only ROOT may change platform branding, per D6.
- **Reads** are gated by `require_admin_or_root` (`policy.py:67`).
- **CSRF** is enforced on the PUT for cookie-auth via `enforce_cookie_csrf` (`policy.py:71–97`).
- **No injection surface**: `name`/`logo_url`/`support_email` are stored and returned as plain strings. They are NOT interpreted as templates by BRAND-001. When a consumer renders `{{platform_name}}` into HTML email, that consumer is responsible for HTML-escaping the value if it could be attacker-influenced — but only ROOT can set it, so the trust boundary is high. (Note for consumers: `_render` in `notification_templates.py:245` does plain string substitution with no auto-escaping; a root-set `name` containing HTML would be injected verbatim. Acceptable given root-only writes; flagged in §10.)
- **Audit**: every write emits `branding.updated` via the best-effort `_audit` wrapper.

### 7.4 Money-safety

BRAND-001 touches **no** billing table, ledger entry, or payment primitive. It does not import `billing_shared` or any provider SDK. There are no financial invariants in scope. (Explicitly distinct from `billing_config`, which *does* hold money parameters; branding is name/logo/email only.)

---

## 8. Backward Compatibility & Migration

### 8.1 Additive-only changes

BRAND-001 adds:
- Five new settings keys to `app/core/settings.py` (additive).
- One new field to the `Tables` dataclass + one new wire in `T = Tables(...)` (`app/core/tables.py`) (additive).
- One new `TableDef` in `scripts/local-ddb-init.py` (additive).
- One new service file `app/services/branding.py` (additive).
- One new router file `app/routers/branding.py` + one import + one `include_router` in `app/main.py` (additive).
- Two new Pydantic models (`BrandingOut`, `BrandingUpdateIn`) in `app/models.py` (additive — no existing model named `Branding*` exists).

No existing file is modified in a breaking way. No existing endpoint, service, table, or model is altered. Notably, `notification_templates.py` is **not** changed by BRAND-001 — `{{platform_name}}` already rendered as an unresolved (passed-through) merge tag before; after BRAND-001 the *consumers* (CMP-006/008, per their own specs) inject the resolved value.

### 8.2 Table creation in dev

`just restart` runs `scripts/local-ddb-init.py` → `_table_defs()` → creates `platform_settings` automatically. No manual migration in dev.

### 8.3 Production deployment

Create the `platform_settings` table (empty) via `CreateTable` before/with deploy. Because `get_branding()` falls back to env defaults when the row/table is absent, the code is safe to deploy before the table exists (it will use `PLATFORM_NAME` env) — though creating the table first is cleaner. No data migration needed; the row is created lazily on the first `PUT`.

### 8.4 Rollback

Revert the five file changes (settings, tables, local-ddb-init, branding.py service, branding.py router, models.py, main.py registration) and optionally drop `platform_settings`. Because consumers fall back to env defaults via `get_branding()` (and pre-BRAND-001 they had no value at all), a partial rollback that keeps the env defaults but removes the DDB row is safe. NOTE: rolling back BRAND-001 while CMP-006/008 are deployed would break their `from app.services.branding import get_branding` import — so BRAND-001 must not be rolled back independently of its consumers.

---

## 9. Test Plan

### 9.1 Hermetic pytest — `tests/test_brand_001_branding.py`

Tests run **offline** — no live stack, no real AWS, no `TestClient`. Pattern: moto-backed `platform_settings` table bound to the frozen `T.platform_settings` handle via `object.__setattr__`; frozen `S` env defaults toggled via `object.__setattr__`; route coroutines called directly on a fresh `asyncio.new_event_loop()`. Same hermetic approach as `tests/test_gap_0265_0266_kyc_risk_scoring.py` and the §9.1 pattern in `docs/open-property/specs/PROP-001.md`.

**Setup block**

```python
import asyncio, boto3, pytest
from moto import mock_aws
from types import SimpleNamespace
from unittest.mock import patch

@pytest.fixture(autouse=True)
def setup_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="platform_settings",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        from app.core import tables as T_mod
        from app.services import branding as svc
        object.__setattr__(T_mod.T, "platform_settings", table)
        object.__setattr__(svc.S, "platform_name", "testlogon")
        object.__setattr__(svc.S, "platform_logo_url", "")
        object.__setattr__(svc.S, "platform_support_email", "")
        object.__setattr__(svc.S, "branding_cache_ttl_seconds", 60)
        svc.invalidate_cache()
        yield table
        svc.invalidate_cache()
```

**Test cases**

1. **Empty table → env defaults**: `get_branding()` returns `platform_name="testlogon"`, `logo_url=""`, `support_email=""`, `updated_at=None`. No exception.
2. **`get_branding` never raises on DDB error**: monkeypatch `T.platform_settings.get_item` to raise; assert `get_branding()` still returns env defaults (no propagation).
3. **`set_branding` creates the row**: `set_branding(name="Acme Co", actor_sub="root1")`; assert returned dict has `platform_name="Acme Co"`, `name="Acme Co"`, `updated_by="root1"`, integer `updated_at`.
4. **Partial update preserves fields**: after case 3, `set_branding(logo_url="https://x/logo.png", actor_sub="root1")`; assert `platform_name` is still `"Acme Co"` and `logo_url` is the new URL.
5. **Read-your-writes (cache invalidation)**: `get_branding()` (warm cache), then `set_branding(name="New", actor_sub="r")`, then `get_branding()` returns `"New"` immediately (cache was invalidated).
6. **`name` reserved-word aliasing**: `set_branding(name="X", actor_sub="r")` succeeds (no `ValidationException`) — proves `ExpressionAttributeNames={"#nm":"name"}` is applied.
7. **Empty-string clears logo**: set a logo, then `set_branding(logo_url="", actor_sub="r")`; assert `get_branding()["logo_url"] == ""`.
8. **Decimal coercion**: after a write, assert `isinstance(get_branding()["updated_at"], int)`.
9. **`platform_name`/`name` parity**: assert `get_branding()["name"] == get_branding()["platform_name"]`.
10. **Router GET — admin allowed**: call `get_branding_endpoint` coroutine with a stub ADMIN user on a fresh loop; assert 200-shaped `BrandingOut`.
11. **Router PUT — root only**: call `put_branding_endpoint` with `BrandingUpdateIn(name="Z")` + a stub ROOT user (with `enforce_cookie_csrf` patched to no-op or a stub request carrying matching CSRF cookie/header); assert the row is written and `BrandingOut.platform_name == "Z"`. (Role enforcement itself is exercised by `require_root`'s own tests; this test drives the handler body.)
12. **Cache TTL expiry**: set `branding_cache_ttl_seconds=0`, write directly to the table out-of-band, assert next `get_branding()` reflects it (cache always stale).

### 9.2 E2E tests — `frontend/e2e/branding.spec.ts` (optional follow-up)

Not a BRAND-001 hard deliverable. If added: `injectAuth(page, "root")` for the PUT (CSRF header required), `injectAuth(page, "charlie_admin")` for the GET (200), and a USER session asserting 403 on GET. Uses the cookie-auth + `x-csrf-token` pattern documented in CLAUDE.md.

---

## 10. Open Questions / Assumptions

1. **Table choice (RESOLVED).** A new `platform_settings` table is chosen over reusing `billing_config`/`cart_reminder_config` — see §3.1. Justification: branding is a platform-singleton, semantically distinct from billing/cart config, and `platform_settings` is the natural home for future platform-wide singletons. **Assumption**: a dedicated tiny table is acceptable (negligible cost).

2. **`name` (input) vs `platform_name` (output) key asymmetry.** `BrandingUpdateIn.name` writes the row's `name` attribute (matching D6's `{name, ...}` shape); `BrandingOut.platform_name` and the dict's `platform_name` key expose it under the merge-tag name. **Assumption**: this is clearer than renaming the merge tag; both keys coexist in the dict so no consumer breaks. An alternative (use `name` everywhere, alias the merge tag) is rejected because CMP-006/008 already call `get_branding().platform_name`.

3. **No `BRANDING_ENABLED` flag (RESOLVED).** Branding is platform infra, always available, safe-by-default via env fallback — §6.1. **Decision**: no master flag, no 404 gate. This is the one intentional §A5 departure.

4. **No `branding_ddb_enabled` toggle.** `billing_config` has `billing_config_ddb_enabled` to skip the DDB read; BRAND-001 omits the analogue because the `try/except` env-fallback already makes the read non-load-bearing. **Assumption**: not needed; can be added later if a "force env only" mode is wanted.

5. **PUT with empty body bumps `updated_at`.** §5.8 — silent touch rather than 422. **Assumption**: callers driving the router send at least one field; the touch behavior is harmless.

6. **HTML-escaping of branding values in email.** `notification_templates._render` (`:245`) does plain substitution with no escaping. A root-set `name` with HTML would render verbatim. **Assumption**: acceptable given root-only writes (high trust). If branding ever becomes admin- or self-service-editable, consumers must escape — flagged for the consumer specs, not BRAND-001.

7. **`logo_url` validation.** Stored as a free-text string; no URL-format validation. **Assumption**: root users supply valid URLs; add a Pydantic `HttpUrl` validator later if needed (would reject empty-string clears, so deferred).

8. **Multi-instance cache staleness.** Up to `branding_cache_ttl_seconds` (60s) of staleness across processes after a PUT. **Assumption**: acceptable for branding (changes rarely); same model as `billing_config`.

---

## 11. Dependencies

### 11.1 BRAND-001 dependencies (none — foundational platform infra)

BRAND-001 has no upstream ticket dependency. It reuses only already-live primitives.

### 11.2 Downstream consumers depending on BRAND-001

| Consumer | Depends on BRAND-001 for |
|---|---|
| **CMP-006** (web-to-lead auto-responder) | `from app.services.branding import get_branding`; `{{platform_name}}` ← `get_branding().platform_name` (`docs/suitecrm/specs/CMP-006.md:266,275,428–433`); supersedes the bespoke `web_to_lead_platform_name` setting |
| **CMP-008** (campaign merge-tag personalisation) | `from app.services.branding import get_branding` (`docs/suitecrm/specs/CMP-008.md:165`); `{{platform_name}}` ← `get_branding().platform_name` |
| **notification_templates send call sites** (ADMIN-002) | injecting `sample_vars["platform_name"] = get_branding()["platform_name"]` so seeded templates (`notification_templates.py:38,50,72`) resolve `{{platform_name}}` — a one-line consumer-side change, NOT a BRAND-001 deliverable |
| **Future**: admin shell header, transactional email layouts, PDF receipt headers | `get_branding()["name"]` / `["logo_url"]` |

### 11.3 Reused primitives (no forking)

| Primitive | Source | Reuse in BRAND-001 |
|---|---|---|
| Cached settings-row + env-fallback pattern | `app/services/billing_config.py:46–278` | `get_branding()` cache/fallback shape copied |
| `invalidate_cache()` on write | `app/services/billing_config.py:54–58` | `branding.invalidate_cache()` |
| Generic `pk`/`sk` settings table | `scripts/local-ddb-init.py:78` (billing_config) | `platform_settings` TableDef |
| `TableDef(...)` idiom | `scripts/local-ddb-init.py:28–36` | `platform_settings` definition |
| `_safe_table(...)` | `app/core/tables.py:65` | `T.platform_settings` wire |
| `os.environ.get(...)` settings idiom | `app/core/settings.py:349,2625–2631` | five branding settings |
| `now_ts()` | `app/core/time.py:2` | `updated_at` |
| `require_root` | `app/auth/policy.py:63` | PUT auth (root only) |
| `require_admin_or_root` | `app/auth/policy.py:67` | GET auth |
| `enforce_cookie_csrf` | `app/auth/policy.py:71–97` | PUT CSRF |
| `_audit()` lazy-import wrapper | `app/services/inventory.py:92–98` | `branding.updated` audit |
| `audit_event` | `app/services/alerts.py:644` (via `_audit`) | audit sink |
| `include_router` registration | `app/main.py:962` (admin block) | `branding_router` mount |

### 11.4 Cross-ticket reconciliation

Per `docs/CROSS_TICKET_AUDIT.md §D6` and §B1 row 2: BRAND-001 is the "small dedicated branding ticket" both CMP-006 (`:428–433`) and CMP-008 (`:25–34`) reference. It owns the `PLATFORM#BRANDING` entity, the `get_branding()` helper, and the `/ui/admin/branding` router; CMP-006's `web_to_lead_platform_name` setting is superseded by it (do NOT add — `docs/suitecrm/specs/CMP-006.md:426`).

---

## 12. Verification Log

Each claim was cross-checked against the live codebase in a second pass. Evidence is cited `file:line`.

| # | Claim | Status | Evidence |
|---|---|---|---|
| 1 | D6 decision exists: `PLATFORM#BRANDING` row, `GET/PUT /ui/admin/branding` root-only, env defaults, cached `get_branding()` | **VERIFIED** | `docs/CROSS_TICKET_AUDIT.md:274–279` (§D6) |
| 2 | §B1 row 2 flags `{{platform_name}}`/`S.platform_name` gap as unowned | **VERIFIED** | `docs/CROSS_TICKET_AUDIT.md:157` |
| 3 | No `platform_name`/`PLATFORM_NAME` setting exists | **VERIFIED** | `grep -n "platform_name\|PLATFORM_NAME" app/core/settings.py` → empty |
| 4 | No `platform_settings` table / `branding` handle exists | **VERIFIED** | `grep -in "platform_settings\|branding" app/core/tables.py scripts/local-ddb-init.py` → empty |
| 5 | `app/services/branding.py` does not exist | **VERIFIED** | `ls app/services/branding.py` → absent (only referenced by CMP specs as a forward dep) |
| 6 | `{{platform_name}}` used in seeded templates at the cited lines | **VERIFIED** | `app/services/notification_templates.py:38,41,50,72` (exact) |
| 7 | `_render` substitutes `{{var}}` from `sample_vars`, records missing, no default pull | **VERIFIED** | `app/services/notification_templates.py:245–260` (esp. `:255–257`) |
| 8 | `preview_template` calls `_render(tpl.get("subject"/"body"), sample_vars)` | **VERIFIED** | `app/services/notification_templates.py:272–273` |
| 9 | `billing_config` cached-settings-row precedent: cache vars, `_cache_ttl`, `get_billing_config`, `invalidate_cache` | **VERIFIED** | `app/services/billing_config.py:46–47,50–51,54–58,236–278` |
| 10 | `billing_config` falls back to defaults on DDB error inside try/except | **VERIFIED** | `app/services/billing_config.py:250–255` |
| 11 | `billing_config` is its own `pk`/`sk` table (not crammed into `billing`) | **VERIFIED** | `scripts/local-ddb-init.py:78`; `billing` table separate at `:67–77` |
| 12 | `billing_config_table_name` / `billing_config_ddb_enabled` settings | **VERIFIED** | `app/core/settings.py:2625–2630` |
| 13 | `TableDef` dataclass + `attr_types` comment | **VERIFIED** | `scripts/local-ddb-init.py:28–36`, comment `:34` |
| 14 | `_resolve_table_name` helper | **VERIFIED** | `scripts/local-ddb-init.py:38–39` |
| 15 | `_safe_table(...)` helper at `:65`; `Tables` `@dataclass(frozen=True)` at `:68` | **VERIFIED** | `app/core/tables.py:65,68` |
| 16 | `T = Tables(...)` wires use `_safe_table(S.<name>)`; wires run through ~`:542` | **VERIFIED** | `app/core/tables.py:322–328,530–542` |
| 17 | `require_root` = `require_roles(user, {Role.ROOT})` at policy.py:63–64 | **VERIFIED** | `app/auth/policy.py:63–64` (exact) |
| 18 | `require_admin_or_root` at policy.py:67–68 | **VERIFIED** | `app/auth/policy.py:67–68` (exact) |
| 19 | `enforce_cookie_csrf` at policy.py:71–97; returns early when no session cookie | **VERIFIED** | `app/auth/policy.py:71–97`, early return `:87–89` |
| 20 | `require_admin_or_root_csrf` = `enforce_cookie_csrf` + role check at :100–106 | **VERIFIED** | `app/auth/policy.py:100–106` (exact) |
| 21 | `require_root_session` alternative exists at deps.py:308–313 (HTTP 403) | **VERIFIED** | `app/auth/deps.py:308–313` (exact) |
| 22 | `now_ts()` at `app/core/time.py:2` | **VERIFIED** | `app/core/time.py:2` |
| 23 | `_audit()` lazy-import wrapper shape at inventory.py:92–98 | **VERIFIED** (referenced by PROP-001 §2.3) | `docs/open-property/specs/PROP-001.md:45–56` cites `app/services/inventory.py:92–98`; reused identically here |
| 24 | `audit_event(event, user_sub, request=None, **fields)` signature | **VERIFIED** | `docs/CROSS_TICKET_AUDIT.md:42` cites `app/services/alerts.py:644` |
| 25 | `Settings` is `@dataclass(frozen=True)` → `object.__setattr__` needed in tests | **VERIFIED** | `app/core/settings.py:6` |
| 26 | `os.environ.get(...)` settings idiom incl. `public_base_url` | **VERIFIED** | `app/core/settings.py:349` |
| 27 | CMP-006 consumes `get_branding().platform_name`, supersedes `web_to_lead_platform_name` | **VERIFIED** | `docs/suitecrm/specs/CMP-006.md:266,275,426,428–433,671–680` |
| 28 | CMP-006 requires `get_branding()` to never raise (`_send_autoresponder` never `AttributeError`) | **VERIFIED** | `docs/suitecrm/specs/CMP-006.md:272` |
| 29 | CMP-008 imports `from app.services.branding import get_branding` and uses `get_branding().platform_name` | **VERIFIED** | `docs/suitecrm/specs/CMP-008.md:25–34,152,165` |
| 30 | `include_router` admin block / registration site in main.py | **VERIFIED** | `app/main.py:962` (admin/invoices block); admin router imports `:74–77` |
| 31 | `name` is a DynamoDB reserved word → `ExpressionAttributeNames` alias required | **VERIFIED** (known DDB reserved-words list; AWS canonical) | DynamoDB reserved-words: `NAME` is reserved; `update_item` `SET name=` raises `ValidationException` without `#alias` — standard DDB behavior, exercised by test case 6 |
| 32 | moto API is `from moto import mock_aws` (not `mock_dynamodb`) | **VERIFIED** | `docs/open-property/specs/PROP-001.md:615` (item 30) confirms installed moto has no `mock_dynamodb`; all tests use `mock_aws` |
| 33 | Hermetic test pattern (frozen `T`/`S` via `object.__setattr__`, no TestClient, fresh asyncio loop) is the established corpus pattern | **VERIFIED** | `docs/open-property/specs/PROP-001.md:434` cites `tests/test_gap_0265_0266_kyc_risk_scoring.py` et al. |
| 34 | No existing `Branding*` Pydantic model collides | **VERIFIED** | `grep -n "class Branding" app/models.py` → empty (additive) |
| 35 | `billing_config` semantically billing-scoped (fee bps, payout min, currency, tax) — wrong home for branding | **VERIFIED** | `app/core/settings.py:2622–2624` (FIN-018 comment) |

**Summary**: 35 claims checked; all **VERIFIED** against the live codebase or the cited corpus specs. Item 31 (DDB `name` reserved word) is grounded in standard DynamoDB semantics and made testable (test case 6) rather than in a repo line, but is a well-established AWS invariant. Item 23/24 reuse the `_audit`/`audit_event` lines already verified-exact in PROP-001's log against `app/services/inventory.py:92–98` and `app/services/alerts.py:644`. No corrections were required (the design was authored directly from the read source). **0 unconfirmed.**
