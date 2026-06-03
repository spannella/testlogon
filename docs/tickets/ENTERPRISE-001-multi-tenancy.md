# ENTERPRISE-001: Multi-Tenancy with Tenant Isolation

**Ticket**: ENTERPRISE-001
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform currently operates as a single-tenant system. Every user, conversation, file, billing record, and configuration setting shares the same global namespace. The `Settings` dataclass in `app/core/settings.py` reads all configuration from environment variables with no per-tenant override mechanism -- a single `S = Settings()` singleton on line 1400 governs every request. The DynamoDB partition key strategy (e.g., `pk=USER#{user_sub}` in `app/services/webhook_service.py` line 112, or `user_sub` as the primary key in `T.users`, `T.profile`, `T.billing`) assumes that user identifiers are globally unique but does not scope them to a tenant boundary.

This makes it impossible to sell the platform as a white-label SaaS offering where multiple independent organizations (tenants) each get their own branded experience, isolated data, and separate billing relationships. Enterprise customers require tenant-level data isolation for compliance (SOC 2, HIPAA), custom branding for their users, and the ability to run on custom domains/subdomains.

### 1.2 How It Works

1. A **root** administrator creates a new tenant via `POST /v1/admin/tenants` with a slug, display name, and custom domain configuration.
2. A DNS record (CNAME or A) is pointed at the platform, and the system provisions a TLS certificate via ACME (Let's Encrypt) or CloudFront.
3. When a request arrives, a **tenant resolution middleware** (inserted in `app/main.py`'s `create_app()` function, before the CORS middleware on line 273) inspects the `Host` header and resolves it to a tenant ID.
4. The resolved `tenant_id` is stored on `request.state.tenant_id` and made available to all downstream auth dependencies and service functions.
5. All DynamoDB partition keys are prefixed with `TENANT#{tenant_id}#` to guarantee data isolation at the storage layer.
6. Per-tenant branding (logo URL, primary color, favicon URL) is served via a `/ui/tenant/branding` endpoint and consumed by the React frontend's `ThemeProvider`.

### 1.3 Design Principles

- **Data isolation by default**: Every DynamoDB query includes the tenant prefix. Cross-tenant data access is impossible without root override.
- **Backward compatible**: The default tenant (`default`) is automatically assigned when no custom domain is configured, preserving all existing behavior.
- **Performance neutral**: Tenant resolution is a single DynamoDB `get_item` call cached in-memory with a 5-minute TTL. Hot path adds <1ms.
- **Branding is declarative**: Tenants upload their branding assets (logo, favicon, CSS overrides) via an admin panel. The frontend reads these at page load and applies them without code changes.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Root admin | As a root admin, I want to create a new tenant with a unique slug and custom domain. | POST creates tenant record; domain is resolvable after DNS propagation + TLS provisioning. |
| Root admin | As a root admin, I want to set branding (logo, colors, favicon) for a tenant. | PATCH updates branding fields; frontend renders the tenant's logo and primary color. |
| Tenant admin | As a tenant admin, I want to manage users within my tenant only. | User list endpoint returns only users belonging to my tenant; no cross-tenant leakage. |
| End user | As an end user on tenant-a.example.com, I should not see data from tenant-b. | All queries are scoped by tenant; DM conversations, files, feed posts isolated. |
| Root admin | As a root admin, I want to list all tenants and their subscription status. | GET returns paginated tenant list with member counts and billing status. |
| Tenant admin | As a tenant admin, I want to upload a custom logo and favicon for my tenant. | Upload endpoint stores files in S3 with tenant-scoped paths; branding endpoint returns new URLs. |
| End user | As an end user, I want to see my tenant's branding on the login page. | Login page fetches branding before rendering; shows tenant logo, colors, and company name. |
| Root admin | As a root admin, I want to suspend a misbehaving tenant. | PATCH sets status=suspended; all non-root requests to that tenant return 503. |

---

## 2. Current State Analysis

### 2.1 Settings Singleton (`app/core/settings.py`)

The entire application configuration is a frozen dataclass instantiated once at module import:

```python
# app/core/settings.py, lines 6-7
@dataclass(frozen=True)
class Settings:
    # AWS
    aws_region: str = os.environ.get("AWS_REGION", "us-east-1")
    ...
```
<!-- CORRECTED: was "line 7-8", actually line 7 (class Settings on line 7, no decorator) -->

And the singleton on line 1494:
<!-- CORRECTED: S = Settings() is at line 1494, not 1400 -->

```python
S = Settings()
```

Every service and router imports `S` directly:

```python
# app/core/settings.py imported throughout
from app.core.settings import S
```

There is no mechanism for per-tenant configuration overrides. Settings like `default_currency` (line 303), `security_csp_header` (line 250-253), `ui_cookie_secure` (line 92), and feature flags like `messaging_encrypted_messages_enabled` (line 1018) are global.
<!-- VERIFIED: app/core/settings.py — default_currency, security_csp_header, ui_cookie_secure, messaging_encrypted_messages_enabled all exist --> Multi-tenancy requires a `TenantSettings` layer that overlays tenant-specific values on top of the global `Settings`.

The frozen dataclass pattern means we cannot mutate `S` at runtime. Instead, `TenantSettings` wraps `S` and provides attribute access that first checks the tenant-specific override dict, then falls back to `S`:

```python
# app/core/tenant.py -- TenantSettings wrapper
class TenantSettings:
    """Per-request settings overlay. Falls back to global S for non-overridden fields."""

    __slots__ = ("_overrides", "_global")

    def __init__(self, overrides: dict[str, Any], global_settings: Settings):
        object.__setattr__(self, "_overrides", overrides)
        object.__setattr__(self, "_global", global_settings)

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_global"), name)

    def __repr__(self) -> str:
        return f"TenantSettings(overrides={object.__getattribute__(self, '_overrides')})"
```

### 2.2 Authentication Flow (`app/auth/deps.py`)

The `get_authenticated_user` function (line 184) resolves the user from the request but never considers a tenant context:
<!-- VERIFIED: app/auth/deps.py:184 — async def get_authenticated_user(request: Request) -> AuthenticatedUser -->

```python
# app/auth/deps.py, line 184
async def get_authenticated_user(request: Request) -> AuthenticatedUser:
```

The `AuthenticatedUser` dataclass (lines 125-129) contains `sub`, `role`, and `admin_profile` but no `tenant_id`:
<!-- CORRECTED: AuthenticatedUser is at line 126, not 125-129 -->

```python
# app/auth/deps.py, lines 125-129
@dataclass(frozen=True)
class AuthenticatedUser:
    sub: str
    role: Role = Role.USER
    admin_profile: AdminProfile = AdminProfile()
```

The cookie-based auth path (lines 211-232) decodes the JWT from `ui_access_token` and extracts `sub` and `role` but has no `tenant_id` claim. The token is signed with `ui_access_token_secret` (line 213), which is a global secret -- multi-tenancy may require per-tenant signing keys or a `tenant_id` claim in the JWT.
<!-- VERIFIED: app/auth/deps.py:211-232 — cookie path with HS256 decode; line 213 reads access_secret -->

The full authentication priority chain in `get_authenticated_user` is:

1. **API key principal** (lines 194-209): Resolves from `X-Api-Key` header via `T.api_keys`. API key records do not have a `tenant_id` field; they must be extended.
2. **Cookie-based path** (lines 211-232): Decodes `ui_access_token` HS256 JWT. Payload contains `sub`, `role`, `admin_profile`. Must add `tenant_id` claim.
3. **Cognito JWT Bearer token** (lines 234-248): Decodes RS256 token from `Authorization: Bearer`. Cognito tokens do not have tenant context; must cross-reference with tenant membership.
4. **Dev-mode fallbacks** (lines 250-270): `X-User-Sub` header (not `X-User-Id`) accepted only when Cognito is disabled AND `dev_mode=True`. Must also accept optional `X-Tenant-Id` header for dev convenience.
<!-- VERIFIED: app/auth/deps.py:194-270 — all four auth paths confirmed. CORRECTED: was "lines 195-209" for API key, actually starts line 194; was "X-User-Id", actually "x-user-sub" at line 254 -->

### 2.3 Middleware Registration (`app/main.py`)

Middleware is registered in `create_app()` starting at line 273:
<!-- VERIFIED: app/main.py:244 — create_app(); line 273 — CORSMiddleware; line 225 — _build_cors_options() -->

```python
# app/main.py, lines 273-278
app.add_middleware(CORSMiddleware, **_build_cors_options())
app.middleware("http")(rate_limit_middleware_factory())
app.middleware("http")(_api_usage_metering_middleware())
app.middleware("http")(_playback_entitlement_middleware())
if METRICS_ENABLED:
    app.middleware("http")(metrics_middleware)
```

The tenant resolution middleware must be inserted as the **outermost** middleware (registered last, since Starlette middleware runs in reverse registration order) so that `request.state.tenant_id` is set before CORS, rate limiting, and auth run. The `_build_cors_options()` function (line 225) reads `CORS_ALLOW_ORIGINS` from environment -- multi-tenancy requires per-tenant CORS origin lists.

The full middleware stack order (outermost to innermost) after multi-tenancy:

1. **TenantMiddleware** (new) -- resolves tenant, sets `request.state.tenant_id`, sets context var
2. **CORSMiddleware** -- must dynamically include tenant custom domains
3. **RateLimitMiddleware** -- must use tenant-scoped rate limit keys
4. **ApiUsageMeteringMiddleware** -- must tag usage by tenant
5. **PlaybackEntitlementMiddleware** -- unchanged
6. **MetricsMiddleware** -- must include `tenant_id` label

### 2.4 DynamoDB Partition Keys (`app/core/tables.py`)

The `Tables` dataclass (line 9) holds references to all DynamoDB tables. Table names come from `Settings`:
<!-- CORRECTED: Tables class is at line 10, not 9 -->

```python
# app/core/tables.py, lines 112-213
T = Tables(
    sessions=ddb.Table(S.ddb_sessions_table),
    users=ddb.Table(S.users_table_name),
    profile=ddb.Table(S.profile_table_name),
    billing=ddb.Table(S.billing_table_name),
    ...
)
```
<!-- CORRECTED: was "lines 112-180", actually lines 112-213 -->

Service code queries tables using partition keys like:

```python
# app/services/webhook_service.py, lines 111-113
item = {
    "pk": f"USER#{user_sub}",
    "sk": f"ENDPOINT#{endpoint_id}",
    ...
}
```
<!-- VERIFIED: app/services/webhook_service.py:111-113 — pk=USER#{user_sub}, sk=ENDPOINT#{endpoint_id} -->

And in the billing system:

```python
# app/services/billing_shared.py, line 16
def user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"
```
<!-- VERIFIED: app/services/billing_shared.py:16 — user_pk returns USER#{user_sub} -->

For tenant isolation, these must become `TENANT#{tenant_id}#USER#{user_sub}`. This is a pervasive change but can be implemented with a helper function that reads `tenant_id` from a thread-local or context variable.

A full inventory of PK patterns that need tenant-scoping:

| Table | Current PK Pattern | Tenant-scoped PK |
|-------|-------------------|-------------------|
| `users` | `user_sub` (bare) | Add `tenant_id` attribute + GSI |
| `profile` | `user_sub` (bare) | Add `tenant_id` attribute + GSI |
| `billing` | `USER#{user_sub}` | `TENANT#{tid}#USER#{user_sub}` |
| `webhook_endpoints` | `USER#{user_sub}` | `TENANT#{tid}#USER#{user_sub}` |
| `webhook_endpoints` | `EVENT#{type}` | `TENANT#{tid}#EVENT#{type}` |
| `alerts` | `user_sub` | Add `tenant_id` attribute |
| `sessions` | `user_sub` + `session_id` | Add `tenant_id` attribute |
| `calendar` | `calendar_id` | `TENANT#{tid}#CAL#{calendar_id}` |
| `contacts` | `user_sub` | `TENANT#{tid}#USER#{user_sub}` |
| `filemgr` | `USER#{user_sub}` | `TENANT#{tid}#USER#{user_sub}` |

### 2.5 Session System (`app/services/sessions.py`)

The `require_ui_session` dependency (line 283) loads sessions from `T.sessions` using `user_sub` + `session_id` as the composite key:
<!-- VERIFIED: app/services/sessions.py:283 — require_ui_session; line 330 — get_item with user_sub + session_id -->

```python
# app/services/sessions.py, line 330
it = T.sessions.get_item(Key={"user_sub": resolved_user_sub, "session_id": session_id}).get("Item")
```

Sessions are global -- a user authenticated on tenant-a could theoretically present their session cookie on tenant-b. The session record must include `tenant_id` and the middleware must validate that the session's tenant matches the resolved tenant from the hostname.

The session creation flow in `create_real_session()` (line 72) currently writes:

```python
{
    "user_sub": user_sub,
    "session_id": session_id,
    "csrf_token": csrf_token,
    "created_at": now,
    "last_seen_at": now,
    "ip": ip,
    "user_agent": user_agent,
    ...
}
```

This must be extended with `"tenant_id": tenant_id` sourced from the request context. The session TTL computation in `_session_ttl_seconds_for_user()` could also become tenant-aware (enterprise tenants may want shorter/longer session lifetimes).

### 2.6 Role System (`app/auth/roles.py`)

Roles are global (`Role.ROOT`, `Role.ADMIN`, `Role.USER` on lines 8-11). Multi-tenancy introduces **tenant admin** as a concept: an admin scoped to a single tenant. The existing `AdminScope` enum (lines 14-18) already supports scoped permissions:
<!-- VERIFIED: app/auth/roles.py:8-11 — Role enum; lines 14-18 — AdminScope enum -->

```python
# app/auth/roles.py, lines 14-18
class AdminScope(str, Enum):
    AUTH_SUPPORT = "auth_support"
    BILLING_SUPPORT = "billing_support"
    CONTENT_MODERATION = "content_moderation"
    CONTENT_MODERATION_SENIOR = "content_moderation_senior"
```

A new `TENANT_ADMIN` scope can be added alongside these, gating tenant management operations. The `admin_profile_has_scope()` function (line 118) already supports scope checking:
<!-- VERIFIED: app/auth/roles.py:118 — admin_profile_has_scope -->

```python
# app/auth/roles.py, line 118
def admin_profile_has_scope(profile: AdminProfile, scope: AdminScope | str) -> bool:
    normalized = normalize_admin_scope(scope)
    if normalized is None:
        return False
    if profile.type is AdminProfileType.GENERAL:
        return True
    return normalized in profile.scopes
```

General admins automatically have all scopes (including `TENANT_ADMIN`). Scoped admins must have `TENANT_ADMIN` explicitly granted to manage tenant settings. Root users bypass all scope checks.

### 2.7 File Manager (`app/routers/filemanager.py`, `app/services/filemanager.py`)

The file manager uses `USER#{user_sub}` as the file tree root PK. S3 paths follow the pattern `uploads/{user_sub}/{path}`. Multi-tenancy changes S3 paths to `uploads/{tenant_id}/{user_sub}/{path}` and DDB PKs to `TENANT#{tid}#USER#{user_sub}`. The `upload_file()`, `download_file()`, `list_children()`, and all dispatched variants in `app/services/filemanager.py` must accept the tenant context.

### 2.8 Messaging System

Conversations use `conversation_id` as PK in the messages table. The conversations table uses `user_sub` as the participant lookup key. Both must be scoped: `TENANT#{tid}#CONV#{conversation_id}` and `TENANT#{tid}#USER#{user_sub}`. Cross-tenant messaging is explicitly blocked -- a user on tenant-a cannot start a DM with a user on tenant-b.

---

## 3. Technical Design

### 3.1 Approach Evaluation

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| **A: Separate DDB tables per tenant** | Each tenant gets its own set of tables | Strongest isolation; simple partition keys | Provisioning complexity; 100+ tables per tenant; DDB account limits |
| **B: Shared tables with tenant-prefixed partition keys** | All tenants share tables; PK includes tenant ID | No provisioning overhead; efficient resource usage; no table limits | Requires careful PK construction; cross-tenant bugs if PK forgotten |
| **C: Separate AWS accounts per tenant** | Each tenant runs in its own AWS account | Maximum isolation | Extreme operational complexity; not viable for SaaS |

### 3.2 Recommended Approach: Shared Tables with Tenant Prefix (Option B)

This is the standard DynamoDB multi-tenancy pattern. It provides strong logical isolation while keeping operational complexity low. A `tenant_pk()` helper function ensures tenant prefixing is never forgotten.

### 3.3 Data Model

#### 3.3.1 Tenant Registry Table

**Table**: `tenants` (new)
**PK**: `tenant_id`
**SK**: (none -- single-item table)

```python
{
    "tenant_id": "acme-corp",
    "display_name": "Acme Corporation",
    "slug": "acme-corp",
    "status": "active",           # active | suspended | trial | deleted
    "plan": "enterprise",         # free | starter | enterprise
    "custom_domains": ["app.acme.com", "portal.acme.com"],
    "primary_domain": "app.acme.com",
    "branding": {
        "logo_url": "/static/uploads/tenants/acme-corp/logo.png",
        "favicon_url": "/static/uploads/tenants/acme-corp/favicon.ico",
        "primary_color": "#2563EB",
        "accent_color": "#7C3AED",
        "font_family": "Inter",
        "login_background_url": "",
        "login_message": "",
        "custom_css": "",
    },
    "settings_overrides": {
        "messaging_encrypted_messages_enabled": true,
        "default_currency": "eur",
    },
    "limits": {
        "max_members": 500,
        "max_storage_bytes": 107374182400,   # 100 GB
        "max_file_size_bytes": 104857600,     # 100 MB
        "max_api_keys_per_user": 5,
        "max_webhook_endpoints_per_user": 10,
    },
    "member_count": 142,
    "storage_used_bytes": 5368709120,
    "created_at": 1716883200,
    "updated_at": 1716883200,
    "created_by": "root.admin@testdev.local",
    "deleted_at": null,
    "suspended_at": null,
    "suspended_reason": null,
}
```

#### 3.3.2 Domain Lookup Table

**Table**: `tenant_domains` (new)
**PK**: `domain` (e.g., `app.acme.com`)
**SK**: `#TENANT`

```python
{
    "domain": "app.acme.com",
    "sk": "#TENANT",
    "tenant_id": "acme-corp",
    "tls_status": "active",       # pending | active | expired | error
    "tls_expires_at": 1748419200,
    "tls_certificate_arn": "arn:aws:acm:us-east-1:...",
    "dns_verification_cname": "_acme-challenge.app.acme.com",
    "dns_verification_value": "abc123.acm-validations.aws",
    "dns_verified_at": 1716883200,
    "created_at": 1716883200,
}
```

#### 3.3.3 Tenant Members Table

**Table**: `tenant_members` (new)
**PK**: `tenant_id`
**SK**: `user_sub`

```python
{
    "tenant_id": "acme-corp",
    "user_sub": "alice@acme.com",
    "role": "admin",              # owner | admin | member
    "status": "active",           # active | suspended | invited
    "invited_by": "root.admin@testdev.local",
    "joined_at": 1716883200,
    "last_active_at": 1716969600,
    "storage_used_bytes": 1073741824,
}
```

**GSI**: `user-tenant-index` (PK: `user_sub`, SK: `tenant_id`) -- allows listing all tenants a user belongs to.

#### 3.3.4 Tenant-Scoped Partition Key Helper

```python
# app/core/tenant.py (new)
from __future__ import annotations

import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Optional

from app.core.settings import S, Settings

_current_tenant: ContextVar[str] = ContextVar("current_tenant", default="default")

def set_current_tenant(tenant_id: str) -> None:
    _current_tenant.set(tenant_id)

def get_current_tenant() -> str:
    return _current_tenant.get()

def tenant_pk(entity_prefix: str, entity_id: str) -> str:
    """Build a tenant-scoped partition key.

    Example: tenant_pk("USER", "alice@test.local") -> "TENANT#acme-corp#USER#alice@test.local"

    When multi-tenancy is disabled (single-tenant mode), returns the legacy
    un-prefixed key for backward compatibility:
        tenant_pk("USER", "alice@test.local") -> "USER#alice@test.local"
    """
    if not S.multi_tenancy_enabled:
        return f"{entity_prefix}#{entity_id}"
    tenant = _current_tenant.get()
    return f"TENANT#{tenant}#{entity_prefix}#{entity_id}"

def tenant_pk_for(tenant_id: str, entity_prefix: str, entity_id: str) -> str:
    """Build a tenant-scoped partition key for a specific tenant (not the current one).

    Used for cross-tenant admin operations and migration scripts.
    """
    if not S.multi_tenancy_enabled:
        return f"{entity_prefix}#{entity_id}"
    return f"TENANT#{tenant_id}#{entity_prefix}#{entity_id}"


class TenantSettings:
    """Per-request settings overlay that checks tenant overrides before global S."""

    __slots__ = ("_overrides", "_global")

    def __init__(self, overrides: dict[str, Any], global_settings: Settings | None = None):
        object.__setattr__(self, "_overrides", overrides or {})
        object.__setattr__(self, "_global", global_settings or S)

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(object.__getattribute__(self, "_global"), name)

_current_tenant_settings: ContextVar[Optional[TenantSettings]] = ContextVar(
    "current_tenant_settings", default=None
)

def set_current_tenant_settings(ts: TenantSettings) -> None:
    _current_tenant_settings.set(ts)

def get_tenant_setting(name: str) -> Any:
    """Read a setting, checking tenant overrides first, then global S."""
    ts = _current_tenant_settings.get()
    if ts is not None:
        return getattr(ts, name)
    return getattr(S, name)
```

### 3.4 Tenant Resolution Middleware

```python
# app/middleware/tenant.py (new)
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.settings import S
from app.core.tenant import (
    TenantSettings,
    set_current_tenant,
    set_current_tenant_settings,
)

logger = logging.getLogger(__name__)

# In-memory domain -> tenant cache with per-entry TTL
_DOMAIN_CACHE: Dict[str, Dict[str, Any]] = {}  # {domain: {"tenant_id": ..., "fetched_at": ...}}


class TenantMiddleware(BaseHTTPMiddleware):
    """Resolve the tenant from the Host header and set request.state.tenant_id.

    Resolution order:
    1. X-Tenant-Id header (dev mode only, for testing convenience)
    2. Host header -> domain lookup cache -> DynamoDB tenant_domains table
    3. Fallback to "default" for localhost / unknown domains
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if not S.multi_tenancy_enabled:
            request.state.tenant_id = S.default_tenant_id
            set_current_tenant(S.default_tenant_id)
            return await call_next(request)

        # Dev mode shortcut
        if S.dev_mode and request.headers.get("x-tenant-id"):
            tenant_id = request.headers["x-tenant-id"]
        else:
            host = (request.headers.get("host") or "localhost").split(":")[0].lower()
            tenant_id, tenant_record = await self._resolve_tenant(host)

        request.state.tenant_id = tenant_id
        set_current_tenant(tenant_id)

        # Check tenant status
        if tenant_id != S.default_tenant_id:
            status = await self._get_tenant_status(tenant_id)
            if status == "suspended":
                # Root admin can still access suspended tenants
                is_root = request.headers.get("x-root-override") == S.root_user_sub
                if not is_root:
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "This tenant is currently suspended."},
                    )
            elif status == "deleted":
                return JSONResponse(
                    status_code=410,
                    content={"detail": "This tenant no longer exists."},
                )

        # Load tenant settings overrides
        overrides = await self._load_settings_overrides(tenant_id)
        if overrides:
            set_current_tenant_settings(TenantSettings(overrides))

        response = await call_next(request)
        return response

    async def _resolve_tenant(self, host: str) -> tuple[str, Optional[dict]]:
        """Resolve hostname to tenant_id with caching."""
        now = time.time()
        cache_ttl = S.tenant_domain_cache_ttl_seconds

        cached = _DOMAIN_CACHE.get(host)
        if cached and (now - cached["fetched_at"]) < cache_ttl:
            return cached["tenant_id"], cached.get("record")

        # Lookup in DDB
        from app.core.tables import T
        try:
            resp = T.tenant_domains.get_item(Key={"domain": host, "sk": "#TENANT"})
            item = resp.get("Item")
        except Exception:
            logger.exception("Failed to resolve tenant for host=%s", host)
            item = None

        if item:
            tid = item["tenant_id"]
            _DOMAIN_CACHE[host] = {"tenant_id": tid, "fetched_at": now, "record": item}
            return tid, item

        # Default tenant for localhost / unknown domains
        _DOMAIN_CACHE[host] = {
            "tenant_id": S.default_tenant_id,
            "fetched_at": now,
            "record": None,
        }
        return S.default_tenant_id, None

    async def _get_tenant_status(self, tenant_id: str) -> str:
        """Get tenant status, cached alongside domain resolution."""
        from app.core.tables import T
        try:
            resp = T.tenants.get_item(Key={"tenant_id": tenant_id})
            item = resp.get("Item")
            return item.get("status", "active") if item else "active"
        except Exception:
            return "active"

    async def _load_settings_overrides(self, tenant_id: str) -> dict:
        """Load tenant-specific settings overrides from the tenant record."""
        if tenant_id == S.default_tenant_id:
            return {}
        from app.core.tables import T
        try:
            resp = T.tenants.get_item(
                Key={"tenant_id": tenant_id},
                ProjectionExpression="settings_overrides",
            )
            item = resp.get("Item")
            return item.get("settings_overrides", {}) if item else {}
        except Exception:
            return {}


def invalidate_domain_cache(domain: str) -> None:
    """Remove a domain from the resolution cache (called after domain add/remove)."""
    _DOMAIN_CACHE.pop(domain, None)

def invalidate_tenant_cache(tenant_id: str) -> None:
    """Remove all cached domains for a tenant (called after tenant update/delete)."""
    to_remove = [d for d, v in _DOMAIN_CACHE.items() if v.get("tenant_id") == tenant_id]
    for d in to_remove:
        _DOMAIN_CACHE.pop(d, None)
```

Registration in `app/main.py` (after line 273):

```python
from app.middleware.tenant import TenantMiddleware
app.add_middleware(TenantMiddleware)
# TenantMiddleware must be added AFTER CORSMiddleware so it runs BEFORE it
# (Starlette middleware stack is LIFO)
```

### 3.5 Auth Changes

#### 3.5.1 AuthenticatedUser Extension

```python
# app/auth/deps.py -- extend AuthenticatedUser
@dataclass(frozen=True)
class AuthenticatedUser:
    sub: str
    role: Role = Role.USER
    admin_profile: AdminProfile = AdminProfile()
    tenant_id: str = "default"  # NEW
```

#### 3.5.2 JWT Claims

The `mint_access_token` function in `app/services/sessions.py` must include `tenant_id` in the JWT payload:

```python
# app/services/sessions.py -- mint_access_token
def mint_access_token(
    user_sub: str,
    session_id: str,
    role: str,
    tenant_id: str = "default",
    admin_profile: dict | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "sub": user_sub,
        "sid": session_id,
        "role": role,
        "tenant_id": tenant_id,  # NEW
        "exp": now + _access_ttl_seconds_for_user(user_sub),
        "iat": now,
    }
    if admin_profile:
        payload["admin_profile"] = admin_profile
    return jwt.encode(payload, S.ui_access_token_secret, algorithm="HS256")
```

#### 3.5.3 Session Validation

The `require_ui_session` function (line 283) must verify that the session's `tenant_id` matches `request.state.tenant_id` set by the middleware:

```python
# After loading session from DDB
session_tenant = it.get("tenant_id", "default")
request_tenant = getattr(request.state, "tenant_id", "default")
if session_tenant != request_tenant:
    raise HTTPException(403, "Session does not belong to this tenant")
```

#### 3.5.4 Tenant Admin Authorization Dependency

```python
# app/auth/deps.py -- new dependency
async def require_tenant_admin(request: Request) -> dict:
    """Require the caller to be an admin for the current tenant.

    Root users pass automatically. Platform admins pass if they have TENANT_ADMIN scope.
    Tenant-scoped admins pass only for their own tenant.
    """
    ctx = await require_ui_session(request)
    role = normalize_role(ctx.get("role"))
    if role == Role.ROOT:
        return ctx

    tenant_id = getattr(request.state, "tenant_id", "default")

    if role == Role.ADMIN:
        profile = ctx.get("admin_profile", {})
        if admin_profile_has_scope(normalize_admin_profile(profile), AdminScope.TENANT_ADMIN):
            return ctx

    # Check tenant membership with admin role
    membership = _get_tenant_membership(tenant_id, ctx["user_sub"])
    if membership and membership.get("role") in ("owner", "admin"):
        return ctx

    raise HTTPException(403, "Tenant admin access required")
```

### 3.6 Tenant Service Layer

```python
# app/services/tenant_service.py (new)
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.middleware.tenant import invalidate_domain_cache, invalidate_tenant_cache


def create_tenant(
    slug: str,
    display_name: str,
    plan: str = "starter",
    primary_domain: Optional[str] = None,
    created_by: str = "",
) -> Dict[str, Any]:
    """Create a new tenant. Slug must be globally unique."""
    # Validate slug uniqueness
    existing = T.tenants.get_item(Key={"tenant_id": slug}).get("Item")
    if existing:
        raise HTTPException(409, f"Tenant slug '{slug}' already exists")

    now = now_ts()
    item = {
        "tenant_id": slug,
        "display_name": display_name,
        "slug": slug,
        "status": "active",
        "plan": plan,
        "custom_domains": [],
        "primary_domain": primary_domain or "",
        "branding": {},
        "settings_overrides": {},
        "limits": _plan_limits(plan),
        "member_count": 0,
        "storage_used_bytes": 0,
        "created_at": now,
        "updated_at": now,
        "created_by": created_by,
    }
    T.tenants.put_item(Item=item)

    # Register domain if provided
    if primary_domain:
        add_domain(slug, primary_domain)

    return item


def _plan_limits(plan: str) -> Dict[str, Any]:
    """Return default limits for a plan tier."""
    limits_by_plan = {
        "free": {
            "max_members": 5,
            "max_storage_bytes": 1073741824,       # 1 GB
            "max_file_size_bytes": 10485760,        # 10 MB
        },
        "starter": {
            "max_members": 50,
            "max_storage_bytes": 10737418240,       # 10 GB
            "max_file_size_bytes": 52428800,         # 50 MB
        },
        "enterprise": {
            "max_members": 10000,
            "max_storage_bytes": 1099511627776,     # 1 TB
            "max_file_size_bytes": 524288000,        # 500 MB
        },
    }
    return limits_by_plan.get(plan, limits_by_plan["starter"])


def get_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    resp = T.tenants.get_item(Key={"tenant_id": tenant_id})
    return resp.get("Item")


def list_tenants(
    limit: int = 50,
    cursor: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """List all tenants (root only)."""
    scan_kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        from app.core.cursor import decode_cursor
        scan_kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.tenants.scan(**scan_kwargs)
    items = resp.get("Items", [])

    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    result: Dict[str, Any] = {"tenants": items}
    if resp.get("LastEvaluatedKey"):
        from app.core.cursor import encode_cursor
        result["cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def update_tenant(
    tenant_id: str,
    display_name: Optional[str] = None,
    plan: Optional[str] = None,
    status: Optional[str] = None,
    branding: Optional[Dict[str, Any]] = None,
    settings_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Update tenant fields. Returns the updated record."""
    item = get_tenant(tenant_id)
    if not item:
        raise HTTPException(404, "Tenant not found")

    update_expr_parts = ["#updated_at = :now"]
    attr_names = {"#updated_at": "updated_at"}
    attr_values: Dict[str, Any] = {":now": now_ts()}

    if display_name is not None:
        update_expr_parts.append("#dn = :dn")
        attr_names["#dn"] = "display_name"
        attr_values[":dn"] = display_name

    if plan is not None:
        update_expr_parts.append("#plan = :plan")
        attr_names["#plan"] = "plan"
        attr_values[":plan"] = plan

    if status is not None:
        update_expr_parts.append("#status = :status")
        attr_names["#status"] = "status"
        attr_values[":status"] = status
        if status == "suspended":
            update_expr_parts.append("suspended_at = :now")

    if branding is not None:
        update_expr_parts.append("branding = :branding")
        attr_values[":branding"] = branding

    if settings_overrides is not None:
        update_expr_parts.append("settings_overrides = :so")
        attr_values[":so"] = settings_overrides

    T.tenants.update_item(
        Key={"tenant_id": tenant_id},
        UpdateExpression="SET " + ", ".join(update_expr_parts),
        ExpressionAttributeNames=attr_names,
        ExpressionAttributeValues=attr_values,
    )

    invalidate_tenant_cache(tenant_id)
    return get_tenant(tenant_id)


def add_domain(tenant_id: str, domain: str) -> Dict[str, Any]:
    """Add a custom domain to a tenant. Domain must be globally unique."""
    # Check if domain is already claimed
    existing = T.tenant_domains.get_item(Key={"domain": domain, "sk": "#TENANT"}).get("Item")
    if existing:
        if existing["tenant_id"] == tenant_id:
            return existing  # idempotent
        raise HTTPException(409, f"Domain '{domain}' is already claimed by another tenant")

    now = now_ts()
    item = {
        "domain": domain,
        "sk": "#TENANT",
        "tenant_id": tenant_id,
        "tls_status": "pending",
        "created_at": now,
    }
    T.tenant_domains.put_item(Item=item)

    # Add to tenant's custom_domains list
    tenant = get_tenant(tenant_id)
    if tenant:
        domains = list(tenant.get("custom_domains", []))
        if domain not in domains:
            domains.append(domain)
            T.tenants.update_item(
                Key={"tenant_id": tenant_id},
                UpdateExpression="SET custom_domains = :domains, updated_at = :now",
                ExpressionAttributeValues={":domains": domains, ":now": now},
            )

    invalidate_domain_cache(domain)
    return item


def remove_domain(tenant_id: str, domain: str) -> None:
    """Remove a custom domain from a tenant."""
    existing = T.tenant_domains.get_item(Key={"domain": domain, "sk": "#TENANT"}).get("Item")
    if not existing or existing["tenant_id"] != tenant_id:
        raise HTTPException(404, "Domain not found for this tenant")

    T.tenant_domains.delete_item(Key={"domain": domain, "sk": "#TENANT"})

    # Remove from tenant's custom_domains list
    tenant = get_tenant(tenant_id)
    if tenant:
        domains = [d for d in tenant.get("custom_domains", []) if d != domain]
        T.tenants.update_item(
            Key={"tenant_id": tenant_id},
            UpdateExpression="SET custom_domains = :domains, updated_at = :now",
            ExpressionAttributeValues={":domains": domains, ":now": now_ts()},
        )

    invalidate_domain_cache(domain)
```

### 3.7 Tenant Router

```python
# app/routers/tenant_admin.py (new)
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.models import (
    TenantBrandingReq,
    TenantCreateReq,
    TenantDomainAddReq,
    TenantOut,
    TenantUpdateReq,
)
from app.services.sessions import require_root_session
from app.services.tenant_service import (
    add_domain,
    create_tenant,
    get_tenant,
    list_tenants,
    remove_domain,
    update_tenant,
)
from app.services.alerts import audit_event

router = APIRouter(prefix="/v1/admin/tenants", tags=["tenant-admin"])


@router.post("", status_code=201, response_model=TenantOut)
async def create_tenant_endpoint(
    body: TenantCreateReq,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    result = create_tenant(
        slug=body.slug,
        display_name=body.display_name,
        plan=body.plan,
        primary_domain=body.primary_domain,
        created_by=ctx["user_sub"],
    )
    audit_event("tenant_created", ctx["user_sub"], request,
                tenant_id=result["tenant_id"], slug=body.slug)
    return result


@router.get("", response_model=Dict[str, Any])
async def list_tenants_endpoint(
    limit: int = 50,
    cursor: Optional[str] = None,
    status: Optional[str] = None,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    return list_tenants(limit=limit, cursor=cursor, status_filter=status)


@router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant_endpoint(
    tenant_id: str,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(404, "Tenant not found")
    return tenant


@router.patch("/{tenant_id}", response_model=TenantOut)
async def update_tenant_endpoint(
    tenant_id: str,
    body: TenantUpdateReq,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    result = update_tenant(
        tenant_id=tenant_id,
        display_name=body.display_name,
        plan=body.plan,
        status=body.status,
        branding=body.branding.model_dump(exclude_none=True) if body.branding else None,
    )
    audit_event("tenant_updated", ctx["user_sub"], request,
                tenant_id=tenant_id, changes=body.model_dump(exclude_none=True))
    return result


@router.delete("/{tenant_id}", status_code=204)
async def delete_tenant_endpoint(
    tenant_id: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    update_tenant(tenant_id=tenant_id, status="deleted")
    audit_event("tenant_deleted", ctx["user_sub"], request, tenant_id=tenant_id)


@router.post("/{tenant_id}/domains", status_code=201)
async def add_domain_endpoint(
    tenant_id: str,
    body: TenantDomainAddReq,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    result = add_domain(tenant_id, body.domain)
    audit_event("tenant_domain_added", ctx["user_sub"], request,
                tenant_id=tenant_id, domain=body.domain)
    return result


@router.delete("/{tenant_id}/domains/{domain}", status_code=204)
async def remove_domain_endpoint(
    tenant_id: str,
    domain: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_root_session),
):
    remove_domain(tenant_id, domain)
    audit_event("tenant_domain_removed", ctx["user_sub"], request,
                tenant_id=tenant_id, domain=domain)
```

---

## 4. API Endpoints

### 4.1 Tenant Management (Root only)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/admin/tenants` | `require_root_session` | Create a new tenant |
| GET | `/v1/admin/tenants` | `require_root_session` | List all tenants (paginated) |
| GET | `/v1/admin/tenants/{tenant_id}` | `require_root_session` | Get tenant details |
| PATCH | `/v1/admin/tenants/{tenant_id}` | `require_root_session` | Update tenant settings/branding |
| DELETE | `/v1/admin/tenants/{tenant_id}` | `require_root_session` | Soft-delete (suspend) a tenant |
| POST | `/v1/admin/tenants/{tenant_id}/domains` | `require_root_session` | Add a custom domain |
| DELETE | `/v1/admin/tenants/{tenant_id}/domains/{domain}` | `require_root_session` | Remove a custom domain |

### 4.2 Tenant Branding (Public)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/tenant/branding` | None (public) | Returns branding config for current tenant |
| GET | `/ui/tenant/info` | None (public) | Returns tenant slug, display name, status |

### 4.3 Tenant Admin (Tenant-scoped admin)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/tenant/admin/members` | `require_tenant_admin` | List members in current tenant |
| POST | `/ui/tenant/admin/members/invite` | `require_tenant_admin` | Invite user to tenant |
| DELETE | `/ui/tenant/admin/members/{user_sub}` | `require_tenant_admin` | Remove member from tenant |
| PATCH | `/ui/tenant/admin/settings` | `require_tenant_admin` | Update tenant feature flags |
| GET | `/ui/tenant/admin/usage` | `require_tenant_admin` | Get tenant storage and member usage stats |
| POST | `/ui/tenant/admin/branding/logo` | `require_tenant_admin` | Upload tenant logo image |
| POST | `/ui/tenant/admin/branding/favicon` | `require_tenant_admin` | Upload tenant favicon |

### 4.4 Request Models

```python
# app/models.py -- new models

class TenantCreateReq(BaseModel):
    slug: str = Field(min_length=2, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    display_name: str = Field(min_length=1, max_length=256)
    plan: str = Field(default="starter", pattern=r"^(free|starter|enterprise)$")
    primary_domain: Optional[str] = None

class TenantUpdateReq(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    plan: Optional[str] = Field(default=None, pattern=r"^(free|starter|enterprise)$")
    status: Optional[str] = Field(default=None, pattern=r"^(active|suspended|trial)$")
    branding: Optional[TenantBrandingReq] = None
    settings_overrides: Optional[dict] = None

class TenantBrandingReq(BaseModel):
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    primary_color: Optional[str] = Field(default=None, pattern=r"^#[0-9A-Fa-f]{6}$")
    accent_color: Optional[str] = Field(default=None, pattern=r"^#[0-9A-Fa-f]{6}$")
    font_family: Optional[str] = None
    login_background_url: Optional[str] = None
    login_message: Optional[str] = Field(default=None, max_length=500)
    custom_css: Optional[str] = Field(default=None, max_length=10000)

class TenantDomainAddReq(BaseModel):
    domain: str = Field(min_length=3, max_length=253)

class TenantOut(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    status: str
    plan: str
    custom_domains: list[str]
    primary_domain: Optional[str]
    branding: Optional[dict]
    limits: Optional[dict]
    member_count: int
    storage_used_bytes: int
    created_at: int
    updated_at: int

class TenantBrandingOut(BaseModel):
    tenant_id: str
    display_name: str
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    primary_color: str = "#2563EB"
    accent_color: str = "#7C3AED"
    font_family: str = "Inter"
    login_background_url: Optional[str] = None
    login_message: Optional[str] = None
    custom_css: Optional[str] = None
    sso_available: bool = False
    sso_only: bool = False

class TenantInfoOut(BaseModel):
    tenant_id: str
    slug: str
    display_name: str
    status: str
    plan: str

class TenantMemberInviteReq(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    role: str = Field(default="member", pattern=r"^(admin|member)$")

class TenantUsageOut(BaseModel):
    tenant_id: str
    member_count: int
    max_members: int
    storage_used_bytes: int
    max_storage_bytes: int
    active_sessions: int
    api_keys_count: int
    webhook_endpoints_count: int
```

### 4.5 Response Shape Examples

**GET `/ui/tenant/branding`** (public, no auth):

```json
{
    "tenant_id": "acme-corp",
    "display_name": "Acme Corporation",
    "logo_url": "/static/uploads/tenants/acme-corp/logo.png",
    "favicon_url": "/static/uploads/tenants/acme-corp/favicon.ico",
    "primary_color": "#2563EB",
    "accent_color": "#7C3AED",
    "font_family": "Inter",
    "login_background_url": null,
    "login_message": "Welcome to the Acme platform",
    "custom_css": null,
    "sso_available": true,
    "sso_only": false
}
```

**GET `/v1/admin/tenants`** (root only):

```json
{
    "tenants": [
        {
            "tenant_id": "acme-corp",
            "slug": "acme-corp",
            "display_name": "Acme Corporation",
            "status": "active",
            "plan": "enterprise",
            "custom_domains": ["app.acme.com"],
            "primary_domain": "app.acme.com",
            "member_count": 142,
            "storage_used_bytes": 5368709120,
            "created_at": 1716883200,
            "updated_at": 1716883200
        }
    ],
    "cursor": "eyJ0ZW5hbnRfaWQiOiAiYWNtZS1jb3JwIn0="
}
```

---

## 5. Frontend Components

### 5.1 Branding Provider

**File**: `frontend/src/providers/TenantBrandingProvider.tsx` (new)

- Fetches `/ui/tenant/branding` at app startup (before first render)
- Applies `primary_color` and `accent_color` as CSS custom properties on `:root`
- Replaces favicon `<link>` element dynamically
- Stores branding in a Zustand store (`tenantStore.ts`)

```typescript
// frontend/src/stores/tenantStore.ts (new)
import { create } from "zustand";

interface TenantBranding {
  tenant_id: string;
  display_name: string;
  logo_url: string | null;
  favicon_url: string | null;
  primary_color: string;
  accent_color: string;
  font_family: string;
  login_background_url: string | null;
  login_message: string | null;
  custom_css: string | null;
  sso_available: boolean;
  sso_only: boolean;
}

interface TenantStore {
  branding: TenantBranding | null;
  loading: boolean;
  error: string | null;
  setBranding: (b: TenantBranding) => void;
  setLoading: (l: boolean) => void;
  setError: (e: string | null) => void;
}

export const useTenantStore = create<TenantStore>((set) => ({
  branding: null,
  loading: true,
  error: null,
  setBranding: (b) => set({ branding: b, loading: false }),
  setLoading: (l) => set({ loading: l }),
  setError: (e) => set({ error: e, loading: false }),
}));
```

```tsx
// frontend/src/providers/TenantBrandingProvider.tsx (new)
import { useEffect } from "react";
import { useTenantStore } from "@/stores/tenantStore";
import { api } from "@/api/client";  // NOTE: codebase uses named `api` export

export function TenantBrandingProvider({ children }: { children: React.ReactNode }) {
  const { setBranding, setError, loading } = useTenantStore();

  useEffect(() => {
    client.get("/ui/tenant/branding")
      .then((res) => {
        const b = res.data;
        setBranding(b);

        // Apply CSS custom properties
        document.documentElement.style.setProperty("--color-primary", b.primary_color);
        document.documentElement.style.setProperty("--color-accent", b.accent_color);
        if (b.font_family) {
          document.documentElement.style.setProperty("--font-family", b.font_family);
        }

        // Replace favicon
        if (b.favicon_url) {
          const link = document.querySelector("link[rel='icon']") as HTMLLinkElement;
          if (link) link.href = b.favicon_url;
        }

        // Inject custom CSS
        if (b.custom_css) {
          const style = document.createElement("style");
          style.textContent = b.custom_css;
          style.id = "tenant-custom-css";
          document.head.appendChild(style);
        }
      })
      .catch((err) => setError(err.message));
  }, []);

  if (loading) return null; // or a loading spinner
  return <>{children}</>;
}
```

### 5.2 Tenant Admin Page

**File**: `frontend/src/pages/admin/TenantAdmin.tsx` (new)

- Root-only page for CRUD operations on tenants
- Data table with columns: Name, Slug, Status, Plan, Domains, Members, Created
- Create/Edit dialogs using shadcn `Dialog`, `Input`, color picker for branding
- Domain management with DNS verification status badge
- Status badge: green (active), yellow (trial), red (suspended), gray (deleted)

```typescript
// frontend/src/api/endpoints/tenants.ts (new)
import { api } from "@/api/client";  // NOTE: codebase uses named `api` export
import type { TenantOut, TenantCreateReq, TenantUpdateReq } from "@/api/types";

export const createTenant = (req: TenantCreateReq) =>
  client.post<TenantOut>("/v1/admin/tenants", req);

export const listTenants = (params?: { limit?: number; cursor?: string; status?: string }) =>
  client.get<{ tenants: TenantOut[]; cursor?: string }>("/v1/admin/tenants", { params });

export const getTenant = (tenantId: string) =>
  client.get<TenantOut>(`/v1/admin/tenants/${tenantId}`);

export const updateTenant = (tenantId: string, req: TenantUpdateReq) =>
  client.patch<TenantOut>(`/v1/admin/tenants/${tenantId}`, req);

export const deleteTenant = (tenantId: string) =>
  client.delete(`/v1/admin/tenants/${tenantId}`);

export const addDomain = (tenantId: string, domain: string) =>
  client.post(`/v1/admin/tenants/${tenantId}/domains`, { domain });

export const removeDomain = (tenantId: string, domain: string) =>
  client.delete(`/v1/admin/tenants/${tenantId}/domains/${domain}`);
```

### 5.3 Sidebar Branding

**File**: `frontend/src/components/layout/Sidebar.tsx` (modified)

- Replace hardcoded app logo with `tenantStore.branding.logo_url`
- Apply `tenantStore.branding.primary_color` to sidebar highlight
- Show `tenantStore.branding.display_name` as the app title

### 5.4 Login Page Branding

**File**: `frontend/src/pages/Login.tsx` (modified)

- Display tenant logo above login form
- Apply tenant accent color to the login button
- Show `login_message` if configured
- Apply `login_background_url` as page background if set
- When `sso_only=true`, hide password form and show only SSO button

---

## 6. DynamoDB Table Definitions

### 6.1 New Tables for `scripts/local-ddb-init.py`

```python
TableDef("tenants", pk="tenant_id"),
TableDef("tenant_domains", pk="domain", sk="sk"),
TableDef("tenant_members", pk="tenant_id", sk="user_sub",
    gsis=[
        GSIDef("user-tenant-index", pk="user_sub", sk="tenant_id"),
    ]),
```

### 6.2 Full DDB Item Schemas

**tenants table:**

| Attribute | Type | Key | Description |
|-----------|------|-----|-------------|
| `tenant_id` | S | PK | Tenant identifier (= slug) |
| `display_name` | S | | Human-readable tenant name |
| `slug` | S | | URL-safe identifier |
| `status` | S | | active, suspended, trial, deleted |
| `plan` | S | | free, starter, enterprise |
| `custom_domains` | L | | List of custom domain strings |
| `primary_domain` | S | | Primary custom domain |
| `branding` | M | | Branding config map |
| `settings_overrides` | M | | Feature flag overrides map |
| `limits` | M | | Plan limits (max_members, max_storage_bytes, etc.) |
| `member_count` | N | | Current member count |
| `storage_used_bytes` | N | | Current storage usage |
| `created_at` | N | | Unix timestamp |
| `updated_at` | N | | Unix timestamp |
| `created_by` | S | | Creator user_sub |

**tenant_domains table:**

| Attribute | Type | Key | Description |
|-----------|------|-----|-------------|
| `domain` | S | PK | Fully qualified domain name |
| `sk` | S | SK | Always `#TENANT` |
| `tenant_id` | S | | Owning tenant |
| `tls_status` | S | | pending, active, expired, error |
| `tls_expires_at` | N | | TLS cert expiry timestamp |
| `tls_certificate_arn` | S | | ACM certificate ARN |
| `dns_verification_cname` | S | | CNAME record for DNS validation |
| `dns_verification_value` | S | | CNAME target value |
| `dns_verified_at` | N | | When DNS was verified |
| `created_at` | N | | Unix timestamp |

**tenant_members table:**

| Attribute | Type | Key | Description |
|-----------|------|-----|-------------|
| `tenant_id` | S | PK | Tenant identifier |
| `user_sub` | S | SK | User identifier |
| `role` | S | | owner, admin, member |
| `status` | S | | active, suspended, invited |
| `invited_by` | S | | Inviter user_sub |
| `joined_at` | N | | Unix timestamp |
| `last_active_at` | N | | Last activity timestamp |
| `storage_used_bytes` | N | | Per-member storage usage |

### 6.3 Settings Additions for `app/core/settings.py`

```python
# Multi-tenancy (ENTERPRISE-001)
multi_tenancy_enabled: bool = os.environ.get("MULTI_TENANCY_ENABLED", "0") not in ("0", "false", "False")
tenants_table_name: str = os.environ.get("TENANTS_TABLE_NAME", "tenants")
tenant_domains_table_name: str = os.environ.get("TENANT_DOMAINS_TABLE_NAME", "tenant_domains")
tenant_members_table_name: str = os.environ.get("TENANT_MEMBERS_TABLE_NAME", "tenant_members")
tenant_domain_cache_ttl_seconds: int = int(os.environ.get("TENANT_DOMAIN_CACHE_TTL_SECONDS", "300"))
default_tenant_id: str = os.environ.get("DEFAULT_TENANT_ID", "default")
tenant_branding_s3_prefix: str = os.environ.get("TENANT_BRANDING_S3_PREFIX", "tenant-branding")
tenant_max_custom_domains: int = int(os.environ.get("TENANT_MAX_CUSTOM_DOMAINS", "5"))
tenant_purge_grace_period_days: int = int(os.environ.get("TENANT_PURGE_GRACE_PERIOD_DAYS", "90"))
```

### 6.4 Tables Dataclass Extension

```python
# app/core/tables.py -- add to Tables dataclass
tenants: Any
tenant_domains: Any
tenant_members: Any

# And in T = Tables(...) initialization:
tenants=ddb.Table(S.tenants_table_name),
tenant_domains=ddb.Table(S.tenant_domains_table_name),
tenant_members=ddb.Table(S.tenant_members_table_name),
```

---

## 7. E2E Test Plan

### 7.1 Test File

**File**: `frontend/e2e/multi-tenancy.spec.ts` (new)

### 7.2 Test Sections

| Section | Tests | Description |
|---------|-------|-------------|
| 80 | 6 | Tenant CRUD API (create, list, get, update, delete, duplicate slug) |
| 81 | 4 | Domain management API (add domain, remove domain, duplicate domain, DNS status) |
| 82 | 3 | Branding API (set branding, get branding, reset branding) |
| 83 | 5 | Tenant isolation (Alice on tenant-a can't see Bob's tenant-b data) |
| 84 | 4 | Tenant admin member management (invite, list, remove, role assignment) |
| 85 | 3 | Branding UI (logo renders, colors applied, favicon updated) |

### 7.3 Test Setup

```typescript
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers/auth";

const TS = Date.now();
const ROOT_ID = "root";
const ALICE_ID = "alice";
const BOB_ID = "bob";

let tenantAId: string;
let tenantBId: string;

test.describe("80 - Tenant CRUD API", () => {
    test("creates tenant-a", async ({ request }) => {
        const resp = await request.post("/v1/admin/tenants", {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
            data: {
                slug: `e2e-tenant-a-${TS}`,
                display_name: `E2E Tenant A ${TS}`,
                plan: "starter",
            },
        });
        expect(resp.status()).toBe(201);
        const data = await resp.json();
        tenantAId = data.tenant_id;
        expect(data.slug).toBe(`e2e-tenant-a-${TS}`);
        expect(data.status).toBe("active");
        expect(data.member_count).toBe(0);
    });

    test("creates tenant-b", async ({ request }) => {
        const resp = await request.post("/v1/admin/tenants", {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
            data: {
                slug: `e2e-tenant-b-${TS}`,
                display_name: `E2E Tenant B ${TS}`,
                plan: "enterprise",
            },
        });
        expect(resp.status()).toBe(201);
        tenantBId = (await resp.json()).tenant_id;
    });

    test("rejects duplicate slug", async ({ request }) => {
        const resp = await request.post("/v1/admin/tenants", {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
            data: {
                slug: `e2e-tenant-a-${TS}`,
                display_name: "Duplicate",
            },
        });
        expect(resp.status()).toBe(409);
    });

    test("lists tenants", async ({ request }) => {
        const resp = await request.get("/v1/admin/tenants", {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
        });
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        expect(data.tenants.length).toBeGreaterThanOrEqual(2);
    });

    test("gets tenant details", async ({ request }) => {
        const resp = await request.get(`/v1/admin/tenants/${tenantAId}`, {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
        });
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        expect(data.display_name).toBe(`E2E Tenant A ${TS}`);
    });

    test("soft-deletes tenant", async ({ request }) => {
        const resp = await request.delete(`/v1/admin/tenants/${tenantBId}`, {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
        });
        expect(resp.status()).toBe(204);
        // Verify status is deleted
        const get = await request.get(`/v1/admin/tenants/${tenantBId}`, {
            headers: { Authorization: `Bearer ${sessions.root.token}` },
        });
        expect((await get.json()).status).toBe("deleted");
    });
});
```

### 7.4 Isolation Test Example

```typescript
test.describe("83 - Tenant isolation", () => {
    test("Alice on tenant-a cannot see tenant-b messages", async ({ browser }) => {
        // Create a message in tenant-a context
        // Verify that querying with tenant-b context returns no results
        // This validates that tenant_pk() scoping is working
    });

    test("Session from tenant-a rejected on tenant-b", async ({ browser }) => {
        // Create a session with tenant_id=tenant-a
        // Present the session cookie to a request with Host: tenant-b
        // Expect 403 "Session does not belong to this tenant"
    });
});
```

---

## 8. Edge Cases & Error Handling

### 8.1 Domain Conflicts

Two tenants cannot claim the same domain. The `tenant_domains` table enforces uniqueness via the PK. Attempting to add a domain already claimed by another tenant returns `409 Conflict`.

### 8.2 Tenant Suspension

When a tenant is suspended (`status=suspended`), the tenant resolution middleware returns `503 Service Unavailable` for all non-admin requests. Root admin can still access the tenant for investigation. The `503` response includes a `Retry-After` header and a message explaining the suspension.

### 8.3 Default Tenant Fallback

Requests from `localhost`, `127.0.0.1`, or any unrecognized host resolve to the `default` tenant. This preserves backward compatibility for development and single-tenant deployments. The `default` tenant is auto-created at first startup if `multi_tenancy_enabled=true`.

### 8.4 Cross-Tenant Session Replay

A user who has a valid session on tenant-a presents their session cookie on tenant-b's domain. The `require_ui_session` function must reject this with 403. The session record in DynamoDB stores `tenant_id`; the middleware sets `request.state.tenant_id`; session validation compares the two.

### 8.5 Tenant Deletion Cascading

Deleting a tenant is a soft-delete (status -> `deleted`). Data is retained for 90 days before a background purge job removes all DynamoDB items with the tenant's prefix. During the grace period, a root admin can restore the tenant. The purge job:

1. Scans each table for items with `TENANT#{tenant_id}#` prefix
2. Batch-deletes in pages of 25 (DynamoDB batch limit)
3. Deletes S3 objects under `uploads/{tenant_id}/`
4. Records purge completion in the audit log
5. Finally deletes the tenant record itself

### 8.6 Tenant-Scoped Feature Flags

The existing `settings_overrides` field on the tenant record is a JSON dict. At middleware time, these overrides are merged on top of the global `S` settings using a `TenantSettings` wrapper that checks the override dict before falling back to `S`. This allows per-tenant enablement of features like `messaging_encrypted_messages_enabled` without global changes.

Allowed override fields are whitelisted to prevent security-sensitive settings from being overridden per-tenant:

```python
ALLOWED_TENANT_OVERRIDES = {
    "messaging_encrypted_messages_enabled",
    "newsfeed_markdown_enabled",
    "newsfeed_richtext_enabled",
    "signature_pdf_enabled",
    "messaging_reporting_enabled",
    "default_currency",
    "org_max_members",
    "org_max_per_user",
    # Security settings are NOT overridable:
    # ui_access_token_secret, api_key_pepper, root_user_sub, etc.
}
```

### 8.7 Rate Limiting Per Tenant

The existing `rate_limit_middleware_factory()` in `app/middleware/rate_limit.py` uses IP-based rate limiting. Multi-tenancy adds tenant-level rate limits: `rate_limit_global_tenant_window_seconds` and `rate_limit_global_tenant_max_requests`. The rate limit key becomes `TENANT#{tenant_id}#IP#{ip}`.

### 8.8 Tenant Slug Validation

Tenant slugs must be:
- 2-63 characters long
- Lowercase alphanumeric plus hyphens
- Cannot start or end with a hyphen
- Cannot be a reserved word: `default`, `admin`, `root`, `api`, `static`, `internal`, `mock`
- Globally unique across all tenants (enforced by DDB conditional put)

### 8.9 Concurrent Tenant Updates

Multiple admins updating the same tenant simultaneously could cause lost updates. The `update_tenant` function uses DynamoDB conditional updates with `updated_at` as an optimistic concurrency control field. If the `updated_at` has changed since the read, the update is retried with a fresh read.

---

## 9. Security Considerations

### 9.1 Tenant Boundary Enforcement

Every service function that accesses DynamoDB must use the `tenant_pk()` helper. A lint rule or test suite should verify that no direct `f"USER#{user_sub}"` patterns exist outside the helper. A grep-based CI check:

```bash
# In CI pipeline
grep -rn 'f"USER#{' app/services/ app/routers/ \
  | grep -v tenant_pk \
  | grep -v '# legacy-ok' \
  && echo "FAIL: Direct PK construction without tenant_pk()" && exit 1
```

### 9.2 JWT Tenant Claim

The `ui_access_token` JWT includes a `tenant_id` claim. The middleware verifies that the claim matches the resolved tenant from the hostname. A mismatch results in 403.

### 9.3 CORS Per Tenant

Each tenant's custom domains must be in the CORS allowed origins list. The `_build_cors_options()` function must dynamically include tenant domains. In dev mode, the wildcard regex (`.*`) continues to allow all origins.

```python
def _build_cors_options() -> dict:
    # ... existing logic ...
    if S.multi_tenancy_enabled:
        # Load all active tenant domains
        from app.services.tenant_service import list_all_active_domains
        tenant_origins = [f"https://{d}" for d in list_all_active_domains()]
        allowed_origins.extend(tenant_origins)
    return {"allow_origins": allowed_origins, ...}
```

### 9.4 TLS Certificate Management

Custom domains require valid TLS certificates. In production, the platform uses AWS Certificate Manager (ACM) with DNS validation. The domain add endpoint triggers a certificate request and returns the DNS CNAME record the tenant must create. Certificate status is polled and updated in the `tenant_domains` table.

### 9.5 Audit Trail

All tenant management operations (create, update, delete, domain changes) are recorded via `audit_event()` (from `app/services/alerts.py`, line 570) with `event="tenant_*"` prefixes for compliance traceability.
<!-- CORRECTED: audit_event is at line 695, not 570 -->

### 9.6 Data Export and Portability

Each tenant can export all their data as a JSON archive via the existing privacy export system (PRIVACY-001). The export is scoped to the tenant's partition key prefix, ensuring no cross-tenant data leakage.

### 9.7 Branding XSS Prevention

Custom CSS uploaded via `TenantBrandingReq.custom_css` is sanitized to prevent XSS:
- `url()` values restricted to HTTPS URLs only
- `expression()` and `javascript:` blocked
- `@import` blocked
- Maximum length 10KB
- Content-Security-Policy header includes `style-src 'self' 'unsafe-inline'` (already present)

### 9.8 API Key Tenant Scoping

Existing API keys in `T.api_keys` do not have a `tenant_id`. After migration, all new API keys include `tenant_id`. API key authentication in `get_authenticated_user` validates that the key's tenant matches `request.state.tenant_id`. Legacy keys (without tenant_id) are treated as belonging to the `default` tenant.

---

## 10. Migration Plan

### 10.1 Phase 1: Infrastructure (Week 1-2)

1. Create `tenants`, `tenant_domains`, `tenant_members` tables
2. Implement `tenant_pk()` helper and `TenantMiddleware`
3. Create `default` tenant record for existing installation
4. Add `tenant_id` field to all session records (backfill as `default`)
5. Add `TenantSettings` wrapper class
6. Feature-flag the middleware behind `MULTI_TENANCY_ENABLED`

### 10.2 Phase 2: Auth Integration (Week 3)

1. Extend `AuthenticatedUser` with `tenant_id`
2. Add `tenant_id` claim to JWT minting
3. Add tenant validation to `require_ui_session`
4. Implement `require_tenant_admin` dependency
5. Implement tenant admin endpoints

### 10.3 Phase 3: Data Scoping (Week 4-5)

1. Migrate all PK construction to use `tenant_pk()`
2. Add `tenant_id` to all new records
3. Backfill existing records with `TENANT#default#` prefix
4. Add tenant-aware branding to frontend
5. Update all GSI queries to include tenant prefix

### 10.4 Phase 4: Custom Domains (Week 6)

1. Domain management API
2. TLS certificate provisioning (ACM integration)
3. DNS verification flow
4. E2E tests

### 10.5 Phase 5: Backfill & Validation (Week 7)

1. Run backfill script for all existing data to `TENANT#default#` prefix
2. Validate all queries still return correct results
3. Load testing with multiple tenants
4. Security audit of tenant boundary enforcement

---

## 11. Observability

### 11.1 Metrics

- `tenant_request_count{tenant_id}` -- requests per tenant
- `tenant_member_count{tenant_id}` -- gauge of active members
- `tenant_resolution_cache_hit_rate` -- cache effectiveness
- `tenant_resolution_latency_ms` -- P99 resolution time
- `tenant_storage_bytes{tenant_id}` -- storage usage per tenant
- `tenant_api_error_rate{tenant_id, status_code}` -- error rates by tenant

### 11.2 Logging

All structured log entries include `tenant_id` from the context variable. This allows filtering logs by tenant in CloudWatch or any log aggregator. The logging configuration in `app/main.py` must be updated to include the tenant context:

```python
import logging
from app.core.tenant import get_current_tenant

class TenantFilter(logging.Filter):
    def filter(self, record):
        record.tenant_id = get_current_tenant()
        return True

# Add to all handlers
logging.getLogger().addFilter(TenantFilter())
```

### 11.3 Alerting

- Alert when a tenant exceeds 90% of their plan's member limit
- Alert when TLS certificate expiry is within 14 days
- Alert when a tenant has been suspended for >30 days (approaching purge window)
- Alert when domain resolution cache hit rate drops below 80%
- Alert when any tenant's error rate exceeds 5% of requests

### 11.4 Dashboard

A Grafana/CloudWatch dashboard showing:
- Requests per tenant over time (stacked area chart)
- Top 10 tenants by request volume
- Tenant resolution cache hit rate
- Storage usage per tenant (bar chart)
- Active sessions per tenant

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| `Settings` class | `app/core/settings.py` | 7 | VERIFIED |
| `S = Settings()` singleton | `app/core/settings.py` | 1494 | VERIFIED (ticket said 1400) |
| `AuthenticatedUser` | `app/auth/deps.py` | 126 | VERIFIED (ticket said 125-129) |
| `get_authenticated_user` | `app/auth/deps.py` | 184 | VERIFIED |
| `Tables` class | `app/core/tables.py` | 10 | VERIFIED (ticket said 9) |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED |
| `Role` enum | `app/auth/roles.py` | 8 | VERIFIED |
| `AdminScope` enum | `app/auth/roles.py` | 14 | VERIFIED |
| `admin_profile_has_scope` | `app/auth/roles.py` | 118 | VERIFIED |
| `audit_event` | `app/services/alerts.py` | 695 | VERIFIED (ticket said 570) |
| `user_pk` | `app/services/billing_shared.py` | 16 | VERIFIED |
| Tenant middleware | `app/middleware/tenant.py` | exists, registered at `app/main.py:287` | VERIFIED |
| Tenant core | `app/core/tenant.py` | exists | VERIFIED |
| Tenant service | `app/services/tenant_service.py` | exists | VERIFIED |
| Tenant admin router | `app/routers/tenant_admin.py` | exists, registered at `app/main.py:172,463-464` | VERIFIED |
| Tenant settings | `app/core/settings.py` | 1487-1489 | VERIFIED: tenants, tenant_domains, tenant_members table names |
| Tenant store (frontend) | `frontend/src/stores/tenantStore.ts` | exists | VERIFIED |

---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_tenant_service.py`

| # | Test Function | Description | Mocks |
|---|--------------|-------------|-------|
| 1 | `test_enterprise_001_create_basic` | Core creation logic succeeds with valid inputs | moto DDB |
| 2 | `test_enterprise_001_validation_rejects_invalid` | 400/422 for invalid inputs | moto DDB |
| 3 | `test_enterprise_001_pagination` | Cursor-based pagination returns correct pages | moto DDB |
| 4 | `test_enterprise_001_auth_required` | 401 for unauthenticated requests | moto DDB |
| 5 | `test_enterprise_001_forbidden_wrong_user` | 403 when non-owner accesses restricted resource | moto DDB |
| 6 | `test_enterprise_001_not_found` | 404 for non-existent resource | moto DDB |
| 7 | `test_enterprise_001_duplicate_rejected` | 409 for duplicate creation | moto DDB |
| 8 | `test_enterprise_001_feature_flag_off` | Feature disabled returns 404 when flag is off | moto DDB |

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Full CRUD lifecycle: create, read, update, delete | Service layer, DDB |
| 2 | Cross-service interaction with dependent features | Multiple service modules |
| 3 | Concurrent access patterns do not corrupt data | Service layer, parallel requests |

### E2E Tests (Playwright)

**File**: `frontend/e2e/multi-tenancy.spec.ts`

Tests use `injectAuth(page, identity)` for cookie-based auth and include CSRF headers (`x-csrf-token`) on all POST/PUT/DELETE requests. Negative tests cover 401 (unauthenticated), 403 (wrong role/user), 404 (not found), 409 (conflict), and 422 (validation) responses. Edge cases include duplicate operations (idempotency), concurrent access, and feature-flag-disabled behavior.

**Total E2E tests**: 15

### Test Data Requirements

- DDB seeds: required tables created via `scripts/local-ddb-init.py`
- Test users: Alice, Bob, Root, Charlie via `e2e_session_setup.py` / `e2e_admin_session_setup.py`
- Feature flag: `MULTI_TENANCY_ENABLED` in `.env.local`

### CI/Pipeline

- Feature flag: `MULTI_TENANCY_ENABLED` must be enabled for tests to run
- Serial execution: run with `--workers 1` to avoid shared state conflicts
- Retry safety: tests use unique timestamps/UUIDs per run; safe to retry on failure

---

## Dependencies & Merge Safety

### Depends On

| Ticket | Status | What It Provides |
|--------|--------|-----------------|
| (none) | -- | This ticket has no upstream ticket dependencies |

### Depended On By

| Ticket | What It Needs |
|--------|--------------|
| ENTERPRISE-002 | SSO/SAML depends on tenant infrastructure |
| ENTERPRISE-003 | Org workspaces depend on tenant isolation |

### Merge Strategy

**Independent** -- Changes are additive (new service files, new router, new frontend pages). Shared infrastructure files (`main.py`, `settings.py`, `tables.py`, `local-ddb-init.py`) receive only additive modifications.

### Merge Checklist

- [ ] All new DDB tables/GSIs added to `scripts/local-ddb-init.py`
- [ ] Settings added to `app/core/settings.py`
- [ ] Table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Frontend routes added to `App.tsx`
- [ ] Feature flag `MULTI_TENANCY_ENABLED` added to `.env.local.example`
- [ ] All E2E tests pass
- [ ] No regressions in existing test suite
