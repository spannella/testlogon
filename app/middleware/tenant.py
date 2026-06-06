"""
Tenant resolution middleware (ENTERPRISE-001).

When ``multi_tenancy_enabled`` is False the middleware simply sets the
tenant context to "default" and continues.  When enabled, it resolves the
tenant from the Host header (with an in-memory cache) and sets context
variables for the request lifecycle.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

import jwt as _jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.settings import S
from app.core.tenant import (
    TenantSettings,
    set_current_tenant,
    set_tenant_settings,
)

logger = logging.getLogger(__name__)

# ── In-memory domain → tenant cache ─────────────────────────────────────────

# Structure: { domain: (tenant_id, tenant_record, fetched_at) }
_DOMAIN_CACHE: Dict[str, Tuple[str, Dict[str, Any], float]] = {}


def invalidate_domain_cache(domain: str) -> None:
    """Remove a single domain entry from the cache."""
    _DOMAIN_CACHE.pop(domain, None)


def invalidate_tenant_cache(tenant_id: str) -> None:
    """Remove all cache entries whose tenant_id matches."""
    to_remove = [d for d, (tid, _, _) in _DOMAIN_CACHE.items() if tid == tenant_id]
    for d in to_remove:
        _DOMAIN_CACHE.pop(d, None)


def _cache_get(domain: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    entry = _DOMAIN_CACHE.get(domain)
    if entry is None:
        return None
    tenant_id, tenant_record, fetched_at = entry
    if time.time() - fetched_at > S.tenant_domain_cache_ttl_seconds:
        _DOMAIN_CACHE.pop(domain, None)
        return None
    return tenant_id, tenant_record


def _cache_set(domain: str, tenant_id: str, tenant_record: Dict[str, Any]) -> None:
    _DOMAIN_CACHE[domain] = (tenant_id, tenant_record, time.time())


def _resolve_tenant_from_domain(domain: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Look up a domain in the tenant_domains table, then fetch the tenant record."""
    from app.core.tables import T

    cached = _cache_get(domain)
    if cached is not None:
        return cached

    try:
        resp = T.tenant_domains.get_item(Key={"domain": domain, "sk": "DOMAIN"})
    except Exception:
        return None
    item = resp.get("Item")
    if not item:
        return None

    tenant_id = item.get("tenant_id", "")
    if not tenant_id:
        return None

    try:
        t_resp = T.tenants.get_item(Key={"tenant_id": tenant_id})
    except Exception:
        return None
    tenant_record = t_resp.get("Item") or {}

    _cache_set(domain, tenant_id, tenant_record)
    return tenant_id, tenant_record


def _request_is_root(request: Request) -> bool:
    """
    Lightweight check: does the incoming request carry a ROOT-role credential?

    Used only to bypass the suspended-tenant 503 guard so a genuine root
    session can reach the auth layer and remediate the suspension. This does
    NOT replace full authentication — the request still passes through
    ``require_root_session`` downstream in the router layer. Forged cookies are
    rejected because the HS256 HMAC signature is verified here.
    """
    # 1. Cookie-based access token (browser session) — HMAC-verified.
    access_secret = getattr(S, "ui_access_token_secret", "") or ""
    access_cookie_name = getattr(S, "ui_access_token_cookie_name", "") or ""
    if access_secret and access_cookie_name:
        cookie_val = request.cookies.get(access_cookie_name, "")
        if cookie_val:
            try:
                payload = _jwt.decode(
                    cookie_val,
                    access_secret,
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                if str(payload.get("role", "")).lower() == "root":
                    return True
            except _jwt.PyJWTError:
                pass

    # 2. Dev-mode header fallback, mirroring the dev header fallback in
    #    app/auth/deps.py. Gated on S.dev_mode so it is inert in production.
    if S.dev_mode and request.headers.get("x-user-role", "").lower() == "root":
        return True

    return False


class TenantMiddleware(BaseHTTPMiddleware):
    """Resolve the current tenant for each request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Feature-flagged off — short-circuit to default tenant
        if not S.multi_tenancy_enabled:
            set_current_tenant(S.default_tenant_id)
            set_tenant_settings(None)
            request.state.tenant_id = S.default_tenant_id
            return await call_next(request)

        # Dev mode: accept X-Tenant-Id header
        tenant_id: Optional[str] = None
        tenant_record: Dict[str, Any] = {}

        if S.dev_mode:
            header_tid = request.headers.get("x-tenant-id", "").strip()
            if header_tid:
                tenant_id = header_tid
                from app.core.tables import T

                try:
                    t_resp = T.tenants.get_item(Key={"tenant_id": header_tid})
                    tenant_record = t_resp.get("Item") or {}
                except Exception:
                    pass

        # Resolve from Host header if not already set
        if not tenant_id:
            host = (request.headers.get("host") or "").split(":")[0].strip().lower()
            if host:
                result = _resolve_tenant_from_domain(host)
                if result:
                    tenant_id, tenant_record = result

        # Fallback to default
        if not tenant_id:
            tenant_id = S.default_tenant_id

        # Check tenant status
        status = str(tenant_record.get("status", "active")).lower()
        if status == "suspended":
            # ROOT sessions bypass the suspension wall so operators can
            # remediate (e.g. lift the suspension) without break-glass access.
            # Full auth still runs downstream in the router layer.
            if not _request_is_root(request):
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Tenant is suspended"},
                )
        if status == "deleted":
            return JSONResponse(
                status_code=410,
                content={"detail": "Tenant has been deleted"},
            )

        # Set context
        set_current_tenant(tenant_id)
        request.state.tenant_id = tenant_id

        # Load settings overrides
        overrides = tenant_record.get("settings_overrides")
        if isinstance(overrides, dict) and overrides:
            set_tenant_settings(TenantSettings(overrides))
        else:
            set_tenant_settings(None)

        return await call_next(request)
