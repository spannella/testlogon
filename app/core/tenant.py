"""
Multi-tenancy context variable system for tenant isolation.

ENTERPRISE-001: When multi_tenancy_enabled is True, all entity primary keys
are prefixed with the tenant ID to ensure data isolation.  When disabled
(the default), keys are generated without any tenant prefix.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Dict, Optional

from app.core.settings import S

_current_tenant: ContextVar[str] = ContextVar("current_tenant", default="default")
_current_tenant_settings: ContextVar[Optional["TenantSettings"]] = ContextVar(
    "current_tenant_settings", default=None,
)


def set_current_tenant(tenant_id: str) -> None:
    """Set the tenant ID for the current request context."""
    _current_tenant.set(tenant_id)


def get_current_tenant() -> str:
    """Get the tenant ID for the current request context."""
    return _current_tenant.get()


def tenant_pk(entity_prefix: str, entity_id: str) -> str:
    """Build a partition key, optionally scoped to the current tenant.

    When ``multi_tenancy_enabled`` is ``True``:
        ``TENANT#<tid>#<prefix>#<id>``
    Otherwise:
        ``<prefix>#<id>``
    """
    if S.multi_tenancy_enabled:
        tid = get_current_tenant()
        return f"TENANT#{tid}#{entity_prefix}#{entity_id}"
    return f"{entity_prefix}#{entity_id}"


class TenantSettings:
    """Per-request settings overlay.

    Attribute access checks the ``overrides`` dict first, then falls back
    to the global ``S`` singleton.
    """

    def __init__(self, overrides: Dict[str, Any] | None = None) -> None:
        object.__setattr__(self, "_overrides", overrides or {})

    def __getattr__(self, name: str) -> Any:
        overrides = object.__getattribute__(self, "_overrides")
        if name in overrides:
            return overrides[name]
        return getattr(S, name)

    def __repr__(self) -> str:
        overrides = object.__getattribute__(self, "_overrides")
        return f"TenantSettings(overrides={overrides!r})"


def set_tenant_settings(settings: TenantSettings | None) -> None:
    _current_tenant_settings.set(settings)


def get_tenant_settings() -> TenantSettings | None:
    return _current_tenant_settings.get()
