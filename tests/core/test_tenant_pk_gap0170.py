"""GAP-0170: tenant_pk() / tenant_pk_for() must namespace DynamoDB keys.

ENTERPRISE-001 introduced a multi-tenancy helper that is intended to prefix
every DynamoDB partition key with ``TENANT#<tid>#`` when
``multi_tenancy_enabled`` is True. The gap: the helper had no companion
``tenant_pk_for()`` wrapper for already-assembled bare keys, so service files
could not incrementally adopt tenant scoping. This test verifies the wrapper
exists and produces non-overlapping keys per tenant.

Fully offline — no AWS, no moto. Exercises the real (frozen) ``S`` settings
object via ``object.__setattr__`` rather than mocking it, then restores it.
"""
from __future__ import annotations

import contextlib

import pytest

from app.core import tenant as tenant_mod
from app.core.settings import S
from app.core.tenant import (
    get_current_tenant,
    set_current_tenant,
    tenant_pk,
    tenant_pk_for,
)


@contextlib.contextmanager
def _multi_tenancy(enabled: bool):
    """Temporarily flip the FROZEN S.multi_tenancy_enabled flag, then restore.

    S is a frozen dataclass; use object.__setattr__ to mutate it. The tenant
    context var is also reset to 'default' on exit so tests don't leak state.
    """
    prev = S.multi_tenancy_enabled
    prev_tenant = get_current_tenant()
    object.__setattr__(S, "multi_tenancy_enabled", enabled)
    try:
        yield
    finally:
        object.__setattr__(S, "multi_tenancy_enabled", prev)
        set_current_tenant(prev_tenant)


def test_tenant_pk_disabled_returns_bare_key():
    with _multi_tenancy(False):
        assert tenant_pk("USER", "alice_sub") == "USER#alice_sub"


def test_tenant_pk_enabled_returns_scoped_key():
    with _multi_tenancy(True):
        set_current_tenant("tenant_acme")
        assert tenant_pk("USER", "alice_sub") == "TENANT#tenant_acme#USER#alice_sub"


def test_tenant_pk_for_disabled_is_passthrough():
    """Default (single-tenant) behaviour: bare key unchanged — dev/prod parity."""
    with _multi_tenancy(False):
        assert tenant_pk_for("USER#alice_sub") == "USER#alice_sub"


def test_tenant_pk_for_enabled_scopes_key():
    with _multi_tenancy(True):
        set_current_tenant("tenant_beta")
        assert tenant_pk_for("CONV#conv_abc") == "TENANT#tenant_beta#CONV#conv_abc"


def test_different_tenants_produce_different_keys():
    """Core isolation guarantee (fails before fix: tenant_pk_for did not exist).

    Two tenants sharing the same entity ID must produce non-overlapping
    partition keys, so a query scoped to tenant A can never return tenant B's
    item.
    """
    with _multi_tenancy(True):
        set_current_tenant("tenant_a")
        key_a = tenant_pk_for("USER#alice")

        set_current_tenant("tenant_b")
        key_b = tenant_pk_for("USER#alice")

    assert key_a != key_b, (
        "GAP-0170: two tenants produce the same DynamoDB key — no isolation"
    )
    assert key_a == "TENANT#tenant_a#USER#alice"
    assert key_b == "TENANT#tenant_b#USER#alice"


def test_tenant_pk_for_consistent_with_tenant_pk():
    """tenant_pk_for(f'{p}#{i}') must equal tenant_pk(p, i) for both flag states."""
    with _multi_tenancy(False):
        assert tenant_pk_for("USER#abc") == tenant_pk("USER", "abc")
    with _multi_tenancy(True):
        set_current_tenant("tenant_x")
        assert tenant_pk_for("USER#abc") == tenant_pk("USER", "abc")


def test_module_exports_tenant_pk_for():
    """Regression guard: the wrapper must be importable from app.core.tenant."""
    assert hasattr(tenant_mod, "tenant_pk_for")
    assert callable(tenant_mod.tenant_pk_for)
