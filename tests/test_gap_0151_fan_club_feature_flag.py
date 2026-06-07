"""Regression test for GAP-0151.

The ``FAN_CLUBS_ENABLED`` feature flag (``S.fan_clubs_enabled``) must be
enforced at the fan-club router level. Before the fix, ``app/routers/fan_club.py``
contained no reference to the flag and all 19 endpoints stayed live even when
``FAN_CLUBS_ENABLED=0``.

The fix adds a ``_check_enabled()`` guard wired as a router-level dependency
(``dependencies=[Depends(_check_enabled)]``) on BOTH ``router`` and
``public_router``, mirroring ``app/routers/collaborations.py:88``.

Fully offline: no AWS / DynamoDB / TestClient. We call the guard coroutine/fn
directly and inspect the router dependency wiring. ``S`` is a frozen dataclass,
so the flag is toggled via ``object.__setattr__`` and restored afterwards.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.core.settings import S
from app.routers import fan_club


def _set_flag(value: bool) -> None:
    object.__setattr__(S, "fan_clubs_enabled", value)


@pytest.fixture(autouse=True)
def _restore_flag():
    original = S.fan_clubs_enabled
    try:
        yield
    finally:
        object.__setattr__(S, "fan_clubs_enabled", original)


def test_check_enabled_blocks_when_flag_off():
    """FAILS-BEFORE (no guard existed); PASSES-AFTER: flag off -> 503."""
    _set_flag(False)
    with pytest.raises(HTTPException) as exc:
        fan_club._check_enabled()
    assert exc.value.status_code == 503
    assert "disabled" in str(exc.value.detail).lower()


def test_check_enabled_allows_when_flag_on():
    """Flag on -> guard is a no-op (does not raise)."""
    _set_flag(True)
    # Must not raise.
    assert fan_club._check_enabled() is None


def test_guard_wired_as_dependency_on_both_routers():
    """The guard must be applied at the router level so no handler is missed."""
    for rtr in (fan_club.router, fan_club.public_router):
        dep_calls = [d.dependency for d in rtr.dependencies]
        assert fan_club._check_enabled in dep_calls, (
            f"_check_enabled must be a router-level dependency on {rtr}"
        )


def test_every_route_inherits_the_guard():
    """Each registered route on both routers carries the flag guard.

    This is the offline equivalent of asserting every endpoint returns 503
    when the flag is off: FastAPI evaluates router-level dependencies before
    the handler for every route, so presence on each route == enforcement.
    """
    for rtr in (fan_club.router, fan_club.public_router):
        assert rtr.routes, f"{rtr} has no routes"
        for route in rtr.routes:
            dep_calls = [d.call for d in getattr(route, "dependant").dependencies]
            assert fan_club._check_enabled in dep_calls, (
                f"route {getattr(route, 'path', route)!r} is not guarded by _check_enabled"
            )
