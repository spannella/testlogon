from __future__ import annotations

from scripts.backfill_admin_profiles_general import _should_backfill


def test_should_backfill_non_admin_is_skipped() -> None:
    should_update, reason, current, desired = _should_backfill({"user_sub": "u1", "role": "user"})
    assert should_update is False
    assert reason == "non_admin"
    assert current == {"type": "general"}
    assert desired == {"type": "general"}


def test_should_backfill_admin_with_missing_profile() -> None:
    should_update, reason, current, desired = _should_backfill({"user_sub": "a1", "role": "admin"})
    assert should_update is True
    assert reason == "missing_or_malformed_profile"
    assert current == {"type": "general"}
    assert desired == {"type": "general"}


def test_should_backfill_admin_with_malformed_profile() -> None:
    should_update, reason, current, desired = _should_backfill(
        {"user_sub": "a1", "role": "admin", "admin_profile": {"type": "scoped", "scopes": ["unknown"]}}
    )
    assert should_update is True
    assert reason == "missing_or_malformed_profile"
    assert current == {"type": "general"}
    assert desired == {"type": "general"}


def test_should_backfill_admin_with_general_profile_is_idempotent() -> None:
    should_update, reason, current, desired = _should_backfill(
        {"user_sub": "a1", "role": "admin", "admin_profile": {"type": "general"}}
    )
    assert should_update is False
    assert reason == "already_general"
    assert current == {"type": "general"}
    assert desired == {"type": "general"}


def test_should_backfill_admin_with_scoped_profile_is_preserved() -> None:
    should_update, reason, current, desired = _should_backfill(
        {"user_sub": "a1", "role": "admin", "admin_profile": {"type": "scoped", "scopes": ["billing_support"]}}
    )
    assert should_update is False
    assert reason == "already_scoped"
    assert current == {"type": "scoped", "scopes": ["billing_support"]}
    assert desired == {"type": "general"}
