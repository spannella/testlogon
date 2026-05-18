from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import google_calendar_flags as flags


def test_sync_flag_defaults_to_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=False,
            google_calendar_writeback_enabled=True,
            google_calendar_sync_rollout_mode="all",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=100,
        ),
    )
    assert flags.is_google_calendar_sync_enabled() is False
    assert flags.is_google_calendar_sync_enabled_for_user("user-1") is False
    assert flags.is_google_calendar_writeback_enabled() is False


def test_writeback_requires_both_sync_and_writeback_flags(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=False,
            google_calendar_sync_rollout_mode="all",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=100,
        ),
    )
    assert flags.is_google_calendar_sync_enabled() is True
    assert flags.is_google_calendar_writeback_enabled() is False

    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=True,
            google_calendar_sync_rollout_mode="all",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=100,
        ),
    )
    assert flags.is_google_calendar_writeback_enabled() is True


def test_cohort_mode_honors_allowlist(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=True,
            google_calendar_sync_rollout_mode="cohort",
            google_calendar_sync_rollout_cohort_user_subs="alpha,beta",
            google_calendar_sync_rollout_percent=0,
        ),
    )

    assert flags.is_google_calendar_sync_enabled_for_user("alpha") is True
    assert flags.is_google_calendar_sync_enabled_for_user("gamma") is False
    assert flags.is_google_calendar_writeback_enabled_for_user("gamma") is False


def test_cohort_mode_supports_percent_rollout(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=True,
            google_calendar_sync_rollout_mode="cohort",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=100,
        ),
    )
    assert flags.is_google_calendar_sync_enabled_for_user("any-user") is True


def test_require_sync_enabled_for_user_raises_feature_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=False,
            google_calendar_sync_rollout_mode="cohort",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=0,
        ),
    )

    with pytest.raises(flags.HTTPException) as exc:
        flags.require_google_calendar_sync_enabled_for_user("outside-user")

    assert exc.value.status_code == 403
    assert exc.value.detail == {"code": "feature_disabled", "feature": "google_calendar_sync"}


def test_require_writeback_enabled_raises_feature_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=False,
            google_calendar_sync_rollout_mode="all",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=100,
        ),
    )

    with pytest.raises(flags.HTTPException) as exc:
        flags.require_google_calendar_writeback_enabled()

    assert exc.value.status_code == 403
    assert exc.value.detail == {"code": "feature_disabled", "feature": "google_calendar_writeback"}


def test_require_helpers_pass_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(
        flags,
        "S",
        SimpleNamespace(
            google_calendar_sync_enabled=True,
            google_calendar_writeback_enabled=True,
            google_calendar_sync_rollout_mode="all",
            google_calendar_sync_rollout_cohort_user_subs="",
            google_calendar_sync_rollout_percent=100,
        ),
    )
    flags.require_google_calendar_sync_enabled()
    flags.require_google_calendar_sync_enabled_for_user("user-1")
    flags.require_google_calendar_writeback_enabled()
    flags.require_google_calendar_writeback_enabled_for_user("user-1")
