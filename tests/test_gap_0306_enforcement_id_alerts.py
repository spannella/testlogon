"""GAP-0306: enforcement_id must be included in warning/ban alert details.

Offline/hermetic: patches `write_alert` (and `account_state.put_item` for the ban
path) on the `moderation_policy_engine` module so no DDB/AWS calls are made.
Asserts the captured alert `details` dict carries the passed `enforcement_id`.

Before the fix, the notification helpers did not accept an `enforcement_id` kwarg,
so calling them with it would raise TypeError. After the fix, the kwarg is accepted
and the value is merged into the alert details.
"""
from __future__ import annotations

from types import SimpleNamespace

import app.services.moderation_policy_engine as mpe


def test_issue_warning_notification_includes_enforcement_id(monkeypatch) -> None:
    calls: list[dict] = []
    monkeypatch.setattr(
        mpe, "write_alert",
        lambda *a, **kw: calls.append(kw) or {"alert_id": "x"},
    )

    mpe.issue_warning_notification(
        offender_user_id="u10",
        ticket_id="t10",
        note="test",
        policy_category="spam",
        enforcement_id="enf_test123",
    )

    assert len(calls) == 1
    assert calls[0]["details"]["enforcement_id"] == "enf_test123"


def test_apply_ban_alert_includes_enforcement_id(monkeypatch) -> None:
    calls: list[dict] = []
    monkeypatch.setattr(
        mpe, "write_alert",
        lambda *a, **kw: calls.append(kw) or {"alert_id": "y"},
    )

    # T is a frozen dataclass; replace the whole account_state handle via
    # object.__setattr__ with a stub, and restore it afterwards.
    original = mpe.T.account_state
    object.__setattr__(mpe.T, "account_state", SimpleNamespace(put_item=lambda **kw: None))
    try:
        mpe.apply_ban(
            offender_user_id="u11",
            ticket_id="t11",
            admin_user_id="admin1",
            note="ban",
            duration_days=0,
            policy_category="criminal",
            enforcement_id="enf_test123",
        )
    finally:
        object.__setattr__(mpe.T, "account_state", original)

    assert len(calls) == 1
    assert calls[0]["details"]["enforcement_id"] == "enf_test123"


def test_warning_without_enforcement_id_omits_key(monkeypatch) -> None:
    """Backward compatibility: no enforcement_id -> key absent (not None)."""
    calls: list[dict] = []
    monkeypatch.setattr(
        mpe, "write_alert",
        lambda *a, **kw: calls.append(kw) or {"alert_id": "x"},
    )

    mpe.issue_warning_notification(
        offender_user_id="u12",
        ticket_id="t12",
        note="test",
        policy_category="spam",
    )

    assert "enforcement_id" not in calls[0]["details"]
