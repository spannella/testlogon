from __future__ import annotations

from app.services import moderation_policy_engine


def test_issue_warning_notification_writes_alert(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(moderation_policy_engine, "write_alert", lambda *args, **kwargs: calls.append((args, kwargs)) or {"alert_id": "a1"})

    moderation_policy_engine.issue_warning_notification(
        offender_user_id="u1",
        ticket_id="t1",
        note="watch it",
        policy_category="criminal",
    )

    assert calls
    args, kwargs = calls[0]
    assert args[0] == "u1"
    assert kwargs["event"] == "moderation_warning"
    assert kwargs["details"]["ticket_id"] == "t1"
    assert kwargs["details"]["policy_category"] == "criminal"


def test_notify_content_removal_writes_alert(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(moderation_policy_engine, "write_alert", lambda *args, **kwargs: calls.append((args, kwargs)) or {"alert_id": "a1"})

    moderation_policy_engine.notify_content_removal(
        offender_user_id="u1",
        ticket_id="t1",
        content_type="feed_post",
        policy_category="sexual",
        note="removed after review",
    )

    assert calls
    args, kwargs = calls[0]
    assert args[0] == "u1"
    assert kwargs["event"] == "moderation_content_removed"
    assert kwargs["details"]["policy_category"] == "sexual"
    assert kwargs["details"]["content_type"] == "feed_post"


def test_apply_ban_updates_account_state_and_alert(monkeypatch) -> None:
    put_calls = []
    alert_calls = []

    monkeypatch.setattr(moderation_policy_engine, "now_ts", lambda: 1700000000)
    monkeypatch.setattr(moderation_policy_engine.T.account_state, "put_item", lambda **kwargs: put_calls.append(kwargs) or {})
    monkeypatch.setattr(moderation_policy_engine, "write_alert", lambda *args, **kwargs: alert_calls.append((args, kwargs)) or {"alert_id": "a2"})

    out = moderation_policy_engine.apply_ban(
        offender_user_id="u2",
        ticket_id="t2",
        admin_user_id="admin_1",
        note="policy violation",
        duration_days=7,
        policy_category="extortion",
    )

    assert out["status"] == "banned"
    assert out["ban_until"] == 1700000000 + (7 * 86400)
    assert put_calls
    item = put_calls[0]["Item"]
    assert item["status"] == "banned"
    assert item["source_ticket_id"] == "t2"
    assert item["ban_duration_days"] == 7
    assert alert_calls
    _args, kwargs = alert_calls[0]
    assert kwargs["details"]["policy_category"] == "extortion"
    assert kwargs["details"]["effective_duration"] == "7 days"


def test_is_user_currently_banned_honors_expiry(monkeypatch) -> None:
    monkeypatch.setattr(moderation_policy_engine, "now_ts", lambda: 1700000500)
    monkeypatch.setattr(
        moderation_policy_engine.T.account_state,
        "get_item",
        lambda Key: {"Item": {"user_sub": "u3", "status": "banned", "ban_until": 1700000400}},
    )

    assert moderation_policy_engine.is_user_currently_banned("u3") is False
