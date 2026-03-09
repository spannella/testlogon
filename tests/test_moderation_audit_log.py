from __future__ import annotations

from app.services import moderation_audit_log


def test_write_moderation_audit_event_puts_immutable_row(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(moderation_audit_log.T.moderation_audit_log, "put_item", lambda **kwargs: calls.append(kwargs) or {})

    audit_id = moderation_audit_log.write_moderation_audit_event(
        action="ticket_resolved",
        actor_user_id="admin_1",
        ticket_id="modtk_1",
        report_id="rpt_1",
        content_type="feed_post",
        content_id="post_1",
        target_user_id="user_1",
        metadata={"resolution": "content_removed"},
    )

    assert audit_id.startswith("modaudit_")
    assert calls
    item = calls[0]["Item"]
    assert item["entity_type"] == "moderation_audit_event"
    assert item["action"] == "ticket_resolved"
    assert item["ticket_id"] == "modtk_1"
    assert item["metadata"]["resolution"] == "content_removed"
