from __future__ import annotations

from app.services import moderation_content_removal


def test_apply_content_removal_feed_post_marks_removed(monkeypatch) -> None:
    updates = []

    class _Table:
        def update_item(self, **kwargs):
            updates.append(kwargs)
            return {}

    class _DDB:
        def Table(self, _name):
            return _Table()

    monkeypatch.setattr(moderation_content_removal, "ddb", _DDB())

    moderation_content_removal.apply_content_removal(
        ticket={"content_type": "feed_post", "content_id": "post_1"},
        reports=[{"metadata": {"post_id": "post_1"}}],
        ticket_id="modtk_1",
        admin_user_id="admin_1",
    )

    assert updates
    assert updates[0]["Key"] == {"pk": "POST#post_1", "sk": "META"}
    assert updates[0]["ExpressionAttributeValues"][":ticket"] == "modtk_1"


def test_apply_content_removal_message_hides_message(monkeypatch) -> None:
    update_calls = []

    class _Table:
        def get_item(self, **kwargs):
            return {"Item": {"conversation_id": "c1", "message_id": "m1", "text": "hello"}}

        def update_item(self, **kwargs):
            update_calls.append(kwargs)
            return {}

    class _DDB:
        def Table(self, _name):
            return _Table()

    monkeypatch.setattr(moderation_content_removal, "ddb", _DDB())

    moderation_content_removal.apply_content_removal(
        ticket={"content_type": "message", "content_id": "m1"},
        reports=[{"metadata": {"conversation_id": "c1"}}],
        ticket_id="modtk_2",
        admin_user_id="admin_2",
    )

    assert update_calls
    values = update_calls[0]["ExpressionAttributeValues"]
    assert values[":t"] is True
    assert values[":removed_text"] == "[removed by moderation]"


def test_apply_content_removal_profile_photo_reverts(monkeypatch) -> None:
    put_calls = []

    def _get_item(**kwargs):
        return {
            "Item": {
                "user_sub": "u1",
                "profile": {
                    "profile_photo_url": "https://cdn/new.jpg",
                    "previous_approved_profile_photo_url": "https://cdn/old.jpg",
                },
            }
        }

    def _put_item(**kwargs):
        put_calls.append(kwargs)
        return {}

    monkeypatch.setattr(moderation_content_removal.T.profile, "get_item", _get_item)
    monkeypatch.setattr(moderation_content_removal.T.profile, "put_item", _put_item)

    moderation_content_removal.apply_content_removal(
        ticket={"content_type": "profile_photo", "content_id": "u1"},
        reports=[{"metadata": {}}],
        ticket_id="modtk_3",
        admin_user_id="admin_3",
    )

    assert put_calls
    profile = put_calls[0]["Item"]["profile"]
    assert profile["profile_photo_url"] == "https://cdn/old.jpg"
    assert profile["moderation_last_removed_ticket_id"] == "modtk_3"
