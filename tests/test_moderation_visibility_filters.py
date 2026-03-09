from __future__ import annotations

from app.routers import messaging


def test_filter_message_visible_hides_moderation_hidden() -> None:
    assert messaging._filter_message_visible({"moderation_hidden": True, "deleted_for": []}, "u1") is False


def test_filter_message_visible_hides_moderation_removed_at() -> None:
    assert messaging._filter_message_visible({"moderation_removed_at": 1700000000, "deleted_for": []}, "u1") is False
