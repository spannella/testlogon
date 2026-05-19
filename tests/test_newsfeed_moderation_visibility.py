from __future__ import annotations

from app.routers import newsfeed


def test_list_comments_excludes_deleted_and_moderation_removed(monkeypatch) -> None:
    monkeypatch.setattr(newsfeed, "ddb_get_item", lambda key: {"post_id": "p1", "locked": False, "user_id": "owner"})
    monkeypatch.setattr(
        newsfeed,
        "ddb_query",
        lambda **kwargs: {
            "Items": [
                {"comment_id": "c1", "post_id": "p1", "deleted": False, "moderation_removed": False, "body": "ok", "body_format": "plain", "body_version": 1},
                {"comment_id": "c2", "post_id": "p1", "deleted": True, "body": "gone", "body_format": "plain", "body_version": 1},
                {"comment_id": "c3", "post_id": "p1", "deleted": False, "moderation_removed": True, "body": "gone", "body_format": "plain", "body_version": 1},
            ]
        },
    )
    monkeypatch.setattr(newsfeed, "has_unlocked", lambda user_id, post_id: True)

    out = newsfeed.list_comments("p1", cursor=None, user_id="viewer")
    assert [i["comment_id"] for i in out["items"]] == ["c1", "c2"]
