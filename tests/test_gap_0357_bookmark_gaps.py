"""Offline regression tests for GAP-0357 (bookmark sub-gaps, shared w/ FEED-009).

Three sub-gaps in `app/routers/newsfeed.py`:
  1. `_post_to_dict` now accepts `bookmarked_ids` and emits `is_bookmarked`.
  2. New `PATCH /ui/bookmarks/{content_type}/{content_id}` move-bookmark endpoint
     (owner-scoped: 404 for a foreign/missing bookmark).
  3. `list_bookmarks` enriches `content_type == "video"` bookmarks with video
     metadata (previously returned an empty content_preview).

Sub-gaps 2 and 3 hit DynamoDB, so the app_single_table is created in-memory with
moto and `newsfeed.tbl` is patched to it. Sub-gap 1 is a pure function call.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.routers import newsfeed


def _make_app_table(ddb):
    return ddb.create_table(
        TableName="app_single_table",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class TestIsBookmarkedField(unittest.TestCase):
    """Sub-gap 1: pure function — no DDB."""

    def test_is_bookmarked_true_when_in_set(self):
        post = {"post_id": "post_1", "user_id": "author_a"}
        d = newsfeed._post_to_dict(post, bookmarked_ids={"post_1"})
        self.assertTrue(d["is_bookmarked"])

    def test_is_bookmarked_false_when_not_in_set(self):
        post = {"post_id": "post_2", "user_id": "author_a"}
        d = newsfeed._post_to_dict(post, bookmarked_ids={"post_1"})
        self.assertFalse(d["is_bookmarked"])

    def test_is_bookmarked_default_false(self):
        post = {"post_id": "post_3", "user_id": "author_a"}
        d = newsfeed._post_to_dict(post)
        self.assertFalse(d["is_bookmarked"])


@unittest.skipIf(mock_aws is None, "moto not installed")
class TestMoveBookmarkEndpoint(unittest.TestCase):
    def setUp(self):
        self._mock = mock_aws()
        self._mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_app_table(ddb)
        self._patch = patch.object(newsfeed, "tbl", self.table)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._mock.stop()

    def _seed_bookmark(self, user_id, content_id, collection_id="default"):
        req = newsfeed.CreateBookmarkRequest(
            content_type="post", content_id=content_id, collection_id=collection_id
        )
        post = {"pk": newsfeed.pk_post(content_id), "sk": newsfeed.sk_post(), "user_id": user_id}
        with patch.object(newsfeed, "ddb_get_item", side_effect=[post, None]):
            newsfeed.create_bookmark(req, user_id)

    def test_move_changes_collection_id(self):
        self._seed_bookmark("alice", "abc", collection_id="default")
        out = newsfeed.move_bookmark(
            "post", "abc", newsfeed.MoveBookmarkRequest(collection_id="travel"), "alice"
        )
        self.assertEqual(out["collection_id"], "travel")
        # The main bookmark item now reflects the new collection.
        item = self.table.get_item(
            Key={"pk": newsfeed.pk_bookmark("alice"), "sk": "post#abc"}
        ).get("Item")
        self.assertEqual(item["collection_id"], "travel")
        # The lookup item is kept in sync.
        lookup = self.table.get_item(
            Key={"pk": newsfeed.pk_bookmark_lookup("alice"), "sk": "post#abc"}
        ).get("Item")
        self.assertEqual(lookup["collection_id"], "travel")

    def test_move_missing_bookmark_404(self):
        with self.assertRaises(HTTPException) as ctx:
            newsfeed.move_bookmark(
                "post", "nope", newsfeed.MoveBookmarkRequest(collection_id="travel"), "alice"
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_move_is_owner_scoped(self):
        # Bob owns the bookmark; Alice may not move it (different partition → 404).
        self._seed_bookmark("bob", "xyz", collection_id="default")
        with self.assertRaises(HTTPException) as ctx:
            newsfeed.move_bookmark(
                "post", "xyz", newsfeed.MoveBookmarkRequest(collection_id="travel"), "alice"
            )
        self.assertEqual(ctx.exception.status_code, 404)
        # Bob's bookmark is untouched.
        item = self.table.get_item(
            Key={"pk": newsfeed.pk_bookmark("bob"), "sk": "post#xyz"}
        ).get("Item")
        self.assertEqual(item["collection_id"], "default")


@unittest.skipIf(mock_aws is None, "moto not installed")
class TestVideoBookmarkEnrichment(unittest.TestCase):
    def setUp(self):
        self._mock = mock_aws()
        self._mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_app_table(ddb)
        self._patch = patch.object(newsfeed, "tbl", self.table)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._mock.stop()

    def test_list_bookmarks_enriches_video(self):
        # Seed a video bookmark (content existence check is skipped for videos).
        req = newsfeed.CreateBookmarkRequest(content_type="video", content_id="vid123")
        with patch.object(newsfeed, "ddb_get_item", return_value=None):
            newsfeed.create_bookmark(req, "alice")

        fake_video = SimpleNamespace(
            title="My Cool Video",
            thumbnail_url="https://x/thumb.jpg",
            owner_user_id="creator_c",
            duration_seconds=42.0,
            view_count=99,
        )
        with patch("app.services.video_metadata_store.get_video", return_value=fake_video), \
             patch.object(newsfeed, "_post_fadt_display_name", return_value="Creator"):
            out = newsfeed.list_bookmarks("alice", limit=24, cursor=None, content_type=None, collection_id=None)

        vid_bk = next((b for b in out["bookmarks"] if b["content_type"] == "video"), None)
        self.assertIsNotNone(vid_bk)
        self.assertEqual(vid_bk["content_preview"]["title"], "My Cool Video")
        self.assertEqual(vid_bk["content_preview"]["creator_id"], "creator_c")
        self.assertEqual(vid_bk["content_preview"]["view_count"], 99)


if __name__ == "__main__":
    unittest.main()
