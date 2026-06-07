"""Offline regression test for GAP-0380 (VOD-017).

Bug: ``app/services/video_comments.py`` stored video comments in the
``T.video_views`` table under a ``VCOMMENT#`` prefix. VideoViews items carry a
90-day TTL (``video_gallery.py`` writes ``ttl = ts + 90*86400``), so comments
were co-mingled with view records in a TTL-enabled table and would be
TTL-deleted after 90 days — silent data loss.

Fix: comments now live in a DEDICATED ``video_comments`` table (no TTL).

This test is fully hermetic: in-memory moto DynamoDB tables are created mirroring
the ``scripts/local-ddb-init.py`` TableDefs and bound onto the FROZEN ``T``
handles via ``object.__setattr__`` (restored on cleanup). The service functions
are called directly. It asserts:
  * ``add_comment`` writes to ``video_comments`` (NOT ``video_views``),
  * the stored item has NO ``ttl`` attribute (fails-before: lived in TTL'd table),
  * ``list_comments`` returns comments newest-first,
  * ``delete_comment`` removes one and is owner-scoped (403 for non-author).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_video_comments_table(ddb):
    """Mirror the video_comments TableDef from scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="VideoComments",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "video_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByVideoCreatedAt",
                "KeySchema": [
                    {"AttributeName": "video_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_video_metadata_table(ddb):
    return ddb.create_table(
        TableName="VideoMetadata",
        KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "video_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_video_views_table(ddb):
    return ddb.create_table(
        TableName="VideoViews",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestVideoCommentsTableGap0380(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.comments_table = _make_video_comments_table(ddb)
        self.metadata_table = _make_video_metadata_table(ddb)
        self.views_table = _make_video_views_table(ddb)

        from app.core.tables import T

        self.T = T
        # Bind moto tables onto the FROZEN T via object.__setattr__, restore after.
        for name, tbl in (
            ("video_comments", self.comments_table),
            ("video_metadata", self.metadata_table),
            ("video_views", self.views_table),
        ):
            orig = getattr(T, name)
            object.__setattr__(T, name, tbl)
            self.addCleanup(lambda n=name, o=orig: object.__setattr__(T, n, o))

        from app.services import video_comments

        self.svc = video_comments

    def test_add_comment_writes_to_video_comments_no_ttl(self):
        """Comment lands in video_comments (NOT video_views) and has no ttl."""
        res = self.svc.add_comment(video_id="vid1", user_id="alice", text="hello")
        self.assertEqual(res["video_id"], "vid1")
        self.assertEqual(res["user_id"], "alice")
        self.assertEqual(res["text"], "hello")

        # Stored in the dedicated comments table...
        items = self.comments_table.scan().get("Items", [])
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["pk"], "VIDEO#vid1")
        self.assertTrue(item["sk"].startswith("COMMENT#"))
        self.assertEqual(item["comment_id"], res["comment_id"])
        # ...with NO ttl attribute (fails-before: comments lived in TTL'd table).
        self.assertNotIn("ttl", item)

        # ...and NOT in the video_views table.
        self.assertEqual(self.views_table.scan().get("Items", []), [])

        # comment_count incremented on metadata.
        meta = self.metadata_table.get_item(Key={"video_id": "vid1"}).get("Item")
        self.assertEqual(int(meta["comment_count"]), 1)

    def test_list_comments_newest_first(self):
        self.svc.add_comment(video_id="vid2", user_id="alice", text="first")
        # bump now_ts so SK ordering is deterministic
        import app.services.video_comments as vc

        orig_now = vc.now_ts
        try:
            vc.now_ts = lambda: orig_now() + 100  # type: ignore[assignment]
            self.svc.add_comment(video_id="vid2", user_id="bob", text="second")
        finally:
            vc.now_ts = orig_now  # type: ignore[assignment]

        out = self.svc.list_comments(video_id="vid2")
        texts = [c["text"] for c in out["comments"]]
        self.assertEqual(texts, ["second", "first"])

    def test_delete_comment_owner_scoped(self):
        c = self.svc.add_comment(video_id="vid3", user_id="alice", text="mine")
        cid = c["comment_id"]

        # Non-author cannot delete (403).
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            self.svc.delete_comment(video_id="vid3", comment_id=cid, user_id="bob")
        self.assertEqual(ctx.exception.status_code, 403)

        # Comment still present.
        self.assertEqual(len(self.comments_table.scan().get("Items", [])), 1)

        # Author can delete.
        self.svc.delete_comment(video_id="vid3", comment_id=cid, user_id="alice")
        self.assertEqual(self.comments_table.scan().get("Items", []), [])

        # 404 for a missing comment.
        with self.assertRaises(HTTPException) as ctx2:
            self.svc.delete_comment(video_id="vid3", comment_id="nope", user_id="alice")
        self.assertEqual(ctx2.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
