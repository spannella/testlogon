"""Offline regression tests for emoji reactions on newsfeed comments.

Mirrors the existing post-reaction feature (POST /posts/{id}/reactions +
/unreact, the nested-map ``reactions: {emoji: {user_id: True}}`` storage shape,
and the ``reactions_counts`` / ``my_reactions`` projection) but for comments:

  - POST /posts/{post_id}/comments/{comment_id}/reactions
  - POST /posts/{post_id}/comments/{comment_id}/unreact

Covers:
  - react adds the viewer to the emoji map (nested-map shape on the comment item)
  - idempotent re-react (same viewer + emoji) does not duplicate
  - unreact removes the viewer (and prunes the empty emoji bucket)
  - invalid emoji -> 422 (validation, before any DDB write)
  - reactions_counts / my_reactions projection is correct *per viewer*
  - reacting to ANOTHER user's comment works

Isolation: a real in-memory DynamoDB is created with moto and the newsfeed
router's module-level ``tbl`` handle is monkeypatched to it (restored on
cleanup). The table has the GSI2 index the comment list path queries. The route
handlers are invoked directly (no FastAPI TestClient); social-alert emission is
patched to a no-op so notifications never touch real infra. No real AWS / no
network.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import boto3
from pydantic import ValidationError

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

import app.routers.newsfeed as nf
from fastapi import HTTPException


APP_TABLE = "newsfeed_comment_reactions_test"


def _make_table(ddb):
    return ddb.create_table(
        TableName=APP_TABLE,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


POST_ID = "p_1"
COMMENT_ID = "c_1"
AUTHOR = "user_author"
ALICE = "user_alice"
BOB = "user_bob"


@unittest.skipIf(mock_aws is None, "moto not installed")
class CommentReactionsTest(unittest.TestCase):
    def setUp(self):
        self._mock = mock_aws()
        self._mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._tbl = _make_table(ddb)
        self._orig_tbl = nf.tbl
        nf.tbl = self._tbl

        # Seed the post META + one comment owned by AUTHOR.
        self._tbl.put_item(Item={
            "pk": nf.pk_post(POST_ID),
            "sk": nf.sk_post(),
            "Entity": "Post",
            "user_id": AUTHOR,
            "status": "published",
        })
        self._created_at = "2026-01-01T00:00:00+00:00"
        self._tbl.put_item(Item={
            "pk": nf.pk_post_comments(POST_ID),
            "sk": f"{self._created_at}#CMT#{COMMENT_ID}",
            "Entity": "Comment",
            "comment_id": COMMENT_ID,
            "post_id": POST_ID,
            "user_id": AUTHOR,
            "created_at": self._created_at,
            "updated_at": None,
            "deleted": False,
            "parent_comment_id": None,
            "body": "hello",
            "body_plain": "hello",
            "body_format": "plain",
            "body_version": 1,
            "version": 1,
            "tip_total_cents": 0,
            "kind": "text",
            "GSI2PK": nf.pk_post_comments(POST_ID),
            "GSI2SK": f"{self._created_at}#CMT#{COMMENT_ID}",
        })

        # Best-effort social alert -> no-op so we never touch alert infra.
        self._alert_patch = patch.object(nf, "emit_social_alert", return_value=None)
        self._alert_patch.start()

    def tearDown(self):
        self._alert_patch.stop()
        nf.tbl = self._orig_tbl
        self._mock.stop()

    # ---- helpers -----------------------------------------------------
    def _raw_comment(self):
        return self._tbl.get_item(Key={
            "pk": nf.pk_post_comments(POST_ID),
            "sk": f"{self._created_at}#CMT#{COMMENT_ID}",
        }).get("Item")

    def _list(self, viewer):
        return nf.list_comments(POST_ID, limit=20, cursor=None, user_id=viewer)["items"]

    def _comment_for_viewer(self, viewer):
        items = self._list(viewer)
        return next(c for c in items if c["comment_id"] == COMMENT_ID)

    # ---- tests -------------------------------------------------------
    def test_react_adds_to_nested_map(self):
        res = nf.add_comment_reaction(POST_ID, COMMENT_ID, nf.CommentReactionRequest(emoji="🔥"), ALICE)
        self.assertEqual(res, {"ok": True})
        reactions = self._raw_comment().get("reactions")
        self.assertEqual(reactions, {"🔥": {ALICE: True}})

    def test_idempotent_re_react(self):
        req = nf.CommentReactionRequest(emoji="❤️")
        nf.add_comment_reaction(POST_ID, COMMENT_ID, req, ALICE)
        nf.add_comment_reaction(POST_ID, COMMENT_ID, req, ALICE)
        reactions = self._raw_comment().get("reactions")
        self.assertEqual(reactions, {"❤️": {ALICE: True}})
        self.assertEqual(self._comment_for_viewer(ALICE)["reactions_counts"], {"❤️": 1})

    def test_unreact_removes_viewer_and_prunes_bucket(self):
        req = nf.CommentReactionRequest(emoji="👍")
        nf.add_comment_reaction(POST_ID, COMMENT_ID, req, ALICE)
        nf.add_comment_reaction(POST_ID, COMMENT_ID, req, BOB)
        # Bob unreacts -> bucket keeps Alice
        nf.remove_comment_reaction(POST_ID, COMMENT_ID, req, BOB)
        self.assertEqual(self._raw_comment().get("reactions"), {"👍": {ALICE: True}})
        # Alice unreacts -> empty bucket pruned away
        nf.remove_comment_reaction(POST_ID, COMMENT_ID, req, ALICE)
        self.assertEqual(self._raw_comment().get("reactions"), {})

    def test_invalid_emoji_422(self):
        # The validated request model rejects out-of-allowlist emoji (FastAPI -> 422).
        with self.assertRaises(ValidationError):
            nf.CommentReactionRequest(emoji="🍕")
        # Allowlist matches the post reaction bar exactly.
        self.assertEqual(
            set(nf.ALLOWED_REACTION_EMOJIS), {"👍", "❤️", "😂", "🔥", "😮"},
        )

    def test_projection_per_viewer(self):
        nf.add_comment_reaction(POST_ID, COMMENT_ID, nf.CommentReactionRequest(emoji="😂"), ALICE)
        nf.add_comment_reaction(POST_ID, COMMENT_ID, nf.CommentReactionRequest(emoji="😂"), BOB)
        nf.add_comment_reaction(POST_ID, COMMENT_ID, nf.CommentReactionRequest(emoji="😮"), ALICE)

        alice_view = self._comment_for_viewer(ALICE)
        self.assertEqual(alice_view["reactions_counts"], {"😂": 2, "😮": 1})
        self.assertEqual(sorted(alice_view["my_reactions"]), sorted(["😂", "😮"]))

        bob_view = self._comment_for_viewer(BOB)
        self.assertEqual(bob_view["reactions_counts"], {"😂": 2, "😮": 1})
        self.assertEqual(bob_view["my_reactions"], ["😂"])

        # A viewer with no reactions sees counts but no own reactions.
        carol_view = self._comment_for_viewer("user_carol")
        self.assertEqual(carol_view["reactions_counts"], {"😂": 2, "😮": 1})
        self.assertEqual(carol_view["my_reactions"], [])

    def test_react_to_another_users_comment(self):
        # AUTHOR owns the comment; ALICE (a different user) reacts -> works.
        res = nf.add_comment_reaction(POST_ID, COMMENT_ID, nf.CommentReactionRequest(emoji="🔥"), ALICE)
        self.assertEqual(res, {"ok": True})
        self.assertEqual(self._comment_for_viewer(AUTHOR)["reactions_counts"], {"🔥": 1})

    def test_react_missing_comment_404(self):
        with self.assertRaises(HTTPException) as ctx:
            nf.add_comment_reaction(POST_ID, "c_missing", nf.CommentReactionRequest(emoji="🔥"), ALICE)
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
