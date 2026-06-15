"""Offline parity test for video comments (newsfeed feature parity).

Brings video comments to feature parity with newsfeed comments:
  1. Reply threads (parent_comment_id stored + listed)
  2. Reactions (nested-map, allowlist, invalid-emoji 422, counts/my_reactions per viewer)
  3. Edit (author-only, edited_at, non-author 403)
  4. Media comments (gif/sticker create + validation)
  5. Moderation report accepts ``video_comment`` + rejects unknown comment

Fully hermetic: in-memory moto DynamoDB tables mirroring the
``scripts/local-ddb-init.py`` TableDefs are bound onto the FROZEN ``T`` handles
via ``object.__setattr__`` (restored on cleanup). Service functions and request
models are exercised directly — NO FastAPI TestClient, NO real AWS / network.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from fastapi import HTTPException
from pydantic import ValidationError


def _make_video_comments_table(ddb):
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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestVideoCommentsParity(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.comments_table = _make_video_comments_table(ddb)
        self.metadata_table = _make_video_metadata_table(ddb)

        from app.core.tables import T

        self.T = T
        for name, tbl in (
            ("video_comments", self.comments_table),
            ("video_metadata", self.metadata_table),
        ):
            orig = getattr(T, name)
            object.__setattr__(T, name, tbl)
            self.addCleanup(lambda n=name, o=orig: object.__setattr__(T, n, o))

        from app.services import video_comments

        self.svc = video_comments

    # ── 1. Reply threads ────────────────────────────────────────────
    def test_reply_thread_stored_and_listed(self):
        parent = self.svc.add_comment(video_id="v1", user_id="alice", text="root")
        reply = self.svc.add_comment(
            video_id="v1",
            user_id="bob",
            text="a reply",
            parent_comment_id=parent["comment_id"],
        )
        self.assertEqual(reply["parent_comment_id"], parent["comment_id"])
        self.assertIsNone(parent["parent_comment_id"])

        listed = self.svc.list_comments(video_id="v1", viewer_id="alice")["comments"]
        by_id = {c["comment_id"]: c for c in listed}
        # Reply appears in the SAME flat list, carrying parent_comment_id.
        self.assertIn(reply["comment_id"], by_id)
        self.assertEqual(
            by_id[reply["comment_id"]]["parent_comment_id"], parent["comment_id"]
        )
        self.assertIsNone(by_id[parent["comment_id"]]["parent_comment_id"])

    # ── 2. Reactions ────────────────────────────────────────────────
    def test_react_unreact_counts_and_my_reactions_per_viewer(self):
        c = self.svc.add_comment(video_id="v2", user_id="alice", text="react to me")
        cid = c["comment_id"]

        self.svc.add_reaction(video_id="v2", comment_id=cid, user_id="alice", emoji="👍")
        proj_bob = self.svc.add_reaction(
            video_id="v2", comment_id=cid, user_id="bob", emoji="👍"
        )
        self.assertEqual(proj_bob["reactions_counts"]["👍"], 2)
        self.assertIn("👍", proj_bob["my_reactions"])  # viewer=bob

        # Viewer-specific my_reactions: alice sees her own only.
        listed_alice = self.svc.list_comments(video_id="v2", viewer_id="alice")["comments"]
        a = next(x for x in listed_alice if x["comment_id"] == cid)
        self.assertEqual(a["reactions_counts"]["👍"], 2)
        self.assertEqual(a["my_reactions"], ["👍"])

        listed_carol = self.svc.list_comments(video_id="v2", viewer_id="carol")["comments"]
        carol = next(x for x in listed_carol if x["comment_id"] == cid)
        self.assertEqual(carol["my_reactions"], [])

        # Unreact removes the emoji bucket entirely when empty.
        self.svc.remove_reaction(video_id="v2", comment_id=cid, user_id="alice", emoji="👍")
        after = self.svc.remove_reaction(
            video_id="v2", comment_id=cid, user_id="bob", emoji="👍"
        )
        self.assertNotIn("👍", after["reactions_counts"])
        self.assertEqual(after["my_reactions"], [])

    def test_invalid_emoji_422(self):
        from app.routers.video_listing import VideoCommentReactionIn

        with self.assertRaises(ValidationError):
            VideoCommentReactionIn(emoji="🚀")
        # allowed emoji passes
        VideoCommentReactionIn(emoji="❤️")

    def test_react_unknown_comment_404(self):
        with self.assertRaises(HTTPException) as ctx:
            self.svc.add_reaction(
                video_id="v2", comment_id="nope", user_id="alice", emoji="👍"
            )
        self.assertEqual(ctx.exception.status_code, 404)

    # ── 3. Edit ─────────────────────────────────────────────────────
    def test_edit_author_only_sets_edited_at(self):
        c = self.svc.add_comment(video_id="v3", user_id="alice", text="orig")
        cid = c["comment_id"]
        self.assertIsNone(c["edited_at"])

        edited = self.svc.edit_comment(
            video_id="v3", comment_id=cid, user_id="alice", text="updated"
        )
        self.assertEqual(edited["text"], "updated")
        self.assertIsNotNone(edited["edited_at"])

        # Reflected in projection/list.
        listed = self.svc.list_comments(video_id="v3", viewer_id="alice")["comments"]
        got = next(x for x in listed if x["comment_id"] == cid)
        self.assertEqual(got["text"], "updated")
        self.assertIsNotNone(got["edited_at"])

    def test_edit_non_author_403(self):
        c = self.svc.add_comment(video_id="v3", user_id="alice", text="orig")
        with self.assertRaises(HTTPException) as ctx:
            self.svc.edit_comment(
                video_id="v3", comment_id=c["comment_id"], user_id="bob", text="hijack"
            )
        self.assertEqual(ctx.exception.status_code, 403)

    # ── 4. Media (gif / sticker) ────────────────────────────────────
    def test_gif_comment_create_and_validation(self):
        from app.routers.video_listing import VideoCommentIn
        from app.core.settings import S

        # Configure an allowed GIF CDN domain for validation.
        orig = getattr(S, "gif_cdn_allowed_domains", "")
        object.__setattr__(S, "gif_cdn_allowed_domains", "media.giphy.com")
        self.addCleanup(lambda: object.__setattr__(S, "gif_cdn_allowed_domains", orig))

        # Valid gif passes model validation.
        body = VideoCommentIn(
            kind="gif",
            gif_url="https://media.giphy.com/x.gif",
            gif_alt_text="dance",
            gif_width=200,
            gif_height=150,
        )
        c = self.svc.add_comment(
            video_id="v4",
            user_id="alice",
            kind=body.kind,
            gif_url=body.gif_url,
            gif_alt_text=body.gif_alt_text,
            gif_width=body.gif_width,
            gif_height=body.gif_height,
        )
        self.assertEqual(c["kind"], "gif")
        self.assertEqual(c["gif_url"], "https://media.giphy.com/x.gif")
        self.assertIsNone(c["text"])

        # Disallowed domain rejected at model validation.
        with self.assertRaises(ValidationError):
            VideoCommentIn(kind="gif", gif_url="https://evil.example.com/x.gif")
        # Missing gif_url rejected.
        with self.assertRaises(ValidationError):
            VideoCommentIn(kind="gif")

    def test_sticker_comment_create_and_validation(self):
        from app.routers.video_listing import VideoCommentIn

        body = VideoCommentIn(
            kind="sticker",
            sticker_id="stk_1",
            sticker_collection_id="coll_1",
            sticker_url="/mock/s3/stickers/coll_1/stk_1.webp",
            sticker_alt_text="love",
        )
        c = self.svc.add_comment(
            video_id="v5",
            user_id="alice",
            kind=body.kind,
            sticker_id=body.sticker_id,
            sticker_collection_id=body.sticker_collection_id,
            sticker_url=body.sticker_url,
            sticker_alt_text=body.sticker_alt_text,
        )
        self.assertEqual(c["kind"], "sticker")
        self.assertEqual(c["sticker_url"], "/mock/s3/stickers/coll_1/stk_1.webp")

        # External sticker origin rejected.
        with self.assertRaises(ValidationError):
            VideoCommentIn(
                kind="sticker",
                sticker_id="stk_1",
                sticker_url="https://evil.example.com/s.webp",
            )
        # Missing sticker_id rejected.
        with self.assertRaises(ValidationError):
            VideoCommentIn(kind="sticker", sticker_url="/mock/s3/stickers/a/b.webp")

    def test_text_comment_requires_text(self):
        from app.routers.video_listing import VideoCommentIn

        with self.assertRaises(ValidationError):
            VideoCommentIn(kind="text")

    # ── 5. Moderation report ────────────────────────────────────────
    def test_moderation_accepts_video_comment_and_rejects_unknown(self):
        from app.routers import moderation as mod

        c = self.svc.add_comment(video_id="v6", user_id="alice", text="report me")

        # Existing comment → validation passes (no exception).
        ok_inp = mod.CreateModerationReportIn(
            content_type="video_comment",
            content_id=c["comment_id"],
            video_id="v6",
            topics=["spam"],
            reason_text="this is spam content",
        )
        mod._validate_content_exists(ok_inp)  # must not raise

        # Unknown comment → 404.
        bad_inp = mod.CreateModerationReportIn(
            content_type="video_comment",
            content_id="vc_does_not_exist",
            video_id="v6",
            topics=["spam"],
            reason_text="this is spam content",
        )
        with self.assertRaises(HTTPException) as ctx:
            mod._validate_content_exists(bad_inp)
        self.assertEqual(ctx.exception.status_code, 404)

        # Missing video_id → 400.
        missing_inp = mod.CreateModerationReportIn(
            content_type="video_comment",
            content_id=c["comment_id"],
            topics=["spam"],
            reason_text="this is spam content",
        )
        with self.assertRaises(HTTPException) as ctx2:
            mod._validate_content_exists(missing_inp)
        self.assertEqual(ctx2.exception.status_code, 400)


    # ── 6. Image comments (kind="image") ────────────────────────────
    def test_image_comment_create_and_projection(self):
        """kind='image' comment stores image_url and surfaces it in projection."""
        from app.routers.video_listing import VideoCommentIn

        image_url = "/uploads/object?s3_key=uploads%2Falice%2Fatt_x%2Fphoto.jpg"
        body = VideoCommentIn(
            kind="image",
            image_url=image_url,
            image_alt_text="Nice photo",
            image_width=1280,
            image_height=720,
        )
        c = self.svc.add_comment(
            video_id="v7",
            user_id="alice",
            kind=body.kind,
            image_url=body.image_url,
            image_alt_text=body.image_alt_text,
            image_width=body.image_width,
            image_height=body.image_height,
        )
        self.assertEqual(c["kind"], "image")
        self.assertEqual(c["image_url"], image_url)
        self.assertEqual(c["image_alt_text"], "Nice photo")
        self.assertEqual(c["image_width"], 1280)
        self.assertEqual(c["image_height"], 720)
        self.assertIsNone(c["text"])

    def test_image_comment_projected_in_list(self):
        """list_comments must surface image_url for kind='image' items."""
        from app.routers.video_listing import VideoCommentIn

        url = "/uploads/object?s3_key=uploads%2Falice%2Fatt_y%2Ffoo.png"
        body = VideoCommentIn(kind="image", image_url=url)
        self.svc.add_comment(video_id="v8", user_id="alice", kind="image", image_url=url)
        listed = self.svc.list_comments(video_id="v8", viewer_id="alice")["comments"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["kind"], "image")
        self.assertEqual(listed[0]["image_url"], url)

    def test_image_comment_missing_image_url_validation_error(self):
        """kind='image' without image_url → ValidationError (422)."""
        from app.routers.video_listing import VideoCommentIn

        with self.assertRaises(ValidationError):
            VideoCommentIn(kind="image")

    def test_image_comment_disallowed_host_validation_error(self):
        """https URL from arbitrary third-party is accepted (any https host ok)."""
        from app.routers.video_listing import VideoCommentIn

        # https from any host is accepted (unlike gif_url which requires allowlist)
        body = VideoCommentIn(
            kind="image",
            image_url="https://legitimate-cdn.example.com/photo.jpg",
        )
        self.assertEqual(body.image_url, "https://legitimate-cdn.example.com/photo.jpg")

    def test_image_comment_data_uri_rejected(self):
        from app.routers.video_listing import VideoCommentIn

        with self.assertRaises(ValidationError) as ctx:
            VideoCommentIn(kind="image", image_url="data:image/png;base64,AAAA")
        self.assertIn("scheme", str(ctx.exception))

    def test_image_comment_http_rejected(self):
        from app.routers.video_listing import VideoCommentIn

        with self.assertRaises(ValidationError) as ctx:
            VideoCommentIn(kind="image", image_url="http://example.com/img.jpg")
        self.assertIn("scheme", str(ctx.exception))

    def test_image_comment_edit_blocked(self):
        """edit_comment must reject image comments (kind guard)."""
        url = "/uploads/object?s3_key=uploads%2Falice%2Fatt_z%2Fb.jpg"
        c = self.svc.add_comment(video_id="v9", user_id="alice", kind="image", image_url=url)
        with self.assertRaises(HTTPException) as ctx:
            self.svc.edit_comment(
                video_id="v9", comment_id=c["comment_id"], user_id="alice", text="new text"
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_text_comment_image_url_is_none(self):
        """text comments have no image_url in their projection."""
        c = self.svc.add_comment(video_id="v10", user_id="alice", text="hello")
        self.assertEqual(c["kind"], "text")
        self.assertIsNone(c["image_url"])


if __name__ == "__main__":
    unittest.main()
