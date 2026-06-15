"""Offline tests for kind='image' comments on newsfeed posts.

Covers the backend model, validator, create path, and projection:
  - Create an image comment (kind=image + valid image_url) succeeds and
    projects image_url in the response and in _comment_to_dict.
  - Missing image_url when kind=image → ValidationError (422).
  - A disallowed-host image_url → ValidationError (422).
  - image_url field present but kind=text → text comment is created normally.
  - data: / javascript: / scheme-relative image_url → ValidationError.
  - Backend edit guard: editing an image comment via PATCH → 400.

Isolation strategy mirrors test_newsfeed_comment_reactions.py:
  - moto in-memory DynamoDB table bound via nf.tbl = <moto table> (module-level
    closure used by all ddb_* helpers).
  - Route handlers invoked directly (no FastAPI TestClient).
  - Social-alert / analytics hooks patched to no-ops.
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


APP_TABLE = "newsfeed_comment_image_test"


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


# A valid platform upload URL produced by POST /uploads/image.
VALID_IMAGE_URL = "/uploads/object?s3_key=uploads%2Fuser1%2Fatt_abc%2Fphoto.jpg"
POST_ID = "p_img_1"
USER_ID = "user_alice"


def _seed_post(tbl, post_id: str = POST_ID, user_id: str = USER_ID):
    """Insert a minimal post item so create_comment can look it up."""
    tbl.put_item(Item={
        "pk": nf.pk_post(post_id),
        "sk": nf.sk_post(),
        "post_id": post_id,
        "user_id": user_id,
        "Entity": "Post",
        "locked": False,
    })


# ─────────────────────── Model-level validation (offline, no DDB) ───────────

class TestCreateCommentRequestImageValidation(unittest.TestCase):
    """Pydantic model instantiation tests — fully offline, no DDB needed."""

    def test_valid_upload_url_accepted(self):
        req = nf.CreateCommentRequest(kind="image", image_url=VALID_IMAGE_URL)
        self.assertEqual(req.kind, "image")
        self.assertEqual(req.image_url, VALID_IMAGE_URL)

    def test_valid_https_url_accepted(self):
        url = "https://cdn.example.com/photos/foo.jpg"
        req = nf.CreateCommentRequest(kind="image", image_url=url)
        self.assertEqual(req.image_url, url)

    def test_missing_image_url_raises(self):
        with self.assertRaises(ValidationError):
            nf.CreateCommentRequest(kind="image")

    def test_empty_image_url_raises(self):
        with self.assertRaises(ValidationError):
            nf.CreateCommentRequest(kind="image", image_url="   ")

    def test_http_url_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            nf.CreateCommentRequest(kind="image", image_url="http://example.com/img.jpg")
        self.assertIn("scheme", str(ctx.exception))

    def test_data_uri_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            nf.CreateCommentRequest(kind="image", image_url="data:image/png;base64,AAAA")
        self.assertIn("scheme", str(ctx.exception))

    def test_javascript_uri_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            nf.CreateCommentRequest(kind="image", image_url="javascript:alert(1)")
        self.assertIn("scheme", str(ctx.exception))

    def test_scheme_relative_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            nf.CreateCommentRequest(kind="image", image_url="//evil.com/img.jpg")
        self.assertIn("scheme", str(ctx.exception))

    def test_arbitrary_relative_path_rejected(self):
        """Only /uploads/object paths are accepted as platform-relative."""
        with self.assertRaises(ValidationError) as ctx:
            nf.CreateCommentRequest(kind="image", image_url="/stickers/foo.jpg")
        self.assertIn("upload", str(ctx.exception).lower())

    def test_image_url_present_for_text_kind_no_error(self):
        """image_url supplied with kind=text is accepted (field is optional)."""
        req = nf.CreateCommentRequest(
            kind="text",
            body_plain="hello",
            image_url=VALID_IMAGE_URL,
        )
        # No validation error; kind stays "text".
        self.assertEqual(req.kind, "text")

    def test_image_fields_optional_dimensions(self):
        req = nf.CreateCommentRequest(
            kind="image",
            image_url=VALID_IMAGE_URL,
            image_alt_text="A photo",
            image_width=800,
            image_height=600,
        )
        self.assertEqual(req.image_width, 800)
        self.assertEqual(req.image_height, 600)
        self.assertEqual(req.image_alt_text, "A photo")


# ─────────────────────── Integration path (moto DDB) ────────────────────────

@unittest.skipIf(mock_aws is None, "moto not installed")
class TestImageCommentCreateAndProject(unittest.TestCase):

    def setUp(self):
        self._mock = mock_aws()
        self._mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._tbl = _make_table(ddb)
        # Bind the module-level tbl so all ddb_* helpers use the moto table.
        self._orig_tbl = nf.tbl
        nf.tbl = self._tbl
        # Patch social-alert / analytics hooks to no-ops.
        self._alert_patch = patch.object(nf, "emit_social_alert", return_value=None)
        self._alert_patch.start()
        self._notif_patch = patch.object(nf, "put_notification", return_value=None)
        self._notif_patch.start()
        _seed_post(self._tbl)

    def tearDown(self):
        self._alert_patch.stop()
        self._notif_patch.stop()
        nf.tbl = self._orig_tbl
        self._mock.stop()

    def _create_image_comment(self, image_url=VALID_IMAGE_URL, **extra):
        req = nf.CreateCommentRequest(kind="image", image_url=image_url, **extra)
        return nf.create_comment(post_id=POST_ID, req=req, user_id=USER_ID)

    def test_create_image_comment_returns_image_url(self):
        resp = self._create_image_comment()
        self.assertEqual(resp.kind, "image")
        self.assertEqual(resp.image_url, VALID_IMAGE_URL)
        # Media comments carry no body text.
        self.assertIsNone(resp.body)
        self.assertIsNone(resp.body_plain)

    def test_create_image_comment_with_metadata(self):
        resp = self._create_image_comment(
            image_alt_text="Sunset photo",
            image_width=1920,
            image_height=1080,
        )
        self.assertEqual(resp.image_alt_text, "Sunset photo")
        self.assertEqual(resp.image_width, 1920)
        self.assertEqual(resp.image_height, 1080)

    def test_image_comment_projected_by_comment_to_dict(self):
        """_comment_to_dict (called by list_comments) must surface image_url."""
        self._create_image_comment(image_alt_text="Test alt")
        resp = nf.list_comments(post_id=POST_ID, limit=10, cursor=None, user_id=USER_ID)
        items = resp["items"]
        self.assertEqual(len(items), 1)
        c = items[0]
        self.assertEqual(c["kind"], "image")
        self.assertEqual(c["image_url"], VALID_IMAGE_URL)
        self.assertEqual(c["image_alt_text"], "Test alt")

    def test_edit_image_comment_blocked(self):
        """Backend edit_comment must reject image comments with 400."""
        resp = self._create_image_comment()
        comment_id = resp.comment_id
        edit_req = nf.EditCommentRequest(body_plain="new text")
        with self.assertRaises(HTTPException) as ctx:
            nf.edit_comment(
                post_id=POST_ID,
                comment_id=comment_id,
                req=edit_req,
                user_id=USER_ID,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Media comments", ctx.exception.detail)

    def test_https_image_url_accepted(self):
        url = "https://cdn.example.com/img.jpg"
        resp = self._create_image_comment(image_url=url)
        self.assertEqual(resp.image_url, url)

    def test_text_comment_image_url_is_none(self):
        """A text comment created without image fields has image_url=None."""
        req = nf.CreateCommentRequest(kind="text", body_plain="hello world")
        resp = nf.create_comment(post_id=POST_ID, req=req, user_id=USER_ID)
        self.assertEqual(resp.kind, "text")
        self.assertIsNone(resp.image_url)
