import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app.routers import newsfeed


class TestNewsfeedContentEnvelope(unittest.TestCase):
    def setUp(self):
        self._orig_markdown_flag = getattr(newsfeed.S, "newsfeed_markdown_enabled", False)
        self._orig_rich_flag = getattr(newsfeed.S, "newsfeed_richtext_enabled", False)
        object.__setattr__(newsfeed.S, "newsfeed_markdown_enabled", True)
        object.__setattr__(newsfeed.S, "newsfeed_richtext_enabled", True)

    def tearDown(self):
        object.__setattr__(newsfeed.S, "newsfeed_markdown_enabled", self._orig_markdown_flag)
        object.__setattr__(newsfeed.S, "newsfeed_richtext_enabled", self._orig_rich_flag)

    def test_create_post_request_accepts_legacy_body(self):
        req = newsfeed.CreatePostRequest(body="Legacy plain")

        content = newsfeed._content_from_payload(req)

        self.assertEqual(content["body"], "Legacy plain")
        self.assertEqual(content["body_plain"], "Legacy plain")
        self.assertIsNone(content["body_markdown"])
        self.assertIsNone(content["body_rich"])
        self.assertEqual(content["body_format"], "plain")
        self.assertEqual(content["body_version"], 1)

    def test_create_post_request_accepts_markdown_content(self):
        req = newsfeed.CreatePostRequest(
            body_plain="hello",
            body_markdown="# hello",
            body_format="markdown",
            body_version=1,
        )

        content = newsfeed._content_from_payload(req)

        self.assertEqual(content["body"], "hello")
        self.assertEqual(content["body_plain"], "hello")
        self.assertEqual(content["body_markdown"], "# hello")
        self.assertEqual(content["body_format"], "markdown")

    def test_create_post_request_accepts_rich_content(self):
        req = newsfeed.CreatePostRequest(
            body_plain="hello rich",
            body_rich={"type": "doc", "content": []},
            body_format="rich",
            body_version=1,
        )

        content = newsfeed._content_from_payload(req)

        self.assertEqual(content["body"], "hello rich")
        self.assertEqual(content["body_plain"], "hello rich")
        self.assertEqual(content["body_rich"], {"type": "doc", "content": []})
        self.assertEqual(content["body_format"], "rich")

    def test_markdown_format_requires_markdown_payload(self):
        with self.assertRaises(ValidationError):
            newsfeed.CreatePostRequest(body_plain="x", body_format="markdown")

    def test_rich_payload_requires_plain_fallback(self):
        with self.assertRaises(ValidationError):
            newsfeed.CreateCommentRequest(
                body_rich={"type": "doc", "content": []},
                body_format="rich",
            )


    def test_plain_text_length_limit_is_configurable(self):
        with patch.object(newsfeed, "_content_max_plain_chars", return_value=5):
            with self.assertRaises(ValidationError) as ctx:
                newsfeed.CreatePostRequest(body="123456")
        self.assertIn("invalid_content_payload: body_plain/body exceeds max length (5)", str(ctx.exception))

    def test_markdown_length_limit_is_configurable(self):
        with (
            patch.object(newsfeed, "_content_max_plain_chars", return_value=100),
            patch.object(newsfeed, "_content_max_markdown_chars", return_value=5),
        ):
            with self.assertRaises(ValidationError) as ctx:
                newsfeed.CreatePostRequest(body_plain="ok", body_markdown="123456", body_format="markdown")
        self.assertIn("invalid_content_payload: body_markdown exceeds max length (5)", str(ctx.exception))

    def test_rich_schema_type_must_be_doc(self):
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(
                body_plain="x",
                body_rich={"type": "paragraph", "content": []},
                body_format="rich",
            )
        self.assertIn("invalid_content_schema:root_not_doc: body_rich.type must be 'doc'", str(ctx.exception))

    def test_rich_schema_node_limit_is_configurable(self):
        rich_doc = {
            "type": "doc",
            "content": [
                {"type": "paragraph", "content": []},
                {"type": "paragraph", "content": []},
            ],
        }
        with patch.object(newsfeed, "_content_max_rich_nodes", return_value=2):
            with self.assertRaises(ValidationError) as ctx:
                newsfeed.CreatePostRequest(body_plain="x", body_rich=rich_doc, body_format="rich")
        self.assertIn("invalid_content_schema:node_limit_exceeded: body_rich node count exceeds max (2)", str(ctx.exception))

    def test_rich_schema_depth_limit_is_configurable(self):
        rich_doc = {
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "paragraph", "content": [{"type": "paragraph", "content": []}]}
                    ],
                }
            ],
        }
        with (
            patch.object(newsfeed, "_content_max_rich_nodes", return_value=999),
            patch.object(newsfeed, "_content_max_rich_depth", return_value=3),
        ):
            with self.assertRaises(ValidationError) as ctx:
                newsfeed.CreatePostRequest(body_plain="x", body_rich=rich_doc, body_format="rich")
        self.assertIn("invalid_content_schema:depth_limit_exceeded: body_rich depth exceeds max (3)", str(ctx.exception))



    def test_rich_schema_rejects_unsupported_node_type_with_reason_code(self):
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(
                body_plain="x",
                body_rich={"type": "doc", "content": [{"type": "iframe", "content": []}]},
                body_format="rich",
            )
        self.assertIn("invalid_content_schema:unsupported_node_type:", str(ctx.exception))

    def test_rich_schema_rejects_raw_html_nodes_by_default(self):
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(
                body_plain="x",
                body_rich={"type": "doc", "content": [{"type": "rawHtml", "content": []}]},
                body_format="rich",
            )
        self.assertIn("invalid_content_schema:unsupported_node_type:", str(ctx.exception))

    def test_rich_schema_rejects_unsupported_node_attrs(self):
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(
                body_plain="x",
                body_rich={
                    "type": "doc",
                    "content": [{"type": "paragraph", "attrs": {"style": "color:red"}, "content": []}],
                },
                body_format="rich",
            )
        self.assertIn("invalid_content_schema:unsupported_node_attr:", str(ctx.exception))

    def test_rich_schema_rejects_unsafe_link_mark(self):
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(
                body_plain="x",
                body_rich={
                    "type": "doc",
                    "content": [{
                        "type": "text",
                        "text": "click",
                        "marks": [{"type": "link", "attrs": {"href": "javascript:alert(1)"}}],
                    }],
                },
                body_format="rich",
            )
        self.assertIn("invalid_content_schema:unsafe_link_protocol:", str(ctx.exception))

    def test_rich_schema_logs_reason_code(self):
        with patch.object(newsfeed.logger, "warning") as warn:
            with self.assertRaises(ValidationError):
                newsfeed.CreatePostRequest(
                    body_plain="x",
                    body_rich={"type": "doc", "content": [{"type": "iframe", "content": []}]},
                    body_format="rich",
                )
        self.assertTrue(warn.called)
        self.assertEqual(warn.call_args.kwargs["extra"]["reason_code"], "unsupported_node_type")

    def test_markdown_sanitizer_allows_https_and_mailto_links(self):
        md = "See [safe](https://example.com) and [mail](mailto:test@example.com)"
        html = newsfeed.render_markdown_sanitized_html(md)
        self.assertIn('href="https://example.com"', html)
        self.assertIn('href="mailto:test@example.com"', html)
        self.assertIn('rel="nofollow noopener noreferrer"', html)

    def test_markdown_sanitizer_blocks_javascript_links(self):
        md = "Click [bad](javascript:alert(1))"
        html = newsfeed.render_markdown_sanitized_html(md)
        self.assertNotIn('javascript:', html)
        self.assertNotIn('<a ', html)
        self.assertIn('bad', html)

    def test_markdown_sanitizer_escapes_raw_script_and_event_handlers(self):
        md = '<script>alert(1)</script> [x](https://a.com" onclick="alert(1))'
        html = newsfeed.render_markdown_sanitized_html(md)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertNotIn('onclick=', html)

    def test_create_post_returns_legacy_and_format_aware_fields(self):
        req = newsfeed.CreatePostRequest(
            body_plain="Hello world",
            body_markdown="# Hello world",
            body_format="markdown",
            visibility="followers",
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish"),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            resp = newsfeed.create_post(req, user_id="u1")

        self.assertEqual(resp.body, "Hello world")
        self.assertEqual(resp.body_plain, "Hello world")
        self.assertEqual(resp.body_markdown, "# Hello world")
        self.assertIsNotNone(resp.body_markdown_html)
        self.assertIsNone(resp.body_rich)
        self.assertEqual(resp.body_format, "markdown")
        self.assertEqual(resp.body_version, 1)


    def test_post_serializer_masks_all_format_fields_when_locked(self):
        post = {
            "post_id": "p1",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body": "legacy body",
            "body_plain": "plain body",
            "body_markdown": "# heading",
            "body_markdown_html": "<p>heading</p>",
            "body_rich": {"type": "doc", "content": [{"type": "text", "text": "secret"}]},
            "body_format": "rich",
            "body_version": 1,
            "image_urls": ["https://cdn.example.com/a.png"],
            "locked": True,
        }

        out = newsfeed._post_to_dict(post, locked_body=True)

        self.assertEqual(out["body"], "[Locked content]")
        self.assertEqual(out["body_plain"], "[Locked content]")
        self.assertIsNone(out["body_markdown"])
        self.assertIsNone(out["body_markdown_html"])
        self.assertIsNone(out["body_rich"])
        self.assertEqual(out["body_format"], "plain")
        self.assertEqual(out["body_version"], 1)
        self.assertEqual(out["image_urls"], [])

    def test_get_post_masks_locked_content_without_format_bypass(self):
        locked_post = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "plain secret",
            "body_markdown": "[x](https://example.com)",
            "body_markdown_html": '<p><a href="https://example.com">x</a></p>',
            "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "secret"}]}]},
            "body_format": "rich",
            "body_version": 1,
            "locked": True,
            "image_urls": ["https://cdn.example.com/private.png"],
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[locked_post, None]),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=False),
        ):
            out = newsfeed.get_post("p1", user_id="viewer_1")

        self.assertEqual(out["body"], "[Locked content]")
        self.assertEqual(out["body_plain"], "[Locked content]")
        self.assertIsNone(out["body_markdown"])
        self.assertIsNone(out["body_markdown_html"])
        self.assertIsNone(out["body_rich"])
        self.assertEqual(out["body_format"], "plain")
        self.assertEqual(out["image_urls"], [])

    def test_comment_serializer_emits_legacy_body_and_content_fields(self):
        item = {
            "comment_id": "c1",
            "post_id": "p1",
            "user_id": "u1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "Hello",
            "body_markdown": "**Hello**",
            "body_format": "markdown",
            "body_version": 1,
            "deleted": False,
            "version": 2,
            "tip_total_cents": 50,
        }

        out = newsfeed._comment_to_dict(item)

        self.assertEqual(out["body"], "Hello")
        self.assertEqual(out["body_plain"], "Hello")
        self.assertEqual(out["body_markdown"], "**Hello**")
        self.assertEqual(out["body_format"], "markdown")
        self.assertEqual(out["body_version"], 1)

    def test_post_serializer_read_path_fallback_from_format_fields_to_legacy_body(self):
        post = {
            "post_id": "p-migrate",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_markdown": "# Migrated markdown",
            "body_format": "markdown",
            "body_version": 2,
            "locked": False,
        }

        out = newsfeed._post_to_dict(post)

        self.assertEqual(out["body"], "# Migrated markdown")
        self.assertEqual(out["body_plain"], "# Migrated markdown")
        self.assertEqual(out["body_markdown"], "# Migrated markdown")
        self.assertEqual(out["body_format"], "markdown")
        self.assertIsNotNone(out["body_markdown_html"])

    def test_comment_serializer_falls_back_to_body_plain_for_unknown_format(self):
        item = {
            "comment_id": "c-legacy",
            "post_id": "p1",
            "user_id": "u1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "Safe plain fallback",
            "body_format": "html",
            "body_version": 1,
            "deleted": False,
            "version": 1,
        }

        out = newsfeed._comment_to_dict(item)

        self.assertEqual(out["body"], "Safe plain fallback")
        self.assertEqual(out["body_plain"], "Safe plain fallback")
        self.assertEqual(out["body_format"], "plain")
        self.assertIsNone(out["body_markdown"])
        self.assertIsNone(out["body_rich"])



    def test_create_comment_supports_rich_payload(self):
        req = newsfeed.CreateCommentRequest(
            body_plain="Rich fallback",
            body_rich={"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Rich fallback"}]}]},
            body_format="rich",
        )
        post_item = {"pk": newsfeed.pk_post("p1"), "sk": newsfeed.sk_post(), "post_id": "p1", "user_id": "author_1", "locked": False}

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post_item),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "new_id", return_value="cmt_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item"),
            patch.object(newsfeed, "ddb_update_item"),
        ):
            resp = newsfeed.create_comment("p1", req, user_id="u1")

        self.assertEqual(resp.body, "Rich fallback")
        self.assertEqual(resp.body_plain, "Rich fallback")
        self.assertEqual(resp.body_format, "rich")
        self.assertIsNotNone(resp.body_rich)
        self.assertIsNone(resp.body_markdown)

    def test_edit_post_roundtrip_for_plain_markdown_and_rich_formats(self):
        existing = {"pk": newsfeed.pk_post("p1"), "sk": newsfeed.sk_post(), "post_id": "p1", "user_id": "u1", "created_at": "2026-01-01T00:00:00+00:00"}

        cases = [
            (
                newsfeed.EditPostRequest(body="legacy plain"),
                {
                    "body": "legacy plain",
                    "body_plain": "legacy plain",
                    "body_markdown": None,
                    "body_rich": None,
                    "body_format": "plain",
                },
            ),
            (
                newsfeed.EditPostRequest(body_plain="md fallback", body_markdown="## md fallback", body_format="markdown"),
                {
                    "body": "md fallback",
                    "body_plain": "md fallback",
                    "body_markdown": "## md fallback",
                    "body_rich": None,
                    "body_format": "markdown",
                },
            ),
            (
                newsfeed.EditPostRequest(
                    body_plain="rich fallback",
                    body_rich={"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "rich fallback"}]}]},
                    body_format="rich",
                ),
                {
                    "body": "rich fallback",
                    "body_plain": "rich fallback",
                    "body_markdown": None,
                    "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "rich fallback"}]}]},
                    "body_format": "rich",
                },
            ),
        ]

        for req, expected in cases:
            with self.subTest(format=expected["body_format"]):
                with (
                    patch.object(newsfeed, "ddb_get_item", return_value=existing),
                    patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
                    patch.object(newsfeed, "ddb_update_item") as upd,
                ):
                    upd.return_value = {
                        **existing,
                        "updated_at": "2026-01-01T00:00:00+00:00",
                        "body": expected["body"],
                        "body_plain": expected["body_plain"],
                        "body_markdown": expected["body_markdown"],
                        "body_markdown_html": "<p>md</p>" if expected["body_markdown"] else None,
                        "body_rich": expected["body_rich"],
                        "body_format": expected["body_format"],
                        "body_version": 1,
                        "locked": False,
                    }
                    out = newsfeed.edit_post("p1", req, user_id="u1")

                self.assertEqual(out["body"], expected["body"])
                self.assertEqual(out["body_plain"], expected["body_plain"])
                self.assertEqual(out["body_markdown"], expected["body_markdown"])
                self.assertEqual(out["body_format"], expected["body_format"])
                self.assertEqual(out["body_rich"], expected["body_rich"])

    def test_get_post_unlocked_roundtrip_for_rich_content(self):
        rich_post = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "rich text",
            "body_rich": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "rich text"}]}]},
            "body_format": "rich",
            "body_version": 1,
            "locked": True,
        }

        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[rich_post, None]),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=True),
        ):
            out = newsfeed.get_post("p1", user_id="viewer_1")

        self.assertEqual(out["body"], "rich text")
        self.assertEqual(out["body_plain"], "rich text")
        self.assertEqual(out["body_format"], "rich")
        self.assertIsNotNone(out["body_rich"])

    def test_edit_comment_roundtrip_for_markdown(self):
        req = newsfeed.EditCommentRequest(
            body_plain="new fallback",
            body_markdown="**new fallback**",
            body_format="markdown",
            expected_version=1,
        )
        existing = {
            "pk": newsfeed.pk_post_comments("p1"),
            "sk": "2026-01-01T00:00:00+00:00#CMT#c1",
            "comment_id": "c1",
            "post_id": "p1",
            "user_id": "u1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "deleted": False,
            "version": 1,
        }

        with (
            patch.object(newsfeed, "ddb_query", return_value={"Items": [existing]}),
            patch.object(newsfeed, "now_iso", return_value="2026-01-02T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_update_item") as upd,
        ):
            upd.return_value = {
                **existing,
                "updated_at": "2026-01-02T00:00:00+00:00",
                "body": "new fallback",
                "body_plain": "new fallback",
                "body_markdown": "**new fallback**",
                "body_markdown_html": "<p><strong>new fallback</strong></p>",
                "body_rich": None,
                "body_format": "markdown",
                "body_version": 1,
                "version": 2,
                "tip_total_cents": 0,
            }
            out = newsfeed.edit_comment("p1", "c1", req, user_id="u1")

        self.assertEqual(out.body, "new fallback")
        self.assertEqual(out.body_plain, "new fallback")
        self.assertEqual(out.body_markdown, "**new fallback**")
        self.assertEqual(out.body_format, "markdown")
        self.assertEqual(out.version, 2)

    def test_list_comments_returns_all_formats(self):
        post = {"pk": newsfeed.pk_post("p1"), "sk": newsfeed.sk_post(), "post_id": "p1", "user_id": "author_1", "locked": False}
        items = [
            {
                "comment_id": "c_plain",
                "post_id": "p1",
                "user_id": "u1",
                "created_at": "2026-01-01T00:00:00+00:00",
                "body": "legacy",
                "deleted": False,
                "version": 1,
            },
            {
                "comment_id": "c_md",
                "post_id": "p1",
                "user_id": "u2",
                "created_at": "2026-01-01T00:00:00+00:00",
                "body_plain": "md",
                "body_markdown": "**md**",
                "body_format": "markdown",
                "deleted": False,
                "version": 1,
            },
            {
                "comment_id": "c_rich",
                "post_id": "p1",
                "user_id": "u3",
                "created_at": "2026-01-01T00:00:00+00:00",
                "body_plain": "rich",
                "body_rich": {"type": "doc", "content": []},
                "body_format": "rich",
                "deleted": False,
                "version": 1,
            },
        ]

        with (
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "ddb_query", return_value={"Items": items}),
            patch.object(newsfeed, "encode_cursor", return_value=None),
        ):
            out = newsfeed.list_comments("p1", limit=20, cursor=None, user_id="viewer")

        self.assertEqual(len(out["items"]), 3)
        self.assertEqual(out["items"][0]["body_format"], "plain")
        self.assertEqual(out["items"][1]["body_format"], "markdown")
        self.assertEqual(out["items"][2]["body_format"], "rich")




    def test_serializer_downgrades_to_plain_when_markdown_flag_disabled(self):
        object.__setattr__(newsfeed.S, "newsfeed_markdown_enabled", False)
        item = {
            "post_id": "p1",
            "user_id": "u1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "plain",
            "body_markdown": "# md",
            "body_markdown_html": "<h1>md</h1>",
            "body_format": "markdown",
        }
        out = newsfeed._post_to_dict(item)
        self.assertEqual(out["body_format"], "plain")
        self.assertIsNone(out["body_markdown"])
        self.assertIsNone(out["body_markdown_html"])
        self.assertEqual(out["body"], "plain")

    def test_serializer_downgrades_to_plain_when_rich_flag_disabled(self):
        object.__setattr__(newsfeed.S, "newsfeed_richtext_enabled", False)
        item = {
            "comment_id": "c1",
            "post_id": "p1",
            "user_id": "u1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "plain",
            "body_rich": {"type": "doc", "content": []},
            "body_format": "rich",
            "deleted": False,
            "version": 1,
        }
        out = newsfeed._comment_to_dict(item)
        self.assertEqual(out["body_format"], "plain")
        self.assertIsNone(out["body_rich"])
        self.assertEqual(out["body"], "plain")


    def test_markdown_payload_rejected_when_markdown_flag_disabled(self):
        object.__setattr__(newsfeed.S, "newsfeed_markdown_enabled", False)
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(body_plain="x", body_markdown="# x", body_format="markdown")
        self.assertIn("feature_disabled: markdown format is disabled", str(ctx.exception))

    def test_rich_payload_rejected_when_rich_flag_disabled(self):
        object.__setattr__(newsfeed.S, "newsfeed_richtext_enabled", False)
        with self.assertRaises(ValidationError) as ctx:
            newsfeed.CreatePostRequest(body_plain="x", body_rich={"type": "doc", "content": []}, body_format="rich")
        self.assertIn("feature_disabled: rich format is disabled", str(ctx.exception))



if __name__ == "__main__":
    unittest.main()
