import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app.routers import newsfeed


class TestNewsfeedContentEnvelope(unittest.TestCase):
    def setUp(self):
        self._orig_markdown_flag = getattr(newsfeed.S, "newsfeed_markdown_enabled", False)
        self._orig_rich_flag = getattr(newsfeed.S, "newsfeed_richtext_enabled", False)
        self._orig_schedule_api_flag = getattr(newsfeed.S, "newsfeed_scheduling_api_enabled", True)
        object.__setattr__(newsfeed.S, "newsfeed_markdown_enabled", True)
        object.__setattr__(newsfeed.S, "newsfeed_richtext_enabled", True)
        object.__setattr__(newsfeed.S, "newsfeed_scheduling_api_enabled", True)

    def tearDown(self):
        object.__setattr__(newsfeed.S, "newsfeed_markdown_enabled", self._orig_markdown_flag)
        object.__setattr__(newsfeed.S, "newsfeed_richtext_enabled", self._orig_rich_flag)
        object.__setattr__(newsfeed.S, "newsfeed_scheduling_api_enabled", self._orig_schedule_api_flag)

    def test_create_post_request_accepts_legacy_body(self):
        req = newsfeed.CreatePostRequest(body="Legacy plain")

        content = newsfeed._content_from_payload(req)

        self.assertEqual(content["body"], "Legacy plain")
        self.assertEqual(content["body_plain"], "Legacy plain")
        self.assertIsNone(content["body_markdown"])
        self.assertIsNone(content["body_rich"])
        self.assertEqual(content["body_format"], "plain")
        self.assertEqual(content["body_version"], 1)

    def test_create_post_request_schema_exposes_scheduling_fields(self):
        schema = newsfeed.CreatePostRequest.model_json_schema()
        props = schema["properties"]

        self.assertIn("publish_at", props)
        self.assertEqual(props["publish_at"]["type"], "integer")
        self.assertEqual(props["publish_at"]["minimum"], 0)
        self.assertIn("Unix timestamp", props["publish_at"]["description"])

        self.assertIn("schedule_timezone", props)
        self.assertEqual(props["schedule_timezone"]["type"], "string")
        self.assertEqual(props["schedule_timezone"]["maxLength"], 64)
        self.assertIn("IANA timezone", props["schedule_timezone"]["description"])

        self.assertIn("scheduled_at_local", props)
        self.assertEqual(props["scheduled_at_local"]["type"], "string")
        self.assertEqual(props["scheduled_at_local"]["maxLength"], 32)
        examples = schema.get("examples", [])
        self.assertTrue(any("publish_at" in example for example in examples))

    def test_create_post_request_remains_backward_compatible_without_schedule(self):
        req = newsfeed.CreatePostRequest(body="Immediate post")
        self.assertIsNone(req.publish_at)
        self.assertIsNone(req.schedule_timezone)
        self.assertIsNone(req.scheduled_at_local)

    def test_create_post_route_documents_schedule_validation_errors(self):
        create_route = next(route for route in newsfeed.router.routes if getattr(route, "path", None) == "/posts" and "POST" in getattr(route, "methods", set()))
        responses = create_route.responses
        self.assertIn(400, responses)
        examples = responses[400]["content"]["application/json"]["examples"]
        self.assertIn("invalid_timezone", examples)
        self.assertIn("publish_at_too_soon", examples)

    def test_edit_post_request_schema_exposes_schedule_fields(self):
        schema = newsfeed.EditPostRequest.model_json_schema()
        props = schema["properties"]
        self.assertIn("publish_at", props)
        self.assertIn("schedule_timezone", props)
        self.assertIn("scheduled_at_local", props)

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
        self.assertEqual(resp.status, "published")
        self.assertEqual(resp.published_at, "2026-01-01T00:00:00+00:00")
        self.assertIsNone(resp.publish_at)
        self.assertIsNone(resp.schedule_timezone)
        self.assertIsNone(resp.scheduled_at_local)

    def test_create_post_immediate_writes_feed_ref_and_meters(self):
        req = newsfeed.CreatePostRequest(
            body="Immediate hello",
            visibility="followers",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_publish,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            resp = newsfeed.create_post(req, user_id="u1")

        self.assertEqual(resp.status, "published")
        self.assertEqual(put_item.call_count, 2)
        self.assertEqual(put_item.call_args_list[0].args[0]["Entity"], "Post")
        self.assertEqual(put_item.call_args_list[1].args[0]["Entity"], "FeedRef")
        meter_publish.assert_called_once_with(user_id="u1", post_id="post_1")

    def test_create_post_supports_scheduled_publish_without_feedref_or_metering(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            visibility="followers",
            publish_at=1767225600,
            schedule_timezone="America/New_York",
            scheduled_at_local="2026-12-31T19:00",
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_publish,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            resp = newsfeed.create_post(req, user_id="u1")

        self.assertEqual(resp.status, "scheduled")
        self.assertIsNone(resp.published_at)
        self.assertEqual(resp.publish_at, 1767225600)
        self.assertEqual(resp.schedule_timezone, "America/New_York")
        self.assertEqual(resp.scheduled_at_local, "2026-12-31T19:00")
        self.assertEqual(put_item.call_count, 2)
        self.assertEqual(put_item.call_args_list[0].args[0]["Entity"], "Post")
        self.assertEqual(put_item.call_args_list[1].args[0]["Entity"], "ScheduledPostRef")
        self.assertEqual(
            put_item.call_args_list[1].args[0]["sk"],
            newsfeed.sk_scheduled_post_ref(1767225600, "post_1"),
        )
        self.assertEqual(put_item.call_args_list[1].args[0]["owner_user_id"], "u1")
        self.assertEqual(put_item.call_args_list[1].args[0]["post_id"], "post_1")
        self.assertEqual(put_item.call_args_list[1].args[0]["publish_at"], 1767225600)
        self.assertEqual(put_item.call_args_list[1].args[0]["created_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(put_item.call_args_list[1].args[0]["status"], "scheduled")
        meter_publish.assert_not_called()

    def test_create_post_scheduled_emits_schedule_metric(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            visibility="followers",
            publish_at=1767225600,
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T19:00",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "ddb_put_item"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish"),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "record_newsfeed_schedule_operation") as schedule_metric,
        ):
            newsfeed.create_post(req, user_id="u1")
        schedule_metric.assert_called_with(operation="create", outcome="success")

    def test_create_post_rejects_invalid_schedule_timezone(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1767225600,
            schedule_timezone="Not/A_Real_Zone",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_timezone_invalid")
        self.assertEqual(ctx.exception.detail["field"], "schedule_timezone")

    def test_create_post_rejects_publish_at_in_past(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1766999999,
            schedule_timezone="UTC",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_publish_at_too_soon")
        self.assertEqual(ctx.exception.detail["field"], "publish_at")
        self.assertIn("minimum_publish_at", ctx.exception.detail)

    def test_create_post_accepts_valid_timezone_and_minimum_future_publish_at(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1767000006,
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T19:00",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "ddb_put_item"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_publish,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            resp = newsfeed.create_post(req, user_id="u1")
        self.assertEqual(resp.status, "scheduled")
        self.assertEqual(resp.publish_at, 1767000006)
        self.assertEqual(resp.schedule_timezone, "UTC")
        meter_publish.assert_not_called()

    def test_create_post_rejects_publish_at_equal_to_now_plus_five_seconds(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1767000005,
            schedule_timezone="UTC",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_publish_at_too_soon")
        self.assertEqual(ctx.exception.detail["minimum_publish_at"], 1767000006)

    def test_create_post_rejects_publish_at_beyond_max_horizon(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1767004000,
            schedule_timezone="UTC",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "_schedule_max_horizon_seconds", return_value=3600),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_publish_at_too_far")
        self.assertEqual(ctx.exception.detail["maximum_publish_at"], 1767003600)

    def test_create_post_rejects_schedule_metadata_without_publish_at(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T19:00",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_publish_at_required")
        self.assertEqual(ctx.exception.detail["field"], "publish_at")

    def test_create_post_scheduling_rejected_when_api_flag_disabled(self):
        object.__setattr__(newsfeed.S, "newsfeed_scheduling_api_enabled", False)
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1767225600,
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T19:00",
        )
        with patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail["code"], "schedule_feature_disabled")

    def test_create_post_rejects_invalid_scheduled_at_local_format(self):
        req = newsfeed.CreatePostRequest(
            body="Scheduled hello",
            publish_at=1767225600,
            schedule_timezone="UTC",
            scheduled_at_local="12/31/2026 19:00",
        )
        with (
            patch.object(newsfeed, "new_id", return_value="post_1"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.create_post(req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_local_datetime_invalid")
        self.assertEqual(ctx.exception.detail["field"], "scheduled_at_local")

    def test_list_scheduled_posts_returns_owner_scheduled_posts(self):
        scheduled_post = {
            "pk": newsfeed.pk_post("p-scheduled"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-scheduled",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "America/New_York",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "scheduled body",
            "body_format": "plain",
            "body_version": 1,
        }
        not_scheduled = {
            "pk": newsfeed.pk_post("p-published"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-published",
            "user_id": "u1",
            "status": "published",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "published body",
            "body_format": "plain",
            "body_version": 1,
        }
        refs = {
            "Items": [
                {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767225600, "p-scheduled"), "post_id": "p-scheduled"},
                {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767229200, "p-published"), "post_id": "p-published"},
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed.ddb, "batch_get_item", return_value={"Responses": {newsfeed.APP_TABLE: [scheduled_post, not_scheduled]}}),
        ):
            out = newsfeed.list_scheduled_posts(limit=20, cursor=None, user_id="u1")

        self.assertEqual(len(out["items"]), 1)
        self.assertEqual(out["items"][0]["post_id"], "p-scheduled")
        self.assertEqual(out["items"][0]["status"], "scheduled")
        self.assertEqual(out["items"][0]["publish_at"], 1767225600)

    def test_list_scheduled_posts_rejected_when_api_flag_disabled(self):
        object.__setattr__(newsfeed.S, "newsfeed_scheduling_api_enabled", False)
        with self.assertRaises(newsfeed.HTTPException) as ctx:
            newsfeed.list_scheduled_posts(limit=20, cursor=None, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail["code"], "schedule_feature_disabled")

    def test_list_scheduled_posts_filters_cross_user_posts(self):
        other_owner_post = {
            "pk": newsfeed.pk_post("p-other-owner"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-other-owner",
            "user_id": "u2",
            "status": "scheduled",
            "publish_at": 1767225600,
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "should not be visible to u1",
            "body_format": "plain",
            "body_version": 1,
        }
        refs = {
            "Items": [
                {
                    "pk": newsfeed.pk_user("u1"),
                    "sk": newsfeed.sk_scheduled_post_ref(1767225600, "p-other-owner"),
                    "post_id": "p-other-owner",
                }
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed.ddb, "batch_get_item", return_value={"Responses": {newsfeed.APP_TABLE: [other_owner_post]}}),
        ):
            out = newsfeed.list_scheduled_posts(limit=20, cursor=None, user_id="u1")
        self.assertEqual(out["items"], [])

    def test_list_scheduled_posts_supports_cursor_and_stable_order(self):
        p_early = {
            "pk": newsfeed.pk_post("p-early"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-early",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "early",
            "body_format": "plain",
            "body_version": 1,
        }
        p_late = {
            "pk": newsfeed.pk_post("p-late"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-late",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767229200,
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "late",
            "body_format": "plain",
            "body_version": 1,
        }
        refs = {
            "Items": [
                {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767229200, "p-late"), "post_id": "p-late"},
                {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767225600, "p-early"), "post_id": "p-early"},
            ],
            "LastEvaluatedKey": {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767229200, "p-late")},
        }
        with (
            patch.object(newsfeed, "decode_cursor_or_400", return_value={"pk": "x", "sk": "y"}),
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed.ddb, "batch_get_item", return_value={"Responses": {newsfeed.APP_TABLE: [p_late, p_early]}}),
            patch.object(newsfeed, "encode_cursor", return_value="cursor_2"),
        ):
            out = newsfeed.list_scheduled_posts(limit=20, cursor="cursor_1", user_id="u1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p-early", "p-late"])
        self.assertEqual(out["next_cursor"], "cursor_2")

    def test_list_scheduled_posts_filters_malformed_and_mismatched_refs(self):
        scheduled = {
            "pk": newsfeed.pk_post("p-good"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-good",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "good",
            "body_format": "plain",
            "body_version": 1,
        }
        refs = {
            "Items": [
                {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767225600, "p-good"), "post_id": "p-good"},
                {"pk": newsfeed.pk_user("u1"), "sk": "SCHEDULEDPOST#bad#p-bad", "post_id": "p-bad"},
                {"pk": newsfeed.pk_user("u1"), "sk": newsfeed.sk_scheduled_post_ref(1767225601, "p-other"), "post_id": "p-mismatch"},
            ],
            "LastEvaluatedKey": None,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(newsfeed.ddb, "batch_get_item", return_value={"Responses": {newsfeed.APP_TABLE: [scheduled]}}),
        ):
            out = newsfeed.list_scheduled_posts(limit=20, cursor=None, user_id="u1")
        self.assertEqual([it["post_id"] for it in out["items"]], ["p-good"])

    def test_scheduled_ref_key_builder_is_stable_and_parseable(self):
        key = newsfeed.sk_scheduled_post_ref(12345, "post_abc")
        self.assertEqual(key, "SCHEDULEDPOST#000000012345#post_abc")
        parsed = newsfeed.parse_scheduled_post_ref_sk(key)
        self.assertEqual(parsed, (12345, "post_abc"))

    def test_scheduled_ref_key_parser_rejects_invalid_shapes(self):
        self.assertIsNone(newsfeed.parse_scheduled_post_ref_sk(""))
        self.assertIsNone(newsfeed.parse_scheduled_post_ref_sk("SCHEDULEDPOST#abc#post_1"))
        self.assertIsNone(newsfeed.parse_scheduled_post_ref_sk("WRONG#000000012345#post_1"))

    def test_view_feed_excludes_scheduled_and_cancelled_posts_when_refs_drift(self):
        refs = {
            "Items": [
                {"post_id": "p-published"},
                {"post_id": "p-scheduled"},
                {"post_id": "p-cancelled"},
            ]
        }
        p_published = {
            "pk": newsfeed.pk_post("p-published"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-published",
            "user_id": "author_1",
            "status": "published",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "published",
            "body_format": "plain",
            "body_version": 1,
        }
        p_scheduled = {
            "pk": newsfeed.pk_post("p-scheduled"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-scheduled",
            "user_id": "author_1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "scheduled",
            "body_format": "plain",
            "body_version": 1,
        }
        p_cancelled = {
            "pk": newsfeed.pk_post("p-cancelled"),
            "sk": newsfeed.sk_post(),
            "post_id": "p-cancelled",
            "user_id": "author_1",
            "status": "cancelled",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "cancelled",
            "body_format": "plain",
            "body_version": 1,
        }
        with (
            patch.object(newsfeed, "ddb_query", return_value=refs),
            patch.object(
                newsfeed.ddb,
                "batch_get_item",
                side_effect=[
                    {"Responses": {newsfeed.APP_TABLE: [p_published, p_scheduled, p_cancelled]}},
                    {"Responses": {newsfeed.APP_TABLE: []}},
                ],
            ),
            patch.object(newsfeed, "is_hidden", return_value=False),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=False),
            patch.object(newsfeed, "encode_cursor", return_value=None),
        ):
            out = newsfeed.view_feed(limit=20, cursor=None, user_id="viewer_1")

        self.assertEqual([it["post_id"] for it in out["items"]], ["p-published"])
        self.assertEqual(out["items"][0]["status"], "published")


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
        self.assertEqual(out["status"], "published")
        self.assertEqual(out["published_at"], "2026-01-01T00:00:00+00:00")

    def test_post_serializer_includes_schedule_metadata_when_present(self):
        post = {
            "post_id": "p-scheduled",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "America/New_York",
            "scheduled_at_local": "2026-12-31T19:00",
            "body_plain": "scheduled body",
            "body_format": "plain",
            "body_version": 1,
        }

        out = newsfeed._post_to_dict(post)

        self.assertEqual(out["status"], "scheduled")
        self.assertEqual(out["publish_at"], 1767225600)
        self.assertEqual(out["schedule_timezone"], "America/New_York")
        self.assertEqual(out["scheduled_at_local"], "2026-12-31T19:00")
        self.assertIsNone(out["published_at"])

    def test_post_serializer_normalizes_invalid_lifecycle_fields_for_legacy_rows(self):
        post = {
            "post_id": "p-legacy",
            "user_id": "author_1",
            "created_at": "2026-01-01T00:00:00+00:00",
            "status": "unknown_status",
            "publish_at": "not-a-number",
            "schedule_timezone": 1234,
            "scheduled_at_local": {"bad": "shape"},
            "body_plain": "legacy body",
            "body_format": "plain",
            "body_version": 1,
        }

        out = newsfeed._post_to_dict(post)

        self.assertEqual(out["status"], "published")
        self.assertEqual(out["published_at"], "2026-01-01T00:00:00+00:00")
        self.assertIsNone(out["publish_at"])
        self.assertIsNone(out["schedule_timezone"])
        self.assertIsNone(out["scheduled_at_local"])

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

    def test_edit_post_rejects_schedule_update_for_non_scheduled_status(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "published",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        req = newsfeed.EditPostRequest(
            body="still body",
            publish_at=1767225600,
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T19:00",
        )
        with patch.object(newsfeed, "ddb_get_item", return_value=existing):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "schedule_update_not_allowed")

    def test_edit_post_schedule_update_rejects_non_owner(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u2",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        req = newsfeed.EditPostRequest(
            body="rescheduled",
            publish_at=1767229200,
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T20:00",
        )
        with patch.object(newsfeed, "ddb_get_item", return_value=existing):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "Not your post")

    def test_edit_post_accepts_schedule_update_for_scheduled_status(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        req = newsfeed.EditPostRequest(
            body="rescheduled",
            publish_at=1767229200,
            schedule_timezone="America/New_York",
            scheduled_at_local="2026-12-31T20:00",
        )
        updated = {
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767229200,
            "schedule_timezone": "America/New_York",
            "scheduled_at_local": "2026-12-31T20:00",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "rescheduled",
            "body_format": "plain",
            "body_version": 1,
        }
        with (
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "now_iso", return_value="2026-01-02T00:00:00+00:00"),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items") as txn,
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, updated]),
        ):
            out = newsfeed.edit_post("p1", req, user_id="u1")
        self.assertEqual(out["publish_at"], 1767229200)
        self.assertEqual(out["schedule_timezone"], "America/New_York")
        self.assertEqual(out["scheduled_at_local"], "2026-12-31T20:00")
        self.assertEqual(txn.call_count, 1)
        tx_items = txn.call_args.kwargs["TransactItems"]
        self.assertEqual(len(tx_items), 3)
        self.assertIn("Update", tx_items[0])
        self.assertIn("Delete", tx_items[1])
        self.assertIn("Put", tx_items[2])
        update_values = tx_items[0]["Update"]["ExpressionAttributeValues"]
        self.assertIn(":sdpk", update_values)
        self.assertIn(":sdsk", update_values)
    
    def test_edit_post_schedule_update_emits_metric(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        updated = {
            **existing,
            "publish_at": 1767229200,
            "schedule_timezone": "America/New_York",
            "scheduled_at_local": "2026-12-31T20:00",
            "body_plain": "rescheduled",
            "body_format": "plain",
            "body_version": 1,
        }
        req = newsfeed.EditPostRequest(
            body="rescheduled",
            publish_at=1767229200,
            schedule_timezone="America/New_York",
            scheduled_at_local="2026-12-31T20:00",
        )
        with (
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items"),
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, updated]),
            patch.object(newsfeed, "record_newsfeed_schedule_operation") as schedule_metric,
        ):
            newsfeed.edit_post("p1", req, user_id="u1")
        schedule_metric.assert_called_with(operation="edit", outcome="success")

    def test_edit_post_schedule_update_same_publish_at_keeps_scheduled_ref_stable(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        req = newsfeed.EditPostRequest(
            body="same publish, different timezone",
            publish_at=1767225600,
            schedule_timezone="America/New_York",
            scheduled_at_local="2026-12-31T14:00",
        )
        updated = {
            **existing,
            "schedule_timezone": "America/New_York",
            "scheduled_at_local": "2026-12-31T14:00",
            "body_plain": "same publish, different timezone",
            "body_format": "plain",
            "body_version": 1,
        }
        with (
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items") as txn,
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, updated]),
        ):
            out = newsfeed.edit_post("p1", req, user_id="u1")
        self.assertEqual(out["publish_at"], 1767225600)
        self.assertEqual(out["schedule_timezone"], "America/New_York")
        tx_items = txn.call_args.kwargs["TransactItems"]
        self.assertEqual(len(tx_items), 1)
        self.assertIn("Update", tx_items[0])

    def test_edit_post_schedule_conflict_returns_deterministic_code(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        req = newsfeed.EditPostRequest(
            body="rescheduled",
            publish_at=1767229200,
            schedule_timezone="America/New_York",
            scheduled_at_local="2026-12-31T20:00",
        )
        err = newsfeed.ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "conflict"}}, "TransactWriteItems")
        with (
            patch.object(newsfeed, "ddb_get_item", return_value=existing),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items", side_effect=err),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "schedule_edit_conflict")

    def test_edit_post_rejects_publish_at_beyond_max_horizon(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        req = newsfeed.EditPostRequest(
            body="rescheduled",
            publish_at=1767004000,
            schedule_timezone="UTC",
            scheduled_at_local="2026-12-31T20:00",
        )
        with (
            patch.object(newsfeed, "ddb_get_item", return_value=existing),
            patch.object(newsfeed.time, "time", return_value=1767000000),
            patch.object(newsfeed, "_schedule_max_horizon_seconds", return_value=3600),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.edit_post("p1", req, user_id="u1")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schedule_publish_at_too_far")
        self.assertEqual(ctx.exception.detail["maximum_publish_at"], 1767003600)

    def test_cancel_scheduled_post_transitions_and_cleans_scheduled_ref(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        cancelled = {
            **existing,
            "status": "cancelled",
            "publish_at": None,
            "schedule_timezone": None,
            "scheduled_at_local": None,
            "published_at": None,
            "updated_at": "2026-01-02T00:00:00+00:00",
        }
        with (
            patch.object(newsfeed, "now_iso", return_value="2026-01-02T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, cancelled]),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items") as txn,
        ):
            out = newsfeed.cancel_scheduled_post("p1", user_id="u1")
        self.assertEqual(out["status"], "cancelled")
        self.assertIsNone(out["publish_at"])
        self.assertEqual(txn.call_count, 1)
        tx_items = txn.call_args.kwargs["TransactItems"]
        self.assertEqual(len(tx_items), 2)
        self.assertIn("Update", tx_items[0])
        self.assertIn("Delete", tx_items[1])
        self.assertIn("GSI_SCHEDULE_PK", tx_items[0]["Update"]["UpdateExpression"])
        self.assertIn("GSI_SCHEDULE_SK", tx_items[0]["Update"]["UpdateExpression"])

    def test_cancel_scheduled_post_emits_metric(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        cancelled = {**existing, "status": "cancelled", "publish_at": None, "schedule_timezone": None, "scheduled_at_local": None, "published_at": None}
        with (
            patch.object(newsfeed, "now_iso", return_value="2026-01-02T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, cancelled]),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items"),
            patch.object(newsfeed, "record_newsfeed_schedule_operation") as schedule_metric,
        ):
            newsfeed.cancel_scheduled_post("p1", user_id="u1")
        schedule_metric.assert_called_with(operation="cancel", outcome="success")

    def test_cancel_scheduled_post_is_idempotent_for_cancelled_posts(self):
        cancelled = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "cancelled",
            "created_at": "2026-01-01T00:00:00+00:00",
            "body_plain": "cancelled",
            "body_format": "plain",
            "body_version": 1,
        }
        with (
            patch.object(newsfeed, "ddb_get_item", return_value=cancelled),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items") as txn,
        ):
            out = newsfeed.cancel_scheduled_post("p1", user_id="u1")
        self.assertEqual(out["status"], "cancelled")
        txn.assert_not_called()

    def test_cancel_scheduled_post_rejects_non_scheduled_posts(self):
        published = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "published",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch.object(newsfeed, "ddb_get_item", return_value=published):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.cancel_scheduled_post("p1", user_id="u1")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "schedule_cancel_not_allowed")

    def test_cancel_scheduled_post_rejects_non_owner(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u2",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch.object(newsfeed, "ddb_get_item", return_value=existing):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.cancel_scheduled_post("p1", user_id="u1")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "Not your post")

    def test_cancel_scheduled_post_conflict_is_retry_safe(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        cancelled = {
            **existing,
            "status": "cancelled",
            "publish_at": None,
            "schedule_timezone": None,
            "scheduled_at_local": None,
        }
        err = newsfeed.ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "conflict"}}, "TransactWriteItems")
        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, cancelled]),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items", side_effect=err),
        ):
            out = newsfeed.cancel_scheduled_post("p1", user_id="u1")
        self.assertEqual(out["status"], "cancelled")

    def test_cancel_scheduled_post_conflict_returns_deterministic_code_when_still_scheduled(self):
        existing = {
            "pk": newsfeed.pk_post("p1"),
            "sk": newsfeed.sk_post(),
            "post_id": "p1",
            "user_id": "u1",
            "status": "scheduled",
            "publish_at": 1767225600,
            "schedule_timezone": "UTC",
            "scheduled_at_local": "2026-12-31T19:00",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        err = newsfeed.ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "conflict"}}, "TransactWriteItems")
        with (
            patch.object(newsfeed, "ddb_get_item", side_effect=[existing, existing]),
            patch.object(newsfeed.ddb.meta.client, "transact_write_items", side_effect=err),
        ):
            with self.assertRaises(newsfeed.HTTPException) as ctx:
                newsfeed.cancel_scheduled_post("p1", user_id="u1")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "schedule_cancel_conflict")

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
