import unittest
import asyncio
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.routers import newsfeed


class TestNewsfeedRoutes(unittest.TestCase):
    def test_meter_newsfeed_post_publish_builds_deterministic_idempotency_key(self):
        table = Mock()
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table

            newsfeed._meter_newsfeed_post_publish(user_id="u1", post_id="p1")

        ddb.Table.assert_called_once_with("FileManager")
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_post")
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_post|p1")

    def test_create_post_success_records_usage_once(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = Mock()
            newsfeed.create_post(req, x_user_id="u1")

        self.assertEqual(put_item.call_count, 2)
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_post")
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_post|post_abc")

    def test_create_post_failed_create_does_not_record_usage(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item", side_effect=RuntimeError("ddb down")),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = Mock()
            with self.assertRaises(RuntimeError):
                newsfeed.create_post(req, x_user_id="u1")

        record_usage.assert_not_called()

    def test_create_post_meters_successful_create(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item") as put_item,
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_post,
            patch.object(newsfeed, "_meter_newsfeed_attachment_uploads") as meter_attachments,
        ):
            resp = newsfeed.create_post(req, x_user_id="u1")

        self.assertEqual(put_item.call_count, 2)
        meter_post.assert_called_once_with(user_id="u1", post_id="post_abc")
        meter_attachments.assert_called_once()
        self.assertEqual(resp.post_id, "post_abc")

    def test_create_post_failed_create_does_not_meter(self):
        req = newsfeed.CreatePostRequest(
            body=newsfeed.RichTextDoc(format="tiptap-json", doc={"type": "doc", "content": []}),
        )

        with (
            patch.object(newsfeed, "new_id", return_value="post_abc"),
            patch.object(newsfeed, "now_iso", return_value="2026-01-01T00:00:00+00:00"),
            patch.object(newsfeed, "ddb_put_item", side_effect=RuntimeError("ddb down")),
            patch.object(newsfeed, "_enforce_newsfeed_post_quota_precheck"),
            patch.object(newsfeed, "_meter_newsfeed_post_publish") as meter_post,
            patch.object(newsfeed, "_meter_newsfeed_attachment_uploads") as meter_attachments,
        ):
            with self.assertRaises(RuntimeError):
                newsfeed.create_post(req, x_user_id="u1")

        meter_post.assert_not_called()
        meter_attachments.assert_not_called()

    def test_meter_newsfeed_attachment_uploads_uses_authoritative_content_length(self):
        table = Mock()
        attachment = newsfeed.Attachment(
            attachment_id="att1",
            filename="a.png",
            content_type="image/png",
            s3_key="uploads/u1/att1/a.png",
        )
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "s3") as s3,
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            s3.head_object.return_value = {"ContentLength": 321}

            newsfeed._meter_newsfeed_attachment_uploads(
                user_id="u1",
                post_id="p1",
                attachments=[attachment],
            )

        s3.head_object.assert_called_once_with(Bucket="bucket", Key="uploads/u1/att1/a.png")
        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_attachment_upload")
        self.assertEqual(event["bytes"], 321)
        self.assertEqual(
            event["idempotency_key"],
            "u1|newsfeed_attachment_upload|bucket/uploads/u1/att1/a.png|p1",
        )

    def test_meter_newsfeed_attachment_uploads_skips_nonpositive_head_size(self):
        table = Mock()
        attachment = newsfeed.Attachment(
            attachment_id="att1",
            filename="a.png",
            content_type="image/png",
            s3_key="uploads/u1/att1/a.png",
        )
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "s3") as s3,
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table
            s3.head_object.return_value = {"ContentLength": 0}

            newsfeed._meter_newsfeed_attachment_uploads(
                user_id="u1",
                post_id="p1",
                attachments=[attachment],
            )

        record_usage.assert_not_called()

    def test_record_newsfeed_attachment_download_builds_deterministic_key(self):
        table = Mock()
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "ddb") as ddb,
            patch.object(newsfeed, "record_usage_event_and_aggregates") as record_usage,
        ):
            settings.filemgr_table_name = "FileManager"
            ddb.Table.return_value = table

            newsfeed._record_newsfeed_attachment_download(
                user_id="u1",
                post_id="p1",
                attachment_key="bucket/uploads/u1/att/a.png",
                bytes_count=77,
                idempotency_operation_id="req-1",
            )

        record_usage.assert_called_once()
        event = record_usage.call_args.args[1]
        self.assertEqual(event["source"], "newsfeed_attachment_download")
        self.assertEqual(event["bytes"], 77)
        self.assertEqual(event["idempotency_key"], "u1|newsfeed_attachment_download|bucket/uploads/u1/att/a.png|req-1")

    def test_download_post_attachment_streams_and_records_download_bytes(self):
        class _Body:
            def iter_chunks(self, chunk_size=65536):
                yield b"ab"
                yield b"cde"

        post = {
            "post_id": "p1",
            "user_id": "u1",
            "attachments": [
                {
                    "attachment_id": "att1",
                    "filename": "a.png",
                    "content_type": "image/png",
                    "s3_key": "uploads/u1/att1/a.png",
                }
            ],
        }
        with (
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "s3") as s3,
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "_record_newsfeed_attachment_download") as meter_download,
        ):
            s3.get_object.return_value = {
                "Body": _Body(),
                "ContentLength": 5,
                "ContentType": "image/png",
            }
            resp = newsfeed.download_post_attachment("p1", "att1", x_user_id="u1", x_request_id="req-1")

            async def _collect() -> bytes:
                chunks = []
                async for chunk in resp.body_iterator:
                    chunks.append(chunk)
                return b"".join(chunks)

            self.assertEqual(asyncio.run(_collect()), b"abcde")

        meter_download.assert_called_once_with(
            user_id="u1",
            post_id="p1",
            attachment_key="bucket/uploads/u1/att1/a.png",
            bytes_count=5,
            idempotency_operation_id="req-1",
        )

    def test_download_post_attachment_locked_requires_unlock(self):
        post = {
            "post_id": "p1",
            "user_id": "u2",
            "locked": True,
            "attachments": [{"attachment_id": "att1", "s3_key": "uploads/u2/att1/a.png"}],
        }
        with (
            patch.object(newsfeed, "UPLOAD_BUCKET", "bucket"),
            patch.object(newsfeed, "s3", Mock()),
            patch.object(newsfeed, "ddb_get_item", return_value=post),
            patch.object(newsfeed, "can_access_creator", return_value=True),
            patch.object(newsfeed, "is_following", return_value=True),
            patch.object(newsfeed, "has_unlocked", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                newsfeed.download_post_attachment("p1", "att1", x_user_id="u1", x_request_id=None)

        self.assertEqual(ctx.exception.status_code, 402)


    def test_newsfeed_post_quota_precheck_blocks_over_limit(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "get_usage_summary", return_value={
                "period_id": "2026-04",
                "post_publish": {"used_count": 5, "limit_count": 5},
            }),
        ):
            settings.filemgr_table_name = "FileManager"
            settings.newsfeed_post_quota_overage_mode = "block"
            with self.assertRaises(HTTPException) as ctx:
                newsfeed._enforce_newsfeed_post_quota_precheck(user_id="u1")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "newsfeed_post_quota_exceeded")

    def test_newsfeed_post_quota_precheck_allows_overage_mode_allow(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "get_usage_summary", return_value={
                "period_id": "2026-04",
                "post_publish": {"used_count": 5, "limit_count": 5},
            }),
        ):
            settings.filemgr_table_name = "FileManager"
            settings.newsfeed_post_quota_overage_mode = "allow"
            newsfeed._enforce_newsfeed_post_quota_precheck(user_id="u1")

    def test_newsfeed_post_quota_warnings_emit_for_configured_thresholds(self):
        with (
            patch.object(newsfeed, "S") as settings,
            patch.object(newsfeed, "get_usage_summary", return_value={
                "period_id": "2026-04",
                "post_publish": {"used_count": 0, "limit_count": 1},
            }),
            patch.object(newsfeed, "_emit_newsfeed_post_quota_warning") as emit_warning,
        ):
            settings.filemgr_table_name = "FileManager"
            settings.newsfeed_post_quota_soft_warnings_enabled = True
            settings.newsfeed_post_quota_warning_thresholds = "80,95"
            newsfeed._enforce_newsfeed_post_quota_precheck(user_id="u1")

        self.assertEqual(emit_warning.call_count, 2)
        self.assertEqual(emit_warning.call_args_list[0].kwargs["threshold_percent"], 80)
        self.assertEqual(emit_warning.call_args_list[1].kwargs["threshold_percent"], 95)


if __name__ == "__main__":
    unittest.main()
