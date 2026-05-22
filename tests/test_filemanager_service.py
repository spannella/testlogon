import io
import tarfile
from types import SimpleNamespace
import unittest
import warnings
import zipfile
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException, UploadFile

from app.services import filemanager


class TestFileManagerService(unittest.TestCase):

    def test_resolve_user_usage_plan_from_db(self):
        table = Mock()
        table.get_item.return_value = {"Item": {"plan_id": "pro"}}
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_default_plan = "default"
            settings.filemgr_usage_plan_limits = '{"pro":{"upload_limit_bytes":300,"download_limit_bytes":400,"storage_limit_bytes":500,"message_send_limit_count":30,"post_publish_limit_count":12}}'
            settings.filemgr_usage_user_plan_overrides = ""
            out = filemanager.resolve_user_usage_plan("u1")
        self.assertEqual(out["plan_id"], "pro")
        self.assertEqual(out["upload_limit_bytes"], 300)
        self.assertEqual(out["source"], "db")
        self.assertEqual(out["message_send_limit_count"], 30)
        self.assertEqual(out["post_publish_limit_count"], 12)

    def test_resolve_user_usage_plan_missing_unit_limits_are_unlimited(self):
        table = Mock()
        table.get_item.return_value = {"Item": {"plan_id": "starter"}}
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_default_plan = "default"
            settings.filemgr_usage_plan_limits = '{"starter":{"upload_limit_bytes":10}}'
            settings.filemgr_usage_user_plan_overrides = ""
            settings.filemgr_usage_message_send_limit_count = 0
            settings.filemgr_usage_post_publish_limit_count = 0
            out = filemanager.resolve_user_usage_plan("u1")

        self.assertEqual(out["plan_id"], "starter")
        self.assertEqual(out["message_send_limit_count"], 0)
        self.assertEqual(out["post_publish_limit_count"], 0)


    def test_upload_file_hard_quota_enforcement_returns_machine_readable_detail(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "S") as settings,
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "get_usage_summary", return_value={
                "upload": {"used_bytes": 95, "limit_bytes": 100},
                "storage": {"used_bytes": 10, "limit_bytes": 1000},
            }),
        ):
            settings.filemgr_table_name = "tbl"
            s3.head_object.return_value = {"ContentLength": 10, "ETag": "etag"}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_file("user", "/docs/a.txt", upload)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "upload_quota_exceeded")
        self.assertEqual(ctx.exception.detail["remaining_bytes"], 5)
        s3.delete_object.assert_called_once()

    def test_assert_download_allowed_enforced(self):
        with (
            patch.object(filemanager, "S") as settings,
            patch.object(filemanager, "get_usage_summary", return_value={
                "download": {"used_bytes": 100, "limit_bytes": 100},
            }),
        ):
            settings.filemgr_download_policy_mode = "enforce"
            with self.assertRaises(HTTPException) as ctx:
                filemanager.assert_download_allowed("user", requested_bytes=1)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "download_quota_exceeded")

    def test_upload_file_rejects_existing_path(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists") as require_not_exists,
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            filemanager.upload_file("user", "/docs/a.txt", upload)
        require_not_exists.assert_called_once()

    def test_upload_file_persists_media_derivative_layout(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": '"etag-1"'}
            filemanager.upload_file("user", "/docs/a.txt", upload)

        stored = put_node.call_args.kwargs.get("item") or put_node.call_args.args[0]
        self.assertIn("media_preview_version", stored)
        self.assertTrue(stored["media_preview_prefix"].startswith("user/derived/media/"))
        self.assertIn("poster_image", stored["media_preview_keys"])
        self.assertIn("hover_clip", stored["media_preview_keys"])
        self.assertIn("waveform_image", stored["media_preview_keys"])


    def test_upload_file_persists_encrypted_flags(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "application/octet-stream"})
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            filemanager.upload_file(
                "user",
                "/docs/a.txt",
                upload,
                encryption_meta={
                    "version": 1,
                    "alg": "AES-256-GCM",
                    "kdf": "PBKDF2-SHA256",
                    "iterations": 600000,
                    "salt_b64": "c2FsdA==",
                    "iv_b64": "aXY=",
                    "orig_name": "a.txt",
                    "orig_size": 5,
                    "mime": "text/plain",
                },
            )
        stored = put_node.call_args.kwargs["item"] if "item" in put_node.call_args.kwargs else put_node.call_args.args[0]
        self.assertTrue(stored["is_encrypted"])
        self.assertIn("enc_metadata", stored)
        self.assertEqual(stored["enc_version"], 1)
        self.assertEqual(stored["enc_alg"], "AES-256-GCM")

    def test_upload_file_rejects_invalid_encryption_meta(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "application/octet-stream"})
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_file(
                    "user",
                    "/docs/a.txt",
                    upload,
                    encryption_meta={
                        "version": 2,
                        "alg": "AES-256-GCM",
                        "kdf": "PBKDF2-SHA256",
                        "iterations": 10,
                        "salt_b64": "%%%",
                        "iv_b64": "i",
                        "orig_name": "a.txt",
                        "orig_size": -1,
                        "mime": "text/plain",
                    },
                )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_upload_file_rejects_missing_encryption_meta_keys(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"), headers={"content-type": "application/octet-stream"})
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_file(
                    "user",
                    "/docs/a.txt",
                    upload,
                    encryption_meta={"version": 1, "alg": "AES-256-GCM"},
                )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_preview_kind_normalization_prefers_extension_for_ambiguous_content_type(self):
        self.assertEqual(
            filemanager._detect_preview_kind({"name": "report.docx", "content_type": "application/octet-stream"}),
            "word",
        )
        self.assertEqual(
            filemanager._detect_preview_kind({"name": "sheet.xlsx", "content_type": "application/octet-stream"}),
            "excel",
        )
        self.assertEqual(
            filemanager._detect_preview_kind({"name": "data.csv", "content_type": "application/vnd.ms-excel"}),
            "csv",
        )

    def test_media_derivative_layout_uses_versioned_prefix_and_expected_keys(self):
        layout = filemanager.build_media_derivative_layout(
            owner="user",
            source_key="user/objects/abc123",
            etag='"etag-1"',
            size=42,
        )
        self.assertIn("media_preview_version", layout)
        self.assertTrue(layout["media_preview_prefix"].startswith("user/derived/media/"))
        self.assertEqual(
            layout["media_preview_keys"],
            {
                "poster_image": f"{layout['media_preview_prefix']}/poster_image.webp",
                "hover_clip": f"{layout['media_preview_prefix']}/hover_clip.mp4",
                "waveform_image": f"{layout['media_preview_prefix']}/waveform_image.png",
            },
        )

    def test_media_derivative_layout_changes_when_source_version_changes(self):
        first = filemanager.build_media_derivative_layout("user", "user/objects/abc123", "etag-1", 42)
        second = filemanager.build_media_derivative_layout("user", "user/objects/abc123", "etag-2", 42)
        self.assertNotEqual(first["media_preview_version"], second["media_preview_version"])
        self.assertNotEqual(first["media_preview_prefix"], second["media_preview_prefix"])

    def test_normalize_media_inspection_result_is_deterministic(self):
        probe = {
            "format": {"duration": "12.9", "format_name": "mov,mp4,m4a,3gp,3g2,mj2"},
            "streams": [
                {"index": 2, "codec_type": "audio", "codec_name": "aac", "sample_rate": "48000", "channels": 2},
                {"index": 1, "codec_type": "video", "codec_name": "h264", "width": 1280, "height": 720},
            ],
        }
        out = filemanager.normalize_media_inspection_result(probe, content_type_hint="video/mp4")
        self.assertTrue(out["ok"])
        self.assertEqual(out["mime_type"], "video/mp4")
        self.assertEqual(out["container"], "mov")
        self.assertEqual(out["duration_seconds"], 12)
        self.assertEqual(out["primary_video_codec"], "h264")
        self.assertEqual(out["primary_audio_codec"], "aac")
        self.assertEqual([s["index"] for s in out["streams"]], [1, 2])

    def test_inspect_media_object_handles_malformed_probe_output(self):
        with (
            patch.object(filemanager.shutil, "which", return_value="/usr/bin/ffprobe"),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="not-json")),
        ):
            s3.download_fileobj = Mock()
            out = filemanager.inspect_media_object(bucket="bucket", s3_key="user/objects/a", content_type_hint="video/mp4")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "probe_malformed")

    def test_inspect_media_object_handles_probe_failure(self):
        with (
            patch.object(filemanager.shutil, "which", return_value="/usr/bin/ffprobe"),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")),
        ):
            s3.download_fileobj = Mock()
            out = filemanager.inspect_media_object(bucket="bucket", s3_key="user/objects/a", content_type_hint="video/mp4")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "probe_failed")

    def test_inspect_media_object_happy_path(self):
        probe_json = {
            "format": {"duration": "7.5", "format_name": "matroska,webm"},
            "streams": [
                {"index": 0, "codec_type": "video", "codec_name": "vp9", "width": 640, "height": 360},
                {"index": 1, "codec_type": "audio", "codec_name": "opus", "sample_rate": "48000", "channels": 2},
            ],
        }
        with (
            patch.object(filemanager.shutil, "which", return_value="/usr/bin/ffprobe"),
            patch.object(filemanager, "_s3") as s3,
            patch.object(
                filemanager.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout=filemanager.json.dumps(probe_json)),
            ),
        ):
            s3.download_fileobj = Mock()
            out = filemanager.inspect_media_object(bucket="bucket", s3_key="user/objects/a", content_type_hint="video/webm")
        self.assertTrue(out["ok"])
        self.assertEqual(out["container"], "matroska")
        self.assertEqual(out["duration_seconds"], 7)
        self.assertEqual(out["primary_video_codec"], "vp9")
        self.assertEqual(out["primary_audio_codec"], "opus")

    def test_media_preview_eligibility_video_guards(self):
        with patch.object(
            filemanager,
            "S",
            SimpleNamespace(
                filemgr_video_preview_max_mb=1,
                filemgr_video_preview_max_duration_seconds=10,
                filemgr_audio_waveform_max_mb=100,
            ),
        ):
            too_large = filemanager.media_preview_eligibility_from_node(
                {"content_type": "video/mp4", "size": 2 * 1024 * 1024, "media_inspection": {"container": "mp4", "primary_video_codec": "h264", "duration_seconds": 5}}
            )
            self.assertFalse(too_large["eligible"])
            self.assertEqual(too_large["reason"], "too_large")

            too_long = filemanager.media_preview_eligibility_from_node(
                {"content_type": "video/mp4", "size": 10, "media_inspection": {"container": "mp4", "primary_video_codec": "h264", "duration_seconds": 20}}
            )
            self.assertFalse(too_long["eligible"])
            self.assertEqual(too_long["reason"], "too_long")

            bad_codec = filemanager.media_preview_eligibility_from_node(
                {"content_type": "video/mp4", "size": 10, "media_inspection": {"container": "mp4", "primary_video_codec": "mpeg2video", "duration_seconds": 5}}
            )
            self.assertFalse(bad_codec["eligible"])
            self.assertEqual(bad_codec["reason"], "unsupported_codec")

    def test_media_preview_eligibility_audio_guard(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_audio_waveform_max_mb=1, filemgr_video_preview_max_mb=200, filemgr_video_preview_max_duration_seconds=600)):
            too_large = filemanager.media_preview_eligibility_from_node(
                {"content_type": "audio/mpeg", "size": 2 * 1024 * 1024, "media_inspection": {"primary_audio_codec": "mp3"}}
            )
            self.assertFalse(too_large["eligible"])
            self.assertEqual(too_large["reason"], "too_large")

            bad_codec = filemanager.media_preview_eligibility_from_node(
                {"content_type": "audio/mpeg", "size": 10, "media_inspection": {"primary_audio_codec": "amr_nb"}}
            )
            self.assertFalse(bad_codec["eligible"])
            self.assertEqual(bad_codec["reason"], "unsupported_codec")

    def test_media_preview_eligibility_rejects_unsupported_container(self):
        with patch.object(
            filemanager,
            "S",
            SimpleNamespace(
                filemgr_video_preview_max_mb=50,
                filemgr_video_preview_max_duration_seconds=60,
                filemgr_audio_waveform_max_mb=50,
            ),
        ):
            out = filemanager.media_preview_eligibility_from_node(
                {
                    "content_type": "video/ogg",
                    "size": 1024,
                    "media_inspection": {
                        "container": "ogg",
                        "primary_video_codec": "theora",
                        "duration_seconds": 5,
                    },
                }
            )
        self.assertFalse(out["eligible"])
        self.assertEqual(out["reason"], "unsupported_container")

    def test_preview_status_state_machine_video_reasons(self):
        with patch.object(
            filemanager,
            "S",
            SimpleNamespace(
                filemgr_media_previews_v1=True,
                filemgr_video_hover_clip_enabled=True,
                filemgr_audio_waveform_enabled=True,
                filemgr_preview_max_bytes=10485760,
                filemgr_video_preview_max_mb=50,
                filemgr_video_preview_max_duration_seconds=120,
                filemgr_audio_waveform_max_mb=50,
            ),
        ):
            unsupported = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "bad.mov",
                    "content_type": "video/quicktime",
                    "size": 1024,
                    "media_inspection": {"container": "mov", "primary_video_codec": "mpeg2video", "duration_seconds": 5},
                    "is_encrypted": False,
                }
            )
            self.assertEqual(unsupported["preview_status"], "unsupported")
            self.assertEqual(unsupported["preview_reason"], "unsupported_codec")

            pending = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "queued.mp4",
                    "content_type": "video/mp4",
                    "size": 1024,
                    "media_inspection": {"container": "mp4", "primary_video_codec": "h264", "duration_seconds": 5},
                    "is_encrypted": False,
                }
            )
            self.assertEqual(pending["preview_status"], "pending")
            self.assertEqual(pending["preview_reason"], "transcoding_pending")

            ready = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "ready.mp4",
                    "content_type": "video/mp4",
                    "size": 1024,
                    "poster_url": "https://example/poster.webp",
                    "hover_preview_url": "https://example/clip.mp4",
                    "media_inspection": {"container": "mp4", "primary_video_codec": "h264", "duration_seconds": 5},
                    "is_encrypted": False,
                }
            )
            self.assertEqual(ready["preview_status"], "ready")
            self.assertIsNone(ready["preview_reason"])

    def test_preview_capability_marks_media_unsupported_when_ineligible(self):
        with patch.object(
            filemanager,
            "S",
            SimpleNamespace(
                filemgr_media_previews_v1=True,
                filemgr_video_hover_clip_enabled=True,
                filemgr_audio_waveform_enabled=True,
                filemgr_preview_max_bytes=10485760,
                filemgr_video_preview_max_mb=1,
                filemgr_video_preview_max_duration_seconds=600,
                filemgr_audio_waveform_max_mb=100,
            ),
        ):
            info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "big.mp4",
                    "content_type": "video/mp4",
                    "size": 2 * 1024 * 1024,
                    "media_inspection": {"container": "mp4", "primary_video_codec": "h264", "duration_seconds": 20},
                    "is_encrypted": False,
                }
            )
            self.assertEqual(info["preview_kind"], "video")
            self.assertEqual(info["preview_status"], "unsupported")
            self.assertEqual(info["preview_reason"], "too_large")

    def test_preview_capability_honors_media_preview_status_override(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=True, filemgr_video_hover_clip_enabled=True, filemgr_audio_waveform_enabled=True, filemgr_preview_max_bytes=10485760, filemgr_video_preview_max_mb=200, filemgr_video_preview_max_duration_seconds=600, filemgr_audio_waveform_max_mb=100)):
            pending = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "clip.mp4",
                    "content_type": "video/mp4",
                    "size": 100,
                    "media_preview_status": "pending",
                    "media_preview_reason": "transcoding_pending",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(pending["preview_status"], "pending")
            self.assertEqual(pending["preview_reason"], "transcoding_pending")

            failed = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "clip.mp4",
                    "content_type": "video/mp4",
                    "size": 100,
                    "media_preview_status": "failed",
                    "media_preview_reason": "generation_failed",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(failed["preview_status"], "failed")
            self.assertEqual(failed["preview_reason"], "generation_failed")

    def test_enqueue_media_preview_job_sets_pending_or_unsupported(self):
        table = Mock()
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "media_preview_eligibility_from_node", return_value={"eligible": True, "reason": None}),
        ):
            table.get_item.return_value = {}
            filemanager._enqueue_media_preview_job(
                "user",
                {
                    "PK": "USER#user",
                    "SK": "NODE#/docs/clip.mp4",
                    "path": "/docs/clip.mp4",
                    "content_type": "video/mp4",
                },
            )
        self.assertGreaterEqual(table.put_item.call_count, 1)
        self.assertGreaterEqual(table.update_item.call_count, 1)

    def test_enqueue_media_preview_job_is_idempotent_for_duplicate_events(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "status": "pending",
                "job_id": "v-dup",
            }
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "media_preview_eligibility_from_node", return_value={"eligible": True, "reason": None}),
        ):
            filemanager._enqueue_media_preview_job(
                "user",
                {
                    "PK": "USER#user",
                    "SK": "NODE#/docs/clip.mp4",
                    "path": "/docs/clip.mp4",
                    "content_type": "video/mp4",
                    "media_preview_version": "abc",
                    "s3_key": "user/objects/1",
                    "etag": "etag",
                    "size": 10,
                },
            )
        table.put_item.assert_not_called()
        self.assertGreaterEqual(table.update_item.call_count, 1)

        table2 = Mock()
        with (
            patch.object(filemanager, "_table", return_value=table2),
            patch.object(filemanager, "media_preview_eligibility_from_node", return_value={"eligible": False, "reason": "unsupported_codec"}),
        ):
            filemanager._enqueue_media_preview_job(
                "user",
                {
                    "PK": "USER#user",
                    "SK": "NODE#/docs/clip.mp4",
                    "path": "/docs/clip.mp4",
                    "content_type": "video/mp4",
                },
            )
        table2.put_item.assert_not_called()
        self.assertGreaterEqual(table2.update_item.call_count, 1)

    def test_mark_media_preview_job_failed_retries_then_dead_letters(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid",
                "job_id": "jid",
                "path": "/docs/clip.mp4",
                "attempts": 0,
                "max_attempts": 2,
                "status": "pending",
            }
        }
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.mark_media_preview_job_failed("user", "jid", reason="ffmpeg_timeout", transient=True)
        self.assertEqual(out["status"], "retry_pending")
        self.assertFalse(out["dead_letter"])

        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid",
                "job_id": "jid",
                "path": "/docs/clip.mp4",
                "attempts": 1,
                "max_attempts": 2,
                "status": "retry_pending",
            }
        }
        with patch.object(filemanager, "_table", return_value=table):
            out2 = filemanager.mark_media_preview_job_failed("user", "jid", reason="unsupported_codec", transient=False)
        self.assertEqual(out2["status"], "dead_letter")
        self.assertTrue(out2["dead_letter"])

    def test_run_media_preview_job_completes_and_sets_poster(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid",
                "job_id": "jid",
                "path": "/docs/clip.mp4",
                "preview_kind": "video",
                "status": "pending",
            }
        }
        node = {
            "path": "/docs/clip.mp4",
            "s3_bucket": "bucket",
            "s3_key": "user/objects/abc",
            "media_preview_keys": {
                "poster_image": "user/derived/media/ver/poster_image.webp",
                "hover_clip": "user/derived/media/ver/hover_clip.mp4",
            },
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "get_node", return_value=node),
            patch.object(filemanager, "_extract_video_poster_bytes", return_value={"bytes": b"img", "content_type": "image/webp", "ext": "webp"}),
            patch.object(filemanager, "_extract_video_hover_clip_bytes", return_value={"bytes": b"clip", "content_type": "video/mp4", "ext": "mp4"}),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "S", SimpleNamespace(filemgr_media_preview_cdn_base_url="", filemgr_media_preview_private=True, filemgr_media_preview_url_ttl_seconds=900)),
        ):
            s3.generate_presigned_url.side_effect = ["https://signed/poster", "https://signed/clip"]
            out = filemanager.run_media_preview_job("user", "jid")
        self.assertEqual(out["status"], "completed")
        self.assertIn("hover_preview_url", out)
        self.assertEqual(s3.put_object.call_count, 2)
        for c in s3.put_object.call_args_list:
            self.assertEqual(c.kwargs.get("CacheControl"), "public, immutable, max-age=31536000")
        self.assertGreaterEqual(table.update_item.call_count, 1)

    def test_run_media_preview_job_marks_failed_when_poster_generation_fails(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid",
                "job_id": "jid",
                "path": "/docs/clip.mp4",
                "preview_kind": "video",
                "status": "pending",
                "attempts": 0,
                "max_attempts": 2,
            }
        }
        node = {
            "path": "/docs/clip.mp4",
            "s3_bucket": "bucket",
            "s3_key": "user/objects/abc",
            "media_preview_keys": {"poster_image": "user/derived/media/ver/poster_image.webp"},
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "get_node", return_value=node),
            patch.object(filemanager, "_extract_video_poster_bytes", return_value=None),
        ):
            out = filemanager.run_media_preview_job("user", "jid")
        self.assertEqual(out["status"], "retry_pending")
        self.assertEqual(out["reason"], "poster_generation_failed")

    def test_run_media_preview_job_dead_letters_when_retry_budget_exhausted(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid",
                "job_id": "jid",
                "path": "/docs/clip.mp4",
                "preview_kind": "video",
                "status": "pending",
                "attempts": 1,
                "max_attempts": 2,
            }
        }
        node = {
            "path": "/docs/clip.mp4",
            "s3_bucket": "bucket",
            "s3_key": "user/objects/abc",
            "media_preview_keys": {"poster_image": "user/derived/media/ver/poster_image.webp"},
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "get_node", return_value=node),
            patch.object(filemanager, "_extract_video_poster_bytes", return_value=None),
        ):
            out = filemanager.run_media_preview_job("user", "jid")
        self.assertEqual(out["status"], "dead_letter")
        self.assertTrue(out["dead_letter"])
        self.assertEqual(out["reason"], "poster_generation_failed")

    def test_extract_video_hover_clip_bytes_honors_config(self):
        class _FakeRun:
            def __init__(self):
                self.args = None

            def __call__(self, args, **kwargs):
                self.args = args
                out_path = args[-1]
                with open(out_path, "wb") as fh:
                    fh.write(b"clip")
                return SimpleNamespace(returncode=0)

        fake_run = _FakeRun()
        with (
            patch.object(filemanager.shutil, "which", return_value="/usr/bin/ffmpeg"),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "_run_media_tool", side_effect=fake_run),
            patch.object(filemanager, "S", SimpleNamespace(filemgr_video_preview_target_height=240, filemgr_video_preview_clip_seconds=4)),
        ):
            s3.download_fileobj = Mock()
            out = filemanager._extract_video_hover_clip_bytes("bucket", "user/objects/abc")

        self.assertIsNotNone(out)
        self.assertEqual(out["content_type"], "video/mp4")
        self.assertIn("-t", fake_run.args)
        self.assertIn("4", fake_run.args)
        self.assertIn("scale=-2:240", fake_run.args)

    def test_extract_video_hover_clip_bytes_handles_timeout_safely(self):
        with (
            patch.object(filemanager.shutil, "which", return_value="/usr/bin/ffmpeg"),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "_run_media_tool", side_effect=filemanager.subprocess.TimeoutExpired(cmd="ffmpeg", timeout=1)),
        ):
            s3.download_fileobj = Mock()
            out = filemanager._extract_video_hover_clip_bytes("bucket", "user/objects/abc")
        self.assertIsNone(out)

    def test_extract_audio_waveform_bytes_uses_standardized_filter(self):
        class _FakeRun:
            def __init__(self):
                self.args = None

            def __call__(self, args, **kwargs):
                self.args = args
                out_path = args[-1]
                with open(out_path, "wb") as fh:
                    fh.write(b"wave")
                return SimpleNamespace(returncode=0)

        fake_run = _FakeRun()
        with (
            patch.object(filemanager.shutil, "which", return_value="/usr/bin/ffmpeg"),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "_run_media_tool", side_effect=fake_run),
        ):
            s3.download_fileobj = Mock()
            out = filemanager._extract_audio_waveform_bytes("bucket", "user/objects/a")
        self.assertIsNotNone(out)
        self.assertEqual(out["content_type"], "image/png")
        self.assertIn("showwavespic=s=640x120:colors=0x4f46e5", " ".join(fake_run.args))

    def test_run_media_preview_job_completes_and_sets_waveform(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid-a",
                "job_id": "jid-a",
                "path": "/docs/track.mp3",
                "preview_kind": "audio",
                "status": "pending",
            }
        }
        node = {
            "path": "/docs/track.mp3",
            "s3_bucket": "bucket",
            "s3_key": "user/objects/audio",
            "media_preview_keys": {"waveform_image": "user/derived/media/ver/waveform_image.png"},
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "get_node", return_value=node),
            patch.object(filemanager, "_extract_audio_waveform_bytes", return_value={"bytes": b"wave", "content_type": "image/png", "ext": "png"}),
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "S", SimpleNamespace(filemgr_media_preview_cdn_base_url="", filemgr_media_preview_private=True, filemgr_media_preview_url_ttl_seconds=900)),
        ):
            s3.generate_presigned_url.return_value = "https://signed/wave"
            out = filemanager.run_media_preview_job("user", "jid-a")
        self.assertEqual(out["status"], "completed")
        self.assertIn("waveform_url", out)
        s3.put_object.assert_called_once()
        self.assertEqual(s3.put_object.call_args.kwargs.get("CacheControl"), "public, immutable, max-age=31536000")

    def test_preview_capability_audio_ready_uses_signed_derivative_url(self):
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=True, filemgr_video_hover_clip_enabled=True, filemgr_audio_waveform_enabled=True, filemgr_preview_max_bytes=10485760, filemgr_media_preview_cdn_base_url="", filemgr_media_preview_private=True, filemgr_media_preview_url_ttl_seconds=600)),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.generate_presigned_url.return_value = "https://signed/wave-derivative"
            info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "track.mp3",
                    "content_type": "audio/mpeg",
                    "size": 100,
                    "s3_bucket": "bucket",
                    "media_preview_status": "ready",
                    "media_preview_reason": None,
                    "media_preview_keys": {"waveform_image": "user/derived/media/ver/waveform_image.png"},
                    "is_encrypted": False,
                }
            )
        self.assertEqual(info["preview_status"], "ready")
        self.assertEqual(info["waveform_url"], "https://signed/wave-derivative")

    def test_preview_capability_audio_ready_uses_cdn_when_public(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=True, filemgr_video_hover_clip_enabled=True, filemgr_audio_waveform_enabled=True, filemgr_preview_max_bytes=10485760, filemgr_media_preview_cdn_base_url="https://cdn.example", filemgr_media_preview_private=False, filemgr_media_preview_url_ttl_seconds=600)):
            info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "track.mp3",
                    "content_type": "audio/mpeg",
                    "size": 100,
                    "s3_bucket": "bucket",
                    "media_preview_status": "ready",
                    "media_preview_reason": None,
                    "media_preview_keys": {"waveform_image": "user/derived/media/ver/waveform_image.png"},
                    "is_encrypted": False,
                }
            )
        self.assertEqual(info["waveform_url"], "https://cdn.example/user/derived/media/ver/waveform_image.png")

    def test_run_media_preview_job_marks_failed_when_waveform_generation_fails(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "PK": "USER#user",
                "SK": "PREVIEWJOB#jid-a",
                "job_id": "jid-a",
                "path": "/docs/track.mp3",
                "preview_kind": "audio",
                "status": "pending",
                "attempts": 0,
                "max_attempts": 2,
            }
        }
        node = {
            "path": "/docs/track.mp3",
            "s3_bucket": "bucket",
            "s3_key": "user/objects/audio",
            "media_preview_keys": {"waveform_image": "user/derived/media/ver/waveform_image.png"},
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "get_node", return_value=node),
            patch.object(filemanager, "_extract_audio_waveform_bytes", return_value=None),
        ):
            out = filemanager.run_media_preview_job("user", "jid-a")
        self.assertEqual(out["status"], "retry_pending")
        self.assertEqual(out["reason"], "waveform_generation_failed")

    def test_media_artifact_url_uses_signed_urls_for_private_delivery(self):
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_media_preview_cdn_base_url="https://cdn.example", filemgr_media_preview_private=True, filemgr_media_preview_url_ttl_seconds=600)),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.generate_presigned_url.return_value = "https://signed.example/object"
            url = filemanager._media_artifact_url(bucket="b", key="k")
        self.assertEqual(url, "https://signed.example/object")
        s3.generate_presigned_url.assert_called_once()

    def test_media_artifact_url_uses_cdn_for_public_delivery(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_preview_cdn_base_url="https://cdn.example", filemgr_media_preview_private=False, filemgr_media_preview_url_ttl_seconds=600)):
            url = filemanager._media_artifact_url(bucket="b", key="path/to/k")
        self.assertEqual(url, "https://cdn.example/path/to/k")

    def test_detect_preview_kind_mapping_matrix(self):
        cases = [
            ({"name": "diagram.PNG", "content_type": "application/octet-stream"}, "image"),
            ({"name": "photo.bin", "content_type": "image/jpeg"}, "image"),
            ({"name": "manual.pdf", "content_type": "application/octet-stream"}, "pdf"),
            ({"name": "notes.docx", "content_type": "application/octet-stream"}, "word"),
            ({"name": "legacy.doc", "content_type": "application/msword"}, "word"),
            ({"name": "table.xlsx", "content_type": "application/octet-stream"}, "excel"),
            ({"name": "records.csv", "content_type": "application/vnd.ms-excel"}, "csv"),
            ({"name": "warehouse.parquet", "content_type": "application/octet-stream"}, "parquet"),
            ({"name": "server.log", "content_type": "application/octet-stream"}, "text"),
            ({"name": "payload.bin", "content_type": "application/json"}, "text"),
            ({"name": "payload.bin", "content_type": "text/plain"}, "text"),
        ]
        for node, expected_kind in cases:
            with self.subTest(node=node):
                self.assertEqual(filemanager._detect_preview_kind(node), expected_kind)

    def test_preview_kind_normalization_unknown_type_resolves_none(self):
        kind = filemanager._detect_preview_kind({"name": "archive.bin", "content_type": "application/octet-stream"})
        self.assertEqual(kind, "none")
        info = filemanager.preview_capability_from_node(
            {"type": "file", "name": "archive.bin", "content_type": "application/octet-stream", "is_encrypted": False}
        )
        self.assertEqual(info["preview_kind"], "none")
        self.assertEqual(info["preview_status"], "unsupported")
        self.assertIsNone(info["poster_url"])
        self.assertIsNone(info["hover_preview_url"])
        self.assertIsNone(info["waveform_url"])
        self.assertFalse(info["preview_supported"])
        self.assertEqual(info["preview_reason"], "unsupported_type")

    def test_preview_capability_rejects_non_file_nodes(self):
        info = filemanager.preview_capability_from_node(
            {"type": "folder", "name": "docs", "content_type": None, "is_encrypted": False}
        )

        self.assertEqual(info["preview_kind"], "none")
        self.assertEqual(info["preview_status"], "unsupported")
        self.assertFalse(info["preview_supported"])
        self.assertEqual(info["preview_reason"], "not_file")

    def test_preview_capability_rejection_reasons_matrix(self):
        cases = [
            (
                {
                    "type": "file",
                    "name": "secret.csv",
                    "content_type": "text/csv",
                    "size": 1,
                    "is_encrypted": True,
                },
                "document",
                "encrypted",
            ),
            (
                {
                    "type": "file",
                    "name": "unknown.bin",
                    "content_type": "application/octet-stream",
                    "size": 1,
                    "is_encrypted": False,
                },
                "none",
                "unsupported_type",
            ),
            (
                {
                    "type": "file",
                    "name": "named.csv",
                    "content_type": "application/octet-stream",
                    "size": 1,
                    "is_encrypted": False,
                },
                "document",
                "not_enabled",
            ),
        ]

        for node, expected_kind, expected_reason in cases:
            with self.subTest(node=node):
                info = filemanager.preview_capability_from_node(node)
                self.assertEqual(info["preview_kind"], expected_kind)
                self.assertFalse(info["preview_supported"])
                self.assertEqual(info["preview_reason"], expected_reason)

    def test_is_previewable_rejects_encrypted(self):
        self.assertFalse(filemanager.is_previewable({"is_encrypted": True, "content_type": "image/png"}))

    def test_is_previewable_allows_extended_tabular_and_word_types(self):
        self.assertTrue(filemanager.is_previewable({"is_encrypted": False, "content_type": "text/csv"}))
        self.assertTrue(
            filemanager.is_previewable(
                {
                    "is_encrypted": False,
                    "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                }
            )
        )
        self.assertTrue(filemanager.is_previewable({"is_encrypted": False, "content_type": "application/parquet"}))
        self.assertTrue(
            filemanager.is_previewable(
                {
                    "is_encrypted": False,
                    "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                }
            )
        )

    def test_is_previewable_matrix_rejects_unknown_binary(self):
        cases = [
            ({"is_encrypted": False, "content_type": "image/webp"}, True),
            ({"is_encrypted": False, "content_type": "application/pdf"}, True),
            ({"is_encrypted": False, "content_type": "application/json"}, True),
            ({"is_encrypted": False, "content_type": "application/octet-stream"}, False),
            ({"is_encrypted": False, "content_type": "application/x-7z-compressed"}, False),
            ({"is_encrypted": True, "content_type": "text/plain"}, False),
        ]
        for node, expected in cases:
            with self.subTest(node=node):
                self.assertEqual(filemanager.is_previewable(node), expected)

    def test_preview_capability_marks_file_too_large(self):
        info = filemanager.preview_capability_from_node(
            {
                "type": "file",
                "name": "big.csv",
                "content_type": "text/csv",
                "size": 20 * 1024 * 1024,
                "is_encrypted": False,
            }
        )

        self.assertEqual(info["preview_kind"], "document")
        self.assertEqual(info["preview_status"], "unsupported")
        self.assertFalse(info["preview_supported"])
        self.assertEqual(info["preview_reason"], "too_large")

    def test_preview_capability_allows_file_at_size_limit(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_preview_max_bytes=1024)):
            info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "exact.csv",
                    "content_type": "text/csv",
                    "size": 1024,
                    "is_encrypted": False,
                }
            )

        self.assertEqual(info["preview_kind"], "document")
        self.assertEqual(info["preview_status"], "ready")
        self.assertTrue(info["preview_supported"])
        self.assertIsNone(info["preview_reason"])

    def test_preview_capability_for_video_and_audio_contract_fields(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=True, filemgr_video_hover_clip_enabled=True, filemgr_audio_waveform_enabled=True, filemgr_preview_max_bytes=10485760)):
            video_info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "clip.mp4",
                    "content_type": "video/mp4",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(video_info["preview_kind"], "video")
            self.assertEqual(video_info["preview_status"], "pending")
            self.assertEqual(video_info["preview_reason"], "transcoding_pending")
            self.assertIsNone(video_info["poster_url"])
            self.assertIsNone(video_info["hover_preview_url"])
            self.assertIsNone(video_info["waveform_url"])

            audio_info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "track.mp3",
                    "content_type": "audio/mpeg",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(audio_info["preview_kind"], "audio")
            self.assertEqual(audio_info["preview_status"], "pending")
            self.assertEqual(audio_info["preview_reason"], "transcoding_pending")

    def test_preview_capability_uses_video_audio_artifacts_when_present(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=True, filemgr_video_hover_clip_enabled=True, filemgr_audio_waveform_enabled=True, filemgr_preview_max_bytes=10485760)):
            video_info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "clip.mp4",
                    "content_type": "video/mp4",
                    "poster_url": "https://example/poster.webp",
                    "hover_preview_url": "https://example/clip.mp4",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(video_info["preview_status"], "ready")
            self.assertIsNone(video_info["preview_reason"])

            audio_info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "track.mp3",
                    "content_type": "audio/mpeg",
                    "waveform_url": "https://example/waveform.png",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(audio_info["preview_status"], "ready")
            self.assertIsNone(audio_info["preview_reason"])

    def test_preview_capability_media_feature_flag_disabled_returns_deterministic_fallback(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=False, filemgr_video_hover_clip_enabled=True, filemgr_audio_waveform_enabled=True, filemgr_preview_max_bytes=10485760)):
            video_info = filemanager.preview_capability_from_node(
                {"type": "file", "name": "clip.mp4", "content_type": "video/mp4", "is_encrypted": False}
            )
            self.assertEqual(video_info["preview_kind"], "video")
            self.assertEqual(video_info["preview_status"], "unsupported")
            self.assertEqual(video_info["preview_reason"], "not_enabled")
            self.assertIsNone(video_info["poster_url"])
            self.assertIsNone(video_info["hover_preview_url"])

            audio_info = filemanager.preview_capability_from_node(
                {"type": "file", "name": "track.mp3", "content_type": "audio/mpeg", "is_encrypted": False}
            )
            self.assertEqual(audio_info["preview_kind"], "audio")
            self.assertEqual(audio_info["preview_status"], "unsupported")
            self.assertEqual(audio_info["preview_reason"], "not_enabled")
            self.assertIsNone(audio_info["waveform_url"])

    def test_preview_capability_artifact_toggles_control_video_and_audio_outputs(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_media_previews_v1=True, filemgr_video_hover_clip_enabled=False, filemgr_audio_waveform_enabled=False, filemgr_preview_max_bytes=10485760)):
            video_info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "clip.mp4",
                    "content_type": "video/mp4",
                    "poster_url": "https://example/poster.webp",
                    "hover_preview_url": "https://example/clip.mp4",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(video_info["preview_status"], "ready")
            self.assertIsNone(video_info["hover_preview_url"])

            audio_info = filemanager.preview_capability_from_node(
                {
                    "type": "file",
                    "name": "track.mp3",
                    "content_type": "audio/mpeg",
                    "waveform_url": "https://example/waveform.png",
                    "is_encrypted": False,
                }
            )
            self.assertEqual(audio_info["preview_status"], "unsupported")
            self.assertEqual(audio_info["preview_reason"], "not_enabled")
            self.assertIsNone(audio_info["waveform_url"])

    def test_download_thumbnail_rejects_encrypted_file(self):
        with patch.object(filemanager, "get_node", return_value={"type": "file", "is_encrypted": True}):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.download_thumbnail("user", "/docs/a.txt")
        self.assertEqual(ctx.exception.status_code, 415)

    def test_upload_zip_rejects_duplicate_paths(self):
        buf = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("dup.txt", b"one")
                zf.writestr("dup.txt", b"two")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_auto_create_parents"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.put_object = Mock()
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 409)



    def test_upload_archive_tar_extracts_file(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            data = b"hello"
            info = tarfile.TarInfo(name="a.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        buf.seek(0)
        upload = UploadFile(filename="files.tar", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_auto_create_parents"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.upload_fileobj = Mock()
            created = filemanager.upload_archive("user", "/", upload)
        self.assertEqual(created, ["/a.txt"])

    def test_upload_archive_rejects_unsupported_extension(self):
        upload = UploadFile(filename="files.7z", file=io.BytesIO(b"x"))
        with self.assertRaises(HTTPException) as ctx:
            filemanager.upload_archive("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_upload_archive_rar_unavailable(self):
        upload = UploadFile(filename="files.rar", file=io.BytesIO(b"x"))
        with patch.object(filemanager, "rarfile", None):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_archive("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 501)

    def test_upload_zip_rejects_too_many_entries(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"a")
            zf.writestr("b.txt", b"b")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 1
            settings.filemgr_zip_max_entry_uncompressed_bytes = 1024
            settings.filemgr_zip_max_total_uncompressed_bytes = 2048
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_upload_zip_rejects_large_entry_and_total_size(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"12345")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 4
            settings.filemgr_zip_max_total_uncompressed_bytes = 100
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)

        buf.seek(0)
        upload2 = UploadFile(filename="files.zip", file=buf)
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 10
            settings.filemgr_zip_max_total_uncompressed_bytes = 4
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx2:
                filemanager.upload_zip("user", "/", upload2)
        self.assertEqual(ctx2.exception.status_code, 413)

    def test_upload_zip_rejects_high_compression_ratio(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", b"a" * 5000)
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_zip_extract_timeout_seconds = 30
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 10000
            settings.filemgr_zip_max_total_uncompressed_bytes = 10000
            settings.filemgr_zip_max_compression_ratio = 1.1
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)

    def test_upload_zip_rejects_timeout_budget(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", b"ok")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "S") as settings,
            patch.object(filemanager.time, "monotonic", side_effect=[0.0, 5.0]),
        ):
            settings.filemgr_zip_extract_timeout_seconds = 1
            settings.filemgr_zip_max_entries = 10
            settings.filemgr_zip_max_entry_uncompressed_bytes = 1024
            settings.filemgr_zip_max_total_uncompressed_bytes = 2048
            settings.filemgr_zip_max_compression_ratio = 100.0
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 413)


    def test_move_node_folder_creates_checkpoint_and_move_id(self):
        src_node = {"path": "/docs/", "type": "folder", "name": "docs"}
        child = {"path": "/docs/a.txt", "type": "file", "name": "a.txt"}
        with (
            patch.object(filemanager, "get_node", return_value=src_node),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "_list_move_tree_items", return_value=[child]),
            patch.object(filemanager, "_execute_checkpoint_move", return_value={"status": "completed"}),
            patch.object(filemanager, "_table") as table_factory,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {}
            out = filemanager.move_node("user", "/docs/", "/archive/docs/")

        self.assertEqual(out["type"], "folder")
        self.assertIn("move_id", out)
        self.assertGreaterEqual(table.put_item.call_count, 1)

    def test_resume_and_rollback_move_delegate(self):
        with patch.object(filemanager, "_execute_checkpoint_move", return_value={"status": "completed"}) as exec_move:
            filemanager.resume_move("user", "m1")
            exec_move.assert_called_once_with("user", "m1", reverse=False)

        with patch.object(filemanager, "_execute_checkpoint_move", return_value={"status": "rolled_back"}) as exec_move:
            filemanager.rollback_move("user", "m1")
            exec_move.assert_called_once_with("user", "m1", reverse=True)

    def test_register_presigned_upload_rejects_wrong_prefix(self):
        with (
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="other/objects/abc",
                    ticket_id="ticket",
                    content_type="text/plain",
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_presigned_upload_requires_matching_ticket_and_metadata(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node") as put_node,
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_s3") as s3,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "content_type": "text/plain",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                }
            }
            s3.head_object.return_value = {
                "ContentLength": 5,
                "ETag": "etag",
                "ContentType": "text/plain",
                "Metadata": {"filemgr-ticket": "ticket-1", "filemgr-user": "user"},
            }

            out = filemanager.register_presigned_upload(
                "user",
                "/docs/a.txt",
                s3_key="user/objects/abc",
                ticket_id="ticket-1",
                content_type=None,
                encryption_meta={
                    "version": 1,
                    "alg": "AES-256-GCM",
                    "kdf": "PBKDF2-SHA256",
                    "iterations": 600000,
                    "salt_b64": "c2FsdA==",
                    "iv_b64": "aXY=",
                    "orig_name": "a.txt",
                    "orig_size": 5,
                    "mime": "text/plain",
                },
            )

        self.assertEqual(out["path"], "/docs/a.txt")
        stored = put_node.call_args.kwargs["item"] if "item" in put_node.call_args.kwargs else put_node.call_args.args[0]
        self.assertEqual(stored["enc_version"], 1)
        self.assertIn("media_preview_version", stored)
        self.assertTrue(stored["media_preview_prefix"].startswith("user/derived/media/"))

    def test_register_presigned_upload_rejects_invalid_ticket(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_table") as table_factory,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {}
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="user/objects/abc",
                    ticket_id="missing",
                    content_type=None,
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_presigned_upload_rejects_expired_ticket(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_table") as table_factory,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "expires_at": "2000-01-01T00:00:00+00:00",
                }
            }
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="user/objects/abc",
                    ticket_id="expired",
                    content_type=None,
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_register_presigned_upload_rejects_metadata_mismatch(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_s3") as s3,
            patch.object(filemanager, "S", SimpleNamespace(dev_mode=False)),
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "content_type": "text/plain",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                }
            }
            s3.head_object.return_value = {
                "ContentLength": 5,
                "ETag": "etag",
                "ContentType": "text/plain",
                "Metadata": {"filemgr-ticket": "wrong", "filemgr-user": "user"},
            }
            with self.assertRaises(HTTPException) as ctx:
                filemanager.register_presigned_upload(
                    "user",
                    "/docs/a.txt",
                    s3_key="user/objects/abc",
                    ticket_id="ticket-1",
                    content_type=None,
                )
        self.assertEqual(ctx.exception.status_code, 403)



    def test_search_text_records_fallback_metric(self):
        with (
            patch.object(filemanager, "_query_token_items", return_value=[]),
            patch.object(filemanager, "_search_text_scan", return_value=[]),
            patch.object(filemanager, "record_filemgr_search_path") as record_path,
            patch.object(filemanager, "record_filemgr_operation_latency") as record_latency,
        ):
            out = filemanager.search_text("user", "doc", limit=5)

        self.assertEqual(out, [])
        record_path.assert_called_once_with("search_text", "scan_fallback")
        record_latency.assert_called()

    def test_search_text_scan_skips_encrypted_items(self):
        encrypted_item = {
            "path": "/docs/enc.bin",
            "type": "file",
            "name": "enc.bin",
            "name_lc": "enc.bin",
            "parent": "/docs/",
            "is_encrypted": True,
            "updated_at": "t1",
            "size": 5,
        }
        plain_item = {
            "path": "/docs/plain.txt",
            "type": "file",
            "name": "plain.txt",
            "name_lc": "plain.txt",
            "parent": "/docs/",
            "is_encrypted": False,
            "updated_at": "t2",
            "size": 4,
        }
        with patch.object(filemanager, "_table") as table_factory:
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {"Items": [encrypted_item, plain_item]}
            out = filemanager._search_text_scan("user", "plain", limit=10)
        self.assertEqual([x["path"] for x in out], ["/docs/plain.txt"])

    def test_purge_deleted_nodes_global_records_purge_run_metric(self):
        with (
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_purge_node_item", return_value="purged"),
            patch.object(filemanager, "record_filemgr_purge_run") as record_purge_run,
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {"Items": [{"PK": "USER#u", "SK": "NODE#/a", "deleted_at": "t", "purge_after": "2000-01-01T00:00:00+00:00"}]}

            out = filemanager.purge_deleted_nodes_global(limit=10)

        self.assertEqual(out["purged"], 1)
        record_purge_run.assert_called_once()

    def test_purge_deleted_nodes_global_uses_purge_index(self):
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_purge_node_item",
            return_value="purged",
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {
                "Items": [{"PK": "USER#u", "SK": "NODE#/a", "deleted_at": "t", "purge_after": "2000-01-01T00:00:00+00:00"}],
            }

            out = filemanager.purge_deleted_nodes_global(limit=10)

        self.assertEqual(out["mode"], "index")
        table.query.assert_called()
        self.assertEqual(table.scan.call_count, 0)

    def test_purge_deleted_nodes_global_falls_back_to_scan(self):
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_purge_node_item",
            return_value="skipped",
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.side_effect = ClientError({"Error": {"Code": "ValidationException", "Message": "missing index"}}, "Query")
            table.scan.return_value = {"Items": [{"PK": "USER#u", "SK": "NODE#/a", "deleted_at": "t"}]}

            out = filemanager.purge_deleted_nodes_global(limit=10)

        self.assertEqual(out["mode"], "scan_fallback")
        table.scan.assert_called()

    def test_purge_deleted_nodes_counts_error_and_skipped(self):
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_purge_node_item",
            side_effect=["error", "skipped"],
        ):
            table = Mock()
            table_factory.return_value = table
            table.query.return_value = {
                "Items": [
                    {"path": "/a", "deleted_at": "t"},
                    {"path": "/b", "deleted_at": "t"},
                ]
            }
            out = filemanager.purge_deleted_nodes("user", limit=10)

        self.assertEqual(out["errors"], 1)
        self.assertEqual(out["skipped"], 1)

    def test_purge_node_item_records_retry_error(self):
        tbl = Mock()
        item = {
            "PK": "USER#u",
            "SK": "NODE#/a",
            "path": "/a",
            "deleted_at": "2024-01-01T00:00:00+00:00",
            "purge_after": "2024-01-02T00:00:00+00:00",
            "s3_bucket": "bucket",
            "s3_key": "key",
        }
        with patch.object(
            filemanager._s3,
            "delete_object",
            side_effect=ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "DeleteObject"),
        ):
            result = filemanager._purge_node_item(tbl, item, filemanager.datetime.now(filemanager.timezone.utc))

        self.assertEqual(result, "error")
        tbl.update_item.assert_called_once()

    def test_execute_checkpoint_move_interrupted_then_resume_idempotent(self):
        checkpoint = {
            "entries": [
                {"src": "/docs/", "dst": "/archive/docs/", "type": "folder"},
                {"src": "/docs/a.txt", "dst": "/archive/docs/a.txt", "type": "file"},
            ],
            "moved": 0,
            "already_done": 0,
        }
        with patch.object(filemanager, "_table") as table_factory, patch.object(
            filemanager,
            "_transact_move_item",
            side_effect=["moved", RuntimeError("boom")],
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {"Item": checkpoint}
            with self.assertRaises(RuntimeError):
                filemanager._execute_checkpoint_move("user", "m1", reverse=False)

        # Resume path with idempotency marker: first already moved, second moved now
        with patch.object(filemanager, "_table") as table_factory2, patch.object(
            filemanager,
            "_transact_move_item",
            side_effect=["already_moved", "moved"],
        ):
            table2 = Mock()
            table_factory2.return_value = table2
            table2.get_item.return_value = {"Item": checkpoint}
            out = filemanager._execute_checkpoint_move("user", "m1", reverse=False)

        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["already_done"], 1)
        self.assertEqual(out["moved_now"], 1)

    def test_upload_file_records_metering_with_authoritative_size(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_record_usage_event_safe") as record_usage,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 11, "ETag": "etag-1"}
            filemanager.upload_file("user", "/docs/a.txt", upload)

        upload_events = [c.args[0] for c in record_usage.call_args_list if c.args[0].get("source") == "api_upload"]
        self.assertEqual(len(upload_events), 1)
        event = upload_events[0]
        self.assertEqual(event["event_type"], "upload")
        self.assertEqual(event["bytes"], 11)

    def test_register_presigned_upload_records_metering_once(self):
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
            patch.object(filemanager, "_record_usage_event_safe") as record_usage,
            patch.object(filemanager, "_table") as table_factory,
            patch.object(filemanager, "_s3") as s3,
        ):
            table = Mock()
            table_factory.return_value = table
            table.get_item.return_value = {
                "Item": {
                    "path": "/docs/a.txt",
                    "s3_key": "user/objects/abc",
                    "content_type": "text/plain",
                    "expires_at": "2999-01-01T00:00:00+00:00",
                }
            }
            s3.head_object.return_value = {
                "ContentLength": 17,
                "ETag": "etag-2",
                "ContentType": "text/plain",
                "Metadata": {"filemgr-ticket": "ticket-1", "filemgr-user": "user"},
            }

            filemanager.register_presigned_upload(
                "user",
                "/docs/a.txt",
                s3_key="user/objects/abc",
                ticket_id="ticket-1",
                content_type=None,
            )

        upload_events = [c.args[0] for c in record_usage.call_args_list if c.args[0].get("source") == "presign_complete"]
        self.assertEqual(len(upload_events), 1)
        event = upload_events[0]
        self.assertEqual(event["event_type"], "upload")
        self.assertEqual(event["bytes"], 17)

    def test_upload_archive_emits_per_entry_and_total_metering_events(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("one.txt", b"abc")
            zf.writestr("two.txt", b"defg")
        buf.seek(0)
        upload = UploadFile(filename="files.zip", file=buf)

        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_auto_create_parents"),
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_put_token_entries"),
            patch.object(filemanager, "_record_usage_event_safe") as record_usage,
            patch.object(filemanager, "_record_usage_event_non_aggregating_safe") as record_usage_total,
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.side_effect = [
                {"ContentLength": 3, "ETag": "etag-1"},
                {"ContentLength": 4, "ETag": "etag-2"},
            ]
            created = filemanager.upload_archive("user", "/", upload)

        self.assertEqual(len(created), 2)
        entry_events = [c.args[0] for c in record_usage.call_args_list if c.args[0].get("source") == "upload_zip_entry"]
        self.assertEqual(len(entry_events), 2)
        entry_bytes = [e["bytes"] for e in entry_events]
        self.assertEqual(entry_bytes, [3, 4])
        total_event = record_usage_total.call_args.args[0]
        self.assertEqual(total_event["bytes"], 7)
        self.assertEqual(total_event["source"], "upload_zip_total")

    def test_get_usage_summary_and_limits(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "upload_bytes_total": 50,
                "download_bytes_total": 100,
                "storage_bytes_current": 25,
                "message_send_count_total": 3,
                "post_publish_count_total": 2,
                "messaging_upload_bytes_total": 11,
                "messaging_download_bytes_total": 12,
                "newsfeed_upload_bytes_total": 13,
                "newsfeed_download_bytes_total": 14,
                "updated_at": "2026-02-01T00:00:00+00:00",
            }
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_upload_limit_bytes = 100
            settings.filemgr_usage_download_limit_bytes = 200
            settings.filemgr_usage_storage_limit_bytes = 50
            settings.filemgr_usage_message_send_limit_count = 6
            settings.filemgr_usage_post_publish_limit_count = 4
            out = filemanager.get_usage_summary("user", period_id="2026-02")

        self.assertEqual(out["upload"]["used_bytes"], 50)
        self.assertEqual(out["upload"]["percent_used"], 50.0)
        self.assertEqual(out["download"]["percent_used"], 50.0)
        self.assertEqual(out["storage"]["percent_used"], 50.0)
        self.assertEqual(out["message_send"]["used_count"], 3)
        self.assertEqual(out["message_send"]["limit_count"], 6)
        self.assertEqual(out["message_send"]["percent_used"], 50.0)
        self.assertEqual(out["post_publish"]["used_count"], 2)
        self.assertEqual(out["post_publish"]["limit_count"], 4)
        self.assertEqual(out["post_publish"]["percent_used"], 50.0)
        self.assertEqual(out["messaging_transfer"]["upload_bytes_total"], 11)
        self.assertEqual(out["messaging_transfer"]["download_bytes_total"], 12)
        self.assertEqual(out["newsfeed_transfer"]["upload_bytes_total"], 13)
        self.assertEqual(out["newsfeed_transfer"]["download_bytes_total"], 14)
        self.assertEqual(out["messaging_upload_bytes_total"], 11)
        self.assertEqual(out["messaging_download_bytes_total"], 12)
        self.assertEqual(out["newsfeed_upload_bytes_total"], 13)
        self.assertEqual(out["newsfeed_download_bytes_total"], 14)

    def test_get_usage_summary_defaults_new_transfer_fields_for_legacy_rows(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "upload_bytes_total": 1,
                "download_bytes_total": 2,
                "storage_bytes_current": 3,
            }
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_upload_limit_bytes = 0
            settings.filemgr_usage_download_limit_bytes = 0
            settings.filemgr_usage_storage_limit_bytes = 0
            settings.filemgr_usage_message_send_limit_count = 0
            settings.filemgr_usage_post_publish_limit_count = 0
            out = filemanager.get_usage_summary("user", period_id="2026-02")

        self.assertEqual(out["messaging_upload_bytes_total"], 0)
        self.assertEqual(out["messaging_download_bytes_total"], 0)
        self.assertEqual(out["newsfeed_upload_bytes_total"], 0)
        self.assertEqual(out["newsfeed_download_bytes_total"], 0)
        self.assertEqual(out["messaging_transfer"]["upload_bytes_total"], 0)
        self.assertEqual(out["newsfeed_transfer"]["download_bytes_total"], 0)


    def test_get_usage_daily_range_filter(self):
        table = Mock()
        table.query.return_value = {
            "Items": [
                {"day_utc": "2026-02-01", "upload_bytes_total": 1, "download_bytes_total": 2, "storage_bytes_end_of_day": 3},
                {"day_utc": "2026-02-10", "upload_bytes_total": 4, "download_bytes_total": 5, "storage_bytes_end_of_day": 6},
                {"day_utc": "2026-03-01", "upload_bytes_total": 7, "download_bytes_total": 8, "storage_bytes_end_of_day": 9},
            ]
        }
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.get_usage_daily("user", from_day="2026-02-01", to_day="2026-02-28")
        self.assertEqual(len(out["items"]), 2)

    def test_get_usage_storage_top_files(self):
        table = Mock()
        table.query.return_value = {
            "Items": [
                {"type": "file", "path": "/a", "size": 10},
                {"type": "file", "path": "/b", "size": 20},
                {"type": "folder", "path": "/docs/"},
                {"type": "file", "path": "/c", "size": 5, "deleted_at": "t"},
            ]
        }
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.get_usage_storage("user", top_n=1)
        self.assertEqual(out["storage_bytes_current"], 30)
        self.assertEqual(len(out["top_files"]), 1)
        self.assertEqual(out["top_files"][0]["path"], "/b")

    def test_recompute_usage_aggregates_admin_report_only(self):
        table = Mock()
        table.scan.side_effect = [
            {
                "Items": [
                    {"entity_type": "usage_event", "user_id": "u1", "timestamp": "2026-02-10T00:00:00+00:00", "bytes": 3, "event_type": "upload", "period_id": "2026-02"},
                    {"entity_type": "usage_event", "user_id": "u1", "timestamp": "2026-02-10T01:00:00+00:00", "bytes": 2, "event_type": "download", "period_id": "2026-02"},
                ]
            }
        ]
        table.get_item.return_value = {"Item": {"upload_bytes_total": 0, "download_bytes_total": 0, "storage_bytes_current": 0}}
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.recompute_usage_aggregates_admin(scope="all", period_id="2026-02", apply=False)
        self.assertEqual(out["events_scanned"], 2)
        self.assertGreaterEqual(out["mismatches"], 1)

    def test_finalize_billing_period_admin_creates_snapshot(self):
        table = Mock()
        table.scan.side_effect = [
            {"Items": [{"PK": "USER#u1", "SK": "USAGE#PERIOD#2026-02", "user_id": "u1"}]}
        ]
        table.get_item.return_value = {
            "Item": {
                "upload_bytes_total": 10,
                "download_bytes_total": 20,
                "storage_bytes_peak": 30,
                "storage_byte_seconds": 40,
                "message_send_count_total": 5,
                "post_publish_count_total": 2,
                "messaging_upload_bytes_total": 100,
                "messaging_download_bytes_total": 75,
                "newsfeed_upload_bytes_total": 50,
                "newsfeed_download_bytes_total": 25,
            }
        }
        table.query.return_value = {"Items": []}
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.finalize_billing_period_admin(period_id="2026-02")
        self.assertEqual(out["finalized_count"], 1)
        table.put_item.assert_called()
        saved = table.put_item.call_args.kwargs["Item"]
        self.assertEqual(saved["schema_version"], 2)
        self.assertEqual(saved["message_send_count_total"], 5)
        self.assertEqual(saved["post_publish_count_total"], 2)
        self.assertEqual(saved["messaging_upload_bytes_total"], 100)
        self.assertEqual(saved["messaging_download_bytes_total"], 75)
        self.assertEqual(saved["newsfeed_upload_bytes_total"], 50)
        self.assertEqual(saved["newsfeed_download_bytes_total"], 25)


    def test_admin_user_usage_detail_redacts_paths_by_default(self):
        table = Mock()
        table.query.return_value = {"Items": []}
        with (
            patch.object(filemanager, "get_usage_summary", return_value={"period_id": "2026-02"}),
            patch.object(filemanager, "get_usage_daily", return_value={"items": []}),
            patch.object(filemanager, "get_usage_storage", return_value={"storage_bytes_current": 10, "top_files": [{"path": "/a", "size": 10}]}),
            patch.object(filemanager, "_table", return_value=table),
        ):
            out = filemanager.get_admin_user_usage_detail("u1", period_id="2026-02", top_n=5)
        self.assertTrue(out["storage"]["paths_redacted"])
        self.assertEqual(out["storage"]["top_files"], [{"size": 10}])

    def test_get_admin_user_usage_detail(self):
        table = Mock()
        table.query.return_value = {
            "Items": [
                {
                    "period_id": "2026-02",
                    "version": 1,
                    "status": "finalized",
                    "upload_bytes_total": 1,
                    "download_bytes_total": 2,
                    "storage_bytes_peak": 3,
                },
                {
                    "period_id": "2026-03",
                    "version": 2,
                    "status": "finalized",
                    "schema_version": 2,
                    "upload_bytes_total": 10,
                    "download_bytes_total": 20,
                    "storage_bytes_peak": 30,
                    "message_send_count_total": 7,
                    "post_publish_count_total": 4,
                },
            ]
        }
        with (
            patch.object(filemanager, "get_usage_summary", return_value={"period_id": "2026-02"}),
            patch.object(filemanager, "get_usage_daily", return_value={"items": []}),
            patch.object(filemanager, "get_usage_storage", return_value={"storage_bytes_current": 1}),
            patch.object(filemanager, "_table", return_value=table),
        ):
            out = filemanager.get_admin_user_usage_detail("u1", period_id="2026-02", top_n=5)
        self.assertEqual(out["user_id"], "u1")
        self.assertEqual(out["summary"]["period_id"], "2026-02")
        self.assertEqual(len(out["snapshots"]), 2)
        # v2 snapshot fields are surfaced
        self.assertEqual(out["snapshots"][0]["schema_version"], 2)
        self.assertEqual(out["snapshots"][0]["message_send_count_total"], 7)
        # older v1-like snapshots remain readable with defaulted zero new counters
        self.assertEqual(out["snapshots"][1]["schema_version"], 1)
        self.assertEqual(out["snapshots"][1]["message_send_count_total"], 0)


    def test_generate_invoice_line_items_for_snapshot_admin(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "upload_bytes_total": 20,
                "download_bytes_total": 10,
                "storage_bytes_peak": 5,
                "message_send_count_total": 8,
                "post_publish_count_total": 4,
                "messaging_upload_bytes_total": 2147483648,
                "messaging_download_bytes_total": 0,
                "newsfeed_upload_bytes_total": 2147483648,
                "newsfeed_download_bytes_total": 1,
            }
        }
        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "S") as settings,
        ):
            settings.filemgr_usage_pricing_catalog = '{"v2":{"upload_included_bytes":0,"download_included_bytes":0,"storage_included_bytes":0,"upload_overage_cents_per_gb":100,"download_overage_cents_per_gb":100,"storage_overage_cents_per_gb":100,"message_send_included_units":5,"post_publish_included_units":1,"message_send_overage_cents_per_unit":2,"post_publish_overage_cents_per_unit":10,"messaging_upload_included_bytes":1073741824,"messaging_download_included_bytes":0,"newsfeed_upload_included_bytes":0,"newsfeed_download_included_bytes":10,"messaging_upload_overage_cents_per_gb":50,"messaging_download_overage_cents_per_gb":25,"newsfeed_upload_overage_cents_per_gb":75,"newsfeed_download_overage_cents_per_gb":100}}'
            settings.filemgr_usage_default_pricing_catalog_version = "v2"
            out = filemanager.generate_invoice_line_items_for_snapshot_admin(
                user_id="u1",
                period_id="2026-02",
                snapshot_version=1,
            )
        self.assertEqual(out["pricing_catalog_version"], "v2")
        self.assertEqual(len(out["line_items"]), 9)
        msg_line = next(x for x in out["line_items"] if x["line_type"] == "message_send_usage")
        post_line = next(x for x in out["line_items"] if x["line_type"] == "post_publish_usage")
        self.assertEqual(msg_line["included_units"], 5)
        self.assertEqual(msg_line["overage_units"], 3)
        self.assertEqual(msg_line["amount_cents"], 6)
        self.assertEqual(post_line["included_units"], 1)
        self.assertEqual(post_line["overage_units"], 3)
        self.assertEqual(post_line["amount_cents"], 30)
        msg_up_line = next(x for x in out["line_items"] if x["line_type"] == "messaging_upload_usage")
        nf_up_line = next(x for x in out["line_items"] if x["line_type"] == "newsfeed_upload_usage")
        nf_down_line = next(x for x in out["line_items"] if x["line_type"] == "newsfeed_download_usage")
        self.assertEqual(msg_up_line["overage_bytes"], 1073741824)
        self.assertEqual(msg_up_line["amount_cents"], 50)
        self.assertEqual(nf_up_line["overage_bytes"], 2147483648)
        self.assertEqual(nf_up_line["amount_cents"], 150)
        self.assertEqual(nf_down_line["overage_bytes"], 0)
        self.assertEqual(nf_down_line["amount_cents"], 0)
        self.assertEqual(out["total_amount_cents"], 236)
        self.assertEqual(out["total_amount_cents"], sum(int(x["amount_cents"]) for x in out["line_items"]))
        table.put_item.assert_called_once()

    def test_generate_invoice_line_items_reconcile_zero_at_limit_and_overage(self):
        scenarios = [
            {
                "name": "zero_usage",
                "snapshot": {
                    "upload_bytes_total": 0,
                    "download_bytes_total": 0,
                    "storage_bytes_peak": 0,
                    "message_send_count_total": 0,
                    "post_publish_count_total": 0,
                    "messaging_upload_bytes_total": 0,
                    "messaging_download_bytes_total": 0,
                    "newsfeed_upload_bytes_total": 0,
                    "newsfeed_download_bytes_total": 0,
                },
                "expected_message_over": 0,
                "expected_post_over": 0,
                "expected_message_cents": 0,
                "expected_post_cents": 0,
                "expected_total": 0,
            },
            {
                "name": "just_at_limit",
                "snapshot": {
                    "upload_bytes_total": 0,
                    "download_bytes_total": 0,
                    "storage_bytes_peak": 0,
                    "message_send_count_total": 10,
                    "post_publish_count_total": 7,
                    "messaging_upload_bytes_total": 0,
                    "messaging_download_bytes_total": 0,
                    "newsfeed_upload_bytes_total": 0,
                    "newsfeed_download_bytes_total": 0,
                },
                "expected_message_over": 0,
                "expected_post_over": 0,
                "expected_message_cents": 0,
                "expected_post_cents": 0,
                "expected_total": 0,
            },
            {
                "name": "overage",
                "snapshot": {
                    "upload_bytes_total": 0,
                    "download_bytes_total": 0,
                    "storage_bytes_peak": 0,
                    "message_send_count_total": 12,
                    "post_publish_count_total": 9,
                    "messaging_upload_bytes_total": 0,
                    "messaging_download_bytes_total": 0,
                    "newsfeed_upload_bytes_total": 0,
                    "newsfeed_download_bytes_total": 0,
                },
                "expected_message_over": 2,
                "expected_post_over": 2,
                "expected_message_cents": 6,
                "expected_post_cents": 10,
                "expected_total": 16,
            },
        ]

        for scenario in scenarios:
            with self.subTest(scenario=scenario["name"]):
                table = Mock()
                table.get_item.return_value = {"Item": scenario["snapshot"]}
                with (
                    patch.object(filemanager, "_table", return_value=table),
                    patch.object(filemanager, "S") as settings,
                ):
                    settings.filemgr_usage_pricing_catalog = '{"v2":{"upload_included_bytes":0,"download_included_bytes":0,"storage_included_bytes":0,"upload_overage_cents_per_gb":0,"download_overage_cents_per_gb":0,"storage_overage_cents_per_gb":0,"message_send_included_units":10,"post_publish_included_units":7,"message_send_overage_cents_per_unit":3,"post_publish_overage_cents_per_unit":5,"messaging_upload_included_bytes":0,"messaging_download_included_bytes":0,"newsfeed_upload_included_bytes":0,"newsfeed_download_included_bytes":0,"messaging_upload_overage_cents_per_gb":0,"messaging_download_overage_cents_per_gb":0,"newsfeed_upload_overage_cents_per_gb":0,"newsfeed_download_overage_cents_per_gb":0}}'
                    settings.filemgr_usage_default_pricing_catalog_version = "v2"
                    out = filemanager.generate_invoice_line_items_for_snapshot_admin(
                        user_id="u1",
                        period_id="2026-02",
                        snapshot_version=1,
                    )

                msg_line = next(x for x in out["line_items"] if x["line_type"] == "message_send_usage")
                post_line = next(x for x in out["line_items"] if x["line_type"] == "post_publish_usage")

                self.assertEqual(msg_line["quantity_units"], scenario["snapshot"]["message_send_count_total"])
                self.assertEqual(post_line["quantity_units"], scenario["snapshot"]["post_publish_count_total"])
                self.assertEqual(msg_line["overage_units"], scenario["expected_message_over"])
                self.assertEqual(post_line["overage_units"], scenario["expected_post_over"])
                self.assertEqual(msg_line["amount_cents"], scenario["expected_message_cents"])
                self.assertEqual(post_line["amount_cents"], scenario["expected_post_cents"])
                self.assertEqual(out["total_amount_cents"], scenario["expected_total"])
                self.assertEqual(out["total_amount_cents"], sum(int(x["amount_cents"]) for x in out["line_items"]))
                table.put_item.assert_called_once()

    def test_parse_pricing_catalog_config_normalizes_new_unit_fields(self):
        with patch.object(filemanager, "S") as settings:
            settings.filemgr_usage_pricing_catalog = '{"v3":{"message_send_included_units":"7","post_publish_included_units":-5,"message_send_overage_cents_per_unit":"3","post_publish_overage_cents_per_unit":"bad","messaging_upload_included_bytes":"12","messaging_download_overage_cents_per_gb":"-2"}}'
            settings.filemgr_usage_default_pricing_catalog_version = "v3"
            catalog = filemanager._parse_pricing_catalog_config()

        self.assertEqual(catalog["v3"]["message_send_included_units"], 7)
        self.assertEqual(catalog["v3"]["post_publish_included_units"], 0)
        self.assertEqual(catalog["v3"]["message_send_overage_cents_per_unit"], 3)
        self.assertEqual(catalog["v3"]["post_publish_overage_cents_per_unit"], 0)
        self.assertEqual(catalog["v3"]["messaging_upload_included_bytes"], 12)
        self.assertEqual(catalog["v3"]["messaging_download_overage_cents_per_gb"], 0)


    def test_create_billing_adjustment_admin_credit(self):
        table = Mock()
        table.get_item.return_value = {"Item": {"SK": "USAGE#SNAPSHOT#2026-02#V0001"}}
        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.create_billing_adjustment_admin(
                user_id="u1",
                period_id="2026-02",
                snapshot_version=1,
                adjustment_type="credit",
                amount_cents=25,
                reason="manual correction",
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["amount_cents"], -25)
        table.put_item.assert_called_once()

    def test_finalize_billing_period_admin_version_increments_on_repeated_finalize(self):
        table = Mock()
        table.scan.side_effect = [
            {"Items": [{"PK": "USER#u1", "SK": "USAGE#PERIOD#2026-02", "user_id": "u1"}]},
            {"Items": [{"PK": "USER#u1", "SK": "USAGE#PERIOD#2026-02", "user_id": "u1"}]},
        ]
        table.get_item.return_value = {"Item": {"upload_bytes_total": 10, "download_bytes_total": 20, "storage_bytes_peak": 30, "storage_byte_seconds": 40}}
        table.query.side_effect = [
            {"Items": [{"version": 1}]},
            {"Items": [{"version": 1}, {"version": 2}]},
        ]
        with patch.object(filemanager, "_table", return_value=table):
            out1 = filemanager.finalize_billing_period_admin(period_id="2026-02")
            out2 = filemanager.finalize_billing_period_admin(period_id="2026-02")

        self.assertEqual(out1["snapshots"][0]["version"], 2)
        self.assertEqual(out2["snapshots"][0]["version"], 3)


    def test_media_preview_eligibility_rejects_malformed_video_inspection(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_video_preview_max_mb=500, filemgr_video_preview_max_duration_seconds=600)):
            out = filemanager.media_preview_eligibility_from_node(
                {
                    "content_type": "video/mp4",
                    "size": 1024,
                    "media_inspection": {"error": "probe_malformed", "container": "unknown", "primary_video_codec": "unknown"},
                }
            )
        self.assertFalse(out["eligible"])
        self.assertEqual(out["reason"], "malformed_media")

    def test_media_preview_eligibility_rejects_malformed_audio_inspection(self):
        with patch.object(filemanager, "S", SimpleNamespace(filemgr_audio_waveform_max_mb=500)):
            out = filemanager.media_preview_eligibility_from_node(
                {
                    "content_type": "audio/mpeg",
                    "size": 1024,
                    "media_inspection": {"error": "probe_failed", "primary_audio_codec": "unknown"},
                }
            )
        self.assertFalse(out["eligible"])
        self.assertEqual(out["reason"], "malformed_media")

    def test_run_media_tool_uses_hardened_subprocess_defaults(self):
        with patch.object(filemanager.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="{}")) as mocked:
            out = filemanager._run_media_tool(["ffprobe", "-version"], timeout_seconds=7)
        self.assertEqual(out.returncode, 0)
        kwargs = mocked.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], filemanager.subprocess.DEVNULL)
        self.assertTrue(kwargs["close_fds"])
        self.assertEqual(kwargs["timeout"], 7)

    def test_run_media_tool_rejects_non_list_args(self):
        with self.assertRaises(ValueError):
            filemanager._run_media_tool("ffprobe -version")






    def test_move_node_dispatched_same_mount_calls_provider_move(self):
        provider = SimpleNamespace(
            get_metadata=lambda ref: {"type": "file", "name": "a.txt", "parents": ["p1"]} if ref == "gdrive://me/items/src" else {"type": "dir", "name": "folder", "parents": []},
            resolve=lambda ref: ref,
            list_children=lambda ref: [],
            move_item=Mock(),
        )
        mount = SimpleNamespace(mount_id="m1", provider="google_drive", mount_path="/integrations/drive/")
        src_dispatch = {"kind": "mount", "mount": mount, "provider": provider, "provider_ref": "gdrive://me/items/src", "mount_path": "/integrations/drive/"}
        dst_dispatch = {"kind": "mount", "mount": mount, "provider": provider, "provider_ref": "gdrive://me/items/dst", "mount_path": "/integrations/drive/"}
        parent_dispatch = {"kind": "mount", "mount": mount, "provider": provider, "provider_ref": "gdrive://me/items/parent", "mount_path": "/integrations/drive/"}
        with patch.object(filemanager, "resolve_path_dispatch", side_effect=[src_dispatch, dst_dispatch, parent_dispatch]), patch.object(filemanager, "_provider_find_child_by_name", return_value=None):
            out = filemanager.move_node_dispatched("owner-1", "/integrations/drive/a.txt", "/integrations/drive/new/a.txt")
        provider.move_item.assert_called_once_with("gdrive://me/items/src", new_parent_ref="gdrive://me/items/parent", new_name="a.txt")
        self.assertEqual(out["type"], "file")

    def test_move_node_dispatched_rejects_cross_mount(self):
        provider = SimpleNamespace(get_metadata=lambda ref: {"type": "file", "parents": ["p1"]}, resolve=lambda ref: ref)
        src_mount = SimpleNamespace(mount_id="m1", provider="google_drive", mount_path="/integrations/drive/")
        dst_mount = SimpleNamespace(mount_id="m2", provider="google_drive", mount_path="/integrations/drive2/")
        src_dispatch = {"kind": "mount", "mount": src_mount, "provider": provider, "provider_ref": "gdrive://me/items/src", "mount_path": "/integrations/drive/"}
        dst_dispatch = {"kind": "mount", "mount": dst_mount, "provider": provider, "provider_ref": "gdrive://me/items/dst", "mount_path": "/integrations/drive2/"}
        with patch.object(filemanager, "resolve_path_dispatch", side_effect=[src_dispatch, dst_dispatch]):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.move_node_dispatched("owner-1", "/integrations/drive/a.txt", "/integrations/drive2/a.txt")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail["code"], "mount_move_unsupported")


    def test_create_empty_folder_dispatched_creates_folder_in_mount(self):
        provider = SimpleNamespace(
            get_metadata=lambda ref: {"type": "dir"},
            create_folder=lambda parent_ref, name: "gdrive://me/items/new-folder",
        )
        parent_dispatch = {
            "kind": "mount",
            "provider": provider,
            "provider_ref": "gdrive://me/items/parent",
        }
        with patch.object(filemanager, "resolve_path_dispatch", side_effect=[{"kind": "mount"}, parent_dispatch]):
            out = filemanager.create_empty_folder_dispatched("owner-1", "/integrations/drive/new/")
        self.assertEqual(out, "/integrations/drive/new/")

    def test_upload_file_dispatched_mount_passes_overwrite_to_provider(self):
        provider = SimpleNamespace(
            get_metadata=lambda ref: {"type": "dir"},
            upload_file=lambda parent_ref, name, file_obj, content_type, overwrite: {"size": 9, "content_type": content_type or "application/octet-stream"},
        )
        parent_dispatch = {
            "kind": "mount",
            "provider": provider,
            "provider_ref": "gdrive://me/items/parent",
        }
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"contents"), headers={"content-type": "text/plain"})
        with (
            patch.object(filemanager, "resolve_path_dispatch", side_effect=[{"kind": "mount"}, parent_dispatch]),
            patch.object(filemanager, "record_filemgr_mount_bytes") as record_filemgr_mount_bytes,
            patch.object(filemanager, "record_filemgr_mount_operation_latency") as record_filemgr_mount_operation_latency,
        ):
            out = filemanager.upload_file_dispatched("owner-1", "/integrations/drive/a.txt", upload, overwrite=True)
        self.assertEqual(out["path"], "/integrations/drive/a.txt")
        self.assertEqual(out["size"], 9)
        record_filemgr_mount_bytes.assert_called_once_with("unknown", "in", "upload", 9)
        record_filemgr_mount_operation_latency.assert_called_once()

    def test_remove_file_dispatched_mount_deletes_provider_item(self):
        provider = SimpleNamespace(
            get_metadata=lambda ref: {"type": "file"},
            delete_item=Mock(),
        )
        dispatch = {"kind": "mount", "provider": provider, "provider_ref": "gdrive://me/items/file-1"}
        with patch.object(filemanager, "resolve_path_dispatch", return_value=dispatch):
            filemanager.remove_file_dispatched("owner-1", "/integrations/drive/a.txt")
        provider.delete_item.assert_called_once_with("gdrive://me/items/file-1")

    def test_remove_folder_dispatched_mount_recursively_deletes(self):
        refs = {
            "gdrive://me/items/folder": {"type": "dir"},
            "gdrive://me/items/child-file": {"type": "file"},
        }
        deleted = []
        provider = SimpleNamespace(
            get_metadata=lambda ref: refs[ref],
            list_children=lambda ref: ["gdrive://me/items/child-file"] if ref == "gdrive://me/items/folder" else [],
            delete_item=lambda ref: deleted.append(ref),
        )
        dispatch = {
            "kind": "mount",
            "provider": provider,
            "provider_ref": "gdrive://me/items/folder",
            "mount_path": "/integrations/drive/",
        }
        with patch.object(filemanager, "resolve_path_dispatch", return_value=dispatch):
            count = filemanager.remove_folder_dispatched("owner-1", "/integrations/drive/sub/")
        self.assertEqual(count, 2)
        self.assertEqual(deleted, ["gdrive://me/items/child-file", "gdrive://me/items/folder"])


    def test_assert_mount_write_allowed_rejects_read_only_mount(self):
        mount_match = {
            "mount": SimpleNamespace(mount_id="m1", mount_path="/integrations/drive/", mode="read_only"),
            "mount_path": "/integrations/drive/",
            "relative_parts": ["a.txt"],
            "requested_path": "/integrations/drive/a.txt",
        }
        with patch.object(filemanager, "_mount_match_for_path", return_value=mount_match):
            with self.assertRaises(HTTPException) as ctx:
                filemanager.assert_mount_write_allowed("owner-1", "/integrations/drive/a.txt", action="upload_file")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "mount_read_only")

    def test_assert_mount_write_allowed_allows_read_write_mount(self):
        mount_match = {
            "mount": SimpleNamespace(mount_id="m2", mount_path="/integrations/drive/", mode="read_write"),
            "mount_path": "/integrations/drive/",
            "relative_parts": ["a.txt"],
            "requested_path": "/integrations/drive/a.txt",
        }
        with patch.object(filemanager, "_mount_match_for_path", return_value=mount_match):
            filemanager.assert_mount_write_allowed("owner-1", "/integrations/drive/a.txt", action="upload_file")


    def test_download_file_dispatched_streams_from_provider_for_mounted_paths(self):
        stream_response = SimpleNamespace(
            iter_content=lambda chunk_size=0: iter([b"abc", b"def"]),
            close=lambda: None,
        )
        provider = SimpleNamespace(
            get_metadata=lambda ref: {
                "name": "a.txt",
                "type": "file",
                "size": 6,
                "mime_type": "text/plain",
                "modified_time": "2026-01-01T00:00:00+00:00",
            },
            stream_file=lambda ref: stream_response,
        )
        dispatch = {
            "kind": "mount",
            "path": "/integrations/drive/a.txt",
            "mount": SimpleNamespace(provider="google_drive"),
            "mount_path": "/integrations/drive/",
            "relative_parts": ["a.txt"],
            "provider": provider,
            "provider_ref": "gdrive://me/items/file-1",
        }

        with (
            patch.object(filemanager, "resolve_path_dispatch", return_value=dispatch),
            patch.object(filemanager, "record_filemgr_mount_bytes") as record_filemgr_mount_bytes,
            patch.object(filemanager, "record_filemgr_mount_operation_latency") as record_filemgr_mount_operation_latency,
        ):
            out = filemanager.download_file_dispatched("owner-1", "/integrations/drive/a.txt")

        self.assertEqual(out["node"]["content_type"], "text/plain")
        self.assertEqual(out["node"]["size"], 6)
        body = out["object"]["Body"]
        self.assertEqual(body.read(3), b"abc")
        self.assertEqual(body.read(3), b"def")
        self.assertEqual(body.read(3), b"")
        record_filemgr_mount_bytes.assert_called_once_with("google_drive", "out", "download", 6)
        record_filemgr_mount_operation_latency.assert_called_once()


    def test_resolve_path_dispatch_returns_local_for_non_mounted_paths(self):
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch("app.services.mounts_store.list_mounts", return_value=[]),
        ):
            out = filemanager.resolve_path_dispatch("owner-1", "/docs/a.txt")

        self.assertEqual(out["kind"], "local")
        self.assertEqual(out["path"], "/docs/a.txt")

    def test_resolve_path_dispatch_ignores_disabled_mounts(self):
        disabled_mount = SimpleNamespace(
            mount_id="m-1",
            provider="google_drive",
            mount_path="/integrations/drive/",
            provider_root_ref="gdrive://me/items/root",
            status="disabled",
        )
        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch("app.services.mounts_store.list_mounts", return_value=[disabled_mount]),
        ):
            out = filemanager.resolve_path_dispatch("owner-1", "/integrations/drive/a.txt")

        self.assertEqual(out["kind"], "local")

    def test_resolve_path_dispatch_selects_longest_owner_mount_and_resolves_relative_segments(self):
        mount_primary = SimpleNamespace(
            mount_id="m-2",
            owner="owner-1",
            provider="google_drive",
            mount_path="/integrations/drive/work/",
            provider_root_ref="gdrive://me/items/work-root",
        )
        mount_parent = SimpleNamespace(
            mount_id="m-1",
            owner="owner-1",
            provider="google_drive",
            mount_path="/integrations/drive/",
            provider_root_ref="gdrive://me/items/parent-root",
        )

        class _Provider:
            def resolve(self, ref):
                return ref

            def list_children(self, canonical_ref):
                if canonical_ref == "gdrive://me/items/work-root":
                    return ["gdrive://me/items/reports-folder"]
                if canonical_ref == "gdrive://me/items/reports-folder":
                    return ["gdrive://me/items/summary-file"]
                return []

            def get_metadata(self, canonical_ref):
                rows = {
                    "gdrive://me/items/work-root": {"name": "work", "type": "dir"},
                    "gdrive://me/items/reports-folder": {"name": "reports", "type": "dir"},
                    "gdrive://me/items/summary-file": {"name": "summary.txt", "type": "file"},
                }
                return rows[canonical_ref]

        registry = SimpleNamespace(get=lambda owner, provider: _Provider())

        with (
            patch.object(filemanager, "S", SimpleNamespace(filemgr_google_drive_mounts_enabled=True)),
            patch("app.services.mounts_store.list_mounts", return_value=[mount_parent, mount_primary]),
            patch("app.services.file_providers.default_provider_registry", return_value=registry),
        ):
            out = filemanager.resolve_path_dispatch("owner-1", "/integrations/drive/work/reports/summary.txt")

        self.assertEqual(out["kind"], "mount")
        self.assertEqual(out["mount"].mount_id, "m-2")
        self.assertEqual(out["provider_ref"], "gdrive://me/items/summary-file")
        self.assertEqual(out["relative_parts"], ["reports", "summary.txt"])

    def test_get_node_dispatched_uses_mount_metadata_for_mounted_path(self):
        provider = SimpleNamespace(
            resolve=lambda ref: ref,
            get_metadata=lambda ref: {
                "name": "summary.txt",
                "type": "file",
                "size": 123,
                "mime_type": "text/plain",
                "modified_time": "2026-01-01T00:00:00+00:00",
            },
        )
        dispatch = {
            "kind": "mount",
            "path": "/integrations/drive/work/reports/summary.txt",
            "mount": SimpleNamespace(provider="google_drive"),
            "mount_path": "/integrations/drive/work/",
            "relative_parts": ["reports", "summary.txt"],
            "provider": provider,
            "provider_ref": "gdrive://me/items/summary-file",
        }

        with patch.object(filemanager, "resolve_path_dispatch", return_value=dispatch):
            node = filemanager.get_node_dispatched("owner-1", "/integrations/drive/work/reports/summary.txt")

        self.assertEqual(node["type"], "file")
        self.assertEqual(node["provider"], "google_drive")
        self.assertEqual(node["provider_ref"], "gdrive://me/items/summary-file")
        self.assertEqual(node["path"], "/integrations/drive/work/reports/summary.txt")
