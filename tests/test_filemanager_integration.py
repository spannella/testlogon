import io
import unittest
from unittest.mock import patch

from fastapi import UploadFile

from app.routers import filemanager as filemanager_router
from app.services import filemanager


class _Body:
    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)

    def read(self, size: int = -1):
        return self._buf.read(size)


class FakeS3:
    def __init__(self):
        self.objects = {}

    def upload_fileobj(self, Fileobj, Bucket, Key, ExtraArgs=None):
        data = Fileobj.read()
        Fileobj.seek(0)
        self.objects[(Bucket, Key)] = {
            "Body": data,
            "ContentType": (ExtraArgs or {}).get("ContentType", "application/octet-stream"),
            "ETag": '"etag"',
        }

    def head_object(self, Bucket, Key):
        obj = self.objects[(Bucket, Key)]
        return {"ContentLength": len(obj["Body"]), "ETag": obj["ETag"], "ContentType": obj["ContentType"], "Metadata": {}}

    def get_object(self, Bucket, Key):
        obj = self.objects[(Bucket, Key)]
        return {"Body": _Body(obj["Body"])}


class FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def update_item(self, Key, UpdateExpression=None, ExpressionAttributeValues=None):
        item = self.items[(Key["PK"], Key["SK"])]
        if "last_download_at" in (UpdateExpression or ""):
            item["last_download_at"] = ExpressionAttributeValues[":t"]
            item["last_download_by"] = ExpressionAttributeValues[":u"]


class TestFileManagerIntegration(unittest.TestCase):
    def test_upload_download_encrypted_and_unencrypted_with_emulators(self):
        table = FakeTable()
        s3 = FakeS3()

        enc_meta = {
            "version": 1,
            "alg": "AES-256-GCM",
            "kdf": "PBKDF2-SHA256",
            "iterations": 600000,
            "salt_b64": "c2FsdA==",
            "iv_b64": "aXY=",
            "orig_name": "secret.txt",
            "orig_size": 6,
            "mime": "text/plain",
        }

        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "_s3", s3),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
        ):
            plain_upload = UploadFile(filename="plain.txt", file=io.BytesIO(b"plain"), headers={"content-type": "text/plain"})
            plain_out = filemanager.upload_file("user", "/docs/plain.txt", plain_upload)
            self.assertEqual(plain_out["path"], "/docs/plain.txt")

            enc_upload = UploadFile(filename="secret.txt", file=io.BytesIO(b"cipher"), headers={"content-type": "application/octet-stream"})
            enc_out = filemanager.upload_file("user", "/docs/secret.txt", enc_upload, encryption_meta=enc_meta)
            self.assertEqual(enc_out["path"], "/docs/secret.txt")

            plain_node = filemanager.get_node("user", "/docs/plain.txt")
            self.assertFalse(plain_node.get("is_encrypted"))

            enc_node = filemanager.get_node("user", "/docs/secret.txt")
            self.assertTrue(enc_node.get("is_encrypted"))
            self.assertEqual(enc_node.get("enc_version"), 1)
            self.assertEqual(enc_node.get("enc_alg"), "AES-256-GCM")

            plain_dl = filemanager.download_file("user", "/docs/plain.txt")
            self.assertEqual(plain_dl["object"]["Body"].read(), b"plain")

            enc_dl = filemanager.download_file("user", "/docs/secret.txt")
            self.assertEqual(enc_dl["object"]["Body"].read(), b"cipher")

    def test_unencrypted_regression_path(self):
        table = FakeTable()
        s3 = FakeS3()

        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "_s3", s3),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=3),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value={"bucket": "bucket", "key": "thumb", "content_type": "image/jpeg"}),
        ):
            upload = UploadFile(filename="video.mp4", file=io.BytesIO(b"video"), headers={"content-type": "video/mp4"})
            out = filemanager.upload_file("user", "/docs/video.mp4", upload)
            self.assertEqual(out["path"], "/docs/video.mp4")
            node = filemanager.get_node("user", "/docs/video.mp4")
            self.assertEqual(node.get("duration_seconds"), 3)
            self.assertIsNotNone(node.get("thumbnail"))
            self.assertFalse(node.get("is_encrypted"))


class FakeMeteringTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None):
        key = (Item["PK"], Item["SK"])
        if ConditionExpression == "attribute_not_exists(SK)" and key in self.items:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "dup"}}, "PutItem")
        self.items[key] = dict(Item)

    def update_item(self, *, Key, ExpressionAttributeValues=None, **kwargs):
        item = self.items.get((Key["PK"], Key["SK"]), {"PK": Key["PK"], "SK": Key["SK"]})
        vals = ExpressionAttributeValues or {}
        if "USAGE#PERIOD#" in Key["SK"]:
            item["entity_type"] = "usage_period_totals"
            item["user_id"] = vals[":user_id"]
            item["period_id"] = vals[":period_id"]
            item["upload_bytes_total"] = int(item.get("upload_bytes_total", 0)) + int(vals[":upload_inc"])
            item["download_bytes_total"] = int(item.get("download_bytes_total", 0)) + int(vals[":download_inc"])
            item["storage_bytes_current"] = int(item.get("storage_bytes_current", 0)) + int(vals[":storage_delta"])
            item["storage_bytes_peak"] = int(item.get("storage_bytes_peak", 0))
            item["storage_byte_seconds"] = int(item.get("storage_byte_seconds", 0))
            item["updated_at"] = vals[":updated_at"]
            item["ttl_epoch"] = vals[":ttl_epoch"]
        elif "USAGE#DAY#" in Key["SK"]:
            item["entity_type"] = "usage_daily"
            item["user_id"] = vals[":user_id"]
            item["day_utc"] = vals[":day_utc"]
            item["period_id"] = vals[":period_id"]
            item["upload_bytes_total"] = int(item.get("upload_bytes_total", 0)) + int(vals[":upload_inc"])
            item["download_bytes_total"] = int(item.get("download_bytes_total", 0)) + int(vals[":download_inc"])
            item["storage_bytes_end_of_day"] = int(item.get("storage_bytes_end_of_day", 0)) + int(vals[":storage_delta"])
            item["updated_at"] = vals[":updated_at"]
            item["ttl_epoch"] = vals[":ttl_epoch"]
        self.items[(Key["PK"], Key["SK"])] = item

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def query(self, **kwargs):
        items = [dict(v) for (pk, sk), v in self.items.items() if sk.startswith("USAGE#EVENT#")]
        return {"Items": items}

    def scan(self, **kwargs):
        return {"Items": [dict(v) for v in self.items.values()]}


class TestUsageMeteringRecomputeIntegration(unittest.TestCase):
    def test_recompute_matches_seeded_upload_download_shared_archive_events(self):
        from app.services.usage_metering import build_usage_event, record_usage_event_and_aggregates

        table = FakeMeteringTable()
        events = [
            build_usage_event(
                user_id="user",
                event_type="upload",
                bytes_count=100,
                source="api_upload",
                resource_path="/docs/a.txt",
                request_id="u-1",
                timestamp="2026-02-05T00:00:00+00:00",
            ),
            build_usage_event(
                user_id="user",
                event_type="download",
                bytes_count=25,
                source="download_file",
                resource_path="/docs/a.txt",
                request_id="d-1",
                timestamp="2026-02-05T00:05:00+00:00",
            ),
            build_usage_event(
                user_id="user",
                event_type="download",
                bytes_count=10,
                source="shared_download",
                resource_path="/shared/x.txt",
                request_id="sd-1",
                timestamp="2026-02-05T00:06:00+00:00",
            ),
            build_usage_event(
                user_id="user",
                event_type="upload",
                bytes_count=50,
                source="upload_archive_entry",
                resource_path="/archives/b.txt",
                request_id="a-1",
                timestamp="2026-02-05T00:07:00+00:00",
            ),
            build_usage_event(
                user_id="user",
                event_type="upload",
                bytes_count=50,
                source="upload_archive_total",
                resource_path="/",
                request_id="a-total",
                timestamp="2026-02-05T00:08:00+00:00",
            ),
            build_usage_event(
                user_id="user",
                event_type="storage_delta",
                bytes_count=150,
                source="upload_create",
                resource_path="/docs/",
                request_id="s-1",
                timestamp="2026-02-05T00:09:00+00:00",
            ),
        ]

        for ev in events:
            apply = ev["source"] != "upload_archive_total"
            record_usage_event_and_aggregates(table, ev, apply_aggregates=apply)

        with patch.object(filemanager, "_table", return_value=table):
            out = filemanager.recompute_usage_aggregates_admin(scope="user", user_id="user", period_id="2026-02", apply=True)

        self.assertEqual(out["events_scanned"], 6)
        self.assertEqual(out["mismatches"], 1)

        period = table.get_item(Key={"PK": "USER#user", "SK": "USAGE#PERIOD#2026-02"}).get("Item") or {}
        self.assertEqual(period.get("upload_bytes_total"), 200)
        self.assertEqual(period.get("download_bytes_total"), 35)
        self.assertEqual(period.get("storage_bytes_current"), 150)


class TestPreviewFlowsIntegration(unittest.TestCase):
    def test_owned_and_shared_preview_success_matrix_for_supported_types(self):
        table = FakeTable()
        s3 = FakeS3()
        owner = "owner"
        viewer = "viewer"

        preview_cases = [
            ("/docs/pic.png", "pic.png", "image/png", b"\x89PNG\r\n"),
            ("/docs/doc.pdf", "doc.pdf", "application/pdf", b"%PDF-1.7"),
            ("/docs/readme.txt", "readme.txt", "text/plain", b"hello"),
            ("/docs/table.csv", "table.csv", "text/csv", b"name,age\nA,1"),
            (
                "/docs/sheet.xlsx",
                "sheet.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                b"PK\x03\x04",
            ),
            ("/docs/data.parquet", "data.parquet", "application/parquet", b"PAR1"),
            (
                "/docs/report.docx",
                "report.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                b"PK\x03\x04",
            ),
        ]

        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "_s3", s3),
            patch.object(filemanager_router, "download_file", side_effect=filemanager.download_file),
            patch.object(filemanager_router, "require_shared_access", return_value={"permission": "read"}),
            patch.object(filemanager_router, "preview_capability_from_node", side_effect=filemanager.preview_capability_from_node),
            patch.object(filemanager_router, "is_previewable", side_effect=filemanager.is_previewable),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
        ):
            for path, filename, content_type, body in preview_cases:
                upload = UploadFile(filename=filename, file=io.BytesIO(body), headers={"content-type": content_type})
                filemanager.upload_file(owner, path, upload)
                owned_preview = filemanager_router.preview_fs_file(path=path, user=owner)
                self.assertEqual(owned_preview.media_type, content_type)
                self.assertIn('inline; filename="', owned_preview.headers.get("content-disposition", ""))

                shared_preview = filemanager_router.shared_preview_fs_file(owner=owner, path=path, user=viewer)
                self.assertEqual(shared_preview.media_type, content_type)
                self.assertIn('inline; filename="', shared_preview.headers.get("content-disposition", ""))

    def test_owned_and_shared_preview_reject_encrypted_files(self):
        table = FakeTable()
        s3 = FakeS3()
        owner = "owner"
        viewer = "viewer"
        enc_meta = {
            "version": 1,
            "alg": "AES-256-GCM",
            "kdf": "PBKDF2-SHA256",
            "iterations": 600000,
            "salt_b64": "c2FsdA==",
            "iv_b64": "aXY=",
            "orig_name": "secret.csv",
            "orig_size": 12,
            "mime": "text/csv",
        }

        with (
            patch.object(filemanager, "_table", return_value=table),
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "_s3", s3),
            patch.object(filemanager_router, "download_file", side_effect=filemanager.download_file),
            patch.object(filemanager_router, "require_shared_access", return_value={"permission": "read"}),
            patch.object(filemanager_router, "preview_capability_from_node", side_effect=filemanager.preview_capability_from_node),
            patch.object(filemanager_router, "is_previewable", side_effect=filemanager.is_previewable),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists"),
            patch.object(filemanager, "_maybe_probe_duration", return_value=None),
            patch.object(filemanager, "_maybe_generate_thumbnail", return_value=None),
        ):
            upload = UploadFile(
                filename="secret.csv",
                file=io.BytesIO(b"ciphertext"),
                headers={"content-type": "application/octet-stream"},
            )
            filemanager.upload_file(owner, "/docs/secret.csv", upload, encryption_meta=enc_meta)
            with self.assertRaises(filemanager_router.HTTPException) as owned_ctx:
                filemanager_router.preview_fs_file(path="/docs/secret.csv", user=owner)
            self.assertEqual(owned_ctx.exception.status_code, 415)

            with self.assertRaises(filemanager_router.HTTPException) as shared_ctx:
                filemanager_router.shared_preview_fs_file(owner=owner, path="/docs/secret.csv", user=viewer)
            self.assertEqual(shared_ctx.exception.status_code, 415)


if __name__ == "__main__":
    unittest.main()
