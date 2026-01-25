import io
import unittest
import warnings
import zipfile
from unittest.mock import Mock, patch

from fastapi import HTTPException, UploadFile

from app.services import filemanager


class TestFileManagerService(unittest.TestCase):
    def test_upload_file_rejects_existing_path(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with (
            patch.object(filemanager, "_bucket", return_value="bucket"),
            patch.object(filemanager, "ensure_folder_exists"),
            patch.object(filemanager, "require_not_exists") as require_not_exists,
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.head_object.return_value = {"ContentLength": 5, "ETag": "etag"}
            filemanager.upload_file("user", "/docs/a.txt", upload)
        require_not_exists.assert_called_once()

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
            patch.object(filemanager, "put_node"),
            patch.object(filemanager, "_s3") as s3,
        ):
            s3.put_object = Mock()
            with self.assertRaises(HTTPException) as ctx:
                filemanager.upload_zip("user", "/", upload)
        self.assertEqual(ctx.exception.status_code, 409)
