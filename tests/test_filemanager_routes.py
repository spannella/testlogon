import io
import unittest
from unittest.mock import patch

from fastapi import UploadFile
from fastapi.responses import StreamingResponse
from app.routers import filemanager


class TestFileManagerRoutes(unittest.TestCase):
    def test_list_and_info(self):
        items = [
            {"path": "/docs/", "type": "folder", "name": "docs", "parent": "/", "updated_at": "t1"},
            {"path": "/docs/a.txt", "type": "file", "name": "a.txt", "parent": "/docs/", "updated_at": "t2", "size": 12},
            {"path": "/docs/sub/b.txt", "type": "file", "name": "b.txt", "parent": "/docs/sub/", "updated_at": "t3", "size": 1},
        ]
        with patch.object(filemanager, "list_children", return_value=items), patch.object(
            filemanager,
            "get_node",
            return_value={
                "path": "/docs/a.txt",
                "type": "file",
                "name": "a.txt",
                "parent": "/docs/",
                "created_at": "t0",
                "updated_at": "t2",
            },
        ):
            resp = filemanager.list_files(path="/docs", user="user")
            self.assertEqual(resp["path"], "/docs/")
            self.assertEqual(len(resp["items"]), 1)
            self.assertEqual(resp["items"][0]["path"], "/docs/a.txt")
            self.assertEqual(resp["items"][0]["name"], "a.txt")

            info = filemanager.file_info(path="/docs/a.txt", user="user")
            self.assertEqual(info["path"], "/docs/a.txt")
            self.assertEqual(info["type"], "file")

    def test_search_and_create(self):
        with patch.object(filemanager, "search_prefix", return_value=[{"path": "/a", "type": "file", "name": "a"}]):
            resp = filemanager.search_filenames(prefix="a", limit=10, user="user")
            self.assertEqual(resp["prefix"], "a")
            self.assertEqual(resp["results"][0]["path"], "/a")

        with patch.object(filemanager, "create_empty_folder", return_value="/docs/"):
            resp = filemanager.create_folder(path="/docs", user="user")
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["path"], "/docs/")

    def test_upload_and_download(self):
        upload = UploadFile(filename="a.txt", file=io.BytesIO(b"hello"))
        with patch.object(filemanager, "upload_file", return_value={"path": "/docs/a.txt", "size": 5}):
            resp = filemanager.upload_fs_file(path="/docs/a.txt", file=upload, user="user")
            self.assertTrue(resp["ok"])
            self.assertEqual(resp["size"], 5)

        obj = {"Body": io.BytesIO(b"hello")}
        node = {"name": "a.txt", "content_type": "text/plain"}
        with patch.object(filemanager, "download_file", return_value={"node": node, "object": obj}):
            resp = filemanager.download_fs_file(path="/docs/a.txt", user="user")
            self.assertIsInstance(resp, StreamingResponse)
            self.assertEqual(resp.media_type, "text/plain")
            self.assertIn("attachment; filename=\"a.txt\"", resp.headers.get("Content-Disposition", ""))

    def test_delete_and_move(self):
        with patch.object(filemanager, "remove_file") as remove_file:
            resp = filemanager.remove_fs_file(path="/docs/a.txt", user="user")
            self.assertTrue(resp["ok"])
            remove_file.assert_called_once_with("user", "/docs/a.txt")

        with patch.object(filemanager, "remove_folder", return_value=3):
            resp = filemanager.remove_fs_folder(path="/docs/", user="user")
            self.assertEqual(resp["deleted_count"], 3)

        with patch.object(filemanager, "move_node", return_value={"type": "file", "src": "/a", "dst": "/b"}):
            resp = filemanager.move_fs_node(src="/a", dst="/b", user="user")
            self.assertEqual(resp["type"], "file")

    def test_rename_and_zip(self):
        with patch.object(filemanager, "move_node", return_value={"type": "file", "src": "/a", "dst": "/b"}) as move_node:
            resp = filemanager.rename_file(path="/a", new_name="b", user="user")
            self.assertTrue(resp["ok"])
            move_node.assert_called_once_with("user", "/a", "/b")

        with patch.object(filemanager, "move_node", return_value={"type": "folder", "src": "/a/", "dst": "/b/"}) as move_node:
            resp = filemanager.rename_folder(path="/a/", new_name="b", user="user")
            self.assertTrue(resp["ok"])
            move_node.assert_called_once_with("user", "/a/", "/b/")

        buf = io.BytesIO(b"zipdata")
        with patch.object(filemanager, "download_zip", return_value=buf):
            resp = filemanager.download_multiple_as_zip(paths=["/a"], user="user")
            self.assertIsInstance(resp, StreamingResponse)
            self.assertEqual(resp.media_type, "application/zip")

        upload = UploadFile(filename="files.zip", file=io.BytesIO(b"zipdata"))
        with patch.object(filemanager, "upload_zip", return_value=["/a.txt"]):
            resp = filemanager.upload_zip_and_extract(dest_folder="/", zip_file=upload, user="user")
            self.assertEqual(resp["count"], 1)

    def test_sharing(self):
        with patch.object(filemanager, "share_node") as share_node:
            resp = filemanager.share_fs_node(path="/a", to_user="bob", user="user")
            self.assertTrue(resp["ok"])
            share_node.assert_called_once_with("user", "/a", "bob")

        with patch.object(filemanager, "list_shared_with", return_value=["bob"]):
            resp = filemanager.list_shared(path="/a", user="user")
            self.assertEqual(resp["shared_with"], ["bob"])

        with patch.object(filemanager, "list_shared_with_me", return_value=[{"owner": "alice", "path": "/a"}]):
            resp = filemanager.list_shared_me(user="user")
            self.assertEqual(resp["items"][0]["owner"], "alice")
