import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import filemanager as filemanager_router


class _Mount:
    def __init__(self, status="healthy"):
        self.status = status


class TestFileManagerMountFlags(unittest.TestCase):
    def test_mount_paths_blocked_when_service_flag_disabled(self):
        with patch.object(filemanager_router, "S") as settings:
            settings.filemgr_sftp_mounts_enabled = False
            settings.filemgr_sftp_mounts_write_enabled = False
            settings.filemgr_sftp_mounts_share_enabled = False
            with self.assertRaises(HTTPException) as ctx:
                filemanager_router._enforce_sftp_mount_flags_for_path("/mounts/mnt_1/docs/a.txt", operation="read")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "sftp_mounts_disabled")

    def test_mount_write_blocked_when_write_flag_disabled(self):
        with patch.object(filemanager_router, "S") as settings:
            settings.filemgr_sftp_mounts_enabled = True
            settings.filemgr_sftp_mounts_write_enabled = False
            settings.filemgr_sftp_mounts_share_enabled = False
            with self.assertRaises(HTTPException) as ctx:
                filemanager_router._enforce_sftp_mount_flags_for_path("/mounts/mnt_1/docs/a.txt", operation="write")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "sftp_mount_writes_disabled")

    def test_mount_share_blocked_when_share_flag_disabled(self):
        with patch.object(filemanager_router, "S") as settings:
            settings.filemgr_sftp_mounts_enabled = True
            settings.filemgr_sftp_mounts_write_enabled = True
            settings.filemgr_sftp_mounts_share_enabled = False
            with self.assertRaises(HTTPException) as ctx:
                filemanager_router._enforce_sftp_mount_flags_for_path("/mounts/mnt_1/docs/a.txt", operation="share")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "sftp_mount_shares_disabled")

    def test_non_mount_paths_are_unaffected(self):
        with patch.object(filemanager_router, "S") as settings:
            settings.filemgr_sftp_mounts_enabled = False
            settings.filemgr_sftp_mounts_write_enabled = False
            settings.filemgr_sftp_mounts_share_enabled = False
            filemanager_router._enforce_sftp_mount_flags_for_path("/docs/a.txt", operation="write")

    def test_disabled_mount_blocks_read_and_write(self):
        with patch.object(filemanager_router, "get_sftp_mount", return_value=_Mount(status="disabled")):
            with self.assertRaises(HTTPException) as read_ctx:
                filemanager_router._enforce_sftp_mount_status_for_path("/mounts/m1/docs/a.txt", owner="u1", operation="read")
            with self.assertRaises(HTTPException) as write_ctx:
                filemanager_router._enforce_sftp_mount_status_for_path("/mounts/m1/docs/a.txt", owner="u1", operation="write")

        self.assertEqual(read_ctx.exception.status_code, 409)
        self.assertEqual(read_ctx.exception.detail["code"], "mount_disabled")
        self.assertEqual(write_ctx.exception.status_code, 409)
        self.assertEqual(write_ctx.exception.detail["code"], "mount_disabled")

    def test_non_mount_path_skips_status_enforcement(self):
        with patch.object(filemanager_router, "get_sftp_mount") as get_mount:
            filemanager_router._enforce_sftp_mount_status_for_path("/docs/a.txt", owner="u1", operation="read")
        get_mount.assert_not_called()

    def test_mount_share_policy_denies_all_mounted_paths(self):
        with self.assertRaises(HTTPException) as ctx:
            filemanager_router._enforce_sftp_mount_share_policy('/mounts/m1/docs/a.txt')
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail['code'], 'sftp_mount_share_not_allowed')

    def test_mount_share_policy_allows_native_paths(self):
        filemanager_router._enforce_sftp_mount_share_policy('/docs/a.txt')


if __name__ == "__main__":
    unittest.main()
