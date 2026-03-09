import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import sftp_mounts


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None):
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def delete_item(self, Key):
        self.items.pop((Key["PK"], Key["SK"]), None)

    def scan(self, Limit=None):
        return {"Items": [dict(v) for v in self.items.values()]}


class _FakeDdb:
    def __init__(self, table):
        self.table = table

    def Table(self, name):
        return self.table


class TestSftpMountsService(unittest.TestCase):
    def test_create_get_update_delete_mount(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        with (
            patch.object(sftp_mounts, "ddb", fake_ddb),
            patch.object(sftp_mounts, "now_iso", side_effect=["t1", "t2", "t3", "t4"]),
            patch("app.core.settings.S") as settings,
        ):
            settings.filemgr_sftp_mounts_table_name = "sftp_mounts"
            created = sftp_mounts.create_sftp_mount(
                owner="user-1",
                host="sftp.example.com",
                port=22,
                auth_credential_ref="cred-1",
                remote_root="/team/docs",
                read_only=True,
            )
            loaded = sftp_mounts.get_sftp_mount(owner="user-1", mount_id=created.id)
            self.assertEqual(loaded.host, "sftp.example.com")
            self.assertEqual(loaded.remote_root, "/team/docs")

            updated = sftp_mounts.update_sftp_mount(
                owner="user-1",
                mount_id=created.id,
                status="degraded",
                read_only=False,
            )
            self.assertEqual(updated.status, "degraded")
            self.assertFalse(updated.read_only)

            resp = sftp_mounts.delete_sftp_mount(owner="user-1", mount_id=created.id)
            self.assertTrue(resp["ok"])
            with self.assertRaises(HTTPException) as ctx:
                sftp_mounts.get_sftp_mount(owner="user-1", mount_id=created.id)
            self.assertEqual(ctx.exception.status_code, 404)

    def test_owner_scoped_listing_and_mount_lookup(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        with (
            patch.object(sftp_mounts, "ddb", fake_ddb),
            patch("app.core.settings.S") as settings,
        ):
            settings.filemgr_sftp_mounts_table_name = "sftp_mounts"
            a = sftp_mounts.create_sftp_mount(
                owner="u1",
                host="a.example.com",
                port=22,
                auth_credential_ref="cred-a",
                remote_root="/",
            )
            sftp_mounts.create_sftp_mount(
                owner="u2",
                host="b.example.com",
                port=22,
                auth_credential_ref="cred-b",
                remote_root="/",
            )

            items = sftp_mounts.list_sftp_mounts(owner="u1")
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].owner, "u1")
            self.assertTrue(hasattr(items[0], "id"))

            looked_up = sftp_mounts.find_sftp_mount_by_id(mount_id=a.id)
            self.assertIsNotNone(looked_up)
            self.assertEqual(looked_up.id, a.id)

    def test_invalid_host_port_and_root_raise_validation_errors(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        with (
            patch.object(sftp_mounts, "ddb", fake_ddb),
            patch("app.core.settings.S") as settings,
        ):
            settings.filemgr_sftp_mounts_table_name = "sftp_mounts"
            with self.assertRaises(HTTPException) as host_ctx:
                sftp_mounts.create_sftp_mount(
                    owner="u1",
                    host="https://bad.host/path",
                    port=22,
                    auth_credential_ref="cred",
                    remote_root="/",
                )
            self.assertEqual(host_ctx.exception.status_code, 400)
            self.assertIn("host", str(host_ctx.exception.detail))

            with self.assertRaises(HTTPException) as port_ctx:
                sftp_mounts.create_sftp_mount(
                    owner="u1",
                    host="good-host",
                    port=0,
                    auth_credential_ref="cred",
                    remote_root="/",
                )
            self.assertEqual(port_ctx.exception.status_code, 400)

            with self.assertRaises(HTTPException) as root_ctx:
                sftp_mounts.create_sftp_mount(
                    owner="u1",
                    host="good-host",
                    port=22,
                    auth_credential_ref="cred",
                    remote_root="../bad",
                )
            self.assertEqual(root_ctx.exception.status_code, 400)
            self.assertIn("remote_root", str(root_ctx.exception.detail))

    def test_destination_policy_enforced_on_mount_create_and_update(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        with (
            patch.object(sftp_mounts, "ddb", fake_ddb),
            patch("app.core.settings.S") as settings,
            patch.object(sftp_mounts, "enforce_sftp_destination_policy") as enforce,
        ):
            settings.filemgr_sftp_mounts_table_name = "sftp_mounts"
            created = sftp_mounts.create_sftp_mount(
                owner="u1",
                host="sftp.allowed.example.com",
                port=22,
                auth_credential_ref="cred",
                remote_root="/",
            )
            sftp_mounts.update_sftp_mount(owner="u1", mount_id=created.id, host="sftp2.allowed.example.com")

        self.assertGreaterEqual(enforce.call_count, 2)

    def test_protocol_validation_and_persistence(self):
        table = _FakeTable()
        fake_ddb = _FakeDdb(table)
        with (
            patch.object(sftp_mounts, "ddb", fake_ddb),
            patch("app.core.settings.S") as settings,
        ):
            settings.filemgr_sftp_mounts_table_name = "sftp_mounts"
            created = sftp_mounts.create_sftp_mount(
                owner="u1",
                protocol="ftp",
                host="ftp.example.com",
                port=21,
                auth_credential_ref="cred",
                remote_root="/",
            )
            self.assertEqual(created.protocol, "ftp")

            updated = sftp_mounts.update_sftp_mount(owner="u1", mount_id=created.id, protocol="scp")
            self.assertEqual(updated.protocol, "scp")

            with self.assertRaises(HTTPException) as ctx:
                sftp_mounts.create_sftp_mount(
                    owner="u1",
                    protocol="badproto",
                    host="host.example.com",
                    port=22,
                    auth_credential_ref="cred",
                    remote_root="/",
                )
            self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
