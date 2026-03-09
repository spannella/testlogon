from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.services import mounts_store


def _mount_item(**overrides):
    base = {
        "PK": "OWNER#user-1",
        "SK": "MOUNT#m-1",
        "entity_type": "fs_mount",
        "mount_id": "m-1",
        "owner": "user-1",
        "provider": "google_drive",
        "mount_path": "/integrations/drive",
        "provider_root_ref": "gdrive://me/items/root",
        "mode": "read_only",
        "status": "active",
        "status_reason": None,
        "reconnect_required": False,
        "last_checked_at": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


class TestMountsStore(unittest.TestCase):
    def test_create_mount_enforces_unique_path(self):
        table = MagicMock()
        table.query.return_value = {"Items": [_mount_item()]}

        with patch.object(mounts_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                mounts_store.create_mount(
                    "user-1",
                    provider="google_drive",
                    mount_path="/integrations/drive",
                    provider_root_ref="gdrive://me/items/root",
                )

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("already exists", ctx.exception.detail)

    def test_create_mount_rejects_overlapping_path(self):
        table = MagicMock()
        table.query.return_value = {"Items": [_mount_item(mount_path="/integrations/drive")]}

        with patch.object(mounts_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                mounts_store.create_mount(
                    "user-1",
                    provider="google_drive",
                    mount_path="/integrations/drive/team",
                    provider_root_ref="gdrive://me/items/root2",
                )

        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("overlaps", ctx.exception.detail)

    def test_create_mount_persists_model(self):
        table = MagicMock()
        table.query.return_value = {"Items": []}

        with (
            patch.object(mounts_store, "T", SimpleNamespace(projects=table)),
            patch.object(mounts_store, "now_iso", return_value="2026-02-01T00:00:00+00:00"),
        ):
            out = mounts_store.create_mount(
                "user-1",
                provider="google_drive",
                mount_path="/integrations/drive",
                provider_root_ref="gdrive://me/items/root",
                mode="read_write",
            )

        self.assertEqual(out.provider, "google_drive")
        self.assertEqual(out.mode, "read_write")
        table.put_item.assert_called_once()

    def test_list_mounts_returns_only_mount_entities(self):
        table = MagicMock()
        table.query.return_value = {
            "Items": [
                _mount_item(mount_id="m-1"),
                {"PK": "OWNER#user-1", "SK": "PROJECT#p-1", "entity_type": "project"},
            ]
        }
        with patch.object(mounts_store, "T", SimpleNamespace(projects=table)):
            out = mounts_store.list_mounts("user-1")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].mount_id, "m-1")

    def test_update_mount_revalidates_overlap(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _mount_item(mount_id="m-1", mount_path="/integrations/drive")}
        table.query.return_value = {"Items": [_mount_item(mount_id="m-2", mount_path="/integrations/team")]}  # overlap

        with patch.object(mounts_store, "T", SimpleNamespace(projects=table)):
            with self.assertRaises(HTTPException) as ctx:
                mounts_store.update_mount("user-1", "m-1", mount_path="/integrations")

        self.assertEqual(ctx.exception.status_code, 409)

    def test_delete_mount(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _mount_item()}
        with patch.object(mounts_store, "T", SimpleNamespace(projects=table)):
            out = mounts_store.delete_mount("user-1", "m-1")
        self.assertTrue(out["deleted"])
        table.delete_item.assert_called_once()

    def test_reconcile_mount_health_reports_revoked_credential(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _mount_item()}
        with (
            patch.object(mounts_store, "T", SimpleNamespace(projects=table)),
            patch("app.services.provider_credentials.get_provider_credential", side_effect=HTTPException(status_code=404, detail="missing")),
        ):
            out = mounts_store.reconcile_mount_health("user-1", "m-1")
        self.assertTrue(out["stale"])
        self.assertIn("revoked_credential", out["issues"])
        self.assertIn("disable_mount", out["recommended_actions"])

    def test_reconcile_mount_health_reports_orphaned_root(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _mount_item(provider_root_ref="gdrive://me/items/missing")}
        registry = SimpleNamespace(get=lambda owner, provider: SimpleNamespace(exists=lambda ref: False))
        cred = SimpleNamespace(metadata={})
        with (
            patch.object(mounts_store, "T", SimpleNamespace(projects=table)),
            patch("app.services.provider_credentials.get_provider_credential", return_value=cred),
            patch("app.services.file_providers.default_provider_registry", return_value=registry),
        ):
            out = mounts_store.reconcile_mount_health("user-1", "m-1")
        self.assertTrue(out["stale"])
        self.assertIn("orphaned_mount_root", out["issues"])

    def test_set_mount_status_updates_state(self):
        table = MagicMock()
        table.get_item.return_value = {"Item": _mount_item()}
        with (
            patch.object(mounts_store, "T", SimpleNamespace(projects=table)),
            patch.object(mounts_store, "now_iso", return_value="2026-02-01T00:00:00+00:00"),
        ):
            out = mounts_store.set_mount_status("user-1", "m-1", status="disabled", status_reason="revoked_credential", reconnect_required=True)
        self.assertEqual(out.status, "disabled")
        self.assertEqual(out.status_reason, "revoked_credential")
        self.assertTrue(out.reconnect_required)
        table.put_item.assert_called_once()


if __name__ == "__main__":
    unittest.main()
