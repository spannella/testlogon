from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services import filemanager_mounts as mounts


class TestFilemanagerMounts(unittest.TestCase):
    def test_create_get_update_delete_mount(self):
        table = Mock()
        table.name = "filemgr_mounts"
        table.meta.client = Mock()
        stored = {
            "pk": "MOUNT#m1",
            "sk": "META",
            "entity_type": "mount",
            "mount_id": "m1",
            "owner_user_sub": "u1",
            "provider": "icloud",
            "mount_path": "/icloud/",
            "status": "pending",
            "secret_ref": "sec-1",
            "created_at": "t1",
            "updated_at": "t1",
            "gsi_owner_pk": "OWNER#u1",
            "gsi_owner_sk": "PATH#/icloud/",
        }
        table.get_item.side_effect = [
            {"Item": stored},
            {"Item": stored},
            {"Item": {**stored, "status": "active", "updated_at": "t2", "secret_ref": "sec-2"}},
            {"Item": {**stored, "status": "active", "updated_at": "t2", "secret_ref": "sec-2"}},
        ]

        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", side_effect=["t1", "t2"]),
            patch.object(mounts, "norm_path", return_value="/icloud/"),
            patch.object(mounts, "list_mounts", return_value=[]),
        ):
            created = mounts.create_mount(
                owner_user_sub="u1",
                provider="icloud",
                mount_path="/icloud",
                mount_id="m1",
                secret_ref="sec-1",
            )
            self.assertEqual(created["mount_id"], "m1")
            self.assertEqual(created["status"], "pending")

            got = mounts.get_mount(owner_user_sub="u1", mount_id="m1")
            self.assertEqual(got["mount_path"], "/icloud/")

            updated = mounts.update_mount(owner_user_sub="u1", mount_id="m1", status="active", secret_ref="sec-2")
            self.assertEqual(updated["status"], "active")
            self.assertEqual(updated["secret_ref"], "sec-2")

            mounts.delete_mount(owner_user_sub="u1", mount_id="m1")

        self.assertTrue(table.meta.client.transact_write_items.called)
        table.update_item.assert_called_once()

    def test_create_mount_duplicate_path_raises_conflict(self):
        table = Mock()
        table.name = "filemgr_mounts"
        table.meta.client = Mock()
        table.meta.client.transact_write_items.side_effect = RuntimeError("conditional failed")
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", return_value="t1"),
            patch.object(mounts, "norm_path", return_value="/icloud/"),
            patch.object(mounts, "list_mounts", return_value=[]),
        ):
            with self.assertRaises(HTTPException) as ctx:
                mounts.create_mount(owner_user_sub="u1", provider="icloud", mount_path="/icloud")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_update_mount_secret_ref_atomic_uses_expected_ref_condition(self):
        table = Mock()
        stored = {
            "pk": "MOUNT#m1",
            "sk": "META",
            "entity_type": "mount",
            "mount_id": "m1",
            "owner_user_sub": "u1",
            "provider": "icloud",
            "mount_path": "/icloud/",
            "status": "active",
            "secret_ref": "sec-new",
        }
        table.get_item.side_effect = [
            {"Item": {**stored, "secret_ref": "sec-old"}},
            {"Item": stored},
        ]
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", return_value="t2"),
        ):
            out = mounts.update_mount_secret_ref_atomic(
                owner_user_sub="u1",
                mount_id="m1",
                expected_secret_ref="sec-old",
                new_secret_ref="sec-new",
            )
        self.assertEqual(out["secret_ref"], "sec-new")
        table.update_item.assert_called_once()


    def test_create_mount_rejects_invalid_conflict_policy(self):
        table = Mock()
        table.name = "filemgr_mounts"
        table.meta.client = Mock()
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", return_value="t1"),
            patch.object(mounts, "norm_path", return_value="/icloud/"),
            patch.object(mounts, "list_mounts", return_value=[]),
        ):
            with self.assertRaises(HTTPException) as ctx:
                mounts.create_mount(owner_user_sub="u1", provider="icloud", mount_path="/icloud", conflict_policy="bad")
        self.assertEqual(ctx.exception.status_code, 400)


    def test_invalid_states_and_root_path_rejected(self):
        with self.assertRaises(HTTPException):
            mounts.create_mount(owner_user_sub="u1", provider="", mount_path="/icloud")

        with patch.object(mounts, "get_mount", return_value={"status": "pending"}):
            with self.assertRaises(HTTPException):
                mounts.update_mount(owner_user_sub="u1", mount_id="m1", status="bad")

        table = Mock()
        table.name = "filemgr_mounts"
        table.meta.client = Mock()
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "norm_path", return_value="/"),
            patch.object(mounts, "list_mounts", return_value=[]),
        ):
            with self.assertRaises(HTTPException) as ctx:
                mounts.create_mount(owner_user_sub="u1", provider="icloud", mount_path="/")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_create_mount_rejects_overlapping_path(self):
        with (
            patch.object(mounts, "list_mounts", return_value=[{"mount_id": "m1", "mount_path": "/icloud/"}]),
            patch.object(mounts, "norm_path", side_effect=lambda p, is_folder=True: p if p.endswith("/") else f"{p}/"),
        ):
            with self.assertRaises(HTTPException) as ctx:
                mounts.create_mount(owner_user_sub="u1", provider="icloud", mount_path="/icloud/team")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_update_mount_rejects_invalid_status_transition(self):
        with patch.object(mounts, "get_mount", return_value={"status": "active"}):
            with self.assertRaises(HTTPException) as ctx:
                mounts.update_mount(owner_user_sub="u1", mount_id="m1", status="pending")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_update_mount_manual_override_can_force_status_transition(self):
        table = Mock()
        table.get_item.return_value = {
            "Item": {
                "entity_type": "mount",
                "mount_id": "m1",
                "owner_user_sub": "u1",
                "provider": "icloud",
                "mount_path": "/icloud/",
                "status": "pending",
            }
        }
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", return_value="t1"),
        ):
            mounts.update_mount(owner_user_sub="u1", mount_id="m1", status="revoked", manual_override=True)
        table.update_item.assert_called_once()

    def test_list_mounts_returns_only_mount_entities(self):
        table = Mock()
        table.query.return_value = {
            "Items": [
                {
                    "entity_type": "mount",
                    "mount_id": "m2",
                    "owner_user_sub": "u1",
                    "provider": "icloud",
                    "mount_path": "/b/",
                    "status": "active",
                },
                {"entity_type": "mount_path", "mount_id": "m2"},
                {
                    "entity_type": "mount",
                    "mount_id": "m1",
                    "owner_user_sub": "u1",
                    "provider": "icloud",
                    "mount_path": "/a/",
                    "status": "pending",
                },
            ]
        }
        with patch.object(mounts, "_table", return_value=table):
            rows = mounts.list_mounts(owner_user_sub="u1")
        self.assertEqual([r["mount_id"] for r in rows], ["m1", "m2"])

    def test_list_mounts_paginates_until_exhausted(self):
        table = Mock()
        table.query.side_effect = [
            {
                "Items": [
                    {"entity_type": "mount", "mount_id": "m2", "owner_user_sub": "u1", "provider": "icloud", "mount_path": "/b/", "status": "active"},
                ],
                "LastEvaluatedKey": {"pk": "next"},
            },
            {
                "Items": [
                    {"entity_type": "mount", "mount_id": "m1", "owner_user_sub": "u1", "provider": "icloud", "mount_path": "/a/", "status": "active"},
                ]
            },
        ]
        with patch.object(mounts, "_table", return_value=table):
            rows = mounts.list_mounts(owner_user_sub="u1")
        self.assertEqual([r["mount_id"] for r in rows], ["m1", "m2"])
        self.assertEqual(table.query.call_count, 2)

    def test_list_mounts_requires_owner(self):
        with self.assertRaises(HTTPException) as ctx:
            mounts.list_mounts(owner_user_sub="")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_resolve_mount_for_path_uses_longest_prefix_and_protects_collisions(self):
        entries = [
            {"mount_id": "m1", "provider": "icloud", "mount_path": "/icloud/", "status": "active"},
            {"mount_id": "m2", "provider": "icloud", "mount_path": "/icloud/team/", "status": "active"},
        ]
        with (
            patch.object(mounts, "list_mounts", return_value=entries),
            patch.object(mounts, "norm_path", side_effect=lambda p, is_folder=None: p),
        ):
            resolved = mounts.resolve_mount_for_path(owner_user_sub="u1", path="/icloud/team/docs/a.txt")
            self.assertEqual(resolved["mount_id"], "m2")

            root_resolved = mounts.resolve_mount_for_path(owner_user_sub="u1", path="/icloud")
            self.assertEqual(root_resolved["mount_id"], "m1")

            collision = mounts.resolve_mount_for_path(owner_user_sub="u1", path="/icloudx/docs")
            self.assertIsNone(collision)

    def test_resolve_mount_for_path_skips_inactive_mounts(self):
        entries = [
            {"mount_id": "m1", "provider": "icloud", "mount_path": "/icloud/", "status": "revoked"},
            {"mount_id": "m2", "provider": "icloud", "mount_path": "/icloud2/", "status": "pending"},
        ]
        with (
            patch.object(mounts, "list_mounts", return_value=entries),
            patch.object(mounts, "norm_path", side_effect=lambda p, is_folder=None: p),
        ):
            self.assertIsNone(mounts.resolve_mount_for_path(owner_user_sub="u1", path="/icloud/docs"))


    def test_apply_mount_health_signal_transitions_and_recovery(self):
        table = Mock()
        mount = {
            "mount_id": "m1",
            "owner_user_sub": "u1",
            "provider": "icloud",
            "mount_path": "/icloud/",
            "status": "active",
            "health_failures": 0,
            "health_successes": 0,
            "manual_override": False,
        }
        table.get_item.side_effect = [
            {"Item": mount},
            {"Item": {**mount, "status": "active", "health_failures": 1, "health_successes": 0}},
            {"Item": {**mount, "status": "active", "health_failures": 1, "health_successes": 0}},
            {"Item": {**mount, "status": "degraded", "health_failures": 2, "health_successes": 0}},
            {"Item": {**mount, "status": "degraded", "health_failures": 2, "health_successes": 0}},
            {"Item": {**mount, "status": "unavailable", "health_failures": 3, "health_successes": 0}},
            {"Item": {**mount, "status": "unavailable", "health_failures": 3, "health_successes": 0}},
            {"Item": {**mount, "status": "active", "health_failures": 0, "health_successes": 1, "status_updated_at": "t1"}},
        ]
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", return_value="t1"),
            patch.object(mounts, "_health_fail_degraded_threshold", return_value=2),
            patch.object(mounts, "_health_fail_unavailable_threshold", return_value=3),
            patch.object(mounts, "_health_success_recovery_threshold", return_value=1),
        ):
            out1 = mounts.apply_mount_health_signal(owner_user_sub="u1", mount_id="m1", outcome="failure", error_class="server_error")
            self.assertEqual(out1["status"], "active")
            out2 = mounts.apply_mount_health_signal(owner_user_sub="u1", mount_id="m1", outcome="failure", error_class="server_error")
            self.assertEqual(out2["status"], "degraded")
            out3 = mounts.apply_mount_health_signal(owner_user_sub="u1", mount_id="m1", outcome="failure", error_class="server_error")
            self.assertEqual(out3["status"], "unavailable")
            out4 = mounts.apply_mount_health_signal(owner_user_sub="u1", mount_id="m1", outcome="success", error_class="none")
            self.assertEqual(out4["status"], "active")
            self.assertEqual(out4["status_updated_at"], "t1")
            self.assertEqual(out4["status_update_sla_seconds"], mounts.S.filemgr_mount_status_update_sla_seconds)

    def test_apply_mount_health_signal_manual_override_blocks_auto_transition(self):
        table = Mock()
        mount = {
            "mount_id": "m1",
            "owner_user_sub": "u1",
            "provider": "icloud",
            "mount_path": "/icloud/",
            "status": "degraded",
            "health_failures": 2,
            "health_successes": 0,
            "manual_override": True,
        }
        table.get_item.side_effect = [
            {"Item": mount},
            {"Item": {**mount, "status": "degraded", "health_failures": 3, "health_successes": 0, "status_updated_at": "t1"}},
        ]
        with (
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_now_iso", return_value="t1"),
            patch.object(mounts, "_health_fail_degraded_threshold", return_value=2),
            patch.object(mounts, "_health_fail_unavailable_threshold", return_value=3),
        ):
            out = mounts.apply_mount_health_signal(owner_user_sub="u1", mount_id="m1", outcome="failure", error_class="server_error")
        self.assertEqual(out["status"], "degraded")

    def test_set_and_clear_mount_status_override(self):
        with (
            patch.object(mounts, "update_mount", return_value={"mount_id": "m1", "status": "degraded", "provider": "icloud", "mount_path": "/icloud/"}) as update_mount,
        ):
            mounts.set_mount_status_override(owner_user_sub="u1", mount_id="m1", status="degraded")
            update_mount.assert_called_with(owner_user_sub="u1", mount_id="m1", status="degraded", manual_override=True)

        with (
            patch.object(mounts, "update_mount", return_value={"mount_id": "m1", "status": "active", "provider": "icloud", "mount_path": "/icloud/"}) as update_mount,
        ):
            mounts.clear_mount_status_override(owner_user_sub="u1", mount_id="m1", target_status="active")
            update_mount.assert_called_with(owner_user_sub="u1", mount_id="m1", status="active", manual_override=False)


if __name__ == "__main__":
    unittest.main()
