from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import filemanager as filemanager_router
from app.services import filemanager_mount_flags as flags


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


class TestFilemanagerICloudMountFlags(unittest.TestCase):
    def test_internal_cohort_only_allows_allowlisted_users_or_tenants(self):
        with patch.object(
            flags,
            "S",
            SimpleNamespace(
                filemgr_icloud_mount_enabled=True,
                filemgr_icloud_mount_kill_switch=False,
                filemgr_icloud_mount_rollout_mode="internal",
                filemgr_icloud_mount_environment="dev",
                filemgr_icloud_mount_rollout_mode_by_env="",
                filemgr_icloud_mount_enabled_tenant_ids="",
                filemgr_icloud_mount_disabled_tenant_ids="",
                filemgr_icloud_mount_internal_user_subs="u-internal",
                filemgr_icloud_mount_internal_tenant_ids="t-internal",
                filemgr_icloud_mount_beta_user_subs="",
                filemgr_icloud_mount_beta_tenant_ids="",
            ),
        ):
            allowed_user = flags.evaluate_icloud_mount_access(user_sub="u-internal", tenant_id="t-x")
            self.assertTrue(allowed_user.enabled)
            self.assertEqual(allowed_user.cohort, "internal")

            allowed_tenant = flags.evaluate_icloud_mount_access(user_sub="u-x", tenant_id="t-internal")
            self.assertTrue(allowed_tenant.enabled)
            self.assertEqual(allowed_tenant.cohort, "internal")

            denied = flags.evaluate_icloud_mount_access(user_sub="u-x", tenant_id="t-x")
            self.assertFalse(denied.enabled)
            self.assertIn("allowlist_miss", denied.reason)

    def test_beta_mode_supports_staged_rollout_cohorts(self):
        with patch.object(
            flags,
            "S",
            SimpleNamespace(
                filemgr_icloud_mount_enabled=True,
                filemgr_icloud_mount_kill_switch=False,
                filemgr_icloud_mount_rollout_mode="beta",
                filemgr_icloud_mount_environment="dev",
                filemgr_icloud_mount_rollout_mode_by_env="",
                filemgr_icloud_mount_enabled_tenant_ids="",
                filemgr_icloud_mount_disabled_tenant_ids="",
                filemgr_icloud_mount_internal_user_subs="u-int",
                filemgr_icloud_mount_internal_tenant_ids="",
                filemgr_icloud_mount_beta_user_subs="u-beta",
                filemgr_icloud_mount_beta_tenant_ids="t-beta",
            ),
        ):
            self.assertTrue(flags.evaluate_icloud_mount_access(user_sub="u-int", tenant_id=None).enabled)
            self.assertTrue(flags.evaluate_icloud_mount_access(user_sub="u-beta", tenant_id=None).enabled)
            self.assertTrue(flags.evaluate_icloud_mount_access(user_sub="u-x", tenant_id="t-beta").enabled)
            denied = flags.evaluate_icloud_mount_access(user_sub="u-x", tenant_id="t-x")
            self.assertFalse(denied.enabled)

    def test_kill_switch_overrides_ga_mode(self):
        with patch.object(
            flags,
            "S",
            SimpleNamespace(
                filemgr_icloud_mount_enabled=True,
                filemgr_icloud_mount_kill_switch=True,
                filemgr_icloud_mount_rollout_mode="ga",
                filemgr_icloud_mount_environment="dev",
                filemgr_icloud_mount_rollout_mode_by_env="",
                filemgr_icloud_mount_enabled_tenant_ids="",
                filemgr_icloud_mount_disabled_tenant_ids="",
                filemgr_icloud_mount_internal_user_subs="",
                filemgr_icloud_mount_internal_tenant_ids="",
                filemgr_icloud_mount_beta_user_subs="",
                filemgr_icloud_mount_beta_tenant_ids="",
            ),
        ):
            with self.assertRaises(HTTPException) as ctx:
                flags.enforce_icloud_mount_enabled(user_sub="u1", tenant_id="t1")
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.detail["reason"], "kill_switch")

    def test_environment_mode_override_and_tenant_overrides(self):
        with patch.object(
            flags,
            "S",
            SimpleNamespace(
                filemgr_icloud_mount_enabled=True,
                filemgr_icloud_mount_kill_switch=False,
                filemgr_icloud_mount_rollout_mode="ga",
                filemgr_icloud_mount_environment="prod",
                filemgr_icloud_mount_rollout_mode_by_env="prod:beta,staging:internal",
                filemgr_icloud_mount_enabled_tenant_ids="t-allow",
                filemgr_icloud_mount_disabled_tenant_ids="t-deny",
                filemgr_icloud_mount_internal_user_subs="u-int",
                filemgr_icloud_mount_internal_tenant_ids="",
                filemgr_icloud_mount_beta_user_subs="u-beta",
                filemgr_icloud_mount_beta_tenant_ids="",
            ),
        ):
            denied = flags.evaluate_icloud_mount_access(user_sub="u-beta", tenant_id="t-deny")
            self.assertFalse(denied.enabled)
            self.assertEqual(denied.reason, "tenant_denylist")

            allowed_override = flags.evaluate_icloud_mount_access(user_sub="u-x", tenant_id="t-allow")
            self.assertTrue(allowed_override.enabled)
            self.assertEqual(allowed_override.cohort, "tenant_override")

            allowed_beta = flags.evaluate_icloud_mount_access(user_sub="u-beta", tenant_id="t-x")
            self.assertTrue(allowed_beta.enabled)
            self.assertEqual(allowed_beta.cohort, "beta")

            missed = flags.evaluate_icloud_mount_access(user_sub="u-x", tenant_id="t-x")
            self.assertFalse(missed.enabled)
            self.assertEqual(missed.reason, "beta_allowlist_miss")

    def test_runtime_overrides_allow_toggle_without_code_change(self):
        with (
            patch.object(
                flags,
                "S",
                SimpleNamespace(
                    filemgr_icloud_mount_enabled=True,
                    filemgr_icloud_mount_kill_switch=False,
                    filemgr_icloud_mount_rollout_mode="ga",
                    filemgr_icloud_mount_environment="dev",
                    filemgr_icloud_mount_rollout_mode_by_env="",
                    filemgr_icloud_mount_enabled_tenant_ids="",
                    filemgr_icloud_mount_disabled_tenant_ids="",
                    filemgr_icloud_mount_internal_user_subs="",
                    filemgr_icloud_mount_internal_tenant_ids="",
                    filemgr_icloud_mount_beta_user_subs="",
                    filemgr_icloud_mount_beta_tenant_ids="",
                ),
            ),
            patch.dict("os.environ", {"FILEMGR_ICLOUD_MOUNT_ENABLED_OVERRIDE": "0", "FILEMGR_ICLOUD_MOUNT_KILL_SWITCH_OVERRIDE": "1"}, clear=False),
        ):
            decision = flags.evaluate_icloud_mount_access(user_sub="u1", tenant_id="t1")
            self.assertFalse(decision.enabled)
            self.assertEqual(decision.reason, "global_flag_off")

    def test_rollout_decision_metric_emitted(self):
        with (
            patch.object(
                flags,
                "S",
                SimpleNamespace(
                    filemgr_icloud_mount_enabled=True,
                    filemgr_icloud_mount_kill_switch=False,
                    filemgr_icloud_mount_rollout_mode="beta",
                    filemgr_icloud_mount_environment="prod",
                    filemgr_icloud_mount_rollout_mode_by_env="",
                    filemgr_icloud_mount_enabled_tenant_ids="",
                    filemgr_icloud_mount_disabled_tenant_ids="",
                    filemgr_icloud_mount_internal_user_subs="",
                    filemgr_icloud_mount_internal_tenant_ids="",
                    filemgr_icloud_mount_beta_user_subs="u-beta",
                    filemgr_icloud_mount_beta_tenant_ids="",
                ),
            ),
            patch.object(flags, "record_filemgr_mount_rollout_decision") as rec_rollout,
        ):
            flags.evaluate_icloud_mount_access(user_sub="u-beta", tenant_id="t1")
            rec_rollout.assert_called_once_with(
                provider="icloud",
                environment="prod",
                mode="beta",
                cohort="beta",
                reason="beta_allowlist",
            )


if __name__ == "__main__":
    unittest.main()
