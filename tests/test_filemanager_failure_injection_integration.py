from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from fastapi import HTTPException, UploadFile

from app.routers import filemanager as filemanager_router
from app.services import filemanager_mounts as mounts
from app.services.filemanager_provider import ICloudProvider, ICloudThrottledError, ICloudTransientError


class _MountHealthTable:
    def __init__(self, item: dict):
        self._item = dict(item)

    def get_item(self, Key, ConsistentRead=False):
        del Key, ConsistentRead
        return {"Item": dict(self._item)}

    def update_item(
        self,
        *,
        Key,
        UpdateExpression=None,
        ExpressionAttributeNames=None,
        ExpressionAttributeValues=None,
        ConditionExpression=None,
    ):
        del Key, UpdateExpression, ConditionExpression
        names = ExpressionAttributeNames or {}
        vals = ExpressionAttributeValues or {}
        for alias, field in names.items():
            value_key = alias.replace("#", ":")
            if value_key in vals:
                self._item[field] = vals[value_key]


class _FlakyWriteTransport:
    def __init__(self):
        self.calls = 0

    def write(self, *, user_sub: str, path: str, data: bytes, content_type: str | None, overwrite: bool = False):
        del user_sub, content_type, overwrite
        self.calls += 1
        if self.calls == 1:
            raise ICloudTransientError("partial write simulated")
        return {"path": path, "size": len(data), "type": "file"}

    def stat(self, *, user_sub: str, path: str):
        del user_sub, path
        return {"path": "/icloud/docs/new.txt", "type": "file", "name": "new.txt"}

    def read(self, *, user_sub: str, path: str):
        del user_sub, path
        return {"node": {"path": "/icloud/docs/new.txt", "type": "file", "name": "new.txt"}, "object": {"Body": io.BytesIO(b"ok")}}

    def list(self, *, user_sub: str, path: str):
        del user_sub, path
        return []

    def delete(self, *, user_sub: str, path: str):
        del user_sub, path
        return {"ok": True}

    def move(self, *, user_sub: str, src: str, dst: str, overwrite: bool = False):
        del user_sub, src, dst, overwrite
        return {"ok": True}


class _ThrottledReadTransport:
    def __init__(self):
        self.calls = 0

    def read(self, *, user_sub: str, path: str):
        del user_sub, path
        self.calls += 1
        if self.calls < 3:
            raise ICloudThrottledError("rate limited")
        return {"node": {"path": "/icloud/docs/a.txt", "type": "file", "name": "a.txt"}, "object": {"Body": io.BytesIO(b"hello")}}

    def stat(self, *, user_sub: str, path: str):
        del user_sub, path
        return {"path": "/icloud/docs/a.txt", "type": "file", "name": "a.txt"}

    def list(self, *, user_sub: str, path: str):
        del user_sub, path
        return []

    def write(self, *, user_sub: str, path: str, data: bytes, content_type: str | None, overwrite: bool = False):
        del user_sub, path, data, content_type, overwrite
        return {"ok": True}

    def delete(self, *, user_sub: str, path: str):
        del user_sub, path
        return {"ok": True}

    def move(self, *, user_sub: str, src: str, dst: str, overwrite: bool = False):
        del user_sub, src, dst, overwrite
        return {"ok": True}


class TestFailureInjectionIntegration(unittest.TestCase):
    def test_verify_flow_handles_mfa_then_recovers_to_active(self):
        inp = filemanager_router.ICloudVerifyIn(onboarding_session_id="filemgr_mount_onboard#abc")

        with (
            patch.object(filemanager_router, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager_router, "enforce_lockout"),
            patch.object(filemanager_router, "rate_limit_filemgr_mount_verify"),
            patch.object(filemanager_router, "get_onboarding_session", return_value={"mount_id": "m1"}),
            patch.object(
                filemanager_router,
                "get_mount_secret",
                return_value={"auth_mode": "session_token", "auth_value": "token", "force_mfa_required": True},
            ),
            patch.object(filemanager_router, "update_onboarding_session") as update_session,
            patch.object(filemanager_router, "update_mount") as update_mount,
            patch.object(filemanager_router, "clear_lockout"),
            patch.object(filemanager_router, "audit_event"),
        ):
            first = filemanager_router.verify_icloud_mount(inp=inp, req=None, user="u1")
            second = filemanager_router.verify_icloud_mount(
                inp=filemanager_router.ICloudVerifyIn(onboarding_session_id="filemgr_mount_onboard#abc", mfa_code="123456"),
                req=None,
                user="u1",
            )

        self.assertEqual(first.outcome, "mfa_required")
        self.assertEqual(second.outcome, "active")
        self.assertEqual(update_session.call_count, 2)
        update_mount.assert_called_once_with(owner_user_sub="u1", mount_id="m1", status="active")

    def test_upload_failures_transition_mount_to_reauth_required(self):
        mount = {
            "pk": "MOUNT#m1",
            "sk": "META",
            "mount_id": "m1",
            "owner_user_sub": "u1",
            "provider": "icloud",
            "mount_path": "/icloud/",
            "status": "active",
            "health_failures": 0,
            "health_successes": 0,
            "manual_override": False,
        }
        table = _MountHealthTable(mount)

        with (
            patch.object(filemanager_router, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager_router, "_storage_context", return_value=("icloud", "m1", True)),
            patch.object(
                filemanager_router._storage_dispatcher,
                "write",
                side_effect=HTTPException(status_code=401, detail={"code": "auth_expired"}),
            ),
            patch.object(filemanager_router, "record_filemgr_provider_operation"),
            patch.object(filemanager_router, "audit_event"),
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_health_fail_reauth_threshold", return_value=2),
        ):
            with self.assertRaises(HTTPException):
                filemanager_router.upload_fs_file(
                    path="/icloud/docs/a.txt",
                    file=UploadFile(filename="a.txt", file=io.BytesIO(b"abc")),
                    user="u1",
                )
            with self.assertRaises(HTTPException):
                filemanager_router.upload_fs_file(
                    path="/icloud/docs/a.txt",
                    file=UploadFile(filename="a.txt", file=io.BytesIO(b"abc")),
                    user="u1",
                )

            out = mounts.get_mount(owner_user_sub="u1", mount_id="m1")

        self.assertEqual(out["status"], "reauth_required")
        self.assertEqual(out["health_failures"], 2)

    def test_repeated_server_errors_transition_degraded_to_unavailable_then_recover(self):
        mount = {
            "pk": "MOUNT#m1",
            "sk": "META",
            "mount_id": "m1",
            "owner_user_sub": "u1",
            "provider": "icloud",
            "mount_path": "/icloud/",
            "status": "active",
            "health_failures": 0,
            "health_successes": 0,
            "manual_override": False,
        }
        table = _MountHealthTable(mount)
        write_side_effects = [
            HTTPException(status_code=503, detail={"code": "upstream_error"}),
            HTTPException(status_code=503, detail={"code": "upstream_error"}),
            HTTPException(status_code=503, detail={"code": "upstream_error"}),
            {"path": "/icloud/docs/a.txt", "size": 3},
        ]

        with (
            patch.object(filemanager_router, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager_router, "_storage_context", return_value=("icloud", "m1", True)),
            patch.object(filemanager_router._storage_dispatcher, "write", side_effect=write_side_effects),
            patch.object(filemanager_router, "record_filemgr_provider_operation"),
            patch.object(filemanager_router, "audit_event"),
            patch.object(mounts, "_table", return_value=table),
            patch.object(mounts, "_health_fail_degraded_threshold", return_value=2),
            patch.object(mounts, "_health_fail_unavailable_threshold", return_value=3),
            patch.object(mounts, "_health_success_recovery_threshold", return_value=1),
        ):
            for _ in range(3):
                with self.assertRaises(HTTPException):
                    filemanager_router.upload_fs_file(
                        path="/icloud/docs/a.txt",
                        file=UploadFile(filename="a.txt", file=io.BytesIO(b"abc")),
                        user="u1",
                    )
            self.assertEqual(mounts.get_mount(owner_user_sub="u1", mount_id="m1")["status"], "unavailable")

            out = filemanager_router.upload_fs_file(
                path="/icloud/docs/a.txt",
                file=UploadFile(filename="a.txt", file=io.BytesIO(b"abc")),
                user="u1",
            )
            self.assertTrue(out["ok"])

            recovered = mounts.get_mount(owner_user_sub="u1", mount_id="m1")

        self.assertEqual(recovered["status"], "active")
        self.assertEqual(recovered["health_failures"], 0)

    def test_icloud_provider_retries_throttled_reads_then_succeeds(self):
        provider = ICloudProvider(transport=_ThrottledReadTransport())
        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_retry_policy", return_value=(3, 0.0, 0.0)),
            patch("time.sleep", return_value=None),
        ):
            out = provider.read("u1", "/icloud/docs/a.txt")
        self.assertEqual(out["node"]["name"], "a.txt")

    def test_icloud_provider_partial_write_failure_recovers_on_retry(self):
        provider = ICloudProvider(transport=_FlakyWriteTransport())
        upload = UploadFile(filename="new.txt", file=io.BytesIO(b"payload"))
        with (
            patch.object(ICloudProvider, "_ensure_enabled", return_value=None),
            patch.object(ICloudProvider, "_retry_policy", return_value=(2, 0.0, 0.0)),
            patch("app.services.filemanager_mounts.resolve_mount_for_path", return_value={"conflict_policy": "last_write_wins"}),
            patch("time.sleep", return_value=None),
        ):
            out = provider.write("u1", "/icloud/docs/new.txt", upload)

        self.assertEqual(out["path"], "/icloud/docs/new.txt")
        self.assertEqual(out["size"], 7)

    def test_verify_flow_handles_expired_auth_then_reauth_success(self):
        inp = filemanager_router.ICloudVerifyIn(onboarding_session_id="filemgr_mount_onboard#abc")
        healthy_secret = {"auth_mode": "session_token", "auth_value": "token", "force_auth_failed": False}

        with (
            patch.object(filemanager_router, "_enforce_filemanager_internal_entitlement"),
            patch.object(filemanager_router, "enforce_lockout"),
            patch.object(filemanager_router, "rate_limit_filemgr_mount_verify"),
            patch.object(filemanager_router, "get_onboarding_session", return_value={"mount_id": "m1"}),
            patch.object(
                filemanager_router,
                "get_mount_secret",
                side_effect=[
                    {"auth_mode": "session_token", "auth_value": "token", "force_auth_failed": True},
                    healthy_secret,
                ],
            ),
            patch.object(filemanager_router, "update_onboarding_session") as update_session,
            patch.object(filemanager_router, "record_lockout_failure") as lockout_failure,
            patch.object(filemanager_router, "record_filemgr_provider_auth_failure") as auth_failure_metric,
            patch.object(filemanager_router, "update_mount") as update_mount,
            patch.object(filemanager_router, "clear_lockout") as clear_lockout,
            patch.object(filemanager_router, "audit_event"),
        ):
            first = filemanager_router.verify_icloud_mount(inp=inp, req=None, user="u1")
            second = filemanager_router.verify_icloud_mount(inp=inp, req=None, user="u1")

        self.assertEqual(first.outcome, "auth_failed")
        self.assertEqual(second.outcome, "active")
        self.assertGreaterEqual(update_session.call_count, 2)
        lockout_failure.assert_called_once()
        auth_failure_metric.assert_called_once_with(provider="icloud", mount_id="m1", reason="auth_failed")
        update_mount.assert_called_once_with(owner_user_sub="u1", mount_id="m1", status="active")
        clear_lockout.assert_called_once()


if __name__ == "__main__":
    unittest.main()
