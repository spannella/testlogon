from __future__ import annotations

import json
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services import filemanager_mount_secrets as svc


def test_create_mount_with_secret_stores_secret_and_saves_secret_ref() -> None:
    sm = Mock()
    sm.create_secret.return_value = {"ARN": "arn:aws:secretsmanager:region:acct:secret:mount1"}

    with (
        patch.object(svc, "_cmk_required", return_value=False),
        patch.object(svc, "secretsmanager", sm),
        patch.object(svc, "create_mount", return_value={"mount_id": "m1", "secret_ref": "arn:aws:secretsmanager:region:acct:secret:mount1"}) as create_mount,
        patch.object(svc, "record_filemgr_mount_secret_access") as rec,
    ):
        out = svc.create_mount_with_secret(
            owner_user_sub="u1",
            provider="icloud",
            mount_path="/icloud",
            mount_id="m1",
            secret_payload={"session_token": "abc", "expires_at": "t1"},
        )

    assert out["mount_id"] == "m1"
    assert create_mount.call_args.kwargs["secret_ref"].startswith("arn:")
    assert sm.create_secret.call_args.kwargs["Tags"]
    assert "session_token" not in json.dumps(create_mount.call_args.kwargs)
    rec.assert_called_with(action="store", outcome="success")


def test_get_mount_secret_reads_from_secret_manager_and_monitors() -> None:
    sm = Mock()
    sm.get_secret_value.return_value = {"SecretString": '{"session_token":"abc"}'}

    with (
        patch.object(svc, "secretsmanager", sm),
        patch.object(svc, "get_mount", return_value={"mount_id": "m1", "provider": "icloud", "secret_ref": "arn:secret:m1"}),
        patch.object(svc, "record_filemgr_mount_secret_access") as rec,
    ):
        out = svc.get_mount_secret(owner_user_sub="u1", mount_id="m1")

    assert out["session_token"] == "abc"
    sm.get_secret_value.assert_called_once_with(SecretId="arn:secret:m1")
    rec.assert_called_with(action="read", outcome="success")


def test_rotate_mount_secret_updates_secret_ref_atomically() -> None:
    sm = Mock()
    sm.create_secret.return_value = {"ARN": "arn:secret:new"}
    with (
        patch.object(svc, "_cmk_required", return_value=False),
        patch.object(svc, "secretsmanager", sm),
        patch.object(svc, "get_mount", return_value={"mount_id": "m1", "provider": "icloud", "secret_ref": "arn:secret:old"}),
        patch.object(svc, "update_mount_secret_ref_atomic", return_value={"mount_id": "m1", "secret_ref": "arn:secret:new"}) as update_ref,
    ):
        rot = svc.rotate_mount_secret(owner_user_sub="u1", mount_id="m1", secret_payload={"session_token": "new"})

    assert rot["ok"] is True
    assert rot["secret_ref"] == "arn:secret:new"
    update_ref.assert_called_once_with(
        owner_user_sub="u1",
        mount_id="m1",
        expected_secret_ref="arn:secret:old",
        new_secret_ref="arn:secret:new",
    )
    sm.delete_secret.assert_called_once_with(SecretId="arn:secret:old", ForceDeleteWithoutRecovery=True)


def test_revoke_mount_secret_sets_revoked_status() -> None:
    sm = Mock()
    with (
        patch.object(svc, "secretsmanager", sm),
        patch.object(svc, "get_mount", return_value={"mount_id": "m1", "provider": "icloud", "secret_ref": "arn:secret:m1"}),
        patch.object(svc, "update_mount", side_effect=[{"status": "revoking"}, {"status": "revoked"}]) as update_mount,
    ):
        rev = svc.revoke_mount_secret(owner_user_sub="u1", mount_id="m1")

    assert rev["deleted"] is True
    assert rev["mount_status"] == "revoked"
    sm.delete_secret.assert_called_once_with(SecretId="arn:secret:m1", ForceDeleteWithoutRecovery=True)
    assert update_mount.call_count == 2


def test_create_mount_with_secret_requires_payload() -> None:
    with patch.object(svc, "record_filemgr_mount_secret_access"):
        try:
            svc.create_mount_with_secret(owner_user_sub="u1", provider="icloud", mount_path="/icloud", secret_payload={})
            assert False, "expected exception"
        except HTTPException as exc:
            assert exc.status_code == 400


def test_create_mount_with_secret_requires_cmk_when_configured() -> None:
    with (
        patch.object(svc, "_cmk_required", return_value=True),
        patch.object(svc, "_secret_kms_key_id", return_value=None),
        patch.object(svc, "record_filemgr_mount_secret_access"),
    ):
        try:
            svc.create_mount_with_secret(
                owner_user_sub="u1",
                provider="icloud",
                mount_path="/icloud",
                mount_id="m1",
                secret_payload={"session_token": "abc"},
            )
            assert False, "expected exception"
        except HTTPException as exc:
            assert exc.status_code == 500
