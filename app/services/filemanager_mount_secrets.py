from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.aws import secretsmanager
from app.core.settings import S
from app.metrics import record_filemgr_mount_secret_access
from app.services.alerts import audit_event
from app.services.filemanager_mounts import (
    create_mount,
    get_mount,
    update_mount,
    update_mount_secret_ref_atomic,
)

_SECRET_TAG_OWNER = "filemgr_owner"
_SECRET_TAG_PROVIDER = "filemgr_provider"
_SECRET_TAG_MOUNT_ID = "filemgr_mount_id"


def _secret_name(*, owner_user_sub: str, mount_id: str, provider: str) -> str:
    prefix = str(getattr(S, "filemgr_mount_secret_prefix", "filemgr/mounts") or "filemgr/mounts").strip("/")
    return f"{prefix}/{owner_user_sub}/{provider}/{mount_id}"


def _secret_kms_key_id() -> Optional[str]:
    value = str(getattr(S, "filemgr_mount_secret_kms_key_id", "") or "").strip()
    return value or None


def _cmk_required() -> bool:
    return bool(getattr(S, "filemgr_mount_secret_require_cmk", True)) and not bool(getattr(S, "dev_mode", False))


def _put_secret(*, secret_name: str, secret_payload: Dict[str, Any], owner_user_sub: str, provider: str, mount_id: str) -> str:
    payload = json.dumps(secret_payload)
    kwargs: Dict[str, Any] = {"Name": secret_name, "SecretString": payload}
    kms_key_id = _secret_kms_key_id()
    if _cmk_required() and not kms_key_id:
        raise HTTPException(status_code=500, detail="mount secret KMS key is required")
    if kms_key_id:
        kwargs["KmsKeyId"] = kms_key_id
    kwargs["Tags"] = [
        {"Key": _SECRET_TAG_OWNER, "Value": str(owner_user_sub)},
        {"Key": _SECRET_TAG_PROVIDER, "Value": str(provider)},
        {"Key": _SECRET_TAG_MOUNT_ID, "Value": str(mount_id)},
        {"Key": "managed-by", "Value": "filemanager-mount-service"},
    ]
    try:
        resp = secretsmanager.create_secret(**kwargs)
        return str(resp.get("ARN") or secret_name)
    except ClientError as exc:
        code = str((exc.response or {}).get("Error", {}).get("Code") or "")
        if code == "ResourceExistsException":
            put = secretsmanager.put_secret_value(SecretId=secret_name, SecretString=payload)
            return str(put.get("ARN") or secret_name)
        raise


def create_mount_with_secret(
    *,
    owner_user_sub: str,
    provider: str,
    mount_path: str,
    secret_payload: Dict[str, Any],
    status: str = "pending",
    mount_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(secret_payload, dict) or not secret_payload:
        raise HTTPException(status_code=400, detail="secret_payload is required")

    working_mount_id = mount_id or "pending"
    secret_name = _secret_name(owner_user_sub=owner_user_sub, mount_id=working_mount_id, provider=provider)
    outcome = "success"
    try:
        secret_ref = _put_secret(
            secret_name=secret_name,
            secret_payload=secret_payload,
            owner_user_sub=owner_user_sub,
            provider=provider,
            mount_id=working_mount_id,
        )
        mount = create_mount(
            owner_user_sub=owner_user_sub,
            provider=provider,
            mount_path=mount_path,
            status=status,
            secret_ref=secret_ref,
            mount_id=(None if mount_id is None else mount_id),
        )
        if mount_id is None:
            # create second canonical secret tied to generated mount_id if needed
            canonical_name = _secret_name(owner_user_sub=owner_user_sub, mount_id=mount["mount_id"], provider=provider)
            if canonical_name != secret_name:
                canonical_ref = _put_secret(
                    secret_name=canonical_name,
                    secret_payload=secret_payload,
                    owner_user_sub=owner_user_sub,
                    provider=provider,
                    mount_id=str(mount.get("mount_id") or ""),
                )
                mount = update_mount(owner_user_sub=owner_user_sub, mount_id=mount["mount_id"], secret_ref=canonical_ref)
                try:
                    secretsmanager.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
                except Exception:
                    pass
        audit_event(
            "filemgr_mount_secret_stored",
            owner_user_sub,
            None,
            outcome="success",
            provider=provider,
            mount_id=mount.get("mount_id"),
            secret_ref=mount.get("secret_ref"),
        )
        return mount
    except ClientError as exc:
        outcome = "failure"
        audit_event(
            "filemgr_mount_secret_store_failed",
            owner_user_sub,
            None,
            outcome="failure",
            provider=provider,
            mount_id=mount_id,
            error_code=str((exc.response or {}).get("Error", {}).get("Code") or "unknown"),
        )
        raise HTTPException(status_code=502, detail=f"secret manager error: {exc}") from exc
    except HTTPException:
        outcome = "failure"
        raise
    finally:
        record_filemgr_mount_secret_access(action="store", outcome=outcome)


def get_mount_secret(*, owner_user_sub: str, mount_id: str) -> Dict[str, Any]:
    mount = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    secret_ref = str(mount.get("secret_ref") or "").strip()
    if not secret_ref:
        raise HTTPException(status_code=404, detail="mount secret not configured")
    outcome = "success"
    try:
        resp = secretsmanager.get_secret_value(SecretId=secret_ref)
        raw = str(resp.get("SecretString") or "")
        payload = json.loads(raw) if raw else {}
        audit_event(
            "filemgr_mount_secret_accessed",
            owner_user_sub,
            None,
            outcome="success",
            provider=mount.get("provider"),
            mount_id=mount_id,
            secret_ref=secret_ref,
        )
        return payload if isinstance(payload, dict) else {}
    except ClientError as exc:
        outcome = "failure"
        audit_event(
            "filemgr_mount_secret_access_failed",
            owner_user_sub,
            None,
            outcome="failure",
            provider=mount.get("provider"),
            mount_id=mount_id,
            secret_ref=secret_ref,
            error_code=str((exc.response or {}).get("Error", {}).get("Code") or "unknown"),
        )
        raise HTTPException(status_code=502, detail=f"secret manager error: {exc}") from exc
    finally:
        record_filemgr_mount_secret_access(action="read", outcome=outcome)


def rotate_mount_secret(*, owner_user_sub: str, mount_id: str, secret_payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(secret_payload, dict) or not secret_payload:
        raise HTTPException(status_code=400, detail="secret_payload is required")
    mount = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    current_secret_ref = str(mount.get("secret_ref") or "").strip()
    if not current_secret_ref:
        raise HTTPException(status_code=404, detail="mount secret not configured")

    provider = str(mount.get("provider") or "icloud")
    rotated_name = _secret_name(owner_user_sub=owner_user_sub, mount_id=mount_id, provider=provider) + f"/rot-{uuid.uuid4().hex}"
    outcome = "success"
    try:
        new_secret_ref = _put_secret(
            secret_name=rotated_name,
            secret_payload=secret_payload,
            owner_user_sub=owner_user_sub,
            provider=provider,
            mount_id=mount_id,
        )
        updated_mount = update_mount_secret_ref_atomic(
            owner_user_sub=owner_user_sub,
            mount_id=mount_id,
            expected_secret_ref=current_secret_ref,
            new_secret_ref=new_secret_ref,
        )
        try:
            secretsmanager.delete_secret(SecretId=current_secret_ref, ForceDeleteWithoutRecovery=True)
        except Exception:
            pass
        audit_event(
            "filemgr_mount_secret_rotated",
            owner_user_sub,
            None,
            outcome="success",
            provider=mount.get("provider"),
            mount_id=mount_id,
            previous_secret_ref=current_secret_ref,
            secret_ref=updated_mount.get("secret_ref"),
        )
        return {"ok": True, "secret_ref": updated_mount.get("secret_ref")}
    except HTTPException:
        outcome = "failure"
        raise
    except ClientError as exc:
        outcome = "failure"
        audit_event(
            "filemgr_mount_secret_rotate_failed",
            owner_user_sub,
            None,
            outcome="failure",
            provider=mount.get("provider"),
            mount_id=mount_id,
            secret_ref=current_secret_ref,
            error_code=str((exc.response or {}).get("Error", {}).get("Code") or "unknown"),
        )
        raise HTTPException(status_code=502, detail=f"secret manager error: {exc}") from exc
    finally:
        record_filemgr_mount_secret_access(action="rotate", outcome=outcome)


def revoke_mount_secret(*, owner_user_sub: str, mount_id: str) -> Dict[str, Any]:
    mount = get_mount(owner_user_sub=owner_user_sub, mount_id=mount_id)
    secret_ref = str(mount.get("secret_ref") or "").strip()
    if not secret_ref:
        revoked_mount = update_mount(owner_user_sub=owner_user_sub, mount_id=mount_id, status="revoked", secret_ref="")
        return {"ok": True, "deleted": False, "mount_status": revoked_mount.get("status")}
    outcome = "success"
    try:
        update_mount(owner_user_sub=owner_user_sub, mount_id=mount_id, status="revoking")
        secretsmanager.delete_secret(SecretId=secret_ref, ForceDeleteWithoutRecovery=True)
        revoked_mount = update_mount(owner_user_sub=owner_user_sub, mount_id=mount_id, status="revoked", secret_ref="")
        audit_event(
            "filemgr_mount_secret_revoked",
            owner_user_sub,
            None,
            outcome="success",
            provider=mount.get("provider"),
            mount_id=mount_id,
            secret_ref=secret_ref,
            mount_status=revoked_mount.get("status"),
        )
        return {"ok": True, "deleted": True, "mount_status": revoked_mount.get("status")}
    except ClientError as exc:
        outcome = "failure"
        update_mount(owner_user_sub=owner_user_sub, mount_id=mount_id, status="revocation_failed")
        audit_event(
            "filemgr_mount_secret_revoke_failed",
            owner_user_sub,
            None,
            outcome="failure",
            provider=mount.get("provider"),
            mount_id=mount_id,
            secret_ref=secret_ref,
            error_code=str((exc.response or {}).get("Error", {}).get("Code") or "unknown"),
        )
        raise HTTPException(status_code=502, detail=f"secret manager error: {exc}") from exc
    finally:
        record_filemgr_mount_secret_access(action="revoke", outcome=outcome)
