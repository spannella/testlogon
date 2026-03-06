from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.aws_clients import kms_client
from app.core.settings import S
from app.services.alerts import audit_event

AUTH_PASSWORD = "password"
AUTH_PRIVATE_KEY = "private_key"
SUPPORTED_AUTH_MODES = {AUTH_PASSWORD, AUTH_PRIVATE_KEY}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table():
    table_name = str(getattr(S, "filemgr_sftp_credentials_table_name", "") or "").strip()
    if not table_name:
        raise HTTPException(status_code=500, detail="sftp credentials table not configured")
    return ddb.Table(table_name)


def _kms_key_id() -> str:
    key_id = str(getattr(S, "filemgr_sftp_credentials_kms_key_id", "") or "").strip()
    if key_id:
        return key_id
    fallback = str(getattr(S, "kms_key_id", "") or "").strip()
    if fallback:
        return fallback
    raise HTTPException(status_code=500, detail="sftp credentials kms key not configured")


def _pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _sk(mount_id: str) -> str:
    return f"SFTP_CRED#{mount_id}"


def _validate_inputs(
    *,
    owner: str,
    mount_id: str,
    auth_mode: str,
    username: str,
    password: Optional[str],
    private_key: Optional[str],
) -> str:
    owner_norm = (owner or "").strip()
    mount_norm = (mount_id or "").strip()
    auth_norm = (auth_mode or "").strip().lower()
    user_norm = (username or "").strip()

    if not owner_norm:
        raise HTTPException(status_code=400, detail="owner is required")
    if not mount_norm:
        raise HTTPException(status_code=400, detail="mount_id is required")
    if auth_norm not in SUPPORTED_AUTH_MODES:
        raise HTTPException(status_code=400, detail="unsupported auth_mode")
    if not user_norm:
        raise HTTPException(status_code=400, detail="username is required")

    if auth_norm == AUTH_PASSWORD:
        if not (password or "").strip():
            raise HTTPException(status_code=400, detail="password is required for password auth")
    if auth_norm == AUTH_PRIVATE_KEY:
        if not (private_key or "").strip():
            raise HTTPException(status_code=400, detail="private_key is required for private_key auth")

    return auth_norm


def _encryption_context(*, owner: str, mount_id: str) -> Dict[str, str]:
    return {
        "app": "filemanager",
        "domain": "sftp_credentials",
        "owner": owner,
        "mount_id": mount_id,
    }


def _envelope_encrypt_payload(*, payload: Dict[str, Any], owner: str, mount_id: str) -> Dict[str, str]:
    kms = kms_client()
    key_id = _kms_key_id()
    context = _encryption_context(owner=owner, mount_id=mount_id)
    data_key_resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256", EncryptionContext=context)
    data_key_plain = data_key_resp.get("Plaintext")
    encrypted_data_key = data_key_resp.get("CiphertextBlob")
    if not isinstance(data_key_plain, (bytes, bytearray)) or len(data_key_plain) != 32:
        raise HTTPException(status_code=500, detail="failed to generate data key")
    if not isinstance(encrypted_data_key, (bytes, bytearray)):
        raise HTTPException(status_code=500, detail="failed to encrypt data key")

    nonce = os.urandom(12)
    aad = f"{owner}:{mount_id}".encode("utf-8")
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(bytes(data_key_plain)).encrypt(nonce, plaintext, aad)

    return {
        "key_encrypted_b64": base64.b64encode(bytes(encrypted_data_key)).decode("utf-8"),
        "secret_ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "aad_b64": base64.b64encode(aad).decode("utf-8"),
        "key_id": key_id,
    }


def _envelope_decrypt_payload(*, item: Dict[str, Any], owner: str, mount_id: str) -> Dict[str, Any]:
    kms = kms_client()
    context = _encryption_context(owner=owner, mount_id=mount_id)
    key_ct = base64.b64decode(str(item.get("key_encrypted_b64") or ""))
    secret_ct = base64.b64decode(str(item.get("secret_ciphertext_b64") or ""))
    nonce = base64.b64decode(str(item.get("nonce_b64") or ""))
    aad = base64.b64decode(str(item.get("aad_b64") or ""))

    if not key_ct or not secret_ct or len(nonce) != 12 or not aad:
        raise HTTPException(status_code=500, detail="stored credential payload is invalid")

    data_key_resp = kms.decrypt(CiphertextBlob=key_ct, EncryptionContext=context)
    data_key_plain = data_key_resp.get("Plaintext")
    if not isinstance(data_key_plain, (bytes, bytearray)) or len(data_key_plain) != 32:
        raise HTTPException(status_code=500, detail="failed to decrypt data key")

    plaintext = AESGCM(bytes(data_key_plain)).decrypt(nonce, secret_ct, aad)
    try:
        out = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=500, detail="stored credential payload could not be decoded") from exc
    if not isinstance(out, dict):
        raise HTTPException(status_code=500, detail="stored credential payload is invalid")
    return out


def upsert_sftp_credential(
    *,
    owner: str,
    mount_id: str,
    auth_mode: str,
    username: str,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    private_key_passphrase: Optional[str] = None,
    actor_sub: Optional[str] = None,
) -> Dict[str, Any]:
    auth_norm = _validate_inputs(
        owner=owner,
        mount_id=mount_id,
        auth_mode=auth_mode,
        username=username,
        password=password,
        private_key=private_key,
    )
    owner_norm = owner.strip()
    mount_norm = mount_id.strip()
    user_norm = username.strip()

    secret_payload: Dict[str, Any] = {}
    if auth_norm == AUTH_PASSWORD:
        secret_payload["password"] = (password or "").strip()
    else:
        secret_payload["private_key"] = private_key or ""
        if (private_key_passphrase or ""):
            secret_payload["private_key_passphrase"] = private_key_passphrase

    encrypted = _envelope_encrypt_payload(payload=secret_payload, owner=owner_norm, mount_id=mount_norm)

    tbl = _table()
    existing = tbl.get_item(Key={"PK": _pk(owner_norm), "SK": _sk(mount_norm)}, ConsistentRead=True).get("Item") or {}
    ts = now_iso()
    item = {
        "PK": _pk(owner_norm),
        "SK": _sk(mount_norm),
        "entity_type": "sftp_credential",
        "owner": owner_norm,
        "mount_id": mount_norm,
        "auth_mode": auth_norm,
        "username": user_norm,
        "key_encrypted_b64": encrypted["key_encrypted_b64"],
        "secret_ciphertext_b64": encrypted["secret_ciphertext_b64"],
        "nonce_b64": encrypted["nonce_b64"],
        "aad_b64": encrypted["aad_b64"],
        "kms_key_id": encrypted["key_id"],
        "created_at": existing.get("created_at") or ts,
        "updated_at": ts,
    }
    tbl.put_item(Item=item)
    audit_event(
        "filemgr_sftp_credential_upserted",
        actor_sub or owner_norm,
        outcome="success",
        owner=owner_norm,
        mount_id=mount_norm,
        auth_mode=auth_norm,
        kms_key_id=encrypted["key_id"],
        operation="upsert",
        secret_redacted=True,
    )
    return {
        "owner": owner_norm,
        "mount_id": mount_norm,
        "auth_mode": auth_norm,
        "username": user_norm,
        "created_at": item["created_at"],
        "updated_at": item["updated_at"],
    }


def get_sftp_credential(
    *,
    owner: str,
    mount_id: str,
    include_secret: bool = True,
    actor_sub: Optional[str] = None,
) -> Dict[str, Any]:
    owner_norm = (owner or "").strip()
    mount_norm = (mount_id or "").strip()
    if not owner_norm or not mount_norm:
        raise HTTPException(status_code=400, detail="owner and mount_id are required")

    tbl = _table()
    item = tbl.get_item(Key={"PK": _pk(owner_norm), "SK": _sk(mount_norm)}, ConsistentRead=True).get("Item")
    if not item or item.get("entity_type") != "sftp_credential":
        raise HTTPException(status_code=404, detail="sftp credential not found")

    response = {
        "owner": owner_norm,
        "mount_id": mount_norm,
        "auth_mode": item.get("auth_mode"),
        "username": item.get("username"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }
    if include_secret:
        response["secret"] = _envelope_decrypt_payload(item=item, owner=owner_norm, mount_id=mount_norm)

    audit_event(
        "filemgr_sftp_credential_accessed",
        actor_sub or owner_norm,
        outcome="success",
        owner=owner_norm,
        mount_id=mount_norm,
        auth_mode=item.get("auth_mode"),
        include_secret=bool(include_secret),
        operation="read",
        secret_redacted=True,
    )
    return response


def delete_sftp_credential(*, owner: str, mount_id: str, actor_sub: Optional[str] = None) -> Dict[str, Any]:
    owner_norm = (owner or "").strip()
    mount_norm = (mount_id or "").strip()
    if not owner_norm or not mount_norm:
        raise HTTPException(status_code=400, detail="owner and mount_id are required")

    tbl = _table()
    key = {"PK": _pk(owner_norm), "SK": _sk(mount_norm)}
    existing = tbl.get_item(Key=key, ConsistentRead=True).get("Item")
    if not existing or existing.get("entity_type") != "sftp_credential":
        raise HTTPException(status_code=404, detail="sftp credential not found")

    tbl.delete_item(Key=key)
    audit_event(
        "filemgr_sftp_credential_deleted",
        actor_sub or owner_norm,
        outcome="success",
        owner=owner_norm,
        mount_id=mount_norm,
        auth_mode=existing.get("auth_mode"),
        operation="delete",
        secret_redacted=True,
    )
    return {"ok": True, "owner": owner_norm, "mount_id": mount_norm}
