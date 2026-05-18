from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException

from app.core.aws_clients import kms_client
from app.core.settings import S

_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {"access_token", "refresh_token", "id_token", "client_secret"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _kms_key_id() -> str:
    key_id = str(getattr(S, "google_calendar_tokens_kms_key_id", "") or "").strip()
    if key_id:
        return key_id
    fallback = str(getattr(S, "kms_key_id", "") or "").strip()
    if fallback:
        return fallback
    raise HTTPException(status_code=500, detail="google calendar token kms key not configured")


def _encryption_context(*, user_sub: str, connection_id: str) -> Dict[str, str]:
    return {
        "service": "google_calendar",
        "scope": "oauth_tokens",
        "user_sub": user_sub,
        "connection_id": connection_id,
    }


def redact_token_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for key, value in payload.items():
        redacted[key] = _REDACTED if key in _SENSITIVE_KEYS else value
    return redacted


def encrypt_token_payload(*, payload: Dict[str, Any], user_sub: str, connection_id: str) -> Dict[str, str]:
    kms = kms_client()
    key_id = _kms_key_id()
    ctx = _encryption_context(user_sub=user_sub, connection_id=connection_id)
    data_key_resp = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256", EncryptionContext=ctx)

    data_key_plain = data_key_resp.get("Plaintext")
    encrypted_data_key = data_key_resp.get("CiphertextBlob")
    if not isinstance(data_key_plain, (bytes, bytearray)):
        raise HTTPException(status_code=500, detail="failed to generate data key")
    if not isinstance(encrypted_data_key, (bytes, bytearray)):
        raise HTTPException(status_code=500, detail="failed to encrypt data key")

    aad = json.dumps(ctx, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(bytes(data_key_plain)).encrypt(nonce, plaintext, aad)

    return {
        "key_encrypted_b64": base64.b64encode(bytes(encrypted_data_key)).decode("utf-8"),
        "secret_ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "aad_b64": base64.b64encode(aad).decode("utf-8"),
        "kms_key_id": key_id,
        "encrypted_at_utc": _utc_now_iso(),
    }


def decrypt_token_payload(*, encrypted: Dict[str, Any], user_sub: str, connection_id: str) -> Dict[str, Any]:
    kms = kms_client()
    ctx = _encryption_context(user_sub=user_sub, connection_id=connection_id)

    try:
        key_ct = base64.b64decode(str(encrypted.get("key_encrypted_b64") or ""))
        nonce = base64.b64decode(str(encrypted.get("nonce_b64") or ""))
        aad = base64.b64decode(str(encrypted.get("aad_b64") or ""))
        secret_ct = base64.b64decode(str(encrypted.get("secret_ciphertext_b64") or ""))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid encrypted token payload") from exc

    data_key_resp = kms.decrypt(CiphertextBlob=key_ct, EncryptionContext=ctx)
    data_key_plain = data_key_resp.get("Plaintext")
    if not isinstance(data_key_plain, (bytes, bytearray)):
        raise HTTPException(status_code=500, detail="failed to decrypt data key")

    try:
        plaintext = AESGCM(bytes(data_key_plain)).decrypt(nonce, secret_ct, aad)
        parsed = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid encrypted token payload") from exc

    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="invalid encrypted token payload")
    return parsed


def rotate_encrypted_token_payload(*, encrypted: Dict[str, Any], user_sub: str, connection_id: str) -> Dict[str, str]:
    payload = decrypt_token_payload(encrypted=encrypted, user_sub=user_sub, connection_id=connection_id)
    return encrypt_token_payload(payload=payload, user_sub=user_sub, connection_id=connection_id)
