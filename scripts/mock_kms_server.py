#!/usr/bin/env python3
"""Minimal AWS KMS-compatible mock server for local development.

Implements the operations used by this app:
  CreateKey, CreateAlias, DescribeKey, ListAliases, Encrypt, Decrypt

Key material is persisted to STATE_FILE (.local/run/kms-state.json) so keys and
their encrypted data survive process restarts.  The file is intentionally NOT
wiped on clean dev-stack restarts so that any already-encrypted DynamoDB records
can still be decrypted after a restart.

Usage:
    python3 scripts/mock_kms_server.py          # port 7999 (default)
    MOCK_KMS_PORT=7999 python3 scripts/mock_kms_server.py
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("MOCK_KMS_PORT", "7999"))
REGION = os.environ.get("AWS_REGION", "us-east-1")
ACCOUNT_ID = "000000000000"
STATE_FILE = Path(
    os.environ.get("MOCK_KMS_STATE_FILE", ".local/run/kms-state.json")
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [kms] %(message)s")
log = logging.getLogger("mock-kms")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Persistent state helpers
# ---------------------------------------------------------------------------

def _load_state() -> Dict[str, Any]:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"keys": {}, "aliases": {}}


def _save_state(state: Dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _arn(key_id: str) -> str:
    return f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/{key_id}"


def _resolve_key_id(state: Dict[str, Any], key_id_or_alias: str) -> Optional[str]:
    """Return the raw UUID key ID for an alias, ARN, or raw key ID; None if not found."""
    if key_id_or_alias.startswith("alias/"):
        return state["aliases"].get(key_id_or_alias)
    # Strip ARN prefix if present
    if "/" in key_id_or_alias:
        key_id_or_alias = key_id_or_alias.split("/")[-1]
    return key_id_or_alias if key_id_or_alias in state["keys"] else None


def _key_metadata(key: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "KeyId": key["key_id"],
        "Arn": key["arn"],
        "Description": key.get("description", ""),
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Enabled": True,
        "CreationDate": key.get("created_at", 0),
        "KeySpec": "SYMMETRIC_DEFAULT",
        "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
    }


# ---------------------------------------------------------------------------
# Encryption helpers (AES-256-GCM)
# ---------------------------------------------------------------------------

def _encrypt_bytes(key_material_b64: str, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Return (nonce, ciphertext)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(base64.b64decode(key_material_b64))
    return nonce, aesgcm.encrypt(nonce, plaintext, None)


def _decrypt_bytes(key_material_b64: str, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(base64.b64decode(key_material_b64))
    return aesgcm.decrypt(nonce, ciphertext, None)


def _pack_blob(key_id: str, nonce: bytes, ciphertext: bytes) -> str:
    """Encode key_id + nonce + ciphertext into a base64 CiphertextBlob."""
    payload = json.dumps(
        {
            "k": key_id,
            "n": base64.b64encode(nonce).decode(),
            "c": base64.b64encode(ciphertext).decode(),
        },
        separators=(",", ":"),
    )
    return base64.b64encode(payload.encode()).decode()


def _unpack_blob(blob_b64: str) -> Tuple[str, bytes, bytes]:
    """Return (key_id, nonce, ciphertext); raises ValueError on bad input."""
    try:
        payload = json.loads(base64.b64decode(blob_b64))
        return payload["k"], base64.b64decode(payload["n"]), base64.b64decode(payload["c"])
    except Exception as exc:
        raise ValueError("Malformed CiphertextBlob") from exc


# ---------------------------------------------------------------------------
# KMS operation handlers
# ---------------------------------------------------------------------------
# Each handler returns (response_dict, error_dict_or_None).
# A non-None error_dict is returned as HTTP 400.

Err = Optional[Dict[str, str]]
Resp = Optional[Dict[str, Any]]


def op_create_key(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    key_id = str(uuid.uuid4())
    key_material = base64.b64encode(os.urandom(32)).decode()
    key: Dict[str, Any] = {
        "key_id": key_id,
        "arn": _arn(key_id),
        "description": body.get("Description", ""),
        "key_material": key_material,
        "created_at": time.time(),
    }
    state["keys"][key_id] = key
    _save_state(state)
    log.info("CreateKey → %s", key_id)
    return {"KeyMetadata": _key_metadata(key)}, None


def op_create_alias(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    alias = body.get("AliasName", "")
    target = body.get("TargetKeyId", "")
    resolved = _resolve_key_id(state, target)
    if not resolved:
        return None, {"__type": "NotFoundException", "message": f"Key '{target}' does not exist"}
    state["aliases"][alias] = resolved
    _save_state(state)
    log.info("CreateAlias %s → %s", alias, resolved)
    return {}, None


def op_describe_key(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    key_id_in = body.get("KeyId", "")
    resolved = _resolve_key_id(state, key_id_in)
    if not resolved or resolved not in state["keys"]:
        return None, {"__type": "NotFoundException", "message": f"Key '{key_id_in}' does not exist"}
    return {"KeyMetadata": _key_metadata(state["keys"][resolved])}, None


def op_list_aliases(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    aliases = [
        {
            "AliasName": name,
            "TargetKeyId": kid,
            "AliasArn": f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:{name}",
        }
        for name, kid in state["aliases"].items()
    ]
    return {"Aliases": aliases, "Truncated": False}, None


def op_encrypt(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    key_id_in = body.get("KeyId", "")
    resolved = _resolve_key_id(state, key_id_in)
    if not resolved or resolved not in state["keys"]:
        return None, {"__type": "NotFoundException", "message": f"Key '{key_id_in}' does not exist"}
    plaintext = base64.b64decode(body.get("Plaintext", ""))
    key = state["keys"][resolved]
    nonce, ct = _encrypt_bytes(key["key_material"], plaintext)
    blob = _pack_blob(resolved, nonce, ct)
    log.info("Encrypt with key %s (%d bytes)", resolved[:8], len(plaintext))
    return {
        "KeyId": key["arn"],
        "CiphertextBlob": blob,
        "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
    }, None


def op_decrypt(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    blob = body.get("CiphertextBlob", "")
    try:
        key_id, nonce, ciphertext = _unpack_blob(blob)
    except ValueError:
        return None, {"__type": "InvalidCiphertextException", "message": "Invalid ciphertext format"}
    if key_id not in state["keys"]:
        return None, {"__type": "NotFoundException", "message": f"Key '{key_id}' does not exist"}
    try:
        plaintext = _decrypt_bytes(state["keys"][key_id]["key_material"], nonce, ciphertext)
    except Exception:
        return None, {"__type": "InvalidCiphertextException", "message": "Decryption failed"}
    log.info("Decrypt with key %s (%d bytes)", key_id[:8], len(plaintext))
    return {
        "KeyId": state["keys"][key_id]["arn"],
        "Plaintext": base64.b64encode(plaintext).decode(),
        "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
    }, None


def op_generate_data_key(state: Dict, body: Dict) -> Tuple[Resp, Err]:
    key_id_in = body.get("KeyId", "")
    resolved = _resolve_key_id(state, key_id_in)
    if not resolved or resolved not in state["keys"]:
        return None, {"__type": "NotFoundException", "message": f"Key '{key_id_in}' does not exist"}

    key_spec = body.get("KeySpec", "AES_256")
    if key_spec == "AES_128":
        data_key_bytes = os.urandom(16)
    else:
        data_key_bytes = os.urandom(32)

    key = state["keys"][resolved]
    nonce, ct = _encrypt_bytes(key["key_material"], data_key_bytes)
    blob = _pack_blob(resolved, nonce, ct)

    log.info("GenerateDataKey with key %s (%s)", resolved[:8], key_spec)
    return {
        "KeyId": key["arn"],
        "Plaintext": base64.b64encode(data_key_bytes).decode(),
        "CiphertextBlob": blob,
    }, None


OPERATIONS = {
    "CreateKey": op_create_key,
    "CreateAlias": op_create_alias,
    "DescribeKey": op_describe_key,
    "ListAliases": op_list_aliases,
    "Encrypt": op_encrypt,
    "Decrypt": op_decrypt,
    "GenerateDataKey": op_generate_data_key,
}

# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/")
def kms_dispatch():
    target = request.headers.get("X-Amz-Target", "")
    # Header format: "TrentService.Encrypt"
    action = target.split(".")[-1] if "." in target else target

    handler = OPERATIONS.get(action)
    if not handler:
        return (
            jsonify({"__type": "UnsupportedOperationException", "message": f"Unknown action: {action}"}),
            400,
        )

    body = request.get_json(force=True, silent=True) or {}
    state = _load_state()
    resp, err = handler(state, body)

    if err:
        return jsonify(err), 400

    return jsonify(resp), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Mock KMS server starting on port %d", PORT)
    log.info("State file: %s", STATE_FILE.resolve())
    log.info("Loaded %d key(s), %d alias(es)", len(_load_state()["keys"]), len(_load_state()["aliases"]))
    app.run(host="0.0.0.0", port=PORT, debug=False)
