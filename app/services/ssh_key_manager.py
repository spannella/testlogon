"""SSH key management -- generate, store (KMS-encrypted), retrieve, and associate with hosts."""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import uuid
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, dsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from boto3.dynamodb.conditions import Key

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Forward an SSH key lifecycle event to the platform audit trail.

    Mirrors the ``_audit`` wrapper in ``app/services/host_inventory.py``: it is
    fire-and-forget and never raises, so an audit/telemetry failure can never
    break the underlying key operation. The import is local to avoid a circular
    import with ``app.services.alerts``.
    """
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, **fields)
    except Exception:  # pragma: no cover - audit must never break the caller
        logger.debug("audit_event failed for %s", event, exc_info=True)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_fingerprint(public_key_openssh: str) -> str:
    """Compute SHA256 fingerprint from an OpenSSH public key string."""
    parts = public_key_openssh.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid OpenSSH public key format")
    key_data = base64.b64decode(parts[1])
    digest = hashlib.sha256(key_data).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _detect_key_type_and_bits(private_key_obj: Any) -> tuple[str, int]:
    """Detect key type and bit size from a loaded private key object."""
    if isinstance(private_key_obj, RSAPrivateKey):
        return "rsa", private_key_obj.key_size
    elif isinstance(private_key_obj, Ed25519PrivateKey):
        return "ed25519", 256
    elif isinstance(private_key_obj, EllipticCurvePrivateKey):
        return "ecdsa", private_key_obj.key_size
    elif isinstance(private_key_obj, DSAPrivateKey):
        return "dss", private_key_obj.key_size
    else:
        raise ValueError(f"Unsupported key type: {type(private_key_obj).__name__}")


def _load_private_key(pem: str, passphrase: Optional[str] = None):
    """Load a private key from PEM. Returns the key object.

    Supports both the classic PEM formats (PKCS#1 / PKCS#8 / TraditionalOpenSSL,
    e.g. ``-----BEGIN RSA PRIVATE KEY-----``) and the modern OpenSSH private key
    format (``-----BEGIN OPENSSH PRIVATE KEY-----``). The latter is what
    ``ssh-keygen`` and ``cryptography``'s ``PrivateFormat.OpenSSH`` produce by
    default, and it is NOT parseable by ``load_pem_private_key`` -- it requires
    ``load_ssh_private_key``.
    """
    pem_bytes = pem.encode("utf-8")
    pw = passphrase.encode("utf-8") if passphrase else None

    if "BEGIN OPENSSH PRIVATE KEY" in pem:
        try:
            return serialization.load_ssh_private_key(pem_bytes, password=pw)
        except TypeError:
            # Raised when key is password-protected but no password was given
            raise ValueError("Passphrase required for this key")
        except ValueError as exc:
            # Wrong passphrase / corrupt key
            msg = str(exc)
            if "password" in msg.lower() or "passphrase" in msg.lower():
                raise ValueError("Passphrase required for this key")
            raise ValueError(f"Invalid private key format: {exc}")
        except Exception as exc:
            raise ValueError(f"Invalid private key format: {exc}")

    try:
        return serialization.load_pem_private_key(pem_bytes, password=pw)
    except TypeError:
        # Raised when key requires passphrase but none given
        raise ValueError("Passphrase required for this key")
    except Exception as exc:
        raise ValueError(f"Invalid private key format: {exc}")


def _serialize_private_key_pem(private_key_obj: Any) -> str:
    """Serialize a private key to PEM format (unencrypted -- KMS handles encryption)."""
    pem_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem_bytes.decode("utf-8")


def _serialize_public_key_openssh(private_key_obj: Any) -> str:
    """Get public key in OpenSSH format from a private key object."""
    pub_bytes = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return pub_bytes.decode("utf-8")


def _item_to_metadata(item: Dict[str, Any]) -> Dict[str, Any]:
    """Strip private key blob from DDB item, convert Decimals to int."""
    out = {}
    skip = {"encrypted_private_key_blob"}
    for k, v in item.items():
        if k in skip:
            continue
        if hasattr(v, "__int__") and not isinstance(v, (str, bool)):
            out[k] = int(v)
        elif isinstance(v, list):
            out[k] = list(v)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_key(
    user_sub: str,
    *,
    label: str,
    key_type: str = "ed25519",
    key_bits: int = 4096,
) -> Dict[str, Any]:
    """Generate a new SSH key pair. Store encrypted private key in DDB.
    Returns key metadata + public key (private key is never returned)."""
    # Enforce per-user limit
    existing = list_keys(user_sub)
    if len(existing) >= S.ssh_key_max_per_user:
        raise KeyLimitExceeded(f"Maximum SSH keys reached ({S.ssh_key_max_per_user})")

    if key_type == "ed25519":
        private_key_obj = ed25519.Ed25519PrivateKey.generate()
        bits = 256
    elif key_type == "rsa":
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_bits,
        )
        bits = key_bits
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    pem_str = _serialize_private_key_pem(private_key_obj)
    pub_str = _serialize_public_key_openssh(private_key_obj)
    fingerprint = _compute_fingerprint(pub_str)
    encrypted_blob = kms_encrypt(pem_str)

    key_id = uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": f"KEY#{key_id}",
        "key_id": key_id,
        "label": label,
        "key_type": key_type,
        "key_bits": bits,
        "public_key_openssh": pub_str,
        "public_key_fingerprint": fingerprint,
        "encrypted_private_key_blob": encrypted_blob,
        "passphrase_protected": False,
        "created_at": ts,
        "last_used_at": 0,
        "associated_hosts": [],
        "use_count": 0,
    }
    T.ssh_keys.put_item(Item=item)

    logger.info("key_generated user_sub=%s key_id=%s key_type=%s bits=%d", user_sub, key_id, key_type, bits)
    _audit("ssh_key.generate", user_sub, key_id=key_id, key_type=key_type, key_bits=bits)

    return _item_to_metadata(item)


def upload_key(
    user_sub: str,
    *,
    label: str,
    private_key_pem: str,
    passphrase: Optional[str] = None,
) -> Dict[str, Any]:
    """Upload an existing private key. Validate, extract public key + fingerprint,
    encrypt with KMS, store in DDB. Returns key metadata + public key."""
    # Enforce per-user limit
    existing = list_keys(user_sub)
    if len(existing) >= S.ssh_key_max_per_user:
        raise KeyLimitExceeded(f"Maximum SSH keys reached ({S.ssh_key_max_per_user})")

    private_key_obj = _load_private_key(private_key_pem, passphrase)
    key_type, bits = _detect_key_type_and_bits(private_key_obj)

    # Re-serialize without passphrase so stored PEM is clean
    pem_str = _serialize_private_key_pem(private_key_obj)
    pub_str = _serialize_public_key_openssh(private_key_obj)
    fingerprint = _compute_fingerprint(pub_str)
    encrypted_blob = kms_encrypt(pem_str)

    key_id = uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": f"KEY#{key_id}",
        "key_id": key_id,
        "label": label,
        "key_type": key_type,
        "key_bits": bits,
        "public_key_openssh": pub_str,
        "public_key_fingerprint": fingerprint,
        "encrypted_private_key_blob": encrypted_blob,
        "passphrase_protected": passphrase is not None,
        "created_at": ts,
        "last_used_at": 0,
        "associated_hosts": [],
        "use_count": 0,
    }
    T.ssh_keys.put_item(Item=item)

    logger.info(
        "key_uploaded user_sub=%s key_id=%s key_type=%s bits=%d passphrase_protected=%s",
        user_sub, key_id, key_type, bits, passphrase is not None,
    )
    _audit(
        "ssh_key.upload", user_sub, key_id=key_id, key_type=key_type,
        key_bits=bits, passphrase_protected=passphrase is not None,
    )

    return _item_to_metadata(item)


def get_key_metadata(user_sub: str, key_id: str) -> Optional[Dict[str, Any]]:
    """Return key metadata (no private key). Includes public key and fingerprint."""
    resp = T.ssh_keys.get_item(Key={"user_sub": user_sub, "sk": f"KEY#{key_id}"})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_metadata(item)


def list_keys(user_sub: str) -> List[Dict[str, Any]]:
    """List all keys for a user (metadata only, no private keys)."""
    resp = T.ssh_keys.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub) & Key("sk").begins_with("KEY#"),
    )
    items = resp.get("Items", [])
    return [_item_to_metadata(item) for item in items]


def delete_key(user_sub: str, key_id: str) -> bool:
    """Delete a key. Returns True if deleted."""
    # First check ownership
    meta = get_key_metadata(user_sub, key_id)
    if not meta:
        return False

    T.ssh_keys.delete_item(Key={"user_sub": user_sub, "sk": f"KEY#{key_id}"})

    logger.info("key_deleted user_sub=%s key_id=%s", user_sub, key_id)
    _audit("ssh_key.delete", user_sub, key_id=key_id)
    return True


def get_decrypted_private_key(user_sub: str, key_id: str) -> Optional[str]:
    """Decrypt and return private key PEM. INTERNAL USE ONLY -- called by SSH bridge,
    never exposed via API."""
    resp = T.ssh_keys.get_item(Key={"user_sub": user_sub, "sk": f"KEY#{key_id}"})
    item = resp.get("Item")
    if not item:
        return None

    encrypted_blob = item.get("encrypted_private_key_blob")
    if not encrypted_blob:
        return None

    pem_bytes = kms_decrypt(encrypted_blob)
    pem_str = pem_bytes.decode("utf-8") if isinstance(pem_bytes, bytes) else pem_bytes

    # Update usage stats
    ts = now_ts()
    use_count = int(item.get("use_count", 0))
    T.ssh_keys.update_item(
        Key={"user_sub": user_sub, "sk": f"KEY#{key_id}"},
        UpdateExpression="SET last_used_at = :ts, use_count = :uc",
        ExpressionAttributeValues={":ts": ts, ":uc": use_count + 1},
    )

    logger.info("key_decrypted user_sub=%s key_id=%s", user_sub, key_id)
    _audit("ssh_key.decrypt", user_sub, key_id=key_id)
    return pem_str


def associate_key_with_host(user_sub: str, key_id: str, host_id: str) -> bool:
    """Link a key to a host. Updates the key's associated_hosts list.
    Returns True on success, False if key not found."""
    meta = get_key_metadata(user_sub, key_id)
    if not meta:
        return False

    hosts = list(meta.get("associated_hosts", []))
    if host_id not in hosts:
        hosts.append(host_id)

    T.ssh_keys.update_item(
        Key={"user_sub": user_sub, "sk": f"KEY#{key_id}"},
        UpdateExpression="SET associated_hosts = :hosts",
        ExpressionAttributeValues={":hosts": hosts},
    )

    logger.info("key_associated user_sub=%s key_id=%s host_id=%s", user_sub, key_id, host_id)
    _audit("ssh_key.associate", user_sub, key_id=key_id, host_id=host_id)
    return True


def disassociate_key_from_host(user_sub: str, key_id: str, host_id: str) -> bool:
    """Unlink a key from a host. Returns True on success."""
    meta = get_key_metadata(user_sub, key_id)
    if not meta:
        return False

    hosts = [h for h in meta.get("associated_hosts", []) if h != host_id]

    T.ssh_keys.update_item(
        Key={"user_sub": user_sub, "sk": f"KEY#{key_id}"},
        UpdateExpression="SET associated_hosts = :hosts",
        ExpressionAttributeValues={":hosts": hosts},
    )

    logger.info("key_disassociated user_sub=%s key_id=%s host_id=%s", user_sub, key_id, host_id)
    _audit("ssh_key.disassociate", user_sub, key_id=key_id, host_id=host_id)
    return True


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class KeyLimitExceeded(Exception):
    """Raised when user has reached the maximum number of SSH keys."""
    pass
