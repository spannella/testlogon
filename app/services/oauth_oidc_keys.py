"""OAU-003: OIDC signing-key lifecycle — RSA-2048 keypair, JWKS, id_token signing.

The private key is KMS-encrypted at rest. The public key is cached in-process.
No dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

import base64
import secrets
from typing import Any, Dict, List, Optional

from app.core.crypto import kms_decrypt, kms_encrypt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# In-process cache for public signing-key metadata (never stores decrypted private key)
_KEY_CACHE: Optional[Dict[str, Any]] = None

# Sentinel partition key for the OIDC signing-key row
_OIDC_KEY_PK = "OIDC_SIGNING_KEY"
_OIDC_KEY_SK = "META"


def _generate_rsa_keypair() -> tuple:
    """Generate RSA-2048 keypair. Returns (private_key_pem_str, public_key_pem_str, n_b64url, e_b64url, kid)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from app.core.crypto import b64url

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, "public_key") else public_key.public_numbers()
    # n and e as big-endian bytes → base64url
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
    n_b64 = b64url(n_bytes)
    e_b64 = b64url(e_bytes)
    kid = secrets.token_hex(8)
    return private_pem, public_pem, n_b64, e_b64, kid


def _generate_and_store_signing_key() -> Dict[str, Any]:
    """Generate RSA keypair, KMS-encrypt private key, store in DDB. Race-safe."""
    private_pem, public_pem, n_b64, e_b64, kid = _generate_rsa_keypair()
    private_key_ct_b64 = kms_encrypt(private_pem)
    ts = now_ts()
    item: Dict[str, Any] = {
        "client_id": _OIDC_KEY_PK,
        "sk": _OIDC_KEY_SK,
        "kid": kid,
        "alg": "RS256",
        "private_key_ct_b64": private_key_ct_b64,
        "public_key_pem": public_pem,
        "public_key_jwk_n": n_b64,
        "public_key_jwk_e": e_b64,
        "created_at": ts,
        "rotated_at": ts,
    }
    try:
        T.oauth_consumers.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(client_id)",
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailedException" in str(exc):
            # Another process won; read the existing row
            resp = T.oauth_consumers.get_item(Key={"client_id": _OIDC_KEY_PK, "sk": _OIDC_KEY_SK})
            item = resp.get("Item") or {}
        else:
            raise
    return item


def get_or_create_oidc_signing_key() -> Dict[str, Any]:
    """Return the public signing-key metadata dict (no decrypted PEM). Creates on first call."""
    global _KEY_CACHE
    if _KEY_CACHE is not None:
        return _KEY_CACHE
    resp = T.oauth_consumers.get_item(Key={"client_id": _OIDC_KEY_PK, "sk": _OIDC_KEY_SK})
    item = resp.get("Item")
    if not item:
        item = _generate_and_store_signing_key()
    # Cache only public fields
    _KEY_CACHE = {k: v for k, v in item.items() if k != "private_key_ct_b64"}
    return _KEY_CACHE


def get_public_jwks() -> Dict[str, Any]:
    """Return the public JWKS document {"keys": [...]}."""
    meta = get_or_create_oidc_signing_key()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": meta["kid"],
        "n": meta["public_key_jwk_n"],
        "e": meta["public_key_jwk_e"],
    }
    return {"keys": [jwk]}


def sign_id_token(payload: Dict[str, Any]) -> str:
    """Decrypt private key from DDB/KMS, sign payload with RS256, return compact JWT."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    # Fetch meta (to get kid + private_key_ct_b64)
    resp = T.oauth_consumers.get_item(Key={"client_id": _OIDC_KEY_PK, "sk": _OIDC_KEY_SK})
    item = resp.get("Item") or {}
    if not item:
        raise RuntimeError("OIDC signing key not found")
    kid = item["kid"]
    ct_b64 = item["private_key_ct_b64"]
    private_pem_bytes = kms_decrypt(ct_b64)
    private_key = load_pem_private_key(private_pem_bytes, password=None)
    token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})
    # Ensure string (PyJWT >=2 returns str, <2 returns bytes)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    # Clear reference to private key bytes
    del private_pem_bytes
    del private_key
    return token


def build_id_token(
    owner_user_sub: str,
    client_id: str,
    granted_scopes: List[str],
    nonce: Optional[str] = None,
    *,
    user_item: Optional[Dict[str, Any]] = None,
) -> str:
    """Build and sign an OIDC id_token for the given owner/client/scopes."""
    scope_set = set(granted_scopes)
    if "openid" not in scope_set:
        raise ValueError("openid must be in granted_scopes")

    # Fetch user from T.users if not provided
    if user_item is None:
        try:
            resp = T.users.get_item(Key={"user_sub": owner_user_sub})
            user_item = resp.get("Item") or {}
        except Exception:
            user_item = {}

    now = now_ts()
    ttl = getattr(S, "oidc_id_token_ttl_seconds", 3600)
    issuer = getattr(S, "oidc_issuer_url", "") or getattr(S, "public_base_url", "http://localhost:8000")

    payload: Dict[str, Any] = {
        "iss": issuer,
        "sub": owner_user_sub,
        "aud": client_id,
        "exp": now + ttl,
        "iat": now,
        "auth_time": now,  # fallback to iat per OIDC §2
    }
    if nonce:
        payload["nonce"] = nonce

    if "email" in scope_set:
        email = user_item.get("email")
        if email:
            payload["email"] = email
        payload["email_verified"] = bool(user_item.get("email_verified", False))

    if "profile" in scope_set:
        name = user_item.get("profile_name") or user_item.get("display_name") or user_item.get("name")
        if name:
            payload["name"] = name
        given = user_item.get("first_name") or user_item.get("given_name")
        if given:
            payload["given_name"] = given
        family = user_item.get("last_name") or user_item.get("family_name")
        if family:
            payload["family_name"] = family

    return sign_id_token(payload)
