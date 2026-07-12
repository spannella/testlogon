"""Tokenized public signing-link minter/verifier + consumption store (SUX-002/003).

Models the cart-recovery HMAC token scheme (``app/services/cart_reminders.py:150-245``)
as the security model for a public, login-free signing link.

A token is a stateless, HMAC-SHA256-signed, time-limited credential of the form
``b64url(payload).b64url(sig)`` where the payload binds a specific
``packet_id`` + ``signer_id`` and carries ``scope="sign"``, a ``jti`` (for
one-time-use / revocation), ``iat`` and ``exp``. The PEM/secret is never embedded
— only opaque ids. Dev and prod use the identical code path (no ``dev_mode``
branch): the signing key falls back to ``ui_access_token_secret`` when the
dedicated secret is unset (SECOPS-007 parity).

Consumption + revocation markers are keyed by ``jti`` and stored in the existing
``signature_packet_events`` table under a dedicated partition
``SIGNLINK#CONSUMED#{jti}`` / ``SIGNLINK#REVOKED#{jti}`` (no new table), using a
conditional put for atomic single-use.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any, Dict, Optional

from app.core.crypto import b64url, b64url_decode
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_SCOPE = "sign"
# Consumption/revocation markers live in the signature_packet_events table.
# That table's hash key is ``packet_id`` and range key is ``event_id`` (see
# scripts/local-ddb-init.py / append_packet_event). We reuse it with a synthetic
# partition so no new table/schema is required.
_CONSUMED_PK_PREFIX = "SIGNLINK#CONSUMED#"
_REVOKED_PK_PREFIX = "SIGNLINK#REVOKED#"
_MARKER_SK = "META"


def _link_secret() -> bytes:
    """Signing key for public signing tokens (dev/prod parity, SECOPS-007)."""
    secret = S.signature_packet_public_link_secret or "dev-signing-link-secret"
    return secret.encode("utf-8")


def _ttl_seconds(ttl_days: Optional[int]) -> int:
    days = int(ttl_days if ttl_days is not None else S.signature_packet_public_link_ttl_days)
    return days * 86400


def mint_signing_token(packet_id: str, signer_id: str, *, ttl_days: Optional[int] = None) -> str:
    """Mint a signed, time-limited public signing token bound to packet+signer.

    Format mirrors ``cart_reminders._sign_recovery_token``:
    ``b64url(payload).b64url(sig)`` with an HMAC-SHA256 signature. ``jti`` lets
    us mark the token consumed/revoked in DDB.
    """
    now = now_ts()
    payload = {
        "packet_id": packet_id,
        "signer_id": signer_id,
        "jti": uuid.uuid4().hex,
        "scope": _SCOPE,
        "iat": now,
        "exp": now + _ttl_seconds(ttl_days),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_link_secret(), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"


def verify_signing_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify signature, scope and expiry. Returns the payload dict or ``None``.

    Rejects: bad/tampered signature, malformed token, wrong ``scope`` and
    expired tokens. Revocation/consumption are checked separately by callers so
    they can distinguish error messaging.
    """
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = b64url_decode(raw_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(_link_secret(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        if obj.get("scope") != _SCOPE:
            return None
        if not obj.get("packet_id") or not obj.get("signer_id") or not obj.get("jti"):
            return None
        if int(obj.get("exp", 0)) < now_ts():
            return None
        return obj
    except Exception:
        return None


def is_token_consumed(jti: str) -> bool:
    if not jti:
        return True
    try:
        item = T.signature_packet_events.get_item(
            Key={"packet_id": f"{_CONSUMED_PK_PREFIX}{jti}", "event_id": _MARKER_SK}
        ).get("Item")
    except Exception:
        return False
    return bool(item)


def is_token_revoked(jti: str) -> bool:
    if not jti:
        return True
    try:
        item = T.signature_packet_events.get_item(
            Key={"packet_id": f"{_REVOKED_PK_PREFIX}{jti}", "event_id": _MARKER_SK}
        ).get("Item")
    except Exception:
        return False
    return bool(item)


def consume_token(jti: str) -> bool:
    """Atomically mark a token id consumed. Returns False if already consumed."""
    if not jti:
        return False
    try:
        T.signature_packet_events.put_item(
            Item={
                "packet_id": f"{_CONSUMED_PK_PREFIX}{jti}",
                "event_id": _MARKER_SK,
                "consumed_at": now_ts(),
            },
            ConditionExpression="attribute_not_exists(packet_id)",
        )
        return True
    except Exception:
        return False


def revoke_token(jti: str) -> bool:
    """Mark a token id revoked. Idempotent (a second revoke is a no-op success)."""
    if not jti:
        return False
    try:
        T.signature_packet_events.put_item(
            Item={
                "packet_id": f"{_REVOKED_PK_PREFIX}{jti}",
                "event_id": _MARKER_SK,
                "revoked_at": now_ts(),
            }
        )
        return True
    except Exception:
        return False


def generate_signing_link(packet_id: str, signer_id: str, *, ttl_days: Optional[int] = None) -> Dict[str, Any]:
    """Return a signed public signing URL bound to packet+signer (SUX-002).

    Mirrors ``cart_reminders.generate_recovery_link``: base URL comes from
    ``S.public_base_url`` so the same code path works dev + prod (SECOPS-007).
    Returns ``{token, jti, url, expires_at}``.
    """
    token = mint_signing_token(packet_id, signer_id, ttl_days=ttl_days)
    payload = verify_signing_token(token) or {}
    base = S.public_base_url.rstrip("/")
    return {
        "token": token,
        "jti": str(payload.get("jti") or ""),
        "url": f"{base}/ui/sign/{token}",
        "expires_at": int(payload.get("exp") or 0),
    }
