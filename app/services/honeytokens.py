"""Honeytoken issuance + matching service (HNY-004 / HNY-006).

DEFENSIVE-only. Mints decoy credentials that look exactly like real ones but
live in an ISOLATED store (``T.honeytokens``), never in ``T.api_keys``. When a
decoy is presented to the API-key chokepoint (HNY-005) or a marked canary row
is read (HNY-006), a high/critical security event is recorded.

Three kinds:
  * ``api_key``          — a real-shaped ``ak_<kid>.<secret>`` key whose
                           ``secret`` hash + ``key_id`` are stored (hash only;
                           plaintext returned once).
  * ``credential_record`` — a decoy username/password pair.
  * ``canary_row``        — a marked data-row id that, when read, matches back.

All rows carry a ``lookup_hash`` for GSI-based matching.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.api_keys import api_key_hash, new_api_key_secret, parse_api_key

logger = logging.getLogger(__name__)

KINDS = ("api_key", "credential_record", "canary_row")
_LOOKUP_HASH_INDEX = "ByLookupHash"


def _new_token_id() -> str:
    return "ht_" + uuid.uuid4().hex


def _new_key_id() -> str:
    # Same opaque shape as real api_keys key_id (hex).
    return uuid.uuid4().hex


def mint_honeytoken(
    *,
    kind: str,
    label: str,
    admin_sub: str,
    placement: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a honeytoken. Returns metadata + (for some kinds) plaintext ONCE.

    The plaintext secret is returned in the result but never persisted in
    plaintext (only its hash is stored), so it can never be retrieved again.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown honeytoken kind: {kind}")

    token_id = _new_token_id()
    ts = now_ts()
    item: Dict[str, Any] = {
        "token_id": token_id,
        "kind": kind,
        "label": str(label or ""),
        "created_by": str(admin_sub or ""),
        "created_at": ts,
        "retired": False,
        "placement": str(placement or ""),
    }
    result: Dict[str, Any] = {
        "token_id": token_id,
        "kind": kind,
        "label": item["label"],
        "created_at": ts,
        "placement": item["placement"],
    }

    if kind == "api_key":
        key_id = _new_key_id()
        secret = new_api_key_secret()
        secret_hash = api_key_hash(secret)
        plaintext = f"ak_{key_id}.{secret}"
        item["key_id"] = key_id
        item["secret_hash"] = secret_hash
        # lookup_hash == secret hash, so the trip-wire can resolve by GSI.
        item["lookup_hash"] = secret_hash
        result["api_key"] = plaintext  # returned ONCE
        result["key_id"] = key_id
    elif kind == "credential_record":
        username = f"svc_{secrets.token_hex(4)}"
        password = secrets.token_urlsafe(18)
        # Store only a hash of the password for matching; never plaintext.
        pw_hash = api_key_hash(password)
        item["decoy_username"] = username
        item["secret_hash"] = pw_hash
        item["lookup_hash"] = pw_hash
        result["username"] = username
        result["password"] = password  # returned ONCE
    elif kind == "canary_row":
        canary_id = "canary_" + uuid.uuid4().hex
        item["canary_id"] = canary_id
        item["lookup_hash"] = canary_id
        result["canary_id"] = canary_id

    T.honeytokens.put_item(Item=item)

    try:
        from app.services.alerts import audit_event

        audit_event(
            "honeytoken.mint",
            admin_sub,
            outcome="info",
            token_id=token_id,
            honeytoken_kind=kind,
            label=item["label"],
        )
    except Exception:
        logger.debug("honeytokens: mint audit failed", exc_info=True)

    return result


def get_honeytoken(token_id: str) -> Optional[Dict[str, Any]]:
    try:
        return T.honeytokens.get_item(Key={"token_id": token_id}).get("Item")
    except Exception:
        return None


def list_honeytokens(*, include_retired: bool = True) -> List[Dict[str, Any]]:
    """List honeytoken metadata. NEVER echoes secret hashes/plaintext."""
    items: List[Dict[str, Any]] = []
    try:
        resp = T.honeytokens.scan()
        items = resp.get("Items", []) or []
        while resp.get("LastEvaluatedKey"):
            resp = T.honeytokens.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []) or [])
    except Exception:
        return []
    out = []
    for it in items:
        if not include_retired and it.get("retired"):
            continue
        out.append(_public_view(it))
    out.sort(key=lambda r: r.get("created_at", 0), reverse=True)
    return out


def _public_view(it: Dict[str, Any]) -> Dict[str, Any]:
    """Strip all secret material from a stored row."""
    return {
        "token_id": it.get("token_id"),
        "kind": it.get("kind"),
        "label": it.get("label", ""),
        "created_by": it.get("created_by", ""),
        "created_at": int(it.get("created_at") or 0),
        "retired": bool(it.get("retired", False)),
        "placement": it.get("placement", ""),
        "key_id": it.get("key_id", ""),
        "decoy_username": it.get("decoy_username", ""),
        "canary_id": it.get("canary_id", ""),
    }


def retire_honeytoken(token_id: str) -> bool:
    try:
        T.honeytokens.update_item(
            Key={"token_id": token_id},
            UpdateExpression="SET retired = :t, retired_at = :now",
            ConditionExpression="attribute_exists(token_id)",
            ExpressionAttributeValues={":t": True, ":now": now_ts()},
        )
        return True
    except Exception:
        return False


def match_api_key(key_id: str, secret: str) -> Optional[Dict[str, Any]]:
    """Return the honeytoken row iff (key_id, secret) matches an api_key decoy.

    Used by the HNY-005 trip-wire. Resolves by the secret hash via the
    ByLookupHash GSI, then verifies the ``key_id`` matches to avoid hash
    collisions across kinds. Returns None on any miss/error (never raises).
    """
    if not key_id or not secret:
        return None
    try:
        lookup = api_key_hash(secret)
    except Exception:
        return None
    try:
        resp = T.honeytokens.query(
            IndexName=_LOOKUP_HASH_INDEX,
            KeyConditionExpression=Key("lookup_hash").eq(lookup),
        )
    except Exception:
        return None
    for it in resp.get("Items", []) or []:
        if it.get("kind") != "api_key":
            continue
        if it.get("retired"):
            continue
        if str(it.get("key_id") or "") == str(key_id):
            return it
    return None


def match_api_key_raw(api_key: str) -> Optional[Dict[str, Any]]:
    """Convenience: parse a raw ``ak_...`` key then match. None on bad format."""
    try:
        parsed = parse_api_key(api_key)
    except Exception:
        return None
    return match_api_key(parsed.get("key_id", ""), parsed.get("secret", ""))


def match_canary(canary_id: str) -> Optional[Dict[str, Any]]:
    """Return the honeytoken row for a canary_id, or None. Cheap GSI lookup."""
    if not canary_id:
        return None
    try:
        resp = T.honeytokens.query(
            IndexName=_LOOKUP_HASH_INDEX,
            KeyConditionExpression=Key("lookup_hash").eq(canary_id),
        )
    except Exception:
        return None
    for it in resp.get("Items", []) or []:
        if it.get("kind") == "canary_row" and not it.get("retired"):
            return it
    return None


def note_canary_access(canary_id: str, *, user_sub: str = "", request: Any = None) -> Optional[str]:
    """HNY-006: record a high-severity event when a marked canary row is read.

    Best-effort + flag-gated (``S.honeytoken_enabled``). Reading a non-canary id
    is a cheap GSI miss and fires nothing. Future high-value read paths can opt
    in with a single line::

        from app.services import honeytokens
        honeytokens.note_canary_access(row_id, user_sub=sub, request=request)
    """
    if not S.honeytoken_enabled:
        return None
    ht = match_canary(canary_id)
    if not ht:
        return None
    try:
        from app.services import security_events

        return security_events.safe_record(
            kind="canary_row_access",
            severity="high",
            user_sub=user_sub,
            request=request,
            token_id=ht.get("token_id", ""),
            canary_id=canary_id,
            label=ht.get("label", ""),
        )
    except Exception:
        return None
