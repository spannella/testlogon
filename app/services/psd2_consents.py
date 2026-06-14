"""PSD2 AIS/PIS Consent lifecycle service (CSN-001 + CSN-002).

Covers:
  - Consent grant (create), status machine, revoke, expiry sweep
  - SCA gate: request_consent_sca / accept_consent
  - PIS consent: payment_ref, consent_authorizes_payment
  - rate_limit_consent lives in app/services/rate_limit.py (CSN-002 §4.3)
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ttl import with_ttl

VALID_VIEW_REFS: frozenset = frozenset({"owner", "accountant", "auditor", "public"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _item_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return item with numeric fields coerced from Decimal to int/float."""
    out: Dict[str, Any] = dict(item)
    for f in ("valid_from", "valid_until", "created_at", "updated_at", "revoked_at"):
        if f in out and out[f] is not None:
            try:
                out[f] = int(out[f])
            except (TypeError, ValueError):
                pass
    return out


def _consent_requires_sca(consent: Dict[str, Any]) -> bool:
    """Return True when this consent must pass SCA before becoming ACCEPTED."""
    if consent.get("consent_type") == "PIS":
        return True
    amount = int(consent.get("amount_hint_cents", 0) or 0)
    threshold = int(getattr(S, "psd2_consent_sca_threshold_cents", 0) or 0)
    return amount >= threshold


# ---------------------------------------------------------------------------
# Core CRUD
# ---------------------------------------------------------------------------

def create_consent(
    owner_sub: str,
    body: Any,  # ConsentCreateIn — avoid circular import
    req: Optional[Request],
) -> Dict[str, Any]:
    """Create a new AIS or PIS consent in INITIATED status."""
    # Validate account_refs
    if not body.account_refs:
        raise HTTPException(400, "account_refs must not be empty")

    # Validate view_refs
    view_refs = list(body.view_refs) if body.view_refs else ["owner"]
    for vr in view_refs:
        if vr not in VALID_VIEW_REFS:
            raise HTTPException(400, f"invalid view_ref: {vr}")

    # Validate PIS/AIS payment_ref consistency
    consent_type = body.consent_type or "AIS"
    payment_ref = getattr(body, "payment_ref", None)
    if consent_type == "PIS" and not payment_ref:
        raise HTTPException(400, "payment_ref_required")
    if consent_type == "AIS" and payment_ref:
        raise HTTPException(400, "payment_ref_not_allowed")

    # Compute valid_until (clamp silently)
    now = now_ts()
    max_until = now + S.psd2_consent_max_ttl_days * 86400
    if body.valid_until is not None:
        valid_until = min(int(body.valid_until), max_until)
    else:
        valid_until = now + S.psd2_consent_default_ttl_days * 86400

    consent_id = "csn_" + uuid.uuid4().hex
    item: Dict[str, Any] = {
        "owner_sub": owner_sub,
        "consent_id": consent_id,
        "consumer_ref": body.consumer_ref,
        "consent_type": consent_type,
        "account_refs": list(body.account_refs),
        "view_refs": view_refs,
        "status": "INITIATED",
        "valid_from": now,
        "valid_until": valid_until,
        "sca_challenge_id": None,
        "recurring": bool(body.recurring),
        "reason": getattr(body, "reason", None),
        "created_at": now,
        "updated_at": now,
        "revoked_at": None,
    }
    if payment_ref:
        item["payment_ref"] = payment_ref

    T.consents.put_item(Item=with_ttl(item, ttl_epoch=valid_until + 86400 * 7))

    try:
        from app.services.alerts import audit_event
        audit_event("consent.created", owner_sub, req, consent_id=consent_id, consumer_ref=body.consumer_ref)
    except Exception:
        pass

    return _item_to_dict(item)


def get_consent(owner_sub: str, consent_id: str) -> Optional[Dict[str, Any]]:
    """Load a consent by PK+SK; returns None for missing or foreign owner."""
    resp = T.consents.get_item(Key={"owner_sub": owner_sub, "consent_id": consent_id})
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_dict(item)


def list_consents_for_owner(
    owner_sub: str,
    *,
    status: Optional[str] = None,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List consents owned by this user, with optional status filter."""
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("owner_sub").eq(owner_sub),
        "Limit": limit,
    }
    if cursor:
        esk = decode_cursor(cursor)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    consents: List[Dict[str, Any]] = []
    last_key = None
    while True:
        resp = T.consents.query(**kwargs)
        for item in resp.get("Items", []):
            if status is None or item.get("status") == status:
                consents.append(_item_to_dict(item))
            if len(consents) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if last_key and len(consents) < limit:
            kwargs["ExclusiveStartKey"] = last_key
            kwargs.pop("Limit", None)
            kwargs["Limit"] = limit
        else:
            break

    return {
        "consents": consents[:limit],
        "cursor": encode_cursor(last_key) if last_key and len(consents) >= limit else None,
        "count": len(consents[:limit]),
    }


def list_consents_for_consumer(
    consumer_ref: str,
    *,
    status: Optional[str] = None,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List consents for a given consumer_ref via ByConsumer GSI."""
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": S.consents_consumer_index,
        "KeyConditionExpression": Key("consumer_ref").eq(consumer_ref),
        "Limit": limit,
    }
    if cursor:
        esk = decode_cursor(cursor)
        if esk:
            kwargs["ExclusiveStartKey"] = esk

    consents: List[Dict[str, Any]] = []
    last_key = None
    while True:
        resp = T.consents.query(**kwargs)
        for item in resp.get("Items", []):
            if status is None or item.get("status") == status:
                consents.append(_item_to_dict(item))
            if len(consents) >= limit:
                break
        last_key = resp.get("LastEvaluatedKey")
        if last_key and len(consents) < limit:
            kwargs["ExclusiveStartKey"] = last_key
        else:
            break

    return {
        "consents": consents[:limit],
        "cursor": encode_cursor(last_key) if last_key and len(consents) >= limit else None,
        "count": len(consents[:limit]),
    }


def revoke_consent(
    owner_sub: str,
    consent_id: str,
    req: Optional[Request] = None,
) -> Dict[str, Any]:
    """Revoke a consent (only from INITIATED or ACCEPTED). Returns updated item."""
    now = now_ts()
    try:
        T.consents.update_item(
            Key={"owner_sub": owner_sub, "consent_id": consent_id},
            UpdateExpression="SET #st = :r, revoked_at = :now, updated_at = :now",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":r": "REVOKED",
                ":now": now,
                ":i": "INITIATED",
                ":a": "ACCEPTED",
            },
            ConditionExpression="#st IN (:i, :a)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        # Check why the condition failed
        item = get_consent(owner_sub, consent_id)
        if item is None:
            raise HTTPException(404, "consent not found")
        raise HTTPException(409, "consent_already_terminal")

    try:
        from app.services.alerts import audit_event
        audit_event("consent.revoked", owner_sub, req, consent_id=consent_id)
    except Exception:
        pass

    item = get_consent(owner_sub, consent_id)
    if item is None:
        raise HTTPException(404, "consent not found")
    return item


def is_consent_valid(
    owner_sub: str,
    consent_id: str,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Return (True, item) iff the consent is ACCEPTED and not expired.

    Both owner_sub and consent_id are required (PK+SK lookup — no GSI supports
    lookup by consent_id alone without knowing owner_sub).
    """
    item = get_consent(owner_sub, consent_id)
    if not item:
        return (False, None)
    valid = item.get("status") == "ACCEPTED" and int(item.get("valid_until", 0)) > now_ts()
    return (valid, item)


def expire_due_consents() -> int:
    """Flip ACCEPTED consents with valid_until < now to EXPIRED. Returns count."""
    now = now_ts()
    resp = T.consents.query(
        IndexName=S.consents_status_index,
        KeyConditionExpression=Key("status").eq("ACCEPTED") & Key("valid_until").lt(now),
        Limit=100,
    )
    count = 0
    for item in resp.get("Items", []):
        try:
            T.consents.update_item(
                Key={"owner_sub": item["owner_sub"], "consent_id": item["consent_id"]},
                UpdateExpression="SET #st = :e, updated_at = :now",
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={":e": "EXPIRED", ":now": now, ":a": "ACCEPTED"},
                ConditionExpression="#st = :a",
            )
            try:
                from app.services.alerts import audit_event
                audit_event("consent.expired", item["owner_sub"], None,
                            consent_id=item["consent_id"])
            except Exception:
                pass
            count += 1
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
    return count


async def start_consent_expiry_task() -> None:
    """Startup loop: expire due consents every poll interval."""
    if not (getattr(S, "open_bank_project_enabled", False) and S.psd2_consents_enabled):
        return
    while True:
        try:
            expire_due_consents()
        except Exception:
            pass
        await asyncio.sleep(S.psd2_consent_expiry_poll_interval)


# ---------------------------------------------------------------------------
# CSN-002: SCA gate
# ---------------------------------------------------------------------------

def request_consent_sca(
    owner_sub: str,
    consent_id: str,
    req: Request,
) -> Dict[str, Any]:
    """Mint an SCA action challenge and stamp it on the consent item."""
    item = get_consent(owner_sub, consent_id)
    if item is None:
        raise HTTPException(404, "consent not found")

    status = item.get("status")
    if status == "ACCEPTED":
        raise HTTPException(409, "already_accepted")
    if status not in ("INITIATED",):
        raise HTTPException(409, "invalid_status")

    try:
        from app.services import sessions as _sessions
        required_factors = _sessions.compute_required_factors(owner_sub)
    except Exception:
        required_factors = []

    pis = item.get("consent_type") == "PIS"
    pis_require = bool(getattr(S, "psd2_consent_pis_require_sca_factor", True))
    if pis and pis_require and not required_factors:
        raise HTTPException(409, "sca_enrollment_required")

    try:
        from app.services import sessions as _sessions
        challenge_id = _sessions.create_action_challenge(
            req,
            owner_sub,
            purpose="consent_sca",
            send_to=[],
            payload={
                "consent_id": consent_id,
                "required_factors": required_factors,
                "passed": {f: False for f in required_factors},
            },
            ttl_seconds=300,
        )
    except Exception as exc:
        raise HTTPException(500, f"sca_init_failed: {exc}") from exc

    # Stamp challenge_id onto the consent item
    T.consents.update_item(
        Key={"owner_sub": owner_sub, "consent_id": consent_id},
        UpdateExpression="SET sca_challenge_id = :c, updated_at = :t",
        ExpressionAttributeValues={":c": challenge_id, ":t": now_ts()},
    )

    try:
        from app.services.alerts import audit_event
        audit_event("consent.sca_required", owner_sub, req,
                    consent_id=consent_id, challenge_id=challenge_id)
    except Exception:
        pass

    return {
        "challenge_id": challenge_id,
        "required_factors": required_factors,
        "consent_id": consent_id,
        "status": "INITIATED",
    }


def accept_consent(
    owner_sub: str,
    consent_id: str,
    req: Request,
) -> Dict[str, Any]:
    """Transition an INITIATED consent to ACCEPTED after SCA."""
    item = get_consent(owner_sub, consent_id)
    if item is None:
        raise HTTPException(404, "consent not found")

    status = item.get("status")
    if status == "ACCEPTED":
        raise HTTPException(409, "already_accepted")
    if status not in ("INITIATED",):
        raise HTTPException(409, "invalid_status")

    sca_challenge_id = item.get("sca_challenge_id")
    if _consent_requires_sca(item) and not sca_challenge_id:
        raise HTTPException(403, "sca_not_initiated")

    if sca_challenge_id:
        try:
            from app.services import sessions as _sessions
            chal = _sessions.load_challenge_or_401(owner_sub, sca_challenge_id)
            if not _sessions.challenge_done(chal):
                raise HTTPException(403, "sca_incomplete")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(401, "Invalid challenge") from exc

    # Conditional update INITIATED → ACCEPTED
    try:
        T.consents.update_item(
            Key={"owner_sub": owner_sub, "consent_id": consent_id},
            UpdateExpression="SET #st = :a, updated_at = :t",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED", ":t": now_ts(), ":i": "INITIATED"},
            ConditionExpression="#st = :i",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, "already_accepted")
        raise

    # Revoke challenge (best-effort)
    if sca_challenge_id:
        try:
            from app.services import sessions as _sessions
            _sessions.revoke_challenge(owner_sub, sca_challenge_id)
        except Exception:
            pass

    try:
        from app.services.alerts import audit_event
        audit_event("consent.accepted", owner_sub, req, consent_id=consent_id)
    except Exception:
        pass

    result = get_consent(owner_sub, consent_id)
    if result is None:
        raise HTTPException(404, "consent not found")
    return result


def consent_authorizes_payment(payment_ref: str) -> bool:
    """Return True iff an ACCEPTED, unexpired PIS consent exists for this payment_ref.

    Read-only. Never writes a ledger, wallet, or billing row.
    Called by the TXR execution engine before moving money.
    """
    if not payment_ref:
        return False
    try:
        resp = T.consents.query(
            IndexName=S.consents_by_payment_ref_index,
            KeyConditionExpression=Key("payment_ref").eq(payment_ref),
        )
    except Exception:
        return False
    now = now_ts()
    for item in resp.get("Items", []):
        if (
            item.get("status") == "ACCEPTED"
            and item.get("consent_type") == "PIS"
            and int(item.get("valid_until", 0) or 0) > now
        ):
            return True
    return False
