"""Broadcast private session service -- manages 1-on-1 paid call sessions during broadcasts."""

from __future__ import annotations

import logging
import math
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("broadcast.private")

DEFAULT_MIN_RATE_CENTS = 100  # $1.00/min platform default
REQUEST_EXPIRY_SECONDS = 60  # Requests expire if creator doesn't respond in 60s


def create_private_request(
    session_id: str,
    viewer_id: str,
    viewer_display_name: str,
    rate_per_minute_cents: int,
    payment_method_id: str,
    max_duration_minutes: int = 60,
    *,
    min_rate_cents: int = DEFAULT_MIN_RATE_CENTS,
) -> Dict[str, Any]:
    """Create a private session request from a viewer.

    Raises:
        HTTPException(400) if rate is below minimum.
        HTTPException(409) if a private session is already pending or active.
    """
    if rate_per_minute_cents < min_rate_cents:
        raise HTTPException(
            status_code=400,
            detail=f"Rate must be at least {min_rate_cents} cents per minute.",
        )

    # Check for existing pending/active private sessions
    existing = _get_active_or_pending(session_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail="A private session is already in progress or pending.",
        )

    ts = now_ts()
    private_id = f"priv_{uuid.uuid4().hex}"

    item: Dict[str, Any] = {
        "pk": f"BCAST#{session_id}",
        "sk": f"PRIVATE#{private_id}",
        "private_session_id": private_id,
        "session_id": session_id,
        "viewer_id": viewer_id,
        "viewer_display_name": viewer_display_name,
        "rate_per_minute_cents": rate_per_minute_cents,
        "payment_method_id": payment_method_id,
        "max_duration_minutes": max_duration_minutes,
        "status": "requested",
        "requested_at": ts,
        "total_billed_cents": 0,
        "ttl": ts + 90 * 24 * 3600,
    }
    T.broadcast_private_sessions.put_item(Item=item)

    logger.info(
        "broadcast.private.requested session_id=%s viewer=%s rate=%d",
        session_id, viewer_id, rate_per_minute_cents,
    )

    return _private_session_out(item)


def list_pending_requests(session_id: str) -> List[Dict[str, Any]]:
    """List pending private requests for a broadcast session."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST#{session_id}")
            & Key("sk").begins_with("PRIVATE#")
        ),
        FilterExpression=Attr("status").eq("requested"),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("requested_at", 0)))
    return [_private_session_out(i) for i in items]


def get_private_session(session_id: str, private_session_id: str) -> Optional[Dict[str, Any]]:
    """Get a single private session item (public API)."""
    return _get_private_session(session_id, private_session_id)


def accept_private_request(
    session_id: str,
    private_session_id: str,
    behavior: str,
    call_id: str,
) -> Dict[str, Any]:
    """Accept a private session request.

    Raises:
        HTTPException(404) if request not found.
        HTTPException(409) if request is not in 'requested' status.
    """
    item = _get_private_session(session_id, private_session_id)
    if not item:
        raise HTTPException(status_code=404, detail="Private request not found.")
    if item.get("status") != "requested":
        raise HTTPException(status_code=409, detail="Request is no longer pending.")

    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression=(
            "SET #st = :status, accepted_at = :at, behavior = :beh, call_id = :cid"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":status": "accepted",
            ":at": ts,
            ":beh": behavior,
            ":cid": call_id,
        },
    )

    logger.info(
        "broadcast.private.accepted session_id=%s private_id=%s behavior=%s",
        session_id, private_session_id, behavior,
    )

    item.update({"status": "accepted", "accepted_at": ts, "behavior": behavior, "call_id": call_id})
    return _private_session_out(item)


def activate_private_session(session_id: str, private_session_id: str) -> Dict[str, Any]:
    """Mark a private session as active (WebRTC connected, billing starts)."""
    ts = now_ts()
    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression="SET #st = :status, started_at = :sa",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "active", ":sa": ts},
    )
    item = _get_private_session(session_id, private_session_id)
    return _private_session_out(item) if item else {}


def end_private_session(
    session_id: str,
    private_session_id: str,
    ended_by: str,
) -> Dict[str, Any]:
    """End an active private session. Calculate and write billing.

    Raises:
        HTTPException(404) if session not found.
        HTTPException(409) if session is not in 'active' status.
    """
    item = _get_private_session(session_id, private_session_id)
    if not item:
        raise HTTPException(status_code=404, detail="Private session not found.")
    if item.get("status") != "active":
        raise HTTPException(status_code=409, detail="Private session is not active.")

    ts = now_ts()
    started_at = int(item.get("started_at", ts))
    duration_seconds = max(0, ts - started_at)
    rate = int(item.get("rate_per_minute_cents", 0))

    # Bill rounded up to nearest minute (minimum 1 minute)
    billed_minutes = max(1, math.ceil(duration_seconds / 60))
    total_billed_cents = billed_minutes * rate

    # Cap at max duration billing
    max_mins = int(item.get("max_duration_minutes", 60))
    total_billed_cents = min(total_billed_cents, max_mins * rate)

    # Write billing ledger entries atomically. If the paired debit/credit
    # transaction fails we must NOT mark the session "ended" (which would imply
    # confirmed billing) — instead flag it "billing_failed" for reconciliation.
    try:
        debit_id, credit_id = _write_private_billing(
            viewer_id=item["viewer_id"],
            creator_id=_get_session_creator(session_id),
            amount_cents=total_billed_cents,
            private_session_id=private_session_id,
            session_id=session_id,
            payment_method_id=item.get("payment_method_id", ""),
        )
    except RuntimeError as exc:
        T.broadcast_private_sessions.update_item(
            Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
            UpdateExpression="SET #st = :status, ended_at = :ea, ended_by = :eb, "
            "total_billed_cents = :tbc, billing_error = :err",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":status": "billing_failed",
                ":ea": ts,
                ":eb": ended_by,
                ":tbc": total_billed_cents,
                ":err": str(exc)[:500],
            },
        )
        logger.error(
            "broadcast.private.billing_failed session_id=%s private_id=%s billed=%d error=%s",
            session_id, private_session_id, total_billed_cents, exc,
        )
        raise HTTPException(
            status_code=500,
            detail="Billing transaction failed; session marked billing_failed.",
        ) from exc

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression=(
            "SET #st = :status, ended_at = :ea, ended_by = :eb, "
            "total_billed_cents = :tbc, billing_debit_entry_id = :did, "
            "billing_credit_entry_id = :cid"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":status": "ended",
            ":ea": ts,
            ":eb": ended_by,
            ":tbc": total_billed_cents,
            ":did": debit_id,
            ":cid": credit_id,
        },
    )

    logger.info(
        "broadcast.private.ended session_id=%s private_id=%s duration=%ds billed=%d",
        session_id, private_session_id, duration_seconds, total_billed_cents,
    )

    return {
        "private_session_id": private_session_id,
        "session_id": session_id,
        "status": "ended",
        "duration_seconds": duration_seconds,
        "total_billed_cents": total_billed_cents,
        "ended_by": ended_by,
    }


def decline_private_request(session_id: str, private_session_id: str) -> bool:
    """Decline a pending private request. Returns True if found and declined."""
    item = _get_private_session(session_id, private_session_id)
    if not item or item.get("status") != "requested":
        return False

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression="SET #st = :status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "declined"},
    )
    return True


def cancel_private_request(session_id: str, private_session_id: str, viewer_id: str) -> bool:
    """Cancel a pending private request (viewer-initiated). Returns True if successful."""
    item = _get_private_session(session_id, private_session_id)
    if not item or item.get("status") != "requested":
        return False
    if item.get("viewer_id") != viewer_id:
        return False

    T.broadcast_private_sessions.update_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"},
        UpdateExpression="SET #st = :status",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":status": "cancelled"},
    )
    return True


def get_private_status(session_id: str) -> Dict[str, Any]:
    """Return current private session state for a broadcast.

    Returns the active/accepted/requested session if one exists, else empty dict.
    """
    active = _get_active_or_pending(session_id)
    if active:
        return _private_session_out(active)
    return {}


# ---- Internal Helpers ------------------------------------------------


def _get_private_session(session_id: str, private_session_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single private session item from DDB."""
    return T.broadcast_private_sessions.get_item(
        Key={"pk": f"BCAST#{session_id}", "sk": f"PRIVATE#{private_session_id}"}
    ).get("Item")


def _get_active_or_pending(session_id: str) -> Optional[Dict[str, Any]]:
    """Check if there is an active or pending private session for this broadcast."""
    resp = T.broadcast_private_sessions.query(
        KeyConditionExpression=(
            Key("pk").eq(f"BCAST#{session_id}")
            & Key("sk").begins_with("PRIVATE#")
        ),
        FilterExpression=Attr("status").is_in(["requested", "accepted", "active"]),
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def _get_session_creator(session_id: str) -> str:
    """Get the creator user_sub for a broadcast session."""
    from app.services.broadcast_store import get_session
    session = get_session(session_id)
    return session.created_by


def _write_private_billing(
    viewer_id: str,
    creator_id: str,
    amount_cents: int,
    private_session_id: str,
    session_id: str,
    payment_method_id: str,
) -> tuple[str, str]:
    """Write paired debit/credit billing ledger entries for a private session.

    The viewer debit and creator credit are committed atomically via DynamoDB
    ``TransactWriteItems`` so that either both ledger rows are written or neither
    is. On failure a ``RuntimeError`` is raised so the caller can mark the
    session ``billing_failed`` instead of silently losing the creator's credit.

    Returns (debit_entry_id, credit_entry_id).
    """
    # Imported at function scope to keep module-level imports minimal. The
    # low-level DynamoDB client is built using the SAME endpoint / region /
    # credential resolution as `ddb_resource()` (the helper that wires every
    # table), so dev (DynamoDB Local) and prod (AWS) behave identically
    # (SECOPS-007 parity). TransactWriteItems is only available on the
    # low-level client, not on the resource Table API.
    import boto3
    from boto3.dynamodb.types import TypeSerializer
    from botocore.exceptions import ClientError

    from app.core.aws_clients import (
        _aws_region,
        _ddb_endpoint_url,
        _local_credentials_kwargs,
    )
    from app.core.settings import S

    endpoint_url = _ddb_endpoint_url()
    client = boto3.client(
        "dynamodb",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        **_local_credentials_kwargs(endpoint_url),
    )

    ts = now_ts()
    debit_id = uuid.uuid4().hex
    credit_id = uuid.uuid4().hex
    reason = "Private session"
    meta: Dict[str, Any] = {
        "content_type": "private_call",
        "private_session_id": private_session_id,
        "session_id": session_id,
        "viewer_id": viewer_id,
        "creator_id": creator_id,
        "payment_method_id": payment_method_id,
    }

    debit_row: Dict[str, Any] = {
        "pk": f"USER#{viewer_id}",
        "sk": f"LEDGER#{ts}#{debit_id}",
        "entry_id": debit_id,
        "ts": ts,
        "type": "debit",
        "amount_cents": amount_cents,
        "currency": "USD",
        "state": "settled",
        "reason": reason,
        "meta": meta,
    }
    credit_row: Dict[str, Any] = {
        "pk": f"USER#{creator_id}",
        "sk": f"LEDGER#{ts}#{credit_id}",
        "entry_id": credit_id,
        "ts": ts,
        "type": "credit",
        "amount_cents": amount_cents,
        "currency": "USD",
        "state": "settled",
        "reason": reason,
        "meta": meta,
    }

    serializer = TypeSerializer()
    table_name = S.billing_table_name

    def _serialize(row: Dict[str, Any]) -> Dict[str, Any]:
        return {k: serializer.serialize(v) for k, v in row.items()}

    try:
        client.transact_write_items(
            TransactItems=[
                {"Put": {"TableName": table_name, "Item": _serialize(debit_row)}},
                {"Put": {"TableName": table_name, "Item": _serialize(credit_row)}},
            ]
        )
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        logger.error(
            "private_billing_transact_failed viewer=%s creator=%s amount=%d error=%s",
            viewer_id, creator_id, amount_cents, error_code,
        )
        raise RuntimeError(
            f"Billing transaction failed ({error_code}): "
            f"viewer={viewer_id} creator={creator_id} amount={amount_cents}"
        ) from exc

    logger.info(
        "private_billing_settled viewer=%s creator=%s amount=%d debit=%s credit=%s",
        viewer_id, creator_id, amount_cents, debit_id, credit_id,
    )
    return debit_id, credit_id


def _private_session_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to output dict with Decimal-to-int coercion."""
    return {
        "request_id": item.get("private_session_id", ""),
        "private_session_id": item.get("private_session_id", ""),
        "session_id": item.get("session_id", ""),
        "viewer_id": item.get("viewer_id", ""),
        "viewer_display_name": item.get("viewer_display_name", ""),
        "rate_per_minute_cents": int(item.get("rate_per_minute_cents", 0)),
        "status": item.get("status", ""),
        "behavior": item.get("behavior"),
        "call_id": item.get("call_id"),
        "max_duration_minutes": int(item.get("max_duration_minutes", 60)),
        "requested_at": int(item.get("requested_at", 0)),
        "accepted_at": int(item["accepted_at"]) if item.get("accepted_at") else None,
        "started_at": int(item["started_at"]) if item.get("started_at") else None,
        "ended_at": int(item["ended_at"]) if item.get("ended_at") else None,
        "ended_by": item.get("ended_by"),
        "total_billed_cents": int(item.get("total_billed_cents", 0)),
    }
