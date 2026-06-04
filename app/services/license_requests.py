"""License request & approval workflow (LICENSE-004)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.issued_licenses import issue_license
from app.services.alerts import write_alert
from app.services.profile import get_profile

logger = logging.getLogger(__name__)

REQUEST_EXPIRY_DAYS = 30
REQUEST_EXPIRY_SECONDS = REQUEST_EXPIRY_DAYS * 86400

VALID_CONTENT_TYPES = {"video", "music", "image", "post", "broadcast", "clip"}
ACTIVE_STATUSES: Set[str] = {"pending", "negotiating"}
TERMINAL_STATUSES: Set[str] = {"approved", "denied", "withdrawn", "expired"}


class ConflictError(Exception):
    """Raised when a duplicate active request exists."""
    pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_request(
    *,
    requester_sub: str,
    content_id: str,
    content_type: str,
    owner_id: str,
    proposed_terms: Dict[str, Any],
    message: str = "",
) -> Dict[str, Any]:
    """Creator requests a license for another creator's content."""
    if requester_sub == owner_id:
        raise ValueError("Cannot request a license for your own content")
    if content_type not in VALID_CONTENT_TYPES:
        raise ValueError(f"Invalid content_type: {content_type}")

    _validate_terms(proposed_terms)
    _check_no_duplicate_request(requester_sub, content_id)

    request_id = f"req_{uuid4().hex}"
    ts = now_ts()
    expires_at = ts + REQUEST_EXPIRY_SECONDS
    profile = get_profile(requester_sub) or {}

    item: Dict[str, Any] = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"REQUEST#{request_id}",
        "request_id": request_id,
        "content_id": content_id,
        "content_type": content_type,
        "requester_id": requester_sub,
        "owner_id": owner_id,
        "status": "pending",
        "proposed_terms": proposed_terms,
        "counter_terms": None,
        "denial_reason": "",
        "message": message,
        "created_at": ts,
        "updated_at": ts,
        "expires_at": expires_at,
        "GSI4PK": "REQ_STATUS#pending",
        "GSI4SK": expires_at,
    }
    T.issued_licenses.put_item(Item=item)

    _write_requester_index(
        request_id, requester_sub, content_id, content_type, owner_id, "pending", ts,
    )
    _write_owner_index(
        request_id, owner_id, content_id, content_type,
        requester_sub, profile, "pending", ts,
    )

    try:
        write_alert(
            owner_id,
            event="license_request_received",
            outcome="info",
            title="License Request Received",
            details={
                "requester_id": requester_sub,
                "requester_name": profile.get("display_name", requester_sub),
                "content_id": content_id,
                "request_id": request_id,
            },
        )
    except Exception:
        logger.warning("Failed to write license request alert", exc_info=True)

    return _sanitize(item)


def approve_request(
    *,
    owner_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Content owner approves a license request. Creates an IssuedLicense."""
    request = _get_request(content_id, request_id)
    _require_owner(request, owner_sub)
    _require_status(request, ACTIVE_STATUSES)

    final_terms = request.get("counter_terms") or request["proposed_terms"]

    issued = issue_license(
        licensor_sub=owner_sub,
        content_id=content_id,
        content_type=request["content_type"],
        license_mode="per_user",
        licensee_id=request["requester_id"],
        profit_share_pct=int(final_terms.get("profit_share_pct", 0)),
        fixed_cost_cents=int(final_terms.get("fixed_cost_cents", 0)),
        revenue_share_pct=int(final_terms.get("revenue_share_pct", 0)),
    )

    _update_request_status(request, "approved")

    try:
        write_alert(
            request["requester_id"],
            event="license_request_approved",
            outcome="info",
            title="License Request Approved",
            details={
                "owner_id": owner_sub,
                "content_id": content_id,
                "issued_license_id": issued["issued_license_id"],
            },
        )
    except Exception:
        logger.warning("Failed to write approval alert", exc_info=True)

    return {"request": _sanitize(request), "issued_license": issued}


def deny_request(
    *,
    owner_sub: str,
    request_id: str,
    content_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Content owner denies a license request."""
    request = _get_request(content_id, request_id)
    _require_owner(request, owner_sub)
    _require_status(request, ACTIVE_STATUSES)

    # Store denial reason on primary record
    T.issued_licenses.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"REQUEST#{request_id}"},
        UpdateExpression="SET #dr = :dr",
        ExpressionAttributeNames={"#dr": "denial_reason"},
        ExpressionAttributeValues={":dr": reason},
    )
    request["denial_reason"] = reason
    _update_request_status(request, "denied")

    try:
        write_alert(
            request["requester_id"],
            event="license_request_denied",
            outcome="warning",
            title="License Request Denied",
            details={
                "owner_id": owner_sub,
                "content_id": content_id,
                "reason": reason,
            },
        )
    except Exception:
        logger.warning("Failed to write denial alert", exc_info=True)

    return _sanitize(request)


def counter_offer(
    *,
    owner_sub: str,
    request_id: str,
    content_id: str,
    counter_terms: Dict[str, Any],
) -> Dict[str, Any]:
    """Content owner proposes different terms."""
    request = _get_request(content_id, request_id)
    _require_owner(request, owner_sub)
    _require_status(request, ACTIVE_STATUSES)
    _validate_terms(counter_terms)

    T.issued_licenses.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"REQUEST#{request_id}"},
        UpdateExpression="SET #ct = :ct",
        ExpressionAttributeNames={"#ct": "counter_terms"},
        ExpressionAttributeValues={":ct": counter_terms},
    )
    request["counter_terms"] = counter_terms
    _update_request_status(request, "negotiating")

    try:
        write_alert(
            request["requester_id"],
            event="license_counter_offer",
            outcome="info",
            title="Counter-Offer Received",
            details={
                "owner_id": owner_sub,
                "content_id": content_id,
                "counter_terms": str(counter_terms),
            },
        )
    except Exception:
        logger.warning("Failed to write counter-offer alert", exc_info=True)

    return _sanitize(request)


def accept_counter(
    *,
    requester_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Requester accepts the owner's counter-offer. Creates an IssuedLicense."""
    request = _get_request(content_id, request_id)
    _require_requester(request, requester_sub)
    _require_status(request, {"negotiating"})

    ct = request.get("counter_terms")
    if not ct:
        raise ValueError("No counter-offer to accept")

    issued = issue_license(
        licensor_sub=request["owner_id"],
        content_id=content_id,
        content_type=request["content_type"],
        license_mode="per_user",
        licensee_id=requester_sub,
        profit_share_pct=int(ct.get("profit_share_pct", 0)),
        fixed_cost_cents=int(ct.get("fixed_cost_cents", 0)),
        revenue_share_pct=int(ct.get("revenue_share_pct", 0)),
    )

    _update_request_status(request, "approved")

    try:
        write_alert(
            request["owner_id"],
            event="license_counter_accepted",
            outcome="info",
            title="Counter-Offer Accepted",
            details={
                "requester_id": requester_sub,
                "content_id": content_id,
                "issued_license_id": issued["issued_license_id"],
            },
        )
    except Exception:
        logger.warning("Failed to write counter-accept alert", exc_info=True)

    return {"request": _sanitize(request), "issued_license": issued}


def reject_counter(
    *,
    requester_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Requester rejects the owner's counter-offer."""
    request = _get_request(content_id, request_id)
    _require_requester(request, requester_sub)
    _require_status(request, {"negotiating"})

    _update_request_status(request, "denied")

    try:
        write_alert(
            request["owner_id"],
            event="license_counter_rejected",
            outcome="info",
            title="Counter-Offer Rejected",
            details={
                "requester_id": requester_sub,
                "content_id": content_id,
            },
        )
    except Exception:
        logger.warning("Failed to write counter-reject alert", exc_info=True)

    return _sanitize(request)


def withdraw_request(
    *,
    requester_sub: str,
    request_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Requester withdraws their pending/negotiating request."""
    request = _get_request(content_id, request_id)
    _require_requester(request, requester_sub)
    _require_status(request, ACTIVE_STATUSES)

    _update_request_status(request, "withdrawn")

    try:
        write_alert(
            request["owner_id"],
            event="license_request_withdrawn",
            outcome="info",
            title="License Request Withdrawn",
            details={
                "requester_id": requester_sub,
                "content_id": content_id,
            },
        )
    except Exception:
        logger.warning("Failed to write withdraw alert", exc_info=True)

    return _sanitize(request)


def list_sent_requests(
    *,
    requester_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List license requests sent by a creator."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"REQUESTER#{requester_sub}")
            & Key("sk").begins_with("REQ_SENT#")
        ),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.issued_licenses.query(**kwargs)
    items = resp.get("Items", [])

    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def list_received_requests(
    *,
    owner_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List license requests received by a content owner (license inbox)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"OWNER#{owner_sub}")
            & Key("sk").begins_with("REQ_RECEIVED#")
        ),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.issued_licenses.query(**kwargs)
    items = resp.get("Items", [])

    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def get_request_detail(
    *,
    content_id: str,
    request_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a specific request (must be requester or owner)."""
    request = _get_request(content_id, request_id)
    if request["requester_id"] != user_id and request["owner_id"] != user_id:
        raise PermissionError("Not authorized to view this request")
    return _sanitize(request)


def process_expired_requests() -> int:
    """Background task: expire stale requests past their expiry date."""
    ts = now_ts()
    expired_count = 0

    for status in ("pending", "negotiating"):
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI4",
            "KeyConditionExpression": (
                Key("GSI4PK").eq(f"REQ_STATUS#{status}")
                & Key("GSI4SK").lt(ts)
            ),
            "Limit": 100,
        }
        resp = T.issued_licenses.query(**kwargs)
        for item in resp.get("Items", []):
            try:
                _update_request_status(item, "expired")
                expired_count += 1
            except Exception:
                logger.warning(
                    "Failed to expire request %s", item.get("request_id"),
                    exc_info=True,
                )

    return expired_count


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_request(content_id: str, request_id: str) -> Dict[str, Any]:
    """Fetch request or raise LookupError."""
    resp = T.issued_licenses.get_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"REQUEST#{request_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise LookupError("License request not found")
    return item


def _require_owner(request: Dict[str, Any], user_id: str) -> None:
    if request.get("owner_id") != user_id:
        raise PermissionError("Only the content owner can perform this action")


def _require_requester(request: Dict[str, Any], user_id: str) -> None:
    if request.get("requester_id") != user_id:
        raise PermissionError("Only the requester can perform this action")


def _require_status(request: Dict[str, Any], valid_statuses: Set[str]) -> None:
    current = request.get("status", "")
    if current not in valid_statuses:
        raise ValueError(
            f"Request is '{current}'; expected one of {sorted(valid_statuses)}"
        )


def _update_request_status(request: Dict[str, Any], new_status: str) -> None:
    """Update status on primary + index records + GSI keys."""
    ts = now_ts()
    content_id = request["content_id"]
    request_id = request["request_id"]
    requester_id = request["requester_id"]
    owner_id = request["owner_id"]

    update_expr = "SET #status = :status, #updated_at = :ts"
    names: Dict[str, str] = {
        "#status": "status",
        "#updated_at": "updated_at",
    }
    values: Dict[str, Any] = {
        ":status": new_status,
        ":ts": ts,
    }

    if new_status in ACTIVE_STATUSES:
        update_expr += ", #gsi4pk = :gsi4pk"
        names["#gsi4pk"] = "GSI4PK"
        values[":gsi4pk"] = f"REQ_STATUS#{new_status}"
    else:
        # Terminal status: remove from expiry index
        update_expr += " REMOVE #gsi4pk, #gsi4sk"
        names["#gsi4pk"] = "GSI4PK"
        names["#gsi4sk"] = "GSI4SK"

    T.issued_licenses.update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"REQUEST#{request_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    request["status"] = new_status
    request["updated_at"] = ts

    # Update requester index
    try:
        T.issued_licenses.update_item(
            Key={"pk": f"REQUESTER#{requester_id}", "sk": f"REQ_SENT#{request_id}"},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": new_status},
        )
    except Exception:
        logger.warning("Failed to update requester index for %s", request_id, exc_info=True)

    # Update owner index
    try:
        T.issued_licenses.update_item(
            Key={"pk": f"OWNER#{owner_id}", "sk": f"REQ_RECEIVED#{request_id}"},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": new_status},
        )
    except Exception:
        logger.warning("Failed to update owner index for %s", request_id, exc_info=True)


def _write_requester_index(
    request_id: str,
    requester_id: str,
    content_id: str,
    content_type: str,
    owner_id: str,
    status: str,
    ts: int,
) -> None:
    T.issued_licenses.put_item(Item={
        "pk": f"REQUESTER#{requester_id}",
        "sk": f"REQ_SENT#{request_id}",
        "request_id": request_id,
        "content_id": content_id,
        "content_type": content_type,
        "owner_id": owner_id,
        "status": status,
        "created_at": ts,
    })


def _write_owner_index(
    request_id: str,
    owner_id: str,
    content_id: str,
    content_type: str,
    requester_id: str,
    profile: Dict[str, Any],
    status: str,
    ts: int,
) -> None:
    T.issued_licenses.put_item(Item={
        "pk": f"OWNER#{owner_id}",
        "sk": f"REQ_RECEIVED#{request_id}",
        "request_id": request_id,
        "content_id": content_id,
        "content_type": content_type,
        "requester_id": requester_id,
        "requester_display_name": (profile.get("display_name") or requester_id),
        "status": status,
        "created_at": ts,
    })


def _check_no_duplicate_request(requester_id: str, content_id: str) -> None:
    resp = T.issued_licenses.query(
        KeyConditionExpression=(
            Key("pk").eq(f"REQUESTER#{requester_id}")
            & Key("sk").begins_with("REQ_SENT#")
        ),
    )
    for item in resp.get("Items", []):
        if (
            item.get("content_id") == content_id
            and item.get("status") in ACTIVE_STATUSES
        ):
            raise ConflictError(
                "You already have an active request for this content"
            )


def _validate_terms(terms: Dict[str, Any]) -> None:
    psp = terms.get("profit_share_pct", 0)
    rsp = terms.get("revenue_share_pct", 0)
    fcc = terms.get("fixed_cost_cents", 0)
    if not isinstance(psp, (int, float)) or psp < 0 or psp > 100:
        raise ValueError("profit_share_pct must be 0-100")
    if not isinstance(rsp, (int, float)) or rsp < 0 or rsp > 100:
        raise ValueError("revenue_share_pct must be 0-100")
    if not isinstance(fcc, (int, float)) or fcc < 0:
        raise ValueError("fixed_cost_cents must be >= 0")


def _sanitize(request: Dict[str, Any]) -> Dict[str, Any]:
    """Strip DynamoDB internal keys for API responses."""
    skip = {"pk", "sk", "GSI2PK", "GSI2SK", "GSI4PK", "GSI4SK"}
    return {k: v for k, v in request.items() if k not in skip}
