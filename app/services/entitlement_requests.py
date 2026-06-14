"""VEW-004 — Entitlement-request workflow.

Self-service request → admin approval queue → (optional) STU ACL grant.
State machine: pending → under_review → approved | rejected | cancelled.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.auth.roles import AdminScope
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_ENTITLEMENT_KINDS: frozenset[str] = frozenset({"acl_role", "admin_scope"})
VALID_ADMIN_SCOPES: frozenset[str] = frozenset({s.value for s in AdminScope})
OPEN_STATUSES: frozenset[str] = frozenset({"pending", "under_review"})
ALL_STATUSES: frozenset[str] = frozenset(
    {"pending", "under_review", "approved", "rejected", "cancelled"}
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    if not (
        getattr(S, "open_bank_project_enabled", False)
        and getattr(S, "entitlement_requests_enabled", False)
    ):
        raise HTTPException(status_code=404, detail="Entitlement requests not enabled")


def _write_audit_row(
    request_id: str,
    event_type: str,
    actor_sub: str,
    from_status: Optional[str],
    to_status: Optional[str],
    reason: str = "",
) -> None:
    try:
        from app.core.tables import T

        ts = now_ts()
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        T.entitlement_requests.put_item(
            Item={
                "pk": f"ENTREQ#{request_id}",
                "sk": f"AUDIT#{ts:013d}#{event_id}",
                "event_type": event_type,
                "actor_sub": actor_sub,
                "from_status": from_status,
                "to_status": to_status,
                "reason": reason,
                "created_at": ts,
            }
        )
    except Exception as exc:
        logger.warning("entitlement_requests._write_audit_row failed: %s", exc)


def _check_duplicate_open_request(
    requester_sub: str,
    entitlement_kind: str,
    target_ref: str,
) -> None:
    """Raise 409 if an open (pending/under_review) request for this (kind,ref) exists."""
    from app.core.tables import T

    lek = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "by-requester",
            "KeyConditionExpression": Key("GSI2PK").eq(f"REQUESTER#{requester_sub}"),
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.entitlement_requests.query(**kwargs)
        for item in resp.get("Items", []):
            if (
                item.get("entitlement_kind") == entitlement_kind
                and item.get("target_ref") == target_ref
                and item.get("status") in OPEN_STATUSES
            ):
                raise HTTPException(
                    status_code=409,
                    detail={"code": "duplicate_open_request", "message": "An open request for this entitlement already exists"},
                )
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break


def _count_open_requests(requester_sub: str) -> int:
    from app.core.tables import T

    lek = None
    count = 0
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "by-requester",
            "KeyConditionExpression": Key("GSI2PK").eq(f"REQUESTER#{requester_sub}"),
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.entitlement_requests.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("status") in OPEN_STATUSES:
                count += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    return count


def _rate_limit_entitlement_request(requester_sub: str) -> None:
    try:
        from app.services.rate_limit import _bucket_limit

        max_n = int(getattr(S, "entitlement_request_max_per_window", 20))
        win = int(getattr(S, "entitlement_request_window_seconds", 3600))
        if not _bucket_limit(requester_sub, "rl#entreq#create", max_n, win):
            raise HTTPException(status_code=429, detail="Rate limit exceeded for entitlement requests")
    except HTTPException:
        raise
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("entitlement_requests: rate limit check failed: %s", exc)


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------


def create_request(
    requester_sub: str,
    entitlement_kind: str,
    target_ref: str,
    justification: str,
) -> Dict[str, Any]:
    from app.core.tables import T

    if entitlement_kind not in VALID_ENTITLEMENT_KINDS:
        raise HTTPException(status_code=400, detail={"code": "invalid_kind", "message": f"Unknown entitlement_kind: {entitlement_kind}"})

    if entitlement_kind == "admin_scope":
        if target_ref not in VALID_ADMIN_SCOPES:
            raise HTTPException(status_code=400, detail={"code": "invalid_scope", "message": f"Unknown admin scope: {target_ref}"})
    elif entitlement_kind == "acl_role":
        # Validate the target role only when the STU ACL module is enabled; if it's
        # disabled (or unbuilt) defer validation to approval time (it can't answer).
        if getattr(S, "crm_acl_enabled", False):
            try:
                from app.services.crm_acl import get_acl_role
                role = get_acl_role(target_ref)
                if not role:
                    raise HTTPException(status_code=404, detail={"code": "role_not_found", "message": f"Role not found: {target_ref}"})
            except ImportError:
                pass  # STU not yet available; defer validation to approval time

    _check_duplicate_open_request(requester_sub, entitlement_kind, target_ref)

    max_open = int(getattr(S, "entitlement_request_max_open_per_user", 10))
    if _count_open_requests(requester_sub) >= max_open:
        raise HTTPException(status_code=429, detail={"code": "open_request_limit_reached", "message": "Open request limit reached"})

    _rate_limit_entitlement_request(requester_sub)

    ts = now_ts()
    request_id = uuid.uuid4().hex
    item: Dict[str, Any] = {
        "pk": f"ENTREQ#{request_id}",
        "sk": "META",
        "request_id": request_id,
        "requester_sub": requester_sub,
        "entitlement_kind": entitlement_kind,
        "target_ref": target_ref,
        "justification": justification,
        "status": "pending",
        "claimed_by_sub": None,
        "claimed_at": None,
        "decided_by_sub": None,
        "decided_at": None,
        "decision_reason": None,
        "grant_pending_acl": False,
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "STATUS#pending",
        "GSI1SK": ts,
        "GSI2PK": f"REQUESTER#{requester_sub}",
        "GSI2SK": ts,
    }
    T.entitlement_requests.put_item(Item=item)

    _write_audit_row(request_id, "created", requester_sub, None, "pending")

    try:
        audit_event(
            "entitlement_request.created",
            requester_sub,
            request_id=request_id,
            kind=entitlement_kind,
            target_ref=target_ref,
        )
    except Exception as exc:
        logger.warning("entitlement_requests: audit_event failed: %s", exc)

    return item


def list_queue(
    status: str = "pending",
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    from app.core.tables import T

    if status not in ALL_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    lek = decode_cursor(cursor) if cursor else None
    kwargs: Dict[str, Any] = {
        "IndexName": "by-status",
        "KeyConditionExpression": Key("GSI1PK").eq(f"STATUS#{status}"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if lek:
        kwargs["ExclusiveStartKey"] = lek
    resp = T.entitlement_requests.query(**kwargs)
    items = [it for it in resp.get("Items", []) if it.get("sk") == "META"]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey")) if resp.get("LastEvaluatedKey") else None
    return {"requests": items, "next_cursor": next_cursor}


def list_my_requests(requester_sub: str) -> List[Dict[str, Any]]:
    from app.core.tables import T

    lek = None
    results: List[Dict[str, Any]] = []
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "by-requester",
            "KeyConditionExpression": Key("GSI2PK").eq(f"REQUESTER#{requester_sub}"),
            "ScanIndexForward": False,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.entitlement_requests.query(**kwargs)
        results.extend(it for it in resp.get("Items", []) if it.get("sk") == "META")
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    return results


def get_request(request_id: str) -> Dict[str, Any]:
    from app.core.tables import T

    item = T.entitlement_requests.get_item(
        Key={"pk": f"ENTREQ#{request_id}", "sk": "META"}
    ).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail={"code": "request_not_found", "message": "Entitlement request not found"})
    return item


def claim_request(request_id: str, admin_sub: str) -> Dict[str, Any]:
    from app.core.tables import T

    item = get_request(request_id)
    if item.get("status") not in OPEN_STATUSES:
        raise HTTPException(status_code=409, detail={"code": "request_not_open", "message": "Request is not open"})

    existing_claimer = item.get("claimed_by_sub")
    if existing_claimer and existing_claimer != admin_sub:
        raise HTTPException(
            status_code=409,
            detail={"code": "already_claimed", "message": "Request already claimed", "claimed_by_sub": existing_claimer},
        )

    ts = now_ts()
    T.entitlement_requests.update_item(
        Key={"pk": f"ENTREQ#{request_id}", "sk": "META"},
        UpdateExpression=(
            "SET #st = :st, claimed_by_sub = :cbs, claimed_at = :ca, "
            "updated_at = :ua, GSI1PK = :gsi1pk"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "under_review",
            ":cbs": admin_sub,
            ":ca": ts,
            ":ua": ts,
            ":gsi1pk": "STATUS#under_review",
        },
    )

    _write_audit_row(request_id, "claimed", admin_sub, item.get("status"), "under_review")

    try:
        audit_event(
            "entitlement_request.claimed",
            admin_sub,
            request_id=request_id,
            requester_sub=item.get("requester_sub"),
        )
    except Exception as exc:
        logger.warning("entitlement_requests: audit_event failed: %s", exc)

    return get_request(request_id)


def approve_request(request_id: str, admin_sub: str, *, reason: str = "") -> Dict[str, Any]:
    from app.core.tables import T

    item = get_request(request_id)
    if item.get("status") not in OPEN_STATUSES:
        raise HTTPException(status_code=400, detail={"code": "request_not_open", "message": "Request is not open"})

    grant_applied = False
    grant_pending_acl = False

    if item.get("entitlement_kind") == "acl_role":
        try:
            from app.services.crm_acl import assign_role_to_user
            assign_role_to_user(admin_sub, item["target_ref"], item["requester_sub"])
            grant_applied = True
        except ImportError:
            logger.warning("entitlement_requests: crm_acl not available; grant_pending_acl=True request_id=%s", request_id)
            grant_pending_acl = True
        except Exception as exc:
            logger.warning("entitlement_requests: STU ACL grant failed request_id=%s: %s", request_id, exc)
            grant_pending_acl = True
    elif item.get("entitlement_kind") == "admin_scope":
        try:
            from app.services.crm_acl import assign_admin_scope
            assign_admin_scope(admin_sub, item["requester_sub"], item["target_ref"])
            grant_applied = True
        except ImportError:
            logger.warning("entitlement_requests: crm_acl not available; grant_pending_acl=True request_id=%s", request_id)
            grant_pending_acl = True
        except Exception as exc:
            logger.warning("entitlement_requests: admin_scope grant failed request_id=%s: %s", request_id, exc)
            grant_pending_acl = True

    ts = now_ts()
    update_expr = (
        "SET #st = :st, decided_by_sub = :dbs, decided_at = :da, "
        "decision_reason = :dr, updated_at = :ua, GSI1PK = :gsi1pk, "
        "grant_pending_acl = :gpa"
    )
    T.entitlement_requests.update_item(
        Key={"pk": f"ENTREQ#{request_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "approved",
            ":dbs": admin_sub,
            ":da": ts,
            ":dr": reason,
            ":ua": ts,
            ":gsi1pk": "STATUS#approved",
            ":gpa": grant_pending_acl,
        },
    )

    _write_audit_row(request_id, "approved", admin_sub, item.get("status"), "approved", reason)

    try:
        audit_event(
            "entitlement_request.approved",
            admin_sub,
            request_id=request_id,
            requester_sub=item.get("requester_sub"),
            target_ref=item.get("target_ref"),
            grant_applied=grant_applied,
            grant_pending_acl=grant_pending_acl,
        )
    except Exception as exc:
        logger.warning("entitlement_requests: audit_event failed: %s", exc)

    return get_request(request_id)


def reject_request(request_id: str, admin_sub: str, reason: str) -> Dict[str, Any]:
    from app.core.tables import T

    item = get_request(request_id)
    if item.get("status") not in OPEN_STATUSES:
        raise HTTPException(status_code=400, detail={"code": "request_not_open", "message": "Request is not open"})

    ts = now_ts()
    T.entitlement_requests.update_item(
        Key={"pk": f"ENTREQ#{request_id}", "sk": "META"},
        UpdateExpression=(
            "SET #st = :st, decided_by_sub = :dbs, decided_at = :da, "
            "decision_reason = :dr, updated_at = :ua, GSI1PK = :gsi1pk"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "rejected",
            ":dbs": admin_sub,
            ":da": ts,
            ":dr": reason,
            ":ua": ts,
            ":gsi1pk": "STATUS#rejected",
        },
    )

    _write_audit_row(request_id, "rejected", admin_sub, item.get("status"), "rejected", reason)

    try:
        audit_event(
            "entitlement_request.rejected",
            admin_sub,
            request_id=request_id,
            requester_sub=item.get("requester_sub"),
            reason=reason,
        )
    except Exception as exc:
        logger.warning("entitlement_requests: audit_event failed: %s", exc)

    return get_request(request_id)


def cancel_request(request_id: str, requester_sub: str) -> Dict[str, Any]:
    from app.core.tables import T

    item = get_request(request_id)
    if item.get("requester_sub") != requester_sub:
        raise HTTPException(status_code=403, detail={"code": "not_requester", "message": "Only the requester can cancel"})
    if item.get("status") not in OPEN_STATUSES:
        raise HTTPException(status_code=400, detail={"code": "request_not_open", "message": "Request is not open"})

    ts = now_ts()
    T.entitlement_requests.update_item(
        Key={"pk": f"ENTREQ#{request_id}", "sk": "META"},
        UpdateExpression="SET #st = :st, updated_at = :ua, GSI1PK = :gsi1pk",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "cancelled",
            ":ua": ts,
            ":gsi1pk": "STATUS#cancelled",
        },
    )

    _write_audit_row(request_id, "cancelled", requester_sub, item.get("status"), "cancelled")

    try:
        audit_event(
            "entitlement_request.cancelled",
            requester_sub,
            request_id=request_id,
        )
    except Exception as exc:
        logger.warning("entitlement_requests: audit_event failed: %s", exc)

    return get_request(request_id)


def get_request_history(request_id: str) -> List[Dict[str, Any]]:
    from app.core.tables import T

    resp = T.entitlement_requests.query(
        KeyConditionExpression=Key("pk").eq(f"ENTREQ#{request_id}") & Key("sk").begins_with("AUDIT#"),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])
