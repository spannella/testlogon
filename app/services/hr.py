"""OFBiz-inspired Human Resources service (HRM-004, HRM-005, HRM-006).

This module owns:
  * Employee party provisioning (HRM-004) — ensure_employee_party
  * Position lifecycle CRUD (HRM-005) — create_position, get_position,
    list_positions, update_position_status
  * Employment lifecycle CRUD (HRM-006) — create_employment, get_employment,
    list_employments, terminate_employment, set_employment_status

All DynamoDB access goes through T.hr (single-table, defined by HRM-002).
Party-layer access (PTY-004/005/006) is done via lazy imports inside
functions — the party module may not be present in the integrated tree at
all deployment stages, and callers must not block on a missing import.

Feature-flag guards live in the router (app/routers/hr.py, HRM-009); these
service functions assume the flag has already been checked.

SECOPS-007 parity: no dev_mode branches; identical logic in dev (moto) and
prod (real DDB).
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, Optional, Set

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.alerts import audit_event


# ──────────────────────────── custom exceptions ────────────────────────────


class PositionInvalidTransitionError(ValueError):
    """Raised when an illegal position status transition is attempted."""


class EmploymentInvalidTransitionError(ValueError):
    """Raised when an illegal employment status transition is attempted."""


# ──────────────────────────── position constants ───────────────────────────


_POSITION_ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "OPEN":   {"FILLED", "CLOSED"},
    "FILLED": {"CLOSED"},
    "CLOSED": set(),      # terminal state
}


# ──────────────────────────── HRM-004: employee party ─────────────────────


def ensure_employee_party(
    user_sub: Optional[str] = None,
    *,
    person_fields: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
) -> str:
    """Idempotently provision a PERSON party carrying the EMPLOYEE role.

    Returns the party_id.  Re-calling with the same correlation_id or
    user_sub returns the same party_id with no duplicate items.

    The party module (PTY-004/005/010) is imported lazily so that a missing
    party module is surfaced immediately on first call rather than at import
    time (which would break test isolation when party tables are absent).

    Guarded on S.party_crm_enabled at call time per RULE-2.
    """
    if not user_sub and not person_fields:
        raise ValueError("ensure_employee_party: user_sub or person_fields required")

    # RULE-2: guard party calls on the party_crm_enabled flag
    if not getattr(S, "party_crm_enabled", False):
        # Party module not active — return a deterministic synthetic party_id
        # so callers can store it as a foreign key without the party graph.
        if user_sub:
            return f"local_{hashlib.sha256(user_sub.encode()).hexdigest()[:28]}"
        if correlation_id:
            return f"local_{hashlib.sha256(correlation_id.encode()).hexdigest()[:28]}"
        return f"local_{uuid.uuid4().hex[:28]}"

    try:
        from app.services import party as _party  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError("party module not available; PTY-004 must be deployed first") from exc

    is_new_party = False

    if user_sub:
        party_id = _party.ensure_person_party(user_sub)
        try:
            existing_roles = _party.list_roles(party_id)
            is_new_party = "EMPLOYEE" not in {r["role_type"] for r in existing_roles}
        except Exception:
            is_new_party = False
    else:
        fields = dict(person_fields or {})
        party_record = _party.create_party(
            "PERSON",
            user_sub=None,
            correlation_id=correlation_id,
            **fields,
        )
        party_id = party_record["party_id"]
        is_new_party = party_record.get("_created", True)

    try:
        _party.add_role(party_id, "EMPLOYEE")
    except Exception:
        pass  # idempotent — a duplicate role is a no-op per PTY-005

    if is_new_party:
        try:
            audit_event(
                "employee.onboarded",
                user_sub or "system",
                party_id=party_id,
                user_sub=user_sub,
            )
        except Exception:
            pass

    return party_id


# ──────────────────────────── HRM-005: position CRUD ──────────────────────


def create_position(
    title: str,
    department: Optional[str] = None,
    *,
    actor_sub: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Idempotently create a new Position record in the hr table.

    Returns the DynamoDB item dict matching the Position model shape.
    """
    if correlation_id:
        position_id = "POS_" + hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:32]
    else:
        position_id = "POS_" + uuid.uuid4().hex

    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": f"POSITION#{position_id}",
        "SK": "META",
        "position_id": position_id,
        "title": title,
        "status": "OPEN",
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "POSITION#OPEN",
        "GSI1SK": f"POSITION#{position_id}",
        "entity_type": "POSITION",
    }
    if department is not None:
        item["department"] = department
    if correlation_id is not None:
        item["correlation_id"] = correlation_id

    try:
        T.hr.put_item(Item=item, ConditionExpression="attribute_not_exists(PK)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_position(position_id)
            return existing or item
        raise

    try:
        audit_event(
            "position.created",
            actor_sub,
            position_id=position_id,
            title=title,
        )
    except Exception:
        pass

    return item


def get_position(position_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single Position by id.  Returns None if not found."""
    resp = T.hr.get_item(Key={"PK": f"POSITION#{position_id}", "SK": "META"})
    return resp.get("Item")


def list_positions(
    status: Optional[str] = None,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List positions filtered by status (GSI1) or newest-first (GSI_CREATED)."""
    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    if status is not None:
        kwargs["IndexName"] = "GSI1"
        kwargs["KeyConditionExpression"] = Key("GSI1PK").eq(f"POSITION#{status}")
    else:
        kwargs["IndexName"] = "GSI_CREATED"
        kwargs["KeyConditionExpression"] = Key("entity_type").eq("POSITION")
        kwargs["ScanIndexForward"] = False

    resp = T.hr.query(**kwargs)
    result: Dict[str, Any] = {"items": resp.get("Items", [])}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def update_position_status(
    position_id: str,
    new_status: str,
    *,
    actor_sub: str,
) -> Dict[str, Any]:
    """Transition a position to a new status.

    Raises:
        LookupError: if the position does not exist.
        PositionInvalidTransitionError: for illegal transitions.
    """
    item = get_position(position_id)
    if item is None:
        raise LookupError(f"position_not_found:{position_id}")

    current_status = item["status"]
    allowed = _POSITION_ALLOWED_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        raise PositionInvalidTransitionError(
            f"{current_status}→{new_status}"
        )

    ts = now_ts()
    T.hr.update_item(
        Key={"PK": f"POSITION#{position_id}", "SK": "META"},
        UpdateExpression="SET #status = :status, updated_at = :ts, GSI1PK = :gsi1pk",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": new_status,
            ":ts": ts,
            ":gsi1pk": f"POSITION#{new_status}",
        },
    )

    try:
        audit_event(
            "position.status_updated",
            actor_sub,
            position_id=position_id,
            old_status=current_status,
            new_status=new_status,
        )
    except Exception:
        pass

    updated = get_position(position_id)
    return updated or item


# ──────────────────────────── HRM-006: employment CRUD ────────────────────


def create_employment(
    party_id: str,
    position_id: str,
    org_party_id: str,
    pay_rate_cents: int,
    pay_period: str,
    start_date: int,
    *,
    end_date: Optional[int] = None,
    currency: str = "usd",
    actor_sub: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Hire a party into a position.  Idempotent on correlation_id.

    Side-effects (all best-effort):
    * Writes a EMPLOYMENT relationship to the party graph (PTY-006).
    * Transitions the position to FILLED (HRM-005).
    * Emits audit event.
    """
    if pay_rate_cents < 0:
        raise ValueError("pay_rate_cents must be >= 0")
    if pay_period not in {"MONTHLY", "BIWEEKLY", "WEEKLY", "HOURLY"}:
        raise ValueError(f"invalid pay_period: {pay_period!r}")
    if end_date is not None and end_date < start_date:
        raise ValueError("end_date must be >= start_date")

    if correlation_id:
        employment_id = "EMP_" + hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:32]
    else:
        employment_id = "EMP_" + uuid.uuid4().hex

    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": f"EMPLOYMENT#{employment_id}",
        "SK": "META",
        "employment_id": employment_id,
        "party_id": party_id,
        "position_id": position_id,
        "org_party_id": org_party_id,
        "status": "ACTIVE",
        "start_date": start_date,
        "pay_rate_cents": pay_rate_cents,
        "pay_period": pay_period,
        "currency": currency.upper(),
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "EMPLOYMENT#ACTIVE",
        "GSI1SK": f"EMPLOYMENT#{employment_id}",
        "GSI2PK": f"PARTY#{party_id}",
        "GSI2SK": f"EMPLOYMENT#{employment_id}",
        "entity_type": "EMPLOYMENT",
    }
    if end_date is not None:
        item["end_date"] = end_date
    if correlation_id is not None:
        item["correlation_id"] = correlation_id

    try:
        T.hr.put_item(Item=item, ConditionExpression="attribute_not_exists(PK)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_employment(employment_id)
            return existing or item
        raise

    # Best-effort: mirror to party graph
    if getattr(S, "party_crm_enabled", False):
        try:
            from app.services import party as _party  # type: ignore[import]
            _party.create_relationship(
                from_party_id=party_id,
                to_party_id=org_party_id,
                relationship_type="EMPLOYMENT",
                correlation_id=employment_id,
            )
        except Exception:
            pass

    # Best-effort: flip position to FILLED
    try:
        update_position_status(position_id, "FILLED", actor_sub=actor_sub)
    except Exception:
        pass

    try:
        audit_event(
            "employment.created",
            actor_sub,
            employment_id=employment_id,
            party_id=party_id,
            position_id=position_id,
            org_party_id=org_party_id,
        )
    except Exception:
        pass

    return item


def get_employment(employment_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single Employment record.  Returns None if not found."""
    resp = T.hr.get_item(Key={"PK": f"EMPLOYMENT#{employment_id}", "SK": "META"})
    return resp.get("Item")


def list_employments(
    *,
    party_id: Optional[str] = None,
    status: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List employments by party (GSI2), status (GSI1), or newest-first (GSI_CREATED)."""
    kwargs: Dict[str, Any] = {"Limit": limit}
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    if party_id is not None:
        kwargs["IndexName"] = "GSI2"
        kwargs["KeyConditionExpression"] = Key("GSI2PK").eq(f"PARTY#{party_id}")
    elif status is not None:
        kwargs["IndexName"] = "GSI1"
        kwargs["KeyConditionExpression"] = Key("GSI1PK").eq(f"EMPLOYMENT#{status}")
    else:
        kwargs["IndexName"] = "GSI_CREATED"
        kwargs["KeyConditionExpression"] = Key("entity_type").eq("EMPLOYMENT")
        kwargs["ScanIndexForward"] = False

    resp = T.hr.query(**kwargs)
    result: Dict[str, Any] = {"items": resp.get("Items", [])}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def terminate_employment(
    employment_id: str,
    end_date: int,
    *,
    actor_sub: str,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Terminate an employment.  Idempotent: already-terminated returns existing item."""
    item = get_employment(employment_id)
    if item is None:
        raise LookupError(f"employment_not_found:{employment_id}")

    # Idempotent re-terminate
    if item["status"] == "TERMINATED":
        return item

    if end_date < int(item["start_date"]):
        raise ValueError("end_date_before_start_date")

    ts = now_ts()
    update_expr = (
        "SET #status = :status, end_date = :end_date, "
        "updated_at = :ts, GSI1PK = :gsi1pk"
    )
    expr_values: Dict[str, Any] = {
        ":status": "TERMINATED",
        ":end_date": end_date,
        ":ts": ts,
        ":gsi1pk": "EMPLOYMENT#TERMINATED",
    }
    if reason:
        update_expr += ", termination_reason = :reason"
        expr_values[":reason"] = reason

    T.hr.update_item(
        Key={"PK": f"EMPLOYMENT#{employment_id}", "SK": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues=expr_values,
    )

    # Best-effort: revert position to OPEN if configured
    if getattr(S, "hr_position_revert_on_terminate", True):
        try:
            update_position_status(item["position_id"], "OPEN", actor_sub=actor_sub)
        except Exception:
            pass

    try:
        audit_event(
            "employment.terminated",
            actor_sub,
            employment_id=employment_id,
            end_date=end_date,
            reason=reason,
        )
    except Exception:
        pass

    updated = get_employment(employment_id)
    return updated or item


def set_employment_status(
    employment_id: str,
    status: str,
    *,
    actor_sub: str,
) -> Dict[str, Any]:
    """Administrative setter for ON_LEAVE and other non-terminate transitions."""
    item = get_employment(employment_id)
    if item is None:
        raise LookupError(f"employment_not_found:{employment_id}")

    ts = now_ts()
    T.hr.update_item(
        Key={"PK": f"EMPLOYMENT#{employment_id}", "SK": "META"},
        UpdateExpression="SET #status = :status, updated_at = :ts, GSI1PK = :gsi1pk",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":status": status,
            ":ts": ts,
            ":gsi1pk": f"EMPLOYMENT#{status}",
        },
    )

    try:
        audit_event(
            "employment.status_changed",
            actor_sub,
            employment_id=employment_id,
            new_status=status,
        )
    except Exception:
        pass

    updated = get_employment(employment_id)
    return updated or item
