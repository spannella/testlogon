"""Lease entity service — LSE-001 / LSE-002 / LSE-003.

Provides the full service layer for the open-property Lease subsystem:
- create_lease / get_lease / transition_status        (LSE-001)
- list_leases / update_lease / admin_list_leases      (LSE-002)
- list_leases_for_tenant / list_upcoming_expirations  (LSE-003)
- check_expiring_leases / run_leases_renewal_check_loop / start_leases_renewal_check_task (LSE-003)

All functions short-circuit on ``not S.leases_enabled`` — no table is touched and no
``if S.dev_mode`` branch exists anywhere in this module (SECOPS-007 parity).

Money movement (ledger entries, billing) is entirely out of scope — see the RNT
rent-ledger cluster for that.  The monetary fields stored on the lease item
(``monthly_rent_cents``, ``security_deposit_cents``) are informational integers only.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, send_alert_email
from app.services.profile import get_profile_identity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State-machine transition table (mirrors tickets.py:30 pattern)
# ---------------------------------------------------------------------------

_LEASE_TRANSITIONS: Dict[str, set] = {
    "draft":    {"upcoming", "active"},
    "upcoming": {"active", "ended"},
    "active":   {"ended"},
    # "ended" is terminal — no outbound edges
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _next_lease_number() -> str:
    """Atomically increment the global counter and return ``LSE-YYYY-NNNNN``."""
    year = datetime.now(timezone.utc).year
    result = T.leases.update_item(
        Key={"pk": "COUNTER", "sk": "LEASE_SEQ"},
        UpdateExpression="ADD next_seq :inc",
        ExpressionAttributeValues={":inc": 1},
        ReturnValues="UPDATED_NEW",
    )
    seq = int(result["Attributes"]["next_seq"])
    return f"LSE-{year}-{seq:05d}"


def _serialize(item: Dict[str, Any]) -> Dict[str, Any]:
    """Strip internal GSI keys and coerce DynamoDB Decimal → int for JSON."""
    _gsi_keys = {"GSI1PK", "GSI1SK", "GSI2PK", "GSI2SK"}
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if k in _gsi_keys:
            continue
        if isinstance(v, Decimal):
            out[k] = int(v)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# LSE-001 — Lease entity: create / get / transition
# ---------------------------------------------------------------------------


def create_lease(
    user_sub: str,
    *,
    tenant_id: str,
    property_id: str,
    unit_id: str,
    start_date: int,
    end_date: Optional[int] = None,
    monthly_rent_cents: int,
    security_deposit_cents: int = 0,
    rent_due_day: int,
    late_fee_type: str = "none",
    late_fee_cents: int = 0,
    late_fee_percent_bps: int = 0,
    late_fee_grace_days: int = 0,
    currency: str = "usd",
    notes: str = "",
    renewal_notice_days: int = 30,
    force_draft: bool = False,
) -> Optional[Dict[str, Any]]:
    """Create a new Lease item.

    Returns ``None`` when the feature flag is off; the router converts this to HTTP 404.
    """
    if not S.leases_enabled:
        return None

    # --- input validation ---
    if start_date <= 0:
        raise HTTPException(400, detail={"code": "invalid_date_range"})
    if end_date is not None and end_date <= start_date:
        raise HTTPException(400, detail={"code": "invalid_date_range"})
    if late_fee_type not in {"none", "flat", "percent"}:
        raise HTTPException(400, detail={"code": "invalid_late_fee_type"})
    if late_fee_type == "flat" and late_fee_cents <= 0:
        raise HTTPException(400, detail={"code": "invalid_late_fee_config"})
    if late_fee_type == "percent" and late_fee_percent_bps <= 0:
        raise HTTPException(400, detail={"code": "invalid_late_fee_config"})

    # --- derive initial status ---
    if force_draft:
        status = "draft"
    elif start_date > now_ts():
        status = "upcoming"
    else:
        status = "active"

    # --- mint identifiers ---
    lease_id = "lse_" + uuid4().hex[:16]
    lease_number = _next_lease_number()
    ts = now_ts()

    item: Dict[str, Any] = {
        "pk": f"USER#{user_sub}",
        "sk": f"LEASE#{lease_id}",
        "lease_id": lease_id,
        "lease_number": lease_number,
        "user_sub": user_sub,
        "tenant_id": tenant_id,
        "property_id": property_id,
        "unit_id": unit_id,
        "status": status,
        "start_date": start_date,
        "monthly_rent_cents": monthly_rent_cents,
        "security_deposit_cents": security_deposit_cents,
        "rent_due_day": rent_due_day,
        "late_fee_type": late_fee_type,
        "late_fee_cents": late_fee_cents,
        "late_fee_percent_bps": late_fee_percent_bps,
        "late_fee_grace_days": late_fee_grace_days,
        "currency": currency,
        "notes": notes,
        "renewal_notice_days": renewal_notice_days,
        "created_at": ts,
        "updated_at": ts,
        # GSI1 — admin / cross-user list
        "GSI1PK": "LEASES#ALL",
        "GSI1SK": ts,
        # GSI2 — per-owner status filter
        "GSI2PK": f"USER#{user_sub}#STATUS#{status}",
    }
    if end_date is not None:
        item["end_date"] = end_date
        item["GSI2SK"] = end_date  # sparse: omitted for open-ended leases

    T.leases.put_item(Item=item)

    try:
        audit_event(
            "lease.created",
            user_sub,
            lease_id=lease_id,
            lease_number=lease_number,
            status=status,
        )
    except Exception:
        logger.warning("lease.created audit_event failed", exc_info=True)

    return item


def get_lease(user_sub: str, lease_id: str) -> Optional[Dict[str, Any]]:
    """Return the lease dict or ``None`` if absent / owned by another user."""
    if not S.leases_enabled:
        return None

    resp = T.leases.get_item(Key={"pk": f"USER#{user_sub}", "sk": f"LEASE#{lease_id}"})
    item = resp.get("Item")
    if not item or item.get("user_sub") != user_sub:
        return None
    return item


def transition_status(
    user_sub: str,
    lease_id: str,
    new_status: str,
) -> Optional[Dict[str, Any]]:
    """Transition a lease's status via conditional update.

    Raises HTTP 400 for invalid transitions and HTTP 409 for concurrent conflicts.
    Returns ``None`` when the feature flag is off.
    """
    if not S.leases_enabled:
        return None

    item = get_lease(user_sub, lease_id)
    if item is None:
        raise HTTPException(404, detail={"code": "lease_not_found"})

    current_status = str(item["status"])

    allowed = _LEASE_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        raise HTTPException(
            400,
            detail={
                "code": "invalid_status_transition",
                "from": current_status,
                "to": new_status,
            },
        )

    ts = now_ts()
    new_gsi2pk = f"USER#{user_sub}#STATUS#{new_status}"

    update_parts = [
        "#s = :new_status",
        "GSI2PK = :gsi2pk",
        "updated_at = :ts",
    ]
    expr_names = {"#s": "status"}
    expr_values: Dict[str, Any] = {
        ":new_status": new_status,
        ":gsi2pk": new_gsi2pk,
        ":ts": ts,
        ":old_status": current_status,
    }

    # GSI2SK = end_date (sparse) — rewrite when present on existing item
    if "end_date" in item:
        update_parts.append("GSI2SK = :gsi2sk")
        expr_values[":gsi2sk"] = int(item["end_date"])

    update_expr = "SET " + ", ".join(update_parts)

    try:
        T.leases.update_item(
            Key={"pk": f"USER#{user_sub}", "sk": f"LEASE#{lease_id}"},
            UpdateExpression=update_expr,
            ConditionExpression="#s = :old_status",
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, detail={"code": "concurrent_update"}) from exc
        raise

    # --- best-effort unit occupancy side-effect ---
    try:
        from app.services import prop_unit as _prop_unit_svc  # type: ignore[import]
        unit_id = str(item.get("unit_id", ""))
        if unit_id:
            if new_status == "active":
                _prop_unit_svc.set_occupancy_status(unit_id, "occupied")
            elif new_status == "ended":
                _prop_unit_svc.set_occupancy_status(unit_id, "vacant")
    except (ImportError, Exception):
        pass  # PROP not yet deployed or failed — never roll back the lease transition

    try:
        audit_event(
            "lease.status_changed",
            user_sub,
            lease_id=lease_id,
            from_status=current_status,
            to_status=new_status,
        )
    except Exception:
        logger.warning("lease.status_changed audit_event failed", exc_info=True)

    return get_lease(user_sub, lease_id)


# ---------------------------------------------------------------------------
# LSE-002 — List / update / admin list
# ---------------------------------------------------------------------------


def list_leases(
    user_sub: str,
    *,
    status: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return a paginated lease list for the authenticated landlord."""
    if not S.leases_enabled:
        return None

    limit = min(limit, 200)
    esk = decode_cursor(cursor)

    # Always use the base-table partition path.
    # GSI2 has a sparse sort key (end_date), meaning open-ended leases (no end_date)
    # are absent from the GSI.  Using the base table + FilterExpression ensures
    # open-ended leases are correctly returned even when status is specified.
    # The FilterExpression does NOT reduce page size in DynamoDB, so we must
    # loop on LastEvaluatedKey (CLAUDE.md FilterExpression gotcha).
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"USER#{user_sub}"),
        "FilterExpression": Attr("sk").begins_with("LEASE#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if status is not None:
        kwargs["FilterExpression"] = (
            Attr("sk").begins_with("LEASE#") & Attr("status").eq(status)
        )
    if esk:
        kwargs["ExclusiveStartKey"] = esk

    items: List[Dict[str, Any]] = []
    last_key = None
    while len(items) < limit:
        resp = T.leases.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
        if len(items) >= limit:
            items = items[:limit]
            break

    next_cursor = encode_cursor(last_key)
    return {
        "leases": [_serialize(i) for i in items],
        "count": len(items),
        "next_cursor": next_cursor,
    }


def update_lease(
    user_sub: str,
    lease_id: str,
    *,
    end_date: Optional[int] = None,
    _end_date_set: bool = False,
    monthly_rent_cents: Optional[int] = None,
    security_deposit_cents: Optional[int] = None,
    rent_due_day: Optional[int] = None,
    late_fee_type: Optional[str] = None,
    late_fee_cents: Optional[int] = None,
    late_fee_percent_bps: Optional[int] = None,
    late_fee_grace_days: Optional[int] = None,
    currency: Optional[str] = None,
    notes: Optional[str] = None,
    renewal_notice_days: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Partially update mutable economic fields on a lease."""
    if not S.leases_enabled:
        return None

    existing = get_lease(user_sub, lease_id)
    if existing is None:
        return None  # router raises 404

    # --- late-fee cross-validation after merge ---
    eff_fee_type = late_fee_type if late_fee_type is not None else existing.get("late_fee_type", "none")
    eff_fee_cents = late_fee_cents if late_fee_cents is not None else int(existing.get("late_fee_cents", 0))
    eff_fee_bps = late_fee_percent_bps if late_fee_percent_bps is not None else int(existing.get("late_fee_percent_bps", 0))
    if eff_fee_type == "flat" and eff_fee_cents <= 0:
        raise HTTPException(400, detail={"code": "invalid_late_fee_config"})
    if eff_fee_type == "percent" and eff_fee_bps <= 0:
        raise HTTPException(400, detail={"code": "invalid_late_fee_config"})

    ts = now_ts()
    set_parts: List[str] = ["updated_at = :ts"]
    remove_parts: List[str] = []
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {":ts": ts}

    scalar_fields = {
        "monthly_rent_cents": monthly_rent_cents,
        "security_deposit_cents": security_deposit_cents,
        "rent_due_day": rent_due_day,
        "late_fee_type": late_fee_type,
        "late_fee_cents": late_fee_cents,
        "late_fee_percent_bps": late_fee_percent_bps,
        "late_fee_grace_days": late_fee_grace_days,
        "currency": currency,
        "renewal_notice_days": renewal_notice_days,
    }
    # notes is a reserved word; use expression attr name
    if notes is not None:
        expr_names["#notes"] = "notes"
        set_parts.append("#notes = :notes")
        expr_values[":notes"] = notes

    for field_name, value in scalar_fields.items():
        if value is not None:
            placeholder = f":{field_name}"
            set_parts.append(f"{field_name} = {placeholder}")
            expr_values[placeholder] = value

    # end_date handling — only when the caller explicitly set it
    if _end_date_set:
        if end_date is not None:
            set_parts.append("end_date = :end_date")
            set_parts.append("GSI2SK = :gsi2sk")
            expr_values[":end_date"] = end_date
            expr_values[":gsi2sk"] = end_date
        else:
            # explicitly clearing end_date (open-ended conversion)
            remove_parts.extend(["end_date", "GSI2SK"])

    # no-op check
    has_changes = len(set_parts) > 1 or remove_parts  # >1 because updated_at always included
    if not has_changes:
        return _serialize(existing)

    update_expr = "SET " + ", ".join(set_parts)
    if remove_parts:
        update_expr += " REMOVE " + ", ".join(remove_parts)

    update_kwargs: Dict[str, Any] = {
        "Key": {"pk": f"USER#{user_sub}", "sk": f"LEASE#{lease_id}"},
        "UpdateExpression": update_expr,
        "ExpressionAttributeValues": expr_values,
    }
    if expr_names:
        update_kwargs["ExpressionAttributeNames"] = expr_names

    T.leases.update_item(**update_kwargs)

    fields_changed = [k for k, v in scalar_fields.items() if v is not None]
    if notes is not None:
        fields_changed.append("notes")
    if _end_date_set:
        fields_changed.append("end_date")

    try:
        audit_event(
            "lease.updated",
            user_sub,
            lease_id=lease_id,
            fields_changed=fields_changed,
        )
    except Exception:
        logger.warning("lease.updated audit_event failed", exc_info=True)

    return get_lease(user_sub, lease_id)


def admin_list_leases(
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Cross-owner admin view via GSI1 (caller must be ADMIN or ROOT)."""
    if not S.leases_enabled:
        return None

    limit = min(limit, 200)
    esk = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "IndexName": "leases-all-index",
        "KeyConditionExpression": Key("GSI1PK").eq("LEASES#ALL"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk

    resp = T.leases.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")

    return {
        "leases": [_serialize(i) for i in items],
        "count": len(items),
        "next_cursor": encode_cursor(last_key),
    }


# ---------------------------------------------------------------------------
# LSE-003 — Tenant history + expiration query + renewal loop
# ---------------------------------------------------------------------------


def list_leases_for_tenant(
    user_sub: str,
    tenant_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return all leases (any status) for a single tenant, scoped to this landlord."""
    if not S.leases_enabled:
        return None

    limit = min(limit, 200)
    esk = decode_cursor(cursor)
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"USER#{user_sub}") & Key("sk").begins_with("LEASE#")
        ),
        "FilterExpression": Attr("tenant_id").eq(tenant_id),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if esk:
        kwargs["ExclusiveStartKey"] = esk

    accumulated: List[Dict[str, Any]] = []
    last_key = None
    # Loop because FilterExpression doesn't reduce the DynamoDB page size
    while len(accumulated) < limit:
        resp = T.leases.query(**kwargs)
        accumulated.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
        if len(accumulated) >= limit:
            accumulated = accumulated[:limit]
            break

    # Application-level sort: newest start_date first
    accumulated.sort(key=lambda x: int(x.get("start_date", 0)), reverse=True)

    return {
        "leases": [_serialize(i) for i in accumulated],
        "count": len(accumulated),
        "next_cursor": encode_cursor(last_key),
    }


def list_upcoming_expirations(
    user_sub: str,
    *,
    within_days: int = 60,
    limit: int = 50,
) -> Optional[List[Dict[str, Any]]]:
    """Return active leases expiring within ``within_days`` days (per-owner)."""
    if not S.leases_enabled:
        return []

    within_days = max(1, min(within_days, 365))
    limit = min(limit, 200)
    now = now_ts()
    window_end = now + within_days * 86400

    resp = T.leases.query(
        IndexName="leases-by-status-index",
        KeyConditionExpression=(
            Key("GSI2PK").eq(f"USER#{user_sub}#STATUS#active")
            & Key("GSI2SK").between(now, window_end)
        ),
        ScanIndexForward=True,  # earliest-expiring first
        Limit=limit,
    )
    return [_serialize(i) for i in resp.get("Items", [])]


def _send_renewal_notice(item: Dict[str, Any], days_remaining: int) -> None:
    """Send a single renewal notice email and write the idempotency marker."""
    ts = now_ts()
    lease_id = str(item.get("lease_id", ""))
    user_sub = str(item.get("user_sub", ""))
    lease_number = str(item.get("lease_number", ""))

    try:
        identity = get_profile_identity(user_sub)
        email = (identity or {}).get("email")
    except Exception:
        email = None

    if not email:
        logger.warning(
            "lease renewal notice: no email for user_sub=%s lease_id=%s — skipping send",
            user_sub,
            lease_id,
        )
        # Still write the marker so we don't retry endlessly
        _write_renewal_marker(item, ts)
        return

    try:
        subject = f"Lease {lease_number} expires in {days_remaining} day(s)"
        body = (
            f"Your lease {lease_number} is expiring in {days_remaining} day(s).\n"
            f"Lease ID: {lease_id}\n"
            f"Please take action to renew or end the tenancy.\n"
        )
        send_alert_email([email], subject, body)
    except Exception:
        # Let the exception propagate so the loop retries on next cycle
        # (idempotency marker is NOT written on failure)
        raise

    _write_renewal_marker(item, ts)

    try:
        audit_event(
            "lease.renewal_notified",
            user_sub,
            lease_id=lease_id,
            lease_number=lease_number,
            days_remaining=days_remaining,
        )
    except Exception:
        logger.warning("lease.renewal_notified audit_event failed", exc_info=True)


def _write_renewal_marker(item: Dict[str, Any], ts: int) -> None:
    """Conditionally write the renewal_notified_at marker (idempotent)."""
    try:
        T.leases.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET renewal_notified_at = :ts",
            ConditionExpression="attribute_not_exists(renewal_notified_at)",
            ExpressionAttributeValues={":ts": ts},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            pass  # concurrent sweep already wrote the marker — silent
        else:
            logger.warning("Failed to write renewal_notified_at: %s", exc)


def check_expiring_leases() -> int:
    """Cross-user sweep: send renewal notices for qualifying active leases.

    Returns the count of notices sent.
    """
    if not S.leases_renewal_notifications_enabled:
        return 0
    if not S.leases_enabled:
        return 0

    now = now_ts()
    sweep_end = now + 90 * 86400
    count = 0
    lek = None

    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "leases-all-index",
            "KeyConditionExpression": Key("GSI1PK").eq("LEASES#ALL"),
            "FilterExpression": (
                Attr("status").eq("active")
                & Attr("end_date").between(now, sweep_end)
            ),
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek

        resp = T.leases.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("renewal_notified_at"):
                continue  # idempotency gate

            days_remaining = (int(item["end_date"]) - now) // 86400
            notice_window = int(item.get("renewal_notice_days", 30))
            if days_remaining > notice_window:
                continue  # not yet in the notification window

            _send_renewal_notice(item, days_remaining)
            count += 1

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break

    return count


async def run_leases_renewal_check_loop(*, poll_interval: Optional[int] = None) -> None:
    """Async background loop — clone of compute_billing.py:653 pattern."""
    interval = poll_interval if poll_interval is not None else S.leases_renewal_check_interval_seconds
    while True:
        try:
            check_expiring_leases()
        except Exception:
            logger.exception("leases_renewal_check_loop error")
        await asyncio.sleep(interval)


def start_leases_renewal_check_task() -> None:
    """Register the background renewal-notice loop at startup (gated on both flags)."""
    if S.leases_enabled and S.leases_renewal_notifications_enabled:
        asyncio.ensure_future(run_leases_renewal_check_loop())
        logger.info(
            "Leases renewal check loop started (interval=%ds)",
            S.leases_renewal_check_interval_seconds,
        )
