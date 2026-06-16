"""AOS CRM Contract entity service (QUO-004).

Contract CRUD + stage machine on the ``aos_contracts`` DynamoDB table, plus a
background renewal-notification checker. Gated behind ``S.aos_contracts_enabled``
(default OFF). Money is integer cents; no billing-ledger interaction here.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, send_alert_email

logger = logging.getLogger(__name__)

VALID_STAGES = {"draft", "active", "expired", "terminated", "renewed"}

_ALLOWED_TRANSITIONS: Dict[str, set] = {
    "draft": {"active"},
    "active": {"expired", "terminated", "renewed"},
}

_MAX_NOTICE_SCAN_DAYS = 90


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _contract_sk(contract_id: str) -> str:
    return f"CONTRACT#{contract_id}"


def _clean_lek(lek: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not lek:
        return None
    return {k: (int(v) if isinstance(v, Decimal) else v) for k, v in lek.items()}


def _next_contract_number() -> str:
    from datetime import datetime, timezone
    year = datetime.now(timezone.utc).year
    result = T.aos_contracts.update_item(
        Key={"pk": "COUNTER", "sk": "CONTRACT_SEQ"},
        UpdateExpression="ADD next_seq :inc",
        ExpressionAttributeValues={":inc": 1},
        ReturnValues="UPDATED_NEW",
    )
    seq = int(result["Attributes"]["next_seq"])
    return f"CON-{year}-{seq:05d}"


def _serialize(item: Dict[str, Any]) -> Dict[str, Any]:
    end_date = item.get("end_date")
    notified = item.get("renewal_notified_at")
    return {
        "contract_id": str(item.get("contract_id") or ""),
        "contract_number": str(item.get("contract_number") or ""),
        "title": str(item.get("title") or ""),
        "stage": str(item.get("stage") or "draft"),
        "account_id": str(item.get("account_id") or ""),
        "contact_id": str(item.get("contact_id") or ""),
        "aos_quote_id": str(item.get("aos_quote_id") or ""),
        "start_date": _coerce_int(item.get("start_date")),
        "end_date": _coerce_int(end_date) if end_date is not None else None,
        "value_cents": _coerce_int(item.get("value_cents")),
        "currency": str(item.get("currency") or "usd"),
        "description": str(item.get("description") or ""),
        "renewal_notice_days": _coerce_int(item.get("renewal_notice_days"), 30),
        "renewal_notified_at": _coerce_int(notified) if notified is not None else None,
        "billing_address": dict(item.get("billing_address") or {}),
        "shipping_address": dict(item.get("shipping_address") or {}),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }


def create_contract(
    user_sub: str,
    *,
    title: str,
    start_date: int,
    end_date: Optional[int] = None,
    value_cents: int = 0,
    currency: str = "usd",
    description: str = "",
    account_id: str = "",
    contact_id: str = "",
    aos_quote_id: str = "",
    renewal_notice_days: int = 30,
    billing_address: Optional[Dict[str, Any]] = None,
    shipping_address: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not S.aos_contracts_enabled:
        return None
    title = (title or "").strip()
    if not title:
        raise ValueError("title is required")
    start_date = _coerce_int(start_date)
    if start_date <= 0:
        raise ValueError("start_date must be a positive integer")
    if end_date is not None:
        end_date = _coerce_int(end_date)
        if end_date <= start_date:
            raise ValueError("end_date must be after start_date")

    contract_number = _next_contract_number()
    contract_id = "con_" + uuid.uuid4().hex[:16]
    ts = now_ts()
    stage = "draft"
    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _contract_sk(contract_id),
        "contract_id": contract_id,
        "contract_number": contract_number,
        "user_sub": user_sub,
        "title": title,
        "stage": stage,
        "account_id": account_id or "",
        "contact_id": contact_id or "",
        "aos_quote_id": aos_quote_id or "",
        "start_date": start_date,
        "value_cents": _coerce_int(value_cents),
        "currency": (currency or "usd").lower(),
        "description": description or "",
        "renewal_notice_days": _coerce_int(renewal_notice_days, 30),
        "billing_address": dict(billing_address or {}),
        "shipping_address": dict(shipping_address or {}),
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": "CONTRACTS#ALL",
        "GSI1SK": ts,
    }
    if end_date is not None:
        item["end_date"] = end_date
        item["GSI2PK"] = f"USER#{user_sub}#STAGE#{stage}"
        item["GSI2SK"] = end_date

    T.aos_contracts.put_item(Item=item)
    audit_event(
        "contract.created", user_sub,
        contract_id=contract_id, contract_number=contract_number,
    )
    return _serialize(item)


def _get_raw(user_sub: str, contract_id: str) -> Optional[Dict[str, Any]]:
    resp = T.aos_contracts.get_item(Key={"pk": _user_pk(user_sub), "sk": _contract_sk(contract_id)})
    return resp.get("Item")


def get_contract(user_sub: str, contract_id: str) -> Optional[Dict[str, Any]]:
    if not S.aos_contracts_enabled:
        return None
    item = _get_raw(user_sub, contract_id)
    return _serialize(item) if item else None


def list_contracts(
    user_sub: str,
    *,
    stage: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not S.aos_contracts_enabled:
        return None
    limit = max(1, min(int(limit or 50), 200))
    query: Dict[str, Any] = {"ScanIndexForward": False, "Limit": limit}
    if stage:
        query["IndexName"] = "contracts-by-stage-index"
        query["KeyConditionExpression"] = "GSI2PK = :pk"
        query["ExpressionAttributeValues"] = {":pk": f"USER#{user_sub}#STAGE#{stage}"}
    else:
        query["KeyConditionExpression"] = "pk = :pk AND begins_with(sk, :sk)"
        query["ExpressionAttributeValues"] = {":pk": _user_pk(user_sub), ":sk": "CONTRACT#"}
    start_key = decode_cursor(cursor)
    if start_key:
        query["ExclusiveStartKey"] = start_key
    resp = T.aos_contracts.query(**query)
    contracts = [_serialize(it) for it in resp.get("Items", [])]
    return {
        "contracts": contracts,
        "count": len(contracts),
        "next_cursor": encode_cursor(_clean_lek(resp.get("LastEvaluatedKey"))),
    }


def update_contract(
    user_sub: str,
    contract_id: str,
    *,
    title: Optional[str] = None,
    end_date: Optional[int] = None,
    value_cents: Optional[int] = None,
    currency: Optional[str] = None,
    description: Optional[str] = None,
    renewal_notice_days: Optional[int] = None,
    billing_address: Optional[Dict[str, Any]] = None,
    shipping_address: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not S.aos_contracts_enabled:
        return None
    item = _get_raw(user_sub, contract_id)
    if not item:
        return None

    if title is not None:
        item["title"] = title
    if end_date is not None:
        ed = _coerce_int(end_date)
        item["end_date"] = ed
        # keep GSI2 (stage + expiry) consistent if the contract has a stage
        item["GSI2PK"] = f"USER#{user_sub}#STAGE#{item.get('stage', 'draft')}"
        item["GSI2SK"] = ed
    if value_cents is not None:
        item["value_cents"] = _coerce_int(value_cents)
    if currency is not None:
        item["currency"] = str(currency).lower()
    if description is not None:
        item["description"] = description
    if renewal_notice_days is not None:
        item["renewal_notice_days"] = _coerce_int(renewal_notice_days, 30)
    if billing_address is not None:
        item["billing_address"] = dict(billing_address)
    if shipping_address is not None:
        item["shipping_address"] = dict(shipping_address)

    item["updated_at"] = now_ts()
    T.aos_contracts.put_item(Item=item)
    audit_event("contract.updated", user_sub, contract_id=contract_id)
    return _serialize(item)


def transition_stage(user_sub: str, contract_id: str, new_stage: str) -> Optional[Dict[str, Any]]:
    if not S.aos_contracts_enabled:
        return None
    item = _get_raw(user_sub, contract_id)
    if not item:
        return None
    current = str(item.get("stage") or "draft")
    if new_stage == current:
        return _serialize(item)
    if new_stage not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_stage_transition", "from": current, "to": new_stage},
        )
    try:
        update_kwargs: Dict[str, Any] = {
            "Key": {"pk": _user_pk(user_sub), "sk": _contract_sk(contract_id)},
            "UpdateExpression": "SET #s = :new, GSI2PK = :gpk, updated_at = :t",
            "ConditionExpression": "#s = :old",
            "ExpressionAttributeNames": {"#s": "stage"},
            "ExpressionAttributeValues": {
                ":new": new_stage,
                ":old": current,
                ":gpk": f"USER#{user_sub}#STAGE#{new_stage}",
                ":t": now_ts(),
            },
        }
        T.aos_contracts.update_item(**update_kwargs)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail={"code": "concurrent_update"})
        raise
    audit_event(
        "contract.stage_changed", user_sub,
        contract_id=contract_id, from_stage=current, to_stage=new_stage,
    )
    return get_contract(user_sub, contract_id)


def admin_list_contracts(*, limit: int = 50, cursor: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not S.aos_contracts_enabled:
        return None
    limit = max(1, min(int(limit or 50), 200))
    query: Dict[str, Any] = {
        "IndexName": "contracts-all-index",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": "CONTRACTS#ALL"},
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        query["ExclusiveStartKey"] = start_key
    resp = T.aos_contracts.query(**query)
    contracts = [_serialize(it) for it in resp.get("Items", [])]
    return {
        "contracts": contracts,
        "count": len(contracts),
        "next_cursor": encode_cursor(_clean_lek(resp.get("LastEvaluatedKey"))),
    }


def check_expiring_contracts() -> int:
    """Scan active contracts approaching end_date and send a renewal email
    once. Returns the count of notifications sent."""
    if not (S.aos_contracts_enabled and S.aos_contracts_renewal_notifications_enabled):
        return 0
    now = now_ts()
    threshold = now + _MAX_NOTICE_SCAN_DAYS * 86400
    sent = 0
    lek = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "contracts-all-index",
            "KeyConditionExpression": "GSI1PK = :pk",
            "FilterExpression": "stage = :st AND end_date BETWEEN :now AND :thr",
            "ExpressionAttributeValues": {
                ":pk": "CONTRACTS#ALL",
                ":st": "active",
                ":now": now,
                ":thr": threshold,
            },
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.aos_contracts.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("renewal_notified_at") is not None:
                continue
            end_date = _coerce_int(item.get("end_date"))
            if end_date <= 0:
                continue
            notice_days = _coerce_int(item.get("renewal_notice_days"), 30)
            if (end_date - now) > notice_days * 86400:
                continue
            owner_sub = str(item.get("user_sub") or "")
            contract_number = str(item.get("contract_number") or "")
            owner_email = owner_sub
            try:
                from app.services.profile import get_profile_identity
                ident = get_profile_identity(owner_sub)
                owner_email = ident.get("email") or owner_sub
            except Exception:
                owner_email = owner_sub
            days_left = max(0, (end_date - now) // 86400)
            subject = f"Contract {contract_number} expires in {days_left} days"
            body = (
                f"Contract: {item.get('title', '')}\n"
                f"Number  : {contract_number}\n"
                f"Expires : {end_date}\n"
                f"Value   : {_coerce_int(item.get('value_cents'))} cents "
                f"{str(item.get('currency') or 'usd').upper()}\n"
            )
            try:
                send_alert_email([owner_email], subject, body)
            except Exception:  # pragma: no cover
                logger.warning("renewal email failed for %s", contract_number, exc_info=True)
            try:
                T.aos_contracts.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression="SET renewal_notified_at = :t",
                    ExpressionAttributeValues={":t": now_ts()},
                )
            except Exception:  # pragma: no cover
                pass
            audit_event(
                "contract.renewal_notified", owner_sub,
                contract_id=str(item.get("contract_id") or ""), end_date=end_date,
            )
            sent += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    return sent


async def run_contracts_renewal_check_loop(*, poll_interval: Optional[int] = None) -> None:
    interval = (
        poll_interval if poll_interval is not None
        else S.aos_contracts_renewal_check_interval_seconds
    )
    while True:
        try:
            check_expiring_contracts()
        except Exception:  # pragma: no cover
            logger.exception("contracts_renewal_check error")
        await asyncio.sleep(interval)


def start_contracts_renewal_check_task() -> None:
    if S.aos_contracts_enabled and S.aos_contracts_renewal_notifications_enabled:
        asyncio.ensure_future(run_contracts_renewal_check_loop())
        logger.info(
            "Contracts renewal checker started (interval=%ds)",
            S.aos_contracts_renewal_check_interval_seconds,
        )
