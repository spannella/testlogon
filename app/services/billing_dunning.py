from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.billing_shared import compute_due, ddb_get, ddb_update, user_pk

logger = logging.getLogger(__name__)


def _retry_schedule_seconds() -> List[int]:
    raw = S.billing_dunning_retry_schedule_seconds
    out: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(max(60, int(part)))
        except ValueError:
            continue
    return out or [3600, 86400, 172800]


def _dunning_sk(next_attempt_ts: int) -> str:
    return f"DUNNING#{next_attempt_ts}#{uuid.uuid4().hex}"


def schedule_dunning(
    *,
    user_id: str,
    provider: str,
    amount_cents: int,
    reason: str,
    payment_ref: Optional[str],
    next_attempt_ts: Optional[int] = None,
) -> None:
    ts = now_ts()
    next_ts = next_attempt_ts or ts
    pk = user_pk(user_id)
    item = {
        "pk": pk,
        "sk": _dunning_sk(next_ts),
        "provider": provider,
        "amount_cents": int(amount_cents),
        "reason": reason,
        "payment_ref": payment_ref,
        "status": "pending",
        "retry_count": 0,
        "next_attempt_ts": next_ts,
        "created_at": ts,
        "updated_at": ts,
    }
    if S.ddb_ttl_attr:
        item[S.ddb_ttl_attr] = ts + 60 * 60 * 24 * 30
    T.billing.put_item(Item=item)


def schedule_ccbill_dunning(
    *,
    user_sub: str,
    amount_cents: int,
    reason: str,
    payment_ref: Optional[str],
    next_attempt_ts: Optional[int] = None,
) -> None:
    ts = now_ts()
    next_ts = next_attempt_ts or ts
    item = {
        "user_sub": user_sub,
        "sk": _dunning_sk(next_ts),
        "provider": "ccbill",
        "amount_cents": int(amount_cents),
        "reason": reason,
        "payment_ref": payment_ref,
        "status": "pending",
        "retry_count": 0,
        "next_attempt_ts": next_ts,
        "created_at": ts,
        "updated_at": ts,
    }
    if S.ddb_ttl_attr:
        item[S.ddb_ttl_attr] = ts + 60 * 60 * 24 * 30
    T.billing.put_item(Item=item)


def schedule_autopay_disabled_notice(user_id: str, provider: str) -> None:
    pk = user_pk(user_id)
    bal = ddb_get(T.billing, pk, "BALANCE") or {}
    due = compute_due(bal)
    due_cents = int(due.get("due_settled_cents", 0))
    if due_cents <= 0:
        return
    schedule_dunning(
        user_id=user_id,
        provider=provider,
        amount_cents=due_cents,
        reason="autopay_disabled",
        payment_ref=None,
        next_attempt_ts=now_ts() + _retry_schedule_seconds()[0],
    )
    audit_event(
        "billing_dunning_autopay_disabled",
        user_id,
        None,
        outcome="info",
        provider=provider,
        amount_cents=due_cents,
    )


def schedule_ccbill_autopay_disabled_notice(user_sub: str) -> None:
    bal = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BALANCE"}).get("Item") or {}
    due = compute_due(bal)
    due_cents = int(due.get("due_settled_cents", 0))
    if due_cents <= 0:
        return
    schedule_ccbill_dunning(
        user_sub=user_sub,
        amount_cents=due_cents,
        reason="autopay_disabled",
        payment_ref=None,
        next_attempt_ts=now_ts() + _retry_schedule_seconds()[0],
    )
    audit_event(
        "billing_dunning_autopay_disabled",
        user_sub,
        None,
        outcome="info",
        provider="ccbill",
        amount_cents=due_cents,
    )


def bump_dunning_after_payment_method_update(user_id: str, provider: str) -> None:
    schedule_dunning(
        user_id=user_id,
        provider=provider,
        amount_cents=0,
        reason="payment_method_updated",
        payment_ref=None,
        next_attempt_ts=now_ts(),
    )


def _scan_dunning_items(limit: int) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    filter_expr = Attr("sk").begins_with("DUNNING#") & Attr("status").eq("pending") & Attr("next_attempt_ts").lte(now_ts())
    while len(items) < limit:
        scan_kwargs: Dict[str, Any] = {"FilterExpression": filter_expr, "Limit": min(200, limit - len(items))}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = T.billing.scan(**scan_kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def _update_dunning(item: Dict[str, Any], *, status: str, retry_count: int, next_attempt_ts: Optional[int] = None) -> None:
    key: Dict[str, Any] = {"sk": item["sk"]}
    if "pk" in item:
        key["pk"] = item["pk"]
        key_name = "pk"
    else:
        key["user_sub"] = item["user_sub"]
        key_name = "user_sub"
    values = {":s": status, ":u": now_ts(), ":r": retry_count}
    expr = "SET #s = :s, updated_at = :u, retry_count = :r"
    if next_attempt_ts is not None:
        values[":n"] = next_attempt_ts
        expr += ", next_attempt_ts = :n"
    T.billing.update_item(
        Key=key,
        UpdateExpression=expr,
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues=values,
    )


def _attempt_stripe_autopay(user_id: str, amount_cents: Optional[int]) -> bool:
    from app.models import PayBalanceReq
    from app.routers import billing as stripe_router

    try:
        stripe_router.pay_balance(PayBalanceReq(amount_cents=amount_cents), req=None, ctx={"user_sub": user_id})
        return True
    except Exception as exc:
        logger.warning("Stripe dunning retry failed", extra={"user_id": user_id}, exc_info=exc)
        return False


def _attempt_ccbill_autopay(user_sub: str, amount_cents: Optional[int]) -> bool:
    from app.services import billing_ccbill

    try:
        billing_ccbill.pay_balance(
            user_sub=user_sub,
            amount_cents=amount_cents,
            idempotency_key=None,
            request=None,
        )
        return True
    except Exception as exc:
        logger.warning("CCBill dunning retry failed", extra={"user_sub": user_sub}, exc_info=exc)
        return False


def process_dunning_queue() -> None:
    schedule = _retry_schedule_seconds()
    for item in _scan_dunning_items(int(S.billing_dunning_scan_limit)):
        provider = item.get("provider", "")
        retry_count = int(item.get("retry_count", 0))

        user_id = None
        user_sub = None
        if "pk" in item:
            pk = item.get("pk")
            if isinstance(pk, str) and pk.startswith("USER#"):
                user_id = pk.split("USER#", 1)[1]
        if "user_sub" in item:
            user_sub = item.get("user_sub")

        if provider == "stripe" and user_id:
            billing = ddb_get(T.billing, user_pk(user_id), "BILLING") or {}
            if not billing.get("autopay_enabled", False):
                audit_event("billing_dunning_autopay_disabled", user_id, None, outcome="info", provider="stripe")
                next_ts = now_ts() + schedule[min(retry_count, len(schedule) - 1)]
                _update_dunning(item, status="pending", retry_count=retry_count + 1, next_attempt_ts=next_ts)
                continue
            if not billing.get("default_payment_method_id"):
                audit_event("billing_dunning_missing_payment_method", user_id, None, outcome="info", provider="stripe")
                next_ts = now_ts() + schedule[min(retry_count, len(schedule) - 1)]
                _update_dunning(item, status="pending", retry_count=retry_count + 1, next_attempt_ts=next_ts)
                continue
            ok = _attempt_stripe_autopay(user_id, item.get("amount_cents"))
            if ok:
                _update_dunning(item, status="completed", retry_count=retry_count)
                audit_event("billing_dunning_succeeded", user_id, None, outcome="success", provider="stripe")
            else:
                next_ts = now_ts() + schedule[min(retry_count, len(schedule) - 1)]
                _update_dunning(item, status="pending", retry_count=retry_count + 1, next_attempt_ts=next_ts)
                audit_event("billing_dunning_retry_scheduled", user_id, None, outcome="failure", provider="stripe")
        elif provider == "ccbill" and user_sub:
            billing = T.billing.get_item(Key={"user_sub": user_sub, "sk": "BILLING"}).get("Item") or {}
            if not billing.get("autopay_enabled", False):
                audit_event("billing_dunning_autopay_disabled", user_sub, None, outcome="info", provider="ccbill")
                next_ts = now_ts() + schedule[min(retry_count, len(schedule) - 1)]
                _update_dunning(item, status="pending", retry_count=retry_count + 1, next_attempt_ts=next_ts)
                continue
            if not billing.get("default_payment_token_id"):
                audit_event("billing_dunning_missing_payment_method", user_sub, None, outcome="info", provider="ccbill")
                next_ts = now_ts() + schedule[min(retry_count, len(schedule) - 1)]
                _update_dunning(item, status="pending", retry_count=retry_count + 1, next_attempt_ts=next_ts)
                continue
            ok = _attempt_ccbill_autopay(user_sub, item.get("amount_cents"))
            if ok:
                _update_dunning(item, status="completed", retry_count=retry_count)
                audit_event("billing_dunning_succeeded", user_sub, None, outcome="success", provider="ccbill")
            else:
                next_ts = now_ts() + schedule[min(retry_count, len(schedule) - 1)]
                _update_dunning(item, status="pending", retry_count=retry_count + 1, next_attempt_ts=next_ts)
                audit_event("billing_dunning_retry_scheduled", user_sub, None, outcome="failure", provider="ccbill")
        else:
            _update_dunning(item, status="skipped", retry_count=retry_count)


async def billing_dunning_loop() -> None:
    interval = max(60, int(S.billing_dunning_interval_seconds))
    while True:
        try:
            process_dunning_queue()
        except Exception:
            logger.exception("Billing dunning loop failed")
        await asyncio.sleep(interval)


def start_billing_dunning_task() -> None:
    if not S.billing_dunning_enabled:
        logger.info("Billing dunning disabled")
        return
    asyncio.create_task(billing_dunning_loop())
