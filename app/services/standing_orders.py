"""OBP PAY-002 — Standing orders (recurring outbound payment) + scheduler executor.

A standing order = "pay counterparty X, amount Y, every cadence Z". On each due tick the
executor emits a ``type=COUNTERPARTY`` Transaction Request via the TXR rail (PAY never
debits the wallet — money-safety #1). Due selection reuses the ``scheduled_actions``
ByDue range-query + conditional-claim discipline; on pause/complete/cancel the due-GSI
keys are REMOVEd so the runner never re-selects (mirrors ``scheduled_actions.cancel_action``).

Money-safety:
- #2 deterministic ``idempotency_key = "{standing_order_id}#{next_run_at}"`` → at most one request per occurrence.
- #3 ``next_run_at`` advances ONLY via a conditional ``update_item`` asserting the prior value (two concurrent ticks → one advances, loser no-ops).
- #5 non-usd counterparty amounts are FX-converted to usd and the rate is stamped on the request ``meta`` (no non-usd ledger row).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_DAY = 86400
_CADENCE_SECONDS = {
    "weekly": 7 * _DAY,
    "biweekly": 14 * _DAY,
    "monthly": 30 * _DAY,  # approximate month; matches scheduled_actions' fixed-interval discipline
}


class StandingOrderError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _so_id() -> str:
    return f"so_{uuid.uuid4().hex}"


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def next_occurrence(cadence: str, from_ts: int) -> int:
    step = _CADENCE_SECONDS.get(cadence)
    if step is None:
        raise StandingOrderError("invalid_cadence", cadence)
    return int(from_ts) + step


def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "standing_order_id": item.get("standing_order_id", ""),
        "counterparty_id": item.get("counterparty_id", ""),
        "amount_cents": _to_int(item.get("amount_cents", 0)),
        "currency": item.get("currency", "usd"),
        "cadence": item.get("cadence", ""),
        "status": item.get("status", "active"),
        "next_run_at": _to_int(item.get("next_run_at")) if item.get("next_run_at") is not None else None,
        "last_run_at": _to_int(item.get("last_run_at")) if item.get("last_run_at") is not None else None,
        "runs_count": _to_int(item.get("runs_count", 0)),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }


def _require_owned_counterparty(user_sub: str, counterparty_id: str) -> Dict[str, Any]:
    from app.services import counterparties

    cp = counterparties.get_counterparty(user_sub, counterparty_id)
    if not cp:
        raise StandingOrderError("counterparty_not_found", "counterparty not found or not yours")
    return cp


def create_standing_order(user_sub: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    counterparty_id = payload["counterparty_id"]
    _require_owned_counterparty(user_sub, counterparty_id)
    cadence = payload["cadence"]
    if cadence not in _CADENCE_SECONDS:
        raise StandingOrderError("invalid_cadence", cadence)
    ts = now_ts()
    start_at = _to_int(payload.get("start_at", ts), ts)
    next_run_at = max(start_at, ts)
    so_id = _so_id()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "standing_order_id": so_id,
        "counterparty_id": counterparty_id,
        "amount_cents": _to_int(payload["amount_cents"]),
        "currency": payload.get("currency", "usd"),
        "cadence": cadence,
        "status": "active",
        "start_at": start_at,
        "end_at": _to_int(payload["end_at"]) if payload.get("end_at") is not None else None,
        "reason": payload.get("reason") or "",
        "next_run_at": next_run_at,
        "last_run_at": None,
        "runs_count": 0,
        # Due-index keys (mirrors scheduled_actions GSI_DUE_PK / GSI_DUE_SK).
        "GSI_DUE_PK": "DUE",
        "created_at": ts,
        "updated_at": ts,
    }
    T.standing_orders.put_item(Item=item)
    _audit("standing_order.created", user_sub, standing_order_id=so_id, counterparty_id=counterparty_id)
    return _to_out(item)


def get_standing_order(user_sub: str, standing_order_id: str) -> Optional[Dict[str, Any]]:
    resp = T.standing_orders.get_item(Key={"user_sub": user_sub, "standing_order_id": standing_order_id})
    return resp.get("Item") or None


def get_standing_order_out(user_sub: str, standing_order_id: str) -> Optional[Dict[str, Any]]:
    item = get_standing_order(user_sub, standing_order_id)
    return _to_out(item) if item else None


def list_standing_orders(
    user_sub: str, *, limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_sub").eq(user_sub),
        "Limit": max(1, min(limit, 200)),
    }
    start = decode_cursor(cursor)
    if start:
        query_kwargs["ExclusiveStartKey"] = start
    resp = T.standing_orders.query(**query_kwargs)
    items = sorted(resp.get("Items", []), key=lambda x: _to_int(x.get("created_at", 0)), reverse=True)
    return [_to_out(it) for it in items], encode_cursor(resp.get("LastEvaluatedKey"))


def update_standing_order(user_sub: str, standing_order_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    existing = get_standing_order(user_sub, standing_order_id)
    if not existing:
        return None
    if payload.get("paused") is True:
        return pause(user_sub, standing_order_id)
    if payload.get("paused") is False:
        return resume(user_sub, standing_order_id)
    sets: Dict[str, Any] = {"updated_at": now_ts()}
    if payload.get("amount_cents") is not None:
        sets["amount_cents"] = _to_int(payload["amount_cents"])
    if payload.get("cadence") is not None:
        if payload["cadence"] not in _CADENCE_SECONDS:
            raise StandingOrderError("invalid_cadence", payload["cadence"])
        sets["cadence"] = payload["cadence"]
    if payload.get("end_at") is not None:
        sets["end_at"] = _to_int(payload["end_at"])
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    parts = []
    for i, (k, v) in enumerate(sets.items()):
        names[f"#f{i}"], values[f":v{i}"] = k, v
        parts.append(f"#f{i} = :v{i}")
    T.standing_orders.update_item(
        Key={"user_sub": user_sub, "standing_order_id": standing_order_id},
        UpdateExpression="SET " + ", ".join(parts),
        ConditionExpression="attribute_exists(standing_order_id)",
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    _audit("standing_order.updated", user_sub, standing_order_id=standing_order_id)
    return get_standing_order_out(user_sub, standing_order_id)


def pause(user_sub: str, standing_order_id: str) -> Optional[Dict[str, Any]]:
    existing = get_standing_order(user_sub, standing_order_id)
    if not existing:
        return None
    T.standing_orders.update_item(
        Key={"user_sub": user_sub, "standing_order_id": standing_order_id},
        UpdateExpression="SET #status = :paused, updated_at = :now REMOVE GSI_DUE_PK, next_run_at",
        ConditionExpression="#status = :active",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":paused": "paused", ":active": "active", ":now": now_ts()},
    )
    _audit("standing_order.paused", user_sub, standing_order_id=standing_order_id)
    return get_standing_order_out(user_sub, standing_order_id)


def resume(user_sub: str, standing_order_id: str) -> Optional[Dict[str, Any]]:
    existing = get_standing_order(user_sub, standing_order_id)
    if not existing:
        return None
    cadence = existing.get("cadence", "monthly")
    now = now_ts()
    next_run_at = max(_to_int(existing.get("next_run_at", now), now), now)
    if next_run_at <= now:
        next_run_at = next_occurrence(cadence, now)
    T.standing_orders.update_item(
        Key={"user_sub": user_sub, "standing_order_id": standing_order_id},
        UpdateExpression="SET #status = :active, GSI_DUE_PK = :due, next_run_at = :nra, updated_at = :now",
        ConditionExpression="#status = :paused",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":active": "active", ":paused": "paused", ":due": "DUE",
            ":nra": next_run_at, ":now": now,
        },
    )
    _audit("standing_order.resumed", user_sub, standing_order_id=standing_order_id)
    return get_standing_order_out(user_sub, standing_order_id)


def cancel(user_sub: str, standing_order_id: str) -> Optional[Dict[str, Any]]:
    existing = get_standing_order(user_sub, standing_order_id)
    if not existing:
        return None
    T.standing_orders.update_item(
        Key={"user_sub": user_sub, "standing_order_id": standing_order_id},
        UpdateExpression="SET #status = :cancelled, updated_at = :now REMOVE GSI_DUE_PK, next_run_at",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":cancelled": "cancelled", ":now": now_ts()},
    )
    _audit("standing_order.cancelled", user_sub, standing_order_id=standing_order_id)
    return get_standing_order_out(user_sub, standing_order_id)


def execute_due_standing_order(user_sub: str, standing_order_id: str) -> Dict[str, Any]:
    """Execute one due occurrence: emit a COUNTERPARTY TXR + conditionally advance.

    Returns a small result dict ``{action, request_emitted: bool}``. NEVER debits the
    wallet itself (money-safety #1).
    """
    item = get_standing_order(user_sub, standing_order_id)
    if not item or item.get("status") != "active":
        return {"action": "noop", "request_emitted": False}
    prev_next = _to_int(item.get("next_run_at", 0))
    if prev_next <= 0:
        return {"action": "noop", "request_emitted": False}

    # money-safety #2 — deterministic idempotency key per occurrence.
    idem = f"{standing_order_id}#{prev_next}"
    amount_cents = _to_int(item.get("amount_cents", 0))
    currency = item.get("currency", "usd")
    counterparty_id = item.get("counterparty_id", "")

    meta: Dict[str, Any] = {"standing_order_id": standing_order_id, "occurrence_ts": prev_next}
    # money-safety #5 — non-usd counterparty amount converted to usd; rate stamped on meta.
    if currency and currency.lower() != "usd":
        from app.services import fx_rates

        conv = fx_rates.convert(amount_cents, currency, "usd")
        amount_cents = conv["target_amount_cents"]
        meta.update({"fx_rate": conv["rate"], "source_currency": currency, "fx_as_of": conv["as_of"]})

    from app.services.pay_txr_bridge import emit_counterparty_request

    created = emit_counterparty_request(
        user_sub,
        counterparty_id=counterparty_id,
        amount_cents=amount_cents,
        idempotency_key=idem,
        reason="standing_order",
        meta=meta,
        execute=True,
    )

    # money-safety #3 — advance next_run_at ONLY via conditional update asserting prev value.
    cadence = item.get("cadence", "monthly")
    new_next = next_occurrence(cadence, prev_next)
    end_at = item.get("end_at")
    completes = end_at is not None and new_next > _to_int(end_at)
    now = now_ts()
    try:
        if completes:
            T.standing_orders.update_item(
                Key={"user_sub": user_sub, "standing_order_id": standing_order_id},
                UpdateExpression=(
                    "SET #status = :completed, last_run_at = :now, runs_count = runs_count + :one, "
                    "updated_at = :now REMOVE GSI_DUE_PK, next_run_at"
                ),
                ConditionExpression="next_run_at = :prev",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":completed": "completed", ":now": now, ":one": 1, ":prev": prev_next},
            )
        else:
            T.standing_orders.update_item(
                Key={"user_sub": user_sub, "standing_order_id": standing_order_id},
                UpdateExpression=(
                    "SET next_run_at = :nra, last_run_at = :now, runs_count = runs_count + :one, updated_at = :now"
                ),
                ConditionExpression="next_run_at = :prev",
                ExpressionAttributeValues={":nra": new_next, ":now": now, ":one": 1, ":prev": prev_next},
            )
    except Exception:
        # Lost the conditional race — another tick already advanced this occurrence. No-op.
        logger.debug("standing_order advance lost race (id=%s, prev=%s)", standing_order_id, prev_next)
        return {"action": "advanced_by_other", "request_emitted": created is not None}

    if created is None:
        _audit("standing_order.skipped", user_sub, standing_order_id=standing_order_id, reason="txr_unavailable")
        return {"action": "advanced_no_request", "request_emitted": False}
    _audit("standing_order.executed", user_sub, standing_order_id=standing_order_id, idempotency_key=idem)
    return {"action": "completed" if completes else "executed", "request_emitted": True}


def query_due(now: int, limit: int = 25) -> List[Dict[str, Any]]:
    """Range-query the ByDue GSI for orders with ``next_run_at <= now`` (same shape as scheduled_actions)."""
    resp = T.standing_orders.query(
        IndexName="ByDue",
        KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("next_run_at").lte(now),
        Limit=limit,
    )
    return resp.get("Items", [])


def run_due_tick(limit: int = 25) -> Dict[str, int]:
    """Polling helper driven by the unified scheduler loop. Gated by the caller on the PAY flag."""
    now = now_ts()
    due = query_due(now, limit=limit)
    processed = 0
    for it in due:
        try:
            execute_due_standing_order(it.get("user_sub", ""), it.get("standing_order_id", ""))
            processed += 1
        except Exception:
            logger.exception("standing_order tick failed (id=%s)", it.get("standing_order_id", "?"))
    return {"due": len(due), "processed": processed}


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass
