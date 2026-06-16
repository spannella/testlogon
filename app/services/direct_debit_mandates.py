"""OBP PAY-003 — Direct-debit mandates (capped pull authorization) + execution hook.

A mandate authorizes a counterparty to *pull* up to ``max_amount_cents`` per cadence
window. Reuses the same scheduler + TXR rail as standing orders; the only new logic is
server-side cap enforcement (money-safety #4): a pull whose amount OR cumulative window
total exceeds the cap creates NO request and debits NOTHING — it is marked ``skipped``
(explicit, never a silent partial pull). ``revoke`` is the user's kill switch (removes
the due-GSI keys → no further pulls).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.services.standing_orders import next_occurrence  # shared cadence math

logger = logging.getLogger(__name__)

_DAY = 86400
_WINDOW_SECONDS = {"weekly": 7 * _DAY, "monthly": 30 * _DAY}


class MandateError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _dd_id() -> str:
    return f"dd_{uuid.uuid4().hex}"


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "mandate_id": item.get("mandate_id", ""),
        "counterparty_id": item.get("counterparty_id", ""),
        "max_amount_cents": _to_int(item.get("max_amount_cents", 0)),
        "currency": item.get("currency", "usd"),
        "cadence": item.get("cadence", ""),
        "status": item.get("status", "active"),
        "next_run_at": _to_int(item.get("next_run_at")) if item.get("next_run_at") is not None else None,
        "last_run_at": _to_int(item.get("last_run_at")) if item.get("last_run_at") is not None else None,
        "pulled_this_window_cents": _to_int(item.get("pulled_this_window_cents", 0)),
        "runs_count": _to_int(item.get("runs_count", 0)),
        "created_at": _to_int(item.get("created_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }


def _require_owned_counterparty(user_sub: str, counterparty_id: str) -> Dict[str, Any]:
    from app.services import counterparties

    cp = counterparties.get_counterparty(user_sub, counterparty_id)
    if not cp:
        raise MandateError("counterparty_not_found", "counterparty not found or not yours")
    return cp


def create_mandate(user_sub: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    counterparty_id = payload["counterparty_id"]
    _require_owned_counterparty(user_sub, counterparty_id)
    cadence = payload["cadence"]
    if cadence not in _WINDOW_SECONDS:
        raise MandateError("invalid_cadence", cadence)
    ts = now_ts()
    start_at = _to_int(payload.get("start_at", ts), ts)
    next_run_at = max(start_at, ts)
    dd_id = _dd_id()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "mandate_id": dd_id,
        "counterparty_id": counterparty_id,
        "max_amount_cents": _to_int(payload["max_amount_cents"]),
        "currency": payload.get("currency", "usd"),
        "cadence": cadence,
        "status": "active",
        "start_at": start_at,
        "end_at": _to_int(payload["end_at"]) if payload.get("end_at") is not None else None,
        "reference": payload.get("reference") or "",
        "next_run_at": next_run_at,
        "last_run_at": None,
        "pulled_this_window_cents": 0,
        "window_started_at": next_run_at,
        "runs_count": 0,
        "GSI_DUE_PK": "DUE",
        "created_at": ts,
        "updated_at": ts,
    }
    T.direct_debit_mandates.put_item(Item=item)
    _audit("mandate.created", user_sub, mandate_id=dd_id, counterparty_id=counterparty_id)
    return _to_out(item)


def get_mandate(user_sub: str, mandate_id: str) -> Optional[Dict[str, Any]]:
    resp = T.direct_debit_mandates.get_item(Key={"user_sub": user_sub, "mandate_id": mandate_id})
    return resp.get("Item") or None


def get_mandate_out(user_sub: str, mandate_id: str) -> Optional[Dict[str, Any]]:
    item = get_mandate(user_sub, mandate_id)
    return _to_out(item) if item else None


def list_mandates(
    user_sub: str, *, limit: int = 50, cursor: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("user_sub").eq(user_sub),
        "Limit": max(1, min(limit, 200)),
    }
    start = decode_cursor(cursor)
    if start:
        query_kwargs["ExclusiveStartKey"] = start
    resp = T.direct_debit_mandates.query(**query_kwargs)
    items = sorted(resp.get("Items", []), key=lambda x: _to_int(x.get("created_at", 0)), reverse=True)
    return [_to_out(it) for it in items], encode_cursor(resp.get("LastEvaluatedKey"))


def revoke(user_sub: str, mandate_id: str) -> Optional[Dict[str, Any]]:
    """User's kill switch — sets status=revoked and removes the due-GSI keys."""
    existing = get_mandate(user_sub, mandate_id)
    if not existing:
        return None
    T.direct_debit_mandates.update_item(
        Key={"user_sub": user_sub, "mandate_id": mandate_id},
        UpdateExpression="SET #status = :revoked, updated_at = :now REMOVE GSI_DUE_PK, next_run_at",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":revoked": "revoked", ":now": now_ts()},
    )
    _audit("mandate.revoked", user_sub, mandate_id=mandate_id)
    return get_mandate_out(user_sub, mandate_id)


def pause(user_sub: str, mandate_id: str) -> Optional[Dict[str, Any]]:
    existing = get_mandate(user_sub, mandate_id)
    if not existing:
        return None
    T.direct_debit_mandates.update_item(
        Key={"user_sub": user_sub, "mandate_id": mandate_id},
        UpdateExpression="SET #status = :paused, updated_at = :now REMOVE GSI_DUE_PK, next_run_at",
        ConditionExpression="#status = :active",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":paused": "paused", ":active": "active", ":now": now_ts()},
    )
    _audit("mandate.paused", user_sub, mandate_id=mandate_id)
    return get_mandate_out(user_sub, mandate_id)


def execute_mandate_pull(user_sub: str, mandate_id: str, pull_amount_cents: int) -> Dict[str, Any]:
    """Execute one capped pull. Cap-violation → NO request, NO debit, marked skipped.

    Returns ``{action, request_emitted, reason?}``. NEVER debits the wallet (money-safety #1).
    """
    item = get_mandate(user_sub, mandate_id)
    if not item or item.get("status") != "active":
        return {"action": "noop", "request_emitted": False}
    prev_next = _to_int(item.get("next_run_at", 0))
    if prev_next <= 0:
        return {"action": "noop", "request_emitted": False}

    cadence = item.get("cadence", "monthly")
    window = _WINDOW_SECONDS.get(cadence, 30 * _DAY)
    max_cents = _to_int(item.get("max_amount_cents", 0))
    pull_cents = _to_int(pull_amount_cents)
    now = now_ts()

    # Window rollover: if the current window has elapsed, reset the running total.
    window_started_at = _to_int(item.get("window_started_at", item.get("start_at", now)), now)
    pulled = _to_int(item.get("pulled_this_window_cents", 0))
    rolled = (now - window_started_at) >= window
    effective_pulled = 0 if rolled else pulled

    # money-safety #4 — cap enforcement (per-pull AND cumulative-window). Over-cap → skip.
    if pull_cents <= 0 or pull_cents > max_cents or (effective_pulled + pull_cents) > max_cents:
        # Advance the occurrence (so the runner doesn't re-fire forever) but emit NO request.
        new_next = next_occurrence(cadence, prev_next)
        try:
            T.direct_debit_mandates.update_item(
                Key={"user_sub": user_sub, "mandate_id": mandate_id},
                UpdateExpression="SET next_run_at = :nra, updated_at = :now",
                ConditionExpression="next_run_at = :prev",
                ExpressionAttributeValues={":nra": new_next, ":now": now, ":prev": prev_next},
            )
        except Exception:
            return {"action": "advanced_by_other", "request_emitted": False}
        _audit("mandate.skipped", user_sub, mandate_id=mandate_id, reason="cap_exceeded",
               pull_amount_cents=pull_cents, max_amount_cents=max_cents)
        return {"action": "skipped", "request_emitted": False, "reason": "cap_exceeded"}

    # Within cap — emit a COUNTERPARTY TXR (TXR owns the debit; money-safety #1).
    idem = f"{mandate_id}#{prev_next}"
    currency = item.get("currency", "usd")
    counterparty_id = item.get("counterparty_id", "")
    meta: Dict[str, Any] = {"mandate_id": mandate_id, "occurrence_ts": prev_next}
    amount_cents = pull_cents
    if currency and currency.lower() != "usd":
        from app.services import fx_rates

        conv = fx_rates.convert(pull_cents, currency, "usd")
        amount_cents = conv["target_amount_cents"]
        meta.update({"fx_rate": conv["rate"], "source_currency": currency, "fx_as_of": conv["as_of"]})

    from app.services.pay_txr_bridge import emit_counterparty_request

    created = emit_counterparty_request(
        user_sub,
        counterparty_id=counterparty_id,
        amount_cents=amount_cents,
        idempotency_key=idem,
        reason="direct_debit",
        meta=meta,
        execute=True,
    )

    # money-safety #3 — conditional advance + window accounting in one atomic update.
    new_next = next_occurrence(cadence, prev_next)
    new_window_started = now if rolled else window_started_at
    new_pulled = (0 if rolled else pulled) + pull_cents
    try:
        T.direct_debit_mandates.update_item(
            Key={"user_sub": user_sub, "mandate_id": mandate_id},
            UpdateExpression=(
                "SET next_run_at = :nra, last_run_at = :now, runs_count = runs_count + :one, "
                "pulled_this_window_cents = :pw, window_started_at = :ws, updated_at = :now"
            ),
            ConditionExpression="next_run_at = :prev",
            ExpressionAttributeValues={
                ":nra": new_next, ":now": now, ":one": 1, ":pw": new_pulled,
                ":ws": new_window_started, ":prev": prev_next,
            },
        )
    except Exception:
        logger.debug("mandate advance lost race (id=%s, prev=%s)", mandate_id, prev_next)
        return {"action": "advanced_by_other", "request_emitted": created is not None}

    if created is None:
        _audit("mandate.skipped", user_sub, mandate_id=mandate_id, reason="txr_unavailable")
        return {"action": "advanced_no_request", "request_emitted": False}
    _audit("mandate.debited", user_sub, mandate_id=mandate_id, idempotency_key=idem, amount_cents=amount_cents)
    return {"action": "debited", "request_emitted": True}


def query_due(now: int, limit: int = 25) -> List[Dict[str, Any]]:
    resp = T.direct_debit_mandates.query(
        IndexName="ByDue",
        KeyConditionExpression=Key("GSI_DUE_PK").eq("DUE") & Key("next_run_at").lte(now),
        Limit=limit,
    )
    return resp.get("Items", [])


def run_due_tick(limit: int = 25) -> Dict[str, int]:
    now = now_ts()
    due = query_due(now, limit=limit)
    processed = 0
    for it in due:
        try:
            # Default scheduled pull amount = the mandate cap (the maximum authorized).
            execute_mandate_pull(it.get("user_sub", ""), it.get("mandate_id", ""), _to_int(it.get("max_amount_cents", 0)))
            processed += 1
        except Exception:
            logger.exception("mandate tick failed (id=%s)", it.get("mandate_id", "?"))
    return {"due": len(due), "processed": processed}


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass
