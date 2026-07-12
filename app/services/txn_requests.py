"""OBP Transaction Requests + Step-Up SCA (TXR-001..TXR-005).

A unified, typed money-movement request object that walks the status machine
INITIATED -> PENDING -> IN_FLIGHT -> COMPLETED | FAILED. Separates the act of
*recording* a payment intention from the act of *executing* it.

Money-safety invariants:
  * No money moves on create (TXR-001). INITIATED is a durable intent only.
  * Status is the concurrency lock: every transition is a conditional
    ``update_item`` asserting the current status (TXR-002 ``_transition``).
  * High-value / sensitive requests are held PENDING behind a step-up SCA
    challenge minted from the LIVE MFA/SCA stack (TXR-003); no new OTP logic.
  * Execution (TXR-004) is fraud-gated, idempotent to COMPLETED, and is the
    ONLY money-out rail — it reuses billing_shared / tip_ledger / creator_payouts
    / billing._do_refund primitives and never forks the ledger or refund path.
  * WALLET_TRANSFER debit+credit is atomic via ``transact_write_items`` so a
    crash cannot leave the sender debited and the recipient uncredited.

No ``if S.dev_mode`` branches (SECOPS-007): provider differences live entirely
inside the existing abstractions (DDB endpoint, Stripe mock, MFA OTP delivery).

Cross-cluster collaborators (banking_accounts.py etc.) are referenced lazily
and treated as opaque strings; this module never hard-imports them.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException, Request

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import TxnRequestCreateIn, TxnRequestOut
from app.services.alerts import audit_event

# --- status machine -------------------------------------------------------

INITIATED = "INITIATED"
PENDING = "PENDING"
IN_FLIGHT = "IN_FLIGHT"
COMPLETED = "COMPLETED"
FAILED = "FAILED"

_VALID_STATUSES = {INITIATED, PENDING, IN_FLIGHT, COMPLETED, FAILED}
_TERMINAL = {COMPLETED, FAILED}

# Legal transitions (TXR-002 §5.1 + TXR-004 §8.2 IN_FLIGHT extension).
_LEGAL_TRANSITIONS = {
    (INITIATED, PENDING),
    (INITIATED, IN_FLIGHT),
    (INITIATED, FAILED),
    (PENDING, IN_FLIGHT),
    (PENDING, FAILED),
    (IN_FLIGHT, COMPLETED),
    (IN_FLIGHT, FAILED),
}

# Per-type amount-ceiling settings attribute names (TXR-002 §4.1).
_LIMIT_ATTR: Dict[str, str] = {
    "WALLET_TRANSFER": "txn_request_limit_wallet_transfer_cents",
    "COUNTERPARTY": "txn_request_limit_counterparty_cents",
    "PAYOUT": "txn_request_limit_payout_cents",
    "REFUND": "txn_request_limit_refund_cents",
    "FREE_FORM": "txn_request_limit_free_form_cents",
}


def _enabled() -> bool:
    """Effective enablement: umbrella (ACC-001 D4) AND per-series flag.

    ``open_bank_project_enabled`` is defined in ACC-001; reference it
    defensively (default True when absent) so this series builds independently
    in a stale worktree while ANDing the umbrella once ACC-001 merges.
    """
    umbrella = bool(getattr(S, "open_bank_project_enabled", True))
    return umbrella and bool(S.txn_requests_enabled)


def _require_enabled() -> None:
    if not _enabled():
        raise HTTPException(status_code=404, detail="txn_requests not enabled")


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _item_to_out(item: Dict[str, Any]) -> TxnRequestOut:
    """Convert a raw DynamoDB item to TxnRequestOut, coercing Decimal -> int."""
    refs = item.get("ledger_refs") or []
    return TxnRequestOut(
        request_id=item["request_id"],
        type=item["type"],
        amount_cents=_to_int(item.get("amount_cents", 0)),
        currency=item.get("currency", "usd"),
        target=dict(item.get("target") or {}),
        status=item.get("status", INITIATED),
        sca_challenge_id=item.get("sca_challenge_id"),
        required_factors=item.get("sca_required_factors") or item.get("required_factors"),
        sca_required_factors=item.get("sca_required_factors"),
        ledger_refs=[str(r) for r in refs],
        created_at=_to_int(item.get("created_at", 0)),
        updated_at=_to_int(item.get("updated_at", 0)),
        failure_reason=item.get("failure_reason"),
    )


# --- TXR-002: per-type amount limits --------------------------------------


def enforce_amount_limit(type_: str, amount_cents: int) -> None:
    """Raise HTTPException(400, amount_over_limit) if over the per-type ceiling.

    A ceiling of 0 (the default for every type) means "no limit".
    """
    attr = _LIMIT_ATTR.get(str(type_).upper())
    if not attr:
        return
    ceiling = _to_int(getattr(S, attr, 0))
    if ceiling > 0 and amount_cents > ceiling:
        raise HTTPException(status_code=400, detail={"code": "amount_over_limit", "ceiling_cents": ceiling})


# --- TXR-001: per-type target validation ----------------------------------


def _validate_target(type_: str, target: Dict[str, Any], user_sub: str) -> None:
    t = str(getattr(type_, "value", type_)).upper()

    def _missing(key: str) -> None:
        raise HTTPException(status_code=400, detail={"code": "invalid_target", "type": t, "missing_key": key})

    if t == "WALLET_TRANSFER":
        to = target.get("to_user_sub")
        if not to:
            _missing("to_user_sub")
        if to == user_sub:
            raise HTTPException(status_code=400, detail={"code": "self_transfer_not_allowed"})
    elif t == "FREE_FORM":
        # to_user_sub is optional (narrative-only allowed; self allowed).
        pass
    elif t == "PAYOUT":
        if not target.get("payout_method_id"):
            _missing("payout_method_id")
    elif t == "REFUND":
        pi = target.get("payment_intent_id")
        if not pi:
            _missing("payment_intent_id")
        if not str(pi).startswith("pi_"):
            raise HTTPException(status_code=400, detail={"code": "invalid_target", "type": t, "reason": "payment_intent_id must start with pi_"})
    elif t == "COUNTERPARTY":
        if not target.get("counterparty_ref"):
            _missing("counterparty_ref")


# --- TXR-002: status transition (the lock) --------------------------------


def _transition(
    user_sub: str,
    request_id: str,
    expected_status: str,
    new_status: str,
    **patch: Any,
) -> Dict[str, Any]:
    """Conditional update asserting current status == expected_status.

    Returns the updated item on success. On ConditionalCheckFailedException
    raises HTTPException(409, invalid_transition) carrying current_status.

    Illegal transitions (not in ``_LEGAL_TRANSITIONS``, e.g. anything out of a
    terminal COMPLETED/FAILED state) are rejected up front with 409 — terminal
    states are truly terminal regardless of the ``expected_status`` passed.
    """
    if (expected_status, new_status) not in _LEGAL_TRANSITIONS:
        current = get_request(user_sub, request_id)
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_transition", "current_status": current.get("status")},
        )

    update_expr = "SET #status = :new, updated_at = :ts"
    attr_values: Dict[str, Any] = {":new": new_status, ":ts": now_ts(), ":expected": expected_status}
    attr_names = {"#status": "status"}

    for k, v in patch.items():
        placeholder = f":p_{k}"
        update_expr += f", {k} = {placeholder}"
        attr_values[placeholder] = v

    try:
        resp = T.txn_requests.update_item(
            Key={"user_sub": user_sub, "request_id": request_id},
            UpdateExpression=update_expr,
            ConditionExpression="#status = :expected",
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ReturnValues="ALL_NEW",
        )
        return resp["Attributes"]
    except T.txn_requests.meta.client.exceptions.ConditionalCheckFailedException:
        current = get_request(user_sub, request_id)
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_transition", "current_status": current.get("status")},
        )


# --- TXR-002: reads -------------------------------------------------------


def get_request(user_sub: str, request_id: str) -> Dict[str, Any]:
    item = T.txn_requests.get_item(Key={"user_sub": user_sub, "request_id": request_id}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="not_found")
    return item


def list_requests(
    user_sub: str,
    status_filter: Optional[str],
    cursor: Optional[str],
    limit: int = 20,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 20), 100))

    if status_filter:
        if status_filter not in _VALID_STATUSES:
            raise HTTPException(status_code=400, detail={"code": "invalid_status"})
        items: List[Dict[str, Any]] = []
        last_key = decode_cursor(cursor)
        # FilterExpression doesn't reduce page size; loop until enough or done.
        while len(items) < limit:
            kwargs: Dict[str, Any] = {
                "IndexName": "GSI_STATUS",
                "KeyConditionExpression": Key("status").eq(status_filter),
                "FilterExpression": Attr("user_sub").eq(user_sub),
                "Limit": limit * 3,
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.txn_requests.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        next_cursor = encode_cursor(last_key) if last_key and len(items) >= limit else None
        items = items[:limit]
    else:
        kwargs = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "Limit": limit,
            "ScanIndexForward": False,
        }
        last_key = decode_cursor(cursor)
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.txn_requests.query(**kwargs)
        items = resp.get("Items", [])
        next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))

    return {"items": [_item_to_out(it) for it in items], "next_cursor": next_cursor}


# --- TXR-003: step-up SCA decision + mint ---------------------------------


def _sca_required(user_sub: str, txn_type: str, amount_cents: int) -> Tuple[bool, List[str]]:
    """Pure decision: (required, factors).

    Required iff amount >= threshold OR type is in the sensitive set. Factors
    come from the user's enrolled MFA devices, falling back to ["email"].
    """
    t = str(getattr(txn_type, "value", txn_type)).upper()
    threshold = _to_int(getattr(S, "txn_request_sca_threshold_cents", 5000), 5000)
    sensitive = set(getattr(S, "txn_request_sca_sensitive_types", frozenset()))
    required = amount_cents >= threshold or t in sensitive
    if not required:
        return False, []
    from app.services.sessions import compute_required_factors

    factors = compute_required_factors(user_sub)
    if not factors:
        factors = ["email"]
    return True, factors


def _mint_sca_challenge(
    req: Request,
    user_sub: str,
    request_id: str,
    txn_type: str,
    amount_cents: int,
    required_factors: List[str],
) -> str:
    """Mint a step-up challenge via the LIVE MFA/SCA stack and bind it to the
    request. Uses ``create_stepup_challenge`` (seeds required_factors + passed
    map correctly) + a follow-up update to stamp the binding payload.
    """
    from app.services.sessions import create_stepup_challenge

    challenge_id = create_stepup_challenge(
        req, user_sub, required_factors, purpose="txn_request_sca"
    )
    try:
        t = str(getattr(txn_type, "value", txn_type)).upper()
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression="SET request_id = :r, amount_cents = :a, txn_type = :t",
            ExpressionAttributeValues={":r": request_id, ":a": int(amount_cents), ":t": t},
        )
    except Exception:
        pass
    return challenge_id


# --- TXR-001/003: create --------------------------------------------------


def create_request(user_sub: str, body: TxnRequestCreateIn, req: Request) -> TxnRequestOut:
    _require_enabled()

    amount_cents = int(body.amount_cents)
    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail={"code": "invalid_amount"})

    type_value = str(getattr(body.type, "value", body.type)).upper()

    # TXR-002: amount ceiling before any DDB write.
    enforce_amount_limit(type_value, amount_cents)

    # TXR-001: per-type target validation.
    _validate_target(type_value, dict(body.target or {}), user_sub)

    # TXR-004 §4.6: idempotency-key dedup (collapse duplicate creates).
    if body.idempotency_key:
        existing = _find_by_idempotency_key(user_sub, body.idempotency_key)
        if existing is not None and existing.get("status") != FAILED:
            return _item_to_out(existing)

    request_id = "txr_" + uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "request_id": request_id,
        "type": type_value,
        "amount_cents": amount_cents,
        "currency": (body.currency or "usd"),
        "target": dict(body.target or {}),
        "status": INITIATED,
        "reason": body.reason,
        "idempotency_key": body.idempotency_key,
        "created_at": ts,
        "updated_at": ts,
        "sca_challenge_id": None,
        "ledger_refs": [],
        "failure_reason": None,
    }
    T.txn_requests.put_item(Item=item)

    try:
        audit_event(
            "txn_request.created",
            user_sub,
            req,
            request_id=request_id,
            type=type_value,
            amount_cents=amount_cents,
            currency=item["currency"],
        )
    except Exception:
        pass

    # TXR-003: step-up SCA decision.
    required, factors = _sca_required(user_sub, type_value, amount_cents)
    if not required:
        return _item_to_out(item)

    challenge_id = _mint_sca_challenge(req, user_sub, request_id, type_value, amount_cents, factors)
    updated = _transition(
        user_sub,
        request_id,
        expected_status=INITIATED,
        new_status=PENDING,
        sca_challenge_id=challenge_id,
        sca_required_factors=factors,
    )
    try:
        audit_event(
            "txn_request.sca_required",
            user_sub,
            req,
            request_id=request_id,
            challenge_id=challenge_id,
            amount_cents=amount_cents,
            txn_type=type_value,
        )
    except Exception:
        pass
    _dispatch_webhook("txn_request.sca_required", user_sub, {"request_id": request_id, "challenge_id": challenge_id})
    return _item_to_out(updated)


def _find_by_idempotency_key(user_sub: str, key: str) -> Optional[Dict[str, Any]]:
    try:
        resp = T.txn_requests.query(
            KeyConditionExpression=Key("user_sub").eq(user_sub),
            FilterExpression=Attr("idempotency_key").eq(key),
        )
        items = resp.get("Items", [])
        return items[0] if items else None
    except Exception:
        return None


# --- TXR-004: execution ---------------------------------------------------


def _dispatch_webhook(event: str, user_sub: str, data: Dict[str, Any]) -> None:
    try:
        from app.services import webhook_service

        webhook_service.dispatch_webhook_event(event, user_sub, data)
    except Exception:
        pass


def _fail(user_sub: str, request_id: str, failure_reason: str, *, detail: str = "") -> None:
    """Transition the request to FAILED from any non-terminal status. Best-effort."""
    try:
        item = get_request(user_sub, request_id)
        current = item.get("status", INITIATED)
        if current in _TERMINAL:
            return
        _transition(user_sub, request_id, current, FAILED, failure_reason=failure_reason)
        try:
            audit_event(
                "txn_request.failed",
                user_sub,
                None,
                request_id=request_id,
                failure_reason=failure_reason,
                detail=detail,
            )
        except Exception:
            pass
        _dispatch_webhook("txn_request.failed", user_sub, {"request_id": request_id, "failure_reason": failure_reason})
    except HTTPException:
        pass
    except Exception:
        pass


def execute_request(user_sub: str, request_id: str, req: Request) -> TxnRequestOut:
    _require_enabled()

    item = get_request(user_sub, request_id)
    status = item.get("status")

    # Step 1: idempotent early return on terminal status.
    if status in _TERMINAL:
        if status == FAILED:
            # A FAILED request is terminal; surface as invalid_transition only
            # when explicitly re-executed against the lock. Return the item so
            # callers see the failure reason (idempotent).
            return _item_to_out(item)
        return _item_to_out(item)

    if status not in (INITIATED, PENDING):
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_transition", "current_status": status},
        )

    # Step 2: SCA gate (PENDING only) + revoke before money moves.
    if status == PENDING:
        from app.services import sessions as _sessions

        sca_challenge_id = item.get("sca_challenge_id")
        if not sca_challenge_id:
            _fail(user_sub, request_id, "sca_incomplete")
            raise HTTPException(status_code=403, detail={"code": "sca_incomplete"})
        try:
            chal = _sessions.load_challenge_or_401(user_sub, sca_challenge_id)
        except HTTPException as exc:
            if exc.status_code == 401:
                _fail(user_sub, request_id, "sca_incomplete")
            raise
        if not _sessions.challenge_done(chal):
            raise HTTPException(
                status_code=403,
                detail={"code": "sca_incomplete", "required_factors": chal.get("required_factors")},
            )
        # Bind the challenge to this request (TXR-003 §5.5).
        if chal.get("request_id") and chal.get("request_id") != request_id:
            raise HTTPException(status_code=403, detail={"code": "challenge_request_mismatch"})
        _sessions.revoke_challenge(user_sub, sca_challenge_id)

    # Step 3: fraud gate (lazy import to avoid circular dependency).
    try:
        from app.routers.billing import _fraud_gate

        entry_type = "debit" if item.get("type") in ("WALLET_TRANSFER", "FREE_FORM", "PAYOUT", "COUNTERPARTY") else "adjustment"
        _fraud_gate(
            user_id=user_sub,
            amount_cents=_to_int(item.get("amount_cents", 0)),
            entry_type=entry_type,
            tx_id=request_id,
            req=req,
            enforce_block=True,
        )
    except HTTPException as exc:
        if exc.status_code == 403:
            reason = "account_frozen" if "frozen" in str(exc.detail).lower() else "fraud_blocked"
            _fail(user_sub, request_id, reason)
        raise

    # Step 4: claim IN_FLIGHT (status-first ordering; single-winner lock).
    _transition(user_sub, request_id, expected_status=status, new_status=IN_FLIGHT)

    # Step 5: dispatch by type (money moves).
    try:
        ledger_refs = _dispatch(user_sub, item, req)
    except HTTPException:
        # Dispatchers transition to FAILED themselves before raising.
        raise
    except Exception as exc:  # pragma: no cover - defensive
        _fail_from_in_flight(user_sub, request_id, "internal_error", detail=str(exc))
        raise HTTPException(status_code=500, detail={"code": "internal_error"})

    # Step 6: finalize.
    updated = _transition(user_sub, request_id, expected_status=IN_FLIGHT, new_status=COMPLETED, ledger_refs=ledger_refs)
    try:
        audit_event(
            "txn_request.executed",
            user_sub,
            req,
            request_id=request_id,
            type=item.get("type"),
            amount_cents=item.get("amount_cents"),
            ledger_refs=ledger_refs,
        )
    except Exception:
        pass
    _dispatch_webhook("txn_request.executed", user_sub, {"request_id": request_id, "ledger_refs": ledger_refs})
    return _item_to_out(updated)


def _fail_from_in_flight(user_sub: str, request_id: str, failure_reason: str, *, detail: str = "") -> None:
    try:
        _transition(user_sub, request_id, IN_FLIGHT, FAILED, failure_reason=failure_reason)
        try:
            audit_event("txn_request.failed", user_sub, None, request_id=request_id, failure_reason=failure_reason, detail=detail)
        except Exception:
            pass
        _dispatch_webhook("txn_request.failed", user_sub, {"request_id": request_id, "failure_reason": failure_reason})
    except Exception:
        pass


def _dispatch(user_sub: str, item: Dict[str, Any], req: Request) -> List[str]:
    t = str(item.get("type"))
    if t in ("WALLET_TRANSFER", "FREE_FORM"):
        return _dispatch_wallet_transfer(user_sub, item)
    if t == "PAYOUT":
        return _dispatch_payout(user_sub, item)
    if t == "REFUND":
        return _dispatch_refund(user_sub, item, req)
    if t == "COUNTERPARTY":
        return _dispatch_counterparty(user_sub, item)
    _fail_from_in_flight(user_sub, item["request_id"], "internal_error")
    raise HTTPException(status_code=500, detail={"code": "internal_error", "reason": "unknown_type"})


def _dispatch_wallet_transfer(user_sub: str, item: Dict[str, Any]) -> List[str]:
    from app.services import group_treasury as gt
    from app.services.billing_shared import (
        WALLET_SK,
        apply_wallet_delta,
        ledger_sk,
        new_ledger_entry,
        ulidish,
        user_pk,
    )
    from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

    request_id = item["request_id"]
    amount = _to_int(item.get("amount_cents", 0))
    currency = (item.get("currency") or "usd")
    to_user = (item.get("target") or {}).get("to_user_sub")

    if not to_user:
        # FREE_FORM with no recipient: debit-only fee pattern.
        try:
            apply_wallet_delta(T.billing, user_pk(user_sub), -amount, currency=currency)
        except T.billing.meta.client.exceptions.ConditionalCheckFailedException:
            _fail_from_in_flight(user_sub, request_id, "insufficient_funds")
            raise HTTPException(status_code=402, detail={"code": "insufficient_funds"})
        led_sk_value, led_item = new_ledger_entry(
            key_name="pk",
            key_value=user_pk(user_sub),
            entry_type="debit",
            amount_cents=amount,
            state="settled",
            reason="free_form_payment",
            extra={"signed_amount_cents": -amount, "txn_request_id": request_id},
        )
        try:
            T.billing.put_item(Item=led_item)
        except Exception:
            pass
        return [led_sk_value]

    # WALLET_TRANSFER (or FREE_FORM with recipient): atomic debit + credit.
    ts = now_ts()
    table_name = T.billing.name
    debit_pk = user_pk(user_sub)
    credit_pk = user_pk(to_user)
    transact_items = [
        {
            "Update": {
                "TableName": table_name,
                "Key": gt._to_ddb_item({"pk": debit_pk, "sk": WALLET_SK}),
                "UpdateExpression": "SET wallet_balance_cents = wallet_balance_cents + :d, updated_at = :t",
                "ConditionExpression": "wallet_balance_cents >= :needed",
                "ExpressionAttributeValues": gt._to_ddb_item({":d": -amount, ":t": ts, ":needed": amount}),
            }
        },
        {
            "Update": {
                "TableName": table_name,
                "Key": gt._to_ddb_item({"pk": credit_pk, "sk": WALLET_SK}),
                "UpdateExpression": (
                    "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :a, "
                    "currency = if_not_exists(currency, :c), updated_at = :t"
                ),
                "ExpressionAttributeValues": gt._to_ddb_item({":z": 0, ":a": amount, ":c": currency, ":t": ts}),
            }
        },
    ]
    try:
        gt._batch_transact(transact_items)
    except gt._transact_client().exceptions.TransactionCanceledException:
        _fail_from_in_flight(user_sub, request_id, "insufficient_funds")
        raise HTTPException(status_code=402, detail={"code": "insufficient_funds"})
    except Exception as exc:
        # moto / boto may surface the cancellation as a ClientError.
        if "ConditionalCheckFailed" in str(exc) or "TransactionCanceled" in str(exc):
            _fail_from_in_flight(user_sub, request_id, "insufficient_funds")
            raise HTTPException(status_code=402, detail={"code": "insufficient_funds"})
        raise

    # Paired ledger rows (audit) — best-effort; money has already moved.
    entry = TipLedgerEntry(
        tipper_user_id=user_sub,
        recipient_user_id=to_user,
        amount_cents=amount,
        currency=currency.upper(),
        content_type="broadcast",
        content_id=request_id,
        extra_meta={"txn_request_id": request_id, "reason": item.get("reason") or ""},
    )
    try:
        write_tip_ledger(entry)
    except Exception:
        pass
    return [entry.tip_payment_id]


def _dispatch_payout(user_sub: str, item: Dict[str, Any]) -> List[str]:
    from app.services.creator_payouts import request_payout

    request_id = item["request_id"]
    amount = _to_int(item.get("amount_cents", 0))
    method_id = (item.get("target") or {}).get("payout_method_id")
    try:
        result = request_payout(
            user_id=user_sub,
            amount_cents=amount,
            method="bank_transfer",
            notes=item.get("reason") or "",
            method_id=method_id,
        )
    except ValueError as exc:
        msg = str(exc)
        if "DUPLICATE_PAYOUT" in msg:
            _fail_from_in_flight(user_sub, request_id, "payout_duplicate")
            raise HTTPException(status_code=409, detail={"code": "payout_duplicate"})
        if "at least" in msg:
            _fail_from_in_flight(user_sub, request_id, "payout_minimum_not_met")
            raise HTTPException(status_code=400, detail={"code": "payout_minimum_not_met"})
        _fail_from_in_flight(user_sub, request_id, "payout_failed", detail=msg)
        raise HTTPException(status_code=400, detail={"code": "payout_failed", "message": msg})
    return [str(result.get("payout_id"))]


def _dispatch_refund(user_sub: str, item: Dict[str, Any], req: Request) -> List[str]:
    request_id = item["request_id"]
    amount = _to_int(item.get("amount_cents", 0))
    pi = (item.get("target") or {}).get("payment_intent_id")
    from app.routers.billing import _do_refund

    try:
        result = _do_refund(
            user_id=user_sub,
            payment_intent_id=pi,
            amount_cents=amount,
            reason=item.get("reason") or "",
            req=req,
        )
    except HTTPException:
        _fail_from_in_flight(user_sub, request_id, "stripe_error")
        raise
    except Exception as exc:
        if "already_refunded" in str(exc).lower():
            _fail_from_in_flight(user_sub, request_id, "refund_already_issued")
            raise HTTPException(status_code=409, detail={"code": "refund_already_issued"})
        _fail_from_in_flight(user_sub, request_id, "stripe_error", detail=str(exc))
        raise HTTPException(status_code=502, detail={"code": "stripe_error"})
    return [str(result.get("led_sk"))]


def _dispatch_counterparty(user_sub: str, item: Dict[str, Any]) -> List[str]:
    """COUNTERPARTY stub: no outbound rail yet. Debit then immediately reverse
    so the platform stays balance-neutral, then mark FAILED. Money never leaves.
    """
    from app.services.billing_shared import apply_wallet_delta, new_ledger_entry, user_pk

    request_id = item["request_id"]
    amount = _to_int(item.get("amount_cents", 0))
    pk = user_pk(user_sub)

    try:
        apply_wallet_delta(T.billing, pk, -amount, currency=item.get("currency", "usd"))
    except T.billing.meta.client.exceptions.ConditionalCheckFailedException:
        _fail_from_in_flight(user_sub, request_id, "insufficient_funds")
        raise HTTPException(status_code=402, detail={"code": "insufficient_funds"})

    led_sk_value, led_item = new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="debit",
        amount_cents=amount,
        state="cancelled",
        reason="counterparty_payment",
        extra={"counterparty_ref": (item.get("target") or {}).get("counterparty_ref"), "txn_request_id": request_id},
    )
    try:
        T.billing.put_item(Item=led_item)
    except Exception:
        pass

    # Reverse the debit immediately (no outbound rail).
    try:
        apply_wallet_delta(T.billing, pk, amount, currency=item.get("currency", "usd"))
    except Exception:
        pass

    _fail_from_in_flight(user_sub, request_id, "counterparty_unsupported")
    raise HTTPException(status_code=501, detail={"code": "counterparty_unsupported"})
