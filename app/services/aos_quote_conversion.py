"""Quote-to-invoice and quote-to-contract conversion (QUO-003).

Kept in its own module to avoid circular imports between ``aos_quotes`` (CRUD)
and ``invoices`` / ``aos_contracts`` (entity creation). Conversions are atomic
from the caller's perspective via a conditional ``update_item`` on the quote so
retries are idempotent (a second convert → 409).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.aos_contracts import create_contract
from app.services.invoices import create_invoice
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _quote_sk(quote_id: str) -> str:
    return f"QUOTE#{quote_id}"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load_quote(user_sub: str, quote_id: str) -> Dict[str, Any]:
    resp = T.aos_quotes.get_item(Key={"pk": _user_pk(user_sub), "sk": _quote_sk(quote_id)})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, {"code": "quote_not_found"})
    return item


def _record_activity_safe(**kwargs: Any) -> None:
    try:
        from app.services.activity_feed import record_activity
        record_activity(**kwargs)
    except Exception:  # pragma: no cover
        logger.warning("record_activity failed", exc_info=True)


def _audit_safe(*args: Any, **kwargs: Any) -> None:
    try:
        audit_event(*args, **kwargs)
    except Exception:  # pragma: no cover
        logger.warning("audit_event failed", exc_info=True)


def convert_to_invoice(
    *,
    user_sub: str,
    quote_id: str,
    request: Any = None,
) -> Dict[str, Any]:
    if not S.aos_quotes_enabled:
        raise HTTPException(404, "AOS quotes are not enabled")
    quote = _load_quote(user_sub, quote_id)

    if quote.get("converted_to_invoice_number"):
        raise HTTPException(409, {"code": "quote_already_converted"})
    stage = str(quote.get("stage") or "")
    if stage != "accepted":
        raise HTTPException(400, {"code": "quote_must_be_accepted", "stage": stage})

    owner_sub = str(quote.get("user_sub") or user_sub)
    subtotal = _coerce_int(quote.get("subtotal_cents"))
    tax = _coerce_int(quote.get("tax_cents"))

    line_items = []
    for li in quote.get("line_items") or []:
        line_items.append({
            "description": str(li.get("description") or "Item"),
            "quantity": _coerce_int(li.get("qty"), 1),
            "amount_cents": _coerce_int(li.get("line_total_cents")),
        })

    buyer_name = ""
    buyer_email = ""
    try:
        from app.services.profile import get_profile_identity
        ident = get_profile_identity(owner_sub)
        buyer_name = ident.get("display_name") or ""
        buyer_email = ident.get("email") or ""
    except Exception:  # pragma: no cover
        pass

    invoice = create_invoice(
        user_sub=owner_sub,
        invoice_type="shop",
        amount_cents=subtotal if subtotal > 0 else max(1, subtotal),
        line_items=line_items,
        tax_cents=tax,
        buyer_name=buyer_name,
        buyer_email=buyer_email,
        currency=str(quote.get("currency") or "usd"),
        aos_quote_id=quote_id,
    )
    if invoice is None:
        raise HTTPException(409, {"code": "invoice_creation_failed"})
    invoice_number = invoice["invoice_number"]

    try:
        T.aos_quotes.update_item(
            Key={"pk": _user_pk(user_sub), "sk": _quote_sk(quote_id)},
            UpdateExpression=(
                "SET #stage = :converted, converted_to_invoice_number = :inv, "
                "GSI2PK = :gpk, updated_at = :t"
            ),
            ConditionExpression="attribute_not_exists(converted_to_invoice_number)",
            ExpressionAttributeNames={"#stage": "stage"},
            ExpressionAttributeValues={
                ":converted": "converted",
                ":inv": invoice_number,
                ":gpk": f"USER#{user_sub}#STAGE#converted",
                ":t": now_ts(),
            },
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, {"code": "quote_already_converted"})
        raise

    _audit_safe(
        "quote.converted", user_sub, request,
        quote_id=quote_id, conversion_target="invoice", target_id=invoice_number,
    )
    _record_activity_safe(
        user_id=owner_sub, actor_id=user_sub, activity_type="quote_converted",
        target_type="invoice", target_id=invoice_number,
    )
    return invoice


def convert_to_contract(
    *,
    user_sub: str,
    quote_id: str,
    request: Any = None,
) -> Dict[str, Any]:
    if not S.aos_quotes_enabled:
        raise HTTPException(404, "AOS quotes are not enabled")
    if not S.aos_contracts_enabled:
        raise HTTPException(409, {"code": "contracts_not_enabled"})
    quote = _load_quote(user_sub, quote_id)

    if quote.get("converted_to_contract_id"):
        raise HTTPException(409, {"code": "quote_already_converted"})
    stage = str(quote.get("stage") or "")
    if stage != "accepted":
        raise HTTPException(400, {"code": "quote_must_be_accepted", "stage": stage})

    owner_sub = str(quote.get("user_sub") or user_sub)
    contract = create_contract(
        owner_sub,
        title=f"Contract from {quote.get('quote_number', '')}",
        start_date=now_ts(),
        end_date=None,
        value_cents=_coerce_int(quote.get("total_cents")),
        currency=str(quote.get("currency") or "usd"),
        account_id=str(quote.get("account_id") or ""),
        contact_id=str(quote.get("contact_id") or ""),
        aos_quote_id=quote_id,
        renewal_notice_days=30,
    )
    if contract is None:
        raise HTTPException(409, {"code": "contracts_not_enabled"})
    contract_id = contract["contract_id"]

    try:
        T.aos_quotes.update_item(
            Key={"pk": _user_pk(user_sub), "sk": _quote_sk(quote_id)},
            UpdateExpression=(
                "SET #stage = :converted, converted_to_contract_id = :cid, "
                "GSI2PK = :gpk, updated_at = :t"
            ),
            ConditionExpression="attribute_not_exists(converted_to_contract_id)",
            ExpressionAttributeNames={"#stage": "stage"},
            ExpressionAttributeValues={
                ":converted": "converted",
                ":cid": contract_id,
                ":gpk": f"USER#{user_sub}#STAGE#converted",
                ":t": now_ts(),
            },
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(409, {"code": "quote_already_converted"})
        raise

    _audit_safe(
        "quote.converted", user_sub, request,
        quote_id=quote_id, conversion_target="contract", target_id=contract_id,
    )
    _record_activity_safe(
        user_id=owner_sub, actor_id=user_sub, activity_type="quote_converted",
        target_type="contract", target_id=contract_id,
    )
    return contract
