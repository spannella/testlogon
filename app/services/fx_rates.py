"""OBP PAY-004 — FX rate store + pure integer ``convert`` helper.

Append-only currency-pair rate history (PK=pair "SRC_TGT", SK=as_of N). The ledger
stays single-currency ``usd``; ``convert`` only annotates a request and NEVER writes
a ledger/wallet row (money-safety #5). Rates are persisted as a scaled integer
``rate_micros`` (``round(rate * 1_000_000)``) to avoid float drift, mirroring the
``amount_cents`` integer discipline used throughout ``billing_shared``/``tip_ledger``.

Flag-gated default-OFF via the router (``S.payments_counterparties_enabled`` AND the
umbrella ``open_bank_project_enabled``). The service functions themselves are pure
data helpers — callers (PAY-002/003 + the router) own the gating.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

_RATE_SCALE = 1_000_000


def _norm_ccy(c: str) -> str:
    return (c or "").strip().upper()


def _pair(src: str, tgt: str) -> str:
    return f"{_norm_ccy(src)}_{_norm_ccy(tgt)}"


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _row_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    rate_micros = _to_int(item.get("rate_micros", 0))
    return {
        "pair": item.get("pair", ""),
        "source_currency": item.get("source_currency", ""),
        "target_currency": item.get("target_currency", ""),
        "rate": rate_micros / _RATE_SCALE,
        "source": item.get("source", "admin"),
        "as_of": _to_int(item.get("as_of", 0)),
        "set_by": item.get("set_by", ""),
    }


def set_rate(
    source_currency: str,
    target_currency: str,
    rate: float,
    *,
    source: str = "admin",
    set_by: str = "",
) -> Dict[str, Any]:
    """Admin-set a rate — appends a new ``as_of`` row (history retained)."""
    src, tgt = _norm_ccy(source_currency), _norm_ccy(target_currency)
    if not src or not tgt:
        raise ValueError("invalid_currency")
    if rate <= 0:
        raise ValueError("invalid_rate")
    if src == tgt:
        raise ValueError("identity_pair_not_stored")
    as_of = now_ts()
    item = {
        "pair": _pair(src, tgt),
        "as_of": as_of,
        "source_currency": src,
        "target_currency": tgt,
        "rate_micros": int(round(rate * _RATE_SCALE)),
        "source": source if source in ("admin", "fetched") else "admin",
        "set_by": set_by,
    }
    T.fx_rates.put_item(Item=item)
    try:
        from app.services.alerts import audit_event

        audit_event("fx_rate.set", set_by, None, pair=item["pair"], rate=rate, source=item["source"])
    except Exception:
        pass
    return _row_to_out(item)


def get_rate(source_currency: str, target_currency: str) -> Optional[Dict[str, Any]]:
    """Newest row for the pair; ``USD_USD`` (any identity pair) → synthetic 1.0."""
    src, tgt = _norm_ccy(source_currency), _norm_ccy(target_currency)
    if src == tgt:
        return {
            "pair": _pair(src, tgt),
            "source_currency": src,
            "target_currency": tgt,
            "rate": 1.0,
            "source": "identity",
            "as_of": now_ts(),
            "set_by": "system",
        }
    resp = T.fx_rates.query(
        KeyConditionExpression=Key("pair").eq(_pair(src, tgt)),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _row_to_out(items[0])


def convert(amount_cents: int, source_currency: str, target_currency: str) -> Dict[str, Any]:
    """Pure integer conversion. Writes NO ledger/wallet row (money-safety #5).

    ``target_amount_cents = round(amount_cents * rate_micros / 1_000_000)`` using
    integer math (no float accumulation). Missing pair → ``LookupError``.
    """
    src, tgt = _norm_ccy(source_currency), _norm_ccy(target_currency)
    if src == tgt:
        return {
            "source_currency": src,
            "target_currency": tgt,
            "source_amount_cents": int(amount_cents),
            "target_amount_cents": int(amount_cents),
            "rate": 1.0,
            "as_of": now_ts(),
        }
    rate = get_rate(src, tgt)
    if rate is None:
        raise LookupError("fx_rate_missing")
    rate_micros = int(round(rate["rate"] * _RATE_SCALE))
    target = (int(amount_cents) * rate_micros + _RATE_SCALE // 2) // _RATE_SCALE
    return {
        "source_currency": src,
        "target_currency": tgt,
        "source_amount_cents": int(amount_cents),
        "target_amount_cents": int(target),
        "rate": rate["rate"],
        "as_of": rate["as_of"],
    }
