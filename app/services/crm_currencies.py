"""INV-002 — Admin currency registry + exchange-rate accessor.

DynamoDB-backed registry of supported currencies (ISO 4217 code, symbol,
decimal precision, and a ``rate_to_usd`` exchange rate). Gated entirely behind
``S.crm_currencies_enabled`` (default OFF) — with the flag off every public
function raises ``ValueError("currency management not enabled")`` immediately
and no DDB call is made.

Used by INV-003 (transaction-time conversion) and INV-004 (PDF symbol lookup),
both of which call into this module via lazy imports + try/except (fail-open).

Money is always integer cents; ``rate_to_usd`` is a ``Decimal`` ("units of USD
per 1 unit of this currency"; ``1`` for USD itself). No ``dev_mode`` branch.
"""
from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

_ACTIVE_GSI1PK = "CURRENCIES#ACTIVE"


def _require_enabled() -> None:
    if not S.crm_currencies_enabled:
        raise ValueError("currency management not enabled")


def _pk(iso_code: str) -> str:
    return f"CURRENCY#{iso_code}"


def _norm_iso(iso_code: str) -> str:
    return str(iso_code or "").strip().lower()


def _to_decimal(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"invalid decimal: {value!r}")


def _serialize(item: Dict[str, Any]) -> Dict[str, Any]:
    try:
        rate = float(item.get("rate_to_usd")) if item.get("rate_to_usd") is not None else 0.0
    except (TypeError, ValueError):
        rate = 0.0
    return {
        "iso_code": str(item.get("iso_code") or ""),
        "name": str(item.get("name") or ""),
        "symbol": str(item.get("symbol") or ""),
        "rate_to_usd": rate,
        "decimal_places": int(item.get("decimal_places") or 0),
        "is_active": bool(item.get("is_active", True)),
        "is_default": bool(item.get("is_default", False)),
        "created_at": int(item.get("created_at") or 0),
        "updated_at": int(item.get("updated_at") or 0),
    }


def create_currency(
    iso_code: str,
    name: str,
    symbol: str,
    rate_to_usd: Decimal,
    decimal_places: int = 2,
    is_active: bool = True,
    is_default: bool = False,
    created_by: Optional[str] = None,
) -> Dict[str, Any]:
    _require_enabled()
    iso = _norm_iso(iso_code)
    if len(iso) != 3:
        raise ValueError("iso_code must be exactly 3 characters")
    rate = _to_decimal(rate_to_usd)
    if rate <= 0:
        raise ValueError("rate_to_usd must be > 0")
    dp = int(decimal_places)
    if dp < 0 or dp > 4:
        raise ValueError("decimal_places must be in [0, 4]")

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(iso),
        "sk": "META",
        "iso_code": iso,
        "name": str(name),
        "symbol": str(symbol),
        "rate_to_usd": rate,
        "decimal_places": dp,
        "is_active": bool(is_active),
        "is_default": bool(is_default),
        "created_at": ts,
        "updated_at": ts,
    }
    if is_active:
        item["GSI1PK"] = _ACTIVE_GSI1PK
        item["GSI1SK"] = iso
    try:
        T.crm_currencies.put_item(
            Item=item, ConditionExpression="attribute_not_exists(pk)"
        )
    except Exception as exc:  # ConditionalCheckFailed → duplicate
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
            raise ValueError(f"currency already exists: {iso}")
        raise
    _audit("currency.created", created_by, iso_code=iso, rate_to_usd=str(rate))
    return _serialize(item)


def update_currency(
    iso_code: str,
    *,
    name: Optional[str] = None,
    symbol: Optional[str] = None,
    rate_to_usd: Optional[Decimal] = None,
    is_active: Optional[bool] = None,
    decimal_places: Optional[int] = None,
    updated_by: Optional[str] = None,
) -> Dict[str, Any]:
    _require_enabled()
    iso = _norm_iso(iso_code)
    existing = T.crm_currencies.get_item(Key={"pk": _pk(iso), "sk": "META"}).get("Item")
    if not existing:
        raise ValueError(f"currency not found: {iso}")

    set_parts: List[str] = ["updated_at = :ua"]
    remove_parts: List[str] = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {":ua": now_ts()}
    rate_changed = False
    old_rate = existing.get("rate_to_usd")

    if name is not None:
        names["#n"] = "name"
        set_parts.append("#n = :name")
        values[":name"] = str(name)
    if symbol is not None:
        set_parts.append("symbol = :sym")
        values[":sym"] = str(symbol)
    if decimal_places is not None:
        dp = int(decimal_places)
        if dp < 0 or dp > 4:
            raise ValueError("decimal_places must be in [0, 4]")
        set_parts.append("decimal_places = :dp")
        values[":dp"] = dp
    if rate_to_usd is not None:
        rate = _to_decimal(rate_to_usd)
        if rate <= 0:
            raise ValueError("rate_to_usd must be > 0")
        set_parts.append("rate_to_usd = :rate")
        values[":rate"] = rate
        rate_changed = True
    if is_active is not None:
        set_parts.append("is_active = :act")
        values[":act"] = bool(is_active)
        if is_active:
            set_parts.append("GSI1PK = :g1pk")
            set_parts.append("GSI1SK = :g1sk")
            values[":g1pk"] = _ACTIVE_GSI1PK
            values[":g1sk"] = iso
        else:
            remove_parts.extend(["GSI1PK", "GSI1SK"])

    update_expr = "SET " + ", ".join(set_parts)
    actual_removes = [r for r in remove_parts if r in existing]
    if actual_removes:
        update_expr += " REMOVE " + ", ".join(actual_removes)

    kwargs: Dict[str, Any] = {
        "Key": {"pk": _pk(iso), "sk": "META"},
        "UpdateExpression": update_expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.crm_currencies.update_item(**kwargs)

    if rate_changed:
        _audit(
            "currency.rate_updated", updated_by,
            iso_code=iso, old_rate=str(old_rate), new_rate=str(values[":rate"]),
        )
    else:
        _audit("currency.updated", updated_by, iso_code=iso)

    updated = T.crm_currencies.get_item(Key={"pk": _pk(iso), "sk": "META"}).get("Item") or {}
    return _serialize(updated)


def get_currency(iso_code: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    iso = _norm_iso(iso_code)
    item = T.crm_currencies.get_item(Key={"pk": _pk(iso), "sk": "META"}).get("Item")
    return _serialize(item) if item else None


def list_currencies(active_only: bool = True) -> List[Dict[str, Any]]:
    _require_enabled()
    if active_only:
        resp = T.crm_currencies.query(
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": _ACTIVE_GSI1PK},
            ScanIndexForward=True,
            Limit=200,
        )
        items = resp.get("Items", [])
    else:
        resp = T.crm_currencies.scan(
            FilterExpression="begins_with(pk, :p) AND sk = :m",
            ExpressionAttributeValues={":p": "CURRENCY#", ":m": "META"},
            Limit=200,
        )
        items = resp.get("Items", [])
        items.sort(key=lambda it: str(it.get("iso_code") or ""))
    return [_serialize(it) for it in items]


def _rate_to_usd_for(iso: str) -> Decimal:
    """Return the ``rate_to_usd`` Decimal for an active currency.

    Treats ``usd`` as ``Decimal("1")`` even when no row is seeded. Raises
    ``ValueError`` for unknown or inactive currencies.
    """
    if iso == "usd":
        item = T.crm_currencies.get_item(Key={"pk": _pk("usd"), "sk": "META"}).get("Item")
        if item is None:
            return Decimal("1")
        if not bool(item.get("is_active", True)):
            raise ValueError("currency not active: usd")
        return _to_decimal(item.get("rate_to_usd") or "1")
    item = T.crm_currencies.get_item(Key={"pk": _pk(iso), "sk": "META"}).get("Item")
    if not item:
        raise ValueError(f"currency not found: {iso}")
    if not bool(item.get("is_active", True)):
        raise ValueError(f"currency not active: {iso}")
    rate = _to_decimal(item.get("rate_to_usd"))
    if rate <= 0:
        raise ValueError(f"invalid rate for currency: {iso}")
    return rate


def get_exchange_rate(from_iso: str, to_iso: str) -> Decimal:
    """Cross-rate: ``from_currency.rate_to_usd / to_currency.rate_to_usd``."""
    _require_enabled()
    f = _norm_iso(from_iso)
    t = _norm_iso(to_iso)
    if f == t:
        return Decimal("1")
    from_rate = _rate_to_usd_for(f)
    to_rate = _rate_to_usd_for(t)
    if to_rate <= 0:
        raise ValueError(f"invalid rate for currency: {t}")
    return from_rate / to_rate


def convert_amount(amount_cents: int, from_iso: str, to_iso: str) -> int:
    """Apply ``get_exchange_rate`` and return rounded integer cents."""
    f = _norm_iso(from_iso)
    t = _norm_iso(to_iso)
    if f == t:
        return int(amount_cents)
    _require_enabled()
    rate = get_exchange_rate(f, t)
    return int((Decimal(int(amount_cents)) * rate).to_integral_value(rounding="ROUND_HALF_EVEN"))


def _audit(event: str, user_sub: Optional[str], **fields: Any) -> None:
    try:
        audit_event(event, str(user_sub or "system"), None, **fields)
    except Exception:  # pragma: no cover - audit must never break the write
        logger.debug("currency audit emit failed", exc_info=True)
