"""INV-005 — Named tax rate / jurisdiction registry.

Admin-managed registry of named tax groups (e.g. "CA Sales Tax 9.5%") each
carrying a jurisdiction label, a ``rate_bps`` integer, and an active toggle.
Referenced at line-item level by INV-006 (per-line tax assignment).

Gated entirely behind ``S.crm_tax_rates_enabled`` (default OFF) — with the flag
off every public function raises ``ValueError("crm_tax_rates is not enabled")``
and no DDB call is made. No ``dev_mode`` branch (SECOPS-007 parity).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

_ACTIVE_GSI1PK = "TAXRATES#ACTIVE"


def _require_enabled() -> None:
    if not S.crm_tax_rates_enabled:
        raise ValueError("crm_tax_rates is not enabled")


def _pk(tax_rate_id: str) -> str:
    return f"TAXRATE#{tax_rate_id}"


def _jur_pk(jurisdiction: str) -> str:
    return f"JURISDICTION#{jurisdiction}"


def _serialize(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tax_rate_id": str(item.get("tax_rate_id") or ""),
        "name": str(item.get("name") or ""),
        "rate_bps": int(item.get("rate_bps") or 0),
        "jurisdiction": str(item.get("jurisdiction") or ""),
        "description": str(item.get("description") or ""),
        "is_active": bool(item.get("is_active", True)),
        "created_by": str(item.get("created_by") or ""),
        "created_at": int(item.get("created_at") or 0),
        "updated_at": int(item.get("updated_at") or 0),
    }


def create_tax_rate(
    *,
    name: str,
    rate_bps: int,
    jurisdiction: str,
    description: str = "",
    created_by: str = "",
) -> Dict[str, Any]:
    _require_enabled()
    rate_bps = int(rate_bps)
    if rate_bps < 0 or rate_bps > 10000:
        raise ValueError("invalid_rate_bps")
    jur = str(jurisdiction or "").strip().upper()
    if not jur:
        raise ValueError("jurisdiction required")
    if not str(name or "").strip():
        raise ValueError("name required")

    tax_rate_id = "tr_" + uuid.uuid4().hex[:12]
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _pk(tax_rate_id),
        "sk": "META",
        "tax_rate_id": tax_rate_id,
        "name": str(name),
        "rate_bps": rate_bps,
        "jurisdiction": jur,
        "description": str(description or ""),
        "is_active": True,
        "created_by": str(created_by or ""),
        "created_at": ts,
        "updated_at": ts,
        "GSI1PK": _ACTIVE_GSI1PK,
        "GSI1SK": str(name),
        "GSI2PK": _jur_pk(jur),
        "GSI2SK": str(name),
    }
    T.crm_tax_rates.put_item(Item=item)
    _audit(
        "tax_rate.created", created_by,
        tax_rate_id=tax_rate_id, name=name, rate_bps=rate_bps, jurisdiction=jur,
    )
    return _serialize(item)


def update_tax_rate(
    tax_rate_id: str,
    *,
    name: Optional[str] = None,
    rate_bps: Optional[int] = None,
    jurisdiction: Optional[str] = None,
    description: Optional[str] = None,
    is_active: Optional[bool] = None,
    updated_by: str = "",
) -> Dict[str, Any]:
    _require_enabled()
    existing = T.crm_tax_rates.get_item(Key={"pk": _pk(tax_rate_id), "sk": "META"}).get("Item")
    if not existing:
        raise KeyError(tax_rate_id)

    new_name = str(name) if name is not None else str(existing.get("name") or "")
    new_jur = (
        str(jurisdiction).strip().upper()
        if jurisdiction is not None
        else str(existing.get("jurisdiction") or "")
    )

    set_parts: List[str] = ["updated_at = :ua"]
    remove_parts: List[str] = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {":ua": now_ts()}

    if name is not None:
        names["#n"] = "name"
        set_parts.append("#n = :name")
        values[":name"] = str(name)
    if rate_bps is not None:
        rb = int(rate_bps)
        if rb < 0 or rb > 10000:
            raise ValueError("invalid_rate_bps")
        set_parts.append("rate_bps = :rb")
        values[":rb"] = rb
    if jurisdiction is not None:
        set_parts.append("jurisdiction = :jur")
        values[":jur"] = new_jur
    if description is not None:
        set_parts.append("description = :desc")
        values[":desc"] = str(description)

    deactivating = False
    if is_active is not None:
        set_parts.append("is_active = :act")
        values[":act"] = bool(is_active)
        if is_active:
            set_parts.append("GSI1PK = :g1pk")
            values[":g1pk"] = _ACTIVE_GSI1PK
        else:
            deactivating = True
            remove_parts.append("GSI1PK")

    # Keep GSI sort/partition keys consistent when name/jurisdiction changed and
    # the item remains in the active index.
    if (name is not None) and not deactivating:
        set_parts.append("GSI1SK = :g1sk")
        values[":g1sk"] = new_name
    if name is not None or jurisdiction is not None:
        set_parts.append("GSI2PK = :g2pk")
        set_parts.append("GSI2SK = :g2sk")
        values[":g2pk"] = _jur_pk(new_jur)
        values[":g2sk"] = new_name

    update_expr = "SET " + ", ".join(set_parts)
    actual_removes = [r for r in remove_parts if r in existing]
    if actual_removes:
        update_expr += " REMOVE " + ", ".join(actual_removes)

    kwargs: Dict[str, Any] = {
        "Key": {"pk": _pk(tax_rate_id), "sk": "META"},
        "UpdateExpression": update_expr,
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.crm_tax_rates.update_item(**kwargs)

    eff_rate = int(values.get(":rb", existing.get("rate_bps") or 0))
    _audit(
        "tax_rate.updated", updated_by,
        tax_rate_id=tax_rate_id, name=new_name, jurisdiction=new_jur, rate_bps=eff_rate,
    )
    if deactivating:
        _audit(
            "tax_rate.deactivated", updated_by,
            tax_rate_id=tax_rate_id, name=new_name, jurisdiction=new_jur, rate_bps=eff_rate,
        )

    updated = T.crm_tax_rates.get_item(Key={"pk": _pk(tax_rate_id), "sk": "META"}).get("Item") or {}
    return _serialize(updated)


def get_tax_rate(tax_rate_id: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    item = T.crm_tax_rates.get_item(Key={"pk": _pk(tax_rate_id), "sk": "META"}).get("Item")
    return _serialize(item) if item else None


def get_tax_rate_by_name(name: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.crm_tax_rates.query(
        IndexName="taxrates-active-index",
        KeyConditionExpression="GSI1PK = :pk AND GSI1SK = :name",
        ExpressionAttributeValues={":pk": _ACTIVE_GSI1PK, ":name": str(name)},
        Limit=1,
    )
    items = resp.get("Items", [])
    return _serialize(items[0]) if items else None


def list_tax_rates(
    jurisdiction: Optional[str] = None,
    active_only: bool = True,
    limit: int = 200,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    _require_enabled()
    limit = max(1, min(int(limit or 200), 200))
    out: List[Dict[str, Any]] = []
    start_key = decode_cursor(cursor)
    next_cursor: Optional[str] = None

    if jurisdiction:
        jur = str(jurisdiction).strip().upper()
        lek = start_key
        while len(out) < limit:
            kwargs: Dict[str, Any] = {
                "IndexName": "taxrates-jurisdiction-index",
                "KeyConditionExpression": "GSI2PK = :pk",
                "ExpressionAttributeValues": {":pk": _jur_pk(jur)},
                "Limit": limit,
            }
            if active_only:
                kwargs["FilterExpression"] = "is_active = :true"
                kwargs["ExpressionAttributeValues"][":true"] = True
            if lek:
                kwargs["ExclusiveStartKey"] = lek
            resp = T.crm_tax_rates.query(**kwargs)
            for it in resp.get("Items", []):
                out.append(_serialize(it))
                if len(out) >= limit:
                    break
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
        next_cursor = encode_cursor(_clean_lek(lek)) if lek and len(out) >= limit else None
    elif active_only:
        kwargs = {
            "IndexName": "taxrates-active-index",
            "KeyConditionExpression": "GSI1PK = :pk",
            "ExpressionAttributeValues": {":pk": _ACTIVE_GSI1PK},
            "ScanIndexForward": True,
            "Limit": limit,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.crm_tax_rates.query(**kwargs)
        out = [_serialize(it) for it in resp.get("Items", [])]
        next_cursor = encode_cursor(_clean_lek(resp.get("LastEvaluatedKey")))
    else:
        kwargs = {
            "FilterExpression": "begins_with(pk, :p) AND sk = :m",
            "ExpressionAttributeValues": {":p": "TAXRATE#", ":m": "META"},
            "Limit": limit,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.crm_tax_rates.scan(**kwargs)
        out = [_serialize(it) for it in resp.get("Items", [])]
        next_cursor = encode_cursor(_clean_lek(resp.get("LastEvaluatedKey")))

    return {"tax_rates": out, "next_cursor": next_cursor}


def _clean_lek(lek: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not lek:
        return None
    from decimal import Decimal
    out: Dict[str, Any] = {}
    for k, v in lek.items():
        out[k] = int(v) if isinstance(v, Decimal) else v
    return out


def _audit(event: str, user_sub: Optional[str], **fields: Any) -> None:
    try:
        audit_event(event, str(user_sub or "system"), None, **fields)
    except Exception:  # pragma: no cover
        logger.debug("tax_rate audit emit failed", exc_info=True)
