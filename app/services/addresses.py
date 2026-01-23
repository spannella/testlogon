from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.time import now_ts
from app.core.tables import T
from app.services.profile import apply_profile_update

MAX_ADDRESS_LINE_LEN = 120
MAX_LABEL_LEN = 64
MAX_NOTES_LEN = 280


def _clean_str(value: Optional[str], *, max_len: Optional[int] = None) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    if max_len is not None and len(trimmed) > max_len:
        raise HTTPException(400, f"Value too long (max {max_len})")
    return trimmed


def _normalize_country(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = _clean_str(value, max_len=2)
    return cleaned.upper() if cleaned else None


def normalize_address_payload(data: Dict[str, Any], *, require_all: bool) -> Dict[str, Any]:
    out = {
        "name": _clean_str(data.get("name"), max_len=MAX_ADDRESS_LINE_LEN),
        "line1": _clean_str(data.get("line1"), max_len=MAX_ADDRESS_LINE_LEN),
        "line2": _clean_str(data.get("line2"), max_len=MAX_ADDRESS_LINE_LEN),
        "city": _clean_str(data.get("city"), max_len=MAX_ADDRESS_LINE_LEN),
        "state": _clean_str(data.get("state"), max_len=MAX_ADDRESS_LINE_LEN),
        "postal_code": _clean_str(data.get("postal_code"), max_len=MAX_ADDRESS_LINE_LEN),
        "country": _normalize_country(data.get("country")) or "US",
        "label": _clean_str(data.get("label"), max_len=MAX_LABEL_LEN),
        "notes": _clean_str(data.get("notes"), max_len=MAX_NOTES_LEN),
    }

    if require_all:
        missing = [
            field
            for field in ("line1", "city", "state", "postal_code")
            if not out.get(field)
        ]
        if missing:
            raise HTTPException(400, f"Missing required fields: {', '.join(missing)}")

    return {k: v for k, v in out.items() if v is not None}


def list_addresses(user_sub: str) -> List[Dict[str, Any]]:
    resp = T.addresses.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    return list(resp.get("Items", []))


def get_address(user_sub: str, address_id: str) -> Dict[str, Any]:
    item = T.addresses.get_item(Key={"user_sub": user_sub, "address_id": address_id}).get("Item")
    if not item:
        raise HTTPException(404, "address not found")
    return item


def create_address(user_sub: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_address_payload(payload, require_all=True)
    ts = now_ts()
    address_id = uuid.uuid4().hex
    item = {
        "user_sub": user_sub,
        "address_id": address_id,
        "is_primary_mailing": False,
        "created_at": ts,
        "updated_at": ts,
        **normalized,
    }
    T.addresses.put_item(Item=item)
    return item


def update_address(user_sub: str, address_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    current = get_address(user_sub, address_id)
    normalized = normalize_address_payload(payload, require_all=False)
    if not normalized:
        raise HTTPException(400, "No valid fields to update")
    updated = {
        **current,
        **normalized,
        "updated_at": now_ts(),
    }
    T.addresses.put_item(Item=updated)
    return updated


def delete_address(user_sub: str, address_id: str) -> Dict[str, Any]:
    current = get_address(user_sub, address_id)
    T.addresses.delete_item(Key={"user_sub": user_sub, "address_id": address_id})
    if current.get("is_primary_mailing"):
        apply_profile_update(user_sub, {"mailing_address": None}, replace=False)
    return current


def set_primary_address(user_sub: str, address_id: str) -> Dict[str, Any]:
    addresses = list_addresses(user_sub)
    target = next((address for address in addresses if address.get("address_id") == address_id), None)
    if not target:
        raise HTTPException(404, "address not found")

    ts = now_ts()
    for address in addresses:
        is_primary = address.get("address_id") == address_id
        if address.get("is_primary_mailing") == is_primary:
            continue
        updated = {**address, "is_primary_mailing": is_primary, "updated_at": ts}
        T.addresses.put_item(Item=updated)

    mailing = {
        "line1": target.get("line1"),
        "line2": target.get("line2"),
        "city": target.get("city"),
        "state": target.get("state"),
        "postal_code": target.get("postal_code"),
        "country": target.get("country"),
    }
    apply_profile_update(user_sub, {"mailing_address": mailing}, replace=False)
    target["is_primary_mailing"] = True
    target["updated_at"] = ts
    return target


def search_addresses(user_sub: str, query: str) -> List[Dict[str, Any]]:
    q = (query or "").strip().lower()
    if not q:
        return list_addresses(user_sub)

    matches: List[Dict[str, Any]] = []
    for address in list_addresses(user_sub):
        haystack = " ".join(
            str(address.get(k) or "")
            for k in ("name", "label", "line1", "line2", "city", "state", "postal_code", "country")
        ).lower()
        if q in haystack:
            matches.append(address)
    return matches
