"""
CCT-006 — vCard 3.0 import and export.

Pure-Python, no external libraries (follows the self-contained pattern of
app/services/receipts.py and app/services/audit_export_pipeline.py).

Export: GET /ui/party/parties/{party_id}/vcard
Import: POST /ui/party/vcard-import

Both gated on S.party_crm_enabled.

Storage is the SAME ``party`` table owned by app.services.party. This module uses
that table's REAL key schema (PK/SK) and the GSI2 (normalized contact-mech value)
+ GSI3 (OWNER#{user_sub}) indexes. Contact-mech values live under the ``value``
attribute. New mech rows carry SK=MECH#{mech_type}#{mech_id} and the GSI2 keys so
they participate in dedup lookups.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_VCARD_MAX_RECORDS = 500


def _pk(party_id: str) -> str:
    return f"PARTY#{party_id}"


def _mech_value(item: Dict[str, Any]) -> Any:
    v = item.get("value")
    if v in (None, ""):
        v = item.get("mech_value", "")
    return v


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _fold_vcard_line(line: str) -> str:
    """Fold a vCard line at 75 chars per RFC 6350 §3.2."""
    if len(line) <= 75:
        return line
    parts = [line[:75]]
    rest = line[75:]
    while rest:
        parts.append(" " + rest[:74])
        rest = rest[74:]
    return "\r\n".join(parts)


def _esc(s: str) -> str:
    """Escape special chars in vCard property values."""
    return s.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")


def export_party_as_vcard(party_id: str, *, actor_sub: str) -> bytes:
    """Build a vCard 3.0 .vcf file from the party's data."""
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    meta_resp = T.party.get_item(Key={"PK": _pk(party_id), "SK": "META"})
    meta = meta_resp.get("Item")
    if not meta:
        raise HTTPException(404, "party_not_found")

    party_type = meta.get("party_type", "PERSON")
    name = meta.get("name", "")
    display_name = meta.get("display_name") or name
    updated_at = int(meta.get("updated_at", 0))

    # Fetch mechs.
    mech_resp = T.party.query(
        KeyConditionExpression=Key("PK").eq(_pk(party_id))
        & Key("SK").begins_with("MECH#"),
    )
    mechs = mech_resp.get("Items", [])

    # Fetch employment relationship to get org name.
    emp_resp = T.party.query(
        KeyConditionExpression=Key("PK").eq(_pk(party_id))
        & Key("SK").begins_with("REL#EMPLOYMENT#"),
    )
    emp_items = emp_resp.get("Items", [])
    org_name = ""
    if emp_items:
        org_id = emp_items[0].get("to_party_id", "")
        if org_id:
            org_meta_resp = T.party.get_item(Key={"PK": _pk(org_id), "SK": "META"})
            org_meta = org_meta_resp.get("Item")
            if org_meta:
                org_name = org_meta.get("name", "")

    lines: List[str] = []
    lines.append("BEGIN:VCARD")
    lines.append("VERSION:3.0")

    if party_type == "PARTY_GROUP":
        lines.append(f"FN:{_esc(name)}")
        lines.append(f"ORG:{_esc(name)}")
    else:
        lines.append(f"FN:{_esc(display_name)}")
        parts = display_name.split(" ", 1)
        if len(parts) == 2:
            last, first = parts[1], parts[0]
        else:
            last, first = display_name, ""
        lines.append(f"N:{_esc(last)};{_esc(first)};;;")

    if org_name and party_type == "PERSON":
        lines.append(f"ORG:{_esc(org_name)}")

    title = meta.get("title", "")
    if title:
        lines.append(f"TITLE:{_esc(title)}")

    def _purpose_str(m: Dict[str, Any]) -> str:
        # Real mechs carry a ``purposes`` list; legacy carry a ``purpose`` scalar.
        purposes = m.get("purposes")
        if isinstance(purposes, (list, tuple)):
            return " ".join(str(p) for p in purposes).upper()
        return (m.get("purpose") or "").upper()

    # EMAIL mechs.
    for m in mechs:
        if m.get("mech_type") == "EMAIL":
            val = _mech_value(m) or ""
            purpose = _purpose_str(m)
            if "WORK" in purpose:
                type_str = "WORK"
            elif "HOME" in purpose:
                type_str = "HOME"
            else:
                type_str = "INTERNET"
            lines.append(f"EMAIL;TYPE={type_str}:{_esc(str(val))}")

    # TEL mechs.
    for m in mechs:
        if m.get("mech_type") == "PHONE":
            val = _mech_value(m) or ""
            purpose = _purpose_str(m)
            type_str = "WORK" if "WORK" in purpose else ("HOME" if "HOME" in purpose else "VOICE")
            lines.append(f"TEL;TYPE={type_str}:{_esc(str(val))}")

    # ADR mechs (POSTAL) — value is the address dict (or legacy postal_address).
    for m in mechs:
        if m.get("mech_type") == "POSTAL":
            pa = _mech_value(m)
            if not isinstance(pa, dict):
                pa = m.get("postal_address") or {}
            line1 = _esc(str(pa.get("line1", "")))
            line2 = _esc(str(pa.get("line2", "")))
            city = _esc(str(pa.get("city", "")))
            state = _esc(str(pa.get("state", "")))
            postal_code = _esc(str(pa.get("postal_code", "")))
            country = _esc(str(pa.get("country", "")))
            lines.append(f"ADR;TYPE=WORK:;;{line1} {line2};{city};{state};{postal_code};{country}")

    lines.append(f"UID:{party_id}")

    if updated_at:
        dt = datetime.fromtimestamp(updated_at, tz=timezone.utc)
        lines.append(f"REV:{dt.strftime('%Y%m%dT%H%M%SZ')}")

    lines.append("END:VCARD")

    vcf_content = "\r\n".join(_fold_vcard_line(l) for l in lines) + "\r\n"
    return vcf_content.encode("utf-8")


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

_FOLD_RE = re.compile(r"\r\n[ \t]")


def _unfold(text: str) -> str:
    """Join folded vCard lines."""
    return _FOLD_RE.sub("", text)


def _parse_vcards(raw: str) -> List[Dict[str, List[str]]]:
    """Parse one or more vCard records from raw text.

    Returns a list of dicts mapping property name → list of raw values.
    """
    text = _unfold(raw.replace("\r\n", "\n").replace("\r", "\n"))
    records: List[Dict[str, List[str]]] = []
    current: Optional[Dict[str, List[str]]] = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        upper = line.upper()
        if upper == "BEGIN:VCARD":
            current = {}
        elif upper == "END:VCARD":
            if current is not None:
                records.append(current)
            current = None
        elif current is not None:
            if ":" not in line:
                continue
            prop_part, _, value = line.partition(":")
            prop_name = prop_part.split(";")[0].upper()
            if prop_name not in current:
                current[prop_name] = []
            current[prop_name].append(value.strip())
    return records


def _unescape(s: str) -> str:
    return (
        s.replace("\\,", ",")
         .replace("\\;", ";")
         .replace("\\n", "\n")
         .replace("\\\\", "\\")
    )


def _find_existing_by_correlation(actor_sub: str, correlation_id: str) -> Optional[Dict[str, Any]]:
    """Look up an existing imported party by owner + correlation_id via GSI3."""
    if not actor_sub:
        return None
    resp = T.party.query(
        IndexName="GSI3",
        KeyConditionExpression=Key("GSI3PK").eq(f"OWNER#{actor_sub}"),
    )
    for item in resp.get("Items", []):
        if item.get("SK") == "META" and item.get("correlation_id") == correlation_id:
            return item
    return None


def _create_party_from_vcard(
    record: Dict[str, List[str]],
    *,
    actor_sub: str,
) -> Optional[Dict[str, Any]]:
    """Create (or return existing) party from a vCard record dict."""
    fn_vals = record.get("FN", [])
    fn = _unescape(fn_vals[0]) if fn_vals else ""
    if not fn:
        return None

    has_org = bool(record.get("ORG"))
    has_n = bool(record.get("N"))
    party_type = "PARTY_GROUP" if (has_org and not has_n) else "PERSON"

    email_vals = record.get("EMAIL", [])
    first_email = _unescape(email_vals[0]).lower() if email_vals else ""
    corr_input = f"{fn}|{first_email}"
    correlation_id = hashlib.sha256(corr_input.encode()).hexdigest()

    existing = _find_existing_by_correlation(actor_sub, correlation_id)
    if existing:
        return existing

    # Deterministic party_id from the correlation hash → idempotent re-import.
    party_id = correlation_id[:32]
    ts = now_ts()
    meta_item: Dict[str, Any] = {
        "PK": _pk(party_id),
        "SK": "META",
        "party_id": party_id,
        "party_type": party_type,
        "status": "ACTIVE",
        "name": fn,
        "display_name": fn,
        "owner_user_sub": actor_sub,
        "user_sub": actor_sub,
        "type": f"TYPE#{party_type}",
        "created_at": ts,
        "updated_at": ts,
        "correlation_id": correlation_id,
        "GSI3PK": f"OWNER#{actor_sub}",
        "GSI3SK": f"PARTY#{party_id}",
    }
    try:
        T.party.put_item(
            Item=meta_item, ConditionExpression="attribute_not_exists(PK)"
        )
    except Exception as exc:
        if "ConditionalCheckFailedException" in type(exc).__name__:
            resp = T.party.get_item(Key={"PK": _pk(party_id), "SK": "META"})
            if resp.get("Item"):
                return resp["Item"]
        raise

    # Add EMAIL mechs.
    for email_val in record.get("EMAIL", []):
        email = _unescape(email_val).lower().strip()
        if not email or "@" not in email:
            continue  # skip malformed — not fatal
        mech_id = uuid4().hex
        T.party.put_item(Item={
            "PK": _pk(party_id),
            "SK": f"MECH#EMAIL#{mech_id}",
            "mech_id": mech_id,
            "party_id": party_id,
            "mech_type": "EMAIL",
            "value": email,
            "purposes": ["WORK_EMAIL"],
            "verified": False,
            "created_at": ts,
            "updated_at": ts,
            "GSI2PK": f"EMAIL#{email}",
            "GSI2SK": f"PARTY#{party_id}",
        })

    # Add PHONE mechs.
    for tel_val in record.get("TEL", []):
        tel = _unescape(tel_val).strip()
        if not tel:
            continue
        try:
            from app.core.normalize import normalize_phone
            tel = normalize_phone(tel)
        except Exception:
            pass  # keep as-is if normalization fails
        mech_id = uuid4().hex
        T.party.put_item(Item={
            "PK": _pk(party_id),
            "SK": f"MECH#PHONE#{mech_id}",
            "mech_id": mech_id,
            "party_id": party_id,
            "mech_type": "PHONE",
            "value": tel,
            "purposes": ["WORK_PHONE"],
            "verified": False,
            "created_at": ts,
            "updated_at": ts,
            "GSI2PK": f"PHONE#{tel}",
            "GSI2SK": f"PARTY#{party_id}",
        })

    try:
        from app.services.alerts import audit_event
        audit_event("party.vcard_import", actor_sub, party_id=party_id, source="vcf")
    except Exception:
        pass

    return meta_item


def import_vcard(vcf_bytes: bytes, *, actor_sub: str) -> List[Dict[str, Any]]:
    """Parse one or more vCard records and create party entries.

    Returns list of CctPartyOut dicts (created or existing-by-idempotency).
    Caps at _VCARD_MAX_RECORDS records per call.
    """
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    try:
        text = vcf_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(400, "invalid_vcf_encoding") from exc

    records = _parse_vcards(text)

    if len(records) > _VCARD_MAX_RECORDS:
        raise HTTPException(400, "too_many_vcards")

    results: List[Dict[str, Any]] = []
    for record in records:
        party = _create_party_from_vcard(record, actor_sub=actor_sub)
        if party:
            results.append(party)

    return results
