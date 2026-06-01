"""Versioned signature templates (KYC-007).

A *signature template* is a named, versioned definition of the fields a signature
packet should contain. When terms change, a NEW version is created — existing
packets that pinned an earlier version are never mutated, so in-flight cases keep
the exact terms they were created under.

Storage: ``signature_templates`` DDB table.
    PK = ``template_key`` (str)
    SK = ``version`` (int, monotonically increasing per key)

Each version row stores the full field list and a content snapshot. A packet
pins a template by recording ``(template_key, version)``; ``is_packet_outdated``
compares that pin against the latest version to drive re-signing migration.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.signature_packet_domain import SignatureFieldType
from app.services.signature_packet_flags import require_signature_pdf_enabled

# Field types permitted inside a versioned template definition. Mirrors the
# SignatureFieldType enum and explicitly includes the KYC-007 notary_stamp type.
VALID_TEMPLATE_FIELD_TYPES = frozenset(t.value for t in SignatureFieldType)


class TemplateVersionError(ValueError):
    """Raised on template-versioning validation failures."""


def _decimal_to_int(value: Any) -> int:
    if isinstance(value, Decimal):
        return int(value)
    return int(value or 0)


def _normalize_fields(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for raw in fields or []:
        field_id = str((raw or {}).get("id") or (raw or {}).get("field_id") or "").strip()
        field_type = str((raw or {}).get("type") or (raw or {}).get("field_type") or "").strip()
        if not field_id:
            raise TemplateVersionError("template_field_missing_id")
        if field_id in seen:
            raise TemplateVersionError("template_field_duplicate_id")
        if field_type not in VALID_TEMPLATE_FIELD_TYPES:
            raise TemplateVersionError("template_field_invalid_type")
        seen.add(field_id)
        entry: Dict[str, Any] = {
            "id": field_id,
            "type": field_type,
            "label": str((raw or {}).get("label") or field_id),
            "required": bool((raw or {}).get("required", True)),
        }
        normalized.append(entry)
    if not normalized:
        raise TemplateVersionError("template_no_fields")
    return normalized


def _row_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template_key": str(item.get("template_key") or ""),
        "version": _decimal_to_int(item.get("version")),
        "display_name": str(item.get("display_name") or ""),
        "description": str(item.get("description") or ""),
        "fields": list(item.get("fields") or []),
        "created_at": _decimal_to_int(item.get("created_at")),
        "created_by": str(item.get("created_by") or ""),
        "is_active": bool(item.get("is_active", True)),
    }


def list_template_versions(template_key: str) -> List[Dict[str, Any]]:
    """Return all versions of a template, newest version first."""
    require_signature_pdf_enabled()
    resp = T.signature_templates.query(
        KeyConditionExpression=Key("template_key").eq(template_key),
        ScanIndexForward=False,
    )
    return [_row_to_out(i) for i in resp.get("Items", [])]


def get_template_version(template_key: str, version: int) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    item = T.signature_templates.get_item(
        Key={"template_key": template_key, "version": int(version)}
    ).get("Item")
    return _row_to_out(item) if item else None


def get_latest_template_version(template_key: str) -> Optional[Dict[str, Any]]:
    versions = list_template_versions(template_key)
    return versions[0] if versions else None


def create_template_version(
    *,
    template_key: str,
    display_name: str,
    description: str,
    fields: List[Dict[str, Any]],
    created_by: str,
) -> Dict[str, Any]:
    """Create the next version of a template.

    The first call for a ``template_key`` creates version 1; subsequent calls
    increment from the current latest version. Existing versions are never
    mutated — this is what keeps in-flight packets immutable.
    """
    require_signature_pdf_enabled()
    key = (template_key or "").strip()
    if not key:
        raise TemplateVersionError("template_key_required")
    if not (display_name or "").strip():
        raise TemplateVersionError("template_display_name_required")
    normalized_fields = _normalize_fields(fields)

    latest = get_latest_template_version(key)
    next_version = (latest["version"] + 1) if latest else 1
    now = now_ts()
    item: Dict[str, Any] = {
        "template_key": key,
        "version": int(next_version),
        "display_name": display_name.strip(),
        "description": (description or "").strip(),
        "fields": normalized_fields,
        "created_at": int(now),
        "created_by": created_by or "",
        "is_active": True,
    }
    T.signature_templates.put_item(Item=item)
    return _row_to_out(item)


def list_all_template_keys() -> List[Dict[str, Any]]:
    """Return the latest version summary for every distinct template key."""
    require_signature_pdf_enabled()
    resp = T.signature_templates.scan()
    latest_by_key: Dict[str, Dict[str, Any]] = {}
    for raw in resp.get("Items", []):
        out = _row_to_out(raw)
        key = out["template_key"]
        if key not in latest_by_key or out["version"] > latest_by_key[key]["version"]:
            latest_by_key[key] = out
    return sorted(latest_by_key.values(), key=lambda r: r["template_key"])


def is_packet_outdated(template_key: str, pinned_version: int) -> bool:
    """True if a newer version exists than the one a packet pinned."""
    latest = get_latest_template_version(template_key)
    if not latest:
        return False
    return int(latest["version"]) > int(pinned_version)


def check_version_migration(pins: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Given a list of ``{template_key, version}`` pins, return the subset that
    has a newer template version available (i.e. needs re-signing)."""
    migrations: List[Dict[str, Any]] = []
    for pin in pins or []:
        key = str(pin.get("template_key") or "")
        pinned = int(pin.get("version") or 0)
        if not key:
            continue
        latest = get_latest_template_version(key)
        if latest and int(latest["version"]) > pinned:
            migrations.append(
                {
                    "template_key": key,
                    "display_name": latest["display_name"],
                    "pinned_version": pinned,
                    "latest_version": int(latest["version"]),
                    "needs_resigning": True,
                }
            )
    return migrations
