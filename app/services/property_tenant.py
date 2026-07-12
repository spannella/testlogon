"""
Property Tenant service — TEN-001 (CRUD), TEN-002 (profile, income docs, emergency contacts,
active-unit link), TEN-003 (lease-history projection).

Gated by S.property_tenants_enabled (PROPERTY_TENANTS_ENABLED, default False).
No S.dev_mode branch anywhere (SECOPS-007 parity).
No money path (rent ledger belongs to RNT cluster).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Module-level constant
# ---------------------------------------------------------------------------
_MAX_EMERGENCY_CONTACTS = int(os.environ.get("TENANT_MAX_EMERGENCY_CONTACTS", "5"))

# ---------------------------------------------------------------------------
# Flag helpers — mirror app/services/inventory.py:50-57 (404 gate, matching PROP-001)
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "property_tenants_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Property tenants are not enabled")


# ---------------------------------------------------------------------------
# Audit wrapper — mirror app/services/inventory.py:92-98
# ---------------------------------------------------------------------------


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _normalize_email_opt(email: Optional[str]) -> Optional[str]:
    if not email:
        return None
    from app.core.normalize import normalize_email

    return normalize_email(email)


def _normalize_phone_opt(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None
    from app.core.normalize import normalize_phone

    return normalize_phone(phone)


# ---------------------------------------------------------------------------
# TEN-001: Core CRUD
# ---------------------------------------------------------------------------

VALID_STATUSES = {"prospect", "active", "past"}
VALID_PATCH_KEYS = {"display_name", "email", "phone", "status"}


def create_tenant(
    owner_id: str,
    *,
    display_name: str,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    party_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> dict:
    """Create a new tenant META row. Idempotent when correlation_id is supplied."""
    _require_enabled()

    # Derive tenant_id
    if correlation_id:
        tenant_id = hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:32]
    else:
        tenant_id = uuid4().hex

    # Normalize optional contact fields
    email = _normalize_email_opt(email)
    phone = _normalize_phone_opt(phone)

    # Create PTY PERSON party if not supplied (lazy import — party may not be merged yet)
    if party_id is None:
        try:
            from app.services import party  # type: ignore[import]

            result = party.create_party(
                "PERSON",
                user_sub=owner_id,
                correlation_id=f"tenant:{tenant_id}",
            )
            party_id = result["party_id"]
        except ImportError:
            # PTY-004 not yet merged — fall back to deterministic opaque id
            party_id = uuid4().hex
        except Exception:
            party_id = uuid4().hex

    # Best-effort seed display_name from platform profile
    if not display_name:
        try:
            from app.services.profile import get_profile_identity

            ident = get_profile_identity(owner_id)
            display_name = ident.get("display_name") or email or "Unknown"
        except Exception:
            pass

    ts = now_ts()
    item: dict = {
        "PK": f"TENANT#{tenant_id}",
        "SK": "META",
        "tenant_id": tenant_id,
        "owner_id": owner_id,
        "party_id": party_id,
        "display_name": display_name,
        "status": "prospect",
        "created_at": ts,
        "updated_at": ts,
    }
    if email is not None:
        item["email"] = email
    if phone is not None:
        item["phone"] = phone
    if correlation_id is not None:
        item["correlation_id"] = correlation_id
    # active_unit_id intentionally absent at creation (TEN-002 wires it)

    try:
        T.property_tenants.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK)",
        )
    except T.property_tenants.meta.client.exceptions.ConditionalCheckFailedException:
        # Idempotent replay — return existing row, no second audit event
        existing = T.property_tenants.get_item(
            Key={"PK": f"TENANT#{tenant_id}", "SK": "META"}
        ).get("Item", item)
        return existing

    _audit("tenant_created", owner_id, tenant_id=tenant_id, party_id=party_id)
    return item


def get_tenant(tenant_id: str) -> Optional[dict]:
    """Return the META row for a tenant, or None if absent."""
    return T.property_tenants.get_item(
        Key={"PK": f"TENANT#{tenant_id}", "SK": "META"}
    ).get("Item")


def list_tenants(
    owner_id: str,
    *,
    status: Optional[str] = None,
    q: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List tenants newest-first for a landlord, with optional status and q filters."""
    _require_enabled()

    from app.core.cursor import decode_cursor, encode_cursor

    lek = decode_cursor(cursor)

    kwargs: dict = {
        "IndexName": "GSI_OWNER",
        "KeyConditionExpression": Key("owner_id").eq(owner_id),
        "ScanIndexForward": False,
        "Limit": min(limit, 50),
    }
    if lek:
        kwargs["ExclusiveStartKey"] = lek

    resp = T.property_tenants.query(**kwargs)
    items = resp.get("Items", [])
    next_lek = resp.get("LastEvaluatedKey")

    # In-memory filters
    if status:
        items = [i for i in items if i.get("status") == status]
    if q:
        q_lower = q.strip().lower()
        if q_lower:
            items = [
                i
                for i in items
                if q_lower
                in (i.get("display_name", "") + " " + i.get("email", "")).lower()
            ]

    return {
        "tenants": items,
        "next_cursor": encode_cursor(next_lek),
        "count": len(items),
    }


def update_tenant(tenant_id: str, caller_sub: str = "system", **patch: Any) -> dict:
    """Update display_name / email / phone / status on the META row."""
    _require_enabled()

    # Validate patch keys
    unknown = set(patch.keys()) - VALID_PATCH_KEYS
    if unknown:
        raise ValueError(f"Unknown patch field(s): {', '.join(sorted(unknown))}")
    if not patch:
        raise ValueError("Nothing to update")

    if "status" in patch and patch["status"] not in VALID_STATUSES:
        raise HTTPException(
            400, f"Invalid status: {patch['status']!r}. Must be one of {VALID_STATUSES}"
        )

    if "email" in patch:
        patch["email"] = _normalize_email_opt(patch["email"])
    if "phone" in patch:
        patch["phone"] = _normalize_phone_opt(patch["phone"])

    # Build UpdateExpression
    set_parts = []
    expr_names: dict = {}
    expr_vals: dict = {":updated_at": now_ts()}
    set_parts.append("updated_at = :updated_at")

    for k, v in patch.items():
        safe_k = f"#{k}"
        expr_names[safe_k] = k
        val_k = f":{k}"
        expr_vals[val_k] = v
        set_parts.append(f"{safe_k} = {val_k}")

    update_expr = "SET " + ", ".join(set_parts)

    try:
        resp = T.property_tenants.update_item(
            Key={"PK": f"TENANT#{tenant_id}", "SK": "META"},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_vals,
            ConditionExpression="attribute_exists(PK)",
            ReturnValues="ALL_NEW",
        )
    except T.property_tenants.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(404, "Tenant not found")

    _audit(
        "tenant_updated",
        caller_sub,
        tenant_id=tenant_id,
        **{k: v for k, v in patch.items() if k != "email"},  # avoid leaking normalized email
    )
    return resp["Attributes"]


# ---------------------------------------------------------------------------
# TEN-002: Profile / employment / income / emergency contacts
# ---------------------------------------------------------------------------


def _normalize_profile(item: dict) -> dict:
    """Coerce Decimal → int/float for numeric fields; ensure defaults."""
    from decimal import Decimal

    def _coerce(v: Any) -> Any:
        if isinstance(v, Decimal):
            return int(v) if v == int(v) else float(v)
        if isinstance(v, dict):
            return {k2: _coerce(v2) for k2, v2 in v.items()}
        if isinstance(v, list):
            return [_coerce(e) for e in v]
        return v

    return {
        "employment": _coerce(item.get("employment", {})),
        "income": _coerce(item.get("income", {})),
        "emergency_contacts": _coerce(item.get("emergency_contacts", [])),
        "updated_at": _coerce(item.get("updated_at")),
    }


def _normalize_incomedoc(item: dict) -> dict:
    from decimal import Decimal

    def _cv(v: Any) -> Any:
        if isinstance(v, Decimal):
            return int(v) if v == int(v) else float(v)
        return v

    return {
        "doc_id": item.get("doc_id", ""),
        "tenant_id": item.get("tenant_id", ""),
        "file_node_path": item.get("file_node_path", ""),
        "file_name": item.get("file_name", ""),
        "content_type": item.get("content_type", "application/octet-stream"),
        "size_bytes": _cv(item.get("size_bytes", 0)),
        "doc_kind": item.get("doc_kind", "other"),
        "uploaded_at": _cv(item.get("uploaded_at", 0)),
        "uploaded_by": item.get("uploaded_by", ""),
    }


def _owner_for(tenant_id: str) -> str:
    t = get_tenant(tenant_id)
    return t.get("owner_id", "unknown") if t else "unknown"


def _require_owned(tenant_id: str, owner_sub: str) -> dict:
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(404, "Tenant not found")
    if tenant["owner_id"] != owner_sub:
        raise HTTPException(403, "Not your tenant")
    return tenant


def _validate_emergency_contacts(contacts: list) -> list:
    if len(contacts) > _MAX_EMERGENCY_CONTACTS:
        raise HTTPException(
            400, f"emergency_contacts may not exceed {_MAX_EMERGENCY_CONTACTS} entries"
        )
    result = []
    for ec in contacts:
        if not ec.get("name"):
            raise HTTPException(422, "emergency contact requires a name")
        ec = dict(ec)
        if "ec_id" not in ec or not ec["ec_id"]:
            ec["ec_id"] = uuid4().hex
        if ec.get("phone"):
            ec["phone"] = _normalize_phone_opt(ec["phone"])
        if ec.get("email"):
            ec["email"] = _normalize_email_opt(ec["email"])
        result.append(ec)
    return result


VALID_EMPLOYMENT_TYPES = {
    "full_time",
    "part_time",
    "self_employed",
    "contract",
    "unemployed",
    "retired",
    "student",
}
VALID_DOC_KINDS = {"pay_stub", "tax_return", "bank_statement", "offer_letter", "other"}
VALID_VERIFICATION_STATUSES = {"unverified", "pending", "verified", "rejected"}


def get_profile(tenant_id: str) -> dict:
    """Return the PROFILE row for a tenant (empty dict if not yet created)."""
    _require_enabled()
    item = T.property_tenants.get_item(
        Key={"PK": f"TENANT#{tenant_id}", "SK": "PROFILE"}
    ).get("Item") or {}
    return _normalize_profile(item)


def update_profile(
    tenant_id: str,
    *,
    employment: Optional[dict] = None,
    income: Optional[dict] = None,
    emergency_contacts: Optional[list] = None,
) -> dict:
    """Read-merge-write the PROFILE row. Passing None leaves a sub-object unchanged."""
    _require_enabled()
    existing = get_profile(tenant_id)

    # Merge employment (None → keep existing; dict → shallow merge)
    merged_employment = {**existing.get("employment", {}), **(employment or {})}

    # Validate employment_type if present
    emp_type = merged_employment.get("employment_type")
    if emp_type is not None and emp_type not in VALID_EMPLOYMENT_TYPES:
        raise HTTPException(400, f"Invalid employment_type: {emp_type!r}")

    # Normalize employer_phone if present
    if merged_employment.get("employer_phone"):
        merged_employment["employer_phone"] = _normalize_phone_opt(
            merged_employment["employer_phone"]
        )

    # Income: None → keep existing; dict → FULL REPLACEMENT (not merge)
    # This allows set_income_verification to remove keys (e.g. verified_at)
    # by passing the complete desired income dict.
    if income is None:
        merged_income = existing.get("income", {})
    else:
        merged_income = dict(income)

    # Emergency contacts: replace wholesale when supplied, else keep existing
    if emergency_contacts is not None:
        merged_ec = _validate_emergency_contacts(emergency_contacts)
    else:
        merged_ec = existing.get("emergency_contacts", [])

    item = {
        "PK": f"TENANT#{tenant_id}",
        "SK": "PROFILE",
        "employment": merged_employment,
        "income": merged_income,
        "emergency_contacts": merged_ec,
        "updated_at": now_ts(),
    }
    T.property_tenants.put_item(Item=item)
    _audit("tenant_profile_updated", _owner_for(tenant_id), tenant_id=tenant_id)
    return _normalize_profile(item)


def add_income_doc(
    tenant_id: str,
    owner_sub: str,
    file: Any,
    *,
    doc_kind: str = "other",
) -> dict:
    """Upload an income-verification document via the file manager and record the link."""
    _require_enabled()
    if doc_kind not in VALID_DOC_KINDS:
        raise HTTPException(422, f"Invalid doc_kind: {doc_kind!r}")

    from app.services import filemanager  # lazy — avoids circular at import time

    doc_id = uuid4().hex
    file_path = f"Tenant Documents/{tenant_id}/{doc_id}/{file.filename}"
    node = filemanager.upload_file(owner_sub, file_path, file)

    item: dict = {
        "PK": f"TENANT#{tenant_id}",
        "SK": f"INCOMEDOC#{doc_id}",
        "doc_id": doc_id,
        "tenant_id": tenant_id,
        "file_node_path": node["path"],
        "file_name": file.filename or "",
        "content_type": getattr(file, "content_type", None) or "application/octet-stream",
        "size_bytes": int(node.get("size", 0)),
        "doc_kind": doc_kind,
        "uploaded_at": now_ts(),
        "uploaded_by": owner_sub,
    }
    T.property_tenants.put_item(Item=item)
    _audit(
        "tenant_income_doc_added",
        owner_sub,
        tenant_id=tenant_id,
        doc_id=doc_id,
        doc_kind=doc_kind,
    )
    return item


def list_income_docs(
    tenant_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """List INCOMEDOC rows for a tenant, newest-first."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    lek = decode_cursor(cursor)
    kwargs: dict = {
        "KeyConditionExpression": Key("PK").eq(f"TENANT#{tenant_id}")
        & Key("SK").begins_with("INCOMEDOC#"),
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }
    if lek:
        kwargs["ExclusiveStartKey"] = lek
    resp = T.property_tenants.query(**kwargs)
    return {
        "docs": [_normalize_incomedoc(i) for i in resp.get("Items", [])],
        "next_cursor": encode_cursor(resp.get("LastEvaluatedKey")),
        "count": len(resp.get("Items", [])),
    }


def remove_income_doc(tenant_id: str, owner_sub: str, doc_id: str) -> bool:
    """Delete an INCOMEDOC row. Returns False if doc didn't exist. Never raises."""
    _require_enabled()
    item = T.property_tenants.get_item(
        Key={"PK": f"TENANT#{tenant_id}", "SK": f"INCOMEDOC#{doc_id}"}
    ).get("Item")
    if not item:
        return False
    T.property_tenants.delete_item(
        Key={"PK": f"TENANT#{tenant_id}", "SK": f"INCOMEDOC#{doc_id}"}
    )
    # Best-effort file cleanup — failure must NOT affect the row deletion result
    try:
        from app.services import filemanager

        filemanager.delete_node(owner_sub, item["file_node_path"])
    except Exception:
        pass
    _audit("tenant_income_doc_removed", owner_sub, tenant_id=tenant_id, doc_id=doc_id)
    return True


def set_income_verification(
    tenant_id: str,
    status: str,
    verifier_sub: str,
) -> dict:
    """Update income.verification_status on the PROFILE row."""
    _require_enabled()
    if status not in VALID_VERIFICATION_STATUSES:
        raise HTTPException(400, f"Invalid verification_status: {status!r}")
    profile = get_profile(tenant_id)
    income = {**profile.get("income", {}), "verification_status": status}
    if status == "verified":
        income["verified_at"] = now_ts()
        income["verified_by"] = verifier_sub
    else:
        income.pop("verified_at", None)
        income.pop("verified_by", None)
    result = update_profile(tenant_id, income=income)
    _audit(
        "tenant_income_verified",
        verifier_sub,
        tenant_id=tenant_id,
        status=status,
    )
    return result


def set_active_unit(
    tenant_id: str,
    owner_sub: str,
    property_id: Optional[str],
    unit_id: Optional[str],
) -> dict:
    """Link a tenant to a property unit (or clear the link)."""
    _require_enabled()
    if unit_id is not None:
        if not property_id:
            raise HTTPException(422, "property_id is required when unit_id is set")
        try:
            from app.services.property_mgmt import get_unit  # type: ignore[import]
        except ImportError:
            raise HTTPException(503, "Unit validation unavailable")
        unit = get_unit(property_id, unit_id)
        if not unit:
            raise HTTPException(404, f"Unit {unit_id!r} not found")
        if unit.get("owner_sub") not in (None, owner_sub):
            raise HTTPException(404, f"Unit {unit_id!r} not found")
        new_status = "active"
    else:
        new_status = "past"

    T.property_tenants.update_item(
        Key={"PK": f"TENANT#{tenant_id}", "SK": "META"},
        UpdateExpression="SET active_unit_id = :u, #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":u": unit_id,
            ":s": new_status,
            ":t": now_ts(),
        },
    )
    _audit(
        "tenant_active_unit_set",
        owner_sub,
        tenant_id=tenant_id,
        unit_id=unit_id,
        new_status=new_status,
    )
    return get_tenant(tenant_id) or {}


# ---------------------------------------------------------------------------
# TEN-003: Lease-history read-projection (delegates to LSE cluster)
# ---------------------------------------------------------------------------


def list_tenant_leases(
    owner_sub: str,
    tenant_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> dict:
    """
    Return lease summaries for a tenant from the LSE cluster.
    Degrades gracefully (empty list) when LSE is absent or disabled.
    Raises HTTPException(404) only when the tenant doesn't exist or wrong owner.
    """
    _require_enabled()
    item = get_tenant(tenant_id)
    if item is None or item.get("owner_id") != owner_sub:
        raise HTTPException(404, "Tenant not found")

    _empty: dict = {"leases": [], "count": 0, "next_cursor": None}
    try:
        from app.services.leases import list_leases_for_tenant  # type: ignore[import]

        if not getattr(S, "leases_enabled", False):
            return _empty
        return list_leases_for_tenant(owner_sub, tenant_id, cursor=cursor, limit=limit)
    except Exception:
        return _empty
