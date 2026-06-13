"""OFBiz-style Party/CRM single-table service.

Owns all reads/writes to the ``party`` DynamoDB table (PTY-002). Functions are
unconditionally callable (the flag guard lives at the router layer) so they are
hermetically testable. There is NO ``S.dev_mode`` branch — the same code runs in
dev (DynamoDB Local) and prod (real DynamoDB), per SECOPS-007.

Builds incrementally:
  PTY-004 — Party CRUD (PERSON / PARTY_GROUP)
  PTY-005 — Role assignment
  PTY-006 — Relationships (+ inbound mirror via GSI3)
  PTY-007 — Unified contact mechanisms (email / phone / postal)
  PTY-008 — B2B org accounts
  PTY-010 — ensure_person_party + profile/address mech back-fill + re-sync
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)


# ── Constant validation sets (inline to avoid circular import with app.models) ──

_VALID_PARTY_TYPES = frozenset({"PERSON", "PARTY_GROUP"})

_PARTY_STATUS_TRANSITIONS: Dict[str, set] = {
    "ACTIVE": {"ACTIVE", "INACTIVE", "MERGED"},
    "INACTIVE": {"INACTIVE", "ACTIVE"},
    "MERGED": {"MERGED"},
}

_VALID_ROLE_TYPES = frozenset(
    {"CUSTOMER", "SUPPLIER", "EMPLOYEE", "ORG_ADMIN", "BILL_TO", "SHIP_TO", "CONTACT"}
)

_VALID_REL_TYPES = frozenset({"EMPLOYMENT", "GROUP_MEMBER", "CONTACT_REL", "OWNER"})

_VALID_MECH_TYPES = frozenset({"EMAIL", "PHONE", "POSTAL"})

CONTACT_MECH_PURPOSES = frozenset(
    {
        "PRIMARY_EMAIL",
        "BILLING",
        "SHIPPING",
        "PRIMARY_PHONE",
        "FAX",
        "WORK_EMAIL",
        "WORK_PHONE",
        "HOME_PHONE",
        "MOBILE_PHONE",
        "GENERAL_CORRESPONDENCE",
        "SALES_CORRESPONDENCE",
        "BILLING_CORRESPONDENCE",
        "WORK",
        "HOME",
    }
)

_VALID_ORG_ROLES = frozenset({"member", "admin", "org_admin"})


def _is_conditional_conflict(exc: ClientError) -> bool:
    return (
        str(exc.response.get("Error", {}).get("Code", ""))
        == "ConditionalCheckFailedException"
    )


def _strip_internal(item: Dict[str, Any]) -> Dict[str, Any]:
    """Drop internal GSI key attributes from a returned item."""
    return {
        k: v
        for k, v in item.items()
        if k
        not in (
            "GSI1PK",
            "GSI1SK",
            "GSI2PK",
            "GSI2SK",
            "GSI3PK",
            "GSI3SK",
        )
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-004 — Party CRUD
# ═══════════════════════════════════════════════════════════════════════════════


def create_party(
    party_type: str,
    *,
    user_sub: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    if party_type not in _VALID_PARTY_TYPES:
        raise ValueError(f"invalid_party_type: {party_type}")

    if correlation_id:
        party_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        party_id = uuid.uuid4().hex

    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": f"PARTY#{party_id}",
        "SK": "META",
        "party_id": party_id,
        "party_type": party_type,
        "status": "ACTIVE",
        "type": f"TYPE#{party_type}",
        "created_at": ts,
        "updated_at": ts,
    }
    if user_sub is not None:
        item["user_sub"] = user_sub
        item["GSI3PK"] = f"OWNER#{user_sub}"
        item["GSI3SK"] = f"PARTY#{party_id}"
    if correlation_id is not None:
        item["correlation_id"] = correlation_id

    try:
        T.party.put_item(
            Item=item, ConditionExpression="attribute_not_exists(PK)"
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            existing = get_party(party_id)
            if existing is not None:
                return existing
            raise
        raise

    audit_event(
        "party_created",
        user_sub or "system",
        None,
        party_id=party_id,
        party_type=party_type,
    )
    return _strip_internal(item)


def get_party(party_id: str) -> Optional[Dict[str, Any]]:
    resp = T.party.get_item(Key={"PK": f"PARTY#{party_id}", "SK": "META"})
    item = resp.get("Item")
    if not item:
        return None
    return _strip_internal(item)


def list_parties(
    party_type: Optional[str] = None,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    limit = max(1, min(limit, 100))

    if party_type is not None:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_CREATED",
            "KeyConditionExpression": Key("type").eq(f"TYPE#{party_type}"),
            "ScanIndexForward": False,
            "Limit": limit,
        }
        start = decode_cursor(cursor)
        if start:
            kwargs["ExclusiveStartKey"] = start
        resp = T.party.query(**kwargs)
        items = [_strip_internal(i) for i in resp.get("Items", [])]
        next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
        return {"parties": items, "next_cursor": next_cursor, "count": len(items)}

    # party_type=None: query both types, merge, sort by created_at desc.
    per = (limit + 1) // 2
    merged: List[Dict[str, Any]] = []
    for pt in ("PERSON", "PARTY_GROUP"):
        resp = T.party.query(
            IndexName="GSI_CREATED",
            KeyConditionExpression=Key("type").eq(f"TYPE#{pt}"),
            ScanIndexForward=False,
            Limit=per,
        )
        merged.extend(_strip_internal(i) for i in resp.get("Items", []))
    merged.sort(key=lambda m: int(m.get("created_at", 0)), reverse=True)
    merged = merged[:limit]
    return {"parties": merged, "next_cursor": None, "count": len(merged)}


def update_party_status(party_id: str, status: str) -> Dict[str, Any]:
    existing = get_party(party_id)
    if existing is None:
        raise KeyError(party_id)

    current_status = existing["status"]
    allowed = _PARTY_STATUS_TRANSITIONS.get(current_status, set())
    if status not in allowed:
        raise ValueError("invalid_status_transition")

    if status == current_status:
        return existing

    ts = now_ts()
    try:
        T.party.update_item(
            Key={"PK": f"PARTY#{party_id}", "SK": "META"},
            UpdateExpression="SET #s = :s, updated_at = :u",
            ConditionExpression="#s = :cur",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": status,
                ":u": ts,
                ":cur": current_status,
            },
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            raise ValueError("concurrent_status_conflict") from exc
        raise

    audit_event(
        "party_status_changed",
        existing.get("user_sub") or "system",
        None,
        party_id=party_id,
        from_status=current_status,
        to_status=status,
    )
    updated = get_party(party_id)
    return updated if updated is not None else existing


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-005 — Role assignment
# ═══════════════════════════════════════════════════════════════════════════════


def add_role(party_id: str, role_type: str) -> Dict[str, Any]:
    if role_type not in _VALID_ROLE_TYPES:
        raise ValueError(f"invalid_role_type: {role_type}")

    existing_party = get_party(party_id)
    if existing_party is None:
        raise KeyError(party_id)

    item = {
        "PK": f"PARTY#{party_id}",
        "SK": f"ROLE#{role_type}",
        "party_id": party_id,
        "role_type": role_type,
        "created_at": now_ts(),
        "GSI1PK": f"ROLE#{role_type}",
        "GSI1SK": f"PARTY#{party_id}",
    }
    try:
        T.party.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            resp = T.party.get_item(
                Key={"PK": f"PARTY#{party_id}", "SK": f"ROLE#{role_type}"}
            )
            return resp.get("Item", item)
        raise

    audit_event(
        "party_role_added",
        existing_party.get("user_sub") or "system",
        None,
        party_id=party_id,
        role_type=role_type,
    )
    return item


def remove_role(party_id: str, role_type: str) -> None:
    if role_type not in _VALID_ROLE_TYPES:
        raise ValueError(f"invalid_role_type: {role_type}")

    resp = T.party.get_item(
        Key={"PK": f"PARTY#{party_id}", "SK": f"ROLE#{role_type}"}
    )
    existing_role = resp.get("Item")

    T.party.delete_item(
        Key={"PK": f"PARTY#{party_id}", "SK": f"ROLE#{role_type}"}
    )

    if existing_role:
        audit_event(
            "party_role_removed",
            "system",
            None,
            party_id=party_id,
            role_type=role_type,
        )


def list_roles(party_id: str) -> List[Dict[str, Any]]:
    resp = T.party.query(
        KeyConditionExpression=Key("PK").eq(f"PARTY#{party_id}")
        & Key("SK").begins_with("ROLE#"),
    )
    return resp.get("Items", [])


def parties_with_role(role_type: str) -> List[Dict[str, Any]]:
    if role_type not in _VALID_ROLE_TYPES:
        raise ValueError(f"invalid_role_type: {role_type}")

    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": Key("GSI1PK").eq(f"ROLE#{role_type}"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.party.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-006 — Relationships (primary + inbound mirror)
# ═══════════════════════════════════════════════════════════════════════════════


def _validate_rel_args(
    from_party_id: str, to_party_id: str, relationship_type: str
) -> None:
    if from_party_id == to_party_id:
        raise ValueError("self_relationship_not_allowed")
    if relationship_type not in _VALID_REL_TYPES:
        raise ValueError("invalid_relationship_type")
    if len(from_party_id) > 64 or len(to_party_id) > 64:
        raise ValueError("party_id_too_long")


def create_relationship(
    from_party_id: str,
    to_party_id: str,
    relationship_type: str,
    *,
    correlation_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    _validate_rel_args(from_party_id, to_party_id, relationship_type)

    if correlation_id:
        rel_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        rel_id = uuid.uuid4().hex

    ts = now_ts()
    primary = {
        "PK": f"PARTY#{from_party_id}",
        "SK": f"REL#{relationship_type}#{to_party_id}",
        "from_party_id": from_party_id,
        "to_party_id": to_party_id,
        "relationship_type": relationship_type,
        "rel_id": rel_id,
        "created_at": ts,
    }
    if correlation_id is not None:
        primary["correlation_id"] = correlation_id
    if extra:
        for k, v in extra.items():
            if v is not None and k not in primary:
                primary[k] = v

    mirror = {
        "PK": f"PARTY#{to_party_id}",
        "SK": f"MIRROR#{relationship_type}#{from_party_id}",
        "from_party_id": from_party_id,
        "to_party_id": to_party_id,
        "relationship_type": relationship_type,
        "rel_id": rel_id,
        "created_at": ts,
        "GSI3PK": f"REL_TO#{to_party_id}",
        "GSI3SK": f"REL#{relationship_type}#{from_party_id}",
    }

    try:
        T.party.put_item(
            Item=primary,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            # Idempotent replay — ensure mirror exists, then return existing primary.
            existing = T.party.get_item(
                Key={
                    "PK": f"PARTY#{from_party_id}",
                    "SK": f"REL#{relationship_type}#{to_party_id}",
                }
            ).get("Item")
            mresp = T.party.get_item(
                Key={
                    "PK": f"PARTY#{to_party_id}",
                    "SK": f"MIRROR#{relationship_type}#{from_party_id}",
                }
            )
            if not mresp.get("Item"):
                T.party.put_item(Item=mirror)
            if existing:
                return existing
            raise
        raise

    # Primary written; write mirror (best-effort recovery if interrupted).
    T.party.put_item(Item=mirror)

    audit_event(
        "party_relationship_created",
        from_party_id,
        None,
        from_party_id=from_party_id,
        to_party_id=to_party_id,
        relationship_type=relationship_type,
        rel_id=rel_id,
    )
    return primary


def list_relationships(
    party_id: str,
    *,
    direction: str = "both",
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    limit = max(1, min(limit, 100))

    def _query(prefix: str, lim: int, cur: Optional[str]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(f"PARTY#{party_id}")
            & Key("SK").begins_with(prefix),
            "ScanIndexForward": False,
            "Limit": lim,
        }
        start = decode_cursor(cur)
        if start:
            kwargs["ExclusiveStartKey"] = start
        return T.party.query(**kwargs)

    if direction == "from":
        resp = _query("REL#", limit, cursor)
        items = [_strip_internal(i) for i in resp.get("Items", [])]
        return {
            "relationships": items,
            "next_cursor": encode_cursor(resp.get("LastEvaluatedKey")),
            "count": len(items),
        }
    if direction == "to":
        resp = _query("MIRROR#", limit, cursor)
        items = [_strip_internal(i) for i in resp.get("Items", [])]
        return {
            "relationships": items,
            "next_cursor": encode_cursor(resp.get("LastEvaluatedKey")),
            "count": len(items),
        }
    if direction == "both":
        per = (limit + 1) // 2
        merged: List[Dict[str, Any]] = []
        for prefix in ("REL#", "MIRROR#"):
            resp = _query(prefix, per, None)
            merged.extend(_strip_internal(i) for i in resp.get("Items", []))
        merged.sort(key=lambda m: int(m.get("created_at", 0)), reverse=True)
        merged = merged[:limit]
        return {"relationships": merged, "next_cursor": None, "count": len(merged)}

    raise ValueError("invalid_direction")


def delete_relationship(
    from_party_id: str,
    to_party_id: str,
    relationship_type: str,
) -> None:
    _validate_rel_args(from_party_id, to_party_id, relationship_type)

    T.party.delete_item(
        Key={
            "PK": f"PARTY#{from_party_id}",
            "SK": f"REL#{relationship_type}#{to_party_id}",
        }
    )
    T.party.delete_item(
        Key={
            "PK": f"PARTY#{to_party_id}",
            "SK": f"MIRROR#{relationship_type}#{from_party_id}",
        }
    )

    audit_event(
        "party_relationship_deleted",
        from_party_id,
        None,
        from_party_id=from_party_id,
        to_party_id=to_party_id,
        relationship_type=relationship_type,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-007 — Unified contact mechanisms
# ═══════════════════════════════════════════════════════════════════════════════


def _normalize_mech_value(mech_type: str, value: Any) -> Any:
    """Return (stored_value, gsi2_pk). EMAIL/PHONE → scalar; POSTAL → dict."""
    from app.core.normalize import normalize_email, normalize_phone

    if mech_type == "EMAIL":
        norm = normalize_email(value)
        return norm, f"EMAIL#{norm}"
    if mech_type == "PHONE":
        norm = normalize_phone(value)
        return norm, f"PHONE#{norm}"
    if mech_type == "POSTAL":
        from app.services.addresses import normalize_address_payload

        if not isinstance(value, dict):
            raise HTTPException(400, "POSTAL value must be an address dict")
        norm = normalize_address_payload(value, require_all=True)
        canon = json.dumps(norm, sort_keys=True)
        hash16 = hashlib.sha256(canon.encode()).hexdigest()[:16]
        return norm, f"POSTAL#{hash16}"
    raise HTTPException(400, f"invalid mech_type: {mech_type}")


def add_contact_mech(
    party_id: str,
    mech_type: str,
    value: Any,
    purposes: List[str],
    *,
    correlation_id: Optional[str] = None,
    verified: bool = False,
) -> Dict[str, Any]:
    if mech_type not in _VALID_MECH_TYPES:
        raise HTTPException(400, f"invalid mech_type: {mech_type}")
    if get_party(party_id) is None:
        raise HTTPException(404, "party not found")

    purposes = purposes or []
    unknown = [p for p in purposes if p not in CONTACT_MECH_PURPOSES]
    if unknown:
        raise HTTPException(400, f"Unknown purpose(s): {unknown}")
    purposes = list(dict.fromkeys(purposes))  # dedupe, preserve order

    stored_value, gsi2_pk = _normalize_mech_value(mech_type, value)

    if correlation_id:
        mech_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        mech_id = uuid.uuid4().hex

    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": f"PARTY#{party_id}",
        "SK": f"MECH#{mech_type}#{mech_id}",
        "mech_id": mech_id,
        "party_id": party_id,
        "mech_type": mech_type,
        "value": stored_value,
        "purposes": purposes,
        "verified": bool(verified),
        "created_at": ts,
        "updated_at": ts,
        "GSI2PK": gsi2_pk,
        "GSI2SK": f"PARTY#{party_id}",
    }
    if correlation_id is not None:
        item["correlation_id"] = correlation_id

    try:
        T.party.put_item(
            Item=item,
            ExpressionAttributeNames={"#pk": "PK"},
            ConditionExpression="attribute_not_exists(#pk)",
        )
    except ClientError as exc:
        if _is_conditional_conflict(exc):
            if correlation_id:
                resp = T.party.get_item(
                    Key={"PK": f"PARTY#{party_id}", "SK": f"MECH#{mech_type}#{mech_id}"}
                )
                if resp.get("Item"):
                    return resp["Item"]
            raise HTTPException(409, "contact mech already exists")
        raise

    audit_event(
        "party.contact_mech.add",
        party_id,
        None,
        mech_type=mech_type,
        mech_id=mech_id,
    )
    return item


def list_contact_mechs(
    party_id: str,
    mech_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    prefix = f"MECH#{mech_type}#" if mech_type else "MECH#"
    resp = T.party.query(
        KeyConditionExpression=Key("PK").eq(f"PARTY#{party_id}")
        & Key("SK").begins_with(prefix),
    )
    return resp.get("Items", [])


def update_contact_mech(
    party_id: str,
    mech_id: str,
    *,
    purposes: Optional[List[str]] = None,
    verified: Optional[bool] = None,
) -> Dict[str, Any]:
    if get_party(party_id) is None:
        raise HTTPException(404, "party not found")

    matched = None
    for m in list_contact_mechs(party_id, mech_type=None):
        if m.get("mech_id") == mech_id:
            matched = m
            break
    if matched is None:
        raise HTTPException(404, "mech not found")

    sk = matched["SK"]
    sets: List[str] = ["updated_at = :u"]
    values: Dict[str, Any] = {":u": now_ts()}

    if purposes is not None:
        unknown = [p for p in purposes if p not in CONTACT_MECH_PURPOSES]
        if unknown:
            raise HTTPException(400, f"Unknown purpose(s): {unknown}")
        sets.append("purposes = :p")
        values[":p"] = list(dict.fromkeys(purposes))
    if verified is not None:
        sets.append("verified = :v")
        values[":v"] = bool(verified)

    T.party.update_item(
        Key={"PK": f"PARTY#{party_id}", "SK": sk},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeValues=values,
    )

    audit_event(
        "party.contact_mech.update",
        party_id,
        None,
        mech_id=mech_id,
    )
    resp = T.party.get_item(Key={"PK": f"PARTY#{party_id}", "SK": sk})
    return resp.get("Item", matched)


def remove_contact_mech(party_id: str, mech_id: str) -> None:
    matched = None
    for m in list_contact_mechs(party_id, mech_type=None):
        if m.get("mech_id") == mech_id:
            matched = m
            break
    if matched is None:
        raise HTTPException(404, "mech not found")

    T.party.delete_item(
        Key={"PK": f"PARTY#{party_id}", "SK": matched["SK"]}
    )
    audit_event(
        "party.contact_mech.remove",
        party_id,
        None,
        mech_id=mech_id,
    )


def find_party_by_contact(mech_type: str, value: Any) -> List[Dict[str, Any]]:
    if mech_type not in _VALID_MECH_TYPES:
        raise HTTPException(400, f"invalid mech_type: {mech_type}")
    _stored, gsi2_pk = _normalize_mech_value(mech_type, value)
    resp = T.party.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(gsi2_pk),
    )
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in resp.get("Items", []):
        pid = item.get("party_id")
        if not pid or pid in seen:
            continue
        seen.add(pid)
        party = get_party(pid)
        if party is not None:
            out.append(party)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-008 — B2B org accounts
# ═══════════════════════════════════════════════════════════════════════════════


def _find_person_party_id(user_sub: str) -> Optional[str]:
    try:
        resp = T.party.query(
            IndexName="GSI3",
            KeyConditionExpression=Key("GSI3PK").eq(f"OWNER#{user_sub}"),
            FilterExpression=Attr("party_type").eq("PERSON"),
            Limit=5,
        )
    except Exception:
        return None
    for item in resp.get("Items", []):
        if item.get("SK") == "META" and item.get("party_type") == "PERSON":
            return item.get("party_id")
    return None


def _assert_org_admin(org_party_id: str, actor_party_id: str) -> None:
    resp = T.party.get_item(
        Key={
            "PK": f"PARTY#{actor_party_id}",
            "SK": f"REL#GROUP_MEMBER#{org_party_id}",
        }
    )
    item = resp.get("Item")
    if not item:
        resp2 = T.party.get_item(
            Key={
                "PK": f"PARTY#{actor_party_id}",
                "SK": f"REL#OWNER#{org_party_id}",
            }
        )
        item = resp2.get("Item")
    if not item or item.get("org_role") not in ("org_admin", "owner"):
        raise HTTPException(403, "org_admin role required")


def create_org_account(
    name: str,
    *,
    owner_user_sub: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    name = (name or "").strip()
    if not name:
        raise HTTPException(422, "name_required")
    if len(name) > 256:
        raise HTTPException(422, "name_too_long")

    if correlation_id:
        org_party_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        org_party_id = uuid.uuid4().hex

    ts = now_ts()
    meta = {
        "PK": f"PARTY#{org_party_id}",
        "SK": "META",
        "party_id": org_party_id,
        "party_type": "PARTY_GROUP",
        "status": "ACTIVE",
        "name": name,
        "type": "TYPE#PARTY_GROUP",
        "created_at": ts,
        "updated_at": ts,
    }
    if correlation_id is not None:
        meta["correlation_id"] = correlation_id

    try:
        T.party.put_item(
            Item=meta, ConditionExpression="attribute_not_exists(PK)"
        )
    except ClientError as exc:
        if not _is_conditional_conflict(exc):
            raise
        # Existing org — converge: fetch META and continue with roles/relationship.
        existing = get_party(org_party_id)
        if existing is not None:
            meta = existing

    # Resolve owner PERSON party.
    owner_person_party_id = _find_person_party_id(owner_user_sub)
    if owner_person_party_id is None:
        raise HTTPException(404, "owner_person_party_not_found")

    add_role(org_party_id, "CUSTOMER")
    add_role(org_party_id, "BILL_TO")

    create_relationship(
        owner_person_party_id,
        org_party_id,
        "OWNER",
        correlation_id=f"{org_party_id}:owner",
    )
    # Mark org_role=owner on the OWNER relationship primary row.
    T.party.update_item(
        Key={
            "PK": f"PARTY#{owner_person_party_id}",
            "SK": f"REL#OWNER#{org_party_id}",
        },
        UpdateExpression="SET org_role = :r",
        ExpressionAttributeValues={":r": "owner"},
    )

    audit_event(
        "party_org_account_created",
        owner_user_sub,
        None,
        org_party_id=org_party_id,
        name=name,
        owner_person_party_id=owner_person_party_id,
    )
    out = dict(meta)
    out["owner_user_sub"] = owner_user_sub
    return _strip_internal(out)


def add_member(
    org_party_id: str,
    actor_party_id: str,
    member_party_id: str,
    role_type: str = "member",
) -> Dict[str, Any]:
    if role_type not in _VALID_ORG_ROLES:
        raise HTTPException(422, "invalid_org_role")

    _assert_org_admin(org_party_id, actor_party_id)

    org = get_party(org_party_id)
    if org is None or org.get("party_type") != "PARTY_GROUP":
        raise HTTPException(404, "org_not_found")

    if member_party_id == org_party_id:
        raise HTTPException(422, "self_membership_not_allowed")

    existing = T.party.get_item(
        Key={
            "PK": f"PARTY#{member_party_id}",
            "SK": f"REL#GROUP_MEMBER#{org_party_id}",
        }
    ).get("Item")
    if existing:
        return existing

    create_relationship(member_party_id, org_party_id, "GROUP_MEMBER")
    T.party.update_item(
        Key={
            "PK": f"PARTY#{member_party_id}",
            "SK": f"REL#GROUP_MEMBER#{org_party_id}",
        },
        UpdateExpression="SET org_role = :r",
        ExpressionAttributeValues={":r": role_type},
    )

    audit_event(
        "party_org_member_added",
        actor_party_id,
        None,
        org_party_id=org_party_id,
        member_party_id=member_party_id,
        role_type=role_type,
    )
    resp = T.party.get_item(
        Key={
            "PK": f"PARTY#{member_party_id}",
            "SK": f"REL#GROUP_MEMBER#{org_party_id}",
        }
    )
    return resp.get("Item", {})


def remove_member(
    org_party_id: str,
    actor_party_id: str,
    member_party_id: str,
) -> None:
    _assert_org_admin(org_party_id, actor_party_id)

    owner_rel = T.party.get_item(
        Key={
            "PK": f"PARTY#{member_party_id}",
            "SK": f"REL#OWNER#{org_party_id}",
        }
    ).get("Item")
    if owner_rel:
        raise HTTPException(409, "cannot_remove_org_owner")

    delete_relationship(member_party_id, org_party_id, "GROUP_MEMBER")

    audit_event(
        "party_org_member_removed",
        actor_party_id,
        None,
        org_party_id=org_party_id,
        member_party_id=member_party_id,
    )


def list_members(
    org_party_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    limit = max(1, min(limit, 1000))

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI3",
        "KeyConditionExpression": Key("GSI3PK").eq(f"REL_TO#{org_party_id}")
        & Key("GSI3SK").begins_with("REL#GROUP_MEMBER#"),
        "Limit": limit,
    }
    start = decode_cursor(cursor)
    if start:
        kwargs["ExclusiveStartKey"] = start
    resp = T.party.query(**kwargs)
    mirror_items = resp.get("Items", [])

    members: List[Dict[str, Any]] = []
    for mirror in mirror_items:
        member_party_id = mirror.get("from_party_id")
        org_role = "member"
        if member_party_id:
            primary = T.party.get_item(
                Key={
                    "PK": f"PARTY#{member_party_id}",
                    "SK": f"REL#GROUP_MEMBER#{org_party_id}",
                }
            ).get("Item")
            if primary:
                org_role = primary.get("org_role", "member")
        entry = _strip_internal(dict(mirror))
        entry["org_role"] = org_role
        members.append(entry)

    return {
        "members": members,
        "next_cursor": encode_cursor(resp.get("LastEvaluatedKey")),
        "count": len(members),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-010 — ensure_person_party + profile/address mech back-fill + re-sync
# ═══════════════════════════════════════════════════════════════════════════════


def ensure_person_party(user_sub: str) -> str:
    from app.core.settings import S

    if not S.party_crm_enabled:
        raise HTTPException(404, "Party CRM is not enabled")

    result = create_party(
        "PERSON",
        user_sub=user_sub,
        correlation_id=f"PERSON:USER:{user_sub}",
    )
    party_id = result["party_id"]
    _backfill_mechs(party_id, user_sub)
    audit_event("party.ensure_person_party", user_sub, None, party_id=party_id)
    return party_id


def _backfill_mechs(party_id: str, user_sub: str) -> None:
    # Email + phone from profile identity.
    try:
        from app.services.profile import get_profile_identity

        ident = get_profile_identity(user_sub)
    except Exception:
        ident = {}

    if ident.get("email"):
        try:
            add_contact_mech(
                party_id,
                "EMAIL",
                ident["email"],
                purposes=["PRIMARY_EMAIL"],
                correlation_id=f"MECH:EMAIL:{user_sub}",
            )
        except Exception:
            logger.exception("party._backfill_mechs email failed user_sub=%s", user_sub)

    if ident.get("phone"):
        try:
            add_contact_mech(
                party_id,
                "PHONE",
                ident["phone"],
                purposes=["MOBILE_PHONE"],
                correlation_id=f"MECH:PHONE:{user_sub}",
            )
        except Exception:
            logger.exception("party._backfill_mechs phone failed user_sub=%s", user_sub)

    # Postal from primary mailing address(es).
    try:
        from app.services.addresses import list_addresses

        addresses = list_addresses(user_sub)
    except Exception:
        addresses = []

    for addr in addresses or []:
        if not addr.get("is_primary_mailing"):
            continue
        try:
            add_contact_mech(
                party_id,
                "POSTAL",
                addr,
                purposes=["SHIPPING", "BILLING"],
                correlation_id=f"MECH:POSTAL:{user_sub}:{addr.get('address_id')}",
            )
        except Exception:
            logger.exception(
                "party._backfill_mechs postal failed user_sub=%s", user_sub
            )


def _resync_email_mech(user_sub: str, new_email: Optional[str]) -> None:
    party_id = _find_person_party_id(user_sub)
    if party_id is None:
        return
    mech_id = hashlib.sha256(f"MECH:EMAIL:{user_sub}".encode()).hexdigest()[:32]
    try:
        remove_contact_mech(party_id, mech_id)
    except Exception:
        pass
    if new_email:
        try:
            add_contact_mech(
                party_id,
                "EMAIL",
                new_email,
                purposes=["PRIMARY_EMAIL"],
                correlation_id=f"MECH:EMAIL:{user_sub}",
            )
        except Exception:
            logger.exception("party._resync_email_mech failed user_sub=%s", user_sub)


def _resync_phone_mech(user_sub: str, new_phone: Optional[str]) -> None:
    party_id = _find_person_party_id(user_sub)
    if party_id is None:
        return
    mech_id = hashlib.sha256(f"MECH:PHONE:{user_sub}".encode()).hexdigest()[:32]
    try:
        remove_contact_mech(party_id, mech_id)
    except Exception:
        pass
    if new_phone:
        try:
            add_contact_mech(
                party_id,
                "PHONE",
                new_phone,
                purposes=["MOBILE_PHONE"],
                correlation_id=f"MECH:PHONE:{user_sub}",
            )
        except Exception:
            logger.exception("party._resync_phone_mech failed user_sub=%s", user_sub)


def _resync_postal_mech(user_sub: str, address: Dict[str, Any]) -> None:
    party_id = _find_person_party_id(user_sub)
    if party_id is None:
        return
    prefix = f"MECH:POSTAL:{user_sub}:"
    for m in list_contact_mechs(party_id, mech_type="POSTAL"):
        if str(m.get("correlation_id", "")).startswith(prefix):
            try:
                remove_contact_mech(party_id, m["mech_id"])
            except Exception:
                pass
    try:
        add_contact_mech(
            party_id,
            "POSTAL",
            address,
            purposes=["SHIPPING", "BILLING"],
            correlation_id=f"MECH:POSTAL:{user_sub}:{address.get('address_id')}",
        )
    except Exception:
        logger.exception("party._resync_postal_mech failed user_sub=%s", user_sub)
