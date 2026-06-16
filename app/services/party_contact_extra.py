"""
CCT-001..CCT-003, CCT-005 — SuiteCRM Contacts Extra: account business
metadata, org hierarchy, manager chain, and party merge.

This module is an ADDITIVE extension over the OFBiz party model (PTY-001..012).
It stores everything in the SAME ``party`` DynamoDB table owned by
``app.services.party`` and uses that table's REAL key schema:

  * Item key:  Key={"PK": "PARTY#{party_id}", "SK": ...}
  * GSI1:      GSI1PK / GSI1SK   — role lookup (ROLE#{type} -> PARTY#{id})
  * GSI2:      GSI2PK / GSI2SK   — contact-mech value lookup (EMAIL#.. -> PARTY#{id})
  * GSI3:      GSI3PK / GSI3SK   — owner listing (OWNER#{sub})  AND
                                   reverse-relationship (REL_TO#{to} -> REL#{type}#{from})
  * GSI_CREATED: type / created_at — newest-first by party_type

Relationship rows follow party.py's convention:
  primary  PK=PARTY#{from}  SK=REL#{type}#{to}
  mirror   PK=PARTY#{to}    SK=MIRROR#{type}#{from}  (+ GSI3 reverse keys)

CCT introduces two relationship types that the base party model does not
manage (PARENT_ORG between orgs, REPORTS_TO between persons); these rows are
written here directly but in the same shape so GSI3 reverse-lookups work.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Industry picklist (CCT-001)
# ---------------------------------------------------------------------------

INDUSTRY_CHOICES = {
    "Technology", "Finance", "Healthcare", "Education", "Retail",
    "Manufacturing", "Media", "Telecommunications", "Transportation",
    "Real Estate", "Legal", "Hospitality", "Energy", "Government",
    "Non-Profit", "Construction", "Consulting", "Agriculture", "Other",
}

_WEBSITE_RE = re.compile(r"^https?://", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Key helpers (REAL party-table schema)
# ---------------------------------------------------------------------------

def _pk(party_id: str) -> str:
    return f"PARTY#{party_id}"


def _meta_key(party_id: str) -> Dict[str, str]:
    return {"PK": _pk(party_id), "SK": "META"}


def _get_meta(party_id: str) -> Optional[Dict[str, Any]]:
    resp = T.party.get_item(Key=_meta_key(party_id))
    return resp.get("Item")


def _validate_industry(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if value not in INDUSTRY_CHOICES:
        raise HTTPException(400, "unknown_industry")
    return value


def _validate_website(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not _WEBSITE_RE.match(value):
        raise HTTPException(400, "invalid_website")
    if len(value) > 2048:
        raise HTTPException(400, "website_too_long")
    return value


def _validate_phone_optional(value: Optional[str]) -> Optional[str]:
    """Normalize phone via core/normalize."""
    if value is None:
        return None
    try:
        from app.core.normalize import normalize_phone
        return normalize_phone(value)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, "invalid_phone") from exc


# ---------------------------------------------------------------------------
# Helper: assert org admin (CCT-001, CCT-002)
# ---------------------------------------------------------------------------

def _assert_org_admin(org_party_id: str, actor_party_id: str) -> None:
    """Raise 403 if actor does not hold org_admin or owner role on the org.

    Org membership lives on the actor's GROUP_MEMBER / OWNER relationship
    primary rows (PK=PARTY#{actor}, SK=REL#{type}#{org}), carrying ``org_role``.
    """
    for rel_type in ("GROUP_MEMBER", "OWNER"):
        sk = f"REL#{rel_type}#{org_party_id}"
        resp = T.party.get_item(Key={"PK": _pk(actor_party_id), "SK": sk})
        item = resp.get("Item")
        if item:
            org_role = item.get("org_role", "")
            if org_role in ("org_admin", "owner"):
                return
    raise HTTPException(403, "org_admin role required")


# ---------------------------------------------------------------------------
# CCT-001: org account business metadata
# ---------------------------------------------------------------------------

def get_org_account(org_party_id: str) -> Optional[Dict[str, Any]]:
    item = _get_meta(org_party_id)
    if not item or item.get("party_type") != "PARTY_GROUP":
        return None
    return item


def update_org_account(
    org_party_id: str,
    actor_party_id: str,
    *,
    name: Optional[str] = None,
    industry: Optional[str] = None,
    website: Optional[str] = None,
    phone: Optional[str] = None,
    employee_count: Optional[int] = None,
    annual_revenue_cents: Optional[int] = None,
) -> Dict[str, Any]:
    if not getattr(S, "party_crm_org_accounts_enabled", False):
        raise HTTPException(503, "party_crm_org_accounts not enabled")

    _assert_org_admin(org_party_id, actor_party_id)

    existing = get_org_account(org_party_id)
    if not existing:
        raise HTTPException(404, "org_not_found")

    industry = _validate_industry(industry)
    website = _validate_website(website)
    phone = _validate_phone_optional(phone)

    set_parts: List[str] = ["#updated_at = :updated_at"]
    expr_names: Dict[str, str] = {"#updated_at": "updated_at"}
    expr_vals: Dict[str, Any] = {":updated_at": now_ts()}

    def _set(attr: str, val: Any) -> None:
        placeholder = f"#{attr}"
        vholder = f":{attr}"
        set_parts.append(f"{placeholder} = {vholder}")
        expr_names[placeholder] = attr
        expr_vals[vholder] = val

    if name is not None:
        _set("name", name)
    if industry is not None:
        _set("industry", industry)
    if website is not None:
        _set("website", website)
    if phone is not None:
        _set("phone", phone)
    if employee_count is not None:
        _set("employee_count", employee_count)
    if annual_revenue_cents is not None:
        _set("annual_revenue_cents", annual_revenue_cents)

    T.party.update_item(
        Key=_meta_key(org_party_id),
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )

    try:
        from app.services.alerts import audit_event
        audit_event("party_org_account_updated", actor_party_id, org_party_id=org_party_id)
    except Exception:
        pass

    return get_org_account(org_party_id) or {}


def create_org_account(
    name: str,
    *,
    owner_user_sub: str,
    correlation_id: Optional[str] = None,
    industry: Optional[str] = None,
    website: Optional[str] = None,
    phone: Optional[str] = None,
    employee_count: Optional[int] = None,
    annual_revenue_cents: Optional[int] = None,
) -> Dict[str, Any]:
    if not getattr(S, "party_crm_org_accounts_enabled", False):
        raise HTTPException(503, "party_crm_org_accounts not enabled")

    industry = _validate_industry(industry)
    website = _validate_website(website)
    phone = _validate_phone_optional(phone)

    party_id = uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "PK": _pk(party_id),
        "SK": "META",
        "party_id": party_id,
        "party_type": "PARTY_GROUP",
        "status": "ACTIVE",
        "name": name,
        # CCT-specific owner attribution; also wire the real GSI3 owner index.
        "owner_user_sub": owner_user_sub,
        "user_sub": owner_user_sub,
        "type": "TYPE#PARTY_GROUP",
        "created_at": ts,
        "updated_at": ts,
        "GSI3PK": f"OWNER#{owner_user_sub}",
        "GSI3SK": f"PARTY#{party_id}",
    }
    if correlation_id:
        item["correlation_id"] = correlation_id
    if industry is not None:
        item["industry"] = industry
    if website is not None:
        item["website"] = website
    if phone is not None:
        item["phone"] = phone
    if employee_count is not None:
        item["employee_count"] = employee_count
    if annual_revenue_cents is not None:
        item["annual_revenue_cents"] = annual_revenue_cents

    if correlation_id:
        # Idempotency: a deterministic party_id derived from correlation_id so a
        # replay collides on the existing META row instead of creating a dup.
        import hashlib
        det_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
        item["party_id"] = det_id
        item["PK"] = _pk(det_id)
        item["GSI3SK"] = f"PARTY#{det_id}"
        try:
            T.party.put_item(
                Item=item, ConditionExpression="attribute_not_exists(PK)"
            )
        except Exception as exc:
            if "ConditionalCheckFailedException" in type(exc).__name__:
                existing = _get_meta(det_id)
                if existing:
                    return existing
            raise
        return item

    T.party.put_item(Item=item)
    return item


# ---------------------------------------------------------------------------
# CCT-002: org hierarchy (parent_org)
# ---------------------------------------------------------------------------

def _query_rel_prefix(party_id: str, prefix: str) -> List[Dict[str, Any]]:
    resp = T.party.query(
        KeyConditionExpression=Key("PK").eq(_pk(party_id))
        & Key("SK").begins_with(prefix),
    )
    return resp.get("Items", [])


def _walk_parent_chain(org_id: str, depth: int = 10) -> List[str]:
    chain: List[str] = []
    current = org_id
    for _ in range(depth):
        items = _query_rel_prefix(current, "REL#PARENT_ORG#")
        if not items:
            break
        parent_id = items[0].get("to_party_id", "")
        if not parent_id or parent_id == org_id:
            break
        chain.append(parent_id)
        current = parent_id
    return chain


def _delete_directed_edge(
    from_id: str, to_id: str, rel_type: str
) -> None:
    """Delete primary + mirror rows for a from->to directed edge."""
    T.party.delete_item(
        Key={"PK": _pk(from_id), "SK": f"REL#{rel_type}#{to_id}"}
    )
    T.party.delete_item(
        Key={"PK": _pk(to_id), "SK": f"MIRROR#{rel_type}#{from_id}"}
    )


def _put_directed_edge(
    from_id: str, to_id: str, rel_type: str, ts: int
) -> Dict[str, Any]:
    """Write primary + mirror rows for a from->to directed edge.

    Mirror carries GSI3 reverse keys so children/reports can be queried by
    REL_TO#{to_id}.
    """
    rel_id = uuid4().hex
    sk = f"REL#{rel_type}#{to_id}"
    edge_item = {
        "PK": _pk(from_id),
        "SK": sk,
        "rel_id": rel_id,
        "from_party_id": from_id,
        "to_party_id": to_id,
        "relationship_type": rel_type,
        "created_at": ts,
    }
    T.party.put_item(Item=edge_item)

    mirror_item = {
        "PK": _pk(to_id),
        "SK": f"MIRROR#{rel_type}#{from_id}",
        "rel_id": rel_id,
        "from_party_id": from_id,
        "to_party_id": to_id,
        "relationship_type": rel_type,
        "created_at": ts,
        "GSI3PK": f"REL_TO#{to_id}",
        "GSI3SK": f"REL#{rel_type}#{from_id}",
    }
    T.party.put_item(Item=mirror_item)
    return edge_item


def set_parent_org(
    child_org_id: str,
    parent_org_id: str,
    *,
    actor_party_id: str,
) -> Dict[str, Any]:
    if not getattr(S, "party_crm_org_accounts_enabled", False):
        raise HTTPException(503, "party_crm_org_accounts not enabled")

    _assert_org_admin(child_org_id, actor_party_id)

    for pid, label in [(child_org_id, "child"), (parent_org_id, "parent")]:
        item = get_org_account(pid)
        if not item:
            raise HTTPException(404, f"{label}_org_not_found")

    if child_org_id == parent_org_id:
        raise HTTPException(400, "circular_hierarchy")

    ancestors_of_parent = _walk_parent_chain(parent_org_id)
    if child_org_id in ancestors_of_parent:
        raise HTTPException(400, "circular_hierarchy")

    ts = now_ts()

    # Remove any existing PARENT_ORG edge (a child has at most one parent).
    for old_item in _query_rel_prefix(child_org_id, "REL#PARENT_ORG#"):
        old_parent_id = old_item.get("to_party_id", "")
        if old_parent_id:
            _delete_directed_edge(child_org_id, old_parent_id, "PARENT_ORG")

    return _put_directed_edge(child_org_id, parent_org_id, "PARENT_ORG", ts)


def remove_parent_org(child_org_id: str, *, actor_party_id: str) -> None:
    if not getattr(S, "party_crm_org_accounts_enabled", False):
        raise HTTPException(503, "party_crm_org_accounts not enabled")

    _assert_org_admin(child_org_id, actor_party_id)

    for old_item in _query_rel_prefix(child_org_id, "REL#PARENT_ORG#"):
        old_parent_id = old_item.get("to_party_id", "")
        if old_parent_id:
            _delete_directed_edge(child_org_id, old_parent_id, "PARENT_ORG")


def _rel_item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rel_id": item.get("rel_id", ""),
        "from_party_id": item.get("from_party_id", ""),
        "to_party_id": item.get("to_party_id", ""),
        "relationship_type": item.get("relationship_type", ""),
        "created_at": int(item.get("created_at", 0)),
        "meta": None,
    }


def _query_children(parent_id: str, rel_type: str) -> List[Dict[str, Any]]:
    """List child/report edges of ``parent_id`` via the GSI3 reverse index."""
    resp = T.party.query(
        IndexName="GSI3",
        KeyConditionExpression=Key("GSI3PK").eq(f"REL_TO#{parent_id}")
        & Key("GSI3SK").begins_with(f"REL#{rel_type}#"),
    )
    return resp.get("Items", [])


def get_org_hierarchy(org_party_id: str, *, direction: str = "both") -> Dict[str, Any]:
    ancestors: List[Dict[str, Any]] = []
    children: List[Dict[str, Any]] = []

    if direction in ("ancestors", "both"):
        current = org_party_id
        for _ in range(10):
            items = _query_rel_prefix(current, "REL#PARENT_ORG#")
            if not items:
                break
            edge = items[0]
            ancestors.append(_rel_item_to_out(edge))
            current = edge.get("to_party_id", "")
            if not current or current == org_party_id:
                break

    if direction in ("children", "both"):
        for item in _query_children(org_party_id, "PARENT_ORG"):
            children.append(_rel_item_to_out(item))

    return {"ancestors": ancestors, "children": children}


# ---------------------------------------------------------------------------
# CCT-003: manager chain (REPORTS_TO)
# ---------------------------------------------------------------------------

def _get_party_meta(party_id: str) -> Optional[Dict[str, Any]]:
    return _get_meta(party_id)


def _walk_reports_to_chain(person_party_id: str, depth: int = 10) -> List[str]:
    chain: List[str] = []
    current = person_party_id
    for _ in range(depth):
        items = _query_rel_prefix(current, "REL#REPORTS_TO#")
        if not items:
            break
        mgr_id = items[0].get("to_party_id", "")
        if not mgr_id or mgr_id == person_party_id:
            break
        chain.append(mgr_id)
        current = mgr_id
    return chain


def set_manager(
    person_party_id: str,
    manager_party_id: str,
    *,
    actor_party_id: str,
) -> Dict[str, Any]:
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    for pid, label in [(person_party_id, "person"), (manager_party_id, "manager")]:
        meta = _get_party_meta(pid)
        if not meta:
            raise HTTPException(404, f"{label}_not_found")
        if meta.get("party_type") != "PERSON":
            raise HTTPException(400, f"{label}_must_be_person")

    if person_party_id == manager_party_id:
        raise HTTPException(400, "circular_reports_to")

    chain_of_manager = _walk_reports_to_chain(manager_party_id)
    if person_party_id in chain_of_manager:
        raise HTTPException(400, "circular_reports_to")

    ts = now_ts()

    # A person reports to at most one manager — remove any existing edge.
    for old_item in _query_rel_prefix(person_party_id, "REL#REPORTS_TO#"):
        old_mgr_id = old_item.get("to_party_id", "")
        if old_mgr_id:
            _delete_directed_edge(person_party_id, old_mgr_id, "REPORTS_TO")

    return _put_directed_edge(person_party_id, manager_party_id, "REPORTS_TO", ts)


def remove_manager(person_party_id: str, *, actor_party_id: str) -> None:
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    for old_item in _query_rel_prefix(person_party_id, "REL#REPORTS_TO#"):
        old_mgr_id = old_item.get("to_party_id", "")
        if old_mgr_id:
            _delete_directed_edge(person_party_id, old_mgr_id, "REPORTS_TO")


def get_reports_to_chain(
    person_party_id: str,
    *,
    direction: str = "manager_chain",
) -> Dict[str, Any]:
    result: List[Dict[str, Any]] = []

    if direction == "manager_chain":
        current = person_party_id
        for _ in range(10):
            items = _query_rel_prefix(current, "REL#REPORTS_TO#")
            if not items:
                break
            edge = items[0]
            result.append(_rel_item_to_out(edge))
            current = edge.get("to_party_id", "")
            if not current or current == person_party_id:
                break
    elif direction == "reports":
        # Direct reports via the GSI3 reverse index on the manager.
        for item in _query_children(person_party_id, "REPORTS_TO"):
            result.append(_rel_item_to_out(item))

    return {"direction": direction, "chain": result}


# ---------------------------------------------------------------------------
# CCT-005: party merge
# ---------------------------------------------------------------------------

def _all_rows_for_party(party_id: str) -> List[Dict[str, Any]]:
    """Return every row under PK=PARTY#{party_id} (paginated)."""
    items: List[Dict[str, Any]] = []
    resp = T.party.query(KeyConditionExpression=Key("PK").eq(_pk(party_id)))
    items.extend(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        resp = T.party.query(
            KeyConditionExpression=Key("PK").eq(_pk(party_id)),
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))
    return items


def merge_parties(
    winner_party_id: str,
    loser_party_id: str,
    *,
    actor_sub: str,
) -> Dict[str, Any]:
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    if winner_party_id == loser_party_id:
        raise HTTPException(400, "cannot_merge_party_with_itself")

    winner_meta = _get_party_meta(winner_party_id)
    loser_meta = _get_party_meta(loser_party_id)
    if not winner_meta:
        raise HTTPException(404, "winner_not_found")
    if not loser_meta:
        raise HTTPException(404, "loser_not_found")

    if winner_meta.get("party_type") != loser_meta.get("party_type"):
        raise HTTPException(400, "party_type_mismatch")

    ts = now_ts()

    loser_items = _all_rows_for_party(loser_party_id)
    winner_items = _all_rows_for_party(winner_party_id)

    # Dedup keys already present on winner.
    winner_role_sks = {i["SK"] for i in winner_items if i.get("SK", "").startswith("ROLE#")}
    winner_rel_sks = {i["SK"] for i in winner_items if i.get("SK", "").startswith("REL#")}
    winner_mech_values = {
        i.get("value")
        for i in winner_items
        if i.get("SK", "").startswith("MECH#") and i.get("value") not in (None, "")
    }

    # Copy ROLE rows (preserve original SK).
    for item in loser_items:
        sk = item.get("SK", "")
        if sk.startswith("ROLE#") and sk not in winner_role_sks:
            new_item = dict(item)
            new_item["PK"] = _pk(winner_party_id)
            new_item["party_id"] = winner_party_id
            new_item["updated_at"] = ts
            if "GSI1PK" in new_item:
                new_item["GSI1SK"] = f"PARTY#{winner_party_id}"
            T.party.put_item(Item=new_item)

    # Copy REL primary rows (re-point from_party_id at the winner).
    for item in loser_items:
        sk = item.get("SK", "")
        if sk.startswith("REL#") and sk not in winner_rel_sks:
            new_item = dict(item)
            new_item["PK"] = _pk(winner_party_id)
            new_item["party_id"] = winner_party_id
            new_item["from_party_id"] = winner_party_id
            T.party.put_item(Item=new_item)

    # Copy MECH rows (dedup by normalized value; mint a fresh mech_id/SK).
    for item in loser_items:
        sk = item.get("SK", "")
        if sk.startswith("MECH#"):
            mv = item.get("value")
            if mv in (None, "") or mv in winner_mech_values:
                continue
            new_mech_id = uuid4().hex
            mech_type = item.get("mech_type", "EMAIL")
            new_item = dict(item)
            new_item["PK"] = _pk(winner_party_id)
            new_item["party_id"] = winner_party_id
            new_item["SK"] = f"MECH#{mech_type}#{new_mech_id}"
            new_item["mech_id"] = new_mech_id
            new_item["GSI2SK"] = f"PARTY#{winner_party_id}"
            T.party.put_item(Item=new_item)
            winner_mech_values.add(mv)

    # Mark loser as MERGED.
    T.party.update_item(
        Key=_meta_key(loser_party_id),
        UpdateExpression="SET #status = :status, #merged_into = :merged_into, #updated_at = :ts",
        ExpressionAttributeNames={
            "#status": "status",
            "#merged_into": "merged_into_party_id",
            "#updated_at": "updated_at",
        },
        ExpressionAttributeValues={
            ":status": "MERGED",
            ":merged_into": winner_party_id,
            ":ts": ts,
        },
    )

    try:
        from app.services.alerts import audit_event
        audit_event(
            "party.merged",
            actor_sub,
            winner_party_id=winner_party_id,
            loser_party_id=loser_party_id,
        )
    except Exception:
        pass

    return _get_party_meta(winner_party_id) or winner_meta
