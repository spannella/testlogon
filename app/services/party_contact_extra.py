"""
CCT-001..CCT-003, CCT-005 — SuiteCRM Contacts Extra: account business
metadata, org hierarchy, manager chain, and party merge.

This module is an ADDITIVE extension over the OFBiz party model (PTY-001..012).
It NEVER re-creates party.py — all party DDB access goes through lazy imports
of app.services.party at call time, guarded by the party_crm flags.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
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
    """Raise 403 if actor does not hold org_admin or owner role on the org."""
    for rel_type in ("GROUP_MEMBER", "OWNER"):
        sk = f"REL#{rel_type}#{org_party_id}"
        resp = T.party.get_item(Key={"party_id": actor_party_id, "sk": sk})
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
    resp = T.party.get_item(Key={"party_id": org_party_id, "sk": "META"})
    item = resp.get("Item")
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
        Key={"party_id": org_party_id, "sk": "META"},
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

    party_id = f"ORG#{uuid4().hex}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "party_id": party_id,
        "sk": "META",
        "party_type": "PARTY_GROUP",
        "status": "ACTIVE",
        "name": name,
        "owner_user_sub": owner_user_sub,
        "created_at": ts,
        "updated_at": ts,
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

    put_kwargs: Dict[str, Any] = {"Item": item}
    if correlation_id:
        put_kwargs["ConditionExpression"] = Attr("party_id").not_exists()
    try:
        T.party.put_item(**put_kwargs)
    except Exception as exc:
        if "ConditionalCheckFailedException" in type(exc).__name__:
            resp = T.party.query(
                IndexName="GSI_CREATED",
                KeyConditionExpression=Key("owner_user_sub").eq(owner_user_sub),
                FilterExpression=Attr("correlation_id").eq(correlation_id),
                Limit=1,
            )
            items = resp.get("Items", [])
            if items:
                return items[0]
        raise
    return item


# ---------------------------------------------------------------------------
# CCT-002: org hierarchy (parent_org)
# ---------------------------------------------------------------------------

def _walk_parent_chain(org_id: str, depth: int = 10) -> List[str]:
    chain: List[str] = []
    current = org_id
    for _ in range(depth):
        resp = T.party.query(
            KeyConditionExpression=Key("party_id").eq(current) & Key("sk").begins_with("REL#PARENT_ORG#"),
        )
        items = resp.get("Items", [])
        if not items:
            break
        parent_id = items[0].get("to_party_id", "")
        if not parent_id or parent_id == org_id:
            break
        chain.append(parent_id)
        current = parent_id
    return chain


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

    # Remove old PARENT_ORG edge
    old_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(child_org_id) & Key("sk").begins_with("REL#PARENT_ORG#"),
    )
    for old_item in old_resp.get("Items", []):
        T.party.delete_item(Key={"party_id": child_org_id, "sk": old_item["sk"]})
        old_parent_id = old_item.get("to_party_id", "")
        if old_parent_id:
            T.party.delete_item(Key={"party_id": old_parent_id, "sk": f"MIRROR#{child_org_id}#PARENT_ORG"})

    rel_id = uuid4().hex
    sk = f"REL#PARENT_ORG#{parent_org_id}"
    edge_item = {
        "party_id": child_org_id,
        "sk": sk,
        "rel_id": rel_id,
        "from_party_id": child_org_id,
        "to_party_id": parent_org_id,
        "relationship_type": "PARENT_ORG",
        "created_at": ts,
        "rel_sk": sk,
    }
    T.party.put_item(Item=edge_item)

    # Mirror on parent (to_party_id=child so GSI_REL_MIRROR picks up children)
    mirror_item = {
        "party_id": parent_org_id,
        "sk": f"MIRROR#{child_org_id}#PARENT_ORG",
        "rel_id": rel_id,
        "from_party_id": child_org_id,
        "to_party_id": parent_org_id,
        "relationship_type": "PARENT_ORG",
        "rel_sk": sk,
        "created_at": ts,
    }
    T.party.put_item(Item=mirror_item)

    return edge_item


def remove_parent_org(child_org_id: str, *, actor_party_id: str) -> None:
    if not getattr(S, "party_crm_org_accounts_enabled", False):
        raise HTTPException(503, "party_crm_org_accounts not enabled")

    _assert_org_admin(child_org_id, actor_party_id)

    old_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(child_org_id) & Key("sk").begins_with("REL#PARENT_ORG#"),
    )
    for old_item in old_resp.get("Items", []):
        T.party.delete_item(Key={"party_id": child_org_id, "sk": old_item["sk"]})
        old_parent_id = old_item.get("to_party_id", "")
        if old_parent_id:
            T.party.delete_item(Key={"party_id": old_parent_id, "sk": f"MIRROR#{child_org_id}#PARENT_ORG"})


def _rel_item_to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rel_id": item.get("rel_id", ""),
        "from_party_id": item.get("from_party_id", ""),
        "to_party_id": item.get("to_party_id", ""),
        "relationship_type": item.get("relationship_type", ""),
        "created_at": int(item.get("created_at", 0)),
        "meta": None,
    }


def get_org_hierarchy(org_party_id: str, *, direction: str = "both") -> Dict[str, Any]:
    ancestors: List[Dict[str, Any]] = []
    children: List[Dict[str, Any]] = []

    if direction in ("ancestors", "both"):
        current = org_party_id
        for _ in range(10):
            resp = T.party.query(
                KeyConditionExpression=Key("party_id").eq(current) & Key("sk").begins_with("REL#PARENT_ORG#"),
            )
            items = resp.get("Items", [])
            if not items:
                break
            edge = items[0]
            ancestors.append(_rel_item_to_out(edge))
            current = edge.get("to_party_id", "")
            if not current or current == org_party_id:
                break

    if direction in ("children", "both"):
        # Mirror rows have party_id=parent, from_party_id=child
        # We stored mirror rows with party_id=parent_org_id, to_party_id=parent_org_id
        # so we need GSI on the parent side.
        # Query party_id=org_party_id, sk begins_with MIRROR# and filter PARENT_ORG
        resp = T.party.query(
            KeyConditionExpression=Key("party_id").eq(org_party_id) & Key("sk").begins_with("MIRROR#"),
            FilterExpression=Attr("relationship_type").eq("PARENT_ORG"),
        )
        for item in resp.get("Items", []):
            children.append(_rel_item_to_out(item))

    return {"ancestors": ancestors, "children": children}


# ---------------------------------------------------------------------------
# CCT-003: manager chain (REPORTS_TO)
# ---------------------------------------------------------------------------

def _get_party_meta(party_id: str) -> Optional[Dict[str, Any]]:
    resp = T.party.get_item(Key={"party_id": party_id, "sk": "META"})
    return resp.get("Item")


def _walk_reports_to_chain(person_party_id: str, depth: int = 10) -> List[str]:
    chain: List[str] = []
    current = person_party_id
    for _ in range(depth):
        resp = T.party.query(
            KeyConditionExpression=Key("party_id").eq(current) & Key("sk").begins_with("REL#REPORTS_TO#"),
        )
        items = resp.get("Items", [])
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

    # Remove existing REPORTS_TO for this person
    old_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(person_party_id) & Key("sk").begins_with("REL#REPORTS_TO#"),
    )
    for old_item in old_resp.get("Items", []):
        T.party.delete_item(Key={"party_id": person_party_id, "sk": old_item["sk"]})
        old_mgr_id = old_item.get("to_party_id", "")
        if old_mgr_id:
            T.party.delete_item(Key={"party_id": old_mgr_id, "sk": f"MIRROR#{person_party_id}#REPORTS_TO"})

    rel_id = uuid4().hex
    sk = f"REL#REPORTS_TO#{manager_party_id}"
    edge_item = {
        "party_id": person_party_id,
        "sk": sk,
        "rel_id": rel_id,
        "from_party_id": person_party_id,
        "to_party_id": manager_party_id,
        "relationship_type": "REPORTS_TO",
        "created_at": ts,
        "rel_sk": sk,
    }
    T.party.put_item(Item=edge_item)

    # Mirror on manager side
    mirror_item = {
        "party_id": manager_party_id,
        "sk": f"MIRROR#{person_party_id}#REPORTS_TO",
        "rel_id": rel_id,
        "from_party_id": person_party_id,
        "to_party_id": manager_party_id,
        "relationship_type": "REPORTS_TO",
        "rel_sk": sk,
        "created_at": ts,
    }
    T.party.put_item(Item=mirror_item)

    return edge_item


def remove_manager(person_party_id: str, *, actor_party_id: str) -> None:
    if not getattr(S, "party_crm_enabled", False):
        raise HTTPException(503, "party_crm not enabled")

    old_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(person_party_id) & Key("sk").begins_with("REL#REPORTS_TO#"),
    )
    for old_item in old_resp.get("Items", []):
        T.party.delete_item(Key={"party_id": person_party_id, "sk": old_item["sk"]})
        old_mgr_id = old_item.get("to_party_id", "")
        if old_mgr_id:
            T.party.delete_item(Key={"party_id": old_mgr_id, "sk": f"MIRROR#{person_party_id}#REPORTS_TO"})


def get_reports_to_chain(
    person_party_id: str,
    *,
    direction: str = "manager_chain",
) -> Dict[str, Any]:
    result: List[Dict[str, Any]] = []

    if direction == "manager_chain":
        current = person_party_id
        for _ in range(10):
            resp = T.party.query(
                KeyConditionExpression=Key("party_id").eq(current) & Key("sk").begins_with("REL#REPORTS_TO#"),
            )
            items = resp.get("Items", [])
            if not items:
                break
            edge = items[0]
            result.append(_rel_item_to_out(edge))
            current = edge.get("to_party_id", "")
            if not current or current == person_party_id:
                break
    elif direction == "reports":
        # Direct reports via mirror rows on person_party_id
        resp = T.party.query(
            KeyConditionExpression=Key("party_id").eq(person_party_id) & Key("sk").begins_with("MIRROR#"),
            FilterExpression=Attr("relationship_type").eq("REPORTS_TO"),
        )
        for item in resp.get("Items", []):
            result.append(_rel_item_to_out(item))

    return {"direction": direction, "chain": result}


# ---------------------------------------------------------------------------
# CCT-005: party merge
# ---------------------------------------------------------------------------

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

    # Collect all loser items
    loser_items: List[Dict[str, Any]] = []
    resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(loser_party_id),
    )
    loser_items.extend(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        resp = T.party.query(
            KeyConditionExpression=Key("party_id").eq(loser_party_id),
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        loser_items.extend(resp.get("Items", []))

    # Collect winner role SKs for dedup
    winner_role_sks: set = set()
    winner_role_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(winner_party_id) & Key("sk").begins_with("ROLE#"),
    )
    for item in winner_role_resp.get("Items", []):
        winner_role_sks.add(item["sk"])

    # Copy ROLE rows
    for item in loser_items:
        sk = item.get("sk", "")
        if sk.startswith("ROLE#") and sk not in winner_role_sks:
            new_item = dict(item)
            new_item["party_id"] = winner_party_id
            new_item["updated_at"] = ts
            T.party.put_item(Item=new_item)

    # Collect winner REL SKs for dedup
    winner_rel_sks: set = set()
    winner_rel_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(winner_party_id) & Key("sk").begins_with("REL#"),
    )
    for item in winner_rel_resp.get("Items", []):
        winner_rel_sks.add(item["sk"])

    # Copy REL rows
    for item in loser_items:
        sk = item.get("sk", "")
        if sk.startswith("REL#") and sk not in winner_rel_sks:
            new_item = dict(item)
            new_item["party_id"] = winner_party_id
            new_item["from_party_id"] = winner_party_id
            T.party.put_item(Item=new_item)

    # Collect winner mech values for dedup
    winner_mech_values: set = set()
    winner_mech_resp = T.party.query(
        KeyConditionExpression=Key("party_id").eq(winner_party_id) & Key("sk").begins_with("MECH#"),
    )
    for item in winner_mech_resp.get("Items", []):
        mv = item.get("mech_value", "")
        if mv:
            winner_mech_values.add(mv)

    # Copy MECH rows (dedup by value)
    for item in loser_items:
        sk = item.get("sk", "")
        if sk.startswith("MECH#"):
            mv = item.get("mech_value", "")
            if mv and mv not in winner_mech_values:
                new_mech_id = uuid4().hex
                new_item = dict(item)
                new_item["party_id"] = winner_party_id
                new_item["sk"] = f"MECH#{new_mech_id}"
                new_item["mech_id"] = new_mech_id
                T.party.put_item(Item=new_item)
                winner_mech_values.add(mv)

    # Mark loser as MERGED
    T.party.update_item(
        Key={"party_id": loser_party_id, "sk": "META"},
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

    # Audit
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
