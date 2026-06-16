"""Party/CRM HTTP boundary (PTY-011 + PTY-012).

All `/ui/party` endpoints are gated by `S.party_crm_enabled`; org-account endpoints
additionally require `S.party_crm_org_accounts_enabled`. Admin migration endpoints
(`/ui/admin/party`) require `S.party_crm_contacts_migration_enabled` + ADMIN/ROOT.
With the relevant flag(s) off every handler returns 503 before any service call.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

import app.services.party as party_svc
from app.auth.policy import AuthenticatedUser, require_admin_or_root_csrf
from app.core.settings import S
from app.models import (
    CrmContactMechIn,
    CrmContactMechListOut,
    CrmContactMechOut,
    CrmContactMechType,
    CrmContactMechUpdateIn,
    CrmCreateOrgAccountIn,
    CrmOrgMemberIn,
    CrmOrgOut,
    CrmPartyIn,
    CrmPartyOut,
    CrmPartyRoleIn,
    CrmPartyRoleOut,
    CrmPartyStatusIn,
    CrmRelationshipIn,
    CrmRelationshipListOut,
    CrmRelationshipOut,
    CrmRoleListOut,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/party", tags=["party"])
admin_party_router = APIRouter(prefix="/ui/admin/party", tags=["admin-party-crm"])


def _guard() -> None:
    if not S.party_crm_enabled:
        raise HTTPException(status_code=503, detail="party_crm_disabled")


def _guard_org() -> None:
    if not S.party_crm_enabled or not S.party_crm_org_accounts_enabled:
        raise HTTPException(503, "party_crm_org_accounts feature not enabled")


def _guard_migration() -> None:
    if not S.party_crm_enabled or not S.party_crm_contacts_migration_enabled:
        raise HTTPException(503, "party_crm_contacts_migration feature not enabled")


# ── Response helpers ─────────────────────────────────────────────────────────


def _item_to_party_out(item: Dict[str, Any]) -> CrmPartyOut:
    return CrmPartyOut(
        party_id=item["party_id"],
        party_type=item["party_type"],
        status=item["status"],
        user_sub=item.get("user_sub"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


def _item_to_role_out(item: Dict[str, Any]) -> CrmPartyRoleOut:
    return CrmPartyRoleOut(
        party_id=item["party_id"],
        role_type=item["role_type"],
        created_at=int(item.get("created_at", 0)),
    )


def _item_to_rel_out(item: Dict[str, Any]) -> CrmRelationshipOut:
    return CrmRelationshipOut(
        from_party_id=item["from_party_id"],
        to_party_id=item["to_party_id"],
        relationship_type=item["relationship_type"],
        created_at=int(item.get("created_at", 0)),
    )


def _item_to_mech_out(item: Dict[str, Any]) -> CrmContactMechOut:
    raw = item.get("value")
    postal = None
    if item["mech_type"] == "POSTAL" and isinstance(raw, dict):
        postal = dict(raw)
        # Surface a human-readable scalar (line1) for value; full dict in postal_address.
        value = str(postal.get("line1") or "")
    else:
        value = raw if isinstance(raw, str) else str(raw)
    return CrmContactMechOut(
        mech_id=item["mech_id"],
        party_id=item["party_id"],
        mech_type=item["mech_type"],
        value=value,
        postal_address=postal,
        purposes=item.get("purposes", []),
        verified=bool(item.get("verified", False)),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
    )


def _resolve_person_party(user_sub: str) -> str:
    pid = party_svc._find_person_party_id(user_sub)
    if not pid:
        raise HTTPException(404, "person_party_not_found_for_user")
    return pid


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-011 — Party CRUD
# ═══════════════════════════════════════════════════════════════════════════════


@router.post("/parties", response_model=CrmPartyOut, status_code=201)
async def create_party_endpoint(
    body: CrmPartyIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmPartyOut:
    _guard()
    user_sub = body.user_sub
    if body.party_type == "PERSON" and not user_sub:
        user_sub = ctx["user_sub"]
    try:
        item = party_svc.create_party(
            body.party_type.value,
            user_sub=user_sub,
            correlation_id=body.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _item_to_party_out(item)


@router.get("/parties", response_model=dict)
async def list_parties_endpoint(
    party_type: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _guard()
    if party_type and party_type not in ("PERSON", "PARTY_GROUP"):
        raise HTTPException(422, "party_type must be PERSON or PARTY_GROUP")
    result = party_svc.list_parties(party_type, cursor=cursor, limit=limit)
    return {
        "parties": [_item_to_party_out(p).model_dump() for p in result["parties"]],
        "cursor": result.get("next_cursor"),
    }


@router.get("/parties/lookup", response_model=CrmPartyOut)
async def lookup_party_endpoint(
    mech_type: str = Query(...),
    value: str = Query(...),
    ctx: dict = Depends(require_ui_session),
) -> CrmPartyOut:
    _guard()
    if mech_type not in CrmContactMechType._value2member_map_:
        raise HTTPException(400, "invalid mech_type")
    parties = party_svc.find_party_by_contact(mech_type, value)
    if not parties:
        raise HTTPException(404, "party not found")
    return _item_to_party_out(parties[0])


@router.get("/parties/{party_id}", response_model=CrmPartyOut)
async def get_party_endpoint(
    party_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CrmPartyOut:
    _guard()
    item = party_svc.get_party(party_id)
    if item is None:
        raise HTTPException(404, "party_not_found")
    return _item_to_party_out(item)


@router.patch("/parties/{party_id}", response_model=CrmPartyOut)
async def update_party_status_endpoint(
    party_id: str,
    body: CrmPartyStatusIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmPartyOut:
    _guard()
    try:
        item = party_svc.update_party_status(party_id, body.status.value)
    except KeyError:
        raise HTTPException(404, "party_not_found")
    except ValueError as exc:
        code = 409 if "concurrent" in str(exc) else 422
        raise HTTPException(code, str(exc)) from exc
    return _item_to_party_out(item)


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-011 — Roles
# ═══════════════════════════════════════════════════════════════════════════════


@router.get("/parties/by-role/{role_type}", response_model=CrmRoleListOut)
async def parties_with_role_endpoint(
    role_type: str,
    ctx: dict = Depends(require_ui_session),
) -> CrmRoleListOut:
    _guard()
    try:
        items = party_svc.parties_with_role(role_type)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return CrmRoleListOut(
        roles=[_item_to_role_out(r) for r in items], count=len(items)
    )


@router.post(
    "/parties/{party_id}/roles", response_model=CrmPartyRoleOut, status_code=201
)
async def add_role_endpoint(
    party_id: str,
    body: CrmPartyRoleIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmPartyRoleOut:
    _guard()
    try:
        item = party_svc.add_role(party_id, body.role_type.value)
    except KeyError:
        raise HTTPException(404, "Party not found")
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _item_to_role_out(item)


@router.get("/parties/{party_id}/roles", response_model=CrmRoleListOut)
async def list_roles_endpoint(
    party_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CrmRoleListOut:
    _guard()
    if party_svc.get_party(party_id) is None:
        raise HTTPException(404, "Party not found")
    roles = party_svc.list_roles(party_id)
    return CrmRoleListOut(
        roles=[_item_to_role_out(r) for r in roles], count=len(roles)
    )


@router.delete("/parties/{party_id}/roles/{role_type}", status_code=204)
async def remove_role_endpoint(
    party_id: str,
    role_type: str,
    ctx: dict = Depends(require_ui_session),
) -> Response:
    _guard()
    try:
        party_svc.remove_role(party_id, role_type)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return Response(status_code=204)


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-011 — Relationships
# ═══════════════════════════════════════════════════════════════════════════════


@router.post(
    "/parties/{party_id}/relationships",
    response_model=CrmRelationshipOut,
    status_code=201,
)
async def create_relationship_endpoint(
    party_id: str,
    body: CrmRelationshipIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmRelationshipOut:
    _guard()
    try:
        item = party_svc.create_relationship(
            body.from_party_id,
            body.to_party_id,
            body.relationship_type.value,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _item_to_rel_out(item)


@router.get(
    "/parties/{party_id}/relationships", response_model=CrmRelationshipListOut
)
async def list_relationships_endpoint(
    party_id: str,
    direction: str = Query("both"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> CrmRelationshipListOut:
    _guard()
    if direction not in ("from", "to", "both"):
        raise HTTPException(422, "direction must be 'from', 'to', or 'both'")
    result = party_svc.list_relationships(
        party_id, direction=direction, cursor=cursor, limit=limit
    )
    return CrmRelationshipListOut(
        relationships=[_item_to_rel_out(r) for r in result["relationships"]],
        next_cursor=result.get("next_cursor"),
        count=result.get("count", 0),
    )


@router.delete("/parties/{party_id}/relationships", status_code=204)
async def delete_relationship_endpoint(
    party_id: str,
    to_party_id: str = Query(...),
    relationship_type: str = Query(...),
    ctx: dict = Depends(require_ui_session),
) -> Response:
    _guard()
    try:
        party_svc.delete_relationship(party_id, to_party_id, relationship_type)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return Response(status_code=204)


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-011 — Contact mechanisms
# ═══════════════════════════════════════════════════════════════════════════════


@router.post(
    "/parties/{party_id}/mechs", response_model=CrmContactMechOut, status_code=201
)
async def add_contact_mech_endpoint(
    party_id: str,
    body: CrmContactMechIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmContactMechOut:
    _guard()
    if body.mech_type == CrmContactMechType.POSTAL:
        raw_value: Any = body.postal_address.model_dump() if body.postal_address else None
    else:
        raw_value = body.value
    item = party_svc.add_contact_mech(
        party_id,
        body.mech_type.value,
        raw_value,
        purposes=[p.value for p in body.purposes],
        correlation_id=body.correlation_id,
        verified=body.verified,
    )
    return _item_to_mech_out(item)


@router.get("/parties/{party_id}/mechs", response_model=CrmContactMechListOut)
async def list_contact_mechs_endpoint(
    party_id: str,
    mech_type: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> CrmContactMechListOut:
    _guard()
    if mech_type and mech_type not in CrmContactMechType._value2member_map_:
        raise HTTPException(400, "invalid mech_type")
    mechs = party_svc.list_contact_mechs(party_id, mech_type=mech_type)
    return CrmContactMechListOut(
        mechs=[_item_to_mech_out(m) for m in mechs], count=len(mechs)
    )


@router.patch(
    "/parties/{party_id}/mechs/{mech_id}", response_model=CrmContactMechOut
)
async def update_contact_mech_endpoint(
    party_id: str,
    mech_id: str,
    body: CrmContactMechUpdateIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmContactMechOut:
    _guard()
    item = party_svc.update_contact_mech(
        party_id,
        mech_id,
        purposes=[p.value for p in body.purposes] if body.purposes is not None else None,
        verified=body.verified,
    )
    return _item_to_mech_out(item)


@router.delete("/parties/{party_id}/mechs/{mech_id}", status_code=204)
async def remove_contact_mech_endpoint(
    party_id: str,
    mech_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Response:
    _guard()
    party_svc.remove_contact_mech(party_id, mech_id)
    return Response(status_code=204)


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-012 — B2B org-account endpoints
# ═══════════════════════════════════════════════════════════════════════════════


def _org_meta_to_out(meta: Dict[str, Any], *, member_count: int = 0) -> CrmOrgOut:
    org_party_id = meta.get("org_party_id") or meta.get("party_id")
    roles = party_svc.list_roles(org_party_id)
    return CrmOrgOut(
        org_party_id=org_party_id,
        name=meta.get("name", ""),
        status=meta.get("status", "ACTIVE"),
        owner_user_sub=meta.get("owner_user_sub"),
        roles=[_item_to_role_out(r) for r in roles],
        member_count=member_count,
        created_at=int(meta.get("created_at", 0)),
        updated_at=int(meta.get("updated_at", 0)),
    )


@router.post("/orgs", response_model=CrmOrgOut, status_code=201)
async def create_org_endpoint(
    body: CrmCreateOrgAccountIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmOrgOut:
    _guard_org()
    meta = party_svc.create_org_account(
        body.name,
        owner_user_sub=ctx["user_sub"],
        correlation_id=body.correlation_id,
    )
    return _org_meta_to_out(meta)


@router.get("/orgs", response_model=dict)
async def list_orgs_endpoint(
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _guard_org()
    person_party_id = party_svc._find_person_party_id(ctx["user_sub"])
    if not person_party_id:
        return {"orgs": [], "next_cursor": None}

    from boto3.dynamodb.conditions import Key

    from app.core.tables import T

    orgs: List[Dict[str, Any]] = []
    seen = set()
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(f"PARTY#{person_party_id}"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.party.query(**kwargs)
        for item in resp.get("Items", []):
            sk = item.get("SK", "")
            if sk.startswith("REL#OWNER#") or sk.startswith("REL#GROUP_MEMBER#"):
                org_id = item.get("to_party_id")
                if org_id and org_id not in seen:
                    seen.add(org_id)
                    meta = party_svc.get_party(org_id)
                    if meta and meta.get("party_type") == "PARTY_GROUP":
                        orgs.append(_org_meta_to_out(meta).model_dump())
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return {"orgs": orgs, "next_cursor": None}


def _assert_org_relationship(person_party_id: str, org_party_id: str) -> None:
    from app.core.tables import T

    rel = (
        T.party.get_item(
            Key={
                "PK": f"PARTY#{person_party_id}",
                "SK": f"REL#OWNER#{org_party_id}",
            }
        ).get("Item")
        or T.party.get_item(
            Key={
                "PK": f"PARTY#{person_party_id}",
                "SK": f"REL#GROUP_MEMBER#{org_party_id}",
            }
        ).get("Item")
    )
    if not rel:
        raise HTTPException(404, "org_not_found")


@router.get("/orgs/{org_party_id}", response_model=CrmOrgOut)
async def get_org_endpoint(
    org_party_id: str,
    ctx: dict = Depends(require_ui_session),
) -> CrmOrgOut:
    _guard_org()
    meta = party_svc.get_party(org_party_id)
    if meta is None or meta.get("party_type") != "PARTY_GROUP":
        raise HTTPException(404, "org_not_found")
    person_party_id = _resolve_person_party(ctx["user_sub"])
    _assert_org_relationship(person_party_id, org_party_id)
    members = party_svc.list_members(org_party_id, limit=1000)
    return _org_meta_to_out(meta, member_count=members.get("count", 0))


@router.post(
    "/orgs/{org_party_id}/members",
    response_model=CrmRelationshipOut,
    status_code=201,
)
async def add_org_member_endpoint(
    org_party_id: str,
    body: CrmOrgMemberIn,
    ctx: dict = Depends(require_ui_session),
) -> CrmRelationshipOut:
    _guard_org()
    actor_party_id = _resolve_person_party(ctx["user_sub"])
    item = party_svc.add_member(
        org_party_id,
        actor_party_id,
        body.member_party_id,
        role_type=body.role_type,
    )
    return _item_to_rel_out(item)


@router.delete(
    "/orgs/{org_party_id}/members/{member_party_id}", status_code=204
)
async def remove_org_member_endpoint(
    org_party_id: str,
    member_party_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Response:
    _guard_org()
    actor_party_id = _resolve_person_party(ctx["user_sub"])
    party_svc.remove_member(org_party_id, actor_party_id, member_party_id)
    return Response(status_code=204)


@router.get("/orgs/{org_party_id}/members", response_model=dict)
async def list_org_members_endpoint(
    org_party_id: str,
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _guard_org()
    person_party_id = _resolve_person_party(ctx["user_sub"])
    _assert_org_relationship(person_party_id, org_party_id)
    result = party_svc.list_members(org_party_id, cursor=cursor)
    return {
        "members": result["members"],
        "next_cursor": result.get("next_cursor"),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PTY-012 — Admin migration endpoints
# ═══════════════════════════════════════════════════════════════════════════════


class CrmMigrateContactsIn(BaseModel):
    owner_id: Optional[str] = None


class CrmMigrateContactsOut(BaseModel):
    scanned: int
    projected: int
    errors: int


class CrmEnsurePersonOut(BaseModel):
    party_id: str
    created: bool
    mechs_synced: int = 0


@admin_party_router.post("/migrate-contacts", response_model=CrmMigrateContactsOut)
async def migrate_contacts_endpoint(
    body: CrmMigrateContactsIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> CrmMigrateContactsOut:
    _guard_migration()
    from app.services.party_contacts_migration import run_contacts_backfill

    stats = await asyncio.to_thread(run_contacts_backfill, owner_id=body.owner_id)
    audit_event(
        "party_crm.migrate_contacts",
        actor.sub,
        None,
        owner_id=body.owner_id,
        **stats,
    )
    return CrmMigrateContactsOut(**stats)


@admin_party_router.post(
    "/ensure-person/{user_sub}", response_model=CrmEnsurePersonOut
)
async def ensure_person_endpoint(
    user_sub: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> CrmEnsurePersonOut:
    _guard_migration()
    existed = party_svc._find_person_party_id(user_sub) is not None
    party_id = await asyncio.to_thread(party_svc.ensure_person_party, user_sub)
    audit_event(
        "party_crm.ensure_person",
        actor.sub,
        None,
        target_user_sub=user_sub,
        party_id=party_id,
        created=not existed,
    )
    return CrmEnsurePersonOut(party_id=party_id, created=not existed, mechs_synced=0)
