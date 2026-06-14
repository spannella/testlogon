"""
CCT-001..CCT-006 — SuiteCRM Contacts Extra router.

All routes are gated on party_crm_enabled or party_crm_org_accounts_enabled.
This router is an ADDITIVE extension — it never re-declares or modifies the
base party router (which lives in app/routers/party.py in the integrated tree).

Route declaration order (CRITICAL per CLAUDE.md gotchas):
  Static paths come before /{party_id} to avoid FastAPI capturing literal
  segment values as path parameters.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Query, Response, UploadFile

from app.auth.policy import require_admin_or_root
from app.auth.deps import AuthenticatedUser
from app.services.sessions import require_ui_session
from app.core.settings import S
from app.models import (
    CctHierarchyOut,
    CctMergePartyIn,
    CctOrgAccountOut,
    CctOrgAccountUpdateIn,
    CctPartyOut,
    CctReportsToOut,
    CctSetManagerIn,
    CctSetParentOrgIn,
    CctDuplicateCandidateListOut,
    CctDuplicateCandidateOut,
    CctRelationshipOut,
)

# ---------------------------------------------------------------------------
# Sub-routers
# ---------------------------------------------------------------------------

# Org-level routes (flag: party_crm_org_accounts_enabled)
org_router = APIRouter(prefix="/ui/party/orgs", tags=["party-cct-orgs"])

# Party-level routes (flag: party_crm_enabled)
party_router = APIRouter(prefix="/ui/party/parties", tags=["party-cct-parties"])

# vCard import route (static, before /{party_id})
vcard_router = APIRouter(prefix="/ui/party", tags=["party-cct-vcard"])

# Admin routes
admin_router = APIRouter(prefix="/ui/admin/party", tags=["party-cct-admin"])


def _flag_org_accounts() -> None:
    if not getattr(S, "party_crm_org_accounts_enabled", False):
        from fastapi import HTTPException
        raise HTTPException(503, "party_crm_org_accounts not enabled")


def _flag_party_crm() -> None:
    if not getattr(S, "party_crm_enabled", False):
        from fastapi import HTTPException
        raise HTTPException(503, "party_crm not enabled")


def _item_to_org_out(item: Dict[str, Any]) -> CctOrgAccountOut:
    from app.models import CctPartyStatus
    return CctOrgAccountOut(
        party_id=item.get("party_id", ""),
        name=item.get("name", ""),
        status=CctPartyStatus(item.get("status", "ACTIVE")),
        roles=[],
        member_count=int(item.get("member_count", 0)),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        industry=item.get("industry"),
        website=item.get("website"),
        phone=item.get("phone"),
        employee_count=item.get("employee_count"),
        annual_revenue_cents=item.get("annual_revenue_cents"),
        parent_org_party_id=item.get("parent_org_party_id"),
        child_org_count=int(item.get("child_org_count", 0)),
    )


def _item_to_party_out(item: Dict[str, Any]) -> CctPartyOut:
    from app.models import CctPartyStatus, CctPartyType
    return CctPartyOut(
        party_id=item.get("party_id", ""),
        party_type=CctPartyType(item.get("party_type", "PERSON")),
        status=CctPartyStatus(item.get("status", "ACTIVE")),
        name=item.get("name", ""),
        display_name=item.get("display_name"),
        owner_user_sub=item.get("owner_user_sub", ""),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        merged_into_party_id=item.get("merged_into_party_id"),
        manager_party_id=item.get("manager_party_id"),
        direct_report_count=int(item.get("direct_report_count", 0)),
    )


def _rel_dict_to_out(d: Dict[str, Any]) -> CctRelationshipOut:
    return CctRelationshipOut(
        rel_id=d.get("rel_id", ""),
        from_party_id=d.get("from_party_id", ""),
        to_party_id=d.get("to_party_id", ""),
        relationship_type=d.get("relationship_type", ""),
        created_at=int(d.get("created_at", 0)),
        meta=d.get("meta"),
    )


# ---------------------------------------------------------------------------
# CCT-001: PATCH /ui/party/orgs/{org_party_id} — update business metadata
# ---------------------------------------------------------------------------

@org_router.patch("/{org_party_id}", response_model=CctOrgAccountOut)
async def patch_org_account(
    org_party_id: str,
    body: CctOrgAccountUpdateIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> CctOrgAccountOut:
    _flag_org_accounts()
    from app.services.party_contact_extra import update_org_account
    actor_party_id = ctx["user_sub"]
    item = update_org_account(
        org_party_id,
        actor_party_id,
        name=body.name,
        industry=body.industry,
        website=body.website,
        phone=body.phone,
        employee_count=body.employee_count,
        annual_revenue_cents=body.annual_revenue_cents,
    )
    return _item_to_org_out(item)


# ---------------------------------------------------------------------------
# CCT-002: Org hierarchy
# ---------------------------------------------------------------------------

@org_router.put("/{org_party_id}/parent", response_model=CctRelationshipOut)
async def set_parent_org(
    org_party_id: str,
    body: CctSetParentOrgIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> CctRelationshipOut:
    _flag_org_accounts()
    from app.services.party_contact_extra import set_parent_org as _set_parent
    actor_party_id = ctx["user_sub"]
    edge = _set_parent(org_party_id, body.parent_org_party_id, actor_party_id=actor_party_id)
    return _rel_dict_to_out(edge)


@org_router.delete("/{org_party_id}/parent")
async def remove_parent_org(
    org_party_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, bool]:
    _flag_org_accounts()
    from app.services.party_contact_extra import remove_parent_org as _remove_parent
    actor_party_id = ctx["user_sub"]
    _remove_parent(org_party_id, actor_party_id=actor_party_id)
    return {"ok": True}


@org_router.get("/{org_party_id}/hierarchy", response_model=CctHierarchyOut)
async def get_org_hierarchy(
    org_party_id: str,
    direction: str = Query("both", regex="^(ancestors|children|both)$"),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> CctHierarchyOut:
    _flag_org_accounts()
    from app.services.party_contact_extra import get_org_hierarchy as _get_hierarchy
    result = _get_hierarchy(org_party_id, direction=direction)
    return CctHierarchyOut(
        ancestors=[_rel_dict_to_out(r) for r in result["ancestors"]],
        children=[_rel_dict_to_out(r) for r in result["children"]],
    )


# ---------------------------------------------------------------------------
# CCT-003: Manager chain  (IMPORTANT: static paths before /{party_id})
# ---------------------------------------------------------------------------

@party_router.put("/{party_id}/manager", response_model=CctRelationshipOut)
async def set_manager(
    party_id: str,
    body: CctSetManagerIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> CctRelationshipOut:
    _flag_party_crm()
    from app.services.party_contact_extra import set_manager as _set_manager
    actor_party_id = ctx["user_sub"]
    edge = _set_manager(party_id, body.manager_party_id, actor_party_id=actor_party_id)
    return _rel_dict_to_out(edge)


@party_router.delete("/{party_id}/manager")
async def remove_manager(
    party_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, bool]:
    _flag_party_crm()
    from app.services.party_contact_extra import remove_manager as _remove_manager
    actor_party_id = ctx["user_sub"]
    _remove_manager(party_id, actor_party_id=actor_party_id)
    return {"ok": True}


@party_router.get("/{party_id}/reports-to", response_model=CctReportsToOut)
async def get_reports_to(
    party_id: str,
    direction: str = Query("manager_chain", regex="^(manager_chain|reports)$"),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> CctReportsToOut:
    _flag_party_crm()
    from app.services.party_contact_extra import get_reports_to_chain
    result = get_reports_to_chain(party_id, direction=direction)
    return CctReportsToOut(
        direction=result["direction"],
        chain=[_rel_dict_to_out(r) for r in result["chain"]],
    )


# ---------------------------------------------------------------------------
# CCT-004: Duplicate detection
# ---------------------------------------------------------------------------

@party_router.get("/{party_id}/duplicates", response_model=List[CctDuplicateCandidateOut])
async def get_duplicates_for_party(
    party_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> List[CctDuplicateCandidateOut]:
    _flag_party_crm()
    from app.services.party_dedup import find_duplicates_for_party
    actor_sub = ctx["user_sub"]
    results = find_duplicates_for_party(party_id, actor_sub=actor_sub)
    return [CctDuplicateCandidateOut(**r) for r in results]


@admin_router.get("/duplicate-candidates", response_model=CctDuplicateCandidateListOut)
async def list_duplicate_candidates(
    cursor: Optional[str] = Query(None),
    admin_user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CctDuplicateCandidateListOut:
    _flag_party_crm()
    from app.services.party_dedup import list_all_duplicate_candidates
    actor_sub = admin_user.sub
    items, next_cursor = list_all_duplicate_candidates(actor_sub, cursor=cursor)
    return CctDuplicateCandidateListOut(
        items=[CctDuplicateCandidateOut(**r) for r in items],
        cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# CCT-005: Party merge  (IMPORTANT: static 'merge' before /{party_id})
# ---------------------------------------------------------------------------

@party_router.post("/merge", response_model=CctPartyOut)
async def merge_parties(
    body: CctMergePartyIn,
    admin_user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CctPartyOut:
    _flag_party_crm()
    from app.services.party_contact_extra import merge_parties as _merge
    actor_sub = admin_user.sub
    item = _merge(body.winner_party_id, body.loser_party_id, actor_sub=actor_sub)
    return _item_to_party_out(item)


# ---------------------------------------------------------------------------
# CCT-006: vCard import/export
# ---------------------------------------------------------------------------

@party_router.get("/{party_id}/vcard")
async def export_vcard(
    party_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Response:
    _flag_party_crm()
    from app.services.party_vcard import export_party_as_vcard
    actor_sub = ctx["user_sub"]
    vcf_bytes = export_party_as_vcard(party_id, actor_sub=actor_sub)

    # Build a safe filename
    from app.core.tables import T
    meta_resp = T.party.get_item(Key={"party_id": party_id, "sk": "META"})
    meta = meta_resp.get("Item") or {}
    display_name = meta.get("display_name") or meta.get("name") or party_id
    safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in display_name)

    return Response(
        content=vcf_bytes,
        media_type="text/vcard; charset=UTF-8",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.vcf"'},
    )


@vcard_router.post("/vcard-import", response_model=List[CctPartyOut])
async def import_vcard(
    file: UploadFile = File(...),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> List[CctPartyOut]:
    _flag_party_crm()
    from app.services.party_vcard import import_vcard as _import
    actor_sub = ctx["user_sub"]
    content = await file.read()
    items = _import(content, actor_sub=actor_sub)
    return [_item_to_party_out(item) for item in items]
