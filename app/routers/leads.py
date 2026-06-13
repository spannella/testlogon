"""CRM Leads router — LED-013.

Registers all Leads-module endpoints under /ui/leads and /ui/admin/leads.
All endpoints guard on S.leads_enabled first.

Route declaration order (FastAPI first-match wins):
  /sources/summary        — static prefix, must precede /{lead_id}
  /prospects/*            — static prefix, must precede /{lead_id}
  /admin/*                — admin endpoints (require ADMIN or ROOT role)
  /{lead_id}/...          — dynamic; converted, activities, score-history last
  /{lead_id}              — catch-all GET/PATCH/DELETE for a lead
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from app.auth.roles import Role
from app.core.settings import S
from app.models import (
    LeadActivityOut,
    LeadConversionIn,
    LeadConversionOut,
    LeadCreateIn,
    LeadOut,
    LeadScoreHistoryOut,
    LeadScoreRulesIn,
    LeadScoreRulesOut,
    LeadUpdateIn,
    ProspectCreateIn,
    ProspectOut,
    ProspectUpdateIn,
    OpportunityStubOut,
)
from app.services.sessions import require_ui_session
import app.services.leads as leads_svc

router = APIRouter(prefix="/ui/leads", tags=["leads"])


def _require_leads_enabled() -> None:
    if not S.leads_enabled:
        raise HTTPException(404, "Leads module not enabled")


def _item_to_lead_out(item: dict) -> LeadOut:
    return LeadOut(
        lead_id=item.get("lead_id", ""),
        first_name=item.get("first_name", ""),
        last_name=item.get("last_name", ""),
        email=item.get("email", ""),
        phone=item.get("phone"),
        company=item.get("company"),
        title=item.get("title"),
        lead_source=item.get("lead_source", "other"),
        description=item.get("description"),
        status=item.get("status", "new"),
        assigned_to=item.get("assigned_to"),
        score=int(item.get("score", 0)),
        website=item.get("website"),
        attribution_code=item.get("attribution_code"),
        campaign_id=item.get("campaign_id"),
        created_by=item.get("created_by", ""),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        converted_at=item.get("converted_at"),
        converted_party_id=item.get("converted_party_id"),
        converted_org_id=item.get("converted_org_id"),
        origin_questionnaire_id=item.get("origin_questionnaire_id"),
        origin_response_session_id=item.get("origin_response_session_id"),
        linked_entity_id=item.get("linked_entity_id"),
    )


def _item_to_prospect_out(item: dict) -> ProspectOut:
    return ProspectOut(
        prospect_id=item.get("prospect_id", ""),
        email=item.get("email", ""),
        first_name=item.get("first_name"),
        last_name=item.get("last_name"),
        phone=item.get("phone"),
        company=item.get("company"),
        suppressed=bool(item.get("suppressed", False)),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# LED-004: source summary (static route BEFORE /{lead_id})
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/sources/summary")
def lead_sources_summary(ctx: dict = Depends(require_ui_session)) -> dict:
    _require_leads_enabled()
    if ctx.get("role") not in (Role.ADMIN, Role.ROOT):
        raise HTTPException(403, "Admin access required")
    counts = leads_svc.get_lead_source_counts()
    return {"sources": counts}


# ─────────────────────────────────────────────────────────────────────────────
# LED-007: Prospects (static /prospects/* prefix BEFORE /{lead_id})
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/prospects", response_model=ProspectOut, status_code=201)
async def create_prospect(
    body: ProspectCreateIn,
    ctx: dict = Depends(require_ui_session),
) -> ProspectOut:
    _require_leads_enabled()
    owner_sub = ctx["user_sub"]
    item = await asyncio.to_thread(leads_svc.create_prospect, owner_sub, body)
    return _item_to_prospect_out(item)


@router.get("/prospects", response_model=dict)
async def list_prospects(
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    include_suppressed: bool = Query(default=True),
    include_deleted: bool = Query(default=False),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_leads_enabled()
    owner_sub = ctx["user_sub"]
    result = await asyncio.to_thread(
        leads_svc.list_prospects, owner_sub,
        cursor=cursor, limit=limit,
        include_suppressed=include_suppressed,
        include_deleted=include_deleted,
    )
    result["prospects"] = [_item_to_prospect_out(p).model_dump() for p in result["prospects"]]
    return result


@router.get("/prospects/{prospect_id}", response_model=ProspectOut)
async def get_prospect(
    prospect_id: str,
    ctx: dict = Depends(require_ui_session),
) -> ProspectOut:
    _require_leads_enabled()
    item = await asyncio.to_thread(leads_svc.get_prospect, prospect_id)
    if not item:
        raise HTTPException(404, "Prospect not found")
    return _item_to_prospect_out(item)


@router.patch("/prospects/{prospect_id}", response_model=ProspectOut)
async def update_prospect(
    prospect_id: str,
    body: ProspectUpdateIn,
    ctx: dict = Depends(require_ui_session),
) -> ProspectOut:
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    item = await asyncio.to_thread(leads_svc.update_prospect, prospect_id, actor_sub, body)
    return _item_to_prospect_out(item)


@router.delete("/prospects/{prospect_id}")
async def delete_prospect(
    prospect_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Response:
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    await asyncio.to_thread(leads_svc.delete_prospect, prospect_id, actor_sub)
    return Response(status_code=204)


# ─────────────────────────────────────────────────────────────────────────────
# LED-013: Admin-only routes (under /admin/ prefix, BEFORE /{lead_id})
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/admin/all", response_model=dict)
async def admin_list_all_leads(
    status: Optional[str] = Query(default=None),
    lead_source: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    """Admin endpoint: list all leads (any owner) filtered by status/source."""
    _require_leads_enabled()
    if ctx.get("role") not in (Role.ADMIN, Role.ROOT):
        raise HTTPException(403, "Admin access required")
    # For admin, use status or source GSI without owner filter
    result = await asyncio.to_thread(
        leads_svc.list_leads,
        owner_sub="__admin__",
        status=status,
        lead_source=lead_source,
        cursor=cursor,
        limit=limit,
    )
    result["leads"] = [_item_to_lead_out(l).model_dump() for l in result["leads"]]
    return result


@router.post("/admin/scoring-rules", response_model=LeadScoreRulesOut)
async def update_scoring_rules(
    body: LeadScoreRulesIn,
    ctx: dict = Depends(require_ui_session),
) -> LeadScoreRulesOut:
    """LED-013 / LED-011: Admin sets scoring rules."""
    _require_leads_enabled()
    if ctx.get("role") not in (Role.ADMIN, Role.ROOT):
        raise HTTPException(403, "Admin access required")
    actor_sub = ctx["user_sub"]
    item = await asyncio.to_thread(leads_svc.update_scoring_rules, actor_sub, body)
    return LeadScoreRulesOut(
        rules=item.get("rules", []),
        max_score=item.get("max_score", 100),
        updated_at=int(item.get("updated_at", 0)),
    )


@router.get("/admin/scoring-rules", response_model=LeadScoreRulesOut)
async def get_scoring_rules(
    ctx: dict = Depends(require_ui_session),
) -> LeadScoreRulesOut:
    _require_leads_enabled()
    if ctx.get("role") not in (Role.ADMIN, Role.ROOT):
        raise HTTPException(403, "Admin access required")
    item = await asyncio.to_thread(leads_svc.get_scoring_rules)
    return LeadScoreRulesOut(
        rules=item.get("rules", []),
        max_score=item.get("max_score", 100),
        updated_at=int(item.get("updated_at", 0)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# LED-003 / LED-013: Core lead CRUD (dynamic /{lead_id} last)
# Sub-paths of /{lead_id} BEFORE /{lead_id} itself
# ─────────────────────────────────────────────────────────────────────────────

@router.post("", response_model=LeadOut, status_code=201)
async def create_lead(
    body: LeadCreateIn,
    ctx: dict = Depends(require_ui_session),
) -> LeadOut:
    _require_leads_enabled()
    creator_sub = ctx["user_sub"]
    item = await asyncio.to_thread(leads_svc.create_lead, creator_sub, body)
    return _item_to_lead_out(item)


@router.get("", response_model=dict)
async def list_leads(
    status: Optional[str] = Query(default=None),
    lead_source: Optional[str] = Query(default=None),
    assigned_to: Optional[str] = Query(default=None),
    created_after: Optional[int] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_leads_enabled()
    owner_sub = ctx["user_sub"]
    result = await asyncio.to_thread(
        leads_svc.list_leads,
        owner_sub=owner_sub,
        status=status,
        lead_source=lead_source,
        assigned_to=assigned_to,
        created_after=created_after,
        cursor=cursor,
        limit=limit,
    )
    result["leads"] = [_item_to_lead_out(l).model_dump() for l in result["leads"]]
    return result


@router.get("/{lead_id}/score-history", response_model=LeadScoreHistoryOut)
async def get_score_history(
    lead_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    ctx: dict = Depends(require_ui_session),
) -> LeadScoreHistoryOut:
    """LED-011 / LED-013: Score history — per-resource ownership check (per-resource: user must own lead)."""
    _require_leads_enabled()
    owner_sub = ctx["user_sub"]
    # Per-resource ownership: user can see score history for leads they created
    # (or admin can see all)
    lead = await asyncio.to_thread(leads_svc.get_lead, lead_id)
    if not lead:
        raise HTTPException(404, "Lead not found")
    if ctx.get("role") not in (Role.ADMIN, Role.ROOT):
        if lead.get("created_by") != owner_sub:
            raise HTTPException(403, "Access denied")
    result = await asyncio.to_thread(
        leads_svc.get_score_history, lead_id, cursor=cursor, limit=int(limit)
    )
    from app.models import LeadScoreHistoryEntry
    return LeadScoreHistoryOut(
        lead_id=lead_id,
        entries=[LeadScoreHistoryEntry(**e) for e in result["entries"]],
        cursor=result.get("cursor"),
    )


@router.post("/{lead_id}/score", response_model=dict)
async def compute_score(
    lead_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    """LED-011: Trigger score computation for a lead."""
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    return await asyncio.to_thread(
        leads_svc.compute_lead_score, lead_id, actor_sub, "manual"
    )


@router.post("/{lead_id}/convert", response_model=LeadConversionOut)
async def convert_lead(
    lead_id: str,
    body: LeadConversionIn,
    ctx: dict = Depends(require_ui_session),
) -> LeadConversionOut:
    """LED-006: Convert a lead to Party + Opportunity stub."""
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    return await asyncio.to_thread(leads_svc.convert_lead, lead_id, actor_sub, body)


@router.post("/{lead_id}/assign", response_model=LeadOut)
async def assign_lead(
    lead_id: str,
    body: dict,
    ctx: dict = Depends(require_ui_session),
) -> LeadOut:
    """LED-010: Assign a lead to a user."""
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    assignee_sub = body.get("assignee_sub", "")
    if not assignee_sub:
        raise HTTPException(400, "assignee_sub required")
    item = await asyncio.to_thread(leads_svc.assign_lead, lead_id, assignee_sub, actor_sub)
    return _item_to_lead_out(item)


@router.post("/{lead_id}/activities", response_model=dict, status_code=201)
async def log_activity(
    lead_id: str,
    body: dict,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    """LED-012: Log a CRM activity on a lead."""
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    activity_type = body.get("activity_type", "note")
    subject = body.get("subject")
    description = body.get("description")
    metadata = body.get("metadata")
    item = await asyncio.to_thread(
        leads_svc.log_lead_activity,
        lead_id, actor_sub, activity_type,
        subject=subject, description=description, metadata=metadata,
    )
    return item


@router.get("/{lead_id}/activities", response_model=dict)
async def list_activities(
    lead_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    """LED-012: List CRM activity log entries for a lead."""
    _require_leads_enabled()
    return await asyncio.to_thread(
        leads_svc.list_lead_activities, lead_id, cursor=cursor, limit=limit
    )


@router.post("/{lead_id}/merge", response_model=LeadOut)
async def merge_leads(
    lead_id: str,
    body: dict,
    ctx: dict = Depends(require_ui_session),
) -> LeadOut:
    """LED-009: Merge secondary lead into this (primary) lead."""
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    secondary_lead_id = body.get("secondary_lead_id", "")
    if not secondary_lead_id:
        raise HTTPException(400, "secondary_lead_id required")
    item = await asyncio.to_thread(
        leads_svc.merge_leads, lead_id, secondary_lead_id, actor_sub
    )
    return _item_to_lead_out(item)


@router.get("/{lead_id}/duplicates", response_model=dict)
async def find_duplicates(
    lead_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    """LED-009: Find potential duplicate leads by email."""
    _require_leads_enabled()
    dupes = await asyncio.to_thread(leads_svc.find_duplicates, lead_id)
    return {"duplicates": [_item_to_lead_out(d).model_dump() for d in dupes]}


@router.get("/{lead_id}", response_model=LeadOut)
async def get_lead(
    lead_id: str,
    ctx: dict = Depends(require_ui_session),
) -> LeadOut:
    _require_leads_enabled()
    item = await asyncio.to_thread(leads_svc.get_lead, lead_id)
    if not item:
        raise HTTPException(404, "Lead not found")
    return _item_to_lead_out(item)


@router.patch("/{lead_id}", response_model=LeadOut)
async def update_lead(
    lead_id: str,
    body: LeadUpdateIn,
    ctx: dict = Depends(require_ui_session),
) -> LeadOut:
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    item = await asyncio.to_thread(leads_svc.update_lead, lead_id, actor_sub, body)
    return _item_to_lead_out(item)


@router.delete("/{lead_id}")
async def delete_lead(
    lead_id: str,
    ctx: dict = Depends(require_ui_session),
) -> Response:
    _require_leads_enabled()
    actor_sub = ctx["user_sub"]
    await asyncio.to_thread(leads_svc.delete_lead, lead_id, actor_sub)
    return Response(status_code=204)
