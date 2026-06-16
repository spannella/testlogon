"""ATI — ATS Integration cross-link router (ATI-owned).

Thin HTTP surface over ``app/services/ats_integration.py``. All endpoints are
cookie/session auth (CSRF for non-GET) and 503 when the ATI master gate is off.
No sibling router is touched.
"""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    AtsCandidateContactLinkIn,
    AtsCandidateContactLinkOut,
    AtsIntegrationLinksOut,
    AtsJobOpportunityLinkIn,
    AtsJobOpportunityLinkOut,
)
from app.services import ats_integration as ati
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/ats/integration", tags=["ats_integration"])


def _guard() -> None:
    if not ati.ats_integration_active():
        raise HTTPException(status_code=503, detail={"code": "ats_integration_disabled"})


@router.post("/candidate-contact-links", response_model=AtsCandidateContactLinkOut)
async def create_candidate_contact_link(
    body: AtsCandidateContactLinkIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
) -> AtsCandidateContactLinkOut:
    _guard()
    row = ati.link_candidate_to_contact(
        owner_sub=ctx["user_sub"],
        candidate_id=body.candidate_id,
        contact_id=body.contact_id,
    )
    return AtsCandidateContactLinkOut(**row)


@router.post("/job-opportunity-links", response_model=AtsJobOpportunityLinkOut)
async def create_job_opportunity_link(
    body: AtsJobOpportunityLinkIn,
    ctx: Dict[str, str] = Depends(require_ui_session),
) -> AtsJobOpportunityLinkOut:
    _guard()
    row = ati.link_job_to_opportunity(
        owner_sub=ctx["user_sub"],
        job_order_id=body.job_order_id,
        opportunity_id=body.opportunity_id,
    )
    return AtsJobOpportunityLinkOut(**row)


@router.get("/links", response_model=AtsIntegrationLinksOut)
async def list_integration_links(
    ctx: Dict[str, str] = Depends(require_ui_session),
) -> AtsIntegrationLinksOut:
    _guard()
    return AtsIntegrationLinksOut(**ati.list_links(ctx["user_sub"]))


@router.delete("/links/{link_type}/{link_id}")
async def delete_integration_link(
    link_type: str,
    link_id: str,
    ctx: Dict[str, str] = Depends(require_ui_session),
) -> Dict[str, bool]:
    _guard()
    ok = ati.unlink(ctx["user_sub"], link_type, link_id)
    if not ok:
        raise HTTPException(status_code=400, detail={"code": "invalid_link_type"})
    return {"ok": True}
