"""Public DMCA endpoints (MOD-002).

Allows rights holders to file claims and content creators to file
counter-notices. Also exposes the designated DMCA agent contact info.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.models import (
    DmcaClaimCreateOut,
    DmcaClaimIn,
    DmcaClaimOut,
    DmcaAgentConfigOut,
    DmcaCounterNoticeIn,
    DmcaCounterNoticeOut,
)
from app.services.dmca_claims import (
    file_counter_notice,
    file_dmca_claim,
    get_claim,
    get_dmca_agent_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/dmca", tags=["dmca"])


@router.post("/claims", response_model=DmcaClaimCreateOut, status_code=201)
async def submit_dmca_claim(
    body: DmcaClaimIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Submit a DMCA takedown claim (rights holder)."""
    result = file_dmca_claim(body.model_dump(), claimant_user_id=user.sub)
    return result


@router.get("/claims/{claim_id}", response_model=DmcaClaimOut)
async def get_dmca_claim(
    claim_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """View a DMCA claim. Only the claimant or the target user may view."""
    item = get_claim(claim_id)
    if not item:
        raise HTTPException(404, "Claim not found")

    # Access control: only claimant or target user
    claimant_user_id = item.get("claimant_user_id", "")
    target_user_id = item.get("target_user_id", "")
    if user.sub not in (claimant_user_id, target_user_id):
        raise HTTPException(403, "Not authorized to view this claim")

    return DmcaClaimOut(
        claim_id=item.get("claim_id", ""),
        status=item.get("status", ""),
        claimant_name=item.get("claimant_name", ""),
        claimant_email=item.get("claimant_email", ""),
        content_url=item.get("content_url", ""),
        content_type=item.get("content_type", ""),
        content_id=item.get("content_id", ""),
        target_user_id=item.get("target_user_id", ""),
        original_work_description=item.get("original_work_description", ""),
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
        content_removed_at=int(item["content_removed_at"]) if item.get("content_removed_at") else None,
        counter_notice_filed_at=int(item["counter_notice_filed_at"]) if item.get("counter_notice_filed_at") else None,
        waiting_period_expires_at=int(item["waiting_period_expires_at"]) if item.get("waiting_period_expires_at") else None,
        resolved_at=int(item["resolved_at"]) if item.get("resolved_at") else None,
        resolution=item.get("resolution") or None,
        strike_number=int(item.get("strike_number", 0)),
    )


@router.post("/claims/{claim_id}/counter-notice", response_model=DmcaCounterNoticeOut)
async def submit_counter_notice(
    claim_id: str,
    body: DmcaCounterNoticeIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """File a DMCA counter-notice (content creator only)."""
    try:
        result = file_counter_notice(claim_id, body.model_dump(), user_id=user.sub)
    except ValueError as exc:
        msg = str(exc)
        if "claim_not_found" in msg:
            raise HTTPException(404, "Claim not found")
        if "invalid_status_transition" in msg:
            raise HTTPException(409, msg)
        raise HTTPException(400, msg)
    except PermissionError:
        raise HTTPException(403, "Only the content creator can file a counter-notice")
    return result


@router.get("/agent-info", response_model=DmcaAgentConfigOut)
async def get_agent_info():
    """Public DMCA designated agent contact information (no auth required)."""
    config = get_dmca_agent_config()
    if not config or not config.get("agent_name"):
        raise HTTPException(404, "DMCA agent information not configured")
    return config
