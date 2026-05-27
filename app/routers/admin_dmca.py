"""Admin DMCA endpoints (MOD-002).

Provides admin/root access to DMCA claim management: listing, detail,
resolution, repeat-infringer checks, and agent config management.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_scope, require_root
from app.auth.roles import AdminScope
from app.models import (
    DmcaAgentConfigIn,
    DmcaAgentConfigOut,
    DmcaClaimDetailOut,
    DmcaClaimListOut,
    DmcaClaimOut,
    DmcaResolveIn,
    DmcaResolveOut,
    RepeatInfringerStatusOut,
)
from app.services.dmca_claims import (
    get_claim,
    get_repeat_infringer_status,
    list_claims_by_status,
    list_claims_by_user,
    list_claims_by_claimant,
    resolve_dmca_claim,
    get_dmca_agent_config,
    set_dmca_agent_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/dmca", tags=["admin-dmca"])

require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)


@router.get("/claims", response_model=DmcaClaimListOut)
async def list_claims(
    status: Optional[str] = Query(None, description="Filter by claim status"),
    target_user_id: Optional[str] = Query(None, description="Filter by target user"),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """List DMCA claims with optional filters."""
    if target_user_id:
        result = list_claims_by_user(target_user_id, limit=limit, cursor=cursor)
    elif status:
        result = list_claims_by_status(status, limit=limit, cursor=cursor)
    else:
        # Default: list all content_removed claims (active claims needing attention)
        result = list_claims_by_status("content_removed", limit=limit, cursor=cursor)

    return DmcaClaimListOut(
        items=[DmcaClaimOut(**i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@router.get("/claims/{claim_id}", response_model=DmcaClaimDetailOut)
async def get_claim_detail(
    claim_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Get full claim detail for admin review."""
    item = get_claim(claim_id)
    if not item:
        raise HTTPException(404, "Claim not found")

    target_user_id = item.get("target_user_id", "")
    claimant_email = item.get("claimant_email", "")

    # Get prior claims counts
    prior_user_claims = list_claims_by_user(target_user_id, limit=100) if target_user_id else {"items": []}
    prior_claimant_claims = list_claims_by_claimant(claimant_email, limit=100) if claimant_email else {"items": []}

    # Get repeat infringer status
    infringer_status = get_repeat_infringer_status(target_user_id) if target_user_id else {
        "status": "clear",
    }

    # Get target user profile (best-effort)
    target_profile: dict = {}
    if target_user_id:
        try:
            from app.core.tables import T
            profile_item = T.profile.get_item(Key={"user_sub": target_user_id}).get("Item")
            if profile_item:
                target_profile = {
                    "user_sub": profile_item.get("user_sub", ""),
                    "display_name": profile_item.get("display_name", ""),
                    "email": profile_item.get("email", ""),
                }
        except Exception:
            pass

    from app.services.dmca_claims import _claim_out

    return DmcaClaimDetailOut(
        claim=DmcaClaimOut(**_claim_out(item)),
        content_snapshot=item.get("content_snapshot") or {},
        target_user_profile=target_profile,
        claimant_full_details={
            "claimant_name": item.get("claimant_name", ""),
            "claimant_email": item.get("claimant_email", ""),
            "claimant_address": item.get("claimant_address", ""),
            "claimant_phone": item.get("claimant_phone", ""),
        },
        prior_claims_against_user=len(prior_user_claims.get("items", [])),
        prior_claims_by_claimant=len(prior_claimant_claims.get("items", [])),
        repeat_infringer_status=infringer_status.get("status", "clear"),
    )


@router.post("/claims/{claim_id}/resolve", response_model=DmcaResolveOut)
async def resolve_claim(
    claim_id: str,
    body: DmcaResolveIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Resolve a DMCA claim."""
    try:
        result = resolve_dmca_claim(
            claim_id=claim_id,
            resolution=body.resolution,
            resolution_notes=body.resolution_notes,
            admin_user_id=admin.sub,
        )
    except ValueError as exc:
        msg = str(exc)
        if "claim_not_found" in msg:
            raise HTTPException(404, "Claim not found")
        if "invalid_status_transition" in msg:
            raise HTTPException(409, msg)
        raise HTTPException(400, msg)
    return result


@router.get("/users/{user_id}/infringer-status", response_model=RepeatInfringerStatusOut)
async def get_infringer_status(
    user_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Check repeat infringer status for a user."""
    return get_repeat_infringer_status(user_id)


@router.put("/agent-config", response_model=DmcaAgentConfigOut)
async def update_agent_config(
    body: DmcaAgentConfigIn,
    admin: AuthenticatedUser = Depends(require_root),
):
    """Update DMCA designated agent configuration (ROOT only)."""
    result = set_dmca_agent_config(body.model_dump())
    return result
