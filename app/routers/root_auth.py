from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import get_authenticated_user_sub
from app.auth.root_network import enforce_root_network_gate
from app.core.settings import S
from app.models import UiSessionStartReq, UiSessionStartResp
from app.services.alerts import audit_event
from app.services.rate_limit import rate_limit_login_attempt
from app.services.sessions import compute_required_factors, create_stepup_challenge

router = APIRouter(prefix="/auth/root", tags=["root-auth"])


@router.post("/login", response_model=UiSessionStartResp)
async def root_login(req: Request, body: UiSessionStartReq, user_sub: str = Depends(get_authenticated_user_sub)):
    root_sub = (S.root_user_sub or "").strip()
    if user_sub != root_sub:
        audit_event("root_login_denied", user_sub, req, outcome="denied", reason="not_root_subject")
        raise HTTPException(status_code=403, detail="Root login requires configured root identity")

    source_ip = enforce_root_network_gate(req)
    rate_limit_login_attempt(user_sub, source_ip)
    required_factors = compute_required_factors(user_sub)
    if not required_factors:
        audit_event("root_login_denied", user_sub, req, outcome="denied", reason="mfa_not_configured", source_ip=source_ip)
        raise HTTPException(status_code=403, detail="Root MFA must be configured before login")

    challenge_id = create_stepup_challenge(
        req,
        user_sub,
        required_factors=required_factors,
        risk_score=0,
        refresh_ttl_seconds=None,
    )
    audit_event(
        "root_login_start",
        user_sub,
        req,
        outcome="info",
        challenge_id=challenge_id,
        required_factors=required_factors,
        source_ip=source_ip,
    )
    return UiSessionStartResp(auth_required=True, challenge_id=challenge_id, required_factors=required_factors)
