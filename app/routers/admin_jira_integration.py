from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.services.jira_feature_flags import get_jira_feature_flags, set_runtime_outbound_kill_switch

router = APIRouter(prefix="/admin/integrations/jira", tags=["admin-jira-integration"])


class JiraFeatureFlagsOut(BaseModel):
    enabled: bool
    read_enabled: bool
    outbound_enabled: bool
    inbound_enabled: bool
    workspace_allowlist: list[str]
    outbound_kill_switch: bool


class OutboundKillSwitchReq(BaseModel):
    disabled: bool


class JiraFeatureFlagsEnvelope(BaseModel):
    flags: JiraFeatureFlagsOut


def _require_admin(user: AuthenticatedUser) -> None:
    if normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(status_code=403, detail="admin role required")


@router.get("/flags", response_model=JiraFeatureFlagsEnvelope)
def get_flags(user: AuthenticatedUser = Depends(get_authenticated_user)):
    _require_admin(user)
    flags = get_jira_feature_flags()
    return JiraFeatureFlagsEnvelope(
        flags=JiraFeatureFlagsOut(
            enabled=flags.enabled,
            read_enabled=flags.read_enabled,
            outbound_enabled=flags.outbound_enabled,
            inbound_enabled=flags.inbound_enabled,
            workspace_allowlist=list(flags.workspace_allowlist),
            outbound_kill_switch=flags.outbound_kill_switch,
        )
    )


@router.post("/flags/outbound-kill-switch", response_model=JiraFeatureFlagsEnvelope)
def set_outbound_kill_switch(body: OutboundKillSwitchReq, user: AuthenticatedUser = Depends(get_authenticated_user)):
    _require_admin(user)
    flags = set_runtime_outbound_kill_switch(disabled=body.disabled)
    return JiraFeatureFlagsEnvelope(
        flags=JiraFeatureFlagsOut(
            enabled=flags.enabled,
            read_enabled=flags.read_enabled,
            outbound_enabled=flags.outbound_enabled,
            inbound_enabled=flags.inbound_enabled,
            workspace_allowlist=list(flags.workspace_allowlist),
            outbound_kill_switch=flags.outbound_kill_switch,
        )
    )
