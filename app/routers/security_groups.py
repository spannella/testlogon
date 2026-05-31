"""Security Groups & Network Rules API router (INFRA-009).

Prefix: /ui/compute/security-groups
All endpoints use cookie-based session auth (require_ui_session). Security groups
are user-owned, so all access is scoped to the authenticated user's `user_sub`.
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import (
    AddRuleIn,
    CreateSgIn,
    EffectiveRuleOut,
    EffectiveRulesOut,
    SecurityGroupOut,
    SgListOut,
    UpdateRuleIn,
    UpdateSgIn,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session
from app.services.security_groups import (
    CannotDeleteDefault,
    DangerousRule,
    MaxRulesExceeded,
    RuleNotFound,
    RuleValidationError,
    SecurityGroupInUse,
    SecurityGroupNotFound,
    add_rule,
    create_security_group,
    delete_security_group,
    get_effective_rules,
    get_security_group,
    list_security_groups,
    remove_rule,
    update_rule,
    update_security_group,
)

logger = logging.getLogger(__name__)

security_groups_router = APIRouter(
    prefix="/ui/compute/security-groups", tags=["security-groups"]
)


def _require_enabled() -> None:
    if not S.security_groups_enabled:
        raise HTTPException(status_code=400, detail="Security groups are disabled")


def _map_mutation_error(exc: Exception) -> HTTPException:
    if isinstance(exc, DangerousRule):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, RuleValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, MaxRulesExceeded):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, SecurityGroupNotFound):
        return HTTPException(status_code=404, detail="Security group not found")
    if isinstance(exc, RuleNotFound):
        return HTTPException(status_code=404, detail="Rule not found")
    if isinstance(exc, CannotDeleteDefault):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, SecurityGroupInUse):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


# ─── Create ──────────────────────────────────────────────────────

@security_groups_router.post("", status_code=201, response_model=SecurityGroupOut)
async def create_sg(
    body: CreateSgIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        sg = create_security_group(
            user_sub,
            name=body.name,
            description=body.description,
            rules=[r.model_dump() for r in body.rules],
        )
    except Exception as exc:  # noqa: BLE001
        raise _map_mutation_error(exc)
    audit_event(
        "compute.sg_created", user_sub, request,
        sg_id=sg["sg_id"], rule_count=len(sg["rules"]),
    )
    return SecurityGroupOut(**sg)


# ─── List ────────────────────────────────────────────────────────

@security_groups_router.get("", response_model=SgListOut)
async def list_sgs(session: Dict = Depends(require_ui_session)):
    _require_enabled()
    user_sub = session["user_sub"]
    sgs = list_security_groups(user_sub)
    return SgListOut(
        security_groups=[SecurityGroupOut(**s) for s in sgs],
        count=len(sgs),
    )


# ─── Get detail ──────────────────────────────────────────────────

@security_groups_router.get("/{sg_id}", response_model=SecurityGroupOut)
async def get_sg(sg_id: str, session: Dict = Depends(require_ui_session)):
    _require_enabled()
    user_sub = session["user_sub"]
    sg = get_security_group(user_sub, sg_id)
    if not sg:
        raise HTTPException(status_code=404, detail="Security group not found")
    return SecurityGroupOut(**sg)


# ─── Effective (resolved) rules ──────────────────────────────────

@security_groups_router.get("/{sg_id}/effective-rules", response_model=EffectiveRulesOut)
async def get_sg_effective_rules(
    sg_id: str, session: Dict = Depends(require_ui_session)
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        rules = get_effective_rules(user_sub, sg_id)
    except SecurityGroupNotFound:
        raise HTTPException(status_code=404, detail="Security group not found")
    return EffectiveRulesOut(
        sg_id=sg_id,
        rules=[EffectiveRuleOut(**r) for r in rules],
        count=len(rules),
    )


# ─── Update ──────────────────────────────────────────────────────

@security_groups_router.patch("/{sg_id}", response_model=SecurityGroupOut)
async def patch_sg(
    sg_id: str,
    body: UpdateSgIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        sg = update_security_group(
            user_sub, sg_id, name=body.name, description=body.description
        )
    except SecurityGroupNotFound:
        raise HTTPException(status_code=404, detail="Security group not found")
    audit_event("compute.sg_updated", user_sub, request, sg_id=sg_id)
    return SecurityGroupOut(**sg)


# ─── Delete ──────────────────────────────────────────────────────

@security_groups_router.delete("/{sg_id}")
async def delete_sg(
    sg_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        delete_security_group(user_sub, sg_id)
    except Exception as exc:  # noqa: BLE001
        raise _map_mutation_error(exc)
    audit_event("compute.sg_deleted", user_sub, request, sg_id=sg_id)
    return {"ok": True}


# ─── Add rule ────────────────────────────────────────────────────

@security_groups_router.post("/{sg_id}/rules", response_model=SecurityGroupOut)
async def add_sg_rule(
    sg_id: str,
    body: AddRuleIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        sg = add_rule(user_sub, sg_id, body.model_dump())
    except Exception as exc:  # noqa: BLE001
        raise _map_mutation_error(exc)
    audit_event(
        "compute.sg_rule_added", user_sub, request,
        sg_id=sg_id, protocol=body.protocol, source=body.source,
        port_from=body.port_from, port_to=body.port_to,
    )
    return SecurityGroupOut(**sg)


# ─── Remove rule ─────────────────────────────────────────────────

@security_groups_router.delete("/{sg_id}/rules/{rule_id}", response_model=SecurityGroupOut)
async def remove_sg_rule(
    sg_id: str,
    rule_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        sg = remove_rule(user_sub, sg_id, rule_id)
    except Exception as exc:  # noqa: BLE001
        raise _map_mutation_error(exc)
    audit_event("compute.sg_rule_removed", user_sub, request, sg_id=sg_id, rule_id=rule_id)
    return SecurityGroupOut(**sg)


# ─── Update rule ─────────────────────────────────────────────────

@security_groups_router.patch("/{sg_id}/rules/{rule_id}", response_model=SecurityGroupOut)
async def patch_sg_rule(
    sg_id: str,
    rule_id: str,
    body: UpdateRuleIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_sub = session["user_sub"]
    try:
        sg = update_rule(user_sub, sg_id, rule_id, **body.model_dump())
    except Exception as exc:  # noqa: BLE001
        raise _map_mutation_error(exc)
    audit_event("compute.sg_rule_updated", user_sub, request, sg_id=sg_id, rule_id=rule_id)
    return SecurityGroupOut(**sg)
