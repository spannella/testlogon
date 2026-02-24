from __future__ import annotations

from typing import Any, Dict, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_scope, require_role_value
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.services.alerts import audit_event
from app.services.entitlement_admin import (
    credit_adjust_entitlement_admin,
    extend_entitlement_admin,
    revoke_entitlement_admin,
)

router = APIRouter(prefix="/v1/admin/entitlements", tags=["admin-entitlements"])

require_billing_support_admin = require_admin_scope("billing_support")


class _AdjustmentBase(BaseModel):
    reason_code: Literal["customer_support", "fraud_review", "billing_correction", "incident_remediation", "goodwill"]
    audit_comment: str = Field(..., min_length=5, max_length=1000)


class RevokeEntitlementIn(_AdjustmentBase):
    pass


class ExtendEntitlementIn(_AdjustmentBase):
    extend_hours: int = Field(..., gt=0, le=24 * 365)


class CreditAdjustEntitlementIn(_AdjustmentBase):
    credit_units: int = Field(..., gt=0, le=1_000_000)


async def require_entitlement_admin_operator(user: AuthenticatedUser = Depends(get_authenticated_user), request: Request = None) -> AuthenticatedUser:
    if bool(getattr(S, "admin_scope_enforce_billing_support", True)):
        return await require_billing_support_admin(request=request, user=user)
    require_role_value(normalize_role(user.role).value, {Role.ADMIN, Role.ROOT})
    return user


@router.post("/{entitlement_id}/revoke")
def revoke_entitlement(
    entitlement_id: str,
    inp: RevokeEntitlementIn,
    req: Request,
    actor: AuthenticatedUser = Depends(require_entitlement_admin_operator),
):
    try:
        out = revoke_entitlement_admin(
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
            audit_comment=inp.audit_comment,
            actor_sub=actor.sub,
        )
        audit_event(
            "admin_entitlement_revoke",
            actor.sub,
            req,
            outcome="success",
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
            audit_comment=inp.audit_comment,
        )
        return out
    except HTTPException as exc:
        audit_event(
            "admin_entitlement_revoke",
            actor.sub,
            req,
            outcome="error",
            status_code=exc.status_code,
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
        )
        raise


@router.post("/{entitlement_id}/extend")
def extend_entitlement(
    entitlement_id: str,
    inp: ExtendEntitlementIn,
    req: Request,
    actor: AuthenticatedUser = Depends(require_entitlement_admin_operator),
):
    try:
        out = extend_entitlement_admin(
            entitlement_id=entitlement_id,
            extend_hours=inp.extend_hours,
            reason_code=inp.reason_code,
            audit_comment=inp.audit_comment,
            actor_sub=actor.sub,
        )
        audit_event(
            "admin_entitlement_extend",
            actor.sub,
            req,
            outcome="success",
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
            extend_hours=inp.extend_hours,
            audit_comment=inp.audit_comment,
        )
        return out
    except HTTPException as exc:
        audit_event(
            "admin_entitlement_extend",
            actor.sub,
            req,
            outcome="error",
            status_code=exc.status_code,
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
        )
        raise


@router.post("/{entitlement_id}/credits")
def credit_adjust_entitlement(
    entitlement_id: str,
    inp: CreditAdjustEntitlementIn,
    req: Request,
    actor: AuthenticatedUser = Depends(require_entitlement_admin_operator),
):
    try:
        out = credit_adjust_entitlement_admin(
            entitlement_id=entitlement_id,
            credit_units=inp.credit_units,
            reason_code=inp.reason_code,
            audit_comment=inp.audit_comment,
            actor_sub=actor.sub,
        )
        audit_event(
            "admin_entitlement_credit_adjust",
            actor.sub,
            req,
            outcome="success",
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
            credit_units=inp.credit_units,
            audit_comment=inp.audit_comment,
        )
        return out
    except HTTPException as exc:
        audit_event(
            "admin_entitlement_credit_adjust",
            actor.sub,
            req,
            outcome="error",
            status_code=exc.status_code,
            entitlement_id=entitlement_id,
            reason_code=inp.reason_code,
        )
        raise
