"""Admin Billing Configuration router (FIN-018).

Exposes the runtime-editable billing/fee/payout overrides:

  GET    /ui/admin/billing-config          -> effective config (ADMIN+)
  PATCH  /ui/admin/billing-config          -> update overrides   (ROOT)
  POST   /ui/admin/billing-config/reset    -> reset to defaults  (ROOT)
  POST   /ui/admin/billing-config/preview  -> impact preview     (ADMIN+)
  GET    /ui/admin/billing-config/audit    -> change history     (ADMIN+)

Reads require ADMIN or ROOT; writes require ROOT (changes affect all future
transactions). Every change is audited via ``audit_event``.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root, require_root
from app.models import (
    BillingConfigAuditLog,
    BillingConfigOut,
    BillingConfigPreview,
    BillingConfigResetRequest,
    BillingConfigUpdate,
)
from app.services import billing_config as svc
from app.services.alerts import audit_event

logger = logging.getLogger("billing_config")

billing_config_router = APIRouter(prefix="/ui/admin/billing-config", tags=["admin-billing-config"])


@billing_config_router.get("", response_model=BillingConfigOut)
def get_config(
    admin: AuthenticatedUser = Depends(require_admin_or_root),
) -> BillingConfigOut:
    """Return the effective billing configuration."""
    return BillingConfigOut(**svc.get_billing_config())


@billing_config_router.patch("", response_model=BillingConfigOut)
async def update_config(
    body: BillingConfigUpdate,
    request: Request,
    admin: AuthenticatedUser = Depends(require_root),
) -> BillingConfigOut:
    """Apply a partial update to billing overrides (ROOT only)."""
    # Reject unknown keys explicitly (Pydantic would otherwise silently drop
    # them, turning a typo into a no-op).
    try:
        raw = await request.json()
    except Exception:
        raw = {}
    if isinstance(raw, dict):
        for key in raw.keys():
            if not svc.is_editable_key(key):
                raise HTTPException(
                    status_code=422,
                    detail={"code": "validation_error", "message": f"unknown config key: {key}"},
                )

    updates = body.model_dump(exclude_none=True)
    try:
        result = svc.update_billing_config(admin_sub=admin.sub, updates=updates)
    except ValueError as exc:
        msg = str(exc)
        # Range conflicts are 400; unknown keys / bad values are 422.
        if "cannot exceed" in msg:
            raise HTTPException(status_code=400, detail={"code": "invalid_range", "message": msg})
        raise HTTPException(status_code=422, detail={"code": "validation_error", "message": msg})

    audit_event(
        "billing_config_updated",
        admin.sub,
        request,
        outcome="success",
        changed_fields=sorted(updates.keys()),
    )
    return BillingConfigOut(**result)


@billing_config_router.post("/reset", response_model=BillingConfigOut)
def reset_config(
    body: Optional[BillingConfigResetRequest],
    request: Request,
    admin: AuthenticatedUser = Depends(require_root),
) -> BillingConfigOut:
    """Reset one or more config keys to their env/code defaults (ROOT only)."""
    keys = body.keys if body else None
    try:
        result = svc.reset_config(admin_sub=admin.sub, keys=keys)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "validation_error", "message": str(exc)})

    audit_event(
        "billing_config_reset",
        admin.sub,
        request,
        outcome="success",
        reset_keys=keys or "all",
    )
    return BillingConfigOut(**result)


@billing_config_router.post("/preview", response_model=BillingConfigPreview)
def preview_config(
    body: BillingConfigUpdate,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
) -> BillingConfigPreview:
    """Project the impact of proposed config changes (read-only)."""
    proposed = body.model_dump(exclude_none=True)
    return BillingConfigPreview(**svc.preview_impact(proposed_changes=proposed))


@billing_config_router.get("/audit", response_model=BillingConfigAuditLog)
def get_audit(
    admin: AuthenticatedUser = Depends(require_admin_or_root),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
) -> BillingConfigAuditLog:
    """Return the billing-config change history (newest first)."""
    return BillingConfigAuditLog(**svc.get_audit_log(limit=limit, cursor=cursor))
