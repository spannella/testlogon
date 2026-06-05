"""Admin notification template management endpoints (ADMIN-002).

Prefix: /ui/admin/notifications
Auth: require_admin_or_root (cookie session + CSRF, or admin/root bearer).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.settings import S
from app.models import (
    NotificationTemplateOut,
    NotificationTemplatePreviewOut,
    NotificationTemplatePreviewRequest,
    NotificationTemplateTestSend,
    NotificationTemplateUpdate,
)
from app.services import notification_templates as svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/admin/notifications", tags=["admin-notifications"])


@router.get("/templates", response_model=list[NotificationTemplateOut])
async def list_notification_templates(
    channel: str | None = None,
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> list[NotificationTemplateOut]:
    """List notification templates, optionally filtered by channel."""
    return [NotificationTemplateOut(**t) for t in svc.list_templates(channel=channel)]


@router.get("/templates/{template_id}", response_model=NotificationTemplateOut)
async def get_notification_template(
    template_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> NotificationTemplateOut:
    """Get a single notification template by ID."""
    tpl = svc.get_template(template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
    return NotificationTemplateOut(**tpl)


@router.patch("/templates/{template_id}", response_model=NotificationTemplateOut)
async def update_notification_template(
    template_id: str,
    payload: NotificationTemplateUpdate = Body(...),
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> NotificationTemplateOut:
    """Update editable template fields (subject, body, active)."""
    if not S.admin_messaging_dashboard_template_edit_enabled:
        raise HTTPException(status_code=403, detail="Template editing is disabled")
    fields = payload.model_dump(exclude_unset=True)
    updated = svc.update_template(
        template_id,
        admin_sub=actor.sub,
        subject=fields["subject"] if "subject" in fields else ...,
        body=fields.get("body"),
        active=fields.get("active"),
    )
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
    return NotificationTemplateOut(**updated)


@router.post(
    "/templates/{template_id}/preview", response_model=NotificationTemplatePreviewOut
)
async def preview_notification_template(
    template_id: str,
    payload: NotificationTemplatePreviewRequest = Body(default=NotificationTemplatePreviewRequest()),
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> NotificationTemplatePreviewOut:
    """Render a template with sample variables for preview."""
    rendered = svc.preview_template(template_id, sample_vars=payload.sample_vars)
    if rendered is None:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
    return NotificationTemplatePreviewOut(**rendered)


@router.post("/templates/{template_id}/test-send")
async def test_send_notification_template(
    template_id: str,
    payload: NotificationTemplateTestSend = Body(...),
    actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    """Send a test notification using the template's channel."""
    if not S.admin_messaging_dashboard_test_send_enabled:
        raise HTTPException(status_code=403, detail="Test send is disabled")
    try:
        result = svc.test_send(
            template_id,
            recipient=payload.recipient,
            admin_sub=actor.sub,
            sample_vars=payload.sample_vars,
        )
    except PermissionError:
        raise HTTPException(
            status_code=429, detail="Too many test sends. Limit: 10 per hour."
        )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")
    return result
