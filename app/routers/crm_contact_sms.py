"""CRM Contact SMS router — EVT-014.

Thin router gated by S.crm_contact_sms_enabled (default False).
"""
from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.settings import S
from app.services.sessions import require_ui_session
from app import models

router = APIRouter(prefix="/ui/crm/contacts", tags=["crm_contact_sms"])


def _require_crm_contact_sms_enabled() -> None:
    if not S.crm_contact_sms_enabled:
        raise HTTPException(status_code=404, detail="CRM Contact SMS feature is not enabled")


@router.post("/{contact_id}/sms", response_model=models.CrmContactSmsOut, status_code=201)
async def send_contact_sms(
    contact_id: str,
    body: models.CrmContactSmsSendIn,
    request: Request,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_contact_sms_enabled()
    # Per-sender rate limit
    from app.services.rate_limit import _bucket_limit  # lazy import (RULE-1)
    if not _bucket_limit(ctx["user_sub"], "rl#crm_sms", S.crm_contact_sms_rate_max, S.crm_contact_sms_rate_window_seconds):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    from app.services.crm_contact_sms import send_contact_sms as _send  # lazy import (RULE-1)
    result = _send(sender_sub=ctx["user_sub"], contact_id=contact_id, body=body.body)
    return result


@router.get("/{contact_id}/sms", response_model=models.CrmContactSmsLogListOut)
async def list_contact_sms(
    contact_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    _require_crm_contact_sms_enabled()
    from app.services.crm_contact_sms import list_contact_sms_log  # lazy import (RULE-1)
    return list_contact_sms_log(ctx["user_sub"], limit=limit, cursor=cursor)
