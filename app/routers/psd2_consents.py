"""PSD2 AIS/PIS Consent API router (CSN-001 + CSN-002).

Routes registered only when S.open_bank_project_enabled AND S.psd2_consents_enabled.

IMPORTANT: /by-consumer/{consumer_ref} MUST be declared BEFORE /{consent_id}
so the literal segment "by-consumer" is not captured as a consent_id param.
Similarly, /{consent_id}/sca and /{consent_id}/accept are declared after the
base collection routes.
"""
from __future__ import annotations

import asyncio
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import require_root_session
from app.core.settings import S
from app.models import ConsentCreateIn
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/consents", tags=["psd2-consents"])


def _require_enabled() -> None:
    if not (getattr(S, "open_bank_project_enabled", False) and S.psd2_consents_enabled):
        raise HTTPException(404, "Not found")


# ---------------------------------------------------------------------------
# List consents for a consumer (admin/root — MUST be declared before /{consent_id})
# ---------------------------------------------------------------------------

@router.get("/by-consumer/{consumer_ref}")
async def list_consents_for_consumer_endpoint(
    consumer_ref: str,
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import list_consents_for_consumer
    return await asyncio.to_thread(
        list_consents_for_consumer, consumer_ref, status=status, limit=limit, cursor=cursor
    )


# ---------------------------------------------------------------------------
# Owner consent collection
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
async def create_consent_endpoint(
    req: Request,
    body: ConsentCreateIn,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import create_consent
    return await asyncio.to_thread(create_consent, ctx["user_sub"], body, req)


@router.get("")
async def list_own_consents(
    req: Request,
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import list_consents_for_owner
    return await asyncio.to_thread(
        list_consents_for_owner, ctx["user_sub"], status=status, limit=limit, cursor=cursor
    )


# ---------------------------------------------------------------------------
# Single consent routes (/{consent_id} must come after literal routes above)
# ---------------------------------------------------------------------------

@router.get("/{consent_id}")
async def get_consent_endpoint(
    consent_id: str,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import get_consent
    item = await asyncio.to_thread(get_consent, ctx["user_sub"], consent_id)
    if item is None:
        raise HTTPException(404, "consent not found")
    return item


@router.post("/{consent_id}/revoke")
async def revoke_consent_endpoint(
    req: Request,
    consent_id: str,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import revoke_consent
    return await asyncio.to_thread(revoke_consent, ctx["user_sub"], consent_id, req)


# ---------------------------------------------------------------------------
# CSN-002: SCA gate endpoints
# ---------------------------------------------------------------------------

@router.post("/{consent_id}/sca")
async def begin_consent_sca(
    consent_id: str,
    req: Request,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import request_consent_sca
    return await asyncio.to_thread(request_consent_sca, ctx["user_sub"], consent_id, req)


@router.post("/{consent_id}/accept")
async def accept_consent_endpoint(
    consent_id: str,
    req: Request,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.psd2_consents import accept_consent
    return await asyncio.to_thread(accept_consent, ctx["user_sub"], consent_id, req)
