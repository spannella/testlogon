"""Syndicate open licensing router (LICENSE-005)."""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends

from app.services.sessions import require_ui_session
from app.models import (
    SyndicateOpenLicensingEnableIn,
    SyndicateOpenLicensingTermsUpdateIn,
    SyndicateOpenLicensingRegisterIn,
    SyndicateOpenLicensingConfigOut,
    SyndicateOpenLicensingEnableOut,
    SyndicateOpenLicensingContentOut,
    SyndicateOpenLicensingRegistrationOut,
    SyndicateOpenLicensingExemptionOut,
)
from app.services import syndicate_open_licensing as svc

logger = logging.getLogger(__name__)

syndicate_open_licensing_router = APIRouter(
    prefix="/ui/syndicates/open-licensing",
    tags=["syndicate-open-licensing"],
)


def _sub(session: Dict[str, Any]) -> str:
    return session["user_sub"]


@syndicate_open_licensing_router.get(
    "/{syndicate_id}", response_model=SyndicateOpenLicensingConfigOut
)
def get_config(syndicate_id: str, session: Dict[str, Any] = Depends(require_ui_session)):
    cfg = svc.get_open_licensing_config(syndicate_id=syndicate_id)
    return SyndicateOpenLicensingConfigOut(**cfg)


@syndicate_open_licensing_router.post(
    "/{syndicate_id}/enable", response_model=SyndicateOpenLicensingEnableOut
)
def enable(
    syndicate_id: str,
    body: SyndicateOpenLicensingEnableIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.enable_open_licensing(
        syndicate_id=syndicate_id,
        admin_sub=_sub(session),
        terms=body.terms.model_dump(),
    )
    return SyndicateOpenLicensingEnableOut(**result)


@syndicate_open_licensing_router.post(
    "/{syndicate_id}/disable", response_model=SyndicateOpenLicensingConfigOut
)
def disable(syndicate_id: str, session: Dict[str, Any] = Depends(require_ui_session)):
    svc.disable_open_licensing(syndicate_id=syndicate_id, admin_sub=_sub(session))
    return SyndicateOpenLicensingConfigOut(**svc.get_open_licensing_config(syndicate_id=syndicate_id))


@syndicate_open_licensing_router.patch(
    "/{syndicate_id}/terms", response_model=SyndicateOpenLicensingConfigOut
)
def update_terms(
    syndicate_id: str,
    body: SyndicateOpenLicensingTermsUpdateIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    svc.update_open_licensing_terms(
        syndicate_id=syndicate_id,
        admin_sub=_sub(session),
        terms=body.terms.model_dump(),
    )
    return SyndicateOpenLicensingConfigOut(**svc.get_open_licensing_config(syndicate_id=syndicate_id))


@syndicate_open_licensing_router.post(
    "/{syndicate_id}/register", response_model=SyndicateOpenLicensingRegistrationOut
)
def register(
    syndicate_id: str,
    body: SyndicateOpenLicensingRegisterIn,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.register_content(
        syndicate_id=syndicate_id,
        creator_sub=_sub(session),
        content_id=body.content_id,
        content_type=body.content_type,
    )
    return SyndicateOpenLicensingRegistrationOut(**result)


@syndicate_open_licensing_router.get("/{syndicate_id}/content")
def list_content(syndicate_id: str, session: Dict[str, Any] = Depends(require_ui_session)):
    items = svc.list_syndicate_content(syndicate_id=syndicate_id)
    return {"items": [SyndicateOpenLicensingContentOut(**i) for i in items]}


@syndicate_open_licensing_router.post(
    "/{syndicate_id}/exempt/{content_id}", response_model=SyndicateOpenLicensingExemptionOut
)
def exempt(
    syndicate_id: str,
    content_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.exempt_content(
        syndicate_id=syndicate_id, creator_sub=_sub(session), content_id=content_id
    )
    return SyndicateOpenLicensingExemptionOut(**result)


@syndicate_open_licensing_router.delete(
    "/{syndicate_id}/exempt/{content_id}", response_model=SyndicateOpenLicensingExemptionOut
)
def unexempt(
    syndicate_id: str,
    content_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
):
    result = svc.remove_content_exemption(
        syndicate_id=syndicate_id, creator_sub=_sub(session), content_id=content_id
    )
    return SyndicateOpenLicensingExemptionOut(**result)
