"""License agreement template management router (LICENSE-001).

Distinct from the issued-license router (`/ui/licenses/issued`, `/ui/licenses/library`)
and the request workflow router. This manages the AGREEMENT templates a creator
uploads and versions, plus admin verification.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
)

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    LicenseAgreementAdminReviewIn,
    LicenseAgreementContentLinkIn,
    LicenseAgreementContentLinkOut,
    LicenseAgreementDownloadOut,
    LicenseAgreementListOut,
    LicenseAgreementOut,
    LicenseAgreementReviewItemOut,
    LicenseAgreementReviewQueueOut,
    LicenseAgreementStatusIn,
    LicenseAgreementUpdateIn,
)
from app.services import license_agreements as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

# Sub-prefix under the existing /ui/licenses area to avoid path collisions
# with the issued-license router.
license_agreements_router = APIRouter(
    prefix="/ui/licenses/agreements", tags=["license-agreements"]
)
license_agreements_admin_router = APIRouter(
    prefix="/ui/admin/licenses", tags=["license-agreements-admin"]
)


def _out(item: dict) -> LicenseAgreementOut:
    return LicenseAgreementOut(
        license_id=item.get("license_id", ""),
        title=item.get("title", ""),
        licensor_name=item.get("licensor_name", ""),
        license_type=item.get("license_type", ""),
        file_name=item.get("file_name", ""),
        file_size=int(item.get("file_size", 0) or 0),
        mime_type=item.get("mime_type", ""),
        status=item.get("status", ""),
        version=int(item.get("version", 1) or 1),
        territory=item.get("territory", "worldwide"),
        expires_at=int(item["expires_at"]) if item.get("expires_at") is not None else None,
        notes=item.get("notes", ""),
        rejection_reason=item.get("rejection_reason", ""),
        created_at=int(item.get("created_at", 0) or 0),
        updated_at=int(item.get("updated_at", 0) or 0),
        content_count=int(item.get("content_count", 0) or 0),
        expiring_soon=bool(item.get("expiring_soon", False)),
    )


# ─── Create / upload ──────────────────────────────────────────────────────

@license_agreements_router.post("", response_model=LicenseAgreementOut)
async def create_agreement(
    title: str = Form(...),
    licensor_name: str = Form(...),
    license_type: str = Form(...),
    territory: str = Form("worldwide"),
    expires_at: Optional[int] = Form(None),
    notes: str = Form(""),
    file: UploadFile = File(...),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    content = await file.read()
    license_id_preview = f"lagr_{__import__('uuid').uuid4().hex}"
    try:
        # Upload first (validates mime/size/magic bytes), then create record.
        file_meta = svc.upload_agreement_file(
            creator_sub=user_sub,
            license_id=license_id_preview,
            file_name=file.filename or "agreement",
            file_bytes=content,
            mime_type=file.content_type or "",
        )
        item = svc.create_agreement(
            creator_sub=user_sub,
            title=title,
            licensor_name=licensor_name,
            license_type=license_type,
            file_key=file_meta["file_key"],
            file_name=file_meta["file_name"],
            file_size=file_meta["file_size"],
            mime_type=file_meta["mime_type"],
            territory=territory,
            expires_at=expires_at,
            notes=notes,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _out(item)


# ─── List / get ───────────────────────────────────────────────────────────

@license_agreements_router.get("", response_model=LicenseAgreementListOut)
def list_agreements(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    result = svc.list_agreements(
        creator_sub=user_sub, status_filter=status, limit=limit, cursor=cursor
    )
    return LicenseAgreementListOut(
        items=[_out(i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@license_agreements_router.get("/{license_id}", response_model=LicenseAgreementOut)
def get_agreement(
    license_id: str,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    item = svc.get_agreement(creator_sub=user_sub, license_id=license_id)
    if not item:
        raise HTTPException(404, "Agreement not found")
    item["content_count"] = len(svc.list_content_for_license(license_id=license_id))
    return _out(item)


@license_agreements_router.patch("/{license_id}", response_model=LicenseAgreementOut)
def update_agreement(
    license_id: str,
    body: LicenseAgreementUpdateIn,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.update_agreement(
            creator_sub=user_sub,
            license_id=license_id,
            updates=body.model_dump(exclude_none=True),
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _out(item)


@license_agreements_router.post("/{license_id}/status", response_model=LicenseAgreementOut)
def change_status(
    license_id: str,
    body: LicenseAgreementStatusIn,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = svc.set_status(
            creator_sub=user_sub, license_id=license_id, new_status=body.status
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _out(item)


@license_agreements_router.delete("/{license_id}")
def delete_agreement(
    license_id: str,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        svc.delete_agreement(creator_sub=user_sub, license_id=license_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"ok": True}


@license_agreements_router.get("/{license_id}/download", response_model=LicenseAgreementDownloadOut)
def download_agreement(
    license_id: str,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        url = svc.get_download_url(creator_sub=user_sub, license_id=license_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return LicenseAgreementDownloadOut(download_url=url)


# ─── Content linking ──────────────────────────────────────────────────────

@license_agreements_router.post(
    "/{license_id}/link", response_model=LicenseAgreementContentLinkOut
)
def link_content(
    license_id: str,
    body: LicenseAgreementContentLinkIn,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        link = svc.link_content(
            creator_sub=user_sub,
            license_id=license_id,
            content_id=body.content_id,
            content_type=body.content_type,
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return LicenseAgreementContentLinkOut(**link)


@license_agreements_router.delete("/{license_id}/link/{content_id}")
def unlink_content(
    license_id: str,
    content_id: str,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    item = svc.get_agreement(creator_sub=user_sub, license_id=license_id)
    if not item:
        raise HTTPException(404, "Agreement not found")
    svc.unlink_content(
        creator_sub=user_sub, license_id=license_id, content_id=content_id
    )
    return {"ok": True}


@license_agreements_router.get("/{license_id}/content")
def list_content_for_agreement(
    license_id: str,
    session: dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    item = svc.get_agreement(creator_sub=user_sub, license_id=license_id)
    if not item:
        raise HTTPException(404, "Agreement not found")
    return {"items": svc.list_content_for_license(license_id=license_id)}


@license_agreements_router.get("/content/{content_id}/licenses")
def list_agreements_for_content(
    content_id: str,
    session: dict = Depends(require_ui_session),
):
    # Returns agreement-template links for a content item (creator-scoped read).
    return {"items": svc.list_licenses_for_content(content_id=content_id)}


# ─── Admin review ─────────────────────────────────────────────────────────

@license_agreements_admin_router.get("/review", response_model=LicenseAgreementReviewQueueOut)
def admin_review_queue(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    result = svc.admin_list_review_queue(limit=limit, cursor=cursor)
    return LicenseAgreementReviewQueueOut(
        items=[LicenseAgreementReviewItemOut(**i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@license_agreements_admin_router.post(
    "/review/{license_id}", response_model=LicenseAgreementOut
)
def admin_review(
    license_id: str,
    body: LicenseAgreementAdminReviewIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        item = svc.admin_review_agreement(
            admin_sub=user.sub,
            license_id=license_id,
            verified=body.verified,
            rejection_reason=body.rejection_reason,
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return _out(item)
