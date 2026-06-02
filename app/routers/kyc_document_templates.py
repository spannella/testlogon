"""KYC-017 — Document Signing Template Library router.

Admin endpoints (require_admin_or_root): create / upload version / list / get /
activate / deactivate / preview / archive.
Case/user endpoints (require_ui_session): list required-for-tier, render-for-case.

Rendered templates are instantiated as signature packets via the EXISTING
``create_draft_packet`` flow (KYC-007) — signing is NOT reimplemented here.
"""
from __future__ import annotations

import base64
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from app.auth.policy import require_admin_or_root
from app.models import (
    KycDocumentTemplateCreateIn,
    KycDocumentTemplateListOut,
    KycDocumentTemplateOut,
    KycDocumentTemplateUploadIn,
    KycDocumentTemplateVersionOut,
    KycRenderedTemplateOut,
    KycRequiredTemplatesOut,
    KycTemplateRenderForCaseIn,
    KycTemplateRenderForCaseOut,
)
from app.services.kyc_document_templates import (
    SERVICE,
    KycTemplateNotFound,
    KycTemplateSlugExists,
    KycTemplateValidationError,
    build_user_profile_for_merge,
    template_tier_for_int,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/kyc/document-templates", tags=["kyc-document-templates"])


# ── serialization helpers ───────────────────────────────────────────────
def _version_out(item: dict) -> KycDocumentTemplateVersionOut:
    return KycDocumentTemplateVersionOut(
        template_id=str(item.get("template_id")),
        version=int(item.get("version") or 0),
        slug=str(item.get("slug")),
        display_name=item.get("display_name"),
        required_tier=str(item.get("required_tier") or "tier_1"),
        status=str(item.get("status") or "active"),
        s3_key=str(item.get("s3_key") or ""),
        pdf_uploaded=bool(item.get("pdf_uploaded") or item.get("s3_key")),
        placeholder_fields=list(item.get("placeholder_fields") or []),
        created_by=item.get("created_by"),
        created_at=int(item.get("created_at") or 0),
        updated_at=int(item.get("updated_at") or 0),
    )


def _template_out(meta: dict, *, with_versions: bool = False) -> KycDocumentTemplateOut:
    versions = []
    if with_versions:
        versions = [_version_out(v) for v in SERVICE.get_template_versions(str(meta.get("template_id")))]
    return KycDocumentTemplateOut(
        template_id=str(meta.get("template_id")),
        slug=str(meta.get("slug")),
        display_name=str(meta.get("display_name")),
        description=str(meta.get("description") or ""),
        required_tier=str(meta.get("required_tier") or "tier_1"),
        status=str(meta.get("status") or "active"),
        placeholder_fields=list(meta.get("placeholder_fields") or []),
        latest_version=int(meta.get("latest_version") or 0),
        s3_key=str(meta.get("s3_key") or ""),
        created_by=meta.get("created_by"),
        created_at=int(meta.get("created_at") or 0),
        updated_at=int(meta.get("updated_at") or 0),
        versions=versions,
    )


def _actor_sub(user) -> str:
    return str(getattr(user, "sub", "") or "")


# ── Admin endpoints ──────────────────────────────────────────────────────
@router.post("", status_code=201, response_model=KycDocumentTemplateOut)
@router.post("/", status_code=201, response_model=KycDocumentTemplateOut, include_in_schema=False)
async def create_template(
    body: KycDocumentTemplateCreateIn,
    user=Depends(require_admin_or_root),
):
    try:
        meta = SERVICE.create_template(
            slug=body.slug,
            display_name=body.display_name,
            description=body.description or "",
            required_tier=body.required_tier,
            placeholder_fields=body.placeholder_fields,
            created_by=_actor_sub(user),
        )
    except KycTemplateSlugExists:
        raise HTTPException(409, {"code": "kyc_template_slug_exists"})
    except KycTemplateValidationError as exc:
        raise HTTPException(422, {"code": str(exc)})
    return _template_out(meta, with_versions=True)


@router.post("/{template_id}/versions", status_code=201, response_model=KycDocumentTemplateVersionOut)
async def upload_version(
    template_id: str,
    body: KycDocumentTemplateUploadIn,
    user=Depends(require_admin_or_root),
):
    try:
        pdf_bytes = base64.b64decode(body.pdf_base64, validate=False)
    except Exception:
        raise HTTPException(422, {"code": "kyc_invalid_file_type"})
    try:
        item = SERVICE.upload_template_version(
            template_id=template_id, pdf_bytes=pdf_bytes, uploaded_by=_actor_sub(user)
        )
    except KycTemplateNotFound:
        raise HTTPException(404, {"code": "kyc_template_not_found"})
    except KycTemplateValidationError as exc:
        code = str(exc)
        status = 413 if code == "kyc_file_too_large" else (409 if code == "kyc_template_already_archived" else 422)
        raise HTTPException(status, {"code": code})
    return _version_out(item)


@router.patch("/{template_id}/versions/{version}/activate", response_model=KycDocumentTemplateVersionOut)
async def activate_version(
    template_id: str,
    version: int,
    user=Depends(require_admin_or_root),
):
    try:
        item = SERVICE.activate_template(template_id=template_id, version=version)
    except KycTemplateNotFound:
        raise HTTPException(404, {"code": "kyc_version_not_found"})
    except KycTemplateValidationError as exc:
        raise HTTPException(400, {"code": str(exc)})
    return _version_out(item)


@router.patch("/{template_id}/versions/{version}/deactivate", response_model=KycDocumentTemplateVersionOut)
async def deactivate_version(
    template_id: str,
    version: int,
    user=Depends(require_admin_or_root),
):
    try:
        item = SERVICE.deactivate_template(template_id=template_id, version=version)
    except KycTemplateNotFound:
        raise HTTPException(404, {"code": "kyc_version_not_found"})
    except KycTemplateValidationError as exc:
        raise HTTPException(400, {"code": str(exc)})
    return _version_out(item)


@router.get("", response_model=KycDocumentTemplateListOut)
@router.get("/", response_model=KycDocumentTemplateListOut, include_in_schema=False)
async def list_templates(
    status: Optional[str] = None,
    user=Depends(require_admin_or_root),
):
    items = SERVICE.list_templates(status=status)
    return KycDocumentTemplateListOut(
        items=[_template_out(m) for m in items], total=len(items)
    )


@router.get("/{template_id}", response_model=KycDocumentTemplateOut)
async def get_template(
    template_id: str,
    user=Depends(require_admin_or_root),
):
    meta = SERVICE.get_template(template_id)
    if not meta:
        raise HTTPException(404, {"code": "kyc_template_not_found"})
    return _template_out(meta, with_versions=True)


@router.get("/{template_id}/versions/{version}/preview")
async def preview_version(
    template_id: str,
    version: int,
    user=Depends(require_admin_or_root),
):
    from fastapi import Response

    try:
        pdf = SERVICE.preview_template(template_id=template_id, version=version)
    except KycTemplateNotFound:
        raise HTTPException(404, {"code": "kyc_version_not_found"})
    except KycTemplateValidationError as exc:
        code = str(exc)
        status = 400 if code in ("kyc_no_pdf_uploaded", "kyc_no_pdf") else 422
        raise HTTPException(status, {"code": code})
    return Response(content=pdf, media_type="application/pdf")


@router.delete("/{template_id}", response_model=KycDocumentTemplateOut)
async def archive_template(
    template_id: str,
    user=Depends(require_admin_or_root),
):
    try:
        meta = SERVICE.archive_template(template_id=template_id)
    except KycTemplateNotFound:
        raise HTTPException(404, {"code": "kyc_template_not_found"})
    except KycTemplateValidationError as exc:
        raise HTTPException(409, {"code": str(exc)})
    return _template_out(meta, with_versions=True)


# ── Case / user endpoints ────────────────────────────────────────────────
@router.get("/required/list", response_model=KycRequiredTemplatesOut)
async def required_for_tier(
    tier: str = "tier_1",
    ctx: dict = Depends(require_ui_session),
):
    try:
        items = SERVICE.get_required_templates_for_tier(tier)
    except KycTemplateValidationError as exc:
        raise HTTPException(400, {"code": str(exc)})
    return KycRequiredTemplatesOut(tier=tier, items=[_version_out(i) for i in items])


@router.post("/render-for-case", response_model=KycTemplateRenderForCaseOut)
async def render_for_case(
    request: Request,
    body: KycTemplateRenderForCaseIn = Body(...),
    ctx: dict = Depends(require_ui_session),
):
    user_sub = ctx["user_sub"]

    # Resolve the case + its owner / target tier.
    from app.services.kyc_cases import STORE as KYC_STORE

    case = KYC_STORE.get_case(body.case_id)
    if not case:
        raise HTTPException(404, {"code": "kyc_case_not_found"})
    owner_sub = str(case.get("user_sub") or "")
    if owner_sub and owner_sub != user_sub and ctx.get("role") not in ("admin", "root"):
        raise HTTPException(403, {"code": "kyc_case_forbidden"})

    target_tier = case.get("target_tier")
    if not isinstance(target_tier, str) or not target_tier.startswith("tier_"):
        # Fall back to the owner's integer KYC tier mapped to a template tier.
        from app.services.kyc_tiers import get_user_kyc_tier

        target_tier = template_tier_for_int(get_user_kyc_tier(owner_sub or user_sub))

    try:
        required = SERVICE.get_required_templates_for_tier(target_tier)
    except KycTemplateValidationError as exc:
        raise HTTPException(400, {"code": str(exc)})
    if not required:
        raise HTTPException(400, {"code": "kyc_no_templates_available"})

    profile = build_user_profile_for_merge(owner_sub or user_sub)
    rendered: list[KycRenderedTemplateOut] = []
    for tmpl in required:
        template_id = str(tmpl.get("template_id"))
        version = int(tmpl.get("version") or 0)
        slug = str(tmpl.get("slug"))
        try:
            key, populated, fallback = SERVICE.render_and_store(
                template_id=template_id,
                version=version,
                user_profile=profile,
                case_id=body.case_id,
                slug=slug,
            )
        except KycTemplateValidationError:
            continue

        packet_id: Optional[str] = None
        try:
            from app.services.signature_packet_store import create_draft_packet

            packet = create_draft_packet(
                owner_user_id=owner_sub or user_sub,
                source_path=key,
                source_content_type="application/pdf",
                source_name=f"{slug}.pdf",
                origin_channel="kyc_document_template",
                origin_ref=f"{body.case_id}:{slug}",
            )
            packet_id = str(packet.get("packet_id"))
        except Exception:
            logger.warning(
                "render_for_case: failed to instantiate packet for %s/%s",
                body.case_id,
                slug,
                exc_info=True,
            )

        rendered.append(
            KycRenderedTemplateOut(
                slug=slug,
                template_id=template_id,
                version=version,
                rendered_s3_key=key,
                packet_id=packet_id,
                fields_populated=populated,
                fields_fallback=fallback,
            )
        )

    return KycTemplateRenderForCaseOut(case_id=body.case_id, rendered=rendered)
