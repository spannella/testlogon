"""Versioned signature templates router (KYC-007).

Exposes CRUD-lite operations over versioned signature templates:
  - list latest template summaries
  - list all versions of a template
  - get a specific pinned version
  - create the next version (admin/notary only)
  - migration check: which pinned versions now have a newer template

Templates are versioned so that creating a packet pins a specific version;
publishing new terms creates a new version without mutating in-flight packets.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    CreateSignatureTemplateVersionIn,
    SignatureTemplateListOut,
    SignatureTemplateMigrationCheckIn,
    SignatureTemplateMigrationListOut,
    SignatureTemplateVersionOut,
    SignatureTemplateVersionsOut,
)
from app.services.sessions import require_ui_session
from app.services.signature_packet_flags import SignaturePdfDisabledError
from app.services.signature_template_versions import (
    TemplateVersionError,
    check_version_migration,
    create_template_version,
    get_template_version,
    list_all_template_keys,
    list_template_versions,
)

router = APIRouter(prefix="/ui/signing/templates", tags=["signature-templates"])


def _pdf_guard(exc: SignaturePdfDisabledError) -> HTTPException:
    return HTTPException(status_code=404, detail={"code": "signature_pdf_disabled"})


@router.get("", response_model=SignatureTemplateListOut)
def list_signature_templates(_ctx: Dict[str, str] = Depends(require_ui_session)) -> Dict[str, Any]:
    try:
        templates = list_all_template_keys()
    except SignaturePdfDisabledError as exc:
        raise _pdf_guard(exc) from exc
    return {"templates": templates}


@router.get("/{template_key}/versions", response_model=SignatureTemplateVersionsOut)
def list_signature_template_versions(
    template_key: str,
    _ctx: Dict[str, str] = Depends(require_ui_session),
) -> Dict[str, Any]:
    try:
        versions = list_template_versions(template_key)
    except SignaturePdfDisabledError as exc:
        raise _pdf_guard(exc) from exc
    return {"template_key": template_key, "versions": versions}


@router.get("/{template_key}/versions/{version}", response_model=SignatureTemplateVersionOut)
def get_signature_template_version(
    template_key: str,
    version: int,
    _ctx: Dict[str, str] = Depends(require_ui_session),
) -> Dict[str, Any]:
    try:
        out = get_template_version(template_key, version)
    except SignaturePdfDisabledError as exc:
        raise _pdf_guard(exc) from exc
    if not out:
        raise HTTPException(status_code=404, detail={"code": "signature_template_version_not_found"})
    return out


@router.post("", response_model=SignatureTemplateVersionOut)
def create_signature_template_version(
    body: CreateSignatureTemplateVersionIn,
    _ctx: Dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    try:
        out = create_template_version(
            template_key=body.template_key,
            display_name=body.display_name,
            description=body.description,
            fields=[f.model_dump() for f in body.fields],
            created_by=user.sub,
        )
    except SignaturePdfDisabledError as exc:
        raise _pdf_guard(exc) from exc
    except TemplateVersionError as exc:
        raise HTTPException(status_code=400, detail={"code": str(exc)}) from exc
    return out


@router.post("/migration-check", response_model=SignatureTemplateMigrationListOut)
def signature_template_migration_check(
    body: SignatureTemplateMigrationCheckIn,
    _ctx: Dict[str, str] = Depends(require_ui_session),
) -> Dict[str, Any]:
    try:
        migrations = check_version_migration([p.model_dump() for p in body.pins])
    except SignaturePdfDisabledError as exc:
        raise _pdf_guard(exc) from exc
    return {"migrations": migrations}
