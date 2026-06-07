"""Third-party KYC Partner API router (KYC-021).

Programmatic, API-key-authenticated access to the KYC application lifecycle
for external partners / white-label integrations, exposed at ``/api/v1/kyc``.

Authentication uses the mature API-key infrastructure via
``require_api_key_principal`` (Authorization: ApiKey <key> or X-API-Key).
These are programmatic (API-key) requests, so CSRF does NOT apply.

Scope model (added to CANONICAL_API_KEY_CAPABILITIES):
* ``kyc:submit``  — create application, submit for review
* ``kyc:read``    — check status, get verification result, list applications
* ``kyc:upload``  — upload documents
* ``kyc:webhook`` — manage webhook endpoints
* ``kyc:admin``   — full access (implies all of the above)

This router does NOT reimplement KYC case logic — it delegates to the existing
``app.services.kyc_cases`` service via ``app.services.kyc_partner_api`` and
emits ``kyc.*`` partner callbacks via the existing ``kyc_webhooks`` glue.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Form, Header, Query, Request, UploadFile

from app.models import (
    KycPartnerApplicationCreateIn,
    KycPartnerWebhookRegisterIn,
)
from app.services import kyc_partner_api as svc
from app.services.api_key_auth_dependency import require_api_key_principal
from app.services.rate_limit import rate_limit_kyc_partner_api

kyc_partner_api_router = APIRouter(prefix="/api/v1/kyc", tags=["KYC Partner API"])


def _is_sandbox(request: Request, principal: Dict[str, Any]) -> bool:
    header = (request.headers.get("x-sandbox") or "").strip().lower()
    if header in ("1", "true", "yes", "on"):
        return True
    return str(principal.get("api_key_id") or "").startswith("sandbox_")


def _require_idempotency(idempotency_key: Optional[str]) -> str:
    from fastapi import HTTPException

    value = (idempotency_key or "").strip()
    if not value:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "kyc_api_missing_idempotency",
                "message": "Idempotency-Key header required",
            },
        )
    return value


# ── Application lifecycle ────────────────────────────────────────────

@kyc_partner_api_router.post("/applications", status_code=201)
async def create_application(
    body: KycPartnerApplicationCreateIn,
    request: Request,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    svc.require_scope(principal, "kyc:submit")
    api_key_id = str(principal.get("api_key_id") or "")
    rate_limit_kyc_partner_api(api_key_id, "applications")
    idem = _require_idempotency(idempotency_key)
    payload = body.model_dump()
    fingerprint = svc._body_fingerprint(payload)

    cached = svc.check_idempotency(
        api_key_id=api_key_id, idempotency_key=idem, body_fingerprint=fingerprint
    )
    if cached is not None:
        return cached

    sandbox = _is_sandbox(request, principal)
    applicant = body.applicant.model_dump()
    if sandbox:
        result = svc.sandbox_create_application(
            principal,
            external_id=body.external_id,
            applicant=applicant,
            tier=body.tier,
            metadata=body.metadata,
        )
    else:
        result = svc.create_application(
            principal,
            external_id=body.external_id,
            applicant=applicant,
            tier=body.tier,
            metadata=body.metadata,
        )
    response = {
        "application_id": result["application_id"],
        "status": result["status"],
        "created_at": result["created_at"],
        "sandbox": result["sandbox"],
    }
    svc.store_idempotency(
        api_key_id=api_key_id,
        idempotency_key=idem,
        body_fingerprint=fingerprint,
        response_status=201,
        response_body=response,
    )
    return response


@kyc_partner_api_router.get("/applications")
async def list_or_lookup_applications(
    external_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=50),
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:read")
    rate_limit_kyc_partner_api(str(principal.get("api_key_id") or ""), "read")
    if external_id:
        return svc.get_application_by_external_id(principal, external_id)
    items = svc.list_applications(principal, limit=limit)
    return {"data": items, "count": len(items)}


@kyc_partner_api_router.get("/applications/{application_id}")
async def get_application(
    application_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:read")
    rate_limit_kyc_partner_api(str(principal.get("api_key_id") or ""), "read")
    return svc.get_application(principal, application_id)


@kyc_partner_api_router.get("/applications/{application_id}/result")
async def get_application_result(
    application_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:read")
    rate_limit_kyc_partner_api(str(principal.get("api_key_id") or ""), "read")
    return svc.get_application_result(principal, application_id)


@kyc_partner_api_router.post("/applications/{application_id}/submit")
async def submit_application(
    application_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    svc.require_scope(principal, "kyc:submit")
    api_key_id = str(principal.get("api_key_id") or "")
    rate_limit_kyc_partner_api(api_key_id, "applications")
    idem = _require_idempotency(idempotency_key)
    fingerprint = svc._body_fingerprint({"application_id": application_id, "op": "submit"})

    cached = svc.check_idempotency(
        api_key_id=api_key_id, idempotency_key=idem, body_fingerprint=fingerprint
    )
    if cached is not None:
        return cached

    result = svc.submit_application(principal, application_id)
    svc.store_idempotency(
        api_key_id=api_key_id,
        idempotency_key=idem,
        body_fingerprint=fingerprint,
        response_status=200,
        response_body=result,
    )
    return result


# ── Document upload ──────────────────────────────────────────────────

@kyc_partner_api_router.post("/applications/{application_id}/documents", status_code=201)
async def upload_document(
    application_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
    document_type: str = Form(...),
    file: UploadFile = File(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    svc.require_scope(principal, "kyc:upload")
    api_key_id = str(principal.get("api_key_id") or "")
    rate_limit_kyc_partner_api(api_key_id, "documents")
    idem = _require_idempotency(idempotency_key)
    fingerprint = svc._body_fingerprint(
        {"application_id": application_id, "document_type": document_type, "filename": file.filename}
    )

    cached = svc.check_idempotency(
        api_key_id=api_key_id, idempotency_key=idem, body_fingerprint=fingerprint
    )
    if cached is not None:
        return cached

    contents = await file.read()
    result = svc.upload_document(
        principal,
        application_id,
        document_type=document_type,
        file_type=str(file.content_type or "application/octet-stream"),
        filename=str(file.filename or ""),
        size_bytes=len(contents),
        contents=contents,
    )
    svc.store_idempotency(
        api_key_id=api_key_id,
        idempotency_key=idem,
        body_fingerprint=fingerprint,
        response_status=201,
        response_body=result,
    )
    return result


@kyc_partner_api_router.get("/applications/{application_id}/documents/{document_id}")
async def download_document(
    application_id: str,
    document_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:read")
    rate_limit_kyc_partner_api(str(principal.get("api_key_id") or ""), "read")
    return svc.get_document_download(principal, application_id, document_id)


# ── Webhook management ───────────────────────────────────────────────

@kyc_partner_api_router.post("/webhooks", status_code=201)
async def register_webhook(
    body: KycPartnerWebhookRegisterIn,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:webhook")
    return svc.register_webhook(
        principal, url=body.url, events=body.events, secret=body.secret
    )


@kyc_partner_api_router.get("/webhooks")
async def list_webhooks(
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:webhook")
    rate_limit_kyc_partner_api(str(principal.get("api_key_id") or ""), "read")
    items = svc.list_webhooks(principal)
    return {"data": items, "count": len(items)}


@kyc_partner_api_router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:webhook")
    return svc.delete_webhook(principal, webhook_id)


@kyc_partner_api_router.post("/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    principal: Dict[str, Any] = Depends(require_api_key_principal),
):
    svc.require_scope(principal, "kyc:webhook")
    rate_limit_kyc_partner_api(str(principal.get("api_key_id") or ""), "webhook_test")
    return svc.test_webhook(principal, webhook_id)
