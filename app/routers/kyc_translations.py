"""KYC-020: Multi-Language Support router.

User-facing endpoints (``require_ui_session``) serve localized KYC content:
supported locales, the translation bundle for a locale, localized
questionnaires and legal notices.

Admin endpoints (``require_admin_or_root``) manage the translation store:
list / upsert / delete keys, bulk import / export, and coverage reporting.

Prefix: ``/v1/kyc/i18n``
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycCoverageReportOut,
    KycLocalizedLegalNoticeOut,
    KycLocalizedQuestionnaireOut,
    KycSupportedLocalesOut,
    KycTranslationBulkImportIn,
    KycTranslationBulkImportOut,
    KycTranslationBundleOut,
    KycTranslationExportOut,
    KycTranslationIn,
    KycTranslationListOut,
    KycTranslationOut,
)
from app.services.kyc_translations import kyc_translation_service as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/kyc/i18n", tags=["kyc-i18n"])


def _require_supported(language: str) -> str:
    if not svc.is_supported(language):
        supported = ", ".join(svc.supported_locales())
        raise HTTPException(
            400,
            detail={
                "code": "unsupported_locale",
                "message": f"Language '{language}' is not supported. Supported: {supported}",
            },
        )
    return language


def _validate_key(key: str) -> str:
    if not key.startswith("kyc."):
        raise HTTPException(
            422, detail={"code": "validation_error", "message": "key must start with 'kyc.'"}
        )
    if len(key) > 500:
        raise HTTPException(
            422,
            detail={"code": "validation_error", "message": "key: ensure this value has at most 500 characters"},
        )
    return key


# ── User-facing endpoints ────────────────────────────────────────────


@router.get("/locales", response_model=KycSupportedLocalesOut)
async def get_supported_locales(
    session: dict = Depends(require_ui_session),
) -> dict:
    return {"default": svc.default_locale(), "locales": svc.locale_descriptors()}


@router.get("/translations/{language}", response_model=KycTranslationBundleOut)
async def get_bundle(
    language: str,
    prefix: Optional[str] = Query(None),
    request: Request = None,  # type: ignore[assignment]
    session: dict = Depends(require_ui_session),
) -> dict:
    effective = svc.normalize_locale(language)
    bundle = svc.get_bundle(language=effective, prefix=prefix, published_only=True)
    return {"language": effective, "rtl": svc.is_rtl(effective), "translations": bundle}


@router.get("/me/locale")
async def get_my_locale(
    request: Request,
    session: dict = Depends(require_ui_session),
) -> dict:
    accept = request.headers.get("accept-language") if request else None
    locale = svc.resolve_locale_for_user(session["user_sub"], accept_language=accept)
    return {"language": locale, "rtl": svc.is_rtl(locale)}


@router.get("/legal-notice/{version}", response_model=KycLocalizedLegalNoticeOut)
async def get_legal_notice(
    version: str,
    lang: str = Query("en"),
    session: dict = Depends(require_ui_session),
) -> dict:
    effective = svc.normalize_locale(lang)
    text, is_fallback = svc.localize_legal_notice(version=version, language=effective)
    return {
        "text": text,
        "language": effective,
        "version": version,
        "is_fallback": is_fallback,
        "rtl": svc.is_rtl(effective),
    }


@router.post("/questionnaire/localized", response_model=KycLocalizedQuestionnaireOut)
async def localize_questionnaire(
    body: Dict[str, Any],
    lang: str = Query("en"),
    session: dict = Depends(require_ui_session),
) -> dict:
    """Localize a questionnaire payload (title/description/questions) to a locale.

    The questionnaire object is supplied in the request body under
    ``questionnaire``; KYC-013's wizard passes the English template through to
    receive localized labels.
    """
    questionnaire = body.get("questionnaire") if isinstance(body, dict) else None
    if not isinstance(questionnaire, dict):
        raise HTTPException(
            422,
            detail={"code": "validation_error", "message": "questionnaire object is required"},
        )
    effective = svc.normalize_locale(lang)
    localized, fallback_keys = svc.localize_questionnaire(
        questionnaire=questionnaire, language=effective
    )
    return {
        "questionnaire": localized,
        "language": effective,
        "rtl": svc.is_rtl(effective),
        "fallback_keys": fallback_keys,
    }


# ── Admin endpoints ──────────────────────────────────────────────────


@router.get("/admin/translations/{language}", response_model=KycTranslationListOut)
async def admin_list_translations(
    language: str,
    prefix: Optional[str] = Query(None),
    status: Optional[str] = Query(None, pattern=r"^(published|draft|needs_review)$"),
    limit: int = Query(100, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_supported(language)
    items = svc.list_translations(language=language, prefix=prefix, status=status, limit=limit)
    coverage = svc.get_translation_coverage(language=language)
    return {"items": items, "coverage": coverage, "total": len(items)}


@router.put("/admin/translations/{language}/{key:path}", response_model=KycTranslationOut)
async def admin_set_translation(
    language: str,
    key: str,
    body: KycTranslationIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_supported(language)
    _validate_key(key)
    return svc.set_translation(
        key=key,
        language=language,
        value=body.value,
        context=body.context,
        status=body.status,
        admin_sub=user.sub,
    )


@router.delete("/admin/translations/{language}/{key:path}")
async def admin_delete_translation(
    language: str,
    key: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_supported(language)
    svc.delete_translation(key=key, language=language, admin_sub=user.sub)
    return {"ok": True}


@router.get("/admin/coverage", response_model=KycCoverageReportOut)
async def admin_coverage(
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return svc.coverage_report()


@router.post(
    "/admin/translations/{language}/bulk-import", response_model=KycTranslationBulkImportOut
)
async def admin_bulk_import(
    language: str,
    body: KycTranslationBulkImportIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_supported(language)
    return svc.bulk_import(
        language=language,
        translations=body.translations,
        status=body.status,
        admin_sub=user.sub,
    )


@router.get("/admin/translations/{language}/export", response_model=KycTranslationExportOut)
async def admin_export(
    language: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_supported(language)
    return {"language": language, "translations": svc.export_language(language=language)}
