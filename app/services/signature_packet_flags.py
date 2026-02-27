from __future__ import annotations

from app.core.settings import S


class SignaturePdfDisabledError(RuntimeError):
    """Raised when signature PDF functionality is disabled via feature flag."""


def signature_pdf_enabled() -> bool:
    return bool(getattr(S, "signature_pdf_enabled", False))


def require_signature_pdf_enabled() -> None:
    if signature_pdf_enabled():
        return
    raise SignaturePdfDisabledError("Signature PDF feature is disabled")
