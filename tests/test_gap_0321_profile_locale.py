"""GAP-0321 lock-in regression: profile `locale` field + validation.

Verify-only lock-in (the feature is already built):
- `locale` exists on ProfileBase / ProfilePatchReq / ProfilePutReq.
- `"locale"` is in PROFILE_FIELDS with visibility "private".
- `normalize_profile_payload` passes through a SUPPORTED locale and raises
  HTTPException(400) for an UNSUPPORTED (non-empty) locale, validated against
  `S.i18n_supported_locales`.

Offline / pure: no AWS, no moto — `normalize_profile_payload` is pure normalization.
"""

import pytest
from fastapi import HTTPException

from app.core.settings import S
from app.models import ProfileBase, ProfilePatchReq, ProfilePutReq
from app.services.profile import (
    PROFILE_FIELDS,
    PROFILE_FIELD_VISIBILITY,
    normalize_profile_payload,
)


def test_locale_field_on_profile_models():
    # Each model accepts a `locale` field.
    for model in (ProfileBase, ProfilePatchReq, ProfilePutReq):
        assert "locale" in model.model_fields
        inst = model(locale="en")
        assert inst.locale == "en"


def test_locale_in_profile_fields_private_visibility():
    assert "locale" in PROFILE_FIELDS
    assert PROFILE_FIELD_VISIBILITY["locale"] == "private"


def test_normalize_accepts_supported_locale():
    supported = [
        loc.strip()
        for loc in S.i18n_supported_locales.split(",")
        if loc.strip()
    ]
    assert supported, "expected at least one supported locale in settings"
    good = supported[0]
    out = normalize_profile_payload({"locale": good})
    assert out["locale"] == good


def test_normalize_rejects_unsupported_locale():
    # Make the supported set deterministic for this assertion. S is frozen.
    original = S.i18n_supported_locales
    object.__setattr__(S, "i18n_supported_locales", "en,es,fr")
    try:
        with pytest.raises(HTTPException) as exc:
            normalize_profile_payload({"locale": "xx-INVALID"})
        assert exc.value.status_code == 400
        # Supported value still passes through under the same setting.
        out = normalize_profile_payload({"locale": "es"})
        assert out["locale"] == "es"
    finally:
        object.__setattr__(S, "i18n_supported_locales", original)


def test_normalize_empty_locale_is_none():
    # Empty/whitespace locale is cleaned to None and skips the supported check.
    out = normalize_profile_payload({"locale": "   "})
    assert out["locale"] is None
