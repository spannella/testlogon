"""
Backend i18n module for PLATFORM-003.

Provides a simple `translate()` function backed by JSON files and a
`get_user_locale()` helper that resolves the best locale for the current
request (profile > Accept-Language > fallback).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from app.core.settings import S

logger = logging.getLogger(__name__)

_translations: Dict[str, Dict[str, str]] = {}
_TRANSLATIONS_DIR = Path(__file__).parent / "translations"


def _load_translations() -> None:
    """Load all translation JSON files at module import time."""
    for path in _TRANSLATIONS_DIR.glob("*.json"):
        locale = path.stem
        try:
            with open(path) as f:
                _translations[locale] = json.load(f)
        except Exception:
            logger.warning("Failed to load translations for locale %s", locale)


# Load translations eagerly on import
_load_translations()


def translate(key: str, locale: str = "en", **kwargs: Any) -> str:
    """Look up a translation key for the given locale.

    Falls back to English if the key is missing in the requested locale.
    Supports interpolation: translate("errors.rate_limited", "es", seconds=30)
    """
    strings = _translations.get(locale, _translations.get("en", {}))
    template = strings.get(key) or _translations.get("en", {}).get(key) or key
    try:
        return template.format(**kwargs) if kwargs else template
    except (KeyError, IndexError):
        return template


def get_supported_locales() -> list[str]:
    """Return list of supported locale codes from settings."""
    return [loc.strip() for loc in S.i18n_supported_locales.split(",") if loc.strip()]


def is_supported_locale(locale: str) -> bool:
    """Check if a locale code is in the supported list."""
    return locale in get_supported_locales()


def get_user_locale_from_request(request: Any) -> str:
    """Extract the best locale from the request.

    Priority: user profile locale > Accept-Language header > default.
    """
    # Check if auth context has locale set
    ctx = getattr(request.state, "auth_context", None)
    if ctx and isinstance(ctx, dict) and ctx.get("locale"):
        locale = ctx["locale"]
        if is_supported_locale(locale):
            return locale

    # Parse Accept-Language header
    accept = request.headers.get("accept-language", "")
    if accept:
        # Take the first language tag
        primary = accept.split(",")[0].split(";")[0].strip().split("-")[0]
        if is_supported_locale(primary):
            return primary

    return S.i18n_default_locale


# Locale metadata for the public /ui/i18n/locales endpoint
LOCALE_METADATA = [
    {"code": "en", "name": "English", "native_name": "English", "rtl": False},
    {"code": "es", "name": "Spanish", "native_name": "Español", "rtl": False},
    {"code": "fr", "name": "French", "native_name": "Français", "rtl": False},
]
