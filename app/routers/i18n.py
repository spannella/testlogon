"""
Router for i18n / locale endpoints (PLATFORM-003).

Public endpoints:
  GET  /ui/i18n/locales               — list available locales
  GET  /ui/i18n/translations/{locale}  — get all translations for a locale

Authenticated endpoints:
  GET  /ui/i18n/locale                 — get user's saved locale
  PUT  /ui/i18n/locale                 — save user's locale preference
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.i18n import (
    LOCALE_METADATA,
    get_supported_locales,
    is_supported_locale,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ui/i18n", tags=["i18n"])


# ── Public endpoints ───────────────────────────────────────────────


@router.get("/locales")
async def list_locales():
    """Return available locales with display names."""
    supported = get_supported_locales()
    locales = [loc for loc in LOCALE_METADATA if loc["code"] in supported]
    return {"locales": locales}


@router.get("/translations/{locale}")
async def get_translations(locale: str):
    """Return all translations for a given locale.

    Merges static JSON file translations with any admin-managed DDB overrides.
    Falls back to English for missing keys.
    """
    if not is_supported_locale(locale):
        raise HTTPException(400, "Unsupported locale")

    # Load static translations from the i18n module
    from app.i18n import _translations

    en_strings = _translations.get("en", {})
    locale_strings = _translations.get(locale, {})

    # Merge: locale overrides English
    merged = {**en_strings, **locale_strings}

    # Try to overlay admin-managed DDB translations (best-effort)
    try:
        resp = T.translations.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"LOCALE#{locale}"},
        )
        for item in resp.get("Items", []):
            sk = item.get("sk", "")
            if sk.startswith("KEY#"):
                key = sk[4:]
                value = item.get("value")
                if value:
                    merged[key] = value
    except Exception:
        # DDB translations table may not exist yet — fall back to static
        pass

    return {
        "locale": locale,
        "translations": merged,
    }


# ── Authenticated endpoints ────────────────────────────────────────


@router.get("/locale")
async def get_user_locale(ctx: Dict[str, Any] = Depends(require_ui_session)):
    """Return the authenticated user's locale preference from their profile."""
    user_sub = ctx["user_sub"]
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item")
    locale = None
    if item:
        profile = item.get("profile") or {}
        locale = profile.get("locale")
    return {"locale": locale or S.i18n_default_locale}


@router.put("/locale")
async def save_user_locale(
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Save the user's locale preference to their profile."""
    body = await request.json()
    locale = body.get("locale", "").strip()

    if not locale or not is_supported_locale(locale):
        raise HTTPException(400, "Invalid or unsupported locale")

    user_sub = ctx["user_sub"]

    # Update the profile item to include the locale field
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    profile = dict(item.get("profile") or {})
    profile["locale"] = locale

    T.profile.put_item(Item={
        **item,
        "user_sub": user_sub,
        "profile": profile,
        "updated_at": now_ts(),
    })

    return {"ok": True, "locale": locale}
