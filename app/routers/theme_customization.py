"""Per-user theme customization endpoints (PLATFORM-013).

Routes are mounted under the `/ui/theme` prefix and are self-scoped to the
authenticated UI session (each user reads/writes only their own theme).

    GET    /ui/theme            -> current theme config (defaults if unset)
    PATCH  /ui/theme            -> merge-update theme config, returns full config
    PUT    /ui/theme            -> alias of PATCH (full/partial replace-merge)
    DELETE /ui/theme            -> reset to defaults

Auth: `require_ui_session` (cookie session + CSRF for non-GET, per the
shared dependency). Bearer-token API clients are also accepted by the
dependency.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends

from app.models import ThemeConfigPatchReq, ThemeConfigResponse
from app.services.sessions import require_ui_session
from app.services import theme_customization

theme_customization_router = APIRouter(prefix="/ui/theme", tags=["theme-customization"])


@theme_customization_router.get("", response_model=ThemeConfigResponse)
def get_theme_customization(
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ThemeConfigResponse:
    user_sub = ctx["user_sub"]
    config = theme_customization.get_theme_config(user_sub)
    return ThemeConfigResponse(theme=config)


@theme_customization_router.patch("", response_model=ThemeConfigResponse)
def patch_theme_customization(
    body: ThemeConfigPatchReq,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ThemeConfigResponse:
    user_sub = ctx["user_sub"]
    patch = body.model_dump(exclude_none=True)
    config = theme_customization.save_theme_config(user_sub, patch)
    return ThemeConfigResponse(theme=config)


@theme_customization_router.put("", response_model=ThemeConfigResponse)
def put_theme_customization(
    body: ThemeConfigPatchReq,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ThemeConfigResponse:
    user_sub = ctx["user_sub"]
    patch = body.model_dump(exclude_none=True)
    config = theme_customization.save_theme_config(user_sub, patch)
    return ThemeConfigResponse(theme=config)


@theme_customization_router.delete("", response_model=ThemeConfigResponse)
def delete_theme_customization(
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ThemeConfigResponse:
    user_sub = ctx["user_sub"]
    config = theme_customization.reset_theme_config(user_sub)
    return ThemeConfigResponse(theme=config)
