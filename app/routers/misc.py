from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.root_invariant import validate_root_user_sub_config
from app.core.crypto import mint_ws_token
from app.models import TokenRefreshReq, TokenRefreshResp
from app.services.cognito import cognito_refresh_tokens
from app.services.sessions import require_ui_session

router = APIRouter(tags=["misc"])

@router.get("/ui/ws_token")
async def ui_ws_token(ctx=Depends(require_ui_session)):
    return {"token": mint_ws_token(ctx["user_sub"], ttl_seconds=120)}

@router.get("/api/ping")
async def ping():
    root_user_sub = validate_root_user_sub_config()
    return {"ok": True, "root_user_sub": root_user_sub}

@router.post("/ui/token/refresh", response_model=TokenRefreshResp)
async def ui_refresh_token(req: Request, body: TokenRefreshReq):
    refresh_token = body.refresh_token or req.cookies.get("refresh_token", "")
    if not refresh_token:
        raise HTTPException(400, "Missing refresh token")
    result = cognito_refresh_tokens(refresh_token)
    return TokenRefreshResp(
        access_token=result.get("AccessToken", ""),
        id_token=result.get("IdToken"),
        expires_in=result.get("ExpiresIn"),
    )
