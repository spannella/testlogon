"""OAU-002: POST /oauth/token — token exchange, refresh, DirectLogin.

No session dependency — client authentication is done in-handler via client_secret.
Registered in main.py when S.open_bank_project_enabled AND S.oauth_provider_enabled.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse

from app.services.oauth_auth_flow import (
    directlogin_grant,
    exchange_code_for_tokens,
    refresh_access_token,
)

router = APIRouter(prefix="/oauth", tags=["oauth"])


@router.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(...),
    # authorization_code fields
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    # refresh_token fields
    refresh_token: Optional[str] = Form(None),
    # common optional
    client_secret: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    # DirectLogin
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
):
    """OAuth2 token endpoint. Supports authorization_code, refresh_token, password."""
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(400, {"error": "invalid_request", "error_description": "code is required"})
        if not redirect_uri:
            raise HTTPException(400, {"error": "invalid_request", "error_description": "redirect_uri is required"})
        if not code_verifier:
            raise HTTPException(400, {"error": "invalid_request", "error_description": "code_verifier is required"})
        result = exchange_code_for_tokens(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            client_secret=client_secret,
        )
        return JSONResponse(content=result)

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(400, {"error": "invalid_request", "error_description": "refresh_token is required"})
        result = refresh_access_token(
            client_id=client_id,
            refresh_token=refresh_token,
            client_secret=client_secret,
        )
        return JSONResponse(content=result)

    elif grant_type == "password":
        if not username or not password:
            raise HTTPException(400, {"error": "invalid_request", "error_description": "username and password are required"})
        if not client_secret:
            raise HTTPException(400, {"error": "invalid_client", "error_description": "client_secret required for DirectLogin"})
        result = directlogin_grant(
            client_id=client_id,
            username=username,
            password=password,
            client_secret=client_secret,
            scope=scope or "",
        )
        return JSONResponse(content=result)

    else:
        raise HTTPException(400, {"error": "unsupported_grant_type", "error_description": f"Unsupported grant_type: {grant_type}"})
