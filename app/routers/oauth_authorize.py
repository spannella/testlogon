"""OAU-002: GET /oauth/authorize — authorization-code + PKCE flow.

Registered in main.py when S.open_bank_project_enabled AND S.oauth_provider_enabled.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.services.sessions import require_ui_session
from app.services.oauth_auth_flow import _validate_requested_scopes, issue_auth_code
from app.services.oauth_consumers import get_consumer

router = APIRouter(prefix="/oauth", tags=["oauth"])


@router.get("/authorize")
async def authorize(
    request: Request,
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    nonce: Optional[str] = None,
    ctx=Depends(require_ui_session),
):
    """OAuth2 authorization-code endpoint. Redirects to redirect_uri with code+state."""

    # ---- Fatal validations (return JSON 400, NOT redirect) ----
    consumer = get_consumer(client_id)
    if not consumer or not consumer.get("enabled"):
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Unknown or disabled client_id"})

    # Validate redirect_uri before using it
    stored_uris = consumer.get("redirect_uris", [])
    if redirect_uri not in stored_uris:
        raise HTTPException(
            400,
            {
                "error": "unauthorized_client",
                "error_description": "redirect_uri not registered for this client",
            },
        )
    parsed = urlparse(redirect_uri)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or "#" in redirect_uri:
        raise HTTPException(400, {"error": "invalid_request", "error_description": "Invalid redirect_uri"})

    # ---- Non-fatal validations (redirect with error) ----
    def _error_redirect(error: str, description: str) -> RedirectResponse:
        params = {"error": error, "error_description": description}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    if response_type != "code":
        return _error_redirect("unsupported_response_type", "Only response_type=code is supported")

    if code_challenge_method != "S256":
        return _error_redirect("invalid_request", "Only code_challenge_method=S256 is supported")

    if not consumer.get("is_confidential", True) and not code_challenge:
        return _error_redirect("invalid_request", "code_challenge is required for public clients")

    # Validate scope
    try:
        granted_scopes = _validate_requested_scopes(scope or "", consumer)
    except HTTPException:
        return _error_redirect("invalid_scope", f"Requested scope not permitted for this client: {scope}")

    if not granted_scopes:
        return _error_redirect("invalid_scope", "scope must not be empty")

    # Issue the code
    code = issue_auth_code(
        client_id=client_id,
        owner_user_sub=ctx["user_sub"],
        redirect_uri=redirect_uri,
        granted_scopes=granted_scopes,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
    )

    params: dict = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)
