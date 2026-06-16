"""OAU-003: OIDC discovery, JWKS, and /userinfo endpoints.

Registered in main.py when S.open_bank_project_enabled AND S.oauth_provider_enabled
AND S.oauth_provider_oidc_enabled.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.auth.deps import get_authenticated_user  # noqa: F401 — used as Depends
from app.core.settings import S
from app.core.tables import T
from app.services.oauth_oidc_keys import get_public_jwks

router = APIRouter(tags=["oidc"])


def _issuer_base() -> str:
    return (getattr(S, "oidc_issuer_url", "") or getattr(S, "public_base_url", "http://localhost:8000")).rstrip("/")


@router.get("/.well-known/openid-configuration")
async def openid_configuration() -> JSONResponse:
    """OIDC discovery document — no auth required."""
    from app.services.api_key_route_scope_registry import API_KEY_ROUTE_SCOPE_REGISTRY
    base = _issuer_base()
    scope_union: set = {"openid", "profile", "email", "offline_access"}
    for policy in API_KEY_ROUTE_SCOPE_REGISTRY.values():
        scope_union.update(policy.get("required_scopes", []))
    grant_types = ["authorization_code", "refresh_token"]
    if getattr(S, "oauth_provider_directlogin_enabled", False):
        grant_types.append("password")
    doc: Dict[str, Any] = {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "jwks_uri": f"{base}/oauth/jwks",
        "registration_endpoint": f"{base}/ui/oauth/consumers",
        "response_types_supported": ["code"],
        "grant_types_supported": grant_types,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": sorted(scope_union),
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time",
            "email", "email_verified", "name", "given_name", "family_name",
        ],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": f"{base}/docs",
    }
    return JSONResponse(content=doc, headers={"Cache-Control": "max-age=86400"})


@router.get("/oauth/jwks")
async def jwks() -> JSONResponse:
    """Public JSON Web Key Set — no auth required."""
    return JSONResponse(
        content=get_public_jwks(),
        headers={"Cache-Control": "max-age=3600, must-revalidate"},
    )


@router.get("/userinfo")
async def userinfo(request: Request, ctx=Depends(get_authenticated_user)) -> JSONResponse:
    """OIDC userinfo — requires an OAuth bearer token with openid scope."""
    state = getattr(request, "state", None)
    raw_scope = getattr(state, "oauth_scope", None)
    if raw_scope is None:
        raise HTTPException(401, {"code": "bearer_token_required", "message": "This endpoint requires an OAuth bearer token"})

    scope_set = set(raw_scope.split())
    if "openid" not in scope_set:
        raise HTTPException(403, {"code": "insufficient_scope", "message": "openid scope is required"})

    # Optionally re-check consumer enabled (OAU-005 enforcement)
    client_id = getattr(state, "oauth_client_id", "")
    if client_id:
        from app.services.oauth_consumers import get_consumer
        consumer = get_consumer(client_id)
        if consumer and not consumer.get("enabled", True):
            raise HTTPException(401, {"code": "oauth_consumer_disabled"})

    owner_sub = ctx.sub if hasattr(ctx, "sub") else ctx.get("user_sub", "")
    try:
        user_resp = T.users.get_item(Key={"user_sub": owner_sub})
        user_item = user_resp.get("Item") or {}
    except Exception:
        user_item = {}

    claims: Dict[str, Any] = {"sub": owner_sub}
    if "email" in scope_set:
        email = user_item.get("email")
        if email:
            claims["email"] = email
        claims["email_verified"] = bool(user_item.get("email_verified", False))
    if "profile" in scope_set:
        name = user_item.get("profile_name") or user_item.get("display_name") or user_item.get("name")
        if name:
            claims["name"] = name
        given = user_item.get("first_name") or user_item.get("given_name")
        if given:
            claims["given_name"] = given
        family = user_item.get("last_name") or user_item.get("family_name")
        if family:
            claims["family_name"] = family

    return JSONResponse(content=claims)
