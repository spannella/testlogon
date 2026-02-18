from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import jwt
import requests
from fastapi import HTTPException, Request

from app.auth.roles import AdminProfile, Role, normalize_admin_profile, normalize_role
from app.auth.root_invariant import enforce_root_role_invariant
from app.core.settings import S
from app.models import UiSessionStartReq

_JWKS_CACHE: Optional[Dict[str, Any]] = None
_JWKS_FETCHED_AT: float = 0.0


def _cognito_enabled() -> bool:
    return bool(S.cognito_user_pool_id and S.cognito_app_client_id)


def _cognito_issuer() -> str:
    if S.cognito_issuer_url:
        return S.cognito_issuer_url.rstrip("/")
    region = S.cognito_region or S.aws_region
    return f"https://cognito-idp.{region}.amazonaws.com/{S.cognito_user_pool_id}"


def _fetch_cognito_jwks() -> Tuple[Dict[str, Any], float]:
    url = S.cognito_jwks_url or f"{_cognito_issuer()}/.well-known/jwks.json"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json(), time.time()


def _cognito_jwks(*, force_refresh: bool = False) -> Dict[str, Any]:
    global _JWKS_CACHE, _JWKS_FETCHED_AT
    ttl = max(0, int(S.cognito_jwks_ttl_seconds))
    now = time.time()
    is_stale = not _JWKS_CACHE or (ttl and (now - _JWKS_FETCHED_AT) >= ttl)
    if force_refresh or is_stale:
        _JWKS_CACHE, _JWKS_FETCHED_AT = _fetch_cognito_jwks()
    return _JWKS_CACHE or {}


def _resolve_cognito_key(kid: str) -> Dict[str, Any]:
    keys = _cognito_jwks().get("keys", [])
    for key in keys:
        if key.get("kid") == kid:
            return key
    keys = _cognito_jwks(force_refresh=True).get("keys", [])
    for key in keys:
        if key.get("kid") == kid:
            return key
    raise HTTPException(401, "Unknown Cognito key id")


def _decode_cognito_token(token: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid token header") from exc

    key = _resolve_cognito_key(header.get("kid", ""))
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=S.cognito_app_client_id,
            issuer=_cognito_issuer(),
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(401, "Token expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid token") from exc

    expected_use = S.cognito_expected_token_use
    token_use = payload.get("token_use")
    if expected_use and token_use != expected_use:
        raise HTTPException(401, "Unexpected token use")

    return payload


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    if token.count(".") != 2:
        return {}
    _, payload, _ = token.split(".", 2)
    if not payload:
        return {}
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _extract_role_from_claims(claims: Dict[str, Any]) -> Role:
    role = claims.get("role")
    if role is not None:
        return normalize_role(role)

    roles = claims.get("roles")
    if isinstance(roles, list):
        for candidate in roles:
            normalized = normalize_role(candidate)
            if normalized is Role.ROOT:
                return Role.ROOT
            if normalized is Role.ADMIN:
                return Role.ADMIN
    return Role.USER


@dataclass(frozen=True)
class AuthenticatedUser:
    sub: str
    role: Role = Role.USER
    admin_profile: AdminProfile = AdminProfile()


def extract_bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(401, "Missing Authorization header")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "Invalid Authorization header")
    return token.strip()


async def get_authenticated_user_sub(request: Request) -> str:
    user = await get_authenticated_user(request)
    return user.sub


async def get_authenticated_user_role(request: Request) -> Role:
    user = await get_authenticated_user(request)
    return user.role


def _extract_admin_profile_from_claims(claims: Dict[str, Any]) -> AdminProfile:
    return normalize_admin_profile(claims.get("admin_profile"))


async def get_authenticated_user(request: Request) -> AuthenticatedUser:
    """
    Wire this into your real authentication (Cognito JWT validation, cookies, etc.)

    Dev fallback: Authorization: Bearer <user_id>
    """
    if _cognito_enabled() and isinstance(request, Request):
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise HTTPException(401, "Missing bearer token")
        token = auth_header.split(" ", 1)[1].strip()
        payload = _decode_cognito_token(token)
        user_sub = payload.get("sub") or payload.get("cognito:username") or payload.get("username")
        if not user_sub:
            raise HTTPException(401, "Token missing subject")
        role = _extract_role_from_claims(payload)
        role = enforce_root_role_invariant(user_sub=str(user_sub), role=role)
        admin_profile = _extract_admin_profile_from_claims(payload)
        return AuthenticatedUser(sub=str(user_sub), role=role, admin_profile=admin_profile)

    if not S.dev_mode:
        raise HTTPException(401, "Authentication not configured")

    fallback_user = request.headers.get("x-user-sub")
    if fallback_user:
        fallback_role = normalize_role(request.headers.get("x-user-role"))
        fallback_role = enforce_root_role_invariant(user_sub=fallback_user, role=fallback_role)
        fallback_admin_profile = normalize_admin_profile(request.headers.get("x-user-admin-profile"))
        return AuthenticatedUser(sub=fallback_user, role=fallback_role, admin_profile=fallback_admin_profile)

    auth = request.headers.get("authorization", "")
    token = extract_bearer_token(auth)
    payload = _decode_jwt_payload(token)
    sub = payload.get("sub") if isinstance(payload.get("sub"), str) and payload.get("sub").strip() else token
    role = _extract_role_from_claims(payload)
    role = enforce_root_role_invariant(user_sub=sub, role=role)
    admin_profile = _extract_admin_profile_from_claims(payload)
    return AuthenticatedUser(sub=sub, role=role, admin_profile=admin_profile)


async def resolve_dev_or_authenticated_user_sub(
    request: Request,
    body: UiSessionStartReq,
) -> str:
    if S.dev_mode and S.dev_test_user and S.dev_test_password:
        context = body.challenge_context or {}
        username = context.get("username")
        password = context.get("password")
        if username == S.dev_test_user and password == S.dev_test_password:
            return S.dev_test_user
    return await get_authenticated_user_sub(request)
