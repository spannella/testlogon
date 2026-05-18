from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
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
from app.services.moderation_policy_engine import is_user_currently_banned

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


def _enforce_not_banned(*, user_sub: str, role: Role) -> None:
    if role in {Role.ROOT, Role.ADMIN}:
        return
    if is_user_currently_banned(user_sub):
        raise HTTPException(status_code=403, detail="account is banned")


def extract_bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(401, "Missing Authorization header")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "Invalid Authorization header")
    return token.strip()


def _extract_admin_profile_from_claims(claims: Dict[str, Any]) -> AdminProfile:
    return normalize_admin_profile(claims.get("admin_profile"))


def _verify_local_password(username: str, password: str) -> Optional[str]:
    """Verify username/password against the local DDB users table.

    Returns the user_sub on success, None on failure.  Deliberately swallows
    all exceptions so that a misconfigured table never leaks details.
    """
    from app.core.normalize import normalize_email
    from app.core.tables import T

    try:
        user_sub = normalize_email(username)
        item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
        if not item:
            return None
        ph = item.get("password_hash") or {}
        if not isinstance(ph, dict):
            return None
        stored_hash_b64 = ph.get("hash_b64", "")
        salt_b64 = ph.get("salt_b64", "")
        iterations = int(ph.get("iterations", 0) or 0)
        if not stored_hash_b64 or not salt_b64 or not iterations:
            return None
        salt = base64.b64decode(salt_b64)
        stored_hash = base64.b64decode(stored_hash_b64)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        if not _hmac.compare_digest(candidate, stored_hash):
            return None
        return user_sub
    except Exception:
        return None


async def get_authenticated_user(request: Request) -> AuthenticatedUser:
    """Resolve the authenticated user from the incoming request.

    Check order:
    1. HMAC-signed access token cookie (browser / cookie-based flow).
       Expiry is NOT enforced here so that the refresh endpoint can still
       identify the user with an expired token; require_ui_session handles it.
    2. Cognito JWT Bearer token (API clients / production SPA).
    3. Dev-mode fallbacks (x-user-sub header, bare Bearer token).
    """
    state = getattr(request, "state", None)
    principal = getattr(state, "api_key_principal", None) if state is not None else None
    if isinstance(principal, dict):
        user_sub = str(principal.get("user_sub") or "").strip()
        if user_sub:
            role = Role.USER
            try:
                from app.core.tables import T

                user_item = T.users.get_item(Key={"user_sub": user_sub}).get("Item") or {}
                role = normalize_role(user_item.get("role"))
            except Exception:
                role = Role.USER
            role = enforce_root_role_invariant(user_sub=user_sub, role=role)
            _enforce_not_banned(user_sub=user_sub, role=role)
            return AuthenticatedUser(sub=user_sub, role=role)

    # 1. Cookie-based path (browser flow)
    access_cookie_name = getattr(S, "ui_access_token_cookie_name", "")
    access_secret = getattr(S, "ui_access_token_secret", "")
    if access_cookie_name and access_secret:
        access_cookie = request.cookies.get(access_cookie_name, "")
        if access_cookie:
            try:
                payload = jwt.decode(
                    access_cookie,
                    access_secret,
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )
                user_sub = payload.get("sub")
                if user_sub:
                    role = _extract_role_from_claims(payload)
                    role = enforce_root_role_invariant(user_sub=str(user_sub), role=role)
                    admin_profile = _extract_admin_profile_from_claims(payload)
                    _enforce_not_banned(user_sub=str(user_sub), role=role)
                    return AuthenticatedUser(sub=str(user_sub), role=role, admin_profile=admin_profile)
            except jwt.PyJWTError:
                pass

    # 2. Cognito JWT Bearer token
    if _cognito_enabled():
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
        _enforce_not_banned(user_sub=str(user_sub), role=role)
        return AuthenticatedUser(sub=str(user_sub), role=role, admin_profile=admin_profile)

    # 3. Dev-mode fallbacks
    if not S.dev_mode:
        raise HTTPException(401, "Authentication not configured")

    fallback_user = request.headers.get("x-user-sub")
    if fallback_user:
        fallback_role = normalize_role(request.headers.get("x-user-role"))
        fallback_role = enforce_root_role_invariant(user_sub=fallback_user, role=fallback_role)
        fallback_admin_profile = normalize_admin_profile(request.headers.get("x-user-admin-profile"))
        _enforce_not_banned(user_sub=fallback_user, role=fallback_role)
        return AuthenticatedUser(sub=fallback_user, role=fallback_role, admin_profile=fallback_admin_profile)

    auth = request.headers.get("authorization", "")
    token = extract_bearer_token(auth)
    payload = _decode_jwt_payload(token)
    sub = payload.get("sub") if isinstance(payload.get("sub"), str) and payload.get("sub").strip() else token
    role = _extract_role_from_claims(payload)
    role = enforce_root_role_invariant(user_sub=sub, role=role)
    admin_profile = _extract_admin_profile_from_claims(payload)
    _enforce_not_banned(user_sub=sub, role=role)
    return AuthenticatedUser(sub=sub, role=role, admin_profile=admin_profile)


async def get_authenticated_user_sub(request: Request) -> str:
    user = await get_authenticated_user(request)
    return user.sub


async def get_authenticated_user_role(request: Request) -> Role:
    user = await get_authenticated_user(request)
    return user.role


async def resolve_dev_or_authenticated_user_sub(
    request: Request,
    body: UiSessionStartReq,
) -> str:
    if S.dev_mode:
        context = body.challenge_context or {}
        username = str(context.get("username") or "").strip()
        password = str(context.get("password") or "").strip()
        if username and password:
            # Legacy DEV_TEST_USER shortcut (if configured)
            if S.dev_test_user and username == S.dev_test_user and S.dev_test_password and password == S.dev_test_password:
                return S.dev_test_user
            # Verify against real DDB password hash
            user_sub = _verify_local_password(username, password)
            if user_sub:
                return user_sub
            raise HTTPException(401, "Invalid credentials")
    return await get_authenticated_user_sub(request)
