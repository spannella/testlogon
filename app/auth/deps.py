from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import time
import contextvars
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
    # Tenant the identity was resolved under (GAP-0171 / ENTERPRISE-001).
    # Defaults to "default" so legacy JWTs/sessions and single-tenant dev
    # deployments (where no request tenant is present) keep working.
    tenant_id: str = "default"


def _request_tenant_id(request: Request) -> str:
    """Best-effort read of the request's resolved tenant.

    Returns ``"default"`` when ``TenantMiddleware`` has not populated
    ``request.state.tenant_id`` (single-tenant dev, or unit-test requests
    that bypass the middleware). Never raises.
    """
    state = getattr(request, "state", None)
    return str(getattr(state, "tenant_id", None) or "default")


# MODX-13: appeals must be reachable BY the very users an enforcement concerns
# (banned/suspended). This context flag lets an explicit appeals dependency
# (``require_appellant``) authenticate a banned principal WITHOUT the global
# ban gate 403ing them out of their own due-process channel. It is set only for
# the narrow appeals surface and always reset in a finally, so no other route
# can ever admit a banned user.
_allow_banned_appellant: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "allow_banned_appellant", default=False
)


def _enforce_not_banned(*, user_sub: str, role: Role) -> None:
    if role in {Role.ROOT, Role.ADMIN}:
        return
    if _allow_banned_appellant.get():
        # MODX-13: appellant lane -- do not 403 a banned user out of appeals.
        return
    if is_user_currently_banned(user_sub):
        raise HTTPException(status_code=403, detail="account is banned")


async def require_appellant(request: Request) -> "AuthenticatedUser":
    """MODX-13: authenticate the caller for the APPEALS surface only, exempting
    them from the ban gate so a banned/suspended user can reach + submit an appeal
    (and read their own enforcement history to fill the form). Identity resolution
    is otherwise identical to ``get_authenticated_user``; the exemption is scoped to
    this call via a context flag that is always reset."""
    token = _allow_banned_appellant.set(True)
    try:
        return await get_authenticated_user(request)
    finally:
        _allow_banned_appellant.reset(token)


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


def _try_oauth_bearer(request: Request):
    """OAU-002: Try to authenticate via an OAuth2 HS256 Bearer token.

    Returns AuthenticatedUser if the token is a valid OAU-002 access token,
    raises HTTPException for expired/disabled tokens, or returns None to fall
    through to the next auth path.
    """
    if not (getattr(S, "oauth_provider_enabled", False) and getattr(S, "open_bank_project_enabled", False)):
        return None
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    candidate = auth_header.split(" ", 1)[1].strip()
    access_secret = getattr(S, "ui_access_token_secret", "")
    if not access_secret:
        return None
    oau_payload = None
    try:
        oau_payload = jwt.decode(
            candidate,
            access_secret,
            algorithms=["HS256"],
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "oauth_token_expired")
    except jwt.PyJWTError:
        return None
    if not isinstance(oau_payload, dict):
        return None
    if oau_payload.get("token_type") != "access" or not oau_payload.get("client_id"):
        return None
    owner_sub = str(oau_payload.get("sub") or "").strip()
    client_id = str(oau_payload.get("client_id") or "").strip()
    if not owner_sub or not client_id:
        raise HTTPException(401, "invalid_oauth_token")
    # Re-check consumer enabled (OAU-005: disable kills existing tokens instantly)
    try:
        from app.services.oauth_consumers import get_consumer as _gc
        _consumer = _gc(client_id)
        if not _consumer or not _consumer.get("enabled"):
            raise HTTPException(401, "oauth_consumer_disabled")
    except HTTPException:
        raise
    except Exception:
        pass
    role = Role.USER
    try:
        _u_item = T.users.get_item(Key={"user_sub": owner_sub}).get("Item") or {}
        role = normalize_role(_u_item.get("role"))
    except Exception:
        role = Role.USER
    role = enforce_root_role_invariant(user_sub=owner_sub, role=role)
    _enforce_not_banned(user_sub=owner_sub, role=role)
    request.state.oauth_scope = str(oau_payload.get("scope") or "")
    request.state.oauth_client_id = client_id
    request.state.oauth_user_sub = owner_sub
    return AuthenticatedUser(sub=owner_sub, role=role, tenant_id=_request_tenant_id(request))


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
    # APIK-E0-4 (FAIL-CLOSED): only bridge an api-key principal to the owner identity when
    # the route explicitly admitted the key via maybe_enforce_api_key_route_policy (which
    # sets api_key_route_authorized after a scope/shadow decision). The global
    # _api_key_principal_middleware injects the principal on ALL routers; without this gate
    # an un-gated/session-only router would grant unscoped owner access (the prod over-scope
    # hole). No marker -> fall through to cookie/bearer auth -> 401.
    _route_authorized = bool(getattr(state, "api_key_route_authorized", False)) if state is not None else False
    if isinstance(principal, dict) and _route_authorized:
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
            return AuthenticatedUser(sub=user_sub, role=role, tenant_id=_request_tenant_id(request))

    # OAU-002: OAuth2 Bearer token branch (HS256 access tokens issued by /oauth/token)
    # Inserted AFTER api_key_principal check and BEFORE cookie/Cognito paths.
    _oau_result = _try_oauth_bearer(request)
    if _oau_result is not None:
        return _oau_result

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
                    return AuthenticatedUser(
                        sub=str(user_sub),
                        role=role,
                        admin_profile=admin_profile,
                        tenant_id=_request_tenant_id(request),
                    )
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
        return AuthenticatedUser(
            sub=str(user_sub),
            role=role,
            admin_profile=admin_profile,
            tenant_id=_request_tenant_id(request),
        )

    # 3. Dev-mode fallbacks
    if not S.dev_mode:
        raise HTTPException(401, "Authentication not configured")

    fallback_user = request.headers.get("x-user-sub")
    if fallback_user:
        fallback_role = normalize_role(request.headers.get("x-user-role"))
        fallback_role = enforce_root_role_invariant(user_sub=fallback_user, role=fallback_role)
        fallback_admin_profile = normalize_admin_profile(request.headers.get("x-user-admin-profile"))
        _enforce_not_banned(user_sub=fallback_user, role=fallback_role)
        return AuthenticatedUser(
            sub=fallback_user,
            role=fallback_role,
            admin_profile=fallback_admin_profile,
            tenant_id=_request_tenant_id(request),
        )

    auth = request.headers.get("authorization", "")
    token = extract_bearer_token(auth)
    payload = _decode_jwt_payload(token)
    sub = payload.get("sub") if isinstance(payload.get("sub"), str) and payload.get("sub").strip() else token
    role = _extract_role_from_claims(payload)
    role = enforce_root_role_invariant(user_sub=sub, role=role)
    admin_profile = _extract_admin_profile_from_claims(payload)
    _enforce_not_banned(user_sub=sub, role=role)
    return AuthenticatedUser(
        sub=sub,
        role=role,
        admin_profile=admin_profile,
        tenant_id=_request_tenant_id(request),
    )


async def require_root_session(request: Request) -> AuthenticatedUser:
    """Require that the caller has ROOT role. Raises 403 otherwise."""
    user = await get_authenticated_user(request)
    if user.role != Role.ROOT:
        raise HTTPException(403, "Root access required")
    return user


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


def require_kyc_tier(minimum_tier: int):
    """FastAPI dependency factory that enforces a minimum KYC tier."""

    async def _check(request: Request):
        # GAP-0268: router-level enforcement is gated behind a dedicated flag that
        # defaults OFF. When disabled, this dependency is a pure pass-through so that
        # existing tier-0 users (dev/E2E) are never blocked. The broader
        # kyc_tier_gating_enabled flag must also be on for tier values to be read
        # from DDB (otherwise get_user_kyc_tier returns KYC_TIER_MAX and all pass).
        if not (S.kyc_tier_enforcement_enabled and S.kyc_tier_gating_enabled):
            return  # Feature flag: skip tier check when disabled
        from app.services.kyc_tiers import get_user_kyc_tier, KYC_TIER_NAMES
        user = await get_authenticated_user(request)
        tier = get_user_kyc_tier(user.sub)
        if tier < minimum_tier:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "kyc_tier_insufficient",
                    "message": f"This action requires {KYC_TIER_NAMES.get(minimum_tier, f'Tier {minimum_tier}')} verification",
                    "current_tier": tier,
                    "required_tier": minimum_tier,
                    "upgrade_url": "/kyc",
                },
            )
        return user

    return _check
