from __future__ import annotations

import base64
import json
from functools import lru_cache
from typing import Any, Dict, Optional

import jwt
import requests
from fastapi import HTTPException, Request

from app.core.settings import S


def _cognito_enabled() -> bool:
    return bool(S.cognito_user_pool_id and S.cognito_app_client_id)


def _cognito_issuer() -> str:
    region = S.cognito_region or S.aws_region
    return f"https://cognito-idp.{region}.amazonaws.com/{S.cognito_user_pool_id}"


@lru_cache(maxsize=1)
def _cognito_jwks() -> Dict[str, Any]:
    url = f"{_cognito_issuer()}/.well-known/jwks.json"
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _resolve_cognito_key(kid: str) -> Dict[str, Any]:
    keys = _cognito_jwks().get("keys", [])
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


def _decode_jwt_sub(token: str) -> Optional[str]:
    if token.count(".") != 2:
        return None
    _, payload, _ = token.split(".", 2)
    if not payload:
        return None
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    sub = data.get("sub")
    return sub if isinstance(sub, str) and sub.strip() else None


def extract_bearer_token(auth_header: Optional[str]) -> str:
    if not auth_header:
        raise HTTPException(401, "Missing Authorization header")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "Invalid Authorization header")
    return token.strip()


async def get_authenticated_user_sub(request: Request) -> str:
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
        return str(user_sub)

    fallback_user = request.headers.get("x-user-sub")
    if fallback_user:
        return fallback_user

    auth = request.headers.get("authorization", "")
    token = extract_bearer_token(auth)
    return _decode_jwt_sub(token) or token
