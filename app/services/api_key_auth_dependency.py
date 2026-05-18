from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

from app.services import api_keys
from app.services.api_key_error_contract import build_api_key_error_detail


def _extract_api_key_raw(request: Request) -> str:
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("apikey "):
        return auth.split(" ", 1)[1].strip()
    return (request.headers.get("x-api-key") or request.headers.get("x-api_key") or "").strip()


def _client_ip(request: Request) -> str:
    client = getattr(request, "client", None)
    host = getattr(client, "host", "") if client is not None else ""
    normalized = (host or "0.0.0.0").strip()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if "%" in normalized:
        # strip optional IPv6 zone id suffix
        normalized = normalized.split("%", 1)[0]
    return normalized or "0.0.0.0"


def _unauthorized(request: Request) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=build_api_key_error_detail(
            code="api_key_invalid",
            reason="invalid_key",
            message="Invalid API key",
            request=request,
        ),
    )


def _origin_denied(request: Request, *, api_key_id: str = "") -> HTTPException:
    return HTTPException(
        status_code=403,
        detail=build_api_key_error_detail(
            code="api_key_origin_denied",
            reason="origin_denied",
            message="API key not allowed from this origin",
            request=request,
            api_key_id=api_key_id,
        ),
    )


async def require_api_key_principal(request: Request) -> Dict[str, Any]:
    raw_key = _extract_api_key_raw(request)
    if not raw_key:
        raise _unauthorized(request)

    try:
        parsed = api_keys.parse_api_key(raw_key)
        item = api_keys.check_api_key_allowed(parsed["key_id"], parsed["secret"], _client_ip(request))
    except HTTPException as exc:
        if exc.status_code == 401:
            raise _unauthorized(request)
        if exc.status_code == 403:
            key_id = ""
            try:
                key_id = str(parsed.get("key_id") or "")
            except Exception:
                key_id = ""
            raise _origin_denied(request, api_key_id=key_id)
        raise

    principal = {
        "auth_type": "api_key",
        "user_sub": str(item.get("user_sub") or ""),
        "api_key_id": str(item.get("key_id") or parsed["key_id"]),
        "capabilities": api_keys.effective_api_key_capabilities(item),
    }
    request.state.api_key_principal = principal
    request.state.authenticated_principal = principal
    return principal


def get_api_key_principal(request: Request) -> Optional[Dict[str, Any]]:
    principal = getattr(request.state, "api_key_principal", None)
    return principal if isinstance(principal, dict) else None
