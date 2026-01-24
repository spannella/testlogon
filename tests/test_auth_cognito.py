from __future__ import annotations

import asyncio
from typing import Any, Dict

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.auth import deps
from app.core.settings import S


def build_request(headers: Dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "scheme": "http",
        "server": ("testserver", 80),
    }

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def run_async(coro):
    return asyncio.run(coro)


def disable_cognito() -> None:
    object.__setattr__(S, "cognito_user_pool_id", "")
    object.__setattr__(S, "cognito_app_client_id", "")


def enable_cognito() -> None:
    object.__setattr__(S, "cognito_user_pool_id", "pool")
    object.__setattr__(S, "cognito_app_client_id", "client")
    object.__setattr__(S, "cognito_region", "us-east-1")


def test_auth_fallback_allows_x_user_sub() -> None:
    disable_cognito()
    req = build_request(headers={"x-user-sub": "user-123"})
    assert run_async(deps.get_authenticated_user_sub(req)) == "user-123"


def test_auth_requires_bearer_token_when_cognito_enabled() -> None:
    enable_cognito()
    req = build_request()
    with pytest.raises(HTTPException) as exc:
        run_async(deps.get_authenticated_user_sub(req))
    assert exc.value.status_code == 401


def test_auth_uses_cognito_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    enable_cognito()

    def fake_decode(token: str) -> Dict[str, Any]:
        assert token == "token123"
        return {"sub": "user-abc"}

    monkeypatch.setattr(deps, "_decode_cognito_token", fake_decode)
    req = build_request(headers={"authorization": "Bearer token123"})
    assert run_async(deps.get_authenticated_user_sub(req)) == "user-abc"


def test_auth_requires_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    enable_cognito()
    monkeypatch.setattr(deps, "_decode_cognito_token", lambda token: {})
    req = build_request(headers={"authorization": "Bearer token123"})
    with pytest.raises(HTTPException) as exc:
        run_async(deps.get_authenticated_user_sub(req))
    assert exc.value.status_code == 401
