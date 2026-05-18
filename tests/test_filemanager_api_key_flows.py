from __future__ import annotations

import asyncio
from types import SimpleNamespace

from fastapi.routing import APIRoute
from starlette.requests import Request

from app.routers import filemanager
from app.services import api_key_policy_enforcement as policy


def _request(path: str = "/v1/fs/list", method: str = "GET", headers: dict[str, str] | None = None) -> Request:
    async def _endpoint():
        return {"ok": True}

    route = APIRoute(path=path, endpoint=_endpoint, methods=[method])
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in (headers or {}).items()],
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "scheme": "http",
        "route": route,
    }
    req = Request(scope)
    req.state.api_key_principal = {"user_sub": "owner-1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}
    return req


def test_current_user_prefers_api_key_principal_over_session(monkeypatch) -> None:
    req = _request()

    async def _require_ui_session(*_args, **_kwargs):
        raise AssertionError("session should not be queried for api-key requests")

    monkeypatch.setattr(filemanager, "require_ui_session", _require_ui_session)
    out = asyncio.run(filemanager._current_user(req, auth_user=None))
    assert out == "owner-1"


def test_current_user_falls_back_to_ui_session(monkeypatch) -> None:
    req = _request()
    req.state.api_key_principal = None

    async def _require_ui_session(*_args, **_kwargs):
        return {"user_sub": "session-user"}

    monkeypatch.setattr(filemanager, "require_ui_session", _require_ui_session)
    out = asyncio.run(filemanager._current_user(req, auth_user=None))
    assert out == "session-user"


def test_policy_enforcement_allows_filemanager_list_route_when_scope_present(monkeypatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})

    async def _principal(_request):
        return {"user_sub": "owner-1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    monkeypatch.setattr(policy, "require_api_key_principal", _principal)
    monkeypatch.setattr(policy.api_usage_entitlements, "enforce_api_package_entitlement_pre_request", lambda _request: {"x-api-entitlement-id": "e1"})
    asyncio.run(policy.maybe_enforce_api_key_route_policy(req))
    assert req.state.api_key_scope_decision["route_id"] == "GET:/v1/fs/list"
