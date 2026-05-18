from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from starlette.requests import Request

from app.services.api_key_authorization import requires_scope, requires_scope_for_request, requires_scope_for_request_from_registry


def _key(capabilities: list[str] | None = None) -> dict:
    item = {"key_id": "k1", "user_sub": "u1"}
    if capabilities is not None:
        item["capabilities"] = capabilities
    return item


def test_requires_scope_allows_when_key_has_scope() -> None:
    out = requires_scope(_key(["tickets:read", "newsfeed:read"]), ["tickets:read"])
    assert out["ok"] is True
    assert out["required_scopes"] == ["tickets:read"]


def test_requires_scope_allows_when_admin_scope_implies_required_scope() -> None:
    out = requires_scope(_key(["tickets:admin"]), ["tickets:write"])
    assert out["ok"] is True


def test_requires_scope_denies_with_missing_scope_reason() -> None:
    with pytest.raises(HTTPException) as exc:
        requires_scope(_key(["tickets:read"]), ["tickets:write"])
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "api_key_scope_denied"
    assert exc.value.detail["reason"] == "missing_scope"
    assert exc.value.detail["missing_scopes"] == ["tickets:write"]


def test_requires_scope_denies_unmapped_route_when_required_scope_missing() -> None:
    with pytest.raises(HTTPException) as exc:
        requires_scope(_key(["tickets:read"]), [])
    assert exc.value.status_code == 403
    assert exc.value.detail["reason"] == "unmapped_route"


def test_requires_scope_applies_legacy_fallback_for_keys_without_capabilities() -> None:
    out = requires_scope(_key(capabilities=None), ["tickets:read"])
    assert out["ok"] is True


def test_requires_scope_distinguishes_missing_entitlement_reason() -> None:
    def _gate(_request, _item, _required):
        return {"allowed": False, "reason": "no_subscription"}

    with pytest.raises(HTTPException) as exc:
        requires_scope(_key(["tickets:read"]), ["tickets:read"], entitlement_gate=_gate)

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "api_key_scope_denied"
    assert exc.value.detail["reason"] == "missing_entitlement"
    assert exc.value.detail["entitlement"]["reason"] == "no_subscription"


def test_requires_scope_allows_when_entitlement_gate_passes() -> None:
    def _gate(_request, _item, _required):
        return {"allowed": True, "entitlement_id": "e1"}

    out = requires_scope(_key(["tickets:read"]), ["tickets:read"], entitlement_gate=_gate)
    assert out["entitlement"]["entitlement_id"] == "e1"


def _request(path: str, method: str = "GET") -> Request:
    async def _endpoint():
        return {"ok": True}

    route = APIRoute(path=path, endpoint=_endpoint, methods=[method])
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "scheme": "http",
        "route": route,
    }
    return Request(scope)


@pytest.mark.parametrize(
    "path,method,required_scope",
    [
        ("/v1/files", "GET", "filemanager:read"),
        ("/v1/newsfeed/posts", "POST", "newsfeed:write"),
        ("/v1/tickets", "GET", "tickets:read"),
        ("/v1/cart/checkout", "POST", "shopping:checkout:write"),
        ("/v1/messages", "POST", "messager:write"),
    ],
)
def test_requires_scope_for_request_supports_route_method_scope_resolution(path: str, method: str, required_scope: str) -> None:
    req = _request(path, method)

    def _resolver(route_id: str):
        return {
            "GET:/v1/files": ["filemanager:read"],
            "POST:/v1/newsfeed/posts": ["newsfeed:write"],
            "GET:/v1/tickets": ["tickets:read"],
            "POST:/v1/cart/checkout": ["shopping:checkout:write"],
            "POST:/v1/messages": ["messager:write"],
        }.get(route_id, [])

    out = requires_scope_for_request(req, _key([required_scope]), resolve_required_scopes=_resolver)
    assert out["route_id"] == f"{method}:{path}"
    assert out["required_scopes"] == [required_scope]


def test_requires_scope_for_request_denies_when_scope_missing() -> None:
    req = _request("/v1/files", "GET")
    with pytest.raises(HTTPException) as exc:
        requires_scope_for_request(req, _key(["newsfeed:read"]), resolve_required_scopes=lambda _route_id: ["filemanager:read"])
    assert exc.value.detail["reason"] == "missing_scope"


def test_requires_scope_for_request_denies_when_entitlement_gate_fails() -> None:
    req = _request("/v1/files", "GET")

    def _gate(_request, _item, _required):
        return {"allowed": False, "reason": "missing_plan"}

    with pytest.raises(HTTPException) as exc:
        requires_scope_for_request(
            req,
            _key(["filemanager:read"]),
            resolve_required_scopes=lambda _route_id: ["filemanager:read"],
            entitlement_gate=_gate,
        )
    assert exc.value.detail["reason"] == "missing_entitlement"


def test_requires_scope_for_request_from_registry_uses_central_mapping() -> None:
    req = _request("/v1/files", "GET")
    out = requires_scope_for_request_from_registry(req, _key(["filemanager:read"]))
    assert out["route_id"] == "GET:/v1/files"
    assert out["required_scopes"] == ["filemanager:read"]
