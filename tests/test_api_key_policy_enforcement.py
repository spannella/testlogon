from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.services import api_key_policy_enforcement as svc


def _request(*, path: str = "/v1/files", method: str = "GET", headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(k.lower().encode("utf-8"), v.encode("utf-8")) for k, v in (headers or {}).items()],
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
        "scheme": "http",
        "route": type("Route", (), {"path": path})(),
    }
    return Request(scope)


def test_policy_enforcement_noops_without_api_key_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"authorization": "Bearer token"})
    called = {"count": 0}

    async def _principal(_request):
        called["count"] += 1
        return {}

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))
    assert called["count"] == 0


def test_policy_enforcement_sets_scope_decision_on_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})
    metric_calls: list[dict[str, str]] = []

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "record_api_key_policy_decision", lambda **kwargs: metric_calls.append(kwargs))
    monkeypatch.setattr(
        svc,
        "requires_scope_for_request_from_registry",
        lambda *_args, **_kwargs: {"route_id": "GET:/v1/files", "entitlement": {"headers": {"x-api-entitlement-id": "e1"}}},
    )

    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))
    assert req.state.api_key_scope_decision["route_id"] == "GET:/v1/files"
    assert req.state.api_key_entitlement_headers["x-api-entitlement-id"] == "e1"
    assert metric_calls[0]["outcome"] == "allow"


def test_policy_enforcement_audits_scope_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})
    audit_calls: list[dict] = []

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    def _deny(*_args, **_kwargs):
        raise HTTPException(403, {"reason": "missing_scope"})

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "requires_scope_for_request_from_registry", _deny)
    monkeypatch.setattr(svc, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(svc, "audit_event", lambda _event, _user, _req, **fields: audit_calls.append(fields))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(svc.maybe_enforce_api_key_route_policy(req))

    assert exc.value.status_code == 403
    assert exc.value.detail["route_id"] == "GET:/v1/files"
    assert exc.value.detail["product"] == ""
    assert exc.value.detail["api_key_id"] == "k1"
    assert audit_calls[0]["reason"] == "missing_scope"


def test_entitlement_gate_returns_denied_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(svc, "is_entitlement_required_for_route", lambda route_id: True)

    def _entitlement(_request):
        raise HTTPException(403, {"code": "api_entitlement_denied"})

    monkeypatch.setattr(svc.api_usage_entitlements, "enforce_api_package_entitlement_pre_request", _entitlement)

    captured = {}

    def _requires(_request, _key_item, entitlement_gate=None):
        gate = entitlement_gate(_request, _key_item, ["filemanager:read"])
        captured.update(gate)
        return {"route_id": "GET:/v1/files", "entitlement": gate}

    monkeypatch.setattr(svc, "requires_scope_for_request_from_registry", _requires)
    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))
    assert captured["allowed"] is False
    assert captured["reason"] == "api_entitlement_denied"


def test_policy_shadow_mode_records_deny_without_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})
    audit_calls: list[dict] = []
    metric_calls: list[dict[str, str]] = []

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(svc, "get_route_scope_policy", lambda _rid: {"product": "filemanager"})
    monkeypatch.setattr(svc, "evaluate_api_key_rollout", lambda _product, _principal: {"product": "filemanager", "phase": "shadow", "enforce": False, "reason": "shadow_only"})

    def _deny(*_args, **_kwargs):
        raise HTTPException(403, {"reason": "missing_scope"})

    monkeypatch.setattr(svc, "requires_scope_for_request_from_registry", _deny)
    monkeypatch.setattr(svc, "audit_event", lambda _event, _user, _req, **fields: audit_calls.append(fields))
    monkeypatch.setattr(svc, "record_api_key_policy_decision", lambda **kwargs: metric_calls.append(kwargs))

    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))
    assert req.state.api_key_rollout_decision["phase"] == "shadow"
    assert req.state.api_key_shadow_error["reason"] == "missing_scope"
    assert audit_calls[0]["phase"] == "shadow"
    assert audit_calls[0]["outcome"] == "failure"
    assert metric_calls[0]["mode"] == "shadow"
    assert metric_calls[0]["outcome"] == "deny"


def test_policy_canary_mode_enforces_when_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(svc, "get_route_scope_policy", lambda _rid: {"product": "filemanager"})
    monkeypatch.setattr(svc, "evaluate_api_key_rollout", lambda _product, _principal: {"product": "filemanager", "phase": "canary", "enforce": True, "reason": "canary_match"})
    monkeypatch.setattr(
        svc,
        "requires_scope_for_request_from_registry",
        lambda *_args, **_kwargs: {"route_id": "GET:/v1/files", "entitlement": {"headers": {"x-api-entitlement-id": "e1"}}},
    )

    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))
    assert req.state.api_key_scope_decision["route_id"] == "GET:/v1/files"


def test_policy_dual_credentials_reject_mode_returns_400(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"authorization": "Bearer token", "x-api-key": "ak_k1.secret"})
    metric_calls: list[dict[str, str]] = []
    audit_calls: list[dict[str, str]] = []
    monkeypatch.setattr(svc, "S", SimpleNamespace(api_key_dual_credential_mode="reject"))
    monkeypatch.setattr(svc, "record_api_key_policy_decision", lambda **kwargs: metric_calls.append(kwargs))
    monkeypatch.setattr(svc, "audit_event", lambda _event, _user, _req, **fields: audit_calls.append(fields))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(svc.maybe_enforce_api_key_route_policy(req))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "api_key_dual_credential_conflict"
    assert exc.value.detail["reason"] == "dual_credential_conflict"
    assert metric_calls[0]["mode"] == "dual_credential"
    assert metric_calls[0]["outcome"] == "deny"
    assert audit_calls[0]["reason"] == "dual_credential_conflict"


def test_policy_dual_credentials_prefer_session_skips_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"authorization": "Bearer token", "x-api-key": "ak_k1.secret"})
    called = {"count": 0}
    metric_calls: list[dict[str, str]] = []
    audit_calls: list[dict[str, str]] = []

    async def _principal(_request):
        called["count"] += 1
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": []}

    monkeypatch.setattr(svc, "S", SimpleNamespace(api_key_dual_credential_mode="prefer_session"))
    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "record_api_key_policy_decision", lambda **kwargs: metric_calls.append(kwargs))
    monkeypatch.setattr(svc, "audit_event", lambda _event, _user, _req, **fields: audit_calls.append(fields))
    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))
    assert called["count"] == 0
    assert metric_calls[0]["outcome"] == "bypass"
    assert metric_calls[0]["reason"] == "prefer_session"
    assert audit_calls[0]["reason"] == "prefer_session"


def test_policy_enforcement_returns_500_on_internal_policy_error(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})
    metric_calls: list[dict[str, str]] = []
    audit_calls: list[dict[str, str]] = []

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    def _boom(*_args, **_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(svc, "requires_scope_for_request_from_registry", _boom)
    monkeypatch.setattr(svc, "record_api_key_policy_decision", lambda **kwargs: metric_calls.append(kwargs))
    monkeypatch.setattr(svc, "audit_event", lambda _event, _user, _req, **fields: audit_calls.append(fields))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(svc.maybe_enforce_api_key_route_policy(req))

    assert exc.value.status_code == 500
    assert exc.value.detail["code"] == "api_key_policy_internal_error"
    assert exc.value.detail["reason"] == "internal_error"
    assert metric_calls[0]["outcome"] == "error"
    assert audit_calls[0]["reason"] == "internal_error"


def test_policy_shadow_mode_internal_error_does_not_block_request(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers={"x-api-key": "ak_k1.secret"})
    metric_calls: list[dict[str, str]] = []
    audit_calls: list[dict[str, str]] = []

    async def _principal(_request):
        return {"user_sub": "u1", "api_key_id": "k1", "capabilities": ["filemanager:read"]}

    monkeypatch.setattr(svc, "require_api_key_principal", _principal)
    monkeypatch.setattr(svc, "route_id_from_request", lambda request: "GET:/v1/files")
    monkeypatch.setattr(svc, "get_route_scope_policy", lambda _rid: {"product": "filemanager"})
    monkeypatch.setattr(svc, "evaluate_api_key_rollout", lambda _product, _principal: {"product": "filemanager", "phase": "shadow", "enforce": False, "reason": "shadow_only"})
    monkeypatch.setattr(svc, "requires_scope_for_request_from_registry", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("unexpected")))
    monkeypatch.setattr(svc, "record_api_key_policy_decision", lambda **kwargs: metric_calls.append(kwargs))
    monkeypatch.setattr(svc, "audit_event", lambda _event, _user, _req, **fields: audit_calls.append(fields))

    asyncio.run(svc.maybe_enforce_api_key_route_policy(req))

    assert req.state.api_key_shadow_error["reason"] == "internal_error"
    assert req.state.api_key_shadow_error["error_type"] == "RuntimeError"
    assert metric_calls[0]["mode"] == "shadow"
    assert metric_calls[0]["outcome"] == "error"
    assert audit_calls[0]["reason"] == "internal_error"
