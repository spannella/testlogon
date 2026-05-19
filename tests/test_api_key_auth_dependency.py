from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.services import api_key_auth_dependency as dep


def _request(*, headers: list[tuple[bytes, bytes]], client_host: str = "203.0.113.7") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/v1/files",
        "headers": headers,
        "query_string": b"",
        "client": (client_host, 5000),
        "server": ("test", 80),
        "scheme": "http",
    }
    return Request(scope)


def test_require_api_key_principal_prefers_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers=[(b"authorization", b"ApiKey ak_keyid.secretA"), (b"x-api-key", b"ak_other.secretB")])

    monkeypatch.setattr(dep.api_keys, "parse_api_key", lambda raw: {"key_id": "keyid", "secret": "secretA"})
    monkeypatch.setattr(dep.api_keys, "check_api_key_allowed", lambda key_id, secret, client_ip: {"key_id": key_id, "user_sub": "u1", "capabilities": ["tickets:read"]})
    monkeypatch.setattr(dep.api_keys, "effective_api_key_capabilities", lambda item: list(item.get("capabilities") or []))

    principal = asyncio.run(dep.require_api_key_principal(req))

    assert principal["auth_type"] == "api_key"
    assert principal["user_sub"] == "u1"
    assert principal["api_key_id"] == "keyid"
    assert principal["capabilities"] == ["tickets:read"]
    assert dep.get_api_key_principal(req) == principal


def test_require_api_key_principal_uses_x_api_key_when_authorization_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers=[(b"x-api-key", b"ak_k1.secret")])

    monkeypatch.setattr(dep.api_keys, "parse_api_key", lambda raw: {"key_id": "k1", "secret": "secret"})
    monkeypatch.setattr(dep.api_keys, "check_api_key_allowed", lambda key_id, secret, client_ip: {"key_id": key_id, "user_sub": "u2"})
    monkeypatch.setattr(dep.api_keys, "effective_api_key_capabilities", lambda item: ["filemanager:read"])

    principal = asyncio.run(dep.require_api_key_principal(req))
    assert principal["api_key_id"] == "k1"
    assert principal["user_sub"] == "u2"


def test_require_api_key_principal_returns_consistent_401_for_parse_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers=[(b"x-api-key", b"invalid")])

    def _parse(_raw: str):
        raise HTTPException(401, "Invalid API key format")

    monkeypatch.setattr(dep.api_keys, "parse_api_key", _parse)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(dep.require_api_key_principal(req))

    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == "api_key_invalid"
    assert exc.value.detail["reason"] == "invalid_key"
    assert "request_id" in exc.value.detail


def test_require_api_key_principal_returns_consistent_401_for_revoked_or_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers=[(b"x-api-key", b"ak_k1.secret")])
    monkeypatch.setattr(dep.api_keys, "parse_api_key", lambda raw: {"key_id": "k1", "secret": "secret"})

    def _check(_key_id: str, _secret: str, _ip: str):
        raise HTTPException(401, "API key expired")

    monkeypatch.setattr(dep.api_keys, "check_api_key_allowed", _check)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(dep.require_api_key_principal(req))

    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == "api_key_invalid"


def test_require_api_key_principal_propagates_non_401_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers=[(b"x-api-key", b"ak_k1.secret")])
    monkeypatch.setattr(dep.api_keys, "parse_api_key", lambda raw: {"key_id": "k1", "secret": "secret"})

    def _check(_key_id: str, _secret: str, _ip: str):
        raise HTTPException(403, "API key denied from this IP")

    monkeypatch.setattr(dep.api_keys, "check_api_key_allowed", _check)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(dep.require_api_key_principal(req))

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "api_key_origin_denied"
    assert exc.value.detail["reason"] == "origin_denied"


def test_require_api_key_principal_passes_ipv6_client_ip_to_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(headers=[(b"x-api-key", b"ak_k1.secret")], client_host="[2001:db8::1]")
    monkeypatch.setattr(dep.api_keys, "parse_api_key", lambda raw: {"key_id": "k1", "secret": "secret"})
    seen: dict[str, str] = {}

    def _check(_key_id: str, _secret: str, ip: str):
        seen["ip"] = ip
        return {"key_id": "k1", "user_sub": "u1"}

    monkeypatch.setattr(dep.api_keys, "check_api_key_allowed", _check)
    monkeypatch.setattr(dep.api_keys, "effective_api_key_capabilities", lambda _item: [])
    asyncio.run(dep.require_api_key_principal(req))
    assert seen["ip"] == "2001:db8::1"


def test_require_api_key_principal_ignores_forwarded_ip_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    req = _request(
        headers=[
            (b"x-api-key", b"ak_k1.secret"),
            (b"x-forwarded-for", b"10.0.0.1"),
            (b"x-real-ip", b"10.0.0.2"),
        ],
        client_host="198.51.100.22",
    )
    monkeypatch.setattr(dep.api_keys, "parse_api_key", lambda raw: {"key_id": "k1", "secret": "secret"})
    seen: dict[str, str] = {}

    def _check(_key_id: str, _secret: str, ip: str):
        seen["ip"] = ip
        return {"key_id": "k1", "user_sub": "u1"}

    monkeypatch.setattr(dep.api_keys, "check_api_key_allowed", _check)
    monkeypatch.setattr(dep.api_keys, "effective_api_key_capabilities", lambda _item: [])
    asyncio.run(dep.require_api_key_principal(req))
    assert seen["ip"] == "198.51.100.22"
