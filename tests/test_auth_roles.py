from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace

from app.auth import deps
from app.auth.roles import Role, normalize_role
from app.core.settings import S


def run_async(coro):
    return asyncio.run(coro)


def _encode_payload(payload: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{header}.{body}."


def test_normalize_role_defaults_to_user_for_unknown_values() -> None:
    assert normalize_role(None) == Role.USER
    assert normalize_role("") == Role.USER
    assert normalize_role("something-else") == Role.USER


def test_normalize_role_accepts_case_insensitive_values() -> None:
    assert normalize_role("ROOT") == Role.ROOT
    assert normalize_role("Admin") == Role.ADMIN
    assert normalize_role("user") == Role.USER


def test_get_authenticated_user_role_defaults_to_user_in_dev_fallback() -> None:
    req = SimpleNamespace(headers={"authorization": "Bearer user-1"})
    assert run_async(deps.get_authenticated_user_role(req)) == Role.USER


def test_get_authenticated_user_role_reads_dev_header() -> None:
    req = SimpleNamespace(headers={"x-user-sub": "user-1", "x-user-role": "admin"})
    assert run_async(deps.get_authenticated_user_role(req)) == Role.ADMIN


def test_get_authenticated_user_role_reads_jwt_role_claim() -> None:
    object.__setattr__(S, "root_user_sub", "user-1")
    token = _encode_payload({"sub": "user-1", "role": "root"})
    req = SimpleNamespace(headers={"authorization": f"Bearer {token}"})
    assert run_async(deps.get_authenticated_user_role(req)) == Role.ROOT


def test_get_authenticated_user_role_rejects_root_claim_for_other_subject() -> None:
    object.__setattr__(S, "root_user_sub", "actual-root")
    token = _encode_payload({"sub": "user-1", "role": "root"})
    req = SimpleNamespace(headers={"authorization": f"Bearer {token}"})
    try:
        run_async(deps.get_authenticated_user_role(req))
        assert False, "expected exception"
    except Exception as exc:
        from fastapi import HTTPException

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 403
        assert exc.detail["code"] == "role_required"


def test_get_authenticated_user_role_prefers_highest_privilege_in_roles_claim() -> None:
    token = _encode_payload({"sub": "user-1", "roles": ["user", "admin"]})
    req = SimpleNamespace(headers={"authorization": f"Bearer {token}"})
    assert run_async(deps.get_authenticated_user_role(req)) == Role.ADMIN
