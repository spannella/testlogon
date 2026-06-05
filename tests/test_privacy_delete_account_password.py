"""Regression test for GAP-0029 (old delete-account endpoint skips password verify).

The legacy ``POST /ui/privacy/delete-account`` handler in ``app/routers/privacy.py``
historically contained a comment-only ``pass`` where production password
verification should have been. In production (``S.dev_mode=False``) it accepted
*any* non-empty password string, letting a session-hijacked account be scheduled
for irreversible deletion without knowing the victim's real password.

The fix routes the legacy handler through ``cognito_auth.verify_user_password``
(the same helper used by the canonical ``account_deletion.py`` endpoint), which
re-authenticates against Cognito in production.

These tests run fully offline (moto for DynamoDB, no real AWS). The router
handler ``request_deletion`` is invoked directly with a forged session dict,
mirroring the direct-call style of ``tests/test_activity_feed_idor.py``.

- FAILS BEFORE FIX: a wrong/garbage password returns 201 (deletion scheduled).
- PASSES AFTER FIX:  a wrong/garbage password raises 401 (Invalid password).
- A correct password still schedules the deletion (201 / item created).
"""

from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ALICE = "alice_user_sub"


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


@pytest.fixture()
def deletion_env(monkeypatch):
    """Create moto-backed ``data_requests`` + ``data_request_audit`` tables.

    Yields the real ``request_deletion`` router handler with the gdpr_service
    table handles swapped to the moto-backed tables. Also forces production
    posture (``S.dev_mode=False``) so the verification branch is exercised.
    """
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        for name in ("data_requests", "data_request_audit"):
            ddb.create_table(
                TableName=name,
                KeySchema=[
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                    {"AttributeName": "sk", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )

        from app.routers import privacy as privacy_router
        from app.services import gdpr_service
        from app.core.settings import S

        tables = gdpr_service.T
        orig_reqs = tables.data_requests
        orig_audit = tables.data_request_audit
        object.__setattr__(tables, "data_requests", ddb.Table("data_requests"))
        object.__setattr__(tables, "data_request_audit", ddb.Table("data_request_audit"))

        # ``S`` is a frozen dataclass, so monkeypatch.undo() can't restore it;
        # mutate via object.__setattr__ and restore manually in ``finally``.
        # Force production posture: the bug only manifests when dev_mode is off.
        orig_dev = S.dev_mode
        orig_enabled = getattr(S, "privacy_deletion_enabled", None)
        object.__setattr__(S, "dev_mode", False)
        object.__setattr__(S, "privacy_deletion_enabled", True)

        try:
            yield privacy_router, gdpr_service
        finally:
            object.__setattr__(S, "dev_mode", orig_dev)
            if orig_enabled is not None:
                object.__setattr__(S, "privacy_deletion_enabled", orig_enabled)
            object.__setattr__(tables, "data_requests", orig_reqs)
            object.__setattr__(tables, "data_request_audit", orig_audit)


def _call(handler, password, reason="test"):
    from app.models import DeleteAccountRequestIn

    body = DeleteAccountRequestIn(password=password, reason=reason)
    ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
    return handler(body=body, ctx=ctx)


def test_wrong_password_rejected_in_prod(deletion_env, monkeypatch):
    """A non-empty but WRONG password must be rejected with 401 in production.

    Before the fix the handler ignored the password entirely and returned 201.
    """
    from fastapi import HTTPException
    from app.services import cognito_auth

    privacy_router, gdpr_service = deletion_env

    # Cognito rejects the password (simulating a stolen-session attacker who
    # does not know the real password).
    monkeypatch.setattr(cognito_auth, "verify_user_password", lambda sub, pw: False)

    with pytest.raises(HTTPException) as exc:
        _call(privacy_router.request_deletion, "wrong_but_nonempty")

    assert exc.value.status_code == 401
    assert "password" in str(exc.value.detail).lower()

    # And crucially: no deletion request was scheduled.
    assert gdpr_service.has_pending_deletion(ALICE) is False


def test_empty_password_rejected(deletion_env):
    """An empty password is always rejected (pre-existing check)."""
    from fastapi import HTTPException

    privacy_router, gdpr_service = deletion_env

    with pytest.raises(HTTPException) as exc:
        _call(privacy_router.request_deletion, "")

    assert exc.value.status_code == 401
    assert gdpr_service.has_pending_deletion(ALICE) is False


def test_correct_password_schedules_deletion(deletion_env, monkeypatch):
    """A correct password proceeds and schedules the deletion request."""
    from app.services import cognito_auth

    privacy_router, gdpr_service = deletion_env

    monkeypatch.setattr(
        cognito_auth, "verify_user_password", lambda sub, pw: pw == "correct_password"
    )

    out = _call(privacy_router.request_deletion, "correct_password")

    assert out is not None
    assert gdpr_service.has_pending_deletion(ALICE) is True
