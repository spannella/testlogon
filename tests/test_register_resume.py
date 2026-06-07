"""Regression tests for GAP-0107 + GAP-0108 (AUTH-001).

GAP-0107: POST /ui/register/check must distinguish a taken+verified account from
          a taken+pending-verification account via an `unverified` hint so the
          frontend can offer a resume/resend path.

GAP-0108: POST /ui/register/start must RESUME a pending_verification account by
          re-issuing a fresh verification challenge, instead of silently swallowing
          the duplicate-email 409 and returning a fake success with no code sent.
          Active accounts must NOT get a new code via /start.

Offline: in-memory fake DynamoDB tables via monkeypatch (no real AWS), matching
the style of tests/test_registration_ttl.py + tests/test_register.py. The router
handlers are invoked directly with the heavy side-effecting collaborators
(send_email_code, rate limiters, audit) patched, while the account-state reads
(_user_exists / get_account_state used by check_email_status / get_pending_user)
run against the real seeded fake tables.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.models import RegisterEmailCheckReq, RegisterStartReq
from app.routers import register
from app.services import account_state as account_state_mod
from app.services import registration


class _FakeKeyValueTable:
    """Minimal in-memory DynamoDB table keyed by user_sub."""

    def __init__(self):
        self.items = {}

    def get_item(self, Key, **kwargs):
        item = self.items.get(Key["user_sub"])
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None, **kwargs):
        if ConditionExpression and "attribute_not_exists" in ConditionExpression:
            if Item["user_sub"] in self.items:
                raise Exception("ConditionalCheckFailed")
        self.items[Item["user_sub"]] = dict(Item)
        return {}

    def update_item(self, Key, UpdateExpression="", ExpressionAttributeValues=None, **kwargs):
        item = self.items.get(Key["user_sub"])
        if item is None:
            return {}
        expr = (UpdateExpression or "").strip()
        if expr.upper().startswith("REMOVE"):
            attr = expr[len("REMOVE"):].strip()
            item.pop(attr, None)
        self.items[Key["user_sub"]] = item
        return {}

    def delete_item(self, Key, **kwargs):
        self.items.pop(Key["user_sub"], None)
        return {}


def _build_request():
    return SimpleNamespace(
        headers={"user-agent": "agent"},
        client=SimpleNamespace(host="127.0.0.1"),
        state=SimpleNamespace(),
        cookies={},
    )


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def fake_tables(monkeypatch):
    users = _FakeKeyValueTable()
    account_state = _FakeKeyValueTable()

    monkeypatch.setattr(registration, "T", SimpleNamespace(users=users))
    monkeypatch.setattr(account_state_mod, "T", SimpleNamespace(account_state=account_state))
    # save_profile touches T.profile; irrelevant here.
    monkeypatch.setattr(registration, "save_profile", lambda *a, **k: None)

    # Settings is a frozen dataclass — swap in a mutable stand-in carrying the
    # fields the registration/router code reads. dev_mode=True forces the
    # non-Cognito path; resume flag on by default.
    fake_s = SimpleNamespace(
        dev_mode=True,
        cognito_app_client_id="",
        registration_allow_resume_unverified=True,
        registration_pending_ttl_days=register.S.registration_pending_ttl_days,
        ddb_ttl_attr=register.S.ddb_ttl_attr,
        referral_enabled=False,
    )
    monkeypatch.setattr(register, "S", fake_s)
    monkeypatch.setattr(registration, "S", fake_s)

    return SimpleNamespace(users=users, account_state=account_state, s=fake_s)


def _seed_pending(email: str):
    registration.create_user_record(
        email=email, full_name="P", password="StrongPassphrase42!",
        verification_required=True,
    )


def _seed_active(email: str):
    registration.create_user_record(
        email=email, full_name="A", password="StrongPassphrase42!",
        verification_required=False,
    )


# ── GAP-0107: /check unverified hint ─────────────────────────────────────────

def test_check_available_email(fake_tables):
    """Unknown email -> available: True, unverified: False."""
    req = _build_request()
    with patch.object(register, "rate_limit_password_recovery"), \
         patch.object(register, "enforce_lockout"), \
         patch.object(register, "clear_lockout"), \
         patch.object(register, "audit_event"):
        result = _run(register.register_check(req, RegisterEmailCheckReq(email="new@example.com")))
    assert result == {"status": "ok", "available": True, "unverified": False}


def test_check_active_account_not_unverified(fake_tables):
    """Verified active email -> available: False, unverified: False."""
    _seed_active("active@example.com")
    req = _build_request()
    with patch.object(register, "rate_limit_password_recovery"), \
         patch.object(register, "enforce_lockout"), \
         patch.object(register, "clear_lockout"), \
         patch.object(register, "audit_event"):
        result = _run(register.register_check(req, RegisterEmailCheckReq(email="active@example.com")))
    assert result["available"] is False
    assert result["unverified"] is False


def test_check_pending_account_is_unverified(fake_tables):
    """Pending-verification email -> available: False, unverified: True.

    FAILS before fix: the field did not exist / was always False.
    """
    _seed_pending("pending@example.com")
    req = _build_request()
    with patch.object(register, "rate_limit_password_recovery"), \
         patch.object(register, "enforce_lockout"), \
         patch.object(register, "clear_lockout"), \
         patch.object(register, "audit_event"):
        result = _run(register.register_check(req, RegisterEmailCheckReq(email="pending@example.com")))
    assert result["available"] is False
    assert result["unverified"] is True


# ── GAP-0108: /start resume path ─────────────────────────────────────────────

def _start_body(email: str) -> RegisterStartReq:
    return RegisterStartReq(
        full_name="P",
        email=email,
        password="StrongPassphrase42!",
        confirm_password="StrongPassphrase42!",
    )


def test_start_reissues_code_for_pending_account(fake_tables):
    """Re-registering a pending_verification email sends a NEW code.

    FAILS before fix: send_email_code was never called (silent fake success).
    """
    _seed_pending("pending2@example.com")
    req = _build_request()
    with patch.object(register, "check_password_breach", return_value=0), \
         patch.object(register, "can_send_verification", return_value=True), \
         patch.object(register, "create_registration_challenge", return_value="123456") as challenge, \
         patch.object(register, "send_email_code") as send_email_code, \
         patch.object(register, "enforce_lockout"), \
         patch.object(register, "rate_limit_password_recovery"), \
         patch.object(register, "record_lockout_failure"), \
         patch.object(register, "clear_lockout"), \
         patch.object(register, "audit_event"):
        result = _run(register.register_start(req, _start_body("pending2@example.com")))
    assert result["status"] == "ok"
    assert result["verification_required"] is True
    send_email_code.assert_called_once()
    challenge.assert_called_once()


def test_start_does_not_reissue_code_for_active_account(fake_tables):
    """Re-registering an active email does NOT send a new code (no hijack)."""
    _seed_active("active2@example.com")
    req = _build_request()
    with patch.object(register, "check_password_breach", return_value=0), \
         patch.object(register, "can_send_verification", return_value=True), \
         patch.object(register, "create_registration_challenge", return_value="123456"), \
         patch.object(register, "send_email_code") as send_email_code, \
         patch.object(register, "enforce_lockout"), \
         patch.object(register, "rate_limit_password_recovery"), \
         patch.object(register, "record_lockout_failure"), \
         patch.object(register, "clear_lockout"), \
         patch.object(register, "audit_event"):
        result = _run(register.register_start(req, _start_body("active2@example.com")))
    assert result["status"] == "ok"
    send_email_code.assert_not_called()


def test_start_resume_disabled_by_flag(fake_tables, monkeypatch):
    """REGISTRATION_ALLOW_RESUME_UNVERIFIED off -> old silent behaviour (no code)."""
    fake_tables.s.registration_allow_resume_unverified = False
    _seed_pending("pending3@example.com")
    req = _build_request()
    with patch.object(register, "check_password_breach", return_value=0), \
         patch.object(register, "can_send_verification", return_value=True), \
         patch.object(register, "create_registration_challenge", return_value="123456"), \
         patch.object(register, "send_email_code") as send_email_code, \
         patch.object(register, "enforce_lockout"), \
         patch.object(register, "rate_limit_password_recovery"), \
         patch.object(register, "record_lockout_failure"), \
         patch.object(register, "clear_lockout"), \
         patch.object(register, "audit_event"):
        result = _run(register.register_start(req, _start_body("pending3@example.com")))
    assert result["status"] == "ok"
    send_email_code.assert_not_called()
