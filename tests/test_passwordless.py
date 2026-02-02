import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.routers import passwordless
from app.models import PasswordlessStartReq, PasswordlessVerifyReq


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


def run_async(coro):
    import asyncio
    return asyncio.run(coro)


class TestPasswordlessRoutes(unittest.TestCase):
    def test_passwordless_start_sends_link(self):
        req = build_request()
        with patch.object(passwordless, "create_magic_link", return_value={"sent_to": ["user@example.com"]}) as create_link, \
             patch.object(passwordless, "rate_limit_password_recovery"), \
             patch.object(passwordless, "enforce_lockout"), \
             patch.object(passwordless, "audit_event"):
            resp = run_async(passwordless.passwordless_start(req, PasswordlessStartReq(username="user"),))
            self.assertEqual(resp["status"], "sent")
            self.assertEqual(resp["sent_to"], ["user@example.com"])
            create_link.assert_called_once()

    def test_passwordless_verify_requires_mfa(self):
        req = build_request()
        with patch.object(passwordless, "load_magic_link", return_value={"target_user_sub": "user"}), \
             patch.object(passwordless, "compute_required_factors", return_value=["totp"]), \
             patch.object(passwordless, "create_stepup_challenge", return_value="chal"), \
             patch.object(passwordless, "mark_magic_link_used") as mark_used, \
             patch.object(passwordless, "enforce_lockout"), \
             patch.object(passwordless, "audit_event"):
            resp = run_async(passwordless.passwordless_verify(req, PasswordlessVerifyReq(token="tok")))
            self.assertTrue(resp["auth_required"])
            self.assertEqual(resp["challenge_id"], "chal")
            mark_used.assert_called_once_with("tok")

    def test_passwordless_verify_creates_session(self):
        req = build_request()
        with patch.object(passwordless, "load_magic_link", return_value={"target_user_sub": "user"}), \
             patch.object(passwordless, "compute_required_factors", return_value=[]), \
             patch.object(passwordless, "create_real_session", return_value="sid"), \
             patch.object(passwordless, "mark_magic_link_used") as mark_used, \
             patch.object(passwordless, "clear_lockout") as clear_lockout, \
             patch.object(passwordless, "enforce_lockout"), \
             patch.object(passwordless, "audit_event"):
            resp = run_async(passwordless.passwordless_verify(req, PasswordlessVerifyReq(token="tok")))
            self.assertEqual(resp["status"], "ok")
            self.assertEqual(resp["session_id"], "sid")
            mark_used.assert_called_once_with("tok")
            clear_lockout.assert_called_once()
