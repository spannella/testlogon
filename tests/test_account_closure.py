import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.models import AccountClosureFinalizeReq
from app.routers import account as account_router


def run_async(coro):
    return asyncio.run(coro)


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


class TestAccountClosureRoutes(unittest.TestCase):
    def test_account_closure_start_requires_step_up(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(account_router, "compute_required_factors", return_value=["totp"]))
            stack.enter_context(patch.object(account_router, "create_stepup_challenge", return_value="chal"))
            stack.enter_context(patch.object(account_router, "audit_event"))

            resp = run_async(account_router.account_closure_start(req, ctx={"user_sub": "user"}))
            self.assertTrue(resp["auth_required"])
            self.assertEqual(resp["challenge_id"], "chal")

    def test_account_closure_finalize_pending(self):
        req = build_request()
        chal = {"purpose": "account_closure", "required_factors": ["totp"], "passed": {"totp": False}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(account_router, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(account_router, "challenge_done", return_value=False))
            delete_mock = stack.enter_context(patch.object(account_router, "delete_user_data"))

            resp = run_async(
                account_router.account_closure_finalize(
                    req, AccountClosureFinalizeReq(challenge_id="chal"), ctx={"user_sub": "user"}
                )
            )
            self.assertEqual(resp["status"], "pending")
            delete_mock.assert_not_called()

    def test_account_closure_finalize_wrong_purpose(self):
        req = build_request()
        chal = {"purpose": "other"}
        with patch.object(account_router, "load_challenge_or_401", return_value=chal):
            with self.assertRaises(HTTPException):
                run_async(
                    account_router.account_closure_finalize(
                        req, AccountClosureFinalizeReq(challenge_id="chal"), ctx={"user_sub": "user"}
                    )
                )

    def test_account_closure_finalize_success(self):
        req = build_request()
        chal = {"purpose": "account_closure", "required_factors": ["totp"], "passed": {"totp": True}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(account_router, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(account_router, "challenge_done", return_value=True))
            delete_mock = stack.enter_context(patch.object(account_router, "delete_user_data"))
            stack.enter_context(patch.object(account_router, "audit_event"))

            resp = run_async(
                account_router.account_closure_finalize(
                    req, AccountClosureFinalizeReq(challenge_id="chal"), ctx={"user_sub": "user"}
                )
            )
            self.assertEqual(resp["status"], "closed")
            delete_mock.assert_called_once_with("user")
