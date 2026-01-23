import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.models import AccountStatusReq
from app.routers import account_state


def run_async(coro):
    return asyncio.run(coro)


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


def build_ctx():
    return {"user_sub": "user", "session_id": "sid"}


class TestAccountStateRoutes(unittest.TestCase):
    def test_account_status(self):
        with patch.object(account_state, "get_account_state", return_value={"status": "active"}):
            resp = run_async(account_state.account_status(ctx=build_ctx()))
            self.assertEqual(resp["status"], "active")

    def test_account_suspend_request(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(account_state, "get_account_state", return_value={"status": "active"}))
            set_state = stack.enter_context(
                patch.object(account_state, "set_account_state", return_value={"status": "suspension_requested"})
            )
            audit = stack.enter_context(patch.object(account_state, "audit_event"))
            resp = run_async(account_state.account_suspend(AccountStatusReq(reason="testing"), req=req, ctx=build_ctx()))

        self.assertEqual(resp["status"], "suspension_requested")
        set_state.assert_called_once()
        audit.assert_called_once()
        self.assertEqual(audit.call_args.args[0], "account_suspension_requested")
        self.assertEqual(audit.call_args.kwargs.get("reason"), "testing")

    def test_account_suspend_rejects_non_active(self):
        req = build_request()
        with patch.object(account_state, "get_account_state", return_value={"status": "suspension_requested"}):
            with self.assertRaises(HTTPException):
                run_async(account_state.account_suspend(AccountStatusReq(reason=None), req=req, ctx=build_ctx()))

    def test_account_reactivate_request(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(account_state, "get_account_state", return_value={"status": "suspension_requested"}))
            set_state = stack.enter_context(
                patch.object(account_state, "set_account_state", return_value={"status": "reactivation_requested"})
            )
            audit = stack.enter_context(patch.object(account_state, "audit_event"))
            resp = run_async(account_state.account_reactivate(AccountStatusReq(reason="ready"), req=req, ctx=build_ctx()))

        self.assertEqual(resp["status"], "reactivation_requested")
        set_state.assert_called_once()
        audit.assert_called_once()
        self.assertEqual(audit.call_args.args[0], "account_reactivation_requested")
        self.assertEqual(audit.call_args.kwargs.get("reason"), "ready")

    def test_account_reactivate_rejects_active(self):
        req = build_request()
        with patch.object(account_state, "get_account_state", return_value={"status": "active"}):
            with self.assertRaises(HTTPException):
                run_async(account_state.account_reactivate(AccountStatusReq(reason=None), req=req, ctx=build_ctx()))

    def test_account_reactivate_rejects_duplicate(self):
        req = build_request()
        with patch.object(account_state, "get_account_state", return_value={"status": "reactivation_requested"}):
            with self.assertRaises(HTTPException):
                run_async(account_state.account_reactivate(AccountStatusReq(reason=None), req=req, ctx=build_ctx()))
