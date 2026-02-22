import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException, Response

from app.models import RegisterConfirmReq, RegisterEmailCheckReq, RegisterResendReq, RegisterStartReq
from app.routers import register


def build_request():
    return SimpleNamespace(
        headers={"user-agent": "agent"},
        client=SimpleNamespace(host="127.0.0.1"),
        state=SimpleNamespace(),
    )


def run_async(coro):
    import asyncio
    return asyncio.run(coro)


class TestRegisterRoutes(unittest.TestCase):
    def test_register_check_email_available(self):
        req = build_request()
        with patch.object(register, "is_email_available", return_value=True), \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery:
            result = run_async(register.register_check(
                req,
                RegisterEmailCheckReq(email="jane@example.com"),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["available"])
            rate_limit_password_recovery.assert_called_once()

    def test_register_start_success_requires_email_verification(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "check_password_breach", return_value=0), \
             patch.object(register, "cognito_sign_up", return_value={"UserConfirmed": True}), \
             patch.object(register, "create_user_record"), \
             patch.object(register, "can_send_verification", return_value=True), \
             patch.object(register, "create_registration_challenge", return_value="code"), \
             patch.object(register, "send_email_code") as send_email_code, \
             patch.object(register, "clear_lockout") as clear_lockout, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_start(
                req,
                RegisterStartReq(
                    full_name="Jane Doe",
                    email="jane@example.com",
                    password="StrongPassphrase42!",
                    confirm_password="StrongPassphrase42!",
                ),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["verification_required"])
            self.assertIsNone(result["delivery_medium"])
            self.assertIsNone(result["delivery_destination"])
            send_email_code.assert_called_once()
            clear_lockout.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called()

    def test_register_start_allows_dev_mode_without_cognito_config(self):
        req = build_request()
        with patch.object(register, "S", SimpleNamespace(cognito_app_client_id="", dev_mode=True, dev_registration_email="", dev_registration_password="", dev_registration_code="", dev_registration_phone="")), \
             patch.object(register, "check_password_breach", return_value=0), \
             patch.object(register, "cognito_sign_up") as cognito_sign_up, \
             patch.object(register, "create_user_record") as create_user_record, \
             patch.object(register, "can_send_verification", return_value=True), \
             patch.object(register, "create_registration_challenge", return_value="code"), \
             patch.object(register, "send_email_code") as send_email_code:
            result = run_async(register.register_start(
                req,
                RegisterStartReq(
                    full_name="Jane Doe",
                    email="jane@example.com",
                    password="StrongPassphrase42!",
                    confirm_password="StrongPassphrase42!",
                ),
            ))
            self.assertEqual(result["status"], "ok")
            create_user_record.assert_called_once()
            send_email_code.assert_called_once()
            cognito_sign_up.assert_not_called()

    def test_register_start_verification_workflow(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "check_password_breach", return_value=0), \
             patch.object(register, "cognito_sign_up", return_value={
                 "UserConfirmed": False,
                 "CodeDeliveryDetails": {
                     "DeliveryMedium": "EMAIL",
                     "Destination": "jane@example.com",
                 },
             }), \
             patch.object(register, "create_user_record"), \
             patch.object(register, "can_send_verification", return_value=True), \
             patch.object(register, "create_registration_challenge", return_value="code"), \
             patch.object(register, "send_email_code") as send_email_code, \
             patch.object(register, "clear_lockout") as clear_lockout, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_start(
                req,
                RegisterStartReq(
                    full_name="Jane Doe",
                    email="jane@example.com",
                    password="StrongPassphrase42!",
                    confirm_password="StrongPassphrase42!",
                ),
            ))
            self.assertTrue(result["verification_required"])
            self.assertIsNone(result["delivery_medium"])
            self.assertIsNone(result["delivery_destination"])
            send_email_code.assert_called_once()
            clear_lockout.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called()

    def test_register_start_duplicate_user(self):
        req = build_request()
        with patch.object(register, "_cognito_available", return_value=True),              patch.object(register, "_require_cognito"),              patch.object(register, "check_password_breach", return_value=0),              patch.object(register, "cognito_sign_up", side_effect=HTTPException(409, "Exists")),              patch.object(register, "record_lockout_failure") as record_lockout_failure,              patch.object(register, "enforce_lockout") as enforce_lockout,              patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery,              patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_start(
                req,
                RegisterStartReq(
                    full_name="Jane Doe",
                    email="jane@example.com",
                    password="StrongPassphrase42!",
                    confirm_password="StrongPassphrase42!",
                ),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertIsNone(result["delivery_medium"])
            self.assertIsNone(result["delivery_destination"])
            record_lockout_failure.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called_once()

    def test_register_start_invalid_password(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "check_password_breach", return_value=1), \
             patch.object(register, "record_lockout_failure") as record_lockout_failure, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            with self.assertRaises(HTTPException):
                run_async(register.register_start(
                    req,
                    RegisterStartReq(
                        full_name="Jane Doe",
                        email="jane@example.com",
                        password="StrongPassphrase42!",
                        confirm_password="StrongPassphrase42!",
                    ),
                ))
            record_lockout_failure.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called_once()

    def test_register_confirm_success(self):
        req = build_request()
        response = Response()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "verify_registration_code", return_value={
                 "user_sub": "jane@example.com",
                 "mfa_setup": ["sms"],
                 "sms_phone": "+15551234567",
             }), \
             patch.object(register, "cognito_admin_confirm_sign_up"), \
             patch.object(register, "mark_user_verified"), \
             patch.object(register, "create_real_session", return_value={"id": "session"}), \
             patch.object(register, "rotate_session_cookies") as rotate_session_cookies, \
             patch.object(register, "session_id_value", return_value="session-id"), \
             patch.object(register, "clear_lockout") as clear_lockout, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_confirm(
                req,
                RegisterConfirmReq(email="jane@example.com", confirmation_code="1234"),
                response=response,
            ))
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["session_id"], "session-id")
            self.assertEqual(result["mfa_setup"], ["sms"])
            self.assertEqual(result["sms_phone"], "+15551234567")
            clear_lockout.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            rotate_session_cookies.assert_called_once()
            audit_event.assert_any_call("register_confirm", "jane@example.com", req, outcome="success")
            audit_event.assert_any_call(
                "register_session_start",
                "jane@example.com",
                req,
                outcome="success",
                session_id="session-id",
            )

    def test_register_confirm_allows_dev_mode_without_cognito_config(self):
        req = build_request()
        response = Response()
        with patch.object(register, "S", SimpleNamespace(cognito_app_client_id="", dev_mode=True, dev_registration_email="", dev_registration_password="", dev_registration_code="", dev_registration_phone="")), \
             patch.object(register, "verify_registration_code", return_value={"user_sub": "jane@example.com"}), \
             patch.object(register, "cognito_admin_confirm_sign_up") as cognito_admin_confirm_sign_up, \
             patch.object(register, "mark_user_verified"), \
             patch.object(register, "create_real_session", return_value={"id": "session"}), \
             patch.object(register, "rotate_session_cookies"), \
             patch.object(register, "session_id_value", return_value="session-id"):
            result = run_async(register.register_confirm(
                req,
                RegisterConfirmReq(email="jane@example.com", confirmation_code="1234"),
                response=response,
            ))
            self.assertEqual(result["status"], "ok")
            cognito_admin_confirm_sign_up.assert_not_called()

    def test_register_confirm_invalid_code(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "verify_registration_code", side_effect=HTTPException(400, "Bad code")), \
             patch.object(register, "record_lockout_failure") as record_lockout_failure, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            with self.assertRaises(HTTPException):
                run_async(register.register_confirm(
                    req,
                    RegisterConfirmReq(email="jane@example.com", confirmation_code="1234"),
                ))
            record_lockout_failure.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called_once()

    def test_register_resend_email(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "can_send_verification", return_value=True), \
             patch.object(register, "create_registration_challenge", return_value="code"), \
             patch.object(register, "send_email_code") as send_email_code, \
             patch.object(register, "clear_lockout") as clear_lockout, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_resend(
                req,
                RegisterResendReq(email="jane@example.com", delivery_method="email"),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertIsNone(result["delivery_medium"])
            self.assertIsNone(result["delivery_destination"])
            send_email_code.assert_called_once()
            clear_lockout.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called()

    def test_register_resend_rate_limited(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "can_send_verification", return_value=False), \
             patch.object(register, "record_lockout_failure") as record_lockout_failure, \
             patch.object(register, "enforce_lockout") as enforce_lockout, \
             patch.object(register, "rate_limit_password_recovery") as rate_limit_password_recovery, \
             patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_resend(
                req,
                RegisterResendReq(email="jane@example.com", delivery_method="email"),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertIsNone(result["delivery_medium"])
            self.assertIsNone(result["delivery_destination"])
            record_lockout_failure.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called_once()


    def test_register_start_rejects_contextual_password(self):
        with self.assertRaises(Exception):
            RegisterStartReq(
                full_name="Jane Doe",
                email="jane@example.com",
                password="jane-secure-passphrase",
                confirm_password="jane-secure-passphrase",
            )

    def test_register_start_rejects_short_password(self):
        with self.assertRaises(Exception):
            RegisterStartReq(
                full_name="Jane Doe",
                email="jane@example.com",
                password="short123",
                confirm_password="short123",
            )


    def test_register_check_is_generic_for_available_and_unavailable(self):
        req = build_request()
        with patch.object(register, "is_email_available", return_value=True):
            available = run_async(register.register_check(req, RegisterEmailCheckReq(email="jane@example.com")))
        with patch.object(register, "is_email_available", return_value=False):
            unavailable = run_async(register.register_check(req, RegisterEmailCheckReq(email="jane@example.com")))
        self.assertEqual(available, unavailable)
        self.assertEqual(available, {"status": "ok", "available": True})

    def test_register_check_times_out_without_hanging(self):
        req = build_request()

        async def slow_run_in_threadpool(*_args, **_kwargs):
            await asyncio.sleep(0.02)
            return True

        with patch.object(register, "run_in_threadpool", new=slow_run_in_threadpool), \
             patch.object(register, "REGISTER_CHECK_TIMEOUT_SECONDS", 0.001), \
             patch.object(register, "record_lockout_failure") as record_lockout_failure, \
             patch.object(register, "audit_event") as audit_event:
            result = run_async(register.register_check(req, RegisterEmailCheckReq(email="jane@example.com")))

        self.assertEqual(result, {"status": "ok", "available": True})
        record_lockout_failure.assert_called_once()
        self.assertTrue(any(call.kwargs.get("reason") == "check_timeout" for call in audit_event.mock_calls))


    def test_register_start_is_generic_on_signup_failure(self):
        req = build_request()
        with patch.object(register, "_cognito_available", return_value=True),              patch.object(register, "_require_cognito"),              patch.object(register, "check_password_breach", return_value=0),              patch.object(register, "cognito_sign_up", side_effect=HTTPException(409, "Exists")),              patch.object(register, "record_lockout_failure"):
            result = run_async(register.register_start(
                req,
                RegisterStartReq(
                    full_name="Jane Doe",
                    email="jane@example.com",
                    password="StrongPassphrase42!",
                    confirm_password="StrongPassphrase42!",
                ),
            ))
        self.assertEqual(result, {
            "status": "ok",
            "verification_required": True,
            "delivery_medium": None,
            "delivery_destination": None,
        })
