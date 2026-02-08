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
    def test_register_start_dev_demo(self):
        req = build_request()
        config = register._dev_registration_config()
        assert config is not None
        with patch.object(register, "_require_cognito") as require_cognito, \
             patch.object(register, "create_user_record") as create_user_record:
            result = run_async(register.register_start(
                req,
                RegisterStartReq(
                    full_name="Demo User",
                    email=config["email"],
                    password=config["password"],
                    confirm_password=config["password"],
                ),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["verification_required"])
            self.assertEqual(result["delivery_medium"], "email")
            require_cognito.assert_not_called()
            create_user_record.assert_not_called()

    def test_register_confirm_dev_demo(self):
        req = build_request()
        config = register._dev_registration_config()
        assert config is not None
        with patch.object(register, "_require_cognito") as require_cognito:
            result = run_async(register.register_confirm(
                req,
                RegisterConfirmReq(
                    email=config["email"],
                    confirmation_code=config["code"],
                ),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["session_id"], "dev-session")
            require_cognito.assert_not_called()

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
                    password="Password\\d1",
                    confirm_password="Password\\d1",
                ),
            ))
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["verification_required"])
            self.assertEqual(result["delivery_medium"], "email")
            self.assertEqual(result["delivery_destination"], "jane@example.com")
            send_email_code.assert_called_once()
            clear_lockout.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called()

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
                    password="Password\\d1",
                    confirm_password="Password\\d1",
                ),
            ))
            self.assertTrue(result["verification_required"])
            self.assertEqual(result["delivery_medium"], "email")
            self.assertEqual(result["delivery_destination"], "jane@example.com")
            send_email_code.assert_called_once()
            clear_lockout.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called()

    def test_register_start_duplicate_user(self):
        req = build_request()
        with patch.object(register, "_require_cognito"), \
             patch.object(register, "check_password_breach", return_value=0), \
             patch.object(register, "cognito_sign_up", side_effect=HTTPException(400, "Exists")), \
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
                        password="Password\\d1",
                        confirm_password="Password\\d1",
                    ),
                ))
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
                        password="Password\\d1",
                        confirm_password="Password\\d1",
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
            self.assertEqual(result["delivery_medium"], "email")
            self.assertEqual(result["delivery_destination"], "jane@example.com")
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
            with self.assertRaises(HTTPException):
                run_async(register.register_resend(
                    req,
                    RegisterResendReq(email="jane@example.com", delivery_method="email"),
                ))
            record_lockout_failure.assert_called_once()
            enforce_lockout.assert_called_once()
            rate_limit_password_recovery.assert_called_once()
            audit_event.assert_called_once()
