import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from app.core.crypto import sha256_str
from app.models import (
    AlertEmailBeginReq,
    AlertEmailConfirmReq,
    AlertEmailPrefsReq,
    AlertEmailRemoveReq,
    AlertPushPrefsReq,
    AlertSmsBeginReq,
    AlertSmsConfirmReq,
    AlertSmsPrefsReq,
    AlertSmsRemoveReq,
    AlertToastPrefsReq,
    ApiKeyIpRulesReq,
    CreateApiKeyReq,
    EmailBeginReq,
    EmailVerifyReq,
    EmailDeviceBeginReq,
    EmailDeviceConfirmReq,
    EmailDeviceRemoveConfirmReq,
    MarkReadReq,
    PushRegisterReq,
    PushRevokeReq,
    RecoveryReq,
    PasswordRecoveryChallengeReq,
    PasswordRecoveryConfirmReq,
    PasswordRecoveryEmailVerifyReq,
    PasswordRecoveryRecoveryCodeReq,
    PasswordRecoverySmsVerifyReq,
    PasswordRecoveryStartReq,
    PasswordRecoveryTotpVerifyReq,
    RevokeApiKeyReq,
    SmsBeginReq,
    SmsDeviceBeginReq,
    SmsDeviceConfirmReq,
    SmsDeviceRemoveConfirmReq,
    SmsVerifyReq,
    TotpDeviceBeginReq,
    TotpDeviceConfirmReq,
    TotpDeviceRemoveReq,
    TotpVerifyReq,
    UiSessionFinalizeReq,
    UiSessionStartReq,
)
from app.routers import alerts, api_keys, misc, mfa_devices, password_recovery, push, recovery, ui_mfa, ui_session


def run_async(coro):
    return asyncio.run(coro)


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


def build_ctx():
    return {"user_sub": "user", "session_id": "sid"}


class TestUiSessionRoutes(unittest.TestCase):
    def test_ui_session_routes(self):
        sessions_table = Mock()
        sessions_table.query.return_value = {
            "Items": [
                {"session_id": "sid", "created_at": 1, "last_seen_at": 2},
                {"session_id": "other", "created_at": 2, "last_seen_at": 3},
            ]
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_session, "compute_required_factors", return_value=[]))
            stack.enter_context(patch.object(ui_session, "create_real_session", return_value="sid"))
            stack.enter_context(patch.object(ui_session, "create_stepup_challenge", return_value="chal"))
            stack.enter_context(patch.object(ui_session, "load_challenge_or_401", return_value={"passed": {}}))
            stack.enter_context(patch.object(ui_session, "maybe_finalize", return_value="sid"))
            stack.enter_context(patch.object(ui_session, "client_ip_from_request", return_value="203.0.113.1"))
            stack.enter_context(patch.object(ui_session, "audit_event"))
            stack.enter_context(patch.object(ui_session, "now_ts", return_value=100))
            stack.enter_context(patch.object(ui_session, "T", fake_tables))

            start_resp = run_async(ui_session.ui_session_start(req, UiSessionStartReq(), user_sub="user"))
            self.assertEqual(start_resp.session_id, "sid")

            finalize_resp = run_async(ui_session.ui_session_finalize(req, UiSessionFinalizeReq(challenge_id="chal"), user_sub="user"))
            self.assertEqual(finalize_resp["session_id"], "sid")

            me_resp = run_async(ui_session.ui_me(req, ctx=build_ctx()))
            self.assertEqual(me_resp["ip"], "203.0.113.1")

            sessions_resp = run_async(ui_session.ui_sessions(ctx=build_ctx()))
            self.assertEqual(len(sessions_resp["sessions"]), 2)

            revoke_resp = run_async(ui_session.ui_sessions_revoke(req, {"session_id": "other"}, ctx=build_ctx()))
            self.assertEqual(revoke_resp["status"], "ok")

            revoke_others = run_async(ui_session.ui_sessions_revoke_others(req, ctx=build_ctx()))
            self.assertEqual(revoke_others["status"], "ok")

    def test_ui_session_start_requires_mfa(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_session, "compute_required_factors", return_value=["totp"]))
            stack.enter_context(patch.object(ui_session, "create_stepup_challenge", return_value="chal"))
            stack.enter_context(patch.object(ui_session, "audit_event"))

            resp = run_async(ui_session.ui_session_start(req, UiSessionStartReq(), user_sub="user"))
            self.assertTrue(resp.auth_required)
            self.assertEqual(resp.challenge_id, "chal")

    def test_ui_session_finalize_pending(self):
        req = build_request()
        chal = {"required_factors": ["totp"], "passed": {"totp": False}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_session, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(ui_session, "maybe_finalize", return_value=None))
            stack.enter_context(patch.object(ui_session, "audit_event"))

            resp = run_async(ui_session.ui_session_finalize(req, UiSessionFinalizeReq(challenge_id="chal"), user_sub="user"))
            self.assertEqual(resp["status"], "pending")


class TestUiMfaRoutes(unittest.TestCase):
    def test_ui_mfa_routes(self):
        fake_tables = SimpleNamespace(sessions=Mock())
        chal = {"required_factors": ["totp", "sms", "email"], "email_code_hash": sha256_str("123456")}
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_mfa, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(ui_mfa, "totp_verify_any_enabled", return_value="dev"))
            stack.enter_context(patch.object(ui_mfa, "mark_factor_passed"))
            stack.enter_context(patch.object(ui_mfa, "maybe_finalize", return_value="sid"))
            stack.enter_context(patch.object(ui_mfa, "list_enabled_sms_numbers", return_value=["+14155550100"]))
            stack.enter_context(patch.object(ui_mfa, "list_enabled_emails", return_value=["user@example.com"]))
            stack.enter_context(patch.object(ui_mfa, "can_send_verification", return_value=True))
            stack.enter_context(patch.object(ui_mfa, "rate_limit_or_429"))
            stack.enter_context(patch.object(ui_mfa, "twilio_start_sms"))
            stack.enter_context(patch.object(ui_mfa, "twilio_check_sms", return_value=True))
            stack.enter_context(patch.object(ui_mfa, "gen_numeric_code", return_value="123456"))
            stack.enter_context(patch.object(ui_mfa, "send_email_code"))
            stack.enter_context(patch.object(ui_mfa, "consume_recovery_code"))
            stack.enter_context(patch.object(ui_mfa, "audit_event"))
            stack.enter_context(patch.object(ui_mfa, "T", fake_tables))

            totp_resp = run_async(ui_mfa.ui_totp_verify(req, TotpVerifyReq(challenge_id="chal", totp_code="123"), user_sub="user"))
            self.assertEqual(totp_resp["status"], "ok")

            sms_begin = run_async(ui_mfa.ui_sms_begin(req, SmsBeginReq(challenge_id="chal"), user_sub="user"))
            self.assertEqual(sms_begin["status"], "sent")

            sms_verify = run_async(ui_mfa.ui_sms_verify(req, SmsVerifyReq(challenge_id="chal", code="123"), user_sub="user"))
            self.assertEqual(sms_verify["status"], "ok")

            email_begin = run_async(ui_mfa.ui_email_begin(req, EmailBeginReq(challenge_id="chal"), user_sub="user"))
            self.assertEqual(email_begin["status"], "sent")

            email_verify = run_async(ui_mfa.ui_email_verify(req, EmailVerifyReq(challenge_id="chal", code="123456"), user_sub="user"))
            self.assertEqual(email_verify["status"], "ok")

            recovery_resp = run_async(ui_mfa.ui_recovery_factor(req, "sms", RecoveryReq(challenge_id="chal", recovery_code="code"), user_sub="user"))
            self.assertEqual(recovery_resp["status"], "ok")

    def test_ui_mfa_rejects_unrequired_factor(self):
        req = build_request()
        chal = {"required_factors": ["totp"]}
        with patch.object(ui_mfa, "load_challenge_or_401", return_value=chal):
            with self.assertRaises(HTTPException):
                run_async(ui_mfa.ui_sms_begin(req, SmsBeginReq(challenge_id="chal"), user_sub="user"))

    def test_ui_mfa_totp_bad_code_audits_failure(self):
        req = build_request()
        chal = {"required_factors": ["totp"]}
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_mfa, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(ui_mfa, "totp_verify_any_enabled", return_value=None))
            audit = stack.enter_context(patch.object(ui_mfa, "audit_event"))
            with self.assertRaises(HTTPException):
                run_async(ui_mfa.ui_totp_verify(req, TotpVerifyReq(challenge_id="chal", totp_code="000000"), user_sub="user"))

        audit.assert_called_once()
        self.assertEqual(audit.call_args.kwargs.get("outcome"), "failure")

    def test_ui_mfa_sms_bad_code_audits_failure(self):
        req = build_request()
        chal = {"required_factors": ["sms"]}
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_mfa, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(ui_mfa, "list_enabled_sms_numbers", return_value=["+14155550100"]))
            stack.enter_context(patch.object(ui_mfa, "twilio_check_sms", return_value=False))
            audit = stack.enter_context(patch.object(ui_mfa, "audit_event"))
            with self.assertRaises(HTTPException):
                run_async(ui_mfa.ui_sms_verify(req, SmsVerifyReq(challenge_id="chal", code="000000"), user_sub="user"))

        audit.assert_called_once()
        self.assertEqual(audit.call_args.kwargs.get("outcome"), "failure")

    def test_ui_mfa_email_bad_code_audits_failure(self):
        req = build_request()
        chal = {
            "required_factors": ["email"],
            "email_code_hash": sha256_str("123456"),
            "email_code_attempts": 0,
            "email_code_sent_at": 0,
        }
        fake_tables = SimpleNamespace(sessions=Mock())
        with ExitStack() as stack:
            stack.enter_context(patch.object(ui_mfa, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(ui_mfa, "now_ts", return_value=0))
            stack.enter_context(patch.object(ui_mfa, "T", fake_tables))
            audit = stack.enter_context(patch.object(ui_mfa, "audit_event"))
            with self.assertRaises(HTTPException):
                run_async(ui_mfa.ui_email_verify(req, EmailVerifyReq(challenge_id="chal", code="bad"), user_sub="user"))

        audit.assert_called_once()
        self.assertEqual(audit.call_args.kwargs.get("outcome"), "failure")


class TestMfaDeviceRoutes(unittest.TestCase):
    def test_mfa_device_routes(self):
        totp_table = Mock()
        totp_table.query.return_value = {"Items": [{"device_id": "d1", "created_at": 1}]}
        sms_table = Mock()
        sms_table.query.return_value = {"Items": []}
        sms_table.get_item.return_value = {"Item": {"phone_e164": "+14155550101"}}
        email_table = Mock()
        email_table.query.return_value = {"Items": []}
        email_table.get_item.return_value = {"Item": {"email": "user@example.com"}}
        fake_tables = SimpleNamespace(totp=totp_table, sms=sms_table, email=email_table)
        chal_sms = {"purpose": "sms_enroll", "send_to": ["+14155550100"], "sms_device_id": "sms_1"}
        chal_sms_remove = {"purpose": "sms_remove", "send_to": ["+14155550100"], "sms_device_id": "sms_1"}
        chal_email = {
            "purpose": "email_enroll",
            "email_device_id": "em_1",
            "email_code_hash": sha256_str("123456"),
        }
        chal_email_remove = {
            "purpose": "email_remove",
            "email_device_id": "em_1",
            "email_code_hash": sha256_str("123456"),
        }
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(mfa_devices, "totp_begin_enroll", return_value={"device_id": "d2"}))
            stack.enter_context(patch.object(mfa_devices, "totp_confirm_enroll"))
            stack.enter_context(patch.object(mfa_devices, "totp_verify_any_enabled", return_value=True))
            stack.enter_context(patch.object(mfa_devices, "rate_limit_or_429"))
            stack.enter_context(patch.object(mfa_devices, "list_enabled_sms_numbers", return_value=["+14155550100"]))
            stack.enter_context(patch.object(mfa_devices, "list_enabled_emails", return_value=["alt@example.com"]))
            stack.enter_context(patch.object(mfa_devices, "twilio_start_sms"))
            stack.enter_context(patch.object(mfa_devices, "verify_code_any_sms", return_value=True))
            stack.enter_context(patch.object(mfa_devices, "gen_numeric_code", return_value="123456"))
            stack.enter_context(patch.object(mfa_devices, "send_email_code"))
            stack.enter_context(patch.object(mfa_devices, "new_recovery_codes", return_value=["r1"]))
            stack.enter_context(patch.object(mfa_devices, "store_recovery_codes"))
            stack.enter_context(patch.object(mfa_devices, "create_action_challenge", return_value="chal"))
            stack.enter_context(patch.object(mfa_devices, "load_challenge_or_401", side_effect=[chal_sms, chal_sms_remove, chal_email, chal_email_remove]))
            stack.enter_context(patch.object(mfa_devices, "revoke_challenge"))
            stack.enter_context(patch.object(mfa_devices, "audit_event"))
            stack.enter_context(patch.object(mfa_devices, "T", fake_tables))

            totp_devices = run_async(mfa_devices.totp_devices(ctx=build_ctx()))
            self.assertEqual(len(totp_devices["devices"]), 1)

            totp_begin = run_async(mfa_devices.totp_devices_begin(req, TotpDeviceBeginReq(label="l"), ctx=build_ctx()))
            self.assertEqual(totp_begin["device_id"], "d2")

            totp_confirm = run_async(mfa_devices.totp_devices_confirm(req, TotpDeviceConfirmReq(device_id="d2", totp_code="123"), ctx=build_ctx()))
            self.assertEqual(totp_confirm["ok"], True)

            totp_remove = run_async(mfa_devices.totp_devices_remove(req, "d2", TotpDeviceRemoveReq(totp_code="123"), ctx=build_ctx()))
            self.assertEqual(totp_remove["ok"], True)

            sms_devices = run_async(mfa_devices.sms_devices(ctx=build_ctx()))
            self.assertIn("devices", sms_devices)

            sms_begin = run_async(mfa_devices.sms_devices_begin(req, SmsDeviceBeginReq(phone_e164="+14155550101", label="l"), ctx=build_ctx()))
            self.assertTrue(sms_begin["sms_device_id"].startswith("sms_"))

            sms_confirm = run_async(mfa_devices.sms_devices_confirm(req, SmsDeviceConfirmReq(challenge_id="chal", code="123"), ctx=build_ctx()))
            self.assertEqual(sms_confirm["ok"], True)

            sms_remove_begin = run_async(mfa_devices.sms_devices_remove_begin(req, "sms_1", ctx=build_ctx()))
            self.assertEqual(sms_remove_begin["challenge_id"], "chal")

            sms_remove_confirm = run_async(mfa_devices.sms_devices_remove_confirm(req, SmsDeviceRemoveConfirmReq(challenge_id="chal", code="123"), ctx=build_ctx()))
            self.assertEqual(sms_remove_confirm["ok"], True)

            email_devices = run_async(mfa_devices.email_devices(ctx=build_ctx()))
            self.assertIn("devices", email_devices)

            email_begin = run_async(mfa_devices.email_devices_begin(req, EmailDeviceBeginReq(email="user@example.com", label="l"), ctx=build_ctx()))
            self.assertTrue(email_begin["email_device_id"].startswith("em_"))

            email_confirm = run_async(mfa_devices.email_devices_confirm(req, EmailDeviceConfirmReq(challenge_id="chal", code="123456"), ctx=build_ctx()))
            self.assertEqual(email_confirm["ok"], True)

            email_remove_begin = run_async(mfa_devices.email_devices_remove_begin(req, "em_1", ctx=build_ctx()))
            self.assertEqual(email_remove_begin["challenge_id"], "chal")

            email_remove_confirm = run_async(mfa_devices.email_devices_remove_confirm(req, EmailDeviceRemoveConfirmReq(challenge_id="chal", code="123456"), ctx=build_ctx()))
            self.assertEqual(email_remove_confirm["ok"], True)

    def test_mfa_device_remove_requires_totp(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(mfa_devices, "totp_verify_any_enabled", return_value=False))
            with self.assertRaises(HTTPException):
                run_async(mfa_devices.totp_devices_remove(req, "d2", TotpDeviceRemoveReq(totp_code="123"), ctx=build_ctx()))


class TestApiKeysRoutes(unittest.TestCase):
    def test_api_keys_routes(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(api_keys, "list_api_keys", return_value=[{"key_id": "k1"}]))
            stack.enter_context(patch.object(api_keys, "create_api_key", return_value={"key_id": "k2"}))
            stack.enter_context(patch.object(api_keys, "revoke_api_key"))
            stack.enter_context(patch.object(api_keys, "set_api_key_ip_rules", return_value={"allow_cidrs": [], "deny_cidrs": []}))
            stack.enter_context(patch.object(api_keys, "audit_event"))

            list_resp = run_async(api_keys.ui_list_api_keys(ctx=build_ctx()))
            self.assertEqual(len(list_resp["keys"]), 1)

            create_resp = run_async(api_keys.ui_create_api_key(req, CreateApiKeyReq(label="label"), ctx=build_ctx()))
            self.assertEqual(create_resp["key_id"], "k2")

            revoke_resp = run_async(api_keys.ui_revoke_api_key(req, RevokeApiKeyReq(key_id="k1"), ctx=build_ctx()))
            self.assertEqual(revoke_resp["ok"], True)

            ip_rules = run_async(api_keys.ui_set_api_key_ip_rules(req, ApiKeyIpRulesReq(key_id="k1", allow_cidrs=["10.0.0.0/24"], deny_cidrs=[]), ctx=build_ctx()))
            self.assertEqual(ip_rules["ok"], True)

    def test_api_keys_empty_label(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(api_keys, "create_api_key", return_value={"key_id": "k3"}))
            stack.enter_context(patch.object(api_keys, "audit_event"))
            resp = run_async(api_keys.ui_create_api_key(req, CreateApiKeyReq(label=None), ctx=build_ctx()))
            self.assertEqual(resp["key_id"], "k3")


class TestAlertRoutes(unittest.TestCase):
    def test_alert_routes(self):
        alerts_table = Mock()
        alerts_table.query.return_value = {"Items": [], "LastEvaluatedKey": None}
        fake_tables = SimpleNamespace(alerts=alerts_table, sessions=Mock())
        prefs = {
            "sms_numbers": ["+14155550100"],
            "sms_event_types": ["login"],
            "email_event_types": ["login"],
            "toast_event_types": ["login"],
            "push_event_types": ["login"],
            "emails": ["user@example.com"],
        }
        sms_chal = {
            "purpose": "alert_sms_add",
            "sms_code_hash": sha256_str("123456"),
            "sms_code_attempts": 0,
            "sms_code_sent_at": 0,
            "phone": "+14155550100",
        }
        email_chal = {
            "purpose": "alert_email_add",
            "email_code_hash": sha256_str("123456"),
            "email_code_attempts": 0,
            "email_code_sent_at": 0,
            "email": "user@example.com",
        }
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(alerts, "decode_cursor", return_value=None))
            stack.enter_context(patch.object(alerts, "encode_cursor", return_value=None))
            stack.enter_context(patch.object(alerts, "get_alert_prefs", return_value=prefs))
            stack.enter_context(patch.object(alerts, "set_alert_prefs", return_value=prefs))
            stack.enter_context(patch.object(alerts, "send_alert_sms"))
            stack.enter_context(patch.object(alerts, "send_alert_email"))
            stack.enter_context(patch.object(alerts, "can_send_verification", return_value=True))
            stack.enter_context(patch.object(alerts, "create_action_challenge", return_value="chal"))
            stack.enter_context(patch.object(alerts, "load_challenge_or_401", side_effect=[sms_chal, email_chal]))
            stack.enter_context(patch.object(alerts, "revoke_challenge"))
            stack.enter_context(patch.object(alerts, "audit_event"))
            stack.enter_context(patch.object(alerts, "sse_subscribe", return_value=Mock()))
            stack.enter_context(patch.object(alerts, "sse_unsubscribe"))
            stack.enter_context(patch.object(alerts, "T", fake_tables))

            types_resp = run_async(alerts.alert_types(build_ctx()))
            self.assertIn("types", types_resp)

            list_resp = run_async(alerts.list_alerts(ctx=build_ctx()))
            self.assertIn("alerts", list_resp)

            mark_read = run_async(alerts.mark_read(MarkReadReq(alert_ids=["a1"]), ctx=build_ctx()))
            self.assertEqual(mark_read["ok"], True)

            email_prefs = run_async(alerts.get_email_prefs(ctx=build_ctx()))
            self.assertIn("email_event_types", email_prefs)

            email_prefs_set = run_async(alerts.set_email_prefs(AlertEmailPrefsReq(email_event_types=[]), ctx=build_ctx()))
            self.assertIn("email_event_types", email_prefs_set)

            sms_prefs = run_async(alerts.get_sms_prefs(ctx=build_ctx()))
            self.assertIn("sms_numbers", sms_prefs)

            sms_prefs_set = run_async(alerts.set_sms_prefs(AlertSmsPrefsReq(sms_event_types=[]), ctx=build_ctx()))
            self.assertIn("sms_event_types", sms_prefs_set)

            toast_prefs = run_async(alerts.get_toast_prefs(ctx=build_ctx()))
            self.assertIn("event_types", toast_prefs)

            toast_prefs_set = run_async(alerts.set_toast_prefs(AlertToastPrefsReq(toast_event_types=[]), ctx=build_ctx()))
            self.assertIn("toast_event_types", toast_prefs_set)

            push_prefs_set = run_async(alerts.set_push_prefs(AlertPushPrefsReq(push_event_types=[]), ctx=build_ctx()))
            self.assertIn("push_event_types", push_prefs_set)

            mark_toast = run_async(alerts.mark_toast_delivered({"alert_ids": ["a1"]}, ctx=build_ctx()))
            self.assertEqual(mark_toast["ok"], True)

            sms_begin = run_async(alerts.alert_sms_add_begin(req, AlertSmsBeginReq(phone="+14155550100"), ctx=build_ctx()))
            self.assertEqual(sms_begin["sent_to"], "+14155550100")

            sms_confirm = run_async(alerts.alert_sms_add_confirm(req, AlertSmsConfirmReq(challenge_id="chal", code="123456"), ctx=build_ctx()))
            self.assertIn("sms_numbers", sms_confirm)

            sms_remove = run_async(alerts.alert_sms_remove(req, AlertSmsRemoveReq(phone="+14155550100"), ctx=build_ctx()))
            self.assertIn("sms_numbers", sms_remove)

            email_begin = run_async(alerts.alert_email_add_begin(req, AlertEmailBeginReq(email="user@example.com"), ctx=build_ctx()))
            self.assertEqual(email_begin["sent_to"], "user@example.com")

            email_confirm = run_async(alerts.alert_email_add_confirm(req, AlertEmailConfirmReq(challenge_id="chal", code="123456"), ctx=build_ctx()))
            self.assertIn("emails", email_confirm)

            email_remove = run_async(alerts.alert_email_remove(req, AlertEmailRemoveReq(email="user@example.com"), ctx=build_ctx()))
            self.assertIn("emails", email_remove)

            stream_resp = run_async(alerts.alerts_stream(ctx=build_ctx()))
            self.assertIsInstance(stream_resp, StreamingResponse)

    def test_alert_confirm_bad_code_bumps_attempts(self):
        req = build_request()
        sms_chal = {
            "purpose": "alert_sms_add",
            "sms_code_hash": sha256_str("123456"),
            "sms_code_attempts": 0,
            "sms_code_sent_at": 0,
            "phone": "+14155550100",
        }
        with ExitStack() as stack:
            stack.enter_context(patch.object(alerts, "load_challenge_or_401", return_value=sms_chal))
            stack.enter_context(patch.object(alerts, "_bump_attempt"))
            stack.enter_context(patch.object(alerts, "audit_event"))
            with self.assertRaises(HTTPException):
                run_async(alerts.alert_sms_add_confirm(req, AlertSmsConfirmReq(challenge_id="chal", code="bad"), ctx=build_ctx()))


class TestPushRoutes(unittest.TestCase):
    def test_push_routes(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(push, "list_push_devices", return_value=[{"device_id": "d1"}]))
            stack.enter_context(patch.object(push, "upsert_push_device", return_value={"device_id": "d1"}))
            stack.enter_context(patch.object(push, "revoke_push_device"))
            stack.enter_context(patch.object(push, "send_push_for_alert"))
            stack.enter_context(patch.object(push, "audit_event"))
            stack.enter_context(patch.object(push, "S", SimpleNamespace(push_enabled=True)))

            list_resp = run_async(push.ui_list_push_devices(ctx=build_ctx()))
            self.assertEqual(len(list_resp["devices"]), 1)

            register_resp = run_async(push.ui_register_push(req, PushRegisterReq(token="t" * 25, platform="ios"), ctx=build_ctx()))
            self.assertEqual(register_resp["device_id"], "d1")

            revoke_resp = run_async(push.ui_revoke_push(req, PushRevokeReq(device_id="d1"), ctx=build_ctx()))
            self.assertEqual(revoke_resp["ok"], True)

            test_resp = run_async(push.ui_push_test(req, ctx=build_ctx()))
            self.assertEqual(test_resp["ok"], True)

    def test_push_register_rejects_short_token(self):
        req = build_request()
        with patch.object(push, "S", SimpleNamespace(push_enabled=True)):
            with self.assertRaises(HTTPException):
                run_async(push.ui_register_push(req, PushRegisterReq(token="short", platform="ios"), ctx=build_ctx()))


class TestRecoveryRoutes(unittest.TestCase):
    def test_recovery_routes(self):
        chal = {"required_factors": ["totp", "sms", "email"]}
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(recovery, "load_challenge_or_401", return_value=chal))
            stack.enter_context(patch.object(recovery, "consume_recovery_code"))
            stack.enter_context(patch.object(recovery, "mark_factor_passed"))
            stack.enter_context(patch.object(recovery, "maybe_finalize", return_value="sid"))
            stack.enter_context(patch.object(recovery, "audit_event"))

            resp = run_async(recovery.recovery_factor(req, "totp", RecoveryReq(challenge_id="chal", recovery_code="code"), user_sub="user"))
            self.assertEqual(resp["ok"], True)

            resp = run_async(recovery.recovery_totp(req, RecoveryReq(challenge_id="chal", recovery_code="code"), user_sub="user"))
            self.assertEqual(resp["ok"], True)

            resp = run_async(recovery.recovery_sms(req, RecoveryReq(challenge_id="chal", recovery_code="code"), user_sub="user"))
            self.assertEqual(resp["ok"], True)

            resp = run_async(recovery.recovery_email(req, RecoveryReq(challenge_id="chal", recovery_code="code"), user_sub="user"))
            self.assertEqual(resp["ok"], True)

    def test_recovery_rejects_invalid_factor(self):
        req = build_request()
        chal = {"required_factors": ["totp"]}
        with patch.object(recovery, "load_challenge_or_401", return_value=chal):
            with self.assertRaises(HTTPException):
                run_async(recovery.recovery_factor(req, "invalid", RecoveryReq(challenge_id="chal", recovery_code="code"), user_sub="user"))


class TestPasswordRecoveryRoutes(unittest.TestCase):
    def test_password_recovery_start_and_confirm(self):
        req = build_request()
        fake_tables = SimpleNamespace(sessions=Mock())
        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "S", SimpleNamespace(cognito_app_client_id="cid")))
            stack.enter_context(patch.object(password_recovery, "cognito_forgot_password", return_value={"CodeDeliveryDetails": {"DeliveryMedium": "EMAIL", "Destination": "u***@e.com"}}))
            stack.enter_context(patch.object(password_recovery, "compute_required_factors", return_value=["sms"]))
            stack.enter_context(patch.object(password_recovery, "create_stepup_challenge", return_value="chal"))
            stack.enter_context(patch.object(password_recovery, "audit_event"))
            stack.enter_context(patch.object(password_recovery, "T", fake_tables))

            resp = run_async(password_recovery.password_recovery_start(req, PasswordRecoveryStartReq(username="user")))
            self.assertEqual(resp["challenge_id"], "chal")
            self.assertEqual(resp["required_factors"], ["sms"])

        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "S", SimpleNamespace(cognito_app_client_id="cid")))
            stack.enter_context(patch.object(password_recovery, "compute_required_factors", return_value=["sms"]))
            stack.enter_context(patch.object(password_recovery, "load_challenge_or_401", return_value={"required_factors": ["sms"], "passed": {"sms": True}, "purpose": "password_recovery"}))
            stack.enter_context(patch.object(password_recovery, "revoke_challenge"))
            confirm = stack.enter_context(patch.object(password_recovery, "cognito_confirm_forgot_password"))
            stack.enter_context(patch.object(password_recovery, "audit_event"))

            resp = run_async(password_recovery.password_recovery_confirm(
                req,
                PasswordRecoveryConfirmReq(
                    username="user",
                    confirmation_code="123456",
                    new_password="N3wPass!123",
                    challenge_id="chal",
                ),
            ))
            self.assertEqual(resp["status"], "ok")
            confirm.assert_called_once()

    def test_password_recovery_challenge_routes(self):
        req = build_request()
        chal = {"required_factors": ["totp", "sms", "email"], "purpose": "password_recovery"}
        email_code = "123456"
        email_chal = {
            **chal,
            "email_code_hash": sha256_str(email_code),
            "email_code_attempts": 0,
            "email_code_sent_at": 0,
        }
        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "S", SimpleNamespace(
                cognito_app_client_id="cid",
                sms_device_limit=3,
                email_device_limit=5,
                email_code_max_attempts=5,
                email_code_attempt_window_seconds=600,
            )))
            stack.enter_context(patch.object(password_recovery, "load_challenge_or_401", side_effect=[chal, chal, chal, chal, email_chal, chal]))
            stack.enter_context(patch.object(password_recovery, "totp_verify_any_enabled", return_value="dev"))
            stack.enter_context(patch.object(password_recovery, "mark_factor_passed"))
            stack.enter_context(patch.object(password_recovery, "audit_event"))
            stack.enter_context(patch.object(password_recovery, "list_enabled_sms_numbers", return_value=["+14155550100"]))
            stack.enter_context(patch.object(password_recovery, "can_send_verification", return_value=True))
            stack.enter_context(patch.object(password_recovery, "rate_limit_or_429"))
            stack.enter_context(patch.object(password_recovery, "twilio_start_sms"))
            stack.enter_context(patch.object(password_recovery, "twilio_check_sms", return_value=True))
            stack.enter_context(patch.object(password_recovery, "list_enabled_emails", return_value=["user@example.com"]))
            stack.enter_context(patch.object(password_recovery, "gen_numeric_code", return_value=email_code))
            stack.enter_context(patch.object(password_recovery, "send_email_code"))
            stack.enter_context(patch.object(password_recovery, "consume_recovery_code"))
            stack.enter_context(patch.object(password_recovery, "now_ts", return_value=0))
            stack.enter_context(patch.object(password_recovery, "T", SimpleNamespace(sessions=Mock())))

            resp = run_async(password_recovery.password_recovery_totp_verify(req, PasswordRecoveryTotpVerifyReq(username="user", challenge_id="chal", totp_code="123456")))
            self.assertEqual(resp["status"], "ok")

            resp = run_async(password_recovery.password_recovery_sms_begin(req, PasswordRecoveryChallengeReq(username="user", challenge_id="chal")))
            self.assertEqual(resp["status"], "sent")

            resp = run_async(password_recovery.password_recovery_sms_verify(req, PasswordRecoverySmsVerifyReq(username="user", challenge_id="chal", code="123456")))
            self.assertEqual(resp["status"], "ok")

            resp = run_async(password_recovery.password_recovery_email_begin(req, PasswordRecoveryChallengeReq(username="user", challenge_id="chal")))
            self.assertEqual(resp["status"], "sent")

            resp = run_async(password_recovery.password_recovery_email_verify(req, PasswordRecoveryEmailVerifyReq(username="user", challenge_id="chal", code=email_code)))
            self.assertEqual(resp["status"], "ok")

            resp = run_async(password_recovery.password_recovery_code(req, PasswordRecoveryRecoveryCodeReq(username="user", challenge_id="chal", factor="sms", recovery_code="code")))
            self.assertEqual(resp["status"], "ok")

    def test_password_recovery_confirm_requires_completed_challenge(self):
        req = build_request()
        pending = {"required_factors": ["sms"], "passed": {"sms": False}, "purpose": "password_recovery"}
        complete = {"required_factors": ["sms"], "passed": {"sms": True}, "purpose": "password_recovery"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "S", SimpleNamespace(cognito_app_client_id="cid")))
            stack.enter_context(patch.object(password_recovery, "compute_required_factors", return_value=["sms"]))
            stack.enter_context(patch.object(password_recovery, "load_challenge_or_401", side_effect=[pending, complete]))
            stack.enter_context(patch.object(password_recovery, "revoke_challenge"))
            confirm = stack.enter_context(patch.object(password_recovery, "cognito_confirm_forgot_password"))
            stack.enter_context(patch.object(password_recovery, "audit_event"))

            with self.assertRaises(HTTPException):
                run_async(password_recovery.password_recovery_confirm(
                    req,
                    PasswordRecoveryConfirmReq(
                        username="user",
                        confirmation_code="123456",
                        new_password="N3wPass!123",
                        challenge_id="chal",
                    ),
                ))

            resp = run_async(password_recovery.password_recovery_confirm(
                req,
                PasswordRecoveryConfirmReq(
                    username="user",
                    confirmation_code="123456",
                    new_password="N3wPass!123",
                    challenge_id="chal",
                ),
            ))
            self.assertEqual(resp["status"], "ok")
            confirm.assert_called_once()

    def test_password_recovery_rejects_wrong_purpose(self):
        req = build_request()
        wrong_purpose = {"required_factors": ["sms"], "passed": {"sms": True}, "purpose": "other"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "S", SimpleNamespace(cognito_app_client_id="cid")))
            stack.enter_context(patch.object(password_recovery, "compute_required_factors", return_value=["sms"]))
            stack.enter_context(patch.object(password_recovery, "load_challenge_or_401", return_value=wrong_purpose))
            stack.enter_context(patch.object(password_recovery, "audit_event"))
            with self.assertRaises(HTTPException):
                run_async(password_recovery.password_recovery_confirm(
                    req,
                    PasswordRecoveryConfirmReq(
                        username="user",
                        confirmation_code="123456",
                        new_password="N3wPass!123",
                        challenge_id="chal",
                    ),
                ))

    def test_password_recovery_rejects_missing_challenge(self):
        req = build_request()
        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "S", SimpleNamespace(cognito_app_client_id="cid")))
            stack.enter_context(patch.object(password_recovery, "compute_required_factors", return_value=["sms"]))
            stack.enter_context(patch.object(password_recovery, "audit_event"))
            with self.assertRaises(HTTPException):
                run_async(password_recovery.password_recovery_confirm(
                    req,
                    PasswordRecoveryConfirmReq(
                        username="user",
                        confirmation_code="123456",
                        new_password="N3wPass!123",
                        challenge_id=None,
                    ),
                ))

    def test_password_recovery_rejects_unrequired_factor(self):
        req = build_request()
        chal = {"required_factors": ["sms"], "purpose": "password_recovery"}
        with ExitStack() as stack:
            stack.enter_context(patch.object(password_recovery, "load_challenge_or_401", return_value=chal))
            with self.assertRaises(HTTPException):
                run_async(password_recovery.password_recovery_totp_verify(
                    req,
                    PasswordRecoveryTotpVerifyReq(username="user", challenge_id="chal", totp_code="123456"),
                ))


class TestMiscRoutes(unittest.TestCase):
    def test_misc_routes(self):
        with patch.object(misc, "mint_ws_token", return_value="token"):
            ws_resp = run_async(misc.ui_ws_token(ctx=build_ctx()))
            self.assertEqual(ws_resp["token"], "token")

        ping_resp = run_async(misc.ping())
        self.assertEqual(ping_resp["ok"], True)

    def test_misc_ws_token_uses_context(self):
        with patch.object(misc, "mint_ws_token", return_value="token"):
            resp = run_async(misc.ui_ws_token(ctx=build_ctx()))
            self.assertIn("token", resp)


if __name__ == "__main__":
    unittest.main()
