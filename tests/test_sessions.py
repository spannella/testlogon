import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.services import sessions as sessions_service


def run_async(coro):
    return asyncio.run(coro)


class TestIsRealUiSessionId(unittest.TestCase):
    def test_rejects_challenge_prefix(self):
        self.assertFalse(sessions_service.is_real_ui_session_id("chal_123"))

    def test_rejects_rate_limit_prefix(self):
        self.assertFalse(sessions_service.is_real_ui_session_id("rl#123"))

    def test_rejects_underscore(self):
        self.assertFalse(sessions_service.is_real_ui_session_id("abc_def"))

    def test_accepts_uuid(self):
        self.assertTrue(sessions_service.is_real_ui_session_id("123e4567-e89b-12d3-a456-426614174000"))


class TestChallengeDone(unittest.TestCase):
    def test_challenge_done_true_when_all_passed(self):
        chal = {"required_factors": ["totp", "sms"], "passed": {"totp": True, "sms": True}}
        self.assertTrue(sessions_service.challenge_done(chal))

    def test_challenge_done_false_when_missing(self):
        chal = {"required_factors": ["totp", "sms"], "passed": {"totp": True}}
        self.assertFalse(sessions_service.challenge_done(chal))


class TestMaybeFinalize(unittest.TestCase):
    def test_maybe_finalize_skips_purpose_challenge(self):
        chal = {"required_factors": [], "passed": {}, "purpose": "account_closure"}
        with patch.object(sessions_service, "load_challenge_or_401", return_value=chal), patch.object(
            sessions_service, "challenge_done", return_value=True
        ), patch.object(sessions_service, "create_real_session") as create_real_session:
            resp = sessions_service.maybe_finalize(Mock(), "user", "chal")

        self.assertIsNone(resp)
        create_real_session.assert_not_called()


class TestMaybeFinalize(unittest.TestCase):
    def test_maybe_finalize_skips_purpose_challenge(self):
        chal = {"required_factors": [], "passed": {}, "purpose": "account_closure"}
        with patch.object(sessions_service, "load_challenge_or_401", return_value=chal), patch.object(
            sessions_service, "challenge_done", return_value=True
        ), patch.object(sessions_service, "create_real_session") as create_real_session:
            resp = sessions_service.maybe_finalize(Mock(), "user", "chal")

        self.assertIsNone(resp)
        create_real_session.assert_not_called()


class TestComputeRequiredFactors(unittest.TestCase):
    def test_compute_required_factors_uses_tables(self):
        totp_table = Mock()
        sms_table = Mock()
        email_table = Mock()
        totp_table.query.return_value = {"Items": [{"enabled": True}]}
        sms_table.query.return_value = {"Items": [{"enabled": False}]}
        email_table.query.return_value = {"Items": [{"enabled": True}]}

        fake_tables = SimpleNamespace(totp=totp_table, sms=sms_table, email=email_table)
        with patch.object(sessions_service, "T", fake_tables):
            required = sessions_service.compute_required_factors("user-sub")

        self.assertEqual(required, ["totp", "email"])
        totp_table.query.assert_called_once()
        sms_table.query.assert_called_once()
        email_table.query.assert_called_once()


class TestRequireUiSession(unittest.TestCase):
    def setUp(self):
        self.request = SimpleNamespace(headers={}, client=None, state=SimpleNamespace())

    def test_require_ui_session_missing_header(self):
        with self.assertRaises(HTTPException):
            run_async(sessions_service.require_ui_session(self.request, user_sub="user", x_session_id=None))

    def test_require_ui_session_unknown_session(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {}
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables):
            with self.assertRaises(HTTPException):
                run_async(sessions_service.require_ui_session(self.request, user_sub="user", x_session_id="sid"))

    def test_require_ui_session_success_sets_state(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {
            "Item": {"revoked": False, "pending_auth": False, "last_seen_at": 0}
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "now_ts", return_value=1000
        ):
            result = run_async(
                sessions_service.require_ui_session(self.request, user_sub="user", x_session_id="sid")
            )

        self.assertEqual(result, {"user_sub": "user", "session_id": "sid"})
        self.assertEqual(self.request.state.user_sub, "user")
        sessions_table.update_item.assert_called_once()

    def test_require_ui_session_rejects_revoked(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {
            "Item": {"revoked": True, "pending_auth": False, "last_seen_at": 0}
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables):
            with self.assertRaises(HTTPException):
                run_async(sessions_service.require_ui_session(self.request, user_sub="user", x_session_id="sid"))

    def test_require_ui_session_rejects_pending(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {
            "Item": {"revoked": False, "pending_auth": True, "last_seen_at": 0}
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables):
            with self.assertRaises(HTTPException):
                run_async(sessions_service.require_ui_session(self.request, user_sub="user", x_session_id="sid"))

    def test_require_ui_session_expires_inactive_session(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {
            "Item": {"revoked": False, "pending_auth": False, "last_seen_at": 1}
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        fake_settings = SimpleNamespace(ui_inactivity_seconds=10)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "S", fake_settings
        ), patch.object(sessions_service, "now_ts", return_value=1000):
            with self.assertRaises(HTTPException):
                run_async(sessions_service.require_ui_session(self.request, user_sub="user", x_session_id="sid"))

        sessions_table.update_item.assert_called_once()


class TestSessionCreation(unittest.TestCase):
    def setUp(self):
        self.request = SimpleNamespace(headers={"user-agent": "agent"}, client=None)

    def test_create_real_session_persists_session(self):
        sessions_table = Mock()
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "now_ts", return_value=100
        ), patch.object(sessions_service, "client_ip_from_request", return_value="203.0.113.9"), patch.object(
            sessions_service, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
        ):
            session_id = sessions_service.create_real_session(self.request, "user")

        self.assertTrue(sessions_service.is_real_ui_session_id(session_id))
        sessions_table.put_item.assert_called_once()
        args = sessions_table.put_item.call_args.kwargs["Item"]
        self.assertEqual(args["user_sub"], "user")
        self.assertEqual(args["ip"], "203.0.113.9")
        self.assertFalse(args["revoked"])

    def test_create_stepup_challenge_sets_required_factors(self):
        sessions_table = Mock()
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "now_ts", return_value=200
        ), patch.object(sessions_service, "client_ip_from_request", return_value="203.0.113.8"), patch.object(
            sessions_service, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
        ):
            challenge_id = sessions_service.create_stepup_challenge(
                self.request, "user", required_factors=["totp", "sms"]
            )

        self.assertTrue(challenge_id.startswith("chal_"))
        payload = sessions_table.put_item.call_args.kwargs["Item"]
        self.assertEqual(payload["required_factors"], ["totp", "sms"])
        self.assertEqual(payload["passed"], {"totp": False, "sms": False})

    def test_create_action_challenge_includes_payload(self):
        sessions_table = Mock()
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "now_ts", return_value=300
        ), patch.object(sessions_service, "client_ip_from_request", return_value="203.0.113.7"), patch.object(
            sessions_service, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}
        ):
            challenge_id = sessions_service.create_action_challenge(
                self.request,
                "user",
                purpose="verify",
                send_to=["example@example.com"],
                payload={"k": "v"},
                ttl_seconds=60,
            )

        self.assertTrue(challenge_id.startswith("verify_"))
        payload = sessions_table.put_item.call_args.kwargs["Item"]
        self.assertEqual(payload["send_to"], ["example@example.com"])
        self.assertEqual(payload["k"], "v")


class TestChallengeLoading(unittest.TestCase):
    def test_load_challenge_or_401_rejects_expired(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {
            "Item": {"revoked": False, "pending_auth": True, "expires_at": 50}
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "now_ts", return_value=100
        ):
            with self.assertRaises(HTTPException):
                sessions_service.load_challenge_or_401("user", "chal_1")

        sessions_table.update_item.assert_called_once()

    def test_load_challenge_or_401_returns_valid(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {
            "Item": {"revoked": False, "pending_auth": True, "expires_at": 500}
        }
        fake_tables = SimpleNamespace(sessions=sessions_table)
        with patch.object(sessions_service, "T", fake_tables), patch.object(
            sessions_service, "now_ts", return_value=100
        ):
            chal = sessions_service.load_challenge_or_401("user", "chal_2")

        self.assertEqual(chal["expires_at"], 500)


class TestFinalize(unittest.TestCase):
    def test_maybe_finalize_returns_none_when_incomplete(self):
        chal = {"required_factors": ["sms"], "passed": {"sms": False}}
        with patch.object(sessions_service, "load_challenge_or_401", return_value=chal):
            result = sessions_service.maybe_finalize(SimpleNamespace(), "user", "chal_1")

        self.assertIsNone(result)

    def test_maybe_finalize_creates_session_when_complete(self):
        chal = {"required_factors": ["sms"], "passed": {"sms": True}}
        with patch.object(sessions_service, "load_challenge_or_401", return_value=chal), patch.object(
            sessions_service, "create_real_session", return_value="sid_1"
        ) as create_session, patch.object(sessions_service, "revoke_challenge") as revoke:
            result = sessions_service.maybe_finalize(SimpleNamespace(), "user", "chal_1")

        self.assertEqual(result, "sid_1")
        create_session.assert_called_once()
        revoke.assert_called_once_with("user", "chal_1")


if __name__ == "__main__":
    unittest.main()
