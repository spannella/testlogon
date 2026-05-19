import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException, Response

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

        self.assertEqual(result, {"user_sub": "user", "session_id": "sid", "role": "user", "ip": ""})
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


class TestRefreshTokenRotation(unittest.TestCase):
    def test_rotate_refresh_token_uses_session_refresh_ttl(self):
        sessions_table = Mock()
        token = "refresh"
        hashed = sessions_service.sha256_str(token)
        sessions_table.get_item.return_value = {"Item": {"refresh_token_hash": hashed, "refresh_ttl_seconds": 1234}}
        with patch.object(sessions_service, "T", SimpleNamespace(sessions=sessions_table)),              patch.object(sessions_service, "_issue_refresh_token") as issue,              patch.object(sessions_service, "mint_access_token", return_value="access"):
            resp = Response()
            sessions_service.rotate_refresh_token(resp, "user", "sid", token)
        issue.assert_called_once_with(resp, "sid", "user", refresh_ttl_seconds=1234)

    def test_rotate_refresh_token_rejects_invalid_hash(self):
        sessions_table = Mock()
        sessions_table.get_item.return_value = {"Item": {"refresh_token_hash": "other"}}
        with patch.object(sessions_service, "T", SimpleNamespace(sessions=sessions_table)):
            with self.assertRaises(HTTPException):
                sessions_service.rotate_refresh_token(Response(), "user", "sid", "bad")

class TestRootSessionHardening(unittest.TestCase):
    def test_create_real_session_uses_shorter_root_ttl(self):
        sessions_table = Mock()
        fake_tables = SimpleNamespace(sessions=sessions_table)
        fake_settings = SimpleNamespace(
            ui_session_ttl_seconds=3600,
            root_session_ttl_seconds=300,
            root_refresh_token_ttl_seconds=120,
            root_user_sub="root-user",
            ui_refresh_token_ttl_seconds=3600,
            login_anomaly_risk_score_threshold=1,
        )
        req = SimpleNamespace(headers={}, client=None)
        with patch.object(sessions_service, "T", fake_tables), patch.object(sessions_service, "S", fake_settings), patch.object(
            sessions_service, "now_ts", return_value=1000
        ), patch.object(sessions_service, "with_ttl", side_effect=lambda item, ttl_epoch: {**item, "ttl_epoch": ttl_epoch}), patch.object(
            sessions_service, "record_device_login"
        ), patch.object(sessions_service, "record_session_created"):
            sessions_service.create_real_session(req, "root-user")
            sessions_service.create_real_session(req, "normal-user")

        first = sessions_table.put_item.call_args_list[0].kwargs["Item"]
        second = sessions_table.put_item.call_args_list[1].kwargs["Item"]
        self.assertEqual(first["ttl_epoch"], 1300)
        self.assertEqual(second["ttl_epoch"], 4600)

    def test_mint_access_token_embeds_root_assurance_claims(self):
        fake_settings = SimpleNamespace(
            ui_access_token_secret="secret",
            ui_access_token_ttl_seconds=900,
            root_access_token_ttl_seconds=120,
            root_user_sub="root-user",
        )
        with patch.object(sessions_service, "S", fake_settings), patch.object(sessions_service, "now_ts", return_value=1000):
            token = sessions_service.mint_access_token("root-user", "sid-1")

        payload = sessions_service.jwt.decode(token, "secret", algorithms=["HS256"], options={"verify_exp": False})
        self.assertEqual(payload["role"], "root")
        self.assertEqual(payload["auth_level"], "high")
        self.assertEqual(payload["exp"], 1120)

    def test_rotate_existing_session_rotates_on_elevation(self):
        req = SimpleNamespace(cookies={"ui_session": "old-sid"})
        resp = Response()
        ctx = {"user_sub": "root-user", "session_id": "old-sid"}
        with patch.object(sessions_service, "create_real_session", return_value=sessions_service.SessionInfo("new-sid", "csrf", "root-user")) as create_session, patch.object(
            sessions_service, "revoke_session"
        ) as revoke, patch.object(sessions_service, "set_session_cookies"), patch.object(
            sessions_service, "ensure_device_cookie"
        ):
            sessions_service.rotate_existing_session(req, resp, ctx, mfa_verified_at=123)

        create_session.assert_called_once()
        revoke.assert_called_once_with("root-user", "old-sid")


class TestImpersonationSessionContext(unittest.TestCase):
    def test_require_ui_session_includes_impersonation_context(self):
        req = SimpleNamespace(headers={}, client=None, state=SimpleNamespace(), cookies={})
        sessions_table = Mock()

        def fake_get_item(Key):
            if Key["session_id"] == "sid":
                return {"Item": {"revoked": False, "pending_auth": False, "last_seen_at": 0}}
            if Key["session_id"] == "imp_1":
                return {"Item": {"purpose": "impersonation", "revoked": False, "expires_at": 2000}}
            return {}

        sessions_table.get_item.side_effect = fake_get_item
        fake_tables = SimpleNamespace(sessions=sessions_table)
        fake_settings = SimpleNamespace(
            ui_access_token_cookie_name="ui_access_token",
            ui_access_token_secret="secret",
            ui_session_cookie_name="ui_session",
            ui_inactivity_seconds=0,
            ddb_ttl_attr="ttl_epoch",
            ddb_sessions_table="",
            ui_csrf_header_name="x-csrf-token",
            ui_csrf_cookie_name="ui_csrf",
        )
        token = sessions_service.jwt.encode(
            {"impersonation": True, "actor_sub": "user", "effective_sub": "target", "sid": "imp_1", "exp": 9999999999},
            "secret",
            algorithm="HS256",
        )
        with patch.object(sessions_service, "T", fake_tables), patch.object(sessions_service, "S", fake_settings), patch.object(
            sessions_service, "now_ts", return_value=1000
        ):
            result = run_async(sessions_service.require_ui_session(req, user_sub="user", x_session_id="sid", x_impersonation_token=token))

        self.assertEqual(result["actor_sub"], "user")
        self.assertEqual(result["effective_sub"], "target")
        self.assertEqual(result["impersonation_id"], "imp_1")

    def test_require_ui_session_rejects_expired_impersonation_session(self):
        req = SimpleNamespace(headers={}, client=None, state=SimpleNamespace(), cookies={})
        sessions_table = Mock()

        def fake_get_item(Key):
            if Key["session_id"] == "sid":
                return {"Item": {"revoked": False, "pending_auth": False, "last_seen_at": 0}}
            if Key["session_id"] == "imp_1":
                return {"Item": {"purpose": "impersonation", "revoked": False, "expires_at": 900}}
            return {}

        sessions_table.get_item.side_effect = fake_get_item
        fake_tables = SimpleNamespace(sessions=sessions_table)
        fake_settings = SimpleNamespace(
            ui_access_token_cookie_name="ui_access_token",
            ui_access_token_secret="secret",
            ui_session_cookie_name="ui_session",
            ui_inactivity_seconds=0,
            ddb_ttl_attr="ttl_epoch",
            ddb_sessions_table="",
            ui_csrf_header_name="x-csrf-token",
            ui_csrf_cookie_name="ui_csrf",
        )
        token = sessions_service.jwt.encode(
            {"impersonation": True, "actor_sub": "user", "effective_sub": "target", "sid": "imp_1", "exp": 9999999999},
            "secret",
            algorithm="HS256",
        )
        with patch.object(sessions_service, "T", fake_tables), patch.object(sessions_service, "S", fake_settings), patch.object(
            sessions_service, "now_ts", return_value=1000
        ):
            with self.assertRaises(HTTPException) as ctx:
                run_async(sessions_service.require_ui_session(req, user_sub="user", x_session_id="sid", x_impersonation_token=token))

        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(str(ctx.exception.detail), "impersonation_expired")
