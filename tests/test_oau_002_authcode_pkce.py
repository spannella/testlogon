"""OAU-002: Hermetic tests for authorization-code + PKCE flow.

Tests: auth-code issuance, token exchange, replay protection, PKCE mismatch,
wrong secret, refresh-token rotation, DirectLogin, OAuth bearer auth branch.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
import jwt
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T, _FloatSafeTable


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _set_settings(stack: ExitStack, **overrides) -> None:
    for key, value in overrides.items():
        original = getattr(S, key)
        object.__setattr__(S, key, value)
        stack.callback(object.__setattr__, S, key, original)


def _make_table(ddb):
    return ddb.create_table(
        TableName="oauth_consumers",
        KeySchema=[
            {"AttributeName": "client_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "client_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "ByOwner",
            "KeySchema": [
                {"AttributeName": "owner_sub", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _make_pkce():
    import secrets
    verifier = secrets.token_urlsafe(32)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class TestAuthCodePkce(unittest.TestCase):

    def setUp(self):
        self.mock_ctx = mock_aws()
        self.mock_ctx.__enter__()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(self.mock_ctx.__exit__, None, None, None)
        orig_table = getattr(T, "oauth_consumers", None)
        object.__setattr__(T, "oauth_consumers", _FloatSafeTable(table))
        self.addCleanup(object.__setattr__, T, "oauth_consumers", orig_table)
        _set_settings(
            self.stack,
            oauth_provider_enabled=True,
            open_bank_project_enabled=True,
            api_key_pepper="test-pepper-oau",
            oauth_consumers_owner_index="ByOwner",
            ws_token_secret="test-ws-secret-oau",
            ui_access_token_secret="test-access-secret-oau",
            oauth_code_ttl_seconds=60,
            oauth_access_token_ttl_seconds=900,
            oauth_refresh_token_ttl_seconds=2592000,
            oauth_always_issue_refresh_token=False,
            oauth_provider_directlogin_enabled=False,
            oauth_provider_oidc_enabled=False,
        )
        # Create a test consumer
        from app.services.oauth_consumers import create_consumer
        self.consumer_result = create_consumer(
            "alice",
            name="TestApp",
            redirect_uris=["https://app.example.com/cb"],
            allowed_scopes=["openid", "messager:read", "offline_access"],
        )
        self.client_id = self.consumer_result["client_id"]
        self.client_secret_plain = self.consumer_result["client_secret"].split(".", 1)[1]
        self.redirect_uri = "https://app.example.com/cb"

    def test_issue_auth_code(self):
        from app.services.oauth_auth_flow import issue_auth_code
        _, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        self.assertIsInstance(code, str)
        self.assertIn(".", code)

    def test_full_authcode_pkce_flow(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        verifier, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        result = exchange_code_for_tokens(
            code=code,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code_verifier=verifier,
            client_secret=self.client_secret_plain,
        )
        self.assertIn("access_token", result)
        self.assertEqual(result["token_type"], "bearer")
        self.assertIn("scope", result)
        # Decode and verify access token claims
        payload = jwt.decode(
            result["access_token"],
            S.ui_access_token_secret,
            algorithms=["HS256"],
        )
        self.assertEqual(payload["sub"], "alice")
        self.assertEqual(payload["client_id"], self.client_id)
        self.assertEqual(payload["token_type"], "access")
        self.assertGreater(payload["exp"], 0)

    def test_replayed_code_rejected(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        from fastapi import HTTPException
        verifier, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        exchange_code_for_tokens(
            code=code,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code_verifier=verifier,
            client_secret=self.client_secret_plain,
        )
        # Second use
        with self.assertRaises(HTTPException) as ctx:
            exchange_code_for_tokens(
                code=code,
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                code_verifier=verifier,
                client_secret=self.client_secret_plain,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_grant", str(ctx.exception.detail))

    def test_pkce_mismatch_rejected(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        from fastapi import HTTPException
        _, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        # Use wrong verifier
        wrong_verifier = "wrong-verifier-value"
        with self.assertRaises(HTTPException) as ctx:
            exchange_code_for_tokens(
                code=code,
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                code_verifier=wrong_verifier,
                client_secret=self.client_secret_plain,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_grant", str(ctx.exception.detail))

    def test_wrong_client_secret_rejected(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        from fastapi import HTTPException
        verifier, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        with self.assertRaises(HTTPException) as ctx:
            exchange_code_for_tokens(
                code=code,
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                code_verifier=verifier,
                client_secret="totally-wrong-secret",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_client", str(ctx.exception.detail))

    def test_redirect_uri_mismatch(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        from fastapi import HTTPException
        verifier, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        with self.assertRaises(HTTPException) as ctx:
            exchange_code_for_tokens(
                code=code,
                client_id=self.client_id,
                redirect_uri="https://evil.example.com/cb",
                code_verifier=verifier,
                client_secret=self.client_secret_plain,
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_expired_code_rejected(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        from fastapi import HTTPException
        # Force TTL=0 so the HMAC envelope expires immediately
        object.__setattr__(S, "oauth_code_ttl_seconds", 0)
        self.stack.callback(object.__setattr__, S, "oauth_code_ttl_seconds", 60)
        _, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        verifier = "anything"
        with self.assertRaises(HTTPException) as ctx:
            exchange_code_for_tokens(
                code=code,
                client_id=self.client_id,
                redirect_uri=self.redirect_uri,
                code_verifier=verifier,
                client_secret=self.client_secret_plain,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_grant", str(ctx.exception.detail))

    def test_refresh_token_rotation(self):
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens, refresh_access_token
        object.__setattr__(S, "oauth_always_issue_refresh_token", True)
        self.stack.callback(object.__setattr__, S, "oauth_always_issue_refresh_token", False)
        verifier, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        token_resp = exchange_code_for_tokens(
            code=code,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code_verifier=verifier,
            client_secret=self.client_secret_plain,
        )
        self.assertIn("refresh_token", token_resp)
        old_refresh = token_resp["refresh_token"]
        # Use the refresh token
        refreshed = refresh_access_token(
            client_id=self.client_id,
            refresh_token=old_refresh,
            client_secret=self.client_secret_plain,
        )
        self.assertIn("access_token", refreshed)
        self.assertIn("refresh_token", refreshed)
        new_refresh = refreshed["refresh_token"]
        # Old refresh token no longer works
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            refresh_access_token(
                client_id=self.client_id,
                refresh_token=old_refresh,
                client_secret=self.client_secret_plain,
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_directlogin_flag_off(self):
        from app.services.oauth_auth_flow import directlogin_grant
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            directlogin_grant(
                client_id=self.client_id,
                username="alice",
                password="pass",
                client_secret=self.client_secret_plain,
                scope="openid",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("unsupported_grant_type", str(ctx.exception.detail))

    def test_directlogin_happy_path(self):
        from app.services.oauth_auth_flow import directlogin_grant
        import app.services.oauth_auth_flow as oauth_flow_mod
        object.__setattr__(S, "oauth_provider_directlogin_enabled", True)
        self.stack.callback(object.__setattr__, S, "oauth_provider_directlogin_enabled", False)
        # Patch _verify_local_password at the source location used by directlogin_grant
        # It imports via `from app.auth.deps import _verify_local_password` inside the function
        with patch("app.auth.deps._verify_local_password", return_value="alice"):
            result = directlogin_grant(
                client_id=self.client_id,
                username="alice",
                password="testpass",
                client_secret=self.client_secret_plain,
                scope="openid",
            )
        self.assertIn("access_token", result)
        payload = jwt.decode(result["access_token"], S.ui_access_token_secret, algorithms=["HS256"])
        self.assertEqual(payload["sub"], "alice")

    def test_oauth_bearer_auth_in_get_authenticated_user(self):
        """OAuth bearer tokens are recognized by get_authenticated_user."""
        from app.services.oauth_auth_flow import issue_auth_code, exchange_code_for_tokens
        from app.auth.deps import get_authenticated_user
        verifier, challenge = _make_pkce()
        code = issue_auth_code(
            client_id=self.client_id,
            owner_user_sub="alice",
            redirect_uri=self.redirect_uri,
            granted_scopes="openid",
            code_challenge=challenge,
        )
        token_resp = exchange_code_for_tokens(
            code=code,
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            code_verifier=verifier,
            client_secret=self.client_secret_plain,
        )
        access_token = token_resp["access_token"]

        # Mock T.users lookup using object.__setattr__ (frozen dataclass)
        from app.core.tables import _FloatSafeTable
        orig_users = T.users
        fake_users = MagicMock()
        fake_users.get_item = MagicMock(return_value={"Item": {}})
        object.__setattr__(T, "users", fake_users)
        self.addCleanup(object.__setattr__, T, "users", orig_users)

        from starlette.datastructures import State
        req = MagicMock()
        req.headers = {"authorization": f"Bearer {access_token}"}
        req.cookies = {}
        req.state = State()

        user = _run(get_authenticated_user(req))
        self.assertEqual(user.sub, "alice")
        # Check oauth_scope was stored on request.state
        self.assertTrue(hasattr(req.state, "oauth_scope"))


if __name__ == "__main__":
    unittest.main()
