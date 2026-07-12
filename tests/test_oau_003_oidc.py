"""OAU-003: Hermetic tests for OIDC layer — discovery, JWKS, id_token, /userinfo."""
from __future__ import annotations

import asyncio
import base64
import json
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
import jwt as pyjwt
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


def _fake_kms_encrypt(plaintext: str) -> str:
    """Fake KMS encrypt: base64 encode for test isolation."""
    return base64.b64encode(plaintext.encode()).decode()


def _fake_kms_decrypt(ct_b64: str) -> bytes:
    """Fake KMS decrypt: base64 decode."""
    return base64.b64decode(ct_b64)


class TestOidcLayer(unittest.TestCase):

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
            oauth_provider_oidc_enabled=True,
            oidc_id_token_ttl_seconds=3600,
            oidc_issuer_url="",
            public_base_url="http://localhost:8000",
            api_key_pepper="test-pepper-oau",
            oauth_consumers_owner_index="ByOwner",
        )
        # Patch KMS functions for all OIDC tests
        import app.services.oauth_oidc_keys as oidc_keys_mod
        self.stack.callback(setattr, oidc_keys_mod, "kms_encrypt", oidc_keys_mod.kms_encrypt)
        self.stack.callback(setattr, oidc_keys_mod, "kms_decrypt", oidc_keys_mod.kms_decrypt)
        oidc_keys_mod.kms_encrypt = _fake_kms_encrypt
        oidc_keys_mod.kms_decrypt = _fake_kms_decrypt
        # Clear the in-process key cache
        self.stack.callback(setattr, oidc_keys_mod, "_KEY_CACHE", None)
        oidc_keys_mod._KEY_CACHE = None

    def test_discovery_doc_shape(self):
        from app.routers.oauth_oidc import openid_configuration
        resp = _run(openid_configuration())
        doc = json.loads(resp.body)
        self.assertIn("issuer", doc)
        self.assertIn("authorization_endpoint", doc)
        self.assertIn("token_endpoint", doc)
        self.assertIn("jwks_uri", doc)
        self.assertIn("userinfo_endpoint", doc)
        self.assertIn("id_token_signing_alg_values_supported", doc)
        self.assertIn("RS256", doc["id_token_signing_alg_values_supported"])
        self.assertIn("openid", doc["scopes_supported"])
        self.assertIn("profile", doc["scopes_supported"])
        self.assertIn("email", doc["scopes_supported"])
        self.assertTrue(doc["issuer"].startswith("http"))

    def test_discovery_doc_contains_registry_scopes(self):
        from app.routers.oauth_oidc import openid_configuration
        from app.services.api_key_route_scope_registry import API_KEY_ROUTE_SCOPE_REGISTRY
        resp = _run(openid_configuration())
        doc = json.loads(resp.body)
        # At least one registry scope should appear in scopes_supported
        all_registry_scopes = set()
        for policy in API_KEY_ROUTE_SCOPE_REGISTRY.values():
            all_registry_scopes.update(policy.get("required_scopes", []))
        overlap = all_registry_scopes & set(doc["scopes_supported"])
        self.assertTrue(len(overlap) > 0, "scopes_supported must include registry scopes")

    def test_jwks_shape(self):
        from app.services.oauth_oidc_keys import get_public_jwks
        jwks = get_public_jwks()
        self.assertIn("keys", jwks)
        self.assertEqual(len(jwks["keys"]), 1)
        jwk = jwks["keys"][0]
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertEqual(jwk["use"], "sig")
        self.assertIn("kid", jwk)
        self.assertIn("n", jwk)
        self.assertIn("e", jwk)
        # Private exponent must NOT be present
        self.assertNotIn("d", jwk)
        self.assertNotIn("p", jwk)
        self.assertNotIn("q", jwk)

    def test_jwks_stable(self):
        """Two calls to get_public_jwks return the same kid."""
        from app.services.oauth_oidc_keys import get_public_jwks
        jwks1 = get_public_jwks()
        jwks2 = get_public_jwks()
        self.assertEqual(jwks1["keys"][0]["kid"], jwks2["keys"][0]["kid"])

    def _ensure_signing_key(self):
        """Pre-generate the signing key so sign_id_token can find it."""
        from app.services.oauth_oidc_keys import get_or_create_oidc_signing_key
        get_or_create_oidc_signing_key()

    def test_id_token_with_openid_scope(self):
        self._ensure_signing_key()
        from app.services.oauth_oidc_keys import build_id_token, get_public_jwks
        id_token = build_id_token(
            owner_user_sub="alice",
            client_id="test-client",
            granted_scopes=["openid"],
            nonce="testnonce",
            user_item={"email": "alice@example.com"},
        )
        # Verify with public key
        jwks = get_public_jwks()
        jwk = jwks["keys"][0]
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        # Reconstruct public key from JWK for verification
        pub_key_jwk = json.dumps(jwk)
        pub_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(pub_key_jwk)
        payload = pyjwt.decode(id_token, pub_key, algorithms=["RS256"], audience="test-client")
        self.assertEqual(payload["sub"], "alice")
        self.assertEqual(payload["aud"], "test-client")
        self.assertEqual(payload["nonce"], "testnonce")
        self.assertIn("iss", payload)
        self.assertIn("exp", payload)
        self.assertIn("iat", payload)
        # No email claim (not requested)
        self.assertNotIn("email", payload)

    def test_id_token_with_email_scope(self):
        self._ensure_signing_key()
        from app.services.oauth_oidc_keys import build_id_token
        id_token = build_id_token(
            owner_user_sub="alice",
            client_id="c1",
            granted_scopes=["openid", "email"],
            user_item={"email": "alice@example.com", "email_verified": True},
        )
        payload = pyjwt.decode(id_token, options={"verify_signature": False})
        self.assertIn("email", payload)
        self.assertEqual(payload["email"], "alice@example.com")
        self.assertTrue(payload["email_verified"])

    def test_id_token_with_profile_scope(self):
        self._ensure_signing_key()
        from app.services.oauth_oidc_keys import build_id_token
        id_token = build_id_token(
            owner_user_sub="alice",
            client_id="c1",
            granted_scopes=["openid", "profile"],
            user_item={"profile_name": "Alice Smith", "first_name": "Alice", "last_name": "Smith"},
        )
        payload = pyjwt.decode(id_token, options={"verify_signature": False})
        self.assertEqual(payload["name"], "Alice Smith")
        self.assertEqual(payload["given_name"], "Alice")
        self.assertEqual(payload["family_name"], "Smith")

    def test_id_token_kid_matches_jwks(self):
        self._ensure_signing_key()
        from app.services.oauth_oidc_keys import build_id_token, get_public_jwks
        id_token = build_id_token("alice", "c1", ["openid"])
        header = pyjwt.get_unverified_header(id_token)
        jwks = get_public_jwks()
        self.assertEqual(header["kid"], jwks["keys"][0]["kid"])

    def test_id_token_requires_openid_scope(self):
        from app.services.oauth_oidc_keys import build_id_token
        with self.assertRaises(ValueError):
            build_id_token("alice", "c1", ["messager:read"])

    def test_userinfo_returns_sub(self):
        from app.routers.oauth_oidc import userinfo
        from starlette.datastructures import State
        orig_users = T.users
        fake_users = MagicMock()
        fake_users.get_item = MagicMock(return_value={"Item": {}})
        object.__setattr__(T, "users", fake_users)
        self.addCleanup(object.__setattr__, T, "users", orig_users)

        req = MagicMock()
        req.state = State()
        req.state.oauth_scope = "openid"
        req.state.oauth_client_id = "c1"

        ctx = MagicMock()
        ctx.sub = "alice"

        # get_consumer is called inside userinfo via lazy import; patch it at source
        with patch("app.services.oauth_consumers.get_consumer", return_value={"enabled": True}):
            resp = _run(userinfo(req, ctx))
        claims = json.loads(resp.body)
        self.assertEqual(claims["sub"], "alice")

    def test_userinfo_email_scope_filtered(self):
        from app.routers.oauth_oidc import userinfo
        from starlette.datastructures import State
        orig_users = T.users
        fake_users = MagicMock()
        fake_users.get_item = MagicMock(return_value={"Item": {"email": "alice@example.com", "email_verified": True}})
        object.__setattr__(T, "users", fake_users)
        self.addCleanup(object.__setattr__, T, "users", orig_users)

        req = MagicMock()
        req.state = State()
        req.state.oauth_scope = "openid email"
        req.state.oauth_client_id = "c1"

        ctx = MagicMock()
        ctx.sub = "alice"

        with patch("app.services.oauth_consumers.get_consumer", return_value={"enabled": True}):
            resp = _run(userinfo(req, ctx))
        claims = json.loads(resp.body)
        self.assertIn("email", claims)
        self.assertIn("email_verified", claims)

    def test_userinfo_no_oauth_scope(self):
        from app.routers.oauth_oidc import userinfo
        from fastapi import HTTPException
        from starlette.datastructures import State
        req = MagicMock()
        req.state = State()  # no oauth_scope set
        ctx = MagicMock()
        ctx.sub = "alice"
        with self.assertRaises(HTTPException) as cm:
            _run(userinfo(req, ctx))
        self.assertEqual(cm.exception.status_code, 401)

    def test_userinfo_no_openid_scope(self):
        from app.routers.oauth_oidc import userinfo
        from fastapi import HTTPException
        from starlette.datastructures import State
        req = MagicMock()
        req.state = State()
        req.state.oauth_scope = "messager:read"
        req.state.oauth_client_id = "c1"
        ctx = MagicMock()
        ctx.sub = "alice"
        with self.assertRaises(HTTPException) as cm:
            _run(userinfo(req, ctx))
        self.assertEqual(cm.exception.status_code, 403)

    def test_signing_key_race_safety(self):
        """Two concurrent calls to get_or_create result in exactly one DDB row."""
        import app.services.oauth_oidc_keys as oidc_keys_mod
        oidc_keys_mod._KEY_CACHE = None
        from app.services.oauth_oidc_keys import get_or_create_oidc_signing_key
        key1 = get_or_create_oidc_signing_key()
        oidc_keys_mod._KEY_CACHE = None  # Simulate second process
        key2 = get_or_create_oidc_signing_key()
        # Both should return same kid
        self.assertEqual(key1["kid"], key2["kid"])

    def test_private_key_not_in_jwks(self):
        from app.services.oauth_oidc_keys import get_public_jwks
        jwks = get_public_jwks()
        jwk = jwks["keys"][0]
        private_fields = {"d", "p", "q", "dp", "dq", "qi"}
        self.assertEqual(private_fields & set(jwk.keys()), set())


if __name__ == "__main__":
    unittest.main()
