"""OAU-001 + OAU-005: Hermetic tests for the OAuth consumer-app registry.

Pattern: unittest.TestCase + moto in-memory DynamoDB + object.__setattr__ on frozen T/S.
No real AWS, no network, no TestClient.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import boto3
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T, _FloatSafeTable


def _run(coro):
    """Run a coroutine on a fresh event loop."""
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
    """Create the oauth_consumers table in moto."""
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


class TestConsumerRegistry(unittest.TestCase):

    def setUp(self):
        self.mock_ctx = mock_aws()
        self.mock_ctx.__enter__()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(self.mock_ctx.__exit__, None, None, None)
        # Bind table to frozen T
        orig_table = getattr(T, "oauth_consumers", None)
        object.__setattr__(T, "oauth_consumers", _FloatSafeTable(table))
        self.addCleanup(object.__setattr__, T, "oauth_consumers", orig_table)
        _set_settings(
            self.stack,
            oauth_provider_enabled=True,
            open_bank_project_enabled=True,
            api_key_pepper="test-pepper-oau",
            oauth_consumers_owner_index="ByOwner",
        )

    # -----------------------------------------------------------------------
    # OAU-001: Basic CRUD
    # -----------------------------------------------------------------------

    def test_create_list_get_cycle(self):
        from app.services.oauth_consumers import create_consumer, list_consumers, get_consumer
        result = create_consumer(
            "alice",
            name="TestApp",
            description="A test app",
            redirect_uris=["https://app.example.com/cb"],
            allowed_scopes=["openid"],
        )
        self.assertIn("client_id", result)
        self.assertIn("client_secret", result)
        self.assertTrue(result["client_secret"].startswith(f"oc_{result['client_id']}."))
        self.assertIn("client_secret_prefix", result)
        self.assertNotIn("client_secret_hash", result)

        consumers = list_consumers("alice")
        self.assertEqual(len(consumers), 1)
        self.assertEqual(consumers[0]["client_id"], result["client_id"])
        self.assertNotIn("client_secret_hash", consumers[0])

        # get_consumer returns hash too
        item = get_consumer(result["client_id"])
        self.assertIn("client_secret_hash", item)
        self.assertEqual(item["name"], "TestApp")

    def test_secret_hash_correctness(self):
        from app.services.oauth_consumers import create_consumer, get_consumer
        from app.services.api_keys import api_key_hash
        result = create_consumer(
            "alice",
            name="HashTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        # Extract plaintext secret from "oc_{client_id}.{secret}"
        parts = result["client_secret"].split(".", 1)
        secret_plain = parts[1]
        item = get_consumer(result["client_id"])
        expected_hash = api_key_hash(secret_plain)
        self.assertEqual(item["client_secret_hash"], expected_hash)

    def test_verify_client_secret_accept(self):
        from app.services.oauth_consumers import create_consumer, verify_client_secret
        result = create_consumer(
            "alice",
            name="VerifyTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        secret_plain = result["client_secret"].split(".", 1)[1]
        self.assertTrue(verify_client_secret(result["client_id"], secret_plain))

    def test_verify_client_secret_reject(self):
        from app.services.oauth_consumers import create_consumer, verify_client_secret
        result = create_consumer(
            "alice",
            name="RejectTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        self.assertFalse(verify_client_secret(result["client_id"], "wrong-secret"))

    def test_verify_client_secret_disabled(self):
        from app.services.oauth_consumers import create_consumer, verify_client_secret
        from app.core.tables import T
        result = create_consumer(
            "alice",
            name="DisabledTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        secret_plain = result["client_secret"].split(".", 1)[1]
        # Manually disable
        T.oauth_consumers.update_item(
            Key={"client_id": result["client_id"], "sk": "META"},
            UpdateExpression="SET enabled = :f",
            ExpressionAttributeValues={":f": False},
        )
        self.assertFalse(verify_client_secret(result["client_id"], secret_plain))

    def test_invalid_redirect_uri_scheme(self):
        from app.services.oauth_consumers import create_consumer
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_consumer(
                "alice",
                name="BadURI",
                redirect_uris=["ftp://bad.example.com"],
                allowed_scopes=["openid"],
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_redirect_uri", str(ctx.exception.detail))

    def test_invalid_redirect_uri_empty_netloc(self):
        from app.services.oauth_consumers import create_consumer
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_consumer(
                "alice",
                name="BadURI2",
                redirect_uris=["https://"],
                allowed_scopes=["openid"],
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_invalid_redirect_uri_fragment(self):
        from app.services.oauth_consumers import create_consumer
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_consumer(
                "alice",
                name="FragURI",
                redirect_uris=["https://example.com/cb#fragment"],
                allowed_scopes=["openid"],
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_invalid_scope(self):
        from app.services.oauth_consumers import create_consumer
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_consumer(
                "alice",
                name="BadScope",
                redirect_uris=["https://example.com/cb"],
                allowed_scopes=["nonexistent:scope:xyz"],
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid_scope", str(ctx.exception.detail))

    def test_oidc_scopes_always_valid(self):
        from app.services.oauth_consumers import create_consumer
        result = create_consumer(
            "alice",
            name="OIDCScopes",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid", "profile", "email"],
        )
        self.assertIn("client_id", result)

    def test_update_consumer(self):
        from app.services.oauth_consumers import create_consumer, update_consumer
        result = create_consumer(
            "alice",
            name="Original",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        updated = update_consumer("alice", result["client_id"], name="Renamed")
        self.assertEqual(updated["name"], "Renamed")

    def test_update_consumer_wrong_owner(self):
        from app.services.oauth_consumers import create_consumer, update_consumer
        from fastapi import HTTPException
        result = create_consumer(
            "alice",
            name="AliceApp",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        with self.assertRaises(HTTPException) as ctx:
            update_consumer("bob", result["client_id"], name="BobAttempt")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_delete_consumer(self):
        from app.services.oauth_consumers import create_consumer, delete_consumer, get_consumer
        result = create_consumer(
            "alice",
            name="ToDelete",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        delete_consumer("alice", result["client_id"])
        item = get_consumer(result["client_id"])
        self.assertEqual(item, {})

    def test_delete_consumer_not_found(self):
        from app.services.oauth_consumers import delete_consumer
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            delete_consumer("alice", "nonexistentclientid00000")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_owner_isolation_via_service(self):
        from app.services.oauth_consumers import create_consumer, get_consumer
        result = create_consumer(
            "alice",
            name="AliceOnly",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        # Service get_consumer returns item regardless of owner (used by auth layer)
        item = get_consumer(result["client_id"])
        self.assertEqual(item["owner_sub"], "alice")
        # Router layer would check ownership — tested by test_router_get_my_consumer_wrong_owner

    def test_oc_prefix_format(self):
        from app.services.oauth_consumers import create_consumer
        result = create_consumer(
            "alice",
            name="PrefixTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        client_id = result["client_id"]
        expected_prefix = f"oc_{client_id}"
        self.assertTrue(result["client_secret"].startswith(expected_prefix + "."))

    def test_public_client_no_secret(self):
        from app.services.oauth_consumers import create_consumer, verify_client_secret
        result = create_consumer(
            "alice",
            name="PublicApp",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
            is_confidential=False,
        )
        # Public client returns empty secret
        self.assertEqual(result["client_secret"], "")
        # verify_client_secret returns False for public clients
        self.assertFalse(verify_client_secret(result["client_id"], "anything"))

    # -----------------------------------------------------------------------
    # OAU-005: Enable/disable + secret rotation
    # -----------------------------------------------------------------------

    def test_set_consumer_enabled_disable(self):
        from app.services.oauth_consumers import create_consumer, set_consumer_enabled, get_consumer
        result = create_consumer(
            "alice",
            name="EnableTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        set_consumer_enabled("alice", result["client_id"], enabled=False)
        item = get_consumer(result["client_id"])
        self.assertFalse(item["enabled"])

    def test_set_consumer_enabled_re_enable(self):
        from app.services.oauth_consumers import create_consumer, set_consumer_enabled, get_consumer
        result = create_consumer(
            "alice",
            name="ReEnableTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        set_consumer_enabled("alice", result["client_id"], enabled=False)
        set_consumer_enabled("alice", result["client_id"], enabled=True)
        item = get_consumer(result["client_id"])
        self.assertTrue(item["enabled"])

    def test_rotate_client_secret(self):
        from app.services.oauth_consumers import create_consumer, rotate_client_secret, verify_client_secret
        result = create_consumer(
            "alice",
            name="RotateTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        old_secret_plain = result["client_secret"].split(".", 1)[1]
        rotation = rotate_client_secret("alice", result["client_id"])
        self.assertIn("client_secret", rotation)
        new_secret_plain = rotation["client_secret"].split(".", 1)[1]
        # Old secret no longer works
        self.assertFalse(verify_client_secret(result["client_id"], old_secret_plain))
        # New secret works
        self.assertTrue(verify_client_secret(result["client_id"], new_secret_plain))

    def test_rotate_client_secret_wrong_owner(self):
        from app.services.oauth_consumers import create_consumer, rotate_client_secret
        from fastapi import HTTPException
        result = create_consumer(
            "alice",
            name="RotateOwnerTest",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        with self.assertRaises(HTTPException) as ctx:
            rotate_client_secret("bob", result["client_id"])
        self.assertEqual(ctx.exception.status_code, 404)

    def test_require_fresh_mfa_called_on_create(self):
        """Assert require_fresh_mfa is called in the create route handler."""
        from app.routers.oauth_consumers import create_my_consumer

        mfa_called = []
        def fake_mfa(ctx):
            mfa_called.append(True)
        req = MagicMock()
        ctx = {"user_sub": "alice", "mfa_verified_at": 0}
        body = {
            "name": "MFATest",
            "redirect_uris": ["https://example.com/cb"],
            "allowed_scopes": ["openid"],
        }
        with patch("app.routers.oauth_consumers.require_fresh_mfa", side_effect=fake_mfa), \
             patch("app.routers.oauth_consumers.audit_event"):
            _run(create_my_consumer(req, body, ctx))
        self.assertEqual(len(mfa_called), 1, "require_fresh_mfa must be called on create")

    def test_router_get_my_consumer_wrong_owner(self):
        """Router should return 404 when client_id doesn't belong to the caller."""
        from app.routers.oauth_consumers import get_my_consumer
        from app.services.oauth_consumers import create_consumer
        from fastapi import HTTPException
        result = create_consumer(
            "alice",
            name="AlicePrivate",
            redirect_uris=["https://example.com/cb"],
            allowed_scopes=["openid"],
        )
        bob_ctx = {"user_sub": "bob"}
        with self.assertRaises(HTTPException) as ctx:
            _run(get_my_consumer(result["client_id"], bob_ctx))
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
