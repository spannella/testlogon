"""Regression test for GAP-0158.

The delegation API-key auth path (`app.services.delegation_api.authenticate_key`)
runs outside `require_ui_session`, which is where the normal session path enforces
platform-wide account bans. Before the fix, `authenticate_key` validated the key,
its expiry, the secret hash, the delegation relationship, and permissions — but
never checked whether the key holder (`owner_sub`) was currently banned. A banned
delegate therefore retained full delegation API-key access.

Fails-before: a banned owner's key authenticates successfully (the item is
returned) because no ban check exists.
Passes-after: a banned owner's key is rejected with HTTP 403 ("suspended"); a
non-banned owner's key still authenticates normally.

Fully offline: the account-ban lookup (`is_user_currently_banned`) is exercised
against a real moto-backed `account_state` table, so the genuine ban path runs
with no real AWS access. The delegation-key plumbing (key lookup, hash, delegate
relationship, rate-limit, usage) is patched to in-memory fakes to isolate the new
ban check.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.time import now_ts
from app.services import delegation_api
from app.services import moderation_policy_engine

FAKE_KEY = "dak_testkey123.secretabc"
KEY_ID = "testkey123"
SECRET = "secretabc"
OWNER_SUB = "banned_delegate_sub"
CREATOR_ID = "creator_alice"


def _key_item():
    return {
        "key_id": KEY_ID,
        "owner_sub": OWNER_SUB,
        "creator_id": CREATOR_ID,
        "secret_hash": "hashed_secret",
        "revoked": False,
        "permissions": ["chat_respond"],
        "rate_limit_rpm": 60,
    }


def _active_delegate():
    return {
        "status": "active",
        "creator_id": CREATOR_ID,
        "delegate_id": OWNER_SUB,
    }


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestGap0158DelegateBanViaApiKey(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.account_state = ddb.create_table(
            TableName="AccountState",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Point the real ban lookup at the moto-backed table. Both `T` (the
        # Tables dataclass) and settings `S` are frozen, so swap the attribute
        # via object.__setattr__ and restore it on cleanup.
        _orig_account_state = moderation_policy_engine.T.account_state
        object.__setattr__(
            moderation_policy_engine.T, "account_state", self.account_state
        )
        self.addCleanup(
            object.__setattr__,
            moderation_policy_engine.T,
            "account_state",
            _orig_account_state,
        )

        # Isolate the new ban check: patch delegation-key plumbing to fakes so
        # the only path under test is the account-ban gate. The ban lookup
        # itself (is_user_currently_banned) is NOT patched — it runs for real.
        self.stack.enter_context(
            patch.object(
                delegation_api,
                "_parse_delegation_key",
                return_value={"key_id": KEY_ID, "secret": SECRET},
            )
        )
        self.stack.enter_context(
            patch.object(delegation_api, "get_key_item", return_value=_key_item())
        )
        self.stack.enter_context(
            patch.object(delegation_api, "api_key_hash", return_value="hashed_secret")
        )
        self.stack.enter_context(
            patch.object(delegation_api, "get_delegate", return_value=_active_delegate())
        )
        self.stack.enter_context(
            patch.object(delegation_api, "_enforce_key_rate_limit", lambda *a, **k: None)
        )
        self.stack.enter_context(
            patch.object(delegation_api, "_record_usage", lambda *a, **k: None)
        )

    def _ban_owner(self):
        self.account_state.put_item(
            Item={
                "user_sub": OWNER_SUB,
                "status": "banned",
                "ban_until": 0,  # permanent ban
                "updated_at": now_ts(),
            }
        )

    def test_banned_owner_blocked(self):
        """A banned delegate's API key must be rejected with 403 'suspended'."""
        self._ban_owner()

        # Sanity: the real ban lookup sees the ban.
        self.assertTrue(moderation_policy_engine.is_user_currently_banned(OWNER_SUB))

        with self.assertRaises(HTTPException) as ctx:
            delegation_api.authenticate_key(
                api_key=FAKE_KEY,
                client_ip="1.2.3.4",
                required_permission="chat_respond",
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("suspended", str(ctx.exception.detail).lower())

    def test_non_banned_owner_allowed(self):
        """A non-banned delegate with a valid key authenticates normally."""
        # No account_state row written -> not banned.
        self.assertFalse(moderation_policy_engine.is_user_currently_banned(OWNER_SUB))

        result = delegation_api.authenticate_key(
            api_key=FAKE_KEY,
            client_ip="1.2.3.4",
            required_permission="chat_respond",
        )
        self.assertEqual(result["owner_sub"], OWNER_SUB)


if __name__ == "__main__":
    unittest.main()
