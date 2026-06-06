"""Offline regression tests for GAP-0176 and GAP-0177 (ENTERPRISE-003).

Both gaps live in ``app/services/org_service.py``:

GAP-0176 — ``_find_invite`` did a full table ``scan`` with ``Limit=100``. That
``Limit`` is a *pre-filter* cap in DynamoDB, so an invite item that sorts beyond
the first 100 scanned items was silently missed → ``_find_invite`` returned
``None`` → ``accept_invite`` raised a bogus 404 for a valid token. The fix uses
the ``invite-id-index`` GSI with a ``query``, which finds the invite regardless
of table size.

GAP-0177 — ``list_user_orgs`` queried the ``user-orgs-index`` GSI for memberships
and then issued one ``get_item`` per membership (the N+1 pattern). The fix uses a
single ``batch_get_item`` (chunked at 100) for the org ``#META`` records.

Fully offline: a real in-memory DynamoDB table is created with moto (no real AWS)
and ``org_service.T`` is patched to point at it. The functions are called
directly (the FastAPI TestClient is unusable in this repo). Each test seeds
enough data that the *old* behaviour produces a wrong answer and the *new*
behaviour is correct.
"""
from __future__ import annotations

import hashlib
import secrets
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_organizations_table(ddb):
    """Create the organizations table mirroring scripts/local-ddb-init.py.

    Includes the GAP-0176 invite-id-index GSI and the existing user-orgs-index.
    """
    return ddb.create_table(
        TableName="organizations",
        KeySchema=[
            {"AttributeName": "org_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "org_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "invite_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "user-orgs-index",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "org_id", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "invite-id-index",
                "KeySchema": [
                    {"AttributeName": "invite_id", "KeyType": "HASH"},
                    {"AttributeName": "org_id", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestFindInviteGap0176(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_organizations_table(ddb)

        from app.services import org_service

        self.org_service = org_service
        self.stack.enter_context(
            patch.object(org_service, "T", SimpleNamespace(organizations=self.table))
        )

    def _seed_invite(self, org_id: str, invite_id: str, status: str = "pending"):
        self.table.put_item(
            Item={
                "org_id": org_id,
                "sk": f"INVITE#{invite_id}",
                "invite_id": invite_id,
                "email": f"{invite_id}@example.com",
                "org_role": "member",
                "invited_by": "owner_sub",
                "status": status,
                "token_hash": "sha256:deadbeef",
            }
        )

    def test_find_invite_beyond_first_100_items(self):
        """GAP-0176: the target invite must be found even with >100 other items.

        FAILS BEFORE FIX: the old ``scan(Limit=100)`` reads only the first 100
        items pre-filter; the target invite (seeded last among 150 items) is
        beyond that window, so the old code returns ``None``.
        PASSES AFTER FIX: the GSI query keyed on ``invite_id`` finds it directly.
        """
        # Seed 149 unrelated items (member + invite records across many orgs).
        for i in range(149):
            org_id = f"org_filler_{i:04d}"
            self.table.put_item(
                Item={
                    "org_id": org_id,
                    "sk": f"MEMBER#user_{i:04d}",
                    "user_sub": f"user_{i:04d}",
                    "org_role": "member",
                    "status": "active",
                }
            )

        target_id = "inv_targetbeyond100x"
        self._seed_invite("org_target", target_id)

        found = self.org_service._find_invite(target_id)

        self.assertIsNotNone(
            found,
            "GAP-0176: _find_invite must locate an invite even when the table "
            "holds more than 100 items (old scan Limit=100 silently missed it)",
        )
        self.assertEqual(found["invite_id"], target_id)
        self.assertEqual(found["org_id"], "org_target")

    def test_find_invite_returns_none_when_absent(self):
        self._seed_invite("org_a", "inv_realone1234567")
        self.assertIsNone(self.org_service._find_invite("inv_doesnotexist000"))

    def test_accept_invite_works_beyond_100_items(self):
        """End-to-end: accept a valid invite that sits beyond the scan window.

        FAILS BEFORE FIX: _find_invite returns None → accept_invite raises 404.
        """
        for i in range(120):
            self.table.put_item(
                Item={
                    "org_id": f"org_pad_{i:04d}",
                    "sk": f"INVITE#inv_pad{i:04d}",
                    "invite_id": f"inv_pad{i:04d}",
                    "status": "declined",
                }
            )

        org_id = "org_accept_target"
        invite_id = "inv_acceptbeyond100"
        token = secrets.token_urlsafe(32)
        token_hash = f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"
        # #META so accept_invite can read the org name + bump member_count.
        self.table.put_item(
            Item={
                "org_id": org_id,
                "sk": "#META",
                "name": "Accept Target Org",
                "status": "active",
                "member_count": 1,
            }
        )
        self.table.put_item(
            Item={
                "org_id": org_id,
                "sk": f"INVITE#{invite_id}",
                "invite_id": invite_id,
                "email": "newbie@example.com",
                "org_role": "member",
                "invited_by": "owner_sub",
                "status": "pending",
                "expires_at": 9_999_999_999,
                "token_hash": token_hash,
            }
        )

        result = self.org_service.accept_invite(invite_id, "newbie_sub", token)

        self.assertEqual(result["org_id"], org_id)
        self.assertEqual(result["org_name"], "Accept Target Org")
        member = self.table.get_item(
            Key={"org_id": org_id, "sk": "MEMBER#newbie_sub"}
        ).get("Item")
        self.assertIsNotNone(member, "membership should have been created on accept")
        self.assertEqual(member["status"], "active")


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestListUserOrgsGap0177(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_organizations_table(ddb)

        from app.services import org_service

        self.org_service = org_service
        self.stack.enter_context(
            patch.object(org_service, "T", SimpleNamespace(organizations=self.table))
        )

    def _seed_org(self, org_id: str, user_sub: str, *, name: str, status: str = "active"):
        self.table.put_item(
            Item={
                "org_id": org_id,
                "sk": "#META",
                "name": name,
                "status": status,
                "plan": "free",
            }
        )
        self.table.put_item(
            Item={
                "org_id": org_id,
                "sk": f"MEMBER#{user_sub}",
                "user_sub": user_sub,
                "org_role": "member",
                "status": "active",
            }
        )

    def test_list_user_orgs_uses_batch_get_not_n_get_items(self):
        """GAP-0177: org metas fetched via one batch_get_item, not N get_items.

        FAILS BEFORE FIX: the old loop calls get_item once per membership, so
        batch_get_item is never called and get_item is called N times.
        PASSES AFTER FIX: a single batch_get_item; get_item not used for #META.
        """
        user = "user_alice"
        for i in range(5):
            self._seed_org(f"org_{i:04d}", user, name=f"Org {i}")

        client = self.table.meta.client
        with patch.object(
            client, "batch_get_item", wraps=client.batch_get_item
        ) as batch_spy, patch.object(
            self.table, "get_item", wraps=self.table.get_item
        ) as get_spy:
            result = self.org_service.list_user_orgs(user)

        self.assertEqual(len(result), 5)
        # Result still carries org metadata + membership fields.
        names = {r["name"] for r in result}
        self.assertEqual(names, {f"Org {i}" for i in range(5)})
        for r in result:
            self.assertEqual(r["org_role"], "member")
            self.assertEqual(r["membership_status"], "active")

        batch_spy.assert_called_once()
        get_spy.assert_not_called()

    def test_list_user_orgs_chunks_above_100(self):
        """150 memberships → 2 batch_get_item calls (ceil(150/100)), all returned.

        FAILS BEFORE FIX: no batch_get_item at all.
        """
        user = "user_big"
        for i in range(150):
            self._seed_org(f"org_big_{i:05d}", user, name=f"BigOrg {i}")

        client = self.table.meta.client
        with patch.object(
            client, "batch_get_item", wraps=client.batch_get_item
        ) as batch_spy:
            result = self.org_service.list_user_orgs(user)

        self.assertEqual(len(result), 150)
        self.assertEqual(batch_spy.call_count, 2)

    def test_list_user_orgs_status_filter(self):
        """Status filter still applies to both membership and org status."""
        user = "user_filter"
        self._seed_org("org_active", user, name="Active Org", status="active")
        self._seed_org("org_suspended", user, name="Suspended Org", status="suspended")

        active = self.org_service.list_user_orgs(user, status="active")
        self.assertEqual([r["org_id"] for r in active], ["org_active"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
