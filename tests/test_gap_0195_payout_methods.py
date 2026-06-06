"""Offline regression test for GAP-0195 (FIN-009): payout methods CRUD.

Before the fix ``app/services/creator_payouts.py`` had no payout-method storage
or management layer at all — creators could not configure a real bank/PayPal
destination, and ``request_payout`` always stored the hardcoded ``"bank_transfer"``
string with no routing context. The functions exercised here
(``add_payout_method``, ``list_payout_methods``, ``set_default_payout_method``,
``get_default_payout_method``, ``delete_payout_method``) did not exist, so every
test below FAILS BEFORE the fix (ImportError / AttributeError) and PASSES AFTER.

Test isolation (per repo rules): we do NOT rely on global moto interception of
the app's pre-bound boto3 clients (that leaks to real AWS when another test file
imported the app first). Instead we create a real in-memory DynamoDB table with
moto and swap the exact handle the code uses — ``T.creator_payouts`` — via
``object.__setattr__`` (``T`` is a frozen dataclass), restoring it afterwards.
Settings ``S`` is likewise frozen and patched via ``object.__setattr__`` where
needed. Functions are called directly (the FastAPI TestClient is unusable here).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_creator_payouts_table(ddb):
    """Mirror the CreatorPayouts TableDef from scripts/local-ddb-init.py.

    HASH key ``payout_id`` only (no range key); GSIs ByUserCreatedAt and
    ByStatusCreatedAt with numeric ``created_at`` sort key.
    """
    return ddb.create_table(
        TableName="CreatorPayouts",
        KeySchema=[{"AttributeName": "payout_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "payout_id", "AttributeType": "S"},
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByUserCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestPayoutMethodsGap0195(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_creator_payouts_table(ddb)

        from app.core.tables import T
        from app.services import creator_payouts as svc

        self.svc = svc
        self.T = T
        # Swap the exact handle the code uses (T is frozen → object.__setattr__),
        # restoring the original after the test so other test files are unaffected.
        original = T.creator_payouts
        object.__setattr__(T, "creator_payouts", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "creator_payouts", original))

    # ── add + list ──────────────────────────────────────────────────────
    def test_add_and_list_payout_method(self):
        result = self.svc.add_payout_method(
            "alice",
            method_type="bank_ach",
            account_last4="1234",
            routing_last4="5678",
            nickname="My Checking",
        )
        self.assertTrue(result["method_id"].startswith("pmth_"))
        self.assertEqual(result["account_last4"], "1234")
        self.assertEqual(result["routing_last4"], "5678")
        # First method is auto-defaulted.
        self.assertTrue(result["is_default"])

        methods = self.svc.list_payout_methods("alice")
        self.assertEqual(len(methods), 1)
        self.assertEqual(methods[0]["method_id"], result["method_id"])

    def test_validation_rejects_unknown_type_and_missing_fields(self):
        with self.assertRaises(ValueError):
            self.svc.add_payout_method("x", method_type="bitcoin")
        with self.assertRaises(ValueError):
            self.svc.add_payout_method("x", method_type="bank_ach", account_last4="1234")
        with self.assertRaises(ValueError):
            self.svc.add_payout_method("x", method_type="paypal")

    # ── default pointer ─────────────────────────────────────────────────
    def test_set_and_get_default(self):
        m1 = self.svc.add_payout_method("bob", method_type="paypal", paypal_email="bob@paypal.com")
        m2 = self.svc.add_payout_method("bob", method_type="check", nickname="Mailed check")
        # m1 became default automatically; switch to m2.
        self.svc.set_default_payout_method("bob", m2["method_id"])
        default = self.svc.get_default_payout_method("bob")
        self.assertIsNotNone(default)
        self.assertEqual(default["method_id"], m2["method_id"])
        # Exactly one default.
        defaults = [m for m in self.svc.list_payout_methods("bob") if m["is_default"]]
        self.assertEqual(len(defaults), 1)
        self.assertEqual(defaults[0]["method_id"], m2["method_id"])
        self.assertNotEqual(m1["method_id"], m2["method_id"])

    # ── delete rules ────────────────────────────────────────────────────
    def test_delete_only_default_allowed(self):
        m = self.svc.add_payout_method("carol", method_type="paypal", paypal_email="carol@paypal.com")
        self.svc.delete_payout_method("carol", m["method_id"])
        self.assertEqual(self.svc.list_payout_methods("carol"), [])

    def test_cannot_delete_default_when_others_exist(self):
        m1 = self.svc.add_payout_method("dave", method_type="paypal", paypal_email="a@p.com")
        self.svc.add_payout_method("dave", method_type="paypal", paypal_email="b@p.com")
        self.svc.set_default_payout_method("dave", m1["method_id"])
        with self.assertRaisesRegex(ValueError, "cannot_delete_default"):
            self.svc.delete_payout_method("dave", m1["method_id"])

    # ── PII: only last-4 ever stored ────────────────────────────────────
    def test_full_account_number_not_stored(self):
        self.svc.add_payout_method(
            "eve", method_type="bank_ach", account_last4="9999", routing_last4="1111"
        )
        resp = self.table.query(
            IndexName="ByUserCreatedAt",
            KeyConditionExpression=Key("user_id").eq("eve"),
        )
        for item in resp.get("Items", []):
            self.assertLessEqual(len(str(item.get("account_last4", ""))), 4)
            self.assertNotIn("account_number", item)
            self.assertNotIn("routing_number", item)

    # ── methods must not leak into payout listings ──────────────────────
    def test_methods_excluded_from_payout_listing(self):
        self.svc.add_payout_method("frank", method_type="paypal", paypal_email="f@p.com")
        listing = self.svc.list_user_payouts("frank")
        self.assertEqual(listing["items"], [])
        # And a method record must not count as an active payout.
        self.assertFalse(self.svc._has_active_payout("frank"))

    # ── request_payout resolves real routing from the method ────────────
    def test_request_payout_uses_method_id(self):
        from app.core.settings import S

        # Seed a ledger credit so the balance covers the request, bypassing the
        # billing query by patching get_available_balance (frozen-S-safe).
        orig_balance = self.svc.get_available_balance
        self.svc.get_available_balance = lambda uid: {  # type: ignore[assignment]
            "available_cents": 100000,
            "pending_cents": 0,
            "total_earned_cents": 100000,
            "hold_cents": 0,
        }
        self.addCleanup(lambda: setattr(self.svc, "get_available_balance", orig_balance))

        m = self.svc.add_payout_method(
            "grace", method_type="bank_wire", account_last4="4321", routing_last4="8765"
        )
        result = self.svc.request_payout("grace", 5000, method_id=m["method_id"])
        self.assertEqual(result["status"], "requested")
        # The stored payout records the real method type + method_id, not the
        # hardcoded "bank_transfer".
        self.assertEqual(result["method"], "bank_wire")
        self.assertEqual(result["method_id"], m["method_id"])

        # A bogus / non-owned method id is rejected.
        with self.assertRaisesRegex(ValueError, "invalid_method_id"):
            self.svc.request_payout("grace2", 5000, method_id=m["method_id"])

        self.assertTrue(S.dev_mode in (True, False))  # touch S without mutating


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
