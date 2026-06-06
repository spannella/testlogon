"""Offline regression test for GAP-0267 (KYC-009).

The admin KYC tier dashboard lists all users at a given KYC tier
(``list_users_by_tier``). The intended access pattern is a ``ByKycTier`` GSI
keyed on ``kyc_tier`` (partition) + ``kyc_tier_updated_at`` (sort), both numeric.

The gap: ``ByKycTier`` was not declared in the ``users`` ``TableDef`` in
``scripts/local-ddb-init.py`` (no ``gsi=`` and no numeric ``attr_types=``). Two
distinct failures could result:

  * GSI not declared at table-creation time -> ``query(IndexName="ByKycTier")``
    raises ``ResourceNotFoundException`` ("The table does not have the specified
    index: ByKycTier").
  * GSI declared but ``attr_types`` missing for the numeric keys -> DynamoDB
    stores ``kyc_tier`` as type ``String`` and an integer-keyed query raises
    ``ValidationException: Type mismatch for key kyc_tier expected: N actual: S``.

The fix adds the GSI to the users ``TableDef`` with
``attr_types={"kyc_tier": "N", "kyc_tier_updated_at": "N"}`` and has
``list_users_by_tier`` ``query()`` that GSI (already present in
``app/services/kyc_tiers.py``).

This test is fully hermetic. We create a real in-memory moto ``users`` table
WITH the new GSI (numeric keys typed ``N``) and patch the exact ``T.users``
handle (``T`` is a frozen dataclass, so we use ``object.__setattr__`` and
restore afterwards). A spy wraps ``.query`` so we can assert the GSI path is
taken.

FAILS BEFORE FIX: ``list_users_by_tier(tier=2)`` raises (no GSI /
type-mismatch) and never returns the seeded tier-2 users.
PASSES AFTER FIX: the GSI query is used and returns exactly the tier-2 users.

It also ``ast.parse``s ``scripts/local-ddb-init.py`` and asserts the users
``TableDef`` declares the ``ByKycTier`` GSI with both numeric keys typed ``N``,
giving dev/prod parity (SECOPS-007).
"""
from __future__ import annotations

import ast
import os
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


_DDB_INIT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "local-ddb-init.py",
)


def _make_users_table(ddb):
    """Mirror scripts/local-ddb-init.py users TableDef (post-GAP-0267).

    Single ``user_sub`` partition key, plus the ``ByKycTier`` GSI whose keys
    (``kyc_tier`` PK, ``kyc_tier_updated_at`` SK) are both numeric (type N).
    """
    return ddb.create_table(
        TableName="users",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "kyc_tier", "AttributeType": "N"},
            {"AttributeName": "kyc_tier_updated_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByKycTier",
                "KeySchema": [
                    {"AttributeName": "kyc_tier", "KeyType": "HASH"},
                    {"AttributeName": "kyc_tier_updated_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class _OpSpy:
    """Wraps a moto table, recording every .query / .scan call (with kwargs)."""

    def __init__(self, table):
        self._table = table
        self.query_calls = []
        self.scan_calls = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return self._table.query(**kwargs)

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        return self._table.scan(**kwargs)

    def __getattr__(self, name):
        return getattr(self._table, name)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestByKycTierGsi(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.users_spy = _OpSpy(_make_users_table(ddb))

        from app.core.tables import T

        self.T = T
        # T is a frozen dataclass — patch the handle via object.__setattr__ and
        # restore the original on cleanup.
        self._orig_users = T.users
        object.__setattr__(T, "users", self.users_spy)

        def _restore():
            object.__setattr__(T, "users", self._orig_users)

        self.addCleanup(_restore)

        from app.services import kyc_tiers

        self.kyc_tiers = kyc_tiers

    # -- seeding helper -----------------------------------------------------

    def _seed_user(self, user_sub, kyc_tier, kyc_tier_updated_at, display_name=None):
        item = {
            "user_sub": user_sub,
            "kyc_tier": kyc_tier,
            "kyc_tier_updated_at": kyc_tier_updated_at,
        }
        if display_name is not None:
            item["display_name"] = display_name
        self.users_spy.put_item(Item=item)

    # -- GSI query behaviour ------------------------------------------------

    def test_list_users_by_tier_uses_bykyctier_gsi(self):
        """FAILS BEFORE FIX: the GSI / numeric attr_types are absent so the
        query raises (ResourceNotFound / ValidationException). PASSES AFTER FIX:
        list_users_by_tier queries ByKycTier and returns only the tier-2 users
        across all users (tier-0 / tier-1 noise excluded)."""
        self._seed_user("u_t2_a", 2, 1700000000, display_name="Alice")
        self._seed_user("u_t2_b", 2, 1700000500, display_name="Bob")
        self._seed_user("u_t0", 0, 1700000100)
        self._seed_user("u_t1", 1, 1700000200)

        results = self.kyc_tiers.list_users_by_tier(tier=2)

        # The GSI query path must be used (not a full-table scan).
        self.assertTrue(
            self.users_spy.query_calls,
            "list_users_by_tier must query the ByKycTier GSI",
        )
        self.assertEqual(self.users_spy.query_calls[0].get("IndexName"), "ByKycTier")
        self.assertEqual(
            self.users_spy.scan_calls, [],
            "tier listing must not fall back to a full-table scan",
        )

        subs = {r["user_sub"] for r in results}
        self.assertEqual(subs, {"u_t2_a", "u_t2_b"})
        for r in results:
            self.assertEqual(r["kyc_tier"], 2)

    def test_list_users_by_tier_returns_empty_for_unused_tier(self):
        """A tier with no users returns an empty list via the GSI (no error)."""
        self._seed_user("u_t0", 0, 1700000100)

        results = self.kyc_tiers.list_users_by_tier(tier=3)

        self.assertEqual(self.users_spy.query_calls[0].get("IndexName"), "ByKycTier")
        self.assertEqual(results, [])

    def test_list_users_by_tier_query_uses_integer_key_value(self):
        """The KeyConditionExpression must bind an integer tier value; this only
        works if kyc_tier is stored as numeric (attr_types N). With a String
        attribute type this query would raise a ValidationException."""
        self._seed_user("u_t2", 2, 1700000000)

        results = self.kyc_tiers.list_users_by_tier(tier=2)

        call = self.users_spy.query_calls[0]
        self.assertEqual(call["ExpressionAttributeValues"][":tier"], 2)
        self.assertEqual({r["user_sub"] for r in results}, {"u_t2"})

    # -- static schema verification (dev/prod parity, SECOPS-007) -----------

    def test_ddb_init_declares_bykyctier_gsi_with_numeric_attr_types(self):
        """ast.parse scripts/local-ddb-init.py and confirm the users TableDef
        declares the ByKycTier GSI plus numeric attr_types for both keys."""
        with open(_DDB_INIT_PATH, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=_DDB_INIT_PATH)

        # Find every TableDef(...) call literal and inspect its gsi / attr_types.
        found = False
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "TableDef"):
                continue
            gsi_arg = None
            attr_types_arg = None
            for kw in node.keywords:
                if kw.arg == "gsi":
                    gsi_arg = kw.value
                elif kw.arg == "attr_types":
                    attr_types_arg = kw.value
            if gsi_arg is None:
                continue
            # Does this TableDef's gsi list contain a ByKycTier index?
            index_names = []
            sort_keys = []
            if isinstance(gsi_arg, (ast.List, ast.Tuple)):
                for elt in gsi_arg.elts:
                    if isinstance(elt, ast.Dict):
                        d = {}
                        for k, v in zip(elt.keys, elt.values):
                            if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                                d[k.value] = v.value
                        if d.get("index_name") == "ByKycTier":
                            index_names.append("ByKycTier")
                            if "partition_key" in d:
                                sort_keys.append(d.get("partition_key"))
                            if "sort_key" in d:
                                sort_keys.append(d.get("sort_key"))
            if "ByKycTier" not in index_names:
                continue

            found = True
            # The GSI must key on kyc_tier (PK) + kyc_tier_updated_at (SK).
            self.assertIn("kyc_tier", sort_keys)
            self.assertIn("kyc_tier_updated_at", sort_keys)

            # attr_types must type both numeric keys as "N".
            self.assertIsNotNone(
                attr_types_arg,
                "users TableDef with ByKycTier GSI must declare attr_types",
            )
            self.assertIsInstance(attr_types_arg, ast.Dict)
            attr_types = {}
            for k, v in zip(attr_types_arg.keys, attr_types_arg.values):
                if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                    attr_types[k.value] = v.value
            self.assertEqual(
                attr_types.get("kyc_tier"), "N",
                "kyc_tier (numeric GSI partition key) must be typed N",
            )
            self.assertEqual(
                attr_types.get("kyc_tier_updated_at"), "N",
                "kyc_tier_updated_at (numeric GSI sort key) must be typed N",
            )
            break

        self.assertTrue(
            found,
            "scripts/local-ddb-init.py must declare a TableDef with the "
            "ByKycTier GSI",
        )


if __name__ == "__main__":
    unittest.main()
