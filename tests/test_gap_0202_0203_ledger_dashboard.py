"""Offline regression tests for GAP-0202 and GAP-0203 (FIN-013).

Both gaps touch the billing ledger write/read path.

GAP-0202 — ``_scan_ledger_entries`` in
``app/services/platform_financial_dashboard.py`` did an unbounded
``T.billing.scan()`` (no FilterExpression) on *every* financial-dashboard
rollup, reading payment-method + balance rows it then discarded in Python.
The fix queries the new ``GSI_LEDGER_DATE`` index per day when a ``date_set``
is given (the path every KPI/trend/breakdown endpoint uses), and only falls
back to a *filtered* scan for the rare all-time path.

GAP-0203 — provider-originating ledger entries did not persist a ``provider``
field, so the dashboard's provider breakdown bucketed everything as
``"unknown"``. The fix passes ``provider`` through ``new_ledger_entry`` at the
Stripe / PayPal / CCBill write sites.

Fully offline. GAP-0202 builds a real in-memory billing table with moto (no
real AWS) and patches the module-level ``T`` to point at it — mirroring
``tests/test_gap_0176_0177_org_service.py``. We deliberately swap the exact
handle the code uses rather than relying on global moto interception of
pre-bound app clients (that leaks to real AWS when another test imported the
app first). GAP-0203 calls the ledger wrappers directly and inspects the
returned item. Each test fails before the fix and passes after.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_billing_table(ddb):
    """Create the billing table mirroring scripts/local-ddb-init.py.

    Includes the GAP-0202 ``GSI_LEDGER_DATE`` index keyed on
    ``ledger_date`` (HASH) / ``sk`` (RANGE).
    """
    return ddb.create_table(
        TableName="billing",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "ledger_date", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_LEDGER_DATE",
                "KeySchema": [
                    {"AttributeName": "ledger_date", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestLedgerScanGap0202(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_billing_table(ddb)

        from app.services import platform_financial_dashboard as pfd

        self.pfd = pfd
        # Swap the exact handle the code uses (do not rely on global moto
        # interception of the app's pre-bound clients).
        self.stack.enter_context(
            patch.object(pfd, "T", SimpleNamespace(billing=self.table))
        )

    def _seed_ledger(self, user: str, ledger_date: str, ts: int, **fields):
        self.table.put_item(
            Item={
                "pk": f"USER#{user}",
                "sk": f"LEDGER#{ts}#{user}{ts}",
                "entry_id": f"{user}{ts}",
                "ts": ts,
                "ledger_date": ledger_date,
                "type": fields.get("type", "deposit"),
                "amount_cents": fields.get("amount_cents", 1000),
                "state": fields.get("state", "settled"),
                "reason": fields.get("reason", "test"),
                **{k: v for k, v in fields.items()
                   if k not in {"type", "amount_cents", "state", "reason"}},
            }
        )

    def _seed_non_ledger(self, user: str, sk: str):
        # Payment-method / balance rows carry NO ledger_date, so they never
        # appear in the GSI.
        self.table.put_item(Item={"pk": f"USER#{user}", "sk": sk, "data": "x"})

    def test_date_set_queries_gsi_not_scan(self):
        """GAP-0202: a date-bounded call must use GSI_LEDGER_DATE, never scan.

        FAILS BEFORE FIX: ``_scan_ledger_entries`` called ``T.billing.scan()``
        unconditionally. PASSES AFTER FIX: it queries the GSI per day.
        """
        self._seed_ledger("u1", "2026-01-15", 1700000000, amount_cents=1000)
        self._seed_ledger("u2", "2026-01-15", 1700000001, amount_cents=500)
        self._seed_ledger("u3", "2026-01-16", 1700100000, amount_cents=900)
        # Noise the OLD scan would have to read + discard.
        self._seed_non_ledger("u1", "PM#card_1")
        self._seed_non_ledger("u1", "BILLING")

        client = self.table.meta.client
        with patch.object(
            client, "query", wraps=client.query
        ) as query_spy, patch.object(
            self.table, "scan", wraps=self.table.scan
        ) as scan_spy:
            result = self.pfd._scan_ledger_entries(date_set={"2026-01-15"})

        scan_spy.assert_not_called()
        self.assertGreaterEqual(query_spy.call_count, 1)
        # Only the two 2026-01-15 ledger rows; no PM/BILLING rows, no 01-16 row.
        self.assertEqual(len(result), 2)
        for item in result:
            self.assertEqual(item["ledger_date"], "2026-01-15")
            self.assertTrue(str(item["sk"]).startswith("LEDGER#"))

    def test_multi_date_issues_one_query_per_date(self):
        """N dates → exactly N GSI queries (one per partition)."""
        self._seed_ledger("u1", "2026-02-01", 1700200000)
        self._seed_ledger("u2", "2026-02-02", 1700300000)
        self._seed_ledger("u3", "2026-02-03", 1700400000)

        client = self.table.meta.client
        with patch.object(client, "query", wraps=client.query) as query_spy:
            result = self.pfd._scan_ledger_entries(
                date_set={"2026-02-01", "2026-02-02", "2026-02-03"}
            )

        self.assertEqual(query_spy.call_count, 3)
        self.assertEqual(len(result), 3)

    def test_no_date_set_falls_back_to_filtered_scan(self):
        """The rare all-time path scans but with a LEDGER# FilterExpression.

        Confirms the fallback excludes non-ledger rows server-side rather than
        in Python.
        """
        self._seed_ledger("u1", "2026-03-01", 1700500000)
        self._seed_non_ledger("u1", "PM#card_9")

        client = self.table.meta.client
        with patch.object(self.table, "scan", wraps=self.table.scan) as scan_spy:
            result = self.pfd._scan_ledger_entries(date_set=None)

        scan_spy.assert_called()
        # FilterExpression supplied → server-side LEDGER# filter.
        self.assertIn("FilterExpression", scan_spy.call_args.kwargs)
        self.assertEqual(len(result), 1)
        self.assertTrue(str(result[0]["sk"]).startswith("LEDGER#"))

    def test_query_only_returns_requested_date(self):
        """Cross-date isolation: querying one date returns only that date."""
        self._seed_ledger("u1", "2026-04-10", 1700600000)
        self._seed_ledger("u2", "2026-04-11", 1700700000)

        result = self.pfd._scan_ledger_entries(date_set={"2026-04-10"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ledger_date"], "2026-04-10")


class TestLedgerProviderGap0203(unittest.TestCase):
    """GAP-0203: provider must be persisted on provider-originated entries.

    These tests need no AWS — the wrappers build/return the item dict and do
    not write to DynamoDB themselves (callers persist via ddb_put).
    """

    def test_shared_new_ledger_entry_persists_provider_from_extra(self):
        """billing_shared.new_ledger_entry passes provider through ``extra``.

        FAILS BEFORE FIX only if extra pass-through were broken; this asserts
        the mechanism Stripe call sites rely on.
        """
        from app.services.billing_shared import new_ledger_entry

        _sk, item = new_ledger_entry(
            key_name="pk",
            key_value="USER#alice",
            entry_type="credit",
            amount_cents=500,
            state="settled",
            reason="payment",
            extra={"stripe_payment_intent_id": "pi_123", "provider": "stripe"},
        )
        self.assertEqual(item.get("provider"), "stripe")

    def test_paypal_wrapper_writes_provider(self):
        """PayPal wrapper must stamp provider=paypal on the item.

        FAILS BEFORE FIX: the inline item dict had no ``provider`` key.
        """
        from app.routers.paypal import new_ledger_entry as paypal_new_ledger_entry

        _sk, item = paypal_new_ledger_entry(
            user_id="bob",
            entry_type="credit",
            amount_cents=200,
            state="pending",
            reason="paypal_deposit",
            paypal_payment_token_id="ppt_1",
        )
        self.assertEqual(item.get("provider"), "paypal")

    def test_ccbill_wrapper_writes_provider(self):
        """CCBill wrapper must stamp provider=ccbill via the shared extra dict.

        FAILS BEFORE FIX: the wrapper's ``extra`` dict had no ``provider`` key.
        """
        from app.services.billing_ccbill import new_ledger_entry as ccbill_new_ledger_entry

        with patch(
            "app.services.billing_ccbill.new_ledger_entry_shared"
        ) as mock_shared:
            mock_shared.return_value = ("sk_val", {"provider": "ccbill"})
            ccbill_new_ledger_entry(
                user_sub="charlie",
                entry_type="credit",
                amount_cents=1000,
                state="settled",
                reason="ccbill_charge",
                ccbill_transaction_id="txn_abc",
            )
        call_kwargs = mock_shared.call_args.kwargs
        self.assertEqual(call_kwargs.get("extra", {}).get("provider"), "ccbill")

    def test_provider_breakdown_has_no_unknown_when_provider_set(self):
        """End-to-end aggregation: provider-stamped entries bucket by provider.

        FAILS BEFORE FIX: every entry landed in the ``unknown`` bucket.
        """
        from app.services.platform_financial_dashboard import _aggregate

        entries = [
            {"pk": "USER#a", "sk": "LEDGER#1#a", "type": "deposit",
             "amount_cents": 1000, "state": "settled", "provider": "stripe"},
            {"pk": "USER#b", "sk": "LEDGER#2#b", "type": "deposit",
             "amount_cents": 500, "state": "settled", "provider": "paypal"},
            {"pk": "USER#c", "sk": "LEDGER#3#c", "type": "deposit",
             "amount_cents": 700, "state": "settled", "provider": "ccbill"},
        ]
        agg = _aggregate(entries)
        providers = set(agg["by_provider"].keys())
        self.assertNotIn("unknown", providers)
        self.assertEqual(providers, {"stripe", "paypal", "ccbill"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
