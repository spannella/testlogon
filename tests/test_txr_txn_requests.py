"""Hermetic, offline regression suite for OBP Transaction Requests + Step-Up SCA
(TXR-001..TXR-005 backend).

No live AWS / Stripe / network. moto in-memory ``txn_requests``, ``sessions``,
``totp_devices``, ``sms_devices``, ``email_devices`` and ``billing`` tables are
bound to the EXACT frozen ``T.*`` handles via ``object.__setattr__`` (restored on
cleanup). Frozen ``S`` flags toggled the same way (restored on cleanup). The
collaborator money/SCA primitives are exercised against moto where cheap and
patched where they call Stripe / fraud / payout. Route coroutines are run on a
fresh ``asyncio.new_event_loop()``; NO TestClient.
"""
from __future__ import annotations

import asyncio
import contextlib
import unittest
from unittest import mock

import boto3
from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.tables import T
import app.services.txn_requests as txr
from app.models import TxnRequestCreateIn, TxnRequestType

FROZEN_TS = 1_700_000_000


class _FakeReq:
    """Minimal stand-in for fastapi.Request (txn_requests only reads headers/client)."""

    def __init__(self):
        self.headers = {}

        class _C:
            host = "127.0.0.1"

        self.client = _C()


def _create_txr_table(ddb):
    return ddb.create_table(
        TableName="txn_requests",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "request_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "request_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _create_kv_table(ddb, name, hash_key, range_key):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": hash_key, "KeyType": "HASH"},
            {"AttributeName": range_key, "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": hash_key, "AttributeType": "S"},
            {"AttributeName": range_key, "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TxnRequestsTestBase(unittest.TestCase):
    USER = "alice"
    OTHER = "bob"

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        handles = {
            "txn_requests": _create_txr_table(ddb),
            "sessions": _create_kv_table(ddb, "sessions", "user_sub", "session_id"),
            "totp": _create_kv_table(ddb, "totp_devices", "user_sub", "device_id"),
            "sms": _create_kv_table(ddb, "sms_devices", "user_sub", "sms_device_id"),
            "email": _create_kv_table(ddb, "email_devices", "user_sub", "email_device_id"),
            "billing": _create_kv_table(ddb, "billing", "pk", "sk"),
        }
        for name, handle in handles.items():
            original = getattr(T, name)
            object.__setattr__(T, name, handle)
            self.addCleanup(object.__setattr__, T, name, original)

        # Enable the engine + a known threshold/sensitive set.
        # The effective gate ANDs the OBP umbrella flag (D4, defined in ACC-001),
        # which exists in the integrated tree and defaults OFF — enable it too.
        self._set_s("open_bank_project_enabled", True)
        self._set_s("txn_requests_enabled", True)
        self._set_s("txn_request_sca_threshold_cents", 5000)
        self._set_s("txn_request_sca_sensitive_types", frozenset({"PAYOUT", "REFUND", "COUNTERPARTY"}))
        for attr in (
            "txn_request_limit_wallet_transfer_cents",
            "txn_request_limit_counterparty_cents",
            "txn_request_limit_payout_cents",
            "txn_request_limit_refund_cents",
            "txn_request_limit_free_form_cents",
        ):
            self._set_s(attr, 0)

        # Freeze time across the service + sessions.
        self.stack.enter_context(mock.patch("app.services.txn_requests.now_ts", return_value=FROZEN_TS))

        self.req = _FakeReq()

    def _set_s(self, name, value):
        original = getattr(S, name, None)
        object.__setattr__(S, name, value)
        self.addCleanup(object.__setattr__, S, name, original)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def _seed_wallet(self, user, cents):
        T.billing.put_item(Item={"pk": f"USER#{user}", "sk": "WALLET", "wallet_balance_cents": cents, "currency": "usd"})

    def _wallet(self, user):
        it = T.billing.get_item(Key={"pk": f"USER#{user}", "sk": "WALLET"}).get("Item")
        return int(it["wallet_balance_cents"]) if it else None

    def _create(self, **kw):
        body = TxnRequestCreateIn(**kw)
        return txr.create_request(self.USER, body, self.req)


# ---------------------------------------------------------------------------
# Group A — create / state machine (TXR-001, TXR-002)
# ---------------------------------------------------------------------------


class TestCreateAndStateMachine(TxnRequestsTestBase):
    def test_create_sub_threshold_initiated(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=1000, target={"to_user_sub": "bob"})
        self.assertEqual(out.status, "INITIATED")
        self.assertTrue(out.request_id.startswith("txr_"))
        self.assertIsNone(out.sca_challenge_id)
        self.assertEqual(out.ledger_refs, [])
        item = T.txn_requests.get_item(Key={"user_sub": self.USER, "request_id": out.request_id}).get("Item")
        self.assertIsNotNone(item)

    def test_create_all_five_types(self):
        cases = [
            (TxnRequestType.WALLET_TRANSFER, {"to_user_sub": "bob"}),
            (TxnRequestType.FREE_FORM, {}),
            (TxnRequestType.PAYOUT, {"payout_method_id": "pm_1"}),
            (TxnRequestType.REFUND, {"payment_intent_id": "pi_123"}),
            (TxnRequestType.COUNTERPARTY, {"counterparty_ref": "cp_1"}),
        ]
        for typ, target in cases:
            out = self._create(type=typ, amount_cents=100, target=target)
            self.assertIn(out.status, ("INITIATED", "PENDING"))

    def test_amount_non_positive_rejected_by_model(self):
        with self.assertRaises(Exception):
            TxnRequestCreateIn(type=TxnRequestType.WALLET_TRANSFER, amount_cents=0, target={"to_user_sub": "b"})
        with self.assertRaises(Exception):
            TxnRequestCreateIn(type=TxnRequestType.WALLET_TRANSFER, amount_cents=-5, target={"to_user_sub": "b"})

    def test_invalid_target_missing_to_user(self):
        with self.assertRaises(HTTPException) as ctx:
            self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "invalid_target")

    def test_self_transfer_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.USER})
        self.assertEqual(ctx.exception.detail.get("code"), "self_transfer_not_allowed")

    def test_refund_bad_prefix(self):
        with self.assertRaises(HTTPException) as ctx:
            self._create(type=TxnRequestType.REFUND, amount_cents=100, target={"payment_intent_id": "not_a_pi"})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_flag_off_404(self):
        object.__setattr__(S, "txn_requests_enabled", False)
        try:
            with self.assertRaises(HTTPException) as ctx:
                self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
            self.assertEqual(ctx.exception.status_code, 404)
        finally:
            object.__setattr__(S, "txn_requests_enabled", True)

    def test_audit_event_on_create(self):
        with mock.patch("app.services.txn_requests.audit_event") as spy:
            out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        names = [c.args[0] for c in spy.call_args_list]
        self.assertIn("txn_request.created", names)
        self.assertEqual(out.status, "INITIATED")

    def test_idempotency_key_dedup(self):
        a = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"}, idempotency_key="k1")
        b = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"}, idempotency_key="k1")
        self.assertEqual(a.request_id, b.request_id)
        resp = T.txn_requests.query(KeyConditionExpression=Key("user_sub").eq(self.USER))
        self.assertEqual(len([i for i in resp["Items"] if i.get("idempotency_key") == "k1"]), 1)

    def test_extra_target_keys_tolerated(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob", "x": "y"})
        self.assertEqual(out.status, "INITIATED")

    def test_gsi_queryable_by_status(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        resp = T.txn_requests.query(IndexName="GSI_STATUS", KeyConditionExpression=Key("status").eq("INITIATED"))
        ids = [i["request_id"] for i in resp["Items"]]
        self.assertIn(out.request_id, ids)

    def test_transition_legal_and_illegal(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        rid = out.request_id
        upd = txr._transition(self.USER, rid, "INITIATED", "IN_FLIGHT")
        self.assertEqual(upd["status"], "IN_FLIGHT")
        upd2 = txr._transition(self.USER, rid, "IN_FLIGHT", "COMPLETED", ledger_refs=["x"])
        self.assertEqual(upd2["status"], "COMPLETED")
        with self.assertRaises(HTTPException) as ctx:
            txr._transition(self.USER, rid, "COMPLETED", "PENDING")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail.get("current_status"), "COMPLETED")

    def test_transition_wrong_expected_fails(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        with self.assertRaises(HTTPException) as ctx:
            txr._transition(self.USER, out.request_id, "PENDING", "COMPLETED")
        self.assertEqual(ctx.exception.status_code, 409)

    def test_get_foreign_request_404(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        with self.assertRaises(HTTPException) as ctx:
            txr.get_request(self.OTHER, out.request_id)
        self.assertEqual(ctx.exception.status_code, 404)


# ---------------------------------------------------------------------------
# Group B — amount limits + list (TXR-002)
# ---------------------------------------------------------------------------


class TestLimitsAndList(TxnRequestsTestBase):
    def test_over_limit_no_item(self):
        object.__setattr__(S, "txn_request_limit_wallet_transfer_cents", 1000)
        with self.assertRaises(HTTPException) as ctx:
            self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=1001, target={"to_user_sub": "bob"})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail.get("code"), "amount_over_limit")
        resp = T.txn_requests.query(KeyConditionExpression=Key("user_sub").eq(self.USER))
        self.assertEqual(len(resp["Items"]), 0)

    def test_at_limit_ok(self):
        object.__setattr__(S, "txn_request_limit_wallet_transfer_cents", 1000)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=1000, target={"to_user_sub": "bob"})
        self.assertEqual(out.status, "INITIATED")

    def test_zero_limit_unlimited(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=999999, target={"to_user_sub": "bob"})
        self.assertIn(out.status, ("INITIATED", "PENDING"))

    def test_list_no_filter(self):
        for _ in range(3):
            self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        res = txr.list_requests(self.USER, None, None, 20)
        self.assertEqual(len(res["items"]), 3)

    def test_list_status_filter(self):
        self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        res = txr.list_requests(self.USER, "INITIATED", None, 20)
        self.assertTrue(all(i.status == "INITIATED" for i in res["items"]))
        self.assertGreaterEqual(len(res["items"]), 1)

    def test_list_invalid_status(self):
        with self.assertRaises(HTTPException) as ctx:
            txr.list_requests(self.USER, "BOGUS", None, 20)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_list_cursor_roundtrip(self):
        for _ in range(5):
            self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        seen = set()
        cursor = None
        for _ in range(5):
            res = txr.list_requests(self.USER, None, cursor, 2)
            for it in res["items"]:
                seen.add(it.request_id)
            cursor = res["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(seen), 5)


# ---------------------------------------------------------------------------
# Group C — SCA gating (TXR-003)
# ---------------------------------------------------------------------------


class TestSca(TxnRequestsTestBase):
    def _seed_totp(self):
        T.totp.put_item(Item={"user_sub": self.USER, "device_id": "d1", "enabled": True})

    def test_sub_threshold_no_challenge(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        self.assertEqual(out.status, "INITIATED")
        self.assertEqual(T.sessions.scan().get("Items", []), [])

    def test_at_threshold_pending_with_challenge(self):
        self._seed_totp()
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=5000, target={"to_user_sub": "bob"})
        self.assertEqual(out.status, "PENDING")
        self.assertTrue(out.sca_challenge_id.startswith("chal_"))
        chal = T.sessions.get_item(Key={"user_sub": self.USER, "session_id": out.sca_challenge_id}).get("Item")
        self.assertEqual(chal["purpose"], "txn_request_sca")
        self.assertTrue(chal["pending_auth"])
        self.assertEqual(chal["required_factors"], ["totp"])
        self.assertEqual(chal["passed"], {"totp": False})
        self.assertEqual(chal["request_id"], out.request_id)

    def test_sensitive_type_always_pending(self):
        for typ, target in (
            (TxnRequestType.PAYOUT, {"payout_method_id": "pm"}),
            (TxnRequestType.REFUND, {"payment_intent_id": "pi_x"}),
            (TxnRequestType.COUNTERPARTY, {"counterparty_ref": "cp"}),
        ):
            out = self._create(type=typ, amount_cents=50, target=target)
            self.assertEqual(out.status, "PENDING", typ)
            self.assertIsNotNone(out.sca_challenge_id)

    def test_free_form_below_threshold_initiated(self):
        out = self._create(type=TxnRequestType.FREE_FORM, amount_cents=100, target={})
        self.assertEqual(out.status, "INITIATED")

    def test_no_factors_email_fallback(self):
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=10000, target={"to_user_sub": "bob"})
        self.assertEqual(out.status, "PENDING")
        self.assertEqual(out.sca_required_factors, ["email"])

    def test_audit_on_sca_mint(self):
        self._seed_totp()
        with mock.patch("app.services.txn_requests.audit_event") as spy:
            out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=5000, target={"to_user_sub": "bob"})
        names = [c.args[0] for c in spy.call_args_list]
        self.assertIn("txn_request.sca_required", names)
        self.assertEqual(out.status, "PENDING")

    def test_idempotent_create_one_challenge(self):
        self._seed_totp()
        a = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=5000, target={"to_user_sub": "bob"}, idempotency_key="k9")
        b = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=5000, target={"to_user_sub": "bob"}, idempotency_key="k9")
        self.assertEqual(a.request_id, b.request_id)
        self.assertEqual(a.sca_challenge_id, b.sca_challenge_id)
        self.assertEqual(len(T.sessions.scan().get("Items", [])), 1)


# ---------------------------------------------------------------------------
# Group D — execution dispatch (TXR-004)
# ---------------------------------------------------------------------------


class TestExecute(TxnRequestsTestBase):
    def setUp(self):
        super().setUp()
        # Default: fraud gate is a no-op pass.
        self.fraud_patch = mock.patch("app.routers.billing._fraud_gate", return_value=None)
        self.fraud_patch.start()
        self.addCleanup(self.fraud_patch.stop)

    def test_wallet_transfer_happy_path(self):
        self._seed_wallet(self.USER, 500)
        self._seed_wallet(self.OTHER, 0)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.OTHER})
        self.assertEqual(out.status, "INITIATED")
        done = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(done.status, "COMPLETED")
        self.assertTrue(done.ledger_refs)
        self.assertEqual(self._wallet(self.USER), 400)
        self.assertEqual(self._wallet(self.OTHER), 100)

    def test_wallet_transfer_creates_recipient_wallet(self):
        self._seed_wallet(self.USER, 500)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "carol"})
        done = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(self._wallet("carol"), 100)

    def test_wallet_transfer_insufficient_funds(self):
        self._seed_wallet(self.USER, 50)
        self._seed_wallet(self.OTHER, 0)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.OTHER})
        with self.assertRaises(HTTPException) as ctx:
            txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(ctx.exception.status_code, 402)
        item = txr.get_request(self.USER, out.request_id)
        self.assertEqual(item["status"], "FAILED")
        self.assertEqual(item["failure_reason"], "insufficient_funds")
        self.assertEqual(self._wallet(self.USER), 50)
        self.assertEqual(self._wallet(self.OTHER), 0)

    def test_double_execute_single_debit(self):
        self._seed_wallet(self.USER, 500)
        self._seed_wallet(self.OTHER, 0)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.OTHER})
        first = txr.execute_request(self.USER, out.request_id, self.req)
        second = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(first.status, "COMPLETED")
        self.assertEqual(second.status, "COMPLETED")
        self.assertEqual(second.request_id, out.request_id)
        self.assertEqual(self._wallet(self.USER), 400)  # debited exactly once

    def test_free_form_no_recipient_debit_only(self):
        self._seed_wallet(self.USER, 500)
        out = self._create(type=TxnRequestType.FREE_FORM, amount_cents=100, target={})
        done = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(self._wallet(self.USER), 400)

    def test_execute_completed_idempotent(self):
        self._seed_wallet(self.USER, 500)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.OTHER})
        txr.execute_request(self.USER, out.request_id, self.req)
        again = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(again.status, "COMPLETED")

    def test_payout_delegates(self):
        out = self._create(type=TxnRequestType.PAYOUT, amount_cents=50, target={"payout_method_id": "pm_1"})
        # Sensitive -> PENDING; satisfy SCA by faking the challenge done.
        self._satisfy_sca(out)
        with mock.patch("app.services.creator_payouts.request_payout", return_value={"payout_id": "payout_abc"}) as rp:
            done = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(done.status, "COMPLETED")
        self.assertIn("payout_abc", done.ledger_refs)
        self.assertEqual(rp.call_args.kwargs["amount_cents"], 50)
        self.assertEqual(rp.call_args.kwargs["method_id"], "pm_1")

    def test_payout_duplicate_fails(self):
        out = self._create(type=TxnRequestType.PAYOUT, amount_cents=50, target={"payout_method_id": "pm_1"})
        self._satisfy_sca(out)
        with mock.patch("app.services.creator_payouts.request_payout", side_effect=ValueError("DUPLICATE_PAYOUT")):
            with self.assertRaises(HTTPException) as ctx:
                txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(txr.get_request(self.USER, out.request_id)["failure_reason"], "payout_duplicate")

    def test_payout_minimum_fails(self):
        out = self._create(type=TxnRequestType.PAYOUT, amount_cents=50, target={"payout_method_id": "pm_1"})
        self._satisfy_sca(out)
        with mock.patch("app.services.creator_payouts.request_payout", side_effect=ValueError("Amount must be at least 1000 cents")):
            with self.assertRaises(HTTPException) as ctx:
                txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(txr.get_request(self.USER, out.request_id)["failure_reason"], "payout_minimum_not_met")

    def test_refund_calls_do_refund_once(self):
        out = self._create(type=TxnRequestType.REFUND, amount_cents=200, target={"payment_intent_id": "pi_777"})
        self._satisfy_sca(out)
        with mock.patch("app.routers.billing._do_refund", return_value={"led_sk": "LEDGER#1#a", "refund_id": "re_1", "payment_intent_id": "pi_777"}) as dr:
            done = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(dr.call_count, 1)
        self.assertIn("LEDGER#1#a", done.ledger_refs)

    def test_refund_double_execute_single_stripe(self):
        out = self._create(type=TxnRequestType.REFUND, amount_cents=200, target={"payment_intent_id": "pi_777"})
        self._satisfy_sca(out)
        with mock.patch("app.routers.billing._do_refund", return_value={"led_sk": "LEDGER#1#a", "refund_id": "re_1", "payment_intent_id": "pi_777"}) as dr:
            txr.execute_request(self.USER, out.request_id, self.req)
            txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(dr.call_count, 1)

    def test_counterparty_fails_unsupported_balance_neutral(self):
        self._seed_wallet(self.USER, 500)
        out = self._create(type=TxnRequestType.COUNTERPARTY, amount_cents=100, target={"counterparty_ref": "cp_1"})
        self._satisfy_sca(out)
        with self.assertRaises(HTTPException) as ctx:
            txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(ctx.exception.status_code, 501)
        item = txr.get_request(self.USER, out.request_id)
        self.assertEqual(item["status"], "FAILED")
        self.assertEqual(item["failure_reason"], "counterparty_unsupported")
        self.assertEqual(self._wallet(self.USER), 500)  # debit reversed

    def test_execute_failed_request_returns_failed(self):
        self._seed_wallet(self.USER, 50)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.OTHER})
        with self.assertRaises(HTTPException):
            txr.execute_request(self.USER, out.request_id, self.req)
        # already FAILED -> idempotent return
        again = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(again.status, "FAILED")

    def test_sca_incomplete_blocks_execute(self):
        out = self._create(type=TxnRequestType.PAYOUT, amount_cents=50, target={"payout_method_id": "pm"})
        self.assertEqual(out.status, "PENDING")
        with self.assertRaises(HTTPException) as ctx:
            txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(txr.get_request(self.USER, out.request_id)["status"], "PENDING")

    def test_sca_complete_allows_and_revokes(self):
        out = self._create(type=TxnRequestType.PAYOUT, amount_cents=50, target={"payout_method_id": "pm"})
        self._satisfy_sca(out)
        with mock.patch("app.services.creator_payouts.request_payout", return_value={"payout_id": "payout_z"}):
            done = txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(done.status, "COMPLETED")
        chal = T.sessions.get_item(Key={"user_sub": self.USER, "session_id": out.sca_challenge_id}).get("Item")
        self.assertTrue(chal.get("revoked"))

    def test_fraud_frozen_account_403(self):
        self._seed_wallet(self.USER, 500)
        out = self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": self.OTHER})
        with mock.patch("app.routers.billing._fraud_gate", side_effect=HTTPException(403, "Account is frozen. Contact support.")):
            with self.assertRaises(HTTPException) as ctx:
                txr.execute_request(self.USER, out.request_id, self.req)
        self.assertEqual(ctx.exception.status_code, 403)
        item = txr.get_request(self.USER, out.request_id)
        self.assertEqual(item["status"], "FAILED")
        self.assertEqual(item["failure_reason"], "account_frozen")

    def _satisfy_sca(self, out):
        """Mark every required factor passed on the minted challenge so
        challenge_done() returns True (drives the LIVE sessions stack directly)."""
        from app.services import sessions as _sessions

        cid = out.sca_challenge_id
        self.assertIsNotNone(cid, "expected a PENDING request with a challenge")
        chal = T.sessions.get_item(Key={"user_sub": self.USER, "session_id": cid}).get("Item")
        for f in chal.get("required_factors", []):
            _sessions.mark_factor_passed(self.USER, cid, f)


# ---------------------------------------------------------------------------
# Group E — router handlers (run as coroutines, no TestClient)
# ---------------------------------------------------------------------------


class TestRouter(TxnRequestsTestBase):
    def setUp(self):
        super().setUp()
        import app.routers.txn_requests as router_mod

        self.router_mod = router_mod
        self.ctx = {"user_sub": self.USER}

    def test_router_create_and_get(self):
        body = TxnRequestCreateIn(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        out = self._run(self.router_mod.create_txn_request(body, self.req, self.ctx))
        self.assertEqual(out.status, "INITIATED")
        got = self._run(self.router_mod.get_txn_request(out.request_id, self.req, self.ctx))
        self.assertEqual(got.request_id, out.request_id)

    def test_router_list(self):
        self._create(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
        res = self._run(self.router_mod.list_txn_requests(self.req, None, None, 20, self.ctx))
        self.assertGreaterEqual(len(res.items), 1)

    def test_router_flag_off_404(self):
        object.__setattr__(S, "txn_requests_enabled", False)
        try:
            body = TxnRequestCreateIn(type=TxnRequestType.WALLET_TRANSFER, amount_cents=100, target={"to_user_sub": "bob"})
            with self.assertRaises(HTTPException) as ctx:
                self._run(self.router_mod.create_txn_request(body, self.req, self.ctx))
            self.assertEqual(ctx.exception.status_code, 404)
        finally:
            object.__setattr__(S, "txn_requests_enabled", True)


if __name__ == "__main__":
    unittest.main()
