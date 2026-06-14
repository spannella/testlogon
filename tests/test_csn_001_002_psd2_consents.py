"""CSN-001 + CSN-002: PSD2 AIS/PIS Consent hermetic tests.

Offline, no real AWS. moto in-memory DynamoDB bound to frozen T.* via
object.__setattr__. Follows the recipe in test_gap_0286_0287_kyc_partner_api.py.
"""
from __future__ import annotations

import asyncio
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _patch_frozen(tc, obj, attr, value):
    original = getattr(obj, attr)
    object.__setattr__(obj, attr, value)
    tc.addCleanup(lambda: object.__setattr__(obj, attr, original))


def _make_consents_table(ddb):
    return ddb.create_table(
        TableName="consents_test",
        KeySchema=[
            {"AttributeName": "owner_sub", "KeyType": "HASH"},
            {"AttributeName": "consent_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "consent_id", "AttributeType": "S"},
            {"AttributeName": "consumer_ref", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "valid_until", "AttributeType": "N"},
            {"AttributeName": "payment_ref", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByConsumer",
                "KeySchema": [
                    {"AttributeName": "consumer_ref", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
            {
                "IndexName": "ByStatusExpiry",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "valid_until", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
            {
                "IndexName": "ByPaymentRef",
                "KeySchema": [
                    {"AttributeName": "payment_ref", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )


def _make_sessions_table(ddb):
    return ddb.create_table(
        TableName="sessions_csn_test",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "session_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "session_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_body(**kwargs):
    """Build a minimal ConsentCreateIn-like object."""
    from app.models import ConsentCreateIn
    defaults = {
        "consumer_ref": "app1",
        "consent_type": "AIS",
        "account_refs": ["acc_001"],
        "view_refs": ["owner"],
        "valid_until": None,
        "recurring": True,
        "reason": None,
        "payment_ref": None,
    }
    defaults.update(kwargs)
    return ConsentCreateIn(**defaults)


class FakeRequest:
    headers: dict = {}
    client = None

    def __init__(self):
        self.headers = {}


@mock_aws
class TestConsentCSN001002(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._consents_table = _make_consents_table(ddb)
        self._sessions_table = _make_sessions_table(ddb)

        _patch_frozen(self, T, "consents", self._consents_table)
        _patch_frozen(self, T, "sessions", self._sessions_table)
        _patch_frozen(self, S, "psd2_consents_enabled", True)
        _patch_frozen(self, S, "open_bank_project_enabled", True)
        _patch_frozen(self, S, "consents_consumer_index", "ByConsumer")
        _patch_frozen(self, S, "consents_status_index", "ByStatusExpiry")
        _patch_frozen(self, S, "consents_by_payment_ref_index", "ByPaymentRef")
        _patch_frozen(self, S, "psd2_consent_default_ttl_days", 90)
        _patch_frozen(self, S, "psd2_consent_max_ttl_days", 365)
        _patch_frozen(self, S, "psd2_consent_expiry_poll_interval", 300)
        _patch_frozen(self, S, "psd2_consent_rl_read_per_hour", 1000)
        _patch_frozen(self, S, "psd2_consent_rl_refresh_per_hour", 100)
        _patch_frozen(self, S, "psd2_consent_pis_require_sca_factor", True)
        _patch_frozen(self, S, "psd2_consent_sca_threshold_cents", 0)
        _patch_frozen(self, S, "ddb_ttl_attr", "ttl_epoch")
        _patch_frozen(self, S, "ddb_sessions_table", "sessions_csn_test")

    # ------------------------------------------------------------------
    # CSN-001 tests
    # ------------------------------------------------------------------

    def test_01_create_consent_returns_initiated(self):
        from app.services.psd2_consents import create_consent
        body = _make_body()
        result = create_consent("alice", body, FakeRequest())
        self.assertEqual(result["status"], "INITIATED")
        self.assertTrue(result["consent_id"].startswith("csn_"))
        self.assertIsNone(result["sca_challenge_id"])
        self.assertIn("valid_until", result)

    def test_02_empty_account_refs_raises_400(self):
        from app.services.psd2_consents import create_consent
        from fastapi import HTTPException
        body = _make_body(account_refs=[])
        with self.assertRaises(HTTPException) as ctx:
            create_consent("alice", body, FakeRequest())
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("account_refs", str(ctx.exception.detail))

    def test_03_invalid_view_ref_raises_400(self):
        from app.services.psd2_consents import create_consent
        from fastapi import HTTPException
        body = _make_body(view_refs=["nonexistent_view"])
        with self.assertRaises(HTTPException) as ctx:
            create_consent("alice", body, FakeRequest())
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid view_ref", str(ctx.exception.detail))

    def test_04_valid_until_clamped(self):
        from app.services.psd2_consents import create_consent
        from app.core.time import now_ts
        far_future = now_ts() + 999 * 86400
        body = _make_body(valid_until=far_future)
        result = create_consent("alice", body, FakeRequest())
        max_until = now_ts() + S.psd2_consent_max_ttl_days * 86400
        self.assertLessEqual(result["valid_until"], max_until + 5)  # small clock skew

    def test_05_get_consent_owner_scoped(self):
        from app.services.psd2_consents import create_consent, get_consent
        body = _make_body()
        result = create_consent("alice", body, FakeRequest())
        cid = result["consent_id"]
        # Alice can see it
        self.assertIsNotNone(get_consent("alice", cid))
        # Bob cannot
        self.assertIsNone(get_consent("bob", cid))

    def test_06_list_consents_for_owner(self):
        from app.services.psd2_consents import create_consent, list_consents_for_owner
        create_consent("alice", _make_body(), FakeRequest())
        create_consent("alice", _make_body(), FakeRequest())
        create_consent("bob", _make_body(), FakeRequest())
        out = list_consents_for_owner("alice")
        self.assertEqual(len(out["consents"]), 2)

    def test_07_list_consents_consumer_isolation(self):
        from app.services.psd2_consents import create_consent, list_consents_for_consumer
        create_consent("alice", _make_body(consumer_ref="app1"), FakeRequest())
        create_consent("alice", _make_body(consumer_ref="app2"), FakeRequest())
        out1 = list_consents_for_consumer("app1")
        out2 = list_consents_for_consumer("app2")
        self.assertEqual(len(out1["consents"]), 1)
        self.assertEqual(len(out2["consents"]), 1)
        self.assertEqual(out1["consents"][0]["consumer_ref"], "app1")

    def test_08_list_status_filter(self):
        from app.services.psd2_consents import create_consent, list_consents_for_owner
        from app.core.time import now_ts
        created = create_consent("alice", _make_body(), FakeRequest())
        # Manually set one to REVOKED
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": created["consent_id"]},
            UpdateExpression="SET #st = :r",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":r": "REVOKED"},
        )
        create_consent("alice", _make_body(), FakeRequest())  # INITIATED
        out = list_consents_for_owner("alice", status="INITIATED")
        statuses = [c["status"] for c in out["consents"]]
        self.assertTrue(all(s == "INITIATED" for s in statuses))

    def test_09_revoke_initiated_consent(self):
        from app.services.psd2_consents import create_consent, revoke_consent
        with patch("app.services.alerts.audit_event"):
            created = create_consent("alice", _make_body(), FakeRequest())
            result = revoke_consent("alice", created["consent_id"], FakeRequest())
        self.assertEqual(result["status"], "REVOKED")
        self.assertIsNotNone(result["revoked_at"])

    def test_10_revoke_accepted_consent(self):
        from app.services.psd2_consents import create_consent, revoke_consent
        created = create_consent("alice", _make_body(), FakeRequest())
        # Manually set to ACCEPTED
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": created["consent_id"]},
            UpdateExpression="SET #st = :a",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED"},
        )
        result = revoke_consent("alice", created["consent_id"])
        self.assertEqual(result["status"], "REVOKED")

    def test_11_double_revoke_raises_409(self):
        from app.services.psd2_consents import create_consent, revoke_consent
        from fastapi import HTTPException
        created = create_consent("alice", _make_body(), FakeRequest())
        revoke_consent("alice", created["consent_id"])
        with self.assertRaises(HTTPException) as ctx:
            revoke_consent("alice", created["consent_id"])
        self.assertEqual(ctx.exception.status_code, 409)

    def test_12_revoke_nonexistent_raises_404(self):
        from app.services.psd2_consents import revoke_consent
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            revoke_consent("alice", "csn_doesnotexist")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_13_expire_due_consents(self):
        from app.services.psd2_consents import create_consent, expire_due_consents
        from app.core.time import now_ts
        # Create one past-due ACCEPTED consent
        created = create_consent("alice", _make_body(), FakeRequest())
        past_ts = now_ts() - 1
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": created["consent_id"]},
            UpdateExpression="SET #st = :a, valid_until = :vu",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED", ":vu": past_ts},
        )
        # Create one future ACCEPTED consent
        future = create_consent("alice", _make_body(), FakeRequest())
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": future["consent_id"]},
            UpdateExpression="SET #st = :a",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED"},
        )
        count = expire_due_consents()
        self.assertGreaterEqual(count, 1)
        # Past item is now EXPIRED
        item = self._consents_table.get_item(
            Key={"owner_sub": "alice", "consent_id": created["consent_id"]}
        ).get("Item")
        self.assertEqual(item["status"], "EXPIRED")

    def test_14_is_consent_valid(self):
        from app.services.psd2_consents import create_consent, is_consent_valid
        from app.core.time import now_ts
        created = create_consent("alice", _make_body(), FakeRequest())
        cid = created["consent_id"]
        # INITIATED → False
        valid, item = is_consent_valid("alice", cid)
        self.assertFalse(valid)
        # Set to ACCEPTED with future valid_until
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": cid},
            UpdateExpression="SET #st = :a",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED"},
        )
        valid, item = is_consent_valid("alice", cid)
        self.assertTrue(valid)
        # Wrong owner → False
        valid2, item2 = is_consent_valid("bob", cid)
        self.assertFalse(valid2)
        self.assertIsNone(item2)

    def test_15_no_billing_write(self):
        """Money-safety: no billing writes during consent lifecycle."""
        from app.services.psd2_consents import create_consent, revoke_consent
        import app.services.billing_shared as bs
        with patch.object(bs, "new_ledger_entry", MagicMock()) as mock_ledger, \
             patch.object(bs, "apply_wallet_delta", MagicMock()) as mock_wallet:
            created = create_consent("alice", _make_body(), FakeRequest())
            revoke_consent("alice", created["consent_id"])
            mock_ledger.assert_not_called()
            mock_wallet.assert_not_called()

    # ------------------------------------------------------------------
    # CSN-002: SCA gate
    # ------------------------------------------------------------------

    def test_16_request_consent_sca_mints_challenge(self):
        """SCA mint creates a sessions item with required fields."""
        from app.services.psd2_consents import create_consent, request_consent_sca

        # Patch compute_required_factors to return ["totp"]
        with patch("app.services.sessions.compute_required_factors", return_value=["totp"]):
            with patch("app.services.sessions.T", T):
                created = create_consent("alice", _make_body(), FakeRequest())
                result = request_consent_sca("alice", created["consent_id"], FakeRequest())

        self.assertIn("challenge_id", result)
        self.assertTrue(result["challenge_id"].startswith("consent_sca_"))
        self.assertEqual(result["status"], "INITIATED")
        # Verify sessions item was written
        sess_item = self._sessions_table.get_item(
            Key={"user_sub": "alice", "session_id": result["challenge_id"]}
        ).get("Item")
        self.assertIsNotNone(sess_item)
        self.assertEqual(sess_item.get("purpose"), "consent_sca")
        self.assertIn("required_factors", sess_item)
        self.assertIn("passed", sess_item)

    def test_17_accept_before_sca_raises_403(self):
        from app.services.psd2_consents import create_consent, accept_consent
        from fastapi import HTTPException
        # PIS always requires SCA (so sca_not_initiated is guaranteed)
        created = create_consent(
            "alice",
            _make_body(consent_type="PIS", payment_ref="txr_abc"),
            FakeRequest(),
        )
        with self.assertRaises(HTTPException) as ctx:
            accept_consent("alice", created["consent_id"], FakeRequest())
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("sca_not_initiated", str(ctx.exception.detail))

    def test_18_accept_with_challenge_done_succeeds(self):
        from app.services.psd2_consents import create_consent, accept_consent

        with patch("app.services.sessions.compute_required_factors", return_value=["totp"]):
            with patch("app.services.sessions.T", T):
                created = create_consent("alice", _make_body(), FakeRequest())
                from app.services.psd2_consents import request_consent_sca
                sca_result = request_consent_sca("alice", created["consent_id"], FakeRequest())

        # Patch challenge_done to return True
        with patch("app.services.sessions.challenge_done", return_value=True):
            with patch("app.services.sessions.T", T):
                result = accept_consent("alice", created["consent_id"], FakeRequest())

        self.assertEqual(result["status"], "ACCEPTED")

    def test_19_accept_replay_on_accepted_raises_409(self):
        from app.services.psd2_consents import create_consent, accept_consent
        from fastapi import HTTPException
        created = create_consent("alice", _make_body(), FakeRequest())
        # Manually set to ACCEPTED
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": created["consent_id"]},
            UpdateExpression="SET #st = :a",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED"},
        )
        with self.assertRaises(HTTPException) as ctx:
            accept_consent("alice", created["consent_id"], FakeRequest())
        self.assertEqual(ctx.exception.status_code, 409)

    # ------------------------------------------------------------------
    # CSN-002: PIS consent
    # ------------------------------------------------------------------

    def test_20_pis_consent_stores_payment_ref(self):
        from app.services.psd2_consents import create_consent, _consent_requires_sca
        body = _make_body(consent_type="PIS", payment_ref="txr_abc123")
        result = create_consent("alice", body, FakeRequest())
        self.assertEqual(result.get("payment_ref") or
                         self._consents_table.get_item(
                             Key={"owner_sub": "alice", "consent_id": result["consent_id"]}
                         ).get("Item", {}).get("payment_ref"), "txr_abc123")
        self.assertTrue(_consent_requires_sca({"consent_type": "PIS"}))

    def test_21_pis_missing_payment_ref_raises_400(self):
        from app.services.psd2_consents import create_consent
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_consent("alice", _make_body(consent_type="PIS"), FakeRequest())
        self.assertEqual(ctx.exception.status_code, 400)

    def test_22_ais_with_payment_ref_raises_400(self):
        from app.services.psd2_consents import create_consent
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_consent("alice", _make_body(consent_type="AIS", payment_ref="txr_x"), FakeRequest())
        self.assertEqual(ctx.exception.status_code, 400)

    def test_23_consent_authorizes_payment_false_before_accept(self):
        from app.services.psd2_consents import create_consent, consent_authorizes_payment
        body = _make_body(consent_type="PIS", payment_ref="txr_test_abc")
        create_consent("alice", body, FakeRequest())
        self.assertFalse(consent_authorizes_payment("txr_test_abc"))

    def test_24_consent_authorizes_payment_true_after_accept(self):
        from app.services.psd2_consents import (
            consent_authorizes_payment, create_consent, revoke_consent,
        )
        from app.core.time import now_ts
        body = _make_body(consent_type="PIS", payment_ref="txr_pis_ok")
        created = create_consent("alice", body, FakeRequest())
        cid = created["consent_id"]
        # Manually accept
        self._consents_table.update_item(
            Key={"owner_sub": "alice", "consent_id": cid},
            UpdateExpression="SET #st = :a",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":a": "ACCEPTED"},
        )
        self.assertTrue(consent_authorizes_payment("txr_pis_ok"))
        # After revoke → False
        revoke_consent("alice", cid)
        self.assertFalse(consent_authorizes_payment("txr_pis_ok"))

    def test_25_pis_no_billing_write(self):
        """PIS consent lifecycle never writes billing rows."""
        from app.services.psd2_consents import consent_authorizes_payment, create_consent
        import app.services.billing_shared as bs

        with patch.object(bs, "new_ledger_entry", MagicMock()) as mock_ledger, \
             patch.object(bs, "apply_wallet_delta", MagicMock()) as mock_wallet:
            body = _make_body(consent_type="PIS", payment_ref="txr_nomoney")
            created = create_consent("alice", body, FakeRequest())
            consent_authorizes_payment("txr_nomoney")
            mock_ledger.assert_not_called()
            mock_wallet.assert_not_called()

    # ------------------------------------------------------------------
    # CSN-002: Consent-scoped rate limit
    # ------------------------------------------------------------------

    def test_26_rate_limit_consent_429_at_cap(self):
        from app.services.rate_limit import rate_limit_consent
        from fastapi import HTTPException
        _patch_frozen(self, S, "psd2_consent_rl_read_per_hour", 3)
        consent_id = "csn_ratelimit_test"
        rate_limit_consent(consent_id, "read")
        rate_limit_consent(consent_id, "read")
        rate_limit_consent(consent_id, "read")
        with self.assertRaises(HTTPException) as ctx:
            rate_limit_consent(consent_id, "read")
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.detail["code"], "consent_rate_limited")
        self.assertEqual(ctx.exception.detail["limit"], 3)
        self.assertEqual(ctx.exception.detail["window_seconds"], 3600)
        self.assertEqual(ctx.exception.headers.get("Retry-After"), "3600")

    def test_27_rate_limit_distinct_ids_separate_budgets(self):
        from app.services.rate_limit import rate_limit_consent
        from fastapi import HTTPException
        _patch_frozen(self, S, "psd2_consent_rl_read_per_hour", 1)
        rate_limit_consent("csn_a", "read")  # uses budget for A
        rate_limit_consent("csn_b", "read")  # uses budget for B — should not 429
        with self.assertRaises(HTTPException):
            rate_limit_consent("csn_a", "read")  # A exhausted

    def test_28_flag_off_router_not_included(self):
        """When psd2_consents_enabled=False, router not in app routes."""
        _patch_frozen(self, S, "psd2_consents_enabled", False)
        from app.main import create_app
        test_app = create_app()
        paths = [str(getattr(r, "path", "")) for r in test_app.routes]
        consent_paths = [p for p in paths if "/ui/consents" in p]
        self.assertEqual(consent_paths, [])
