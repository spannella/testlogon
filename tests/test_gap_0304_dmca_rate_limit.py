"""Offline regression test for GAP-0304 (MOD-002).

GAP-0304 — ``file_dmca_claim`` in ``app/services/dmca_claims.py`` performed no
per-claimant rate limiting, so a single claimant could file unbounded DMCA
takedown claims. The fix adds ``_check_claimant_rate_limit`` which queries the
``ByClaimantCreatedAt`` GSI (partition=claimant_email, sort=created_at) for the
claimant's claims in the last 24h and raises HTTP 429 once the configurable cap
(``S.dmca_max_claims_per_claimant_per_day``) is reached.

Fully offline: a real in-memory DynamoDB ``dmca_claims`` table (including the
``ByClaimantCreatedAt`` GSI) is created with moto and bound to the exact frozen
handle the service uses (``T.dmca_claims``) via ``object.__setattr__``. The
side-effecting collaborators of ``file_dmca_claim`` (content hiding, owner
resolution, strike counting, alerts, audit) are stubbed so a successful filing
only touches the DDB table. The cap is lowered to 3 via ``object.__setattr__``.

FAILS BEFORE FIX: with no rate limit, the 4th filing succeeds.
PASSES AFTER FIX: the 4th filing raises HTTP 429; claims older than 24h don't
count toward the limit.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_dmca_table(ddb):
    """Create the dmca_claims table mirroring scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="DmcaClaims",
        KeySchema=[{"AttributeName": "claim_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "claim_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "target_user_id", "AttributeType": "S"},
            {"AttributeName": "claimant_email", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "waiting_period_expires_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByTargetUserCreatedAt",
                "KeySchema": [
                    {"AttributeName": "target_user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByClaimantCreatedAt",
                "KeySchema": [
                    {"AttributeName": "claimant_email", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByWaitingPeriodExpiry",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "waiting_period_expires_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _claim_input(email: str) -> dict:
    return {
        "claimant_name": "Rights Holder",
        "claimant_email": email,
        "claimant_address": "1 Copyright Ave",
        "claimant_phone": "555-0100",
        "content_url": "",
        "content_type": "other",
        "content_id": "",
        "original_work_description": "My original work",
        "sworn_statement": True,
        "good_faith_belief": True,
        "signature": "RH",
    }


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestDmcaClaimantRateLimitGap0304(unittest.TestCase):
    CAP = 3

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_dmca_table(ddb)

        from app.core.settings import S
        from app.core.tables import T
        from app.services import dmca_claims

        self.dmca_claims = dmca_claims
        self.S = S
        self.T = T

        # Bind the moto table to the EXACT frozen handle the service uses.
        self._orig_table = T.dmca_claims
        object.__setattr__(T, "dmca_claims", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "dmca_claims", self._orig_table))

        # Lower the cap on the frozen settings object.
        self._orig_cap = S.dmca_max_claims_per_claimant_per_day
        object.__setattr__(S, "dmca_max_claims_per_claimant_per_day", self.CAP)
        self.addCleanup(
            lambda: object.__setattr__(
                S, "dmca_max_claims_per_claimant_per_day", self._orig_cap
            )
        )

        # Stub the side-effecting collaborators so a successful filing only
        # touches the DDB table (no content ops, alerts, audit, bans).
        for name, retval in (
            ("hide_content_for_dmca", {}),
            ("write_alert", None),
            ("write_moderation_audit_event", None),
            ("apply_ban", None),
            ("resolve_content_owner", ""),
        ):
            self.stack.enter_context(
                patch.object(dmca_claims, name, lambda *a, _r=retval, **k: _r)
            )
        self.stack.enter_context(
            patch.object(
                dmca_claims, "resolve_content_from_url", lambda *a, **k: ("other", "")
            )
        )
        # count_strikes itself queries the table; keep it deterministic.
        self.stack.enter_context(
            patch.object(dmca_claims, "count_strikes", lambda *a, **k: 0)
        )

    def test_filings_up_to_cap_succeed_then_429(self):
        email = "claimant@example.com"
        for i in range(self.CAP):
            res = self.dmca_claims.file_dmca_claim(_claim_input(email), f"user_{i}")
            self.assertTrue(res["ok"], f"filing {i} should succeed")

        with self.assertRaises(HTTPException) as ctx:
            self.dmca_claims.file_dmca_claim(_claim_input(email), "user_over")
        self.assertEqual(ctx.exception.status_code, 429)

    def test_other_claimant_not_affected(self):
        email_a = "a@example.com"
        for i in range(self.CAP):
            self.dmca_claims.file_dmca_claim(_claim_input(email_a), f"a_{i}")
        # A different claimant email has its own budget.
        res = self.dmca_claims.file_dmca_claim(_claim_input("b@example.com"), "b_0")
        self.assertTrue(res["ok"])

    def test_old_claims_do_not_count(self):
        email = "old@example.com"
        from app.core.time import now_ts

        # Seed CAP claims with created_at older than 24h directly.
        old_ts = now_ts() - 86400 - 3600
        for i in range(self.CAP):
            self.table.put_item(
                Item={
                    "claim_id": f"dmca_old_{i}",
                    "entity_type": "dmca_claim",
                    "status": "content_removed",
                    "claimant_name": "Old",
                    "claimant_email": email,
                    "created_at": old_ts,
                    "updated_at": old_ts,
                }
            )
        # Despite CAP existing claims, all are >24h old -> a new filing succeeds.
        res = self.dmca_claims.file_dmca_claim(_claim_input(email), "fresh")
        self.assertTrue(res["ok"])


if __name__ == "__main__":
    unittest.main()
