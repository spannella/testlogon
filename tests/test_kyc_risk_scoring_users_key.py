"""Regression test for GAP-0023.

``KycRiskScoringService._compute_country_risk`` / ``_compute_profile_completeness``
/ ``_compute_account_age`` previously read the users table with a composite
``Key={"pk": f"USER#{user_sub}", "sk": "PROFILE"}``. The real ``users`` table has
a single ``user_sub`` partition key and no sort key, so ``GetItem`` silently
returned an empty item for every user. As a result all three factors always
returned their "data unavailable" fallback (country=30, completeness=80,
account_age=60), inflating every user's KYC risk score.

The fix reads the data via the same mechanism the rest of the codebase uses:

* country / nationality + created_at -> ``T.users.get_item(Key={"user_sub": ...})``
  (matching ``kyc_sanctions_screening`` / ``registration``)
* first_name / last_name / birthday -> ``app.services.profile.get_profile`` (the
  profile table stores the date of birth as ``birthday``, not ``date_of_birth``)

These tests use real ``moto`` (in-memory DynamoDB) with the production key schema,
so no real AWS is required. They FAIL before the fix (scores 30 / 80 / 60) and
PASS after (scores 0).
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from app.core.time import now_ts


@pytest.fixture
def ddb_tables():
    """Create real-schema ``users`` and ``profile`` tables in moto and wire the
    service's table handles + the profile service's table handle to them.

    ``T`` is a frozen dataclass, so attributes are swapped via
    ``object.__setattr__`` and restored afterwards.
    """
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        users = ddb.create_table(
            TableName="test-users",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        profile = ddb.create_table(
            TableName="test-profile",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        users.wait_until_exists()
        profile.wait_until_exists()

        # Point the shared table registry at the moto tables. Both the risk
        # scorer (T.users) and the profile service (T.profile) read through `T`.
        from app.core import tables as tables_mod

        orig = {name: getattr(tables_mod.T, name) for name in ("users", "profile")}
        object.__setattr__(tables_mod.T, "users", users)
        object.__setattr__(tables_mod.T, "profile", profile)
        try:
            yield {"users": users, "profile": profile}
        finally:
            for name, value in orig.items():
                object.__setattr__(tables_mod.T, name, value)


def _make_scorer():
    from app.services.kyc_risk_scoring import KycRiskScoringService

    return KycRiskScoringService()


def test_country_risk_reads_real_profile(ddb_tables):
    """_compute_country_risk must return score 0 for a known low-risk country."""
    user_sub = "test-user-country"
    ddb_tables["users"].put_item(
        Item={
            "user_sub": user_sub,
            "country": "GB",
            "created_at": now_ts() - 200 * 86400,
        }
    )

    result = _make_scorer()._compute_country_risk(case_id="c1", user_sub=user_sub)

    # BEFORE fix: score == 30 ("unknown", composite key never matched).
    # AFTER fix:  score == 0  (GB is a low-risk country).
    assert result["score"] == 0, f"Expected score 0 for GB, got {result}"
    assert result["raw_value"] == "GB"


def test_account_age_reads_created_at(ddb_tables):
    """_compute_account_age must read created_at from the users table."""
    user_sub = "test-user-age"
    ddb_tables["users"].put_item(
        Item={"user_sub": user_sub, "created_at": now_ts() - 200 * 86400}
    )

    result = _make_scorer()._compute_account_age(case_id="c2", user_sub=user_sub)

    # BEFORE fix: score == 60 ("unknown"). AFTER fix: score == 0 (>180 days old).
    assert result["score"] == 0, f"Expected score 0 for 200-day-old account, got {result}"


def test_profile_completeness_reads_real_fields(ddb_tables):
    """_compute_profile_completeness must count populated fields across the
    profile table (first/last/birthday) and the users table (email)."""
    user_sub = "test-user-profile"
    # Profile service nests fields under a "profile" sub-document and stores the
    # date of birth as "birthday".
    ddb_tables["profile"].put_item(
        Item={
            "user_sub": user_sub,
            "profile": {
                "first_name": "Alice",
                "last_name": "Smith",
                "birthday": "1990-01-01",
            },
        }
    )
    ddb_tables["users"].put_item(
        Item={"user_sub": user_sub, "email": "alice@example.com"}
    )

    result = _make_scorer()._compute_profile_completeness(case_id="c3", user_sub=user_sub)

    # BEFORE fix: score == 80 (4 fields "missing" from the empty composite read).
    # AFTER fix:  score == 0  (all 4 critical fields present).
    assert result["score"] == 0, f"Expected score 0 for complete profile, got {result}"
    assert result["raw_value"] == "complete"


def test_country_risk_still_falls_back_when_genuinely_absent(ddb_tables):
    """Sanity: a user with no record still gets the unknown-country fallback."""
    result = _make_scorer()._compute_country_risk(case_id="c4", user_sub="nobody")
    assert result["score"] == 30
    assert result["raw_value"] == "unknown"
