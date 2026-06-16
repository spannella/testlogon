"""PMD-001 hermetic offline tests for rent_policy service + router.

Pattern: moto in-memory DynamoDB, frozen T.rent_policy via object.__setattr__,
frozen S flags via object.__setattr__, route coroutines called directly on a
fresh asyncio.new_event_loop(). No TestClient, no real AWS.

Mirrors: tests/test_gap_0265_0266_kyc_risk_scoring.py isolation pattern.
"""
from __future__ import annotations

import asyncio
import sys
import types
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Test isolation fixture — scope="module" (RULE-4)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _pmd001_isolation():
    """Inject moto-backed T.rent_policy and flip S.property_dashboard_enabled."""
    import moto
    import boto3

    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = ddb.create_table(
            TableName="rent_policy",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core import tables as T_module
        from app.core.settings import S

        _orig_rent_policy = getattr(T_module.T, "rent_policy", None)
        _orig_enabled = getattr(S, "property_dashboard_enabled", False)

        object.__setattr__(T_module.T, "rent_policy", tbl)
        object.__setattr__(S, "property_dashboard_enabled", True)

        # Clear module-level cache before each test module run
        import app.services.rent_policy as svc
        svc._cache.clear()

        yield tbl

        # Restore
        if _orig_rent_policy is not None:
            object.__setattr__(T_module.T, "rent_policy", _orig_rent_policy)
        object.__setattr__(S, "property_dashboard_enabled", _orig_enabled)
        svc._cache.clear()


def _run(coro):
    """Run an async coroutine on a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_cache():
    import app.services.rent_policy as svc
    svc._cache.clear()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRentPolicyService:
    """Directly test service-layer functions (no HTTP)."""

    def setup_method(self):
        _clear_cache()

    def test_effective_default_no_row(self):
        """get_policy returns defaults with is_default=True when no row exists."""
        import app.services.rent_policy as svc
        policy = svc.get_policy("owner_no_row")
        assert policy["rent_due_day"] == 1
        assert policy["late_fee_cents"] == 0
        assert policy["grace_period_days"] == 0
        assert policy["currency"] == "usd"
        assert policy["is_default"] is True
        assert policy["updated_at"] is None
        assert policy["updated_by"] is None

    def test_set_policy_then_get(self):
        """Saved policy overrides defaults; is_default becomes False."""
        import app.services.rent_policy as svc
        svc.set_policy(
            "owner_saved",
            rent_due_day=15,
            late_fee_cents=5000,
            grace_period_days=5,
            currency="gbp",
            actor_sub="admin_1",
        )
        _clear_cache()
        policy = svc.get_policy("owner_saved")
        assert policy["rent_due_day"] == 15
        assert policy["late_fee_cents"] == 5000
        assert policy["grace_period_days"] == 5
        assert policy["currency"] == "gbp"
        assert policy["is_default"] is False
        assert policy["updated_by"] == "admin_1"
        assert policy["updated_at"] is not None

    def test_validation_rent_due_day_zero(self):
        import app.services.rent_policy as svc
        with pytest.raises(ValueError, match="rent_due_day"):
            svc._validate_policy(0, 0, 0, "usd")

    def test_validation_rent_due_day_29(self):
        import app.services.rent_policy as svc
        with pytest.raises(ValueError, match="rent_due_day"):
            svc._validate_policy(29, 0, 0, "usd")

    def test_validation_rent_due_day_28_ok(self):
        import app.services.rent_policy as svc
        # Should not raise
        svc._validate_policy(28, 0, 0, "usd")

    def test_validation_late_fee_negative(self):
        import app.services.rent_policy as svc
        with pytest.raises(ValueError, match="late_fee_cents"):
            svc._validate_policy(1, -1, 0, "usd")

    def test_validation_grace_period_negative(self):
        import app.services.rent_policy as svc
        with pytest.raises(ValueError, match="grace_period_days"):
            svc._validate_policy(1, 0, -1, "usd")

    def test_validation_currency_2_chars(self):
        import app.services.rent_policy as svc
        with pytest.raises(ValueError, match="currency"):
            svc._validate_policy(1, 0, 0, "US")

    def test_validation_currency_non_alpha(self):
        import app.services.rent_policy as svc
        with pytest.raises(ValueError, match="currency"):
            svc._validate_policy(1, 0, 0, "1US")

    def test_validation_currency_usd_normalized(self):
        import app.services.rent_policy as svc
        # Should not raise; currency normalized to lowercase
        result = svc.set_policy(
            "owner_usd_norm",
            rent_due_day=1,
            late_fee_cents=0,
            grace_period_days=0,
            currency="USD",
            actor_sub="admin_x",
        )
        assert result["currency"] == "usd"

    def test_audit_row_appended_on_each_set(self):
        """Two consecutive set_policy calls produce two AUDIT rows."""
        import app.services.rent_policy as svc
        owner = "owner_audit_test"
        svc.set_policy(owner, rent_due_day=1, late_fee_cents=0, grace_period_days=0,
                       currency="usd", actor_sub="admin_a")
        svc.set_policy(owner, rent_due_day=1, late_fee_cents=0, grace_period_days=0,
                       currency="usd", actor_sub="admin_a")
        _clear_cache()
        audit = svc.list_policy_audit(owner, limit=50)
        assert audit["count"] == 2

    def test_cache_invalidation_on_set(self):
        """Cache is invalidated after set_policy; next get reads fresh DDB value."""
        import app.services.rent_policy as svc
        owner = "owner_cache_test"
        # First get → populates cache with defaults
        policy1 = svc.get_policy(owner)
        assert policy1["is_default"] is True
        # Set policy (invalidates cache)
        svc.set_policy(owner, rent_due_day=10, late_fee_cents=100, grace_period_days=2,
                       currency="eur", actor_sub="admin_b")
        # Next get reads fresh from DDB
        policy2 = svc.get_policy(owner)
        assert policy2["rent_due_day"] == 10
        assert policy2["is_default"] is False

    def test_flag_off_raises_404(self):
        """When property_dashboard_enabled=False, get_policy raises HTTPException(404)."""
        from app.core.settings import S
        from fastapi import HTTPException
        import app.services.rent_policy as svc
        object.__setattr__(S, "property_dashboard_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.get_policy("owner_x")
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "property_dashboard_enabled", True)

    def test_second_identical_put_writes_second_audit_row(self):
        """Two identical PUTs produce two AUDIT rows (audit is append-only)."""
        import app.services.rent_policy as svc
        owner = "owner_idempotent_audit"
        kwargs = dict(rent_due_day=5, late_fee_cents=1000,
                      grace_period_days=3, currency="usd", actor_sub="adm")
        svc.set_policy(owner, **kwargs)
        svc.set_policy(owner, **kwargs)
        # CURRENT row should be exactly 1
        from app.core.tables import T
        resp = T.rent_policy.query(
            KeyConditionExpression=(
                __import__("boto3").dynamodb.conditions.Key("pk").eq(f"POLICY#{owner}")
                & __import__("boto3").dynamodb.conditions.Key("sk").eq("CURRENT")
            )
        )
        assert len(resp["Items"]) == 1
        # AUDIT rows should be 2
        audit = svc.list_policy_audit(owner)
        assert audit["count"] == 2

    def test_audit_pagination(self):
        """Seed 5 audit rows; paginate with limit=3."""
        import app.services.rent_policy as svc
        owner = "owner_audit_paginate"
        for i in range(5):
            svc.set_policy(owner, rent_due_day=i + 1, late_fee_cents=0,
                           grace_period_days=0, currency="usd", actor_sub="adm")
        page1 = svc.list_policy_audit(owner, limit=3)
        assert page1["count"] == 3
        assert page1["cursor"] is not None
        page2 = svc.list_policy_audit(owner, limit=3, cursor=page1["cursor"])
        assert page2["count"] == 2
        assert page2["cursor"] is None

    def test_cross_owner_isolation(self):
        """set_policy for owner_a does not affect owner_b."""
        import app.services.rent_policy as svc
        svc.set_policy("owner_a_iso", rent_due_day=20, late_fee_cents=0,
                       grace_period_days=0, currency="usd", actor_sub="adm")
        _clear_cache()
        policy_b = svc.get_policy("owner_b_iso")
        assert policy_b["is_default"] is True
        assert policy_b["rent_due_day"] == 1

    def test_admin_actor_recorded_in_audit(self):
        """audit row actor_sub matches admin who called, not owner_sub."""
        import app.services.rent_policy as svc
        svc.set_policy("owner_for_admin_test", rent_due_day=3, late_fee_cents=0,
                       grace_period_days=0, currency="usd", actor_sub="admin_recorded")
        audit = svc.list_policy_audit("owner_for_admin_test")
        assert audit["entries"][0]["actor_sub"] == "admin_recorded"
