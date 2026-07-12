"""PMD-003 hermetic offline tests for portfolio_dashboard service.

Tests compute_kpis / monthly_rent_snapshot / priority_items.
Uses moto-backed T.billing for ledger rows; sibling clusters (PROP/LSE/WOV)
are either absent (flag-off) or stubbed via monkeypatch.

Pattern: frozen T/S via object.__setattr__, no real AWS, no TestClient.
"""
from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException


@pytest.fixture(scope="module", autouse=True)
def _pmd003_isolation():
    """Set up moto-backed T.billing and T.rent_policy; enable flags."""
    import moto
    import boto3

    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        billing_tbl = ddb.create_table(
            TableName="pmd003_billing",
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

        rent_policy_tbl = ddb.create_table(
            TableName="pmd003_rent_policy",
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

        _orig_billing = getattr(T_module.T, "billing", None)
        _orig_rent_policy = getattr(T_module.T, "rent_policy", None)
        _orig_enabled = getattr(S, "property_dashboard_enabled", False)
        _orig_leases = getattr(S, "leases_enabled", False)
        _orig_prop = getattr(S, "property_mgmt_enabled", False)
        _orig_wo = getattr(S, "work_orders_enabled", False)

        object.__setattr__(T_module.T, "billing", billing_tbl)
        object.__setattr__(T_module.T, "rent_policy", rent_policy_tbl)
        object.__setattr__(S, "property_dashboard_enabled", True)
        # Keep sibling flags OFF (RULE-2: guard on their flags)
        object.__setattr__(S, "leases_enabled", False)
        object.__setattr__(S, "property_mgmt_enabled", False)
        object.__setattr__(S, "work_orders_enabled", False)

        yield {"billing": billing_tbl, "rent_policy": rent_policy_tbl}

        # Restore
        if _orig_billing is not None:
            object.__setattr__(T_module.T, "billing", _orig_billing)
        if _orig_rent_policy is not None:
            object.__setattr__(T_module.T, "rent_policy", _orig_rent_policy)
        object.__setattr__(S, "property_dashboard_enabled", _orig_enabled)
        object.__setattr__(S, "leases_enabled", _orig_leases)
        object.__setattr__(S, "property_mgmt_enabled", _orig_prop)
        object.__setattr__(S, "work_orders_enabled", _orig_wo)


def _seed_ledger_row(billing_tbl, owner_sub: str, entry_type: str,
                      amount_cents: int, state: str = "settled",
                      ledger_date: str = "2025-03-01", ts: int = 1700000000):
    billing_tbl.put_item(Item={
        "pk":          f"USER#{owner_sub}",
        "sk":          f"LEDGER#{ts}#{entry_type[:4]}",
        "type":        entry_type,
        "state":       state,
        "amount_cents": Decimal(str(amount_cents)),
        "ledger_date": ledger_date,
        "ts":          Decimal(str(ts)),
    })


class TestComputeKpis:

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        import app.services.portfolio_dashboard as svc
        object.__setattr__(S, "property_dashboard_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc:
                svc.compute_kpis("owner_x")
            assert exc.value.status_code == 404
        finally:
            object.__setattr__(S, "property_dashboard_enabled", True)

    def test_empty_returns_zero_kpis(self):
        """Owner with no data returns all-zero KPIs (no error)."""
        import app.services.portfolio_dashboard as svc
        result = svc.compute_kpis("empty_owner")
        assert result["occupancy_rate"] == 0.0
        assert result["active_lease_count"] == 0
        assert result["outstanding_rent_cents"] == 0
        assert result["open_work_order_count"] == 0
        assert "computed_at" in result

    def test_outstanding_rent_from_ledger(self, _pmd003_isolation):
        """outstanding_rent_cents computed from ledger when BALANCE absent."""
        import app.services.portfolio_dashboard as svc
        billing_tbl = _pmd003_isolation["billing"]
        owner = "owner_ledger_test"
        _seed_ledger_row(billing_tbl, owner, "rent_charge", 120000, ts=1700000001)
        _seed_ledger_row(billing_tbl, owner, "rent_payment", 60000, ts=1700000002)
        result = svc.compute_kpis(owner)
        # No BALANCE row, so fallback sums rent_charge rows only (spec design)
        assert result["outstanding_rent_cents"] == 120000

    def test_reversed_rows_excluded(self, _pmd003_isolation):
        """Reversed ledger rows are excluded from KPIs."""
        import app.services.portfolio_dashboard as svc
        billing_tbl = _pmd003_isolation["billing"]
        owner = "owner_reversed"
        _seed_ledger_row(billing_tbl, owner, "rent_charge", 50000, state="reversed",
                         ts=1700000010)
        result = svc.compute_kpis(owner)
        assert result["outstanding_rent_cents"] == 0

    def test_sibling_flags_off_do_not_error(self):
        """When PROP/LSE/WOV flags are off, all degrade to 0 (no exception)."""
        import app.services.portfolio_dashboard as svc
        from app.core.settings import S
        # All sibling flags are already OFF per fixture
        result = svc.compute_kpis("owner_degraded")
        assert result["occupancy_rate"] == 0.0
        assert result["active_lease_count"] == 0
        assert result["open_work_order_count"] == 0


class TestMonthlyRentSnapshot:

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        import app.services.portfolio_dashboard as svc
        object.__setattr__(S, "property_dashboard_enabled", False)
        try:
            with pytest.raises(HTTPException):
                svc.monthly_rent_snapshot("owner_x", year=2025, month=3)
        finally:
            object.__setattr__(S, "property_dashboard_enabled", True)

    def test_invalid_month_raises_422(self):
        import app.services.portfolio_dashboard as svc
        with pytest.raises(HTTPException) as exc:
            svc.monthly_rent_snapshot("owner_y", year=2025, month=13)
        assert exc.value.status_code == 422

    def test_invalid_year_raises_422(self):
        import app.services.portfolio_dashboard as svc
        with pytest.raises(HTTPException) as exc:
            svc.monthly_rent_snapshot("owner_z", year=1999, month=1)
        assert exc.value.status_code == 422

    def test_snapshot_buckets_correct(self, _pmd003_isolation):
        """charged=charged, collected=payment, outstanding=charge-payment."""
        import app.services.portfolio_dashboard as svc
        billing_tbl = _pmd003_isolation["billing"]
        owner = "owner_snapshot_test"
        _seed_ledger_row(billing_tbl, owner, "rent_charge", 100000,
                         ledger_date="2025-01-01", ts=1700001000)
        _seed_ledger_row(billing_tbl, owner, "rent_payment", 60000,
                         ledger_date="2025-01-15", ts=1700001001)
        result = svc.monthly_rent_snapshot(owner, year=2025, month=1)
        assert result["charged_cents"] == 100000
        assert result["collected_cents"] == 60000
        assert result["outstanding_cents"] == 40000
        assert result["year"] == 2025
        assert result["month"] == 1

    def test_snapshot_no_data_returns_zeros(self):
        import app.services.portfolio_dashboard as svc
        result = svc.monthly_rent_snapshot("owner_empty_snap", year=2025, month=6)
        assert result["charged_cents"] == 0
        assert result["collected_cents"] == 0
        assert result["outstanding_cents"] == 0
        assert result["overdue_cents"] == 0

    def test_reconciliation_invariant(self, _pmd003_isolation):
        """collected + outstanding == charged (within rounding)."""
        import app.services.portfolio_dashboard as svc
        billing_tbl = _pmd003_isolation["billing"]
        owner = "owner_invariant"
        _seed_ledger_row(billing_tbl, owner, "rent_charge", 200000,
                         ledger_date="2025-02-01", ts=1700002000)
        _seed_ledger_row(billing_tbl, owner, "rent_payment", 150000,
                         ledger_date="2025-02-10", ts=1700002001)
        result = svc.monthly_rent_snapshot(owner, year=2025, month=2)
        assert result["collected_cents"] + result["outstanding_cents"] == result["charged_cents"]
        assert result["overdue_cents"] <= result["outstanding_cents"]


class TestPriorityItems:

    def test_flag_off_raises_404(self):
        from app.core.settings import S
        import app.services.portfolio_dashboard as svc
        object.__setattr__(S, "property_dashboard_enabled", False)
        try:
            with pytest.raises(HTTPException):
                svc.priority_items("owner_x")
        finally:
            object.__setattr__(S, "property_dashboard_enabled", True)

    def test_empty_returns_no_items(self):
        import app.services.portfolio_dashboard as svc
        result = svc.priority_items("owner_no_items")
        assert result["count"] == 0
        assert result["upcoming_expirations"] == []
        assert result["open_work_orders"] == []

    def test_ticket_fallback_when_wov_disabled(self):
        """When WOV disabled, falls back to TicketStore; returns gracefully."""
        import app.services.portfolio_dashboard as svc
        from app.core.settings import S
        # work_orders_enabled is False per fixture; ticket fallback is attempted
        # With no ticket data seeded, open_work_orders list is empty
        result = svc.priority_items("owner_no_wov")
        assert "open_work_orders" in result
        assert isinstance(result["open_work_orders"], list)

    def test_limit_applied(self):
        import app.services.portfolio_dashboard as svc
        result = svc.priority_items("owner_limit_test", limit=5)
        assert result["count"] <= 5


class TestPortfolioRouter:
    """Call async route handlers directly on a fresh event loop."""

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_kpis_endpoint(self):
        from app.routers.portfolio_dashboard import get_portfolio_kpis
        session = {"user_sub": "router_test_owner"}
        result = self._run(get_portfolio_kpis(session=session))
        assert hasattr(result, "occupancy_rate") or isinstance(result, dict)

    def test_rent_snapshot_endpoint(self):
        from app.routers.portfolio_dashboard import get_rent_snapshot
        session = {"user_sub": "router_snap_owner"}
        result = self._run(get_rent_snapshot(year=2025, month=3, session=session))
        assert hasattr(result, "charged_cents") or isinstance(result, dict)

    def test_priority_items_endpoint(self):
        from app.routers.portfolio_dashboard import get_priority_items
        session = {"user_sub": "router_priority_owner"}
        result = self._run(get_priority_items(limit=10, session=session))
        assert hasattr(result, "count") or isinstance(result, dict)
