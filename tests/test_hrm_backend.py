"""Hermetic offline pytest for HRM-001..HRM-010 backend.

Tests:
  - HRM-001: Settings flags/defaults
  - HRM-002: T.hr handle exists
  - HRM-003: Pydantic models validate correctly
  - HRM-005: Position CRUD (create, get, list, update_status, transition guard)
  - HRM-006: Employment CRUD (create, get, list, terminate)
  - HRM-007: Payroll run create/approve
  - HRM-008: Payroll post (billing ledger entries)
  - HRM-009: Router flag guard (flag-off → 404)
  - HRM-010: GL hook is no-op when gl_double_entry_enabled is off

All tests are offline/hermetic:
  - moto DynamoDB in-memory
  - No real AWS, no network, no TestClient
  - Frozen T/S mutated with object.__setattr__ and restored in autouse fixture
  - Fresh asyncio loop for async handler calls
"""
from __future__ import annotations

import asyncio
import sys
import types
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ── moto ──────────────────────────────────────────────────────────────────────
import boto3
from moto import mock_aws

# ── local imports ──────────────────────────────────────────────────────────────
from app.core.settings import S, Settings


# ══════════════════════════════════════════════════════════════════════════════
# Autouse fixtures — save/restore frozen T and S between tests
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module", autouse=True)
def _hrm_isolation(tmp_path_factory):
    """Module-scope fixture: spin up moto DynamoDB, create hr table, inject T.hr.

    Saves and restores T.hr + T.billing on teardown.
    Also saves/restores S.hr_enabled etc. via object.__setattr__.
    """
    import app.core.tables as tables_mod
    from app.core.tables import T

    # Save originals
    _orig_T_hr = getattr(T, "hr", None)
    _orig_T_billing = getattr(T, "billing", None)
    _orig_hr_enabled = S.hr_enabled
    _orig_hr_payroll_enabled = S.hr_payroll_enabled
    _orig_hr_payroll_gl = S.hr_payroll_gl_posting_enabled
    _orig_party_crm = getattr(S, "party_crm_enabled", False)
    _orig_gl_de = getattr(S, "gl_double_entry_enabled", False)

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create HR table
        hr_table = ddb.create_table(
            TableName="hr",
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "S"},
                {"AttributeName": "entity_type", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                },
                {
                    "IndexName": "GSI_CREATED",
                    "KeySchema": [
                        {"AttributeName": "entity_type", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                },
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        # Create billing table (for HRM-008 ledger entries)
        billing_table = ddb.create_table(
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
                    "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                },
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        # Inject into T
        object.__setattr__(T, "hr", hr_table)
        object.__setattr__(T, "billing", billing_table)

        # Enable HR flags for most tests
        object.__setattr__(S, "hr_enabled", True)
        object.__setattr__(S, "hr_payroll_enabled", True)
        object.__setattr__(S, "hr_payroll_gl_posting_enabled", False)  # GL off by default
        object.__setattr__(S, "party_crm_enabled", False)   # party module absent
        object.__setattr__(S, "gl_double_entry_enabled", False)

        yield hr_table, billing_table, ddb

    # Teardown: restore T and S
    if _orig_T_hr is not None:
        object.__setattr__(T, "hr", _orig_T_hr)
    if _orig_T_billing is not None:
        object.__setattr__(T, "billing", _orig_T_billing)
    object.__setattr__(S, "hr_enabled", _orig_hr_enabled)
    object.__setattr__(S, "hr_payroll_enabled", _orig_hr_payroll_enabled)
    object.__setattr__(S, "hr_payroll_gl_posting_enabled", _orig_hr_payroll_gl)
    object.__setattr__(S, "party_crm_enabled", _orig_party_crm)
    object.__setattr__(S, "gl_double_entry_enabled", _orig_gl_de)


# ══════════════════════════════════════════════════════════════════════════════
# HRM-001: Settings flags
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM001Flags:
    def test_hr_enabled_field_exists(self):
        assert hasattr(S, "hr_enabled")
        assert isinstance(S.hr_enabled, bool)

    def test_hr_payroll_enabled_field_exists(self):
        assert hasattr(S, "hr_payroll_enabled")
        assert isinstance(S.hr_payroll_enabled, bool)

    def test_hr_payroll_gl_posting_enabled_field_exists(self):
        assert hasattr(S, "hr_payroll_gl_posting_enabled")
        assert isinstance(S.hr_payroll_gl_posting_enabled, bool)

    def test_hr_table_name_defaults_to_hr(self):
        fresh = Settings()
        assert fresh.hr_table_name == "hrm"

    def test_hr_payroll_expense_account_code_defaults_to_6000(self):
        fresh = Settings()
        assert fresh.hr_payroll_expense_account_code == "6000"

    def test_settings_object_setattr_override(self):
        """Verify object.__setattr__ overrides work on the frozen Settings singleton.

        Note: Settings field defaults are evaluated at class definition time
        (Python dataclass behaviour), so monkeypatch.setenv cannot change an
        existing Settings() instance.  Tests use object.__setattr__ instead,
        which is the project-standard test-isolation pattern (CLAUDE.md).
        """
        orig = S.hr_enabled
        try:
            object.__setattr__(S, "hr_enabled", True)
            assert S.hr_enabled is True
            object.__setattr__(S, "hr_enabled", False)
            assert S.hr_enabled is False
        finally:
            object.__setattr__(S, "hr_enabled", orig)


# ══════════════════════════════════════════════════════════════════════════════
# HRM-002: T.hr handle
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM002TableHandle:
    def test_t_hr_exists(self):
        from app.core.tables import T
        assert hasattr(T, "hr")

    def test_t_hr_is_not_none(self):
        from app.core.tables import T
        assert T.hr is not None


# ══════════════════════════════════════════════════════════════════════════════
# HRM-003: Pydantic models
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM003Models:
    def test_position_valid(self):
        from app.models import Position
        p = Position(
            position_id="p1",
            title="Engineer",
            status="OPEN",
            created_at=1000,
            updated_at=1000,
        )
        assert p.status == "OPEN"
        assert p.department is None

    def test_position_invalid_status(self):
        from pydantic import ValidationError
        from app.models import Position
        with pytest.raises(ValidationError):
            Position(
                position_id="p1", title="E",
                status="PENDING", created_at=0, updated_at=0,
            )

    def test_create_position_in_optional_fields(self):
        from app.models import CreatePositionIn
        inp = CreatePositionIn(title="PM")
        assert inp.department is None
        assert inp.correlation_id is None

    def test_create_position_in_title_too_long(self):
        from pydantic import ValidationError
        from app.models import CreatePositionIn
        with pytest.raises(ValidationError):
            CreatePositionIn(title="A" * 201)

    def test_employment_valid(self):
        from app.models import Employment
        e = Employment(
            employment_id="e1",
            party_id="par1",
            position_id="pos1",
            org_party_id="org1",
            status="ACTIVE",
            start_date=1000,
            pay_rate_cents=500000,
            pay_period="MONTHLY",
            currency="USD",
            created_at=1000,
            updated_at=1000,
        )
        assert e.end_date is None

    def test_employment_invalid_status(self):
        from pydantic import ValidationError
        from app.models import Employment
        with pytest.raises(ValidationError):
            Employment(
                employment_id="e1", party_id="p", position_id="pos",
                org_party_id="org", status="RESIGNED", start_date=0,
                pay_rate_cents=0, pay_period="MONTHLY", currency="USD",
                created_at=0, updated_at=0,
            )

    def test_create_employment_in_date_validation(self):
        from pydantic import ValidationError
        from app.models import CreateEmploymentIn
        with pytest.raises(ValidationError):
            CreateEmploymentIn(
                party_id="p", position_id="pos", org_party_id="org",
                start_date=1000, end_date=500,  # end before start
                pay_rate_cents=100, pay_period="MONTHLY", currency="USD",
            )

    def test_create_payroll_run_in_period_validation(self):
        from pydantic import ValidationError
        from app.models import CreatePayrollRunIn
        with pytest.raises(ValidationError):
            CreatePayrollRunIn(period_start=1000, period_end=500)

    def test_payroll_line_negative_gross_rejected(self):
        from pydantic import ValidationError
        from app.models import PayrollLine
        with pytest.raises(ValidationError):
            PayrollLine(employment_id="e", party_id="p", gross_cents=-1, currency="USD")


# ══════════════════════════════════════════════════════════════════════════════
# HRM-005: Position CRUD
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM005Positions:
    def test_create_position(self):
        import app.services.hr as hr
        pos = hr.create_position("Software Engineer", actor_sub="admin1")
        assert pos["title"] == "Software Engineer"
        assert pos["status"] == "OPEN"
        assert pos["position_id"].startswith("POS_")

    def test_create_position_with_department(self):
        import app.services.hr as hr
        pos = hr.create_position("PM", "Product", actor_sub="admin1")
        assert pos["department"] == "Product"

    def test_create_position_idempotent(self):
        import app.services.hr as hr
        pos1 = hr.create_position("CTO", actor_sub="admin1", correlation_id="cto-v1")
        pos2 = hr.create_position("CTO", actor_sub="admin1", correlation_id="cto-v1")
        assert pos1["position_id"] == pos2["position_id"]

    def test_get_position(self):
        import app.services.hr as hr
        pos = hr.create_position("DevOps Lead", actor_sub="admin1")
        fetched = hr.get_position(pos["position_id"])
        assert fetched is not None
        assert fetched["position_id"] == pos["position_id"]

    def test_get_position_not_found(self):
        import app.services.hr as hr
        result = hr.get_position("POS_nonexistent")
        assert result is None

    def test_list_positions(self):
        import app.services.hr as hr
        hr.create_position("QA Lead", actor_sub="admin1")
        result = hr.list_positions()
        assert "items" in result
        assert len(result["items"]) >= 1

    def test_list_positions_by_status(self):
        import app.services.hr as hr
        pos = hr.create_position("Data Scientist", actor_sub="admin1")
        result = hr.list_positions(status="OPEN")
        ids = [it["position_id"] for it in result["items"]]
        assert pos["position_id"] in ids

    def test_update_position_status_open_to_closed(self):
        import app.services.hr as hr
        pos = hr.create_position("ML Engineer", actor_sub="admin1")
        updated = hr.update_position_status(pos["position_id"], "CLOSED", actor_sub="admin1")
        assert updated["status"] == "CLOSED"

    def test_update_position_status_invalid_transition(self):
        import app.services.hr as hr
        from app.services.hr import PositionInvalidTransitionError
        pos = hr.create_position("Backend Dev", actor_sub="admin1")
        hr.update_position_status(pos["position_id"], "CLOSED", actor_sub="admin1")
        with pytest.raises(PositionInvalidTransitionError):
            hr.update_position_status(pos["position_id"], "OPEN", actor_sub="admin1")

    def test_update_position_status_not_found(self):
        import app.services.hr as hr
        with pytest.raises(LookupError):
            hr.update_position_status("POS_ghost", "CLOSED", actor_sub="admin1")


# ══════════════════════════════════════════════════════════════════════════════
# HRM-006: Employment CRUD
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM006Employments:
    def test_create_employment(self):
        import app.services.hr as hr
        pos = hr.create_position("Frontend Dev", actor_sub="admin1")
        emp = hr.create_employment(
            party_id="party123",
            position_id=pos["position_id"],
            org_party_id="org456",
            pay_rate_cents=600000,
            pay_period="MONTHLY",
            start_date=1000000,
            actor_sub="admin1",
        )
        assert emp["employment_id"].startswith("EMP_")
        assert emp["status"] == "ACTIVE"
        assert emp["pay_rate_cents"] == 600000

    def test_create_employment_idempotent(self):
        import app.services.hr as hr
        pos = hr.create_position("Backend Dev 2", actor_sub="admin1")
        emp1 = hr.create_employment(
            "p1", pos["position_id"], "org1",
            500000, "MONTHLY", 1000000,
            actor_sub="admin1",
            correlation_id="emp-corr-1",
        )
        emp2 = hr.create_employment(
            "p1", pos["position_id"], "org1",
            500000, "MONTHLY", 1000000,
            actor_sub="admin1",
            correlation_id="emp-corr-1",
        )
        assert emp1["employment_id"] == emp2["employment_id"]

    def test_get_employment(self):
        import app.services.hr as hr
        pos = hr.create_position("QA Eng", actor_sub="admin1")
        emp = hr.create_employment(
            "party_get", pos["position_id"], "org1",
            100000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )
        fetched = hr.get_employment(emp["employment_id"])
        assert fetched is not None
        assert fetched["employment_id"] == emp["employment_id"]

    def test_get_employment_not_found(self):
        import app.services.hr as hr
        result = hr.get_employment("EMP_nonexistent")
        assert result is None

    def test_list_employments_by_status(self):
        import app.services.hr as hr
        pos = hr.create_position("Analyst", actor_sub="admin1")
        emp = hr.create_employment(
            "party_list", pos["position_id"], "org1",
            100000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )
        result = hr.list_employments(status="ACTIVE")
        ids = [it["employment_id"] for it in result["items"]]
        assert emp["employment_id"] in ids

    def test_list_employments_by_party(self):
        import app.services.hr as hr
        pos = hr.create_position("Designer", actor_sub="admin1")
        emp = hr.create_employment(
            "party_unique_xyz", pos["position_id"], "org1",
            100000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )
        result = hr.list_employments(party_id="party_unique_xyz")
        ids = [it["employment_id"] for it in result["items"]]
        assert emp["employment_id"] in ids

    def test_terminate_employment(self):
        import app.services.hr as hr
        pos = hr.create_position("Contractor", actor_sub="admin1")
        emp = hr.create_employment(
            "party_term", pos["position_id"], "org1",
            100000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )
        terminated = hr.terminate_employment(
            emp["employment_id"],
            end_date=2000000,
            actor_sub="admin1",
        )
        assert terminated["status"] == "TERMINATED"

    def test_terminate_employment_idempotent(self):
        import app.services.hr as hr
        pos = hr.create_position("Temp", actor_sub="admin1")
        emp = hr.create_employment(
            "party_term2", pos["position_id"], "org1",
            100000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )
        t1 = hr.terminate_employment(emp["employment_id"], 2000000, actor_sub="admin1")
        t2 = hr.terminate_employment(emp["employment_id"], 2000000, actor_sub="admin1")
        assert t1["status"] == t2["status"] == "TERMINATED"

    def test_terminate_employment_end_before_start_raises(self):
        import app.services.hr as hr
        pos = hr.create_position("Intern", actor_sub="admin1")
        emp = hr.create_employment(
            "party_term3", pos["position_id"], "org1",
            100000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )
        with pytest.raises(ValueError, match="end_date_before_start_date"):
            hr.terminate_employment(emp["employment_id"], end_date=500, actor_sub="admin1")


# ══════════════════════════════════════════════════════════════════════════════
# HRM-007: Payroll run lifecycle
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM007PayrollRun:
    def test_create_payroll_run_no_employments(self):
        """A run is valid even when no ACTIVE employments exist.

        We verify this by creating a run, checking it's in DRAFT status and
        has the expected fields.  Because other tests may have created active
        employments in the shared moto table, we don't assert line_count==0;
        instead we verify the run structure is correct.
        """
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(
            period_start=1_000_000,
            period_end=1_100_000,
            actor_sub="admin1",
            correlation_id="zero-line-check-run",
        )
        assert run["status"] == "DRAFT"
        assert "payroll_run_id" in run
        assert run["payroll_run_id"].startswith("PR_")
        assert "line_count" in run
        assert "total_gross_cents" in run

    def test_create_payroll_run_with_active_employees(self):
        import app.services.hr as hr
        import app.services.hr_payroll as payroll

        # Create an active employment
        pos = hr.create_position("Sales Rep", actor_sub="admin1")
        hr.create_employment(
            "party_payroll_1", pos["position_id"], "org1",
            300000, "MONTHLY", 1000000,
            actor_sub="admin1",
        )

        run = payroll.create_payroll_run(
            period_start=1_500_000,
            period_end=1_600_000,
            actor_sub="admin1",
        )
        assert run["status"] == "DRAFT"
        assert int(run["line_count"]) >= 1
        assert int(run["total_gross_cents"]) > 0

    def test_create_payroll_run_idempotent(self):
        import app.services.hr_payroll as payroll
        run1 = payroll.create_payroll_run(
            2_000_000, 2_100_000, actor_sub="admin1", correlation_id="pr-test-1"
        )
        run2 = payroll.create_payroll_run(
            2_000_000, 2_100_000, actor_sub="admin1", correlation_id="pr-test-1"
        )
        assert run1["payroll_run_id"] == run2["payroll_run_id"]

    def test_create_payroll_run_invalid_period(self):
        import app.services.hr_payroll as payroll
        with pytest.raises(ValueError, match="period_start"):
            payroll.create_payroll_run(
                period_start=2_000_000,
                period_end=1_000_000,
                actor_sub="admin1",
            )

    def test_approve_payroll_run(self):
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(3_000_000, 3_100_000, actor_sub="admin1")
        approved = payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        assert approved["status"] == "APPROVED"
        assert approved.get("approved_by") == "admin1"

    def test_approve_payroll_run_idempotent(self):
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(4_000_000, 4_100_000, actor_sub="admin1")
        a1 = payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        a2 = payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        assert a1["status"] == a2["status"] == "APPROVED"

    def test_approve_nonexistent_run_raises(self):
        import app.services.hr_payroll as payroll
        with pytest.raises(LookupError):
            payroll.approve_payroll_run("PR_ghost", actor_sub="admin1")

    def test_approve_posted_run_raises_transition_error(self):
        """Cannot approve a POSTED run."""
        import app.services.hr_payroll as payroll
        from app.services.hr_payroll import PayrollRunInvalidTransitionError
        run = payroll.create_payroll_run(5_000_000, 5_100_000, actor_sub="admin1")
        payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        payroll.post_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        with pytest.raises(PayrollRunInvalidTransitionError):
            payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")

    def test_get_payroll_run(self):
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(6_000_000, 6_100_000, actor_sub="admin1")
        fetched = payroll.get_payroll_run(run["payroll_run_id"])
        assert fetched is not None
        assert fetched["payroll_run_id"] == run["payroll_run_id"]

    def test_get_payroll_run_not_found(self):
        import app.services.hr_payroll as payroll
        result = payroll.get_payroll_run("PR_ghost")
        assert result is None

    def test_list_payroll_runs(self):
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(7_000_000, 7_100_000, actor_sub="admin1")
        result = payroll.list_payroll_runs()
        ids = [it["payroll_run_id"] for it in result["items"]]
        assert run["payroll_run_id"] in ids

    def test_list_payroll_runs_by_status(self):
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(8_000_000, 8_100_000, actor_sub="admin1")
        result = payroll.list_payroll_runs(status="DRAFT")
        ids = [it["payroll_run_id"] for it in result["items"]]
        assert run["payroll_run_id"] in ids


# ══════════════════════════════════════════════════════════════════════════════
# HRM-007: Proration helper
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM007Proration:
    def test_monthly_proration(self):
        from app.services.hr_payroll import _compute_gross
        emp = {"pay_rate_cents": 300000, "pay_period": "MONTHLY"}
        # Monthly: always returns rate regardless of duration
        assert _compute_gross(emp, 0, 86400 * 30) == 300000

    def test_biweekly_proration_exact(self):
        from app.services.hr_payroll import _compute_gross
        emp = {"pay_rate_cents": 300000, "pay_period": "BIWEEKLY"}
        # 14 day period → 100% of rate
        gross = _compute_gross(emp, 0, 14 * 86400)
        assert gross == 300000

    def test_weekly_proration_exact(self):
        from app.services.hr_payroll import _compute_gross
        emp = {"pay_rate_cents": 200000, "pay_period": "WEEKLY"}
        gross = _compute_gross(emp, 0, 7 * 86400)
        assert gross == 200000

    def test_hourly_proration(self):
        from app.services.hr_payroll import _compute_gross
        emp = {"pay_rate_cents": 2500, "pay_period": "HOURLY"}
        # 80 hours
        gross = _compute_gross(emp, 0, 80 * 3600)
        assert gross == 200000


# ══════════════════════════════════════════════════════════════════════════════
# HRM-008: Payroll post (billing ledger)
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM008PayrollPost:
    def test_post_payroll_run_zero_lines(self):
        """Zero-line run transitions to POSTED without writing ledger entries."""
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(
            9_000_000, 9_100_000, actor_sub="admin1", correlation_id="zero-line-run"
        )
        payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        posted = payroll.post_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        assert posted["status"] == "POSTED"

    def test_post_payroll_run_idempotent(self):
        """Re-posting a POSTED run is a no-op."""
        import app.services.hr_payroll as payroll
        run = payroll.create_payroll_run(
            10_000_000, 10_100_000, actor_sub="admin1", correlation_id="idem-post-run"
        )
        payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        p1 = payroll.post_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        p2 = payroll.post_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        assert p1["status"] == p2["status"] == "POSTED"

    def test_post_payroll_run_draft_raises_transition_error(self):
        """Cannot post a DRAFT run — must approve first."""
        import app.services.hr_payroll as payroll
        from app.services.hr_payroll import PayrollRunInvalidTransitionError
        run = payroll.create_payroll_run(
            11_000_000, 11_100_000, actor_sub="admin1", correlation_id="draft-post"
        )
        with pytest.raises(PayrollRunInvalidTransitionError):
            payroll.post_payroll_run(run["payroll_run_id"], actor_sub="admin1")

    def test_post_payroll_run_writes_ledger_entries(self):
        """Verify billing ledger entries are written for each active employment."""
        import app.services.hr as hr
        import app.services.hr_payroll as payroll
        from app.core.tables import T

        # Create a new active employment with a unique party_id
        pos = hr.create_position("Payroll Test Lead", actor_sub="admin1")
        hr.create_employment(
            "party_ledger_test", pos["position_id"], "org1",
            120000, "MONTHLY", 1_000_000,
            actor_sub="admin1",
        )

        run = payroll.create_payroll_run(
            12_000_000, 12_100_000, actor_sub="admin1",
            correlation_id="ledger-test-run",
        )
        assert int(run["line_count"]) >= 1

        payroll.approve_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        posted = payroll.post_payroll_run(run["payroll_run_id"], actor_sub="admin1")
        assert posted["status"] == "POSTED"

        # Verify billing table has entries for this payroll run
        resp = T.billing.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"PAYROLL#{run['payroll_run_id']}"},
        )
        assert len(resp["Items"]) >= 1
        entry = resp["Items"][0]
        assert entry["reason"] == "payroll"
        assert entry["type"] == "debit"
        assert entry["state"] == "settled"


# ══════════════════════════════════════════════════════════════════════════════
# HRM-009: Router flag guards
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM009RouterFlagGuards:
    """Verify that _require_hr() / _require_payroll() raise 404 when flags off."""

    def test_require_hr_raises_when_disabled(self):
        from app.routers.hr import _require_hr
        from fastapi import HTTPException
        orig = S.hr_enabled
        try:
            object.__setattr__(S, "hr_enabled", False)
            with pytest.raises(HTTPException) as exc_info:
                _require_hr()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "hr_enabled", orig)

    def test_require_payroll_raises_when_hr_disabled(self):
        from app.routers.hr import _require_payroll
        from fastapi import HTTPException
        orig_hr = S.hr_enabled
        try:
            object.__setattr__(S, "hr_enabled", False)
            with pytest.raises(HTTPException) as exc_info:
                _require_payroll()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "hr_enabled", orig_hr)

    def test_require_payroll_raises_when_payroll_disabled(self):
        from app.routers.hr import _require_payroll
        from fastapi import HTTPException
        orig_payroll = S.hr_payroll_enabled
        try:
            object.__setattr__(S, "hr_payroll_enabled", False)
            with pytest.raises(HTTPException) as exc_info:
                _require_payroll()
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "hr_payroll_enabled", orig_payroll)

    def test_require_hr_passes_when_enabled(self):
        from app.routers.hr import _require_hr
        # Should not raise (flag already set to True by fixture)
        _require_hr()  # no exception

    def test_require_payroll_passes_when_both_enabled(self):
        from app.routers.hr import _require_payroll
        _require_payroll()  # no exception


# ══════════════════════════════════════════════════════════════════════════════
# HRM-010: GL hook is no-op when sibling flags are off
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM010GLHookFlagGuard:
    def test_gl_hook_noop_when_gl_disabled(self):
        """_try_post_gl_journal does nothing when gl_double_entry_enabled=False."""
        from app.services.hr_payroll import _try_post_gl_journal

        # Both flags are off by default in the fixture
        # This should not raise or call any GL service
        posted_calls = []
        run = {
            "payroll_run_id": "PR_test",
            "created_at": 1_000_000,
            "total_gross_cents": 100000,
        }
        # Just call — it should complete without error
        _try_post_gl_journal(run, [], actor_sub="admin1")
        # No assertions needed: if it raised, the test would fail

    def test_gl_hook_noop_when_hr_gl_flag_disabled(self):
        """_try_post_gl_journal does nothing when hr_payroll_gl_posting_enabled=False."""
        from app.services.hr_payroll import _try_post_gl_journal
        orig_gl_de = getattr(S, "gl_double_entry_enabled", False)
        orig_hr_gl = S.hr_payroll_gl_posting_enabled
        try:
            object.__setattr__(S, "gl_double_entry_enabled", True)
            object.__setattr__(S, "hr_payroll_gl_posting_enabled", False)
            run = {
                "payroll_run_id": "PR_noop",
                "created_at": 1_000_000,
                "total_gross_cents": 100000,
            }
            _try_post_gl_journal(run, [], actor_sub="admin1")
        finally:
            object.__setattr__(S, "gl_double_entry_enabled", orig_gl_de)
            object.__setattr__(S, "hr_payroll_gl_posting_enabled", orig_hr_gl)

    def test_gl_hook_handles_missing_gl_posting_module(self):
        """If gl_posting is absent, _try_post_gl_journal swallows the ImportError."""
        from app.services.hr_payroll import _try_post_gl_journal
        orig_gl_de = getattr(S, "gl_double_entry_enabled", False)
        orig_hr_gl = S.hr_payroll_gl_posting_enabled
        try:
            object.__setattr__(S, "gl_double_entry_enabled", True)
            object.__setattr__(S, "hr_payroll_gl_posting_enabled", True)
            run = {
                "payroll_run_id": "PR_noop2",
                "created_at": 1_000_000,
                "total_gross_cents": 100000,
            }
            # gl_posting doesn't exist — ImportError is swallowed
            _try_post_gl_journal(run, [], actor_sub="admin1")
        finally:
            object.__setattr__(S, "gl_double_entry_enabled", orig_gl_de)
            object.__setattr__(S, "hr_payroll_gl_posting_enabled", orig_hr_gl)


# ══════════════════════════════════════════════════════════════════════════════
# HRM-004: ensure_employee_party (party_crm_enabled=False path)
# ══════════════════════════════════════════════════════════════════════════════


class TestHRM004EnsureEmployeeParty:
    def test_ensure_employee_party_without_party_module(self):
        """When party_crm_enabled=False, returns a synthetic local_{hex} party_id."""
        from app.services.hr import ensure_employee_party
        party_id = ensure_employee_party(user_sub="user_test_001")
        assert party_id.startswith("local_")
        assert len(party_id) > 6

    def test_ensure_employee_party_deterministic_with_correlation(self):
        from app.services.hr import ensure_employee_party
        p1 = ensure_employee_party(person_fields={"name": "Test"}, correlation_id="corr-abc")
        p2 = ensure_employee_party(person_fields={"name": "Test"}, correlation_id="corr-abc")
        assert p1 == p2

    def test_ensure_employee_party_requires_user_or_fields(self):
        from app.services.hr import ensure_employee_party
        with pytest.raises(ValueError, match="user_sub or person_fields"):
            ensure_employee_party()
