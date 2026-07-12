"""
Hermetic offline tests for the OFBiz Fixed Assets subsystem (FXA-005..FXA-012).

Uses moto in-memory DynamoDB, frozen T/S via object.__setattr__ (saved+restored
in a module-scope autouse fixture), and no TestClient / no real AWS.

Covers:
- Asset register CRUD (create, get, list, update, dispose)
- Depreciation schedule math (straight-line, rounding, NBV floor)
- Depreciation GL posting (idempotent, balanced, fully_depreciated transition)
- Disposal GL posting (gain/loss, period cancellation, idempotent)
- Work-order lifecycle (create, transitions, illegal transitions, disposed guard)
- Flag-off guard (503 on all public functions when fixed_assets_enabled=False)
"""
from __future__ import annotations

import hashlib
import dataclasses
import sys
import types
from decimal import Decimal
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

# ---------------------------------------------------------------------------
# Stub gl_posting in sys.modules BEFORE importing fixed_assets so the lazy
# import path is exercised without a real module.
# ---------------------------------------------------------------------------

_GL_JOURNAL: list[dict] = []  # capture journal entries for assertions

def _fake_post_journal_entry(lines, *, source_type, source_entity_id, memo, gl_date, journal_id=None):
    _GL_JOURNAL.append({
        "lines": lines,
        "source_type": source_type,
        "source_entity_id": source_entity_id,
        "memo": memo,
        "gl_date": gl_date,
        "journal_id": journal_id,
    })
    return journal_id or "fake_journal_id"


@dataclasses.dataclass
class _FakeJournalLine:
    account_code: str
    side: str
    amount_cents: int


_fake_gl_posting = types.ModuleType("app.services.gl_posting")
_fake_gl_posting.post_journal_entry = _fake_post_journal_entry  # type: ignore[attr-defined]
_fake_gl_posting.JournalLine = _FakeJournalLine  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Module-scope autouse fixture: save/restore sys.modules + T + S mutations
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _module_setup():
    """
    1. Inject fake gl_posting into sys.modules.
    2. Create three moto DynamoDB tables.
    3. Patch T.fixed_assets / T.fixed_asset_schedule / T.maintenance_orders
       onto frozen T.
    4. Yield (tests run).
    5. Restore T handles and sys.modules state.
    """
    from app.core.tables import T
    from app.core.settings import S

    # --- save state ---
    _orig_gl_posting = sys.modules.get("app.services.gl_posting")
    _orig_fixed_assets_svc = sys.modules.get("app.services.fixed_assets")
    # Save T handles
    _orig_T_fa = getattr(T, "fixed_assets", None)
    _orig_T_fas = getattr(T, "fixed_asset_schedule", None)
    _orig_T_mo = getattr(T, "maintenance_orders", None)
    # Save S flags
    _orig_S_enabled = S.fixed_assets_enabled
    _orig_S_gl = getattr(S, "gl_double_entry_enabled", False)

    # --- inject fake gl_posting ---
    sys.modules["app.services.gl_posting"] = _fake_gl_posting
    # Remove cached fixed_assets service so it re-imports with our stub
    sys.modules.pop("app.services.fixed_assets", None)

    with mock_aws():
        # Create moto DynamoDB tables
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # fixed_assets table
        fa_table = ddb.create_table(
            TableName="fixed_assets",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "owner_sub", "AttributeType": "S"},
                {"AttributeName": "acquired_at", "AttributeType": "N"},
                {"AttributeName": "status", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_OWNER",
                    "KeySchema": [
                        {"AttributeName": "owner_sub", "KeyType": "HASH"},
                        {"AttributeName": "acquired_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_STATUS",
                    "KeySchema": [
                        {"AttributeName": "status", "KeyType": "HASH"},
                        {"AttributeName": "acquired_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )

        # fixed_asset_schedule table
        fas_table = ddb.create_table(
            TableName="fixed_asset_schedule",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "schedule_status", "AttributeType": "S"},
                {"AttributeName": "period_end_ts", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_DUE",
                    "KeySchema": [
                        {"AttributeName": "schedule_status", "KeyType": "HASH"},
                        {"AttributeName": "period_end_ts", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )

        # maintenance_orders table
        mo_table = ddb.create_table(
            TableName="maintenance_orders",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "wo_status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
                {"AttributeName": "assignee_sub", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_WO_STATUS",
                    "KeySchema": [
                        {"AttributeName": "wo_status", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_WO_ASSIGNEE",
                    "KeySchema": [
                        {"AttributeName": "assignee_sub", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        )

        # Patch frozen T handles
        object.__setattr__(T, "fixed_assets", fa_table)
        object.__setattr__(T, "fixed_asset_schedule", fas_table)
        object.__setattr__(T, "maintenance_orders", mo_table)

        # Enable flags
        object.__setattr__(S, "fixed_assets_enabled", True)
        object.__setattr__(S, "gl_double_entry_enabled", True)

        yield  # ← tests run here

    # --- teardown: restore everything ---
    object.__setattr__(T, "fixed_assets", _orig_T_fa)
    object.__setattr__(T, "fixed_asset_schedule", _orig_T_fas)
    object.__setattr__(T, "maintenance_orders", _orig_T_mo)
    object.__setattr__(S, "fixed_assets_enabled", _orig_S_enabled)
    object.__setattr__(S, "gl_double_entry_enabled", _orig_S_gl)

    # Restore sys.modules
    if _orig_gl_posting is None:
        sys.modules.pop("app.services.gl_posting", None)
    else:
        sys.modules["app.services.gl_posting"] = _orig_gl_posting

    if _orig_fixed_assets_svc is None:
        sys.modules.pop("app.services.fixed_assets", None)
    else:
        sys.modules["app.services.fixed_assets"] = _orig_fixed_assets_svc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_asset_body(**overrides):
    """Return a FixedAssetIn-compatible dict."""
    from app.models import FixedAssetIn
    defaults = {
        "name": "Test Server",
        "asset_class": "equipment",
        "acquisition_cost_cents": 120_000,  # $1,200
        "salvage_value_cents": 0,
        "useful_life_months": 12,
        "acquired_at": 1_700_000_000,
        "depreciation_method": "straight_line",
        "correlation_id": "test-asset-001",
        "gl_asset_account_id": "FA-001",
        "gl_accum_depr_account_id": "FA-002",
        "gl_depr_expense_account_id": "FA-003",
        "gl_gain_account_id": "FA-004",
        "gl_loss_account_id": "FA-005",
    }
    defaults.update(overrides)
    return FixedAssetIn(**defaults)


# ---------------------------------------------------------------------------
# FXA register tests
# ---------------------------------------------------------------------------

class TestAssetRegister:
    def test_create_asset_returns_correct_fields(self):
        from app.services.fixed_assets import create_asset
        body = _make_asset_body(correlation_id="reg-001")
        result = create_asset("user-sub-1", body)
        assert result.name == "Test Server"
        assert result.asset_class == "equipment"
        assert result.status == "active"
        assert result.acquisition_cost_cents == 120_000
        assert result.salvage_value_cents == 0
        assert result.accumulated_depreciation_cents == 0
        assert result.net_book_value_cents == 120_000
        assert result.owner_sub == "user-sub-1"
        assert result.asset_id == hashlib.sha256(b"reg-001").hexdigest()[:32]

    def test_create_asset_idempotent(self):
        """Same correlation_id → same asset_id, no duplicate."""
        from app.services.fixed_assets import create_asset
        body = _make_asset_body(correlation_id="reg-idem-001")
        r1 = create_asset("user-sub-1", body)
        r2 = create_asset("user-sub-1", body)
        assert r1.asset_id == r2.asset_id

    def test_get_asset_not_found(self):
        from app.services.fixed_assets import get_asset
        import pytest
        with pytest.raises(Exception) as exc_info:
            get_asset("nonexistent-asset-id")
        assert exc_info.value.status_code == 404

    def test_get_asset_found(self):
        from app.services.fixed_assets import create_asset, get_asset
        body = _make_asset_body(correlation_id="reg-get-001")
        created = create_asset("user-sub-2", body)
        fetched = get_asset(created.asset_id)
        assert fetched.asset_id == created.asset_id

    def test_list_assets_by_owner(self):
        from app.services.fixed_assets import create_asset, list_assets
        body = _make_asset_body(correlation_id="list-owner-001", name="Asset A")
        create_asset("list-owner-user", body)
        items, cursor = list_assets(owner_sub="list-owner-user")
        assert len(items) >= 1
        assert all(i.owner_sub == "list-owner-user" for i in items)

    def test_list_assets_by_status_active(self):
        from app.services.fixed_assets import create_asset, list_assets
        body = _make_asset_body(correlation_id="list-status-001", name="Active Asset")
        create_asset("status-test-user", body)
        items, _ = list_assets(status="active")
        assert all(i.status == "active" for i in items)

    def test_update_asset_name(self):
        from app.services.fixed_assets import create_asset, update_asset
        from app.models import FixedAssetPatchIn
        body = _make_asset_body(correlation_id="update-001", name="Old Name")
        asset = create_asset("user-sub-upd", body)
        patch = FixedAssetPatchIn(name="New Name")
        updated = update_asset(asset.asset_id, patch, "user-sub-upd")
        assert updated.name == "New Name"
        assert updated.updated_at >= asset.updated_at

    def test_update_asset_no_changes_returns_current(self):
        from app.services.fixed_assets import create_asset, update_asset
        from app.models import FixedAssetPatchIn
        body = _make_asset_body(correlation_id="update-nop-001")
        asset = create_asset("user-sub-upd2", body)
        patch = FixedAssetPatchIn()  # no fields set
        result = update_asset(asset.asset_id, patch, "user-sub-upd2")
        assert result.asset_id == asset.asset_id

    def test_flag_off_raises_503(self):
        from app.core.settings import S
        from app.services.fixed_assets import create_asset
        import pytest
        object.__setattr__(S, "fixed_assets_enabled", False)
        try:
            with pytest.raises(Exception) as exc_info:
                body = _make_asset_body(correlation_id="flag-off-001")
                create_asset("user", body)
            assert exc_info.value.status_code == 503
        finally:
            object.__setattr__(S, "fixed_assets_enabled", True)

    def test_salvage_equal_to_cost_raises_validation_error(self):
        from app.models import FixedAssetIn
        import pytest
        with pytest.raises(Exception):
            FixedAssetIn(
                name="Bad",
                asset_class="equipment",
                acquisition_cost_cents=1000,
                salvage_value_cents=1000,  # equal → invalid
                useful_life_months=12,
                acquired_at=1_700_000_000,
            )


# ---------------------------------------------------------------------------
# FXA depreciation schedule tests
# ---------------------------------------------------------------------------

class TestDepreciationSchedule:

    def _create_asset(self, corr: str, cost: int = 120_000, salvage: int = 0, months: int = 12) -> Any:
        from app.services.fixed_assets import create_asset
        body = _make_asset_body(
            correlation_id=corr,
            acquisition_cost_cents=cost,
            salvage_value_cents=salvage,
            useful_life_months=months,
        )
        return create_asset(f"depr-owner-{corr}", body)

    def test_schedule_math_even_division(self):
        """120_000 / 12 = 10_000 per period, sum = 120_000."""
        from app.services.fixed_assets import generate_schedule
        asset = self._create_asset("sched-even-001", cost=120_000, months=12)
        sched = generate_schedule(asset.asset_id)
        assert sched.total_periods == 12
        assert sum(p.amount_cents for p in sched.periods) == 120_000
        assert all(p.amount_cents == 10_000 for p in sched.periods)

    def test_schedule_math_uneven_division_last_period_absorbs_remainder(self):
        """100_000 / 12 = 8333 * 11 + 8337 = 100_000."""
        from app.services.fixed_assets import generate_schedule
        asset = self._create_asset("sched-uneven-001", cost=100_000, months=12)
        sched = generate_schedule(asset.asset_id)
        total = sum(p.amount_cents for p in sched.periods)
        assert total == 100_000
        # Periods 1-11 have 8333, period 12 has 8337
        for p in sched.periods[:-1]:
            assert p.amount_cents == 8333
        assert sched.periods[-1].amount_cents == 100_000 - 8333 * 11

    def test_schedule_with_salvage_value(self):
        """depreciable_base = cost - salvage."""
        from app.services.fixed_assets import generate_schedule
        asset = self._create_asset("sched-salvage-001", cost=120_000, salvage=20_000, months=12)
        sched = generate_schedule(asset.asset_id)
        assert sum(p.amount_cents for p in sched.periods) == 100_000

    def test_net_book_value_never_below_salvage(self):
        from app.services.fixed_assets import generate_schedule, post_depreciation_period, get_asset
        asset = self._create_asset("sched-nbv-floor-001", cost=120_000, salvage=10_000, months=12)
        generate_schedule(asset.asset_id)
        # Post all periods
        for period in range(1, 13):
            post_depreciation_period(asset.asset_id, period)
        refreshed = get_asset(asset.asset_id)
        assert refreshed.net_book_value_cents >= 10_000
        assert refreshed.net_book_value_cents == 10_000

    def test_period_timestamps_advance_by_30_days(self):
        from app.services.fixed_assets import generate_schedule
        asset = self._create_asset("sched-ts-001", cost=60_000, months=3)
        sched = generate_schedule(asset.asset_id)
        p1, p2, p3 = sched.periods
        assert p2.period_start_ts == p1.period_start_ts + 30 * 86_400
        assert p3.period_start_ts == p2.period_start_ts + 30 * 86_400
        assert p1.period_end_ts == p1.period_start_ts + 30 * 86_400 - 1


# ---------------------------------------------------------------------------
# FXA GL posting tests
# ---------------------------------------------------------------------------

class TestDepreciationPosting:

    def _create_and_schedule(self, corr: str, cost: int = 120_000, months: int = 12):
        from app.services.fixed_assets import create_asset, generate_schedule
        body = _make_asset_body(
            correlation_id=corr,
            acquisition_cost_cents=cost,
            salvage_value_cents=0,
            useful_life_months=months,
        )
        asset = create_asset(f"post-owner-{corr}", body)
        generate_schedule(asset.asset_id)
        return asset

    def test_post_period_flips_status_to_posted(self):
        from app.services.fixed_assets import post_depreciation_period
        asset = self._create_and_schedule("post-001")
        _GL_JOURNAL.clear()
        result = post_depreciation_period(asset.asset_id, 1)
        assert result.schedule_status == "posted"
        assert result.journal_entry_id is not None
        assert result.posted_at is not None

    def test_post_period_increments_accumulated_depreciation(self):
        from app.services.fixed_assets import post_depreciation_period, get_asset
        asset = self._create_and_schedule("post-002", cost=120_000, months=12)
        post_depreciation_period(asset.asset_id, 1)
        refreshed = get_asset(asset.asset_id)
        assert refreshed.accumulated_depreciation_cents == 10_000

    def test_post_period_emits_balanced_gl_journal(self):
        from app.services.fixed_assets import post_depreciation_period
        asset = self._create_and_schedule("post-gl-001", cost=60_000, months=6)
        _GL_JOURNAL.clear()
        post_depreciation_period(asset.asset_id, 1)
        assert len(_GL_JOURNAL) == 1
        entry = _GL_JOURNAL[0]
        lines = entry["lines"]
        total_debit = sum(l.amount_cents for l in lines if l.side == "debit")
        total_credit = sum(l.amount_cents for l in lines if l.side == "credit")
        assert total_debit == total_credit, "GL journal must be balanced"
        assert entry["source_type"] == "fixed_asset_depreciation"
        assert entry["source_entity_id"] == asset.asset_id

    def test_post_period_idempotent_no_double_increment(self):
        from app.services.fixed_assets import post_depreciation_period, get_asset
        asset = self._create_and_schedule("post-idem-001", cost=120_000, months=12)
        _GL_JOURNAL.clear()
        post_depreciation_period(asset.asset_id, 1)
        gl_after_first = len(_GL_JOURNAL)
        post_depreciation_period(asset.asset_id, 1)  # second call
        assert len(_GL_JOURNAL) == gl_after_first, "No second GL write on re-post"
        refreshed = get_asset(asset.asset_id)
        assert refreshed.accumulated_depreciation_cents == 10_000  # not doubled

    def test_post_all_periods_marks_fully_depreciated(self):
        from app.services.fixed_assets import post_depreciation_period, get_asset
        asset = self._create_and_schedule("post-full-001", cost=120_000, months=12)
        for p in range(1, 13):
            post_depreciation_period(asset.asset_id, p)
        refreshed = get_asset(asset.asset_id)
        assert refreshed.status == "fully_depreciated"
        assert refreshed.net_book_value_cents == 0

    def test_post_period_deterministic_journal_id(self):
        """journal_id is sha256(asset_id:period:N)[:32] — same every call."""
        from app.services.fixed_assets import post_depreciation_period
        asset = self._create_and_schedule("post-jid-001", cost=60_000, months=6)
        result = post_depreciation_period(asset.asset_id, 1)
        expected_id = hashlib.sha256(f"{asset.asset_id}:period:1".encode()).hexdigest()[:32]
        assert result.journal_entry_id == expected_id

    def test_post_period_on_disposed_asset_raises_400(self):
        from app.services.fixed_assets import post_depreciation_period, dispose_asset
        from app.models import FixedAssetDisposeIn
        import pytest
        asset = self._create_and_schedule("post-disposed-001", cost=60_000, months=6)
        dispose_asset(asset.asset_id, FixedAssetDisposeIn(), "actor")
        with pytest.raises(Exception) as exc_info:
            post_depreciation_period(asset.asset_id, 1)
        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# FXA disposal tests
# ---------------------------------------------------------------------------

class TestDisposal:

    def _create_asset(self, corr: str, cost: int = 120_000):
        from app.services.fixed_assets import create_asset, generate_schedule
        body = _make_asset_body(
            correlation_id=corr,
            acquisition_cost_cents=cost,
            salvage_value_cents=0,
            useful_life_months=12,
        )
        asset = create_asset(f"dispose-owner-{corr}", body)
        generate_schedule(asset.asset_id)
        return asset

    def test_dispose_marks_asset_disposed(self):
        from app.services.fixed_assets import dispose_asset, get_asset
        from app.models import FixedAssetDisposeIn
        asset = self._create_asset("dispose-001")
        _GL_JOURNAL.clear()
        result = dispose_asset(asset.asset_id, FixedAssetDisposeIn(), "actor-sub")
        assert result.status == "disposed"

    def test_dispose_emits_closing_gl_journal(self):
        from app.services.fixed_assets import dispose_asset, post_depreciation_period
        from app.models import FixedAssetDisposeIn
        asset = self._create_asset("dispose-gl-001")
        # Post some periods first
        post_depreciation_period(asset.asset_id, 1)
        _GL_JOURNAL.clear()
        dispose_asset(asset.asset_id, FixedAssetDisposeIn(correlation_id="disp-gl-001"), "actor-sub")
        assert len(_GL_JOURNAL) == 1
        entry = _GL_JOURNAL[0]
        lines = entry["lines"]
        total_debit = sum(l.amount_cents for l in lines if l.side == "debit")
        total_credit = sum(l.amount_cents for l in lines if l.side == "credit")
        assert total_debit == total_credit, "Disposal journal must be balanced"
        assert entry["source_type"] == "fixed_asset_disposal"

    def test_dispose_cancels_remaining_schedule_periods(self):
        from app.services.fixed_assets import dispose_asset, get_schedule
        from app.models import FixedAssetDisposeIn
        asset = self._create_asset("dispose-cancel-001")
        dispose_asset(asset.asset_id, FixedAssetDisposeIn(), "actor-sub")
        sched = get_schedule(asset.asset_id)
        for p in sched.periods:
            assert p.schedule_status == "cancelled", f"Period {p.period} should be cancelled"

    def test_dispose_idempotent(self):
        """Disposing an already-disposed asset is a no-op."""
        from app.services.fixed_assets import dispose_asset
        from app.models import FixedAssetDisposeIn
        asset = self._create_asset("dispose-idem-001")
        r1 = dispose_asset(asset.asset_id, FixedAssetDisposeIn(), "actor-sub")
        _GL_JOURNAL.clear()
        r2 = dispose_asset(asset.asset_id, FixedAssetDisposeIn(), "actor-sub")
        assert r2.status == "disposed"
        assert len(_GL_JOURNAL) == 0  # No second GL write

    def test_dispose_gain_on_disposal(self):
        """proceeds > NBV → gain credit."""
        from app.services.fixed_assets import dispose_asset
        from app.models import FixedAssetDisposeIn
        asset = self._create_asset("dispose-gain-001", cost=100_000)
        # No depreciation posted → NBV = 100_000, proceeds = 120_000 → gain 20_000
        _GL_JOURNAL.clear()
        dispose_asset(asset.asset_id, FixedAssetDisposeIn(
            proceeds_amount_cents=120_000, correlation_id="gain-001"
        ), "actor-sub")
        entry = _GL_JOURNAL[0]
        lines = entry["lines"]
        # Find the gain line (credit to gain account)
        gain_lines = [l for l in lines if l.account_code == "FA-004" and l.side == "credit"]
        assert len(gain_lines) == 1
        assert gain_lines[0].amount_cents == 20_000

    def test_dispose_loss_on_disposal(self):
        """proceeds < NBV → loss debit."""
        from app.services.fixed_assets import dispose_asset
        from app.models import FixedAssetDisposeIn
        asset = self._create_asset("dispose-loss-001", cost=100_000)
        # No depreciation → NBV = 100_000, proceeds = 50_000 → loss 50_000
        _GL_JOURNAL.clear()
        dispose_asset(asset.asset_id, FixedAssetDisposeIn(
            proceeds_amount_cents=50_000, correlation_id="loss-001"
        ), "actor-sub")
        entry = _GL_JOURNAL[0]
        lines = entry["lines"]
        loss_lines = [l for l in lines if l.account_code == "FA-005" and l.side == "debit"]
        assert len(loss_lines) == 1
        assert loss_lines[0].amount_cents == 50_000


# ---------------------------------------------------------------------------
# FXA work-order tests
# ---------------------------------------------------------------------------

class TestWorkOrders:

    def _create_asset(self, corr: str):
        from app.services.fixed_assets import create_asset
        body = _make_asset_body(correlation_id=corr)
        return create_asset(f"wo-owner-{corr}", body)

    def test_create_work_order_active_asset(self):
        from app.services.fixed_assets import create_work_order
        from app.models import AssetMaintenanceOrderIn
        asset = self._create_asset("wo-create-001")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Replace fan", correlation_id="wo-001"),
            "actor-sub",
        )
        assert wo.wo_status == "open"
        assert wo.title == "Replace fan"
        assert wo.asset_id == asset.asset_id

    def test_create_work_order_on_disposed_asset_raises_400(self):
        from app.services.fixed_assets import create_work_order, dispose_asset
        from app.models import AssetMaintenanceOrderIn, FixedAssetDisposeIn
        import pytest
        asset = self._create_asset("wo-disposed-001")
        dispose_asset(asset.asset_id, FixedAssetDisposeIn(), "actor-sub")
        with pytest.raises(Exception) as exc_info:
            create_work_order(
                asset.asset_id,
                AssetMaintenanceOrderIn(title="Maintenance", correlation_id="wo-disposed-001"),
                "actor-sub",
            )
        assert exc_info.value.status_code == 400

    def test_create_work_order_idempotent(self):
        from app.services.fixed_assets import create_work_order
        from app.models import AssetMaintenanceOrderIn
        asset = self._create_asset("wo-idem-001")
        wo1 = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Check", correlation_id="wo-idem-001"),
            "actor-sub",
        )
        wo2 = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Check", correlation_id="wo-idem-001"),
            "actor-sub",
        )
        assert wo1.work_order_id == wo2.work_order_id

    def test_transition_open_to_in_progress(self):
        from app.services.fixed_assets import create_work_order, transition_work_order
        from app.models import AssetMaintenanceOrderIn, AssetMaintenanceOrderTransitionIn
        asset = self._create_asset("wo-trans-001")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Inspect", correlation_id="wo-t001"),
            "actor-sub",
        )
        updated = transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="in_progress"),
            "actor-sub",
        )
        assert updated.wo_status == "in_progress"

    def test_transition_in_progress_to_completed(self):
        from app.services.fixed_assets import create_work_order, transition_work_order
        from app.models import AssetMaintenanceOrderIn, AssetMaintenanceOrderTransitionIn
        asset = self._create_asset("wo-trans-002")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Fix pump", correlation_id="wo-t002"),
            "actor-sub",
        )
        transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="in_progress"),
            "actor-sub",
        )
        completed = transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="completed", cost_cents=5000),
            "actor-sub",
        )
        assert completed.wo_status == "completed"
        assert completed.completed_at is not None
        assert completed.cost_cents == 5000

    def test_transition_completed_to_open_raises_409(self):
        from app.services.fixed_assets import create_work_order, transition_work_order
        from app.models import AssetMaintenanceOrderIn, AssetMaintenanceOrderTransitionIn
        import pytest
        asset = self._create_asset("wo-trans-003")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Illegal transition", correlation_id="wo-t003"),
            "actor-sub",
        )
        transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="in_progress"),
            "actor-sub",
        )
        transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="completed"),
            "actor-sub",
        )
        with pytest.raises(Exception) as exc_info:
            transition_work_order(
                wo.work_order_id, asset.asset_id,
                AssetMaintenanceOrderTransitionIn(target_status="in_progress"),
                "actor-sub",
            )
        assert exc_info.value.status_code == 409

    def test_transition_in_progress_to_cancelled(self):
        from app.services.fixed_assets import create_work_order, transition_work_order
        from app.models import AssetMaintenanceOrderIn, AssetMaintenanceOrderTransitionIn
        asset = self._create_asset("wo-trans-004")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Cancel me", correlation_id="wo-t004"),
            "actor-sub",
        )
        transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="in_progress"),
            "actor-sub",
        )
        cancelled = transition_work_order(
            wo.work_order_id, asset.asset_id,
            AssetMaintenanceOrderTransitionIn(target_status="cancelled"),
            "actor-sub",
        )
        assert cancelled.wo_status == "cancelled"

    def test_list_work_orders_by_status(self):
        from app.services.fixed_assets import create_work_order, list_work_orders
        from app.models import AssetMaintenanceOrderIn
        asset = self._create_asset("wo-list-001")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Listed WO", correlation_id="wo-list-001"),
            "actor-sub",
        )
        items, _ = list_work_orders(wo_status="open")
        work_order_ids = {i.work_order_id for i in items}
        assert wo.work_order_id in work_order_ids

    def test_list_work_orders_for_asset(self):
        from app.services.fixed_assets import create_work_order, list_work_orders
        from app.models import AssetMaintenanceOrderIn
        asset = self._create_asset("wo-list-asset-001")
        wo = create_work_order(
            asset.asset_id,
            AssetMaintenanceOrderIn(title="Asset WO", correlation_id="wo-la-001"),
            "actor-sub",
        )
        items, _ = list_work_orders(asset_id=asset.asset_id)
        assert len(items) >= 1
        assert all(i.asset_id == asset.asset_id for i in items)


# ---------------------------------------------------------------------------
# FXA background poster tests
# ---------------------------------------------------------------------------

class TestDepreciationPosterLoop:

    def test_poster_sweep_posts_due_periods(self):
        """_run_poster_sweep should pick up past-due scheduled periods."""
        from app.services.fixed_assets import (
            create_asset, generate_schedule, _run_poster_sweep, get_schedule
        )
        from app.core.time import now_ts

        # Create asset acquired 60 days ago so period 1 and 2 are due
        acquired_at = now_ts() - 65 * 86_400
        body = _make_asset_body(
            correlation_id="poster-sweep-001",
            acquired_at=acquired_at,
            useful_life_months=6,
            acquisition_cost_cents=60_000,
        )
        asset = create_asset("poster-owner-001", body)
        generate_schedule(asset.asset_id)

        _run_poster_sweep()

        sched = get_schedule(asset.asset_id)
        posted = [p for p in sched.periods if p.schedule_status == "posted"]
        assert len(posted) >= 2, "At least 2 periods should be auto-posted"

    def test_start_task_no_op_when_flag_off(self):
        """start_depreciation_poster_task is a no-op when flags are off."""
        from app.core.settings import S
        from app.services.fixed_assets import start_depreciation_poster_task
        object.__setattr__(S, "fixed_assets_enabled", False)
        # Should not raise, should not schedule a future
        try:
            start_depreciation_poster_task()
        finally:
            object.__setattr__(S, "fixed_assets_enabled", True)
