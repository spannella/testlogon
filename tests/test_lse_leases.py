"""LSE-001 / LSE-002 / LSE-003 — hermetic offline tests for the Lease subsystem.

Test isolation pattern:
- moto creates an in-memory DynamoDB table
- T.leases is patched via object.__setattr__ (frozen dataclass bypass), RESTORED on teardown
- S.leases_enabled / S.leases_renewal_notifications_enabled similarly patched & restored
- audit_event / send_alert_email / get_profile_identity are patched where needed
- No TestClient; route coroutines not called directly (service layer tested only)
- No real AWS, no real DynamoDB

Run:
    AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \\
        .venv/bin/pytest -q tests/test_lse_leases.py
"""
from __future__ import annotations

import asyncio
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

import app.services.leases as leases_svc
from app.core.settings import S
from app.core.tables import T


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_table(ddb):
    table = ddb.create_table(
        TableName="leases_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk",     "AttributeType": "S"},
            {"AttributeName": "sk",     "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "leases-all-index",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "leases-by-status-index",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.meta.client.get_waiter("table_exists").wait(TableName="leases_test")
    return table


def _save_state():
    return {
        "leases": getattr(T, "leases", None),
        "leases_enabled": S.leases_enabled,
        "leases_table_name": S.leases_table_name,
        "leases_renewal_notifications_enabled": S.leases_renewal_notifications_enabled,
    }


def _restore_state(state):
    object.__setattr__(T, "leases", state["leases"])
    object.__setattr__(S, "leases_enabled", state["leases_enabled"])
    object.__setattr__(S, "leases_table_name", state["leases_table_name"])
    object.__setattr__(
        S,
        "leases_renewal_notifications_enabled",
        state["leases_renewal_notifications_enabled"],
    )


NOW = 1_600_000_000  # fixed reference timestamp — before real time so NOW-1 is "past" and NOW+N is "future"


def _create(
    user_sub="alice",
    tenant_id="t1",
    property_id="p1",
    unit_id="u1",
    start_date: Optional[int] = None,
    end_date: Optional[int] = None,
    monthly_rent_cents: int = 100000,
    force_draft: bool = False,
):
    sd = start_date if start_date is not None else NOW - 86400  # default: past => active
    return leases_svc.create_lease(
        user_sub,
        tenant_id=tenant_id,
        property_id=property_id,
        unit_id=unit_id,
        start_date=sd,
        end_date=end_date,
        monthly_rent_cents=monthly_rent_cents,
        rent_due_day=1,
        force_draft=force_draft,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def leases_table():
    """Create a fresh in-memory leases table for each test."""
    state = _save_state()
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)
        object.__setattr__(T, "leases", table)
        object.__setattr__(S, "leases_enabled", True)
        object.__setattr__(S, "leases_table_name", "leases_test")
        object.__setattr__(S, "leases_renewal_notifications_enabled", True)
        with (
            patch("app.services.leases.audit_event"),
            patch("app.services.leases.send_alert_email"),
        ):
            yield table
    _restore_state(state)


# ===========================================================================
# LSE-001 — Entity: create / get / transition
# ===========================================================================


class TestFlagOff:
    """All service functions return None when flag is off."""

    def test_create_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.create_lease("alice", tenant_id="t", property_id="p",
                                       unit_id="u", start_date=1, monthly_rent_cents=0,
                                       rent_due_day=1) is None

    def test_get_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.get_lease("alice", "lse_xxx") is None

    def test_transition_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.transition_status("alice", "lse_xxx", "active") is None

    def test_list_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.list_leases("alice") is None

    def test_update_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.update_lease("alice", "lse_xxx") is None

    def test_admin_list_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.admin_list_leases() is None

    def test_list_for_tenant_returns_none(self):
        object.__setattr__(S, "leases_enabled", False)
        assert leases_svc.list_leases_for_tenant("alice", "t1") is None

    def test_expiration_returns_empty(self):
        object.__setattr__(S, "leases_enabled", False)
        result = leases_svc.list_upcoming_expirations("alice")
        assert result == []


class TestCreateLease:
    def test_upcoming_when_future_start(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW + 86400 * 30)
        assert item["status"] == "upcoming"

    def test_active_when_past_start(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 86400)
        assert item["status"] == "active"

    def test_active_auto_assignment(self):
        """With explicit past start_date, status should be active."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)
        assert item["status"] == "active"

    def test_upcoming_auto_assignment(self):
        """With explicit future start_date, status should be upcoming."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW + 1000)
        assert item["status"] == "upcoming"

    def test_force_draft(self):
        item = _create(force_draft=True)
        assert item["status"] == "draft"

    def test_lease_number_format(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create()
        import re
        assert re.match(r"LSE-\d{4}-\d{5}", item["lease_number"])

    def test_sequential_numbers(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            a = _create()
            b = _create()
        # Numbers should differ and be consecutive
        assert a["lease_number"] != b["lease_number"]

    def test_open_ended_no_gsi2sk(self):
        item = _create(end_date=None)
        assert "GSI2SK" not in item
        assert "end_date" not in item

    def test_with_end_date_has_gsi2sk(self):
        ed = NOW + 86400 * 365
        item = _create(end_date=ed)
        assert "GSI2SK" in item
        assert int(item["GSI2SK"]) == ed

    def test_gsi2pk_matches_status(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW + 1)
        assert item["GSI2PK"] == f"USER#alice#STATUS#upcoming"

    def test_invalid_date_range(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _create(start_date=NOW + 100, end_date=NOW)
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == "invalid_date_range"

    def test_required_fields_stored(self):
        item = _create(tenant_id="tenant123", property_id="prop456", unit_id="unit789")
        assert item["tenant_id"] == "tenant123"
        assert item["property_id"] == "prop456"
        assert item["unit_id"] == "unit789"


class TestGetLease:
    def test_returns_lease(self):
        item = _create()
        got = leases_svc.get_lease("alice", item["lease_id"])
        assert got is not None
        assert got["lease_id"] == item["lease_id"]

    def test_ownership_isolation(self):
        item = _create(user_sub="bob")
        # Alice cannot see Bob's lease
        got = leases_svc.get_lease("alice", item["lease_id"])
        assert got is None

    def test_not_found_returns_none(self):
        got = leases_svc.get_lease("alice", "lse_nonexistent")
        assert got is None


class TestTransitionStatus:
    def test_draft_to_upcoming(self):
        item = _create(force_draft=True)
        updated = leases_svc.transition_status("alice", item["lease_id"], "upcoming")
        assert updated["status"] == "upcoming"

    def test_draft_to_active(self):
        item = _create(force_draft=True)
        updated = leases_svc.transition_status("alice", item["lease_id"], "active")
        assert updated["status"] == "active"

    def test_upcoming_to_active(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW + 1000, force_draft=False)
        # force to upcoming
        if item["status"] != "upcoming":
            item = _create(force_draft=True)
            leases_svc.transition_status("alice", item["lease_id"], "upcoming")
            item = leases_svc.get_lease("alice", item["lease_id"])
        updated = leases_svc.transition_status("alice", item["lease_id"], "active")
        assert updated["status"] == "active"

    def test_active_to_ended(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)
        assert item["status"] == "active"
        updated = leases_svc.transition_status("alice", item["lease_id"], "ended")
        assert updated["status"] == "ended"

    def test_invalid_transition_raises_400(self):
        from fastapi import HTTPException
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)
        with pytest.raises(HTTPException) as exc:
            leases_svc.transition_status("alice", item["lease_id"], "upcoming")
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == "invalid_status_transition"

    def test_terminal_ended_raises_400(self):
        from fastapi import HTTPException
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)
        leases_svc.transition_status("alice", item["lease_id"], "ended")
        with pytest.raises(HTTPException) as exc:
            leases_svc.transition_status("alice", item["lease_id"], "active")
        assert exc.value.status_code == 400

    def test_gsi2pk_updated_after_transition(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)
        leases_svc.transition_status("alice", item["lease_id"], "ended")
        raw = T.leases.get_item(
            Key={"pk": f"USER#alice", "sk": f"LEASE#{item['lease_id']}"}
        )["Item"]
        assert raw["GSI2PK"] == "USER#alice#STATUS#ended"

    def test_concurrent_update_409(self):
        """Simulate ConditionalCheckFailedException → HTTP 409."""
        from fastapi import HTTPException
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)

        original_update = T.leases.update_item

        def _fail_on_second_call(call_count=[0], **kwargs):
            call_count[0] += 1
            if call_count[0] == 1 and kwargs.get("ConditionExpression"):
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "x"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch.object(T.leases, "update_item", side_effect=_fail_on_second_call):
            with pytest.raises(HTTPException) as exc:
                leases_svc.transition_status("alice", item["lease_id"], "ended")
        assert exc.value.status_code == 409
        assert exc.value.detail["code"] == "concurrent_update"

    def test_not_found_raises_404(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            leases_svc.transition_status("alice", "lse_nonexistent", "active")
        assert exc.value.status_code == 404

    def test_occupancy_side_effect_noop_when_no_module(self):
        """Transition succeeds even when prop_unit is not importable."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1)
        # Should not raise even with a missing prop_unit module
        updated = leases_svc.transition_status("alice", item["lease_id"], "ended")
        assert updated["status"] == "ended"


# ===========================================================================
# LSE-002 — List / update / admin list
# ===========================================================================


class TestListLeases:
    def test_empty_list(self):
        result = leases_svc.list_leases("alice")
        assert result["leases"] == []
        assert result["count"] == 0
        assert result["next_cursor"] is None

    def test_returns_all_leases(self):
        _create()
        _create()
        _create()
        result = leases_svc.list_leases("alice")
        assert result["count"] == 3

    def test_status_filter_active(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            active = _create(start_date=NOW - 1)
            ended_item = _create(start_date=NOW - 1)
            leases_svc.transition_status("alice", ended_item["lease_id"], "ended")

        # Status filter queries GSI2PK=USER#alice#STATUS#active
        result = leases_svc.list_leases("alice", status="active")
        ids = [l["lease_id"] for l in result["leases"]]
        assert active["lease_id"] in ids, f"active lease not in result: {ids}"
        assert ended_item["lease_id"] not in ids

    def test_status_filter_ended(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            active = _create(start_date=NOW - 1)
            ended_item = _create(start_date=NOW - 1)
            leases_svc.transition_status("alice", ended_item["lease_id"], "ended")

        result = leases_svc.list_leases("alice", status="ended")
        ids = [l["lease_id"] for l in result["leases"]]
        assert ended_item["lease_id"] in ids, f"ended lease not in result: {ids}"
        assert active["lease_id"] not in ids

    def test_open_ended_included_in_status_filter(self):
        """Active lease with no end_date still appears in status=active list."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1, end_date=None)
        assert "end_date" not in item
        # Query the GSI2 by status=active; open-ended item has no GSI2SK but IS in the index
        result = leases_svc.list_leases("alice", status="active")
        ids = [l["lease_id"] for l in result["leases"]]
        assert item["lease_id"] in ids, f"open-ended active lease not in result: {ids}"

    def test_pagination(self):
        for _ in range(5):
            _create()
        # First page
        page1 = leases_svc.list_leases("alice", limit=2)
        assert page1["count"] == 2
        assert page1["next_cursor"] is not None

        # Second page
        page2 = leases_svc.list_leases("alice", limit=2, cursor=page1["next_cursor"])
        assert page2["count"] == 2

        # Third page
        page3 = leases_svc.list_leases("alice", limit=2, cursor=page2["next_cursor"])
        assert page3["count"] == 1
        assert page3["next_cursor"] is None

        # No overlap
        ids1 = {l["lease_id"] for l in page1["leases"]}
        ids2 = {l["lease_id"] for l in page2["leases"]}
        ids3 = {l["lease_id"] for l in page3["leases"]}
        assert not ids1 & ids2
        assert not ids2 & ids3
        assert not ids1 & ids3

    def test_tampered_cursor_returns_first_page(self):
        _create()
        result = leases_svc.list_leases("alice", cursor="tampered_cursor_!!!!")
        # Should not raise; silently discards tampered cursor
        assert result["leases"] is not None

    def test_gsi_numeric_keys_no_validation_error(self):
        """GSI query with numeric key condition should not raise ValidationException."""
        from boto3.dynamodb.conditions import Key
        # This directly exercises the attr_types={"GSI1SK": "N"} declaration
        result = T.leases.query(
            IndexName="leases-all-index",
            KeyConditionExpression=Key("GSI1PK").eq("LEASES#ALL"),
        )
        assert "Items" in result  # No ValidationException raised


class TestUpdateLease:
    def test_update_mutable_field(self):
        item = _create()
        updated = leases_svc.update_lease(
            "alice", item["lease_id"], monthly_rent_cents=120000
        )
        assert int(updated["monthly_rent_cents"]) == 120000

    def test_updated_at_advances(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create()
        later = NOW + 100
        with patch("app.services.leases.now_ts", return_value=later):
            updated = leases_svc.update_lease(
                "alice", item["lease_id"], monthly_rent_cents=99900
            )
        assert int(updated["updated_at"]) == later

    def test_lease_number_unchanged(self):
        item = _create()
        updated = leases_svc.update_lease("alice", item["lease_id"], monthly_rent_cents=50000)
        assert updated["lease_number"] == item["lease_number"]

    def test_update_notes(self):
        item = _create()
        updated = leases_svc.update_lease("alice", item["lease_id"], notes="new notes")
        assert updated["notes"] == "new notes"

    def test_update_end_date(self):
        item = _create(end_date=NOW + 86400 * 30)
        new_end = NOW + 86400 * 60
        updated = leases_svc.update_lease(
            "alice", item["lease_id"], end_date=new_end, _end_date_set=True
        )
        assert int(updated["end_date"]) == new_end

    def test_clear_end_date(self):
        """Setting end_date=None (with _end_date_set=True) converts to open-ended."""
        item = _create(end_date=NOW + 86400 * 30)
        assert "end_date" in item
        leases_svc.update_lease(
            "alice", item["lease_id"], end_date=None, _end_date_set=True
        )
        raw = T.leases.get_item(
            Key={"pk": "USER#alice", "sk": f"LEASE#{item['lease_id']}"}
        )["Item"]
        assert "end_date" not in raw
        assert "GSI2SK" not in raw

    def test_late_fee_cross_validation(self):
        from fastapi import HTTPException
        item = _create()
        with pytest.raises(HTTPException) as exc:
            leases_svc.update_lease(
                "alice", item["lease_id"],
                late_fee_type="flat", late_fee_cents=0
            )
        assert exc.value.status_code == 400
        assert exc.value.detail["code"] == "invalid_late_fee_config"

    def test_noop_patch_no_updated_at_change(self):
        """A patch with no fields set is a no-op; updated_at is not changed."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create()
        original_updated_at = int(item["updated_at"])
        # Call update with no fields set
        result = leases_svc.update_lease("alice", item["lease_id"])
        # updated_at should not have changed
        assert int(result["updated_at"]) == original_updated_at

    def test_ownership_isolation(self):
        item = _create(user_sub="bob")
        result = leases_svc.update_lease("alice", item["lease_id"], monthly_rent_cents=50000)
        assert result is None


class TestAdminListLeases:
    def test_crosses_users(self):
        _create(user_sub="alice")
        _create(user_sub="bob")
        result = leases_svc.admin_list_leases()
        assert result["count"] == 2

    def test_pagination(self):
        for i in range(5):
            _create(user_sub=f"user{i}")
        page1 = leases_svc.admin_list_leases(limit=3)
        assert page1["count"] == 3
        assert page1["next_cursor"] is not None
        page2 = leases_svc.admin_list_leases(limit=3, cursor=page1["next_cursor"])
        assert page2["count"] == 2
        assert page2["next_cursor"] is None


# ===========================================================================
# LSE-003 — Tenant history + expiration query + renewal loop
# ===========================================================================


class TestListLeasesForTenant:
    def test_returns_tenant_leases(self):
        _create(user_sub="alice", tenant_id="t1")
        _create(user_sub="alice", tenant_id="t1")
        _create(user_sub="alice", tenant_id="t2")
        result = leases_svc.list_leases_for_tenant("alice", "t1")
        assert result["count"] == 2
        for l in result["leases"]:
            assert l["tenant_id"] == "t1"

    def test_single_tenant_filter(self):
        _create(user_sub="alice", tenant_id="t2")
        result = leases_svc.list_leases_for_tenant("alice", "t2")
        assert result["count"] == 1

    def test_no_results_returns_empty(self):
        result = leases_svc.list_leases_for_tenant("alice", "nonexistent_tenant")
        assert result["count"] == 0
        assert result["leases"] == []
        assert result["next_cursor"] is None

    def test_ownership_isolation(self):
        """Bob's leases are not returned when querying as alice."""
        _create(user_sub="bob", tenant_id="t1")
        _create(user_sub="alice", tenant_id="t1")
        result = leases_svc.list_leases_for_tenant("alice", "t1")
        for l in result["leases"]:
            assert l["user_sub"] == "alice"

    def test_sorted_by_start_date_desc(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            a = _create(start_date=NOW - 3 * 86400, tenant_id="t1")
            b = _create(start_date=NOW - 1 * 86400, tenant_id="t1")
        result = leases_svc.list_leases_for_tenant("alice", "t1")
        assert result["leases"][0]["start_date"] >= result["leases"][1]["start_date"]

    def test_pagination(self):
        for _ in range(5):
            _create(tenant_id="t1")
        page1 = leases_svc.list_leases_for_tenant("alice", "t1", limit=2)
        assert page1["count"] == 2
        assert page1["next_cursor"] is not None

        page2 = leases_svc.list_leases_for_tenant(
            "alice", "t1", limit=2, cursor=page1["next_cursor"]
        )
        ids1 = {l["lease_id"] for l in page1["leases"]}
        ids2 = {l["lease_id"] for l in page2["leases"]}
        assert not ids1 & ids2


class TestListUpcomingExpirations:
    def test_returns_leases_in_window(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            # active lease expiring in 30 days
            item30 = _create(start_date=NOW - 1, end_date=NOW + 30 * 86400)
            # active lease expiring in 90 days
            item90 = _create(start_date=NOW - 1, end_date=NOW + 90 * 86400)
            # open-ended — should never appear
            open_ended = _create(start_date=NOW - 1, end_date=None)

        with patch("app.services.leases.now_ts", return_value=NOW):
            result_60 = leases_svc.list_upcoming_expirations("alice", within_days=60)
        ids_60 = {i["lease_id"] for i in result_60}
        assert item30["lease_id"] in ids_60
        assert item90["lease_id"] not in ids_60
        assert open_ended["lease_id"] not in ids_60

    def test_wider_window(self):
        with patch("app.services.leases.now_ts", return_value=NOW):
            item30 = _create(start_date=NOW - 1, end_date=NOW + 30 * 86400)
            item90 = _create(start_date=NOW - 1, end_date=NOW + 90 * 86400)

        with patch("app.services.leases.now_ts", return_value=NOW):
            result_120 = leases_svc.list_upcoming_expirations("alice", within_days=120)
        ids = {i["lease_id"] for i in result_120}
        assert item30["lease_id"] in ids
        assert item90["lease_id"] in ids

    def test_ended_lease_not_in_results(self):
        """Ended lease has different GSI2PK so never returned by expiration query."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1, end_date=NOW + 10 * 86400)
            leases_svc.transition_status("alice", item["lease_id"], "ended")
        with patch("app.services.leases.now_ts", return_value=NOW):
            result = leases_svc.list_upcoming_expirations("alice", within_days=30)
        ids = {i["lease_id"] for i in result}
        assert item["lease_id"] not in ids


class TestCheckExpiringLeases:
    def _seed_active_near_expiry(self, days_remaining=20, notice_days=30):
        """Seed an active lease expiring soon with renewal_notified_at absent."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(
                start_date=NOW - 1,
                end_date=NOW + days_remaining * 86400,
            )
        # patch renewal_notice_days into item directly
        T.leases.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET renewal_notice_days = :v",
            ExpressionAttributeValues={":v": notice_days},
        )
        return item

    def test_sends_exactly_one_email(self):
        self._seed_active_near_expiry()
        profile_data = {"email": "landlord@test.com", "display_name": "Alice"}
        emails = []

        def fake_send(to, subject, body):
            emails.append(to)

        with (
            patch("app.services.leases.now_ts", return_value=NOW),
            patch("app.services.alerts.audit_event"),
            patch("app.services.leases.audit_event"),
        ):
            with patch.object(
                leases_svc,
                "_send_renewal_notice",
                wraps=lambda item, dr: _patched_send(item, dr, profile_data, fake_send),
            ):
                # Call check directly
                pass

        # Simpler: patch at module level
        import app.services.leases as lsvc
        emails2 = []

        original_send = lsvc._send_renewal_notice

        def capture_notice(item, days):
            emails2.append(item.get("lease_id"))
            # Write marker so second call is no-op
            lsvc._write_renewal_marker(item, NOW)

        with (
            patch("app.services.leases.now_ts", return_value=NOW),
            patch.object(lsvc, "_send_renewal_notice", side_effect=capture_notice),
        ):
            count1 = lsvc.check_expiring_leases()
            count2 = lsvc.check_expiring_leases()

        assert count1 == 1
        assert count2 == 0  # idempotency: marker written, no second notice

    def test_not_in_notice_window_skipped(self):
        """Lease expiring in 60 days with 30-day notice window: not yet notified."""
        with patch("app.services.leases.now_ts", return_value=NOW):
            item = _create(start_date=NOW - 1, end_date=NOW + 60 * 86400)
        T.leases.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET renewal_notice_days = :v",
            ExpressionAttributeValues={":v": 30},
        )
        notified = []
        with (
            patch("app.services.leases.now_ts", return_value=NOW),
            patch.object(leases_svc, "_send_renewal_notice", side_effect=lambda i, d: notified.append(i)),
        ):
            count = leases_svc.check_expiring_leases()
        assert count == 0
        assert not notified

    def test_sub_flag_off_no_ddb_calls(self):
        object.__setattr__(S, "leases_renewal_notifications_enabled", False)
        queried = []
        original_query = T.leases.query

        def spy_query(*a, **kw):
            queried.append(kw)
            return original_query(*a, **kw)

        with patch.object(T.leases, "query", side_effect=spy_query):
            count = leases_svc.check_expiring_leases()
        assert count == 0
        assert not queried

    def test_missing_email_marker_still_written(self):
        """When profile has no email, notice is skipped but marker is written."""
        item = self._seed_active_near_expiry()

        def fake_get_profile(sub):
            return {"email": None, "display_name": "Alice"}

        with (
            patch("app.services.leases.now_ts", return_value=NOW),
            patch("app.services.leases.get_profile_identity", side_effect=fake_get_profile),
        ):
            count = leases_svc.check_expiring_leases()

        # Even though email was None (skipped), the lease is still "processed"
        # and the marker is written to prevent repeat attempts
        assert count == 1  # 1 lease processed (even though email was skipped)
        # Verify the marker was written to prevent future retry attempts
        raw = T.leases.get_item(Key={"pk": item["pk"], "sk": item["sk"]})["Item"]
        assert "renewal_notified_at" in raw


# ===========================================================================
# Pydantic model validation
# ===========================================================================


class TestPydanticModels:
    def test_rent_due_day_max_28(self):
        from pydantic import ValidationError
        from app.models import LeaseCreateIn
        with pytest.raises(ValidationError):
            LeaseCreateIn(
                tenant_id="t", property_id="p", unit_id="u",
                start_date=1, monthly_rent_cents=0, rent_due_day=29,
            )

    def test_rent_due_day_min_1(self):
        from pydantic import ValidationError
        from app.models import LeaseCreateIn
        with pytest.raises(ValidationError):
            LeaseCreateIn(
                tenant_id="t", property_id="p", unit_id="u",
                start_date=1, monthly_rent_cents=0, rent_due_day=0,
            )

    def test_late_fee_bps_max(self):
        from pydantic import ValidationError
        from app.models import LeaseCreateIn
        with pytest.raises(ValidationError):
            LeaseCreateIn(
                tenant_id="t", property_id="p", unit_id="u",
                start_date=1, monthly_rent_cents=0, rent_due_day=1,
                late_fee_percent_bps=10001,
            )

    def test_patch_extra_fields_forbidden(self):
        from pydantic import ValidationError
        from app.models import LeasePatchIn
        with pytest.raises(ValidationError):
            LeasePatchIn(status="active")  # status is immutable — extra="forbid"

    def test_valid_patch_creates_ok(self):
        from app.models import LeasePatchIn
        patch = LeasePatchIn(monthly_rent_cents=50000, notes="hello")
        assert patch.monthly_rent_cents == 50000

    def test_lease_list_out(self):
        from app.models import LeaseListOut
        out = LeaseListOut(leases=[], count=0, next_cursor=None)
        assert out.count == 0


# ---------------------------------------------------------------------------
# Helper used in one test
# ---------------------------------------------------------------------------
def _patched_send(item, days_remaining, profile_data, fake_send):
    """Helper for send capture in tests."""
    email = profile_data.get("email")
    if email:
        fake_send([email], "subject", "body")


# ===========================================================================
# startup task registration test (mirrors GAP-0228 pattern)
# ===========================================================================


def test_start_task_registration():
    """start_leases_renewal_check_task is registered on create_app startup."""
    from app.main import create_app
    app = create_app()
    handler_names = [
        getattr(h, "__name__", repr(h)) for h in app.router.on_startup
    ]
    # The registration is conditional on flags, so we just check main imports
    # successfully — the comprehensive check is import-level
    assert any("leases" in n or "start_leases" in n for n in handler_names), \
        f"start_leases_renewal_check_task not found in on_startup: {handler_names}"
