"""
WOV-002 hermetic pytest — work-order lifecycle (assign/schedule/transition/list).

Isolation: scope="module" autouse fixture saves/restores T.maintenance_orders
           and S.maintenance_orders_enabled.  moto in-memory DynamoDB.
No TestClient, no real AWS.
"""
from __future__ import annotations

import sys
import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Table factory helper
# ---------------------------------------------------------------------------

def _make_wo_table(ddb):
    table = ddb.create_table(
        TableName="maintenance_orders_wov002",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "wo_status", "AttributeType": "S"},
            {"AttributeName": "assignee_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_WO_STATUS",
                "KeySchema": [
                    {"AttributeName": "wo_status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
            {
                "IndexName": "GSI_WO_ASSIGNEE",
                "KeySchema": [
                    {"AttributeName": "assignee_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.meta.client.get_waiter("table_exists").wait(TableName="maintenance_orders_wov002")
    return table


# ---------------------------------------------------------------------------
# Module-level isolation fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _module_isolation():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_wo_table(ddb)

        import app.core.tables as tables_mod
        import app.services.maintenance_orders as svc
        from app.core.settings import S

        orig_t = tables_mod.T.maintenance_orders
        orig_flag = S.maintenance_orders_enabled
        orig_escrow = S.maintenance_orders_escrow_enabled

        object.__setattr__(tables_mod.T, "maintenance_orders", table)
        object.__setattr__(S, "maintenance_orders_enabled", True)
        object.__setattr__(S, "maintenance_orders_escrow_enabled", False)

        with patch("app.services.alerts.audit_event", MagicMock()):
            yield table

        object.__setattr__(tables_mod.T, "maintenance_orders", orig_t)
        object.__setattr__(S, "maintenance_orders_enabled", orig_flag)
        object.__setattr__(S, "maintenance_orders_escrow_enabled", orig_escrow)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _svc():
    import app.services.maintenance_orders as m
    return m


def _make_body(**kwargs):
    from app.models import MaintenanceOrderIn
    defaults = {"title": "Test WO", "property_id": "prop-002"}
    defaults.update(kwargs)
    return MaintenanceOrderIn(**defaults)


def _create_wo(prop="prop-002", title="Test WO", **kwargs):
    svc = _svc()
    body = _make_body(property_id=prop, title=title, **kwargs)
    return svc.create_work_order(prop, body, "admin-1")


# ---------------------------------------------------------------------------
# Group A: assign happy path
# ---------------------------------------------------------------------------

def test_assign_happy_path():
    from app.models import MaintenanceOrderAssignIn
    wo = _create_wo(title="Assign test")
    svc = _svc()
    body = MaintenanceOrderAssignIn(property_id="prop-002", assignee_sub="staff-1")
    out = svc.assign_work_order("prop-002", wo.work_order_id, body, "admin-1")
    assert out.wo_status == "assigned"
    assert out.assignee_sub == "staff-1"
    assert out.updated_at >= wo.updated_at


# ---------------------------------------------------------------------------
# Group B: assign with vendor guard (WOV-004 absent)
# ---------------------------------------------------------------------------

def test_assign_vendor_wov004_absent():
    """When WOV-004 ImportError is raised, assignment with vendor_id succeeds silently."""
    from app.models import MaintenanceOrderAssignIn
    import app.services.maintenance_orders as svc_mod

    wo = _create_wo(title="Vendor absent test")

    # Patch sys.modules to simulate ImportError on maintenance_vendors import
    saved = sys.modules.get("app.services.maintenance_vendors")
    sys.modules["app.services.maintenance_vendors"] = None  # type: ignore[assignment]
    try:
        body = MaintenanceOrderAssignIn(property_id="prop-002", vendor_id="v-fake-1")
        out = svc_mod.assign_work_order("prop-002", wo.work_order_id, body, "admin-1")
        assert out.wo_status == "assigned"
    finally:
        if saved is None:
            sys.modules.pop("app.services.maintenance_vendors", None)
        else:
            sys.modules["app.services.maintenance_vendors"] = saved


# ---------------------------------------------------------------------------
# Group C: assign to inactive vendor
# ---------------------------------------------------------------------------

def test_assign_inactive_vendor():
    from app.models import MaintenanceOrderAssignIn
    wo = _create_wo(title="Inactive vendor test")
    mock_vendor = SimpleNamespace(status="inactive", vendor_id="v-inactive")
    mock_mod = MagicMock()
    mock_mod.get_vendor = MagicMock(return_value=mock_vendor)
    with patch.dict(sys.modules, {"app.services.maintenance_vendors": mock_mod}):
        svc = _svc()
        body = MaintenanceOrderAssignIn(property_id="prop-002", vendor_id="v-inactive")
        with pytest.raises(HTTPException) as exc:
            svc.assign_work_order("prop-002", wo.work_order_id, body, "admin-1")
        assert exc.value.status_code == 422
        assert "vendor_inactive" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Group D: assign requires target
# ---------------------------------------------------------------------------

def test_assign_requires_target():
    from app.models import MaintenanceOrderAssignIn
    wo = _create_wo(title="Requires target test")
    svc = _svc()
    body = MaintenanceOrderAssignIn(property_id="prop-002")  # both None
    with pytest.raises(HTTPException) as exc:
        svc.assign_work_order("prop-002", wo.work_order_id, body, "admin-1")
    assert exc.value.status_code == 422
    assert "assign_requires_target" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Group E: assign to terminal WO
# ---------------------------------------------------------------------------

def test_assign_to_completed_wo():
    from app.models import MaintenanceOrderAssignIn, MaintenanceOrderTransitionIn
    wo = _create_wo(title="Terminal assign test")
    svc = _svc()
    # Open → in_progress → completed
    svc.assign_work_order("prop-002", wo.work_order_id,
                          MaintenanceOrderAssignIn(property_id="prop-002", assignee_sub="s1"), "admin-1")
    svc.transition_work_order("prop-002", wo.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-002", target_status="in_progress"), "admin-1")
    svc.transition_work_order("prop-002", wo.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-002", target_status="completed"), "admin-1")
    body = MaintenanceOrderAssignIn(property_id="prop-002", assignee_sub="s2")
    with pytest.raises(HTTPException) as exc:
        svc.assign_work_order("prop-002", wo.work_order_id, body, "admin-1")
    assert exc.value.status_code == 409
    assert "illegal_assignment_terminal" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Group F: schedule happy path
# ---------------------------------------------------------------------------

def test_schedule_happy_path():
    from app.models import MaintenanceOrderScheduleIn
    wo = _create_wo(title="Schedule test")
    svc = _svc()
    body = MaintenanceOrderScheduleIn(property_id="prop-002", scheduled_for=9999999999)
    out = svc.schedule_work_order("prop-002", wo.work_order_id, body, "admin-1")
    assert out.scheduled_for == 9999999999

    # Reschedule
    body2 = MaintenanceOrderScheduleIn(property_id="prop-002", scheduled_for=8888888888)
    out2 = svc.schedule_work_order("prop-002", wo.work_order_id, body2, "admin-1")
    assert out2.scheduled_for == 8888888888


# ---------------------------------------------------------------------------
# Group G: schedule terminal WO
# ---------------------------------------------------------------------------

def test_schedule_cancelled_wo():
    from app.models import MaintenanceOrderScheduleIn, MaintenanceOrderTransitionIn
    wo = _create_wo(title="Cancel schedule test")
    svc = _svc()
    svc.transition_work_order("prop-002", wo.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-002", target_status="cancelled"), "admin-1")
    body = MaintenanceOrderScheduleIn(property_id="prop-002", scheduled_for=9999999999)
    with pytest.raises(HTTPException) as exc:
        svc.schedule_work_order("prop-002", wo.work_order_id, body, "admin-1")
    assert exc.value.status_code == 409
    assert "cannot_schedule_terminal" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Group H: transition valid chain
# ---------------------------------------------------------------------------

def test_transition_valid_chain():
    from app.models import MaintenanceOrderAssignIn, MaintenanceOrderTransitionIn
    wo = _create_wo(title="Valid chain test")
    svc = _svc()
    # open → assigned
    t1 = svc.transition_work_order("prop-002", wo.work_order_id,
                                   MaintenanceOrderTransitionIn(property_id="prop-002", target_status="assigned"), "admin-1")
    assert t1.wo_status == "assigned"
    assert t1.completed_at is None

    # assigned → in_progress
    t2 = svc.transition_work_order("prop-002", wo.work_order_id,
                                   MaintenanceOrderTransitionIn(property_id="prop-002", target_status="in_progress"), "admin-1")
    assert t2.wo_status == "in_progress"

    # in_progress → completed with cost_cents
    t3 = svc.transition_work_order("prop-002", wo.work_order_id,
                                   MaintenanceOrderTransitionIn(property_id="prop-002", target_status="completed", cost_cents=15000), "admin-1")
    assert t3.wo_status == "completed"
    assert t3.completed_at is not None
    assert t3.cost_cents == 15000


# ---------------------------------------------------------------------------
# Group I: cancellation paths
# ---------------------------------------------------------------------------

def test_cancel_from_open():
    from app.models import MaintenanceOrderTransitionIn
    wo = _create_wo(title="Cancel from open")
    svc = _svc()
    out = svc.transition_work_order("prop-002", wo.work_order_id,
                                    MaintenanceOrderTransitionIn(property_id="prop-002", target_status="cancelled"), "admin-1")
    assert out.wo_status == "cancelled"


def test_cancel_from_in_progress():
    from app.models import MaintenanceOrderTransitionIn
    wo = _create_wo(title="Cancel from in_progress")
    svc = _svc()
    svc.transition_work_order("prop-002", wo.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-002", target_status="in_progress"), "admin-1")
    out = svc.transition_work_order("prop-002", wo.work_order_id,
                                    MaintenanceOrderTransitionIn(property_id="prop-002", target_status="cancelled"), "admin-1")
    assert out.wo_status == "cancelled"


# ---------------------------------------------------------------------------
# Group J: illegal transitions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("start,path_to_start,illegal_target", [
    ("open", [], "completed"),
    ("assigned", ["assigned"], "completed"),
    ("cancelled", ["cancelled"], "in_progress"),
])
def test_illegal_transition(start, path_to_start, illegal_target):
    from app.models import MaintenanceOrderTransitionIn
    wo = _create_wo(title=f"Illegal {start}->{illegal_target}")
    svc = _svc()
    # Drive to the start state
    for target in path_to_start:
        svc.transition_work_order("prop-002", wo.work_order_id,
                                  MaintenanceOrderTransitionIn(property_id="prop-002", target_status=target), "admin-1")
    with pytest.raises(HTTPException) as exc:
        svc.transition_work_order("prop-002", wo.work_order_id,
                                  MaintenanceOrderTransitionIn(property_id="prop-002", target_status=illegal_target), "admin-1")
    assert exc.value.status_code == 409
    assert "illegal_transition" in str(exc.value.detail)


def test_completed_to_open_illegal():
    """completed → open: VALID_TRANSITIONS.get('completed') is empty set → 409."""
    from app.models import MaintenanceOrderTransitionIn
    wo = _create_wo(title="Completed to open illegal")
    svc = _svc()
    # Drive to completed state
    svc.transition_work_order("prop-002", wo.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-002", target_status="in_progress"), "admin-1")
    svc.transition_work_order("prop-002", wo.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-002", target_status="completed"), "admin-1")
    # Now try any valid-literal transition (assigned)
    with pytest.raises(HTTPException) as exc:
        svc.transition_work_order("prop-002", wo.work_order_id,
                                  MaintenanceOrderTransitionIn(property_id="prop-002", target_status="assigned"), "admin-1")
    assert exc.value.status_code == 409
    assert "illegal_transition" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Group K: concurrent transition
# ---------------------------------------------------------------------------

def test_concurrent_transition():
    from app.models import MaintenanceOrderTransitionIn
    from botocore.exceptions import ClientError as BotoClientError
    wo = _create_wo(title="Concurrent test")
    svc = _svc()

    def fake_update_item(**kwargs):
        error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "failed"}, "ResponseMetadata": {}}
        raise BotoClientError(error_response, "UpdateItem")

    import app.core.tables as T_mod
    orig = T_mod.T.maintenance_orders.update_item
    try:
        T_mod.T.maintenance_orders.update_item = fake_update_item
        with pytest.raises(HTTPException) as exc:
            svc.transition_work_order("prop-002", wo.work_order_id,
                                      MaintenanceOrderTransitionIn(property_id="prop-002", target_status="in_progress"), "admin-1")
        assert exc.value.status_code == 409
        assert "concurrent_transition" in str(exc.value.detail)
    finally:
        T_mod.T.maintenance_orders.update_item = orig


# ---------------------------------------------------------------------------
# Group L: list by property with pagination
# ---------------------------------------------------------------------------

def test_list_mode_a_pagination():
    svc = _svc()
    # Create 3 WOs on prop-page
    for i in range(3):
        _create_wo(prop="prop-page", title=f"Page WO {i}")
    page1 = svc.list_work_orders(property_id="prop-page", limit=2)
    assert len(page1.items) == 2
    assert page1.cursor is not None

    page2 = svc.list_work_orders(property_id="prop-page", limit=2, cursor=page1.cursor)
    assert len(page2.items) == 1
    assert page2.cursor is None


# ---------------------------------------------------------------------------
# Group M: list by status
# ---------------------------------------------------------------------------

def test_list_mode_b_status():
    from app.models import MaintenanceOrderTransitionIn
    svc = _svc()
    # Create 2 open and advance 1 to assigned
    wo1 = _create_wo(prop="prop-status", title="Status open A")
    wo2 = _create_wo(prop="prop-status", title="Status open B")
    wo3 = _create_wo(prop="prop-status", title="Status assigned")
    svc.transition_work_order("prop-status", wo3.work_order_id,
                              MaintenanceOrderTransitionIn(property_id="prop-status", target_status="assigned"), "admin-1")

    open_list = svc.list_work_orders(wo_status="open")
    open_ids = {w.work_order_id for w in open_list.items}
    assert wo1.work_order_id in open_ids
    assert wo2.work_order_id in open_ids
    assert wo3.work_order_id not in open_ids

    assigned_list = svc.list_work_orders(wo_status="assigned")
    assigned_ids = {w.work_order_id for w in assigned_list.items}
    assert wo3.work_order_id in assigned_ids


# ---------------------------------------------------------------------------
# Group N: list by assignee
# ---------------------------------------------------------------------------

def test_list_mode_c_assignee():
    from app.models import MaintenanceOrderAssignIn
    svc = _svc()
    wa = _create_wo(prop="prop-assignee", title="Assignee A-1")
    wb = _create_wo(prop="prop-assignee", title="Assignee A-2")
    wc = _create_wo(prop="prop-assignee", title="Assignee B")
    wu = _create_wo(prop="prop-assignee", title="Unassigned")

    svc.assign_work_order("prop-assignee", wa.work_order_id,
                          MaintenanceOrderAssignIn(property_id="prop-assignee", assignee_sub="staff-A"), "admin-1")
    svc.assign_work_order("prop-assignee", wb.work_order_id,
                          MaintenanceOrderAssignIn(property_id="prop-assignee", assignee_sub="staff-A"), "admin-1")
    svc.assign_work_order("prop-assignee", wc.work_order_id,
                          MaintenanceOrderAssignIn(property_id="prop-assignee", assignee_sub="staff-B"), "admin-1")

    a_list = svc.list_work_orders(assignee_sub="staff-A")
    assert len(a_list.items) == 2

    b_list = svc.list_work_orders(assignee_sub="staff-B")
    assert len(b_list.items) == 1

    # Unassigned WO doesn't appear
    u_list = svc.list_work_orders(assignee_sub="staff-A")
    ids = {w.work_order_id for w in u_list.items}
    assert wu.work_order_id not in ids


# ---------------------------------------------------------------------------
# Group O: no filter raises 400
# ---------------------------------------------------------------------------

def test_list_no_filter():
    with pytest.raises(HTTPException) as exc:
        _svc().list_work_orders()
    assert exc.value.status_code == 400
    assert "supply_filter" in str(exc.value.detail)


# ---------------------------------------------------------------------------
# Group P: flag-off guard
# ---------------------------------------------------------------------------

def test_flag_off_all_lifecycle():
    from app.core.settings import S
    from app.models import MaintenanceOrderAssignIn, MaintenanceOrderScheduleIn, MaintenanceOrderTransitionIn
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        for fn, args in [
            (_svc().assign_work_order, ["p", "w", MaintenanceOrderAssignIn(property_id="p", assignee_sub="s"), "a"]),
            (_svc().schedule_work_order, ["p", "w", MaintenanceOrderScheduleIn(property_id="p", scheduled_for=1), "a"]),
            (_svc().transition_work_order, ["p", "w", MaintenanceOrderTransitionIn(property_id="p", target_status="cancelled"), "a"]),
            (_svc().list_work_orders, []), # with property_id kwarg
        ]:
            with pytest.raises(HTTPException) as exc:
                if fn == _svc().list_work_orders:
                    fn(property_id="p")
                else:
                    fn(*args)
            assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


# ---------------------------------------------------------------------------
# Group Q: board columns
# ---------------------------------------------------------------------------

def test_default_wo_columns():
    cols = _svc().default_wo_columns()
    assert len(cols) == 5
    column_ids = {c["column_id"] for c in cols}
    assert "wo_open" in column_ids
    assert "wo_assigned" in column_ids
    assert "wo_in_progress" in column_ids
    assert "wo_completed" in column_ids
    assert "wo_cancelled" in column_ids
    status_keys = {c["status_key"] for c in cols}
    assert status_keys == {"open", "assigned", "in_progress", "completed", "cancelled"}


# ---------------------------------------------------------------------------
# Missing SimpleNamespace import
# ---------------------------------------------------------------------------

from types import SimpleNamespace
