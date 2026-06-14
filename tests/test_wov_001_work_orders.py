"""
WOV-001 hermetic pytest — maintenance work-order entity, flag, create+get.

Isolation pattern:
- scope="module" autouse fixture saves/restores frozen T.maintenance_orders and S.maintenance_orders_enabled.
- moto intercepts all DynamoDB calls.
- No TestClient, no real AWS.
"""
from __future__ import annotations

import sys
import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

# ---------------------------------------------------------------------------
# Module-level setup fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _module_isolation():
    """Save/restore T.maintenance_orders and S.maintenance_orders_enabled."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="maintenance_orders",
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
        table.meta.client.get_waiter("table_exists").wait(TableName="maintenance_orders")

        import app.core.tables as tables_mod
        import app.services.maintenance_orders as svc
        from app.core.settings import S

        # Save original
        orig_t = tables_mod.T.maintenance_orders
        orig_flag = S.maintenance_orders_enabled

        # Inject moto table
        object.__setattr__(tables_mod.T, "maintenance_orders", table)
        object.__setattr__(S, "maintenance_orders_enabled", True)

        # Patch audit to no-op
        with patch("app.services.alerts.audit_event", MagicMock()):
            yield table

        # Restore
        object.__setattr__(tables_mod.T, "maintenance_orders", orig_t)
        object.__setattr__(S, "maintenance_orders_enabled", orig_flag)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_body(**kwargs):
    from app.models import MaintenanceOrderIn
    defaults = {
        "title": "Fix leaky pipe",
        "property_id": "prop-001",
        "priority": "normal",
    }
    defaults.update(kwargs)
    return MaintenanceOrderIn(**defaults)


def _svc():
    import app.services.maintenance_orders as m
    return m


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_flag_off_blocks_create():
    from app.core.settings import S
    from fastapi import HTTPException
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc:
            _svc().create_work_order("prop-001", _make_body(), "actor-1")
        assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


def test_flag_off_blocks_get():
    from app.core.settings import S
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc:
            _svc().get_work_order("prop-001", "nonexistent")
        assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


def test_create_happy_path():
    from app.models import MaintenanceOrderOut
    body = _make_body(correlation_id="corr-happy-001")
    out = _svc().create_work_order("prop-001", body, "actor-1")
    assert isinstance(out, MaintenanceOrderOut)
    assert out.wo_status == "open"
    assert out.priority == "normal"
    assert len(out.work_order_id) == 32
    assert isinstance(out.created_at, int)
    assert isinstance(out.updated_at, int)
    assert out.property_id == "prop-001"


def test_create_idempotent():
    body = _make_body(correlation_id="corr-idem-001")
    out1 = _svc().create_work_order("prop-001", body, "actor-2")
    out2 = _svc().create_work_order("prop-001", body, "actor-2")
    assert out1.work_order_id == out2.work_order_id


def test_create_no_correlation_id():
    body1 = _make_body()
    body2 = _make_body()
    out1 = _svc().create_work_order("prop-001", body1, "actor-3")
    out2 = _svc().create_work_order("prop-001", body2, "actor-3")
    assert out1.work_order_id != out2.work_order_id


def test_bad_priority_422():
    body = _make_body(priority="critical", correlation_id="bad-priority-1")
    with pytest.raises(HTTPException) as exc:
        _svc().create_work_order("prop-001", body, "actor-1")
    assert exc.value.status_code == 422
    assert "invalid_priority" in str(exc.value.detail)


def test_unknown_property_404():
    import app.services.maintenance_orders as svc_mod
    mock_get = MagicMock(return_value=None)
    with patch.dict(sys.modules, {"app.services.property_mgmt": MagicMock(get_property=mock_get)}):
        body = _make_body(correlation_id="unknown-prop-1")
        with pytest.raises(HTTPException) as exc:
            svc_mod.create_work_order("prop-missing", body, "actor-1")
        assert exc.value.status_code == 404
        assert "property_not_found" in str(exc.value.detail)


def test_property_import_error_skips_guard():
    """If property_mgmt is not importable, WO creation proceeds."""
    # Remove module if cached
    sys.modules.pop("app.services.property_mgmt", None)
    body = _make_body(title="Import error test", correlation_id="import-err-001")
    # Should NOT raise
    out = _svc().create_work_order("prop-001", body, "actor-1")
    assert out.wo_status == "open"


def test_get_existing():
    body = _make_body(title="Get test", correlation_id="get-test-001")
    created = _svc().create_work_order("prop-001", body, "actor-1")
    fetched = _svc().get_work_order("prop-001", created.work_order_id)
    assert fetched is not None
    assert fetched.work_order_id == created.work_order_id
    assert isinstance(fetched.created_at, int)
    assert isinstance(fetched.updated_at, int)


def test_get_missing_returns_none():
    result = _svc().get_work_order("prop-001", "nonexistent_32char_hexhexhexhex")
    assert result is None


def test_audit_emitted():
    from unittest.mock import MagicMock
    mock_audit = MagicMock()
    with patch("app.services.alerts.audit_event", mock_audit):
        body = _make_body(correlation_id="audit-test-001")
        _svc().create_work_order("prop-001", body, "actor-audit")
    calls = [str(c) for c in mock_audit.call_args_list]
    assert any("maintenance_order.created" in c for c in calls)


def test_sparse_fields_absent():
    body = _make_body(title="Sparse test", correlation_id="sparse-001")
    # No description, unit_id, scheduled_for
    out = _svc().create_work_order("prop-001", body, "actor-1")
    assert out.description is None
    assert out.unit_id is None
    assert out.scheduled_for is None
    assert out.completed_at is None
    assert out.vendor_id is None


def test_default_priority():
    body = _make_body(correlation_id="default-priority-001")
    out = _svc().create_work_order("prop-001", body, "actor-1")
    assert out.priority == "normal"
    assert out.wo_status == "open"


def test_default_wo_columns():
    cols = _svc().default_wo_columns()
    assert len(cols) == 5
    status_keys = {c["status_key"] for c in cols}
    assert status_keys == {"open", "assigned", "in_progress", "completed", "cancelled"}
    for c in cols:
        assert "column_id" in c
        assert "title" in c
        assert "order" in c
        assert c["column_id"].startswith("wo_")
