"""
WOV-004 hermetic pytest — maintenance vendor directory.

Uses the standalone maintenance_vendors table (PUR-003 path is skipped in tests
since we're in isolation).  moto intercepts all DynamoDB calls.
"""
from __future__ import annotations

import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Module-level isolation fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _module_isolation():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = ddb.create_table(
            TableName="maintenance_vendors_test",
            KeySchema=[
                {"AttributeName": "vendor_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "vendor_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI_VENDOR_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        tbl.meta.client.get_waiter("table_exists").wait(TableName="maintenance_vendors_test")

        import app.core.tables as T_mod
        from app.core.settings import S
        import app.services.maintenance_vendors as vsvc

        orig_t = T_mod.T.maintenance_vendors
        orig_flag = S.maintenance_orders_enabled
        orig_pur_avail = vsvc._PUR_AVAILABLE

        object.__setattr__(T_mod.T, "maintenance_vendors", tbl)
        object.__setattr__(S, "maintenance_orders_enabled", True)
        vsvc._PUR_AVAILABLE = False  # force standalone path

        with patch("app.services.alerts.audit_event", MagicMock()):
            yield tbl

        object.__setattr__(T_mod.T, "maintenance_vendors", orig_t)
        object.__setattr__(S, "maintenance_orders_enabled", orig_flag)
        vsvc._PUR_AVAILABLE = orig_pur_avail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vsvc():
    import app.services.maintenance_vendors as m
    return m


def _make_body(**kwargs):
    from app.models import VendorCreateIn
    defaults = {
        "name": "ABC Plumbing",
        "trade_category": "plumbing",
    }
    defaults.update(kwargs)
    return VendorCreateIn(**defaults)


def _create(actor="admin-1", **kwargs):
    return _vsvc().create_vendor(actor, _make_body(**kwargs))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_flag_off_create():
    from app.core.settings import S
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc:
            _vsvc().create_vendor("admin-1", _make_body(name="Flag off vendor"))
        assert exc.value.status_code == 404
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


def test_flag_off_list():
    from app.core.settings import S
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        with pytest.raises(HTTPException):
            _vsvc().list_vendors()
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


def test_flag_off_update():
    from app.core.settings import S
    from app.models import VendorPatchIn
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        with pytest.raises(HTTPException):
            _vsvc().update_vendor("fake-id", "admin-1", VendorPatchIn(name="X"))
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


def test_get_vendor_no_flag_check():
    """get_vendor bypasses flag check (for WOV-002 use)."""
    v = _create(name="Get bypass test", trade_category="electrical")
    from app.core.settings import S
    object.__setattr__(S, "maintenance_orders_enabled", False)
    try:
        result = _vsvc().get_vendor(v.vendor_id)
        assert result is not None
        assert result.vendor_id == v.vendor_id
    finally:
        object.__setattr__(S, "maintenance_orders_enabled", True)


def test_create_happy_path():
    from app.models import VendorOut
    v = _create(name="Happy Path Plumbing", trade_category="plumbing")
    assert isinstance(v, VendorOut)
    assert v.status == "active"
    assert v.trade_category == "plumbing"
    assert v.source == "maintenance_vendor"
    assert len(v.vendor_id) == 32


def test_create_idempotent():
    v1 = _create(name="Idempotent Plumber")
    v2 = _create(name="Idempotent Plumber")
    assert v1.vendor_id == v2.vendor_id


def test_create_bad_trade_category():
    with pytest.raises(HTTPException) as exc:
        _create(name="Roofing Co", trade_category="roofing")
    assert exc.value.status_code == 422
    detail = exc.value.detail
    assert "invalid_trade_category" in str(detail)
    assert "allowed" in str(detail)


def test_get_existing():
    v = _create(name="Get existing test", trade_category="hvac")
    fetched = _vsvc().get_vendor(v.vendor_id)
    assert fetched is not None
    assert fetched.vendor_id == v.vendor_id
    assert isinstance(fetched.created_at, int)
    assert isinstance(fetched.updated_at, int)


def test_get_missing():
    result = _vsvc().get_vendor("nonexistent_id_32chars_hexhexhex1")
    assert result is None


def test_update_trade_category():
    from app.models import VendorPatchIn
    v = _create(name="Update trade cat", trade_category="plumbing")
    updated = _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(trade_category="electrical"))
    assert updated.trade_category == "electrical"
    assert updated.updated_at >= v.updated_at


def test_update_bad_trade_category():
    from app.models import VendorPatchIn
    v = _create(name="Bad trade cat update", trade_category="plumbing")
    with pytest.raises(HTTPException) as exc:
        _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(trade_category="poolService"))
    assert exc.value.status_code == 422


def test_update_phone_normalization():
    from app.models import VendorPatchIn
    v = _create(name="Phone norm test", trade_category="general")
    updated = _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(phone="+1 (555) 000-0001"))
    assert updated.phone == "+15550000001"


def test_create_with_user_sub():
    v = _create(name="Linked vendor D2", trade_category="plumbing", user_sub="sub_vendor_1")
    assert v.user_sub == "sub_vendor_1"


def test_create_without_user_sub():
    v = _create(name="External vendor D2", trade_category="cleaning")
    assert v.user_sub is None


def test_update_set_user_sub():
    from app.models import VendorPatchIn
    v = _create(name="Set link vendor", trade_category="handyman")
    updated = _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(user_sub="sub_vendor_2"))
    assert updated.user_sub == "sub_vendor_2"


def test_update_clear_user_sub():
    from app.models import VendorPatchIn
    v = _create(name="Clear link vendor", trade_category="landscaping", user_sub="sub_vendor_3")
    assert v.user_sub == "sub_vendor_3"
    cleared = _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(user_sub=""))
    assert cleared.user_sub is None


def test_update_user_sub_none_preserves():
    from app.models import VendorPatchIn
    v = _create(name="Preserve link vendor", trade_category="hvac", user_sub="sub_preserve")
    updated = _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(name="Preserve link updated"))
    # user_sub=None in PatchIn means "leave as-is"
    assert updated.user_sub == "sub_preserve"


def test_set_status_inactive():
    v = _create(name="Inactive test vendor", trade_category="electrical")
    _vsvc().set_vendor_status(v.vendor_id, "inactive", "admin-1")
    fetched = _vsvc().get_vendor(v.vendor_id)
    assert fetched is not None
    assert fetched.status == "inactive"
    # Should not appear in active list
    active = _vsvc().list_vendors(status="active")
    active_ids = {vv.vendor_id for vv in active.vendors}
    assert v.vendor_id not in active_ids


def test_set_status_reactivate():
    v = _create(name="Reactivate test vendor", trade_category="plumbing")
    _vsvc().set_vendor_status(v.vendor_id, "inactive", "admin-1")
    _vsvc().set_vendor_status(v.vendor_id, "active", "admin-1")
    active = _vsvc().list_vendors(status="active")
    active_ids = {vv.vendor_id for vv in active.vendors}
    assert v.vendor_id in active_ids


def test_set_status_invalid():
    v = _create(name="Invalid status test", trade_category="hvac")
    with pytest.raises(HTTPException) as exc:
        _vsvc().set_vendor_status(v.vendor_id, "suspended", "admin-1")
    assert exc.value.status_code == 422


def test_set_status_unknown():
    with pytest.raises(HTTPException) as exc:
        _vsvc().set_vendor_status("nonexistent_vendor_id", "inactive", "admin-1")
    assert exc.value.status_code == 404


def test_list_by_status():
    # Create 3 active + 1 inactive (with unique names to avoid idempotency collisions)
    import time
    ts = str(int(time.time() * 1000))
    v1 = _create(name=f"List status A1 {ts}", trade_category="plumbing")
    v2 = _create(name=f"List status A2 {ts}", trade_category="electrical")
    v3 = _create(name=f"List status A3 {ts}", trade_category="hvac")
    v4 = _create(name=f"List status I1 {ts}", trade_category="general")
    _vsvc().set_vendor_status(v4.vendor_id, "inactive", "admin-1")

    active = _vsvc().list_vendors(status="active")
    active_ids = {v.vendor_id for v in active.vendors}
    assert v1.vendor_id in active_ids
    assert v2.vendor_id in active_ids
    assert v3.vendor_id in active_ids
    assert v4.vendor_id not in active_ids


def test_list_trade_filter():
    import time
    ts = str(int(time.time() * 1000))
    vp1 = _create(name=f"Plumb filter 1 {ts}", trade_category="plumbing")
    vp2 = _create(name=f"Plumb filter 2 {ts}", trade_category="plumbing")
    ve = _create(name=f"Elec filter {ts}", trade_category="electrical")

    plumbing = _vsvc().list_vendors(trade_category="plumbing")
    plumbing_ids = {v.vendor_id for v in plumbing.vendors}
    assert vp1.vendor_id in plumbing_ids
    assert vp2.vendor_id in plumbing_ids
    assert ve.vendor_id not in plumbing_ids


def test_list_source_isolation():
    """A raw DDB row without source=maintenance_vendor must be excluded."""
    import app.core.tables as T_mod
    # Insert a raw row without source
    T_mod.T.maintenance_vendors.put_item(Item={
        "vendor_id": "raw-supplier-no-source",
        "sk": "META",
        "name": "Raw Supplier",
        "status": "active",
        "created_at": 1,
        "updated_at": 1,
        "created_by": "system",
        "trade_category": "general",
        # NO source field
    })
    all_active = _vsvc().list_vendors(status="active")
    ids = {v.vendor_id for v in all_active.vendors}
    assert "raw-supplier-no-source" not in ids


def test_categories_constant():
    from app.services.maintenance_vendors import VENDOR_TRADE_CATEGORIES
    cats = sorted(VENDOR_TRADE_CATEGORIES)
    assert len(cats) == 7
    assert "plumbing" in cats
    assert "electrical" in cats
    assert "hvac" in cats
    assert "handyman" in cats
    assert "cleaning" in cats
    assert "landscaping" in cats
    assert "general" in cats


def test_audit_emitted():
    from app.models import VendorPatchIn
    mock_audit = MagicMock()
    with patch("app.services.alerts.audit_event", mock_audit):
        v = _vsvc().create_vendor("admin-1", _make_body(name="Audit create vendor", trade_category="cleaning"))
        _vsvc().update_vendor(v.vendor_id, "admin-1", VendorPatchIn(name="Audit updated"))
        _vsvc().set_vendor_status(v.vendor_id, "inactive", "admin-1")
    calls = [str(c) for c in mock_audit.call_args_list]
    assert any("maintenance_vendor.created" in c for c in calls)
    assert any("maintenance_vendor.updated" in c for c in calls)
    assert any("maintenance_vendor.status_changed" in c for c in calls)


def test_audit_failure_swallowed():
    """Audit failure must not block service operations."""
    with patch("app.services.alerts.audit_event", side_effect=RuntimeError("audit down")):
        # Should NOT raise
        v = _vsvc().create_vendor("admin-1", _make_body(name="Audit fail test", trade_category="hvac"))
    assert v.vendor_id is not None
