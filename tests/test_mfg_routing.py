"""MFG-005 hermetic tests — per-BOM routing tasks + cost computation.

Offline: moto-backed mfg_boms + mfg_work_centers tables bound to the frozen
T via object.__setattr__ (restored on teardown); frozen S flag toggled.
No TestClient, no real AWS.
"""
from __future__ import annotations

from types import SimpleNamespace

import boto3
import pytest


def _make_boms_table(ddb):
    return ddb.create_table(
        TableName="rt_test_mfg_boms",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "bom_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "bom_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "product_sku", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_PRODUCT",
                "KeySchema": [
                    {"AttributeName": "product_sku", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _make_wc_table(ddb):
    return ddb.create_table(
        TableName="rt_test_mfg_work_centers",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "work_center_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "work_center_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


_STATE: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _rt_tables():
    import moto
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        boms_tbl = _make_boms_table(ddb)
        wc_tbl = _make_wc_table(ddb)

        import app.services.manufacturing_routing as svc
        from app.core import tables as tables_mod
        from app.core.settings import S

        orig_boms = getattr(tables_mod.T, "mfg_boms", None)
        orig_wc = getattr(tables_mod.T, "mfg_work_centers", None)
        orig_flag = getattr(S, "manufacturing_mrp_enabled", False)

        object.__setattr__(tables_mod.T, "mfg_boms", boms_tbl)
        object.__setattr__(tables_mod.T, "mfg_work_centers", wc_tbl)
        object.__setattr__(S, "manufacturing_mrp_enabled", True)

        # Seed two work centers with distinct cost rates
        wc_a = svc.create_work_center("Assembly", 10, 6000, user_sub="test")
        wc_b = svc.create_work_center("Finishing", 5, 3000, user_sub="test")
        _STATE["wc_a"] = wc_a["work_center_id"]
        _STATE["wc_b"] = wc_b["work_center_id"]
        _STATE["bom_id"] = "bom-routing-test"

        yield

        object.__setattr__(S, "manufacturing_mrp_enabled", orig_flag)
        if orig_boms is not None:
            object.__setattr__(tables_mod.T, "mfg_boms", orig_boms)
        if orig_wc is not None:
            object.__setattr__(tables_mod.T, "mfg_work_centers", orig_wc)


# ---------------------------------------------------------------------------
# add / list / delete
# ---------------------------------------------------------------------------

def test_add_routing_task_returns_row():
    from app.services.manufacturing_routing import add_routing_task
    bom = "bom-add"
    t = add_routing_task(bom, _STATE["wc_a"], sequence=0, setup_minutes=30,
                         run_minutes_per_unit=5, description="Drill", user_sub="test")
    assert t["bom_id"] == bom
    assert t["sequence"] == 0
    assert t["work_center_id"] == _STATE["wc_a"]
    assert t["setup_minutes"] == 30
    assert t["run_minutes_per_unit"] == 5
    assert t["description"] == "Drill"


def test_list_routing_tasks_ordered():
    from app.services.manufacturing_routing import add_routing_task, list_routing_tasks
    bom = "bom-order"
    add_routing_task(bom, _STATE["wc_a"], sequence=20, user_sub="test")
    add_routing_task(bom, _STATE["wc_b"], sequence=0, user_sub="test")
    add_routing_task(bom, _STATE["wc_a"], sequence=10, user_sub="test")
    tasks = list_routing_tasks(bom)
    assert [t["sequence"] for t in tasks] == [0, 10, 20]


def test_add_duplicate_sequence_409():
    from app.services.manufacturing_routing import add_routing_task
    from fastapi import HTTPException
    bom = "bom-dup"
    add_routing_task(bom, _STATE["wc_a"], sequence=0, user_sub="test")
    with pytest.raises(HTTPException) as exc:
        add_routing_task(bom, _STATE["wc_a"], sequence=0, user_sub="test")
    assert exc.value.status_code == 409


def test_add_unknown_work_center_422():
    from app.services.manufacturing_routing import add_routing_task
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        add_routing_task("bom-bad-wc", "WC#does-not-exist", sequence=0, user_sub="test")
    assert exc.value.status_code == 422


def test_delete_routing_task():
    from app.services.manufacturing_routing import (
        add_routing_task, delete_routing_task, list_routing_tasks,
    )
    bom = "bom-del"
    add_routing_task(bom, _STATE["wc_a"], sequence=0, user_sub="test")
    assert len(list_routing_tasks(bom)) == 1
    delete_routing_task(bom, 0, user_sub="test")
    assert list_routing_tasks(bom) == []


def test_delete_missing_task_404():
    from app.services.manufacturing_routing import delete_routing_task
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        delete_routing_task("bom-none", 99, user_sub="test")
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# cost / time computation
# ---------------------------------------------------------------------------

def test_compute_routing_time():
    from app.services.manufacturing_routing import add_routing_task, compute_routing_time
    bom = "bom-time"
    add_routing_task(bom, _STATE["wc_a"], sequence=0, setup_minutes=30, run_minutes_per_unit=5, user_sub="test")
    add_routing_task(bom, _STATE["wc_b"], sequence=1, setup_minutes=0, run_minutes_per_unit=2, user_sub="test")
    res = compute_routing_time(bom, 10)
    # setup: 30 + 0 = 30; run: 5*10 + 2*10 = 70; total 100
    assert res["total_setup_minutes"] == 30
    assert res["total_run_minutes"] == 70
    assert res["total_minutes"] == 100


def test_compute_routing_cost():
    from app.services.manufacturing_routing import add_routing_task, compute_routing_cost
    bom = "bom-cost"
    # wc_a rate 6000/hr, wc_b rate 3000/hr
    add_routing_task(bom, _STATE["wc_a"], sequence=0, setup_minutes=30, run_minutes_per_unit=5, user_sub="test")
    add_routing_task(bom, _STATE["wc_b"], sequence=1, setup_minutes=0, run_minutes_per_unit=2, user_sub="test")
    res = compute_routing_cost(bom, 10)
    # task_a: 30 + 5*10 = 80 min -> ceil(80/60 * 6000) = ceil(8000) = 8000
    # task_b: 0 + 2*10 = 20 min  -> ceil(20/60 * 3000) = ceil(1000) = 1000
    assert res["total_labor_cost_cents"] == 9000
    assert res["total_minutes"] == 100
    assert len(res["tasks"]) == 2


def test_compute_routing_cost_empty_is_zero():
    from app.services.manufacturing_routing import compute_routing_cost
    res = compute_routing_cost("bom-empty", 5)
    assert res["total_labor_cost_cents"] == 0
    assert res["total_minutes"] == 0
    assert res["tasks"] == []


def test_compute_routing_cost_ceil_rounding():
    from app.services.manufacturing_routing import add_routing_task, compute_routing_cost
    bom = "bom-ceil"
    # 1 minute at 1 cent/hr -> ceil(1/60 * 1) = ceil(0.0167) = 1 cent (not 0)
    wc = _STATE["wc_a"]
    # use a center with rate 1; create one
    from app.services.manufacturing_routing import create_work_center
    cheap = create_work_center("Cheap", 1, 1, user_sub="test")
    add_routing_task(bom, cheap["work_center_id"], sequence=0, setup_minutes=1, run_minutes_per_unit=0, user_sub="test")
    res = compute_routing_cost(bom, 1)
    assert res["total_labor_cost_cents"] == 1


# ---------------------------------------------------------------------------
# flag gate
# ---------------------------------------------------------------------------

def test_flag_off_404():
    from app.services.manufacturing_routing import add_routing_task, list_routing_tasks, compute_routing_cost
    from app.core.settings import S
    from fastapi import HTTPException
    object.__setattr__(S, "manufacturing_mrp_enabled", False)
    try:
        with pytest.raises(HTTPException) as e1:
            list_routing_tasks("bom-x")
        assert e1.value.status_code == 404
        with pytest.raises(HTTPException) as e2:
            add_routing_task("bom-x", _STATE["wc_a"], sequence=0)
        assert e2.value.status_code == 404
        with pytest.raises(HTTPException) as e3:
            compute_routing_cost("bom-x", 1)
        assert e3.value.status_code == 404
    finally:
        object.__setattr__(S, "manufacturing_mrp_enabled", True)
