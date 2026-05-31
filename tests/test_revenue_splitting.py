"""Unit tests for SYND-003: Syndicate Revenue Splitting engine.

DynamoDB tables are mocked via moto; the ``T`` table registry is patched in the
service modules under test.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ADMIN = "alice"
MEMBER = "bob"


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


def _make_pksk_table(ddb, name, *, with_gsi1=False):
    attrs = [
        {"AttributeName": "pk", "AttributeType": "S"},
        {"AttributeName": "sk", "AttributeType": "S"},
    ]
    gsi = []
    if with_gsi1:
        attrs += [
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ]
        gsi = [{
            "IndexName": "GSI1",
            "KeySchema": [
                {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }]
    kwargs = dict(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=attrs,
        BillingMode="PAY_PER_REQUEST",
    )
    if gsi:
        kwargs["GlobalSecondaryIndexes"] = gsi
    ddb.create_table(**kwargs)
    return ddb.Table(name)


@pytest.fixture()
def split_env():
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        syndicates = _make_pksk_table(ddb, "syndicates")
        split_tbl = _make_pksk_table(ddb, "syndicate_revenue_split", with_gsi1=True)
        billing = _make_pksk_table(ddb, "billing")

        from app.services import syndicates as syndicate_svc
        from app.services import syndicate_revenue_split as split_svc

        synd_T = SimpleNamespace(syndicates=syndicates)
        split_T = SimpleNamespace(
            syndicate_revenue_split=split_tbl, billing=billing
        )
        with patch.object(syndicate_svc, "T", synd_T), \
             patch.object(split_svc, "T", split_T):
            # Create a syndicate with two members (Alice admin + Bob).
            synd = syndicate_svc.create_syndicate(creator_sub=ADMIN, name="S")
            sid = synd["syndicate_id"]
            syndicate_svc._add_member(sid, MEMBER, role="member")
            syndicate_svc._increment_member_count(sid, 1)
            yield {
                "sid": sid,
                "syndicate_svc": syndicate_svc,
                "split_svc": split_svc,
                "billing": billing,
                "split_tbl": split_tbl,
            }


def test_equal_split_divides_evenly(split_env):
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    svc.set_split_config(syndicate_id=sid, admin_sub=ADMIN, mode="equal", platform_fee_bps=1500)
    split = svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    assert split["platform_fee_cents"] == 300
    assert split["net_amount_cents"] == 1700
    amounts = sorted(d["amount_cents"] for d in split["distributions"])
    assert amounts == [850, 850]
    assert sum(amounts) == split["net_amount_cents"]


def test_weighted_split_respects_percentages(split_env):
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    svc.set_split_config(
        syndicate_id=sid, admin_sub=ADMIN, mode="weighted",
        weights_bps={ADMIN: 6000, MEMBER: 4000},
    )
    split = svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    by_user = {d["user_id"]: d["amount_cents"] for d in split["distributions"]}
    assert by_user[ADMIN] == 1020  # 60% of 1700
    assert by_user[MEMBER] == 680   # 40% of 1700


def test_weighted_must_sum_to_100(split_env):
    from fastapi import HTTPException

    svc = split_env["split_svc"]
    sid = split_env["sid"]
    with pytest.raises(HTTPException) as exc:
        svc.set_split_config(
            syndicate_id=sid, admin_sub=ADMIN, mode="weighted",
            weights_bps={ADMIN: 6000, MEMBER: 3000},
        )
    assert exc.value.status_code == 400


def test_rounding_remainder_distributed(split_env):
    """$10.00 (1000c) net split 3 ways -> 334/333/333, no cents lost."""
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    split_env["syndicate_svc"]._add_member(sid, "carol", role="member")
    split_env["syndicate_svc"]._increment_member_count(sid, 1)
    svc.set_split_config(syndicate_id=sid, admin_sub=ADMIN, mode="equal", platform_fee_bps=0)
    split = svc.execute_split(syndicate_id=sid, gross_amount_cents=1000)
    amounts = sorted((d["amount_cents"] for d in split["distributions"]), reverse=True)
    assert amounts == [334, 333, 333]
    assert sum(amounts) == 1000


def test_split_writes_per_member_credit_entries(split_env):
    from boto3.dynamodb.conditions import Key

    svc = split_env["split_svc"]
    sid = split_env["sid"]
    billing = split_env["billing"]
    svc.set_split_config(syndicate_id=sid, admin_sub=ADMIN, mode="equal", platform_fee_bps=1500)
    split = svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    for member in (ADMIN, MEMBER):
        items = billing.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{member}")
        ).get("Items", [])
        credits = [
            it for it in items
            if it.get("reason") == "Syndicate bundle revenue share"
            and it.get("meta", {}).get("split_id") == split["split_id"]
        ]
        assert len(credits) == 1
        assert credits[0]["type"] == "credit"


def test_platform_fee_deducted_before_split(split_env):
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    svc.set_split_config(syndicate_id=sid, admin_sub=ADMIN, mode="equal", platform_fee_bps=2000)
    split = svc.execute_split(syndicate_id=sid, gross_amount_cents=1000)
    assert split["platform_fee_cents"] == 200
    assert split["net_amount_cents"] == 800
    assert split["platform_fee_cents"] + split["net_amount_cents"] == split["gross_amount_cents"]


def test_split_history_and_earnings_recorded(split_env):
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    svc.set_split_config(syndicate_id=sid, admin_sub=ADMIN, mode="equal", platform_fee_bps=1500)
    svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    svc.execute_split(syndicate_id=sid, gross_amount_cents=1000)
    history = svc.get_split_history(sid)
    assert len(history) == 2
    earnings = svc.get_member_earnings(sid, MEMBER)
    # 850 + 425 = 1275
    assert earnings["total_cents"] == 1275
    assert earnings["split_count"] == 2


def test_update_config_applies_to_future_only(split_env):
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    svc.set_split_config(syndicate_id=sid, admin_sub=ADMIN, mode="equal", platform_fee_bps=1500)
    first = svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    svc.set_split_config(
        syndicate_id=sid, admin_sub=ADMIN, mode="weighted",
        weights_bps={ADMIN: 7000, MEMBER: 3000},
    )
    second = svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    assert first["mode"] == "equal"
    assert second["mode"] == "weighted"
    # Historical split record is unchanged.
    stored_first = svc.get_split(sid, first["split_id"])
    assert stored_first["mode"] == "equal"


def test_performance_split_uses_seeded_scores(split_env):
    svc = split_env["split_svc"]
    sid = split_env["sid"]
    svc.set_split_config(
        syndicate_id=sid, admin_sub=ADMIN, mode="performance",
        performance_metric="views", performance_window_days=30,
    )
    svc.set_performance_scores(
        syndicate_id=sid, admin_sub=ADMIN, metric="views",
        scores={ADMIN: 3, MEMBER: 1},
    )
    split = svc.execute_split(syndicate_id=sid, gross_amount_cents=2000)
    by_user = {d["user_id"]: d["amount_cents"] for d in split["distributions"]}
    # net 1700, scores 3:1 -> 1275 / 425.
    assert by_user[ADMIN] == 1275
    assert by_user[MEMBER] == 425


def test_non_admin_cannot_set_config(split_env):
    from fastapi import HTTPException

    svc = split_env["split_svc"]
    sid = split_env["sid"]
    with pytest.raises(HTTPException) as exc:
        svc.set_split_config(syndicate_id=sid, admin_sub=MEMBER, mode="equal")
    assert exc.value.status_code == 403
