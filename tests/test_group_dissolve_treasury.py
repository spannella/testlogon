"""GAP-0021 regression: dissolve_group() must dissolve the group treasury.

Before the fix, dissolve_group() marked the group dissolved and deleted member
records but never invoked group_treasury.dissolve_treasury(), so contributed
funds were permanently orphaned in the billing table and donations never reached
PLATFORM#ESCROW.

These tests run fully offline against moto-backed DynamoDB (no real AWS): the
real `user_groups` and `billing` tables are created in-process and `T` is patched
on both service modules to point at them.
"""
from __future__ import annotations

from contextlib import ExitStack
from types import SimpleNamespace

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto is not installed")


def _create_user_groups_table(ddb):
    return ddb.create_table(
        TableName="user_groups",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _create_billing_table(ddb):
    return ddb.create_table(
        TableName="billing",
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


@pytest.fixture()
def ddb_tables():
    """Spin up moto DynamoDB, create real tables, patch T on the service modules."""
    from unittest.mock import patch

    from app.services import user_groups as ug_svc
    from app.services import group_treasury as gt_svc

    with ExitStack() as stack:
        stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        user_groups_table = _create_user_groups_table(ddb)
        billing_table = _create_billing_table(ddb)

        # group_treasury.apply_wallet_delta receives the billing table explicitly,
        # so only the two service modules that reference `T` need patching.
        fake_T = SimpleNamespace(user_groups=user_groups_table, billing=billing_table)
        stack.enter_context(patch.object(ug_svc, "T", fake_T))
        stack.enter_context(patch.object(gt_svc, "T", fake_T))

        yield SimpleNamespace(user_groups=user_groups_table, billing=billing_table)


def _wallet_balance(billing_table, user_sub):
    resp = billing_table.get_item(Key={"pk": f"USER#{user_sub}", "sk": "WALLET"})
    return int(resp.get("Item", {}).get("wallet_balance_cents", 0))


def test_dissolve_group_calls_treasury_and_refunds_contributors(ddb_tables):
    from app.services.user_groups import create_group, dissolve_group
    from app.services.group_treasury import contribute, get_treasury_balance
    from app.services.billing_shared import apply_wallet_delta

    alice = "alice-sub-001"
    g = create_group(creator_sub=alice, name="Test Group")
    group_id = g["group_id"]

    # Fund Alice's wallet and contribute it all into the treasury.
    apply_wallet_delta(ddb_tables.billing, f"USER#{alice}", 1000)
    contribute(group_id=group_id, user_id=alice, amount_cents=1000)

    # Sanity: treasury holds the funds, wallet is empty before dissolution.
    assert get_treasury_balance(group_id)["balance_cents"] == 1000
    assert _wallet_balance(ddb_tables.billing, alice) == 0

    result = dissolve_group(group_id=group_id, admin_id=alice)

    # After fix: group dissolved, treasury zeroed, contributor fully refunded.
    assert result["status"] == "dissolved"
    assert "treasury" in result  # FAILS before fix
    assert get_treasury_balance(group_id)["balance_cents"] == 0  # FAILS before fix
    assert _wallet_balance(ddb_tables.billing, alice) == 1000  # FAILS before fix


def test_dissolve_group_zero_balance_is_noop(ddb_tables):
    from app.services.user_groups import create_group, dissolve_group

    alice = "alice-sub-002"
    g = create_group(creator_sub=alice, name="Empty Treasury Group")
    group_id = g["group_id"]

    result = dissolve_group(group_id=group_id, admin_id=alice)
    assert result["status"] == "dissolved"
    assert result.get("treasury", {}).get("refunded_count", 0) == 0


def test_dissolve_group_routes_donations_to_escrow(ddb_tables):
    from app.services.user_groups import create_group, dissolve_group
    from app.services.group_treasury import credit_donation, get_treasury_balance

    alice = "alice-sub-003"
    g = create_group(creator_sub=alice, name="Donation Group")
    group_id = g["group_id"]

    # An external donation (not a contribution) of 500 cents.
    credit_donation(group_id=group_id, amount_cents=500, donor_name="Anon")
    assert get_treasury_balance(group_id)["total_donated_cents"] == 500

    dissolve_group(group_id=group_id, admin_id=alice)

    # After fix: donated funds swept to PLATFORM#ESCROW, treasury zeroed.
    escrow = ddb_tables.billing.get_item(Key={"pk": "PLATFORM#ESCROW", "sk": "WALLET"})
    escrow_balance = int(escrow.get("Item", {}).get("wallet_balance_cents", 0))
    assert escrow_balance >= 500, "Donated funds must reach PLATFORM#ESCROW on dissolution"
    assert get_treasury_balance(group_id)["balance_cents"] == 0
