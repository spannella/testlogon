"""
FXA-011 — fixed-asset disposal cash proceeds routed through the money layer
(hermetic offline).

Disposal proceeds are a fresh CREDIT to the asset owner (money in), so the
billing primitive is new_ledger_entry(entry_type="credit") + apply_balance_delta
— NOT refund_payment (which reverses a prior charge). This test verifies:
  - disposal with proceeds posts exactly ONE credit ledger row + a balance delta;
  - zero-proceeds disposal posts none;
  - re-disposal does not double-credit (status guard + ledger-sk marker).

Pattern: moto in-memory DDB bound onto frozen T (fixed_assets +
fixed_asset_schedule + billing) via object.__setattr__, restored on teardown;
frozen S flags toggled; gl_posting stubbed in sys.modules. NO TestClient.
"""
from __future__ import annotations

import hashlib
import sys
from types import SimpleNamespace

import boto3
import pytest

try:
    from moto import mock_aws
    _MOTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _MOTO_AVAILABLE = False
    mock_aws = None

pytestmark = pytest.mark.skipif(not _MOTO_AVAILABLE, reason="moto not installed")


# ── fake gl_posting (records calls; never touches DDB) ──────────────────────────

class _FakeGlPosting:
    def __init__(self):
        self.calls = []

    def post_journal_entry(self, lines, **kwargs):
        self.calls.append({"lines": list(lines), **kwargs})
        return kwargs.get("journal_id") or "je_fake"


@pytest.fixture(autouse=True)
def _env():
    from app.core.tables import T
    from app.core.settings import S

    orig_fa = getattr(T, "fixed_assets", None)
    orig_fas = getattr(T, "fixed_asset_schedule", None)
    orig_billing = getattr(T, "billing", None)
    orig_enabled = S.fixed_assets_enabled
    orig_gl = getattr(S, "gl_double_entry_enabled", False)
    orig_gl_mod = sys.modules.get("app.services.gl_posting")

    fake_gl = _FakeGlPosting()
    sys.modules["app.services.gl_posting"] = SimpleNamespace(
        post_journal_entry=fake_gl.post_journal_entry,
    )

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        fa = ddb.create_table(
            TableName="fixed_assets",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        fas = ddb.create_table(
            TableName="fixed_asset_schedule",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        billing = ddb.create_table(
            TableName="billing",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        object.__setattr__(T, "fixed_assets", fa)
        object.__setattr__(T, "fixed_asset_schedule", fas)
        object.__setattr__(T, "billing", billing)
        object.__setattr__(S, "fixed_assets_enabled", True)
        object.__setattr__(S, "gl_double_entry_enabled", True)

        yield SimpleNamespace(fa=fa, fas=fas, billing=billing, gl=fake_gl)

    object.__setattr__(T, "fixed_assets", orig_fa)
    object.__setattr__(T, "fixed_asset_schedule", orig_fas)
    object.__setattr__(T, "billing", orig_billing)
    object.__setattr__(S, "fixed_assets_enabled", orig_enabled)
    object.__setattr__(S, "gl_double_entry_enabled", orig_gl)
    if orig_gl_mod is None:
        sys.modules.pop("app.services.gl_posting", None)
    else:
        sys.modules["app.services.gl_posting"] = orig_gl_mod


def _seed_asset(env, asset_id="asset_1", owner="owner_1", cost=120_000,
                salvage=0, accum=40_000):
    env.fa.put_item(Item={
        "pk": f"ASSET#{asset_id}", "sk": "META",
        "asset_id": asset_id, "owner_sub": owner, "name": "Server",
        "asset_class": "equipment", "acquisition_cost_cents": cost,
        "salvage_value_cents": salvage, "useful_life_months": 12,
        "acquired_at": 1_700_000_000, "depreciation_method": "straight_line",
        "status": "active", "accumulated_depreciation_cents": accum,
        "gl_asset_account_id": "1500", "gl_accum_depr_account_id": "1600",
        "gl_depr_expense_account_id": "6100", "gl_gain_account_id": "4800",
        "gl_loss_account_id": "5800",
        "created_at": 1_700_000_000, "updated_at": 1_700_000_000,
    })
    return asset_id, owner


def _ledger_rows(env, owner="owner_1"):
    resp = env.billing.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": f"USER#{owner}", ":p": "LEDGER#"},
    )
    return resp.get("Items", [])


# ── tests ───────────────────────────────────────────────────────────────────────

def test_disposal_with_proceeds_posts_one_credit_and_balance(_env):
    from app.services.fixed_assets import dispose_asset
    from app.models import FixedAssetDisposeIn
    asset_id, owner = _seed_asset(_env)

    out = dispose_asset(
        asset_id,
        FixedAssetDisposeIn(
            proceeds_payment_intent_id="pi_x",
            proceeds_amount_cents=30_000,
            correlation_id="disp-1",
        ),
        actor_sub="admin",
    )
    assert out.status == "disposed"

    rows = _ledger_rows(_env)
    assert len(rows) == 1, "exactly one disposal credit ledger row"
    row = rows[0]
    assert row["type"] == "credit"
    assert row["provider"] == "fixed_asset_disposal"
    assert row["reason"] == "fixed_asset_disposal"
    assert int(row["amount_cents"]) == 30_000
    assert int(row["signed_amount_cents"]) == 30_000  # credit -> positive
    assert row["asset_id"] == asset_id

    # balance row credited via apply_balance_delta
    bal = _env.billing.get_item(Key={"pk": f"USER#{owner}", "sk": "BALANCE"})["Item"]
    assert int(bal["payments_settled_cents"]) == 30_000

    # marker persisted for idempotency
    a = _env.fa.get_item(Key={"pk": f"ASSET#{asset_id}", "sk": "META"})["Item"]
    assert a.get("disposal_proceeds_ledger_sk")
    assert int(a.get("disposal_proceeds_cents")) == 30_000


def test_zero_proceeds_posts_no_money(_env):
    from app.services.fixed_assets import dispose_asset
    from app.models import FixedAssetDisposeIn
    asset_id, owner = _seed_asset(_env)

    out = dispose_asset(
        asset_id,
        FixedAssetDisposeIn(correlation_id="disp-zero"),
        actor_sub="admin",
    )
    assert out.status == "disposed"
    assert _ledger_rows(_env) == []
    # no balance row created
    assert _env.billing.get_item(
        Key={"pk": f"USER#{owner}", "sk": "BALANCE"}
    ).get("Item") is None


def test_redispose_does_not_double_credit(_env):
    from app.services.fixed_assets import dispose_asset
    from app.models import FixedAssetDisposeIn
    asset_id, owner = _seed_asset(_env)

    body = FixedAssetDisposeIn(
        proceeds_payment_intent_id="pi_x",
        proceeds_amount_cents=30_000,
        correlation_id="disp-redo",
    )
    dispose_asset(asset_id, body, actor_sub="admin")
    # second disposal — asset is already 'disposed', returns current state
    out2 = dispose_asset(asset_id, body, actor_sub="admin")
    assert out2.status == "disposed"

    rows = _ledger_rows(_env)
    assert len(rows) == 1, "re-disposal must NOT post a second credit"
    bal = _env.billing.get_item(Key={"pk": f"USER#{owner}", "sk": "BALANCE"})["Item"]
    assert int(bal["payments_settled_cents"]) == 30_000


def test_route_proceeds_helper_idempotent_with_marker(_env):
    """The _route_disposal_proceeds helper itself no-ops when a marker exists."""
    from app.services.fixed_assets import _route_disposal_proceeds
    sk1 = _route_disposal_proceeds(
        asset_id="a", owner_sub="owner_2", proceeds_cents=5_000, already_marked=None,
    )
    assert sk1
    # second call with the prior marker -> returns it, posts nothing new
    sk2 = _route_disposal_proceeds(
        asset_id="a", owner_sub="owner_2", proceeds_cents=5_000, already_marked=sk1,
    )
    assert sk2 == sk1
    assert len(_ledger_rows(_env, "owner_2")) == 1
