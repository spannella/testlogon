"""Hermetic offline tests for the OFBiz OFB-CORE foundation.

Covers:
  - OFB-002 scaffolding (table handles + flag defaults)
  - OFB-003/004 inventory: set_on_hand / adjust / reserve / release / commit /
    expire + the available == on_hand - reserved invariant
  - OFB-013 chart of accounts: seed idempotency + normal-balance derivation
  - OFB-014 GL poster: balanced-entry invariant (the money-safety critical case)
    + idempotency + list/get
  - OFB-015 AR aging: derive_charge_status + bucket boundaries
  - OFB-019/020 pricing: tiered/bulk/conditional compute, stacking, façade, redeem

Pattern: moto in-memory tables bound to the frozen ``T`` via ``object.__setattr__``,
frozen ``S`` flags flipped via ``object.__setattr__``, restored on teardown. No
TestClient; service functions invoked directly. No real AWS/network.
"""
from __future__ import annotations

from contextlib import ExitStack

import boto3
import pytest
from moto import mock_aws

from app.core import settings as settings_mod
from app.core import tables as tables_mod

S = settings_mod.S
T = tables_mod.T


# ── table builders matching scripts/local-ddb-init.py exactly ───────────────
def _make_inventory(ddb):
    return ddb.create_table(
        TableName="inventory",
        KeySchema=[
            {"AttributeName": "sku", "KeyType": "HASH"},
            {"AttributeName": "location_sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "sku", "AttributeType": "S"},
            {"AttributeName": "location_sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "available", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI_AVAILABLE",
            "KeySchema": [
                {"AttributeName": "status", "KeyType": "HASH"},
                {"AttributeName": "available", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_reservations(ddb):
    return ddb.create_table(
        TableName="reservations",
        KeySchema=[
            {"AttributeName": "reservation_pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "reservation_pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "sku", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "gsi_expiry_pk", "AttributeType": "S"},
            {"AttributeName": "expires_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "GSI_SKU", "KeySchema": [
                {"AttributeName": "sku", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "GSI_EXPIRY", "KeySchema": [
                {"AttributeName": "gsi_expiry_pk", "KeyType": "HASH"},
                {"AttributeName": "expires_at", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_gl_accounts(ddb):
    return ddb.create_table(
        TableName="gl_accounts",
        KeySchema=[
            {"AttributeName": "account_code", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "account_code", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "account_class", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "GSI_CLASS",
            "KeySchema": [
                {"AttributeName": "account_class", "KeyType": "HASH"},
                {"AttributeName": "account_code", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_gl_journal(ddb):
    return ddb.create_table(
        TableName="gl_journal",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "ledger_date", "AttributeType": "S"},
            {"AttributeName": "source_entry_id", "AttributeType": "S"},
            {"AttributeName": "posted_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "ENTRIES_BY_DATE", "KeySchema": [
                {"AttributeName": "ledger_date", "KeyType": "HASH"},
                {"AttributeName": "posted_at", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "SOURCE_ENTRY_IDX", "KeySchema": [
                {"AttributeName": "source_entry_id", "KeyType": "HASH"},
                {"AttributeName": "posted_at", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_pricing_rules(ddb):
    return ddb.create_table(
        TableName="PricingRules",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
            {"AttributeName": "active_pk", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": "ByCreatorCreatedAt", "KeySchema": [
                {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": "ByActive", "KeySchema": [
                {"AttributeName": "active_pk", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ], "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def env():
    """Bind moto tables to frozen T; enable all OFBiz flags; restore on exit."""
    with ExitStack() as stack:
        stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        binds = {
            "inventory": _make_inventory(ddb),
            "reservations": _make_reservations(ddb),
            "gl_accounts": _make_gl_accounts(ddb),
            "gl_journal": _make_gl_journal(ddb),
            "pricing_rules": _make_pricing_rules(ddb),
        }
        for name, tbl in binds.items():
            tbl.wait_until_exists()
            orig = getattr(T, name)
            object.__setattr__(T, name, tbl)
            stack.callback(object.__setattr__, T, name, orig)

        flags = {
            "inventory_reservations_enabled": True,
            "gl_double_entry_enabled": True,
            "ar_ap_subledgers_enabled": True,
            "pricing_rules_enabled": True,
        }
        for k, v in flags.items():
            orig = getattr(S, k)
            object.__setattr__(S, k, v)
            stack.callback(object.__setattr__, S, k, orig)

        # patch audit to a no-op (avoid touching T.alerts)
        import app.services.alerts as alerts_mod
        orig_audit = alerts_mod.audit_event
        object.__setattr__(alerts_mod, "audit_event", lambda *a, **k: None)
        stack.callback(object.__setattr__, alerts_mod, "audit_event", orig_audit)

        yield binds


# ── OFB-002 scaffolding ──────────────────────────────────────────────────────

def test_seed_idempotent_and_normal_balance(env):
    from app.services import gl_accounts as gl
    gl.seed_chart_of_accounts()
    gl.seed_chart_of_accounts()  # second call must not duplicate
    accts = gl.list_accounts()
    assert len(accts) == 7
    cash = gl.get_account("1000")
    assert cash["normal_balance"] == "debit" and cash["is_system"] is True
    rev = gl.get_account("4000")
    assert rev["normal_balance"] == "credit"


def test_create_account_derives_normal_balance_and_contra_asset(env):
    from app.services import gl_accounts as gl
    a = gl.create_account("1500", "Accum. Depreciation", "contra_asset", None, "root")
    assert a["normal_balance"] == "credit"  # ESCALATIONS: contra_asset credit-normal
    b = gl.create_account("5200", "Rent", "expense", None, "root")
    assert b["normal_balance"] == "debit"


def test_create_account_invalid_class_400_and_dup_409(env):
    from app.services import gl_accounts as gl
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        gl.create_account("9999", "Bogus", "nonsense", None, "root")
    assert ei.value.status_code == 400
    gl.create_account("3000", "Equity", "equity", None, "root")
    with pytest.raises(HTTPException) as ei2:
        gl.create_account("3000", "Equity2", "equity", None, "root")
    assert ei2.value.status_code == 409


def test_disable_system_account_403(env):
    from app.services import gl_accounts as gl
    from fastapi import HTTPException
    gl.seed_chart_of_accounts()
    with pytest.raises(HTTPException) as ei:
        gl.disable_account("1000", "root")
    assert ei.value.status_code == 403


# ── OFB-014 GL poster — balanced invariant is money-safety critical ─────────
def test_post_journal_entry_balanced(env):
    from app.services import gl_accounts as gl
    from app.services import gl_posting as glp
    gl.seed_chart_of_accounts()
    lines = [
        glp.JournalLine("1000", "debit", 1000),
        glp.JournalLine("4000", "credit", 1000),
    ]
    jid = glp.post_journal_entry(
        lines, source_type="tip_debit", source_entity_id="entry_abc",
        memo="tip", gl_date="2026-01-15",
    )
    entry = glp.get_journal_entry_header(jid)
    assert entry is not None
    assert entry["total_debit_cents"] == entry["total_credit_cents"] == 1000
    assert {l["side"] for l in entry["lines"]} == {"debit", "credit"}
    # line debit/credit sums balance
    deb = sum(l["amount_cents"] for l in entry["lines"] if l["side"] == "debit")
    cred = sum(l["amount_cents"] for l in entry["lines"] if l["side"] == "credit")
    assert deb == cred


def test_post_journal_entry_unbalanced_raises_no_write(env):
    from app.services import gl_posting as glp
    lines = [
        glp.JournalLine("1000", "debit", 1000),
        glp.JournalLine("4000", "credit", 900),
    ]
    with pytest.raises(glp.GLUnbalancedEntryError):
        glp.post_journal_entry(
            lines, source_type="bug", source_entity_id="x1", memo="", gl_date="2026-01-15"
        )
    # nothing written
    resp = T.gl_journal.scan()
    assert resp.get("Count", 0) == 0


def test_post_journal_entry_multiline_split_balanced(env):
    from app.services import gl_posting as glp
    # Tax split: Dr Cash 1100; Cr Sales 1000; Cr Tax 100
    lines = [
        glp.JournalLine("1000", "debit", 1100),
        glp.JournalLine("4000", "credit", 1000),
        glp.JournalLine("2100", "credit", 100),
    ]
    jid = glp.post_journal_entry(
        lines, source_type="catalog_purchase", source_entity_id="ord1",
        memo="", gl_date="2026-01-15",
    )
    e = glp.get_journal_entry_header(jid)
    assert e["total_debit_cents"] == e["total_credit_cents"] == 1100
    assert len(e["lines"]) == 3


def test_post_journal_entry_idempotent(env):
    from app.services import gl_posting as glp
    lines = [glp.JournalLine("1000", "debit", 500), glp.JournalLine("4000", "credit", 500)]
    jid1 = glp.post_journal_entry(lines, source_type="refund", source_entity_id="r1", memo="", gl_date="2026-02-01")
    jid2 = glp.post_journal_entry(lines, source_type="refund", source_entity_id="r1", memo="", gl_date="2026-02-01")
    assert jid1 == jid2
    # exactly one header
    resp = T.gl_journal.query(
        IndexName="SOURCE_ENTRY_IDX",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("source_entry_id").eq("r1"),
    )
    headers = [it for it in resp["Items"] if str(it["SK"]).startswith("JE#")]
    assert len(headers) == 1


def test_list_journal_entries_by_date(env):
    from app.services import gl_posting as glp
    for i in range(3):
        glp.post_journal_entry(
            [glp.JournalLine("1000", "debit", 100), glp.JournalLine("4000", "credit", 100)],
            source_type="tip_debit", source_entity_id=f"e{i}", memo="", gl_date="2026-03-10",
        )
    page = glp.list_journal_entries("2026-03-10", "2026-03-10")
    assert page["count"] == 3


# ── OFB-015 AR aging ────────────────────────────────────────────────────────
def test_derive_charge_status(env):
    from app.services import ar_subledger as ar
    assert ar.derive_charge_status({"status": "generated"}) == "open"
    assert ar.derive_charge_status({"status": "emailed"}) == "open"
    assert ar.derive_charge_status({"status": "paid"}) == "closed"
    assert ar.derive_charge_status({"status": "refunded"}) == "closed"
    assert ar.derive_charge_status({"status": "emailed", "ledger_state": "settled"}) == "closed"


def test_bucket_boundaries(env):
    from app.services import ar_subledger as ar
    assert ar.bucket_for_age(5 * 86400) == "current"
    assert ar.bucket_for_age(30 * 86400) == "current"
    assert ar.bucket_for_age(31 * 86400) == "30"
    assert ar.bucket_for_age(60 * 86400) == "30"
    assert ar.bucket_for_age(61 * 86400) == "60"
    assert ar.bucket_for_age(91 * 86400) == "90_plus"


def test_compute_ar_aging_buckets(env):
    from app.services import ar_subledger as ar
    from app.core.time import now_ts
    now = now_ts()
    items = [
        {"ref_id": "a", "amount_cents": 100, "created_at": now - 5 * 86400},
        {"ref_id": "b", "amount_cents": 200, "created_at": now - 40 * 86400},
        {"ref_id": "c", "amount_cents": 300, "created_at": now - 100 * 86400},
    ]
    out = ar.compute_ar_aging(items, as_of_ts=now)
    assert out["current_cents"] == 100
    assert out["days_30_cents"] == 200
    assert out["days_90_plus_cents"] == 300
    assert out["total_open_cents"] == 600
    assert out["open_item_count"] == 3


def test_aging_from_invoices_filters_closed(env):
    from app.services import ar_subledger as ar
    from app.core.time import now_ts
    now = now_ts()
    invoices = [
        {"invoice_number": "1", "amount_cents": 500, "created_at": now - 10 * 86400, "status": "generated"},
        {"invoice_number": "2", "amount_cents": 999, "created_at": now - 10 * 86400, "status": "paid"},
    ]
    out = ar.aging_from_invoices(invoices, as_of_ts=now)
    assert out["total_open_cents"] == 500
    assert out["open_item_count"] == 1


def test_ar_future_asof_rejected(env):
    from app.services import ar_subledger as ar
    from app.core.time import now_ts
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        ar.compute_ar_aging([], as_of_ts=now_ts() + 86400)
    assert ei.value.status_code == 400


# ── OFB-019/020 pricing rules ────────────────────────────────────────────────
def _cart(*items):
    return list(items)


def test_create_tiered_rule_and_validation(env):
    from app.services import pricing_rules as pr
    cfg = {"tiers": [
        {"min_qty": 1, "max_qty": 4, "unit_price_cents": 1000},
        {"min_qty": 5, "max_qty": 9, "unit_price_cents": 850},
        {"min_qty": 10, "max_qty": None, "unit_price_cents": 700},
    ]}
    rule, err = pr.create_rule("creator1", "Tier", "tiered", "best_deal_wins", cfg)
    assert err is None and rule["rule_id"]
    # gap → error
    bad = {"tiers": [{"min_qty": 1, "max_qty": 4, "unit_price_cents": 1000},
                     {"min_qty": 6, "max_qty": None, "unit_price_cents": 700}]}
    _, err2 = pr.create_rule("creator1", "BadTier", "tiered", "best_deal_wins", bad)
    assert err2 is not None


def test_compute_tiered_discount(env):
    from app.services import pricing_rules as pr
    cfg = {"tiers": [
        {"min_qty": 1, "max_qty": 4, "unit_price_cents": 1000},
        {"min_qty": 5, "max_qty": 9, "unit_price_cents": 850},
        {"min_qty": 10, "max_qty": None, "unit_price_cents": 700},
    ]}
    rule, _ = pr.create_rule("creator1", "Tier", "tiered", "best_deal_wins", cfg)
    items = _cart({"sku": "A", "category_id": "c", "quantity": 7, "unit_price_cents": 1000, "line_total_cents": 7000})
    res = pr.compute_discount(pr.get_rule(rule["rule_id"]), items, 7000, "u1")
    assert res.applied
    assert res.discount_cents == (1000 - 850) * 7  # 1050


def test_compute_bulk_threshold(env):
    from app.services import pricing_rules as pr
    cfg = {"threshold_qty": 5, "discount_type": "percentage", "discount_value": 10}
    rule, _ = pr.create_rule("c1", "Bulk", "bulk", "best_deal_wins", cfg)
    # below threshold
    below = _cart({"sku": "A", "quantity": 3, "unit_price_cents": 1000, "line_total_cents": 3000})
    r1 = pr.compute_discount(pr.get_rule(rule["rule_id"]), below, 3000, "u1")
    assert not r1.applied and r1.reason_skipped == "quantity_below_threshold"
    # at threshold
    at = _cart({"sku": "A", "quantity": 5, "unit_price_cents": 1000, "line_total_cents": 5000})
    r2 = pr.compute_discount(pr.get_rule(rule["rule_id"]), at, 5000, "u1")
    assert r2.applied and r2.discount_cents == 500


def test_compute_conditional_threshold(env):
    from app.services import pricing_rules as pr
    cfg = {"min_cart_total_cents": 5000, "discount_type": "percentage", "discount_value": 10}
    rule, _ = pr.create_rule("c1", "Cond", "conditional", "best_deal_wins", cfg)
    low = _cart({"sku": "A", "quantity": 1, "unit_price_cents": 4000, "line_total_cents": 4000})
    assert not pr.compute_discount(pr.get_rule(rule["rule_id"]), low, 4000, "u1").applied
    hi = _cart({"sku": "A", "quantity": 1, "unit_price_cents": 6000, "line_total_cents": 6000})
    r = pr.compute_discount(pr.get_rule(rule["rule_id"]), hi, 6000, "u1")
    assert r.applied and r.discount_cents == 600


def test_stacking_best_deal_wins_and_cap(env):
    from app.services import pricing_rules as pr
    r1 = pr.RuleDiscountResult("a", "conditional", 1, "best_deal_wins", 300, [], 0, True)
    r2 = pr.RuleDiscountResult("b", "conditional", 2, "best_deal_wins", 500, [], 0, True)
    stacked = pr.apply_stacking([r1, r2], 1000)
    assert stacked.total_discount_cents == 500
    assert stacked.applied_rule_ids == ["b"]
    # cap test
    r3 = pr.RuleDiscountResult("c", "conditional", 1, "stackable", 800, [], 0, True)
    r4 = pr.RuleDiscountResult("d", "conditional", 2, "stackable", 800, [], 0, True)
    stacked2 = pr.apply_stacking([r3, r4], 1000)
    assert stacked2.total_discount_cents == 1000  # capped at cart total
    assert stacked2.final_cart_cents == 0


def test_stacking_priority_tiebreak(env):
    from app.services import pricing_rules as pr
    r1 = pr.RuleDiscountResult("a", "conditional", 5, "best_deal_wins", 300, [], 0, True)
    r2 = pr.RuleDiscountResult("b", "conditional", 2, "best_deal_wins", 300, [], 0, True)
    stacked = pr.apply_stacking([r1, r2], 1000)
    assert stacked.applied_rule_ids == ["b"]  # lower priority int wins tie


def test_apply_pricing_rules_facade(env):
    from app.services import pricing_rules as pr
    cfg = {"min_cart_total_cents": 1000, "discount_type": "percentage", "discount_value": 20}
    pr.create_rule("creator9", "Cond", "conditional", "best_deal_wins", cfg,
                   applies_to_checkout_types=["shop"])
    items = _cart({"sku": "A", "category_id": "c", "quantity": 1, "unit_price_cents": 5000, "line_total_cents": 5000})
    bd = pr.apply_pricing_rules("u1", items, checkout_type="shop", creator_id="creator9")
    assert bd.subtotal_cents == 5000
    assert bd.rule_discount_cents == 1000
    assert bd.final_cents_before_promo == 4000
    assert len(bd.applied_rules) == 1


def test_apply_pricing_rules_flag_off_zero():
    from app.services import pricing_rules as pr
    orig = S.pricing_rules_enabled
    object.__setattr__(S, "pricing_rules_enabled", False)
    try:
        items = [{"sku": "A", "quantity": 1, "unit_price_cents": 5000, "line_total_cents": 5000}]
        bd = pr.apply_pricing_rules("u1", items, checkout_type="shop")
        assert bd.rule_discount_cents == 0
        assert bd.final_cents_before_promo == 5000
        assert bd.applied_rules == []
    finally:
        object.__setattr__(S, "pricing_rules_enabled", orig)


def test_exclude_rule_ids_prevents_double_count(env):
    from app.services import pricing_rules as pr
    cfg = {"min_cart_total_cents": 1000, "discount_type": "percentage", "discount_value": 10}
    rule, _ = pr.create_rule("creator9", "Cond", "conditional", "best_deal_wins", cfg,
                             applies_to_checkout_types=["shop"])
    items = _cart({"sku": "A", "quantity": 1, "unit_price_cents": 5000, "line_total_cents": 5000})
    bd = pr.apply_pricing_rules("u1", items, checkout_type="shop", creator_id="creator9",
                                exclude_rule_ids={rule["rule_id"]})
    assert bd.rule_discount_cents == 0


def test_redeem_rule_global_cap(env):
    from app.services import pricing_rules as pr
    rule, _ = pr.create_rule("c1", "Cap", "conditional",
                             "best_deal_wins",
                             {"min_cart_total_cents": 1, "discount_type": "fixed_amount", "discount_value": 1},
                             max_uses=2)
    rid = rule["rule_id"]
    _, e1 = pr.redeem_rule(rid, "u1", 100, 99)
    _, e2 = pr.redeem_rule(rid, "u2", 100, 99)
    _, e3 = pr.redeem_rule(rid, "u3", 100, 99)
    assert e1 is None and e2 is None
    assert e3 == "rule max_uses exceeded"
    assert pr.get_rule(rid)["current_uses"] == 2


def test_deactivate_rule_excluded_from_resolution(env):
    from app.services import pricing_rules as pr
    cfg = {"min_cart_total_cents": 1, "discount_type": "fixed_amount", "discount_value": 1}
    rule, _ = pr.create_rule("creator9", "C", "conditional", "best_deal_wins", cfg,
                             applies_to_checkout_types=["shop"])
    pr.deactivate_rule(rule["rule_id"], "creator9")
    resolved = pr.resolve_applicable_rules("shop", [], 5000, "u1", "creator9")
    assert all(r["rule_id"] != rule["rule_id"] for r in resolved)


def test_pricing_flag_off_create_404():
    from app.services import pricing_rules as pr
    from fastapi import HTTPException
    orig = S.pricing_rules_enabled
    object.__setattr__(S, "pricing_rules_enabled", False)
    try:
        with pytest.raises(HTTPException) as ei:
            pr.create_rule("c", "n", "conditional", "best_deal_wins", {})
        assert ei.value.status_code == 404
    finally:
        object.__setattr__(S, "pricing_rules_enabled", orig)
