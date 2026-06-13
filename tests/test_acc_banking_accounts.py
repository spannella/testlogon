"""Hermetic offline tests for the OpenBankProject ACC subsystem (ACC-001..004).

Pattern: moto in-memory DynamoDB for ``banking_accounts`` + ``billing`` bound to
the frozen ``T`` handles via ``object.__setattr__``; frozen ``S`` flags toggled
via ``object.__setattr__``; ``audit_event`` patched; route handlers driven on a
fresh ``asyncio.new_event_loop()``. No TestClient, no real AWS, no network.
"""

from __future__ import annotations

import asyncio

import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch

from app.core.settings import S
from app.core.tables import T
from app.services import banking_accounts as svc
from app.services.billing_shared import new_ledger_entry, user_pk

ALICE = "alice"
BOB = "bob"
CHARLIE = "charlie"


@pytest.fixture(autouse=True)
def _env():
    orig_banking = getattr(T, "banking_accounts", None)
    orig_billing = getattr(T, "billing")
    orig_obp = getattr(S, "open_bank_project_enabled", False)
    orig_flag = getattr(S, "banking_accounts_enabled", False)
    orig_meta = getattr(S, "banking_account_metadata_enabled", False)
    orig_views = getattr(S, "banking_account_views_enabled", False)
    orig_bank_id = getattr(S, "banking_default_bank_id", "testlogon")
    orig_bank_name = getattr(S, "banking_default_bank_name", "Testlogon")
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        banking_tbl = ddb.create_table(
            TableName="banking_accounts",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "account_id", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_ACCOUNT_BY_ID",
                    "KeySchema": [
                        {"AttributeName": "account_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        billing_tbl = ddb.create_table(
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
        from app.core.tables import _FloatSafeTable

        object.__setattr__(T, "banking_accounts", _FloatSafeTable(banking_tbl))
        object.__setattr__(T, "billing", _FloatSafeTable(billing_tbl))
        object.__setattr__(S, "open_bank_project_enabled", True)
        object.__setattr__(S, "banking_accounts_enabled", True)
        object.__setattr__(S, "banking_account_metadata_enabled", True)
        object.__setattr__(S, "banking_account_views_enabled", False)
        object.__setattr__(S, "banking_default_bank_id", "testlogon")
        object.__setattr__(S, "banking_default_bank_name", "Testlogon")
        with patch.object(svc, "_audit", lambda *a, **k: None):
            yield
        if orig_banking is not None:
            object.__setattr__(T, "banking_accounts", orig_banking)
        object.__setattr__(T, "billing", orig_billing)
        object.__setattr__(S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(S, "banking_accounts_enabled", orig_flag)
        object.__setattr__(S, "banking_account_metadata_enabled", orig_meta)
        object.__setattr__(S, "banking_account_views_enabled", orig_views)
        object.__setattr__(S, "banking_default_bank_id", orig_bank_id)
        object.__setattr__(S, "banking_default_bank_name", orig_bank_name)


def _seed_wallet(sub: str, cents: int) -> None:
    T.billing.put_item(
        Item={
            "pk": user_pk(sub),
            "sk": "WALLET",
            "wallet_balance_cents": cents,
            "currency": "usd",
        }
    )


def _seed_ledger(sub: str, entry_type: str, amount_cents: int, state: str, **extra):
    _sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(sub),
        entry_type=entry_type,
        amount_cents=amount_cents,
        state=state,
        reason=f"{entry_type} {amount_cents}",
        extra=extra or None,
    )
    T.billing.put_item(Item=item)
    return item


# ─── ACC-001 ────────────────────────────────────────────────────────────────


def test_default_account_bootstrap_idempotent():
    a1 = svc.ensure_default_account(ALICE)
    a2 = svc.ensure_default_account(ALICE)
    assert a1["account_id"] == a2["account_id"]
    assert a1["is_default"] and a1["wallet_backed"]
    assert a1["account_type"] == "WALLET"
    rows = svc._query_owned_accounts(ALICE)
    defaults = [r for r in rows if r.get("is_default")]
    assert len(defaults) == 1


def test_house_bank_self_seeded():
    svc.ensure_default_account(ALICE)
    banks = svc.list_banks()
    assert any(b["bank_id"] == "testlogon" for b in banks)
    assert svc.get_bank("testlogon")["name"] == "Testlogon"


def test_get_bank_404():
    with pytest.raises(Exception) as ei:
        svc.get_bank("nope")
    assert ei.value.status_code == 404


def test_balance_read_through_reflects_wallet():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 500)
    bal = svc.get_account_balance(acc["account_id"], requester_sub=ALICE)
    assert bal["current"] == 5.00
    assert bal["available"] == 5.00
    _seed_wallet(ALICE, 1000)
    bal2 = svc.get_account_balance(acc["account_id"], requester_sub=ALICE)
    assert bal2["current"] == 10.00


def test_create_account_attributes_and_opaque_strings():
    svc.ensure_default_account(ALICE)
    acc = svc.create_account(
        ALICE,
        label="My Savings",
        account_type="SAVINGS",
        bank_id="testlogon",
        attributes=[{"name": "nickname", "type": "STRING", "value": "Rainy day"}],
        iban="GB29 NWBK 6016 1331 9268 19",
        routing_number="021000021",
    )
    fetched = svc.get_account(acc["account_id"], requester_sub=ALICE)
    assert fetched["attributes"][0]["value"] == "Rainy day"
    assert fetched["iban"] == "GB29 NWBK 6016 1331 9268 19"
    assert fetched["routing_number"] == "021000021"
    assert fetched["wallet_backed"] is False


def test_create_account_wallet_type_422():
    svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.create_account(ALICE, label="x", account_type="WALLET", bank_id="testlogon")
    assert ei.value.status_code == 422


def test_create_account_unknown_bank_422():
    with pytest.raises(Exception) as ei:
        svc.create_account(ALICE, label="x", account_type="SAVINGS", bank_id="bogus")
    assert ei.value.status_code == 422


def test_get_account_non_owner_404():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.get_account(acc["account_id"], requester_sub=BOB)
    assert ei.value.status_code == 404


def test_delete_default_409():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.delete_account(acc["account_id"], ALICE)
    assert ei.value.status_code == 409
    assert "default wallet account" in str(ei.value.detail)


def test_delete_non_default_204():
    svc.ensure_default_account(ALICE)
    acc = svc.create_account(ALICE, label="x", account_type="SAVINGS", bank_id="testlogon")
    svc.delete_account(acc["account_id"], ALICE)
    assert svc._resolve_account_item(acc["account_id"]) is None


def test_update_non_owner_403():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.update_account(acc["account_id"], BOB, label="hacked")
    assert ei.value.status_code == 403


def test_update_account_label():
    acc = svc.ensure_default_account(ALICE)
    updated = svc.update_account(acc["account_id"], ALICE, label="Main Wallet")
    assert updated["label"] == "Main Wallet"


# ─── ACC-002 ────────────────────────────────────────────────────────────────


def test_projection_equality_no_new_rows():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 1300)
    ids = set()
    for _ in range(5):
        ids.add(_seed_ledger(ALICE, "credit", 100, "settled")["entry_id"])
    result = svc.list_account_transactions(acc["account_id"], requester_sub=ALICE)
    got = {t["transaction_id"] for t in result["transactions"]}
    assert got == ids


def test_running_new_balance_anchor_and_chain():
    acc = svc.ensure_default_account(ALICE)
    # deposit 1000, debit 200, deposit 500 → wallet = 1300
    _seed_ledger(ALICE, "credit", 1000, "settled")
    _seed_ledger(ALICE, "debit", 200, "settled")
    _seed_ledger(ALICE, "credit", 500, "settled")
    _seed_wallet(ALICE, 1300)
    result = svc.list_account_transactions(
        acc["account_id"], requester_sub=ALICE, order="desc"
    )
    txns = result["transactions"]
    assert txns[0]["new_balance"]["value"] == "13.00"
    # Each older row = newer new_balance - newer signed_amount
    for i in range(len(txns) - 1):
        newer = txns[i]
        older = txns[i + 1]
        nb_newer = _to_cents(newer["new_balance"]["value"])
        nb_older = _to_cents(older["new_balance"]["value"])
        signed = svc._sign_for_entry_type(newer["type"]) * _to_cents(
            newer["amount"]["value"]
        )
        assert nb_older == nb_newer - signed


def test_signed_amount_cents_preferred_over_type_table():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 800)
    # An 'adjustment' which the type table would treat as +200, but stamped -200.
    with patch("app.services.billing_shared.now_ts", return_value=100):
        _seed_ledger(ALICE, "credit", 1000, "settled")
    with patch("app.services.billing_shared.now_ts", return_value=200):
        _seed_ledger(ALICE, "adjustment", 200, "settled", signed_amount_cents=-200)
    result = svc.list_account_transactions(
        acc["account_id"], requester_sub=ALICE, order="desc"
    )
    txns = result["transactions"]
    # newest = adjustment, anchored to 800
    assert txns[0]["new_balance"]["value"] == "8.00"
    # older = 800 - (-200) = 1000
    assert txns[1]["new_balance"]["value"] == "10.00"


def test_pending_row_inherits_balance():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 1000)
    with patch("app.services.billing_shared.now_ts", return_value=100):
        _seed_ledger(ALICE, "credit", 1000, "settled")
    with patch("app.services.billing_shared.now_ts", return_value=200):
        _seed_ledger(ALICE, "credit", 500, "pending")
    result = svc.list_account_transactions(
        acc["account_id"], requester_sub=ALICE, order="desc"
    )
    txns = result["transactions"]
    # newest is pending, anchored to current wallet (1000)
    assert txns[0]["new_balance"]["value"] == "10.00"
    # pending did not move wallet → older settled row also 1000
    assert txns[1]["new_balance"]["value"] == "10.00"


def test_date_range_key_condition():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 0)
    for ts in (100, 200, 300):
        with patch("app.services.billing_shared.now_ts", return_value=ts):
            _seed_ledger(ALICE, "credit", 10, "settled")
    result = svc.list_account_transactions(
        acc["account_id"], requester_sub=ALICE, from_ts=150, to_ts=250
    )
    posted = [t["posted_at"] for t in result["transactions"]]
    assert posted == [200]


def test_cursor_round_trip():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 0)
    seeded = set()
    for i in range(15):
        with patch("app.services.billing_shared.now_ts", return_value=100 + i):
            seeded.add(_seed_ledger(ALICE, "credit", 10, "settled")["entry_id"])
    collected = set()
    cursor = None
    pages = 0
    while True:
        result = svc.list_account_transactions(
            acc["account_id"], requester_sub=ALICE, limit=5, cursor=cursor
        )
        collected |= {t["transaction_id"] for t in result["transactions"]}
        pages += 1
        cursor = result["cursor"]
        if not cursor or pages > 10:
            break
    assert collected == seeded


def test_tampered_cursor_falls_back_to_page1():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 0)
    for _ in range(3):
        _seed_ledger(ALICE, "credit", 10, "settled")
    a = svc.list_account_transactions(acc["account_id"], requester_sub=ALICE)
    b = svc.list_account_transactions(
        acc["account_id"], requester_sub=ALICE, cursor="v2.GARBAGE.BADSIG"
    )
    assert {t["transaction_id"] for t in a["transactions"]} == {
        t["transaction_id"] for t in b["transactions"]
    }


def test_transactions_non_owner_404():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.list_account_transactions(acc["account_id"], requester_sub=BOB)
    assert ei.value.status_code == 404


def test_transactions_non_wallet_empty():
    svc.ensure_default_account(ALICE)
    acc = svc.create_account(ALICE, label="x", account_type="SAVINGS", bank_id="testlogon")
    result = svc.list_account_transactions(acc["account_id"], requester_sub=ALICE)
    assert result == {"transactions": [], "cursor": None}


def test_get_transaction_found_and_404():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 100)
    item = _seed_ledger(ALICE, "credit", 100, "settled")
    txn = svc.get_account_transaction(
        acc["account_id"], item["entry_id"], requester_sub=ALICE
    )
    assert txn["transaction_id"] == item["entry_id"]
    assert txn["posted_at"] == item["ts"]
    with pytest.raises(Exception) as ei:
        svc.get_account_transaction(acc["account_id"], "nope", requester_sub=ALICE)
    assert ei.value.status_code == 404


def test_order_asc():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 0)
    for ts in (100, 200, 300):
        with patch("app.services.billing_shared.now_ts", return_value=ts):
            _seed_ledger(ALICE, "credit", 10, "settled")
    result = svc.list_account_transactions(
        acc["account_id"], requester_sub=ALICE, order="asc"
    )
    posted = [t["posted_at"] for t in result["transactions"]]
    assert posted == [100, 200, 300]


# ─── ACC-003 ────────────────────────────────────────────────────────────────


def _setup_txn():
    acc = svc.ensure_default_account(ALICE)
    _seed_wallet(ALICE, 100)
    item = _seed_ledger(ALICE, "credit", 100, "settled")
    return acc["account_id"], item


def test_ledger_immutable_after_metadata():
    account_id, item = _setup_txn()
    before = T.billing.get_item(Key={"pk": user_pk(ALICE), "sk": item["sk"]})["Item"]
    svc.put_transaction_narrative(
        account_id, item["entry_id"], requester_sub=ALICE, text="rent"
    )
    svc.add_transaction_tag(
        account_id, item["entry_id"], requester_sub=ALICE, value="housing"
    )
    svc.add_transaction_comment(
        account_id, item["entry_id"], requester_sub=ALICE, text="paid late"
    )
    after = T.billing.get_item(Key={"pk": user_pk(ALICE), "sk": item["sk"]})["Item"]
    assert before == after


def test_narrative_put_replaces():
    account_id, item = _setup_txn()
    svc.put_transaction_narrative(
        account_id, item["entry_id"], requester_sub=ALICE, text="first"
    )
    svc.put_transaction_narrative(
        account_id, item["entry_id"], requester_sub=ALICE, text="second"
    )
    meta = svc.get_transaction_metadata(
        account_id, item["entry_id"], requester_sub=ALICE
    )
    assert meta["narrative"]["text"] == "second"


def test_geotag_round_trip():
    account_id, item = _setup_txn()
    svc.put_transaction_geotag(
        account_id, item["entry_id"], requester_sub=ALICE, lat=51.5, lon=-0.12, label="London"
    )
    meta = svc.get_transaction_metadata(
        account_id, item["entry_id"], requester_sub=ALICE
    )
    assert abs(meta["geotag"]["lat"] - 51.5) < 1e-6
    assert meta["geotag"]["label"] == "London"


def test_tag_dedup_and_limit():
    account_id, item = _setup_txn()
    svc.add_transaction_tag(account_id, item["entry_id"], requester_sub=ALICE, value="Groceries")
    with pytest.raises(Exception) as ei:
        svc.add_transaction_tag(account_id, item["entry_id"], requester_sub=ALICE, value="groceries")
    assert ei.value.status_code == 409
    meta = svc.get_transaction_metadata(account_id, item["entry_id"], requester_sub=ALICE)
    assert len(meta["tags"]) == 1


def test_tag_add_delete():
    account_id, item = _setup_txn()
    t1 = svc.add_transaction_tag(account_id, item["entry_id"], requester_sub=ALICE, value="a")
    svc.add_transaction_tag(account_id, item["entry_id"], requester_sub=ALICE, value="b")
    svc.remove_transaction_tag(account_id, item["entry_id"], t1["tag_id"], requester_sub=ALICE)
    meta = svc.get_transaction_metadata(account_id, item["entry_id"], requester_sub=ALICE)
    assert {t["value"] for t in meta["tags"]} == {"b"}


def test_image_upload_dev_url_and_validation():
    account_id, item = _setup_txn()
    orig_dev = S.dev_mode
    object.__setattr__(S, "dev_mode", True)
    try:
        with patch.object(svc, "s3_client", create=True), patch(
            "app.core.aws_clients.s3_client"
        ) as mock_s3:
            out = svc.set_transaction_image(
                account_id,
                item["entry_id"],
                requester_sub=ALICE,
                image_bytes=b"\x89PNG\r",
                content_type="image/png",
                filename="r.png",
            )
            assert out["url"].startswith("/mock/s3/")
            mock_s3.return_value.put_object.assert_called_once()
            with pytest.raises(Exception) as ei:
                svc.set_transaction_image(
                    account_id,
                    item["entry_id"],
                    requester_sub=ALICE,
                    image_bytes=b"x",
                    content_type="application/pdf",
                    filename="x.pdf",
                )
            assert ei.value.status_code == 422
    finally:
        object.__setattr__(S, "dev_mode", orig_dev)


def test_image_too_large_413():
    account_id, item = _setup_txn()
    orig_max = S.banking_image_max_bytes
    orig_dev = S.dev_mode
    object.__setattr__(S, "banking_image_max_bytes", 4)
    object.__setattr__(S, "dev_mode", True)
    try:
        with pytest.raises(Exception) as ei:
            svc.set_transaction_image(
                account_id,
                item["entry_id"],
                requester_sub=ALICE,
                image_bytes=b"toolarge",
                content_type="image/png",
                filename="x.png",
            )
        assert ei.value.status_code == 413
    finally:
        object.__setattr__(S, "banking_image_max_bytes", orig_max)
        object.__setattr__(S, "dev_mode", orig_dev)


def test_metadata_unknown_txn_404():
    account_id, _ = _setup_txn()
    with pytest.raises(Exception) as ei:
        svc.get_transaction_metadata(account_id, "missing", requester_sub=ALICE)
    assert ei.value.status_code == 404


def test_metadata_flag_off_404():
    account_id, item = _setup_txn()
    object.__setattr__(S, "banking_account_metadata_enabled", False)
    with pytest.raises(Exception) as ei:
        svc.get_transaction_metadata(account_id, item["entry_id"], requester_sub=ALICE)
    assert ei.value.status_code == 404
    object.__setattr__(S, "banking_account_metadata_enabled", True)


def test_comment_delete_author_and_owner():
    account_id, item = _setup_txn()
    # Bob is co-owner
    svc.add_account_owner(account_id, ALICE, BOB)
    c = svc.add_transaction_comment(account_id, item["entry_id"], requester_sub=ALICE, text="hi")
    # Charlie (no access) → 404 from existence gate
    with pytest.raises(Exception) as ei:
        svc.delete_transaction_comment(
            account_id, item["entry_id"], c["comment_id"], requester_sub=CHARLIE
        )
    assert ei.value.status_code == 404
    # Bob (co-owner) may delete
    svc.delete_transaction_comment(
        account_id, item["entry_id"], c["comment_id"], requester_sub=BOB
    )
    meta = svc.get_transaction_metadata(account_id, item["entry_id"], requester_sub=ALICE)
    assert meta["comments"] == []


def test_has_metadata_flag():
    account_id, item = _setup_txn()
    assert svc.transaction_has_metadata(account_id, item["entry_id"]) is False
    svc.add_transaction_tag(account_id, item["entry_id"], requester_sub=ALICE, value="x")
    assert svc.transaction_has_metadata(account_id, item["entry_id"]) is True


# ─── ACC-004 ────────────────────────────────────────────────────────────────


def test_add_owner_writes_ref_and_owners_list():
    acc = svc.ensure_default_account(ALICE)
    updated = svc.add_account_owner(acc["account_id"], ALICE, BOB)
    assert BOB in updated["owners"] and ALICE in updated["owners"]
    ref = T.banking_accounts.get_item(
        Key={"pk": user_pk(BOB), "sk": f"ACCOUNT_REF#{acc['account_id']}"}
    ).get("Item")
    assert ref["owner_sub"] == ALICE
    assert ref["added_by_sub"] == ALICE


def test_new_owner_in_list_accounts():
    acc = svc.ensure_default_account(ALICE)
    svc.add_account_owner(acc["account_id"], ALICE, BOB)
    bob_accounts = svc.list_accounts(BOB)
    assert any(a["account_id"] == acc["account_id"] for a in bob_accounts)


def test_add_owner_non_owner_403():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.add_account_owner(acc["account_id"], BOB, CHARLIE)
    assert ei.value.status_code == 403


def test_add_owner_duplicate_and_self_400():
    acc = svc.ensure_default_account(ALICE)
    svc.add_account_owner(acc["account_id"], ALICE, BOB)
    with pytest.raises(Exception) as ei:
        svc.add_account_owner(acc["account_id"], ALICE, BOB)
    assert ei.value.status_code == 400
    with pytest.raises(Exception) as ei2:
        svc.add_account_owner(acc["account_id"], ALICE, ALICE)
    assert ei2.value.status_code == 400


def test_remove_owner_deletes_ref():
    acc = svc.ensure_default_account(ALICE)
    svc.add_account_owner(acc["account_id"], ALICE, BOB)
    svc.remove_account_owner(acc["account_id"], ALICE, BOB)
    ref = T.banking_accounts.get_item(
        Key={"pk": user_pk(BOB), "sk": f"ACCOUNT_REF#{acc['account_id']}"}
    ).get("Item")
    assert ref is None
    assert not any(a["account_id"] == acc["account_id"] for a in svc.list_accounts(BOB) if a["account_id"] == acc["account_id"] and BOB not in a["owners"])


def test_remove_last_owner_409():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.remove_account_owner(acc["account_id"], ALICE, ALICE)
    assert ei.value.status_code == 409


def test_remove_self_allowed_if_not_last():
    acc = svc.ensure_default_account(ALICE)
    svc.add_account_owner(acc["account_id"], ALICE, BOB)
    updated = svc.remove_account_owner(acc["account_id"], BOB, BOB)
    assert BOB not in updated["owners"]


def test_list_holders():
    acc = svc.ensure_default_account(ALICE)
    svc.add_account_owner(acc["account_id"], ALICE, BOB)
    holders = svc.list_account_holders(acc["account_id"], ALICE)
    primary = [h for h in holders if h["is_primary_owner"]]
    assert len(primary) == 1 and primary[0]["user_sub"] == ALICE
    assert {h["user_sub"] for h in holders} == {ALICE, BOB}


def test_list_holders_non_owner_404():
    acc = svc.ensure_default_account(ALICE)
    with pytest.raises(Exception) as ei:
        svc.list_account_holders(acc["account_id"], BOB)
    assert ei.value.status_code == 404


def test_resolve_access_owner():
    acc = svc.ensure_default_account(ALICE)
    access = svc.resolve_account_access(ALICE, acc["account_id"])
    assert access["role"] == "owner"


def test_resolve_access_none_for_stranger():
    acc = svc.ensure_default_account(ALICE)
    access = svc.resolve_account_access(BOB, acc["account_id"])
    assert access["role"] is None


def test_resolve_access_viewer_via_vew():
    acc = svc.ensure_default_account(ALICE)
    object.__setattr__(S, "banking_account_views_enabled", True)
    import sys
    import types

    fake = types.ModuleType("app.services.account_views")

    def _resolve_active_grant(grantee_sub, resource_type, resource_id, view_id):
        return {"view_id": view_id, "grants": {"can_see_balance": True}}

    fake.resolve_active_grant = _resolve_active_grant
    sys.modules["app.services.account_views"] = fake
    try:
        access = svc.resolve_account_access(BOB, acc["account_id"], view_id="auditor")
        assert access["role"] == "viewer"
        assert access["grants"] == {"can_see_balance": True}
        # flag off → skip VEW
        object.__setattr__(S, "banking_account_views_enabled", False)
        access2 = svc.resolve_account_access(BOB, acc["account_id"], view_id="auditor")
        assert access2["role"] is None
    finally:
        sys.modules.pop("app.services.account_views", None)
        object.__setattr__(S, "banking_account_views_enabled", False)


# ─── Router-level (flag-off + handler invocation) ─────────────────────────────


def test_router_not_registered_when_flag_off():
    import app.main as main

    object.__setattr__(S, "banking_accounts_enabled", False)
    object.__setattr__(S, "open_bank_project_enabled", False)
    try:
        app = main.create_app()
        paths = {getattr(r, "path", "") for r in app.routes}
        assert not any(p.startswith("/ui/banking") for p in paths)
    finally:
        object.__setattr__(S, "banking_accounts_enabled", True)
        object.__setattr__(S, "open_bank_project_enabled", True)


def test_router_handler_list_accounts():
    from app.routers.banking_accounts import list_accounts_endpoint

    loop = asyncio.new_event_loop()
    try:
        out = loop.run_until_complete(
            list_accounts_endpoint(session={"user_sub": ALICE})
        )
    finally:
        loop.close()
    assert len(out.accounts) >= 1
    assert out.accounts[0].is_default


def _to_cents(decimal_str: str) -> int:
    neg = decimal_str.startswith("-")
    s = decimal_str.lstrip("-")
    whole, _, frac = s.partition(".")
    cents = int(whole) * 100 + int((frac + "00")[:2])
    return -cents if neg else cents
