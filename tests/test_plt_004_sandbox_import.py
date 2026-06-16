"""PLT-004 hermetic unit tests: Sandbox JSON import."""
from __future__ import annotations

import asyncio
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


@pytest.fixture(autouse=True, scope="module")
def _setup_sandbox_tables():
    """Create moto users/profiles/billing tables, bind to T.*, set S flags."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        users_tbl = ddb.create_table(
            TableName="users_test_sb",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        profile_tbl = ddb.create_table(
            TableName="profiles_test_sb",
            KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        billing_tbl = ddb.create_table(
            TableName="billing_test_sb",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "ledger_date", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI_LEDGER_DATE",
                "KeySchema": [
                    {"AttributeName": "ledger_date", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
        )

        for t in [users_tbl, profile_tbl, billing_tbl]:
            t.meta.client.get_waiter("table_exists").wait(TableName=t.name)

        from app.core.tables import T
        from app.core.settings import S

        orig_users = T.users
        orig_profile = T.profile
        orig_billing = T.billing
        orig_obp = S.open_bank_project_enabled
        orig_si = S.sandbox_import_enabled
        orig_dm = S.dev_mode
        orig_max = S.sandbox_import_max_items
        orig_admin = getattr(S, "filemgr_admin_users", "")

        object.__setattr__(T, "users", users_tbl)
        object.__setattr__(T, "profile", profile_tbl)
        object.__setattr__(T, "billing", billing_tbl)
        object.__setattr__(S, "open_bank_project_enabled", True)
        object.__setattr__(S, "sandbox_import_enabled", True)
        object.__setattr__(S, "dev_mode", True)
        object.__setattr__(S, "sandbox_import_max_items", 500)
        object.__setattr__(S, "filemgr_admin_users", "admin_sb_test")

        yield {"users": users_tbl, "profile": profile_tbl, "billing": billing_tbl}

        object.__setattr__(T, "users", orig_users)
        object.__setattr__(T, "profile", orig_profile)
        object.__setattr__(T, "billing", orig_billing)
        object.__setattr__(S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(S, "sandbox_import_enabled", orig_si)
        object.__setattr__(S, "dev_mode", orig_dm)
        object.__setattr__(S, "sandbox_import_max_items", orig_max)
        object.__setattr__(S, "filemgr_admin_users", orig_admin)


def _clear_all(tbls):
    for tbl in tbls.values():
        resp = tbl.scan()
        items = resp.get("Items", [])
        if not items:
            continue
        # Find the PK/SK names
        key_schema = tbl.key_schema
        keys = {ks["AttributeName"] for ks in key_schema}
        with tbl.batch_writer() as batch:
            for item in items:
                batch.delete_item(Key={k: item[k] for k in keys if k in item})


# Test 1: Customers section creates user and profile
def test_customers_creates_user_and_profile(_setup_sandbox_tables):
    tbls = _setup_sandbox_tables
    _clear_all(tbls)

    from app.models import SandboxImportIn, SandboxCustomerIn
    from app.services.sandbox_import import import_sandbox_payload

    payload = SandboxImportIn(customers=[
        SandboxCustomerIn(email="a@b.com", display_name="A Tester"),
    ])
    result = import_sandbox_payload(payload, actor_sub="admin_sb_test")

    assert result.customers_created == 1
    assert result.errors == []
    # Verify user row exists
    resp = tbls["users"].scan()
    items = resp.get("Items", [])
    assert len(items) == 1
    assert items[0]["email"] == "a@b.com"
    assert items[0]["source"] == "sandbox_import"
    # Verify profile row
    presp = tbls["profile"].scan()
    pitems = presp.get("Items", [])
    assert len(pitems) == 1


# Test 2: Duplicate user_sub is row error (not crash)
def test_duplicate_user_sub_is_row_error(_setup_sandbox_tables):
    tbls = _setup_sandbox_tables
    _clear_all(tbls)

    from app.models import SandboxImportIn, SandboxCustomerIn
    from app.services.sandbox_import import import_sandbox_payload

    # Pre-seed the user
    tbls["users"].put_item(Item={"user_sub": "dup123", "email": "old@test.com"})

    payload = SandboxImportIn(customers=[
        SandboxCustomerIn(user_sub="dup123", email="x@y.com"),
    ])
    result = import_sandbox_payload(payload, actor_sub="admin_sb_test")

    assert result.customers_created == 0
    assert len(result.errors) == 1
    assert result.errors[0].code == "duplicate_user_sub"
    assert result.ok is True


# Test 3: Accounts section seeds wallet
def test_accounts_seeds_wallet(_setup_sandbox_tables):
    tbls = _setup_sandbox_tables
    _clear_all(tbls)

    from app.models import SandboxImportIn, SandboxAccountIn
    from app.services.sandbox_import import import_sandbox_payload

    payload = SandboxImportIn(accounts=[
        SandboxAccountIn(user_sub="u_wallet_test", initial_balance_cents=5000, currency="usd"),
    ])
    result = import_sandbox_payload(payload, actor_sub="admin_sb_test")

    assert result.accounts_created == 1
    wallet = tbls["billing"].get_item(Key={"pk": "USER#u_wallet_test", "sk": "WALLET"}).get("Item")
    assert wallet is not None
    assert int(wallet["wallet_balance_cents"]) == 5000


# Test 4: Zero balance creates wallet row
def test_zero_balance_creates_wallet_row(_setup_sandbox_tables):
    tbls = _setup_sandbox_tables
    _clear_all(tbls)

    from app.models import SandboxImportIn, SandboxAccountIn
    from app.services.sandbox_import import import_sandbox_payload

    payload = SandboxImportIn(accounts=[
        SandboxAccountIn(user_sub="u_zero", initial_balance_cents=0),
    ])
    result = import_sandbox_payload(payload, actor_sub="admin_sb_test")

    assert result.accounts_created == 1
    wallet = tbls["billing"].get_item(Key={"pk": "USER#u_zero", "sk": "WALLET"}).get("Item")
    assert wallet is not None
    assert int(wallet["wallet_balance_cents"]) == 0


# Test 5: Transactions section writes ledger row with ledger_date
def test_transactions_write_ledger_row(_setup_sandbox_tables):
    tbls = _setup_sandbox_tables
    _clear_all(tbls)

    from app.models import SandboxImportIn, SandboxTransactionIn
    from app.services.sandbox_import import import_sandbox_payload

    payload = SandboxImportIn(transactions=[
        SandboxTransactionIn(user_sub="u_tx", entry_type="credit", amount_cents=1000, reason="seed"),
    ])
    result = import_sandbox_payload(payload, actor_sub="admin_sb_test")

    assert result.transactions_created == 1
    resp = tbls["billing"].query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": "USER#u_tx", ":prefix": "LEDGER#"},
    )
    items = resp.get("Items", [])
    assert len(items) == 1
    assert items[0].get("ledger_date") is not None
    assert items[0].get("source") == "sandbox_import"


# Test 6: Flag off returns 404
def test_flag_off_returns_404(_setup_sandbox_tables):
    from app.core.settings import S
    from app.routers.sandbox import data_import
    from app.models import SandboxImportIn

    object.__setattr__(S, "sandbox_import_enabled", False)
    try:
        req = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(HTTPException) as exc_info:
                loop.run_until_complete(
                    data_import(body=SandboxImportIn(), req=req, admin_sub="admin_sb_test")
                )
            assert exc_info.value.status_code == 404
        finally:
            loop.close()
    finally:
        object.__setattr__(S, "sandbox_import_enabled", True)


# Test 7: dev_mode off returns 404
def test_dev_mode_off_returns_404(_setup_sandbox_tables):
    from app.core.settings import S
    from app.routers.sandbox import data_import
    from app.models import SandboxImportIn

    object.__setattr__(S, "dev_mode", False)
    try:
        req = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(HTTPException) as exc_info:
                loop.run_until_complete(
                    data_import(body=SandboxImportIn(), req=req, admin_sub="admin_sb_test")
                )
            assert exc_info.value.status_code == 404
        finally:
            loop.close()
    finally:
        object.__setattr__(S, "dev_mode", True)


# Test 8: Section cap truncates rows
def test_section_cap_truncates(_setup_sandbox_tables):
    tbls = _setup_sandbox_tables
    _clear_all(tbls)

    from app.core.settings import S
    from app.models import SandboxImportIn, SandboxCustomerIn
    from app.services.sandbox_import import import_sandbox_payload

    object.__setattr__(S, "sandbox_import_max_items", 2)
    try:
        payload = SandboxImportIn(customers=[
            SandboxCustomerIn(email=f"user{i}@test.com") for i in range(3)
        ])
        result = import_sandbox_payload(payload, actor_sub="admin_sb_test")
        assert result.customers_created == 2
        trunc_errors = [e for e in result.errors if e.code == "section_truncated"]
        assert len(trunc_errors) == 1
        assert trunc_errors[0].index == -1
    finally:
        object.__setattr__(S, "sandbox_import_max_items", 500)


# Test 9: Audit event emitted
def test_audit_event_emitted(_setup_sandbox_tables):
    from app.routers.sandbox import data_import
    from app.models import SandboxImportIn

    req = MagicMock()
    loop = asyncio.new_event_loop()
    try:
        with patch("app.routers.sandbox.audit_event") as mock_audit:
            loop.run_until_complete(
                data_import(body=SandboxImportIn(), req=req, admin_sub="admin_sb_test")
            )
        mock_audit.assert_called_once()
        assert mock_audit.call_args[0][0] == "sandbox_data_import"
    finally:
        loop.close()
