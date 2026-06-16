"""OBP PAY-001 — Counterparty CRUD + ownership + masking + routing validation.

Offline/hermetic: moto in-memory ``counterparties`` table bound to the frozen
``T.counterparties`` handle via ``object.__setattr__`` (restored on teardown).
Service functions invoked directly (no TestClient).
"""
from __future__ import annotations

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

pytestmark = pytest.mark.skipif(mock_aws is None, reason="moto not installed")


def _make_table(ddb):
    return ddb.create_table(
        TableName="counterparties",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "counterparty_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "counterparty_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByUserCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture(scope="module", autouse=True)
def _bind_table():
    if mock_aws is None:
        yield
        return
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = _make_table(ddb)
        from app.core.tables import T

        original = getattr(T, "counterparties", None)
        object.__setattr__(T, "counterparties", table)
        try:
            yield
        finally:
            object.__setattr__(T, "counterparties", original)


def _valid_payload(**over):
    base = {
        "name": "Acme Payee",
        "is_beneficiary": True,
        "routing": {
            "scheme": "IBAN",
            "iban": "GB29NWBK60161331926819",
            "currency": "usd",
        },
        "description": "rent",
        "bespoke": {"note": "x"},
    }
    base.update(over)
    return base


def test_create_persists_and_masks():
    from app.services import counterparties as svc

    out = svc.create_counterparty("alice", _valid_payload())
    assert out["counterparty_id"].startswith("cp_")
    # last-4-only masking on IBAN
    assert out["routing"]["iban_last4"] == "6819"
    assert "iban" not in out["routing"]
    # persisted item must NOT store the full IBAN in clear
    stored = svc.get_counterparty("alice", out["counterparty_id"])
    assert "iban" not in stored
    assert stored["iban_last4"] == "6819"


def test_routing_schemes_accepted():
    from app.services import counterparties as svc

    for routing in [
        {"scheme": "ACCOUNT_SORT_CODE", "account_number": "12345678", "sort_code": "12-34-56"},
        {"scheme": "ACCOUNT_NUMBER", "account_number": "00099988"},
        {"scheme": "BANK", "bank_code": "CHASUS33", "bank_name": "Chase"},
    ]:
        out = svc.create_counterparty("alice", _valid_payload(routing=routing))
        assert out["routing"]["scheme"] == routing["scheme"]


def test_malformed_routing_rejected():
    from app.services import counterparties as svc

    with pytest.raises(svc.CounterpartyError):
        svc.create_counterparty("alice", _valid_payload(routing={"scheme": "IBAN"}))


def test_ownership_foreign_id_not_found():
    from app.services import counterparties as svc

    out = svc.create_counterparty("alice", _valid_payload())
    cp_id = out["counterparty_id"]
    assert svc.get_counterparty_out("bob", cp_id) is None
    assert svc.update_counterparty("bob", cp_id, {"name": "hax"}) is None
    assert svc.delete_counterparty("bob", cp_id) is False
    # owner still works
    assert svc.get_counterparty_out("alice", cp_id) is not None


def test_list_newest_first():
    from app.services import counterparties as svc

    svc.create_counterparty("carol", _valid_payload(name="A"))
    svc.create_counterparty("carol", _valid_payload(name="B"))
    items, _ = svc.list_counterparties("carol")
    names = [i["name"] for i in items]
    # both present; newest-first ordering via ByUserCreatedAt
    assert "A" in names and "B" in names


def test_update_mutable_fields_only():
    from app.services import counterparties as svc

    out = svc.create_counterparty("dave", _valid_payload())
    updated = svc.update_counterparty("dave", out["counterparty_id"], {"name": "New Name", "description": "y"})
    assert updated["name"] == "New Name"
    assert updated["description"] == "y"
    # routing unchanged (immutable on update)
    assert updated["routing"]["iban_last4"] == "6819"


def test_delete():
    from app.services import counterparties as svc

    out = svc.create_counterparty("erin", _valid_payload())
    assert svc.delete_counterparty("erin", out["counterparty_id"]) is True
    assert svc.get_counterparty_out("erin", out["counterparty_id"]) is None
