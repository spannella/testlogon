from __future__ import annotations

from typing import Any, Dict, List, Tuple

from fastapi.testclient import TestClient

from app.core.tables import T
from app.main import create_app
from app.services.sessions import require_ui_session


class FakeTable:
    def __init__(self) -> None:
        self.items: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def get_item(self, *, Key: Dict[str, str]) -> Dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": item} if item else {}

    def put_item(self, *, Item: Dict[str, Any], **_: Any) -> None:
        self.items[(Item["pk"], Item["sk"])] = Item

    def delete_item(self, *, Key: Dict[str, str]) -> None:
        self.items.pop((Key["pk"], Key["sk"]), None)

    def query(self, *, ExpressionAttributeValues: Dict[str, str], **_: Any) -> Dict[str, List[Dict[str, Any]]]:
        pk = ExpressionAttributeValues[":pk"]
        return {"Items": [item for (item_pk, _), item in self.items.items() if item_pk == pk]}

    def update_item(self, **_: Any) -> None:  # pragma: no cover - not used in these tests
        raise NotImplementedError


def build_client(fake_table: FakeTable) -> TestClient:
    app = create_app()
    app.dependency_overrides[require_ui_session] = lambda: {"user_sub": "user-123", "session_id": "sess-123"}
    object.__setattr__(T, "billing", fake_table)
    return TestClient(app)


def test_billing_balance_initializes() -> None:
    fake_table = FakeTable()
    client = build_client(fake_table)

    resp = client.get("/api/billing/balance")
    assert resp.status_code == 200
    payload = resp.json()

    assert payload["currency"] == "usd"
    assert payload["owed_pending_cents"] == 0
    assert payload["owed_settled_cents"] == 0
    assert payload["payments_pending_cents"] == 0
    assert payload["payments_settled_cents"] == 0
    assert payload["due_settled_cents"] == 0
    assert payload["due_if_all_settles_cents"] == 0

    assert ("USER#user-123", "BALANCE") in fake_table.items


def test_billing_ledger_limit() -> None:
    fake_table = FakeTable()
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "LEDGER#1#A", "ts": 1})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "LEDGER#2#B", "ts": 2})
    fake_table.put_item(Item={"pk": "USER#user-123", "sk": "LEDGER#3#C", "ts": 3})
    client = build_client(fake_table)

    resp = client.get("/api/billing/ledger?limit=1")
    assert resp.status_code == 200
    payload = resp.json()

    assert len(payload["items"]) == 1
    assert payload["items"][0]["sk"] == "LEDGER#3#C"
