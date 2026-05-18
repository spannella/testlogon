from __future__ import annotations

from types import SimpleNamespace

from app.services import purchase_history


class _FakeTransactionsTable:
    def __init__(self):
        self.put_calls = []

    def query(self, **kwargs):
        return {"Items": []}

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)
        return {}


def test_create_transaction_replays_existing_idempotency_key(monkeypatch):
    existing = {"txn_id": "txn_existing", "status": "PENDING", "created_at": 123}
    monkeypatch.setattr(purchase_history, "_fetch_txn_by_idempotency_key", lambda _user, _idem: existing)

    fake = _FakeTransactionsTable()
    monkeypatch.setattr(purchase_history, "T", SimpleNamespace(purchase_transactions=fake, purchase_events=SimpleNamespace(put_item=lambda **_kwargs: {})))

    out = purchase_history.create_transaction(
        "u1",
        {"money": {"amount": 1.0, "currency": "USD"}},
        idempotency_key="idem-1",
    )

    assert out == {"txn_id": "txn_existing", "status": "PENDING", "created_at": 123}
    assert fake.put_calls == []
