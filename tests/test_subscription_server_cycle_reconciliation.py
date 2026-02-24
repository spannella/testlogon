from __future__ import annotations

import pytest

from app.routers import subscription_server as router


def test_emit_and_reconcile_uses_invoice_identity_and_default_reconciliation(monkeypatch) -> None:
    captured = {}

    def _fake_emit_subscription_cycle_order(**kwargs):
        captured.update(kwargs)
        return {"order_id": "ord-1", "reconciliation": {"status": "processed"}}

    monkeypatch.setattr(router, "emit_subscription_cycle_order", _fake_emit_subscription_cycle_order)

    out = router.emit_subscription_cycle_order_and_reconcile(
        subscription={"subscription_id": "sub-1", "subscriber_id": "u1"},
        plan={"plan_id": "pro"},
        invoice={"provider_invoice_id": "prov-inv-1", "amount_cents": 1000},
    )

    assert out["order_id"] == "ord-1"
    assert captured["enable_default_reconciliation"] is True
    assert captured["invoice"]["invoice_id"] == "prov-inv-1"
    assert captured["invoice"]["provider_invoice_id"] == "prov-inv-1"


def test_emit_and_reconcile_raises_if_reconciliation_skipped(monkeypatch) -> None:
    monkeypatch.setattr(
        router,
        "emit_subscription_cycle_order",
        lambda **kwargs: {"order_id": "ord-1", "reconciliation": {"status": "skipped"}},
    )

    with pytest.raises(RuntimeError):
        router.emit_subscription_cycle_order_and_reconcile(
            subscription={"subscription_id": "sub-1", "subscriber_id": "u1"},
            plan={"plan_id": "pro"},
            invoice={"invoice_id": "inv-1", "amount_cents": 1000},
        )
