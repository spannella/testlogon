from __future__ import annotations

from app.services.entitlements_service import EntitlementsService, InMemoryEntitlementsRepository
from app.services import payment_reconciliation as pr


def _seed_order(repo: InMemoryEntitlementsRepository, order_id: str, *, user_id: str = "u1") -> None:
    repo.orders[order_id] = {"order_id": order_id, "user_id": user_id, "status": "paid", "created_by": "tester"}
    repo.order_items[order_id] = [
        {
            "sku": "api-pro",
            "product_type": "api_package",
            "scope": {"allowed_actions": ["request_units"], "resource": {}},
            "usage_limit": 5,
        }
    ]


def test_webhook_success_grants_and_is_idempotent(monkeypatch) -> None:
    ent_repo = InMemoryEntitlementsRepository()
    _seed_order(ent_repo, "ord-1", user_id="u-success")
    svc = EntitlementsService(ent_repo)
    rec = pr.InMemoryPaymentReconciliationRepository()
    pay = pr.PaymentWebhookReconciliationService(repository=rec, entitlements=svc)

    events = []
    monkeypatch.setattr(pr, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))

    payload = {
        "id": "evt_1",
        "type": "payment_intent.succeeded",
        "created": 1771527000,
        "data": {"object": {"metadata": {"order_id": "ord-1"}}},
    }
    first = pay.process_webhook_event(provider="stripe", payload=payload)
    second = pay.process_webhook_event(provider="stripe", payload=payload)

    assert first["status"] == "processed"
    assert first["action"] == "granted"
    assert second["status"] == "duplicate"
    assert len(ent_repo.entitlements) == 1
    assert any(a[0][0] == "payment_webhook_entitlement_link" for a in events)


def test_webhook_failure_revokes_active_entitlements() -> None:
    ent_repo = InMemoryEntitlementsRepository()
    _seed_order(ent_repo, "ord-2", user_id="u-fail")
    svc = EntitlementsService(ent_repo)
    grant = svc.grant_entitlement("ord-2")
    assert grant and grant[0].status == "active"

    rec = pr.InMemoryPaymentReconciliationRepository()
    pay = pr.PaymentWebhookReconciliationService(repository=rec, entitlements=svc)
    payload = {
        "id": "evt_2",
        "type": "charge.refunded",
        "created": 1771527001,
        "data": {"object": {"metadata": {"order_id": "ord-2"}}},
    }
    out = pay.process_webhook_event(provider="stripe", payload=payload)
    assert out["status"] == "processed"
    assert out["action"] == "revoked"
    assert all(e.status == "revoked" for e in ent_repo.entitlements.values())


def test_dead_letter_and_replay_deterministic() -> None:
    ent_repo = InMemoryEntitlementsRepository()
    _seed_order(ent_repo, "ord-3", user_id="u-replay")
    svc = EntitlementsService(ent_repo)
    rec = pr.InMemoryPaymentReconciliationRepository()
    pay = pr.PaymentWebhookReconciliationService(repository=rec, entitlements=svc)

    payload = {
        "id": "evt_3",
        "type": "payment_intent.succeeded",
        "created": 1771527002,
        "data": {"object": {"metadata": {"order_id": "ord-3"}}},
    }

    original_grant = svc.grant_entitlement

    def flaky_grant(order_id: str):
        if not getattr(flaky_grant, "done", False):
            flaky_grant.done = True
            raise RuntimeError("transient failure")
        return original_grant(order_id)

    svc.grant_entitlement = flaky_grant  # type: ignore[assignment]

    first = pay.process_webhook_event(provider="stripe", payload=payload)
    assert first["status"] == "dead_lettered"
    assert len(rec.dead_letters) == 1

    replay = pay.replay_dead_letters()
    assert replay["replayed"] == 1
    assert replay["processed"] == 1
    assert replay["failed"] == 0

    # deterministic final state: further deliveries dedupe
    again = pay.process_webhook_event(provider="stripe", payload=payload)
    assert again["status"] == "duplicate"


def test_paypal_normalization_success_path() -> None:
    ent_repo = InMemoryEntitlementsRepository()
    _seed_order(ent_repo, "ord-4", user_id="u-paypal")
    svc = EntitlementsService(ent_repo)
    rec = pr.InMemoryPaymentReconciliationRepository()
    pay = pr.PaymentWebhookReconciliationService(repository=rec, entitlements=svc)

    payload = {
        "id": "WH-123",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "create_time": "2026-01-01T00:00:00Z",
        "resource": {"custom_id": "ord-4"},
    }
    out = pay.process_webhook_event(provider="paypal", payload=payload)
    assert out["status"] == "processed"
    assert out["action"] == "granted"
