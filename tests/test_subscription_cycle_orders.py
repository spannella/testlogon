from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

from app.services import subscription_cycle_orders as svc
from app.services import entitlements_visibility as visibility


class _Table:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(dict(Item))


def test_emit_subscription_cycle_order_writes_canonical_subscription_source(monkeypatch) -> None:
    captured = {}

    def _fake_create_order_from_line_items(**kwargs):
        captured.update(kwargs)
        return {"order_id": "ord-sub-1", "line_items": kwargs["line_items"], "status": "pending_payment"}

    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(svc, "commerce_order_service", SimpleNamespace(create_order_from_line_items=_fake_create_order_from_line_items))

    out = svc.emit_subscription_cycle_order(
        subscription={
            "subscription_id": "sub-1",
            "subscriber_id": "u1",
            "plan_id": "pro",
            "interval": "month",
            "renewal_policy": "auto",
            "currency": "USD",
        },
        plan={
            "plan_id": "pro",
            "plan_version": 2,
            "product_type": "api_package",
            "sku": "subscription_plan:pro",
            "limit_overrides": {"monthly_call_limit": 5000},
        },
        invoice={
            "invoice_id": "inv-1",
            "amount_cents": 1900,
            "currency": "USD",
            "period_start": "2026-01-01T00:00:00Z",
            "period_end": "2026-02-01T00:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
        },
    )

    assert out["order_id"] == "ord-sub-1"
    assert captured["source_system"] == "subscription_cycle"
    assert captured["metadata"]["subscription_id"] == "sub-1"
    assert captured["metadata"]["invoice_id"] == "inv-1"


def test_reconciliation_gateway_defaults_to_table_backed_repository() -> None:
    gateway = svc.SubscriptionCycleReconciliationGateway()
    assert isinstance(gateway.entitlements_repo, svc.TableBackedEntitlementsRepository)


def test_emit_subscription_cycle_order_invokes_reconciliation_hook(monkeypatch) -> None:
    reconciliation = Mock()
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        svc,
        "commerce_order_service",
        SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": "ord-sub-2", "line_items": kwargs["line_items"], "status": "pending_payment"}),
    )
    reconciliation.process_webhook_event.return_value = {"status": "processed"}

    svc.emit_subscription_cycle_order(
        subscription={
            "subscription_id": "sub-2",
            "subscriber_id": "u2",
            "plan_id": "pro",
            "interval": "month",
            "renewal_policy": "auto",
            "currency": "USD",
        },
        plan={
            "plan_id": "pro",
            "plan_version": 1,
            "product_type": "internal_api_package",
            "sku": "subscription_plan:pro",
            "scope": {"internal_namespaces": ["messaging.*"]},
        },
        invoice={
            "invoice_id": "inv-2",
            "amount_cents": 1000,
            "currency": "USD",
            "created_at": "2026-01-01T00:00:00Z",
        },
        reconciliation_hook=reconciliation,
    )

    reconciliation.process_webhook_event.assert_called_once()
    _, kwargs = reconciliation.process_webhook_event.call_args
    assert kwargs["provider"] == "subscription_system"
    assert kwargs["payload"]["event_id"] == "subscription_charge:inv-2"
    assert kwargs["payload"]["order_id"]


def test_emit_subscription_cycle_order_uses_default_gateway_when_hook_absent(monkeypatch) -> None:
    gateway = Mock()
    gateway.process_webhook_event.return_value = {"status": "processed"}
    monkeypatch.setattr(svc, "default_reconciliation_gateway", gateway)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        svc,
        "commerce_order_service",
        SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": "ord-sub-3", "line_items": kwargs["line_items"], "status": "pending_payment"}),
    )

    svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-3", "subscriber_id": "u3", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-3", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )

    gateway.process_webhook_event.assert_called_once()


def test_emit_subscription_cycle_order_logs_reconciliation_error(monkeypatch) -> None:
    events = []

    class _Boom:
        def process_webhook_event(self, *, provider, payload):
            raise RuntimeError("boom")

    monkeypatch.setattr(svc, "default_reconciliation_gateway", _Boom())
    monkeypatch.setattr(svc, "commerce_order_service", SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": "ord-sub-4"}))
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))

    out = svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-4", "subscriber_id": "u4", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-4", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )

    assert out["reconciliation"]["status"] == "failed"
    failed = [call for call in events if call[0][0] == "subscription_cycle_reconciliation_failed"]
    assert failed
    assert failed[0][1]["normalized_event_id"] == "subscription_charge:inv-4"
    assert failed[0][1]["failure_reason"] == "boom"


class _OrdersTable:
    def __init__(self, order=None):
        self.order = order

    def get_item(self, Key):
        if self.order and self.order.get("order_id") == Key.get("order_id"):
            return {"Item": dict(self.order)}
        return {}


class _OrderItemsTable:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def query(self, KeyConditionExpression):
        return {"Items": list(self.rows)}

    def scan(self):
        return {"Items": list(self.rows)}


class _EntitlementsTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item, ConditionExpression=None):
        item = dict(Item)
        if ConditionExpression and any(x.get("user_id") == item.get("user_id") and x.get("entitlement_id") == item.get("entitlement_id") for x in self.items):
            class _CExc(Exception):
                def __init__(self):
                    self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}

            raise _CExc()
        self.items = [x for x in self.items if not (x.get("user_id") == item.get("user_id") and x.get("entitlement_id") == item.get("entitlement_id"))]
        self.items.append(item)

    def query(self, KeyConditionExpression):
        # test helper keeps single-subject rows
        return {"Items": list(self.items)}

    def scan(self, **kwargs):
        filt = kwargs.get("FilterExpression")
        if filt is None:
            return {"Items": list(self.items)}
        # minimal behavior for get_entitlement scan path; return first match by entitlement_id
        ent_id = kwargs.get("ExpressionAttributeValues", {}).get(":v") if isinstance(kwargs.get("ExpressionAttributeValues"), dict) else None
        if ent_id:
            return {"Items": [x for x in self.items if x.get("entitlement_id") == ent_id]}
        return {"Items": list(self.items)}


def test_gateway_loads_canonical_order_rows_before_reconciliation(monkeypatch) -> None:
    order_id = "ord-sub-adapter"
    repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u1", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 3}
        ]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    out = gateway.process_webhook_event(
        provider="subscription_system",
        payload={
            "event_id": "subscription_charge:inv-adapter",
            "order_id": order_id,
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00Z",
            "raw": {"subscriber_id": "u1"},
        },
    )

    assert out["status"] == "processed"
    assert out["action"] == "granted"


def test_gateway_dead_letters_when_order_projection_missing(monkeypatch) -> None:
    events = []
    repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable(None),
        order_items_table=_OrderItemsTable([]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))

    out = gateway.process_webhook_event(
        provider="subscription_system",
        payload={
            "event_id": "subscription_charge:inv-missing",
            "order_id": "ord-missing",
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00Z",
            "raw": {"subscriber_id": "u-missing"},
        },
    )

    assert out["status"] == "dead_lettered"
    assert out["reason"] == "missing_order"
    assert out["owner_team"] == "commerce_platform"
    assert any(call[0][0] == "subscription_cycle_reconciliation_invariant_failed" for call in events)


def test_emit_subscription_cycle_order_duplicate_invoice_is_idempotent(monkeypatch) -> None:
    events = []
    order_id = "ord-dup-1"

    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(
        svc,
        "commerce_order_service",
        SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": order_id, "line_items": kwargs["line_items"], "status": "pending_payment"}),
    )

    ent_repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-dup", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 2}
        ]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=ent_repo)
    monkeypatch.setattr(svc, "default_reconciliation_gateway", gateway)

    first = svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-dup", "subscriber_id": "u-dup", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-dup", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )
    second = svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-dup", "subscriber_id": "u-dup", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-dup", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )

    assert first["reconciliation"]["status"] == "processed"
    assert second["reconciliation"]["status"] == "duplicate"
    assert len(ent_repo.entitlements) == 1


def test_gateway_dead_letter_surface_includes_owner_metadata(monkeypatch) -> None:
    events = []
    order_id = "ord-dl-1"
    repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-dl", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 2}
        ]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))

    original = gateway._service.entitlements.grant_entitlement

    def _boom(order_id: str):
        raise RuntimeError("grant boom")

    gateway._service.entitlements.grant_entitlement = _boom  # type: ignore[assignment]
    out = gateway.process_webhook_event(
        provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER,
        payload={
            "event_id": "subscription_charge:inv-dl-1",
            "order_id": order_id,
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00Z",
            "raw": {"subscriber_id": "u-dl", "invoice_id": "inv-dl-1"},
        },
    )
    gateway._service.entitlements.grant_entitlement = original  # type: ignore[assignment]

    assert out["status"] == "dead_lettered"
    assert out["owner_team"] == "commerce_platform"
    assert out["invoice_id"] == "inv-dl-1"
    assert out["provider_event_id"] == "subscription_charge:inv-dl-1"
    assert out["remediation_hint"] == "replay_recurring_grants_for_invoice_range"
    assert gateway.reconciliation_repo.dead_letters[0]["invoice_id"] == "inv-dl-1"
    assert gateway.reconciliation_repo.dead_letters[0]["subscription_id"] == ""
    assert gateway.reconciliation_repo.dead_letters[0]["order_id"] == order_id
    assert gateway.reconciliation_repo.dead_letters[0]["owner_team"] == "commerce_platform"
    assert any(call[0][0] == "subscription_cycle_reconciliation_dead_lettered" for call in events)


def test_replay_dead_letters_for_invoice_range(monkeypatch) -> None:
    order_id = "ord-replay-1"
    repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-replay", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 2}
        ]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    gateway.reconciliation_repo.dead_letters = [
        {
            "provider": svc.SUBSCRIPTION_SYSTEM_PROVIDER,
            "provider_event_id": "subscription_charge:inv-100",
            "order_id": order_id,
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00+00:00",
            "reason": "test",
            "raw": {
                "event_id": "subscription_charge:inv-100",
                "order_id": order_id,
                "status": "succeeded",
                "occurred_at": "2026-01-01T00:00:00Z",
                "raw": {"invoice_id": "inv-100", "subscriber_id": "u-replay"},
            },
        }
    ]
    out = gateway.replay_dead_letters_for_invoice_range(invoice_start="inv-100", invoice_end="inv-100")

    assert out["replayed"] == 1
    assert out["processed"] == 1
    assert out["failed"] == 0


def test_list_dead_letters_for_invoice_range_returns_queryable_rows(monkeypatch) -> None:
    order_id = "ord-list-1"
    repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable(None),
        order_items_table=_OrderItemsTable([]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    gateway.process_webhook_event(
        provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER,
        payload={
            "event_id": "subscription_charge:inv-list-1",
            "order_id": order_id,
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00Z",
            "raw": {"subscriber_id": "u-list", "invoice_id": "inv-list-1", "subscription_id": "sub-list-1"},
        },
    )

    rows = gateway.list_dead_letters_for_invoice_range(invoice_start="inv-list-1", invoice_end="inv-list-1")
    assert len(rows) == 1
    assert rows[0]["invoice_id"] == "inv-list-1"
    assert rows[0]["subscription_id"] == "sub-list-1"
    assert rows[0]["provider_event_id"] == "subscription_charge:inv-list-1"
    assert rows[0]["owner_team"] == "commerce_platform"


def test_emit_subscription_cycle_order_audits_attempt_and_success_chain(monkeypatch) -> None:
    events = []
    gateway = Mock()
    gateway.process_webhook_event.return_value = {"status": "processed"}
    monkeypatch.setattr(svc, "default_reconciliation_gateway", gateway)
    monkeypatch.setattr(svc, "commerce_order_service", SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": "ord-sub-audit"}))
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: events.append((args, kwargs)))

    svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-audit", "subscriber_id": "u-audit", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-audit", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )

    attempted = [call for call in events if call[0][0] == "subscription_cycle_reconciliation_attempted"]
    succeeded = [call for call in events if call[0][0] == "subscription_cycle_reconciliation_succeeded"]
    assert attempted and succeeded
    assert attempted[0][1]["order_id"] == "ord-sub-audit"
    assert attempted[0][1]["subscription_id"] == "sub-audit"
    assert attempted[0][1]["invoice_id"] == "inv-audit"
    assert attempted[0][1]["normalized_event_id"] == "subscription_charge:inv-audit"
    assert attempted[0][1]["failure_reason"] is None
    assert succeeded[0][1]["normalized_event_id"] == "subscription_charge:inv-audit"
    assert succeeded[0][1]["failure_reason"] is None


def test_subscription_renewal_flow_grants_active_entitlement(monkeypatch) -> None:
    order_id = "ord-renew-1"
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        svc,
        "commerce_order_service",
        SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": order_id, "line_items": kwargs["line_items"], "status": "pending_payment"}),
    )

    ent_repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-renew", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 10}
        ]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=ent_repo)
    monkeypatch.setattr(svc, "default_reconciliation_gateway", gateway)

    out = svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-renew", "subscriber_id": "u-renew", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-renew", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )

    assert out["reconciliation"]["status"] == "processed"
    assert len(ent_repo.entitlements) == 1
    rec = next(iter(ent_repo.entitlements.values()))
    assert rec.status == "active"


def test_table_backed_repository_writes_are_visible_in_entitlements_api(monkeypatch) -> None:
    order_id = "ord-table-1"
    ent_table = _EntitlementsTable()
    repo = svc.TableBackedEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-table", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 5, "source_system": "subscription_cycle"}
        ]),
        entitlements_table=ent_table,
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo)
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    out = gateway.process_webhook_event(
        provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER,
        payload={
            "event_id": "subscription_charge:inv-table-1",
            "order_id": order_id,
            "status": "succeeded",
            "occurred_at": "2026-01-01T00:00:00Z",
            "raw": {"subscriber_id": "u-table", "invoice_id": "inv-table-1"},
        },
    )
    assert out["status"] == "processed"
    assert len(ent_table.items) == 1

    monkeypatch.setattr(visibility.T.entitlements, "query", ent_table.query)
    listed = visibility.list_user_entitlements("u-table")
    assert listed["count"] == 1


def test_duplicate_event_after_gateway_restart_does_not_duplicate_entitlement_rows(monkeypatch) -> None:
    order_id = "ord-restart-1"
    ent_table = _EntitlementsTable()
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)

    payload = {
        "event_id": "subscription_charge:inv-restart-1",
        "order_id": order_id,
        "status": "succeeded",
        "occurred_at": "2026-01-01T00:00:00Z",
        "raw": {"subscriber_id": "u-restart", "invoice_id": "inv-restart-1"},
    }

    repo1 = svc.TableBackedEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-restart", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "item_id": "1", "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 5}
        ]),
        entitlements_table=ent_table,
    )
    g1 = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo1)
    out1 = g1.process_webhook_event(provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER, payload=payload)
    assert out1["status"] == "processed"
    assert len(ent_table.items) == 1

    repo2 = svc.TableBackedEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-restart", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "item_id": "1", "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 5}
        ]),
        entitlements_table=ent_table,
    )
    g2 = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=repo2)
    out2 = g2.process_webhook_event(provider=svc.SUBSCRIPTION_SYSTEM_PROVIDER, payload=payload)
    assert out2["status"] == "processed"
    assert len(ent_table.items) == 1


def test_transient_failure_dead_letter_then_replay_grants_entitlement(monkeypatch) -> None:
    order_id = "ord-transient-1"
    monkeypatch.setattr(svc, "audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        svc,
        "commerce_order_service",
        SimpleNamespace(create_order_from_line_items=lambda **kwargs: {"order_id": order_id, "line_items": kwargs["line_items"], "status": "pending_payment"}),
    )

    ent_repo = svc.CanonicalOrderEntitlementsRepository(
        orders_table=_OrdersTable({"order_id": order_id, "user_id": "u-transient", "status": "paid", "created_by": "system"}),
        order_items_table=_OrderItemsTable([
            {"order_id": order_id, "sku": "subscription_plan:pro", "product_type": "api_package", "scope": {"allowed_actions": ["request_units"], "resource": {}}, "usage_limit": 2}
        ]),
    )
    gateway = svc.SubscriptionCycleReconciliationGateway(entitlements_repo=ent_repo)
    monkeypatch.setattr(svc, "default_reconciliation_gateway", gateway)

    original = gateway._service.entitlements.grant_entitlement

    def _flaky(order_id: str):
        if not getattr(_flaky, "done", False):
            _flaky.done = True
            raise RuntimeError("transient grant failure")
        return original(order_id)

    gateway._service.entitlements.grant_entitlement = _flaky  # type: ignore[assignment]

    first = svc.emit_subscription_cycle_order(
        subscription={"subscription_id": "sub-transient", "subscriber_id": "u-transient", "plan_id": "pro"},
        plan={"plan_id": "pro", "plan_version": 1, "sku": "subscription_plan:pro"},
        invoice={"invoice_id": "inv-transient", "amount_cents": 1900, "created_at": "2026-01-01T00:00:00Z"},
    )

    assert first["reconciliation"]["status"] == "dead_lettered"
    replay = gateway.replay_dead_letters_for_invoice_range(invoice_start="inv-transient", invoice_end="inv-transient")
    assert replay["replayed"] == 1
    assert replay["processed"] == 1
    assert len(ent_repo.entitlements) == 1
    rec = next(iter(ent_repo.entitlements.values()))
    assert rec.status == "active"
