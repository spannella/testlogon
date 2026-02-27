from __future__ import annotations

from app.services import entitlement_billing_reconciliation as svc


class _Table:
    def __init__(self, items):
        self.items = list(items)
        self.updated = []

    def scan(self, **kwargs):
        return {"Items": list(self.items)}

    def put_item(self, Item):
        self.items.append(dict(Item))

    def update_item(self, **kwargs):
        self.updated.append(kwargs)


def test_reconcile_usage_events_with_service_logs_includes_owner_metadata():
    usage = [
        {"entitlement_id": "e-api", "meter": "request_units", "amount": 3},
        {"entitlement_id": "e-msg", "meter": "messaging.send", "amount": 2},
    ]
    service_logs = [
        {"entitlement_id": "e-api", "meter": "request_units", "amount": 5},
        {"entitlement_id": "e-msg", "meter": "messaging.send", "amount": 2},
    ]

    report = svc.reconcile_usage_events_with_service_logs(usage_events=usage, service_logs=service_logs)

    assert report["drift_count"] == 1
    row = report["diffs"][0]
    assert row["entitlement_id"] == "e-api"
    assert row["delta_units"] == -2
    assert row["owner_team"] == "api"
    assert row["recommended_action"] == "replay_missing_usage_events"


def test_build_billing_drift_report_compares_consumed_vs_billed_units():
    usage = [
        {"entitlement_id": "e1", "meter": "request_units", "amount": 4},
    ]
    billed = [
        {"entitlement_id": "e1", "meter": "request_units", "billed_units": 6},
    ]

    report = svc.build_billing_drift_report(usage_events=usage, billed_units=billed)

    assert report["drift_count"] == 1
    assert report["diffs"][0]["variance_units"] == 2


def test_replay_and_recompute_repairs_apply_deterministically():
    usage_table = _Table(
        [
            {"entitlement_id": "e1", "event_id": "evt-1", "idempotency_key": "k1", "meter": "request_units", "amount": 1},
        ]
    )
    entitlements = _Table(
        [
            {"user_id": "u1", "entitlement_id": "e1", "usage_consumed": 0},
        ]
    )
    service_logs = [
        {"entitlement_id": "e1", "meter": "request_units", "amount": 1, "idempotency_key": "k1", "event_id": "evt-1"},
        {"entitlement_id": "e1", "meter": "request_units", "amount": 1, "idempotency_key": "k2", "event_id": "evt-2"},
    ]

    replay = svc.replay_missing_usage_events(usage_events_table=usage_table, service_logs=service_logs, apply=True)
    assert replay["missing_events"] == 1
    assert replay["replayed_events"] == 1

    recompute = svc.recompute_entitlement_usage(entitlements_table=entitlements, usage_events=usage_table, apply=True)
    assert recompute["drift_count"] == 1
    assert recompute["repaired"] == 1
    assert entitlements.updated[0]["ExpressionAttributeValues"][":u"] == 2


def test_run_job_returns_actionable_sections():
    usage_table = _Table([{"entitlement_id": "e1", "meter": "request_units", "amount": 1}])
    entitlements = _Table([{"user_id": "u1", "entitlement_id": "e1", "usage_consumed": 1}])
    service_logs = [{"entitlement_id": "e1", "meter": "request_units", "amount": 2, "idempotency_key": "k2"}]
    billed_units = [{"entitlement_id": "e1", "meter": "request_units", "billed_units": 3}]

    report = svc.run_entitlement_billing_reconciliation_job(
        entitlements_table=entitlements,
        usage_events_table=usage_table,
        service_logs=service_logs,
        billed_units=billed_units,
        apply_repairs=False,
    )

    assert set(report.keys()) >= {"usage_vs_logs", "billing_drift", "replay_report", "recompute_report"}
    assert report["usage_vs_logs"]["drift_count"] == 1
    assert report["billing_drift"]["drift_count"] == 1


def test_cross_system_invariants_report_actionable_drift_rows() -> None:
    billed_units = [{"invoice_id": "inv-1", "billed_units": 200}]
    order_items = [
        {"order_id": "ord-1", "amount_cents": 100, "metadata": {"invoice_id": "inv-1"}},
    ]
    entitlements = []
    subscription_events = [{"event_type": "invoice.paid", "invoice_id": "inv-1"}]
    recurring_orders = []

    report = svc.run_cross_system_reconciliation_invariants(
        billed_units=billed_units,
        order_items=order_items,
        entitlements=entitlements,
        subscription_events=subscription_events,
        recurring_orders=recurring_orders,
    )

    assert report["total_drift_count"] == 3
    assert len(report["actionable_alerts"]) == 3
    assert all(row.get("owner_team") for row in report["actionable_alerts"])
    assert all(row.get("recommended_action") for row in report["actionable_alerts"])


def test_subscription_renewal_vs_recurring_order_invariant_detects_both_sides() -> None:
    events = [
        {"event_type": "invoice.paid", "invoice_id": "inv-a"},
    ]
    recurring_orders = [
        {"source_system": "subscription_cycle", "metadata": {"invoice_id": "inv-b"}, "order_id": "ord-b"},
    ]

    report = svc.reconcile_subscription_renewal_events_with_recurring_orders(
        subscription_events=events,
        orders=recurring_orders,
    )

    assert report["drift_count"] == 2
    invs = {row["invoice_id"] for row in report["diffs"]}
    assert invs == {"inv-a", "inv-b"}
