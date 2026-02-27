from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


OwnerResolver = Callable[[str, str], Dict[str, str]]


@dataclass(frozen=True)
class ReconciliationKey:
    entitlement_id: str
    meter: str


def _scan_all(table: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = table.scan(**kwargs)
        items.extend(list(resp.get("Items", [])))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def _to_records(source: Any) -> List[Dict[str, Any]]:
    if source is None:
        return []
    if isinstance(source, list):
        return [dict(x) for x in source]
    if hasattr(source, "scan"):
        return _scan_all(source)
    return [dict(x) for x in list(source)]


def _default_owner(entitlement_id: str, meter: str) -> Dict[str, str]:
    owner_team = "billing"
    if meter.startswith("messaging."):
        owner_team = "messaging"
    elif meter.startswith("filemanager."):
        owner_team = "filemanager"
    elif meter in {"request_units", "api.request_units"}:
        owner_team = "api"
    return {
        "owner_team": owner_team,
        "owner_contact": f"{owner_team}-oncall",
        "entitlement_ref": entitlement_id,
    }


def _owner_meta(entitlement_id: str, meter: str, resolver: OwnerResolver | None) -> Dict[str, str]:
    if resolver is None:
        return _default_owner(entitlement_id, meter)
    out = dict(_default_owner(entitlement_id, meter))
    out.update(dict(resolver(entitlement_id, meter) or {}))
    return out


def _aggregate_units(records: List[Dict[str, Any]], *, amount_field: str = "amount") -> Dict[ReconciliationKey, int]:
    agg: Dict[ReconciliationKey, int] = defaultdict(int)
    for row in records:
        entitlement_id = str(row.get("entitlement_id") or "").strip()
        meter = str(row.get("meter") or "").strip()
        if not entitlement_id or not meter:
            continue
        amt = int(row.get(amount_field) or 0)
        if amt <= 0:
            continue
        agg[ReconciliationKey(entitlement_id=entitlement_id, meter=meter)] += amt
    return agg


def reconcile_usage_events_with_service_logs(
    *,
    usage_events: Any,
    service_logs: Any,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    usage_rows = _to_records(usage_events)
    service_rows = _to_records(service_logs)

    actual = _aggregate_units(usage_rows, amount_field="amount")
    expected = _aggregate_units(service_rows, amount_field="amount")

    all_keys = sorted(set(actual.keys()) | set(expected.keys()), key=lambda k: (k.entitlement_id, k.meter))
    diffs: List[Dict[str, Any]] = []
    for key in all_keys:
        actual_units = int(actual.get(key, 0))
        expected_units = int(expected.get(key, 0))
        delta = actual_units - expected_units
        if delta == 0:
            continue
        meta = _owner_meta(key.entitlement_id, key.meter, owner_resolver)
        diffs.append(
            {
                "entitlement_id": key.entitlement_id,
                "meter": key.meter,
                "actual_units": actual_units,
                "expected_units": expected_units,
                "delta_units": delta,
                "severity": "high" if abs(delta) >= 10 else "medium",
                "recommended_action": "replay_missing_usage_events" if delta < 0 else "review_duplicate_or_overcounted_events",
                **meta,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "drift_count": len(diffs),
        "diffs": diffs,
        "totals": {
            "actual_units": sum(actual.values()),
            "expected_units": sum(expected.values()),
        },
    }


def build_billing_drift_report(
    *,
    usage_events: Any,
    billed_units: Any,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    usage_rows = _to_records(usage_events)
    billed_rows = _to_records(billed_units)

    consumed = _aggregate_units(usage_rows, amount_field="amount")
    billed = _aggregate_units(billed_rows, amount_field="billed_units")

    all_keys = sorted(set(consumed.keys()) | set(billed.keys()), key=lambda k: (k.entitlement_id, k.meter))
    diffs: List[Dict[str, Any]] = []
    for key in all_keys:
        consumed_units = int(consumed.get(key, 0))
        billed_units_count = int(billed.get(key, 0))
        variance = billed_units_count - consumed_units
        if variance == 0:
            continue
        meta = _owner_meta(key.entitlement_id, key.meter, owner_resolver)
        diffs.append(
            {
                "entitlement_id": key.entitlement_id,
                "meter": key.meter,
                "consumed_units": consumed_units,
                "billed_units": billed_units_count,
                "variance_units": variance,
                "severity": "high" if abs(variance) >= 10 else "medium",
                "recommended_action": "create_billing_adjustment" if variance != 0 else "none",
                **meta,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "drift_count": len(diffs),
        "diffs": diffs,
    }


def replay_missing_usage_events(*, usage_events_table: Any, service_logs: Any, apply: bool = False) -> Dict[str, Any]:
    service_rows = _to_records(service_logs)
    existing = _to_records(usage_events_table)

    seen_keys = {
        str(row.get("idempotency_key") or row.get("source_event_id") or f"{row.get('entitlement_id')}:{row.get('meter')}:{row.get('event_id')}")
        for row in existing
    }

    missing: List[Dict[str, Any]] = []
    for row in service_rows:
        idem = str(row.get("idempotency_key") or row.get("source_event_id") or "").strip()
        if not idem:
            idem = f"repair:{row.get('entitlement_id')}:{row.get('meter')}:{row.get('event_id') or row.get('timestamp') or len(missing)}"
        if idem in seen_keys:
            continue
        entitlement_id = str(row.get("entitlement_id") or "").strip()
        meter = str(row.get("meter") or "").strip()
        amount = int(row.get("amount") or 0)
        if not entitlement_id or not meter or amount <= 0:
            continue
        candidate = {
            "entitlement_id": entitlement_id,
            "event_id": str(row.get("event_id") or f"repair_{abs(hash(idem))}"),
            "idempotency_key": idem,
            "meter": meter,
            "amount": amount,
            "user_id": row.get("user_id"),
            "timestamp": row.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "source_event_id": row.get("source_event_id") or row.get("event_id") or idem,
            "repair_reason": "replay_from_service_log",
        }
        missing.append(candidate)
        seen_keys.add(idem)

    replayed = 0
    if apply:
        for item in missing:
            usage_events_table.put_item(Item=item)
            replayed += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "missing_events": len(missing),
        "replayed_events": replayed,
        "dry_run": not apply,
        "items": missing,
    }


def recompute_entitlement_usage(
    *,
    entitlements_table: Any,
    usage_events: Any,
    apply: bool = False,
) -> Dict[str, Any]:
    entitlements = _to_records(entitlements_table)
    usage_rows = _to_records(usage_events)
    usage_by_entitlement: Dict[str, int] = defaultdict(int)
    for row in usage_rows:
        entitlement_id = str(row.get("entitlement_id") or "").strip()
        if not entitlement_id:
            continue
        usage_by_entitlement[entitlement_id] += int(row.get("amount") or 0)

    drift_rows: List[Dict[str, Any]] = []
    repaired = 0
    for ent in entitlements:
        entitlement_id = str(ent.get("entitlement_id") or "").strip()
        if not entitlement_id:
            continue
        computed = int(usage_by_entitlement.get(entitlement_id, 0))
        stored = int(ent.get("usage_consumed") or 0)
        if computed == stored:
            continue
        drift_rows.append(
            {
                "entitlement_id": entitlement_id,
                "stored_usage_consumed": stored,
                "computed_usage_consumed": computed,
                "delta_units": computed - stored,
            }
        )
        if apply:
            entitlements_table.update_item(
                Key={"user_id": ent.get("user_id"), "entitlement_id": entitlement_id},
                UpdateExpression="SET usage_consumed = :u, updated_at = :ts",
                ExpressionAttributeValues={
                    ":u": computed,
                    ":ts": datetime.now(timezone.utc).isoformat(),
                },
            )
            repaired += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "drift_count": len(drift_rows),
        "repaired": repaired,
        "dry_run": not apply,
        "rows": drift_rows,
    }


def run_entitlement_billing_reconciliation_job(
    *,
    entitlements_table: Any,
    usage_events_table: Any,
    service_logs: Any,
    billed_units: Any,
    apply_repairs: bool = False,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    usage_vs_logs = reconcile_usage_events_with_service_logs(
        usage_events=usage_events_table,
        service_logs=service_logs,
        owner_resolver=owner_resolver,
    )
    billed_drift = build_billing_drift_report(
        usage_events=usage_events_table,
        billed_units=billed_units,
        owner_resolver=owner_resolver,
    )
    replay_report = replay_missing_usage_events(
        usage_events_table=usage_events_table,
        service_logs=service_logs,
        apply=apply_repairs,
    )
    recompute_report = recompute_entitlement_usage(
        entitlements_table=entitlements_table,
        usage_events=usage_events_table,
        apply=apply_repairs,
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "usage_vs_logs": usage_vs_logs,
        "billing_drift": billed_drift,
        "replay_report": replay_report,
        "recompute_report": recompute_report,
    }


def reconcile_billed_units_with_order_items(
    *,
    billed_units: Any,
    order_items: Any,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    billed_rows = _to_records(billed_units)
    order_item_rows = _to_records(order_items)

    billed_by_invoice: Dict[str, int] = defaultdict(int)
    for row in billed_rows:
        invoice_id = str(row.get("invoice_id") or row.get("provider_invoice_id") or "").strip()
        if not invoice_id:
            continue
        billed_by_invoice[invoice_id] += int(row.get("billed_units") or row.get("amount_cents") or 0)

    order_by_invoice: Dict[str, int] = defaultdict(int)
    invoice_owner_key: Dict[str, tuple[str, str]] = {}
    for row in order_item_rows:
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        invoice_id = str(row.get("invoice_id") or metadata.get("invoice_id") or "").strip()
        if not invoice_id:
            continue
        order_by_invoice[invoice_id] += int(row.get("amount_cents") or 0)
        invoice_owner_key[invoice_id] = (str(row.get("entitlement_id") or "invoice"), str(row.get("meter") or "subscription.billing"))

    keys = sorted(set(billed_by_invoice.keys()) | set(order_by_invoice.keys()))
    diffs: List[Dict[str, Any]] = []
    for invoice_id in keys:
        billed_amt = int(billed_by_invoice.get(invoice_id, 0))
        order_amt = int(order_by_invoice.get(invoice_id, 0))
        delta = billed_amt - order_amt
        if delta == 0:
            continue
        ent_ref, meter = invoice_owner_key.get(invoice_id, ("invoice", "subscription.billing"))
        meta = _owner_meta(ent_ref, meter, owner_resolver)
        diffs.append(
            {
                "invariant": "billed_units_eq_canonical_order_items",
                "invoice_id": invoice_id,
                "billed_units": billed_amt,
                "order_item_units": order_amt,
                "delta_units": delta,
                "severity": "high" if abs(delta) >= 100 else "medium",
                "recommended_action": "repair_order_or_billing_rows",
                **meta,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "drift_count": len(diffs),
        "diffs": diffs,
    }


def reconcile_order_items_with_entitlement_grants(
    *,
    order_items: Any,
    entitlements: Any,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    order_rows = _to_records(order_items)
    entitlement_rows = _to_records(entitlements)

    grants_by_order: Dict[str, int] = defaultdict(int)
    for ent in entitlement_rows:
        order_id = str(ent.get("order_id") or (((ent.get("scope") or {}).get("subscription") or {}).get("order_id")) or "").strip()
        if order_id:
            grants_by_order[order_id] += 1

    items_by_order: Dict[str, int] = defaultdict(int)
    order_owner_key: Dict[str, tuple[str, str]] = {}
    for row in order_rows:
        order_id = str(row.get("order_id") or "").strip()
        if not order_id:
            continue
        items_by_order[order_id] += 1
        order_owner_key[order_id] = (str(row.get("entitlement_id") or order_id), str(row.get("meter") or "subscription.billing"))

    keys = sorted(set(items_by_order.keys()) | set(grants_by_order.keys()))
    diffs: List[Dict[str, Any]] = []
    for order_id in keys:
        item_count = int(items_by_order.get(order_id, 0))
        grant_count = int(grants_by_order.get(order_id, 0))
        delta = item_count - grant_count
        if delta == 0:
            continue
        ent_ref, meter = order_owner_key.get(order_id, (order_id, "subscription.billing"))
        meta = _owner_meta(ent_ref, meter, owner_resolver)
        diffs.append(
            {
                "invariant": "canonical_order_items_eq_entitlement_grants",
                "order_id": order_id,
                "order_item_count": item_count,
                "entitlement_grant_count": grant_count,
                "delta_count": delta,
                "severity": "high" if abs(delta) >= 1 else "medium",
                "recommended_action": "replay_entitlement_grant_from_order",
                **meta,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "drift_count": len(diffs),
        "diffs": diffs,
    }


def reconcile_subscription_renewal_events_with_recurring_orders(
    *,
    subscription_events: Any,
    orders: Any,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    event_rows = _to_records(subscription_events)
    order_rows = _to_records(orders)

    renewals: set[str] = set()
    for evt in event_rows:
        kind = str(evt.get("event_type") or evt.get("kind") or "").lower()
        if "renew" not in kind and "invoice.paid" not in kind and "rebill" not in kind:
            continue
        invoice_id = str(evt.get("invoice_id") or ((evt.get("metadata") or {}).get("invoice_id")) or "").strip()
        if invoice_id:
            renewals.add(invoice_id)

    recurring: set[str] = set()
    invoice_owner_key: Dict[str, tuple[str, str]] = {}
    for order in order_rows:
        source = str(order.get("source_system") or "")
        metadata = order.get("metadata") if isinstance(order.get("metadata"), dict) else {}
        if source != "subscription_cycle":
            continue
        invoice_id = str(metadata.get("invoice_id") or order.get("invoice_id") or "").strip()
        if not invoice_id:
            continue
        recurring.add(invoice_id)
        invoice_owner_key[invoice_id] = (str(order.get("order_id") or "invoice"), "subscription.billing")

    diffs: List[Dict[str, Any]] = []
    for invoice_id in sorted(renewals - recurring):
        ent_ref, meter = invoice_owner_key.get(invoice_id, ("invoice", "subscription.billing"))
        meta = _owner_meta(ent_ref, meter, owner_resolver)
        diffs.append(
            {
                "invariant": "subscription_renewal_events_eq_recurring_order_stream",
                "invoice_id": invoice_id,
                "renewal_event_present": True,
                "recurring_order_present": False,
                "severity": "high",
                "recommended_action": "emit_missing_recurring_order",
                **meta,
            }
        )
    for invoice_id in sorted(recurring - renewals):
        ent_ref, meter = invoice_owner_key.get(invoice_id, ("invoice", "subscription.billing"))
        meta = _owner_meta(ent_ref, meter, owner_resolver)
        diffs.append(
            {
                "invariant": "subscription_renewal_events_eq_recurring_order_stream",
                "invoice_id": invoice_id,
                "renewal_event_present": False,
                "recurring_order_present": True,
                "severity": "medium",
                "recommended_action": "reconcile_or_backfill_subscription_event",
                **meta,
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "drift_count": len(diffs),
        "diffs": diffs,
    }


def run_cross_system_reconciliation_invariants(
    *,
    billed_units: Any,
    order_items: Any,
    entitlements: Any,
    subscription_events: Any,
    recurring_orders: Any,
    owner_resolver: OwnerResolver | None = None,
) -> Dict[str, Any]:
    billed_vs_orders = reconcile_billed_units_with_order_items(
        billed_units=billed_units,
        order_items=order_items,
        owner_resolver=owner_resolver,
    )
    orders_vs_entitlements = reconcile_order_items_with_entitlement_grants(
        order_items=order_items,
        entitlements=entitlements,
        owner_resolver=owner_resolver,
    )
    renewals_vs_recurring = reconcile_subscription_renewal_events_with_recurring_orders(
        subscription_events=subscription_events,
        orders=recurring_orders,
        owner_resolver=owner_resolver,
    )

    actionable_alerts: List[Dict[str, Any]] = []
    for section_name, section in [
        ("billed_vs_orders", billed_vs_orders),
        ("orders_vs_entitlements", orders_vs_entitlements),
        ("renewals_vs_recurring", renewals_vs_recurring),
    ]:
        for row in section.get("diffs", []):
            actionable_alerts.append(
                {
                    "section": section_name,
                    "severity": row.get("severity"),
                    "owner_team": row.get("owner_team"),
                    "owner_contact": row.get("owner_contact"),
                    "recommended_action": row.get("recommended_action"),
                    "invariant": row.get("invariant"),
                    "reference": row.get("invoice_id") or row.get("order_id") or row.get("entitlement_id"),
                }
            )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "billed_vs_orders": billed_vs_orders,
        "orders_vs_entitlements": orders_vs_entitlements,
        "renewals_vs_recurring": renewals_vs_recurring,
        "actionable_alerts": actionable_alerts,
        "total_drift_count": int(billed_vs_orders.get("drift_count", 0)) + int(orders_vs_entitlements.get("drift_count", 0)) + int(renewals_vs_recurring.get("drift_count", 0)),
    }
