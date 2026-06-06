"""Compute cost tracking -- per-minute billing for EC2 instances and K8s pods (INFRA-005)."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate cards -- cents per minute for each resource type / size
# ---------------------------------------------------------------------------

EC2_RATES: Dict[str, float] = {
    "t3.micro": 0.2,
    "t3.small": 0.4,
    "t3.medium": 0.8,
    "t3.large": 1.5,
    "m5.xlarge": 3.2,
}

K8S_RATES: Dict[str, float] = {
    "small": 0.1,
    "medium": 0.3,
    "large": 0.6,
    "xlarge": 1.2,
    "standard-2cpu-4gb": 0.5,
    "standard-4cpu-8gb": 1.0,
    "standard-8cpu-16gb": 2.0,
}

DEFAULT_BUDGET_MONTHLY_CENTS = 5000
DEFAULT_ALERT_THRESHOLDS = [50, 80, 100]


class InsufficientBalanceError(Exception):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _current_month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def get_rate(resource_type: str, type_or_preset: str) -> float:
    """Lookup cents-per-minute rate for a resource type."""
    if resource_type == "ec2":
        return EC2_RATES.get(type_or_preset, S.compute_billing_default_budget_cents * 0.0001)
    elif resource_type == "k8s":
        return K8S_RATES.get(type_or_preset, 0.3)
    return 0.3  # fallback


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


# ---------------------------------------------------------------------------
# Billing events
# ---------------------------------------------------------------------------

def record_billing_tick(
    user_sub: str,
    *,
    resource_type: str,
    resource_id: str,
    resource_label: str = "",
    instance_type_or_preset: str,
    event: str = "periodic_tick",
    duration_minutes: float,
) -> Dict[str, Any]:
    """Write a billing ledger entry and deduct from wallet.

    Returns the created ledger entry dict.
    """
    rate = get_rate(resource_type, instance_type_or_preset)
    amount_cents = max(1, int(round(rate * duration_minutes)))
    ts = now_ts()
    entry_id = f"e_{uuid.uuid4().hex[:8]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # Deduct from wallet
    wallet_balance_after = _deduct_from_wallet(user_sub, amount_cents)

    # Write ledger entry
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "sk": f"TICK#{ts}#{entry_id}",
        "entry_id": entry_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_label": resource_label,
        "instance_type_or_preset": instance_type_or_preset,
        "event": event,
        "amount_cents": amount_cents,
        "duration_minutes": Decimal(str(round(duration_minutes, 2))),
        "rate_cents_per_min": Decimal(str(rate)),
        "wallet_balance_after": wallet_balance_after,
        "created_at": ts,
        "month_key": month_key,
    }
    T.compute_billing.put_item(Item=item)

    # Update monthly running total
    _update_monthly_total(user_sub, month_key, amount_cents)

    # Check spending alerts
    try:
        check_spending_alerts(user_sub)
    except Exception:
        logger.exception("Error checking spending alerts for %s", user_sub)

    logger.info(
        "compute_billing_tick user_sub=%s resource_id=%s resource_type=%s "
        "amount_cents=%d duration_minutes=%.2f wallet_balance_after=%d",
        user_sub, resource_id, resource_type, amount_cents, duration_minutes, wallet_balance_after,
    )

    return {
        "entry_id": entry_id,
        "amount_cents": amount_cents,
        "wallet_balance_after": wallet_balance_after,
        "rate_cents_per_min": float(rate),
        "created_at": ts,
    }


def _deduct_from_wallet(user_sub: str, amount_cents: int) -> int:
    """Deduct from wallet using the billing table. Returns new balance."""
    from app.services.billing_shared import apply_wallet_delta, user_pk

    pk = user_pk(user_sub)
    try:
        new_balance = apply_wallet_delta(T.billing, pk, -amount_cents)
        return new_balance
    except Exception:
        raise InsufficientBalanceError(
            f"Wallet balance insufficient for {amount_cents}c deduction"
        )


def _update_monthly_total(user_sub: str, month_key: str, amount_cents: int) -> None:
    """Atomically increment the monthly running total."""
    T.compute_billing.update_item(
        Key={"user_sub": user_sub, "sk": f"MONTH#{month_key}"},
        UpdateExpression=(
            "SET current_month_total_cents = if_not_exists(current_month_total_cents, :z) + :a, "
            "month_key = :mk"
        ),
        ExpressionAttributeValues={
            ":z": 0,
            ":a": amount_cents,
            ":mk": month_key,
        },
    )


# ---------------------------------------------------------------------------
# Spending queries
# ---------------------------------------------------------------------------

def get_monthly_summary(user_sub: str, *, month: Optional[str] = None) -> Dict[str, Any]:
    """Get spending summary for a month."""
    month_key = month or _current_month_key()

    # Get monthly total from the MONTH# item
    resp = T.compute_billing.get_item(
        Key={"user_sub": user_sub, "sk": f"MONTH#{month_key}"},
    )
    month_item = resp.get("Item") or {}
    total_cents = int(month_item.get("current_month_total_cents", 0))

    # Get budget
    budget = get_budget(user_sub)
    budget_cents = budget["budget_monthly_cents"]

    # Get per-type breakdown by querying all TICK# entries for this month
    entries = _query_ticks_for_month(user_sub, month_key)
    ec2_total = 0
    k8s_total = 0
    resource_ids = set()
    for e in entries:
        amt = int(e.get("amount_cents", 0))
        rt = e.get("resource_type", "")
        if rt == "ec2":
            ec2_total += amt
        elif rt == "k8s":
            k8s_total += amt
        resource_ids.add(e.get("resource_id", ""))

    return {
        "month": month_key,
        "total_cents": total_cents,
        "budget_cents": budget_cents,
        "budget_pct": round((total_cents / budget_cents * 100) if budget_cents > 0 else 0, 2),
        "ec2_total_cents": ec2_total,
        "k8s_total_cents": k8s_total,
        "resource_count": len(resource_ids),
    }


def _query_ticks_for_month(user_sub: str, month_key: str) -> List[Dict[str, Any]]:
    """Query all billing tick entries for a user in a given month via ByMonth GSI."""
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "ByMonth",
        "KeyConditionExpression": Key("month_key").eq(month_key),
    }
    # ByMonth GSI PK is month_key -- we need to filter by user_sub
    resp = T.compute_billing.query(**kwargs)
    for item in resp.get("Items", []):
        if item.get("user_sub") == user_sub:
            items.append(item)
    while resp.get("LastEvaluatedKey"):
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        resp = T.compute_billing.query(**kwargs)
        for item in resp.get("Items", []):
            if item.get("user_sub") == user_sub:
                items.append(item)
    return items


def get_resource_breakdown(user_sub: str, *, month: Optional[str] = None) -> List[Dict[str, Any]]:
    """Per-resource spending breakdown for a month."""
    month_key = month or _current_month_key()
    entries = _query_ticks_for_month(user_sub, month_key)

    resources: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        rid = e.get("resource_id", "")
        if rid not in resources:
            resources[rid] = {
                "resource_id": rid,
                "resource_label": e.get("resource_label", ""),
                "resource_type": e.get("resource_type", ""),
                "instance_type_or_preset": e.get("instance_type_or_preset", ""),
                "total_cents": 0,
                "total_minutes": 0.0,
                "status": "unknown",
            }
        resources[rid]["total_cents"] += int(e.get("amount_cents", 0))
        resources[rid]["total_minutes"] += float(e.get("duration_minutes", 0))
        # Use label from latest entry
        if e.get("resource_label"):
            resources[rid]["resource_label"] = e["resource_label"]

    return list(resources.values())


def get_spending_ledger(
    user_sub: str,
    *,
    resource_id: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List billing ledger entries with optional resource filter."""
    if resource_id:
        return _get_ledger_by_resource(user_sub, resource_id, limit=limit, cursor=cursor)

    # Query main table by user_sub, sk begins_with TICK#
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("user_sub").eq(user_sub) & Key("sk").begins_with("TICK#")
        ),
        "ScanIndexForward": False,
        "Limit": min(limit, 500),
    }
    if cursor:
        import json, base64
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor))
        except Exception:
            pass

    resp = T.compute_billing.query(**kwargs)
    items = resp.get("Items", [])

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        import json, base64
        next_cursor = base64.b64encode(
            json.dumps(resp["LastEvaluatedKey"], default=str).encode()
        ).decode()

    entries = [_item_to_ledger_entry(item) for item in items]
    return {
        "entries": entries,
        "count": len(entries),
        "cursor": next_cursor,
    }


def _get_ledger_by_resource(
    user_sub: str, resource_id: str, *, limit: int = 100, cursor: Optional[str] = None
) -> Dict[str, Any]:
    """Query ByResourceId GSI for a specific resource."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByResourceId",
        "KeyConditionExpression": Key("resource_id").eq(resource_id),
        "ScanIndexForward": False,
        "Limit": min(limit, 500),
    }
    if cursor:
        import json, base64
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor))
        except Exception:
            pass

    resp = T.compute_billing.query(**kwargs)
    items = [i for i in resp.get("Items", []) if i.get("user_sub") == user_sub]

    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        import json, base64
        next_cursor = base64.b64encode(
            json.dumps(resp["LastEvaluatedKey"], default=str).encode()
        ).decode()

    entries = [_item_to_ledger_entry(item) for item in items]
    return {
        "entries": entries,
        "count": len(entries),
        "cursor": next_cursor,
    }


def _item_to_ledger_entry(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB item to a ledger entry dict."""
    return {
        "entry_id": item.get("entry_id", ""),
        "resource_type": item.get("resource_type", ""),
        "resource_id": item.get("resource_id", ""),
        "resource_label": item.get("resource_label", ""),
        "instance_type_or_preset": item.get("instance_type_or_preset", ""),
        "event": item.get("event", ""),
        "amount_cents": int(item.get("amount_cents", 0)),
        "duration_minutes": float(item.get("duration_minutes", 0)),
        "rate_cents_per_min": float(item.get("rate_cents_per_min", 0)),
        "wallet_balance_after": int(item.get("wallet_balance_after", 0)),
        "created_at": int(item.get("created_at", 0)),
    }


# ---------------------------------------------------------------------------
# Budget management
# ---------------------------------------------------------------------------

def get_budget(user_sub: str) -> Dict[str, Any]:
    """Get user's budget settings. Returns defaults if no budget set."""
    resp = T.compute_billing.get_item(
        Key={"user_sub": user_sub, "sk": "BUDGET"},
    )
    item = resp.get("Item")
    if not item:
        return {
            "budget_monthly_cents": S.compute_billing_default_budget_cents,
            "alert_thresholds": DEFAULT_ALERT_THRESHOLDS,
        }
    thresholds = item.get("alert_thresholds", DEFAULT_ALERT_THRESHOLDS)
    if isinstance(thresholds, set):
        thresholds = sorted(int(t) for t in thresholds)
    elif isinstance(thresholds, list):
        thresholds = [int(t) for t in thresholds]
    return {
        "budget_monthly_cents": int(item.get("budget_monthly_cents", S.compute_billing_default_budget_cents)),
        "alert_thresholds": thresholds,
    }


def set_budget(
    user_sub: str,
    *,
    budget_monthly_cents: int,
    alert_thresholds: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Set monthly budget and alert thresholds."""
    thresholds = alert_thresholds or DEFAULT_ALERT_THRESHOLDS
    ts = now_ts()

    T.compute_billing.put_item(Item={
        "user_sub": user_sub,
        "sk": "BUDGET",
        "budget_monthly_cents": budget_monthly_cents,
        "alert_thresholds": thresholds,
        "updated_at": ts,
    })

    return get_budget_status(user_sub)


def get_budget_status(user_sub: str) -> Dict[str, Any]:
    """Get budget with current month spending status."""
    budget = get_budget(user_sub)
    month_key = _current_month_key()

    resp = T.compute_billing.get_item(
        Key={"user_sub": user_sub, "sk": f"MONTH#{month_key}"},
    )
    month_item = resp.get("Item") or {}
    total_cents = int(month_item.get("current_month_total_cents", 0))
    budget_cents = budget["budget_monthly_cents"]

    return {
        "budget_monthly_cents": budget_cents,
        "alert_thresholds": budget["alert_thresholds"],
        "current_month_total_cents": total_cents,
        "current_month_pct": round((total_cents / budget_cents * 100) if budget_cents > 0 else 0, 2),
    }


# ---------------------------------------------------------------------------
# Spending alerts
# ---------------------------------------------------------------------------

def check_spending_alerts(user_sub: str) -> List[int]:
    """Check if any threshold has been crossed and send alerts. Returns thresholds alerted."""
    budget = get_budget(user_sub)
    month_key = _current_month_key()

    resp = T.compute_billing.get_item(
        Key={"user_sub": user_sub, "sk": f"MONTH#{month_key}"},
    )
    month_item = resp.get("Item") or {}
    total = int(month_item.get("current_month_total_cents", 0))
    budget_cents = budget["budget_monthly_cents"]
    thresholds = budget.get("alert_thresholds", DEFAULT_ALERT_THRESHOLDS)

    # Get already-sent alerts for this month
    already_sent = set()
    alerts_sent_raw = month_item.get("alerts_sent")
    if alerts_sent_raw:
        if isinstance(alerts_sent_raw, set):
            already_sent = {int(x) for x in alerts_sent_raw}
        elif isinstance(alerts_sent_raw, list):
            already_sent = {int(x) for x in alerts_sent_raw}

    alerts_to_send: List[int] = []
    for pct in thresholds:
        threshold_cents = budget_cents * pct / 100
        if total >= threshold_cents and pct not in already_sent:
            # Send alert
            try:
                from app.services.alerts import write_alert
                write_alert(
                    user_sub,
                    event="compute.spending_threshold",
                    outcome="warning",
                    title=f"Compute spending at {pct}% of monthly budget",
                    details={
                        "total_cents": total,
                        "budget_cents": budget_cents,
                        "threshold_pct": pct,
                    },
                )
            except Exception:
                logger.exception("Failed to send spending alert for %s at %d%%", user_sub, pct)
            alerts_to_send.append(pct)

    if alerts_to_send:
        _update_alerts_sent(user_sub, month_key, alerts_to_send)

    return alerts_to_send


def _update_alerts_sent(user_sub: str, month_key: str, new_thresholds: List[int]) -> None:
    """Record which threshold alerts were sent for this month."""
    # Use ADD with a number set to track sent thresholds
    T.compute_billing.update_item(
        Key={"user_sub": user_sub, "sk": f"MONTH#{month_key}"},
        UpdateExpression="ADD alerts_sent :t",
        ExpressionAttributeValues={
            ":t": set(new_thresholds),
        },
    )


# ---------------------------------------------------------------------------
# Background billing timer (GAP-0228 / INFRA-005)
#
# The manual POST /ui/remote/billing/tick endpoint calls record_billing_tick
# for a single resource. This timer performs the same per-tick deduction
# automatically for every running EC2 instance and K8s pod on a fixed poll
# interval, tracking a per-resource last_billed_at timestamp so duration is
# computed accurately, and auto-terminating resources whose wallet runs dry.
# ---------------------------------------------------------------------------

# Minimum elapsed minutes before a periodic tick is emitted, to avoid
# sub-interval ticks (e.g. immediately after launch).
_MIN_TICK_MINUTES = 0.5


def _scan_all_running_instances() -> List[Dict[str, Any]]:
    """Scan all running EC2 instances system-wide (no user_sub filter)."""
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "FilterExpression": "attribute_exists(instance_id) AND #st = :running",
        "ExpressionAttributeNames": {"#st": "status"},
        "ExpressionAttributeValues": {":running": "running"},
    }
    while True:
        resp = T.ec2_instances.scan(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _scan_all_running_pods() -> List[Dict[str, Any]]:
    """Scan all running K8s pods system-wide (no user_sub filter)."""
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "FilterExpression": "attribute_exists(pod_id) AND #st = :running",
        "ExpressionAttributeNames": {"#st": "status"},
        "ExpressionAttributeValues": {":running": "running"},
    }
    while True:
        resp = T.k8s_pods.scan(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def _update_last_billed_at(resource_type: str, user_sub: str, resource_id: str, ts: int) -> None:
    """Record when a resource was last billed, to compute the next tick's duration."""
    if resource_type == "ec2":
        table = T.ec2_instances
        sk = f"INSTANCE#{resource_id}"
    else:
        table = T.k8s_pods
        sk = f"POD#{resource_id}"
    table.update_item(
        Key={"user_sub": user_sub, "sk": sk},
        UpdateExpression="SET last_billed_at = :t",
        ExpressionAttributeValues={":t": ts},
    )


def _auto_terminate_resource(resource_type: str, user_sub: str, resource_id: str) -> None:
    """Terminate a resource whose wallet balance can no longer cover it."""
    try:
        if resource_type == "ec2":
            from app.services.ec2_launcher import terminate_instance
            terminate_instance(user_sub, resource_id)
        else:
            from app.services.k8s_launcher import terminate_pod
            terminate_pod(user_sub, resource_id)
    except Exception:
        logger.exception(
            "compute_billing_auto_terminate_failed resource_type=%s user_sub=%s resource_id=%s",
            resource_type, user_sub, resource_id,
        )


def _tick_resource(
    *,
    resource_type: str,
    user_sub: str,
    resource_id: str,
    resource_label: str,
    instance_type_or_preset: str,
    last_billed: int,
    started_at: int,
    now: int,
) -> bool:
    """Emit a single periodic billing tick for one running resource.

    Returns True if a tick was emitted, False if skipped (too soon).
    Auto-terminates the resource on InsufficientBalanceError.
    """
    anchor = last_billed if last_billed else (started_at or now)
    elapsed_minutes = max(0.0, (now - anchor) / 60.0)
    if elapsed_minutes < _MIN_TICK_MINUTES:
        return False

    try:
        record_billing_tick(
            user_sub,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_label=resource_label,
            instance_type_or_preset=instance_type_or_preset,
            event="periodic_tick",
            duration_minutes=elapsed_minutes,
        )
        _update_last_billed_at(resource_type, user_sub, resource_id, now)
        return True
    except InsufficientBalanceError:
        logger.warning(
            "compute_billing_zero_balance resource_type=%s user_sub=%s resource_id=%s -- terminating",
            resource_type, user_sub, resource_id,
        )
        _auto_terminate_resource(resource_type, user_sub, resource_id)
        return False


def _tick_all_running_resources() -> int:
    """Enumerate all running EC2 instances and K8s pods; emit periodic billing
    ticks. Returns the number of ticks emitted.
    """
    ticked = 0
    now = now_ts()

    for inst in _scan_all_running_instances():
        if _tick_resource(
            resource_type="ec2",
            user_sub=inst.get("user_sub", ""),
            resource_id=inst.get("instance_id", ""),
            resource_label=inst.get("label", ""),
            instance_type_or_preset=inst.get("instance_type", "t3.micro"),
            last_billed=int(inst.get("last_billed_at", 0) or 0),
            started_at=int(inst.get("started_at", 0) or 0),
            now=now,
        ):
            ticked += 1

    for pod in _scan_all_running_pods():
        if _tick_resource(
            resource_type="k8s",
            user_sub=pod.get("user_sub", ""),
            resource_id=pod.get("pod_id", ""),
            resource_label=pod.get("label", ""),
            instance_type_or_preset=pod.get("preset", "small"),
            last_billed=int(pod.get("last_billed_at", 0) or 0),
            started_at=int(pod.get("started_at", 0) or 0),
            now=now,
        ):
            ticked += 1

    logger.info("compute_billing_timer_tick ticked=%d", ticked)
    return ticked


async def run_compute_billing_timer(*, poll_interval: int | None = None) -> None:
    """Background task: periodically bill every running compute resource.

    Performs the same per-tick deduction as POST /ui/remote/billing/tick for
    all running EC2 instances and K8s pods, and auto-terminates resources whose
    wallet balance is exhausted.
    """
    interval = poll_interval if poll_interval is not None else S.compute_billing_poll_interval
    while True:
        try:
            _tick_all_running_resources()
        except Exception:
            logger.exception("compute_billing_timer error")
        await asyncio.sleep(interval)


def start_compute_billing_timer_task() -> None:
    """Register the compute billing timer background task at app startup."""
    if S.compute_billing_enabled:
        asyncio.ensure_future(run_compute_billing_timer())
        logger.info(
            "Compute billing timer started (interval=%ds)",
            S.compute_billing_poll_interval,
        )
