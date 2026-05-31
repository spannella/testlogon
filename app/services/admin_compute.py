"""Admin compute resource management (INFRA-012).

Cross-user instance/pod visibility, platform-wide spending aggregation,
per-user quotas, force-terminate, and instance-type popularity metrics.

Cross-user queries use table scans. ec2_instances and k8s_pods are keyed by
user_sub, so a global view requires scanning. This is acceptable for admin
operations (the per-user launchers already scan in their idle/TTL checkers).
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event, write_alert
from app.services.ec2_launcher import (
    INSTANCE_TYPES,
    terminate_instance as _user_terminate_ec2,
)
from app.services.k8s_launcher import (
    RESOURCE_PRESETS,
    terminate_pod as _user_terminate_k8s,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cursor helpers
# ---------------------------------------------------------------------------

def _encode_cursor(key: Dict[str, Any] | None) -> Optional[str]:
    if not key:
        return None
    return base64.b64encode(json.dumps(key, default=str).encode()).decode()


def _decode_cursor(cursor: str | None) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    try:
        return json.loads(base64.b64decode(cursor))
    except Exception:
        return None


def _current_month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


# ---------------------------------------------------------------------------
# Cross-user instance / pod listing
# ---------------------------------------------------------------------------

def _scan_all(table, *, item_filter) -> List[Dict[str, Any]]:
    """Scan an entire table, keeping only items matching item_filter."""
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {}
    while True:
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            if item_filter(item):
                out.append(item)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


def list_all_instances(
    *,
    status: str | None = None,
    user_sub: str | None = None,
    instance_type: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> Dict[str, Any]:
    """List all EC2 instances across all users with optional filters."""

    def _keep(item: Dict[str, Any]) -> bool:
        if "instance_id" not in item:
            return False
        if status and item.get("status") != status:
            return False
        if user_sub and item.get("user_sub") != user_sub:
            return False
        if instance_type and item.get("instance_type") != instance_type:
            return False
        return True

    items = _scan_all(T.ec2_instances, item_filter=_keep)
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)

    # In-memory pagination over the sorted result.
    start = 0
    decoded = _decode_cursor(cursor)
    if decoded and isinstance(decoded.get("offset"), int):
        start = decoded["offset"]
    page = items[start:start + limit]
    next_cursor = _encode_cursor({"offset": start + limit}) if start + limit < len(items) else None

    return {
        "instances": [_instance_out(i) for i in page],
        "count": len(items),
        "cursor": next_cursor,
    }


def list_all_pods(
    *,
    status: str | None = None,
    user_sub: str | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> Dict[str, Any]:
    """List all K8s pods across all users with optional filters."""

    def _keep(item: Dict[str, Any]) -> bool:
        if "pod_id" not in item:
            return False
        if status and item.get("status") != status:
            return False
        if user_sub and item.get("user_sub") != user_sub:
            return False
        return True

    items = _scan_all(T.k8s_pods, item_filter=_keep)
    items.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)

    start = 0
    decoded = _decode_cursor(cursor)
    if decoded and isinstance(decoded.get("offset"), int):
        start = decoded["offset"]
    page = items[start:start + limit]
    next_cursor = _encode_cursor({"offset": start + limit}) if start + limit < len(items) else None

    return {
        "pods": [_pod_out(i) for i in page],
        "count": len(items),
        "cursor": next_cursor,
    }


def _instance_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "instance_id": item.get("instance_id", ""),
        "user_sub": item.get("user_sub", ""),
        "label": item.get("label", ""),
        "instance_type": item.get("instance_type", ""),
        "ami_name": item.get("ami_name", ""),
        "status": item.get("status", ""),
        "public_ip": item.get("public_ip", ""),
        "created_at": int(item.get("created_at", 0)),
        "last_activity_at": int(item.get("last_activity_at", 0)),
        "auto_terminate_after": int(item.get("auto_terminate_after", 0)),
    }


def _pod_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pod_id": item.get("pod_id", ""),
        "user_sub": item.get("user_sub", ""),
        "label": item.get("label", ""),
        "image": item.get("image", ""),
        "preset": item.get("preset", ""),
        "status": item.get("status", ""),
        "pod_ip": item.get("pod_ip", ""),
        "created_at": int(item.get("created_at", 0)),
        "ttl_seconds": int(item.get("ttl_seconds", 0)),
        "expires_at": int(item.get("expires_at", 0)),
    }


# ---------------------------------------------------------------------------
# Force-terminate
# ---------------------------------------------------------------------------

def force_terminate_instance(
    admin_sub: str,
    user_sub: str,
    instance_id: str,
    *,
    reason: str = "",
    request=None,
) -> Dict[str, Any]:
    """Force-terminate any user's EC2 instance. Audit-logged + alerts owner."""
    result = _user_terminate_ec2(user_sub, instance_id)

    audit_event(
        "admin.compute.force_terminate",
        admin_sub,
        request,
        outcome="warning",
        resource_type="ec2",
        target_user=user_sub,
        instance_id=instance_id,
        reason=reason,
    )
    try:
        write_alert(
            user_sub,
            event="compute.admin_terminated",
            outcome="warning",
            title="An administrator terminated your instance",
            details={"instance_id": instance_id, "reason": reason, "resource_type": "ec2"},
        )
    except Exception:
        logger.exception("force_terminate_instance: alert failed for %s", user_sub)

    logger.warning(
        "admin_force_terminate admin_sub=%s target_user=%s resource_type=ec2 instance_id=%s reason=%s",
        admin_sub, user_sub, instance_id, reason,
    )
    return _instance_out(result)


def force_terminate_pod(
    admin_sub: str,
    user_sub: str,
    pod_id: str,
    *,
    reason: str = "",
    request=None,
) -> Dict[str, Any]:
    """Force-terminate any user's K8s pod. Audit-logged + alerts owner."""
    result = _user_terminate_k8s(user_sub, pod_id)

    audit_event(
        "admin.compute.force_terminate_pod",
        admin_sub,
        request,
        outcome="warning",
        resource_type="k8s",
        target_user=user_sub,
        pod_id=pod_id,
        reason=reason,
    )
    try:
        write_alert(
            user_sub,
            event="compute.admin_terminated",
            outcome="warning",
            title="An administrator terminated your container",
            details={"pod_id": pod_id, "reason": reason, "resource_type": "k8s"},
        )
    except Exception:
        logger.exception("force_terminate_pod: alert failed for %s", user_sub)

    logger.warning(
        "admin_force_terminate admin_sub=%s target_user=%s resource_type=k8s pod_id=%s reason=%s",
        admin_sub, user_sub, pod_id, reason,
    )
    return _pod_out(result)


# ---------------------------------------------------------------------------
# Platform spending aggregation
# ---------------------------------------------------------------------------

def _scan_month_ticks(month_key: str) -> List[Dict[str, Any]]:
    """All TICK# billing entries for a given month across all users (ByMonth GSI)."""
    items: List[Dict[str, Any]] = []
    from boto3.dynamodb.conditions import Key

    kwargs: Dict[str, Any] = {
        "IndexName": "ByMonth",
        "KeyConditionExpression": Key("month_key").eq(month_key),
    }
    resp = T.compute_billing.query(**kwargs)
    items.extend(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        resp = T.compute_billing.query(**kwargs)
        items.extend(resp.get("Items", []))
    return items


def get_platform_spending(*, month: str | None = None) -> Dict[str, Any]:
    """Aggregate spending across all users for a given month."""
    month_key = month or _current_month_key()
    ticks = _scan_month_ticks(month_key)

    total = ec2_total = k8s_total = 0
    users: set[str] = set()
    for t in ticks:
        amt = int(t.get("amount_cents", 0))
        total += amt
        rt = t.get("resource_type", "")
        if rt == "ec2":
            ec2_total += amt
        elif rt == "k8s":
            k8s_total += amt
        if t.get("user_sub"):
            users.add(t["user_sub"])

    # Count active resources from the resource tables.
    active_instances = _scan_all(
        T.ec2_instances,
        item_filter=lambda i: "instance_id" in i and i.get("status") in ("running", "launching", "stopping"),
    )
    active_pods = _scan_all(
        T.k8s_pods,
        item_filter=lambda p: "pod_id" in p and p.get("status") in ("running", "pending"),
    )

    return {
        "month": month_key,
        "total_cents": total,
        "ec2_total_cents": ec2_total,
        "k8s_total_cents": k8s_total,
        "active_user_count": len(users),
        "active_instance_count": len(active_instances),
        "active_pod_count": len(active_pods),
    }


def get_per_user_spending(*, month: str | None = None, limit: int = 50) -> Dict[str, Any]:
    """Per-user spending breakdown, sorted by total descending."""
    month_key = month or _current_month_key()
    ticks = _scan_month_ticks(month_key)

    by_user: Dict[str, Dict[str, int]] = {}
    for t in ticks:
        us = t.get("user_sub", "")
        if not us:
            continue
        entry = by_user.setdefault(us, {"total": 0, "ec2": 0, "k8s": 0})
        amt = int(t.get("amount_cents", 0))
        entry["total"] += amt
        if t.get("resource_type") == "ec2":
            entry["ec2"] += amt
        elif t.get("resource_type") == "k8s":
            entry["k8s"] += amt

    # Resource counts per user.
    inst_counts: Dict[str, int] = {}
    for i in _scan_all(T.ec2_instances, item_filter=lambda x: "instance_id" in x and x.get("status") not in ("terminated",)):
        inst_counts[i.get("user_sub", "")] = inst_counts.get(i.get("user_sub", ""), 0) + 1
    pod_counts: Dict[str, int] = {}
    for p in _scan_all(T.k8s_pods, item_filter=lambda x: "pod_id" in x and x.get("status") not in ("terminated",)):
        pod_counts[p.get("user_sub", "")] = pod_counts.get(p.get("user_sub", ""), 0) + 1

    rows = [
        {
            "user_sub": us,
            "total_cents": v["total"],
            "ec2_cents": v["ec2"],
            "k8s_cents": v["k8s"],
            "instance_count": inst_counts.get(us, 0),
            "pod_count": pod_counts.get(us, 0),
        }
        for us, v in by_user.items()
    ]
    rows.sort(key=lambda r: r["total_cents"], reverse=True)

    return {"users": rows[:limit], "month": month_key}


def get_instance_type_stats() -> Dict[str, Any]:
    """Instance type popularity: running + total launched counts per type."""
    instances = _scan_all(T.ec2_instances, item_filter=lambda i: "instance_id" in i)

    running: Dict[str, int] = {}
    total: Dict[str, int] = {}
    for i in instances:
        it = i.get("instance_type", "")
        if not it:
            continue
        total[it] = total.get(it, 0) + 1
        if i.get("status") == "running":
            running[it] = running.get(it, 0) + 1

    # Include known types even with zero usage for stable display.
    all_types = set(total) | set(INSTANCE_TYPES.keys())
    stats = [
        {
            "instance_type": it,
            "running_count": running.get(it, 0),
            "total_launched": total.get(it, 0),
        }
        for it in all_types
    ]
    stats.sort(key=lambda s: (s["running_count"], s["total_launched"]), reverse=True)
    return {"stats": stats}


# ---------------------------------------------------------------------------
# Per-user quotas
# ---------------------------------------------------------------------------

def _default_quota(user_sub: str) -> Dict[str, Any]:
    return {
        "user_sub": user_sub,
        "max_ec2_instances": S.compute_quota_default_max_ec2,
        "max_k8s_pods": S.compute_quota_default_max_k8s,
        "max_monthly_spend_cents": S.compute_quota_default_max_spend_cents,
        "allowed_instance_types": [],
        "allowed_k8s_presets": [],
        "is_custom": False,
        "updated_at": 0,
        "updated_by": "",
        "notes": "",
    }


def _coerce_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, (set, list, tuple)):
        return [str(x) for x in v]
    return []


def get_quota(user_sub: str) -> Dict[str, Any]:
    """Get a user's compute quotas. Returns defaults if no custom quota set."""
    resp = T.compute_quotas.get_item(Key={"user_sub": user_sub})
    item = resp.get("Item")
    if not item:
        return _default_quota(user_sub)
    return {
        "user_sub": user_sub,
        "max_ec2_instances": int(item.get("max_ec2_instances", S.compute_quota_default_max_ec2)),
        "max_k8s_pods": int(item.get("max_k8s_pods", S.compute_quota_default_max_k8s)),
        "max_monthly_spend_cents": int(item.get("max_monthly_spend_cents", S.compute_quota_default_max_spend_cents)),
        "allowed_instance_types": _coerce_list(item.get("allowed_instance_types")),
        "allowed_k8s_presets": _coerce_list(item.get("allowed_k8s_presets")),
        "is_custom": True,
        "updated_at": int(item.get("updated_at", 0)),
        "updated_by": item.get("updated_by", ""),
        "notes": item.get("notes", ""),
    }


class InvalidInstanceType(Exception):
    pass


def set_quota(
    admin_sub: str,
    user_sub: str,
    *,
    max_ec2_instances: int,
    max_k8s_pods: int,
    max_monthly_spend_cents: int,
    allowed_instance_types: list[str] | None = None,
    allowed_k8s_presets: list[str] | None = None,
    notes: str = "",
    request=None,
) -> Dict[str, Any]:
    """Set/update a user's compute quotas. Root-only (enforced at router)."""
    allowed_instance_types = allowed_instance_types or []
    allowed_k8s_presets = allowed_k8s_presets or []

    for it in allowed_instance_types:
        if it not in INSTANCE_TYPES:
            raise InvalidInstanceType(f"Unknown instance type: {it}")
    for ps in allowed_k8s_presets:
        if ps not in RESOURCE_PRESETS:
            raise InvalidInstanceType(f"Unknown K8s preset: {ps}")

    ts = now_ts()
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "max_ec2_instances": max_ec2_instances,
        "max_k8s_pods": max_k8s_pods,
        "max_monthly_spend_cents": max_monthly_spend_cents,
        "allowed_instance_types": allowed_instance_types,
        "allowed_k8s_presets": allowed_k8s_presets,
        "updated_at": ts,
        "updated_by": admin_sub,
        "notes": notes,
    }
    T.compute_quotas.put_item(Item=item)

    audit_event(
        "admin.compute.set_quota",
        admin_sub,
        request,
        outcome="success",
        target_user=user_sub,
        max_ec2_instances=max_ec2_instances,
        max_k8s_pods=max_k8s_pods,
        max_monthly_spend_cents=max_monthly_spend_cents,
    )
    logger.info(
        "admin_quota_set admin_sub=%s target_user=%s max_ec2=%d max_k8s=%d max_spend_cents=%d",
        admin_sub, user_sub, max_ec2_instances, max_k8s_pods, max_monthly_spend_cents,
    )
    return get_quota(user_sub)


def delete_quota(admin_sub: str, user_sub: str, *, request=None) -> bool:
    """Remove custom quotas for a user (reverts to platform defaults). Root-only."""
    T.compute_quotas.delete_item(Key={"user_sub": user_sub})
    audit_event(
        "admin.compute.delete_quota",
        admin_sub,
        request,
        outcome="success",
        target_user=user_sub,
    )
    logger.info("admin_quota_deleted admin_sub=%s target_user=%s", admin_sub, user_sub)
    return True


# ---------------------------------------------------------------------------
# Quota enforcement (called from launchers)
# ---------------------------------------------------------------------------

class QuotaExceeded(Exception):
    pass


class SpendingLimitReached(Exception):
    pass


def enforce_ec2_quota(user_sub: str, instance_type: str) -> None:
    """Raise if launching an EC2 instance would violate the user's quota."""
    quota = get_quota(user_sub)

    from app.services.ec2_launcher import list_instances
    active = [
        i for i in list_instances(user_sub)
        if i.get("status") in ("running", "stopped", "launching", "stopping")
    ]
    if len(active) >= quota["max_ec2_instances"]:
        raise QuotaExceeded(f"Maximum {quota['max_ec2_instances']} instances allowed")

    if quota["allowed_instance_types"] and instance_type not in quota["allowed_instance_types"]:
        raise QuotaExceeded(f"Instance type {instance_type} not allowed by your quota")

    _check_spend(user_sub, quota)


def enforce_k8s_quota(user_sub: str, preset: str) -> None:
    """Raise if launching a K8s pod would violate the user's quota."""
    quota = get_quota(user_sub)

    from app.services.k8s_launcher import list_pods
    active = [p for p in list_pods(user_sub) if p.get("status") in ("running", "pending")]
    if len(active) >= quota["max_k8s_pods"]:
        raise QuotaExceeded(f"Maximum {quota['max_k8s_pods']} pods allowed")

    if quota["allowed_k8s_presets"] and preset not in quota["allowed_k8s_presets"]:
        raise QuotaExceeded(f"Preset {preset} not allowed by your quota")

    _check_spend(user_sub, quota)


def _check_spend(user_sub: str, quota: Dict[str, Any]) -> None:
    try:
        from app.services.compute_billing import get_monthly_summary
        summary = get_monthly_summary(user_sub)
        if summary["total_cents"] >= quota["max_monthly_spend_cents"]:
            raise SpendingLimitReached("Monthly spending limit reached")
    except SpendingLimitReached:
        raise
    except Exception:
        logger.exception("quota spend check failed for %s", user_sub)
