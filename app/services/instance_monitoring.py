"""Instance Monitoring & Health (INFRA-008).

Per-instance, OWNER-scoped resource monitoring. Distinct from INFRA-012
(admin cross-user view): this records metric datapoints (cpu_pct, mem_pct,
disk_pct, network, status) into the `instance_metrics` time-series table,
serves latest + time-series queries, and derives a deterministic health
status (healthy / warning / critical / unknown) from configurable thresholds.

Storage layout (`instance_metrics` table):
    PK: instance_id
    SK: TS#{ts:010d}
    ts (N): unix seconds (also the ByTs GSI sort key)
    cpu_pct, mem_pct, disk_pct, net_in_kbps, net_out_kbps (N, ints)
    status (S)

There is no real CloudWatch in the mock — datapoints arrive via the
ingest endpoint, or are deterministically seeded for tests.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ec2_launcher import get_instance

logger = logging.getLogger(__name__)

HEALTH_HEALTHY = "healthy"
HEALTH_WARNING = "warning"
HEALTH_CRITICAL = "critical"
HEALTH_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InstanceNotOwned(Exception):
    """The instance does not exist for this owner (404/403 boundary)."""


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------

def require_owned_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Return the owner's instance item or raise InstanceNotOwned.

    Instances are owner-scoped: get_instance keys on (user_sub, instance_id),
    so a miss means either nonexistent or owned by someone else. Either way
    the caller may not access its metrics.
    """
    item = get_instance(user_sub, instance_id)
    if not item:
        raise InstanceNotOwned(f"Instance {instance_id} not found for this user")
    return item


def resolve_owned_resource(
    user_sub: str, resource_id: str
) -> Tuple[Dict[str, Any], str]:
    """Resolve a compute resource owned by ``user_sub`` as either EC2 or K8s.

    Returns ``(item, resource_type)`` where ``resource_type`` is ``"ec2"`` or
    ``"k8s"``. EC2 is checked first (keyed ``INSTANCE#``), then K8s (``POD#``).
    Raises ``InstanceNotOwned`` if neither table holds an item for this owner.

    This is the shared ownership boundary for the restart-policy and timeline
    endpoints, which must work for both EC2 instances and K8s pods (GAP-0230,
    GAP-0231).
    """
    ec2 = get_instance(user_sub, resource_id)
    if ec2:
        return ec2, "ec2"

    # Lazy import so the kubernetes-less / EC2-only paths stay light.
    from app.services.k8s_launcher import get_pod

    pod = get_pod(user_sub, resource_id)
    if pod:
        return pod, "k8s"

    raise InstanceNotOwned(f"Resource {resource_id} not found for this user")


# ---------------------------------------------------------------------------
# Thresholds + health derivation
# ---------------------------------------------------------------------------

def thresholds() -> Dict[str, int]:
    return {
        "cpu_warning_pct": S.instance_monitoring_cpu_warning_pct,
        "cpu_critical_pct": S.instance_monitoring_cpu_critical_pct,
        "mem_warning_pct": S.instance_monitoring_mem_warning_pct,
        "mem_critical_pct": S.instance_monitoring_mem_critical_pct,
        "disk_warning_pct": S.instance_monitoring_disk_warning_pct,
        "disk_critical_pct": S.instance_monitoring_disk_critical_pct,
    }


def derive_health(
    point: Optional[Dict[str, Any]],
    *,
    instance_status: str = "",
) -> Dict[str, Any]:
    """Deterministically derive health from the latest datapoint + thresholds.

    Returns {"health_status": str, "reasons": [str], "cpu_pct", "mem_pct",
    "disk_pct"}. No randomness — same inputs always yield the same output.
    """
    th = thresholds()

    # An instance that isn't running has no meaningful resource health.
    if instance_status and instance_status not in ("running",):
        return {
            "health_status": HEALTH_UNKNOWN,
            "reasons": [f"instance status is '{instance_status}'"],
            "cpu_pct": 0,
            "mem_pct": 0,
            "disk_pct": 0,
        }

    if not point:
        return {
            "health_status": HEALTH_UNKNOWN,
            "reasons": ["no metric datapoints recorded"],
            "cpu_pct": 0,
            "mem_pct": 0,
            "disk_pct": 0,
        }

    cpu = int(point.get("cpu_pct", 0))
    mem = int(point.get("mem_pct", 0))
    disk = int(point.get("disk_pct", 0))
    status = str(point.get("status", "running"))

    reasons: List[str] = []
    level = 0  # 0 healthy, 1 warning, 2 critical

    def _bump(metric: str, value: int, warn: int, crit: int) -> None:
        nonlocal level
        if value >= crit:
            level = max(level, 2)
            reasons.append(f"{metric} {value}% >= critical {crit}%")
        elif value >= warn:
            level = max(level, 1)
            reasons.append(f"{metric} {value}% >= warning {warn}%")

    _bump("cpu", cpu, th["cpu_warning_pct"], th["cpu_critical_pct"])
    _bump("mem", mem, th["mem_warning_pct"], th["mem_critical_pct"])
    _bump("disk", disk, th["disk_warning_pct"], th["disk_critical_pct"])

    # A reported non-running status from the datapoint itself is critical.
    if status in ("unreachable", "stopped", "error", "crashed"):
        level = max(level, 2)
        reasons.append(f"reported status '{status}'")

    health = {0: HEALTH_HEALTHY, 1: HEALTH_WARNING, 2: HEALTH_CRITICAL}[level]
    return {
        "health_status": health,
        "reasons": reasons,
        "cpu_pct": cpu,
        "mem_pct": mem,
        "disk_pct": disk,
    }


# ---------------------------------------------------------------------------
# Datapoint storage
# ---------------------------------------------------------------------------

def _point_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "instance_id": item.get("instance_id", ""),
        "ts": int(item.get("ts", 0)),
        "cpu_pct": int(item.get("cpu_pct", 0)),
        "mem_pct": int(item.get("mem_pct", 0)),
        "disk_pct": int(item.get("disk_pct", 0)),
        "net_in_kbps": int(item.get("net_in_kbps", 0)),
        "net_out_kbps": int(item.get("net_out_kbps", 0)),
        "status": str(item.get("status", "running")),
    }


def _store_point(
    instance_id: str,
    *,
    ts: int,
    cpu_pct: int,
    mem_pct: int,
    disk_pct: int,
    net_in_kbps: int,
    net_out_kbps: int,
    status: str,
) -> Dict[str, Any]:
    item = {
        "instance_id": instance_id,
        "sk": f"TS#{ts:010d}",
        "ts": int(ts),
        "cpu_pct": int(cpu_pct),
        "mem_pct": int(mem_pct),
        "disk_pct": int(disk_pct),
        "net_in_kbps": int(net_in_kbps),
        "net_out_kbps": int(net_out_kbps),
        "status": status,
        "ttl": int(ts) + int(S.instance_monitoring_ttl_seconds),
    }
    T.instance_metrics.put_item(Item=item)
    return item


def ingest_datapoint(
    user_sub: str,
    instance_id: str,
    *,
    cpu_pct: int,
    mem_pct: int,
    disk_pct: int,
    net_in_kbps: int = 0,
    net_out_kbps: int = 0,
    status: str = "running",
    ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Record one metric datapoint for an owned instance.

    Returns {"point": <stored point>, "health_status": str}. Fires a health
    alert when monitoring alerts are enabled and the derived status is
    warning/critical.
    """
    instance = require_owned_instance(user_sub, instance_id)
    point_ts = int(ts) if ts is not None else now_ts()

    stored = _store_point(
        instance_id,
        ts=point_ts,
        cpu_pct=cpu_pct,
        mem_pct=mem_pct,
        disk_pct=disk_pct,
        net_in_kbps=net_in_kbps,
        net_out_kbps=net_out_kbps,
        status=status,
    )
    point = _point_from_item(stored)

    health = derive_health(point, instance_status=instance.get("status", ""))
    _retain(instance_id)

    if S.instance_monitoring_alerts_enabled and health["health_status"] in (
        HEALTH_WARNING,
        HEALTH_CRITICAL,
    ):
        _maybe_alert(user_sub, instance, health)

    # GAP-0230: when a critical datapoint arrives and auto-restart is enabled
    # both globally (flag) and per-instance, evaluate the restart policy. Gated
    # OFF by default so dev/test never auto-restarts (SECOPS-007).
    if (
        S.instance_monitoring_auto_restart_enabled
        and health["health_status"] == HEALTH_CRITICAL
    ):
        try:
            _check_restart_policy(user_sub, instance, health, resource_type="ec2")
        except Exception:
            logger.exception(
                "instance_restart_policy_check_failed user_sub=%s instance_id=%s",
                user_sub, instance_id,
            )

    logger.info(
        "instance_monitoring_ingest user_sub=%s instance_id=%s health=%s cpu=%d mem=%d disk=%d",
        user_sub, instance_id, health["health_status"], cpu_pct, mem_pct, disk_pct,
    )
    return {"point": point, "health_status": health["health_status"], "ts": point_ts}


def _maybe_alert(user_sub: str, instance: Dict[str, Any], health: Dict[str, Any]) -> None:
    try:
        from app.services.alerts import write_alert
        label = instance.get("label") or instance.get("instance_id", "")
        write_alert(
            user_sub,
            event="compute.instance_health",
            outcome="warning" if health["health_status"] == HEALTH_WARNING else "error",
            title=f"{label} health is {health['health_status']}",
            details={
                "instance_id": instance.get("instance_id", ""),
                "health_status": health["health_status"],
                "reasons": "; ".join(health.get("reasons", [])),
            },
        )
    except Exception:
        logger.exception("instance_monitoring_alert_failed instance_id=%s", instance.get("instance_id"))


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def _retain(instance_id: str) -> None:
    """Trim stored datapoints to the configured retention cap (oldest first)."""
    cap = max(1, int(S.instance_monitoring_retention_points))
    resp = T.instance_metrics.query(
        IndexName="ByTs",
        KeyConditionExpression=Key("instance_id").eq(instance_id),
        ScanIndexForward=True,  # oldest first
        ProjectionExpression="instance_id, sk, ts",
    )
    items = resp.get("Items", [])
    excess = len(items) - cap
    if excess <= 0:
        return
    for old in items[:excess]:
        try:
            T.instance_metrics.delete_item(
                Key={"instance_id": instance_id, "sk": old["sk"]}
            )
        except Exception:
            logger.exception("instance_monitoring_retain_delete_failed instance_id=%s", instance_id)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def get_latest(user_sub: str, instance_id: str) -> Optional[Dict[str, Any]]:
    """Return the most recent datapoint for an owned instance, or None."""
    require_owned_instance(user_sub, instance_id)
    resp = T.instance_metrics.query(
        IndexName="ByTs",
        KeyConditionExpression=Key("instance_id").eq(instance_id),
        ScanIndexForward=False,  # newest first
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _point_from_item(items[0])


def get_timeseries(
    user_sub: str,
    instance_id: str,
    *,
    limit: int = 100,
    since: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return recent datapoints for an owned instance, newest first.

    `limit` is capped at instance_monitoring_max_query_points. `since`
    restricts to datapoints with ts >= since.
    """
    require_owned_instance(user_sub, instance_id)
    cap = int(S.instance_monitoring_max_query_points)
    eff_limit = max(1, min(int(limit), cap))

    key = Key("instance_id").eq(instance_id)
    if since is not None:
        key = key & Key("ts").gte(int(since))

    resp = T.instance_metrics.query(
        IndexName="ByTs",
        KeyConditionExpression=key,
        ScanIndexForward=False,  # newest first
        Limit=eff_limit,
    )
    return [_point_from_item(i) for i in resp.get("Items", [])]


def get_health(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Compute the current health summary for an owned instance."""
    instance = require_owned_instance(user_sub, instance_id)
    latest = get_latest(user_sub, instance_id)
    th = thresholds()

    # datapoint count (bounded scan of the index)
    resp = T.instance_metrics.query(
        IndexName="ByTs",
        KeyConditionExpression=Key("instance_id").eq(instance_id),
        Select="COUNT",
    )
    count = int(resp.get("Count", 0))

    derived = derive_health(latest, instance_status=instance.get("status", ""))
    return {
        "instance_id": instance_id,
        "instance_type": instance.get("instance_type", ""),
        "instance_status": instance.get("status", ""),
        "health_status": derived["health_status"],
        "reasons": derived["reasons"],
        "cpu_pct": derived["cpu_pct"],
        "mem_pct": derived["mem_pct"],
        "disk_pct": derived["disk_pct"],
        "datapoints": count,
        "last_metric_ts": int(latest["ts"]) if latest else 0,
        "checked_at": now_ts(),
        "thresholds": th,
    }


# ---------------------------------------------------------------------------
# Lifecycle event timeline (GAP-0231)
#
# Timeline items live in the SAME table as the resource they describe
# (ec2_instances / k8s_pods), under a TIMELINE# sort-key prefix on the owner's
# partition. This is the single-table pattern called for by INFRA-008:
#     PK: user_sub
#     SK: TIMELINE#{resource_id}#{ts:010d}#{event_id}
# The zero-padded ts makes the lexical SK order match chronological order, so a
# ScanIndexForward=False query returns events newest-first with no client sort.
# ---------------------------------------------------------------------------

def _timeline_table(resource_type: str):
    return T.k8s_pods if resource_type == "k8s" else T.ec2_instances


def record_timeline_event(
    user_sub: str,
    resource_id: str,
    event_type: str,
    *,
    resource_type: str = "ec2",
    detail: Optional[Dict[str, Any]] = None,
    ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Write one TIMELINE item recording a lifecycle event (best-effort).

    Timeline writes must NEVER block or roll back the lifecycle operation that
    triggered them, so all exceptions are swallowed (logged). Returns the item
    that was written (or attempted).
    """
    event_ts = int(ts) if ts is not None else now_ts()
    event_id = uuid.uuid4().hex[:12]
    item = {
        "user_sub": user_sub,
        "sk": f"TIMELINE#{resource_id}#{event_ts:010d}#{event_id}",
        "resource_id": resource_id,
        "resource_type": resource_type,
        "event_type": event_type,
        "ts": event_ts,
        "event_id": event_id,
        "detail": detail or {},
    }
    try:
        _timeline_table(resource_type).put_item(Item=item)
        logger.info(
            "instance_timeline_event user_sub=%s resource_id=%s type=%s event_id=%s",
            user_sub, resource_id, event_type, event_id,
        )
    except Exception:
        logger.exception(
            "instance_timeline_write_failed user_sub=%s resource_id=%s type=%s",
            user_sub, resource_id, event_type,
        )
    return item


def list_timeline_events(
    user_sub: str,
    resource_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Return lifecycle events for an owned resource, newest first.

    Resolves the resource (EC2 or K8s) to enforce the ownership boundary, then
    queries the owning table for the TIMELINE# SK prefix.
    """
    _, resource_type = resolve_owned_resource(user_sub, resource_id)
    eff_limit = max(1, min(int(limit), 200))
    resp = _timeline_table(resource_type).query(
        KeyConditionExpression=Key("user_sub").eq(user_sub)
        & Key("sk").begins_with(f"TIMELINE#{resource_id}#"),
        ScanIndexForward=False,  # newest first (ts is zero-padded in the SK)
        Limit=eff_limit,
    )
    out: List[Dict[str, Any]] = []
    for it in resp.get("Items", []):
        out.append({
            "event_id": str(it.get("event_id", "")),
            "event_type": str(it.get("event_type", "")),
            "ts": int(it.get("ts", 0)),
            "detail": dict(it.get("detail", {}) or {}),
        })
    return out


# ---------------------------------------------------------------------------
# Auto-restart policy (GAP-0230)
# ---------------------------------------------------------------------------

def _sk_for(resource_type: str, resource_id: str) -> str:
    return f"POD#{resource_id}" if resource_type == "k8s" else f"INSTANCE#{resource_id}"


def update_restart_policy(
    user_sub: str,
    resource_id: str,
    *,
    auto_restart_enabled: Optional[bool] = None,
    max_restarts: Optional[int] = None,
) -> Dict[str, Any]:
    """Set the auto-restart policy for an owned EC2 instance or K8s pod."""
    instance, resource_type = resolve_owned_resource(user_sub, resource_id)

    sets: List[str] = []
    values: Dict[str, Any] = {}
    if auto_restart_enabled is not None:
        sets.append("auto_restart_enabled = :are")
        values[":are"] = bool(auto_restart_enabled)
    if max_restarts is not None:
        if max_restarts < 0 or max_restarts > 10:
            raise ValueError("max_restarts must be 0-10")
        sets.append("max_restarts = :mr")
        values[":mr"] = int(max_restarts)

    table = _timeline_table(resource_type)
    sk = _sk_for(resource_type, resource_id)

    if sets:
        table.update_item(
            Key={"user_sub": user_sub, "sk": sk},
            UpdateExpression="SET " + ", ".join(sets),
            ExpressionAttributeValues=values,
        )
        logger.info(
            "instance_restart_policy_updated user_sub=%s resource_id=%s type=%s",
            user_sub, resource_id, resource_type,
        )

    fresh = table.get_item(Key={"user_sub": user_sub, "sk": sk}).get("Item") or instance
    return {
        "instance_id": resource_id,
        "resource_type": resource_type,
        "auto_restart_enabled": bool(fresh.get("auto_restart_enabled", False)),
        "max_restarts": int(fresh.get("max_restarts", 3)),
        "restart_count": int(fresh.get("restart_count", 0)),
        "last_restart_at": int(fresh.get("last_restart_at", 0)),
    }


def _increment_restart_count(
    user_sub: str, resource_type: str, resource_id: str
) -> None:
    _timeline_table(resource_type).update_item(
        Key={"user_sub": user_sub, "sk": _sk_for(resource_type, resource_id)},
        UpdateExpression=(
            "SET restart_count = if_not_exists(restart_count, :z) + :one, "
            "last_restart_at = :ts"
        ),
        ExpressionAttributeValues={":z": 0, ":one": 1, ":ts": now_ts()},
    )


def _perform_restart(
    user_sub: str, instance: Dict[str, Any], resource_type: str
) -> None:
    """Trigger the appropriate restart action for the resource type.

    Both branches go through the existing launcher functions, so they honour the
    dev mock paths (S.ec2_mock_enabled / S.k8s_mock_enabled) unchanged
    (SECOPS-007). K8s pods cannot be stopped/started, so a restart is a
    terminate + fresh launch.
    """
    if resource_type == "k8s":
        from app.services.k8s_launcher import terminate_pod, launch_pod
        pod_id = instance.get("pod_id") or instance.get("instance_id", "")
        terminate_pod(user_sub, pod_id)
        launch_pod(
            user_sub,
            label=instance.get("label", "Restarted Pod"),
            image=instance.get("image", "ubuntu-ssh"),
            preset=instance.get("preset", "small"),
            ttl_seconds=int(instance.get("ttl_seconds", 14400)),
        )
    else:
        from app.services.ec2_launcher import stop_instance, start_instance
        instance_id = instance.get("instance_id", "")
        stop_instance(user_sub, instance_id)
        start_instance(user_sub, instance_id)


def _check_restart_policy(
    user_sub: str,
    instance: Dict[str, Any],
    health: Dict[str, Any],
    *,
    resource_type: str = "ec2",
) -> bool:
    """Evaluate the auto-restart policy for a resource in critical health.

    Returns True if a restart was initiated and completed, False otherwise. All
    decisions and outcomes are written to the lifecycle timeline (GAP-0231).
    """
    if health.get("health_status") != HEALTH_CRITICAL:
        return False
    if not instance.get("auto_restart_enabled", False):
        return False

    resource_id = instance.get("instance_id") or instance.get("pod_id", "")
    max_restarts = int(instance.get("max_restarts", 3))
    restart_count = int(instance.get("restart_count", 0))

    if restart_count >= max_restarts:
        logger.warning(
            "instance_restart_limit_reached resource_id=%s restart_count=%d max=%d",
            resource_id, restart_count, max_restarts,
        )
        record_timeline_event(
            user_sub, resource_id, "restart_limit_reached",
            resource_type=resource_type,
            detail={"restart_count": restart_count, "max_restarts": max_restarts},
        )
        return False

    record_timeline_event(
        user_sub, resource_id, "auto_restart_initiated",
        resource_type=resource_type,
        detail={
            "restart_count": restart_count + 1,
            "max_restarts": max_restarts,
            "health_reasons": health.get("reasons", []),
        },
    )

    try:
        _perform_restart(user_sub, instance, resource_type)
        _increment_restart_count(user_sub, resource_type, resource_id)
        record_timeline_event(
            user_sub, resource_id, "auto_restart_completed",
            resource_type=resource_type,
            detail={"restart_count": restart_count + 1},
        )
        logger.info(
            "instance_auto_restarted user_sub=%s resource_id=%s restart_count=%d",
            user_sub, resource_id, restart_count + 1,
        )
        return True
    except Exception:
        logger.exception(
            "instance_auto_restart_failed user_sub=%s resource_id=%s",
            user_sub, resource_id,
        )
        record_timeline_event(
            user_sub, resource_id, "auto_restart_failed",
            resource_type=resource_type,
            detail={"error": "restart exception (see logs)"},
        )
        return False


# ---------------------------------------------------------------------------
# Deterministic seeding (tests / demos)
# ---------------------------------------------------------------------------

def seed_metrics(
    user_sub: str,
    instance_id: str,
    *,
    points: int = 20,
    interval_seconds: int = 60,
    base_cpu_pct: int = 30,
    base_mem_pct: int = 40,
    base_disk_pct: int = 20,
) -> int:
    """Deterministically write `points` datapoints ending at now_ts().

    Values follow a fixed sawtooth derived from the index, so a given set of
    parameters always produces the same series (no randomness). Returns the
    number of datapoints written.
    """
    require_owned_instance(user_sub, instance_id)
    end = now_ts()
    written = 0
    for i in range(points):
        # oldest first; newest point is at `end`
        offset = points - 1 - i
        ts = end - offset * interval_seconds
        cpu = _clamp(base_cpu_pct + (i % 10) * 3)
        mem = _clamp(base_mem_pct + (i % 7) * 2)
        disk = _clamp(base_disk_pct + (i % 5))
        _store_point(
            instance_id,
            ts=ts,
            cpu_pct=cpu,
            mem_pct=mem,
            disk_pct=disk,
            net_in_kbps=100 + (i % 12) * 25,
            net_out_kbps=50 + (i % 8) * 15,
            status="running",
        )
        written += 1
    _retain(instance_id)
    logger.info(
        "instance_monitoring_seed user_sub=%s instance_id=%s points=%d",
        user_sub, instance_id, written,
    )
    return written


def _clamp(v: int) -> int:
    return max(0, min(100, int(v)))
