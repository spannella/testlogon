"""Payment provider health monitoring (FIN-014).

Records per-provider success/failure/latency datapoints for payment
operations, computes a health status (healthy/degraded/down), error
rates (bps), latency percentiles (ms), an incident timeline, and an
uptime report.

This module does NOT reimplement billing. It exposes a lightweight
recorder hook (``record_provider_event``) that the existing payment /
webhook path calls when a provider call succeeds or fails. Status and
rollups are computed synchronously over the recorded datapoints, so
seeded data yields deterministic results for E2E tests.

Storage (DynamoDB table ``payment_provider_health``):

  Datapoint rows
    pk = PROVIDER#{provider}
    sk = DP#{ts}#{uuid}
    ts (N), success (BOOL), latency_ms (N), error_type (S), op (S)
    GSI1PK = PROVIDER#{provider}, GSI1SK = ts  (time-ordered query)

  Config row
    pk = PROVIDER#{provider}
    sk = CONFIG
    enabled (BOOL), alert_error_rate_threshold (N, bps),
    alert_latency_threshold_ms (N), alert_email (S),
    disabled_at / disabled_by / disable_reason

  Incident rows
    pk = PROVIDER#{provider}
    sk = INCIDENT#{incident_id}
    GSI1PK = INCIDENTS#ALL, GSI1SK = started_at (N)
    started_at (N), ended_at (N|null), status (S),
    peak_error_rate (N, bps), affected_webhooks (N)
"""

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

PROVIDERS = ["stripe", "paypal", "ccbill"]

STATUS_HEALTHY = "healthy"
STATUS_DEGRADED = "degraded"
STATUS_DOWN = "down"

# Auto-detection thresholds expressed in basis points (bps; 1% = 100 bps).
DEFAULT_DEGRADED_ERROR_BPS = 500    # 5% errors -> degraded
DEFAULT_DOWN_ERROR_BPS = 2500       # 25% errors -> down
DEFAULT_ALERT_ERROR_BPS = 500       # 5% default alert threshold
DEFAULT_ALERT_LATENCY_MS = 500
DEFAULT_DATAPOINT_WINDOW_HOURS = 24


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _provider_pk(provider: str) -> str:
    return f"PROVIDER#{provider}"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(Decimal(str(value)))
    except Exception:
        return default


def _hour_iso(ts: int) -> str:
    dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).replace(
        minute=0, second=0, microsecond=0
    )
    return dt.strftime("%Y-%m-%dT%H:00:00Z")


def normalize_provider(provider: str) -> str:
    return str(provider or "").strip().lower()


def is_known_provider(provider: str) -> bool:
    return normalize_provider(provider) in PROVIDERS


def _error_rate_bps(success: int, failure: int) -> int:
    total = success + failure
    if total <= 0:
        return 0
    return int(round((failure / total) * 10000))


def _success_rate_pct(success: int, failure: int) -> float:
    total = success + failure
    if total <= 0:
        return 100.0
    return round((success / total) * 100.0, 2)


def _status_for_error_bps(error_bps: int, *, has_data: bool) -> str:
    if not has_data:
        return STATUS_HEALTHY
    if error_bps >= DEFAULT_DOWN_ERROR_BPS:
        return STATUS_DOWN
    if error_bps >= DEFAULT_DEGRADED_ERROR_BPS:
        return STATUS_DEGRADED
    return STATUS_HEALTHY


# ---------------------------------------------------------------------------
# Recorder hook (called from the payment / webhook path)
# ---------------------------------------------------------------------------

def record_provider_event(
    *,
    provider: str,
    success: bool,
    latency_ms: int = 0,
    error_type: str = "",
    op: str = "",
    ts: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Record a single provider health datapoint.

    Returns the stored item, or None if the feature is disabled / the
    provider is unknown. Swallows storage errors so it never breaks the
    payment path.
    """
    if not S.payment_provider_health_enabled:
        return None
    prov = normalize_provider(provider)
    if prov not in PROVIDERS:
        return None
    when = int(ts) if ts is not None else now_ts()
    item: Dict[str, Any] = {
        "pk": _provider_pk(prov),
        "sk": f"DP#{when}#{uuid.uuid4().hex}",
        "GSI1PK": _provider_pk(prov),
        "GSI1SK": when,
        "ts": when,
        "success": bool(success),
        "latency_ms": _to_int(latency_ms),
        "error_type": str(error_type or ""),
        "op": str(op or ""),
    }
    try:
        T.payment_provider_health.put_item(Item=item)
    except Exception:
        logger.debug("Failed to record provider health datapoint for %s", prov)
        return None
    return item


# ---------------------------------------------------------------------------
# Datapoint queries
# ---------------------------------------------------------------------------

def _query_datapoints(provider: str, *, since_ts: int, limit: int = 5000) -> List[Dict[str, Any]]:
    prov = normalize_provider(provider)
    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": Key("GSI1PK").eq(_provider_pk(prov))
            & Key("GSI1SK").gte(int(since_ts)),
            "ScanIndexForward": False,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.payment_provider_health.query(**kwargs)
        except Exception:
            logger.debug("Failed to query provider health datapoints for %s", prov)
            break
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) >= limit:
            break
    return items[:limit]


def _percentile(sorted_vals: List[int], pct: float) -> int:
    if not sorted_vals:
        return 0
    if len(sorted_vals) == 1:
        return int(sorted_vals[0])
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = rank - lo
    return int(round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac))


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_provider_status(provider: str, *, hours: int = DEFAULT_DATAPOINT_WINDOW_HOURS) -> Dict[str, Any]:
    """Current health status for a provider over the trailing window."""
    prov = normalize_provider(provider)
    since = now_ts() - hours * 3600
    dps = _query_datapoints(prov, since_ts=since)
    config = get_provider_config(prov)

    success = sum(1 for d in dps if bool(d.get("success")))
    failure = len(dps) - success
    latencies = sorted(_to_int(d.get("latency_ms")) for d in dps)
    avg_latency = int(round(sum(latencies) / len(latencies))) if latencies else 0
    has_data = len(dps) > 0
    error_bps = _error_rate_bps(success, failure)
    status = _status_for_error_bps(error_bps, has_data=has_data)
    last_check = max((_to_int(d.get("ts")) for d in dps), default=0)

    return {
        "provider": prov,
        "status": status,
        "enabled": bool(config.get("enabled", True)),
        "success_rate": _success_rate_pct(success, failure),
        "error_rate_bps": error_bps,
        "avg_latency_ms": avg_latency,
        "p50_latency_ms": _percentile(latencies, 50),
        "p95_latency_ms": _percentile(latencies, 95),
        "p99_latency_ms": _percentile(latencies, 99),
        "total_success": success,
        "total_failure": failure,
        "last_check_at": last_check,
    }


def get_all_providers_status(*, hours: int = DEFAULT_DATAPOINT_WINDOW_HOURS) -> List[Dict[str, Any]]:
    return [get_provider_status(p, hours=hours) for p in PROVIDERS]


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def get_health_timeline(provider: str, *, hours: int = 24) -> Dict[str, Any]:
    """Hourly health snapshots for the timeline chart."""
    prov = normalize_provider(provider)
    since = now_ts() - hours * 3600
    dps = _query_datapoints(prov, since_ts=since)

    buckets: Dict[str, Dict[str, Any]] = {}
    for d in dps:
        hour = _hour_iso(_to_int(d.get("ts")))
        b = buckets.setdefault(
            hour, {"hour": hour, "success": 0, "failure": 0, "_lat_sum": 0, "_lat_n": 0}
        )
        if bool(d.get("success")):
            b["success"] += 1
        else:
            b["failure"] += 1
        b["_lat_sum"] += _to_int(d.get("latency_ms"))
        b["_lat_n"] += 1

    data: List[Dict[str, Any]] = []
    for hour in sorted(buckets.keys()):
        b = buckets[hour]
        n = b.pop("_lat_n")
        s = b.pop("_lat_sum")
        b["avg_latency_ms"] = int(round(s / n)) if n else 0
        b["status"] = _status_for_error_bps(
            _error_rate_bps(b["success"], b["failure"]), has_data=(n > 0)
        )
        data.append(b)

    return {"provider": prov, "hours": hours, "data": data}


# ---------------------------------------------------------------------------
# Error drilldown
# ---------------------------------------------------------------------------

def get_error_drilldown(provider: str, *, hours: int = 24, recent_limit: int = 100) -> Dict[str, Any]:
    prov = normalize_provider(provider)
    since = now_ts() - hours * 3600
    dps = _query_datapoints(prov, since_ts=since)

    error_types: Dict[str, int] = {}
    recent: List[Dict[str, Any]] = []
    for d in dps:
        if bool(d.get("success")):
            continue
        etype = str(d.get("error_type") or "unknown")
        error_types[etype] = error_types.get(etype, 0) + 1
        if len(recent) < recent_limit:
            recent.append(
                {
                    "ts": _to_int(d.get("ts")),
                    "provider": prov,
                    "error_type": etype,
                    "op": str(d.get("op") or ""),
                    "latency_ms": _to_int(d.get("latency_ms")),
                }
            )

    recent.sort(key=lambda r: r["ts"], reverse=True)
    return {"provider": prov, "error_types": error_types, "recent_failures": recent}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _config_defaults(provider: str) -> Dict[str, Any]:
    return {
        "provider": provider,
        "enabled": True,
        "alert_error_rate_threshold": DEFAULT_ALERT_ERROR_BPS,
        "alert_latency_threshold_ms": DEFAULT_ALERT_LATENCY_MS,
        "alert_email": "",
        "disabled_at": None,
        "disabled_by": "",
        "disable_reason": "",
    }


def get_provider_config(provider: str) -> Dict[str, Any]:
    prov = normalize_provider(provider)
    defaults = _config_defaults(prov)
    try:
        item = T.payment_provider_health.get_item(
            Key={"pk": _provider_pk(prov), "sk": "CONFIG"}
        ).get("Item")
    except Exception:
        item = None
    if not item:
        return defaults
    return {
        "provider": prov,
        "enabled": bool(item.get("enabled", True)),
        "alert_error_rate_threshold": _to_int(
            item.get("alert_error_rate_threshold"), DEFAULT_ALERT_ERROR_BPS
        ),
        "alert_latency_threshold_ms": _to_int(
            item.get("alert_latency_threshold_ms"), DEFAULT_ALERT_LATENCY_MS
        ),
        "alert_email": str(item.get("alert_email") or ""),
        "disabled_at": _to_int(item.get("disabled_at")) or None,
        "disabled_by": str(item.get("disabled_by") or ""),
        "disable_reason": str(item.get("disable_reason") or ""),
    }


def update_provider_config(
    provider: str,
    *,
    admin_sub: str,
    alert_error_rate_threshold: Optional[int] = None,
    alert_latency_threshold_ms: Optional[int] = None,
    alert_email: Optional[str] = None,
) -> Dict[str, Any]:
    prov = normalize_provider(provider)
    current = get_provider_config(prov)
    item = {
        "pk": _provider_pk(prov),
        "sk": "CONFIG",
        "enabled": bool(current.get("enabled", True)),
        "alert_error_rate_threshold": (
            _to_int(alert_error_rate_threshold)
            if alert_error_rate_threshold is not None
            else _to_int(current["alert_error_rate_threshold"])
        ),
        "alert_latency_threshold_ms": (
            _to_int(alert_latency_threshold_ms)
            if alert_latency_threshold_ms is not None
            else _to_int(current["alert_latency_threshold_ms"])
        ),
        "alert_email": (
            str(alert_email) if alert_email is not None else str(current.get("alert_email") or "")
        ),
        "disabled_at": current.get("disabled_at") or None,
        "disabled_by": str(current.get("disabled_by") or ""),
        "disable_reason": str(current.get("disable_reason") or ""),
        "updated_at": now_ts(),
        "updated_by": str(admin_sub or ""),
    }
    # DynamoDB cannot store None values directly.
    store = {k: v for k, v in item.items() if v is not None}
    T.payment_provider_health.put_item(Item=store)
    return get_provider_config(prov)


def toggle_provider(
    provider: str,
    *,
    enabled: bool,
    admin_sub: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Enable or disable a payment provider (idempotent)."""
    prov = normalize_provider(provider)
    current = get_provider_config(prov)
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _provider_pk(prov),
        "sk": "CONFIG",
        "enabled": bool(enabled),
        "alert_error_rate_threshold": _to_int(current["alert_error_rate_threshold"]),
        "alert_latency_threshold_ms": _to_int(current["alert_latency_threshold_ms"]),
        "alert_email": str(current.get("alert_email") or ""),
        "updated_at": ts,
        "updated_by": str(admin_sub or ""),
    }
    if enabled:
        item["disabled_at"] = None
        item["disabled_by"] = ""
        item["disable_reason"] = ""
    else:
        item["disabled_at"] = ts
        item["disabled_by"] = str(admin_sub or "")
        item["disable_reason"] = str(reason or "")[:500]

    store = {k: v for k, v in item.items() if v is not None}
    T.payment_provider_health.put_item(Item=store)
    return {
        "provider": prov,
        "enabled": bool(enabled),
        "toggled_at": ts,
        "reason": str(reason or "") if not enabled else "",
    }


def is_provider_enabled(provider: str) -> bool:
    """Whether a provider is currently accepting new payment initiation."""
    return bool(get_provider_config(provider).get("enabled", True))


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def create_incident(
    provider: str,
    *,
    status: str = STATUS_DEGRADED,
    peak_error_rate: int = 0,
    affected_webhooks: int = 0,
    started_at: Optional[int] = None,
) -> Dict[str, Any]:
    prov = normalize_provider(provider)
    incident_id = uuid.uuid4().hex
    start = int(started_at) if started_at is not None else now_ts()
    item = {
        "pk": _provider_pk(prov),
        "sk": f"INCIDENT#{incident_id}",
        "GSI1PK": "INCIDENTS#ALL",
        "GSI1SK": start,
        "incident_id": incident_id,
        "provider": prov,
        "started_at": start,
        "ended_at": None,
        "status": str(status),
        "peak_error_rate": _to_int(peak_error_rate),
        "affected_webhooks": _to_int(affected_webhooks),
    }
    store = {k: v for k, v in item.items() if v is not None}
    T.payment_provider_health.put_item(Item=store)
    return _incident_out(store)


def resolve_incident(provider: str, incident_id: str, *, ended_at: Optional[int] = None) -> Optional[Dict[str, Any]]:
    prov = normalize_provider(provider)
    end = int(ended_at) if ended_at is not None else now_ts()
    try:
        resp = T.payment_provider_health.update_item(
            Key={"pk": _provider_pk(prov), "sk": f"INCIDENT#{incident_id}"},
            UpdateExpression="SET ended_at = :e",
            ConditionExpression="attribute_exists(pk)",
            ExpressionAttributeValues={":e": end},
            ReturnValues="ALL_NEW",
        )
    except Exception:
        return None
    return _incident_out(resp.get("Attributes", {}))


def _incident_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "incident_id": str(item.get("incident_id") or ""),
        "provider": str(item.get("provider") or ""),
        "started_at": _to_int(item.get("started_at")),
        "ended_at": (_to_int(item.get("ended_at")) if item.get("ended_at") is not None else None),
        "status": str(item.get("status") or STATUS_DEGRADED),
        "peak_error_rate": _to_int(item.get("peak_error_rate")),
        "affected_webhooks": _to_int(item.get("affected_webhooks")),
    }


def get_incidents(*, provider: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    if provider:
        prov = normalize_provider(provider)
        try:
            resp = T.payment_provider_health.query(
                KeyConditionExpression=Key("pk").eq(_provider_pk(prov))
                & Key("sk").begins_with("INCIDENT#"),
            )
            items = resp.get("Items", [])
        except Exception:
            items = []
    else:
        try:
            resp = T.payment_provider_health.query(
                IndexName="GSI1",
                KeyConditionExpression=Key("GSI1PK").eq("INCIDENTS#ALL"),
                ScanIndexForward=False,
            )
            items = resp.get("Items", [])
        except Exception:
            items = []
    out = [_incident_out(i) for i in items]
    out.sort(key=lambda i: i["started_at"], reverse=True)
    return out[:limit]


# ---------------------------------------------------------------------------
# Uptime report
# ---------------------------------------------------------------------------

def get_uptime_report(provider: str, *, days: int = 30) -> Dict[str, Any]:
    prov = normalize_provider(provider)
    window_start = now_ts() - days * 86400
    now = now_ts()
    window_seconds = max(days * 86400, 1)

    incidents = [i for i in get_incidents(provider=prov, limit=500)]
    total_downtime = 0
    counted = 0
    for inc in incidents:
        start = max(inc["started_at"], window_start)
        end = inc["ended_at"] if inc["ended_at"] is not None else now
        end = min(end, now)
        if end <= window_start or start >= now:
            continue
        # Only "down" incidents count against uptime; degraded is partial.
        if inc["status"] == STATUS_DOWN:
            total_downtime += max(end - start, 0)
        counted += 1

    uptime_pct = round(max(0.0, (window_seconds - total_downtime) / window_seconds) * 100.0, 2)
    return {
        "provider": prov,
        "days": days,
        "uptime_pct": uptime_pct,
        "total_incidents": counted,
        "total_downtime_minutes": int(total_downtime // 60),
    }


# ---------------------------------------------------------------------------
# Alerting (used by background health check task / synchronous check)
# ---------------------------------------------------------------------------

def check_and_alert(provider: str) -> Optional[Dict[str, Any]]:
    """Evaluate provider thresholds and deliver an alert when breached.

    Returns the alert payload if the provider exceeds a configured threshold,
    otherwise ``None``. When a breach is detected and no per-provider alert
    cooldown is active (GAP-0205), the alert is delivered via the platform
    email + in-app notification services through :func:`_dispatch_alert` before
    the payload is returned.
    """
    prov = normalize_provider(provider)
    status = get_provider_status(prov)
    config = get_provider_config(prov)
    if status["total_success"] + status["total_failure"] == 0:
        return None

    breaches: List[str] = []
    if status["error_rate_bps"] >= _to_int(config["alert_error_rate_threshold"]):
        breaches.append("error_rate")
    if status["avg_latency_ms"] >= _to_int(config["alert_latency_threshold_ms"]):
        breaches.append("latency")
    if not breaches:
        return None

    alert = {
        "provider": prov,
        "status": status["status"],
        "breaches": breaches,
        "error_rate_bps": status["error_rate_bps"],
        "avg_latency_ms": status["avg_latency_ms"],
        "alert_email": config["alert_email"],
        "at": now_ts(),
    }
    # GAP-0205: actually deliver the alert (email + in-app), de-duped by a
    # per-provider cooldown so a sustained incident does not spam every cycle.
    if not _is_alert_suppressed(prov):
        _dispatch_alert(alert)
        _mark_alert_sent(prov)
    return alert


# ---------------------------------------------------------------------------
# Background health-check task (GAP-0204 / FIN-014)
#
# `check_and_alert` was previously dead code: defined but never invoked, so
# configured provider alert thresholds (error rate, latency) were never
# evaluated automatically. This loop runs every 5 minutes and calls
# `check_and_alert` for each known provider, emitting a structured warning log
# when a threshold is breached. Mirrors the in-process asyncio task pattern
# used by `app/services/billing_dunning.py` (register_task is called inside the
# loop; the `start_*` entrypoint only schedules the loop via create_task).
# ---------------------------------------------------------------------------

_HEALTH_CHECK_INTERVAL_SECONDS = 300  # 5 minutes

# Suppress repeat alerts for the same provider for this window so a sustained
# incident does not fire a fresh email every 5-minute cycle (GAP-0205).
_ALERT_COOLDOWN_SECONDS = 1800  # 30 minutes

# Sentinel user_sub for system-level (ROOT/ADMIN visible) operational alerts.
_SYSTEM_ALERT_SUB = "SYSTEM"


def _is_alert_suppressed(provider: str) -> bool:
    """Return True if an alert was dispatched for this provider recently."""
    prov = normalize_provider(provider)
    try:
        item = T.payment_provider_health.get_item(
            Key={"pk": _provider_pk(prov), "sk": "ALERT_COOLDOWN"}
        ).get("Item")
    except Exception:
        return False
    if not item:
        return False
    last_sent = _to_int(item.get("last_sent_at"))
    return (now_ts() - last_sent) < _ALERT_COOLDOWN_SECONDS


def _mark_alert_sent(provider: str) -> None:
    """Record the time an alert was dispatched, for cooldown de-dup."""
    prov = normalize_provider(provider)
    try:
        T.payment_provider_health.put_item(
            Item={
                "pk": _provider_pk(prov),
                "sk": "ALERT_COOLDOWN",
                "last_sent_at": now_ts(),
            }
        )
    except Exception:
        logger.debug("Failed to record alert cooldown for %s", prov)


def _dispatch_alert(alert: Dict[str, Any]) -> None:
    """Deliver a provider health breach alert (GAP-0205).

    Delivers via the existing platform alerting helpers:

    - ``send_alert_email`` for the configured ``alert_email`` recipient. It
      handles dev/prod parity itself (writes to ``S.dev_email_log`` in dev
      mode, SES in prod) — SECOPS-007.
    - ``write_alert`` for an in-app alert (ROOT/ADMIN visible in the Alerts UI)
      under a SYSTEM sentinel user.

    Never raises: each channel is best-effort so a delivery failure cannot kill
    the background health-check loop. A structured warning is always logged so
    the breach remains observable even if all delivery channels are no-ops.
    """
    from app.services.alerts import send_alert_email, write_alert

    prov = str(alert.get("provider") or "unknown")
    breaches = alert.get("breaches") or []
    status = str(alert.get("status") or "unknown")
    err_bps = _to_int(alert.get("error_rate_bps"))
    latency_ms = _to_int(alert.get("avg_latency_ms"))
    alert_email = str(alert.get("alert_email") or "").strip()
    breach_str = ", ".join(str(b) for b in breaches)

    logger.warning(
        "provider_health_alert provider=%s status=%s breaches=%s "
        "error_rate_bps=%s avg_latency_ms=%s alert_email=%s",
        prov, status, breaches, err_bps, latency_ms, alert_email or "(none)",
    )

    subject = (
        f"[ALERT] Payment provider {prov.upper()} is {status.upper()} "
        f"({breach_str})"
    )
    body = (
        "Payment provider health alert\n"
        f"Provider   : {prov}\n"
        f"Status     : {status}\n"
        f"Breaches   : {breach_str}\n"
        f"Error rate : {err_bps / 100:.1f}% ({err_bps} bps)\n"
        f"Avg latency: {latency_ms} ms\n"
        f"Detected at: {alert.get('at', '')}\n\n"
        f"Investigate at: /admin/payment-health/{prov}"
    )

    email_sent = False
    if alert_email:
        try:
            send_alert_email([alert_email], subject, body)
            email_sent = True
        except Exception:
            logger.exception(
                "Failed to send provider health alert email for %s", prov
            )

    in_app_sent = False
    try:
        write_alert(
            _SYSTEM_ALERT_SUB,
            event="payment.provider_health",
            outcome="warning" if status != STATUS_DOWN else "error",
            title=f"Payment provider {prov} is {status}",
            details={
                "alert_type": "payment_provider_health",
                "provider": prov,
                "status": status,
                "breaches": breach_str,
                "error_rate_bps": err_bps,
                "avg_latency_ms": latency_ms,
            },
        )
        in_app_sent = True
    except Exception:
        logger.exception(
            "Failed to create in-app alert for %s provider health", prov
        )

    logger.info(
        "provider_alert_dispatched provider=%s email_sent=%s in_app_sent=%s",
        prov, email_sent, in_app_sent,
    )


async def _provider_health_loop(interval: int = _HEALTH_CHECK_INTERVAL_SECONDS) -> None:
    """Periodic loop: evaluate every provider against its alert thresholds."""
    import time as _time
    from app.services.job_registry import register_task, report_error, report_poll

    interval = max(60, int(interval))
    register_task(
        "payment_provider_health_check",
        interval,
        enabled=True,
        description=(
            "Checks payment provider health thresholds and dispatches alerts "
            "when error rate or latency exceed configured limits"
        ),
    )

    while True:
        _start = _time.perf_counter()
        try:
            for prov in PROVIDERS:
                try:
                    # check_and_alert dispatches the alert internally (GAP-0205,
                    # de-duped by a per-provider cooldown); the return value is
                    # only the payload for observability.
                    check_and_alert(prov)
                except Exception:
                    logger.exception(
                        "provider_health_check failed for %s", prov
                    )
            _dur = (_time.perf_counter() - _start) * 1000
            report_poll("payment_provider_health_check", duration_ms=_dur)
        except Exception as exc:
            report_error("payment_provider_health_check", str(exc))
            logger.exception("Payment provider health loop failed")
        await asyncio.sleep(interval)


def start_provider_health_check_task() -> None:
    """Register and start the payment provider health-check background task.

    Registered as a FastAPI startup handler in `app/main.py`. Respects the
    `S.payment_provider_health_enabled` feature flag (same flag that gates
    `record_provider_event`): when disabled, the task is registered as
    disabled in the job registry and the loop is not started.
    """
    from app.services.job_registry import register_task

    if not S.payment_provider_health_enabled:
        register_task(
            "payment_provider_health_check",
            _HEALTH_CHECK_INTERVAL_SECONDS,
            enabled=False,
            description=(
                "Checks payment provider health thresholds and dispatches "
                "alerts when error rate or latency exceed configured limits"
            ),
        )
        logger.info("Payment provider health check disabled")
        return
    asyncio.create_task(_provider_health_loop(_HEALTH_CHECK_INTERVAL_SECONDS))
