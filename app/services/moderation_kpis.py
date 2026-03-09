from __future__ import annotations

import time
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.services.alerts import write_alert
from app.services.moderation_audit_log import write_moderation_audit_event


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _scan_all(table: Any, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    while True:
        req = dict(kwargs)
        if cursor:
            req["ExclusiveStartKey"] = cursor
        resp = table.scan(**req)
        items.extend(resp.get("Items", []))
        cursor = resp.get("LastEvaluatedKey")
        if not cursor:
            break
    return items


def _percentile(values: list[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = int((len(ordered) - 1) * q)
    return int(ordered[idx])


def _parse_oncall_user_subs(raw: str) -> list[str]:
    out: list[str] = []
    for chunk in str(raw or "").split(","):
        value = chunk.strip()
        if value and value not in out:
            out.append(value)
    return out


def compute_moderation_kpis(*, now_ts: int | None = None, lookback_hours: int | None = None, surge_window_minutes: int | None = None) -> dict[str, Any]:
    now = int(now_ts or time.time())
    lookback = max(1, int(lookback_hours or S.moderation_kpi_lookback_hours))
    surge_window = max(1, int(surge_window_minutes or S.moderation_kpi_surge_window_minutes))

    since = now - (lookback * 3600)
    surge_since = now - (surge_window * 60)

    tickets = [
        row
        for row in _scan_all(T.moderation_tickets)
        if row.get("entity_type") == "moderation_ticket"
    ]
    reports = [
        row
        for row in _scan_all(T.content_reports)
        if row.get("entity_type") == "content_report"
    ]
    enforcements = [
        row
        for row in _scan_all(T.user_enforcement_history)
        if row.get("entity_type") == "user_enforcement"
    ]

    tickets_in_window = [row for row in tickets if _to_int(row.get("created_at"), 0) >= since]
    resolved_in_window = [
        row
        for row in tickets
        if _to_int(row.get("resolved_at"), 0) >= since and str(row.get("status") or "") == "closed"
    ]
    latency_values = [
        max(0, _to_int(row.get("resolved_at"), 0) - _to_int(row.get("created_at"), 0))
        for row in resolved_in_window
        if _to_int(row.get("resolved_at"), 0) > 0 and _to_int(row.get("created_at"), 0) > 0
    ]

    open_tickets = [row for row in tickets if str(row.get("status") or "") == "open"]
    critical_open = [row for row in open_tickets if str(row.get("priority") or "").lower() == "critical"]
    oldest_open_age_minutes = 0
    if open_tickets:
        oldest_open_created = min(_to_int(row.get("created_at"), now) for row in open_tickets)
        oldest_open_age_minutes = max(0, (now - oldest_open_created) // 60)

    enforcement_in_window = [row for row in enforcements if _to_int(row.get("created_at"), 0) >= since]
    warning_count = sum(1 for row in enforcement_in_window if str(row.get("enforcement_type") or "") == "warn")
    ban_count = sum(1 for row in enforcement_in_window if str(row.get("enforcement_type") or "") == "ban")
    denom = max(1, len(enforcement_in_window))

    surge_reports = [
        row
        for row in reports
        if _to_int(row.get("created_at"), 0) >= surge_since
        and any(str(t).strip().lower() in {"extortion", "criminal"} for t in (row.get("topics") or []))
    ]

    return {
        "generated_at": now,
        "lookback_hours": lookback,
        "surge_window_minutes": surge_window,
        "ticket_volume": len(tickets_in_window),
        "resolution_count": len(resolved_in_window),
        "resolution_latency_avg_seconds": int(sum(latency_values) / len(latency_values)) if latency_values else 0,
        "resolution_latency_p95_seconds": _percentile(latency_values, 0.95),
        "warning_count": warning_count,
        "ban_count": ban_count,
        "warning_rate": round(warning_count / denom, 4),
        "ban_rate": round(ban_count / denom, 4),
        "open_ticket_count": len(open_tickets),
        "critical_backlog": len(critical_open),
        "oldest_open_age_minutes": oldest_open_age_minutes,
        "extortion_criminal_reports_window_count": len(surge_reports),
    }


def _already_fired(*, alert_key: str, marker: str, since_ts: int) -> bool:
    try:
        resp = T.moderation_audit_log.query(
            IndexName="ByActionCreatedAt",
            KeyConditionExpression=Key("action").eq("kpi_alert_fired") & Key("created_at").gte(str(since_ts)),
            ScanIndexForward=False,
            Limit=100,
        )
    except Exception:
        return False
    for row in resp.get("Items", []):
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if str(metadata.get("alert_key") or "") == alert_key and str(metadata.get("marker") or "") == marker:
            return True
    return False


def evaluate_and_dispatch_moderation_alerts(*, actor_user_id: str = "system", now_ts: int | None = None) -> dict[str, Any]:
    now = int(now_ts or time.time())
    kpis = compute_moderation_kpis(now_ts=now)
    oncall_user_subs = _parse_oncall_user_subs(S.moderation_oncall_user_subs)
    fired: list[dict[str, Any]] = []

    if not oncall_user_subs:
        return {"kpis": kpis, "alerts_fired": fired, "notified_user_subs": []}

    surge_threshold = int(S.moderation_alert_extortion_criminal_surge_threshold)
    surge_window_seconds = max(60, int(S.moderation_kpi_surge_window_minutes) * 60)
    surge_marker = str(now // surge_window_seconds)
    surge_alert_key = "extortion_criminal_surge"

    if int(kpis.get("extortion_criminal_reports_window_count") or 0) >= surge_threshold and not _already_fired(
        alert_key=surge_alert_key,
        marker=surge_marker,
        since_ts=now - surge_window_seconds,
    ):
        details = {
            "alert_key": surge_alert_key,
            "marker": surge_marker,
            "threshold": surge_threshold,
            "observed": int(kpis.get("extortion_criminal_reports_window_count") or 0),
            "window_minutes": int(kpis.get("surge_window_minutes") or 0),
        }
        for user_sub in oncall_user_subs:
            write_alert(
                user_sub,
                event="moderation_extortion_criminal_surge",
                outcome="warning",
                title="Moderation surge detected",
                details=details,
            )
        write_moderation_audit_event(action="kpi_alert_fired", actor_user_id=actor_user_id, metadata=details)
        fired.append({"alert": surge_alert_key, **details})

    critical_threshold = int(S.moderation_alert_sla_open_critical_threshold)
    oldest_threshold = int(S.moderation_alert_sla_oldest_open_minutes_threshold)
    sla_breach = (
        int(kpis.get("critical_backlog") or 0) >= critical_threshold
        or int(kpis.get("oldest_open_age_minutes") or 0) >= oldest_threshold
    )
    sla_window_seconds = max(300, int(S.moderation_alert_sla_window_minutes) * 60)
    sla_marker = str(now // sla_window_seconds)
    sla_alert_key = "sla_breach"

    if sla_breach and not _already_fired(
        alert_key=sla_alert_key,
        marker=sla_marker,
        since_ts=now - sla_window_seconds,
    ):
        details = {
            "alert_key": sla_alert_key,
            "marker": sla_marker,
            "critical_backlog": int(kpis.get("critical_backlog") or 0),
            "oldest_open_age_minutes": int(kpis.get("oldest_open_age_minutes") or 0),
            "critical_backlog_threshold": critical_threshold,
            "oldest_open_age_threshold_minutes": oldest_threshold,
        }
        for user_sub in oncall_user_subs:
            write_alert(
                user_sub,
                event="moderation_sla_breach",
                outcome="warning",
                title="Moderation SLA breach",
                details=details,
            )
        write_moderation_audit_event(action="kpi_alert_fired", actor_user_id=actor_user_id, metadata=details)
        fired.append({"alert": sla_alert_key, **details})

    return {
        "kpis": kpis,
        "alerts_fired": fired,
        "notified_user_subs": oncall_user_subs,
    }
