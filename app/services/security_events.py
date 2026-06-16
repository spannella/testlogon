"""Security event recorder + severity-aware alert bridge (HNY-003).

DEFENSIVE-only. Records unified IDS / honeypot / honeytoken signal rows into
``T.security_events`` and bridges high/critical signals into the existing
audit/alert pipeline (``app.services.alerts.audit_event``) so IP / user-agent /
impersonation enrichment and ``write_alert`` persistence are reused rather than
reimplemented.

All public entry points are best-effort: a recorder failure must NEVER break
the request path it is hooked into (mirrors ``host_inventory._audit``).
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Constrained severity enum. Order matters for comparisons / escalation.
SEVERITIES = ("info", "low", "medium", "high", "critical")
_ALERTING_SEVERITIES = ("high", "critical")


def _normalize_severity(severity: str | None) -> str:
    s = str(severity or "info").strip().lower()
    return s if s in SEVERITIES else "info"


def _event_date(ts: int) -> str:
    # UTC YYYY-MM-DD partition for the ByDate GSI.
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _client_ip(source_ip: str | None, request: Any) -> str:
    if source_ip:
        return str(source_ip)
    if request is not None:
        try:
            from app.core.normalize import client_ip_from_request

            return client_ip_from_request(request) or ""
        except Exception:
            return ""
    return ""


def _user_agent(request: Any) -> str:
    if request is None:
        return ""
    try:
        return (request.headers.get("user-agent", "") or "")[:256]
    except Exception:
        return ""


def record_security_event(
    *,
    kind: str,
    severity: str,
    source_ip: str | None = None,
    user_sub: Optional[str] = None,
    request: Any = None,
    **details: Any,
) -> str:
    """Persist a security event row and (for high/critical) emit one alert.

    Returns the generated ``event_id``. Raises on internal DDB failure — use
    :func:`safe_record` for the fire-and-forget path.
    """
    sev = _normalize_severity(severity)
    ts = now_ts()
    event_id = "se_" + uuid.uuid4().hex
    ip = _client_ip(source_ip, request)
    ua = _user_agent(request)

    item: Dict[str, Any] = {
        "pk": f"EVENT#{event_id}",
        "sk": "META",
        "event_id": event_id,
        "kind": str(kind),
        "severity": sev,
        "source_ip": ip,
        "user_agent": ua,
        "user_sub": str(user_sub or ""),
        "ts": ts,
        "event_date": _event_date(ts),
    }
    # Flatten scalar details onto the row (DDB-friendly); nest the rest.
    flat: Dict[str, Any] = {}
    for k, v in (details or {}).items():
        if k in item:
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            flat[k] = v
        else:
            flat[k] = str(v)
    if flat:
        item["details"] = flat

    T.security_events.put_item(Item=item)

    # Bridge high/critical into the existing alert pipeline. info/low/medium
    # are recorded but do not page (avoids alert-fatigue from routine probes).
    if sev in _ALERTING_SEVERITIES:
        try:
            from app.services.alerts import audit_event

            audit_event(
                event="security_signal",
                user_sub=str(user_sub or "system_security"),
                request=request,
                outcome="suspicious",
                severity=sev,
                security_kind=str(kind),
                security_event_id=event_id,
                source_ip=ip,
                **flat,
            )
        except Exception:
            logger.debug("security_events: alert bridge failed", exc_info=True)

    return event_id


def safe_record(
    *,
    kind: str,
    severity: str,
    source_ip: str | None = None,
    user_sub: Optional[str] = None,
    request: Any = None,
    **details: Any,
) -> Optional[str]:
    """Fire-and-forget wrapper. Swallows all exceptions, returns None on error."""
    try:
        return record_security_event(
            kind=kind,
            severity=severity,
            source_ip=source_ip,
            user_sub=user_sub,
            request=request,
            **details,
        )
    except Exception:
        logger.debug("security_events.safe_record swallowed error", exc_info=True)
        return None


# Backwards-friendly alias matching the ticket's ``_safe_record`` name.
_safe_record = safe_record


def get_event(event_id: str) -> Optional[Dict[str, Any]]:
    try:
        return T.security_events.get_item(Key={"pk": f"EVENT#{event_id}", "sk": "META"}).get("Item")
    except Exception:
        return None


def list_events_for_token(token_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    """Admin-only: events whose flattened details reference a honeytoken id.

    Low-frequency inspection path (HNY-007 ``/{token_id}/hits``); a scan is
    acceptable here. Matches on the persisted ``details.token_id`` field.
    """
    out: List[Dict[str, Any]] = []
    if not token_id:
        return out
    try:
        resp = T.security_events.scan()
        items = resp.get("Items", []) or []
        while resp.get("LastEvaluatedKey") and len(items) < 5000:
            resp = T.security_events.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []) or [])
    except Exception:
        return out
    for it in items:
        details = it.get("details") or {}
        if str(details.get("token_id") or "") == str(token_id):
            out.append(it)
    out.sort(key=lambda e: int(e.get("ts") or 0), reverse=True)
    return out[:limit]
