from __future__ import annotations

import uuid
from typing import Any

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import get_alert_prefs, send_alert_email, write_alert
from app.services.payment_incidents_store import PaymentIncidentRepository


def _billing_recovery_link() -> str:
    base = (S.public_base_url or "").rstrip("/")
    if not base:
        return "/billing?tab=overview"
    return f"{base}/billing?tab=overview"


def _is_failure_alert_status(incident: dict[str, Any]) -> bool:
    return str(incident.get("incident_type") or "") == "payment_failure" and str(incident.get("status") or "") in {
        "customer_action_required",
        "retry_failed_terminal",
    }


def _is_recovery_status(incident: dict[str, Any]) -> bool:
    return str(incident.get("incident_type") or "") == "payment_failure" and str(incident.get("status") or "") == "retry_succeeded"


def dispatch_auto_payment_failure_alert(repo: PaymentIncidentRepository, *, incident: dict[str, Any]) -> bool:
    if not _is_failure_alert_status(incident):
        return False

    incident_id = str(incident.get("incident_id") or "")
    user_sub = str(incident.get("account_id") or incident.get("customer_id") or "")
    if not incident_id or not user_sub:
        return False

    alert_key = f"{incident_id}:{incident.get('status')}"
    events = repo.list_incident_events(incident_id=incident_id, limit=100)
    for event in events:
        if str(event.get("event_type") or "") == "auto_payment_failure_alert_sent" and str((event.get("payload") or {}).get("alert_key") or "") == alert_key:
            return False

    amount = str(incident.get("amount") or "0")
    currency = str(incident.get("currency") or "usd").upper()
    due_at = str(incident.get("response_due_at") or "")
    cta = _billing_recovery_link()
    title = "Automatic payment failed"

    write_alert(
        user_sub,
        event="billing_auto_payment_failed",
        outcome="failure",
        title=title,
        details={
            "incident_id": incident_id,
            "status": str(incident.get("status") or ""),
            "amount": amount,
            "currency": currency,
            "due_at": due_at,
            "recovery_cta": cta,
        },
    )

    prefs = get_alert_prefs(user_sub)
    emails = prefs.get("emails") or []
    if emails:
        subject = f"[Billing] Automatic payment failed ({currency} {amount})"
        body = (
            f"Incident: {incident_id}\n"
            f"Amount: {currency} {amount}\n"
            f"Due date: {due_at or 'n/a'}\n"
            f"Recover now: {cta}\n"
        )
        send_alert_email(emails, subject, body)

    repo.append_incident_event(
        incident_id=incident_id,
        event_id=str(uuid.uuid4()),
        event_type="auto_payment_failure_alert_sent",
        payload={"alert_key": alert_key, "recovery_cta": cta},
    )
    return True


def clear_auto_payment_failure_alerts(repo: PaymentIncidentRepository, *, incident: dict[str, Any]) -> int:
    if not _is_recovery_status(incident):
        return 0

    incident_id = str(incident.get("incident_id") or "")
    user_sub = str(incident.get("account_id") or incident.get("customer_id") or "")
    if not incident_id or not user_sub:
        return 0

    out = T.alerts.query(
        KeyConditionExpression="user_sub = :u",
        ExpressionAttributeValues={":u": user_sub},
        ScanIndexForward=False,
        Limit=200,
    )
    items = out.get("Items", [])
    ts = now_ts()
    cleared = 0
    for item in items:
        if str(item.get("event") or "") != "billing_auto_payment_failed":
            continue
        details = item.get("details") or {}
        if str(details.get("incident_id") or "") != incident_id:
            continue
        if bool(item.get("read")):
            continue
        try:
            T.alerts.update_item(
                Key={"user_sub": user_sub, "alert_id": str(item.get("alert_id"))},
                UpdateExpression="SET #r=:t, read_at=:ts",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":t": True, ":ts": ts},
            )
            cleared += 1
        except Exception:
            continue

    if cleared > 0:
        repo.append_incident_event(
            incident_id=incident_id,
            event_id=str(uuid.uuid4()),
            event_type="auto_payment_failure_alert_cleared",
            payload={"cleared_count": cleared},
        )
    return cleared
