"""DISP-050 -- payment-dispute NOTIFICATIONS (both tracks).

A single seam that fans dispute state-changes to the right parties over the
shared alert + tappable-push rail (mirrors ``moderation_lifecycle._notify`` and
``refund_requests`` ECOMX-52). Every notify:
  * persists an Alerts row (``write_alert``) with an explicit relative
    ``action_url`` deep-link, and
  * fires a real tappable PUSH (``send_push_for_alert``) -- the dispute event
    types are default-ON in ``alerts.DEFAULT_PUSH_EVENT_TYPES`` (opt-out, not
    opt-in), so a payer/creator gets pushed without having to enable anything.

Deep-links (relative, open-redirect-safe):
  * payer  -> ``/billing/disputes/{id}``       (My Disputes / track screen)
  * creator/seller -> ``/creator/disputes/{id}`` (Disputes-to-respond screen)

Best-effort throughout: a notification failure never blocks a money move or a
state transition. Gated by ``S.dispute_notifications_enabled`` (default ON).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.settings import S
from app.services.alerts import write_alert
from app.services.push import send_push_for_alert

logger = logging.getLogger(__name__)


def _enabled() -> bool:
    return bool(getattr(S, "dispute_notifications_enabled", True))


def _payer_url(dispute_id: str) -> str:
    return f"/billing/disputes/{dispute_id}" if dispute_id else "/billing/disputes"


def _creator_url(dispute_id: str) -> str:
    return f"/creator/disputes/{dispute_id}" if dispute_id else "/creator/disputes"


def _notify(
    user_id: Optional[str],
    *,
    event: str,
    outcome: str,
    title: str,
    body: str,
    action_url: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist one alert row + fire one tappable push. Never raises."""
    if not _enabled():
        return
    uid = str(user_id or "").strip()
    if not uid:
        return
    det = {"alert_type": event, "message": body}
    if details:
        det.update({k: v for k, v in details.items() if v is not None})
    try:
        wr = write_alert(
            uid,
            event=event,
            outcome=outcome,
            title=title,
            details=det,
            action_url=action_url,
        )
    except Exception:
        logger.exception("dispute_notify.write_alert failed user=%s event=%s", uid, event)
        return
    try:
        alert_id = (wr or {}).get("alert_id", "") if isinstance(wr, dict) else ""
        send_push_for_alert(uid, event, title, body, alert_id, action_url=action_url)
    except Exception:
        logger.exception("dispute_notify.push failed user=%s event=%s", uid, event)


def _money(cents: Any) -> str:
    try:
        return f"${int(cents) / 100:.2f}"
    except Exception:
        return "$0.00"


# ---------------------------------------------------------------------------
# USER TRACK
# ---------------------------------------------------------------------------

def notify_opened(*, dispute_id: str, payer_id: Optional[str], recipient_id: Optional[str],
                  amount_cents: int, reason: str = "", charge_type: str = "") -> None:
    """A user dispute was FILED: ack the payer + alert the creator/seller."""
    _notify(
        payer_id, event="dispute_opened", outcome="info",
        title="Your dispute was opened",
        body=f"We opened your {_money(amount_cents)} dispute and are reviewing it.",
        action_url=_payer_url(dispute_id),
        details={"dispute_id": dispute_id, "amount_cents": int(amount_cents), "reason": reason},
    )
    _notify(
        recipient_id, event="dispute_filed_against", outcome="warning",
        title="A payment was disputed",
        body=f"A {_money(amount_cents)} {charge_type or 'charge'} you received is being disputed.",
        action_url=_creator_url(dispute_id),
        details={"dispute_id": dispute_id, "amount_cents": int(amount_cents), "reason": reason},
    )


def notify_needs_response(*, dispute_id: str, recipient_id: Optional[str],
                          amount_cents: int, respond_by: Optional[int] = None,
                          reason: str = "") -> None:
    """DISP-012: the creator/seller must respond -- invite them into the window."""
    _notify(
        recipient_id, event="dispute_needs_response", outcome="warning",
        title="Action needed: respond to a dispute",
        body=f"Respond to the {_money(amount_cents)} dispute before the deadline or it goes to review.",
        action_url=_creator_url(dispute_id),
        details={"dispute_id": dispute_id, "amount_cents": int(amount_cents),
                 "respond_by": respond_by, "reason": reason},
    )


def notify_creator_responded(*, dispute_id: str, payer_id: Optional[str]) -> None:
    """The creator/seller submitted a rebuttal -> keep the payer informed."""
    _notify(
        payer_id, event="dispute_creator_responded", outcome="info",
        title="The other party responded to your dispute",
        body="Your dispute is now under review.",
        action_url=_payer_url(dispute_id),
        details={"dispute_id": dispute_id},
    )


def notify_sla_warning(*, dispute_id: str, recipient_id: Optional[str],
                       respond_by: Optional[int] = None) -> None:
    """DISP-050: response-window reminder (called by the sweep before expiry)."""
    _notify(
        recipient_id, event="dispute_response_reminder", outcome="warning",
        title="Reminder: a dispute needs your response",
        body="Your response window is closing soon. Respond now to contest the dispute.",
        action_url=_creator_url(dispute_id),
        details={"dispute_id": dispute_id, "respond_by": respond_by},
    )


def notify_resolved(*, dispute_id: str, payer_id: Optional[str], recipient_id: Optional[str],
                    resolution: str, moved_cents: int = 0) -> None:
    """A terminal user resolution: notify BOTH parties per the outcome."""
    res = (resolution or "").lower()
    if res in ("refunded", "full", "partial"):
        _notify(
            payer_id, event="dispute_resolved", outcome="success",
            title=f"You were refunded {_money(moved_cents)}",
            body="Your dispute was resolved in your favor.",
            action_url=_payer_url(dispute_id),
            details={"dispute_id": dispute_id, "resolution": res, "refunded_cents": int(moved_cents)},
        )
        _notify(
            recipient_id, event="dispute_resolved_against", outcome="warning",
            title="A dispute was resolved in the buyer's favor",
            body=f"{_money(moved_cents)} was reversed from your earnings for a disputed charge.",
            action_url=_creator_url(dispute_id),
            details={"dispute_id": dispute_id, "resolution": res, "clawback_cents": int(moved_cents)},
        )
    else:  # denied
        _notify(
            payer_id, event="dispute_resolved", outcome="info",
            title="Your dispute was reviewed",
            body="After review, your dispute was denied. No refund was issued.",
            action_url=_payer_url(dispute_id),
            details={"dispute_id": dispute_id, "resolution": "denied"},
        )
        _notify(
            recipient_id, event="dispute_resolved_favor", outcome="success",
            title="A dispute was resolved in your favor",
            body="A dispute against a charge you received was denied. Your earnings stand.",
            action_url=_creator_url(dispute_id),
            details={"dispute_id": dispute_id, "resolution": "denied"},
        )


# ---------------------------------------------------------------------------
# PROCESSOR (CHARGEBACK) TRACK
# ---------------------------------------------------------------------------

def notify_chargeback_opened(*, incident_id: str, recipient_id: Optional[str],
                             amount_cents: int = 0, charge_type: str = "",
                             respond_by: Optional[int] = None) -> None:
    """DISP-050: a processor chargeback OPENED -> the funds are held; tell the
    creator/seller so they can supply evidence before the response deadline."""
    _notify(
        recipient_id, event="dispute_chargeback_opened", outcome="warning",
        title="A chargeback was opened on your earnings",
        body=(f"A {_money(amount_cents)} {charge_type or 'charge'} is being charged back. "
              "Funds are on hold pending the bank's decision."),
        action_url=_creator_url(incident_id),
        details={"incident_id": incident_id, "amount_cents": int(amount_cents),
                 "charge_type": charge_type, "respond_by": respond_by},
    )


def notify_evidence_due(*, incident_id: str, recipient_id: Optional[str],
                        due_at: Optional[int] = None) -> None:
    """DISP-050/032: evidence-due reminder for an open chargeback."""
    _notify(
        recipient_id, event="dispute_chargeback_evidence_due", outcome="warning",
        title="Evidence due for a chargeback",
        body="Submit your evidence before the deadline to contest this chargeback.",
        action_url=_creator_url(incident_id),
        details={"incident_id": incident_id, "due_at": due_at},
    )


def notify_chargeback_terminal(*, incident_id: str, recipient_id: Optional[str],
                               outcome: str, clawback_cents: int = 0,
                               fee_cents: int = 0) -> None:
    """DISP-050: a chargeback reached a terminal outcome. LOST/ACCEPTED -> the
    creator lost the funds (+fee); WON -> the held funds were released."""
    o = (outcome or "").lower()
    if o in ("lost", "accepted"):
        fee_txt = f" plus a {_money(fee_cents)} chargeback fee" if fee_cents else ""
        _notify(
            recipient_id, event="dispute_chargeback_lost", outcome="warning",
            title="A chargeback was lost",
            body=(f"{_money(clawback_cents)} was reversed from your earnings{fee_txt}."),
            action_url=_creator_url(incident_id),
            details={"incident_id": incident_id, "outcome": o,
                     "clawback_cents": int(clawback_cents), "fee_cents": int(fee_cents)},
        )
    elif o == "won":
        _notify(
            recipient_id, event="dispute_chargeback_won", outcome="success",
            title="A chargeback was won",
            body="The bank sided with you. The held funds were released back to your balance.",
            action_url=_creator_url(incident_id),
            details={"incident_id": incident_id, "outcome": "won"},
        )
