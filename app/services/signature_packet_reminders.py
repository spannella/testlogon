from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr

from app.core.settings import S
from app.core.tables import T
from app.metrics import record_signature_packet_reminder_email
from app.services.alerts import send_alert_email
from app.services.profile import get_profile_identity
from app.services.signature_packet_domain import SignaturePacketStatus, SignatureSignerStatus
from app.services.signature_packet_flags import require_signature_pdf_enabled
from app.services.signature_packet_store import append_packet_event, get_packet


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str | None) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _reminder_schedule_hours() -> List[int]:
    vals: List[int] = []
    for raw in str(S.signature_packet_reminder_schedule_hours or "").split(","):
        t = raw.strip()
        if not t:
            continue
        try:
            v = int(t)
        except ValueError:
            continue
        if v > 0:
            vals.append(v)
    return sorted(set(vals))


def _current_due_step(sent_at: datetime, now: datetime, schedule_hours: List[int]) -> int:
    elapsed_hours = (now - sent_at).total_seconds() / 3600.0
    step = 0
    for idx, hr in enumerate(schedule_hours, start=1):
        if elapsed_hours >= hr:
            step = idx
    return step


def _claim_reminder_step(packet_id: str, signer_id: str, next_step: int, now: datetime) -> bool:
    try:
        T.signature_packet_signers.update_item(
            Key={"packet_id": packet_id, "signer_id": signer_id},
            UpdateExpression="SET reminder_last_step = :step, reminder_last_sent_at = :sent_at",
            ExpressionAttributeValues={
                ":step": int(next_step),
                ":sent_at": now.isoformat(),
            },
            ConditionExpression=Attr("reminder_last_step").not_exists() | Attr("reminder_last_step").lt(int(next_step)),
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise
    return True


def _build_sign_packet_link(packet_id: str) -> str:
    base = (S.public_base_url or "http://localhost:8000").rstrip("/")
    return f"{base}/files?signaturePacketId={packet_id}"


def _reminder_email_body(*, packet_id: str, source_name: str, signer_display_name: str | None, owner_display_name: str | None) -> str:
    greeting = f"Hi {signer_display_name},\n\n" if signer_display_name else "\n"
    owner = owner_display_name or "A sender"
    link = _build_sign_packet_link(packet_id)
    return (
        f"{greeting}"
        f"{owner} requested your signature for packet {packet_id}"
        + (f" ({source_name})" if source_name else "")
        + ".\n\n"
        f"Please review and sign here: {link}\n\n"
        "If you already signed, you can ignore this reminder."
    )


def process_signature_packet_reminders(*, limit: int = 500) -> Dict[str, int]:
    require_signature_pdf_enabled()
    schedule_hours = _reminder_schedule_hours()
    if not schedule_hours:
        return {"processed": 0, "sent": 0, "skipped": 0}

    now = _now()
    processed = 0
    sent = 0
    skipped = 0

    # worker scans pending signer assignments and applies schedule/idempotency checks per signer.
    resp = T.signature_packet_signers.scan(
        FilterExpression=Attr("status").eq(SignatureSignerStatus.PENDING.value),
        Limit=limit,
    )
    assignments = resp.get("Items", [])

    for signer in assignments:
        processed += 1
        packet_id = str(signer.get("packet_id") or "")
        signer_id = str(signer.get("signer_id") or "")
        if not packet_id or not signer_id:
            skipped += 1
            continue

        packet = get_packet(packet_id) or {}
        status = str(packet.get("status") or "")
        if status not in {SignaturePacketStatus.SENT.value, SignaturePacketStatus.PARTIALLY_SIGNED.value}:
            skipped += 1
            continue

        sent_at = _parse_iso(str(packet.get("sent_at") or ""))
        if not sent_at:
            skipped += 1
            continue

        due_step = _current_due_step(sent_at, now, schedule_hours)
        if due_step <= 0:
            skipped += 1
            continue

        last_step = int(signer.get("reminder_last_step") or 0)
        if due_step <= last_step:
            skipped += 1
            continue

        if not _claim_reminder_step(packet_id, signer_id, due_step, now):
            skipped += 1
            continue

        signer_identity = get_profile_identity(signer_id)
        email = (signer_identity.get("email") or "").strip()
        if not email:
            append_packet_event(
                packet_id=packet_id,
                actor_user_id="system",
                event_type="signer_reminder_skipped",
                event_payload={"signer_id": signer_id, "reason": "missing_email", "step": due_step},
            )
            record_signature_packet_reminder_email(outcome="skipped", reason="missing_email")
            skipped += 1
            continue

        owner_identity = get_profile_identity(str(packet.get("owner_user_id") or ""))
        source_name = str(packet.get("source_name") or "")
        send_alert_email(
            [email],
            subject=f"Reminder: signature requested for packet {packet_id}",
            body_text=_reminder_email_body(
                packet_id=packet_id,
                source_name=source_name,
                signer_display_name=signer_identity.get("display_name"),
                owner_display_name=owner_identity.get("display_name"),
            ),
        )
        append_packet_event(
            packet_id=packet_id,
            actor_user_id="system",
            event_type="signer_reminder_sent",
            event_payload={
                "signer_id": signer_id,
                "step": due_step,
                "email": email,
                "sign_link": _build_sign_packet_link(packet_id),
            },
        )
        record_signature_packet_reminder_email(outcome="sent", reason="none")
        sent += 1

    return {"processed": processed, "sent": sent, "skipped": skipped}
