from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from datetime import datetime, timezone
from uuid import uuid4

from app.core.tables import T
from app.metrics import record_signature_packet_event
from app.services.signature_packet_domain import (
    SignatureFieldType,
    SignaturePacketStatus,
    SignatureSignerStatus,
    signer_status_sort_key,
)
from app.services.signature_packet_flags import require_signature_pdf_enabled

OWNER_CREATED_INDEX = "OWNER_CREATED_INDEX"
SIGNER_STATUS_INDEX = "SIGNER_STATUS_INDEX"


def list_packets_by_sender(owner_user_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    """Return packets owned by sender, newest first."""
    require_signature_pdf_enabled()
    response = T.signature_packets.query(
        IndexName=OWNER_CREATED_INDEX,
        KeyConditionExpression=Key("owner_user_id").eq(owner_user_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    return response.get("Items", [])


def list_packets_for_signer(
    signer_id: str,
    status: SignatureSignerStatus,
    *,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return signer assignments filtered by status."""
    require_signature_pdf_enabled()
    response = T.signature_packet_signers.query(
        IndexName=SIGNER_STATUS_INDEX,
        KeyConditionExpression=Key("signer_id").eq(signer_id) & Key("status_key").begins_with(f"{status.value}#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return response.get("Items", [])


def load_packet_aggregate(packet_id: str) -> Dict[str, Any]:
    """Load packet + signers + fields + events + artifacts by packet ID."""
    require_signature_pdf_enabled()
    packet = T.signature_packets.get_item(Key={"packet_id": packet_id}).get("Item")
    signers = T.signature_packet_signers.query(KeyConditionExpression=Key("packet_id").eq(packet_id)).get("Items", [])
    fields = T.signature_packet_fields.query(KeyConditionExpression=Key("packet_id").eq(packet_id)).get("Items", [])
    events = T.signature_packet_events.query(KeyConditionExpression=Key("packet_id").eq(packet_id)).get("Items", [])
    artifact = T.signature_packet_artifacts.get_item(Key={"packet_id": packet_id}).get("Item")
    return {
        "packet": packet,
        "signers": signers,
        "fields": fields,
        "events": events,
        "artifact": artifact,
    }



def _ensure_packet_not_completed(packet_id: str) -> None:
    packet = get_packet(packet_id)
    if packet and str(packet.get("status") or "") == SignaturePacketStatus.COMPLETED.value:
        raise ValueError("packet_immutable")


def _ensure_packet_draft(packet_id: str) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise ValueError("packet_not_found")
    status = str(packet.get("status") or "")
    if status != SignaturePacketStatus.DRAFT.value:
        if status == SignaturePacketStatus.COMPLETED.value:
            raise ValueError("packet_immutable")
        raise ValueError("packet_not_draft")
    return packet


def create_draft_packet(
    *,
    owner_user_id: str,
    source_path: str,
    source_content_type: str,
    source_name: str,
    origin_channel: str,
    origin_ref: str | None = None,
) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    packet_id = f"sp_{uuid4().hex}"
    now = datetime.now(timezone.utc).isoformat()
    item: Dict[str, Any] = {
        "packet_id": packet_id,
        "owner_user_id": owner_user_id,
        "source_path": source_path,
        "source_content_type": source_content_type,
        "source_name": source_name,
        "status": SignaturePacketStatus.DRAFT.value,
        "origin_channel": origin_channel,
        "created_at": now,
        "updated_at": now,
    }
    if origin_ref:
        item["origin_ref"] = origin_ref
    T.signature_packets.put_item(Item=item)
    return item


def get_packet(packet_id: str) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    return T.signature_packets.get_item(Key={"packet_id": packet_id}).get("Item")


def signer_assignment_exists(packet_id: str, signer_id: str) -> bool:
    require_signature_pdf_enabled()
    if not signer_id:
        return False
    item = T.signature_packet_signers.get_item(Key={"packet_id": packet_id, "signer_id": signer_id}).get("Item")
    return bool(item)


def upsert_packet_field(
    *,
    packet_id: str,
    field_id: str,
    page: int,
    x: float,
    y: float,
    width: float,
    height: float,
    field_type: SignatureFieldType,
    assigned_signer_id: Optional[str],
    required: bool,
) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    _ensure_packet_draft(packet_id)
    now = datetime.now(timezone.utc).isoformat()
    item: Dict[str, Any] = {
        "packet_id": packet_id,
        "field_id": field_id,
        "page": int(page),
        "x": Decimal(str(x)),
        "y": Decimal(str(y)),
        "width": Decimal(str(width)),
        "height": Decimal(str(height)),
        "field_type": field_type.value,
        "required": bool(required),
        "updated_at": now,
    }
    existing = T.signature_packet_fields.get_item(Key={"packet_id": packet_id, "field_id": field_id}).get("Item")
    item["created_at"] = (existing or {}).get("created_at", now)
    if assigned_signer_id:
        item["assigned_signer_id"] = assigned_signer_id
    T.signature_packet_fields.put_item(Item=item)
    return item


def delete_packet_field(*, packet_id: str, field_id: str) -> None:
    require_signature_pdf_enabled()
    _ensure_packet_draft(packet_id)
    T.signature_packet_fields.delete_item(Key={"packet_id": packet_id, "field_id": field_id})


def list_packet_signers(packet_id: str) -> List[Dict[str, Any]]:
    require_signature_pdf_enabled()
    return T.signature_packet_signers.query(KeyConditionExpression=Key("packet_id").eq(packet_id)).get("Items", [])


def list_packet_fields(packet_id: str) -> List[Dict[str, Any]]:
    require_signature_pdf_enabled()
    return T.signature_packet_fields.query(KeyConditionExpression=Key("packet_id").eq(packet_id)).get("Items", [])




def list_packet_events(packet_id: str) -> List[Dict[str, Any]]:
    """Return packet events in chronological order for support/debug reconstruction."""
    require_signature_pdf_enabled()
    events = T.signature_packet_events.query(
        KeyConditionExpression=Key("packet_id").eq(packet_id)
    ).get("Items", [])
    events.sort(key=lambda e: (str(e.get("created_at") or e.get("timestamp") or ""), str(e.get("event_id") or "")))
    return events
def append_packet_event(
    *,
    packet_id: str,
    actor_user_id: str,
    event_type: str,
    event_payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    now = datetime.now(timezone.utc).isoformat()
    item = {
        "packet_id": packet_id,
        "event_id": f"evt_{uuid4().hex}",
        "actor_user_id": actor_user_id,
        "event_type": event_type,
        "event_payload": event_payload or {},
        "created_at": now,
        "timestamp": now,
    }
    T.signature_packet_events.put_item(Item=item)
    record_signature_packet_event(event_type=event_type)
    return item


def mark_packet_sent(packet_id: str) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    _ensure_packet_not_completed(packet_id)
    now = datetime.now(timezone.utc).isoformat()
    response = T.signature_packets.update_item(
        Key={"packet_id": packet_id},
        UpdateExpression="SET #status = :sent, sent_at = :now, updated_at = :now, fields_locked = :locked",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":sent": SignaturePacketStatus.SENT.value,
            ":now": now,
            ":locked": True,
            ":draft": SignaturePacketStatus.DRAFT.value,
        },
        ConditionExpression="#status = :draft",
        ReturnValues="ALL_NEW",
    )
    return response.get("Attributes", {})


def get_packet_signer(packet_id: str, signer_id: str) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    if not signer_id:
        return None
    return T.signature_packet_signers.get_item(Key={"packet_id": packet_id, "signer_id": signer_id}).get("Item")


def get_packet_field(packet_id: str, field_id: str) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    return T.signature_packet_fields.get_item(Key={"packet_id": packet_id, "field_id": field_id}).get("Item")


def fill_packet_field(
    *,
    packet_id: str,
    field_id: str,
    value: str,
    filled_by_signer_id: str,
    capture_mode: str | None = None,
    render_payload: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    _ensure_packet_not_completed(packet_id)
    now = datetime.now(timezone.utc).isoformat()
    expression = "SET #value = :value, filled_at = :filled_at, filled_by_signer_id = :filled_by_signer_id, updated_at = :updated_at"
    values: Dict[str, Any] = {
        ":value": value,
        ":filled_at": now,
        ":filled_by_signer_id": filled_by_signer_id,
        ":updated_at": now,
    }
    if capture_mode:
        expression += ", capture_mode = :capture_mode"
        values[":capture_mode"] = capture_mode
    if render_payload is not None:
        expression += ", render_payload = :render_payload"
        values[":render_payload"] = render_payload

    response = T.signature_packet_fields.update_item(
        Key={"packet_id": packet_id, "field_id": field_id},
        UpdateExpression=expression,
        ExpressionAttributeNames={"#value": "value"},
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return response.get("Attributes", {})


def signer_has_accepted_notice(packet_id: str, signer_id: str, notice_version: str) -> bool:
    require_signature_pdf_enabled()
    signer = get_packet_signer(packet_id, signer_id) or {}
    return str(signer.get("legal_notice_accepted_version") or "") == notice_version


def mark_signer_notice_shown(packet_id: str, signer_id: str, notice_version: str) -> bool:
    require_signature_pdf_enabled()
    now = datetime.now(timezone.utc).isoformat()
    try:
        T.signature_packet_signers.update_item(
            Key={"packet_id": packet_id, "signer_id": signer_id},
            UpdateExpression=(
                "SET legal_notice_last_shown_version = :version, legal_notice_last_shown_at = :shown_at"
            ),
            ExpressionAttributeValues={
                ":version": notice_version,
                ":shown_at": now,
            },
            ConditionExpression=Attr("legal_notice_last_shown_version").not_exists() | Attr("legal_notice_last_shown_version").ne(notice_version),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return False
        raise
    return True


def mark_signer_notice_accepted(packet_id: str, signer_id: str, notice_version: str) -> bool:
    require_signature_pdf_enabled()
    now = datetime.now(timezone.utc).isoformat()
    try:
        T.signature_packet_signers.update_item(
            Key={"packet_id": packet_id, "signer_id": signer_id},
            UpdateExpression=(
                "SET legal_notice_accepted_version = :version, legal_notice_accepted_at = :accepted_at"
            ),
            ExpressionAttributeValues={
                ":version": notice_version,
                ":accepted_at": now,
            },
            ConditionExpression=Attr("legal_notice_accepted_version").not_exists() | Attr("legal_notice_accepted_version").ne(notice_version),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return False
        raise
    return True


def mark_signer_completed(packet_id: str, signer_id: str, *, source_ip: str | None = None) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    _ensure_packet_not_completed(packet_id)
    now = datetime.now(timezone.utc).isoformat()
    try:
        update_expression = "SET #status = :completed, completed_at = :completed_at, #status_key = :status_key"
        values: Dict[str, Any] = {
            ":completed": SignatureSignerStatus.COMPLETED.value,
            ":completed_at": now,
            ":status_key": signer_status_sort_key(SignatureSignerStatus.COMPLETED, packet_id),
            ":pending": SignatureSignerStatus.PENDING.value,
        }
        if source_ip:
            update_expression += ", completed_ip = :completed_ip"
            values[":completed_ip"] = source_ip

        response = T.signature_packet_signers.update_item(
            Key={"packet_id": packet_id, "signer_id": signer_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames={"#status": "status", "#status_key": "status_key"},
            ExpressionAttributeValues=values,
            ConditionExpression="#status = :pending",
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise ValueError("signer_not_pending") from exc
        raise
    return response.get("Attributes", {})


def mark_packet_partially_signed(packet_id: str) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    _ensure_packet_not_completed(packet_id)
    now = datetime.now(timezone.utc).isoformat()
    try:
        response = T.signature_packets.update_item(
            Key={"packet_id": packet_id},
            UpdateExpression="SET #status = :partially_signed, updated_at = :updated_at",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":partially_signed": SignaturePacketStatus.PARTIALLY_SIGNED.value,
                ":updated_at": now,
                ":sent": SignaturePacketStatus.SENT.value,
            },
            ConditionExpression="#status = :sent",
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return None
        raise
    return response.get("Attributes", {})


def are_required_signers_completed(packet_id: str) -> bool:
    require_signature_pdf_enabled()
    signers = list_packet_signers(packet_id)
    required_signers = [signer for signer in signers if bool(signer.get("required", True))]
    return all(str(signer.get("status") or "") == SignatureSignerStatus.COMPLETED.value for signer in required_signers)


def mark_packet_completed(packet_id: str) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    now = datetime.now(timezone.utc).isoformat()
    try:
        response = T.signature_packets.update_item(
            Key={"packet_id": packet_id},
            UpdateExpression="SET #status = :completed, completed_at = :completed_at, updated_at = :updated_at",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":completed": SignaturePacketStatus.COMPLETED.value,
                ":completed_at": now,
                ":updated_at": now,
            },
            ConditionExpression=Attr("status").is_in(
                [
                    SignaturePacketStatus.SENT.value,
                    SignaturePacketStatus.PARTIALLY_SIGNED.value,
                ]
            ),
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return None
        raise
    return response.get("Attributes", {})




def get_signature_packet_progress_for_user(packet_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Return participant-aware status metadata for rendering in origin surfaces."""
    require_signature_pdf_enabled()
    if not packet_id or not user_id:
        return None

    packet = get_packet(packet_id)
    if not packet:
        return None

    owner_user_id = str(packet.get("owner_user_id") or "")
    signer = get_packet_signer(packet_id, user_id)
    is_owner = owner_user_id == user_id
    if not is_owner and not signer:
        return None

    status = str(packet.get("status") or "")
    role = "sender" if is_owner else "signer"
    signer_status = str((signer or {}).get("status") or "") if signer else None

    chip = "waiting_on_others"
    text = "Waiting on others"
    if status == SignaturePacketStatus.COMPLETED.value:
        chip = "completed"
        text = "Completed"
    elif role == "signer" and status in {
        SignaturePacketStatus.SENT.value,
        SignaturePacketStatus.PARTIALLY_SIGNED.value,
    } and signer_status != SignatureSignerStatus.COMPLETED.value:
        chip = "awaiting_your_signature"
        text = "Awaiting your signature"

    progress: Dict[str, Any] = {
        "signature_packet_id": packet_id,
        "signature_packet_role": role,
        "signature_packet_status": status,
        "signature_packet_status_chip": chip,
        "signature_packet_status_text": text,
        "signature_packet_completed_at": packet.get("completed_at"),
    }

    if status == SignaturePacketStatus.COMPLETED.value:
        artifact = get_packet_artifact(packet_id) or {}
        if artifact.get("status") == "ready":
            progress["signature_packet_final_pdf_url"] = f"/v1/signature-packets/{packet_id}/final-pdf"

    return progress
def get_packet_artifact(packet_id: str) -> Optional[Dict[str, Any]]:
    require_signature_pdf_enabled()
    return T.signature_packet_artifacts.get_item(Key={"packet_id": packet_id}).get("Item")


def put_packet_artifact(packet_id: str, artifact: Dict[str, Any]) -> Dict[str, Any]:
    require_signature_pdf_enabled()
    item = {"packet_id": packet_id, **artifact}
    T.signature_packet_artifacts.put_item(Item=item)
    return item


def list_completed_packets(*, limit: int = 25) -> List[Dict[str, Any]]:
    require_signature_pdf_enabled()
    response = T.signature_packets.scan(
        FilterExpression=Attr("status").eq(SignaturePacketStatus.COMPLETED.value),
        Limit=limit,
    )
    return response.get("Items", [])



def mark_completion_notices_sent(packet_id: str, *, recipient_user_ids: List[str]) -> bool:
    require_signature_pdf_enabled()
    now = datetime.now(timezone.utc).isoformat()
    recipients = sorted({str(u) for u in recipient_user_ids if str(u)})
    if not recipients:
        return False
    try:
        T.signature_packet_artifacts.update_item(
            Key={"packet_id": packet_id},
            UpdateExpression=(
                "SET completion_notified_at = :now, completion_notified_user_ids = :recipient_user_ids, updated_at = :now"
            ),
            ExpressionAttributeValues={
                ":now": now,
                ":recipient_user_ids": recipients,
            },
            ConditionExpression="attribute_not_exists(completion_notified_at)",
            ReturnValues="NONE",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return False
        raise
    return True
