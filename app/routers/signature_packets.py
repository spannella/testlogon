from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from datetime import date, datetime, timezone
import base64
import json
import time

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.filemanager import get_node
from app.services.sessions import require_ui_session
from app.services.signature_packet_domain import (
    SignatureFieldType,
    SignaturePacketStatus,
    SignatureSignerStatus,
)
from app.services.signature_packet_store import (
    add_packet_signer,
    append_packet_event,
    are_required_signers_completed,
    mark_packet_completed,
    create_draft_packet,
    remove_packet_signer,
    delete_packet_field,
    fill_packet_field,
    get_packet_field,
    get_packet,
    get_packet_signer,
    list_packet_fields,
    list_packet_signers,
    list_packet_events,
    mark_packet_partially_signed,
    mark_signer_completed,
    mark_packet_sent,
    mark_completion_notices_sent,
    signer_assignment_exists,
    upsert_packet_field,
    get_packet_artifact,
    mark_signer_notice_accepted,
    mark_signer_notice_shown,
    signer_has_accepted_notice,
)

router = APIRouter(prefix="/v1/signature-packets", tags=["signature-packets"])


def _raise_packet_error(
    *,
    status_code: int,
    code: str,
    user_sub: str,
    packet_id: Optional[str] = None,
    category: Literal["authorization", "validation"] = "validation",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    if packet_id:
        event_type = "packet_authorization_failed" if category == "authorization" else "packet_validation_failed"
        payload = {"code": code}
        if extra:
            payload.update(extra)
        try:
            append_packet_event(
                packet_id=packet_id,
                actor_user_id=user_sub,
                event_type=event_type,
                event_payload=payload,
            )
        except Exception:
            pass
    raise HTTPException(status_code=status_code, detail={"code": code})


def _current_user(ctx=Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


def _current_session(ctx=Depends(require_ui_session)) -> Dict[str, str]:
    return ctx


def _current_ip(ctx=Depends(require_ui_session)) -> str:
    return str(ctx.get("ip") or "")


class CreateSignaturePacketIn(BaseModel):
    source_path: str = Field(..., description="Path to an existing uploaded PDF")
    origin_channel: Literal["share", "message"] = Field(..., description="Workflow origin surface")
    origin_ref: Optional[str] = Field(default=None, description="Optional channel-specific reference id")


class CreateSignaturePacketOut(BaseModel):
    packet_id: str
    status: str
    owner_user_id: str
    source_path: str
    origin_channel: Literal["share", "message"]
    origin_ref: Optional[str] = None
    created_at: str


class SignaturePacketFieldMutationIn(BaseModel):
    action: Literal["create", "update", "delete"]
    field_id: Optional[str] = None
    page: Optional[int] = None
    x: Optional[float] = None
    y: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None
    field_type: Optional[SignatureFieldType] = None
    assigned_signer_id: Optional[str] = None
    required: bool = True


class SignaturePacketFieldMutationOut(BaseModel):
    packet_id: str
    action: Literal["create", "update", "delete"]
    field_id: str
    field: Optional[Dict[str, Any]] = None


class SendSignaturePacketOut(BaseModel):
    packet_id: str
    status: str
    sent_at: str
    invited_signers: int


class SignaturePacketDetailOut(BaseModel):
    packet_id: str
    status: str
    owner_user_id: str
    source_path: str
    origin_channel: Optional[str] = None
    origin_ref: Optional[str] = None
    created_at: Optional[str] = None
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None
    role: Literal["sender", "signer"]
    signer_status: Optional[str] = None
    signers: list[Dict[str, Any]]
    fields: list[Dict[str, Any]]
    capabilities: Dict[str, bool]
    legal_notice: Optional[Dict[str, Any]] = None


class SignaturePacketLegalNoticeAckOut(BaseModel):
    packet_id: str
    signer_id: str
    accepted: bool
    notice_version: str


class NotaryStampFieldIn(BaseModel):
    stamp_image_ref: str = Field(..., min_length=1, max_length=512)
    stamp_number: str = Field(..., min_length=1, max_length=128)
    stamp_expiry: str = Field(..., min_length=1, max_length=10, description="YYYY-MM-DD")


class SignaturePacketFieldFillIn(BaseModel):
    value: Optional[str] = None
    input_mode: Optional[Literal["typed", "drawn"]] = None
    drawn_strokes: Optional[list[list[float]]] = None
    notary_stamp: Optional[NotaryStampFieldIn] = None


class SignaturePacketFieldFillOut(BaseModel):
    packet_id: str
    field_id: str
    value: str
    filled_at: str
    filled_by_signer_id: str
    capture_mode: Optional[str] = None


class SignaturePacketMarkDoneOut(BaseModel):
    packet_id: str
    signer_id: str
    signer_status: str
    packet_status: str
    completed_at: str


class SignaturePacketFinalPdfOut(BaseModel):
    packet_id: str
    content_type: str
    sha256: str
    size_bytes: int


class SignaturePacketEventOut(BaseModel):
    event_id: str
    packet_id: str
    actor_user_id: str
    event_type: str
    event_payload: Dict[str, Any]
    created_at: str


class SignaturePacketEventsOut(BaseModel):
    packet_id: str
    events: list[SignaturePacketEventOut]


class AddSignerIn(BaseModel):
    signer_id: str = Field(..., min_length=1, max_length=256)
    email: Optional[str] = Field(default=None, max_length=256)
    required: bool = True


class AddSignerOut(BaseModel):
    packet_id: str
    signer_id: str
    status: str
    required: bool
    added_at: str


def _emit_completion_notices_once(packet_id: str, owner_user_id: str, signers: list[Dict[str, Any]], actor_user_id: str) -> bool:
    recipients = [owner_user_id] + [str(s.get("signer_id") or "") for s in signers]
    if not mark_completion_notices_sent(packet_id, recipient_user_ids=recipients):
        return False

    unique_recipients = sorted({str(u) for u in recipients if str(u)})
    for recipient in unique_recipients:
        append_packet_event(
            packet_id=packet_id,
            actor_user_id=actor_user_id,
            event_type="completion_notice_sent",
            event_payload={"recipient_user_id": recipient},
        )
    return True


def _legal_notice() -> Dict[str, str]:
    return {
        "version": S.signature_packet_legal_notice_version,
        "text": S.signature_packet_legal_notice_text,
    }


def _signer_requires_legal_notice_ack(packet_id: str, signer_id: str, signer_record: Optional[Dict[str, Any]] = None) -> bool:
    notice_version = _legal_notice()["version"]
    if signer_record is not None:
        return str(signer_record.get("legal_notice_accepted_version") or "") != notice_version
    return not signer_has_accepted_notice(packet_id, signer_id, notice_version)


@router.post("", response_model=CreateSignaturePacketOut)
def create_signature_packet(inp: CreateSignaturePacketIn, user_sub: str = Depends(_current_user)) -> Dict[str, Any]:
    node = get_node(user_sub, inp.source_path)
    if node.get("type") != "file":
        raise HTTPException(status_code=400, detail={"code": "invalid_source_file", "message": "Source path must be a file"})

    content_type = str(node.get("content_type") or "").strip().lower()
    if content_type != "application/pdf":
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_source_file_type",
                "message": "Source file must be a PDF",
                "expected_content_type": "application/pdf",
                "actual_content_type": content_type or "unknown",
            },
        )

    packet = create_draft_packet(
        owner_user_id=user_sub,
        source_path=inp.source_path,
        source_content_type=content_type,
        source_name=str(node.get("name") or ""),
        origin_channel=inp.origin_channel,
        origin_ref=inp.origin_ref,
    )
    append_packet_event(
        packet_id=packet["packet_id"],
        actor_user_id=user_sub,
        event_type="packet_created",
        event_payload={"origin_channel": inp.origin_channel, "origin_ref": inp.origin_ref},
    )
    return {
        "packet_id": packet["packet_id"],
        "status": packet["status"],
        "owner_user_id": packet["owner_user_id"],
        "source_path": packet["source_path"],
        "origin_channel": packet["origin_channel"],
        "origin_ref": packet.get("origin_ref"),
        "created_at": packet["created_at"],
    }


def _validate_packet_owner_and_draft(packet_id: str, user_sub: str) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})
    if packet.get("owner_user_id") != user_sub:
        _raise_packet_error(
            status_code=403,
            code="signature_packet_not_owner",
            packet_id=packet_id,
            user_sub=user_sub,
            category="authorization",
        )
    if packet.get("status") != SignaturePacketStatus.DRAFT.value:
        _raise_packet_error(
            status_code=409,
            code="signature_packet_not_draft",
            packet_id=packet_id,
            user_sub=user_sub,
            category="validation",
            extra={"status": str(packet.get("status") or "")},
        )
    return packet


@router.post("/{packet_id}/signers", response_model=AddSignerOut)
def add_signer(
    packet_id: str,
    inp: AddSignerIn,
    user_sub: str = Depends(_current_user),
) -> Dict[str, Any]:
    _validate_packet_owner_and_draft(packet_id, user_sub)
    signer = add_packet_signer(
        packet_id=packet_id,
        signer_id=inp.signer_id,
        email=inp.email,
        required=inp.required,
    )
    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="signer_added",
        event_payload={"signer_id": inp.signer_id, "required": bool(inp.required)},
    )
    return {
        "packet_id": packet_id,
        "signer_id": inp.signer_id,
        "status": str(signer.get("status") or SignatureSignerStatus.PENDING.value),
        "required": bool(inp.required),
        "added_at": str(signer.get("added_at") or ""),
    }


@router.delete("/{packet_id}/signers/{signer_id}", status_code=204)
def remove_signer(
    packet_id: str,
    signer_id: str,
    user_sub: str = Depends(_current_user),
) -> Response:
    _validate_packet_owner_and_draft(packet_id, user_sub)
    remove_packet_signer(packet_id=packet_id, signer_id=signer_id)
    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="signer_removed",
        event_payload={"signer_id": signer_id},
    )
    return Response(status_code=204)


def _validate_field_geometry(inp: SignaturePacketFieldMutationIn) -> None:
    if inp.page is None or inp.page < 1:
        raise HTTPException(status_code=400, detail={"code": "invalid_field_page"})
    for key in ("x", "y", "width", "height"):
        value = getattr(inp, key)
        if value is None:
            raise HTTPException(status_code=400, detail={"code": f"missing_{key}"})
    if inp.width <= 0 or inp.height <= 0:
        raise HTTPException(status_code=400, detail={"code": "invalid_field_size"})
    if inp.x < 0 or inp.y < 0 or inp.width > 1 or inp.height > 1 or (inp.x + inp.width) > 1 or (inp.y + inp.height) > 1:
        raise HTTPException(status_code=400, detail={"code": "invalid_field_bounds"})


@router.post("/{packet_id}/fields", response_model=SignaturePacketFieldMutationOut)
def mutate_signature_packet_field(
    packet_id: str,
    inp: SignaturePacketFieldMutationIn,
    user_sub: str = Depends(_current_user),
) -> Dict[str, Any]:
    _validate_packet_owner_and_draft(packet_id, user_sub)

    if inp.action == "delete":
        if not inp.field_id:
            raise HTTPException(status_code=400, detail={"code": "missing_field_id"})
        try:
            delete_packet_field(packet_id=packet_id, field_id=inp.field_id)
        except ValueError as exc:
            if str(exc) == "packet_immutable":
                raise HTTPException(status_code=409, detail={"code": "signature_packet_immutable"}) from exc
            raise
        append_packet_event(
            packet_id=packet_id,
            actor_user_id=user_sub,
            event_type="field_deleted",
            event_payload={"field_id": inp.field_id},
        )
        return {"packet_id": packet_id, "action": inp.action, "field_id": inp.field_id, "field": None}

    if inp.action == "update" and not inp.field_id:
        raise HTTPException(status_code=400, detail={"code": "missing_field_id"})
    if inp.action == "create" and inp.field_id:
        raise HTTPException(status_code=400, detail={"code": "field_id_not_allowed_for_create"})
    if inp.field_type is None:
        raise HTTPException(status_code=400, detail={"code": "missing_field_type"})

    _validate_field_geometry(inp)

    if inp.assigned_signer_id and not signer_assignment_exists(packet_id, inp.assigned_signer_id):
        raise HTTPException(status_code=400, detail={"code": "invalid_assigned_signer"})

    field_id = inp.field_id or f"sf_{uuid4().hex}"
    try:
        field = upsert_packet_field(
            packet_id=packet_id,
            field_id=field_id,
            page=int(inp.page),
            x=float(inp.x),
            y=float(inp.y),
            width=float(inp.width),
            height=float(inp.height),
            field_type=inp.field_type,
            assigned_signer_id=inp.assigned_signer_id,
            required=inp.required,
        )
    except ValueError as exc:
        if str(exc) == "packet_immutable":
            raise HTTPException(status_code=409, detail={"code": "signature_packet_immutable"}) from exc
        raise
    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="field_created" if inp.action == "create" else "field_updated",
        event_payload={
            "field_id": field_id,
            "field_type": inp.field_type.value if inp.field_type else None,
            "assigned_signer_id": inp.assigned_signer_id,
            "required": bool(inp.required),
            "page": int(inp.page),
        },
    )
    return {"packet_id": packet_id, "action": inp.action, "field_id": field_id, "field": field}


@router.post("/{packet_id}/send", response_model=SendSignaturePacketOut)
def send_signature_packet(packet_id: str, user_sub: str = Depends(_current_user)) -> Dict[str, Any]:
    _validate_packet_owner_and_draft(packet_id, user_sub)

    signers = list_packet_signers(packet_id)
    if not signers:
        raise HTTPException(status_code=400, detail={"code": "signature_packet_no_signers"})

    fields = list_packet_fields(packet_id)
    if not fields:
        raise HTTPException(status_code=400, detail={"code": "signature_packet_no_fields"})

    required_fields = [field for field in fields if field.get("required", True)]
    unassigned_required = [field.get("field_id") for field in required_fields if not field.get("assigned_signer_id")]
    if unassigned_required:
        raise HTTPException(
            status_code=400,
            detail={"code": "required_field_unassigned", "field_ids": [f for f in unassigned_required if f]},
        )

    signer_ids = {str(s.get("signer_id")) for s in signers if s.get("signer_id")}
    invalid_assignees = sorted(
        {
            str(field.get("assigned_signer_id"))
            for field in required_fields
            if field.get("assigned_signer_id") and str(field.get("assigned_signer_id")) not in signer_ids
        }
    )
    if invalid_assignees:
        raise HTTPException(status_code=400, detail={"code": "required_field_invalid_assignee", "assignees": invalid_assignees})

    sent_packet = mark_packet_sent(packet_id)
    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="packet_sent",
        event_payload={"invited_signers": len(signer_ids)},
    )
    for signer_id in signer_ids:
        append_packet_event(
            packet_id=packet_id,
            actor_user_id=user_sub,
            event_type="signer_invited",
            event_payload={"signer_id": signer_id},
        )
    return {
        "packet_id": packet_id,
        "status": sent_packet.get("status", SignaturePacketStatus.SENT.value),
        "sent_at": sent_packet.get("sent_at") or "",
        "invited_signers": len(signer_ids),
    }


@router.get("/{packet_id}", response_model=SignaturePacketDetailOut)
def get_signature_packet_detail(packet_id: str, user_sub: str = Depends(_current_user)) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})

    signer_record = get_packet_signer(packet_id, user_sub)
    is_owner = packet.get("owner_user_id") == user_sub
    if not is_owner and not signer_record:
        _raise_packet_error(status_code=403, code="signature_packet_not_participant", packet_id=packet_id, user_sub=user_sub, category="authorization")

    signers = list_packet_signers(packet_id)
    fields = list_packet_fields(packet_id)
    status = str(packet.get("status") or "")
    role: Literal["sender", "signer"] = "sender" if is_owner else "signer"

    can_edit_fields = is_owner and status == SignaturePacketStatus.DRAFT.value
    can_send = is_owner and status == SignaturePacketStatus.DRAFT.value
    can_fill_fields = (not is_owner) and status in {
        SignaturePacketStatus.SENT.value,
        SignaturePacketStatus.PARTIALLY_SIGNED.value,
    }
    legal_notice_required = False
    legal_notice = None
    if not is_owner:
        legal = _legal_notice()
        legal_notice_required = _signer_requires_legal_notice_ack(packet_id, user_sub, signer_record)
        legal_notice = {
            "required": legal_notice_required,
            "accepted": not legal_notice_required,
            "version": legal["version"],
            "text": legal["text"],
        }
        if legal_notice_required and mark_signer_notice_shown(packet_id, user_sub, legal["version"]):
            append_packet_event(
                packet_id=packet_id,
                actor_user_id=user_sub,
                event_type="legal_notice_shown",
                event_payload={"notice_version": legal["version"]},
            )
        can_fill_fields = can_fill_fields and not legal_notice_required

    viewer_signer_id = user_sub if not is_owner else None
    shaped_fields: list[Dict[str, Any]] = []
    for field in fields:
        assigned_signer_id = field.get("assigned_signer_id")
        shaped = {
            "field_id": field.get("field_id"),
            "page": field.get("page"),
            "x": field.get("x"),
            "y": field.get("y"),
            "width": field.get("width"),
            "height": field.get("height"),
            "field_type": field.get("field_type"),
            "required": bool(field.get("required", True)),
            "assigned_signer_id": assigned_signer_id,
            "is_assigned_to_viewer": bool(viewer_signer_id and assigned_signer_id == viewer_signer_id),
        }
        shaped_fields.append(shaped)

    return {
        "packet_id": packet.get("packet_id"),
        "status": status,
        "owner_user_id": packet.get("owner_user_id"),
        "source_path": packet.get("source_path"),
        "origin_channel": packet.get("origin_channel"),
        "origin_ref": packet.get("origin_ref"),
        "created_at": packet.get("created_at"),
        "sent_at": packet.get("sent_at"),
        "completed_at": packet.get("completed_at"),
        "role": role,
        "signer_status": signer_record.get("status") if signer_record else None,
        "signers": signers,
        "fields": shaped_fields,
        "capabilities": {
            "can_edit_fields": can_edit_fields,
            "can_send": can_send,
            "can_fill_fields": can_fill_fields,
        },
        "legal_notice": legal_notice,
    }


@router.post("/{packet_id}/acknowledge-legal-notice", response_model=SignaturePacketLegalNoticeAckOut)
def acknowledge_signature_packet_legal_notice(packet_id: str, user_sub: str = Depends(_current_user)) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})

    signer_record = get_packet_signer(packet_id, user_sub)
    if not signer_record:
        _raise_packet_error(status_code=403, code="signature_packet_not_signer", packet_id=packet_id, user_sub=user_sub, category="authorization")

    notice_version = _legal_notice()["version"]
    accepted = mark_signer_notice_accepted(packet_id, user_sub, notice_version)
    if accepted:
        append_packet_event(
            packet_id=packet_id,
            actor_user_id=user_sub,
            event_type="legal_notice_accepted",
            event_payload={"notice_version": notice_version},
        )
    return {
        "packet_id": packet_id,
        "signer_id": user_sub,
        "accepted": True,
        "notice_version": notice_version,
    }


def _normalize_field_value(field_type: str, inp: SignaturePacketFieldFillIn) -> Dict[str, Any]:
    raw = (inp.value or "").strip()
    if field_type in {SignatureFieldType.SIGNATURE.value, SignatureFieldType.INITIALS.value}:
        mode = inp.input_mode or "typed"
        if mode not in {"typed", "drawn"}:
            raise HTTPException(status_code=400, detail={"code": "invalid_signature_input_mode"})
        if mode == "typed":
            if not raw:
                raise HTTPException(status_code=400, detail={"code": "empty_signature_value"})
            if len(raw) > 64:
                raise HTTPException(status_code=400, detail={"code": "signature_value_too_long", "max_length": 64})
            return {
                "value": raw,
                "capture_mode": "typed",
                "render_payload": {"kind": "typed_text", "text": raw},
            }

        strokes = inp.drawn_strokes or []
        if not strokes:
            raise HTTPException(status_code=400, detail={"code": "empty_signature_strokes"})
        if len(strokes) > 20:
            raise HTTPException(status_code=400, detail={"code": "signature_stroke_count_too_large", "max_strokes": 20})
        normalized_strokes: list[list[float]] = []
        for point in strokes:
            if len(point) != 2:
                raise HTTPException(status_code=400, detail={"code": "invalid_signature_stroke_point"})
            x, y = float(point[0]), float(point[1])
            if x < 0 or x > 1 or y < 0 or y > 1:
                raise HTTPException(status_code=400, detail={"code": "signature_stroke_out_of_bounds"})
            normalized_strokes.append([x, y])
        if len(normalized_strokes) < 2:
            raise HTTPException(status_code=400, detail={"code": "signature_stroke_too_short", "min_points": 2})
        return {
            "value": "[drawn]",
            "capture_mode": "drawn",
            "render_payload": {"kind": "drawn_path", "strokes": normalized_strokes, "point_count": len(normalized_strokes)},
        }
    if field_type == SignatureFieldType.DATE.value:
        if not raw:
            raise HTTPException(status_code=400, detail={"code": "empty_date_value"})
        try:
            normalized = date.fromisoformat(raw).isoformat()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_date_format", "expected": "YYYY-MM-DD"}) from exc
        return {"value": normalized}
    if field_type == SignatureFieldType.TEXT.value:
        if len(raw) > 500:
            raise HTTPException(status_code=400, detail={"code": "text_value_too_long", "max_length": 500})
        return {"value": raw}
    if field_type == SignatureFieldType.NOTARY_STAMP.value:
        return _normalize_notary_stamp_value(inp)
    raise HTTPException(status_code=400, detail={"code": "unsupported_field_type"})


def _normalize_notary_stamp_value(inp: SignaturePacketFieldFillIn) -> Dict[str, Any]:
    """Validate and normalize a notary_stamp field value.

    The stamp payload is supplied either via the structured ``notary_stamp`` body
    field or, for convenience/E2E determinism, as a JSON object encoded in ``value``.
    Stores stamp_image_ref, stamp_number, stamp_expiry (YYYY-MM-DD) and stamped_at.
    """
    payload = getattr(inp, "notary_stamp", None)
    data: Dict[str, Any]
    if payload is not None:
        data = payload.model_dump() if hasattr(payload, "model_dump") else dict(payload)
    else:
        raw = (inp.value or "").strip()
        if not raw:
            raise HTTPException(status_code=400, detail={"code": "empty_notary_stamp_value"})
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail={"code": "invalid_notary_stamp_value"}) from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail={"code": "invalid_notary_stamp_value"})
        data = parsed

    stamp_image_ref = str(data.get("stamp_image_ref") or "").strip()
    stamp_number = str(data.get("stamp_number") or "").strip()
    stamp_expiry = str(data.get("stamp_expiry") or "").strip()
    if not stamp_image_ref or not stamp_number or not stamp_expiry:
        raise HTTPException(
            status_code=400,
            detail={"code": "notary_stamp_missing_fields", "required": ["stamp_image_ref", "stamp_number", "stamp_expiry"]},
        )
    try:
        expiry_date = date.fromisoformat(stamp_expiry)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"code": "invalid_notary_stamp_expiry", "expected": "YYYY-MM-DD"}) from exc
    # Reject expired notary commissions (error matrix #14).
    if expiry_date < datetime.now(timezone.utc).date():
        raise HTTPException(status_code=400, detail={"code": "notary_stamp_expired"})

    stamped_at = int(time.time())
    render_payload = {
        "kind": "notary_stamp",
        "stamp_image_ref": stamp_image_ref,
        "stamp_number": stamp_number,
        "stamp_expiry": stamp_expiry,
        "stamped_at": stamped_at,
    }
    return {
        "value": f"notary:{stamp_number}",
        "capture_mode": "notary_stamp",
        "render_payload": render_payload,
    }


@router.post("/{packet_id}/fields/{field_id}/fill", response_model=SignaturePacketFieldFillOut)
def fill_signature_packet_field(
    packet_id: str,
    field_id: str,
    inp: SignaturePacketFieldFillIn,
    user_sub: str = Depends(_current_user),
    request_ip: str = Depends(_current_ip),
) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})

    if packet.get("status") not in {SignaturePacketStatus.SENT.value, SignaturePacketStatus.PARTIALLY_SIGNED.value}:
        raise HTTPException(status_code=409, detail={"code": "signature_packet_not_fillable"})

    signer_record = get_packet_signer(packet_id, user_sub)
    if not signer_record:
        _raise_packet_error(status_code=403, code="signature_packet_not_signer", packet_id=packet_id, user_sub=user_sub, category="authorization")
    if _signer_requires_legal_notice_ack(packet_id, user_sub, signer_record):
        raise HTTPException(status_code=409, detail={"code": "signature_packet_legal_notice_required"})

    field = get_packet_field(packet_id, field_id)
    if not field:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_field_not_found"})

    assigned_signer_id = field.get("assigned_signer_id")
    if assigned_signer_id != user_sub:
        _raise_packet_error(status_code=403, code="signature_packet_field_not_assigned_to_signer", packet_id=packet_id, user_sub=user_sub, category="authorization", extra={"field_id": field_id})

    normalized = _normalize_field_value(str(field.get("field_type") or ""), inp)
    try:
        updated = fill_packet_field(
            packet_id=packet_id,
            field_id=field_id,
            value=str(normalized["value"]),
            filled_by_signer_id=user_sub,
            capture_mode=normalized.get("capture_mode"),
            render_payload=normalized.get("render_payload"),
        )
    except ValueError as exc:
        if str(exc) == "packet_immutable":
            raise HTTPException(status_code=409, detail={"code": "signature_packet_immutable"}) from exc
        raise
    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="field_filled",
        event_payload={
            "field_id": field_id,
            "field_type": field.get("field_type"),
            "capture_mode": normalized.get("capture_mode"),
            "source_ip": request_ip,
        },
    )
    return {
        "packet_id": packet_id,
        "field_id": field_id,
        "value": str(updated.get("value") or normalized["value"]),
        "filled_at": str(updated.get("filled_at") or ""),
        "filled_by_signer_id": str(updated.get("filled_by_signer_id") or user_sub),
        "capture_mode": str(updated.get("capture_mode") or normalized.get("capture_mode") or "") or None,
    }


@router.post("/{packet_id}/mark-done", response_model=SignaturePacketMarkDoneOut)
def mark_signature_packet_done(
    packet_id: str,
    user_sub: str = Depends(_current_user),
    request_ip: str = Depends(_current_ip),
) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})

    packet_status = str(packet.get("status") or "")
    if packet_status not in {SignaturePacketStatus.SENT.value, SignaturePacketStatus.PARTIALLY_SIGNED.value}:
        raise HTTPException(status_code=409, detail={"code": "signature_packet_not_completable"})

    signer_record = get_packet_signer(packet_id, user_sub)
    if not signer_record:
        _raise_packet_error(status_code=403, code="signature_packet_not_signer", packet_id=packet_id, user_sub=user_sub, category="authorization")
    if _signer_requires_legal_notice_ack(packet_id, user_sub, signer_record):
        raise HTTPException(status_code=409, detail={"code": "signature_packet_legal_notice_required"})
    if signer_record.get("status") == "completed":
        raise HTTPException(status_code=409, detail={"code": "signer_already_completed"})

    fields = list_packet_fields(packet_id)
    required_for_signer = [
        field
        for field in fields
        if bool(field.get("required", True)) and field.get("assigned_signer_id") == user_sub
    ]
    remaining_required = [
        str(field.get("field_id") or "")
        for field in required_for_signer
        if not field.get("filled_at")
    ]
    remaining_required = [fid for fid in remaining_required if fid]
    if remaining_required:
        try:
            append_packet_event(
                packet_id=packet_id,
                actor_user_id=user_sub,
                event_type="packet_validation_failed",
                event_payload={
                    "code": "required_fields_incomplete",
                    "remaining_required_count": len(remaining_required),
                    "remaining_field_ids": remaining_required,
                },
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail={
                "code": "required_fields_incomplete",
                "remaining_required_count": len(remaining_required),
                "remaining_field_ids": remaining_required,
            },
        )

    try:
        signer = mark_signer_completed(packet_id, user_sub, source_ip=request_ip)
    except ValueError as exc:
        if str(exc) == "signer_not_pending":
            raise HTTPException(status_code=409, detail={"code": "signer_not_pending"}) from exc
        if str(exc) == "packet_immutable":
            raise HTTPException(status_code=409, detail={"code": "signature_packet_immutable"}) from exc
        raise

    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="signer_completed",
        event_payload={"signer_id": user_sub, "source_ip": request_ip},
    )

    completed_packet = None
    if are_required_signers_completed(packet_id):
        completed_packet = mark_packet_completed(packet_id)
        if completed_packet:
            append_packet_event(
                packet_id=packet_id,
                actor_user_id=user_sub,
                event_type="packet_completed",
                event_payload={"completed_by_signer_id": user_sub},
            )
            append_packet_event(
                packet_id=packet_id,
                actor_user_id=user_sub,
                event_type="packet_finalize_requested",
                event_payload={"packet_id": packet_id},
            )
            _emit_completion_notices_once(
                packet_id=packet_id,
                owner_user_id=str(packet.get("owner_user_id") or ""),
                signers=list_packet_signers(packet_id),
                actor_user_id=user_sub,
            )

    if completed_packet:
        current_packet_status = str(completed_packet.get("status") or SignaturePacketStatus.COMPLETED.value)
    else:
        updated_packet = mark_packet_partially_signed(packet_id)
        current_packet_status = str((updated_packet or {}).get("status") or packet_status)
    return {
        "packet_id": packet_id,
        "signer_id": user_sub,
        "signer_status": str(signer.get("status") or "completed"),
        "packet_status": current_packet_status,
        "completed_at": str(signer.get("completed_at") or ""),
    }


@router.get("/{packet_id}/events", response_model=SignaturePacketEventsOut)
def get_signature_packet_events(packet_id: str, user_sub: str = Depends(_current_user)) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})

    signer_record = get_packet_signer(packet_id, user_sub)
    is_owner = packet.get("owner_user_id") == user_sub
    if not is_owner and not signer_record:
        _raise_packet_error(
            status_code=403,
            code="signature_packet_not_participant",
            packet_id=packet_id,
            user_sub=user_sub,
            category="authorization",
        )

    events = list_packet_events(packet_id)
    return {"packet_id": packet_id, "events": events}


@router.get("/{packet_id}/final-pdf")
def get_signature_packet_final_pdf(packet_id: str, user_sub: str = Depends(_current_user)) -> Response:
    packet = get_packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"})

    signer_record = get_packet_signer(packet_id, user_sub)
    is_owner = packet.get("owner_user_id") == user_sub
    if not is_owner and not signer_record:
        _raise_packet_error(status_code=403, code="signature_packet_not_participant", packet_id=packet_id, user_sub=user_sub, category="authorization")

    if str(packet.get("status") or "") != SignaturePacketStatus.COMPLETED.value:
        raise HTTPException(status_code=409, detail={"code": "signature_packet_not_completed"})

    artifact = get_packet_artifact(packet_id)
    if not artifact or str(artifact.get("status") or "") != "ready" or not artifact.get("final_pdf_base64"):
        raise HTTPException(status_code=404, detail={"code": "signature_packet_final_pdf_not_ready"})

    try:
        pdf_bytes = base64.b64decode(str(artifact.get("final_pdf_base64") or ""), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail={"code": "signature_packet_final_pdf_corrupt"}) from exc

    append_packet_event(
        packet_id=packet_id,
        actor_user_id=user_sub,
        event_type="packet_final_pdf_downloaded",
        event_payload={"sha256": str(artifact.get("sha256") or "")},
    )
    headers = {
        "Content-Disposition": f'attachment; filename="signature-packet-{packet_id}.pdf"',
        "X-Signature-Packet-Sha256": str(artifact.get("sha256") or ""),
    }
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
