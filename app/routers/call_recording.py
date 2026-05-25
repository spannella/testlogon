"""WebRTC call recording endpoints (CALL-009).

Provides mutual-consent recording request/accept/decline, presigned upload,
upload completion, download URL generation, and recording listing.
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.settings import S
from app.core.time import now_ts

router = APIRouter(tags=["call-recording"])


# ---------------------------------------------------------------------------
# Auth dependency — reuse from messaging router
# ---------------------------------------------------------------------------


async def _get_user_id(request: Request) -> str:
    """Extract user ID from session (same pattern as messaging get_messaging_user_id)."""
    from app.routers.messaging import get_messaging_user_id

    authorization = request.headers.get("authorization")
    x_session_id = request.headers.get("x-session-id")
    return await get_messaging_user_id(request, authorization=authorization, x_session_id=x_session_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_recording_enabled():
    if not S.call_recording_enabled:
        raise HTTPException(status_code=503, detail={"code": "feature_disabled", "message": "Call recording is disabled"})


def _get_call_session(call_id: str):
    from app.services.messaging_call_sessions import get_call_session
    session = get_call_session(call_id)
    if not session:
        raise HTTPException(status_code=404, detail={"code": "call_not_found", "message": "Call session not found"})
    return session


def _require_call_participant(call_session, user_id: str):
    participants = {call_session.caller_user_id, call_session.callee_user_id}
    if user_id not in participants:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "Not a call participant"})


def _require_recording_participant(recording, user_id: str):
    if user_id not in recording.participants:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "Not a recording participant"})


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class RecordingRequestOut(BaseModel):
    recording_id: str
    status: str
    created_at: int


class RecordingConsentOut(BaseModel):
    recording_id: str
    status: str
    started_at: int


class RecordingDeclineOut(BaseModel):
    ok: bool = True


class RecordingUploadPresignIn(BaseModel):
    content_type: str = Field(..., pattern=r"^video/(webm|mp4)$")
    file_size_bytes: int = Field(..., gt=0)


class RecordingUploadPresignOut(BaseModel):
    upload_url: str
    recording_id: str
    s3_key: str
    expires_at: int


class RecordingUploadCompleteIn(BaseModel):
    recording_id: str
    duration_seconds: float = Field(..., gt=0)


class RecordingUploadCompleteOut(BaseModel):
    recording_id: str
    status: str
    download_url: Optional[str] = None
    download_expires_at: Optional[int] = None


class RecordingMetadataOut(BaseModel):
    recording_id: str
    call_id: str
    conversation_id: str
    initiated_by: str
    participants: list[str]
    status: str
    mime_type: str
    duration_seconds: float
    file_size_bytes: int
    created_at: int
    started_at: int
    completed_at: int
    download_url: Optional[str] = None
    download_expires_at: Optional[int] = None


class RecordingListOut(BaseModel):
    items: list[RecordingMetadataOut]


class RecordingDownloadOut(BaseModel):
    download_url: str
    download_expires_at: int
    file_size_bytes: int
    filename: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/messages/calls/{call_id}/recording/request", response_model=RecordingRequestOut)
async def request_recording(
    call_id: str,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Request recording — creates recording in pending_consent status."""
    _require_recording_enabled()

    from app.services.call_recording_store import create_recording, get_active_recording_for_call

    call_session = _get_call_session(call_id)
    _require_call_participant(call_session, user_id)

    if call_session.state != "connected":
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": "Call must be in connected state to record"},
        )

    existing = get_active_recording_for_call(call_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail={"code": "recording_already_active", "message": "A recording is already active for this call"},
        )

    participants = [call_session.caller_user_id, call_session.callee_user_id]
    recording = create_recording(
        call_id=call_id,
        conversation_id=call_session.conversation_id,
        initiated_by=user_id,
        participants=participants,
    )

    return RecordingRequestOut(
        recording_id=recording.recording_id,
        status=recording.status,
        created_at=recording.created_at,
    )


@router.post("/messages/calls/{call_id}/recording/consent", response_model=RecordingConsentOut)
async def consent_recording_endpoint(
    call_id: str,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Accept recording request — transitions to recording status."""
    _require_recording_enabled()

    from app.services.call_recording_store import consent_recording, get_active_recording_for_call

    call_session = _get_call_session(call_id)
    _require_call_participant(call_session, user_id)

    recording = get_active_recording_for_call(call_id)
    if not recording:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "No pending recording for this call"},
        )

    if recording.status != "pending_consent":
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": "Recording is not in pending_consent state"},
        )

    if recording.initiated_by == user_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "self_consent", "message": "Cannot consent to your own recording request"},
        )

    updated = consent_recording(recording.recording_id, user_id)
    if not updated:
        raise HTTPException(status_code=500, detail={"code": "internal_error", "message": "Failed to update recording"})

    return RecordingConsentOut(
        recording_id=updated.recording_id,
        status=updated.status,
        started_at=updated.started_at,
    )


@router.post("/messages/calls/{call_id}/recording/decline", response_model=RecordingDeclineOut)
async def decline_recording_endpoint(
    call_id: str,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Decline recording request — deletes the pending recording."""
    _require_recording_enabled()

    from app.services.call_recording_store import get_active_recording_for_call, soft_delete_recording

    call_session = _get_call_session(call_id)
    _require_call_participant(call_session, user_id)

    recording = get_active_recording_for_call(call_id)
    if not recording:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "No pending recording for this call"},
        )

    if recording.status != "pending_consent":
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": "Recording is not in pending_consent state"},
        )

    soft_delete_recording(recording.recording_id)
    return RecordingDeclineOut(ok=True)


@router.post("/messages/calls/{call_id}/recording/upload/presign", response_model=RecordingUploadPresignOut)
async def presign_recording_upload(
    call_id: str,
    body: RecordingUploadPresignIn,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Get presigned URL for client-side recording upload."""
    _require_recording_enabled()

    from app.services.call_recording_store import get_active_recording_for_call, update_recording_status

    call_session = _get_call_session(call_id)
    _require_call_participant(call_session, user_id)

    recording = get_active_recording_for_call(call_id)
    if not recording:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "No active recording for this call"},
        )

    if recording.status not in ("recording", "uploading"):
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": "Recording must be in recording or uploading state"},
        )

    if body.file_size_bytes > S.call_recording_max_file_size_bytes:
        raise HTTPException(
            status_code=400,
            detail={"code": "file_too_large", "message": f"File exceeds maximum size of {S.call_recording_max_file_size_bytes} bytes"},
        )

    # Transition to uploading if not already
    if recording.status == "recording":
        recording = update_recording_status(recording.recording_id, "uploading")

    ext = "webm" if "webm" in body.content_type else "mp4"
    s3_key = f"{S.call_recording_s3_prefix}{recording.recording_id}/recording.{ext}"
    expires_at = int(now_ts()) + S.call_recording_upload_ttl_seconds

    # In dev mode, use mock S3 path
    if S.dev_mode:
        bucket = S.filemgr_bucket or "local-uploads"
        upload_url = f"/mock/s3/{bucket}/{s3_key}"
    else:
        # Production: generate actual presigned URL
        from app.core.aws import s3_client
        bucket = S.filemgr_bucket or "local-uploads"
        upload_url = s3_client().generate_presigned_url(
            "put_object",
            Params={"Bucket": bucket, "Key": s3_key, "ContentType": body.content_type},
            ExpiresIn=S.call_recording_upload_ttl_seconds,
        )

    return RecordingUploadPresignOut(
        upload_url=upload_url,
        recording_id=recording.recording_id,
        s3_key=s3_key,
        expires_at=expires_at,
    )


@router.post("/messages/calls/{call_id}/recording/upload/complete", response_model=RecordingUploadCompleteOut)
async def complete_recording_upload(
    call_id: str,
    body: RecordingUploadCompleteIn,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Confirm recording upload completed."""
    _require_recording_enabled()

    from app.services.call_recording_store import get_recording, complete_upload

    call_session = _get_call_session(call_id)
    _require_call_participant(call_session, user_id)

    recording = get_recording(body.recording_id)
    if not recording:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "Recording not found"},
        )

    if recording.call_id != call_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "call_mismatch", "message": "Recording does not belong to this call"},
        )

    if recording.status != "uploading":
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_state", "message": "Recording must be in uploading state to complete"},
        )

    _require_recording_participant(recording, user_id)

    # Determine S3 key from existing record or generate one
    ext = "webm" if "webm" in recording.mime_type else "mp4"
    s3_key = f"{S.call_recording_s3_prefix}{recording.recording_id}/recording.{ext}"
    bucket = S.filemgr_bucket or "local-uploads"

    # In dev mode, skip head_object verification (moto mock)
    if not S.dev_mode:
        from app.core.aws import s3_client
        try:
            s3_client().head_object(Bucket=bucket, Key=s3_key)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail={"code": "upload_not_found", "message": "Upload not found in storage"},
            )

    updated = complete_upload(
        recording.recording_id,
        s3_key=s3_key,
        s3_bucket=bucket,
        file_size_bytes=recording.file_size_bytes or 0,
        duration_seconds=body.duration_seconds,
        mime_type=recording.mime_type,
    )

    download_url = None
    download_expires_at = None
    if updated and updated.status == "ready":
        download_url, download_expires_at = _make_download_url(updated)

    return RecordingUploadCompleteOut(
        recording_id=updated.recording_id if updated else body.recording_id,
        status=updated.status if updated else "failed",
        download_url=download_url,
        download_expires_at=download_expires_at,
    )


@router.get("/messages/calls/{call_id}/recording", response_model=RecordingMetadataOut)
async def get_call_recording(
    call_id: str,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Get recording metadata for a call."""
    from app.services.call_recording_store import get_recordings_for_call

    call_session = _get_call_session(call_id)
    _require_call_participant(call_session, user_id)

    recordings = get_recordings_for_call(call_id, limit=1)
    if not recordings:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "No recording found for this call"},
        )

    recording = recordings[0]
    download_url = None
    download_expires_at = None
    if recording.status == "ready":
        download_url, download_expires_at = _make_download_url(recording)

    return RecordingMetadataOut(
        recording_id=recording.recording_id,
        call_id=recording.call_id,
        conversation_id=recording.conversation_id,
        initiated_by=recording.initiated_by,
        participants=recording.participants,
        status=recording.status,
        mime_type=recording.mime_type,
        duration_seconds=recording.duration_seconds,
        file_size_bytes=recording.file_size_bytes,
        created_at=recording.created_at,
        started_at=recording.started_at,
        completed_at=recording.completed_at,
        download_url=download_url,
        download_expires_at=download_expires_at,
    )


@router.get("/messages/recordings", response_model=RecordingListOut)
async def list_user_recordings(
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """List recordings the user participated in."""
    from app.services.call_recording_store import _table, _record_from_item

    # Scan and filter by participant — acceptable for v1 with limited data
    table = _table()
    items = []
    response = table.scan(Limit=200)
    for item in response.get("Items", []):
        participants = item.get("participants") or []
        if user_id in participants and str(item.get("status", "")) != "deleted":
            items.append(item)

    recordings = [_record_from_item(item) for item in items]
    recordings.sort(key=lambda r: r.created_at, reverse=True)

    out_items = []
    for recording in recordings[:50]:
        download_url = None
        download_expires_at = None
        if recording.status == "ready":
            download_url, download_expires_at = _make_download_url(recording)
        out_items.append(RecordingMetadataOut(
            recording_id=recording.recording_id,
            call_id=recording.call_id,
            conversation_id=recording.conversation_id,
            initiated_by=recording.initiated_by,
            participants=recording.participants,
            status=recording.status,
            mime_type=recording.mime_type,
            duration_seconds=recording.duration_seconds,
            file_size_bytes=recording.file_size_bytes,
            created_at=recording.created_at,
            started_at=recording.started_at,
            completed_at=recording.completed_at,
            download_url=download_url,
            download_expires_at=download_expires_at,
        ))

    return RecordingListOut(items=out_items)


@router.get("/messages/recordings/{recording_id}/download", response_model=RecordingDownloadOut)
async def download_recording(
    recording_id: str,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Get download URL for a specific recording."""
    from app.services.call_recording_store import get_recording

    recording = get_recording(recording_id)
    if not recording:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "Recording not found"},
        )

    if recording.status != "ready":
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_ready", "message": "Recording is not ready for download"},
        )

    _require_recording_participant(recording, user_id)

    download_url, download_expires_at = _make_download_url(recording)
    ext = "webm" if "webm" in recording.mime_type else "mp4"
    filename = f"recording_{recording.call_id[:8]}.{ext}"

    return RecordingDownloadOut(
        download_url=download_url,
        download_expires_at=download_expires_at,
        file_size_bytes=recording.file_size_bytes,
        filename=filename,
    )


@router.delete("/messages/recordings/{recording_id}")
async def delete_recording_endpoint(
    recording_id: str,
    request: Request,
    user_id: str = Depends(_get_user_id),
):
    """Soft-delete a recording."""
    from app.services.call_recording_store import get_recording, soft_delete_recording

    recording = get_recording(recording_id)
    if not recording:
        raise HTTPException(
            status_code=404,
            detail={"code": "recording_not_found", "message": "Recording not found"},
        )

    _require_recording_participant(recording, user_id)

    soft_delete_recording(recording_id)
    return {"ok": True, "recording_id": recording_id, "status": "deleted"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_download_url(recording) -> tuple[str, int]:
    """Generate a download URL for a ready recording."""
    expires_at = int(now_ts()) + S.call_recording_download_ttl_seconds

    if S.dev_mode:
        bucket = recording.s3_bucket or S.filemgr_bucket or "local-uploads"
        s3_key = recording.s3_key
        if not s3_key:
            ext = "webm" if "webm" in recording.mime_type else "mp4"
            s3_key = f"{S.call_recording_s3_prefix}{recording.recording_id}/recording.{ext}"
        download_url = f"/mock/s3/{bucket}/{s3_key}"
    else:
        from app.core.aws import s3_client
        bucket = recording.s3_bucket or S.filemgr_bucket or "local-uploads"
        s3_key = recording.s3_key
        download_url = s3_client().generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": s3_key},
            ExpiresIn=S.call_recording_download_ttl_seconds,
        )

    return download_url, expires_at
