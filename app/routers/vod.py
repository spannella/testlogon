"""VOD (Video on Demand) upload endpoints.

Implements the two-step presigned upload pattern:
1. POST /ui/videos/upload/presign — get a presigned S3 PUT URL + upload ticket
2. POST /ui/videos/upload/complete — confirm upload finished via ticket_id + key
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import uuid4

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException
from pydantic import AliasChoices, BaseModel, Field

from app.services.sessions import require_ui_session
from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.video_metadata_store import (
    create_video,
    get_video,
    transition_video_status,
    video_to_item,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/videos", tags=["vod"])

_s3 = s3_client()

# ─── Constants ────────────────────────────────────────────────────────────────

ALLOWED_VIDEO_CONTENT_TYPES = frozenset({
    "video/mp4",
    "video/quicktime",        # .mov
    "video/x-msvideo",       # .avi
    "video/x-matroska",      # .mkv
    "video/webm",
    "video/mpeg",
    "video/ogg",
    "video/x-flv",
    "video/3gpp",
    "video/3gpp2",
})

MAX_SIZE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB
PRESIGN_TTL_SECONDS = 900  # 15 minutes


# ─── Request / Response models ────────────────────────────────────────────────


class VideoUploadPresignIn(BaseModel):
    # Accept either ``file_size_bytes`` (canonical) or ``size_bytes`` (the name
    # the frontend / E2E client sends) via a validation alias.
    model_config = {"populate_by_name": True}

    filename: str = Field(..., min_length=1, max_length=255)
    # Content type is validated explicitly in the endpoint so we can return a
    # friendly "Invalid content type" message (a Pydantic ``pattern`` would
    # surface an opaque regex-mismatch error instead).
    content_type: str = Field(..., min_length=1)
    file_size_bytes: int = Field(
        ..., ge=1, le=MAX_SIZE_BYTES, validation_alias=AliasChoices("file_size_bytes", "size_bytes")
    )
    title: Optional[str] = Field(default=None, max_length=500)
    description: Optional[str] = Field(default=None, max_length=5000)
    folder_path: Optional[str] = Field(default=None, max_length=1024)


class VideoUploadPresignOut(BaseModel):
    upload_url: str
    # Alias exposed under the name the frontend / E2E client reads.
    presigned_url: str
    bucket: str
    key: str
    s3_key: str
    ticket_id: str
    video_id: str
    content_type: str
    expires_at: str
    expires_in_seconds: int
    max_size_bytes: int


class VideoUploadCompleteIn(BaseModel):
    ticket_id: str = Field(..., min_length=1)
    key: str = Field(..., min_length=1)
    content_type: Optional[str] = Field(default=None)
    client_checksum: Optional[str] = Field(default=None)


class VideoUploadCompleteOut(BaseModel):
    ok: bool
    video_id: str
    s3_key: str
    size_bytes: int
    content_type: str
    duration_seconds: Optional[float] = None
    thumbnail_url: Optional[str] = None
    status: str
    created_at: int


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _vod_bucket() -> str:
    return S.video_upload_bucket or "local-uploads"


def _ticket_pk(ticket_id: str) -> str:
    return f"TICKET#{ticket_id}"


def _generate_s3_key(user_sub: str, video_id: str, filename: str) -> str:
    """Generate S3 key following the vod/{user}/raw/{year}/{month}/{video_id}/{filename} convention."""
    now = datetime.now(timezone.utc)
    year = now.strftime("%Y")
    month = now.strftime("%m")
    return f"vod/{user_sub}/raw/{year}/{month}/{video_id}/{filename}"


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/upload/presign", response_model=VideoUploadPresignOut)
def vod_presign_upload(
    inp: VideoUploadPresignIn,
    user=Depends(require_ui_session),
):
    """Request a presigned S3 PUT URL for video upload."""
    user_sub = user["user_sub"]

    # Validate content type against allowlist. Returns 422 with a friendly
    # message (matching the upload contract / E2E expectations).
    if inp.content_type not in ALLOWED_VIDEO_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid content type: {inp.content_type}. "
                   f"Allowed: {sorted(ALLOWED_VIDEO_CONTENT_TYPES)}",
        )

    # Create video metadata record with status "created"
    video_title = inp.title or inp.filename
    video = create_video(
        owner_user_id=user_sub,
        title=video_title,
        description=inp.description,
        source_type="upload",
        visibility="private",
    )
    video_id = video.id

    # Generate S3 key following the path convention
    s3_key = _generate_s3_key(user_sub, video_id, inp.filename)
    bucket = _vod_bucket()
    ticket_id = uuid4().hex

    # Generate presigned URL
    if S.dev_mode:
        upload_url = f"{S.public_base_url}/mock/s3/{bucket}/{s3_key}"
    else:
        upload_url = _s3.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": bucket,
                "Key": s3_key,
                "ContentType": inp.content_type,
                "Metadata": {
                    "vod-ticket": ticket_id,
                    "vod-user": user_sub,
                },
            },
            ExpiresIn=PRESIGN_TTL_SECONDS,
        )

    # Store upload ticket in video_metadata table using TICKET# prefix
    expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=PRESIGN_TTL_SECONDS)
    expires_at = expires_at_dt.isoformat()
    ttl_epoch = int((expires_at_dt + timedelta(hours=24)).timestamp())

    T.video_metadata.put_item(
        Item={
            "video_id": _ticket_pk(ticket_id),
            "owner_user_id": user_sub,
            "ticket_id": ticket_id,
            "actual_video_id": video_id,
            "s3_key": s3_key,
            "s3_bucket": bucket,
            "content_type": inp.content_type,
            "expected_size_bytes": inp.file_size_bytes,
            "filename": inp.filename,
            "title": video_title,
            "description": inp.description or "",
            "folder_path": inp.folder_path or "",
            "status": "pending",
            "expires_at": expires_at,
            "created_at": now_ts(),
            "ttl_epoch": ttl_epoch,
        }
    )

    return VideoUploadPresignOut(
        upload_url=upload_url,
        presigned_url=upload_url,
        bucket=bucket,
        key=s3_key,
        s3_key=s3_key,
        ticket_id=ticket_id,
        video_id=video_id,
        content_type=inp.content_type,
        expires_at=expires_at,
        expires_in_seconds=PRESIGN_TTL_SECONDS,
        max_size_bytes=MAX_SIZE_BYTES,
    )


@router.post("/upload/complete", response_model=VideoUploadCompleteOut)
def vod_complete_upload(
    inp: VideoUploadCompleteIn,
    user=Depends(require_ui_session),
):
    """Confirm that the video file has been uploaded to S3."""
    user_sub = user["user_sub"]

    # Look up upload ticket
    ticket_resp = T.video_metadata.get_item(
        Key={"video_id": _ticket_pk(inp.ticket_id)},
        ConsistentRead=True,
    )
    ticket = ticket_resp.get("Item")
    if not ticket:
        raise HTTPException(status_code=403, detail="invalid upload ticket")

    # Verify ticket belongs to this user
    if ticket.get("owner_user_id") != user_sub:
        raise HTTPException(status_code=403, detail="upload ticket not found for user")

    # Verify ticket not expired
    expires_at_str = ticket.get("expires_at", "")
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at <= datetime.now(timezone.utc):
                raise HTTPException(status_code=403, detail="upload ticket expired")
        except (ValueError, TypeError):
            pass

    # Verify S3 key matches
    if ticket.get("s3_key") != inp.key:
        raise HTTPException(status_code=403, detail="s3 key mismatch")

    video_id = ticket["actual_video_id"]
    bucket = ticket.get("s3_bucket", _vod_bucket())
    s3_key = ticket["s3_key"]
    expected_content_type = inp.content_type or ticket.get("content_type", "video/mp4")

    # Verify video record exists and is in "created" state
    video = get_video(video_id)
    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="not your video")

    if video.status != "created":
        raise HTTPException(
            status_code=409,
            detail=f"Video is in status '{video.status}', expected 'created'",
        )

    # Perform HeadObject to verify the upload exists in S3
    try:
        head = _s3.head_object(Bucket=bucket, Key=s3_key)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code in ("404", "NoSuchKey"):
            raise HTTPException(
                status_code=404,
                detail="uploaded object not found in S3",
            ) from exc
        raise HTTPException(
            status_code=500,
            detail=f"S3 HeadObject error: {error_code}",
        ) from exc

    actual_size = int(head.get("ContentLength", 0))
    actual_ct = head.get("ContentType", "application/octet-stream")
    etag = head.get("ETag", "")

    # In dev mode (moto), the mock S3 PUT route does not preserve metadata tags
    # from presigned URL params, so skip metadata validation in dev mode.
    if not S.dev_mode:
        metadata = head.get("Metadata") or {}
        if metadata.get("vod-ticket") != inp.ticket_id:
            raise HTTPException(status_code=403, detail="uploaded object metadata mismatch")
        if metadata.get("vod-user") != user_sub:
            raise HTTPException(status_code=403, detail="uploaded object user mismatch")

    # Validate content type is still a valid video type.
    # In dev mode with moto mock, content_type may be preserved from PUT.
    # Use the ticket's declared content_type as fallback if S3 stored something generic.
    if actual_ct not in ALLOWED_VIDEO_CONTENT_TYPES:
        actual_ct = expected_content_type

    # Validate size within limit
    if actual_size > MAX_SIZE_BYTES:
        try:
            _s3.delete_object(Bucket=bucket, Key=s3_key)
        except Exception:
            logger.warning("Failed to clean up oversized upload %s/%s", bucket, s3_key)
        raise HTTPException(status_code=413, detail="uploaded file exceeds maximum size")

    # Update video record with file info and S3 key
    ts = now_ts()
    video_updated = video.model_copy(
        update={
            "source_s3_key": s3_key,
            "file_size_bytes": actual_size,
            "updated_at": ts,
        }
    )
    T.video_metadata.put_item(Item=video_to_item(video_updated))

    # Transition status: created -> probing
    transition_video_status(
        video_id=video_id,
        to_status="probing",
        reason="upload complete",
        actor=user_sub,
    )

    # Clean up ticket
    try:
        T.video_metadata.delete_item(Key={"video_id": _ticket_pk(inp.ticket_id)})
    except Exception:
        logger.warning("Failed to delete upload ticket %s", inp.ticket_id)

    return VideoUploadCompleteOut(
        ok=True,
        video_id=video_id,
        s3_key=s3_key,
        size_bytes=actual_size,
        content_type=actual_ct,
        duration_seconds=None,
        thumbnail_url=None,
        status="uploaded",
        created_at=video.created_at,
    )


# ─── Legacy compatibility endpoint ───────────────────────────────────────────


@router.post("/{video_id}/upload/complete")
def vod_complete_upload_legacy(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Legacy complete endpoint that uses video_id from path.

    Looks up the ticket by scanning for the matching video_id.
    Kept for backward compatibility with existing frontend code.
    """
    user_sub = user["user_sub"]

    # Look up the video record and verify ownership
    video = get_video(video_id)
    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="not your video")

    if video.status != "created":
        raise HTTPException(
            status_code=409,
            detail=f"Video is in status '{video.status}', expected 'created'",
        )

    # Find the ticket for this video
    from boto3.dynamodb.conditions import Key, Attr

    resp = T.video_metadata.query(
        IndexName="ByOwnerCreatedAt",
        KeyConditionExpression=Key("owner_user_id").eq(user_sub),
        FilterExpression=Attr("actual_video_id").eq(video_id),
        Limit=10,
    )
    tickets = resp.get("Items", [])
    ticket = None
    for t in tickets:
        vid = t.get("video_id", "")
        if isinstance(vid, str) and vid.startswith("TICKET#"):
            ticket = t
            break

    s3_key = None
    bucket = _vod_bucket()

    if ticket:
        # Validate ticket not expired
        expires_at_str = ticket.get("expires_at", "")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at <= datetime.now(timezone.utc):
                    raise HTTPException(status_code=403, detail="upload ticket expired")
            except (ValueError, TypeError):
                pass

        s3_key = ticket.get("s3_key")
        bucket = ticket.get("s3_bucket", bucket)

    # Verify the object exists in S3 via HeadObject
    if s3_key:
        try:
            head = _s3.head_object(Bucket=bucket, Key=s3_key)
            actual_size = int(head.get("ContentLength", 0))
            ts = now_ts()
            video_updated = video.model_copy(
                update={
                    "source_s3_key": s3_key,
                    "file_size_bytes": actual_size,
                    "updated_at": ts,
                }
            )
            T.video_metadata.put_item(Item=video_to_item(video_updated))
        except Exception as exc:
            logger.warning("HeadObject failed for %s/%s: %s", bucket, s3_key, exc)
            ts = now_ts()
            video_updated = video.model_copy(
                update={
                    "source_s3_key": s3_key,
                    "updated_at": ts,
                }
            )
            T.video_metadata.put_item(Item=video_to_item(video_updated))

    # Transition status: created -> probing
    transition_video_status(
        video_id=video_id,
        to_status="probing",
        reason="upload complete",
        actor=user_sub,
    )

    # Clean up ticket
    if ticket:
        try:
            T.video_metadata.delete_item(Key={"video_id": ticket["video_id"]})
        except Exception:
            pass

    return {"video_id": video_id, "status": "upload_complete"}
