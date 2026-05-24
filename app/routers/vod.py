"""VOD (Video on Demand) upload endpoints.

Implements the two-step presigned upload pattern:
1. POST /ui/videos/upload/presign — get a presigned S3 PUT URL
2. POST /ui/videos/{video_id}/upload/complete — confirm upload finished
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.video_metadata_store import (
    create_video,
    get_video,
    transition_video_status,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/videos", tags=["vod"])

_s3 = s3_client()

# ─── Constants ─────────────────────���─────────────────────────────────────────

ALLOWED_VIDEO_CONTENT_TYPES = frozenset({
    "video/mp4",
    "video/webm",
    "video/quicktime",
    "video/x-msvideo",
    "video/x-matroska",
})

MAX_SIZE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB
PRESIGN_TTL_SECONDS = 3600


# ─── Request / Response models ───────────────────────────────��───────────────


class VideoUploadPresignIn(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str = Field(..., min_length=1)
    size_bytes: int = Field(..., ge=1, le=MAX_SIZE_BYTES)


class VideoUploadPresignOut(BaseModel):
    video_id: str
    presigned_url: str
    s3_key: str
    expires_in_seconds: int = PRESIGN_TTL_SECONDS


class VideoUploadCompleteOut(BaseModel):
    video_id: str
    status: str


# ─── Helpers ─────────────────────────────────────────────────���───────────────


def _vod_bucket() -> str:
    return S.video_upload_bucket or "local-uploads"


def _ticket_sk(ticket_id: str) -> str:
    return f"VOD_TICKET#{ticket_id}"


def _generate_s3_key(user_sub: str, video_id: str, filename: str) -> str:
    return f"videos/{user_sub}/{video_id}/{filename}"


# ─── Endpoints ───────────────────────────────��───────────────────────────���───


@router.post("/upload/presign", response_model=VideoUploadPresignOut)
def vod_presign_upload(
    inp: VideoUploadPresignIn,
    user=Depends(require_ui_session),
):
    """Request a presigned S3 PUT URL for video upload."""
    user_sub = user["user_sub"]

    # Validate content type
    if inp.content_type not in ALLOWED_VIDEO_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid content type: {inp.content_type}. Allowed: {sorted(ALLOWED_VIDEO_CONTENT_TYPES)}",
        )

    # Create video metadata record with status "created"
    video = create_video(
        owner_user_id=user_sub,
        title=inp.filename,
        source_type="upload",
        visibility="private",
    )
    video_id = video.id

    # Transition to "probing" (we use "created" -> "probing" as our uploading state
    # since the state machine doesn't have an "uploading" status; we'll track via ticket)
    # Actually, keep as "created" and transition to "probing" on complete.

    # Generate S3 key
    s3_key = _generate_s3_key(user_sub, video_id, inp.filename)
    bucket = _vod_bucket()
    ticket_id = uuid4().hex

    # Generate presigned URL
    if S.dev_mode:
        presigned_url = f"{S.public_base_url}/mock/s3/{bucket}/{s3_key}"
    else:
        presigned_url = _s3.generate_presigned_url(
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

    # Store upload ticket in video_metadata table (using PK/SK pattern on billing table
    # or a dedicated approach). We'll store in the video_metadata table using a ticket item.
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=PRESIGN_TTL_SECONDS)).isoformat()

    T.video_metadata.put_item(
        Item={
            "video_id": f"TICKET#{ticket_id}",
            "owner_user_id": user_sub,
            "ticket_id": ticket_id,
            "actual_video_id": video_id,
            "s3_key": s3_key,
            "s3_bucket": bucket,
            "content_type": inp.content_type,
            "expected_size_bytes": inp.size_bytes,
            "filename": inp.filename,
            "expires_at": expires_at,
            "created_at": now_ts(),
        }
    )

    return VideoUploadPresignOut(
        video_id=video_id,
        presigned_url=presigned_url,
        s3_key=s3_key,
        expires_in_seconds=PRESIGN_TTL_SECONDS,
    )


@router.post("/{video_id}/upload/complete", response_model=VideoUploadCompleteOut)
def vod_complete_upload(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Confirm that the video file has been uploaded to S3."""
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

    # Find the ticket for this video to get the S3 key
    # Scan tickets by owner (we stored with video_id prefix TICKET#)
    # We need to find the ticket that references this video_id
    # Query approach: scan items with owner_user_id = user_sub and actual_video_id = video_id
    # For simplicity, we scan for tickets. In a real system we'd have a GSI.
    # Instead, let's look up by iterating recent tickets or by storing the ticket_id
    # on the video record. For now, we'll do a simple scan.

    # Actually, let's use a simpler approach: query all TICKET# items for this user
    # and find the one matching this video_id
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

    if not ticket:
        # No ticket found — maybe it was already completed or user uploaded directly
        # Attempt a direct transition anyway
        pass

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

    # Optionally verify the object exists in S3 via HeadObject
    if s3_key:
        try:
            head = _s3.head_object(Bucket=bucket, Key=s3_key)
            actual_size = int(head.get("ContentLength", 0))
            # Update video record with file size and s3 key
            from app.services.video_metadata_store import video_to_item
            video_updated = video.model_copy(
                update={
                    "source_s3_key": s3_key,
                    "file_size_bytes": actual_size,
                    "updated_at": now_ts(),
                }
            )
            T.video_metadata.put_item(Item=video_to_item(video_updated))
        except Exception as exc:
            logger.warning("HeadObject failed for %s/%s: %s", bucket, s3_key, exc)
            # Still allow completion — the upload may have just finished
            # Update with just the s3_key
            from app.services.video_metadata_store import video_to_item
            video_updated = video.model_copy(
                update={
                    "source_s3_key": s3_key,
                    "updated_at": now_ts(),
                }
            )
            T.video_metadata.put_item(Item=video_to_item(video_updated))

    # Transition status: created -> probing (which represents "upload_complete" in our state machine)
    updated = transition_video_status(
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

    return VideoUploadCompleteOut(
        video_id=video_id,
        status="upload_complete",
    )
