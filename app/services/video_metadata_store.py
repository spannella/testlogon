from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.models_video import (
    CreateVideoIn,
    UpdateVideoIn,
    VideoMetadataModel,
    VideoRendition,
)
from app.services.video_state_machine import validate_transition


def video_to_item(video: VideoMetadataModel) -> Dict[str, Any]:
    """Serialize a VideoMetadataModel to a DynamoDB item dict."""
    item: Dict[str, Any] = {
        "video_id": video.id,
        "owner_user_id": video.owner_user_id,
        "title": video.title,
        "status": video.status,
        "created_at": video.created_at,
        "updated_at": video.updated_at,
        "source_type": video.source_type,
        "visibility": video.visibility,
    }

    # Optional string fields - only include if set
    _optional_str_fields = [
        "description",
        "source_file_node_id",
        "source_s3_key",
        "video_codec",
        "audio_codec",
        "container_format",
        "encoding_profile_id",
        "encoding_job_id",
        "encoding_error_message",
        "thumbnail_s3_key",
        "thumbnail_url",
        "hls_manifest_s3_key",
        "hls_manifest_url",
        "dash_manifest_s3_key",
        "review_status",
        "reviewed_by",
        "review_notes",
        "drm_policy_id",
        "drm_key_id",
        "entitlement_sku",
    ]
    for field in _optional_str_fields:
        val = getattr(video, field, None)
        if val is not None:
            item[field] = val

    # Optional numeric fields
    _optional_num_fields = [
        "duration_seconds",
        "width",
        "height",
        "frame_rate",
        "audio_channels",
        "bitrate_kbps",
        "file_size_bytes",
        "encoding_started_at",
        "encoding_completed_at",
        "reviewed_at",
        "published_at",
        "deleted_at",
    ]
    for field in _optional_num_fields:
        val = getattr(video, field, None)
        if val is not None:
            item[field] = val

    # source_broadcast_session_id is a GSI partition key -- must omit if None
    # to avoid DynamoDB storing NULL in GSI key attributes
    if video.source_broadcast_session_id is not None:
        item["source_broadcast_session_id"] = video.source_broadcast_session_id

    # Renditions: store as list of dicts
    if video.renditions:
        item["renditions"] = [r.model_dump() for r in video.renditions]

    return item


def video_from_item(item: Dict[str, Any]) -> VideoMetadataModel:
    """Deserialize a DynamoDB item to a VideoMetadataModel with safe coercion."""

    def _int_or_none(val: Any) -> Optional[int]:
        if val is None:
            return None
        return int(val)

    def _float_or_none(val: Any) -> Optional[float]:
        if val is None:
            return None
        return float(val)

    renditions_raw = item.get("renditions") or []
    renditions = [VideoRendition(**r) for r in renditions_raw]

    return VideoMetadataModel(
        id=item["video_id"],
        owner_user_id=item["owner_user_id"],
        title=item["title"],
        description=item.get("description"),
        status=item.get("status") or "created",
        created_at=int(item.get("created_at") or 0),
        updated_at=int(item.get("updated_at") or 0),
        source_type=item.get("source_type") or "upload",
        source_file_node_id=item.get("source_file_node_id"),
        source_broadcast_session_id=item.get("source_broadcast_session_id"),
        source_s3_key=item.get("source_s3_key"),
        duration_seconds=_float_or_none(item.get("duration_seconds")),
        width=_int_or_none(item.get("width")),
        height=_int_or_none(item.get("height")),
        frame_rate=_float_or_none(item.get("frame_rate")),
        video_codec=item.get("video_codec"),
        audio_codec=item.get("audio_codec"),
        audio_channels=_int_or_none(item.get("audio_channels")),
        bitrate_kbps=_int_or_none(item.get("bitrate_kbps")),
        container_format=item.get("container_format"),
        file_size_bytes=_int_or_none(item.get("file_size_bytes")),
        encoding_profile_id=item.get("encoding_profile_id"),
        encoding_job_id=item.get("encoding_job_id"),
        encoding_started_at=_int_or_none(item.get("encoding_started_at")),
        encoding_completed_at=_int_or_none(item.get("encoding_completed_at")),
        encoding_error_message=item.get("encoding_error_message"),
        thumbnail_s3_key=item.get("thumbnail_s3_key"),
        thumbnail_url=item.get("thumbnail_url"),
        hls_manifest_s3_key=item.get("hls_manifest_s3_key"),
        hls_manifest_url=item.get("hls_manifest_url"),
        dash_manifest_s3_key=item.get("dash_manifest_s3_key"),
        renditions=renditions,
        review_status=item.get("review_status"),
        reviewed_by=item.get("reviewed_by"),
        reviewed_at=_int_or_none(item.get("reviewed_at")),
        review_notes=item.get("review_notes"),
        drm_policy_id=item.get("drm_policy_id"),
        drm_key_id=item.get("drm_key_id"),
        entitlement_sku=item.get("entitlement_sku"),
        visibility=item.get("visibility") or "private",
        published_at=_int_or_none(item.get("published_at")),
        deleted_at=_int_or_none(item.get("deleted_at")),
    )


def create_video(
    *,
    owner_user_id: str,
    title: str,
    description: Optional[str] = None,
    source_type: str = "upload",
    source_file_node_id: Optional[str] = None,
    source_broadcast_session_id: Optional[str] = None,
    source_s3_key: Optional[str] = None,
    encoding_profile_id: Optional[str] = None,
    visibility: str = "private",
    drm_policy_id: Optional[str] = None,
    entitlement_sku: Optional[str] = None,
) -> VideoMetadataModel:
    """Create a new video metadata record."""
    ts = now_ts()
    video = VideoMetadataModel(
        id=f"v_{uuid4().hex}",
        owner_user_id=owner_user_id,
        title=title,
        description=description,
        status="created",
        created_at=ts,
        updated_at=ts,
        source_type=source_type,  # type: ignore[arg-type]
        source_file_node_id=source_file_node_id,
        source_broadcast_session_id=source_broadcast_session_id,
        source_s3_key=source_s3_key,
        encoding_profile_id=encoding_profile_id,
        visibility=visibility,  # type: ignore[arg-type]
        drm_policy_id=drm_policy_id,
        entitlement_sku=entitlement_sku,
    )
    T.video_metadata.put_item(
        Item=video_to_item(video),
        ConditionExpression="attribute_not_exists(video_id)",
    )
    return video


def get_video(video_id: str) -> VideoMetadataModel:
    """Get a video by ID. Raises 404 if not found."""
    resp = T.video_metadata.get_item(Key={"video_id": video_id}, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="video not found")
    return video_from_item(item)


def update_video(video_id: str, updates: UpdateVideoIn) -> VideoMetadataModel:
    """Update mutable fields on a video. Raises 404 if not found."""
    current = get_video(video_id)

    # Apply non-None fields from the update
    data = current.model_dump()
    for field, value in updates.model_dump(exclude_unset=True).items():
        if value is not None:
            data[field] = value

    data["updated_at"] = now_ts()

    updated = VideoMetadataModel(**data)
    T.video_metadata.put_item(Item=video_to_item(updated))
    return updated


def soft_delete_video(video_id: str) -> VideoMetadataModel:
    """Soft-delete a video by setting status=deleted and deleted_at."""
    current = get_video(video_id)
    ts = now_ts()

    updated = current.model_copy(
        update={
            "status": "deleted",
            "deleted_at": ts,
            "updated_at": ts,
        }
    )
    T.video_metadata.put_item(Item=video_to_item(updated))
    return updated


def transition_video_status(
    *,
    video_id: str,
    to_status: str,
    reason: str = "",
    actor: str = "",
) -> VideoMetadataModel:
    """Validate and apply a status transition. Raises 409 if illegal."""
    current = get_video(video_id)
    validation = validate_transition(current.status, to_status)  # type: ignore[arg-type]
    if not validation.legal:
        raise HTTPException(
            status_code=409,
            detail={
                "code": validation.error_code,
                "from_status": current.status,
                "to_status": to_status,
            },
        )

    ts = now_ts()
    update_data: Dict[str, Any] = {
        "status": to_status,
        "updated_at": ts,
    }
    # Set deleted_at when transitioning to deleted
    if to_status == "deleted":
        update_data["deleted_at"] = ts
    # Set published_at when transitioning to published
    if to_status == "published" and current.published_at is None:
        update_data["published_at"] = ts

    updated = current.model_copy(update=update_data)
    T.video_metadata.put_item(Item=video_to_item(updated))
    return updated


def list_videos_by_owner(
    owner_user_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List videos by owner, newest first."""
    if not owner_user_id:
        raise HTTPException(status_code=400, detail="owner_user_id is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    kwargs: Dict[str, Any] = {
        "IndexName": "ByOwnerCreatedAt",
        "KeyConditionExpression": Key("owner_user_id").eq(owner_user_id),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor

    resp = T.video_metadata.query(**kwargs)
    items = [video_from_item(i) for i in resp.get("Items", [])]
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}


def list_videos_by_status(
    status: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List videos by status."""
    if not status:
        raise HTTPException(status_code=400, detail="status is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq(status),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor

    resp = T.video_metadata.query(**kwargs)
    items = [video_from_item(i) for i in resp.get("Items", [])]
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}


def get_video_by_broadcast_session(session_id: str) -> Optional[VideoMetadataModel]:
    """Look up the video record derived from a specific broadcast session."""
    resp = T.video_metadata.query(
        IndexName="BySourceBroadcast",
        KeyConditionExpression=Key("source_broadcast_session_id").eq(session_id),
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return video_from_item(items[0])
