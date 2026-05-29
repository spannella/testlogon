from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.models_video import (
    CreateVideoIn,
    SubtitleTrack,
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
        "drm_enabled": video.drm_enabled,
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
        "access_mode",
        # Clipping provenance (VOD-015)
        "source_video_id",
        "created_via",
        # Gallery (VOD-017)
        "category",
        "gallery_status",
    ]
    # List fields — store as-is (DynamoDB supports lists natively)
    if video.source_video_ids:
        item["source_video_ids"] = video.source_video_ids
    if video.tags:
        item["tags"] = video.tags
    for field in _optional_str_fields:
        val = getattr(video, field, None)
        if val is not None:
            item[field] = val

    # Optional numeric fields — convert floats to Decimal for DynamoDB
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
        "price_cents",
        "purchase_count",
        "revenue_cents",
        # Clipping provenance (VOD-015)
        "clip_start_seconds",
        "clip_end_seconds",
        # Scheduled Publishing (CREATOR-005)
        "scheduled_publish_at",
        # Gallery (VOD-017)
        "view_count",
        "like_count",
        "comment_count",
        "trending_score",
        "trending_score_sort",
    ]
    for field in _optional_num_fields:
        val = getattr(video, field, None)
        if val is not None:
            if isinstance(val, float):
                item[field] = Decimal(str(val))
            else:
                item[field] = val

    # Download fields (VOD-012)
    item["allow_download"] = video.allow_download
    if video.download_mp4_key:
        item["download_mp4_key"] = video.download_mp4_key
    if video.download_mp4_size_bytes:
        item["download_mp4_size_bytes"] = video.download_mp4_size_bytes
    if video.download_mp4_status:
        item["download_mp4_status"] = video.download_mp4_status
    if video.download_count:
        item["download_count"] = video.download_count

    # Watermarked Downloads (VOD-020)
    item["watermark_downloads"] = video.watermark_downloads

    # Gallery (VOD-017)
    item["gallery_published"] = video.gallery_published
    # gallery_status is a GSI partition key — omit if None to avoid storing NULL
    # (already handled in _optional_str_fields)

    # Ad-Supported (VOD-018)
    if video.ad_config is not None:
        item["ad_config"] = video.ad_config
    item["ads_free_for_subscribers"] = video.ads_free_for_subscribers
    if video.ad_revenue_cents:
        item["ad_revenue_cents"] = video.ad_revenue_cents
    if video.ad_impression_count:
        item["ad_impression_count"] = video.ad_impression_count

    # Purchase Tiers (VOD-019)
    if video.available_purchase_types:
        item["available_purchase_types"] = video.available_purchase_types
    if video.view_once_price_cents is not None:
        item["view_once_price_cents"] = video.view_once_price_cents
    if video.rental_price_cents is not None:
        item["rental_price_cents"] = video.rental_price_cents
    if video.rental_duration_hours is not None:
        item["rental_duration_hours"] = video.rental_duration_hours
    if video.download_price_cents is not None:
        item["download_price_cents"] = video.download_price_cents

    # source_broadcast_session_id is a GSI partition key -- must omit if None
    # to avoid DynamoDB storing NULL in GSI key attributes
    if video.source_broadcast_session_id is not None:
        item["source_broadcast_session_id"] = video.source_broadcast_session_id

    # Subtitles / Closed Captions (VOD-021)
    if video.subtitle_tracks:
        item["subtitle_tracks"] = [t.model_dump() for t in video.subtitle_tracks]

    # Renditions: store as list of dicts (convert any floats to Decimal)
    if video.renditions:
        rendition_items = []
        for r in video.renditions:
            rd = r.model_dump()
            for k, v in rd.items():
                if isinstance(v, float):
                    rd[k] = Decimal(str(v))
            rendition_items.append(rd)
        item["renditions"] = rendition_items

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
        drm_enabled=bool(item.get("drm_enabled", False)),
        drm_policy_id=item.get("drm_policy_id"),
        drm_key_id=item.get("drm_key_id"),
        entitlement_sku=item.get("entitlement_sku"),
        price_cents=_int_or_none(item.get("price_cents")),
        access_mode=item.get("access_mode"),
        purchase_count=int(item.get("purchase_count") or 0),
        revenue_cents=int(item.get("revenue_cents") or 0),
        visibility=item.get("visibility") or "private",
        published_at=_int_or_none(item.get("published_at")),
        deleted_at=_int_or_none(item.get("deleted_at")),
        # Scheduled Publishing (CREATOR-005)
        scheduled_publish_at=_int_or_none(item.get("scheduled_publish_at")),
        # Download (VOD-012)
        allow_download=bool(item.get("allow_download", False)),
        download_mp4_key=item.get("download_mp4_key") or "",
        download_mp4_size_bytes=int(item.get("download_mp4_size_bytes") or 0),
        download_mp4_status=item.get("download_mp4_status") or "",
        download_count=int(item.get("download_count") or 0),
        # Watermarked Downloads (VOD-020)
        watermark_downloads=bool(item.get("watermark_downloads", False)),
        # Clipping provenance (VOD-015)
        source_video_id=item.get("source_video_id"),
        clip_start_seconds=_float_or_none(item.get("clip_start_seconds")),
        clip_end_seconds=_float_or_none(item.get("clip_end_seconds")),
        created_via=item.get("created_via"),
        # Concatenation provenance (VOD-016)
        source_video_ids=item.get("source_video_ids") or None,
        # Gallery (VOD-017)
        gallery_published=bool(item.get("gallery_published", False)),
        gallery_status=item.get("gallery_status"),
        category=item.get("category"),
        tags=list(item.get("tags") or []),
        view_count=int(item.get("view_count") or 0),
        like_count=int(item.get("like_count") or 0),
        comment_count=int(item.get("comment_count") or 0),
        trending_score=float(item.get("trending_score") or 0),
        trending_score_sort=_int_or_none(item.get("trending_score_sort")),
        # Ad-Supported (VOD-018)
        ad_config=item.get("ad_config"),
        ads_free_for_subscribers=bool(item.get("ads_free_for_subscribers", False)),
        ad_revenue_cents=int(item.get("ad_revenue_cents") or 0),
        ad_impression_count=int(item.get("ad_impression_count") or 0),
        # Purchase Tiers (VOD-019)
        available_purchase_types=item.get("available_purchase_types") or [],
        view_once_price_cents=_int_or_none(item.get("view_once_price_cents")),
        rental_price_cents=_int_or_none(item.get("rental_price_cents")),
        rental_duration_hours=_int_or_none(item.get("rental_duration_hours")),
        download_price_cents=_int_or_none(item.get("download_price_cents")),
        # Subtitles / Closed Captions (VOD-021)
        subtitle_tracks=[SubtitleTrack(**t) for t in (item.get("subtitle_tracks") or [])],
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
    status_filter: Optional[str] = None,
    visibility_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """List videos by owner, newest first. Excludes deleted. Supports filters."""
    if not owner_user_id:
        raise HTTPException(status_code=400, detail="owner_user_id is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    from boto3.dynamodb.conditions import Attr

    collected: List[VideoMetadataModel] = []
    current_cursor = cursor
    max_pages = 10

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByOwnerCreatedAt",
            "KeyConditionExpression": Key("owner_user_id").eq(owner_user_id),
            "Limit": limit * 3,
            "ScanIndexForward": False,
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor

        # Build filter expression: always exclude deleted
        filters = [Attr("status").ne("deleted")]
        if status_filter:
            filters.append(Attr("status").eq(status_filter))
        if visibility_filter:
            filters.append(Attr("visibility").eq(visibility_filter))

        combined_filter = filters[0]
        for f in filters[1:]:
            combined_filter = combined_filter & f
        kwargs["FilterExpression"] = combined_filter

        resp = T.video_metadata.query(**kwargs)
        for item in resp.get("Items", []):
            # Skip ticket items
            vid = item.get("video_id", "")
            if isinstance(vid, str) and vid.startswith("TICKET#"):
                continue
            collected.append(video_from_item(item))
            if len(collected) >= limit:
                break

        current_cursor = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not current_cursor:
            break

    return {"items": collected[:limit], "cursor": current_cursor}


def list_videos_by_status(
    status: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List videos by status (admin use)."""
    if not status:
        raise HTTPException(status_code=400, detail="status is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    from boto3.dynamodb.conditions import Attr

    collected: List[VideoMetadataModel] = []
    current_cursor = cursor
    max_pages = 10

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq(status),
            "Limit": limit * 3,
            "ScanIndexForward": False,
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor

        # Filter out ticket items
        kwargs["FilterExpression"] = Attr("video_id").begins_with("v_")

        resp = T.video_metadata.query(**kwargs)
        for item in resp.get("Items", []):
            collected.append(video_from_item(item))
            if len(collected) >= limit:
                break

        current_cursor = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not current_cursor:
            break

    return {"items": collected[:limit], "cursor": current_cursor}


def list_videos_public(
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List published + public videos (discovery feed)."""
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    from boto3.dynamodb.conditions import Attr

    collected: List[VideoMetadataModel] = []
    current_cursor = cursor
    max_pages = 10

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq("published"),
            "Limit": limit * 3,
            "ScanIndexForward": False,
            "FilterExpression": Attr("visibility").eq("public") & Attr("video_id").begins_with("v_"),
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor

        resp = T.video_metadata.query(**kwargs)
        for item in resp.get("Items", []):
            collected.append(video_from_item(item))
            if len(collected) >= limit:
                break

        current_cursor = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not current_cursor:
            break

    return {"items": collected[:limit], "cursor": current_cursor}


def list_videos_by_creator_public(
    creator_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List a creator's published + public videos."""
    if not creator_id:
        raise HTTPException(status_code=400, detail="creator_id is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    from boto3.dynamodb.conditions import Attr

    collected: List[VideoMetadataModel] = []
    current_cursor = cursor
    max_pages = 10

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByOwnerCreatedAt",
            "KeyConditionExpression": Key("owner_user_id").eq(creator_id),
            "Limit": limit * 3,
            "ScanIndexForward": False,
            "FilterExpression": (
                Attr("status").eq("published")
                & Attr("visibility").eq("public")
                & Attr("video_id").begins_with("v_")
            ),
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor

        resp = T.video_metadata.query(**kwargs)
        for item in resp.get("Items", []):
            collected.append(video_from_item(item))
            if len(collected) >= limit:
                break

        current_cursor = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not current_cursor:
            break

    return {"items": collected[:limit], "cursor": current_cursor}


def delete_video(video_id: str, owner_user_id: str) -> None:
    """Soft-delete a video (owner-only). Sets status=deleted, deleted_at=now."""
    current = get_video(video_id)
    if current.owner_user_id != owner_user_id:
        raise HTTPException(status_code=403, detail="not your video")
    ts = now_ts()
    updated = current.model_copy(
        update={
            "status": "deleted",
            "deleted_at": ts,
            "updated_at": ts,
        }
    )
    T.video_metadata.put_item(Item=video_to_item(updated))


def increment_download_count(video_id: str) -> None:
    """Atomically increment download_count on a video record."""
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET download_count = if_not_exists(download_count, :zero) + :one, updated_at = :now",
        ExpressionAttributeValues={
            ":zero": 0,
            ":one": 1,
            ":now": now_ts(),
        },
    )


def update_clip_fields(
    *,
    video_id: str,
    source_video_id: str,
    clip_start_seconds: float,
    clip_end_seconds: float,
    created_via: str = "clip",
) -> None:
    """Set clipping provenance fields on a video record (VOD-015)."""
    from decimal import Decimal as _D

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression=(
            "SET source_video_id = :svid, clip_start_seconds = :cs, "
            "clip_end_seconds = :ce, created_via = :cv, updated_at = :ua"
        ),
        ExpressionAttributeValues={
            ":svid": source_video_id,
            ":cs": _D(str(clip_start_seconds)),
            ":ce": _D(str(clip_end_seconds)),
            ":cv": created_via,
            ":ua": now_ts(),
        },
    )


def update_concat_fields(
    *,
    video_id: str,
    source_video_ids: List[str],
    created_via: str = "concat",
    duration_seconds: Optional[float] = None,
) -> None:
    """Set concatenation provenance fields on a video record (VOD-016)."""
    from decimal import Decimal as _D

    update_expr = (
        "SET source_video_ids = :svids, created_via = :cv, updated_at = :ua"
    )
    values: Dict[str, Any] = {
        ":svids": source_video_ids,
        ":cv": created_via,
        ":ua": now_ts(),
    }
    if duration_seconds is not None:
        update_expr += ", duration_seconds = :dur"
        values[":dur"] = _D(str(duration_seconds))

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=values,
    )


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
