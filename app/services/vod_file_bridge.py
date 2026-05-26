"""VOD ↔ File Manager bridge service (VOD-014)."""
from __future__ import annotations
import logging
import re
from typing import Any, Dict, Optional
from fastapi import HTTPException
from app.core.settings import S
from app.core.time import now_ts
from app.services.filemanager import (
    ensure_folder_exists, get_node, put_node, node_key,
    pk_user, sk_node, split_parent_name, norm_path, now_iso,
    _table, _put_token_entries,
)
from app.services.video_metadata_store import get_video, create_video, transition_video_status

logger = logging.getLogger(__name__)
DEFAULT_VIDEO_FOLDER = "/Videos/"


def link_video_to_filemanager(video_id: str, *, target_folder: Optional[str] = None) -> Dict[str, Any]:
    video = get_video(video_id)
    owner = video.owner_user_id
    folder = norm_path(target_folder or DEFAULT_VIDEO_FOLDER, is_folder=True)
    _ensure_videos_folder(owner, folder)
    filename = _safe_filename(video.title, video.source_s3_key)
    file_path = norm_path(f"{folder}{filename}", is_folder=False)
    file_path = _resolve_unique_path(owner, file_path)

    # Idempotent: check if already linked
    try:
        existing = get_node(owner, file_path)
        if existing and existing.get("vod_video_id") == video_id:
            _update_linked_node_vod_metadata(owner, file_path, video)
            return {"path": file_path, "video_id": video_id, "linked": False}
    except HTTPException as exc:
        if exc.status_code != 404:
            raise

    s3_bucket = getattr(S, "video_upload_bucket", "local-uploads") or "local-uploads"
    s3_key = video.source_s3_key or ""
    if not s3_key:
        logger.warning("Cannot link video %s: no source_s3_key", video_id)
        return {"path": "", "video_id": video_id, "linked": False}

    parent, name = split_parent_name(file_path)
    content_type = _infer_content_type(s3_key)
    size = video.file_size_bytes or 0

    item = {
        "PK": pk_user(owner),
        "SK": sk_node(file_path),
        "type": "file",
        "path": file_path,
        "name": name,
        "name_lc": name.lower(),
        "parent": parent,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "upload_at": now_iso(),
        "upload_by": owner,
        "size": size,
        "content_type": content_type,
        "duration_seconds": video.duration_seconds,
        "s3_bucket": s3_bucket,
        "s3_key": s3_key,
        "is_encrypted": False,
        "vod_video_id": video_id,
        "vod_linked": True,
        "vod_status": video.status,
        "vod_hls_manifest_url": video.hls_manifest_url,
        "vod_thumbnail_url": video.thumbnail_url,
        "vod_duration_seconds": video.duration_seconds,
        "vod_width": video.width,
        "vod_height": video.height,
        "vod_linked_at": now_iso(),
        "GSI1PK": pk_user(owner),
        "GSI1SK": f"NAME#{name.lower()}#PATH#{file_path}",
        "GSI2PK": f"PARENT#{parent}",
        "GSI2SK": f"TYPE#file#NAME#{name.lower()}#PATH#{file_path}",
    }
    if video.thumbnail_url:
        item["poster_url"] = video.thumbnail_url
        item["media_preview_status"] = "ready"

    put_node(item)
    _put_token_entries(owner, item)
    _update_video_source_file_node(video_id, file_path)
    logger.info("Linked VOD video %s to file manager path %s", video_id, file_path)
    return {"path": file_path, "video_id": video_id, "linked": True}


def import_file_to_vod(owner: str, file_path: str, *, title: Optional[str] = None, visibility: str = "private") -> Dict[str, Any]:
    node = get_node(owner, norm_path(file_path, is_folder=False))
    content_type = str(node.get("content_type") or "").lower()
    if not content_type.startswith("video/"):
        raise HTTPException(400, "file is not a video")
    existing_video_id = node.get("vod_video_id")
    if existing_video_id:
        raise HTTPException(409, {"code": "already_linked", "video_id": existing_video_id, "message": "file is already linked to a VOD record"})
    s3_key = node.get("s3_key")
    s3_bucket = node.get("s3_bucket")
    if not s3_key or not s3_bucket:
        raise HTTPException(400, "file has no S3 backing object")

    video_title = title or node.get("name") or "Imported Video"
    video = create_video(
        owner_user_id=owner,
        title=video_title,
        source_type="upload",
        source_file_node_id=file_path,
        source_s3_key=s3_key,
        visibility=visibility,
    )

    from app.core.tables import T
    if node.get("size"):
        T.video_metadata.update_item(
            Key={"video_id": video.id},
            UpdateExpression="SET file_size_bytes = :s",
            ExpressionAttributeValues={":s": int(node["size"])},
        )

    transition_video_status(video_id=video.id, to_status="probing", reason="imported from file manager", actor=owner)

    _table().update_item(
        Key=node_key(owner, norm_path(file_path, is_folder=False)),
        UpdateExpression="SET vod_video_id = :vid, vod_linked = :t, vod_status = :s, vod_linked_at = :ts, updated_at = :ts",
        ExpressionAttributeValues={":vid": video.id, ":t": True, ":s": "probing", ":ts": now_iso()},
    )

    _enqueue_transcode_for_import(video.id, owner, s3_bucket, s3_key)
    logger.info("Imported file %s to VOD pipeline as video %s", file_path, video.id)
    return {"video_id": video.id, "status": "probing", "file_path": file_path}


def unlink_video_from_filemanager(video_id: str, owner: str) -> Dict[str, Any]:
    video = get_video(video_id)
    if video.owner_user_id != owner:
        raise HTTPException(403, "not your video")
    file_path = video.source_file_node_id
    if not file_path:
        return {"video_id": video_id, "unlinked": False}
    try:
        node = get_node(owner, file_path)
    except HTTPException:
        return {"video_id": video_id, "unlinked": False}
    if node.get("vod_video_id") != video_id:
        return {"video_id": video_id, "unlinked": False}
    _table().update_item(
        Key=node_key(owner, norm_path(file_path, is_folder=False)),
        UpdateExpression="REMOVE vod_video_id, vod_linked, vod_status, vod_hls_manifest_url, vod_thumbnail_url, vod_duration_seconds, vod_width, vod_height, vod_linked_at",
    )
    return {"video_id": video_id, "unlinked": True}


def _ensure_videos_folder(owner: str, folder: str) -> None:
    try:
        existing = get_node(owner, folder)
        if existing:
            return
    except HTTPException:
        pass
    item = {
        "PK": pk_user(owner),
        "SK": sk_node(folder),
        "type": "folder",
        "path": folder,
        "name": folder.rstrip("/").rsplit("/", 1)[-1] or "Videos",
        "name_lc": (folder.rstrip("/").rsplit("/", 1)[-1] or "videos").lower(),
        "parent": "/" if folder.count("/") <= 2 else folder.rstrip("/").rsplit("/", 1)[0] + "/",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "GSI1PK": pk_user(owner),
        "GSI1SK": f"NAME#{(folder.rstrip('/').rsplit('/', 1)[-1] or 'videos').lower()}#PATH#{folder}",
        "GSI2PK": f"PARENT#{('/' if folder.count('/') <= 2 else folder.rstrip('/').rsplit('/', 1)[0] + '/')}",
        "GSI2SK": f"TYPE#folder#NAME#{(folder.rstrip('/').rsplit('/', 1)[-1] or 'videos').lower()}#PATH#{folder}",
    }
    put_node(item)


def _safe_filename(title: str, s3_key: Optional[str]) -> str:
    ext = ".mp4"
    if s3_key and "." in s3_key.split("/")[-1]:
        ext = "." + s3_key.split("/")[-1].rsplit(".", 1)[-1]
    safe = re.sub(r"[^\w\s\-.]", "", title.strip())[:200]
    if not safe:
        safe = "video"
    return f"{safe}{ext}"


def _infer_content_type(s3_key: Optional[str]) -> str:
    if not s3_key:
        return "video/mp4"
    lower = s3_key.lower()
    if lower.endswith(".webm"):
        return "video/webm"
    if lower.endswith(".mov"):
        return "video/quicktime"
    if lower.endswith(".mkv"):
        return "video/x-matroska"
    return "video/mp4"


def _resolve_unique_path(owner: str, base_path: str) -> str:
    try:
        existing = get_node(owner, base_path)
        if existing and existing.get("vod_video_id"):
            return base_path  # Already linked, will be handled by idempotent check
    except HTTPException:
        return base_path
    parts = base_path.rsplit(".", 1)
    stem = parts[0]
    ext = f".{parts[1]}" if len(parts) > 1 else ""
    for i in range(1, 100):
        candidate = f"{stem} ({i}){ext}"
        try:
            get_node(owner, candidate)
        except HTTPException:
            return candidate
    raise HTTPException(409, "too many filename collisions")


def _update_video_source_file_node(video_id: str, file_path: str) -> None:
    from app.core.tables import T
    try:
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET source_file_node_id = :p, updated_at = :t",
            ExpressionAttributeValues={":p": file_path, ":t": now_ts()},
        )
    except Exception:
        logger.warning("Failed to set source_file_node_id on video %s", video_id)


def _update_linked_node_vod_metadata(owner: str, file_path: str, video) -> None:
    updates = {":s": video.status, ":t": now_iso()}
    expr_parts = ["vod_status = :s", "updated_at = :t"]
    if video.hls_manifest_url:
        updates[":hls"] = video.hls_manifest_url
        expr_parts.append("vod_hls_manifest_url = :hls")
    if video.thumbnail_url:
        updates[":thumb"] = video.thumbnail_url
        expr_parts.extend(["vod_thumbnail_url = :thumb", "poster_url = :thumb"])
        updates[":pstatus"] = "ready"
        expr_parts.append("media_preview_status = :pstatus")
    if video.duration_seconds is not None:
        updates[":dur"] = video.duration_seconds
        expr_parts.extend(["vod_duration_seconds = :dur", "duration_seconds = :dur"])
    if video.width:
        updates[":w"] = video.width
        expr_parts.append("vod_width = :w")
    if video.height:
        updates[":h"] = video.height
        expr_parts.append("vod_height = :h")
    _table().update_item(
        Key=node_key(owner, norm_path(file_path, is_folder=False)),
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=updates,
    )


def _enqueue_transcode_for_import(video_id: str, owner: str, bucket: str, s3_key: str) -> None:
    try:
        from app.services.transcode_job_store import create_job
        create_job(video_id=video_id, tenant_id=owner, source_uri=f"s3://{bucket}/{s3_key}", rendition_profiles=[])
    except Exception:
        logger.warning("Failed to enqueue transcode job for imported video %s", video_id, exc_info=True)
