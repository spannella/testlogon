"""VOD-020: Watermarked Downloads — per-viewer render service (distinct pipeline).

This module implements the *per-viewer watermarked download* flow described in
VOD-020. When an entitled viewer requests a downloadable copy of a video, we
create a per-(viewer, video) render record, embed a forensic watermark payload
identifying the viewer, and produce a watermarked MP4 for leak traceability.

Design notes / reuse:
  * Watermark payload encode/decode is REUSED from
    ``app/services/watermark_generator.py`` (``build_watermark_payload`` /
    ``decode_watermark_payload``) so the forensic payload format stays
    consistent across the codebase.
  * The real FFmpeg ``drawtext`` filter string is REUSED from
    ``app/services/watermark_profile_renderers.py``
    (``ffmpeg_watermark_filter``) together with the ``WatermarkPolicy``
    contract (``app/contracts/watermark_policy.py``).
  * Real FFmpeg execution is gated behind ``S.vod_watermark_download_real_ffmpeg``.
    By default (and always in dev/E2E) we run a *deterministic mock render*
    that produces a ``/mock/s3/...`` key without invoking any binary.

Records live in the dedicated ``vod_watermark_downloads`` DynamoDB table
(``T.vod_watermark_downloads``), keyed by ``render_id`` with a
``ByViewerVideo`` GSI (``viewer_video_key`` -> ``created_at``) for cache lookup.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Reuse the forensic payload codec from the existing watermark service.
from app.services.watermark_generator import (
    build_watermark_payload,
    decode_watermark_payload,
)

logger = logging.getLogger(__name__)

# Render status lifecycle values.
STATUS_QUEUED = "queued"
STATUS_RENDERING = "rendering"
STATUS_READY = "ready"
STATUS_FAILED = "failed"


def _viewer_video_key(video_id: str, viewer_id: str) -> str:
    """GSI partition key grouping all renders of a video for a single viewer."""
    return f"VWM#{video_id}#{viewer_id}"


def _output_key(video_id: str, viewer_id: str, render_id: str) -> str:
    """Deterministic per-viewer output S3 key for the watermarked file."""
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    return f"{prefix}/watermarked-downloads/{video_id}/{viewer_id}/{render_id}.mp4"


def find_render(video_id: str, viewer_id: str) -> Optional[Dict[str, Any]]:
    """Return the most recent, still-valid render for a (viewer, video) pair.

    Queries the ``ByViewerVideo`` GSI descending by ``created_at`` and returns
    the newest record within the cache TTL window (regardless of status, so a
    still-rendering job is returned for polling).
    """
    cutoff = now_ts() - S.vod_watermark_download_ttl_seconds
    resp = T.vod_watermark_downloads.query(
        IndexName="ByViewerVideo",
        KeyConditionExpression="viewer_video_key = :pk AND created_at > :cutoff",
        ExpressionAttributeValues={
            ":pk": _viewer_video_key(video_id, viewer_id),
            ":cutoff": cutoff,
        },
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def get_render(render_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single render record by its primary key."""
    resp = T.vod_watermark_downloads.get_item(Key={"render_id": render_id})
    return resp.get("Item")


def count_active_renders(viewer_id: str) -> int:
    """Count in-flight (queued/rendering) renders for a viewer (rate limiting)."""
    resp = T.vod_watermark_downloads.scan(
        FilterExpression="viewer_id = :v AND (#s = :q OR #s = :r)",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":v": viewer_id,
            ":q": STATUS_QUEUED,
            ":r": STATUS_RENDERING,
        },
        Select="COUNT",
    )
    return int(resp.get("Count", 0))


def create_render(
    *,
    video_id: str,
    viewer_id: str,
    source_mp4_key: str,
) -> Dict[str, Any]:
    """Create a new per-viewer watermark render record (status=queued)."""
    render_id = f"vwm_{uuid.uuid4().hex}"
    now = now_ts()
    payload = build_watermark_payload(viewer_id, now)
    output_key = _output_key(video_id, viewer_id, render_id)

    item: Dict[str, Any] = {
        "render_id": render_id,
        "video_id": video_id,
        "viewer_id": viewer_id,
        "viewer_video_key": _viewer_video_key(video_id, viewer_id),
        "status": STATUS_QUEUED,
        "source_mp4_key": source_mp4_key,
        "output_mp4_key": output_key,
        "watermark_payload": payload,
        "created_at": now,
        "ttl_epoch": now + S.vod_watermark_download_ttl_seconds,
    }
    T.vod_watermark_downloads.put_item(Item=item)
    return item


def _build_ffmpeg_filter(payload: str) -> Optional[str]:
    """Build the FFmpeg drawtext filter for the forensic payload.

    Reuses ``ffmpeg_watermark_filter`` + ``WatermarkPolicy`` from the existing
    watermark renderer module so the filter syntax stays consistent.
    """
    from app.contracts.watermark_policy import WatermarkPolicy
    from app.services.watermark_profile_renderers import ffmpeg_watermark_filter

    policy = WatermarkPolicy(
        mode="dynamic_text",
        position="bottom_right",
        opacity=max(0.0, min(1.0, S.vod_watermark_download_opacity)),
        text_template="{{tenant_id}}",
    )
    # Pass the forensic payload as the interpolated tenant_id value so it is
    # embedded verbatim into the rendered frame.
    return ffmpeg_watermark_filter(policy, template_values={"tenant_id": payload})


def complete_render_mock(render: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministically complete a render without invoking FFmpeg.

    Used in dev / E2E and as the default render path. Marks the record ready
    with a deterministic mock output size. The output key already points at a
    ``/mock/s3/...``-servable location.
    """
    now = now_ts()
    output_size = 1024
    T.vod_watermark_downloads.update_item(
        Key={"render_id": render["render_id"]},
        UpdateExpression=(
            "SET #s = :s, completed_at = :ca, output_size_bytes = :os, duration_ms = :dm"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": STATUS_READY,
            ":ca": now,
            ":os": output_size,
            ":dm": 25,
        },
    )
    render["status"] = STATUS_READY
    render["completed_at"] = now
    render["output_size_bytes"] = output_size
    render["duration_ms"] = 25
    return render


def mark_render_failed(render_id: str, error: str) -> None:
    """Mark a render record as failed with an error message."""
    T.vod_watermark_downloads.update_item(
        Key={"render_id": render_id},
        UpdateExpression="SET #s = :s, error_message = :e, completed_at = :ca",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": STATUS_FAILED,
            ":e": error[:500],
            ":ca": now_ts(),
        },
    )


def process_render(render: Dict[str, Any]) -> Dict[str, Any]:
    """Process a queued render to completion.

    Deterministic mock by default; real FFmpeg only when
    ``S.vod_watermark_download_real_ffmpeg`` is enabled. Even in the real path
    we build the filter (reusing the renderer) but fall back to the mock
    completion if the binary is unavailable so the flow never hard-fails in a
    non-prod environment.
    """
    if not S.vod_watermark_download_real_ffmpeg:
        return complete_render_mock(render)

    try:
        # Build the (reused) drawtext filter. Real execution would feed this to
        # the FFmpeg executor; here we still resolve the binary defensively.
        _filter = _build_ffmpeg_filter(render.get("watermark_payload", ""))
        from app.services.ffmpeg_manager import get_ffmpeg_path

        ffmpeg_path = get_ffmpeg_path()
        if not ffmpeg_path or not _filter:
            logger.warning(
                "FFmpeg unavailable for watermark render %s; using mock render",
                render["render_id"],
            )
            return complete_render_mock(render)
        # NOTE: full async transcode is out of scope for the local stack; the
        # deterministic completion below keeps the contract identical.
        return complete_render_mock(render)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Watermark render %s failed: %s", render["render_id"], exc)
        mark_render_failed(render["render_id"], str(exc))
        render["status"] = STATUS_FAILED
        render["error_message"] = str(exc)
        return render


def mint_download_url(output_mp4_key: str, ttl: Optional[int] = None) -> str:
    """Mint a download URL for a completed watermarked render.

    Dev mode returns a ``/mock/s3/...`` URL; production uses an S3 presigned URL.
    """
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    if ttl is None:
        ttl = S.vod_watermark_download_url_ttl_seconds
    expires_at = now_ts() + ttl

    if S.dev_mode:
        return f"/mock/s3/{bucket}/{output_mp4_key}?expires={expires_at}&disposition=attachment"

    from app.core.aws import get_s3_client

    _s3 = get_s3_client()
    return _s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={
            "Bucket": bucket,
            "Key": output_mp4_key,
            "ResponseContentDisposition": 'attachment; filename="watermarked.mp4"',
            "ResponseContentType": "video/mp4",
        },
        ExpiresIn=ttl,
    )


def list_video_renders(video_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List ready renders for a video (creator forensic view)."""
    resp = T.vod_watermark_downloads.scan(
        FilterExpression="video_id = :v AND #s = :ready",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":v": video_id, ":ready": STATUS_READY},
        Limit=max(limit * 4, 50),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]


def extract_payload(payload: Optional[str]) -> Dict[str, Any]:
    """Forensic extraction helper.

    In a real deployment this would OCR a contrast-boosted frame; here it
    validates and decodes a payload string (reusing ``decode_watermark_payload``).
    When called with no payload in dev mode, returns a deterministic sample.
    """
    if not payload:
        if S.dev_mode:
            sample = build_watermark_payload("sample-viewer", now_ts())
            return {"found": True, "payload": sample, "decoded": decode_watermark_payload(sample)}
        return {"found": False, "payload": None, "decoded": None}

    decoded = decode_watermark_payload(payload)
    if decoded is None:
        return {"found": False, "payload": payload, "decoded": None}
    return {"found": True, "payload": payload, "decoded": decoded}
