"""Subtitle management service for VOD-021.

Handles SRT-to-VTT conversion, VTT validation, content sanitization,
S3 upload/delete, and subtitle track CRUD on video metadata.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import HTTPException

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models_video import SubtitleTrack

logger = logging.getLogger(__name__)

_s3 = s3_client()

# ─── Language validation ─────────────────────────────────────────────────────

_LANG_RE = re.compile(r"^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{1,8})*$")


def validate_language_code(code: str) -> bool:
    """Validate an ISO 639-1 / BCP-47 language code."""
    return bool(_LANG_RE.match(code))


# ─── SRT to VTT conversion ──────────────────────────────────────────────────

_SRT_TIMESTAMP_RE = re.compile(
    r"(\d{2}:\d{2}:\d{2}),(\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}),(\d{3})"
)


def srt_to_vtt(srt_content: str) -> str:
    """Convert SRT subtitle content to WebVTT format."""
    lines = srt_content.strip().replace("\r\n", "\n").replace("\r", "\n").split("\n")
    vtt_lines: list[str] = ["WEBVTT", ""]

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip numeric sequence identifiers
        if line.isdigit():
            i += 1
            continue

        # Convert timestamp line
        match = _SRT_TIMESTAMP_RE.match(line)
        if match:
            start = f"{match.group(1)}.{match.group(2)}"
            end = f"{match.group(3)}.{match.group(4)}"
            vtt_lines.append(f"{start} --> {end}")
            i += 1
            continue

        # Pass through empty lines and cue text
        vtt_lines.append(line)
        i += 1

    return "\n".join(vtt_lines) + "\n"


# ─── VTT validation ─────────────────────────────────────────────────────────

_VTT_TIMESTAMP_RE = re.compile(
    r"(\d{2}:\d{2}:\d{2}\.\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}\.\d{3})"
)


def _parse_vtt_timestamp(ts: str) -> Optional[int]:
    """Parse VTT timestamp 'HH:MM:SS.mmm' to total milliseconds."""
    try:
        parts = ts.split(":")
        h, m = int(parts[0]), int(parts[1])
        sec_parts = parts[2].split(".")
        s, ms = int(sec_parts[0]), int(sec_parts[1])
        return (h * 3600 + m * 60 + s) * 1000 + ms
    except (ValueError, IndexError):
        return None


def validate_vtt(content: str) -> list[str]:
    """Validate VTT content. Returns list of error messages (empty = valid)."""
    errors: list[str] = []
    # Strip BOM
    cleaned = content.lstrip("﻿").strip()
    lines = cleaned.split("\n")

    if not lines or not lines[0].strip().startswith("WEBVTT"):
        errors.append("Missing WEBVTT header")
        return errors

    cue_count = 0
    for line in lines:
        match = _VTT_TIMESTAMP_RE.match(line.strip())
        if match:
            cue_count += 1
            start_str, end_str = match.group(1), match.group(2)
            start_ms = _parse_vtt_timestamp(start_str)
            end_ms = _parse_vtt_timestamp(end_str)
            if start_ms is not None and end_ms is not None and start_ms >= end_ms:
                errors.append(
                    f"Cue {cue_count}: start time >= end time ({start_str} --> {end_str})"
                )

    if cue_count == 0:
        errors.append("No valid cues found")

    return errors


# ─── Content sanitization ────────────────────────────────────────────────────

# Allowlist of WebVTT cue-payload tags (SEC-012 §4.4). Only these tags survive
# sanitization; everything else is stripped. The voice tag `<v NAME>` carries a
# speaker name that is preserved; all *other* attributes on permitted tags are
# discarded. `<c>` and `<lang>` are intentionally excluded (they carry
# class/attribute vectors and are rarely required for accessibility).
#
# Matches a single tag (with its angle brackets) and captures:
#   group 1 ("close") — "/" for a closing tag, else empty
#   group 2 ("name")  — the tag name
#   group 3 ("rest")  — any trailing content (attributes / voice name)
_VTT_ALLOWED_TAGS_RE = re.compile(
    r"<\s*(?P<close>/?)\s*(?P<name>b|i|u|ruby|rt|v)(?P<rest>\b[^>]*)?>",
    re.IGNORECASE,
)
# Defense-in-depth: even though the allowlist removes every attribute, scrub any
# javascript:/data: URIs that might appear in surviving (or escaped) cue text.
_DATA_URI_RE = re.compile(r"data\s*:", re.IGNORECASE)
_JAVASCRIPT_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)


def _normalize_allowed_tag(match: "re.Match[str]") -> str:
    """Rewrite a permitted WebVTT tag, stripping every attribute.

    For the voice tag `<v NAME>` the speaker name (the tag's leading text) is
    preserved because it is semantically part of the tag, not an attribute.
    All other tags collapse to their bare form (`<b onclick=x>` -> `<b>`).
    """
    close = match.group("close")
    name = match.group("name").lower()
    rest = (match.group("rest") or "").strip()

    if close:
        return f"</{name}>"

    if name == "v" and rest:
        # Preserve only the voice name: take the first whitespace-delimited
        # token and reject anything containing attribute-like syntax (=, quotes).
        candidate = rest.split()[0] if rest.split() else ""
        if candidate and not any(c in candidate for c in "=\"'<>"):
            return f"<v {candidate}>"
        return "<v>"

    return f"<{name}>"


def _sanitize_vtt_line(line: str) -> str:
    """Sanitize a single cue-payload line via the tag allowlist.

    Allowed tags are normalized (attributes stripped); every other ``<...>``
    construct has its angle brackets removed so no executable markup remains.
    """
    out: list[str] = []
    pos = 0
    length = len(line)
    while pos < length:
        ch = line[pos]
        if ch == "<":
            m = _VTT_ALLOWED_TAGS_RE.match(line, pos)
            if m:
                out.append(_normalize_allowed_tag(m))
                pos = m.end()
                continue
            # Not an allowlisted tag: drop up to the closing '>' (or the rest of
            # the line if unterminated), discarding the dangerous markup. The
            # inner text of stripped container tags is preserved (only the
            # angle-bracketed tag itself is removed).
            close_idx = line.find(">", pos)
            if close_idx == -1:
                pos = length
            else:
                pos = close_idx + 1
            continue
        out.append(ch)
        pos += 1
    return "".join(out)


def sanitize_vtt_content(content: str) -> str:
    """Strip dangerous HTML from VTT cue payloads using a strict allowlist.

    Only the WebVTT-permitted tags (`<b>`, `<i>`, `<u>`, `<v NAME>`, `<ruby>`,
    `<rt>` and their closing tags) survive; all attributes are removed and every
    other tag is stripped (SEC-012 §4.4). Cue timestamp lines and plain text are
    preserved unchanged. Signature and return type are unchanged from the
    previous denylist implementation.
    """
    lines = content.split("\n")
    in_cue = False
    result: list[str] = []
    for line in lines:
        if _VTT_TIMESTAMP_RE.match(line.strip()):
            in_cue = True
            result.append(line)
        elif in_cue and line.strip() == "":
            in_cue = False
            result.append(line)
        elif in_cue:
            result.append(_sanitize_vtt_line(line))
        else:
            result.append(line)
    sanitized = "\n".join(result)
    # Belt-and-suspenders URI scrubbing across the whole payload.
    sanitized = _DATA_URI_RE.sub("", sanitized)
    sanitized = _JAVASCRIPT_URI_RE.sub("", sanitized)
    return sanitized


# ─── S3 operations ───────────────────────────────────────────────────────────


def _resolve_bucket_prefix() -> tuple[str, str]:
    bucket = getattr(S, "vod_output_bucket", None) or getattr(S, "transcode_output_bucket", None) or "vod-output"
    prefix = getattr(S, "vod_output_prefix", None) or getattr(S, "transcode_output_prefix", None) or "tenants"
    return bucket, prefix


def upload_subtitle_to_s3(video_id: str, track_id: str, vtt_content: str) -> str:
    """Upload VTT content to S3. Returns the S3 key."""
    bucket, prefix = _resolve_bucket_prefix()
    s3_key = f"{prefix}/subtitles/{video_id}/{track_id}.vtt"

    _s3.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=vtt_content.encode("utf-8"),
        ContentType="text/vtt",
        CacheControl="max-age=86400",
    )
    return s3_key


def delete_subtitle_from_s3(s3_key: str) -> None:
    """Delete a VTT file from S3."""
    bucket, _ = _resolve_bucket_prefix()
    try:
        _s3.delete_object(Bucket=bucket, Key=s3_key)
    except Exception:
        logger.warning("Failed to delete S3 object %s/%s", bucket, s3_key)


def mint_subtitle_url(s3_key: str) -> str:
    """Generate a presigned URL (or mock path in dev mode) for a VTT file."""
    bucket, _ = _resolve_bucket_prefix()
    if S.dev_mode:
        return f"/mock/s3/{bucket}/{s3_key}"
    ttl = S.video_subtitle_url_ttl_seconds
    return _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": s3_key},
        ExpiresIn=ttl,
    )


# ─── Track CRUD on video metadata ───────────────────────────────────────────


def upload_subtitle(
    *,
    video_id: str,
    owner_id: str,
    language: str,
    label: str,
    content: str,
    file_format: str,
    is_default: bool = False,
) -> dict:
    """Full subtitle upload pipeline: validate, convert, sanitize, store."""
    from app.services.video_metadata_store import get_video

    if not S.video_subtitle_enabled:
        raise HTTPException(status_code=403, detail="video subtitles are not enabled")

    # Language validation
    if not validate_language_code(language):
        raise HTTPException(status_code=400, detail="invalid language code")

    # Fetch video and verify ownership
    video = get_video(video_id)
    if video.owner_user_id != owner_id:
        raise HTTPException(status_code=403, detail="forbidden")

    # Check max tracks
    existing_tracks = video.subtitle_tracks or []
    if len(existing_tracks) >= S.video_subtitle_max_tracks:
        raise HTTPException(
            status_code=409,
            detail=f"maximum subtitle tracks reached ({S.video_subtitle_max_tracks})",
        )

    # Convert SRT to VTT if needed
    if file_format == "srt":
        content = srt_to_vtt(content)

    # Validate VTT
    errors = validate_vtt(content)
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"invalid VTT content: {'; '.join(errors)}",
        )

    # Sanitize
    content = sanitize_vtt_content(content)

    # Generate track ID and upload to S3
    track_id = f"st_{uuid4().hex[:16]}"
    s3_key = upload_subtitle_to_s3(video_id, track_id, content)

    # Build track record
    ts = now_ts()
    track = SubtitleTrack(
        track_id=track_id,
        language=language,
        label=label,
        format="vtt",
        s3_key=s3_key,
        is_default=is_default,
        is_auto_generated=False,
        created_at=ts,
    )

    # If is_default, unset existing defaults
    if is_default and existing_tracks:
        _unset_all_defaults(video_id, existing_tracks)

    # Append track atomically
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = list_append(if_not_exists(subtitle_tracks, :empty), :new_track), updated_at = :ts",
        ExpressionAttributeValues={
            ":new_track": [track.model_dump()],
            ":empty": [],
            ":ts": ts,
        },
    )

    vtt_url = mint_subtitle_url(s3_key)
    return {
        "track_id": track_id,
        "video_id": video_id,
        "language": language,
        "label": label,
        "format": "vtt",
        "vtt_url": vtt_url,
        "is_default": is_default,
        "is_auto_generated": False,
        "created_at": ts,
    }


def _unset_all_defaults(video_id: str, tracks: list) -> None:
    """Set is_default=False on all existing tracks."""
    updated = []
    for t in tracks:
        td = t.model_dump() if hasattr(t, "model_dump") else dict(t)
        td["is_default"] = False
        updated.append(td)
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :ts",
        ExpressionAttributeValues={
            ":tracks": updated,
            ":ts": now_ts(),
        },
    )


def list_subtitles(video_id: str) -> dict:
    """List all subtitle tracks for a video with VTT URLs."""
    from app.services.video_metadata_store import get_video

    video = get_video(video_id)
    tracks_out = []
    for t in video.subtitle_tracks or []:
        td = t.model_dump() if hasattr(t, "model_dump") else dict(t)
        td["vtt_url"] = mint_subtitle_url(td["s3_key"])
        tracks_out.append(td)

    return {"video_id": video_id, "tracks": tracks_out}


def delete_subtitle(*, video_id: str, track_id: str, owner_id: str) -> dict:
    """Delete a subtitle track from a video."""
    from app.services.video_metadata_store import get_video

    if not S.video_subtitle_enabled:
        raise HTTPException(status_code=403, detail="video subtitles are not enabled")

    video = get_video(video_id)
    if video.owner_user_id != owner_id:
        raise HTTPException(status_code=403, detail="forbidden")

    existing = video.subtitle_tracks or []
    found = None
    remaining = []
    for t in existing:
        if t.track_id == track_id:
            found = t
        else:
            remaining.append(t.model_dump())

    if not found:
        raise HTTPException(status_code=404, detail="subtitle track not found")

    # Delete from S3
    delete_subtitle_from_s3(found.s3_key)

    # Update DDB
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :ts",
        ExpressionAttributeValues={
            ":tracks": remaining,
            ":ts": now_ts(),
        },
    )

    return {"ok": True, "track_id": track_id, "video_id": video_id}


def update_subtitle(
    *,
    video_id: str,
    track_id: str,
    owner_id: str,
    label: Optional[str] = None,
    is_default: Optional[bool] = None,
) -> dict:
    """Update a subtitle track's label or default status."""
    from app.services.video_metadata_store import get_video

    if not S.video_subtitle_enabled:
        raise HTTPException(status_code=403, detail="video subtitles are not enabled")

    video = get_video(video_id)
    if video.owner_user_id != owner_id:
        raise HTTPException(status_code=403, detail="forbidden")

    existing = video.subtitle_tracks or []
    found_idx = None
    for i, t in enumerate(existing):
        if t.track_id == track_id:
            found_idx = i
            break

    if found_idx is None:
        raise HTTPException(status_code=404, detail="subtitle track not found")

    # Build updated list
    updated_tracks = [t.model_dump() for t in existing]

    if is_default is True:
        for td in updated_tracks:
            td["is_default"] = False

    if label is not None:
        updated_tracks[found_idx]["label"] = label
    if is_default is not None:
        updated_tracks[found_idx]["is_default"] = is_default

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET subtitle_tracks = :tracks, updated_at = :ts",
        ExpressionAttributeValues={
            ":tracks": updated_tracks,
            ":ts": now_ts(),
        },
    )

    track_out = dict(updated_tracks[found_idx])
    track_out["vtt_url"] = mint_subtitle_url(track_out["s3_key"])
    return track_out
