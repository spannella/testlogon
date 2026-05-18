from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional

_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class FeedFilterParams:
    author_id: Optional[str] = None
    q: Optional[str] = None
    from_dt: Optional[datetime] = None
    to_dt: Optional[datetime] = None
    has_media: Optional[bool] = None


def parse_filter_dt(value: Optional[str], *, bound: str = "any") -> Optional[datetime]:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if _DATE_ONLY_RE.fullmatch(raw):
        if bound == "to":
            raw = f"{raw}T23:59:59+00:00"
        else:
            raw = f"{raw}T00:00:00+00:00"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid 'from'/'to' datetime; expected ISO-8601") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_filter_window(from_value: Optional[str], to_value: Optional[str]) -> tuple[Optional[datetime], Optional[datetime]]:
    from_dt = parse_filter_dt(from_value, bound="from")
    to_dt = parse_filter_dt(to_value, bound="to")
    if from_dt and to_dt and from_dt > to_dt:
        raise ValueError("'from' must be less than or equal to 'to'")
    return from_dt, to_dt


def post_has_media(post: Dict[str, Any]) -> bool:
    image_urls = post.get("image_urls") or []
    attachments = post.get("attachments") or []
    file_attachments = post.get("file_attachments") or []
    return bool(image_urls or attachments or file_attachments)


def post_matches_search(post: Dict[str, Any], q: Optional[str]) -> bool:
    if not q:
        return True
    term = str(q).strip().lower()
    if not term:
        return True
    haystack = " ".join(str(post.get(k) or "") for k in ("body", "body_plain", "body_markdown")).lower()
    return term in haystack


def post_matches_filters(post: Dict[str, Any], params: FeedFilterParams) -> bool:
    author = post.get("user_id")
    if params.author_id and author != params.author_id:
        return False

    try:
        created_dt = parse_filter_dt(post.get("created_at"))
    except ValueError:
        created_dt = None
    if params.from_dt and (created_dt is None or created_dt < params.from_dt):
        return False
    if params.to_dt and (created_dt is None or created_dt > params.to_dt):
        return False

    if params.has_media is not None and post_has_media(post) is not params.has_media:
        return False

    if not post_matches_search(post, params.q):
        return False

    return True


def sort_posts_deterministically(posts: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    return sorted(
        posts,
        key=lambda p: (str(p.get("created_at") or ""), str(p.get("post_id") or "")),
        reverse=True,
    )
