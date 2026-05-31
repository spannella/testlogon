"""PLATFORM-005: SEO / Open Graph metadata generation for public resources.

This service builds crawler/share-preview metadata (title, description,
og:*, twitter:*, canonical URL, JSON-LD) for *publicly shareable* resources
addressed by ``(resource_type, resource_id)``.

Design goals:

* **Privacy-respecting** -- only genuinely public, non-private, non-deleted
  content produces real metadata. Private / unlisted / locked content returns
  generic ("not available" style) metadata and NEVER leaks bodies, private
  fields, or images. Locked posts in particular never expose their body text.
* **No content-service recreation** -- this module *reads* the existing
  profile, calendar, newsfeed and video services. It only assembles metadata.
* **Deterministic** -- given identical stored data it returns identical output
  (stable ordering, fixed truncation), which keeps E2E assertions reliable.

The crawler-facing router (:mod:`app.routers.seo_metadata`) exposes this with
no authentication; callers therefore only ever see public data.
"""
from __future__ import annotations

import html
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SITE_NAME = "Control Panel"
DEFAULT_TITLE = "Control Panel"
DEFAULT_DESCRIPTION = (
    "Your all-in-one platform for messaging, commerce, and content creation."
)
DEFAULT_LOCALE = "en_US"

# Maximum description length surfaced in social previews.
MAX_DESCRIPTION_LEN = 200

# Supported public resource types.
RESOURCE_TYPES = ("profile", "event", "post", "video", "live")

# Public routes that crawlers may request (used by robots/sitemap helpers).
PUBLIC_PATH_PREFIXES = ("/u/", "/event/", "/posts/", "/videos/", "/live/")
# Routes that must NOT be crawled / indexed (private app surface).
DISALLOWED_PATH_PREFIXES = (
    "/messages",
    "/settings",
    "/billing",
    "/security",
    "/admin",
    "/files",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate(text: Optional[str], limit: int = MAX_DESCRIPTION_LEN) -> str:
    """Collapse whitespace and hard-truncate ``text`` to ``limit`` chars."""
    if not text:
        return ""
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rstrip()


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _absolute(base_url: Optional[str], path: str) -> str:
    """Return an absolute URL for ``path`` given an optional ``base_url``."""
    if not path:
        path = "/"
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not base_url:
        return path
    return f"{base_url.rstrip('/')}{path if path.startswith('/') else '/' + path}"


def default_metadata(base_url: Optional[str] = None, path: str = "/") -> Dict[str, Any]:
    """Generic site-wide metadata used for unknown / private resources."""
    canonical = _absolute(base_url, path)
    return {
        "resource_type": None,
        "resource_id": None,
        "available": False,
        "title": DEFAULT_TITLE,
        "description": DEFAULT_DESCRIPTION,
        "canonical_url": canonical,
        "site_name": SITE_NAME,
        "locale": DEFAULT_LOCALE,
        "og": {
            "og:title": DEFAULT_TITLE,
            "og:description": DEFAULT_DESCRIPTION,
            "og:type": "website",
            "og:site_name": SITE_NAME,
            "og:locale": DEFAULT_LOCALE,
            "og:url": canonical,
        },
        "twitter": {
            "twitter:card": "summary",
            "twitter:title": DEFAULT_TITLE,
            "twitter:description": DEFAULT_DESCRIPTION,
        },
        "image": None,
        "json_ld": None,
    }


def _assemble(
    *,
    resource_type: str,
    resource_id: str,
    title: str,
    description: str,
    path: str,
    base_url: Optional[str],
    og_type: str,
    image: Optional[str] = None,
    json_ld: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble a full metadata document from already privacy-filtered parts."""
    canonical = _absolute(base_url, path)
    image_abs = _absolute(base_url, image) if image else None
    description = _truncate(description)

    og: Dict[str, Any] = {
        "og:title": title,
        "og:description": description,
        "og:type": og_type,
        "og:site_name": SITE_NAME,
        "og:locale": DEFAULT_LOCALE,
        "og:url": canonical,
    }
    if image_abs:
        og["og:image"] = image_abs

    twitter: Dict[str, Any] = {
        "twitter:card": "summary_large_image" if image_abs else "summary",
        "twitter:title": title,
        "twitter:description": description,
    }
    if image_abs:
        twitter["twitter:image"] = image_abs

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "available": True,
        "title": title,
        "description": description,
        "canonical_url": canonical,
        "site_name": SITE_NAME,
        "locale": DEFAULT_LOCALE,
        "og": og,
        "twitter": twitter,
        "image": image_abs,
        "json_ld": json_ld,
    }


# ---------------------------------------------------------------------------
# Per-resource builders (read existing services; never leak private data)
# ---------------------------------------------------------------------------

def _profile_metadata(identifier: str, base_url: Optional[str]) -> Dict[str, Any]:
    path = f"/u/{identifier}"
    try:
        from app.routers.profile import (
            _resolve_profile_identifier_to_user_sub,
            _resolve_canonical_identifier_for_user_sub,
        )
        from app.services.profile import get_profile
        from app.services.profile_discoverability import (
            get_profile_discoverability_state,
            DiscoverabilityState,
        )

        try:
            user_sub = _resolve_profile_identifier_to_user_sub(identifier)
        except Exception:
            return default_metadata(base_url, path)
        if not user_sub:
            return default_metadata(base_url, path)

        # Privacy: hidden / deactivated / deleted profiles do not leak.
        disc = get_profile_discoverability_state(user_sub) or {}
        status = str(disc.get("discoverability_status", "active")).strip().lower()
        if status in (
            DiscoverabilityState.DEACTIVATED.value,
            DiscoverabilityState.DELETED.value,
            DiscoverabilityState.HIDDEN.value,
        ):
            return default_metadata(base_url, path)

        profile = get_profile(user_sub) or {}
        if not profile:
            return default_metadata(base_url, path)

        # Only public-classified fields are surfaced.
        display_name = _clean(profile.get("display_name")) or "User"
        bio = (
            _clean(profile.get("description"))
            or _clean(profile.get("title"))
            or f"{display_name}'s profile"
        )
        image = _clean(profile.get("profile_photo_url"))

        try:
            canonical_id = _resolve_canonical_identifier_for_user_sub(user_sub) or identifier
        except Exception:
            canonical_id = identifier
        canonical_path = f"/u/{canonical_id}"
        canonical_url = _absolute(base_url, canonical_path)

        json_ld: Dict[str, Any] = {
            "@context": "https://schema.org",
            "@type": "Person",
            "name": display_name,
            "url": canonical_url,
        }
        if bio:
            json_ld["description"] = _truncate(bio)
        if image:
            json_ld["image"] = _absolute(base_url, image)

        return _assemble(
            resource_type="profile",
            resource_id=identifier,
            title=f"{display_name} | {SITE_NAME}",
            description=bio,
            path=canonical_path,
            base_url=base_url,
            og_type="profile",
            image=image,
            json_ld=json_ld,
        )
    except Exception:
        logger.exception("seo_metadata: failed building profile meta for %s", identifier)
        return default_metadata(base_url, path)


def _event_metadata(
    calendar_id: str, event_id: str, base_url: Optional[str]
) -> Dict[str, Any]:
    path = f"/event/{calendar_id}/{event_id}"
    try:
        event = _load_public_event(calendar_id, event_id)
        if not event:
            return default_metadata(base_url, path)

        # Privacy: only events explicitly shared publicly produce metadata.
        if not _event_is_public(event):
            return default_metadata(base_url, path)

        name = _clean(event.get("name")) or _clean(event.get("title")) or "Event"
        location = _clean(event.get("location"))
        when = _format_event_when(event)
        desc_parts = [p for p in (when, location) if p]
        description = (
            _clean(event.get("description")) or " · ".join(desc_parts) or f"{name}"
        )

        json_ld: Dict[str, Any] = {
            "@context": "https://schema.org",
            "@type": "Event",
            "name": name,
            "url": _absolute(base_url, path),
        }
        start = _clean(event.get("start_utc"))
        end = _clean(event.get("end_utc"))
        if start:
            json_ld["startDate"] = start
        if end:
            json_ld["endDate"] = end
        if event.get("description"):
            json_ld["description"] = _truncate(str(event.get("description")))
        if location:
            json_ld["location"] = {"@type": "Place", "name": location}

        return _assemble(
            resource_type="event",
            resource_id=f"{calendar_id}/{event_id}",
            title=f"{name} | {SITE_NAME}",
            description=description,
            path=path,
            base_url=base_url,
            og_type="event",
            image=None,
            json_ld=json_ld,
        )
    except Exception:
        logger.exception(
            "seo_metadata: failed building event meta for %s/%s", calendar_id, event_id
        )
        return default_metadata(base_url, path)


def _load_public_event(calendar_id: str, event_id: str) -> Optional[Dict[str, Any]]:
    """Best-effort read of an event item from the calendar table."""
    try:
        from app.core.tables import T

        item = (
            T.calendar.get_item(
                Key={"calendar_id": calendar_id, "event_id": event_id}
            ).get("Item")
        )
        if item:
            return dict(item)
    except Exception:
        pass
    # Fallback: some schemas key calendar events differently; try a service.
    try:
        from app.services import calendar as calendar_svc  # type: ignore

        for fn_name in (
            "get_public_event_details",
            "get_public_event",
            "get_event",
        ):
            fn = getattr(calendar_svc, fn_name, None)
            if callable(fn):
                try:
                    out = fn(calendar_id, event_id)
                except TypeError:
                    continue
                if out:
                    return dict(out) if not isinstance(out, dict) else out
    except Exception:
        pass
    return None


def _event_is_public(event: Dict[str, Any]) -> bool:
    """An event is shareable only if it opted into public visibility."""
    for key in ("public", "is_public", "shared_public"):
        if key in event:
            return bool(event.get(key))
    visibility = str(event.get("visibility", "")).strip().lower()
    if visibility:
        return visibility in ("public", "shared")
    share_mode = str(event.get("share_mode", "")).strip().lower()
    if share_mode:
        return share_mode in ("public", "link")
    # Default: if a public-event lookup returned it, treat as shareable.
    return True


def _format_event_when(event: Dict[str, Any]) -> str:
    if event.get("all_day") and _clean(event.get("all_day_date")):
        return str(event.get("all_day_date"))
    start = _clean(event.get("start_utc"))
    if not start:
        return ""
    end = _clean(event.get("end_utc"))
    return f"{start} – {end}" if end else start


def _post_metadata(post_id: str, base_url: Optional[str]) -> Dict[str, Any]:
    path = f"/posts/{post_id}"
    try:
        post = _load_post(post_id)
        if not post:
            return default_metadata(base_url, path)

        # Privacy: only published, public posts are eligible.
        status = str(post.get("status", "published")).strip().lower()
        if status != "published":
            return default_metadata(base_url, path)
        visibility = str(post.get("visibility", "public")).strip().lower()
        if visibility not in ("public", ""):
            return default_metadata(base_url, path)

        author = (
            _clean(post.get("author_display_name"))
            or _clean(post.get("user_id"))
            or "a creator"
        )
        title = f"Post by {author} | {SITE_NAME}"

        # Locked / paywalled posts NEVER expose body text or images.
        lock_price = 0
        try:
            lock_price = int(
                post.get("lock_price_cents")
                or post.get("unlock_price_cents")
                or 0
            )
        except Exception:
            lock_price = 0
        is_locked = bool(post.get("locked")) or lock_price > 0

        if is_locked:
            return _assemble(
                resource_type="post",
                resource_id=post_id,
                title=title,
                description="This post is locked. Subscribe or pay to view.",
                path=path,
                base_url=base_url,
                og_type="article",
                image=None,
                json_ld={
                    "@context": "https://schema.org",
                    "@type": "Article",
                    "headline": title,
                    "url": _absolute(base_url, path),
                },
            )

        body = (
            _clean(post.get("body_plain"))
            or _clean(post.get("body"))
            or "Read this post on Control Panel."
        )
        images = post.get("image_urls") or []
        image = _clean(images[0]) if isinstance(images, list) and images else None

        json_ld = {
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": _truncate(body, 110) or title,
            "url": _absolute(base_url, path),
            "author": {"@type": "Person", "name": author},
        }
        if image:
            json_ld["image"] = _absolute(base_url, image)

        return _assemble(
            resource_type="post",
            resource_id=post_id,
            title=title,
            description=body,
            path=path,
            base_url=base_url,
            og_type="article",
            image=image,
            json_ld=json_ld,
        )
    except Exception:
        logger.exception("seo_metadata: failed building post meta for %s", post_id)
        return default_metadata(base_url, path)


def _load_post(post_id: str) -> Optional[Dict[str, Any]]:
    """Best-effort read of a single post item without recreating services."""
    # Try router/service helpers first.
    for mod_name, fn_names in (
        ("app.routers.newsfeed", ("_get_post_item", "_load_post_item")),
        ("app.services.newsfeed", ("get_post_item", "get_post_by_id", "_get_post")),
    ):
        try:
            mod = __import__(mod_name, fromlist=["*"])
        except Exception:
            continue
        for fn_name in fn_names:
            fn = getattr(mod, fn_name, None)
            if callable(fn):
                try:
                    out = fn(post_id)
                except TypeError:
                    continue
                except Exception:
                    continue
                if out:
                    return dict(out) if not isinstance(out, dict) else out
    # Fallback: direct single-table read.
    try:
        import os
        from app.core.aws import ddb

        table = ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))
        item = table.get_item(
            Key={"pk": f"POST#{post_id}", "sk": f"POST#{post_id}"}
        ).get("Item")
        if item:
            return dict(item)
    except Exception:
        pass
    return None


def _video_metadata(video_id: str, base_url: Optional[str]) -> Dict[str, Any]:
    path = f"/videos/{video_id}"
    try:
        from app.services.video_metadata_store import get_video

        try:
            video = get_video(video_id)
        except Exception:
            return default_metadata(base_url, path)
        if not video:
            return default_metadata(base_url, path)

        def _attr(obj: Any, name: str) -> Any:
            if isinstance(obj, dict):
                return obj.get(name)
            return getattr(obj, name, None)

        # Privacy: only published / public videos.
        status = str(_attr(video, "status") or "").strip().lower()
        visibility = str(_attr(video, "visibility") or "public").strip().lower()
        if status and status not in ("published", "ready", "active", "complete", "completed"):
            return default_metadata(base_url, path)
        if visibility not in ("public", ""):
            return default_metadata(base_url, path)

        title = _clean(_attr(video, "title")) or "Video"
        description = _clean(_attr(video, "description")) or f"{title}"
        image = _clean(_attr(video, "thumbnail_url")) or _clean(_attr(video, "poster_url"))

        json_ld = {
            "@context": "https://schema.org",
            "@type": "VideoObject",
            "name": title,
            "url": _absolute(base_url, path),
        }
        if description:
            json_ld["description"] = _truncate(description)
        if image:
            json_ld["thumbnailUrl"] = _absolute(base_url, image)

        return _assemble(
            resource_type="video",
            resource_id=video_id,
            title=f"{title} | {SITE_NAME}",
            description=description,
            path=path,
            base_url=base_url,
            og_type="video.other",
            image=image,
            json_ld=json_ld,
        )
    except Exception:
        logger.exception("seo_metadata: failed building video meta for %s", video_id)
        return default_metadata(base_url, path)


def _live_metadata(session_id: str, base_url: Optional[str]) -> Dict[str, Any]:
    path = f"/live/{session_id}"
    return _assemble(
        resource_type="live",
        resource_id=session_id,
        title=f"Live Stream | {SITE_NAME}",
        description="Watch live on Control Panel.",
        path=path,
        base_url=base_url,
        og_type="video.other",
        image=None,
        json_ld={
            "@context": "https://schema.org",
            "@type": "BroadcastEvent",
            "name": "Live Stream",
            "url": _absolute(base_url, path),
            "isLiveBroadcast": True,
        },
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_metadata(
    resource_type: str,
    resource_id: str,
    *,
    base_url: Optional[str] = None,
    secondary_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build SEO/OpenGraph metadata for ``(resource_type, resource_id)``.

    ``secondary_id`` is used by event resources (calendar_id + event_id).
    Unknown types or missing/private resources return generic default
    metadata (``available == False``) and never leak private content.
    """
    rtype = (resource_type or "").strip().lower()
    rid = (resource_id or "").strip()
    if not rtype or not rid:
        return default_metadata(base_url, "/")

    if rtype == "profile":
        return _profile_metadata(rid, base_url)
    if rtype == "event":
        event_id = (secondary_id or "").strip()
        if not event_id:
            return default_metadata(base_url, f"/event/{rid}")
        return _event_metadata(rid, event_id, base_url)
    if rtype == "post":
        return _post_metadata(rid, base_url)
    if rtype == "video":
        return _video_metadata(rid, base_url)
    if rtype == "live":
        return _live_metadata(rid, base_url)

    return default_metadata(base_url, "/")


def metadata_for_path(path: str, *, base_url: Optional[str] = None) -> Dict[str, Any]:
    """Resolve a public URL ``path`` (e.g. ``/u/alice``) to metadata."""
    import re

    raw = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not raw.startswith("/"):
        raw = "/" + raw

    m = re.match(r"^/u/([^/]+)/?$", raw)
    if m:
        return build_metadata("profile", m.group(1), base_url=base_url)

    m = re.match(r"^/event/([^/]+)/([^/]+)/?$", raw)
    if m:
        return build_metadata(
            "event", m.group(1), secondary_id=m.group(2), base_url=base_url
        )

    m = re.match(r"^/posts/([^/]+)/?$", raw)
    if m:
        return build_metadata("post", m.group(1), base_url=base_url)

    m = re.match(r"^/(?:videos|gallery)/([^/]+)/?$", raw)
    if m:
        return build_metadata("video", m.group(1), base_url=base_url)

    m = re.match(r"^/live/([^/]+)/?$", raw)
    if m:
        return build_metadata("live", m.group(1), base_url=base_url)

    return default_metadata(base_url, raw)


def render_meta_tags(metadata: Dict[str, Any]) -> str:
    """Render a metadata document into a server-side ``<meta>`` tag block.

    All user-controlled values are HTML-escaped to prevent injection through
    title / description / image fields.
    """
    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value), quote=True)

    tags: List[str] = []
    title = metadata.get("title") or DEFAULT_TITLE
    tags.append(f"<title>{esc(title)}</title>")
    tags.append(
        f'<meta name="description" content="{esc(metadata.get("description"))}" />'
    )

    for key, value in (metadata.get("og") or {}).items():
        if value is None:
            continue
        tags.append(f'<meta property="{esc(key)}" content="{esc(value)}" />')

    for key, value in (metadata.get("twitter") or {}).items():
        if value is None:
            continue
        tags.append(f'<meta name="{esc(key)}" content="{esc(value)}" />')

    canonical = metadata.get("canonical_url")
    if canonical:
        tags.append(f'<link rel="canonical" href="{esc(canonical)}" />')

    json_ld = metadata.get("json_ld")
    if json_ld:
        import json as _json

        # json.dumps already escapes </ sequences via ensure_ascii defaults for
        # most chars; additionally guard against closing-script breakout.
        serialized = _json.dumps(json_ld, ensure_ascii=False, sort_keys=True)
        serialized = serialized.replace("</", "<\\/")
        tags.append(
            f'<script type="application/ld+json">{serialized}</script>'
        )

    return "\n    ".join(tags)


def build_robots_txt(*, base_url: Optional[str] = None) -> str:
    """Produce a robots.txt allowing public content and blocking private routes."""
    lines: List[str] = ["User-agent: *"]
    for prefix in PUBLIC_PATH_PREFIXES:
        lines.append(f"Allow: {prefix}")
    for prefix in DISALLOWED_PATH_PREFIXES:
        lines.append(f"Disallow: {prefix}")
    if base_url:
        lines.append("")
        lines.append(f"Sitemap: {base_url.rstrip('/')}/seo/sitemap.xml")
    return "\n".join(lines) + "\n"


def build_sitemap_xml(
    entries: Optional[List[Dict[str, Any]]] = None, *, base_url: Optional[str] = None
) -> str:
    """Produce a sitemap.xml from public ``entries`` (``{"path", "lastmod"}``).

    ``entries`` defaults to the static public landing routes. Callers may pass
    discovered public profile / event paths to extend it. Output is
    deterministic for a given input ordering.
    """
    def esc(value: Any) -> str:
        return html.escape("" if value is None else str(value), quote=True)

    if entries is None:
        entries = [{"path": "/"}]

    parts: List[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for entry in entries:
        loc = _absolute(base_url, str(entry.get("path") or "/"))
        parts.append("  <url>")
        parts.append(f"    <loc>{esc(loc)}</loc>")
        lastmod = entry.get("lastmod")
        if lastmod:
            parts.append(f"    <lastmod>{esc(lastmod)}</lastmod>")
        parts.append("  </url>")
    parts.append("</urlset>")
    return "\n".join(parts) + "\n"
