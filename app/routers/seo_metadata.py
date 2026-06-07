"""PLATFORM-005: Crawler-facing SEO / Open Graph metadata router.

These endpoints are **public** (no authentication). They only ever return
metadata derived from genuinely public resources -- private, unlisted, deleted
or locked content yields generic default metadata and never leaks bodies,
private fields or images (see :mod:`app.services.seo_metadata`).

Endpoints (prefix ``/seo``):

* ``GET /seo/metadata`` -- JSON metadata for a resource by ``type`` + ``id``
  (events also take ``secondary_id``), or by ``path`` (e.g. ``/u/alice``).
* ``GET /seo/meta-tags`` -- the same metadata pre-rendered as a ``<meta>`` tag
  block (HTML) for crawler / share-preview injection.
* ``GET /seo/robots.txt`` -- robots policy (allow public, block private).
* ``GET /seo/sitemap.xml`` -- minimal sitemap of public landing routes.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import PlainTextResponse, Response

from app.services.seo_metadata import (
    build_metadata,
    build_robots_txt,
    build_sitemap_xml,
    default_metadata,
    metadata_for_path,
    render_meta_tags,
)

seo_metadata_router = APIRouter(prefix="/seo", tags=["seo"])


def _base_url(req: Request) -> str:
    """Derive an origin (scheme://host) for canonical / absolute URLs."""
    try:
        return str(req.base_url).rstrip("/")
    except Exception:
        return ""


def _resolve_path(path: Optional[str], url: Optional[str]) -> Optional[str]:
    """Normalise a ``path`` or ``url`` query param into a routable path.

    ``url`` is an alias for ``path``; if it is a full URL (``https://host/u/x``)
    only the path component is kept so ``metadata_for_path`` can dispatch on it.
    Returns ``None`` when neither was supplied (so callers can fall back to
    ``type``/``id`` resolution).
    """
    candidate = path if path else url
    if not candidate:
        return None
    candidate = candidate.strip()
    if not candidate:
        return None
    if candidate.startswith("http://") or candidate.startswith("https://"):
        try:
            from urllib.parse import urlparse

            parsed = urlparse(candidate)
            candidate = parsed.path or "/"
        except Exception:
            return "/"
    return candidate


@seo_metadata_router.get("/metadata")
async def get_seo_metadata(
    req: Request,
    type: Optional[str] = Query(default=None, max_length=32),
    id: Optional[str] = Query(default=None, max_length=256),
    secondary_id: Optional[str] = Query(default=None, max_length=256),
    path: Optional[str] = Query(default=None, max_length=512),
    url: Optional[str] = Query(default=None, max_length=2048),
):
    """Return SEO/OpenGraph metadata for a public resource.

    Provide either ``type`` + ``id`` (+ ``secondary_id`` for events), or a
    ``path``/``url`` such as ``/u/alice`` / ``/event/cal/evt`` / ``/posts/p_abc``.
    ``url`` is an alias for ``path`` (a full URL is accepted -- its path is used)
    so crawler middleware can dispatch with ``GET /seo/metadata?url=...``.
    """
    base = _base_url(req)
    target = _resolve_path(path, url)
    if target is not None:
        return metadata_for_path(target, base_url=base)
    if type and id:
        return build_metadata(type, id, secondary_id=secondary_id, base_url=base)
    return default_metadata(base, "/")


@seo_metadata_router.get("/meta-tags", response_class=Response)
async def get_seo_meta_tags(
    req: Request,
    type: Optional[str] = Query(default=None, max_length=32),
    id: Optional[str] = Query(default=None, max_length=256),
    secondary_id: Optional[str] = Query(default=None, max_length=256),
    path: Optional[str] = Query(default=None, max_length=512),
    url: Optional[str] = Query(default=None, max_length=2048),
):
    """Return an HTML ``<meta>`` tag block for crawler / preview injection.

    Accepts ``type`` + ``id``, or a ``path``/``url`` (``url`` is an alias for
    ``path``; a full URL is accepted and only its path component is used).
    """
    base = _base_url(req)
    target = _resolve_path(path, url)
    if target is not None:
        meta = metadata_for_path(target, base_url=base)
    elif type and id:
        meta = build_metadata(type, id, secondary_id=secondary_id, base_url=base)
    else:
        meta = default_metadata(base, "/")
    return Response(content=render_meta_tags(meta), media_type="text/html; charset=utf-8")


@seo_metadata_router.get("/robots.txt", response_class=PlainTextResponse)
async def get_robots_txt(req: Request):
    return PlainTextResponse(content=build_robots_txt(base_url=_base_url(req)))


@seo_metadata_router.get("/sitemap.xml", response_class=Response)
async def get_sitemap_xml(req: Request):
    base = _base_url(req)
    entries = [
        {"path": "/"},
        {"path": "/login"},
        {"path": "/register"},
    ]
    return Response(
        content=build_sitemap_xml(entries, base_url=base),
        media_type="application/xml",
    )
