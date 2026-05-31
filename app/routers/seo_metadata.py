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


@seo_metadata_router.get("/metadata")
async def get_seo_metadata(
    req: Request,
    type: Optional[str] = Query(default=None, max_length=32),
    id: Optional[str] = Query(default=None, max_length=256),
    secondary_id: Optional[str] = Query(default=None, max_length=256),
    path: Optional[str] = Query(default=None, max_length=512),
):
    """Return SEO/OpenGraph metadata for a public resource.

    Provide either ``type`` + ``id`` (+ ``secondary_id`` for events), or a
    ``path`` such as ``/u/alice`` / ``/event/cal/evt`` / ``/posts/p_abc``.
    """
    base = _base_url(req)
    if path:
        return metadata_for_path(path, base_url=base)
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
):
    """Return an HTML ``<meta>`` tag block for crawler / preview injection."""
    base = _base_url(req)
    if path:
        meta = metadata_for_path(path, base_url=base)
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
