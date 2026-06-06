"""Routers for encrypted one-time share links (FILES-001).

- ``router`` (authenticated, cookie + CSRF): owner link management
  (create / list / revoke) under ``/ui/files/share-links``.
- ``public_router`` (no auth): recipient info + download under
  ``/public/files/share``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from app.core.normalize import client_ip_from_request
from app.models import (
    CreateShareLinkIn,
    ShareLinkDownloadIn,
    ShareLinkListOut,
    ShareLinkOut,
    ShareLinkPublicInfoOut,
)
from app.services import file_share_links as svc
from app.services.rate_limit import rate_limit_share_link_download
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/files/share-links", tags=["file-share-links"])
public_router = APIRouter(prefix="/public/files/share", tags=["public-file-share"])


# ---------------------------------------------------------------------------
# Authenticated owner endpoints
# ---------------------------------------------------------------------------


@router.post("", status_code=201, response_model=ShareLinkOut)
def create_share_link_endpoint(
    body: CreateShareLinkIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ShareLinkOut:
    out = svc.create_share_link(
        file_node_id=body.file_node_id,
        owner_sub=ctx["user_sub"],
        expiry_hours=body.expiry_hours,
        max_downloads=body.max_downloads,
        password=body.password,
    )
    return ShareLinkOut(**out)


@router.get("", response_model=ShareLinkListOut)
def list_share_links_endpoint(
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ShareLinkListOut:
    items = svc.list_share_links(ctx["user_sub"])
    return ShareLinkListOut(items=[ShareLinkOut(**it) for it in items])


@router.delete("/{link_id}")
def revoke_share_link_endpoint(
    link_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    svc.revoke_share_link(link_id, ctx["user_sub"])
    return {"ok": True, "link_id": link_id}


# ---------------------------------------------------------------------------
# Public recipient endpoints (no auth)
# ---------------------------------------------------------------------------


@public_router.get("/{link_id}/info", response_model=ShareLinkPublicInfoOut)
def get_share_link_info_endpoint(link_id: str) -> ShareLinkPublicInfoOut:
    info = svc.get_share_link_info(link_id)
    return ShareLinkPublicInfoOut(**info)


def _download_response(result: Dict[str, Any]) -> Response:
    file_name = result.get("file_name") or "file"
    return Response(
        content=result["content"],
        media_type=result.get("content_type") or "application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{file_name}"; '
                f"filename*=UTF-8''{quote(file_name)}"
            ),
        },
    )


@public_router.post("/{link_id}/download")
def download_share_link_endpoint(
    link_id: str, req: Request, body: ShareLinkDownloadIn | None = None
) -> Response:
    rate_limit_share_link_download(link_id, client_ip_from_request(req))
    password = body.password if body else None
    result = svc.consume_share_link(link_id=link_id, password=password)
    return _download_response(result)


@public_router.get("/{link_id}/download")
def download_share_link_get_endpoint(
    link_id: str, req: Request, password: str | None = None
) -> Response:
    rate_limit_share_link_download(link_id, client_ip_from_request(req))
    result = svc.consume_share_link(link_id=link_id, password=password)
    return _download_response(result)
