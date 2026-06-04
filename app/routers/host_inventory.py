"""Host Inventory Management API router (INFRA-001).

Prefix: ``/ui/hosts``. All endpoints use cookie-based session auth
(``require_ui_session``) and are owner-scoped — a user can only read/modify
their own saved hosts (owner isolation via the ``user_sub`` partition key →
cross-user access returns 404).

A *host* is a saved remote-connection target (hostname/port/username/protocol +
group/tags/notes). Records hold connection METADATA only — never plaintext
passwords or private keys. SSH credentials are still supplied per-session via
the terminal WebSocket; for VNC the quick-connect builder returns a
``target_id``/``ws_url`` reference resolved by the existing VNC session system.

This router integrates with — and does not re-implement — the VNC
(``vnc_sessions``) and SSH terminal (``browser_ssh_terminal``) systems.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    CreateHostIn,
    HostGroupListOut,
    HostHistoryOut,
    HostListOut,
    HostOut,
    HostQuickConnectOut,
    ImportHostsCsvIn,
    ImportResultOut,
    UpdateHostIn,
)
from app.services.host_inventory import (
    HostLimitExceeded,
    HostNotFound,
    HostValidationError,
    create_host,
    delete_host,
    get_history,
    get_host,
    import_hosts_csv,
    list_groups,
    list_hosts,
    quick_connect,
    record_connection,
    update_host,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

host_inventory_router = APIRouter(prefix="/ui/hosts", tags=["host-inventory"])


# ─── List groups (declared before /{host_id} to avoid path capture) ─────────

@host_inventory_router.get("/groups", response_model=HostGroupListOut)
async def list_host_groups(session: Dict = Depends(require_ui_session)):
    return HostGroupListOut(groups=list_groups(session["user_sub"]))


# ─── List hosts ─────────────────────────────────────────────────────────────

@host_inventory_router.get("", response_model=HostListOut)
async def list_hosts_endpoint(
    protocol: Optional[str] = Query(default=None),
    group: Optional[str] = Query(default=None),
    sort_by: str = Query(default="label"),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: Optional[str] = Query(default=None),
    session: Dict = Depends(require_ui_session),
):
    result = list_hosts(
        session["user_sub"],
        protocol=protocol,
        group=group,
        sort_by=sort_by,
        limit=limit,
        cursor=cursor,
    )
    return HostListOut(
        hosts=[HostOut(**h) for h in result["hosts"]],
        count=result["count"],
        cursor=result["cursor"],
    )


# ─── Create host ────────────────────────────────────────────────────────────

@host_inventory_router.post("", status_code=201, response_model=HostOut)
async def create_host_endpoint(
    body: CreateHostIn,
    session: Dict = Depends(require_ui_session),
):
    try:
        host = create_host(
            session["user_sub"],
            label=body.label,
            hostname=body.hostname,
            port=body.port,
            protocol=body.protocol,
            username=body.username,
            description=body.description,
            tags=body.tags,
            group=body.group,
            os_type=body.os_type,
            source="manual",
        )
    except HostLimitExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except HostValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return HostOut(**host)


# ─── CSV import ─────────────────────────────────────────────────────────────

@host_inventory_router.post("/import", response_model=ImportResultOut)
async def import_hosts_endpoint(
    body: ImportHostsCsvIn,
    session: Dict = Depends(require_ui_session),
):
    try:
        result = import_hosts_csv(session["user_sub"], body.csv_content)
    except HostValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ImportResultOut(**result)


# ─── Get single host ────────────────────────────────────────────────────────

@host_inventory_router.get("/{host_id}", response_model=HostOut)
async def get_host_endpoint(
    host_id: str,
    session: Dict = Depends(require_ui_session),
):
    host = get_host(session["user_sub"], host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return HostOut(**host)


# ─── Update host ────────────────────────────────────────────────────────────

@host_inventory_router.patch("/{host_id}", response_model=HostOut)
async def update_host_endpoint(
    host_id: str,
    body: UpdateHostIn,
    session: Dict = Depends(require_ui_session),
):
    updates = body.model_dump(exclude_unset=True)
    try:
        host = update_host(session["user_sub"], host_id, **updates)
    except HostNotFound:
        raise HTTPException(status_code=404, detail="Host not found")
    except HostValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return HostOut(**host)


# ─── Delete host ────────────────────────────────────────────────────────────

@host_inventory_router.delete("/{host_id}")
async def delete_host_endpoint(
    host_id: str,
    session: Dict = Depends(require_ui_session),
):
    if not delete_host(session["user_sub"], host_id):
        raise HTTPException(status_code=404, detail="Host not found")
    return {"ok": True}


# ─── Connection history ─────────────────────────────────────────────────────

@host_inventory_router.get("/{host_id}/history", response_model=HostHistoryOut)
async def host_history_endpoint(
    host_id: str,
    session: Dict = Depends(require_ui_session),
):
    history = get_history(session["user_sub"], host_id)
    if history is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return HostHistoryOut(**history)


# ─── Record connection ──────────────────────────────────────────────────────

@host_inventory_router.post("/{host_id}/record-connection", response_model=HostOut)
async def record_connection_endpoint(
    host_id: str,
    session: Dict = Depends(require_ui_session),
):
    host = record_connection(session["user_sub"], host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return HostOut(**host)


# ─── Quick-connect ──────────────────────────────────────────────────────────

@host_inventory_router.post("/{host_id}/quick-connect", response_model=HostQuickConnectOut)
async def quick_connect_endpoint(
    host_id: str,
    session: Dict = Depends(require_ui_session),
):
    params = quick_connect(session["user_sub"], host_id)
    if params is None:
        raise HTTPException(status_code=404, detail="Host not found")
    return HostQuickConnectOut(**params)
