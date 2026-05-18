from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from urllib.parse import urlencode
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services.sessions import require_ui_session
from app.services.jira_oauth import JiraOAuthConfigError, create_and_store_oauth_state, get_jira_oauth_config, get_oauth_state
from app.services.jira_oauth_exchange import JiraOAuthExchangeError, exchange_authorization_code, fetch_accessible_resource
from app.services.jira_secret_refs import put_secret
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.jira_projects import JiraProjectDiscoveryError, list_projects
from app.services.jira_webhook import JiraWebhookAuthError, process_jira_webhook
from app.services.jira_link_creation import (
    JiraLinkCreateError,
    create_jira_issue_and_link,
    link_existing_jira_issue_to_ticket,
    unlink_jira_issue_from_ticket,
)
from app.services.jira_conflict_resolution import JiraConflictResolutionError, resolve_link_conflict
import uuid

router = APIRouter(tags=["jira-integrations"])


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


def _jira_webhook_auth_error_code(message: str) -> str:
    normalized = str(message or "").strip().lower()
    if "source ip required" in normalized:
        return "jira_webhook_source_ip_required"
    if "source ip invalid" in normalized:
        return "jira_webhook_source_ip_invalid"
    if "source ip not allowed" in normalized:
        return "jira_webhook_source_ip_not_allowed"
    if "source ip policy misconfigured" in normalized:
        return "jira_webhook_source_ip_policy_misconfigured"
    if "source ip policy mode invalid" in normalized:
        return "jira_webhook_source_ip_policy_mode_invalid"
    if "signature required" in normalized:
        return "jira_webhook_signature_required"
    if "signature invalid" in normalized:
        return "jira_webhook_signature_invalid"
    return "jira_webhook_auth_invalid"


def _error_responses() -> dict[int | str, dict[str, Any]]:
    return {
        400: {"model": ErrorEnvelope, "description": "Bad request"},
        401: {"model": ErrorEnvelope, "description": "Unauthorized"},
        403: {"model": ErrorEnvelope, "description": "Forbidden"},
        404: {"model": ErrorEnvelope, "description": "Not found"},
        409: {"model": ErrorEnvelope, "description": "Conflict"},
        429: {"model": ErrorEnvelope, "description": "Rate limited"},
        500: {"model": ErrorEnvelope, "description": "Server misconfiguration"},
        502: {"model": ErrorEnvelope, "description": "Upstream integration failure"},
    }


class JiraConnectReq(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    redirect_uri: str = Field(..., min_length=1)


class JiraConnectOut(BaseModel):
    connect_url: str
    state: str


class JiraCallbackOut(BaseModel):
    status: Literal["connected", "failed"]
    connection_id: str | None = None
    error_code: str | None = None


class JiraProjectOut(BaseModel):
    cloud_id: str
    project_id: str
    project_key: str
    name: str
    is_private: bool = False


class JiraProjectListOut(BaseModel):
    items: list[JiraProjectOut]
    next_cursor: str | None = None


class JiraConnectionOut(BaseModel):
    connection_id: str
    workspace_id: str
    cloud_id: str
    site_url: str
    status: str
    scopes: list[str] = Field(default_factory=list)
    updated_at: int | None = None


class JiraConnectionStatusOut(BaseModel):
    connected: bool
    items: list[JiraConnectionOut]


class JiraDisconnectReq(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    connection_id: str = Field(..., min_length=1)


class JiraProjectPreferencesReq(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    cloud_id: str = Field(..., min_length=1)
    project_keys: list[str] = Field(default_factory=list)


class JiraProjectPreferencesOut(BaseModel):
    workspace_id: str
    cloud_id: str
    project_keys: list[str] = Field(default_factory=list)
    updated_at: int | None = None


class LinkCreateReq(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    project_key: str = Field(..., min_length=1)
    issue_type: str = Field(default="Task", min_length=1)
    link_mode: Literal["push_only", "pull_only", "bidirectional"] = "bidirectional"


class LinkExistingReq(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    external_issue_id: str | None = None
    external_issue_key: str | None = None
    link_mode: Literal["push_only", "pull_only", "bidirectional"] = "bidirectional"


class TicketSyncLinkOut(BaseModel):
    ticket_id: str
    link_id: str
    provider: Literal["jira"]
    external_issue_id: str
    external_issue_key: str
    link_mode: Literal["push_only", "pull_only", "bidirectional"]
    sync_state: Literal["queued", "in_sync", "conflict", "failed"]


class TicketSyncStatusOut(BaseModel):
    ticket_id: str
    linked: bool
    provider: Literal["jira"] | None = None
    sync_state: Literal["not_linked", "queued", "in_sync", "conflict", "failed"]
    link_id: str | None = None
    external_issue_id: str | None = None
    external_issue_key: str | None = None
    jira_status: str | None = None
    last_synced_at: int | None = None
    conflict_fields: list[str] = Field(default_factory=list)
    conflict_local_values: dict[str, Any] = Field(default_factory=dict)
    conflict_remote_values: dict[str, Any] = Field(default_factory=dict)


class JiraConflictResolveReq(BaseModel):
    workspace_id: str = Field(..., min_length=1)
    action: Literal["keep_internal", "keep_jira"]
    current_ticket: dict[str, Any] = Field(default_factory=dict)


class JiraConflictResolveOut(BaseModel):
    ticket_id: str
    link_id: str
    action: Literal["keep_internal", "keep_jira"]
    resolved_fields: list[str]
    sync_state: Literal["in_sync"]
    follow_up_tasks: int = 0


class JiraWebhookReq(BaseModel):
    event_type: str = Field(..., min_length=1)
    cloud_id: str = Field(..., min_length=1)
    issue_id: str | None = None
    issue_key: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class JiraWebhookOut(BaseModel):
    accepted: bool
    enqueued: bool
    deduplicated: bool
    trace_id: str


@router.get("/integrations/jira/status", response_model=JiraConnectionStatusOut, responses=_error_responses())
def jira_status(
    workspace_id: str = Query(..., min_length=1),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    store = JiraTicketSyncStore()
    rows = store.list_connections_for_user(workspace_id=workspace_id, user_id=user.sub, limit=100)
    return JiraConnectionStatusOut(
        connected=any(str(row.get("status") or "") == "active" for row in rows),
        items=[
            JiraConnectionOut(
                connection_id=str(row.get("connection_id") or ""),
                workspace_id=str(row.get("workspace_id") or workspace_id),
                cloud_id=str(row.get("cloud_id") or ""),
                site_url=str(row.get("site_url") or ""),
                status=str(row.get("status") or "unknown"),
                scopes=[str(x) for x in (row.get("scopes") or []) if str(x).strip()],
                updated_at=int(row.get("updated_at") or 0) or None,
            )
            for row in rows
        ],
    )


@router.post("/integrations/jira/disconnect", responses=_error_responses())
def jira_disconnect(
    body: JiraDisconnectReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    store = JiraTicketSyncStore()
    row = store.get_connection(workspace_id=body.workspace_id, connection_id=body.connection_id)
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "jira_connection_not_found", "message": "connection not found"}})
    if str(row.get("user_id") or "") != user.sub:
        raise HTTPException(status_code=403, detail={"error": {"code": "jira_connection_forbidden", "message": "not authorized"}})
    store.delete_connection(workspace_id=body.workspace_id, connection_id=body.connection_id)
    return {"ok": True}


@router.get("/integrations/jira/preferences", response_model=JiraProjectPreferencesOut, responses=_error_responses())
def get_jira_preferences(
    workspace_id: str = Query(..., min_length=1),
    cloud_id: str = Query(..., min_length=1),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    store = JiraTicketSyncStore()
    row = store.get_project_preferences(workspace_id=workspace_id, user_id=user.sub, cloud_id=cloud_id) or {}
    return JiraProjectPreferencesOut(
        workspace_id=workspace_id,
        cloud_id=cloud_id,
        project_keys=[str(x) for x in (row.get("project_keys") or []) if str(x).strip()],
        updated_at=int(row.get("updated_at") or 0) or None,
    )


@router.put("/integrations/jira/preferences", response_model=JiraProjectPreferencesOut, responses=_error_responses())
def put_jira_preferences(
    body: JiraProjectPreferencesReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    if len(body.project_keys) > 100:
        raise HTTPException(status_code=400, detail={"error": {"code": "jira_project_preferences_too_large", "message": "too many project keys"}})
    store = JiraTicketSyncStore()
    row = store.upsert_project_preferences(
        workspace_id=body.workspace_id,
        user_id=user.sub,
        cloud_id=body.cloud_id,
        project_keys=body.project_keys,
    )
    return JiraProjectPreferencesOut(
        workspace_id=str(row.get("workspace_id") or body.workspace_id),
        cloud_id=str(row.get("cloud_id") or body.cloud_id),
        project_keys=[str(x) for x in (row.get("project_keys") or []) if str(x).strip()],
        updated_at=int(row.get("updated_at") or 0) or None,
    )


@router.post("/integrations/jira/connect", response_model=JiraConnectOut, responses=_error_responses())
def jira_connect(
    body: JiraConnectReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        oauth_cfg = get_jira_oauth_config()
    except JiraOAuthConfigError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc

    state_row = create_and_store_oauth_state(
        workspace_id=body.workspace_id,
        user_sub=user.sub,
        redirect_uri=body.redirect_uri,
        state_ttl_seconds=oauth_cfg.state_ttl_seconds,
    )

    query = urlencode(
        {
            "audience": oauth_cfg.audience,
            "client_id": oauth_cfg.client_id,
            "scope": oauth_cfg.scopes,
            "redirect_uri": body.redirect_uri,
            "state": state_row.state,
            "response_type": "code",
            "prompt": "consent",
        }
    )
    return JiraConnectOut(connect_url=f"{oauth_cfg.authorize_url}?{query}", state=state_row.state)


@router.get("/integrations/jira/callback", response_model=JiraCallbackOut, responses=_error_responses())
def jira_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    if error:
        mapped = "jira_oauth_access_denied" if error == "access_denied" else "jira_oauth_provider_error"
        return JiraCallbackOut(status="failed", error_code=mapped)
    if not code or not state:
        raise HTTPException(status_code=400, detail={"error": {"code": "jira_callback_invalid", "message": "missing code/state"}})

    state_row = get_oauth_state(state)
    if not state_row:
        raise HTTPException(status_code=400, detail={"error": {"code": "jira_oauth_state_invalid", "message": "oauth state invalid or expired"}})

    try:
        tokens = exchange_authorization_code(code=code, redirect_uri=state_row.redirect_uri)
    except JiraOAuthExchangeError as exc:
        return JiraCallbackOut(status="failed", error_code=exc.code)

    cloud_id, site_url = fetch_accessible_resource(access_token=tokens.access_token)
    connection_id = f"jira_conn_{uuid.uuid4().hex[:12]}"
    access_ref = put_secret(tokens.access_token, prefix="jira-oauth://access")
    refresh_ref = put_secret(tokens.refresh_token, prefix="jira-oauth://refresh") if tokens.refresh_token else ""

    store = JiraTicketSyncStore()
    store.upsert_connection(
        workspace_id=state_row.workspace_id,
        connection_id=connection_id,
        user_id=state_row.user_sub,
        cloud_id=cloud_id or "unknown",
        site_url=site_url,
        auth_type="oauth",
        scopes=tokens.scopes,
        access_token_ref=access_ref,
        refresh_token_ref=refresh_ref,
        expires_at=state_row.created_at + max(60, int(tokens.expires_in or 3600)),
        status="active",
    )
    return JiraCallbackOut(status="connected", connection_id=connection_id)


@router.get("/integrations/jira/projects", response_model=JiraProjectListOut, responses=_error_responses())
def jira_projects(
    workspace_id: str = Query(..., min_length=1, description="Workspace scope for selecting Jira connection"),
    cloud_id: str = Query(..., min_length=1),
    q: str | None = Query(default=None, description="Optional search text filter"),
    project_keys: list[str] | None = Query(default=None, description="Optional project key filters"),
    cursor: str | None = Query(default=None, description="Opaque pagination cursor"),
    limit: int = Query(default=25, ge=1, le=100),
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        result = list_projects(
            workspace_id=workspace_id,
            user_sub=user.sub,
            cloud_id=cloud_id,
            q=q,
            project_keys=project_keys,
            cursor=cursor,
            limit=limit,
        )
    except JiraProjectDiscoveryError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc

    return JiraProjectListOut(
        items=[
            JiraProjectOut(
                cloud_id=item.cloud_id,
                project_id=item.project_id,
                project_key=item.project_key,
                name=item.name,
                is_private=item.is_private,
            )
            for item in result.items
        ],
        next_cursor=result.next_cursor,
    )


@router.post("/tickets/{ticket_id}/external-links/jira", response_model=TicketSyncLinkOut, responses=_error_responses())
def create_jira_link(
    ticket_id: str,
    body: LinkCreateReq,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8),
    _ctx: dict[str, str] = Depends(require_ui_session),
    _user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ = idempotency_key
    try:
        link = create_jira_issue_and_link(
            workspace_id=body.workspace_id,
            ticket_id=ticket_id,
            user_sub=_user.sub,
            project_key=body.project_key,
            issue_type=body.issue_type,
            link_mode=body.link_mode,
        )
    except JiraLinkCreateError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": {"code": exc.code, "message": exc.message}}) from exc
    return TicketSyncLinkOut(
        ticket_id=ticket_id,
        link_id=str(link.get("link_id") or ""),
        provider="jira",
        external_issue_id=str(link.get("external_issue_id") or ""),
        external_issue_key=str(link.get("external_issue_key") or ""),
        link_mode=str(link.get("link_mode") or "bidirectional"),
        sync_state=str(link.get("sync_state") or "queued"),
    )


@router.post("/tickets/{ticket_id}/external-links/jira/link-existing", response_model=TicketSyncLinkOut, responses=_error_responses())
def link_existing_jira_issue(
    ticket_id: str,
    body: LinkExistingReq,
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8),
    _ctx: dict[str, str] = Depends(require_ui_session),
    _user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ = idempotency_key
    try:
        link = link_existing_jira_issue_to_ticket(
            workspace_id=body.workspace_id,
            ticket_id=ticket_id,
            user_sub=_user.sub,
            external_issue_id=body.external_issue_id,
            external_issue_key=body.external_issue_key,
            link_mode=body.link_mode,
        )
    except JiraLinkCreateError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": {"code": exc.code, "message": exc.message}}) from exc
    return TicketSyncLinkOut(
        ticket_id=ticket_id,
        link_id=str(link.get("link_id") or ""),
        provider="jira",
        external_issue_id=str(link.get("external_issue_id") or ""),
        external_issue_key=str(link.get("external_issue_key") or ""),
        link_mode=str(link.get("link_mode") or body.link_mode),
        sync_state=str(link.get("sync_state") or "queued"),
    )


@router.delete("/tickets/{ticket_id}/external-links/{link_id}", responses=_error_responses())
def unlink_jira_issue(
    ticket_id: str,
    link_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    _user: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        return unlink_jira_issue_from_ticket(ticket_id=ticket_id, link_id=link_id, actor_user_id=_user.sub)
    except JiraLinkCreateError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": {"code": exc.code, "message": exc.message}}) from exc


@router.post(
    "/tickets/{ticket_id}/external-links/{link_id}/resolve-conflict",
    response_model=JiraConflictResolveOut,
    responses=_error_responses(),
)
def resolve_jira_conflict(
    ticket_id: str,
    link_id: str,
    body: JiraConflictResolveReq,
    _ctx: dict[str, str] = Depends(require_ui_session),
    _user: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        result = resolve_link_conflict(
            workspace_id=body.workspace_id,
            ticket_id=ticket_id,
            link_id=link_id,
            action=body.action,
            current_ticket=body.current_ticket,
        )
    except JiraConflictResolutionError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": {"code": exc.code, "message": exc.message}}) from exc
    return JiraConflictResolveOut(
        ticket_id=result["ticket_id"],
        link_id=result["link_id"],
        action=result["action"],
        resolved_fields=list(result.get("resolved_fields") or []),
        sync_state="in_sync",
        follow_up_tasks=len(result.get("follow_up_tasks") or []),
    )


@router.get("/tickets/{ticket_id}/sync-status", response_model=TicketSyncStatusOut, responses=_error_responses())
def ticket_sync_status(
    ticket_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    _user: AuthenticatedUser = Depends(get_authenticated_user),
):
    store = JiraTicketSyncStore()
    links = store.list_links_for_ticket(internal_ticket_id=ticket_id)
    active_links = [row for row in links if row.get("entity_type") == "ticket_external_link" and str(row.get("sync_state") or "") != "deleted"]
    if not active_links:
        return TicketSyncStatusOut(ticket_id=ticket_id, linked=False, provider=None, sync_state="not_linked")
    active = sorted(active_links, key=lambda row: int(row.get("updated_at") or 0), reverse=True)[0]
    mirror = store.get_issue_mirror(external_issue_id=str(active.get("external_issue_id") or ""))
    return TicketSyncStatusOut(
        ticket_id=ticket_id,
        linked=True,
        provider="jira",
        sync_state=str(active.get("sync_state") or "queued"),
        link_id=str(active.get("link_id") or ""),
        external_issue_id=str(active.get("external_issue_id") or ""),
        external_issue_key=str(active.get("external_issue_key") or ""),
        jira_status=(str(mirror.get("status") or "") if mirror else None),
        last_synced_at=int(active.get("last_synced_at") or 0) or None,
        conflict_fields=[str(x) for x in (active.get("conflict_fields") or []) if str(x).strip()],
        conflict_local_values=dict((active.get("conflict_payload") or {}).get("local") or {}),
        conflict_remote_values=dict((active.get("conflict_payload") or {}).get("remote") or {}),
    )


@router.post("/integrations/jira/webhook", response_model=JiraWebhookOut, responses=_error_responses())
def jira_webhook(
    body: JiraWebhookReq,
    request: Request,
    x_jira_event: str = Header(..., alias="X-Jira-Event"),
    x_jira_webhook_identifier: str | None = Header(default=None, alias="X-Webhook-Id"),
    x_jira_signature: str | None = Header(default=None, alias="X-Jira-Signature"),
):
    forwarded_for = str(request.headers.get("X-Forwarded-For", "")).strip()
    remote_ip = (forwarded_for.split(",", 1)[0].strip() if forwarded_for else "") or (request.client.host if request.client else "")
    try:
        result = process_jira_webhook(
            event_type=body.event_type,
            cloud_id=body.cloud_id,
            issue_id=body.issue_id,
            issue_key=body.issue_key,
            payload=body.payload,
            header_event_type=x_jira_event,
            webhook_identifier=x_jira_webhook_identifier,
            signature_header=x_jira_signature,
            remote_ip=remote_ip or None,
        )
    except JiraWebhookAuthError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"error": {"code": _jira_webhook_auth_error_code(exc.message), "message": exc.message}},
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "jira_webhook_invalid", "message": str(exc)}}) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503, detail={"error": {"code": "jira_webhook_dispatch_unavailable", "message": str(exc)}}
        ) from exc
    return JiraWebhookOut(
        accepted=result.accepted,
        enqueued=result.enqueued,
        deduplicated=result.deduplicated,
        trace_id=result.trace_id,
    )
