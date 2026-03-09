from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.alerts import audit_event

from app.services.projects_store import (
    add_tracked_file,
    create_project,
    delete_project,
    get_project,
    get_project_detail,
    list_projects,
    list_project_events,
    list_tracked_files,
    remove_tracked_file,
    update_project,
)
from app.services.provider_credentials import (
    delete_provider_credential,
    get_provider_credential,
    upsert_provider_credential,
)
from app.services.provider_oauth import build_google_oauth_start, complete_google_oauth_callback
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/projects", tags=["projects"])


class ProjectCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    tags: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)


class ProjectUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    tags: Optional[List[str]] = None
    settings: Optional[Dict[str, Any]] = None


class ProjectOut(BaseModel):
    id: str
    owner: str
    name: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ProjectListOut(BaseModel):
    items: List[ProjectOut] = Field(default_factory=list)
    cursor: Optional[str] = None


class DeleteProjectOut(BaseModel):
    ok: bool


class TrackedFileCreateIn(BaseModel):
    provider: str = Field(default="local", min_length=1, max_length=32)
    provider_ref: str = Field(..., min_length=1, max_length=2048)
    display_path: Optional[str] = Field(default=None, max_length=2048)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TrackedFileOut(BaseModel):
    id: str
    project_id: str
    owner: str
    provider: str
    provider_ref: str
    display_path: str
    status: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    last_seen_at: Optional[str] = None
    archived_at: Optional[str] = None


class TrackedFileListOut(BaseModel):
    items: List[TrackedFileOut] = Field(default_factory=list)
    cursor: Optional[str] = None


class DeleteTrackedFileOut(BaseModel):
    ok: bool
    deleted: bool


class ProjectDetailOut(BaseModel):
    project: ProjectOut
    files: List[TrackedFileOut] = Field(default_factory=list)
    cursor: Optional[str] = None


class ProjectEventOut(BaseModel):
    id: str
    project_id: str
    owner: str
    event_type: str
    tracked_file_id: Optional[str] = None
    provider: Optional[str] = None
    provider_ref: Optional[str] = None
    message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ProjectEventListOut(BaseModel):
    items: List[ProjectEventOut] = Field(default_factory=list)
    cursor: Optional[str] = None


class ProviderCredentialUpsertIn(BaseModel):
    token: str = Field(..., min_length=1, max_length=8192)
    org: Optional[str] = Field(default=None, max_length=256)
    api_base_url: Optional[str] = Field(default=None, max_length=2048)
    required_scopes: List[str] = Field(default_factory=list)


class ProviderCredentialOut(BaseModel):
    provider: str
    org: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class DeleteProviderCredentialOut(BaseModel):
    ok: bool
    deleted: bool


class ProviderOAuthStartOut(BaseModel):
    provider: str
    authorization_url: str
    state: str
    expires_at: str


class ProviderOAuthCallbackIn(BaseModel):
    code: str = Field(..., min_length=1, max_length=8192)
    state: str = Field(..., min_length=1, max_length=8192)


def _current_user(ctx=Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


def _encode_cursor(cursor: Optional[Dict[str, Any]]) -> Optional[str]:
    if not cursor:
        return None
    payload = json.dumps(cursor).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def _decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    try:
        payload = base64.urlsafe_b64decode(cursor.encode("utf-8"))
        value = json.loads(payload.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="invalid cursor")
    return value


@router.post("", response_model=ProjectOut)
def create_project_route(body: ProjectCreateIn, user: str = Depends(_current_user)):
    project = create_project(
        user,
        body.name,
        description=body.description,
        tags=body.tags,
        settings=body.settings,
    )
    return ProjectOut(**project.model_dump())


@router.get("/{project_id}", response_model=ProjectOut)
def get_project_route(project_id: str, user: str = Depends(_current_user)):
    project = get_project(user, project_id)
    return ProjectOut(**project.model_dump())


@router.get("", response_model=ProjectListOut)
def list_projects_route(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    name_query: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
):
    payload = _decode_cursor(cursor)
    result = list_projects(user, limit=limit, cursor=payload, tag=tag, name_query=name_query)
    items = [ProjectOut(**item.model_dump()) for item in result["items"]]
    return ProjectListOut(items=items, cursor=_encode_cursor(result.get("cursor")))


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project_route(project_id: str, body: ProjectUpdateIn, user: str = Depends(_current_user)):
    project = update_project(
        user,
        project_id,
        name=body.name,
        description=body.description,
        tags=body.tags,
        settings=body.settings,
    )
    return ProjectOut(**project.model_dump())


@router.delete("/{project_id}", response_model=DeleteProjectOut)
def delete_project_route(project_id: str, user: str = Depends(_current_user)):
    result = delete_project(user, project_id)
    return DeleteProjectOut(**result)


@router.post("/{project_id}/files", response_model=TrackedFileOut)
def add_tracked_file_route(project_id: str, body: TrackedFileCreateIn, user: str = Depends(_current_user)):
    tracked = add_tracked_file(
        user,
        project_id,
        provider=body.provider,
        provider_ref=body.provider_ref,
        display_path=body.display_path,
        metadata=body.metadata,
    )
    return TrackedFileOut(**tracked.model_dump())


@router.get("/{project_id}/files", response_model=TrackedFileListOut)
def list_tracked_files_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
):
    payload = _decode_cursor(cursor)
    result = list_tracked_files(user, project_id, limit=limit, cursor=payload, status=status, provider=provider)
    items = [TrackedFileOut(**item.model_dump()) for item in result["items"]]
    return TrackedFileListOut(items=items, cursor=_encode_cursor(result.get("cursor")))


@router.delete("/{project_id}/files/{tracked_file_id}", response_model=DeleteTrackedFileOut)
def remove_tracked_file_route(project_id: str, tracked_file_id: str, user: str = Depends(_current_user)):
    result = remove_tracked_file(user, project_id, tracked_file_id)
    return DeleteTrackedFileOut(**result)


@router.get("/{project_id}/detail", response_model=ProjectDetailOut)
def get_project_detail_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
):
    payload = _decode_cursor(cursor)
    result = get_project_detail(
        user,
        project_id,
        limit=limit,
        cursor=payload,
        status=status,
        provider=provider,
    )
    project = ProjectOut(**result["project"].model_dump())
    files = [TrackedFileOut(**item) for item in result["files"]]
    return ProjectDetailOut(project=project, files=files, cursor=_encode_cursor(result.get("cursor")))


@router.get("/{project_id}/events", response_model=ProjectEventListOut)
def list_project_events_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
):
    payload = _decode_cursor(cursor)
    result = list_project_events(user, project_id, limit=limit, cursor=payload)
    items = [ProjectEventOut(**item.model_dump()) for item in result["items"]]
    return ProjectEventListOut(items=items, cursor=_encode_cursor(result.get("cursor")))


@router.put("/providers/{provider}/credentials", response_model=ProviderCredentialOut)
def upsert_provider_credential_route(provider: str, body: ProviderCredentialUpsertIn, user: str = Depends(_current_user)):
    out = upsert_provider_credential(
        user,
        provider,
        body.token,
        org=body.org,
        required_scopes=body.required_scopes,
        api_base_url=body.api_base_url,
    )
    return ProviderCredentialOut(
        provider=out.provider,
        org=out.org,
        scopes=out.scopes,
        metadata=out.metadata,
        created_at=out.created_at,
        updated_at=out.updated_at,
    )


@router.get("/providers/{provider}/credentials", response_model=ProviderCredentialOut)
def get_provider_credential_route(provider: str, org: Optional[str] = Query(default=None), user: str = Depends(_current_user)):
    out = get_provider_credential(user, provider, org=org)
    return ProviderCredentialOut(
        provider=out.provider,
        org=out.org,
        scopes=out.scopes,
        metadata=out.metadata,
        created_at=out.created_at,
        updated_at=out.updated_at,
    )


@router.delete("/providers/{provider}/credentials", response_model=DeleteProviderCredentialOut)
def delete_provider_credential_route(provider: str, org: Optional[str] = Query(default=None), user: str = Depends(_current_user)):
    result = delete_provider_credential(user, provider, org=org)
    audit_event(
        "provider_oauth_disconnect",
        user,
        None,
        outcome="success",
        provider=(provider or "").strip().lower(),
        deleted=bool(result.get("deleted")),
    )
    return DeleteProviderCredentialOut(**result)


@router.post("/providers/google_drive/oauth/start", response_model=ProviderOAuthStartOut)
def start_google_drive_oauth_route(user: str = Depends(_current_user)):
    return ProviderOAuthStartOut(**build_google_oauth_start(user))


@router.post("/providers/google_drive/oauth/callback", response_model=ProviderCredentialOut)
def complete_google_drive_oauth_callback_route(body: ProviderOAuthCallbackIn, user: str = Depends(_current_user)):
    return ProviderCredentialOut(**complete_google_oauth_callback(user, code=body.code, state=body.state))
