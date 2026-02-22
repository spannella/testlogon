from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.tables import T
from app.metrics import record_project_count_delta, record_tracked_file_count_delta
from app.models import ProjectEventModel, ProjectModel, TrackedFileModel
from app.services.file_providers import ProviderRegistry, default_provider_registry


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _project_sk(project_id: str) -> str:
    return f"PROJECT#{project_id}"


def _tracked_file_sk(tracked_file_id: str) -> str:
    return f"TRACKED_FILE#{tracked_file_id}"


def _event_sk(created_at: str, event_id: str) -> str:
    return f"EVENT#{created_at}#{event_id}"


def _tracked_file_unique_key(provider: str, provider_ref: str) -> str:
    return f"{provider.lower()}#{provider_ref.strip()}"


def project_to_item(project: ProjectModel) -> Dict[str, Any]:
    return {
        "PK": _project_pk(project.owner),
        "SK": _project_sk(project.id),
        "entity_type": "project",
        "id": project.id,
        "owner": project.owner,
        "name": project.name,
        "description": project.description,
        "tags": project.tags,
        "settings": project.settings,
        "created_at": project.created_at,
        "updated_at": project.updated_at,
        "GSI1PK": f"PROJECT#{project.id}",
        "GSI1SK": f"OWNER#{project.owner}",
    }


def project_from_item(item: Dict[str, Any]) -> ProjectModel:
    return ProjectModel(
        id=item["id"],
        owner=item["owner"],
        name=item["name"],
        description=item.get("description"),
        tags=item.get("tags") or [],
        settings=item.get("settings") or {},
        created_at=item["created_at"],
        updated_at=item["updated_at"],
    )


def _coerce_project(*, project_id: str, owner: str, name: str, description: Optional[str], tags: Optional[List[str]], settings: Optional[Dict[str, Any]], created_at: str, updated_at: str) -> ProjectModel:
    try:
        return ProjectModel(
            id=project_id,
            owner=owner,
            name=name,
            description=description,
            tags=tags or [],
            settings=settings or {},
            created_at=created_at,
            updated_at=updated_at,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail="invalid project payload") from exc


def create_project(
    owner: str,
    name: str,
    description: Optional[str] = None,
    *,
    tags: Optional[List[str]] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> ProjectModel:
    ts = now_iso()
    project = _coerce_project(
        project_id=str(uuid4()),
        owner=owner,
        name=name,
        description=description,
        tags=tags,
        settings=settings,
        created_at=ts,
        updated_at=ts,
    )
    T.projects.put_item(
        Item=project_to_item(project),
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )
    record_project_count_delta(1)
    return project


def get_project(owner: str, project_id: str) -> ProjectModel:
    if not owner or not project_id:
        raise HTTPException(status_code=400, detail="owner and project_id are required")
    resp = T.projects.get_item(Key={"PK": _project_pk(owner), "SK": _project_sk(project_id)}, ConsistentRead=True)
    item = resp.get("Item")
    if not item or item.get("entity_type") != "project":
        raise HTTPException(status_code=404, detail="project not found")
    return project_from_item(item)


def list_projects(
    owner: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
    tag: Optional[str] = None,
    name_query: Optional[str] = None,
) -> Dict[str, Any]:
    if not owner:
        raise HTTPException(status_code=400, detail="owner is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")
    if cursor is not None and not isinstance(cursor, dict):
        raise HTTPException(status_code=400, detail="invalid cursor")

    normalized_tag = (tag or "").strip().lower() or None
    normalized_query = (name_query or "").strip().lower() or None

    items: List[ProjectModel] = []
    last_key = cursor
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(_project_pk(owner)) & Key("SK").begins_with("PROJECT#"),
            "Limit": max(limit, 25),
            "ScanIndexForward": False,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.projects.query(**kwargs)

        for raw in resp.get("Items", []):
            if raw.get("entity_type") != "project":
                continue
            project = project_from_item(raw)
            if normalized_tag and normalized_tag not in project.tags:
                continue
            if normalized_query and normalized_query not in project.name.lower():
                continue
            items.append(project)
            if len(items) >= limit:
                break

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    return {
        "items": items,
        "cursor": last_key,
    }


def update_project(
    owner: str,
    project_id: str,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> ProjectModel:
    existing = get_project(owner, project_id)

    merged = _coerce_project(
        project_id=existing.id,
        owner=existing.owner,
        name=existing.name if name is None else name,
        description=existing.description if description is None else description,
        tags=existing.tags if tags is None else tags,
        settings=existing.settings if settings is None else settings,
        created_at=existing.created_at,
        updated_at=now_iso(),
    )

    T.projects.put_item(
        Item=project_to_item(merged),
        ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
    )
    return merged


def delete_project(owner: str, project_id: str) -> Dict[str, bool]:
    try:
        T.projects.delete_item(
            Key={"PK": _project_pk(owner), "SK": _project_sk(project_id)},
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=404, detail="project not found") from exc
        raise
    record_project_count_delta(-1)
    return {"ok": True}


def tracked_file_to_item(tracked: TrackedFileModel) -> Dict[str, Any]:
    unique_key = _tracked_file_unique_key(tracked.provider, tracked.provider_ref)
    return {
        "PK": f"PROJECT#{tracked.project_id}",
        "SK": _tracked_file_sk(tracked.id),
        "entity_type": "tracked_file",
        "id": tracked.id,
        "project_id": tracked.project_id,
        "owner": tracked.owner,
        "provider": tracked.provider,
        "provider_ref": tracked.provider_ref,
        "provider_ref_key": unique_key,
        "display_path": tracked.display_path,
        "status": tracked.status,
        "metadata": tracked.metadata,
        "created_at": tracked.created_at,
        "updated_at": tracked.updated_at,
        "last_seen_at": tracked.last_seen_at,
        "archived_at": tracked.archived_at,
        "GSI1PK": f"PROJECT#{tracked.project_id}",
        "GSI1SK": f"PROVIDER_REF#{unique_key}",
        "GSI2PK": f"OWNER#{tracked.owner}",
        "GSI2SK": f"PROJECT#{tracked.project_id}#TRACKED_FILE#{tracked.id}",
    }


def project_event_to_item(event: ProjectEventModel) -> Dict[str, Any]:
    return {
        "PK": f"PROJECT#{event.project_id}",
        "SK": _event_sk(event.created_at, event.id),
        "entity_type": "project_event",
        "id": event.id,
        "project_id": event.project_id,
        "owner": event.owner,
        "event_type": event.event_type,
        "tracked_file_id": event.tracked_file_id,
        "provider": event.provider,
        "provider_ref": event.provider_ref,
        "message": event.message,
        "metadata": event.metadata,
        "created_at": event.created_at,
        "GSI2PK": f"OWNER#{event.owner}",
        "GSI2SK": f"PROJECT#{event.project_id}#EVENT#{event.created_at}#{event.id}",
    }


def project_event_from_item(item: Dict[str, Any]) -> ProjectEventModel:
    return ProjectEventModel(
        id=item["id"],
        project_id=item["project_id"],
        owner=item["owner"],
        event_type=item["event_type"],
        tracked_file_id=item.get("tracked_file_id"),
        provider=item.get("provider"),
        provider_ref=item.get("provider_ref"),
        message=item.get("message"),
        metadata=item.get("metadata") or {},
        created_at=item["created_at"],
    )


def emit_project_event(
    owner: str,
    project_id: str,
    event_type: str,
    *,
    tracked_file_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_ref: Optional[str] = None,
    message: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> ProjectEventModel:
    event = ProjectEventModel(
        id=str(uuid4()),
        project_id=project_id,
        owner=owner,
        event_type=event_type,
        tracked_file_id=tracked_file_id,
        provider=provider,
        provider_ref=provider_ref,
        message=message,
        metadata=metadata or {},
        created_at=now_iso(),
    )
    T.projects.put_item(Item=project_event_to_item(event))
    return event


def tracked_file_from_item(item: Dict[str, Any]) -> TrackedFileModel:
    return TrackedFileModel(
        id=item["id"],
        project_id=item["project_id"],
        owner=item["owner"],
        provider=item["provider"],
        provider_ref=item["provider_ref"],
        display_path=item["display_path"],
        status=item.get("status", "active"),
        metadata=item.get("metadata") or {},
        created_at=item["created_at"],
        updated_at=item["updated_at"],
        last_seen_at=item.get("last_seen_at"),
        archived_at=item.get("archived_at"),
    )


def put_tracked_file(
    tracked_file: TrackedFileModel,
    *,
    registry: Optional[ProviderRegistry] = None,
) -> TrackedFileModel:
    provider_registry = registry or default_provider_registry()
    provider = provider_registry.get(tracked_file.owner, tracked_file.provider)

    canonical_ref = provider.resolve(tracked_file.provider_ref)
    if not provider.exists(canonical_ref):
        raise HTTPException(status_code=404, detail="tracked file target not found")

    metadata = provider.get_metadata(canonical_ref)
    display_path = (tracked_file.display_path or "").strip() or canonical_ref
    tracked = tracked_file.model_copy(
        update={
            "provider": tracked_file.provider.lower(),
            "provider_ref": canonical_ref,
            "display_path": display_path,
            "metadata": {**metadata, **(tracked_file.metadata or {})},
            "updated_at": tracked_file.updated_at or now_iso(),
            "last_seen_at": tracked_file.last_seen_at or now_iso(),
        }
    )

    existing = T.projects.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"PROJECT#{tracked.project_id}")
        & Key("GSI1SK").eq(f"PROVIDER_REF#{_tracked_file_unique_key(tracked.provider, tracked.provider_ref)}"),
        Limit=1,
    )
    if existing.get("Items"):
        raise HTTPException(status_code=409, detail="tracked file already exists for provider_ref")

    try:
        T.projects.put_item(
            Item=tracked_file_to_item(tracked),
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="tracked file id already exists") from exc
        raise
    return tracked


def add_tracked_file(
    owner: str,
    project_id: str,
    *,
    provider: str,
    provider_ref: str,
    display_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    registry: Optional[ProviderRegistry] = None,
) -> TrackedFileModel:
    # Authorization/project scope check
    get_project(owner, project_id)

    ts = now_iso()
    tracked = TrackedFileModel(
        id=str(uuid4()),
        project_id=project_id,
        owner=owner,
        provider=provider,
        provider_ref=provider_ref,
        display_path=(display_path or provider_ref or "").strip(),
        status="active",
        metadata=metadata or {},
        created_at=ts,
        updated_at=ts,
        last_seen_at=ts,
    )
    stored = put_tracked_file(tracked, registry=registry)
    record_tracked_file_count_delta(1)
    emit_project_event(
        owner,
        project_id,
        "file_added",
        tracked_file_id=stored.id,
        provider=stored.provider,
        provider_ref=stored.provider_ref,
        metadata={"display_path": stored.display_path},
    )
    return stored


def list_tracked_files(
    owner: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
    status: Optional[str] = None,
    provider: Optional[str] = None,
) -> Dict[str, Any]:
    get_project(owner, project_id)

    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")
    if cursor is not None and not isinstance(cursor, dict):
        raise HTTPException(status_code=400, detail="invalid cursor")

    normalized_provider = (provider or "").strip().lower() or None
    normalized_status = (status or "").strip().lower() or None

    items: List[TrackedFileModel] = []
    last_key = cursor
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(f"PROJECT#{project_id}") & Key("SK").begins_with("TRACKED_FILE#"),
            "Limit": max(limit, 25),
            "ScanIndexForward": False,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.projects.query(**kwargs)

        for raw in resp.get("Items", []):
            if raw.get("entity_type") != "tracked_file":
                continue
            if raw.get("owner") != owner:
                continue
            tracked = tracked_file_from_item(raw)
            if normalized_provider and tracked.provider.lower() != normalized_provider:
                continue
            if normalized_status and (tracked.status or "").lower() != normalized_status:
                continue
            items.append(tracked)
            if len(items) >= limit:
                break

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    return {"items": items, "cursor": last_key}


def remove_tracked_file(owner: str, project_id: str, tracked_file_id: str) -> Dict[str, bool]:
    # authorization/project scope check
    get_project(owner, project_id)

    key = {"PK": f"PROJECT#{project_id}", "SK": _tracked_file_sk(tracked_file_id)}
    resp = T.projects.get_item(Key=key, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        return {"ok": True, "deleted": False}
    if item.get("entity_type") != "tracked_file" or item.get("owner") != owner:
        raise HTTPException(status_code=404, detail="tracked file not found")

    model = tracked_file_from_item(item)
    if model.status == "archived":
        return {"ok": True, "deleted": False}

    archived = model.model_copy(update={"status": "archived", "updated_at": now_iso(), "archived_at": now_iso()})
    T.projects.put_item(Item=tracked_file_to_item(archived))
    record_tracked_file_count_delta(-1)
    emit_project_event(
        owner,
        project_id,
        "file_removed",
        tracked_file_id=archived.id,
        provider=archived.provider,
        provider_ref=archived.provider_ref,
        metadata={"display_path": archived.display_path},
    )
    return {"ok": True, "deleted": True}


def list_project_events(
    owner: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    get_project(owner, project_id)

    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")
    if cursor is not None and not isinstance(cursor, dict):
        raise HTTPException(status_code=400, detail="invalid cursor")

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("PK").eq(f"PROJECT#{project_id}") & Key("SK").begins_with("EVENT#"),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor

    resp = T.projects.query(**kwargs)
    items: List[ProjectEventModel] = []
    for raw in resp.get("Items", []):
        if raw.get("entity_type") != "project_event":
            continue
        if raw.get("owner") != owner:
            continue
        items.append(project_event_from_item(raw))
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}


def get_project_detail(
    owner: str,
    project_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
    status: Optional[str] = None,
    provider: Optional[str] = None,
    registry: Optional[ProviderRegistry] = None,
) -> Dict[str, Any]:
    project = get_project(owner, project_id)
    tracked_page = list_tracked_files(
        owner,
        project_id,
        limit=limit,
        cursor=cursor,
        status=status,
        provider=provider,
    )

    provider_registry = registry or default_provider_registry()
    rows: List[Dict[str, Any]] = []
    for tracked in tracked_page["items"]:
        provider_client = provider_registry.get(owner, tracked.provider)
        canonical_ref = provider_client.resolve(tracked.provider_ref)

        row_status = tracked.status
        hydrated_meta = dict(tracked.metadata or {})
        try:
            exists = provider_client.exists(canonical_ref)
            if exists:
                fresh_meta = provider_client.get_metadata(canonical_ref)
                hydrated_meta = {**hydrated_meta, **fresh_meta}
                row_status = "active" if tracked.status != "archived" else "archived"
            elif tracked.status != "archived":
                row_status = "missing"
        except HTTPException as exc:
            if exc.status_code == 404 and tracked.status != "archived":
                row_status = "missing"
            else:
                raise

        rows.append(
            {
                "id": tracked.id,
                "project_id": tracked.project_id,
                "provider": tracked.provider,
                "provider_ref": canonical_ref,
                "display_path": (tracked.display_path or canonical_ref),
                "status": row_status,
                "last_seen_at": tracked.last_seen_at,
                "updated_at": tracked.updated_at,
                "metadata": hydrated_meta,
            }
        )

    return {
        "project": project,
        "files": rows,
        "cursor": tracked_page.get("cursor"),
    }


def archive_tracked_file(project_id: str, tracked_file_id: str) -> TrackedFileModel:
    key = {"PK": f"PROJECT#{project_id}", "SK": _tracked_file_sk(tracked_file_id)}
    resp = T.projects.get_item(Key=key, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="tracked file not found")

    model = tracked_file_from_item(item)
    model = model.model_copy(update={"status": "archived", "updated_at": now_iso(), "archived_at": now_iso()})
    T.projects.put_item(Item=tracked_file_to_item(model))
    return model
