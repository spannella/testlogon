"""CRM Studio router.

STU-011: Custom field CRUD endpoints under /ui/admin/studio/fields/{entity_type}.

Registered in app/main.py inside `if _S.crm_studio_enabled:` block.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import enforce_cookie_csrf, require_admin_or_root, require_root
from app.auth.roles import Role, normalize_role
from app.models import (
    StudioFieldCreateIn,
    StudioFieldListOut,
    StudioFieldOut,
    StudioFieldUpdateIn,
)
import app.services.crm_studio_fields as fields_svc
from app.services.crm_studio_fields import (
    ALLOWED_ENTITY_TYPES,
    FieldAlreadyExistsError,
    FieldNotFoundError,
)

router = APIRouter(prefix="/ui/admin/studio", tags=["studio"])


def _item_to_out(item: dict) -> StudioFieldOut:
    return StudioFieldOut(
        entity_type=item.get("entity_type", ""),
        field_key=item.get("field_key", ""),
        label=item.get("label", ""),
        field_type=item.get("field_type", "text"),
        required=bool(item.get("required", False)),
        default_value=item.get("default_value"),
        picklist_name=item.get("picklist_name"),
        max_length=int(item.get("max_length", 1000)),
        min_value=float(item["min_value"]) if item.get("min_value") is not None else None,
        max_value=float(item["max_value"]) if item.get("max_value") is not None else None,
        sort_order=int(item.get("sort_order", 0)),
        is_active=bool(item.get("is_active", True)),
        created_by_sub=item.get("created_by_sub", ""),
        created_at=int(item.get("created_at", 0)),
        updated_by_sub=item.get("updated_by_sub", ""),
        updated_at=int(item.get("updated_at", 0)),
    )


@router.get("/fields/{entity_type}", response_model=StudioFieldListOut)
async def list_entity_fields(
    entity_type: str,
    include_inactive: bool = Query(False),
    cursor: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> StudioFieldListOut:
    if entity_type not in ALLOWED_ENTITY_TYPES:
        raise HTTPException(400, {"code": "invalid_entity_type", "entity_type": entity_type})
    # include_inactive requires ROOT
    if include_inactive and normalize_role(user.role) != Role.ROOT:
        raise HTTPException(403, {"code": "root_required_for_include_inactive"})

    items, next_cursor = fields_svc.list_fields(
        entity_type,
        include_inactive=include_inactive,
        limit=limit,
        cursor=cursor,
    )
    return StudioFieldListOut(
        fields=[_item_to_out(i) for i in items],
        next_cursor=next_cursor,
        total_count=len(items) if include_inactive and not cursor else None,
    )


@router.post("/fields/{entity_type}", response_model=StudioFieldOut, status_code=201)
async def create_entity_field(
    entity_type: str,
    request: Request,
    body: StudioFieldCreateIn,
    user: AuthenticatedUser = Depends(require_root),
) -> StudioFieldOut:
    enforce_cookie_csrf(request)
    if entity_type not in ALLOWED_ENTITY_TYPES:
        raise HTTPException(400, {"code": "invalid_entity_type", "entity_type": entity_type})
    try:
        item = fields_svc.create_field(
            user.sub,
            entity_type,
            body.field_key,
            body.label,
            body.field_type,
            required=body.required,
            default_value=body.default_value,
            picklist_name=body.picklist_name,
            max_length=body.max_length,
            min_value=body.min_value,
            max_value=body.max_value,
            sort_order=body.sort_order,
        )
    except FieldAlreadyExistsError:
        raise HTTPException(409, {"code": "field_already_exists", "field_key": body.field_key})
    except ValueError as e:
        raise HTTPException(400, {"code": str(e)})
    return _item_to_out(item)


@router.get("/fields/{entity_type}/{field_key}", response_model=StudioFieldOut)
async def get_entity_field(
    entity_type: str,
    field_key: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> StudioFieldOut:
    item = fields_svc.get_field(entity_type, field_key)
    if not item:
        raise HTTPException(404, {"code": "field_not_found", "entity_type": entity_type, "field_key": field_key})
    return _item_to_out(item)


@router.patch("/fields/{entity_type}/{field_key}", response_model=StudioFieldOut)
async def update_entity_field(
    entity_type: str,
    field_key: str,
    request: Request,
    body: StudioFieldUpdateIn,
    user: AuthenticatedUser = Depends(require_root),
) -> StudioFieldOut:
    enforce_cookie_csrf(request)
    try:
        item = fields_svc.update_field(
            user.sub,
            entity_type,
            field_key,
            label=body.label,
            required=body.required,
            default_value=body.default_value,
            max_length=body.max_length,
            min_value=body.min_value,
            max_value=body.max_value,
            sort_order=body.sort_order,
            reactivate=body.reactivate,
        )
    except FieldNotFoundError:
        raise HTTPException(404, {"code": "field_not_found", "entity_type": entity_type, "field_key": field_key})
    return _item_to_out(item)


@router.delete("/fields/{entity_type}/{field_key}", status_code=204)
async def deactivate_entity_field(
    entity_type: str,
    field_key: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
) -> None:
    enforce_cookie_csrf(request)
    try:
        fields_svc.delete_field(user.sub, entity_type, field_key)
    except FieldNotFoundError:
        raise HTTPException(404, {"code": "field_not_found", "entity_type": entity_type, "field_key": field_key})
