"""Dynamic Entities router (CSN-003).

Two sub-routers:
  def_router  — admin definition CRUD (require_root_session)
  crud_router — generated CRUD per entity_name (require_ui_session)

Registered in app/main.py only when S.dynamic_entities_enabled is True.
"""
from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.auth.deps import require_root_session
from app.core.settings import S
from app.models import (
    DynamicEntityDefOut,
    DynamicEntityListDefsOut,
    DynamicEntityListRowsOut,
    DynamicEntityRegisterIn,
    DynamicEntityRowIn,
    DynamicEntityRowOut,
)
from app.services.sessions import require_ui_session

# Admin definition router
def_router = APIRouter(prefix="/ui/dynamic-entities", tags=["dynamic-entities-admin"])
# Generated CRUD router
crud_router = APIRouter(prefix="/ui/dynamic", tags=["dynamic-entities-crud"])


def _require_enabled() -> None:
    if not S.dynamic_entities_enabled:
        raise HTTPException(404, "Not found")


# ---------------------------------------------------------------------------
# Admin definition endpoints
# ---------------------------------------------------------------------------

@def_router.post("", status_code=201)
async def register_entity_endpoint(
    req: Request,
    body: DynamicEntityRegisterIn,
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import register_entity
    return register_entity(
        ctx.sub,
        body.entity_name,
        body.json_schema,
        req,
        description=body.description,
        expected_version=body.expected_version,
    )


@def_router.get("")
async def list_entity_defs_endpoint(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import list_entity_defs
    return list_entity_defs(admin_sub=ctx.sub, cursor=cursor, limit=limit)


@def_router.get("/{entity_name}")
async def get_entity_def_endpoint(
    entity_name: str,
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import get_entity_def
    defn = get_entity_def(entity_name)
    if defn is None:
        raise HTTPException(404, {"code": "entity_not_found", "entity_name": entity_name})
    return defn


@def_router.delete("/{entity_name}", status_code=204, response_model=None)
async def delete_entity_endpoint(
    req: Request,
    entity_name: str,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    from app.services.dynamic_entities import delete_entity
    delete_entity(ctx.sub, entity_name, req)


# ---------------------------------------------------------------------------
# Generated CRUD endpoints (require_ui_session)
# ---------------------------------------------------------------------------

@crud_router.post("/{entity_name}", status_code=201)
async def create_row_endpoint(
    entity_name: str,
    body: DynamicEntityRowIn,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import create_row
    return create_row(entity_name, ctx["user_sub"], body.data)


@crud_router.get("/{entity_name}")
async def list_rows_endpoint(
    entity_name: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import list_rows
    return list_rows(entity_name, owner_sub=ctx["user_sub"], cursor=cursor, limit=limit)


@crud_router.get("/{entity_name}/{row_id}")
async def get_row_endpoint(
    entity_name: str,
    row_id: str,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import get_row
    row = get_row(entity_name, row_id, ctx["user_sub"])
    if row is None:
        raise HTTPException(404, "not found")
    return row


@crud_router.put("/{entity_name}/{row_id}")
async def update_row_endpoint(
    entity_name: str,
    row_id: str,
    body: DynamicEntityRowIn,
    ctx=Depends(require_ui_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_entities import update_row
    return update_row(entity_name, row_id, ctx["user_sub"], body.data)


@crud_router.delete("/{entity_name}/{row_id}", status_code=204, response_model=None)
async def delete_row_endpoint(
    entity_name: str,
    row_id: str,
    ctx=Depends(require_ui_session),
):
    _require_enabled()
    from app.services.dynamic_entities import delete_row
    delete_row(entity_name, row_id, ctx["user_sub"])
