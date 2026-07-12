"""Dynamic Endpoints router (CSN-004).

Two sub-routers:
  router        — admin definition CRUD (require_root_session, /ui/dynamic-endpoints)
  gateway_router — catch-all gateway (require_ui_session, /custom)

Registered in app/main.py only when S.dynamic_endpoints_enabled is True.

IMPORTANT: /openapi route MUST be declared before /{endpoint_id} in the admin
router to prevent FastAPI capturing the literal "openapi" as a path param.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.auth.deps import require_root_session
from app.core.settings import S
from app.models import DynamicEndpointCreateIn
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/dynamic-endpoints", tags=["dynamic-endpoints-admin"])
gateway_router = APIRouter(prefix="/custom", tags=["dynamic-endpoints-gateway"])


def _require_enabled() -> None:
    if not S.dynamic_endpoints_enabled:
        raise HTTPException(404, "Not found")


# ---------------------------------------------------------------------------
# Admin definition endpoints
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
async def register_endpoint_handler(
    req: Request,
    body: DynamicEndpointCreateIn,
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_endpoints import register_endpoint
    return register_endpoint(
        ctx.sub,
        body.method,
        body.path,
        body.connector_kind,
        body.connector_config,
        openapi_spec=body.openapi_spec,
        req=req,
    )


@router.get("")
async def list_endpoints_handler(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_endpoints import list_endpoints
    return list_endpoints(created_by=ctx.sub, cursor_token=cursor, limit=limit)


# MUST be before /{endpoint_id}
@router.get("/openapi")
async def get_openapi_handler(
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_endpoints import list_endpoints
    result = list_endpoints(limit=200)
    paths: Dict[str, Any] = {}
    for ep in result.get("endpoints", []):
        path = ep.get("path", "")
        method = ep.get("method", "GET").lower()
        spec = ep.get("openapi_spec", {})
        if path not in paths:
            paths[path] = {}
        paths[path][method] = spec
    return {"paths": paths}


@router.get("/{endpoint_id}")
async def get_endpoint_handler(
    endpoint_id: str,
    ctx=Depends(require_root_session),
) -> Dict:
    _require_enabled()
    from app.services.dynamic_endpoints import get_endpoint_by_id
    ep = get_endpoint_by_id(endpoint_id)
    if ep is None:
        raise HTTPException(404, {"code": "endpoint_not_found", "endpoint_id": endpoint_id})
    return ep


@router.delete("/{endpoint_id}", status_code=204, response_model=None)
async def delete_endpoint_handler(
    req: Request,
    endpoint_id: str,
    ctx=Depends(require_root_session),
):
    _require_enabled()
    from app.services.dynamic_endpoints import delete_endpoint
    delete_endpoint(ctx.sub, endpoint_id, req)


# ---------------------------------------------------------------------------
# Gateway catch-all router
# ---------------------------------------------------------------------------

async def _dispatch_gateway(method: str, path: str, req: Request, ctx: dict) -> JSONResponse:
    _require_enabled()
    from app.services.dynamic_endpoints import get_endpoint, invoke_endpoint
    full_path = f"/custom/{path}"
    ep = get_endpoint(method, full_path)
    if ep is None:
        raise HTTPException(404, {"code": "endpoint_not_found", "path": full_path})
    body: Optional[dict] = None
    if method in ("POST", "PUT"):
        try:
            body = await req.json()
        except Exception:
            body = {}
    query_params = dict(req.query_params)
    return invoke_endpoint(
        ep,
        method,
        full_path,
        ctx["user_sub"],
        body,
        query_params,
        req,
    )


@gateway_router.get("/{path:path}")
async def gateway_get(path: str, request: Request, ctx=Depends(require_ui_session)) -> JSONResponse:
    return await _dispatch_gateway("GET", path, request, ctx)


@gateway_router.post("/{path:path}")
async def gateway_post(path: str, request: Request, ctx=Depends(require_ui_session)) -> JSONResponse:
    return await _dispatch_gateway("POST", path, request, ctx)


@gateway_router.put("/{path:path}")
async def gateway_put(path: str, request: Request, ctx=Depends(require_ui_session)) -> JSONResponse:
    return await _dispatch_gateway("PUT", path, request, ctx)


@gateway_router.delete("/{path:path}")
async def gateway_delete(path: str, request: Request, ctx=Depends(require_ui_session)) -> JSONResponse:
    return await _dispatch_gateway("DELETE", path, request, ctx)
