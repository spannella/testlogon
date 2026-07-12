"""VEW-001/002/003 — Account Views router.

Provides REST endpoints for named field-level access delegation over financial
resources (wallet / ledger_account / payout_destination).

Router objects exported:
  router       — authenticated endpoints, prefix /ui/views
  public_router — unauthenticated public-link endpoint, no prefix
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.services import account_views as svc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

router = APIRouter(tags=["account-views"])
public_router = APIRouter(tags=["account-views-public"])


def _require_enabled() -> None:
    svc._require_enabled()


# ---------------------------------------------------------------------------
# Grant catalog (literal path declared first to avoid capture as resource_type)
# ---------------------------------------------------------------------------


@router.get("/ui/views/grant-catalog")
async def get_grant_catalog(
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.get_grant_catalog()


# ---------------------------------------------------------------------------
# VEW-002 — "Shared with me" (literal, must come before dynamic /{resource_type})
# ---------------------------------------------------------------------------


@router.get("/ui/views/shared-with-me")
async def list_views_shared_with_me(
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.list_views_shared_with_me(user.sub, cursor=cursor, limit=limit)


# ---------------------------------------------------------------------------
# VEW-002 — Public-link revoke (authenticated, DELETE /ui/views/public/{token})
# Declared here before /{resource_type} to avoid capture
# ---------------------------------------------------------------------------


@router.delete("/ui/views/public/{token}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_public_link(
    token: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Response:
    _require_enabled()
    svc.revoke_public_link(user.sub, token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# VEW-001 — View CRUD
# ---------------------------------------------------------------------------


@router.post("/ui/views/{resource_type}/{resource_id}", status_code=status.HTTP_201_CREATED)
async def create_view(
    resource_type: str,
    resource_id: str,
    body: "ViewCreateIn",
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    # Ensure owner system view exists first (idempotent)
    try:
        svc.ensure_owner_view(user.sub, resource_type, resource_id)
    except HTTPException:
        raise
    except Exception:
        pass

    grants_dict = body.grants.model_dump() if hasattr(body.grants, "model_dump") else dict(body.grants)
    result = svc.create_view(
        owner_sub=user.sub,
        resource_type=resource_type,
        resource_id=resource_id,
        name=body.name,
        grants=grants_dict,
        preset=body.preset,
        description=body.description or "",
        metadata_visibility=body.metadata_visibility or "",
    )
    return result


@router.get("/ui/views/{resource_type}/{resource_id}")
async def list_views(
    resource_type: str,
    resource_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> List[Dict[str, Any]]:
    _require_enabled()
    # Owner-only
    svc._assert_owns_resource(user.sub, resource_type, resource_id)
    return svc.list_views(resource_type, resource_id)


@router.get("/ui/views/{resource_type}/{resource_id}/{view_id}")
async def get_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    view = svc.get_view(resource_type, resource_id, view_id)
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    # Owner or active grantee (VEW-002 extends this)
    is_owner = svc._is_resource_owner(user.sub, resource_type, resource_id)
    if not is_owner:
        grant = svc.resolve_active_grant(user.sub, resource_type, resource_id, view_id)
        if not grant:
            raise HTTPException(status_code=403, detail="No active view grant")
    return view


@router.patch("/ui/views/{resource_type}/{resource_id}/{view_id}")
async def update_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
    body: "ViewUpdateIn",
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    grants_dict: Optional[Dict[str, bool]] = None
    if body.grants is not None:
        grants_dict = body.grants.model_dump() if hasattr(body.grants, "model_dump") else dict(body.grants)
    return svc.update_view(
        owner_sub=user.sub,
        resource_type=resource_type,
        resource_id=resource_id,
        view_id=view_id,
        name=body.name,
        grants=grants_dict,
        description=body.description,
        metadata_visibility=body.metadata_visibility,
    )


@router.delete("/ui/views/{resource_type}/{resource_id}/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Response:
    _require_enabled()
    svc.delete_view(user.sub, resource_type, resource_id, view_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# VEW-002 — Grant management
# ---------------------------------------------------------------------------


@router.post(
    "/ui/views/{resource_type}/{resource_id}/{view_id}/grants",
    status_code=status.HTTP_201_CREATED,
)
async def grant_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
    body: "ViewGrantIn",
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.grant_view(user.sub, resource_type, resource_id, view_id, body.grantee_sub)


@router.get("/ui/views/{resource_type}/{resource_id}/{view_id}/grants")
async def list_grants_for_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    # Owner-only
    view = svc.get_view(resource_type, resource_id, view_id)
    if not view:
        raise HTTPException(status_code=404, detail="View not found")
    if view.get("owner_sub") != user.sub:
        raise HTTPException(status_code=403, detail="Not the resource owner")
    return svc.list_grants_for_resource(resource_type, resource_id, cursor=cursor, limit=limit)


@router.delete(
    "/ui/views/{resource_type}/{resource_id}/{view_id}/grants/{grantee_sub}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_grant(
    resource_type: str,
    resource_id: str,
    view_id: str,
    grantee_sub: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Response:
    _require_enabled()
    svc.revoke_view_grant(user.sub, resource_type, resource_id, view_id, grantee_sub)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/ui/views/{resource_type}/{resource_id}/{view_id}/grants/{grantee_sub}/respond",
)
async def respond_to_grant(
    resource_type: str,
    resource_id: str,
    view_id: str,
    grantee_sub: str,
    body: "ViewGrantRespondIn",
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Optional[Dict[str, Any]]:
    _require_enabled()
    if user.sub != grantee_sub:
        raise HTTPException(status_code=403, detail="Only the grantee can respond")
    return svc.respond_to_view_grant(user.sub, resource_type, resource_id, view_id, body.accept)


# ---------------------------------------------------------------------------
# VEW-002 — Public-link creation
# ---------------------------------------------------------------------------


@router.post(
    "/ui/views/{resource_type}/{resource_id}/{view_id}/public-link",
    status_code=status.HTTP_201_CREATED,
)
async def create_public_link(
    resource_type: str,
    resource_id: str,
    view_id: str,
    body: "PublicViewLinkIn",
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()
    return svc.create_public_view_link(
        user.sub,
        resource_type,
        resource_id,
        view_id,
        ttl_days=body.ttl_days,
    )


# ---------------------------------------------------------------------------
# VEW-003 — Projected resource read (authenticated)
# ---------------------------------------------------------------------------


@router.get("/ui/views/{resource_type}/{resource_id}/{view_id}/data")
async def read_resource_through_view(
    resource_type: str,
    resource_id: str,
    view_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
) -> Dict[str, Any]:
    _require_enabled()

    is_owner = svc._is_resource_owner(user.sub, resource_type, resource_id)
    if is_owner:
        view_row = svc.ensure_owner_view(user.sub, resource_type, resource_id)
        grants = view_row.get("grants", {k: True for k in svc.VIEW_FIELD_GRANTS})
        effective_view_id = svc._OWNER_VIEW_ID
    else:
        grant_row = svc.resolve_active_grant(user.sub, resource_type, resource_id, view_id)
        if not grant_row:
            raise HTTPException(status_code=403, detail="No active view grant")
        view_row = svc.get_view(resource_type, resource_id, view_id) or {}
        grants = view_row.get("grants", {})
        effective_view_id = view_id

    # Assemble full resource
    try:
        if resource_type == "wallet":
            full_resource = svc._assemble_wallet_resource(resource_id)
        elif resource_type == "ledger_account":
            full_resource = svc._assemble_ledger_resource(resource_id)
        elif resource_type == "payout_destination":
            full_resource = svc._assemble_payout_destination_resource(user.sub, resource_id)
        else:
            raise HTTPException(status_code=400, detail="Unknown resource_type")
    except HTTPException:
        raise

    metadata_visibility = view_row.get("metadata_visibility", "")
    projected = svc.project_resource(full_resource, grants, resource_type, metadata_visibility=metadata_visibility)

    provenance = {
        "view_id": effective_view_id,
        "view_name": view_row.get("name", ""),
        "preset": view_row.get("preset"),
        "granted_fields": [k for k, v in grants.items() if v],
    }

    try:
        from app.services.alerts import audit_event
        audit_event(
            "account_view.read",
            user.sub,
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=effective_view_id,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "data": projected,
        "_view": provenance,
    }


# ---------------------------------------------------------------------------
# VEW-002/003 — Public (unauthenticated) read
# ---------------------------------------------------------------------------


@public_router.get("/ui/views/public/{token}")
async def read_public_view(token: str) -> Dict[str, Any]:
    svc._require_enabled()
    resolved = svc.resolve_public_view(token)

    resource_type = resolved["resource_type"]
    resource_id = resolved["resource_id"]
    view_id = resolved["view_id"]
    grants = resolved["grants"]
    metadata_visibility = resolved.get("metadata_visibility", "")

    try:
        full_resource = svc._assemble_resource(resource_type, resource_id)
    except HTTPException:
        raise

    projected = svc.project_resource(full_resource, grants, resource_type, metadata_visibility=metadata_visibility)

    provenance = {
        "view_id": view_id,
        "view_name": resolved.get("view_name", ""),
        "preset": resolved.get("preset"),
        "granted_fields": [k for k, v in grants.items() if v],
    }

    try:
        from app.services.alerts import audit_event
        audit_event(
            "account_view.public_read",
            "anonymous",
            resource_type=resource_type,
            resource_id=resource_id,
            view_id=view_id,
        )
    except Exception as exc:
        logger.warning("account_views: audit_event failed: %s", exc)

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "data": projected,
        "_view": provenance,
        "expires_at": resolved.get("exp"),
    }


# ---------------------------------------------------------------------------
# Deferred model imports (avoids circular import at module load time)
# ---------------------------------------------------------------------------

# Pydantic models are imported lazily when the router is used.
# We use string annotations above; the actual classes are pulled in here
# at the bottom so FastAPI can resolve them via the module namespace.

from app.models import (  # noqa: E402
    ViewCreateIn,
    ViewUpdateIn,
    ViewGrantIn,
    ViewGrantRespondIn,
    PublicViewLinkIn,
)
