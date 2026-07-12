"""OAU-001 + OAU-005: Consumer-app registry REST endpoints.

All endpoints: /ui/oauth/consumers (prefix). Registered in main.py when
S.open_bank_project_enabled AND S.oauth_provider_enabled.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.services.alerts import audit_event
from app.services.oauth_consumers import (
    create_consumer,
    delete_consumer,
    get_consumer,
    list_consumers,
    rotate_client_secret,
    set_consumer_enabled,
    update_consumer,
)
from app.services.sessions import require_fresh_mfa, require_ui_session

router = APIRouter(prefix="/ui/oauth/consumers", tags=["oauth-consumers"])


@router.get("")
async def list_my_consumers(ctx=Depends(require_ui_session)):
    """List all OAuth consumer apps registered by the authenticated user."""
    return list_consumers(ctx["user_sub"])


@router.post("")
async def create_my_consumer(req: Request, body: dict, ctx=Depends(require_ui_session)):
    """Register a new OAuth consumer app. Returns one-time client_secret."""
    require_fresh_mfa(ctx)
    result = create_consumer(
        ctx["user_sub"],
        name=body.get("name", ""),
        description=body.get("description", ""),
        redirect_uris=body.get("redirect_uris", []),
        allowed_scopes=body.get("allowed_scopes", []),
        is_confidential=body.get("is_confidential", True),
    )
    audit_event("oauth_consumer_create", ctx["user_sub"], req, outcome="success", client_id=result["client_id"])
    return result


@router.get("/{client_id}")
async def get_my_consumer(client_id: str, ctx=Depends(require_ui_session)):
    """Get a consumer app by client_id. Returns 404 if not owned by caller."""
    from fastapi import HTTPException
    item = get_consumer(client_id)
    if not item or item.get("owner_sub") != ctx["user_sub"]:
        raise HTTPException(404, "Consumer not found")
    # Strip hash before returning
    return {k: v for k, v in item.items() if k != "client_secret_hash"}


@router.patch("/{client_id}")
async def update_my_consumer(client_id: str, req: Request, body: dict, ctx=Depends(require_ui_session)):
    """Update name/description/redirect_uris/allowed_scopes of a consumer."""
    require_fresh_mfa(ctx)
    result = update_consumer(
        ctx["user_sub"],
        client_id,
        name=body.get("name"),
        description=body.get("description"),
        redirect_uris=body.get("redirect_uris"),
        allowed_scopes=body.get("allowed_scopes"),
    )
    audit_event("oauth_consumer_update", ctx["user_sub"], req, outcome="success", client_id=client_id)
    return result


@router.delete("/{client_id}")
async def delete_my_consumer(client_id: str, req: Request, ctx=Depends(require_ui_session)):
    """Delete a consumer app. Irreversible."""
    require_fresh_mfa(ctx)
    delete_consumer(ctx["user_sub"], client_id)
    audit_event("oauth_consumer_delete", ctx["user_sub"], req, outcome="success", client_id=client_id)
    return {"ok": True}


@router.post("/{client_id}/enable")
async def enable_my_consumer(client_id: str, req: Request, ctx=Depends(require_ui_session)):
    """Re-enable a previously disabled consumer app."""
    require_fresh_mfa(ctx)
    result = set_consumer_enabled(ctx["user_sub"], client_id, enabled=True)
    audit_event("oauth_consumer_enable", ctx["user_sub"], req, outcome="success", client_id=client_id)
    return result


@router.post("/{client_id}/disable")
async def disable_my_consumer(client_id: str, req: Request, ctx=Depends(require_ui_session)):
    """Disable a consumer app (all existing tokens immediately rejected)."""
    require_fresh_mfa(ctx)
    result = set_consumer_enabled(ctx["user_sub"], client_id, enabled=False)
    audit_event("oauth_consumer_disable", ctx["user_sub"], req, outcome="success", client_id=client_id)
    return result


@router.post("/{client_id}/rotate-secret")
async def rotate_my_consumer_secret(client_id: str, req: Request, ctx=Depends(require_ui_session)):
    """Rotate the client_secret. Returns new plaintext once; old secret immediately invalid."""
    require_fresh_mfa(ctx)
    result = rotate_client_secret(ctx["user_sub"], client_id)
    audit_event("oauth_consumer_secret_rotate", ctx["user_sub"], req, outcome="success", client_id=client_id)
    return result
