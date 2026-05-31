"""Delegation API router (DELEGATE-005).

Exposes two endpoint groups under the single prefix ``/ui/delegation-api``:

1. Management endpoints (cookie / ``require_ui_session`` auth) for delegates
   to issue/list/revoke their delegation API keys, for creators to view and
   revoke keys scoped to them, and for scope discovery.
2. Programmatic ``/v1/*`` endpoints authenticated by an issued delegation API
   key (``Authorization: Bearer dak_<key_id>.<secret>``). These wrap the
   underlying delegate services and enforce the key's permission scope.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.models import (
    DelegationApiKeyCreateIn,
    DelegationApiKeyOut,
    DelegationApiKeyScopeOut,
    DelegationApiSendMessageIn,
)
from app.services import delegation_api as svc
from app.services import delegate_chat
from app.services.sessions import require_ui_session

delegation_api_router = APIRouter(prefix="/ui/delegation-api", tags=["delegation-api"])


def _client_ip(req: Request) -> str:
    return req.client.host if req.client else ""


# ---------------------------------------------------------------------------
# Management endpoints (cookie session auth)
# ---------------------------------------------------------------------------


@delegation_api_router.post("/keys", response_model=DelegationApiKeyOut)
async def create_key(body: DelegationApiKeyCreateIn, ctx=Depends(require_ui_session)):
    """Issue a delegation-scoped API key (caller must be an active delegate)."""
    created = svc.create_delegation_api_key(
        owner_sub=ctx["user_sub"],
        label=body.label,
        creator_id=body.creator_id,
        permissions=body.permissions,
        expires_in_days=body.expires_in_days,
    )
    return DelegationApiKeyOut(**created)


@delegation_api_router.get("/keys", response_model=List[DelegationApiKeyOut])
async def list_my_keys(ctx=Depends(require_ui_session)):
    """List the caller's own delegation API keys."""
    return [DelegationApiKeyOut(**k) for k in svc.list_keys_for_owner(ctx["user_sub"])]


@delegation_api_router.delete("/keys/{key_id}")
async def revoke_my_key(key_id: str, ctx=Depends(require_ui_session)):
    """Owner revokes one of their delegation API keys."""
    svc.revoke_key_by_owner(owner_sub=ctx["user_sub"], key_id=key_id)
    return {"ok": True}


@delegation_api_router.get("/keys/{key_id}/scope", response_model=DelegationApiKeyScopeOut)
async def get_key_scope(key_id: str, ctx=Depends(require_ui_session)):
    """Scope discovery: available actions for a key (owner or creator only)."""
    return DelegationApiKeyScopeOut(**svc.get_key_scope(key_id, requester_sub=ctx["user_sub"]))


@delegation_api_router.get("/creator-keys", response_model=List[DelegationApiKeyOut])
async def list_creator_keys(ctx=Depends(require_ui_session)):
    """Creator view: all delegation API keys scoped to the caller's account."""
    return [DelegationApiKeyOut(**k) for k in svc.list_keys_for_creator(ctx["user_sub"])]


@delegation_api_router.delete("/creator-keys/{key_id}")
async def creator_revoke_key(key_id: str, ctx=Depends(require_ui_session)):
    """Creator revokes a delegation API key scoped to them."""
    svc.revoke_key_by_creator(creator_id=ctx["user_sub"], key_id=key_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Programmatic endpoints (delegation API key auth)
# ---------------------------------------------------------------------------


def _authenticate(req: Request, required_permission: str) -> dict:
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    api_key = auth[7:].strip()
    return svc.authenticate_key(
        api_key=api_key,
        client_ip=_client_ip(req),
        required_permission=required_permission,
    )


def _apply_rate_headers(response: Response, key_item: dict) -> None:
    key_id = key_item.get("key_id", "")
    rpm = int(key_item.get("rate_limit_rpm") or svc._default_rate_limit_rpm())
    for k, v in svc.rate_limit_headers(key_id, rpm).items():
        response.headers[k] = v


@delegation_api_router.get("/v1/scope", response_model=DelegationApiKeyScopeOut)
async def api_scope(req: Request, response: Response):
    """Return the authenticated key's scope and available actions."""
    key_item = _authenticate(req, required_permission=_first_permission(req))
    _apply_rate_headers(response, key_item)
    return DelegationApiKeyScopeOut(**svc._scope_view(key_item))


def _first_permission(req: Request) -> str:
    """Resolve a permission the key holds for the scope endpoint.

    The scope endpoint should work for ANY valid key, so we authenticate
    against whatever first permission the key declares. We peek the key
    without consuming a rate-limit slot is not possible cheaply, so we
    require ``chat_read`` only as a placeholder default and fall back.
    """
    # The scope endpoint is permission-agnostic; authenticate_key requires a
    # concrete permission, so resolve it from the key itself first.
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    parsed = svc._parse_delegation_key(auth[7:].strip())
    item = svc.get_key_item(parsed["key_id"])
    perms = item.get("permissions", []) if item else []
    if not perms:
        raise HTTPException(401, "Invalid delegation API key")
    return perms[0]


@delegation_api_router.get("/v1/conversations")
async def api_list_conversations(req: Request, response: Response):
    """List the bound creator's conversations (requires chat_read)."""
    key_item = _authenticate(req, required_permission="chat_read")
    _apply_rate_headers(response, key_item)
    convos = delegate_chat.list_creator_conversations(
        creator_id=key_item["creator_id"],
        delegate_id=key_item["owner_sub"],
    )
    return {"conversations": convos}


@delegation_api_router.get("/v1/conversations/{conversation_id}/messages")
async def api_list_messages(conversation_id: str, req: Request, response: Response):
    """List messages in a creator conversation (requires chat_read)."""
    key_item = _authenticate(req, required_permission="chat_read")
    _apply_rate_headers(response, key_item)
    msgs = delegate_chat.get_creator_conversation_messages(
        creator_id=key_item["creator_id"],
        delegate_id=key_item["owner_sub"],
        conversation_id=conversation_id,
    )
    return {"messages": msgs}


@delegation_api_router.post("/v1/conversations/{conversation_id}/messages")
async def api_send_message(
    conversation_id: str,
    body: DelegationApiSendMessageIn,
    req: Request,
    response: Response,
):
    """Send a message as the creator (requires chat_respond)."""
    key_item = _authenticate(req, required_permission="chat_respond")
    _apply_rate_headers(response, key_item)
    result = delegate_chat.send_message_as_creator(
        creator_id=key_item["creator_id"],
        delegate_id=key_item["owner_sub"],
        conversation_id=conversation_id,
        text=body.text,
        reply_to_message_id=body.reply_to_message_id,
    )
    return result
