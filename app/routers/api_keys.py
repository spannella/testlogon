from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.models import CreateApiKeyReq, RevokeApiKeyReq, ApiKeyIpRulesReq
from app.services.api_keys import create_api_key, list_api_keys, revoke_api_key, set_api_key_ip_rules
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["api-keys"])

@router.get("/api_keys")
async def ui_list_api_keys(ctx=Depends(require_ui_session)):
    return {"keys": list_api_keys(ctx["user_sub"])}

@router.post("/api_keys")
async def ui_create_api_key(req: Request, body: CreateApiKeyReq, ctx=Depends(require_ui_session)):
    created = create_api_key(ctx["user_sub"], body.label or "")
    audit_event("api_key_create", ctx["user_sub"], req, outcome="success", key_id=created["key_id"])
    return created

@router.post("/api_keys/revoke")
async def ui_revoke_api_key(req: Request, body: RevokeApiKeyReq, ctx=Depends(require_ui_session)):
    revoke_api_key(ctx["user_sub"], body.key_id)
    audit_event("api_key_revoke", ctx["user_sub"], req, outcome="success", key_id=body.key_id)
    return {"ok": True}

@router.post("/api_keys/ip_rules")
async def ui_set_api_key_ip_rules(req: Request, body: ApiKeyIpRulesReq, ctx=Depends(require_ui_session)):
    rules = set_api_key_ip_rules(ctx["user_sub"], body.key_id, body.allow_cidrs, body.deny_cidrs)
    audit_event("api_key_ip_rules_set", ctx["user_sub"], req, outcome="success", key_id=body.key_id, allow=len(rules["allow_cidrs"]), deny=len(rules["deny_cidrs"]))
    return {"ok": True, "allow_cidrs": rules["allow_cidrs"], "deny_cidrs": rules["deny_cidrs"]}
