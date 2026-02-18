from __future__ import annotations

import base64
import json
import uuid
from typing import Any, Dict

import jwt
from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.rate_limit import rate_limit_admin_action
from app.services.sessions import require_ui_session
from app.services.ttl import with_ttl

router = APIRouter(prefix="/admin/impersonation", tags=["admin-impersonation"])



def _encode_cursor(cursor: Dict[str, Any] | None) -> str | None:
    if not cursor:
        return None
    return base64.urlsafe_b64encode(json.dumps(cursor, separators=(",", ":")).encode("utf-8")).decode("utf-8")


def _decode_cursor(cursor: str | None) -> Dict[str, Any]:
    if not cursor:
        return {}
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc


def _load_user_or_404(user_sub: str) -> Dict[str, Any]:
    item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="target user not found")
    return item


def _forbidden_impersonation() -> HTTPException:
    return HTTPException(status_code=403, detail="impersonation_not_allowed")


def _compute_impersonation_ttl(body: Dict[str, Any]) -> int:
    requested = int((body or {}).get("duration_seconds") or 0)
    base = requested if requested > 0 else int(S.impersonation_ttl_seconds)
    hard_cap = max(60, int(S.impersonation_max_ttl_seconds))
    return max(60, min(base, hard_cap))


@router.post("/start")
def start_impersonation(
    req: Request,
    body: Dict[str, Any] = Body(default={}),
    _ctx: Dict[str, str] = Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    rate_limit_admin_action(actor.sub, "impersonation_start")
    target_user_sub = str((body or {}).get("target_user_sub") or "").strip()
    reason = str((body or {}).get("reason") or "").strip()
    ticket_id = str((body or {}).get("ticket_id") or "").strip()
    if not target_user_sub:
        raise HTTPException(status_code=400, detail="target_user_sub is required")

    user = _load_user_or_404(target_user_sub)
    target_role = normalize_role(user.get("role"))

    emergency_enabled = bool(S.impersonation_allow_privileged_targets)
    is_root_actor = normalize_role(actor.role) is Role.ROOT
    if target_role in {Role.ADMIN, Role.ROOT} and not (is_root_actor and emergency_enabled):
        raise _forbidden_impersonation()

    if target_role is not Role.USER and not (is_root_actor and emergency_enabled):
        raise _forbidden_impersonation()

    ts = now_ts()
    ttl = _compute_impersonation_ttl(body)
    expires_at = ts + ttl
    impersonation_id = f"imp_{uuid.uuid4().hex}"

    item = {
        "user_sub": actor.sub,
        "session_id": impersonation_id,
        "purpose": "impersonation",
        "actor_sub": actor.sub,
        "effective_sub": target_user_sub,
        "impersonation": True,
        "reason": reason,
        "ticket_id": ticket_id,
        "created_at": ts,
        "expires_at": expires_at,
        "revoked": False,
    }
    T.sessions.put_item(Item=with_ttl(item, ttl_epoch=expires_at))

    token_payload = {
        "sub": actor.sub,
        "sid": impersonation_id,
        "impersonation": True,
        "actor_sub": actor.sub,
        "effective_sub": target_user_sub,
        "auth_level": "impersonation",
        "iat": ts,
        "exp": expires_at,
    }
    token = jwt.encode(token_payload, S.ui_access_token_secret, algorithm="HS256") if S.ui_access_token_secret else ""

    audit_event(
        "admin_impersonation_start",
        actor.sub,
        req,
        outcome="success",
        actor_sub=actor.sub,
        target_user_sub=target_user_sub,
        target_role=target_role.value,
        impersonation_id=impersonation_id,
        reason=reason,
        ticket_id=ticket_id,
        expires_at=expires_at,
        ttl_seconds=ttl,
    )
    return {
        "ok": True,
        "impersonation_id": impersonation_id,
        "actor_sub": actor.sub,
        "effective_sub": target_user_sub,
        "token": token,
        "expires_at": expires_at,
        "ttl_seconds": ttl,
        "reason": reason,
        "ticket_id": ticket_id,
    }


@router.post("/stop")
def stop_impersonation(
    req: Request,
    body: Dict[str, Any] = Body(default={}),
    _ctx: Dict[str, str] = Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    rate_limit_admin_action(actor.sub, "impersonation_stop")
    impersonation_id = str((body or {}).get("impersonation_id") or "").strip()
    if not impersonation_id:
        raise HTTPException(status_code=400, detail="impersonation_id is required")

    item = T.sessions.get_item(Key={"user_sub": actor.sub, "session_id": impersonation_id}).get("Item")
    if not item or item.get("purpose") != "impersonation":
        raise HTTPException(status_code=404, detail="impersonation session not found")

    if int(item.get("expires_at") or 0) <= now_ts():
        raise HTTPException(status_code=401, detail="impersonation_expired")

    if item.get("revoked"):
        return {"ok": True, "impersonation_id": impersonation_id, "already_stopped": True}

    T.sessions.update_item(
        Key={"user_sub": actor.sub, "session_id": impersonation_id},
        UpdateExpression="SET revoked=:t, revoked_at=:ts",
        ExpressionAttributeValues={":t": True, ":ts": now_ts()},
    )

    audit_event(
        "admin_impersonation_stop",
        actor.sub,
        req,
        outcome="success",
        actor_sub=actor.sub,
        effective_sub=item.get("effective_sub", ""),
        impersonation_id=impersonation_id,
    )
    return {"ok": True, "impersonation_id": impersonation_id, "stopped": True}


@router.get("/audit")
def impersonation_audit(
    actor_sub: str | None = Query(default=None),
    start_ts: int = Query(default=0, ge=0),
    end_ts: int | None = Query(default=None, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    _ctx: Dict[str, str] = Depends(require_ui_session),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
):
    end = int(end_ts or now_ts())
    if start_ts > end:
        raise HTTPException(status_code=400, detail="start_ts must be <= end_ts")

    c = _decode_cursor(cursor)
    offset = int(c.get("offset", 0) or 0)
    capped = max(1, min(limit, 200))

    items: list[Dict[str, Any]] = []
    if actor_sub:
        r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(actor_sub), Limit=500)
        candidates = r.get("Items", [])
    else:
        r = T.sessions.scan(Limit=500)
        candidates = r.get("Items", [])

    for it in candidates:
        if it.get("purpose") != "impersonation":
            continue
        ts = int(it.get("created_at") or 0)
        if ts < int(start_ts) or ts > int(end):
            continue
        items.append({
            "impersonation_id": it.get("session_id"),
            "actor_sub": it.get("actor_sub") or it.get("user_sub"),
            "effective_sub": it.get("effective_sub"),
            "reason": it.get("reason"),
            "ticket_id": it.get("ticket_id"),
            "created_at": it.get("created_at"),
            "expires_at": it.get("expires_at"),
            "revoked": bool(it.get("revoked")),
            "revoked_at": it.get("revoked_at"),
        })

    items.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    page = items[offset: offset + capped]
    next_cursor = _encode_cursor({"offset": offset + capped}) if (offset + capped) < len(items) else None
    return {"items": page, "cursor": next_cursor}
