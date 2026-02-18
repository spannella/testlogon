from __future__ import annotations

import base64
import json
import uuid
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_assignable_role, require_root
from app.auth.roles import Role, normalize_role
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.rate_limit import rate_limit_admin_action
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/admin/roles", tags=["admin-roles"])


class RoleGrantReq(BaseModel):
    target_user_sub: str = Field(..., min_length=1)
    role: str = Field(default="admin")
    reason: str = Field(default="", max_length=500)


class RoleRevokeReq(BaseModel):
    target_user_sub: str = Field(..., min_length=1)
    role: str = Field(default="admin")
    reason: str = Field(default="", max_length=500)


def _load_user_or_404(user_sub: str) -> Dict[str, Any]:
    item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="target user not found")
    return item


def _encode_cursor(last_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_key:
        return None
    payload = json.dumps(last_key, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def _decode_cursor(cursor: Optional[str]) -> Optional[Dict[str, Any]]:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid cursor") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid cursor")
    return data


def _persist_role_assignment_event(
    *,
    req: Request,
    actor_sub: str,
    target_user_sub: str,
    action: str,
    previous_role: Role,
    new_role: Role,
    reason: str,
) -> Dict[str, Any]:
    ts = now_ts()
    event_id = str(uuid.uuid4())
    request_id = (req.headers.get("x-request-id") or req.headers.get("x-amzn-trace-id") or "").strip()
    item = {
        "pk": f"ACTOR#{actor_sub}",
        "sk": f"TS#{ts:013d}#{event_id}",
        "event_id": event_id,
        "event_type": "role_assignment",
        "action": action,
        "actor_sub": actor_sub,
        "target_user_sub": target_user_sub,
        "previous_role": previous_role.value,
        "new_role": new_role.value,
        "reason": reason,
        "ip": client_ip_from_request(req),
        "request_id": request_id,
        "ts": ts,
    }
    T.role_audit.put_item(Item=item, ConditionExpression="attribute_not_exists(event_id)")
    return item


@router.post("/grant")
def grant_role(
    body: RoleGrantReq,
    req: Request,
    _ctx: Dict[str, str] = Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(require_root),
):
    rate_limit_admin_action(actor.sub, "role_grant")
    target = body.target_user_sub.strip()
    desired = require_assignable_role(body.role)
    if desired is not Role.ADMIN:
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="invalid_role_transition", requested_role=desired.value, status_code=400)
        raise HTTPException(status_code=400, detail="only admin role is assignable via this endpoint")

    try:
        user = _load_user_or_404(target)
    except HTTPException as exc:
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="target_not_found", status_code=exc.status_code)
        raise

    current = normalize_role(user.get("role"))
    if current is Role.ROOT or target == (S.root_user_sub or "").strip():
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="root_immutable", status_code=409)
        raise HTTPException(status_code=409, detail="cannot modify root role through admin grant API")
    if current is Role.ADMIN:
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="already_admin", status_code=409)
        raise HTTPException(status_code=409, detail="target user is already admin")

    reason = (body.reason or "").strip()
    T.users.update_item(
        Key={"user_sub": target},
        UpdateExpression="SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={
            ":role": Role.ADMIN.value,
            ":ts": now_ts(),
            ":by": actor.sub,
            ":reason": reason,
        },
    )
    event = _persist_role_assignment_event(
        req=req,
        actor_sub=actor.sub,
        target_user_sub=target,
        action="grant",
        previous_role=current,
        new_role=Role.ADMIN,
        reason=reason,
    )
    audit_event(
        "admin_role_granted",
        actor.sub,
        req,
        outcome="success",
        target_user_sub=target,
        actor_sub=actor.sub,
        role=Role.ADMIN.value,
        previous_role=current.value,
        reason=reason,
        role_audit_event_id=event["event_id"],
    )
    return {"ok": True, "target_user_sub": target, "role": Role.ADMIN.value, "event_id": event["event_id"]}


@router.post("/revoke")
def revoke_role(
    body: RoleRevokeReq,
    req: Request,
    _ctx: Dict[str, str] = Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(require_root),
):
    rate_limit_admin_action(actor.sub, "role_revoke")
    target = body.target_user_sub.strip()
    desired = require_assignable_role(body.role)
    if desired is not Role.ADMIN:
        audit_event("admin_role_revoke_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="invalid_role_transition", requested_role=desired.value, status_code=400)
        raise HTTPException(status_code=400, detail="only admin role is revocable via this endpoint")

    try:
        user = _load_user_or_404(target)
    except HTTPException as exc:
        audit_event("admin_role_revoke_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="target_not_found", status_code=exc.status_code)
        raise

    current = normalize_role(user.get("role"))
    if current is Role.ROOT or target == (S.root_user_sub or "").strip():
        audit_event("admin_role_revoke_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="root_immutable", status_code=409)
        raise HTTPException(status_code=409, detail="cannot modify root role through admin revoke API")
    if current is Role.USER:
        audit_event("admin_role_revoke_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="not_admin", status_code=409)
        raise HTTPException(status_code=409, detail="target user is not admin")

    reason = (body.reason or "").strip()
    T.users.update_item(
        Key={"user_sub": target},
        UpdateExpression="SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={
            ":role": Role.USER.value,
            ":ts": now_ts(),
            ":by": actor.sub,
            ":reason": reason,
        },
    )
    event = _persist_role_assignment_event(
        req=req,
        actor_sub=actor.sub,
        target_user_sub=target,
        action="revoke",
        previous_role=current,
        new_role=Role.USER,
        reason=reason,
    )
    audit_event(
        "admin_role_revoked",
        actor.sub,
        req,
        outcome="success",
        target_user_sub=target,
        actor_sub=actor.sub,
        role=Role.ADMIN.value,
        previous_role=current.value,
        reason=reason,
        role_audit_event_id=event["event_id"],
    )
    return {"ok": True, "target_user_sub": target, "role": Role.USER.value, "event_id": event["event_id"]}


@router.get("/audit")
def list_role_audit(
    actor_sub: Optional[str] = Query(default=None),
    start_ts: int = Query(default=0, ge=0),
    end_ts: Optional[int] = Query(default=None, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    _ctx: Dict[str, str] = Depends(require_ui_session),
    _actor: AuthenticatedUser = Depends(require_root),
):
    capped_limit = max(1, min(limit, 200))
    eks = _decode_cursor(cursor)
    end = int(end_ts or now_ts())
    if start_ts > end:
        raise HTTPException(status_code=400, detail="start_ts must be <= end_ts")

    if actor_sub:
        sk_start = f"TS#{int(start_ts):013d}"
        sk_end = f"TS#{int(end):013d}~"
        query_kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"ACTOR#{actor_sub}") & Key("sk").between(sk_start, sk_end),
            "Limit": capped_limit,
            "ScanIndexForward": False,
        }
        if eks:
            query_kwargs["ExclusiveStartKey"] = eks
        resp = T.role_audit.query(**query_kwargs)
    else:
        scan_kwargs: Dict[str, Any] = {
            "FilterExpression": Attr("ts").between(int(start_ts), int(end)),
            "Limit": capped_limit,
        }
        if eks:
            scan_kwargs["ExclusiveStartKey"] = eks
        resp = T.role_audit.scan(**scan_kwargs)

    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    out = [
        {
            "event_id": it.get("event_id"),
            "action": it.get("action"),
            "actor_sub": it.get("actor_sub"),
            "target_user_sub": it.get("target_user_sub"),
            "previous_role": it.get("previous_role"),
            "new_role": it.get("new_role"),
            "reason": it.get("reason"),
            "ip": it.get("ip"),
            "request_id": it.get("request_id"),
            "ts": it.get("ts"),
        }
        for it in items
    ]
    if not actor_sub:
        out.sort(key=lambda x: int(x.get("ts") or 0), reverse=True)
    return {"items": out, "cursor": _encode_cursor(last_key)}
