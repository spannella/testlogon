from __future__ import annotations

import base64
import json
import uuid
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Attr, Key
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_assignable_role, require_roles, require_root
from app.auth.roles import AdminProfileType, AdminScope, Role, normalize_admin_profile, normalize_admin_scope, normalize_role
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
    admin_profile_type: str = Field(default=AdminProfileType.GENERAL.value)
    admin_scopes: list[str] = Field(default_factory=list)


class RoleRevokeReq(BaseModel):
    target_user_sub: str = Field(..., min_length=1)
    role: str = Field(default="admin")
    reason: str = Field(default="", max_length=500)


class RoleUpdateProfileReq(BaseModel):
    target_user_sub: str = Field(..., min_length=1)
    admin_profile_type: str = Field(default=AdminProfileType.GENERAL.value)
    admin_scopes: list[str] = Field(default_factory=list)
    reason: str = Field(default="", max_length=500)


def _normalize_admin_profile_type(value: str | None) -> AdminProfileType | None:
    if isinstance(value, str):
        normalized = value.strip().lower()
        for profile_type in AdminProfileType:
            if profile_type.value == normalized:
                return profile_type
    return None


def _validate_admin_profile_input(*, admin_profile_type: str | None, admin_scopes: list[str] | None) -> Dict[str, Any]:
    profile_type = _normalize_admin_profile_type(admin_profile_type)
    if profile_type is None:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_admin_profile_type",
                "allowed_profile_types": sorted([item.value for item in AdminProfileType]),
            },
        )

    raw_scopes = admin_scopes or []
    if profile_type is AdminProfileType.GENERAL:
        if raw_scopes:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "invalid_admin_scopes",
                    "reason": "general_profile_disallows_scopes",
                },
            )
        return {"type": AdminProfileType.GENERAL.value}

    normalized_scopes: list[AdminScope] = []
    seen: set[AdminScope] = set()
    duplicate_scopes: set[str] = set()
    invalid_scopes: set[str] = set()

    for raw_scope in raw_scopes:
        scope = normalize_admin_scope(raw_scope)
        if scope is None:
            invalid_scopes.add(str(raw_scope).strip())
            continue
        if scope in seen:
            duplicate_scopes.add(scope.value)
            continue
        seen.add(scope)
        normalized_scopes.append(scope)

    if invalid_scopes:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_admin_scopes",
                "reason": "unknown_scope_values",
                "invalid_scopes": sorted(s for s in invalid_scopes if s),
                "allowed_scopes": sorted([scope.value for scope in AdminScope]),
            },
        )

    if duplicate_scopes:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_admin_scopes",
                "reason": "duplicate_scope_values",
                "duplicate_scopes": sorted(duplicate_scopes),
            },
        )

    if not normalized_scopes:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "invalid_admin_scopes",
                "reason": "scoped_profile_requires_non_empty_scopes",
            },
        )

    return {"type": AdminProfileType.SCOPED.value, "scopes": sorted([scope.value for scope in normalized_scopes])}


def _load_user_or_404(user_sub: str) -> Dict[str, Any]:
    item = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="target user not found")
    return item




def _normalized_user_admin_profile(user_item: Dict[str, Any]) -> Dict[str, Any]:
    return normalize_admin_profile(user_item.get("admin_profile")).to_dict()


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
    previous_admin_profile: Dict[str, Any] | None,
    new_admin_profile: Dict[str, Any] | None,
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
        "previous_admin_profile": previous_admin_profile,
        "new_admin_profile": new_admin_profile,
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
        admin_profile = _validate_admin_profile_input(admin_profile_type=body.admin_profile_type, admin_scopes=body.admin_scopes)
    except HTTPException as exc:
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="invalid_admin_profile", status_code=exc.status_code)
        raise

    try:
        user = _load_user_or_404(target)
    except HTTPException as exc:
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="target_not_found", status_code=exc.status_code)
        raise

    current = normalize_role(user.get("role"))
    previous_admin_profile = _normalized_user_admin_profile(user)
    if current is Role.ROOT or target == (S.root_user_sub or "").strip():
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="root_immutable", status_code=409)
        raise HTTPException(status_code=409, detail="cannot modify root role through admin grant API")
    if current is Role.ADMIN:
        audit_event("admin_role_grant_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="already_admin", status_code=409)
        raise HTTPException(status_code=409, detail="target user is already admin")

    reason = (body.reason or "").strip()
    T.users.update_item(
        Key={"user_sub": target},
        UpdateExpression="SET #role=:role, admin_profile=:admin_profile, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={
            ":role": Role.ADMIN.value,
            ":admin_profile": admin_profile,
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
        previous_admin_profile=previous_admin_profile,
        new_admin_profile=admin_profile,
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
        admin_profile=admin_profile,
        role_audit_event_id=event["event_id"],
    )
    return {"ok": True, "target_user_sub": target, "role": Role.ADMIN.value, "admin_profile": admin_profile, "event_id": event["event_id"]}


@router.post("/update-profile")
def update_role_profile(
    body: RoleUpdateProfileReq,
    req: Request,
    _ctx: Dict[str, str] = Depends(require_ui_session),
    actor: AuthenticatedUser = Depends(require_root),
):
    require_roles(actor, {Role.ROOT})
    rate_limit_admin_action(actor.sub, "role_update_profile")
    target = body.target_user_sub.strip()

    try:
        admin_profile = _validate_admin_profile_input(admin_profile_type=body.admin_profile_type, admin_scopes=body.admin_scopes)
    except HTTPException as exc:
        audit_event("admin_role_profile_update_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="invalid_admin_profile", status_code=exc.status_code)
        raise

    try:
        user = _load_user_or_404(target)
    except HTTPException as exc:
        audit_event("admin_role_profile_update_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="target_not_found", status_code=exc.status_code)
        raise

    current = normalize_role(user.get("role"))
    previous_admin_profile = _normalized_user_admin_profile(user)
    if current is Role.ROOT or target == (S.root_user_sub or "").strip():
        audit_event("admin_role_profile_update_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="root_immutable", status_code=409)
        raise HTTPException(status_code=409, detail="cannot modify root role through admin profile API")
    if current is not Role.ADMIN:
        audit_event("admin_role_profile_update_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="target_not_admin", status_code=409)
        raise HTTPException(status_code=409, detail="target user is not admin")

    reason = (body.reason or "").strip()
    T.users.update_item(
        Key={"user_sub": target},
        UpdateExpression="SET admin_profile=:admin_profile, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason",
        ExpressionAttributeValues={
            ":admin_profile": admin_profile,
            ":ts": now_ts(),
            ":by": actor.sub,
            ":reason": reason,
        },
    )
    event = _persist_role_assignment_event(
        req=req,
        actor_sub=actor.sub,
        target_user_sub=target,
        action="update_profile",
        previous_role=Role.ADMIN,
        new_role=Role.ADMIN,
        previous_admin_profile=previous_admin_profile,
        new_admin_profile=admin_profile,
        reason=reason,
    )

    audit_event(
        "admin_role_profile_updated",
        actor.sub,
        req,
        outcome="success",
        target_user_sub=target,
        actor_sub=actor.sub,
        role=Role.ADMIN.value,
        reason=reason,
        admin_profile=admin_profile,
        role_audit_event_id=event["event_id"],
    )
    return {"ok": True, "target_user_sub": target, "role": Role.ADMIN.value, "admin_profile": admin_profile, "event_id": event["event_id"]}


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
    previous_admin_profile = _normalized_user_admin_profile(user)
    if current is Role.ROOT or target == (S.root_user_sub or "").strip():
        audit_event("admin_role_revoke_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="root_immutable", status_code=409)
        raise HTTPException(status_code=409, detail="cannot modify root role through admin revoke API")
    if current is Role.USER:
        audit_event("admin_role_revoke_failed", actor.sub, req, outcome="error", target_user_sub=target, reason="not_admin", status_code=409)
        raise HTTPException(status_code=409, detail="target user is not admin")

    reason = (body.reason or "").strip()
    T.users.update_item(
        Key={"user_sub": target},
        UpdateExpression="SET #role=:role, role_updated_at=:ts, role_updated_by=:by, role_reason=:reason REMOVE admin_profile",
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
        previous_admin_profile=previous_admin_profile,
        new_admin_profile=None,
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
            "previous_admin_profile": it.get("previous_admin_profile"),
            "new_admin_profile": it.get("new_admin_profile"),
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
