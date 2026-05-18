from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.services.ttl import with_ttl


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso8601(raw: str) -> datetime:
    txt = str(raw or "").strip()
    if not txt:
        raise ValueError("missing datetime")
    # Support UTC "Z" suffix while remaining compatible with fromisoformat.
    if txt.endswith("Z"):
        txt = f"{txt[:-1]}+00:00"
    dt = datetime.fromisoformat(txt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def create_onboarding_session(*, user_sub: str, mount_id: str, provider: str, next_action: str = "verify") -> Dict[str, Any]:
    session_id = f"filemgr_mount_onboard#{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=1)
    item = {
        "user_sub": user_sub,
        "session_id": session_id,
        "entity_type": "filemgr_mount_onboarding",
        "provider": provider,
        "mount_id": mount_id,
        "next_action": next_action,
        "status": "pending",
        "created_at": _now_iso(),
        "expires_at": expires_at.isoformat(),
    }
    try:
        T.sessions.put_item(Item=with_ttl(item, int(expires_at.timestamp())))
    except Exception:
        # Session persistence best-effort in local/dev environments.
        pass
    return {
        "onboarding_session_id": session_id,
        "mount_id": mount_id,
        "status": "pending",
        "next_action": next_action,
        "expires_at": expires_at.isoformat(),
    }


def get_onboarding_session(*, user_sub: str, onboarding_session_id: str) -> Dict[str, Any]:
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": onboarding_session_id}, ConsistentRead=True).get("Item") or {}
    if not it or str(it.get("entity_type") or "") != "filemgr_mount_onboarding":
        raise HTTPException(status_code=404, detail="onboarding session not found")
    expires_at_raw = str(it.get("expires_at") or "")
    if expires_at_raw:
        try:
            if _parse_iso8601(expires_at_raw) <= datetime.now(timezone.utc):
                raise HTTPException(status_code=410, detail="onboarding session expired")
        except HTTPException:
            raise
        except Exception:
            # Invalid persisted expiry data should be treated as invalid session.
            raise HTTPException(status_code=400, detail="onboarding session has invalid expiry metadata")
    return it


def update_onboarding_session(*, user_sub: str, onboarding_session_id: str, status: str, next_action: str, attempts_inc: int = 0) -> Dict[str, Any]:
    now = _now_iso()
    key = {"user_sub": user_sub, "session_id": onboarding_session_id}
    T.sessions.update_item(
        Key=key,
        UpdateExpression="SET #status=:s, #next=:n, updated_at=:u ADD verify_attempts :inc",
        ExpressionAttributeNames={"#status": "status", "#next": "next_action"},
        ExpressionAttributeValues={":s": status, ":n": next_action, ":u": now, ":inc": int(attempts_inc)},
    )
    return get_onboarding_session(user_sub=user_sub, onboarding_session_id=onboarding_session_id)


def clear_onboarding_sessions_for_mount(*, user_sub: str, mount_id: str) -> int:
    """Delete onboarding sessions for a mount to prevent further verify attempts after revoke."""
    deleted = 0
    cursor: Dict[str, Any] | None = None
    try:
        while True:
            query_kwargs: Dict[str, Any] = {"KeyConditionExpression": Key("user_sub").eq(user_sub), "Limit": 200}
            if cursor:
                query_kwargs["ExclusiveStartKey"] = cursor
            resp = T.sessions.query(**query_kwargs)
            for it in resp.get("Items", []):
                if str(it.get("entity_type") or "") != "filemgr_mount_onboarding":
                    continue
                if str(it.get("mount_id") or "") != str(mount_id):
                    continue
                sid = str(it.get("session_id") or "")
                if not sid:
                    continue
                try:
                    T.sessions.delete_item(Key={"user_sub": user_sub, "session_id": sid})
                    deleted += 1
                except Exception:
                    pass
            cursor = resp.get("LastEvaluatedKey")
            if not cursor:
                break
    except Exception:
        return 0
    return deleted
