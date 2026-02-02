from __future__ import annotations

import os
from fastapi import HTTPException

from app.core.time import now_ts
from app.core.settings import S
from app.core.tables import T
from app.services.ttl import with_ttl


def _sessions_table_enabled() -> bool:
    return bool(getattr(S, "ddb_sessions_table", ""))

def rate_limit_or_429(user_sub: str, factor: str) -> None:
    if not _sessions_table_enabled():
        return
    now = now_ts()
    earliest = now - S.mfa_send_min_interval_seconds
    bucket = now // 3600
    key = {"user_sub": user_sub, "session_id": f"rl#{factor}"}

    # New bucket -> reset to 1
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="SET bucket=:b, count=:one, last_sent_at=:now, updated_at=:now",
            ConditionExpression="attribute_not_exists(bucket) OR bucket <> :b",
            ExpressionAttributeValues={":b": bucket, ":one": 1, ":now": now},
        )
        return
    except Exception:
        pass

    # Same bucket -> increment with min interval + max/hour
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="ADD count :one SET last_sent_at=:now, updated_at=:now",
            ConditionExpression="bucket = :b AND count < :limit AND (attribute_not_exists(last_sent_at) OR last_sent_at <= :earliest)",
            ExpressionAttributeValues={
                ":b": bucket,
                ":one": 1,
                ":now": now,
                ":limit": S.mfa_send_max_per_hour,
                ":earliest": earliest,
            },
        )
        return
    except Exception:
        raise HTTPException(429, "Too many verification sends; try again shortly")

def _bucket_limit(user_sub: str, sid: str, max_n: int, win: int) -> bool:
    if not _sessions_table_enabled():
        return True
    now = now_ts()
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item") or {}
    start = int(it.get("bucket_start", 0))
    count = int(it.get("bucket_count", 0))
    if start == 0 or (now - start) >= win:
        start = now
        count = 0
    if count >= max_n:
        return False
    try:
        T.sessions.put_item(Item=with_ttl(
            {"user_sub": user_sub, "session_id": sid, "bucket_start": start, "bucket_count": count + 1},
            ttl_epoch=now + win + 3600
        ))
    except Exception:
        pass
    return True

def _ip_user(ip: str) -> str:
    return f"ip#{ip}" if ip else "ip#unknown"

def rate_limit_login_attempt(user_sub: str, ip: str) -> None:
    if not _bucket_limit(user_sub, "rl#login", S.login_attempt_max_per_window, S.login_attempt_window_seconds):
        raise HTTPException(429, "Too many login attempts; try again later")
    if not _bucket_limit(_ip_user(ip), "rl#login", S.login_attempt_max_per_window, S.login_attempt_window_seconds):
        raise HTTPException(429, "Too many login attempts; try again later")

def rate_limit_mfa_verify(user_sub: str, ip: str, factor: str) -> None:
    sid = f"rl#mfa_verify#{factor}"
    if not _bucket_limit(user_sub, sid, S.mfa_verify_max_per_window, S.mfa_verify_window_seconds):
        raise HTTPException(429, "Too many verification attempts; try again later")
    if not _bucket_limit(_ip_user(ip), sid, S.mfa_verify_max_per_window, S.mfa_verify_window_seconds):
        raise HTTPException(429, "Too many verification attempts; try again later")

def rate_limit_password_recovery(user_sub: str, ip: str, action: str) -> None:
    sid = f"rl#password_recovery#{action}"
    if not _bucket_limit(user_sub, sid, S.login_attempt_max_per_window, S.login_attempt_window_seconds):
        raise HTTPException(429, "Too many recovery attempts; try again later")
    if not _bucket_limit(_ip_user(ip), sid, S.login_attempt_max_per_window, S.login_attempt_window_seconds):
        raise HTTPException(429, "Too many recovery attempts; try again later")

def _lockout_key(user_sub: str, action: str) -> str:
    return f"lockout#{action}"

def enforce_lockout(user_sub: str, ip: str, action: str) -> None:
    if not _sessions_table_enabled():
        return
    now = now_ts()
    for target in (user_sub, _ip_user(ip)):
        sid = _lockout_key(target, action)
        it = T.sessions.get_item(Key={"user_sub": target, "session_id": sid}).get("Item") or {}
        lockout_until = int(it.get("lockout_until", 0) or 0)
        if lockout_until and lockout_until > now:
            raise HTTPException(429, "Account temporarily locked; try again later")

def record_lockout_failure(user_sub: str, ip: str, action: str) -> None:
    if not _sessions_table_enabled():
        return
    for target in (user_sub, _ip_user(ip)):
        _record_lockout_failure_target(target, action)

def clear_lockout(user_sub: str, ip: str, action: str) -> None:
    if not _sessions_table_enabled():
        return
    for target in (user_sub, _ip_user(ip)):
        sid = _lockout_key(target, action)
        try:
            T.sessions.delete_item(Key={"user_sub": target, "session_id": sid})
        except Exception:
            pass

def _record_lockout_failure_target(user_sub: str, action: str) -> None:
    if not _sessions_table_enabled():
        return
    now = now_ts()
    sid = _lockout_key(user_sub, action)
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item") or {}
    window_start = int(it.get("window_start", 0) or 0)
    count = int(it.get("count", 0) or 0)
    lockout_until = int(it.get("lockout_until", 0) or 0)
    lockout_level = int(it.get("lockout_level", 0) or 0)

    if lockout_until and lockout_until > now:
        return

    if window_start == 0 or (now - window_start) >= S.lockout_window_seconds:
        window_start = now
        count = 0

    count += 1
    if count >= S.lockout_max_attempts:
        lockout_level += 1
        duration = min(S.lockout_base_seconds * lockout_level, S.lockout_max_seconds)
        lockout_until = now + duration
        count = 0
        window_start = now

    ttl = now + max(S.lockout_window_seconds, S.lockout_max_seconds) + 3600
    item = {
        "user_sub": user_sub,
        "session_id": sid,
        "window_start": window_start,
        "count": count,
        "lockout_until": lockout_until,
        "lockout_level": lockout_level,
    }
    try:
        T.sessions.put_item(Item=with_ttl(item, ttl_epoch=ttl))
    except Exception:
        pass

def can_send_verification(user_sub: str, channel: str) -> bool:
    if channel == "email":
        return _bucket_limit(user_sub, "rl#verify_email", S.verify_email_max_per_window, S.verify_email_window_seconds)
    if channel == "sms":
        return _bucket_limit(user_sub, "rl#verify_sms", S.verify_sms_max_per_window, S.verify_sms_window_seconds)
    return True

def can_send_alert_channel(user_sub: str, channel: str) -> bool:
    if channel == "email":
        return _bucket_limit(user_sub, "rl#alert_email", S.alerts_email_max_per_window, S.alerts_email_window_seconds)
    if channel == "sms":
        return _bucket_limit(user_sub, "rl#alert_sms", S.alerts_sms_max_per_window, S.alerts_sms_window_seconds)
    if channel == "push":
        max_n = int(os.environ.get("ALERTS_PUSH_MAX_PER_WINDOW", "20"))
        win = int(os.environ.get("ALERTS_PUSH_WINDOW_SECONDS", "3600"))
        return _bucket_limit(user_sub, "rl#alert_push", max_n, win)
    if channel == "webhook":
        return _bucket_limit(
            user_sub,
            "rl#alert_webhook",
            S.alerts_webhook_max_per_window,
            S.alerts_webhook_window_seconds,
        )
    return True
