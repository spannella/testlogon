from __future__ import annotations

import os
from fastapi import HTTPException

from app.core.time import now_ts
from app.core.settings import S
from app.core.tables import T
from app.services.ttl import with_ttl

def rate_limit_or_429(user_sub: str, factor: str) -> None:
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
    return True
