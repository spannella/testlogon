from __future__ import annotations

import os
from typing import Optional
from fastapi import HTTPException

from app.core.time import now_ts
from app.core.crypto import sha256_str
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

    # 'bucket' and 'count' are DynamoDB reserved keywords; escape them.
    names = {"#bkt": "bucket", "#cnt": "count"}

    # New bucket -> reset to 1
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="SET #bkt=:b, #cnt=:one, last_sent_at=:now, updated_at=:now",
            ConditionExpression="attribute_not_exists(#bkt) OR #bkt <> :b",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":b": bucket, ":one": 1, ":now": now},
        )
        return
    except Exception:
        pass

    # Same bucket -> increment with min interval + max/hour
    try:
        T.sessions.update_item(
            Key=key,
            UpdateExpression="ADD #cnt :one SET last_sent_at=:now, updated_at=:now",
            ConditionExpression="#bkt = :b AND #cnt < :limit AND (attribute_not_exists(last_sent_at) OR last_sent_at <= :earliest)",
            ExpressionAttributeNames=names,
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

def _ip_prefix(ip: str) -> str:
    if not ip:
        return ""
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:4])
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else ip

def _anom_window_reset(item: Dict[str, Any], window_seconds: int) -> Dict[str, Any]:
    now = now_ts()
    window_start = int(item.get("window_start", 0))
    if not window_start or (now - window_start) >= window_seconds:
        return {"window_start": now, "set": set()}
    return {"window_start": window_start, "set": set(item.get("set", []) or [])}

def record_login_anomaly(user_sub: str, ip: str) -> Dict[str, Any]:
    ip_prefix = _ip_prefix(ip)
    if not _sessions_table_enabled():
        return {
            "ip_prefix": ip_prefix,
            "user_ip_count": 0,
            "ip_user_count": 0,
            "user_threshold_exceeded": False,
            "ip_threshold_exceeded": False,
        }
    now = now_ts()
    window = getattr(S, "login_anomaly_window_seconds", 0)
    user_key = {"user_sub": user_sub, "session_id": "anom#login_ips"}
    ip_key = {"user_sub": _ip_user(ip_prefix), "session_id": "anom#login_targets"}

    user_item = T.sessions.get_item(Key=user_key).get("Item") or {}
    ip_item = T.sessions.get_item(Key=ip_key).get("Item") or {}

    user_state = _anom_window_reset({"window_start": user_item.get("window_start", 0), "set": user_item.get("ip_prefixes", [])}, window)
    ip_state = _anom_window_reset({"window_start": ip_item.get("window_start", 0), "set": ip_item.get("target_hashes", [])}, window)

    if ip_prefix:
        user_state["set"].add(ip_prefix)
    ip_state["set"].add(sha256_str(user_sub))

    ttl = now + window + 3600
    try:
        T.sessions.put_item(Item=with_ttl(
            {
                "user_sub": user_sub,
                "session_id": "anom#login_ips",
                "window_start": user_state["window_start"],
                "ip_prefixes": list(user_state["set"]),
                "last_seen_at": now,
            },
            ttl_epoch=ttl,
        ))
    except Exception:
        pass
    try:
        T.sessions.put_item(Item=with_ttl(
            {
                "user_sub": _ip_user(ip_prefix),
                "session_id": "anom#login_targets",
                "window_start": ip_state["window_start"],
                "target_hashes": list(ip_state["set"]),
                "last_seen_at": now,
            },
            ttl_epoch=ttl,
        ))
    except Exception:
        pass

    user_ip_count = len(user_state["set"])
    ip_user_count = len(ip_state["set"])
    return {
        "ip_prefix": ip_prefix,
        "user_ip_count": user_ip_count,
        "ip_user_count": ip_user_count,
        "user_threshold_exceeded": user_ip_count >= getattr(S, "login_anomaly_ip_prefix_threshold", 0),
        "ip_threshold_exceeded": ip_user_count >= getattr(S, "login_anomaly_user_threshold", 0),
    }

def rate_limit_login_attempt(user_sub: str, ip: str) -> None:
    if not _bucket_limit(user_sub, "rl#login", S.login_attempt_max_per_window, S.login_attempt_window_seconds):
        raise HTTPException(429, "Too many login attempts; try again later")
    if not _bucket_limit(_ip_user(ip), "rl#login", S.login_attempt_max_per_window, S.login_attempt_window_seconds):
        raise HTTPException(429, "Too many login attempts; try again later")


def rate_limit_admin_action(actor_sub: str, action: str) -> None:
    sid = f"rl#admin#{action}"
    if not _bucket_limit(actor_sub, sid, S.admin_action_max_per_window, S.admin_action_window_seconds):
        raise HTTPException(429, "Too many privileged actions; try again later")

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


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        return max(1, int(raw))
    except Exception:
        return max(1, int(default))


def rate_limit_profile_lookup(requester_user_sub: Optional[str], ip: str) -> None:
    window_seconds = _env_int("PROFILE_LOOKUP_RATE_LIMIT_WINDOW_SECONDS", 60)
    auth_max = _env_int("PROFILE_LOOKUP_RATE_LIMIT_AUTH_MAX", 120)
    anon_max = _env_int("PROFILE_LOOKUP_RATE_LIMIT_ANON_MAX", 30)

    if requester_user_sub:
        if not _bucket_limit(requester_user_sub, "rl#profile_lookup#auth", auth_max, window_seconds):
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "profile_lookup_rate_limited",
                    "tier": "authenticated",
                    "retry_after_seconds": window_seconds,
                },
                headers={"Retry-After": str(window_seconds)},
            )
        return

    if not _bucket_limit(_ip_user(ip), "rl#profile_lookup#anon", anon_max, window_seconds):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "profile_lookup_rate_limited",
                "tier": "anonymous",
                "retry_after_seconds": window_seconds,
            },
            headers={"Retry-After": str(window_seconds)},
        )

def rate_limit_feed_query(user_sub: str, mode: str) -> None:
    cap = max(1, int(getattr(S, "newsfeed_feed_query_max_per_window", 180) or 180))
    window = max(1, int(getattr(S, "newsfeed_feed_query_window_seconds", 60) or 60))
    sid = f"rl#feed_query#{(mode or 'unknown').lower()}"
    if not _bucket_limit(user_sub, sid, cap, window):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "feed_rate_limited",
                "message": "Too many feed queries; try again later",
                "mode": (mode or "unknown").lower(),
                "limit": cap,
                "window_seconds": window,
            },
            headers={"Retry-After": str(window)},
        )

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


def rate_limit_share_link_download(link_id: str, ip: str) -> None:
    """Enforce IP-based rate limits on the public share-link download endpoint.

    Two independent limits (both via the existing DynamoDB-backed counter):
    1. General per-IP download cap (default 10 req / 60s) — enumeration / DoS
       protection across all links.
    2. Per-(link, IP) attempt cap (default 5 / 60s) — password brute-force
       protection for password-protected links.

    Limits are configurable via env vars so dev/prod parity holds (SECOPS-007):
    the same code path runs in both environments; no ``dev_mode`` bypass.
    """
    global_win = _env_int("SHARE_LINK_DOWNLOAD_WINDOW_SECONDS", 60)
    global_max = _env_int("SHARE_LINK_DOWNLOAD_MAX_PER_WINDOW", 10)
    pwd_win = _env_int("SHARE_LINK_PASSWORD_WINDOW_SECONDS", 60)
    pwd_max = _env_int("SHARE_LINK_PASSWORD_MAX_PER_WINDOW", 5)

    ip_key = _ip_user(ip)

    # 1. General per-IP download limit.
    if not _bucket_limit(ip_key, "rl#share_download", global_max, global_win):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "download_rate_limited",
                "message": "Too many download requests; try again shortly",
                "retry_after_seconds": global_win,
            },
            headers={"Retry-After": str(global_win)},
        )

    # 2. Per-(link, IP) attempt limit (hash link_id to keep the sort key short).
    link_hash = sha256_str(link_id)[:16]
    if not _bucket_limit(ip_key, f"rl#share_pwd#{link_hash}", pwd_max, pwd_win):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "password_attempt_rate_limited",
                "message": "Too many attempts for this link; try again shortly",
                "retry_after_seconds": pwd_win,
            },
            headers={"Retry-After": str(pwd_win)},
        )


def rate_limit_kyc_partner_api(api_key_id: str, category: str) -> None:
    """Per-API-key hourly rate limit for the KYC Partner API (GAP-0286, KYC-021).

    The KYC-021 ticket (§4.7) specifies distinct hourly caps per category:
      * ``applications``   — 100 / hour  (POST /applications, /submit)
      * ``documents``      — 200 / hour  (POST /applications/{id}/documents)
      * ``read``           — 1000 / hour (all GET endpoints)
      * ``webhook_test``   — 10 / hour   (POST /webhooks/{id}/test)

    Keying on ``apikey:{api_key_id}`` (not the partner's ``user_sub``) means each
    issued API key gets its own budget. Uses the existing DynamoDB-backed counter
    (``_bucket_limit``) so the same code path runs in dev (DynamoDB Local) and
    prod (real DynamoDB) — no ``dev_mode`` bypass (SECOPS-007 parity). Caps are
    env-configurable via the ``KYC_PARTNER_API_RL_*`` settings.
    """
    caps = {
        "applications": int(getattr(S, "kyc_partner_api_rl_applications_per_hour", 100) or 100),
        "documents": int(getattr(S, "kyc_partner_api_rl_documents_per_hour", 200) or 200),
        "read": int(getattr(S, "kyc_partner_api_rl_read_per_hour", 1000) or 1000),
        "webhook_test": int(getattr(S, "kyc_partner_api_rl_webhook_test_per_hour", 10) or 10),
    }
    cap = caps.get(category)
    if cap is None:
        return
    win = 3600
    sid = f"rl#kyc_api#{category}"
    key = f"apikey:{api_key_id or 'unknown'}"
    if not _bucket_limit(key, sid, cap, win):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "kyc_api_rate_limited",
                "message": "Too many requests for this API key; try again later",
                "category": category,
                "limit": cap,
                "window_seconds": win,
            },
            headers={"Retry-After": str(win)},
        )


def rate_limit_filemgr_mount_onboarding(user_sub: str, ip: str) -> None:
    sid = "rl#filemgr_mount_onboarding"
    max_n = int(getattr(S, "filemgr_mount_initiate_max_per_window", 5) or 5)
    win = int(getattr(S, "filemgr_mount_initiate_window_seconds", 900) or 900)
    if not _bucket_limit(user_sub, sid, max_n, win):
        raise HTTPException(429, "Too many mount onboarding attempts; try again later")
    if not _bucket_limit(_ip_user(ip), sid, max_n, win):
        raise HTTPException(429, "Too many mount onboarding attempts; try again later")


def rate_limit_filemgr_mount_verify(user_sub: str, ip: str) -> None:
    sid = "rl#filemgr_mount_verify"
    max_n = int(getattr(S, "filemgr_mount_verify_max_per_window", 10) or 10)
    win = int(getattr(S, "filemgr_mount_verify_window_seconds", 900) or 900)
    if not _bucket_limit(user_sub, sid, max_n, win):
        raise HTTPException(429, "Too many mount verification attempts; try again later")
    if not _bucket_limit(_ip_user(ip), sid, max_n, win):
        raise HTTPException(429, "Too many mount verification attempts; try again later")


def rate_limit_filemgr_mount_rotate(user_sub: str, ip: str) -> None:
    sid = "rl#filemgr_mount_rotate"
    max_n = int(S.filemgr_mount_rotate_max_per_window)
    win = int(S.filemgr_mount_rotate_window_seconds)
    if not _bucket_limit(user_sub, sid, max_n, win):
        raise HTTPException(429, "Too many mount rotate attempts; try again later")
    if not _bucket_limit(_ip_user(ip), sid, max_n, win):
        raise HTTPException(429, "Too many mount rotate attempts; try again later")


def rate_limit_filemgr_mount_revoke(user_sub: str, ip: str) -> None:
    sid = "rl#filemgr_mount_revoke"
    max_n = int(S.filemgr_mount_revoke_max_per_window)
    win = int(S.filemgr_mount_revoke_window_seconds)
    if not _bucket_limit(user_sub, sid, max_n, win):
        raise HTTPException(429, "Too many mount revoke attempts; try again later")
    if not _bucket_limit(_ip_user(ip), sid, max_n, win):
        raise HTTPException(429, "Too many mount revoke attempts; try again later")
