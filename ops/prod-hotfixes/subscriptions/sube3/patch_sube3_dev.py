#!/usr/bin/env python3
"""SUB-E3-1: subscriber-only content-gating enforcement across surfaces.
Idempotent-ish exact-string patcher. Run from repo root."""
import io, sys, os

EDITS = []  # (path, old, new, label)

def E(path, old, new, label):
    EDITS.append((path, old, new, label))

# ---------------------------------------------------------------- subscription_access.py
SA = "app/services/subscription_access.py"

E(SA,
"""def list_active_subscriber_ids(creator_id: str) -> List[str]:""",
"""def is_platform_admin(user_id: str) -> bool:
    \"\"\"SUB-E3: best-effort platform-admin/root check for owner+ADMIN bypass on
    gated surfaces. Reads the users table role; never raises.\"\"\"
    if not user_id:
        return False
    try:
        from app.core.tables import T
        item = T.users.get_item(Key={"user_sub": user_id}).get("Item") or {}
    except Exception:
        return False
    return str(item.get("role") or "").strip().lower() in {"admin", "root"}


def content_locked_for_viewer(viewer_id: str, creator_id: str, *, subscriber_only: bool = True) -> bool:
    \"\"\"SUB-E3 single source of truth for subscriber-only content gating.

    Returns True when a subscriber-only item owned by ``creator_id`` must be
    LOCKED (body withheld, non-destructive paywall) for ``viewer_id``:
      * not flagged subscriber-only    -> False (open)
      * owner / platform admin         -> False (bypass)
      * active subscriber (lifecycle)  -> False (unlocked)
      * syndicate-bundle holder        -> False (unlocked)
      * everyone else                  -> True  (locked)

    Re-locks automatically on expiry because ``has_active_subscription`` is
    lifecycle-aware (SUB-E1: bounded by grace-extended current_period_end).\"\"\"
    if not subscriber_only:
        return False
    if not creator_id:
        return False
    if viewer_id and viewer_id == creator_id:
        return False
    if is_platform_admin(viewer_id):
        return False
    if viewer_id and has_active_subscription(viewer_id, creator_id):
        return False
    try:
        from app.services.syndicate_subscriptions import has_bundle_access
        if viewer_id and has_bundle_access(viewer_id, creator_id):
            return False
    except Exception:
        pass
    return True


def list_active_subscriber_ids(creator_id: str) -> List[str]:""",
"SA: add is_platform_admin + content_locked_for_viewer")

E(SA,
"""    if not creator_requires_subscription(creator_id):
        return True
    if has_active_subscription(subscriber_id, creator_id):
        return True""",
"""    if not creator_requires_subscription(creator_id):
        return True
    if is_platform_admin(subscriber_id):  # SUB-E3: admin bypass
        return True
    if has_active_subscription(subscriber_id, creator_id):
        return True""",
"SA: admin bypass in can_access_creator")

# ---------------------------------------------------------------- newsfeed.py
NF = "app/routers/newsfeed.py"

E(NF,
"from app.services.subscription_access import can_access_creator\n",
"from app.services.subscription_access import can_access_creator, content_locked_for_viewer\n",
"NF: import content_locked_for_viewer")

E(NF,
"""    visibility: Literal["followers", "public"] = "followers"
    lock_type: Optional[Literal["fixed_price", "tip_lottery"]] = None""",
"""    visibility: Literal["followers", "public"] = "followers"
    subscriber_only: bool = False  # SUB-E3: per-post subscriber-only gate
    lock_type: Optional[Literal["fixed_price", "tip_lottery"]] = None""",
"NF: CreatePostRequest.subscriber_only")

E(NF,
"""        "visibility": req.visibility,
        "locked": locked,""",
"""        "visibility": req.visibility,
        "subscriber_only": bool(getattr(req, "subscriber_only", False)),
        "locked": locked,""",
"NF: persist subscriber_only on create")

# _post_to_dict: compute sub-lock at top (after lifecycle fields resolve)
E(NF,
"""    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, body_version = _resolve_read_body_fields(post)
    status, publish_at, published_at, schedule_timezone, scheduled_at_local = _resolve_post_lifecycle_fields(post)""",
"""    body, body_plain, body_markdown, body_markdown_html, body_rich, body_format, body_version = _resolve_read_body_fields(post)
    status, publish_at, published_at, schedule_timezone, scheduled_at_local = _resolve_post_lifecycle_fields(post)
    # SUB-E3: per-post subscriber-only gate -> non-destructive lock marker.
    _sub_author = str(post.get("user_id") or "")
    _sub_locked = False
    if (not locked_body) and viewer_id and _sub_author and _sub_author != viewer_id and bool(post.get("subscriber_only")):
        try:
            from app.services.subscription_access import content_locked_for_viewer as _clfv
            _sub_locked = _clfv(viewer_id, _sub_author, subscriber_only=True)
        except Exception:
            _sub_locked = False
    if _sub_locked:
        locked_body = True""",
"NF: _post_to_dict compute sub-lock")

E(NF,
"""        "visibility": post.get("visibility", "followers"),
        "locked": bool(post.get("locked")),""",
"""        "visibility": post.get("visibility", "followers"),
        "subscriber_only": bool(post.get("subscriber_only")),
        "subscriber_locked": _sub_locked,
        "creator_id": _sub_author,
        "locked": bool(post.get("locked")),""",
"NF: _post_to_dict output fields")

# helper before can_view_post
E(NF,
"""def can_view_post(viewer_id: str, post: Dict[str, Any]) -> bool:""",
"""def _subscriber_locked_post(post: Dict[str, Any], viewer_id) -> bool:
    \"\"\"SUB-E3: True when a per-post subscriber-only item must be locked for the
    viewer (owner/admin/active-subscriber bypass via content_locked_for_viewer).\"\"\"
    author = str(post.get("user_id") or "")
    if not author or author == viewer_id or not bool(post.get("subscriber_only")):
        return False
    try:
        return content_locked_for_viewer(viewer_id, author, subscriber_only=True)
    except Exception:
        return False


def can_view_post(viewer_id: str, post: Dict[str, Any]) -> bool:""",
"NF: _subscriber_locked_post helper")

# get_post_file gate
E(NF,
"""    attachments = post.get("file_attachments") or []
    if file_index < 0 or file_index >= len(attachments):""",
"""    if _subscriber_locked_post(post, user_id):
        raise HTTPException(status_code=403, detail={"code": "SUBSCRIBER_ONLY", "detail": "Subscribe to unlock this content", "creator_id": author})
    attachments = post.get("file_attachments") or []
    if file_index < 0 or file_index >= len(attachments):""",
"NF: get_post_file subscriber gate")

# download_post_attachment gate
E(NF,
"""    attachment = None
    for it in post.get("attachments") or []:""",
"""    if _subscriber_locked_post(post, user_id):
        raise HTTPException(status_code=403, detail={"code": "SUBSCRIBER_ONLY", "detail": "Subscribe to unlock this content", "creator_id": author})

    attachment = None
    for it in post.get("attachments") or []:""",
"NF: download_post_attachment subscriber gate")

# list_comments gate
E(NF,
"""        raise HTTPException(status_code=402, detail="Post is locked; unlock required to view comments")
""",
"""        raise HTTPException(status_code=402, detail="Post is locked; unlock required to view comments")

    if _subscriber_locked_post(post, user_id):
        raise HTTPException(status_code=403, detail={"code": "SUBSCRIBER_ONLY", "detail": "Subscribe to view comments on this content", "creator_id": post.get("user_id")})
""",
"NF: list_comments subscriber gate")

# create_comment gate
E(NF,
"""        raise HTTPException(status_code=402, detail="Post is locked; unlock required to comment")
""",
"""        raise HTTPException(status_code=402, detail="Post is locked; unlock required to comment")

    if _subscriber_locked_post(post, user_id):
        raise HTTPException(status_code=403, detail={"code": "SUBSCRIBER_ONLY", "detail": "Subscribe to comment on this content", "creator_id": post.get("user_id")})
""",
"NF: create_comment subscriber gate")

# ---------------------------------------------------------------- vod_purchase.py
VP = "app/services/vod_purchase.py"
E(VP,
"from app.services.subscription_access import has_active_subscription\n",
"from app.services.subscription_access import has_active_subscription, is_platform_admin\n",
"VP: import is_platform_admin")

E(VP,
"""    # 1. Owner check
    if user_id == creator_id:
        return VodAccessResult(entitled=True, reason="owner")""",
"""    # 1. Owner check
    if user_id == creator_id:
        return VodAccessResult(entitled=True, reason="owner")

    # SUB-E3: platform admins bypass subscriber gating on every surface.
    try:
        if is_platform_admin(user_id):
            return VodAccessResult(entitled=True, reason="admin")
    except Exception:
        pass""",
"VP: admin bypass in check_vod_access")

# ---------------------------------------------------------------- broadcast_privacy.py
BP = "app/services/broadcast_privacy.py"
E(BP,
"""    visibility = (visibility or "public").strip().lower()
    if visibility != "private":
        return""",
"""    # SUB-E3: subscriber-only broadcast gate (independent of visibility).
    if viewer_id != creator_id:
        try:
            from app.core.tables import T as _T
            _raw = _T.broadcast_sessions.get_item(Key={"session_id": session_id}).get("Item", {}) or {}
        except Exception:
            _raw = {}
        if bool(_raw.get("subscriber_only")):
            from app.services.subscription_access import content_locked_for_viewer
            if content_locked_for_viewer(viewer_id, creator_id, subscriber_only=True):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "code": "BROADCAST_SUBSCRIBER_ONLY",
                        "detail": "Subscribe to watch this broadcast.",
                        "creator_id": creator_id,
                    },
                )
    visibility = (visibility or "public").strip().lower()
    if visibility != "private":
        return""",
"BP: subscriber-only broadcast gate")

# ---------------------------------------------------------------- models_broadcast.py
MB = "app/models_broadcast.py"
E(MB,
"    clips_enabled: bool = True\n",
"    clips_enabled: bool = True\n    subscriber_only: bool = False  # SUB-E3: subscriber-only broadcast gate\n",
"MB: model subscriber_only field")

# ---------------------------------------------------------------- broadcast_store.py
BS = "app/services/broadcast_store.py"
E(BS,
'        "clips_enabled": session.clips_enabled,\n',
'        "clips_enabled": session.clips_enabled,\n        "subscriber_only": getattr(session, "subscriber_only", False),\n',
"BS: session_to_item subscriber_only")

E(BS,
"        clips_enabled=bool(item.get(\"clips_enabled\", True)),\n",
"        clips_enabled=bool(item.get(\"clips_enabled\", True)),\n        subscriber_only=bool(item.get(\"subscriber_only\", False)),\n",
"BS: session_from_item subscriber_only")

E(BS,
"""    mid_roll_ad_break_duration_seconds: int = 30,
    mid_roll_skip_after_seconds: int = 15,
) -> BroadcastSessionModel:""",
"""    mid_roll_ad_break_duration_seconds: int = 30,
    mid_roll_skip_after_seconds: int = 15,
    subscriber_only: bool = False,
) -> BroadcastSessionModel:""",
"BS: create_session signature subscriber_only")

E(BS,
"""        mid_roll_ad_break_duration_seconds=mid_roll_ad_break_duration_seconds,
        mid_roll_skip_after_seconds=mid_roll_skip_after_seconds,
    )
    T.broadcast_sessions.put_item(""",
"""        mid_roll_ad_break_duration_seconds=mid_roll_ad_break_duration_seconds,
        mid_roll_skip_after_seconds=mid_roll_skip_after_seconds,
        subscriber_only=subscriber_only,
    )
    T.broadcast_sessions.put_item(""",
"BS: create_session model construct subscriber_only")

# ---------------------------------------------------------------- broadcast.py (router)
BR = "app/routers/broadcast.py"
E(BR,
"    clips_enabled: bool = True\n",
"    clips_enabled: bool = True\n    subscriber_only: bool = False  # SUB-E3\n",
"BR: create request subscriber_only")

E(BR,
"""        mid_roll_ad_break_duration_seconds=body.mid_roll_ad_break_duration_seconds,
        mid_roll_skip_after_seconds=body.mid_roll_skip_after_seconds,
    )""",
"""        mid_roll_ad_break_duration_seconds=body.mid_roll_ad_break_duration_seconds,
        mid_roll_skip_after_seconds=body.mid_roll_skip_after_seconds,
        subscriber_only=getattr(body, "subscriber_only", False),
    )""",
"BR: create_session_route pass subscriber_only")


def main():
    dry = bool(os.environ.get("SUBE3_DRY"))
    failures = []
    for path, old, new, label in EDITS:
        if not os.path.exists(path):
            failures.append(f"MISSING FILE {path} [{label}]"); continue
        with io.open(path, "r", encoding="utf-8") as f:
            src = f.read()
        if new in src and old not in src:
            print(f"SKIP (already applied): {label}"); continue
        n = src.count(old)
        if n != 1:
            failures.append(f"ANCHOR count={n} (need 1) for [{label}] in {path}"); continue
        if dry:
            print(f"PROBE OK (anchor==1): {label}"); continue
        src = src.replace(old, new, 1)
        with io.open(path, "w", encoding="utf-8") as f:
            f.write(src)
        print(f"OK: {label}")
    if failures:
        print("\n=== FAILURES ===")
        for x in failures:
            print(x)
        sys.exit(1)
    print("\nALL EDITS APPLIED")

if __name__ == "__main__":
    main()
