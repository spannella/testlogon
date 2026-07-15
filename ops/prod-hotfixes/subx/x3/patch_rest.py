def patch(p, edits):
    s = open(p, encoding="utf-8").read()
    orig = s
    for old, new in edits:
        n = s.count(old)
        if n < 1:
            raise SystemExit(f"[{p}] ANCHOR NOT FOUND: {old[:70]!r}")
        s = s.replace(old, new, 1)
    open(p, "w", encoding="utf-8").write(s)
    import ast
    ast.parse(s)
    print(f"PATCHED {p}; delta {len(s)-len(orig)}")

# ---- subscription_renewal.py : downgrade apply re-resolves tier_level ----
patch("app/services/subscription_renewal.py", [
    (
        '    sub["plan_change_applied_at"] = now\n    # a plan change resets any old-plan discount',
        '    sub["plan_change_applied_at"] = now\n    # SUBX-30/33: a DOWNGRADE (or period-end change) applies now -> re-resolve the\n    # tier level so the subscriber drops to the new tier exactly at period end.\n    try:\n        from app.services.subscription_access import get_plan_level as _gpl\n        _lvl = _gpl(str(sub.get("creator_id") or ""), str(sub["plan_id"]))\n        if _lvl:\n            sub["tier_level"] = _lvl\n    except Exception:\n        pass\n    # a plan change resets any old-plan discount',
    ),
])

# ---- newsfeed.py : thread required_tier_level through the post gate + emit it ----
patch("app/routers/newsfeed.py", [
    # _post_to_dict gate call: read required_tier_level, pass it, surface for the app card
    (
        '        try:\n            from app.services.subscription_access import content_locked_for_viewer as _clfv\n            _sub_locked = _clfv(viewer_id, _sub_author, subscriber_only=True)\n        except Exception:\n            _sub_locked = False\n    if _sub_locked:\n        locked_body = True',
        '        try:\n            from app.services.subscription_access import content_locked_for_viewer as _clfv\n            _req_level = int(post.get("required_tier_level") or 0)\n            _sub_locked = _clfv(viewer_id, _sub_author, subscriber_only=True, required_level=_req_level)\n        except Exception:\n            _sub_locked = False\n    if _sub_locked:\n        locked_body = True',
    ),
    # _subscriber_locked_post helper: pass required_tier_level too
    (
        '    try:\n        return content_locked_for_viewer(viewer_id, author, subscriber_only=True)\n    except Exception:\n        return False',
        '    try:\n        return content_locked_for_viewer(\n            viewer_id, author, subscriber_only=True,\n            required_level=int(post.get("required_tier_level") or 0),\n        )\n    except Exception:\n        return False',
    ),
])

# ---- broadcast_privacy.py : thread required_tier_level from the session ----
patch("app/services/broadcast_privacy.py", [
    (
        '        if bool(_raw.get("subscriber_only")):\n            from app.services.subscription_access import content_locked_for_viewer\n            if content_locked_for_viewer(viewer_id, creator_id, subscriber_only=True):',
        '        if bool(_raw.get("subscriber_only")):\n            from app.services.subscription_access import content_locked_for_viewer\n            _req_level = int(_raw.get("required_tier_level") or 0)  # SUBX-31\n            if content_locked_for_viewer(viewer_id, creator_id, subscriber_only=True, required_level=_req_level):',
    ),
])

# ---- vod_purchase.py : thread required_tier_level from the video ----
patch("app/services/vod_purchase.py", [
    (
        '    if access_mode in ("subscriber_only", "subscriber_free"):\n        has_sub = has_active_subscription(subscriber_id=user_id, creator_id=creator_id)\n        if has_sub:',
        '    if access_mode in ("subscriber_only", "subscriber_free"):\n        _req_level = int(getattr(video, "required_tier_level", 0) or 0)  # SUBX-31\n        has_sub = has_active_subscription(subscriber_id=user_id, creator_id=creator_id, required_level=_req_level)\n        if has_sub:',
    ),
])
print("ALL PATCHED")
