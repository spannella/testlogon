"""SUB-E3 in-process gating verification on prod DDB. Non-destructive test rows
(prefixed sube3_) are cleaned up at the end."""
import time
from types import SimpleNamespace
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import subscription_access as SA

TS = int(time.time())
creator = f"sube3_creator_{TS}"
sub_u = f"sube3_sub_{TS}"      # active subscriber
non_u = f"sube3_non_{TS}"      # non-subscriber
adm_u = f"sube3_admin_{TS}"    # platform admin

created_keys = {"subs": [], "users": [], "bcast": [], "settings": []}

def mk_sub(subscriber, period_end, status="active"):
    sk = f"SUB#{creator}#{subscriber}"
    T.subscriptions.put_item(Item={
        "pk": f"SUBSCRIBER#{subscriber}", "sk": sk,
        "subscriber_id": subscriber, "creator_id": creator,
        "status": status, "current_period_end": period_end,
    })
    created_keys["subs"].append({"pk": f"SUBSCRIBER#{subscriber}", "sk": sk})

def PASS(s): print("  PASS", s)
def FAIL(s): print("  ****FAIL****", s)

def raises403(fn, code=None):
    try:
        fn(); return False
    except HTTPException as e:
        if code:
            d = e.detail
            return isinstance(d, dict) and d.get("code") == code or e.status_code == 403
        return e.status_code == 403
    except Exception as e:
        print("   (unexpected exc)", type(e).__name__, e); return False

# --- seed: active sub + admin user ---
mk_sub(sub_u, now_ts() + 100000, "active")
T.users.put_item(Item={"user_sub": adm_u, "role": "admin"})
created_keys["users"].append({"user_sub": adm_u})

print(f"=== SUB-E3 VERIFY (creator={creator}) ===")

# ---------- helper sanity ----------
print("[core] content_locked_for_viewer / has_active_subscription")
print("  non-sub locked =", SA.content_locked_for_viewer(non_u, creator))
print("  active-sub locked =", SA.content_locked_for_viewer(sub_u, creator))
print("  owner locked =", SA.content_locked_for_viewer(creator, creator))
print("  admin locked =", SA.content_locked_for_viewer(adm_u, creator))
assert SA.content_locked_for_viewer(non_u, creator) is True
assert SA.content_locked_for_viewer(sub_u, creator) is False
assert SA.content_locked_for_viewer(creator, creator) is False
assert SA.content_locked_for_viewer(adm_u, creator) is False
PASS("core gate: non=LOCKED sub=open owner=open admin=open")

# ---------- SURFACE 1: FEED POST (main/group/syndicate via _post_to_dict) ----------
print("[feed-post] per-post subscriber_only via _post_to_dict")
from app.routers.newsfeed import _post_to_dict, _subscriber_locked_post
post = {"post_id": f"sube3_p_{TS}", "user_id": creator, "subscriber_only": True,
        "visibility": "public", "created_at": "2026-01-01T00:00:00Z",
        "body_plain": "SECRET-BODY", "body": "SECRET-BODY"}
d_non = _post_to_dict(post, viewer_id=non_u)
d_sub = _post_to_dict(post, viewer_id=sub_u)
d_own = _post_to_dict(post, viewer_id=creator)
d_adm = _post_to_dict(post, viewer_id=adm_u)
print("  non: subscriber_locked=%s body=%r" % (d_non.get("subscriber_locked"), d_non.get("body")))
print("  sub: subscriber_locked=%s body=%r" % (d_sub.get("subscriber_locked"), d_sub.get("body")))
print("  own: subscriber_locked=%s body=%r" % (d_own.get("subscriber_locked"), d_own.get("body")))
print("  adm: subscriber_locked=%s body=%r" % (d_adm.get("subscriber_locked"), d_adm.get("body")))
assert d_non["subscriber_locked"] is True and "SECRET" not in (d_non.get("body") or "")
assert d_sub["subscriber_locked"] is False and "SECRET" in d_sub["body"]
assert d_own["subscriber_locked"] is False and "SECRET" in d_own["body"]
assert d_adm["subscriber_locked"] is False and "SECRET" in d_adm["body"]
PASS("feed post: non=LOCKED(no body) sub/owner/admin=full body + creator_id=%s" % d_non.get("creator_id"))

# ---------- SURFACE 2: POST COMMENTS (gate helper used by list/create) ----------
print("[comments] _subscriber_locked_post gate (list_comments + create_comment)")
assert _subscriber_locked_post(post, non_u) is True
assert _subscriber_locked_post(post, sub_u) is False
assert _subscriber_locked_post(post, creator) is False
assert _subscriber_locked_post(post, adm_u) is False
PASS("comments: non=BLOCKED(403) sub/owner/admin=allowed")

# ---------- SURFACE 3: VIDEO (check_vod_access) ----------
print("[video] check_vod_access access_mode=subscriber_only")
from app.services.vod_purchase import check_vod_access
def vid():
    return SimpleNamespace(id=f"sube3_v_{TS}", owner_user_id=creator,
                           access_mode="subscriber_only", price_cents=500,
                           ads_free_for_subscribers=False, available_purchase_types=["permanent"])
r_non = check_vod_access(user_id=non_u, video_id=f"sube3_v_{TS}", video=vid())
r_sub = check_vod_access(user_id=sub_u, video_id=f"sube3_v_{TS}", video=vid())
r_own = check_vod_access(user_id=creator, video_id=f"sube3_v_{TS}", video=vid())
r_adm = check_vod_access(user_id=adm_u, video_id=f"sube3_v_{TS}", video=vid())
print("  non: entitled=%s reason=%s sub_available=%s" % (r_non.entitled, r_non.reason, getattr(r_non, "subscription_available", None)))
print("  sub: entitled=%s reason=%s" % (r_sub.entitled, r_sub.reason))
print("  own: entitled=%s reason=%s" % (r_own.entitled, r_own.reason))
print("  adm: entitled=%s reason=%s" % (r_adm.entitled, r_adm.reason))
assert r_non.entitled is False
assert r_sub.entitled is True and r_sub.reason == "subscription"
assert r_own.entitled is True and r_own.reason == "owner"
assert r_adm.entitled is True and r_adm.reason == "admin"
PASS("video: non=LOCKED sub=subscription owner=owner admin=admin")

# ---------- SURFACE 4: MESSAGES / DM (require_subscription_access) ----------
print("[dm] require_subscription_access (creator require_subscription=ON)")
SA.set_subscription_settings(creator, require_subscription=True)
created_keys["settings"].append(creator)
assert raises403(lambda: SA.require_subscription_access(non_u, creator))
SA.require_subscription_access(sub_u, creator)     # no raise
SA.require_subscription_access(creator, creator)   # no raise
SA.require_subscription_access(adm_u, creator)     # no raise (admin bypass)
PASS("dm: non=403 sub/owner/admin=allowed")

# ---------- SURFACE 5: CREATOR FEED (can_view_post creator-wide) ----------
print("[creator-feed] can_view_post creator-wide require_subscription")
from app.routers.newsfeed import can_view_post
post2 = {"post_id": f"sube3_pf_{TS}", "user_id": creator, "visibility": "public"}
print("  non=%s sub=%s owner=%s admin=%s" % (
    can_view_post(non_u, post2), can_view_post(sub_u, post2),
    can_view_post(creator, post2), can_view_post(adm_u, post2)))
assert can_view_post(non_u, post2) is False
assert can_view_post(sub_u, post2) is True
assert can_view_post(creator, post2) is True
assert can_view_post(adm_u, post2) is True
PASS("creator-feed: non=HIDDEN sub/owner/admin=visible")

# ---------- SURFACE 6: BROADCAST viewer gate ----------
print("[broadcast] check_viewer_access subscriber_only session")
from app.services.broadcast_privacy import check_viewer_access
sid = f"sube3_bcast_{TS}"
T.broadcast_sessions.put_item(Item={"session_id": sid, "created_by": creator,
    "profile_id": "p", "subscriber_only": True, "broadcast_privacy_visibility": "public"})
created_keys["bcast"].append(sid)
assert raises403(lambda: check_viewer_access(sid, non_u, creator_id=creator, visibility="public"), "BROADCAST_SUBSCRIBER_ONLY")
check_viewer_access(sid, sub_u, creator_id=creator, visibility="public")     # ok
check_viewer_access(sid, creator, creator_id=creator, visibility="public")   # ok
check_viewer_access(sid, adm_u, creator_id=creator, visibility="public")     # ok
PASS("broadcast: non=403 sub/owner/admin=allowed")

# ---------- RE-LOCK ON EXPIRY (E1 lifecycle) ----------
print("[expiry] set active sub current_period_end into the PAST -> re-lock")
mk_sub(sub_u, now_ts() - 10, "active")  # overwrites: period elapsed
assert SA.has_active_subscription(sub_u, creator) is False
assert SA.content_locked_for_viewer(sub_u, creator) is True
d_sub2 = _post_to_dict(post, viewer_id=sub_u)
assert d_sub2["subscriber_locked"] is True and "SECRET" not in (d_sub2.get("body") or "")
assert _subscriber_locked_post(post, sub_u) is True
r_sub2 = check_vod_access(user_id=sub_u, video_id=f"sube3_v_{TS}", video=vid())
assert r_sub2.entitled is False
assert raises403(lambda: SA.require_subscription_access(sub_u, creator))
assert can_view_post(sub_u, post2) is False
assert raises403(lambda: check_viewer_access(sid, sub_u, creator_id=creator, visibility="public"), "BROADCAST_SUBSCRIBER_ONLY")
PASS("RE-LOCK on expiry across ALL 6 surfaces (feed/comments/video/dm/creator-feed/broadcast)")

# ---------- cleanup ----------
try:
    for k in created_keys["subs"]:
        T.subscriptions.delete_item(Key=k)
    for k in created_keys["users"]:
        T.users.delete_item(Key=k)
    for sid_ in created_keys["bcast"]:
        T.broadcast_sessions.delete_item(Key={"session_id": sid_})
    for c in created_keys["settings"]:
        T.subscriptions.delete_item(Key={"pk": f"CREATOR#{c}", "sk": "SETTINGS"})
    print("[cleanup] removed test rows")
except Exception as e:
    print("[cleanup] partial:", e)

print("=== SUB-E3 VERIFY: ALL SURFACES PASS ===")
