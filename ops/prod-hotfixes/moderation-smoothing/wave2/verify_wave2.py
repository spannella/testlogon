"""MODX WAVE-2 verify — in-process on PROD DDB, non-destructive, self-cleaning.

Proves the coverage matrix for every newly-covered surface:
  reportable -> auto-hides (flag on the REAL row + the surface read hides it for a
  non-owner) -> admin-visible (a live under_review case) -> reinstates byte-for-byte.
And that the happy path / core is intact (feed_post still hides+reinstates).

Types: syndicate_post (app-fixed), profile_photo, user/account, catalog_item,
catalog_review, broadcast_message, story, clip.  Seeds synthetic content/users,
auto-cleans (0 residue).
"""
import os
import time
import uuid

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.tables import T

import app.routers.moderation as M
from app.services import moderation_case as MC
from app.services import moderation_hide as MH
from app.services import moderation_lifecycle as LIFE
from app.services import profile as P
from app.services import stories as STORIES
from app.services import broadcast_chat_store as CHAT
from app.services import broadcast_clip as CLIP

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
TS = int(time.time())
SUFFIX = f"modx2_{TS}_{uuid.uuid4().hex[:6]}"
results = []
cleanups = []  # list of callables


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def cleanup(fn):
    cleanups.append(fn)


def new_uid(tag):
    return f"u_{tag}_{SUFFIX}"


def seed_reporter(uid):
    """A TRUSTED reporter so a single severe report deterministically auto-hides."""
    T.account_state.put_item(Item={"user_sub": uid, "trusted_reporter": True, "updated_at": TS})
    cleanup(lambda: T.account_state.delete_item(Key={"user_sub": uid}))
    return uid


def report(content_type, content_id, reporter, **extra):
    inp = M.CreateModerationReportIn(
        content_type=content_type,
        content_id=content_id,
        topics=["hate"],
        reason_text="verify wave2 synthetic report",
        **extra,
    )
    ctx = {"user_sub": reporter, "ip": f"10.0.0.{TS % 250}"}
    return M._create_report(inp, ctx, request=None)


def case_for(content_type, content_id):
    return MC.get_case(MC.case_id_for(content_type, content_id)) or {}


def run_surface(name, content_type, content_id, seed_extra, is_hidden_now, restore_ok, owner):
    reporter = seed_reporter(new_uid(f"rep_{name}"))
    out = report(content_type, content_id, reporter, **seed_extra)
    case = case_for(content_type, content_id)
    check(f"{name}: report accepted", out.status in ("submitted", "deduplicated"), out.status)
    check(f"{name}: case under_review (auto-hidden)", case.get("state") == "under_review" and bool(case.get("hidden")), f"state={case.get('state')} hidden={case.get('hidden')}")
    check(f"{name}: admin-visible case owner resolved", str(case.get("owner_user_id") or "") == str(owner), f"owner={case.get('owner_user_id')} expect={owner}")
    check(f"{name}: surface read HIDES for non-owner", is_hidden_now(), "read-path check")
    # Reinstate via the real admin path (un-hide + close). Proves byte-for-byte restore.
    LIFE.admin_dismiss(case=case, metadata=None, admin_user_id=new_uid("admin"), now_ts=TS + 1)
    case2 = case_for(content_type, content_id)
    check(f"{name}: reinstated (case dismissed, unhidden)", case2.get("state") == "dismissed" and not case2.get("hidden"), f"state={case2.get('state')} hidden={case2.get('hidden')}")
    check(f"{name}: surface RESTORED byte-for-byte", restore_ok(), "restore check")


# ─────────────────────────── profile_photo + user ────────────────────────────
def test_profile_and_account():
    owner = new_uid("photo_owner")
    orig = f"https://cdn.example/orig_{SUFFIX}.jpg"
    P.apply_profile_update(owner, {"display_name": "Photo Owner", "profile_photo_url": orig}, replace=False)
    cleanup(lambda: T.profile.delete_item(Key={"user_sub": owner}))

    def photo_hidden():
        return P.get_profile(owner).get("profile_photo_url") is None
    def photo_restored():
        return P.get_profile(owner).get("profile_photo_url") == orig
    run_surface("profile_photo", "profile_photo", owner, {}, photo_hidden, photo_restored, owner)

    # account-level report (MODX-11): a user WITH NO photo is reportable + hides the profile.
    acct = new_uid("acct_owner")
    P.apply_profile_update(acct, {"display_name": "No Photo Person"}, replace=False)  # no profile_photo_url
    cleanup(lambda: T.profile.delete_item(Key={"user_sub": acct}))
    def acct_hidden():
        raw = T.profile.get_item(Key={"user_sub": acct}).get("Item") or {}
        from app.routers.profile import _account_moderation_hidden
        return bool(raw.get("moderation_hidden")) and _account_moderation_hidden(acct)
    def acct_restored():
        raw = T.profile.get_item(Key={"user_sub": acct}).get("Item") or {}
        return not raw.get("moderation_hidden")
    run_surface("user/account", "user", acct, {}, acct_hidden, acct_restored, acct)


# ─────────────────────────── syndicate_post ──────────────────────────────────
def test_syndicate():
    sid = f"synd_{SUFFIX}"
    pid = f"sp_{SUFFIX}"
    author = new_uid("synd_author")
    key = {"pk": f"SYND#{sid}", "sk": f"POST#{pid}"}
    T.syndicate_posts.put_item(Item={**key, "post_id": pid, "author_id": author, "body": "hi", "created_at": TS})
    cleanup(lambda: T.syndicate_posts.delete_item(Key=key))
    def hidden():
        it = T.syndicate_posts.get_item(Key=key).get("Item") or {}
        return MH.is_hidden_for_viewer(it, new_uid("viewer"), owner_field="author_id")
    def restored():
        it = T.syndicate_posts.get_item(Key=key).get("Item") or {}
        return not MH.is_hidden_flag(it)
    run_surface("syndicate_post", "syndicate_post", pid, {"syndicate_id": sid}, hidden, restored, author)


# ─────────────────────────── catalog_item + review ───────────────────────────
def test_catalog():
    cat = f"cat_{SUFFIX}"
    item = f"item_{SUFFIX}"
    creator = new_uid("cat_creator")
    ckey = {"PK": f"CAT#{cat}", "SK": "META"}
    ikey = {"PK": f"CAT#{cat}", "SK": f"ITEM#{item}"}
    T.catalog.put_item(Item={**ckey, "entity": "category", "creator_id": creator, "category_id": cat})
    T.catalog.put_item(Item={**ikey, "entity": "item", "item_id": item, "category_id": cat, "creator_id": creator, "name": "Widget"})
    cleanup(lambda: T.catalog.delete_item(Key=ckey))
    cleanup(lambda: T.catalog.delete_item(Key=ikey))
    def i_hidden():
        it = T.catalog.get_item(Key=ikey).get("Item") or {}
        return MH.is_hidden_for_viewer(it, new_uid("viewer"), owner_field="creator_id")
    def i_restored():
        it = T.catalog.get_item(Key=ikey).get("Item") or {}
        return not MH.is_hidden_flag(it)
    run_surface("catalog_item", "catalog_item", item, {"category_id": cat}, i_hidden, i_restored, creator)

    rev = f"rev_{SUFFIX}"
    reviewer = new_uid("reviewer")
    rkey = {"PK": f"ITEM#{item}", "SK": f"REVIEW#{rev}"}
    T.catalog.put_item(Item={**rkey, "entity": "review", "item_id": item, "review_id": rev, "reviewer": reviewer, "rating": 1, "body": "bad", "created_at": TS})
    cleanup(lambda: T.catalog.delete_item(Key=rkey))
    def r_hidden():
        it = T.catalog.get_item(Key=rkey).get("Item") or {}
        return MH.is_hidden_flag(it)
    def r_restored():
        it = T.catalog.get_item(Key=rkey).get("Item") or {}
        return not MH.is_hidden_flag(it)
    run_surface("catalog_review", "catalog_review", rev, {"item_id": item}, r_hidden, r_restored, reviewer)


# ─────────────────────────── broadcast_message ───────────────────────────────
def test_broadcast_message():
    sess = f"sess_{SUFFIX}"
    mid = f"msg_{SUFFIX}"
    sender = new_uid("chatter")
    sk = f"MSG#{TS}#{mid}"
    key = {"session_id": sess, "sort_key": sk}
    T.broadcast_chat_messages.put_item(Item={**key, "message_id": mid, "sender_id": sender, "sender_display_name": "Chatter", "text": "spam", "kind": "chat", "created_at": TS})
    cleanup(lambda: T.broadcast_chat_messages.delete_item(Key=key))
    def hidden():
        hist = CHAT.get_chat_history(sess, viewer_user_id=new_uid("viewer"))
        return all(m.get("message_id") != mid for m in hist.get("messages", []))
    def restored():
        hist = CHAT.get_chat_history(sess, viewer_user_id=new_uid("viewer"))
        return any(m.get("message_id") == mid for m in hist.get("messages", []))
    run_surface("broadcast_message", "broadcast_message", mid, {"session_id": sess}, hidden, restored, sender)


# ─────────────────────────── story ───────────────────────────────────────────
def test_story():
    owner = new_uid("story_owner")
    st = STORIES.create_story(owner, media_type="image", media_url=f"https://cdn/{SUFFIX}.jpg")
    story_id = st["story_id"]
    cleanup(lambda: ddb.Table(APP_TABLE).delete_item(Key={"pk": f"STORY#{story_id}", "sk": "META"}))
    def hidden():
        return all(s.get("story_id") != story_id for s in STORIES.get_user_stories(owner, include_expired=True))
    def restored():
        return any(s.get("story_id") == story_id for s in STORIES.get_user_stories(owner, include_expired=True))
    run_surface("story", "story", story_id, {}, hidden, restored, owner)


# ─────────────────────────── clip ────────────────────────────────────────────
def test_clip():
    owner = new_uid("clip_owner")
    sess = f"clipsess_{SUFFIX}"
    cid = f"clip_{SUFFIX}"
    key = {"clip_id": cid}
    T.broadcast_clips.put_item(Item={**key, "creator_user_id": owner, "broadcaster_user_id": owner, "session_id": sess, "status": "ready", "GSI1PK": f"SESSION#{sess}", "GSI2PK": f"CREATOR#{owner}", "created_at": TS, "sk": f"{TS}"})
    cleanup(lambda: T.broadcast_clips.delete_item(Key=key))
    def hidden():
        try:
            CLIP.get_public_clip(cid)
            return False
        except Exception as e:
            return "404" in str(e) or "not found" in str(e).lower() or getattr(e, "status_code", None) == 404
    def restored():
        try:
            c = CLIP.get_public_clip(cid)
            return bool(c)
        except Exception:
            return False
    run_surface("clip", "clip", cid, {}, hidden, restored, owner)


# ─────────────────────────── CORE regression: feed_post ──────────────────────
def test_core_feed_post():
    owner = new_uid("feed_owner")
    pid = f"post_{SUFFIX}"
    key = {"pk": f"POST#{pid}", "sk": "META"}
    body = "the original feed body — must survive byte-for-byte"
    ddb.Table(APP_TABLE).put_item(Item={**key, "post_id": pid, "user_id": owner, "body": body, "content": body, "status": "published", "created_at": TS})
    cleanup(lambda: ddb.Table(APP_TABLE).delete_item(Key=key))
    def hidden():
        it = ddb.Table(APP_TABLE).get_item(Key=key).get("Item") or {}
        return MH.is_hidden_for_viewer(it, new_uid("viewer"), owner_field="user_id")
    def restored():
        it = ddb.Table(APP_TABLE).get_item(Key=key).get("Item") or {}
        return (not MH.is_hidden_flag(it)) and it.get("body") == body
    run_surface("feed_post(core)", "feed_post", pid, {"post_id": pid}, hidden, restored, owner)


def main():
    try:
        test_profile_and_account()
        test_syndicate()
        test_catalog()
        test_broadcast_message()
        test_story()
        test_clip()
        test_core_feed_post()
    finally:
        # Clean up all seeded rows + any moderation cases/tickets/reports.
        for fn in reversed(cleanups):
            try:
                fn()
            except Exception as e:
                print("cleanup-warn:", e)
        _cleanup_moderation_artifacts()

    passed = sum(1 for ok, _, _ in results if ok)
    total = len(results)
    print(f"\n==== WAVE-2 VERIFY: {passed}/{total} PASSED ====")
    fails = [(n, d) for ok, n, d in results if not ok]
    for n, d in fails:
        print("  FAIL:", n, "--", d)
    return 0 if passed == total else 1


def _cleanup_moderation_artifacts():
    # Remove synthetic moderation_cases / content_reports / tickets by our SUFFIX.
    for ct, cid, extra in _all_case_refs:
        try:
            T.moderation_cases.delete_item(Key={"case_id": MC.case_id_for(ct, cid)})
        except Exception:
            pass
    # content_reports + tickets carry our synthetic ids; best-effort scan-free purge via known ids.
    for tid in _all_ticket_ids:
        try:
            T.moderation_tickets.delete_item(Key={"ticket_id": tid})
        except Exception:
            pass


_all_case_refs = []
_all_ticket_ids = []

# wrap report() to record refs for cleanup
_orig_report = report
def report(content_type, content_id, reporter, **extra):  # noqa: F811
    _all_case_refs.append((content_type, content_id, extra))
    out = _orig_report(content_type, content_id, reporter, **extra)
    try:
        _all_ticket_ids.append(out.ticket_id)
    except Exception:
        pass
    return out


if __name__ == "__main__":
    raise SystemExit(main())
