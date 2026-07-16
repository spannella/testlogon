#!/usr/bin/env python3
"""MODX WAVE-2 re-apply helper (coverage: close the silent-enforcement-failure surfaces).

Idempotent, anchor-based in-place edits. Prod == dev HEAD byte-for-byte on every
target region (probed), so the SAME script applies to the dev clone and to prod.

Files patched:
  app/services/moderation_hide.py      MODX-10/11/12 real hide primitives + dispatch + resolve_owner
  app/services/moderation_delete.py    terminal delete primitives + dispatch for the new types
  app/routers/moderation.py            content_type Literal + fields + validation + metadata passthrough + photo-exists fix
  app/services/moderation_flags.py     default-on reporting-surface gates for the new surfaces
  app/routers/profile.py               account-hold 404 for non-owners (MODX-11 read enforcement)
  app/services/broadcast_chat_store.py live-chat read filter honors moderation_hidden (MODX-12)
  app/services/broadcast_clip.py       clip read filter honors moderation_hidden (MODX-12)
  app/services/stories.py              story read filter honors moderation_hidden (MODX-12)
  app/routers/catalog.py               catalog item/review read filter honors moderation_hidden (MODX-12)

Run from a testlogon checkout root:  python3 apply_wave2.py
"""
import sys

HIDE = "app/services/moderation_hide.py"
DEL = "app/services/moderation_delete.py"
ROUTER = "app/routers/moderation.py"
FLAGS = "app/services/moderation_flags.py"
PROFILE = "app/routers/profile.py"
CHAT = "app/services/broadcast_chat_store.py"
CLIP = "app/services/broadcast_clip.py"
STORIES = "app/services/stories.py"
CATALOG = "app/routers/catalog.py"

# ─────────────────────────── moderation_hide.py ──────────────────────────────
HIDE_FUNCS = '''# ── MODX-10/11/12: real hide primitives for the previously-silent surfaces ────
def _hide_profile_photo(*, user_sub: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-10 (B2): profile-photo hide used to be a literal no-op. Real, NON-
    DESTRUCTIVE hide: stash + null the photo url so non-owners stop seeing it, and
    restore it byte-for-byte on unhide. Photo-scoped flags are kept SEPARATE from
    the account-level moderation flags so a photo hold never hides the profile."""
    if not user_sub:
        return None
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item")
    if not item:
        return None
    profile = dict(item.get("profile") or {})
    if hidden:
        if profile.get("profile_photo_url") is not None:
            profile["moderation_saved_photo_url"] = profile.get("profile_photo_url")
        profile["profile_photo_url"] = None
    else:
        if profile.get("moderation_saved_photo_url") is not None:
            profile["profile_photo_url"] = profile.get("moderation_saved_photo_url")
        profile.pop("moderation_saved_photo_url", None)
    new_item = dict(item)
    new_item["profile"] = profile
    new_item["moderation_photo_hidden"] = bool(hidden)
    new_item["moderation_photo_case_id"] = case_id
    new_item["moderation_photo_state"] = state
    new_item["moderation_photo_hidden_at"] = _now_iso()
    T.profile.put_item(Item=new_item)
    return user_sub


def _hide_user_account(*, user_sub: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-11 (B3): account-level enforcement. Non-destructive account-hidden flag
    over the intact profile row; the public profile read honors it (404 for non-
    owners) and reinstate clears it. NEVER deletes the account (ban is the remedy)."""
    if not user_sub:
        return None
    item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {"user_sub": user_sub}
    new_item = dict(item)
    new_item["user_sub"] = user_sub
    new_item.update({
        "moderation_hidden": bool(hidden),
        "moderation_removed": bool(hidden),
        "moderation_case_id": case_id,
        "moderation_state": state,
        "moderation_hidden_at": _now_iso(),
    })
    T.profile.put_item(Item=new_item)
    return user_sub


def _hide_catalog_item(*, category_id: str, item_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-12 (B4): non-destructive hide over a catalog item row (T.catalog)."""
    if not category_id or not item_id:
        return None
    key = {"PK": f"CAT#{category_id}", "SK": f"ITEM#{item_id}"}
    item = T.catalog.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    T.catalog.update_item(Key=key, UpdateExpression=_SET_EXPR, ExpressionAttributeValues=_flag_values(case_id, state, hidden))
    return item.get("creator_id")


def _hide_catalog_review(*, item_id: str, review_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-12 (B4): non-destructive hide over a product-review row (T.catalog)."""
    if not item_id or not review_id:
        return None
    key = {"PK": f"ITEM#{item_id}", "SK": f"REVIEW#{review_id}"}
    item = T.catalog.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    T.catalog.update_item(Key=key, UpdateExpression=_SET_EXPR, ExpressionAttributeValues=_flag_values(case_id, state, hidden))
    return item.get("reviewer")


def _bcast_msg_sort_key(session_id: str, message_id: str) -> Optional[str]:
    try:
        resp = T.broadcast_chat_messages.query(
            IndexName="MessageIdIndex",
            KeyConditionExpression=Key("message_id").eq(message_id),
        )
    except Exception:
        return None
    for it in resp.get("Items", []):
        if it.get("session_id") == session_id:
            return it.get("sort_key")
    return None


def _hide_broadcast_message(*, session_id: str, message_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-12 (B5): viewer-reported live-chat message -> the real state machine
    (non-destructive hide over T.broadcast_chat_messages), not just the parallel mute."""
    if not session_id or not message_id:
        return None
    sk = _bcast_msg_sort_key(session_id, message_id)
    if not sk:
        return None
    key = {"session_id": session_id, "sort_key": sk}
    item = T.broadcast_chat_messages.get_item(Key=key).get("Item") or {}
    T.broadcast_chat_messages.update_item(Key=key, UpdateExpression=_SET_EXPR, ExpressionAttributeValues=_flag_values(case_id, state, hidden))
    return item.get("sender_id")


def _hide_story(*, story_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-12 (B6): non-destructive hide over an ephemeral story row (APP_TABLE)."""
    if not story_id:
        return None
    key = {"pk": f"STORY#{story_id}", "sk": "META"}
    item = ddb.Table(APP_TABLE).get_item(Key=key).get("Item") or {}
    if not item:
        return None
    ddb.Table(APP_TABLE).update_item(Key=key, UpdateExpression=_SET_EXPR, ExpressionAttributeValues=_flag_values(case_id, state, hidden))
    return item.get("author_id")


def _hide_clip(*, clip_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    """MODX-12 (B6): non-destructive hide over a broadcast clip row (T.broadcast_clips)."""
    if not clip_id:
        return None
    key = {"clip_id": clip_id}
    item = T.broadcast_clips.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    T.broadcast_clips.update_item(Key=key, UpdateExpression=_SET_EXPR, ExpressionAttributeValues=_flag_values(case_id, state, hidden))
    return item.get("creator_user_id")


def _apply(*, content_type: str, content_id: str, metadata: Dict[str, Any], case_id: str, state: str, hidden: bool) -> Optional[str]:
    md = metadata or {}'''
HIDE_FUNCS_ANCHOR = '''def _apply(*, content_type: str, content_id: str, metadata: Dict[str, Any], case_id: str, state: str, hidden: bool) -> Optional[str]:
    md = metadata or {}'''

HIDE_DISPATCH_ANCHOR = '''    if content_type == "profile_photo":
        # Profile photos already have a dedicated non-destructive revert path; no flag write here.
        return content_id
    logger.warning("moderation_hide: unsupported content_type %s", content_type)'''
HIDE_DISPATCH = '''    if content_type == "profile_photo":
        return _hide_profile_photo(user_sub=str(md.get("profile_user_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type in ("user", "account"):
        return _hide_user_account(user_sub=str(md.get("profile_user_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type == "catalog_item":
        return _hide_catalog_item(category_id=str(md.get("category_id") or ""), item_id=str(md.get("item_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type == "catalog_review":
        return _hide_catalog_review(item_id=str(md.get("item_id") or ""), review_id=str(md.get("review_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type == "broadcast_message":
        return _hide_broadcast_message(session_id=str(md.get("session_id") or ""), message_id=content_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "story":
        return _hide_story(story_id=str(md.get("story_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type == "clip":
        return _hide_clip(clip_id=str(md.get("clip_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    logger.warning("moderation_hide: unsupported content_type %s", content_type)'''

HIDE_OWNER_ANCHOR = '''        if content_type == "syndicate_post":
            # MOD-SYND
            _sid = str(md.get("syndicate_id") or "")
            _pid = str(md.get("post_id") or content_id)
            if not _sid:
                return None
            _it = T.syndicate_posts.get_item(Key={"pk": f"SYND#{_sid}", "sk": f"POST#{_pid}"}).get("Item") or {}
            return _it.get("author_id")
    except Exception:'''
HIDE_OWNER = '''        if content_type == "syndicate_post":
            # MOD-SYND
            _sid = str(md.get("syndicate_id") or "")
            _pid = str(md.get("post_id") or content_id)
            if not _sid:
                return None
            _it = T.syndicate_posts.get_item(Key={"pk": f"SYND#{_sid}", "sk": f"POST#{_pid}"}).get("Item") or {}
            return _it.get("author_id")
        if content_type in ("profile_photo", "user", "account"):
            return str(md.get("profile_user_id") or content_id) or None
        if content_type == "catalog_item":
            _cid = str(md.get("category_id") or "")
            _iid = str(md.get("item_id") or content_id)
            if not _cid:
                return None
            _it = T.catalog.get_item(Key={"PK": f"CAT#{_cid}", "SK": f"ITEM#{_iid}"}).get("Item") or {}
            return _it.get("creator_id")
        if content_type == "catalog_review":
            _iid = str(md.get("item_id") or "")
            _rid = str(md.get("review_id") or content_id)
            if not _iid:
                return None
            _it = T.catalog.get_item(Key={"PK": f"ITEM#{_iid}", "SK": f"REVIEW#{_rid}"}).get("Item") or {}
            return _it.get("reviewer")
        if content_type == "broadcast_message":
            _bsid = str(md.get("session_id") or "")
            if not _bsid:
                return None
            _bsk = _bcast_msg_sort_key(_bsid, content_id)
            if not _bsk:
                return None
            _it = T.broadcast_chat_messages.get_item(Key={"session_id": _bsid, "sort_key": _bsk}).get("Item") or {}
            return _it.get("sender_id")
        if content_type == "story":
            _stid = str(md.get("story_id") or content_id)
            _it = ddb.Table(APP_TABLE).get_item(Key={"pk": f"STORY#{_stid}", "sk": "META"}).get("Item") or {}
            return _it.get("author_id")
        if content_type == "clip":
            _clid = str(md.get("clip_id") or content_id)
            _it = T.broadcast_clips.get_item(Key={"clip_id": _clid}).get("Item") or {}
            return _it.get("creator_user_id")
    except Exception:'''

# ─────────────────────────── moderation_delete.py ────────────────────────────
DEL_FUNCS = '''def _delete_user_account(user_sub: str) -> Optional[str]:
    # MODX-11: account-level moderation NEVER hard-deletes the account (ban is the
    # account remedy). Terminal-delete is a safe no-op that just returns the owner.
    return user_sub or None


def _delete_catalog_item(category_id: str, item_id: str) -> Optional[str]:
    if not category_id or not item_id:
        return None
    key = {"PK": f"CAT#{category_id}", "SK": f"ITEM#{item_id}"}
    item = T.catalog.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    owner = item.get("creator_id")
    T.catalog.delete_item(Key=key)
    return owner


def _delete_catalog_review(item_id: str, review_id: str) -> Optional[str]:
    if not item_id or not review_id:
        return None
    key = {"PK": f"ITEM#{item_id}", "SK": f"REVIEW#{review_id}"}
    item = T.catalog.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    owner = item.get("reviewer")
    T.catalog.delete_item(Key=key)
    return owner


def _delete_broadcast_message(session_id: str, message_id: str) -> Optional[str]:
    if not session_id or not message_id:
        return None
    from app.services.broadcast_chat_store import _find_sort_key
    sk = _find_sort_key(session_id, message_id)
    if not sk:
        return None
    key = {"session_id": session_id, "sort_key": sk}
    item = T.broadcast_chat_messages.get_item(Key=key).get("Item") or {}
    owner = item.get("sender_id")
    T.broadcast_chat_messages.delete_item(Key=key)
    return owner


def _delete_story(story_id: str) -> Optional[str]:
    if not story_id:
        return None
    key = {"pk": f"STORY#{story_id}", "sk": "META"}
    item = ddb.Table(APP_TABLE).get_item(Key=key).get("Item") or {}
    if not item:
        return None
    owner = item.get("author_id")
    ddb.Table(APP_TABLE).delete_item(Key=key)
    return owner


def _delete_clip(clip_id: str) -> Optional[str]:
    if not clip_id:
        return None
    key = {"clip_id": clip_id}
    item = T.broadcast_clips.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    owner = item.get("creator_user_id")
    T.broadcast_clips.delete_item(Key=key)
    return owner


def delete_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None) -> Optional[str]:
    """Hard-delete content for a terminal moderation case. Returns owner id."""
    md = metadata or {}'''
DEL_FUNCS_ANCHOR = '''def delete_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None) -> Optional[str]:
    """Hard-delete content for a terminal moderation case. Returns owner id."""
    md = metadata or {}'''

DEL_DISPATCH_ANCHOR = '''        if content_type == "profile_photo":
            return _delete_profile_photo(content_id)
    except Exception:'''
DEL_DISPATCH = '''        if content_type in ("user", "account"):
            return _delete_user_account(content_id)
        if content_type == "catalog_item":
            return _delete_catalog_item(str(md.get("category_id") or ""), str(md.get("item_id") or content_id))
        if content_type == "catalog_review":
            return _delete_catalog_review(str(md.get("item_id") or ""), str(md.get("review_id") or content_id))
        if content_type == "broadcast_message":
            return _delete_broadcast_message(str(md.get("session_id") or ""), content_id)
        if content_type == "story":
            return _delete_story(str(md.get("story_id") or content_id))
        if content_type == "clip":
            return _delete_clip(str(md.get("clip_id") or content_id))
        if content_type == "profile_photo":
            return _delete_profile_photo(content_id)
    except Exception:'''

# ─────────────────────────── moderation.py (router) ──────────────────────────
LIT_A = 'content_type: Literal["feed_post", "feed_comment", "feed_media", "message", "message_media", "video", "video_comment", "syndicate_post", "profile_photo"]'
LIT_B = 'content_type: Literal["feed_post", "feed_comment", "feed_media", "message", "message_media", "video", "video_comment", "syndicate_post", "profile_photo", "user", "account", "catalog_item", "catalog_review", "broadcast_message", "story", "clip"]'

FIELDS_A = '''    syndicate_id: Optional[str] = Field(default=None, max_length=256)

    @field_validator("topics")'''
FIELDS_B = '''    syndicate_id: Optional[str] = Field(default=None, max_length=256)
    category_id: Optional[str] = Field(default=None, max_length=256)
    item_id: Optional[str] = Field(default=None, max_length=256)
    review_id: Optional[str] = Field(default=None, max_length=256)
    session_id: Optional[str] = Field(default=None, max_length=256)
    story_id: Optional[str] = Field(default=None, max_length=256)
    clip_id: Optional[str] = Field(default=None, max_length=256)
    profile_user_id: Optional[str] = Field(default=None, max_length=256)

    @field_validator("topics")'''

PHOTO_EXISTS_A = '''def _profile_photo_exists(user_id: str) -> bool:
    item = T.profile.get_item(Key={"user_id": user_id}).get("Item") or {}
    return bool(item.get("profile_photo_url"))'''
PHOTO_EXISTS_B = '''def _profile_photo_exists(user_id: str) -> bool:
    # MODX-10: T.profile is keyed by user_sub and stores the photo NESTED under
    # `profile`; the prior top-level/user_id read always missed -> photo reports 404'd.
    item = T.profile.get_item(Key={"user_sub": user_id}).get("Item") or {}
    profile = item.get("profile") or {}
    return bool(profile.get("profile_photo_url"))


def _user_exists(user_id: str) -> bool:
    # MODX-11: an account is reportable even with NO profile photo.
    try:
        if T.users.get_item(Key={"user_sub": user_id}).get("Item"):
            return True
    except Exception:
        pass
    return bool(T.profile.get_item(Key={"user_sub": user_id}).get("Item"))'''

VALIDATE_A = '''    if inp.content_type == "profile_photo":
        if not _profile_photo_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")'''
VALIDATE_B = '''    if inp.content_type in ("user", "account"):
        if not _user_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "catalog_item":
        if not inp.category_id:
            raise HTTPException(status_code=400, detail="category_id is required for catalog_item")
        _ci = T.catalog.get_item(Key={"PK": f"CAT#{inp.category_id}", "SK": f"ITEM#{inp.content_id}"}).get("Item")
        if not _ci:
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "catalog_review":
        if not inp.item_id:
            raise HTTPException(status_code=400, detail="item_id is required for catalog_review")
        _cr = T.catalog.get_item(Key={"PK": f"ITEM#{inp.item_id}", "SK": f"REVIEW#{inp.content_id}"}).get("Item")
        if not _cr:
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "broadcast_message":
        if not inp.session_id:
            raise HTTPException(status_code=400, detail="session_id is required for broadcast_message")
        from app.services.broadcast_chat_store import _find_sort_key
        if not _find_sort_key(inp.session_id, inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "story":
        from app.services.stories import get_story
        if not get_story(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "clip":
        from app.services.broadcast_clip import get_clip
        _cl = get_clip(inp.content_id)
        if not _cl or not _cl.get("clip_id"):
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "profile_photo":
        if not _profile_photo_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")'''

META_A = '''                "video_id": getattr(inp, "video_id", None),
                "syndicate_id": getattr(inp, "syndicate_id", None),
            },
            now_ts=now_ts,
        )'''
META_B = '''                "video_id": getattr(inp, "video_id", None),
                "syndicate_id": getattr(inp, "syndicate_id", None),
                "category_id": getattr(inp, "category_id", None),
                "item_id": getattr(inp, "item_id", None),
                "review_id": getattr(inp, "review_id", None),
                "session_id": getattr(inp, "session_id", None),
                "story_id": getattr(inp, "story_id", None),
                "clip_id": getattr(inp, "clip_id", None),
                "profile_user_id": getattr(inp, "profile_user_id", None),
            },
            now_ts=now_ts,
        )'''

# ─────────────────────────── moderation_flags.py ─────────────────────────────
FLAGS_A = '''    if ctype == "profile_photo" and not bool(flags.get("report_profile_enabled", True)):
        raise HTTPException(status_code=403, detail="profile reporting is disabled")'''
FLAGS_B = '''    if ctype == "profile_photo" and not bool(flags.get("report_profile_enabled", True)):
        raise HTTPException(status_code=403, detail="profile reporting is disabled")
    if ctype in ("user", "account") and not bool(flags.get("report_account_enabled", True)):
        raise HTTPException(status_code=403, detail="account reporting is disabled")
    if ctype in ("catalog_item", "catalog_review") and not bool(flags.get("report_commerce_enabled", True)):
        raise HTTPException(status_code=403, detail="commerce reporting is disabled")
    if ctype == "broadcast_message" and not bool(flags.get("report_livechat_enabled", True)):
        raise HTTPException(status_code=403, detail="live chat reporting is disabled")
    if ctype in ("story", "clip") and not bool(flags.get("report_ephemeral_enabled", True)):
        raise HTTPException(status_code=403, detail="ephemeral reporting is disabled")'''

# ─────────────────────────── profile.py ──────────────────────────────────────
PROF_HELPER_A = 'def _profile_lookup_etag(body: dict) -> str:'
PROF_HELPER_B = '''def _account_moderation_hidden(user_sub: str) -> bool:
    # MODX-11: True when an account-level moderation hold hides this profile.
    try:
        item = T.profile.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    except Exception:
        return False
    return bool(item.get("moderation_hidden") or item.get("moderation_removed"))


def _profile_lookup_etag(body: dict) -> str:'''

PROF_CHECK_A = '''        viewer_sub = ctx.get("user_sub")
    except Exception:
        pass

    if viewer_sub and viewer_sub != user_sub:'''
PROF_CHECK_B = '''        viewer_sub = ctx.get("user_sub")
    except Exception:
        pass

    # MODX-11: an account-level moderation hold hides the profile from everyone but
    # the owner (who keeps access so they can respond / appeal).
    if _account_moderation_hidden(user_sub) and viewer_sub != user_sub:
        raise HTTPException(status_code=404, detail="Profile not found")

    if viewer_sub and viewer_sub != user_sub:'''

# ─────────────────────────── broadcast_chat_store.py ─────────────────────────
CHAT_A = '"FilterExpression": Attr("deleted").ne(True) & Attr("kind").ne("private_chat"),'
CHAT_B = '"FilterExpression": Attr("deleted").ne(True) & Attr("kind").ne("private_chat") & Attr("moderation_hidden").ne(True),'

# ─────────────────────────── broadcast_clip.py ───────────────────────────────
CLIP_GET_A = '    if not item or item.get("status") == "deleted":\n        raise HTTPException(404, "Clip not found")'
CLIP_GET_B = '    if not item or item.get("status") == "deleted" or item.get("moderation_hidden") is True:\n        raise HTTPException(404, "Clip not found")'
CLIP_LIST_A = 'FilterExpression=Attr("status").ne("deleted"),'
CLIP_LIST_B = 'FilterExpression=Attr("status").ne("deleted") & Attr("moderation_hidden").ne(True),'

# ─────────────────────────── stories.py ──────────────────────────────────────
STORY_LIST_A = '''        items = [
            it for it in items
            if int(it.get("expires_at", 0)) > now or it.get("highlighted") is True
        ]
    return items'''
STORY_LIST_B = '''        items = [
            it for it in items
            if int(it.get("expires_at", 0)) > now or it.get("highlighted") is True
        ]
    # MODX-12: drop moderation-hidden stories from listings (reversible on reinstate).
    items = [it for it in items if not (it.get("moderation_hidden") or it.get("moderation_removed"))]
    return items'''
STORY_BAR_A = '        active = [it for it in items if int(it.get("expires_at", 0)) > now or it.get("highlighted") is True]'
STORY_BAR_B = '        active = [it for it in items if (int(it.get("expires_at", 0)) > now or it.get("highlighted") is True) and not (it.get("moderation_hidden") or it.get("moderation_removed"))]'

# ─────────────────────────── catalog.py ──────────────────────────────────────
CAT_ITEM_A = '''    for item in items:
        if item.get("entity") != "item":
            continue
        # GEO-001 (GAP-0216): drop items the viewer's region is blocked from.'''
CAT_ITEM_B = '''    for item in items:
        if item.get("entity") != "item":
            continue
        # MODX-12: hide moderation-held catalog items from non-owners.
        if (item.get("moderation_hidden") or item.get("moderation_removed")) and item.get("creator_id") != ctx["user_sub"]:
            continue
        # GEO-001 (GAP-0216): drop items the viewer's region is blocked from.'''
CAT_REVIEW_A = '''    for item in items:
        if item.get("entity") != "review":
            continue
        out.append('''
CAT_REVIEW_B = '''    for item in items:
        if item.get("entity") != "review":
            continue
        # MODX-12: hide moderation-held reviews.
        if item.get("moderation_hidden") or item.get("moderation_removed"):
            continue
        out.append('''


def patch(path, edits, allow_multi=False):
    # edits: list of (anchor, replacement, guard). guard is a string that is
    # present ONLY after the edit is applied (used for idempotency when the anchor
    # is a substring of the replacement).
    s = open(path, encoding="utf-8").read()
    ok = True
    for a, b, guard in edits:
        if guard in s:
            print("  already applied:", path, "::", guard[:56])
            continue
        n = s.count(a)
        if allow_multi:
            if n == 0:
                print("  ANCHOR MISS (0) in %s :: %s" % (path, a[:56]))
                ok = False
                continue
        elif n != 1:
            print("  ANCHOR MISS (%d) in %s :: %s" % (n, path, a[:56]))
            ok = False
            continue
        s = s.replace(a, b)
    open(path, "w", encoding="utf-8").write(s)
    return ok


ok = True
print("moderation_hide.py:")
ok &= patch(HIDE, [
    (HIDE_FUNCS_ANCHOR, HIDE_FUNCS, "def _hide_profile_photo("),
    (HIDE_DISPATCH_ANCHOR, HIDE_DISPATCH, "return _hide_profile_photo(user_sub="),
    (HIDE_OWNER_ANCHOR, HIDE_OWNER, 'if content_type in ("profile_photo", "user", "account"):'),
])
print("moderation_delete.py:")
ok &= patch(DEL, [
    (DEL_FUNCS_ANCHOR, DEL_FUNCS, "def _delete_catalog_item("),
    (DEL_DISPATCH_ANCHOR, DEL_DISPATCH, 'if content_type in ("user", "account"):'),
])
print("moderation.py:")
ok &= patch(ROUTER, [
    (LIT_A, LIT_B, '"catalog_item", "catalog_review", "broadcast_message"'),
    (FIELDS_A, FIELDS_B, "profile_user_id: Optional[str] = Field"),
    (PHOTO_EXISTS_A, PHOTO_EXISTS_B, "def _user_exists("),
    (VALIDATE_A, VALIDATE_B, 'if inp.content_type == "catalog_item":'),
    (META_A, META_B, '"profile_user_id": getattr(inp'),
])
print("moderation_flags.py:")
ok &= patch(FLAGS, [(FLAGS_A, FLAGS_B, "account reporting is disabled")])
print("profile.py:")
ok &= patch(PROFILE, [
    (PROF_HELPER_A, PROF_HELPER_B, "def _account_moderation_hidden("),
    (PROF_CHECK_A, PROF_CHECK_B, "an account-level moderation hold hides the profile"),
])
print("broadcast_chat_store.py:")
ok &= patch(CHAT, [(CHAT_A, CHAT_B, 'Attr("kind").ne("private_chat") & Attr("moderation_hidden")')], allow_multi=True)
print("broadcast_clip.py:")
ok &= patch(CLIP, [(CLIP_GET_A, CLIP_GET_B, 'item.get("moderation_hidden") is True')], allow_multi=True)
ok &= patch(CLIP, [(CLIP_LIST_A, CLIP_LIST_B, 'Attr("status").ne("deleted") & Attr("moderation_hidden")')], allow_multi=True)
print("stories.py:")
ok &= patch(STORIES, [
    (STORY_LIST_A, STORY_LIST_B, "drop moderation-hidden stories"),
    (STORY_BAR_A, STORY_BAR_B, 'is True) and not (it.get("moderation_hidden")'),
])
print("catalog.py:")
ok &= patch(CATALOG, [
    (CAT_ITEM_A, CAT_ITEM_B, "hide moderation-held catalog items"),
    (CAT_REVIEW_A, CAT_REVIEW_B, "hide moderation-held reviews"),
])
print("RESULT:", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
