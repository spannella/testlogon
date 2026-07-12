#!/usr/bin/env python3
"""MOD-E/F backend hotfix: enforcement hardening (fail-closed + status + no-scan)
and the SYNDICATE-POST hide-gap closure.

Idempotent, anchor-based source patcher. Runs on BOTH the dev clone and prod
(they diverge only OUTSIDE these anchors). Writes one per-file .bak_modef_<ts>.
Reports PATCHED / SKIPPED_ALREADY / MISSING per edit. Any MISSING => non-zero
exit (do NOT restart).
"""
from __future__ import annotations
import sys, time, os

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
TS = int(time.time())
results = []
fail = False


def patch(relpath, edits):
    global fail
    path = os.path.join(ROOT, relpath)
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    original = src
    for name, old, new, marker in edits:
        if marker in src:
            results.append(("SKIPPED_ALREADY", relpath, name))
            continue
        if old not in src:
            results.append(("MISSING", relpath, name))
            fail = True
            continue
        if src.count(old) != 1:
            results.append(("AMBIGUOUS(%d)" % src.count(old), relpath, name))
            fail = True
            continue
        src = src.replace(old, new, 1)
        results.append(("PATCHED", relpath, name))
    if src != original:
        with open(path + ".bak_modef_%d" % TS, "w", encoding="utf-8") as f:
            f.write(original)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)


# ── 1) moderation_hide.py — syndicate_post non-destructive hide + owner resolve ──
patch("app/services/moderation_hide.py", [
    (
        "H1_syn_hide_fn",
        'def _apply(*, content_type: str, content_id: str, metadata: Dict[str, Any], case_id: str, state: str, hidden: bool) -> Optional[str]:',
        '''def _syndicate_post_key(syndicate_id: str, post_id: str) -> Dict[str, str]:
    return {"pk": f"SYND#{syndicate_id}", "sk": f"POST#{post_id}"}


def _hide_syndicate_post(*, syndicate_id: str, post_id: str, case_id: str, state: str, hidden: bool) -> Optional[str]:
    # MOD-SYND: syndicate posts live in their OWN store (T.syndicate_posts), keyed
    # SYND#{sid}/POST#{pid}. Non-destructive flag write over the intact row so a
    # later reinstate restores it byte-for-byte.
    if not syndicate_id or not post_id:
        return None
    item = T.syndicate_posts.get_item(Key=_syndicate_post_key(syndicate_id, post_id)).get("Item") or {}
    if not item:
        return None
    T.syndicate_posts.update_item(
        Key=_syndicate_post_key(syndicate_id, post_id),
        UpdateExpression=_SET_EXPR,
        ExpressionAttributeValues=_flag_values(case_id, state, hidden),
    )
    return item.get("author_id")


def _apply(*, content_type: str, content_id: str, metadata: Dict[str, Any], case_id: str, state: str, hidden: bool) -> Optional[str]:''',
        "_hide_syndicate_post",
    ),
    (
        "H1_syn_apply_branch",
        '''    if content_type == "video_comment":
        return _hide_video_comment(video_id=str(md.get("video_id") or ""), comment_id=content_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "profile_photo":''',
        '''    if content_type == "video_comment":
        return _hide_video_comment(video_id=str(md.get("video_id") or ""), comment_id=content_id, case_id=case_id, state=state, hidden=hidden)
    if content_type == "syndicate_post":
        return _hide_syndicate_post(syndicate_id=str(md.get("syndicate_id") or ""), post_id=str(md.get("post_id") or content_id), case_id=case_id, state=state, hidden=hidden)
    if content_type == "profile_photo":''',
        "return _hide_syndicate_post(syndicate_id=",
    ),
    (
        "H2_syn_resolve_owner",
        '''            return (_row or {}).get("user_id")
    except Exception:
        logger.exception("moderation_hide.resolve_owner failed")''',
        '''            return (_row or {}).get("user_id")
        if content_type == "syndicate_post":
            # MOD-SYND
            _sid = str(md.get("syndicate_id") or "")
            _pid = str(md.get("post_id") or content_id)
            if not _sid:
                return None
            _it = T.syndicate_posts.get_item(Key={"pk": f"SYND#{_sid}", "sk": f"POST#{_pid}"}).get("Item") or {}
            return _it.get("author_id")
    except Exception:
        logger.exception("moderation_hide.resolve_owner failed")''',
        '_sid = str(md.get("syndicate_id")',
    ),
])

# ── 2) moderation_delete.py — syndicate_post terminal hard-delete ──
patch("app/services/moderation_delete.py", [
    (
        "D1_syn_delete_fn",
        'def delete_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None) -> Optional[str]:',
        '''def _delete_syndicate_post(syndicate_id: str, post_id: str) -> Optional[str]:
    # MOD-SYND: terminal hard-delete in the syndicate's own store.
    if not syndicate_id or not post_id:
        return None
    key = {"pk": f"SYND#{syndicate_id}", "sk": f"POST#{post_id}"}
    item = T.syndicate_posts.get_item(Key=key).get("Item") or {}
    if not item:
        return None
    owner = item.get("author_id")
    T.syndicate_posts.delete_item(Key=key)
    return owner


def delete_content(*, content_type: str, content_id: str, metadata: Optional[Dict[str, Any]] = None, case_id: Optional[str] = None) -> Optional[str]:''',
        "_delete_syndicate_post",
    ),
    (
        "D2_syn_delete_branch",
        '''        if content_type == "video_comment":
            return _delete_video_comment(str(md.get("video_id") or ""), content_id)
        if content_type == "profile_photo":''',
        '''        if content_type == "video_comment":
            return _delete_video_comment(str(md.get("video_id") or ""), content_id)
        if content_type == "syndicate_post":
            return _delete_syndicate_post(str(md.get("syndicate_id") or ""), str(md.get("post_id") or content_id))
        if content_type == "profile_photo":''',
        "return _delete_syndicate_post(str(md.get",
    ),
])

# ── 3) syndicate_feed.py — owner-aware moderation-hidden read filter ──
patch("app/services/syndicate_feed.py", [
    (
        "S1_syn_read_filter",
        '''    # Trim to requested limit.
    visible = items[:limit]''',
        '''    # MOD-SYND: owner-aware moderation hide — reported/hidden syndicate posts
    # vanish for everyone except their author (admins use the board). Applied
    # BEFORE the limit trim so a hidden row does not consume a page slot.
    def _mod_hidden_syndicate(p: Dict[str, Any]) -> bool:
        if not (p.get("moderation_hidden") or p.get("moderation_removed") or p.get("moderation_removed_at")):
            return False
        return not (viewer_sub and str(p.get("author_id")) == str(viewer_sub))

    items = [p for p in items if not _mod_hidden_syndicate(p)]

    # Trim to requested limit.
    visible = items[:limit]''',
        "_mod_hidden_syndicate",
    ),
])

# ── 4) routers/moderation.py — accept syndicate_post + syndicate_id + validate + metadata ──
patch("app/routers/moderation.py", [
    (
        "M1_content_type_literal",
        'content_type: Literal["feed_post", "feed_comment", "feed_media", "message", "message_media", "video", "video_comment", "profile_photo"]',
        'content_type: Literal["feed_post", "feed_comment", "feed_media", "message", "message_media", "video", "video_comment", "syndicate_post", "profile_photo"]',
        '"video_comment", "syndicate_post"',
    ),
    (
        "M2_syndicate_id_field",
        '    media_index: Optional[int] = Field(default=None, ge=0)',
        '''    media_index: Optional[int] = Field(default=None, ge=0)
    syndicate_id: Optional[str] = Field(default=None, max_length=256)''',
        "syndicate_id: Optional[str] = Field(default=None, max_length=256)",
    ),
    (
        "M3_validate_branch",
        '''    if inp.content_type == "profile_photo":
        if not _profile_photo_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")''',
        '''    if inp.content_type == "syndicate_post":
        if not inp.syndicate_id:
            raise HTTPException(status_code=400, detail="syndicate_id is required for syndicate_post")
        try:
            from app.services.syndicate_feed import _get_post as _syn_get_post
            _sp = _syn_get_post(inp.syndicate_id, inp.content_id)
        except Exception:
            _sp = None
        if not _sp:
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "profile_photo":
        if not _profile_photo_exists(inp.content_id):
            raise HTTPException(status_code=404, detail="content not found")''',
        "from app.services.syndicate_feed import _get_post as _syn_get_post",
    ),
    (
        "M4_case_metadata",
        '                "video_id": getattr(inp, "video_id", None),',
        '''                "video_id": getattr(inp, "video_id", None),
                "syndicate_id": getattr(inp, "syndicate_id", None),''',
        '"syndicate_id": getattr(inp, "syndicate_id", None),',
    ),
])

# ── 5) moderation_policy_engine.py — fail-CLOSED enforcement + status gating ──
patch("app/services/moderation_policy_engine.py", [
    (
        "P1_imports",
        '''from __future__ import annotations

from typing import Any

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert''',
        '''from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert

logger = logging.getLogger(__name__)''',
        "logger = logging.getLogger(__name__)",
    ),
    (
        "P2_fail_closed",
        '''def is_user_currently_banned(user_sub: str) -> bool:
    if not user_sub:
        return False
    try:
        item = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    except Exception:
        return False
    if str(item.get("status") or "") != BAN_STATUS:
        return False

    ban_until = _coerce_int(item.get("ban_until"), 0)
    if ban_until > 0 and now_ts() >= ban_until:
        return False
    return True''',
        '''# MOD-F1: statuses that gate the authenticated request path. ``banned`` is the
# ban model; ``suspended`` is an admin-imposed hold. Both are enforced; timed
# entries auto-expire via ``ban_until``.
ENFORCED_BLOCK_STATUSES = {BAN_STATUS, "suspended"}


def _load_account_state_or_fail_closed(user_sub: str) -> dict[str, Any]:
    # MOD-F1 (fail-CLOSED): a transient DDB read error must NOT admit a possibly
    # -banned user. Retry briefly, then DENY the request with a 503 rather than
    # silently returning "not banned" (the previous fail-OPEN behavior).
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            return T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
        except Exception as exc:  # noqa: BLE001 - transient DDB error
            last_exc = exc
            time.sleep(0.05 * (attempt + 1))
    logger.error("account_state read failed for %s; failing CLOSED", user_sub, exc_info=last_exc)
    raise HTTPException(status_code=503, detail="account state temporarily unavailable")


def is_user_currently_banned(user_sub: str) -> bool:
    if not user_sub:
        return False
    item = _load_account_state_or_fail_closed(user_sub)
    if str(item.get("status") or "") not in ENFORCED_BLOCK_STATUSES:
        return False

    ban_until = _coerce_int(item.get("ban_until"), 0)
    if ban_until > 0 and now_ts() >= ban_until:
        return False
    return True''',
        "_load_account_state_or_fail_closed",
    ),
])

# ── 6) admin_moderation.py — replace unbounded offender scan with a Key query ──
patch("app/routers/admin_moderation.py", [
    (
        "AM1_no_scan_offender_summary",
        '''    # Best-effort summary from moderation tickets table (future: dedicated offender index).
    scanned = T.moderation_tickets.scan(FilterExpression=Attr("offender_user_id").eq(offender_user_id)).get("Items", [])
    ticket_rows = [r for r in scanned if r.get("entity_type") == "moderation_ticket"]
    open_tickets = sum(1 for r in ticket_rows if str(r.get("status") or "") == "open")

    return OffenderHistorySummaryOut(
        offender_user_id=offender_user_id,
        total_tickets=len(ticket_rows),
        open_tickets=open_tickets,
        total_reports=len(reports),
    )''',
        '''    # MOD-F1: replaced the unbounded full-table moderation_tickets scan with a
    # bounded Key query on user_enforcement_history (keyed by user_id). The
    # offender's prior tickets are the distinct source tickets that produced an
    # enforcement record; "open" counts currently-active enforcements.
    history = _query_enforcement_history(offender_user_id, limit=100)
    distinct_tickets = {str(h.get("source_ticket_id") or "") for h in history if h.get("source_ticket_id")}
    active_enforcements = sum(
        1 for h in history if str(h.get("status") or "").lower() in ("active", "banned", "open")
    )

    return OffenderHistorySummaryOut(
        offender_user_id=offender_user_id,
        total_tickets=len(distinct_tickets),
        open_tickets=active_enforcements,
        total_reports=len(reports),
    )''',
        "MOD-F1: replaced the unbounded full-table",
    ),
])

for status, rel, name in results:
    print(f"{status:20s} {rel}  {name}")
print("MODEF_PATCH_RESULT=%s TS=%d" % ("FAIL" if fail else "OK", TS))
sys.exit(1 if fail else 0)
