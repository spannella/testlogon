#!/usr/bin/env python3
"""MOD-A1..A3 idempotent, anchor-based source patcher.

Runs on both the dev clone and prod (they diverge only outside these anchors).
Writes a per-file .bak_moda_<ts>. Reports PATCHED / SKIPPED_ALREADY / MISSING
for every edit. MISSING on any edit => non-zero exit (do not restart).
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
    for edit in edits:
        name, old, new, marker = edit[0], edit[1], edit[2], edit[3]
        optional = edit[4] if len(edit) > 4 else False
        if marker in src:
            results.append(("SKIPPED_ALREADY", relpath, name))
            continue
        if old not in src:
            if optional:
                results.append(("OPTIONAL_ABSENT", relpath, name))
            else:
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
        with open(path + ".bak_moda_%d" % TS, "w", encoding="utf-8") as b:
            b.write(original)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)


# ── settings.py: new table name ─────────────────────────────────────────────
patch("app/core/settings.py", [(
    "moderation_cases_table_name",
    (
        '    moderation_tickets_table_name: str = os.environ.get(\n'
        '        "DDB_MODERATION_TICKETS",\n'
        '        "ModerationTickets",\n'
        '    )\n'
    ),
    (
        '    moderation_tickets_table_name: str = os.environ.get(\n'
        '        "DDB_MODERATION_TICKETS",\n'
        '        "ModerationTickets",\n'
        '    )\n'
        '    moderation_cases_table_name: str = os.environ.get(\n'
        '        "DDB_MODERATION_CASES",\n'
        '        "ModerationCases",\n'
        '    )\n'
    ),
    "moderation_cases_table_name",
)])

# ── core/tables.py: dataclass field + assignment ────────────────────────────
patch("app/core/tables.py", [
    (
        "dataclass field moderation_cases",
        "    moderation_tickets: Any\n",
        "    moderation_tickets: Any\n    moderation_cases: Any\n",
        "moderation_cases: Any",
    ),
    (
        "table assignment moderation_cases",
        "    moderation_tickets=_safe_table(S.moderation_tickets_table_name),\n",
        "    moderation_tickets=_safe_table(S.moderation_tickets_table_name),\n"
        '    moderation_cases=_safe_table(getattr(S, "moderation_cases_table_name", "ModerationCases")),\n',
        "moderation_cases=_safe_table",
    ),
])

# ── scripts/local-ddb-init.py: TableDef with ByState GSI ────────────────────
patch("scripts/local-ddb-init.py", [(
    "ModerationCases TableDef",
    (
        '        TableDef(\n'
        '            _resolve_table_name(S.content_reports_table_name, "ContentReports"),'
    ),
    (
        '        # Moderation Cases (MOD-A1) — one case per reported content ref; the\n'
        '        # non-destructive hide state machine. ByState GSI feeds the 30d sweep.\n'
        '        TableDef(\n'
        '            _resolve_table_name(getattr(S, "moderation_cases_table_name", "ModerationCases"), "ModerationCases"),\n'
        '            "case_id",\n'
        '            gsi=[\n'
        '                {"index_name": "ByState", "partition_key": "state", "sort_key": "hold_until"},\n'
        '            ],\n'
        '            attr_types={"hold_until": "N"},\n'
        '        ),\n'
        '        TableDef(\n'
        '            _resolve_table_name(S.content_reports_table_name, "ContentReports"),'
    ),
    '"moderation_cases_table_name", "ModerationCases"',
)])

# ── moderation.py: 6 categories + wire on_report_filed ──────────────────────
patch("app/routers/moderation.py", [
    (
        "6 categories (back-compat)",
        'ALLOWED_TOPICS = {"sexual", "extortion", "criminal", "spam", "racist"}',
        'ALLOWED_TOPICS = {"sexual", "extortion", "criminal", "spam", "racist", "harassment", "hate", "violence_threats", "other"}',
        '"violence_threats"',
    ),
    (
        "wire on_report_filed (auto-hide + notify)",
        (
            '        metadata={"topics": inp.topics},\n'
            '    )\n'
            '    write_alert(\n'
            '        reporter_user_id,\n'
            '        event="moderation_report_received",\n'
            '        outcome="success",\n'
            '        title="Report received",\n'
            '        details={"report_id": report_id, "ticket_id": ticket_id, "status": "submitted"},'
        ),
        (
            '        metadata={"topics": inp.topics},\n'
            '    )\n'
            '    # MOD-A3: aggregate the report onto the moderation_case, apply the guarded\n'
            '    # auto-hide (severe=1 report; lower>=3 or trusted reporter), and notify the\n'
            '    # poster when hidden. Best-effort: never breaks the report write.\n'
            '    try:\n'
            '        from app.services import moderation_case as _mod_case\n'
            '        _mod_case.on_report_filed(\n'
            '            content_type=inp.content_type,\n'
            '            content_id=inp.content_id,\n'
            '            topics=inp.topics,\n'
            '            reporter_user_id=reporter_user_id,\n'
            '            ticket_id=ticket_id,\n'
            '            metadata={\n'
            '                "post_id": inp.post_id,\n'
            '                "conversation_id": inp.conversation_id,\n'
            '                "media_index": inp.media_index,\n'
            '                "video_id": getattr(inp, "video_id", None),\n'
            '            },\n'
            '            now_ts=now_ts,\n'
            '        )\n'
            '    except Exception:\n'
            '        logger.exception("moderation_case.on_report_filed failed (report still recorded)")\n'
            '    write_alert(\n'
            '        reporter_user_id,\n'
            '        event="moderation_report_received",\n'
            '        outcome="success",\n'
            '        title="Report received",\n'
            '        details={"report_id": report_id, "ticket_id": ticket_id, "status": "submitted"},'
        ),
        "on_report_filed",
    ),
])

# ── newsfeed.py: owner-aware read filters (non-destructive hide) ─────────────
patch("app/routers/newsfeed.py", [
    (
        "feed list site A (user_id)",
        '                if post.get("moderation_removed") or post.get("moderation_removed_at"):\n                    continue',
        '                if (post.get("moderation_removed") or post.get("moderation_removed_at")) and post.get("user_id") != user_id:\n                    continue',
        'moderation_removed_at")) and post.get("user_id") != user_id:\n                    continue',
    ),
    (
        "feed list site B (user_id)",
        '        if post.get("moderation_removed") or post.get("moderation_removed_at"):\n            continue',
        '        if (post.get("moderation_removed") or post.get("moderation_removed_at")) and post.get("user_id") != user_id:\n            continue',
        'moderation_removed_at")) and post.get("user_id") != user_id:\n            continue',
        True,
    ),
    (
        "for-you _exclude site C (viewer_id)",
        '        if post.get("moderation_removed") or post.get("moderation_removed_at"):\n            return True',
        '        if (post.get("moderation_removed") or post.get("moderation_removed_at")) and post.get("user_id") != viewer_id:\n            return True',
        'moderation_removed_at")) and post.get("user_id") != viewer_id:\n            return True',
        True,
    ),
    (
        "comments list owner-aware",
        '        for it in resp.get("Items", [])\n        if not it.get("moderation_removed")',
        '        for it in resp.get("Items", [])\n        if (not it.get("moderation_removed")) or it.get("user_id") == user_id',
        'if (not it.get("moderation_removed")) or it.get("user_id") == user_id',
    ),
    (
        "single-GET owner-aware (fixes leak)",
        (
            'def get_post(post_id: str, user_id: UserIdDep):\n'
            '    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})\n'
            '    if not post:\n'
            '        raise HTTPException(status_code=404, detail="Post not found")\n'
            '    author = post.get("user_id")\n'
        ),
        (
            'def get_post(post_id: str, user_id: UserIdDep):\n'
            '    post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})\n'
            '    if not post:\n'
            '        raise HTTPException(status_code=404, detail="Post not found")\n'
            '    author = post.get("user_id")\n'
            '    if (post.get("moderation_removed") or post.get("moderation_removed_at")) and author != user_id:\n'
            '        raise HTTPException(status_code=404, detail="Post not found")\n'
        ),
        "and author != user_id:\n        raise HTTPException(status_code=404, detail=\"Post not found\")",
    ),
])

# ── messaging.py: owner-aware message hide (sender keeps owner-view) ─────────
patch("app/routers/messaging.py", [(
    "message filter owner-aware",
    '    if message_item.get("moderation_hidden") or message_item.get("moderation_removed_at"):\n        return False',
    '    if message_item.get("moderation_hidden") or message_item.get("moderation_removed_at"):\n        if message_item.get("sender_id") != user_id:\n            return False',
    'if message_item.get("sender_id") != user_id:\n            return False',
)])

# ── group_feed.py: add the missing owner-aware moderation filter ─────────────
patch("app/services/group_feed.py", [(
    "group feed owner-aware filter",
    '        post = post_map.get(pid)\n        if not post:\n            continue\n        result_posts.append(_post_out(post, viewer_id=viewer_id))',
    '        post = post_map.get(pid)\n        if not post:\n            continue\n        if (post.get("moderation_removed") or post.get("moderation_removed_at")) and post.get("user_id") != viewer_id:\n            continue\n        result_posts.append(_post_out(post, viewer_id=viewer_id))',
    'moderation_removed_at")) and post.get("user_id") != viewer_id:\n            continue\n        result_posts.append',
)])

# ── video_comments.py: viewer_id param + owner-aware hide filter ─────────────
# Prod's video_comments.py diverges (already has viewer_id + a list-comprehension
# projection). Provide dev-form AND prod-form edits, both optional, sharing one
# marker so whichever env matches applies exactly once.
_VC_MARK = 'item.get("moderation_hidden") or item.get("moderation_removed")) and item.get("user_id") != viewer_id'
patch("app/services/video_comments.py", [
    (
        "list_comments viewer_id param (dev form)",
        'def list_comments(\n    *,\n    video_id: str,\n    cursor: Optional[str] = None,\n    limit: int = 20,\n) -> Dict[str, Any]:',
        'def list_comments(\n    *,\n    video_id: str,\n    viewer_id: Optional[str] = None,\n    cursor: Optional[str] = None,\n    limit: int = 20,\n) -> Dict[str, Any]:',
        "viewer_id: Optional[str] = None,\n    cursor: Optional[str] = None,",
        True,
    ),
    (
        "video comment owner-aware filter (dev form)",
        '    comments = []\n    for item in items_raw:\n        comments.append({',
        '    comments = []\n    for item in items_raw:\n        if (' + _VC_MARK + ':\n            continue\n        comments.append({',
        _VC_MARK,
        True,
    ),
    (
        "video comment owner-aware filter (prod form)",
        '    comments = [_comment_projection(item, viewer_id=viewer_id) for item in items_raw]',
        '    comments = [_comment_projection(item, viewer_id=viewer_id) for item in items_raw if not ((' + _VC_MARK + ')]',
        _VC_MARK,
        True,
    ),
])

print("=== MOD-A apply @ ROOT=%s ts=%d ===" % (ROOT, TS))
for status, rel, name in results:
    print("  %-18s %-34s %s" % (status, rel, name))
print("FAIL" if fail else "ALL_OK")
sys.exit(1 if fail else 0)
