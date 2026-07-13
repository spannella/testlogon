#!/usr/bin/env python3
"""APIK EPIC E1 (#118) — newsfeed parity patch (registry re-point + money-gate).

Idempotent, exact-string patch of app/services/api_key_route_scope_registry.py.
Usage: python apply_apik_e1_patch.py /path/to/repo/app/services/api_key_route_scope_registry.py
Re-points the phantom /v1/newsfeed* rollout onto the REAL newsfeed routes
(newsfeed.py, no prefix), maps reads->newsfeed:read, author mutations->newsfeed:write,
tips/paid-unlock->newsfeed:tips (distinct money scope, NOT newsfeed:write), exempts
client telemetry, and adds the real prefixes to the drift-monitor rollout tuple.
"""
import sys, io

READ = [
    "GET:/feed",
    "GET:/feed/capabilities",
    "GET:/feed/hidden",
    "GET:/feed/interesting",
    "GET:/notifications",
    "GET:/posts/drafts",
    "GET:/posts/drafts/{draft_id}",
    "GET:/posts/find-datetime/{poll_id}",
    "GET:/posts/scheduled",
    "GET:/posts/{post_id}",
    "GET:/posts/{post_id}/attachments/{attachment_id}",
    "GET:/posts/{post_id}/comments",
    "GET:/posts/{post_id}/files/{file_index}",
    "GET:/posts/{post_id}/poll-results",
    "GET:/posts/{post_id}/reposts",
    "GET:/sse",
    "GET:/uploads/object",
    "GET:/ui/bookmarks",
    "GET:/ui/bookmarks/status",
    "GET:/ui/bookmark-collections",
    "POST:/posts/{post_id}/video/entitlement",
]
WRITE = [
    "POST:/posts",
    "PATCH:/posts/{post_id}",
    "DELETE:/posts/{post_id}",
    "POST:/posts/{post_id}/cancel",
    "POST:/posts/bulk-archive",
    "POST:/posts/bulk-delete",
    "POST:/posts/drafts",
    "PATCH:/posts/drafts/{draft_id}",
    "DELETE:/posts/drafts/{draft_id}",
    "POST:/posts/drafts/{draft_id}/publish",
    "POST:/posts/find-datetime",
    "POST:/posts/find-datetime/{poll_id}/availability",
    "POST:/posts/find-datetime/{poll_id}/close",
    "POST:/posts/{post_id}/close-poll",
    "POST:/posts/{post_id}/vote",
    "DELETE:/posts/{post_id}/vote",
    "POST:/posts/{post_id}/like",
    "POST:/posts/{post_id}/unlike",
    "POST:/posts/{post_id}/reactions",
    "POST:/posts/{post_id}/unreact",
    "POST:/posts/{post_id}/repost",
    "DELETE:/posts/{post_id}/repost",
    "POST:/posts/{post_id}/comments",
    "PATCH:/posts/{post_id}/comments/{comment_id}",
    "DELETE:/posts/{post_id}/comments/{comment_id}",
    "POST:/posts/{post_id}/comments/{comment_id}/reactions",
    "POST:/posts/{post_id}/comments/{comment_id}/unreact",
    "POST:/uploads/image",
    "POST:/feed/hide",
    "POST:/feed/unhide",
    "POST:/feed/interesting",
    "POST:/feed/uninteresting",
    "POST:/social/refollow",
    "POST:/social/unfollow",
    "POST:/ui/bookmarks",
    "PATCH:/ui/bookmarks/{content_type}/{content_id}",
    "DELETE:/ui/bookmarks/{content_type}/{content_id}",
    "POST:/ui/bookmark-collections",
    "PATCH:/ui/bookmark-collections/{collection_id}",
    "DELETE:/ui/bookmark-collections/{collection_id}",
]
# APIK-E1-2 [SECURITY]: money routes gated by DISTINCT newsfeed:tips (NOT newsfeed:write)
TIPS = [
    "POST:/posts/{post_id}/tip",
    "POST:/posts/{post_id}/reactions/tip",
    "POST:/posts/{post_id}/comments/{comment_id}/tip",
    "POST:/posts/unlock",
]
EXEMPT = {
    "POST:/telemetry/content-render": "client render telemetry, session-auth only, not API-key product traffic",
    "POST:/telemetry/draft-lifecycle": "client draft-lifecycle telemetry, session-auth only, not API-key product traffic",
}

def row(rid, scope):
    return ('    "%s": {"product": "newsfeed", "required_scopes": ["%s"], "entitlement_required": True},'
            % (rid, scope))

def build_rows():
    lines = []
    lines.append("    # Newsfeed -- APIK-E1-1: re-pointed off phantom /v1/newsfeed* onto the REAL")
    lines.append("    # newsfeed.py routes (no prefix). reads->newsfeed:read, author mutations->newsfeed:write.")
    lines.append("    # newsfeed:moderate has no distinct route (all deletes are owner-scoped write) but")
    lines.append("    # remains a valid superset via inheritance (moderate>=write>=read).")
    for r in READ:
        lines.append(row(r, "newsfeed:read"))
    for r in WRITE:
        lines.append(row(r, "newsfeed:write"))
    lines.append("    # APIK-E1-2 [SECURITY] money routes: tips / paid content unlock require the distinct")
    lines.append("    # newsfeed:tips money scope, NEVER the coarse newsfeed:write.")
    for r in TIPS:
        lines.append(row(r, "newsfeed:tips"))
    return "\n".join(lines)

OLD_NF_BLOCK = (
    "    # Newsfeed -- APIK-E0-5: phantom /v1/newsfeed* rows deleted (real routes are /feed, /posts;\n"
    "    # they are re-pointed at real route_ids in EPIC E1). Registry intentionally empty here.\n"
)
OLD_PREFIX = (
    'API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES = (\n'
    '    "/v1/fs",\n'
    '    "/v1/newsfeed",\n'
    '    "/tickets",\n'
    '    "/ui/catalog",\n'
    '    "/ui/shoppingcart",\n'
    '    "/ui/purchase-history",\n'
    '    "/messaging",\n'
    ')\n'
)
NEW_PREFIX = (
    'API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES = (\n'
    '    "/v1/fs",\n'
    '    # APIK-E1-1: real newsfeed surfaces (phantom "/v1/newsfeed" retired).\n'
    '    "/feed",\n'
    '    "/posts",\n'
    '    "/uploads",\n'
    '    "/social",\n'
    '    "/notifications",\n'
    '    "/sse",\n'
    '    "/ui/bookmarks",\n'
    '    "/ui/bookmark-collections",\n'
    '    "/tickets",\n'
    '    "/ui/catalog",\n'
    '    "/ui/shoppingcart",\n'
    '    "/ui/purchase-history",\n'
    '    "/messaging",\n'
    ')\n'
)
EXEMPT_ANCHOR = (
    '    "GET:/feed/for-you": {"reason": "session-auth newsfeed For-You route, not in initial API-key rollout scope"},\n'
)

def main():
    path = sys.argv[1]
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if "APIK-E1-1: re-pointed" in src:
        print("ALREADY_PATCHED", path)
        return

    # 1) newsfeed rows
    assert OLD_NF_BLOCK in src, "newsfeed E0-5 comment anchor not found"
    src = src.replace(OLD_NF_BLOCK, build_rows() + "\n")

    # 2) rollout prefixes
    assert OLD_PREFIX in src, "rollout prefix tuple anchor not found"
    src = src.replace(OLD_PREFIX, NEW_PREFIX)

    # 3) telemetry exemptions
    assert EXEMPT_ANCHOR in src, "for-you exemption anchor not found"
    ex_lines = EXEMPT_ANCHOR
    ex_lines += "    # APIK-E1-1: newsfeed client telemetry is session-only (honest exemption).\n"
    for rid, reason in EXEMPT.items():
        ex_lines += '    "%s": {"reason": "%s"},\n' % (rid, reason)
    src = src.replace(EXEMPT_ANCHOR, ex_lines)

    with io.open(path, "w", encoding="utf-8") as f:
        f.write(src)
    print("PATCHED", path)

if __name__ == "__main__":
    main()
