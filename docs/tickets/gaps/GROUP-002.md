# GROUP-002 gaps

- [MED] Audience field stored on feed index record (`app/services/group_feed.py:123`) but audience enforcement for non-members reads the index record `audience` field (`line:187`), not the authoritative post item — a stale index record (e.g. if post was updated post-creation) could leak a `members_only` post to non-members; the pinned-flag already has a comment noting this drift risk (`line:173-177`) — Fix: filter by audience from the batch-fetched authoritative post item, not the index record — Effort: S

- [LOW] `list_group_feed` raises bare `ValueError("Group not found")` (`app/services/group_feed.py:150`) which the router maps to HTTP 404 (`app/routers/group_feed.py:44`), but a dissolved group raises `ValueError("This group has been dissolved")` which is correctly mapped to 410 — the "group not found" and "dissolved" paths share the same ValueError type; a typo in the message string would map dissolution to 404 instead of 410 — Fix: use distinct exception types (`GroupNotFoundError`, `GroupDissolvedException`) or separate error codes — Effort: S

- [LOW] `delete_group_post` raises bare `PermissionError` (`app/services/group_feed.py:297`) but the router at `app/routers/group_feed.py:113` only catches `ValueError`, not `PermissionError` — a PermissionError from `delete_group_post` will propagate as an unhandled 500 — Fix: add `except PermissionError as e: raise HTTPException(403, str(e))` in the delete handler — Effort: S

- [LOW] `has_more` pagination flag computed as `len(index_records) > limit` before audience filtering (`app/services/group_feed.py:196`) — for non-members who have many `members_only` posts filtered out, `has_more=True` may be returned even when no public posts remain on subsequent pages, causing infinite empty pagination — Fix: compute `has_more` after audience filtering — Effort: S

- [LOW] No feature flag check (`group_feed_enabled`) on the public feed endpoint — `app/routers/group_feed.py` calls `_require_feed_enabled()` on authenticated endpoints but the `public_group_feed_router` at line `119` also calls it; this is correct — no gap here. (Verified clean.)
