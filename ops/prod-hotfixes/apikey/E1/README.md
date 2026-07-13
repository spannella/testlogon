# APIK EPIC E1 — Newsfeed parity (#118)

Closes the newsfeed phantom-registry P0: the API-key route-scope registry pointed at
`/v1/newsfeed*` paths that exist nowhere, so every real newsfeed route (`newsfeed.py`,
mounted with **no prefix**) fell through to `unmapped_route` 403 for any API key even
though the router already carries `Depends(maybe_enforce_api_key_route_policy)`.

## What changed (registry-only; no router/handler code touched)
File: `app/services/api_key_route_scope_registry.py`

- **APIK-E1-1** — Re-pointed the registry at the 66 real newsfeed routes:
  - reads (`GET /feed`, `/feed/capabilities|hidden|interesting`, `GET /posts/{id}`,
    `/posts/{id}/comments|reposts|poll-results|attachments|files`, drafts read,
    `/notifications`, `/sse`, `/uploads/object`, bookmarks read,
    `POST /posts/{id}/video/entitlement` — a no-charge playback-token issue) → `newsfeed:read`
  - author mutations (create/edit/delete post, comment CRUD, reactions/unreact, like/unlike,
    repost, vote/close-poll, drafts CRUD+publish, find-datetime poll CRUD, uploads/image,
    feed hide/unhide/interesting, social follow/unfollow, bookmarks/collections write) → `newsfeed:write`
  - `newsfeed:moderate` maps to no distinct route (all deletes are owner-scoped `write`)
    but remains a valid superset via inheritance (`moderate ⊇ write ⊇ read`).
- **APIK-E1-2 [SECURITY]** — the four money routes
  (`POST /posts/{id}/tip`, `/posts/{id}/reactions/tip`, `/posts/{id}/comments/{cid}/tip`,
  `POST /posts/unlock` paid-unlock) require the **distinct `newsfeed:tips` money scope**,
  never the coarse `newsfeed:write`. `newsfeed:tips` is standalone (no inheritance) so a
  read/write key cannot move money and a tips key cannot author.
- Added the real newsfeed surfaces to `API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES`
  (`/feed`, `/posts`, `/uploads`, `/social`, `/notifications`, `/sse`, `/ui/bookmarks`,
  `/ui/bookmark-collections`) and retired the phantom `/v1/newsfeed` prefix, so the drift
  monitor tracks them. Client telemetry (`POST /telemetry/content-render`,
  `/telemetry/draft-lifecycle`) and `GET /feed/for-you` stay honest **session-only
  exemptions** (API keys get `unmapped_route` 403 there — enforcement reads only the registry).

Newsfeed product phase is already `ga` (enforce) from E0, so these mappings enforce immediately.

## Files
- `apply_apik_e1_patch.py` — idempotent exact-anchor patcher (usage: `python apply_apik_e1_patch.py <repo>/app/services/api_key_route_scope_registry.py`).
- `verify_apik_e1.py` — in-process TestClient verifier on real DDB (`APIK_PHASE=BEFORE|AFTER`), synthetic keys+users, auto-cleaned (0 residue).

## Verify (in-process on PROD DDB, synthetic, auto-cleaned)
BEFORE: newsfeed routes `unmapped_route` 403. AFTER: read→`GET /feed` 200; write→full
create/edit/delete/comment/react/poll lifecycle; wrong scope→403 `api_key_scope_denied`;
money routes require `newsfeed:tips` (write-only 403, tips passes the gate);
UI-session feed unaffected; other keyed products, and `dak_` delegation, unaffected.
