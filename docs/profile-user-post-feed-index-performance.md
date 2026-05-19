# Profile Feed Author-Scoped Index Performance Notes (PUF-005)

## Scope
Ticket: **PUF-005 — Add/verify indexes for author-scoped feed performance**.

This note records the index strategy, query-path updates, and latency/read-path expectations for profile-mode feed requests.

## Index Strategy
- Existing DynamoDB table (`app_single_table`) already exposes `GSI2` (`GSI2PK`, `GSI2SK`).
- We now index Post rows for author-timeline retrieval:
  - `GSI2PK = POST_AUTHOR#{author_id}`
  - `GSI2SK = {created_at}#POST#{post_id}`

This provides deterministic ordering aligned with `created_at desc, post_id desc` via `ScanIndexForward=False` and lexicographic tie-breaking on `post_id`.

## Query Plan Evidence

### Before (author mode)
- `GET /feed?author_id=...` queried viewer feed refs via `GSI1PK=FEED#{viewer}` and filtered in application code.
- Cost scaled with viewer feed density, not target author post density.

### After (author mode)
- `GET /feed?author_id=...` queries `GSI2PK=POST_AUTHOR#{author_id}` directly.
- Candidate rows are already author-scoped, reducing non-matching reads before additional filters (`q`, `from`, `to`, `has_media`).

### Non-author (general feed) mode
- Query path remains on `GSI1PK=FEED#{viewer}`.
- No index behavior changes for non-author mode.

## Data Migration
A backfill migration is included for existing post records:
- `scripts/migrations/20260326_newsfeed_post_author_gsi2_backfill.py`

It scans `Entity=Post` rows and sets missing `GSI2PK/GSI2SK` fields idempotently.

## Latency Notes (Expected)
- **Profile author mode:** lower p95 expected due to author-indexed retrieval path replacing broad viewer-feed scan-and-filter.
- **General feed mode:** no material change expected because it still uses `GSI1` path.

## Rollout Safety
1. Deploy code that writes `GSI2PK/GSI2SK` on new posts.
2. Run backfill migration for historical posts.
3. Monitor profile feed latency/error metrics after cutover.

Rollback: if needed, route can revert to legacy `GSI1` viewer-feed path without schema rollback.
