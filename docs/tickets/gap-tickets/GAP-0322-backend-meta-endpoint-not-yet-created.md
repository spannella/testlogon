# GAP-0322: Backend meta endpoint not yet created

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-005 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-005.md`); see also `docs/tickets/writeups/PLATFORM-005.md`

## Location
`app/routers/meta.py`

## Problem / Impact
file does not exist; `app/main.py` has no `meta_router` registration; crawler-detection middleware cannot function without it; social media crawlers still see `<title>Control Panel</title>` for all URLs

## Fix
create `app/routers/meta.py` with `GET /api/meta?url=...`; register in `main.py`; implement `_profile_meta`, `_event_meta`, `_post_meta`, `_video_meta` helpers

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Verified already-built: seo_metadata router + per-entity meta helpers (`_profile_metadata`/`_event_metadata`/`_post_metadata`/`_video_metadata`/`_live_metadata`), the URL→entity dispatcher `metadata_for_path`, and `render_meta_tags` all exist in `app/services/seo_metadata.py` and are exposed by `app/routers/seo_metadata.py` (prefix `/seo`, registered in `app/main.py`). The ticket's premise ("`app/routers/meta.py` does not exist; no backend meta endpoint") is FALSE. The existing `GET /seo/metadata` and `GET /seo/meta-tags` already accept a `path=` query param and dispatch by URL. Added (small): a `url=` alias on both handlers (+ `_resolve_path` helper) so crawler middleware can call the ticket's requested `?url=...` form (a full URL is accepted; only its path is used). Did NOT edit `app/main.py` (router already registered). Added lock-in regression test `tests/test_gap_0322_seo_meta_endpoint.py` (offline, 20 tests, all pass).
