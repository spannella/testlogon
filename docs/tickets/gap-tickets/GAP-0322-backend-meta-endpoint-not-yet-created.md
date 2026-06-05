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
