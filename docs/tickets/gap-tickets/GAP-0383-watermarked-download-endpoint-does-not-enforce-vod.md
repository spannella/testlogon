# GAP-0383: watermarked-download endpoint does not enforce VOD-019 download-tier entitlement

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-020 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/VOD-020.md`); see also `docs/tickets/writeups/VOD-020.md`

## Location
`app/routers/watermark.py:106-110`

## Problem / Impact
the endpoint checks `video.allow_download` (global flag) and `video.download_mp4_status == "ready"` but never calls `check_entitlement_purchase_only` to verify `ent.download_allowed`; a viewer who purchased "permanent" tier (download_allowed=False) can call `POST /ui/videos/{id}/download/watermarked` and receive a watermarked MP4, circumventing the download-tier paywall enforced by the plain download endpoint at `app/routers/video_listing.py:800-804`

## Fix
before the cache lookup in `request_watermarked_download`, add the same entitlement check used in `video_listing.py:800-804`

## Notes
This gap was identified by the second-pass as-built review of VOD-020. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
