# GAP-0299: DRM support reduced to AES-128 flag only

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MEDIA-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MEDIA-001.md`); see also `docs/tickets/writeups/MEDIA-001.md`

## Location
`frontend/src/components/shared/MediaPlayer.tsx:79,321-323`

## Problem / Impact
DRM support reduced to AES-128 flag only

## Fix
add `DrmConfig` interface with `licenseUrl`/`token`/`fairplayCertificateUrl`; set `drmSystems` on Hls config and add `licenseXhrSetup` callback; add Safari native FairPlay path

## Notes
This gap was identified by the second-pass as-built review of MEDIA-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
