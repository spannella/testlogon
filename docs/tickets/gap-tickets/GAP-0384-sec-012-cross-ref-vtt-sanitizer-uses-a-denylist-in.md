# GAP-0384: SEC-012 cross-ref: VTT sanitizer uses a denylist instead of an allowlist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-021 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-021.md`); see also `docs/tickets/writeups/VOD-021.md`

## Location
`app/services/vod_subtitle_manager.py:123-138`

## Problem / Impact
SEC-012 cross-ref: VTT sanitizer uses a denylist instead of an allowlist

## Fix
replace the denylist with an allowlist parser that strips all tags except `<b>`, `<i>`, `<u>`, `<v NAME>`, `<ruby>`, `<rt>` and removes all attributes from permitted tags (SEC-012 §4.4 design already written at `docs/tickets/writeups/SEC-012.md:181-206`)

## Notes
This gap was identified by the second-pass as-built review of VOD-021. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
