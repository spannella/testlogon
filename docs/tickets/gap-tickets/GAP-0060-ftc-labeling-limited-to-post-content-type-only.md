# GAP-0060: FTC labeling limited to post content_type only

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADS-013 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADS-013.md`); see also `docs/tickets/writeups/ADS-013.md`

## Location
`app/services/sponsorship_deals.py:_add_ftc_label:272`

## Problem / Impact
video and broadcast sponsored content silently skipped; FTC disclosure not applied

## Fix
extend _add_ftc_label to update T.video_metadata and T.broadcasts for respective content types

## Notes
This gap was identified by the second-pass as-built review of ADS-013. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
