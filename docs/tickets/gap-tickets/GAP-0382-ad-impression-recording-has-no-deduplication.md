# GAP-0382: Ad impression recording has no deduplication

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: VOD-018 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/VOD-018.md`); see also `docs/tickets/writeups/VOD-018.md`

## Location
`app/services/ad_placement.py:253-271`

## Problem / Impact
the ticket security section (6.2) calls out impression deduplication as required; a single authenticated user can call `POST /{video_id}/ad-impression` with `event_type=complete` unlimited times per video per day, inflating creator ad revenue without bound

## Fix
add a DDB conditional write using key `AD_IMP#{date}#USER#{user_id}#VIDEO#{video_id}#SLOT#{slot_index}` with `attribute_not_exists(pk)` to cap one complete event per slot per user per day

## Notes
This gap was identified by the second-pass as-built review of VOD-018. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
