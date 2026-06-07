# GAP-0313: `_presence_event_cache` is an in-process dict that will not persist across worker restarts or scale to multiple processes

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: MSG-004 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/MSG-004.md`); see also `docs/tickets/writeups/MSG-004.md`

## Location
`_presence_event_cache`

## Problem / Impact
if the backend is restarted frequently, every restart floods all conversation partners with presence:update events; in a multi-worker deployment each worker fires its own cooldown-less burst

## Fix
store cooldown timestamps in DynamoDB (TTL-based) or Redis rather than in-process dict

## Notes
This gap was identified by the second-pass as-built review of MSG-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
