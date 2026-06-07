# GAP-0334: `analytics_events.py` service not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-019 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-019.md`); see also `docs/tickets/writeups/PLATFORM-019.md`

## Location
`analytics_events.py`

## Problem / Impact
All event-recording functions (`record_page_view`, `record_revenue_event`, `record_subscriber_event`, `record_engagement_event`) are missing; no raw analytics data is ever stored

## Fix
create `app/services/analytics_events.py` with the four recording functions writing to `T.analytics_events`

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-019. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
