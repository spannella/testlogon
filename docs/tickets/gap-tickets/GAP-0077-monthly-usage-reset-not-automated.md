# GAP-0077: monthly usage reset not automated

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-001 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-001.md`); see also `docs/tickets/writeups/AGENT-001.md`

## Location
`app/services/llm_provider_keys.py:310`

## Problem / Impact
usage_reset_at stored but no background task zeros current_month_usage_cents at month boundary

## Fix
add daily startup task scanning for expired usage_reset_at and resetting

## Notes
This gap was identified by the second-pass as-built review of AGENT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
