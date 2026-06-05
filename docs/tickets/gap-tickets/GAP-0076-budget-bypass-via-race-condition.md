# GAP-0076: budget bypass via race condition

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-001.md`); see also `docs/tickets/writeups/AGENT-001.md`

## Location
`app/services/llm_provider_keys.py:310`

## Problem / Impact
two-step ADD + conditional SET allows concurrent call to read status="active" between writes

## Fix
replace with single atomic UpdateItem or DDB transaction

## Notes
This gap was identified by the second-pass as-built review of AGENT-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
