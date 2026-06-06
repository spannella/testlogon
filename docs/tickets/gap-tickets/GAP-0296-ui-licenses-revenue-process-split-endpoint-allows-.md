# GAP-0296: `/ui/licenses/revenue/process-split` endpoint allows any user to trigger arbitrary splits

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: LICENSE-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/LICENSE-003.md`); see also `docs/tickets/writeups/LICENSE-003.md`

## Location
`/ui/licenses/revenue/process-split`

## Problem / Impact
Any authenticated user can POST to this endpoint to manually fire revenue splits with any `content_id`, `licensee_id`, and `source_amount_cents`; this is a test-only endpoint inadvertently exposed in production code

## Fix
gate behind `require_admin_or_root` or `S.dev_mode` flag; remove from production router

## Notes
This gap was identified by the second-pass as-built review of LICENSE-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
