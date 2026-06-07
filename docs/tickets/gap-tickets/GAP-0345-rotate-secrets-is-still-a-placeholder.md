# GAP-0345: `rotate-secrets` is still a placeholder

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: ROOTCTL-001 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/ROOTCTL-001.md`); see also `docs/tickets/writeups/ROOTCTL-001.md`

## Location
`rotate-secrets`

## Problem / Impact
command parses and audits but calls `_placeholder_mutation_command` with no-op return; signing secrets never rotated

## Fix
implement real key rotation (re-generate `UI_ACCESS_TOKEN_SECRET`, `API_KEY_PEPPER`, KMS break-glass key) with audit trail

## Notes
This gap was identified by the second-pass as-built review of ROOTCTL-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Fix landed; see commit on impl/crit-batch-1. Regression test added.
