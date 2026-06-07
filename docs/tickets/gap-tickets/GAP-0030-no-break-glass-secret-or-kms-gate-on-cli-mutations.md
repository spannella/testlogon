# GAP-0030: No break-glass secret or KMS gate on CLI mutations

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: CRIT (Critical) · **Source ticket**: ROOTCTL-001 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/ROOTCTL-001.md`); see also `docs/tickets/writeups/ROOTCTL-001.md`

## Location
`app/cli/rootctl.py:2006-2018`

## Problem / Impact
anyone with DDB credentials + `--actor-sub` flag can run any mutation; ticket says "only a string-equality requires_root check"

## Fix
add `_require_break_glass_auth()` gate reading `ROOTCTL_BREAK_GLASS_SECRET` env var (or KMS) before any write in `_dispatch_mutation_gate()`

## Notes
This gap was identified by the second-pass as-built review of ROOTCTL-001. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
