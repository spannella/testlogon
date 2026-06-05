# GAP-0362: execute_split uses Python `assert` for financial integrity invariant

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: SYND-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/SYND-003.md`); see also `docs/tickets/writeups/SYND-003.md`

## Location
`assert`

## Problem / Impact
Python assertions are silently disabled when the interpreter runs with the `-O` flag (optimized mode); if the split calculation ever produces a distribution mismatch the assertion passes silently, crediting members with wrong amounts and leaving platform fee inconsistent

## Fix
replace both `assert` statements with `if ... raise HTTPException(500, ...)` or `raise RuntimeError(...)` that will always execute regardless of optimization flags

## Notes
This gap was identified by the second-pass as-built review of SYND-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
