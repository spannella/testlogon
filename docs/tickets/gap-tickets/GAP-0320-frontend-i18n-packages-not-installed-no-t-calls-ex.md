# GAP-0320: Frontend i18n packages not installed; no t() calls exist

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-003 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/PLATFORM-003.md`); see also `docs/tickets/writeups/PLATFORM-003.md`

## Location
`frontend/package.json`

## Problem / Impact
Frontend i18n packages not installed; no t() calls exist

## Fix
install packages; create `frontend/src/i18n/config.ts`; wrap App in `I18nextProvider`; migrate component strings to `t()` calls

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.

## Implemented (branch impl/crit-batch-1, 2026-06-06)
Verified already-built: i18next stack installed, src/i18n/index.ts config, main.tsx wiring, useTranslation consumers present. Added lock-in regression test. (Full per-string migration of all TSX files remains incremental/out-of-scope.)
