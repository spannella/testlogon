# GAP-0036: removeFromBlocklist and removeFromAllowlist use wrong /v1/ URL prefix

**Status**: No change needed (verified already-correct, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: ADMIN-003 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/ADMIN-003.md`); see also `docs/tickets/writeups/ADMIN-003.md`

## Location
`frontend/src/api/endpoints/adminRateLimits.ts:67`

## Problem / Impact
DELETE calls target /v1/admin/rate-limits/blocklist/{id} and /v1/admin/rate-limits/allowlist/{id} instead of /ui/admin/rate-limits/...; Vite proxy does not forward /v1/; both DELETE operations silently 404; admins cannot remove entries from blocklist or allowlist via UI

## Fix
change both calls to use /ui/admin/rate-limits/ prefix

## Notes
This gap was identified by the second-pass as-built review of ADMIN-003. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
