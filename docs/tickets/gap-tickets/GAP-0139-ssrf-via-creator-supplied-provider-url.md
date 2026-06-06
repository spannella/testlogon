# GAP-0139: SSRF via creator-supplied `provider_url`

**Status**: Deferred (unbuilt BOT-004 prereq, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BOT-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-004.md`); see also `docs/tickets/writeups/BOT-004.md`

## Location
`provider_url`

## Problem / Impact
SSRF via creator-supplied `provider_url`

## Fix
validate URL against a private-IP blocklist in `configure_ai_bot()` mirroring `app/services/webhook_ssrf.py`

## Notes
This gap was identified by the second-pass as-built review of BOT-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
