# GAP-0141: API key ciphertext must never appear in API responses

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: BOT-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-004.md`); see also `docs/tickets/writeups/BOT-004.md`

## Location
`app/services/bot_ai.py`

## Problem / Impact
API key ciphertext must never appear in API responses

## Fix
`AiConfigOut` excludes `ai_api_key_encrypted`; service returns `api_key_masked = "..."+key[-3:]`

## Notes
This gap was identified by the second-pass as-built review of BOT-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
