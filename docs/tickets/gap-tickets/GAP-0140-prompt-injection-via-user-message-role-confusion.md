# GAP-0140: Prompt injection via user message role confusion

**Status**: Deferred (unbuilt BOT-004 prereq, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: BOT-004 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/BOT-004.md`); see also `docs/tickets/writeups/BOT-004.md`

## Location
`app/services/bot_ai.py`

## Problem / Impact
LLM message array must strictly place user input in the `user` role; checking forbidden topics only on input misses injection that causes the LLM output to violate restrictions

## Fix
run `_check_forbidden_topics()` on both user message and LLM output before delivering response

## Notes
This gap was identified by the second-pass as-built review of BOT-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
