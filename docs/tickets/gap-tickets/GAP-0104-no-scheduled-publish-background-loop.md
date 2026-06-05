# GAP-0104: no scheduled-publish background loop

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: AGENT-017 · **Effort**: S
**From**: gap audit (`docs/tickets/gaps/AGENT-017.md`); see also `docs/tickets/writeups/AGENT-017.md`

## Location
`app/services/agent_marketing.py:507`

## Problem / Impact
schedule_content sets status=scheduled and GSI3SK but no background task promotes due content to published; scheduled items never auto-publish

## Fix
add asyncio background task in app/main.py calling publish_due_scheduled_content every 30s

## Notes
This gap was identified by the second-pass as-built review of AGENT-017. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
