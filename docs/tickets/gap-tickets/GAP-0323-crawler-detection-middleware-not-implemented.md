# GAP-0323: Crawler-detection middleware not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: PLATFORM-005 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/PLATFORM-005.md`); see also `docs/tickets/writeups/PLATFORM-005.md`

## Location
`frontend/vite.config.ts`

## Problem / Impact
social bots (Facebook, Twitter/X, Discord, Slack) do not execute JS; client-side `react-helmet-async` alone produces no OG tags for them; the middleware that intercepts crawler UAs and injects server-side meta is absent

## Fix
implement crawler UA detection + meta injection in production proxy and as a Vite plugin for dev

## Notes
This gap was identified by the second-pass as-built review of PLATFORM-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
