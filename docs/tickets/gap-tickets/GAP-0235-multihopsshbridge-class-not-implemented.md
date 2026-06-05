# GAP-0235: `MultiHopSshBridge` class not implemented

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-011 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/INFRA-011.md`); see also `docs/tickets/writeups/INFRA-011.md`

## Location
`MultiHopSshBridge`

## Problem / Impact
the ticket design requires a `MultiHopSshBridge` class using Paramiko `direct-tcpip` channel forwarding; no such class exists in the terminal router; `SshBastionPage.tsx` can configure chains but the WebSocket handler ignores `host_id` and the `resolve_connection_chain` path; multi-hop connections cannot actually be established

## Fix
implement `MultiHopSshBridge` as designed in the ticket (section 3.3) and wire it into the WebSocket `connect` handler

## Notes
This gap was identified by the second-pass as-built review of INFRA-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
