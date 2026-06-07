# GAP-0236: `resolve_connection_chain` function missing

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-011 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/INFRA-011.md`); see also `docs/tickets/writeups/INFRA-011.md`

## Location
`resolve_connection_chain`

## Problem / Impact
the service provides `resolve_bastion_path()` which produces a ProxyJump/ssh_config representation, but the actual chain resolution function that returns a list of hop dicts with credentials (for programmatic connection) described in ticket section 3.2 is absent; there is no `get_connection_profile()` call or SSH-key lookup per hop

## Fix
add `resolve_connection_chain(user_sub, path_id)` that fetches each hop's SSH key via `ssh_key_manager.get_decrypted_private_key()` and returns a ready-to-connect chain

## Notes
This gap was identified by the second-pass as-built review of INFRA-011. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.


## Implemented (branch impl/crit-batch-1, 2026-06-06)

Fix landed; see commit on impl/crit-batch-1. Regression test added.
