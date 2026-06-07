# GAP-0099: backend computes source hashes directly from filesystem

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-014 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-014.md`); see also `docs/tickets/writeups/AGENT-014.md`

## Location
`app/services/agent_docs.py:198`

## Problem / Impact
_compute_source_hash opens files via open(path,"rb") on the backend server; in prod where backend and agent terminal are separate machines this returns wrong/missing hashes

## Fix
gate local hash computation on S.dev_mode; accept externally-provided source_hashes dict from agent via API payload

## Notes
This gap was identified by the second-pass as-built review of AGENT-014. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
