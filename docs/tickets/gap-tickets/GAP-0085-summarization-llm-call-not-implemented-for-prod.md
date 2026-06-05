# GAP-0085: summarization LLM call not implemented for prod

**Status**: Implemented (branch impl/crit-batch-1, 2026-06-05) · **Severity**: HIGH (High) · **Source ticket**: AGENT-005 · **Effort**: M
**From**: gap audit (`docs/tickets/gaps/AGENT-005.md`); see also `docs/tickets/writeups/AGENT-005.md`

## Location
`app/services/agent_memory.py:535`

## Problem / Impact
_maybe_trigger_summarization truncates to 200 chars in all environments; prod loses semantic information silently

## Fix
implement SummarizationClient interface with MockSummarizationClient (dev) and AnthropicSummarizationClient (prod) gated by S.dev_mode

## Notes
This gap was identified by the second-pass as-built review of AGENT-005. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
