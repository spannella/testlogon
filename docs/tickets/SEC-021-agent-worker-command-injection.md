# SEC-021: Agent Worker/Coder Command-Injection (latent, gated)

**Ticket**: SEC-021 · **Status**: Open · **Priority**: Medium (latent) · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 4)

## Problem
User-controlled values are interpolated into shell commands in the agent execution
paths; currently gated/dead, but a foot-gun the moment they're enabled:
- `app/services/agent_coder.py` (~:290) / `agent_architect.py` — `repo_url` and
  `branch` are f-string-interpolated into `git clone {repo_url} ...` /
  `-b {branch}`. Gated by `AGENT_CODER_EXECUTE_COMMANDS` / `ARCHITECT_EXECUTE_COMMANDS`
  (default off). With execution on, `repo_url='; rm -rf / #'` or a git `ext::` URL →
  arbitrary command execution / SSRF on the worker (or orchestrator). branch sanitized
  in coder but verify architect parity.
- `CreateWorkerIn.custom_install_commands` / `custom_verify_command` (`models.py:5287`)
  are accepted but never stored/executed (dead code) — if wired up later, same risk.
- `app/services/llm_provider_keys.py:234` returns the provider's raw error body
  (`resp.text[:200]`) to the client on key-test failure (minor info leak).

## Fix
- Never build shell strings from user input: use `subprocess(..., shell=False)` with an
  argv list, or `shlex.quote`; validate `repo_url` against an allowed scheme/host set
  and reject git transports like `ext::`/`file://`; apply the coder's branch
  sanitization in architect too.
- Remove `custom_install_commands`/`custom_verify_command` until they can be executed
  safely (argv + allowlist), or keep them inert and documented.
- Return a generic "authentication failed" on LLM key test; don't echo provider body.

## Testing
pytest: with execution enabled, a `repo_url`/`branch`/install-command containing shell
metacharacters is rejected or passed as a literal argv (no command runs); key-test
failure returns a generic message.
