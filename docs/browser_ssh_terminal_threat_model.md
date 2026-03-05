# Browser SSH Terminal Threat Model and Security Test Pass (SSH-017)

## Scope
This document covers threat modeling and targeted security tests for the Browser SSH terminal feature (`/api/browser-ssh/ws`, `/api/browser-ssh/config`, `/browser-ssh`).

### In scope
- Credential handling for password/private key/passphrase in browser-to-gateway messages.
- WebSocket abuse risks (malformed payloads, flooding/connect abuse, unauthorized access).
- Destination restrictions (host/port allowlist/denylist policy enforcement).

### Out of scope
- Host-side command authorization inside target SSH hosts.
- Network-layer controls external to this service (WAF, firewall policies).

## Assets and trust boundaries
- **Sensitive assets**: password, private key, passphrase, UI session identity, audit events.
- **Boundary A**: Browser client <-> WebSocket gateway.
- **Boundary B**: Gateway <-> Remote SSH destination.
- **Boundary C**: Gateway <-> logs/metrics/audit sinks.

## Threat analysis (STRIDE-oriented)

| ID | Threat | Impact | Existing controls | Residual risk |
|---|---|---|---|---|
| TM-01 | Credential disclosure via logs | Secret leakage | `_redact_connect_payload` masks password/privateKey/passphrase before logging; tests assert no plain secret in audited fields. | Low |
| TM-02 | Unauthorized terminal session open | Privilege escalation | `_authorize_terminal_access` requires authenticated UI identity + role allowlist + audit deny events. | Medium (depends on upstream auth/session hardening) |
| TM-03 | Destination policy bypass | Lateral movement | `_enforce_destination_policy` checks denylist first, then allowlist, before SSH dial. | Low |
| TM-04 | WebSocket message schema abuse | Crash/DoS/input confusion | Structured validation for envelope/type/payload with deterministic error responses and session continuity. | Medium |
| TM-05 | Connect-flood abuse | Resource exhaustion | Per-user connect rate limit and per-user active session cap with metrics and structured errors. | Medium |
| TM-06 | Zombie sessions | Resource leakage | Idle timeout/max duration and close cleanup of bridge/session slots. | Low |

## Targeted security test pass

### Executed test groups
1. **Credential redaction and logging safety**
   - Validates masking behavior for `password`, `privateKey`, `passphrase`.
   - Validates websocket connect request logging does not include raw password.
2. **WebSocket abuse handling**
   - Invalid JSON and missing `type` receive structured errors without crashing session.
   - Unsupported message types are rejected safely.
3. **Destination restriction enforcement**
   - Denied host/port is blocked with structured policy error.
   - SSH bridge is not created when policy blocks destination.
4. **AuthN/AuthZ and audit controls**
   - Unauthorized users denied and access denials audited.
5. **Rate limiting/session quotas/timeouts**
   - Connect rate limiting and session cap paths return deterministic errors.

## Findings and disposition
- **Critical**: 0
- **High**: 0
- **Medium**: 0 new (known residual risks tracked above)
- **Low**: 0 new

No unresolved High/Critical findings were observed in the targeted automated security test pass for this change.

## Security owner review
- **Owner**: `@security-owner` (to be assigned by maintainers)
- **Review status**: Pending owner sign-off in PR review.
- **Risk acceptance required**: None for High/Critical (none identified).

## Evidence
- Test module: `tests/test_browser_ssh_terminal_security.py`
- Existing companion suites: `tests/test_browser_ssh_terminal_scaffold.py`, `tests/test_browser_ssh_terminal_protocol_unit.py`, `tests/test_browser_ssh_terminal_e2e_flow.py`
- CI workflow: `.github/workflows/browser-ssh-terminal-tests.yml`
