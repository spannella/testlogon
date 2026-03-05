# Browser SSH Terminal Implementation Tickets

This ticket set turns `SSH_BROWSER_TERMINAL_PLAN.md` into an implementation-ready backlog.

## Milestone 1 — MVP (Password auth + interactive terminal)

### SSH-001: Project scaffolding and feature flag
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Create frontend module and backend gateway service skeleton for browser SSH terminal.
- Add feature flag (e.g., `browserSshTerminal.enabled`) to allow safe rollout.

**Acceptance Criteria**
- New frontend route/component loads behind feature flag.
- Backend service starts with health endpoint and WS endpoint placeholder.
- Feature can be toggled without redeploy (existing config mechanism).

**Dependencies**
- None.

---

### SSH-002: Connection form UI (host, port, username, auth mode)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Build connection form with fields: host, port (default 22), username, auth type selector.
- Show password field when auth type is `password`.

**Acceptance Criteria**
- Client-side validation for required fields and valid port range.
- Connect button disabled until fields are valid.
- Disconnect button appears when session is active.

**Dependencies**
- SSH-001.

---

### SSH-003: xterm.js terminal component + resize fit
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add xterm.js terminal view with fit addon.
- Hook container/window resize to terminal fit and resize events.

**Acceptance Criteria**
- Terminal renders and accepts keyboard input.
- Initial cols/rows are computed correctly.
- Resize emits dimension change callback.

**Dependencies**
- SSH-001.

---

### SSH-004: WebSocket session protocol v1
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Implement message contract (`connect`, `input`, `resize`, `output`, `status`, `error`).
- Add schema validation on server for all inbound message types.

**Acceptance Criteria**
- Invalid payloads receive structured error response and do not crash session.
- Protocol documented in code comments and API docs.
- Integration test covers happy path message exchange.

**Dependencies**
- SSH-001.

---

### SSH-005: SSH gateway password authentication flow
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Implement backend flow to open SSH session via password.
- Bridge SSH stdin/stdout with WS input/output streams.

**Acceptance Criteria**
- User can connect to test SSH host and run `echo` command interactively.
- Failed auth shows clear non-sensitive error in UI.
- Session closes cleanly on disconnect or browser close.

**Dependencies**
- SSH-004.

---

### SSH-006: PTY defaults and terminal resize propagation
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Request PTY (`xterm-256color`) and propagate client resize events to SSH channel.

**Acceptance Criteria**
- Terminal apps (`top`, `vim`) render correctly in test environment.
- Rapid resize does not crash server or freeze terminal.

**Dependencies**
- SSH-003, SSH-005.

---

### SSH-007: Copy/paste support and keyboard shortcuts
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add copy/paste behavior for Linux/Windows/macOS shortcuts.
- Add context menu actions and Clipboard API fallback handling.

**Acceptance Criteria**
- Copy selected text works across supported browsers.
- Paste sends text to remote shell with normalized line endings.
- Browsers that deny clipboard permissions show actionable message.

**Dependencies**
- SSH-003, SSH-005.

---

### SSH-008: Session state UX and errors
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add visible status states: connecting, connected, disconnected, auth failed, network error.

**Acceptance Criteria**
- User sees status transitions in real time.
- Error copy avoids leaking secrets.
- Retry path available after failure.

**Dependencies**
- SSH-002, SSH-004, SSH-005.

---

## Milestone 2 — Private key auth + UX polish

### SSH-009: Private key auth form and secure handling
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add private key input (paste and optional file load-to-memory) and passphrase field.
- Ensure sensitive fields are masked/redacted in logs and telemetry.

**Acceptance Criteria**
- UI toggles correctly between password and key auth modes.
- Key material never written to persistent storage.
- Validation rejects unsupported key formats with clear feedback.

**Dependencies**
- SSH-002.

---

### SSH-010: Backend private key SSH authentication
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Parse key + passphrase and connect with public key authentication.

**Acceptance Criteria**
- Encrypted and unencrypted keys are supported in integration tests.
- Invalid passphrase/key produces deterministic user-facing error.
- Sensitive values are redacted in logs.

**Dependencies**
- SSH-004, SSH-009.

---

### SSH-011: Reconnect and disconnect UX polish
**Type:** Feature  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- Add reconnect action and better empty/disconnected terminal states.

**Acceptance Criteria**
- User can reconnect without full page refresh.
- Prior credentials are not auto-replayed unless explicitly chosen.

**Dependencies**
- SSH-008.

---

## Milestone 3 — Security, policy, and operations

### SSH-012: Host/port policy controls (allowlist/denylist)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Enforce destination policy at backend before SSH dial.

**Acceptance Criteria**
- Requests to blocked hosts/ports are denied with clear reason.
- Policy source is configurable via existing environment/config system.

**Dependencies**
- SSH-005, SSH-010.

---

### SSH-013: AuthN/AuthZ integration for terminal access
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Require application identity for opening sessions.
- Add role check (e.g., `terminal.connect`).

**Acceptance Criteria**
- Unauthorized users cannot open websocket session.
- Authorized users can connect normally.
- Access denials are audited.

**Dependencies**
- SSH-001.

---

### SSH-014: Timeouts, quotas, and rate limiting
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add idle timeout, max session duration, and per-user session limits.
- Apply connection rate limiting on WS connect attempts.

**Acceptance Criteria**
- Idle sessions terminate after configured timeout.
- User exceeding limits gets structured error.
- Metrics exposed for throttled/denied attempts.

**Dependencies**
- SSH-013.

---

### SSH-015: Observability and audit metadata
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add structured logs and metrics for session lifecycle.
- Capture audit metadata (user, host, start/end, outcome) without command payloads or secrets.

**Acceptance Criteria**
- Dashboard includes active sessions and connect failure rate.
- Logs include session ID correlation.
- Security review signs off on redaction behavior.

**Dependencies**
- SSH-005, SSH-010, SSH-013.

---

## Milestone 4 — Quality and release readiness

### SSH-016: Automated test suite (unit + integration + E2E)
**Type:** Test  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add tests for protocol schema, auth mode handling, and websocket/ssh bridging.
- Add browser E2E for connect, run command, copy, paste, disconnect.

**Acceptance Criteria**
- CI job runs all new tests.
- Test fixture SSH server/container used for deterministic integration tests.
- Flake rate under agreed threshold.

**Dependencies**
- SSH-007, SSH-010.

---

### SSH-017: Threat model and security test pass
**Type:** Security  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Run threat modeling for credential handling, websocket abuse, and destination restrictions.
- Execute targeted security test cases from plan.

**Acceptance Criteria**
- Threat model document reviewed by security owner.
- High/Critical findings resolved or risk-accepted with approval.

**Dependencies**
- SSH-012, SSH-014, SSH-015.

---

### SSH-018: Rollout plan and runbook
**Type:** Ops  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Create staged rollout plan (internal -> beta -> general availability).
- Document on-call runbook and common failure recovery steps.

**Acceptance Criteria**
- Runbook includes incident triage for SSH connect failures and websocket outages.
- Rollback steps verified in staging.

**Dependencies**
- SSH-015, SSH-016.

---

## Suggested execution order
1. SSH-001 → SSH-004 → SSH-005 (core backend path)
2. SSH-002 + SSH-003 → SSH-006 + SSH-008 (core UI/terminal)
3. SSH-007 (copy/paste) and complete MVP release gate
4. SSH-009 + SSH-010 (private key auth)
5. SSH-012 + SSH-013 + SSH-014 + SSH-015 (security/ops hardening)
6. SSH-016 + SSH-017 + SSH-018 (quality and production readiness)

## Definition of Done (cross-ticket)
- No secrets in logs, traces, analytics, or client error payloads.
- WS connections are WSS-only in non-local environments.
- Terminal session resources are cleaned up on disconnect and timeout.
- All new tests pass in CI and feature flag supports safe rollback.
