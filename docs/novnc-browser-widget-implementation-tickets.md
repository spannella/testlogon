# noVNC Browser Widget — Implementation Tickets

This ticket set converts `docs/novnc-browser-widget-plan.md` into executable engineering work. Tickets are grouped by epic with scope, deliverables, dependencies, and acceptance criteria.

## Epic 1: Foundations, Architecture, and Session Brokering

### VNC-001 — Finalize noVNC architecture decision record
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None

**Scope**
- Produce architecture decision record (ADR) for browser → API → WS bridge → VNC target.
- Define where `websockify` (or equivalent) runs and how it scales.
- Decide whether user-entered target host/port is allowed or target must be selected from inventory.

**Deliverables**
- ADR committed to docs at `docs/novnc-architecture-decision-record.md`.
- Sequence diagram for connect and disconnect lifecycle.
- Error taxonomy (auth failure, target unreachable, bridge timeout, token expired).

**Acceptance Criteria**
- Engineering and security stakeholders approve ADR.
- Architecture explicitly defines trust boundaries and data flow.
- Error taxonomy is referenced by backend and frontend tickets.

---

### VNC-002 — Implement VNC session bootstrap + teardown API
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-001

**Scope**
- Add `POST /api/vnc/session` and `DELETE /api/vnc/session/{session_id}`.
- Return: `session_id`, `ws_url`, token/connect params, `expires_at`, capability flags.
- Validate request payload and enforce per-target authorization.

**Deliverables**
- API routes + service-layer handlers.
- Request/response schema definitions.
- Error responses with stable codes aligned to ADR section 7 (`docs/novnc-architecture-decision-record.md`).

**Acceptance Criteria**
- Session bootstrap succeeds for authorized users and valid targets.
- Unauthorized users receive 403 with stable code.
- Teardown ends active bridge session and returns success status.

---

### VNC-003 — Add ephemeral token issuance and verification
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-002

**Scope**
- Issue short-lived connect tokens (1–5 minute TTL).
- Verify token audience, session binding, expiry, and replay protection.
- Do not persist plaintext VNC credentials.

**Deliverables**
- Token mint/verify utility.
- TTL and signing secret configuration via env.
- Unit tests for expiry/replay/invalid signature.

**Acceptance Criteria**
- Expired and tampered tokens are rejected deterministically.
- Token cannot be reused across different targets/sessions.
- No logs contain secret/token plaintext.

---

### VNC-004 — Integrate WebSocket-VNC bridge lifecycle manager
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-002, VNC-003

**Scope**
- Implement bridge session lifecycle: create, monitor, cleanup.
- Track session state transitions (`creating`, `active`, `closing`, `closed`, `failed`).
- Handle bridge and target connection failures with mapped error codes.

**Deliverables**
- Bridge lifecycle manager module.
- Cleanup hooks on disconnect, timeout, and process crash.
- Structured session lifecycle logs.

**Acceptance Criteria**
- No orphan sessions after teardown/timeout.
- Bridge failures are surfaced to API with stable mapped codes.
- Session state transitions are observable in logs/metrics.

---

## Epic 2: Frontend Viewer Experience (MVP)

### VNC-005 — Build Remote Desktop connection form
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-002

**Scope**
- Create form for target/host, port, optional display label, and auth input mode.
- Add validation and submit handling for bootstrap API.
- Persist non-secret form values for convenience.

**Deliverables**
- Connection form component(s).
- Client-side input validation states.
- API client wiring and error display.

**Acceptance Criteria**
- Users can submit valid connection payloads from UI.
- Invalid payloads are blocked with inline guidance.
- Backend error codes map to clear user-facing messages from ADR taxonomy (`docs/novnc-architecture-decision-record.md`).

---

### VNC-006 — Embed noVNC viewer with core controls
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-005

**Scope**
- Initialize noVNC viewer from bootstrap response.
- Add controls: connect/disconnect, fullscreen, Ctrl+Alt+Del.
- Render connection state and remote session status.

**Deliverables**
- Viewer container component.
- Controls toolbar.
- Connection state model in UI store/component state.

**Acceptance Criteria**
- Users can start and end sessions from browser reliably.
- Fullscreen and CAD controls execute expected noVNC actions.
- UI presents `connecting`, `connected`, `failed`, and `disconnected` states.

---

### VNC-007 — Add UX for reconnect and failure handling
**Type:** Feature  
**Priority:** P1  
**Dependencies:** VNC-006

**Scope**
- Add retry/reconnect flow for transient failures.
- Present actionable error messaging by code using ADR taxonomy (`docs/novnc-architecture-decision-record.md`).
- Add idle/session-expiry messaging and redirect behavior.

**Deliverables**
- Reconnect CTA and retry backoff policy.
- Error message map by backend code.
- Session expiry modal/banner.

**Acceptance Criteria**
- Transient network errors can be retried without page reload.
- Expired sessions guide users through re-auth/bootstrap flow.
- Fatal errors produce deterministic user guidance.

---

## Epic 3: Clipboard, File Transfer, and Capability Gating

### VNC-008 — Implement clipboard copy/paste integration
**Type:** Feature  
**Priority:** P1  
**Dependencies:** VNC-006

**Scope**
- Add clipboard side panel and explicit send/read actions.
- Gate clipboard interactions on browser permission + server capability.
- Handle payload size limits and unsupported operations.

**Deliverables**
- Clipboard UI panel.
- Clipboard sync handlers and error states.
- Telemetry for clipboard success/failure.

**Acceptance Criteria**
- Users can send clipboard text to remote when supported.
- Unsupported clipboard flows are clearly indicated.
- Permission-denied and oversized payload cases are handled gracefully.

---

### VNC-009 — Implement session capability negotiation model
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-002

**Scope**
- Define and return capability flags:
  - `clipboard`
  - `file_transfer`
  - `drag_drop_upload`
- Determine capability source (target inventory metadata, runtime negotiation, or both).

**Deliverables**
- Backend capability resolver.
- Extended session response schema.
- Capability contract tests.

**Acceptance Criteria**
- Session response includes capability booleans for every session.
- Capability values are deterministic for given target config.
- Frontend can rely on schema without null/undefined ambiguity.

---

### VNC-010 — Add capability-gated file upload + drag/drop UI
**Type:** Feature  
**Priority:** P1  
**Dependencies:** VNC-006, VNC-009

**Scope**
- Add upload button and drag/drop zone when supported.
- Disable/hide controls when unsupported.
- Provide inline progress and failure states.

**Deliverables**
- File transfer/drag-drop UI components.
- Upload state machine (queued/uploading/success/failure).
- Capability-aware rendering logic.

**Acceptance Criteria**
- File transfer controls appear only when `file_transfer=true`.
- Drag/drop is enabled only when `drag_drop_upload=true`.
- Upload failures produce actionable errors and safe retries.

---

### VNC-011 — Implement fallback transfer workflow for unsupported targets
**Type:** Feature  
**Priority:** P2  
**Dependencies:** VNC-009

**Scope**
- Provide alternate transfer path (SFTP/SCP/object upload link) when native transfer is unavailable.
- Ensure consistent UX and auditability across fallback flow.

**Deliverables**
- Fallback transfer UX spec + implementation.
- Backend endpoint(s) or integration adapter for chosen fallback.
- Audit log events for fallback transfer actions.

**Acceptance Criteria**
- Unsupported targets provide a visible, usable transfer alternative.
- Fallback actions are logged with user/session correlation.
- Users are clearly informed which method is in use.

---

## Epic 4: Security, Compliance, and Operations

### VNC-012 — Enforce security controls and rate limits
**Type:** Feature  
**Priority:** P0  
**Dependencies:** VNC-002, VNC-003

**Scope**
- Enforce strict authorization by target and role.
- Add bootstrap/session creation rate limiting.
- Verify TLS/WSS requirements in configuration and runtime checks.

**Deliverables**
- AuthZ guardrails in API layer.
- Rate-limiting policy + config.
- Security runbook updates for VNC feature.

**Acceptance Criteria**
- Unauthorized target access is blocked and logged.
- Burst session creation above threshold is throttled.
- Non-TLS misconfiguration is detected and blocked in non-dev environments.

---

### VNC-013 — Add observability: metrics, logs, traces
**Type:** Feature  
**Priority:** P1  
**Dependencies:** VNC-004

**Scope**
- Emit metrics for session start/stop, duration, failure types.
- Add structured logs with correlation IDs.
- Add trace spans for bootstrap and bridge connect path.

**Deliverables**
- Metrics dashboard panels and alerts.
- Structured logging fields documented.
- Trace instrumentation in key backend paths.

**Acceptance Criteria**
- On-call can identify top failure reasons by code/target.
- Session lifecycle is traceable end-to-end by `session_id`.
- Alerts trigger on abnormal failure rate spikes.

---

### VNC-014 — Add idle timeout + max session duration enforcement
**Type:** Feature  
**Priority:** P1  
**Dependencies:** VNC-004

**Scope**
- Enforce idle timeout and hard max duration policies.
- Notify users prior to timeout/termination.
- Ensure deterministic teardown on timeout.

**Deliverables**
- Timeout policy config and enforcement service.
- Frontend timeout warning UI.
- Session termination audit entries.

**Acceptance Criteria**
- Idle sessions terminate automatically per policy.
- User receives warning before forced disconnect.
- Timeout-triggered sessions are cleaned up without orphaned processes.

---

## Epic 5: Quality, Testing, and Rollout

### VNC-015 — Backend automated test suite for VNC session flows
**Type:** Test  
**Priority:** P0  
**Dependencies:** VNC-002, VNC-003, VNC-004, VNC-009

**Scope**
- Unit tests for token, authZ, capability resolver.
- Integration tests for create-session/connect/teardown.
- Negative path tests (expired token, unreachable target, unauthorized access).

**Deliverables**
- Automated backend tests in CI.
- Stable test fixtures/mocks for bridge behaviors.

**Acceptance Criteria**
- CI fails on auth/token/capability regressions and ADR error-code contract drift.
- Core happy + critical error paths are covered.
- Test results include deterministic assertions on error codes.

---

### VNC-016 — Frontend e2e coverage for viewer and capabilities
**Type:** Test  
**Priority:** P1  
**Dependencies:** VNC-006, VNC-008, VNC-010

**Scope**
- E2E tests for connect/disconnect, status transitions, and error states.
- Clipboard behavior tests for supported/unsupported modes.
- Capability-gated visibility tests for upload and drag/drop controls.

**Deliverables**
- E2E suite integrated into CI.
- Test data matrix for capability combinations.

**Acceptance Criteria**
- Viewer critical path is validated in automated browser tests.
- Capability flags reliably alter UI rendering.
- Regression tests catch clipboard/transfer UX breaks and ADR error-message mapping regressions.

---

### VNC-017 — Progressive rollout plan and operational readiness
**Type:** Ops  
**Priority:** P1  
**Dependencies:** VNC-012, VNC-013, VNC-015

**Scope**
- Plan phased rollout: internal users → limited tenant cohort → GA.
- Define rollback strategy and feature flags.
- Create runbook for incident triage and safe disablement.

**Deliverables**
- Rollout checklist and milestone gates.
- Feature flag configuration and kill switch.
- Incident response guide for VNC service degradation.

**Acceptance Criteria**
- Each rollout phase has explicit entry/exit criteria.
- Rollback can be executed without redeploy.
- On-call runbook validated in tabletop exercise.

---

## Suggested Sequencing
1. **Foundation first:** VNC-001 → VNC-004
2. **MVP viewer:** VNC-005 → VNC-007
3. **Capabilities + advanced UX:** VNC-009, VNC-008, VNC-010, VNC-011
4. **Security/operations:** VNC-012 → VNC-014
5. **Quality + release:** VNC-015 → VNC-017

## Milestone Mapping
- **Milestone A (MVP):** VNC-001, VNC-002, VNC-003, VNC-004, VNC-005, VNC-006
- **Milestone B (Clipboard):** VNC-008, VNC-007
- **Milestone C (Transfer):** VNC-009, VNC-010, VNC-011
- **Milestone D (Hardening + GA):** VNC-012, VNC-013, VNC-014, VNC-015, VNC-016, VNC-017
