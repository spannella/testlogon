# Messaging WebRTC Direct Chat — Ticket Breakdown

This ticket set maps directly to `docs/messaging-webrtc-direct-chat-implementation-plan.md` and breaks delivery into milestone-based implementation work for 1:1 direct audio/video chat.

---

## Milestone 0 — Product definition, contracts, and rollout guardrails

### WRTC-001: Finalize v1 product specification and call semantics
**Status**
- Implemented on 2026-03-24 via `docs/messaging-webrtc-direct-chat-spec.md`.

**Scope**
- Lock v1 behavior for 1:1 direct chat call flows (audio/video).
- Define caller/callee UX and edge-case outcomes:
  - ringing timeout
  - busy recipient
  - decline
  - caller cancel
  - call drop before connect
- Define unsupported behavior messaging for v1 exclusions (group calls, recording, screen share).

**Acceptance criteria**
- Product spec is approved by product, backend, frontend, and security stakeholders.
- A complete behavior matrix exists for invite/accept/decline/end outcomes.
- User-visible copy is finalized for all call lifecycle outcomes.
- Specification is published in `docs/messaging-webrtc-direct-chat-spec.md`.

**Dependencies**
- None.

---

### WRTC-002: Publish signaling event contract (v1)
**Status**
- Implemented on 2026-03-24 via `docs/messaging-webrtc-signaling-contract.md` and `docs/messaging-webrtc-signaling-schema-v1.json`.

**Scope**
- Define and version signaling event schemas for:
  - `call.invite`
  - `call.ring`
  - `call.accept`
  - `call.decline`
  - `webrtc.offer`
  - `webrtc.answer`
  - `webrtc.ice_candidate`
  - `call.end`
- Document required envelope fields and validation behavior.
- Define backward/forward compatibility behavior for unknown event versions.

**Acceptance criteria**
- Contract document is published in `docs/messaging-webrtc-signaling-contract.md`.
- JSON schema artifact is published in `docs/messaging-webrtc-signaling-schema-v1.json`.
- Validation and rejection rules are deterministic and documented.
- Realtime/event consumers can parse contract payloads without ambiguity.

**Dependencies**
- WRTC-001.

---

### WRTC-003: Add feature flags, kill switch, and rollout controls
**Status**
- Implemented on 2026-04-04 via `docs/messaging-webrtc-rollout-runbook.md`, `app/services/messaging_call_flags.py`, `app/core/settings.py`, and `frontend/src/lib/featureFlags.ts`.

**Scope**
- Add backend and frontend feature flags for direct calling.
- Add cohort/tenant targeting controls.
- Define emergency disable path that blocks new calls while allowing active calls to end cleanly.

**Acceptance criteria**
- Kill switch and rollout runbook is published in `docs/messaging-webrtc-rollout-runbook.md`.
- Calls cannot be initiated when disabled.
- Existing messaging behavior remains unchanged when disabled.
- Staging verification demonstrates kill-switch behavior.

**Dependencies**
- WRTC-001.

---

## Milestone 1 — Backend call lifecycle and persistence foundations

### WRTC-010: Implement call session persistence model
**Status**
- Implemented on 2026-04-04 via `app/services/messaging_call_sessions.py`, `app/core/settings.py`, `app/core/tables.py`, `scripts/local-ddb-init.py`, and `scripts/migrations/20260404_webrtc_call_sessions_schema.py`.

**Scope**
- Add storage model for call sessions with fields from plan:
  - `call_id`, `conversation_id`, `caller_user_id`, `callee_user_id`
  - `initial_mode`, `state`
  - `start_ts`, `connect_ts`, `end_ts`, `end_reason`, `network_path`
- Add indexes required for conversation and participant queries.
- Ensure backward compatibility and rollback safety.

**Acceptance criteria**
- Call sessions are persisted and queryable by `call_id` and `conversation_id`.
- State updates are durable and timestamped.
- Migration/bootstrap scripts are reviewed and rollback-safe.
- No regressions in existing messaging persistence paths.

**Dependencies**
- WRTC-002.

---

### WRTC-011: Build backend call lifecycle service APIs
**Status**
- Implemented on 2026-04-04 via `app/services/messaging_call_lifecycle.py` and `tests/test_messaging_call_lifecycle.py`.

**Scope**
- Implement backend handlers/services for:
  - create invite
  - accept invite
  - decline invite
  - end call
- Enforce participant authorization based on conversation membership.
- Enforce deterministic lifecycle transitions.

**Acceptance criteria**
- Only eligible conversation participants can transition call state.
- Invalid transitions are rejected with documented errors.
- State transitions are persisted and produce lifecycle events.
- Unit tests cover valid/invalid transition paths.

**Dependencies**
- WRTC-010.

---

### WRTC-012: Add idempotency and duplicate-event protections
**Status**
- Implemented on 2026-04-04 via `app/services/messaging_call_lifecycle.py`, `app/services/messaging_call_sessions.py`, and `tests/test_messaging_call_lifecycle.py`.

**Scope**
- Add idempotency keys for invite/accept/end operations.
- Ensure duplicate signaling events do not corrupt state.
- Ensure retries return deterministic responses.

**Acceptance criteria**
- Duplicate invites/accepts/end requests are safely deduplicated.
- Retried requests with same idempotency key return consistent results.
- Race conditions produce one canonical persisted call state.
- Tests cover concurrent duplicate request scenarios.

**Dependencies**
- WRTC-011.

---

### WRTC-013: Emit conversation timeline events for calls
**Status**
- Implemented on 2026-04-04 via `app/services/messaging_call_timeline.py`, `app/services/messaging_call_lifecycle.py`, and `tests/test_messaging_call_timeline.py`.

**Scope**
- Add message timeline/system entries for lifecycle milestones:
  - call started/ringing
  - accepted/connected
  - declined/missed/busy
  - ended + reason
- Ensure events conform to messaging archive/compliance behaviors.

**Acceptance criteria**
- Conversation history reflects key call lifecycle events.
- Event payloads are consistent with messaging timeline contracts.
- Archive/compliance paths include call metadata events.
- Regression tests verify non-call message rendering remains intact.

**Dependencies**
- WRTC-011.

---

## Milestone 2 — Realtime signaling and WebRTC session establishment

### WRTC-020: Integrate signaling events into existing realtime channel
**Status**
- Implemented on 2026-04-04 via `app/services/messaging_call_signaling.py` and `tests/test_messaging_call_signaling.py`.

**Scope**
- Route call signaling payloads through existing websocket/realtime infrastructure.
- Add server-side validation, authentication, and authorization checks per event type.
- Add delivery acknowledgments or failure handling hooks where applicable.

**Acceptance criteria**
- Signaling events are delivered to intended participant(s) only.
- Unauthorized/spoofed event attempts are rejected.
- Event delivery failures are observable via logs/metrics.
- Integration tests validate event flow across caller/callee sessions.

**Dependencies**
- WRTC-002, WRTC-011.

---

### WRTC-021: Implement TURN credential issuance service
**Status**
- Implemented on 2026-04-05 via `app/services/messaging_turn_credentials.py`, `/messages/calls/{call_id}/turn-credentials` endpoint in `app/routers/messaging.py`, `app/metrics.py`, and `tests/test_messaging_turn_credentials.py`.

**Scope**
- Add endpoint/service for short-lived TURN credentials.
- Enforce auth and call/session eligibility checks.
- Return ICE server config compatible with frontend call bootstrap.

**Acceptance criteria**
- Authorized users receive short-lived TURN credentials.
- Invalid/unauthorized requests are rejected with clear errors.
- Credential TTL and issuance policy are documented.
- Metrics track issuance success/failure counts.

**Dependencies**
- WRTC-011.

---

### WRTC-022: Configure STUN/TURN environments and runbooks
**Status**
- Implemented on 2026-04-05 via `docs/messaging-webrtc-turn-runbook.md` and `scripts/check_webrtc_turn_readiness.py` (with tests in `tests/test_webrtc_turn_readiness_script.py`).

**Scope**
- Stand up non-prod and prod-capable STUN/TURN configurations.
- Configure TLS/auth/secrets management and rotation process.
- Document firewall/network requirements and relay capacity assumptions.

**Acceptance criteria**
- TURN service is reachable from client test environments.
- Secrets rotation process is documented and validated.
- Operational runbook is published in `docs/messaging-webrtc-turn-runbook.md`.
- Baseline connectivity checks pass in staging.

**Dependencies**
- WRTC-021.

---

## Milestone 3 — Frontend call UX and state management

### WRTC-030: Add conversation-level call entry points
**Scope**
- Add “Start audio call” and “Start video call” controls in direct-message conversation header.
- Gate controls by feature flag and conversation eligibility.
- Provide disabled-state and unsupported-state UX messaging.

**Acceptance criteria**
- Eligible direct conversations show call actions.
- Ineligible contexts hide/disable call actions appropriately.
- Actions dispatch correct call initiation payloads.
- UI tests verify visibility, disabled, and click behavior.

**Dependencies**
- WRTC-003, WRTC-020.

---

### WRTC-031: Implement incoming/outgoing call UI flows
**Status**
- Implemented on 2026-04-05 via `frontend/src/pages/messages/CallSessionOverlay.tsx`, `frontend/src/pages/messages/ConversationView.tsx`, stream dispatch wiring in `frontend/src/hooks/useMessagingStream.ts`, and lifecycle tests in `frontend/src/pages/messages/ConversationView.call_flows.test.tsx`.

**Scope**
- Build incoming call modal/sheet with accept/decline controls.
- Build outgoing call ringing/connecting states.
- Add clear UX for decline, busy, timeout, and failure outcomes.

**Acceptance criteria**
- Callee can accept or decline from incoming call UI.
- Caller sees deterministic state changes (ringing → connected/ended/failure).
- Busy/timeout/decline outcomes show correct user-facing messaging.
- Component tests cover lifecycle state transitions.

**Dependencies**
- WRTC-030.

---

### WRTC-032: Implement in-call experience with media controls
**Scope**
- Add in-call panel with local/remote streams.
- Add controls: mute mic, disable camera, end call, call duration timer.
- Add permission-denied handling and fallback guidance.

**Acceptance criteria**
- Local and remote media render during connected calls.
- Mic/camera toggles update call state and media tracks correctly.
- Permission-denied states provide actionable guidance.
- End-call action triggers proper backend lifecycle transition.

**Dependencies**
- WRTC-031.

---

### WRTC-033: Implement deterministic client call state machine
**Status**
- Implemented on 2026-04-05 via deterministic reducer + teardown utilities in `frontend/src/pages/messages/callStateMachine.ts`, integration in `frontend/src/pages/messages/ConversationView.tsx`, and regression coverage in `frontend/src/pages/messages/callStateMachine.test.ts`.

**Scope**
- Create explicit caller/callee state machine implementation.
- Handle reconnect/retry cases for transient signaling failures.
- Ensure teardown/cleanup removes peer connections and media tracks reliably.

**Acceptance criteria**
- State transitions are deterministic and test-covered.
- Reconnect logic avoids duplicate connections and ghost call UIs.
- Call teardown is complete (tracks stopped, PC closed, listeners removed).
- Regression tests cover tab background/foreground and reconnect cases.

**Dependencies**
- WRTC-031, WRTC-032.

---

## Milestone 4 — Reliability, security, and abuse controls

### WRTC-040: Add invite rate limiting and abuse protections
**Scope**
- Add per-user and per-conversation invite rate limits.
- Add anti-spam behavior for repeated declines/ignored invites.
- Integrate with existing moderation/reporting hooks where available.

**Acceptance criteria**
- Excessive invite attempts are throttled with clear responses.
- Abuse telemetry is emitted for moderation visibility.
- Legitimate call flows remain unaffected under normal usage.
- Documentation includes limit policies and escalation paths.

**Dependencies**
- WRTC-011, WRTC-020.

---

### WRTC-041: Security hardening and threat model validation
**Status**
- Implemented on 2026-04-05 via signaling replay/spoof hardening in `app/services/messaging_call_signaling.py`, security tests in `tests/test_messaging_call_signaling.py`, and threat-model publication in `docs/messaging-webrtc-threat-model.md`.

**Scope**
- Validate auth checks on all signaling and lifecycle events.
- Add replay/spoof protections and timestamp/nonce checks where required.
- Perform focused threat model and remediation tracking.

**Acceptance criteria**
- Threat model is published in `docs/messaging-webrtc-threat-model.md`.
- Unauthorized conversation access and replay attempts are rejected.
- Security tests cover spoofed sender IDs and stale/replayed events.
- High-risk findings are resolved or formally risk-accepted.

**Dependencies**
- WRTC-020.

---

### WRTC-042: Reliability hardening for network edge cases
**Status**
- Implemented on 2026-04-05 via lifecycle contention checks in `app/services/messaging_call_lifecycle.py`, stale event ordering protection in `frontend/src/pages/messages/ConversationView.tsx`, and documented staging matrix in `docs/messaging-webrtc-reliability-test-matrix.md`.

**Scope**
- Handle simultaneous call attempts and recipient already-on-call cases.
- Add ICE restart/reconnect behavior for transient network drops.
- Improve resilience for backgrounded tabs and delayed event delivery.

**Acceptance criteria**
- Simultaneous/competing call attempts resolve deterministically.
- Mid-call transient network loss can recover when feasible.
- Failure cases surface clear reason codes and user-facing states.
- Test matrix is documented and executed in staging.

**Dependencies**
- WRTC-033, WRTC-022.

---

## Milestone 5 — Observability, rollout, and launch

### WRTC-050: Implement call observability dashboards and alerts
**Status**
- Implemented on 2026-04-05 via new WebRTC call metrics in `app/metrics.py`, dashboard artifact `docs/dashboards/messaging-webrtc-calls-dashboard.json`, and runbook alert interpretation updates in `docs/messaging-webrtc-rollout-runbook.md`.

**Scope**
- Add telemetry for:
  - call setup success rate
  - setup latency
  - call duration
  - TURN relay ratio
  - failure reason taxonomy
- Build operational dashboards and baseline alerts.

**Acceptance criteria**
- Dashboard is published in `docs/dashboards/messaging-webrtc-calls-dashboard.json`.
- Alert thresholds are defined for key regressions.
- Metrics are segmented by platform/browser where feasible.
- On-call runbook references dashboard and alert interpretation.

**Dependencies**
- WRTC-020, WRTC-021, WRTC-042.

---

### WRTC-051: Execute staged rollout and validation gates
**Scope**
- Roll out by phases: internal users → beta cohort → broad enablement.
- Define measurable go/no-go gates for each phase.
- Validate kill-switch behavior during rollout rehearsals.

**Acceptance criteria**
- Rollout checklist is completed for each cohort stage.
- Gate metrics meet predefined SLOs before expansion.
- Kill switch is tested and documented as operationally ready.
- Launch report captures outcomes and follow-up items.

**Dependencies**
- WRTC-003, WRTC-050.

---

### WRTC-052: Cross-browser QA and release certification
**Status**
- Implemented on 2026-04-05 via cross-browser QA evidence in `docs/qa/messaging-webrtc-cross-browser-qa-matrix.md` and release certification/watch-window sign-off in `docs/release/messaging-webrtc-release-certification.md`.

**Scope**
- Execute manual/automated QA matrix for Chromium, Firefox, Safari.
- Validate media permissions, device switching, and failure UX by browser.
- Certify release readiness against critical scenarios.

**Acceptance criteria**
- QA matrix evidence is captured and shared.
- Critical/high defects are fixed or deferred with approval.
- Release readiness sign-off is documented.
- Post-launch watch window and ownership are assigned.

**Dependencies**
- WRTC-031, WRTC-032, WRTC-042, WRTC-051.

---

## Suggested implementation order (critical path)
1. WRTC-001 → WRTC-002 → WRTC-003
2. WRTC-010 → WRTC-011 → WRTC-012 → WRTC-013
3. WRTC-020 + WRTC-021 → WRTC-022
4. WRTC-030 → WRTC-031 → WRTC-032 → WRTC-033
5. WRTC-040 + WRTC-041 + WRTC-042
6. WRTC-050 → WRTC-051 → WRTC-052

## Notes
- Ticket IDs are intentionally milestone-prefixed to simplify planning board setup.
- If capacity is constrained, prioritize audio-only under the same ticket structure and phase video enablement behind a sub-flag.
- All tickets should remain feature-flagged until WRTC-051 rollout gates are satisfied.
