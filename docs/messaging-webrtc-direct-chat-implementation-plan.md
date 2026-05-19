# WebRTC Direct Video + Audio Chat Implementation Plan

## Goals
- Add **1:1 direct video/audio calling** to the existing messaging experience.
- Reuse the current conversation and presence model so users can escalate a text chat into a call.
- Keep reliability and moderation/compliance controls aligned with existing messaging standards.

## Scope
### In scope (v1)
- 1:1 audio + video calls from an existing direct-message thread.
- Call states: ringing, accepted, declined, busy, timeout, ended.
- In-call controls: mute mic, mute camera, end call, basic device selection.
- NAT traversal with STUN/TURN.
- Call events persisted as conversation system messages.
- Basic observability (success rate, setup latency, call duration).

### Out of scope (later phases)
- Group calls.
- Screen sharing.
- Call recording/transcription.
- PSTN/SIP bridging.

## Architecture Overview
1. **Signaling over existing messaging transport**
   - Use messaging realtime channel/websocket infrastructure for signaling payloads:
     - `call.invite`
     - `call.ring`
     - `call.accept`
     - `call.decline`
     - `webrtc.offer`
     - `webrtc.answer`
     - `webrtc.ice_candidate`
     - `call.end`
   - Include `conversation_id`, `call_id`, sender, recipient, timestamp, and versioned schema.

2. **WebRTC media path**
   - Browser peers exchange SDP/ICE via signaling.
   - Media flows peer-to-peer when possible.
   - TURN relay fallback for restrictive networks.

3. **Backend call coordinator (lightweight)**
   - Authorizes call attempts and recipient eligibility.
   - Issues short-lived TURN credentials.
   - Manages call timeout rules and idempotency.
   - Emits durable call lifecycle events into message history.

4. **Client call state machine**
   - Deterministic states for both caller/callee to reduce race bugs.
   - Reconnect and retry handling for signaling interruptions.

## Detailed Work Plan

## Phase 0 — Discovery and design (3–5 days)
- Review existing messaging event contracts and frontend conversation state flow.
- Define signaling JSON schema and versioning strategy.
- Produce sequence diagrams for:
  - Successful call flow.
  - Decline/busy flow.
  - Timeout flow.
  - Mid-setup disconnect flow.
- Decide provider strategy for TURN (self-hosted coturn vs managed).

**Deliverables**
- RFC/design doc with state diagrams.
- API + event contract draft.

## Phase 1 — Backend signaling and call lifecycle (1–2 weeks)
- Add call service module:
  - `create_call_invite`
  - `accept_call`
  - `decline_call`
  - `end_call`
  - `issue_turn_credentials`
- Enforce access control: only conversation participants can initiate/respond.
- Add idempotency keys to prevent duplicate invites/accepts.
- Persist call session metadata:
  - `call_id`, participants, started_at, connected_at, ended_at, end_reason.
- Emit conversation timeline messages for call lifecycle.
- Add metrics/logging hooks.

**Deliverables**
- Backend endpoints and/or websocket event handlers.
- Storage schema migration for call sessions.
- Unit/integration tests for lifecycle transitions.

## Phase 2 — Frontend call UX + WebRTC integration (1–2 weeks)
- Add call controls to conversation header:
  - Start audio call
  - Start video call
- Build incoming call modal with ringtone + actions (accept/decline).
- Implement call panel:
  - Local + remote media views.
  - Device permission handling.
  - Mute toggles + call timer + end button.
- Integrate RTCPeerConnection:
  - Offer/answer exchange.
  - ICE handling.
  - Track add/remove and cleanup.
- Add UI states for:
  - Ringing
  - Connecting
  - Connected
  - Reconnecting
  - Ended/failed

**Deliverables**
- Reusable call hooks/components.
- Frontend tests for state transitions and UI behavior.

## Phase 3 — NAT traversal + reliability hardening (1 week)
- Deploy/configure STUN/TURN with TLS and auth.
- Add fallback logic for relay-only environments.
- Handle edge cases:
  - Simultaneous call attempts.
  - Recipient already on another call.
  - Browser tab backgrounding.
  - Network drop and ICE restart attempts.

**Deliverables**
- TURN runbook and secrets rotation process.
- Reliability test matrix across network scenarios.

## Phase 4 — Security, privacy, and compliance (parallel + 1 week hardening)
- Validate auth on every signaling event.
- Rate-limit call invites to reduce abuse/spam.
- Add feature flags by tenant/user cohort.
- Ensure call metadata retention policy aligns with messaging retention.
- Decide and document that media is not server-recorded in v1.
- Add abuse reporting hooks from call UI.

**Deliverables**
- Threat model + mitigations.
- Security test cases (spoofed event, replayed event, unauthorized conversation access).

## Phase 5 — Rollout and observability (1 week)
- Add dashboards:
  - Call setup success rate.
  - Median time to connect.
  - TURN relay ratio.
  - Failure reason breakdown.
- Staged rollout:
  - Internal users → beta cohort → 100%.
- Add kill switch/feature flag rollback path.

**Deliverables**
- Operational runbook.
- Launch checklist and rollback checklist.

## Data & Contract Additions

## Signaling event envelope
- `type`: event type string
- `version`: schema version
- `conversation_id`
- `call_id`
- `sender_user_id`
- `recipient_user_id`
- `payload`
- `created_at`

## Call session record
- `call_id` (pk)
- `conversation_id`
- `caller_user_id`
- `callee_user_id`
- `initial_mode` (`audio` | `video`)
- `state` (`invited` | `accepted` | `connected` | `ended` | `missed` | `declined`)
- `start_ts`, `connect_ts`, `end_ts`
- `end_reason`
- `network_path` (`p2p` | `turn`)

## Testing Strategy
- **Backend unit tests**: lifecycle state transitions and authorization.
- **Backend integration tests**: signaling delivery and persistence.
- **Frontend unit tests**: call state machine transitions.
- **E2E tests**:
  - caller invites, callee accepts, media connects.
  - callee declines.
  - recipient timeout.
  - network interruption during setup.
- **Manual cross-browser matrix**: Chromium, Firefox, Safari.

## Risks and Mitigations
- **NAT/firewall failures** → strong TURN setup + telemetry for relay failures.
- **Race conditions in signaling** → strict state machine + idempotent server handlers.
- **Permission denial (camera/mic)** → graceful fallback to audio-only retry guidance.
- **Spam invites** → invite rate limits + block/report integration.

## Suggested Milestone Timeline (example, 6 weeks)
- Week 1: discovery, contracts, RFC.
- Week 2–3: backend lifecycle + signaling.
- Week 3–4: frontend call UX + WebRTC.
- Week 5: reliability/security hardening.
- Week 6: staged rollout + observability review.

## Immediate Next Actions
1. Approve signaling contract and call state machine.
2. Select TURN hosting strategy and provision non-prod environment.
3. Implement backend call coordinator behind feature flag.
4. Implement frontend incoming/outgoing call MVP for internal testing.
5. Run end-to-end beta with instrumentation before broad rollout.
