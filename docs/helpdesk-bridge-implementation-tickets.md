# Helpdesk Bridge Conversation Mode — Implementation Ticket Backlog

This backlog translates `docs/helpdesk-bridge-conversation-plan.md` into actionable engineering tickets.

## Epic A — Routing model and state machine foundation

### HB-001: Add helpdesk routing metadata schema
**Goal**: Persist routing state for helpdesk bridge conversations.

**Scope**
- Add `conversation_routing` fields needed for helpdesk mode:
  - `routing_mode`, `group_id`, `state`, `active_agent_user_id`, `active_agent_claimed_at`
  - `last_failover_at`, `assignment_version`, `no_agents_notice_sent_at`
- Add migration/backfill defaults for existing conversations.
- Add indexes for state-driven lookups (for example `state + group_id`).

**Acceptance criteria**
- New helpdesk conversations persist routing metadata successfully.
- Existing conversations are unaffected and continue to load without null-handling regressions.
- Versioned conditional writes are supported by persistence layer.

---

### HB-002: Implement routing state machine with guarded transitions
**Goal**: Centralize valid transitions between `awaiting_agent`, `assigned`, and `paused_no_agents_online`.

**Scope**
- Add routing service/domain module with explicit transition API.
- Enforce transition guards and terminal/error behavior.
- Emit typed transition outcomes for API/realtime layers.

**Acceptance criteria**
- Invalid transitions fail with deterministic error codes.
- State transitions are covered by unit tests (happy and failure paths).
- Service can be reused by claim, send, and presence flows.

---

### HB-003: Add routing event audit log
**Goal**: Make assignment/failover transitions reviewable.

**Scope**
- Introduce `conversation_routing_events` store/table.
- Record claim/release/failover/no-agents transitions with actor and metadata.
- Add query support for operational debugging.

**Acceptance criteria**
- Every routing transition creates an immutable audit record.
- Logs include enough metadata to reconstruct assignment timeline.

---

## Epic B — Conversation creation and alert fanout

### HB-004: Add helpdesk conversation creation mode
**Goal**: Allow users to start a helpdesk-routed conversation.

**Scope**
- Extend create-conversation API/command with `routing_mode=helpdesk_bridge`.
- Ensure virtual helpdesk participant model is set on create.
- Initialize routing state to `awaiting_agent`.

**Acceptance criteria**
- New helpdesk conversation can be created from supported clients.
- Newly created conversation is discoverable in helpdesk agent queue.

---

### HB-005: Alert online helpdesk group members on new unassigned conversation
**Goal**: Notify available agents immediately.

**Scope**
- Resolve online users in configured helpdesk group.
- Emit `helpdesk.conversation.alerted` event with conversation context.
- Track alert emission metrics.

**Acceptance criteria**
- Online helpdesk members receive alert event in realtime channel.
- Alert is emitted once per creation event (idempotent under retries).

---

### HB-006: Emit deterministic no-agents-online user notice at creation time
**Goal**: Provide immediate user feedback when no helpdesk agent is online.

**Scope**
- Detect zero online agents during conversation creation.
- Transition to `paused_no_agents_online`.
- Inject standardized system message: nobody online, try again later.

**Acceptance criteria**
- User sees consistent no-agents-online message in thread.
- Duplicate notices are suppressed according to throttling policy.

---

## Epic C — Claiming and assignment ownership

### HB-007: Implement claim endpoint for helpdesk agents
**Goal**: Let one agent claim ownership of a waiting conversation.

**Scope**
- Add `POST /v1/messaging/helpdesk/conversations/{id}/claim`.
- Validate caller is in helpdesk group and currently available.
- Return conflict semantics when already assigned to another agent.

**Acceptance criteria**
- Eligible agents can successfully claim `awaiting_agent` conversations.
- Ineligible callers get authorization/validation failures.
- Conflict behavior is deterministic and client-safe.

---

### HB-008: Add optimistic concurrency + idempotency for claims
**Goal**: Prevent dual assignment under race conditions.

**Scope**
- Use `assignment_version` conditional write/CAS in claim path.
- Support idempotent claim retry behavior for same agent/request.
- Instrument claim success/conflict metrics.

**Acceptance criteria**
- Concurrent claims yield exactly one winner.
- Retried claim from winning agent returns idempotent success.
- Claim conflict rate is observable via metrics.

---

### HB-009: Support auto-claim on first agent reply (feature-flagged)
**Goal**: Reduce operational friction while preserving exclusivity.

**Scope**
- Add optional auto-claim path in send-message flow.
- Reuse same CAS/locking semantics as explicit claim.
- Gate behavior behind config/feature flag.

**Acceptance criteria**
- First reply can atomically claim when flag is enabled.
- Disabled flag enforces explicit claim-only behavior.

---

## Epic D — Identity masking and read/write behavior

### HB-010: Implement masked sender projection for user-facing APIs
**Goal**: Hide agent identity from end users.

**Scope**
- Update message serializer/projection in helpdesk mode.
- Render agent-authored messages as virtual `Helpdesk` identity.
- Preserve true sender internally for authorized admin/audit use.

**Acceptance criteria**
- End user never sees individual agent identifiers in helpdesk thread.
- Internal privileged views retain true sender metadata.

---

### HB-011: Enforce send constraints for unassigned conversations
**Goal**: Ensure only active assignee can respond as Helpdesk.

**Scope**
- Reject agent send attempts when conversation is unassigned unless auto-claim succeeds.
- Reject non-assignee send attempts while assigned.
- Return clear error codes for client handling.

**Acceptance criteria**
- Only assignee (or successful auto-claimer) can send.
- Error codes are stable and mapped in client UX.

---

### HB-012: Split participant/read models for end user vs helpdesk agents
**Goal**: Expose the right metadata per audience.

**Scope**
- User read/list APIs show participant = user + `Helpdesk`.
- Agent read/list APIs expose assignment state and ownership info.
- Keep response shape backward-compatible where required.

**Acceptance criteria**
- User payloads remain masked and minimal.
- Agent payloads include operational assignment fields.

---

## Epic E — Presence-driven release and failover

### HB-013: Subscribe routing service to presence events
**Goal**: Drive assignment lifecycle from agent availability.

**Scope**
- Consume `online/offline/unavailable` events for helpdesk agents.
- Correlate active assignee presence with assigned conversations.
- Trigger transition commands in routing state machine.

**Acceptance criteria**
- Assignee offline/unavailable event is detected within target SLA.
- Presence pipeline integration is observable and retry-safe.

---

### HB-014: Implement automatic release and re-alert flow on assignee disconnect
**Goal**: Keep conversations serviceable without manual intervention.

**Scope**
- Transition `assigned -> awaiting_agent` on assignee loss.
- Clear assignee metadata and stamp `last_failover_at`.
- Emit `helpdesk.conversation.released` + `helpdesk.conversation.alerted`.

**Acceptance criteria**
- Conversation ownership is automatically released on disconnect.
- Online group members are re-alerted immediately after release.

---

### HB-015: Handle no-agents-available during failover and recovery back to awaiting
**Goal**: Provide deterministic fallback when nobody can take over.

**Scope**
- If no online agents after release, set `paused_no_agents_online` and emit no-agent notice.
- When any eligible agent comes online, transition back to `awaiting_agent` and alert group.
- Throttle repeated no-agent notices.

**Acceptance criteria**
- Failover with zero agents results in exactly one throttled user notice window.
- Returning agent availability automatically reopens assignment flow.

---

## Epic F — Realtime and delivery guarantees

### HB-016: Add helpdesk routing realtime event contract
**Goal**: Provide consistent assignment lifecycle events to clients.

**Scope**
- Add event types:
  - `helpdesk.conversation.alerted`
  - `helpdesk.conversation.assigned`
  - `helpdesk.conversation.released`
  - `helpdesk.conversation.no_agents_online`
- Define payload schemas and compatibility rules.

**Acceptance criteria**
- Event schemas are documented and validated in tests.
- Clients can subscribe and react to all four lifecycle events.

---

### HB-017: Enforce channel-level data segregation for masked vs internal events
**Goal**: Prevent accidental identity leakage across channels.

**Scope**
- Ensure user channel only receives masked sender and user-safe routing data.
- Ensure helpdesk/internal channel can carry assignee IDs for authorized consumers.
- Add serializer guard tests.

**Acceptance criteria**
- No user-channel payload contains `active_agent_user_id` or true sender IDs.
- Authorized internal channels retain required operational details.

---

## Epic G — Testing, observability, rollout

### HB-018: Implement unit/integration/E2E coverage for assignment and masking flows
**Goal**: Validate correctness under normal and race conditions.

**Scope**
- Unit tests for state transitions, masking, and claim CAS/idempotency.
- Integration tests for create-alert-claim-release/no-agent flows.
- E2E test for mid-thread assignee change while user sees continuous Helpdesk identity.

**Acceptance criteria**
- Race-condition scenarios are reproducible and asserted in CI.
- Regression suite blocks identity leakage and dual assignment bugs.

---

### HB-019: Add operational metrics and dashboards for helpdesk routing health
**Goal**: Monitor responsiveness and reliability in production.

**Scope**
- Emit metrics:
  - `helpdesk_alerts_sent_total`
  - `helpdesk_claim_success_total`
  - `helpdesk_claim_conflict_total`
  - `helpdesk_failover_total`
  - `helpdesk_no_agents_notice_total`
  - `helpdesk_time_to_first_claim_ms`
- Build dashboard panels and alert thresholds.

**Acceptance criteria**
- Metrics are emitted in staging and production.
- On-call dashboard shows claim latency, failover count, and no-agent rate trends.

---

### HB-020: Roll out via feature flag with staged tenant/group enablement
**Goal**: Reduce rollout risk and support quick rollback.

**Scope**
- Add `helpdesk_bridge_mode` feature flag controls.
- Pilot with internal helpdesk group, then expand by tenant/group.
- Document rollback procedure to disable routing mode safely.

**Acceptance criteria**
- Feature can be enabled/disabled without deploy.
- Rollback path is tested and documented in runbook.

---

## Suggested implementation order (critical path)

1. HB-001, HB-002, HB-004 (schema + core state machine + creation mode)
2. HB-005, HB-006 (alerting + no-agent notice)
3. HB-007, HB-008, HB-010, HB-011 (claiming + masking + send guards)
4. HB-013, HB-014, HB-015 (presence failover)
5. HB-016, HB-017 (realtime contract + channel segregation)
6. HB-018, HB-019, HB-020 (hardening + observability + rollout)
