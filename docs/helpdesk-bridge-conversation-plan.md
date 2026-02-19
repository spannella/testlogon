# Helpdesk Bridge Conversation Mode — Implementation Plan

## Goals

Implement a special messaging mode where an end user chats with a **Helpdesk** identity while the system dynamically routes the conversation to an available helpdesk agent.

Behavior required:

1. User starts a conversation addressed to the Helpdesk identity.
2. All online members of the helpdesk group are alerted.
3. First agent to accept/respond becomes the active responder in a temporary 1:1 bridge.
4. End user always sees the responder as the Helpdesk identity (agent identity hidden).
5. If active agent goes offline/disconnects while conversation is still open, routing returns to group-available mode.
6. If no helpdesk agents are online when routing is needed, show a deterministic system message telling user nobody is online and to try again later.

---

## Solution outline

Treat this as a **stateful routed conversation** with a virtual participant (`helpdesk_group`) and an optional live assignee (`agent_user_id`).

### Conversation states

- `awaiting_agent`: no live assignee; group members may claim.
- `assigned`: exactly one active assignee is handling replies.
- `paused_no_agents_online`: no available agents; user is informed and conversation waits for availability.
- `closed` (optional, existing lifecycle).

### Key principles

- **Identity masking**: user-facing events and payloads render sender as `Helpdesk` for all agent messages.
- **Single active assignee**: only one agent can own an assigned conversation at a time.
- **Fast failover**: loss of active assignee transitions back to `awaiting_agent` and re-alerts online group members.
- **Deterministic system messaging**: standardized event/message when nobody is online.

---

## Data model changes

Add or extend `conversation_routing` metadata (same record or sibling table):

- `conversation_id`
- `routing_mode` = `helpdesk_bridge`
- `group_id` (helpdesk group)
- `state` (`awaiting_agent|assigned|paused_no_agents_online|closed`)
- `active_agent_user_id` (nullable)
- `active_agent_claimed_at` (nullable)
- `last_failover_at` (nullable)
- `assignment_version` (integer for optimistic concurrency)
- `no_agents_notice_sent_at` (nullable; throttle duplicate notices)

Optional audit table (`conversation_routing_events`):

- `event_id`, `conversation_id`, `event_type`, `actor_user_id`, `from_state`, `to_state`, `created_at`, `metadata`

This helps compliance/debugging without exposing agent identity to end users.

---

## API and service changes

## 1) Conversation creation

When user starts a helpdesk chat:

- Create conversation with `routing_mode=helpdesk_bridge`, `state=awaiting_agent`.
- Publish alert event to all currently online users in `group_id`.
- If no one online at creation time:
  - set `state=paused_no_agents_online`
  - inject user-visible system message: "No helpdesk agents are online right now. Please try again later."

## 2) Agent claim/accept endpoint

Add endpoint (or command) for helpdesk members:

- `POST /v1/messaging/helpdesk/conversations/{id}/claim`

Server behavior:

- Validate caller in helpdesk group and online/available.
- Atomic compare-and-set from `awaiting_agent -> assigned`.
- Set `active_agent_user_id`, timestamps, increment `assignment_version`.
- Return idempotent success if caller already assignee.
- Return conflict if already assigned to another agent.

## 3) Sending messages

For assigned conversations:

- Agent reply is stored with true sender internally.
- User-facing render path maps sender display to Helpdesk virtual identity.
- Agent identity is only available to authorized internal/admin/audit paths.

For unassigned conversations:

- Block outbound agent send unless first claiming (or auto-claim on first reply with same CAS logic).

## 4) Presence and failover

Subscribe routing service to presence changes (`online/offline/unavailable`):

- If active assignee goes offline/unavailable:
  - transition `assigned -> awaiting_agent`
  - clear `active_agent_user_id`
  - publish group re-alert event
  - if no online agents exist, set `paused_no_agents_online` and emit the offline notice (throttled)

- If in `paused_no_agents_online` and any agent comes online:
  - transition to `awaiting_agent`
  - alert group members

## 5) Read/list APIs

User view:

- Participants include user + `Helpdesk` virtual user.
- Messages from any agent appear as from `Helpdesk`.

Agent view:

- Show assignment status and ownership metadata needed for operations.
- Optionally include "claimed by you / another agent" indicators.

---

## Realtime/eventing changes

Add events:

- `helpdesk.conversation.alerted`
- `helpdesk.conversation.assigned`
- `helpdesk.conversation.released`
- `helpdesk.conversation.no_agents_online`

Channel strategy:

- User channel receives masked message/user events only.
- Helpdesk group channel receives claim/release/alert events with actual agent IDs where authorized.

Ensure websocket payload serializer applies identity masking consistently (API and realtime parity).

---

## Concurrency and correctness

Use optimistic locking (`assignment_version`) or transactional conditional writes to prevent dual assignment.

Critical race scenarios to cover:

1. Two agents claim simultaneously.
2. Agent sends first reply at same instant another agent claims.
3. Agent disconnect event races with outbound send.
4. Presence flapping causing repeated no-agent notices.

Mitigations:

- CAS for claim and auto-claim.
- Idempotency keys for claim requests.
- Notice throttling window (for example 5–10 minutes).
- Ordered event processing by conversation key where possible.

---

## UX behaviors

### End user

- Starts chat with "Helpdesk".
- Sees continuous thread from Helpdesk identity.
- If no one available, sees explicit system notice and optional CTA (retry later, leave message if supported).

### Helpdesk agent

- Receives incoming alert with "Claim conversation" action.
- Once claimed, sees locked ownership status.
- If disconnected, ownership is released automatically.

---

## Security and privacy

- Enforce that only helpdesk-group members can claim/respond.
- Do not leak `active_agent_user_id` in user-facing APIs/events.
- Audit all claim/release transitions.
- Add tests for serialization redaction.

---

## Implementation phases

## Phase 1 — Foundation

1. Add routing metadata schema + migrations.
2. Introduce state machine and transition guards in messaging service.
3. Add masked sender projection for helpdesk mode.

## Phase 2 — Assignment flow

1. Implement claim endpoint/command with CAS.
2. Add helpdesk alert event on new unassigned conversation.
3. Support auto-claim on first agent response (optional but recommended).

## Phase 3 — Presence failover

1. Wire presence events to routing transitions.
2. Implement release/re-alert/no-agent notice flow.
3. Add throttling for repeated no-agent notices.

## Phase 4 — UI integration

1. End-user thread labeling and no-agent system message UX.
2. Agent inbox alert + claim controls + ownership indicators.
3. Realtime updates for assignment changes.

## Phase 5 — Hardening

1. Concurrency and race-condition tests.
2. Load test for bursty helpdesk conversations.
3. Audit logging and observability dashboards.

---

## Test plan

### Unit tests

- State transitions valid/invalid paths.
- Masking logic for message serialization.
- Claim CAS behavior and idempotency.

### Integration tests

- Create helpdesk conversation with online agents -> alerts emitted.
- Claim conflict between two agents -> only one winner.
- Assignee disconnect -> conversation released and re-alerted.
- No agents online -> user gets deterministic notice.

### E2E tests

- User chats continuously while assignee changes; user only sees Helpdesk identity.
- Conversation recovers when agent logs off mid-thread.

### Observability checks

Track metrics:

- `helpdesk_alerts_sent_total`
- `helpdesk_claim_success_total`
- `helpdesk_claim_conflict_total`
- `helpdesk_failover_total`
- `helpdesk_no_agents_notice_total`
- `helpdesk_time_to_first_claim_ms`

---

## Rollout plan

1. Feature flag: `helpdesk_bridge_mode`.
2. Internal pilot with limited helpdesk group.
3. Monitor claim conflicts, failovers, and no-agent rates.
4. Gradual rollout by tenant/group.
5. Define rollback: disable flag and keep existing conversation behavior.

---

## Open product decisions

1. Should first agent reply auto-claim if unassigned, or require explicit claim always?
2. Should users be able to leave offline messages when no agents are online?
3. Maximum idle timeout before auto-release of assigned conversation?
4. Can supervisors force-reassign an active conversation?
5. SLA targets for first response and failover time?

