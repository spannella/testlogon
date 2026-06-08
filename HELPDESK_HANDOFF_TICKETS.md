# Helpdesk → Messenger Handoff — Implementation Tickets

This backlog turns the helpdesk queue into a live, presence-driven handoff: when an admin/agent is available a client's support chat is auto-routed straight into a live messenger DM (skipping the queue), with graceful fallback to the queue/ticket flow when nobody is online and clearer client-side status throughout. It builds on the existing helpdesk-bridge routing in `app/routers/messaging.py`, the presence/heartbeat plumbing, and the `app/services/messaging_routing.py` state machine.

## Milestone 1 — Presence-driven availability

### HMH-001: Agent availability service (presence-backed)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Today availability is computed ad hoc inside the router: `_is_user_online_available` (`app/routers/messaging.py:5165`) and `_resolve_online_helpdesk_members` (`app/routers/messaging.py:5175`) batch-read the presence table and apply `ONLINE_WINDOW_SEC` (`app/routers/messaging.py:209`) + `status in {"online","available"}`. Extract this into a dedicated `app/services/helpdesk_availability.py` so routing, claim, and the new auto-route path share one code path.
- Provide `count_available_agents(group_id, now_ts)`, `pick_available_agent(group_id, now_ts, *, exclude=set())`, and `is_agent_available(user_id, now_ts)`; reuse `_resolve_helpdesk_group_members` (`app/routers/messaging.py:5121`) for membership and the `batch_get_item` presence read already in `_resolve_online_helpdesk_members`.
- Add a least-loaded selection input so HMH-004 can prefer agents with the fewest `assigned` conversations (count via the `RoutingStateGroupIndex` query used in `get_helpdesk_queue`, `app/routers/messaging.py:6740`).
- Keep `status` normalization consistent with `_normalize_presence_status` (`app/routers/messaging.py:5197`); never raise (mirror the `try/except → []`/`False` behavior of the existing helpers).

**Acceptance Criteria**
- `count_available_agents` / `pick_available_agent` return the same set as `_resolve_online_helpdesk_members` for identical presence rows.
- `pick_available_agent` respects `exclude` and returns `None` when no member is online/available.
- The router helpers `_is_user_online_available` and `_resolve_online_helpdesk_members` delegate to the new service (no behavior change for existing callers).
- Unit tests cover: nobody online, one online, multiple online with `exclude`, stale `last_seen_at` beyond `ONLINE_WINDOW_SEC`, and `status="unavailable"`.

**Dependencies**
- None.

---

### HMH-002: Availability snapshot endpoint for the client
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add `GET /messaging/helpdesk/availability?group_id=...` returning `{ available_agent_count, any_available }` so the client can show "agents online" before starting a chat and choose the right status copy (HMH-008).
- Back it with `helpdesk_availability.count_available_agents` (HMH-001). This is read-only and must not require helpdesk-group membership (a customer needs to see it), unlike `get_helpdesk_queue` (`app/routers/messaging.py:6729`) which gates on `_is_helpdesk_group_member`.
- Throttle/cache is unnecessary at current scale but the response must never leak agent identities — return counts only.

**Acceptance Criteria**
- Endpoint returns `any_available=true` iff at least one group member is online/available.
- No agent `user_id`s appear in the payload.
- Endpoint is callable by a non-agent (customer) session.
- Pytest covers available vs. none-available.

**Dependencies**
- HMH-001.

---

## Milestone 2 — Auto-route to live messenger

### HMH-003: Auto-route flag and config
**Type:** Chore  
**Priority:** P0  
**Estimate:** 0.5 day

**Description**
- Add `HELPDESK_AUTO_ROUTE_ENABLED` (default off) alongside the existing `HELPDESK_AUTO_CLAIM_ON_REPLY_ENABLED` (`app/routers/messaging.py:1271`) so the queue-skipping handoff can be rolled out safely.
- Document it in `CLAUDE.md` feature-flags table and `.env.local.example`.
- Wire it into Settings parsing the same way the existing helpdesk env vars are read at module load.

**Acceptance Criteria**
- Flag defaults to off; when off, behavior is identical to today (alert-only fanout at creation, `app/routers/messaging.py:6016`).
- Flag is readable in the router module and toggled without code change.

**Dependencies**
- None.

---

### HMH-004: Auto-assign on conversation creation when an agent is available
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- In `create_conversation`'s helpdesk branch (`app/routers/messaging.py:6015`), today every new helpdesk chat is created in `routing_state="awaiting_agent"` (`app/routers/messaging.py:5947`) and only `fanout_helpdesk_alert` is called. When `HELPDESK_AUTO_ROUTE_ENABLED` (HMH-003) is on, first try `pick_available_agent(group_id, ...)` (HMH-001); if an agent is found, immediately drive the `assign_agent` transition via `_apply_helpdesk_routing_transition` (`app/routers/messaging.py:4727`) and add the agent as an active `admin` participant — reuse the exact participant-join + `participant_count` increment + membership-archive-event logic already in `_claim_helpdesk_conversation_internal` (`app/routers/messaging.py:6652`).
- Factor that participant-join block out of `_claim_helpdesk_conversation_internal` into a shared `_attach_agent_participant(conversation_id, agent_user_id, ts)` so claim and auto-route stay consistent (single source of truth, avoids drift).
- The conversation now behaves as a live messenger DM between customer and agent (it already is a `type=dm` helpdesk_bridge convo, `app/routers/messaging.py:1709`); the customer's `ConversationView` will show "agent joined" via HMH-009.
- If `pick_available_agent` returns `None`, fall back to the current path: `fanout_helpdesk_alert` and, if `delivered==0`, `_emit_no_agents_online_notice` (`app/routers/messaging.py:6016`).
- Emit the `helpdesk.conversation.assigned` lifecycle event (already fanned out by `_fanout_helpdesk_lifecycle_event`, `app/routers/messaging.py:4686`) so both parties' SSE streams update.
- Record metrics: reuse `record_helpdesk_claim("success")` / `record_helpdesk_claim_success` with a distinguishing reason in metadata, and add a `record_helpdesk_auto_routed` counter.

**Acceptance Criteria**
- With the flag on and an agent online, a freshly created helpdesk conversation comes back in `routing_state="assigned"` with `active_agent_user_id` set and the agent as an active `admin` participant.
- The queue (`GET /messaging/helpdesk/queue`) shows the conversation under `assigned`, not `awaiting_agent`.
- With the flag on and no agent online, behavior is byte-for-byte the existing fallback (alert + no-agents notice).
- With the flag off, behavior is unchanged.
- A `helpdesk.conversation.assigned` event is fanned out to the customer and the assigned agent.

**Dependencies**
- HMH-001, HMH-003.

---

### HMH-005: Notify the assigned agent on auto-route
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- When auto-routed (HMH-004), the chosen agent must be actively notified, not just have the conversation appear in their queue. Today `fanout_helpdesk_alert` (`app/routers/messaging.py:5374`) writes `helpdesk.conversation.alerted` events to all online members; for auto-route, write a targeted `helpdesk.conversation.assigned` alert to the single assigned agent and (best-effort) an in-app alert via `app.services.alerts.send_alert_email`/notification path used elsewhere in helpdesk.
- Ensure the agent's `useMessagingStream` (`frontend/src/hooks/useMessagingStream.ts:39`) already invalidates on `helpdesk.conversation.assigned`; extend it to also surface a toast "You've been connected with a customer" when the assigned agent is the current user.

**Acceptance Criteria**
- The assigned agent receives an `assigned` event scoped to them and a visible toast/notification.
- Other online agents do NOT get an actionable alert for an already-assigned conversation.
- Best-effort: a notification failure never rolls back the assignment.

**Dependencies**
- HMH-004.

---

### HMH-006: Pick a replacement agent when the assignee disconnects (handoff)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Today when an agent goes offline, `_handle_helpdesk_presence_event` (`app/routers/messaging.py:5284`) releases their `assigned` conversations back to `awaiting_agent` and re-alerts the group (`app/routers/messaging.py:5294`-`5326`). Extend that release path so that, when `HELPDESK_AUTO_ROUTE_ENABLED` is on, after `release_agent` it immediately calls `pick_available_agent(..., exclude={departing_agent})` and, if another agent is online, re-assigns straight to them (handoff) instead of leaving the chat waiting.
- Reuse `_attach_agent_participant` (HMH-004) and the `assign_agent` transition; emit `helpdesk.conversation.released` then `helpdesk.conversation.assigned` so both events are auditable in the routing-events log (`GET /conversations/{id}/routing-events`, `app/routers/messaging.py:6820`).
- If no replacement is available, keep the existing re-alert / pause-no-agents behavior.

**Acceptance Criteria**
- Assignee disconnect with another agent online → conversation transitions `assigned → awaiting_agent → assigned` to the new agent automatically.
- The new agent is added as an active participant and the old assignee's `active_agent_user_id` is cleared.
- No replacement online → existing release+re-alert (or pause) path is preserved.
- Routing-events log shows both the release and the re-assign with distinct events.

**Dependencies**
- HMH-004.

---

### HMH-007: Manual reassignment / transfer endpoint
**Type:** Feature  
**Priority:** P2  
**Estimate:** 2 days

**Description**
- Add `POST /messaging/helpdesk/conversations/{id}/transfer` (body `{ to_agent_user_id }`) so an assigned agent or admin can hand a live chat to a specific colleague. Validate the target is a group member (`_is_helpdesk_group_member`, `app/routers/messaging.py:5158`) and online (`helpdesk_availability.is_agent_available`).
- Implement as `release_agent` (must be called by current assignee — reuse the `routing_release_agent_mismatch` guard in `transition_helpdesk_routing`, `app/services/messaging_routing.py:140`) followed by `assign_agent` to the target, via `_apply_helpdesk_routing_transition`, attaching the target with `_attach_agent_participant` (HMH-004).
- Audit via `audit_event("messaging_helpdesk_conversation_transferred", ...)` mirroring the claim audit at `app/routers/messaging.py:6705`.

**Acceptance Criteria**
- Only the current assignee or an admin can transfer; others get 403.
- Transfer to an offline/non-member target is rejected with a structured error.
- After transfer, `active_agent_user_id` is the target, who can send messages (passes `_enforce_helpdesk_send_constraints`, `app/routers/messaging.py:6776`).
- Both `released` and `assigned` events are emitted and visible in routing-events.

**Dependencies**
- HMH-006.

---

## Milestone 3 — Client-side UX

### HMH-008: Expose routing status to the customer (non-agent)
**Type:** Bug  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Root cause of the poor client UX: `_conversation_out_from_items` (`app/routers/messaging.py:4587`) only populates `routing_state`/`active_agent_user_id` when `_is_helpdesk_agent_viewer` is true (`app/routers/messaging.py:4592`). For the customer, `routing_state` is empty, so the `HelpdeskRoutingBanner` short-circuits to `null` (`frontend/src/pages/messages/ConversationView.tsx:1606`, gated again by `conversation.routing_state` at line 1208). The customer sees no status at all.
- Expose a customer-safe routing view: always set `out.routing_state` for participants of a helpdesk_bridge convo, but DO NOT leak the agent's `active_agent_user_id` to the customer (keep that agent-only, consistent with `_project_helpdesk_lifecycle_payload_for_user`, `app/routers/messaging.py:4662`). Add a derived boolean `agent_connected` instead.
- Add `routing_state` (customer-safe values) + `agent_connected` to `ConversationOut` / `frontend/src/api/types.ts`.
- (Verified 2026-06-08) `routing_mode` is ALREADY exposed to customers for helpdesk_bridge convos (`app/routers/messaging.py:4588-4591`) so they can identify the chat — that exposure must be preserved; only `routing_state`/`active_agent_user_id` are agent-gated today. This ticket adds `routing_state` (customer-safe) without changing the `routing_mode` behavior.

**Acceptance Criteria**
- A customer's `GET /messaging/conversations` returns `routing_state` for their helpdesk chat and `agent_connected` reflecting `assigned`.
- The customer payload still includes `routing_mode` (unchanged) and never includes the agent's `active_agent_user_id`.
- Agent payloads are unchanged (still include `active_agent_user_id`).

**Dependencies**
- None.

---

### HMH-009: Customer status banner — "connecting…/in queue/agent joined"
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Rework `HelpdeskRoutingBanner` (`frontend/src/pages/messages/ConversationView.tsx:1575`) so it renders distinct, friendly copy for the CUSTOMER role (not just agents): `awaiting_agent` → "Connecting you to an agent…" (with spinner) or "You're in the queue — an agent will join shortly" when no agents are online (use HMH-002 availability); `assigned`/`agent_connected` → "An agent has joined the chat"; `paused_no_agents_online` → "No agents are online right now. We'll connect you as soon as one is available."; `closed` → "This support chat is closed."
- Hide the agent-only "Claim" button for customers (currently `showClaim` only triggers on `awaiting_agent` and there's no role check, `frontend/src/pages/messages/ConversationView.tsx:1593`) — gate `showClaim` on the viewer being a helpdesk agent.
- Drive the banner from HMH-008 fields so it works for customers; keep agent copy intact.

**Acceptance Criteria**
- Customer sees "Connecting…"/"in queue" while `awaiting_agent` and "An agent has joined" once `assigned`.
- The Claim button is never shown to customers.
- Agent-side banner copy and Claim button are unchanged.
- Component test covers customer vs. agent rendering for each state.

**Dependencies**
- HMH-008.

---

### HMH-010: Live status updates via SSE on the customer side
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- `useMessagingStream` (`frontend/src/hooks/useMessagingStream.ts:37`-`53`) currently invalidates `["conversations"]` and `["helpdesk-queue"]` on lifecycle events. Confirm the customer (who is NOT an agent and so won't have `helpdesk-queue`) gets the `["conversations"]` invalidation so their banner flips from "connecting" to "agent joined" without a manual refresh.
- The lifecycle events ARE fanned out to customers (`_helpdesk_lifecycle_recipients` includes non-`helpdesk_group:` active participants, `app/routers/messaging.py:4670`), so wire the customer banner refresh and a one-time toast ("An agent has joined your chat") on `helpdesk.conversation.assigned` when the viewer is the customer.

**Acceptance Criteria**
- On auto-route/claim, the customer's banner updates within one SSE round-trip (no reload).
- A toast fires once for the customer on `assigned`.
- No regression to the agent's existing `helpdesk-queue` invalidation.

**Dependencies**
- HMH-008, HMH-009.

---

### HMH-011: Pre-chat availability hint on "Contact Support"
**Type:** Feature  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- In `HelpdeskPage` (`frontend/src/pages/helpdesk/HelpdeskPage.tsx:152`), before the user starts a chat, fetch HMH-002's availability and adjust the button/subtext: agents online → "Contact Support (agents available)"; none online → "Leave a message — no agents online right now, we'll follow up."
- This sets expectations so the queue fallback (HMH-004) doesn't feel like a dead end.

**Acceptance Criteria**
- Button copy/subtext reflects live availability.
- Starting a chat still works in both states.
- No extra network calls per render (single query with sane `staleTime`).

**Dependencies**
- HMH-002.

---

## Milestone 4 — Fallback & queue/ticket integration

### HMH-012: Robust no-agents fallback to queue (and optional ticket)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Harden the no-agents path so a customer chat created while everyone is offline is never lost: the existing `_emit_no_agents_online_notice` (`app/routers/messaging.py:5421`) writes a system message and pauses the convo; ensure that when an agent later comes online, the resume path (`_handle_helpdesk_presence_event`, available branch at `app/routers/messaging.py:5337`-`5364`, which resumes `paused_no_agents_online` → `awaiting_agent` and re-alerts) ALSO attempts an immediate auto-assign when `HELPDESK_AUTO_ROUTE_ENABLED` is on (reuse HMH-004's assign helper), so the customer is connected the moment an agent appears.
- Optionally (behind a flag) open a support ticket for paused chats older than a threshold so they enter the ticketing SLA flow; cite the ticket service as the integration point but keep this additive and off by default.

**Acceptance Criteria**
- Customer chats created with no agents online are paused with a clear system notice (existing behavior preserved).
- When an agent next comes online, a paused chat is auto-assigned to them (flag on) rather than only re-queued.
- Ticket creation, if enabled, is additive and does not change the messenger flow.

**Dependencies**
- HMH-004.

---

## Milestone 5 — Tests

### HMH-013: Backend regression tests for auto-route, handoff, and fallback
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `tests/test_helpdesk_handoff.py` (offline, moto/in-memory, mirroring `tests/test_messaging_routing.py` and the patched-table style in CLAUDE.md) covering: auto-assign on create with an agent online (HMH-004); fallback to alert/no-agents notice with nobody online; handoff to a replacement on assignee disconnect (HMH-006); manual transfer authorization + state (HMH-007); resume-then-auto-assign on agent return (HMH-012).
- Assert the customer-safe projection: `active_agent_user_id` absent for the customer, present for the agent (HMH-008).
- Toggle `HELPDESK_AUTO_ROUTE_ENABLED` via the frozen-settings `object.__setattr__` pattern used across the suite.

**Acceptance Criteria**
- All new pytest cases pass under `just test` with the dev stack down.
- Flag-off cases assert byte-for-byte current behavior (no auto-route).
- Availability service (HMH-001) has direct unit coverage independent of the router.

**Dependencies**
- HMH-004, HMH-006, HMH-007, HMH-008, HMH-012.

---

### HMH-014: E2E coverage for the client handoff experience
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Extend `frontend/e2e/helpdesk.spec.ts` / `helpdesk-extra.spec.ts` with: customer starts a chat while an agent (Charlie) is online → customer sees "An agent has joined" without claiming; customer starts a chat with no agents → sees "in queue / no agents" copy; agent comes online → customer banner flips live; transfer between two agents reflects on the customer side as continuity.
- Seed agent presence by writing presence rows directly to DynamoDB (same direct-seed approach used for sessions per CLAUDE.md), since `presence/heartbeat` (`app/routers/messaging.py:6835`/`12835`) drives availability.
- Follow the established E2E conventions in CLAUDE.md: `injectAuth`, `page.request` + `x-csrf-token`, scope text assertions with `page.locator("p").filter(...)` to avoid strict-mode violations, and trigger refetch via `window.dispatchEvent(new Event("online"))`.

**Acceptance Criteria**
- New specs pass under `just e2e` after `just restart` (clean seed).
- Customer-visible status strings are asserted for each routing state.
- Tests do not leak agent identity into customer-side assertions.

**Dependencies**
- HMH-009, HMH-010, HMH-013.

---
