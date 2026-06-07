# HELP-001: Helpdesk No-Agent-Available Improvements (SLA, Out-of-Hours, Queue Feedback)

**Ticket**: HELP-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Dependencies**: messaging helpdesk routing (`app/routers/messaging.py`, `app/services/messaging_routing.py`), tickets system (TEST/ticket pipeline), notifications

---

## 1. Overview & Motivation

### 1.1 Current behavior (what exists)

The helpdesk is a **presence-driven pull queue**. A customer starts a chat
(`POST /messaging/conversations`, `routing_mode="helpdesk_bridge"`) → conversation
enters `routing_state="awaiting_agent"`; online agents see it via
`GET /helpdesk/queue` and **claim** it (`POST /helpdesk/conversations/{id}/claim`)
→ `assigned`. State machine (`messaging_routing.py`):
`awaiting_agent → assigned → closed`, plus `paused_no_agents_online`.

**When no agent is available it IS handled, but passively:**
- `fanout_helpdesk_alert()` finds 0 online agents → the conversation is auto-paused
  to `paused_no_agents_online` and a **system message** is posted: *"No helpdesk
  agents are online right now. Please try again later."* (throttled by
  `NO_AGENTS_NOTICE_THROTTLE_SEC`, default 600s) — `messaging.py` ~5401-5447.
- The customer can still send messages (stored, not rejected); UI shows a red
  "No agents online — will resume when an agent comes online" banner.
- When an agent's presence heartbeat arrives, paused conversations in that group
  auto-resume to `awaiting_agent` and agents are alerted.

**The gap:** a customer can wait **indefinitely**. There is no SLA/timeout,
no escalation, no out-of-hours fallback, and no queue feedback.

### 1.2 Proposed improvements

Make the no-agent path active and bounded:

1. **SLA timeout → escalation / auto-ticket.** A background sweep over
   `awaiting_agent` + `paused_no_agents_online` conversations: if unclaimed for
   `HELPDESK_UNCLAIMED_TIMEOUT_MINUTES` (e.g. 30), escalate — notify an
   admin/escalation group and/or **auto-create a support ticket** (reuse the
   tickets system) seeded from the conversation, and tell the customer
   ("We've created ticket #X and will follow up by email").
2. **Out-of-hours / business-hours fallback.** Distinguish "open but no agents"
   from "closed". If outside configured business hours, post an
   out-of-hours notice and route to the fallback (auto-ticket / email capture)
   instead of an indefinite pause.
3. **Queue feedback to the customer.** Show position-in-queue and/or an estimated
   wait while `awaiting_agent` (e.g. "You're #3 in line").
4. **(Optional) CSAT on close** and **(optional) bot/FAQ auto-responder** for the
   no-agent window.

### 1.3 Design principles

- **Don't drop messages** (already true) — improvements are additive.
- **Bounded waits**: every queued chat has a deterministic escalation path so
  nothing sits forever.
- **Config-driven**: business hours, timeouts, and fallback type are settings;
  defaults preserve current behavior when unset.

---

## 2. Implementation

### 2.1 Settings (`app/core/settings.py`)
- `HELPDESK_UNCLAIMED_TIMEOUT_MINUTES` (default 30; 0 = disabled)
- `HELPDESK_ESCALATION_GROUP_ID` / escalation target
- `HELPDESK_AUTO_TICKET_ON_TIMEOUT` (bool)
- `HELPDESK_BUSINESS_HOURS` (per-group schedule + timezone) and
  `HELPDESK_OUT_OF_HOURS_FALLBACK` (none | notice | auto_ticket)
- `HELPDESK_QUEUE_POSITION_ENABLED` (bool)

### 2.2 Backend
- **SLA worker**: a periodic task (alongside the existing scheduled-message /
  promotion loops) scanning routing-state GSIs for aged `awaiting_agent` /
  `paused_no_agents_online` items → escalate / auto-ticket / notify. Use a
  `last_state_change_at` (and the existing `no_agents_notice_sent_at`) to measure age.
- **Business-hours check** in the create/queue path (`messaging.py` ~5948) before
  fanout: if closed, take the out-of-hours fallback instead of pausing.
- **Queue position**: derive from the routing-state group index ordering; expose
  on the conversation/queue payload.
- **Auto-ticket**: map a helpdesk conversation → a ticket (subject from first
  message, transcript link, requester = customer).

### 2.3 Frontend
- Customer `ConversationView` helpdesk banner: show queue position/ETA when
  `awaiting_agent`; show out-of-hours / escalation-created states.
- Optional CSAT prompt on `closed`.

---

## 3. Testing
- **pytest**: SLA sweep escalates after timeout; business-hours fallback (open vs
  closed); auto-ticket creation from a timed-out chat; resume-on-agent-online
  still works; throttle of the no-agents notice preserved.
- **E2E**: customer starts chat with no agents → notice + paused → (timeout) →
  escalation/ticket + customer told; agent comes online → resumes; queue position
  shown; out-of-hours fallback path.

## 4. Out of Scope
- Full on-call scheduling / shift management (future).
- Knowledge-base/bot answering beyond a simple FAQ auto-responder (future).

---

## 5. Current-state reference (for implementers)
- Create + initial routing: `app/routers/messaging.py` ~5839-5949.
- No-agents notice + pause: `_emit_no_agents_online_notice()` ~5401-5447; notice
  text + throttle ~1265-1266.
- Presence-driven resume: `_handle_helpdesk_presence_event()` ~5264-5347.
- Claim: `_claim_helpdesk_conversation_internal()` ~6503-6649.
- State machine: `app/services/messaging_routing.py` ~77-246.
- Frontend banners: `frontend/src/pages/messages/ConversationView.tsx` ~1475-1510;
  queue/your-chats: `frontend/src/pages/helpdesk/HelpdeskPage.tsx`.
