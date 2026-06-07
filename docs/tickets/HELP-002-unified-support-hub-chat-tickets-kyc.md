# HELP-002: Unified Support Hub — Live Chat + Tickets + KYC in one UI

**Ticket**: HELP-002
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: High
**Dependencies**: HELP-001 (helpdesk no-agent/escalation), KYC-025 (KYC appeals), helpdesk routing (`app/routers/messaging.py`), tickets (`app/routers/tickets.py`, `app/services/tickets.py`), KYC cases (`app/services/kyc_cases.py`)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Support is fragmented across **three disconnected surfaces**:
- **Live helpdesk chat** — `frontend/src/pages/helpdesk/HelpdeskPage.tsx`
  (messaging `routing_mode="helpdesk_bridge"`).
- **Tickets** — `frontend/src/pages/tickets/*` (TicketsPage, spaces, kanban).
- **KYC** — separate KYC pages; KYC cases already carry a `ticket_id` and
  `sync_from_ticket_event` (`app/services/kyc_cases.py:84,300-316,420-428`), but
  there's no user-facing place to *talk to support* about a KYC problem.

A user has no single place to: get **immediate help (chat)**, **file/monitor a
ticket** when no one's available or the issue is async, or **resolve a KYC issue**
(which is itself ticket-backed). They must know which silo to use.

### 1.2 Goal — one Support Hub

A single **Support** experience where a user can:
1. **Chat now** with a person (live helpdesk), or
2. **File a helpdesk ticket** (async), and **monitor all their tickets** (status,
   replies, history) in one list, and
3. Handle **KYC** in the same place — see their KYC case + its required steps as
   **linked tickets**, and **talk to helpdesk about a KYC issue** (a chat/ticket
   linked to the `kyc_case_id`).

The two modes are unified: a chat with no available agent can become a ticket
(HELP-001 auto-ticket), and a ticket can spawn a live chat — same thread of
record.

### 1.3 Design Principles

- **One entry point, two modes**: "Get help" → choose *Chat now* (if available) or
  *Submit a request* (ticket). Availability/business-hours (HELP-001) drive which
  is offered/recommended.
- **One record, cross-linked**: a support interaction has a stable identity that
  can carry both a conversation and a ticket; KYC cases link in via their existing
  `ticket_id`.
- **Reuse, don't rebuild**: leverage existing helpdesk routing, the tickets
  system, and the KYC↔ticket sync. The new work is the **link layer + unified
  UI + unified list endpoint**.

---

## 2. Scope

### 2.1 Unified UI (`frontend/src/pages/support/` — new, absorbing helpdesk + tickets)
- **Support hub** with tabs/sections:
  - **Get help** (composer): pick a category; choose **Chat now** (live, shown only
    when agents available / in hours) or **Submit a request** (ticket). KYC is a
    selectable category.
  - **My conversations** (live + recently active helpdesk chats).
  - **My tickets** (all helpdesk + KYC-linked tickets, with status filters).
  - **KYC** panel: current case status + required steps (each step a linked
    ticket), with a "Get help with KYC" action that opens a chat/ticket linked to
    the case.
- Migrate `HelpdeskPage` + `TicketsPage` content under this hub (keep deep links
  working / redirect). Agent-side queue UI stays (HELP-001).

### 2.2 Link layer (backend)
- **Conversation ↔ ticket link** (NEW — does not exist today): store a
  `ticket_id` on a helpdesk conversation and a `conversation_id` on a ticket, so a
  chat can be promoted to a ticket and vice-versa, sharing transcript/context.
  (HELP-001's auto-ticket-on-timeout uses this.)
- **KYC ↔ support**: reuse the existing `kyc_cases` `ticket_id`/`sync_from_ticket_event`
  so KYC step tickets appear in "My tickets"; add a "support about KYC" path that
  opens a helpdesk chat/ticket tagged with `kyc_case_id` and surfaces it on the
  KYC panel.
- **Unified support list endpoint**: `GET /ui/support/items` returning the user's
  helpdesk conversations + tickets (helpdesk + KYC) merged, sorted by recency, with
  type/status — powering "My tickets/conversations".

### 2.3 Categories & routing
- A small category taxonomy (General, Billing, KYC, …) on create; KYC category +
  KYC-linked items route to the KYC/compliance group; others to the helpdesk group.

---

## 3. Implementation Sketch

### Backend
- `app/services/`: add the conversation↔ticket link helpers; a
  `support_inbox`/aggregator service for the unified list (merges helpdesk
  conversations + `list_tickets` + KYC case tickets for the user).
- `app/routers/support.py` (new): `GET /ui/support/items`, `POST /ui/support/request`
  (creates chat or ticket per chosen mode + category, linking `kyc_case_id` when
  relevant), `POST /ui/support/conversations/{id}/to-ticket` (promote chat→ticket).
- Reuse: messaging helpdesk create/claim, tickets create/list/message, kyc_cases
  link/sync. Register router in `app/main.py`.

### Frontend
- `frontend/src/pages/support/SupportHub.tsx` (+ subcomponents) consuming
  `api/endpoints/support.ts`. Route `support` in `App.tsx`; redirect old
  `/helpdesk` and `/tickets` user routes into the hub (agent/admin ticket-space
  routes unchanged).
- KYC panel reads the user's case + step tickets; "Get help with KYC" → support
  request with `category=kyc`, `kyc_case_id` linked.

### Settings/flags
- `SUPPORT_HUB_ENABLED` to gate rollout; reuse HELP-001 availability/business-hours
  to decide whether "Chat now" is offered.

---

## 4. Testing
- **E2E**: from the hub, start a live chat; submit a ticket and see it in "My
  tickets"; with no agents, "Chat now" is hidden/falls back to ticket (HELP-001);
  promote a chat to a ticket; KYC category opens a case-linked item; a KYC step
  ticket appears in the unified list and its status syncs to the KYC case.
- **pytest**: unified-list aggregation (helpdesk + tickets + KYC), conversation↔ticket
  link integrity, KYC `kyc_case_id` tagging + `sync_from_ticket_event`.

## 5. Out of Scope
- Agent-side console redesign (only the customer hub here).
- On-call scheduling / bot answering (future; see HELP-001 optional items).

---

## 6. Current-state reference
- Helpdesk chat + routing: `app/routers/messaging.py` (helpdesk_bridge create/claim/queue), `messaging_routing.py`.
- Tickets: `app/routers/tickets.py`, `app/services/tickets.py`, `frontend/src/pages/tickets/*`.
- KYC↔ticket (already linked): `app/services/kyc_cases.py:84,300-316,420-428` (`ticket_id`, `sync_from_ticket_event`).
- Helpdesk UI: `frontend/src/pages/helpdesk/HelpdeskPage.tsx`.
- Related tickets: **HELP-001** (no-agent SLA/escalation/auto-ticket — the chat→ticket bridge this hub surfaces), **KYC-025** (KYC appeals — appeals become a support item here).
