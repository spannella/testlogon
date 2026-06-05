# HELP-002: Unified Support Hub — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

HELP-002 specifies a **Unified Support Hub** that merges three disconnected support surfaces — live helpdesk chat (helpdesk_bridge), the ticket system, and KYC case tracking — into a single user-facing `/support` entry point. The hub exposes three modes: (1) "Chat now" for live helpdesk conversations, (2) "My tickets" for async ticket management, and (3) a KYC panel for case-linked support. It also introduces a new **conversation ↔ ticket link layer** (a `ticket_id` field on a helpdesk conversation and a `conversation_id` field on a ticket) plus a unified `GET /ui/support/items` aggregator endpoint.

- **Type**: feature
- **Priority**: High
- **Status**: UNBUILT — none of the required backend services, routers, frontend pages, or link layer exist
- **Owning area**: Support / Helpdesk Engineering
- **User persona**: any authenticated user (customer) seeking support; also KYC applicants
- **Cross-referenced tickets**: HELP-001 (auto-ticket-on-timeout, availability), KYC-025 (KYC appeals)
- **Dependencies**: existing helpdesk routing (`app/routers/messaging.py`, `app/services/messaging_routing.py`), tickets (`app/routers/tickets.py`, `app/services/tickets.py`), KYC cases (`app/services/kyc_cases.py:84,300-316,420-428`)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Helpdesk chat (already built)

Live helpdesk chat uses the `routing_mode="helpdesk_bridge"` path in the messaging system:
- `app/routers/messaging.py` — `POST /ui/messaging/helpdesk/conversations` (create helpdesk convo), `POST /ui/messaging/helpdesk/conversations/{id}/claim` (agent claim), `GET /ui/messaging/helpdesk/queue` (agent queue)
- `app/services/messaging_routing.py` — `route_new_helpdesk_conversation()`, `claim_helpdesk_conversation()`
- Frontend: `frontend/src/pages/helpdesk/HelpdeskPage.tsx` — single-file page that shows the user's helpdesk conversations. No tab for tickets or KYC.

### 2.2 Tickets (already built)

- `app/routers/tickets.py` — full CRUD + messaging + spaces + kanban
- `app/services/tickets.py` — DynamoDB-backed ticket management
- Frontend: `frontend/src/pages/tickets/` — `TicketsPage.tsx`, space views, kanban board. Completely separate navigation item from helpdesk.

### 2.3 KYC ↔ ticket link (partially built)

`app/services/kyc_cases.py:84` — `KycCase` dataclass has a `ticket_id: str | None` field.
`app/services/kyc_cases.py:300-316` — `create_kyc_ticket()` creates a ticket for a KYC step and stores the `ticket_id` back on the case.
`app/services/kyc_cases.py:420-428` — `sync_from_ticket_event()` propagates ticket status changes back to the KYC case.

The KYC ↔ ticket bridge is functional. But there is **no user-facing surface** that shows a user "here are the tickets linked to your KYC case" alongside their helpdesk conversations.

### 2.4 Missing: conversation ↔ ticket link

The `Conversation` DynamoDB schema (`app/routers/messaging.py`) stores a `routing_mode`, participant list, and metadata — but no `ticket_id` field. The ticket schema (`app/services/tickets.py`) has no `conversation_id` field. HELP-001's auto-ticket-on-timeout feature cannot store the resulting ticket ID back on the conversation, and the hub's "promote chat → ticket" action has no data to write to.

### 2.5 Missing: unified list endpoint

No `GET /ui/support/items` or similar aggregator exists. `app/main.py` has no `support` router registered. `grep -rn "/ui/support" app/` returns nothing.

### 2.6 Missing: frontend hub

`frontend/src/pages/support/` does not exist. `frontend/src/App.tsx` has no `/support` route.

---

## 3. Gap / Feature Analysis

### 3.1 What must be built

**Backend link layer (new fields on existing records)**:
- `conversations` DDB item: add `ticket_id: str | None = None` (nullable, set when a chat is promoted to a ticket)
- `tickets` DDB item: add `conversation_id: str | None = None` (nullable, set when a ticket spawns a live chat)
- Neither field is a GSI key — they're metadata, looked up by traversal after fetching one record

**Backend service: `app/services/support_hub.py`** (new, ~200 lines):
- `get_unified_support_items(user_sub: str) -> list[dict]` — merges helpdesk conversations (filtered to `routing_mode="helpdesk_bridge"`, owner or participant) + `list_tickets(user_sub)` + KYC case tickets for the user; sorts by `last_activity_at` / `updated_at` descending; returns a typed list with `item_type` (conversation | ticket | kyc_ticket) + `status`, `created_at`, `title`
- `promote_conversation_to_ticket(user_sub, conversation_id) -> dict` — creates a ticket from a helpdesk conversation, links both sides
- `open_support_request(user_sub, category, kyc_case_id?, mode) -> dict` — creates either a helpdesk conversation (mode=chat) or a ticket (mode=ticket) with optional `kyc_case_id` tag

**Backend router: `app/routers/support.py`** (new, ~100 lines):
- `GET /ui/support/items` → aggregated list
- `POST /ui/support/request` → create chat or ticket
- `POST /ui/support/conversations/{id}/to-ticket` → promote conversation to ticket
- Registered in `app/main.py`

**Frontend (new)**:
- `frontend/src/pages/support/SupportHub.tsx` — tabbed hub (Get Help / My Conversations / My Tickets / KYC)
- `frontend/src/api/endpoints/support.ts` — API wrappers
- Route `/support` in `App.tsx`
- Redirect `/helpdesk` → `/support` (user-facing; agent queue at `/helpdesk/queue` unchanged)

### 3.2 Dependency ordering

HELP-001 provides "chat now vs. submit request" availability logic (business hours, agent availability). The hub consumes HELP-001's availability check to decide which mode to offer first. If HELP-001 is not merged yet, the hub can default to always showing both options.

### 3.3 Feature flags

`SUPPORT_HUB_ENABLED` env var (default `false` until rollout) gates all new endpoints; existing `/helpdesk` and `/tickets` routes remain active as fallback.

---

## 4. Proposed Design / Fix

### 4.1 DynamoDB changes (backward-compatible adds)

No new tables needed. Two optional fields added to existing item schemas:
- `conversations` table: `ticket_id` written by `promote_conversation_to_ticket()`
- `tickets` table: `conversation_id` written by same function and by `open_support_request(mode=chat)`

### 4.2 `support_hub.py` sketch

```python
def get_unified_support_items(user_sub: str) -> list[dict]:
    items = []
    # 1. Helpdesk conversations where user is a participant
    convos = list_helpdesk_conversations(user_sub)  # from messaging_routing
    items.extend({"item_type": "conversation", "id": c["conversation_id"],
                  "status": c.get("status"), "title": c.get("subject", "Support Chat"),
                  "last_activity_at": c.get("last_message_at", 0)} for c in convos)
    # 2. Tickets owned by user
    tickets = list_tickets(user_sub)  # from tickets.py
    items.extend({"item_type": "ticket", "id": t["ticket_id"],
                  "status": t.get("status"), "title": t.get("subject", ""),
                  "last_activity_at": t.get("updated_at", 0)} for t in tickets)
    # 3. KYC-linked tickets (from kyc_cases.list_case_tickets)
    kyc_tickets = list_kyc_tickets_for_user(user_sub)  # kyc_cases.py helper
    items.extend({"item_type": "kyc_ticket", **kt} for kt in kyc_tickets)
    items.sort(key=lambda x: x["last_activity_at"], reverse=True)
    return items
```

### 4.3 Dev/Prod parity (SECOPS-007)

No new AWS services. All operations go through the existing DynamoDB client (`T.conversations`, `T.tickets`, `T.kyc_cases`). The support hub is pure application logic on top of existing tables — same code path in dev and prod. No new `*_MOCK_ENABLED` flag needed.

### 4.4 Migration / rollback

No table migrations. The two new nullable fields default to `None` / absent; existing items without them are handled by `item.get("ticket_id")` returning `None`. Rollback: remove router registration from `app/main.py`; old `/helpdesk` and `/tickets` routes remain.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (new file: `tests/test_support_hub.py`)
- `test_unified_list_merges_convos_tickets_kyc` — mocked convos + tickets + kyc tickets all appear in result
- `test_unified_list_sorted_by_recency`
- `test_promote_conversation_links_both_sides` — ticket created + both `conversation_id` and `ticket_id` set
- `test_open_chat_request_creates_helpdesk_conversation`
- `test_open_ticket_request_creates_ticket_with_kyc_case_id`

### Playwright E2E (new file: `frontend/e2e/support-hub.spec.ts`, ~15 tests)
- From hub, start a live chat (shows in "My Conversations")
- Submit a ticket (shows in "My Tickets")
- KYC category creates item tagged `kyc_case_id`
- Promote chat → ticket via "to-ticket" endpoint; verify both sides linked
- Hub shows KYC step ticket linked to KYC case
- SUPPORT_HUB_ENABLED=false → 404 on all new endpoints; old routes still work

### Observability
- Counter `support_hub_items_total{type}` per `get_unified_support_items` call
- Counter `support_hub_promotion_total` per promote-to-ticket
- Tie to SECOPS-001 audit_event: `support.request_created`, `support.conversation_promoted`

### Effort estimate
- Backend service + router: M (2-3 days)
- Frontend hub page: M (2-3 days)
- E2E tests: S (1 day)
- Total: L (5-7 days)

### Suggested implementation order
1. Add `ticket_id` / `conversation_id` nullable fields (backward-compat)
2. `app/services/support_hub.py` + `app/routers/support.py` + registration in `app/main.py`
3. `frontend/src/pages/support/SupportHub.tsx` + route
4. E2E spec
5. Redirect old `/helpdesk` → `/support`
