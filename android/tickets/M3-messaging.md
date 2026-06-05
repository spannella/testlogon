# M3 — Messaging — Tickets

Decomposition of milestone **M3** (epics **E18–E22**). Conventions as in
[`M1-auth-foundation.md`](./M1-auth-foundation.md). Format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**.

**Milestone exit criteria:** real-time send/receive against the dev backend; common message types;
attachments via presign; in-conversation + global search; groups + helpdesk basics.

---

## Epic E18 — Messaging core

### AND-120 — Messaging API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `MessagingApi` + DTOs for `/messaging/conversations`, `/conversations/{id}`,
`/conversations/{id}/messages`, `/config`.
**Acceptance:** Conversation + message payloads map (tested vs fixtures).

### AND-121 — Conversation list screen
**Type:** Feature · **Priority:** P0 · **Deps:** AND-120, AND-024
**Scope:** List with avatar, last message, unread, timestamp; pull-to-refresh; empty state.
**Acceptance:** Renders conversations from backend; opens a thread.

### AND-122 — Conversation list ViewModel + paging
**Type:** Feature · **Priority:** P0 · **Deps:** AND-120, AND-098
**Scope:** Paging 3 source, unread aggregation, sort.
**Acceptance:** Paging + state unit-tested.

### AND-123 — Thread (message list) screen
**Type:** Feature · **Priority:** P0 · **Deps:** AND-120
**Scope:** Paged history (reverse), date separators, sender grouping, scroll-to-bottom.
**Acceptance:** History loads + paginates; new messages append.

### AND-124 — Send text message
**Type:** Feature · **Priority:** P0 · **Deps:** AND-123
**Scope:** Composer; `POST /conversations/{id}/messages`; optimistic send + failure retry.
**Acceptance:** Text sends, appears optimistically, reconciles on ack (tested).

### AND-125 — Read / unread state
**Type:** Feature · **Priority:** P1 · **Deps:** AND-123
**Scope:** `POST /conversations/{id}/read`; unread counters update.
**Acceptance:** Opening a thread marks read; counts update.

### AND-126 — Message domain model + mappers
**Type:** Feature · **Priority:** P0 · **Deps:** AND-120
**Scope:** Sealed message-type model (text/image/video/file/voice/gif/sticker/poll/countdown/
calendar/system) + mappers.
**Acceptance:** All known types map without loss (tested).

### AND-127 — DM find-or-create
**Type:** Feature · **Priority:** P1 · **Deps:** AND-120
**Scope:** `POST /conversations/dm/find-or-create`; start DM from profile/contact.
**Acceptance:** Starting a DM opens/creates the conversation.

### AND-128 — Messaging core tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-124, AND-126
**Scope:** Repo + UI tests for list/thread/send.
**Acceptance:** Tests pass headlessly.

---

## Epic E19 — Rich messages & attachments

### AND-129 — Attachment pipeline (presign→PUT→confirm)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-117
**Scope:** Reusable uploader: request presign, PUT to storage, confirm; progress + cancel + retry.
**Acceptance:** A file uploads end-to-end with progress (tested w/ MockWebServer).

### AND-130 — Image messages
**Type:** Feature · **Priority:** P0 · **Deps:** AND-129
**Scope:** `/messages/image` + `images/presign`; pick/capture, compress, thumbnail, viewer.
**Acceptance:** Image sends and displays full-screen on tap.

### AND-131 — Video messages / share
**Type:** Feature · **Priority:** P1 · **Deps:** AND-129, AND-023(media)
**Scope:** `/messages/video-share`; upload + inline playback.
**Acceptance:** Video sends and plays inline.

### AND-132 — File messages / share
**Type:** Feature · **Priority:** P1 · **Deps:** AND-129
**Scope:** `/messages/file`, `/messages/file-share`; download + open with consume/grant flow.
**Acceptance:** File sends; recipient can download/open (tested).

### AND-133 — Voice messages
**Type:** Feature · **Priority:** P1 · **Deps:** AND-129
**Scope:** `/voice-message(+presign)`; record, waveform, play.
**Acceptance:** Record→send→play round-trip works.

### AND-134 — Voicemail
**Type:** Feature · **Priority:** P2 · **Deps:** AND-133
**Scope:** `/voicemail(+presign)` flow.
**Acceptance:** Voicemail send/play works.

### AND-135 — GIFs, stickers, custom emoji
**Type:** Feature · **Priority:** P2 · **Deps:** AND-124
**Scope:** `/messages/gif`, `/messages/sticker`, custom emojis picker.
**Acceptance:** Send + render each type.

### AND-136 — Polls, meeting-poll, find-datetime
**Type:** Feature · **Priority:** P2 · **Deps:** AND-124
**Scope:** `/messages/meeting-poll`, `/polls/{id}/vote|confirm`, find-datetime availability/close.
**Acceptance:** Create/vote/close a poll; results render.

### AND-137 — Countdown messages
**Type:** Feature · **Priority:** P2 · **Deps:** AND-124
**Scope:** `/messages/countdown`; live countdown rendering.
**Acceptance:** Countdown message sends and ticks.

### AND-138 — Calendar event / share messages
**Type:** Feature · **Priority:** P2 · **Deps:** AND-124, AND-037(M6 cal)
**Scope:** `/messages/calendar-event`, `/messages/calendar-share`.
**Acceptance:** Calendar message renders + opens detail.

### AND-139 — Tips & paid/unlockable messages
**Type:** Feature · **Priority:** P1 · **Deps:** AND-124, AND-031(billing)
**Scope:** `/messages/{id}/tip`, `/messages/{id}/unlock`, lottery unlock; locked message UI.
**Acceptance:** Locked message unlock + tip flows work (with payment dependency stubbed/tested).

### AND-140 — Reactions, pins, edits, delete/revoke
**Type:** Feature · **Priority:** P1 · **Deps:** AND-123
**Scope:** reactions(+details), pin/unpin(+pins list), edits history, delete/revoke, hide.
**Acceptance:** Each action updates the thread + persists (tested).

### AND-141 — Drafts
**Type:** Feature · **Priority:** P2 · **Deps:** AND-124
**Scope:** `/conversations/{id}/drafts` CRUD; restore draft on open.
**Acceptance:** Draft saves/restores/clears (tested).

### AND-142 — Rich message tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-130, AND-140
**Scope:** Upload + render + action tests for key types.
**Acceptance:** Tests pass headlessly.

---

## Epic E20 — Real-time messaging

### AND-143 — SSE client core
**Type:** Feature · **Priority:** P0 · **Deps:** AND-009
**Scope:** OkHttp `EventSource` wrapper: lifecycle-aware, auth cookies, reconnect/backoff, `Flow` of events.
**Acceptance:** Connects, emits events, reconnects after drop (tested w/ MockWebServer).

### AND-144 — Messaging events stream
**Type:** Feature · **Priority:** P0 · **Deps:** AND-143, AND-123
**Scope:** Subscribe `/messaging/events/stream` (+ `/events`); dispatch new-message/edit/delete events.
**Acceptance:** New messages appear live in the open thread + list.

### AND-145 — Presence + heartbeat
**Type:** Feature · **Priority:** P1 · **Deps:** AND-143
**Scope:** `/messaging/presence(+heartbeat)`; online indicators.
**Acceptance:** Presence reflects online/last-seen; heartbeat runs while foregrounded.

### AND-146 — Typing indicators
**Type:** Feature · **Priority:** P1 · **Deps:** AND-144
**Scope:** `/conversations/{id}/typing` send + receive.
**Acceptance:** Typing shows/clears correctly.

### AND-147 — Read receipts / views
**Type:** Feature · **Priority:** P1 · **Deps:** AND-144
**Scope:** message `/view`, `/views`; delivered/seen markers.
**Acceptance:** Receipts update live.

### AND-148 — Live reconciliation
**Type:** Feature · **Priority:** P0 · **Deps:** AND-144, AND-116
**Scope:** Merge SSE events with cache/paging without dupes/gaps; ordering.
**Acceptance:** No duplicates/gaps across reconnect (tested).

### AND-149 — Reconnect/backoff + lifecycle
**Type:** Feature · **Priority:** P1 · **Deps:** AND-143
**Scope:** Backoff, foreground/background subscribe/unsubscribe, flaky-host tolerance.
**Acceptance:** Survives host blips; no leaks (tested).

### AND-150 — Real-time tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-148
**Scope:** SSE reconciliation + reconnect tests.
**Acceptance:** Deterministic tests pass.

---

## Epic E21 — Messaging search & contacts

### AND-151 — In-conversation search
**Type:** Feature · **Priority:** P1 · **Deps:** AND-123
**Scope:** `/conversations/{id}/messages/search`; highlight + jump-to.
**Acceptance:** Finds + scrolls to matches.

### AND-152 — Global message search
**Type:** Feature · **Priority:** P1 · **Deps:** AND-120
**Scope:** `/messaging/messages/search` with sender/after filters; results screen.
**Acceptance:** Cross-conversation search returns + opens results.

### AND-153 — Contacts list + search
**Type:** Feature · **Priority:** P1 · **Deps:** AND-120
**Scope:** `/messaging/contacts/search` (name tokenization); contacts screen.
**Acceptance:** Search by name/fragment works.

### AND-154 — Contact → start conversation
**Type:** Feature · **Priority:** P1 · **Deps:** AND-153, AND-127
**Scope:** Open profile / start DM from a contact.
**Acceptance:** Starting from a contact opens the DM.

### AND-155 — Search/contacts ViewModels + paging
**Type:** Feature · **Priority:** P1 · **Deps:** AND-152, AND-153
**Scope:** Debounced query state, paging, empty states.
**Acceptance:** Unit-tested.

### AND-156 — Search/contacts tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-155
**Scope:** Repo + UI tests.
**Acceptance:** Tests pass.

---

## Epic E22 — Groups & helpdesk

### AND-157 — Group create
**Type:** Feature · **Priority:** P1 · **Deps:** AND-120
**Scope:** `POST /conversations/group`; name/avatar/participants.
**Acceptance:** Group creates and opens.

### AND-158 — Group participants management
**Type:** Feature · **Priority:** P1 · **Deps:** AND-157
**Scope:** participants add/remove/role (PATCH/DELETE).
**Acceptance:** Membership changes persist + reflect.

### AND-159 — Group settings
**Type:** Feature · **Priority:** P2 · **Deps:** AND-157
**Scope:** mute, leave, accept-invite.
**Acceptance:** Each setting works (tested).

### AND-160 — Mass messages
**Type:** Feature · **Priority:** P2 · **Deps:** AND-120
**Scope:** `/messaging/mass-messages` list/create/cancel (creator).
**Acceptance:** Create + cancel a campaign.

### AND-161 — Helpdesk queue
**Type:** Feature · **Priority:** P2 · **Deps:** AND-120
**Scope:** `/messaging/helpdesk/queue` list for agents.
**Acceptance:** Queue renders for agent role.

### AND-162 — Helpdesk claim + reply
**Type:** Feature · **Priority:** P2 · **Deps:** AND-161
**Scope:** `/helpdesk/conversations/{id}/claim` + reply; handle claim/assignee error codes.
**Acceptance:** Claim→reply works; claim errors surface correctly.

### AND-163 — Report message / conversation
**Type:** Feature · **Priority:** P1 · **Deps:** AND-140
**Scope:** message `/report`, report status; ties into Trust & Safety (E50).
**Acceptance:** Report submits + confirmation.

### AND-164 — Legal holds / compliance (read)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-120
**Scope:** Read-only legal-holds indicators where present.
**Acceptance:** Hold state displays; no destructive actions.

### AND-165 — Groups/helpdesk tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-158, AND-162
**Scope:** Repo + UI tests.
**Acceptance:** Tests pass.

---

### M3 ticket count: 46 (E18:9, E19:14, E20:8, E21:6, E22:9)
**Running total through M3:** 165 tickets (AND-001…AND-165).
