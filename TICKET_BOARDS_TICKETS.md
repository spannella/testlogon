# Ticket Boards (Kanban) — Implementation Tickets

This backlog renames the ticket "spaces" concept to "boards" and turns them into a Trello-style Kanban experience (per-board status columns, drag-and-drop, configurable/custom columns, rich cards) while keeping every existing `space`/`ticket` API and stored row working throughout the transition.

## Milestone 1 — Backend rename + backward compatibility

### TKB-001: Add `board_id` alias + dual-read accessors to the ticket store
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Today the store keys boards as `SPACE#{id}` (`app/services/tickets.py:101-106`) and uses helpers `_space_pk`, `_space_meta_key`, `_space_member_sk`, `_space_index_pk`, `_space_status_index_pk`, `_space_assignee_index_pk`, `_member_index_pk`/`_member_index_sk` (`app/services/tickets.py:101-130`).
- Introduce `board_id` as the canonical public field name without changing the physical PK. Add aliasing so `create_space`/`get_space`/`add_space_member`/`remove_space_member`/`list_spaces_for_member` (`app/services/tickets.py:152-252`) also expose `board_id`, `boards`, `board_membership` alongside the legacy `space_id`/`spaces`/`ticket_space` keys in their return dicts.
- Keep the existing `spc_` id prefix (`app/services/tickets.py:154`) so already-stored ids resolve unchanged; `board_id == space_id` for every row.
- Add thin alias methods (`create_board`, `get_board`, `add_board_member`, `remove_board_member`, `list_boards_for_member`, `list_board_tickets`) that delegate to the existing space methods so callers can migrate gradually.

**Acceptance Criteria**
- `get_space(id)` and `get_board(id)` return the same object; the dict contains both `space_id` and `board_id` with equal values, and both `members` and identical content.
- No DynamoDB PK/SK string changes — an existing `SPACE#{id}` META row created before this change still resolves via both accessors.
- `create_ticket(space_id=...)` and a new `create_ticket(board_id=...)` keyword both write the same `space_id` attribute and space GSI keys (`app/services/tickets.py:307-312`).

**Dependencies**
- None.

---

### TKB-002: `entity_type` + GSI attribute parity for boards
**Type:** Chore  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Board rows persist `entity_type="ticket_space"`/`"space_membership"` (`app/services/tickets.py:158,169`). Keep writing those values for compatibility but ALSO write the new `entity_type` aliases (`ticket_board`/`board_membership`) is NOT safe (one column) — instead add a sibling attribute `board_entity_type` so consumers can filter on either without a migration.
- Confirm the member-spaces GSI (`gsi_member_pk`/`gsi_member_sk`, index `S.tickets_member_spaces_index_name`, `app/services/tickets.py:175-176,428`, `scripts/local-ddb-init.py:706`) and all space GSIs (`scripts/local-ddb-init.py:703-705`) remain unchanged and continue to power `list_boards_for_member`.

**Acceptance Criteria**
- New board META + membership rows carry both `entity_type` (legacy) and `board_entity_type` (new) attributes.
- No new GSI is required; `just restart` recreates tables unchanged.
- `list_boards_for_member` returns boards created before AND after this change.

**Dependencies**
- TKB-001.

---

### TKB-003: New `/boards` router that aliases `/ticket-spaces`
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- The current router (`app/routers/ticket_spaces.py:13`) is mounted at `/ticket-spaces` and registered in `app/main.py:97,682`.
- Add a parallel `/boards` router exposing the same endpoints (`POST/GET /boards`, `GET /boards/{board_id}`, `POST/DELETE /boards/{board_id}/members[...]`, `POST/GET /boards/{board_id}/tickets`, ticket assign/messages/status — mirroring `app/routers/ticket_spaces.py:200-412`). Both routers should delegate to the same `TicketStore` methods so there is exactly one source of truth.
- Response models should expose `board_id` (and keep `space_id` for compatibility). Reuse `TicketSpaceOut`/`SpaceMemberOut`/`SpaceTicketOut` by adding the `board_id` field with a default, or subclass them.
- Register the new router in `app/main.py` next to the existing one (`app/main.py:682`). Do NOT remove `/ticket-spaces`.

**Acceptance Criteria**
- `POST /boards` and `POST /ticket-spaces` create equivalent rows; a board created on one path is visible via the other.
- All four error codes used by the legacy router (`ticket_space_not_found`, `space_access_forbidden`, `space_write_forbidden`, `space_owner_required`, `app/routers/ticket_spaces.py:140-171`) have board-named equivalents returned by `/boards` (e.g. `board_not_found`) while `/ticket-spaces` keeps emitting the old codes.
- `openapi.json` lists both `/boards/*` and `/ticket-spaces/*`.

**Dependencies**
- TKB-001.

---

### TKB-004: Vite proxy + SPA bypass for `/boards`
**Type:** Chore  
**Priority:** P1  
**Estimate:** 0.5 day

**Description**
- The `/ticket-spaces` and `/tickets` proxy entries use a `bypass` that serves `index.html` for `text/html` navigations and proxies XHR/JSON to the backend (`frontend/vite.config.ts:121-142`).
- Add an identical `/boards` proxy entry so the new API path and the future SPA route `tickets/boards` both work (SPA route + API route share the prefix, same pattern as tickets).

**Acceptance Criteria**
- `GET /boards` with `Accept: application/json` proxies to backend:8000; a browser navigation to `/boards/<id>` returns the SPA `index.html`.
- Existing `/tickets` and `/ticket-spaces` proxy behavior is unchanged.

**Dependencies**
- TKB-003.

---

### TKB-005: Backend regression tests for the rename + dual API
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add `tests/test_ticket_boards_rename.py` (moto-backed, following the existing `tickets` table pattern; the `tickets` table with its 7 GSIs is created by `scripts/local-ddb-init.py:700-706`).
- Cover: board CRUD via `/boards` and `/ticket-spaces` are interchangeable; `get_board`/`get_space` parity; membership add/remove; that pre-rename rows (written with only `space_id`/`entity_type=ticket_space`) still resolve.

**Acceptance Criteria**
- `.venv/bin/pytest tests/test_ticket_boards_rename.py` passes offline.
- A test writes a legacy-shaped META row directly and asserts `get_board` returns it with `board_id` populated.

**Dependencies**
- TKB-001, TKB-002, TKB-003.

---

## Milestone 2 — Configurable columns / custom statuses per board

### TKB-006: Board column model + persistence
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Global ticket statuses are a fixed tuple with a fixed transition map (`app/services/tickets.py:15-40`). The Kanban board currently hardcodes 4 columns (`frontend/src/pages/tickets/TicketKanbanBoard.tsx:30-35`).
- Add a per-board `columns` list to the board META row: each column `{column_id, title, status_key, order, wip_limit?, color?}`. `status_key` maps a board column to one of the underlying ticket statuses (`open`, `in_progress`, `waiting_on_user`, `done`, etc., `app/services/tickets.py:15-29`).
- On `create_board`, seed a default column set mirroring today's 4 columns (Open / In Progress / Waiting on User / Done) so existing boards behave the same.
- Add `update_board_columns(board_id, columns)` (owner/editor only) with validation that every `status_key` is in `_TICKET_STATUSES`.

**Acceptance Criteria**
- A board created after this change has 4 default columns whose `status_key`s are `open`/`in_progress`/`waiting_on_user`/`done`.
- `update_board_columns` rejects an unknown `status_key` with a 400 and a structured error.
- Boards created before this change (no `columns` attribute) return the default column set from `get_board` (back-fill at read time).

**Dependencies**
- TKB-001.

---

### TKB-007: Custom-status support without breaking the global transition map
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- `update_status` enforces `_STATUS_TRANSITIONS` (`app/services/tickets.py:750-773`) and `_coerce_status` maps `reopened`→`open` (`app/services/tickets.py:133-137`).
- Allow boards to declare custom column labels that still map onto an allowed underlying `status_key`, so drag-and-drop persists a real, transition-valid status. Custom labels are display-only; the stored ticket `status` stays within `_TICKET_STATUSES`.
- Document (code comment + ticket) that arbitrary brand-new persisted statuses are out of scope for M2 — columns re-skin existing statuses. A follow-up spike (TKB-016) covers truly free-form statuses.

**Acceptance Criteria**
- A board can show a column titled "Needs review" mapped to `status_key=waiting_on_user`; moving a card there persists `status=waiting_on_user`.
- `update_status` still rejects an invalid underlying transition with `invalid_ticket_status_transition` (`app/services/tickets.py:766`).

**Dependencies**
- TKB-006.

---

### TKB-008: Board column CRUD endpoints
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Expose on the `/boards` router (TKB-003): `GET /boards/{board_id}/columns`, `PUT /boards/{board_id}/columns` (reorder/add/remove/rename), gated by `_require_space_write`/owner checks (`app/routers/ticket_spaces.py:161-171`).
- Reuse the conflict/error envelope helpers (`_error`, `_raise`, `app/routers/ticket_spaces.py:123-128`).

**Acceptance Criteria**
- A viewer (read-only member) gets 403 on `PUT .../columns`; an editor/owner succeeds.
- `PUT` validates `status_key`s and column-id uniqueness; returns the updated board.

**Dependencies**
- TKB-006, TKB-003.

---

### TKB-009: Backend tests for columns + custom statuses
**Type:** Chore  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add `tests/test_ticket_board_columns.py`: default seeding, read-time back-fill for legacy boards, `update_board_columns` validation, role enforcement, and that a custom-titled column maps to a valid persisted status.

**Acceptance Criteria**
- `.venv/bin/pytest tests/test_ticket_board_columns.py` passes offline.
- Includes a negative test for an unknown `status_key` and for a non-editor caller.

**Dependencies**
- TKB-006, TKB-007, TKB-008.

---

## Milestone 3 — Frontend boards UI (Kanban, drag-and-drop, cards)

### TKB-010: Frontend types + endpoint wrappers for boards
**Type:** Feature  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Current wrappers target `/ticket-spaces` and use `TicketSpace`/`SpaceRole` types (`frontend/src/api/endpoints/tickets.ts:61-88,126-167`).
- Add `Board`/`BoardMember`/`BoardColumn` types and `createBoard`/`listBoards`/`getBoard`/`addBoardMember`/`removeBoardMember`/`listBoardTickets`/`getBoardColumns`/`updateBoardColumns` wrappers hitting `/boards`. Keep the old space wrappers exported (deprecated) so nothing breaks mid-migration.

**Acceptance Criteria**
- New wrappers compile and are typed against the M2 column shape.
- Old `*TicketSpace*` exports remain (re-exported as deprecated aliases of the board wrappers where the shapes match).

**Dependencies**
- TKB-003, TKB-006.

---

### TKB-011: Per-board Kanban board view driven by board columns
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- `TicketKanbanBoard.tsx` already renders columns and drag-and-drop via `@dnd-kit` (`frontend/src/pages/tickets/TicketKanbanBoard.tsx:30-216`) but hardcodes `KANBAN_COLUMNS` (lines 30-35) and `VALID_TRANSITIONS` (lines 24-28) and operates on the global ticket list (`frontend/src/pages/tickets/TicketsPage.tsx:182-184`).
- Refactor it into a board-scoped component that takes `columns` from `getBoard` and buckets `listBoardTickets` results by each column's `status_key`. Render one droppable per board column; keep the existing `DragOverlay`/`DraggableTicketCard` UX.
- Replace the hardcoded `KANBAN_COLUMNS`/`VALID_TRANSITIONS` with values derived from the board config (transitions still mirror backend `_STATUS_TRANSITIONS`, `app/services/tickets.py:30-40`).

**Acceptance Criteria**
- The board renders exactly the columns configured on that board (not a fixed 4) with per-column counts (`data-testid="kanban-count-*"` preserved).
- Cards appear in the column whose `status_key` equals the ticket status.
- `data-testid="ticket-kanban-board"` and `kanban-column-*`/`kanban-card-*` test hooks are preserved.

**Dependencies**
- TKB-010.

---

### TKB-012: Optimistic drag-and-drop persistence
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Drag currently calls `setTicketStatus` and only invalidates on success (`frontend/src/pages/tickets/TicketKanbanBoard.tsx:135-167`), with no optimistic move; an invalid transition shows a toast and snaps back.
- Implement React Query optimistic update: on drag end, move the card in cache immediately, fire `setTicketStatus`/board status endpoint, and roll back on error (re-show the card in its original column + toast). Map `done`→`reopened` continues via `statusToWritable` (`frontend/src/pages/tickets/TicketKanbanBoard.tsx:37-40`).

**Acceptance Criteria**
- Dropping a card to a valid column moves it instantly (before the network resolves) and the move persists after refetch.
- A backend `invalid_ticket_status_transition` rolls the card back to its source column and shows an error toast.
- Client-side transition guard still blocks obviously invalid drops before any request.

**Dependencies**
- TKB-011.

---

### TKB-013: Card UI — assignee, priority, labels
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- The card currently shows subject + status badge + assignee (`frontend/src/pages/tickets/TicketKanbanBoard.tsx:60-82`). Tickets already carry `labels` and a `complexity` derived from `complexity:<level>` labels (`app/services/tickets.py:56-60,275-276,372-373`) and `assigned_to_sub`/`assigned_admin_sub` (`app/services/tickets.py:381-384`).
- Enrich the card with: assignee avatar/handle (via `UserProfileLink`, already imported), a priority/complexity pill sourced from `complexity`, and label chips from `labels`. Truncate gracefully.

**Acceptance Criteria**
- A ticket with `complexity:high` renders a "High" priority pill; tickets with labels render up to N label chips with overflow indicator.
- Assignee renders via `UserProfileLink`; unassigned cards show no assignee row.

**Dependencies**
- TKB-011.

---

### TKB-014: Board CRUD + membership UI ("boards" wording)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Existing pages `TicketSpacesPage.tsx` + `TicketSpaceDetailPage.tsx` are routed at `tickets/spaces` / `tickets/spaces/:spaceId` (`frontend/src/App.tsx:77-78,360-361`).
- Add `BoardsPage` + `BoardDetailPage` (or rename in place) routed at `tickets/boards` / `tickets/boards/:boardId`, using "Board" wording throughout. The detail page shows the Kanban view (TKB-011) plus a column-config panel (TKB-008) and member management (reuse add/remove member calls, `frontend/src/api/endpoints/tickets.ts:138-142`).
- Keep the old `tickets/spaces` routes as redirects to `tickets/boards` so bookmarks/links survive.

**Acceptance Criteria**
- `/tickets/boards` lists the user's boards; `/tickets/boards/:id` shows the Kanban + members + column config.
- Navigating to a legacy `/tickets/spaces/:id` redirects to `/tickets/boards/:id`.
- All visible copy says "Board(s)", not "Space(s)".

**Dependencies**
- TKB-010, TKB-011.

---

### TKB-015: TicketsPage board-mode integration
**Type:** Chore  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- `TicketsPage.tsx` has a List/Board toggle (`frontend/src/pages/tickets/TicketsPage.tsx:163-184`) that renders the global-list Kanban. Update the "Board" button copy + wire the link to the new boards experience, or embed a board picker so the toggle shows a chosen board's Kanban.

**Acceptance Criteria**
- The List/Board toggle (`data-testid="view-toggle"`) still works; selecting "Board" surfaces a real per-board Kanban (or a board picker), not the hardcoded-column global view.

**Dependencies**
- TKB-011, TKB-014.

---

## Milestone 4 — Hardening & tests

### TKB-016: Spike — truly free-form custom statuses
**Type:** Spike  
**Priority:** P2  
**Estimate:** 1 day

**Description**
- Investigate persisting board-defined statuses outside `_TICKET_STATUSES`/`_STATUS_TRANSITIONS` (`app/services/tickets.py:15-40`) and the status GSI implications (`gsi2pk`/`gsi_space_status_pk`, `app/services/tickets.py:303,309`). Produce a design note + follow-up tickets.

**Acceptance Criteria**
- Written recommendation covering GSI key cardinality, transition validation, and migration; no code change required.

**Dependencies**
- TKB-007.

---

### TKB-017: E2E tests — board rename + Kanban + DnD
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Existing e2e `frontend/e2e/tickets.spec.ts` covers Spaces CRUD + members (Section 55, `frontend/e2e/tickets.spec.ts:380-498`) and space ticket lifecycle (Section 56, line 500+) via `apiPost`/`apiGet` helpers against `ticket-spaces`.
- Add new sections: (a) `/boards` API parity (board created via `/boards` is visible via `/ticket-spaces` and vice-versa, board CRUD + members); (b) column config CRUD + role enforcement; (c) a UI Kanban test that loads a board, asserts configured columns/counts render (`data-testid="kanban-column-*"`/`kanban-count-*`), drags a card to another column and asserts optimistic move + persisted status after reload, and asserts an invalid drop rolls back.
- Keep Sections 55-56 unchanged to prove backward compatibility.

**Acceptance Criteria**
- New sections pass under `cd frontend && npx playwright test e2e/tickets.spec.ts`.
- Sections 55 and 56 still pass unmodified.
- DnD test verifies the persisted status by reloading and re-reading the card's column.

**Dependencies**
- TKB-003, TKB-008, TKB-011, TKB-012, TKB-014.

---

### TKB-018: Docs + CLAUDE.md gotcha update
**Type:** Chore  
**Priority:** P2  
**Estimate:** 0.5 day

**Description**
- Update `docs/file-reference.md` and add a "boards (formerly spaces)" gotcha to `CLAUDE.md` noting: physical PK stays `SPACE#{id}`, both `/boards` and `/ticket-spaces` are live, `board_id == space_id`, and the vite `/boards` proxy bypass mirrors `/tickets` (`frontend/vite.config.ts:121-142`).

**Acceptance Criteria**
- Docs reference the new endpoints, the alias relationship, and the migration-free storage approach.

**Dependencies**
- TKB-003, TKB-014.

---
