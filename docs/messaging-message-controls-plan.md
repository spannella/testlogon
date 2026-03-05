# Messaging Message Controls Plan

## Scope
Implement message-level controls in conversations:

1. Copy message content to clipboard.
2. Hide message for the current viewer (personal visibility control).
3. Hidden messages center/menu to review hidden messages and unhide.
4. Pin message to conversation.
5. Pinned messages banner (show latest pinned message).
6. Pins menu to browse current pins, unpin, and jump-to-message.
7. Report message for moderation with a required statement and explicit notice that nearby context is included.

## Product Behavior

### Copy Message
- Add a **Copy** action in each message action menu.
- Copy plain-text content for text messages; for attachments copy a canonical share label (e.g., filename + URL when available).
- Show inline feedback (`Copied`) for ~2 seconds.

### Hide Message (Per-User)
- Add **Hide for me** action in message menu.
- Hidden messages are fully removed from the user’s default conversation timeline.
- Hidden state is per-user and does not affect other participants.
- Provide a conversation-level menu entry: **Hidden messages**.
- Hidden messages view shows hidden items in chronological order with:
  - `Unhide`
  - `Jump to original position`

### Pin Message
- Add **Pin** action in message menu.
- Conversation header shows a small banner with the **most recently pinned** active pin.
- Banner actions:
  - `View all pins`
  - `Jump`
  - `Dismiss banner` (UI only; pin remains active)
- Conversation-level menu entry: **Pinned messages**.
- Pins menu lists all active pins with metadata (author, pinned by, timestamp) and actions:
  - `Unpin`
  - `Jump to message`

### Report Message
- Add **Report message** action in message menu.
- Open modal/sheet with:
  - Reason category (abuse, spam, harassment, illegal content, etc.)
  - Required free-text statement (`Why are you reporting this?`)
  - Notice text: `Recent conversation context will be included with this report for moderation review.`
  - Confirm + cancel
- On submit:
  - Create moderation report event.
  - Include target message and bounded context window.
  - Show user confirmation toast.

## Technical Design

## Data Model

### Client-side message actions
- Extend message action enum to include:
  - `copy`
  - `hide`
  - `unhide`
  - `pin`
  - `unpin`
  - `report`

### Persistence (backend)
1. **Hidden messages (per user)**
   - `message_visibility_overrides`
     - `conversation_id`
     - `message_id`
     - `user_id`
     - `state` (`hidden` | `visible`)
     - `updated_at`
   - Unique key: (`conversation_id`, `message_id`, `user_id`)

2. **Pins (conversation-wide)**
   - `conversation_pins`
     - `conversation_id`
     - `message_id`
     - `pinned_by_user_id`
     - `pinned_at`
     - `is_active`
     - `unpinned_by_user_id` (nullable)
     - `unpinned_at` (nullable)
   - Indexes:
     - active pins by conversation
     - latest active pin by conversation

3. **Moderation reports**
   - `message_reports`
     - `report_id`
     - `conversation_id`
     - `message_id`
     - `reported_by_user_id`
     - `reason_code`
     - `statement`
     - `context_message_ids` (or separate linked table)
     - `created_at`
     - `status`

## API Endpoints

### Hide/Unhide
- `POST /conversations/:id/messages/:messageId/hide`
- `DELETE /conversations/:id/messages/:messageId/hide`
- `GET /conversations/:id/hidden-messages` (paged)

### Pins
- `POST /conversations/:id/messages/:messageId/pin`
- `DELETE /conversations/:id/messages/:messageId/pin`
- `GET /conversations/:id/pins`
- Optional in conversation payload: `latestPinnedMessage`

### Report
- `POST /conversations/:id/messages/:messageId/report`
  - body: `{ reasonCode, statement }`
  - backend appends context window server-side.

## Context Capture for Reports
- Include ±N messages around target (e.g., 5 before + 5 after) constrained by:
  - access control
  - retention policy
  - legal/compliance filters
- Store immutable snapshot references for moderation auditability.
- Do not allow client to specify arbitrary context IDs.

## UX Flow & Components

1. **MessageActionMenu**
   - Add menu items with permission gating.
2. **HiddenMessagesPanel**
   - Drawer/modal route (`/conversations/:id/hidden` optional).
3. **PinnedMessagesBanner**
   - Sticky compact header under conversation title.
4. **PinsPanel**
   - Drawer/modal route (`/conversations/:id/pins` optional).
5. **ReportMessageModal**
   - Validation: statement required, min/max length, reason required.

## Authorization & Safety
- Hide/unhide allowed for any participant, scoped to self.
- Pin/unpin policy options:
  - v1: any participant can pin/unpin their own pins.
  - alt: admins/moderators only for unpin-any.
- Report allowed for participants; rate-limit per user/conversation.
- Audit logs for pin/unpin/report actions.

## Rollout Plan

### Phase 1: Foundations
- Add DB tables/migrations and API contracts.
- Implement hide/unhide + list hidden messages.
- Implement copy action in UI.

### Phase 2: Pins
- Implement pin/unpin APIs.
- Add latest pin banner + pins panel.
- Add deep-link jump-to-message handling.

### Phase 3: Moderation Reporting
- Add report modal + backend endpoint.
- Add contextual snapshot capture.
- Add moderation queue integration.

### Phase 4: Hardening
- Telemetry dashboards.
- Abuse/rate-limit tuning.
- Accessibility and localization pass.

## Testing Strategy

### Unit
- Reducers/state updates for hidden/pinned/report actions.
- Validation logic for report statement.

### Integration
- Hide/unhide visibility filtering by current user.
- Pin lifecycle and banner updates.
- Report submission includes server-generated context.

### E2E
- Copy action success feedback.
- Hidden message disappears from timeline, appears in hidden panel, returns on unhide.
- Pin appears in banner and pins panel; jump navigates correctly.
- Report modal enforces statement and submits successfully.

### Security/Abuse
- Verify users cannot unhide others’ visibility overrides.
- Verify unauthorized pin/unpin is rejected.
- Verify report endpoint rate-limits and stores immutable audit trail.

## Observability
- Metrics:
  - `messaging.hide.count`
  - `messaging.unhide.count`
  - `messaging.pin.count`
  - `messaging.unpin.count`
  - `messaging.report.count`
  - `messaging.report.validation_error.count`
- Logs:
  - action actor, conversation, message, result status
- Alerts:
  - spikes in reports per conversation/user
  - pin/unpin error-rate threshold

## Open Decisions
1. Should hidden messages affect unread counts and search results?
2. Pin permissions: any participant vs role-based moderation.
3. Max active pins per conversation.
4. Report reason taxonomy and moderation SLA mapping.
5. Whether `copy` should include rich text/markdown formatting.
