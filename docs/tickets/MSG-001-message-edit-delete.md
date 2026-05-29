# MSG-001: Message Editing & Deletion

**Status**: Complete (verified 2026-05-27 — edit, delete, revoke implemented in backend + frontend + E2E)
**Author**: Engineering
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 5-7 days

---

## 1. Executive Summary

Message editing and deletion are table-stakes messaging features that every user expects. Currently, once a message is sent through `POST /messaging/conversations/{id}/messages`, it is immutable -- there is no PATCH or DELETE operation.
<!-- CORRECTED: Edit and delete operations ALREADY EXIST. PATCH at messaging.py:9654 (edit_message), DELETE at line 9480 (delete_message_for_me), and DELETE .../revoke at line 9519 (revoke_message_for_all). EditMessageIn model at messaging.py:2216. MessageEdits table at local-ddb-init.py:271. --> Users who make typos, send messages to the wrong conversation, or accidentally share sensitive content have no recourse other than sending a follow-up correction, which clutters the conversation timeline.

This ticket adds two operations to the messaging system: **edit** (within a configurable time window, default 15 minutes) and **soft-delete** (permanently redacts content while preserving the message skeleton for conversation ordering and reply chains). The implementation extends the existing `Messages` DynamoDB table with `edited`, `edited_at`, `deleted`, and `deleted_by` attributes; adds PATCH and DELETE endpoints to `app/routers/messaging.py`; extends the `MessageOut` Pydantic model; and updates the frontend `MessageBubble` component with context menu actions, an inline edit flow, and a "This message was deleted" placeholder.
<!-- CORRECTED: PATCH edit_message already exists at messaging.py:9654. DELETE delete_message_for_me at line 9480 and DELETE revoke_message_for_all at line 9519 also exist. The Messages table already has edited_at and edited_by fields (set by edit_message). The MessageEdits table (DDB_MESSAGE_EDITS) already exists (local-ddb-init.py:271, messaging.py:175,233). EditMessageIn with text:str validation already exists at messaging.py:2216-2229. This ticket should focus on EXTENDING these existing implementations rather than building from scratch. -->

Encrypted messages cannot be edited (re-encryption by all participants is infeasible) but can be deleted (clears ciphertext). Locked, view-once, and already-delivered scheduled messages have edit restrictions. Admin users can delete any message for moderation purposes. All mutations are audit-logged and emit SSE events for real-time UI updates across participants.

---

## 2. Detailed Problem Analysis

### User Stories

| As a... | I want to... | So that... |
|---------|-------------|-----------|
| Sender | Fix a typo in a message I just sent | My conversation partner sees the corrected version |
| Sender | Delete a message I sent to the wrong person | The recipient cannot continue reading it |
| Sender | Delete a message with sensitive info (password, address) | The content is permanently removed from the conversation |
| Recipient | See that a message was edited | I know the text may have changed from what I initially read |
| Recipient | See a placeholder for deleted messages | I understand why the conversation flow has a gap |
| Admin | Delete any message for moderation | I can enforce community guidelines even if the sender does not cooperate |
| Sender | Edit a scheduled message before it delivers | I can fix the content before anyone sees it |

### Pain Points

1. **Typo anxiety**: Users hesitate to type quickly because there is no safety net for mistakes.
2. **Sensitive data exposure**: Accidental sharing of passwords, phone numbers, or addresses is permanent.
3. **Conversation clutter**: Follow-up corrections ("*I meant...") add noise to the conversation.
4. **Moderation gap**: Admins can see offensive messages but cannot remove them from the recipient's view.

### Competitive Analysis

| Platform | Edit | Delete | Notes |
|----------|------|--------|-------|
| WhatsApp | No | Yes (delete for everyone) | 48-hour window for delete-for-everyone |
| Telegram | Yes (48 hours) | Yes (no time limit) | Shows "edited" indicator |
| Discord | Yes (no time limit) | Yes (no time limit) | Shows "edited" + edit history |
| Slack | Yes (no time limit) | Yes (admins can restrict) | Shows "edited" indicator |
| This ticket | Yes (15 min window) | Yes (no time limit for own; admin can delete any) | Shows "edited" indicator; "This message was deleted" placeholder |

---

## 3. Technical Architecture

### System Diagram

```
User clicks "Edit" in MessageContextMenu
           |
           v
ComposeBar enters edit mode (pre-fills text, shows "Editing" banner)
           |
           v (user submits)
PATCH /ui/messaging/conversations/{conv_id}/messages/{msg_id}
           |
           v
messaging_mutations.edit_message()
  1. Load message from Messages table
  2. Validate: sender owns it, within window, not encrypted/locked/view-once/deleted
  3. DDB UpdateItem: set text, edited=true, edited_at, original_text (audit), edit_count++
  4. Emit SSE event: message:edited -> all conversation participants
  5. Audit log: audit_event("message.edited", ...)
           |
           v
Return updated MessageOut (edited=true, edited_at=timestamp)
           |
           v
Frontend: optimistic update in React Query cache; SSE event triggers
          invalidation for other participants' views

-------

User clicks "Delete" in MessageContextMenu
           |
           v
Confirmation Dialog ("Delete this message? This cannot be undone.")
           |
           v (user confirms)
DELETE /ui/messaging/conversations/{conv_id}/messages/{msg_id}
           |
           v
messaging_mutations.delete_message()
  1. Load message from Messages table
  2. Validate: sender or admin, not already deleted
  3. DDB UpdateItem: set deleted=true, deleted_at, deleted_by,
     clear text/image_url/file_url/encryption_envelope
  4. Emit SSE event: message:deleted -> all conversation participants
  5. Audit log: audit_event("message.deleted", ...)
           |
           v
Return { ok: true, message_id: "m_..." }
           |
           v
Frontend: optimistic removal of message content; SSE event triggers
          cache update for other participants
```

### Component Interactions

- **`app/routers/messaging.py`**: PATCH and DELETE route handlers ALREADY EXIST at lines 9654 and 9480/9519 respectively. <!-- VERIFIED --> The edit logic is inline in the router, NOT in a separate mutations file.
- **`app/services/messaging_mutations.py`** (proposed new file): The ticket proposes a separate file, but currently all edit/delete logic lives directly in `app/routers/messaging.py`. <!-- CORRECTED: No messaging_mutations.py exists. The existing edit_message() at line 9655 and delete_message_for_me() at line 9481 and revoke_message_for_all() at line 9519 are all defined inline in the router. -->
- **`_message_out_from_item()`** in `messaging.py` (line 3725): Already handles message output transformation. Would need to be extended for `deleted` placeholder behavior. <!-- VERIFIED: _message_out_from_item at messaging.py:3725 -->
- **SSE stream**: The existing `fanout_event_to_conversation()` (messaging.py:5192) is used for messaging events, NOT `sse_publish_alert()`. Edit events already emit `message:edited` at line 9726-9732. <!-- CORRECTED: was "sse_publish_alert()", actually "fanout_event_to_conversation()" for messaging events. sse_publish_alert() in alerts.py is for alert-type notifications, not messaging. -->
- **Frontend `useMessagingStream.ts`**: Listens for new event types and invalidates the messages query for the affected conversation.

---

## 4. Data Model Deep Dive

### DynamoDB Changes -- Messages Table

The `Messages` table (PK: `conversation_id`, SK: `message_id`) already exists. No new table or GSI is needed. New attributes are added to existing message items.

**New attributes:**

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `edited` | BOOL | `false` | Set to `true` after first edit |
| `edited_at` | N | `0` | Unix timestamp of most recent edit |
| `original_text` | S | (absent) | Original text before first edit, for audit. NOT exposed via API. |
| `edit_count` | N | `0` | Number of times the message has been edited |
| `deleted` | BOOL | `false` | Set to `true` after soft-delete |
| `deleted_at` | N | `0` | Unix timestamp of deletion |
| `deleted_by` | S | (absent) | `user_sub` of the person who deleted (sender or admin) |

**MessageEdits table** (already exists at `DDB_MESSAGE_EDITS`): PK=`message_key` (formatted as `{conversation_id}#{message_id}`), SK=`edited_at` (numeric). Used to store a complete edit history entry per edit, for compliance/audit purposes. <!-- VERIFIED: DDB_MESSAGE_EDITS env var at messaging.py:175, tbl_edits = ddb.Table(DDB_MESSAGE_EDITS) at line 233. TableDef at local-ddb-init.py:271: PK=message_key, SK=edited_at. -->
<!-- NOTE: The existing edit_message() at line 9693-9701 already writes to tbl_edits with fields: message_key, edited_at (as str(ts)), edited_by, old_text, new_text, ttl. The SK "edited_at" is stored as STRING (str(ts)) not as numeric. The DDB init at line 271 does not declare attr_types for edited_at, so DynamoDB infers String type from the first write. -->

### Example: Message Before and After Edit

**Before edit:**
```json
{
  "conversation_id": "conv_abc",
  "message_id": "m_1a2b3c",
  "sender_id": "alice-uuid",
  "text": "Teh meeting is at 3pm",
  "created_at": 1748350000,
  "edited": false
}
```

**After edit:**
```json
{
  "conversation_id": "conv_abc",
  "message_id": "m_1a2b3c",
  "sender_id": "alice-uuid",
  "text": "The meeting is at 3pm",
  "created_at": 1748350000,
  "edited": true,
  "edited_at": 1748350120,
  "original_text": "Teh meeting is at 3pm",
  "edit_count": 1
}
```

**After delete:**
```json
{
  "conversation_id": "conv_abc",
  "message_id": "m_1a2b3c",
  "sender_id": "alice-uuid",
  "text": null,
  "image_url": null,
  "file_url": null,
  "encryption_envelope": null,
  "created_at": 1748350000,
  "edited": true,
  "edited_at": 1748350120,
  "deleted": true,
  "deleted_at": 1748350300,
  "deleted_by": "alice-uuid",
  "edit_count": 1
}
```

### Edit History Entry (MessageEdits table)

```json
{
  "message_key": "conv_abc#m_1a2b3c",
  "edited_at": 1748350120,
  "previous_text": "Teh meeting is at 3pm",
  "new_text": "The meeting is at 3pm",
  "editor_user_id": "alice-uuid",
  "edit_number": 1
}
```

### Access Patterns

| Pattern | Key | Index | Notes |
|---------|-----|-------|-------|
| Get message by ID | PK=conv_id, SK=msg_id | Table | Standard get_item |
| List messages in conversation | PK=conv_id, SK begins_with "m_" | Table | Existing pattern |
| Get edit history for message | PK=`{conv_id}#{msg_id}` | MessageEdits table | Compliance/audit only |

---

## 5. API Contract Design

### PATCH `/ui/messaging/conversations/{conv_id}/messages/{msg_id}`

**Request body:**

```json
{
  "text": "The meeting is at 3pm"
}
```

**Pydantic model:**

```python
class EditMessageReq(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
```
<!-- CORRECTED: The existing model is named EditMessageIn (not EditMessageReq), at messaging.py:2216-2229. It has text: str = Field(min_length=1, max_length=4000) and an optional body: str field with a legacy normalizer. Max length is 4000, not 10000. -->

**Response 200:** Updated `MessageOut`:

```json
{
  "message_id": "m_1a2b3c",
  "conversation_id": "conv_abc",
  "sender_id": "alice-uuid",
  "text": "The meeting is at 3pm",
  "created_at": 1748350000,
  "edited": true,
  "edited_at": 1748350120,
  "kind": "text",
  "deleted": false,
  "tip_amount_cents": 0,
  "reactions": {}
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Message can no longer be edited (15-minute window)"}` | `now_ts() - created_at > edit_window_seconds` |
| 400 | `{"detail": "Encrypted messages cannot be edited"}` | Message has `encryption_envelope` |
| 400 | `{"detail": "Locked messages cannot be edited"}` | Message has `lock_price_cents > 0` |
| 400 | `{"detail": "View-once messages cannot be edited"}` | Message has `view_once=True` |
| 400 | `{"detail": "Message has already been deleted"}` | `deleted=True` |
| 403 | `{"detail": "Only the sender can edit this message"}` | `sender_id != user_sub` |
| 404 | `{"detail": "Message not found"}` | No item with that PK/SK |

### DELETE `/ui/messaging/conversations/{conv_id}/messages/{msg_id}`

**No request body required.**

**Response 200:**

```json
{
  "ok": true,
  "message_id": "m_1a2b3c"
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Message has already been deleted"}` | `deleted=True` |
| 403 | `{"detail": "Only the sender or an admin can delete this message"}` | Not sender AND not admin/root |
| 404 | `{"detail": "Message not found"}` | No item with that PK/SK |

**Rate limits:** Standard messaging rate limits apply (existing `rate_limit.py` patterns). No additional rate limiting for edit/delete beyond what already exists for the conversation.

---

## 6. Frontend Component Design

### Component Tree

```
<ConversationView>
  <MessageBubble message={msg}>
    {msg.deleted ? (
      <DeletedPlaceholder />
    ) : (
      <>
        <MessageContent text={msg.text} ... />
        {msg.edited && <EditedIndicator editedAt={msg.edited_at} />}
      </>
    )}
    <MessageContextMenu
      message={msg}
      onEdit={() => setEditingMessage(msg)}
      onDelete={() => setDeletingMessage(msg)}
    />
  </MessageBubble>

  {editingMessage && (
    <ComposeBar
      mode="edit"
      initialText={editingMessage.text}
      onCancel={() => setEditingMessage(null)}
      onSubmit={(text) => editMutation.mutate({ msgId, text })}
    />
  )}

  {deletingMessage && (
    <DeleteConfirmDialog
      message={deletingMessage}
      onConfirm={() => deleteMutation.mutate(deletingMessage.message_id)}
      onCancel={() => setDeletingMessage(null)}
    />
  )}
</ConversationView>
```

### State Management

- **`editingMessage`**: Local state in `ConversationView`. When set, ComposeBar switches to edit mode.
- **`deletingMessage`**: Local state. When set, a confirmation dialog opens.
- **React Query mutations**:
  - `useEditMessage(convId)`: `useMutation` calling `PATCH /ui/messaging/conversations/{convId}/messages/{msgId}`. `onMutate`: optimistic update in `["messages", convId]` cache (update text, set edited=true). `onError`: roll back. `onSettled`: invalidate.
  - `useDeleteMessage(convId)`: `useMutation` calling `DELETE /ui/messaging/conversations/{convId}/messages/{msgId}`. `onMutate`: optimistic update (set deleted=true, null out content). `onError`: roll back. `onSettled`: invalidate.
- **SSE events in `useMessagingStream.ts`**:
  - `message:edited`: `queryClient.invalidateQueries(["messages", event.conversation_id])`.
  - `message:deleted`: Same invalidation. Could also do a targeted cache update (set `deleted=true` on the specific message) for instant UI feedback.

### MessageContextMenu

Rendered via Radix UI `ContextMenu` (right-click on desktop) and a long-press handler (mobile). Menu items:

| Item | Condition | Action |
|------|-----------|--------|
| Edit | Own message, within window, not encrypted/locked/view-once/deleted | `onEdit(message)` |
| Delete | Own message OR user is admin/root; not already deleted | `onDelete(message)` |
| Copy Text | Not deleted; has text | Copy `message.text` to clipboard |
| Reply | Not deleted | Existing reply flow |

The edit time window is enforced client-side (gray out "Edit" if expired) AND server-side (400 if expired). Client-side uses `Date.now() / 1000 - message.created_at > 900` (15 min).

### ComposeBar Edit Mode

When `mode="edit"`:
- Pre-fill the textarea with `editingMessage.text`.
- Show a banner above the textarea: "Editing message" with an X (cancel) button.
- Change the Send button icon from `SendHorizonal` to `Check`.
- Disable file/image/calendar pickers (edit only changes text).
- On submit: call `editMutation.mutate({ msgId: editingMessage.message_id, text })`.
- On cancel: clear `editingMessage` state; restore normal ComposeBar.

### UI Mockup Descriptions

1. **Edited indicator**: Below the message timestamp, a small gray italic text "(edited)" appears. On hover/tap, a tooltip shows the edit timestamp formatted as "Edited May 27, 2026 at 3:15 PM".

2. **Deleted placeholder**: The entire message bubble is replaced with a gray italic text "This message was deleted" centered in a slightly dimmed bubble. Reactions, tips, lock badges, and action buttons are hidden. The sender name and timestamp remain visible.

3. **Context menu**: A dropdown menu appearing at the cursor position (right-click) or below the message (long-press). Items have icons: `Pencil` for Edit, `Trash2` for Delete, `Copy` for Copy Text, `Reply` for Reply.

4. **Delete confirmation dialog**: A `AlertDialog` (shadcn/ui) with title "Delete message?", body "This message will be permanently deleted for all participants. This action cannot be undone.", and two buttons: "Cancel" (secondary) and "Delete" (destructive red).

---

## 7. Security & Privacy Considerations

### Authentication & Authorization

- Both PATCH and DELETE require `require_ui_session` (cookie auth + CSRF token).
- Edit: Only the sender (`sender_id == session.user_sub`) can edit their own message. Admin cannot edit on behalf of sender.
- Delete: The sender can delete their own message. Admin/root users (`session.role in {ADMIN, ROOT}`) can delete any message for moderation.
- Participant validation: The authenticated user must be a participant in the conversation (checked via the participants table, same as existing message operations). <!-- CORRECTED: The participants table is NOT accessed through T.participants. It is accessed as tbl_parts = ddb.Table(DDB_PARTICIPANTS) directly in messaging.py:222. The Participants table is defined in local-ddb-init.py:241-244 with PK=user_id, SK=conversation_id. The existing edit_message uses require_participant_active() at line 9662. -->

### Input Validation

- Edit text: `min_length=1, max_length=4000` (matches existing EditMessageIn at messaging.py:2217). <!-- CORRECTED: was 10000, actually 4000 -->
- Message ID: Validated as existing in the conversation (404 if not found).
- Conversation ID: Validated as existing and user is a participant.

### Data Protection

- **Original text preserved for audit**: `original_text` is stored in the Messages table but NEVER included in the `MessageOut` response. It is only accessible through direct DDB access (admin tooling / compliance queries).
- **Edit history**: Each edit creates a row in the `MessageEdits` table for compliance audit trails. This table is not exposed via any API endpoint.
- **Deleted content truly cleared**: On delete, `text`, `image_url`, `file_url`, and `encryption_envelope` are set to `null` in DDB. The data is not recoverable through the API. The `original_text` field (if present from a prior edit) is also cleared on delete.
- **S3 objects for deleted image/file messages**: The S3 object is NOT deleted by this operation (retained for compliance). A future cleanup job could delete orphaned S3 objects after a retention period.

### Abuse Prevention

- **Edit window**: 15-minute default prevents using edit to change a message long after the recipient has read and acted on it. Configurable via `MESSAGE_EDIT_WINDOW_SECONDS` setting.
- **No edit for encrypted messages**: Prevents a sender from changing plaintext after all participants have decrypted the original.
- **No edit for locked messages**: Prevents bait-and-switch -- changing content after a buyer has paid to unlock.
- **No edit for view-once messages**: Content is already consumed or pending; editing could bypass the view-once contract.
- **Admin delete audit trail**: Every admin deletion is recorded via `audit_event()` with the admin's `user_sub`, the message content (before deletion), and the reason. This prevents abuse of admin delete power.

---

## 8. Performance & Scalability

### Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Edit message | 1 GetItem + 1 UpdateItem + 1 PutItem (edit history) | 3 WCU + 1 RCU |
| Delete message | 1 GetItem + 1 UpdateItem | 2 WCU + 1 RCU |
| List messages (with edited/deleted) | No additional cost | Existing fields added to projection |

### Caching Strategy

- **No backend caching**: Message mutations must be immediately visible. DDB conditional updates ensure consistency.
- **Frontend React Query**: Optimistic updates for instant feedback. Mutations use `onMutate` for immediate cache modification and `onSettled` for server-truth reconciliation.
- **SSE events**: Push-based invalidation ensures other participants see changes within 1-2 seconds.

### Known Bottlenecks

1. **Edit history table growth**: Each edit creates a new row in MessageEdits. For a very active user who edits frequently, this table could grow. Mitigation: TTL on edit history rows (90 days), same as message compliance retention.
2. **SSE fan-out for large group chats**: An edit/delete in a group with 100 members emits 100 SSE events. This uses the existing SSE infrastructure which already handles message send events at the same scale.

---

## 9. Migration & Rollback Plan

### Deployment Phases

1. **Phase 1 -- Backend schema extension**: Add `edited`, `edited_at`, `deleted`, `deleted_by` to `MessageOut` Pydantic model with backward-compatible defaults (all `False`/`None`). Deploy to production. No behavioral change -- existing messages do not have these attributes, so they default to `False`.
2. **Phase 2 -- Backend endpoints**: Deploy PATCH and DELETE handlers behind feature flag `MESSAGE_EDIT_DELETE_ENABLED`. When disabled, both endpoints return 404.
3. **Phase 3 -- Frontend**: Deploy UI changes (context menu, edit mode, deleted placeholder). The context menu shows Edit/Delete only when the backend feature flag is enabled (check via a feature flags endpoint or simply handle 404 gracefully).
4. **Phase 4 -- Enable**: Set `MESSAGE_EDIT_DELETE_ENABLED=true` in production.

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `MESSAGE_EDIT_DELETE_ENABLED` | `true` (dev), `false` (prod) | Master enable/disable for edit+delete endpoints |
| `MESSAGE_EDIT_WINDOW_SECONDS` | `900` (15 min) | Configurable edit time window |
| `MESSAGE_EDIT_ADMIN_AUDIT_ENABLED` | `true` | Whether admin deletes are audit-logged (should always be true) |
<!-- NOTE: None of these settings exist yet in settings.py. The existing edit_message() at messaging.py:9654 has NO time-window check — it allows editing at any time. The EDITS_TTL_SEC at line 214 (90 days) controls edit history row TTL, not the edit window. These settings must be added. -->

### Rollback Steps

1. Set `MESSAGE_EDIT_DELETE_ENABLED=false` -- endpoints return 404, UI disables context menu items.
2. Already-edited messages retain `edited=true` and `edited_at` -- this is harmless (UI shows "(edited)" but no edit operation is available).
3. Already-deleted messages retain `deleted=true` with null content -- this is the intended permanent state and cannot be rolled back (by design).

---

## 10. Testing Strategy

### Unit Tests (`tests/test_messaging_mutations.py`)

| Test | Description |
|------|-------------|
| `test_edit_message_success` | Sender edits own message within window; assert text updated, edited=true, edited_at set. |
| `test_edit_preserves_original_text` | After edit, `original_text` stored in DDB item. Not present in API response. |
| `test_edit_increments_count` | Two edits; assert `edit_count=2`. |
| `test_edit_window_expired` | Message created >15 min ago; assert 400 with window message. |
| `test_edit_not_sender` | Another user attempts edit; assert 403. |
| `test_edit_encrypted_blocked` | Message with encryption_envelope; assert 400. |
| `test_edit_locked_blocked` | Message with lock_price_cents > 0; assert 400. |
| `test_edit_view_once_blocked` | Message with view_once=True; assert 400. |
| `test_edit_already_deleted` | Message already deleted; assert 400. |
| `test_edit_scheduled_message` | Scheduled (not yet delivered) message can be edited; assert success. |
| `test_delete_by_sender` | Sender deletes own message; assert deleted=true, text=None. |
| `test_delete_by_admin` | Admin deletes another user's message; assert success. |
| `test_delete_not_sender_not_admin` | Regular user deletes another's message; assert 403. |
| `test_delete_already_deleted` | Double delete; assert 400. |
| `test_delete_clears_content` | After delete, text, image_url, file_url, encryption_envelope are null in DDB. |
| `test_delete_preserves_metadata` | After delete, sender_id, created_at, conversation_id remain. |
| `test_edit_history_created` | After edit, MessageEdits table has entry with previous_text and new_text. |
| `test_audit_event_on_edit` | Edit triggers audit_event with event type "message.edited". |
| `test_audit_event_on_delete` | Delete triggers audit_event with event type "message.deleted". |
| `test_participant_validation` | Non-participant cannot edit/delete; assert 403. |

### E2E Test Matrix (`frontend/e2e/message-edit-delete.spec.ts`)

**Section A: Edit API (7 tests)**

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | Sender edits message text successfully | Alice sends "hello", then PATCH with "goodbye" | Response has `text: "goodbye"`, `edited: true` |
| 2 | Edited message has edited=true and edited_at set | Same as above | `edited_at` is within 5 seconds of now |
| 3 | Edit after time window returns 400 | Alice sends message; set MESSAGE_EDIT_WINDOW_SECONDS=1; wait 2s; PATCH | Status 400, detail contains "window" |
| 4 | Non-sender cannot edit another user's message (403) | Alice sends; Bob PATCHes | Status 403 |
| 5 | Encrypted message edit returns 400 | Alice sends encrypted message; PATCH | Status 400, detail contains "Encrypted" |
| 6 | Locked message edit returns 400 | Alice sends locked message (lock_price_cents=100); PATCH | Status 400, detail contains "Locked" |
| 7 | View-once message edit returns 400 | Alice sends view-once; PATCH | Status 400, detail contains "View-once" |

**Section B: Delete API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Sender deletes own message successfully | Status 200, ok=true |
| 2 | Deleted message returns deleted=true with null text | GET message; text=null, deleted=true |
| 3 | Admin deletes another user's message | Root deletes Alice's message; 200 |
| 4 | Non-sender, non-admin cannot delete (403) | Bob deletes Alice's message; 403 |
| 5 | Double-delete returns 400 | Delete twice; second returns 400 |

**Section C: Edit UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Context menu shows "Edit" for own message within window | Right-click on Alice's message; "Edit" menu item visible |
| 2 | Context menu hides "Edit" for other user's message | Right-click on Bob's message; "Edit" not visible |
| 3 | Edit mode pre-fills ComposeBar with message text | Click "Edit"; ComposeBar textarea contains message text; "Editing message" banner visible |
| 4 | Saving edit updates message bubble with "edited" indicator | Submit edit; message bubble shows "(edited)" text |

**Section D: Delete UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Context menu shows "Delete" for own message | Right-click on Alice's message; "Delete" menu item visible |
| 2 | Delete confirmation dialog appears | Click "Delete"; AlertDialog visible with "Delete message?" title |
| 3 | Confirming delete replaces message with "This message was deleted" | Click "Delete" in dialog; message bubble shows placeholder text |
| 4 | Deleted message hides reactions and tip amount | Message with reactions + tip; after delete, neither visible |

---

## 11. Monitoring & Alerting

### Metrics to Track

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `messaging_edits_total` | Counter | `status` (success/error) | Total edit operations |
| `messaging_deletes_total` | Counter | `status`, `actor` (sender/admin) | Total delete operations |
| `messaging_edit_latency_seconds` | Histogram | - | Edit operation duration |
| `messaging_delete_latency_seconds` | Histogram | - | Delete operation duration |
| `messaging_edit_window_rejections_total` | Counter | - | Edits rejected due to expired window |
| `messaging_admin_deletes_total` | Counter | `admin_user_sub` | Admin delete actions (audit) |

### Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Edit error rate spike | `messaging_edits_total{status="error"}` > 10 in 5 minutes | Warning |
| Admin delete spike | `messaging_admin_deletes_total` > 50 in 1 hour | Warning (possible abuse) |
| Edit latency high | P95 > 1 second for 5 minutes | Warning |

---

## 12. Open Questions & Risks

### Unresolved Decisions

1. **Edit history visibility**: Should users be able to see the edit history of a message (like Discord)? This ticket stores edit history in MessageEdits for audit but does not expose it via API. Recommendation: Defer user-facing edit history to a follow-up ticket; keep audit-only for v1.

2. **Delete for me vs. delete for everyone**: Should there be a "delete for me" option that only hides the message from the deleter's view (like WhatsApp)? This ticket implements "delete for everyone" only. Recommendation: Defer "delete for me" -- it requires a separate visibility layer (already partially built with `MessageVisibilityOverrides`).

3. **Notification of deletion**: Should the recipient get a push/toast notification when a message they already read is deleted? Pro: transparency. Con: noise. Recommendation: No notification; the UI placeholder is sufficient.

4. **Edit for image/file messages**: This ticket only supports editing text messages. Should image captions be editable? Recommendation: Defer; image messages do not currently have a separate caption field.

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Race condition: edit while SSE event in flight | Recipient sees stale text briefly | SSE invalidation handles this; stale state resolves within seconds |
| DDB conditional update failure | Edit could silently fail if message was concurrently deleted | Use ConditionExpression `attribute_exists(message_id) AND deleted <> :true` |
| Compliance: edit removes evidence | Edited messages lose original text in API | original_text preserved in DDB + edit history in MessageEdits table |

---

## 13. Implementation Timeline

### Phase 1: Backend (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add settings (`MESSAGE_EDIT_DELETE_ENABLED`, `MESSAGE_EDIT_WINDOW_SECONDS`). Extend `MessageOut` with `edited`, `edited_at`, `deleted` fields. Create `app/services/messaging_mutations.py` with `edit_message()` and `delete_message()`. |
| 2 | Add PATCH and DELETE route handlers to `app/routers/messaging.py`. Wire up SSE events (`message:edited`, `message:deleted`). Add audit logging. Write edit history to MessageEdits table. |
| 3 | Write unit tests (20 tests). Test all validation rules, edge cases, audit logging, and SSE event emission. |

### Phase 2: Frontend (Days 4-5)

| Day | Task |
|-----|------|
| 4 | Create `MessageContextMenu.tsx` with Edit/Delete/Copy/Reply items. Add context menu trigger to `MessageBubble.tsx`. Create `DeleteConfirmDialog.tsx`. Add "(edited)" indicator and "This message was deleted" placeholder to MessageBubble. |
| 5 | Implement ComposeBar edit mode (pre-fill, banner, cancel). Create `useEditMessage` and `useDeleteMessage` mutations. Wire SSE event handlers in `useMessagingStream.ts`. |

### Phase 3: E2E Tests + Polish (Days 6-7)

| Day | Task |
|-----|------|
| 6 | Write `frontend/e2e/message-edit-delete.spec.ts` -- 20 tests across 4 sections. |
| 7 | Fix bugs found in E2E testing. Mobile responsive testing. Final code review. |

---

## Appendix: Codebase Citations

| Claim | Verified? | File:Line | Notes |
|-------|-----------|-----------|-------|
| Messages table exists | Yes | `scripts/local-ddb-init.py:246-257` | PK=conversation_id, SK=message_id |
| MessageEdits table exists | Yes | `scripts/local-ddb-init.py:271` | PK=message_key, SK=edited_at |
| `tbl_edits` reference in messaging router | Yes | `app/routers/messaging.py:233` | `tbl_edits = ddb.Table(DDB_MESSAGE_EDITS)` |
| `edit_message()` ALREADY EXISTS | Yes | `app/routers/messaging.py:9655` | PATCH endpoint at line 9654, validates sender, kind=text, not encrypted, not revoked |
| `delete_message_for_me()` ALREADY EXISTS | Yes | `app/routers/messaging.py:9481` | DELETE endpoint at line 9480, adds user to `deleted_for` set |
| `revoke_message_for_all()` ALREADY EXISTS | Yes | `app/routers/messaging.py:9520` | DELETE .../revoke endpoint at line 9519 |
| `EditMessageIn` model ALREADY EXISTS | Yes | `app/routers/messaging.py:2216-2229` | `text: str = Field(min_length=1, max_length=4000)`, NOT max_length=10000 as proposed |
| `_message_out_from_item()` | Yes | `app/routers/messaging.py:3725` | Transforms DDB item to MessageOut |
| `fanout_event_to_conversation()` | Yes | `app/routers/messaging.py:5192` | Used for messaging SSE events, NOT sse_publish_alert |
| `require_ui_session` | Yes | `app/services/sessions.py:283` | Standard auth dependency |
| `EDITS_TTL_SEC` | Yes | `app/routers/messaging.py:214` | `int(os.getenv("EDITS_TTL_SEC", "7776000"))` = 90 days TTL on edit history rows |
| `DDB_MESSAGE_EDITS` env var | Yes | `app/routers/messaging.py:175` | Default "MessageEdits" |
| Participants table (not via T) | Yes | `app/routers/messaging.py:222` | `tbl_parts = ddb.Table(DDB_PARTICIPANTS)`, local-ddb-init.py:241-244 |
| `_ensure_can_revoke_message()` | Yes | `app/routers/messaging.py:4793` | Validates revoke permissions |
| Edit emits SSE event | Yes | `app/routers/messaging.py:9726-9732` | `fanout_event_to_conversation(event_type="message:edited")` |
| Edit records audit event | Yes | `app/routers/messaging.py:9735-9742` | `audit_event("messaging_message_edited", ...)` |
| Edit updates search index | Yes | `app/routers/messaging.py:9720-9721` | `remove_message_search()` + `index_message_search()` |
| No MESSAGE_EDIT_WINDOW_SECONDS setting | Confirmed | `app/core/settings.py` | Does not exist. Current edit has no time window. |
| No MESSAGE_EDIT_DELETE_ENABLED setting | Confirmed | `app/core/settings.py` | Does not exist. Edit/delete are always enabled. |
| `messaging_mutations.py` does NOT exist | Confirmed | `app/services/` | All edit/delete logic is inline in the router. |

---

## 14. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Edit window expired | 400 | `edit_window_expired` | "Message can no longer be edited (15-minute window)." | Send a follow-up message instead |
| Encrypted message edit | 400 | `edit_encrypted_blocked` | "Encrypted messages cannot be edited." | Delete and re-send if needed |
| Locked message edit | 400 | `edit_locked_blocked` | "Locked messages cannot be edited." | Cannot modify paid content |
| View-once message edit | 400 | `edit_view_once_blocked` | "View-once messages cannot be edited." | Cannot modify ephemeral content |
| Message already deleted | 400 | `already_deleted` | "This message has already been deleted." | No action needed |
| Not sender (edit) | 403 | `not_sender` | "Only the sender can edit this message." | Contact the sender |
| Not sender and not admin (delete) | 403 | `not_authorized_delete` | "Only the sender or an admin can delete this message." | Contact admin for moderation |
| Message not found | 404 | `message_not_found` | "Message not found." | Refresh the conversation |
| Not a conversation participant | 403 | `not_participant` | "You are not a participant in this conversation." | Join the conversation |
| Empty edit text | 422 | `validation_error` | "Message text cannot be empty." | Enter message text |
| Edit text exceeds max length | 422 | `validation_error` | "Message text exceeds maximum length (4000 characters)." | Shorten the message |

---

## 15. DynamoDB Access Patterns

| Access Pattern | PK | SK / Index | Operation | Notes |
|---|---|---|---|---|
| Get message by ID | `conversation_id` | `message_id` | GetItem | 1 RCU, used for edit/delete validation |
| Update message text (edit) | `conversation_id` | `message_id` | UpdateItem | Sets text, edited, edited_at, edit_count |
| Soft-delete message | `conversation_id` | `message_id` | UpdateItem | Clears text/image/file, sets deleted=true |
| Write edit history | `{conv_id}#{msg_id}` (MessageEdits) | `edited_at` | PutItem | Audit trail, TTL=90 days |
| Get edit history | `{conv_id}#{msg_id}` (MessageEdits) | Query all | Query | Compliance only, not exposed via API |
| Check participant status | `user_id` (Participants) | `conversation_id` | GetItem | Authorization check |

**Example DynamoDB Update (edit):**
```json
{
  "TableName": "Messages",
  "Key": {"conversation_id": "conv_abc", "message_id": "m_1a2b3c"},
  "UpdateExpression": "SET #text = :text, edited = :t, edited_at = :ts, original_text = if_not_exists(original_text, #text), edit_count = if_not_exists(edit_count, :zero) + :one",
  "ConditionExpression": "attribute_exists(message_id) AND (attribute_not_exists(deleted) OR deleted = :f)",
  "ExpressionAttributeNames": {"#text": "text"},
  "ExpressionAttributeValues": {
    ":text": "The meeting is at 3pm",
    ":t": true,
    ":ts": 1748350120,
    ":f": false,
    ":zero": 0,
    ":one": 1
  }
}
```

---

## 16. Observability & Monitoring (Extended)

### 16.1 Dashboard Queries

| Dashboard Panel | Query | Description |
|---|---|---|
| Edit volume over time | `sum(rate(messaging_edits_total[5m]))` | Edits per second |
| Delete volume by actor | `sum by (actor)(rate(messaging_deletes_total[5m]))` | Sender vs admin deletes |
| Edit window rejections | `rate(messaging_edit_window_rejections_total[5m])` | Users hitting the time limit |
| Edit latency distribution | `histogram_quantile(0.95, messaging_edit_latency_seconds_bucket)` | P95 edit latency |
| Admin moderation activity | `sum by (admin_user_sub)(messaging_admin_deletes_total)` | Per-admin delete counts |

### 16.2 Rollout Plan (Extended)

| Phase | Duration | Criteria to Advance |
|---|---|---|
| Phase 1: Backend schema | Day 1 | Zero runtime errors for 24h |
| Phase 2: Backend endpoints (flag off) | Day 2-3 | Unit tests pass, E2E dry run |
| Phase 3: Frontend changes | Day 4-5 | UI renders correctly, optimistic updates work |
| Phase 4: Enable for internal team | Day 6 | 50+ edits/deletes by team, no data corruption |
| Phase 5: Enable for all users | Day 7 | Monitor edit/delete volume, alert thresholds stable |

### 16.3 Performance Notes

- Edit and delete operations are single-item DDB updates (constant cost regardless of conversation size)
- SSE fan-out for edits/deletes uses the same infrastructure as message sends (no additional scaling concern)
- Edit history (MessageEdits table) rows have 90-day TTL to prevent unbounded growth
- The `original_text` field is set only on the first edit (`if_not_exists`), preventing repeated overwrites

**Key finding**: The ticket's premise that edit/delete "does not exist" is **incorrect**. Both operations are already implemented. This ticket should be scoped as an **enhancement** of the existing edit/delete functionality, adding: time-window enforcement, admin moderation delete, proper "deleted" placeholder behavior in the UI, and frontend context menu integration.

---

## Codebase References

| File | Line(s) | What was verified |
|------|---------|-------------------|
| `app/routers/messaging.py` | 10157 | ALREADY EXISTS: `edit_message()` function |
| `app/routers/messaging.py` | 9983 | ALREADY EXISTS: `delete_message_for_me()` function |
| `app/routers/messaging.py` | 10022 | ALREADY EXISTS: `revoke_message_for_all()` function |
| `app/routers/messaging.py` | 2255 | ALREADY EXISTS: `EditMessageIn` Pydantic model |
| `app/routers/messaging.py` | 175, 234 | EXISTS: `DDB_MESSAGE_EDITS` env var and `tbl_edits` table handle |
| `app/routers/messaging.py` | 10195 | EXISTS: edit history written to `tbl_edits` table |
| `app/routers/messaging.py` | 10273 | EXISTS: edit history queried from `tbl_edits` |
| `scripts/local-ddb-init.py` | 276 | EXISTS: `MessageEdits` table definition |
| `app/routers/messaging.py` | 1264 | EXISTS: `ENCRYPTED_EDIT_ERROR_CODE` — encrypted message edit restriction |
