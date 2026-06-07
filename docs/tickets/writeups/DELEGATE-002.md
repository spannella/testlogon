# DELEGATE-002: Chat Delegation — Investigation & Implementation Write-up

## 1. Summary & Classification

DELEGATE-002 lets delegates with `chat_read` or `chat_respond` permissions view and respond to a creator's direct messages and group chats. The core flow is: (1) delegate enters "Managing @creator" mode in the UI, (2) API calls hit new `/messaging/delegate/{creator_id}/*` endpoints, (3) sent messages are stored with `sender_id=creator_id` but carry `sent_by_delegate` metadata, and (4) encrypted messages are redacted at the service layer. The ticket also defines an SSE stream for real-time delivery to delegates.

- **Type**: Feature (authz-delegated messaging access)
- **Priority**: High
- **Status**: Core implementation shipped; SSE delegate stream and audit UI component are absent
- **Owning area**: Messaging / authorization
- **User personas**: Delegate (read/respond), Creator (audit), Fan (transparent experience)
- **Cross-references**: [[DELEGATE-001]] (required — `require_delegate_permission`, audit), [[SEC-005]] (IDOR — delegate cannot access creator's non-messaging data), [[SEC-018]] (revocation — should terminate SSE and block next API call), [[SECOPS-007]] (dev/prod parity), [[DELEGATE-005]] (wraps this service for API-key access)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/delegate_chat.py` (392 lines, fully implemented)

| Function | Location | Notes |
|----------|----------|-------|
| `list_creator_conversations` | `delegate_chat.py:37` | Calls `require_delegate_permission(..., "chat_read")`; paginates `tbl_parts` with `Limit=500` up to 2000 items; batch-fetches conversations; sorts by `last_message_at` |
| `get_creator_conversation_messages` | `delegate_chat.py:143` | Calls `require_delegate_permission(..., "chat_read")`; verifies creator is a participant (`_require_creator_participant`); queries DDB; calls `_redact_encrypted_for_delegate` on each message |
| `send_message_as_creator` | `delegate_chat.py:187` | Calls `require_delegate_permission(..., "chat_respond")`; builds delegate tag from `show_delegate_tag` + `delegate_tag_format`; writes `message_id`, `sender_id=creator_id`, `sent_by_delegate=delegate_id`; bumps unread counts; writes delegation audit entry |
| `get_delegated_messages_audit` | `delegate_chat.py:304` | Creator-only (enforces `requester_id == creator_id`); queries `AUDIT#` prefix, filters `action == chat_message_sent` |
| `_redact_encrypted_for_delegate` | `delegate_chat.py:386` | Sets `text=None`, `delegate_cannot_decrypt=True` when `is_encrypted` or `encryption` fields are truthy |

**Direct table access**: `delegate_chat.py` hits `Conversations`, `Participants`, and `Messages` tables via `ddb.Table(os.getenv("DDB_CONVERSATIONS", ...))` etc. — it does not use `T.*` handles from `app/core/tables.py`. This works in both dev and prod because `ddb` is the boto3 resource initialized from `ddb_endpoint_url`.

### 2.2 Router — endpoints in `app/routers/messaging.py` (at line ~14215)

Four delegation endpoints are appended to the existing messaging router (which has `prefix="/messaging"` visible in `MessagesPage` frontend URL patterns):

| Method | Path | Auth dependency | Permission enforced |
|--------|------|-----------------|---------------------|
| `GET` | `/messaging/delegate/{creator_id}/conversations` | `get_messaging_user_id` | `chat_read` (in service) |
| `GET` | `/messaging/delegate/{creator_id}/conversations/{cid}/messages` | `get_messaging_user_id` | `chat_read` (in service) |
| `POST` | `/messaging/delegate/{creator_id}/conversations/{cid}/messages` | `get_messaging_user_id` | `chat_respond` (in service) |
| `GET` | `/messaging/delegate/{creator_id}/audit` | `get_messaging_user_id` | creator-only check (in service) |

`get_messaging_user_id` (`messaging.py:1549`) supports cookie auth, bearer auth, and API-key principal injection. The delegate endpoints inherit this — a delegate using cookie auth goes through `require_ui_session` which performs the CSRF + ban check; a delegate using a delegation API key goes through the `api_key_principal` path.

**No SSE endpoint** (`/messaging/delegate/{creator_id}/sse`) exists. The ticket design specified it but it was not implemented.

### 2.3 Frontend — `DelegateBanner.tsx`, `DelegateConversationView.tsx`, `MessagesPage.tsx`

`MessagesPage.tsx:22` reads `managingCreatorId` from `authStore`. When set:
- `useMessagingStream` is disabled (`!managingCreatorId`) at line 36 — own SSE is paused.
- A React Query query for `["delegate", "conversations", managingCreatorId]` fires using `listDelegatedConversations` (line 57-59).
- `DelegateBanner.tsx` (85 lines) renders "Managing @{creator}" with an exit button that calls `setManagingCreator(null)`.
- `DelegateConversationView.tsx` (218 lines) renders messages with a `DelegateMessageBubble` inline component (line 156) showing `[via @delegate]` tags and `[Encrypted — cannot decrypt]` placeholders.

**Missing frontend components** compared to ticket design:
- `CreatorSelector.tsx` — no standalone file exists (switching creators is not implemented in the UI)
- `DelegateAuditView.tsx` — no audit tab in the messaging UI
- API wrapper `listChatDelegateAudit` exists in `delegates.ts:113` but there is no React component that calls it

**`authStore.ts`**: `managingCreatorId` (string | null) and `setManagingCreator` are implemented at lines 15, 34, 50, 69.

### 2.4 E2E test file

`frontend/e2e/chat-delegation.spec.ts` exists.

### 2.5 Dev vs Prod behavior

No feature flag gates chat delegation. The delegate chat service uses DDB tables directly; in dev these are DDB Local. `app/services/sessions.py:284` handles auth for both cookie and bearer modes without `if dev:` branches. No mock backend is needed — fully offline. The SSE gap affects both dev and prod equally.

---

## 3. Gap / Threat Analysis

### 3.1 Missing SSE delegate stream (functional gap)

The ticket specified `GET /messaging/delegate/{creator_id}/sse` and a server-side fan-out mechanism so delegates receive real-time events for the creator's conversations. No such endpoint exists. The current workaround in `MessagesPage.tsx` is to disable the delegate's own SSE and rely on React Query refetch via `window.dispatchEvent(new Event("online"))`. This means:

- Delegates do not see new messages in real-time; they must manually trigger a refetch.
- Delegates cannot rely on the standard `online` event path because `ConversationView` is replaced by `DelegateConversationView`, which may or may not wire the same listener.

**Impact**: Degraded UX, not a correctness issue. The DELEGATE-002 acceptance criterion "Delegates receive real-time SSE events" is not met.

### 3.2 Creator selector missing (functional gap)

`MessagesPage.tsx` reads `managingCreatorId` from `authStore` but provides no UI to switch between managed creators. The `DelegateBanner` shows the current creator and an exit button, but if a delegate manages multiple creators (each relationship from DELEGATE-001 GSI1), there is no way to switch without going to `/delegates` and re-entering managing mode.

### 3.3 Audit UI missing (functional gap)

`DelegateAuditView.tsx` is absent. The backend endpoint `GET /messaging/delegate/{creator_id}/audit` exists and the API client wrapper `listChatDelegateAudit` exists, but no React component surfaces this data.

### 3.4 Authorization (SEC-005)

Every service function validates the delegation relationship before accessing creator data. `_require_creator_participant` at `delegate_chat.py:356` verifies the creator is actually a participant in the specified conversation — this prevents a delegate from guessing an arbitrary `conversation_id` and accessing it (IDOR defense). All creator path parameters are validated against the DDB record.

### 3.5 Revocation (SEC-018)

`require_delegate_permission` at `delegates.py:256` does a live DDB `get_item` on every call. After `revoke_delegate` deletes the record, the next API call returns 403 immediately. The SSE gap means there is no active SSE connection to terminate, so the SEC-018 "SSE must close on revocation" criterion is vacuously met (there is no SSE to close). Once SSE is added, a heartbeat-based revocation check must be wired in.

### 3.6 Encrypted message protection

`_redact_encrypted_for_delegate` at `delegate_chat.py:386` is called on every message before returning. It checks both `is_encrypted` (boolean flag) and `encryption` (object field). This double check is correct — the platform stores encrypted messages with both indicators in some cases.

### 3.7 Code sites that need changes

| File | What | Why |
|------|------|-----|
| `app/routers/messaging.py` | Add `GET /delegate/{creator_id}/sse` endpoint | Real-time delegate delivery |
| `frontend/src/pages/messages/` | Add `CreatorSelector.tsx` | Multi-creator switching |
| `frontend/src/pages/messages/` | Add `DelegateAuditView.tsx` | Creator audit tab in messages |
| `frontend/src/hooks/useMessagingStream.ts` | Add creator-scoped mode | Delegate SSE subscription |

---

## 4. Proposed Design / Fix

### 4.1 SSE for delegates (highest priority gap)

**Backend**: Add to `app/routers/messaging.py` after the existing delegation endpoints:

```python
@router.get("/delegate/{creator_id}/sse")
async def delegate_sse_stream(
    creator_id: str,
    user_id: str = Depends(get_messaging_user_id),
    request: Request = None,
):
    """SSE stream for creator's conversations, delivered to delegate."""
    from app.services.delegates import require_delegate_permission
    require_delegate_permission(
        creator_id=creator_id,
        delegate_id=user_id,
        required_permission="chat_read",
    )
    # Reuse existing SSE generator, scoped to creator_id
```

The existing messaging SSE stream is keyed by `user_id`. Reusing it with `creator_id` substituted delivers creator events to the delegate connection. A heartbeat loop should call `check_delegate_permission` every 30s and close the stream on False (SEC-018 enforcement).

**Frontend**: Update `useMessagingStream.ts` to accept an optional `creatorId` parameter; when set, connect to `/messaging/delegate/{creatorId}/sse` instead of the default stream.

### 4.2 Creator selector

Add `CreatorSelector.tsx` that calls `listManagedCreators()` from `delegates.ts` and renders a dropdown. Clicking an entry calls `setManagingCreator(creatorId, displayName)` in authStore. Place it inside `DelegateBanner.tsx`.

### 4.3 Delegate audit view

Add `DelegateAuditView.tsx` that calls `listChatDelegateAudit(creatorId)`. Surface it as a tab in `MessagesPage.tsx` visible only when `managingCreatorId` is set and the creator (i.e., when the user is viewing their own creator account and someone else is managing it — shown when `authStore.user_sub === managingCreatorId` is false and the audit is requested by the creator checking their own account). The backend endpoint already enforces this: `get_delegated_messages_audit` returns 403 if `requester_id !== creator_id`.

### 4.4 Dev/Prod parity (SECOPS-007)

The DDB tables accessed (`Conversations`, `Participants`, `Messages`) use `os.getenv("DDB_*", default)` at module load in `delegate_chat.py:28-34`. In dev these resolve to DDB Local. In prod they resolve to real DynamoDB tables. No mocks are needed. The SSE endpoint will use the same `EventSourceResponse` pattern as the existing messaging SSE, which runs without AWS.

### 4.5 Rate limiting (per ticket design)

Currently no per-delegate messaging rate limit exists. The standard `broadcast_chat_rate_limit` pattern in `broadcast_chat_store.py` uses an in-memory dict. A similar `_delegate_msg_rate_buckets: Dict[Tuple[str,str], deque]` keyed by `(delegate_id, creator_id)` should be added to `delegate_chat.py`. The ticket specifies 60 messages/min.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_delegate_chat.py`)

| Case | Assertion |
|------|-----------|
| `test_list_conversations_requires_chat_read` | 403 when delegate has only `feed_post` |
| `test_send_message_attribution` | `sender_id=creator`, `sent_by_delegate=delegate` |
| `test_delegate_tag_appended_when_enabled` | `text` ends with `[via @Bob]` |
| `test_delegate_tag_omitted_when_disabled` | `show_delegate_tag=false` on delegate record; no tag suffix |
| `test_encrypted_message_redacted` | `text=None`, `delegate_cannot_decrypt=True` |
| `test_chat_respond_requires_permission` | 403 for `chat_read`-only delegate on POST |
| `test_require_creator_participant_enforced` | 404 for conversation where creator is not a participant |
| `test_audit_creator_only` | 403 when `requester_id != creator_id` |

### 5.2 Playwright E2E (`frontend/e2e/chat-delegation.spec.ts`)

File exists. Verify sections 491-494 per ticket (15 tests). The SSE tests (494.1-494.2) will fail until the SSE endpoint is implemented — mark as `test.skip` with a TODO until then.

### 5.3 Manual verification

1. `just restart`.
2. Alice adds Bob as delegate with `chat_read` + `chat_respond`; Bob accepts invite.
3. Bob navigates to messaging, enters "Managing Alice" mode.
4. Bob sends a message to one of Alice's conversations — verify it appears with delegate tag.
5. Alice views the conversation — sees the message attributed to herself with `[via @Bob]`.
6. Alice revokes Bob. Bob's next conversation load returns 403 and exits managing mode.
7. Alice checks audit log (`/ui/delegates/audit`) — sees `chat_message_sent` entry.

### 5.4 Rollout

No feature flag exists for chat delegation. If needed, add `chat_delegation_enabled` to `app/core/settings.py` and gate the four messaging router endpoints on `S.chat_delegation_enabled`. The service functions themselves need no gating.

### 5.5 Effort estimate

- SSE endpoint + frontend hook update: **M** (2-3 days)
- Creator selector: **S** (0.5 day)
- Delegate audit view: **S** (0.5 day)
- Rate limiting: **S** (0.5 day)
- E2E fixes (SSE tests skipped until SSE ships): **S** (0.5 day)
