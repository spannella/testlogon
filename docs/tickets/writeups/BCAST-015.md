# BCAST-015: Rich Messaging Features in Broadcast Chat — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-015 brings five "phases" of rich messaging to broadcast chat: (A) emoji reactions, (B) quoted replies, (C) expiring messages, (D) locked/tipped messages with per-message paywalls, and (E) view-once messages. These mirror features from the main messenger (`app/routers/messaging.py`) but are adapted for the high-throughput, ephemeral, public broadcast chat context. Phase F (encryption) is scoped to future BCAST-012 private tiers only.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Implemented — `app/services/broadcast_chat_rich.py` (315 lines), two new router endpoints (`react`, `unlock`), extended `BroadcastChatSendIn` and `BroadcastChatMessageOut` models in `app/routers/broadcast.py`, extended `_store_send_chat()` to pass rich fields to `broadcast_chat_store.py`, E2E spec `frontend/e2e/broadcast-chat-rich.spec.ts`, frontend components `ChatReactionBar.tsx`, `ChatReplyQuote.tsx`, `ChatLockedCard.tsx`.
- **Owning area**: `app/services/broadcast_chat_rich.py`, `app/routers/broadcast.py` (~lines 1460–1690), `app/services/broadcast_chat_store.py`.
- **User personas**: All viewers (reactions, replies, read locked messages after paying), broadcasters (send expiring messages, locked messages, view-once; receive tips; react to messages).
- **Cross-references**: BCAST-005 (underlying chat store, SSE delivery), [[SEC-004]] (billing ledger for locked message unlocks — `_write_chat_billing()` in `broadcast_chat_rich.py`), [[SEC-025]] (broadcast IDOR), [[SECOPS-007]] (dev = DDB Local; prod = same code path; no new AWS services).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/broadcast_chat_rich.py` (315 lines)

| Function | Line | Purpose |
|---|---|---|
| `_enforce_rate_limit()` | 39 | Generic rate limiter shared by reactions, unlocks, and tips; accepts bucket dict, lock, key, limit_ms, error code, message. |
| `react_to_chat_message()` | 65 | Validates emoji against `ALLOWED_REACTIONS` set (👍 ❤️ 😂 🔥 😮 👏); enforces 500ms reaction rate limit; resolves sort key via `_find_sort_key()`; uses `ADD reactions.#emoji :user_id_set` DDB expression for atomic add; creates `reactions` map if it doesn't exist (two-step fallback); publishes `chat:reaction` SSE with updated counts. |
| `unlock_chat_message()` | 150 | Validates message has `lock_price_cents`; checks not already unlocked via `unlocked_by` DDB map; validates PM from billing table; writes billing debit/credit; atomically adds `user_id` to `unlocked_by` map and increments `tip_total_cents` with conditional write; publishes `chat:unlock` SSE. |
| `_find_sort_key()` | 229 | Scans `BroadcastChatMessages` for item with `message_id == target` by doing a forward query — O(n) in the worst case since `message_id` is not the sort key. |
| `_build_reaction_counts()` | 235 | Converts `reactions` DDB map (emoji → string set of user_ids) to `{emoji: count}` dict. |
| `_write_chat_billing()` | 247 | Writes debit + credit `LEDGER#` entries to `T.billing` (direct `put_item`, separate `try/except` blocks — same atomicity gap as BCAST-011/012/014). |
| `reset_rich_rate_limits()` | 308 | Clears rate limit state for tests. |

### 2.2 Extended send model — `app/routers/broadcast.py` (lines ~1464–1478)

`BroadcastChatSendIn` now includes:

```python
reply_to_message_id: Optional[str] = Field(default=None, max_length=128)     # Phase B
expires_in_seconds: Optional[int] = Field(default=None, ge=10, le=86400)      # Phase C
lock_price_cents: Optional[int] = Field(default=None, ge=1, le=100_000)       # Phase D
lock_description: Optional[str] = Field(default=None, max_length=200)         # Phase D
```

View-once (Phase E) and tip attached to message (Phase D) are accepted via the dedicated tip endpoint (BCAST-013) rather than the base send endpoint.

### 2.3 Extended output model — `app/routers/broadcast.py` (lines ~1507–1531)

`BroadcastChatMessageOut` now includes all rich fields:

```python
tip_amount_cents: Optional[int] = None          # BCAST-013
tip_currency: Optional[str] = None              # BCAST-013
tip_payment_id: Optional[str] = None            # BCAST-013
reactions_counts: Optional[dict] = None         # Phase A
my_reactions: Optional[list] = None             # Phase A
reply_to_message_id: Optional[str] = None       # Phase B
reply_to_preview: Optional[dict] = None         # Phase B
expires_at: Optional[int] = None                # Phase C
expired: bool = False                           # Phase C
lock_price_cents: Optional[int] = None          # Phase D
lock_description: Optional[str] = None          # Phase D
is_unlocked: Optional[bool] = None              # Phase D
tip_total_cents: Optional[int] = None           # Phase D (total unlock tips)
lottery_id: Optional[str] = None               # BCAST-014
```

`text` is now `Optional[str] = None` to accommodate locked messages where text is null until unlocked.

### 2.4 Send route changes — `app/routers/broadcast.py` (lines ~1565–1600)

`send_chat_message_route()` enforces broadcaster-only for phases C and D:

```python
if body.expires_in_seconds is not None or body.lock_price_cents is not None:
    if user_id != session.created_by:
        raise HTTPException(403, {"code": "NOT_BROADCASTER", "message": "Only the broadcaster can send special messages"})
```

Reply-to (Phase B) is available to all participants.

### 2.5 Chat store extensions — `app/services/broadcast_chat_store.py`

`send_chat_message()` (line 136) now passes `reply_to_message_id`, `expires_in_seconds`, `lock_price_cents`, `lock_description` to the DDB item. The `_store_send_chat()` wrapper in `broadcast.py` passes these fields through.

`_chat_msg_out()` at line 296 now includes `reactions_counts` (computed via `_build_reaction_counts(item.get("reactions", {}))`), `reply_to_message_id`, `reply_to_preview`, `expires_at`, `expired` (computed as `expires_at < now_ts()` if set), `lock_price_cents`, `lock_description`, `is_unlocked` (computed by checking `unlocked_by` map for the requesting viewer's `user_sub`), `tip_total_cents`, `lottery_id`.

The `_store_get_history()` wrapper passes `viewer_user_id` to `_chat_msg_out()` so `is_unlocked` can be personalized.

### 2.6 New router endpoints — `app/routers/broadcast.py` (lines ~1650–1710)

- `POST /sessions/{id}/chat/{message_id}/react` — any authenticated viewer; calls `react_to_chat_message()`.
- `POST /sessions/{id}/chat/{message_id}/unlock` — any authenticated viewer with a PM; calls `unlock_chat_message()`.

Both endpoints call `get_session(session_id)` for 404 protection but do not check `status == "live"` — reactions and unlocks work on messages even after a session ends (post-session chat archive access).

### 2.7 SSE events

New event types published by the rich chat service:
- `chat:reaction` — `{message_id, emoji, action, user_id, counts}` — published by `react_to_chat_message()`.
- `chat:unlock` — `{message_id, user_id, tip_total_cents}` — published by `unlock_chat_message()`.

### 2.8 Frontend components

- `ChatReactionBar.tsx` — emoji picker + reaction counts display below each chat message.
- `ChatReplyQuote.tsx` — quoted reply preview above message text.
- `ChatLockedCard.tsx` — "Locked · $X.00" badge with unlock button.

### 2.9 Dev vs. Prod parity (SECOPS-007)

All DDB operations use `T.broadcast_chat_messages` and `T.billing` — DDB Local in dev, DDB in prod. The `reactions` attribute is a DDB Set type (created by boto3 with `boto3.dynamodb.types.TypeSerializer`) — behavior is identical between DDB Local and DDB in prod. No new AWS services introduced. The `_find_sort_key()` scan is an internal DDB query — no diff between environments.

---

## 3. Gap / Threat Analysis

### 3.1 `_find_sort_key()` is O(n) and unsafe for high-volume sessions

`_find_sort_key()` at `broadcast_chat_rich.py:229` works by querying `T.broadcast_chat_messages` with `KeyConditionExpression(PK=session_id)` and scanning forward until it finds an item with `message_id == target`. In a busy session with 100,000 messages, this requires scanning up to 100,000 DDB items to find one. This will cause O(n) DDB read costs and unacceptable latency for reactions on older messages.

**Fix**: Require the caller to pass `sort_key` alongside `message_id` (the frontend has both from the chat history response). Alternatively, store a `GSI2PK = message_id` on each chat item and add a `MessageIdIndex` GSI to `BroadcastChatMessages` for O(1) lookup.

### 3.2 Reaction map initialization race (two-step write)

`react_to_chat_message()` at line 65 has a two-step fallback for the reactions map: first try `ADD reactions.#emoji :set`, and if that fails, first `SET reactions = :empty` then `ADD`. Between the two calls, a concurrent reaction from a different user could either succeed (if the first ADD happened to work) or create a duplicate initialization. The DDB `ADD` expression on a nested map path does not auto-create the map — this is a documented DDB limitation. A safer approach is to use a single `update_item` with `UpdateExpression = "SET reactions.#e = if_not_exists(reactions.#e, :empty_set) ADD reactions.#e :u"`. However, DDB does not allow mixing `SET` and `ADD` on the same path in one expression. The cleanest solution is to always store `reactions` as a map initialized at message creation time and rely on `ADD` only.

### 3.3 Billing atomicity — `_write_chat_billing()` (same pattern as 011/012/014)

`_write_chat_billing()` at `broadcast_chat_rich.py:247` uses two separate `try/except`-wrapped `put_item()` calls. Same money-path gap: failed credit after successful debit = viewer charged, broadcaster not paid.

### 3.4 Expired message content still returned in some code paths

When `_chat_msg_out()` computes `expired = expires_at < now_ts()`, the current implementation sets `expired=True` but still returns the `text` field. If a locked message has `expires_at` set, after expiry neither the locked check nor the expiry check currently nulls out the text. The design intent is that expired message text should be replaced with `"[This message has expired]"`. This needs to be enforced in `_chat_msg_out()`:

```python
if item.get("expires_at") and int(item["expires_at"]) < now_ts():
    out["text"] = None  # or "[This message has expired]"
    out["expired"] = True
```

### 3.5 View-once (Phase E) — not visible in schema

`BroadcastChatSendIn` does not have a `view_once` field, and `_chat_msg_out()` does not expose `view_once` or `view_once_seen`. The chat store `send_chat_message()` function does not write a `view_once` attribute. Phase E is listed in the ticket design but appears not to be implemented in the current code (only phases A, B, C, D are present).

### 3.6 `is_unlocked` requires `viewer_user_id` in all history calls

`_store_get_history()` accepts and passes `viewer_user_id`. The SSE stream path (chat messages polled from DDB and returned as SSE events) goes through `_store_fetch_after()` which calls `_chat_msg_out()` without a `viewer_user_id`. This means SSE-delivered locked messages always have `is_unlocked=None` regardless of whether the viewer has unlocked the message. A viewer who unlocks a locked message via the REST endpoint will see the text immediately via the REST response, but if another SSE poll delivers the same message, it shows `is_unlocked=None` again.

---

## 4. Proposed Design / Fix

### 4.1 Fix `_find_sort_key()` with GSI or caller-supplied key

**Option A (preferred)**: Add a `MessageIdIndex` GSI to `BroadcastChatMessages`:
```python
# scripts/local-ddb-init.py
GSIDef("MessageIdIndex", pk="message_id", sk="session_id", attr_types={"message_id": "S"})
```
Replace `_find_sort_key()` with a single `Query(GSI=MessageIdIndex, pk=message_id, limit=1)` call.

**Option B**: Change the reaction and unlock endpoints to accept `sort_key` as a query parameter or in the request body. The frontend already has `sort_key` from the chat history response.

### 4.2 Fix reactions map initialization

Change `react_to_chat_message()` to write the `reactions` map at message creation time (in `send_chat_message()`, always include `"reactions": {}`). Then the `ADD reactions.#emoji :set` call is always safe because the map exists.

### 4.3 Fix billing atomicity in `_write_chat_billing()`

Same `TransactWriteItems` pattern as BCAST-011/012/014. This is the fourth occurrence of the same gap — consolidate into a shared `write_billing_pair()` utility in `app/services/billing_utils.py` that all four broadcast billing functions call. The utility wraps `T.billing.meta.client.transact_write_items()`.

### 4.4 Fix expired text not nulled

In `broadcast_chat_store.py`, in `_chat_msg_out()`, add after the existing `expires_at` block:

```python
if out.get("expires_at") and int(out["expires_at"]) <= now_ts():
    out["text"] = None
    out["expired"] = True
```

This must also null out `lock_description` and the `lock_price_cents` (arguably these can remain for display).

### 4.5 Implement Phase E (view-once)

Add `view_once: Optional[bool]` to `BroadcastChatSendIn`. In `send_chat_message()`, store `view_once=True` on the DDB item. In `_chat_msg_out()`, if `view_once=True` and `viewer_user_id in item.get("view_once_seen", set())`, return `text=None` with a `view_once_consumed=True` flag. Add a `POST /sessions/{id}/chat/{message_id}/view` endpoint that calls `update_item(ADD view_once_seen :user_set)`.

### 4.6 Dev/Prod parity (SECOPS-007)

No AWS-specific services involved. GSI addition (fix 4.1 option A) requires adding `attr_types` in `scripts/local-ddb-init.py`. The `TransactWriteItems` call in fix 4.3 is supported by DDB Local v2.x.

---

## 5. Testing, Verification & Rollout

### pytest unit tests — `tests/test_broadcast_chat_rich.py`

Concrete cases:
1. `test_react_add_creates_reactions_map` — first reaction on a message with no `reactions` attribute → item has `reactions={emoji: {user_id}}`.
2. `test_react_remove_decrements_count` — add then remove → count is 0 (or key absent).
3. `test_react_rate_limit` — two reactions within 500ms → second returns 429.
4. `test_react_disallowed_emoji` — emoji not in `ALLOWED_REACTIONS` → 400.
5. `test_unlock_writes_billing_pair` — unlock → debit for viewer, credit for broadcaster; item `unlocked_by` map includes viewer.
6. `test_unlock_idempotent` — unlock twice → second returns 200 without re-charging (already in `unlocked_by`).
7. `test_expired_message_text_nulled` — message with `expires_at` in the past → `text=None` in `_chat_msg_out()` (after fix 4.4).
8. `test_locked_message_text_hidden_before_unlock` — viewer calls history; locked message → `text=None`, `lock_price_cents` set.
9. `test_locked_message_text_shown_after_unlock` — viewer unlocks → subsequent history call returns `text`, `is_unlocked=True`.
10. `test_reply_preview_included` — message with `reply_to_message_id` → `reply_to_preview` contains `sender_display_name` and truncated `text`.

### Playwright E2E — `frontend/e2e/broadcast-chat-rich.spec.ts` (exists)

Add scenarios:
- Reaction flow: viewer reacts 👍 → `chat:reaction` SSE → `ChatReactionBar` shows count=1.
- Locked message: broadcaster sends locked message ($1) → other viewer sees "Locked · $1.00" badge → clicks unlock with PM → sees text.
- Reply: viewer replies to a message → `reply_to_preview` shows quoted text above message.
- Expiry: broadcaster sends `expires_in_seconds=15` message → after 15 seconds, message shows "[This message has expired]".

### Manual QA

1. Start a live broadcast.
2. Broadcaster sends locked message with `lock_price_cents=100`.
3. Viewer calls `GET /sessions/{id}/chat` — verify `text=null`, `lock_price_cents=100` in response.
4. Viewer calls `POST /sessions/{id}/chat/{msg_id}/unlock` with PM — verify `is_unlocked=true` in response and `chat:unlock` SSE event.
5. Viewer reacts with 👍 — verify `chat:reaction` SSE with `counts={👍: 1}`.
6. Broadcaster sends `expires_in_seconds=10` message — verify after 10 seconds the text is null in chat history.

### Rollout

- Phases A and B (reactions and replies) are viewer-side only — additive, no billing.
- Phases C and D (expiry and locking) are broadcaster-only and involve billing — require billing atomicity fix (4.3) before enabling in prod.
- Fix 4.1 (`_find_sort_key` O(n)) is a critical performance fix — deploy before production traffic reaches a session with > 5,000 messages.

**Effort**: Billing atomicity (shared utility): S (~2 hours). `_find_sort_key` GSI: S (~2 hours). Phase E view-once: M (~1 day). SSE `is_unlocked` context (fix 4.6): S (~1 day).
