# BCAST-012: Broadcast Private Chat Tiers — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-012 adds paid 1-on-1 text chat inside a live broadcast. A viewer can purchase a timed block (tier 1, participant) and type private messages directly to the creator while the public broadcast continues. Other viewers can pay a lower voyeur rate (tier 2) to read that private conversation in real time. Billing is prepaid at purchase time; chat messages are stored in the existing `BroadcastChatMessages` table with a `private_chat_id` field. All messages are SSE-published to the full session channel and filtered client-side.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Implemented — service, DDB storage pattern, router endpoints, frontend API wrappers, and E2E spec are all present.
- **Owning area**: `app/services/broadcast_private_chat.py` (681 lines), `app/routers/broadcast.py` (~1250–1460), `app/services/broadcast_chat_store.py`, `T.broadcast_private_sessions` (shared table with BCAST-011)
- **User personas**: Paying viewers (tier 1 participants, tier 2 voyeurs), broadcasters (manage concurrent private chats, set pricing).
- **Cross-references**: BCAST-005 (chat store, `BroadcastChatMessages` table reused), BCAST-011 (shares `BroadcastPrivateSessions` DDB table), [[SEC-004]] (billing ledger — debit/credit entries at purchase time), [[SEC-025]] (broadcast IDOR — creator-only endpoints must verify session ownership), [[SECOPS-007]] (dev = DDB Local, no AWS).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/broadcast_private_chat.py` (681 lines)

The service is fully implemented. Key functions:

| Function | Line | Purpose |
|---|---|---|
| `purchase_private_chat()` | ~50 | Tier 1: creates `BCAST_PCHAT#{session_id}` / `CHAT#{chat_id}` item, writes billing entries, publishes `private_chat:started` SSE. Tier 2: creates `VOYEUR#{chat_id}#{viewer_id}` item, validates target chat active, clamps expiry to parent chat expiry. |
| `send_private_chat_message()` | ~100 | Writes `kind="private_chat"` item with `private_chat_id` to `T.broadcast_chat_messages`, publishes `private_chat:message` SSE. |
| `get_private_chat_history()` | ~150 | Queries `T.broadcast_chat_messages` with `FilterExpression` on `private_chat_id` (not part of SK). Over-fetches `limit*2` to compensate for DDB filter after 1MB read. |
| `end_private_chat()` | ~200 | Updates chat to `"ended"`, calls `_end_voyeurs_for_chat()` to cascade, publishes `private_chat:ended` SSE. |
| `extend_private_chat()` | ~250 | Validates `active` or `expiring` status, extends `expires_at`, writes additional billing entries. |
| `list_active_chats()` | ~320 | Creator-facing; queries `CHAT#` SK prefix, counts voyeurs per chat, returns `remaining_seconds`. |
| `update_chat_settings()` | ~380 | PATCH on `BroadcastSessions` item directly via `update_item` (not a full put_item replace). |
| `check_and_expire_chats()` | ~430 | Stub — returns 0; background expiry logic deferred. |
| `_write_private_chat_billing()` | ~500 | Direct `T.billing.put_item()` for debit (full amount) and credit (after platform fee). |

### 2.2 DDB storage — shared `BroadcastPrivateSessions` table

Private chat items live in the same table as BCAST-011 but use a different PK prefix: `BCAST_PCHAT#{session_id}` for chat sessions and voyeur records. This avoids a separate table. The access patterns are:

- `GetItem(BCAST_PCHAT#{session_id}, CHAT#{chat_id})` — fetch single chat
- `GetItem(BCAST_PCHAT#{session_id}, VOYEUR#{chat_id}#{viewer_id})` — check voyeur access
- `Query(BCAST_PCHAT#{session_id}, begins_with("CHAT#"))` — list all chats for a session
- `Query(BCAST_PCHAT#{session_id}, begins_with("VOYEUR#{chat_id}#"))` — list voyeurs for a chat

This is sound. No GSI is needed for these patterns.

### 2.3 Chat message storage

Private chat messages are stored in `T.broadcast_chat_messages` (PK `session_id`, SK `sort_key`) with `kind="private_chat"` and `private_chat_id` set. The existing `_chat_msg_out()` at `broadcast_chat_store.py:296` does not include `private_chat_id` in its output, meaning chat history queries (`get_chat_history_route()`) currently return these private messages mixed with public messages without any scoping field in the response. Any viewer fetching chat history can see the plaintext of private chat messages if they know the session_id.

### 2.4 Session model fields — `app/models_broadcast.py` (lines 66–69)

```python
# Private Chat (BCAST-012)
private_chat_enabled: bool = False
private_chat_tiers: Optional[list] = None  # [{minutes, price_cents}, ...]
private_chat_voyeur_enabled: bool = False
private_chat_voyeur_price_cents: Optional[int] = None
```

These fields are present. However the ticket design specified `private_chat_rate_per_minute_cents` and `voyeur_rate_per_minute_cents` as per-minute rates with separate `private_chat_time_blocks` (list of allowed durations). The implementation instead uses `private_chat_tiers` (a list of `{minutes, price_cents}` blocks) and `private_chat_voyeur_price_cents` as a flat rate. The conceptual model is equivalent but the field names differ from the ticket spec — this is intentional simplification.

### 2.5 Settings — `app/core/settings.py` (lines 1528–1530)

```python
broadcast_private_chat_enabled: bool = ...
broadcast_private_chat_max_duration_minutes: int = ...
broadcast_private_chat_voyeur_enabled: bool = ...
```

### 2.6 Router endpoints — `app/routers/broadcast.py`

Endpoints registered in the section following the BCAST-011 private session endpoints:
- `POST /sessions/{id}/private-chat/purchase`
- `POST /sessions/{id}/private-chat/{chat_id}/message`
- `GET /sessions/{id}/private-chat/{chat_id}/messages`
- `POST /sessions/{id}/private-chat/{chat_id}/extend`
- `POST /sessions/{id}/private-chat/{chat_id}/end`
- `GET /sessions/{id}/private-chats` (creator list)
- `PATCH /sessions/{id}/private-chat/settings`

### 2.7 Frontend and E2E

`frontend/src/api/endpoints/broadcastPrivateChat.ts` — API wrappers present.
`frontend/e2e/broadcast-private-chat.spec.ts` — E2E spec exists.

### 2.8 Dev vs. Prod parity

All storage is via `T.broadcast_private_sessions` and `T.broadcast_chat_messages` (both DDB Local in dev, DDB in prod). No AWS-specific services used. Feature flags `broadcast_private_chat_enabled` and `broadcast_private_chat_voyeur_enabled` gate availability. In dev mode, moto is not involved here — only DDB Local.

---

## 3. Gap / Threat Analysis

### 3.1 Private message plaintext exposure in public chat history

`get_chat_history_route()` (`broadcast.py`) calls `_store_get_history()` which calls `broadcast_chat_store.get_chat_history()`. That function queries all messages for a `session_id` and returns them including `kind="private_chat"` items. The `_chat_msg_out()` serializer at line 296 does not filter by `private_chat_id`, so any authenticated viewer who calls `GET /broadcast/sessions/{id}/chat` receives all private chat messages from all active private chats in the response. The text field is plaintext — this is a confidentiality gap.

**Fix**: Either add a `FilterExpression` to `get_chat_history()` to exclude `kind="private_chat"` items by default, or add `private_chat_id` to `_chat_msg_out()` output and have the existing chat history endpoint only return items where `private_chat_id` is absent.

### 3.2 Billing atomicity (same pattern as BCAST-011)

`_write_private_chat_billing()` at `broadcast_private_chat.py:~500` uses two separate `try/except`-wrapped `T.billing.put_item()` calls. If the credit write fails after the debit succeeds, the viewer is charged but the creator is not paid. Same remediation as BCAST-011: use `TransactWriteItems` to make both writes atomic.

### 3.3 Background expiry stub

`check_and_expire_chats()` at `broadcast_private_chat.py:~430` is a stub returning 0. No background task is registered in `app/main.py`. Active chats can therefore run past their `expires_at` indefinitely. The `expiring` status transition and `private_chat:expiring` SSE event are never published. Viewers who purchased a 15-minute block get unlimited access until someone explicitly calls the end endpoint.

### 3.4 Voyeur rate validation

`purchase_private_chat()` does not enforce that the voyeur rate is lower than the tier-1 rate at purchase time — it trusts the session settings. The `update_chat_settings()` endpoint validates `voyeur_rate < participant_rate` via the `PrivateChatSettingsIn` model validator. However, if a creator sets the rates individually via two separate PATCH calls, the model validator only fires per-call. An intermediate state is possible where voyeur rate exceeds tier-1 rate.

### 3.5 `get_private_chat_history()` FilterExpression pagination

`get_private_chat_history()` at `broadcast_private_chat.py:~150` uses `Limit=limit*2` to compensate for DDB's 1MB filter behavior. If a session has a very active public chat (tens of thousands of messages), the function may return 0 results on a busy partition because the 1MB pre-filter reads only non-private messages. The CLAUDE.md "Common gotchas" section explicitly warns about this pattern. A proper fix requires either a GSI on `private_chat_id` or storing private chat messages in a separate prefix/table.

### 3.6 SEC-025 IDOR — creator ownership on chat management endpoints

The `end_private_chat` and creator-list endpoints must verify `ctx["user_sub"] == session.created_by`. The service (`end_private_chat`) does not perform this check itself — it's the router's responsibility. If the router guard is bypassed (e.g., via SEC-025's IDOR pattern), any user could end another creator's private chat sessions.

---

## 4. Proposed Design / Fix

### 4.1 Fix private message exposure in chat history

Modify `broadcast_chat_store.get_chat_history()` to accept a `viewer_user_id` and a set of `authorized_chat_ids`:

```python
# broadcast_chat_store.py — get_chat_history()
# Add FilterExpression:
filter_expr = Attr("kind").ne("private_chat") | Attr("private_chat_id").is_in(authorized_chat_ids)
```

Where `authorized_chat_ids` is resolved by the route handler by querying the private chat table for active sessions belonging to the requesting user. The simpler fix (acceptable for v1) is to always exclude `kind="private_chat"` from the public chat history: `FilterExpression=Attr("kind").ne("private_chat")`. Private chat history is already served via the dedicated `GET /sessions/{id}/private-chat/{chat_id}/messages` endpoint.

### 4.2 Fix billing atomicity

Refactor `_write_private_chat_billing()` to use `T.billing`'s `TransactWriteItems`:

```python
T.billing.meta.client.transact_write_items(TransactItems=[
    {"Put": {"TableName": T.billing.name, "Item": debit_item}},
    {"Put": {"TableName": T.billing.name, "Item": credit_item}},
])
```

Both entries are written atomically. If the transaction fails, raise `HTTPException(500, "Billing write failed")` and roll back the chat item creation.

### 4.3 Implement background expiry in `app/main.py`

Add a startup task that calls `check_and_expire_chats()` every 30 seconds. The function needs to enumerate active sessions: scan `T.broadcast_sessions` for `status="live"` sessions and for each call `list_active_chats()` to find items past `expires_at`. In production, add a GSI on `(status, expires_at)` for efficiency.

```python
async def _private_chat_expiry_loop():
    while True:
        await asyncio.sleep(30)
        from app.services.broadcast_private_chat import check_and_expire_chats
        check_and_expire_chats()
```

### 4.4 GSI for private chat message history (production)

For the `get_private_chat_history()` FilterExpression issue, add a GSI to `BroadcastChatMessages`:

```python
# scripts/local-ddb-init.py
TableDef(
    ...,
    gsis=[GSIDef("PrivateChatIndex", pk="private_chat_id", sk="sort_key")]
)
```

This allows efficient `Query(GSI, pk=private_chat_id)` without scanning the full session partition.

### 4.5 Dev/Prod parity (SECOPS-007)

No AWS-specific services are used by private chat. The feature flags `broadcast_private_chat_enabled` and `broadcast_private_chat_voyeur_enabled` can be set to `"0"` in `.env.local` to test the disabled path. The billing writes target `T.billing` which maps to DDB Local in dev and DDB in prod — identical code path.

---

## 5. Testing, Verification & Rollout

### pytest unit tests — `tests/test_broadcast_private_chat.py`

Concrete cases:
1. `test_purchase_tier1_success` — creates chat item with correct `expires_at`, writes debit+credit to `T.billing`.
2. `test_purchase_tier2_requires_active_chat` — tier 2 purchase against non-existent chat_id → 404.
3. `test_tier2_expires_not_after_parent` — voyeur `expires_at` clamped to parent chat `expires_at` even if `duration_minutes` would exceed it.
4. `test_send_message_tier2_rejected` — voyeur attempts to send message → 403 `VOYEUR_CANNOT_SEND`.
5. `test_private_messages_excluded_from_public_history` — after fix 4.1, `get_chat_history()` returns 0 `kind="private_chat"` items.
6. `test_billing_atomicity_failure_aborts` — mock second `put_item` to raise; verify first debit is not persisted (or transaction rolls back).
7. `test_extend_chat_updates_expires_at` — extend adds minutes to `expires_at`, writes additional billing entry.
8. `test_end_chat_cascades_to_voyeurs` — end primary chat → all active voyeur items transitioned to `"ended"`.

### Playwright E2E — `frontend/e2e/broadcast-private-chat.spec.ts` (exists)

Add scenarios:
- Purchase tier 1 → send messages → creator responds → verify `private_chat:message` SSE events.
- Purchase tier 2 → verify read-only access (send blocked with 403).
- Chat expiry: purchase 5-min block, mock `now_ts()` to 6 min later, call extend → verify new `expires_at`.

### Manual QA

1. Enable `private_chat_enabled` on a session.
2. As viewer, purchase 15-min tier-1 block.
3. Send messages; creator replies — verify only these two parties see the messages in the private chat panel.
4. As second viewer, purchase tier-2 for the same chat — verify they can read but not send.
5. After 15 minutes (or manually call end), verify chat ends and voyeurs are also ended.
6. Call `GET /sessions/{id}/chat` as an unauthenticated viewer — verify no `kind="private_chat"` items in response (after fix 4.1).

### Rollout

- `BROADCAST_PRIVATE_CHAT_ENABLED=1` (default) in `.env.local.example`.
- Ship billing atomicity fix (4.2) before enabling in production.
- Private message exposure fix (4.1) is a security remediation — prioritize for prod deploy before enabling voyeur mode.

**Effort**: Security fixes (4.1 billing atomicity, private message exposure): S (~1 day). Background expiry + GSI: M (~2 days).
