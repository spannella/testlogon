# BCAST-005: Live Chat Overlay for Broadcast Viewers — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-005 specified a broadcast-specific chat system with ephemeral DynamoDB-backed messages, SSE fan-out via session-level partition polling, in-memory rate limiting (1 message per 2 seconds per user), broadcaster moderation (delete + mute), and a frontend panel with scrolling video overlay. The ticket was written when none of this existed. The implementation is complete: the service layer, endpoints, DDB tables, frontend components, and E2E tests are all present.

- **Type**: Feature (viewer engagement / community)
- **Priority**: High (core interactive broadcast experience)
- **Status**: Implemented — all backend, frontend, and E2E components exist
- **User persona**: Viewer (send messages, see chat), Broadcaster (moderate: delete, mute), Admin/Root (same moderation rights as broadcaster)
- **Cross-referenced tickets**: BCAST-001 (session CRUD; chat endpoints verify session status), BCAST-002 (LivePlayer page integrates chat panel + overlay), BCAST-003 (session `live` status required; `AwsBroadcastProvider.stop` triggers session cleanup), BCAST-004 (viewer count feeds rate-limit policy thinking), SEC-010 (chat stream SSE IDOR — `broadcast_chat_stream_route` at `broadcast.py:1763` lacks `check_viewer_access`; compounded by `_chat_msg_out` receiving no `viewer_user_id` argument), SEC-025 (broadcast session IDOR — broadcaster-only chat moderation routes check `session.created_by` but that ownership check is absent on the lifecycle start/stop routes)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Chat store service

`app/services/broadcast_chat_store.py`:
- `_store_send_chat(session_id, user_id, display_name, text, reply_to_message_id, expires_in_seconds, lock_price_cents, lock_description)` — constructs sort key `f"{ts_ms:016d}#{msg_id}"` and writes to `T.broadcast_chat_messages`
- `_store_fetch_after(session_id, after_sort_key, limit)` — range query `SK > after_sort_key`, `ScanIndexForward=True`, for SSE stream polling
- `_store_get_history(session_id, limit, before_sort_key)` — newest-first query (`ScanIndexForward=False`) for initial page load
- `_store_delete_chat_message(session_id, message_id)` — soft-delete via `UpdateExpression "SET deleted = :t, deleted_by = :u"`
- `_store_get_mute(session_id, user_id)` → queries `T.broadcast_chat_mutes` by PK `f"{session_id}#{user_id}"`
- `_store_set_mute(session_id, target_user_id, duration_seconds, actor)` → puts mute item

`app/services/broadcast_chat_rich.py` — rich message support (BCAST-015 extension): locked messages, expiring messages, reactions, per-viewer unlock state.

### 2.2 DynamoDB tables

Settings at `app/core/settings.py:513–514`:
```python
broadcast_chat_messages_table_name: str = os.environ.get("DDB_BROADCAST_CHAT_MESSAGES", "BroadcastChatMessages")
broadcast_chat_mutes_table_name: str = os.environ.get("DDB_BROADCAST_CHAT_MUTES", "BroadcastChatMutes")
```

Table definitions at `scripts/local-ddb-init.py:727–732`:
```python
TableDef(_resolve_table_name(S.broadcast_chat_messages_table_name, "BroadcastChatMessages"),
         "session_id", "sort_key", attr_types={"created_at": "N"})
TableDef(_resolve_table_name(S.broadcast_chat_mutes_table_name, "BroadcastChatMutes"),
         "session_user")
```

Table handles at `app/core/tables.py:153–154`: `T.broadcast_chat_messages`, `T.broadcast_chat_mutes`.

**Sort key format**: `f"{ts_ms:016d}#{msg_id}"` — zero-padded 16-digit millisecond timestamp ensures lexicographic order matches chronological order. Example: `0001716580123456#cm_abc123def456`.

**TTL**: `created_at + 7 * 24 * 3600` (7 days). Post-broadcast TTL update to `stopped_at + 86400` is not yet wired in the stop path.

### 2.3 Backend endpoints (`broadcast.py`)

**Chat send** at `broadcast.py:1548–1593`:
- Checks `session.status == "live"` → 403 if not
- Enforces broadcaster-only rules for `expires_in_seconds`/`lock_price_cents` (BCAST-015 Phase C/D)
- In-memory rate limiting via `_CHAT_RATE_LIMIT_LOCK` + `_CHAT_RATE_BUCKETS`
- Checks mute via `_store_get_mute(session_id, user_id)` → 403 with `muted_until` if active
- Resolves `display_name` from `T.profile` table
- Rate-limit setting at `app/core/settings.py:515`: `broadcast_chat_rate_limit_ms` (default 2000ms)

**Chat history** at `broadcast.py:1596–1614`: `GET /sessions/{id}/chat` — returns last `limit` messages via `_store_get_history`, `ScanIndexForward=False` + reverse.

**Chat SSE stream** at `broadcast.py:1763–1822`:
```python
@router.get("/sessions/{session_id}/chat/stream")
async def broadcast_chat_stream_route(session_id: str, after: Optional[str] = Query(default=None),
                                        poll_ms: int = Query(default=500, ge=200, le=3000),
                                        ctx: dict = Depends(_ctx)):
    _ = ctx
    session = get_session(session_id)
    if session.status not in ("live", "ready"):
        raise HTTPException(403, ...)
    # No check_viewer_access — SEC-010 gap
    async def gen():
        ...
        if msg.get("deleted"):
            yield f"event: chat:delete\ndata: {payload}\n\n"
        else:
            out = _chat_msg_out(msg)   # ← no viewer_user_id — SEC-010 bug 2
            ...
            yield f"event: {event_type}\ndata: {payload}\n\n"
```

**Chat moderation** at `broadcast.py:1617–1645`:
- `DELETE /sessions/{id}/chat/{message_id}` at line 1617 — checks `ctx["user_sub"] != session.created_by` then falls back to admin role via `_require_operator_role`
- `POST /sessions/{id}/chat/mute` at line 1631 — same ownership check pattern

**Additional rich-chat endpoints** (BCAST-015 additions): `POST /sessions/{id}/chat/{msg_id}/react`, `POST /sessions/{id}/chat/{msg_id}/unlock`, `POST /sessions/{id}/chat/product-link` at lines 1650–1762.

### 2.4 Rate limiting implementation

In-memory sliding window at `broadcast.py` (search for `_CHAT_RATE_LIMIT`):
```python
_CHAT_RATE_LOCK = threading.Lock()
_CHAT_RATE_BUCKETS: dict[str, int] = {}  # key: "{session_id}#{user_id}" -> last_send_ts_ms

def _enforce_chat_rate_limit(session_id: str, user_id: str) -> None:
    key = f"{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _CHAT_RATE_LOCK:
        last = _CHAT_RATE_BUCKETS.get(key, 0)
        if now_ms - last < S.broadcast_chat_rate_limit_ms:
            raise HTTPException(429, detail={
                "code": "BROADCAST_CHAT_RATE_LIMITED",
                "retry_after_ms": S.broadcast_chat_rate_limit_ms - (now_ms - last),
            })
        _CHAT_RATE_BUCKETS[key] = now_ms
```

`_CHAT_RATE_BUCKETS` is a module-level dict; it grows unbounded if sessions accumulate many chatters over long broadcasts. A periodic pruning step is absent.

### 2.5 Frontend components

- `frontend/src/pages/broadcast/BroadcastChat.tsx` — main chat panel; loads history on mount; uses `useBroadcastChatStream` hook for SSE; handles `chat:message` / `chat:delete` events; 280-char input with 2s cooldown button
- `frontend/src/api/endpoints/broadcast-chat.ts` — API wrappers: `sendChatMessage`, `getChatHistory`, `deleteChatMessage`, `muteChatUser`
- `LivePlayer.tsx:310`: `<BroadcastChat sessionId={sessionId} isBroadcaster={...} />` — chat panel integrated into the player
- Chat overlay: enabled via toggle in LivePlayer, CSS `@keyframes scroll-left` animation

E2E test suite:
- `frontend/e2e/broadcast-chat.spec.ts` — sections 96–99 (send/history API, moderation API, SSE stream, UI panel)
- `frontend/e2e/broadcast-chat-rich.spec.ts` — rich-message tests (BCAST-015)

### 2.6 Dev vs Prod behavior (SECOPS-007)

Chat is entirely DynamoDB + in-memory. In dev: DynamoDB Local (port 8001) stores messages; `_CHAT_RATE_BUCKETS` is per-process (single worker). In prod: DynamoDB (same table schema); `_CHAT_RATE_BUCKETS` remains in-process — if multiple uvicorn workers run, rate limits are per-worker, not global. SSE stream polling reads from the same DynamoDB partition in both modes; no provider switch needed. Session-level chat is activated purely by session status (`live`) in both environments; the `broadcast_provider` setting has no bearing on chat behavior.

---

## 3. Gap / Threat Analysis

### 3.1 SEC-010 — chat SSE stream lacks `check_viewer_access` and `viewer_user_id`

`broadcast_chat_stream_route` at `broadcast.py:1763–1822`:

**Bug 1 (IDOR)**: `ctx` is set to `_ = ctx` (discarded) after extraction at line 1771. `check_viewer_access` is never called. Any authenticated user can subscribe to the chat stream of a private or subscriber-gated broadcast session and receive all chat messages in real time. Compare: `send_chat_message_route` at line 1553 checks `session.status == "live"` but also does not call `check_viewer_access` — so a non-entitled user can both subscribe to the chat stream AND post messages to a private session's chat.

**Bug 2 (content redaction bypass)**: `_chat_msg_out(msg)` at line 1806 is called without `viewer_user_id`. The `_chat_msg_out` signature in `broadcast_chat_store.py:344` accepts `viewer_user_id: Optional[str] = None`. With `None`, locked message text is delivered in clear (lock paywall is bypassed), and expiry-hidden messages are delivered to the subscriber. This is detailed in SEC-010.

### 3.2 Chat send endpoint — no `check_viewer_access`

`send_chat_message_route` at `broadcast.py:1548` also lacks a `check_viewer_access` call. A user who is not entitled to view a private session can still POST messages to it. This is a write-path IDOR companion to the read-path IDOR in the stream.

### 3.3 `_CHAT_RATE_BUCKETS` memory leak

The `_CHAT_RATE_BUCKETS` dict at module level is never pruned. Each unique `{session_id}#{user_id}` key is retained until process restart. A long-running broadcast with many unique chatters (even bots) can grow this dict to hundreds of thousands of entries. A TTL-based cleanup or LRU eviction (e.g., `cachetools.TTLCache`) should replace the plain dict.

### 3.4 Sort key `find` N+1 for delete-by-message-id

`delete_chat_message_route` at `broadcast.py:1617` looks up the sort key for a `message_id` via `_store_find_sort_key(session_id, message_id)`. If this is implemented as a scan/query with a `FilterExpression` on `message_id` (rather than a direct key lookup), it is an O(N) scan across the entire session's chat history. For long sessions with thousands of messages, this is expensive. The `message_id` should be stored as a GSI PK in `BroadcastChatMessages` for O(1) lookup.

### 3.5 Chat TTL not set on session stop

The ticket specifies that when a broadcast stops, all chat messages should have their TTL set to `stopped_at + 86400`. The current `stop_session_route` at `broadcast.py:402` calls `stop_session_with_provider` and then conditionally calls `_promo.sync(session_id)` at line 443, but there is no chat TTL update step. Messages accumulate with their default 7-day TTL regardless of when the broadcast ends.

### 3.6 Mute duration maximum vs. broadcast duration

The mute endpoint at `broadcast.py:1631` accepts `duration_seconds` up to 86400 (24 hours). If the broadcast ends and the session transitions to `stopped`, the mute record persists in `BroadcastChatMutes` indefinitely (no TTL on mute records). A subsequent broadcast session with the same `session_id` (impossible given UUID generation) would inherit the mute, but a user banned in one session is not banned in future sessions — which is the intended behaviour. However, the mute table may accumulate stale rows over time; mute records should have TTL.

---

## 4. Proposed Design / Fix

### 4.1 SEC-010 fix — viewer access gate on chat stream and send

**Chat stream** (`broadcast.py:1763`):

```python
async def broadcast_chat_stream_route(session_id: str, ...,
                                        invite_token: Optional[str] = Query(default=None),
                                        ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    if session.status not in ("live", "ready"):
        raise HTTPException(403, ...)
    from app.services.broadcast_privacy import check_viewer_access
    check_viewer_access(session_id, ctx["user_sub"],
                        creator_id=session.created_by,
                        visibility=session.broadcast_privacy_visibility,
                        invite_token=invite_token)
    # Pass viewer_user_id for per-viewer redaction
    ...
    out = _chat_msg_out(msg, viewer_user_id=ctx["user_sub"])
```

**Chat send** (`broadcast.py:1548`): add `check_viewer_access` call after `session.status` check.

### 4.2 `_CHAT_RATE_BUCKETS` memory management

Replace the plain dict with a size-bounded TTL cache. Options:
1. `cachetools.TTLCache(maxsize=100_000, ttl=S.broadcast_chat_rate_limit_ms / 1000 + 10)` — drop-in replacement; evicts entries after the rate window expires
2. Periodic background cleanup: `asyncio.create_task` in startup that prunes `_CHAT_RATE_BUCKETS` entries older than the rate window every 60 seconds

Option 1 is simpler; add `cachetools` to `requirements.txt` or use `functools.lru_cache` with a manual TTL approach.

### 4.3 GSI for `message_id` delete lookup

Add a GSI to `BroadcastChatMessages` in `scripts/local-ddb-init.py`:
```python
TableDef(
    _resolve_table_name(S.broadcast_chat_messages_table_name, "BroadcastChatMessages"),
    "session_id", "sort_key",
    attr_types={"created_at": "N", "message_id": "S"},
    gsis=[{"name": "ByMessageId", "pk": "message_id", "sk": None}],
)
```

Then `_store_find_sort_key` uses `T.broadcast_chat_messages.query(IndexName="ByMessageId", KeyConditionExpression=Key("message_id").eq(message_id))` for O(1) lookup.

### 4.4 Chat TTL update on session stop

In `stop_session_route` at `broadcast.py:402`, after `stop_session_with_provider` succeeds, call a new service function:

```python
from app.services.broadcast_chat_store import expire_session_chat_messages
expire_session_chat_messages(session_id, stopped_at=now_ts(), grace_days=1)
```

`expire_session_chat_messages` performs a paginated query on `BroadcastChatMessages` for the session and batch-updates TTL to `stopped_at + 86400`. This is idempotent (TTL can be updated multiple times).

### 4.5 Mute record TTL

In `_store_set_mute`, add `ttl = now_ts() + duration_seconds + 60` to the DDB item so expired mute records are automatically collected.

### 4.6 Dev/Prod parity (SECOPS-007)

All fixes above are pure DynamoDB + code logic:
- `check_viewer_access` reads from `T.broadcast_allowlist` (DDB Local in dev, DDB in prod) — same call in both environments
- `_chat_msg_out(msg, viewer_user_id=...)` is pure Python
- `_CHAT_RATE_BUCKETS` TTL cache — same behaviour in single-process dev and prod
- GSI is defined in `scripts/local-ddb-init.py` (DDB Local in dev) and the DDB table definition (prod) — same schema
- Chat TTL cleanup task uses `batch_writer` on DDB Local or prod DDB — no AWS dependency

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests

**File**: `tests/test_broadcast_chat.py`

| Test | Description |
|------|-------------|
| `test_send_chat_message_stored` | POST send; `_store_get_history` returns message with correct fields |
| `test_chat_history_chronological` | Seed 5 messages; history returns oldest-first |
| `test_rate_limit_1_per_2_seconds` | Two sends within 2s; second returns 429 with `retry_after_ms` |
| `test_rate_limit_resets_after_window` | Two sends separated by > 2s; both succeed |
| `test_delete_message_by_broadcaster` | Broadcaster DELETE; `deleted=True` in DDB |
| `test_delete_by_non_owner_rejected` | Non-owner, non-admin DELETE → 403 |
| `test_mute_viewer_prevents_send` | Set mute; subsequent send returns 403 `BROADCAST_CHAT_MUTED` |
| `test_chat_stream_private_session_denied` | After fix: stream subscribe without viewer access → 403 |
| `test_chat_send_private_session_denied` | After fix: send to private session → 403 |
| `test_locked_msg_redacted_for_nonpayer` | After `viewer_user_id` fix: locked text is null for non-payer |
| `test_rate_buckets_no_memory_leak` | After fix: 10k unique keys; cache evicts old entries |
| `test_expire_session_chat_ttl` | `expire_session_chat_messages`; all messages get new TTL |

### 5.2 Playwright E2E tests

Existing `frontend/e2e/broadcast-chat.spec.ts` sections 96–99 cover the happy path. Add:

**Section 100 (access control — to add)**:
- `100.1` Non-viewer POSTs to private session chat → 403 (post-fix)
- `100.2` Non-viewer subscribes to private session chat stream → 403 (post-fix)
- `100.3` Invited viewer with `invite_token` can send and receive chat messages

**Section 101 (moderation post-fix)**:
- `101.1` Broadcaster deletes message; SSE delivers `chat:delete` event to Bob's client
- `101.2` Muted user's Send button shows remaining cooldown
- `101.3` Admin (Charlie) can delete any message in any session

Auth pattern: `injectAuth(page, "alice")` for viewer, `injectAuth(page, "root")` for broadcaster/admin. CSRF header required for POST/DELETE.

### 5.3 Manual / QA steps

1. `just restart`; Root creates + starts a session
2. Alice (viewer) opens `/live/{sessionId}`; types message; clicks Send; verify message appears in Root's broadcaster dashboard chat panel
3. Root clicks delete on Alice's message; verify Alice's client removes the message from chat (SSE `chat:delete` event)
4. Root mutes Alice for 300 seconds; Alice attempts to send → verify 403 toast in UI
5. Test overlay: Alice enables chat overlay toggle in player; Bob sends message → message appears scrolling over video

### 5.4 Observability

Add to `app/metrics.py`:
- `broadcast_chat_messages_total` (labels: `session_id_prefix` for high-cardinality protection) — counts successful sends
- `broadcast_chat_rate_limited_total` — counts 429 responses
- `broadcast_chat_moderation_actions_total` (labels: `action`: `delete`/`mute`) — counts moderation events
- `broadcast_chat_access_denied_total` (labels: `endpoint`: `send`/`stream`) — post-fix, counts IDOR-blocked attempts

Alarm: `broadcast_chat_access_denied_total > 10/min` → investigate potential abuse or misconfigured client.

### 5.5 Rollout

1. SEC-010 chat access fixes (4.1): deploy immediately; tighten access for private sessions; public session behavior unchanged
2. Rate bucket TTL cache (4.2): deploy; backward-compatible
3. GSI for message_id delete (4.3): requires table migration in prod (add GSI to existing table via `update_table`); run as a separate deployment step; include DDB migration script
4. Chat TTL on stop (4.4): deploy alongside or after 4.3; idempotent
5. Mute TTL (4.5): deploy independently; new mute records get TTL; old ones persist until natural DDB expiry cleanup

### 5.6 Effort estimate

- SEC-010 chat stream + send fix: **S** (2 hours including unit tests)
- Rate bucket memory fix: **XS** (1 hour)
- GSI for delete lookup: **S** (2 hours: schema + migration + test)
- Chat TTL on stop: **S** (1 hour)
- Mute TTL: **XS** (30 minutes)
- E2E section 100–101: **S** (2 hours)
