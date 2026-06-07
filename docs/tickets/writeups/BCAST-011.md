# BCAST-011: Broadcast "Go Private" (1-on-1 Paid Call) — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-011 bridges the live broadcast and messenger-call subsystems to allow a viewer watching a live session to escalate into a private 1-on-1 paid video call with the creator. The creator sets a minimum per-minute rate; the viewer offers a rate and maximum duration; billing is settled at session end. The public broadcast optionally pauses, ends, or continues during the private session, and resumes when the creator signals it is over.

- **Type**: Feature
- **Priority**: High
- **Status**: Implemented — all backend service code, DDB table, router endpoints, and frontend stubs are present.
- **Owning area**: `app/services/broadcast_private.py`, `app/routers/broadcast.py` (lines ~977-1240), `app/models_broadcast.py`, `app/services/broadcast_state_machine.py`
- **User personas**: Live-stream viewers (requesters), broadcasters (acceptors/decliners).
- **Cross-references**: BCAST-005 (live chat, SSE infrastructure reused), CALL-001–CALL-010 (WebRTC signaling, `MessageCallSessions` table), [[SEC-004]] (billing ledger pattern), [[SEC-025]] (broadcast session IDOR — `_require_session_owner` must also protect private-request acceptance), [[SECOPS-007]] (dev mode returns mock DDB and no AWS MediaLive calls).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/broadcast_private.py` (379 lines)

The service is fully implemented. Key functions and their line numbers:

| Function | Line | Purpose |
|---|---|---|
| `create_private_request()` | 22 | Validates rate vs. minimum, checks for existing pending session, writes `BroadcastPrivateSessions` item with `status="requested"` |
| `list_pending_requests()` | 80 | Queries `BCAST#{session_id}` SK prefix `PRIVATE#`, filters `status="requested"` |
| `get_private_session()` | 94 | Public accessor for a single private session item |
| `accept_private_request()` | 99 | Transitions request to `"accepted"`, stores `behavior`, `call_id`, `accepted_at` via `update_item` |
| `activate_private_session()` | 141 | Transitions to `"active"` when WebRTC connects; sets `started_at` |
| `end_private_session()` | 154 | Calculates billing (`ceil(duration/60) * rate`), writes debit/credit to `T.billing`, transitions to `"ended"` |
| `decline_private_request()` | 227 | Sets `status="declined"` |
| `cancel_private_request()` | 242 | Viewer-initiated cancel; checks `viewer_id` ownership before writing `status="cancelled"` |
| `get_private_status()` | 259 | Returns active/pending session summary for a broadcast |
| `_write_private_billing()` | 300 | Writes paired `LEDGER#{ts}#{id}` debit and credit entries to `T.billing`; `content_type="private_call"` (not via `TipLedgerEntry` — direct `put_item` calls, separate from the `write_tip_ledger()` path in `tip_ledger.py`) |
| `_private_session_out()` | 360 | Decimal → int coercion, output dict builder |

### 2.2 State machine — `app/services/broadcast_state_machine.py` (lines 11–22)

The `"private"` status is implemented in `_ALLOWED_TRANSITIONS`:

```python
"live":    {"stopping", "private", "error"},
"private": {"live", "stopping", "error"},
```

`BroadcastSessionStatus` in `app/models_broadcast.py` (line 8) includes `"private"` in its `Literal`. The ticket's design was fully adopted.

### 2.3 Session model — `app/models_broadcast.py` (lines 60–64)

```python
# Go-Private (BCAST-011)
private_session_id: Optional[str] = None
private_behavior: Optional[str] = None  # "pause", "end"
private_min_rate_cents: Optional[int] = None
```

These fields are present and serialized through `session_to_item()` / `session_from_item()` in `app/services/broadcast_store.py`.

### 2.4 DynamoDB table — `scripts/local-ddb-init.py` (line ~1000)

`BroadcastPrivateSessions` table is provisioned with composite PK (`pk` S) + SK (`sk` S). Table handle at `app/core/tables.py:164` (`broadcast_private_sessions: Any`) and wired at line 400 (`broadcast_private_sessions=_safe_table(S.broadcast_private_sessions_table_name)`). Setting `broadcast_private_sessions_table_name` at `app/core/settings.py:1520`.

### 2.5 Router endpoints — `app/routers/broadcast.py` (lines 977–1240)

All seven endpoints are registered:

| Endpoint | Line | Auth | Notes |
|---|---|---|---|
| `POST /sessions/{id}/private-request` | 977 | session viewer | Validates session `live`, rate ≥ min, PM exists in billing table |
| `GET /sessions/{id}/private-requests` | 1044 | session creator | Lists pending requests |
| `POST /sessions/{id}/private-requests/{req_id}/accept` | 1062 | session creator | Creates WebRTC call record; publishes SSE; transitions to `"private"` |
| `POST /sessions/{id}/private-requests/{req_id}/decline` | 1147 | session creator | |
| `POST /sessions/{id}/private-requests/{req_id}/cancel` | 1172 | requesting viewer | Ownership verified in service |
| `POST /sessions/{id}/private/{priv_id}/end` | 1196 | viewer or creator | Computes billing, clears `private_session_id` from session at line 1219 |
| `POST /sessions/{id}/resume` | ~1240 | session creator | Transitions `"private"` → `"live"`, publishes `private:broadcast_resumed` SSE |

The `accept` handler (line ~1097) calls `accept_private_request()` then writes an audit entry with `action="go_private"` and publishes `private:accepted` via `broadcast_sse_publish`. Payment method validation uses the direct billing table query pattern from `messaging.py`.

### 2.6 Frontend — exists as named files

`frontend/src/api/endpoints/broadcastPrivate.ts` — API wrappers are present. The broadcast frontend pages (`BroadcastPage.tsx`, `LivePlayer.tsx`) exist but `GoPrivateButton.tsx`, `PrivateSessionView.tsx`, `PrivateHoldingScreen.tsx`, and `PrivateRequestNotification.tsx` as named in the ticket design are not present as separate component files; the functionality is partially inlined in `LivePlayer.tsx` and `BroadcastPage.tsx`.

### 2.7 E2E tests — `frontend/e2e/broadcast-private.spec.ts`

File exists. Tests cover the full API lifecycle (request → accept → activate → end → resume) as well as decline and cancel paths.

### 2.8 Dev vs. Prod parity

All DDB operations (`T.broadcast_private_sessions`, `T.billing`) work against DDB Local in dev mode. The WebRTC call creation at accept-time calls `create_call_session()` from `app/services/messaging_call_sessions.py`, which uses `T.message_call_sessions` — this table works the same way in dev and prod. No AWS-specific APIs are used by the private session service itself. The `S.dev_mode` flag does not short-circuit any private session logic; the code path is identical in both environments.

---

## 3. Gap / Threat Analysis

### 3.1 Money path — billing gap

`_write_private_billing()` (`broadcast_private.py:300`) writes billing entries directly using `T.billing.put_item()` with `content_type="private_call"` in the `meta` dict. This bypasses `TipLedgerEntry` and `write_tip_ledger()` from `app/services/tip_ledger.py`. The ledger writes are wrapped in bare `try/except` blocks (lines ~355–375) that swallow exceptions and log a warning — a failed debit entry means the viewer is charged without a ledger record, and a failed credit means the creator is not paid. This is a money integrity gap: both writes should be atomic, or at minimum the debit failure should abort the session-end rather than silently swallowing it.

### 3.2 SEC-025 IDOR exposure

The accept/decline endpoints at lines 1062 and 1147 verify `ctx["user_sub"] == session.created_by` inline. However, the `session.created_by` check is done after `get_session()` — if an attacker can enumerate `session_id` and `request_id` values, they can call the accept endpoint against another creator's session if there is a bug in how `session` is fetched. The `_require_session_owner` helper introduced by SEC-025 should be centralized and reused here for defense-in-depth.

### 3.3 Max-duration auto-timeout

The ticket design specifies a background `asyncio` task that auto-ends private sessions past their `max_duration_minutes`. The service code at `broadcast_private.py:154–226` does billing computation but there is no background loop registered in `app/main.py` that calls an auto-timeout function. Sessions can therefore run indefinitely past the agreed maximum if neither party calls the `end` endpoint.

### 3.4 Behavior="end" not fully wired

When `behavior="end"`, the accept handler (line ~1103) transitions the broadcast session to `"private"` status and stores `private_behavior="end"`. The design calls for immediately triggering `stop_session_with_provider()` at that point to fully stop the broadcast. Inspection of the accept route shows it calls `broadcast_sse_publish` with `reason="go_private"` and an SSE event but does not call `stop_session_with_provider`. The "end" behavior is thus partially implemented — the session record changes but the MediaLive channel is not torn down.

### 3.5 Frontend component gaps

`GoPrivateButton.tsx`, `PrivateSessionView.tsx`, `PrivateHoldingScreen.tsx`, and `PrivateRequestNotification.tsx` are not present as standalone component files as specified in the ticket design. The viewer-facing UX for requesting a private session and the creator-side acceptance notification UI are not independently accessible components; they need to be split out for testability and reuse.

---

## 4. Proposed Design / Fix

### 4.1 Fix billing atomicity in `_write_private_billing()`

Replace the bare `try/except` with a transactional write or at minimum a raise-on-failure pattern:

- Change `_write_private_billing()` at `broadcast_private.py:300` to use `T.billing` `transact_write` (DDB `TransactWriteItems`) bundling both debit and credit in one atomic call.
- If the transaction fails, raise `HTTPException(500, "Billing write failed — session not ended")` so the caller knows the session-end did not complete cleanly.
- Alternatively, adopt `TipLedgerEntry` + `write_tip_ledger()` after extending `content_type` in `tip_ledger.py:50` to accept `"private_call"` (alongside the existing `"broadcast"` extension from BCAST-013). This aligns all tip/pay money paths through a single well-tested billing function (cross-ref [[SEC-004]]).

### 4.2 Add auto-timeout background task to `app/main.py`

Add a startup event handler in `app/main.py`:

```python
@app.on_event("startup")
async def start_private_session_timeout_loop():
    asyncio.create_task(_private_session_timeout_loop())
```

Implement `_private_session_timeout_loop()` (stub exists conceptually in the ticket design) in `broadcast_private.py` to scan active sessions via `T.broadcast_private_sessions.scan(FilterExpression=Attr("status").eq("active"))` and call `end_private_session()` for any where `started_at + max_duration_minutes * 60 < now_ts()`. In production, replace the scan with a GSI on `status` + `expires_at`; in dev mode, a 30-second scan loop is acceptable given small data volume.

### 4.3 Wire `behavior="end"` fully in accept handler

In `broadcast.py:accept_private_request_route()` (~line 1097), after writing the private session record, add:

```python
if body.behavior == "end":
    from app.services.broadcast_orchestrator import stop_session_with_provider
    stop_session_with_provider(session_id=session_id, actor=ctx["user_sub"], reason="go_private_end")
```

This properly stops the MediaLive channel. In dev mode, `LocalBroadcastProvider.stop()` is a no-op that updates status only — correct behavior.

### 4.4 Dev/Prod parity (SECOPS-007)

All DDB calls (`T.broadcast_private_sessions`, `T.billing`) are provider-agnostic. The WebRTC call creation is via DDB, not AWS MediaLive. The only prod-specific code path is `behavior="end"` which calls `stop_session_with_provider()` — in dev mode this calls `LocalBroadcastProvider.stop()` (a mock, see `app/services/broadcast_provider.py:57`). No new AWS-specific code paths are introduced by the fixes above.

### 4.5 Frontend components

Create the four missing standalone components as specified in the ticket:
- `frontend/src/pages/broadcast/GoPrivateButton.tsx` — viewer-facing button + `GoPrivateDialog` using `broadcastPrivate.ts` endpoints.
- `frontend/src/pages/broadcast/PrivateSessionView.tsx` — reuses WebRTC media components from messenger calls; shows billing timer.
- `frontend/src/pages/broadcast/PrivateHoldingScreen.tsx` — overlay for waiting viewers; listens for `private:broadcast_resumed` SSE.
- `frontend/src/pages/broadcast/PrivateRequestNotification.tsx` — creator-side accept/decline panel.

---

## 5. Testing, Verification & Rollout

### pytest unit tests — `tests/test_broadcast_private.py`

Concrete cases:
1. `test_create_private_request_success` — valid rate, valid PM, no existing session → `status="requested"` in DDB.
2. `test_create_private_request_rate_too_low` — rate below `min_rate_cents` → 400.
3. `test_create_private_request_duplicate` — existing `"requested"` session → 409.
4. `test_accept_sets_behavior_and_call_id` — accept with `behavior="pause"` → `status="accepted"`, `call_id` stored.
5. `test_end_billing_debit_credit_written` — end active session → two LEDGER entries in `T.billing`.
6. `test_end_billing_failure_raises` — mock DDB to throw on first `put_item` → 500 (after fix 4.1).
7. `test_auto_timeout_ends_expired_session` — mock `now_ts()` to exceed `started_at + max_duration_minutes * 60` → session ended automatically.
8. `test_cancel_wrong_viewer_rejected` — cancel with different `viewer_id` → returns `False` → 404.
9. `test_state_machine_private_transitions` — validate `live → private`, `private → live`, `private → stopping` all legal; `private → provisioning` illegal.

### Playwright E2E — `frontend/e2e/broadcast-private.spec.ts` (already exists)

Verify existing tests pass; add scenarios for:
- Behavior `"end"`: accept → confirm broadcast session transitions to `"stopped"` (not `"private"`).
- Auto-timeout (mock `max_duration_minutes=1`, wait 65 s) → session ends with `ended_by="timeout"`.
- Non-creator cannot call accept/decline endpoints (403).

### Manual QA

1. Start a live broadcast as creator.
2. As a viewer, click "Go Private", enter rate >= creator's minimum, select PM, submit.
3. Creator sees notification, accepts with `behavior="pause"` → viewer sees holding screen, private call begins.
4. After call, creator clicks "Resume" → holding screen clears.
5. Check `T.billing` for paired LEDGER entries with correct amounts.

### Observability

Add structured log fields at `end_private_session()` (`broadcast_private.py:154`): `duration_seconds`, `billed_cents`, `ended_by`. These feed into Prometheus counters for `broadcast.private.sessions.ended` with labels `behavior` and `ended_by` (cross-ref SECOPS-001).

### Rollout

- Feature flag: `BROADCAST_PRIVATE_ENABLED` in `app/core/settings.py` (not yet present; add alongside existing `broadcast_private_sessions_table_name`).
- Deploy backend changes first (table already exists in prod); frontend component split is purely additive.
- Rollback: disable feature flag → all private-request endpoints return 403.

**Effort**: S (billing atomicity + timeout loop + behavior="end" wire-up = ~1 day). Frontend component split: M (~2 days).
