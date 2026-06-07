# BCAST-016: Broadcast Multiple Video Inputs / Co-Streaming — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-016 extends the broadcast system from single-RTMP-input to multi-input co-streaming. Up to 8 RTMP_PUSH inputs can be attached to a single MediaLive channel. Guests join via a one-time invite link with a per-invite RTMP URL and stream key, or via a browser-based WebRTC-to-RTMP relay. The broadcaster switches between four layout presets (single, side-by-side, PiP, grid) in real time. Input and guest state is stored in a new `BroadcastInputs` DynamoDB table. In dev mode all provisioning is mocked; in production, AWS MediaLive `BatchUpdateSchedule` drives input switching.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Implemented — `app/services/broadcast_multi_input.py` (171 lines, dev-mode mock), `app/services/broadcast_input_store.py` (379 lines), `app/services/broadcast_layout.py` (128 lines), `app/services/broadcast_webrtc_relay.py` (exists), `app/routers/broadcast.py` (lines ~3656–3950), frontend components (`InputManager.tsx`, `LayoutSwitcher.tsx`, `GuestInviteDialog.tsx`), `frontend/src/api/endpoints/broadcast-inputs.ts`, E2E spec `frontend/e2e/broadcast-multi-input.spec.ts`.
- **Owning area**: `app/services/broadcast_multi_input.py`, `app/services/broadcast_input_store.py`, `app/services/broadcast_layout.py`, `app/routers/broadcast.py`.
- **User personas**: Broadcasters (add inputs, manage guest invites, switch layouts), guests (receive invite link, push RTMP or join via browser).
- **Cross-references**: BCAST-003 (AWS MediaLive provisioning, `provision_mediolive_input_and_channel()` in `broadcast_mediolive.py`), CALL-002 (WebRTC TURN/ICE infrastructure reused for browser guest relay), [[SEC-025]] (broadcast IDOR — input/guest management endpoints must verify session ownership), [[SECOPS-007]] (dev mode = `_is_dev()` returns mock results; prod = real AWS MediaLive API calls).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Multi-input provisioning — `app/services/broadcast_multi_input.py` (171 lines)

```python
def _is_dev() -> bool:
    return bool(S.dev_mode)
```

All functions check `_is_dev()` and return mock data in dev mode, bypassing boto3 calls entirely:

| Function | Line | Purpose |
|---|---|---|
| `create_additional_input()` | 42 | Dev: returns `InputProvisionResult` with mock `input_id`, mock ARN, mock `rtmp://localhost:1935/live/...` URL. Prod: creates an RTMP_PUSH MediaLive input via boto3, returns real ARN and ingest URL. |
| `attach_input_to_channel()` | ~80 | Dev: no-op (mock). Prod: calls MediaLive `BatchUpdateSchedule` with `InputSwitchScheduleActionSettings` to add the input to the channel's schedule. |
| `detach_input_from_channel()` | ~110 | Dev: no-op. Prod: removes input attachment. |
| `delete_medialive_input()` | ~140 | Dev: no-op. Prod: calls `delete_input()` on MediaLive. |

The `InputProvisionResult` dataclass at line ~20 has four fields: `input_id`, `input_arn`, `ingest_url`, `stream_key` (one-time value, not persisted).

### 2.2 Input store — `app/services/broadcast_input_store.py` (379 lines)

Stores `BroadcastInputModel` items in `T.broadcast_inputs` (DDB table `BroadcastInputs`). PK: `SESSION#{session_id}`, SK: `INPUT#{input_id}`.

| Function | Line | Purpose |
|---|---|---|
| `create_input()` | 42 | Writes input item; `input_type` in `{primary, guest, screen}`; `is_live=False` initially. |
| `get_input()` | 83 | GetItem by PK/SK. |
| `list_inputs()` | 93 | Query all `INPUT#` SK items for a session. |
| `update_input()` | 102 | Partial update via re-fetch + put_item. |
| `delete_input()` | 119 | DeleteItem. |
| `mark_input_live()` | 129 | Atomic `SET is_live = :bool`. |
| `count_inputs()` | 140 | Query with `Select="COUNT"`. |
| `delete_all_inputs()` | 148 | Batch delete for session cleanup. |
| `create_guest_invite()` | 186 | Writes `INVITE#{invite_id}` SK item with `expires_at = now_ts() + invite_ttl_seconds` (default 24 hours). `stream_key` is a one-time random hex stored on the invite, not the DDB item — it is only returned in the API response and not persisted after creation. |
| `get_guest_invite()` | 224 | GetItem. |
| `list_guest_invites()` | 234 | Query all `INVITE#` SK items with optional status filter. |
| `accept_guest_invite()` | 244 | Validates invite is `pending` and not expired; updates to `accepted`; creates an input record for the guest. |
| `revoke_guest_invite()` | 269 | Updates invite to `revoked`. |
| `expire_pending_invites()` | 273 | Scans `pending` invites past `expires_at`, transitions to `expired`. |
| `save_layout()` | 341 | Writes `LAYOUT#current` SK item with layout config (positions, mode, input_ids). |
| `get_layout()` | 356 | GetItem. Returns `None` if not set. |

### 2.3 Layout engine — `app/services/broadcast_layout.py` (128 lines)

`switch_layout()` at line 77 validates session `status in ("live", "private")`, validates `mode` against `VALID_LAYOUTS = {"single", "side_by_side", "pip", "grid"}`, resolves `input_ids` from `list_inputs()` if not provided, calls the appropriate layout function, persists via `save_layout()`, updates session fields `active_layout`, `active_input_ids`, `primary_input_id` via `update_session_fields()`.

Layout functions:
- `_layout_single()` (line 19): full screen with primary input.
- `_layout_side_by_side()` (line 24): two inputs, 50/50 split.
- `_layout_pip()` (line 34): primary 100%, secondary 28×28% at bottom-right (z_index=1).
- `_layout_grid()` (line 45): up to 4 inputs in a 2×2 grid; 1 input = full screen; 2 inputs = 1×2; 3–4 inputs = 2×2.

### 2.4 Session model extensions — `app/models_broadcast.py`

The following fields are present on `BroadcastSessionModel` (after the tip fields at line 76):

```python
# Multi-input / Co-streaming (BCAST-016)
max_inputs: int = Field(default=4, ge=1, le=8)
active_layout: Optional[str] = None
active_input_ids: Optional[list] = None
primary_input_id: Optional[str] = None
guest_invite_enabled: bool = False
```

`BroadcastLayoutConfig` and `LayoutPosition` dataclasses are defined in `app/models_broadcast.py`.

### 2.5 DynamoDB table — `BroadcastInputs`

Registered in `scripts/local-ddb-init.py` (line ~973), handle at `app/core/tables.py:166` (`broadcast_inputs: Any`), wired at line 402, setting `broadcast_inputs_table_name` at `settings.py:1533`.

The table uses a single-table pattern with PK `SESSION#{session_id}` and SK prefix `INPUT#`, `INVITE#`, or `LAYOUT#`. No GSIs needed — all queries are by session.

### 2.6 Router endpoints — `app/routers/broadcast.py` (lines ~3656–3950)

All endpoints are gated by `_ensure_multi_input_enabled()` which checks `S.broadcast_multi_input_enabled` (setting at `settings.py:1537`).

| Endpoint | Line | Auth | Notes |
|---|---|---|---|
| `POST /sessions/{id}/inputs` | ~3682 | Session creator | Validates `count_inputs < session.max_inputs`; calls `create_additional_input()` then `create_input()`. |
| `GET /sessions/{id}/inputs` | ~3739 | Authenticated | Lists all inputs for session. |
| `DELETE /sessions/{id}/inputs/{input_id}` | ~3758 | Session creator | Detaches + deletes input. |
| `POST /sessions/{id}/layout` | ~3765 | Session creator | Calls `switch_layout()`; publishes `layout:switched` SSE event. |
| `GET /sessions/{id}/layout` | ~3786 | Authenticated | Returns current layout from `get_layout()`. |
| `POST /sessions/{id}/inputs/{input_id}/mute` | ~3803 | Session creator | Updates `is_muted` flag on input. |
| `POST /sessions/{id}/inputs/{input_id}/promote` | ~3823 | Session creator | Sets input as `primary_input_id` on session. |
| `POST /sessions/{id}/guest-invites` | ~3841 | Session creator | Creates invite + provisions input; returns `invite_url`, `ingest_url`, `stream_key` (one-time). |
| `GET /sessions/{id}/guest-invites` | ~3909 | Session creator | Lists all invites. |
| `POST /sessions/{id}/guest-invites/{id}/revoke` | ~3930 | Session creator | Revokes invite. |
| `POST /sessions/{id}/guest-invites/accept/{token}` | ~3950 | Unauthenticated (invite token) | Guest accepts invite, input becomes active. |

### 2.7 Frontend components

- `InputManager.tsx` — panel showing all active inputs with live/offline status, mute toggle, remove button.
- `LayoutSwitcher.tsx` — preset layout selector with visual preview icons for each mode.
- `GuestInviteDialog.tsx` — dialog to create/copy invite link; shows `ingest_url` and `stream_key` for OBS guests.
- `frontend/src/pages/broadcast/BroadcastPage.tsx` — existing page; the multi-input UI is integrated via these components.

### 2.8 WebRTC relay — `app/services/broadcast_webrtc_relay.py`

File exists. Provides browser-guest-to-RTMP relay logic: accepts WebRTC offer from guest browser, sends ICE candidates, relays media via FFmpeg process (or mock in dev) to an RTMP input URL. In dev mode returns a mock relay session. In prod, spawns an FFmpeg subprocess or delegates to a relay microservice.

### 2.9 Dev vs. Prod parity (SECOPS-007)

`broadcast_multi_input.py` explicitly gates all AWS MediaLive calls behind `_is_dev()`. In dev mode:
- `create_additional_input()` returns a mock `InputProvisionResult` with `rtmp://localhost:1935/live/...` URL — the local RTMP ingest is not actually running, but the DDB records are created correctly.
- `attach_input_to_channel()` and `detach_input_from_channel()` are no-ops.
- `delete_medialive_input()` is a no-op.

All DDB operations (`broadcast_input_store.py`) are identical between dev and prod. The SSE events (`input:connected`, `input:disconnected`, `layout:switched`) work the same way through `broadcast_sse_publish()`.

The `guest-invites/accept/{token}` endpoint is unauthenticated — the token must be validated against the DDB invite record. This endpoint works identically in dev (DDB Local) and prod (DDB).

---

## 3. Gap / Threat Analysis

### 3.1 Stream key one-time value not persisted — replay impossible after loss

In `create_guest_invite()` at `broadcast_input_store.py:186`, the `stream_key` is generated as `secrets.token_hex(32)` and included in the API response but explicitly **not** stored in DDB:

```
# stream_key is one-time only — not stored after response
```

If the broadcaster loses the invite response, they cannot retrieve the stream key. They must revoke the invite and create a new one. This is the correct security posture (keys should not be recoverable) but it means the frontend must prompt the user to copy the key immediately, and the API response must be clearly marked as one-time.

### 3.2 `accept_guest_invite()` does not validate `expires_at`

`accept_guest_invite()` at `broadcast_input_store.py:244` checks `invite.status == "pending"` but does not check `invite.expires_at >= now_ts()`. An expired invite in `pending` status can still be accepted. The `expire_pending_invites()` function at line 273 is a cleanup sweep that runs (if registered) to mark expired invites, but if the sweep hasn't run, a guest with an expired invite URL can still accept it.

**Fix**: Add `if now_ts() > invite.expires_at: raise HTTPException(410, "Invite has expired")` at the start of `accept_guest_invite()`.

### 3.3 Unauthenticated invite accept endpoint — abuse vector

`POST /sessions/{id}/guest-invites/accept/{token}` is unauthenticated. An attacker who obtains or brute-forces a token can accept a guest invite and gain RTMP push access to a live broadcast. The `stream_key` is 32 random bytes (hex) — 256 bits of entropy — making brute force computationally infeasible. However, if the invite URL is leaked (e.g., via browser history, shoulder surfing, or link-sharing), any party can accept the invite.

**Mitigation** (not a fix, just noting): The `accept` endpoint should log the accepting IP address for audit. Revoke is always available to the broadcaster. For additional protection, require the accepting party to authenticate before accepting (change from unauthenticated to `require_ui_session`), but this may be intentionally left unauthenticated to allow guest access without platform accounts.

### 3.4 Layout `side_by_side` and `pip` enforce minimum 2 inputs but don't handle mid-stream input loss

`switch_layout()` validates `len(input_ids) >= 2` for `side_by_side` and `pip`. However, if a layout is already set to `side_by_side` with 2 inputs and one input disconnects mid-stream, there is no automatic fallback to `single`. The `input:disconnected` SSE event is published (by `mark_input_live(session_id, input_id, is_live=False)`) but no server-side layout fallback is triggered. The broadcaster must manually switch layouts.

**Fix for production**: Add a background handler that listens for `input:disconnected` events and calls `switch_layout(mode="single", primary_input_id=remaining_input_id)` if the active layout requires inputs that are now offline. In dev mode, inputs never truly disconnect, so this is prod-only behavior.

### 3.5 `broadcast_webrtc_relay.py` dev/prod divergence

In dev mode, the WebRTC relay returns a mock session without actually relaying media. E2E tests cannot test the WebRTC path. This is acceptable for the API-level tests but the browser-guest UX (clicking "Join" in `GuestStreamPanel`) cannot be exercised end-to-end without real WebRTC infrastructure.

### 3.6 SEC-025 IDOR on guest-invite management

The guest-invite management endpoints (`revoke`, `list`) and input management endpoints (`mute`, `promote`, `delete`) must verify `ctx["user_sub"] == session.created_by`. The router inline checks (`session = get_session(); if ctx["user_sub"] != session.created_by`) follow the pattern established by other broadcast endpoints. However, the SEC-025 writeup identifies that these ownership checks are not centralized — they should use the `_require_session_owner(ctx, session)` helper once that helper is implemented per SEC-025.

---

## 4. Proposed Design / Fix

### 4.1 Fix expired invite not checked in `accept_guest_invite()`

In `broadcast_input_store.py:accept_guest_invite()`, add immediately after the status check:

```python
if now_ts() > int(invite.expires_at):
    raise HTTPException(status_code=410, detail={"code": "INVITE_EXPIRED", "message": "This invite link has expired."})
```

This is a one-line fix with no schema changes.

### 4.2 Auto-fallback layout on input disconnect

In `broadcast_multi_input.py`, add a function called by the input status update:

```python
def handle_input_disconnected(session_id: str, input_id: str) -> None:
    """If the active layout requires the disconnected input, fall back to single."""
    from app.services.broadcast_layout import switch_layout
    from app.services.broadcast_store import get_session
    session = get_session(session_id)
    if session.active_layout in ("side_by_side", "pip", "grid"):
        active_ids = session.active_input_ids or []
        if input_id in active_ids and not _is_dev():
            remaining = [i for i in active_ids if i != input_id]
            if remaining:
                switch_layout(
                    session_id=session_id,
                    mode="single",
                    primary_input_id=remaining[0],
                    input_ids=remaining,
                )
```

Call `handle_input_disconnected()` from the input status webhook handler or SSE event processing.

### 4.3 Add invite expiry to `accept_guest_invite()` in prod SSE webhook

When a production MediaLive input signals a connection (via a CloudWatch event or webhook), `mark_input_live()` is called. The inverse (input disconnect) should also call `handle_input_disconnected()`. Wire this up in `app/main.py` or the relevant webhook handler.

### 4.4 Dev/Prod parity gap documentation (SECOPS-007)

The explicit dev/prod split in `broadcast_multi_input.py` is correct but the mock values (`rtmp://localhost:1935/live/...`) should be configurable via `S.broadcast_rtmp_mock_base_url` to allow testing with a local RTMP server (e.g., `nginx-rtmp`) without hardcoding `localhost`. Add:

```python
broadcast_rtmp_mock_base_url: str = os.environ.get("BROADCAST_RTMP_MOCK_BASE_URL", "rtmp://localhost:1935/live")
```

### 4.5 Input count enforcement with conditional DDB write

The add-input endpoint checks `count_inputs(session_id) < session.max_inputs` before creating. This is a read-then-write pattern subject to a race: two concurrent add-input requests both pass the check and both create inputs, exceeding `max_inputs`. Add a conditional write to `create_input()`:

```python
T.broadcast_inputs.put_item(
    Item=item,
    ConditionExpression=Attr("input_id").not_exists(),
)
```

And check input count with a consistent read or use a DDB counter with conditional increment (similar to the lottery max_entries fix in BCAST-014).

---

## 5. Testing, Verification & Rollout

### pytest unit tests — `tests/test_broadcast_multi_input.py`

Concrete cases:
1. `test_add_input_creates_ddb_item` — `create_input()` → item in `T.broadcast_inputs` with correct `input_type`, `is_live=False`.
2. `test_add_input_above_max_rejected` — `count_inputs()` at `max_inputs` → 409.
3. `test_layout_switch_single` — one input, switch to `"single"` → `positions=[{x:0, y:0, width:1, height:1}]`.
4. `test_layout_switch_side_by_side_requires_2_inputs` — one input → 400.
5. `test_layout_pip_primary_promoted` — switch to `"pip"` with `primary_input_id=X` → X at full screen, other input at PiP position.
6. `test_guest_invite_created_stream_key_not_in_ddb` — create invite → invite item in DDB; no `stream_key` attribute in DDB item.
7. `test_expired_invite_cannot_be_accepted` — create invite, mock `now_ts()` past `expires_at` → `accept_guest_invite()` raises 410 (after fix 4.1).
8. `test_accept_pending_invite_creates_input` — accept valid invite → input item created with `input_type="guest"`.
9. `test_revoke_invite_blocks_accept` — revoke → `accept_guest_invite()` returns 409.
10. `test_mark_input_live_updates_flag` — `mark_input_live(is_live=True)` → item `is_live=True`; `mark_input_live(is_live=False)` → `is_live=False`.

### Playwright E2E — `frontend/e2e/broadcast-multi-input.spec.ts` (exists)

Add scenarios:
- Add input: broadcaster adds second input → input appears in `InputManager` with `is_live=false`.
- Layout switch: broadcaster switches to `side_by_side` with 2 inputs → SSE `layout:switched` event received.
- Guest invite: broadcaster creates invite → `invite_url` returned → guest accepts (simulated API call) → input appears as `is_live=true` for broadcaster.
- Revoke: broadcaster revokes invite → subsequent accept attempt returns 409.

### Manual QA

1. Start a live broadcast.
2. Broadcaster calls `POST /sessions/{id}/inputs` — verify DDB item created, mock RTMP URL returned in dev.
3. Broadcaster calls `POST /sessions/{id}/layout` with `mode="side_by_side"` and two input IDs — verify `layout:switched` SSE event and DDB `LAYOUT#current` item updated.
4. Broadcaster creates guest invite — verify `stream_key` in response, not in DDB.
5. Guest calls `POST /sessions/{id}/guest-invites/accept/{token}` — verify input item created with `input_type="guest"`.
6. Broadcaster revokes invite — verify subsequent accept returns 409.

### Rollout

- `BROADCAST_MULTI_INPUT_ENABLED=1` (default) for dev and staging.
- In production, start with `max_inputs=2` (override via `S.broadcast_max_inputs_default`) for initial rollout; scale to 8 after stability validation.
- Layout auto-fallback (fix 4.2) is production-critical; deploy before enabling multi-input in prod.
- Expired-invite fix (4.1) is a one-line change; include in next patch.

**Effort**: Expired invite fix: XS (<1 hour). Auto-fallback layout: S (~4 hours). Production MediaLive wiring (attach/detach real API calls): M (~3 days with AWS integration testing). WebRTC relay end-to-end integration: L (~5 days).
