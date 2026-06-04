# CALL-012: Group Video Calls — Investigation & Implementation Write-up

## 1. Summary & Classification

Group video calls extend the platform's existing 1:1 WebRTC call infrastructure to support up to 8 concurrent participants within a group conversation. The structural constraint today is that `CallSessionRecord` (`app/services/messaging_call_sessions.py:18-48`) carries exactly two participant fields — `caller_user_id` and `callee_user_id` — making a third participant architecturally impossible in the existing schema. The feature introduces a parallel, purpose-built subsystem: a new DynamoDB table, a new service module, a new router, and a dedicated frontend overlay.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Partially implemented — backend and E2E spec are complete; frontend hook and participant tile are missing.
- **Area**: Messaging / WebRTC
- **User persona**: Group chat members who want video/audio calls without leaving the platform.
- **Dependencies**: CALL-002 (RTCPeerConnection), depended upon by CALL-013 (screen share overlay).

## 2. Current-State Investigation (what exists today)

### 2.1 The 1:1 structural barrier

`CallSessionRecord` (a frozen dataclass at `app/services/messaging_call_sessions.py:18-48`) has `caller_user_id: str` (line 22) and `callee_user_id: str` (line 23) as explicit two-party fields. The lifecycle functions `create_invite` (line 132), `accept_invite` (line 217), and `end_call` (line 330) in `app/services/messaging_call_lifecycle.py` all operate on exactly two participants. The state machine constants `TERMINAL_STATES` and `ALLOWED_TRANSITIONS` at lines 23-28 of that file have no concept of a participant count. This is the root cause — a structural, not configural, limitation.

Group conversations already exist (3+ members) in the messaging system, but attempting to call any of them using the existing endpoint would result in exactly two participants in a `CallSessionRecord` with the rest silently excluded.

### 2.2 New backend subsystem (implemented)

The following exist and are complete:

| File | Lines | Role |
|---|---|---|
| `app/services/group_call_service.py` | 500 | All business logic: create/join/leave/end/signal/media |
| `app/routers/group_calls.py` | 275 | REST endpoints, prefix `/ui/calls/group` |
| `app/models.py:3219-3310` | 92 | 12 Pydantic model classes |
| `app/core/settings.py:1412-1417` | 6 | Feature flags and limits |
| `scripts/local-ddb-init.py:958-968` | ~10 | `GroupCallSessions` table definition |
| `app/core/tables.py:109,233` | — | `group_call_sessions` table handle |
| `app/main.py:104,427` | — | Router registered as `group_calls_router` |

The router exposes 11 endpoints via `_get_user` (line 53 of `group_calls.py`), which extracts `user_id` and `role` from the session. `create_group_call` in the service (line 74) enforces the feature flag at line 84: `if not S.group_calls_enabled: raise GroupCallError(403, ...)`.

**SFU/mesh mode selection** is encoded in `_signaling_info()` at `group_calls.py:115-120`: it returns `mode="sfu"` if `S.group_call_sfu_endpoint` is non-empty, otherwise `mode="mesh"`. This is the dev/prod branch — in dev, `S.group_call_sfu_endpoint` is `""` (the default), so mesh mode is returned. In production, setting `GROUP_CALL_SFU_ENDPOINT` switches to SFU mode without any code change.

The service uses a single-table design in `GroupCallSessions`:
- `PK=CALL#{call_id}, SK=META` — call metadata
- `PK=CALL#{call_id}, SK=PART#{user_id}` — per-participant row

Participant membership is validated via `_get_conversation_participant_ids(conversation_id)` at service line 49, which queries the `Participants` table directly using `ddb.Table(os.getenv("DDB_PARTICIPANTS", "Participants"))` — correctly replicating the pattern from `app/routers/messaging.py:159,222` rather than using a non-existent `T.participants` accessor.

### 2.3 Frontend: overlay exists, hook is missing

| File | Status | Notes |
|---|---|---|
| `frontend/src/pages/messages/GroupCallOverlay.tsx` | EXISTS (489 lines) | Renders grid/speaker layouts, controls, participant state |
| `frontend/src/hooks/useGroupCall.ts` | **MISSING** | `useGroupCall` hook that manages RTCPeerConnection lifecycle |
| `frontend/src/pages/messages/ParticipantTile.tsx` | **MISSING** | Per-participant video tile (logic is inline in GroupCallOverlay) |
| `frontend/e2e/group-calls.spec.ts` | EXISTS (677 lines) | Full E2E suite |

`GroupCallOverlay.tsx` manages local media state at line 185-189 and polls call data at lines 192-196 with `refetchInterval: 3000`. It references `toggleScreenShare` (line 243) which depends on `useScreenShare` (CALL-013). Screen share button exists at line 396-401, and simultaneous share prevention comes from `_check_screen_share_conflict` at `group_call_service.py:357-391`. The media mutation at lines 227-233 calls `updateGroupCallMedia`, which maps to `PATCH /{call_id}/media` at `group_calls.py:255-275`.

The critical gap: `GroupCallOverlay` imports from `useGroupCall` which does not exist. Without the hook, the overlay cannot:
- Acquire `getUserMedia()` for the local stream
- Create `RTCPeerConnection` instances per remote participant (mesh mode)
- Exchange SDP offers/answers via the `/signal` endpoint
- Manage `track.onended` and peer connection cleanup on leave/end

### 2.4 Dev vs. production today

In dev (`DEV_MODE=1`, `GROUP_CALL_SFU_ENDPOINT=""`):
- `S.group_calls_enabled` defaults to `True` (it reads `DEV_MODE`): `settings.py:1858`
- Signaling mode is `"mesh"` — clients form direct RTCPeerConnections with each other
- DynamoDB Local on port 8001 stores all call state
- TURN credentials endpoint returns a stub (no real TURN server needed for localhost)
- `GROUP_CALL_DEV_MESH_MAX_PARTICIPANTS` defaults to 4 — UI warns and blocks 5+ in mesh mode

In production:
- `GROUP_CALLS_ENABLED=true` plus `GROUP_CALL_SFU_ENDPOINT=<url>` switches to SFU mode
- The service's `relay_signal` function (line 417) routes SDP payloads to the SFU endpoint instead of peer-to-peer
- No code path difference — the same `relay_signal` function is used; the SFU endpoint string presence is the only switch

## 3. Gap / Threat Analysis

### 3.1 Missing implementation pieces

1. **`useGroupCall.ts` hook** — This is the single most important missing piece. The overlay UI exists but without the hook, the entire WebRTC media layer is absent. Required: `getUserMedia()` call, `RTCPeerConnection` per remote participant (mesh) or one to SFU, SDP offer/answer via `/signal`, ICE candidate handling, `track.onended` for remote streams, cleanup on leave/end/unmount.

2. **`ParticipantTile.tsx`** — The overlay renders participant tiles inline; factoring them out improves testability and separation, but the inline implementation in GroupCallOverlay partially covers this.

3. **`tests/test_group_calls.py`** — No unit tests. The service functions (`create_group_call`, `join_call`, `leave_call`, `end_call`, `relay_signal`, `update_media_state`) are completely untested by pytest. E2E tests at `group-calls.spec.ts` cover API paths but not edge cases like concurrent joins or the 8-participant cap.

4. **Timeline integration** — `_emit_timeline` at `group_call_service.py:451` calls into `messaging_call_timeline.py` but the `_preview_for_event` function at `messaging_call_timeline.py:21-36` only handles 1:1 event types. Group call timeline entries would fall through to the generic `f"Call event: {call_state}"` fallback.

5. **Feature flag not checked in router** — `group_calls.py` does not call `_check_enabled()` before endpoints. The check is in the service (`group_call_service.py:84`), which means a `403 GroupCallError` is raised rather than a clean `404` HTTP response when the flag is off.

### 3.2 Security / abuse considerations

- Non-conversation-members cannot join (enforced at `group_call_service.py:95-100` for create and `join_call:172-180` for join).
- Only the creator or an admin/root user can `end_call` for all (enforced at `group_call_service.py:280-307`). Admin detection uses `role: str = "USER"` parameter — the endpoint at `group_calls.py:177` passes `user["role"]`.
- Signal relay validates both sender and target are active participants before relaying (`relay_signal:430-443`). Signal `payload` is validated as a JSON-serializable object, and signal type must be in the allowed set: `"offer"`, `"answer"`, `"ice_candidate"` — the router validates this in `GroupCallSignalIn`.
- Concurrent call creation guard: `get_active_call_for_conversation` at line 132 + 409 response at line 103 prevents duplicate active calls.
- Max participants: `max_participants` is clamped at service line 90: `max_participants = max(2, min(max_participants, cap))` where `cap = S.group_call_max_participants` (default 8). A client cannot bypass the cap by sending a larger value.
- Max duration: `S.group_call_max_duration_seconds` (default 14400 = 4 hours). The `_end_call_internal` function is called by an auto-expiry mechanism when this limit is exceeded — this background check must be wired into the scheduler (currently not confirmed as registered in `app/main.py`).
- TURN credential exposure: In dev mode, `_signaling_info()` returns only a public STUN server. In production with an SFU, the SFU endpoint is server-side only — clients never receive the SFU API key. Short-lived TURN credentials (per-call TTL) must be generated server-side and included in the join response's `ice_servers` list.
- Mesh mode in dev is capped at 4 participants via `S.group_call_dev_mesh_max_participants`.

## 4. Proposed Design / Fix

### 4.1 `useGroupCall.ts` hook

Create `frontend/src/hooks/useGroupCall.ts`. The hook takes `{ callId, callData, userId, mode, enabled }` and returns `{ localStream, remoteStreams: Map<string, MediaStream>, connectionStates, leaveCall, endCall, toggleMute, toggleCamera }`.

Internal structure:
1. Acquire local media via `acquireLocalMedia(mode)` from `frontend/src/lib/webrtc.ts:15`.
2. For each remote participant, create an `RTCPeerConnection` (from `frontend/src/lib/webrtc.ts`).
3. Exchange SDP via `POST /ui/calls/group/{callId}/signal` — use caller/callee role assignment to avoid duplicate offer generation (participant with lower `user_id` lexicographically sends the offer first).
4. Store `pcRefs: Map<string, RTCPeerConnection>` and `streamRefs: Map<string, MediaStream>`.
5. Subscribe to call state changes: poll `["group-call", callId]` at 5-second interval as fallback, plus WebSocket events when SSE `call:participant_joined` / `call:participant_left` events arrive.
6. On leave/end/unmount: stop all local tracks, close all peer connections.

**Dev/prod parity**: No SFU SDK dependency in the hook. In mesh mode (`signaling.mode === "mesh"`), the hook manages direct RTCPeerConnections. In SFU mode (`signaling.mode === "sfu"`), it manages a single RTCPeerConnection to the SFU endpoint using the `signaling.sfu_endpoint` URL returned by `/join`. The same hook handles both — mode is driven by the join response, not a compile-time flag.

### 4.2 `ParticipantTile.tsx` extraction

Extract the inline tile rendering from `GroupCallOverlay.tsx` into `frontend/src/pages/messages/ParticipantTile.tsx`. Props: `{ participant: GroupCallParticipant, stream: MediaStream | null, isSelf: boolean, isPinned: boolean, onPin: () => void }`. This enables isolated unit testing of the tile component.

### 4.3 Unit tests (`tests/test_group_calls.py`)

Use `moto` for DynamoDB. Patch `_get_conversation_participant_ids` to return a fixed set of 3 user IDs. Test:
- `create_group_call`: happy path, feature-flag disabled (403), non-member (403), duplicate active call (409), non-group conversation (400).
- `join_call`: happy path, call at max capacity (409), call already ended (410).
- `leave_call`: last participant auto-ends call.
- `end_call`: creator ends for all, non-creator rejected (403).
- `relay_signal`: valid relay, sender not active participant (403), target not active participant (403).
- `update_media_state`: screen share conflict prevention via `_check_screen_share_conflict`.

### 4.4 Timeline preview strings

Add group call event types to `messaging_call_timeline.py:_preview_for_event`:
```python
if event_type == "group_call.start":
    return "Started a group call"
if event_type == "group_call.join":
    return "Joined the group call"
if event_type == "group_call.end":
    return f"Group call ended ({reason})" if reason else "Group call ended"
```

### 4.5 Router feature flag guard

Add a `_check_enabled()` function to `group_calls.py` mirroring the pattern in `collaborations.py:88-93`:
```python
def _check_enabled():
    if not S.group_calls_enabled:
        raise HTTPException(status_code=404, detail="Group calls are not enabled")
```
Call it at the top of each endpoint handler.

### 4.6 Dev/prod parity for SFU credentials

Short-lived TURN credentials should be generated per-join. In dev, return a static stub `{"urls": "stun:stun.l.google.com:19302"}`. In prod, call the TURN credential API (e.g., Twilio NTS or coturn REST API) based on `S.group_call_sfu_endpoint` being set. The same `_signaling_info()` function in `group_calls.py:115` should include TURN credentials in prod but skip them in dev — gated by `if S.group_call_sfu_endpoint`.

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests

New file: `tests/test_group_calls.py`. All tests use moto `@mock_aws` decorator + `create_table(...)` for `GroupCallSessions`. Patch `_get_conversation_participant_ids` with `monkeypatch.setattr`. Run with: `.venv/bin/pytest tests/test_group_calls.py -v`. No AWS or real DDB required.

### 5.2 Playwright E2E

`frontend/e2e/group-calls.spec.ts` (677 lines) already exists. Tests require `--use-fake-device-for-media-stream` Chromium flag (already set in `playwright.config.ts`). Tests cover: create call, join, leave, end, signal relay, screen share state, media toggle, layout switching, feature flag gate (disabled flag → call button hidden).

Run: `cd frontend && npx playwright test e2e/group-calls.spec.ts`.

### 5.3 Manual verification steps

1. `just restart` — clean state, re-seed E2E sessions.
2. Open Alice (`/messages`) and Bob and Charlie in separate browser tabs with `injectAuth`.
3. Navigate to a 3-person group conversation.
4. Click "Start Call" — verify `POST /ui/calls/group/create` 201, overlay appears.
5. Bob joins via "Join" banner — verify `current_participant_count` becomes 2.
6. Charlie joins — verify grid layout shows 3 tiles.
7. Charlie leaves — verify `remaining_participants: 2` in leave response.
8. Alice ends for all — verify `state=ended`, all overlays close.
9. Verify `GET /ui/calls/group/history/{conversation_id}` returns the completed call with `end_reason` and `duration_seconds`.
10. Attempt to rejoin ended call — verify `410 Call has ended`.
11. With feature flag off (`GROUP_CALLS_ENABLED=0`): verify create returns 403, "Start Call" button is hidden.
12. Attempt to join as a non-member (different user) — verify 403.
13. Create a second group call in the same conversation before the first ends — verify 409.
14. Test audio-only mode: click "Start Audio Call" — verify local video track is null, only audio track is acquired by `useGroupCall`.
15. In a 4-person mesh call: toggle Alice's camera off via `PATCH /{call_id}/media` with `{video: false}` — verify other participants' tiles show Alice's avatar placeholder within 3 seconds (next poll cycle).

### 5.4 Metrics to add

Add Prometheus counters in `group_call_service.py` (following the pattern in `app/metrics.py`):
- `group_call_created_total{mode}` — incremented in `create_group_call`
- `group_call_participants_total` — incremented in `join_call`
- `group_call_duration_seconds` histogram — recorded in `_end_call_internal` using `(end_ts - start_ts)`

### 5.5 Rollout plan

1. **Phase 1** (already done): DDB table, settings, service, router, models, E2E spec.
2. **Phase 2** (next): Implement `useGroupCall.ts` hook with mesh signaling.
3. **Phase 3**: Extract `ParticipantTile.tsx`, add unit tests.
4. **Phase 4**: Wire `GroupCallOverlay` into `ConversationView` header (add "Start Call" button for group conversations, replacing 1:1 call buttons for groups ≥ 3).
5. **Phase 5** (prod): Set `GROUP_CALL_SFU_ENDPOINT` + test SFU SDP relay.
6. **Phase 6**: Enable `GROUP_CALLS_ENABLED=true` in production deployment.

**Rollback**: Set `GROUP_CALLS_ENABLED=false`. The router guard in the service returns 403 immediately. "Start Call" button in group headers must be conditionally hidden on the frontend based on the feature flag (exposed via `GET /ui/config` or similar).

**Effort**: Implementing `useGroupCall.ts` is M (3-5 days). Unit tests are S (1 day). Full mesh mode E2E pass is S (1 day). SFU integration is L (5-7 days, requires staging SFU server).
