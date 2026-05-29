# CALL-012: Group Video Calls

**Status**: Implemented (Backend + Frontend partially wired)
**Author**: Engineering
**Date**: 2026-05-27
**Priority**: Medium
**Estimated effort**: 10-14 days

> **NOTE — Feature is PARTIALLY IMPLEMENTED.** Backend: router (`app/routers/group_calls.py`, 275 lines), service (`app/services/group_call_service.py`, 500 lines), Pydantic models (`app/models.py:3219-3310`), settings (`app/core/settings.py:1412-1417`), DDB table (`GroupCallSessions` in `scripts/local-ddb-init.py:958-968`), table handle (`app/core/tables.py:109,233`), main.py registration (`app/main.py:104,427`). Frontend: `GroupCallOverlay.tsx` (489 lines) exists but `useGroupCall.ts` hook and `ParticipantTile.tsx` do NOT. E2E tests exist (`frontend/e2e/group-calls.spec.ts`, 677 lines). Unit tests do NOT exist (`tests/test_group_calls.py` missing). The spec proposed separate `group_call_sessions.py`, `group_call_lifecycle.py`, and `sfu_signaling.py` service files — the actual implementation consolidates everything into a single `group_call_service.py`.

---

## 1. Executive Summary

The current WebRTC call system supports only 1:1 calls between two participants. The data model in `app/services/messaging_call_sessions.py` enforces this with explicit `caller_user_id` and `callee_user_id` fields, and the lifecycle state machine in `app/services/messaging_call_lifecycle.py` assumes exactly two parties at every transition.
<!-- VERIFIED: CallSessionRecord at messaging_call_sessions.py:18-48 has caller_user_id and callee_user_id (two-party only). The lifecycle at messaging_call_lifecycle.py uses create_invite():128-214, accept_invite():217-272, end_call():330-397 -- all assuming exactly two parties. --> Group conversations already exist in the messaging system -- users can create group chats with 3+ members -- but there is no way to start a voice or video call with all members.

This ticket extends the call infrastructure to support group calls with up to 8 concurrent participants. The architecture uses an SFU (Selective Forwarding Unit) model where each participant sends their media to a central server, which forwards it to all others -- this scales linearly (N connections) rather than the quadratic scaling of full mesh (N*(N-1)/2 connections). In production, the SFU is an external media server (mediasoup, Janus, or LiveKit); in dev mode, the backend acts as a signaling relay and clients establish mesh connections for small groups (3-4 participants).

The frontend adds a `GroupCallView` component with two layout modes (grid and speaker view), a participant list overlay, per-participant media controls, and dynamic layout switching as participants join and leave. The call lifecycle is managed through a new `group_call_sessions` DynamoDB table and signaled via both REST endpoints and a WebSocket channel for real-time SDP/ICE exchange.

---

## 2. Detailed Problem Analysis

### User Stories

| As a... | I want to... | So that... |
|---------|-------------|-----------|
| Group chat member | Start a video call in our group conversation | We can have a face-to-face discussion |
| Group member | Join an active group call after it starts | I can hop in late without missing the whole meeting |
| Participant | Leave a call without ending it for others | I can step away while the group continues |
| Call creator | End the call for all participants | I can close out the meeting when it is over |
| Participant | See all participants in a grid layout | I can see everyone equally |
| Participant | Switch to speaker view with the active speaker large | I can focus on who is talking |
| Participant | Toggle my microphone and camera independently | I can control my own audio/video presence |
| Participant | Share my screen with the group | I can present slides or demo something |
| Non-member | Be prevented from joining a group call | Security: only conversation members can participate |

### Pain Points

1. **No group communication**: For group projects, planning sessions, or friend groups, users must fall back to external tools (Zoom, Google Meet) because the platform only supports 1:1 calls.
2. **Full mesh does not scale**: Even if we allowed multiple 1:1 calls in a group, the client-side peer connection count would be N*(N-1)/2 = 28 for 8 participants -- far too many for mobile browsers.
3. **Signaling architecture mismatch**: The existing `CallSessionRecord` uses `caller_user_id` / `callee_user_id` fields that structurally prevent a third participant.
<!-- VERIFIED: CallSessionRecord dataclass at messaging_call_sessions.py:18-48. Fields include caller_user_id, callee_user_id, initial_mode, state, start_ts, connect_ts, end_ts, end_reason, plus CALL-011 pay-per-minute billing fields (paid, rate_cents_per_min, billing_status, etc.) and BCAST-011 broadcast_session_id. -->

### Competitive Analysis

| Platform | Max participants | SFU | Layout | Dev mode |
|----------|-----------------|-----|--------|----------|
| Zoom | 100+ | Yes | Grid, Speaker, Gallery | N/A |
| Google Meet | 100 | Yes | Auto, Tiled, Spotlight | N/A |
| Discord | 25 | Yes | Grid, Focus | Yes (free) |
| WhatsApp | 32 | Yes | Grid | N/A |
| This ticket | 8 | Yes (prod) / Mesh (dev) | Grid, Speaker | Mesh 3-4, disabled 5+ |

---

## 3. Technical Architecture

### System Diagram

```
+------------------+     +-------------------+     +------------------+
|  Participant A   |     |  Backend Server   |     |  Participant B   |
|  (Browser/App)   |     |  (FastAPI)        |     |  (Browser/App)   |
+--------+---------+     +--------+----------+     +--------+---------+
         |                        |                         |
         |--- POST /create ----->|                         |
         |<-- {call_id, state} --|                         |
         |                        |                         |
         |                        |<-- POST /join ----------|
         |                        |--- SSE: participant_joined ->|
         |<- SSE: participant_joined                        |
         |                        |                         |
  [DEV MODE: Mesh signaling]      |                         |
         |--- POST /signal ------>| (relay to B)           |
         |                        |--- POST /signal ------->|
         |<-- POST /signal -------|<--- POST /signal -------|
         |                        |                         |
  [PROD MODE: SFU signaling]     |                         |
         |--- offer to SFU ----->| (forward to SFU server) |
         |<-- answer from SFU ---|                         |
         |== media stream ======>| SFU ==> forward =======>|
         |<= media stream =======| SFU <== forward ========|
         |                        |                         |
         |                        |<-- POST /leave ---------|
         |<- SSE: participant_left                          |
         |                        |                         |
         |--- POST /end -------->|                         |
         |                        |--- SSE: call_ended ---->|
```

### Data Flow: Group Call Lifecycle

1. **Create**: User A clicks "Start Call" in group conversation header. Frontend sends `POST /ui/calls/group/create` with `conversation_id` and `mode` (audio/video). Backend creates a `group_call_sessions` DDB row with `state=created`, returns `call_id`.

2. **Join**: Participants click "Join" on the active call banner. `POST /ui/calls/group/{call_id}/join`. Backend adds a `PARTICIPANT#` row. If this is the first join, state transitions to `active`. SSE event `call:participant_joined` emitted to all conversation members.

3. **Signaling**: Each participant exchanges SDP offers/answers and ICE candidates with either the SFU (production) or directly with other participants (dev mesh mode). `POST /ui/calls/group/{call_id}/signal` routes messages. In production, a WebSocket at `/ws/calls/group/{call_id}` provides lower-latency signaling.

4. **Media flow**: In production, each participant sends their media stream to the SFU. The SFU selectively forwards streams to all other participants. In dev mode, participants establish direct WebRTC peer connections.

5. **Leave**: Participant clicks "Leave". `POST /ui/calls/group/{call_id}/leave`. Backend sets `left_at` on participant row. SSE event emitted. If the last participant leaves, call auto-ends.

6. **End**: Creator clicks "End call for all". `POST /ui/calls/group/{call_id}/end`. Backend sets `state=ended`, `end_ts`, `end_reason`. SSE event `call:ended` emitted to all.

7. **Timeline**: A system message is written to the conversation timeline (reusing existing `messaging_call_timeline.py` patterns) showing "Group call started" and "Group call ended (duration: Xm Ys)".

### Component Interactions

- **`app/services/group_call_service.py`** (implemented, 500 lines): Consolidates CRUD, lifecycle, and signaling into a single service file. Exports: `create_group_call`, `join_call`, `leave_call`, `end_call`, `get_call`, `get_active_call_for_conversation`, `list_participants`, `list_call_history`, `relay_signal`, `update_media_state`, `GroupCallError`.
<!-- NOTE: The spec proposed three separate files (group_call_sessions.py, group_call_lifecycle.py, sfu_signaling.py). The actual implementation consolidates everything into group_call_service.py. group_call_sessions.py, group_call_lifecycle.py, and sfu_signaling.py do NOT exist. -->
- **`app/routers/group_calls.py`** (implemented, 275 lines): REST endpoints. Registered in `app/main.py:104,427`. Prefix: `/ui/calls/group`.
<!-- VERIFIED: Router registration pattern in app/main.py. New routers are imported and registered via app.include_router(). See main.py for existing pattern (645 lines). -->
- **Conversation participants table**: Used to validate that only conversation members can create/join a call.
<!-- CORRECTED: The ticket says "T.participants" but participants are NOT accessed through the T dataclass. In messaging.py, participants are accessed via tbl_parts = ddb.Table(DDB_PARTICIPANTS) (messaging.py:159,222). DDB_PARTICIPANTS defaults to "Participants" (env var DDB_PARTICIPANTS). The group_calls router must use the same pattern: import ddb from app.core.aws and create a table handle via ddb.Table(os.getenv("DDB_PARTICIPANTS", "Participants")). -->
- **`app/services/messaging_call_timeline.py`** (existing): Extended to emit group call timeline events.
<!-- VERIFIED: emit_call_timeline_event() at messaging_call_timeline.py:39. Accepts call_id, conversation_id, actor_user_id, event_type, call_state, reason, extra_payload. Currently emits events for call.invite, call.accept, call.decline, call.end, call.missed (see _preview_for_event at line 21-36). Extension needed: add "group_call.start", "group_call.join", "group_call.leave", "group_call.end" event types. -->

---

## 4. Data Model Deep Dive

### DynamoDB Table: `group_call_sessions`

**Table definition for `scripts/local-ddb-init.py`:**
<!-- VERIFIED: TableDef pattern matches local-ddb-init.py:28-35. attr_types={"created_at": "N"} correct for numeric GSI sort key. Existing MessageCallSessions table at local-ddb-init.py:624-634 uses a similar structure. -->

```python
TableDef(
    os.environ.get("DDB_GROUP_CALL_SESSIONS", "GroupCallSessions"),
    "pk",
    "sk",
    gsi=[
        # GSI1: Find active/recent calls by conversation
        {"index_name": "ByConversationCreatedAt", "partition_key": "conversation_id", "sort_key": "created_at"},
        # GSI2: Find all calls by state (for cleanup jobs)
        {"index_name": "ByStateCreatedAt", "partition_key": "state", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Settings entry for `app/core/settings.py`:**
<!-- VERIFIED: All settings now exist at app/core/settings.py:1412-1417. group_call_sessions_table_name:1412, group_calls_enabled:1413, group_call_max_participants:1414, group_call_max_duration_seconds:1415, group_call_sfu_endpoint:1416, group_call_dev_mesh_max_participants:1417. Note: group_calls_enabled defaults to DEV_MODE (enabled in dev), not "false" as spec proposed. Also, group_call_sfu_api_key setting does NOT exist (spec proposed it but implementation omitted). -->

```python
group_call_sessions_table_name: str = os.environ.get("DDB_GROUP_CALL_SESSIONS", "GroupCallSessions")
group_call_max_participants: int = int(os.environ.get("GROUP_CALL_MAX_PARTICIPANTS", "8"))
group_call_max_duration_seconds: int = int(os.environ.get("GROUP_CALL_MAX_DURATION_SECONDS", "14400"))  # 4 hours
group_call_sfu_endpoint: str = os.environ.get("GROUP_CALL_SFU_ENDPOINT", "")
group_call_sfu_api_key: str = os.environ.get("GROUP_CALL_SFU_API_KEY", "")
group_call_dev_mesh_max_participants: int = int(os.environ.get("GROUP_CALL_DEV_MESH_MAX_PARTICIPANTS", "4"))
```

### Primary Access Patterns

| Access Pattern | Key Condition | Index | Notes |
|---|---|---|---|
| Get call metadata | PK=`CALL#{call_id}`, SK=`META` | Table | Single get_item |
| Get call participant | PK=`CALL#{call_id}`, SK=`PARTICIPANT#{user_id}` | Table | Single get_item |
| List all participants | PK=`CALL#{call_id}`, SK begins_with `PARTICIPANT#` | Table | Query |
| Find active call in conversation | GSI1PK=`{conversation_id}`, filter state=active | ByConversationCreatedAt | Usually 0-1 results |
| Find active calls globally | GSI2PK=`active` | ByStateCreatedAt | For cleanup/monitoring |

### Example Items

**Call metadata (META row):**

```json
{
  "pk": "CALL#gc_1a2b3c4d",
  "sk": "META",
  "call_id": "gc_1a2b3c4d",
  "conversation_id": "conv_xyz789",
  "creator_user_id": "alice-uuid",
  "state": "active",
  "mode": "video",
  "max_participants": 8,
  "current_participant_count": 3,
  "start_ts": 1748361600,
  "end_ts": 0,
  "end_reason": "",
  "sfu_session_id": "sfu_sess_abc",
  "created_at": 1748361590,
  "updated_at": 1748361650
}
```

**Participant row:**

```json
{
  "pk": "CALL#gc_1a2b3c4d",
  "sk": "PARTICIPANT#alice-uuid",
  "user_id": "alice-uuid",
  "display_name": "Alice",
  "joined_at": 1748361600,
  "left_at": 0,
  "media_status": {"audio": true, "video": true, "screen": false},
  "connection_quality": "good",
  "state": "active"
}
```

**Participant who left:**

```json
{
  "pk": "CALL#gc_1a2b3c4d",
  "sk": "PARTICIPANT#charlie-uuid",
  "user_id": "charlie-uuid",
  "display_name": "Charlie",
  "joined_at": 1748361620,
  "left_at": 1748362200,
  "media_status": {"audio": false, "video": false, "screen": false},
  "connection_quality": "good",
  "state": "left"
}
```

---

## 5. API Contract Design

### POST `/ui/calls/group/create`

**Request body:**

```json
{
  "conversation_id": "conv_xyz789",
  "mode": "video",
  "max_participants": 8
}
```

**Response 201:**

```json
{
  "call_id": "gc_1a2b3c4d",
  "conversation_id": "conv_xyz789",
  "creator_user_id": "alice-uuid",
  "state": "created",
  "mode": "video",
  "max_participants": 8,
  "current_participant_count": 0,
  "participants": []
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Conversation is not a group conversation"}` | Conversation has only 2 participants (use 1:1 call) |
| 403 | `{"detail": "Not a member of this conversation"}` | User not in participants table |
| 409 | `{"detail": "An active call already exists in this conversation"}` | Another call with state != ended exists |

### POST `/ui/calls/group/{call_id}/join`

**No request body.**

**Response 200:**

```json
{
  "call_id": "gc_1a2b3c4d",
  "state": "active",
  "mode": "video",
  "current_participant_count": 2,
  "participants": [
    {
      "user_id": "alice-uuid",
      "display_name": "Alice",
      "joined_at": 1748361600,
      "media_status": {"audio": true, "video": true, "screen": false},
      "connection_quality": "good"
    },
    {
      "user_id": "bob-uuid",
      "display_name": "Bob",
      "joined_at": 1748361650,
      "media_status": {"audio": true, "video": true, "screen": false},
      "connection_quality": "good"
    }
  ],
  "signaling": {
    "mode": "mesh",
    "ice_servers": [
      {"urls": "stun:stun.l.google.com:19302"},
      {"urls": "turn:turn.example.com:3478", "username": "user", "credential": "pass"}
    ]
  }
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 403 | `{"detail": "Not a member of this conversation"}` | Non-member |
| 404 | `{"detail": "Call not found"}` | Invalid call_id |
| 409 | `{"detail": "Call is at maximum capacity"}` | current_participant_count >= max_participants |
| 410 | `{"detail": "Call has ended"}` | state == ended |

### POST `/ui/calls/group/{call_id}/leave`

**Response 200:**

```json
{
  "ok": true,
  "call_ended": false,
  "remaining_participants": 2
}
```

If the last participant leaves, `call_ended: true` and the call state transitions to `ended`.

### POST `/ui/calls/group/{call_id}/end`

**Response 200:**

```json
{
  "ok": true,
  "call_id": "gc_1a2b3c4d",
  "duration_seconds": 600,
  "total_participants": 4
}
```

**Error:** 403 if not the creator or an admin/root user.

### GET `/ui/calls/group/{call_id}`

**Response 200:** Same schema as the create response, with full participant list.

### GET `/ui/calls/group/{call_id}/participants`

**Response 200:**

```json
{
  "participants": [
    {"user_id": "alice-uuid", "display_name": "Alice", "joined_at": 1748361600, "left_at": 0, "media_status": {"audio": true, "video": true, "screen": false}, "connection_quality": "good"},
    {"user_id": "bob-uuid", "display_name": "Bob", "joined_at": 1748361650, "left_at": 0, "media_status": {"audio": true, "video": false, "screen": false}, "connection_quality": "fair"}
  ],
  "total_active": 2,
  "total_joined": 4
}
```

### POST `/ui/calls/group/{call_id}/signal`

**Request body:**

```json
{
  "type": "offer",
  "target_user_id": "bob-uuid",
  "payload": {
    "sdp": "v=0\r\no=- ...",
    "type": "offer"
  }
}
```

**Response 200:**

```json
{
  "ok": true,
  "relayed_to": "bob-uuid"
}
```

**Error:** 403 if sender is not an active participant.

### WS `/ws/calls/group/{call_id}`

WebSocket messages follow the same schema as the signal REST endpoint. Used for lower-latency signaling in production. Falls back to REST polling in dev mode.

**WebSocket message types (JSON):**

| Type | Direction | Description |
|------|-----------|-------------|
| `signal` | Client -> Server | SDP offer/answer/ICE candidate |
| `signal` | Server -> Client | Relayed signal from another participant |
| `participant_joined` | Server -> Client | New participant notification |
| `participant_left` | Server -> Client | Participant left notification |
| `media_status_changed` | Client -> Server | Audio/video/screen toggle |
| `media_status_changed` | Server -> Client | Other participant's media update |
| `call_ended` | Server -> Client | Call terminated |
| `ping/pong` | Bidirectional | Keep-alive |

---

## 6. Frontend Component Design

### Component Tree

```
<ConversationView>
  <ConversationHeader>
    {!activeCall && <StartCallButton onClick={createCallMutation.mutate} />}
    {activeCall && <ActiveCallBanner call={activeCall} onJoin={joinCall} />}
  </ConversationHeader>

  {inCall && (
    <GroupCallOverlay>
      <GroupCallView
        callId={callId}
        participants={participants}
        layout={layout}
      >
        {layout === "grid" ? (
          <GridLayout>
            {participants.map(p => <ParticipantTile key={p.user_id} participant={p} />)}
          </GridLayout>
        ) : (
          <SpeakerLayout>
            <LargeTile participant={activeSpeaker} />
            <TileStrip>
              {otherParticipants.map(p => <SmallTile key={p.user_id} participant={p} />)}
            </TileStrip>
          </SpeakerLayout>
        )}
      </GroupCallView>

      <GroupCallControls
        onToggleMute={toggleMute}
        onToggleCamera={toggleCamera}
        onToggleScreen={toggleScreen}
        onToggleLayout={toggleLayout}
        onLeave={leaveCall}
        onEndAll={endCallForAll}
        isCreator={isCreator}
      />

      <ParticipantList
        participants={participants}
        isOpen={showParticipantList}
      />
    </GroupCallOverlay>
  )}
</ConversationView>
```

### State Management

- **`useGroupCall` hook** (`frontend/src/hooks/useGroupCall.ts`): Manages the entire call lifecycle.
  - Creates/joins call via REST API.
  - Manages `RTCPeerConnection` instances (one per remote participant in mesh mode; one to SFU in prod mode).
  - Handles `getUserMedia()` for local stream.
  - Subscribes to signaling WebSocket/REST for SDP/ICE exchange.
  - Exposes: `localStream`, `remoteStreams: Map<string, MediaStream>`, `participants`, `layout`, `callState`.
  - Cleanup: Closes all peer connections and streams on leave/end/unmount.

- **React Query keys**:
  - `["group-call", callId]`: Call metadata (polled every 5 seconds as fallback).
  - `["group-call", callId, "participants"]`: Participant list (updated via WebSocket events + query invalidation).

- **Active speaker detection**: Uses `AudioContext` + `AnalyserNode` to measure audio level of each remote stream. The participant with the highest audio level for >1 second becomes the active speaker (for speaker view layout).

### Layout Modes

1. **Grid view**: CSS Grid with responsive columns:
   - 2 participants: 1x2 (side by side)
   - 3-4 participants: 2x2
   - 5-6 participants: 2x3
   - 7-8 participants: 2x4
   - Each tile is equal size with `aspect-ratio: 16/9`.

2. **Speaker view**: Flexbox layout:
   - Large tile (80% of viewport height) showing the active speaker.
   - Bottom strip (20%) showing all other participants as small tiles.
   - Click a small tile to pin that participant as the "speaker" (overrides audio detection).

### ParticipantTile Component

Each tile shows:
- Video stream via `<video>` element (or avatar placeholder when camera is off).
- Name overlay at the bottom.
- Microphone mute indicator (top-left, red mic-off icon).
- Connection quality indicator (top-right, signal strength bars: green/yellow/red).
- Pin button on hover (locks this participant in speaker view).
- Screen share indicator (small badge if `media_status.screen === true`).

### Navigation Integration

- No new page route -- the call UI renders as a full-screen overlay within the conversation view (same pattern as existing 1:1 calls).
- A "Start Call" button (Video and Phone icons) appears in the group conversation header, replacing the 1:1 call buttons.
- When a call is active, an "Active call" banner appears at the top of the conversation with a "Join" button.

---

## 7. Security & Privacy Considerations

### Authentication & Authorization

- All REST endpoints require `require_ui_session`.
<!-- VERIFIED: require_ui_session at app/services/sessions.py:283 -->
- WebSocket connection requires a valid session cookie or a short-lived token (generated via REST, validated on WS connect).
- Participant validation: Only members of the conversation (checked via `T.participants`) can create/join the call.
<!-- CORRECTED: Participants table is NOT accessed via T.participants. It is accessed via tbl_parts = ddb.Table(DDB_PARTICIPANTS) in messaging.py:222. DDB_PARTICIPANTS = os.getenv("DDB_PARTICIPANTS", "Participants") at messaging.py:159. The group_calls router must use the same direct table access pattern. -->
- End-for-all: Only the call creator or an admin/root user can end the call for everyone.
<!-- NOTE: For admin/root authorization, use require_admin_or_root from app/auth/policy.py:67, not a non-existent require_admin_session. -->

### Input Validation

- `conversation_id`: Must exist and have 3+ members (group, not DM).
- `max_participants`: Clamped to `[2, group_call_max_participants]` (default max 8).
- `mode`: Must be `"audio"` or `"video"`.
- Signal `payload`: Size-limited to 16KB (SDP offers can be large with many media lines).
- Signal `target_user_id`: Must be an active participant (prevent signaling to non-participants).

### Media Security

- SRTP (Secure Real-time Transport Protocol) is enforced by WebRTC by default -- all media is encrypted in transit.
- TURN server credentials are short-lived tokens (5-minute TTL) generated per-call.
- SFU server access is authenticated via API key (backend <-> SFU only).
- No media recording by default (CALL-009 recording is a separate opt-in feature).

### Abuse Prevention

- Rate limit: Max 5 call creates per user per hour.
- Max duration: 4 hours per call (auto-end). Configurable via `GROUP_CALL_MAX_DURATION_SECONDS`.
- Concurrent calls: Only one active call per conversation at a time (409 on second create).
- WebSocket message rate limit: Max 50 messages per second per connection (prevents signaling flood).

---

## 8. Performance & Scalability

### Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Create call | 1 PutItem (META) | 1 WCU |
| Join call | 1 GetItem (META) + 1 PutItem (PARTICIPANT) + 1 UpdateItem (count) | 2 WCU + 1 RCU |
| Leave call | 1 UpdateItem (PARTICIPANT) + 1 UpdateItem (META count) | 2 WCU |
| Get call status | 1 Query (META + all PARTICIPANT rows) | ~1 RCU |
| End call | 1 UpdateItem (META) + N UpdateItem (PARTICIPANT left_at) | N+1 WCU |

### Bandwidth Considerations

| Mode | Per participant (up) | Per participant (down) | Total for 8 participants |
|------|---------------------|----------------------|-------------------------|
| Video 720p | ~1.5 Mbps | ~1.5 Mbps * (N-1) | ~84 Mbps total bandwidth |
| Video 360p | ~500 Kbps | ~500 Kbps * (N-1) | ~28 Mbps total bandwidth |
| Audio only | ~50 Kbps | ~50 Kbps * (N-1) | ~2.8 Mbps total bandwidth |

SFU reduces upload bandwidth to 1 stream per participant (vs. N-1 in mesh). The SFU handles the fan-out.

### Known Bottlenecks

1. **Mesh mode for 5+ participants**: In dev mode without an SFU, mesh connections become impractical at 5+ participants. The UI will show a warning and cap at `GROUP_CALL_DEV_MESH_MAX_PARTICIPANTS` (default 4).
2. **WebSocket connection management**: Each active call participant holds a WebSocket connection. For 100 concurrent group calls with 8 participants each = 800 WebSocket connections. The backend must be configured with sufficient file descriptors and async concurrency.
3. **SFU server as SPOF**: The external SFU is a single point of failure for media delivery. Mitigation: Health checks on SFU; automatic fallback to mesh for small groups if SFU is unavailable.

---

## 9. Migration & Rollback Plan

### Deployment Phases

1. **Phase 1 -- Table + settings**: Add `GroupCallSessions` table to `local-ddb-init.py`. Add settings. Add table handle. No behavioral change.
2. **Phase 2 -- Backend services**: Deploy `group_call_sessions.py`, `group_call_lifecycle.py`, `sfu_signaling.py` behind feature flag `GROUP_CALLS_ENABLED`.
3. **Phase 3 -- Router**: Deploy `group_calls.py` router. Endpoints return 404 when feature flag is off.
4. **Phase 4 -- Frontend (dev mesh mode)**: Deploy `GroupCallView`, `ParticipantTile`, etc. In dev mode, mesh signaling works without SFU.
5. **Phase 5 -- SFU integration testing**: Connect to staging SFU server. Verify SDP relay and media forwarding.
6. **Phase 6 -- Production enable**: Set `GROUP_CALLS_ENABLED=true` and configure `GROUP_CALL_SFU_ENDPOINT`.

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `GROUP_CALLS_ENABLED` | `true` (dev), `false` (prod) | Master enable/disable |
| `GROUP_CALL_MAX_PARTICIPANTS` | `8` | Max participants per call |
| `GROUP_CALL_SFU_ENDPOINT` | `""` | SFU server URL (empty = mesh/dev mode) |
| `GROUP_CALL_DEV_MESH_MAX_PARTICIPANTS` | `4` | Max participants in dev mesh mode |
| `GROUP_CALL_MAX_DURATION_SECONDS` | `14400` | Auto-end after 4 hours |

### Rollback Steps

1. Set `GROUP_CALLS_ENABLED=false`. "Start Call" button hidden in group headers. Active calls continue until they end naturally (or force-end via admin).
2. Frontend gracefully hides call UI when feature flag is off.
3. `GroupCallSessions` table can remain -- it contains no critical data and causes no harm.

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_12.py`

**Mock setup**: moto mock for DynamoDB (call session tables). Mock RTCPeerConnection for frontend unit tests. Chromium fake media devices for E2E.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_lifecycle_transitions` | Verify allowed state transitions succeed |
| `test_invalid_transition_rejected` | Invalid transition returns 409 |
| `test_authorization_check` | Non-participant returns 403 |
| `test_idempotent_operation` | Repeated call returns same result |
| `test_cleanup_on_end` | Resources cleaned up after call ends |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full call lifecycle through real DDB (invite -> accept -> connect -> end)
2. Signaling relay: offer/answer/ICE exchange between two sessions
3. State machine transitions verified end-to-end

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/call-12.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for caller; `injectAuth(page, "bob")` for callee; separate browser contexts for two-peer tests

| # | Test Name | Assertion |
|---|---|---|
| 1 | Call invite creates session | POST invite -> 200 with call_id |
| 2 | Call accept transitions state | POST accept -> state = accepted |
| 3 | Signaling relay delivers events | POST signal -> SSE event received by peer |
| 4 | Connected state shows overlay | Both peers reach connected; overlay visible |
| 5 | End call cleans up resources | POST end -> state = ended; tracks stopped |
| 6 | Call overlay shows correct UI | Ringing/connected/ended states render correctly |
| 7 | Feature flag gates functionality | Disabled flag -> call button hidden |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-participant returns 403 | Third party -> 403 |
| 10 | Non-existent call returns 404 | Invalid call_id -> 404 |
| 11 | Invalid transition returns 409 | End already-ended call -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-participant, 404 non-existent call, 409 invalid transition, 422 invalid payload

**Edge cases**: Concurrent accept/decline, call timeout (30s), ICE restart during connected state, tab backgrounding, network offline

### Test Data Requirements

Create DM conversation between Alice and Bob in `beforeAll`. Use `--use-fake-device-for-media-stream` Chromium flag for media tests.

**Test users**: Alice (USER, caller), Bob (USER, callee), Root (ROOT, admin for feature flags)

### CI/Pipeline

Serial execution (WebRTC requires sequential peer setup). `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| CALL-002 | RTCPeerConnection for mesh/SFU connections | Implemented | Yes |

### Depended On By

| Ticket | What It Needs |
|---|---|
| CALL-013 | Group call overlay for screen share integration |

### Merge Strategy

Independent. New group call system (backend + frontend). New DDB table (`GroupCallSessions`).

### Merge Checklist

- [ ] Backend endpoint/service changes registered in `app/main.py`
- [ ] Frontend hooks and components created/modified
- [ ] Settings and feature flags configured
- [ ] DDB tables added if needed (`scripts/local-ddb-init.py`)
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing call endpoints

---

## Appendix: Codebase Citations

> The ticket correctly identifies the core limitation: the 1:1 call data model structurally prevents group calls. The proposed architecture (separate table, SFU+mesh dual mode, REST signaling) is sound. Key corrections: participants table access pattern, admin auth dependency naming, service file consolidation, and implementation status updates.

| Claim / Reference | Status | Actual Location | Notes |
|---|---|---|---|
| `CallSessionRecord` has `caller_user_id` / `callee_user_id` | VERIFIED | `app/services/messaging_call_sessions.py:19-48` | Frozen dataclass; also has CALL-011 billing fields |
| Lifecycle assumes two parties | VERIFIED | `app/services/messaging_call_lifecycle.py:128-397` | `create_invite()`, `accept_invite()`, `end_call()` all two-party |
| `TERMINAL_STATES`, `ALLOWED_TRANSITIONS` | VERIFIED | `app/services/messaging_call_lifecycle.py:23-28` | State machine for 1:1 calls |
| `messaging_call_timeline.py` exists | VERIFIED | `app/services/messaging_call_timeline.py:39` | `emit_call_timeline_event()` |
| Timeline `_preview_for_event()` | VERIFIED | `messaging_call_timeline.py:21-36` | Returns human-readable strings for call events |
| `T.participants` for conversation membership | **INCORRECT** | `app/routers/messaging.py:159,222` | Uses `tbl_parts = ddb.Table(DDB_PARTICIPANTS)` directly, NOT through T dataclass |
| `DDB_PARTICIPANTS` env var | VERIFIED | `messaging.py:159` | `os.getenv("DDB_PARTICIPANTS", "Participants")` |
| MessageCallSessions table in DDB init | VERIFIED | `scripts/local-ddb-init.py:629-639` | Existing 1:1 call sessions table |
| `message_call_sessions_table_name` setting | VERIFIED | `app/core/settings.py:1141` | `os.environ.get("DDB_MESSAGE_CALL_SESSIONS", "MessageCallSessions")` |
| `require_ui_session` | VERIFIED | `app/services/sessions.py:283` | Cookie + CSRF auth |
| Router registration in main.py | VERIFIED | `app/main.py:104,427` | `group_calls_router` imported and registered |
| **Proposed settings** | **NOW EXIST** | `app/core/settings.py:1412-1417` | All 6 settings present (group_call_sfu_api_key omitted) |
| **Proposed table handle** | **NOW EXISTS** | `app/core/tables.py:109,233` | `group_call_sessions` handle wired |
| **GroupCallSessions table** | **NOW EXISTS** | `scripts/local-ddb-init.py:958-968` | PK=pk, SK=sk, 2 GSIs as proposed |
| **group_call_sessions.py service** | **DOES NOT EXIST** | N/A | Consolidated into `app/services/group_call_service.py` (500 lines) |
| **group_call_lifecycle.py service** | **DOES NOT EXIST** | N/A | Consolidated into `app/services/group_call_service.py` |
| **sfu_signaling.py service** | **DOES NOT EXIST** | N/A | Consolidated into `app/services/group_call_service.py` |
| **group_calls.py router** | **EXISTS** | `app/routers/group_calls.py` (275 lines) | Prefix `/ui/calls/group`, 11 endpoints |
| **Pydantic models** | **EXIST** | `app/models.py:3219-3310` | 12 model classes for group calls |
| **GroupCallOverlay.tsx** | **EXISTS** | `frontend/src/pages/messages/GroupCallOverlay.tsx` (489 lines) | Frontend overlay component |
| **useGroupCall.ts hook** | **DOES NOT EXIST** | N/A | Not yet implemented |
| **ParticipantTile.tsx** | **DOES NOT EXIST** | N/A | Not yet implemented as separate component |
| **E2E tests** | **EXIST** | `frontend/e2e/group-calls.spec.ts` (677 lines) | Group call E2E tests |
| **Unit tests** | **DO NOT EXIST** | N/A | `tests/test_group_calls.py` not created |
