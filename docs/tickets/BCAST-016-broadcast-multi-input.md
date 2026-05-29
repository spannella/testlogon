# BCAST-016: Broadcast Multiple Video Inputs / Co-Streaming

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: Medium  
**Estimated effort**: 12-16 days  
**Dependencies**: BCAST-001, BCAST-003, CALL-002

---

## 1. Overview & Motivation

### 1.1 The Gap

The broadcast system provisions exactly one RTMP_PUSH input per session. In `app/services/broadcast_mediolive.py` (line 81), `provision_mediolive_input_and_channel()` creates a single input named `broadcast-{session_id}-input` and a single channel with one `InputAttachment`:
<!-- VERIFIED: app/services/broadcast_mediolive.py:81, input name at :88, channel at :89 -->

```python
InputAttachments=[{"InputId": input_id, "InputAttachmentName": f"{session_id}-input-attach"}],
```
<!-- VERIFIED: app/services/broadcast_mediolive.py:127 -->

The `MediaLiveProvisionResult` dataclass (line 33) returns a single `input_arn`, `channel_arn`, `channel_id`, `state_snapshot`, and `archive_prefix`. There is no concept of multiple inputs, no mechanism for guest co-streamers, no input switching or layout composition, and no way to combine multiple camera angles into a single broadcast output.
<!-- VERIFIED: app/services/broadcast_mediolive.py:33-39 -->

The `BroadcastSessionModel` in `app/models_broadcast.py` (line 37) stores a single `ingest_url` and `stream_key_ref`. There are no fields for multiple inputs, active layout mode, or guest management. The `BroadcastPage.tsx` frontend shows a single RTMP URL with no multi-source UI.
<!-- VERIFIED: app/models_broadcast.py:37, ingest_url at :41, stream_key_ref at :42 -->

This means:

1. A broadcaster cannot invite a guest to co-stream -- there is no second ingest point.
2. A broadcaster cannot switch between multiple camera angles during a live session.
3. There is no picture-in-picture, side-by-side, or grid layout composition.
4. Screen sharing requires the broadcaster to mux via external OBS scene switching.
5. Collaborative broadcasts (interviews, panels, gaming) require external tools (StreamYard, Discord), losing platform-native monetization and chat integration.

### 1.2 Why This Is Needed

1. **Creator collaboration**: Multi-person broadcasts are the fastest-growing format. Without co-streaming, creators must use external tools and lose platform monetization.
2. **Production value**: Input switching and layout composition (PiP, side-by-side, grid) enable professional broadcasts without third-party software -- table-stakes for competing with YouTube Live and Twitch.
3. **Guest accessibility**: Requiring guests to install OBS is a high barrier. A browser-based guest path (WebRTC-to-RTMP bridge using CALL-002 infrastructure) lets guests join from any browser.
4. **Monetization surface**: Co-streaming enables paid guest slots, multi-creator subscription bundling, and per-input tip targeting.

### 1.3 User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| US-1 | Broadcaster | add up to 4 RTMP inputs to a single broadcast session | I can push multiple camera angles from my OBS setup or hardware encoders |
| US-2 | Broadcaster | invite a guest to co-stream via a shareable invite link | I can host interviews, panels, and collaborative content without external tools |
| US-3 | Broadcaster | switch between single, side-by-side, PiP, and grid layout modes while live | I can produce professional multi-cam broadcasts without switching away from the platform |
| US-4 | Broadcaster | see a real-time status indicator for each input (live/offline/connecting) | I know which cameras are active before switching the on-screen layout |
| US-5 | Guest (browser) | join a broadcast via a browser link without installing streaming software | I can participate in co-streams from any device with a webcam |
| US-6 | Guest (OBS) | receive an RTMP URL and one-time stream key to push from my encoder | I can co-stream at higher quality using my own production setup |
| US-7 | Broadcaster | mute, remove, or promote a guest in real time | I maintain full control over the broadcast composition and audio mix |
| US-8 | Broadcaster | see all pending and accepted guest invites with revoke capability | I can manage who has access to my broadcast inputs |
| US-9 | Viewer | see a smooth transition when the broadcaster switches layouts | I get a seamless viewing experience without dropped frames or black screens |
| US-10 | Broadcaster | add a "screen share" input alongside my camera input | I can demonstrate software, show slides, or share gameplay without stopping the camera feed |
| US-11 | Broadcaster | have the primary input automatically fill the screen if all guests disconnect | the broadcast continues uninterrupted even if guests have connectivity issues |
| US-12 | Platform Admin | configure the maximum number of inputs per session via an environment variable | I can control infrastructure costs and scaling per deployment |

### 1.4 Scope

**In scope:**
- Multi-input provisioning (up to 8, default 4) with per-input RTMP ingest URLs
- Guest invite system with one-time stream keys and expiring invite links
- Four layout modes: single, side_by_side, pip, grid
- Real-time input connection/disconnection tracking via SSE
- Layout switching during live sessions via MediaLive ScheduleAction
- Browser-based guest connectivity via WebRTC-to-RTMP relay (dev mode mock)
- Guest management: mute, remove, promote
- DynamoDB storage for input records and guest invites
- Frontend: InputManager panel, LayoutSwitcher, GuestInviteDialog, GuestStreamPanel
- E2E tests for all API and UI paths

**Non-goals (explicitly out of scope):**
- Audio mixing/ducking between inputs (MediaLive does not support per-input volume control; this requires a custom audio processor upstream)
- Custom layout coordinates via drag-and-drop (use preset templates only for v1)
- Per-input recording isolation (the channel records the composed output; per-input recording requires separate MediaLive channels)
- Multi-region input failover (all inputs must be in the same region as the channel)
- Paid guest slots / monetization of guest positions (deferred to BCAST-017)
- Guest-to-guest audio communication (guests hear the mixed output via the HLS stream; low-latency guest comms require CALL-002 integration, deferred)
- Input resolution normalization (MediaLive handles this internally; no custom transcoding)
- Programmatic scene transitions (dissolve, wipe, fade) -- only hard cuts supported by MediaLive ImmediateMode

### 1.5 Competitive Analysis

| Platform | Multi-Input / Co-Stream Feature | How It Works | Key Limitations |
|----------|-------------------------------|-------------|----------------|
| **Twitch Guest Star** | Up to 5 guests via browser; layout auto-adjusts | WebRTC browser capture -> Twitch transcoding; host controls layout from dashboard | Browser-only (no OBS guest path); no custom layouts; limited to 5 guests; audio-only option available |
| **YouTube Multi-Cam** | Multiple RTMP inputs via YouTube Studio | Separate RTMP URLs per angle; viewer selects angle in player (no server-side composition) | No server-side layout composition; viewer must manually switch; limited to 8 angles; no guest invite flow |
| **Instagram Live Rooms** | Up to 4 participants via mobile app | WebRTC p2p + Instagram SFU; fixed 2x2 grid layout | Mobile-only; no OBS support; no layout customization; no screen share; 4 participant hard limit |
| **StreamYard** | Up to 10 guests via browser; 6 on-screen | WebRTC browser -> server-side composition -> RTMP out to any platform | Third-party dependency; adds $49/mo cost; no platform-native monetization integration; ~3s added latency |
| **OBS Ninja (VDO.Ninja)** | Unlimited browser guests via WebRTC | Peer-to-peer WebRTC; OBS ingests via browser source | Requires OBS on host side; no server-side layout; CPU-intensive on host; no centralized management |
| **Our platform (this ticket)** | Up to 8 inputs; 4 layout modes; browser + OBS guests | AWS MediaLive InputSwitch + server-side composition; browser guests via WebRTC relay | MediaLive has ~6s inherent latency; hard cut transitions only; relay adds latency for browser guests |

Our approach combines the best elements: server-side composition (like StreamYard) without third-party dependency, both browser and OBS guest paths (like Twitch + OBS Ninja), and native integration with platform monetization (tips, subscriptions, product shelf). The key differentiator is tight coupling with our existing billing, chat, and recording infrastructure.

### 1.6 Architecture After This Change

```
Broadcaster (OBS)            Guest A (OBS)            Guest B (Browser)
      |                           |                         |
      | RTMP Push                 | RTMP Push               | WebRTC
      v                           v                         v
+----------------------------------------------------------------------+
|  AWS MediaLive Channel (broadcast-{session_id}-channel)              |
|                                                                      |
|  InputAttachments:                                                   |
|    [0] broadcast-{session_id}-input-0  (primary, broadcaster)        |
|    [1] broadcast-{session_id}-input-1  (guest-a, RTMP)               |
|    [2] broadcast-{session_id}-input-2  (guest-b, via RTMP relay)     |
|    [3] broadcast-{session_id}-input-3  (spare / screen share)        |
|                                                                      |
|  Active Layout: SIDE_BY_SIDE                                         |
|  +------------------+------------------+                             |
|  |  Input 0 (50%)   |  Input 1 (50%)   |                             |
|  |  Broadcaster      |  Guest A          |                             |
|  +------------------+------------------+                             |
|                                                                      |
|  Output: HLS -> MediaPackage -> CloudFront -> Viewers                |
+----------------------------------------------------------------------+

WebRTC-to-RTMP Relay (for browser guests):
  Guest B's browser -> getUserMedia() -> WebRTC PeerConnection
    -> Backend relay process -> FFmpeg -> RTMP Push to Input 2
    (reuses ICE/TURN from CALL-002 infrastructure)

Guest Invite Flow:
  POST /broadcast/sessions/{id}/guest-invites
  -> { invite_id, invite_url, ingest_url, stream_key, expires_at }
  -> Guest opens invite_url -> GuestStreamPanel.tsx
  -> Guest clicks "Join" -> pushes RTMP or starts WebRTC relay
  -> SSE: "input:connected" -> Broadcaster sees guest in InputManager
```

---

## 2. Current State Analysis

### 2.1 MediaLive Provisioning (`app/services/broadcast_mediolive.py`)

The `MediaLiveProvisionResult` dataclass is defined at line 33 with five fields -- all singular:

```python
@dataclass(frozen=True)
class MediaLiveProvisionResult:
    input_arn: str           # Single input ARN
    channel_arn: str         # Channel ARN
    channel_id: str          # Channel ID
    state_snapshot: Dict[str, Any]
    archive_prefix: str
```
<!-- VERIFIED: app/services/broadcast_mediolive.py:33-39 -->

The `_client()` function at line 42 creates a boto3 MediaLive client using `S.aws_region` and `S.aws_endpoint_url`:

```python
def _client():
    if boto3 is None:
        raise RuntimeError("boto3 is required for aws broadcast provider")
    return boto3.client(
        "medialive",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )
```
<!-- VERIFIED: app/services/broadcast_mediolive.py:42-49 -->

The `_with_retry()` utility at line 52 retries transient MediaLive errors (Throttling, InternalError, etc.) with exponential backoff up to 4 attempts:

```python
def _with_retry(fn: Callable[[], Dict[str, Any]], *, max_attempts: int = 4, base_sleep_seconds: float = 0.2) -> Dict[str, Any]:
```
<!-- VERIFIED: app/services/broadcast_mediolive.py:52 -->

The core provisioning function `provision_mediolive_input_and_channel()` starts at line 81. It creates exactly one RTMP_PUSH input and one channel:

```python
def provision_mediolive_input_and_channel(
    *,
    session_id: str,
    correlation_id: str,
    idempotency_key: str,
) -> MediaLiveProvisionResult:
```
<!-- VERIFIED: app/services/broadcast_mediolive.py:81-86 -->

The input is created with naming convention `broadcast-{session_id}-input` (line 88) and the channel with `broadcast-{session_id}-channel` (line 89). The channel creation at line 127 attaches exactly one input:
<!-- CORRECTED: was "line 124", actually line 127 (line 124 is `create_channel = _with_retry(`) -->

```python
InputAttachments=[{"InputId": input_id, "InputAttachmentName": f"{session_id}-input-attach"}],
```
<!-- VERIFIED: app/services/broadcast_mediolive.py:127 -->

AWS MediaLive channels support up to 20 input attachments and input switching via `BatchUpdateSchedule` with `InputSwitchScheduleActionSettings`. The infrastructure supports multi-input natively -- the limitation is entirely in our provisioning code. The `_find_input_by_name()` helper at line 65 and `_find_channel_by_name()` at line 73 enable idempotent lookups but only for a single input.

### 2.2 Session Model (`app/models_broadcast.py`)

The `BroadcastSessionStatus` Literal is defined at line 8 with 10 possible states:

```python
BroadcastSessionStatus = Literal[
    "draft", "scheduled", "provisioning", "ready", "live",
    "private", "stopping", "stopped", "cancelled", "error",
]
```
<!-- VERIFIED: app/models_broadcast.py:8-19 -->

`BroadcastSessionModel` at line 37 stores a single `ingest_url` (line 41) and `stream_key_ref` (line 42). The model includes scheduling fields (BCAST-009, lines 51-58), go-private fields (BCAST-011, lines 60-64), and private chat fields (BCAST-012, lines 66-69) but no multi-input fields:
<!-- CORRECTED: was "ingest_url (line 42) and stream_key_ref (line 43)", actually line 41 and line 42 -->

```python
class BroadcastSessionModel(BaseModel):
    id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    status: BroadcastSessionStatus = "draft"
    ingest_url: Optional[str] = None
    stream_key_ref: Optional[str] = None
    stream_key_last_rotated_at: Optional[str] = None
    stream_key_rotation_interval_seconds: int = 86400
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    created_by: str = Field(min_length=1)
    created_at: str = ""
    updated_at: str = ""
```
<!-- VERIFIED: app/models_broadcast.py:37-50 -->

The `BroadcastOutputModel` at line 72 stores a single `aws_input_arn` (line 77) -- no support for multiple input ARNs:

```python
class BroadcastOutputModel(BaseModel):
    session_id: str = Field(min_length=1)
    mediapackage_endpoint: Optional[str] = None
    cloudfront_playback_url: Optional[str] = None
    s3_archive_prefix: Optional[str] = None
    aws_input_arn: Optional[str] = None
    aws_channel_arn: Optional[str] = None
    provider_state_snapshot: dict = Field(default_factory=dict)
    updated_at: str = ""
```
<!-- VERIFIED: app/models_broadcast.py:72-80 -->

The `BroadcastActionAuditEventModel` at line 102 has an `action` Literal with 12 values (lines 104-108). No multi-input or guest-related audit actions exist:

```python
class BroadcastActionAuditEventModel(BaseModel):
    audit_id: str = Field(min_length=1)
    action: Literal[
        "create_profile", "create_session", "start_session", "stop_session", "delete_session",
        "schedule_session", "cancel_scheduled_session", "reschedule_session",
        "go_private", "end_private", "private_chat_start", "private_chat_end",
    ]
```
<!-- VERIFIED: app/models_broadcast.py:102-108 -->

### 2.3 Session Store (`app/services/broadcast_store.py`)

`session_to_item()` at line 111 serializes the single `ingest_url` and `stream_key_ref` to DynamoDB. It already handles optional fields by removing `None` values at line 145:

```python
return {k: v for k, v in item.items() if v is not None}
```
<!-- VERIFIED: app/services/broadcast_store.py:145 -->

`session_from_item()` at line 148 deserializes using `.get()` with defaults for all optional fields. This pattern means new optional fields added to the model are backward-compatible with existing items.
<!-- VERIFIED: app/services/broadcast_store.py:148-179 -->

`create_session()` at line 182 accepts single ingest parameters (`ingest_url`, `stream_key_ref`). No mechanism to store per-input records.
<!-- VERIFIED: app/services/broadcast_store.py:182-209 -->

`transition_session_status()` at line 302 uses `validate_transition()` from the state machine and supports `extra_fields` (line 327) for atomic field updates during transitions. This pattern can be reused for setting layout state during transitions.
<!-- VERIFIED: app/services/broadcast_store.py:302-340 -->

`update_session_fields()` at line 435 does a get-modify-put cycle to update arbitrary session fields. This will be used to persist `active_layout`, `active_input_ids`, and `primary_input_id`.
<!-- VERIFIED: app/services/broadcast_store.py:435-446 -->

### 2.4 Orchestrator (`app/services/broadcast_orchestrator.py`)

`start_session_with_provider()` at line 17 provisions a single input via the provider and stores one input ARN via `put_output()` at line 39:

```python
def start_session_with_provider(
    *,
    session_id: str,
    actor: str,
    reason: str,
    correlation_id: str = "",
    idempotency_key: str = "",
) -> BroadcastSessionModel:
    provider = get_broadcast_provider()
    current = get_session(session_id)
    profile = get_profile(current.profile_id)
```
<!-- VERIFIED: app/services/broadcast_orchestrator.py:17-28 -->

The provisioning block (lines 29-67) creates one input, stores one `aws_input_arn` in the output record, and transitions to "ready". No provision for adding inputs post-creation.

`stop_session_with_provider()` at line 125 stops the channel and triggers the recording pipeline (BCAST-006, lines 155-173). This is the integration point where we will add cleanup of relay processes and input status on stop.
<!-- VERIFIED: app/services/broadcast_orchestrator.py:125-175 -->

`delete_session_with_provider()` at line 178 calls `provider.teardown()` and `delete_session()`. This is where we will add deletion of all input and invite records from the `BroadcastInputs` table.
<!-- VERIFIED: app/services/broadcast_orchestrator.py:178-187 -->

### 2.5 Provider (`app/services/broadcast_provider.py`)

The `BroadcastProvider` protocol at line 40 defines five methods: `provision`, `start`, `stop`, `status`, `teardown`. The `LocalBroadcastProvider` at line 57 returns mock results for all operations. The `AwsBroadcastProvider` at line 200 calls `provision_mediolive_input_and_channel()` (line 213) and `provision_mediapackage_channel_and_endpoint()` (line 218).
<!-- VERIFIED: app/services/broadcast_provider.py:40-55, 57-82, 200-242 -->

The `_resolve_channel_id()` helper at line 164 extracts the channel ID from the output record. This is needed by `broadcast_multi_input.py` for attaching additional inputs to the channel.
<!-- VERIFIED: app/services/broadcast_provider.py:164-179 -->

The `_resolve_input_id()` helper at line 182 looks up the primary input ID by naming convention. The naming pattern `broadcast-{session.id}-input` must be extended to `broadcast-{session.id}-input-{index}` for additional inputs.
<!-- VERIFIED: app/services/broadcast_provider.py:182-197 -->

The `AwsBroadcastProvider.teardown()` at line 381 deletes the channel, waits for it to be idle, then deletes the single input by name `broadcast-{session.id}-input`. For multi-input, teardown must iterate all inputs named `broadcast-{session.id}-input-{0..N}`.
<!-- VERIFIED: app/services/broadcast_provider.py:381-466 -->

### 2.6 State Machine (`app/services/broadcast_state_machine.py`)

The `_ALLOWED_TRANSITIONS` map at line 11 defines session-level state transitions:

```python
_ALLOWED_TRANSITIONS: Dict[BroadcastSessionStatus, Set[BroadcastSessionStatus]] = {
    "draft": {"provisioning", "scheduled", "error"},
    "scheduled": {"provisioning", "cancelled", "error"},
    "provisioning": {"ready", "error"},
    "ready": {"live", "stopping", "error"},
    "live": {"stopping", "private", "error"},
    "private": {"live", "stopping", "error"},
    "stopping": {"stopped", "error"},
    "stopped": set(),
    "cancelled": set(),
    "error": {"provisioning", "stopped"},
}
```
<!-- VERIFIED: app/services/broadcast_state_machine.py:11-22 -->

Input switching and layout changes are sub-operations within the `"live"` state and do not require new state machine transitions. The constraint is that layout switching is only valid when `status == "live"` (or `"private"` for the private session case where the channel is still running).

`validate_transition()` at line 35 and `build_transition_audit()` at line 41 do not need changes.
<!-- VERIFIED: app/services/broadcast_state_machine.py:35-38, 41-61 -->

### 2.7 Router (`app/routers/broadcast.py`)

The broadcast router is defined at line 64 with prefix `/broadcast`. It is the largest router in the codebase at 2530 lines.
<!-- VERIFIED: app/routers/broadcast.py:64 -->
<!-- CORRECTED: was "2531 lines", actually 2530 lines -->

`BroadcastSessionCreateIn` at line 93 accepts a single `ingest_url` and `stream_key_ref`:

```python
class BroadcastSessionCreateIn(BaseModel):
    profile_id: str = Field(..., min_length=1)
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key_ref: Optional[str] = Field(default=None, max_length=512)
```
<!-- VERIFIED: app/routers/broadcast.py:93-97 -->

`BroadcastSessionOut` at line 105 returns single `ingest_url`, `aws_input_arn`, and `aws_channel_arn` fields. It includes scheduling fields (BCAST-009, lines 124-131) but no multi-input fields.
<!-- VERIFIED: app/routers/broadcast.py:105-131 -->

The session detail endpoint `get_session_route()` at line 410 merges session and output data via `_to_session_out()` (line 204). The output merge at line 206-217 copies single `aws_input_arn` and `aws_channel_arn`.
<!-- VERIFIED: app/routers/broadcast.py:204-218, 410-418 -->

The SSE endpoint `broadcast_event_stream_route()` at line 619 uses `broadcast_sse_subscribe()` and yields events with `event_type` from `_type` key. This is the channel for input and layout events.
<!-- VERIFIED: app/routers/broadcast.py:619-639 -->

The `_require_operator_role()` check at line 191 requires admin or root role. Input management endpoints will use session ownership checks instead (matching the pattern used by scheduling endpoints at line 1704).
<!-- VERIFIED: app/routers/broadcast.py:191-196, schedule_session_route at :1704, ownership check at :1716 -->

### 2.8 Frontend (`frontend/src/pages/broadcast/BroadcastPage.tsx`)

The main `BroadcastPage` component at line 110 renders sessions in a card grid. The `SessionDetailDialog` at line 573 shows one "Ingest Configuration" section (line 651) displaying a single RTMP URL and stream key.
<!-- VERIFIED: frontend/src/pages/broadcast/BroadcastPage.tsx:110, 573, 651-679 -->

The `CreateSessionDialog` at line 855 collects a single ingest URL (line 914) and stream key reference (line 923):

```tsx
<Label htmlFor="session-ingest">Ingest URL (optional)</Label>
<Input
  id="session-ingest"
  placeholder="rtmp://ingest.example.com/live"
  value={ingestUrl}
  onChange={(e) => setIngestUrl(e.target.value)}
/>
```
<!-- VERIFIED: frontend/src/pages/broadcast/BroadcastPage.tsx:914-919 -->

The `BroadcastSession` TypeScript interface in `broadcast.ts` at line 31 mirrors the single-input backend model with fields `ingest_url`, `stream_key_ref`, `aws_input_arn`, `aws_channel_arn`.
<!-- VERIFIED: frontend/src/api/endpoints/broadcast.ts:31-57 -->

### 2.9 SSE Events (`app/services/broadcast_sse.py`)

The SSE module is a lightweight in-memory pub/sub. `_BROADCAST_SUBSCRIBERS` at line 8 is a dict mapping `session_id` to a set of `asyncio.Queue` instances:

```python
_BROADCAST_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}
```
<!-- VERIFIED: app/services/broadcast_sse.py:8 -->

`broadcast_sse_subscribe()` at line 11 creates a queue with `maxsize=100` and adds it to the session's subscriber set.
<!-- VERIFIED: app/services/broadcast_sse.py:11-15 -->

`broadcast_sse_publish()` at line 29 iterates all subscriber queues and puts the event dict. Dead queues (full) are automatically discarded:

```python
def broadcast_sse_publish(session_id: str, event: Dict[str, Any]) -> None:
    subs = _BROADCAST_SUBSCRIBERS.get(session_id)
    if not subs:
        return
    dead = []
    for q in list(subs):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
```
<!-- VERIFIED: app/services/broadcast_sse.py:29-39 -->

`broadcast_sse_subscriber_count()` at line 46 returns the number of active SSE subscribers. No input-related event types exist today. The `_type` field on the event dict is used as the SSE event name in the stream endpoint.
<!-- VERIFIED: app/services/broadcast_sse.py:46-49 -->

### 2.10 Existing Patterns

The `BroadcastPrivateSessions` table (`app/services/broadcast_private.py`) already uses a per-session sub-entity pattern:
- PK: `BCAST#{session_id}`, SK: `PRIVATE#{private_id}`
- This single-table pattern is established and well-tested.
<!-- VERIFIED: app/services/broadcast_private.py:56-57 (PK/SK pattern in create_private_request) -->

Multi-input follows the same DynamoDB single-table pattern with PK: `SESSION#{session_id}` and SK prefixes for inputs and invites.

### 2.11 Settings Infrastructure (`app/core/settings.py`)

Broadcast-related settings span lines 452-505 and 1116-1189 of `settings.py`. Key patterns:
- Table names: `broadcast_*_table_name: str = os.environ.get("DDB_BROADCAST_*", "Broadcast*")`
- Feature flags: `broadcast_*_enabled: bool = os.environ.get("BROADCAST_*", "1") not in ("0", "false", "False")`
- Numeric configs: `broadcast_*_seconds: int = int(os.environ.get("BROADCAST_*", "..."))`
<!-- VERIFIED: app/core/settings.py:452-505, 1116-1189 -->

### 2.12 Table Registry (`app/core/tables.py`)

Broadcast table handles span lines 39-43 and 78-88. Each handle is wired to a `S.*_table_name` setting at lines 139-143 and 178-188:

```python
broadcast_profiles=ddb.Table(S.broadcast_profiles_table_name),
broadcast_sessions=ddb.Table(S.broadcast_sessions_table_name),
broadcast_outputs=ddb.Table(S.broadcast_outputs_table_name),
broadcast_session_transitions=ddb.Table(S.broadcast_session_transitions_table_name),
broadcast_action_audit=ddb.Table(S.broadcast_action_audit_table_name),
...
broadcast_private_sessions=ddb.Table(S.broadcast_private_sessions_table_name),
```
<!-- VERIFIED: app/core/tables.py:39-43, 78-88, 139-143, 178-188 -->

---

## 3. Technical Design

### 3.1 Extended Session Model

Add the following fields to `BroadcastSessionModel` in `app/models_broadcast.py`, after the Private Chat block (line 69):
<!-- VERIFIED: app/models_broadcast.py:69 is private_chat_voyeur_price_cents, last line of Private Chat block -->

```python
# Multi-input / Co-streaming (BCAST-016)
max_inputs: int = Field(default=4, ge=1, le=8)
active_layout: Optional[str] = None       # "single" | "side_by_side" | "pip" | "grid"
active_input_ids: Optional[list] = None   # List of input_ids currently on-screen
primary_input_id: Optional[str] = None    # Main input in PiP mode
guest_invite_enabled: bool = False
```

These fields are all `Optional` with defaults, ensuring backward compatibility with existing sessions. `session_from_item()` already uses `.get()` with defaults for all optional fields.

### 3.2 New Backend Models

#### BroadcastInputModel

Represents a single input attached to a session. Stored in the `BroadcastInputs` DynamoDB table:

```python
class BroadcastInputModel(BaseModel):
    """A single video input attached to a broadcast session.

    PK: SESSION#{session_id}
    SK: INPUT#{input_id}
    """
    input_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    input_type: Literal["primary", "guest", "screen"] = "primary"
    label: str = Field(default="", max_length=100)
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key_ref: Optional[str] = Field(default=None, max_length=2048)
    aws_input_arn: Optional[str] = Field(default=None, max_length=512)
    aws_input_id: Optional[str] = Field(default=None, max_length=64)
    is_live: bool = False
    connected_at: Optional[int] = None
    disconnected_at: Optional[int] = None
    position: int = Field(default=0, ge=0, le=7)
    created_by: str = Field(min_length=1)
    created_at: str = ""
    updated_at: str = ""
    relay_mode: Optional[Literal["rtmp", "webrtc_relay"]] = None
    relay_process_id: Optional[str] = None
```

#### BroadcastGuestInvite

Represents an invitation for a co-streamer. Stored in the same table:

```python
class BroadcastGuestInvite(BaseModel):
    """Guest co-streamer invite. PK: SESSION#{session_id}, SK: INVITE#{invite_id}."""
    invite_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    input_id: str = Field(min_length=1, max_length=64)  # Pre-allocated input for this guest
    created_by: str = Field(min_length=1)
    status: Literal["pending", "accepted", "expired", "revoked"] = "pending"
    guest_user_id: Optional[str] = None
    guest_display_name: Optional[str] = Field(default=None, max_length=100)
    join_mode: Literal["rtmp", "browser"] = "browser"
    ingest_url: Optional[str] = Field(default=None, max_length=1024)
    stream_key: Optional[str] = None   # Returned once in the creation response, not persisted
    stream_key_ref: Optional[str] = Field(default=None, max_length=2048)  # Secrets Manager ARN
    expires_at: int = 0
    accepted_at: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""
```

#### LayoutPosition and BroadcastLayoutConfig

```python
class LayoutPosition(BaseModel):
    """Position of a single input in the composed output, using normalized coordinates."""
    input_id: str = Field(min_length=1, max_length=64)
    x: float = Field(ge=0.0, le=1.0, description="Left edge, 0=left, 1=right")
    y: float = Field(ge=0.0, le=1.0, description="Top edge, 0=top, 1=bottom")
    width: float = Field(gt=0.0, le=1.0, description="Width as fraction of output")
    height: float = Field(gt=0.0, le=1.0, description="Height as fraction of output")
    z_index: int = Field(default=0, ge=0, le=10, description="Stacking order for overlapping inputs")

class BroadcastLayoutConfig(BaseModel):
    """Full layout configuration for a broadcast session."""
    mode: Literal["single", "side_by_side", "pip", "grid"]
    positions: list[LayoutPosition] = Field(default_factory=list)
    primary_input_id: Optional[str] = None
    input_ids: list[str] = Field(default_factory=list)
    updated_at: str = ""
```

### 3.3 DynamoDB Changes

#### New Table: `BroadcastInputs`

Stores per-input records and guest invites in a single-table design:

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.broadcast_inputs_table_name, "BroadcastInputs"),
    "pk",       # SESSION#{session_id}
    "sk",       # INPUT#{input_id} or INVITE#{invite_id}
    gsis=[
        {
            "index_name": "ByCreator",
            "partition_key": "created_by",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByStatus",
            "partition_key": "invite_status",
            "sort_key": "expires_at",
        },
    ],
    attr_types={"expires_at": "N"},
),
```

**Entity types stored in this table:**

| SK pattern | Entity | Purpose |
|-----------|--------|---------|
| `INPUT#{input_id}` | BroadcastInputModel | Per-input metadata (ingest URL, live status, position, relay mode) |
| `INVITE#{invite_id}` | BroadcastGuestInvite | Guest invite (status, guest info, expiry, join mode) |
| `LAYOUT` | BroadcastLayoutConfig | Current layout configuration (mode, positions, primary input) |

**Key access patterns:**

| Access Pattern | Key Condition | Index |
|----------------|--------------|-------|
| List all inputs for a session | `PK = SESSION#{session_id}` AND `begins_with(SK, "INPUT#")` | Table |
| Get single input | `PK = SESSION#{session_id}` AND `SK = INPUT#{input_id}` | Table |
| List all invites for a session | `PK = SESSION#{session_id}` AND `begins_with(SK, "INVITE#")` | Table |
| Get single invite | `PK = SESSION#{session_id}` AND `SK = INVITE#{invite_id}` | Table |
| Get layout config | `PK = SESSION#{session_id}` AND `SK = LAYOUT` | Table |
| Find invites by creator | `created_by = X` | ByCreator GSI |
| Find expiring invites | `invite_status = "pending"` AND `expires_at <= now` | ByStatus GSI |

**DynamoDB item examples:**

```json
// INPUT record
{
  "pk": "SESSION#abc123",
  "sk": "INPUT#inp_001",
  "input_id": "inp_001",
  "session_id": "abc123",
  "input_type": "primary",
  "label": "Main Camera",
  "ingest_url": "rtmp://medialive-input-0.example.com/live",
  "stream_key_ref": "arn:aws:secretsmanager:us-east-1:000000000000:secret:bcast/abc123/input-0",
  "aws_input_arn": "arn:aws:medialive:us-east-1:000000000000:input:12345",
  "aws_input_id": "12345",
  "is_live": true,
  "connected_at": 1748476800,
  "position": 0,
  "created_by": "user_abc",
  "created_at": "2026-05-28T10:00:00+00:00",
  "updated_at": "2026-05-28T10:05:00+00:00"
}

// INVITE record
{
  "pk": "SESSION#abc123",
  "sk": "INVITE#inv_789",
  "invite_id": "inv_789",
  "session_id": "abc123",
  "input_id": "inp_002",
  "created_by": "user_abc",
  "invite_status": "pending",
  "join_mode": "browser",
  "expires_at": 1748480400,
  "stream_key_ref": "arn:aws:secretsmanager:us-east-1:000000000000:secret:bcast/abc123/invite-789",
  "created_at": "2026-05-28T10:00:00+00:00"
}

// LAYOUT record
{
  "pk": "SESSION#abc123",
  "sk": "LAYOUT",
  "mode": "side_by_side",
  "positions": [
    {"input_id": "inp_001", "x": 0.0, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0},
    {"input_id": "inp_002", "x": 0.5, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0}
  ],
  "primary_input_id": "inp_001",
  "input_ids": ["inp_001", "inp_002"],
  "updated_at": "2026-05-28T10:15:00+00:00"
}
```

#### Settings and Table Handles

In `app/core/settings.py`, add after line 1189:
<!-- VERIFIED: app/core/settings.py:1189 is broadcast_private_chat_voyeur_enabled (last BCAST-012 setting) -->

```python
# Multi-input / Co-streaming (BCAST-016)
broadcast_inputs_table_name: str = os.environ.get("DDB_BROADCAST_INPUTS", "BroadcastInputs")
broadcast_max_inputs_per_session: int = int(os.environ.get("BROADCAST_MAX_INPUTS_PER_SESSION", "4"))
broadcast_guest_invite_expiry_seconds: int = int(os.environ.get("BROADCAST_GUEST_INVITE_EXPIRY_SECONDS", "3600"))
broadcast_webrtc_relay_enabled: bool = os.environ.get("BROADCAST_WEBRTC_RELAY_ENABLED", "false").lower() in ("1", "true")
broadcast_multi_input_enabled: bool = os.environ.get("BROADCAST_MULTI_INPUT_ENABLED", "1") not in ("0", "false", "False")
broadcast_layout_switch_cooldown_seconds: int = int(os.environ.get("BROADCAST_LAYOUT_SWITCH_COOLDOWN_SECONDS", "2"))
```

In `app/core/tables.py`, add `broadcast_inputs: Any` to the table handle dataclass (after line 88) and wire to `ddb.Table(S.broadcast_inputs_table_name)` (after line 188).
<!-- VERIFIED: app/core/tables.py:88 is broadcast_private_sessions, line 188 is its wiring -->

### 3.4 Multi-Input MediaLive Service (`app/services/broadcast_multi_input.py`)

New file (~250 lines) with functions extending the single-input provisioning. Imports `_client` and `_with_retry` from `broadcast_mediolive.py`:

```python
"""Multi-input MediaLive operations for BCAST-016.

Extends broadcast_mediolive.py with:
- Additional RTMP_PUSH input creation/deletion
- Input attachment to running channels
- InputSwitch schedule actions for input switching
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional
from uuid import uuid4

from app.core.settings import S
from app.services.broadcast_mediolive import _client, _with_retry

logger = logging.getLogger("broadcast.multi_input")


@dataclass(frozen=True)
class InputProvisionResult:
    input_id: str
    input_arn: str
    ingest_url: str
    stream_key: str       # One-time value, not persisted


def create_additional_input(
    *,
    session_id: str,
    input_index: int,
    correlation_id: str = "",
    idempotency_key: str = "",
) -> InputProvisionResult:
    """Create a new RTMP_PUSH input named broadcast-{session_id}-input-{index}.

    Returns InputProvisionResult with input_id, input_arn, ingest_url, and
    one-time stream_key. The stream_key is returned to the caller for delivery
    to the guest and is NOT stored -- only the Secrets Manager ARN is persisted.
    """
    client = _client()
    input_name = f"broadcast-{session_id}-input-{input_index}"
    idem_key = idempotency_key or f"{session_id}:input:{input_index}"

    create_resp = _with_retry(
        lambda: client.create_input(
            Name=input_name,
            Type="RTMP_PUSH",
            RequestId=idem_key,
            Tags={
                "broadcast-session-id": session_id,
                "input-index": str(input_index),
                "correlation-id": correlation_id,
            },
        )
    )
    input_data = create_resp.get("Input", {})
    input_id = str(input_data.get("Id") or "")
    input_arn = str(input_data.get("Arn") or "")

    # Extract ingest URL and stream key from destinations
    destinations = input_data.get("Destinations", [])
    ingest_url = ""
    stream_key = ""
    if destinations:
        first = destinations[0]
        ingest_url = first.get("Url", "")
        stream_key = first.get("StreamName", str(uuid4().hex))

    return InputProvisionResult(
        input_id=input_id,
        input_arn=input_arn,
        ingest_url=ingest_url,
        stream_key=stream_key,
    )


def attach_input_to_channel(
    *,
    channel_id: str,
    input_id: str,
    attachment_name: str,
) -> Dict[str, Any]:
    """Attach an input to a running MediaLive channel.

    Calls DescribeChannel to get current attachments, appends the new one,
    and calls UpdateChannel. MediaLive supports hot-attaching to running channels.
    """
    client = _client()

    # Get current channel config
    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_attachments = desc.get("InputAttachments", [])

    # Append new attachment
    new_attachment = {
        "InputId": input_id,
        "InputAttachmentName": attachment_name,
    }
    updated_attachments = current_attachments + [new_attachment]

    # Update channel
    result = _with_retry(
        lambda: client.update_channel(
            ChannelId=channel_id,
            InputAttachments=updated_attachments,
        )
    )
    return result


def schedule_input_switch(
    *,
    channel_id: str,
    input_attachment_name: str,
    action_name: str,
) -> Dict[str, Any]:
    """Switch the active input on a running channel using ImmediateMode.

    Uses BatchUpdateSchedule with ImmediateModeScheduleActionStartSettings
    and InputSwitchScheduleActionSettings.
    """
    client = _client()

    schedule_action = {
        "ActionName": action_name,
        "ScheduleActionStartSettings": {
            "ImmediateModeScheduleActionStartSettings": {}
        },
        "ScheduleActionSettings": {
            "InputSwitchSettings": {
                "InputAttachmentNameReference": input_attachment_name,
            }
        },
    }

    result = _with_retry(
        lambda: client.batch_update_schedule(
            ChannelId=channel_id,
            Creates={"ScheduleActions": [schedule_action]},
        )
    )
    return result


def detach_input_from_channel(
    *,
    channel_id: str,
    input_attachment_name: str,
) -> Dict[str, Any]:
    """Remove an input from the channel by filtering it out of InputAttachments."""
    client = _client()
    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_attachments = desc.get("InputAttachments", [])

    filtered = [
        a for a in current_attachments
        if a.get("InputAttachmentName") != input_attachment_name
    ]

    if len(filtered) == len(current_attachments):
        logger.warning("Attachment %s not found on channel %s", input_attachment_name, channel_id)
        return {"detached": False}

    result = _with_retry(
        lambda: client.update_channel(
            ChannelId=channel_id,
            InputAttachments=filtered,
        )
    )
    return {"detached": True, "result": result}


def delete_medialive_input(input_id: str) -> Dict[str, Any]:
    """Delete a MediaLive input resource."""
    client = _client()
    result = _with_retry(lambda: client.delete_input(InputId=input_id))
    return result
```

### 3.5 Input Store (`app/services/broadcast_input_store.py`)

New file (~320 lines) with DynamoDB CRUD for inputs and guest invites.

**Input operations:**

```python
def create_input(
    *,
    session_id: str,
    input_type: str = "primary",
    label: str = "",
    ingest_url: str | None = None,
    stream_key_ref: str | None = None,
    aws_input_arn: str | None = None,
    aws_input_id: str | None = None,
    position: int = 0,
    created_by: str,
    relay_mode: str | None = None,
) -> BroadcastInputModel:
    """Create an input record in DDB. Returns the created model.

    input_id is generated as f"inp_{uuid4().hex[:12]}".
    PK = SESSION#{session_id}, SK = INPUT#{input_id}.
    """

def get_input(session_id: str, input_id: str) -> BroadcastInputModel:
    """Get a single input. Raises HTTPException(404) if not found."""

def list_inputs(session_id: str) -> list[BroadcastInputModel]:
    """List all inputs for a session, sorted by position ascending."""

def update_input(session_id: str, input_id: str, fields: dict) -> BroadcastInputModel:
    """Update arbitrary fields on an input via get-modify-put."""

def delete_input(session_id: str, input_id: str) -> bool:
    """Delete an input record. Returns True if deleted, False if not found."""

def mark_input_live(session_id: str, input_id: str, *, is_live: bool = True) -> BroadcastInputModel:
    """Set is_live and connected_at/disconnected_at timestamps."""

def count_inputs(session_id: str) -> int:
    """Count inputs for a session using Select='COUNT'."""

def delete_all_inputs(session_id: str) -> int:
    """Delete all INPUT# and INVITE# and LAYOUT records for a session. Returns count deleted."""
```

**Guest invite operations:**

```python
def create_guest_invite(
    *,
    session_id: str,
    input_id: str,
    created_by: str,
    join_mode: str = "browser",
    ingest_url: str | None = None,
    stream_key_ref: str | None = None,
    expires_at: int,
) -> BroadcastGuestInvite:
    """Create a guest invite. invite_id = f"inv_{uuid4().hex[:12]}"."""

def get_guest_invite(session_id: str, invite_id: str) -> BroadcastGuestInvite:
    """Get a single invite. Raises HTTPException(404) if not found."""

def list_guest_invites(session_id: str, *, status_filter: str | None = None) -> list[BroadcastGuestInvite]:
    """List invites for a session, optionally filtered by status."""

def accept_guest_invite(
    session_id: str,
    invite_id: str,
    *,
    guest_user_id: str,
    guest_display_name: str,
) -> BroadcastGuestInvite:
    """Accept an invite.

    Validates: status == "pending" and expires_at > now_ts().
    Returns 409 if already accepted, 410 if expired.
    Sets guest_user_id, guest_display_name, accepted_at, status="accepted".
    """

def revoke_guest_invite(session_id: str, invite_id: str) -> BroadcastGuestInvite:
    """Set invite status to "revoked". Returns updated invite."""

def expire_pending_invites(session_id: str) -> int:
    """Expire all pending invites for a session. Returns count expired."""
```

**Layout operations:**

```python
def save_layout(session_id: str, layout: BroadcastLayoutConfig) -> None:
    """Persist layout config to DDB (PK=SESSION#{session_id}, SK=LAYOUT)."""

def get_layout(session_id: str) -> BroadcastLayoutConfig | None:
    """Get current layout. Returns None if no layout set."""
```

### 3.6 Layout Engine (`app/services/broadcast_layout.py`)

New service (~220 lines) managing layout state and computing positions:

```python
"""Layout engine for multi-input broadcasts.

Supports four preset layouts: single, side_by_side, pip, grid.
Each layout is defined as a template function that takes a list of input_ids
and returns a list of LayoutPosition objects with normalized coordinates.
"""

from __future__ import annotations

from typing import Optional
from fastapi import HTTPException

from app.models_broadcast import BroadcastSessionModel
from app.services.broadcast_store import get_session, update_session_fields
from app.services.broadcast_input_store import list_inputs, get_layout, save_layout

VALID_LAYOUTS = {"single", "side_by_side", "pip", "grid"}

# ── Layout Template Functions ──────────────────────────────────────

def _layout_single(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    """Full-screen single input."""
    target = primary_input_id or input_ids[0]
    return [{"input_id": target, "x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0, "z_index": 0}]

def _layout_side_by_side(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    """Two inputs, each 50% width, full height."""
    ids = input_ids[:2]
    # If primary is specified and in list, put it first
    if primary_input_id and primary_input_id in ids:
        ids = [primary_input_id] + [i for i in ids if i != primary_input_id]
    return [
        {"input_id": ids[0], "x": 0.0, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0},
        {"input_id": ids[1], "x": 0.5, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0},
    ]

def _layout_pip(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    """Picture-in-picture: primary full-screen, secondary small overlay at bottom-right."""
    primary = primary_input_id or input_ids[0]
    secondary = [i for i in input_ids if i != primary]
    if not secondary:
        # Only one input -- fall back to single
        return _layout_single(input_ids, primary)
    return [
        {"input_id": primary, "x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0, "z_index": 0},
        {"input_id": secondary[0], "x": 0.7, "y": 0.7, "width": 0.28, "height": 0.28, "z_index": 1},
    ]

def _layout_grid(input_ids: list[str], primary_input_id: str | None = None) -> list[dict]:
    """Adaptive grid layout.

    1 input:  1x1 full screen
    2 inputs: 1x2 (stacked horizontally, each 50% width)
    3 inputs: 2x2 with bottom-right empty (3 cells filled)
    4 inputs: 2x2 grid (each 50% width, 50% height)
    """
    _ = primary_input_id  # Grid treats all inputs equally
    n = min(len(input_ids), 4)
    if n == 1:
        return [{"input_id": input_ids[0], "x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0, "z_index": 0}]

    positions = []
    cols = 2
    rows = 2 if n > 2 else 1
    w = 1.0 / cols
    h = 1.0 / rows
    for idx in range(n):
        col = idx % cols
        row = idx // cols
        positions.append({
            "input_id": input_ids[idx],
            "x": round(col * w, 4),
            "y": round(row * h, 4),
            "width": round(w, 4),
            "height": round(h, 4),
            "z_index": 0,
        })
    return positions

_LAYOUT_FUNCTIONS = {
    "single": _layout_single,
    "side_by_side": _layout_side_by_side,
    "pip": _layout_pip,
    "grid": _layout_grid,
}


# ── Main Entry Point ───────────────────────────────────────────────

def switch_layout(
    *,
    session_id: str,
    mode: str,
    primary_input_id: str | None = None,
    input_ids: list[str] | None = None,
) -> dict:
    """Validate session, compute layout positions, persist, and return result.

    Algorithm:
    1. Validate session is live (409 if not)
    2. Validate mode is in VALID_LAYOUTS (400 if not)
    3. If input_ids not provided, use all live inputs sorted by position
    4. Validate sufficient inputs for the requested mode
    5. Compute positions using the layout template function
    6. Persist layout to DDB (both BroadcastInputs LAYOUT record and session fields)
    7. Return mode + positions + primary_input_id
    """
    session = get_session(session_id)
    if session.status not in ("live", "private"):
        raise HTTPException(status_code=409, detail="Layout switching requires a live session.")

    if mode not in VALID_LAYOUTS:
        raise HTTPException(status_code=400, detail=f"Invalid layout mode: {mode}. Valid: {', '.join(sorted(VALID_LAYOUTS))}")

    # Resolve input IDs
    if not input_ids:
        inputs = list_inputs(session_id)
        input_ids = [inp.input_id for inp in inputs]

    # Validate sufficient inputs
    if mode in ("side_by_side", "pip") and len(input_ids) < 2:
        raise HTTPException(status_code=400, detail=f"Layout '{mode}' requires at least 2 inputs, got {len(input_ids)}.")

    # Validate primary_input_id
    if mode == "pip" and primary_input_id and primary_input_id not in input_ids:
        raise HTTPException(status_code=400, detail="primary_input_id must be in input_ids for pip mode.")

    # Compute positions
    layout_fn = _LAYOUT_FUNCTIONS[mode]
    positions = layout_fn(input_ids, primary_input_id)

    # Persist to DDB
    from app.services.broadcast_input_store import save_layout as _save_layout
    from app.models_broadcast import BroadcastLayoutConfig
    from app.services.broadcast_store import now_iso

    layout_config = BroadcastLayoutConfig(
        mode=mode,
        positions=[LayoutPosition(**p) for p in positions],
        primary_input_id=primary_input_id,
        input_ids=input_ids,
        updated_at=now_iso(),
    )
    _save_layout(session_id, layout_config)

    # Update session fields
    update_session_fields(session_id, {
        "active_layout": mode,
        "active_input_ids": input_ids,
        "primary_input_id": primary_input_id,
    })

    return {
        "mode": mode,
        "positions": positions,
        "primary_input_id": primary_input_id,
        "input_ids": input_ids,
    }
```

### 3.7 WebRTC-to-RTMP Relay (`app/services/broadcast_webrtc_relay.py`)

New service (~160 lines) for browser-based guest connections:

```python
"""WebRTC-to-RTMP relay for browser-based broadcast guests.

In production: starts an FFmpeg process that ingests WebRTC media and
outputs to the RTMP ingest URL of the guest's allocated MediaLive input.

In dev mode: returns mock SDP answers and tracks relay state in memory
without starting real processes.
"""

from __future__ import annotations

import logging
import signal
import subprocess
from typing import Any, Dict, Optional

from app.core.settings import S

logger = logging.getLogger("broadcast.webrtc_relay")

# In-memory relay tracking: {(session_id, input_id): process_or_mock}
_ACTIVE_RELAYS: Dict[tuple[str, str], Any] = {}


def start_relay(
    *,
    session_id: str,
    input_id: str,
    rtmp_target_url: str,
    sdp_offer: str,
) -> dict:
    """Start a WebRTC-to-RTMP relay.

    In dev mode, returns a mock SDP answer and stores a placeholder.
    In production, starts an FFmpeg subprocess.
    """
    key = (session_id, input_id)
    if key in _ACTIVE_RELAYS:
        return {"status": "already_running", "session_id": session_id, "input_id": input_id}

    if S.dev_mode or not S.broadcast_webrtc_relay_enabled:
        # Dev mock: return fake SDP answer
        _ACTIVE_RELAYS[key] = {"mock": True, "session_id": session_id, "input_id": input_id}
        return {
            "status": "started",
            "sdp_answer": "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=mock\r\nt=0 0\r\n",
            "session_id": session_id,
            "input_id": input_id,
        }

    # Production: start FFmpeg process
    # ... (FFmpeg subprocess creation with SDP -> RTMP pipeline)
    logger.info("Starting WebRTC relay for session=%s input=%s", session_id, input_id)
    _ACTIVE_RELAYS[key] = {"mock": False, "session_id": session_id, "input_id": input_id}
    return {"status": "started", "session_id": session_id, "input_id": input_id}


def stop_relay(session_id: str, input_id: str) -> dict:
    """Stop a running relay. SIGTERM then SIGKILL if needed."""
    key = (session_id, input_id)
    relay = _ACTIVE_RELAYS.pop(key, None)
    if not relay:
        return {"status": "not_found"}

    if isinstance(relay, dict) and relay.get("mock"):
        return {"status": "stopped", "session_id": session_id, "input_id": input_id}

    # Production: terminate subprocess
    # ...
    return {"status": "stopped", "session_id": session_id, "input_id": input_id}


def stop_all_relays_for_session(session_id: str) -> int:
    """Stop all relay processes for a session. Called on session stop."""
    keys_to_stop = [k for k in _ACTIVE_RELAYS if k[0] == session_id]
    for key in keys_to_stop:
        stop_relay(key[0], key[1])
    return len(keys_to_stop)


def get_relay_status(session_id: str, input_id: str) -> dict | None:
    """Check if a relay is active for the given input."""
    key = (session_id, input_id)
    relay = _ACTIVE_RELAYS.get(key)
    if not relay:
        return None
    return {"status": "running", "session_id": session_id, "input_id": input_id}
```

### 3.8 API Endpoints

All added to `app/routers/broadcast.py`. Each endpoint includes request/response models, auth checks, and SSE event publishing.

| # | Method | Path | Auth | Status Code | Purpose |
|---|--------|------|------|------------|---------|
| 1 | GET | `/sessions/{id}/inputs` | Session owner or viewer | 200 | List all inputs sorted by position |
| 2 | POST | `/sessions/{id}/inputs` | Session owner | 201 | Add new RTMP input (provisions MediaLive input + attaches to channel) |
| 3 | DELETE | `/sessions/{id}/inputs/{input_id}` | Session owner | 200 | Remove input (detach + delete MediaLive + DDB) |
| 4 | POST | `/sessions/{id}/layout` | Session owner | 200 | Switch layout mode (single/side_by_side/pip/grid) |
| 5 | GET | `/sessions/{id}/layout` | Session owner or viewer | 200 | Get current layout configuration |
| 6 | POST | `/sessions/{id}/inputs/{input_id}/activate` | Session owner | 200 | Bring input on-screen |
| 7 | POST | `/sessions/{id}/inputs/{input_id}/deactivate` | Session owner | 200 | Remove input from layout |
| 8 | POST | `/sessions/{id}/guest-invites` | Session owner | 201 | Create guest invite link |
| 9 | GET | `/sessions/{id}/guest-invites` | Session owner | 200 | List guest invites |
| 10 | POST | `/sessions/{id}/guest-invites/{invite_id}/accept` | Any authenticated | 200 | Guest accepts invite |
| 11 | POST | `/sessions/{id}/guest-invites/{invite_id}/revoke` | Session owner | 200 | Revoke invite |
| 12 | POST | `/sessions/{id}/guests/{input_id}/remove` | Session owner | 200 | Remove guest |
| 13 | POST | `/sessions/{id}/guests/{input_id}/mute` | Session owner | 200 | Mute guest (SSE event only) |
| 14 | POST | `/sessions/{id}/guests/{input_id}/promote` | Session owner | 200 | Promote guest to primary |
| 15 | POST | `/sessions/{id}/inputs/{input_id}/webrtc-offer` | Guest user | 200 | WebRTC relay SDP offer |
| 16 | POST | `/sessions/{id}/inputs/{input_id}/ice-candidate` | Guest user | 200 | WebRTC relay ICE candidate |

**Request/response model definitions:**

```python
# ─── Multi-Input Request/Response Models (BCAST-016) ────────────

class BroadcastInputCreateIn(BaseModel):
    """Request body for adding a new input to a broadcast session."""
    input_type: Literal["primary", "guest", "screen"] = "guest"
    label: str = Field(default="", max_length=100)

class BroadcastInputOut(BaseModel):
    """Response model for a single broadcast input."""
    input_id: str
    session_id: str
    input_type: str
    label: str
    ingest_url: Optional[str] = None
    stream_key_ref: Optional[str] = None
    aws_input_arn: Optional[str] = None
    is_live: bool = False
    connected_at: Optional[int] = None
    disconnected_at: Optional[int] = None
    position: int = 0
    created_by: str
    created_at: str
    updated_at: str
    relay_mode: Optional[str] = None

class BroadcastInputListOut(BaseModel):
    """Response model for listing inputs."""
    session_id: str
    inputs: List[BroadcastInputOut] = Field(default_factory=list)
    count: int = 0
    max_inputs: int = 4

class BroadcastInputCreateOut(BaseModel):
    """Response for input creation -- includes one-time stream_key."""
    input_id: str
    session_id: str
    input_type: str
    label: str
    ingest_url: str
    stream_key: str  # One-time, not stored
    aws_input_arn: Optional[str] = None
    position: int

class BroadcastLayoutSwitchIn(BaseModel):
    """Request body for switching layout mode."""
    mode: Literal["single", "side_by_side", "pip", "grid"]
    primary_input_id: Optional[str] = None
    input_ids: Optional[List[str]] = None

class BroadcastLayoutOut(BaseModel):
    """Response model for layout configuration."""
    mode: str
    positions: List[dict] = Field(default_factory=list)
    primary_input_id: Optional[str] = None
    input_ids: List[str] = Field(default_factory=list)

class BroadcastGuestInviteCreateIn(BaseModel):
    """Request body for creating a guest invite."""
    join_mode: Literal["rtmp", "browser"] = "browser"
    label: str = Field(default="Guest", max_length=100)
    expiry_minutes: int = Field(default=60, ge=5, le=1440)

class BroadcastGuestInviteOut(BaseModel):
    """Response model for a guest invite."""
    invite_id: str
    session_id: str
    input_id: str
    invite_url: Optional[str] = None
    ingest_url: Optional[str] = None
    stream_key: Optional[str] = None  # Only on creation, never on list
    join_mode: str
    status: str
    guest_user_id: Optional[str] = None
    guest_display_name: Optional[str] = None
    expires_at: int
    accepted_at: Optional[int] = None
    created_at: str

class BroadcastGuestInviteListOut(BaseModel):
    """Response model for listing guest invites."""
    session_id: str
    invites: List[BroadcastGuestInviteOut] = Field(default_factory=list)
    count: int = 0

class BroadcastGuestAcceptIn(BaseModel):
    """Request body for accepting a guest invite."""
    display_name: str = Field(min_length=1, max_length=100)

class BroadcastGuestAcceptOut(BaseModel):
    """Response model for accepting a guest invite."""
    invite_id: str
    input_id: str
    ingest_url: Optional[str] = None
    join_mode: str
    session_id: str

class BroadcastWebRTCOfferIn(BaseModel):
    """Request body for WebRTC SDP offer."""
    sdp_offer: str = Field(min_length=1, max_length=65536)

class BroadcastWebRTCOfferOut(BaseModel):
    """Response model for WebRTC SDP answer."""
    sdp_answer: str
    session_id: str
    input_id: str

class BroadcastGuestMuteIn(BaseModel):
    """Request body for muting/unmuting a guest."""
    muted: bool = True
```

**Example endpoint implementations:**

```python
@router.get("/sessions/{session_id}/inputs", response_model=BroadcastInputListOut)
def list_inputs_route(session_id: str, ctx: dict = Depends(_ctx)):
    """List all inputs for a broadcast session."""
    session = get_session(session_id)
    from app.services.broadcast_input_store import list_inputs
    inputs = list_inputs(session_id)
    return BroadcastInputListOut(
        session_id=session_id,
        inputs=[BroadcastInputOut(**inp.model_dump()) for inp in inputs],
        count=len(inputs),
        max_inputs=S.broadcast_max_inputs_per_session,
    )


@router.post("/sessions/{session_id}/inputs", response_model=BroadcastInputCreateOut, status_code=201)
def add_input_route(session_id: str, body: BroadcastInputCreateIn, request: Request, ctx: dict = Depends(_ctx)):
    """Add a new input to a broadcast session. Provisions MediaLive input and attaches to channel."""
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by:
        raise HTTPException(status_code=403, detail="Only the broadcaster can add inputs.")
    if session.status in ("stopped", "error", "cancelled"):
        raise HTTPException(status_code=409, detail=f"Cannot add inputs when session is {session.status}.")

    from app.services.broadcast_input_store import count_inputs, create_input, list_inputs
    current_count = count_inputs(session_id)
    if current_count >= S.broadcast_max_inputs_per_session:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {S.broadcast_max_inputs_per_session} inputs per session.",
        )

    # Provision MediaLive input
    from app.services.broadcast_multi_input import create_additional_input, attach_input_to_channel
    from app.services.broadcast_provider import _resolve_channel_id

    provision_result = create_additional_input(
        session_id=session_id,
        input_index=current_count,
        correlation_id=_correlation_id(request),
    )

    # Attach to channel if session has one
    output = get_output(session_id)
    if output and output.aws_channel_arn:
        channel_id = output.provider_state_snapshot.get("details", {}).get("channel_id", "")
        if channel_id:
            attach_input_to_channel(
                channel_id=channel_id,
                input_id=provision_result.input_id,
                attachment_name=f"{session_id}-input-{current_count}-attach",
            )

    # Create DDB record
    new_input = create_input(
        session_id=session_id,
        input_type=body.input_type,
        label=body.label,
        ingest_url=provision_result.ingest_url,
        aws_input_arn=provision_result.input_arn,
        aws_input_id=provision_result.input_id,
        position=current_count,
        created_by=ctx["user_sub"],
    )

    # SSE event
    broadcast_sse_publish(session_id, {
        "_type": "input:added",
        "input_id": new_input.input_id,
        "input_type": body.input_type,
        "label": body.label,
        "position": current_count,
    })

    # Audit
    record_broadcast_action(
        action="add_input",
        actor=ctx["user_sub"],
        correlation_id=_correlation_id(request),
        resource_type="session",
        resource_id=session_id,
        metadata={"input_id": new_input.input_id, "input_type": body.input_type},
    )

    return BroadcastInputCreateOut(
        input_id=new_input.input_id,
        session_id=session_id,
        input_type=body.input_type,
        label=body.label,
        ingest_url=provision_result.ingest_url,
        stream_key=provision_result.stream_key,
        aws_input_arn=provision_result.input_arn,
        position=current_count,
    )
```

### 3.9 Audit Actions

Extend `BroadcastActionAuditEventModel.action` Literal in `app/models_broadcast.py` (line 104):
<!-- VERIFIED: app/models_broadcast.py:102-108, action Literal starts at line 104 -->

```python
action: Literal[
    # Existing
    "create_profile", "create_session", "start_session", "stop_session", "delete_session",
    "schedule_session", "cancel_scheduled_session", "reschedule_session",
    "go_private", "end_private", "private_chat_start", "private_chat_end",
    # Multi-input (BCAST-016)
    "add_input", "remove_input", "switch_layout",
    "create_guest_invite", "accept_guest_invite", "revoke_guest_invite",
    "remove_guest", "mute_guest", "promote_guest",
    "start_webrtc_relay", "stop_webrtc_relay",
]
```

### 3.10 SSE Events

All events are published via `broadcast_sse_publish(session_id, {...})`. The `_type` field becomes the SSE event name.

| Event Type | Payload Fields | Trigger |
|------------|---------------|---------|
| `input:added` | `input_id`, `input_type`, `label`, `position` | New input provisioned via POST /inputs |
| `input:removed` | `input_id` | Input deleted via DELETE /inputs/{id} |
| `input:connected` | `input_id`, `connected_at` | RTMP stream begins pushing (detected via MediaLive InputState or health report) |
| `input:disconnected` | `input_id`, `disconnected_at` | RTMP stream stops pushing |
| `input:activated` | `input_id` | Input brought on-screen via POST /inputs/{id}/activate |
| `input:deactivated` | `input_id` | Input removed from layout via POST /inputs/{id}/deactivate |
| `layout:changed` | `mode`, `positions: list[dict]`, `primary_input_id`, `input_ids: list[str]` | Layout mode switched via POST /layout |
| `guest:invited` | `invite_id`, `input_id`, `join_mode`, `expires_at` | Guest invite created via POST /guest-invites |
| `guest:accepted` | `invite_id`, `input_id`, `guest_display_name`, `guest_user_id` | Guest accepted invite |
| `guest:removed` | `input_id`, `reason` | Guest removed by broadcaster |
| `guest:muted` | `input_id`, `muted: bool` | Guest muted/unmuted by broadcaster |
| `guest:promoted` | `input_id`, `new_primary_input_id` | Guest promoted to primary |

**Example SSE event payloads:**

```json
// layout:changed
{
  "_type": "layout:changed",
  "mode": "side_by_side",
  "positions": [
    {"input_id": "inp_001", "x": 0.0, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0},
    {"input_id": "inp_002", "x": 0.5, "y": 0.0, "width": 0.5, "height": 1.0, "z_index": 0}
  ],
  "primary_input_id": "inp_001",
  "input_ids": ["inp_001", "inp_002"]
}

// input:connected
{
  "_type": "input:connected",
  "input_id": "inp_002",
  "connected_at": 1748476800
}

// guest:accepted
{
  "_type": "guest:accepted",
  "invite_id": "inv_789",
  "input_id": "inp_002",
  "guest_display_name": "Alex",
  "guest_user_id": "user_xyz"
}
```

### 3.11 MediaLive InputSwitch ScheduleAction JSON

The `schedule_input_switch()` function creates this MediaLive API payload:

```json
{
  "ChannelId": "12345",
  "Creates": {
    "ScheduleActions": [
      {
        "ActionName": "switch-to-input-1-1748476800",
        "ScheduleActionStartSettings": {
          "ImmediateModeScheduleActionStartSettings": {}
        },
        "ScheduleActionSettings": {
          "InputSwitchSettings": {
            "InputAttachmentNameReference": "abc123-input-1-attach",
            "InputClippingSettings": null,
            "UrlPath": []
          }
        }
      }
    ]
  }
}
```

`ImmediateModeScheduleActionStartSettings` (empty object) tells MediaLive to execute the switch immediately. The `InputAttachmentNameReference` must match the `InputAttachmentName` used when attaching the input to the channel. Each action must have a unique `ActionName` (timestamp-based to avoid collisions).

### 3.12 Frontend Types

Add to `frontend/src/api/types.ts`:

```typescript
// ─── Multi-Input / Co-Streaming (BCAST-016) ─────────────────

export interface BroadcastInput {
  input_id: string;
  session_id: string;
  input_type: "primary" | "guest" | "screen";
  label: string;
  ingest_url: string | null;
  stream_key_ref: string | null;
  aws_input_arn: string | null;
  is_live: boolean;
  connected_at: number | null;
  disconnected_at: number | null;
  position: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  relay_mode: "rtmp" | "webrtc_relay" | null;
}

export type BroadcastLayoutMode = "single" | "side_by_side" | "pip" | "grid";

export interface BroadcastLayoutPosition {
  input_id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  z_index: number;
}

export interface BroadcastLayoutConfig {
  mode: BroadcastLayoutMode;
  positions: BroadcastLayoutPosition[];
  primary_input_id: string | null;
  input_ids: string[];
}

export interface BroadcastGuestInvite {
  invite_id: string;
  session_id: string;
  input_id: string;
  invite_url: string | null;
  ingest_url: string | null;
  stream_key: string | null;
  join_mode: "rtmp" | "browser";
  status: "pending" | "accepted" | "expired" | "revoked";
  guest_user_id: string | null;
  guest_display_name: string | null;
  expires_at: number;
  accepted_at: number | null;
  created_at: string;
}

export interface BroadcastInputListResponse {
  session_id: string;
  inputs: BroadcastInput[];
  count: number;
  max_inputs: number;
}

export interface BroadcastInputCreateResponse {
  input_id: string;
  session_id: string;
  input_type: string;
  label: string;
  ingest_url: string;
  stream_key: string;
  aws_input_arn: string | null;
  position: number;
}

export interface BroadcastGuestInviteListResponse {
  session_id: string;
  invites: BroadcastGuestInvite[];
  count: number;
}
```

Extend `BroadcastSession` interface in `broadcast.ts`:

```typescript
// Add to existing BroadcastSession interface:
max_inputs?: number;
active_layout?: BroadcastLayoutMode | null;
active_input_ids?: string[] | null;
primary_input_id?: string | null;
guest_invite_enabled?: boolean;
```

### 3.13 Frontend API Endpoints

Add to `frontend/src/api/endpoints/broadcast.ts`:

```typescript
// ─── Multi-Input API (BCAST-016) ──────────────────────────────

export const listInputs = (sessionId: string) =>
  api.get<BroadcastInputListResponse>(`/broadcast/sessions/${sessionId}/inputs`);

export const addInput = (sessionId: string, body: { input_type?: string; label?: string }) =>
  api.post<BroadcastInputCreateResponse>(`/broadcast/sessions/${sessionId}/inputs`, body);

export const removeInput = (sessionId: string, inputId: string) =>
  api.del<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/inputs/${inputId}`);

export const switchLayout = (sessionId: string, body: {
  mode: BroadcastLayoutMode;
  primary_input_id?: string;
  input_ids?: string[];
}) =>
  api.post<BroadcastLayoutConfig>(`/broadcast/sessions/${sessionId}/layout`, body);

export const getLayout = (sessionId: string) =>
  api.get<BroadcastLayoutConfig>(`/broadcast/sessions/${sessionId}/layout`);

export const createGuestInvite = (sessionId: string, body: {
  join_mode?: "rtmp" | "browser";
  label?: string;
  expiry_minutes?: number;
}) =>
  api.post<BroadcastGuestInvite>(`/broadcast/sessions/${sessionId}/guest-invites`, body);

export const listGuestInvites = (sessionId: string) =>
  api.get<BroadcastGuestInviteListResponse>(`/broadcast/sessions/${sessionId}/guest-invites`);

export const acceptGuestInvite = (sessionId: string, inviteId: string, body: { display_name: string }) =>
  api.post<{ invite_id: string; input_id: string }>(`/broadcast/sessions/${sessionId}/guest-invites/${inviteId}/accept`, body);

export const revokeGuestInvite = (sessionId: string, inviteId: string) =>
  api.post<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/guest-invites/${inviteId}/revoke`);

export const removeGuest = (sessionId: string, inputId: string) =>
  api.post<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/guests/${inputId}/remove`);

export const muteGuest = (sessionId: string, inputId: string, muted: boolean) =>
  api.post<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/guests/${inputId}/mute`, { muted });

export const promoteGuest = (sessionId: string, inputId: string) =>
  api.post<{ ok: boolean }>(`/broadcast/sessions/${sessionId}/guests/${inputId}/promote`);
```

### 3.14 Frontend Components

#### InputManager.tsx

Broadcaster panel showing all inputs with live/offline status, ingest URLs, and controls:

```
+--------------------------------------------+
| Inputs (3/4)                    [+ Add]     |
+--------------------------------------------+
| [thumb]  Primary Camera          LIVE       |
|          rtmp://...input-0  [Copy]          |
| [thumb]  Guest: Alex             LIVE       |
|          rtmp://...input-1  [Mute][Remove]  |
| [thumb]  Screen Share           OFFLINE      |
|          rtmp://...input-2  [Copy] [x]      |
+--------------------------------------------+
```

Uses `useQuery(["broadcast", "inputs", sessionId])` with 5s refetch. The [+ Add] button opens a popover with "Add RTMP Input", "Invite Guest (Browser)", "Invite Guest (RTMP)", "Add Screen Share". Disabled when input count >= max_inputs. Each input row shows:
- A status badge (LIVE green pulse / OFFLINE gray / CONNECTING yellow)
- The label and input type
- Copy button for ingest URL
- Controls: Mute/Remove for guests, Delete for non-primary inputs
- The primary input (position 0) cannot be removed

SSE events (`input:connected`, `input:disconnected`) update the `is_live` field in real time via React Query cache mutation in `useMessagingStream.ts` (extended for broadcast events).

#### LayoutSwitcher.tsx

Layout mode picker with visual previews:

```
+----------------------------------------------+
| Layout                                        |
| [Full] [Side] [PiP] [Grid]                   |
|  (*)    [ ]    [ ]   [ ]                      |
| Primary: [Input 0: Primary Camera v]          |
+----------------------------------------------+
```

Each mode shows a miniature visual preview (4 SVG icons representing the layout geometry). Disabled modes show tooltips ("Requires 2+ live inputs"). On change, calls `POST /sessions/{id}/layout` via `useMutation`. The "Primary" dropdown is only visible for PiP mode.

#### GuestInviteDialog.tsx

Dialog for creating and managing guest invite links. Two tabs: "Create Invite" and "Active Invites".

Create tab:
- Radio group: "Browser (no software needed)" / "OBS/RTMP (higher quality)"
- Label text input (default "Guest")
- Expiry duration dropdown: 15m, 30m, 1h, 4h, 24h
- Create button -> POST /guest-invites

After creation:
- Browser mode: shows a copyable invite URL (`{origin}/broadcast/{sessionId}/guest/{inviteId}`)
- RTMP mode: shows ingest URL + one-time stream key (with copy buttons and warning that the key is shown once)

Active invites tab:
- List of all invites with status badges (pending/accepted/expired/revoked)
- Revoke button for pending invites
- Timer showing time until expiry

#### GuestStreamPanel.tsx

Browser guest streaming UI rendered at `/broadcast/{sessionId}/guest/{inviteId}`. This is a standalone component that does not require the full BroadcastPage shell.

Flow:
1. Component loads, fetches invite status via `GET /guest-invites/{inviteId}`
2. If invite is not pending, shows appropriate message (expired/revoked/already accepted)
3. Shows camera preview via `getUserMedia()` using CALL-002/003 media capture patterns
4. Guest enters display name and clicks "Join Broadcast"
5. Calls `POST /guest-invites/{inviteId}/accept` with display name
6. Establishes WebRTC PeerConnection to relay server (send-only)
7. Shows "Broadcasting" indicator with mic/camera toggle and "Leave" button

Media controls:
- Mic toggle (mutes local audio track)
- Camera toggle (replaces video track with black frame)
- Leave button (stops all tracks, closes PeerConnection, shows "You have left")

#### GuestStreamPage.tsx

Thin route wrapper (~30 lines) extracting `sessionId` and `inviteId` from URL params:

```tsx
import { useParams } from "react-router-dom";
import GuestStreamPanel from "./GuestStreamPanel";

export default function GuestStreamPage() {
  const { sessionId, inviteId } = useParams<{ sessionId: string; inviteId: string }>();
  if (!sessionId || !inviteId) return <p>Invalid invite link</p>;
  return <GuestStreamPanel sessionId={sessionId} inviteId={inviteId} />;
}
```

#### BroadcastPage.tsx Changes

Add `InputManager` and `LayoutSwitcher` panels to the `SessionDetailDialog` component (after the "Playback" section, before "AWS Resources"):

```tsx
{/* Multi-Input Manager (BCAST-016) */}
{["ready", "live", "private"].includes(session.status) && (
  <>
    <InputManager sessionId={session.id} sessionStatus={session.status} />
    <LayoutSwitcher sessionId={session.id} sessionStatus={session.status} />
  </>
)}
```

Add "Invite Guest" button to the session card action bar (visible when status is ready/live).

### 3.15 Frontend Route

Add to `frontend/src/App.tsx`:

```typescript
const GuestStreamPage = lazy(() => import("@/pages/broadcast/GuestStreamPage"));

// In route definitions:
<Route path="/broadcast/:sessionId/guest/:inviteId" element={<GuestStreamPage />} />
```

This route does not require authentication -- guests may be unauthenticated users (the invite URL is a capability token). The accept endpoint requires any authenticated user, so the GuestStreamPanel will prompt for login if needed.

---

## 4. Implementation Plan

### Phase 1: Data Model + Storage Layer (2 days)

| File | Change | Est. Lines |
|------|--------|-----------|
| `app/models_broadcast.py` | Add `BroadcastInputModel`, `BroadcastGuestInvite`, `LayoutPosition`, `BroadcastLayoutConfig` models; extend `BroadcastSessionModel` with 5 new fields; extend `BroadcastActionAuditEventModel.action` Literal with 11 new values | +80 |
| `app/services/broadcast_store.py` | Extend `session_to_item()` lines 111-145 to serialize new session fields (`max_inputs`, `active_layout`, `active_input_ids`, `primary_input_id`, `guest_invite_enabled`); extend `session_from_item()` lines 148-179 to deserialize them with `.get()` defaults | +25 |
<!-- VERIFIED: broadcast_store.py session_to_item at line 111, session_from_item at line 148 -->
| `app/services/broadcast_input_store.py` | **New file**: input CRUD (`create_input`, `get_input`, `list_inputs`, `update_input`, `delete_input`, `mark_input_live`, `count_inputs`, `delete_all_inputs`), guest invite CRUD (`create_guest_invite`, `get_guest_invite`, `list_guest_invites`, `accept_guest_invite`, `revoke_guest_invite`, `expire_pending_invites`), layout operations (`save_layout`, `get_layout`) | ~320 |
| `scripts/local-ddb-init.py` | Add `BroadcastInputs` `TableDef` with 2 GSIs (`ByCreator`, `ByStatus`) and `attr_types={"expires_at": "N"}` | +15 |
| `app/core/settings.py` | Add 6 new settings: `broadcast_inputs_table_name`, `broadcast_max_inputs_per_session`, `broadcast_guest_invite_expiry_seconds`, `broadcast_webrtc_relay_enabled`, `broadcast_multi_input_enabled`, `broadcast_layout_switch_cooldown_seconds` | +8 |
| `app/core/tables.py` | Add `broadcast_inputs: Any` field and wire to `ddb.Table(S.broadcast_inputs_table_name)` | +4 |

### Phase 2: Multi-Input MediaLive + Layout Engine (2 days)

| File | Change | Est. Lines |
|------|--------|-----------|
| `app/services/broadcast_multi_input.py` | **New file**: `InputProvisionResult` dataclass, `create_additional_input()`, `attach_input_to_channel()`, `schedule_input_switch()`, `detach_input_from_channel()`, `delete_medialive_input()` | ~250 |
| `app/services/broadcast_layout.py` | **New file**: layout template functions (`_layout_single`, `_layout_side_by_side`, `_layout_pip`, `_layout_grid`), `switch_layout()` with validation, position computation, DDB persistence | ~220 |
| `app/services/broadcast_webrtc_relay.py` | **New file**: `start_relay()`, `stop_relay()`, `stop_all_relays_for_session()`, `get_relay_status()` with dev mock and production FFmpeg subprocess management | ~160 |

### Phase 3: Orchestrator Integration (1 day)

| File | Change | Est. Lines |
|------|--------|-----------|
| `app/services/broadcast_orchestrator.py` | In `start_session_with_provider()` (line 17): after provisioning, create primary input record in DDB via `broadcast_input_store.create_input()`. In `stop_session_with_provider()` (line 125): call `stop_all_relays_for_session()`, mark all inputs offline via `broadcast_input_store`, expire pending invites. In `delete_session_with_provider()` (line 178): call `delete_all_inputs()` | +45 |
<!-- VERIFIED: orchestrator.py start at 17, stop at 125, delete at 178 -->
| `app/services/broadcast_mediolive.py` | Export `_client()` and `_with_retry()` (already importable, just add `__all__` for clarity); add `_find_inputs_by_session()` helper for multi-input teardown | +15 |
<!-- VERIFIED: mediolive.py _client at 42, _with_retry at 52 -->
| `app/services/broadcast_provider.py` | In `AwsBroadcastProvider.teardown()` (line 381): iterate and delete all inputs matching pattern `broadcast-{session.id}-input-*` (not just the single primary) | +20 |
<!-- VERIFIED: provider.py teardown at line 381 -->

### Phase 4: API Endpoints (3 days)

| File | Change | Est. Lines |
|------|--------|-----------|
| `app/routers/broadcast.py` | Add 16 new endpoints with Pydantic request/response models, auth checks, input validation, SSE event publishing, and audit recording. Endpoints listed in section 3.8 | +550 |

### Phase 5: Frontend (3-4 days)

| File | Change | Est. Lines |
|------|--------|-----------|
| `frontend/src/api/types.ts` | Add `BroadcastInput`, `BroadcastLayoutMode`, `BroadcastLayoutPosition`, `BroadcastLayoutConfig`, `BroadcastGuestInvite`, and response interfaces | +60 |
| `frontend/src/api/endpoints/broadcast.ts` | Add 13 new endpoint functions (`listInputs`, `addInput`, `removeInput`, `switchLayout`, `getLayout`, `createGuestInvite`, `listGuestInvites`, `acceptGuestInvite`, `revokeGuestInvite`, `removeGuest`, `muteGuest`, `promoteGuest`), extend `BroadcastSession` interface | +90 |
| `frontend/src/pages/broadcast/InputManager.tsx` | **New file**: input list panel with live/offline status, ingest URL copy, add popover, mute/remove controls | ~220 |
| `frontend/src/pages/broadcast/LayoutSwitcher.tsx` | **New file**: layout mode radio group with SVG previews, primary input dropdown, mutation hook | ~170 |
| `frontend/src/pages/broadcast/GuestInviteDialog.tsx` | **New file**: create invite form (join mode, label, expiry), invite list with revoke, copy invite URL/stream key | ~200 |
| `frontend/src/pages/broadcast/GuestStreamPanel.tsx` | **New file**: browser guest streaming UI with getUserMedia, WebRTC PeerConnection, media controls (mic/camera/leave) | ~250 |
| `frontend/src/pages/broadcast/GuestStreamPage.tsx` | **New file**: thin route wrapper extracting params | ~30 |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Add InputManager + LayoutSwitcher to SessionDetailDialog (after Playback, before AWS Resources). Add "Invite Guest" button to session card actions | +65 |
| `frontend/src/App.tsx` | Add guest stream route: `<Route path="/broadcast/:sessionId/guest/:inviteId" .../>` | +5 |

### Phase 6: E2E Tests (2 days)

| File | Change | Est. Lines |
|------|--------|-----------|
| `frontend/e2e/broadcast-multi-input.spec.ts` | **New file**: sections 140-148, 25+ tests covering input CRUD API, guest invite lifecycle, layout switching, UI components | ~550 |

### Summary of All Files Modified/Created

| File | Type | Est. Lines Changed |
|------|------|-------------------|
| `app/models_broadcast.py` | Modify | +80 |
| `app/services/broadcast_store.py` | Modify | +25 |
| `app/services/broadcast_input_store.py` | Create | ~320 |
| `app/services/broadcast_multi_input.py` | Create | ~250 |
| `app/services/broadcast_layout.py` | Create | ~220 |
| `app/services/broadcast_webrtc_relay.py` | Create | ~160 |
| `app/services/broadcast_orchestrator.py` | Modify | +45 |
| `app/services/broadcast_mediolive.py` | Modify | +15 |
| `app/services/broadcast_provider.py` | Modify | +20 |
| `app/routers/broadcast.py` | Modify | +550 |
| `app/core/settings.py` | Modify | +8 |
| `app/core/tables.py` | Modify | +4 |
| `scripts/local-ddb-init.py` | Modify | +15 |
| `frontend/src/api/types.ts` | Modify | +60 |
| `frontend/src/api/endpoints/broadcast.ts` | Modify | +90 |
| `frontend/src/pages/broadcast/InputManager.tsx` | Create | ~220 |
| `frontend/src/pages/broadcast/LayoutSwitcher.tsx` | Create | ~170 |
| `frontend/src/pages/broadcast/GuestInviteDialog.tsx` | Create | ~200 |
| `frontend/src/pages/broadcast/GuestStreamPanel.tsx` | Create | ~250 |
| `frontend/src/pages/broadcast/GuestStreamPage.tsx` | Create | ~30 |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | Modify | +65 |
| `frontend/src/App.tsx` | Modify | +5 |
| `frontend/e2e/broadcast-multi-input.spec.ts` | Create | ~550 |
| **Total** | | **~3352** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_multi_input.py`)

New file, ~400 lines. Tests with moto-mocked DynamoDB and mocked MediaLive client.

**Input store tests (8 tests):**

| Test | What It Verifies |
|------|------------------|
| `test_create_input_stores_record` | `input_id` has `inp_` prefix, session_id matches, input_type set, `is_live=False` by default |
| `test_create_input_sets_timestamps` | `created_at` and `updated_at` are ISO strings, not empty |
| `test_list_inputs_sorted_by_position` | Create 3 inputs with positions 2, 0, 1; verify returned in 0, 1, 2 order |
| `test_mark_input_live_sets_connected_at` | `is_live=True`, `connected_at` is a valid Unix timestamp > 0 |
| `test_mark_input_offline_sets_disconnected_at` | `is_live=False`, `disconnected_at` populated, `connected_at` preserved |
| `test_count_inputs_returns_correct_count` | Create 3 inputs, verify `count_inputs()` returns 3 |
| `test_delete_input_removes_record` | Delete an input, verify `get_input()` raises 404 |
| `test_delete_all_inputs_clears_session` | Create 3 inputs + 2 invites, verify `delete_all_inputs()` removes all 5 records |

**Guest invite tests (7 tests):**

| Test | What It Verifies |
|------|------------------|
| `test_create_guest_invite_pending` | Status is "pending", `invite_id` has `inv_` prefix, `expires_at` is in the future |
| `test_accept_guest_invite_fills_guest_fields` | `guest_user_id`, `guest_display_name`, `accepted_at` are set; status is "accepted" |
| `test_accept_expired_invite_returns_410` | Create with `expires_at` in the past, verify HTTPException with status 410 |
| `test_accept_already_accepted_invite_returns_409` | Accept twice, verify second call raises HTTPException with status 409 |
| `test_revoke_guest_invite` | Status changes to "revoked"; attempting to accept a revoked invite fails |
| `test_list_guest_invites_status_filter` | Create 3 invites (pending, accepted, revoked), filter by status returns correct subset |
| `test_expire_pending_invites_batch` | Create 3 pending invites, expire all, verify all have status "expired" |

**Layout engine tests (8 tests):**

| Test | What It Verifies |
|------|------------------|
| `test_layout_single_one_input` | Single input at full screen: x=0, y=0, width=1.0, height=1.0 |
| `test_layout_side_by_side_two_inputs` | Two inputs each at 50% width: first at x=0, second at x=0.5 |
| `test_layout_pip_primary_full_secondary_overlay` | Primary at width=1.0, secondary at x=0.7, y=0.7, width=0.28, height=0.28, z_index=1 |
| `test_layout_grid_1_input` | Full screen (width=1.0, height=1.0) |
| `test_layout_grid_2_inputs` | Each at 50% width, 100% height (1 row) |
| `test_layout_grid_4_inputs` | 2x2 grid: each at 50% width, 50% height |
| `test_switch_layout_rejects_non_live_session` | Session status "draft" -> HTTPException 409 |
| `test_switch_layout_rejects_insufficient_inputs` | `side_by_side` with 1 input -> HTTPException 400 |

**Multi-input MediaLive tests (5 tests):**

| Test | What It Verifies |
|------|------------------|
| `test_create_additional_input_returns_result` | `InputProvisionResult` has non-empty `input_id`, `input_arn`, `ingest_url` |
| `test_attach_input_to_channel_appends_attachment` | Channel's InputAttachments list grows by 1 |
| `test_detach_input_from_channel_removes_attachment` | Channel's InputAttachments list shrinks by 1 |
| `test_schedule_input_switch_creates_action` | BatchUpdateSchedule called with ImmediateMode action |
| `test_delete_medialive_input_succeeds` | No exception raised; subsequent describe returns NotFoundException |

**WebRTC relay tests (3 tests):**

| Test | What It Verifies |
|------|------------------|
| `test_start_relay_dev_mode_returns_mock_sdp` | Returns status "started" with mock SDP answer |
| `test_stop_relay_removes_from_active` | After stop, `get_relay_status()` returns None |
| `test_stop_all_relays_for_session` | All relays for a session are stopped; other sessions unaffected |

### 5.2 E2E Tests (`frontend/e2e/broadcast-multi-input.spec.ts`)

New file, ~550 lines, sections 140-148.

**Section 140: Multi-Input CRUD API (6 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 140.1 | `POST /inputs creates new input with ingest URL` | Returns 201 with `input_id`, `ingest_url`, one-time `stream_key`, `position` |
| 140.2 | `GET /inputs lists all inputs sorted by position` | Returns inputs array sorted by position; primary is position 0 |
| 140.3 | `DELETE /inputs/{input_id} removes non-primary input` | Returns 200; subsequent GET shows reduced count |
| 140.4 | `DELETE /inputs/{primary_input_id} returns 400` | Cannot remove primary input (position 0) |
| 140.5 | `POST /inputs at max_inputs returns 400` | After creating max_inputs, next creation returns 400 with limit message |
| 140.6 | `POST /inputs on stopped session returns 409` | Trying to add input to stopped session fails |

**Section 141: Guest Invite Lifecycle API (6 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 141.1 | `POST /guest-invites creates invite with browser join_mode` | Returns 201 with `invite_id`, `invite_url`, status "pending" |
| 141.2 | `POST /guest-invites creates invite with rtmp join_mode` | Returns 201 with `ingest_url` and one-time `stream_key` |
| 141.3 | `POST /guest-invites/{id}/accept sets guest fields` | Status changes to "accepted"; `guest_user_id` and `guest_display_name` set |
| 141.4 | `Accept expired invite returns 410` | Create with 5min expiry, wait/mock expiry, accept returns 410 |
| 141.5 | `POST /guest-invites/{id}/revoke sets status revoked` | Status changes to "revoked"; accepting revoked invite fails |
| 141.6 | `GET /guest-invites lists all with status` | Returns all invites with correct status values |

**Section 142: Layout Engine API (5 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 142.1 | `POST /layout single mode returns full-screen position` | Position: x=0, y=0, width=1.0, height=1.0 |
| 142.2 | `POST /layout pip positions with primary full-screen` | Primary at width=1.0, secondary at 0.28x0.28 overlay |
| 142.3 | `POST /layout grid with 4 inputs returns 2x2 positions` | Four positions, each 0.5x0.5 |
| 142.4 | `POST /layout on non-live session returns 409` | Session must be live |
| 142.5 | `POST /layout side_by_side with 1 input returns 400` | Requires at least 2 inputs |

**Section 143: Guest Management API (4 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 143.1 | `POST /guests/{input_id}/remove marks input offline and SSE` | Input `is_live` set to false; guest invite status unchanged |
| 143.2 | `POST /guests/{input_id}/mute publishes SSE event` | Returns 200; would verify SSE event via concurrent listener |
| 143.3 | `POST /guests/{input_id}/promote switches layout to single` | Layout mode becomes "single" with promoted input as primary |
| 143.4 | `Non-owner cannot manage guests` | Different user_sub returns 403 |

**Section 144: WebRTC Signaling API (3 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 144.1 | `POST /inputs/{input_id}/webrtc-offer returns SDP answer` | In dev mode, returns mock SDP answer |
| 144.2 | `WebRTC offer for non-guest user returns 403` | Only the accepted guest's user_sub can send offers |
| 144.3 | `WebRTC offer for non-existent input returns 404` | Input must exist |

**Section 145: Session Lifecycle Integration (3 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 145.1 | `Stop session expires pending invites` | All pending invites set to "expired" after session stop |
| 145.2 | `Stop session marks all inputs offline` | All inputs have `is_live=false` after session stop |
| 145.3 | `Delete session removes all input and invite records` | GET /inputs returns empty after session deletion |

**Section 146: Multi-Input UI - InputManager (3 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 146.1 | `InputManager visible on live session` | Panel renders with "Inputs (N/M)" heading |
| 146.2 | `Add input button creates new row in InputManager` | Clicking "+ Add" -> "Add RTMP Input" creates new input row |
| 146.3 | `Copy ingest URL button copies to clipboard` | Click copy button, verify toast "Copied to clipboard" |

**Section 147: Multi-Input UI - LayoutSwitcher (3 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 147.1 | `LayoutSwitcher shows 4 mode buttons` | "Full", "Side", "PiP", "Grid" buttons visible |
| 147.2 | `Clicking Side mode with 2 inputs switches layout` | Layout mode changes; positions update |
| 147.3 | `Disabled mode shows tooltip` | PiP button disabled when only 1 input; tooltip visible on hover |

**Section 148: Multi-Input UI - GuestInviteDialog (3 tests)**

| # | Test Name | What It Verifies |
|---|-----------|------------------|
| 148.1 | `Guest invite dialog creates browser invite` | Opens dialog, selects browser mode, clicks Create, shows invite URL |
| 148.2 | `Guest invite dialog shows active invites` | Switches to Active tab, sees pending invite with revoke button |
| 148.3 | `Revoke button sets invite to revoked` | Click Revoke, status badge changes to "revoked" |

**Total E2E tests: 36 across 9 sections (140-148).**

### 5.3 Edge Cases Matrix

| # | Edge Case | Expected Behavior | How Tested |
|---|-----------|-------------------|-----------|
| 1 | Add input to stopped session | 409 "Cannot add inputs when session is stopped" | E2E 140.6 |
| 2 | Remove input that is in active layout | Layout falls back to `single` with primary; SSE `layout:changed` | Unit test |
| 3 | Two users accept same invite | First succeeds; second gets 409 "already accepted" | E2E 141.3 (idempotency) |
| 4 | Guest invite expires during acceptance | 410 returned; invite auto-set to "expired" | E2E 141.4 |
| 5 | WebRTC relay crashes mid-stream | Input marked offline; SSE `input:disconnected`; broadcaster sees offline indicator | Unit test (mock) |
| 6 | Primary input disconnects | Session stays live; layout switches to next available input if in multi-input mode | Unit test |
| 7 | All inputs disconnect | Session stays live (channel running); viewers see frozen/black frame | Manual test |
| 8 | Session stops with active guests | `stop_session_with_provider` terminates all relays, marks inputs offline, expires invites | E2E 145.1-145.2 |
| 9 | Layout switch during recording | Recording captures the composed output; layout change is reflected in recording | Manual test |
| 10 | Add input during live session | MediaLive hot-attach; input appears offline until RTMP push begins | E2E 140.1 |
| 11 | Remove guest while in PiP layout as secondary | Layout falls back to single with primary; SSE events for both input:removed and layout:changed | Unit test |
| 12 | Guest disconnects and reconnects | `input:disconnected` followed by `input:connected`; layout unchanged | Unit test |
| 13 | Max inputs reached, guest invite creation blocked | Cannot create invite if creating the input would exceed max_inputs | E2E (implied by 140.5) |
| 14 | Concurrent layout switch requests | Second request wins (last-write-wins); no DDB conditional check needed for layout | Load test |
| 15 | Guest sends WebRTC offer before accepting invite | 403 -- must accept first to associate user_sub with the invite | E2E 144.2 |

### 5.4 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| MediaLive API calls in E2E tests | Dev mode uses `LocalBroadcastProvider` which returns mock results; no real AWS calls |
| WebRTC relay processes in CI | Dev mode uses mock relay (no FFmpeg subprocess spawning) |
| SSE event ordering in tests | Tests use `waitForResponse` on API calls, not SSE events; SSE is fire-and-forget |
| DDB eventual consistency | All gets use `ConsistentRead=True` (matching existing broadcast store pattern at line 104, 213) |
<!-- VERIFIED: broadcast_store.py:104 get_profile ConsistentRead=True, :213 get_session ConsistentRead=True -->
| Input count race conditions | `count_inputs()` uses `Select='COUNT'` with `ConsistentRead=True`; add + count in same request handler |
| Invite expiry timing | Tests either mock time or use sufficiently long expiry; no 1-second timing windows |
| Guest media device access in CI | GuestStreamPanel E2E tests mock `getUserMedia()` at the browser level via `page.addInitScript()` |

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

| Operation | Required Auth | Enforcement |
|-----------|---------------|-------------|
| Input management (add/remove/list) | Session owner (`ctx["user_sub"] == session.created_by`) | Same ownership check as scheduling endpoints (line 1716) |
<!-- CORRECTED: was "line 1717", actually line 1716 where ownership check is -->
| Layout switching | Session owner | Same as input management |
| Guest invite creation | Session owner | Same as input management |
| Guest invite acceptance | Any authenticated user with valid `invite_id` | The invite URL is a capability token shared by the broadcaster |
| Guest invite listing | Session owner | Owner-only to prevent information leakage |
| WebRTC signaling | Guest user whose `user_sub` matches the invite's `guest_user_id` | Prevents media injection by unauthorized users |
| Guest management (mute/remove/promote) | Session owner | Same as input management |

### 6.2 Input Validation

| Field | Validation | Enforcement |
|-------|-----------|-------------|
| `max_inputs` | Server-enforced cap: `ge=1, le=8`, default 4 | Checked on every `POST /inputs` before provisioning |
| Layout `mode` | Must be in `{"single", "side_by_side", "pip", "grid"}` | Validated by Pydantic Literal type |
| Layout coordinates | `x`, `y` in `[0.0, 1.0]`; `width`, `height` in `(0.0, 1.0]` | Validated by Pydantic Field constraints |
| `input_ids` in layout | Must be input_ids belonging to the same session | Cross-validated against DDB records |
| `expiry_minutes` | `ge=5, le=1440` (5 minutes to 24 hours) | Prevents perpetual invite links |
| `label` | `max_length=100` | Prevents oversized display names |
| `display_name` | `min_length=1, max_length=100` | Prevents empty or oversized guest names |
| `sdp_offer` | `max_length=65536` | Prevents oversized SDP payloads |

### 6.3 Abuse Vector Analysis

| # | Abuse Vector | Impact | Mitigation |
|---|-------------|--------|-----------|
| 1 | Invite link leaking (shared publicly) | Unauthorized user joins broadcast | Only one user can accept a given invite; invites auto-expire; broadcaster can revoke; invite_id is a random UUID (128 bits of entropy) |
| 2 | Guest RTMP flooding (high bitrate) | Channel bandwidth exhaustion, viewer quality degradation | MediaLive enforces per-input bitrate limits; broadcaster can remove guest instantly; health monitoring alerts on bitrate spikes |
| 3 | Input creation spam (rapid POST /inputs) | MediaLive resource exhaustion, DDB write capacity consumed | Rate-limited via existing request metrics middleware (10 req/min/user); `max_inputs` cap prevents unbounded growth |
| 4 | Relay resource exhaustion (many browser guests) | Server memory/CPU from FFmpeg processes | Max 1 relay per input, max `max_inputs` relays per session; relay processes have memory limits |
| 5 | Layout switch flooding (rapid POST /layout) | MediaLive ScheduleAction queue overflow | `broadcast_layout_switch_cooldown_seconds` (default 2s) enforced server-side; rapid switches coalesced |
| 6 | Expired invite replay attack | User attempts to accept an expired invite | `expires_at` checked on accept; expired invites return 410 |
| 7 | Cross-session input reference | User sends `input_ids` from a different session | Validated that all `input_ids` belong to the target session's PK |
| 8 | Guest WebRTC media injection | Attacker sends media to another guest's input | WebRTC signaling validates `guest_user_id` matches the invite's accepted user |

### 6.4 Rate Limiting Per Endpoint

| Endpoint | Rate Limit | Rationale |
|----------|-----------|-----------|
| `POST /inputs` | 10/min/session | Matches max_inputs cap; prevents rapid provisioning |
| `POST /layout` | 30/min/session | Layout switches should be infrequent but not blocked |
| `POST /guest-invites` | 10/min/session | Matches max_inputs cap |
| `POST /guest-invites/{id}/accept` | 5/min/user | Prevents brute-force invite ID guessing |
| `POST /inputs/{id}/webrtc-offer` | 10/min/user | WebRTC renegotiation may require multiple offers |
| `POST /guests/{id}/mute` | 30/min/session | Rapid mute/unmute should be responsive |

### 6.5 Stream Key Security

For RTMP guest invites, the stream key lifecycle:

1. **Generation**: MediaLive generates the stream key during `create_input()` (AWS-managed, returned in `Destinations[0].StreamName`).
2. **One-time delivery**: The stream key is returned in the `POST /guest-invites` response as a plain string. It is NOT stored in the invite DDB record.
3. **Persistence**: Only the `stream_key_ref` (Secrets Manager ARN or SSM parameter name) is stored in DDB, matching the existing primary input pattern (`enforce_secret_reference_only()` at `broadcast_store.py:191`).
<!-- VERIFIED: broadcast_store.py:191 enforce_secret_reference_only("stream_key_ref", stream_key_ref) -->
4. **Dev mode exception**: In dev mode (`S.dev_mode=True`), plaintext keys are allowed since the MediaLive mock does not support Secrets Manager.
5. **Rotation**: Guest stream keys are not rotated (invites are short-lived). The `stream_key_rotation_interval_seconds` field on `BroadcastSessionModel` applies only to the primary input.

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table Creation in `local-ddb-init.py`

Add the following `TableDef` to the broadcast tables section (after line 783 in `scripts/local-ddb-init.py`):
<!-- VERIFIED: scripts/local-ddb-init.py:783 is BroadcastPrivateSessions TableDef -->

```python
# Broadcast Multi-Input (BCAST-016)
TableDef(
    _resolve_table_name(
        os.environ.get("DDB_BROADCAST_INPUTS", "BroadcastInputs"),
        "BroadcastInputs",
    ),
    "pk",   # SESSION#{session_id}
    "sk",   # INPUT#{input_id} | INVITE#{invite_id} | LAYOUT
    gsis=[
        {
            "index_name": "ByCreator",
            "partition_key": "created_by",
            "sort_key": "created_at",
        },
        {
            "index_name": "ByStatus",
            "partition_key": "invite_status",
            "sort_key": "expires_at",
        },
    ],
    attr_types={"expires_at": "N"},
),
```

**Important**: The `expires_at` sort key in the `ByStatus` GSI is numeric (Unix timestamp), so `attr_types={"expires_at": "N"}` is required. Without this, DynamoDB stores it as String, causing `ValidationException` when queried with integer values (see CLAUDE.md gotcha about numeric GSI sort keys).

In production: Create the table before code deployment using the same schema. Use CloudFormation or `aws dynamodb create-table` with the exact key schema and GSI definitions.

### 7.2 Feature Flags

| Flag | Env Var | Default | Purpose |
|------|---------|---------|---------|
| Multi-input enabled | `BROADCAST_MULTI_INPUT_ENABLED` | `true` | Master switch for multi-input endpoints; set to `false` to disable all multi-input API |
| Max inputs per session | `BROADCAST_MAX_INPUTS_PER_SESSION` | `4` | Set to `1` to effectively disable multi-input while keeping code deployed |
| WebRTC relay enabled | `BROADCAST_WEBRTC_RELAY_ENABLED` | `false` | Enable browser-based guest connections; disabled by default (requires FFmpeg) |
| Guest invite expiry | `BROADCAST_GUEST_INVITE_EXPIRY_SECONDS` | `3600` | Default invite link expiry duration |
| Layout switch cooldown | `BROADCAST_LAYOUT_SWITCH_COOLDOWN_SECONDS` | `2` | Minimum seconds between layout switches |

### 7.3 Backward Compatibility Analysis

| Component | Impact | Risk |
|-----------|--------|------|
| `BroadcastSessionModel` | 5 new optional fields with defaults | **None**: `session_from_item()` uses `.get()` with defaults; existing items work unchanged |
| `BroadcastSessionOut` | 5 new optional fields | **None**: API consumers that don't expect these fields ignore them (JSON forward-compat) |
| `BroadcastActionAuditEventModel` | 11 new Literal values added to `action` | **None**: Pydantic Literal is output-side; existing audit queries don't filter by action type |
| Frontend `BroadcastSession` interface | 5 new optional fields | **None**: TypeScript optional fields are backward-compatible |
| `BroadcastInputs` table | New table, no changes to existing tables | **None**: New table is additive |
| `broadcast_mediolive.py` | No changes to existing functions | **None**: `provision_mediolive_input_and_channel()` unchanged |
| `broadcast_orchestrator.py` | Additional operations in start/stop/delete | **Low**: New operations are additive (create primary input record, cleanup); if they fail, existing behavior is preserved |
| SSE events | New event types | **None**: Frontend SSE handlers ignore unknown event types |

### 7.4 Rollback Steps

1. **Immediate mitigation**: Set `BROADCAST_MAX_INPUTS_PER_SESSION=1` to disable new input creation. Existing sessions continue with current inputs.
2. **Active sessions**: Multi-input sessions that are already live continue to work until they stop. Layout remains at whatever was last set.
3. **Frontend rollback**: Revert the frontend bundle. InputManager, LayoutSwitcher, and GuestInviteDialog are self-contained components that don't affect the rest of BroadcastPage.
4. **Backend rollback**: Revert backend code. The new endpoints return 404 (router not registered). `BroadcastInputs` table remains with orphaned data but is harmless -- no existing code reads it.
5. **Data cleanup** (optional): Run a cleanup script to delete all records from the `BroadcastInputs` table:
   ```python
   # scripts/cleanup_broadcast_inputs.py
   import boto3
   ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001")
   table = ddb.Table("BroadcastInputs")
   scan = table.scan(Select="ALL_ATTRIBUTES")
   with table.batch_writer() as batch:
       for item in scan.get("Items", []):
           batch.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
   ```
6. **Table deletion** (optional, production only): Drop the `BroadcastInputs` table after confirming no code references it.

### 7.5 Deployment Order

1. Create `BroadcastInputs` DDB table (production: CloudFormation/CLI; dev: `local-ddb-init.py` handles it)
2. Deploy backend with `BROADCAST_MAX_INPUTS_PER_SESSION=1` (code deployed but effectively disabled)
3. Deploy frontend (new components are lazy-loaded and won't render without backend support)
4. Set `BROADCAST_MAX_INPUTS_PER_SESSION=4` to enable multi-input
5. Monitor error rates and SSE event delivery for 1 hour
6. Set `BROADCAST_WEBRTC_RELAY_ENABLED=true` to enable browser guests (requires FFmpeg on server)

---

## 8. Acceptance Criteria

### Multi-Input Provisioning

1. A broadcaster can add up to `max_inputs` (default 4) RTMP inputs via `POST /sessions/{id}/inputs`. Each input receives a unique `input_id`, `ingest_url`, and MediaLive input ARN.
2. The primary input (position 0) is created automatically during session provisioning by the orchestrator and cannot be removed via the API.
3. Inputs can be added to sessions in `draft`, `scheduled`, `ready`, or `live` status. Adding to `stopped`, `cancelled`, or `error` returns 409 with the current status in the error message.
4. Removing an input detaches it from the MediaLive channel, deletes the MediaLive resource, and removes the DDB record. If the removed input was in the active layout, layout falls back to `single` with the primary input.
5. `GET /sessions/{id}/inputs` returns all inputs sorted by position with `is_live` status, `ingest_url`, and `connected_at` timestamps.
6. Exceeding `max_inputs` returns 400 with the message "Maximum N inputs per session" where N is the configured limit.
7. Each input's `ingest_url` and one-time `stream_key` are returned on creation but the stream key is never returned again (only `stream_key_ref` is persisted).
8. The `count` and `max_inputs` fields in the list response allow the frontend to show "Inputs (3/4)" and disable the add button when full.

### Layout Switching

9. Four layout modes are available via `POST /sessions/{id}/layout`: `single` (full-screen), `side_by_side` (50/50 horizontal), `pip` (main + small overlay), `grid` (2x2 adaptive).
10. Layout switching is only permitted when session status is `live` or `private` (409 otherwise).
11. `side_by_side` and `pip` require at least 2 inputs (400 otherwise with descriptive message).
12. `pip` mode places `primary_input_id` full-screen (width=1.0, height=1.0) with the secondary input at bottom-right (x=0.7, y=0.7, width=0.28, height=0.28, z_index=1).
13. `grid` mode adaptively places 1-4 inputs: 1 input = full screen, 2 inputs = side by side, 3 inputs = 2x2 with one cell empty, 4 inputs = 2x2 grid.
14. The response includes computed `positions` with normalized coordinates (`x`, `y`, `width`, `height`, `z_index`).
15. Layout changes are broadcast to all SSE subscribers via `layout:changed` event with the full position set.
16. `GET /sessions/{id}/layout` returns the current layout configuration without modifying it.
17. A layout switch cooldown of `BROADCAST_LAYOUT_SWITCH_COOLDOWN_SECONDS` (default 2s) prevents rapid switching.

### Guest Co-Streaming

18. Broadcaster creates guest invites via `POST /sessions/{id}/guest-invites` with `join_mode` (browser/rtmp), `label`, and `expiry_minutes` (5-1440 range).
19. RTMP invites include `ingest_url` and one-time `stream_key` (not stored in plaintext in DDB).
20. Browser invites include `invite_url` pointing to `/broadcast/{sessionId}/guest/{inviteId}`.
21. Guest accepts via `POST /guest-invites/{invite_id}/accept` with `display_name`. Expired invites return 410; already-accepted return 409; revoked invites return 409.
22. Only one user can accept a given invite. The first `accept` call wins.
23. Broadcaster can revoke pending invites. Revoking an already-accepted invite does not disconnect the guest (use remove for that).
24. Broadcaster can remove an active guest via `POST /guests/{input_id}/remove`. This marks the input offline and publishes `guest:removed` SSE event.
25. Broadcaster can mute/unmute a guest via `POST /guests/{input_id}/mute`. This publishes `guest:muted` SSE event (audio control is client-side).
26. Promoting a guest via `POST /guests/{input_id}/promote` switches the layout to `single` with that guest's input as the primary.

### Browser Guest (WebRTC Relay)

27. When `BROADCAST_WEBRTC_RELAY_ENABLED=true`, browser guests use `getUserMedia()` + WebRTC PeerConnection to the relay server. The relay converts WebRTC to RTMP push to the guest's allocated MediaLive input.
28. In dev mode, relay is mocked. Signaling endpoints (`/webrtc-offer`, `/ice-candidate`) are functional for testing the handshake but no real media flows.
29. Relay terminates when the guest leaves, is removed by the broadcaster, or the session stops.
30. Only the accepted guest's `user_sub` can send WebRTC signaling messages to their assigned input (403 for others).

### Session Lifecycle Integration

31. On session stop: all relay processes terminated, all inputs marked `is_live=false` with `disconnected_at`, all pending invites set to "expired".
32. On session delete: all input, invite, and layout records deleted from `BroadcastInputs` table.
33. Primary input is created in `BroadcastInputs` during session provisioning; its `position=0` and `input_type="primary"`.

### SSE Event Delivery

34. All 12 SSE event types listed in section 3.10 are published via `broadcast_sse_publish()` at the appropriate trigger points.
35. SSE events are delivered to all connected subscribers within the same SSE queue timeout (15s ping interval).

### Testing

36. All E2E tests (sections 140-148) pass with 0 flakes on 3 consecutive runs.
37. Unit tests cover: input CRUD, guest invite lifecycle (including expiry and conflict), layout positions for all 4 modes, layout validation, PiP primary ordering, WebRTC relay mock, and multi-input MediaLive operations.
38. At least 36 E2E tests and 31 unit tests pass.

---

## 9. Error Handling Matrix

### API Error Responses

| Endpoint | Condition | HTTP Status | Error Code | Error Message |
|----------|----------|------------|------------|---------------|
| `POST /inputs` | Session not found | 404 | (FastAPI default) | "broadcast session not found" |
| `POST /inputs` | Not session owner | 403 | (inline) | "Only the broadcaster can add inputs." |
| `POST /inputs` | Session stopped/error/cancelled | 409 | (inline) | "Cannot add inputs when session is {status}." |
| `POST /inputs` | Max inputs reached | 400 | (inline) | "Maximum N inputs per session." |
| `POST /inputs` | MediaLive provisioning failure | 500 | (provider error) | Wrapped provider exception |
| `DELETE /inputs/{id}` | Input not found | 404 | (FastAPI default) | "Input not found" |
| `DELETE /inputs/{id}` | Cannot remove primary | 400 | CANNOT_REMOVE_PRIMARY | "Cannot remove the primary input (position 0)." |
| `POST /layout` | Session not live/private | 409 | (inline) | "Layout switching requires a live session." |
| `POST /layout` | Invalid mode | 400 | (inline) | "Invalid layout mode: X. Valid: grid, pip, side_by_side, single" |
| `POST /layout` | Insufficient inputs for mode | 400 | (inline) | "Layout 'X' requires at least 2 inputs, got 1." |
| `POST /layout` | Cooldown not elapsed | 429 | LAYOUT_SWITCH_COOLDOWN | "Layout switch cooldown: wait N seconds." |
| `POST /guest-invites` | Not session owner | 403 | (inline) | "Only the broadcaster can create guest invites." |
| `POST /guest-invites` | No available input slots | 400 | (inline) | "No available input slots for a new guest." |
| `POST /guest-invites/{id}/accept` | Invite not found | 404 | (FastAPI default) | "Guest invite not found" |
| `POST /guest-invites/{id}/accept` | Invite expired | 410 | INVITE_EXPIRED | "This invite has expired." |
| `POST /guest-invites/{id}/accept` | Invite already accepted | 409 | INVITE_ALREADY_ACCEPTED | "This invite has already been accepted." |
| `POST /guest-invites/{id}/accept` | Invite revoked | 409 | INVITE_REVOKED | "This invite has been revoked." |
| `POST /guest-invites/{id}/revoke` | Not session owner | 403 | (inline) | "Only the broadcaster can revoke invites." |
| `POST /guests/{id}/remove` | Not session owner | 403 | (inline) | "Only the broadcaster can remove guests." |
| `POST /guests/{id}/remove` | Input not found | 404 | (FastAPI default) | "Input not found" |
| `POST /inputs/{id}/webrtc-offer` | Relay disabled | 503 | WEBRTC_RELAY_DISABLED | "WebRTC relay is not enabled." |
| `POST /inputs/{id}/webrtc-offer` | User not the accepted guest | 403 | (inline) | "Only the accepted guest can send WebRTC offers." |
| `POST /inputs/{id}/webrtc-offer` | Relay already running | 409 | RELAY_ALREADY_RUNNING | "Relay already active for this input." |

### Internal Error Handling

| Component | Failure Mode | Recovery Strategy |
|-----------|-------------|------------------|
| `create_additional_input()` | MediaLive `ThrottlingException` | Retry with exponential backoff (4 attempts via `_with_retry`) |
| `attach_input_to_channel()` | Channel in non-updatable state | Return error to caller; input created but not attached; can retry |
| `schedule_input_switch()` | BatchUpdateSchedule fails | Log error; layout state in DDB may be inconsistent with channel; next switch attempt resolves |
| `start_relay()` | FFmpeg process fails to start | Return error; input marked as offline; guest sees error in GuestStreamPanel |
| `stop_all_relays_for_session()` | One relay fails to stop (process kill fails) | Log warning; continue stopping other relays; orphaned process eventually times out |
| `accept_guest_invite()` | DDB conditional check fails (race condition) | Return 409; first acceptor wins |
| DDB write capacity exceeded | Provisioned throughput exceeded | DDB auto-scaling handles this; boto3 retries with backoff |

---

## 10. Performance & Capacity Planning

### 10.1 AWS MediaLive Limits

| Resource | Default Limit | Per-Session Usage | Headroom |
|----------|--------------|-------------------|----------|
| Inputs per region | 100 | 1-8 per session | ~12-100 concurrent sessions per region |
| Input attachments per channel | 20 | 1-8 per session | Well within limit |
| ScheduleActions per channel | 1000 active | 1 per layout switch | Effectively unlimited for manual switching |
| Channels per region | 5 (default, can request increase) | 1 per session | Request increase for production |
| Input security groups per region | 5 (default) | 1 per session | Request increase for production |

### 10.2 Concurrent Input Capacity

| Scenario | Inputs | MediaLive Channels | Monthly Cost Est. |
|----------|--------|-------------------|-------------------|
| 10 sessions, 2 inputs each | 20 | 10 | ~$3,000 (on-demand) |
| 10 sessions, 4 inputs each | 40 | 10 | ~$3,000 (same channel cost; inputs are free) |
| 50 sessions, 4 inputs each | 200 | 50 | ~$15,000 (requires limit increase) |
| 100 sessions, 8 inputs each | 800 | 100 | ~$30,000 (requires limit increase) |

**Key insight**: MediaLive charges per channel, not per input. Adding inputs is free. The cost driver is concurrent channels, not concurrent inputs.

### 10.3 DynamoDB Capacity

| Operation | Frequency | WCU Impact | RCU Impact |
|-----------|-----------|-----------|-----------|
| Create input | Low (during setup) | 1 WCU per input | 0 |
| List inputs | Medium (5s polling) | 0 | 1 RCU per query (< 4KB response) |
| Mark input live/offline | Low (on connect/disconnect) | 1 WCU | 1 RCU (read-modify-write) |
| Save layout | Low (manual switches) | 1 WCU | 0 |
| Create/accept invite | Low | 1 WCU each | 1 RCU each |
| Delete all inputs (on session stop) | Very low | 1 WCU per item | 1 RCU (scan) |

**Estimate**: 50 concurrent live sessions with 4 inputs each, 5s input polling = 10 RCU sustained. Well within DynamoDB on-demand mode.

### 10.4 SSE Event Throughput

| Event Source | Events/Second (Peak) | Subscriber Count (Peak) | Total Events/Second |
|-------------|---------------------|------------------------|---------------------|
| Input connection status changes | 0.1 per session | 100 viewers per session | 10 per session |
| Layout switches | 0.5 per session (manual) | 100 viewers per session | 50 per session |
| Guest join/leave | 0.05 per session | 100 viewers per session | 5 per session |

SSE events are delivered in-process via `asyncio.Queue`. With `maxsize=100` per subscriber, a burst of 100 events is absorbed before any are dropped. Dead (disconnected) subscribers are auto-cleaned on `QueueFull`.

### 10.5 WebRTC Relay Resource Usage

| Resource | Per Relay Process | Max Per Server (4 inputs/session, 50 sessions) |
|----------|------------------|-----------------------------------------------|
| FFmpeg CPU | ~0.5 vCPU (WebRTC decode + RTMP encode) | 100 vCPU (200 relays) |
| FFmpeg Memory | ~100MB | 20GB (200 relays) |
| Network bandwidth | 2-5 Mbps per relay | 400-1000 Mbps |

**Recommendation**: For production with > 20 concurrent browser guests, run relay processes on dedicated instances (not the API server). The `relay_process_id` field on `BroadcastInputModel` supports this by decoupling relay management from the API process.

---

## 11. Edge Cases Deep Dive

### 11.1 Guest Disconnects Mid-Stream

**Scenario**: Guest A is streaming via RTMP and their internet drops while in a side_by_side layout.

**Sequence**:
1. MediaLive detects input loss (no incoming packets for 5+ seconds)
2. Health monitoring detects `input_loss_seconds > 0` for Guest A's input
3. Backend marks input as offline: `mark_input_live(session_id, input_id, is_live=False)`
4. SSE event `input:disconnected` published with `disconnected_at` timestamp
5. Frontend `InputManager` updates Guest A's status badge from LIVE (green) to OFFLINE (gray)
6. **Layout does NOT auto-switch**: The broadcaster maintains control. MediaLive shows the last frame or black for the disconnected input. The broadcaster can manually switch to `single` or remove the guest.
7. If the guest reconnects (RTMP push resumes), MediaLive detects the new stream. `input:connected` event published. Status badge returns to LIVE.

**Why no auto-switch**: Auto-switching would surprise the broadcaster and viewers during brief network glitches. The broadcaster knows best when to adapt the layout. A future enhancement could add an optional "auto-fallback" setting.

### 11.2 Layout Switch During Recording

**Scenario**: Session is live with recording enabled. Broadcaster switches from `single` to `side_by_side`.

**Behavior**:
- MediaLive records the **composed output** (what viewers see), not individual inputs.
- The InputSwitch ScheduleAction takes effect immediately. MediaLive transitions the encoder pipeline to the new input configuration.
- The recording (HLS segments written to S3) captures the transition as a hard cut. There is a brief (~1 frame) moment where the output may show black or the old layout.
- The recording pipeline (BCAST-006) processes segments chronologically. The layout change is preserved in the final MP4.

**Limitation**: There is no way to retroactively apply a layout change to already-recorded segments. The recording reflects the broadcast exactly as viewers saw it.

### 11.3 Multiple Guests Accept Same Invite (Race Condition)

**Scenario**: Broadcaster shares an invite link in a group chat. Two guests click "Accept" simultaneously.

**Resolution**:
- `accept_guest_invite()` uses a DDB conditional update: `ConditionExpression = Attr("status").eq("pending")`
- The first write succeeds and sets `status = "accepted"`
- The second write fails the condition check (status is now "accepted", not "pending")
- The second caller receives HTTP 409 with message "This invite has already been accepted"
- This is atomic at the DDB level -- no application-level locking needed

### 11.4 Session Stops While Guest Has Active WebRTC Relay

**Scenario**: Session owner clicks "Stop" while Guest B is streaming via browser (WebRTC relay).

**Sequence**:
1. `stop_session_with_provider()` called
2. **Added by this ticket**: `stop_all_relays_for_session(session_id)` called
3. Each relay process receives SIGTERM (graceful shutdown)
4. If process doesn't exit within 5 seconds, SIGKILL is sent
5. All inputs marked offline via `mark_input_live(is_live=False)`
6. All pending invites expired via `expire_pending_invites()`
7. Channel is stopped via provider
8. Recording pipeline triggered (records composed output up to the stop point)
9. SSE events published: `input:disconnected` for each input
10. Guest B's `GuestStreamPanel` receives a connection error on the PeerConnection; shows "Broadcast ended" message

### 11.5 Input Added During Live Session (Hot-Attach)

**Scenario**: Broadcaster adds a new RTMP input while the session is already live.

**Sequence**:
1. `POST /sessions/{id}/inputs` called
2. `create_additional_input()` creates a new MediaLive input
3. `attach_input_to_channel()` calls `UpdateChannel` to add the new InputAttachment
4. MediaLive hot-attaches the input. The channel continues running uninterrupted.
5. The new input is in `DETACHED` or `IDLE` state until RTMP push begins
6. DDB record created with `is_live=False`
7. SSE event `input:added` published
8. Frontend shows new input row with OFFLINE status
9. When the broadcaster (or guest) starts pushing RTMP to the new ingest URL:
   - MediaLive detects the incoming stream
   - Input transitions to `ATTACHED` / receiving state
   - Health monitoring or MediaLive events trigger `mark_input_live(is_live=True)`
   - SSE event `input:connected` published
   - Frontend shows LIVE status

### 11.6 Primary Input Removed by Accident

**Protection**: The API explicitly rejects deletion of the primary input:

```python
if input_record.position == 0 and input_record.input_type == "primary":
    raise HTTPException(status_code=400, detail="Cannot remove the primary input (position 0).")
```

The primary input is the broadcaster's own camera/encoder. Removing it would leave the channel with no guaranteed input source. If the broadcaster wants to swap their primary source, they should use layout switching to bring a different input to full-screen, not remove the primary.

### 11.7 Guest Joins But Never Pushes Media

**Scenario**: Guest accepts an invite (browser mode) but never clicks "Start Broadcasting" in the GuestStreamPanel, or their camera/mic permissions are denied.

**Behavior**:
- The invite status is "accepted" and the input record exists in DDB
- `is_live` remains `false` on the input
- The input appears as OFFLINE in the InputManager
- The broadcaster can include the OFFLINE input in a layout (MediaLive shows black/last-frame for inputs with no incoming media)
- After a configurable timeout (or broadcaster decision), the broadcaster can remove the guest
- The invite and input remain until explicitly cleaned up or session stops

### 11.8 Network Partition Between Backend and MediaLive

**Scenario**: The backend loses connectivity to the MediaLive API during a layout switch.

**Behavior**:
- `schedule_input_switch()` fails after 4 retry attempts
- The layout state in DDB is NOT updated (layout switch is atomic: DDB update only happens after MediaLive succeeds)
- The error propagates to the API response (500)
- The frontend shows a toast error "Failed to switch layout"
- The current layout remains unchanged on both MediaLive and in DDB
- Subsequent layout switch attempts will succeed once connectivity is restored

---

## 12. Observability

### 12.1 Prometheus Metrics

Add to `app/metrics.py`:

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `broadcast_inputs_total` | Gauge | `session_id`, `status` | Current input count per session by live/offline status |
| `broadcast_input_provision_latency_seconds` | Histogram | `result` (success/failure) | MediaLive input creation latency |
| `broadcast_layout_switch_total` | Counter | `mode`, `result` | Layout switch count by mode and success/failure |
| `broadcast_guest_invite_total` | Counter | `join_mode`, `status` | Invite creation/acceptance/revocation count |
| `broadcast_relay_active` | Gauge | `session_id` | Active WebRTC relay process count |

### 12.2 Structured Logging

All new service functions log at INFO level with structured fields:

```python
logger.info("Input created", extra={
    "session_id": session_id,
    "input_id": input_id,
    "input_type": input_type,
    "position": position,
})
```

Error cases log at WARNING or ERROR with exception details:

```python
logger.warning("Guest invite acceptance conflict", extra={
    "session_id": session_id,
    "invite_id": invite_id,
    "attempted_by": guest_user_id,
    "current_status": current_status,
})
```

### 12.3 Audit Trail

All 11 new audit actions are recorded via `record_broadcast_action()` with relevant metadata. The audit trail is queryable via the existing `GET /broadcast/admin/audit` endpoint with actor and time range filters.

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/services/broadcast_multi_input.py` | — | EXISTS | Multi-input management service |
| `app/services/broadcast_input_store.py` | — | EXISTS | Input storage service |
| `app/services/broadcast_layout.py` | — | EXISTS | Layout management service |
| `app/services/broadcast_webrtc_relay.py` | — | EXISTS | WebRTC relay for guest inputs |
| `app/core/settings.py` | 1213 | EXISTS | `broadcast_inputs_table_name` |
| `app/core/tables.py` | 89 | EXISTS | `T.broadcast_inputs` handle |
| `scripts/local-ddb-init.py` | 781-790 | EXISTS | BroadcastInputs table |
| `frontend/src/api/endpoints/broadcast-inputs.ts` | — | EXISTS | Input API wrappers |
| `frontend/src/pages/broadcast/InputManager.tsx` | — | EXISTS | Input manager UI |
| `frontend/src/pages/broadcast/GuestInviteDialog.tsx` | — | EXISTS | Guest invite dialog |
| `frontend/src/pages/broadcast/LayoutSwitcher.tsx` | — | EXISTS | Layout switcher UI |
| `frontend/e2e/broadcast-multi-input.spec.ts` | — | EXISTS | E2E tests |
| `app/services/broadcast_audit.py` | — | EXISTS | `record_broadcast_action()` for audit trail |
