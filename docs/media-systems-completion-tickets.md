# Media Systems Completion — Implementation Tickets

This ticket set covers the remaining work to bring **WebRTC 1:1 Calls**, **Video Broadcasting**, and **VOD Upload/Transcode/Watermark/DRM** from their current architectural state to production-ready functionality.

**Current state:** All three systems have complete contracts, state machines, DynamoDB persistence, and API orchestration layers. What's missing is the actual media plane — real WebRTC connections, real streaming, and real video processing.

---

## Epic 1 — WebRTC 1:1 Calls: Media Plane Implementation

> **Prerequisite tickets already done:** WRTC-001 through WRTC-022, WRTC-031, WRTC-033, WRTC-041, WRTC-042, WRTC-050, WRTC-052.
> **What exists:** Call lifecycle API, state machine, TURN credentials, signaling framework (backend), call overlay UI (buttons/states), SSE events.
> **What's missing:** Actual WebRTC peer connection, media capture, signaling endpoint, audio/video rendering.

---

### CALL-001: Expose signaling HTTP endpoint for offer/answer/ICE exchange

**Type:** Backend
**Priority:** P0
**Size:** M
**Description:** The backend `route_signaling_event()` function in `messaging_call_signaling.py` is fully implemented but has no HTTP endpoint. Create `POST /messages/calls/{call_id}/signal` to accept `webrtc.offer`, `webrtc.answer`, and `webrtc.ice_candidate` payloads and relay them to the other participant via SSE.

**Deliverables:**
- New endpoint in `app/routers/messaging.py`
- Request model: `{ type: "offer"|"answer"|"ice_candidate", payload: { sdp?: string, candidate?: RTCIceCandidateInit } }`
- Relay via existing SSE messaging stream (`messaging:call-event` dispatch)
- Rate limiting: max 50 ICE candidates per call, max 2 offers/answers per call

**Acceptance criteria:**
- Alice sends offer → Bob receives it via SSE within 500ms
- Bob sends answer → Alice receives it via SSE
- ICE candidates flow bidirectionally
- Non-participant gets 403; wrong call state gets 409
- E2E test validates round-trip signaling

**Dependencies:** None (all backend infrastructure exists).

---

### CALL-002: Implement frontend RTCPeerConnection setup and teardown

**Type:** Frontend
**Priority:** P0
**Size:** L
**Description:** Create a `useWebRTCCall` hook that manages the `RTCPeerConnection` lifecycle, integrating with the existing `callStateMachine.ts` state reducer and `CallSessionOverlay.tsx` UI.

**Deliverables:**
- `frontend/src/hooks/useWebRTCCall.ts`
- Creates `RTCPeerConnection` with TURN credentials from `POST /messages/calls/{call_id}/turn-credentials`
- Handles `createOffer()` / `createAnswer()` / `setLocalDescription()` / `setRemoteDescription()`
- Gathers ICE candidates and sends via CALL-001 endpoint
- Receives remote ICE candidates from SSE and calls `addIceCandidate()`
- Connects to `callStateMachine` state transitions (accepted → create offer, etc.)
- Full teardown on call end (close PC, stop tracks, remove listeners)

**Acceptance criteria:**
- Peer connection establishes between two browser tabs on same machine
- ICE connection state reaches "connected" or "completed"
- Teardown releases all resources (no leaked MediaStreams)
- Works with STUN-only (local) and TURN relay (remote)

**Dependencies:** CALL-001.

---

### CALL-003: Implement getUserMedia capture with permission handling

**Type:** Frontend
**Priority:** P0
**Size:** M
**Description:** Add media capture logic that requests microphone (and optionally camera) access, handles permission denials gracefully, and provides track management (mute/unmute, camera on/off).

**Deliverables:**
- Media capture integrated into `useWebRTCCall` hook
- Audio-only for voice calls, audio+video for video calls (based on `initial_mode`)
- Permission denied → clear UI error state in `CallSessionOverlay`
- Device enumeration for mic/camera selection (future: device picker UI)
- Track mute/unmute without renegotiation (track.enabled toggle)
- Camera on/off with renegotiation (add/remove video track)

**Acceptance criteria:**
- Browser prompts for microphone permission on call start
- Permission denied shows actionable guidance ("Allow microphone access in browser settings")
- Mute/unmute works without call interruption
- Camera toggle adds/removes video track from peer connection

**Dependencies:** CALL-002.

---

### CALL-004: Render local and remote media streams in call overlay

**Type:** Frontend
**Priority:** P0
**Size:** M
**Description:** Add `<audio>` and `<video>` elements to `CallSessionOverlay.tsx` that render local preview and remote streams from the peer connection.

**Deliverables:**
- Remote audio always plays (even in "audio call" mode, to handle upgrade)
- Remote video renders in main area when video call
- Local video preview in picture-in-picture corner (small, draggable)
- Audio-only call shows avatar + call duration timer
- Video-off state shows avatar placeholder for that participant
- Proper cleanup of `srcObject` on unmount

**Acceptance criteria:**
- Two users in separate browsers can hear each other (audio call)
- Two users can see each other (video call)
- Call duration timer increments correctly
- No audio echo (local stream not played back to self)
- Stream cleanup on call end (no orphaned audio)

**Dependencies:** CALL-002, CALL-003.

---

### CALL-005: Add in-call media controls (mute, camera, end)

**Type:** Frontend
**Priority:** P0
**Size:** S
**Description:** Wire the existing `CallSessionOverlay` button slots to actual media control actions.

**Deliverables:**
- Mute mic button → `audioTrack.enabled = false/true` + visual indicator
- Camera toggle button → add/remove video track + UI state
- End call button → existing `endCallMutation` + teardown
- Call duration display (mm:ss format, starts when state = "connected")
- Visual indicators: mic muted icon, camera off icon, connection quality (ICE state)

**Acceptance criteria:**
- Muting stops audio transmission (remote side confirms silence)
- Camera off removes video from remote side (shows avatar)
- End call terminates for both sides within 2 seconds
- UI accurately reflects current media state

**Dependencies:** CALL-003, CALL-004.

---

### CALL-006: E2E tests for WebRTC media establishment

**Type:** Testing
**Priority:** P1
**Size:** M
**Description:** Add Playwright E2E tests that verify the full call flow including media connection. Use `--use-fake-device-for-media-stream` and `--use-fake-ui-for-media-stream` Chromium flags to avoid real device access.

**Deliverables:**
- `frontend/e2e/webrtc-media.spec.ts`
- Tests: invite → accept → verify ICE connected state → end
- Tests: invite → accept → mute → verify mute indicator on remote
- Tests: permission denied → error UI shown
- Tests: network quality degradation handling (simulate via throttling)
- Chromium launch args: `--use-fake-device-for-media-stream --use-fake-ui-for-media-stream`

**Acceptance criteria:**
- All tests pass with fake media streams
- No real microphone/camera access required in CI
- Tests complete within 30 seconds each

**Dependencies:** CALL-001 through CALL-005.

---

### CALL-007: Add call ringing timeout and missed-call handling

**Type:** Full-stack
**Priority:** P1
**Size:** S
**Description:** If callee doesn't accept within 30 seconds, auto-transition to "missed" state. Show notification for missed calls.

**Deliverables:**
- Backend: background task or client-driven timeout → `state = "missed"` after 30s
- Frontend caller: "No answer" UI after timeout
- Frontend callee: missed call indicator in conversation (system message)
- Configurable timeout via settings (default 30s)

**Acceptance criteria:**
- Unanswered call transitions to "missed" after 30s
- Caller sees "No answer" and call overlay dismisses
- Callee sees "Missed call from X" in conversation timeline
- No zombie call sessions left in "invited" state

**Dependencies:** CALL-002.

---

### CALL-008: ICE restart and mid-call reconnection

**Type:** Frontend
**Priority:** P1
**Size:** M
**Description:** Handle transient network drops during an active call by triggering ICE restart rather than ending the call immediately.

**Deliverables:**
- Detect ICE connection state "disconnected" or "failed"
- Attempt ICE restart (createOffer with iceRestart: true) up to 2 times
- Show "Reconnecting..." UI during restart attempt
- If restart fails after 2 attempts, end call with reason "network_failure"
- Resume normal call if restart succeeds

**Acceptance criteria:**
- Brief network interruption (<5s) recovers without user action
- "Reconnecting" indicator shows during recovery
- Persistent failure ends call cleanly after ~10s
- No duplicate media streams after reconnection

**Dependencies:** CALL-002.

---

## Epic 2 — Video Broadcasting: Frontend & AWS Execution

> **What exists:** Session state machine, AWS MediaLive/MediaPackage provisioning logic, CloudFront signed URLs, local ffmpeg transcoder, watermark overlay, audit trail, reconciler, 45+ E2E tests.
> **What's missing:** Frontend UI for broadcasters/viewers, AWS mode actually calling MediaLive APIs, viewer experience (player + chat).

---

### BCAST-001: Build broadcaster dashboard page (create/manage sessions)

**Type:** Frontend
**Priority:** P0
**Size:** L
**Description:** Create `/broadcast` page for authenticated users to create profiles, start sessions, and monitor live broadcasts.

**Deliverables:**
- `frontend/src/pages/broadcast/BroadcastDashboard.tsx`
- Profile creation form (name, rendition preset, watermark asset, DRM toggle)
- Session list with status badges (draft/live/stopped)
- "Go Live" / "Stop" buttons with confirmation dialogs
- RTMP ingest URL + stream key display (copyable) for OBS configuration
- Session details panel (viewer count placeholder, duration, health)

**Acceptance criteria:**
- User can create a profile and session from the UI
- RTMP URL and stream key are displayed for OBS setup
- Start/stop transitions update UI in real-time (polling or SSE)
- Stopped sessions show archive status

**Dependencies:** None (backend API complete).

---

### BCAST-002: Build viewer playback page with HLS player

**Type:** Frontend
**Priority:** P0
**Size:** L
**Description:** Create `/live/{sessionId}` page that plays back a live broadcast using HLS.js (or Video.js + HLS plugin) with entitlement token integration.

**Deliverables:**
- `frontend/src/pages/broadcast/LivePlayer.tsx`
- Fetch playback URL via `POST /broadcast/sessions/{id}/playback-url`
- HLS.js player with adaptive quality switching
- DRM support via EME (Encrypted Media Extensions) for protected streams
- Loading/buffering/error states with user-friendly messages
- "Stream ended" state when broadcast stops
- Responsive layout (mobile + desktop)

**Acceptance criteria:**
- Live stream plays within 5 seconds of page load
- Quality adapts to bandwidth automatically
- Protected streams decrypt and play (using entitlement token)
- Graceful handling of stream end (no frozen frame)

**Dependencies:** None (backend playback-url endpoint exists).

---

### BCAST-003: Wire AWS MediaLive start/stop to actual API calls

**Type:** Backend
**Priority:** P0
**Size:** M
**Description:** The `AwsBroadcastProvider` currently stubs `provision()`, `start()`, and `stop()`. Implement actual boto3 calls to MediaLive and MediaPackage.

**Deliverables:**
- `provision()`: Create MediaLive input (RTMP_PUSH) + channel + MediaPackage endpoint
- `start()`: Call `start_channel()` on MediaLive, poll until state = "RUNNING"
- `stop()`: Call `stop_channel()`, wait for "IDLE", then delete resources (or leave for archive)
- Error handling: channel creation failure → session state = "error" with reason
- Async polling with timeout (provision = 120s, start = 60s, stop = 60s)
- Cleanup: delete MediaLive input/channel + MediaPackage channel on session delete

**Acceptance criteria:**
- End-to-end: create session → provision → start → push RTMP → stream plays → stop
- Resource cleanup leaves no orphaned AWS resources
- Timeout/failure transitions session to "error" state
- Idempotent: calling start on already-live session returns success

**Dependencies:** AWS credentials configured in production environment.

---

### BCAST-004: Add real-time viewer count and session health metrics

**Type:** Full-stack
**Priority:** P1
**Size:** M
**Description:** Track concurrent viewers and broadcast health (bitrate, dropped frames, latency) and display in broadcaster dashboard.

**Deliverables:**
- Backend: viewer count endpoint (increment on playback-url request, decrement on token expiry or explicit leave)
- Backend: health endpoint pulling from MediaLive CloudWatch metrics (input loss, output errors)
- Frontend: real-time viewer count badge on broadcaster dashboard
- Frontend: health indicator (green/yellow/red) based on metrics
- SSE or polling (every 10s) for live updates

**Acceptance criteria:**
- Viewer count increments when new viewer joins, decrements when they leave
- Health indicator turns yellow on elevated errors, red on input loss
- Metrics update within 15 seconds of state change

**Dependencies:** BCAST-001, BCAST-003.

---

### BCAST-005: Add live chat for broadcast viewers

**Type:** Full-stack
**Priority:** P2
**Size:** L
**Description:** Real-time chat sidebar on the viewer page, allowing authenticated viewers to send messages during a live broadcast.

**Deliverables:**
- Backend: `POST /broadcast/sessions/{id}/chat` + `GET /broadcast/sessions/{id}/chat/stream` (SSE)
- DynamoDB table for broadcast chat messages (PK: session_id, SK: timestamp#msg_id)
- Frontend: chat panel in `LivePlayer.tsx` with message list + input
- Rate limiting: 1 message per 2 seconds per user
- Moderation: broadcaster can delete messages

**Acceptance criteria:**
- Messages appear for all viewers within 2 seconds of send
- Rate limiting prevents spam
- Broadcaster can moderate (delete messages)
- Chat history loads on page entry (last 100 messages)

**Dependencies:** BCAST-002.

---

### BCAST-006: Implement broadcast recording and VOD archive access

**Type:** Full-stack
**Priority:** P1
**Size:** M
**Description:** After a broadcast stops, provide access to the recorded archive as a VOD asset.

**Deliverables:**
- Backend: on session stop, register S3 archive path as a VOD asset
- Backend: `GET /broadcast/sessions/{id}/recording` → signed playback URL for archive
- Frontend: "Watch Recording" button on stopped sessions in dashboard
- Frontend: recording playback page (reuse LivePlayer component with VOD mode)
- Retention: configurable per-profile (default 30 days, already in broadcast_archive.py)

**Acceptance criteria:**
- Recording is available within 5 minutes of broadcast end
- Signed URL provides time-limited access
- Recording plays from start to finish without gaps
- Expired recordings return 410 Gone

**Dependencies:** BCAST-003.

---

### BCAST-007: Add sidebar navigation and route for broadcast pages

**Type:** Frontend
**Priority:** P0
**Size:** S
**Description:** Add broadcast/live pages to the app navigation and routing.

**Deliverables:**
- Route: `/broadcast` → BroadcastDashboard (auth required)
- Route: `/live/:sessionId` → LivePlayer (auth required for protected streams)
- Sidebar: "Broadcast" item with Radio/Video icon in Media group
- MobileNav: add to MORE_LINKS

**Acceptance criteria:**
- Navigation works from sidebar and direct URL
- Unauthenticated users redirected to login
- Active broadcast shows indicator badge in sidebar

**Dependencies:** BCAST-001, BCAST-002.

---

## Epic 3 — VOD Pipeline: Upload, Transcode, Package, Serve

> **What exists:** Playback entitlement tokens (issue/validate/revoke), watermark asset management, watermark rendering (ffmpeg filter gen), ABR profiles, pipeline contract + validation, DRM entitlement contract + mock provider.
> **What's missing:** Video upload endpoint, job queue/worker, actual FFmpeg execution, HLS/DASH packaging, video metadata model, frontend upload UI.

---

### VOD-001: Create video metadata model and DynamoDB table

**Type:** Backend
**Priority:** P0
**Size:** M
**Description:** Define the video asset model for tracking uploaded videos through the processing pipeline.

**Deliverables:**
- DynamoDB table: `videos` (PK: `user_sub`, SK: `VIDEO#{video_id}`)
- Fields: video_id, title, description, status (uploading/processing/ready/failed/deleted), upload_key (S3), duration_seconds, resolution, file_size_bytes, thumbnail_url, manifest_url, created_at, updated_at
- GSI: by status (for admin queries), by created_at (for listing)
- Pydantic models in `app/models.py`
- Service: `app/services/video_assets.py` (CRUD operations)

**Acceptance criteria:**
- Videos can be created, queried, updated, and soft-deleted
- Status transitions are validated (uploading → processing → ready)
- Pagination works for user video listings

**Dependencies:** None.

---

### VOD-002: Implement video upload endpoint with S3 presigned URL

**Type:** Backend
**Priority:** P0
**Size:** M
**Description:** Create a two-step upload flow: (1) request presigned URL, (2) confirm upload complete.

**Deliverables:**
- `POST /ui/videos/upload-url` → returns { video_id, upload_url, fields } (S3 presigned POST)
- `POST /ui/videos/{video_id}/upload-complete` → validates S3 object exists, sets status = "processing", enqueues transcode job
- File size limit: 5GB (configurable)
- Allowed content types: video/mp4, video/quicktime, video/webm, video/x-matroska
- S3 path: `uploads/videos/{user_sub}/{video_id}/original.{ext}`

**Acceptance criteria:**
- Frontend can upload directly to S3 without proxying through backend
- Large files (>100MB) work without timeout
- Invalid content types are rejected
- Upload completion triggers processing pipeline

**Dependencies:** VOD-001.

---

### VOD-003: Implement async transcode job queue and worker

**Type:** Backend
**Priority:** P0
**Size:** XL
**Description:** Create a job processing system that takes uploaded videos through the transcode pipeline. Use an in-process background worker for dev mode and SQS+Lambda for production.

**Deliverables:**
- Job model: `TranscodeJob` (job_id, video_id, status, progress_pct, error_message, started_at, completed_at)
- Dev mode: `asyncio` background task that runs FFmpeg locally
- Production mode: SQS queue + Lambda/ECS worker (stubbed, config-driven)
- Job states: queued → running → completed / failed
- Progress tracking: update progress_pct during transcode (based on FFmpeg output parsing)
- Retry: up to 2 retries on transient failure, then mark failed
- `app/services/video_transcode_worker.py` — orchestrates the pipeline

**Acceptance criteria:**
- Uploaded video automatically starts processing
- Progress is queryable via API
- Failed jobs have clear error messages
- Dev mode processes videos locally with FFmpeg
- Worker handles concurrent jobs (up to 2 in dev mode)

**Dependencies:** VOD-002.

---

### VOD-004: Implement FFmpeg execution with ABR output and watermark

**Type:** Backend
**Priority:** P0
**Size:** L
**Description:** Execute the FFmpeg commands that `ffmpeg_abr_pipeline.py` currently only generates as arguments. Produce actual HLS segments and manifests.

**Deliverables:**
- `app/services/video_ffmpeg_executor.py`
- Takes: S3 input path, rendition profiles, watermark policy
- Runs: FFmpeg subprocess with progress parsing (frame count / duration)
- Outputs: HLS segments + variant playlists + master playlist to local temp dir
- Applies: watermark overlay (static image or dynamic text) per policy
- Error handling: FFmpeg exit code != 0 → capture stderr, mark job failed
- Resource limits: max 2 concurrent FFmpeg processes, timeout after 30 minutes

**Acceptance criteria:**
- 1080p input produces 4-tier ABR ladder (1080p/720p/540p/360p)
- Watermark visible at configured position and opacity
- Master playlist references all variants with correct bandwidth
- Segments are ~4 seconds each
- Process respects timeout and resource limits

**Dependencies:** VOD-003.

---

### VOD-005: Upload transcode outputs to S3 and generate manifest URLs

**Type:** Backend
**Priority:** P0
**Size:** M
**Description:** After FFmpeg completes, upload all output files to S3 and update the video record with playback URLs.

**Deliverables:**
- Upload HLS directory to S3: `videos/{user_sub}/{video_id}/hls/`
- Generate CloudFront-signed or presigned manifest URL
- Update video record: status = "ready", manifest_url, thumbnail_url, duration
- Thumbnail: extract frame at 25% mark via FFmpeg (`-ss` + `-frames:v 1`)
- Cleanup: delete local temp files after successful upload

**Acceptance criteria:**
- Video status transitions to "ready" after successful upload
- Manifest URL is playable in HLS.js
- Thumbnail is accessible and shows representative frame
- S3 paths follow consistent convention

**Dependencies:** VOD-004.

---

### VOD-006: Implement video listing and detail API endpoints

**Type:** Backend
**Priority:** P0
**Size:** S
**Description:** CRUD endpoints for users to manage their video library.

**Deliverables:**
- `GET /ui/videos` — list user's videos (paginated, filterable by status)
- `GET /ui/videos/{video_id}` — video details + playback URL (with entitlement token)
- `DELETE /ui/videos/{video_id}` — soft-delete (marks deleted, schedules S3 cleanup)
- `PATCH /ui/videos/{video_id}` — update title/description
- Playback URL includes entitlement token from existing `playback_entitlements.py`

**Acceptance criteria:**
- Users can only see their own videos
- Pagination works with cursor-based tokens
- Deleted videos are hidden from listings
- Playback URLs expire after configured TTL

**Dependencies:** VOD-001, VOD-005.

---

### VOD-007: Build frontend video upload page

**Type:** Frontend
**Priority:** P0
**Size:** L
**Description:** Create `/videos` page with upload functionality, progress tracking, and video library grid.

**Deliverables:**
- `frontend/src/pages/videos/VideosPage.tsx`
- Upload zone: drag-and-drop + file picker (accepts video/*)
- Upload progress bar (S3 multipart upload with XHR progress events)
- Processing status indicator (polling every 5s while status = "processing")
- Video library grid: thumbnails, titles, status badges, duration
- Actions: edit title, delete, copy playback URL

**Acceptance criteria:**
- User can upload a video file via drag-and-drop
- Upload progress shows accurate percentage
- Processing indicator shows until video is ready
- Ready videos display thumbnail and are clickable

**Dependencies:** VOD-002, VOD-006.

---

### VOD-008: Build frontend video player page with DRM support

**Type:** Frontend
**Priority:** P0
**Size:** M
**Description:** Create `/videos/:videoId` page with HLS.js player, DRM decryption, and video metadata display.

**Deliverables:**
- `frontend/src/pages/videos/VideoPlayer.tsx`
- HLS.js player with quality selector
- EME integration for DRM-protected content (using entitlement token as license)
- Video title, description, upload date display
- Share button (generates time-limited signed URL)
- Error states: expired token, video not found, still processing

**Acceptance criteria:**
- Unprotected videos play immediately
- DRM-protected videos decrypt and play with valid entitlement
- Quality selector shows available renditions
- Expired/invalid tokens show "Access expired" message

**Dependencies:** VOD-006, BCAST-002 (reuse player component).

---

### VOD-009: Add video routes and navigation

**Type:** Frontend
**Priority:** P0
**Size:** S
**Description:** Wire video pages into app routing and navigation.

**Deliverables:**
- Route: `/videos` → VideosPage (auth required)
- Route: `/videos/:videoId` → VideoPlayer (auth required)
- Sidebar: "Videos" item with Film icon in Media group
- MobileNav: add to MORE_LINKS

**Acceptance criteria:**
- Navigation works from sidebar and direct URL
- Unauthenticated users redirected to login

**Dependencies:** VOD-007, VOD-008.

---

### VOD-010: DRM encryption during packaging (production mode)

**Type:** Backend
**Priority:** P1
**Size:** L
**Description:** Encrypt HLS segments during packaging using the DRM entitlement system for protected content.

**Deliverables:**
- Integration with Shaka Packager for CENC encryption (Widevine + FairPlay)
- Key fetching from DRM entitlement service (content key per video)
- Encrypted segments + PSSH boxes in manifests
- License acquisition URL in manifest (points to `/drm/license` endpoint)
- Configurable: DRM can be enabled/disabled per video (user setting or admin policy)

**Acceptance criteria:**
- Encrypted video plays only with valid entitlement token
- Without token, player shows license acquisition error
- Key rotation works (new key after configured interval)
- Both Widevine (Chrome/Android) and FairPlay (Safari/iOS) work

**Dependencies:** VOD-005, existing DRM infrastructure.

---

### VOD-011: E2E tests for video upload and playback pipeline

**Type:** Testing
**Priority:** P1
**Size:** M
**Description:** End-to-end tests covering the full VOD workflow in dev mode.

**Deliverables:**
- `frontend/e2e/video-upload.spec.ts`
- Tests: upload small video → wait for processing → verify "ready" status
- Tests: play back processed video → verify HLS manifest loads
- Tests: delete video → verify removed from listing
- Tests: upload invalid file type → verify rejection
- Use small test video fixture (5s, 720p, ~500KB)

**Acceptance criteria:**
- Full pipeline test completes within 60 seconds (small fixture)
- All CRUD operations verified
- Error paths tested (invalid type, too large)

**Dependencies:** VOD-003 through VOD-009.

---

## Epic 4 — Cross-Cutting: Shared Player Component & Media Infrastructure

---

### MEDIA-001: Create shared HLS/DRM player component

**Type:** Frontend
**Priority:** P0
**Size:** M
**Description:** Extract a reusable `<MediaPlayer>` component used by both broadcast viewer and VOD player pages.

**Deliverables:**
- `frontend/src/components/shared/MediaPlayer.tsx`
- Props: `src` (manifest URL), `drm` (license URL + token), `autoplay`, `poster`, `onError`, `onEnded`
- HLS.js integration with quality level API
- EME/DRM integration (Widevine + FairPlay via native EME)
- Quality selector dropdown
- Fullscreen, picture-in-picture controls
- Loading/buffering/error states

**Acceptance criteria:**
- Works for both live (DVR disabled) and VOD (seekable) content
- Quality adapts automatically, manual override available
- DRM content decrypts transparently
- Consistent UI across broadcast viewer and VOD player

**Dependencies:** None (can be built in parallel with BCAST-002 and VOD-008).

---

### MEDIA-002: Add FFmpeg binary management for dev mode

**Type:** Infrastructure
**Priority:** P0
**Size:** S
**Description:** Ensure FFmpeg is available in the dev environment for VOD processing and local broadcast transcoding.

**Deliverables:**
- Add FFmpeg installation to `scripts/setup_ubuntu.sh` (if not already present)
- Verify FFmpeg version ≥ 5.0 with libx264, libx265, libvpx, libopus
- Add health check in `just status` for FFmpeg availability
- Settings: `FFMPEG_BINARY_PATH` (default: "ffmpeg" from PATH)

**Acceptance criteria:**
- `just status` reports FFmpeg version
- VOD transcode worker can locate and execute FFmpeg
- Setup script installs FFmpeg on fresh host

**Dependencies:** None.

---

## Summary and Priority Order

### Phase 1 — Foundation (enables all three systems)
| Ticket | System | Size | Priority |
|--------|--------|------|----------|
| MEDIA-001 | Shared | M | P0 |
| MEDIA-002 | Infra | S | P0 |
| CALL-001 | WebRTC | M | P0 |
| VOD-001 | VOD | M | P0 |
| BCAST-007 | Broadcast | S | P0 |

### Phase 2 — Core Implementation
| Ticket | System | Size | Priority |
|--------|--------|------|----------|
| CALL-002 | WebRTC | L | P0 |
| CALL-003 | WebRTC | M | P0 |
| CALL-004 | WebRTC | M | P0 |
| CALL-005 | WebRTC | S | P0 |
| VOD-002 | VOD | M | P0 |
| VOD-003 | VOD | XL | P0 |
| VOD-004 | VOD | L | P0 |
| VOD-005 | VOD | M | P0 |
| VOD-006 | VOD | S | P0 |
| BCAST-001 | Broadcast | L | P0 |
| BCAST-002 | Broadcast | L | P0 |
| BCAST-003 | Broadcast | M | P0 |

### Phase 3 — Frontend & Integration
| Ticket | System | Size | Priority |
|--------|--------|------|----------|
| VOD-007 | VOD | L | P0 |
| VOD-008 | VOD | M | P0 |
| VOD-009 | VOD | S | P0 |
| CALL-006 | WebRTC | M | P1 |
| CALL-007 | WebRTC | S | P1 |
| CALL-008 | WebRTC | M | P1 |
| BCAST-004 | Broadcast | M | P1 |
| BCAST-006 | Broadcast | M | P1 |

### Phase 4 — Polish & Production Hardening
| Ticket | System | Size | Priority |
|--------|--------|------|----------|
| VOD-010 | VOD | L | P1 |
| VOD-011 | VOD | M | P1 |
| BCAST-005 | Broadcast | L | P2 |

---

## Effort Estimates

| Epic | Tickets | Total Size | Estimated Hours |
|------|---------|-----------|-----------------|
| WebRTC Media Plane | 8 | ~5L equivalent | 50-70h |
| Broadcast Frontend + AWS | 7 | ~5L equivalent | 50-65h |
| VOD Pipeline | 11 | ~7L equivalent | 70-90h |
| Shared/Infra | 2 | ~1L equivalent | 10-15h |
| **Total** | **28** | | **180-240h** |
