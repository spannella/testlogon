---
id: AND-300
title: Group call grid
milestone: M7
epic: E40
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-299]
blocks: []
---

# AND-300 — Group call grid

## 1. Overview & Goal

Provide the in-call rendering surface for multi-party (group) calls established by
AND-299. The deliverable is an **adaptive video grid** for the `feature-calls`
module that arranges 1..N remote participants plus the local participant into a
responsive layout that scales with participant count, surfaces the current
**active speaker**, and supports **pinning** a single participant to a focused
view. AND-299 owns multi-party signaling and media plumbing
(`/ui/calls/group/*`, the SFU/WebRTC tracks, and the
`GroupCallSession`/participant stream model); AND-298 owns the 1:1 in-call chrome
(mute/cam/speaker/flip/end, duration, connection quality). This ticket consumes
those abstractions and is responsible **only** for the visual composition and
layout behavior of the participant tiles.

Goal: a `GroupCallGrid` composable that, given an observable list of participants
and their media tracks, renders a correct, performant, accessible grid that
adapts deterministically to participant count and orientation, highlights the
active speaker, and toggles pinned/focused mode without dropping or
re-subscribing video tracks. Acceptance is met when the grid layout adapts to the
participant count (1, 2, 3-4, 5-6, 7-9, 10+) and re-flows on join/leave and
rotation.

## 2. Context & References

- Module: `feature-calls` (depends on `core-ui`, `core-model`, `core-data`).
- Namespace: `com.testlogon.android.feature.calls.grid`.
- Upstream: **AND-299** (group call session, participant model, media tracks),
  **AND-298** (in-call controls + connection-quality chip reused per tile),
  **AND-296** (call entry/lifecycle), **AND-293** (WebRTC/Media3 video sink
  primitives), **AND-290** (permissions/foreground service for calls).
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP),
  Coroutines/Flow. Video frames render through the WebRTC `SurfaceViewRenderer`
  / `VideoTrack` sink provided by AND-293/AND-299, wrapped in `AndroidView`.
- Web reference: group call grid behavior in `frontend/` calls feature (tile
  ordering, active-speaker outline, pin toggle) — mirror its breakpoints and
  ordering semantics, not its CSS.
- This ticket performs **no network I/O of its own**; all call REST/WS traffic
  belongs to AND-299. See §5.

## 3. Functional Requirements

FR-1 **Adaptive grid.** Render an N-tile grid whose row/column count is derived
from participant count and available aspect ratio. Required breakpoints
(portrait): 1 → 1×1 (full bleed); 2 → 1 over 1 (2 rows); 3-4 → 2×2; 5-6 → 2×3;
7-9 → 3×3; 10+ → 3 columns, vertically scrollable, newest/lower-priority tiles
below the fold. Landscape transposes columns/rows (e.g. 2 → side-by-side, 3-4 →
2×2, 5-6 → 3×2).

FR-2 **Tile content.** Each tile renders the participant's video track when
present and unmuted-video; otherwise an avatar placeholder (Coil) on a tinted
surface with initials. Overlay: display name (truncated), mic-muted glyph,
poor-connection glyph (reusing AND-298's quality model), and a "speaking" border
when active.

FR-3 **Active speaker.** Continuously highlight the participant with the highest
audio level via a 2dp animated border and elevation bump. In grids that cannot
fit all participants (10+), the active speaker is promoted into the visible
region. Active-speaker state updates are debounced (≥500ms hold) to avoid
flicker.

FR-4 **Pin.** Long-press or tap a tile's overflow to pin it. Pinned mode renders
the pinned participant in a large focus area (top ~70% portrait / left ~70%
landscape) with the remaining participants in a scrollable filmstrip. Tapping the
pinned tile's unpin affordance, or pinning another tile, updates the focus.
Pinning is purely local UI state and survives config changes but not process
death.

FR-5 **Local participant.** The local (self) tile renders the local camera
preview (mirrored), is never the auto active speaker, and is included in the
count for layout. When the local camera is off, show the self avatar.

FR-6 **Re-flow.** On participant join/leave, mute/unmute-video, and orientation
change, the grid animates to the new layout (≤250ms) without tearing down
surviving tiles' renderers or re-subscribing their tracks. Tile identity is keyed
by stable `participantId`.

FR-7 **Empty/edge states.** 0 remote participants → show "Waiting for others to
join" with the self tile full-bleed. Connection-lost for a tile → dim + spinner
overlay (state owned by AND-299, rendered here).

## 4. Technical Design

New package `com.testlogon.android.feature.calls.grid`:

```kotlin
@Immutable
data class CallParticipantUi(
    val id: String,                 // stable participantId from AND-299
    val displayName: String,
    val avatarUrl: String?,
    val isLocal: Boolean,
    val isAudioMuted: Boolean,
    val isVideoEnabled: Boolean,
    val connection: ConnectionQuality, // reused from AND-298
    val audioLevel: Float,          // 0f..1f, normalized by AND-299
    val videoTrack: VideoTrackHandle?, // opaque sink handle from AND-293/299
    val tileState: TileState        // CONNECTING, LIVE, RECONNECTING, LOST
)

enum class TileState { CONNECTING, LIVE, RECONNECTING, LOST }

@Immutable
data class GroupGridUiState(
    val participants: List<CallParticipantUi> = emptyList(),
    val pinnedId: String? = null,
    val activeSpeakerId: String? = null
)
```

Layout decision is a pure function so it is unit-testable independent of Compose:

```kotlin
data class GridSpec(val columns: Int, val rows: Int, val scrollable: Boolean)

object GridLayoutPolicy {
    fun spec(count: Int, orientation: Orientation): GridSpec
    /** Visible participant ordering: pinned first, then active speaker,
     *  then stable join order. Local tile floats to a fixed slot. */
    fun order(
        participants: List<CallParticipantUi>,
        pinnedId: String?,
        activeSpeakerId: String?
    ): List<CallParticipantUi>
}
```

ViewModel exposes a single `StateFlow<GroupGridUiState>` derived from the
AND-299 session:

```kotlin
@HiltViewModel
class GroupCallGridViewModel @Inject constructor(
    private val session: GroupCallSession,          // from AND-299
    private val activeSpeaker: ActiveSpeakerDetector // see below
) : ViewModel() {
    val uiState: StateFlow<GroupGridUiState>
    fun pin(participantId: String)
    fun unpin()
}
```

`ActiveSpeakerDetector` consumes `session.audioLevels: Flow<Map<String, Float>>`
and emits a debounced dominant-speaker id:

```kotlin
class ActiveSpeakerDetector(
    private val holdMs: Long = 500,
    private val threshold: Float = 0.15f
) {
    fun detect(levels: Flow<Map<String, Float>>): Flow<String?>
}
```

Composables:

```kotlin
@Composable
fun GroupCallGrid(
    state: GroupGridUiState,
    onPin: (String) -> Unit,
    onUnpin: () -> Unit,
    modifier: Modifier = Modifier
)

@Composable
private fun ParticipantTile(
    p: CallParticipantUi,
    isActiveSpeaker: Boolean,
    isPinned: Boolean,
    onPin: () -> Unit,
    modifier: Modifier = Modifier
)
```

Implementation notes:
- Use `BoxWithConstraints` + a `LazyVerticalGrid` (`GridCells.Fixed(spec.columns)`)
  for the non-pinned grid; in pinned mode use a `Column`/`Row` with the focus
  region and a `LazyRow` filmstrip. Pass stable `key = { it.id }` so renderers are
  not recreated on reorder.
- Video frames render via `AndroidView` wrapping the renderer from AND-293; the
  factory binds `p.videoTrack` and `update` re-binds only when the handle
  identity changes. Tiles must call the renderer release path on disposal via
  `DisposableEffect` to avoid surface leaks.
- Orientation comes from `LocalConfiguration.current.orientation`; layout
  recomputes through `GridLayoutPolicy.spec` only (no extra recomposition state).
- Animate layout with `Modifier.animateItem()` (Lazy) and `animateContentSize`
  for the focus region; cap at 250ms `tween`.

## 5. API Contract

This ticket defines **no new endpoints**. All group-call signaling, participant
roster, track subscription, and audio-level telemetry are owned by **AND-299**
under `/ui/calls/group/*`. Verified against the backend OpenAPI index, the
relevant endpoints are: `POST /ui/calls/group/{call_id}/join`
(returns the join payload incl. roster + `signaling.ice_servers`),
`GET /ui/calls/group/{call_id}/participants` (the dedicated **roster** endpoint,
returns `GroupCallParticipantsOut`), and
`GET /ui/calls/group/{call_id}` (returns the full call object incl. participants).
> Correction: an earlier draft cited `GET /ui/calls/group/{callId}` as "the
> roster" endpoint. The authoritative roster endpoint is
> `GET /ui/calls/group/{call_id}/participants`; the `{call_id}` GET returns the
> whole `GroupCallOut`. Note the backend uses snake_case path params (`call_id`).
> **There is no REST per-participant audio-level / dominant-speaker field** in the
> contract (see §13 R2 / §16); active-speaker is derived client-side or carried on
> the realtime signaling channel that AND-299 owns. The grid consumes the
already-decoded domain model exposed by AND-299:

```kotlin
interface GroupCallSession {
    val participants: Flow<List<CallParticipantUi>> // mapped from roster + tracks
    val audioLevels: Flow<Map<String, Float>>       // participantId -> 0f..1f
}
```

Actual roster shape produced upstream (verified against
`GroupCallParticipantsOut` / `GroupCallParticipant` in the frontend
`src/api/types.ts`; mapping owned by AND-299, including FastAPI `detail` error
mapping per core-network conventions). **Corrected** from the earlier draft,
which used `id`/`avatar_url`/`audio_muted`/`video_enabled` — those fields do not
exist. The real `GroupCallParticipant` keys are `user_id`, `display_name`,
`media_status:{audio,video,screen}` (booleans), `connection_quality`, `state`,
`joined_at`, `left_at`. There is **no `avatar_url`** in the call roster (avatar
must be resolved by AND-299 from the profile service / a separate lookup):

```json
{
  "participants": [
    {"user_id": "u_12", "display_name": "Ada", "joined_at": 1717700000,
     "left_at": 0, "media_status": {"audio": true, "video": true, "screen": false},
     "connection_quality": "good", "state": "live"},
    {"user_id": "u_07", "display_name": "Lin", "joined_at": 1717700050,
     "left_at": 0, "media_status": {"audio": false, "video": false, "screen": false},
     "connection_quality": "poor", "state": "connecting"}
  ],
  "total_active": 2,
  "total_joined": 2
}
```

The `CallParticipantUi` mapping is therefore: `id ← user_id`,
`isAudioMuted ← !media_status.audio`, `isVideoEnabled ← media_status.video`,
`connection ← connection_quality`, `tileState ← state`. `avatarUrl` and
`audioLevel` are not in this DTO and are populated by AND-299 from other sources.

422 validation failures use the FastAPI `HTTPValidationError`
(`{"detail": [ValidationError, ...]}`); core-network maps `detail` to a
user-facing message (verified: `client.ts normalizeErrorDetail`).

If AND-299 surfaces an `ApiResult.Failure`, the grid renders the §3 edge states;
it does not retry network calls itself.

## 6. Data & State Management

- Single source of truth: `GroupGridUiState` in `GroupCallGridViewModel`,
  produced by `combine(session.participants, activeSpeaker.detect(...),
  pinnedFlow)` and exposed as `StateFlow` (`stateIn(viewModelScope,
  SharingStarted.WhileSubscribed(5_000), initial)`).
- `pinnedId` is local UI state held in a `MutableStateFlow<String?>` inside the
  ViewModel; preserved across configuration changes (ViewModel survives rotation).
  Not persisted to DataStore/Room — pin is ephemeral per call.
- No Room/DataStore usage in this ticket; the call is live-only data. Avatar
  images are cached by Coil's default disk cache (core-ui).
- Reordering must be pure and stable: `GridLayoutPolicy.order` produces a
  deterministic list so Compose keys remain stable and renderers are retained.
- Active-speaker debounce state lives in `ActiveSpeakerDetector` (Flow operator
  chain: `sample`/`debounce` + threshold + hold), not in Compose.

## 7. Error Handling & Resilience

- Per-tile failure: `TileState.RECONNECTING`/`LOST` (set by AND-299) renders a
  dimmed tile with spinner / "Reconnecting…" rather than removing the tile, so
  the grid does not thrash layout on transient track loss.
- No video track but `isVideoEnabled == true` and `tileState == LIVE` → show
  avatar with a brief shimmer for up to 3s, then static avatar (track may be
  paused by SFU).
- The grid never initiates retries; all backoff/refresh (including 401 →
  `POST /ui/session/refresh` once) is handled by core-network and AND-299.
- Defensive layout: `GridLayoutPolicy.spec` clamps to sane bounds for unexpected
  counts (e.g. count ≤ 0 → 1×1 placeholder; very large counts → 3 columns
  scrollable) so a malformed roster cannot crash the UI.
- Surface lifecycle: `DisposableEffect` guarantees renderer release on tile
  removal and on `ON_STOP` to survive backgrounding without leaking GL surfaces.

## 8. Security & Privacy

- The grid renders only data already authorized by the cookie-based session
  (POST `/ui/session/start` → MFA → `/ui/session/finalize`, with `X-CSRF-Token`
  echoed from `ui_csrf`) and the call-join authorization performed by AND-299. No
  credentials, cookies, or CSRF handling occur in this module.
- No participant media or audio levels are logged or persisted; audio levels are
  numeric only and never recorded.
- The local camera preview is mirrored and confined to the call screen; no
  screenshots/frames are written to disk by this ticket. Respect any
  `FLAG_SECURE` set on the call Activity by AND-298/AND-296.
- Avatar URLs load over the configured base host (dev backend is plaintext HTTP);
  no PII beyond display name/avatar is rendered.

## 9. Accessibility & i18n

- Each tile exposes a merged `semantics` node with `contentDescription` =
  "<name>, <muted|unmuted>, <speaking?>" and a custom action "Pin <name>" /
  "Unpin". The active-speaker border is supplemented by the speaking glyph (not
  color-only) to satisfy non-color signaling.
- Minimum touch target 48dp for the pin/overflow affordance; long-press also
  triggers pin with TalkBack double-tap-and-hold support.
- All strings (`waiting_for_others`, `reconnecting`, `you_label`, `muted`,
  `cd_pin`, `cd_unpin`) live in `feature-calls` `strings.xml`; no concatenated
  user-facing strings — use parameterized resources for name interpolation.
- Layout uses density-independent constraints and supports RTL (filmstrip and
  overlay alignment mirror). Honors system font scale up to 200% (name truncates
  with ellipsis, glyphs do not overlap).

## 10. Telemetry & Logging

- Emit structured analytics via the core telemetry facade (no PII): event
  `call_grid_layout_changed { call_id_hash, count, columns, rows, scrollable,
  orientation }`, `call_grid_pin_toggled { pinned: Boolean }`,
  `active_speaker_changed` (count of switches per call, sampled — never the
  participant id in plaintext logs).
- Debug logging gated behind `BuildConfig.DEBUG`; log layout spec transitions and
  renderer attach/release at `Log.d`. Never log audio levels, names, or avatar
  URLs.
- Renderer leak guard: log a warning if a tile is disposed while its renderer is
  still attached (surfaces a defect, no PII).

## 11. Testing Strategy

Unit (`core-testing`, JUnit + Turbine):
- `GridLayoutPolicyTest`: assert `spec(n, orientation)` for n ∈ {0,1,2,3,4,5,6,
  7,9,10,12} in both orientations matches the FR-1 table; assert clamping for
  invalid n.
- `GridLayoutPolicy.order` stability: pinned-first, then active speaker, then
  stable join order; local tile slot fixed; identical input → identical output.
- `ActiveSpeakerDetectorTest`: feed a `flow` of level maps; assert debounce/hold
  (no switch under `holdMs`), threshold gating, and null when all below
  threshold.
- `GroupCallGridViewModelTest`: fake `GroupCallSession`; assert `uiState`
  combines roster + active speaker + pin; `pin`/`unpin` mutate state; join/leave
  re-emits without losing pinned tile.

Compose UI (`createComposeRule`):
- Renders correct tile count and grid columns for representative counts (tag
  tiles `test:tile:<id>`).
- Active-speaker border/glyph appears on the speaking tile; pin via long-press
  enters focus mode and shows filmstrip; unpin restores grid.
- Waiting/empty state shown at 0 remote participants.
- Orientation change (`AndroidComposeTestRule` config) re-flows to transposed
  spec without recreating tile nodes (assert renderer not re-attached via fake).

CI runs unit tests (AND-050) and instrumented Compose tests on the headless
emulator (AND-051).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-299** — provides `GroupCallSession`, participant model,
  audio levels, and track handles. This ticket cannot be merged before AND-299
  lands those interfaces.
- Reuses **AND-298** `ConnectionQuality` model and quality glyph, and the
  `VideoTrackHandle`/renderer primitive from **AND-293**. Coordinate the
  `CallParticipantUi`/`VideoTrackHandle` contracts with AND-299 before
  implementation to avoid a parallel-DTO fork.
- Downstream: in-call recording/screenshare or speaker-view enhancements (later
  M7 tickets) build on this grid. No ticket is hard-blocked by AND-300 today
  (`blocks: []`), though group-call polish tickets will consume it.
- Sequencing: implement `GridLayoutPolicy` + `ActiveSpeakerDetector` (pure,
  testable) first; then `GroupCallGridViewModel`; then composables wired to a
  fake session; integrate real `GroupCallSession` last.

## 13. Risks & Open Questions

- **R1 Renderer reuse on reorder.** If Compose recreates `AndroidView` factories
  on reorder, video flickers / surfaces leak. Mitigation: stable `key`, identity
  checks in `update`, `DisposableEffect` release; verified by the
  "no re-attach on reorder" UI test.
- **R2 Active-speaker source of truth.** Partly resolved by review: the **REST
  contract carries no per-participant audio level and no dominant-speaker field**
  (`GroupCallParticipant` has only `media_status`/`connection_quality`/`state`;
  verified in `src/api/types.ts`). Therefore active-speaker must be derived
  client-side from WebRTC `RTCStats` audio levels, or carried over the realtime
  signaling channel (`POST /ui/calls/group/{call_id}/signal`, payload owned by
  AND-299). `ActiveSpeakerDetector` is **not** a pass-through over a server event
  unless AND-299 chooses to synthesize one on the signal channel. Still open:
  which of the two AND-299 will expose as `session.audioLevels`. Confirm with the
  AND-299 owner.
- **R3 Large-call performance.** 10+ live video tiles may exceed decode/GPU
  budget on minSdk 24 devices. Mitigation: cap simultaneously rendered video
  tiles (e.g. visible + active speaker), render avatars for off-screen/low-priority
  participants; cap value is an open tuning question pending AND-299 SFU limits.
- **R4 Pin vs. server-promoted speaker.** Define precedence: a local pin must
  override active-speaker promotion (assumed yes — pin wins). Confirmed in §3 FR-4.
- **R5 Orientation breakpoints.** Exact landscape mapping for 7-9 / 10+ may need
  UX sign-off; spec defaults provided and are adjustable in `GridLayoutPolicy`.

## 14. Acceptance Criteria

AC-1 (source) The grid **adapts to participant count**: it renders the FR-1
column/row spec for 1, 2, 3-4, 5-6, 7-9, and 10+ participants in both
orientations, validated by `GridLayoutPolicyTest` and a Compose count test.
AC-2 Adding/removing a participant (and toggling a participant's video) re-flows
the grid within ≤250ms without recreating surviving tiles' renderers.
AC-3 The active speaker is visibly highlighted (border + speaking glyph), updates
are debounced (no switch under 500ms hold), and the active speaker is visible
even when the grid is scrollable.
AC-4 A tile can be pinned (long-press/overflow) to enter focus mode with a
filmstrip, and unpinned to restore the grid; pin survives rotation.
AC-5 0 remote participants shows the waiting state with self full-bleed; per-tile
`RECONNECTING`/`LOST` renders the dimmed/spinner overlay without removing the
tile.
AC-6 Accessibility: every tile is a single semantics node with name + state
contentDescription and a Pin/Unpin custom action; targets ≥48dp; strings
externalized and RTL-correct.
AC-7 No network calls originate from this module; all data flows from the AND-299
`GroupCallSession`.

## 15. Definition of Done

- `feature-calls` `grid` package implemented: `GridLayoutPolicy`,
  `ActiveSpeakerDetector`, `GroupCallGridViewModel`, `GroupCallGrid` +
  `ParticipantTile`, with stable keys and `DisposableEffect` renderer lifecycle.
- All §11 unit and Compose tests written and green locally and in CI
  (AND-050/AND-051); no flaky renderer/surface assertions.
- Lint/detekt/ktlint clean (AND-005); no new public API in `core-*` except the
  agreed `CallParticipantUi`/`VideoTrackHandle` contracts coordinated with
  AND-299.
- Manual verification on a 3+ party call (against AND-299) on a minSdk 24 device
  and a current device: grid adapts on join/leave, active speaker highlights,
  pin/unpin works, rotation re-flows without flicker, no surface leaks under
  background/foreground cycles.
- Strings externalized; TalkBack pass for tile actions; telemetry events emit
  with no PII.
- Code reviewed and merged to `android-port`; spec status moved from `draft` to
  `accepted`; open questions R2/R3/R5 resolved or explicitly deferred with
  owning ticket noted.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Group-call endpoints live under `/ui/calls/group/*`.** VERIFIED.
   Source: OpenAPI `GET /ui/calls/group/{call_id}`, `POST /ui/calls/group/{call_id}/join`,
   `POST /ui/calls/group/{call_id}/leave`, `POST /ui/calls/group/{call_id}/end`,
   `GET /ui/calls/group/{call_id}/participants`, `PATCH /ui/calls/group/{call_id}/media`,
   `POST /ui/calls/group/{call_id}/signal`, `POST /ui/calls/group/create`,
   `GET /ui/calls/group/active/{conversation_id}`,
   `GET /ui/calls/group/history/{conversation_id}`. Also `src/api/endpoints/groupCalls.ts`.
2. **Join is `POST /ui/calls/group/{callId}/join`.** VERIFIED.
   Source: OpenAPI `POST /ui/calls/group/{call_id}/join`;
   `src/api/endpoints/groupCalls.ts: joinGroupCall`.
3. **Roster is `GET /ui/calls/group/{callId}` (original draft claim).** CORRECTED.
   The dedicated roster endpoint is `GET /ui/calls/group/{call_id}/participants`
   returning `GroupCallParticipantsOut`; `GET /ui/calls/group/{call_id}` returns
   the full `GroupCallOut`. Source: OpenAPI
   `GET /ui/calls/group/{call_id}/participants`;
   `src/api/endpoints/groupCalls.ts: getGroupCallParticipants` /
   `src/api/types.ts: GroupCallParticipantsOut`.
4. **Roster participant fields `id`/`avatar_url`/`audio_muted`/`video_enabled` (original draft JSON).**
   CORRECTED. Real fields per `GroupCallParticipant` are `user_id`,
   `display_name`, `joined_at`, `left_at`, `media_status:{audio,video,screen}`,
   `connection_quality`, `state`. No `id`, no `avatar_url`, no top-level mute
   flags. Source: `src/api/types.ts: GroupCallParticipant`,
   `src/api/types.ts: GroupCallMediaStatus`.
5. **AND-299 supplies normalized per-participant audio levels / a server dominant-speaker.**
   CORRECTED / Unverified-assumption. The REST DTOs carry NO audio-level and NO
   dominant-speaker field; active speaker must be derived client-side (WebRTC
   stats) or carried on the `signal` channel. Source: `src/api/types.ts:
   GroupCallParticipant` (absence), `src/api/endpoints/groupCalls.ts:
   sendGroupCallSignal`, OpenAPI `POST /ui/calls/group/{call_id}/signal`
   (`GroupCallSignalIn`). The exact shape AND-299 will expose as
   `session.audioLevels` is an Open assumption (below).
6. **CSRF: `X-CSRF-Token` header echoed from the `ui_csrf` cookie.** VERIFIED.
   Source: `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).
7. **Session bootstrap: `POST /ui/session/start` → MFA → `POST /ui/session/finalize`.**
   VERIFIED. Source: OpenAPI `POST /ui/session/start` (`UiSessionStartReq` →
   `UiSessionStartResp`), `POST /ui/session/finalize` (`UiSessionFinalizeReq`).
8. **401 → refresh once via `POST /ui/session/refresh`, handled by core-network (not this module).**
   VERIFIED. Source: OpenAPI `POST /ui/session/refresh`;
   `src/api/client.ts` (`fetch(withApiBase("/ui/session/refresh"))`, "try
   refreshing the session once" on `res.status === 401`).
9. **422 errors use FastAPI `detail`.** VERIFIED. Source: OpenAPI
   `components.schemas.HTTPValidationError` (`{detail: ValidationError[]}`);
   `src/api/client.ts: normalizeErrorDetail`.
10. **`media`/`signal` request bodies.** VERIFIED (informational; mapping owned by
    AND-299). Source: OpenAPI `GroupCallMediaUpdateIn` (`audio?/video?/screen?`),
    `GroupCallSignalIn` (`type`, `target_user_id`, `payload`),
    `GroupCallCreateIn` (`conversation_id`, `mode`, `max_participants≤8`).
11. **This ticket performs no network I/O.** VERIFIED by design — no endpoint
    calls appear in this module's API contract (§5); all calls are AND-299's.
12. **Compose/Material3 + `LazyVerticalGrid`/`BoxWithConstraints`/`animateItem`/`DisposableEffect` choices.**
    Unverified-assumption (framework ref). These are standard Jetpack Compose
    APIs; correctness depends on the AND-299 renderer primitive. framework ref:
    Jetpack Compose lists/grids docs
    (https://developer.android.com/develop/ui/compose/lists) and side-effects
    (https://developer.android.com/develop/ui/compose/side-effects).
13. **WebRTC `SurfaceViewRenderer` / `VideoTrack` sink wrapped in `AndroidView`.**
    Unverified-assumption (depends on AND-293/AND-299 primitive). framework ref:
    AndroidView interop
    (https://developer.android.com/develop/ui/compose/migrate/interoperability-apis/views-in-compose).
14. **minSdk 24 large-call decode budget (R3).** Unverified-assumption — no source
    in the provided references defines the simultaneous-decode cap; pending AND-299
    SFU limits and on-device profiling.

### Corrections made
- §5: roster endpoint corrected to `GET /ui/calls/group/{call_id}/participants`
  (was `GET /ui/calls/group/{callId}`); clarified that `{call_id}` GET returns the
  full call object and that path params are snake_case.
- §5: roster JSON corrected to the real `GroupCallParticipant` shape
  (`user_id`, `display_name`, `media_status:{audio,video,screen}`,
  `connection_quality`, `state`, `joined_at`, `left_at`); removed the nonexistent
  `id`/`avatar_url`/`audio_muted`/`video_enabled`; added the
  `CallParticipantUi` field-mapping and the real 422 `detail` shape.
- §13 R2: corrected the premise — the backend exposes no audio-level/dominant-speaker
  field, so `ActiveSpeakerDetector` cannot be a server-event pass-through.

### Open assumptions
- **`session.audioLevels` / active-speaker source (R2):** AND-299 must decide
  between WebRTC-stats-derived levels vs. a synthesized signal-channel
  dominant-speaker event. Not resolvable from the provided sources (no such REST
  field exists).
- **Avatar URL source:** the call roster has no `avatar_url`; AND-299 must resolve
  avatars via a separate profile lookup. The exact lookup is out of scope here and
  not specified in the provided references.
- **Renderer/track primitive contract (`VideoTrackHandle`, release path):** owned
  by AND-293/AND-299; not present in the provided references, so the disposal
  contract is assumed, not verified.
- **Large-call simultaneous-decode cap (R3):** no authoritative value available;
  requires SFU limits + physical-device profiling.

## 17. Test Plan

IDs `TC-AND-300-NN`. "Traces" links to §14 acceptance criteria (AC-1..AC-7).
Most cases are device-independent and run on JVM/Robolectric or the headless
emulator AVD `test35` (API 35). Cases exercising real GPU/multi-surface video
decode and rotation behavior under load PREFER the physical device
(Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a) — these are flagged.

- **TC-AND-300-01** — Type: unit (JVM). Target: `GridLayoutPolicy.spec`.
  Preconditions: none. Steps: call `spec(n, orientation)` for
  n ∈ {1,2,3,4,5,6,7,9,10,12} in PORTRAIT and LANDSCAPE. Expected: portrait
  1→1×1, 2→rows=2/cols=1, 3-4→2×2, 5-6→cols=2/rows=3, 7-9→3×3,
  10+→cols=3/scrollable=true; landscape transposes per FR-1 (2→side-by-side,
  3-4→2×2, 5-6→3×2). Traces: AC-1.
- **TC-AND-300-02** — Type: unit (JVM). Target: `GridLayoutPolicy.spec` clamping.
  Preconditions: none. Steps: call with n ∈ {0, -1, 9999}. Expected: n≤0 → 1×1
  placeholder spec; very large → cols=3, scrollable=true; never throws.
  Traces: AC-1, AC-5.
- **TC-AND-300-03** — Type: unit (JVM). Target: `GridLayoutPolicy.order`.
  Preconditions: roster with local + several remotes. Steps: order with a
  pinnedId and an activeSpeakerId set. Expected: pinned tile first, then active
  speaker, then stable join order; local tile in its fixed slot; identical input
  yields identical output (determinism). Traces: AC-3, AC-4.
- **TC-AND-300-04** — Type: unit (JVM, Turbine). Target: `ActiveSpeakerDetector.detect`.
  Preconditions: detector holdMs=500, threshold=0.15. Steps: emit level maps that
  (a) raise one speaker above threshold, (b) flip to another speaker before 500ms,
  (c) drop all below threshold. Expected: no switch before holdMs; switch after
  hold; emits null when all below threshold. Traces: AC-3.
- **TC-AND-300-05** — Type: unit (JVM, Turbine). Target: `GroupCallGridViewModel`.
  Preconditions: fake `GroupCallSession` emitting roster + audioLevels.
  Steps: collect `uiState`; call `pin(id)` then `unpin()`; emit a join then a
  leave. Expected: `uiState` combines roster + active speaker + pin; pin/unpin
  mutate `pinnedId`; join/leave re-emit without dropping the pinned tile or
  resetting active speaker. Traces: AC-2, AC-4, AC-7.
- **TC-AND-300-06** — Type: contract/MockWebServer (JVM/Robolectric).
  Target: the AND-299 roster→`CallParticipantUi` mapper this grid consumes
  (mapper exercised via fake session fed from a recorded response).
  Preconditions: MockWebServer returns a real `GroupCallParticipantsOut` body
  (`user_id`, `media_status:{audio,video,screen}`, `connection_quality`, `state`,
  `total_active`, `total_joined`). Steps: drive the session, map to
  `CallParticipantUi`. Expected: `id←user_id`, `isAudioMuted←!media_status.audio`,
  `isVideoEnabled←media_status.video`, `connection←connection_quality`,
  `tileState←state`; absent `avatar_url` → null avatar (placeholder path).
  Traces: AC-7, AC-5.
- **TC-AND-300-07** — Type: contract/MockWebServer (JVM/Robolectric).
  Target: error-shape handling surfaced to the grid edge states.
  Preconditions: MockWebServer returns 422 `HTTPValidationError`
  (`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`) and a 401 then a
  successful `/ui/session/refresh`. Steps: drive AND-299 session through both.
  Expected: grid does NOT retry; on `ApiResult.Failure` it shows the §3/§7 edge
  state; 401-refresh-once is handled upstream and the grid simply re-renders the
  refreshed roster. Traces: AC-7, AC-5.
- **TC-AND-300-08** — Type: Compose-UI (`createComposeRule`, emulator `test35`).
  Target: `GroupCallGrid` tile count + columns. Preconditions: state with N
  participants. Steps: render for N ∈ {1,4,6,9}; query nodes tagged
  `test:tile:<id>`. Expected: tile count == N and visible columns match
  `GridLayoutPolicy.spec`. Traces: AC-1.
- **TC-AND-300-09** — Type: Compose-UI (`createComposeRule`, emulator `test35`).
  Target: active-speaker highlight + pin/unpin. Preconditions: multi-tile state.
  Steps: set activeSpeakerId → assert speaking border AND speaking glyph (not
  color-only) on that tile; long-press a tile → assert focus region + `LazyRow`
  filmstrip; trigger unpin → assert grid restored. Expected: highlight and
  pin/unpin transitions occur as specified. Traces: AC-3, AC-4.
- **TC-AND-300-10** — Type: Compose-UI (`createComposeRule`, emulator `test35`).
  Target: empty + per-tile fault states. Preconditions: 0 remote participants;
  then a tile with `tileState=RECONNECTING`/`LOST`. Steps: render each.
  Expected: 0 remotes → "Waiting for others to join" with self full-bleed;
  RECONNECTING/LOST → dimmed tile + spinner overlay, tile NOT removed.
  Traces: AC-5.
- **TC-AND-300-11** — Type: Compose-UI / instrumented (emulator `test35`).
  Target: re-flow without renderer recreation. Preconditions: state with a fake
  renderer that counts attach/detach. Steps: add a participant, then toggle a
  participant's video; observe layout change. Expected: layout re-flows ≤250ms;
  surviving tiles' renderers are NOT re-attached and tracks not re-subscribed
  (stable `key=id`). Traces: AC-2.
- **TC-AND-300-12** — Type: instrumented/e2e (PHYSICAL DEVICE, SM-A156U).
  MUST run on the physical device — exercises real GPU multi-surface video
  decode, rotation, and surface lifecycle that the emulator does not represent
  faithfully; also validates arm64-v8a / API-34. Preconditions: a live 3+ party
  call via AND-299 (or a 4-track WebRTC harness). Steps: join a 4-party call;
  rotate portrait↔landscape; background then foreground the app; trigger a tile
  RECONNECTING. Expected: grid re-flows to the transposed spec without flicker or
  black tiles; no surface/GL leak across background cycles (DisposableEffect
  release verified via logcat leak-guard warning absence); video keeps rendering
  for surviving tiles. Traces: AC-1, AC-2, AC-5.
- **TC-AND-300-13** — Type: instrumented (emulator `test35`, optionally physical).
  Target: accessibility. Preconditions: multi-tile state, TalkBack semantics
  asserted via Compose semantics tree. Steps: inspect each tile's merged
  semantics node; invoke the "Pin <name>"/"Unpin" custom action; measure the
  pin/overflow target. Expected: one semantics node per tile with
  contentDescription "<name>, <muted|unmuted>, <speaking?>"; Pin/Unpin custom
  action present and functional; target ≥48dp; strings come from resources (no
  concatenation). Traces: AC-6.
- **TC-AND-300-14** — Type: manual (PHYSICAL DEVICE, SM-A156U).
  Target: end-to-end UX + offline/flaky-host path. Preconditions: dev backend
  (plaintext HTTP host) reachable; a 3+ party call. Steps: join; toggle others'
  join/leave; observe active-speaker promotion in a scrollable (10+) grid; pin a
  participant and rotate (pin must survive rotation); enable airplane mode briefly
  to force a flaky/offline host, then restore. Expected: grid adapts on
  join/leave; active speaker stays visible when scrollable; pin survives rotation;
  on offline the grid shows the §7 edge state and recovers when AND-299
  re-subscribes — the grid itself never issues retries. Traces: AC-2, AC-3, AC-4,
  AC-7.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (adaptive grid spec, both orientations) | TC-01, TC-02, TC-08, TC-12 |
| AC-2 (re-flow ≤250ms, no renderer recreation) | TC-05, TC-11, TC-12, TC-14 |
| AC-3 (active speaker: highlight, debounce, visible when scrollable) | TC-03, TC-04, TC-09, TC-14 |
| AC-4 (pin/unpin focus+filmstrip, survives rotation) | TC-03, TC-05, TC-09, TC-14 |
| AC-5 (waiting state + per-tile RECONNECTING/LOST) | TC-02, TC-06, TC-07, TC-10, TC-12 |
| AC-6 (accessibility: semantics, custom actions, ≥48dp, RTL/strings) | TC-13 |
| AC-7 (no network from module; data from AND-299 session) | TC-05, TC-06, TC-07, TC-14 |
