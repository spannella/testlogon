---
id: AND-300
title: Group call grid
milestone: M7
epic: E40
priority: P1
size: M
status: draft
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
under `/ui/calls/group/*` (e.g. `POST /ui/calls/group/{callId}/join`,
`GET /ui/calls/group/{callId}` for roster, and the WebSocket/WebRTC channel that
streams participant join/leave and audio-level events). The grid consumes the
already-decoded domain model exposed by AND-299:

```kotlin
interface GroupCallSession {
    val participants: Flow<List<CallParticipantUi>> // mapped from roster + tracks
    val audioLevels: Flow<Map<String, Float>>       // participantId -> 0f..1f
}
```

Expected roster shape produced upstream (for reference; mapping owned by AND-299,
including FastAPI `detail` error mapping per core-network conventions):

```json
{
  "call_id": "c_8f3a",
  "participants": [
    {"id": "u_12", "display_name": "Ada", "avatar_url": "https://…/a.jpg",
     "audio_muted": false, "video_enabled": true, "state": "live"},
    {"id": "u_07", "display_name": "Lin", "avatar_url": null,
     "audio_muted": true, "video_enabled": false, "state": "connecting"}
  ]
}
```

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
- **R2 Active-speaker source of truth.** Open: does AND-299 supply normalized
  audio levels or only a server-chosen dominant speaker? If the SFU already emits
  a dominant-speaker event, `ActiveSpeakerDetector` becomes a thin pass-through.
  Confirm with AND-299 owner.
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
