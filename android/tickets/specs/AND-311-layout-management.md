---
id: AND-311
title: Layout management
milestone: M7
epic: E41
priority: P2
size: M
status: draft
depends_on: [AND-310]
blocks: []
---

# AND-311 — Layout management

## 1. Overview & Goal

A live TestLogon broadcast composites its active **inputs** (AND-310) into a
visual **scene** described by a **layout**. A layout is the spatial recipe the
server-side mixer uses to arrange input sources on the program canvas: a single
full-frame source, a picture-in-picture, a side-by-side split, or a host-defined
grid. This ticket delivers the host-facing surface that **reads the available
scenes/layouts for the active broadcast and sets the current layout**, with the
change applying to the live program in near real time.

The goal: a host on the broadcast control screen can see the set of selectable
scenes (each a named layout, optionally with a thumbnail and the input slots it
exposes), see which scene is currently live, and tap a scene to make it the
active layout. The selection is sent to the server, the mixer re-composites the
program, and the change is reflected back to the host UI and to viewers
("layout changes apply"). The feature is read-then-mutate against the FastAPI
`/ui/broadcasts/{id}/layout` and `/ui/broadcasts/{id}/scenes` resources and
renders inside the existing `feature-broadcast` module.

Out of scope: defining/creating new layout templates, drag-to-reorder slot
authoring, and the actual server-side compositing — this ticket selects among
scenes the backend already offers and persists the choice. Input
activation/program-source selection is owned by AND-310 and consumed here as the
content that the chosen layout arranges.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6 (cache), DataStore (prefs), Coil (thumbnails). minSdk 24,
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Namespace / applicationId base:** `com.testlogon.android`. This feature lives
  at `com.testlogon.android.feature.broadcast.layout`.
- **Module layering:** `app -> feature-broadcast -> core-network, core-model,
  core-data, core-ui, core-testing`. ViewModels expose `StateFlow<UiState>`;
  network calls return typed `ApiResult<T>`; FastAPI `detail` is mapped
  (string | `[{msg}]` | `{code,...}`) by the shared error mapper.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). Cookie-based session + `ui_csrf` echoed as
  `X-CSRF-Token`; on 401 the OkHttp authenticator calls
  `POST /ui/session/refresh` once and retries. Persistent cookie jar required.
  Contract authority is `/openapi.json`; web reference is
  `frontend/src/api/endpoints/broadcasts.ts` and `frontend/src/api/types.ts`.
- **Upstream deps:** **AND-310 (Inputs management, P1)** establishes the inputs
  collection, the program-source invariant, and the `feature-broadcast` inputs
  surface. AND-311 depends on AND-310 supplying the broadcast id, an
  authenticated host session, and the set of inputs that scenes reference by
  slot. The inputs Room cache and `InputsRepository` from AND-310 are reused to
  resolve which inputs fill a scene's slots. Core session/CSRF/cookie-jar,
  `ApiResult`, and the `detail` error mapper are inherited from M1.

## 3. Functional Requirements

FR-1. **List scenes.** On entering the layout panel for broadcast `{id}`, fetch
`GET /ui/broadcasts/{id}/scenes` and render one selectable card per scene
showing: `name`, `kind` (`single | pip | split | grid | custom`), the number of
input slots, an optional thumbnail (Coil), and whether the scene is currently
the live layout.

FR-2. **Show current layout.** Fetch `GET /ui/broadcasts/{id}/layout` (or read
the `current_scene_id` embedded in the scenes response) and badge the active
scene as "LIVE".

FR-3. **Set layout (live switch).** Tapping a non-active scene calls
`PUT /ui/broadcasts/{id}/layout {scene_id}`. Exactly one scene is live at a time;
selecting scene B demotes scene A locally and on the server. This is the
acceptance behavior — "layout changes apply."

FR-4. **Slot mapping (display).** For scenes with named input slots
(`slots: [{id,label}]`), render the input currently assigned to each slot using
the cached inputs from AND-310. If the backend exposes per-slot input assignment
in the scene payload, it is shown read-only; slot re-assignment authoring is out
of scope.

FR-5. **Guards.** The currently-live scene's card is shown as selected and is a
no-op on tap (no redundant `PUT`). A scene that references an input slot with no
resolvable input is rendered with a non-blocking "needs a source" hint but
remains selectable (server is authoritative on validity).

FR-6. **Live refresh.** The active-layout indicator reflects server-driven
changes within ~3s without manual reload, via poll (default) or the broadcast
event channel if AND-308/AND-310 expose it. Stale data is visibly flagged when
the backend is unreachable.

FR-7. **No teardown.** Setting a layout mutates the running broadcast's
compositing only; it never starts, stops, or ends the broadcast.

## 4. Technical Design

New package `com.testlogon.android.feature.broadcast.layout` inside
`feature-broadcast`.

**Domain model** (`core-model`):

```kotlin
enum class SceneKind { SINGLE, PIP, SPLIT, GRID, CUSTOM, UNKNOWN }

data class SceneSlot(
    val id: String,
    val label: String,
    val assignedInputId: String?, // resolved against InputsRepository cache
)

data class Scene(
    val id: String,
    val broadcastId: String,
    val name: String,
    val kind: SceneKind,
    val slots: List<SceneSlot>,
    val thumbnailUrl: String?,
    val updatedAt: Instant,
)

data class BroadcastLayout(
    val broadcastId: String,
    val currentSceneId: String?,
    val scenes: List<Scene>,
    val updatedAt: Instant,
)
```

**Repository** (`core-data`, interface in `core-data`, impl Hilt-bound):

```kotlin
interface LayoutRepository {
    fun observeLayout(broadcastId: String): Flow<BroadcastLayout> // cache-backed
    suspend fun refresh(broadcastId: String): ApiResult<BroadcastLayout>
    suspend fun setLayout(broadcastId: String, sceneId: String): ApiResult<BroadcastLayout>
}
```

`observeLayout` emits from the Room cache (`broadcast_scenes` table keyed by
`(broadcastId, id)` plus a `broadcast_layout` row holding `currentSceneId`);
`refresh` performs the GETs and upserts. `setLayout` writes through: on success
the server's returned layout replaces the cached `currentSceneId` and scene
rows; on failure the cache is restored from the pre-mutation snapshot.

**ViewModel:**

```kotlin
@HiltViewModel
class LayoutViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val layoutRepo: LayoutRepository,
    private val inputsRepo: InputsRepository, // AND-310, for slot resolution
) : ViewModel() {
    private val broadcastId: String = savedState["broadcastId"]!!
    val uiState: StateFlow<LayoutUiState>
    fun onSelectScene(sceneId: String)
    fun onRetry()
}

sealed interface LayoutUiState {
    data object Loading : LayoutUiState
    data class Content(
        val scenes: List<SceneCard>,
        val currentSceneId: String?,
        val isStale: Boolean = false,
        val banner: String? = null,
        val pendingSceneId: String? = null, // in-flight optimistic switch
    ) : LayoutUiState
    data class Empty(val isStale: Boolean = false) : LayoutUiState
    data class Error(val message: String, val retryable: Boolean) : LayoutUiState
}

data class SceneCard(
    val scene: Scene,
    val isLive: Boolean,        // scene.id == currentSceneId
    val isSelectable: Boolean,  // !isLive && pendingSceneId == null
    val unresolvedSlots: Int,   // slots whose assignedInputId is missing/unknown
)
```

`uiState` is built by combining `observeLayout`, the AND-310
`inputsRepo.observeInputs` flow (to resolve `unresolvedSlots`), and a
`pendingSceneId` `MutableStateFlow`, surfaced via
`stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`. A
polling loop (`while (isActive) { layoutRepo.refresh(broadcastId); delay(3_000) }`)
runs only while subscribed; if the broadcast event channel is available it is
collected instead, falling back to poll on disconnect.

**UI** (`LayoutScreen`, `SceneCardItem` composables): a Material 3 vertical grid
(`LazyVerticalGrid`, adaptive min cell ~160dp) of scene cards. Each card =
Coil thumbnail (placeholder kind-icon when absent), scene name, kind + slot-count
chip, and a selected/"LIVE" affordance on the active card. The pending card shows
a centered progress indicator and the grid is non-interactive while a switch is
in flight. Empty state and full-screen error/retry reuse shared `core-ui`
state composables (AND-021). Navigation route
`broadcast/{broadcastId}/layout` is added to the `feature-broadcast` nav graph.

## 5. API Contract

All requests carry session cookies and `X-CSRF-Token` (from `ui_csrf`).
Confirm exact shapes against `/openapi.json`; map deltas in code review (see R3).

**List scenes** — `GET /ui/broadcasts/{id}/scenes` → `200`:

```json
{
  "current_scene_id": "sc_01H...",
  "scenes": [
    {
      "id": "sc_01H...",
      "broadcast_id": "bc_01H...",
      "name": "Picture in picture",
      "kind": "pip",
      "thumbnail_url": "https://.../thumb/pip.png",
      "slots": [
        { "id": "main", "label": "Main", "assigned_input_id": "in_01H..." },
        { "id": "inset", "label": "Inset", "assigned_input_id": null }
      ],
      "updated_at": "2026-06-05T12:00:00Z"
    }
  ]
}
```

**Get current layout** — `GET /ui/broadcasts/{id}/layout` → `200`:

```json
{ "broadcast_id": "bc_01H...", "current_scene_id": "sc_01H...",
  "updated_at": "2026-06-05T12:00:00Z" }
```

If `scenes` already embeds `current_scene_id`, the dedicated layout GET is
optional and used only for the live-refresh poll (cheaper payload).

**Set layout** — `PUT /ui/broadcasts/{id}/layout`:

```json
{ "scene_id": "sc_01H..." }
```

→ `200` returns the full refreshed layout (so the demoted prior scene is
reflected atomically), shape equal to the scenes response above (or at minimum
`{ "current_scene_id": "...", "scenes": [...] }`). `PUT` is chosen for idempotent
"set to this value" semantics; if the backend exposes `POST .../layout` instead,
adapt in the API layer and pin via the contract guard test (§11).

**Errors:** `400` invalid scene (e.g., scene references an input not on this
broadcast), `401` session expired (authenticator refresh+retry), `403`
non-host / CSRF mismatch, `404` broadcast or scene not found, `409` conflicting
concurrent layout change, `5xx`/timeout from the unreliable dev host. FastAPI
`detail` is parsed via the shared mapper (string | `[{msg}]` | `{code,msg}`).

**Moshi DTOs** (`core-network`): `SceneDto`, `SceneSlotDto`, `ScenesResponseDto`,
`LayoutDto`, `SetLayoutRequestDto`; `@Json(name=...)` for snake_case; a
`MapToSceneKind` adapter coerces unknown enum strings to `UNKNOWN` rather than
throwing.

## 6. Data & State Management

- **Room** (`core-data`): table `broadcast_scenes` (PK `(broadcastId, id)`),
  columns mirroring `Scene` with `slots` stored via a Moshi `List<SceneSlot>`
  type converter; a `broadcast_layout` table (PK `broadcastId`) holding
  `currentSceneId` + `updatedAt`. `LayoutDao` with `observeScenes`,
  `observeLayout`, `upsertScenes`, `replaceScenesForBroadcast`, `upsertLayout`.
  The cache is the UI source of truth so the panel renders instantly on re-entry
  and survives transient network loss (FR-6 stale handling).
- **Optimistic switch:** on `onSelectScene`, `pendingSceneId` is set and the
  card's selected/"LIVE" badge moves to the target immediately; on
  `ApiResult.Success` the server-returned layout is upserted and
  `pendingSceneId` cleared; on failure the cached `currentSceneId` is restored
  and a transient banner shown.
- **Single-live invariant:** `setLayout` replaces the layout row + scene rows
  from the server response, guaranteeing exactly one `currentSceneId`. If a poll
  response and a switch response race, last-write-by-`updatedAt` wins on upsert.
- **Slot resolution:** `unresolvedSlots` is derived at the ViewModel layer by
  cross-referencing `SceneSlot.assignedInputId` against the AND-310 inputs cache;
  it is presentation-only and never persisted.
- **DataStore:** persists per-broadcast UI prefs only (e.g., last grid scroll /
  preferred card density); no session, scene identity, or input identity is
  stored there.
- **Lifecycle:** polling/event collection is tied to `WhileSubscribed`; leaving
  the screen stops it. No background work is scheduled.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s for these endpoints, matching the
  unreliable dev host budget.
- **Retry policy:** only the idempotent `GET .../scenes` and `GET .../layout` are
  auto-retried with bounded exponential backoff (3 attempts, 500ms→2s, jitter).
  `PUT .../layout` is idempotent at the HTTP level but is **not** auto-retried by
  default to avoid surprising re-applies during a fast manual sequence; failures
  surface with a manual "Retry" affordance. (If product wants resilient
  auto-apply, enabling retry for this single `PUT` is safe given its idempotent
  set-semantics — tracked as OQ.)
- **Offline / unreachable:** if `refresh` fails but cache exists, render
  `Content(isStale=true)` with a "Showing last known layout" banner; if no cache,
  render `Error(retryable=true)`.
- **Optimistic rollback:** any `setLayout` failure restores the prior
  `currentSceneId` and shows the mapped `detail` message (e.g., "Scene needs a
  live source").
- **401 handling:** delegated to the OkHttp authenticator (single
  `session/refresh` + retry); a second 401 surfaces a re-auth prompt routed to
  the auth flow.
- **Concurrent edits:** a `409` triggers a forced `refresh` and a banner
  ("Layout changed elsewhere — refreshed").
- **Missing thumbnails:** Coil load failure falls back to the kind icon; never
  blocks card interaction.

## 8. Security & Privacy

- All calls require the authenticated host cookie session and a valid
  `X-CSRF-Token`; the persistent cookie jar from M1 is reused. The `PUT` mutation
  is host-only — a `403` is rendered as "You don't have permission to change the
  layout."
- No credentials, cookies, `scene_id`s, or `input_id`s are written to logs
  (see §10) or to DataStore. The plaintext dev host is dev-only;
  `cleartextTrafficPermitted` stays scoped to the dev host in the network
  security config inherited from core-network — no plaintext exception for prod.
- Scene `name` and slot `label` may contain user-entered text; they are rendered
  as text only (no HTML/markdown) to avoid UI injection.
- Thumbnail URLs are loaded by Coil over the configured client only; only
  same-host/HTTPS (prod) image hosts are honored. No media bytes are processed
  in this feature (compositing is server-side).
- No PII beyond the host's own session is handled.

## 9. Accessibility & i18n

- Each scene card is a single focusable element with
  `semantics { role = Button; stateDescription = "Live" / "Not live" }` and a
  `contentDescription` of "Scene <name>, <kind>, <n> slots". The live card adds
  "Currently live layout".
- The "LIVE" badge pairs color with a text label and icon (never color-only) to
  meet contrast/colorblind needs; minimum touch target 48dp; the unresolved-slot
  hint is conveyed by icon + text, not color alone.
- All strings live in `res/values/strings.xml` (no hardcoded literals); slot
  counts use Android plurals; timestamps formatted with the device locale.
  RTL-safe layouts (start/end padding, mirrored kind icons).
- Layout changes use `liveRegion = LiveRegionMode.Polite` so screen readers
  announce "<name> is now the live layout" without stealing focus.
- Thumbnails carry no semantic content (decorative); the card's text label is the
  accessible name, so images use `contentDescription = null`.

## 10. Telemetry & Logging

- Structured events via the shared analytics interface (`core-data`):
  `layout_viewed{broadcast_id_hash, scene_count}`,
  `layout_changed{from_kind, to_kind, result}`,
  `layout_refresh_failed{http_status, cause}`,
  `scene_slot_unresolved{kind, missing_slots}`. Broadcast/scene/input ids are
  hashed, not raw, in analytics.
- `Timber` debug logs gate behind `BuildConfig.DEBUG`; request/response bodies
  are never logged at info+; the OkHttp logging interceptor is `BASIC` in debug
  and `NONE` in release. CSRF tokens and cookies are redacted by the existing
  interceptor redaction list.
- A `result` dimension (`success | error | timeout`) on `layout_changed` feeds
  the acceptance check that layout changes actually land server-side.

## 11. Testing Strategy

- **Unit (ViewModel, `core-testing` + Turbine):** loading→content transition;
  `onSelectScene` optimistically moves the live badge and keeps it on success;
  `setLayout` failure rolls back `currentSceneId` and emits a banner; tapping the
  already-live card is a no-op (no repo call); `unresolvedSlots` computed from the
  combined inputs flow; stale flag set when refresh fails with warm cache; grid
  non-interactive while `pendingSceneId != null`.
- **Repository (MockWebServer):** scenes GET parse incl. unknown `kind` →
  `UNKNOWN` and null `assigned_input_id`; `setLayout` whole-layout replacement
  enforces a single `currentSceneId`; GET retried on 503 then succeeds; `PUT` not
  retried on 503 by default; 401 path triggers authenticator refresh (one retry);
  `detail` mapping for string/list/object shapes; `409` surfaces and is followed
  by a refresh.
- **DAO (Room in-memory):** scene upsert keyed by `(broadcastId,id)`,
  `replaceScenesForBroadcast` atomicity, `slots` type-converter round-trip,
  `observeLayout` emits on `currentSceneId` change.
- **Compose UI tests:** live card shows "LIVE" and is non-actionable; selecting a
  non-live card shows its pending progress and disables the grid; empty and
  error/retry states; unresolved-slot hint rendered; semantics/contentDescription
  and `stateDescription` assertions; Coil fallback icon on image failure (test
  dispatcher / fake image loader).
- **Contract guard:** a JSON fixture test pinned to `/openapi.json` example
  payloads for `scenes`, `layout`, and the `PUT` body, failing if field names
  (`scene_id`, `current_scene_id`, `assigned_input_id`) or the verb drift from §5.

## 12. Dependencies & Sequencing

- **Depends on AND-310 (P1):** provides the inputs collection, the inputs Room
  cache + `InputsRepository` reused for slot resolution, and the
  `feature-broadcast` host control surface this panel sits alongside. AND-311
  must not begin UI integration until AND-310's input identifiers (`input_id`)
  and the broadcast id contract are stable, since scene slots reference them.
- Transitively depends on AND-308 (broadcast + optional event channel for live
  refresh) via AND-310.
- Inherits M1 session/CSRF/cookie-jar, `ApiResult`, and the `detail` error mapper
  from `core-network`; reuses AND-021 state composables and AND-019 theme.
- **Sequencing:** (1) DTOs + `LayoutRepository` + DAO + type converters;
  (2) ViewModel + state + optimistic/rollback + slot resolution against inputs
  cache; (3) Compose grid UI + nav route + Coil thumbnails; (4) live-refresh
  (poll, then swap to event channel if exposed). No tickets currently declare a
  hard block on AND-311.

## 13. Risks & Open Questions

- **R1 — scenes vs layout endpoints:** whether the backend exposes separate
  `/scenes` (catalog) and `/layout` (current) resources or a single combined one,
  and whether scenes are broadcast-scoped or account-level templates, is
  unconfirmed. Assumed broadcast-scoped with `current_scene_id` embedded in the
  scenes payload; confirm against `/openapi.json` (contract guard catches drift).
- **R2 — set verb/body:** `PUT .../layout {scene_id}` vs `POST` vs a body key of
  `scene_id` / `layout_id` / `current_scene_id` is an assumption pending the
  spec; isolated in the API layer + contract test.
- **R3 — slot authoring scope:** this ticket displays slot→input assignment
  read-only. If product expects the host to re-map inputs to slots from this
  screen, scope grows to L (drag/assign UI + a slot-assignment mutation endpoint)
  and should be split into a follow-up ticket.
- **R4 — real-time channel:** existence/shape of a broadcast event channel is
  unconfirmed; fallback is 3s polling, acceptable for "layout changes apply"
  within ~3s.
- **R5 — concurrency:** multiple host devices changing layout; mitigated by
  `409` → forced refresh, but no locking exists.
- **OQ:** Is selecting a scene whose slots are unresolved rejected by the server
  (`400`) or accepted with empty slots? Should the `PUT` auto-retry on transient
  5xx given its idempotent set-semantics? Pending product/backend input.

## 14. Acceptance Criteria

- AC-1. The layout panel lists every scene of broadcast `{id}` with name, kind,
  slot count, optional thumbnail, and a "LIVE" badge on the current scene.
- AC-2. **Layout changes apply:** selecting a non-live scene issues
  `PUT /ui/broadcasts/{id}/layout {scene_id}`, makes it the live layout, demotes
  the prior one, and the change is reflected within ~3s (poll or event channel).
  *(source acceptance)*
- AC-3. Exactly one scene is live at any time; the live scene's card is shown
  selected and tapping it issues no request.
- AC-4. The selection is optimistic and rolls back to the prior live scene on
  failure with a user-visible, `detail`-mapped message.
- AC-5. Scenes with unresolved input slots render a non-blocking hint (resolved
  against the AND-310 inputs cache) and remain selectable.
- AC-6. Mixed/duplicate scene kinds and the empty/0-scene case render correctly.
- AC-7. With the dev host unreachable, the panel shows the cached layout flagged
  stale (warm cache) or a retryable error (cold cache); GETs retry, the layout
  `PUT` does not auto-retry.
- AC-8. All controls are keyboard/TalkBack accessible with correct state
  semantics; all strings are localized resources; thumbnails are decorative.

## 15. Definition of Done

- All AC-1..AC-8 verified by automated tests where feasible and one manual host
  walkthrough on a device against the dev backend (switch a live broadcast
  between at least two scenes and observe the change apply).
- Code merged to `android-port` under `feature-broadcast`, package
  `com.testlogon.android.feature.broadcast.layout`, respecting module layering
  (no `core-*` → `feature-*` deps).
- Unit + repository + DAO + Compose UI tests pass in CI; contract guard test
  green against the current `/openapi.json`.
- No hardcoded strings; lint/detekt/ktlint clean; no cookies/CSRF/ids in logs.
- KDoc on `LayoutRepository`, `LayoutViewModel`, and public DTOs.
- §13 open questions (R1 endpoint shape, R2 verb/body, R3 slot-authoring scope,
  and the `PUT` auto-retry OQ) resolved or explicitly deferred with owners noted
  in the PR description.
