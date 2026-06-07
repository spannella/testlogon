---
id: AND-311
title: Layout management
milestone: M7
epic: E41
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-310]
blocks: []
---

# AND-311 — Layout management

## 1. Overview & Goal

A live TestLogon broadcast composites its active **inputs** (AND-310) into a
visual program described by a **layout**. A layout is the spatial recipe the
server-side mixer uses to arrange input sources on the program canvas. Per the
verified contract (`BroadcastLayoutSwitchIn` / `BroadcastLayoutOut`), a layout is
**not** a named "scene" object — it is a **`mode`** chosen from a fixed enum
(`single | side_by_side | pip | grid`) together with the participating
`input_ids`, an optional `primary_input_id`, and server-computed `positions`.
This ticket delivers the host-facing surface that **reads the current layout for
the active broadcast session and switches the layout mode**, with the change
applying to the live program in near real time.

> **REVIEW CORRECTION (R1/R2):** The original draft assumed a `/scenes` catalog
> of named, thumbnailed scenes with per-scene input *slots*, selected by
> `scene_id` via `PUT /ui/broadcasts/{id}/layout`. The authoritative backend
> (`reference/openapi.index.txt` lines 193–194) and web client
> (`reference/src/pages/broadcast/LayoutSwitcher.tsx`) show **no scenes endpoint
> exists**. The real model is a 4-mode enum switch. The spec below has been
> corrected to that model; "scene" now means "a selectable layout **mode**."

The goal: a host on the broadcast control screen sees the four selectable layout
modes (Full / Side / PiP / Grid, mirroring the web client's `LAYOUT_MODES`),
sees which mode is currently live, and taps a mode to make it active. The
selection is sent to the server (`POST /broadcast/sessions/{session_id}/layout`),
the mixer re-composites the program, and the change is reflected back to the host
UI and to viewers ("layout changes apply"). The feature is read-then-mutate
against the FastAPI `/broadcast/sessions/{session_id}/layout` resource (GET +
POST) and renders inside the existing `feature-broadcast` module.

Out of scope: defining/creating new layout templates, drag-to-reorder authoring,
free-form per-input `positions` editing, and the actual server-side compositing
— this ticket selects among the four modes the backend already supports and
applies the choice. Input activation/program-source selection is owned by
AND-310 and consumed here (its `input_ids`) as the content the chosen mode
arranges.

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
  (plaintext, unreliable). **CORRECTED auth model** (verified in
  `reference/src/api/client.ts`): the primary credential is an
  `Authorization: Bearer <accessToken>` header sourced from the auth store; in
  addition the request sends the `ui_csrf` cookie value as `X-CSRF-Token`, sends
  cookies (`credentials: include`), and may send `X-IMPERSONATION-TOKEN`. On
  `401` the client calls `POST /ui/session/refresh` once and retries the original
  request (verified `client.ts: refreshSession`). The Android port reuses the M1
  Bearer-token + CSRF + persistent cookie jar transport. The layout endpoints
  additionally document an optional `user_sub` **query param** and optional
  `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (OpenAPI lines 193–194).
  Contract authority is `/openapi.json`; web reference is
  `reference/src/api/endpoints/broadcast-inputs.ts` (NOT `broadcasts.ts`) and
  `reference/src/api/types.ts` (`BroadcastLayout`).
- **Upstream deps:** **AND-310 (Inputs management, P1)** establishes the inputs
  collection, the program-source invariant, and the `feature-broadcast` inputs
  surface. AND-311 depends on AND-310 supplying the broadcast id, an
  authenticated host session, and the set of inputs that scenes reference by
  slot. The inputs Room cache and `InputsRepository` from AND-310 are reused to
  resolve which inputs fill a scene's slots. Core session/CSRF/cookie-jar,
  `ApiResult`, and the `detail` error mapper are inherited from M1.

## 3. Functional Requirements

FR-1. **List layout modes.** On entering the layout panel for session
`{session_id}`, render one selectable card per **fixed mode** in the enum
`single | side_by_side | pip | grid` (CORRECTED from `single|pip|split|grid|custom`;
there is **no** `split`/`custom`, and `side_by_side` was missing). The mode list
is a client-side constant (mirroring the web client's `LAYOUT_MODES`), **not** a
server-fetched catalog — no `GET .../scenes` endpoint exists. Each card shows the
mode label/icon (Full / Side / PiP / Grid) and whether it is currently live.

FR-2. **Show current layout.** Fetch `GET /broadcast/sessions/{session_id}/layout`
→ `BroadcastLayoutOut` and badge the card whose `mode` equals the returned `mode`
as "LIVE". (There is no `current_scene_id`; the live indicator is the returned
`mode` field.)

FR-3. **Set layout (live switch).** Tapping a non-active mode calls
`POST /broadcast/sessions/{session_id}/layout` (CORRECTED from `PUT`) with body
`BroadcastLayoutSwitchIn { mode, input_ids?, primary_input_id? }`. Exactly one
mode is live at a time; selecting mode B replaces mode A on the server (the
response carries the new `mode`). This is the acceptance behavior — "layout
changes apply."

FR-4. **Input arrangement (display).** The returned `BroadcastLayoutOut` carries
`input_ids`, `primary_input_id`, and server-computed `positions[]` (each
`{input_id, x, y, width, height, z_index}`). These are shown **read-only**;
resolving `input_ids` / `primary_input_id` to human-readable input names uses the
cached inputs from AND-310. There are no named per-scene "slots" in the contract;
free-form `positions` editing is out of scope.

FR-5. **Guards.** The currently-live mode's card is shown as selected and is a
no-op on tap (no redundant `POST`). A mode selected while the broadcast has no
resolvable program inputs is rendered with a non-blocking hint but remains
selectable (server is authoritative on validity — `422` if the body is invalid).

FR-6. **Live refresh.** The active-layout indicator reflects server-driven
changes without manual reload via poll. **CORRECTED interval:** the web client
polls `getLayout` every **5000ms** (`LayoutSwitcher.tsx: refetchInterval: 5000`);
the Android port matches ~5s by default (the prior "~3s" is not backed by the
reference and is downgraded to a target). If a broadcast event channel is exposed
by AND-308/AND-310 it may be collected instead — UNVERIFIED, no such channel is
visible in the reference. Stale data is visibly flagged when the backend is
unreachable.

FR-7. **No teardown.** Switching layout mutates the running broadcast's
compositing only; it never starts, stops, or ends the broadcast (the layout
endpoint is distinct from `start`/`stop`, OpenAPI lines 244–245).

## 4. Technical Design

New package `com.testlogon.android.feature.broadcast.layout` inside
`feature-broadcast`.

**Domain model** (`core-model`) — CORRECTED to the verified `BroadcastLayoutOut`
shape (no named scenes, no slots, no thumbnails):

```kotlin
// The four server-accepted modes (pattern ^(single|side_by_side|pip|grid)$),
// plus UNKNOWN for forward-compat on unrecognized server values.
enum class LayoutMode { SINGLE, SIDE_BY_SIDE, PIP, GRID, UNKNOWN }

// One server-computed placement rect for a participating input.
data class InputPosition(
    val inputId: String,   // input_id
    val x: Float,
    val y: Float,
    val width: Float,
    val height: Float,
    val zIndex: Int,       // z_index
)

// Mirrors BroadcastLayoutOut { mode, input_ids, positions, primary_input_id }.
data class BroadcastLayout(
    val sessionId: String,          // not in the body; carried from the request
    val mode: LayoutMode,           // required
    val inputIds: List<String>,     // input_ids (defaults to empty)
    val primaryInputId: String?,    // primary_input_id (nullable)
    val positions: List<InputPosition>,
)
```

The selectable set of modes is a static UI constant (`LayoutMode.SINGLE`,
`SIDE_BY_SIDE`, `PIP`, `GRID`), not data fetched from the server.

**Repository** (`core-data`, interface in `core-data`, impl Hilt-bound):

```kotlin
interface LayoutRepository {
    fun observeLayout(sessionId: String): Flow<BroadcastLayout> // cache-backed
    suspend fun refresh(sessionId: String): ApiResult<BroadcastLayout>
    suspend fun setLayout(
        sessionId: String,
        mode: LayoutMode,
        inputIds: List<String>? = null,        // optional; omit to let server keep set
        primaryInputId: String? = null,
    ): ApiResult<BroadcastLayout>
}
```

`observeLayout` emits from the Room cache (single `broadcast_layout` row per
`sessionId` holding `mode`, `primaryInputId`, and the `inputIds`/`positions`
collections via type converters); `refresh` performs the single
`GET .../layout` and upserts. `setLayout` writes through: on success the server's
returned `BroadcastLayoutOut` replaces the cached row; on failure the cache is
restored from the pre-mutation snapshot. There is no separate scenes table
because there is no scenes endpoint.

**ViewModel:**

```kotlin
@HiltViewModel
class LayoutViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val layoutRepo: LayoutRepository,
    private val inputsRepo: InputsRepository, // AND-310, to label input_ids
) : ViewModel() {
    private val sessionId: String = savedState["sessionId"]!!
    val uiState: StateFlow<LayoutUiState>
    fun onSelectMode(mode: LayoutMode)
    fun onRetry()
}

sealed interface LayoutUiState {
    data object Loading : LayoutUiState
    data class Content(
        val cards: List<ModeCard>,
        val currentMode: LayoutMode,
        val activeInputCount: Int,   // input_ids size, for the "no source" hint
        val isStale: Boolean = false,
        val banner: String? = null,
        val pendingMode: LayoutMode? = null, // in-flight optimistic switch
    ) : LayoutUiState
    data class Error(val message: String, val retryable: Boolean) : LayoutUiState
}

data class ModeCard(
    val mode: LayoutMode,       // one of the four fixed modes
    val isLive: Boolean,        // mode == currentMode
    val isSelectable: Boolean,  // !isLive && pendingMode == null
    val needsSource: Boolean,   // true when activeInputCount == 0
)
```

`uiState` is built by combining `observeLayout`, the AND-310
`inputsRepo.observeInputs` flow (to label/validate `input_ids`), and a
`pendingMode` `MutableStateFlow`, surfaced via
`stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`. A
polling loop (`while (isActive) { layoutRepo.refresh(sessionId); delay(5_000) }`,
CORRECTED from 3_000 to match the web client) runs only while subscribed. No
broadcast event channel is used (none is visible in the reference — see §13 R4).
Note there is no `Empty` state: the four modes are always shown; loading/error
only gate the initial fetch of the *current* mode.

**UI** (`LayoutScreen`, `ModeCardItem` composables): a Material 3 row/grid
(`LazyVerticalGrid`, adaptive min cell ~120dp, or a simple `Row` of four buttons
mirroring the web `LayoutSwitcher`) of the four mode cards. Each card = a mode
icon (Full = monitor, Side = columns, PiP = picture-in-picture, Grid = grid;
matching `LayoutSwitcher.tsx` lucide icons), the mode label, and a
selected/"LIVE" affordance on the active card. No Coil/thumbnails are used —
there are no scene thumbnail URLs in the contract; the mode icon is a static
vector. The pending card shows a centered progress indicator and the grid is
non-interactive while a switch is in flight. Full-screen error/retry reuses
shared `core-ui` state composables (AND-021); there is no empty state (modes are
always present). Navigation route `broadcast/{sessionId}/layout` (CORRECTED from
`{broadcastId}`) is added to the `feature-broadcast` nav graph.

## 5. API Contract

All requests carry the `Authorization: Bearer` token, `X-CSRF-Token` (from
`ui_csrf`), and session cookies (verified `reference/src/api/client.ts`). The
layout endpoints also accept an optional `user_sub` query param and optional
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (OpenAPI lines 193–194). Shapes
below are taken **verbatim** from `components.schemas` and `types.ts`.

> **REVIEW CORRECTION:** There is **no** `GET /ui/broadcasts/{id}/scenes` and no
> `PUT`. The original payloads (named scenes, slots, thumbnails, `scene_id`,
> `current_scene_id`, `broadcast_id`, `updated_at`) do **not** exist in the
> contract and have been removed.

**Get current layout** — `GET /broadcast/sessions/{session_id}/layout` → `200`
`BroadcastLayoutOut` (verified OpenAPI line 193; `types.ts: BroadcastLayout`):

```json
{
  "mode": "pip",
  "input_ids": ["in_01H...", "in_02H..."],
  "primary_input_id": "in_01H...",
  "positions": [
    { "input_id": "in_01H...", "x": 0, "y": 0, "width": 1280, "height": 720, "z_index": 0 },
    { "input_id": "in_02H...", "x": 960, "y": 540, "width": 320, "height": 180, "z_index": 1 }
  ]
}
```

Only `mode` is required; `input_ids` defaults to `[]`, `primary_input_id` is
nullable, `positions` is a list of free-form objects (web `types.ts` pins the
`{input_id,x,y,width,height,z_index}` shape — treat extra keys leniently).

**Set layout** — `POST /broadcast/sessions/{session_id}/layout` (verified OpenAPI
line 194), body `BroadcastLayoutSwitchIn`:

```json
{ "mode": "pip", "input_ids": ["in_01H..."], "primary_input_id": "in_01H..." }
```

`mode` is required and constrained to `^(single|side_by_side|pip|grid)$`;
`input_ids` and `primary_input_id` are optional/nullable. The web client sends
only `{ mode }` (`LayoutSwitcher.tsx: switchLayout(sessionId, { mode })`); the
Android port may do the same and let the server retain the input set. → `200`
returns the refreshed `BroadcastLayoutOut` (same shape as the GET), so the new
`mode` is reflected atomically. **POST**, not PUT — pinned via the §11 contract
guard.

**Errors:** the only documented non-2xx for these ops is **`422`
HTTPValidationError** (FastAPI validation, e.g. a `mode` not matching the
pattern), whose `detail` is the list form `[{loc, msg, type}]`. `401`/`403`
arise at runtime from the shared auth dependency (handled by the
refresh+retry authenticator and the `detail` mapper) but are **not** in the
endpoint's documented responses — treated as UNVERIFIED-for-this-op assumptions.
There is **no documented** `400`/`404`/`409` for layout; the prior spec's
`400 invalid scene`, `404 scene not found`, and `409 concurrent change` are
unverified and downgraded (see §16). `5xx`/timeout from the unreliable dev host
still apply at the transport layer. FastAPI `detail` is parsed via the shared
mapper (string | `[{msg}]` list | `{code,...}` object — all three forms exist in
`client.ts: normalizeErrorDetail`).

**Moshi DTOs** (`core-network`): `BroadcastLayoutOutDto`, `InputPositionDto`,
`BroadcastLayoutSwitchInDto`; `@Json(name=...)` for snake_case
(`input_ids`, `primary_input_id`, `input_id`, `z_index`); a `MapToLayoutMode`
adapter coerces unrecognized `mode` strings to `UNKNOWN` rather than throwing.

## 6. Data & State Management

- **Room** (`core-data`): a single `broadcast_layout` table (PK `sessionId`)
  holding `mode`, `primaryInputId`, plus `inputIds` (`List<String>`) and
  `positions` (`List<InputPosition>`) stored via Moshi type converters.
  `LayoutDao` with `observeLayout`, `upsertLayout`. (CORRECTED: no
  `broadcast_scenes` table, no `currentSceneId`, no `updatedAt` — those fields do
  not exist in the contract.) The cache is the UI source of truth so the live
  indicator renders instantly on re-entry and survives transient network loss
  (FR-6 stale handling).
- **Optimistic switch:** on `onSelectMode`, `pendingMode` is set and the
  selected/"LIVE" badge moves to the target immediately; on `ApiResult.Success`
  the server-returned layout is upserted and `pendingMode` cleared; on failure
  the cached `mode` is restored and a transient banner shown.
- **Single-live invariant:** `setLayout` replaces the single layout row from the
  server response, so the cached `mode` is always exactly the server's current
  mode. There is no `updatedAt` for tie-breaking; a switch response always wins
  over a stale in-flight poll (the poll loop reads after the switch upsert).
- **Input labeling:** the `needsSource` hint and human-readable input labels are
  derived at the ViewModel layer by cross-referencing `inputIds` /
  `primaryInputId` against the AND-310 inputs cache; presentation-only, never
  persisted.
- **DataStore:** persists per-session UI prefs only (e.g., preferred card
  density); no session token, layout, or input identity is stored there.
- **Lifecycle:** polling/event collection is tied to `WhileSubscribed`; leaving
  the screen stops it. No background work is scheduled.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s for these endpoints, matching the
  unreliable dev host budget.
- **Retry policy:** only the idempotent `GET .../layout` is auto-retried with
  bounded exponential backoff (3 attempts, 500ms→2s, jitter). The
  `POST .../layout` switch (idempotent in effect — "set to this mode") is **not**
  auto-retried by default to avoid surprising re-applies during a fast manual
  sequence; failures surface with a manual "Retry" affordance. (Enabling retry
  for this single POST is safe given its set-semantics — tracked as OQ.)
- **Offline / unreachable:** if `refresh` fails but cache exists, render
  `Content(isStale=true)` with a "Showing last known layout" banner; if no cache,
  render `Error(retryable=true)`. The four mode cards still render either way.
- **Optimistic rollback:** any `setLayout` failure restores the prior `mode` and
  shows the mapped `detail` message (e.g., a `422` "value is not a valid mode").
- **401 handling:** delegated to the OkHttp authenticator (single
  `POST /ui/session/refresh` + retry, verified `client.ts`); a second 401
  surfaces a re-auth prompt routed to the auth flow.
- **Validation errors (`422`):** the only documented error code for these ops;
  the `detail` list is mapped and surfaced; the optimistic switch rolls back.
- **Concurrent edits:** no `409` is documented for layout, so there is no
  conflict-specific handling; instead the ~5s poll naturally converges the cached
  `mode` to whatever the server last accepted (last-writer-wins server-side).
- **No thumbnails:** mode icons are static vectors, so there is no image-load
  failure path to handle.

## 8. Security & Privacy

- All calls require the authenticated host's `Authorization: Bearer` token and a
  valid `X-CSRF-Token`, plus the session cookies; the persistent cookie jar from
  M1 is reused. The `POST` switch is host-only — a runtime `403` is rendered as
  "You don't have permission to change the layout."
- No credentials, cookies, Bearer/CSRF tokens, or `input_id`s are written to logs
  (see §10) or to DataStore. The plaintext dev host is dev-only;
  `cleartextTrafficPermitted` stays scoped to the dev host in the network
  security config inherited from core-network — no plaintext exception for prod.
- The `mode` value is from a fixed enum and is validated client-side before send;
  the server additionally enforces the `^(single|side_by_side|pip|grid)$`
  pattern (`422` on violation), so no free-form user text reaches this endpoint.
- No scene names, slot labels, or thumbnail URLs exist in this feature
  (CORRECTED — those were artifacts of the removed scenes model); there is no
  Coil image loading and thus no image-host trust surface here.
- No media bytes are processed (compositing is server-side). No PII beyond the
  host's own session is handled.

## 9. Accessibility & i18n

- Each mode card is a single focusable element with
  `semantics { role = Button; stateDescription = "Live" / "Not live" }` and a
  `contentDescription` of the localized mode label (e.g., "Picture in picture
  layout"). The live card adds "Currently live layout".
- The "LIVE" badge pairs color with a text label and icon (never color-only) to
  meet contrast/colorblind needs; minimum touch target 48dp; the "needs a source"
  hint is conveyed by icon + text, not color alone.
- All strings live in `res/values/strings.xml` (no hardcoded literals — including
  the four mode labels). RTL-safe layouts (start/end padding, mirrored mode
  icons where directional, e.g. side-by-side).
- Layout changes use `liveRegion = LiveRegionMode.Polite` so screen readers
  announce "<mode label> is now the live layout" without stealing focus.
- Mode icons are decorative; the card's text label is the accessible name, so the
  icons use `contentDescription = null`.

## 10. Telemetry & Logging

- Structured events via the shared analytics interface (`core-data`):
  `layout_viewed{session_id_hash, current_mode}`,
  `layout_changed{from_mode, to_mode, result}`,
  `layout_refresh_failed{http_status, cause}`,
  `layout_no_source{mode, input_count}`. The `mode` values are the fixed enum
  (low cardinality, safe to log raw); session/input ids are hashed, not raw.
- `Timber` debug logs gate behind `BuildConfig.DEBUG`; request/response bodies
  are never logged at info+; the OkHttp logging interceptor is `BASIC` in debug
  and `NONE` in release. CSRF tokens and cookies are redacted by the existing
  interceptor redaction list.
- A `result` dimension (`success | error | timeout`) on `layout_changed` feeds
  the acceptance check that layout changes actually land server-side.

## 11. Testing Strategy

- **Unit (ViewModel, `core-testing` + Turbine):** loading→content transition;
  `onSelectMode` optimistically moves the live badge and keeps it on success;
  `setLayout` failure rolls back `mode` and emits a banner; tapping the
  already-live card is a no-op (no repo call); `needsSource` computed from the
  combined inputs flow (`input_ids` empty); stale flag set when refresh fails with
  warm cache; grid non-interactive while `pendingMode != null`.
- **Repository (MockWebServer):** layout GET parse incl. unknown `mode` →
  `UNKNOWN`, null `primary_input_id`, and empty/absent `input_ids`/`positions`;
  `setLayout` replaces the single layout row from the POST response; GET retried
  on 503 then succeeds; POST not retried on 503 by default; 401 path triggers
  authenticator refresh + retry (one retry); `detail` mapping for
  string/list/object shapes; `422` HTTPValidationError surfaces a mapped message
  and rolls back.
- **DAO (Room in-memory):** layout upsert keyed by `sessionId`,
  `inputIds`/`positions` type-converter round-trip, `observeLayout` emits on
  `mode` change.
- **Compose UI tests:** four mode cards always render; live card shows "LIVE" and
  is non-actionable; selecting a non-live card shows its pending progress and
  disables the grid; error/retry state; "needs a source" hint rendered when no
  inputs; semantics/contentDescription and `stateDescription` assertions.
- **Contract guard:** a JSON fixture test pinned to `/openapi.json` schemas for
  `BroadcastLayoutOut` and `BroadcastLayoutSwitchIn`, failing if field names
  (`mode`, `input_ids`, `primary_input_id`, `positions`, `z_index`), the `mode`
  enum pattern, or the HTTP verb (POST) drift from §5.

## 12. Dependencies & Sequencing

- **Depends on AND-310 (P1):** provides the inputs collection, the inputs Room
  cache + `InputsRepository` reused to label/validate `input_ids` /
  `primary_input_id`, and the `feature-broadcast` host control surface this panel
  sits alongside. AND-311 must not begin UI integration until AND-310's input
  identifiers (`input_id`) and the session id contract are stable, since the
  layout response references them.
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

- **R1 — scenes vs layout endpoints (RESOLVED):** verified against
  `openapi.index.txt` (lines 193–194) and `LayoutSwitcher.tsx` — there is **no**
  `/scenes` catalog. The only resource is session-scoped
  `GET|POST /broadcast/sessions/{session_id}/layout`, and a "layout" is a `mode`
  enum + input arrangement, not a named scene. The spec has been rewritten to
  this model; the contract guard still pins it against drift.
- **R2 — set verb/body (RESOLVED):** verified **POST** with body
  `BroadcastLayoutSwitchIn { mode, input_ids?, primary_input_id? }` (required key
  is `mode`, not `scene_id`). Isolated in the API layer + contract test.
- **R3 — arrangement authoring scope:** this ticket switches `mode` only and
  shows `positions`/`input_ids` read-only. If product wants free-form per-input
  `positions` editing or primary-input reassignment from this screen, scope grows
  (a richer editor over `BroadcastLayoutSwitchIn.input_ids`/`primary_input_id`)
  and should be a follow-up ticket.
- **R4 — real-time channel (still UNVERIFIED):** no broadcast event channel is
  visible in the reference; the web client uses **5s polling**
  (`refetchInterval: 5000`). The Android port matches ~5s polling; "within ~3s"
  is downgraded to a non-binding target.
- **R5 — concurrency:** multiple host devices may switch mode; there is **no**
  `409` in the contract, so resolution is last-writer-wins server-side and the
  ~5s poll converges all clients. No locking exists.
- **OQ:** Does the server reject a mode switch when the session has zero inputs
  (`422`) or accept it with an empty arrangement? Should the `POST` auto-retry on
  transient 5xx given its set-semantics? Pending product/backend input.

## 14. Acceptance Criteria

- AC-1. The layout panel lists the four fixed modes (Full / Side / PiP / Grid)
  for session `{session_id}`, each with its label and icon, and a "LIVE" badge on
  the card whose `mode` equals the server's current `mode`.
- AC-2. **Layout changes apply:** selecting a non-live mode issues
  `POST /broadcast/sessions/{session_id}/layout { mode }`, makes it the live
  layout, and the change is reflected within ~5s (poll). *(source acceptance)*
- AC-3. Exactly one mode is live at any time; the live mode's card is shown
  selected and tapping it issues no request.
- AC-4. The selection is optimistic and rolls back to the prior live mode on
  failure with a user-visible, `detail`-mapped message (e.g., `422`).
- AC-5. When the session has no resolvable program inputs (`input_ids` empty), a
  non-blocking "needs a source" hint (resolved against the AND-310 inputs cache)
  is shown; modes remain selectable.
- AC-6. An unrecognized server `mode` value maps to `UNKNOWN` without crashing;
  the four known mode cards still render and remain usable.
- AC-7. With the dev host unreachable, the panel shows the cached layout flagged
  stale (warm cache) or a retryable error (cold cache); the GET retries, the
  layout `POST` does not auto-retry.
- AC-8. All controls are keyboard/TalkBack accessible with correct state
  semantics; all strings (including mode labels) are localized resources; mode
  icons are decorative.

## 15. Definition of Done

- All AC-1..AC-8 verified by automated tests where feasible and one manual host
  walkthrough on a device against the dev backend (switch a live broadcast
  between at least two modes and observe the change apply).
- Code merged to `android-port` under `feature-broadcast`, package
  `com.testlogon.android.feature.broadcast.layout`, respecting module layering
  (no `core-*` → `feature-*` deps).
- Unit + repository + DAO + Compose UI tests pass in CI; contract guard test
  green against the current `/openapi.json`.
- No hardcoded strings; lint/detekt/ktlint clean; no cookies/CSRF/ids in logs.
- KDoc on `LayoutRepository`, `LayoutViewModel`, and public DTOs.
- §13 open questions (R3 arrangement-authoring scope, R4 event channel, and the
  `POST` auto-retry OQ) resolved or explicitly deferred with owners noted in the
  PR description. (R1 endpoint shape and R2 verb/body are resolved by this
  review — see §16.)

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Layout GET endpoint is `GET /broadcast/sessions/{session_id}/layout` →
   `BroadcastLayoutOut`.** VERDICT: Corrected (original was
   `GET /ui/broadcasts/{id}/layout`). SOURCE: `openapi.index.txt` line 193
   (`GET /broadcast/sessions/{session_id}/layout | resp=200:BroadcastLayoutOut`);
   `reference/src/api/endpoints/broadcast-inputs.ts: getLayout`.
2. **Layout switch is `POST` (not `PUT`).** VERDICT: Corrected. SOURCE:
   `openapi.index.txt` line 194
   (`POST /broadcast/sessions/{session_id}/layout | req=BroadcastLayoutSwitchIn`);
   `broadcast-inputs.ts: switchLayout` (`api.post`).
3. **No `/scenes` catalog endpoint exists.** VERDICT: Corrected (original FR-1
   fetched `GET /ui/broadcasts/{id}/scenes`). SOURCE: absence in
   `openapi.index.txt` (grep for `scene` returns only the two layout rows);
   `LayoutSwitcher.tsx` builds modes from a client-side `LAYOUT_MODES` constant.
4. **A layout is a `mode` enum, not a named scene with slots/thumbnails.**
   VERDICT: Corrected. SOURCE: `components.schemas.BroadcastLayoutOut`
   (openapi.pretty.json lines 10447–10484) and `types.ts: BroadcastLayout`
   (lines 4336–4348): fields are `mode`, `input_ids`, `positions`,
   `primary_input_id` — no `id`, `name`, `kind`, `slots`, `thumbnail_url`.
5. **Mode enum is `single | side_by_side | pip | grid`.** VERDICT: Corrected
   (original was `single|pip|split|grid|custom`; `split`/`custom` do not exist and
   `side_by_side` was missing). SOURCE: `BroadcastLayoutSwitchIn.mode.pattern`
   `^(single|side_by_side|pip|grid)$` (openapi.pretty.json line 10503);
   `types.ts: BroadcastLayout.mode` union; `LayoutSwitcher.tsx: LAYOUT_MODES`.
6. **Switch request body is `BroadcastLayoutSwitchIn { mode (required),
   input_ids?, primary_input_id? }` — key is `mode`, not `scene_id`.** VERDICT:
   Corrected. SOURCE: `components.schemas.BroadcastLayoutSwitchIn`
   (openapi.pretty.json lines 10486–10523, `required: [mode]`);
   `broadcast-inputs.ts: switchLayout` body type.
7. **Response carries `input_ids`, `positions[]{input_id,x,y,width,height,
   z_index}`, `primary_input_id`.** VERDICT: Verified. SOURCE:
   `types.ts: BroadcastLayout.positions` (lines 4338–4345); `BroadcastLayoutOut`
   properties (openapi.pretty.json lines 10448–10478, `positions` items are
   open objects — web type pins the rect shape).
8. **Live poll interval is ~5s (not ~3s).** VERDICT: Corrected. SOURCE:
   `LayoutSwitcher.tsx` line 27 (`refetchInterval: 5000`).
9. **Auth = `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) +
   cookies; optional `X-IMPERSONATION-TOKEN`.** VERDICT: Corrected (original
   omitted the Bearer token, which is the primary credential). SOURCE:
   `reference/src/api/client.ts` lines 157–171 (sets `Authorization: Bearer`,
   `X-CSRF-Token` from `getCookie("ui_csrf")`, `X-IMPERSONATION-TOKEN`,
   `credentials: include`).
10. **On 401, client calls `POST /ui/session/refresh` once then retries.**
    VERDICT: Verified. SOURCE: `client.ts: refreshSession` (lines 121–130) and
    the 401 branch (lines 194–237).
11. **FastAPI `detail` mapper handles string | `[{msg}]` | `{code,...}`.**
    VERDICT: Verified. SOURCE: `client.ts: normalizeErrorDetail` (lines 66–102)
    plus `mapAuthorizationError` (object/`code` form, lines 34–64).
12. **Only documented non-2xx for the layout ops is `422 HTTPValidationError`.**
    VERDICT: Verified (and the original's `400`/`404`/`409` are unverified).
    SOURCE: `openapi.index.txt` lines 193–194 (`resp=...;422:HTTPValidationError`
    only); response objects in openapi.pretty.json lines 101437–101557.
13. **Layout endpoints also expose `user_sub` query param and `X-SESSION-ID` /
    `X-IMPERSONATION-TOKEN` headers.** VERDICT: Verified. SOURCE:
    `openapi.index.txt` lines 193–194 `params=session_id,user_sub,X-SESSION-ID,
    X-IMPERSONATION-TOKEN`; openapi.pretty.json lines 101468–101524.
14. **Switch never starts/stops the broadcast (FR-7).** VERDICT: Verified
    (distinct endpoints). SOURCE: `start`/`stop` are
    `POST /broadcast/sessions/{session_id}/start|stop` (openapi.index.txt lines
    244–245), separate from the layout route.
15. **Web reference for layout lives in `broadcast-inputs.ts` + the
    `LayoutSwitcher.tsx` page (not `broadcasts.ts`).** VERDICT: Corrected.
    SOURCE: `reference/src/api/endpoints/broadcast-inputs.ts`;
    `reference/src/pages/broadcast/LayoutSwitcher.tsx`.
16. **Compose + Material 3, `LazyVerticalGrid`, semantics/`stateDescription`,
    `LiveRegionMode.Polite`.** VERDICT: Unverified-assumption (Android framework
    choices, not derivable from backend/web sources). SOURCE: framework ref —
    developer.android.com/jetpack/compose (Material3, accessibility semantics).

### Corrections made

- Endpoint base path corrected from `/ui/broadcasts/{id}/...` to
  `/broadcast/sessions/{session_id}/...` throughout (§1, §2, §3, §5, §14).
- Switch verb corrected `PUT` → `POST` (§3, §5, §7, §8, §11, §14).
- Removed the entire fictional "scenes" model (named scenes, `scene_id`,
  `current_scene_id`, per-scene `slots`, `thumbnail_url`, `broadcast_id`,
  `updated_at`); replaced with the verified `mode`+arrangement model (§1, §3, §4,
  §5, §6).
- Mode enum corrected to `single|side_by_side|pip|grid` (dropped `split`,
  `custom`; added `side_by_side`) (§3, §4, §5, §14).
- Request body key corrected `scene_id` → `mode` (+ optional `input_ids`,
  `primary_input_id`) (§3, §5).
- Domain model rewritten: `Scene`/`SceneSlot`/`SceneKind` → `BroadcastLayout`/
  `InputPosition`/`LayoutMode`; ViewModel `onSelectScene`→`onSelectMode`,
  `SceneCard`→`ModeCard`, `currentSceneId`→`currentMode`, removed `Empty` state
  (§4).
- Room schema simplified to a single `broadcast_layout` row (no
  `broadcast_scenes` table, no `currentSceneId`/`updatedAt`) (§4, §6).
- Auth model corrected to add the primary `Authorization: Bearer` credential
  (§2, §5, §8).
- Poll interval corrected ~3s → ~5s to match the web client (§3, §4, §13, §14).
- Error set corrected to documented `422` only; downgraded the unverified
  `400`/`404`/`409` handling (§5, §7, §13).
- Removed Coil/thumbnail handling (no thumbnail URLs in the contract) (§4, §7,
  §8, §9).
- Telemetry dimensions retargeted from scenes/kinds/slots to modes (§10).
- Path param renamed `broadcastId` → `sessionId` (nav route, ViewModel) (§4).
- Frontend reference pointer corrected `broadcasts.ts` → `broadcast-inputs.ts`
  (§2).
- R1/R2 marked RESOLVED with verified facts; R4/R5 reframed around 5s poll and
  the absence of `409` (§13).

### Open assumptions

- **Runtime `401`/`403` on the layout ops** — handled by the shared
  authenticator and `detail` mapper, but NOT enumerated in the endpoint's OpenAPI
  responses (only `422` is). Carried as a transport-layer assumption; the
  contract guard cannot pin them.
- **Broadcast event channel for sub-poll latency (R4)** — no such channel is
  visible in the reference; 5s polling is the verified mechanism.
- **`positions[]` exact field shape** — the OpenAPI types `positions` items as
  open objects (`additionalProperties: true`); the
  `{input_id,x,y,width,height,z_index}` shape is taken from the web `types.ts`
  and treated leniently (extra/missing keys tolerated).
- **Server behavior on a switch when `input_ids` is empty** — whether rejected
  (`422`) or accepted with an empty arrangement is unconfirmed (§13 OQ).
- **All Android framework/library choices** (Compose, Hilt, Room, Moshi,
  Retrofit/OkHttp, Coroutines) — design decisions, not contract facts;
  framework refs only.

## 17. Test Plan

IDs `TC-AND-311-NN`. "Traces" links to §14 acceptance criteria. Targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
**Samsung Galaxy A15 5G** (SM-A156U, API 34, arm64, serial R5CX821TA9R). These
endpoints have no camera/biometric/WebRTC/FCM dependency, so most cases run
locally or on the emulator; physical-device cases are limited to real-network
behavior against the flaky dev host and the arm64/API-34 smoke check.

- **TC-AND-311-01 — Happy path: load + render current mode.**
  Type: contract/MockWebServer. Target: JVM/Robolectric.
  Preconditions: MockWebServer returns `BroadcastLayoutOut { "mode":"pip",
  "input_ids":["in_1","in_2"], "primary_input_id":"in_1", "positions":[...] }`
  for `GET /broadcast/sessions/{id}/layout`.
  Steps: open the layout panel; let the repo `refresh`.
  Expected: four mode cards render; the **PiP** card shows "LIVE"; request was a
  GET to the corrected path with `Authorization: Bearer` + `X-CSRF-Token` headers.
  Traces: AC-1.

- **TC-AND-311-02 — Happy path: switch mode applies (POST).**
  Type: contract/MockWebServer. Target: JVM/Robolectric.
  Preconditions: current `mode=single`; POST handler returns
  `BroadcastLayoutOut { "mode":"grid", ... }`.
  Steps: tap the **Grid** card.
  Expected: a single `POST /broadcast/sessions/{id}/layout` is sent with body
  `{ "mode":"grid" }`; the live badge moves to Grid; no `PUT` and no `scene_id`
  key are ever emitted. Traces: AC-2.

- **TC-AND-311-03 — Optimistic switch + propagation within ~5s.**
  Type: integration. Target: emulator `test35`.
  Preconditions: current `mode=single`; POST succeeds; subsequent GET poll (5s)
  returns `mode=grid`.
  Steps: tap Grid; observe immediate optimistic badge; advance/await ~5s poll.
  Expected: badge moves to Grid instantly (optimistic) and remains after the poll
  reconciles; poll interval is ~5s. Traces: AC-2.

- **TC-AND-311-04 — Live card tap is a no-op.**
  Type: unit (ViewModel + Turbine). Target: JVM.
  Preconditions: current `mode=pip`.
  Steps: invoke `onSelectMode(PIP)`.
  Expected: no repository `setLayout` call; state unchanged. Traces: AC-3.

- **TC-AND-311-05 — Single-live invariant after switch.**
  Type: unit (ViewModel + Turbine). Target: JVM.
  Preconditions: switch from `side_by_side` to `single` succeeds.
  Steps: select Single.
  Expected: exactly one card (`single`) is `isLive=true`; all others false.
  Traces: AC-3.

- **TC-AND-311-06 — Optimistic rollback on `422`.**
  Type: contract/MockWebServer. Target: JVM/Robolectric.
  Preconditions: current `mode=single`; POST returns `422`
  `{"detail":[{"loc":["body","mode"],"msg":"string does not match regex",
  "type":"value_error.str.regex"}]}`.
  Steps: tap PiP.
  Expected: badge briefly shows PiP then rolls back to Single; banner shows the
  mapped `msg`; cached `mode` stays `single`. Traces: AC-4.

- **TC-AND-311-07 — `detail` mapping across all three shapes.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: three POST responses with `detail` as (a) string,
  (b) `[{msg}]` list, (c) `{code,...}` object.
  Steps: trigger a failed switch for each.
  Expected: each maps to a non-empty user message via the shared mapper (matches
  `client.ts: normalizeErrorDetail`). Traces: AC-4.

- **TC-AND-311-08 — "Needs a source" hint when no inputs.**
  Type: Compose-UI. Target: emulator `test35`.
  Preconditions: layout returns `input_ids: []`; AND-310 inputs cache empty.
  Steps: render the panel.
  Expected: a non-blocking "needs a source" hint (icon + text, not color-only)
  shows; all four mode cards remain selectable. Traces: AC-5.

- **TC-AND-311-09 — Unknown server `mode` → UNKNOWN, no crash.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: GET returns `{"mode":"cinema", ...}` (not in enum).
  Steps: refresh.
  Expected: `MapToLayoutMode` coerces to `UNKNOWN`; no card shows "LIVE"; the four
  known cards still render and remain usable; no exception. Traces: AC-6.

- **TC-AND-311-10 — Offline warm cache (stale) and cold cache (error).**
  Type: integration. Target: **physical device (SM-A156U)** — exercise the real
  flaky dev-host/offline path on cellular/Wi-Fi toggling.
  Preconditions: (warm) a prior layout is cached, then network is dropped;
  (cold) cache cleared, network down.
  Steps: enter the panel offline in each state; for GET failures observe retry.
  Expected: warm → `Content(isStale=true)` with "Showing last known layout"
  banner and the four cards still rendered; cold → `Error(retryable=true)`; the
  GET auto-retries (bounded backoff) and the layout POST does not auto-retry.
  Traces: AC-7. (MUST be physical device to reproduce real radio/DNS timeouts
  against the unreliable host.)

- **TC-AND-311-11 — 401 → refresh + retry once.**
  Type: contract/MockWebServer. Target: JVM/Robolectric.
  Preconditions: GET returns `401` once, then the authenticator's
  `POST /ui/session/refresh` returns 200, then GET retry returns 200; a second
  persistent 401 triggers re-auth.
  Steps: refresh through the authenticator.
  Expected: exactly one refresh + one retry on the first 401; second 401 routes to
  re-auth; tokens/cookies are not logged. Traces: AC-2, AC-7 (resilience).

- **TC-AND-311-12 — Security: headers present, secrets never logged.**
  Type: contract/MockWebServer + unit. Target: JVM.
  Preconditions: capture outbound request + Timber/OkHttp log output in debug.
  Steps: perform a GET and a switch POST.
  Expected: requests carry `Authorization: Bearer`, `X-CSRF-Token`; the logging
  interceptor is BASIC (debug)/NONE (release) and the redaction list hides the
  Bearer token, cookies, and CSRF; no `input_id` printed at info+. Traces: AC-8
  (security aspect), §8.

- **TC-AND-311-13 — Accessibility semantics.**
  Type: Compose-UI (TalkBack/semantics). Target: emulator `test35`.
  Preconditions: current `mode=grid`.
  Steps: assert node semantics for each card.
  Expected: each card has `role=Button`, localized `contentDescription`,
  `stateDescription` "Live"/"Not live"; the Grid card adds "Currently live
  layout"; touch targets ≥48dp; mode labels resolve from `strings.xml` (no
  hardcoded literals); a live-region polite announcement fires on switch.
  Traces: AC-8.

- **TC-AND-311-14 — ABI/API smoke on real hardware.**
  Type: instrumented/e2e. Target: **physical device (SM-A156U, arm64, API 34)**.
  Preconditions: signed debug build installed via adb on serial R5CX821TA9R.
  Steps: load the panel, switch single→pip→grid against the dev backend.
  Expected: feature works on arm64-v8a / API 34 identically to the API-35
  emulator (no x86-only assumptions, no API-35 API usage that breaks on 34);
  layout changes apply end-to-end. Traces: AC-2 (real-device confirmation), DoD
  manual walkthrough. (MUST be physical device to cover arm64-vs-x86 and
  API-34-vs-35.)

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01 |
| AC-2 | TC-02, TC-03, TC-11, TC-14 |
| AC-3 | TC-04, TC-05 |
| AC-4 | TC-06, TC-07 |
| AC-5 | TC-08 |
| AC-6 | TC-09 |
| AC-7 | TC-10, TC-11 |
| AC-8 | TC-12, TC-13 |
