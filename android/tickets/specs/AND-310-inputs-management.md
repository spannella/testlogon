---
id: AND-310
title: Inputs management
milestone: M7
epic: E41
priority: P1
size: M
status: draft
depends_on: [AND-308]
blocks: []
---

# AND-310 — Inputs management

## 1. Overview & Goal

A live broadcast in TestLogon can be fed by more than one **input**: the host's
camera/mic published via WebRTC (AND-308), an HLS restream, an RTMP push, or an
auxiliary screen-share source. This ticket delivers the host-facing surface that
**lists the inputs attached to the active broadcast, switches which input is the
live program source, and activates/deactivates individual sources** without
ending the broadcast.

The goal: a host viewing the broadcast control screen can see every input bound
to the broadcast, observe each input's connection/health state, toggle an input
active or inactive, and promote any active input to the live program — with the
change taking effect on the server and reflected to viewers in near real time
("inputs switch live"). The feature is read-then-mutate against the FastAPI
`/ui/broadcasts/{id}/inputs` resource and renders inside the existing
`feature-broadcast` module. WebRTC publishing itself, offer/answer negotiation,
and the camera/mic capture pipeline are owned by AND-308 and consumed here as a
producer of one input row; this ticket does not implement transport.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6 (cache), DataStore (prefs). minSdk 24, compile/target 35,
  JDK 17, AGP 8.7.3, Gradle 8.9.
- **Namespace / applicationId base:** `com.testlogon.android`. This feature lives
  at `com.testlogon.android.feature.broadcast.inputs`.
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
- **Upstream deps:** **AND-308 (WebRTC ingest, P0)** establishes the broadcast,
  the `inputs` collection, and one WebRTC input producer. AND-310 depends on
  AND-308 supplying the broadcast id, an authenticated host session, and at least
  one input to manage. Core session/CSRF/auth plumbing is inherited from M1.

## 3. Functional Requirements

FR-1. **List inputs.** On entering the inputs panel for broadcast `{id}`, fetch
`GET /ui/broadcasts/{id}/inputs` and render one row per input showing: label,
`kind` (`webrtc | hls | rtmp | screen`), `status`
(`idle | connecting | live | error`), `active` flag, and whether it is the
current **program** input.

FR-2. **Activate / deactivate.** Each input exposes a toggle. Activating calls
`POST /ui/broadcasts/{id}/inputs/{inputId}/activate`; deactivating calls
`.../deactivate`. The toggle is optimistic with rollback on failure.

FR-3. **Switch program (live switch).** A "Make live" action on any **active**
input promotes it to the program source via
`POST /ui/broadcasts/{id}/program {input_id}`. Exactly one input is the program
at a time; promoting input B demotes input A locally and on the server. This is
the acceptance behavior — "inputs switch live."

FR-4. **Guards.** "Make live" is disabled for inputs whose `status != live` or
`active == false`. The currently-live program input cannot be deactivated; the
toggle for it is disabled with an explanatory affordance.

FR-5. **Live refresh.** The list reflects server-driven status changes within
~3s without manual reload, via poll (default) or WebSocket if AND-308 exposes the
broadcast event channel. Stale data is visibly flagged when the backend is
unreachable.

FR-6. **Multiple sources.** The panel correctly handles 0..N inputs of mixed
kinds, including duplicate kinds (e.g., two `webrtc` inputs), and an empty state.

FR-7. **No teardown.** All actions mutate input state on a running broadcast; none
end the broadcast.

## 4. Technical Design

New package `com.testlogon.android.feature.broadcast.inputs` inside
`feature-broadcast`.

**Domain model** (`core-model`):

```kotlin
enum class InputKind { WEBRTC, HLS, RTMP, SCREEN, UNKNOWN }
enum class InputStatus { IDLE, CONNECTING, LIVE, ERROR, UNKNOWN }

data class BroadcastInput(
    val id: String,
    val broadcastId: String,
    val label: String,
    val kind: InputKind,
    val status: InputStatus,
    val active: Boolean,
    val isProgram: Boolean,
    val updatedAt: Instant,
)
```

**Repository** (`core-data`, interface in `core-data`, impl Hilt-bound):

```kotlin
interface InputsRepository {
    fun observeInputs(broadcastId: String): Flow<List<BroadcastInput>> // cache-backed
    suspend fun refresh(broadcastId: String): ApiResult<List<BroadcastInput>>
    suspend fun setActive(broadcastId: String, inputId: String, active: Boolean): ApiResult<BroadcastInput>
    suspend fun setProgram(broadcastId: String, inputId: String): ApiResult<List<BroadcastInput>>
}
```

`observeInputs` emits from the Room cache (`broadcast_inputs` table keyed by
`(broadcastId, id)`); `refresh` performs the GET and upserts. Mutations write
through: on success the server's returned row(s) replace cached rows; on failure
the cache is restored from the pre-mutation snapshot.

**ViewModel:**

```kotlin
@HiltViewModel
class InputsViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repo: InputsRepository,
) : ViewModel() {
    private val broadcastId: String = savedState["broadcastId"]!!
    val uiState: StateFlow<InputsUiState>
    fun onToggleActive(inputId: String, target: Boolean)
    fun onMakeLive(inputId: String)
    fun onRetry()
}

sealed interface InputsUiState {
    data object Loading : InputsUiState
    data class Content(
        val inputs: List<InputRow>,
        val isStale: Boolean = false,
        val banner: String? = null,
        val pendingIds: Set<String> = emptySet(),
    ) : InputsUiState
    data class Empty(val isStale: Boolean = false) : InputsUiState
    data class Error(val message: String, val retryable: Boolean) : InputsUiState
}

data class InputRow(
    val input: BroadcastInput,
    val canMakeLive: Boolean,   // status==LIVE && active && !isProgram
    val canDeactivate: Boolean, // !isProgram
)
```

`uiState` is built by combining `observeInputs` with a `pendingIds` set
(`MutableStateFlow`) tracking in-flight optimistic mutations, surfaced via
`stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`. A
polling loop (`while(isActive){ repo.refresh(); delay(3_000) }`) runs only while
subscribed; if AND-308's broadcast event channel is available, the loop is
replaced by collecting that channel and falling back to poll on disconnect.

**UI** (`InputsScreen`, `InputRowItem` composables): a Material 3 list. Each row =
leading kind icon, label + status chip, a trailing `Switch` (active), and a
"Make live" `FilledTonalButton` gated by `canMakeLive`. The program input carries
a "LIVE" badge. Pending rows show an inline progress indicator and are
non-interactive. Empty state and full-screen error/retry use shared `core-ui`
components. Navigation route `broadcast/{broadcastId}/inputs` added to the
`feature-broadcast` nav graph.

## 5. API Contract

All requests carry session cookies and `X-CSRF-Token` (from `ui_csrf`).
Confirm exact shapes against `/openapi.json`; map deltas in code review.

**List** — `GET /ui/broadcasts/{id}/inputs` → `200`:

```json
{
  "inputs": [
    {
      "id": "in_01H...",
      "broadcast_id": "bc_01H...",
      "label": "Host camera",
      "kind": "webrtc",
      "status": "live",
      "active": true,
      "is_program": true,
      "updated_at": "2026-06-05T12:00:00Z"
    }
  ]
}
```

**Activate** — `POST /ui/broadcasts/{id}/inputs/{inputId}/activate` (empty body)
→ `200` returns the updated input object (same shape as a list element).
**Deactivate** — `POST /ui/broadcasts/{id}/inputs/{inputId}/deactivate` → `200`
updated input.

**Set program** — `POST /ui/broadcasts/{id}/program`:

```json
{ "input_id": "in_01H..." }
```

→ `200` returns the full refreshed `{"inputs":[...]}` (so the demoted prior
program is reflected atomically).

**Errors:** `400` invalid transition (e.g., promoting a non-live input), `401`
session expired (handled by authenticator refresh+retry), `403` non-host /
CSRF mismatch, `404` broadcast or input not found, `409` conflicting concurrent
mutation, `5xx`/timeout from the unreliable dev host. FastAPI `detail` is parsed
via the shared mapper (string | `[{msg}]` | `{code,msg}`).

**Moshi DTOs** (`core-network`): `InputDto`, `InputsResponseDto`,
`SetProgramRequestDto`; `@Json(name=...)` for snake_case; a `MapToInputStatus`
adapter coerces unknown enum strings to `UNKNOWN` rather than throwing.

## 6. Data & State Management

- **Room** (`core-data`): table `broadcast_inputs` (PK `(broadcastId, id)`),
  columns mirroring `BroadcastInput`; `InputsDao` with `observeByBroadcast`,
  `upsertAll`, `replaceForBroadcast`, `deleteForBroadcast`. The cache is the UI
  source of truth so the panel renders instantly on re-entry and survives
  transient network loss (FR-5 stale handling).
- **Optimistic mutations:** before the network call, the targeted row is updated
  in-memory and its id added to `pendingIds`; on `ApiResult.Success` the
  server-returned row(s) are upserted and the id cleared; on failure the cached
  row is restored and a transient banner is shown.
- **Single-program invariant:** `setProgram` replaces all rows for the broadcast
  from the server response, guaranteeing exactly one `isProgram == true`. If a
  poll response and a mutation response race, last-write-by-`updatedAt` wins on
  upsert.
- **DataStore:** persists per-broadcast UI prefs only (e.g., last sort order); no
  session or input identity is stored there.
- **Lifecycle:** polling/event collection is tied to `WhileSubscribed`; leaving
  the screen stops it. No background work is scheduled.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s for these endpoints, matching the
  unreliable dev host budget.
- **Retry policy:** only the idempotent `GET .../inputs` is auto-retried with
  bounded exponential backoff (e.g., 3 attempts, 500ms→2s, jitter). The
  `activate`/`deactivate`/`program` POSTs are **not** auto-retried; failures
  surface to the user with a manual "Retry" affordance to avoid duplicate state
  flips.
- **Offline / unreachable:** if `refresh` fails but cache exists, render
  `Content(isStale=true)` with a "Showing last known state" banner; if no cache,
  render `Error(retryable=true)`.
- **Optimistic rollback:** any mutation failure restores the prior cached row and
  shows the mapped `detail` message (e.g., "Input is not live yet").
- **401 handling:** delegated to the OkHttp authenticator (single
  `session/refresh` + retry); a second 401 surfaces a re-auth prompt routed to
  the auth flow.
- **Concurrent edits:** a `409` triggers a forced `refresh` and a banner
  ("Inputs changed elsewhere — refreshed").

## 8. Security & Privacy

- All calls require the authenticated host cookie session and a valid
  `X-CSRF-Token`; the persistent cookie jar from M1 is reused. The mutation
  endpoints are host-only — a `403` is rendered as "You don't have permission to
  manage inputs."
- No credentials, cookies, or `input_id`s are written to logs (see §10) or to
  DataStore. The plaintext dev host is dev-only; production assumes HTTPS and
  there is no plaintext exception for prod (`cleartextTrafficPermitted` scoped to
  the dev host in the network security config inherited from core-network).
- Input labels may contain user-entered text; they are rendered as text only
  (no HTML/markdown) to avoid injection in the UI layer.
- No PII beyond the host's own session is handled; no media bytes touch this
  feature (media transport is AND-308).

## 9. Accessibility & i18n

- Every interactive control has a `contentDescription` /
  `semantics { stateDescription }`: the active `Switch` announces
  "Input <label> active/inactive"; "Make live" announces target and disabled
  reason via `disabled` semantics. The program badge exposes
  `stateDescription = "Live program source"`.
- Status chips pair color with a text label and icon (never color-only) to meet
  contrast/colorblind needs; minimum touch target 48dp.
- All strings live in `res/values/strings.xml` (no hardcoded literals);
  plurals/number formatting via Android resources. RTL-safe layouts (start/end
  padding, mirrored icons). Timestamps formatted with the device locale.
- Live status changes use `liveRegion = LiveRegionMode.Polite` so screen readers
  announce a source going live without stealing focus.

## 10. Telemetry & Logging

- Structured events via the shared analytics interface (`core-data`):
  `inputs_viewed{broadcast_id_hash, count}`,
  `input_active_toggled{kind, target, result}`,
  `input_made_live{kind, from_kind, result}`,
  `inputs_refresh_failed{http_status, cause}`. Broadcast/input ids are hashed,
  not raw, in analytics.
- `Timber` debug logs gate behind `BuildConfig.DEBUG`; request/response bodies
  are never logged at info+; the OkHttp logging interceptor is `BASIC` in debug
  and `NONE` in release. CSRF tokens and cookies are redacted by the existing
  interceptor redaction list.
- A `result` dimension (`success | error | timeout`) on mutation events feeds the
  acceptance check that switches actually land server-side.

## 11. Testing Strategy

- **Unit (ViewModel, `core-testing` + Turbine):** loading→content transition;
  optimistic activate success keeps new state; activate failure rolls back and
  emits banner; `onMakeLive` updates `isProgram` and demotes prior; `canMakeLive`
  guard false when `status != LIVE`; program input has `canDeactivate == false`;
  stale flag set when refresh fails with warm cache.
- **Repository (MockWebServer):** GET parse incl. unknown `kind`/`status` →
  `UNKNOWN`; activate/deactivate return-row upsert; `setProgram` whole-list
  replacement enforces single program; GET retried on 503 then succeeds; POST
  **not** retried on 503; 401 path triggers authenticator refresh (one retry);
  `detail` mapping for string/list/object shapes.
- **DAO (Room in-memory):** upsert keyed by `(broadcastId,id)`,
  `replaceForBroadcast` atomicity, observe emits on change.
- **Compose UI tests:** toggle disabled for program input; "Make live" disabled
  with correct semantics for non-live input; pending row shows progress and is
  non-interactive; empty and error/retry states; semantics/contentDescription
  assertions.
- **Contract guard:** a JSON fixture test pinned to `/openapi.json` example
  payloads, failing if field names drift from §5.

## 12. Dependencies & Sequencing

- **Depends on AND-308 (P0):** provides the active broadcast, the `inputs`
  collection, the WebRTC input producer, and (optionally) the broadcast event
  channel for live refresh. AND-310 must not begin UI integration until
  AND-308's `GET .../inputs` shape is stable.
- Inherits M1 session/CSRF/cookie-jar, `ApiResult`, and the `detail` error mapper
  from `core-network`.
- **Sequencing:** (1) DTOs + `InputsRepository` + DAO; (2) ViewModel + state +
  optimistic/rollback; (3) Compose UI + nav route; (4) live-refresh (poll, then
  swap to event channel if AND-308 ships it). No tickets currently declare a hard
  block on AND-310.

## 13. Risks & Open Questions

- **R1 — live-switch transport:** does promoting a program input require any
  client WebRTC renegotiation, or is it purely server-side mixing? Assumed
  server-side; confirm with AND-308 owner. If client work is needed, scope grows
  (size could move to L).
- **R2 — real-time channel:** existence/shape of a broadcast event WebSocket is
  unconfirmed; fallback is 3s polling, acceptable for "switch live within ~3s".
- **R3 — endpoint shapes:** `activate/deactivate` vs a single `PATCH input`, and
  `/program` body key (`input_id` vs `program_input_id`), are assumptions pending
  `/openapi.json`; the contract guard test (§11) will catch drift.
- **R4 — concurrency:** multiple host devices editing inputs; mitigated by
  `409` → forced refresh, but no locking exists.
- **OQ:** Is there a max active-inputs limit per broadcast? Is deactivating the
  sole live input allowed (and what does the viewer see)? Pending product input.

## 14. Acceptance Criteria

- AC-1. The inputs panel lists every input of broadcast `{id}` with label, kind,
  status, active state, and program badge.
- AC-2. Activating/deactivating an input calls the correct
  `.../activate|deactivate` endpoint, updates optimistically, and rolls back on
  failure with a user-visible message.
- AC-3. **Inputs switch live:** promoting an active, live input via
  `POST .../program` makes it the program source, demotes the prior one, and the
  change is reflected within ~3s (poll or event channel). *(source acceptance)*
- AC-4. Exactly one input is the program at any time; the live program input
  cannot be deactivated and its "Make live" is hidden/disabled.
- AC-5. "Make live" is disabled for inputs that are inactive or `status != live`.
- AC-6. Multiple inputs of mixed and duplicate kinds, and the empty/0-input case,
  render correctly.
- AC-7. With the dev host unreachable, the panel shows cached inputs flagged
  stale (warm cache) or a retryable error (cold cache); GETs retry, mutation
  POSTs do not.
- AC-8. All controls are keyboard/TalkBack accessible with correct state
  semantics; all strings are localized resources.

## 15. Definition of Done

- All AC-1..AC-8 verified by automated tests where feasible and one manual host
  walkthrough on a device against the dev backend.
- Code merged to `android-port` under `feature-broadcast`, package
  `com.testlogon.android.feature.broadcast.inputs`, respecting module layering
  (no `core-*` → `feature-*` deps).
- Unit + repository + DAO + Compose UI tests pass in CI; contract guard test
  green against the current `/openapi.json`.
- No hardcoded strings; lint/detekt/ktlint clean; no cookies/CSRF/ids in logs.
- KDoc on `InputsRepository`, `InputsViewModel`, and public DTOs.
- §13 open questions (R1, max-inputs, sole-live deactivation) resolved or
  explicitly deferred with owners noted in the PR description.
