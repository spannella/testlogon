---
id: AND-310
title: Inputs management
milestone: M7
epic: E41
priority: P1
size: M
depends_on: [AND-308]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
`/broadcast/sessions/{session_id}/inputs` resource (CORRECTED from the original
`/ui/broadcasts/{id}/inputs`, which does not exist in the backend; verified in
§16) and renders inside the existing `feature-broadcast` module. WebRTC publishing itself, offer/answer negotiation,
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
  (plaintext, unreliable). Auth (verified against `src/api/client.ts`): cookie
  session sent with every request (`credentials: include`) **plus** an
  `Authorization: Bearer <accessToken>` header from the auth store, **plus**
  `ui_csrf` cookie echoed as `X-CSRF-Token`; an optional `X-IMPERSONATION-TOKEN`
  is added when impersonating. (The original spec omitted the Bearer token and
  impersonation header — CORRECTED.) On 401 the client refreshes once via
  `POST /ui/session/refresh` and retries; the OkHttp authenticator mirrors this.
  Persistent cookie jar required. NOTE: the OpenAPI declares an `X-SESSION-ID`
  header param on these routes; the web reference client does not send it (it
  relies on the session cookie + Bearer) — reconcile in code review (§16).
  Contract authority is `/openapi.json`; web reference is
  `src/api/endpoints/broadcast-inputs.ts` and `src/api/types.ts` (CORRECTED from
  the non-existent `broadcasts.ts`).
- **Upstream deps:** **AND-308 (WebRTC ingest, P0)** establishes the broadcast,
  the `inputs` collection, and one WebRTC input producer. AND-310 depends on
  AND-308 supplying the broadcast id, an authenticated host session, and at least
  one input to manage. Core session/CSRF/auth plumbing is inherited from M1.

## 3. Functional Requirements

FR-1. **List inputs.** On entering the inputs panel for session `{session_id}`,
fetch `GET /broadcast/sessions/{session_id}/inputs` and render one row per input
showing: `label`, `input_type` (`primary | guest | screen`), connection state
derived from the boolean `is_live`, and whether it is the current **program**
input (i.e. it equals the layout's `primary_input_id`). CORRECTED: the backend
`BroadcastInputOut` has NO `kind`, NO `status` enum, NO `active` flag, and NO
`is_program` flag. The valid `input_type` values are `primary|guest|screen`
(not `webrtc|hls|rtmp|screen`); "live vs offline" is the single boolean
`is_live`; "program" is computed by comparing `input_id` to the layout's
`primary_input_id`. (Verified §16.)

FR-2. **Activate / deactivate.** Each input exposes a toggle. Activating calls
`POST /broadcast/sessions/{session_id}/inputs/{input_id}/activate`; deactivating
calls `.../deactivate`. Both take an **empty body** and return `{"ok": true}`
(NOT the updated input object — CORRECTED). Because the response carries no row,
the UI re-fetches the list after a successful mutation to learn the new
`is_live`. The toggle MAY be optimistic with rollback on failure, but note the
web reference (`InputManager.tsx`) is non-optimistic: it invalidates and refetches
on success.

FR-3. **Switch program (live switch).** A "Make live" action promotes an input to
the program source. CORRECTED: there is **no** `/program` endpoint. The program
source is the layout's `primary_input_id`, set via
`POST /broadcast/sessions/{session_id}/layout` with body
`BroadcastLayoutSwitchIn { mode, primary_input_id?, input_ids? }` (`mode` is
required, one of `single|side_by_side|pip|grid`). The response is
`BroadcastLayoutOut { mode, input_ids, positions, primary_input_id }`. Exactly
one input is the program at a time (`primary_input_id` is a single value);
promoting input B sets `primary_input_id = B` server-side, implicitly demoting A.
This is the acceptance behavior — "inputs switch live."

FR-4. **Guards.** "Make live" is disabled for inputs that are not `is_live`. The
currently-program input (`input_id == primary_input_id`) cannot be deactivated;
the toggle for it is disabled with an explanatory affordance. NOTE: this guard is
a client-side product rule, not enforced by the backend contract (unverified §16).

FR-5. **Live refresh.** The list reflects server-driven `is_live`/program changes
within ~5s without manual reload, via poll (the web reference uses a 5000ms
`refetchInterval` — CORRECTED from the original ~3s) or WebSocket if AND-308
exposes the broadcast event channel. Stale data is visibly flagged when the
backend is unreachable.

FR-6. **Multiple sources.** The panel correctly handles 0..N inputs of mixed
kinds, including duplicate kinds (e.g., two `webrtc` inputs), and an empty state.

FR-7. **No teardown.** All actions mutate input state on a running broadcast; none
end the broadcast.

## 4. Technical Design

New package `com.testlogon.android.feature.broadcast.inputs` inside
`feature-broadcast`.

**Domain model** (`core-model`). CORRECTED to match `BroadcastInputOut`:
`input_type` is `primary|guest|screen` (not webrtc/hls/rtmp); there is no status
enum — connection state is the boolean `is_live`; there is no server `active` or
`is_program` field. `isProgram` is a CLIENT-DERIVED flag (input_id ==
layout.primary_input_id), not a wire field. `connected_at`/`disconnected_at` are
nullable epoch **integers** (not ISO strings); `created_at`/`updated_at` are ISO
strings.

```kotlin
enum class InputType { PRIMARY, GUEST, SCREEN, UNKNOWN }

data class BroadcastInput(
    val inputId: String,
    val sessionId: String,
    val label: String,
    val inputType: InputType,
    val isLive: Boolean,              // wire: is_live
    val isProgram: Boolean,          // client-derived: inputId == layout.primaryInputId
    val ingestUrl: String?,          // nullable
    val position: Int,
    val connectedAt: Long?,          // epoch seconds, nullable
    val disconnectedAt: Long?,       // epoch seconds, nullable
    val createdBy: String,
    val createdAt: Instant,          // ISO string
    val updatedAt: Instant,          // ISO string
)
```

**Repository** (`core-data`, interface in `core-data`, impl Hilt-bound):

```kotlin
interface InputsRepository {
    fun observeInputs(sessionId: String): Flow<List<BroadcastInput>> // cache-backed
    suspend fun refresh(sessionId: String): ApiResult<List<BroadcastInput>>
    // activate/deactivate return {"ok":true}; repo refetches the list to learn is_live.
    suspend fun setActive(sessionId: String, inputId: String, active: Boolean): ApiResult<List<BroadcastInput>>
    // "Make live" = set layout primary_input_id via POST .../layout (mode required).
    suspend fun setProgram(sessionId: String, inputId: String, mode: String): ApiResult<BroadcastLayout>
    fun observeLayout(sessionId: String): Flow<BroadcastLayout?>  // supplies primary_input_id
    suspend fun refreshLayout(sessionId: String): ApiResult<BroadcastLayout>
}
```

CORRECTED: keyed by `sessionId`/`inputId` (no `broadcastId`). `setActive` cannot
return the updated row because activate/deactivate return only `{"ok":true}`; it
refetches. `setProgram` posts to `/layout` (carrying the current/required `mode`)
and returns `BroadcastLayoutOut`; `isProgram` per input is then computed by
comparing `inputId` to `primary_input_id`. `observeInputs` emits from the Room
cache (`broadcast_inputs` table keyed by `(sessionId, inputId)`); `refresh`
performs the GET and upserts. The program/primary state is cached separately
(layout) and joined into `InputRow` at the ViewModel.

**ViewModel:**

```kotlin
@HiltViewModel
class InputsViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repo: InputsRepository,
) : ViewModel() {
    private val sessionId: String = savedState["sessionId"]!! // CORRECTED: route arg is sessionId
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
    val canMakeLive: Boolean,   // CORRECTED: input.isLive && !input.isProgram
    val canDeactivate: Boolean, // !input.isProgram  (client rule, see FR-4 note)
)
```

`uiState` is built by combining `observeInputs` with a `pendingIds` set
(`MutableStateFlow`) tracking in-flight optimistic mutations, surfaced via
`stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`. A
polling loop (`while(isActive){ repo.refresh(); repo.refreshLayout(); delay(5_000) }`,
matching the web reference's 5000ms `refetchInterval` — CORRECTED from 3000ms)
runs only while subscribed; if AND-308's broadcast event channel is available, the loop is
replaced by collecting that channel and falling back to poll on disconnect.

**UI** (`InputsScreen`, `InputRowItem` composables): a Material 3 list. Each row =
leading kind icon, label + status chip, a trailing `Switch` (active), and a
"Make live" `FilledTonalButton` gated by `canMakeLive`. The program input carries
a "LIVE" badge. Pending rows show an inline progress indicator and are
non-interactive. Empty state and full-screen error/retry use shared `core-ui`
components. Navigation route `broadcast/{sessionId}/inputs` (CORRECTED from
`{broadcastId}`) added to the `feature-broadcast` nav graph.

## 5. API Contract

This section was REWRITTEN against `/openapi.json` and `src/api/endpoints/
broadcast-inputs.ts`; the original paths/shapes were wrong (see §16). All
requests carry the session cookie (`credentials: include`), an
`Authorization: Bearer <accessToken>` header, and `X-CSRF-Token` (from the
`ui_csrf` cookie); `X-IMPERSONATION-TOKEN` when impersonating. OpenAPI also
declares an `X-SESSION-ID` header on these routes (see §2 note).

**List** — `GET /broadcast/sessions/{session_id}/inputs` → `200`
`BroadcastInputListOut`:

```json
{
  "session_id": "sess_01H...",
  "count": 1,
  "max_inputs": 4,
  "inputs": [
    {
      "input_id": "in_01H...",
      "session_id": "sess_01H...",
      "input_type": "primary",
      "label": "Host camera",
      "is_live": true,
      "ingest_url": "rtmp://...",
      "stream_key_ref": null,
      "aws_input_arn": null,
      "relay_mode": null,
      "position": 0,
      "connected_at": 1749126000,
      "disconnected_at": null,
      "created_by": "user_01H...",
      "created_at": "2026-06-05T12:00:00Z",
      "updated_at": "2026-06-05T12:00:00Z"
    }
  ]
}
```

Required fields per `BroadcastInputOut`: `input_id, session_id, input_type,
label, created_by, created_at, updated_at`. `is_live` defaults `false`,
`position` defaults `0`. `connected_at`/`disconnected_at` are nullable epoch
integers. `max_inputs` defaults `4` (answers the §13 "max inputs" question).

**Activate** — `POST /broadcast/sessions/{session_id}/inputs/{input_id}/activate`
(empty body) → `200`. **Deactivate** —
`POST /broadcast/sessions/{session_id}/inputs/{input_id}/deactivate` → `200`.
Both return only `{"ok": true}` (the OpenAPI `200` response declares no schema;
the web client types it as `{ ok: boolean }`). They do NOT return the updated
input — the client must re-`GET` the list to observe the new `is_live`.

**Set program (live switch)** — there is no `/program` endpoint. Use
`POST /broadcast/sessions/{session_id}/layout`, body `BroadcastLayoutSwitchIn`:

```json
{ "mode": "single", "primary_input_id": "in_01H...", "input_ids": null }
```

`mode` is REQUIRED (`single|side_by_side|pip|grid`); `primary_input_id` and
`input_ids` are optional/nullable. → `200` `BroadcastLayoutOut`:

```json
{
  "mode": "single",
  "primary_input_id": "in_01H...",
  "input_ids": ["in_01H...", "in_02H..."],
  "positions": [ { "input_id": "in_01H...", "x": 0, "y": 0, "width": 1920, "height": 1080, "z_index": 0 } ]
}
```

Current layout is readable via `GET /broadcast/sessions/{session_id}/layout`
(also `BroadcastLayoutOut`). The "program" input is the one whose `input_id`
equals `primary_input_id`.

**Errors:** the OpenAPI declares only `422 HTTPValidationError`
(`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`) on these routes; `200`
otherwise. `401` (session expired → refresh+retry) and `403` (permission, e.g.
`{"detail":{"code":"role_required",...}}`) are produced by shared middleware and
handled by the client; `404` (session/input not found) and `5xx`/timeout from
the unreliable dev host are expected operationally but are NOT documented per-
route. The original spec's `400 invalid transition` and `409 conflict` are
UNVERIFIED assumptions (no contract evidence — see §16). FastAPI `detail` is
parsed by the shared mapper (string | `[{msg}]` | `{code,msg}`), matching
`normalizeErrorDetail` in `src/api/client.ts`.

**Moshi DTOs** (`core-network`): `InputDto` (→ `BroadcastInputOut`),
`InputsResponseDto` (→ `BroadcastInputListOut`), `OkDto` (`{ok}` for
activate/deactivate), `LayoutSwitchRequestDto` (→ `BroadcastLayoutSwitchIn`),
`LayoutDto` (→ `BroadcastLayoutOut`); `@Json(name=...)` for snake_case; an
`InputType` adapter coerces unknown strings to `UNKNOWN` rather than throwing.

## 6. Data & State Management

- **Room** (`core-data`): table `broadcast_inputs` (PK `(sessionId, inputId)`,
  CORRECTED), columns mirroring `BroadcastInput`; `InputsDao` with
  `observeBySession`, `upsertAll`, `replaceForSession`, `deleteForSession`. A
  separate `broadcast_layout` row per session caches `primary_input_id`/`mode`
  (program state lives in the layout, not on the input). The cache is the UI
  source of truth so the panel renders instantly on re-entry and survives
  transient network loss (FR-5 stale handling).
- **Optimistic mutations:** before the network call, the targeted row's `is_live`
  (or, for program, the cached `primary_input_id`) is updated in-memory and the
  id added to `pendingIds`; on `ApiResult.Success` (activate/deactivate return
  only `{ok}`) the repo re-fetches the list and upserts the authoritative rows,
  then clears the id; on failure the cached row/layout is restored and a transient
  banner is shown. (The web reference is non-optimistic — invalidate+refetch — so
  optimism is an Android-side enhancement, not a contract requirement.)
- **Single-program invariant:** program identity is the layout's single
  `primary_input_id`; setting it server-side via `/layout` and re-reading the
  layout guarantees exactly one `isProgram == true` when joined to the input list.
  If a poll response and a mutation response race, last-write-by-`updated_at` wins
  on input upsert; the layout cache takes the latest layout response.
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
  optimistic activate success keeps new state (after refetch); activate failure
  rolls back and emits banner; `onMakeLive` sets the layout `primary_input_id` and
  the derived `isProgram` moves to the new input (prior demoted); `canMakeLive`
  guard false when `!isLive`; program input has `canDeactivate == false`; stale
  flag set when refresh fails with warm cache.
- **Repository (MockWebServer):** GET parse incl. unknown `input_type` →
  `UNKNOWN` and nullable `connected_at`/`ingest_url`; activate/deactivate return
  `{"ok":true}` then repo refetches list; `setProgram` posts `/layout` with
  required `mode` and derives single program from `primary_input_id`; GET retried
  on 503 then succeeds; POST **not** retried on 503; 401 path triggers
  authenticator refresh (one retry); `422`/`detail` mapping for
  string/list/object shapes.
- **DAO (Room in-memory):** upsert keyed by `(sessionId,inputId)`,
  `replaceForSession` atomicity, observe emits on change.
- **Compose UI tests:** toggle disabled for program input; "Make live" disabled
  with correct semantics for non-live input; pending row shows progress and is
  non-interactive; empty and error/retry states; semantics/contentDescription
  assertions.
- **Contract guard:** a JSON fixture test pinned to `/openapi.json`
  `BroadcastInputOut`/`BroadcastInputListOut`/`BroadcastLayoutOut` shapes, failing
  if field names drift from §5 (in particular `input_type`, `is_live`,
  `primary_input_id`).

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
  unconfirmed; fallback is 5s polling (matching the web reference), acceptable for
  "switch live within ~5s".
- **R3 — endpoint shapes (RESOLVED):** verified against `/openapi.json` and
  `src/api/endpoints/broadcast-inputs.ts`. There is no `PATCH input` and no
  `/program` endpoint; activate/deactivate are dedicated POSTs returning `{ok}`,
  and program = layout `primary_input_id`. The contract guard test (§11) pins
  this.
- **R4 — concurrency:** multiple host devices editing inputs; the backend exposes
  no documented `409`/locking on these routes, so mitigation is a periodic poll
  (5s) reconciling state. NOTE: the original `409 → forced refresh` design is an
  unverified assumption (§16); treat any non-2xx as a generic error + refresh.
- **OQ (PARTIALLY RESOLVED):** max inputs per session is `max_inputs` (default 4,
  returned in `BroadcastInputListOut`) — enforce the add-input cap against it.
  Still open: is deactivating the sole live / program input allowed server-side,
  and what does the viewer see? No contract evidence; pending product/AND-308.

## 14. Acceptance Criteria

- AC-1. The inputs panel lists every input of session `{session_id}` with
  `label`, `input_type`, live/offline state (`is_live`), and program badge
  (input matching layout `primary_input_id`).
- AC-2. Activating/deactivating an input calls the correct
  `.../activate|deactivate` endpoint (returning `{ok}`), refetches to confirm the
  new `is_live`, updates optimistically, and rolls back on failure with a
  user-visible message.
- AC-3. **Inputs switch live:** promoting a live input via
  `POST .../layout` with `primary_input_id` makes it the program source, demotes
  the prior one, and the change is reflected within ~5s (poll or event channel).
  *(source acceptance)*
- AC-4. Exactly one input is the program at any time (one `primary_input_id`); the
  program input cannot be deactivated and its "Make live" is hidden/disabled.
- AC-5. "Make live" is disabled for inputs that are not `is_live`.
- AC-6. Multiple inputs of mixed and duplicate `input_type`s, and the empty/
  0-input case, render correctly; the add control is capped at `max_inputs`.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI
sources are `reference/openapi.index.txt` / `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend sources are under `reference/src/`.

1. **List endpoint is `GET /broadcast/sessions/{session_id}/inputs`.** Verdict:
   **Corrected** (spec originally said `GET /ui/broadcasts/{id}/inputs`, which
   does not exist). Source: OpenAPI `GET /broadcast/sessions/{session_id}/inputs`
   (op `list_inputs_route...`, resp `200:BroadcastInputListOut`);
   `src/api/endpoints/broadcast-inputs.ts: listInputs`.
2. **Activate / Deactivate endpoints
   `POST .../inputs/{input_id}/activate|deactivate`.** Verdict: **Verified** (path
   shape) / **Corrected** (base path was wrong). Source: OpenAPI
   `POST /broadcast/sessions/{session_id}/inputs/{input_id}/activate` and
   `.../deactivate`; `src/api/endpoints/broadcast-inputs.ts: activateInput,
   deactivateInput`.
3. **Activate/deactivate return `{"ok": true}`, not the updated input object.**
   Verdict: **Corrected**. Source: OpenAPI both routes `resp=200:` (no schema);
   `broadcast-inputs.ts: activateInput` returns `Promise<{ ok: boolean }>`.
4. **There is no `/program` endpoint; the program source is the layout's
   `primary_input_id`, set via `POST /broadcast/sessions/{session_id}/layout`.**
   Verdict: **Corrected** (spec invented `POST /ui/broadcasts/{id}/program
   {input_id}`). Source: grep of `openapi.pretty.json` for `/program` →
   only `primary_input_id` matches; OpenAPI `POST .../layout`
   (req `BroadcastLayoutSwitchIn`, resp `200:BroadcastLayoutOut`);
   `broadcast-inputs.ts: switchLayout`.
5. **`BroadcastLayoutSwitchIn` requires `mode` (`single|side_by_side|pip|grid`)
   with optional `primary_input_id`, `input_ids`.** Verdict: **Verified**. Source:
   `components.schemas.BroadcastLayoutSwitchIn` (`required:["mode"]`, `mode`
   pattern `^(single|side_by_side|pip|grid)$`).
6. **`BroadcastLayoutOut` returns `mode, input_ids, positions,
   primary_input_id`.** Verdict: **Verified**. Source:
   `components.schemas.BroadcastLayoutOut`; `src/api/types.ts: BroadcastLayout`.
7. **Input fields are `input_id, session_id, input_type, label, is_live,
   ingest_url, stream_key_ref, aws_input_arn, relay_mode, position, connected_at,
   disconnected_at, created_by, created_at, updated_at`.** Verdict: **Corrected**
   (spec used `id, broadcast_id, kind, status, active, is_program, updated_at`).
   Source: `components.schemas.BroadcastInputOut`; `src/api/types.ts:
   BroadcastInput`.
8. **`input_type` values are `primary|guest|screen` (NOT `webrtc|hls|rtmp|
   screen`).** Verdict: **Corrected**. Source: `BroadcastInputCreateIn.input_type`
   pattern `^(primary|guest|screen)$`; `src/api/types.ts: BroadcastInput.
   input_type: "primary"|"guest"|"screen"`.
9. **Connection state is the boolean `is_live`; there is no `status` enum
   (`idle/connecting/live/error`) and no separate `active` flag.** Verdict:
   **Corrected**. Source: `BroadcastInputOut.is_live` (boolean, default false);
   `InputManager.tsx` toggles purely on `inp.is_live`.
10. **"Program" is derived (input_id == layout.primary_input_id), not a wire
    field.** Verdict: **Corrected/derived**. Source: absence of `is_program` in
    `BroadcastInputOut`; presence of `primary_input_id` in `BroadcastLayoutOut`.
11. **`connected_at`/`disconnected_at` are nullable epoch integers; `created_at`/
    `updated_at` are ISO strings.** Verdict: **Verified/Corrected** (spec modeled
    only `updatedAt: Instant`). Source: `BroadcastInputOut` (`connected_at` anyOf
    integer/null; `created_at`/`updated_at` type string).
12. **List response wrapper is `{session_id, count, inputs[], max_inputs}` with
    `max_inputs` default 4.** Verdict: **Verified/Corrected** (spec used bare
    `{inputs:[...]}`). Source: `components.schemas.BroadcastInputListOut`;
    `src/api/types.ts: BroadcastInputList`; `InputManager.tsx` renders
    `inputs.length/${data?.max_inputs ?? 4}`.
13. **Live-refresh poll interval is ~5s (not ~3s).** Verdict: **Corrected**.
    Source: `InputManager.tsx` `useQuery({ ..., refetchInterval: 5000 })`.
14. **Auth = session cookie + `Authorization: Bearer <accessToken>` +
    `X-CSRF-Token` (from `ui_csrf`), `X-IMPERSONATION-TOKEN` when impersonating;
    401 → `POST /ui/session/refresh` once then retry.** Verdict: **Verified**
    (CSRF + refresh) / **Corrected** (spec omitted Bearer + impersonation).
    Source: `src/api/client.ts` (`Authorization` Bearer, `getCookie("ui_csrf")` →
    `X-CSRF-Token`, `X-IMPERSONATION-TOKEN`, `refreshSession()` →
    `/ui/session/refresh`).
15. **OpenAPI declares an `X-SESSION-ID` header param on these routes.** Verdict:
    **Verified (contract)** but the web client does NOT send it (relies on cookie
    + Bearer). Source: `params=...,X-SESSION-ID,...` in `openapi.index.txt` lines
    187-194 vs `src/api/client.ts` (no `X-SESSION-ID` set). Flagged for code-review
    reconciliation.
16. **`detail` error shapes are string | `[{msg}]` | `{code,...}`.** Verdict:
    **Verified**. Source: `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError` (handles string, array-of-`{msg}`, and `{code}` like
    `role_required`); `components.schemas.HTTPValidationError`
    (`{detail:[ValidationError]}`).
17. **The only per-route documented error is `422 HTTPValidationError`.** Verdict:
    **Verified**. Source: every inputs/layout line in `openapi.index.txt` shows
    `resp=200:...;422:HTTPValidationError` and nothing else.
18. **Web reference file is `broadcast-inputs.ts` / `types.ts` (not
    `broadcasts.ts`).** Verdict: **Corrected**. Source: directory listing of
    `src/api/endpoints/` (no `broadcasts.ts`; `broadcast-inputs.ts` exists).
19. **Web UI is non-optimistic (invalidate + refetch on success).** Verdict:
    **Verified**. Source: `InputManager.tsx` mutations call
    `queryClient.invalidateQueries(...)` in `onSuccess`; no `onMutate`.
20. **Framework choices (Compose Material 3 list, `Switch`, `liveRegion`,
    `WhileSubscribed`, MockWebServer).** Verdict: **Unverified-assumption**
    (Android implementation choice, not derivable from backend/frontend sources).
    framework ref: Jetpack Compose / `androidx.compose.material3`,
    `kotlinx.coroutines.flow.SharingStarted.WhileSubscribed`,
    `com.squareup.okhttp3.mockwebserver`.

### Corrections made

- **C1 — Endpoint base path.** `/ui/broadcasts/{id}/...` → `/broadcast/sessions/
  {session_id}/...` across §1, §2, §3, §4, §5, §6, §14 (claims 1-2).
- **C2 — `/program` endpoint removed.** Replaced with
  `POST .../layout {mode, primary_input_id}` and the derived program concept
  (§3 FR-3, §4, §5, §6, §13 R3, §14 AC-3/AC-4) (claim 4-5, 10).
- **C3 — Input field/enum model.** Dropped `kind`/`status`/`active`/`is_program`/
  `broadcast_id`; adopted `input_type (primary|guest|screen)`, `is_live`, real
  field names, nullable integer timestamps, and the `{session_id,count,inputs,
  max_inputs}` wrapper (§3, §4, §5, §11, §14) (claims 7-9, 11-12).
- **C4 — Activate/deactivate response.** `{ok}` (no row) → refetch, instead of
  "returns updated input" (§3 FR-2, §5, §6, §11, §14 AC-2) (claim 3).
- **C5 — Poll interval.** ~3s → ~5s to match the web reference (§3 FR-5, §4, §13
  R2, §14 AC-3) (claim 13).
- **C6 — Auth headers.** Added `Authorization: Bearer` and `X-IMPERSONATION-TOKEN`
  to the documented auth model; flagged `X-SESSION-ID` divergence (§2, §5) (claims
  14-15).
- **C7 — Reference file name.** `broadcasts.ts` → `broadcast-inputs.ts` (§2)
  (claim 18).
- **C8 — Room keys / DAO names.** `(broadcastId,id)` → `(sessionId,inputId)`;
  added a `broadcast_layout` cache for program state (§6, §11).
- **C9 — `max_inputs` resolves the "max inputs" open question** (default 4)
  (§5, §13 OQ).

### Open assumptions

- **OA1 — `400 invalid transition` and `409 conflict` error handling (§5, §7,
  §13 R4).** Unverifiable: the OpenAPI documents only `422` on these routes and no
  conflict semantics; no frontend code handles 400/409 specifically. Kept as
  defensive handling but explicitly flagged as assumptions.
- **OA2 — Client-side guards (program input cannot be deactivated; "Make live"
  only when `is_live`).** Unverifiable as server-enforced rules; they are product
  rules with no contract evidence. Backend may permit either operation.
- **OA3 — Broadcast event WebSocket for sub-poll live refresh (§3 FR-5, §13 R2).**
  Owned by AND-308; no channel found in the reference sources, so the 5s poll is
  the verified fallback.
- **OA4 — Live-switch transport (§13 R1).** Whether changing `primary_input_id`
  requires client WebRTC renegotiation vs server-side mixing is not answerable
  from these sources; assumed server-side, confirm with AND-308 owner.
- **OA5 — Deactivating the sole live / program input behavior (§13 OQ).** No
  contract or frontend evidence; pending product/AND-308.
- **OA6 — Android framework specifics (Compose, Hilt, Room, OkHttp authenticator,
  Turbine/Robolectric).** Implementation choices, not contract facts; labeled
  framework refs (claim 20).

## 17. Test Plan

Targets: **JVM** = JVM unit/Robolectric (no device); **MWS** =
MockWebServer contract test (JVM); **EMU** = headless emulator AVD `test35`
(x86_64, API 35); **DEVICE** = physical Samsung Galaxy A15 5G (SM-A156U, serial
R5CX821TA9R, API 34, arm64-v8a). This ticket is data/UI only (no camera,
biometrics, push, or WebRTC media), so most cases run on JVM/EMU; the manual
host walkthrough and the API-34 arm64 smoke MUST run on DEVICE.

- **TC-AND-310-01 — List renders inputs (happy path).** Type: unit (ViewModel).
  Target: JVM. Preconditions: repo returns 2 inputs (`input_type` primary+guest,
  one `is_live=true`), layout `primary_input_id` = the live one. Steps: collect
  `uiState` via Turbine. Expected: `Loading` → `Content` with 2 `InputRow`s;
  labels/`input_type`/live state correct; the primary-matching row has
  `isProgram=true` and a program badge. Traces: AC-1.

- **TC-AND-310-02 — List/DTO contract parse incl. unknowns & nulls.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: MWS serves a
  `BroadcastInputListOut` with `count`, `max_inputs:4`, one input whose
  `input_type` is an unknown string and `ingest_url`/`connected_at` null. Steps:
  call `refresh(sessionId)`. Expected: parses without throwing; unknown
  `input_type` → `UNKNOWN`; nulls map to null; wrapper fields populated. Traces:
  AC-1, AC-6.

- **TC-AND-310-03 — Activate optimistic success + refetch.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: input `is_live=false`; MWS
  queues `POST .../activate` → `200 {"ok":true}`, then `GET .../inputs` →
  same input `is_live=true`. Steps: `onToggleActive(id, true)`. Expected: POST has
  empty body; row optimistically live + `pendingIds` contains id; after refetch
  the authoritative `is_live=true` persists and `pendingIds` clears. Traces: AC-2.

- **TC-AND-310-04 — Activate failure rolls back + banner.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: MWS `POST .../activate` →
  `422` with `{"detail":[{"loc":["body"],"msg":"input not connected","type":"value_error"}]}`.
  Steps: `onToggleActive(id, true)`. Expected: optimistic flip reverts to prior
  cached row; banner shows mapped message "input not connected"; no auto-retry of
  the POST. Traces: AC-2, AC-7.

- **TC-AND-310-05 — Make-live switches program via /layout.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: inputs A (program) and B
  (live, not program); MWS `POST .../layout` body `{mode,primary_input_id:B}` →
  `200 BroadcastLayoutOut{primary_input_id:B}`. Steps: `onMakeLive(B)`. Expected:
  request includes required `mode`; after layout response, derived `isProgram`
  moves to B and A is demoted; exactly one program. Traces: AC-3, AC-4.

- **TC-AND-310-06 — Single-program invariant under race.** Type: unit
  (ViewModel/repo). Target: JVM. Preconditions: a poll list refresh and a layout
  mutation response arrive close together. Steps: emit both. Expected: derived
  `isProgram` reflects the latest `primary_input_id`; never two program rows.
  Traces: AC-4.

- **TC-AND-310-07 — Guards: program row can't deactivate; non-live can't go
  live.** Type: Compose-UI. Target: EMU. Preconditions: rows = program (live) +
  offline input. Steps: render `InputsScreen`. Expected: program row's active
  Switch disabled with explanatory semantics; offline row's "Make live" disabled;
  assert `assertIsNotEnabled()` + `stateDescription`. Traces: AC-4, AC-5, AC-8.

- **TC-AND-310-08 — Mixed/duplicate types + empty state + max cap.** Type:
  Compose-UI. Target: EMU. Preconditions: case (a) 3 inputs incl. two `guest`;
  case (b) 0 inputs; `max_inputs=4`. Steps: render each. Expected: (a) all rows
  render with correct per-row state; add control disabled/hidden once
  count==max_inputs; (b) empty-state component shown. Traces: AC-6.

- **TC-AND-310-09 — GET retried on 503, POST not retried.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: MWS `GET .../inputs` →
  `503` then `200`; separately `POST .../activate` → `503`. Steps: `refresh` then
  `onToggleActive`. Expected: GET succeeds after bounded backoff (≤3 attempts);
  POST surfaces error immediately with manual Retry, no duplicate POST sent.
  Traces: AC-7.

- **TC-AND-310-10 — Offline warm vs cold cache (flaky dev host).** Type:
  integration. Target: JVM (Robolectric + in-memory Room) for warm/cold logic;
  re-run on EMU for end-to-end banner. Preconditions: (warm) Room has cached
  inputs, network fails; (cold) empty Room, network fails. Steps: enter panel.
  Expected: warm → `Content(isStale=true)` + "Showing last known state" banner;
  cold → `Error(retryable=true)`. Traces: AC-7.

- **TC-AND-310-11 — 401 triggers single session refresh + retry.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: MWS `GET .../inputs` →
  `401`, `POST /ui/session/refresh` → `200`, retried `GET` → `200`. Steps:
  `refresh`. Expected: exactly one refresh call then one retry; success surfaces;
  a second consecutive 401 routes to re-auth (no infinite loop). Traces: AC-2,
  AC-7.

- **TC-AND-310-12 — Auth headers present on mutations (security).** Type:
  contract/MockWebServer. Target: MWS. Preconditions: cookie jar seeded with
  `ui_csrf`; auth store has access token. Steps: issue activate + layout POSTs.
  Expected: each request carries the session cookie, `Authorization: Bearer ...`,
  and `X-CSRF-Token` equal to the `ui_csrf` value; no cookie/CSRF/token values
  appear in logs (interceptor redaction). Traces: AC-2, AC-3.

- **TC-AND-310-13 — Permission denied (403) rendering.** Type:
  contract/MockWebServer. Target: MWS. Preconditions: non-host session; MWS
  `POST .../layout` → `403 {"detail":{"code":"role_required"}}`. Steps:
  `onMakeLive`. Expected: optimistic change rolls back; user sees the mapped
  permission message ("You don't currently have permission..."); no state flip
  persists. Traces: AC-2, AC-3.

- **TC-AND-310-14 — Accessibility/TalkBack + localization audit.** Type:
  Compose-UI (semantics) + manual TalkBack on DEVICE. Target: EMU for semantics
  asserts; DEVICE for real TalkBack pass. Preconditions: panel with a program +
  an offline input. Steps: (auto) assert `contentDescription`/`stateDescription`
  on Switch, "Make live", program badge, and `liveRegion=Polite` on the list;
  (manual) swipe-navigate with TalkBack on the A15, flip an input. Expected:
  every control is reachable and announces label + state + disabled reason; a
  source going live is announced without focus theft; no hardcoded strings
  (all from `strings.xml`). Traces: AC-8.

- **TC-AND-310-15 — Real-host walkthrough + ABI/API smoke (manual).** Type:
  manual / instrumented e2e. Target: DEVICE (MUST — physical SM-A156U, arm64-v8a,
  API 34, to cover arm64-vs-x86 and API-34-vs-35 differences against the live
  dev backend). Preconditions: AND-308 has created a session with ≥1 input; host
  signed in. Steps: open panel; activate an offline input; "Make live" a second
  input; toggle airplane mode to force the stale path then recover. Expected:
  switches land server-side and reflect within ~5s; stale banner appears offline
  and clears on recovery; no crash/ANR on arm64/API-34; no teardown of the
  broadcast. Traces: AC-1, AC-2, AC-3, AC-7.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (list with label/type/live/program) | TC-01, TC-02, TC-15 |
| AC-2 (activate/deactivate + rollback) | TC-03, TC-04, TC-11, TC-12, TC-13, TC-15 |
| AC-3 (inputs switch live via /layout, ~5s) | TC-05, TC-12, TC-13, TC-15 |
| AC-4 (single program; program can't deactivate) | TC-05, TC-06, TC-07 |
| AC-5 ("Make live" disabled when not live) | TC-07 |
| AC-6 (mixed/duplicate types, empty, max cap) | TC-02, TC-08 |
| AC-7 (offline stale/cold; GET retry, POST no retry) | TC-04, TC-09, TC-10, TC-11, TC-15 |
| AC-8 (a11y/TalkBack + localized strings) | TC-07, TC-14 |
