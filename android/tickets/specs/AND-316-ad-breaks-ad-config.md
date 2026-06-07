---
id: AND-316
title: Ad breaks / ad config
milestone: M7
epic: E41
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-309]
blocks: []
---

# AND-316 — Ad breaks / ad config

## 1. Overview & Goal

This ticket adds **host-side ad-break orchestration and ad configuration** to the
TestLogon Android live-broadcast host surface. A broadcaster running a live session
must be able to (a) read and edit the session's ad configuration (pre-roll toggle,
mid-roll ad-break duration, viewer skip-after window), (b) trigger a mid-roll ad
break for all viewers on demand, and (c) end an in-progress ad break early. The
client reflects the live ad-break state (active / not active, started-at timestamp,
running countdown, total breaks so far) in the host control surface.

The feature builds directly on **AND-309 (Host controls)**, which owns the host
session control panel, the resolved `session_id`, lifecycle controls
(start/stop/resume/reschedule), and the health-report channel. AND-316 contributes
the ad-break and ad-config segment of that panel plus the repository/ViewModel
plumbing behind it. It does **not** own viewer-side ad rendering or WebRTC ingest;
viewer ad insertion is a separate consumer surface and is out of scope here. The
single load-bearing acceptance signal is: **triggering an ad break flips the session
into an active ad-break state that the host UI surfaces, and ending it (manually or by
expiry) clears that state.**

The host is the authenticated broadcaster who owns the session; all calls in scope
are broadcaster-only mutations gated by the cookie session established in the auth
milestone (M2) and reused by every authenticated repository.

## 2. Context & References

- **Backend (authoritative):** FastAPI, tag `broadcast-ads`. Endpoints under
  `/broadcast/sessions/{session_id}/...`. Dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable — design for ~20s timeouts and offline/stale states).
  OpenAPI at `/openapi.json`.
- **Schemas used:** `BroadcastAdConfigOut`, `BroadcastAdConfigIn`, `AdBreakOut`.
  (Note: `AdConfigIn` exists in the schema set but belongs to the VOD ad-config
  surface — `AND-194` — and is NOT used here. This ticket uses only the
  `Broadcast*` variants.)
- **Web reference:** `frontend/src/api/endpoints/*.ts` (broadcast host calls) and
  shared types in `frontend/src/api/types.ts`.
- **Upstream dependency:** `AND-309` — host control panel, `session_id` source of
  truth, host-area Hilt graph, lifecycle/health wiring.
- **Cross-cutting infrastructure (already delivered):** persistent cookie jar
  (AND-011), CSRF interceptor echoing `ui_csrf` as `X-CSRF-Token` (AND-012), 401
  single-refresh authenticator (AND-013), bounded backoff for idempotent GETs
  (AND-016), `ApiResult<T>` (AND-018), FastAPI `detail` error mapping (AND-015),
  state composables loading/empty/error/offline (AND-021).
- **Namespace:** all code under `com.testlogon.android`.

## 3. Functional Requirements

FR-1. The host control surface exposes an **Ads** section that loads the current ad
config and live ad-break state on entry via `GET .../ad-config`.

FR-2. The host can edit ad configuration: `pre_roll_enabled` (toggle),
`mid_roll_ad_break_duration_seconds` (integer, 15–60 inclusive),
`mid_roll_skip_after_seconds` (integer, 5–30 inclusive). The client validates ranges
before submit and disables submit on invalid input. Save sends a `PATCH` with **only
the changed fields** (all three `BroadcastAdConfigIn` fields are nullable/optional).

FR-3. The host can **trigger an ad break** via a primary action. While no break is
active and a session is live, the action is enabled; it is disabled while a break is
already active or while a trigger/end request is in flight.

FR-4. The host can **end an active ad break early** via `POST .../ad-break/end`. This
action is enabled only while `ad_break_active == true`.

FR-5. When a break is active, the UI shows a countdown derived from
`ad_break_started_at + mid_roll_ad_break_duration_seconds`, the configured skip-after
value, and the running `total_ad_breaks` count. When the computed remaining time
reaches zero the UI treats the break as expired (auto-clears active state) without
requiring the end call, and re-fetches config to reconcile with the server.

FR-6. All three mutations (`PATCH ad-config`, `POST ad-break`, `POST ad-break/end`)
optimistically update local state where safe and reconcile against the returned
`BroadcastAdConfigOut` / `AdBreakOut`, then refresh from the server on success.

FR-7. Config and ad-break state are scoped to the active `session_id` supplied by
AND-309; switching sessions resets the ad sub-state.

## 4. Technical Design

Module placement: `feature-host` (the host control feature module created in AND-309),
depending on `core-network`, `core-model`, `core-data`, `core-ui`.

### DTOs (`core-model`, Moshi)

```kotlin
@JsonClass(generateAdapter = true)
data class BroadcastAdConfigOut(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "pre_roll_enabled") val preRollEnabled: Boolean,
    @Json(name = "mid_roll_ad_break_duration_seconds") val midRollAdBreakDurationSeconds: Int,
    @Json(name = "mid_roll_skip_after_seconds") val midRollSkipAfterSeconds: Int,
    @Json(name = "ad_break_active") val adBreakActive: Boolean,
    @Json(name = "ad_break_started_at") val adBreakStartedAt: Long?, // epoch seconds, nullable
    @Json(name = "total_ad_breaks") val totalAdBreaks: Int,
)

@JsonClass(generateAdapter = true)
data class BroadcastAdConfigIn(
    @Json(name = "pre_roll_enabled") val preRollEnabled: Boolean? = null,
    @Json(name = "mid_roll_ad_break_duration_seconds") val midRollAdBreakDurationSeconds: Int? = null,
    @Json(name = "mid_roll_skip_after_seconds") val midRollSkipAfterSeconds: Int? = null,
)

@JsonClass(generateAdapter = true)
data class AdBreakOut(
    val ok: Boolean = true,
    @Json(name = "duration_seconds") val durationSeconds: Int,
    @Json(name = "started_at") val startedAt: Long, // epoch seconds
    @Json(name = "skip_after_seconds") val skipAfterSeconds: Int,
)
```

Nullable `Int?`/`Boolean?` in `BroadcastAdConfigIn` must serialize as **omitted when
null** so PATCH is a true partial update; configure the Moshi adapter with
`.serializeNulls(false)` (default) and never set fields the user did not change.

### Retrofit API (`core-network` / `feature-host`)

```kotlin
interface HostAdApi {
    @GET("broadcast/sessions/{sessionId}/ad-config")
    suspend fun getAdConfig(@Path("sessionId") sessionId: String): Response<BroadcastAdConfigOut>

    @PATCH("broadcast/sessions/{sessionId}/ad-config")
    suspend fun updateAdConfig(
        @Path("sessionId") sessionId: String,
        @Body body: BroadcastAdConfigIn,
    ): Response<BroadcastAdConfigOut>

    @POST("broadcast/sessions/{sessionId}/ad-break")
    suspend fun triggerAdBreak(@Path("sessionId") sessionId: String): Response<AdBreakOut>

    @POST("broadcast/sessions/{sessionId}/ad-break/end")
    suspend fun endAdBreak(@Path("sessionId") sessionId: String): Response<Unit>
}
```

The optional backend params (`user_sub` query, `X-SESSION-ID`,
`X-IMPERSONATION-TOKEN` headers) are not set by the client — the cookie session
identifies the broadcaster. They remain available for future impersonation tooling
but are out of scope.

### Repository

```kotlin
interface HostAdRepository {
    suspend fun getAdConfig(sessionId: String): ApiResult<BroadcastAdConfigOut>
    suspend fun updateAdConfig(sessionId: String, patch: BroadcastAdConfigIn): ApiResult<BroadcastAdConfigOut>
    suspend fun triggerAdBreak(sessionId: String): ApiResult<AdBreakOut>
    suspend fun endAdBreak(sessionId: String): ApiResult<Unit>
}
```

`HostAdRepositoryImpl(@Inject api: HostAdApi, errorMapper: ApiErrorMapper)` wraps each
call: `GET` runs through the AND-016 idempotent-GET backoff; the three mutations
(`PATCH`/`POST`) do **not** retry on transient failure (non-idempotent) and surface
errors directly. Provided via `@Provides`/`@Binds` in a `@Module @InstallIn(SingletonComponent::class)`.

### ViewModel & state

```kotlin
data class AdControlUiState(
    val loading: Boolean = false,
    val config: AdConfigForm = AdConfigForm(),       // editable form
    val adBreakActive: Boolean = false,
    val adBreakStartedAt: Long? = null,
    val adBreakDurationSeconds: Int = 0,
    val skipAfterSeconds: Int = 0,
    val remainingSeconds: Int = 0,                   // derived, ticked locally
    val totalAdBreaks: Int = 0,
    val mutationInFlight: Boolean = false,
    val error: UiError? = null,
    val offline: Boolean = false,
)

data class AdConfigForm(
    val preRollEnabled: Boolean = true,
    val midRollDurationSeconds: Int = 30,
    val skipAfterSeconds: Int = 5,
    val durationValid: Boolean = true,   // 15..60
    val skipValid: Boolean = true,       // 5..30
    val dirty: Boolean = false,
)

@HiltViewModel
class HostAdViewModel @Inject constructor(
    private val repo: HostAdRepository,
    savedState: SavedStateHandle,        // sessionId from AND-309 nav args
) : ViewModel() {
    private val sessionId: String = checkNotNull(savedState["sessionId"])
    val state: StateFlow<AdControlUiState>
    fun refresh()
    fun onPreRollToggled(enabled: Boolean)
    fun onDurationChanged(seconds: Int)
    fun onSkipAfterChanged(seconds: Int)
    fun saveConfig()
    fun triggerAdBreak()
    fun endAdBreak()
}
```

The countdown is driven by a coroutine `tick` (`while (isActive) { emit; delay(1.seconds) }`)
started only while `adBreakActive`; `remainingSeconds` is recomputed from
`adBreakStartedAt + adBreakDurationSeconds - now`. On reaching 0 the ViewModel clears
active state and calls `refresh()` to reconcile `total_ad_breaks` with the server.

### UI (`core-ui` Compose + Material 3)

`AdControlSection(state, callbacks)` composable embedded in the AND-309 host panel:
a `Switch` for pre-roll, two stepper/numeric fields with inline validation messages,
a "Save config" button (enabled only when `dirty && durationValid && skipValid`), and
an ad-break control card showing either a "Trigger ad break" `FilledTonalButton` or,
while active, an animated countdown chip with an "End early" `OutlinedButton`. Uses the
AND-021 loading/error/offline state composables for the section-level shell.

## 5. API Contract

Base path prefix: `/` on the broadcast host (no `/ui` prefix for `broadcast-*`
routes). All calls carry the session cookie + `X-CSRF-Token` (AND-012).

**GET `/broadcast/sessions/{session_id}/ad-config`** → `200 BroadcastAdConfigOut`
```json
{
  "session_id": "sess_abc123",
  "pre_roll_enabled": true,
  "mid_roll_ad_break_duration_seconds": 30,
  "mid_roll_skip_after_seconds": 5,
  "ad_break_active": false,
  "ad_break_started_at": null,
  "total_ad_breaks": 2
}
```

**PATCH `/broadcast/sessions/{session_id}/ad-config`** — body `BroadcastAdConfigIn`
(all fields optional; send only changed):
```json
{ "pre_roll_enabled": false, "mid_roll_ad_break_duration_seconds": 45 }
```
→ `200 BroadcastAdConfigOut` (full refreshed config). Server constraints:
`mid_roll_ad_break_duration_seconds` ∈ [15, 60]; `mid_roll_skip_after_seconds` ∈
[5, 30]. Out-of-range → `422` `HTTPValidationError`.

**POST `/broadcast/sessions/{session_id}/ad-break`** (no body) → `200 AdBreakOut`
```json
{ "ok": true, "duration_seconds": 30, "started_at": 1749081600, "skip_after_seconds": 5 }
```

**POST `/broadcast/sessions/{session_id}/ad-break/end`** (no body) → `200`.
*(Correction: the OpenAPI declares the 200 content schema as `{}` — i.e. an
**untyped** JSON schema, not literally an empty object. The web reference
(`src/api/endpoints/broadcast-ads.ts: endAdBreak`) types the response as
`{ ok: boolean }`. Either way the body is not load-bearing for this client, so we
deserialize to `Unit`/ignore it and rely on a follow-up `GET ad-config`.)*

**Error body shape (all routes):** FastAPI `{"detail": ...}` where `detail` is a
string, an array `[{"msg": "...", "loc": [...]}]` (422), or an object
`{"code": "...", ...}` — mapped by the shared `ApiErrorMapper` (AND-015) into
`UiError`.

## 6. Data & State Management

- **No Room persistence.** Ad config and ad-break state are live, session-scoped, and
  short-lived; they are held in `HostAdViewModel` memory only. There is no offline
  cache requirement beyond showing the last-loaded snapshot while a refresh is in
  flight.
- **Source of truth:** the server. Local optimistic edits are reconciled against the
  returned `BroadcastAdConfigOut`/`AdBreakOut` on every successful mutation.
- **Timestamps:** `started_at` / `ad_break_started_at` are epoch **seconds** (Long).
  The countdown uses device clock; clock skew is tolerated by reconciling via
  `refresh()` on expiry rather than trusting only the local timer.
- **Session scoping:** `sessionId` is injected from the AND-309 nav args via
  `SavedStateHandle`. The ViewModel is scoped to the host-control nav destination, so
  navigating away and back re-creates state and re-fetches.
- **Config form vs. server state:** the editable `AdConfigForm` is kept separate from
  the canonical server values so an in-progress edit is not stomped by a background
  refresh; `dirty` guards the merge.

## 7. Error Handling & Resilience

- **GET ad-config:** idempotent → AND-016 bounded backoff (max ~3 attempts, jittered),
  ~20s OkHttp timeout. On exhaustion show the AND-021 error/offline state with retry.
- **Mutations (PATCH/POST):** non-idempotent → **no automatic retry**. On failure show
  an inline error and roll back the optimistic change. Re-fetch config to reconcile.
- **401:** handled transparently by the AND-013 authenticator (single
  `POST /ui/session/refresh` then one retry); a second 401 surfaces as a session-expired
  error routed to re-auth by the existing host-area handling.
- **422 (validation):** map `detail[].msg` to field-level errors on the duration/skip
  inputs; should be rare because the client validates ranges pre-submit.
- **Race — break already active:** if `POST ad-break` returns a conflict/error because a
  break is already running, reconcile from `GET ad-config` and show the active state.
- **Offline:** disable all mutation actions; show offline banner; allow read of
  last-known snapshot.
- **Expiry without explicit end:** local timer clears active state at
  `started_at + duration_seconds`, then reconciles via refresh.

## 8. Security & Privacy

- All four calls are broadcaster-only mutations/reads authorized by the cookie session
  (no bearer tokens stored). The client never persists credentials; it relies on the
  persistent cookie jar (AND-011). *(Note: the web reference client additionally sends
  `Authorization: Bearer <accessToken>` alongside the cookie — see
  `src/api/client.ts`. The Android port's cookie-only posture is a deliberate
  app-side decision inherited from the M2 auth milestone, not a property of the
  backend contract; the backend accepts the cookie session for these routes.)*
- Every mutating request (`PATCH`, `POST`) must carry the `X-CSRF-Token` header echoed
  from the `ui_csrf` cookie (AND-012). Verify the CSRF interceptor applies to the
  `broadcast/*` host calls and not only `/ui/*`.
- `user_sub` / `X-IMPERSONATION-TOKEN` are deliberately **not** sent from the app; only
  admin impersonation tooling would set them, which is out of scope.
- No PII is involved in ad config/break payloads. `session_id` is treated as
  non-sensitive but is not logged at INFO with surrounding user identifiers.
- Plaintext dev HTTP is acceptable only against the dev host; production base URL must
  be HTTPS (enforced by the host-selection interceptor AND-014 / build config).

## 9. Accessibility & i18n

- All interactive controls (pre-roll switch, numeric steppers, Trigger/End buttons)
  have `contentDescription` / semantics labels and a touch target ≥ 48dp.
- The active-break countdown uses `liveRegion = LiveRegionMode.Polite` so screen
  readers announce state changes (break started / N seconds remaining / break ended)
  without spamming every tick — announce on start, on end, and at coarse thresholds.
- Numeric fields announce valid ranges (15–60s duration, 5–30s skip) and validation
  errors via supporting text.
- All strings (labels, button text, error messages, "{n}s remaining", "{count} ad
  breaks") live in `strings.xml` with plurals for break counts; no hardcoded text.
  Durations formatted via locale-aware number formatting.

## 10. Telemetry & Logging

- Structured analytics events (existing app analytics facade): `ad_config_viewed`,
  `ad_config_saved {changed_fields}`, `ad_break_triggered {session_id_hash,
  duration_seconds}`, `ad_break_ended {manual: Boolean, elapsed_seconds}`.
- Log failures at WARN with the mapped `UiError.code` and HTTP status; never log full
  cookie/CSRF values or request/response bodies containing them. OkHttp logging
  interceptor (AND-009) remains at `BASIC`/`HEADERS` redacted level for these routes.
- Emit a single counter on auto-expiry vs. manual end to monitor how often hosts let
  breaks run to completion.

## 11. Testing Strategy

- **Unit (repository):** MockWebServer (AND-046 harness) fixtures for each endpoint —
  200 success, 422 validation, 401→refresh→retry, timeout. Assert PATCH body omits
  unchanged fields; assert GET goes through backoff and POSTs do not retry.
- **Unit (ViewModel):** with a fake `HostAdRepository` and a test dispatcher +
  controllable clock:
  - trigger flips `adBreakActive=true`, sets `remainingSeconds`, starts countdown;
  - countdown reaches 0 → active cleared + `refresh()` invoked;
  - `endAdBreak` clears active state and disables End button;
  - range validation: duration 14/61 and skip 4/31 set `*Valid=false` and disable Save;
  - mutation failure rolls back optimistic state and surfaces `error`.
- **Compose UI tests (AND-048/049 patterns):** Save disabled until dirty+valid; Trigger
  disabled while active/in-flight; End visible only while active; offline disables
  mutations; countdown chip renders.
- **Contract test (AND-047 style):** validate DTO (de)serialization against captured
  OpenAPI example payloads for `BroadcastAdConfigOut`, `AdBreakOut`, and a partial
  `BroadcastAdConfigIn`.

## 12. Dependencies & Sequencing

- **Depends on AND-309 (Host controls):** provides the host control panel host,
  `session_id` nav arg, host-area Hilt graph, and session-live signal. AND-316 cannot
  be exercised until a live session exists.
- **Transitively depends on** the network/auth infrastructure: AND-011 (cookie jar),
  AND-012 (CSRF), AND-013 (401 refresh), AND-015 (error mapping), AND-016 (GET
  backoff), AND-018 (`ApiResult`), AND-021 (state composables), AND-046/047 (test
  harness/contract patterns).
- **Blocks:** none recorded in the backlog. Viewer-side ad rendering, if added later,
  would consume the same `ad-config` read but is not tracked as a dependency here.
- **Sequencing within ticket:** DTOs → API → repository → ViewModel → UI section →
  tests. UI section is merged into the AND-309 panel last.

## 13. Risks & Open Questions

- **R1 — Live ad-break propagation to viewers is server-driven.** The host trigger only
  returns `AdBreakOut`. *Correction:* the backend DOES expose a server-driven channel —
  `GET /broadcast/sessions/{session_id}/stream` (SSE / `EventSource`), which publishes
  `ad_break:start` / `ad_break:end` events (plus `viewer_count` / `health_update` /
  `session_status`). The web reference (`src/hooks/useBroadcastStream.ts`) drives the
  broadcaster's *own* live ad-break state from this stream, not from a local timer. So a
  signal that a break started/ended is available; AND-316 chooses (per §6) to model
  host-side state locally rather than open a second SSE connection. *Open:* whether the
  host needs confirmation that viewers actually *entered* the break, or whether
  host-side state is sufficient for AND-316 — still unverified from the sources.
- **R2 — Server end signal exists via SSE, not a typed REST body.** *Correction to the
  prior draft:* there IS a server-side end event (`ad_break:end` on the SSE stream); the
  earlier claim of "no server end event for natural expiry" was inaccurate. This ticket
  deliberately infers expiry locally from `started_at + duration_seconds` (no SSE
  subscription in scope), so clock skew or a missed refresh could briefly mis-display
  state; mitigated by reconcile-on-expiry. *Open:* whether to subscribe to the AND-309
  SSE/health stream and consume `ad_break:end` instead of a local timer is a viable
  future refinement (would remove the round-trip and the skew window).
- **R3 — `ad-break/end` returns `{}` (no typed body).** We map to `Unit` and rely on a
  follow-up `GET ad-config` for truth. Acceptable but adds a round-trip.
- **R4 — Concurrent breaks / double-trigger** under flaky network: mitigated by
  disabling the trigger while in-flight and reconciling on error.
- **R5 — `user_sub`/impersonation headers** are intentionally unset; confirm no host
  flow requires them.

## 14. Acceptance Criteria

- AC-1. Opening the host Ads section loads current config and live state from
  `GET .../ad-config` and renders pre-roll, duration, skip-after, total breaks.
- AC-2. Editing duration/skip outside [15,60]/[5,30] disables Save and shows a
  field-level error; valid edits enable Save.
- AC-3. Saving sends a `PATCH` containing **only changed** fields and updates the UI
  from the returned `BroadcastAdConfigOut`.
- AC-4. With a live session and no active break, tapping **Trigger ad break** calls
  `POST .../ad-break`, and on success the UI shows `ad_break_active = true`, a running
  countdown derived from `started_at + duration_seconds`, the skip-after value, and an
  incremented total. **(Primary acceptance: "Ad break triggers.")**
- AC-5. While a break is active, **End early** calls `POST .../ad-break/end` and the UI
  returns to the non-active state.
- AC-6. When the countdown reaches zero with no manual end, the UI auto-clears active
  state and re-fetches config; `total_ad_breaks` reflects the completed break.
- AC-7. Mutations are not auto-retried; GET ad-config is retried with bounded backoff;
  401 triggers a single transparent refresh+retry.
- AC-8. Offline disables Trigger/End/Save and shows the offline state; reads show the
  last-known snapshot.
- AC-9. All new strings are localized; controls have accessibility semantics and the
  active countdown announces politely.

## 15. Definition of Done

- All Acceptance Criteria pass against the dev backend
  (`http://18.222.237.167:8000`) and against MockWebServer fixtures.
- `BroadcastAdConfigOut`, `BroadcastAdConfigIn`, `AdBreakOut` DTOs, `HostAdApi`,
  `HostAdRepository`/Impl, `HostAdViewModel`, and `AdControlSection` are implemented
  under `com.testlogon.android` in `feature-host` and wired into the AND-309 panel.
- Unit tests (repository + ViewModel), Compose UI tests, and the DTO contract test are
  added and green in CI (AND-050).
- `ktlint`/`detekt`/lint clean (AND-005); no hardcoded strings; no secrets/cookies
  logged.
- CSRF header confirmed on `broadcast/*` mutations; GET-only backoff confirmed.
- PR reviewed and merged to `android-port`; spec status moved from `draft` to `done`.

## 16. Citations & Assumption Audit

Each claim is listed with a VERDICT (Verified / Corrected / Unverified-assumption) and
an exact source pointer. OpenAPI pointers reference
`reference/openapi.index.txt` / `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend pointers reference `reference/src/...`.

1. **`GET /broadcast/sessions/{session_id}/ad-config` → 200 `BroadcastAdConfigOut`.**
   VERDICT: Verified. SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/ad-config`
   (op `get_ad_config_route_...`, resp `200:BroadcastAdConfigOut`);
   `src/api/endpoints/broadcast-ads.ts: getAdConfig`.
2. **`PATCH /broadcast/sessions/{session_id}/ad-config` body `BroadcastAdConfigIn` →
   200 `BroadcastAdConfigOut`.** VERDICT: Verified. SOURCE: OpenAPI
   `PATCH /broadcast/sessions/{session_id}/ad-config` (`req=BroadcastAdConfigIn`,
   `resp=200:BroadcastAdConfigOut`); `src/api/endpoints/broadcast-ads.ts: updateAdConfig`.
3. **`POST /broadcast/sessions/{session_id}/ad-break` (no request body) → 200
   `AdBreakOut`.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /broadcast/sessions/{session_id}/ad-break` (`req=` empty, `resp=200:AdBreakOut`);
   `src/api/endpoints/broadcast-ads.ts: triggerAdBreak`.
4. **`POST /broadcast/sessions/{session_id}/ad-break/end` (no body) → 200, body
   ignored / mapped to `Unit`.** VERDICT: Corrected. The OpenAPI 200 schema is `{}`
   (an **untyped** JSON schema, not literally an empty object); the web client types it
   `{ ok: boolean }`. SOURCE: OpenAPI
   `POST /broadcast/sessions/{session_id}/ad-break/end` (`responses.200.content.
   application/json.schema = {}`); `src/api/endpoints/broadcast-ads.ts: endAdBreak`.
5. **`BroadcastAdConfigOut` fields: `session_id` (str), `pre_roll_enabled` (bool),
   `mid_roll_ad_break_duration_seconds` (int), `mid_roll_skip_after_seconds` (int),
   `ad_break_active` (bool), `ad_break_started_at` (int|null), `total_ad_breaks`
   (int).** VERDICT: Verified — names, types, and the nullable-only-on-`ad_break_started_at`
   shape all match; `required` = all except `ad_break_started_at`. SOURCE:
   `components.schemas.BroadcastAdConfigOut`; `src/api/endpoints/broadcast-ads.ts:
   BroadcastAdConfig`.
6. **`BroadcastAdConfigIn` fields all optional/nullable: `pre_roll_enabled`,
   `mid_roll_ad_break_duration_seconds`, `mid_roll_skip_after_seconds`.** VERDICT:
   Verified — every property is `anyOf [T, null]` with no `required` block, confirming
   true partial-update semantics. SOURCE: `components.schemas.BroadcastAdConfigIn`;
   `src/api/endpoints/broadcast-ads.ts: BroadcastAdConfigUpdate`.
7. **Server range constraints: duration ∈ [15,60], skip-after ∈ [5,30].** VERDICT:
   Verified — `mid_roll_ad_break_duration_seconds` `minimum:15 maximum:60`,
   `mid_roll_skip_after_seconds` `minimum:5 maximum:30`. SOURCE:
   `components.schemas.BroadcastAdConfigIn`.
8. **`AdBreakOut` fields: `ok` (bool, default true), `duration_seconds` (int),
   `started_at` (int), `skip_after_seconds` (int).** VERDICT: Verified — `ok` has
   `default: true` and is NOT in `required`; the other three are required integers.
   SOURCE: `components.schemas.AdBreakOut`; `src/api/endpoints/broadcast-ads.ts:
   AdBreakResponse`.
9. **Timestamps (`ad_break_started_at`, `started_at`) are epoch integers.** VERDICT:
   Verified as integer type (OpenAPI shows `type: integer`); the **seconds-vs-millis**
   interpretation is an assumption — see Open assumptions. SOURCE:
   `components.schemas.BroadcastAdConfigOut`, `components.schemas.AdBreakOut`.
10. **CSRF: every request carries `X-CSRF-Token` echoed from the `ui_csrf` cookie, and
    this applies to `broadcast/*` routes (not only `/ui/*`).** VERDICT: Verified — the
    web client sets the header unconditionally for all paths. SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`
    in the shared `api()` wrapper used by all endpoints).
11. **401 handling: a single transparent refresh via `POST /ui/session/refresh` then one
    retry; a second 401 logs out / surfaces session-expired.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`refreshSession()` posts `/ui/session/refresh`;
    single-flight `refreshPromise`; retry once; on retry 401 → `logout("session_expired")`).
12. **Trigger button enabled only when session live AND no active break AND no request in
    flight.** VERDICT: Verified — web disables on `!isLive || adBreakActive ||
    mutation.isPending`. SOURCE: `src/pages/broadcast/AdBreakButton.tsx` (`const disabled
    = !isLive || adBreakActive || mutation.isPending`).
13. **Optional backend params `user_sub` (query), `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`
    (headers) exist on all four routes and are not required.** VERDICT: Verified — listed
    as `params=session_id,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` and all marked
    `required: false` in the path spec. SOURCE: OpenAPI index lines for the four
    `ad-config`/`ad-break` routes; path object for `.../ad-break/end`.
14. **Error body is FastAPI `{"detail": ...}` where `detail` may be a string, a `422`
    array of `{msg, loc}`, or an object with a `code`.** VERDICT: Verified — `422` uses
    `HTTPValidationError` (array of `ValidationError` with `msg`/`loc`); the web error
    normalizer handles string, `[{msg}]`, and `{code}` object forms. SOURCE: OpenAPI
    `responses.422` = `HTTPValidationError` on all four routes;
    `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`.
15. **Server-driven ad-break propagation exists via SSE
    `GET /broadcast/sessions/{session_id}/stream` with `ad_break:start` /
    `ad_break:end` events.** VERDICT: Corrected (the prior draft asserted no server end
    signal). SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/stream`
    (op `broadcast_event_stream_route_...`); `src/hooks/useBroadcastStream.ts`
    (`EventSource(".../stream")`, `addEventListener("ad_break:start"|"ad_break:end")`).
16. **Web reference also sends `Authorization: Bearer <accessToken>` alongside the
    cookie.** VERDICT: Corrected/clarified the §8 "cookie-only, no bearer" framing as an
    app-side choice, not a backend constraint. SOURCE: `src/api/client.ts`
    (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
17. **DTO/Retrofit choices (Moshi `@JsonClass`, omit-null serialization for partial
    PATCH, Retrofit `@PATCH`/`@POST`/`@GET`, Hilt `SingletonComponent`).** VERDICT:
    Unverified-assumption (framework ref). These are standard Android patterns, not
    derivable from the backend/frontend sources. Framework refs:
    Moshi `https://github.com/square/moshi`, Retrofit `https://square.github.io/retrofit/`,
    Hilt `https://developer.android.com/training/dependency-injection/hilt-android`,
    Compose `https://developer.android.com/jetpack/compose`.
18. **Accessibility approach (`liveRegion = LiveRegionMode.Polite`, ≥48dp targets,
    `contentDescription`).** VERDICT: Unverified-assumption (framework ref). SOURCE:
    `https://developer.android.com/jetpack/compose/accessibility`.

### Corrections made

- **§5** `ad-break/end` response: changed "→ `200 {}` (empty object)" to clarify the
  OpenAPI schema is an *untyped* `{}` and the web client types it `{ ok: boolean }`;
  body is non-load-bearing and mapped to `Unit`.
- **§13 R1/R2**: corrected the assertion that there is "no server end event for natural
  expiry." A server-driven SSE stream (`.../stream`) emits `ad_break:start` /
  `ad_break:end`; the web client drives broadcaster ad-break state from it. Reframed the
  local-timer design as a deliberate scope choice rather than a workaround for a missing
  server capability, and noted the SSE route as a future refinement.
- **§8**: noted that the web client sends `Authorization: Bearer` in addition to the
  cookie; the Android cookie-only posture is an app-side decision, not a backend
  contract property.
- All other concrete API/DTO/auth claims in the draft were checked and found accurate;
  no further edits required.

### Open assumptions

- **Timestamp units (seconds vs. milliseconds).** OpenAPI/frontend only declare
  `integer`; nothing in the sources fixes the unit. The spec assumes **epoch seconds**.
  The example `started_at: 1749081600` (~2025-06-05) is consistent with seconds, but
  this should be confirmed against the dev backend before relying on the countdown math.
- **Whether `POST ad-break` returns a conflict when a break is already active** (§7
  "race — break already active"). No `409`/conflict response is declared in OpenAPI
  (only `200`/`422`); the handling is defensive and unverified — confirm against the dev
  host.
- **Whether the host needs viewer-entered-break confirmation** (R1). Not derivable from
  the sources; product/backend confirmation needed.
- **`total_ad_breaks` increment timing** (on trigger vs. on completion). The countdown
  reconcile (FR-5/AC-6) assumes the server increments it; the exact moment is not
  specified by the sources — confirm against the dev backend.
- **All Android framework/library choices** (Moshi/Retrofit/Hilt/Compose, AND-0xx
  infra tickets AND-011..AND-021/046/047) are project conventions, not verifiable from
  the backend or web reference; accepted as-is per the dependency milestones.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35) for fast UI/instrumented CI suites;
**A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, API 34,
arm64-v8a) for real-hardware behavior. This ticket has **no** camera / biometrics /
WebRTC / push / Telecom surface, so most cases run on JVM or emu35; only the
ABI/API-parity smoke (TC-13) and the real-network flaky-host case (TC-12) call for the
physical device.

- **TC-AND-316-01 — Load config happy path (GET).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200 BroadcastAdConfigOut` ( `ad_break_active=false`, `total_ad_breaks=2`).
  Steps: open the Ads section / call `repo.getAdConfig(sessionId)`. Expected: request is
  `GET /broadcast/sessions/{sessionId}/ad-config`; DTO deserializes with all 7 fields;
  state renders pre-roll, duration, skip-after, total=2; not active. Traces: AC-1.
- **TC-AND-316-02 — DTO (de)serialization contract.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: captured OpenAPI example
  payloads for `BroadcastAdConfigOut`, `AdBreakOut`, and a partial `BroadcastAdConfigIn`
  (`{pre_roll_enabled, mid_roll_ad_break_duration_seconds}` only). Steps: round-trip each
  through Moshi. Expected: field names map per `@Json`; `ad_break_started_at=null`
  tolerated; `AdBreakOut.ok` defaults true when absent; serializing the partial
  `BroadcastAdConfigIn` **omits** the unset `mid_roll_skip_after_seconds` key entirely.
  Traces: AC-3.
- **TC-AND-316-03 — PATCH sends only changed fields.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: loaded config; user toggles
  pre-roll and changes duration to 45, leaves skip-after untouched; MockWebServer returns
  `200 BroadcastAdConfigOut`. Steps: `saveConfig()`. Expected: recorded request is
  `PATCH .../ad-config` whose JSON body contains exactly `pre_roll_enabled` and
  `mid_roll_ad_break_duration_seconds` (no `mid_roll_skip_after_seconds`); UI updates from
  the returned body. Traces: AC-3.
- **TC-AND-316-04 — Range validation disables Save.**
  Type: unit (ViewModel). Target: JVM. Preconditions: loaded config. Steps: set duration
  to 14 then 61; set skip-after to 4 then 31; then set valid values (30 / 5). Expected:
  out-of-range values set `durationValid=false` / `skipValid=false` and Save disabled
  with field-level error; valid values enable Save; no network call occurs for invalid
  input. Traces: AC-2.
- **TC-AND-316-05 — Trigger ad break happy path.**
  Type: unit (ViewModel) + contract/MockWebServer. Target: JVM. Preconditions: session
  live, no active break; MockWebServer returns `200 AdBreakOut {ok:true,
  duration_seconds:30, started_at:<now>, skip_after_seconds:5}`. Steps: `triggerAdBreak()`.
  Expected: request `POST .../ad-break` (no body); state flips `adBreakActive=true`,
  `remainingSeconds≈30` derived from `started_at + duration_seconds`, skip-after=5,
  countdown coroutine running, total incremented after reconcile. Traces: AC-4.
- **TC-AND-316-06 — Countdown auto-expiry reconciles.**
  Type: unit (ViewModel). Target: JVM (virtual-time test dispatcher + controllable clock).
  Preconditions: active break with duration 30; a refresh `GET` is stubbed to return
  `ad_break_active=false, total_ad_breaks=3`. Steps: advance virtual clock past
  `started_at + 30s`. Expected: at 0 the VM clears `adBreakActive`, invokes `refresh()`,
  and `total_ad_breaks` updates to 3 from the server response (not trusted to local timer
  alone). Traces: AC-6.
- **TC-AND-316-07 — End ad break early.**
  Type: unit (ViewModel) + contract/MockWebServer. Target: JVM. Preconditions: active
  break; `POST .../ad-break/end` returns `200` (body ignored); follow-up `GET` returns
  inactive. Steps: `endAdBreak()`. Expected: request `POST .../ad-break/end`; response
  body deserializes to `Unit` without error even if body is `{}` or `{"ok":true}`; state
  returns to non-active; End button hidden; reconcile GET fired. Traces: AC-5.
- **TC-AND-316-08 — 422 validation mapping.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: force an out-of-range PATCH to
  the server (bypassing client guard); MockWebServer returns `422 HTTPValidationError`
  with `detail:[{"msg":"ensure this value is less than or equal to 60","loc":["body",
  "mid_roll_ad_break_duration_seconds"]}]`. Steps: `saveConfig()`. Expected: `ApiErrorMapper`
  produces a `UiError` whose message/loc maps to the duration field's supporting text;
  optimistic change rolled back. Traces: AC-2, AC-3.
- **TC-AND-316-09 — 401 single refresh + retry on GET.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: GET returns `401` once, then
  the refresh endpoint `200`, then GET `200`. Steps: `getAdConfig()`. Expected: exactly one
  `POST /ui/session/refresh` then a single GET retry that succeeds; a second consecutive
  `401` instead surfaces a session-expired error (no infinite loop). Traces: AC-7.
- **TC-AND-316-10 — Mutations not retried; GET uses backoff.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: PATCH returns a transient
  `503`; separately GET returns `503` twice then `200`. Steps: `saveConfig()` then
  `getAdConfig()`. Expected: PATCH makes exactly **one** attempt and surfaces the error
  with optimistic rollback (no auto-retry); GET retries with bounded jittered backoff
  (≤3 attempts) and ultimately succeeds. Traces: AC-7.
- **TC-AND-316-11 — Compose UI gating & a11y.**
  Type: Compose-UI. Target: emu35. Preconditions: render `AdControlSection` with seeded
  states. Steps/Expected: (a) Save disabled until `dirty && durationValid && skipValid`;
  (b) Trigger disabled while `adBreakActive` or `mutationInFlight`; (c) End visible only
  while active; (d) active countdown chip renders and exposes `liveRegion=Polite`
  semantics; (e) all controls have non-empty `contentDescription` and ≥48dp touch
  targets; (f) no hardcoded strings (assert via resource lookups). Traces: AC-2, AC-4,
  AC-5, AC-9.
- **TC-AND-316-12 — Flaky dev-host / offline path.**
  Type: integration. Target: **A15 (physical device — must run here)**. Preconditions:
  app pointed at the plaintext dev host `http://18.222.237.167:8000`; toggle device
  Wi-Fi/airplane mode and induce slow/lost responses on real radio. Steps: load Ads
  section while offline, then trigger/save while offline, then restore connectivity.
  Expected: offline banner shown; Trigger/End/Save disabled while offline; last-loaded
  snapshot still readable; ~20s timeout honored on a stalled GET then AND-021 error/retry
  state; on reconnect a retry succeeds. Rationale for physical device: real cellular/Wi-Fi
  transitions and the unreliable plaintext host exercise timeout/offline behavior an
  emulator's synthetic network cannot faithfully reproduce. Traces: AC-7, AC-8.
- **TC-AND-316-13 — ABI / API-parity smoke.**
  Type: instrumented/e2e. Target: **A15 (arm64-v8a, API 34)** vs **emu35 (x86_64, API
  35)**. Preconditions: built APK installable on both. Steps: run the core flow
  (load → save → trigger → countdown → end) on each. Expected: identical behavior and DTO
  parsing across ABI and API level; no Moshi/codegen or API-34-vs-35 divergence.
  Rationale for physical device: only arm64/API-34 hardware surfaces ABI- or
  platform-version-specific regressions. Traces: AC-1, AC-3, AC-4, AC-5, AC-6.
- **TC-AND-316-14 — CSRF header present on broadcast mutations (security).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: cookie jar seeded with a
  `ui_csrf` cookie; CSRF interceptor (AND-012) installed. Steps: perform `PATCH .../ad-config`,
  `POST .../ad-break`, `POST .../ad-break/end`. Expected: every recorded mutating request
  carries `X-CSRF-Token` equal to the `ui_csrf` value, applied to `broadcast/*` (not just
  `/ui/*`); GET need not be asserted but must not fail for lacking it; no cookie/CSRF
  value appears in logcat at the configured log level. Traces: AC-7 (auth/transport),
  §8 security.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (load config & state on entry) | TC-01, TC-13 |
| AC-2 (range validation gates Save) | TC-04, TC-08, TC-11 |
| AC-3 (PATCH only changed fields; UI updates) | TC-02, TC-03, TC-08, TC-13 |
| AC-4 (trigger → active + countdown + total) | TC-05, TC-11, TC-13 |
| AC-5 (End early → non-active) | TC-07, TC-11, TC-13 |
| AC-6 (auto-expiry clears + refetch) | TC-06, TC-13 |
| AC-7 (no mutation retry; GET backoff; 401 single refresh) | TC-09, TC-10, TC-12, TC-14 |
| AC-8 (offline disables actions; last-known snapshot) | TC-12 |
| AC-9 (localized strings; a11y; polite countdown) | TC-11 |
