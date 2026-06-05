---
id: AND-316
title: Ad breaks / ad config
milestone: M7
epic: E41
priority: P2
size: M
status: draft
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

**POST `/broadcast/sessions/{session_id}/ad-break/end`** (no body) → `200 {}`
(empty object; mapped to `Unit`).

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
  persistent cookie jar (AND-011).
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
  returns `AdBreakOut`; how viewers learn a break started (push/WS/poll) is not in this
  ticket. Risk: "ad break triggers" acceptance is host-observable only. *Open:* confirm
  whether the host needs any signal that viewers actually entered the break, or whether
  host-side state is sufficient for AND-316.
- **R2 — No server "end" event for natural expiry.** The client infers expiry from
  `started_at + duration`. Clock skew or a missed refresh could briefly mis-display
  state. Mitigated by reconcile-on-expiry; *open:* is there a polling cadence the host
  panel already runs (from AND-309 health) we can piggyback on instead of a local timer?
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
