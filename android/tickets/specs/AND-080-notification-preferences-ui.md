---
id: AND-080
title: Notification preferences UI
milestone: M2
epic: E11
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-078, AND-088]
blocks: []
---

# AND-080 — Notification preferences UI

## 1. Overview & Goal

This ticket delivers the **Notification preferences UI**: a Jetpack Compose screen
that surfaces per-category notification toggles across three delivery channels —
**push**, **email**, and **SMS** — and persists user changes to the backend through
the preferences repository introduced in AND-078.

The user lands on a single scrollable screen grouped by notification *category*
(for example `security_alerts`, `account_activity`, `product_updates`,
`billing`, `marketing`). Each category exposes up to three channel switches.
Toggling a switch optimistically updates the UI and issues a debounced
write to the preferences repository. (NOTE — corrected during review: the path
`/ui/preferences/notifications` does **not** exist in the backend OpenAPI. The
nearest matching endpoint is `POST /ui/alerts/type-preferences` with schema
`AlertTypePreferenceUpdate`; see §5 and §16.) The screen reflects loading, saved,
saving, error, and offline/stale states, and survives configuration changes and
process death.

Goal: a production-ready, accessible, testable screen whose acceptance gate is
**"Changes persist (tested)"** — verified by instrumented and unit tests that
prove a toggle round-trips through the repository to the API and re-hydrates
correctly on reload.

Scope boundary: this ticket owns the **standalone notification-preferences screen
and its ViewModel** in `feature-settings`. It does **not** own the unified alert
preferences screen (AND-088, epic E12) nor the preferences API/DTO/repository
layer (AND-078, epic E11). It consumes both.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. New code lives in `feature-settings` and consumes
  `core-data`, `core-model`, `core-network`, `core-ui`.
- **Namespace:** `com.testlogon.android` everywhere a package appears.
  Screen package: `com.testlogon.android.feature.settings.notifications`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15,
  DataStore (last-known-good cache), minSdk 24 / target 35, JDK 17.
- **Upstream dependency AND-078 (Preferences API + DTOs):** provides
  `PreferencesApi` (Retrofit), `NotificationPrefsDto`, the `preferences.ts`-mirrored
  endpoint set, and `NotificationPreferencesRepository` exposing typed
  `ApiResult<T>` flows. This ticket binds to that repository and **must not**
  re-implement networking.
- **Upstream dependency AND-088 (Alert preferences screen):** owns the *unified*
  channels+categories UI and shared composable building blocks. AND-080 reuses the
  shared row composable (`PreferenceChannelRow`) and category-grouping model from
  AND-088 where available; if AND-088 lands after this ticket, AND-080 ships a
  local copy of the row composable behind the same signature and is refactored to
  the shared one in a follow-up.
- **Auth/transport:** session credentials + `X-CSRF-Token` echo and single
  `POST /ui/session/refresh` retry on 401 — all handled by the OkHttp
  interceptor stack from `core-network`; this screen issues no auth logic itself.
  (Corrected during review: the web reference client is **not** cookie-only — its
  `api()` wrapper additionally sends `Authorization: Bearer <accessToken>` from the
  auth store and an optional `X-IMPERSONATION-TOKEN`, alongside `credentials:
  "include"` cookies; `X-CSRF-Token` is read from the `ui_csrf` cookie and sent on
  **every** request, not only writes. The exact Android auth scheme is owned by
  core-network/AND-078; see §16. `POST /ui/session/refresh` and the single-retry
  behavior are verified against `src/api/client.ts`.)
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. FastAPI `detail` error
  shape (`string | [{msg}] | {code,...}`) is mapped to `ApiResult.Error` in
  `core-network` and surfaced here as user-facing strings.

## 3. Functional Requirements

FR-1. The screen renders a list of notification **categories** returned by the
backend, each with a localized title and optional description.

FR-2. Each category exposes up to three **channel switches** (push / email / SMS).
A channel is rendered only if the backend marks it `available` for that category;
unavailable channels are omitted (not shown disabled).

FR-3. Toggling any switch updates the on-screen state **optimistically and
immediately**, then schedules a persisted write.

FR-4. Writes are **debounced** (default 600 ms) and **coalesced**: rapid toggles
on the same category collapse into one `PATCH` carrying the latest desired state.

FR-5. On a successful write the row shows a transient "Saved" affordance
(no blocking dialog). On failure the toggle **rolls back** to the last persisted
value and an inline error + Retry is shown.

FR-6. A global **master push switch** (mirroring OS-level notification permission
state on API 33+) gates per-category push switches: when push is OFF at OS level,
push columns render disabled with a "Turn on in system settings" inline action
that deep-links to app notification settings. Email/SMS are unaffected.

FR-7. The screen supports **pull-to-refresh** to re-fetch canonical preferences,
and shows a **stale banner** when displaying cached values after a load failure.

FR-8. State survives rotation and process death; in-flight optimistic edits that
have not yet been confirmed are restored from `SavedStateHandle` and re-attempted.

FR-9. Empty state (no categories returned) renders an explanatory message rather
than a blank screen.

## 4. Technical Design

Single-Activity Navigation-Compose. Route added to the settings nav graph.

```kotlin
// com.testlogon.android.feature.settings.notifications

const val NOTIFICATION_PREFS_ROUTE = "settings/notifications"

fun NavGraphBuilder.notificationPreferencesScreen(onNavigateUp: () -> Unit) {
    composable(NOTIFICATION_PREFS_ROUTE) {
        NotificationPreferencesRoute(onNavigateUp = onNavigateUp)
    }
}
```

UiState is a sealed hierarchy exposed as `StateFlow<NotificationPrefsUiState>`:

```kotlin
data class ChannelToggle(
    val channel: NotificationChannel,   // PUSH, EMAIL, SMS
    val enabled: Boolean,
    val available: Boolean,
    val saving: Boolean = false,
    val osBlocked: Boolean = false,     // push only, API 33+ permission off
)

data class CategoryPrefUi(
    val id: String,                     // e.g. "security_alerts"
    val title: String,
    val description: String?,
    val channels: List<ChannelToggle>,
)

sealed interface NotificationPrefsUiState {
    data object Loading : NotificationPrefsUiState
    data class Ready(
        val categories: List<CategoryPrefUi>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,          // showing cached after load failure
        val transientError: String? = null,    // inline, dismissible
    ) : NotificationPrefsUiState
    data class Error(val message: String) : NotificationPrefsUiState   // hard load failure, no cache
    data object Empty : NotificationPrefsUiState
}
```

ViewModel (Hilt, `@HiltViewModel`):

```kotlin
@HiltViewModel
class NotificationPreferencesViewModel @Inject constructor(
    private val repository: NotificationPreferencesRepository,   // from AND-078
    private val notificationPermission: NotificationPermissionMonitor, // OS push state
    private val savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<NotificationPrefsUiState>

    fun onToggle(categoryId: String, channel: NotificationChannel, enabled: Boolean)
    fun onRefresh()
    fun onRetrySave(categoryId: String)
    fun onDismissError()
    fun onOpenSystemNotificationSettings()   // emits a one-shot nav/intent event
}
```

Internal pipeline:
- A `MutableStateFlow<Map<String, CategoryPrefUi>>` holds the working model.
- `onToggle` mutates the working model optimistically, marks the affected
  `ChannelToggle.saving = true`, and pushes a `(categoryId)` key into a
  `MutableSharedFlow<String>` debounce channel.
- A `viewModelScope` collector applies `.debounce(600).groupedBy(categoryId)`
  semantics — implemented as a per-category `mapLatest` over a flow keyed by
  category — to coalesce writes and cancel superseded ones.
- Each persisted write calls `repository.updateNotificationPrefs(patch)` and
  reconciles the returned canonical DTO back into the working model; on
  `ApiResult.Error` it reverts the toggle and sets `transientError`.

Debounce/coalesce helper:

```kotlin
private val pendingSaves = MutableSharedFlow<String>(extraBufferCapacity = 64)

init {
    pendingSaves
        .groupBy { it }                       // per-category stream
        .flatMapMerge { byCat ->
            byCat.debounce(DEBOUNCE_MS).mapLatest { categoryId -> save(categoryId) }
        }
        .launchIn(viewModelScope)
}
```

Compose layer is stateless and hoists everything from `uiState`:

```kotlin
@Composable
fun NotificationPreferencesScreen(
    state: NotificationPrefsUiState,
    onToggle: (String, NotificationChannel, Boolean) -> Unit,
    onRefresh: () -> Unit,
    onRetrySave: (String) -> Unit,
    onDismissError: () -> Unit,
    onOpenSystemSettings: () -> Unit,
    onNavigateUp: () -> Unit,
)
```

The list uses `LazyColumn` with `items(categories, key = { it.id })`. Each category
is a Material 3 `Card` containing a header and a row of channel switches built from
`PreferenceChannelRow` (shared with AND-088). Pull-to-refresh uses the Material 3
`PullToRefreshBox`.

The `NotificationPermissionMonitor` reads `POST_NOTIFICATIONS` grant state
(API 33+) and `NotificationManagerCompat.areNotificationsEnabled()` and exposes a
`StateFlow<Boolean>` that re-checks on `ON_RESUME`. `onOpenSystemNotificationSettings`
fires `Settings.ACTION_APP_NOTIFICATION_SETTINGS` (API 26+) via a one-shot event.

## 5. API Contract

This screen does not call Retrofit directly; it consumes
`NotificationPreferencesRepository` (AND-078). AND-078 owns the DTOs and exact
(de)serialization. Shapes below are the contract this UI relies on.

> **REVIEW CORRECTION (authoritative).** The originally-specified path
> `/ui/preferences/notifications` (GET/PATCH) does **not** exist in the backend
> OpenAPI, and web `preferences.ts` does **not** expose notification-channel
> toggles — it calls `GET`/`PATCH /ui/settings/preferences` (`PreferencesPatchReq`),
> which carries only UI theme/density prefs (accent_color, font_size, …), not
> push/email/SMS. The backend endpoint that actually models per-type
> push/email/SMS booleans is:
>
> - **`GET /ui/alerts/type-preferences`** (`op=get_type_preferences…`) — response
>   schema is **untyped** in OpenAPI (`200: {}`), so the GET response shape is an
>   **unverified assumption** and must be confirmed with AND-078 / backend.
> - **`POST /ui/alerts/type-preferences`** (`op=update_type_preferences…`,
>   req=`AlertTypePreferenceUpdate`) — **POST, not PATCH**; **one alert type per
>   call**; response `200: {}` (untyped).
>
> The verified `AlertTypePreferenceUpdate` request shape is:
> `{ "alert_type": string (required, 1–64 chars), "enabled"?: bool|null,
> "push"?: bool|null, "email"?: bool|null, "sms"?: bool|null, "in_app"?: bool|null }`.
> Note the key is **`alert_type`** (not `category_id`), channels are **flat
> top-level booleans** (not a nested `channels` object), there is an extra
> **`in_app`** channel and an **`enabled`** master flag, and there is **no
> `available` field** anywhere in the schema — per-channel availability (FR-2)
> is NOT backend-expressed and is an unverified assumption (see OQ-2, §16).
>
> Note also the web client (`src/api/endpoints/alerts.ts`) does not call
> `type-preferences` at all; it uses separate per-channel endpoints
> (`POST /ui/alerts/email_prefs`, `/sms_prefs`, `/toast_prefs`, `/webhook_prefs`)
> that take **event-type string arrays**, not booleans. The example JSON below is
> retained as the *desired UI-facing contract* AND-078 must adapt to/from, but it
> is **not** a verbatim backend shape. Reconcile via OQ-1 before implementation.

**GET notification preferences** (illustrative UI-facing shape; backend source is
`GET /ui/alerts/type-preferences`, response schema untyped/unverified).

Response `200`:
```json
{
  "categories": [
    {
      "id": "security_alerts",
      "title": "Security alerts",
      "description": "Sign-ins, password and MFA changes",
      "channels": [
        { "channel": "push",  "enabled": true,  "available": true },
        { "channel": "email", "enabled": true,  "available": true },
        { "channel": "sms",   "enabled": false, "available": true }
      ]
    }
  ]
}
```

**Write — `POST /ui/alerts/type-preferences`** — update one alert type's channels.
(Corrected: was specified as `PATCH /ui/preferences/notifications`; the real
verb is **POST** and the path is `/ui/alerts/type-preferences`.) Treated as a
non-idempotent write (no auto-retry).

Verified backend request body (`AlertTypePreferenceUpdate`):
```json
{
  "alert_type": "security_alerts",
  "push": true,
  "email": true,
  "sms": false,
  "in_app": true,
  "enabled": true
}
```
Note: flat channel booleans, key `alert_type`, optional `in_app` + `enabled`.
The UI-facing `{ "category_id", "channels": {…} }` shape below is what AND-078's
repository should accept; AND-078 is responsible for mapping it onto
`AlertTypePreferenceUpdate`.

UI-facing request (repository input — AND-078 maps to backend):
```json
{
  "category_id": "security_alerts",
  "channels": { "push": true, "email": true, "sms": false }
}
```

Response `200` — **unverified.** The backend OpenAPI declares `200: {}` (untyped)
for `POST /ui/alerts/type-preferences`, so the "canonical category" reconciliation
response below is an **unverified assumption** and must be confirmed (OQ-1). If the
backend returns no usable body, reconciliation must instead re-`GET` preferences:
```json
{
  "category": {
    "id": "security_alerts",
    "channels": [
      { "channel": "push",  "enabled": true,  "available": true },
      { "channel": "email", "enabled": true,  "available": true },
      { "channel": "sms",   "enabled": false, "available": true }
    ]
  }
}
```

Headers: session credentials + `X-CSRF-Token` (read from the `ui_csrf` cookie)
applied by the `core-network` interceptor. (Corrected: per `src/api/client.ts` the
web client sets `X-CSRF-Token` on **every** request, not only writes — and also
sends `Authorization: Bearer` + cookies. The header presence on the write is the
load-bearing assertion for AC-3.)

Error responses use FastAPI `detail`. The three `detail` shapes are **verified**
against `src/api/client.ts: normalizeErrorDetail` (string | array-of-`{msg}` |
object-with-`code`) and `HTTPValidationError`/`ValidationError` in OpenAPI
(422 bodies are `{detail:[{loc, msg, type}]}`):
```json
{ "detail": "Notification category not found" }
{ "detail": [ { "loc": ["body","channels","sms"], "msg": "channel unavailable" } ] }
{ "detail": { "code": "preference_locked", "message": "Managed by org policy" } }
```
The object-with-`code` shape is real (the web client maps codes like
`role_required`, `role_required_scope`, `geo_blocked` in `mapAuthorizationError`),
but the specific code **`preference_locked` is an unverified assumption** — it does
not appear in the reference sources (see §16). These map to
`ApiResult.Error(message, code?)`; a `403` org-policy lock (if it exists) is
surfaced as a non-retryable inline message and the toggle reverts. Some `alerts`
endpoints in OpenAPI also wrap errors in `ErrorEnvelope` (`{error:{...}}`); AND-078
must normalize both shapes.

Because the real path/verb differs from this spec's original assumption, the
repository contract (function names + DTO types) is authoritative and this UI is
insulated from the exact path — see Open Question OQ-1 and §16.

## 6. Data & State Management

- **Source of truth:** backend, fetched on screen entry via the repository.
- **Cache:** repository (AND-078) caches the last successful preferences GET
  (backend `GET /ui/alerts/type-preferences`) in DataStore as JSON (last-known-good).
  This screen reads cache to populate `Ready(isStale = true)` when a live fetch
  fails but cache exists.
- **In-memory working model:** `MutableStateFlow<Map<String, CategoryPrefUi>>`
  in the ViewModel; the public `uiState` is derived via `map { ... }.stateIn(...)`.
- **Optimistic edits:** applied immediately to the working model; the pending
  desired-state per category is held so a debounced save sends the latest value.
- **Process death:** unconfirmed optimistic edits are serialized to
  `SavedStateHandle` under key `pending_edits` (a `Map<String, Map<String,Boolean>>`)
  and replayed through the save pipeline on restore.
- **Reconciliation:** every successful `PATCH` response replaces the working
  category with the server's canonical version, eliminating drift.
- **Threading:** all writes on `viewModelScope` with `Dispatchers.Default` for the
  debounce/merge; repository hops to IO internally.

## 7. Error Handling & Resilience

- **Initial load failure, cache present:** render `Ready(isStale = true)` with a
  dismissible stale banner ("Showing saved settings — couldn't reach server").
- **Initial load failure, no cache:** render `Error(message)` with full-screen
  Retry. Use the mapped `detail` string; fall back to a generic copy on network
  exceptions.
- **Toggle save failure:** revert the optimistic value, clear `saving`, set
  `transientError`, and show inline Retry for that category via `onRetrySave`.
- **Timeouts:** GET uses the `core-network` ~20s timeout with bounded backoff
  retry (idempotent GET only). `PATCH` writes are **not** auto-retried — only the
  explicit user Retry re-issues them, to avoid duplicate/racey writes.
- **401:** handled transparently by the interceptor's single
  `POST /ui/session/refresh` + retry; if refresh fails the screen receives an
  `ApiResult.Error` and treats it as a save/load failure (no auth UI here).
- **Offline:** detected via `ApiResult.Error` (IOException class); messaging
  emphasizes connectivity and offers Retry.
- **No partial-success ambiguity:** because each `PATCH` is per-category and the
  response is reconciled, a failed write never leaves a half-applied category.

## 8. Security & Privacy

- No credentials or PII are stored by this screen. Toggle state is non-sensitive
  preference data; the DataStore cache (owned by AND-078) holds only category ids
  and booleans — no contact endpoints (phone/email addresses) are cached here.
- All writes carry the `X-CSRF-Token` header (CSRF mandatory on `PATCH`);
  this is enforced by the `core-network` interceptor, not bypassable from the UI.
- The screen never logs preference values or category contents at info level
  (see §10) to avoid leaking behavioral data.
- Plaintext HTTP to the dev host is a known dev-only posture; production builds
  must target HTTPS. No secrets are embedded in this module.
- Deep-link to system notification settings uses only the app's own package; no
  cross-app data exposure.

## 9. Accessibility & i18n

- Every switch has a `Modifier.semantics` with a `contentDescription` that
  includes category + channel ("Security alerts, push notifications"),
  `role = Switch`, and announces on/off via `toggleableState`.
- Saving and error states announce via `liveRegion = Assertive` for errors and
  `Polite` for "Saved".
- Touch targets ≥ 48dp; switches and the system-settings inline action meet this.
- Full TalkBack pass: list is navigable, headers are `heading()` semantics, and
  the stale banner is announced once on appearance.
- Supports dynamic font scaling and dark theme via Material 3 `core-ui` theme.
- All strings (category fallbacks, banners, errors, Retry, "Turn on in system
  settings") live in `strings.xml`; backend-provided titles/descriptions are shown
  verbatim and are the backend's localization responsibility.
- RTL-safe layouts (use start/end, not left/right).

## 10. Telemetry & Logging

Events emitted through the shared analytics interface (`core-data` Analytics):

- `notif_prefs_viewed` — on first `Ready`/`Empty`.
- `notif_prefs_toggled` — props `{ category_id, channel, enabled }`
  (category_id and channel are non-PII identifiers; **no** contact values).
- `notif_prefs_save_result` — props `{ category_id, channel, success, error_code? }`.
- `notif_prefs_refreshed` — props `{ stale: Boolean }`.
- `notif_prefs_os_blocked_push` — when a push toggle is blocked by OS permission.

Logging: `Timber` tags `NotifPrefsVM`. Debug-level logs may include category ids;
**never** log full preference payloads or any contact endpoint. Save failures log
the mapped error code/message at warn level. No PII in any log line.

## 11. Testing Strategy

The acceptance bar is **"Changes persist (tested)"** — the following make that
testable and enforced in CI.

**Unit (ViewModel, `core-testing` + Turbine + fake repository):**
- `onToggle` produces an immediate optimistic state change (assert via Turbine).
- Debounce coalescing: three rapid toggles on one category yield exactly **one**
  `repository.updateNotificationPrefs` call carrying the final value
  (verify with a recording fake + virtual time `TestDispatcher`).
- Save success reconciles canonical server state into `uiState`.
- Save failure reverts the toggle and sets `transientError`; `onRetrySave`
  re-issues the write.
- Load failure with cache → `Ready(isStale = true)`; without cache → `Error`.
- `SavedStateHandle` restore replays a pending edit through the save pipeline.
- OS push blocked: push toggles render `osBlocked = true`, email/SMS unaffected.

**Persistence round-trip (the headline acceptance test):**
- Integration test with `MockWebServer`: load → toggle SMS on → assert outbound
  write hits the real backend route (`POST /ui/alerts/type-preferences`, **POST**)
  with an `AlertTypePreferenceUpdate` body whose `sms` is `true` (e.g.
  `{"alert_type":"...","sms":true,...}`) and with `X-CSRF-Token` present → server
  returns its body (or, if untyped/empty, the ViewModel re-`GET`s) → re-create
  ViewModel (simulating reload) → assert the toggle is `true` (proves persistence
  end-to-end through the repository). The repository-input shape may use
  `category_id`/`channels`; the *on-the-wire* assertion is against the backend
  contract above (see §5 correction).

**Compose UI (`createAndroidComposeRule`):**
- Toggling a switch flips its semantics state.
- Stale banner, empty state, error+Retry render correctly.
- Disabled push column shows "Turn on in system settings" and invokes the callback.
- TalkBack semantics assertions (contentDescription + role) for switches.

**Screenshot tests (Roborazzi):** Ready, Loading, Error, Empty, Stale, OS-blocked.

Coverage target: ViewModel ≥ 85% lines. All tests run on JVM/Robolectric in CI
except the instrumented persistence round-trip.

## 12. Dependencies & Sequencing

- **Hard depends on AND-078** (Preferences API + DTOs / repository): provides
  `NotificationPreferencesRepository`, DTOs, endpoints, and the DataStore cache.
  AND-080 cannot be merged until AND-078's repository interface is stable.
- **Depends on AND-088** (Alert preferences screen, E12) for the shared
  `PreferenceChannelRow` composable and category-grouping model. If AND-088 is not
  yet merged, ship a local row composable with an identical signature behind a
  `core-ui` placeholder and file a follow-up to consolidate — this avoids blocking
  on cross-epic sequencing while keeping the public API stable.
- Transitively relies on `core-network` interceptor stack (cookie jar, CSRF, 401
  refresh) and `core-ui` theme — both pre-existing.
- **Blocks:** none recorded in backlog.
- Sequencing: land after AND-078; coordinate composable ownership with AND-088.

## 13. Risks & Open Questions

- **OQ-1 — Endpoint shape (PARTIALLY RESOLVED in review):** the originally-assumed
  `PATCH /ui/preferences/notifications` is wrong. Verified backend route is
  `POST /ui/alerts/type-preferences` (req `AlertTypePreferenceUpdate`, one alert
  type per call); its `200` response is untyped in OpenAPI, so the reconciliation
  body is still unconfirmed. Outstanding: confirm the GET/POST response shapes and
  whether a bulk variant exists. Mitigation: depend on repository function
  signatures, not raw paths.
- **OQ-2 — Channel availability source:** does the backend express SMS/email
  availability per category, or globally (e.g., SMS only if a verified phone
  exists)? If global, the UI must gate channels by account capability flags.
  Needs AND-078 clarification.
- **OQ-3 — `preference_locked` (org policy):** confirm whether managed categories
  should render as disabled-on with a lock icon vs. hidden. Current design: shown,
  disabled, with inline explanation.
- **Risk — unreliable dev host:** flaky `PATCH`es could cause perceived
  non-persistence; mitigated by canonical-response reconciliation and explicit
  Retry (no silent retries on writes).
- **Risk — AND-088 ordering:** cross-epic composable dependency; mitigated by the
  local-fallback row composable strategy in §12.
- **Risk — OS permission drift:** push permission can change while the app is
  backgrounded; mitigated by re-checking on `ON_RESUME`.

## 14. Acceptance Criteria

1. Screen renders categories with up to three per-category channel switches
   (push/email/SMS), omitting channels the backend marks unavailable. (FR-1, FR-2)
2. Toggling a switch updates the UI optimistically and persists a debounced,
   coalesced `PATCH` to the preferences repository. (FR-3, FR-4)
3. **Persistence proven by test:** an automated round-trip (toggle → write →
   reload → re-render) confirms the changed value survives, including the
   `X-CSRF-Token` header on the write. (Headline acceptance — §11)
4. Save failure reverts the toggle, shows inline error + Retry, and Retry
   re-issues the write successfully. (FR-5)
5. OS-level push-off (API 33+) disables push switches and offers a deep-link to
   system notification settings, leaving email/SMS functional. (FR-6)
6. Pull-to-refresh re-fetches; cached-after-failure shows a stale banner;
   no-categories shows an empty state. (FR-7, FR-9)
7. State survives rotation and process death; unconfirmed edits are restored and
   re-attempted. (FR-8)
8. All switches expose correct TalkBack semantics (label, role, state); strings
   are externalized. (§9)
9. Unit + Compose + screenshot tests pass in CI; ViewModel coverage ≥ 85%. (§11)

## 15. Definition of Done

- Code merged to `android-port` under
  `com.testlogon.android.feature.settings.notifications`, behind the
  `NOTIFICATION_PREFS_ROUTE` in the settings nav graph.
- ViewModel exposes `StateFlow<NotificationPrefsUiState>`; Compose layer is
  stateless and hoisted; no Retrofit calls outside the AND-078 repository.
- All acceptance criteria in §14 met, including the persistence round-trip test.
- Unit, Compose, and Roborazzi screenshot tests green in CI; coverage gate met.
- Telemetry events wired and verified; no PII/preference payloads in logs.
- Accessibility pass (TalkBack) completed; all strings localized in `strings.xml`.
- ktlint/detekt clean; module builds with AGP 8.7.3 / Gradle 8.9 / JDK 17.
- Open questions OQ-1..OQ-3 either resolved or filed as tracked follow-ups with
  owners; any local fallback `PreferenceChannelRow` annotated with a follow-up to
  consolidate with AND-088.
- PR reviewed and approved; spec linked in the PR description.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** Preferences are fetched/written at `/ui/preferences/notifications`
   (GET + PATCH). **VERDICT: Corrected.** No such path exists in the backend.
   **Source:** OpenAPI index (`reference/openapi.index.txt`) — no `/ui/preferences/notifications`
   entry; nearest endpoints are `GET /ui/settings/preferences` /
   `PATCH /ui/settings/preferences` (`PreferencesPatchReq`, theme/UI only) and
   `GET /ui/alerts/type-preferences` / `POST /ui/alerts/type-preferences`.
2. **Claim:** The write is a `PATCH` carrying `{category_id, channels:{push,email,sms}}`.
   **VERDICT: Corrected.** Real backend write is **`POST /ui/alerts/type-preferences`**
   with body `AlertTypePreferenceUpdate` = `{alert_type (req), enabled?, push?,
   email?, sms?, in_app?}` (flat booleans; key `alert_type` not `category_id`).
   **Source:** OpenAPI `POST /ui/alerts/type-preferences`
   (op=`update_type_preferences_ui_alerts_type_preferences_post`) and schema
   `components.schemas.AlertTypePreferenceUpdate` (openapi.pretty.json L4676-4746).
3. **Claim:** The GET returns `{categories:[{id,title,description,channels:[{channel,enabled,available}]}]}`.
   **VERDICT: Unverified-assumption.** OpenAPI declares `GET /ui/alerts/type-preferences`
   response as `200:{}` (untyped). No `categories`/`title`/`description`/`available`
   keys exist in any schema. **Source:** OpenAPI `GET /ui/alerts/type-preferences`
   (op=`get_type_preferences…`, openapi.pretty.json L178501-178509, empty schema).
4. **Claim:** The PATCH/POST `200` returns a "canonical category" for reconciliation.
   **VERDICT: Unverified-assumption.** POST response is `200:{}` (untyped) in OpenAPI;
   no documented body. Reconcile-by-re-GET is the safe fallback (added to §5/§11).
   **Source:** OpenAPI `POST /ui/alerts/type-preferences` responses block (untyped).
5. **Claim:** Each channel has a per-category `available` flag the UI honors (FR-2).
   **VERDICT: Unverified-assumption.** No `available` field exists in
   `AlertTypePreferenceUpdate` or related schemas; per-channel availability is not
   backend-modeled. **Source:** schema `AlertTypePreferenceUpdate` (no `available`);
   grep of openapi.pretty.json for `"available"` returns only unrelated commerce schemas.
6. **Claim:** Web client mirrors this via `preferences.ts`. **VERDICT: Corrected.**
   `preferences.ts` targets `/ui/settings/preferences` (theme/density only) and the
   alerts prefs live in `alerts.ts` as per-channel POSTs taking **event-type
   arrays** (not booleans), and the web app does not call `type-preferences` at all.
   **Source:** `src/api/endpoints/preferences.ts: getPreferences/patchPreferences`
   (L30-42); `src/api/endpoints/alerts.ts: setEmailPrefs/setSmsPrefs/setToastPrefs`
   (L23-48).
7. **Claim:** Auth is cookie-based session with `X-CSRF-Token` echo from `ui_csrf`.
   **VERDICT: Corrected (incomplete).** CSRF-from-`ui_csrf` is correct, but the web
   client ALSO sends `Authorization: Bearer <accessToken>` and optional
   `X-IMPERSONATION-TOKEN`, and includes cookies via `credentials:"include"`;
   `X-CSRF-Token` is sent on **all** requests, not just writes. **Source:**
   `src/api/client.ts: api()` (L154-176) and `getCookie("ui_csrf")` (L168).
8. **Claim:** 401 is handled by a single `POST /ui/session/refresh` retry.
   **VERDICT: Verified.** **Source:** `src/api/client.ts: refreshSession()` (L121-130)
   and the 401 handling block (L194-237); OpenAPI `POST /ui/session/refresh`
   (op=`ui_session_refresh…`, openapi.index.txt L1847).
9. **Claim:** CSRF is required on the write. **VERDICT: Verified (as sent header).**
   The header is attached to the write; whether the server *rejects* a missing token
   is not asserted by the client. **Source:** `src/api/client.ts` L168-171.
10. **Claim:** FastAPI `detail` error shape is `string | [{msg}] | {code,...}`.
    **VERDICT: Verified.** **Source:** `src/api/client.ts: normalizeErrorDetail`
    (L66-102) and `mapAuthorizationError` (L34-64); 422 bodies use
    `HTTPValidationError`/`ValidationError` (`detail:[{loc,msg,type}]`) in OpenAPI.
11. **Claim:** `403 preference_locked` (code `preference_locked`) is a real org-policy error.
    **VERDICT: Unverified-assumption.** The object-with-`code` error *shape* is real,
    but `preference_locked` itself is not in the sources; observed codes are
    `role_required*`, `geo_blocked`, `helpdesk_*`. **Source:** `mapAuthorizationError`
    (src/api/client.ts L34-64) lists the actual codes; no `preference_locked` present.
12. **Claim:** Network/offline maps to an error result (IOException-class). **VERDICT:
    Verified (analogue).** Web client throws `ApiError(0, "Network error")` on fetch
    failure; the Android core-network equivalent is an IOException → `ApiResult.Error`.
    **Source:** `src/api/client.ts` catch block (L185-189).
13. **Claim:** `POST_NOTIFICATIONS` runtime permission applies on API 33+ and
    `Settings.ACTION_APP_NOTIFICATION_SETTINGS` exists on API 26+ (FR-6, §4).
    **VERDICT: Verified (framework ref).** **Source:** Android docs —
    https://developer.android.com/develop/ui/views/notifications/notification-permission
    and https://developer.android.com/reference/android/provider/Settings#ACTION_APP_NOTIFICATION_SETTINGS .
14. **Claim:** Material 3 `PullToRefreshBox` is the pull-to-refresh primitive (§4).
    **VERDICT: Verified (framework ref).** **Source:**
    https://developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary .
15. **Claim:** Repository `NotificationPreferencesRepository` / DTOs come from AND-078.
    **VERDICT: Unverified-assumption (upstream).** Internal upstream artifact; not
    present in the provided reference sources. **Source:** none available — owned by AND-078.

### Corrections made
- **§1, §5, §6, §11, §13:** replaced the non-existent `PATCH /ui/preferences/notifications`
  with the verified `POST /ui/alerts/type-preferences` (and noted `GET` equivalent).
- **§5:** corrected verb (PATCH→POST), request body (`alert_type` + flat booleans
  `push/email/sms/in_app/enabled`, no `category_id`/`channels`/`available`),
  flagged GET and write response bodies as untyped/unverified, and added the
  reconcile-by-re-GET fallback.
- **§2 & §5:** corrected the auth description — not cookie-only; Bearer +
  impersonation + cookies, and CSRF on every request (not just writes).
- **§5:** flagged `preference_locked` as an unverified code; verified the three
  `detail` shapes; noted some alerts endpoints use `ErrorEnvelope`.
- **§11:** rewrote the MockWebServer round-trip assertion to target the real route/verb.
- **§13 OQ-1:** marked partially resolved with the verified endpoint.

### Open assumptions
- **GET and write response shapes** for `/ui/alerts/type-preferences` (untyped
  `{}` in OpenAPI) — cannot verify field names; AND-078/backend must confirm.
- **Per-channel `available` flag (FR-2)** — not backend-modeled; UI gating source
  (per-type vs account-capability, e.g. verified phone for SMS) is unresolved (OQ-2).
- **`preference_locked` / org-policy lock (OQ-3)** — code not found in sources;
  presence and HTTP status unverified.
- **`category_id`/`channels` vs `alert_type`/flat-booleans mapping** — assumed to
  live in AND-078's repository; the mapping layer itself is not in the references.
- **`NotificationPreferencesRepository`, DTOs, DataStore cache** — upstream AND-078
  artifacts, not in the provided sources.
- **`X-SESSION-ID` / `user_sub` query+header params** appear on the alerts prefs
  endpoints in OpenAPI; whether the Android core-network stack supplies them (vs.
  cookie/Bearer) is an upstream/AND-078 detail, unverified here.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35) in CI; **deviceA15** = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a).
Most cases are device-agnostic and run on emu35 in CI; cases that exercise real OS
notification-permission behavior, ON_RESUME permission drift, or the system-settings
deep-link SHOULD run on **deviceA15** to validate real OEM (Samsung One UI) behavior
in addition to emu35.

- **TC-AND-080-01 — Happy path: load + render categories**
  - Type: contract/MockWebServer (+ Robolectric). Target: JVM.
  - Preconditions: MockWebServer returns a 200 preferences payload with 2
    categories, each exposing push/email/sms.
  - Steps: create ViewModel → collect `uiState` until `Ready`.
  - Expected: `Ready` with both categories; each renders its channel toggles;
    unavailable channels (per OQ-2 mapping) are omitted, not disabled.
  - Traces: AC-1.

- **TC-AND-080-02 — Optimistic toggle + debounced/coalesced single write**
  - Type: unit (Turbine + virtual-time `TestDispatcher` + recording fake repo). Target: JVM.
  - Preconditions: `Ready` state loaded; debounce = 600 ms.
  - Steps: call `onToggle(cat, SMS, true/false/true)` three times rapidly within
    the debounce window → advance virtual time past 600 ms.
  - Expected: UI flips immediately on first toggle (optimistic); exactly **one**
    repository write occurs carrying the final value (`sms=true`); superseded
    saves are cancelled.
  - Traces: AC-2.

- **TC-AND-080-03 — Persistence round-trip (headline) over the wire**
  - Type: integration/MockWebServer. Target: emu35 (instrumented).
  - Preconditions: server accepts the write and serves the new value on re-GET.
  - Steps: load → toggle SMS on → capture outbound request → server responds →
    recreate ViewModel (simulate reload) → collect `uiState`.
  - Expected: outbound request is **`POST /ui/alerts/type-preferences`** with an
    `AlertTypePreferenceUpdate`-shaped body where `sms=true`, and header
    `X-CSRF-Token` is present; after reload the toggle re-hydrates to `true`.
  - Traces: AC-2, AC-3.

- **TC-AND-080-04 — CSRF header present on write**
  - Type: contract/MockWebServer. Target: JVM.
  - Preconditions: `ui_csrf` cookie seeded in the cookie jar.
  - Steps: perform a toggle write → inspect `RecordedRequest` headers.
  - Expected: `X-CSRF-Token` header present and equal to the cookie value.
  - Traces: AC-3.

- **TC-AND-080-05 — Save failure: revert + inline error + Retry succeeds**
  - Type: unit (fake repo returning `ApiResult.Error` then success). Target: JVM.
  - Preconditions: `Ready`; first write fails (e.g. 422 `{detail:[{msg:"channel
    unavailable"}]}`), second succeeds.
  - Steps: toggle → save fails → assert state → `onRetrySave(cat)` → save succeeds.
  - Expected: on failure the toggle reverts to last persisted value, `saving`
    clears, `transientError` is the mapped `detail` message, inline Retry shown;
    Retry re-issues the write and the value sticks.
  - Traces: AC-4.

- **TC-AND-080-06 — Error-shape mapping (string | [{msg}] | {code})**
  - Type: contract/MockWebServer. Target: JVM.
  - Preconditions: parametrized server responses: `{"detail":"Notification
    category not found"}` (404), `{"detail":[{"loc":[...],"msg":"channel
    unavailable"}]}` (422), `{"detail":{"code":"role_required","message":"…"}}` (403).
  - Steps: trigger a write per variant → observe `transientError`/state.
  - Expected: each `detail` shape maps to a non-empty user-facing message; the
    object form surfaces its message; a 403 code is treated as non-retryable.
    (Note: `preference_locked` is unverified — test uses a verified code; see §16.)
  - Traces: AC-4.

- **TC-AND-080-07 — Flaky dev host / offline: stale cache vs hard error**
  - Type: contract/MockWebServer. Target: JVM.
  - Preconditions: variant A — cache present, live GET fails (timeout/IOException);
    variant B — no cache, GET fails.
  - Steps: enter screen with each variant.
  - Expected: A → `Ready(isStale=true)` with dismissible stale banner showing
    cached values; B → `Error(message)` full-screen Retry; on flaky write,
    no silent auto-retry occurs (only user Retry re-issues).
  - Traces: AC-4, AC-6.

- **TC-AND-080-08 — Pull-to-refresh and empty state**
  - Type: Compose-UI (`createAndroidComposeRule`). Target: emu35.
  - Preconditions: initial `Ready`; refresh returns updated data; separate run
    returns zero categories.
  - Steps: trigger `PullToRefreshBox` refresh → assert refreshed; load empty set.
  - Expected: refresh re-fetches and updates rows; `isRefreshing` toggles;
    zero-category response renders the explanatory empty state, not a blank screen.
  - Traces: AC-6.

- **TC-AND-080-09 — State survives rotation and process death**
  - Type: instrumented. Target: emu35.
  - Preconditions: a toggle is optimistically applied but its write not yet confirmed.
  - Steps: rotate device; then simulate process death + restore via
    `SavedStateHandle` (`pending_edits`).
  - Expected: after rotation the working model is intact; after restore the pending
    edit is replayed through the save pipeline and re-attempted.
  - Traces: AC-7.

- **TC-AND-080-10 — OS push-off gating + system-settings deep-link (real OS)**
  - Type: instrumented/e2e. Target: **deviceA15** (MUST run on physical device;
    also smoke on emu35). Rationale: real `POST_NOTIFICATIONS` denial and Samsung
    One UI app-notification-settings screen behavior differ from a stock emulator.
  - Preconditions: app's notifications disabled at OS level (API 33+ permission off).
  - Steps: open screen → observe push column → tap "Turn on in system settings".
  - Expected: push toggles render disabled/`osBlocked=true` with the inline action;
    email/SMS remain functional; the action fires
    `Settings.ACTION_APP_NOTIFICATION_SETTINGS` and lands on the app's own settings;
    on `ON_RESUME` after re-enabling, push columns re-enable.
  - Traces: AC-5.

- **TC-AND-080-11 — Security: CSRF & no PII in logs/cache**
  - Type: unit + contract. Target: JVM.
  - Preconditions: Timber test tree captures logs; cache inspected.
  - Steps: perform load + toggle + a failing save.
  - Expected: write carries `X-CSRF-Token` (cannot be bypassed from UI);
    no full preference payloads or contact endpoints (phone/email values) appear in
    any log line; DataStore cache contains only category ids + booleans.
  - Traces: AC-3, AC-8 (security posture, §8/§10).

- **TC-AND-080-12 — Accessibility: TalkBack semantics + live regions**
  - Type: Compose-UI (semantics assertions). Target: emu35 (full TalkBack pass on
    **deviceA15** as manual confirmation).
  - Preconditions: `Ready` with at least one category.
  - Steps: assert switch semantics; toggle and observe announcements; show error
    and stale banner.
  - Expected: each switch has `role=Switch`, a contentDescription including
    category + channel ("Security alerts, push notifications"), and on/off
    toggle state; errors announce `Assertive`, "Saved" announces `Polite`; headers
    have `heading()`; touch targets ≥ 48dp; strings sourced from `strings.xml`.
  - Traces: AC-8.

- **TC-AND-080-13 — Screenshot/state coverage (Roborazzi)**
  - Type: unit (Roborazzi). Target: JVM.
  - Preconditions: deterministic state fixtures.
  - Steps: render Ready, Loading, Error, Empty, Stale, OS-blocked.
  - Expected: golden screenshots match for each state; CI fails on diff.
  - Traces: AC-9.

- **TC-AND-080-14 — ViewModel coverage gate**
  - Type: unit (Jacoco/Kover). Target: JVM.
  - Preconditions: full unit suite (TC-02/05/06/07/09 etc.) runs.
  - Steps: run coverage report on `NotificationPreferencesViewModel`.
  - Expected: line coverage ≥ 85%; CI gate enforced.
  - Traces: AC-9.

### Coverage matrix (AC → covering TCs)

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 — render categories, omit unavailable channels | TC-01 |
| AC-2 — optimistic toggle + debounced/coalesced write | TC-02, TC-03 |
| AC-3 — persistence proven incl. `X-CSRF-Token` | TC-03, TC-04, TC-11 |
| AC-4 — save failure revert + inline Retry | TC-05, TC-06, TC-07 |
| AC-5 — OS push-off gating + deep-link | TC-10 |
| AC-6 — pull-to-refresh, stale banner, empty state | TC-07, TC-08 |
| AC-7 — survives rotation + process death | TC-09 |
| AC-8 — TalkBack semantics + externalized strings | TC-11, TC-12 |
| AC-9 — unit + Compose + screenshot pass, coverage ≥ 85% | TC-13, TC-14 (all unit/Compose TCs feed coverage) |
