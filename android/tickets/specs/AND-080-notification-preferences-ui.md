---
id: AND-080
title: Notification preferences UI
milestone: M2
epic: E11
priority: P1
size: M
status: draft
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
`PATCH /ui/preferences/notifications` write. The screen reflects loading, saved,
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
- **Auth/transport:** cookie-based session with `X-CSRF-Token` echo and single
  `POST /ui/session/refresh` retry on 401 — all handled by the OkHttp
  interceptor stack from `core-network`; this screen issues no auth logic itself.
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
`NotificationPreferencesRepository` (AND-078). The repository wraps these endpoints
(mirrored from web `preferences.ts`). Shapes below are the contract this UI relies
on; AND-078 owns the DTOs and exact (de)serialization.

**GET `/ui/preferences/notifications`** — fetch current preferences.

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

**PATCH `/ui/preferences/notifications`** — partial update for one category.
Idempotent in effect but treated as a non-idempotent write (no auto-retry).

Request:
```json
{
  "category_id": "security_alerts",
  "channels": { "push": true, "email": true, "sms": false }
}
```

Response `200` returns the canonical category (used to reconcile optimistic state):
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

Headers: cookie session + `X-CSRF-Token` (from `ui_csrf` cookie) applied by the
`core-network` interceptor. CSRF is **required** on `PATCH`.

Error responses use FastAPI `detail`:
```json
{ "detail": "Notification category not found" }
{ "detail": [ { "loc": ["body","channels","sms"], "msg": "channel unavailable" } ] }
{ "detail": { "code": "preference_locked", "message": "Managed by org policy" } }
```
These map to `ApiResult.Error(message, code?)`; `403 preference_locked` is surfaced
as a non-retryable inline message and the toggle reverts.

If AND-078's deployed endpoint names diverge from `/ui/preferences/notifications`,
the repository contract (function names + DTO types) is authoritative and this UI
is unaffected — see Open Question OQ-1.

## 6. Data & State Management

- **Source of truth:** backend, fetched on screen entry via the repository.
- **Cache:** repository (AND-078) caches the last successful
  `GET /ui/preferences/notifications` in DataStore as JSON (last-known-good).
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
  `PATCH /ui/preferences/notifications` body
  `{"category_id":"...","channels":{...,"sms":true}}` with `X-CSRF-Token` present
  → server returns canonical → re-create ViewModel (simulating reload) → assert
  the toggle is `true` (proves persistence end-to-end through the repository).

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

- **OQ-1 — Endpoint shape:** the exact path/verb (`PATCH` vs `PUT`, per-category
  vs bulk) is owned by AND-078 and must be confirmed against `/openapi.json`.
  Mitigation: depend on repository function signatures, not raw paths.
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
