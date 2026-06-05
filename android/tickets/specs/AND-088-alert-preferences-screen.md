---
id: AND-088
title: Alert preferences screen
milestone: M2
epic: E12
priority: P1
size: M
status: draft
depends_on: [AND-086, AND-087]
blocks: []
---

# AND-088 — Alert preferences screen

## 1. Overview & Goal

AND-088 delivers a single unified **Alert Preferences** screen that composes the
email and SMS alert-target capabilities shipped by AND-086 and AND-087 into one
coherent settings surface, and adds the **category** layer on top of the
**channel** layer. A "channel" is a delivery target (a verified email address or
phone number, plus the implicit in-app/push channel); a "category" is a class of
alert event (e.g. `security`, `account`, `billing`, `product`) that the user can
independently enable or disable per channel.

The goal is a screen where the user can:

1. See all verified channels (emails, SMS numbers) with their verification state.
2. Add / verify / remove channels by reusing the AND-086/AND-087 flows.
3. Toggle each alert **category** on or off **per channel**, with changes
   persisted to the backend and surviving process death and re-login.

This ticket owns the **composition, the category matrix UI, and persistence of
the combined preference state**. It does **not** re-implement the email or SMS
add/verify/remove network calls — those are owned by AND-086 (`/ui/alerts/emails/*`,
`/ui/alerts/email_prefs`) and AND-087 (`/ui/alerts/sms/*`, `/ui/alerts/sms_prefs`).
"Prefs render and persist" is the acceptance bar.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`. This screen lives in
  `feature-alerts` (`com.testlogon.android.feature.alerts.prefs`).
- Stack: Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Module layering: `app -> feature-alerts -> core-*`. ViewModels expose
  `StateFlow<UiState>`; network returns typed `ApiResult<T>`; FastAPI `detail`
  errors mapped via the shared `core-network` error mapper.
- Dependencies (this ticket):
  - **AND-086** — provides `EmailAlertRepository`, `EmailTarget` model, and the
    `/ui/alerts/emails/begin|confirm|remove` + `/ui/alerts/email_prefs` calls.
  - **AND-087** — provides `SmsAlertRepository`, `SmsTarget` model, and the
    `/ui/alerts/sms/begin|confirm|remove` + `/ui/alerts/sms_prefs` calls.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). Cookie-based auth with `ui_csrf` echoed as `X-CSRF-Token`;
  persistent cookie jar; on 401 call `POST /ui/session/refresh` once then retry.
  OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/alerts.ts`,
  types in `frontend/src/api/types.ts`.
- The exact category preference endpoint shape MUST be reconciled against
  `/openapi.json` before implementation (see §13). This spec uses the
  `email_prefs` / `sms_prefs` GET/PUT shapes that AND-086/087 already integrate.

## 3. Functional Requirements

FR-1. The screen renders three logical regions: **Channels**, **Categories
matrix**, and **per-channel default toggles**, inside a single scrollable
`LazyColumn`.

FR-2. **Channels region** lists every verified email (from AND-086) and SMS number
(from AND-087), each showing the masked target, a verified/pending badge, and an
overflow action to **Remove** (delegates to the respective repository). An "Add
email" and "Add SMS number" entry route to the AND-086/AND-087 add flows.

FR-3. **Categories matrix**: for each alert category the user sees a row with the
category label/description and a per-channel `Switch` (one switch per active
channel kind: Email, SMS, Push). Toggling a switch optimistically updates UI and
issues a persist call.

FR-4. Categories are data-driven, not hardcoded in Compose. The set of categories
and their default state come from the prefs payload returned by the backend; an
unknown category id renders with a fallback label = the raw id.

FR-5. On first load the screen fetches channel lists and current prefs
concurrently and shows a single loading state until both resolve (or one fails).

FR-6. **Persistence**: any toggle change is written to the backend via the prefs
PUT and is reflected on reload and after app restart. No local-only "save button"
— changes auto-save (optimistic with rollback on failure).

FR-7. If there are no channels of a kind, that channel's column is hidden and a
"No email/SMS targets — add one" affordance is shown instead of dead switches.

FR-8. Pull-to-refresh re-fetches both channels and prefs.

FR-9. A "Disable all alerts" master toggle sets every category-channel pair off in
one batched persist; re-enabling restores the previous map (kept in memory for the
session only).

## 4. Technical Design

Package: `com.testlogon.android.feature.alerts.prefs`.

Navigation route (added to the feature-alerts nav graph; entry from Settings):

```kotlin
const val AlertPrefsRoute = "alerts/preferences"

fun NavGraphBuilder.alertPrefsScreen(
    onAddEmail: () -> Unit,     // -> AND-086 add flow
    onAddSms: () -> Unit,       // -> AND-087 add flow
) {
    composable(AlertPrefsRoute) {
        AlertPrefsScreen(
            onAddEmail = onAddEmail,
            onAddSms = onAddSms,
        )
    }
}
```

UI state and models:

```kotlin
enum class ChannelKind { EMAIL, SMS, PUSH }

data class AlertChannel(
    val id: String,            // target id, or "push" for the device channel
    val kind: ChannelKind,
    val display: String,       // masked email / formatted number / "This device"
    val verified: Boolean,
)

data class AlertCategory(
    val id: String,            // e.g. "security"
    val label: String,
    val description: String?,
)

// One toggle = (categoryId, channelKind) -> enabled
data class PrefMatrix(
    val enabled: Map<Pair<String, ChannelKind>, Boolean>,
) {
    fun isOn(category: String, kind: ChannelKind) =
        enabled[category to kind] ?: false
    fun with(category: String, kind: ChannelKind, value: Boolean) =
        PrefMatrix(enabled + ((category to kind) to value))
}

sealed interface AlertPrefsUiState {
    data object Loading : AlertPrefsUiState
    data class Error(val message: String, val retryable: Boolean) : AlertPrefsUiState
    data class Ready(
        val channels: List<AlertChannel>,
        val categories: List<AlertCategory>,
        val matrix: PrefMatrix,
        val activeKinds: List<ChannelKind>,   // kinds with >=1 verified channel (+PUSH)
        val isRefreshing: Boolean = false,
        val pendingKeys: Set<Pair<String, ChannelKind>> = emptySet(), // in-flight toggles
        val masterDisabled: Boolean = false,
    ) : AlertPrefsUiState
}
```

ViewModel:

```kotlin
@HiltViewModel
class AlertPrefsViewModel @Inject constructor(
    private val emailRepo: EmailAlertRepository,   // AND-086
    private val smsRepo: SmsAlertRepository,        // AND-087
    private val prefsRepo: AlertPrefsRepository,    // this ticket
) : ViewModel() {

    val uiState: StateFlow<AlertPrefsUiState>      // backed by MutableStateFlow

    fun load()                                      // concurrent fetch, see §6
    fun refresh()
    fun onToggle(categoryId: String, kind: ChannelKind, value: Boolean)
    fun onMasterToggle(disableAll: Boolean)
    fun onRemoveChannel(channel: AlertChannel)
    fun retry()
}
```

Repository (new, in `feature-alerts` data layer, returns `ApiResult`):

```kotlin
interface AlertPrefsRepository {
    suspend fun getPrefs(): ApiResult<AlertPrefsBundle>          // GET email_prefs + sms_prefs + categories
    suspend fun setCategoryPref(
        categoryId: String, kind: ChannelKind, enabled: Boolean,
    ): ApiResult<Unit>                                            // PUT prefs
    suspend fun setBulkPrefs(matrix: PrefMatrix): ApiResult<Unit>
}

data class AlertPrefsBundle(
    val categories: List<AlertCategory>,
    val matrix: PrefMatrix,
)
```

The repository merges the `email_prefs` and `sms_prefs` GET responses (already
modeled by AND-086/087) plus a categories list into one `AlertPrefsBundle`. The
Retrofit service interface is `AlertPrefsApi` (Moshi-mapped). `setCategoryPref`
maps a single switch back to the channel-kind-specific prefs PUT.

Composable structure:

```kotlin
@Composable fun AlertPrefsScreen(onAddEmail: () -> Unit, onAddSms: () -> Unit,
    vm: AlertPrefsViewModel = hiltViewModel())
@Composable private fun ChannelsSection(channels, onAdd, onRemove)
@Composable private fun CategoryMatrix(categories, activeKinds, matrix,
    pendingKeys, onToggle)
@Composable private fun CategoryRow(category, activeKinds, matrix, pending, onToggle)
@Composable private fun MasterDisableRow(disabled, onToggle)
```

`CategoryMatrix` renders a header row of channel-kind icons aligned with each
`CategoryRow`'s switches. Switches whose `(categoryId, kind)` is in `pendingKeys`
show a disabled state to prevent double-fire while a PUT is in flight.

## 5. API Contract

This ticket consumes endpoints owned by AND-086/AND-087 plus a category layer.
No new add/verify/remove endpoints are introduced here.

Read prefs (per channel kind; merged client-side). Example email prefs:

```
GET /ui/alerts/email_prefs
200 OK
{
  "targets": [
    { "id": "em_a1", "email": "s***@gmail.com", "verified": true }
  ],
  "categories": [
    { "id": "security", "label": "Security", "description": "Logins, MFA" },
    { "id": "billing",  "label": "Billing",  "description": null }
  ],
  "prefs": { "security": true, "billing": false }   // categoryId -> enabled for this channel kind
}
```

`GET /ui/alerts/sms_prefs` returns the same shape with `phone` masked targets.

Write a single category toggle (channel-kind-scoped PUT). Email example:

```
PUT /ui/alerts/email_prefs
Headers: X-CSRF-Token: <ui_csrf cookie value>
Content-Type: application/json
{ "prefs": { "security": true } }     // partial merge: only changed keys
200 OK
{ "prefs": { "security": true, "billing": false } }   // canonical post-write map
```

SMS uses `PUT /ui/alerts/sms_prefs` identically. PUSH category prefs, if exposed
by the backend, use the same `prefs` map under whatever push prefs endpoint
`/openapi.json` declares; if PUSH prefs are not yet available server-side, the
PUSH column is hidden (see §13 open question).

Remove channel (delegated): `POST /ui/alerts/emails/remove {"id":"em_a1"}` /
`POST /ui/alerts/sms/remove {"id":"sm_b2"}` — owned by AND-086/087.

All requests carry session cookies and the `X-CSRF-Token` header. On `401`,
`core-network` performs one `POST /ui/session/refresh` then retries (idempotent
GETs auto-retry; the PUT retries only after a successful refresh, not on backoff).
FastAPI error mapping: `detail` may be `string | [{msg}] | {code,...}` and is
normalized by the shared mapper to `ApiResult.Error(message, code?)`.

## 6. Data & State Management

- **Load**: `load()` launches two `async` fetches (`emailRepo.getPrefs()` /
  `smsRepo.getPrefs()`) plus categories via `prefsRepo.getPrefs()`, `await`s all.
  Categories are the union of category lists across channel responses (dedup by
  id). The `PrefMatrix` is assembled as `(categoryId, kind) -> enabled` from each
  channel's `prefs` map. `activeKinds` = kinds with ≥1 verified target, plus PUSH
  if push prefs are supported.
- **Optimistic toggle**: `onToggle` immediately emits `Ready` with
  `matrix.with(...)` and the key added to `pendingKeys`, then calls
  `prefsRepo.setCategoryPref(...)`. On success it reconciles against the returned
  canonical map and removes the key from `pendingKeys`. On failure it **rolls
  back** the single key, removes it from `pendingKeys`, and surfaces a snackbar.
- **Master toggle**: snapshot current matrix into a session-only field, set all
  pairs off (or restore), persist via `setBulkPrefs`. On failure, restore the
  snapshot.
- **Persistence**: source of truth is the backend (`prefs` maps). DataStore is
  used only to cache the last successfully loaded `AlertPrefsBundle` (Moshi
  JSON in a `Preferences` key) so the screen can render stale-but-usable content
  offline, clearly marked stale, while a refresh runs. No Room table is required
  for this ticket; the channel lists themselves are owned by AND-086/087 caches.
- **Process death**: `uiState` is rebuilt by re-running `load()` in `init`; the
  optimistic in-flight set is not persisted (any unconfirmed toggle is re-fetched
  from the backend, which is the safe canonical state).

## 7. Error Handling & Resilience

- Dev host is unreliable: GETs use ~20s timeout and bounded backoff retry (max 2
  retries, jittered) for the idempotent prefs/channel fetches. The toggle PUT is
  **not** auto-retried via backoff (non-idempotent semantics for the user); it
  fails fast and rolls back.
- Initial load failure where nothing is cached -> `AlertPrefsUiState.Error` with
  a Retry button (`retryable = true`). If a cached bundle exists, render it with a
  "Couldn't refresh — showing saved settings" banner instead of a full-screen
  error.
- Toggle persist failure -> rollback + snackbar "Couldn't save that change.
  Try again." with a Retry action that re-issues the single toggle.
- 401 handled transparently by the `core-network` authenticator (refresh-once);
  if refresh fails, the user is routed to re-auth and the screen state is
  preserved for return.
- Concurrent toggles on the same key are blocked by `pendingKeys`; toggles on
  different keys may run concurrently.
- All mapped errors go through the FastAPI `detail` normalizer; never display raw
  JSON.

## 8. Security & Privacy

- Channel displays are **masked** (`s***@gmail.com`, `+1 ••• ••• ••12`). Full
  email/phone values are never rendered on this screen.
- All writes include the `X-CSRF-Token` header sourced from the `ui_csrf` cookie;
  requests without it are rejected by the backend — the shared OkHttp interceptor
  guarantees attachment so this screen needs no special handling.
- Cookie jar is the shared persistent jar; this screen adds no token storage.
- Dev backend is plaintext HTTP — acceptable only for the dev host via the
  existing network-security-config cleartext allowlist; no new cleartext domains.
- No PII is logged (see §10). Cached prefs bundle in DataStore contains only
  masked targets and category booleans, no raw contact values.

## 9. Accessibility & i18n

- Every `Switch` has a `contentDescription` of the form
  "<Category> alerts via <Channel>, <on/off>" (e.g. "Security alerts via Email,
  on"). The matrix header icons carry text labels for screen readers.
- Switches and rows meet the 48dp minimum touch target; matrix columns reflow to
  a stacked per-channel layout when the row width is insufficient (narrow screens
  / large font scale) instead of clipping switches.
- All strings live in `feature-alerts` `strings.xml`; category labels come from
  the backend and are shown verbatim (no client translation) — descriptions
  likewise. Static chrome ("Add email", "Disable all alerts", error/snackbar
  copy) is localizable.
- Supports dynamic type / font scaling and dark theme via Material 3 tokens.
  Verified/pending badges use both color and text/icon, not color alone.

## 10. Telemetry & Logging

- Events (via the app's analytics abstraction, no PII):
  - `alert_prefs_view` — on screen open.
  - `alert_pref_toggle` — props: `category_id`, `channel_kind`, `enabled`,
    `result` (`ok`|`error`).
  - `alert_prefs_master_toggle` — props: `disable_all`, `result`.
  - `alert_prefs_refresh` — props: `trigger` (`pull`|`retry`), `result`.
- Logging: structured debug logs gated behind `BuildConfig.DEBUG`; never log
  email/phone values or full cookie/CSRF contents. Log only masked target ids and
  category ids. Network timings logged via the shared OkHttp logging interceptor
  (body logging off in release).

## 11. Testing Strategy

Acceptance is "Prefs render and persist," so tests center on matrix assembly,
optimistic-toggle persistence, and rollback.

- **Unit (ViewModel)** with `core-testing` fakes + `MainDispatcherRule`:
  - `load()` merges email+sms category lists (dedup) and builds the correct
    `PrefMatrix`; `activeKinds` excludes kinds with no verified targets.
  - `onToggle` emits optimistic on-state with key in `pendingKeys`, then
    reconciles to the canonical returned map on success.
  - `onToggle` failure rolls back exactly the one key and emits a snackbar event;
    other keys unchanged.
  - `onMasterToggle(true)` sets all pairs off; failure restores snapshot.
  - Load failure with cached bundle -> `Ready` + stale flag; without cache ->
    `Error(retryable=true)`.
- **Repository** with MockWebServer:
  - `getPrefs` parses the `email_prefs`/`sms_prefs` JSON (string/array/object
    `detail` error variants mapped correctly).
  - `setCategoryPref` issues `PUT .../email_prefs` with partial `{prefs:{...}}`
    and the `X-CSRF-Token` header; 401 triggers single refresh+retry.
- **Compose UI tests** (`ComposeTestRule`):
  - Matrix renders one switch per active kind per category; toggling a switch
    invokes `onToggle` with correct args and reflects new state.
  - Empty-kind state shows "Add" affordance, not switches.
  - `contentDescription`s present for accessibility assertions.
- **Persistence test**: toggle -> simulate process recreation (re-run `load()`
  against MockWebServer returning the updated map) -> switch reflects persisted
  value.
- CI: `:feature-alerts:testDebugUnitTest` + `connectedDebugAndroidTest` (or
  Robolectric for the Compose tests) green.

## 12. Dependencies & Sequencing

- **Depends on AND-086** (email targets + `email_prefs` GET/PUT, `EmailAlertRepository`,
  remove flow) and **AND-087** (SMS equivalents). This screen cannot be completed
  until both repositories and their prefs endpoints are merged; it may be built
  in parallel against `core-testing` fakes mirroring those interfaces.
- Transitively depends on AND-078 (the alerts API/session plumbing both parents
  build on) via AND-086/087.
- Reuses `core-network` (auth/CSRF/refresh interceptors, `ApiResult`, FastAPI
  error mapper), `core-ui` (Switch/Badge/Banner components, pull-to-refresh),
  `core-data` (DataStore), and `core-testing`.
- Blocks: none currently listed in the backlog.
- Sequencing: land repository + ViewModel + unit tests first (no real backend
  needed via fakes), then wire Compose + nav, then integration tests against the
  dev host.

## 13. Risks & Open Questions

- **R1 — Category-prefs contract uncertainty.** This spec models category prefs as
  a `prefs: {categoryId: bool}` map inside `email_prefs`/`sms_prefs`. The actual
  `/openapi.json` may instead expose a separate `/ui/alerts/category_prefs` or a
  different field name. **Action:** confirm against `/openapi.json` and
  `frontend/src/api/endpoints/alerts.ts` before coding; adjust `AlertPrefsApi`
  accordingly. The ViewModel/UI contracts above are insulated from this.
- **R2 — PUSH channel availability.** If the backend has no push-category prefs in
  M2, the PUSH column is hidden and `activeKinds` excludes PUSH (no dead UI). Open
  question: is push prefs in scope for M2 or a later ticket?
- **R3 — Partial vs full PUT.** Whether the backend accepts a partial `prefs`
  merge or requires the full map per write affects `setCategoryPref`/`setBulkPrefs`.
  Default to partial; fall back to read-modify-write full map if 422 is returned.
- **R4 — Unreliable dev host** may make integration tests flaky; rely on
  MockWebServer for deterministic CI and treat dev-host runs as smoke only.
- **R5 — Category set divergence** between email and SMS responses; resolved by
  union+dedup, but a category present for one kind only renders a switch only for
  that kind. Confirm this is the desired product behavior.

## 14. Acceptance Criteria

AC-1. Opening the screen shows all verified email and SMS channels (masked, with
verified/pending badges) and a category matrix with one switch per active channel
kind per category. (Maps to backlog "Prefs render.")

AC-2. Toggling any category-channel switch persists to the backend
(`PUT email_prefs`/`sms_prefs` with the changed key) and the new value survives
pull-to-refresh and app restart (re-load reflects it). (Maps to "persist.")

AC-3. A failed persist rolls back exactly the toggled switch and shows a
retryable snackbar; no other switches change.

AC-4. Channels with no targets of a kind show an "Add" affordance instead of
non-functional switches; tapping it routes to the AND-086/AND-087 add flow.

AC-5. Removing a channel (via overflow) delegates to the correct repository and
the channel disappears from the list and its matrix column collapses if it was the
last of its kind.

AC-6. "Disable all alerts" turns every switch off in one persist and re-enabling
restores the prior map within the session.

AC-7. Initial load with no cache and a backend failure shows a full-screen
retryable error; with a cache it shows stale content plus a "couldn't refresh"
banner.

AC-8. All switches expose `contentDescription` and meet 48dp touch targets;
matrix reflows (does not clip) at large font scale.

AC-9. No raw email/phone/CSRF/cookie values appear in logs or analytics.

## 15. Definition of Done

- `feature-alerts` builds on `android-port` with the new
  `AlertPrefsScreen`, `AlertPrefsViewModel`, `AlertPrefsRepository`/`AlertPrefsApi`,
  and nav entry wired into Settings; package `com.testlogon.android.feature.alerts.prefs`.
- All §14 acceptance criteria demonstrably pass.
- Unit, repository (MockWebServer), and Compose UI tests from §11 implemented and
  green in CI (`:feature-alerts` test tasks).
- Category-prefs contract reconciled against `/openapi.json` (R1) and any field
  renames applied; PUSH handling (R2) decided and reflected.
- No new cleartext domains; CSRF header attached on all writes via shared
  interceptor; masked displays only.
- Telemetry events (§10) fire with no PII; debug-only logging.
- Accessibility checks (TalkBack labels, touch targets, font-scale reflow, dark
  theme, color-independent badges) verified.
- Lint/detekt/ktlint clean; KDoc on public ViewModel and repository APIs.
- PR reviewed and merged to `android-port` with screenshots of the rendered matrix
  and a persistence demo (toggle -> restart -> state retained).
