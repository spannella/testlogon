---
id: AND-088
title: Alert preferences screen
milestone: M2
epic: E12
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-086, AND-087]
blocks: []
---

# AND-088 — Alert preferences screen

## 1. Overview & Goal

AND-088 delivers a single unified **Alert Preferences** screen that composes the
email and SMS alert-target capabilities shipped by AND-086 and AND-087 into one
coherent settings surface, and adds the **category** layer on top of the
**channel** layer. A "channel" is a delivery target (a verified email address or
phone number, plus the implicit in-app/push channel); a "category" is an **alert
event type** (the backend calls these `event_types`, e.g. `security`, `account`,
`billing`, `product`) that the user can independently enable or disable per
channel.

> **Review note (contract):** The backend does **not** model per-category booleans.
> "Enabled for a channel" means the event-type id is a member of that channel's
> `*_event_types` string array (e.g. `email_event_types`). The authoritative list
> of categories comes from `GET /ui/alerts/types` → `{ types, event_types }`, not
> from the prefs payload. The internal `PrefMatrix` in §4 is a client-side
> projection of these arrays; it is assembled/serialized as
> `event_type ∈ <kind>_event_types`. See §16 for the full audit.

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
- **R1 RESOLVED (this review):** The category-prefs contract was reconciled against
  `/openapi.json` and `src/api/endpoints/alerts.ts`. Writes are **`POST`** (not PUT)
  to `/ui/alerts/email_prefs` / `/ui/alerts/sms_prefs`, the body is the **full**
  enabled list `{ email_event_types: [...] }` / `{ sms_event_types: [...] }`
  (read-modify-write of the whole array — NOT a partial `{prefs:{cat:bool}}` merge),
  and the GET responses are the `AlertPreferences` shape with `email_event_types`/
  `emails` (plain `string[]`). The original `prefs: {categoryId: bool}` map assumed
  in this spec does not exist server-side. See §5 (corrected) and §16.

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
    // NOTE: the backend identifies targets by VALUE, not an id. GET prefs returns
    // `emails: String[]` / `sms_numbers: String[]` (plain values, no per-target id
    // or verified flag). `id` here is the value itself (the email/phone), or "push".
    val id: String,            // the email/phone value, or "push" for the device channel
    val kind: ChannelKind,
    val display: String,       // see §8: web shows full value; Android masks for display
    val verified: Boolean,     // backend GET has no per-target verified flag; treat
                               // every configured target as verified (only verified
                               // targets are persisted server-side). "pending" exists
                               // only transiently during the AND-086/087 confirm flow.
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
    suspend fun getPrefs(): ApiResult<AlertPrefsBundle>          // GET /ui/alerts/types + email_prefs + sms_prefs
    suspend fun setCategoryPref(
        categoryId: String, kind: ChannelKind, enabled: Boolean,
    ): ApiResult<Unit>                                            // read-modify-write: POST <kind>_prefs with full array
    suspend fun setBulkPrefs(matrix: PrefMatrix): ApiResult<Unit>  // POST each kind's full *_event_types array
}

data class AlertPrefsBundle(
    val categories: List<AlertCategory>,
    val matrix: PrefMatrix,
)
```

The repository merges the `email_prefs` and `sms_prefs` GET responses (already
modeled by AND-086/087) plus the category list from `GET /ui/alerts/types`
(`event_types`) into one `AlertPrefsBundle`. The Retrofit service interface is
`AlertPrefsApi` (Moshi-mapped). `setCategoryPref` performs a **read-modify-write**:
it adds/removes the event-type id in the cached `<kind>_event_types` array and
**POSTs the full array** to the channel-kind-specific prefs endpoint (there is no
partial/PUT variant). The POST returns the canonical `AlertPreferences` which the
repo uses to reconcile state.

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

> **Corrected in this review.** The shapes below were verified against
> `openapi.index.txt`, `openapi.pretty.json` (schemas `AlertEmailPrefsReq`,
> `AlertSmsPrefsReq`, `AlertPushPrefsReq`, `AlertEmailRemoveReq`,
> `AlertSmsRemoveReq`) and `src/api/endpoints/alerts.ts` / `src/api/types.ts`
> (`AlertPreferences`). The previously documented `targets`/`categories`/`prefs`
> JSON and the **PUT** method were wrong and have been replaced.

**Category list** comes from a dedicated endpoint, not the prefs payload:

```
GET /ui/alerts/types
200 OK
{ "types": ["security", ...], "event_types": ["security_login", "billing_invoice", ...] }
```

The matrix rows are driven by `event_types` (the per-event toggles); `types` is a
coarser grouping (informational). FR-4's "data-driven categories" maps to
`event_types`.

Read prefs (per channel kind; merged client-side). Response is the
`AlertPreferences` schema. Example email prefs:

```
GET /ui/alerts/email_prefs
200 OK
{
  "emails": ["alerts@example.com", "ops@example.com"],   // plain string[] of configured addresses
  "email_event_types": ["security_login", "billing_invoice"]   // ENABLED event types for this channel
}
```

`GET /ui/alerts/sms_prefs` returns the same shape with `sms_numbers` (string[]) and
`sms_event_types`. (Optional fields per `AlertPreferences`: `emails`, `sms_numbers`,
`toast_event_types`, `push_event_types`, `webhook_urls`, `webhook_event_types`.)
A category is "on" for a channel iff its `event_type` id is present in that
channel's `*_event_types` array.

Write prefs — **POST** (not PUT), sending the **full** enabled list (read-modify-write):

```
POST /ui/alerts/email_prefs
Headers: X-CSRF-Token: <ui_csrf cookie value>
Content-Type: application/json
{ "email_event_types": ["security_login", "billing_invoice"] }   // entire enabled set, not a delta
200 OK
{ "emails": [...], "email_event_types": ["security_login", "billing_invoice"] }   // canonical AlertPreferences
```

To toggle one switch: read current `email_event_types`, add/remove the event-type
id, POST the whole array (mirrors `toggleEventType` in `src/pages/alerts/AlertPrefs.tsx`).
This makes `setCategoryPref` a read-modify-write over the cached array; there is no
partial-merge endpoint, so R3 is moot.

SMS uses `POST /ui/alerts/sms_prefs { "sms_event_types": [...] }` identically.
**PUSH:** there is a `POST /ui/alerts/push_prefs { "push_event_types": [...] }`
(schema `AlertPushPrefsReq`) for writing, but the index exposes **no
`GET` for push prefs** — push enabled-state cannot be read back. Therefore the PUSH
column renders only if a push prefs GET is added (see §16 open assumptions); for M2,
default to hiding PUSH and `activeKinds` excludes it.

> **Alternative API (not used):** the backend also exposes
> `GET/POST /ui/alerts/type-preferences` (schema `AlertTypePreferenceUpdate`:
> `{ alert_type, email?, sms?, push?, in_app?, enabled? }`), which is a true
> per-event × per-channel matrix in one call. The web client does **not** use it,
> so this ticket follows the web contract (`*_prefs` arrays). If a single-call
> matrix write is desired later, `type-preferences` is the path. Flagged in §16.

Remove channel (delegated, **by value not by id**):
`POST /ui/alerts/emails/remove {"email":"alerts@example.com"}` (schema
`AlertEmailRemoveReq`, required field `email`) /
`POST /ui/alerts/sms/remove {"phone":"+15550000000"}` (schema `AlertSmsRemoveReq`,
required field `phone`) — owned by AND-086/087. Both return the updated
`AlertPreferences`.

All requests carry session cookies and the `X-CSRF-Token` header (sourced from the
`ui_csrf` cookie). **Verified** against `src/api/client.ts`: the web client sends
`credentials: "include"`, attaches `X-CSRF-Token` from `getCookie("ui_csrf")`, and on
`401` calls `POST /ui/session/refresh` exactly once (a single shared in-flight
`refreshPromise`) then **retries the original request** (the web client retries the
same request method after refresh — it does not distinguish GET vs POST here; on
this screen the only write is the POST prefs save, which is naturally idempotent
since it sends the full array). If refresh fails the client logs out
(`session_expired`). FastAPI error mapping: `detail` may be
`string | [{msg,...}] | {code,message,...}` and is normalized by
`normalizeErrorDetail(body.detail, ...)` (verified in `client.ts`) to a single
message; the shared `core-network` mapper produces `ApiResult.Error(message, code?)`.
A `403` with `detail.code == "geo_blocked"` is a distinct path in the web client.

## 6. Data & State Management

- **Load**: `load()` launches concurrent `async` fetches: `GET /ui/alerts/types`
  (the authoritative `event_types` list), `emailRepo.getPrefs()`
  (`GET email_prefs`), `smsRepo.getPrefs()` (`GET sms_prefs`); `await`s all.
  Categories come from `event_types` (NOT from per-channel responses — that was the
  pre-review error; channel GETs only return the *enabled* subset). The `PrefMatrix`
  is assembled as `(eventType, kind) -> (eventType ∈ <kind>_event_types)`.
  `activeKinds` = kinds with ≥1 configured target (`emails` / `sms_numbers`
  non-empty), plus PUSH only if a push-prefs GET is available (currently it is
  not — see §5/§16).
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
  > **Divergence note (verified):** the web reference (`src/pages/alerts/AlertPrefs.tsx`)
  > renders the **full** address/number (`font-mono`, unmasked) because the GET
  > returns plain `emails`/`sms_numbers` strings with no masking and no per-target
  > id. Masking here is a deliberate Android-side hardening choice, not a backend
  > guarantee. Because remove is **by value** (`{email}`/`{phone}`), the un-masked
  > value must still be retained in memory (not displayed) to issue the remove call.
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
  - `setCategoryPref` issues `POST .../email_prefs` with the **full**
    `{email_event_types:[...]}` array and the `X-CSRF-Token` header; 401 triggers a
    single `POST /ui/session/refresh` then retry.
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

- **R1 — Category-prefs contract uncertainty. [RESOLVED in review 2026-06-06.]**
  Confirmed against `openapi.index.txt` + `src/api/endpoints/alerts.ts`: prefs are
  per-channel `*_event_types` string arrays, written via **POST** `email_prefs`/
  `sms_prefs` (full array). The assumed `prefs: {categoryId: bool}` map does not
  exist. Category ids come from `GET /ui/alerts/types`. `AlertPrefsApi` updated in
  §5. (A separate `/ui/alerts/type-preferences` matrix endpoint also exists but is
  unused by the web client.)
- **R2 — PUSH channel availability. [PARTIALLY RESOLVED.]** A push **write** exists
  (`POST /ui/alerts/push_prefs`, `AlertPushPrefsReq.push_event_types`) but there is
  **no push GET** in the index, so enabled-state cannot be read back. For M2 the
  PUSH column is hidden and `activeKinds` excludes PUSH. Open question: add a
  `GET push_prefs` server-side, or use `GET /ui/alerts/type-preferences` (which
  carries a `push` boolean per type) to source push state?
- **R3 — Partial vs full write. [RESOLVED in review.]** The backend accepts only
  the **full** `*_event_types` array per POST; there is no partial merge. Both
  `setCategoryPref` and `setBulkPrefs` are read-modify-write over the cached array.
  No 422-fallback logic is needed.
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
(`POST email_prefs`/`sms_prefs` with the full updated `*_event_types` array) and the
new value survives pull-to-refresh and app restart (re-load reflects it). (Maps to
"persist.")

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend = `reference/src/...`.

1. **Read email prefs endpoint** — `GET /ui/alerts/email_prefs`.
   VERDICT: Verified.
   SOURCE: OpenAPI `GET /ui/alerts/email_prefs` (op `get_email_prefs_...`);
   `src/api/endpoints/alerts.ts: getEmailPrefs`.
2. **Read SMS prefs endpoint** — `GET /ui/alerts/sms_prefs`.
   VERDICT: Verified.
   SOURCE: OpenAPI `GET /ui/alerts/sms_prefs`; `src/api/endpoints/alerts.ts: getSmsPrefs`.
3. **Write prefs HTTP method is POST, not PUT.**
   VERDICT: Corrected (spec said PUT).
   SOURCE: OpenAPI `POST /ui/alerts/email_prefs` / `POST /ui/alerts/sms_prefs`
   (ops `set_email_prefs_...` / `set_sms_prefs_...`); `src/api/endpoints/alerts.ts:
   setEmailPrefs` / `setSmsPrefs` (both `api.post`).
4. **Write body is the full `*_event_types` string array, not a partial
   `{prefs:{categoryId:bool}}` map.**
   VERDICT: Corrected.
   SOURCE: `components.schemas.AlertEmailPrefsReq` = `{ email_event_types: string[] }`;
   `AlertSmsPrefsReq` = `{ sms_event_types: string[] }`; `src/api/endpoints/alerts.ts:
   setEmailPrefs` posts `{ email_event_types }`; toggle logic in
   `src/pages/alerts/AlertPrefs.tsx: toggleEventType` rebuilds & posts the whole array.
5. **GET prefs response shape is `AlertPreferences` with plain `emails: string[]` /
   `sms_numbers: string[]` and `*_event_types: string[]` — there is no
   `targets`/`categories`/`prefs` object.**
   VERDICT: Corrected.
   SOURCE: `src/api/types.ts: AlertPreferences` (lines ~446-455);
   `src/pages/alerts/AlertPrefs.tsx` uses `emailPrefs.data.emails`,
   `.email_event_types`, `smsPrefs.data.sms_numbers`.
6. **Category/event-type list comes from `GET /ui/alerts/types` →
   `{ types: string[], event_types: string[] }`, not from the prefs payload.**
   VERDICT: Corrected (spec embedded `categories` in the prefs response).
   SOURCE: OpenAPI `GET /ui/alerts/types` (op `alert_types_...`);
   `src/api/endpoints/alerts.ts: getAlertTypes`; consumed in `AlertPrefs.tsx`
   (`typesQuery.data.event_types`).
7. **Remove email is by value `{email}`, not `{id}`.**
   VERDICT: Corrected (spec said `{"id":"em_a1"}`).
   SOURCE: `components.schemas.AlertEmailRemoveReq` (required `email`);
   OpenAPI `POST /ui/alerts/emails/remove`; `src/api/endpoints/alerts.ts:
   alertEmailRemove(email)`.
8. **Remove SMS is by value `{phone}`, not `{id}`.**
   VERDICT: Corrected (spec said `{"id":"sm_b2"}`).
   SOURCE: `components.schemas.AlertSmsRemoveReq` (required `phone`);
   OpenAPI `POST /ui/alerts/sms/remove`; `src/api/endpoints/alerts.ts:
   alertSmsRemove(phone)`.
9. **PUSH prefs: a write endpoint exists but no read endpoint.**
   VERDICT: Corrected/clarified (spec treated push as fully open question).
   SOURCE: OpenAPI `POST /ui/alerts/push_prefs` (op `set_push_prefs_...`,
   `AlertPushPrefsReq.push_event_types`) present; **no** `GET .../push_prefs` line in
   `openapi.index.txt`. `AlertPreferences.push_event_types` exists in types.ts but is
   not read by the web client.
10. **An alternative matrix endpoint `GET/POST /ui/alerts/type-preferences` exists
    (`AlertTypePreferenceUpdate { alert_type, email?, sms?, push?, in_app?, enabled? }`).**
    VERDICT: Verified (informational; web client does not use it).
    SOURCE: OpenAPI `GET/POST /ui/alerts/type-preferences`;
    `components.schemas.AlertTypePreferenceUpdate`; absent from
    `src/api/endpoints/alerts.ts`.
11. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie on all requests.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
12. **Auth: cookie-based, `credentials: include`; on 401 perform one
    `POST /ui/session/refresh` then retry; logout on refresh failure.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`refreshSession()` → `fetch(.../ui/session/refresh)`,
    single shared `refreshPromise`, retry of original request, `logout("session_expired")`).
13. **FastAPI `detail` is normalized (string | array | object incl. `{code,message}`)
    to a single message.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail(body.detail, ...)`; 403
    `detail.code === "geo_blocked"` branch; error responses use
    `HTTPValidationError` (FastAPI `{detail:[{loc,msg,type}]}`) per OpenAPI
    (`resp=...;422:HTTPValidationError` on every alerts route).
14. **All write errors surface as `422 HTTPValidationError`** (the only declared
    error code on these routes besides auth).
    VERDICT: Verified.
    SOURCE: OpenAPI index lines for `POST /ui/alerts/email_prefs`, `.../sms_prefs`,
    `.../emails/remove`, `.../sms/remove` (all `resp=200:;422:HTTPValidationError`).
15. **Add-channel flows (begin/confirm) owned by AND-086/087.**
    VERDICT: Verified.
    SOURCE: OpenAPI `POST /ui/alerts/emails/begin|confirm`,
    `POST /ui/alerts/sms/begin|confirm` (`AlertEmailBeginReq`/`AlertEmailConfirmReq`/
    `AlertSmsBeginReq`/`AlertSmsConfirmReq`); `src/api/endpoints/alerts.ts:
    alertEmailBegin/Confirm`, `alertSmsBegin/Confirm`.
16. **Masked display of email/phone on the prefs screen.**
    VERDICT: Corrected to "Android-only hardening, not a backend/web behavior."
    SOURCE: `src/pages/alerts/AlertPrefs.tsx` renders full values (`font-mono`,
    `configuredEmails.map`, `configuredSmsNumbers.map`); no masking in
    `AlertPreferences`.
17. **Compose + Material 3, single-Activity Navigation-Compose, Hilt, StateFlow
    UDF.**
    VERDICT: Unverified-assumption (no Android source in reference; standard for the
    stack in §2). SOURCE: framework ref —
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/guide/navigation ,
    https://developer.android.com/topic/architecture/ui-layer#define-ui-state .
18. **Pull-to-refresh, DataStore stale cache, optimistic toggle + rollback.**
    VERDICT: Unverified-assumption (Android UX choices; no backend/web contract
    governs them). SOURCE: framework ref —
    https://developer.android.com/jetpack/androidx/releases/datastore .

### Corrections made

- §1: redefined "category" as backend `event_type`; clarified "enabled" = array
  membership; added review note.
- §2: replaced the open R1 reconciliation note with the resolved POST/full-array
  contract.
- §4: `AlertChannel` documented as value-keyed (no server id / verified flag);
  repository doc comments changed PUT→POST and partial-merge→read-modify-write; the
  merge paragraph now sources categories from `GET /ui/alerts/types`.
- §5: full rewrite of the API Contract — `GET /ui/alerts/types`; corrected GET
  `AlertPreferences` shape; **POST** (not PUT) with full `*_event_types`; remove
  **by value** (`{email}`/`{phone}`) not `{id}`; push write-only (no GET); noted the
  unused `type-preferences` matrix endpoint; CSRF/refresh/`detail` claims verified
  with exact `client.ts` behavior.
- §6: load now fetches `/ui/alerts/types` for categories; matrix is array-membership.
- §8: added divergence note (web shows unmasked values; masking is Android-only;
  un-masked value retained in memory for value-based remove).
- §11, §14 (AC-2): PUT→POST + full-array wording.
- §13: R1 and R3 marked RESOLVED; R2 marked PARTIALLY RESOLVED (push write-only).

### Open assumptions

- **PUSH enabled-state is not readable.** `POST /ui/alerts/push_prefs` exists but no
  GET; without `GET push_prefs` (or adopting `GET /ui/alerts/type-preferences`) the
  Android client cannot render an accurate push column. M2: hide PUSH. Cannot be
  resolved from current sources — needs a backend decision.
- **No per-target verified/pending flag in GET prefs.** `emails`/`sms_numbers` are
  plain strings; the "pending badge" in §3/§14-AC-1 has no backend field to bind to.
  Assumed: all returned targets are verified; pending exists only transiently in the
  AND-086/087 confirm flow. Unverifiable here (depends on AND-086/087 internals).
- **Relationship between `types` and `event_types`** from `GET /ui/alerts/types` is
  not documented in the schema (response is untyped `200:` in the index). Assumed
  `event_types` drives matrix rows (matches `AlertPrefs.tsx`); `types` is a coarser
  grouping. Could not confirm exact semantics from the spec.
- **Android UI/architecture choices** (Compose, Hilt, DataStore cache, optimistic
  rollback, pull-to-refresh) are framework conventions, not derivable from the
  backend/web sources (no Android reference app provided). See citations 17-18.
- **`detail` array element fields** beyond `msg` (the spec's `[{msg}]`) — FastAPI
  emits `{loc,msg,type}`; only `msg` is used for display. Verified shape, but the
  Android mapper's exact field handling is an AND-078/`core-network` concern, assumed
  to mirror `normalizeErrorDetail`.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device); **MWS** =
contract test with MockWebServer (JVM); **emu** = headless AVD `test35`
(x86_64 / API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34 / arm64-v8a). Compose-UI tests run on Robolectric or
`emu`; instrumented/e2e on `emu` unless real hardware/push is required (then
**device**).

- **TC-AND-088-01 — Matrix assembly from `/types` + per-channel arrays.**
  Type: unit (JVM). Target: `AlertPrefsViewModel` + `AlertPrefsRepository` (fakes).
  Preconditions: `GET /ui/alerts/types` → `event_types=[security_login, billing_invoice]`;
  `email_prefs.email_event_types=[security_login]`; `sms_prefs.sms_event_types=[]`;
  `emails=[a@x.com]`, `sms_numbers=[]`.
  Steps: call `load()`, await `Ready`.
  Expected: 2 category rows; Email column present and `security_login` ON /
  `billing_invoice` OFF; SMS in `activeKinds` only if `sms_numbers` non-empty (here
  excluded → SMS column hidden); PUSH excluded.
  Traces: AC-1.

- **TC-AND-088-02 — `setCategoryPref` does read-modify-write POST with full array
  and CSRF header.**
  Type: contract/MockWebServer (MWS). Target: `AlertPrefsApi`/repository.
  Preconditions: cached `email_event_types=[security_login]`; `ui_csrf` cookie set.
  Steps: `setCategoryPref("billing_invoice", EMAIL, true)`; capture the request.
  Expected: `POST /ui/alerts/email_prefs`, body
  `{"email_event_types":["security_login","billing_invoice"]}` (full set, not a
  delta), header `X-CSRF-Token` = cookie value; 200 `AlertPreferences` reconciled.
  Traces: AC-2.

- **TC-AND-088-03 — Toggle OFF removes the id from the array.**
  Type: unit (JVM). Target: ViewModel.
  Preconditions: `security_login` ON for Email.
  Steps: `onToggle("security_login", EMAIL, false)`.
  Expected: optimistic state OFF with key in `pendingKeys`; persisted POST body omits
  `security_login`; on success key cleared.
  Traces: AC-2.

- **TC-AND-088-04 — Optimistic rollback on persist failure.**
  Type: contract/MockWebServer (MWS). Target: ViewModel + repository.
  Preconditions: server returns `422 {"detail":[{"loc":["body"],"msg":"bad","type":"value_error"}]}`
  for `POST email_prefs`.
  Steps: `onToggle("billing_invoice", EMAIL, true)`.
  Expected: UI flips ON optimistically, then rolls back **only** that key to OFF;
  other switches unchanged; retryable snackbar shows the normalized `msg`
  ("bad"), never raw JSON.
  Traces: AC-3, AC-9 (no raw JSON).

- **TC-AND-088-05 — 401 triggers single session refresh then retry.**
  Type: contract/MockWebServer (MWS). Target: `core-network` authenticator + repo.
  Preconditions: first `POST email_prefs` → 401; `POST /ui/session/refresh` → 200;
  retried `POST email_prefs` → 200.
  Steps: `setCategoryPref(...)`.
  Expected: exactly one refresh call, then the original POST retried once and
  succeeding; no infinite loop; second 401 (refresh fails) surfaces re-auth and
  preserves screen state.
  Traces: AC-2, AC-3.

- **TC-AND-088-06 — Remove channel posts by VALUE not id, collapses column.**
  Type: contract/MockWebServer (MWS) + unit. Target: ViewModel + email/sms repos.
  Preconditions: single email `a@x.com` configured; Email column visible.
  Steps: `onRemoveChannel(AlertChannel(id="a@x.com", EMAIL, ...))`.
  Expected: request `POST /ui/alerts/emails/remove {"email":"a@x.com"}` (field
  `email`, not `id`); on success the email disappears and, being the last email, the
  Email matrix column collapses and `activeKinds` drops EMAIL.
  Traces: AC-5.

- **TC-AND-088-07 — Empty-kind shows Add affordance, no dead switches.**
  Type: Compose-UI (Robolectric/emu). Target: `AlertPrefsScreen`/`CategoryMatrix`.
  Preconditions: `emails=[]`, `sms_numbers=[a]`.
  Steps: render `Ready`.
  Expected: Email column replaced by "No email targets — add one" affordance; tapping
  it invokes `onAddEmail`; SMS column shows switches.
  Traces: AC-4.

- **TC-AND-088-08 — Master "Disable all" then restore within session.**
  Type: unit (JVM). Target: ViewModel.
  Preconditions: mixed ON/OFF matrix.
  Steps: `onMasterToggle(true)` → assert all pairs OFF persisted via per-kind full
  arrays (each `*_event_types=[]`); `onMasterToggle(false)` → restore snapshot.
  Expected: one batched persist per active kind; re-enable restores the exact prior
  arrays from the in-memory snapshot; on persist failure the snapshot is restored.
  Traces: AC-6.

- **TC-AND-088-09 — Load failure: cache vs no-cache.**
  Type: unit (JVM). Target: ViewModel + DataStore cache fake.
  Preconditions: backend GET fails (timeout). Variant A: a cached `AlertPrefsBundle`
  exists; Variant B: none.
  Steps: `load()`.
  Expected: A → `Ready` with stale flag + "Couldn't refresh — showing saved settings"
  banner; B → `Error(retryable=true)` full-screen with Retry.
  Traces: AC-7.

- **TC-AND-088-10 — Flaky/offline dev-host resilience.**
  Type: contract/MockWebServer (MWS). Target: repository retry/backoff.
  Preconditions: `GET email_prefs` fails twice (socket reset) then 200; toggle POST
  fails once.
  Steps: `load()`; then `onToggle(...)`.
  Expected: GET auto-retries (max 2, jittered) and eventually succeeds; the toggle
  **POST is not auto-retried** by backoff (fails fast → rollback + snackbar);
  no crash on cleartext-HTTP socket errors.
  Traces: AC-3, AC-7.

- **TC-AND-088-11 — Accessibility: contentDescription, 48dp, font-scale reflow.**
  Type: Compose-UI (Robolectric/emu). Target: `CategoryRow`/`MasterDisableRow`.
  Preconditions: matrix with ≥2 active kinds.
  Steps: assert each `Switch` has cd "<Category> alerts via <Channel>, on/off";
  assert touch target ≥48dp; set font scale 2.0 and assert no clipping (stacked
  reflow).
  Expected: all assertions pass; header icons carry text labels.
  Traces: AC-8.

- **TC-AND-088-12 — No PII in logs/analytics.**
  Type: unit (JVM). Target: telemetry + logging.
  Preconditions: debug build; toggle + remove performed.
  Steps: capture emitted analytics props and log lines.
  Expected: `alert_pref_toggle` carries `category_id`/`channel_kind`/`enabled`/`result`
  only; no email/phone, no `ui_csrf`/cookie values, no raw `detail` JSON in any log.
  Traces: AC-9.

- **TC-AND-088-13 — Persistence across process death (instrumented).**
  Type: instrumented/e2e (emu). Target: full screen against MockWebServer or dev host.
  Preconditions: toggle `billing_invoice` Email ON; server now returns it in
  `email_event_types`.
  Steps: toggle ON → trigger Activity recreation / process kill → re-`load()`.
  Expected: switch reflects the persisted ON value after restart.
  Traces: AC-2.

- **TC-AND-088-14 — Real FCM push delivery vs hidden PUSH column.**
  Type: instrumented/e2e — **MUST run on the physical device** (real FCM token + APIs
  cannot be exercised on the headless x86 emulator without Play services / real push).
  Target: PUSH column gating + push prefs write.
  Preconditions: device registered for FCM (AND-085-class plumbing); `push_prefs`
  write reachable; no `GET push_prefs`.
  Steps: open screen; confirm PUSH column is HIDDEN for M2 (no readable state);
  if/when a push read is added, write `push_event_types` via
  `POST /ui/alerts/push_prefs` and confirm a real push is/ isn't delivered per toggle.
  Expected: M2 — PUSH column absent, no dead switches; write path (if invoked) sends
  `{push_event_types:[...]}` with CSRF.
  Traces: AC-1 (active-kinds gating), AC-2 (push write contract).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (render channels + matrix) | TC-01, TC-07, TC-14 |
| AC-2 (toggle persists; survives refresh/restart) | TC-02, TC-03, TC-05, TC-13, TC-14 |
| AC-3 (rollback + retryable snackbar) | TC-04, TC-05, TC-10 |
| AC-4 (empty-kind Add affordance) | TC-07 |
| AC-5 (remove delegates, column collapses) | TC-06 |
| AC-6 (master disable + restore) | TC-08 |
| AC-7 (no-cache error vs cached stale banner) | TC-09, TC-10 |
| AC-8 (a11y: cd, 48dp, reflow) | TC-11 |
| AC-9 (no PII/CSRF/cookie/raw-JSON) | TC-04, TC-12 |
