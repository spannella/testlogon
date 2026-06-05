---
id: AND-113
title: Server-locale sync
milestone: M2
epic: E16
priority: P2
size: M
status: draft
depends_on: [AND-111, AND-027]
blocks: []
---

# AND-113 — Server-locale sync

## 1. Overview & Goal

The TestLogon backend persists a per-user locale preference (returned from `GET /ui/me`
and mutable via the user-preferences endpoint). On the web reference app this preference
is the source of truth that drives `i18n.ts` resource selection. The native Android port
must achieve functional parity: after a user authenticates, the locale the server reports
for that account must be reflected in the rendered UI, and a locale chosen on Android must
be written back to the server so the preference roams across devices and the web app.

This ticket connects three layers that already exist or are being built in parallel:

- The on-device i18n plumbing and externalized string resources delivered by **AND-111**.
- The authenticated session and `GET /ui/me` payload delivered by **AND-027**.
- A new locale read/write API surface plus the reconciliation logic that decides, on a
  per-launch and per-change basis, which locale "wins" between the device default, a
  locally cached choice, and the server preference.

**Goal:** When an authenticated user's server-side locale preference is `X`, the app renders
strings, dates, numbers, and plurals for locale `X` without requiring an app restart, and a
locale change made in the app is persisted to the server and survives reinstall/relogin. The
deliverable is testable end-to-end with an instrumentation test that flips the server
preference and asserts the visible UI language.

This is a feature ticket (Type: Feature, Priority: P2). It does not introduce new screens; it
introduces a `LocaleRepository`, a small API, a `Flow`-driven locale state, and the Compose
wiring that applies the resolved locale to the composition.

## 2. Context & References

- **Repo / module layout:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lands primarily in `core-data` (repository + DataStore),
  `core-network` (`LocaleApi`), `core-model` (DTOs / domain model), and `core-ui` (the
  `LocalAppLocale` composition local and `LocaleProvider`). Namespace base
  `com.testlogon.android` everywhere.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 +
  OkHttp 4.12 + Moshi 1.15, DataStore (prefs). minSdk 24, compile/target 35, JDK 17.
- **AND-111 (depends_on):** establishes string-resource conventions (`strings.xml` per
  `values-<lang>` qualifier folder), plurals, and the formatting helpers. This ticket consumes
  those resources; it does not define string content. The hardcoded-string lint from AND-111
  must remain green.
- **AND-027 (depends_on):** provides `AuthApi` and the authenticated cookie session
  (`X-CSRF-Token` echo of the `ui_csrf` cookie, single `POST /ui/session/refresh` on 401,
  persistent cookie jar). `GET /ui/me` is the canonical place the server reports the user's
  current `locale`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT,
  unreliable). OpenAPI at `/openapi.json`. FastAPI error `detail` mapping (string |
  `[{msg}]` | `{code,...}`). Design for ~20s timeouts and bounded backoff retry on idempotent
  GETs only.
- **Web reference:** `frontend/src/i18n.ts` (locale selection), `frontend/src/api/endpoints/*.ts`
  (locale/preferences endpoints), `frontend/src/api/types.ts` (shared `Me` / preferences types).
  These define the authoritative request/response shapes mirrored below; verify against
  `/openapi.json` during implementation as the field names are the single source of truth.

## 3. Functional Requirements

FR-1 **Resolve effective locale on launch.** On every app start the app computes an effective
locale using a deterministic precedence: (1) an explicit in-app override the user set this
session, else (2) the server preference from the last successful `GET /ui/me`, else (3) a
locally cached preference from DataStore, else (4) the device/system default filtered to the
set of supported locales, else (5) the app default (`en`).

FR-2 **Apply without restart.** A change to the effective locale recomposes the UI in the new
language within the same process — no activity recreation required for string/format changes.
(A `Configuration`-based recreate is an acceptable fallback only if a resource cannot be
resolved through the per-composition locale; see §4.)

FR-3 **Sync server -> device.** After login and on each foregrounded `GET /ui/me`, if the
server's `locale` differs from the cached value and the user has NOT set an explicit in-app
override during this session, adopt the server locale and persist it to DataStore.

FR-4 **Sync device -> server.** When the user selects a locale in-app (the picker UI itself may
be a later ticket; this ticket exposes the repository entry point), persist locally immediately
(optimistic) and PUT the preference to the server. On server success, clear any "pending sync"
flag. On failure, keep the local choice and mark it pending for retry.

FR-5 **Supported-locale gating.** Only locales for which `values-<lang>` resources exist (per
AND-111) are selectable/adoptable. A server preference outside the supported set falls back to
the closest base language, then to `en`, and is logged (§10) but not applied verbatim.

FR-6 **Offline / unreliable backend tolerance.** If `GET /ui/me` or the locale PUT fails or
times out, the app continues with the cached/effective locale and surfaces no blocking error;
the device->server write is queued for retry on next successful authenticated call.

FR-7 **Persistence across reinstall semantics.** The server preference is the durable record;
after reinstall + relogin, the UI reflects the server locale (FR-3), proving roaming.

## 4. Technical Design

### 4.1 Domain & model (`core-model`)

```kotlin
// com.testlogon.android.core.model.locale
@JvmInline value class LocaleTag(val value: String) // BCP-47, e.g. "en", "es", "fr-CA"

data class LocalePreference(
    val effective: LocaleTag,         // what the UI is rendering now
    val source: LocaleSource,         // where `effective` came from
    val pendingServerSync: Boolean,   // a local change not yet PUT to server
)

enum class LocaleSource { IN_APP_OVERRIDE, SERVER, CACHE, DEVICE, DEFAULT }
```

### 4.2 Network (`core-network`)

```kotlin
// com.testlogon.android.core.network.api
interface LocaleApi {
    // Read is normally folded into GET /ui/me; this dedicated GET exists for refresh-only fetch.
    @GET("ui/me")
    suspend fun me(): Response<MeDto>

    @PUT("ui/preferences")
    suspend fun updatePreferences(@Body body: UpdatePreferencesRequest): Response<PreferencesDto>
}
```

`MeDto` and `PreferencesDto` deserialized with Moshi; the CSRF header and cookie jar are
applied by the shared OkHttp interceptors from AND-027 — `LocaleApi` adds nothing
auth-specific. All calls reuse the same `Retrofit` instance (20s call timeout already
configured project-wide).

### 4.3 Persistence (`core-data`)

DataStore (`Preferences`) keys under a `locale_prefs` datastore:

```kotlin
private val KEY_LOCALE      = stringPreferencesKey("locale_tag")
private val KEY_SOURCE      = stringPreferencesKey("locale_source")
private val KEY_PENDING     = booleanPreferencesKey("locale_pending_sync")
private val KEY_OVERRIDE    = booleanPreferencesKey("locale_in_app_override")
```

### 4.4 Repository (`core-data`)

```kotlin
// com.testlogon.android.core.data.locale
@Singleton
class LocaleRepository @Inject constructor(
    private val api: LocaleApi,
    private val store: DataStore<Preferences>,
    private val supported: SupportedLocales,        // from AND-111 resource set
    private val deviceLocaleProvider: DeviceLocaleProvider,
    @Dispatcher(IO) private val io: CoroutineDispatcher,
) {
    /** Cold flow of the resolved preference; recomputes on store changes. */
    val preference: Flow<LocalePreference>

    /** Reconcile against a freshly fetched server value (called post-login / on resume). */
    suspend fun syncFromServer(me: MeDto): ApiResult<LocalePreference>

    /** User-initiated change; persists locally then PUTs to server (FR-4). */
    suspend fun setUserLocale(tag: LocaleTag): ApiResult<LocalePreference>

    /** Retry a previously failed device->server write (FR-6). */
    suspend fun flushPendingSync(): ApiResult<Unit>

    /** Clears the session override so server value can win again. */
    suspend fun clearOverride()
}
```

`SupportedLocales.normalize(tag)` performs FR-5 gating: exact match -> base-language match ->
`en`. `ApiResult<T>` is the project's typed result with `detail` mapping.

### 4.5 Applying the locale to Compose (`core-ui`)

Use `AppCompatDelegate.setApplicationLocales(LocaleListCompat)` as the OS-level mechanism (it
back-ports per-app language on minSdk 24 via `androidx.appcompat`), combined with a composition
local so previews and tests can drive it directly:

```kotlin
// com.testlogon.android.core.ui.locale
val LocalAppLocale = staticCompositionLocalOf<LocaleTag> { error("LocaleProvider missing") }

@Composable
fun LocaleProvider(repository: LocaleRepository, content: @Composable () -> Unit) {
    val pref by repository.preference.collectAsStateWithLifecycle(initialValue = null)
    val tag = pref?.effective ?: rememberDeviceDefaultTag()
    LaunchedEffect(tag) {
        AppCompatDelegate.setApplicationLocales(
            LocaleListCompat.forLanguageTags(tag.value)
        )
    }
    CompositionLocalProvider(LocalAppLocale provides tag, content = content)
}
```

`setApplicationLocales` triggers a configuration change so `stringResource(...)` resolves the
new `values-<lang>` automatically (satisfying FR-2). The composition local is the test seam and
lets non-resource formatting (number/date via `java.text` / `NumberFormat`) read the active tag
without touching the OS state.

### 4.6 Wiring at app start

The single Activity wraps its content in `LocaleProvider`. The session-bootstrap flow
(post `GET /ui/me`, owned by AND-027) calls `localeRepository.syncFromServer(me)` after a
successful fetch; `ON_RESUME` re-runs the fetch+sync through the existing me-refresh path.

## 5. API Contract

Two endpoints. Field names below mirror `frontend/src/api/types.ts`; confirm against
`/openapi.json` before merge.

**Read (via session) — `GET /ui/me`** (200):

```json
{
  "id": "u_8f31",
  "username": "sean",
  "email": "spannella@gmail.com",
  "locale": "es",
  "preferences": { "locale": "es", "timezone": "America/New_York" }
}
```

The app reads `preferences.locale` when present, else top-level `locale`, else null.

**Write — `PUT /ui/preferences`**

Request:

```json
{ "locale": "fr-CA" }
```

`UpdatePreferencesRequest` (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class UpdatePreferencesRequest(@Json(name = "locale") val locale: String)
```

Response (200) `PreferencesDto`:

```json
{ "locale": "fr-CA", "timezone": "America/New_York" }
```

Headers: cookie session + `X-CSRF-Token: <ui_csrf>` (injected by AND-027 interceptor). On 401
the shared interceptor performs one `POST /ui/session/refresh` and retries.

Errors: FastAPI `detail` mapped via the shared parser — `422` (`[{msg}]`) for an invalid/
unsupported locale string, `401` (string) for an expired session, `{code,...}` objects for
typed domain errors. All map to `ApiResult.Failure(detail)`.

## 6. Data & State Management

- **Single source of truth on device:** the `locale_prefs` DataStore. `LocaleRepository.preference`
  is the only `Flow` UI observes; recomposition is automatic on store writes.
- **Reconciliation table** for `syncFromServer` given server `S`, cache `C`, override flag `O`:

  | O (override set this session) | Action |
  |---|---|
  | true  | keep local; do nothing (server does not clobber an explicit in-app choice) |
  | false, `S != C` | adopt `S`, write `KEY_LOCALE=S`, `KEY_SOURCE=SERVER` |
  | false, `S == C` | no-op |
  | false, `S == null` | keep `C` (or device default) |

- **`setUserLocale` ordering:** write DataStore (`OVERRIDE=true`, `PENDING=true`) -> emit new
  `preference` -> `PUT /ui/preferences` -> on success set `PENDING=false`; on failure leave
  `PENDING=true`.
- **Pending flush:** `flushPendingSync()` is invoked opportunistically after any successful
  authenticated response (hook into AND-027's me-refresh). It is a no-op when `PENDING=false`.
- No Room involvement — this is small scalar preference state, DataStore only.

## 7. Error Handling & Resilience

- **Idempotent GET retry:** the `GET /ui/me` fetch uses the project's bounded backoff (e.g. 3
  attempts, jittered) since it is idempotent. The `PUT` is NOT retried automatically beyond the
  one auth refresh; it is queued via `PENDING` and retried opportunistically (FR-6).
- **Timeouts:** rely on the 20s OkHttp call timeout. A timeout on `me` -> keep effective locale,
  no UI error. A timeout on `PUT` -> keep optimistic local value, `PENDING=true`.
- **Unsupported server locale:** `SupportedLocales.normalize` downgrades and logs (§10); never
  throws into the UI.
- **CSRF/401:** delegated entirely to AND-027 interceptors; this ticket assumes one transparent
  refresh-and-retry. A second 401 surfaces as `ApiResult.Failure` and is treated like any sync
  failure (keep local).
- **DataStore read failure:** `catch` on the flow emits the device-default-derived preference so
  the UI always has a locale.

## 8. Security & Privacy

- Locale is low-sensitivity but is personal preference data; it travels only over the existing
  authenticated session. No new credentials, tokens, or PII are added.
- No locale data is logged at value level in release builds beyond the BCP-47 tag (not tied to
  identity in logs); see §10.
- The dev backend is PLAINTEXT HTTP — acceptable for the dev host only. Cleartext is permitted
  via the existing network-security-config dev exception from earlier tickets; this ticket adds
  no new hosts. Production must be HTTPS (inherited constraint).
- CSRF protection on the `PUT` is mandatory and provided by the shared header injection; a
  missing `X-CSRF-Token` must fail closed (server returns 403/401), never silently succeed.

## 9. Accessibility & i18n

- This ticket is itself i18n infrastructure. All user-facing strings introduced (none expected
  beyond reuse) must come from AND-111 resources; the hardcoded-string lint stays enabled.
- RTL: applying an RTL locale (e.g. `ar`, `he`) must flip layout direction. `LocaleProvider`'s
  `setApplicationLocales` drives `LayoutDirection`; verify mirrored layouts when a supported RTL
  locale is added (gated by AND-111's supported set).
- Number/date/plural formatting must follow the effective locale, not the device locale — helpers
  read `LocalAppLocale` (or the active `Locale.getDefault()` after `setApplicationLocales`).
- Accessibility services (TalkBack) announce in the applied locale because the OS configuration
  changes; confirm `contentDescription`s resolve from the localized resources.

## 10. Telemetry & Logging

- Emit a structured event `locale_resolved` with fields `{ effective, source, server_present }`
  on each launch resolution and on adoption of a server change.
- Emit `locale_changed` `{ from, to, origin: "user", synced: bool }` on `setUserLocale`.
- Emit `locale_sync_failed` `{ endpoint, http_status?, detail_code? }` on PUT/me failures
  (sampled / debug-verbose).
- Emit `locale_unsupported_downgrade` `{ requested, applied }` for FR-5 fallbacks.
- Log via the project logging facade; release builds log tags only (no username/id correlation).
  No raw cookies or CSRF tokens are ever logged.

## 11. Testing Strategy

**Unit (`core-testing`, JUnit + Turbine + fakes):**
- `LocaleRepository.syncFromServer` covers all four reconciliation rows in §6.
- `setUserLocale` sets `PENDING` then clears it on `Response.success`; leaves it on failure.
- `SupportedLocales.normalize`: exact, base-language, and unsupported->`en` cases, with
  `locale_unsupported_downgrade` emission asserted.
- `flushPendingSync` no-ops when `PENDING=false`; PUTs when true.

**Network (MockWebServer):**
- `PUT /ui/preferences` sends `{ "locale": ... }` with the `X-CSRF-Token` header and parses
  `PreferencesDto`.
- `GET /ui/me` parses both `preferences.locale` and top-level `locale` shapes.
- 401-then-refresh-then-200 path (using AND-027 interceptor) returns success.
- 422 `[{msg}]` and timeout map to `ApiResult.Failure` without throwing.

**Instrumentation / Compose (acceptance proof, FR-1/FR-2/FR-3):**
- `LocaleProviderTest`: seed DataStore + fake repository with server `locale = "es"`, launch the
  test host, assert a known screen renders the Spanish string resource (e.g.
  `onNodeWithText(context.getString(R.string.x))` in the `es` configuration), then flip the fake
  server to `"fr"`, drive `syncFromServer`, and assert the French string appears without activity
  recreation. This is the testable acceptance criterion.

## 12. Dependencies & Sequencing

- **Depends on AND-111** (i18n plumbing, supported-locale resource set, lint). Hard blocker —
  `SupportedLocales` and `values-<lang>` resources must exist.
- **Depends on AND-027** (`AuthApi`, authenticated session, cookie jar, CSRF interceptor,
  `GET /ui/me`, one-shot refresh-on-401). Hard blocker — locale read/write ride this session.
- **Blocks:** none listed. A user-facing locale-picker screen, if specced separately, would
  consume `LocaleRepository.setUserLocale` and is downstream of this ticket.
- Sequencing: implement `core-model` DTOs -> `LocaleApi` (MockWebServer green) -> DataStore +
  `LocaleRepository` (unit green) -> `LocaleProvider` Compose wiring -> instrumentation
  acceptance test.

## 13. Risks & Open Questions

- **OQ-1:** Is the write endpoint `PUT /ui/preferences` (assumed, mirroring the web app) or a
  dedicated `PUT /ui/me/locale`? Verify against `/openapi.json` and `frontend/src/api/endpoints/*`
  before implementation; the repository abstracts this so only `LocaleApi` changes if wrong.
- **OQ-2:** Does `GET /ui/me` return locale under `preferences.locale`, top-level `locale`, or
  both? Parser handles both defensively (§5); confirm canonical field.
- **OQ-3:** Exact supported-locale set is owned by AND-111; this ticket must not hardcode a list
  independently — it reads `SupportedLocales`.
- **Risk:** `AppCompatDelegate.setApplicationLocales` on minSdk 24 requires the activity to be
  `AppCompatActivity`/use `AppCompatDelegate`; confirm the single Activity meets this or add the
  appcompat delegate. Mitigation: composition-local fallback can render via explicit
  `Configuration` override if needed.
- **Risk:** Unreliable dev backend may make the device->server PUT flaky; mitigated by the
  `PENDING` queue (FR-6) and opportunistic flush.

## 14. Acceptance Criteria

- AC-1 (source ticket): The server's locale preference is reflected in the rendered UI, proven by
  an instrumentation test that sets server `locale` and asserts the visible language (§11
  `LocaleProviderTest`).
- AC-2: Effective-locale precedence (FR-1) is implemented and unit-tested across all
  reconciliation rows (§6).
- AC-3: A locale change via `setUserLocale` persists locally immediately and issues
  `PUT /ui/preferences` with the `X-CSRF-Token` header; on success `PENDING` clears (MockWebServer
  tested).
- AC-4: Locale changes apply without activity recreation (FR-2), verified by the Compose test.
- AC-5: `me`/PUT failures or timeouts never block the UI and never lose the user's chosen locale;
  failed writes are queued and flushed (FR-6), unit-tested.
- AC-6: Unsupported server locales downgrade to base language then `en` and emit
  `locale_unsupported_downgrade` (FR-5), unit-tested.
- AC-7: AND-111 hardcoded-string lint remains green; no new hardcoded user-facing strings.

## 15. Definition of Done

- All §14 acceptance criteria pass in CI (unit + MockWebServer + instrumentation).
- `LocaleApi`, `LocaleRepository`, DataStore keys, `LocaleProvider`, and `LocalAppLocale` merged
  under `com.testlogon.android.*` in the layered modules (`core-network`, `core-data`, `core-ui`,
  `core-model`).
- Single Activity wraps content in `LocaleProvider`; session bootstrap calls `syncFromServer`
  after `GET /ui/me`; resume path re-syncs and flushes pending writes.
- Telemetry events (§10) emitted; no secrets/PII logged.
- `ktlint`/detekt and the AND-111 hardcoded-string lint pass; no new lint baseline entries.
- OQ-1 and OQ-2 resolved against `/openapi.json` and the web reference, with the final field
  names reflected in DTOs and tests.
- Code review approved on branch `android-port`; docs/KDoc on public repository API present.
