---
id: AND-113
title: Server-locale sync
milestone: M2
epic: E16
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-111, AND-027]
blocks: []
---

# AND-113 — Server-locale sync

## 1. Overview & Goal

The TestLogon backend persists a per-user locale preference, exposed through a dedicated
i18n surface: `GET /ui/i18n/locale` (read) and `PUT /ui/i18n/locale` (write). [CORRECTED:
the original draft claimed the preference is returned from `GET /ui/me` and mutated via a
`/ui/preferences` endpoint; neither is true — `MeResp` carries no locale field and there is
no `/ui/preferences` endpoint. See §16.] The native Android port must achieve functional
parity: after a user authenticates, the locale the server reports for that account must be
reflected in the rendered UI, and a locale chosen on Android must be written back to the
server so the preference roams across devices and the web app.

[CORRECTED — web behavior:] On the web reference app the server preference is NOT the live
source of truth for i18n resource selection. `src/i18n/index.ts` configures i18next with
detection order `["localStorage", "navigator"]` (key `i18nextLng`) and `fallbackLng: "en"`;
the `LanguageSwitcher` writes the chosen locale to the server **best-effort** (errors
swallowed) via `saveUserLocale` while persisting locally to `localStorage`. The web app does
not call `getUserLocale` to seed the active language on boot. This Android ticket deliberately
goes **beyond** web parity by making the server value an input to launch-time reconciliation
(FR-1/FR-3); that stronger behavior is an intentional design choice, documented as such.

This ticket connects three layers that already exist or are being built in parallel:

- The on-device i18n plumbing and externalized string resources delivered by **AND-111**.
- The authenticated session (cookie + `Authorization: Bearer` + `X-CSRF-Token`) delivered by
  **AND-027**. (Note: `GET /ui/me` returns only `{ user_sub, session_id, ip }` and does NOT
  carry locale — locale is read from the dedicated `GET /ui/i18n/locale`. See §5/§16.)
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
- **AND-027 (depends_on):** provides `AuthApi` and the authenticated session. Per the web
  client (`src/api/client.ts`): every request sends `credentials: "include"` (cookie jar),
  an `Authorization: Bearer <accessToken>` header when a token is present, and an
  `X-CSRF-Token` header echoing the `ui_csrf` cookie; a single `POST /ui/session/refresh` is
  performed once on a 401 and the request retried. [CORRECTED: `GET /ui/me` is NOT the place
  the server reports locale — `MeResp` = `{ user_sub, session_id, ip }` only. The canonical
  read is `GET /ui/i18n/locale` → `{ locale }`. See §5/§16.]
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (PLAINTEXT,
  unreliable). OpenAPI at `/openapi.json`. FastAPI error `detail` mapping (string |
  `[{msg}]` | `{code,...}`). Design for ~20s timeouts and bounded backoff retry on idempotent
  GETs only.
- **Web reference:** `src/i18n/index.ts` (i18next config + `SUPPORTED_LOCALES`),
  `src/api/endpoints/i18n.ts` (`getLocales`, `getUserLocale`, `saveUserLocale`,
  `getTranslations`), `src/api/endpoints/auth.ts` (`getMe`), `src/api/types.ts` (`MeResp`),
  and `src/api/client.ts` (auth/CSRF/refresh transport). [CORRECTED path: the source app has
  no `frontend/src/i18n.ts`; the real files are under `src/i18n/index.ts` and
  `src/api/endpoints/i18n.ts`.] The OpenAPI spec types the i18n read/write responses as empty
  schemas (`{}`), so the **frontend TypeScript types are the authoritative response shapes**;
  the request body for the PUT is undocumented in OpenAPI and is taken from the frontend.

## 3. Functional Requirements

FR-1 **Resolve effective locale on launch.** On every app start the app computes an effective
locale using a deterministic precedence: (1) an explicit in-app override the user set this
session, else (2) the server preference from the last successful `GET /ui/i18n/locale`
[CORRECTED from `GET /ui/me`], else (3) a
locally cached preference from DataStore, else (4) the device/system default filtered to the
set of supported locales, else (5) the app default (`en`).

FR-2 **Apply without restart.** A change to the effective locale recomposes the UI in the new
language within the same process — no activity recreation required for string/format changes.
(A `Configuration`-based recreate is an acceptable fallback only if a resource cannot be
resolved through the per-composition locale; see §4.)

FR-3 **Sync server -> device.** After login and on each foreground refresh (via
`GET /ui/i18n/locale` [CORRECTED from `GET /ui/me`]), if the server's `locale` differs from the
cached value and the user has NOT set an explicit in-app override during this session, adopt the
server locale and persist it to DataStore.

FR-4 **Sync device -> server.** When the user selects a locale in-app (the picker UI itself may
be a later ticket; this ticket exposes the repository entry point), persist locally immediately
(optimistic) and PUT the preference to the server. On server success, clear any "pending sync"
flag. On failure, keep the local choice and mark it pending for retry.

FR-5 **Supported-locale gating.** Only locales for which `values-<lang>` resources exist (per
AND-111) are selectable/adoptable. A server preference outside the supported set falls back to
the closest base language, then to `en`, and is logged (§10) but not applied verbatim.

FR-6 **Offline / unreliable backend tolerance.** If `GET /ui/i18n/locale` or the locale PUT fails or
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
    // CORRECTED: locale is NOT on /ui/me. Dedicated read endpoint returns { "locale": "<tag>" }.
    @GET("ui/i18n/locale")
    suspend fun getUserLocale(): Response<UserLocaleDto>          // { locale: String }

    // CORRECTED: write is PUT /ui/i18n/locale with body { locale }, response { ok, locale }.
    @PUT("ui/i18n/locale")
    suspend fun saveUserLocale(@Body body: SaveLocaleRequest): Response<SaveLocaleResponse>

    // Optional: public (no-auth) list of supported locales w/ display names + rtl flag.
    @GET("ui/i18n/locales")
    suspend fun listLocales(): Response<LocalesDto>               // { locales: [{ code, name, native_name, rtl }] }
}
```

[CORRECTED] The original draft used `@GET("ui/me")` and `@PUT("ui/preferences")` — neither
serves locale. `MeDto` is irrelevant here (`MeResp` = `{ user_sub, session_id, ip }`). DTOs
deserialized with Moshi; the auth header(s), CSRF header, and cookie jar are applied by the
shared OkHttp interceptors from AND-027 — `LocaleApi` adds nothing auth-specific. Note
`GET /ui/i18n/locales` is documented as public/no-auth and may be called pre-login. All calls
reuse the same `Retrofit` instance (20s call timeout already configured project-wide).

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

    /** Reconcile against a freshly fetched server value (called post-login / on resume).
     *  CORRECTED: takes the locale tag from GET /ui/i18n/locale, not a MeDto. */
    suspend fun syncFromServer(serverLocale: LocaleTag?): ApiResult<LocalePreference>

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

The single Activity wraps its content in `LocaleProvider`. After a successful authenticated
bootstrap (AND-027), the flow issues `GET /ui/i18n/locale` and calls
`localeRepository.syncFromServer(serverLocale)` with the parsed `{ locale }` value
[CORRECTED: previously stated `syncFromServer(me)` off `GET /ui/me`]; `ON_RESUME` re-runs the
i18n-locale fetch+sync and triggers `flushPendingSync()`. Because the locale read is a small,
dedicated, idempotent GET, it can be issued independently of (and in parallel with) the
existing `/ui/me` session-validation call.

## 5. API Contract

[FULLY CORRECTED — the original §5 described `GET /ui/me` and `PUT /ui/preferences` with a
`preferences`/`timezone` shape. None of that matches the sources. Authoritative endpoints
below come from `openapi.index.txt`, `src/api/endpoints/i18n.ts`, and `src/api/types.ts`.]

Two endpoints (plus one optional list endpoint). OpenAPI types the i18n responses as empty
schemas, so the **frontend TS types are authoritative for response shapes**.

**Read (authenticated) — `GET /ui/i18n/locale`** (200):

```json
{ "locale": "es" }
```

`UserLocaleDto` (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class UserLocaleDto(@Json(name = "locale") val locale: String)
```

Maps to web `UserLocaleResponse { locale: string }` in `src/api/endpoints/i18n.ts`. The app
reads the single `locale` field (no `preferences` object exists).

**Write (authenticated) — `PUT /ui/i18n/locale`**

Request body (taken from the frontend; the body is undocumented in OpenAPI):

```json
{ "locale": "fr" }
```

```kotlin
@JsonClass(generateAdapter = true)
data class SaveLocaleRequest(@Json(name = "locale") val locale: String)
```

Response (200) — `SaveLocaleResponse`:

```json
{ "ok": true, "locale": "fr" }
```

```kotlin
@JsonClass(generateAdapter = true)
data class SaveLocaleResponse(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "locale") val locale: String,
)
```

[CORRECTED: response is `{ ok, locale }` (web `Promise<{ ok: boolean; locale: string }>`),
NOT `{ locale, timezone }`.] The web `LanguageSwitcher` treats this write as **best-effort**
(it catches and ignores errors because the locale is also persisted locally) — Android mirrors
that resilience via the `PENDING` queue (FR-6).

**Optional — `GET /ui/i18n/locales`** (200, public/no-auth): `{ "locales": [ { "code": "en",
"name": "English", "native_name": "English", "rtl": false }, … ] }` (web `LocalesResponse` /
`LocaleInfo`). Useful for validating/displaying the supported set; the supported gate itself
remains owned by AND-111 (§13 OQ-3).

Headers: cookie session + `Authorization: Bearer` (when present) + `X-CSRF-Token: <ui_csrf>`,
injected by the AND-027 interceptor (per `src/api/client.ts`). On 401 the shared interceptor
performs one `POST /ui/session/refresh` and retries.

Errors: OpenAPI lists only `200` and `422` for these i18n endpoints. `422` validation errors
have shape `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`
(`HTTPValidationError` → `ValidationError`), i.e. the `[{msg}]` form. `401` (string detail) is
handled by the shared refresh-and-retry. All non-2xx map to `ApiResult.Failure(detail)` via the
shared parser (string | `[{msg}]` | `{code,...}`). [Note: a typed `{code,...}` domain error is
not documented for these specific endpoints; the parser still handles it defensively.]

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
  `preference` -> `PUT /ui/i18n/locale` -> on success (`{ ok, locale }`) set `PENDING=false`; on failure leave
  `PENDING=true`.
- **Pending flush:** `flushPendingSync()` is invoked opportunistically after any successful
  authenticated response (hook into AND-027's me-refresh). It is a no-op when `PENDING=false`.
- No Room involvement — this is small scalar preference state, DataStore only.

## 7. Error Handling & Resilience

- **Idempotent GET retry:** the `GET /ui/i18n/locale` fetch uses the project's bounded backoff (e.g. 3
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
- `PUT /ui/i18n/locale` sends `{ "locale": ... }` with the `X-CSRF-Token` (and `Authorization`
  when present) header and parses `SaveLocaleResponse { ok, locale }`. [CORRECTED endpoint +
  response shape.]
- `GET /ui/i18n/locale` parses `{ "locale": "<tag>" }`. [CORRECTED: no `/ui/me`
  `preferences.locale`/top-level `locale` parsing — that shape does not exist.]
- 401-then-refresh-then-200 path (using AND-027 interceptor) returns success.
- 422 `{ "detail": [{ "loc", "msg", "type" }] }` and timeout map to `ApiResult.Failure`
  without throwing.

**Instrumentation / Compose (acceptance proof, FR-1/FR-2/FR-3):**
- `LocaleProviderTest`: seed DataStore + fake repository with server `locale = "es"`, launch the
  test host, assert a known screen renders the Spanish string resource (e.g.
  `onNodeWithText(context.getString(R.string.x))` in the `es` configuration), then flip the fake
  server to `"fr"`, drive `syncFromServer`, and assert the French string appears without activity
  recreation. This is the testable acceptance criterion.

## 12. Dependencies & Sequencing

- **Depends on AND-111** (i18n plumbing, supported-locale resource set, lint). Hard blocker —
  `SupportedLocales` and `values-<lang>` resources must exist.
- **Depends on AND-027** (`AuthApi`, authenticated session, cookie jar + `Authorization: Bearer`
  + `X-CSRF-Token`, one-shot refresh-on-401). Hard blocker — the locale read/write
  (`GET`/`PUT /ui/i18n/locale`) ride this authenticated session. (AND-027 also owns `GET /ui/me`
  for session validation, but that endpoint carries no locale.)
- **Blocks:** none listed. A user-facing locale-picker screen, if specced separately, would
  consume `LocaleRepository.setUserLocale` and is downstream of this ticket.
- Sequencing: implement `core-model` DTOs -> `LocaleApi` (MockWebServer green) -> DataStore +
  `LocaleRepository` (unit green) -> `LocaleProvider` Compose wiring -> instrumentation
  acceptance test.

## 13. Risks & Open Questions

- **OQ-1 (RESOLVED):** The write endpoint is `PUT /ui/i18n/locale` with body `{ locale }` and
  response `{ ok, locale }` — confirmed in `openapi.index.txt` and `src/api/endpoints/i18n.ts:
  saveUserLocale`. It is NOT `PUT /ui/preferences` (no such endpoint) nor `PUT /ui/me/locale`.
- **OQ-2 (RESOLVED):** `GET /ui/me` does NOT return locale at all — `MeResp` =
  `{ user_sub, session_id, ip }` (`src/api/types.ts:31`). Locale is read from the dedicated
  `GET /ui/i18n/locale` → `{ locale }`. There is no `preferences.locale` field anywhere.
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
  `PUT /ui/i18n/locale` with body `{ locale }` and the `X-CSRF-Token` header; on a
  `{ ok, locale }` 200, `PENDING` clears (MockWebServer tested). [CORRECTED endpoint.]
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
  after `GET /ui/i18n/locale` [CORRECTED from `GET /ui/me`]; resume path re-syncs and flushes
  pending writes.
- Telemetry events (§10) emitted; no secrets/PII logged.
- `ktlint`/detekt and the AND-111 hardcoded-string lint pass; no new lint baseline entries.
- OQ-1 and OQ-2 resolved (see §13/§16): endpoints are `GET`/`PUT /ui/i18n/locale`; DTOs are
  `UserLocaleDto { locale }`, `SaveLocaleRequest { locale }`, `SaveLocaleResponse { ok, locale }`,
  reflected in DTOs and tests.
- Code review approved on branch `android-port`; docs/KDoc on public repository API present.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Locale read endpoint is `GET /ui/i18n/locale` returning `{ locale }`.** VERIFIED (and the
   draft's `GET /ui/me` claim CORRECTED). Source: OpenAPI `GET /ui/i18n/locale`
   (`op=get_user_locale_ui_i18n_locale_get`); `src/api/endpoints/i18n.ts: getUserLocale` →
   `UserLocaleResponse { locale: string }`.
2. **Locale write endpoint is `PUT /ui/i18n/locale`, body `{ locale }`, response `{ ok, locale }`.**
   CORRECTED (draft said `PUT /ui/preferences` with `{ locale, timezone }`). Source: OpenAPI
   `PUT /ui/i18n/locale` (`op=save_user_locale_ui_i18n_locale_put`); `src/api/endpoints/i18n.ts:
   saveUserLocale` → `Promise<{ ok: boolean; locale: string }>`, body `JSON.stringify({ locale })`.
3. **`GET /ui/me` does NOT carry locale; `MeResp = { user_sub, session_id, ip }`.** CORRECTED
   (draft's `/ui/me` JSON with `locale` + `preferences.locale` is fabricated). Source: OpenAPI
   `GET /ui/me` (`op=ui_me_ui_me_get`, resp `200` schema empty); `src/api/types.ts:31 MeResp`;
   `src/api/endpoints/auth.ts: getMe`.
4. **There is no `/ui/preferences` endpoint.** VERIFIED. Source: `openapi.index.txt` — the
   preference endpoints that exist are domain-specific (`/ui/settings/preferences` PATCH,
   `/ui/media/preferences`, `/ui/alerts/type-preferences`, etc.), none named `/ui/preferences`,
   and none is the locale write path.
5. **PUT request body shape is `{ "locale": "<tag>" }`.** Source: `src/api/endpoints/i18n.ts:
   saveUserLocale` (`body: JSON.stringify({ locale })`). VERIFIED against frontend; the OpenAPI
   `requestBody` is absent for this operation (Unverified-assumption from OpenAPI alone — the
   frontend is authoritative here).
6. **PUT/GET i18n responses are typed `{}` (empty) in OpenAPI; frontend TS types are
   authoritative for response shape.** VERIFIED. Source: `openapi.pretty.json` lines ~214091 /
   ~214169 (both `"schema": {}`); shapes taken from `src/api/endpoints/i18n.ts`.
7. **422 validation error shape is `{ detail: [{ loc, msg, type }] }` (the `[{msg}]` form).**
   VERIFIED. Source: OpenAPI `components.schemas.HTTPValidationError` (array of
   `ValidationError { loc, msg, type }`) at `openapi.pretty.json:37133` / `:80337`.
8. **Auth transport = cookies (`credentials: include`) + `Authorization: Bearer <accessToken>`
   (when present) + `X-CSRF-Token` echo of the `ui_csrf` cookie.** VERIFIED (draft mentioned only
   the CSRF echo; the `Authorization: Bearer` header was omitted and is now added). Source:
   `src/api/client.ts` (`headers.set("Authorization", ...)`, `getCookie("ui_csrf")` →
   `X-CSRF-Token`, `credentials: "include"`).
9. **On 401, one `POST /ui/session/refresh` then retry; second 401 → logout/failure.** VERIFIED.
   Source: `src/api/client.ts: refreshSession` + the 401 retry block.
10. **Web app does NOT use the server locale as its live i18n source of truth.** CORRECTED (draft
    claimed it does). Source: `src/i18n/index.ts` (i18next `detection.order = ["localStorage",
    "navigator"]`, `lookupLocalStorage: "i18nextLng"`, `fallbackLng: "en"`); `LanguageSwitcher.tsx`
    reads `i18n.language`/localStorage and only writes the server via `saveUserLocale` best-effort
    (`try { await saveUserLocale } catch {}`). Making the server value drive launch reconciliation
    on Android (FR-1/FR-3) is an intentional design choice beyond web parity (Open assumption O-1).
11. **Supported locale set (web) = `en`, `es`, `fr`; RTL set = `ar`, `he`, `fa`, `ur`.** VERIFIED
    as the web reference set. Source: `src/i18n/index.ts: SUPPORTED_LOCALES` + `RTL_LOCALES`. For
    Android, the authoritative supported set is owned by AND-111 (`SupportedLocales`), not this
    list (§13 OQ-3) — Unverified-assumption that AND-111's set matches the web set.
12. **Public `GET /ui/i18n/locales` returns `{ locales: [{ code, name, native_name, rtl }] }`,
    no auth.** VERIFIED. Source: OpenAPI `GET /ui/i18n/locales` (`params=` empty, no security
    params); `src/api/endpoints/i18n.ts: getLocales` → `LocalesResponse`/`LocaleInfo`.
13. **`AppCompatDelegate.setApplicationLocales(LocaleListCompat)` back-ports per-app language to
    API 24 and triggers a config change so `stringResource` re-resolves.** Verified as framework
    behavior (framework ref:
    https://developer.android.com/guide/topics/resources/app-languages and
    https://developer.android.com/reference/androidx/appcompat/app/AppCompatDelegate#setApplicationLocales(androidx.core.os.LocaleListCompat)).
    The requirement that the host be an `AppCompatActivity` remains a code-level assumption (§13).
14. **Dev backend `http://18.222.237.167:8000` is PLAINTEXT and unreliable; ~20s timeout.**
    Unverified-assumption (carried from the ticket/§2; not checkable from the provided sources).

### Corrections made

- **C-1 / §1, §2, §5, §3 FR-3, FR-1, FR-6, §4.2, §4.4, §4.6, §6, §7, §11, §13, §15, AC-3:**
  replaced the locale **read** path `GET /ui/me` (+ fabricated `preferences.locale` / top-level
  `locale` payload) with the real `GET /ui/i18n/locale` → `{ locale }`.
- **C-2 / §1, §2, §4.2, §5, §6, §11, §13, §15, AC-3:** replaced the locale **write** path
  `PUT /ui/preferences` (+ `{ locale, timezone }` response) with the real `PUT /ui/i18n/locale`,
  body `{ locale }`, response `{ ok, locale }`.
- **C-3 / §1:** corrected the false claim that the web app uses the server preference as the
  i18n source of truth; it uses localStorage/navigator detection and writes the server
  best-effort. Reframed Android's stronger behavior as an intentional design choice.
- **C-4 / §2:** corrected the web-reference file paths (`frontend/src/i18n.ts` →
  `src/i18n/index.ts`; endpoints under `src/api/endpoints/i18n.ts`).
- **C-5 / §2, §5, §12:** added the omitted `Authorization: Bearer` header to the auth-transport
  description (CSRF echo was already correct).
- **C-6 / §4.4:** changed `syncFromServer(me: MeDto)` to `syncFromServer(serverLocale: LocaleTag?)`
  since the value no longer comes from a `MeDto`.
- **C-7 / §13:** marked OQ-1 and OQ-2 RESOLVED with concrete answers.

### Open assumptions

- **O-1:** Android intentionally makes the server locale drive launch-time reconciliation
  (FR-1/FR-3), which the web app does not do. This is a design decision, not verified parity —
  product/UX should confirm the desired precedence vs. pure web parity (server write only).
- **O-2:** The exact PUT request body field name (`locale`) and the `{ ok, locale }` response are
  taken from the frontend because OpenAPI types them as empty/absent. If the backend changes these
  shapes, only `LocaleApi`/DTOs need updating (the repository abstracts them).
- **O-3:** The Android `SupportedLocales` set (owned by AND-111) is assumed to align with the web
  set (`en/es/fr`). Cannot be verified from these sources; AND-111 is the authority.
- **O-4:** `GET /ui/i18n/locale` may return a tag outside the supported set (server is not known
  to gate against the Android resource set); FR-5 normalization handles this defensively.
- **O-5:** Whether the single host Activity is an `AppCompatActivity` (needed for
  `setApplicationLocales` on API 24) is a code-level fact not determinable from the spec sources.
- **O-6:** Dev-host reliability/timeout figures are inherited from the ticket and unverifiable here.

## 17. Test Plan

Acceptance criteria are in §14 (AC-1…AC-7). Test targets: JVM/Robolectric (local), emulator AVD
`test35` (x86_64, API 35), and the physical Samsung Galaxy A15 5G (SM-A156U, serial
R5CX821TA9R, API 34, arm64-v8a). Hardware/ABI-sensitive cases note the required target.

- **TC-AND-113-01 — Reconcile: server differs, no override (adopt server).**
  Type: unit (JVM). Target: JVM/Robolectric. Preconditions: DataStore cached `C="en"`,
  `OVERRIDE=false`; `SupportedLocales={en,es,fr}`. Steps: call
  `syncFromServer(LocaleTag("es"))`. Expected: `KEY_LOCALE="es"`, `KEY_SOURCE=SERVER`,
  `preference.effective="es"`; `ApiResult.Success`. Traces: AC-2.
- **TC-AND-113-02 — Reconcile: override set (server does not clobber).**
  Type: unit (JVM). Target: JVM. Preconditions: `OVERRIDE=true`, cache `C="fr"`. Steps:
  `syncFromServer(LocaleTag("es"))`. Expected: no DataStore write; `effective="fr"`,
  `source=IN_APP_OVERRIDE`. Traces: AC-2, AC-5.
- **TC-AND-113-03 — Reconcile: server == cache, and server == null.**
  Type: unit (JVM). Target: JVM. Preconditions: (a) `C="es"`, `OVERRIDE=false`; (b) `C="es"`,
  server null. Steps: `syncFromServer("es")`; then `syncFromServer(null)`. Expected: both
  no-ops; `effective="es"` retained. Traces: AC-2.
- **TC-AND-113-04 — Effective-locale precedence ladder (FR-1).**
  Type: unit (JVM). Target: JVM. Preconditions: drive each tier in isolation (override > server
  > cache > device-default-filtered > `en`). Steps: configure fakes so only one tier has a value
  per run. Expected: `effective`/`source` match the highest-priority populated tier; empty/all
  → `en`/`DEFAULT`. Traces: AC-2.
- **TC-AND-113-05 — `setUserLocale` happy path clears PENDING.**
  Type: contract/MockWebServer. Target: JVM (MockWebServer). Preconditions: MockWebServer
  enqueues `200 {"ok":true,"locale":"fr"}`. Steps: call `setUserLocale(LocaleTag("fr"))`.
  Expected: request is `PUT /ui/i18n/locale`, JSON body `{"locale":"fr"}`, headers include
  `X-CSRF-Token` (and `Authorization` when a token is set); after success `PENDING=false`,
  `OVERRIDE=true`, `effective="fr"`. Traces: AC-3.
- **TC-AND-113-06 — `setUserLocale` write failure keeps optimistic value + PENDING.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `500` (or socket
  disconnect). Steps: `setUserLocale("fr")`. Expected: local `effective="fr"` immediately,
  `PENDING=true`, `ApiResult.Failure`; no exception thrown; `locale_sync_failed` emitted.
  Traces: AC-3, AC-5.
- **TC-AND-113-07 — Offline/flaky-host: GET timeout keeps effective locale.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer with throttled/no
  response to force the 20s call timeout; cache `C="es"`. Steps: trigger the
  `GET /ui/i18n/locale` sync. Expected: timeout maps to `ApiResult.Failure`, UI keeps `"es"`,
  no blocking error surfaced (FR-6). Traces: AC-5.
- **TC-AND-113-08 — `flushPendingSync` retries when PENDING, no-ops otherwise.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: (a) `PENDING=true`, enqueue `200
  {"ok":true,"locale":"fr"}`; (b) `PENDING=false`. Steps: call `flushPendingSync()` in each.
  Expected: (a) issues `PUT /ui/i18n/locale`, then `PENDING=false`; (b) issues no request.
  Traces: AC-5.
- **TC-AND-113-09 — 401 → refresh → retry succeeds (AND-027 interceptor).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then a `200` for
  `POST /ui/session/refresh`, then `200 {"ok":true,"locale":"fr"}` for the retried PUT. Steps:
  `setUserLocale("fr")`. Expected: exactly one refresh; retried PUT succeeds; `PENDING=false`.
  Traces: AC-3, AC-5.
- **TC-AND-113-10 — 422 unsupported/invalid locale maps to Failure without throwing.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `422 {"detail":[{"loc":
  ["body","locale"],"msg":"invalid locale","type":"value_error"}]}`. Steps: `setUserLocale`
  with a server-rejected tag. Expected: `ApiResult.Failure` carrying the parsed `msg`; no crash;
  local value retained, `PENDING=true`. Traces: AC-3, AC-5.
- **TC-AND-113-11 — Unsupported server locale downgrades (FR-5) + telemetry.**
  Type: unit (JVM). Target: JVM. Preconditions: `SupportedLocales={en,es,fr}`. Steps:
  `SupportedLocales.normalize("fr-CA")` → `fr`; `normalize("de")` → `en`. Expected: base-language
  match then `en` fallback; `locale_unsupported_downgrade {requested, applied}` emitted on the
  `de`→`en` case. Traces: AC-6.
- **TC-AND-113-12 — Acceptance proof: server locale flip changes UI without recreation.**
  Type: Compose-UI / instrumented. Target: emulator AVD `test35` (fast CI run). Preconditions:
  fake repository seeded with server `locale="es"`, test host wrapped in `LocaleProvider`.
  Steps: launch and assert a known screen shows the Spanish string
  (`onNodeWithText(context.getString(R.string.x))` resolved in `es`); flip the fake server to
  `"fr"`, drive `syncFromServer("fr")`; assert the French string appears and the Activity
  instance is unchanged (no recreation). Expected: visible language updates in-process.
  Traces: AC-1, AC-4.
- **TC-AND-113-13 — RTL locale flips layout direction.**
  Type: Compose-UI / instrumented. Target: emulator AVD `test35` (run on the physical A15 only
  if validating real on-device mirroring). Preconditions: an RTL locale (e.g. `ar`) present in
  AND-111's supported set. Steps: apply `ar` via `LocaleProvider`. Expected:
  `LocalLayoutDirection == Rtl`, mirrored layout. If no RTL locale is in the supported set, mark
  SKIPPED with reason (gated by AND-111, see O-3). Traces: AC-1, AC-2 (RTL aspect of §9).
- **TC-AND-113-14 — Accessibility: TalkBack announces in the applied locale.**
  Type: instrumented/e2e. Target: PHYSICAL DEVICE (Samsung Galaxy A15, API 34) — TalkBack is a
  real accessibility service best exercised on hardware (and validates API-34/arm64 behavior vs
  the API-35 emulator). Preconditions: server `locale="es"`, TalkBack enabled. Steps: navigate a
  localized screen with TalkBack on. Expected: `contentDescription`s resolve from the localized
  (`es`) resources and are announced in Spanish; no hardcoded-string leakage. Traces: AC-1, AC-7.
- **TC-AND-113-15 — Persistence across reinstall/relogin (roaming).**
  Type: instrumented/e2e. Target: PHYSICAL DEVICE (full reinstall lifecycle + real auth).
  Preconditions: server `locale="fr"` for the test account. Steps: set a different local locale,
  uninstall, reinstall, relogin; allow the `GET /ui/i18n/locale` sync to run. Expected: UI
  reflects the server `"fr"` (FR-7) since DataStore was cleared and no in-app override exists.
  Traces: AC-1, AC-5.
- **TC-AND-113-16 — Security: missing CSRF must fail closed.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: simulate the interceptor omitting
  `X-CSRF-Token`; MockWebServer asserts the header absence and returns `403`. Steps: attempt
  `setUserLocale`. Expected: the PUT does not silently succeed — `403` maps to
  `ApiResult.Failure`, local value retained, `PENDING=true`; no token/cookie logged. Traces:
  AC-3, AC-5 (and §8 fail-closed requirement).

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (server locale reflected in UI) | TC-12, TC-13, TC-14, TC-15 |
| AC-2 (precedence + reconciliation rows) | TC-01, TC-02, TC-03, TC-04, TC-11 (RTL: TC-13) |
| AC-3 (`setUserLocale` → `PUT /ui/i18n/locale`, PENDING clears) | TC-05, TC-06, TC-09, TC-10, TC-16 |
| AC-4 (apply without activity recreation) | TC-12 |
| AC-5 (failures/timeouts never block or lose locale; queued + flushed) | TC-02, TC-06, TC-07, TC-08, TC-09, TC-10, TC-15, TC-16 |
| AC-6 (unsupported downgrade + telemetry) | TC-11 |
| AC-7 (hardcoded-string lint green / no new hardcoded strings) | TC-14 |
