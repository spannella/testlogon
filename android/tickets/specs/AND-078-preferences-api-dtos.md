---
id: AND-078
title: Preferences API + DTOs
milestone: M2
epic: E11
priority: P0
size: M
depends_on:
  - AND-027
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-078 — Preferences API + DTOs

## 1. Overview & Goal

This ticket delivers the network and data layer for **user preferences** in the
TestLogon native Android app: the Retrofit API surface, the Moshi DTOs that mirror
the FastAPI preferences contract, the `core-model` domain types, and a
`PreferencesRepository` that exposes load/save operations as suspend functions
returning `ApiResult<T>`. It is the Android port of the web reference's
`src/api/endpoints/preferences.ts` (canonical types live there as `UiPreferences`,
not in `src/api/types.ts`).

The deliverable is **non-UI**. No Compose screens, ViewModels, or navigation are in
scope here; those are owned by the downstream settings/preferences feature ticket
in epic E11. The goal is a fully tested, dependency-injectable repository that
returns mapped domain models and surfaces typed errors, so that feature code can
consume preferences without knowing about Retrofit, Moshi, cookies, or CSRF.

Success means: a caller can call `repository.getPreferences()` and
`repository.updatePreferences(patch)`, receive `ApiResult.Success(UserPreferences)`
on the happy path, and receive a mapped `ApiResult.Failure` (with the FastAPI
`detail` decoded) on every error path — all verified by MockWebServer tests.

> **Reviewer note (corrected):** The backend `PATCH /ui/settings/preferences` does
> **not** return the updated preferences; it returns `{"ok": true}`. Therefore
> `updatePreferences(patch)` cannot read back server-truth from the PATCH response.
> It returns `ApiResult<Unit>` (save acknowledged) — or, if callers need the merged
> state, the repository performs a follow-up `GET`. See §5.2 and §6.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. Code lands in `core-network` (API + DTOs + mappers) and
  `core-data` (repository), under namespace `com.testlogon.android`.
- **Web reference:** `src/api/endpoints/preferences.ts` (endpoint shapes, `UiPreferences`
  interface, `PreferencesPatchReq` body). Note: there is **no** `UserPreferences` type in
  `src/api/types.ts`; the web type is `UiPreferences` declared in `preferences.ts`.
- **OpenAPI:** authoritative request/response schema at
  `http://18.222.237.167:8000/openapi.json` — verify field names/optionality before
  finalizing DTOs; this spec records the expected shape but OpenAPI wins on conflict.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** preferences are a
  **cookie-authenticated** resource. This ticket reuses the shared, persistent cookie
  jar, the `X-CSRF-Token` echo of the `ui_csrf` cookie, and the 401 → single
  `POST /ui/session/refresh` → retry behavior established by the auth/network stack
  (AND-026/AND-027). It does **not** re-implement any of that; it depends on the
  configured `OkHttpClient`/`Retrofit` and the `ApiResult` + error-mapping utilities.
- **Stack:** Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 (codegen via KSP),
  Coroutines/Flow, Hilt (KSP). minSdk 24, JDK 17.
- **Backend caveat:** dev host is plaintext HTTP and unreliable; ~20s timeouts and
  bounded backoff retry on the idempotent `GET` only.

## 3. Functional Requirements

FR-1. Provide a Retrofit `PreferencesApi` with a `GET` to load the current user's
preferences and a `PATCH` (partial update) to save changes.

FR-2. Define Moshi DTOs (`PreferencesDto`, `UpdatePreferencesRequestDto`) that
exactly mirror the backend JSON, including nullability and snake_case field names
via `@Json(name=...)`.

FR-3. Define a domain model `UserPreferences` in `core-model` (no JSON annotations,
no nullable-for-wire concessions where the domain has sensible defaults).

FR-4. Provide pure mapper functions `PreferencesDto.toDomain()` and
`UserPreferences.toUpdateRequest(...)` / a patch builder, isolating wire concerns.

FR-5. Provide `PreferencesRepository` with:
- `suspend fun getPreferences(): ApiResult<UserPreferences>`
- `suspend fun updatePreferences(patch: PreferencesPatch): ApiResult<UserPreferences>`

FR-6. The `GET` path must be treated as idempotent and eligible for bounded backoff
retry; the `PATCH` path must **not** be retried on network failure.

FR-7. All FastAPI error shapes for `detail` (string | `[{msg}]` | `{code,...}`) must
be decoded into the shared domain error type and returned via `ApiResult.Failure`.

FR-8. The repository must be Hilt-injectable (`@Inject constructor`) and bound via a
module so feature code depends on the interface, not the implementation.

FR-9. Save semantics are **partial update**: only fields present in `PreferencesPatch`
are serialized; absent fields must be omitted from the JSON body (not sent as null).

## 4. Technical Design

### 4.1 Module placement

```
core-model/   -> UserPreferences, ThemeMode, PreferencesPatch (pure Kotlin)
core-network/ -> PreferencesApi, *Dto, mappers, error decoding (shared)
core-data/    -> PreferencesRepository (interface + impl), Hilt module
```

### 4.2 Domain model (`core-model`)

```kotlin
package com.testlogon.android.core.model

enum class ThemeMode { SYSTEM, LIGHT, DARK }
enum class AccentColor { BLUE, PURPLE, GREEN, ORANGE, PINK, RED, TEAL, CUSTOM }
enum class FontSize { SMALL, DEFAULT, LARGE, XLARGE }
enum class Density { COMPACT, COMFORTABLE, SPACIOUS }

data class UserPreferences(
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val sidebarCollapsed: Boolean = false,
    val accentColor: AccentColor = AccentColor.BLUE,
    val customAccentHex: String? = null,   // <=7 chars, e.g. "#1a2b3c"
    val fontSize: FontSize = FontSize.DEFAULT,
    val density: Density = Density.COMFORTABLE,
    val highContrast: Boolean = false,
)

/** Partial update. Null field == "leave unchanged" (omitted from request body). */
data class PreferencesPatch(
    val theme: ThemeMode? = null,
    val sidebarCollapsed: Boolean? = null,
    val accentColor: AccentColor? = null,
    val customAccentHex: String? = null,
    val fontSize: FontSize? = null,
    val density: Density? = null,
    val highContrast: Boolean? = null,
)
```

> **Corrected against authoritative sources.** The fields above are the verified set
> from `PreferencesPatchReq` (OpenAPI) and the `UiPreferences` interface in
> `src/api/endpoints/preferences.ts`. The original draft's fields (`locale`,
> `emailNotifications`, `pushNotifications`, `autoplayVideo`, `updatedAt`) do **not**
> exist in the contract and have been removed. Enum value sets:
> theme = `system|light|dark`; accent_color = `blue|purple|green|orange|pink|red|teal|custom`;
> font_size = `small|default|large|xlarge`; density = `compact|comfortable|spacious`.
> Defaults are app-side fallbacks: the GET response returns **only** explicitly-set keys
> ("Missing keys mean the frontend should use its default value" — per the OpenAPI
> description), so the domain model supplies defaults for absent keys.

### 4.3 DTOs (`core-network`)

```kotlin
package com.testlogon.android.core.network.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

// GET /ui/settings/preferences returns a WRAPPER: {"preferences": { ...keys... }}
@JsonClass(generateAdapter = true)
data class PreferencesEnvelopeDto(
    @Json(name = "preferences") val preferences: PreferencesDto = PreferencesDto(),
)

@JsonClass(generateAdapter = true)
data class PreferencesDto(
    @Json(name = "theme") val theme: String? = null,
    @Json(name = "sidebar_collapsed") val sidebarCollapsed: Boolean? = null,
    @Json(name = "accent_color") val accentColor: String? = null,
    @Json(name = "custom_accent_hex") val customAccentHex: String? = null,
    @Json(name = "font_size") val fontSize: String? = null,
    @Json(name = "density") val density: String? = null,
    @Json(name = "high_contrast") val highContrast: Boolean? = null,
)

// PATCH /ui/settings/preferences body == PreferencesPatchReq (same field names).
@JsonClass(generateAdapter = true)
data class UpdatePreferencesRequestDto(
    @Json(name = "theme") val theme: String? = null,
    @Json(name = "sidebar_collapsed") val sidebarCollapsed: Boolean? = null,
    @Json(name = "accent_color") val accentColor: String? = null,
    @Json(name = "custom_accent_hex") val customAccentHex: String? = null,
    @Json(name = "font_size") val fontSize: String? = null,
    @Json(name = "density") val density: String? = null,
    @Json(name = "high_contrast") val highContrast: Boolean? = null,
)

// PATCH response body == {"ok": true}; the repository does not read prefs back from it.
@JsonClass(generateAdapter = true)
data class OkResponseDto(
    @Json(name = "ok") val ok: Boolean = false,
)
```

> **Corrected:** GET wraps the prefs object as `{"preferences": {...}}` (decode the
> envelope, then `.preferences`). PATCH responds `{"ok": true}` — there is no updated
> body to map. Field names verified against `PreferencesPatchReq` (OpenAPI) and
> `UiPreferences` (`src/api/endpoints/preferences.ts`).

For partial-update semantics, the request adapter must **omit nulls**. Configure the
shared Moshi instance with `.serializeNulls()` **disabled** (the default), so any
`null` field in `UpdatePreferencesRequestDto` is excluded from the emitted JSON.
This makes "field absent" == "leave unchanged" on the wire.

### 4.4 Retrofit API (`core-network`)

```kotlin
package com.testlogon.android.core.network.preferences

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH

interface PreferencesApi {

    @GET("ui/settings/preferences")
    suspend fun getPreferences(): Response<PreferencesEnvelopeDto>

    @PATCH("ui/settings/preferences")
    suspend fun updatePreferences(
        @Body body: UpdatePreferencesRequestDto,
    ): Response<OkResponseDto>
}
```

> **Corrected paths/return types:** the endpoint is `ui/settings/preferences`
> (not `ui/preferences`). GET returns the `{"preferences": {...}}` envelope; PATCH
> returns `{"ok": true}`. Verified: OpenAPI `GET /ui/settings/preferences`,
> `PATCH /ui/settings/preferences`; frontend `src/api/endpoints/preferences.ts`.

Returning `Response<T>` (not raw `T`) lets the repository inspect status codes and
the error body for `detail` mapping. The CSRF header and cookies are injected by the
shared OkHttp interceptors/cookie jar from AND-026/AND-027 — not declared here.

### 4.5 Mappers (`core-network`)

```kotlin
internal fun PreferencesEnvelopeDto.toDomain(): UserPreferences = preferences.toDomain()

internal fun PreferencesDto.toDomain(): UserPreferences = UserPreferences(
    theme = theme.toThemeModeOrDefault(),
    sidebarCollapsed = sidebarCollapsed ?: false,
    accentColor = accentColor.toAccentColorOrDefault(),
    customAccentHex = customAccentHex,
    fontSize = fontSize.toFontSizeOrDefault(),
    density = density.toDensityOrDefault(),
    highContrast = highContrast ?: false,
)

private fun String?.toThemeModeOrDefault(): ThemeMode = when (this?.lowercase()) {
    "light" -> ThemeMode.LIGHT
    "dark" -> ThemeMode.DARK
    "system", null -> ThemeMode.SYSTEM
    else -> ThemeMode.SYSTEM // unknown server value -> safe default
}

private fun String?.toAccentColorOrDefault(): AccentColor = when (this?.lowercase()) {
    "purple" -> AccentColor.PURPLE
    "green" -> AccentColor.GREEN
    "orange" -> AccentColor.ORANGE
    "pink" -> AccentColor.PINK
    "red" -> AccentColor.RED
    "teal" -> AccentColor.TEAL
    "custom" -> AccentColor.CUSTOM
    "blue", null -> AccentColor.BLUE
    else -> AccentColor.BLUE
}

private fun String?.toFontSizeOrDefault(): FontSize = when (this?.lowercase()) {
    "small" -> FontSize.SMALL
    "large" -> FontSize.LARGE
    "xlarge" -> FontSize.XLARGE
    "default", null -> FontSize.DEFAULT
    else -> FontSize.DEFAULT
}

private fun String?.toDensityOrDefault(): Density = when (this?.lowercase()) {
    "compact" -> Density.COMPACT
    "spacious" -> Density.SPACIOUS
    "comfortable", null -> Density.COMFORTABLE
    else -> Density.COMFORTABLE
}

internal fun PreferencesPatch.toRequestDto(): UpdatePreferencesRequestDto =
    UpdatePreferencesRequestDto(
        theme = theme?.name?.lowercase(),
        sidebarCollapsed = sidebarCollapsed,
        accentColor = accentColor?.name?.lowercase(),
        customAccentHex = customAccentHex,
        fontSize = fontSize?.name?.lowercase(),
        density = density?.name?.lowercase(),
        highContrast = highContrast,
    )
```

> Enum `.name.lowercase()` is safe here because every Kotlin enum constant name maps
> 1:1 to the lowercase wire token (e.g. `XLARGE` -> `"xlarge"`). Verified against the
> enum value sets in `PreferencesPatchReq` (OpenAPI).

### 4.6 Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.preferences

interface PreferencesRepository {
    suspend fun getPreferences(): ApiResult<UserPreferences>
    /**
     * Saves the patch. The backend acknowledges with {"ok": true} and does NOT
     * echo the merged preferences, so this returns the locally-applied result:
     * the patch merged onto the last-known/fetched preferences. If callers require
     * authoritative server state, call getPreferences() afterwards (see §6).
     */
    suspend fun updatePreferences(patch: PreferencesPatch): ApiResult<UserPreferences>
}

internal class DefaultPreferencesRepository @Inject constructor(
    private val api: PreferencesApi,
    private val errorMapper: ApiErrorMapper,           // shared, decodes `detail`
    @IoDispatcher private val io: CoroutineDispatcher,
) : PreferencesRepository {

    override suspend fun getPreferences(): ApiResult<UserPreferences> =
        withContext(io) {
            safeApiCall(errorMapper) { api.getPreferences() }
                .map { it.toDomain() } // unwraps {"preferences":{...}} -> UserPreferences
        }

    override suspend fun updatePreferences(
        patch: PreferencesPatch,
    ): ApiResult<UserPreferences> = withContext(io) {
        // PATCH returns {"ok": true} only; re-fetch for authoritative merged state.
        when (val save = safeApiCall(errorMapper) { api.updatePreferences(patch.toRequestDto()) }) {
            is ApiResult.Success -> safeApiCall(errorMapper) { api.getPreferences() }.map { it.toDomain() }
            is ApiResult.Failure -> save
        }
    }
}
```

> **Corrected:** the previous `.map { it.toDomain() }` on the PATCH response was wrong
> — the PATCH body is `{"ok": true}`, not a `PreferencesDto`. The repository now either
> (a) returns the locally-merged patch, or (b) issues a follow-up GET to obtain
> server-truth (shown above). Pick one per the consumer's needs; both are valid given
> the contract. If a follow-up GET is undesirable on the unreliable dev host, prefer
> `ApiResult<Unit>` for `updatePreferences` and let the feature layer apply the patch
> optimistically (matches the web client's fire-and-forget behavior).

`safeApiCall` is the shared helper (from the network core) that wraps a
`suspend () -> Response<T>`, converts HTTP/transport/parse failures into
`ApiResult.Failure`, and decodes the FastAPI `detail` body. The repository adds no
network logic of its own beyond dispatching to IO and mapping DTO → domain.

### 4.7 Hilt wiring (`core-data`)

```kotlin
@Module
@InstallIn(SingletonComponent::class)
internal abstract class PreferencesDataModule {
    @Binds
    abstract fun bindPreferencesRepository(
        impl: DefaultPreferencesRepository,
    ): PreferencesRepository
}

@Module
@InstallIn(SingletonComponent::class)
internal object PreferencesNetworkModule {
    @Provides
    fun providePreferencesApi(retrofit: Retrofit): PreferencesApi =
        retrofit.create(PreferencesApi::class.java)
}
```

## 5. API Contract

Base URL (dev): `http://18.222.237.167:8000/`. Both calls require the session cookie
and the `X-CSRF-Token: <ui_csrf>` header (added by shared interceptors).

### 5.1 Load — `GET /ui/settings/preferences`

Request: no body. Response `200` is a **wrapper** containing only the explicitly-set
keys (missing keys → use app default):

```json
{
  "preferences": {
    "theme": "dark",
    "accent_color": "teal",
    "font_size": "large",
    "density": "compact",
    "high_contrast": true,
    "sidebar_collapsed": false,
    "custom_accent_hex": "#1a2b3c"
  }
}
```

### 5.2 Save — `PATCH /ui/settings/preferences`

Request body (`PreferencesPatchReq`; only changed fields present, nulls omitted):

```json
{ "theme": "light", "accent_color": "purple" }
```

Response `200`:

```json
{ "ok": true }
```

> **Corrected:** PATCH does **not** return the updated preferences — it returns
> `{"ok": true}`. The repository therefore cannot map the PATCH response to
> `UserPreferences`; to obtain server-truth after a save it must issue a follow-up
> `GET` (see §4.6), or apply the patch locally. Verified: OpenAPI
> `PATCH /ui/settings/preferences` (description: "Returns {\"ok\": True} on success");
> frontend `patchPreferences` returns `Promise<void>` (fire-and-forget).

### 5.3 Error responses (FastAPI `detail`)

- `401 Unauthorized` — handled by shared 401 interceptor: one
  `POST /ui/session/refresh` then retry; if still 401 → `ApiResult.Failure(Unauthorized)`.
- `403 Forbidden` — missing/stale CSRF → `Failure` with mapped message.
- `422 Unprocessable Entity` — validation list form:
  ```json
  { "detail": [ { "loc": ["body","theme"], "msg": "value is not a valid enumeration member", "type": "value_error" } ] }
  ```
- `4xx/5xx` string or object form:
  ```json
  { "detail": "preferences temporarily unavailable" }
  { "detail": { "code": "RATE_LIMITED", "retry_after": 5 } }
  ```

All three `detail` shapes (string | `[{msg}]` | `{code,...}`) decode through the
shared `ApiErrorMapper` into the typed domain error carried by `ApiResult.Failure`.
This mirrors the web client's `normalizeErrorDetail` (`src/api/client.ts`), which
handles exactly these shapes (string, array-of-`{msg}`, and object-with-`code` via
`mapAuthorizationError`).

> **Verification note:** OpenAPI documents only `200` and `422` (`HTTPValidationError`,
> i.e. `{"detail":[{loc,msg,type}]}`) for these two endpoints. `401`/`403`/`5xx` are
> **not** declared per-endpoint; they are produced and handled **globally** by the
> shared transport layer (`src/api/client.ts`: 401→refresh→retry; 403 detail mapping;
> generic non-2xx → `ApiError(status, normalizeErrorDetail(detail))`). The 422 list
> shape is verified against the OpenAPI `ValidationError` schema (`loc`, `msg`, `type`).
> Treat the 4xx-string and `{code,...}` examples below as plausible-but-not-endpoint-
> documented shapes the shared mapper must still handle (covered globally).
>
> **Corrected:** endpoint path is `ui/settings/preferences` (not `ui/preferences`);
> verb is `PATCH` (confirmed — not `PUT`). OQ-2 is now resolved.

## 6. Data & State Management

This ticket owns the **network/repository** layer only; it holds no in-memory or
on-disk state. There is no Room caching and no DataStore persistence here — the
repository performs a live fetch/patch and returns mapped results.

- **No local cache (this ticket):** `getPreferences()` always hits the network.
  A DataStore-backed cache + a `StateFlow<PreferencesUiState>` are the responsibility
  of the downstream E11 settings feature ticket, which will layer over this repo.
- **Save → state update (corrected):** the backend PATCH returns only `{"ok": true}`,
  **not** the updated preferences. So "read-through from the PATCH response" is not
  possible. The repository instead either (a) issues a follow-up `GET` to obtain
  server-truth, or (b) returns the locally-merged patch / `Unit` and lets the feature
  layer apply the change optimistically (matching the web client's fire-and-forget
  `patchPreferences`). The follow-up-GET option costs one extra round trip on the
  unreliable dev host; choose per consumer needs.
- **Threading:** all calls run on `@IoDispatcher`; the repository is stateless and
  therefore thread-safe; it is provided as a `@Singleton`-scoped binding.
- **Patch builder:** `PreferencesPatch` is the unit of change. Constructing it with
  only the fields the user toggled guarantees minimal, null-omitting request bodies.

## 7. Error Handling & Resilience

- **Result type:** every public method returns `ApiResult<UserPreferences>`; no
  exceptions cross the repository boundary. Cancellation
  (`CancellationException`) is rethrown, never swallowed.
- **Timeouts:** rely on the shared OkHttp client (~20s call/connect/read timeouts)
  configured for the unreliable dev host.
- **Retry policy:**
  - `GET /ui/settings/preferences` is idempotent → eligible for the shared **bounded
    backoff retry** (e.g., max 2 retries, jittered backoff) on transport errors / `5xx`.
  - `PATCH /ui/settings/preferences` is **not idempotent** → **no automatic retry**; a failed
    save returns `Failure` and the feature layer surfaces a retry affordance.
- **Auth refresh:** the shared interceptor performs at most one
  `POST /ui/session/refresh` on `401` and replays the original request; a second
  `401` yields `ApiResult.Failure(Unauthorized)`.
- **Parse failures:** malformed/missing fields map to a typed
  `Failure(Parse/Unexpected)` rather than crashing; unknown enum values for `theme`
  fall back to `ThemeMode.SYSTEM` (lenient read, strict write).
- **Offline:** `IOException` (no connectivity) maps to `Failure(Network)` so the
  feature can render an offline/stale state.

## 8. Security & Privacy

- **Cookie-based auth:** session rides on the shared persistent cookie jar; this
  ticket adds no token handling and stores no credentials.
- **CSRF:** mutating `PATCH` requires the `X-CSRF-Token` header echoing the `ui_csrf`
  cookie; provided by the shared interceptor. Verify in tests that the header is
  present on the `PATCH` request.
- **Transport:** dev backend is plaintext HTTP; release builds must use HTTPS and a
  network-security-config that forbids cleartext for production hosts (owned by the
  network-config ticket; this repo must not pin the cleartext dev host into release).
- **PII:** preferences may include `locale`; treat the payload as user data. Do not
  log full request/response bodies at `INFO`+; redact in any logging interceptor
  (body logging only in debug builds).
- **No secrets** are introduced by this ticket.

## 9. Accessibility & i18n

No UI is delivered here, so there are no direct a11y obligations (owned by the E11
settings screen ticket). i18n touchpoints relevant to this layer:

- **Corrected:** there is **no** `locale` field in this preferences contract (the
  original draft assumed one). Locale/language selection is not part of
  `/ui/settings/preferences`. The UI preference fields here (`theme`, `accent_color`,
  `font_size`, `density`, `high_contrast`, `sidebar_collapsed`, `custom_accent_hex`)
  are enum/boolean/string tokens passed through verbatim; the repository does not
  interpret or localize them.
- Error messages returned in `detail` are server strings; the repository surfaces the
  raw message via the typed error. User-facing localization of error copy is the
  feature layer's responsibility — do not hardcode English UI strings in core.

## 10. Telemetry & Logging

- **Structured logs (debug only):** log `GET`/`PATCH` outcome as
  `prefs_load_result` / `prefs_save_result` with fields `{ status, durationMs,
  errorCode }` — never the body, never preference field values at INFO.
- **Metrics hooks:** emit a counter for save success/failure and a latency timing for
  load, via the shared analytics abstraction if present; otherwise leave a TODO
  referencing the telemetry ticket. No new analytics SDK is added here.
- **OkHttp logging:** rely on the shared `HttpLoggingInterceptor` set to `BODY` only
  in debug, `NONE` in release.

## 11. Testing Strategy

All tests use **MockWebServer** + the real Moshi/Retrofit config (in `core-testing`),
plus JUnit, Truth/assertk, and coroutines-test. Acceptance is "Preferences load/save
(tested)".

**Repository / API (MockWebServer):**
1. `getPreferences` 200 → parses the `{"preferences":{...}}` envelope → `Success(UserPreferences)`
   with all fields mapped (including `theme="dark"` → `ThemeMode.DARK`, `accent_color="teal"`
   → `AccentColor.TEAL`).
2. `getPreferences` enqueues recorded request → asserts method `GET`, path
   `/ui/settings/preferences`.
3. `updatePreferences` with `PreferencesPatch(theme=LIGHT, accentColor=PURPLE)` →
   recorded request body contains **only** `theme` and `accent_color` (assert
   absent keys for unset fields → null-omission verified).
4. `updatePreferences` PATCH 200 `{"ok":true}` → repository follow-up `GET` returns the
   merged prefs → `Success` reflecting server values (two recorded requests: PATCH then GET).
5. `updatePreferences` recorded PATCH request carries `X-CSRF-Token` header.
6. Error mapping: 422 list `detail`, 4xx string `detail`, 5xx object `detail` each →
   `Failure` with the expected mapped code/message (one test per shape).
7. 401 once → refresh → retry success (using shared interceptor harness); 401 twice →
   `Failure(Unauthorized)`.
8. `getPreferences` transport error retried (bounded); `updatePreferences` transport
   error **not** retried (assert single dispatched request).
9. Lenient read: unknown `theme`/`accent_color`/`font_size`/`density` value → safe
   default (`SYSTEM`/`BLUE`/`DEFAULT`/`COMFORTABLE`); missing keys → domain defaults;
   empty `{"preferences":{}}` → all-defaults `UserPreferences`.

**Mapper unit tests (pure, no network):** `PreferencesDto.toDomain()` and
`PreferencesPatch.toRequestDto()` round-trip and default behavior.

**DI test:** Hilt graph resolves `PreferencesRepository` and `PreferencesApi`.

Coverage target: ≥ 90% lines on mappers and repository.

## 12. Dependencies & Sequencing

- **Depends on AND-027 (AuthApi / session endpoints)** and, transitively, the network
  core (cookie jar, CSRF interceptor, 401-refresh, `Retrofit`/`OkHttp`/Moshi config,
  `ApiResult`, `ApiErrorMapper`, `safeApiCall`). This ticket must not start until the
  shared `Retrofit` instance and error-mapping utilities are merged.
- **Blocks:** the downstream E11 settings/preferences **feature** ticket (UI +
  ViewModel + DataStore cache), which consumes `PreferencesRepository`. (No AND-### id
  for that feature is provided in this ticket's source bullets; this spec records the
  consumer dependency without inventing an id.)
- **Sequencing:** land `core-model` types → DTOs + mappers + API in `core-network` →
  repository + Hilt module in `core-data` → tests. Single PR is acceptable given the
  size.

## 13. Risks & Open Questions

- **OQ-1 (field set): RESOLVED.** Verified fields = `theme`, `sidebar_collapsed`,
  `accent_color`, `custom_accent_hex` (≤7 chars), `font_size`, `density`,
  `high_contrast` (source: `PreferencesPatchReq` in OpenAPI; `UiPreferences` in
  `src/api/endpoints/preferences.ts`). The draft's `locale`/`email_notifications`/
  `push_notifications`/`autoplay_video`/`updated_at` do not exist and were removed.
- **OQ-2 (verb/path): RESOLVED.** Verb is `PATCH`; path is `/ui/settings/preferences`
  (not `/ui/preferences` or `/ui/me/preferences`). GET response is the
  `{"preferences": {...}}` envelope. Source: OpenAPI + frontend endpoint file.
- **OQ-3 (partial update support): RESOLVED.** The backend natively supports
  `PATCH` merge semantics ("only provided fields are merged"); a GET-merge-PUT flow is
  **not** required. However, PATCH returns only `{"ok": true}` (not the merged doc), so
  obtaining server-truth after a save requires a follow-up `GET` (see §4.6/§6).
- **OQ-4 (related endpoint, NEW):** `POST /ui/settings/validate-color`
  (`validate_custom_color_ui_settings_validate_color_post`) validates `custom_accent_hex`
  and returns contrast/WCAG info (`ValidateColorResponse` in the frontend). It is used
  by the settings UI before saving a custom accent. It is arguably in-scope for the
  preferences API surface; decide whether to include it here or defer to the E11 feature
  ticket. Currently treated as **out of scope** for AND-078 (color validation is a
  UI-driven concern), flagged for the downstream owner.
- **Risk:** unreliable dev host produces flaky integration runs — mitigated by using
  MockWebServer for all CI tests and treating live-host calls as manual smoke only.
- **Risk:** Moshi null-omission misconfiguration would send `null` for unset fields,
  unintentionally clearing them server-side — explicitly covered by test #3.

## 14. Acceptance Criteria

- AC-1. `PreferencesApi` exposes `GET ui/settings/preferences` (returns
  `Response<PreferencesEnvelopeDto>`) and `PATCH ui/settings/preferences` (returns
  `Response<OkResponseDto>`); paths/verbs/bodies match the contract (MockWebServer-verified).
- AC-2. `PreferencesRepository.getPreferences()` returns
  `ApiResult.Success(UserPreferences)` with all fields correctly mapped on `200`,
  unwrapping the `{"preferences": {...}}` envelope and applying domain defaults for
  absent keys.
- AC-3. `PreferencesRepository.updatePreferences(patch)` sends a body containing
  **only** the fields set in the patch (nulls omitted). Because PATCH responds
  `{"ok": true}` (no merged document), the repository obtains the resulting
  `UserPreferences` via a follow-up `GET` (or returns the locally-merged patch / `Unit`,
  per the chosen variant in §4.6); it does **not** parse the PATCH body as preferences.
- AC-4. All three FastAPI `detail` shapes (string, `[{msg}]`, `{code,...}`) map to
  `ApiResult.Failure` with the correct typed error.
- AC-5. `GET` is retried under the bounded backoff policy; `PATCH` is never
  auto-retried (verified by dispatched-request count).
- AC-6. `PATCH` requests carry the `X-CSRF-Token` header; 401 triggers exactly one
  refresh-and-retry.
- AC-7. Repository and API are Hilt-injectable; the graph resolves in a DI test.
- AC-8. "Preferences load/save (tested)": load and save have passing MockWebServer
  tests as enumerated in §11.

## 15. Definition of Done

- All §14 acceptance criteria met and CI green on branch `android-port`.
- Code under `com.testlogon.android.core.{model,network,data}` with `@Binds`/`@Provides`
  modules; feature/app modules depend only on the `PreferencesRepository` interface.
- DTO field names reconciled against `/openapi.json` (`PreferencesPatchReq`) and
  `src/api/endpoints/preferences.ts` (`UiPreferences`); OQ-1/OQ-2/OQ-3 resolved (see §13),
  OQ-4 (validate-color) explicitly deferred.
- Mapper + repository unit/integration tests added (≥ 90% coverage on those files);
  MockWebServer fixtures committed under `core-testing`.
- No cleartext-host pinning leaks into release config; body logging gated to debug.
- ktlint/detekt clean; KSP (Moshi + Hilt) builds with no warnings; merged via reviewed
  PR; downstream E11 settings feature unblocked.

## 16. Citations & Assumption Audit

Each claim below is tagged **Verified** / **Corrected** / **Unverified-assumption**
with an exact source pointer. OpenAPI pointers use `METHOD /path` and/or a schema name;
frontend pointers use `src/...: symbol`; framework choices are labelled `framework ref`.

1. **Endpoint path is `/ui/settings/preferences` (not `/ui/preferences`).**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/settings/preferences`,
   `PATCH /ui/settings/preferences` (ops `ui_get_preferences_ui_settings_preferences_get`,
   `ui_update_preferences_ui_settings_preferences_patch`); `src/api/endpoints/preferences.ts: getPreferences/patchPreferences`.
2. **Load verb is `GET`; save verb is `PATCH` (not `PUT`).**
   VERDICT: Verified. SOURCE: OpenAPI `GET`/`PATCH /ui/settings/preferences`;
   `src/api/endpoints/preferences.ts: patchPreferences` (`api.patch(...)`).
3. **GET response is wrapped: `{"preferences": {...}}` (not a bare object).**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/settings/preferences` description
   ("Returns {\"preferences\": {...}} ..."); `src/api/endpoints/preferences.ts: getPreferences`
   (`api.get<{ preferences: UiPreferences }>(...)` then `return resp.preferences`).
4. **PATCH response is `{"ok": true}` and does NOT return the updated preferences.**
   VERDICT: Corrected (draft claimed read-through of the full updated DTO).
   SOURCE: OpenAPI `PATCH /ui/settings/preferences` description ("Returns {\"ok\": True} on success");
   `src/api/endpoints/preferences.ts: patchPreferences` returns `Promise<void>` (fire-and-forget).
5. **Preference field set = `theme, sidebar_collapsed, accent_color, custom_accent_hex,
   font_size, density, high_contrast`.**
   VERDICT: Corrected (draft's `locale, email_notifications, push_notifications,
   autoplay_video, updated_at` do not exist). SOURCE: OpenAPI `components.schemas.PreferencesPatchReq`;
   `src/api/endpoints/preferences.ts: UiPreferences`.
6. **Enum value sets: theme=`system|light|dark`; accent_color=`blue|purple|green|orange|pink|red|teal|custom`;
   font_size=`small|default|large|xlarge`; density=`compact|comfortable|spacious`.**
   VERDICT: Verified. SOURCE: OpenAPI `PreferencesPatchReq` (enum members);
   `src/api/endpoints/preferences.ts: AccentColor/FontSize/Density` type unions.
7. **`custom_accent_hex` is a string with `maxLength: 7`.**
   VERDICT: Verified. SOURCE: OpenAPI `PreferencesPatchReq.custom_accent_hex` (`maxLength: 7`).
8. **GET returns only explicitly-set keys; missing keys → app default.**
   VERDICT: Verified. SOURCE: OpenAPI `GET /ui/settings/preferences` description
   ("Missing keys mean the frontend should use its default value").
9. **PATCH is a partial merge (only provided fields merged; nulls/absent = unchanged).**
   VERDICT: Verified. SOURCE: OpenAPI `PreferencesPatchReq` description ("only provided
   fields are merged into the existing preferences map"); `src/api/endpoints/preferences.ts: patchPreferences` (`Partial<UiPreferences>`).
10. **Auth is cookie-based; CSRF via `X-CSRF-Token` header echoing the `ui_csrf` cookie.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
11. **401 → exactly one `POST /ui/session/refresh` → retry original; second 401 → fail/logout.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` and the 401 branch
    (single `refreshPromise`, retry once, logout on retry 401); OpenAPI `POST /ui/session/refresh` exists.
12. **The three `detail` shapes (string | `[{msg}]` | `{code,...}`) are decodable.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` (handles string,
    array-of-`{msg}`, and object via `mapAuthorizationError`).
13. **422 validation shape is `{"detail": [{loc, msg, type}]}`.**
    VERDICT: Verified. SOURCE: OpenAPI `HTTPValidationError` → `ValidationError`
    (required: `loc`, `msg`, `type`); both endpoints declare `422: HTTPValidationError`.
14. **`X-IMPERSONATION-TOKEN` and `Authorization: Bearer` are also sent by the web client;
    `user_sub` is an optional query param on both endpoints.**
    VERDICT: Verified (additional transport detail). SOURCE: `src/api/client.ts` (auth/imp
    headers); OpenAPI `GET`/`PATCH /ui/settings/preferences` params
    (`user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`). These are added by the shared
    AND-026/AND-027 stack, not this ticket.
15. **A related `POST /ui/settings/validate-color` endpoint exists (custom accent validation).**
    VERDICT: Verified (newly noted; out of scope, see OQ-4). SOURCE: OpenAPI
    `POST /ui/settings/validate-color` (`validate_custom_color_ui_settings_validate_color_post`);
    `src/api/endpoints/preferences.ts: validateColor` / `ValidateColorResponse`.
16. **Stack/library choices: Retrofit `@PATCH`/`@GET`/`@Body`, Moshi null-omission default.**
    VERDICT: Verified (framework ref). SOURCE: framework ref — Retrofit HTTP annotations
    (https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/PATCH.html) and Moshi,
    which omits null properties unless `serializeNulls()` is enabled
    (https://github.com/square/moshi#omitting-fields).
17. **`enum.name.lowercase()` produces the exact wire token for every constant.**
    VERDICT: Verified. SOURCE: cross-check of the §4.2 Kotlin enums against the enum
    members in OpenAPI `PreferencesPatchReq` (1:1, e.g. `XLARGE` → `xlarge`).

### Corrections made

- Endpoint path corrected from `/ui/preferences` to `/ui/settings/preferences`
  throughout (§1, §2, §4.4, §5, §7, §14). (Claims 1.)
- GET response corrected to the `{"preferences": {...}}` envelope; added
  `PreferencesEnvelopeDto` and envelope-unwrapping mapper (§4.3, §4.5, §5.1). (Claim 3.)
- PATCH response corrected to `{"ok": true}`; removed the false "read-through returns the
  updated DTO" behavior. Repository now does a follow-up `GET` (or returns local/`Unit`).
  Added `OkResponseDto`; updated §1, §4.6, §5.2, §6, §11(#4), §14 AC-3. (Claim 4.)
- Field set corrected to the real seven fields; removed non-existent
  `locale/email_notifications/push_notifications/autoplay_video/updated_at`; added
  `AccentColor/FontSize/Density` enums and their mappers (§4.2, §4.3, §4.5, §9, §10). (Claims 5–7.)
- i18n `locale` passthrough claim removed — no `locale` field exists (§9). (Claim 5.)
- Open questions OQ-1/OQ-2/OQ-3 marked RESOLVED with sources; added OQ-4 for the
  validate-color endpoint (§13). (Claims 1–9, 15.)

### Open assumptions

- **Per-endpoint 401/403/5xx shapes:** OpenAPI documents only `200` and `422` for both
  preferences endpoints. The `401`/`403`/`5xx` handling (including the string and
  `{code,...}` `detail` examples in §5.3) is **inferred from the global transport layer**
  (`src/api/client.ts`), not from per-endpoint OpenAPI responses. UNVERIFIABLE at the
  endpoint level; the shared `ApiErrorMapper` must still handle all shapes.
- **Bounded-backoff retry on GET / no-retry on PATCH:** an Android-side resilience policy
  inherited from the AND-026/AND-027 network core; not expressible in OpenAPI or the web
  client (the web client does not retry transport errors). Unverified-assumption about
  the shared stack's exact retry parameters (max attempts, jitter).
- **`updatePreferences` return-type choice** (`UserPreferences` via follow-up GET vs
  `Unit`/local-merge): a design decision left to the consumer; the contract permits both.
  The web client uses fire-and-forget (favors `Unit`/local-merge).
- **DataStore/cache, defaults at the app level:** the specific default constants for
  unset keys are app conventions (BLUE/DEFAULT/COMFORTABLE/false), not server-specified;
  only "missing → use a default" is contract-verified.

## 17. Test Plan

IDs `TC-AND-078-NN`. Test targets: **JVM** (local JVM/Robolectric unit, no device),
**emu35** (headless AVD `test35`, API 35 x86_64), **device** (Samsung Galaxy A15 5G,
SM-A156U, serial R5CX821TA9R, API 34 arm64-v8a). This ticket is a non-UI network/data
layer, so the suite is overwhelmingly JVM + MockWebServer (contract) tests; a couple of
instrumented cases verify the Hilt graph and the real OkHttp transport on-device.

- **TC-AND-078-01 — Load happy path (envelope unwrap + mapping)**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: MockWebServer enqueues `200` with body
  `{"preferences":{"theme":"dark","accent_color":"teal","font_size":"large","density":"compact","high_contrast":true,"sidebar_collapsed":false,"custom_accent_hex":"#1a2b3c"}}`.
  Steps: call `repository.getPreferences()`; capture `RecordedRequest`.
  Expected: `ApiResult.Success(UserPreferences(theme=DARK, accentColor=TEAL, fontSize=LARGE,
  density=COMPACT, highContrast=true, sidebarCollapsed=false, customAccentHex="#1a2b3c"))`;
  recorded request method=`GET`, path=`/ui/settings/preferences`.
  Traces: AC-1, AC-2.

- **TC-AND-078-02 — Load with sparse/empty body → defaults**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `200` `{"preferences":{}}` (and a second sub-case `{"preferences":{"theme":"light"}}`).
  Steps: call `getPreferences()`.
  Expected: empty → all domain defaults (`SYSTEM/false/BLUE/null/DEFAULT/COMFORTABLE/false`);
  partial → `theme=LIGHT`, rest defaults.
  Traces: AC-2.

- **TC-AND-078-03 — Lenient enum decode (unknown server values)**
  Type: unit (mapper, JVM).
  Target: JVM.
  Preconditions: `PreferencesDto(theme="ultraviolet", accentColor="chartreuse", fontSize="huge", density="airy")`.
  Steps: call `PreferencesDto.toDomain()`.
  Expected: unknown values fall back to `SYSTEM/BLUE/DEFAULT/COMFORTABLE` (no exception).
  Traces: AC-2.

- **TC-AND-078-04 — Save sends only changed fields (null omission)**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `200` `{"ok":true}`; (for the follow-up-GET variant) also enqueue a
  `200` envelope for the subsequent GET.
  Steps: `repository.updatePreferences(PreferencesPatch(theme=LIGHT, accentColor=PURPLE))`;
  read the recorded PATCH body JSON.
  Expected: PATCH body == exactly `{"theme":"light","accent_color":"purple"}` — keys
  `sidebar_collapsed/custom_accent_hex/font_size/density/high_contrast` ABSENT (not `null`);
  method=`PATCH`, path=`/ui/settings/preferences`.
  Traces: AC-1, AC-3.

- **TC-AND-078-05 — Save resolves merged state via follow-up GET**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue PATCH `200` `{"ok":true}`, then GET `200`
  `{"preferences":{"theme":"light","accent_color":"purple"}}`.
  Steps: call `updatePreferences(...)`; inspect dispatched requests.
  Expected: `ApiResult.Success(UserPreferences(theme=LIGHT, accentColor=PURPLE, ...defaults))`;
  exactly two requests in order: `PATCH` then `GET` on `/ui/settings/preferences`. (If the
  `Unit`/local-merge variant is chosen instead, assert exactly one PATCH and a Success
  carrying the locally-merged prefs — document which variant the build uses.)
  Traces: AC-3.

- **TC-AND-078-06 — CSRF header present on PATCH (security)**
  Type: contract/MockWebServer (JVM, with shared CSRF interceptor + seeded `ui_csrf` cookie).
  Target: JVM.
  Preconditions: cookie jar seeded with `ui_csrf=abc123`; enqueue `200` `{"ok":true}`.
  Steps: call `updatePreferences(...)`; read recorded PATCH headers.
  Expected: header `X-CSRF-Token: abc123` present on the PATCH; cookie sent.
  Traces: AC-6.

- **TC-AND-078-07 — 422 validation error mapping**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue `422`
  `{"detail":[{"loc":["body","theme"],"msg":"value is not a valid enumeration member","type":"value_error"}]}`.
  Steps: call `updatePreferences(PreferencesPatch(theme=...))`.
  Expected: `ApiResult.Failure` with the validation typed error and message
  "value is not a valid enumeration member" (joined per `normalizeErrorDetail`); no follow-up GET.
  Traces: AC-4.

- **TC-AND-078-08 — String and object `detail` error mapping**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: two sub-cases — `503` `{"detail":"preferences temporarily unavailable"}` and
  `429` `{"detail":{"code":"RATE_LIMITED","retry_after":5}}`.
  Steps: call `getPreferences()` for each.
  Expected: both → `ApiResult.Failure`; string form surfaces the raw message; object form
  decodes the `code` (RATE_LIMITED) per the shared mapper.
  Traces: AC-4.

- **TC-AND-078-09 — 401 → single refresh → retry success**
  Type: contract/MockWebServer (JVM, shared 401 interceptor harness).
  Target: JVM.
  Preconditions: enqueue GET `401`, then a `200` for `POST /ui/session/refresh`, then GET `200` envelope.
  Steps: call `getPreferences()`; inspect dispatched requests.
  Expected: `ApiResult.Success`; exactly one `POST /ui/session/refresh` dispatched between the
  two GETs; original request replayed once.
  Traces: AC-6.

- **TC-AND-078-10 — 401 twice → Failure(Unauthorized)**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue GET `401`, refresh `200`, GET `401` again.
  Steps: call `getPreferences()`.
  Expected: `ApiResult.Failure(Unauthorized)`; at most one refresh attempted; no infinite loop.
  Traces: AC-6.

- **TC-AND-078-11 — Retry policy: GET retried, PATCH not retried**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: GET sub-case — enqueue transport failure / `503` ×2 then `200`; PATCH sub-case
  — enqueue a single transport failure.
  Steps: call `getPreferences()` then `updatePreferences()`.
  Expected: GET succeeds after bounded backoff (assert >1 dispatched GET, within max attempts);
  PATCH → `ApiResult.Failure` with exactly ONE dispatched PATCH (no auto-retry, no follow-up GET).
  Traces: AC-5.

- **TC-AND-078-12 — Offline / flaky dev host (IOException → Network failure)**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: MockWebServer set to `SocketPolicy.DISCONNECT_AT_START` (or shut down) to
  simulate the unreliable plaintext dev host / no connectivity.
  Steps: call `getPreferences()` and `updatePreferences()`.
  Expected: both → `ApiResult.Failure(Network)` (no crash); `CancellationException` is rethrown
  if the coroutine is cancelled mid-call (separate assertion).
  Traces: AC-5, AC-8.

- **TC-AND-078-13 — Hilt graph resolves repository + API**
  Type: instrumented (Hilt) — runnable on emu35 (preferred for CI) or device.
  Target: emu35.
  Preconditions: `@HiltAndroidTest` with the test application; `SingletonComponent` graph built.
  Steps: inject `PreferencesRepository` and `PreferencesApi`; assert non-null and that the
  bound impl is `DefaultPreferencesRepository`.
  Expected: graph resolves with no missing-binding errors.
  Traces: AC-7.

- **TC-AND-078-14 — Real-transport smoke over OkHttp on physical device**
  Type: instrumented/e2e (manual smoke).
  Target: **device (SM-A156U, R5CX821TA9R)** — MUST run on the physical arm64-v8a/API-34
  device to exercise the real OkHttp/Conscrypt stack and the unreliable plaintext HTTP dev
  host on actual mobile networking (cleartext + arm64 ABI differ from x86 emu).
  Preconditions: device on a network reachable to `http://18.222.237.167:8000/`; a valid
  authenticated session cookie + `ui_csrf` seeded; debug build (cleartext permitted in debug
  network-security-config only).
  Steps: run `getPreferences()` then `updatePreferences(PreferencesPatch(theme=DARK))` then
  `getPreferences()` against the live host.
  Expected: load returns Success; save acknowledged (`{"ok":true}`); follow-up load reflects
  `theme=dark`; transient host flakiness surfaces as `Failure(Network)` not a crash. Treated as
  manual/non-gating (live host is unreliable per §13).
  Traces: AC-2, AC-3, AC-8.

> No Compose-UI or accessibility cases: this ticket delivers **no UI** (§9). UI and a11y
> coverage are owned by the downstream E11 settings-screen ticket. Security coverage here is
> the CSRF-header assertion (TC-06) and the cleartext-in-debug-only constraint exercised by
> TC-14 on-device; no runtime permissions are requested by this layer.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (paths/verbs/return types) | TC-01, TC-04 |
| AC-2 (GET maps all fields, envelope, defaults) | TC-01, TC-02, TC-03, TC-14 |
| AC-3 (PATCH null-omit body; merged state via follow-up GET) | TC-04, TC-05, TC-14 |
| AC-4 (all three `detail` shapes → Failure) | TC-07, TC-08 |
| AC-5 (GET retried; PATCH not) | TC-11, TC-12 |
| AC-6 (CSRF header on PATCH; one 401 refresh-retry) | TC-06, TC-09, TC-10 |
| AC-7 (Hilt-injectable; graph resolves) | TC-13 |
| AC-8 ("load/save (tested)") | TC-01, TC-04, TC-05, TC-12, TC-14 |
