---
id: AND-078
title: Preferences API + DTOs
milestone: M2
epic: E11
priority: P0
size: M
status: draft
depends_on:
  - AND-027
blocks: []
---

# AND-078 — Preferences API + DTOs

## 1. Overview & Goal

This ticket delivers the network and data layer for **user preferences** in the
TestLogon native Android app: the Retrofit API surface, the Moshi DTOs that mirror
the FastAPI preferences contract, the `core-model` domain types, and a
`PreferencesRepository` that exposes load/save operations as suspend functions
returning `ApiResult<T>`. It is the Android port of the web reference's
`frontend/src/api/endpoints/preferences.ts` plus the associated shared types.

The deliverable is **non-UI**. No Compose screens, ViewModels, or navigation are in
scope here; those are owned by the downstream settings/preferences feature ticket
in epic E11. The goal is a fully tested, dependency-injectable repository that
returns mapped domain models and surfaces typed errors, so that feature code can
consume preferences without knowing about Retrofit, Moshi, cookies, or CSRF.

Success means: a caller can call `repository.getPreferences()` and
`repository.updatePreferences(patch)`, receive `ApiResult.Success(UserPreferences)`
on the happy path, and receive a mapped `ApiResult.Failure` (with the FastAPI
`detail` decoded) on every error path — all verified by MockWebServer tests.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. Code lands in `core-network` (API + DTOs + mappers) and
  `core-data` (repository), under namespace `com.testlogon.android`.
- **Web reference:** `frontend/src/api/endpoints/preferences.ts` (endpoint shapes),
  `frontend/src/api/types.ts` (shared `UserPreferences` / patch types).
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

data class UserPreferences(
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val locale: String = "en",
    val emailNotifications: Boolean = true,
    val pushNotifications: Boolean = true,
    val autoplayVideo: Boolean = true,
    val updatedAt: String? = null, // server ISO-8601, read-only
)

/** Partial update. Null field == "leave unchanged" (omitted from request body). */
data class PreferencesPatch(
    val theme: ThemeMode? = null,
    val locale: String? = null,
    val emailNotifications: Boolean? = null,
    val pushNotifications: Boolean? = null,
    val autoplayVideo: Boolean? = null,
)
```

> Field set is provisional and MUST be reconciled against `/openapi.json` and
> `frontend/src/api/types.ts` before merge (see Open Questions OQ-1). The
> architecture below is invariant under field-set changes.

### 4.3 DTOs (`core-network`)

```kotlin
package com.testlogon.android.core.network.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class PreferencesDto(
    @Json(name = "theme") val theme: String? = null,
    @Json(name = "locale") val locale: String? = null,
    @Json(name = "email_notifications") val emailNotifications: Boolean? = null,
    @Json(name = "push_notifications") val pushNotifications: Boolean? = null,
    @Json(name = "autoplay_video") val autoplayVideo: Boolean? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class UpdatePreferencesRequestDto(
    @Json(name = "theme") val theme: String? = null,
    @Json(name = "locale") val locale: String? = null,
    @Json(name = "email_notifications") val emailNotifications: Boolean? = null,
    @Json(name = "push_notifications") val pushNotifications: Boolean? = null,
    @Json(name = "autoplay_video") val autoplayVideo: Boolean? = null,
)
```

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

    @GET("ui/preferences")
    suspend fun getPreferences(): Response<PreferencesDto>

    @PATCH("ui/preferences")
    suspend fun updatePreferences(
        @Body body: UpdatePreferencesRequestDto,
    ): Response<PreferencesDto>
}
```

Returning `Response<T>` (not raw `T`) lets the repository inspect status codes and
the error body for `detail` mapping. The CSRF header and cookies are injected by the
shared OkHttp interceptors/cookie jar from AND-026/AND-027 — not declared here.

### 4.5 Mappers (`core-network`)

```kotlin
internal fun PreferencesDto.toDomain(): UserPreferences = UserPreferences(
    theme = theme.toThemeModeOrDefault(),
    locale = locale ?: "en",
    emailNotifications = emailNotifications ?: true,
    pushNotifications = pushNotifications ?: true,
    autoplayVideo = autoplayVideo ?: true,
    updatedAt = updatedAt,
)

private fun String?.toThemeModeOrDefault(): ThemeMode = when (this?.lowercase()) {
    "light" -> ThemeMode.LIGHT
    "dark" -> ThemeMode.DARK
    "system", null -> ThemeMode.SYSTEM
    else -> ThemeMode.SYSTEM // unknown server value -> safe default
}

internal fun PreferencesPatch.toRequestDto(): UpdatePreferencesRequestDto =
    UpdatePreferencesRequestDto(
        theme = theme?.name?.lowercase(),
        locale = locale,
        emailNotifications = emailNotifications,
        pushNotifications = pushNotifications,
        autoplayVideo = autoplayVideo,
    )
```

### 4.6 Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.preferences

interface PreferencesRepository {
    suspend fun getPreferences(): ApiResult<UserPreferences>
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
                .map { it.toDomain() }
        }

    override suspend fun updatePreferences(
        patch: PreferencesPatch,
    ): ApiResult<UserPreferences> = withContext(io) {
        safeApiCall(errorMapper) { api.updatePreferences(patch.toRequestDto()) }
            .map { it.toDomain() }
    }
}
```

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

### 5.1 Load — `GET /ui/preferences`

Request: no body. Response `200`:

```json
{
  "theme": "dark",
  "locale": "en",
  "email_notifications": true,
  "push_notifications": false,
  "autoplay_video": true,
  "updated_at": "2026-06-05T12:00:00Z"
}
```

### 5.2 Save — `PATCH /ui/preferences`

Request body (only changed fields present; nulls omitted):

```json
{ "theme": "light", "push_notifications": true }
```

Response `200`: full updated `PreferencesDto` (same shape as 5.1). The repository
maps the response to the canonical `UserPreferences`, so callers always get
server-truth after a save.

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

> Endpoint paths (`ui/preferences`) and verb (`PATCH` vs `PUT`) MUST be confirmed
> against `/openapi.json` before merge (OQ-2).

## 6. Data & State Management

This ticket owns the **network/repository** layer only; it holds no in-memory or
on-disk state. There is no Room caching and no DataStore persistence here — the
repository performs a live fetch/patch and returns mapped results.

- **No local cache (this ticket):** `getPreferences()` always hits the network.
  A DataStore-backed cache + a `StateFlow<PreferencesUiState>` are the responsibility
  of the downstream E11 settings feature ticket, which will layer over this repo.
- **Save → read-through:** `updatePreferences` returns the server's post-update
  representation, so the feature layer can update its state directly from the result
  without a follow-up `GET`.
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
  - `GET /ui/preferences` is idempotent → eligible for the shared **bounded backoff
    retry** (e.g., max 2 retries, jittered backoff) on transport errors / `5xx`.
  - `PATCH /ui/preferences` is **not idempotent** → **no automatic retry**; a failed
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

- `UserPreferences.locale` is a wire-level string (e.g., `"en"`, `"es"`); the
  repository passes it through verbatim and does not interpret or localize it.
- Error messages returned in `detail` are server strings; the repository surfaces the
  raw message via the typed error. User-facing localization of error copy is the
  feature layer's responsibility — do not hardcode English UI strings in core.

## 10. Telemetry & Logging

- **Structured logs (debug only):** log `GET`/`PATCH` outcome as
  `prefs_load_result` / `prefs_save_result` with fields `{ status, durationMs,
  errorCode }` — never the body, never `locale` values at INFO.
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
1. `getPreferences` 200 → parses full body → `Success(UserPreferences)` with all
   fields mapped (including `theme="dark"` → `ThemeMode.DARK`).
2. `getPreferences` enqueues recorded request → asserts method `GET`, path
   `/ui/preferences`.
3. `updatePreferences` with `PreferencesPatch(theme=LIGHT, pushNotifications=true)` →
   recorded request body contains **only** `theme` and `push_notifications` (assert
   absent keys for unset fields → null-omission verified).
4. `updatePreferences` 200 returns updated DTO → `Success` reflecting server values.
5. `updatePreferences` recorded request carries `X-CSRF-Token` header.
6. Error mapping: 422 list `detail`, 4xx string `detail`, 5xx object `detail` each →
   `Failure` with the expected mapped code/message (one test per shape).
7. 401 once → refresh → retry success (using shared interceptor harness); 401 twice →
   `Failure(Unauthorized)`.
8. `getPreferences` transport error retried (bounded); `updatePreferences` transport
   error **not** retried (assert single dispatched request).
9. Lenient read: unknown `theme` value → `ThemeMode.SYSTEM`; missing optional fields →
   domain defaults.

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

- **OQ-1 (field set):** Exact preferences fields/types must be confirmed from
  `frontend/src/api/types.ts` and `/openapi.json`. The model above is provisional;
  the design is field-agnostic, so additions are mechanical.
- **OQ-2 (verb/path):** Confirm `PATCH` vs `PUT` and whether the path is
  `/ui/preferences` (singular) vs `/ui/me/preferences`. Adjust `PreferencesApi`
  annotations accordingly.
- **OQ-3 (partial update support):** If the backend does **not** support `PATCH`
  semantics and requires a full document on `PUT`, the repository must first `GET`,
  merge the patch, then `PUT` — changing the update flow. Verify before implementing.
- **Risk:** unreliable dev host produces flaky integration runs — mitigated by using
  MockWebServer for all CI tests and treating live-host calls as manual smoke only.
- **Risk:** Moshi null-omission misconfiguration would send `null` for unset fields,
  unintentionally clearing them server-side — explicitly covered by test #3.

## 14. Acceptance Criteria

- AC-1. `PreferencesApi` exposes `GET ui/preferences` and `PATCH ui/preferences`
  returning `Response<PreferencesDto>`; paths/verbs/bodies match the contract
  (MockWebServer-verified).
- AC-2. `PreferencesRepository.getPreferences()` returns
  `ApiResult.Success(UserPreferences)` with all fields correctly mapped on `200`.
- AC-3. `PreferencesRepository.updatePreferences(patch)` sends a body containing
  **only** the fields set in the patch (nulls omitted) and returns the updated
  `UserPreferences` from the response.
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
- DTO field names reconciled against `/openapi.json` and `frontend/src/api/types.ts`;
  OQ-1/OQ-2/OQ-3 resolved or explicitly deferred with tickets.
- Mapper + repository unit/integration tests added (≥ 90% coverage on those files);
  MockWebServer fixtures committed under `core-testing`.
- No cleartext-host pinning leaks into release config; body logging gated to debug.
- ktlint/detekt clean; KSP (Moshi + Hilt) builds with no warnings; merged via reviewed
  PR; downstream E11 settings feature unblocked.
