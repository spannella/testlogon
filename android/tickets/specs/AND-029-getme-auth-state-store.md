---
id: AND-029
title: getMe + auth state store
milestone: M1
epic: E04
priority: P0
size: M
status: draft
depends_on: [AND-028, AND-011]
blocks: [AND-025, AND-032, AND-043, AND-044]
---

# AND-029 — getMe + auth state store

## 1. Overview & Goal

This ticket implements the authoritative, app-wide source of truth for *who is logged in*. It delivers two tightly coupled pieces:

1. A `getMe()` operation in `AuthRepository` that calls `GET /ui/me` and maps the cookie-backed session into a typed domain `User` model.
2. A persistent **auth state store** — an `AuthStateStore` backed by DataStore (Preferences) — that records the durable, observable facts of the session: an `authenticated` flag and the user's `userSub`. This state is exposed as a `StateFlow<AuthState>` so that navigation gating (AND-025), logout (AND-032), and refresh/expiry UX (AND-044) can react to it without re-hitting the network on every screen.

The TestLogon session is **cookie-based**: there is no bearer token to inspect locally. Cookies live in the persistent jar from AND-011; this store is the *projection* of that session into a fast, synchronous-at-startup, observable form. The contract is: after a successful login (AND-028 finalize), `getMe()` populates the in-memory `me` and the DataStore-backed `AuthState`, and that state survives a process restart, so the user lands authenticated on cold start without a login round-trip on the critical path.

Goal, stated as a single testable sentence: *after a successful login, `me` populates and auth state (`authenticated=true`, `userSub`) persists across an app restart, and is cleared on logout.*

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app in `android/`, branch `android-port`. Code lands in `:core:data` (the store + repository wiring) and `:core:model` (domain `User`, `AuthState`), namespace `com.testlogon.android`.
- **Stack:** Kotlin 2.0.21, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, DataStore (Preferences). minSdk 24 / targetSdk 35, JDK 17.
- **Upstream deps:**
  - **AND-011 (Persistent cookie jar):** supplies the OkHttp `CookieJar` that survives restart. `getMe()` relies on those cookies; `AuthStateStore` is the durable *mirror* of that session.
  - **AND-028 (AuthRepository: session start + branching):** owns `login()` and the `session/start` → MFA → `session/finalize` flow. This ticket extends the same `AuthRepository` with `getMe()` and wires the finalize success path to write `AuthState`.
- **Downstream (this ticket blocks):** AND-025 (auth-gated routing consumes `authState: StateFlow<AuthState>`), AND-032 (logout calls `clear()`), AND-043 (active sessions reads `userSub`), AND-044 (refresh/expiry transitions `authState`).
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts` (the `me`/session calls) and `frontend/src/api/types.ts` (shape of the `me` payload).
- **CSRF:** authenticated requests echo the `ui_csrf` cookie as `X-CSRF-Token`; on 401 the client refreshes once then retries (AND-013/AND-044 own the interceptor; `getMe()` must be safe to retry).

## 3. Functional Requirements

FR-1. `AuthRepository.getMe()` issues `GET /ui/me` using the shared OkHttp client (persistent cookie jar + CSRF header) and returns `ApiResult<User>`.

FR-2. On a successful `getMe()` (HTTP 200), the repository writes `AuthState(authenticated = true, userSub = user.sub)` to the `AuthStateStore` and caches the `User` in memory for the session.

FR-3. On a `getMe()` returning 401 (no/expired session) after the single refresh-retry has been exhausted, the repository writes `AuthState(authenticated = false, userSub = null)` and returns `ApiResult.Error(Unauthorized)`. A 401 is the canonical "you are not logged in" signal and MUST flip the store to unauthenticated.

FR-4. On network/timeout/5xx errors, `getMe()` returns `ApiResult.Error` and MUST NOT mutate the persisted `authenticated` flag (a flaky dev host must not log the user out). The previously persisted state remains the source of truth.

FR-5. `AuthStateStore` exposes `val authState: StateFlow<AuthState>` that emits the persisted value at startup and on every change. The first emission is derived from DataStore (durable), not a hardcoded default.

FR-6. `AuthStateStore.clear()` resets to `AuthState.Unauthenticated` and removes `userSub` from DataStore (used by AND-032 logout).

FR-7. After login finalize (AND-028) succeeds, the repository calls `getMe()` so the store is populated before navigation observes it. The login flow's authenticated result is not considered complete until `me` resolves.

FR-8. The store value persists across process death and cold start: a relaunched app reads `authenticated`/`userSub` from DataStore synchronously enough to gate the start destination without flashing the login screen (AND-025 contract).

## 4. Technical Design

### 4.1 Domain models (`:core:model`)

```kotlin
data class User(
    val sub: String,
    val username: String,
    val email: String?,
    val displayName: String?,
    val mfaEnabled: Boolean,
    val createdAt: String?, // ISO-8601, as returned by backend
)

sealed interface AuthState {
    data object Unknown : AuthState           // pre-DataStore-read, optional bootstrap value
    data object Unauthenticated : AuthState
    data class Authenticated(val userSub: String) : AuthState
}
```

`AuthState` is intentionally minimal — only the durable facts (`authenticated`, `userSub`). The full `User` lives in memory (and may be re-fetched), because it is not safe to assume PII should sit in plaintext DataStore (see §8).

### 4.2 AuthStateStore (`:core:data`)

```kotlin
interface AuthStateStore {
    val authState: StateFlow<AuthState>
    suspend fun setAuthenticated(userSub: String)
    suspend fun clear()
}

@Singleton
class DataStoreAuthStateStore @Inject constructor(
    @ApplicationContext context: Context,
    @AppScope private val scope: CoroutineScope, // SupervisorJob + Dispatchers.IO
) : AuthStateStore {

    private val dataStore = context.authDataStore // Preferences DataStore, name "auth_state"

    private object Keys {
        val AUTHENTICATED = booleanPreferencesKey("authenticated")
        val USER_SUB = stringPreferencesKey("user_sub")
    }

    override val authState: StateFlow<AuthState> =
        dataStore.data
            .map { prefs ->
                val sub = prefs[Keys.USER_SUB]
                if (prefs[Keys.AUTHENTICATED] == true && !sub.isNullOrBlank())
                    AuthState.Authenticated(sub)
                else AuthState.Unauthenticated
            }
            .stateIn(scope, SharingStarted.Eagerly, AuthState.Unknown)

    override suspend fun setAuthenticated(userSub: String) {
        dataStore.edit { it[Keys.AUTHENTICATED] = true; it[Keys.USER_SUB] = userSub }
    }

    override suspend fun clear() {
        dataStore.edit { it[Keys.AUTHENTICATED] = false; it.remove(Keys.USER_SUB) }
    }
}

private val Context.authDataStore by preferencesDataStore(name = "auth_state")
```

`SharingStarted.Eagerly` ensures the DataStore read begins at construction (the store is a `@Singleton` created early via Hilt) so the value is warm by the time the start destination is computed. `Unknown` is the bootstrap value; AND-025 treats `Unknown` as "show splash, wait one emission".

### 4.3 AuthRepository extension (`:core:data`)

```kotlin
interface AuthRepository {
    // ... login(), MFA, finalize() from AND-028 ...
    suspend fun getMe(): ApiResult<User>
    val cachedUser: StateFlow<User?>
}

@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authStateStore: AuthStateStore,
    @IoDispatcher private val io: CoroutineDispatcher,
) : AuthRepository {

    private val _cachedUser = MutableStateFlow<User?>(null)
    override val cachedUser: StateFlow<User?> = _cachedUser.asStateFlow()

    override suspend fun getMe(): ApiResult<User> = withContext(io) {
        when (val r = api.getMe().toApiResult { it.toDomain() }) {
            is ApiResult.Success -> {
                _cachedUser.value = r.data
                authStateStore.setAuthenticated(r.data.sub)
                r
            }
            is ApiResult.Error -> {
                if (r.kind == ErrorKind.Unauthorized) {
                    _cachedUser.value = null
                    authStateStore.clear()
                }
                r // network/5xx: state untouched (FR-4)
            }
        }
    }
}
```

`toApiResult` is the shared mapper (typed `ApiResult<T>`, FastAPI `detail` handling). `ErrorKind.Unauthorized` is produced by the network layer for HTTP 401 *after* the refresh-retry interceptor (AND-013/AND-044) has had its single attempt.

### 4.4 Hilt wiring

A `@Module @InstallIn(SingletonComponent::class)` binds `AuthStateStore` → `DataStoreAuthStateStore` and provides `@AppScope CoroutineScope`. `AuthRepository` is already provided by AND-028; this ticket adds the `AuthStateStore` constructor dependency.

## 5. API Contract

### 5.1 `GET /ui/me`

Request: no body. Cookies (session + `ui_csrf`) from the persistent jar are attached automatically; `X-CSRF-Token: <ui_csrf>` header is added by the shared interceptor.

Success `200 OK` (shape mirrors `frontend/src/api/types.ts`; confirm exact keys against `/openapi.json` at integration):

```json
{
  "sub": "user_8f3a...",
  "username": "alice",
  "email": "alice@example.com",
  "display_name": "Alice A.",
  "mfa_enabled": true,
  "created_at": "2025-11-02T18:04:11Z"
}
```

Moshi DTO (snake_case via `@Json`):

```kotlin
@JsonClass(generateAdapter = true)
data class MeResponse(
    val sub: String,
    val username: String,
    val email: String?,
    @Json(name = "display_name") val displayName: String?,
    @Json(name = "mfa_enabled") val mfaEnabled: Boolean = false,
    @Json(name = "created_at") val createdAt: String?,
) { fun toDomain() = User(sub, username, email, displayName, mfaEnabled, createdAt) }
```

Retrofit:

```kotlin
interface AuthApi {
    @GET("ui/me") suspend fun getMe(): Response<MeResponse>
}
```

Error responses: `401 Unauthorized` (no/expired/invalid session) → mapped to `ErrorKind.Unauthorized`. FastAPI error bodies use `detail` (`string | [{msg}] | {code,...}`) and are decoded by the shared error mapper. This ticket consumes the GET only; it does not own session/start, MFA, finalize, refresh, or logout endpoints (those are AND-028, AND-013/AND-044, AND-032).

## 6. Data & State Management

- **Durable store:** Preferences DataStore file `auth_state` with keys `authenticated: Boolean`, `user_sub: String`. This is the *only* thing persisted by this ticket. Session cookies are persisted separately by AND-011's jar.
- **Observable surface:** `authState: StateFlow<AuthState>` (single source of truth for "am I logged in?"), `cachedUser: StateFlow<User?>` (in-memory, lost on process death — re-hydrated by calling `getMe()` after cold start when `authState` is `Authenticated`).
- **Cold-start sequence:** App launches → Hilt builds `DataStoreAuthStateStore` (singleton, eager) → `authState` emits persisted value → AND-025 routes accordingly. If `Authenticated`, a background `getMe()` refresh repopulates `cachedUser` and confirms the cookie is still valid; a 401 there flips to `Unauthenticated`.
- **Consistency rule:** `authState` is derived purely from DataStore; never set it from a transient in-memory variable. Writes go through `setAuthenticated`/`clear` only, keeping a single write path.
- **Threading:** all DataStore reads/writes on `Dispatchers.IO` via DataStore's own executor; the `StateFlow` is shared in `@AppScope`.

## 7. Error Handling & Resilience

- **Flaky dev host:** `getMe()` uses the shared ~20s OkHttp timeout. As an idempotent GET it is eligible for bounded backoff retry (per project policy) and the single 401 refresh-retry. Network/timeout/5xx → `ApiResult.Error` with the persisted `authenticated` flag **untouched** (FR-4), so a dropped dev connection never silently logs the user out.
- **Definitive 401:** only a 401 surviving the refresh attempt clears state. This is the one path that demotes the user to `Unauthenticated`.
- **DataStore failures:** `dataStore.data` emits `IOException` on read corruption; the flow catches `IOException` and emits `emptyPreferences()` → resolves to `Unauthenticated` (fail-safe: when we cannot prove a session, treat as logged out, but never crash). Write failures are logged and surfaced as `ApiResult.Error`; the login flow (AND-028) treats a store-write failure as a non-fatal warning since cookies still hold the session.
- **Race safety:** `setAuthenticated` and `clear` are suspend, serialized by DataStore's single-writer transaction. Logout (AND-032) calling `clear()` concurrently with a late `getMe()` success is resolved by last-write-wins; logout additionally clears the cookie jar so a subsequent `getMe()` 401s and re-clears.

## 8. Security & Privacy

- **No tokens stored:** auth is cookie-based; no bearer/refresh token is persisted by this ticket. The session secret lives only in AND-011's cookie jar.
- **Minimal PII in DataStore:** only `authenticated` and `user_sub` are persisted. `user_sub` is an opaque identifier, not a credential. Email/username/displayName stay in memory (`cachedUser`) and are dropped on process death. Standard (unencrypted) Preferences DataStore is acceptable for `user_sub`; do **not** add email/password there.
- **Cookie jar encryption** is AND-011's responsibility (EncryptedSharedPreferences/DataStore); this ticket must not duplicate or leak cookies into `auth_state`.
- **Clear-on-logout:** `clear()` removes `user_sub` and resets the flag; AND-032 pairs it with cookie-jar clear so no residual identity remains.
- **CSRF:** `getMe()` rides the shared interceptor that echoes `ui_csrf` as `X-CSRF-Token`; no per-call CSRF handling here.
- **Logging:** never log cookie values, full `user_sub`, email, or response bodies (see §10).

## 9. Accessibility & i18n

No direct UI is delivered by this ticket — it is a data/repository layer. Accessibility is N/A here and is owned by the consuming UI tickets (AND-025 routing/splash, AND-032 logout UI, AND-044 expiry UX). Any user-facing strings that result from `getMe()` errors (e.g., "Session expired") are defined by those downstream tickets and must live in `strings.xml` for localization; this ticket exposes only typed `ApiResult.Error` kinds, not display copy.

## 10. Telemetry & Logging

- **Events (debug/structured only, no PII):**
  - `auth_state_restored{authenticated}` — emitted on first cold-start emission.
  - `getme_result{outcome=success|unauthorized|network_error|server_error, latency_ms}`.
  - `auth_state_changed{from, to}` — on every store transition.
- **Logging rules:** `Timber` (or project logger) at DEBUG; redact `user_sub` to a short hash/prefix; never log response bodies, cookies, or the CSRF token. Production builds strip DEBUG logs via the project's `Timber` tree setup.
- **No analytics SDK** is introduced by this ticket; events are local logs/hooks the app's existing telemetry layer can consume.

## 11. Testing Strategy

**Unit — `AuthStateStore` (`:core:data` test):**
- Uses an in-memory/temp-file Preferences DataStore.
- `setAuthenticated("sub_1")` → `authState` emits `Authenticated("sub_1")`.
- `clear()` → emits `Unauthenticated`; `user_sub` key removed.
- **Persistence test (core acceptance):** write `setAuthenticated`, dispose the DataStore instance, recreate over the same file → first emission is `Authenticated("sub_1")`. This proves "survives restart".
- Corrupt/empty preferences → `Unauthenticated`, no crash.

**Unit — `AuthRepositoryImpl.getMe()` (MockWebServer + `core-testing`):**
- 200 with representative `MeResponse` → `ApiResult.Success`, `cachedUser` populated, `setAuthenticated(sub)` invoked.
- 401 → `ApiResult.Error(Unauthorized)`, `clear()` invoked, `cachedUser=null`.
- 500 and socket timeout → `ApiResult.Error`, store **not** mutated (verify `setAuthenticated`/`clear` never called via a fake store).
- Moshi mapping: `display_name`/`mfa_enabled`/`created_at` map correctly; missing optional fields tolerated.

**Integration:**
- Login finalize (AND-028 path, mocked) → repository auto-calls `getMe()` → `authState` becomes `Authenticated`.
- Cold-start simulation: pre-seed DataStore file, construct graph, assert `authState.first()` is `Authenticated` without any network call.

**Instrumented (smoke, optional against dev host):** real login → kill/relaunch process → assert app resolves `Authenticated` and `getMe()` confirms 200.

Coverage target: store and repository `getMe` branches ≥ 90% line coverage.

## 12. Dependencies & Sequencing

- **Requires AND-011** (persistent cookie jar) — `getMe()` cannot authenticate without restored cookies; merge after AND-011.
- **Requires AND-028** (AuthRepository session start + branching) — extends the same repository and hooks the finalize-success path; merge after AND-028.
- **Blocks:**
  - **AND-025** (auth-gated routing) — consumes `authState: StateFlow<AuthState>`.
  - **AND-032** (logout flow) — consumes `AuthStateStore.clear()`.
  - **AND-043** (active sessions list + revoke) — reads `userSub`.
  - **AND-044** (session refresh wiring & expiry UX) — drives `authState` transitions on refresh failure.
- Implementation order within this ticket: (1) domain models in `:core:model`, (2) `AuthStateStore` + DataStore + Hilt binding, (3) `MeResponse`/`AuthApi`/`getMe()`, (4) finalize-path wiring, (5) tests.

## 13. Risks & Open Questions

- **R1 — exact `/ui/me` payload keys.** Field names (`display_name`, `mfa_enabled`, presence of `created_at`) assumed from `frontend/src/api/types.ts`; verify against `/openapi.json` before locking the DTO. *Mitigation:* tolerant optionals + a mapping test pinned to a captured sample.
- **R2 — DataStore read latency on cold start.** If the eager read is not warm before AND-025 computes the start destination, a brief splash is required. *Mitigation:* `SharingStarted.Eagerly` + `Unknown` bootstrap state that AND-025 holds on (no login flash).
- **R3 — refresh-retry ownership overlap.** The single-401-refresh interceptor is AND-013/AND-044; if not yet merged, `getMe()` still treats raw 401 as `Unauthorized`. *Open question:* confirm interceptor is in the OkHttp stack before this ticket relies on post-refresh 401 semantics.
- **R4 — should `cachedUser` be persisted?** Decided no (PII minimization). Open question if a downstream profile screen needs offline `User` — would belong to a separate cache (Room) ticket, not here.
- **R5 — concurrent logout vs in-flight getMe.** Last-write-wins is acceptable because logout also clears cookies; confirm AND-032 ordering (clear cookies then `clear()`).

## 14. Acceptance Criteria

AC-1. `AuthRepository.getMe()` exists, calls `GET /ui/me`, and returns `ApiResult<User>` with correct Moshi mapping for a representative 200 payload. *(unit, tested)*

AC-2. After a successful login (finalize), `cachedUser` is populated via `getMe()` and `authState` is `Authenticated(userSub)`. *(integration, tested)*

AC-3. **Auth state persists across process restart:** writing authenticated state then recreating the DataStore over the same file yields `Authenticated(userSub)` on first emission, with no network call. *(unit/integration, tested — primary backlog AC)*

AC-4. A definitive 401 from `getMe()` (post-refresh) transitions `authState` to `Unauthenticated` and clears `user_sub`. *(unit, tested)*

AC-5. Network/timeout/5xx from `getMe()` do **not** mutate the persisted `authenticated` flag. *(unit, tested)*

AC-6. `AuthStateStore.clear()` resets to `Unauthenticated` and removes `user_sub`. *(unit, tested)*

AC-7. `authState` is a hot `StateFlow` exposing the persisted value to consumers (AND-025 can observe it). *(unit, tested)*

## 15. Definition of Done

- All §14 acceptance criteria pass in CI.
- `User`, `AuthState` in `:core:model`; `AuthStateStore`/`DataStoreAuthStateStore`, `getMe()`, `MeResponse`, `AuthApi.getMe` in `:core:data`, all under `com.testlogon.android`.
- Hilt binds `AuthStateStore` as `@Singleton` with eager state; `AuthRepository` injects it; graph compiles (KSP) with no missing-binding errors.
- Unit + integration tests added (store persistence, `getMe` branches, mapping) with ≥90% coverage on the new code; `MockWebServer` used for the repository.
- No PII/credentials/cookies persisted in `auth_state`; no secrets logged; lint/detekt clean.
- No mutation of `authenticated` on transient errors verified by test.
- KDoc on public `AuthStateStore`/`AuthRepository.getMe()` surface; PR notes downstream consumers (AND-025/032/043/044).
- Builds green on `android-port` (AGP 8.7.3 / Gradle 8.9 / JDK 17); merged behind AND-011 and AND-028.
