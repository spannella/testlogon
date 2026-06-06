---
id: AND-029
title: getMe + auth state store
milestone: M1
epic: E04
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-2. On a successful `getMe()` (HTTP 200), the repository writes `AuthState(authenticated = true, userSub = user.userSub)` to the `AuthStateStore` and caches the `User` in memory for the session.

FR-3. On a `getMe()` returning 401 (no/expired session) after the single refresh-retry has been exhausted, the repository writes `AuthState(authenticated = false, userSub = null)` and returns `ApiResult.Error(Unauthorized)`. A 401 is the canonical "you are not logged in" signal and MUST flip the store to unauthenticated.

FR-4. On network/timeout/5xx errors, `getMe()` returns `ApiResult.Error` and MUST NOT mutate the persisted `authenticated` flag (a flaky dev host must not log the user out). The previously persisted state remains the source of truth.

FR-5. `AuthStateStore` exposes `val authState: StateFlow<AuthState>` that emits the persisted value at startup and on every change. The first emission is derived from DataStore (durable), not a hardcoded default.

FR-6. `AuthStateStore.clear()` resets to `AuthState.Unauthenticated` and removes `userSub` from DataStore (used by AND-032 logout).

FR-7. After login finalize (AND-028) succeeds, the repository calls `getMe()` so the store is populated before navigation observes it. The login flow's authenticated result is not considered complete until `me` resolves.

FR-8. The store value persists across process death and cold start: a relaunched app reads `authenticated`/`userSub` from DataStore synchronously enough to gate the start destination without flashing the login screen (AND-025 contract).

## 4. Technical Design

### 4.1 Domain models (`:core:model`)

```kotlin
// CORRECTED: the real GET /ui/me payload is minimal (see §5.1 / §16).
// It returns only the session identity facts — NOT a rich user profile.
data class User(
    val userSub: String,   // maps "user_sub"
    val sessionId: String, // maps "session_id"
    val ip: String,        // maps "ip"
)

sealed interface AuthState {
    data object Unknown : AuthState           // pre-DataStore-read, optional bootstrap value
    data object Unauthenticated : AuthState
    data class Authenticated(val userSub: String) : AuthState
}
```

`AuthState` is intentionally minimal — only the durable facts (`authenticated`, `userSub`). The full `User` lives in memory (and may be re-fetched). Note (correction): `/ui/me` does **not** return profile PII (email/username/display name) — it returns only `user_sub`, `session_id`, `ip` (see §5.1 and §16). The PII-minimization rationale in §8 still holds (do not persist `session_id`/`ip` beyond memory), but the original claim that `User` carries email/displayName was inaccurate and has been corrected.

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
                authStateStore.setAuthenticated(r.data.userSub)
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

Success `200 OK`. **CORRECTED** against the web contract `frontend/src/api/types.ts: MeResp` (the OpenAPI `200` response for `ui_me_ui_me_get` has an *empty* schema `{}`, so the frontend type is the authoritative shape). The real payload is minimal — it is the session identity, not a user profile:

```json
{
  "user_sub": "user_8f3a...",
  "session_id": "sess_4c2e...",
  "ip": "203.0.113.7"
}
```

> Earlier draft incorrectly listed `sub`/`username`/`email`/`display_name`/`mfa_enabled`/`created_at`. Those fields do **not** exist on `/ui/me`. See §16 for the audit.

Moshi DTO (snake_case via `@Json`):

```kotlin
@JsonClass(generateAdapter = true)
data class MeResponse(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "session_id") val sessionId: String,
    val ip: String,
) { fun toDomain() = User(userSub, sessionId, ip) }
```

Retrofit:

```kotlin
interface AuthApi {
    @GET("ui/me") suspend fun getMe(): Response<MeResponse>
}
```

Error responses: `401 Unauthorized` (no/expired/invalid session) → mapped to `ErrorKind.Unauthorized`. (Verified: 401 is enforced at runtime by the backend auth dependency and handled globally by the web client `src/api/client.ts`; the OpenAPI document only *enumerates* `422 HTTPValidationError` for this op — `resp=200:;422:HTTPValidationError`.) FastAPI error bodies use `detail` (`string | [{msg}] | {code,...}` — confirmed: `HTTPValidationError.detail = ValidationError[]` with `{loc,msg,type}`, and `src/api/client.ts: normalizeErrorDetail` handles the string / array-of-`{msg}` / object-with-`{code}` variants). These are decoded by the shared error mapper. This ticket consumes the GET only; it does not own session/start, MFA, finalize, refresh, or logout endpoints (those are AND-028, AND-013/AND-044, AND-032).

> Refresh-retry contract (verified against `src/api/client.ts`): on a 401 for an already-authenticated caller, the web client calls `POST /ui/session/refresh` **once** (coalesced via a single shared `refreshPromise`) and retries the original request; if the retry is still 401 it logs out with reason `session_expired`. The Android `getMe()` relies on the same single-refresh-then-retry semantics (interceptor owned by AND-013/AND-044) before treating a 401 as definitive.

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
- **Minimal PII in DataStore:** only `authenticated` and `user_sub` are persisted. `user_sub` is an opaque identifier, not a credential. The other `/ui/me` fields (`session_id`, `ip` — corrected; `/ui/me` does not return email/username/displayName) stay in memory (`cachedUser`) and are dropped on process death. In particular `ip` is mildly sensitive and `session_id` is session-scoped, so neither is persisted. Standard (unencrypted) Preferences DataStore is acceptable for `user_sub`; do **not** add `session_id`, `ip`, or any future profile PII there.
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
- Moshi mapping (corrected): `user_sub`→`userSub`, `session_id`→`sessionId`, `ip`→`ip` map correctly from a captured `MeResp` sample; a malformed/missing required field surfaces a mapping error (these three fields are required per `src/api/types.ts: MeResp`).

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

- **R1 — exact `/ui/me` payload keys (RESOLVED in review).** Verified against `frontend/src/api/types.ts: MeResp`: the payload is `{ user_sub, session_id, ip }` (all required). The OpenAPI `200` schema for `ui_me_ui_me_get` is empty (`{}`), so the frontend type is the binding contract. The earlier draft's `display_name`/`mfa_enabled`/`created_at` were incorrect and have been removed. *Residual risk:* because OpenAPI does not pin the shape, the backend could drift; *mitigation:* a contract/MockWebServer mapping test pinned to a captured `MeResp` sample (see TC-AND-029-01) so any drift fails CI.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`getMe()` calls `GET /ui/me`.** — VERIFIED. OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`); frontend `src/api/endpoints/auth.ts: getMe` (`api.get<MeResp>("/ui/me")`).

2. **`/ui/me` is a GET with no request body.** — VERIFIED. OpenAPI `GET /ui/me` (`req=` empty); `src/api/endpoints/auth.ts: getMe` sends no body.

3. **`/ui/me` 200 payload shape = `{ user_sub, session_id, ip }`.** — CORRECTED (was `sub/username/email/display_name/mfa_enabled/created_at`). SOURCE: `src/api/types.ts: MeResp` (`{ user_sub: string; session_id: string; ip: string }`). NOTE: OpenAPI's `200` content schema for `ui_me_ui_me_get` is empty (`{}`), so the frontend type is the authoritative contract.

4. **A 401 from `getMe()` is the canonical "not logged in" signal.** — VERIFIED (behavioral). `src/api/client.ts` lines ~194-237: a 401 triggers refresh+retry; a still-401 retry calls `useAuthStore.getState().logout("session_expired")`. The 401 itself is enforced at runtime by the backend auth dependency (not enumerated in OpenAPI, which lists only `422:HTTPValidationError` for this op).

5. **Single refresh-then-retry on 401, via `POST /ui/session/refresh`.** — VERIFIED. OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`); `src/api/client.ts: refreshSession` + the coalesced `refreshPromise` (one in-flight refresh) and single retry; `src/api/endpoints/auth.ts: refreshSession`.

6. **CSRF: authenticated requests echo `ui_csrf` cookie as `X-CSRF-Token`.** — VERIFIED. `src/api/client.ts` lines ~167-171: `const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`.

7. **Network/timeout errors do NOT log the user out.** — VERIFIED. `src/api/client.ts` lines ~185-189: a fetch throw becomes `ApiError(0, "Network error", err)` and does not touch auth state (no `logout()` call). Supports FR-4/AC-5.

8. **FastAPI error bodies use `detail` (string | array-of-`{msg}` | object-with-`{code}`).** — VERIFIED. Schema `HTTPValidationError.detail = ValidationError[]` (each `{loc, msg, type}`) in `openapi.pretty.json`; `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError` handle all three variants.

9. **Logout endpoint exists and is owned by AND-032.** — VERIFIED (endpoint). OpenAPI `POST /ui/session/logout` (op `ui_session_logout_ui_session_logout_post`); `src/api/endpoints/auth.ts: logout`. (Ownership attribution to AND-032 is an internal planning fact, not externally verifiable.)

10. **Login finalize endpoint exists and is owned by AND-028.** — VERIFIED (endpoint). OpenAPI `POST /ui/session/finalize` (op `ui_session_finalize_ui_session_finalize_post`, `req=UiSessionFinalizeReq`); `src/api/endpoints/auth.ts: sessionFinalize`. Finalize response shape (`src/api/types.ts: SessionFinalizeResp = { status:"ok"|"pending"; session_id?; required_factors; passed }`) — VERIFIED; relevant because the "finalize success → call getMe()" wiring (FR-7) keys off `status === "ok"`.

11. **`user_sub` is an opaque identifier safe for plaintext DataStore; richer PII is not returned.** — CORRECTED/VERIFIED. Since `/ui/me` returns only `user_sub`/`session_id`/`ip` (`src/api/types.ts: MeResp`), there is no email/username/displayName to leak. `user_sub` is used as a query/identifier param across the API (e.g. `params=user_sub` on `GET /ui/me`), consistent with opaque-id treatment.

12. **Cookie-based session; web client uses cookies via `credentials: "include"`.** — VERIFIED. `src/api/client.ts`: every `fetch` uses `credentials: "include"`. ASSUMPTION-NOTED: the web client *also* attaches a `Bearer` token from `useAuthStore` when present (`src/api/client.ts` lines ~157-160) — a hybrid. The Android port deliberately targets the cookie path only (cookie jar from AND-011); treat "no bearer token stored" (§8) as an intentional Android design decision, not a contradiction of the web client.

13. **DataStore (Preferences), Hilt, StateFlow, `SharingStarted.Eagerly`, Moshi `@Json` snake_case mapping, OkHttp persistent CookieJar.** — UNVERIFIED-ASSUMPTION (framework refs; not derivable from backend/frontend sources). These are Android implementation choices: DataStore Preferences (framework ref: developer.android.com/topic/libraries/architecture/datastore), Hilt (framework ref: developer.android.com/training/dependency-injection/hilt-android), Kotlin Flow `stateIn`/`SharingStarted` (framework ref: kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/state-in.html), OkHttp `CookieJar` (framework ref: square.github.io/okhttp). Reasonable and idiomatic; called out as assumptions because the reference sources are a web app + backend.

14. **`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` accepted by `/ui/me`.** — VERIFIED (and intentionally out of scope here). OpenAPI `GET /ui/me` `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`; `src/api/client.ts` sets `X-IMPERSONATION-TOKEN` only when impersonation is active. The Android port does not implement impersonation in this ticket; the cookie session suffices, so these headers are not sent by `getMe()`.

### Corrections made

- **C1 (major).** Replaced the entire `/ui/me` payload model. The draft's `User`/`MeResponse`/JSON sample/mapping used `sub, username, email, display_name, mfa_enabled, created_at`; the real `MeResp` (`src/api/types.ts`) is `{ user_sub, session_id, ip }`. Fixed: §4.1 `User` model, §4.3 `setAuthenticated(r.data.userSub)`, §5.1 JSON sample + `MeResponse` DTO + `toDomain()`, FR-2 (`user.userSub`), §8 PII bullet, §11 mapping test, §13 R1.
- **C2.** §5.1 error-response note: clarified that 401 is runtime-enforced (OpenAPI enumerates only `422:HTTPValidationError` for `ui_me`) and added the verified single-refresh-then-retry contract from `client.ts`.
- **C3.** §8: corrected which fields are "kept in memory" (now `session_id`/`ip`, not email/username/displayName) and added that `ip`/`session_id` must not be persisted.
- **C4.** §13 R1 downgraded from open risk to RESOLVED with the verified shape and a residual-drift mitigation.

### Open assumptions

- **OA1.** OpenAPI does not pin the `/ui/me` 200 schema (empty `{}`), so the contract rests solely on the frontend `MeResp` type. If the backend changes `/ui/me`, only a captured-sample contract test (TC-AND-029-01) will catch it. Unverifiable beyond the frontend type.
- **OA2.** All Android-stack choices (DataStore/Hilt/Flow/OkHttp/Moshi, eager state warm-up timing, ~20s timeout) are framework decisions not present in the reference sources (web app + backend). Cited as framework refs in item 13; the cold-start "warm before start destination" timing (R2) is an empirical assumption to validate on-device.
- **OA3.** Ownership of the refresh-retry interceptor (AND-013/AND-044) and logout ordering (AND-032 clears cookies then `clear()`) are cross-ticket planning assumptions; the *endpoints* are verified but the inter-ticket sequencing cannot be verified from the sources (R3, R5).

## 17. Test Plan

IDs `TC-AND-029-NN`. "Traces" links to §14 acceptance criteria.

- **TC-AND-029-01 — Moshi mapping of real `MeResp` (200).** Type: contract/MockWebServer. Preconditions: MockWebServer enqueues `200` with body `{"user_sub":"user_8f3a","session_id":"sess_4c2e","ip":"203.0.113.7"}` (captured sample matching `src/api/types.ts: MeResp`). Steps: call `AuthRepositoryImpl.getMe()`. Expected: `ApiResult.Success(User(userSub="user_8f3a", sessionId="sess_4c2e", ip="203.0.113.7"))`; request was `GET /ui/me` with no body. Traces: AC-1.

- **TC-AND-029-02 — Malformed/missing required field fails mapping.** Type: unit/contract. Preconditions: MockWebServer enqueues `200` with `{"session_id":"s","ip":"1.2.3.4"}` (missing `user_sub`). Steps: call `getMe()`. Expected: `ApiResult.Error` (mapping/parse error kind), store NOT mutated, `cachedUser` unchanged. Traces: AC-1, AC-5.

- **TC-AND-029-03 — Success populates cachedUser + flips store to Authenticated.** Type: unit (MockWebServer + fake/real `AuthStateStore`). Preconditions: store starts `Unauthenticated`. Steps: enqueue valid `200`; call `getMe()`. Expected: `cachedUser` = mapped `User`; `setAuthenticated("user_8f3a")` invoked; `authState` emits `Authenticated("user_8f3a")`. Traces: AC-1, AC-2, AC-7.

- **TC-AND-029-04 — Definitive 401 (post-refresh) clears state.** Type: unit/contract. Preconditions: store seeded `Authenticated("old_sub")`; refresh interceptor simulated as already-exhausted so the 401 reaches the repo as `ErrorKind.Unauthorized`. Steps: enqueue `401` with `{"detail":"Authentication required"}`; call `getMe()`. Expected: `ApiResult.Error(Unauthorized)`; `clear()` invoked; `authState` emits `Unauthenticated`; `user_sub` removed; `cachedUser=null`. Traces: AC-4, AC-6.

- **TC-AND-029-05 — 5xx does NOT mutate persisted auth flag.** Type: unit/contract. Preconditions: store seeded `Authenticated("sub_1")` via a spy/fake store. Steps: enqueue `500`; call `getMe()`. Expected: `ApiResult.Error`; neither `setAuthenticated` nor `clear` called; `authState` stays `Authenticated("sub_1")`. Traces: AC-5.

- **TC-AND-029-06 — Network drop / socket timeout (flaky dev host) does NOT log out.** Type: unit/contract (MockWebServer `SocketPolicy.DISCONNECT_AT_START` or no-response + short timeout). Preconditions: store seeded `Authenticated("sub_1")`. Steps: call `getMe()` against the failing host. Expected: `ApiResult.Error` (network/timeout kind); store untouched (`setAuthenticated`/`clear` never called); persisted `authenticated=true` remains. Traces: AC-5.

- **TC-AND-029-07 — `clear()` resets store.** Type: unit (temp-file Preferences DataStore). Preconditions: `setAuthenticated("sub_1")` applied. Steps: call `AuthStateStore.clear()`; read `authState`. Expected: emits `Unauthenticated`; `authenticated=false`; `user_sub` key absent. Traces: AC-6.

- **TC-AND-029-08 — Persistence across process restart (primary backlog AC).** Type: integration. Preconditions: temp DataStore file path. Steps: construct store A → `setAuthenticated("sub_1")` → dispose A → construct store B over the SAME file → read `authState.first()` (filtering out the `Unknown` bootstrap emission). Expected: first non-`Unknown` emission is `Authenticated("sub_1")`; no network call made. Traces: AC-3, AC-7.

- **TC-AND-029-09 — Corrupt/empty preferences fail safe.** Type: unit. Preconditions: DataStore read throws `IOException` (corrupted file) or returns `emptyPreferences()`. Steps: collect `authState`. Expected: resolves to `Unauthenticated` (no crash). Traces: AC-6.

- **TC-AND-029-10 — Login finalize success auto-calls getMe and authenticates.** Type: integration. Preconditions: mocked AND-028 finalize returns `SessionFinalizeResp{status:"ok"}`; MockWebServer enqueues valid `/ui/me` `200`. Steps: run finalize-success path. Expected: repo calls `getMe()`; `authState` becomes `Authenticated(userSub)` and `cachedUser` populated before the result is reported complete. Traces: AC-2, AC-7.

- **TC-AND-029-11 — Cold-start gating without network.** Type: integration. Preconditions: pre-seed DataStore file as `Authenticated("sub_1")`; no MockWebServer expectation. Steps: build the Hilt graph (or store singleton) and read `authState.first { it != Unknown }`. Expected: `Authenticated("sub_1")` with zero HTTP calls (verify MockWebServer `requestCount == 0`). Traces: AC-3, AC-7.

- **TC-AND-029-12 — CSRF header + cookies attached on getMe.** Type: contract/MockWebServer. Preconditions: cookie jar (AND-011) holds session + `ui_csrf` cookies; shared interceptor installed. Steps: call `getMe()`; inspect `RecordedRequest`. Expected: request carries the session `Cookie` header and `X-CSRF-Token: <ui_csrf value>`; matches `src/api/client.ts` CSRF behavior. Traces: AC-1.

- **TC-AND-029-13 — No PII/secrets persisted or logged.** Type: unit + manual (security). Preconditions: run a full success + 401 cycle. Steps: dump the `auth_state` Preferences file and captured logs. Expected: file contains only `authenticated` + `user_sub`; never `session_id`, `ip`, cookie values, or `X-CSRF-Token`; logs redact `user_sub` to a short hash. Traces: AC-4, AC-6 (security guardrail on the clear/persist paths).

- **TC-AND-029-14 — Instrumented restart smoke (optional, dev host).** Type: instrumented/e2e. Preconditions: device/emulator, reachable dev host `http://18.222.237.167:8000`, real login completed. Steps: kill + relaunch the app process; observe start destination; let background `getMe()` run. Expected: app resolves `Authenticated` from DataStore without a login flash; background `getMe()` returns `200` and `cachedUser` repopulates; a forced 401 (e.g. server-side session revoke) flips to `Unauthenticated`. Traces: AC-2, AC-3, AC-4.

Accessibility note: this ticket ships no UI (§9), so no Compose-UI/a11y cases are included; accessibility is owned by consumers (AND-025/032/044). The only UI-adjacent guarantee here — not flashing the login screen on cold start — is covered behaviorally by TC-11/TC-14.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (`getMe` → `GET /ui/me`, `ApiResult<User>`, correct mapping) | TC-01, TC-02, TC-03, TC-12 |
| AC-2 (finalize → `cachedUser` + `Authenticated`) | TC-03, TC-10, TC-14 |
| AC-3 (persists across restart, no network) | TC-08, TC-11, TC-14 |
| AC-4 (definitive 401 → `Unauthenticated`, clears `user_sub`) | TC-04, TC-13, TC-14 |
| AC-5 (network/timeout/5xx do not mutate flag) | TC-02, TC-05, TC-06 |
| AC-6 (`clear()` resets + removes `user_sub`) | TC-04, TC-07, TC-09, TC-13 |
| AC-7 (hot `StateFlow` exposes persisted value) | TC-03, TC-08, TC-10, TC-11 |
