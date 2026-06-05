---
id: AND-032
title: Logout flow
milestone: M1
epic: E04
priority: P0
size: S
status: draft
depends_on: [AND-029]
blocks: []
---

# AND-032 — Logout flow

## 1. Overview & Goal

Provide a single, reliable logout operation for the TestLogon native Android app. Invoking logout must terminate the user's cookie-based backend session, clear all locally held authentication artifacts (the persistent cookie jar, the DataStore-backed auth state from AND-029, and any user-scoped cached data in Room), and deterministically route the user back to the login screen.

The goal is a logout that leaves the device in a clean, unauthenticated state such that any subsequent protected API call fails with HTTP 401 (and is *not* silently recovered by the refresh-once interceptor), and such that an app restart shows the login screen rather than authenticated content. Logout must be idempotent, resilient to the unreliable dev backend (best-effort server-side invalidation, guaranteed local teardown), and free of leftover state that could leak the previous user's data to a subsequent user on a shared device.

This ticket owns the `session/logout` use case, repository method, and the wiring that clears state and navigates. It depends on AND-029 (`getMe` + persistent auth state store), which establishes the `AuthStateStore` and the authenticated/`user_sub` state that logout tears down.

## 2. Context & References

- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`.
- Web reference: `frontend/src/api/endpoints/*.ts` (session endpoints), `frontend/src/api/types.ts`.
- Auth model: cookie-based sessions established via `POST /ui/session/start` → MFA → `POST /ui/session/finalize`, with a `ui_csrf` cookie echoed as the `X-CSRF-Token` header on mutating requests. A persistent `CookieJar` rides every request; on 401 a one-shot `POST /ui/session/refresh` is attempted then the call is retried.
- Upstream dependency AND-029: defines `AuthStateStore` (DataStore prefs: `authenticated: Boolean`, `userSub: String?`) and `getMe()`. Logout is the inverse of the state population AND-029 performs.
- Sibling tickets in epic E04: AND-028 (`AuthRepository` session start), AND-031 (`LoginViewModel`), AND-033 (MFA API). Logout reuses the `AuthRepository` and `CookieJar` infrastructure those tickets establish.
- Namespace: `com.testlogon.android`. Module layering: `app` → `feature-*` → `core-*`.

## 3. Functional Requirements

FR-1. Expose a single suspend operation `logout()` reachable from authenticated UI (e.g., a settings/profile menu item — the *trigger UI* is owned by the consuming feature; this ticket provides the callable use case and the ViewModel-facing repository method).

FR-2. On logout, perform in order: (a) best-effort server-side session termination via `POST /ui/session/logout`; (b) clear the persistent cookie jar (all cookies, including session + `ui_csrf`); (c) clear DataStore auth state (set `authenticated=false`, `userSub=null`); (d) clear user-scoped Room caches; (e) emit a state change that drives navigation to login.

FR-3. Local teardown (b–e) MUST execute even if the server call (a) fails, times out, or returns a non-2xx status. Server invalidation is best-effort; local sign-out is guaranteed.

FR-4. Logout MUST be idempotent: calling it when already logged out, or twice in succession, completes without error and leaves the device unauthenticated.

FR-5. After logout completes, the auth state flow MUST emit unauthenticated, and the single-Activity Navigation-Compose graph MUST navigate to the login destination, clearing the authenticated back stack (`popUpTo(graph start) { inclusive }`, `launchSingleTop = true`) so back-press cannot return to authenticated screens.

FR-6. The logout button/affordance MUST be disabled / show progress while logout is in flight to prevent double-invocation; the operation always resolves to the unauthenticated state.

FR-7. After logout, a protected request (e.g., `GET /ui/me`) MUST return 401 and MUST NOT be auto-recovered (no valid refresh cookie remains), confirming the session is truly gone.

## 4. Technical Design

Code lives primarily in `core-data` (use case + repository method) and `core-network` (cookie jar clearing), with a small surface in `core-model` and the auth state flow from AND-029.

### 4.1 Repository method (core-data)

```kotlin
// com.testlogon.android.core.data.auth.AuthRepository
interface AuthRepository {
    // ... existing: startSession(), finalize(), getMe() (AND-028/029)
    suspend fun logout(): ApiResult<Unit>
}
```

```kotlin
@Singleton
class AuthRepositoryImpl @Inject constructor(
    private val sessionApi: SessionApi,                 // Retrofit service
    private val cookieJar: ClearableCookieJar,          // core-network
    private val authStateStore: AuthStateStore,         // AND-029, DataStore-backed
    private val cacheCleaner: UserScopedCacheCleaner,   // core-data
    @IoDispatcher private val io: CoroutineDispatcher,
) : AuthRepository {

    override suspend fun logout(): ApiResult<Unit> = withContext(io) {
        // (a) best-effort server invalidation; failures are swallowed.
        val serverResult = runCatching { sessionApi.logout() }
            .fold(
                onSuccess = { resp -> if (resp.isSuccessful) ApiResult.Success(Unit)
                                      else ApiResult.Error(resp.toApiError()) },
                onFailure = { ApiResult.Error(it.toApiError()) }
            )
        // (b–d) guaranteed local teardown regardless of (a).
        cookieJar.clear()
        authStateStore.clear()          // authenticated=false, userSub=null
        cacheCleaner.clearUserScoped()  // Room user-scoped tables
        // Logout is reported successful once local teardown succeeds.
        serverResult.let { /* logged for telemetry */ }
        ApiResult.Success(Unit)
    }
}
```

The contract: `logout()` returns `ApiResult.Success(Unit)` whenever local teardown succeeds, independent of the server response. The server result is captured for telemetry only (Section 10). It would only return `ApiResult.Error` if DataStore/Room teardown itself throws — a non-recoverable local failure.

### 4.2 Use case (core-data)

```kotlin
class LogoutUseCase @Inject constructor(
    private val authRepository: AuthRepository,
) {
    suspend operator fun invoke(): ApiResult<Unit> = authRepository.logout()
}
```

### 4.3 Clearable cookie jar (core-network)

Extend the persistent cookie jar (introduced with the auth stack) with a `clear()` that removes every persisted cookie from its backing store:

```kotlin
interface ClearableCookieJar : okhttp3.CookieJar {
    fun clear()
}

@Singleton
class PersistentCookieJar @Inject constructor(
    private val store: CookieStore,   // DataStore/file-backed persistence
) : ClearableCookieJar {
    override fun clear() = store.removeAll()   // session + ui_csrf + all others
}
```

`clear()` must be synchronous w.r.t. subsequent requests on the same OkHttp client so the next request carries no cookies.

### 4.4 User-scoped cache cleaner (core-data)

```kotlin
class UserScopedCacheCleaner @Inject constructor(
    private val db: AppDatabase,
) {
    suspend fun clearUserScoped() = db.withTransaction {
        db.clearUserScopedTables()   // DAO @Query("DELETE FROM ...") per user table
    }
}
```

Clears Room tables holding user-specific data (profile, watch history, lists, etc.). Reference/config tables that are not user-specific are left intact. Exact table set is owned by the feature tickets that create those tables; this cleaner aggregates their delete calls.

### 4.5 Auth state teardown (AND-029 surface)

```kotlin
// com.testlogon.android.core.data.auth.AuthStateStore  (AND-029)
suspend fun clear()  // sets authenticated=false, userSub=null
val authState: StateFlow<AuthState>   // emits Unauthenticated after clear()
```

### 4.6 Navigation reaction (app)

A top-level observer in the single Activity collects `authStateStore.authState`; on transition to `Unauthenticated` it navigates to the login graph:

```kotlin
LaunchedEffect(authState) {
    if (authState is AuthState.Unauthenticated) {
        navController.navigate(Routes.LOGIN) {
            popUpTo(navController.graph.findStartDestination().id) { inclusive = true }
            launchSingleTop = true
        }
    }
}
```

Driving navigation off the auth-state flow (rather than a one-shot event) makes logout consistent with session-expiry handling and keeps the back stack clean.

## 5. API Contract

Single endpoint consumed.

### `POST /ui/session/logout`

Retrofit service (core-network):

```kotlin
interface SessionApi {
    @POST("ui/session/logout")
    suspend fun logout(): Response<Unit>
}
```

- Request: no body. Cookies (session + `ui_csrf`) sent automatically by the cookie jar. The `X-CSRF-Token` header (value = `ui_csrf` cookie) is attached by the existing CSRF interceptor since this is a mutating POST.
- Success response: `200 OK` (or `204 No Content`). The server clears its session cookie via `Set-Cookie` with an expired/empty value; the cookie jar's `clear()` makes this moot locally.
- Error/`detail` mapping: standard FastAPI `detail` shape (`string | [{msg}] | {code,...}`) parsed by the shared error mapper. Logout treats any non-2xx (including `401` if the session is already gone) as a no-op for control flow — local teardown proceeds regardless.

Verify exact path and method against `/openapi.json` and `frontend/src/api/endpoints/*.ts` at implementation time; if the canonical endpoint differs (e.g., `/ui/session/end`), update `SessionApi` and Section 14 acceptance accordingly.

## 6. Data & State Management

State cleared by logout:

| Store | Mechanism | Keys / scope cleared |
|---|---|---|
| Cookie jar | `PersistentCookieJar.clear()` | All cookies incl. session + `ui_csrf` |
| Auth state | `AuthStateStore.clear()` (DataStore) | `authenticated` → `false`, `userSub` → `null` |
| User cache | `UserScopedCacheCleaner` (Room) | User-scoped tables only |

ViewModel exposure (consuming feature, e.g. `SettingsViewModel`):

```kotlin
data class LogoutUiState(val inProgress: Boolean = false, val error: String? = null)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val logout: LogoutUseCase,
) : ViewModel() {
    private val _ui = MutableStateFlow(LogoutUiState())
    val ui: StateFlow<LogoutUiState> = _ui.asStateFlow()

    fun onLogoutClicked() {
        if (_ui.value.inProgress) return            // FR-6 guard
        viewModelScope.launch {
            _ui.update { it.copy(inProgress = true, error = null) }
            logout()                                  // always resolves unauthenticated
            // navigation driven by authStateStore.authState (Section 4.6)
            _ui.update { it.copy(inProgress = false) }
        }
    }
}
```

The authoritative signal for "logged out" is `authStateStore.authState == Unauthenticated`, persisted in DataStore, so the unauthenticated state survives process death and a cold start lands on login.

## 7. Error Handling & Resilience

- Server call wrapped in `runCatching`; timeouts (the dev host warrants the standard ~20s timeout), connection failures, and non-2xx are all swallowed for control flow. No retry/backoff on logout — it is not an idempotent GET and local teardown is the source of truth.
- Local teardown ordering: clear cookies → clear auth state → clear cache. Each step is independent; if cache clearing throws it is logged but the auth state is already unauthenticated, so the user is still signed out.
- Idempotency: clearing already-empty stores is a no-op; the `inProgress` guard prevents concurrent invocations.
- Network unavailable: logout still succeeds locally. The stale server session (if any) is left to expire server-side; the local device retains nothing usable.
- Race with in-flight requests: after `cookieJar.clear()`, any concurrent protected request loses its cookies and will 401; the refresh interceptor's one-shot `POST /ui/session/refresh` will also lack a valid refresh cookie and fail, correctly resolving to unauthenticated rather than silently re-authenticating.

## 8. Security & Privacy

- Logout MUST remove all auth cookies from persistent storage so no session token remains at rest after sign-out (shared-device safety).
- User-scoped cached data MUST be deleted so a subsequent user on the device cannot read the previous user's content.
- The `X-CSRF-Token` header derived from `ui_csrf` is sent on the logout POST to satisfy CSRF protection; the cookie is then cleared.
- Best-effort server invalidation reduces the window in which a captured session cookie (on the plaintext dev host) remains valid. Note: dev backend is HTTP, so cookies traverse the network in clear text — out of scope to fix here, but logout minimizes local persistence.
- No credentials are logged. Telemetry records only the logout event and the server-call outcome, never cookie values or `user_sub` in plaintext beyond what auth state already stores.

## 9. Accessibility & i18n

- Logout affordance (provided by consuming feature) must have a descriptive `contentDescription` / label ("Log out") and meet 48dp touch-target minimum; this ticket specifies the requirement for the wiring, the visual element is owned by the settings feature.
- In-progress state announced via state semantics (e.g., disabled button + progress indicator with `stateDescription`).
- All user-visible strings (button label, optional "Signed out" confirmation, any error) sourced from `strings.xml` (`R.string.action_logout`, `R.string.logout_error`) — no hardcoded literals. Default `values/` (English) supplied; locale dirs added as the app's i18n baseline grows.

## 10. Telemetry & Logging

- Emit analytics event `auth_logout` with properties: `server_ack: Boolean` (server call returned 2xx), `server_status: Int?`, `duration_ms: Long`. No PII.
- Structured debug logs (debug builds only) at each teardown step: `cookies_cleared`, `auth_state_cleared`, `cache_cleared`. Errors from the server call logged at `warn` (expected on the unreliable dev host); local teardown failures at `error`.
- Verify via the standard analytics test double in `core-testing` that exactly one `auth_logout` event fires per logout.

## 11. Testing Strategy

Unit tests (`core-data`, JUnit + Turbine + MockWebServer):

- `logout()` returns `Success(Unit)` when server returns 200 → asserts `cookieJar.clear()`, `authStateStore.clear()`, `cacheCleaner.clearUserScoped()` all invoked (verify with relaxed mocks/fakes).
- `logout()` returns `Success(Unit)` when server returns 500 / times out / throws IOException → local teardown still invoked (FR-3).
- Idempotency: two sequential `logout()` calls both succeed; second is a no-op on already-empty stores (FR-4).
- `AuthStateStore.clear()` flips `authState` flow to `Unauthenticated` (Turbine) and value persists across a new store instance (DataStore-backed).
- `PersistentCookieJar.clear()` removes all cookies; subsequent `loadForRequest` returns empty list.

Integration test (the core acceptance, MockWebServer):

- Authenticate (seed cookies + auth state) → call `logout()` → issue `GET /ui/me` through the real OkHttp stack → assert it receives 401 AND the refresh-once interceptor does not recover it (server returns 401 to refresh too) → final state is `Unauthenticated`. This directly satisfies the AC "protected calls afterward 401 → login".

UI/ViewModel test (`feature` consuming logout, Compose test + fake use case):

- Clicking logout sets `inProgress`, then on completion the nav controller navigates to `LOGIN` with the authenticated back stack cleared (assert `currentDestination` and that prior route is not in back stack).
- Double-tap guard: rapid double click invokes `LogoutUseCase` once.

Restart test: after logout, recreate the app graph (cold start) → start destination resolves to login (auth state persisted as unauthenticated).

## 12. Dependencies & Sequencing

- Depends on AND-029 (`getMe` + auth state store): provides `AuthStateStore` with `authState: StateFlow` and `clear()`, plus the `user_sub`/authenticated persistence logout tears down. Logout cannot be implemented before this store exists.
- Reuses infrastructure from AND-028 (`AuthRepository`, `SessionApi`, cookie jar) — implement after or alongside it.
- Consumed by the settings/profile feature ticket that renders the logout affordance and by any session-expiry handling that wants to reuse the same teardown path; those tickets depend on this one for `LogoutUseCase`.
- No tickets are hard-blocked by AND-032 per the backlog (`blocks: []`), though feature tickets adding user-scoped Room tables should register their delete in `UserScopedCacheCleaner`.

## 13. Risks & Open Questions

- R-1: Exact logout endpoint path/method unconfirmed. Mitigation: verify against `/openapi.json` and `frontend/src/api/endpoints/*.ts`; `SessionApi.logout()` is a one-line change if it differs (e.g., `/ui/session/end`).
- R-2: The set of "user-scoped" Room tables is not yet fully known (other feature tickets define them). Mitigation: `UserScopedCacheCleaner` aggregates per-feature delete calls; treat as an extension point and add a test that fails loudly if a user table is registered without a clear.
- R-3: Plaintext HTTP dev host means cookies are exposed on the wire; logout cannot mitigate transport exposure. Open question: does prod use HTTPS + `Secure` cookies (assumed yes)?
- R-4: Whether to surface a user-visible error if server logout fails. Decision: no — logout always succeeds locally; server failure is silent (telemetry only) to avoid confusing a user who is, in fact, signed out.
- R-5: Concurrent requests racing the cookie clear could trigger an extra refresh attempt; acceptable since it resolves to unauthenticated. Confirm the refresh interceptor's one-shot guard does not loop.

## 14. Acceptance Criteria

AC-1. Invoking logout clears the persistent cookie jar (no session or `ui_csrf` cookie remains), sets DataStore auth state to `authenticated=false`/`userSub=null`, and clears user-scoped Room tables. (Unit + integration tests.)

AC-2. After logout, a `GET /ui/me` (or any protected call) returns 401 and is NOT auto-recovered by the refresh-once interceptor; final auth state is `Unauthenticated`. (Integration test — primary backlog AC.)

AC-3. After logout, the app navigates to the login destination with the authenticated back stack cleared (back press does not return to authenticated screens). (UI test.)

AC-4. Local teardown completes even when the server `POST /ui/session/logout` fails, times out, or is unreachable; `logout()` returns `Success(Unit)`. (Unit test.)

AC-5. Logout is idempotent: a second invocation succeeds and leaves the device unauthenticated. (Unit test.)

AC-6. After logout, a cold app restart resolves to the login screen (unauthenticated state persisted). (Restart test.)

AC-7. Exactly one `auth_logout` telemetry event is emitted per logout, carrying no PII or cookie values. (Telemetry test.)

## 15. Definition of Done

- `AuthRepository.logout()`, `LogoutUseCase`, `ClearableCookieJar.clear()`, `UserScopedCacheCleaner`, and the `AuthStateStore.clear()` usage are implemented under `com.testlogon.android.core.data`/`core-network`, wired via Hilt (KSP).
- Navigation-to-login on `Unauthenticated` is wired in the single Activity and clears the authenticated back stack.
- All tests in Section 11 written and passing; AC-1 through AC-7 verified.
- Logout endpoint path confirmed against `/openapi.json`; `SessionApi.logout()` matches.
- No hardcoded user-facing strings; logout affordance requirements (label, touch target) documented for the consuming feature.
- `auth_logout` telemetry verified; no credentials/cookies logged.
- Code passes ktlint/detekt, builds on JDK 17 / AGP 8.7.3 / Gradle 8.9, merged to `android-port`.
