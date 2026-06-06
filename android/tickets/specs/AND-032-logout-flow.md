---
id: AND-032
title: Logout flow
milestone: M1
epic: E04
priority: P0
size: S
status: reviewed
reviewed_on: 2026-06-06
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
- Auth model: cookie-based sessions established via `POST /ui/session/start` → MFA → `POST /ui/session/finalize`, with a `ui_csrf` cookie echoed as the `X-CSRF-Token` header on every request (verified: web `client.ts` sets `X-CSRF-Token` from `ui_csrf` unconditionally, not only on mutating requests). A persistent `CookieJar` rides every request; on 401 a one-shot `POST /ui/session/refresh` is attempted then the call is retried once. **Verified nuance:** the web client only attempts the refresh when the auth store reports `isAuthenticated` — an unauthenticated 401 propagates directly. The Android port should mirror this (do not attempt refresh once auth state is `Unauthenticated`), which is exactly the post-logout condition. (Endpoint schema names in OpenAPI are `UiSessionStartReq`/`UiSessionStartResp`/`UiSessionFinalizeReq`; the web `types.ts` aliases them as `SessionStartReq`/`SessionStartResp`/etc.)
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
    // Verified path/method: POST /ui/session/logout (OpenAPI op=ui_session_logout_ui_session_logout_post).
    // Body is ignored (Response<Unit>); web client types the 200 body as StatusResp{status:String} if needed.
    @POST("ui/session/logout")
    suspend fun logout(): Response<Unit>
}
```

- Request: no body. Cookies (session + `ui_csrf`) sent automatically by the cookie jar. The `X-CSRF-Token` header (value = `ui_csrf` cookie) is attached by the existing CSRF interceptor since this is a mutating POST. (Verified: web `client.ts` reads the `ui_csrf` cookie and sets `X-CSRF-Token` on every request; `endpoints/auth.ts` `logout()` posts with no body.)
- Success response: **`200 OK`** (verified against OpenAPI — `POST /ui/session/logout` declares only `200` and `422`; there is **no** documented `204` and **no** documented `401`). The OpenAPI `200` schema is empty (`{}`), so no body shape is guaranteed on the wire; the web client nonetheless types the body as `StatusResp` = `{ status: string }` (`src/api/endpoints/auth.ts: logout` → `api.post<StatusResp>("/ui/session/logout")`). The Android client ignores the body (`Response<Unit>`) and treats `200` as success; modelling it as `Response<StatusResp>` would also be valid. The server is expected to clear its session cookie via `Set-Cookie` with an expired value, but this is an assumption (the response cookie behavior is not described in OpenAPI); the cookie jar's `clear()` makes it moot locally regardless.
- Note: the endpoint takes only optional query/header params (`user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`) and declares no auth-required error, so calling it without a valid session is not documented to return `401`. The spec's earlier assumption that logout returns `401` "if the session is already gone" is therefore **unverified**; treat any non-2xx (or network failure) as a no-op for control flow — local teardown proceeds regardless. The only documented error is `422 HTTPValidationError` (validation of the optional params), which is not expected for a normal no-body logout.
- Error/`detail` mapping: standard FastAPI `detail` shape (`string | [{msg}] | {code,...}`) parsed by the shared error mapper; for logout the result is logged for telemetry only.

Path and method are **verified** against the OpenAPI index (`POST /ui/session/logout | op=ui_session_logout_ui_session_logout_post`) and the web client (`src/api/endpoints/auth.ts: logout`). The earlier `/ui/session/end` alternative does NOT exist in the backend and can be dropped from risk tracking.

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
- Race with in-flight requests: after `cookieJar.clear()`, any concurrent protected request loses its cookies and will 401. If auth state is still `Authenticated` at that instant, the refresh interceptor's one-shot `POST /ui/session/refresh` may fire but will lack a valid refresh cookie and fail, correctly resolving to unauthenticated. Once `authStateStore.clear()` has run, the interceptor should skip refresh entirely (mirroring the web client's `isAuthenticated` gate — verified in `client.ts`), so it never silently re-authenticates.

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

- R-1: ~~Exact logout endpoint path/method unconfirmed.~~ **RESOLVED in review:** `POST /ui/session/logout` is confirmed against OpenAPI (`op=ui_session_logout_ui_session_logout_post`, responses `200`/`422`) and the web client (`src/api/endpoints/auth.ts: logout`). No `/ui/session/end` exists. Residual: the `200` body shape is unspecified in OpenAPI (web types it `StatusResp`); the Android client ignores the body, so this is immaterial.
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
- Logout endpoint path confirmed against `/openapi.json` (`POST /ui/session/logout`, verified in review — see §16); `SessionApi.logout()` matches.
- No hardcoded user-facing strings; logout affordance requirements (label, touch target) documented for the consuming feature.
- `auth_logout` telemetry verified; no credentials/cookies logged.
- Code passes ktlint/detekt, builds on JDK 17 / AGP 8.7.3 / Gradle 8.9, merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Logout endpoint is `POST /ui/session/logout`.** VERDICT: **Verified.** Source: OpenAPI index `POST /ui/session/logout | op=ui_session_logout_ui_session_logout_post | resp=200:;422:HTTPValidationError`; OpenAPI spec `paths./ui/session/logout.post`; frontend `src/api/endpoints/auth.ts: logout` (`api.post<StatusResp>("/ui/session/logout")`).

2. **Logout request carries no body.** VERDICT: **Verified.** Source: `src/api/endpoints/auth.ts: logout` (no body arg); OpenAPI logout op has no `requestBody`.

3. **Logout success status is `200` (no `204`).** VERDICT: **Corrected** (spec said "200 OK or 204 No Content"). Source: OpenAPI `paths./ui/session/logout.post.responses` declares only `200` (empty schema) and `422`. No `204` documented.

4. **Logout returns `401` when the session is already gone.** VERDICT: **Unverified-assumption** (now flagged in §5). Source: OpenAPI logout op declares no `401`; endpoint params are all optional. No source supports a `401` from logout.

5. **Logout `200` body shape.** VERDICT: **Corrected/clarified.** OpenAPI declares an empty `200` schema (`{}`); the web client types it as `StatusResp = { status: string }` (`src/api/types.ts: StatusResp`, used by `src/api/endpoints/auth.ts: logout`). Android `Response<Unit>` (body ignored) is acceptable. Source: `src/api/types.ts` lines defining `StatusResp`; OpenAPI logout response.

6. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERDICT: **Verified**, with correction to "mutating-only" wording. Source: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); ... headers.set("X-CSRF-Token", csrf)`) — set on **every** request, not only mutating ones. Spec §2 corrected accordingly.

7. **Protected probe endpoint `GET /ui/me`.** VERDICT: **Verified.** Source: OpenAPI index `GET /ui/me | op=ui_me_ui_me_get`; frontend `src/api/endpoints/auth.ts: getMe` (`api.get<MeResp>("/ui/me")`).

8. **On 401, a one-shot `POST /ui/session/refresh` is attempted, then the call is retried once.** VERDICT: **Verified.** Source: `src/api/client.ts` (`refreshPromise` single-flight; `refreshSession()` posts `/ui/session/refresh`; one retry of the original request). OpenAPI index `POST /ui/session/refresh | op=ui_session_refresh_ui_session_refresh_post | resp=200:` (no `422`).

9. **Refresh is only attempted when the user is authenticated; an unauthenticated 401 propagates directly.** VERDICT: **Verified** (newly surfaced nuance, added to §2/§7). Source: `src/api/client.ts` (`if (!useAuthStore.getState().isAuthenticated) { throw new ApiError(401, ...) }` before refresh).

10. **On retry still returning 401, the client forces logout (`session_expired`).** VERDICT: **Verified.** Source: `src/api/client.ts` (`if (retryRes.status === 401) { useAuthStore.getState().logout("session_expired"); }`); also the `refreshSession` failure path calls `logout("session_expired")`.

11. **Session established via `POST /ui/session/start` → MFA → `POST /ui/session/finalize`.** VERDICT: **Verified.** Source: OpenAPI index `POST /ui/session/start | req=UiSessionStartReq | resp=200:UiSessionStartResp` and `POST /ui/session/finalize | req=UiSessionFinalizeReq`; frontend `src/api/endpoints/auth.ts: sessionStart, sessionFinalize`. Note: web `types.ts` aliases the schemas as `SessionStartReq/Resp`.

12. **Web client clears local/offline cache on logout (motivates Room teardown).** VERDICT: **Verified (analogous behavior).** Source: `src/lib/offlineCache.ts` ("Called on logout to prevent data leakage"); `src/components/layout/Header.tsx: handleLogout` (`await apiLogout(); ... logoutAuth();`) — server call best-effort, local logout always runs (matches FR-3).

13. **User-facing logout label exists in web i18n ("Log Out").** VERDICT: **Verified.** Source: `src/i18n/locales/en.json` (`"auth.logout": "Log Out"`), `es.json`/`fr.json` equivalents. Supports §9 string-resource requirement.

14. **`/ui/session/end` alternative endpoint.** VERDICT: **Corrected — does not exist.** Source: absent from OpenAPI index (only `/ui/session/{start,finalize,logout,refresh}` exist). Removed from active risk.

15. **Single-Activity + Navigation-Compose `popUpTo(start){inclusive}` / `launchSingleTop` back-stack clearing.** VERDICT: **Unverified-assumption (framework choice).** This is an Android architecture decision, not derivable from backend/web sources. framework ref: https://developer.android.com/guide/navigation/backstack (NavOptions popUpTo / launchSingleTop).

16. **OkHttp `CookieJar` + persistent clearable store for cookie teardown.** VERDICT: **Unverified-assumption (framework choice).** framework ref: https://square.github.io/okhttp/ (CookieJar) — web equivalent is the browser cookie store via `credentials: "include"` in `src/api/client.ts`.

17. **DataStore-backed auth state (`AuthStateStore`, `clear()`).** VERDICT: **Unverified-assumption** — defined by upstream ticket AND-029, not by the reviewed sources. framework ref: https://developer.android.com/topic/libraries/architecture/datastore. Treated as a dependency contract.

18. **Telemetry event `auth_logout` and its properties.** VERDICT: **Unverified-assumption** — Android-side instrumentation decision; no backend/web counterpart in the reviewed sources.

### Corrections made

- §5 (API Contract): removed unsupported "`204 No Content`" success claim; logout success is `200` only (OpenAPI declares `200`/`422`).
- §5: flagged the "logout returns `401` if session already gone" claim as an unverified assumption (no `401` documented).
- §5: clarified the `200` body — OpenAPI empty schema vs. web `StatusResp`; documented that Android's `Response<Unit>` ignores it.
- §5 / §13 (R-1): marked the endpoint path/method as verified and removed the non-existent `/ui/session/end` alternative.
- §2: corrected CSRF wording — `X-CSRF-Token` is sent on **every** request, not only mutating ones (per `client.ts`); noted OpenAPI schema names `UiSession*` vs. web aliases.
- §2 / §7: added the verified refresh gate — refresh is attempted only while authenticated, so a post-logout `Unauthenticated` state suppresses refresh (prevents silent re-auth).
- Frontmatter: `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- Server sends an expiring `Set-Cookie` on logout — not described in OpenAPI; immaterial because the local cookie jar is cleared unconditionally.
- Logout behavior when called with no/expired session (idempotency on the wire) — OpenAPI shows no `401`; actual runtime behavior on the unreliable dev host is untested here and is covered defensively (any non-2xx swallowed).
- `AuthStateStore`/`AuthState`/`clear()` semantics — owned by AND-029; assumed to expose `authState: StateFlow` emitting `Unauthenticated` after `clear()`.
- The exact set of user-scoped Room tables (R-2) — owned by feature tickets; `UserScopedCacheCleaner` is an aggregation extension point.
- Telemetry pipeline and `auth_logout` schema — Android-side decision, no source contract.
- Production HTTPS + `Secure` cookies (R-3) — assumed; dev host is plaintext HTTP.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** = headless emulator AVD `test35` (x86_64, API 35) in CI; **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a) on the build host. Logout has no camera/biometric/WebRTC/telephony surface, so most cases run on JVM or EMU; one ABI/API-parity case is pinned to DEV.

- **TC-AND-032-01** — Type: unit (JVM). Target: `AuthRepositoryImpl.logout()`. Preconditions: MockWebServer enqueues `200` for `POST /ui/session/logout`; fakes for `ClearableCookieJar`, `AuthStateStore`, `UserScopedCacheCleaner`; seeded authenticated state + cookies. Steps: call `logout()`. Expected: returns `ApiResult.Success(Unit)`; `cookieJar.clear()`, `authStateStore.clear()`, `cacheCleaner.clearUserScoped()` each invoked exactly once; recorded request is `POST /ui/session/logout` with `X-CSRF-Token` header present and no body. Traces: AC-1.

- **TC-AND-032-02** — Type: unit (JVM). Target: `AuthRepositoryImpl.logout()` server-failure resilience. Preconditions: MockWebServer enqueues `500` (then a variant enqueuing `SocketPolicy.NO_RESPONSE`/disconnect, and a variant throwing `IOException`). Steps: call `logout()` for each failure mode. Expected: each returns `ApiResult.Success(Unit)`; all three local teardown calls still invoked. Traces: AC-4.

- **TC-AND-032-03** — Type: unit (JVM). Target: logout under simulated dev-host timeout/offline. Preconditions: MockWebServer with throttled/`NO_RESPONSE` body to force read timeout near the ~20s client timeout (use a shortened test timeout); also a case with the server socket closed (offline). Steps: call `logout()`. Expected: returns `Success(Unit)` after timeout; cookie/auth/cache teardown all ran; no retry of the logout POST was attempted (single recorded request). Traces: AC-4.

- **TC-AND-032-04** — Type: unit (JVM). Target: idempotency. Preconditions: stores already empty / already logged out. Steps: call `logout()` twice sequentially (and once when never authenticated). Expected: both calls return `Success(Unit)`; clears are no-ops on empty stores; final state `Unauthenticated`. Traces: AC-5.

- **TC-AND-032-05** — Type: unit (JVM). Target: `AuthStateStore.clear()` + flow. Preconditions: real DataStore in a temp dir, seeded `authenticated=true,userSub="sub-123"`. Steps: collect `authState` via Turbine; call `clear()`. Expected: flow emits `Unauthenticated`; reading a freshly constructed store instance over the same file returns `authenticated=false,userSub=null` (persists across process death). Traces: AC-1, AC-6.

- **TC-AND-032-06** — Type: unit (JVM). Target: `PersistentCookieJar.clear()`. Preconditions: jar seeded with session + `ui_csrf` + other cookies via `saveFromResponse`. Steps: call `clear()`, then `loadForRequest(any url)`. Expected: returns empty list; backing store `removeAll()` invoked; no `ui_csrf` remains. Traces: AC-1.

- **TC-AND-032-07** — Type: contract/MockWebServer (JVM). Target: full OkHttp stack — the primary acceptance. Preconditions: real OkHttp client with cookie jar + CSRF interceptor + refresh-once interceptor; authenticate by enqueuing `Set-Cookie` (session + `ui_csrf`) so the jar is populated and auth state = Authenticated. Steps: (1) call `logout()` (MockWebServer returns `200` for the logout POST); (2) issue `GET /ui/me`; MockWebServer enqueues `401` for `/ui/me` and `401` for the one-shot `POST /ui/session/refresh`. Expected: the `/ui/me` call surfaces `401`; the refresh interceptor makes at most one `/ui/session/refresh` attempt (suppressed entirely if auth state already `Unauthenticated`), does NOT recover the request, and resolves to `Unauthenticated`. Recorded requests show no second refresh and carry no cookies after teardown. Traces: AC-2.

- **TC-AND-032-08** — Type: contract/MockWebServer (JVM). Target: refresh-suppression gate. Preconditions: same stack, auth state already `Unauthenticated` (post-logout). Steps: issue a protected `GET /ui/me`; server returns `401`. Expected: NO `/ui/session/refresh` request is sent (mirrors web `isAuthenticated` gate); the `401` propagates directly. Traces: AC-2.

- **TC-AND-032-09** — Type: contract/MockWebServer (JVM). Target: CSRF header on logout POST. Preconditions: cookie jar seeded with `ui_csrf=abc123`. Steps: call `logout()`. Expected: recorded logout request includes header `X-CSRF-Token: abc123` (value from the `ui_csrf` cookie); sent on this mutating POST. Traces: AC-1.

- **TC-AND-032-10** — Type: Compose-UI (EMU). Target: `SettingsViewModel` + logout affordance. Preconditions: fake `LogoutUseCase`; test NavHost with authenticated start + login destination. Steps: tap "Log out"; advance to completion. Expected: `inProgress` toggles true then false; on `Unauthenticated` emission the nav controller navigates to `Routes.LOGIN`; `popUpTo(startDestination){inclusive}` + `launchSingleTop` clear the authenticated back stack (assert `currentDestination == LOGIN` and prior authenticated route absent from back stack; simulated back-press does not return to it). Traces: AC-3.

- **TC-AND-032-11** — Type: Compose-UI (EMU). Target: double-invocation guard (FR-6). Preconditions: fake `LogoutUseCase` counting invocations. Steps: rapid double-tap the logout control. Expected: `LogoutUseCase` invoked exactly once; control disabled / shows progress while in flight. Traces: AC-3 (and FR-6).

- **TC-AND-032-12** — Type: Compose-UI accessibility (EMU). Target: logout affordance semantics. Preconditions: settings screen rendered. Steps: assert semantics. Expected: control has non-empty contentDescription/label sourced from `R.string.action_logout` (no hardcoded literal); touch target ≥ 48dp; in-progress state exposes `stateDescription` and disabled semantics. Traces: AC-3 (supports §9).

- **TC-AND-032-13** — Type: instrumented/e2e restart (EMU). Target: cold-start lands on login. Preconditions: app instrumented; perform logout so DataStore persists `Unauthenticated`. Steps: kill and relaunch the app process (or recreate the app graph). Expected: start destination resolves to login; no authenticated content shown. Traces: AC-6.

- **TC-AND-032-14** — Type: instrumented/e2e (EMU). Target: telemetry. Preconditions: analytics test double from `core-testing` installed. Steps: perform one logout. Expected: exactly one `auth_logout` event; properties include `server_ack:Boolean`, `server_status:Int?`, `duration_ms:Long`; event contains no cookie values, no `user_sub` plaintext, no other PII. Traces: AC-7.

- **TC-AND-032-15** — Type: instrumented/e2e (DEV, physical device — **must run on device**). Target: ABI/API parity of cookie + DataStore teardown on real arm64-v8a / API 34. Preconditions: app installed on SM-A156U (serial R5CX821TA9R) via adb; logged in against a local MockWebServer or stub. Steps: log in, log out, then attempt a protected call and a cold restart. Expected: identical behavior to the emulator (API 35/x86_64) — no cookie/auth-state remnant, `401` not recovered, cold start on login. Rationale for DEV: validates real arm64-v8a + API-34-vs-35 differences in DataStore/file-backed cookie persistence that the x86_64/API-35 emulator cannot cover. Traces: AC-1, AC-2, AC-6.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (cookies + auth state + Room cleared) | TC-01, TC-05, TC-06, TC-09, TC-15 |
| AC-2 (post-logout 401 not auto-recovered) | TC-07, TC-08, TC-15 |
| AC-3 (navigate to login, back stack cleared) | TC-10, TC-11, TC-12 |
| AC-4 (local teardown on server failure/timeout/offline) | TC-02, TC-03 |
| AC-5 (idempotent) | TC-04 |
| AC-6 (cold restart → login) | TC-05, TC-13, TC-15 |
| AC-7 (exactly one `auth_logout`, no PII) | TC-14 |
