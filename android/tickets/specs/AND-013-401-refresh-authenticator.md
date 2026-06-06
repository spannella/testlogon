---
id: AND-013
title: 401 refresh authenticator
milestone: M1
epic: E02
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-011]
blocks: [AND-015, AND-016, AND-017]
---

# AND-013 — 401 refresh authenticator

## 1. Overview & Goal

TestLogon's session is cookie-based: an authenticated client carries an HTTP-only
session cookie plus a `ui_csrf` cookie (mirrored into the `X-CSRF-Token` header by
AND-012). Sessions expire server-side. When a request fails with HTTP `401`, the
backend contract is to call `POST /ui/session/refresh` exactly once, and if that
succeeds, transparently retry the original request. If refresh fails — or the user
was never authenticated — the client must surface a clean logged-out state rather
than spinning or surfacing the raw `401` to feature code.

This ticket delivers a single OkHttp `Authenticator` (`SessionAuthenticator`) that
implements this behavior with **strict single-flight semantics**: concurrent in-flight
requests that each receive a `401` must trigger **at most one** refresh call, not N
refreshes. On refresh success all blocked requests retry; on refresh failure the
authenticator emits a logged-out signal once and gives up. The goal is correctness
under concurrency, no infinite retry loops, and a deterministic, testable logout path.

Out of scope: the cookie jar (AND-011), the CSRF header (AND-012), the host-selection
interceptor (AND-014), and any login/MFA UI (epic E03). This ticket only handles the
expired-session refresh-and-retry edge of an already-authenticated session.

## 2. Context & References

- **Module:** `core-network` (`com.testlogon.android.core.network.auth`). Wired into
  the shared `OkHttpClient` provided by AND-009.
- **Depends on AND-011** (persistent cookie jar) — refresh only makes sense when the
  session/CSRF cookies persist across requests and process restart. The authenticator
  reads "is there a session cookie?" state from the jar to distinguish authenticated
  vs. unauthenticated `401`s.
- **Adjacent:** AND-009 (OkHttp client/timeouts/logging), AND-010 (Retrofit/Moshi),
  AND-012 (CSRF interceptor), AND-014 (host-selection interceptor). The refresh call
  must traverse the same interceptor chain so it carries cookies + CSRF + the runtime
  base URL.
- **Backend:** FastAPI at `http://18.222.237.167:8000` (dev, plaintext HTTP, unreliable).
  Endpoint `POST /ui/session/refresh`. OpenAPI at `/openapi.json`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` — the web client performs the
  same "on 401 → refresh once → retry" flow in its fetch wrapper. This port mirrors
  that single-flight behavior. Shared error shape in `frontend/src/api/types.ts`.
- **Auth model:** session rides on cookies; `ui_csrf` cookie echoed as `X-CSRF-Token`;
  on `401` the client refreshes once then retries. **Verified** against
  `src/api/client.ts` (`credentials: "include"`, `getCookie("ui_csrf")` →
  `X-CSRF-Token`, and the 401-refresh-retry block lines ~191-237).
  **Clarification (verified):** the web client *additionally* sends an
  `Authorization: Bearer <accessToken>` header (from its auth store) and an
  `X-IMPERSONATION-TOKEN` header when impersonating (`src/api/client.ts` lines ~156-165).
  This Android ticket intentionally scopes to the **cookie-based** session only (no bearer
  token, no impersonation) — this is a deliberate scope simplification, recorded as an
  open assumption in §16, not an oversight. The `/ui/session/refresh` endpoint itself
  requires no bearer/session-id param (OpenAPI `params=` empty), so cookie-only refresh is
  contract-valid. Also note: the web 401 handler clears impersonation
  (`useImpersonationStore.getState().clear()`) before refreshing — N/A here since this port
  has no impersonation.

## 3. Functional Requirements

FR-1. Provide an `okhttp3.Authenticator` named `SessionAuthenticator` installed via
`OkHttpClient.Builder.authenticator(...)` in the Hilt network module.

FR-2. **Authenticated 401 → refresh once → retry.** On a `401` for a request whose
originating user is authenticated (a session cookie exists), call
`POST /ui/session/refresh` exactly once and, on success, return a retried copy of the
original request.

FR-3. **Single-flight.** When multiple requests receive `401` concurrently, exactly one
refresh network call is issued. All other `401`ed requests await that single result and
then retry (on success) or fail (on failure). Verified by request-count assertion.

FR-4. **Bounded retry.** A given request is retried **at most once** due to refresh.
If the retried request again returns `401`, the authenticator returns `null` (OkHttp
stops). No request triggers more than one refresh attempt on its behalf.

FR-5. **Refresh failure → logged out.** If refresh returns non-2xx (including `401`),
times out, or throws, the authenticator clears the session via the cookie jar's
clear-on-logout API (AND-011), emits a logged-out event **once**, and returns `null`.

FR-6. **Unauthenticated 401 → no refresh.** If no session cookie is present (user never
logged in, or already logged out), the authenticator does **not** call refresh; it
returns `null` and emits logged-out at most once (idempotent).

FR-7. **No refresh-of-refresh.** A `401` on the `POST /ui/session/refresh` request
itself must never trigger another refresh (loop guard). Such a `401` is treated as
refresh failure (FR-5).

FR-8. Expose a `Flow<SessionEvent>` (or `SharedFlow`) so feature/app layers can observe
`SessionEvent.LoggedOut` and navigate to the login graph. The authenticator does not
perform navigation itself.

## 4. Technical Design

Package: `com.testlogon.android.core.network.auth`.

```kotlin
sealed interface SessionEvent {
    data object LoggedOut : SessionEvent
}

interface SessionEvents {
    val events: SharedFlow<SessionEvent>
    suspend fun emitLoggedOut()
}

@Singleton
class SessionEventsImpl @Inject constructor() : SessionEvents {
    private val _events = MutableSharedFlow<SessionEvent>(
        replay = 0, extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    override val events: SharedFlow<SessionEvent> = _events.asSharedFlow()
    override suspend fun emitLoggedOut() { _events.emit(SessionEvent.LoggedOut) }
}
```

A thin abstraction performs the refresh network call without re-entering the
`Authenticator`. It uses a dedicated `OkHttpClient` derived from the shared client but
with the `Authenticator` removed (loop-safe) while keeping cookie jar + interceptors:

```kotlin
interface SessionRefresher {
    /** Synchronous; returns true iff POST /ui/session/refresh returned 2xx. */
    fun refresh(): Boolean
}

@Singleton
class SessionRefresherImpl @Inject constructor(
    @RefreshClient private val client: OkHttpClient,   // shared client, no authenticator
    private val baseUrlProvider: BaseUrlProvider,       // AND-014; falls back to BuildConfig
) : SessionRefresher {
    override fun refresh(): Boolean {
        val url = baseUrlProvider.current().newBuilder()
            .addPathSegments("ui/session/refresh").build()
        val req = Request.Builder().url(url)
            .post(EMPTY_REQUEST)
            .header("X-TL-Refresh", "1")   // marks this as the refresh call (loop guard)
            .build()
        return try { client.newCall(req).execute().use { it.isSuccessful } }
        catch (e: IOException) { false }
    }
    private companion object { val EMPTY_REQUEST = ByteArray(0).toRequestBody(null) }
}
```

The authenticator itself (OkHttp calls `authenticate` off the network thread, so the
synchronous refresh + a lock is the idiomatic pattern):

```kotlin
@Singleton
class SessionAuthenticator @Inject constructor(
    private val refresher: SessionRefresher,
    private val cookieStore: SessionCookieStore,   // AND-011: hasSession(), clearSession()
    private val sessionEvents: SessionEvents,
    private val appScope: CoroutineScope,           // @ApplicationScope, SupervisorJob
) : Authenticator {

    private val lock = Any()
    // Monotonic counter; bumped after each successful refresh. Used for single-flight.
    @Volatile private var refreshGeneration: Int = 0

    override fun authenticate(route: Route?, response: Response): Request? {
        // FR-7: never refresh the refresh call.
        if (response.request.header("X-TL-Refresh") != null) {
            failLogout(); return null
        }
        // FR-4: at most one refresh-driven retry per request.
        if (priorRetryCount(response) >= 1) return null
        // FR-6: don't refresh if we were never authenticated.
        if (!cookieStore.hasSession()) { failLogout(); return null }

        val seenGeneration = generationOf(response.request)
        val ok = synchronized(lock) {
            // Single-flight: if another thread already refreshed since we issued the
            // original request, reuse its result instead of refreshing again.
            if (refreshGeneration != seenGeneration && cookieStore.hasSession()) {
                true
            } else {
                refresher.refresh().also { success ->
                    if (success) refreshGeneration++ else { /* handled below */ }
                }
            }
        }
        if (!ok) { failLogout(); return null }

        // FR-2/FR-3: retry the original request (cookie jar + CSRF interceptor will
        // attach the freshened session/CSRF on the retry).
        return response.request.newBuilder()
            .header("X-TL-Retry", (priorRetryCount(response) + 1).toString())
            .header("X-TL-Gen", refreshGeneration.toString())
            .build()
    }

    private fun failLogout() {
        cookieStore.clearSession()
        appScope.launch { sessionEvents.emitLoggedOut() }
    }
    private fun priorRetryCount(r: Response) =
        r.request.header("X-TL-Retry")?.toIntOrNull() ?: 0
    private fun generationOf(req: Request) =
        req.header("X-TL-Gen")?.toIntOrNull() ?: 0
}
```

**Single-flight rationale.** `authenticate` is invoked synchronously per failed call by
OkHttp's connection threads. Each captures the `refreshGeneration` that was current when
its request was *built* (carried in `X-TL-Gen`, defaulting to 0 for first attempts).
Inside the lock, if the global generation has already advanced past the request's
captured generation and a session still exists, the refresh already happened on another
thread — we skip the network call and retry. Otherwise we perform the one refresh and
bump the generation. This collapses N concurrent `401`s into one refresh call (FR-3)
while remaining lock-cheap (only the boolean refresh is inside the monitor).

**Hilt wiring** (in `NetworkModule`, AND-009):

```kotlin
@Provides @Singleton @RefreshClient
fun refreshClient(@BaseClient base: OkHttpClient): OkHttpClient =
    base.newBuilder().authenticator(Authenticator.NONE).build()

@Provides @Singleton
fun okHttpClient(
    builder: OkHttpClient.Builder,        // base: timeouts, logging, cookie jar, csrf
    authenticator: SessionAuthenticator,
): OkHttpClient = builder.authenticator(authenticator).build()
```

## 5. API Contract

Endpoint: `POST /ui/session/refresh`

Request: empty body. Cookies (session + `ui_csrf`) attached by the persistent cookie
jar (AND-011); `X-CSRF-Token` attached by the CSRF interceptor (AND-012). Header
`X-TL-Refresh: 1` is internal (loop guard) and is **not** part of the wire contract with
the backend — strip or ignore server-side.

> **Web-divergence note (verified):** the web reference's `refreshSession()` issues the
> refresh as a **bare** `POST /ui/session/refresh` with only `credentials: "include"` —
> it does **not** set `X-CSRF-Token` on the refresh call itself (`src/api/client.ts:
> refreshSession`, lines ~121-130), unlike normal `api()` calls which always attach it.
> The backend accepts the refresh without CSRF (OpenAPI lists `params=` empty, i.e. no
> required headers/params for this endpoint). Attaching `X-CSRF-Token` on the Android
> refresh via the global AND-012 interceptor is therefore **harmless and a superset** of
> the web contract, not a mismatch — but it is not *required* by the backend. Keep it for
> consistency with the cookie-jar-attached CSRF on the retried request.

Success — `200 OK`. The response sets refreshed `Set-Cookie` headers (session + possibly
rotated `ui_csrf`), captured automatically by the cookie jar. **Verified:** OpenAPI
declares the `200` response with an empty/unconstrained schema (`"schema": {}`) — the
backend does not document a success body shape. The example below is **illustrative
only** and is NOT a verified contract; do not depend on any field:

```json
{ }   // body shape unspecified by OpenAPI; treat any/empty 2xx body as success
```

Failure — runtime `401 Unauthorized` (or `403`) when the session cannot be refreshed.
**Correction:** OpenAPI documents **only** a `200` response for `POST /ui/session/refresh`
(no `401`/`403`/`422` is declared, and the endpoint has no request params). The `401`/`403`
arises at runtime from the FastAPI auth dependency, not from the documented schema, so the
exact error body below is an **unverified assumption**:

```json
{ "detail": "..." }   // exact detail text NOT documented by OpenAPI — illustrative
```

FastAPI `detail` may be a string, `[{"loc": [...], "msg": "...", "type": "..."}]`
(verified via `components.schemas.HTTPValidationError` → `ValidationError`), or a
`{"code": "...", ...}` object (the web client's `normalizeErrorDetail` handles all three —
see `src/api/client.ts: normalizeErrorDetail`). This ticket does **not** parse `detail`
(only the status code matters), but it must not crash on any of those shapes — the body
is ignored on non-2xx.

The original retried request reuses its own method, URL, and body. Note: OkHttp will not
replay non-repeatable request bodies; in practice TestLogon mutations are small JSON
(repeatable) and the dominant case is idempotent `GET`s. Requests with one-shot bodies
that 401 will simply not be retried by OkHttp — acceptable for this dev scope.

## 6. Data & State Management

- **Session presence** is read from AND-011's `SessionCookieStore.hasSession()`
  (true iff a non-expired session cookie is in the jar). No new persistence is added
  here.
- **`refreshGeneration`** is in-memory, `@Volatile`, `@Singleton`-scoped. It is the
  only mutable authenticator state; it is reset implicitly on process restart (a fresh
  session restored from disk starts at 0). It is not persisted.
- **Logout signal** flows through `SessionEvents.events: SharedFlow<SessionEvent>`
  (replay 0, buffer 1, drop-oldest) collected by the app shell to navigate to the login
  graph and by ViewModels to flush in-memory UI state. The authenticator never touches
  Navigation directly.
- On `failLogout()` the cookie jar's `clearSession()` (AND-011) removes session +
  `ui_csrf` cookies so subsequent requests start unauthenticated.

## 7. Error Handling & Resilience

- **Refresh timeout / IOException:** caught in `SessionRefresherImpl.refresh()` → returns
  `false` → treated as logout (FR-5). The refresh call inherits AND-009's ~20s timeouts;
  it is **not** retried/backed-off here (refresh is a mutation, not an idempotent GET).
- **Refresh returns 401/403:** `isSuccessful` is false → logout. The `X-TL-Refresh`
  guard prevents the authenticator from recursing on this `401` (FR-7).
- **Retried request returns 401 again:** `priorRetryCount >= 1` → return `null`, no
  second refresh (FR-4). OkHttp surfaces the `401` to the caller; the app's ApiResult
  mapping treats it as an auth error and the already-emitted/about-to-emit logout drives
  navigation.
- **Thundering herd / unreliable dev host:** single-flight (FR-3) guarantees one refresh
  regardless of concurrent `401`s, preventing N parallel refreshes against the flaky dev
  backend.
- **Idempotent-logout:** `failLogout()` is safe to call multiple times — `clearSession()`
  is idempotent and the `SharedFlow` collector debounces to a single navigation.

## 8. Security & Privacy

- The authenticator never logs cookie values, `X-CSRF-Token`, or `Set-Cookie`. AND-009's
  `HttpLoggingInterceptor` already redacts `Cookie`, `Set-Cookie`, and `X-CSRF-Token`;
  the refresh client inherits that interceptor, so the refresh exchange is redacted too.
- `clearSession()` must remove **all** auth-bearing cookies (session + `ui_csrf`) on
  failure so a stale session cannot be reused.
- Dev backend is plaintext HTTP — no transport confidentiality. This is a known dev-host
  constraint (cleartext allowed via network-security-config for the dev host only); this
  ticket adds no new exposure beyond existing traffic.
- The internal `X-TL-Refresh` / `X-TL-Retry` / `X-TL-Gen` headers carry no sensitive data
  (a flag and small integers) and are stripped/ignored server-side.

## 9. Accessibility & i18n

No UI is produced by this ticket — N/A for direct a11y. The single user-visible
consequence is navigation to the login screen on logout, owned downstream (epic E03 login
UI / app-shell navigation). Any user-facing "Your session expired" copy must be a
localized string resource defined by the consuming screen, not hard-coded here. The
`SessionEvent.LoggedOut` signal carries no human-readable text.

## 10. Telemetry & Logging

- Debug-only structured logs (no PII, no tokens): `refresh.start`, `refresh.success`,
  `refresh.failure(reason=timeout|http_<code>|io)`, `refresh.skipped_single_flight`,
  and `auth.logged_out(reason=refresh_failed|unauthenticated_401|refresh_call_401)`.
- A counter/gauge hook (behind the same logging facade as AND-009) for number of refresh
  attempts and single-flight collapses, to validate FR-3 in QA. No analytics SDK is
  introduced by this ticket.
- Logs use the network module's tag (`TL.Net.Auth`) and respect the debug-only gate so
  release builds emit nothing.

## 11. Testing Strategy

All tests run against `okhttp3.mockwebserver.MockWebServer` in `core-network` unit tests
(no instrumentation needed), using the `core-testing` fakes for `SessionCookieStore` and
`SessionEvents`.

- **T-1 (FR-2, AC):** Queue `401` then `200` for `/refresh`, then `200` for the retried
  request. Assert: original request retried once, succeeds, and `/ui/session/refresh` was
  called **exactly once** (`server.requestCount` / path assertion).
- **T-2 (FR-5, AC):** Queue `401`, then `401` for `/refresh`. Assert: no retry of the
  original beyond the refresh, `clearSession()` called, and exactly one
  `SessionEvent.LoggedOut` collected from the `SharedFlow`.
- **T-3 (FR-3 single-flight):** Fire ~10 concurrent requests (thread pool) that all get
  `401`; queue one `200` refresh. Assert `/ui/session/refresh` hit **exactly once** and
  all 10 retried successfully.
- **T-4 (FR-4 bounded retry):** Refresh returns `200` but the retried request returns
  `401` again. Assert no second refresh; final response is `401`; `LoggedOut` not
  required (single failed retry is the cap) — verify request count == original+1 retry.
- **T-5 (FR-6 unauthenticated):** `hasSession()` returns false; a `401` arrives. Assert
  `/ui/session/refresh` **never** called; `LoggedOut` emitted at most once.
- **T-6 (FR-7 loop guard):** A `401` on `/ui/session/refresh` itself does not recurse;
  treated as failure (covered jointly with T-2 by asserting refresh path called once).
- **T-7 (timeout):** MockWebServer delays refresh beyond timeout → `refresh()` returns
  false → logout path. Use a short test-injected timeout client.

Determinism: inject `appScope` as a `TestScope` and collect events via Turbine.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-011** (persistent cookie jar) — provides `SessionCookieStore`
  (`hasSession()`, `clearSession()`) and the jar that captures refreshed `Set-Cookie`s.
- **Soft/co-required:** AND-009 (OkHttp client to attach the authenticator to),
  AND-010 (Retrofit), AND-012 (CSRF header on the refresh + retried requests),
  AND-014 (`BaseUrlProvider` for the refresh URL; falls back to `BuildConfig` if AND-014
  not yet merged).
- **Blocks:** any authenticated feature endpoints that must survive session expiry
  (e.g., AND-015/AND-016/AND-017 session start/finalize/me wiring and downstream feature
  data calls) depend on this transparent refresh being in place.
- **Sequencing:** land after AND-011 and AND-009; wire alongside AND-012 so the refreshed
  CSRF cookie is mirrored on the retry.

## 13. Risks & Open Questions

- **R-1 (RESOLVED in review):** `POST /ui/session/refresh` path + `POST` method are
  **verified** present in OpenAPI (`op=ui_session_refresh_ui_session_refresh_post`).
  The success body shape is **confirmed unspecified** (OpenAPI `200` has an empty schema
  `{}`); no `401`/`403`/`422` is documented. Mitigated by keying only on HTTP status, not
  body — the design is unaffected. See §16 for the full audit.
- **R-2:** Non-repeatable request bodies are not replayed by OkHttp; if a mutating call
  with a streamed body 401s, it won't auto-retry. Open question: do any TestLogon
  mutations use streamed/one-shot bodies? Assumed no (small JSON).
- **R-3:** Does `/refresh` rotate the `ui_csrf` cookie? If so, the CSRF interceptor
  (AND-012) must read the *post-refresh* cookie on retry — confirm interceptor ordering
  so CSRF is applied after the cookie jar updates.
- **R-4:** Generation-based single-flight assumes first attempts default `X-TL-Gen` to 0;
  confirm no interceptor strips internal `X-TL-*` headers before the authenticator runs.
- **R-5:** Unreliable dev host may make refresh flaky → false logouts. Acceptable for dev;
  revisit backoff for refresh if it proves disruptive in QA.

## 14. Acceptance Criteria

- **AC-1 (source):** A simulated session expiry triggers **exactly one**
  `POST /ui/session/refresh` followed by **exactly one** retry of the original request,
  which then succeeds (verified by MockWebServer request count — T-1).
- **AC-2 (source):** Repeated refresh failure logs the user out — `clearSession()` is
  invoked and exactly one `SessionEvent.LoggedOut` is emitted (T-2).
- **AC-3:** Concurrent `401`s collapse into a single refresh call (T-3).
- **AC-4:** No request triggers more than one refresh-driven retry; a re-`401` after
  refresh stops cleanly with no second refresh (T-4).
- **AC-5:** An unauthenticated `401` (no session cookie) does not call refresh (T-5).
- **AC-6:** A `401` on the refresh call itself does not recurse (T-6).
- **AC-7:** No cookie, CSRF, or `Set-Cookie` value appears in any log at any level.

## 15. Definition of Done

- `SessionAuthenticator`, `SessionRefresher(Impl)`, `SessionEvents(Impl)`, and the
  `@RefreshClient` Hilt binding are implemented in
  `com.testlogon.android.core.network.auth` and installed on the shared `OkHttpClient`.
- All tests T-1…T-7 pass in CI (JVM unit tests, MockWebServer + Turbine); coverage for
  the authenticator class is meaningful (single-flight + logout paths exercised).
- AC-1…AC-7 demonstrably satisfied.
- No sensitive data logged (manual log inspection + redaction test).
- Code passes ktlint/detekt and the module builds with AGP 8.7.3 / Gradle 8.9 / JDK 17,
  Kotlin 2.0.21, KSP-generated Hilt components.
- `depends_on` (AND-011) merged; integration with AND-012 verified (CSRF present on the
  refresh + retried requests); graceful `BuildConfig` fallback when AND-014 absent.
- Spec reviewed; the `SessionEvent.LoggedOut` consumer hook is documented for the
  downstream app-shell/navigation ticket.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** The refresh endpoint is `POST /ui/session/refresh`.
   **VERDICT: Verified.**
   **Source:** OpenAPI `POST /ui/session/refresh`
   (`op=ui_session_refresh_ui_session_refresh_post`); frontend `src/api/client.ts:
   refreshSession` (`fetch(withApiBase("/ui/session/refresh"), { method: "POST" })`).

2. **Claim:** Refresh `200` success body is `{ "ok": true }`.
   **VERDICT: Corrected → Unverified-assumption.**
   **Source:** OpenAPI `POST /ui/session/refresh` → `responses.200.content.application/json.schema`
   is empty (`{}`) — no body shape is specified. The web client (`refreshSession`) checks
   only `res.ok` and never reads the body. The illustrative example was downgraded and the
   `{ "ok": true }` literal removed.

3. **Claim:** Refresh failure returns `401` (or `403`) with body `{ "detail": "Session expired" }`.
   **VERDICT: Corrected → Unverified-assumption (status real, body unverified).**
   **Source:** OpenAPI declares **only** a `200` for this endpoint (no `401`/`403`/`422`).
   The `401`/`403` is a runtime FastAPI auth-dependency result, not a documented schema; the
   exact `detail` text is not in any source. Design keys on status only, so unaffected.

4. **Claim:** FastAPI `detail` may be a string, a list of `{msg,...}`, or a `{code,...}` object.
   **VERDICT: Verified.**
   **Source:** `components.schemas.HTTPValidationError` → `detail: ValidationError[]` and
   `components.schemas.ValidationError` (`{loc, msg, type}`); frontend
   `src/api/client.ts: normalizeErrorDetail` handles string / `[{msg}]` / `{code}` shapes.

5. **Claim:** Auth is cookie-based; `ui_csrf` cookie is mirrored to `X-CSRF-Token`.
   **VERDICT: Verified (with clarification).**
   **Source:** `src/api/client.ts` — `fetch(..., { credentials: "include" })`,
   `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`. Clarification: web also
   sends `Authorization: Bearer` + `X-IMPERSONATION-TOKEN`; intentionally out of scope here
   (see Open assumptions).

6. **Claim:** On `401`, the web client refreshes once then retries the original request.
   **VERDICT: Verified.**
   **Source:** `src/api/client.ts` lines ~191-237 (the `if (res.status === 401)` block:
   guard → `refreshSession()` → single retry → on retry `401` `logout`).

7. **Claim:** Single-flight — concurrent `401`s collapse into one refresh call.
   **VERDICT: Verified (web equivalent).**
   **Source:** `src/api/client.ts` — module-level `let refreshPromise` reused by all callers
   (`if (!refreshPromise) refreshPromise = refreshSession().finally(...)`). The Android
   generation-counter + lock is the threaded analogue (framework ref:
   https://square.github.io/okhttp/recipes/#handling-authentication-kt-java —
   `Authenticator` runs synchronously off the I/O thread).

8. **Claim:** Unauthenticated `401` does not trigger refresh.
   **VERDICT: Verified.**
   **Source:** `src/api/client.ts` — `if (!useAuthStore.getState().isAuthenticated) { ... throw }`
   *before* touching `refreshPromise`. Android reads this from `SessionCookieStore.hasSession()`
   (AND-011) instead of an auth store.

9. **Claim:** A re-`401` after the single retry logs the user out (bounded retry).
   **VERDICT: Verified.**
   **Source:** `src/api/client.ts` — `if (retryRes.status === 401) useAuthStore().logout("session_expired")`;
   refresh failure path also calls `logout("session_expired")` in `refreshSession`.

10. **Claim:** Refresh failure clears the session and emits a single logged-out signal.
    **VERDICT: Verified (web equivalent).**
    **Source:** `src/api/client.ts: refreshSession` → `useAuthStore.getState().logout("session_expired")`
    on `!res.ok`. Android maps this to `cookieStore.clearSession()` + one
    `SessionEvent.LoggedOut` (AND-011 clear API).

11. **Claim:** The refresh call carries `X-CSRF-Token` (via AND-012 interceptor).
    **VERDICT: Corrected (clarified divergence).**
    **Source:** `src/api/client.ts: refreshSession` issues a **bare** POST with only
    `credentials: "include"` — no `X-CSRF-Token`. OpenAPI `params=` empty for the endpoint
    (no required headers). Sending CSRF on the Android refresh is a harmless superset, not a
    requirement; documented in §5.

12. **Claim:** `/ui/session/refresh` requires no `X-SESSION-ID`/`user_sub`/bearer param.
    **VERDICT: Verified.**
    **Source:** OpenAPI index line `POST /ui/session/refresh | ... | params=` (empty),
    contrasted with sibling `/ui/session/logout` and most `/ui/*` and `/api/*` endpoints
    which list `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`.

13. **Claim:** Sibling endpoints exist for the broader session flow this unblocks
    (start / finalize / logout).
    **VERDICT: Verified.**
    **Source:** OpenAPI `POST /ui/session/start` (`req=UiSessionStartReq`,
    `resp=200:UiSessionStartResp`), `POST /ui/session/finalize` (`req=UiSessionFinalizeReq`),
    `POST /ui/session/logout`.

14. **Claim:** OkHttp `Authenticator` is the correct framework hook for transparent 401
    re-auth, invoked synchronously and supporting `Response.priorResponse`/retry-count guards.
    **VERDICT: Verified (framework ref).**
    **Source:** framework ref https://square.github.io/okhttp/recipes/#handling-authentication-kt-java
    and `okhttp3.Authenticator` API docs
    https://square.github.io/okhttp/4.x/okhttp/okhttp3/-authenticator/ .

15. **Claim:** Cleartext HTTP to the dev host requires `network-security-config` opt-in.
    **VERDICT: Verified (framework ref).**
    **Source:** framework ref
    https://developer.android.com/training/articles/security-config (cleartext is blocked by
    default since API 28; per-domain `cleartextTrafficPermitted` required).

### Corrections made

- **§5 success body:** removed the asserted `{ "ok": true }` contract; OpenAPI specifies an
  empty `200` schema, so the body shape is now flagged illustrative/unverified (claim #2).
- **§5 failure body:** clarified that OpenAPI documents **no** `401`/`403`/`422` for this
  endpoint; the failure status is a runtime auth result and the `{ "detail": "Session expired" }`
  text is an unverified assumption (claim #3). Tied the `detail` polymorphism to the real
  `HTTPValidationError`/`ValidationError` schemas (claim #4).
- **§5 CSRF on refresh:** added a verified web-divergence note — the web `refreshSession`
  sends **no** `X-CSRF-Token`; attaching it on Android is a harmless superset (claim #11).
- **§2 auth model:** added verified pointers to `src/api/client.ts` and recorded that the web
  client additionally sends `Authorization: Bearer` + `X-IMPERSONATION-TOKEN`, deliberately
  out of scope here (claim #5).
- **§13 R-1:** marked resolved — path/method verified, success/error schemas confirmed
  unspecified.

### Open assumptions

- **Exact refresh error body / status:** unverifiable — OpenAPI documents only `200`; the
  `401`/`403` and any `detail` text are runtime behavior not captured in the sources. Design
  keys on status only, so this does not block implementation.
- **`/refresh` rotating the `ui_csrf` cookie (spec R-3):** unverifiable from OpenAPI (no
  `Set-Cookie`/response-header schema) or frontend (cookies handled by the browser). Must be
  confirmed empirically against the live dev backend; mitigated by interceptor ordering
  (cookie jar before CSRF on the retry).
- **Bearer-token / impersonation scope omission:** the web client uses a bearer token and
  impersonation header in addition to cookies; this port assumes cookie-only auth is
  sufficient for TestLogon's authenticated session. Unverified that no authenticated endpoint
  *requires* the bearer token — flagged for confirmation before feature tickets (AND-015+).
- **Non-repeatable request bodies (spec R-2):** whether any TestLogon mutation uses a
  streamed/one-shot body is unverifiable from the sources (request bodies in OpenAPI are JSON
  schemas, which are repeatable in practice); assumed none.
- **Internal `X-TL-*` headers untouched (spec R-4):** cannot be verified against the backend
  (they are client-internal); relies on the Android interceptor ordering, not an external
  contract.

## 17. Test Plan

All cases live in `core-network` JVM unit tests against `okhttp3.mockwebserver.MockWebServer`
unless marked otherwise, using `core-testing` fakes for `SessionCookieStore` and
`SessionEvents`, and Turbine for `SharedFlow` collection. `appScope` is injected as a
`TestScope` for determinism.

- **TC-AND-013-01 — Happy path: 401 → one refresh → one retry → success.**
  Type: contract/MockWebServer.
  Preconditions: fake `hasSession()` = true; MockWebServer dispatcher queues `401` for the
  business request, `200` for `/ui/session/refresh`, then `200` for the retried business
  request.
  Steps: issue one GET through the authenticated client.
  Expected: business call returns `200`; `/ui/session/refresh` was hit **exactly once**
  (path + `requestCount` assertion); the business request was sent exactly twice (original +
  one retry); no `SessionEvent.LoggedOut` emitted.
  Traces: AC-1.

- **TC-AND-013-02 — Repeated refresh failure logs the user out.**
  Type: contract/MockWebServer.
  Preconditions: `hasSession()` = true; queue `401` for the business request, then `401`
  (non-2xx) for `/ui/session/refresh`.
  Steps: issue one GET; collect `SessionEvents.events` via Turbine.
  Expected: `refresher.refresh()` returns false → `clearSession()` called exactly once →
  **exactly one** `SessionEvent.LoggedOut` emitted; authenticator returns `null` (OkHttp
  surfaces the `401`); business request NOT retried after the failed refresh.
  Traces: AC-2.

- **TC-AND-013-03 — Single-flight: concurrent 401s collapse to one refresh.**
  Type: integration (thread pool + MockWebServer).
  Preconditions: `hasSession()` = true; queue one `200` for `/ui/session/refresh` and `200`
  for each retried business request; dispatcher returns `401` to the first attempt of each.
  Steps: fire ~10 concurrent requests on an executor so they all `401` near-simultaneously.
  Expected: `/ui/session/refresh` hit **exactly once**; all 10 business requests retry and
  succeed; `refreshGeneration` advanced by exactly 1; a single-flight-collapse counter
  (§10) registers the skipped refreshes.
  Traces: AC-3.

- **TC-AND-013-04 — Bounded retry: re-401 after refresh stops with no second refresh.**
  Type: contract/MockWebServer.
  Preconditions: `hasSession()` = true; queue `401` business, `200` refresh, then `401` again
  for the retried business request.
  Steps: issue one GET.
  Expected: `/ui/session/refresh` hit **exactly once**; business request sent exactly twice
  (original + one retry); on the second `401` `authenticate` returns `null` (via
  `priorRetryCount >= 1`) — no second refresh; final response is `401`.
  Traces: AC-4.

- **TC-AND-013-05 — Unauthenticated 401 → no refresh.**
  Type: unit + contract/MockWebServer.
  Preconditions: `hasSession()` = false; queue `401` for the business request.
  Steps: issue one GET.
  Expected: `/ui/session/refresh` **never** called (`requestCount` for that path == 0);
  `authenticate` returns `null`; `LoggedOut` emitted at most once (idempotent — assert
  exactly 0 or 1, not duplicated).
  Traces: AC-5.

- **TC-AND-013-06 — Loop guard: a 401 on /ui/session/refresh never recurses.**
  Type: unit.
  Preconditions: construct a `Response` whose `request` carries the internal `X-TL-Refresh: 1`
  header and status `401`.
  Steps: call `authenticate(route, response)` directly.
  Expected: returns `null` immediately (no call to `refresher.refresh()`); treated as refresh
  failure → `clearSession()` + one `LoggedOut`. No recursion / no second refresh.
  Traces: AC-6.

- **TC-AND-013-07 — Refresh timeout / IOException → logout (flaky dev host / offline).**
  Type: contract/MockWebServer.
  Preconditions: `hasSession()` = true; MockWebServer set to `SocketPolicy.NO_RESPONSE` (or
  body throttled beyond a short test-injected timeout) for `/ui/session/refresh`.
  Steps: issue one GET against a refresh client built with a ~200ms timeout.
  Expected: `SessionRefresherImpl.refresh()` catches `IOException`/timeout → returns false →
  `clearSession()` + exactly one `LoggedOut`; no infinite retry; the failure-reason telemetry
  records `timeout`/`io`.
  Traces: AC-2, AC-4.

- **TC-AND-013-08 — Offline before refresh even starts (no connectivity).**
  Type: contract/MockWebServer.
  Preconditions: `hasSession()` = true; business `401` queued, then the server is shut down
  (`server.shutdown()`) so the refresh connection fails outright.
  Steps: issue one GET.
  Expected: refresh throws `IOException` → false → logout path (one `LoggedOut`); no crash;
  authenticator returns `null`.
  Traces: AC-2.

- **TC-AND-013-09 — Redaction: no cookie/CSRF/Set-Cookie in logs.**
  Type: unit (log capture).
  Preconditions: capture the `TL.Net.Auth`/OkHttp `HttpLoggingInterceptor` output via an
  in-memory log sink; debug build flags on; refresh and retry exchanges carry `Cookie`,
  `X-CSRF-Token`, and `Set-Cookie`.
  Steps: run the happy-path exchange (TC-01) with logging enabled; scan captured logs.
  Expected: no raw cookie value, no `ui_csrf`/session value, no `X-CSRF-Token` value, and no
  `Set-Cookie` value appears at any level (headers redacted to `██`); only structured event
  names (`refresh.start`, `refresh.success`, etc.) appear.
  Traces: AC-7.

- **TC-AND-013-10 — Security: clearSession removes ALL auth cookies on failure.**
  Type: unit.
  Preconditions: real or fake `SessionCookieStore` seeded with both the session cookie and
  `ui_csrf`.
  Steps: drive the logout path (e.g. reuse TC-02), then inspect the cookie jar.
  Expected: after `failLogout()`, `hasSession()` == false AND `ui_csrf` is gone — no
  auth-bearing cookie survives; a subsequent request starts unauthenticated (so a following
  `401` takes the FR-6 no-refresh branch).
  Traces: AC-2, AC-5, AC-7.

- **TC-AND-013-11 — LoggedOut consumer/navigation hook (downstream wiring smoke).**
  Type: instrumented/e2e (lightweight).
  Preconditions: a test app shell collecting `SessionEvents.events`; a stubbed authenticated
  client driven to the logout path.
  Steps: trigger refresh failure; observe the app shell.
  Expected: exactly one navigation to the login graph is requested; the `SharedFlow`
  collector debounces duplicate emissions to a single navigation; the authenticator itself
  performs no navigation.
  Traces: AC-2.

- **TC-AND-013-12 — Accessibility of the resulting logout UX (downstream-owned check).**
  Type: Compose-UI / manual.
  Preconditions: the consuming login screen reached via `LoggedOut`.
  Steps: with TalkBack on, confirm any "session expired" copy is a localized string resource
  and is announced; verify focus moves to the login screen.
  Expected: session-expiry messaging is a localized resource (not hard-coded in
  `core-network`), is screen-reader announced, and meets focus/contrast guidance. Note: this
  ticket emits only the signal (no human-readable text on `SessionEvent.LoggedOut`), so the
  a11y obligation lives with the consuming screen — this case documents the boundary.
  Traces: AC-7 (no-text-in-signal guarantee) and the §9 a11i contract.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (one refresh + one retry → success) | TC-AND-013-01 |
| AC-2 (repeated failure → clearSession + one LoggedOut) | TC-AND-013-02, TC-AND-013-07, TC-AND-013-08, TC-AND-013-10, TC-AND-013-11 |
| AC-3 (concurrent 401s → single refresh) | TC-AND-013-03 |
| AC-4 (no second refresh-driven retry) | TC-AND-013-04, TC-AND-013-07 |
| AC-5 (unauthenticated 401 → no refresh) | TC-AND-013-05, TC-AND-013-10 |
| AC-6 (401 on refresh call does not recurse) | TC-AND-013-06 |
| AC-7 (no cookie/CSRF/Set-Cookie in logs) | TC-AND-013-09, TC-AND-013-10, TC-AND-013-12 |
