---
id: AND-044
title: Session refresh wiring & expiry UX
milestone: M1
epic: E06
priority: P0
size: M
status: draft
depends_on: [AND-013, AND-029]
blocks: []
---

# AND-044 — Session refresh wiring & expiry UX

## 1. Overview & Goal

The cookie-based session for the TestLogon Android app rides on an OkHttp persistent cookie
jar (AND-011), a CSRF interceptor (AND-012), and a 401 `Authenticator` (AND-013) that performs a
single-flight `POST /ui/session/refresh` before retrying a failed request. AND-013 produces the
*signal* of an unrecoverable session loss (refresh failed) but deliberately stops at "emit
logged-out" — it has no opinion about UI. AND-029 owns the persistent auth-state store (the
`authenticated` flag and `user_sub`) backed by DataStore.

This ticket is the **wiring layer** between those two: it connects the authenticator's logged-out
signal to the auth-state store, drives a global expiry event to the navigation layer, shows a
user-facing "session expired" message, and routes the user cleanly to the login screen carrying a
machine-readable *reason*. The goal is a single, deterministic, fully-tested expiry path so that an
expired or revoked session never lands the user on a broken authenticated screen, never double-prompts,
and never silently fails. Re-login after expiry must restore the user to a clean unauthenticated
state with the back stack cleared.

This is a pure integration/UX ticket. It introduces no new endpoints and no new persisted schema; it
introduces a `SessionEvent` bus, an expiry-reason model, and the navigation glue that consumes them.

## 2. Context & References

- **AND-013 (401 refresh authenticator):** `SessionAuthenticator : okhttp3.Authenticator` calls
  `POST /ui/session/refresh` once (single-flight) on a 401 for an authenticated user, retries, and on
  failure must "emit logged-out". This ticket defines *where that emission goes* and what the UX is.
- **AND-029 (getMe + auth state store):** `AuthStateStore` exposes `StateFlow<AuthState>` and
  persists `authenticated`/`user_sub` to DataStore, reflecting the cookie session. This ticket calls
  its `clear(...)` path and reads its flow for routing.
- **AND-025 (auth-gated routing):** top-level gate that chooses the authenticated vs unauthenticated
  nav graph based on `AuthState`. This ticket feeds it a transient expiry event in addition to the
  steady-state flag.
- **AND-023 (unauthenticated nav graph) / AND-030 (login screen):** the destination of the expiry
  route; login must accept and render an expiry reason.
- **AND-032 (logout flow):** shares the "tear down session + route to login" path; this ticket must
  not conflict with explicit logout (different reason, same teardown).
- Backend dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). `POST /ui/session/refresh`,
  `GET /ui/me`. OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`.
- Namespace: `com.testlogon.android`. Module: this code lives in `core-data`
  (`com.testlogon.android.core.data.session`) for the event bus + handler, `core-model`
  (`com.testlogon.android.core.model.session`) for the reason enum, and `app`
  (`com.testlogon.android.navigation`) for routing glue.

## 3. Functional Requirements

FR-1. When `SessionAuthenticator` exhausts its single refresh attempt (refresh returns non-2xx, throws,
or the retried request is again 401), the system MUST mark the session unrecoverably expired exactly
once per session lifecycle and propagate a `SessionEvent.Expired(reason)`.

FR-2. On an `Expired` event the system MUST: (a) clear the persisted auth state via
`AuthStateStore.clear(reason)`; (b) clear the persistent cookie jar's session cookies; (c) emit a
one-shot UI event consumed by the navigation host.

FR-3. The navigation host MUST react to the one-shot expiry event by navigating to the login route with
the reason as an argument, popping the entire authenticated back stack (`popUpTo(graph root)
{ inclusive = true }`, `launchSingleTop = true`) so back-press cannot return to an authenticated screen.

FR-4. The login screen MUST render a non-dismissable inline banner/snackbar describing the reason
(e.g. "Your session expired. Please sign in again." vs "You were signed out." for explicit logout vs
"Your session was revoked." for server revocation), localized via string resources.

FR-5. Expiry MUST be idempotent and debounced: concurrent in-flight requests that each receive a
post-refresh 401 MUST collapse into a single `Expired` event and a single navigation. No double banner,
no nav loop.

FR-6. The event MUST be observed only while the UI is in an active lifecycle state
(`repeatOnLifecycle(STARTED)`); events received while backgrounded MUST be delivered on the next
resume (no loss), using a buffered/replay-last channel.

FR-7. Distinguish an *unrecoverable expiry* (this ticket) from a transient network failure (offline) —
the latter must NOT route to login; it surfaces the offline/stale state (AND-021) and leaves auth state
intact.

FR-8. After the user re-authenticates from the expiry-driven login, the app MUST consume/clear the
reason so a later normal logout or a fresh launch does not re-show the stale expiry banner.

## 4. Technical Design

### 4.1 Reason model (`core-model`)

```kotlin
package com.testlogon.android.core.model.session

enum class LogoutReason {
    SESSION_EXPIRED,   // refresh failed after 401 (this ticket's primary path)
    SESSION_REVOKED,   // server explicitly invalidated (e.g. 403 session_revoked)
    USER_INITIATED,    // explicit logout (AND-032)
    UNKNOWN
}
```

### 4.2 Session event bus (`core-data`)

A process-singleton, Hilt-provided bus decoupling the OkHttp/network layer from Compose. Uses a
`MutableSharedFlow` with `replay = 0` plus an internal "armed" guard for idempotency, and an
`extraBufferCapacity` so emission from the authenticator's IO thread never suspends.

```kotlin
package com.testlogon.android.core.data.session

sealed interface SessionEvent {
    data class Expired(val reason: LogoutReason) : SessionEvent
}

@Singleton
class SessionEventBus @Inject constructor() {
    private val _events = MutableSharedFlow<SessionEvent>(
        replay = 0, extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val events: SharedFlow<SessionEvent> = _events.asSharedFlow()

    private val expired = AtomicBoolean(false)

    /** Idempotent: only the first call per session lifecycle emits. */
    fun notifyExpired(reason: LogoutReason) {
        if (expired.compareAndSet(false, true)) {
            _events.tryEmit(SessionEvent.Expired(reason))
        }
    }

    /** Re-arm after a successful (re)login so a future expiry can fire again. */
    fun reset() { expired.set(false) }
}
```

### 4.3 Wiring the authenticator (modifies AND-013 collaborator surface)

AND-013's `SessionAuthenticator` is given an injected `SessionExpiryHandler` (interface in `core-data`)
that it calls on unrecoverable failure instead of touching UI:

```kotlin
interface SessionExpiryHandler {
    /** Called from OkHttp IO thread when refresh+retry cannot recover the session. */
    fun onUnrecoverableExpiry(reason: LogoutReason)
}

@Singleton
class DefaultSessionExpiryHandler @Inject constructor(
    private val authStateStore: AuthStateStore,        // AND-029
    private val cookieJar: PersistentCookieJar,         // AND-011
    private val bus: SessionEventBus,
    @ApplicationScope private val scope: CoroutineScope, // SupervisorJob + Dispatchers.IO
) : SessionExpiryHandler {
    override fun onUnrecoverableExpiry(reason: LogoutReason) {
        scope.launch {
            authStateStore.clear(reason)   // sets authenticated=false, persists last reason
            cookieJar.clearSession()       // drop session + ui_csrf cookies
            bus.notifyExpired(reason)
        }
    }
}
```

In `SessionAuthenticator.authenticate(...)`, replace the AND-013 placeholder
(`// emit logged-out`) with `expiryHandler.onUnrecoverableExpiry(LogoutReason.SESSION_EXPIRED)` and
return `null` (stop authenticating, surface the 401 to the caller). Revocation (HTTP 403 with
`detail.code == "session_revoked"`, mapped per AND-015) routes through the same handler with
`SESSION_REVOKED` from the response interceptor rather than the authenticator.

### 4.4 Navigation glue (`app`)

The single Activity's root composable collects the bus and drives Navigation-Compose:

```kotlin
@Composable
fun rememberSessionExpiryNavigator(navController: NavHostController) {
    val bus = LocalSessionEventBus.current
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(navController) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            bus.events.collect { event ->
                when (event) {
                    is SessionEvent.Expired -> navController.navigate(
                        Routes.login(reason = event.reason.name)
                    ) {
                        popUpTo(navController.graph.id) { inclusive = true }
                        launchSingleTop = true
                    }
                }
            }
        }
    }
}
```

`Routes.login(reason: String?)` (AND-022/AND-023) gains an optional `reason` nav argument
(`login?reason={reason}`, type `StringType`, nullable, default `null`). `LoginViewModel` (AND-031)
reads it via `SavedStateHandle`, maps to `LogoutReason`, exposes it in `LoginUiState`, and the screen
renders the banner. On a successful login the LoginViewModel calls `bus.reset()` and clears the reason
from `SavedStateHandle` (FR-8).

### 4.5 Threading & ownership

- Emission originates on OkHttp's IO thread → handler hops to `@ApplicationScope` (IO) for the
  suspend `clear`/`clearSession`, then `tryEmit` (non-suspending) onto the SharedFlow.
- Collection happens on the main thread inside `repeatOnLifecycle(STARTED)`.
- The `AtomicBoolean` guard makes N concurrent failures yield ≤1 emission (FR-5).

## 5. API Contract

This ticket adds **no new endpoints**. It consumes two existing ones owned by other tickets:

- `POST /ui/session/refresh` — invoked by `SessionAuthenticator` (AND-013), not by this ticket
  directly. Success (`2xx`) sets refreshed cookies; failure (`4xx/5xx`) is the trigger for
  `onUnrecoverableExpiry`. The request must carry the `X-CSRF-Token` header from the `ui_csrf` cookie
  (AND-012).
- `GET /ui/me` — owned by AND-029; not re-called here. A 401 from `/ui/me` after refresh also routes
  through the expiry handler.

Reference unrecoverable-refresh response shapes this ticket reacts to (FastAPI `detail` per AND-015):

```json
// 401 — session expired / refresh rejected
{ "detail": "Not authenticated" }

// 403 — server-side revocation (routed as SESSION_REVOKED)
{ "detail": { "code": "session_revoked", "msg": "Session has been revoked" } }
```

The detailed request/response contract for `refresh` is owned by **AND-013**; the `me`/auth-state
contract by **AND-029**.

## 6. Data & State Management

- **Transient event:** `SessionEvent.Expired` flows through `SessionEventBus` (in-memory only,
  process-singleton, not persisted).
- **Persisted state (AND-029 store, extended):** `AuthStateStore.clear(reason: LogoutReason)` sets
  `authenticated = false`, nulls `user_sub`, and persists `last_logout_reason: String` in DataStore so
  that a cold launch into the login screen can show the correct banner even after process death.
  Cleared by the LoginViewModel on successful re-auth (FR-8).
- **UI state (AND-031 `LoginUiState`):** gains `expiryReason: LogoutReason? = null`. The screen renders
  the banner iff non-null and not yet dismissed.
- **Cookie jar:** `PersistentCookieJar.clearSession()` removes the session and `ui_csrf` cookies but
  preserves any non-session preferences. This is the authoritative invalidation; DataStore is the UX
  cache of *why*.
- Single source of truth for "are we logged in" remains `AuthStateStore.state: StateFlow<AuthState>`;
  the bus only handles the *one-shot* navigation+banner concern so AND-025's steady-state gate and this
  ticket's transient event do not race (the gate would also eventually route, but the event makes it
  immediate and carries the reason).

## 7. Error Handling & Resilience

- **Transient vs terminal (FR-7):** the authenticator only calls `onUnrecoverableExpiry` when it
  actually received a fresh 401/refresh-rejection. Connection failures / timeouts (the unreliable dev
  host, ~20s) throw `IOException` and surface as `ApiResult.NetworkError` (AND-018); they do NOT clear
  auth state or route to login. Verified by test (TS-4).
- **Refresh storm prevention:** AND-013 already single-flights refresh; this ticket adds the
  `AtomicBoolean` so even if multiple parallel requests each see a post-refresh 401, only one teardown
  and one navigation occur.
- **Nav-loop guard:** `launchSingleTop = true` plus the idempotency guard prevents repeated navigation
  to login. If already on the login route, the reason is updated in place rather than stacking.
- **Backgrounded delivery:** `repeatOnLifecycle(STARTED)` + `extraBufferCapacity = 1` ensures an event
  emitted while the app is in the background is delivered on resume rather than dropped, except that if
  multiple expiries somehow occur the `DROP_OLDEST` policy keeps the latest (they are equivalent).
- **Cold-launch fallback:** if the process dies between teardown and navigation, the persisted
  `last_logout_reason` + `authenticated = false` cause AND-025's gate to land on login with the banner.
- **CSRF/refresh edge:** if the `ui_csrf` cookie is missing at refresh time, refresh is treated as
  unrecoverable → `SESSION_EXPIRED`.

## 8. Security & Privacy

- On expiry, session cookies and `ui_csrf` MUST be cleared from the persistent jar before navigation so
  no authenticated request can be replayed.
- The expiry reason is a coarse enum; no PII (no username, token, or `user_sub`) is placed in the nav
  argument, the banner text, or logs.
- `last_logout_reason` in DataStore is non-sensitive; nonetheless it is cleared on re-login.
- No new network surface; existing plaintext-HTTP dev-host caveat is unchanged and out of scope here.
- The expiry path must never leak the previous user's authenticated screens via the back stack
  (`popUpTo(inclusive)` requirement, FR-3) — a security-relevant assertion covered by TS-3.

## 9. Accessibility & i18n

- Banner strings live in `core-ui` / `app` `strings.xml`: `session_expired_message`,
  `session_revoked_message`, `signed_out_message`. No hard-coded strings.
- The banner is announced via Compose `Modifier.semantics { liveRegion = LiveRegionMode.Polite }` so
  TalkBack reads the reason on arrival at login.
- Banner contrast and touch targets follow Material 3 / AND-019 theme; the dismiss affordance (if any)
  is ≥48dp and has a `contentDescription`.
- RTL-safe (no manual padding directionality). Reason mapping is locale-independent (enum → resource).

## 10. Telemetry & Logging

- Log at `INFO`: `"session_expiry reason=<reason> navigated=true"` via the app's Timber/`Logger`
  wrapper, no PII.
- Increment a counter event `session_expired_total{reason}` through the existing analytics seam if
  present; if no analytics module exists yet, leave a TODO referencing the telemetry epic and log only.
- Log at `DEBUG`: each `notifyExpired` call and whether the idempotency guard suppressed it, to debug
  refresh storms.
- Do NOT log cookie values, CSRF tokens, or `user_sub`.

## 11. Testing Strategy

Unit (JVM, `core-testing` fakes):

- TS-1 `SessionEventBusTest`: concurrent `notifyExpired` from N coroutines emits exactly one
  `Expired`; after `reset()` a subsequent call emits again. (FR-1, FR-5)
- TS-2 `DefaultSessionExpiryHandlerTest`: `onUnrecoverableExpiry` calls `authStateStore.clear(reason)`,
  `cookieJar.clearSession()`, then `bus.notifyExpired(reason)` in order (verify with relaxed mocks /
  fakes + `runTest`). (FR-2)
- TS-3 Navigation test (`androidx.navigation.testing.TestNavHostController` or Robolectric): emitting
  `Expired` navigates to `login?reason=SESSION_EXPIRED` and the authenticated back stack is empty
  (`popUpTo inclusive`). Back-press does not return to an authenticated route. (FR-3, security)
- TS-4 `SessionAuthenticatorExpiryTest` (extends AND-013 tests, MockWebServer): a post-refresh 401
  triggers exactly one `onUnrecoverableExpiry(SESSION_EXPIRED)`; an `IOException`/timeout does NOT
  trigger it and leaves auth state intact. (FR-7)
- TS-5 `LoginViewModelTest`: `SavedStateHandle` with `reason=SESSION_REVOKED` yields
  `expiryReason = SESSION_REVOKED`; successful login calls `bus.reset()` and clears the reason. (FR-4,
  FR-8)

Instrumented / Compose UI:

- TS-6 `LoginScreen` shows the correct localized banner per reason and announces it as a live region.
  (FR-4, A11y)
- TS-7 End-to-end expiry happy path: authenticated state → simulated 401 storm via MockWebServer
  dispatcher → user lands on login with banner, no duplicate banners, no nav loop. (the ticket's single
  Acceptance Criterion)

Lifecycle:

- TS-8 Event emitted while `STOPPED` is delivered after `STARTED` resume (no loss). (FR-6)

## 12. Dependencies & Sequencing

- **Depends on AND-013** (401 refresh authenticator): provides the unrecoverable-failure trigger point;
  this ticket replaces its "emit logged-out" placeholder with the `SessionExpiryHandler` call.
- **Depends on AND-029** (getMe + auth state store): provides `AuthStateStore.clear(...)` and the
  persisted auth flag; this ticket extends `clear` to take a `LogoutReason` and persist
  `last_logout_reason`.
- Soft-couples to **AND-011** (cookie jar — `clearSession()`), **AND-022/AND-023** (login route +
  `reason` arg), **AND-025** (auth-gated routing — steady-state fallback), **AND-031** (LoginViewModel),
  **AND-032** (logout reuses teardown with `USER_INITIATED`), **AND-015** (detail mapping for the 403
  revocation code).
- Sequencing: land after AND-013 and AND-029 are merged; coordinate the small `AuthStateStore.clear`
  signature change and the `Routes.login` argument addition with AND-029/AND-023 owners. No tickets are
  blocked by AND-044.

## 13. Risks & Open Questions

- R-1: AND-013 currently "emits logged-out" via an unspecified mechanism; if it already wrote directly
  to `AuthStateStore`, this ticket must refactor that into the shared handler to avoid double teardown.
  **Action:** make `DefaultSessionExpiryHandler` the only teardown path.
- R-2: Race between AND-025's steady-state gate (which also routes to login when `authenticated=false`)
  and this ticket's event-driven nav could double-navigate. Mitigated by `launchSingleTop` + the gate
  observing the same flow; verify in TS-3/TS-7.
- OQ-1: Does the backend expose a distinct revocation signal (403 `session_revoked`) or only generic
  401? Confirm against `/openapi.json` and `frontend/src/api/endpoints`. If only 401 exists, collapse
  `SESSION_REVOKED` into `SESSION_EXPIRED` and drop the 403 interceptor branch.
- OQ-2: Should the expiry banner be a dismissable snackbar or a persistent inline banner? Spec assumes
  persistent inline (non-dismissable until re-login) for clarity; confirm with design.
- OQ-3: Cookie-jar API: does AND-011 expose `clearSession()` (session-only) vs `clear()` (all)? If only
  `clear()` exists, request the narrower method from the AND-011 owner.

## 14. Acceptance Criteria

- AC-1 (from backlog): The expiry path produces a clean re-login experience, demonstrated by an
  automated test (TS-7): a simulated unrecoverable 401 routes the user to the login screen with a
  localized "session expired" reason, the authenticated back stack is cleared, and re-login succeeds.
- AC-2: A post-refresh 401 triggers exactly one teardown (`clear` + `clearSession` + bus emit) and
  exactly one navigation even under concurrent failing requests (TS-1, TS-4, TS-7).
- AC-3: A network/timeout failure against the unreliable dev host does NOT clear auth state nor route to
  login (TS-4).
- AC-4: The login screen shows the correct localized, accessibility-announced banner for
  `SESSION_EXPIRED`, `SESSION_REVOKED`, and `USER_INITIATED` (TS-5, TS-6).
- AC-5: After successful re-login the reason is cleared and `bus.reset()` is called so no stale banner
  reappears on subsequent normal logout or cold launch (TS-5).
- AC-6: An expiry event emitted while backgrounded is delivered on resume, not dropped (TS-8).

## 15. Definition of Done

- `SessionEventBus`, `SessionEvent`, `SessionExpiryHandler` / `DefaultSessionExpiryHandler`, and
  `LogoutReason` implemented under `com.testlogon.android` in the modules named in §2, wired via Hilt.
- `SessionAuthenticator` (AND-013) calls `onUnrecoverableExpiry`; `AuthStateStore.clear(reason)` and
  `Routes.login(reason)` extensions merged with their owning tickets.
- Navigation glue (`rememberSessionExpiryNavigator`) integrated in the single-Activity root and login
  banner rendered with localized strings + live region.
- All tests TS-1…TS-8 implemented and green in CI (AND-008); lint/detekt/ktlint clean (AND-005).
- No PII or secrets in logs; cookies cleared before navigation verified.
- Open questions OQ-1…OQ-3 resolved or explicitly deferred with owner sign-off; spec status moved from
  `draft` to `approved`.
