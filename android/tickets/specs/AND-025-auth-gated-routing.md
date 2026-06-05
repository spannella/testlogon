---
id: AND-025
title: Auth-gated routing
milestone: M1
epic: E03
priority: P0
size: M
status: draft
depends_on: [AND-023, AND-024, AND-029]
blocks: [AND-026, AND-027, AND-028]
---

# AND-025 — Auth-gated routing

## 1. Overview & Goal

TestLogon's Android client is a cookie-session app: a user is either logged out
(must see Login → MFA flows) or logged in (must see the bottom-nav app shell).
This ticket wires the **single source of truth for auth state** into
Navigation-Compose so that the visible nav graph always matches the observed
session, and so that out-of-band session changes — explicit logout, a hard 401
that survives refresh, or session expiry — deterministically redirect the user
to the correct graph without leaving stale authenticated screens on the back
stack.

The goal is a small, well-tested routing layer in `:app` that:

1. Observes the persistent auth state produced by AND-029
   (`AuthStateStore.state: StateFlow<AuthState>`).
2. Selects the **unauthenticated graph** (AND-023) or the **authenticated graph**
   (AND-024) as the active top-level destination.
3. Reacts to *transitions* in auth state (Unknown→Unauthenticated→Authenticated
   and back) by navigating and **clearing the opposing graph from the back
   stack** so Back never crosses the auth boundary.
4. Shows a deterministic splash/bootstrap state while auth is `Unknown` (first
   launch, before DataStore + `getMe()` resolve), preventing a login-screen
   flash for already-authenticated users.

Non-goals: building the graphs themselves (AND-023/AND-024), implementing
`getMe()` or the DataStore-backed store (AND-029), the network 401→refresh
interceptor (owned by core-network / AND-028), and the actual Login/MFA UIs
(E03 feature tickets). This ticket is the *glue and redirect policy* plus its
test suite.

## 2. Context & References

- Repo `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. Module under work: `:app` (namespace
  `com.testlogon.android`). New routing code lives in
  `com.testlogon.android.navigation`.
- Module layering: `app -> feature-* -> core-*`. The auth state contract is in
  `:core-data` (AND-029); routing consumes it but does not own persistence.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, single-Activity. minSdk 24 / compileSdk 35, JDK 17.
- **Upstream contracts:**
  - AND-022 — `NavHost`, typed route definitions, `MainActivity`. This ticket
    extends the host created there.
  - AND-023 — Unauthenticated graph; `Login` is its start destination.
  - AND-024 — Authenticated graph + bottom-nav scaffold; post-login destination.
  - AND-029 — `getMe()` + `AuthStateStore` (authenticated flag, `user_sub`),
    backed by DataStore, reflecting the cookie session. **This is the observed
    input.**
- Backend (FastAPI, dev `http://18.222.237.167:8000`, plaintext + unreliable):
  cookie session via `POST /ui/session/start` → MFA → `POST /ui/session/finalize`
  → `GET /ui/me`; `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 client calls
  `POST /ui/session/refresh` once then retries. Logout is `POST /ui/session/logout`.
  Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.

## 3. Functional Requirements

FR-1. **Single graph visible per auth state.** When `AuthState` is
`Unauthenticated`, only the unauthenticated graph is reachable; when
`Authenticated`, only the authenticated graph is reachable.

FR-2. **Bootstrap gating.** While `AuthState == Unknown`, the host shows a
bootstrap (splash) destination, not Login and not Home. No login flash for
returning authenticated users.

FR-3. **Login → app transition.** When state transitions
`Unauthenticated → Authenticated`, navigate to the authenticated graph and pop
the entire unauthenticated graph (inclusive) off the back stack.

FR-4. **Logout / expiry → login transition.** When state transitions
`Authenticated → Unauthenticated` (explicit logout, or a 401 that survived
refresh, or session expiry), navigate to the unauthenticated graph and pop the
entire authenticated graph (inclusive). Any in-flight authenticated screen is
removed.

FR-5. **Back-stack isolation.** Pressing system Back from the start destination
of either graph must not navigate into the other graph; from authenticated Home
it follows normal Compose Back behavior (exits app at the start tab) and never
reveals Login.

FR-6. **Idempotent / debounced redirects.** Repeated emissions of the same
`AuthState` value must not re-trigger navigation. Only *distinct* transitions
drive a `navigate(...)`.

FR-7. **Optional return target on expiry.** When redirected to Login due to
expiry from a deep authenticated route, the route key may be captured so a
future ticket can restore it post-login. This ticket captures and stores it in
the routing VM but does not implement restoration (named below as AND-026's
concern).

FR-8. **Logout trigger.** Expose a `logout()` entry point usable by the
authenticated UI (e.g., Profile) that calls the store/repository to clear the
session, which causes the state transition that FR-4 handles. (UI button is
AND-024/feature scope; the function is wired here.)

## 4. Technical Design

### 4.1 Auth state model (consumed from AND-029)

```kotlin
// :core-data — defined by AND-029, referenced here.
sealed interface AuthState {
    data object Unknown : AuthState          // bootstrap, not yet resolved
    data object Unauthenticated : AuthState
    data class Authenticated(val userSub: String) : AuthState
}

interface AuthStateStore {
    val state: StateFlow<AuthState>          // hot, replays latest
    suspend fun refreshFromBackend()         // calls getMe(), updates state
    suspend fun clear()                      // local clear (used by logout)
}
```

### 4.2 Top-level destinations & typed routes (extends AND-022)

```kotlin
// com.testlogon.android.navigation
sealed interface TopLevelGraph {
    @Serializable data object Bootstrap : TopLevelGraph          // splash
    @Serializable data object Unauthenticated : TopLevelGraph    // AND-023 graph
    @Serializable data object Authenticated : TopLevelGraph      // AND-024 graph
}
```

The single `NavHost` from AND-022 gets `startDestination = Bootstrap` and three
`navigation<TopLevelGraph.X>` subgraphs (the two real graphs are contributed by
AND-023/AND-024 via extension functions on `NavGraphBuilder`).

### 4.3 Routing ViewModel

```kotlin
@HiltViewModel
class AuthRoutingViewModel @Inject constructor(
    private val authStateStore: AuthStateStore,
    private val sessionRepository: SessionRepository, // logout(), owned by AND-028
) : ViewModel() {

    val routeState: StateFlow<AuthState> =
        authStateStore.state
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), AuthState.Unknown)

    private val _pendingReturnRoute = MutableStateFlow<String?>(null)
    val pendingReturnRoute: StateFlow<String?> = _pendingReturnRoute.asStateFlow()

    fun capturePendingReturnRoute(route: String?) { _pendingReturnRoute.value = route }

    fun logout() = viewModelScope.launch {
        runCatching { sessionRepository.logout() }   // POST /ui/session/logout
            .also { authStateStore.clear() }         // ensure local clear even if network fails
    }
}
```

`logout()` always performs a local clear: the dev backend is unreliable, so a
failed network logout must still log the user out locally (FR-4, FR-8).

### 4.4 The auth-gated effect (the core of the ticket)

```kotlin
@Composable
fun AuthGatedNavHost(
    navController: NavHostController,
    viewModel: AuthRoutingViewModel = hiltViewModel(),
) {
    val authState by viewModel.routeState.collectAsStateWithLifecycle()

    LaunchedEffect(navController) {
        viewModel.routeState
            .map { it.toTopLevelTarget() }       // Unknown->Bootstrap, etc.
            .distinctUntilChanged()              // FR-6: only distinct transitions
            .collect { target -> navController.routeTo(target) }
    }

    NavHost(navController, startDestination = TopLevelGraph.Bootstrap) {
        composable<TopLevelGraph.Bootstrap> { BootstrapScreen() }
        unauthenticatedGraph(navController)      // AND-023
        authenticatedGraph(navController, onLogout = viewModel::logout) // AND-024
    }
}

private fun AuthState.toTopLevelTarget(): TopLevelGraph = when (this) {
    AuthState.Unknown          -> TopLevelGraph.Bootstrap
    AuthState.Unauthenticated  -> TopLevelGraph.Unauthenticated
    is AuthState.Authenticated -> TopLevelGraph.Authenticated
}

private fun NavHostController.routeTo(target: TopLevelGraph) {
    if (currentBackStackEntry?.destination?.hierarchy?.any { it.hasRoute(target) } == true) return
    navigate(target) {
        popUpTo(graph.id) { inclusive = true }   // clear everything across the boundary
        launchSingleTop = true
    }
}
```

`popUpTo(graph.id) { inclusive = true }` guarantees the opposing graph is fully
removed from the back stack (FR-3, FR-4, FR-5). The early `return` when already
on the target subgraph makes redirects idempotent on re-subscription
(config change / process death restore).

### 4.5 Bootstrap kickoff

`MainActivity.onCreate` (AND-022) launches `authStateStore.refreshFromBackend()`
once at startup (debounced to a single in-flight call). Until it completes,
state stays `Unknown` → `Bootstrap` is shown. AND-029 owns the read of cached
DataStore state, which may resolve `Authenticated`/`Unauthenticated`
optimistically before the `getMe()` round-trip confirms it; this ticket simply
follows whatever state is emitted.

### 4.6 Why ViewModel + effect, not navigation in the store

Navigation requires a `NavController` (a UI/Activity-scoped object) and must run
on the main thread tied to the composition lifecycle. The store stays
platform-agnostic and testable; the `LaunchedEffect`/VM bridge keeps navigation
side effects observable and unit-testable via `TestNavHostController`.

## 5. API Contract

This ticket performs **no new network calls of its own**; it reacts to state.
Two existing endpoints are referenced through repositories owned by other
tickets:

- `GET /ui/me` (AND-029) → drives `AuthState`. Response shape (subset):
  ```json
  { "user_sub": "us-east-2:abc-123", "username": "spannella", "factors": ["totp"] }
  ```
  A `200` resolves `Authenticated(userSub)`; a `401` (after one
  `/ui/session/refresh` retry) resolves `Unauthenticated`.
- `POST /ui/session/logout` (AND-028 `SessionRepository.logout()`) — invoked by
  `AuthRoutingViewModel.logout()`. Requires `X-CSRF-Token` header echoing the
  `ui_csrf` cookie (handled by the core-network interceptor). Request body
  empty; `204`/`200` expected; on success or network failure the client clears
  local auth state.

Error `detail` mapping (`string | [{msg}] | {code,...}`) is handled in
core-network and surfaces to this layer only as a thrown `ApiResult.Error`,
which `logout()` swallows after a local clear. The downstream tickets named
above own these contracts; routing asserts only on the resulting `AuthState`.

## 6. Data & State Management

- **Source of truth:** `AuthStateStore.state: StateFlow<AuthState>` (AND-029),
  DataStore-backed for persistence across process death. Routing never writes
  auth state except indirectly via `logout()`/`clear()`.
- **Derived UI state:** `AuthRoutingViewModel.routeState` re-exposes the store
  flow with `SharingStarted.WhileSubscribed(5_000)` and `Unknown` as the initial
  value, so a config change does not collapse to a wrong default.
- **Navigation state:** owned by `NavHostController`; the back stack is the
  durable record of where the user is *within* a graph. Cross-graph transitions
  always `popUpTo(inclusive)`, so the back stack never holds both graphs.
- **Pending return route:** held in-VM (`_pendingReturnRoute`), not persisted in
  this ticket. Survives config change (VM scope) but not process death; full
  persistence/restoration is deferred to AND-026.
- **Process-death restore:** on restore, store replays last persisted state →
  effect re-runs → idempotent `routeTo` no-ops if already correct; otherwise
  redirects. No double-navigation because of `distinctUntilChanged` +
  hierarchy check.

## 7. Error Handling & Resilience

- **getMe() failure / timeout (~20s):** AND-029 maps it to `Unauthenticated` (or
  retains cached state per its policy). Routing treats whatever is emitted as
  authoritative — it never blocks the UI on the network. While unresolved, state
  is `Unknown` → `Bootstrap` with a timeout-bounded spinner; if bootstrap
  exceeds ~25s the `BootstrapScreen` shows a "Couldn't reach server — Retry"
  action that re-invokes `refreshFromBackend()`.
- **401 after refresh (expiry):** core-network's interceptor performs the single
  `POST /ui/session/refresh` retry; a still-401 flips the store to
  `Unauthenticated`, which FR-4 turns into a Login redirect. No retry loop here.
- **Logout network failure:** local `clear()` runs regardless (FR-8); user is
  always logged out locally even against the flaky dev host.
- **Rapid state flapping:** `distinctUntilChanged` + `launchSingleTop` + the
  hierarchy guard prevent duplicate destinations and animation stacking.
- **Backoff:** only the bootstrap `getMe()` (idempotent GET) is retried, with
  bounded backoff owned by core-network; logout (POST) is not retried.

## 8. Security & Privacy

- The cookie jar (persistent) and `ui_csrf`/`X-CSRF-Token` handling live in
  core-network; this ticket holds no credentials. On logout, the local clear
  must also trigger cookie-jar clearing (delegated to `SessionRepository.logout()`
  / AND-028) so a subsequent `getMe()` cannot silently re-authenticate.
- Redirect-on-401 ensures authenticated screens (which may render PII from
  `/ui/me`) are popped *inclusive* the moment the session is invalid — no stale
  authenticated UI remains visible behind a Login screen.
- `user_sub` is the only identity field touched here; it is not logged (see §10).
- Dev backend is plaintext HTTP; no secrets are introduced by this ticket, but
  the `usesCleartextTraffic`/network-security-config concern is owned by the
  build/network tickets, not routing.

## 9. Accessibility & i18n

- `BootstrapScreen` exposes a `CircularProgressIndicator` with
  `Modifier.semantics { contentDescription = stringResource(R.string.bootstrap_loading) }`
  and a polite live-region announcement when transitioning to the retry state.
- All routing-introduced strings (bootstrap loading, retry button, "Couldn't
  reach server") are in `:app` `strings.xml`; no hardcoded literals. Locale
  changes are config changes — `routeState` survives them and re-derives the
  target without re-navigation.
- Focus: after a graph swap, focus is restored to the new start destination's
  primary header so TalkBack users are not stranded on a removed node.
- Redirects are not announced as errors except expiry, which posts a polite
  (non-assertive) "Session expired, please sign in again" message.

## 10. Telemetry & Logging

- Emit a structured event on each *distinct* transition:
  `nav_auth_transition { from, to, reason }` where `reason ∈
  {bootstrap, login, logout, expiry, refresh_failed}`. Reason is inferred from
  the prior state and the trigger (logout vs. interceptor-driven).
- Bootstrap timing: `nav_bootstrap_resolved { duration_ms, resolved_state }`.
- Logging via the project logger (Timber/equivalent), **never log `user_sub`,
  cookies, or CSRF tokens**; log only the `AuthState` *type* name. Debug-only
  verbose logs gated behind `BuildConfig.DEBUG`.
- No third-party analytics introduced; events go through the existing telemetry
  sink (or a no-op binding if none exists yet). If the telemetry module is not
  present at M1, define a `NavTelemetry` interface with a no-op default Hilt
  binding so call sites are stable.

## 11. Testing Strategy

**Unit (`:app` test, JVM, no device):**

- `AuthRoutingViewModel`:
  - `routeState` emits `Unknown` initially then mirrors the store.
  - `logout()` calls `sessionRepository.logout()` AND `authStateStore.clear()`
    even when `logout()` throws (use a throwing fake).
  - `capturePendingReturnRoute` stores/clears the route.
  - Use `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher`; fake
    `AuthStateStore` backed by a `MutableStateFlow`.

**Navigation behavior (`TestNavHostController`, Robolectric/JVM):**

- Transition matrix driven by pushing values into the fake store flow:
  - `Unknown → Bootstrap` shows Bootstrap.
  - `Unknown → Authenticated` lands on authenticated graph, **no** unauth entry
    on back stack.
  - `Unauthenticated → Authenticated` pops unauth inclusive (assert back stack
    has no `Unauthenticated` route).
  - `Authenticated → Unauthenticated` pops auth inclusive (FR-4).
  - Duplicate same-state emission → exactly one `navigate` (assert via
    back-stack entry count / spy).
- Back from each graph start destination does not cross the boundary (FR-5).

**Instrumented (`androidTest`, optional smoke):**

- Compose UI test: stub authenticated → emit `Unauthenticated`, assert Login
  start destination is displayed and the previous authenticated node is gone.

**Coverage gate:** the transition derivation (`toTopLevelTarget`) and `routeTo`
guard logic must be 100% branch-covered. Acceptance ("auth state changes drive
navigation correctly (tested)") maps directly to the transition-matrix tests.

## 12. Dependencies & Sequencing

- **Depends on:**
  - AND-023 (unauthenticated graph + `Login` start) — provides
    `NavGraphBuilder.unauthenticatedGraph`.
  - AND-024 (authenticated graph + bottom nav) — provides
    `NavGraphBuilder.authenticatedGraph` and the `onLogout` hook target.
  - AND-029 (`getMe()` + `AuthStateStore`) — provides the observed `AuthState`.
  - Transitively AND-022 (NavHost/host scaffold) and AND-028
    (`SessionRepository`/interceptor) for `logout()` and 401→refresh.
- **Sequencing:** land after AND-023/024/029 expose their public surfaces.
  Integrate the `AuthGatedNavHost` into `MainActivity` (AND-022) last. If
  AND-028 is not yet merged, stub `SessionRepository.logout()` behind an
  interface so this ticket can land with a local-clear-only path.
- **Blocks:** AND-026 (deep-link / return-route restoration), AND-027, and
  AND-028's end-to-end session wiring depend on the gating policy defined here.

## 13. Risks & Open Questions

- **R1 — login flash:** if AND-029 emits `Unauthenticated` before reading cached
  DataStore, returning users briefly see Login. Mitigation: `Bootstrap` start
  destination + `Unknown` initial value; require AND-029 to emit `Unknown` until
  cache read completes. *Open:* confirm AND-029's emission ordering.
- **R2 — double navigation on restore:** mitigated by `distinctUntilChanged` +
  hierarchy guard; verify under process-death (`testProcessDeath`).
- **R3 — pending-return persistence:** not persisted here; if AND-026 needs it
  across process death, it must move into `SavedStateHandle`/DataStore.
  *Open question for AND-026.*
- **R4 — expiry reason inference:** distinguishing user logout from interceptor
  expiry for telemetry requires a signal from core-network (e.g., a
  `clear(reason)` overload). *Open:* does AND-028 expose a reason?
- **R5 — graph contribution shape:** assumes AND-023/024 expose
  `NavGraphBuilder` extension functions rather than self-contained `NavHost`s.
  Confirm the integration contract with those tickets.

## 14. Acceptance Criteria

AC-1. With state `Unauthenticated`, the unauthenticated graph (Login start) is
displayed; the authenticated graph is not on the back stack. *(test)*

AC-2. With state `Unknown` at launch, `Bootstrap` is displayed — no Login flash
for a user who resolves to `Authenticated`. *(test)*

AC-3. On `Unauthenticated → Authenticated`, the app navigates to the
authenticated graph and the unauthenticated graph is popped inclusive (assert
absent from back stack). *(test)*

AC-4. On `Authenticated → Unauthenticated` (logout, expiry, or post-refresh
401), the app navigates to Login and the authenticated graph is popped inclusive.
*(test)*

AC-5. System Back from either graph's start destination never crosses the auth
boundary. *(test)*

AC-6. Duplicate identical `AuthState` emissions trigger no additional
navigation. *(test)*

AC-7. `logout()` clears local auth state even when the network logout call
fails. *(test)*

AC-8. The transition-matrix and `routeTo` guard logic are 100% branch-covered;
the suite encodes the backlog AC "auth state changes drive navigation correctly
(tested)".

## 15. Definition of Done

- `AuthGatedNavHost`, `AuthRoutingViewModel`, `TopLevelGraph`, and
  `BootstrapScreen` implemented in `com.testlogon.android.navigation`, wired into
  `MainActivity`'s single `NavHost`.
- All FR-1…FR-8 satisfied; all AC-1…AC-8 tests green in CI on the
  `android-port` branch.
- No `user_sub`/cookie/CSRF values logged; telemetry events emitted on distinct
  transitions; strings externalized to `strings.xml`.
- `logout()` performs network logout (best effort) plus guaranteed local clear,
  delegating cookie-jar clearing to `SessionRepository`.
- Code passes ktlint/detekt and the module's Hilt/KSP build; no new lint
  baseline suppressions.
- PR description links AND-023/AND-024/AND-029 and notes the stubbed paths (if
  AND-028 not merged) plus the resolution of open questions R1 and R4.
- Reviewed by a code owner of `:app` navigation; merged to `android-port`.
