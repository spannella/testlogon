---
id: AND-023
title: Unauthenticated nav graph
milestone: M1
epic: E03
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-022]
blocks: [AND-024]
---

# AND-023 — Unauthenticated nav graph

## 1. Overview & Goal

This ticket defines and wires the **unauthenticated navigation graph** for the
TestLogon native Android app (`com.testlogon.android`). The graph contains the
set of screens a user can reach while *logged out*: the Login screen, the MFA
(multi-factor) screen, and placeholder destinations for Register, Recovery, and
Magic-link flows.

The goal is structural, not behavioral: deliver a typed, testable
Navigation-Compose subgraph (`authNavGraph`) that nests under the single-Activity
`NavHost` introduced in AND-022, with **Login as the start destination when the
user is logged out**. Screen *content* (real Login UI, MFA verification, etc.) is
owned by downstream feature tickets in epics E04/E05; this ticket delivers the
route definitions, the nested graph builder, the inter-destination wiring
(Login → MFA → Register/Recovery/Magic-link), and minimal placeholder
composables so the graph compiles and is navigable end-to-end.

A user logged out lands on Login; from Login they can reach MFA (challenge
continuation), Register, Recovery, and Magic-link. The acceptance bar is: the
graph is wired, the unauthenticated subgraph is the start destination of the host
when logged out, and navigation between its destinations is verified by tests.

## 2. Context & References

- **Repo:** `spannella/testlogon`, monorepo Android app under `android/`, branch
  `android-port`.
- **Module:** Routes and graph live in the `app` module
  (`com.testlogon.android` namespace) alongside the AND-022 `NavHost`. Placeholder
  screen composables live in `feature-auth` (`com.testlogon.android.feature.auth`)
  to avoid churn when real screens land. Route enums/sealed types live in
  `core-ui` navigation utilities (`com.testlogon.android.core.ui.navigation`) so
  both `app` and `feature-*` can reference them without an `app` dependency.
- **Depends on AND-022** (Navigation host & routes): provides the single-Activity
  `NavHost`, the typed route convention, and shared transition specs. This ticket
  consumes that host and registers the auth subgraph into it.
- **Blocks AND-024** (Authenticated nav graph + bottom nav skeleton): the
  authenticated graph is the post-login sibling of this subgraph; the top-level
  switch between the two is exercised once AND-024 lands.
- **Auth model (E04/E05):** the cookie-based session flow
  (`POST /ui/session/start` → MFA `begin`/`verify` → `POST /ui/session/finalize`
  → `GET /ui/me`) is the eventual driver of which graph shows. This ticket does
  **not** implement that flow; it only models the *destinations* that flow will
  navigate between and reads a coarse logged-in/logged-out signal. *(Verified
  against OpenAPI: `POST /ui/session/start`, `POST /ui/session/finalize`,
  `GET /ui/me`, plus `POST /ui/mfa/{totp,sms,email}/verify` and
  `POST /ui/mfa/{totp,sms,email}/begin` all exist — see §16.)*
- **Web reference:** the `frontend/` SPA exposes the unauthenticated routes
  `/login`, `/register`, `/password-recovery`, and `/magic-link-verify`
  (verified in `src/App.tsx`). **Correction:** the web app has **no** `/mfa`
  route and no `/recovery` or `/magic-link` route. In the web client, MFA is an
  *in-page step* of the Login page (`LoginStep = "credentials" | "mfa" |
  "magic-link" | "webauthn"` in `src/pages/Login.tsx`), and the `challenge_id`
  is held in React component state, **not** passed as a URL argument. Modelling
  MFA as a *separate* arg-bearing Android destination (this ticket's design) is
  therefore a deliberate platform divergence, not a mirror of the web routes —
  it is recorded as a design assumption in §16, not a contract requirement.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17,
  Gradle 8.9, AGP 8.7.3.

## 3. Functional Requirements

FR-1. Define a nested navigation graph, the **auth graph**, addressable by a
stable route constant `AuthGraph.ROUTE` (`"auth_graph"`).

FR-2. The auth graph contains exactly these destinations:

| Destination  | Route                       | Status in this ticket |
|--------------|-----------------------------|-----------------------|
| Login        | `auth/login`                | Placeholder screen    |
| MFA          | `auth/mfa/{challengeId}`    | Placeholder screen, arg-bearing |
| Register     | `auth/register`             | Placeholder screen    |
| Recovery     | `auth/recovery`             | Placeholder screen    |
| Magic-link   | `auth/magic_link`           | Placeholder screen    |

FR-3. **Login is the start destination** of the auth graph
(`startDestination = AuthDest.Login.route`).

FR-4. The auth graph is the host's start destination **when the session state is
logged out**. A coarse `SessionStatus` (`Unknown | LoggedOut | LoggedIn`) gates
which top-level graph the host starts on; this ticket wires the `LoggedOut`
branch to `AuthGraph.ROUTE` and leaves a clearly named hook for the `LoggedIn`
branch (owned by AND-024).

FR-5. Navigation edges are wired so that from **Login** the user can navigate to:
MFA (with a `challengeId` argument), Register, Recovery, and Magic-link. MFA,
Register, Recovery, and Magic-link each support back navigation to Login (system
back / explicit up).

FR-6. Navigation actions are exposed to screens via lambda callbacks (not by
passing `NavController` into composables), preserving the unidirectional,
testable wiring established in AND-022.

FR-7. The MFA destination accepts a required `challengeId: String` path argument,
mirroring the `challenge_id` returned by `POST /ui/session/start`. A typed
helper builds the route (`AuthDest.Mfa.build(challengeId)`).

FR-8. Each placeholder composable renders an identifiable title and the buttons
required to exercise its outbound edges (e.g., Login renders "Continue to MFA",
"Register", "Recover account", "Use magic link"), so navigation is testable by
node tag/text. No network calls, no real form logic.

## 4. Technical Design

### 4.1 Route model (`core-ui`)

```kotlin
package com.testlogon.android.core.ui.navigation

/** Stable route id for the unauthenticated subgraph. */
object AuthGraph {
    const val ROUTE = "auth_graph"
}

/** Typed destinations within the auth graph. */
sealed interface AuthDest {
    val route: String

    data object Login : AuthDest { override val route = "auth/login" }

    data object Mfa : AuthDest {
        const val ARG_CHALLENGE_ID = "challengeId"
        override val route = "auth/mfa/{$ARG_CHALLENGE_ID}"
        fun build(challengeId: String): String =
            "auth/mfa/${Uri.encode(challengeId)}"
    }

    data object Register : AuthDest { override val route = "auth/register" }
    data object Recovery : AuthDest { override val route = "auth/recovery" }
    data object MagicLink : AuthDest { override val route = "auth/magic_link" }
}
```

### 4.2 Navigation actions

A thin action holder converts intent into `NavController` calls, keeping
composables controller-free:

```kotlin
class AuthNavActions(private val navController: NavController) {
    fun toMfa(challengeId: String) = navController.navigate(AuthDest.Mfa.build(challengeId))
    fun toRegister() = navController.navigate(AuthDest.Register.route)
    fun toRecovery() = navController.navigate(AuthDest.Recovery.route)
    fun toMagicLink() = navController.navigate(AuthDest.MagicLink.route)
    fun back() = navController.popBackStack()
}
```

### 4.3 Graph builder (`app` module)

```kotlin
fun NavGraphBuilder.authNavGraph(actions: AuthNavActions) {
    navigation(
        route = AuthGraph.ROUTE,
        startDestination = AuthDest.Login.route,
    ) {
        composable(AuthDest.Login.route) {
            LoginPlaceholderScreen(
                onContinueToMfa = { challengeId -> actions.toMfa(challengeId) },
                onRegister = actions::toRegister,
                onRecovery = actions::toRecovery,
                onMagicLink = actions::toMagicLink,
            )
        }
        composable(
            route = AuthDest.Mfa.route,
            arguments = listOf(
                navArgument(AuthDest.Mfa.ARG_CHALLENGE_ID) { type = NavType.StringType }
            ),
        ) { entry ->
            val challengeId = entry.arguments
                ?.getString(AuthDest.Mfa.ARG_CHALLENGE_ID).orEmpty()
            MfaPlaceholderScreen(challengeId = challengeId, onBack = actions::back)
        }
        composable(AuthDest.Register.route) { RegisterPlaceholderScreen(onBack = actions::back) }
        composable(AuthDest.Recovery.route) { RecoveryPlaceholderScreen(onBack = actions::back) }
        composable(AuthDest.MagicLink.route) { MagicLinkPlaceholderScreen(onBack = actions::back) }
    }
}
```

### 4.4 Host integration

The AND-022 host registers this subgraph and selects the start graph by coarse
session state:

```kotlin
@Composable
fun TestLogonNavHost(
    sessionStatus: SessionStatus,
    navController: NavHostController = rememberNavController(),
) {
    val authActions = remember(navController) { AuthNavActions(navController) }
    val start = when (sessionStatus) {
        SessionStatus.LoggedIn -> RootGraph.MAIN   // owned by AND-024
        else -> AuthGraph.ROUTE                     // Unknown & LoggedOut -> auth
    }
    NavHost(navController = navController, startDestination = start) {
        authNavGraph(actions = authActions)
        // mainNavGraph(...) added by AND-024
    }
}
```

`SessionStatus` is provided to the host from a `RootViewModel`
(`StateFlow<SessionStatus>`); until the real session source lands (E04), it
emits `LoggedOut`, satisfying the acceptance criterion. `Unknown` is treated as
logged-out for routing so the user always sees Login during boot rather than a
blank host.

### 4.5 Placeholder screens (`feature-auth`)

Each placeholder is a stateless composable taking only navigation lambdas, each
tagged with `Modifier.testTag(...)` for instrumented tests, e.g.
`testTag("login_screen")`, `testTag("login_to_mfa_button")`. No ViewModel, no DI,
no I/O.

## 5. API Contract

**No backend API is consumed by this ticket.** It is pure client navigation
plumbing. The only contract surface is the **navigation route contract** in
§4.1, plus the *future* coupling: the MFA destination's `challengeId` argument is
shaped to receive the `challenge_id` string returned by `POST /ui/session/start`
(OpenAPI request schema `UiSessionStartReq`, response schema
`UiSessionStartResp`; the frontend aliases these as `SessionStartReq` /
`SessionStartResp` in `src/api/types.ts`):

```json
{ "auth_required": true, "challenge_id": "chg_abc123", "required_factors": ["totp"] }
```

**Verified field shapes (`UiSessionStartResp`):** `auth_required: boolean`
(the *only* required field), `challenge_id: string | null` (optional/nullable),
`required_factors: string[]`, `session_id: string | null` (optional). Because
`challenge_id` may be **absent** (e.g. when `auth_required` is `false` and the
session is established directly via `session_id`), the producer in E04 must only
navigate to the MFA destination when a non-null `challenge_id` is present; the
route argument itself is non-nullable `NavType.StringType`.

The real `/ui/session/*` and `/ui/mfa/*` calls, cookie jar, and `X-CSRF-Token`
handling are owned by the auth feature tickets (E04/E05); this ticket only
guarantees the route can carry `challenge_id` losslessly via `Uri.encode`.
*(CSRF mechanism verified: the web client reads the `ui_csrf` cookie and sends
it as the `X-CSRF-Token` header with `credentials: "include"` —
`src/api/client.ts`.)*

## 6. Data & State Management

- **Navigation back stack** is the primary state, owned by `NavController`. No
  Room, no DataStore, no Paging in this ticket.
- **`SessionStatus`** is the only external state read:

  ```kotlin
  enum class SessionStatus { Unknown, LoggedOut, LoggedIn }
  ```

  Exposed as `RootViewModel.sessionStatus: StateFlow<SessionStatus>`, collected in
  the host with `collectAsStateWithLifecycle()`. For this ticket the backing
  source is a stub returning `LoggedOut`; the StateFlow contract is finalized now
  so E04 can swap the source without touching the host.
- **MFA argument** flows as a `NavType.StringType` path arg, read from
  `NavBackStackEntry.arguments`, never persisted by this ticket.
- **Start-destination recomputation:** changing `startDestination` after first
  composition does not retroactively rebuild the back stack. Because the live
  switch from auth→main happens via explicit navigation after finalize (E04),
  the `start` selection here only governs cold start; this is documented as the
  intended behavior and asserted in tests for the `LoggedOut` boot case.

## 7. Error Handling & Resilience

- **Network resilience: N/A** — no network in this ticket (timeouts/backoff are
  owned by core-network and the auth feature tickets).
- **Navigation robustness:** all `navigate` calls target literal, compiled route
  constants, eliminating malformed-route risk. The MFA arg is `Uri.encode`d on
  build and decoded by Navigation, so special characters in `challenge_id` are
  safe.
- **Missing/empty argument:** if `challengeId` is absent, `MfaPlaceholderScreen`
  receives `""` (via `orEmpty()`) and renders without crashing; a guard logs a
  warning. Real validation/redirect is deferred to the MFA feature ticket.
- **Double navigation / rapid taps:** placeholder buttons rely on Navigation's
  single-top behavior where appropriate; to prevent duplicate destinations from
  fast double-taps, outbound `navigate` calls use `launchSingleTop = true`.
- **Back stack integrity:** system back from any auth destination pops toward
  Login; back from Login at the root exits the app (default host behavior, no
  custom interception added here).

## 8. Security & Privacy

- No credentials, tokens, cookies, or PII are handled, stored, or logged in this
  ticket. The `challengeId` is an opaque server-issued correlation id; it is
  passed only in-process via the nav back stack, never persisted to disk and
  never logged at info level.
- No deep links are registered for auth destinations in this ticket (deep-link /
  magic-link URL handling is its own future ticket); this avoids exposing
  `challenge_id` via external intents prematurely.
- Cookie jar, CSRF header (`X-CSRF-Token` from the `ui_csrf` cookie), and
  `session/refresh`-on-401 logic are explicitly out of scope and owned by
  core-network / E04. *(Verified against `src/api/client.ts`: on a `401` for an
  authenticated request the web client calls `POST /ui/session/refresh` once,
  de-duplicated via a shared `refreshPromise`, then retries the original
  request; an unauthenticated `401` is surfaced directly without refresh.)*

## 9. Accessibility & i18n

- Placeholder screens use Material 3 components with default focus/touch-target
  sizing (≥ 48dp). Every actionable button has a content description / accessible
  label sourced from `strings.xml` (no hardcoded UI strings), e.g.
  `R.string.auth_login_continue_to_mfa`.
- All visible labels are externalized to `res/values/strings.xml` to keep the
  graph translation-ready even though placeholders are temporary; this prevents a
  string-extraction backfill when real screens land.
- Screen roots expose a semantic heading (`Modifier.semantics { heading() }`) so
  TalkBack announces each destination. RTL is inherited from Compose defaults; no
  custom directional layout is introduced.

## 10. Telemetry & Logging

- Lightweight navigation breadcrumbs only: a single `NavController.OnDestination
  ChangedListener` (registered in the host) logs `route` transitions at DEBUG via
  the shared logger, with `challengeId` **redacted** (logged as `mfa/<redacted>`).
- No analytics events are emitted from this structural ticket; a named hook
  (`AuthNavAnalytics` interface, no-op default binding via Hilt) is provided so
  E04 can attach real screen-view events without modifying the graph builder.
- No PII, credentials, or full route arguments are logged.

## 11. Testing Strategy

**Unit (JVM, `core-testing`):**
- `AuthDest.Mfa.build("chg_abc123")` returns `auth/mfa/chg_abc123`; verify
  encoding of a value containing `/` and spaces.
- `AuthNavActions` calls the expected `NavController.navigate` route for each
  edge (verified with a mock/fake `NavController`).

**Instrumented / Compose UI (`androidTest`, `createComposeRule` +
`TestNavHostController`):**
- *Start destination:* host with `SessionStatus.LoggedOut` asserts current
  destination route == `AuthDest.Login.route` and current graph == `AuthGraph.ROUTE`.
- *Unknown boots to Login:* `SessionStatus.Unknown` also lands on Login.
- *Edges from Login:* click `login_to_mfa_button` → assert route matches
  `auth/mfa/{challengeId}` and arg present; click Register/Recovery/Magic-link →
  assert respective routes.
- *Back navigation:* from each child destination, `Espresso.pressBack()` /
  `navController.popBackStack()` returns to Login.
- *Arg propagation:* navigate to MFA with `challengeId = "chg_xyz"`; assert
  `MfaPlaceholderScreen` displays/receives `chg_xyz`.

Target: graph wiring and start-destination behavior fully covered; this satisfies
the AC "Graph wired; login is the start destination when logged out."

## 12. Dependencies & Sequencing

- **Depends on AND-022** (Navigation host & routes) — must be merged first; this
  ticket registers `authNavGraph` into that `NavHost` and reuses its typed-route
  convention and transition specs.
- **Blocks AND-024** (Authenticated nav graph + bottom nav skeleton) — AND-024
  adds `mainNavGraph` as the sibling top-level graph and exercises the
  `LoggedIn` branch of the start-destination switch defined here.
- **Soft coupling to E04/E05 auth feature tickets** — those replace placeholder
  composables with real screens and wire the live `SessionStatus` source and the
  `challenge_id` producer; no API change to the route contract is expected.
- **Sequencing:** AND-022 → **AND-023** → AND-024 → E04 auth screens.

## 13. Risks & Open Questions

- **R1 — Start-destination vs. live state.** Recomputing `startDestination`
  doesn't re-home an existing back stack. Mitigation: rely on explicit post-
  finalize navigation (E04) for the runtime switch; `start` here governs cold
  boot only. *Open: confirm with AND-024 whether the auth→main transition should
  `popUpTo(RootGraph.ROOT) { inclusive = true }`.*
- **R2 — Route ownership location.** Placing route types in `core-ui` vs. a
  dedicated `core-navigation` module. Chosen `core-ui` to avoid a new module for
  M1; revisit if navigation types grow.
- **R3 — Magic-link deep links.** Magic-link will eventually need an external
  deep link (`https`/custom scheme). Deliberately excluded here; *open question:*
  which ticket owns deep-link registration and `challenge_id` extraction.
- **R4 — MFA factor variants.** Real MFA needs factor selection
  (`totp`/`sms`/`email`). This ticket models one MFA destination; *open:* whether
  factor becomes a second arg or in-screen state (recommend in-screen state,
  decided by the MFA feature ticket).

## 14. Acceptance Criteria

- AC-1. A nested `authNavGraph` exists with route `auth_graph` containing Login,
  MFA, Register, Recovery, and Magic-link destinations.
- AC-2. **Login is the start destination** of the auth graph, and the auth graph
  is the host's start destination when `SessionStatus` is `LoggedOut` (and
  `Unknown`) — verified by an instrumented test.
- AC-3. From Login, navigation to MFA (with a `challengeId` arg), Register,
  Recovery, and Magic-link all succeed — verified by instrumented tests.
- AC-4. Back navigation from MFA/Register/Recovery/Magic-link returns to Login.
- AC-5. The `challengeId` path argument round-trips losslessly (encode on build,
  decode on read), including special characters.
- AC-6. No `NavController` is passed into any screen composable; screens receive
  navigation lambdas only.
- AC-7. All described unit and Compose UI tests pass in CI.

## 15. Definition of Done

- `AuthGraph`, `AuthDest`, and `AuthNavActions` implemented in `core-ui`;
  `authNavGraph` builder implemented in `app` and registered in the AND-022
  `NavHost`.
- Five placeholder composables implemented in `feature-auth`, stateless, tagged
  with `testTag`s, strings externalized to `strings.xml`.
- `SessionStatus` enum and `RootViewModel.sessionStatus: StateFlow<SessionStatus>`
  (stubbed to `LoggedOut`) wired into the host's start-destination selection,
  with a named hook for the `LoggedIn`/AND-024 branch.
- Unit + Compose UI tests from §11 written and green in CI; lint and detekt
  clean; module layering (`app → feature-* → core-*`) preserved with no `app`
  dependency leaking into `core-*`.
- All package references use `com.testlogon.android`. PR opened against
  `android-port` with the test evidence for AC-2/AC-3 referenced in the
  description, and the AND-024 integration point documented in code comments.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index/spec under `reference/openapi.*`; frontend under `reference/src/`;
Android framework docs labelled *(framework ref)*.

1. **`POST /ui/session/start` exists and returns the login/MFA challenge.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/start`
   (`req=UiSessionStartReq`, `resp=200:UiSessionStartResp`);
   `src/api/endpoints/auth.ts: sessionStart`.
2. **`UiSessionStartResp` field shape — `auth_required: bool` (required),
   `challenge_id: string|null`, `required_factors: string[]`,
   `session_id: string|null`.** VERDICT: Verified (with refinement: only
   `auth_required` is required; `challenge_id` is nullable/optional). SOURCE:
   OpenAPI `components.schemas.UiSessionStartResp`; mirrored in
   `src/api/types.ts: SessionStartResp`.
3. **The §5 example JSON `{auth_required, challenge_id, required_factors}` is a
   valid `UiSessionStartResp`.** VERDICT: Verified. SOURCE: schema
   `UiSessionStartResp` (note `session_id` also permitted; `challenge_id`
   optional).
4. **The MFA destination's `challengeId` corresponds to the server
   `challenge_id`.** VERDICT: Verified. SOURCE: `UiSessionStartResp.challenge_id`;
   `src/pages/Login.tsx` (`resp.challenge_id` captured after `sessionStart`).
5. **Auth-model chain `session/start → MFA begin/verify → session/finalize →
   /ui/me`.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/finalize`
   (`req=UiSessionFinalizeReq`), `GET /ui/me`, `POST /ui/mfa/totp/verify`,
   `POST /ui/mfa/sms/{begin,verify}`, `POST /ui/mfa/email/{begin,verify}`;
   `src/api/endpoints/auth.ts: sessionFinalize, getMe, verifyTotp, beginSms,
   verifySms, beginEmail, verifyEmail`.
6. **Web SPA unauthenticated routes are `/login`, `/register`,
   `/password-recovery`, `/magic-link-verify`.** VERDICT: Corrected (spec
   originally listed `/mfa`, `/recovery`, `/magic-link`). SOURCE:
   `src/App.tsx` (`<Route path="/login">`, `"/register"`,
   `"/password-recovery"`, `"/magic-link-verify"`).
7. **The web app has a dedicated `/mfa` route.** VERDICT: Corrected — false. MFA
   is an in-page step of the Login page. SOURCE: `src/App.tsx` (no `/mfa` route);
   `src/pages/Login.tsx` (`type LoginStep = "credentials" | "mfa" |
   "magic-link" | "webauthn"`; `challenge_id` kept in component state, set via
   `setStep("mfa")`).
8. **MFA factor variants are `totp | sms | email | recovery`, selectable
   in-screen (informs R4).** VERDICT: Verified. SOURCE: `src/pages/Login.tsx`
   (`type MfaMethod = "totp" | "sms" | "email" | "recovery"`, `activeMfa`
   state); OpenAPI `POST /ui/mfa/{totp,sms,email}/verify`,
   `POST /ui/mfa/recovery/{factor}`.
9. **Auth transport is cookie-based with CSRF header `X-CSRF-Token` sourced from
   the `ui_csrf` cookie, `credentials: "include"`.** VERDICT: Verified. SOURCE:
   `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token",
   csrf)`, `credentials: "include"`).
10. **`session/refresh`-on-401 retry-once is part of the transport (out of scope
    here).** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/refresh`;
    `src/api/client.ts` (refresh-once via shared `refreshPromise`, then retry).
11. **Validation/error responses use `HTTPValidationError` (422) with a
    `detail` array.** VERDICT: Verified. SOURCE: OpenAPI
    `resp=...;422:HTTPValidationError` on `POST /ui/session/start`;
    `components.schemas.HTTPValidationError`; `src/api/client.ts`
    (`normalizeErrorDetail(body.detail, ...)`).
12. **Register / Recovery / Magic-link backend endpoints exist (future
    coupling for placeholders).** VERDICT: Verified. SOURCE:
    `src/api/endpoints/auth.ts` — `registerStart` (`/ui/register/start`),
    `passwordRecoveryStart` (`/ui/password-recovery/start`), `passwordlessStart`
    (`/ui/passwordless/start`); the web app's "magic link" is the *passwordless*
    flow.
13. **Navigation-Compose nested graph via `navigation(route, startDestination)
    {}` and `NavGraphBuilder` extension.** VERDICT: Verified *(framework ref)*.
    SOURCE: Android docs — Navigation Compose nested graphs,
    https://developer.android.com/develop/ui/compose/navigation#nested-nav.
14. **Path argument via `navArgument(...) { type = NavType.StringType }` read
    from `NavBackStackEntry.arguments`.** VERDICT: Verified *(framework ref)*.
    SOURCE: https://developer.android.com/develop/ui/compose/navigation#nav-with-args.
15. **`Uri.encode` makes path args containing `/` and spaces round-trip
    losslessly.** VERDICT: Verified *(framework ref)*. SOURCE:
    `android.net.Uri.encode`,
    https://developer.android.com/reference/android/net/Uri#encode(java.lang.String).
16. **`collectAsStateWithLifecycle()` for collecting `StateFlow<SessionStatus>`
    in the host.** VERDICT: Verified *(framework ref)*. SOURCE:
    https://developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware.
17. **`launchSingleTop = true` prevents duplicate destinations on rapid taps.**
    VERDICT: Verified *(framework ref)*. SOURCE: Navigation `navigate` /
    `NavOptionsBuilder.launchSingleTop`,
    https://developer.android.com/guide/navigation/backstack#singleTop.

### Corrections made

- **§2 web routes (claims 6 & 7):** removed the non-existent `/mfa`, `/recovery`,
  and `/magic-link` web routes; replaced with the actual `/login`, `/register`,
  `/password-recovery`, `/magic-link-verify`. Clarified that web MFA is an
  in-page Login step (state-held `challenge_id`), and that modelling MFA as a
  separate arg-bearing Android destination is a deliberate platform divergence /
  design assumption, not a web-contract mirror.
- **§5 response shape (claim 2):** refined the field contract to match
  `UiSessionStartResp` exactly — `auth_required` is the only required field and
  `challenge_id` is nullable/optional; added the rule that E04 must only navigate
  to MFA when `challenge_id` is non-null. Added the correct OpenAPI schema names
  (`UiSessionStartReq`/`UiSessionStartResp`) and their frontend aliases.
- **§2 / §5 / §8 citations:** annotated the session-flow, CSRF (`X-CSRF-Token` /
  `ui_csrf`), and 401-refresh claims with verified source pointers.

### Open assumptions

- **A1 — Android MFA modelled as a standalone arg-bearing destination
  (`auth/mfa/{challengeId}`).** Unverifiable against the web contract because the
  web app keeps MFA in-page; this is an intentional native-navigation design
  choice. No backend contract requires it.
- **A2 — Route strings (`auth/login`, `auth/mfa/{challengeId}`, `auth/register`,
  `auth/recovery`, `auth/magic_link`) and graph id `auth_graph`.** Client-internal
  identifiers; not derivable from any backend or web source. Assumed stable for
  this ticket.
- **A3 — `SessionStatus { Unknown, LoggedOut, LoggedIn }` and
  `RootViewModel.sessionStatus: StateFlow<SessionStatus>`.** New Android
  abstraction with a stub emitting `LoggedOut`; the real source (derived from
  `GET /ui/me` / session cookies) lands in E04. The coarse tri-state is an
  assumption, not a backend-provided enum.
- **A4 — `Unknown` is routed to the auth (Login) graph during cold boot.** A
  product/UX assumption (avoid a blank host); no source dictates boot behavior.
- **A5 — Android module placement (`core-ui` for route types, `feature-auth` for
  placeholders, `app` for the graph builder).** Internal architecture decision
  (R2); unverifiable externally.

## 17. Test Plan

Test IDs `TC-AND-023-NN`. AC references point at §14. Because this ticket is pure
client navigation plumbing, contract/MockWebServer cases assert the *shape the
route arg must carry* (the verified `UiSessionStartResp.challenge_id`) rather
than live calls, which belong to E04.

- **TC-AND-023-01 — Unit: `AuthDest.Mfa.build` happy path.**
  Type: unit (JVM). Preconditions: `AuthDest` available on classpath.
  Steps: call `AuthDest.Mfa.build("chg_abc123")`. Expected:
  returns `"auth/mfa/chg_abc123"`. Traces: AC-1, AC-5.

- **TC-AND-023-02 — Unit: `challengeId` encoding of special characters.**
  Type: unit (JVM). Preconditions: none. Steps: call
  `AuthDest.Mfa.build("a/b c+d?e")`. Expected: `/`, space, `+`, `?` are
  percent-encoded (`Uri.encode`) so the produced route parses back to the
  original value when decoded by Navigation. Traces: AC-5.

- **TC-AND-023-03 — Unit: `AuthNavActions` routes each edge correctly.**
  Type: unit (JVM, mock/fake `NavController`). Preconditions: fake controller
  recording `navigate(route)`. Steps: invoke `toMfa("chg_x")`, `toRegister()`,
  `toRecovery()`, `toMagicLink()`, `back()`. Expected: navigate called with
  `auth/mfa/chg_x`, `auth/register`, `auth/recovery`, `auth/magic_link`
  respectively; `back()` calls `popBackStack()`. Traces: AC-1, AC-3, AC-6.

- **TC-AND-023-04 — Compose-UI: start destination when LoggedOut.**
  Type: Compose-UI / instrumented (`createComposeRule` +
  `TestNavHostController`). Preconditions: host composed with
  `SessionStatus.LoggedOut`. Steps: render `TestLogonNavHost`. Expected: current
  graph route == `AuthGraph.ROUTE` (`auth_graph`) and current destination route
  == `AuthDest.Login.route` (`auth/login`); `login_screen` test tag is
  displayed. Traces: AC-2.

- **TC-AND-023-05 — Compose-UI: Unknown boots to Login.**
  Type: Compose-UI / instrumented. Preconditions: host composed with
  `SessionStatus.Unknown`. Steps: render host. Expected: start destination is
  `auth/login` (Unknown treated as logged-out for routing). Traces: AC-2.

- **TC-AND-023-06 — Compose-UI: Login → MFA edge carries arg.**
  Type: Compose-UI / instrumented. Preconditions: host at Login; MFA invoked
  with `challengeId = "chg_xyz"`. Steps: click `login_to_mfa_button`. Expected:
  current route matches pattern `auth/mfa/{challengeId}` and
  `NavBackStackEntry.arguments.getString("challengeId") == "chg_xyz"`;
  `MfaPlaceholderScreen` displays `chg_xyz`. Traces: AC-3, AC-5.

- **TC-AND-023-07 — Compose-UI: Login → Register / Recovery / Magic-link edges.**
  Type: Compose-UI / instrumented. Preconditions: host at Login. Steps: click
  Register, then back; Recovery, then back; Magic-link. Expected: routes become
  `auth/register`, `auth/recovery`, `auth/magic_link` respectively. Traces:
  AC-3.

- **TC-AND-023-08 — Instrumented: back navigation returns to Login.**
  Type: instrumented / e2e (`Espresso.pressBack()`). Preconditions: navigated to
  MFA (with arg), Register, Recovery, Magic-link in separate runs. Steps: from
  each child destination press system back. Expected: current destination
  returns to `auth/login`; from Login, a further back exits the host (no custom
  interception). Traces: AC-4.

- **TC-AND-023-09 — Compose-UI: no `NavController` passed into screens.**
  Type: Compose-UI / static-architecture. Preconditions: placeholder composable
  signatures available. Steps: assert each placeholder composable's parameter
  list contains only navigation lambdas / primitives (no `NavController` /
  `NavHostController` parameter) — enforced via a compile-time signature check or
  a detekt/lint rule. Expected: no controller type appears in any screen
  signature. Traces: AC-6.

- **TC-AND-023-10 — Contract/MockWebServer: MFA arg matches
  `UiSessionStartResp.challenge_id`.**
  Type: contract / MockWebServer. Preconditions: MockWebServer enqueues
  `200 {"auth_required":true,"challenge_id":"chg_abc123",
  "required_factors":["totp"]}`. Steps: parse the body with the
  `SessionStartResp` DTO and feed `challenge_id` into `AuthDest.Mfa.build`.
  Expected: parsed `challenge_id == "chg_abc123"`, `auth_required == true`,
  `required_factors == ["totp"]`; built route ==
  `auth/mfa/chg_abc123`. Confirms the route arg is shaped to carry the real
  server field. Traces: AC-5.

- **TC-AND-023-11 — Contract: response with absent `challenge_id`
  (auth not required).**
  Type: contract / unit. Preconditions: body
  `{"auth_required":false,"required_factors":[],"session_id":"sess_1"}` (a valid
  `UiSessionStartResp` per schema). Steps: parse with `SessionStartResp` DTO.
  Expected: `challenge_id` deserializes as null/absent without error; the
  caller must NOT navigate to the MFA destination (no `build` with null). Guards
  the nullable-`challenge_id` contract (§16 claim 2). Traces: AC-3, AC-5.

- **TC-AND-023-12 — Unit: empty / missing MFA argument is rendered safely
  (offline/degraded path).**
  Type: unit / Compose-UI. Preconditions: navigate to `auth/mfa/` with the arg
  effectively empty. Steps: read arg via `orEmpty()`. Expected:
  `MfaPlaceholderScreen` receives `""` and renders without crashing; a guard
  logs a warning. (Stands in for the flaky-dev-host/offline case: this ticket
  has no network, so the resilience surface is the empty-arg guard.) Traces:
  AC-5.

- **TC-AND-023-13 — Security: `challengeId` redacted in nav breadcrumb logs.**
  Type: unit / instrumented. Preconditions: `OnDestinationChangedListener`
  installed; capturing logger. Steps: navigate to `auth/mfa/chg_secret`.
  Expected: emitted DEBUG breadcrumb is `mfa/<redacted>` (no raw
  `chg_secret` in any log line); no cookies/tokens logged; no deep link is
  registered for auth destinations. Traces: AC-3 (covers §8/§10 security
  posture).

- **TC-AND-023-14 — Accessibility: placeholder screens are TalkBack-navigable.**
  Type: Compose-UI accessibility. Preconditions: each placeholder rendered.
  Steps: assert via semantics that each screen root has a `heading()` semantic;
  every actionable button has a non-empty content description sourced from
  `strings.xml` (e.g. `R.string.auth_login_continue_to_mfa`) and a touch target
  ≥ 48dp. Expected: all assertions pass; no hardcoded UI strings. Traces: AC-1
  (covers §9 accessibility requirements).

### Coverage matrix

| Acceptance criterion (§14) | Covering test case(s) |
|----------------------------|------------------------|
| AC-1 (graph + 5 destinations exist) | TC-01, TC-03, TC-14 |
| AC-2 (Login is start dest; LoggedOut/Unknown boot to auth) | TC-04, TC-05 |
| AC-3 (Login → MFA/Register/Recovery/Magic-link) | TC-03, TC-06, TC-07, TC-11, TC-13 |
| AC-4 (back from children returns to Login) | TC-08 |
| AC-5 (`challengeId` round-trips losslessly) | TC-01, TC-02, TC-06, TC-10, TC-11, TC-12 |
| AC-6 (no `NavController` in screens; lambdas only) | TC-03, TC-09 |
| AC-7 (unit + Compose UI tests pass in CI) | All TC-01 … TC-14 |
