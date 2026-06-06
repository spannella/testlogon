---
id: AND-022
title: Navigation host & routes
milestone: M1
epic: E03
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-002]
blocks: [AND-023]
---

# AND-022 — Navigation host & routes

## 1. Overview & Goal

This ticket establishes the single-Activity navigation backbone for the TestLogon
native Android app: one `NavHost` hosted inside `MainActivity`'s root Compose tree,
a type-safe route catalogue, and a reusable navigation API that downstream feature
graphs build on. It is the foundational E03 (App Shell) plumbing ticket — every
authenticated and unauthenticated screen flows through the structures defined here.

The goal is a working, tested navigation host that wires two placeholder
destinations together using **Navigation-Compose 2.8 type-safe routes**
(`@Serializable` route objects + `composable<T>` overloads), provides typed
navigation actions, and applies the app's standard transition policy. No real
feature screens are introduced; AND-022 ships the host plus two throwaway
placeholders solely to prove navigation end-to-end. The unauthenticated graph
(Login → MFA → …) is delivered by **AND-023**, which `import`s the route types and
helpers defined here.

Out of scope: bottom navigation / tab scaffolding (separate shell ticket), deep
links from external intents, auth-state-driven graph switching, and any backend
interaction. This is a UI-shell ticket with no network surface.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose 2.8.x, Hilt (KSP), `androidx.hilt:hilt-navigation-compose`.
  minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. The `NavHost` and the
  cross-cutting route registry live in the `app` module (it is the only module that
  may depend on every feature module). Shared, feature-agnostic route primitives
  (the `TopLevelRoute` marker, transition specs, `NavKey` helpers) live in
  `core-ui` so feature modules can reference them without depending on `app`.
- **Package base (exact):** `com.testlogon.android`.
  - App nav: `com.testlogon.android.navigation`
  - Shared nav primitives: `com.testlogon.android.core.ui.navigation`
- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Upstream dependency — AND-002:** provides the `app` module, `MainActivity`, the
  `Application` class, and an empty Compose host (`setContent { TestLogonTheme { } }`).
  AND-022 replaces the empty host body with the `NavHost`.
- **Downstream — AND-023:** consumes the route catalogue and `NavGraphBuilder`
  extension pattern to assemble the real unauthenticated graph; it owns the
  `Login`/`Mfa`/`Register`/`Recovery`/`MagicLink` route definitions and start
  destination logic.
- **Web reference:** `frontend/` (`src/App.tsx`) uses React Router. The
  unauthenticated client routes are `/login`, `/register`, `/password-recovery`,
  and `/magic-link-verify`; authenticated screens live under a
  `ProtectedRoute` → `AppShell` subtree whose `index` route renders the
  `Dashboard`. **Correction (review AND-022):** there is **no** client-side
  `/mfa` or `/me` route in the web app — MFA is an in-page *step* of `Login.tsx`
  (`LoginStep = "credentials" | "mfa" | "magic-link" | "webauthn"`), and `/ui/me`
  is a backend API endpoint, not a browser route. These names inform our Android
  route naming but are not binding — Android uses type-safe in-process routes, not
  URL strings.
- **No backend reference** is relevant; OpenAPI/`/openapi.json` is not touched by
  this ticket.

## 3. Functional Requirements

1. **Single NavHost.** Exactly one `NavHost` exists in the app, rooted in
   `MainActivity`'s `setContent`, wrapped by `TestLogonTheme` and a top-level
   `Surface`. No other Activities are introduced.
2. **Type-safe routes.** Routes are declared as `@Serializable` Kotlin
   objects/classes (not raw strings). Destinations are registered with the
   `composable<RouteType>` / `navigation<GraphType>` type-safe builder overloads.
   Argument-bearing routes carry their args as constructor parameters.
3. **Two placeholder destinations.** `PlaceholderA` (start destination) and
   `PlaceholderB`. `PlaceholderA` renders a button "Go to B" that navigates to
   `PlaceholderB` passing a `String` argument; `PlaceholderB` renders the received
   argument and a "Back" button that pops the back stack.
4. **Typed navigation actions.** A `TestLogonNavigator` (or
   `NavController` extension functions) exposes intent-revealing methods rather
   than raw `navigate(route)` calls scattered through UI, e.g.
   `navigateToPlaceholderB(text: String)` and `navigateUp()`.
5. **Transition policy.** A single shared transition spec (enter/exit/popEnter/
   popExit) is applied at the `NavHost` level so all destinations animate
   consistently (horizontal slide + fade, 300 ms). Individual destinations may
   override but default to the shared spec.
6. **Back handling.** System Back and the on-screen Back button both pop the back
   stack; popping past the start destination finishes the Activity (default
   Navigation-Compose behavior — no custom suppression).
7. **State survival.** Navigation state (current destination + back stack +
   arguments) survives configuration change (rotation) and process-death
   restoration via `rememberNavController()` + saved-state handling.
8. **Extensibility hook.** A `NavGraphBuilder.placeholderGraph()` extension
   demonstrates the per-feature graph-registration pattern AND-023 will follow.

## 4. Technical Design

### 4.1 Route catalogue

```kotlin
// core-ui: com.testlogon.android.core.ui.navigation
/** Marker for routes that are valid NavHost destinations. */
sealed interface NavRoute

/** Marker for routes eligible to be a top-level (back-stack root) destination. */
sealed interface TopLevelRoute : NavRoute
```

```kotlin
// app: com.testlogon.android.navigation
import kotlinx.serialization.Serializable

@Serializable
data object PlaceholderA : TopLevelRoute

@Serializable
data class PlaceholderB(val text: String) : NavRoute
```

`@Serializable` requires the `org.jetbrains.kotlinx:kotlinx-serialization` plugin
and `kotlinx-serialization-json` runtime; Navigation-Compose 2.8's type-safe APIs
use Kotlin serialization to encode routes and arguments. Add the
`kotlin("plugin.serialization")` Gradle plugin (version aligned to Kotlin 2.0.21)
to the `app` module and `core-ui`.

### 4.2 Navigation host

```kotlin
// app: com.testlogon.android.navigation
@Composable
fun TestLogonNavHost(
    navController: NavHostController = rememberNavController(),
    startDestination: NavRoute = PlaceholderA,
    modifier: Modifier = Modifier,
) {
    NavHost(
        navController = navController,
        startDestination = startDestination,
        modifier = modifier,
        enterTransition = { TLTransitions.enter() },
        exitTransition = { TLTransitions.exit() },
        popEnterTransition = { TLTransitions.popEnter() },
        popExitTransition = { TLTransitions.popExit() },
    ) {
        placeholderGraph(navController)
        // AND-023 will add: unauthenticatedGraph(navController)
    }
}
```

### 4.3 Graph registration extension (pattern for AND-023)

```kotlin
fun NavGraphBuilder.placeholderGraph(navController: NavHostController) {
    composable<PlaceholderA> {
        PlaceholderAScreen(
            onNavigateToB = { text -> navController.navigateToPlaceholderB(text) }
        )
    }
    composable<PlaceholderB> { backStackEntry ->
        val args = backStackEntry.toRoute<PlaceholderB>()
        PlaceholderBScreen(
            text = args.text,
            onBack = { navController.navigateUp() }
        )
    }
}
```

### 4.4 Typed navigator

```kotlin
fun NavHostController.navigateToPlaceholderB(text: String) {
    navigate(PlaceholderB(text)) {
        launchSingleTop = true
    }
}
```

For broader use a `TestLogonNavigator` wrapper class may be injected, but for this
ticket `NavHostController` extensions are sufficient and keep UI testable. Screens
receive **lambda callbacks**, never the `NavController` directly, so feature
composables stay navigation-agnostic and previewable.

### 4.5 MainActivity integration (replaces AND-002 empty host)

```kotlin
@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            TestLogonTheme {
                Surface(Modifier.fillMaxSize()) {
                    TestLogonNavHost()
                }
            }
        }
    }
}
```

### 4.6 Transition specs

```kotlin
// core-ui: com.testlogon.android.core.ui.navigation
object TLTransitions {
    private const val DURATION = 300
    fun enter(): EnterTransition =
        slideInHorizontally(tween(DURATION)) { it / 4 } + fadeIn(tween(DURATION))
    fun exit(): ExitTransition =
        slideOutHorizontally(tween(DURATION)) { -it / 4 } + fadeOut(tween(DURATION))
    fun popEnter(): EnterTransition =
        slideInHorizontally(tween(DURATION)) { -it / 4 } + fadeIn(tween(DURATION))
    fun popExit(): ExitTransition =
        slideOutHorizontally(tween(DURATION)) { it / 4 } + fadeOut(tween(DURATION))
}
```

Respect the system "remove animations" / reduced-motion setting (see §9) by
collapsing `DURATION` to 0 when animations are disabled.

## 5. API Contract

**Not applicable.** This is a pure in-app UI-shell ticket with no backend or
network interaction; no HTTP endpoints, request/response shapes, or `ApiResult<T>`
handling are introduced. The only "contract" is the internal navigation API
(route types + navigator extensions) specified in §4, which downstream **AND-023**
and subsequent feature tickets consume. No `core-network`, Retrofit, or Moshi code
is added.

## 6. Data & State Management

- **Navigation state** is owned by `NavHostController` created via
  `rememberNavController()` in `MainActivity` and is the single source of truth for
  the current destination, back stack, and per-entry arguments. It is **not**
  duplicated in any ViewModel.
- **No ViewModel / StateFlow** is required for AND-022 itself; placeholders are
  stateless. The pattern for future feature ViewModels —
  `class XViewModel : ViewModel { val uiState: StateFlow<XUiState> }` scoped via
  `hiltViewModel()` keyed by `NavBackStackEntry` — is documented here as guidance
  but not implemented.
- **Route arguments** are typed (`PlaceholderB.text: String`) and serialized by
  Navigation-Compose; they are read with `backStackEntry.toRoute<PlaceholderB>()`.
  No nullable/optional args in this ticket.
- **Configuration change:** `rememberNavController` retains the back stack across
  rotation. Verified by test (§11).
- **Process death:** Navigation-Compose persists the back stack of `@Serializable`
  routes via saved state; on restoration the host returns to the same destination
  with arguments intact. No manual `SavedStateHandle` plumbing is needed for the
  placeholders.
- **DataStore / Room:** none used by this ticket.

## 7. Error Handling & Resilience

Navigation in-process has a narrow failure surface; the host handles it
defensively:

- **Unknown / unregistered route:** type-safe `composable<T>` makes most
  mismatches compile-time errors. A runtime `IllegalStateException` from an
  unregistered destination is treated as a programming error and surfaced loudly in
  debug (rethrow) while logging in release (see §10) — it must never be silently
  swallowed.
- **Double navigation / rapid taps:** all forward navigations use
  `launchSingleTop = true` to avoid duplicate destinations from double-clicks.
- **Pop on empty back stack:** `navigateUp()` returns `false` when nothing to pop;
  `MainActivity` lets the system default (finish Activity) apply. No crash.
- **Backend/offline states:** N/A here — owned by **AND-021** (state composables:
  loading/empty/error/offline) which feature screens, not the nav host, render.

This ticket introduces no retries, timeouts, or backoff (no network).

## 8. Security & Privacy

- **No PII, credentials, or tokens** pass through navigation routes in this ticket.
  Placeholder arguments are non-sensitive strings only.
- **Policy (binding for downstream):** sensitive values (passwords, OTP codes,
  `challenge_id`, session/CSRF tokens) **must never** be encoded into route
  arguments, because route args are serialized into the saved-state `Bundle` which
  can be persisted to disk on process death and inspected. AND-023 and auth tickets
  must pass such values via injected ViewModels / `core-data` session state, not
  via `navigate(Route(...))`. This constraint is documented in the route file's
  KDoc.
- **No deep links / external intents** are exposed by AND-022, so there is no
  external-navigation attack surface (no exported intent filters added beyond the
  AND-002 launcher).
- No logging of route arguments at WARN/ERROR in release (see §10).

## 9. Accessibility & i18n

- Placeholder buttons use `Modifier.semantics` / proper `Button` text so TalkBack
  announces "Go to B" and "Back"; touch targets ≥ 48 dp.
- All user-visible strings (even placeholder labels) are declared in
  `core-ui`/`app` `strings.xml` (`R.string.placeholder_go_to_b`, etc.) — no
  hardcoded literals — to keep the i18n discipline consistent from the start.
- **Reduced motion:** `TLTransitions` checks
  `Settings.Global.ANIMATOR_DURATION_SCALE` (or `LocalAccessibilityManager`) and
  uses zero-duration `tween`s when animations are disabled, so navigation remains
  usable for motion-sensitive users.
- Destination changes should move focus to the new screen's primary content for
  screen-reader continuity (`Modifier.focusRequester` on the root of each screen).
- Content is LTR/RTL-safe; slide transitions use start/end semantics via Compose's
  layout-direction-aware offsets where applicable.

## 10. Telemetry & Logging

- A lightweight `NavController.OnDestinationChangedListener` (debug builds, gated by
  `BuildConfig.DEBUG`) logs `route` simple-name transitions via the project logger
  (Timber if present from core; otherwise `android.util.Log` with tag
  `"TLNav"`). **Route argument values are not logged** — only the route type name —
  to satisfy §8.
- A pluggable `NavAnalytics` interface is declared (`fun onScreen(routeName: String)`)
  with a no-op default binding via Hilt, so a real analytics ticket can later bind a
  screen-view tracker without touching the host. No analytics SDK is added now.
- Failures (§7 unregistered route) log at ERROR with the route type name only.

## 11. Testing Strategy

**Unit / route tests (JVM, `core-testing` helpers):**
- `kotlinx.serialization` round-trip: serialize/deserialize `PlaceholderB("x")`
  yields equal instance — guards against arg encoding regressions.

**Compose UI / navigation tests (`createComposeRule` /
`androidx.navigation:navigation-testing` `TestNavHostController`):**
1. `navHost_startsAtPlaceholderA` — initial route is `PlaceholderA`.
2. `clickGoToB_navigatesToPlaceholderB_withArg` — perform click on "Go to B";
   assert current destination is `PlaceholderB` and the rendered text equals the
   passed argument (**this is the ticket's core acceptance test**).
3. `placeholderB_back_popsToA` — click "Back"; assert current destination is
   `PlaceholderA` and back stack depth is 1.
4. `systemBack_fromB_returnsToA` — `Espresso.pressBack()` (or `onBackPressed`)
   returns to `PlaceholderA`.
5. `rotation_preservesDestination` — navigate to B, recreate Activity, assert still
   on B with same arg.
6. `doubleClickGoToB_singleDestination` — two rapid clicks produce one
   `PlaceholderB` on the back stack (`launchSingleTop`).

Use `TestNavHostController` to assert `currentBackStackEntry?.destination?.route`
and `toRoute<PlaceholderB>()` rather than scraping UI where possible.

**Tooling:** tests run under `./gradlew :app:testDebugUnitTest` (JVM/Robolectric for
nav-testing) and `:app:connectedDebugAndroidTest` for instrumented rotation/back
cases. CI must execute at least the route round-trip and the
`clickGoToB_navigatesToPlaceholderB_withArg` test headlessly.

## 12. Dependencies & Sequencing

- **Depends on AND-002** (P0): the `app` module, `MainActivity`, `Application`, and
  the empty Compose host must exist; AND-022 swaps the empty body for the
  `NavHost`.
- **Implicitly relies on** the `TestLogonTheme` from `core-ui` (theming ticket); if
  not yet merged, a temporary `MaterialTheme {}` is acceptable and replaced when the
  theme lands.
- **Blocks AND-023** (Unauthenticated nav graph), which extends the `NavHost` with
  `unauthenticatedGraph()` and sets `Login` as the start destination when logged
  out. AND-023 reuses the `NavRoute`/`TopLevelRoute` markers, `composable<T>`
  pattern, `TLTransitions`, and the callback-passing convention defined here.
- **New Gradle additions:** `kotlin("plugin.serialization")` +
  `kotlinx-serialization-json` (app, core-ui); `androidx.navigation:navigation-compose`
  2.8.x; `androidx.navigation:navigation-testing`;
  `androidx.hilt:hilt-navigation-compose`. Add to the version catalog
  (`gradle/libs.versions.toml`).
- **Sequencing:** can proceed in parallel with AND-021 (state composables); no code
  overlap (AND-021 owns state UI, AND-022 owns the host). Both feed the app shell.

## 13. Risks & Open Questions

- **R1 — Nav-Compose type-safe API maturity.** Type-safe routes
  (`composable<T>`/`toRoute`) require Navigation-Compose 2.8+. Risk that the pinned
  version in the catalog is older. *Mitigation:* pin 2.8.x explicitly; if blocked,
  fall back to string routes with a thin typed wrapper and migrate later (tracked).
- **R2 — Serialization plugin version skew** with Kotlin 2.0.21. *Mitigation:* use
  the Kotlin-bundled serialization plugin version; verify `assembleDebug`.
- **R3 — Process-death restoration** of `@Serializable` routes can be flaky on some
  OEM Android 7–8 (minSdk 24) builds. *Mitigation:* instrumented test on an API 24
  emulator; keep args small/serializable.
- **Q1 — Navigator abstraction shape:** `NavHostController` extensions (this spec)
  vs an injectable `TestLogonNavigator`. Default: extensions now; revisit if
  deep-link/cross-feature navigation in later tickets demands a central navigator.
- **Q2 — Where does the auth-state graph switch live?** Deferred to AND-023 / a
  shell ticket; AND-022 only proves the mechanism with placeholders.
- **Q3 — Edge-to-edge insets** interaction with slide transitions — verify no
  clipping under the status/nav bars.

## 14. Acceptance Criteria

1. App launches (from AND-002 base) directly into `PlaceholderA` rendered inside a
   single `NavHost` in `MainActivity` — only one Activity exists.
2. Routes are defined as `@Serializable` type-safe route objects/classes and
   registered via `composable<T>`; no raw string routes in app code.
3. Tapping "Go to B" on `PlaceholderA` navigates to `PlaceholderB`, passing a
   `String` argument that `PlaceholderB` renders correctly. **(Core AC — covered by
   automated test `clickGoToB_navigatesToPlaceholderB_withArg`.)**
4. "Back" button and system Back both pop from `PlaceholderB` to `PlaceholderA`;
   popping from the start destination finishes the Activity without crashing.
5. The shared `TLTransitions` enter/exit/pop transitions animate destination
   changes and collapse to zero duration when system animations are disabled.
6. Navigation state survives rotation (destination + argument preserved).
7. Forward navigation uses `launchSingleTop`; double-tap produces a single
   destination instance.
8. A `NavGraphBuilder.placeholderGraph()` extension demonstrates the graph-
   registration pattern that AND-023 will follow; screens receive lambda callbacks,
   not the `NavController`.
9. All listed §11 navigation tests pass in CI.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated by passing automated tests.
- Code merged to `android-port` under `android/app/.../navigation/` and
  `android/core-ui/.../core/ui/navigation/`, using package base
  `com.testlogon.android` exactly.
- Version catalog updated with navigation-compose 2.8.x, navigation-testing,
  hilt-navigation-compose, and kotlinx-serialization; `./gradlew :app:assembleDebug`
  and `:app:testDebugUnitTest` green locally and in CI.
- No raw-string routes; no sensitive data in route args; route arg values not
  logged in release.
- Public nav API (`NavRoute`, `TopLevelRoute`, `TestLogonNavHost`,
  `placeholderGraph`, navigator extensions, `TLTransitions`) has KDoc, including the
  §8 "no sensitive data in routes" note.
- All user-visible strings externalized to `strings.xml`; reduced-motion handling
  verified with TalkBack/animation-scale-off.
- Lint and ktlint/detekt pass with no new warnings; PR reviewed and approved.
- AND-023 owner confirms the route catalogue and graph-builder pattern are
  sufficient to assemble the unauthenticated graph without modifying AND-022 code.

## 16. Citations & Assumption Audit

This is a UI-shell ticket with **no backend/network surface** (see §5). There are
therefore no API endpoint, HTTP-method, request/response-field, or auth/CSRF
claims to verify against the OpenAPI spec — the only externally-checkable claims
are (a) the web-app reference behavior cited in §2 and (b) the Android framework
choices. Each key claim below is listed with a VERDICT and an exact SOURCE
pointer.

1. **Claim:** This ticket touches no backend; OpenAPI/`/openapi.json` is not
   relevant (§2, §5). **VERDICT: Verified.** The ticket scope (single-Activity
   `NavHost`, typed routes, transitions, two placeholders) introduces no HTTP
   calls; no endpoint in the index pertains to navigation shell.
   **SOURCE:** `reference/openapi.index.txt` (no nav/shell endpoints);
   ticket scope `specs-src/AND-022.md`.

2. **Claim:** The web app uses React Router for routing (§2). **VERDICT: Verified.**
   **SOURCE:** `src/App.tsx` (`<Routes>` / `<Route path=… element=… />`, lines
   ~273–335); `react-router` imports present across `src/`.

3. **Claim:** Web unauthenticated route names are `/login` (+ register, recovery,
   magic-link) (§2). **VERDICT: Verified / Corrected.** `/login` is a real client
   route; the sibling routes are `/register`, `/password-recovery`,
   `/magic-link-verify`. **SOURCE:** `src/App.tsx:275–278`.

4. **Claim (original):** Web route names include `/mfa` and `/me` (§2, pre-review).
   **VERDICT: Corrected.** No client-side `/mfa` or `/me` route exists. MFA is an
   in-page step of the Login screen, and `/ui/me` is a backend endpoint, not a
   browser route. Corrected inline in §2. **SOURCE:** `src/pages/Login.tsx:40`
   (`type LoginStep = "credentials" | "mfa" | "magic-link" | "webauthn"`);
   `src/App.tsx` (grep for `/mfa`, `/me` → no matches); OpenAPI
   `GET /ui/me | op=ui_me_ui_me_get` confirms `/ui/me` is an API path.

5. **Claim:** Authenticated web screens sit behind a `ProtectedRoute`/`AppShell`
   with an `index` Dashboard (§2, corrected). **VERDICT: Verified.**
   **SOURCE:** `src/App.tsx:289–290` (`<Route element={<ProtectedRoute><AppShell/></ProtectedRoute>}>` … `<Route index element={<Dashboard />}/>`).

6. **Claim:** AND-023 will own the real `Login`/`Mfa`/`Register`/`Recovery`/
   `MagicLink` unauthenticated graph (§1, §2, §12). **VERDICT:
   Unverified-assumption (internal planning).** This is a cross-ticket ownership
   statement, not verifiable from OpenAPI/frontend; it is consistent with the web
   set of unauthenticated screens (Login, Register, PasswordRecovery,
   MagicLinkVerify) per `src/App.tsx:275–278`. The naming of an Android `Mfa`
   route is a design choice (web has no `/mfa` route — see #4).

7. **Claim:** Navigation-Compose 2.8 provides type-safe routes via `@Serializable`
   route objects + `composable<T>` / `navigation<T>` overloads and
   `backStackEntry.toRoute<T>()` (§2, §4.1, §4.3). **VERDICT:
   Verified (framework ref).** **SOURCE (framework ref):**
   https://developer.android.com/guide/navigation/design/type-safety .

8. **Claim:** Type-safe routes require Kotlin Serialization
   (`kotlin("plugin.serialization")` + `kotlinx-serialization-json`) (§4.1, §12).
   **VERDICT: Verified (framework ref).** **SOURCE (framework ref):**
   https://developer.android.com/guide/navigation/design/type-safety#kotlin-dsl
   and https://kotlinlang.org/docs/serialization.html .

9. **Claim:** `NavHost` accepts `enterTransition`/`exitTransition`/
   `popEnterTransition`/`popExitTransition` lambdas applied host-wide, overridable
   per `composable` (§4.2, §4.6). **VERDICT: Verified (framework ref).**
   **SOURCE (framework ref):**
   https://developer.android.com/develop/ui/compose/navigation#animate-transitions .

10. **Claim:** `rememberNavController()` retains back stack across config change,
    and Navigation-Compose persists/restores the back stack across process death
    via saved state (§6, §7). **VERDICT: Verified (framework ref).**
    **SOURCE (framework ref):**
    https://developer.android.com/develop/ui/compose/navigation and
    https://developer.android.com/guide/navigation/backstack .

11. **Claim:** `navigateUp()` returns `false` when the back stack cannot pop and
    popping the start destination finishes the Activity by default (§7).
    **VERDICT: Verified (framework ref).** **SOURCE (framework ref):**
    https://developer.android.com/reference/androidx/navigation/NavController#navigateUp() .

12. **Claim:** `launchSingleTop = true` prevents duplicate top-of-stack
    destinations from rapid taps (§4.4, §7). **VERDICT: Verified (framework ref).**
    **SOURCE (framework ref):**
    https://developer.android.com/guide/navigation/backstack#singleTop .

13. **Claim:** `androidx.navigation:navigation-testing` provides
    `TestNavHostController` for asserting current destination/back stack (§11).
    **VERDICT: Verified (framework ref).** **SOURCE (framework ref):**
    https://developer.android.com/guide/navigation/testing .

14. **Claim:** Reduced-motion can be honored by collapsing animation duration when
    system animations are disabled, read via `Settings.Global.ANIMATOR_DURATION_SCALE`
    (§4.6, §9). **VERDICT: Verified (framework ref).** **SOURCE (framework ref):**
    https://developer.android.com/reference/android/provider/Settings.Global#ANIMATOR_DURATION_SCALE .

### Corrections made

- **§2 web route names.** Removed the incorrect claim that the web app has `/mfa`
  and `/me` *routes*. Replaced with the verified route set
  (`/login`, `/register`, `/password-recovery`, `/magic-link-verify`, plus a
  `ProtectedRoute`/`AppShell` `index` Dashboard) and noted that MFA is an in-page
  Login step (`Login.tsx`) and `/ui/me` is a backend API endpoint, not a browser
  route. SOURCES: `src/App.tsx:275–290`, `src/pages/Login.tsx:40`,
  OpenAPI `GET /ui/me`.

No other factual errors were found; all Android-framework claims verified against
official Android/Kotlin docs (cited above).

### Open assumptions

- **Cross-ticket ownership (AND-023 owns the auth graph; AND-021 owns state
  composables).** Not verifiable from OpenAPI or the frontend; these are
  internal program-plan statements. Treated as planning assumptions.
- **Exact pinned versions** (Navigation-Compose 2.8.x, AGP 8.7.3, Gradle 8.9,
  Kotlin 2.0.21, compileSdk 35) are environment/build assumptions to confirm
  against `gradle/libs.versions.toml` at implementation time; the version-catalog
  file is not present in the provided sources, so they remain unverified here.
- **Process-death restoration reliability on API 24–26 OEM builds** (R3) is an
  empirical assumption to confirm on-device; not statically verifiable.

## 17. Test Plan

All cases trace to the §14 Acceptance Criteria (AC-1 … AC-9). Because AND-022 has
no network surface, there are no contract/MockWebServer cases; the analogous
"resilience" case is the reduced-motion / animations-disabled path and the
empty-back-stack pop. Test IDs are stable.

- **TC-AND-022-01 — Serialization round-trip of route args**
  - **Type:** unit (JVM)
  - **Preconditions:** `kotlinx-serialization-json` on classpath; `PlaceholderB`
    is `@Serializable`.
  - **Steps:** Encode `PlaceholderB("hello")` to JSON and decode it back.
  - **Expected:** Decoded instance equals the original (`text == "hello"`); no
    exception. Guards arg-encoding regressions.
  - **Traces: AC-2, AC-3.**

- **TC-AND-022-02 — Host starts at PlaceholderA**
  - **Type:** Compose-UI (`createComposeRule` + `TestNavHostController`)
  - **Preconditions:** `TestLogonNavHost` set as content with a test
    `NavHostController`.
  - **Steps:** Render the host; read `currentBackStackEntry`.
  - **Expected:** Current destination route corresponds to `PlaceholderA`; only
    one `NavHost`/Activity exists.
  - **Traces: AC-1.**

- **TC-AND-022-03 — Go-to-B navigates and renders the passed argument (core)**
  - **Type:** Compose-UI
  - **Preconditions:** Host rendered at `PlaceholderA`.
  - **Steps:** `onNodeWithText("Go to B")` (via `R.string.placeholder_go_to_b`)
    `.performClick()`; then read current destination and on-screen text.
  - **Expected:** Current destination is `PlaceholderB`;
    `backStackEntry.toRoute<PlaceholderB>().text` equals the passed string and is
    rendered on screen. **(Core acceptance test.)**
  - **Traces: AC-3.**

- **TC-AND-022-04 — On-screen Back pops B → A**
  - **Type:** Compose-UI
  - **Preconditions:** On `PlaceholderB` (after TC-03 navigation).
  - **Steps:** Click the "Back" button (`R.string.placeholder_back`).
  - **Expected:** Current destination is `PlaceholderA`; back-stack depth is 1;
    no crash.
  - **Traces: AC-4.**

- **TC-AND-022-05 — System Back pops B → A**
  - **Type:** instrumented/e2e (`Espresso.pressBack()`)
  - **Preconditions:** On `PlaceholderB`.
  - **Steps:** Invoke system Back.
  - **Expected:** Returns to `PlaceholderA`; back-stack depth 1.
  - **Traces: AC-4.**

- **TC-AND-022-06 — Pop from start destination finishes Activity (no crash)**
  - **Type:** instrumented/e2e
  - **Preconditions:** On `PlaceholderA` (start destination), back stack depth 1.
  - **Steps:** Invoke system Back.
  - **Expected:** `navigateUp()`/default handling finishes the Activity without
    throwing; `activity.isFinishing` is true. No `IllegalStateException`.
  - **Traces: AC-4.**

- **TC-AND-022-07 — Rotation preserves destination and argument**
  - **Type:** instrumented/e2e (Activity recreate)
  - **Preconditions:** Navigated to `PlaceholderB("keep-me")`.
  - **Steps:** Recreate the Activity (configuration change / rotation).
  - **Expected:** Still on `PlaceholderB`; rendered/`toRoute` arg is still
    `"keep-me"`.
  - **Traces: AC-6.**

- **TC-AND-022-08 — Process-death restoration preserves destination + arg**
  - **Type:** instrumented/e2e (saved-state restore; run on API 24 emulator)
  - **Preconditions:** Navigated to `PlaceholderB("survive")`.
  - **Steps:** Simulate process death and restore from saved instance state.
  - **Expected:** Host restores to `PlaceholderB` with arg `"survive"` intact; no
    manual `SavedStateHandle` plumbing required.
  - **Traces: AC-6.** (Addresses risk R3.)

- **TC-AND-022-09 — Double-tap "Go to B" yields a single destination**
  - **Type:** Compose-UI
  - **Preconditions:** On `PlaceholderA`.
  - **Steps:** Perform two rapid clicks on "Go to B".
  - **Expected:** Exactly one `PlaceholderB` entry on the back stack
    (`launchSingleTop` honored).
  - **Traces: AC-7.**

- **TC-AND-022-10 — Shared transitions applied; collapse to 0 ms when animations
  disabled**
  - **Type:** instrumented/e2e
  - **Preconditions:** Two test runs — (a) `ANIMATOR_DURATION_SCALE = 1`,
    (b) `= 0` (animations off).
  - **Steps:** Navigate A → B in each run; observe transition duration used by
    `TLTransitions`.
  - **Expected:** (a) enter/exit/pop transitions animate (~300 ms);
    (b) effective duration is 0 (no animation), navigation still completes
    correctly.
  - **Traces: AC-5.**

- **TC-AND-022-11 — Graph-builder pattern: screens receive lambdas, not NavController**
  - **Type:** unit / Compose-UI (API/usage assertion)
  - **Preconditions:** `placeholderGraph(navController)` registered in the host.
  - **Steps:** Inspect/exercise `PlaceholderAScreen` / `PlaceholderBScreen`
    signatures and render them in isolation with stub lambdas (no NavController).
  - **Expected:** Both screens are previewable/testable with `onNavigateToB` /
    `onBack` lambda callbacks only; no `NavController` parameter is exposed to the
    screen composables.
  - **Traces: AC-8.**

- **TC-AND-022-12 — Security: no sensitive data encoded in route args (policy guard)**
  - **Type:** unit / static-style assertion
  - **Preconditions:** Route catalogue defined.
  - **Steps:** Assert route arg types are limited to non-sensitive placeholders
    (`PlaceholderB.text: String`); confirm no route declares
    password/OTP/`challenge_id`/token fields. (Enforced by review + KDoc note;
    test asserts the placeholder shape.)
  - **Expected:** Only non-sensitive `String` args present; policy KDoc present on
    the route file.
  - **Traces: AC-2** (and §8 security policy).

- **TC-AND-022-13 — Telemetry does not log route argument values (release-safe)**
  - **Type:** unit
  - **Preconditions:** `OnDestinationChangedListener` logging enabled.
  - **Steps:** Navigate A → B with a recognizable arg (e.g. `"secret-123"`);
    capture emitted log lines.
  - **Expected:** Logs contain the route **type name** only (e.g. `PlaceholderB`),
    never the arg value `"secret-123"`.
  - **Traces: AC-9** (and §8/§10 logging policy).

- **TC-AND-022-14 — Accessibility: TalkBack labels and touch targets**
  - **Type:** Compose-UI (semantics) / manual (TalkBack)
  - **Preconditions:** Both placeholder screens rendered.
  - **Steps:** Assert semantics for the "Go to B" and "Back" buttons; verify
    touch target ≥ 48 dp; manually sweep with TalkBack.
  - **Expected:** Buttons expose accessible text from `strings.xml` (no hardcoded
    literals); targets ≥ 48 dp; focus moves to the new screen's primary content on
    destination change.
  - **Traces: AC-5** (reduced-motion ties in) **and §9 accessibility.**

### Coverage matrix (AC → TC)

| Acceptance criterion (§14)                                   | Covered by                          |
|--------------------------------------------------------------|-------------------------------------|
| AC-1 Single NavHost, launches at PlaceholderA, one Activity  | TC-02                               |
| AC-2 Type-safe `@Serializable` routes via `composable<T>`    | TC-01, TC-12                        |
| AC-3 Go-to-B passes/renders String arg (core)                | TC-01, TC-03                        |
| AC-4 On-screen + system Back pop; pop-from-start finishes     | TC-04, TC-05, TC-06                  |
| AC-5 TLTransitions animate; collapse to 0 when disabled       | TC-10, TC-14                         |
| AC-6 Nav state survives rotation (and process death)          | TC-07, TC-08                         |
| AC-7 `launchSingleTop`; double-tap = single destination       | TC-09                               |
| AC-8 `placeholderGraph()` pattern; screens take lambdas       | TC-11                               |
| AC-9 §11 navigation tests pass in CI                          | TC-01, TC-02, TC-03, TC-04, TC-05, TC-07, TC-09, TC-13 |
