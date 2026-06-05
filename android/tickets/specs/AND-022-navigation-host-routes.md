---
id: AND-022
title: Navigation host & routes
milestone: M1
epic: E03
priority: P0
size: M
status: draft
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
- **Web reference:** `frontend/` uses React Router; route names there
  (`/login`, `/mfa`, `/me`) inform our route naming but are not binding — Android
  uses type-safe in-process routes, not URL strings.
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
