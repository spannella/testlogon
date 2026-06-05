---
id: AND-024
title: Authenticated nav graph + bottom nav skeleton
milestone: M1
epic: E03
priority: P1
size: M
status: draft
depends_on: [AND-022]
blocks: [AND-025]
---

# AND-024 — Authenticated nav graph + bottom nav skeleton

## 1. Overview & Goal

This ticket delivers the **authenticated navigation subgraph** and the **bottom-navigation scaffold** that become the destination of a user after a successful login + MFA + session finalize flow. Once a session exists, the single-Activity `NavHost` (built in AND-022) must be able to display a Material 3 `Scaffold` with a `NavigationBar` exposing two top-level tabs: **Home** (a placeholder destination for the future content/feed work) and **Profile/Me** (a placeholder that will later render `GET /ui/me`). Switching tabs must swap the visible destination while preserving each tab's own back stack and scroll/UI state, following the standard Navigation-Compose multi-back-stack pattern.

The scope is deliberately a **skeleton**: no real network calls, no list content, no logout wiring. The deliverable is the structural plumbing — a nested authenticated graph, the route type definitions, the `Scaffold` + `NavigationBar` host, tab reselection behavior, and per-tab state preservation — so that AND-025 (auth-gated routing) can route into this graph when auth state flips to authenticated, and so that later feature tickets can populate Home and Me without re-touching navigation structure. Success is measured behaviorally: after a (test-simulated) login, the authenticated graph is shown as the start destination, the bottom bar renders both tabs, and tapping a tab switches the active destination correctly.

## 2. Context & References

- **Module:** `feature-shell` (the app-shell feature that owns the authenticated `Scaffold` and bottom nav) consuming `core-ui` and `core-model`; wired into the app `NavHost` from the `app` module. Package root `com.testlogon.android`.
- **Branch / repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Depends on AND-022 (Navigation host & routes):** provides the single-Activity `NavHost`, the typed-route convention, and shared transition specs. This ticket plugs a nested graph into that host.
- **Sibling AND-023 (Unauthenticated nav graph):** the parallel unauthenticated subgraph (Login → MFA → …). AND-024 is its authenticated counterpart; both are siblings under the root host.
- **Blocks AND-025 (Auth-gated routing):** AND-025 observes auth state and chooses between the unauth graph (AND-023) and this authenticated graph, and handles logout/expiry redirects. AND-024 must expose a stable route constant and entry point that AND-025 can target with `popUpTo`.
- **Web reference:** `frontend/` post-login shell (tabbed layout) is the UX reference; the Me tab maps to the web `/me` view backed by `GET /ui/me`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 — **Authenticated subgraph exists.** A nested navigation graph rooted at a stable route (`AuthedGraph`) is registered in the app `NavHost`. Its start destination is the bottom-nav shell.

FR-2 — **Bottom-nav shell.** The shell renders a Material 3 `Scaffold` with a `NavigationBar` `bottomBar`. The bar contains exactly two `NavigationBarItem`s: **Home** and **Profile/Me**, each with icon, label, and selected state.

FR-3 — **Two placeholder destinations.** `HomeRoute` and `MeRoute` are distinct destinations inside the shell. Each renders a placeholder Composable (centered text identifying the tab) — no network calls in this ticket.

FR-4 — **Tab switching.** Tapping a `NavigationBarItem` navigates to that tab's destination and updates the selected indicator. The default selected tab on entry is **Home**.

FR-5 — **Multi-back-stack / state preservation.** Each tab maintains its own back stack and saved state. Re-selecting the current tab pops that tab's stack to its root (`launchSingleTop`, `restoreState`, `popUpTo(startDestination){ saveState = true }`). Switching away and back restores the prior destination/scroll state.

FR-6 — **Entry contract for AND-025.** The graph exposes a public route constant (`AuthedGraph.ROUTE`) and a `NavGraphBuilder.authedGraph(...)` extension so AND-025 can navigate to it with a single `popUpTo(rootGraph){ inclusive = true }` after auth success.

FR-7 — **Back behavior at root.** Pressing system Back while on the Home root (the start tab) does not navigate within the authed graph; back handling beyond the graph root is owned by AND-025 (logout/expiry). On a non-Home tab root, system Back returns to the Home tab.

## 4. Technical Design

**Module/package layout** (`feature-shell`):

```
com.testlogon.android.feature.shell.navigation.AuthedGraph
com.testlogon.android.feature.shell.navigation.AuthedTab
com.testlogon.android.feature.shell.ui.AuthedShellScreen
com.testlogon.android.feature.shell.ui.AuthedShellViewModel
com.testlogon.android.feature.shell.ui.home.HomePlaceholderScreen
com.testlogon.android.feature.shell.ui.me.MePlaceholderScreen
```

**Route definitions.** Using the AND-022 typed-route convention (string-based routes with sealed-class wrappers; `@Serializable` type-safe routes are acceptable if AND-022 adopted them — keep consistent with that ticket):

```kotlin
object AuthedGraph {
    const val ROUTE = "authed_graph"
}

enum class AuthedTab(
    val route: String,
    @StringRes val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
) {
    HOME("authed/home", R.string.tab_home, Icons.Filled.Home, Icons.Outlined.Home),
    ME("authed/me", R.string.tab_me, Icons.Filled.Person, Icons.Outlined.Person);

    companion object {
        val START = HOME
        fun fromRoute(route: String?): AuthedTab =
            entries.firstOrNull { route?.startsWith(it.route) == true } ?: START
    }
}
```

**Graph registration** — an extension installed by the app host:

```kotlin
fun NavGraphBuilder.authedGraph(navController: NavHostController) {
    composable(route = AuthedGraph.ROUTE) {
        AuthedShellScreen()   // owns its OWN inner NavController for the tabs
    }
}
```

**Shell with nested NavController.** The shell owns an inner `NavController` for the two tabs (keeps tab back stacks isolated from the root host):

```kotlin
@Composable
fun AuthedShellScreen() {
    val tabNav = rememberNavController()
    val backStack by tabNav.currentBackStackEntryAsState()
    val current = AuthedTab.fromRoute(backStack?.destination?.route)

    Scaffold(
        bottomBar = {
            NavigationBar {
                AuthedTab.entries.forEach { tab ->
                    val selected = tab == current
                    NavigationBarItem(
                        selected = selected,
                        onClick = { tabNav.navigateToTab(tab) },
                        icon = {
                            Icon(
                                if (selected) tab.selectedIcon else tab.unselectedIcon,
                                contentDescription = null,
                            )
                        },
                        label = { Text(stringResource(tab.labelRes)) },
                        modifier = Modifier.testTag("tab_${tab.name.lowercase()}"),
                    )
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = tabNav,
            startDestination = AuthedTab.START.route,
            modifier = Modifier.padding(padding),
        ) {
            composable(AuthedTab.HOME.route) { HomePlaceholderScreen() }
            composable(AuthedTab.ME.route) { MePlaceholderScreen() }
        }
    }
}

private fun NavController.navigateToTab(tab: AuthedTab) {
    navigate(tab.route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}
```

**Placeholder screens** are minimal Composables, e.g. `HomePlaceholderScreen` renders a centered `Text("Home")` inside a `Column`/`Box` with `testTag("home_placeholder")`; `MePlaceholderScreen` analogous with `testTag("me_placeholder")`.

**ViewModel.** `AuthedShellViewModel` is a Hilt `@HiltViewModel` placeholder in this ticket (no state to load yet) exposing `val uiState: StateFlow<ShellUiState>` where `ShellUiState` currently only carries `selectedTab: AuthedTab`. It is included now so the per-tab content tickets and AND-025 logout wiring have an injection point. Tab selection state is derived from the inner NavController back stack (single source of truth) rather than duplicated in the ViewModel.

**Window insets / edge-to-edge.** `Scaffold` consumes the bottom bar insets; placeholder content uses the provided `padding`. Edge-to-edge config (if enabled in AND-002/AND-022) must not double-pad.

## 5. API Contract

**N/A for this ticket.** AND-024 is structural navigation only and makes no network calls. The **Me** tab placeholder will be backed by `GET /ui/me` (cookie session + `X-CSRF-Token`), but wiring that endpoint, its `ApiResult<MeResponse>` mapping, and the Retrofit interface are owned by the downstream Profile/Me feature ticket (and AND-025 for session/auth observation). This spec defines only the navigation seam (`AuthedTab.ME` route) into which that content is later injected. No request/response shapes are introduced here.

## 6. Data & State Management

- **Navigation state** is the only persisted state. The inner tab `NavController` holds the per-tab back stacks; `saveState`/`restoreState` flags preserve them across tab switches. `rememberNavController()` survives recomposition; `rememberSaveable` semantics inside placeholder screens are not needed yet but the back-stack `saveState` ensures future scroll positions survive tab toggles.
- **Selected tab** is derived state: `currentBackStackEntryAsState()` → `AuthedTab.fromRoute(route)`. There is no second copy of "which tab is selected." This avoids drift between the bar indicator and the actual visible destination.
- **`ShellUiState`** (`StateFlow`, MVI-lite per project convention): `data class ShellUiState(val selectedTab: AuthedTab = AuthedTab.START)`. Emitted from `AuthedShellViewModel`; for this ticket it is informational only and not the source of truth for navigation.
- **No Room / DataStore** usage in this ticket. No DTOs, no cache, no prefs. (Auth/session persistence — cookie jar, refresh — lives in core-network/core-data and is consumed by AND-025, not here.)

## 7. Error Handling & Resilience

There are no I/O or network operations, so classic error handling (timeouts, 401 refresh, backoff) is **N/A** and owned downstream (AND-025 for session expiry → redirect; per-tab feature tickets for content load failures). The resilience concerns specific to this ticket are navigation-correctness edge cases:

- **Rapid double-tap on a tab:** `launchSingleTop = true` prevents stacking duplicate destinations.
- **Re-select current tab:** must pop the tab's inner stack to its root (no-op if already at root) without re-creating the destination.
- **Process death / config change:** the inner `NavController` restores its saved back stack; the selected tab is recomputed from the restored route, so the bar indicator stays consistent after rotation.
- **Unknown/empty route** (e.g., transient null during graph init): `AuthedTab.fromRoute(null)` falls back to `START` (Home) so the bar always has a valid selection.

## 8. Security & Privacy

This ticket renders no user data and stores nothing sensitive. The only security-relevant requirement is the **gating invariant**: the authenticated graph must only be reachable when a session exists. AND-024 does **not** enforce that invariant itself — it deliberately exposes a single entry route (`AuthedGraph.ROUTE`) so that **AND-025** is the sole component that decides when to navigate into it (post-finalize) and when to evict it (logout/expiry). To keep that contract safe, this ticket must NOT add any direct navigation edge from the unauthenticated graph (AND-023) into `AuthedGraph`; entry happens only via AND-025's auth-state observer. No PII, tokens, or cookies are touched in `feature-shell`. Placeholder strings are non-sensitive.

## 9. Accessibility & i18n

- **Labels** (`tab_home`, `tab_me`) and placeholder text are externalized in `core-ui`/`feature-shell` `strings.xml`; no hardcoded UI strings. RTL-safe (Compose default).
- **NavigationBarItem** uses Material 3 defaults so the selected item is announced; the `Icon` `contentDescription` is `null` because the adjacent `label` (always shown) provides the accessible name, avoiding double-announcement. Each item is a single focusable touch target ≥ 48dp (Material default).
- **Selected state** is exposed to TalkBack via the `selected` flag (announced as "selected"). Tab labels are always visible (`alwaysShowLabel` default true) for low-vision users.
- **Dynamic type / large fonts:** labels must not be clipped; verify at 200% font scale that both tabs remain legible (single line with ellipsis acceptable).
- **Contrast** follows the Material 3 theme from `core-ui`; no custom colors introduced.

## 10. Telemetry & Logging

Lightweight and structural for this ticket. Emit a single navigation event on tab change through the shared analytics interface (defined in `core-ui`/`core-data`; if not yet present, log via a `Timber`-style tag and leave a `// TODO(AND-0xx telemetry)` hook):

- `nav_tab_selected` with attribute `tab = "home" | "me"` and `reselect = true|false`.
- Debug-only `Log.d("AuthedShell", ...)` on graph entry for QA. No PII is ever logged. No network/latency telemetry applies here. Detailed screen-view analytics for Home/Me content are owned by their respective feature tickets.

## 11. Testing Strategy

**Unit (JVM, `core-testing` helpers):**
- `AuthedTabTest` — `fromRoute()` returns the correct tab for each route prefix and falls back to `HOME` for `null`/unknown.
- `AuthedShellViewModelTest` — initial `ShellUiState.selectedTab == HOME`.

**Compose UI / instrumented (`createComposeRule` / `createAndroidComposeRule` + `TestNavHostController`):**
- `shellRendersBothTabs` — both `tab_home` and `tab_me` nodes exist; `home_placeholder` is displayed by default.
- `tabSwitchingChangesDestination` — `onNodeWithTag("tab_me").performClick()` → `me_placeholder` displayed, `home_placeholder` not displayed; bar selection reflects Me.
- `reselectPopsToRoot` — navigate within a tab (where possible) then re-tap the same tab → returns to that tab's root, single instance.
- `stateRestoredAcrossTabSwitch` — switch Home→Me→Home restores Home's prior state (assert via a scroll position or remembered counter once content exists; for placeholders assert destination identity is restored, not recreated).
- `entersAuthedGraphAsStartWhenAuthenticated` — with a `TestNavHostController` set to `AuthedGraph.ROUTE`, assert the shell + bottom bar render (covers AC: "after login, the authenticated graph shows"). The login simulation is a test-only direct navigation, since real auth-state routing is AND-025.

**Quality gates:** all new Composables pass `detekt`/`ktlint`; tests run in CI on the `android-port` branch.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-022** (Navigation host & routes) — must merge first; this ticket plugs `authedGraph()` into that host and reuses its route/transition conventions.
- **Sibling: AND-023** (Unauthenticated graph) — independent; both are mounted in the same root host. No direct edges between them (see §8).
- **Blocks: AND-025** (Auth-gated routing) — consumes `AuthedGraph.ROUTE` and the `authedGraph()` entry point; AND-025 cannot be completed until this exists.
- **Downstream consumers:** future Home-content and Profile/Me feature tickets fill `HomePlaceholderScreen`/`MePlaceholderScreen`; AND-025 adds the logout action surfaced from the shell (likely via `AuthedShellViewModel`).
- **Sequencing:** AND-022 → **AND-024** (parallel with AND-023) → AND-025.

## 13. Risks & Open Questions

- **R1 — Inner vs. flat NavController.** This design uses a nested `NavController` inside the shell for clean per-tab back stacks. Risk: AND-025's expiry redirect must pop the *root* host, not the inner one. Mitigation: AND-025 targets `AuthedGraph.ROUTE` on the root host; the inner controller is disposed with the destination. Confirm with AND-025 owner.
- **R2 — Type-safe routes.** If AND-022 adopted `@Serializable` type-safe Navigation routes, the string constants here should be replaced with serializable route objects for consistency. Open question: which convention did AND-022 land on? Default to matching AND-022.
- **R3 — Icons dependency.** `Icons.Outlined.*` requires `material-icons-extended`; if not already a dependency, add it to `feature-shell` (or use core icon set) to avoid bloating the icon artifact.
- **R4 — Number of tabs.** Backlog specifies two tabs (Home, Me). If product later adds more, the `enum`-driven bar scales without structural change — noted, not in scope.
- **Q1 — Logout entry point.** Should the placeholder Me tab include a logout affordance now? Assumed **no** (owned by AND-025); confirm.

## 14. Acceptance Criteria

AC-1 — After a (test-simulated) login, navigating to `AuthedGraph.ROUTE` shows the authenticated shell with the Material 3 `NavigationBar` and both **Home** and **Profile/Me** items rendered. *(Backlog AC: "After login, the authenticated graph shows.")*

AC-2 — **Home** is the default selected tab and `home_placeholder` is displayed on entry.

AC-3 — Tapping the **Me** item switches the visible destination to `me_placeholder`, hides `home_placeholder`, and moves the selected indicator to Me; tapping **Home** switches back. *(Backlog AC: "bottom nav switches tabs.")*

AC-4 — Each tab preserves its own back stack/state: switching away and back does not recreate the tab's root from scratch (verified by test).

AC-5 — Re-selecting the currently selected tab pops that tab to its root and does not stack a duplicate destination.

AC-6 — The graph exposes `AuthedGraph.ROUTE` and a `NavGraphBuilder.authedGraph(navController)` extension usable by AND-025.

AC-7 — All tab labels are string resources; `NavigationBarItem`s are TalkBack-navigable with correct selected announcements; targets ≥ 48dp.

AC-8 — Unit + Compose UI tests in §11 pass in CI on `android-port`.

## 15. Definition of Done

- [ ] `feature-shell` module contains `AuthedGraph`, `AuthedTab`, `AuthedShellScreen`, `AuthedShellViewModel`, and the two placeholder screens under `com.testlogon.android.feature.shell.*`.
- [ ] `authedGraph()` extension is registered in the app `NavHost`; navigating to `AuthedGraph.ROUTE` renders the shell.
- [ ] Bottom `NavigationBar` shows Home + Me; tab switching and multi-back-stack state preservation work per AC-2..AC-5.
- [ ] No direct navigation edge from the unauthenticated graph into the authed graph (entry reserved for AND-025).
- [ ] Strings externalized; accessibility verified (labels, selected state, 48dp targets, 200% font scale).
- [ ] `nav_tab_selected` telemetry hook in place; no PII logged.
- [ ] Unit and Compose UI tests written and green in CI; `ktlint`/`detekt` clean.
- [ ] Public API (`AuthedGraph.ROUTE`, `authedGraph(...)`) documented with KDoc for AND-025.
- [ ] Code reviewed and merged to `android-port`.
