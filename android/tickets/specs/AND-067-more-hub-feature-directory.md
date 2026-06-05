---
id: AND-067
title: "\"More\" hub (feature directory)"
milestone: M2
epic: E09
priority: P1
size: M
status: draft
depends_on: [AND-024]
blocks: []
---

# AND-067 — "More" hub (feature directory)

## 1. Overview & Goal

The TestLogon app exposes a small set of primary destinations in the bottom navigation bar (Home, Profile/Me — see AND-024). The long tail of secondary features (settings, security, sessions, notifications, help, about, developer tools, etc.) cannot all live in the bottom bar. The "More" hub is the canonical entry point into that long tail: a single scrollable directory screen, reachable from a bottom-nav "More" tab or overflow, that lists the secondary features as a grid/list of entries, each of which deep-links to an existing destination in the authenticated navigation graph.

The goal of this ticket is to deliver a **data-driven, availability-gated feature directory**. Each entry is described by a static descriptor (icon, label, route/deep-link, availability predicate). Entries whose target destination is not available — because the destination feature ticket is not yet merged, because a server capability flag is off, or because the current user lacks the entitlement — are either hidden or rendered disabled with an explanatory affordance. The hub itself owns no business data; it is a routing surface. Navigation correctness and availability gating are the two acceptance pillars (per the source ticket: *"Hub navigates to existing destinations; unavailable items hidden/disabled."*).

This is deliberately scoped to the **directory and its gating logic**, not the destination screens. The hub must degrade gracefully as destinations come online: adding a feature is a matter of registering one descriptor, not editing the hub UI.

## 2. Context & References

- **Source ticket:** AND-067 — "More" hub (feature directory). Type: Feature · Priority: P1 · Deps: AND-024.
- **Dependency AND-024** (Authenticated nav graph + bottom nav skeleton, M1/E03): provides the single-Activity `NavHost`, the authenticated nested graph, and the bottom-nav scaffold this hub plugs into. AND-067 adds the `More` tab/route and screen to that graph.
- **Project stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. This ticket introduces `feature-more` and uses `core-ui`, `core-model`, `core-data` (for capability/entitlement flags) and `core-testing`.
- **Namespace:** `com.testlogon.android` (e.g., `com.testlogon.android.feature.more`).
- **Web reference:** the `frontend/` React app's "More"/settings index and route table (`frontend/src/api/types.ts` for any capability flags) inform which entries exist and their labels. The hub mirrors that catalog but is Android-native and route-driven.
- **Backend:** No dedicated endpoint for the hub. The only server interaction is reading user capability/entitlement signals already surfaced by `GET /ui/me` (consumed via `core-data` from AND's session work). See §5.

## 3. Functional Requirements

FR-1. **More tab/route.** A `More` destination is registered in the authenticated nav graph at route `more`. It is reachable as a bottom-nav item (preferred) or, if the bottom bar is full, as an overflow entry. Selecting it shows the hub screen; re-selecting it pops the More sub-stack to root (standard bottom-nav behavior).

FR-2. **Directory rendering.** The hub renders a vertically scrolling list of **sections**, each section containing a set of **entries** laid out as a responsive grid (adaptive columns: 2 columns at compact width, 3+ at expanded width via `LazyVerticalGrid` with `GridCells.Adaptive`). Each entry shows a leading icon, a primary label, and an optional secondary supporting line.

FR-3. **Static catalog.** Entries are declared in a static, ordered catalog (`MoreCatalog`) in code. No network call is required to render the catalog. The catalog is the single source of truth for label, icon, route, section, and availability rule.

FR-4. **Availability gating.** Every entry has an `availability` resolved at render time to one of: `Available`, `Hidden`, or `Disabled(reason)`.
  - `Hidden` entries are not composed at all (not in the layout, not in the semantics tree).
  - `Disabled(reason)` entries are composed but non-interactive: greyed (reduced alpha), not clickable, and expose a reason (tooltip/long-press/inline supporting text) such as "Coming soon" or "Not available for your account".
  - `Available` entries are fully interactive.

FR-5. **Navigation.** Tapping an `Available` entry navigates via the entry's declared route/deep-link using the shared `NavController` from AND-024. Navigation must reach an **existing** destination; tapping an entry whose route is not registered in the graph is a defect (guarded against in tests, see §11).

FR-6. **Empty/degraded state.** If, after gating, a section has zero visible entries, the section header is suppressed. If the entire catalog resolves to zero visible entries (theoretically possible), the hub shows a neutral empty state ("Nothing here yet").

FR-7. **No destination ownership.** The hub does not implement any destination screen. Routes that do not yet exist resolve to `Hidden` or `Disabled` via their availability predicate so the hub never links to a missing screen.

FR-8. **Idempotent recomposition.** The screen is stateless except for the resolved UI state; rotation/process-death restores the same scroll position (via `rememberLazyGridState` + saved state) and re-resolves availability.

## 4. Technical Design

### 4.1 Module & package layout

New Gradle module `feature-more` (`com.testlogon.android.feature.more`):

```
feature-more/
  MoreRoute.kt           // route constant + NavGraphBuilder ext
  MoreCatalog.kt         // static descriptors
  MoreViewModel.kt
  MoreUiState.kt
  ui/MoreScreen.kt
  ui/MoreEntryCard.kt
  di/MoreModule.kt
```

### 4.2 Descriptor model (`core-model`)

```kotlin
data class MoreEntry(
    val id: String,                 // stable analytics/test id, e.g. "security"
    @StringRes val labelRes: Int,
    @StringRes val supportingRes: Int? = null,
    val icon: ImageVector,
    val route: String,              // target route already in the nav graph
    val section: MoreSection,
    val requiredCapability: Capability? = null, // null => no server gate
    val featureFlag: FeatureFlag? = null,        // null => always built
)

enum class MoreSection(@StringRes val titleRes: Int) {
    ACCOUNT(R.string.more_section_account),
    SECURITY(R.string.more_section_security),
    APP(R.string.more_section_app),
    SUPPORT(R.string.more_section_support),
}

sealed interface EntryAvailability {
    data object Available : EntryAvailability
    data object Hidden : EntryAvailability
    data class Disabled(@StringRes val reasonRes: Int) : EntryAvailability
}
```

`Capability` (server-driven, from `GET /ui/me`) and `FeatureFlag` (local/remote toggle from `core-data`) are existing enums; if a flag/capability type is not yet available, the predicate defaults to "built but `Disabled(Coming soon)`".

### 4.3 Availability resolution

A pure resolver, unit-testable in isolation:

```kotlin
class MoreAvailabilityResolver @Inject constructor(
    private val routeRegistry: RouteRegistry,        // known registered routes
    private val capabilities: CapabilityProvider,    // from /ui/me snapshot
    private val flags: FeatureFlagProvider,
) {
    fun resolve(entry: MoreEntry): EntryAvailability {
        if (!routeRegistry.isRegistered(entry.route)) return EntryAvailability.Hidden
        entry.featureFlag?.let { if (!flags.isEnabled(it)) return EntryAvailability.Hidden }
        entry.requiredCapability?.let {
            if (!capabilities.has(it)) return EntryAvailability.Disabled(R.string.more_unavailable_account)
        }
        return EntryAvailability.Available
    }
}
```

Precedence: unregistered route → `Hidden`; disabled flag → `Hidden`; missing capability → `Disabled`. This makes "feature not built yet" invisible while "feature exists but you can't use it" explanatory.

### 4.4 ViewModel & UI

```kotlin
@HiltViewModel
class MoreViewModel @Inject constructor(
    private val resolver: MoreAvailabilityResolver,
    private val catalog: MoreCatalog,
) : ViewModel() {
    val uiState: StateFlow<MoreUiState> =
        catalog.flow                                  // re-emits on flag/capability change
            .map { entries -> entries.toUiState(resolver) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MoreUiState.Loading)
}

@Composable
fun MoreScreen(
    onNavigate: (route: String) -> Unit,
    viewModel: MoreViewModel = hiltViewModel(),
)
```

`MoreUiState`:

```kotlin
sealed interface MoreUiState {
    data object Loading : MoreUiState
    data object Empty : MoreUiState
    data class Content(val sections: List<MoreSectionUi>) : MoreUiState
}
data class MoreSectionUi(val section: MoreSection, val items: List<MoreItemUi>)
data class MoreItemUi(val entry: MoreEntry, val availability: EntryAvailability)
```

`Hidden` items are filtered out in `toUiState`; only `Available`/`Disabled` reach the UI.

### 4.5 Route registration

```kotlin
const val MORE_ROUTE = "more"
fun NavGraphBuilder.moreScreen(onNavigate: (String) -> Unit) {
    composable(MORE_ROUTE) { MoreScreen(onNavigate = onNavigate) }
}
```

`onNavigate` is wired in `app` to `navController.navigate(route) { launchSingleTop = true }`. The `RouteRegistry` is populated in `app` from the set of routes the authenticated graph actually registers, so the resolver's "is registered" check is authoritative rather than guessed.

## 5. API Contract

This ticket has **no dedicated backend endpoint**. The hub is a local routing surface. The only server data consumed is the existing user session snapshot used for capability gating:

- `GET /ui/me` (owned by the session/auth tickets; cookie-based session, `X-CSRF-Token` echoed from `ui_csrf` cookie). Relevant fields are read through `core-data`'s cached user model, e.g.:

```json
{
  "id": "u_123",
  "username": "alice",
  "capabilities": ["sessions.view", "security.totp", "billing.manage"],
  "flags": { "developer_tools": false }
}
```

The hub maps `entry.requiredCapability` against `capabilities[]` and never calls the network itself. If `/ui/me` is stale/unavailable (the dev host `http://18.222.237.167:8000` is unreliable), the resolver uses the last cached snapshot from `core-data`; missing data is treated conservatively as "capability absent" → `Disabled` rather than wrongly enabling an entry. No write/mutation occurs from this screen. Owner of the `/ui/me` contract and refresh-on-401 logic is the session epic, not AND-067.

## 6. Data & State Management

- **Catalog:** in-memory static list (`MoreCatalog`), no persistence. Compiled in; ordering is the declared order.
- **UI state:** `StateFlow<MoreUiState>` exposed by `MoreViewModel`, collected with `collectAsStateWithLifecycle()`. State is derived; nothing is written back.
- **Capability/flag inputs:** read-only `Flow`s from `core-data` (`CapabilityProvider`, `FeatureFlagProvider`). When these emit (e.g., `/ui/me` refresh flips a capability), `uiState` recomputes and the grid re-gates without manual refresh.
- **Scroll position:** `rememberLazyGridState()` (survives recomposition; saved across config changes). No Room/DataStore writes are introduced by this ticket.
- **Threading:** resolution is pure CPU work on the default dispatcher inside `map`; the catalog is small (tens of entries) so no paging is needed.

## 7. Error Handling & Resilience

- **No network of its own**, so no timeouts/retries originate here; the 20s timeout + bounded-backoff-for-idempotent-GET policy applies only to the upstream `/ui/me` refresh owned elsewhere.
- **Stale/unavailable capabilities:** resolver degrades to last cached snapshot; absent capability → `Disabled` (fail-closed), never silently `Available`.
- **Unregistered route:** resolver returns `Hidden`; tapping is impossible because the entry isn't composed. A defensive guard in the `app` navigation lambda ignores navigation to an unregistered route and logs a warning (should be unreachable).
- **Empty catalog after gating:** `MoreUiState.Empty` renders a neutral message rather than a blank screen.
- **Disabled tap:** consumes the click as a no-op and surfaces the reason (snackbar/tooltip) instead of navigating.

## 8. Security & Privacy

- The hub renders **only entries the user is entitled to interact with**; gated entries are hidden or disabled, so the UI does not advertise features the account cannot use beyond an intentional "Coming soon"/"Not available for your account" affordance. Gating is **fail-closed**.
- No credentials, tokens, or PII are read or written by this screen. Capability data is already in memory from the authenticated session; the hub does not log capability lists.
- Gating is a **UX convenience, not an authorization boundary** — the destination screens and the backend remain responsible for enforcing access on entry. The hub must not be relied upon as the sole access control.
- No new permissions, no new persisted data, no exported components introduced.

## 9. Accessibility & i18n

- All labels, supporting text, section titles, disabled reasons, and the empty state use string resources (`@StringRes`); no hardcoded user-facing text. Default `values/strings.xml` (en) plus `strings_more.xml` keys prefixed `more_`.
- Each entry card has `contentDescription` combining label + state (e.g., "Security. Available" / "Developer tools. Disabled, coming soon"); `Disabled` cards set `Modifier.semantics { disabled() }` and are excluded from click semantics.
- Touch targets ≥ 48dp; icon-only is never the sole label. Grid is keyboard/d-pad and TalkBack traversable in declared order.
- Supports dynamic font scaling (no fixed text heights), RTL via logical paddings, and light/dark + dynamic color (Material 3). Color is never the only signal for `Disabled` (reduced alpha + reason text/semantics).

## 10. Telemetry & Logging

- **Screen view:** emit `more_hub_viewed` when the screen enters `RESUMED`, with `{ visible_count, disabled_count }` (no entry ids of disabled items beyond counts to avoid leaking feature names).
- **Entry tap:** emit `more_entry_tapped` `{ entry_id, route, availability }` for `Available` taps and `more_entry_blocked` `{ entry_id, reason }` for `Disabled` taps.
- Telemetry goes through the existing analytics abstraction in `core-ui`/`core-data`; no PII, no capability dumps. Debug logging via the project logger at `DEBUG` for resolver decisions; nothing logged at `INFO`+ in release.

## 11. Testing Strategy

- **Unit (`MoreAvailabilityResolver`):** registered+capable → `Available`; unregistered route → `Hidden`; disabled flag → `Hidden`; missing capability → `Disabled(reason)`; precedence order verified. Fakes for `RouteRegistry`/`CapabilityProvider`/`FeatureFlagProvider` from `core-testing`.
- **ViewModel:** `MoreViewModel.uiState` emits `Loading` → `Content` with `Hidden` filtered out; recomputes when a capability flow emits; empty result → `Empty`. Uses `Turbine` + test dispatcher.
- **Catalog integrity test:** assert **every** `MoreEntry.route` in `MoreCatalog` is present in the authenticated graph's known route set (prevents linking to non-existent destinations — directly enforces the acceptance criterion). Run against the same `RouteRegistry` the app builds.
- **Compose UI (`createAndroidComposeRule`):** `Hidden` entries have no node (`assertDoesNotExist`); `Disabled` entries exist, are not clickable, and expose reason semantics; `Available` entries clickable and invoke `onNavigate(route)` exactly once with the right route.
- **Navigation/integration:** from a test `NavHost` with stub destinations registered, tapping each `Available` entry lands on the expected route; tapping a `Disabled` entry does not navigate.
- Coverage target: resolver + ViewModel ≥ 90% line; UI smoke for the three availability states.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-024 (authenticated nav graph + bottom-nav skeleton) must be merged — it provides the `NavHost`, the bottom-nav slot for the More tab, and the shared `NavController`/route plumbing.
- **Soft / downstream:** the destination tickets the hub links to (settings, security, sessions, notifications, help/about, developer tools, etc.). The hub does **not** block on them — entries for unbuilt destinations resolve to `Hidden`/`Disabled` and become live automatically as those routes register. As each destination ticket merges, it (a) registers its route and (b) adds/enables its `MoreEntry` (or the entry is already present and flips to `Available`).
- **Provides:** a stable extension point (`MoreCatalog`) so feature tickets attach themselves to the hub by adding one descriptor.
- **Sequencing:** can start as soon as AND-024 lands; ship before the bulk of long-tail feature tickets so they have a home on arrival.

## 13. Risks & Open Questions

- **R1 — Tab vs. overflow placement.** If the bottom bar already holds Home + Profile and design wants ≤ 3–4 items, "More" is a natural 3rd tab; confirm with design whether More is a bottom-nav tab or an app-bar overflow. (Default: bottom-nav tab.)
- **R2 — Capability/flag types not yet defined.** `Capability`/`FeatureFlag` enums may not exist when this lands; mitigation: ship with `requiredCapability = null`/`featureFlag = null` so entries are gated only by route registration, and tighten gating as those types arrive.
- **R3 — Catalog ownership drift.** Multiple feature tickets editing `MoreCatalog` risks merge conflicts; mitigation: one descriptor per entry, alphabetized within section, plus the catalog-integrity test as a guardrail.
- **R4 — Hidden vs. Disabled UX choice.** Source ticket allows either "hidden or disabled". Open question: should "coming soon" features be visible-disabled (discoverability) or fully hidden? Proposed default: unbuilt route → `Hidden`; built-but-unentitled → `Disabled`. Confirm with product.
- **Q1 — Section taxonomy.** Final section list/labels to be confirmed against the web `frontend/` settings index.

## 14. Acceptance Criteria

AC-1. A "More" destination exists in the authenticated nav graph at route `more` and is reachable from the bottom nav (or overflow per design), per AND-024 plumbing.
AC-2. The hub renders the catalog as a responsive grid grouped into sections, with leading icon + label per entry.
AC-3. Tapping any `Available` entry navigates to an **existing, registered** destination (verified by the catalog-integrity test: every catalog route is in the registered route set).
AC-4. Entries whose target route is unregistered or whose feature flag is off are **not present** in the UI (no node in the semantics tree).
AC-5. Entries the user lacks the capability for are **Disabled**: visibly greyed, non-clickable, with a reason exposed to TalkBack and not navigating on tap.
AC-6. Availability re-resolves when capability/flag inputs change, without leaving the screen.
AC-7. With zero visible entries, a neutral empty state is shown (no blank screen).
AC-8. All user-facing strings are localized; cards meet 48dp touch targets and expose correct accessibility semantics for each state.

## 15. Definition of Done

- `feature-more` module created under `com.testlogon.android.feature.more`, wired via Hilt and registered in the authenticated nav graph (`moreScreen`), bottom-nav entry added.
- `MoreEntry`/`MoreSection`/`EntryAvailability` in `core-model`; `MoreCatalog`, `MoreAvailabilityResolver`, `MoreViewModel`, `MoreScreen`, `MoreEntryCard` implemented.
- All §14 acceptance criteria pass; unit + ViewModel + Compose UI + navigation + catalog-integrity tests added and green in CI; resolver/ViewModel coverage ≥ 90%.
- Telemetry events emitted as in §10; no PII/capability dumps logged.
- Strings localized; accessibility verified with TalkBack for `Available`/`Disabled`/empty states; light/dark + dynamic color verified.
- `ktlint`/`detekt` clean; no new lint regressions; module builds on AGP 8.7.3 / Gradle 8.9 / JDK 17.
- Code reviewed and merged to `android-port`; spec status moved from `draft` to `done`.
