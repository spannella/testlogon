---
id: AND-067
title: "\"More\" hub (feature directory)"
milestone: M2
epic: E09
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (verified):** the web client implements an equivalent "More" surface in `src/components/layout/MobileNav.tsx`. There, a bottom-nav `More` button opens a Material `Sheet` that renders a static `MORE_LINKS` catalog (label + i18nKey + path + icon) in a 4-column grid; each link calls `navigate(link.path)`. The catalog is gated by a `.filter(...)` predicate that hides links based on (a) feature flags (`isBroadcastNavigationEnabled()`, `isVncRemoteDesktopEnabled()` from `src/lib/featureFlags`) and (b) JWT-derived roles (`canSeeRootRoleManagement()`, `canAccessModerationBoard()` from `src/lib/adminCapabilities`). NOTE: the web app uses **hide-only** gating (no disabled/greyed state); the `Disabled(reason)` state in this spec is a deliberate Android-native enhancement, not a mirror of web behavior. The Android hub mirrors the catalog-of-descriptors + predicate-filter pattern but is a dedicated route rather than a sheet.
- **Backend:** No dedicated endpoint for the hub. The hub makes no network calls of its own. Capability/entitlement gating on web is driven by the **JWT access-token claims** (`role`, `admin_profile.scopes`), parsed client-side (`getRoleFromAccessToken` / `getAdminProfileFromAccessToken` in `src/lib/adminCapabilities.ts`), plus local feature flags — NOT by fields in `GET /ui/me`. See §5 for the corrected source-of-truth.

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

`Capability` (derived from the **decoded JWT access-token claims** — `role` / `admin_profile.scopes` — mirroring web `src/lib/adminCapabilities.ts`, NOT from `/ui/me` body fields) and `FeatureFlag` (local/remote toggle from `core-data`) are existing enums; if a flag/capability type is not yet available, the predicate defaults to "built but `Disabled(Coming soon)`".

### 4.3 Availability resolution

A pure resolver, unit-testable in isolation:

```kotlin
class MoreAvailabilityResolver @Inject constructor(
    private val routeRegistry: RouteRegistry,        // known registered routes
    private val capabilities: CapabilityProvider,    // from decoded JWT access-token claims (role/admin_profile.scopes), not /ui/me body
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

This ticket has **no dedicated backend endpoint**. The hub is a local routing surface and makes **no network calls of its own**.

**CORRECTION (verified against sources):** Earlier drafts of this spec claimed the hub reads `capabilities[]` and `flags{}` from `GET /ui/me`. That is **wrong**. The actual `MeResp` returned by `GET /ui/me` (web `src/api/types.ts: MeResp`) is only:

```json
{
  "user_sub": "string",
  "session_id": "string",
  "ip": "string"
}
```

`/ui/me` carries **no** `capabilities`, `flags`, `id`, or `username` fields (the OpenAPI 200 response for `GET /ui/me` is an unconstrained schema `{}`, and the web `MeResp` type confirms the three-field shape). Capability/entitlement gating on web is therefore NOT sourced from `/ui/me`. The verified sources of gating signals are:

1. **Role / admin scope** — derived by parsing the **JWT access-token claims** client-side: `claims.role` and `claims.admin_profile.scopes` (`src/lib/adminCapabilities.ts: getRoleFromAccessToken / getAdminProfileFromAccessToken`). The access token is held in the auth store and attached as `Authorization: Bearer <token>` by the client (`src/api/client.ts`).
2. **Feature flags** — local toggles in `src/lib/featureFlags.ts` (e.g. `isBroadcastNavigationEnabled()`, `isVncRemoteDesktopEnabled()`).

**Android mapping:** the Android `CapabilityProvider` should therefore derive capability from the **decoded access-token claims** surfaced by the session layer (mirroring the web JWT-claims approach), and `FeatureFlagProvider` from `core-data`'s local/remote flags — NOT from a `capabilities[]` field on `/ui/me`. The hub itself still never calls the network: it consumes these already-in-memory signals via `core-data`.

**Transport/auth context (verified, owned by the session epic — not AND-067):** the web client uses cookie-based sessions (`fetch(..., { credentials: "include" })`) and echoes the CSRF token from the `ui_csrf` cookie into the `X-CSRF-Token` request header (`src/api/client.ts`), in addition to the `Authorization: Bearer` access token. On a `401`, the client refreshes once via `POST /ui/session/refresh` and retries; on refresh failure it logs out. If session signals are stale/unavailable (the dev host `http://18.222.237.167:8000` is unreliable), the resolver uses the last cached snapshot from `core-data`; missing data is treated conservatively as "capability absent" → `Disabled` (fail-closed) rather than wrongly enabling an entry. No write/mutation occurs from this screen.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **A web "More" hub exists and uses a static catalog of descriptors filtered by predicates.** VERIFIED. Source: `src/components/layout/MobileNav.tsx` — `MORE_LINKS` (static array of `{ label, i18nKey, path, icon }`) rendered in a `Sheet`, filtered by `MORE_LINKS.filter(...)`.
2. **The web "More" surface is a bottom-sheet opened from a bottom-nav button, not a dedicated route.** VERIFIED. Source: `src/components/layout/MobileNav.tsx` (`setMoreOpen(true)` → `<Sheet open={moreOpen}>`). The Android decision to use a dedicated `more` route instead is an intentional platform divergence (see §3 FR-1) — UNVERIFIED-ASSUMPTION as a product decision, but consistent with Navigation-Compose conventions (framework ref: https://developer.android.com/jetpack/compose/navigation).
3. **The web "More" catalog renders as a grid.** VERIFIED. Source: `src/components/layout/MobileNav.tsx` (`<div className="grid grid-cols-4 gap-4">`). Backs FR-2 / AC-2 (responsive grid).
4. **Web gating hides entries by feature flag.** VERIFIED. Source: `src/components/layout/MobileNav.tsx` (`if (item.path === "/broadcast") return isBroadcastNavigationEnabled();`, `isVncRemoteDesktopEnabled()`), flags defined in `src/lib/featureFlags.ts`.
5. **Web gating hides entries by user role/scope.** VERIFIED. Source: `src/components/layout/MobileNav.tsx` (`canSeeRootRoleManagement(accessToken)`, `canAccessModerationBoard(accessToken)`) → `src/lib/adminCapabilities.ts`.
6. **Capability/role on web is derived from JWT access-token claims, NOT from `/ui/me`.** VERIFIED. Source: `src/lib/adminCapabilities.ts: getRoleFromAccessToken / getAdminProfileFromAccessToken` (decodes `atob(token.split(".")[1])`, reads `claims.role` and `claims.admin_profile.scopes`); token attached in `src/api/client.ts` as `Authorization: Bearer`.
7. **`GET /ui/me` exists.** VERIFIED. Source: OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`, tag `ui-session`).
8. **`GET /ui/me` returns `{ user_sub, session_id, ip }` and does NOT include `capabilities[]`/`flags{}`/`id`/`username`.** CORRECTED (was wrong in earlier draft). Source: `src/api/types.ts: MeResp` (exactly `user_sub`, `session_id`, `ip`); OpenAPI `GET /ui/me` 200 response schema is unconstrained (`{}`), so it does not assert any capability/flag fields.
9. **The hub maps `requiredCapability` against a `capabilities[]` array from `/ui/me`.** CORRECTED → the array does not exist; gating must derive from decoded JWT claims (claim 6) + local feature flags (claim 4). Source: same as claims 6 and 8.
10. **Web auth uses cookie session + `X-CSRF-Token` from `ui_csrf` cookie.** VERIFIED. Source: `src/api/client.ts` (`credentials: "include"`, `const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`).
11. **Web client also attaches `Authorization: Bearer <accessToken>`.** VERIFIED (and was omitted from the earlier draft's transport description). Source: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
12. **On 401 the client refreshes once via `POST /ui/session/refresh` and retries.** VERIFIED. Source: `src/api/client.ts` (`refreshSession()` → `fetch(withApiBase("/ui/session/refresh"), { method: "POST" })`, then retry; logout on failure) and `src/api/endpoints/auth.ts: refreshSession → POST /ui/session/refresh`.
13. **`/ui/me` accepts an optional `X-IMPERSONATION-TOKEN` header (impersonation path).** VERIFIED. Source: OpenAPI `GET /ui/me` params `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`; web sends it conditionally in `src/api/client.ts` (`headers.set("X-IMPERSONATION-TOKEN", imp.token)`). Not used by the hub directly; noted for the session layer.
14. **Validation errors (422) use `HTTPValidationError { detail: ValidationError[] }`.** VERIFIED. Source: OpenAPI `components.schemas.HTTPValidationError` and `components.schemas.ValidationError`. (Not raised by the hub itself, but the shape governs any upstream session-refresh failure surfaced to gating.)
15. **Web "More" gating is hide-only (no disabled/greyed state).** VERIFIED. Source: `src/components/layout/MobileNav.tsx` uses `.filter(...)` (entry simply absent). The spec's `Disabled(reason)` state (FR-4) is an Android-native enhancement, NOT mirrored from web.
16. **Android stack/tooling (Compose + Material 3, single-Activity Navigation-Compose, Hilt/KSP, `LazyVerticalGrid` + `GridCells.Adaptive`, `rememberLazyGridState`, `collectAsStateWithLifecycle`).** UNVERIFIED from backend/frontend sources (framework choices). framework refs: Navigation-Compose https://developer.android.com/jetpack/compose/navigation ; LazyVerticalGrid/GridCells.Adaptive https://developer.android.com/jetpack/compose/lists#lazy-grids ; Hilt https://developer.android.com/training/dependency-injection/hilt-android ; lifecycle-aware collection https://developer.android.com/jetpack/compose/state#use-other-types-of-state-in-jetpack-compose .
17. **Touch targets ≥ 48dp; non-color signalling for disabled; TalkBack semantics.** UNVERIFIED from app sources (a11y design choice). framework ref: https://developer.android.com/guide/topics/ui/accessibility/principles .

### Corrections made

- **§2 (Context):** rewrote the web-reference bullet to cite the real web "More" implementation (`MobileNav.tsx` sheet + `MORE_LINKS` + predicate filter) and the real gating sources (JWT claims via `adminCapabilities.ts`, flags via `featureFlags.ts`); noted that web is hide-only and the `Disabled` state is an Android addition. Removed the incorrect implication that capability flags live in `src/api/types.ts`.
- **§2 / §5:** removed the false claim that the hub reads `capabilities[]`/`flags{}` from `GET /ui/me`. Replaced §5's fabricated JSON body with the verified `MeResp` (`user_sub`, `session_id`, `ip`) and re-pointed capability gating at decoded JWT access-token claims + local feature flags. Added the verified transport/auth context (cookie + `X-CSRF-Token`, `Authorization: Bearer`, 401→`/ui/session/refresh` retry).
- **§4.2 / §4.3:** fixed inline comments asserting `Capability` comes "from `GET /ui/me`" → now "decoded JWT access-token claims (role/admin_profile.scopes)".

### Open assumptions

- **OA-1 — `more` as a dedicated route/tab vs. a sheet.** The web equivalent is a bottom sheet; this spec proposes a dedicated `more` route. This is a product/design decision (mirrors §13 R1) and is not derivable from the sources. Unverifiable until design confirms.
- **OA-2 — Android `Capability`/`FeatureFlag` enum existence and the JWT-claims plumbing in `core-data`.** The session/auth tickets must expose decoded access-token claims (role/scopes) to a `CapabilityProvider`. Not present in the reference sources (web parses the JWT inline). Mirrors §13 R2; resolve when those types land.
- **OA-3 — Final section taxonomy and per-entry route names.** The web `MORE_LINKS` paths (e.g. `/security`, `/billing`, `/settings`, `/notifications`) suggest the catalog, but the Android route constants and section grouping are not yet fixed (mirrors §13 Q1). Unverifiable until destination tickets register their routes.
- **OA-4 — Whether the access token is a JWT on Android.** Web decodes a base64 JWT payload; if the Android session layer stores an opaque token instead, capability derivation needs a different surface. Unverifiable from current sources.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **Emulator** = headless AVD `test35` (x86_64, Android 15 / API 35); **Device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). For this ticket no case strictly requires the physical device — there is no camera/biometrics/FCM/WebRTC/Telecom/streaming hardware path — so UI/instrumented cases default to the **Emulator**; one accessibility case is additionally exercised on the **Device** to validate real TalkBack + API-34/arm64 behavior.

- **TC-AND-067-01 — Resolver: available path.** Type: unit (JVM). Target: `MoreAvailabilityResolver`. Preconditions: fakes from `core-testing` — `RouteRegistry.isRegistered(route)=true`, no `featureFlag`, no `requiredCapability`. Steps: `resolve(entry)`. Expected: returns `EntryAvailability.Available`. Traces: AC-3.
- **TC-AND-067-02 — Resolver: unregistered route → Hidden.** Type: unit (JVM). Target: `MoreAvailabilityResolver`. Preconditions: `RouteRegistry.isRegistered(route)=false`. Steps: `resolve(entry)`. Expected: `Hidden`. Traces: AC-4.
- **TC-AND-067-03 — Resolver: disabled feature flag → Hidden.** Type: unit (JVM). Target: `MoreAvailabilityResolver`. Preconditions: route registered, `featureFlag` set, `FeatureFlagProvider.isEnabled(flag)=false`. Steps: `resolve(entry)`. Expected: `Hidden`. Traces: AC-4.
- **TC-AND-067-04 — Resolver: missing capability → Disabled(reason).** Type: unit (JVM). Target: `MoreAvailabilityResolver`. Preconditions: route registered, flag enabled, `requiredCapability` set, `CapabilityProvider.has(cap)=false`. Steps: `resolve(entry)`. Expected: `Disabled(R.string.more_unavailable_account)`. Traces: AC-5.
- **TC-AND-067-05 — Resolver: precedence (unregistered beats missing-capability).** Type: unit (JVM). Target: `MoreAvailabilityResolver`. Preconditions: route NOT registered AND capability missing AND flag disabled. Steps: `resolve(entry)`. Expected: `Hidden` (route check wins; never leaks an unbuilt feature as `Disabled`). Traces: AC-4, AC-5.
- **TC-AND-067-06 — Capability derived from JWT claims, not `/ui/me` body.** Type: contract/MockWebServer (Emulator or JVM/Robolectric). Target: `CapabilityProvider` + session layer adapter. Preconditions: MockWebServer returns `GET /ui/me` = `{ "user_sub":"u1","session_id":"s1","ip":"1.2.3.4" }` (verified shape, no `capabilities`) and the auth store holds an access token whose decoded payload contains `{"role":"root"}`. Steps: resolve an entry whose `requiredCapability` maps to a root-only capability. Expected: capability is satisfied from the decoded token claim (entry `Available`); the absence of `capabilities[]` in `/ui/me` does NOT cause it to be treated as missing. Negative variant: token with `{"role":"user"}` → capability absent → `Disabled`. Traces: AC-5.
- **TC-AND-067-07 — Catalog integrity: every route is registered.** Type: integration (JVM/Robolectric). Target: `MoreCatalog` × app `RouteRegistry`. Preconditions: build the same `RouteRegistry` the `app` module assembles from the authenticated graph. Steps: for each `MoreEntry` in `MoreCatalog`, assert `routeRegistry.isRegistered(entry.route)` OR the entry is intentionally gated (flag/capability) — fail if a catalog route can never resolve to a real destination. Expected: no catalog entry links to a non-existent destination. Traces: AC-3, AC-4.
- **TC-AND-067-08 — ViewModel: Loading → Content with Hidden filtered out.** Type: unit (JVM, Turbine + test dispatcher). Target: `MoreViewModel`. Preconditions: catalog with a mix resolving to `Available`/`Disabled`/`Hidden`. Steps: collect `uiState`. Expected: first `Loading`, then `Content` whose sections contain only `Available`+`Disabled` items (no `Hidden`); empty sections suppressed. Traces: AC-2, AC-4, AC-6.
- **TC-AND-067-09 — ViewModel: re-resolves on capability/flag emission.** Type: unit (JVM, Turbine). Target: `MoreViewModel`. Preconditions: a `Disabled` entry; capability flow then emits the granting capability. Steps: emit new capability snapshot. Expected: `uiState` re-emits `Content` with that entry now `Available`, without leaving the screen. Traces: AC-6.
- **TC-AND-067-10 — ViewModel: empty after gating → Empty.** Type: unit (JVM, Turbine). Target: `MoreViewModel`. Preconditions: every entry resolves to `Hidden`. Steps: collect `uiState`. Expected: terminal state `MoreUiState.Empty`. Traces: AC-7.
- **TC-AND-067-11 — Compose-UI: three availability states render correctly.** Type: Compose-UI (Emulator, `createAndroidComposeRule`). Target: `MoreScreen`/`MoreEntryCard`. Preconditions: stub state with one `Hidden`, one `Disabled`, one `Available` entry. Steps: assert tree. Expected: `Hidden` → `assertDoesNotExist`; `Disabled` → exists, `assertHasNoClickAction`, reason exposed via semantics; `Available` → exists, clickable. Traces: AC-2, AC-4, AC-5.
- **TC-AND-067-12 — Compose-UI/integration: Available tap navigates; Disabled tap does not.** Type: integration/Compose-UI (Emulator). Target: `MoreScreen` in a test `NavHost` with stub destinations. Preconditions: catalog with one `Available` and one `Disabled` entry whose routes are registered. Steps: tap each. Expected: `Available` invokes `onNavigate(route)` exactly once and lands on the stub destination; `Disabled` consumes the click as a no-op (no nav) and surfaces the reason. Traces: AC-3, AC-5.
- **TC-AND-067-13 — Offline / flaky-dev-host degradation (fail-closed).** Type: contract/MockWebServer (Emulator). Target: `CapabilityProvider` + `MoreAvailabilityResolver` via `MoreViewModel`. Preconditions: simulate the dev host `http://18.222.237.167:8000` unreachable / session refresh failing (MockWebServer returns connection drop or `401` with no successful refresh). Steps: render the hub. Expected: resolver uses last cached snapshot; entries requiring an unconfirmed capability resolve to `Disabled` (fail-closed), never silently `Available`; no crash; hub still renders ungated entries. Traces: AC-5, AC-6.
- **TC-AND-067-14 — Accessibility & touch targets.** Type: instrumented/e2e + manual (Emulator for automated semantics assertions; **Device** for real TalkBack pass). Target: `MoreScreen`. Preconditions: hub rendered with `Available`/`Disabled` entries and (separately) the empty state. Steps: (a) automated — assert each card `contentDescription` combines label + state, `Disabled` cards set `semantics { disabled() }` and are excluded from click semantics, touch targets ≥ 48dp, traversal order = declared order; (b) manual on the physical A15 (API 34, arm64) — enable TalkBack, swipe through, confirm `Available`/`Disabled`/empty are announced correctly and color is not the only disabled signal. Expected: all semantics/target assertions pass on both targets. Traces: AC-8, AC-5, AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (More destination in nav graph, reachable) | TC-AND-067-12 (nav into registered destinations; route plumbing exercised) |
| AC-2 (responsive grid grouped into sections, icon+label) | TC-AND-067-08, TC-AND-067-11 |
| AC-3 (Available tap → existing registered destination) | TC-AND-067-01, TC-AND-067-07, TC-AND-067-12 |
| AC-4 (unregistered/flag-off → not present in UI) | TC-AND-067-02, TC-AND-067-03, TC-AND-067-05, TC-AND-067-07, TC-AND-067-08 |
| AC-5 (missing capability → Disabled, non-clickable, reason, no nav) | TC-AND-067-04, TC-AND-067-06, TC-AND-067-11, TC-AND-067-12, TC-AND-067-13, TC-AND-067-14 |
| AC-6 (re-resolves on input change without leaving screen) | TC-AND-067-08, TC-AND-067-09, TC-AND-067-13 |
| AC-7 (zero visible entries → neutral empty state) | TC-AND-067-10, TC-AND-067-14 |
| AC-8 (localized strings, 48dp targets, correct a11y semantics) | TC-AND-067-14 |
