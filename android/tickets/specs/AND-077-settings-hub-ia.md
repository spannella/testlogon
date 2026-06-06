---
id: AND-077
title: Settings hub IA
milestone: M2
epic: E11
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-024]
blocks: [AND-079, AND-080, AND-081, AND-082, AND-083, AND-088]
---

# AND-077 — Settings hub IA

## 1. Overview & Goal

This ticket delivers the **Settings hub** — the information architecture (IA) and
navigation landing screen that is the single entry point for all user-configurable
settings in the TestLogon Android app. The hub presents a Material 3 list of
**six sections** — Account, Security, Notifications, Media, Appearance, and Privacy —
and routes the user to the corresponding subsection destination when a row is tapped.

The scope of AND-077 is deliberately narrow: it owns the **landing screen, the section
catalog, the navigation routes, and the availability gating** that wires the hub into
the authenticated nav graph (`AND-024`). It does **not** own the subsection screens
themselves, their data layers, or any preferences read/write. Each subsection is a
separate downstream ticket (Media → `AND-079`, Notifications → `AND-080`/`AND-088`,
Appearance → `AND-081`, Account → `AND-082`); some of those subsections may not yet
exist when this hub ships, so the hub must render gracefully with placeholder/disabled
rows for not-yet-implemented destinations.

**Goal:** A user reaching the Settings hub sees the six sections, and tapping any
*available* section navigates to its subsection destination; *unavailable* sections are
visibly disabled (not crashing, not dead-linking). This is the structural backbone that
the entire E11 (Settings & Preferences) epic hangs off of, hence **P0**.

## 2. Context & References

- **Epic:** E11 — Settings & Preferences. **Milestone:** M2.
- **Backlog source:** `Type: Feature · Priority: P0 · Deps: AND-024`. Scope:
  "Settings landing with sections (account, security, notifications, media,
  appearance, privacy)." Acceptance: "Hub navigates to each subsection."
- **Upstream dependency — `AND-024` (Authenticated nav graph + bottom-nav skeleton):**
  the Settings hub is an authenticated destination reached from the bottom-nav /
  "More" surface. This ticket registers the hub route inside that graph.
- **Sibling pattern — `AND-067` ("More" hub / feature directory):** same IA pattern
  (a gated directory of destinations). Reuse the availability-gating approach and the
  row composables from `AND-067` where practical; the Settings hub is effectively a
  curated, fixed-catalog cousin of the More hub.
- **Downstream owners of subsections (each provides its own route + screen):**
  - Account → `AND-082` (sessions link, account status, privacy/data-export entry).
  - Notifications → `AND-080` (notification preferences UI) and `AND-088` (alert prefs).
  - Media → `AND-079` (`/ui/media/preferences`).
  - Appearance → `AND-081` (theme / dynamic color).
  - Security → handled via Account/E02 surfaces (sessions `AND-043`, server URL
    `AND-041`, MFA device management `AND-064`); the hub exposes a Security section
    that routes to a Security subsection screen owned downstream.
  - Privacy → entry surfaced here; data-export / closure handled in `AND-082` + E50.
- **Preferences data layer:** `AND-078` (Preferences API + DTOs). The hub does **not**
  call it; subsection screens do.
- **Reusable building blocks:** `AND-019` (Material 3 theme), `AND-021` (state
  composables: loading/empty/error/offline), `AND-022` (NavHost + routes),
  `core-ui` design system, `core-data` availability/feature-flag source.
- **Web reference:** `frontend/` settings (`src/api/endpoints/preferences.ts`, which calls
  `GET`/`PATCH /ui/settings/preferences`, and `src/pages/settings/SettingsPage.tsx`).
  **Correction (verified):** the web settings page is **not** a six-section hub with the
  same taxonomy — it is a single scrolling page of cards (Language, Appearance,
  Customization, Theme Customization, Account, Jira Integration). The six-section
  Account/Security/Notifications/Media/Appearance/Privacy IA is an **Android-specific**
  design from the backlog scope, not a web-parity mirror. Use the web only for
  per-feature naming hints (e.g. "Appearance"), not for the hub structure. See §16.
- **Package base:** `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **Hub screen.** A `SettingsHubScreen` composable renders a scrollable, grouped
list of the six sections in a fixed, deterministic order: Account, Security,
Notifications, Media, Appearance, Privacy.

FR-2. **Section rows.** Each row shows a leading icon, a localized title, an optional
one-line summary/subtitle, and a trailing chevron (for available rows). Rows are
`ListItem` (Material 3) clickable surfaces with a minimum 48 dp touch target.

FR-3. **Navigation.** Tapping an *available* row navigates to that section's route
within the authenticated nav graph via the shared `NavController`. Navigation is
performed by route constant, never by hard-coded string at the call site.

FR-4. **Availability gating.** Each section declares an availability predicate. Rows for
sections whose destination is not yet implemented (or is feature-flag-disabled) render
**disabled** (greyed, non-clickable, no chevron, optional "Coming soon" subtitle). The
hub never navigates to a non-existent route.

FR-5. **Stable section identity.** Sections are modeled by a sealed
`SettingsSection` type with a stable `key` (used for analytics, test tags, and the
nav route). Reordering or hiding a section must not require touching navigation code.

FR-6. **Back behavior.** The hub is a standard back-stack destination; system back from
the hub returns to the previous authenticated destination. Back from a subsection
returns to the hub.

FR-7. **Entry point.** The hub is reachable from the bottom-nav "More"/Settings affordance
defined in `AND-024`. The hub's own route is `settings`; subsection routes are nested
under it (e.g. `settings/account`).

FR-8. **No data fetch on hub.** The hub renders synchronously from a static section
catalog plus availability flags; it performs **no** network call. (Subtitles that
require live data, e.g. a session count, are deferred to subsection screens.)

## 4. Technical Design

**Module:** new `feature-settings` module under `android/feature/feature-settings`,
namespace `com.testlogon.android.feature.settings`. Layering: `feature-settings ->
core-ui, core-model, core-data`. No `core-network` dependency for this ticket.

**Section model (core-model or feature-local):**

```kotlin
package com.testlogon.android.feature.settings.model

enum class SettingsSectionKey { ACCOUNT, SECURITY, NOTIFICATIONS, MEDIA, APPEARANCE, PRIVACY }

data class SettingsSection(
    val key: SettingsSectionKey,
    @StringRes val titleRes: Int,
    @StringRes val subtitleRes: Int?,   // null when no static subtitle
    val icon: ImageVector,
    val route: String,                  // target route in the nav graph
    val available: Boolean,             // gated; false => disabled row
)
```

**Routes** (`feature-settings/navigation/SettingsRoutes.kt`):

```kotlin
object SettingsRoutes {
    const val HUB = "settings"
    const val ACCOUNT = "settings/account"
    const val SECURITY = "settings/security"
    const val NOTIFICATIONS = "settings/notifications"
    const val MEDIA = "settings/media"
    const val APPEARANCE = "settings/appearance"
    const val PRIVACY = "settings/privacy"
}
```

**Nav graph contribution** (called from the authenticated graph in `AND-024`):

```kotlin
fun NavGraphBuilder.settingsGraph(
    navController: NavController,
    onOpenSubsection: (String) -> Unit = { navController.navigate(it) },
) {
    composable(SettingsRoutes.HUB) {
        SettingsHubRoute(onOpenSection = onOpenSubsection)
    }
    // Subsection composable(...) destinations are registered by their owning tickets
    // (AND-079/080/081/082/088). This ticket registers placeholders only where a
    // route must resolve but no screen exists yet (see Availability gating).
}
```

**ViewModel** — minimal; exposes the catalog + availability as a `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class SettingsHubViewModel @Inject constructor(
    private val availability: SettingsAvailability,   // core-data feature-flag source
) : ViewModel() {

    data class UiState(val sections: List<SettingsSection> = emptyList())

    val uiState: StateFlow<UiState> =
        availability.flags()
            .map { flags -> UiState(sections = buildCatalog(flags)) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), UiState())

    private fun buildCatalog(flags: SettingsFlags): List<SettingsSection> = listOf(/* … */)
}
```

`SettingsAvailability` is a thin interface in `core-data` returning a
`Flow<SettingsFlags>`; the baseline implementation returns static `true` for sections
whose owning ticket is merged and `false` otherwise. This decouples the hub from
subsection delivery order.

**Screen / composables** (`feature-settings/ui/`):

```kotlin
@Composable fun SettingsHubRoute(
    onOpenSection: (String) -> Unit,
    viewModel: SettingsHubViewModel = hiltViewModel(),
)

@Composable fun SettingsHubScreen(
    state: SettingsHubViewModel.UiState,
    onOpenSection: (SettingsSection) -> Unit,
)

@Composable private fun SettingsSectionRow(
    section: SettingsSection,
    onClick: () -> Unit,
)
```

`SettingsHubScreen` is a `Scaffold` + `LazyColumn` of `SettingsSectionRow`s.
Disabled rows are non-clickable and rendered with reduced alpha. Test tags follow
`"settings_row_${section.key.name.lowercase()}"`.

## 5. API Contract

**N/A for this ticket.** The Settings hub performs no network I/O — it is pure IA and
navigation rendered from a static catalog plus local availability flags. The backend
preferences contract is owned by **`AND-078` (Preferences API + DTOs)** and consumed by
the subsection tickets. **Correction (verified against OpenAPI):** the relevant backend
endpoints are `GET /ui/settings/preferences` + `PATCH /ui/settings/preferences`
(UI prefs; the web client uses these), `GET /ui/media/preferences` +
**`PUT`** `/ui/media/preferences` (`MediaPreferencesOut`/`MediaPreferencesIn`), and
`GET`/`POST /ui/alerts/type-preferences` (`AlertTypePreferenceUpdate`). The draft's
`POST/GET /ui/media/preferences` was **wrong** on the write method (it is `PUT`, not
`POST`) and conflated media prefs with the generic settings prefs endpoint. These are
consumed by the subsection tickets
(`AND-079`, `AND-080`, `AND-086`, `AND-087`, `AND-088`). No `openapi.json` endpoints,
DTOs, or `ApiResult<T>` flows are introduced here.

The only "contract" this ticket defines is the **internal navigation contract**: the
route constants in `SettingsRoutes`. Downstream subsection tickets MUST register their
`composable(route)` against these exact constants so the hub's tap-to-navigate resolves.

## 6. Data & State Management

- **UiState:** `SettingsHubViewModel.UiState` holds only the resolved
  `List<SettingsSection>`. There is no loading/error state for the hub itself because no
  I/O occurs; the catalog is always available synchronously (worst case: an all-disabled
  list, which is still a valid render).
- **Availability source:** `SettingsAvailability` in `core-data`. For M2 baseline it may
  back onto a compile-time map or a `DataStore`-backed feature-flag store; either way it
  is a `Flow` so the hub re-renders if flags change at runtime. No Room cache is needed.
- **No persistence in this ticket.** Theme persistence (`AND-081`), preference
  persistence (`AND-078`), etc. live downstream. The hub is stateless across process
  death apart from normal nav back-stack restoration handled by Navigation-Compose.
- **State hoisting:** `SettingsHubScreen` is stateless (state in, callbacks out) for
  preview-ability and UI testing; `SettingsHubRoute` binds the ViewModel and
  `collectAsStateWithLifecycle()`.

## 7. Error Handling & Resilience

- **No network → no network errors.** The hub does not surface loading/error/offline
  states (`AND-021`) because it never fetches. This is intentional and keeps Settings
  reachable even when the unreliable dev backend (`http://18.222.237.167:8000`) is down —
  a user can always open Settings to fix the server URL (`AND-041`) or theme.
- **Unresolved route guard:** navigation is funneled through `onOpenSection`, which only
  fires for `available == true` rows. As defense-in-depth, the navigate call is wrapped
  so a missing destination logs a warning and no-ops instead of throwing
  `IllegalArgumentException` from Navigation-Compose.
- **Empty/partial catalog:** if every section is gated off, the hub shows the full list
  with all rows disabled (never a blank screen). At least Account and Appearance are
  expected to be available at M2 GA.

## 8. Security & Privacy

- The hub is an **authenticated-only** destination; it is registered inside the
  authenticated nav graph (`AND-024`) and is unreachable while logged out
  (auth-gated routing, `AND-025`).
- The hub displays **no PII** and stores nothing. Section titles/subtitles are static
  localized strings; no user data, tokens, cookies, or `ui_csrf` values are referenced.
- The **Privacy** and **Account** rows are entry points only; the actual privacy controls
  (data export, account closure/reactivation) and their strong-confirmation flows are
  owned by `AND-082` + E50 and are out of scope here.
- No new permissions, no logging of identifiers (see §10).

## 9. Accessibility & i18n

- All six section titles and any subtitles are externalized to `strings.xml`
  (`settings_section_account_title`, `..._security_title`, etc.) — no hard-coded UI text.
- Each row exposes a merged semantics node with a content description combining title +
  state ("Account, double tap to open" / "Notifications, coming soon, disabled").
- Disabled rows set `Modifier.semantics { disabled() }` so TalkBack announces them as
  unavailable and they are skipped by default focus where appropriate.
- Touch targets ≥ 48 dp; chevron is decorative (`contentDescription = null`).
- Layout uses Material 3 typography/`ListItem` and supports dynamic type scaling and RTL
  (icon leading position mirrors automatically). Contrast meets WCAG AA via the
  `AND-019` theme tokens; disabled rows still meet non-text contrast where feasible.

## 10. Telemetry & Logging

- Emit a screen-view event `settings_hub_viewed` on first composition of the route.
- On a section tap emit `settings_section_opened` with property `section_key` (the stable
  enum name, e.g. `MEDIA`) — a non-PII, low-cardinality value. Disabled taps are not
  navigations and emit nothing (rows are non-clickable).
- Routed through the shared analytics abstraction (the same redacted logging path
  established for auth, `AND-052`). No usernames, emails, tokens, cookies, CSRF values,
  or backend URLs are logged.
- Debug builds may `Timber.d` the resolved catalog size and availability flags; release
  builds log nothing for the hub.

## 11. Testing Strategy

**Unit (ViewModel):**
- `buildCatalog` returns exactly six sections in the fixed order Account → Security →
  Notifications → Media → Appearance → Privacy.
- Availability flags correctly map to each section's `available` field (flag on ⇒ enabled,
  flag off ⇒ disabled).
- `uiState` emits a non-empty catalog without any I/O (use a fake `SettingsAvailability`).

**Compose UI tests** (`feature-settings/src/androidTest`, `core-testing` harness):
- All six rows render with their localized titles (assert via test tags
  `settings_row_account` … `settings_row_privacy`).
- Tapping an *available* row invokes `onOpenSection` with the correct route constant
  (verify via a fake `NavController` / recorded callback). **This is the primary
  acceptance test** ("Hub navigates to each subsection").
- Tapping a *disabled* row does **not** invoke `onOpenSection` and the node is marked
  disabled in semantics.
- Accessibility: each row exposes a content description; disabled rows announce as such.

**Navigation integration test:** with stub subsection destinations registered, asserting
that selecting each available section changes the current route to the expected
`SettingsRoutes.*` value.

**Coverage target:** ViewModel + catalog logic ≥ 90%; screen interaction paths covered by
UI tests. Settings round-trip data tests are explicitly out of scope and owned by
`AND-083`.

## 12. Dependencies & Sequencing

- **Hard dependency:** `AND-024` (authenticated nav graph + bottom nav) — the hub must
  be registered inside it. Blocked until `AND-024` merges.
- **Soft/reuse:** `AND-019` (theme), `AND-021` (state composables, for parity), `AND-022`
  (NavHost), `AND-067` (More-hub gating pattern).
- **Blocks (these consume `SettingsRoutes` and the hub entry):** `AND-079` (Media prefs),
  `AND-080` (Notification prefs UI), `AND-081` (Appearance), `AND-082` (Account settings),
  `AND-088` (Alert prefs screen), and `AND-083` (Settings tests).
- **Sequencing note:** ship the hub with availability gating so subsection tickets can
  land in any order; flip each section's flag to `available = true` as its owning ticket
  merges. The hub itself does not depend on `AND-078`.

## 13. Risks & Open Questions

- **R1 — Section ↔ ticket mapping for "Security" and "Privacy":** the backlog lists six
  sections but only four have a clearly named owning subsection ticket
  (Account/Notifications/Media/Appearance). *Open question:* does Security route to a new
  dedicated screen, or aggregate existing E02 surfaces (sessions `AND-043`, server URL
  `AND-041`, MFA device mgmt `AND-064`)? Assumed: a thin Security subsection that links
  out to those. Privacy assumed to fold into `AND-082`/E50. **Confirm with PM.**
- **R2 — Availability source of truth:** is gating compile-time (module presence) or a
  runtime feature flag? Baseline assumes a `core-data` flag interface; if a remote flag
  service is mandated it becomes a dependency. **Open.**
- **R3 — Subtitle data:** some sections may want live subtitles (e.g. "3 active
  sessions"). Deferred to subsections to avoid a network call on the hub; revisit if PM
  wants live summaries on the landing screen.
- **R4 — Entry-point placement:** whether Settings is a top-level bottom-nav tab or lives
  under the "More" hub (`AND-067`) depends on `AND-024`'s final bottom-nav set. The hub
  route is agnostic to this.

## 14. Acceptance Criteria

- **AC-1 (backlog):** The Settings hub renders the six sections — Account, Security,
  Notifications, Media, Appearance, Privacy — in that order, each as a labeled row.
- **AC-2 (backlog):** Tapping an available section navigates to its subsection
  destination (asserted for every available route via UI/navigation tests).
- **AC-3:** Sections without an implemented destination render disabled (non-clickable,
  no navigation) and never crash or dead-link.
- **AC-4:** The hub performs no network request and is reachable even when the backend is
  unreachable.
- **AC-5:** The hub is authenticated-only and absent from the unauthenticated graph.
- **AC-6:** All section labels are localized; rows meet 48 dp targets and expose TalkBack
  semantics (including disabled state).
- **AC-7:** `settings_hub_viewed` and `settings_section_opened{section_key}` analytics fire
  with no PII; nothing sensitive is logged.
- **AC-8:** Unit + Compose UI tests for catalog order, navigation on tap, and disabled-tap
  no-op pass in CI.

## 15. Definition of Done

- `feature-settings` module created (`com.testlogon.android.feature.settings`), wired into
  the `app` module and the authenticated nav graph from `AND-024`.
- `SettingsRoutes`, `SettingsSection`/`SettingsSectionKey`, `SettingsHubViewModel`,
  `SettingsHubRoute`/`Screen`/`Row`, and `settingsGraph(...)` implemented per §4.
- Availability gating implemented via `core-data` `SettingsAvailability`; at least Account
  and Appearance available at merge, others gated until their tickets land.
- All strings externalized and localized; accessibility semantics verified with TalkBack.
- Analytics events emitted through the redacted logging path; no PII logged.
- Unit and Compose UI tests (per §11) written and green on the CI unit + headless
  instrumented pipelines (`AND-050`/`AND-051`).
- Lint/detekt/ktlint clean (`AND-005`); no new warnings; builds under JDK 17 / AGP 8.7.3 /
  Gradle 8.9 with `minSdk 24`, `compile/targetSdk 35`.
- Code reviewed and merged to `android-port`; downstream subsection tickets can register
  against `SettingsRoutes` without modifying the hub.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Claim:** The backend preferences write for media is `POST /ui/media/preferences`
   (§5 draft). **VERDICT: Corrected.** The actual endpoints are `GET /ui/media/preferences`
   (`resp 200: MediaPreferencesOut`) and `PUT /ui/media/preferences`
   (`req MediaPreferencesIn`, `resp 200: MediaPreferencesOut`). There is no `POST`.
   **Source:** OpenAPI index `GET /ui/media/preferences`
   (`op=ui_get_media_preferences_ui_media_preferences_get`) and
   `PUT /ui/media/preferences` (`op=ui_save_media_preferences_ui_media_preferences_put`).
2. **Claim:** The web client's preferences endpoint module backs the settings IA.
   **VERDICT: Corrected/clarified.** `src/api/endpoints/preferences.ts` calls
   `GET /ui/settings/preferences` (`getPreferences`, returns `{ preferences: UiPreferences }`)
   and `PATCH /ui/settings/preferences` (`patchPreferences`), plus
   `POST /ui/settings/validate-color` (`validateColor`). It does **not** call
   `/ui/media/preferences`. **Source:** `src/api/endpoints/preferences.ts: getPreferences`,
   `patchPreferences`, `validateColor`; OpenAPI index `GET /ui/settings/preferences`
   (`op=ui_get_preferences_...`) and `PATCH /ui/settings/preferences`
   (`op=ui_update_preferences_...`).
3. **Claim:** The web app has a six-section settings IA
   (Account/Security/Notifications/Media/Appearance/Privacy) with naming parity (§2 draft).
   **VERDICT: Corrected.** The web settings page is a single scrolling page of cards:
   Language, Appearance, Customization, Theme Customization, Account, Jira Integration —
   not a six-row gated hub. The six-section taxonomy is an Android-specific design taken
   from the AND-077 backlog scope. **Source:** `src/pages/settings/SettingsPage.tsx`
   (Card sections enumerated lines 21-72); backlog `specs-src/AND-077.md` Scope line.
4. **Claim:** This ticket performs no network I/O and introduces no endpoints/DTOs
   (§5, §8, FR-8, AC-4). **VERDICT: Verified (by design/scope).** Nothing in the ticket
   calls the API; consistent with backlog Acceptance "Hub navigates to each subsection."
   **Source:** `specs-src/AND-077.md`; no endpoint cross-reference required. The web
   transport (Bearer + `ui_csrf`) is therefore out of scope here but is documented in
   claim 5 for the downstream subsection tickets that will fetch.
5. **Claim (§8):** The app uses `ui_csrf` cookie / no CSRF values are referenced by the hub.
   **VERDICT: Verified.** The web client reads the `ui_csrf` cookie and sends it as the
   `X-CSRF-Token` request header; auth is `Authorization: Bearer <accessToken>`; a 401
   triggers one `POST /ui/session/refresh`; a fetch failure throws `ApiError(0, "Network
   error")`. The hub itself references none of these (correct). **Source:**
   `src/api/client.ts` (lines 135-189: `getCookie("ui_csrf")` -> `X-CSRF-Token`;
   `refreshSession` -> `POST /ui/session/refresh`; offline -> `ApiError(0, ...)`).
6. **Claim:** Settings is an authenticated-only destination registered in the
   authenticated nav graph (`AND-024`), unreachable logged-out (§8, AC-5).
   **VERDICT: Unverified-assumption.** `AND-024`/`AND-025` are sibling Android tickets,
   not present in the authoritative backend/frontend sources; the auth-gating contract
   cannot be confirmed here. Plausible and consistent with the web (which gates on
   `useAuthStore.isAuthenticated`), but treat as a cross-ticket dependency assumption.
   **Source:** none authoritative; cf. `src/api/client.ts: useAuthStore` for the web's
   auth-state notion only.
7. **Claim:** The unreliable dev backend is `http://18.222.237.167:8000` (§7).
   **VERDICT: Unverified-assumption.** The frontend resolves its base URL from the
   `VITE_API_BASE_URL` env var (`src/api/client.ts: API_BASE_URL`), not a hard-coded IP,
   so this host cannot be confirmed from source. It is an environment/infra detail.
   **Source:** `src/api/client.ts: API_BASE_URL` (env-driven); no literal IP in source.
8. **Claim:** Alert/notification preferences exist as a backend contract owned downstream
   (§2, §5). **VERDICT: Verified (endpoint exists).** `GET /ui/alerts/type-preferences`
   and `POST /ui/alerts/type-preferences` (`req AlertTypePreferenceUpdate`) are present.
   **Source:** OpenAPI index `GET`/`POST /ui/alerts/type-preferences`.
9. **Claim:** Real backend error shapes are `ErrorEnvelope`/`HTTPValidationError`.
   **VERDICT: Verified (for downstream use).** Preferences endpoints declare
   `422: HTTPValidationError`; `ErrorEnvelope` wraps a single `error: ErrorDetail`
   (used by other endpoints, e.g. jira prefs returning `400/401/.../502: ErrorEnvelope`).
   **Source:** OpenAPI index lines for `/ui/*/preferences`;
   `components.schemas.ErrorEnvelope` (`pretty.json` ~line 31777, `required: [error]`),
   `components.schemas.HTTPValidationError` (~line 37133).
10. **Claim:** Framework choices — Jetpack Compose Material 3 `ListItem`, Navigation-Compose
    route constants, Hilt `@HiltViewModel`, `StateFlow`/`collectAsStateWithLifecycle`,
    `Modifier.semantics { disabled() }`, 48 dp touch targets (§4, §6, §9).
    **VERDICT: Unverified-assumption (framework ref).** Standard, current Android/Compose
    APIs and conventions; not verifiable against the backend/frontend sources.
    **Source (framework ref):** Compose Material 3 `ListItem`
    (https://developer.android.com/jetpack/compose/components/list),
    Navigation-Compose (https://developer.android.com/jetpack/compose/navigation),
    accessibility semantics (https://developer.android.com/jetpack/compose/accessibility),
    Material touch-target guidance
    (https://m3.material.io/foundations/designing/structure#touch-targets).
11. **Claim:** Toolchain — JDK 17 / AGP 8.7.3 / Gradle 8.9, `minSdk 24`,
    `compile/targetSdk 35` (§15). **VERDICT: Unverified-assumption (framework ref).**
    Cross-ticket build-config convention (`AND-005`); not in authoritative sources.
    AGP 8.7.x requires JDK 17 and pairs with Gradle 8.9+, which is internally consistent.
    **Source (framework ref):** AGP release notes
    (https://developer.android.com/build/releases/gradle-plugin).

### Corrections made

- **§ frontmatter:** `status: draft` -> `status: reviewed`; added `reviewed_on: 2026-06-06`.
- **§2 Web reference:** corrected the false "section naming parity" / six-section web IA
  claim; clarified the web is a single-page card layout and the six-section hub is an
  Android-specific design; pinned `preferences.ts` to `GET`/`PATCH /ui/settings/preferences`.
- **§5 API Contract:** corrected `POST/GET /ui/media/preferences` to the real
  `GET`/`PUT /ui/media/preferences` (`MediaPreferencesOut`/`MediaPreferencesIn`), and
  added the actual `GET`/`PATCH /ui/settings/preferences` and
  `GET`/`POST /ui/alerts/type-preferences` contracts for downstream context.

### Open assumptions

- **Auth-gating (claim 6):** the hub being authenticated-only depends on `AND-024`/`AND-025`,
  which are not in the authoritative sources — confirm when those tickets land.
- **Dev backend host (claim 7):** `18.222.237.167:8000` is env/infra config, not in source.
- **Section -> ticket mapping for Security & Privacy (existing R1):** unresolved in sources;
  remains a PM question.
- **Availability source of truth (existing R2):** compile-time vs runtime feature flag —
  not determinable from backend/frontend; an Android architecture decision.
- **Framework/toolchain (claims 10-11):** verified only against external Android docs, not
  the project's authoritative API sources.

## 17. Test Plan

Acceptance Criteria referenced are from §14 (AC-1 … AC-8). Test targets: JVM/Robolectric
(local, no device), emulator AVD `test35` (x86_64, API 35), or the physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is pure IA/navigation with no
camera/biometrics/push/WebRTC, so most cases are JVM or emulator; the physical device is
used only where real-device a11y (TalkBack) and ABI/API-level parity matter.

- **TC-AND-077-01 — Catalog order & size (happy path).**
  Type: unit (JVM). Target: JVM/Robolectric. Preconditions: fake `SettingsAvailability`
  emitting all-true flags. Steps: build `SettingsHubViewModel`, collect first `uiState`,
  read `sections`. Expected: exactly 6 sections in order Account, Security, Notifications,
  Media, Appearance, Privacy; each with non-null `titleRes`/`icon`/`route`. Traces: AC-1.
- **TC-AND-077-02 — Availability mapping.**
  Type: unit (JVM). Target: JVM. Preconditions: fake availability with a mixed flag set
  (e.g. Account=on, Media=off). Steps: collect `uiState`. Expected: each section's
  `available` equals its flag; flag-off rows have `available=false`. Traces: AC-3.
- **TC-AND-077-03 — No I/O on hub render.**
  Type: unit (JVM). Target: JVM. Preconditions: fake availability; a `core-network`/HTTP
  test double that fails if invoked. Steps: instantiate ViewModel + collect state.
  Expected: state emits synchronously; zero network calls; no `core-network` dependency
  on the classpath. Traces: AC-4, FR-8.
- **TC-AND-077-04 — Rows render with localized titles.**
  Type: Compose-UI (instrumented). Target: emulator `test35`. Preconditions: state with
  all 6 sections available. Steps: set `SettingsHubScreen`; assert nodes with test tags
  `settings_row_account` … `settings_row_privacy` exist and display their string-resource
  titles (not raw keys). Expected: all six rows visible with localized text. Traces: AC-1, AC-6.
- **TC-AND-077-05 — Tap available row navigates with correct route (primary acceptance).**
  Type: Compose-UI (instrumented). Target: emulator `test35`. Preconditions: recorded
  `onOpenSection` callback; all rows available. Steps: click each available row in turn.
  Expected: `onOpenSection` invoked once per tap with the matching `SettingsRoutes.*`
  constant (e.g. tapping Media -> `"settings/media"`). Traces: AC-2, AC-8.
- **TC-AND-077-06 — Navigation integration to real routes.**
  Type: integration (instrumented). Target: emulator `test35`. Preconditions: a NavHost
  with `settingsGraph(...)` plus stub `composable(route)` destinations for each section.
  Steps: from HUB, tap each available section. Expected: `navController.currentDestination.route`
  becomes the expected `SettingsRoutes.*`; system back returns to `settings`. Traces: AC-2, FR-6.
- **TC-AND-077-07 — Disabled row is a no-op.**
  Type: Compose-UI (instrumented). Target: emulator `test35`. Preconditions: state with at
  least one section `available=false` (e.g. Notifications). Steps: assert the row is
  `isNotEnabled()`; perform click. Expected: `onOpenSection` is never invoked; no chevron;
  no navigation/crash. Traces: AC-3, AC-8.
- **TC-AND-077-08 — Unresolved-route guard (defense-in-depth).**
  Type: unit (JVM). Target: JVM. Preconditions: navigate lambda wrapping a NavController
  whose graph lacks the target route. Steps: invoke the wrapped navigate for a missing
  destination. Expected: a warning is logged and the call no-ops; no
  `IllegalArgumentException` propagates. Traces: AC-3.
- **TC-AND-077-09 — All-gated catalog still renders (resilience / offline-equivalent).**
  Type: Compose-UI (instrumented). Target: emulator `test35`. Preconditions: availability
  source emits all-false (simulating subsections not yet shipped / flags off). Steps: render
  hub. Expected: six disabled rows shown; screen is reachable and non-blank; no spinner/error
  state. Traces: AC-3, AC-4.
- **TC-AND-077-10 — Hub reachable with backend down (no-network path).**
  Type: integration (instrumented). Target: emulator `test35` with networking disabled
  (airplane mode / no base URL). Preconditions: app authenticated locally; backend
  unreachable. Steps: navigate to `settings`. Expected: hub renders the catalog with no
  network attempt, no error toast, no crash. Traces: AC-4.
- **TC-AND-077-11 — Authenticated-only gating.**
  Type: integration (instrumented). Target: emulator `test35`. Preconditions: app in
  logged-out state. Steps: attempt to resolve/navigate to `settings`. Expected: route is
  absent from the unauthenticated graph / redirects to auth; hub does not display.
  (Depends on AND-024/AND-025 — see §16 open assumption 6.) Traces: AC-5.
- **TC-AND-077-12 — Analytics events, no PII.**
  Type: unit (JVM). Target: JVM. Preconditions: fake analytics sink. Steps: enter the route
  (compose) and tap an available section; for a disabled section, tap it. Expected:
  `settings_hub_viewed` fires once on first composition; `settings_section_opened` fires with
  `section_key` = stable enum name (e.g. `MEDIA`) only on available taps; disabled taps emit
  nothing; payloads contain no username/email/token/cookie/CSRF/URL. Traces: AC-7.
- **TC-AND-077-13 — Accessibility & touch targets (real TalkBack).**
  Type: instrumented/e2e (a11y). Target: **physical device** (SM-A156U) — TalkBack and real
  font-scale/RTL behavior should be validated on hardware, not just emulator. Preconditions:
  TalkBack enabled; one section disabled. Steps: navigate rows with TalkBack; inspect
  semantics. Expected: each row has a merged content description combining title + state
  ("Account, double tap to open" / "Notifications, coming soon, disabled"); disabled rows
  carry `disabled()` semantics; every row's touch target ≥ 48 dp; chevron is decorative
  (no content description). Traces: AC-6.
- **TC-AND-077-14 — ABI / API-level parity smoke.**
  Type: instrumented (smoke). Target: **physical device** (arm64-v8a, API 34) — complements
  the x86_64/API-35 emulator runs to catch ABI/API-level differences. Steps: launch app,
  open `settings`, render and tap one available row. Expected: identical catalog order,
  rendering, and navigation behavior as on `test35`; no ABI/resource crashes. Traces: AC-1, AC-2.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (six sections, fixed order) | TC-01, TC-04, TC-14 |
| AC-2 (tap available navigates) | TC-05, TC-06, TC-14 |
| AC-3 (disabled rows no-op, no dead-link/crash) | TC-02, TC-07, TC-08, TC-09 |
| AC-4 (no network, reachable when backend down) | TC-03, TC-09, TC-10 |
| AC-5 (authenticated-only) | TC-11 |
| AC-6 (localized, 48 dp, TalkBack semantics) | TC-04, TC-13 |
| AC-7 (analytics, no PII) | TC-12 |
| AC-8 (unit + Compose tests for order/nav/disabled-tap pass in CI) | TC-01, TC-05, TC-07 |
