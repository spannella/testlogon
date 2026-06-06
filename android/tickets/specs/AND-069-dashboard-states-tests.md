---
id: AND-069
title: Dashboard states + tests
milestone: M2
epic: E09
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-066, AND-068]
blocks: []
---

# AND-069 — Dashboard states + tests

## 1. Overview & Goal

The Dashboard feature (`feature-dashboard`) exposes a single `StateFlow<DashboardUiState>` from `DashboardViewModel` (AND-068) and renders it through `DashboardScreen` plus its widget composables (AND-066). Those two tickets establish the happy path: real widgets/cards, quick links, and pull-to-refresh against live backend data. This ticket completes the feature by making every *non-happy* surface a first-class, fully rendered, testable state, and by locking those surfaces down with instrumented Compose UI tests that run headlessly in CI.

Concretely, AND-069 delivers:

1. Three reusable, polished state composables — **empty**, **error**, and **offline** — wired into `DashboardScreen` so the screen always shows a coherent surface for every value of `DashboardUiState`.
2. A headless Compose UI test suite (`DashboardScreenTest`) that drives each state via a fake `DashboardViewModel`/state and asserts the correct composable, copy, and affordances render, including the retry/refresh interaction path.

The goal is *completeness and verifiability of the dashboard's visual states*, not new data flows. No new endpoints, no new ViewModel logic beyond what AND-068 already exposes (we consume its state contract; we may add a `retry()`/`refresh()` invocation hook if not already present, but the state machine itself is owned by AND-068).

## 2. Context & References

- Repo `spannella/testlogon`, monorepo Android app under `android/`, branch `android-port`.
- Module: `feature-dashboard` (depends on `core-ui`, `core-model`, `core-data`, `core-testing`). Package root `com.testlogon.android.feature.dashboard`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow, single-Activity Navigation-Compose. compileSdk/targetSdk 35, minSdk 24, JDK 17, AGP 8.7.3, Gradle 8.9.
- **AND-066 — Dashboard screen + widgets** (P0): owns `DashboardScreen`, widget/card composables, quick links, pull-to-refresh container. This ticket *adds branches* into that screen's `when (state)` and *adds* the three state composables; it must not regress the loaded path.
- **AND-068 — Dashboard ViewModel + state** (P0): owns `DashboardViewModel` and the sealed `DashboardUiState` contract (loading / loaded / error / offline) plus `refresh` events. State *transitions* are unit-tested there; this ticket tests *rendering* of those states.
- `core-ui` provides shared error/empty scaffolding primitives (`AppScaffold`, theme, `Strings`/`stringResource` plumbing) and design tokens. `core-testing` provides Compose test rules, fake dispatchers, and shared fakes.
- Backend (FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`) is unreliable; the offline/stale states this ticket renders are the user-facing consequence of the ~20s timeout + bounded-retry policy defined in `core-network`. No direct network calls occur in this ticket's tests — all backend interaction is faked.

## 3. Functional Requirements

FR-1. For every value of `DashboardUiState`, `DashboardScreen` renders exactly one primary surface and never an indeterminate/blank screen.

FR-2. **Empty state** — when the dashboard loads successfully but contains no widgets/cards to show (`Loaded` with an empty content set), render `DashboardEmptyState`: an illustration/icon, a headline, a supporting line, and a primary "Refresh" action that invokes `onRefresh`.

FR-3. **Error state** — when loading fails with a non-connectivity error (`Error`), render `DashboardErrorState`: an error icon, a headline, the human-readable message derived from the FastAPI `detail` mapping, and a "Try again" action invoking `onRetry`. *(Verified shape: the web client's `normalizeErrorDetail` in `src/api/client.ts` handles `detail` as a `string`, an array of `{msg}` objects — the FastAPI `HTTPValidationError`/`ValidationError` 422 shape — or an object with a `code`/`required_scope` (authorization error). Android `core-network`/AND-068 must mirror these three branches; this ticket consumes the result as a pre-mapped `String`.)*

FR-4. **Offline state** — when the failure is connectivity-related (`Offline`, e.g. no network or transport timeout against the unreliable dev host), render `DashboardOfflineState`: an offline icon, offline-specific copy, an optional "showing cached data from <relative time>" stale banner when stale cache exists, and a "Retry" action invoking `onRetry`.

FR-5. **Stale-while-error** — if cached dashboard data exists, the error and offline states surface a non-blocking banner above the (still-rendered) cached content rather than fully replacing it. If no cache exists, the full-screen state composable is shown. (Whether `DashboardUiState` carries cached content alongside the error is owned by AND-068; this ticket renders both shapes — full-screen and banner-over-content — and selects based on whether content is present.)

FR-6. **Loading state** — render the existing loading affordance from AND-066 (skeleton/spinner). This ticket does not redefine it but the test suite asserts it appears.

FR-7. All three new state composables are **stateless and preview-able**: they take their copy/handlers as parameters, expose `@Preview`s, and are independently testable without a ViewModel.

FR-8. The UI test suite runs **headlessly** (no manual interaction, no real device features) and passes in CI on an emulator via `connectedAndroidTest`, plus any Robolectric-eligible portions via `testDebugUnitTest`.

## 4. Technical Design

State composables live in `feature-dashboard/src/main/java/com/testlogon/android/feature/dashboard/states/`.

```kotlin
package com.testlogon.android.feature.dashboard.states

@Composable
fun DashboardEmptyState(
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
)

@Composable
fun DashboardErrorState(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)

@Composable
fun DashboardOfflineState(
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    staleAsOf: String? = null, // pre-formatted relative time, null when no cache
)

// Non-blocking banner reused for stale-while-error (FR-5)
@Composable
fun DashboardStaleBanner(
    text: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)
```

These share a private `DashboardStateScaffold(icon, headline, body, action)` to keep spacing/typography consistent and to centralize test tags. All visible copy is sourced from string resources via `core-ui`.

`DashboardScreen` (AND-066) gains an exhaustive `when` over the state contract from AND-068:

```kotlin
@Composable
fun DashboardScreen(
    state: DashboardUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onQuickLink: (QuickLinkId) -> Unit,
    modifier: Modifier = Modifier,
) {
    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh) {
        when (state) {
            is DashboardUiState.Loading -> DashboardLoading()                 // AND-066
            is DashboardUiState.Loaded ->
                if (state.widgets.isEmpty()) DashboardEmptyState(onRefresh)
                else DashboardContent(state, onQuickLink)                     // AND-066
            is DashboardUiState.Error ->
                state.cached?.let { c -> ContentWithBanner(c, error = true, onRetry, onQuickLink) }
                    ?: DashboardErrorState(state.message, onRetry)
            is DashboardUiState.Offline ->
                state.cached?.let { c -> ContentWithBanner(c, error = false, onRetry, onQuickLink, state.staleAsOf) }
                    ?: DashboardOfflineState(onRetry, staleAsOf = state.staleAsOf)
        }
    }
}
```

The route-level `DashboardRoute(viewModel: DashboardViewModel = hiltViewModel())` collects state with `collectAsStateWithLifecycle()` and forwards `viewModel::refresh` / `viewModel::retry`. If AND-068 exposed only `refresh()`, `retry()` maps to `refresh(force = true)`; no new state logic is introduced.

**Test tags.** Each state composable applies a stable `Modifier.testTag(...)` on its root and on its action button, defined as constants in `DashboardTestTags` so production and test agree:

```kotlin
object DashboardTestTags {
    const val LOADING = "dashboard_loading"
    const val CONTENT = "dashboard_content"
    const val EMPTY = "dashboard_empty"
    const val ERROR = "dashboard_error"
    const val OFFLINE = "dashboard_offline"
    const val STALE_BANNER = "dashboard_stale_banner"
    const val RETRY_ACTION = "dashboard_retry"
    const val REFRESH_ACTION = "dashboard_refresh"
}
```

**Test harness.** Tests drive `DashboardScreen` directly with hand-built `DashboardUiState` values plus lambda spies — they do not require Hilt or a real ViewModel, which keeps them deterministic and headless. A thin `FakeDashboardStateFactory` in the test source produces canonical instances of each state.

## 5. API Contract

N/A for this ticket. No HTTP endpoints are introduced or consumed directly. The dashboard's data fetch and its endpoints, timeout, and retry policy are owned by AND-066/AND-068 and `core-network`. For reference (verified against OpenAPI and the web client), the underlying surface those tickets own is: `GET /ui/dashboard/summary` (op `dashboard_summary_ui_dashboard_summary_get`; web client `getDashboardSummary` → `DashboardSummary`) for the data fetch, and `POST /ui/dashboard/refresh` (op `dashboard_refresh_ui_dashboard_refresh_post`; web client `refreshDashboard`) for the force-refresh action. Note the `GET` is the *idempotent* read referenced by the retry policy in §7; `POST /ui/dashboard/refresh` is **not** idempotent and is therefore *not* part of the auto-retry path — only the user-initiated refresh button triggers it. Auth/CSRF for those calls (cookie session + `X-CSRF-Token` echoed from the `ui_csrf` cookie) is owned by `core-network` (see §8). The FastAPI `detail` error mapping referenced in FR-3 is consumed only as an already-mapped `String` carried in `DashboardUiState.Error.message`; the mapping itself is owned by `core-network`/AND-068. The OpenAPI surface (`/openapi.json`) is not exercised by this ticket's tests.

## 6. Data & State Management

This ticket consumes, and must remain exhaustive over, the `DashboardUiState` contract from AND-068. The shape it depends on:

```kotlin
sealed interface DashboardUiState {
    val isRefreshing: Boolean

    data class Loading(override val isRefreshing: Boolean = false) : DashboardUiState
    data class Loaded(
        val widgets: List<DashboardWidget>,
        val quickLinks: List<QuickLink>,
        override val isRefreshing: Boolean = false,
    ) : DashboardUiState
    data class Error(
        val message: String,
        val cached: DashboardContent? = null,
        override val isRefreshing: Boolean = false,
    ) : DashboardUiState
    data class Offline(
        val cached: DashboardContent? = null,
        val staleAsOf: String? = null,
        override val isRefreshing: Boolean = false,
    ) : DashboardUiState
}
```

If AND-068's final shape differs (e.g., `cached`/`staleAsOf` not present), this ticket adapts the `when` accordingly and degrades FR-5 to full-screen-only; the empty/error/offline rendering and tests remain mandatory. No new persistence is added — stale data originates from the Room cache wired by `core-data`/AND-066. The state composables are pure functions of their parameters and hold no internal state beyond transient Compose UI state (e.g., button press ripples).

## 7. Error Handling & Resilience

- **Message safety**: `DashboardErrorState` never displays a raw exception, stack trace, or null. If `message` is blank, it falls back to a generic localized "Something went wrong" string.
- **Connectivity classification**: the split between `Error` (FR-3) and `Offline` (FR-4) is made upstream in AND-068 (transport/timeout/`UnknownHost` → `Offline`; HTTP/parse/4xx-5xx → `Error`). This ticket renders whichever it is given and must handle both even if upstream misclassifies (no crash, no blank).
- **Retry idempotency**: automatic backoff retry applies only to the idempotent `GET /ui/dashboard/summary`, consistent with the project rule that backoff retry applies to idempotent GETs only. The user-initiated force-refresh maps to `POST /ui/dashboard/refresh`, which is **not** idempotent and therefore must **not** be auto-retried on transport failure — it is only re-issued by an explicit user tap. The action lambdas are debounced by disabling the button while `isRefreshing` is true to avoid duplicate in-flight requests (the web client does the same: its Refresh button is `disabled` while the refresh mutation `isPending` — `src/pages/dashboard/CreatorDashboard.tsx`).
- **Stale data**: when cache exists, the offline/error banner keeps content visible (FR-5), satisfying the "offline/stale UI states" project requirement for the unreliable dev host.

## 8. Security & Privacy

No new auth, tokens, cookies, or PII handling. The dashboard relies on the existing cookie-based session (verified in `src/api/client.ts`: `credentials: "include"` cookie jar plus a `X-CSRF-Token` header echoed from the `ui_csrf` cookie, and an `Authorization: Bearer` token from the auth store) established elsewhere; this ticket does not touch session or refresh logic. Error copy must not leak server internals: the `detail` mapping is already sanitized upstream, and `DashboardErrorState` displays only user-appropriate text — no headers, cookies, URLs, or raw `detail` objects are rendered. No data is logged from these composables beyond the telemetry in section 10.

## 9. Accessibility & i18n

- All copy in the three state composables and the stale banner comes from string resources; no hardcoded user-facing strings. Pseudolocale (`en-XA`) renders without truncation/clipping.
- Each state root carries a `Modifier.semantics { }` with a meaningful `contentDescription`/role; decorative icons set `contentDescription = null`. Action buttons have descriptive labels ("Try again", "Retry", "Refresh") usable by TalkBack.
- Minimum touch target 48dp for all actions; text scales to 200% font without overflow (verified by a large-font test variant).
- The stale banner is announced as a `liveRegion` (polite) so TalkBack users learn data is stale without focus theft.
- Color is not the sole signal for error vs offline — each uses a distinct icon + text.

## 10. Telemetry & Logging

- Emit one analytics event per non-loaded state shown: `dashboard_state_shown` with `state` ∈ {`empty`,`error`,`offline`} and `has_cache: Boolean`, fired once per entry into the state (not on recomposition) via `LaunchedEffect(state::class)`.
- Emit `dashboard_retry_tapped` with `from_state` on retry/refresh from a non-loaded state.
- Logging uses the project's tagged logger at `DEBUG`; no PII, no message bodies. Telemetry interface is injected where the route is composed; the stateless composables themselves do not log (they invoke parameter lambdas). If the analytics facade is not yet available in `feature-dashboard`, gate behind a no-op `DashboardAnalytics` interface defined here and implemented later.

## 11. Testing Strategy

Primary deliverable. Tests live in `feature-dashboard/src/androidTest/java/.../DashboardScreenTest.kt` (instrumented Compose) with a Robolectric-runnable mirror in `src/test/...` where feasible, both using `createComposeRule()`.

Cases:

1. `loading_showsLoadingAffordance` — `Loading` → `LOADING` tag asserted displayed.
2. `loaded_nonEmpty_showsContent` — `Loaded(widgets=[..])` → `CONTENT` displayed; no empty/error/offline tags.
3. `loaded_empty_showsEmptyState` — `Loaded(widgets=[])` → `EMPTY` displayed with headline text and `REFRESH_ACTION`.
4. `empty_refreshTap_invokesOnRefresh` — click `REFRESH_ACTION`; spy lambda invoked exactly once.
5. `error_noCache_showsErrorWithMessage` — `Error("Service unavailable")` → `ERROR` displayed and the exact message asserted.
6. `error_blankMessage_showsFallbackCopy` — `Error("")` → generic fallback string asserted.
7. `error_retryTap_invokesOnRetry` — click `RETRY_ACTION`; spy invoked once.
8. `offline_noCache_showsOfflineState` — `Offline()` → `OFFLINE` displayed.
9. `offline_withCache_showsContentPlusStaleBanner` — `Offline(cached=..., staleAsOf="2 min ago")` → `CONTENT` and `STALE_BANNER` both displayed; banner text contains the relative time.
10. `error_withCache_showsContentPlusBanner` — analogous to (9) for `Error`.
11. `staleBanner_retryTap_invokesOnRetry`.
12. `refreshing_disablesAction` — `isRefreshing=true` → action node `assertIsNotEnabled()`.
13. `largeFont_noCrash` — render each state with `fontScale = 2f`; assert root still displayed.
14. `eachState_hasContentDescription` — semantics assertion per state.

CI: tests must pass headlessly via Gradle managed devices / emulator (`./gradlew :feature-dashboard:connectedDebugAndroidTest` or the project's managed-device task) and via `:feature-dashboard:testDebugUnitTest` for the Robolectric mirror. Flakiness budget: zero — no real network, no `Thread.sleep`; use `composeRule.mainClock`/`waitForIdle`. Lambda spies implemented with simple counters (no MockK needed) to keep the suite hermetic.

## 12. Dependencies & Sequencing

- **Blocked by AND-066** (Dashboard screen + widgets): provides `DashboardScreen`, `DashboardContent`, loading affordance, quick links, pull-to-refresh container that this ticket branches into.
- **Blocked by AND-068** (Dashboard ViewModel + state): provides the `DashboardUiState` sealed contract this ticket must exhaustively render and test.
- Consumes `core-ui` (scaffold, theme, string plumbing) and `core-testing` (Compose test rules, fakes).
- **Blocks**: none recorded in backlog. It is a quality gate completing E09 dashboard in M2; downstream dashboard polish/feature tickets should not merge over a red `DashboardScreenTest`.
- Sequencing: start once AND-068's `DashboardUiState` shape is merged (or stable on `android-port`) to avoid `when`-branch churn; the stateless composables (FR-2..FR-4, FR-7) can be built and preview-tested in parallel beforehand.

## 13. Risks & Open Questions

- **State contract drift**: if AND-068 ships a different sealed shape (e.g., merges `Offline` into `Error` with a flag, or omits `cached`/`staleAsOf`), the `when` and FR-5 must be reconciled. Mitigation: depend on the merged contract; keep stale-banner rendering behind a content-present check so it degrades gracefully.
- **Emulator availability in CI**: instrumented tests need an emulator/managed device; if CI lacks one, the Robolectric mirror must cover the assertions. Open question: does the `android-port` CI already run `connectedAndroidTest`, or only unit tests? Confirm with infra before relying solely on instrumented coverage.
- **Empty-state definition**: "empty" must be defined precisely (no widgets vs. all widgets failed-to-load). Assumed: `Loaded` with zero renderable widgets. Confirm with AND-066/AND-068 owners.
- **Stale time formatting**: relative-time string ("2 min ago") formatting ownership — assumed pre-formatted by AND-068 into `staleAsOf`; if not, this ticket adds a small formatter in `core-ui`.
- **Analytics facade**: may not yet exist in `feature-dashboard`; mitigated by the no-op interface in section 10.

## 14. Acceptance Criteria

AC-1. All four runtime states render a coherent, non-blank surface: loading, loaded-non-empty (content), loaded-empty (`DashboardEmptyState`), error (`DashboardErrorState`), and offline (`DashboardOfflineState`). (Maps to source acceptance "All states render".)

AC-2. `DashboardErrorState` displays the mapped `detail` message, and falls back to a generic localized string when the message is blank.

AC-3. When cached content is present, error and offline render the cached content plus a non-blocking `DashboardStaleBanner` instead of a full-screen state.

AC-4. Empty/error/offline/banner actions invoke `onRefresh`/`onRetry` exactly once per tap and are disabled while `isRefreshing`.

AC-5. The `when (state)` over `DashboardUiState` is exhaustive (compiles without an `else`), guaranteeing no unhandled state.

AC-6. `DashboardScreenTest` covers all cases in section 11 and **passes headlessly** in CI (instrumented and/or Robolectric mirror) with no flakiness and no real network. (Maps to source acceptance "UI test passes headlessly".)

AC-7. Each new state composable has at least one `@Preview` and a stable `testTag`; all user-facing copy is from string resources and renders under pseudolocale and `fontScale = 2f`.

## 15. Definition of Done

- `DashboardEmptyState`, `DashboardErrorState`, `DashboardOfflineState`, and `DashboardStaleBanner` implemented under `com.testlogon.android.feature.dashboard.states`, stateless, with previews and test tags.
- `DashboardScreen` updated with an exhaustive `when` wiring all states; loaded happy path from AND-066 unchanged/non-regressed.
- `DashboardScreenTest` (and Robolectric mirror where applicable) implemented and green locally and in CI headlessly; zero flaky retries needed.
- All copy externalized to string resources; accessibility (content descriptions, 48dp targets, live-region banner, 200% font) verified.
- Telemetry events `dashboard_state_shown` and `dashboard_retry_tapped` emitted once per state entry / tap, with no PII.
- `./gradlew :feature-dashboard:lint :feature-dashboard:testDebugUnitTest` clean; instrumented suite passes on the managed device.
- Code reviewed and merged to `android-port`; depends-on tickets AND-066 and AND-068 referenced in the PR.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json` (`components.schemas.<Name>`), frontend `reference/src/...`, or Android framework docs.

1. **Dashboard data is fetched via `GET /ui/dashboard/summary`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/dashboard/summary` (op `dashboard_summary_ui_dashboard_summary_get`, resp `200` inline + `422:HTTPValidationError`); frontend `src/api/endpoints/dashboard.ts: getDashboardSummary` → `api.get<DashboardSummary>("/ui/dashboard/summary")`.
2. **The summary response shape (`DashboardSummary`).** VERDICT: Verified. SOURCE: `src/api/types.ts: DashboardSummary` (fields `today_earnings_cents`, `earnings_breakdown`, `period_views`, `period_revenue_cents`, `total_subscribers`, `top_content`, `active_broadcasts`, `recent_milestones`, `currency`, `generated_at`, `warnings: string[]`). Note: OpenAPI declares the `200` body inline (no named schema), but the web client types it as `DashboardSummary`; the field list above is from the frontend DTO.
3. **Force-refresh is `POST /ui/dashboard/refresh`.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/dashboard/refresh` (op `dashboard_refresh_ui_dashboard_refresh_post`, resp `200` inline + `422:HTTPValidationError`); frontend `src/api/endpoints/dashboard.ts: refreshDashboard` → `api.post<{ ok; message; refreshed_at }>("/ui/dashboard/refresh")`.
4. **`POST /ui/dashboard/refresh` is not idempotent and is excluded from auto-retry; only the GET is auto-retried (§7).** VERDICT: Verified (method semantics) / Corrected in §7. SOURCE: OpenAPI methods above (POST vs GET). The original §7 wording implied "retry/refresh re-issues the GET"; corrected to distinguish the idempotent GET (auto-retry eligible) from the non-idempotent refresh POST (user-tap only).
5. **FastAPI error `detail` is mapped from one of: a `string`, an array of `{msg}` objects, or an object carrying a `code`/`required_scope` (FR-3).** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` (handles `typeof detail === "string"`, `Array.isArray(detail)` mapping `msg`, and `mapAuthorizationError` reading `detail.code`/`detail.required_scope`). The array-of-`{msg}` form is the FastAPI 422 shape: OpenAPI `components.schemas.HTTPValidationError` = `{ detail: ValidationError[] }`, and `ValidationError` carries `loc`/`msg`/`type`.
6. **Auth/CSRF transport: cookie session + `X-CSRF-Token` header echoed from a cookie + `Authorization: Bearer` (§8).** VERDICT: Verified, with the cookie name corrected/anchored. SOURCE: `src/api/client.ts` — `credentials: "include"`; `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `Authorization: Bearer ${accessToken}`. The cookie is specifically named `ui_csrf`.
7. **A pure network/transport failure surfaces distinctly from an HTTP error (basis for the Android `Offline` vs `Error` split, §7/FR-3/FR-4).** VERDICT: Verified (web analog). SOURCE: `src/api/client.ts` — the `fetch` `catch` branch throws `new ApiError(0, "Network error", err)` (status `0`) for offline/DNS failures, separate from HTTP `4xx/5xx` paths. This supports the upstream classification AND-068 performs; the exact Kotlin classifier (`UnknownHost`/timeout → `Offline`) is owned by AND-068/`core-network`.
8. **Web client disables the Refresh action while a refresh is in flight (basis for AC-4 "disabled while `isRefreshing`").** VERDICT: Verified. SOURCE: `src/pages/dashboard/CreatorDashboard.tsx` — Refresh `<button ... disabled={refreshMut.isPending}>`, label toggles to "Refreshing...".
9. **Web client renders a loading branch for the dashboard summary.** VERDICT: Verified. SOURCE: `src/pages/dashboard/CreatorDashboard.tsx` — `const { data: summary, isLoading } = useQuery(...)` with an `if (isLoading) { ... }` early return; corroborates FR-6/AC-1 loading surface.
10. **The web client has no dedicated empty/error/offline composable for this screen (the three Android state composables are net-new UI).** VERDICT: Verified (absence). SOURCE: `src/pages/dashboard/CreatorDashboard.tsx` shows only an `isLoading` branch and inline widgets; no offline/empty/error screen-level surface. The Android empty/error/offline UX is therefore a new design, not a port of an existing web surface (see Open assumptions).
11. **Dev backend is unreliable at `http://18.222.237.167:8000` with a ~20s timeout + bounded retry (§2).** VERDICT: Unverified-assumption. SOURCE: not derivable from OpenAPI or frontend (timeout/host policy lives in `core-network`, AND-066/AND-068). Treated as a project-context assumption.
12. **`DashboardUiState` sealed contract (Loading/Loaded/Error/Offline with `cached`/`staleAsOf`), §6.** VERDICT: Unverified-assumption (owned by AND-068, not in these sources). SOURCE: AND-068 (not present in `reference/`). The spec already flags this as adaptable in §6/§13.
13. **Compose UI test stack (`createComposeRule()`, test tags, semantics, `connectedAndroidTest`, Robolectric mirror).** VERDICT: Verified (framework ref). SOURCE: Android framework refs — Compose testing `https://developer.android.com/develop/ui/compose/testing`; managed/connected device tests `https://developer.android.com/studio/test/gradle-managed-devices`; Robolectric `https://robolectric.org`.
14. **Accessibility expectations: 48dp min touch target, live region for the stale banner (§9).** VERDICT: Verified (framework ref). SOURCE: Material/Android a11y — touch target sizing `https://support.google.com/accessibility/android/answer/7101858`; Compose semantics/liveRegion `https://developer.android.com/develop/ui/compose/accessibility`.

### Corrections made

- **§7 retry idempotency** — clarified that only `GET /ui/dashboard/summary` is auto-retried; `POST /ui/dashboard/refresh` is non-idempotent and is re-issued only by an explicit user tap (was previously conflated as "retry/refresh re-issues the GET"). Added the verified web-client precedent for disabling the action while refreshing.
- **§5 API contract** — kept "N/A (no direct calls)" but anchored the *underlying* surface owned by AND-066/AND-068 to the verified endpoints/ops (`GET /ui/dashboard/summary`, `POST /ui/dashboard/refresh`) and noted the refresh POST is outside the auto-retry path. Previously the section listed no concrete endpoint names.
- **FR-3** — anchored the `detail` mapping to the verified three branches in `normalizeErrorDetail` and the FastAPI `HTTPValidationError`/`ValidationError` 422 shape (was an unsourced inline shorthand `string | [{msg}] | {code,...}`).
- **§8 CSRF** — anchored the CSRF mechanism to the exact verified details (cookie name `ui_csrf`, `X-CSRF-Token` header, `credentials: "include"`, `Authorization: Bearer`). The original claim was correct but unsourced.

### Open assumptions

- **`DashboardUiState` shape (claim 12)** — owned by AND-068, which is not in `reference/`; cannot be verified here. Risk already tracked in §13 (state-contract drift).
- **Dev-host unreliability / ~20s timeout / bounded-retry policy (claim 11)** — a `core-network` concern not present in the provided sources; accepted as project context.
- **Offline/empty/error UX design (claim 10)** — no web precedent exists, so the visual/copy design is net-new and not verifiable against the reference app; copy is owned by `core-ui` string resources.
- **`staleAsOf` relative-time formatting ownership** — assumed pre-formatted by AND-068 (per §13); not verifiable in these sources.
- **Whether `DashboardSummary.warnings` (a real field, claim 2) should drive any of these states** — unconfirmed; this ticket does not consume the raw DTO and leaves warning-surfacing to AND-066/AND-068.

## 17. Test Plan

All cases below target the rendering of `DashboardScreen`/state composables. Test targets: **JVM/Robolectric** (local, no device), **emulator AVD `test35`** (x86_64, API 35), **physical device** Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Because this ticket has **no real hardware/network dependencies** (all backend interaction faked, FR-8), the default target is JVM/Robolectric for the mirror and the emulator `test35` for the instrumented suite; the physical device is used only for the explicit ABI/API-parity smoke (TC-AND-069-12). No case requires camera/biometrics/FCM/WebRTC/Telecom.

- **TC-AND-069-01** — Loading renders the loading affordance.
  - Type: Compose-UI (instrumented on `test35`) + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `DashboardScreen` composed with `DashboardUiState.Loading`.
  - Steps: Set state = `Loading`; `composeRule.onNodeWithTag(LOADING)`.
  - Expected: `LOADING` node `assertIsDisplayed()`; no `CONTENT/EMPTY/ERROR/OFFLINE` nodes exist.
  - Traces: AC-1, AC-5.

- **TC-AND-069-02** — Loaded non-empty renders content only.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Loaded(widgets=[≥1], quickLinks=[…])`.
  - Steps: Set state; assert tags.
  - Expected: `CONTENT` displayed; `EMPTY/ERROR/OFFLINE/STALE_BANNER` absent.
  - Traces: AC-1.

- **TC-AND-069-03** — Loaded empty renders `DashboardEmptyState` with headline + Refresh.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Loaded(widgets=[])`.
  - Steps: Set state; assert `EMPTY` displayed; assert headline string-resource text present; assert `REFRESH_ACTION` displayed.
  - Expected: empty surface shown with copy and Refresh affordance.
  - Traces: AC-1, AC-7.

- **TC-AND-069-04** — Empty Refresh tap invokes `onRefresh` exactly once.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Loaded(widgets=[])`, counter spy for `onRefresh`.
  - Steps: `onNodeWithTag(REFRESH_ACTION).performClick()`.
  - Expected: spy count == 1; no `onRetry` invocation.
  - Traces: AC-4.

- **TC-AND-069-05** — Error (no cache) renders `DashboardErrorState` with the mapped `detail` message.
  - Type: contract/MockWebServer-informed Compose-UI (uses a *real* error shape) + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Error(message = normalizeDetail(<422 body>))`, cache = null. Use a real 422 body `{"detail":[{"loc":["query","days"],"msg":"value is not a valid integer","type":"int_parsing"}]}` mapped to its `msg` (mirrors `HTTPValidationError`/`ValidationError`), and a plain-string `detail` ("Service unavailable") as a second data point.
  - Steps: Set state; assert `ERROR` displayed; assert the exact mapped message text.
  - Expected: error surface shows the human message (the `msg`, never the raw `detail` object/JSON).
  - Traces: AC-1, AC-2; SOURCE: `src/api/client.ts: normalizeErrorDetail`, OpenAPI `HTTPValidationError`.

- **TC-AND-069-06** — Error with blank message shows generic localized fallback.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Error(message = "")`.
  - Steps: Set state; assert `ERROR` displayed; assert the generic "Something went wrong" string-resource text.
  - Expected: fallback copy shown; no blank/empty text node.
  - Traces: AC-2.

- **TC-AND-069-07** — Error Retry tap invokes `onRetry` exactly once.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Error(...)`, spy for `onRetry`.
  - Steps: `onNodeWithTag(RETRY_ACTION).performClick()`.
  - Expected: spy count == 1.
  - Traces: AC-4.

- **TC-AND-069-08** — Offline (no cache / transport failure) renders `DashboardOfflineState`.
  - Type: Compose-UI + Robolectric mirror (simulates the flaky-dev-host/offline path via faked `Offline` state; no real network).
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Offline(cached = null, staleAsOf = null)` — the Android analog of the web client's `ApiError(0, "Network error")` transport-failure path.
  - Steps: Set state; assert `OFFLINE` displayed; assert offline-specific copy and `RETRY_ACTION`.
  - Expected: offline surface shown; distinct icon + text from the error state (color not sole signal).
  - Traces: AC-1, AC-7; SOURCE: `src/api/client.ts` fetch `catch` → `ApiError(0,…)`.

- **TC-AND-069-09** — Offline with cache renders content + stale banner.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Offline(cached = <content>, staleAsOf = "2 min ago")`.
  - Steps: Set state; assert `CONTENT` and `STALE_BANNER` both displayed; assert banner text contains "2 min ago"; assert no full-screen `OFFLINE` surface.
  - Expected: cached content stays visible behind a non-blocking banner (FR-5).
  - Traces: AC-3.

- **TC-AND-069-10** — Error with cache renders content + banner (analog of 09 for `Error`).
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: `Error(message = "Service unavailable", cached = <content>)`.
  - Steps: Set state; assert `CONTENT` + `STALE_BANNER` displayed; assert no full-screen `ERROR`.
  - Expected: cached content + banner (error variant).
  - Traces: AC-3.

- **TC-AND-069-11** — Stale-banner Retry tap invokes `onRetry`; refreshing disables the action.
  - Type: Compose-UI + Robolectric mirror.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: banner-over-content state with spy; also a variant with `isRefreshing = true`.
  - Steps: Click `STALE_BANNER` retry → assert spy == 1; then with `isRefreshing = true` assert the retry/refresh action `assertIsNotEnabled()`.
  - Expected: tap counted once; action disabled while refreshing (no duplicate in-flight request), matching the web client's disabled-while-pending behavior.
  - Traces: AC-4; SOURCE: `src/pages/dashboard/CreatorDashboard.tsx` (`disabled={refreshMut.isPending}`).

- **TC-AND-069-12** — Headless suite passes on the emulator AND on the physical device (ABI/API parity smoke).
  - Type: instrumented/e2e (headless).
  - Target: emulator `test35` (x86_64, API 35) **and** physical Samsung A15 5G (arm64-v8a, API 34, serial R5CX821TA9R). MUST run on the physical device for the arm64/API-34 leg — this is the only case that needs real hardware, to catch ABI- or API-level rendering/behavior differences the emulator cannot.
  - Preconditions: app installed via adb on both targets.
  - Steps: `./gradlew :feature-dashboard:connectedDebugAndroidTest` against `test35`; then `adb -s R5CX821TA9R` install + run the same suite on the A15.
  - Expected: all `DashboardScreenTest` cases green on both ABIs/APIs, headlessly, zero flaky retries, no real network.
  - Traces: AC-6.

- **TC-AND-069-13** — Large font (`fontScale = 2f`) and pseudolocale render without crash/clip for every state.
  - Type: Compose-UI (instrumented; emulator preferred for locale/density control) + Robolectric mirror where feasible.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: each of Loading/Loaded-empty/Error/Offline/banner; `fontScale = 2f`; locale `en-XA`.
  - Steps: Compose each state with the scaled/pseudolocalized config; assert root tag still displayed.
  - Expected: no crash, no truncation/overflow; all copy from string resources.
  - Traces: AC-7.

- **TC-AND-069-14** — Accessibility: each state root has a meaningful contentDescription/role; banner is a polite live region; touch targets ≥48dp.
  - Type: Compose-UI (instrumented) + Robolectric mirror for semantics assertions.
  - Target: emulator `test35` / JVM-Robolectric.
  - Preconditions: each state composed.
  - Steps: For each state assert a non-empty semantics contentDescription on the root; assert action buttons expose descriptive labels ("Try again"/"Retry"/"Refresh") and a ≥48dp touch target; assert `STALE_BANNER` carries a polite `liveRegion`; assert decorative icons have `contentDescription = null`.
  - Expected: all semantics present; TalkBack-usable; no color-only signalling.
  - Traces: AC-7 (and §9).

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (all states render a coherent non-blank surface) | TC-01, TC-02, TC-03, TC-05, TC-08 |
| AC-2 (error shows mapped `detail`; blank → generic fallback) | TC-05, TC-06 |
| AC-3 (cache present → content + non-blocking stale banner) | TC-09, TC-10 |
| AC-4 (actions invoke once per tap; disabled while refreshing) | TC-04, TC-07, TC-11 |
| AC-5 (`when` over `DashboardUiState` is exhaustive) | TC-01 (asserts mutually-exclusive surfaces); compile-time enforced (no `else`) |
| AC-6 (suite passes headlessly in CI, no flakiness, no real network) | TC-12 (and the whole suite runs headlessly) |
| AC-7 (preview + testTag; string-res copy; pseudolocale + `fontScale=2f`) | TC-03, TC-08, TC-13, TC-14 |
