---
id: AND-117
title: Stale/reconnect UX hooks
milestone: M2
epic: E17
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-116, AND-042]
blocks: []
---

# AND-117 — Stale/reconnect UX hooks

## 1. Overview & Goal

The TestLogon dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and unreliable: it stalls, 5xxs, or drops connections without warning. AND-116 delivered a stale-while-revalidate (SWR) base repository that emits cached data immediately and then attempts a background refresh; AND-042 delivered a single global health banner driven by the backend-health probe. Neither, on its own, tells the user that *the specific data they are looking at right now is cached and a refresh failed or is in flight.*

This ticket fills that gap with **per-screen stale/reconnect UX hooks**: a small, reusable set of state primitives and composables that let any feature surface the standard "showing cached data / reconnecting…" affordances, derived from (a) the SWR emission metadata from AND-116 and (b) the backend-health signal already consumed by AND-042. The affordances are: a lightweight inline "stale" chip/bar above content when data is served from cache and the last refresh failed; a "reconnecting…" indicator while a background revalidation is running against a degraded/unreachable host; and a manual "Try again" retry action wired to the repository's revalidate path.

Goal: a deterministic, reusable, UI-tested presentation layer (`StaleState`, `rememberStaleState`, `StaleBar`, `StaleContent`) such that when the host is down and a screen has cached data, that screen renders the cached data plus a visible stale indicator with a working retry — with no bespoke per-feature wiring beyond passing one flow.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/` on branch `android-port`. Namespace/applicationId base `com.testlogon.android`.
- **Upstream — AND-116 (Cache repository pattern, SWR):** owns `CacheRepository`/the SWR base that emits `Resource<T>` (cache-first then fresh). This ticket *consumes* that emission stream and its freshness/error metadata; it does not perform caching or networking. The `Resource<T>` shape and its `isFromCache`/`isStale`/`error` flags are the authoritative contract source.
- **Upstream — AND-042 (Backend health banner):** owns `BackendStatusMonitor` (`Flow<BackendStatus>`, enum `Unknown | Reachable | Degraded | Unreachable`, originally produced by AND-017) and the global banner. This ticket reuses `BackendStatus` to phrase per-screen copy ("reconnecting…" vs "offline") and to coordinate so the per-screen bar and the global banner are complementary, not duplicative (see §13 R-2).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt DI (KSP), Coroutines/Flow. ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module placement:** all primitives and composables in `core-ui` so every `feature-*` can reuse them; no feature-specific logic. The freshness metadata is read from `core-data` (AND-116) and `BackendStatus` from `core-model`/`core-data` (AND-042/AND-017).
- **Backend:** FastAPI; OpenAPI at `/openapi.json`. No new endpoint is introduced — see §5. FastAPI error `detail` is mapped to `ApiResult` upstream and never rendered raw here.
- **Divergence from the web client (verified, §16):** the reference web app's offline/stale UX is *not* health-probe driven. It surfaces (a) a global `OfflineBanner` driven by the browser `navigator.onLine` event + an offline action queue, and (b) a per-widget "Cached {age} ago" `StalenessIndicator` keyed off a `cachedAt` timestamp. There is no 4-state `BackendStatus` enum and no health/ping fetch in the frontend. The Android `BackendStatus(Unknown|Reachable|Degraded|Unreachable)` model (AND-017/AND-042) is an intentional Android-side construct, not a port of an existing web contract; `GET /api/ping` exists in the API and is the natural probe target but is owned upstream. This ticket's per-screen bar is the closest Android analog of the web `StalenessIndicator`, fused with the freshness/error metadata that the web app does not expose.

## 3. Functional Requirements

FR-1. **Cache + stale indicator.** When a screen's data stream emits a value that `isFromCache == true` **and** the most recent revalidation failed (`error != null`) OR the cached value is older than its freshness TTL (`isStale == true`), the screen renders the cached content plus a non-blocking stale indicator (`StaleBar`) at the top of the content area. (Directly satisfies the backlog acceptance: "With host down, cached data shows with stale indicator.")

FR-2. **Reconnecting indicator.** While a background revalidation is in flight (`Resource` carries `isRefreshing == true`) against a `Degraded`/`Unreachable` host, the `StaleBar` shows a "Reconnecting…" state with an indeterminate progress affordance. When refresh completes successfully with fresh data, the bar animates out.

FR-3. **Manual retry.** The `StaleBar` exposes a "Try again" action that invokes a caller-supplied `onRetry: () -> Unit`, which is wired to the repository's revalidate trigger (AND-116). Retry is disabled (greyed, not hidden) while a refresh is already in flight to prevent retry storms against the unreliable host.

FR-4. **Condition-specific copy.** Copy is derived from cache state + `BackendStatus`:
- Cache shown, last refresh failed, host `Unreachable` → "Offline — showing saved data."
- Cache shown, last refresh failed, host `Degraded` → "Couldn't refresh — showing saved data."
- Background refresh in flight → "Reconnecting…"
- Cache shown but only TTL-stale (no error, host `Reachable`) → "Showing saved data." (refresh will replace it shortly)

FR-5. **Fresh = no bar.** When the stream emits fresh, non-cache data (`isFromCache == false`, `error == null`), the stale indicator is hidden. The transition is animated (expand/shrink + fade).

FR-6. **No first-load false positive.** The stale indicator never appears during the initial load when there is *no* cached value yet (that case is the AND-021 `Loading`/`Empty`/`Error` states, not a stale state). The bar requires a present, cache-sourced value to render.

FR-7. **Non-modal & inset-correct.** The `StaleBar` is a thin inset above per-screen content; it does not block interaction with the content below and participates in window insets so it never overlaps the app bar/status bar. It is per-screen (one per hosting screen), distinct from the single app-wide AND-042 banner.

FR-8. **Reusable, stateless rendering.** Features integrate by wrapping content in `StaleContent(...)` or placing `StaleBar(state, onRetry)` and passing a single derived `StateFlow`/state object — no feature re-implements freshness logic.

## 4. Technical Design

### 4.1 Upstream contracts (consumed, not defined here)

```kotlin
// core-data (owned by AND-116) — referenced, not redefined
sealed interface Resource<out T> {
    data class Success<T>(
        val data: T,
        val isFromCache: Boolean,
        val isStale: Boolean,       // cached value older than freshness TTL
        val isRefreshing: Boolean,  // background revalidation in flight
        val error: AppError? = null // last revalidation error, if any
    ) : Resource<T>
    data class Loading(val isFromCache: Boolean = false) : Resource<Nothing>
    data class Error(val error: AppError, val cached: Any? = null) : Resource<Nothing>
}

// core-model (owned by AND-017 via AND-042) — referenced
enum class BackendStatus { Unknown, Reachable, Degraded, Unreachable }
```

> If AND-116 names these flags differently (e.g. `origin = Cache|Network`), the single adapter `Resource<*>.toFreshness()` in §4.3 is the only place this ticket changes.

### 4.2 Stale UI state

```kotlin
// core-ui
data class StaleState(
    val showBar: Boolean = false,
    val mode: Mode = Mode.None,
    val messageRes: Int = 0,
    val retryEnabled: Boolean = false,
) {
    enum class Mode { None, Stale, RefreshFailed, Reconnecting }
}
```

### 4.3 Derivation — pure function, no I/O

The mapping is a pure function so it is trivially unit-testable and can be reused inside a ViewModel or inline in composition:

```kotlin
// core-ui
fun deriveStaleState(
    freshness: Freshness,        // distilled from Resource<*> (see toFreshness)
    backend: BackendStatus,
): StaleState = when {
    !freshness.hasCachedValue -> StaleState() // FR-6: nothing to show

    freshness.isRefreshing -> StaleState(
        showBar = true, mode = StaleState.Mode.Reconnecting,
        messageRes = R.string.stale_reconnecting, retryEnabled = false
    )

    freshness.lastRefreshFailed && backend == BackendStatus.Unreachable -> StaleState(
        showBar = true, mode = StaleState.Mode.RefreshFailed,
        messageRes = R.string.stale_offline_saved, retryEnabled = true
    )

    freshness.lastRefreshFailed -> StaleState( // Degraded or transient failure
        showBar = true, mode = StaleState.Mode.RefreshFailed,
        messageRes = R.string.stale_refresh_failed, retryEnabled = true
    )

    freshness.isStale -> StaleState(
        showBar = true, mode = StaleState.Mode.Stale,
        messageRes = R.string.stale_showing_saved, retryEnabled = true
    )

    else -> StaleState() // fresh data → FR-5
}

data class Freshness(
    val hasCachedValue: Boolean,
    val isStale: Boolean,
    val isRefreshing: Boolean,
    val lastRefreshFailed: Boolean,
)

fun Resource<*>.toFreshness(): Freshness = when (this) {
    is Resource.Success -> Freshness(
        hasCachedValue = isFromCache,
        isStale = isStale,
        isRefreshing = isRefreshing,
        lastRefreshFailed = error != null,
    )
    is Resource.Loading -> Freshness(isFromCache, isStale = false, isRefreshing = true, lastRefreshFailed = false)
    is Resource.Error -> Freshness(hasCachedValue = cached != null, isStale = true, isRefreshing = false, lastRefreshFailed = true)
}
```

### 4.4 Composition helper

A `remember`-based helper combines the screen's `Resource` flow with the shared `BackendStatus` flow so features pass exactly one flow plus a retry lambda:

```kotlin
// core-ui
@Composable
fun rememberStaleState(
    resource: Resource<*>,
    backend: BackendStatus = LocalBackendStatus.current, // CompositionLocal seeded at AppScaffold
): StaleState = remember(resource, backend) { deriveStaleState(resource.toFreshness(), backend) }
```

`LocalBackendStatus` is a `CompositionLocal` provided once at the AND-042 `AppScaffold` root (collected via `collectAsStateWithLifecycle`), so per-screen code does not re-collect the health flow.

### 4.5 Composables

```kotlin
@Composable
fun StaleBar(
    state: StaleState,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)

@Composable
fun StaleContent(
    resource: Resource<*>,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    val state = rememberStaleState(resource)
    Column(modifier) {
        StaleBar(state = state, onRetry = onRetry, modifier = Modifier.fillMaxWidth())
        content()
    }
}
```

`StaleBar` wraps its row in `AnimatedVisibility(visible = state.showBar)` with `expandVertically()/shrinkVertically()` + fade (FR-5). Severity → Material 3 roles: `RefreshFailed` → `errorContainer`/`onErrorContainer`; `Stale` → `surfaceVariant`/`onSurfaceVariant`; `Reconnecting` → `secondaryContainer`/`onSecondaryContainer` with a leading `CircularProgressIndicator` (indeterminate, 16.dp). Leading icons: `Icons.Filled.CloudOff` (RefreshFailed), `Icons.Filled.Schedule` (Stale). A trailing `TextButton` shows "Try again" when `mode != Reconnecting`, `enabled = state.retryEnabled`. Both composables are stateless w.r.t. the input `state`, so they are previewable and directly UI-testable.

### 4.6 Feature integration (illustrative)

```kotlin
// in any feature-* screen
val resource by viewModel.resource.collectAsStateWithLifecycle()
StaleContent(resource = resource, onRetry = viewModel::refresh) {
    when (val r = resource) {
        is Resource.Success -> ItemList(r.data)
        is Resource.Loading -> LoadingState()      // AND-021
        is Resource.Error   -> if (r.cached != null) ItemList(r.cached) else ErrorState(onRetry = viewModel::refresh)
    }
}
```

`viewModel.refresh()` calls the AND-116 repository's revalidate entry point (idempotent `GET`; bounded backoff handled there, not here).

## 5. API Contract

**No new API surface is introduced by this ticket.** All network I/O — the cache reads/writes, the revalidating `GET`, the ~20 s timeout, and bounded-backoff retry for idempotent GETs — is owned by **AND-116** (SWR repository) and the underlying `core-network` client. Backend health classification is owned by **AND-042/AND-017**. This ticket consumes `Resource<T>` and `BackendStatus` and performs zero network calls; `onRetry` merely re-triggers the AND-116 revalidate path.

For reference, the freshness metadata this UI relies on (`isFromCache`, `isStale`, `isRefreshing`, `error`) is populated by AND-116 from the result of that idempotent `GET`. FastAPI's `detail` error shape (`string | [{msg}] | {code,...}`) is already mapped to `AppError`/`ApiResult` upstream; this ticket renders only the generic strings in §4.3, never the raw `detail`.

## 6. Data & State Management

- **Sources of truth:** (1) the screen's `Resource<T>` `StateFlow` from its feature ViewModel (AND-116-backed); (2) `BackendStatusMonitor.status: Flow<BackendStatus>` (AND-042), surfaced via `LocalBackendStatus`.
- **Derived state:** `StaleState` is computed purely (`deriveStaleState`) per recomposition via `rememberStaleState`; it is not separately persisted. No new ViewModel is required for the bar itself — it is a function of inputs.
- **No persistence:** the bar holds no state of its own; freshness/TTL bookkeeping lives in AND-116's cache layer (Room + timestamps). Nothing is written to Room or DataStore by this ticket.
- **Lifecycle:** features collect their `Resource` flow with `collectAsStateWithLifecycle`; `LocalBackendStatus` is likewise lifecycle-collected once at the root. On backgrounding, collection pauses; on return, the latest `Resource`/`BackendStatus` re-derive the bar with no stale leftover.
- **Threading:** derivation is synchronous and cheap (a `when`), runs on the composition thread; all suspending work (cache read, refresh) is upstream in `viewModelScope`.

## 7. Error Handling & Resilience

- **This UI is the resilience surface for cache-vs-network divergence.** It has no failure mode that surfaces to the user beyond the bar itself.
- **Retry-storm guard (FR-3):** "Try again" is disabled while `isRefreshing`, so rapid taps cannot fan out concurrent GETs against the flaky host. Underlying bounded backoff is AND-116's responsibility; this UI never loops retries automatically.
- **Defensive mapping:** `toFreshness` is total over the `Resource` sealed hierarchy (exhaustive `when`); an unexpected/unknown error degrades to `RefreshFailed` (show cached + retry) rather than crashing.
- **No flicker on success:** when refresh succeeds, `isFromCache` flips false and the bar animates out via `AnimatedVisibility`; a brief `isRefreshing` flash on fast networks is acceptable and self-clears.
- **Complementarity with AND-042 (R-2):** if the global health banner is already visible (host `Unreachable`), per-screen copy uses the shorter "Offline — showing saved data." to avoid double messaging; resolution tracked in §13.

## 8. Security & Privacy

- No new data is collected, transmitted, or persisted; the component reads in-memory `Resource`/`BackendStatus`.
- Copy must never leak the host/IP (`18.222.237.167:8000`), FastAPI `detail` payloads, stack traces, or response bodies — only the generic, user-facing strings in §4.3/FR-4.
- No PII, credentials, cookies, or `X-CSRF-Token` values are referenced by these composables.
- Telemetry (§10) records only the coarse `StaleState.Mode` enum, `BackendStatus`, and durations — no request/response content.

## 9. Accessibility & i18n

- **i18n:** all copy in `strings.xml` (`stale_offline_saved`, `stale_refresh_failed`, `stale_showing_saved`, `stale_reconnecting`, and `stale_retry` for the button); no hardcoded strings. The bar uses wrapping `Text` (no truncation) so longer translations stay readable.
- **a11y / TalkBack:** the bar container sets `Modifier.semantics { liveRegion = LiveRegionMode.Polite; contentDescription = <message> }` so screen readers announce appearance without stealing focus. Leading icons and the progress indicator are decorative (`contentDescription = null`). The retry `TextButton` carries its own label and a `Reconnecting…`-state `disabled` semantics so TalkBack reports it as unavailable while refreshing.
- **Contrast:** Material 3 container/on-container role pairs meet WCAG AA in light and dark themes; verified in both.
- **Motion:** expand/shrink + fade respects the system "remove animations" setting via Compose's reduced-motion handling; state is conveyed by icon + text, never motion alone.
- **Touch target:** the retry button meets the 48.dp minimum target size.

## 10. Telemetry & Logging

- **Structured log (debug builds):** on each committed bar transition, `Log.i("StaleBar", "mode=${mode}, backend=${backend}")`. No payloads.
- **Analytics events** (via the app analytics abstraction, fire-and-forget):
  - `stale_bar_shown` `{ mode: "stale"|"refresh_failed"|"reconnecting", backend: "degraded"|"unreachable"|"reachable" }`
  - `stale_retry_tapped` `{ mode, backend }`
  - `stale_bar_cleared` `{ visible_ms: Long }` (duration the bar was shown, on transition back to fresh)
- Events fire on confirmed transitions only (deduped per `mode`), so recompositions do not inflate counts. These quantify how often users see cached data and how often manual retry is used against the unreliable backend, without logging any content.

## 11. Testing Strategy

**Unit (core-testing, JVM, `kotlinx-coroutines-test` + Turbine):**
- `deriveStaleState` truth table: every combination of `hasCachedValue`/`isStale`/`isRefreshing`/`lastRefreshFailed` × `BackendStatus` maps to the expected `StaleState` (showBar, mode, messageRes, retryEnabled).
- FR-6: `hasCachedValue == false` → `StaleState()` (hidden) regardless of other flags.
- FR-3: `isRefreshing == true` → `retryEnabled == false`, `mode == Reconnecting`.
- `Resource<*>.toFreshness()` is exhaustive over `Success`/`Loading`/`Error` (including `Error` with non-null `cached` → `hasCachedValue = true, lastRefreshFailed = true`).

**Compose UI test (this ticket's primary acceptance gate, AndroidX Compose test rule):**
- Render `StaleContent` with a fake `Resource.Success(data, isFromCache=true, error=AppError)` and `LocalBackendStatus = Unreachable`:
  - cached content node `assertIsDisplayed()` **and** the `stale_offline_saved` string `assertIsDisplayed()` — **directly satisfies the backlog AC "host down → cached data shows with stale indicator (UI-tested)."**
  - "Try again" button `assertIsDisplayed()` and `assertIsEnabled()`; tapping invokes `onRetry` (verified via a spy).
- Reconnecting: `isRefreshing=true` → `stale_reconnecting` displayed, retry button `assertIsNotEnabled()`.
- Fresh: `isFromCache=false, error=null` → stale string `assertDoesNotExist()`, content still displayed (FR-5).
- Semantics: live-region + contentDescription present when the bar is visible.

**Integration (optional, MockWebServer):** drive a real AND-116 repository against a `MockWebServer` enqueued with a failure (cache served, bar shown) then a 200 on retry (bar clears), asserting end-to-end through the real `Resource` flow.

## 12. Dependencies & Sequencing

- **Hard depends on AND-116** — provides the SWR `Resource<T>` emission with freshness metadata (`isFromCache`/`isStale`/`isRefreshing`/`error`) and the revalidate trigger wired to `onRetry`. Cannot start until that contract merges; if its flag names differ, only `toFreshness` (§4.3) changes.
- **Hard depends on AND-042** — provides `BackendStatus`/`BackendStatusMonitor` and the `AppScaffold` root where `LocalBackendStatus` is provided. Per-screen copy and the R-2 complementarity rule depend on it.
- **Blocks:** none currently; downstream `feature-*` screens will adopt `StaleContent` as they wire their AND-116-backed repositories, but none are hard-blocked by this ticket.
- **Sequencing:** implement after both deps merge to `android-port`. Order: (1) `StaleState` + `Freshness` + `deriveStaleState`/`toFreshness` + unit truth-table tests; (2) `StaleBar`/`StaleContent` composables + `rememberStaleState` + `LocalBackendStatus` provision in `AppScaffold`; (3) Compose UI acceptance test; (4) telemetry + a11y pass; (5) adopt in one pilot feature screen as a smoke integration.

## 13. Risks & Open Questions

- **R-1 (double messaging with AND-042):** the global health banner (host down) and a per-screen stale bar can show simultaneously. Decision: global banner = server health; per-screen bar = *this screen's data is cached*; per-screen copy shortens to "Offline — showing saved data." when host is `Unreachable`. Confirm with design that simultaneous display is acceptable, or suppress the per-screen text portion when the global banner is up.
- **R-2 (TTL semantics depend on AND-116):** the meaning of `isStale` (TTL-based) vs `lastRefreshFailed` is owned by AND-116. If AND-116 only exposes `isFromCache` (no TTL), the `Stale` mode collapses into "showing saved" and the truth table simplifies; track AND-116's final contract.
- **R-3 (retry vs backoff interaction):** manual "Try again" must not bypass AND-116's bounded backoff and hammer the host. Mitigated by disabling retry while `isRefreshing` and delegating actual throttling to the repository.
- **OQ-1:** Should the bar auto-retry on regaining connectivity (when `BackendStatus` flips `Unreachable → Reachable`), or wait for user action? v1: no auto-retry from this UI (AND-116's own revalidation handles it); revisit if users report stuck stale data.
- **OQ-2:** Should `Reconnecting…` be shown only when a prior cached value exists, or also during a first load with no cache? v1: only with cached value (first load is AND-021 `Loading`); confirm with design.

## 14. Acceptance Criteria

- **AC-1 (from backlog):** With the host down (`BackendStatus.Unreachable`) and a screen holding a cached value (`Resource.Success(isFromCache=true, error!=null)`), the screen renders the cached content **and** a visible stale indicator, verified by an automated Compose UI test (§11) — this is the gating criterion.
- **AC-2:** A background revalidation (`isRefreshing=true`) shows the "Reconnecting…" mode with an indeterminate indicator and a disabled retry button.
- **AC-3:** "Try again" invokes the caller's `onRetry` (wired to AND-116 revalidate) when enabled, and is disabled while a refresh is in flight (no retry storm).
- **AC-4:** Fresh data (`isFromCache=false, error=null`) hides the stale indicator with an animated transition; content remains displayed (FR-5).
- **AC-5:** No stale indicator appears during initial load when no cached value exists (FR-6).
- **AC-6:** The component performs no network I/O; it derives entirely from `Resource` + `BackendStatus` (verified by absence of network dependencies in `core-ui` for this component).
- **AC-7:** All copy is in `strings.xml`; the bar exposes a polite live region and contentDescription; retry meets the 48.dp target and reports disabled state to TalkBack.
- **AC-8:** No host/IP or FastAPI `detail` payload is ever rendered (verified by string inspection / review).

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android` with `StaleState`, `Freshness`, `deriveStaleState`, `Resource<*>.toFreshness()`, `rememberStaleState`, `StaleBar`, and `StaleContent` in `core-ui`, plus `LocalBackendStatus` provided at the AND-042 `AppScaffold` root.
- Unit truth-table tests and the Compose UI acceptance test (AC-1) pass in CI; coverage includes stale/refresh-failed/reconnecting/fresh and no-cache paths.
- Strings externalized; light + dark theme contrast and TalkBack announcement (including disabled-retry state) verified.
- Telemetry events (`stale_bar_shown`, `stale_retry_tapped`, `stale_bar_cleared`) emitting on confirmed transitions; no payload/PII logged.
- At least one pilot `feature-*` screen adopts `StaleContent` against its AND-116 repository as a smoke check.
- Ktlint/detekt clean; no hardcoded host strings or `detail` payloads rendered.
- §13 R-1 (double-messaging) and OQ-1/OQ-2 resolved with design/product or explicitly deferred with a follow-up note; reviewer-approved PR.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption) and an exact SOURCE pointer.

1. **CSRF is carried as `X-CSRF-Token`, sourced from a cookie** (§8: "No PII, credentials, cookies, or `X-CSRF-Token` values are referenced"). VERDICT: **Verified.** SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, lines 168–171); also `src/stores/offlineStore.ts` `getCsrfFromCookie()` reads `ui_csrf`.
2. **FastAPI error `detail` shape is `string | [{msg}] | {code,...}`, mapped upstream and never rendered raw** (§5, §7, §8). VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail` (handles `string`, `Array<{msg}>`, and `{code,...}` via `mapAuthorizationError`, lines 66–102); OpenAPI schemas `HTTPValidationError`/`ValidationError` (422 responses across the index, e.g. `GET /api/billing/balance | resp=...;422:HTTPValidationError`).
3. **Network failure / unreachable host produces a distinct transport error (not an HTTP status)** — basis for the "offline / showing saved data" path. VERDICT: **Verified.** SOURCE: `src/api/client.ts` catch block — `fetch` throw → `toast.error("Network error...")` → `throw new ApiError(0, "Network error", err)` (lines 185–189). Confirms a status-0/transport class the Android `AppError`/`Unreachable` mapping mirrors.
4. **No new API surface; the revalidate is an idempotent GET owned by AND-116** (§5, §4.6). VERDICT: **Verified (no new endpoint) + Unverified-assumption (the specific GET + ~20s timeout + bounded backoff).** SOURCE: This ticket adds nothing to `reference/openapi.index.txt`; the concrete revalidate endpoint/timeout/backoff live in AND-116's `CacheRepository`, which is not present in these sources — see Open assumptions.
5. **A backend health probe exists for AND-017/AND-042 to classify reachability.** VERDICT: **Verified (endpoint exists) + Unverified-assumption (that AND-017 uses it / its classification thresholds).** SOURCE: OpenAPI `GET /api/ping | op=ping_api_ping_get | resp=200: | params=` (no auth, no params, empty 200 schema) and `GET /api/browser-ssh/health`. The frontend does **not** call either (no `api.get(.../ping|/health)` match in `src/`), so the probe + `BackendStatus` enum are Android-side, not a web contract.
6. **`BackendStatus(Unknown|Reachable|Degraded|Unreachable)` and the per-screen stale/reconnect pattern mirror the web client** (§1, §2). VERDICT: **Corrected / clarified.** The web client has **no** such enum and **no** health-driven stale model: it uses `navigator.onLine` (`src/components/shared/OfflineBanner.tsx`) plus a `cachedAt`-timestamp badge (`src/components/shared/StalenessIndicator.tsx`, label "Cached {age} ago"). Added a "Divergence from the web client" note to §2 stating the Android model is an intentional construct, not a port. SOURCE: `src/components/shared/OfflineBanner.tsx`, `src/components/shared/StalenessIndicator.tsx`, `src/stores/offlineStore.ts`.
7. **Web offline affordance copy uses "showing cached data"** — sanity check on §4.3/FR-4 wording. VERDICT: **Verified (web wording differs slightly; Android copy is a deliberate rephrase).** SOURCE: `OfflineBanner.tsx` renders "You're offline — showing cached data"; Android spec uses "Offline — showing saved data." (intentional, externalized in `strings.xml`). Noted as acceptable wording divergence.
8. **`Resource<T>` carries `isFromCache`/`isStale`/`isRefreshing`/`error` flags** (§4.1, §4.3). VERDICT: **Unverified-assumption.** SOURCE: owned by AND-116 (`core-data`), not present in `reference/`. The spec already hedges this (§4.1 note, §4.3 `toFreshness` adapter, §13 R-2) — retained as the single point of change if flag names differ.
9. **Jetpack Compose / Material 3 role pairs, `AnimatedVisibility`, `semantics{liveRegion}`, 48.dp touch target, reduced-motion handling** (§4.5, §9). VERDICT: **Verified (framework ref).** SOURCE (framework ref): Material 3 color roles — https://m3.material.io/styles/color/roles ; Compose `AnimatedVisibility` — https://developer.android.com/develop/ui/compose/animation/composables-modifiers#animatedvisibility ; semantics/live region & accessibility — https://developer.android.com/develop/ui/compose/accessibility ; touch target 48dp — https://support.google.com/accessibility/android/answer/7101858 ; reduced motion — https://developer.android.com/develop/ui/compose/animation/customize#reduced-motion .
10. **Stack: minSdk 24 / compile+target 35, AGP 8.7.3, Gradle 8.9, Kotlin 2.0.21, Hilt+KSP, `collectAsStateWithLifecycle`** (§2). VERDICT: **Unverified-assumption (project convention).** SOURCE: no Android project files in `reference/` (frontend is the only reference app); these are inherited from the AND-port baseline, not checkable here. The targetSdk 35 aligns with CI AVD `test35` (API 35).

### Corrections made

- **§2 (new "Divergence from the web client" bullet):** Added an explicit, source-backed clarification that the web reference app has no `BackendStatus` enum and no health-probe-driven stale model — it uses `navigator.onLine` + an offline queue (`OfflineBanner.tsx`) and a `cachedAt` badge (`StalenessIndicator.tsx`). This prevents a reader inferring that the 4-state health model is a ported web contract; it is an intentional Android construct (AND-017/AND-042). No other claim in §1–§15 was factually wrong against the verifiable sources, so edits were kept minimal.
- No changes were needed to the CSRF (§8) or error-`detail` (§5/§7) claims — both verified exactly against `client.ts`.

### Open assumptions

- **AND-116 `Resource<T>` contract** (flag names `isFromCache`/`isStale`/`isRefreshing`/`error`, TTL semantics, the revalidate trigger, ~20s timeout, bounded backoff): not in `reference/`; owned by an unmerged upstream ticket. Mitigated by the single `toFreshness` adapter (§4.3) and §13 R-2. Verify at AND-116 merge.
- **AND-017/AND-042 health classification**: that `BackendStatus` is computed from `GET /api/ping` (or similar) and the Degraded-vs-Unreachable thresholds. Endpoint exists; the classifier is upstream. Verify at AND-042 merge.
- **Android project/build config** (SDK levels, AGP/Gradle/Kotlin versions, module layout `core-ui`/`core-data`/`core-model`): no Android sources in `reference/` to confirm; inherited from the port baseline.
- **Analytics abstraction + event names** (§10 `stale_bar_shown`, etc.): app-internal; not verifiable from these sources.

## 17. Test Plan

Targets: **JVM/Robolectric** (local, no device); **Emulator `test35`** (x86_64, API 35); **Physical device** Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is a pure UI/state presentation layer with **zero** device-hardware dependencies (no camera, biometrics, FCM, WebRTC, Telecom, or streaming), so almost everything runs on JVM or the headless emulator. The physical device is used only for the real-network/offline behavior case and the ABI/API-level differential, where actual radio/connectivity behavior matters.

- **TC-AND-117-01 — `deriveStaleState` truth table.** Type: unit (JVM). Target: JVM/Robolectric. Preconditions: pure function under test. Steps: parameterize over `Freshness{hasCachedValue,isStale,isRefreshing,lastRefreshFailed}` × `BackendStatus{Unknown,Reachable,Degraded,Unreachable}`; assert the resulting `StaleState{showBar,mode,messageRes,retryEnabled}` against the §4.3 matrix. Expected: every combination maps as specified — Reconnecting takes precedence when `isRefreshing`; `lastRefreshFailed`+`Unreachable` → `RefreshFailed`/`stale_offline_saved`; other `lastRefreshFailed` → `RefreshFailed`/`stale_refresh_failed`; `isStale` only → `Stale`/`stale_showing_saved`; else hidden. Traces: AC-1, AC-2, AC-4.
- **TC-AND-117-02 — No-cache suppression (FR-6).** Type: unit (JVM). Target: JVM. Preconditions: none. Steps: call `deriveStaleState(Freshness(hasCachedValue=false, ...any...), anyBackend)`. Expected: returns default `StaleState()` (showBar=false, mode=None) for all other flag/backend combinations. Traces: AC-5.
- **TC-AND-117-03 — Retry-storm guard (FR-3).** Type: unit (JVM). Target: JVM. Preconditions: none. Steps: derive with `isRefreshing=true` across backends. Expected: `mode==Reconnecting`, `retryEnabled==false`. Traces: AC-2, AC-3.
- **TC-AND-117-04 — `Resource<*>.toFreshness()` exhaustiveness.** Type: unit (JVM). Target: JVM. Preconditions: none. Steps: map `Resource.Success` (with/without `error`, `isFromCache` true/false), `Resource.Loading`, and `Resource.Error(cached=null)` and `Resource.Error(cached!=null)`. Expected: total over the sealed hierarchy; `Error(cached!=null)` → `hasCachedValue=true, lastRefreshFailed=true`; `Loading` → `isRefreshing=true, lastRefreshFailed=false`. Traces: AC-1, AC-6.
- **TC-AND-117-05 — Acceptance: host down → cached content + stale indicator (gating).** Type: Compose-UI. Target: Emulator `test35` (or Robolectric Compose). Preconditions: `StaleContent` rendered with `Resource.Success(data, isFromCache=true, error=AppError(...))`, `LocalBackendStatus=Unreachable`. Steps: assert content node `assertIsDisplayed()`; assert `stale_offline_saved` text `assertIsDisplayed()`. Expected: cached content AND the stale bar are both visible. Traces: AC-1.
- **TC-AND-117-06 — Retry enabled + invokes `onRetry`.** Type: Compose-UI. Target: Emulator `test35`. Preconditions: same as TC-05 with a spy `onRetry`. Steps: find "Try again" (`stale_retry`), `assertIsDisplayed()`, `assertIsEnabled()`, `performClick()`. Expected: `onRetry` invoked exactly once. Traces: AC-3.
- **TC-AND-117-07 — Reconnecting state disables retry.** Type: Compose-UI. Target: Emulator `test35`. Preconditions: `Resource.Success(isFromCache=true, isRefreshing=true)`, backend `Degraded`. Steps: assert `stale_reconnecting` displayed; assert the indeterminate progress indicator present; assert retry button `assertIsNotEnabled()` (or absent per §4.5 "Try again shown when mode != Reconnecting") and that tapping is a no-op. Expected: reconnecting copy + disabled/absent retry. Traces: AC-2, AC-3.
- **TC-AND-117-08 — Fresh data hides bar with animated transition (FR-5).** Type: Compose-UI. Target: Emulator `test35`. Preconditions: start from a cached+failed state, then recompose with `Resource.Success(isFromCache=false, error=null)`. Steps: assert stale strings `assertDoesNotExist()` after the transition; assert content still `assertIsDisplayed()`. Expected: bar animates out (AnimatedVisibility), content persists. Traces: AC-4.
- **TC-AND-117-09 — Condition-specific copy (FR-4).** Type: Compose-UI. Target: Emulator `test35`. Preconditions: parameterized renders. Steps: (a) failed+`Unreachable` → `stale_offline_saved`; (b) failed+`Degraded` → `stale_refresh_failed`; (c) `isStale` only + `Reachable` → `stale_showing_saved`; (d) `isRefreshing` → `stale_reconnecting`. Expected: each variant shows exactly its string and no other stale string. Traces: AC-1, AC-2.
- **TC-AND-117-10 — Accessibility / TalkBack semantics.** Type: instrumented (a11y). Target: Emulator `test35`. Preconditions: bar visible (cached+failed). Steps: assert the bar container exposes `liveRegion = Polite` and a `contentDescription` equal to the message; assert leading icon/progress are decorative (`contentDescription == null`); assert retry button reports `disabled` semantics in Reconnecting; assert retry touch target ≥ 48.dp. Expected: all semantics present; no hardcoded literals (strings resolve from `strings.xml`). Traces: AC-7.
- **TC-AND-117-11 — No leakage of host/IP or `detail` (security).** Type: unit + Compose-UI. Target: JVM + Emulator `test35`. Preconditions: feed an `AppError` whose underlying message contains `18.222.237.167:8000` and a raw FastAPI `detail` payload. Steps: render every mode and snapshot all displayed text; scan for the host/IP substring and for `detail`/stack-trace content; also static-scan `core-ui` for the literal IP. Expected: only generic §4.3 strings appear; no host/IP/`detail`/body rendered. Traces: AC-8.
- **TC-AND-117-12 — No network I/O from `core-ui` (architecture).** Type: unit (JVM/static). Target: JVM. Preconditions: build graph available. Steps: assert the `core-ui` stale-bar component has no dependency on `core-network`/OkHttp/Retrofit and performs no I/O (dependency-rule test, e.g. Konsist/ArchUnit-style or module dep assertion). Expected: zero network deps; derivation is pure. Traces: AC-6.
- **TC-AND-117-13 — End-to-end SWR through MockWebServer.** Type: contract/MockWebServer (integration). Target: Emulator `test35`. Preconditions: a real (or test-double) AND-116 repository wired to a `MockWebServer`. Steps: enqueue a transport failure/5xx for the revalidate GET so cache is served (bar shown), tap "Try again", enqueue a 200 with fresh body. Expected: bar shows on first failure, clears after the successful retry; asserted through the real `Resource` flow and `StaleContent`. Traces: AC-1, AC-3, AC-4.
- **TC-AND-117-14 — Real flaky/offline host on physical device (MUST run on device).** Type: instrumented/e2e. Target: **Physical device (SM-A156U, API 34, arm64-v8a)** — MUST use the physical device because it exercises the real radio/connectivity stack (airplane-mode toggle, real DNS/connect failures) that the emulator only simulates, and validates arm64-v8a + API-34 behavior vs the API-35 x86_64 emulator. Preconditions: app on a pilot `feature-*` screen with previously-cached data; backend `http://18.222.237.167:8000` reachable, then made unreachable (enable airplane mode or block the host). Steps: load screen (cache warms), drop connectivity, navigate back to the screen / trigger revalidate; observe `Unreachable` classification and the stale bar; restore connectivity and tap "Try again". Expected: with host down, cached data renders with the "Offline — showing saved data" bar and an enabled retry; on reconnect, retry clears the bar with fresh data; no crash/ANR; behavior matches the emulator suite (no ABI/API-level divergence). Traces: AC-1, AC-3, AC-4.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (host down → cached + stale indicator, gating) | TC-01, TC-04, TC-05, TC-09, TC-13, TC-14 |
| AC-2 (reconnecting mode + disabled retry) | TC-01, TC-03, TC-07, TC-09 |
| AC-3 (retry invokes onRetry; disabled while refreshing) | TC-03, TC-06, TC-07, TC-13, TC-14 |
| AC-4 (fresh hides bar, animated; content stays) | TC-01, TC-08, TC-13, TC-14 |
| AC-5 (no stale on first load / no cache) | TC-02 |
| AC-6 (no network I/O; derives from inputs) | TC-04, TC-12 |
| AC-7 (strings.xml; live region + contentDescription; 48.dp; disabled reported) | TC-10 |
| AC-8 (no host/IP or FastAPI detail rendered) | TC-11 |
