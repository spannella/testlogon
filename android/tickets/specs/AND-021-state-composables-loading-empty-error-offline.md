---
id: AND-021
title: State composables (loading/empty/error/offline)
milestone: M1
epic: E03
priority: P0
size: M
status: draft
depends_on: [AND-019]
blocks: [AND-042]
---

# AND-021 — State composables (loading/empty/error/offline)

## 1. Overview & Goal

Every screen in the TestLogon Android app consumes a `StateFlow<UiState>` from its
ViewModel and must render one of a small, well-known set of non-content states:
**Loading**, **Empty**, **Error (with retry)**, and **Offline/stale**. Today each
feature would re-implement these by hand, producing inconsistent spinners, ad-hoc
error strings, missing retry affordances, and no shared offline/stale messaging.
Given that the dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and
unreliable (~20s timeouts, frequent transient failures), consistent and correct
non-content states are a first-class product concern, not polish.

This ticket delivers a reusable family of stateless Compose composables plus a
thin app-level `Scaffold` wrapper, all in `core-ui`. The goal is that any feature
can map its `UiState` to a fully-styled, accessible, themed state surface in one
call, with a `retry` lambda wired to the ViewModel. Scope is the **presentation
layer only**: the composables are pure functions of their inputs and own no data,
no networking, and no connectivity detection. Connectivity *sources* and the
global health banner are owned downstream (AND-042); this ticket provides the
visual primitives they reuse.

Success means: each state composable renders correctly in light/dark themes, the
Error and Offline retry callbacks fire on tap (verified by UI test), and at least
one feature screen can be wired to these primitives without bespoke state UI.

## 2. Context & References

- **Module:** `core-ui` (layer: `app -> feature-* -> core-*`). No feature or
  network dependencies are introduced.
- **Depends on AND-019 (Material 3 theme):** all colors, typography, and shapes
  come from `TestLogonTheme` (`MaterialTheme.colorScheme`,
  `MaterialTheme.typography`, `MaterialTheme.shapes`). No hard-coded colors or
  `dp` font sizes.
- **Blocks AND-042 (Backend health banner):** the global degraded/unreachable
  banner reuses `OfflineBanner`/`StaleBanner` and the `AppScaffold` banner slot
  defined here.
- **Consumes (forward reference):** the canonical `UiState<T>` sealed hierarchy
  and `ApiResult<T>` are defined in `core-model`/`core-data` mapping tickets.
  This ticket defines a *local* `ScreenState` mapping helper but does not depend
  on `core-network`; the contract is documented in §6 so consumers can adapt.
- **Web reference:** `frontend/src/api/types.ts` (FastAPI `detail` shapes) and
  `frontend/src/api/endpoints/*.ts` inform the error-message extraction rules
  reused by `errorMessage()` in §7.
- **Package base:** `com.testlogon.android` — all classes live under
  `com.testlogon.android.core.ui.state` and `com.testlogon.android.core.ui.scaffold`.

## 3. Functional Requirements

FR-1. Provide `LoadingState` — a centered, accessible progress indicator with an
optional message; supports a full-screen variant and an inline/list-footer
variant (the latter reused by Paging 3 append states downstream).

FR-2. Provide `EmptyState` — an illustration/icon, title, optional body, and an
optional primary action button (e.g. "Refresh"). Used when a request succeeds
but returns zero items.

FR-3. Provide `ErrorState` — an error icon, a human-readable title and message,
and a **Retry** button that invokes a supplied `onRetry: () -> Unit`. The
message is derived from a typed error via `errorMessage()` (§7), never a raw
exception `toString()`.

FR-4. Provide `OfflineBanner` and `StaleBanner` — slim, dismissible/persistent
banners shown above content. `OfflineBanner` signals no connectivity; `StaleBanner`
signals cached/stale data is being shown with a "last updated" relative time and
an optional retry. Both are inline (do not replace content).

FR-5. Provide `AppScaffold` — a Material 3 `Scaffold` wrapper exposing slots for
top bar, snackbar host, an optional **banner region** (for FR-4 banners), and a
content lambda. It standardizes insets/padding and is the single entry point used
by feature screens.

FR-6. Provide `ScreenStateContainer` — a convenience composable that takes a
`ScreenState` value and renders the correct full-screen state (loading/empty/
error) or the content, so a feature screen is one `when`-free call.

FR-7. All composables are **stateless** (no `remember`-ed business state, no side
effects, no coroutines). All callbacks (`onRetry`, `onAction`, `onDismiss`) are
hoisted parameters.

FR-8. All user-visible strings are sourced from `core-ui` string resources
(`strings.xml`); no inline English literals in composable bodies.

FR-9. Every composable has at least one `@Preview` (light + dark) and a default
parameter surface that allows previewing with no required arguments.

## 4. Technical Design

All composables live in `core-ui` and are pure functions. Signatures:

```kotlin
package com.testlogon.android.core.ui.state

@Composable
fun LoadingState(
    modifier: Modifier = Modifier,
    message: String? = null,
    fullScreen: Boolean = true,
)

@Composable
fun EmptyState(
    title: String,
    modifier: Modifier = Modifier,
    body: String? = null,
    imageVector: ImageVector = Icons.Outlined.Inbox,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
)

@Composable
fun ErrorState(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    title: String = stringResource(R.string.state_error_title),
    retryLabel: String = stringResource(R.string.action_retry),
    imageVector: ImageVector = Icons.Outlined.ErrorOutline,
)

@Composable
fun OfflineBanner(
    modifier: Modifier = Modifier,
    message: String = stringResource(R.string.state_offline_message),
    onRetry: (() -> Unit)? = null,
)

@Composable
fun StaleBanner(
    lastUpdated: Instant?,
    modifier: Modifier = Modifier,
    onRetry: (() -> Unit)? = null,
    clock: Clock = Clock.System,
)
```

The local screen-state mapping type (in `core-ui` to avoid a `core-network`
dependency; consumers adapt their own `UiState`):

```kotlin
package com.testlogon.android.core.ui.state

sealed interface ScreenState<out T> {
    data object Loading : ScreenState<Nothing>
    data class Content<T>(val value: T) : ScreenState<T>
    data object Empty : ScreenState<Nothing>
    data class Error(val message: String, val offline: Boolean = false) : ScreenState<Nothing>
}

@Composable
fun <T> ScreenStateContainer(
    state: ScreenState<T>,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    emptyTitle: String = stringResource(R.string.state_empty_title),
    content: @Composable (T) -> Unit,
) {
    Box(modifier.fillMaxSize()) {
        when (state) {
            ScreenState.Loading -> LoadingState()
            ScreenState.Empty -> EmptyState(title = emptyTitle)
            is ScreenState.Error ->
                if (state.offline) OfflineBanner(onRetry = onRetry)
                else ErrorState(message = state.message, onRetry = onRetry)
            is ScreenState.Content -> content(state.value)
        }
    }
}
```

The app scaffold wrapper:

```kotlin
package com.testlogon.android.core.ui.scaffold

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScaffold(
    modifier: Modifier = Modifier,
    topBar: @Composable () -> Unit = {},
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    banner: @Composable () -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        modifier = modifier,
        topBar = topBar,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = floatingActionButton,
    ) { inner ->
        Column(Modifier.padding(inner)) {
            banner()                       // FR-4 banner region, above content
            content(PaddingValues(0.dp))   // banner consumes top inset
        }
    }
}
```

Design notes:
- `LoadingState(fullScreen=true)` centers a `CircularProgressIndicator`; with
  `fullScreen=false` it renders a compact row suitable as a Paging `LazyColumn`
  footer.
- Banners use `colorScheme.secondaryContainer` (stale) / `errorContainer`
  (offline/error) for surface and `on*Container` for content, per AND-019 tokens.
- `StaleBanner` formats `lastUpdated` as a relative string ("Updated 3m ago")
  using `clock` for testability; `null` renders a generic "Showing saved data"
  message.
- Composables target ~150-line max each; shared spacing constants come from a
  `core-ui` `Dimens` object (or theme spacing if AND-019 provides one).

## 5. API Contract

N/A — this ticket performs no network I/O and defines no endpoints. It consumes
the *result* of API calls only as already-mapped `ScreenState`/error strings.
The HTTP/cookie/session contract (POST `/ui/session/start`, MFA, `/ui/session/
finalize`, `/ui/me`, `/ui/session/refresh`, `X-CSRF-Token`) is owned by the
networking and session tickets. The FastAPI `detail` JSON shapes that drive
error-string extraction are documented in §7 because `errorMessage()` must
handle them, but no request is issued here.

## 6. Data & State Management

- **No persisted or in-memory app state** is introduced. Composables are pure
  functions of parameters; `AppScaffold` holds only ephemeral `SnackbarHostState`
  hoisted to callers when needed.
- **Consumer contract:** feature ViewModels expose `StateFlow<UiState<T>>`. The
  feature layer maps `UiState<T>` -> `ScreenState<T>` at the screen boundary:

```kotlin
fun <T> UiState<T>.toScreenState(isEmpty: (T) -> Boolean = { false }): ScreenState<T> =
    when (this) {
        is UiState.Loading -> ScreenState.Loading
        is UiState.Success ->
            if (isEmpty(data)) ScreenState.Empty else ScreenState.Content(data)
        is UiState.Failure ->
            ScreenState.Error(errorMessage(cause), offline = cause.isConnectivity())
    }
```

  (`UiState`/`ApiResult` are defined upstream; the helper above is illustrative
  and may live in `core-ui` as an extension once `core-model` is available. If
  `core-model` is not yet merged, consumers construct `ScreenState` directly.)
- **Stale vs. offline distinction:** "offline" = request failed and no cache;
  "stale" = cached `Content` is shown *plus* a `StaleBanner`. The container shows
  `OfflineBanner` only in the no-content error path; the stale path renders
  `Content` with a banner via the `AppScaffold` banner slot.
- **Configuration changes / process death:** none of these composables hold state
  that survives recomposition; survival is the ViewModel's responsibility.

## 7. Error Handling & Resilience

`ErrorState` never displays a raw throwable. A shared mapper converts errors to
user-facing copy and is unit-tested independently of Compose:

```kotlin
package com.testlogon.android.core.ui.state

fun errorMessage(t: Throwable, res: Resources? = null): String
fun Throwable.isConnectivity(): Boolean   // UnknownHost/SocketTimeout/IO/no-network
```

Rules:
- Connectivity errors (`UnknownHostException`, `SocketTimeoutException`,
  `ConnectException`, generic `IOException` with no response) -> generic offline
  copy and `offline=true`, surfaced via `OfflineBanner`/`OfflineBanner`-path.
- HTTP errors carrying a FastAPI `detail` body map per these shapes (string |
  array of `{msg}` | object `{code,...}`):

```json
{ "detail": "Invalid credentials" }
{ "detail": [ { "loc": ["body","password"], "msg": "field required" } ] }
{ "detail": { "code": "mfa_required", "message": "MFA required" } }
```

  Extraction precedence: object `.message` -> first array element `.msg` ->
  string `detail` -> HTTP-status fallback ("Something went wrong. Please try
  again."). The parsed `detail` string is passed into `ErrorState(message=...)`.
- Retry is **idempotent-only by contract**: `ErrorState`/`OfflineBanner` merely
  invoke `onRetry`; the actual retry/backoff (bounded backoff for GETs, ~20s
  timeouts) lives in the network layer. This composable adds no retry logic and
  no retry loop of its own.
- Defensive rendering: `null`/blank `message` falls back to the status default;
  `lastUpdated` in the future clamps to "just now".

## 8. Security & Privacy

- No credentials, tokens, cookies, CSRF values, or PII pass through these
  composables. Error strings are sanitized via `errorMessage()`; raw exception
  stack traces and server internals are **never** rendered to the user.
- `errorMessage()` must not echo backend `detail` content that could contain
  sensitive context for auth flows verbatim into screenshots/logs beyond the
  short user-facing message; long/unexpected detail payloads are truncated to a
  safe length (e.g. 200 chars) and never logged at INFO.
- No new permissions, no network access, no storage. The plaintext-HTTP risk of
  the dev backend is out of scope here (owned by network/cleartext-config
  tickets); these composables simply present the resulting failure states.

## 9. Accessibility & i18n

- **Content descriptions:** every decorative icon uses
  `contentDescription = null`; informative icons (error/empty) carry a localized
  description. `LoadingState` sets a `progressSemantics()`/live-region so screen
  readers announce "Loading".
- **Live regions:** `ErrorState`, `OfflineBanner`, and `StaleBanner` use
  `Modifier.semantics { liveRegion = LiveRegionMode.Polite }` so TalkBack
  announces appearance.
- **Touch targets:** Retry/action buttons are >= 48dp; `OfflineBanner` retry is a
  full-height tappable region.
- **Contrast & scaling:** colors come from AND-019 tokens (verified AA); text uses
  `MaterialTheme.typography` scales (`sp`), respecting font-scale up to 200%
  without clipping (verified by a large-font preview).
- **i18n:** all strings in `core-ui/src/main/res/values/strings.xml`
  (`state_error_title`, `action_retry`, `state_offline_message`,
  `state_stale_message`, `state_empty_title`, `state_loading`, etc.). Relative
  times via locale-aware formatting. No string concatenation for sentences;
  use placeholders.

## 10. Telemetry & Logging

- These are leaf UI composables and should not own analytics. They accept
  optional, hoisted telemetry hooks so callers can record events:
  `onRetry`/`onAction` are the natural instrumentation points (caller wraps).
- A lightweight debug log (Timber, `Log.d`) may be emitted by `errorMessage()`
  at DEBUG only, recording the throwable class and HTTP status (no `detail`
  body, no PII). No logging in release builds beyond this.
- Recommended event names for downstream wiring (not implemented here):
  `state_error_shown`, `state_error_retry_tapped`, `state_offline_shown`,
  `state_empty_shown`, with a `screen` attribute supplied by the feature.

## 11. Testing Strategy

Module: `core-ui` androidTest + unit tests; helpers from `core-testing`.

Unit (JVM, no device):
- `errorMessage()` table tests for all four `detail` shapes plus connectivity
  exceptions and the status fallback; assert truncation and null/blank handling.
- `Throwable.isConnectivity()` true/false matrix.
- `StaleBanner` relative-time formatting with a fixed `clock` (e.g.
  `Clock` fixed at a known `Instant`), including future-time clamp.

Compose UI (`createComposeRule`):
- **AC-critical:** `ErrorState` renders title/message + Retry button; performing
  click on the Retry node invokes the supplied lambda exactly once
  (`onRetry` backed by a test counter / MockK `verify(exactly = 1)`).
- `OfflineBanner` with `onRetry` non-null: retry node exists and click fires.
- `EmptyState` with `actionLabel`/`onAction`: action fires; without it, no button
  node exists.
- `LoadingState` exposes a node with the "Loading" semantics / progress role.
- `ScreenStateContainer` renders the correct child per `ScreenState` variant and
  routes its `onRetry` to the displayed Error/Offline state.
- `AppScaffold` renders banner slot above content and applies snackbar host.

Screenshot/preview:
- Light + dark previews for each composable compile and (if Paparazzi/Roborazzi
  is configured in `core-testing`) snapshot-tested; large-font-scale preview for
  `ErrorState`/`EmptyState`.

Target: 100% of public composables have a render test; both retry paths
(Error, Offline) and the Empty action path have callback-fired assertions.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-019 (Material 3 theme) — must be merged so tokens
  (`colorScheme`, `typography`, `shapes`) exist; previews wrap content in
  `TestLogonTheme`.
- **Soft/forward dependency:** `UiState`/`ApiResult` from `core-model`/
  `core-data`. If unavailable at implementation time, ship `ScreenState` and the
  composables standalone; add the `UiState.toScreenState()` extension when
  `core-model` lands (no API break to composables).
- **Blocks:** AND-042 (Backend health banner) reuses `OfflineBanner`/`StaleBanner`
  and the `AppScaffold` banner slot; AND-042 owns connectivity *detection* and
  the global, auto-dismissing banner host. Do not implement connectivity sources
  here.
- **No build/dependency additions** beyond what AND-019/core-ui already provide
  (Compose, Material 3, `kotlinx-datetime` for `Instant`/`Clock` if not already
  present — add to `core-ui` if missing).

## 13. Risks & Open Questions

- **R1 — `UiState` location/shape not finalized.** Mitigation: define
  `ScreenState` locally in `core-ui` and provide the mapping as an opt-in
  extension; revisit if `core-model` diverges.
- **R2 — Overlap with AND-042 banner ownership.** Risk of duplicate banner logic.
  Mitigation: this ticket ships *presentational* banners only; AND-042 owns the
  global host and dismissal lifecycle. Confirm the `AppScaffold` banner-slot API
  is sufficient for AND-042's auto-dismiss-on-recovery requirement.
- **R3 — Stale vs. offline semantics ambiguity.** Open question: should a
  cache-hit-with-failed-refresh always show `StaleBanner`, or only after N
  failures? Default: show on first failed refresh; revisit with product.
- **OQ1 — Illustrations vs. icons for `EmptyState`.** Default to Material icons
  now; swap to branded illustrations if design assets arrive (no API change).
- **OQ2 — `kotlinx-datetime` dependency** for `Instant`/`Clock`: confirm it is an
  acceptable `core-ui` dependency or fall back to `java.time` (minSdk 24 +
  desugaring already enabled).

## 14. Acceptance Criteria

AC-1. `LoadingState`, `EmptyState`, `ErrorState`, `OfflineBanner`, `StaleBanner`,
`AppScaffold`, and `ScreenStateContainer` exist in `core-ui` with the signatures
in §4 and compile against `TestLogonTheme`.

AC-2. **Each state composable renders** correctly in an instrumented Compose test
in both light and dark themes (per source AC: "Each state composable renders").

AC-3. **Retry callback fires** (per source AC: "retry callback fires (tested)"):
clicking Retry in `ErrorState` and in `OfflineBanner` invokes the supplied lambda
exactly once, verified by UI test; `EmptyState` action fires likewise.

AC-4. `errorMessage()` maps all three FastAPI `detail` shapes and connectivity
exceptions to non-empty, sanitized, localized strings, verified by unit tests; no
raw throwable text reaches the UI.

AC-5. `ScreenStateContainer` renders the correct surface for each `ScreenState`
variant and routes `onRetry`, verified by UI test.

AC-6. All visible strings resolve from `strings.xml`; no inline literals (verified
by lint/review). Icons have correct content descriptions; Loading/Error/banners
expose live-region or progress semantics.

AC-7. At least one feature screen (or a demo/preview harness in `core-ui`) is
wired through `AppScaffold` + `ScreenStateContainer` demonstrating end-to-end use.

## 15. Definition of Done

- All §14 acceptance criteria pass in CI on branch `android-port`.
- Code merged into `core-ui` under `com.testlogon.android.core.ui.state` and
  `com.testlogon.android.core.ui.scaffold`; no dependency on `core-network` or any
  `feature-*` module introduced.
- Unit + Compose UI tests added and green; coverage includes both retry paths and
  the empty-action path; `errorMessage()` table tests included.
- `@Preview`s (light + dark, plus a large-font preview for text-heavy states)
  render without crashing; screenshot tests pass if configured in `core-testing`.
- ktlint/detekt and Android lint clean (no hard-coded colors, no missing content
  descriptions, no inline strings).
- KDoc on every public composable and on `errorMessage()`/`ScreenState`,
  documenting hoisted callbacks and the stale-vs-offline contract.
- PR references AND-021, notes AND-019 dependency, and flags the AND-042 banner
  reuse contract for the next implementer.
