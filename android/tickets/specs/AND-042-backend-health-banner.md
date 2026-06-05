---
id: AND-042
title: Backend health banner
milestone: M1
epic: E06
priority: P1
size: S
status: draft
depends_on: [AND-017, AND-021]
blocks: []
---

# AND-042 — Backend health banner

## 1. Overview & Goal

The TestLogon dev backend (`http://18.222.237.167:8000`) is a plaintext HTTP host that is frequently slow, degraded, or fully unreachable. When the backend is down, screens silently fail with empty or error states that the user cannot distinguish from a genuine "no data" condition, and there is no single, app-wide indication that the *server*, rather than a specific feature, is the problem.

This ticket delivers a single global health banner that is rendered once at the root of the app `Scaffold` and is driven entirely by the `Flow<BackendStatus>` produced by AND-017. The banner appears whenever the backend is unreachable or degraded, communicates the condition in plain language, and auto-dismisses the moment the probe reports recovery. It does not own any networking, polling, or reachability logic — it is a thin, reactive presentation layer over the existing health probe and the existing offline/stale banner composable from AND-021.

Goal: a deterministic, UI-tested, reactive banner — driven by `BackendStatus` — that becomes visible on `Unreachable`/`Degraded` and hides on `Reachable`, with no per-screen wiring required.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/` on branch `android-port`. Namespace/applicationId base `com.testlogon.android`.
- **Upstream — AND-017 (Connectivity & backend health probe):** owns the reachability monitor and exposes `Flow<BackendStatus>`. This ticket *consumes* that flow; it does not create probing logic. The `BackendStatus` type is the authoritative contract source.
- **Upstream — AND-021 (State composables):** owns the standard `Loading`/`Empty`/`Error`/`Offline` composables and the app `Scaffold` wrapper (`AppScaffold`). The health banner is hosted inside that wrapper and reuses the `OfflineBanner` styling primitives defined there for visual consistency.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt DI (KSP), Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17.
- **Module placement:** banner UI lives in `core-ui` (so any feature hosted under `AppScaffold` benefits); the status-to-banner state mapping ViewModel lives in `app` (root composition scope) or `core-ui` if a Hilt entry point is available there. Probe lives in `core-data`/`core-network` per AND-017.
- **Backend:** FastAPI; OpenAPI at `/openapi.json`. No new endpoint is introduced by this ticket — see §5.

## 3. Functional Requirements

FR-1. A single banner is rendered at the application root, above the per-screen content but below any modal/dialog scrim, inside the AND-021 `AppScaffold`. It is global: exactly one instance exists regardless of the current navigation destination.

FR-2. The banner is **visible** when the latest `BackendStatus` is `Unreachable` or `Degraded`, and **hidden** when the latest status is `Reachable` (or before the first probe result while status is `Unknown` — treated as not-yet-degraded, banner hidden).

FR-3. The banner auto-dismisses on recovery: when status transitions to `Reachable`, the banner animates out without user action. No manual dismiss control is provided in v1 (the condition is server-side and self-resolving); a user-dismiss affordance is an open question (§13).

FR-4. Banner copy is condition-specific:
- `Unreachable` → "Can't reach the server. Showing saved data where available."
- `Degraded` → "The server is responding slowly. Some actions may fail or be delayed."

FR-5. To avoid flicker on a flaky host, visibility changes are debounced: a transition *into* a banner-visible state is shown immediately, but a transition *to* `Reachable` (hide) is held for a short settle window (default 1500 ms) so a single recovered probe between failures does not flap the banner. The show path is not debounced (fail fast, recover slow).

FR-6. The banner must not block interaction with screen content beneath it; it is a non-modal inset at the top of the content area and participates in window insets correctly (does not overlap the status bar or app bar).

FR-7. The banner is purely reactive — it triggers no network calls of its own. The only retry mechanism is the AND-017 probe and any per-screen retry from AND-021.

## 4. Technical Design

### 4.1 Status contract (consumed from AND-017)

```kotlin
// core-model (owned by AND-017) — referenced, not defined here
enum class BackendStatus { Unknown, Reachable, Degraded, Unreachable }
```

### 4.2 Banner UI state

```kotlin
// core-ui
data class HealthBannerUiState(
    val visible: Boolean = false,
    val severity: Severity = Severity.None,
    val messageRes: Int = 0,
) {
    enum class Severity { None, Degraded, Unreachable }
}
```

### 4.3 ViewModel — status-to-banner mapping with settle debounce

```kotlin
@HiltViewModel
class HealthBannerViewModel @Inject constructor(
    backendStatus: BackendStatusMonitor, // AND-017 surface, exposes Flow<BackendStatus>
) : ViewModel() {

    private val settleMillis = 1_500L

    val uiState: StateFlow<HealthBannerUiState> =
        backendStatus.status
            .map { it.toSeverity() }
            .distinctUntilChanged()
            .flatMapLatest { severity ->
                // Hide path (severity == None) is delayed; show path is immediate.
                if (severity == HealthBannerUiState.Severity.None) {
                    flow { delay(settleMillis); emit(severity) }
                } else {
                    flowOf(severity)
                }
            }
            .map { it.toUiState() }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), HealthBannerUiState())

    private fun BackendStatus.toSeverity() = when (this) {
        BackendStatus.Unreachable -> HealthBannerUiState.Severity.Unreachable
        BackendStatus.Degraded    -> HealthBannerUiState.Severity.Degraded
        BackendStatus.Reachable,
        BackendStatus.Unknown     -> HealthBannerUiState.Severity.None
    }

    private fun HealthBannerUiState.Severity.toUiState(): HealthBannerUiState = when (this) {
        HealthBannerUiState.Severity.None ->
            HealthBannerUiState(visible = false, severity = this, messageRes = 0)
        HealthBannerUiState.Severity.Degraded ->
            HealthBannerUiState(true, this, R.string.health_banner_degraded)
        HealthBannerUiState.Severity.Unreachable ->
            HealthBannerUiState(true, this, R.string.health_banner_unreachable)
    }
}
```

`flatMapLatest` guarantees the settle delay is cancelled if status flips back to a visible severity during the window, so the banner stays up through transient recoveries (satisfies FR-5).

### 4.4 Composables

```kotlin
@Composable
fun GlobalHealthBanner(
    state: HealthBannerUiState,
    modifier: Modifier = Modifier,
)

@Composable
fun HealthBannerHost(
    viewModel: HealthBannerViewModel = hiltViewModel(),
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GlobalHealthBanner(state = state, modifier = modifier)
}
```

`GlobalHealthBanner` wraps content in `AnimatedVisibility` with `expandVertically()/shrinkVertically()` + fade so show/hide is animated. It maps `severity` to Material 3 colors: `Unreachable` → `errorContainer`/`onErrorContainer`; `Degraded` → `tertiaryContainer`/`onTertiaryContainer`. A leading icon (`Icons.Filled.CloudOff` / `Icons.Filled.SyncProblem`) precedes the text. The composable takes a stateless `state` argument so it is trivially testable and previewable.

### 4.5 Integration into AppScaffold (AND-021)

```kotlin
// core-ui — AppScaffold provided by AND-021; this ticket adds the HealthBannerHost slot
@Composable
fun AppScaffold(/* existing params */ content: @Composable (PaddingValues) -> Unit) {
    Scaffold(/* ... */) { padding ->
        Column(Modifier.padding(padding)) {
            HealthBannerHost(modifier = Modifier.fillMaxWidth())
            content(PaddingValues(0.dp)) // banner is part of the top inset
        }
    }
}
```

The banner sits above per-screen content so it never overlaps the system status bar or top app bar, satisfying FR-6.

## 5. API Contract

**No new API surface is introduced by this ticket.** The reachability/health probe and any `GET` ping endpoint (e.g. a lightweight HEAD/GET against `/openapi.json` or a `/healthz`-style route) are owned by **AND-017**, which is the sole producer of `Flow<BackendStatus>`. This ticket consumes that flow and performs zero network I/O.

For reference, the upstream probe (AND-017) classifies status from the result of an idempotent `GET` with a ~20 s timeout and bounded backoff: a successful 2xx within the slow threshold → `Reachable`; a 2xx that exceeds the latency threshold or partial degradation → `Degraded`; timeout / connection failure / 5xx after retries → `Unreachable`. If AND-017's enum or threshold semantics change, the mapping in §4.3 (`toSeverity`) is the only place this ticket must be updated.

## 6. Data & State Management

- **Source of truth:** `BackendStatusMonitor.status: Flow<BackendStatus>` (AND-017), a hot/shared flow updated by the probe loop.
- **Derived UI state:** `HealthBannerUiState` via `StateFlow` from `HealthBannerViewModel`, scoped to the root composition (`hiltViewModel()` at the `AppScaffold` host).
- **No persistence:** banner state is ephemeral and fully derived; nothing is written to Room or DataStore. On process death the banner state is rebuilt from the first probe emission after restart (initial value `HealthBannerUiState()` → hidden until first non-`Reachable` result).
- **Lifecycle:** `collectAsStateWithLifecycle()` + `SharingStarted.WhileSubscribed(5_000)` ensures the mapping flow stops collecting when the app is backgrounded and resumes (re-evaluating against the latest probe state) on return, avoiding a stale banner after long backgrounding.
- **Threading:** all mapping runs on the default dispatcher inside `viewModelScope`; collection on the main thread via lifecycle-aware collection.

## 7. Error Handling & Resilience

- The banner *is* the resilience UX for backend failure; it has no failure mode of its own that surfaces to the user. If the upstream `status` flow errors, the ViewModel applies `.catch { emit(BackendStatus.Unknown) }` upstream of the mapping so a probe-layer crash degrades to "banner hidden" rather than crashing the app, and logs the throwable (see §10).
- **Flicker control:** the settle debounce (FR-5, §4.3) prevents banner flapping on an intermittently reachable host — the dominant real-world condition for this dev backend.
- **Fail-fast / recover-slow:** show is immediate (1 failing probe shows the banner) but hide waits the settle window, so users are warned promptly and the warning does not blink off on a single lucky probe.
- **No retry storms:** because the banner performs no I/O, there is no risk of it amplifying load against the already-unreliable host.

## 8. Security & Privacy

- No new data is collected, transmitted, or persisted. The banner reads an in-memory enum.
- Banner copy must not leak host, IP, internal error strings, stack traces, or response bodies — only the generic, user-facing strings in FR-4. Specifically, the raw dev host `18.222.237.167:8000` and any FastAPI `detail` payload are never rendered in the banner.
- No PII, credentials, cookies, or `X-CSRF-Token` values are referenced by this component.
- Telemetry events (§10) record only the coarse `BackendStatus` enum value and timestamps — no request/response content.

## 9. Accessibility & i18n

- **i18n:** all copy in `strings.xml` (`health_banner_unreachable`, `health_banner_degraded`); no hardcoded strings in composables. Banner layout uses wrapping `Text` (no truncation) so longer translations remain fully readable.
- **a11y / TalkBack:** the banner container sets `Modifier.semantics { liveRegion = LiveRegionMode.Polite; contentDescription = <message> }` so screen readers announce appearance/disappearance without stealing focus. The leading icon is decorative (`contentDescription = null`).
- **Contrast:** color pairs use Material 3 container/on-container roles, which meet WCAG AA contrast in both light and dark themes; verified in both.
- **Motion:** the expand/shrink + fade animation respects the system "remove animations" setting via Compose's reduced-motion handling; the banner never relies on motion alone to convey state (icon + text carry the meaning).

## 10. Telemetry & Logging

- **Structured log (debug builds):** on each *committed* visibility transition, `Log.i("HealthBanner", "status -> ${severity}, visible=${visible}")`. No payloads.
- **Analytics events** (via the app's analytics abstraction, fire-and-forget):
  - `health_banner_shown` with `{ severity: "degraded"|"unreachable" }`
  - `health_banner_dismissed_auto` with `{ outage_ms: Long }` (duration the banner was visible)
- These enable measuring backend-outage frequency and duration as experienced by the client without any content logging. Events fire from the ViewModel on confirmed (post-debounce) transitions only, so flapping does not inflate counts.

## 11. Testing Strategy

**Unit (core-testing, JVM, `kotlinx-coroutines-test` + Turbine):**
- `HealthBannerViewModel` maps `Unreachable`/`Degraded`/`Reachable`/`Unknown` to the correct `HealthBannerUiState` (visible flag, severity, messageRes).
- Settle debounce: feeding `Unreachable → Reachable` then `Unreachable` again within 1500 ms keeps `visible = true` throughout (using `advanceTimeBy`); a clean `Unreachable → Reachable` held past 1500 ms yields `visible = false`.
- Show path is immediate: `Reachable → Unreachable` flips `visible = true` with zero virtual-time advance.
- Upstream error → `Unknown` → banner hidden (no crash).

**Compose UI test (this ticket's primary acceptance gate, AndroidX Compose test rule):**
- Given a fake `BackendStatusMonitor` flow, asserting:
  - `setStatus(Unreachable)` → node with the unreachable string `assertIsDisplayed()`.
  - `setStatus(Reachable)` (after settle) → `assertDoesNotExist()` / `assertIsNotDisplayed()` — **directly satisfies AC "Banner shows when host down, hides on recovery (UI-tested)."**
  - `setStatus(Degraded)` → degraded string displayed.
- Semantics: live-region and contentDescription present when visible.

**Integration (optional, MockWebServer):** drive AND-017's real probe against a `MockWebServer` that is enqueued with failures then a 200, and assert the banner shows then auto-hides end-to-end through the real flow (mirrors AND-017's MockWebServer test harness).

## 12. Dependencies & Sequencing

- **Hard depends on AND-017** — provides `BackendStatusMonitor`/`Flow<BackendStatus>` and the `BackendStatus` enum in `core-model`. This ticket cannot start until that contract is merged. If AND-017 lands with a different enum shape, only §4.3 mapping changes.
- **Hard depends on AND-021** — provides `AppScaffold` (the host slot) and `OfflineBanner` styling primitives reused for visual consistency. The `HealthBannerHost` is inserted into the AND-021 scaffold.
- **Blocks:** none currently.
- **Sequencing:** implement after both deps merge to `android-port`. Order within this ticket: (1) `HealthBannerUiState` + ViewModel + unit tests; (2) `GlobalHealthBanner`/`HealthBannerHost` composables + previews; (3) wire into `AppScaffold`; (4) Compose UI acceptance test; (5) telemetry + a11y pass.

## 13. Risks & Open Questions

- **R-1 (flicker on flaky host):** the dev backend flaps frequently; mitigated by the settle debounce (§4.3, §4.5). Open: is 1500 ms the right window? Should it be configurable via DataStore? Default ships hardcoded; revisit if QA reports flapping.
- **R-2 (overlap with per-screen offline state):** AND-021 also shows per-screen offline/stale banners. Risk of double messaging. Decision: global banner = server health (host down/degraded); AND-021 per-screen banner = stale/cached data context. They are complementary; confirm with design that simultaneous display is acceptable, or suppress the global banner's text when a screen already shows a stale banner.
- **R-3 (Unknown at cold start):** treating `Unknown` as hidden means a genuinely-down backend shows nothing until the first probe completes (~up to 20 s). Acceptable for v1; per-screen states cover the gap.
- **OQ-1:** Should users be able to manually dismiss the banner? v1 says no (condition is self-resolving). Revisit if user testing shows the banner is intrusive.
- **OQ-2:** Should `Degraded` be surfaced at all, or only `Unreachable`? Current design surfaces both with distinct copy/severity; confirm with product.

## 14. Acceptance Criteria

- **AC-1 (from backlog):** Banner is displayed when the backend host is down (`BackendStatus.Unreachable`) and is hidden on recovery (`BackendStatus.Reachable`), verified by an automated Compose UI test (§11) — this is the gating criterion.
- **AC-2:** Banner appears on `Degraded` with degraded-specific copy and severity styling.
- **AC-3:** Recovery auto-dismisses the banner with no user action; the show path is immediate and the hide path observes the 1500 ms settle window (unit-tested with virtual time).
- **AC-4:** Exactly one banner instance exists app-wide (hosted in `AppScaffold`); no per-screen wiring is required for the banner to function.
- **AC-5:** Banner performs no network I/O; it derives entirely from the AND-017 flow (verified by absence of network dependencies in the ViewModel).
- **AC-6:** All copy is in `strings.xml`; the banner exposes a polite live region and contentDescription for TalkBack.
- **AC-7:** Upstream flow error degrades to "banner hidden" without crashing (unit-tested).

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android` with `HealthBannerViewModel`, `HealthBannerUiState`, `GlobalHealthBanner`, and `HealthBannerHost` in the correct modules (`core-ui` / `app`), wired into the AND-021 `AppScaffold`.
- Unit tests and the Compose UI acceptance test (AC-1) pass in CI; coverage includes show/hide, debounce, degraded, and error-to-hidden paths.
- Strings externalized; light + dark theme contrast and TalkBack announcement verified.
- Telemetry events (`health_banner_shown`, `health_banner_dismissed_auto`) emitting on confirmed transitions; no payload/PII logged.
- Ktlint/detekt clean; no hardcoded host strings or `detail` payloads rendered.
- §13 open questions OQ-1/OQ-2 and R-2 resolved with design/product or explicitly deferred with a follow-up note; reviewer-approved PR.
