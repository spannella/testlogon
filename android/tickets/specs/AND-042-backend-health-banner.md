---
id: AND-042
title: Backend health banner
milestone: M1
epic: E06
priority: P1
size: S
status: reviewed
reviewed_on: 2026-06-06
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

**No new API surface is introduced by this ticket.** The reachability/health probe and its ping endpoint are owned by **AND-017**, which is the sole producer of `Flow<BackendStatus>`. This ticket consumes that flow and performs zero network I/O.

> **Reviewer correction (2026-06-06):** The original draft suggested AND-017 probes `/openapi.json` or a root `/healthz` route. Verified against the backend OpenAPI: there is **no** root `/healthz` endpoint. The authoritative lightweight liveness endpoint is **`GET /api/ping`** (`op=ping_api_ping_get`, response `200` with an empty/untyped JSON body, **no params, no request schema, no auth params**) — see OpenAPI index line `GET /api/ping`. A `GET /` index route also exists (`op=index__get`, `200`). The only `healthz` route is the subsystem-specific `GET /messaging/healthz` (`200`), which is **not** a general backend-health signal and should not be used by the global probe. AND-017 should prefer `GET /api/ping`. This is a §16 citation note; AND-042 itself still performs no I/O.

For reference, the upstream probe (AND-017) is expected to classify status from the result of an idempotent `GET /api/ping` with a ~20 s timeout and bounded backoff: a successful 2xx within the slow threshold → `Reachable`; a 2xx that exceeds the latency threshold or partial degradation → `Degraded`; timeout / connection failure / 5xx after retries → `Unreachable`. If AND-017's enum or threshold semantics change, the mapping in §4.3 (`toSeverity`) is the only place this ticket must be updated.

> **Reviewer note:** the `Degraded` classification (a healthy-but-slow 2xx) is an **Android-side construct**. The web reference client has no `Degraded` concept — it derives connectivity solely from the browser `navigator.onLine` signal plus the offline action queue (`src/components/shared/OfflineBanner.tsx`, `src/stores/offlineStore.ts`); it does not poll a backend health endpoint at all. The latency/degradation thresholds are therefore an unverified AND-017 design assumption, not a contract observable in the sources (see §16 Open assumptions).

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
- Banner copy must not leak host, IP, internal error strings, stack traces, or response bodies — only the generic, user-facing strings in FR-4. Specifically, the dev host base URL and any FastAPI `detail` payload are never rendered in the banner. (Note: the web client resolves its base URL from a configurable `VITE_API_BASE_URL` via `withApiBase()` in `src/api/client.ts`; the `18.222.237.167:8000` value in §1 is a dev-only convenience host, not a hardcoded contract — treat it as configuration, not a constant.)
- FastAPI `4xx`/`422` error bodies follow the `HTTPValidationError` shape — `{ detail: ValidationError[] }` where each `ValidationError` has `loc`/`msg`/`type` — and other errors a `{ detail: string | object }` shape (verified in OpenAPI `components.schemas.HTTPValidationError` / `ValidationError`; web client normalizes these via `normalizeErrorDetail` in `src/api/client.ts`). None of these payloads are surfaced by the banner.
- No PII, credentials, cookies, or `X-CSRF-Token` values are referenced by this component. (For context, the web client does attach auth state — it sends `X-CSRF-Token` read from the `ui_csrf` cookie and uses `credentials: "include"`, per `src/api/client.ts`. The health banner deliberately stays out of that path: `GET /api/ping` requires no CSRF token or session.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and an exact source pointer. Sources: OpenAPI index/full spec under `reference/`, frontend reference app under `reference/src/`, and Android framework docs (labeled `framework ref`).

1. **Claim:** AND-017's reachability probe pings a lightweight liveness endpoint.
   **VERDICT:** Corrected.
   **Source:** OpenAPI `GET /api/ping` (`op=ping_api_ping_get`, `200` with empty schema `{}`, no params, no request body). The draft's suggested `/healthz` (root) and `/openapi.json` are wrong/inappropriate: there is **no** root `/healthz`, and `/openapi.json` is the schema document. Corrected in §5.

2. **Claim:** A `healthz` route exists for general backend health.
   **VERDICT:** Corrected (scoped).
   **Source:** OpenAPI `GET /messaging/healthz` (`op=healthz_messaging_healthz_get`, `200`) is the **only** `healthz` route and is messaging-subsystem-specific, not a general backend signal. Also `GET /` (`op=index__get`, `200`) exists as a root index. Noted in §5.

3. **Claim:** `GET /api/ping` requires no auth/CSRF and returns no typed body.
   **VERDICT:** Verified.
   **Source:** OpenAPI full spec `paths./api/ping.get` — `responses.200.content.application/json.schema = {}`, no `parameters`, no `security` entry, no request body.

4. **Claim:** The web client sends `X-CSRF-Token` (from the `ui_csrf` cookie) with `credentials: "include"`; the banner must not touch this.
   **VERDICT:** Verified.
   **Source:** `src/api/client.ts` — `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, and `fetch(..., { credentials: "include" })`. §8 updated to cite this and confirm the banner stays out of the auth path.

5. **Claim:** Backend `4xx`/`422` error bodies use the `HTTPValidationError` shape `{ detail: ValidationError[] }`.
   **VERDICT:** Verified.
   **Source:** OpenAPI `components.schemas.HTTPValidationError` (`detail: array of #/components/schemas/ValidationError`) and `ValidationError` (`loc`/`msg`/`type`); web normalization in `src/api/client.ts: normalizeErrorDetail`. Used to specify real error shapes in §17 contract tests.

6. **Claim:** The web reference client surfaces backend-down state via a global banner driven by a health probe.
   **VERDICT:** Corrected / Unverified-assumption.
   **Source:** `src/components/shared/OfflineBanner.tsx` derives state from `navigator.onLine` (browser `online`/`offline` events) plus the offline action queue; `src/stores/offlineStore.ts` (`isOnline` from `navigator.onLine`). The web app does **not** poll a backend health endpoint and has **no** `Degraded` concept. The AND-042 server-health probe model is an Android-side design, not a web-app behavior. Noted in §5/§8.

7. **Claim:** `Degraded` = a healthy-but-slow 2xx classified by a latency threshold (~slow threshold, ~20 s timeout).
   **VERDICT:** Unverified-assumption.
   **Source:** Not observable in any authoritative source (no degraded concept web-side; AND-017 not yet merged). Belongs to AND-017's design. Listed under Open assumptions.

8. **Claim:** `BackendStatus` enum `{ Unknown, Reachable, Degraded, Unreachable }` and `BackendStatusMonitor.status: Flow<BackendStatus>` exist in `core-model`/AND-017.
   **VERDICT:** Unverified-assumption.
   **Source:** Upstream AND-017 ticket contract; not present in the reference sources (Android modules not in this repo snapshot). The §4.3 mapping is the single point of change if the enum differs.

9. **Claim:** The dev backend is reachable at `http://18.222.237.167:8000`.
   **VERDICT:** Unverified-assumption (config, not contract).
   **Source:** Web client resolves base URL from `VITE_API_BASE_URL` via `src/api/client.ts: withApiBase` — the host is environment configuration, not a hardcoded constant. §8 reworded accordingly.

10. **Claim:** Compose `AnimatedVisibility` with `expandVertically()/shrinkVertically()` + fade and `Modifier.semantics { liveRegion = LiveRegionMode.Polite }` provide the show/hide animation and TalkBack announcement.
    **VERDICT:** Verified (framework ref).
    **Source:** framework ref — Compose `AnimatedVisibility` (https://developer.android.com/develop/ui/compose/animation/composables-modifiers#animatedvisibility) and accessibility semantics `liveRegion` (https://developer.android.com/develop/ui/compose/accessibility/key-steps).

11. **Claim:** `collectAsStateWithLifecycle()` + `SharingStarted.WhileSubscribed(5_000)` stop collection while backgrounded and resume on return.
    **VERDICT:** Verified (framework ref).
    **Source:** framework ref — https://developer.android.com/topic/architecture/ui-layer/state-production#stateflow and lifecycle-aware collection https://developer.android.com/topic/libraries/architecture/coroutines#statein.

12. **Claim:** `flatMapLatest` cancels the in-flight settle `delay` when severity flips back to visible, holding the banner up through transient recovery (FR-5).
    **VERDICT:** Verified (framework ref).
    **Source:** framework ref — kotlinx.coroutines `Flow.flatMapLatest` cancels the previous inner flow on each new upstream emission (https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/flat-map-latest.html). Logic in §4.3 is internally consistent with this.

### Corrections made

- **§5:** Replaced the probe-endpoint guess (`/openapi.json` / root `/healthz`) with the verified `GET /api/ping`; documented that root `/healthz` does not exist and that `GET /messaging/healthz` is subsystem-scoped (claims 1, 2, 3).
- **§5:** Added a note that `Degraded` and the latency thresholds are an Android-side construct with no web-app equivalent (claims 6, 7).
- **§8:** Reworded the `18.222.237.167:8000` reference to "configurable base URL (`VITE_API_BASE_URL`/`withApiBase`)" rather than a hardcoded host (claim 9); added the verified `X-CSRF-Token`/`ui_csrf`/`credentials: "include"` context and confirmed the banner stays out of the auth path (claim 4); specified the real `HTTPValidationError` error shape (claim 5).

### Open assumptions

- **AND-017 enum and monitor surface** (`BackendStatus`, `BackendStatusMonitor.status`): unverifiable here — defined in upstream AND-017, not in the reference snapshot. Mapping is isolated to §4.3.
- **`Degraded` semantics / latency thresholds (~slow threshold, ~20 s timeout):** unverifiable — no degraded concept exists web-side; this is an AND-017 design decision (claim 7).
- **Dev host `18.222.237.167:8000`:** environment configuration, not a contract; the actual base URL is injected at build/runtime (claim 9).
- **AND-021 surfaces** (`AppScaffold`, `OfflineBanner` styling primitives): upstream Android ticket, not present in the reference sources; integration in §4.5 assumes the documented slot.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric (no device); **emu(test35)** = headless emulator AVD `test35` (x86_64, Android 15 / API 35) for fast CI UI/instrumented suites; **device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). This ticket is pure Compose UI + Flow logic with **no** camera/biometric/FCM/WebRTC/Telecom/streaming surface, so most cases run on JVM or the emulator; the physical device is used only for the real-network/flaky-host integration path and the API-34 reduced-motion accessibility check (real-hardware behavior that the x86 emulator does not faithfully reproduce).

- **TC-AND-042-01** — Happy path: down → banner shown.
  Type: unit. Target: JVM.
  Preconditions: `HealthBannerViewModel` wired to a fake `BackendStatusMonitor` flow; Turbine + `kotlinx-coroutines-test`.
  Steps: emit `BackendStatus.Unreachable`.
  Expected: `uiState` emits `visible=true`, `severity=Unreachable`, `messageRes=R.string.health_banner_unreachable`, with **zero** virtual-time advance (show path is immediate).
  Traces: AC-1, AC-3.

- **TC-AND-042-02** — Degraded copy/severity mapping.
  Type: unit. Target: JVM.
  Preconditions: as 01.
  Steps: emit `BackendStatus.Degraded`.
  Expected: `visible=true`, `severity=Degraded`, `messageRes=R.string.health_banner_degraded`, immediate.
  Traces: AC-2.

- **TC-AND-042-03** — Recovery auto-hide observes the 1500 ms settle window.
  Type: unit. Target: JVM.
  Preconditions: as 01; start from `Unreachable` (visible).
  Steps: emit `Reachable`; `advanceTimeBy(1499)` assert still `visible=true`; `advanceTimeBy(1)` (total 1500) then assert.
  Expected: banner remains visible until 1500 ms elapse, then `visible=false`, `severity=None`.
  Traces: AC-3.

- **TC-AND-042-04** — Anti-flap: recovery cancelled within the settle window keeps banner up.
  Type: unit. Target: JVM.
  Preconditions: start from `Unreachable` (visible).
  Steps: emit `Reachable`; `advanceTimeBy(800)`; emit `Unreachable` again; advance well past 1500 ms.
  Expected: `visible=true` throughout (no `visible=false` ever emitted); confirms `flatMapLatest` cancels the pending hide delay (FR-5).
  Traces: AC-3.

- **TC-AND-042-05** — Unknown at cold start = hidden.
  Type: unit. Target: JVM.
  Preconditions: fresh ViewModel (initial `HealthBannerUiState()`).
  Steps: emit `BackendStatus.Unknown` (or no emission yet).
  Expected: `visible=false`, `severity=None`; no banner before first non-Reachable result.
  Traces: AC-1 (R-3 behavior).

- **TC-AND-042-06** — Upstream flow error degrades to hidden, no crash.
  Type: unit. Target: JVM.
  Preconditions: fake monitor whose `status` throws after one emission; `.catch { emit(Unknown) }` per §7.
  Steps: emit `Unreachable` (banner up), then make the flow error.
  Expected: no exception propagates; final state `visible=false`; throwable logged (verify via injected logger/fake).
  Traces: AC-7.

- **TC-AND-042-07** — Telemetry fires only on confirmed transitions.
  Type: unit. Target: JVM.
  Preconditions: ViewModel with a fake analytics sink; start `Reachable`.
  Steps: `Unreachable` → flap to `Reachable` for 800 ms → `Unreachable` (within settle) → finally `Reachable` held > 1500 ms.
  Expected: exactly one `health_banner_shown{severity:"unreachable"}` and exactly one `health_banner_dismissed_auto{outage_ms>0}`; the transient mid-flap recovery emits nothing.
  Traces: AC-3 (no flap inflation; supports §10).

- **TC-AND-042-08** — Compose UI acceptance: shows on down, hides on recovery (gating).
  Type: Compose-UI. Target: emu(test35).
  Preconditions: `createComposeRule()`; `GlobalHealthBanner`/`HealthBannerHost` fed by a fake `BackendStatusMonitor`.
  Steps: `setStatus(Unreachable)` → assert unreachable string node `assertIsDisplayed()`; `setStatus(Reachable)`, advance past settle → re-assert.
  Expected: unreachable text displayed when down; after recovery + settle `assertDoesNotExist()` (or `assertIsNotDisplayed()`). Directly satisfies the backlog AC.
  Traces: AC-1, AC-3.

- **TC-AND-042-09** — Compose UI: degraded copy + severity styling rendered.
  Type: Compose-UI. Target: emu(test35).
  Preconditions: as 08.
  Steps: `setStatus(Degraded)`.
  Expected: degraded string displayed; tertiaryContainer color role and `SyncProblem` icon present (assert via test tag / semantics).
  Traces: AC-2.

- **TC-AND-042-10** — Single global instance, no per-screen wiring.
  Type: Compose-UI. Target: emu(test35).
  Preconditions: host two distinct screen contents inside one `AppScaffold` with `HealthBannerHost`; navigate between them with status `Unreachable`.
  Steps: assert banner node count; navigate; re-assert.
  Expected: exactly one banner node exists app-wide and persists across navigation destinations.
  Traces: AC-4.

- **TC-AND-042-11** — Accessibility: polite live region + contentDescription; decorative icon.
  Type: Compose-UI (semantics). Target: emu(test35).
  Preconditions: banner visible (`Unreachable`).
  Steps: query the semantics tree.
  Expected: container node has `liveRegion = Polite` and a non-null `contentDescription` equal to the message; the icon node has no contentDescription.
  Traces: AC-6.

- **TC-AND-042-12** — No network I/O / no auth dependency in the banner path.
  Type: contract/MockWebServer. Target: JVM (Robolectric/MockWebServer).
  Preconditions: instantiate `HealthBannerViewModel` with a `MockWebServer` available but **no** request enqueued/dispatcher installed for it; drive only the fake `BackendStatus` flow.
  Steps: cycle `Unreachable → Reachable`; after the test, inspect `MockWebServer.requestCount`.
  Expected: `requestCount == 0` — the banner issues zero requests and never reads cookies/`X-CSRF-Token`; confirms it is purely reactive.
  Traces: AC-5.

- **TC-AND-042-13** — Integration over the real probe against a flaky/offline host.
  Type: integration / instrumented (real network). Target: **device(A15) — MUST run on physical device.**
  Preconditions: AND-017 probe wired to a `MockWebServer` (or the dev host) reachable over the device's real network stack; banner hosted in `AppScaffold`. Run on the A15 (arm64, API 34) to exercise real OkHttp socket/timeout behavior and Android 14 background-network constraints rather than the emulator's virtualized loopback.
  Steps: enqueue connection failures / a delayed-then-200 sequence to simulate the flaky dev host; observe banner; then enqueue steady 200s.
  Expected: banner shows on failures/timeout (`Unreachable`), stays up through a single transient 200 inside the settle window, then auto-hides after sustained recovery; no flapping. Note the real ~20 s timeout path is exercised here, not faked.
  Traces: AC-1, AC-3, AC-5.

- **TC-AND-042-14** — Reduced-motion / contrast accessibility on real hardware.
  Type: instrumented (manual-assisted accessibility). Target: **device(A15) — physical device** (real "Remove animations" system setting + real display).
  Preconditions: enable Settings → Accessibility → Remove animations on the A15; TalkBack on.
  Steps: trigger `Unreachable` then `Reachable`; observe transition and TalkBack announcement in both light and dark themes.
  Expected: state still conveyed by icon + text (not motion alone); banner appears/disappears correctly with animations suppressed; TalkBack announces the message without stealing focus; container/on-container color pairs meet WCAG AA in light and dark.
  Traces: AC-2, AC-6.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (shows on Unreachable, hides on Reachable; UI-tested) | TC-01, TC-05, TC-08, TC-13 |
| AC-2 (Degraded copy + severity styling) | TC-02, TC-09, TC-14 |
| AC-3 (auto-dismiss; immediate show, 1500 ms settle hide) | TC-01, TC-03, TC-04, TC-07, TC-08, TC-13 |
| AC-4 (exactly one global instance; no per-screen wiring) | TC-10 |
| AC-5 (no network I/O; derives from AND-017 flow) | TC-12, TC-13 |
| AC-6 (strings externalized; polite live region + contentDescription) | TC-11, TC-14 |
| AC-7 (upstream error → hidden, no crash) | TC-06 |
