---
id: AND-328
title: Screening
milestone: M7
epic: E42
priority: P2
size: S
status: draft
depends_on: [AND-319]
blocks: []
---

# AND-328 — Screening

## 1. Overview & Goal

This ticket delivers the read-only presentation of the customer's KYC **screening**
status (`kycScreening`) inside the TestLogon native Android app. Screening is the
backend's sanctions / PEP / adverse-media / watchlist check that runs as part of the
KYC lifecycle. The user cannot *act* on screening directly (it is an automated,
backend-driven evaluation), but they must be able to *see* where they stand: whether
screening is pending, cleared, under manual review, or has produced a hit that blocks
further onboarding.

The goal is a single, well-tested Compose surface that consumes the already-typed KYC
DTOs from **AND-319** (`/v1/kyc/*`) and renders the `kycScreening` status with correct
visual treatment, accurate state mapping, and resilient offline/stale behavior against
the unreliable dev backend. No new network endpoints are introduced by this ticket; the
data already arrives via the KYC requirements/evaluate payloads modeled in AND-319.

Acceptance per backlog: **"Screening status renders."** This spec makes that concrete:
every documented `kycScreening` status value maps to a deterministic, accessible UI
state with loading, error, and stale variants.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- **Namespace:** `com.testlogon.android`. This ticket lives in
  `feature-kyc` (`com.testlogon.android.feature.kyc.screening`) and consumes
  `core-model`, `core-data`, `core-network`, `core-ui`.
- **Upstream dependency — AND-319 (P0):** owns the KYC API client, the `/v1/kyc/*`
  endpoints, and all DTO ↔ domain mapping (tiers/me, requirements, evaluate, cases).
  `kycScreening` is one field within those payloads. AND-328 does **not** define DTOs;
  it consumes the domain models AND-319 exposes and adds only the presentation layer.
- **Sibling tickets in E42 / M7:** AND-327 (Proof of funds), AND-321 (KYC submission
  flow). Screening is a *status-only* sibling of those interactive sub-flows and shares
  the same KYC repository and the same status-chip visual vocabulary in `core-ui`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. Auth is cookie-based with `ui_csrf`
  echoed via `X-CSRF-Token`; the OkHttp stack (AND-027 era) already supplies the
  persistent cookie jar, CSRF interceptor, 20s timeouts, and single-shot
  `/ui/session/refresh` on 401.
- **Web reference:** `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`
  are the authority for the exact `kycScreening` enum spelling. The Android enum mapper
  (in AND-319) must mirror those string literals; this ticket assumes that mapping and
  surfaces an explicit `UNKNOWN` fallback for forward compatibility.

## 3. Functional Requirements

1. **FR-1 — Render screening status.** Given a loaded KYC payload, the screen displays
   the `kycScreening` status as a labeled status chip plus a short human-readable
   description and (where applicable) a guidance line.
2. **FR-2 — Cover all statuses.** Each `KycScreeningStatus` value renders a distinct
   label, color token, and description: `NOT_STARTED`, `PENDING`/`IN_PROGRESS`,
   `CLEAR`, `REVIEW` (manual review), `HIT` (potential match / blocked), and `UNKNOWN`.
3. **FR-3 — Loading state.** While the first fetch is in flight and no cached data
   exists, show a skeleton/placeholder for the status card.
4. **FR-4 — Empty / not-applicable.** If the payload omits `kycScreening` (null), render
   `NOT_STARTED` with copy explaining screening has not yet been initiated.
5. **FR-5 — Error state.** On a fetch failure with no cached value, show an error card
   with a **Retry** action.
6. **FR-6 — Stale/offline state.** If cached screening data exists but the latest
   refresh failed or the device is offline, render the last-known status with a
   non-blocking "Showing saved status — last updated {timestamp}" banner.
7. **FR-7 — Pull-to-refresh / manual refresh.** The user can trigger a re-fetch; this
   re-reads the KYC payload (idempotent GET) and updates the displayed status.
8. **FR-8 — Auto-refresh for transient states.** When status is `PENDING`/`IN_PROGRESS`,
   the screen schedules a single bounded re-poll on resume (not a tight loop) so a
   user returning to the screen sees fresh progress.
9. **FR-9 — Deep-link entry.** The screen is reachable from the KYC hub via a
   Navigation-Compose route `kyc/screening` and as a standalone destination.

## 4. Technical Design

Single-Activity, Navigation-Compose, Hilt-injected MVVM. No new persistence schema:
screening reuses the KYC cache row written by AND-319's repository.

**Domain model (owned by AND-319, referenced here):**

```kotlin
// core-model — defined in AND-319, consumed by AND-328
enum class KycScreeningStatus {
    NOT_STARTED, PENDING, IN_PROGRESS, CLEAR, REVIEW, HIT, UNKNOWN
}

data class KycScreening(
    val status: KycScreeningStatus,
    val updatedAt: Instant?,     // last evaluation time, if provided
    val reason: String?          // optional backend note for REVIEW/HIT
)
```

**Repository accessor (extends AND-319's `KycRepository`):**

```kotlin
interface KycRepository {
    // existing AND-319 surface returns the full KYC snapshot
    fun observeKyc(): Flow<KycSnapshot>                 // cache-backed, hot
    suspend fun refreshKyc(): ApiResult<KycSnapshot>    // forces network GET
}
```

`KycSnapshot` already contains `screening: KycScreening?` (mapped in AND-319). AND-328
adds **no** new repository methods; it derives a screening-only projection in the
ViewModel.

**ViewModel:**

```kotlin
@HiltViewModel
class ScreeningViewModel @Inject constructor(
    private val kycRepository: KycRepository,
    private val clock: Clock,
) : ViewModel() {

    val uiState: StateFlow<ScreeningUiState> =
        kycRepository.observeKyc()
            .map { snapshot -> snapshot.toScreeningUiState(clock) }
            .catch { emit(ScreeningUiState.Error(it.toUserMessage())) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000),
                     ScreeningUiState.Loading)

    fun refresh() { viewModelScope.launch { kycRepository.refreshKyc() } }

    fun onResume() {
        // FR-8: re-poll once if currently transient
        if ((uiState.value as? ScreeningUiState.Content)?.isTransient == true) refresh()
    }
}
```

**UI state:**

```kotlin
sealed interface ScreeningUiState {
    data object Loading : ScreeningUiState
    data class Content(
        val status: KycScreeningStatus,
        val title: String,
        val description: String,
        val guidance: String?,
        val updatedAtLabel: String?,
        val isStale: Boolean,
        val isTransient: Boolean,      // PENDING / IN_PROGRESS
    ) : ScreeningUiState
    data class Error(val message: String) : ScreeningUiState
}
```

**Composables:**

```kotlin
@Composable fun ScreeningRoute(viewModel: ScreeningViewModel = hiltViewModel())
@Composable fun ScreeningScreen(state: ScreeningUiState,
                                onRetry: () -> Unit,
                                onRefresh: () -> Unit)
@Composable fun ScreeningStatusCard(content: ScreeningUiState.Content)
```

`ScreeningStatusCard` uses a shared `StatusChip` from `core-ui` keyed off a
`statusTone(status): StatusTone` mapping (Neutral/Info/Success/Warning/Error). The
mapping is the single source of color truth so AND-327 and the wider KYC hub stay
visually consistent.

## 5. API Contract

This ticket introduces **no new endpoints**. The screening field is delivered inside the
KYC snapshot fetched by **AND-319**, primarily via the requirements/evaluate response:

- `GET /v1/kyc/me` (or `/v1/kyc/requirements`, per AND-319's mapping) — idempotent GET.

Representative response fragment (the only part AND-328 reads):

```json
{
  "kycTier": "tier1",
  "kycScreening": {
    "status": "review",
    "updatedAt": "2026-06-04T17:22:09Z",
    "reason": "Manual analyst review in progress"
  }
}
```

String-literal mapping (mirrors `frontend/src/api/types.ts`), implemented in AND-319 and
asserted by AND-328's tests:

| Wire value (`status`) | `KycScreeningStatus` |
|-----------------------|----------------------|
| `"not_started"` / null| `NOT_STARTED`        |
| `"pending"`           | `PENDING`            |
| `"in_progress"`       | `IN_PROGRESS`        |
| `"clear"` / `"passed"`| `CLEAR`              |
| `"review"`            | `REVIEW`             |
| `"hit"` / `"flagged"` | `HIT`                |
| anything else         | `UNKNOWN`            |

Error envelope follows the project-standard FastAPI `detail` mapping
(`string | [{msg}] | {code,...}`) handled by `core-network`'s `ApiResult<T>` and the
shared `Throwable.toUserMessage()`; no screening-specific error codes are defined.

## 6. Data & State Management

- **Cache:** Reuses AND-319's Room-backed KYC cache (`kyc_snapshot` row, single-user).
  No new Room entity, DAO, or migration is added by this ticket.
- **Source of truth:** `observeKyc()` emits the cached snapshot immediately, then the
  repository updates the cache on a successful `refreshKyc()`, which re-emits.
- **Projection:** `KycSnapshot.toScreeningUiState(clock)` is a pure function (unit-tested
  in isolation) that maps status → labels, formats `updatedAt` relative to `clock`, and
  sets `isStale` (cache served but last refresh failed/older than a freshness window) and
  `isTransient`.
- **DataStore:** Not used by this ticket. No user-tunable preferences are involved.
- **Process death:** State is fully derived from the cache + repository flow, so it
  rehydrates on recreation; no `SavedStateHandle` keys are required beyond the nav route.

## 7. Error Handling & Resilience

- **Timeouts/retry:** Inherited from the OkHttp stack — ~20s call timeout; bounded
  exponential backoff retry applies to the idempotent KYC GET only. AND-328 adds no
  custom retry logic.
- **401:** Handled transparently by the session-refresh interceptor
  (`POST /ui/session/refresh` once, then retry). The screen never shows an auth error for
  a recoverable 401.
- **No-cache failure (FR-5):** `ScreeningUiState.Error` with `onRetry` → `refresh()`.
- **Cache + failed refresh (FR-6):** stay on `Content` with `isStale = true`; surface a
  dismissible banner, never block the last-known status.
- **Null/unknown status:** `null` → `NOT_STARTED`; unrecognized wire string → `UNKNOWN`
  rendered with neutral tone and generic copy (forward-compatibility, no crash).
- **Transient re-poll (FR-8):** a single `refresh()` on resume when transient — explicitly
  **not** a polling loop, to respect the unreliable dev host.

## 8. Security & Privacy

- Screening results can include sensitive compliance signals (PEP/sanctions hits). The UI
  must **not** expose raw analyst notes beyond the backend-provided `reason` string, and
  must not log `reason` or `status` values containing PII at non-debug levels.
- All transport relies on the shared cookie jar + `X-CSRF-Token` header; no new auth
  surface. Screening data is never written to logs, screenshots-in-test, or analytics
  payloads in raw form (see §10).
- Plaintext-HTTP dev host: cleartext is permitted only via the existing
  `network_security_config` dev allowlist (AND-027); production builds remain
  HTTPS-only. This ticket changes nothing there.
- No data leaves the device. Nothing is persisted beyond the existing encrypted-at-rest
  KYC cache row.

## 9. Accessibility & i18n

- All status chips have `contentDescription` combining label + status semantics
  (e.g., "Screening status: under review"); color is never the sole signal — each tone
  pairs with an icon and text label (WCAG 1.4.1).
- Minimum 4.5:1 contrast for status text on chip backgrounds via Material 3 tonal roles.
- Touch targets (Retry, Refresh) ≥ 48dp; full TalkBack traversal order top-to-bottom.
- All strings live in `feature-kyc` `strings.xml`; no hardcoded literals in Composables.
  Status labels, descriptions, guidance, and the stale banner are externalized and
  pluralization-safe. `updatedAt` formatting is locale-aware via `java.time` +
  `DateUtils.getRelativeTimeSpanString` semantics.

## 10. Telemetry & Logging

- **Screen view event:** `kyc_screening_viewed { status: <enum name>, is_stale: Bool }`.
  Status is logged as the **enum name only** (never `reason`/PII).
- **Refresh event:** `kyc_screening_refresh { trigger: manual|resume, result: ok|error }`.
- **Logging:** structured `Timber`/`core-ui` logger at `DEBUG` for state transitions;
  `WARN` on refresh failure with the mapped user message only. `reason` is logged at
  `VERBOSE` in debug builds only and stripped from release.
- Telemetry routes through the app's existing analytics abstraction (no direct SDK calls
  here); if that abstraction is not yet present, events are emitted via a no-op logger and
  the event names above are the contract for the owning analytics ticket.

## 11. Testing Strategy

- **Unit (core-testing + JUnit5/Turbine):**
  - `toScreeningUiState` mapping: one test per `KycScreeningStatus` asserting
    title/description/tone/`isTransient`.
  - Null `kycScreening` → `NOT_STARTED`; unknown wire string → `UNKNOWN`.
  - `isStale` logic: cache-served + failed refresh ⇒ `isStale = true`; fresh ⇒ false.
  - `ScreeningViewModel`: `Loading → Content` on emission; `Error` on `observeKyc` throw;
    `onResume()` calls `refresh()` only when transient (verify with a fake repository).
- **Wire-mapping (in AND-319, cross-checked here):** Moshi parse of each documented
  `status` literal → correct enum, using fixture JSON from `/openapi.json` examples.
- **Compose UI (`createComposeRule`):**
  - Each `ScreeningUiState` renders expected text + chip semantics; Retry invokes
    callback; stale banner appears iff `isStale`.
  - Accessibility: `contentDescription` present on chip; merged semantics assertions.
- **Robustness:** fake repository simulating offline (cache-only) and error-no-cache
  paths.
- No instrumented network tests against the live dev host (unreliable); all tests use
  fakes/fixtures.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-319** (KYC API + DTOs, P0) — must merge first; it provides
  `KycRepository`, `KycSnapshot`, `KycScreening`, and the `KycScreeningStatus` enum +
  Moshi mapping. AND-328 cannot start its data layer until those types exist.
- **Soft alignment:** shares the `StatusChip`/`StatusTone` vocabulary with AND-327 (Proof
  of funds) and the KYC hub; whichever lands first should add it to `core-ui` and the
  other reuses it.
- **Blocks:** none recorded in the backlog.
- **Sequencing:** AND-319 → AND-328 (this) in parallel with AND-321/AND-327 under epic
  E42, milestone M7.

## 13. Risks & Open Questions

- **R-1 — Enum spelling drift.** Exact `kycScreening` wire literals must be confirmed
  against `frontend/src/api/types.ts` / `/openapi.json`. Mitigation: `UNKNOWN` fallback +
  fixture-driven mapping tests in AND-319. *Open:* confirm whether the field is nested
  under `/v1/kyc/me` vs `/v1/kyc/requirements`.
- **R-2 — Status granularity.** Backend may distinguish `PENDING` vs `IN_PROGRESS`, or
  collapse them. UI treats both as transient; copy must read sensibly either way. *Open:*
  is there a distinct "blocked/HIT" terminal status the user must escalate, and what is
  the CTA (contact support)?
- **R-3 — `reason` PII.** Whether `reason` is safe to display to the end user, or is
  analyst-internal. *Open:* default to **not** rendering `reason` for `HIT` until product
  confirms; show generic guidance instead.
- **R-4 — Refresh cost on unreliable host.** Auto-refresh on resume could repeatedly time
  out. Mitigated by single-shot, transient-only re-poll.

## 14. Acceptance Criteria

1. Navigating to `kyc/screening` with a loaded KYC snapshot renders the `kycScreening`
   status as a labeled, color-and-icon status chip with a description (satisfies backlog
   "Screening status renders").
2. Every `KycScreeningStatus` value (`NOT_STARTED`, `PENDING`, `IN_PROGRESS`, `CLEAR`,
   `REVIEW`, `HIT`, `UNKNOWN`) renders a distinct, correct label/tone — covered by
   parameterized unit + Compose tests.
3. Null `kycScreening` renders `NOT_STARTED`; an unrecognized wire value renders
   `UNKNOWN` without crashing.
4. Loading shows a skeleton; error-with-no-cache shows an error card whose Retry triggers
   `refresh()`; cache-with-failed-refresh shows the last status plus a stale banner with a
   formatted "last updated" timestamp.
5. Pull-to-refresh/manual refresh issues exactly one idempotent KYC GET and updates the
   status on success; `onResume()` re-polls once only when the current status is transient.
6. Status chips expose TalkBack `contentDescription`, color is never the sole signal,
   targets are ≥48dp, and all copy is externalized in `strings.xml`.
7. `reason`/status PII is not logged above debug level; telemetry events
   `kyc_screening_viewed` and `kyc_screening_refresh` fire with the documented payloads.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated by passing automated tests.
- Code merged to `android-port` under `com.testlogon.android.feature.kyc.screening`, with
  no new endpoints, Room entities, or migrations added by this ticket.
- Unit + Compose tests green in CI; coverage includes every status mapping and the
  loading/error/stale branches; no live-host network tests.
- Strings externalized and localizable; accessibility checks (chip semantics, contrast,
  target size) verified.
- `StatusChip`/`StatusTone` reused from `core-ui` (added by whichever KYC ticket lands
  first); no duplicated status-color logic.
- Lint/detekt/ktlint clean; PR reviewed; depends-on AND-319 confirmed merged.
- Open questions R-1/R-2/R-3 either resolved or explicitly deferred with the `UNKNOWN`/
  no-`reason` safe defaults documented in code comments.
