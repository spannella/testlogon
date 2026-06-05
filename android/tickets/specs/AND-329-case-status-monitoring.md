---
id: AND-329
title: Case status + monitoring
milestone: M7
epic: E42
priority: P1
size: M
status: draft
depends_on: [AND-319]
blocks: []
---

# AND-329 — Case status + monitoring

## 1. Overview & Goal

This ticket delivers the **KYC case status and ongoing-monitoring** surface of the
TestLogon Android app: the screen(s) and supporting repository/ViewModel layer that
let an authenticated user view the state of any open compliance/KYC case opened on
their behalf (typically by `POST /v1/kyc/evaluate` returning a `case_id`, see
AND-319) and the chronological **timeline/history** of that case as it moves through
review, plus the ongoing `kycMonitoring` signal that surfaces re-verification or
re-screening requirements after a tier was already granted.

Scope, verbatim from the backlog: *`kyc-cases`/`kycMonitoring`; case timeline/status.*
The single acceptance criterion is **Case status + history render** — given a case id
(or the caller's case list) the screen renders the current status and the ordered
history of timeline events, and the monitoring banner surfaces when an active
monitoring item exists, with loading / empty / error / offline states.

This is a **feature** ticket. It owns: the `feature-kyc` case-status screens
(`KycCaseListScreen`, `KycCaseDetailScreen`), their `KycCaseViewModel` /
`KycMonitoringViewModel` exposing `StateFlow<UiState>`, the `KycCaseRepository`
methods in `core-data` that wrap `KycApi.cases()` / `KycApi.case(caseId)` plus the
monitoring read, the domain models + mappers for timeline events, and the navigation
route wiring. It deliberately does **not** own: the `KycApi` interface or wire DTOs
(AND-319), the SWR cache primitives (AND-116), the typed `ApiResult`/`ApiError`
mapping (AND-015/AND-018), the document-capture/evaluate submission flow (AND-321),
or the tier-status/requirements screen (AND-320).

Deliverable: a navigable case list, a case-detail timeline screen, the monitoring
banner, the repository + ViewModels, and a full state/test matrix proving
`status + history render`.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. UI lands in module **`feature-kyc`** under package
  `com.testlogon.android.feature.kyc.cases`; repository + domain models land in
  **`core-data`** under `com.testlogon.android.core.data.kyc`; reused DTOs/`KycApi`
  live in `core-model`/`core-network` (AND-319).
- **Canonical package / applicationId base:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  Navigation-Compose (single Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 /
  OkHttp 4.12 / Moshi 1.15 (via AND-319), Room 2.6 + DataStore (cache, via AND-116),
  Coil. minSdk 24 / compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-kyc -> core-*`. ViewModels expose
  `StateFlow<UiState>`; the repository returns `ApiResult<T>` (AND-018). No
  `feature-*` symbol leaks into `core-*`.
- **Upstream dependency — AND-319 (KYC API + DTOs):** provides `KycApi.cases(): KycCasesResp`,
  `KycApi.case(caseId): KycCase`, and the `KycCase` / `KycStatus` / `KycTierId` types
  this ticket consumes. AND-319 is the **only hard backlog dependency** named on this
  ticket. The timeline-event sub-shape is consumed from `KycCase` (see R-1/Q-1).
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is plaintext
  HTTP and unreliable: design for ~20s timeouts, bounded backoff on the idempotent
  case GETs (AND-016), and offline/stale UI states (AND-021 / AND-045 patterns).
  Inspect `/openapi.json` for the `/v1/kyc/cases*` and monitoring schemas; web
  reference field names: `frontend/src/api/endpoints/kyc.ts`, `frontend/src/api/types.ts`.
- **Shared composables:** loading/empty/error/offline state composables (AND-021),
  Material 3 theme (AND-019), navigation host/routes (AND-022). Reuse, do not fork.
- **Auth:** cookie-based session (cookie jar AND-011, CSRF AND-012, 401-refresh
  AND-013) is inherited via the shared OkHttp/Retrofit; case endpoints 401 without it.

## 3. Functional Requirements

FR-1. **Case list.** `KycCaseListScreen` renders the caller's cases from
`KycApi.cases()`, each row showing `caseId`, a human-readable status chip
(`KycStatus`), `targetTier`, `openedAt`, and `updatedAt` (relative time). Rows are
ordered by `openedAt` descending. Tapping a row navigates to detail.

FR-2. **Case detail + timeline.** `KycCaseDetailScreen(caseId)` renders the current
status prominently and an **ordered, vertical timeline** of history events
(status transitions / notes / decisions) for that case, newest first or oldest first
per design (default: oldest→newest top-to-bottom with the latest emphasized). Each
event shows its timestamp, event kind/status, and any `note`.

FR-3. **Status semantics.** Map `KycStatus` to a status presentation:
`PENDING`/`REVIEW` → "In review" (amber, in-progress affordance), `VERIFIED` →
"Approved" (positive), `REJECTED` → "Rejected" (negative, surface `rejectReason`/note),
`UNVERIFIED` → "Not started", `UNKNOWN` → a non-silent "Status unavailable" state
(never rendered as blank — per AND-319 R-5).

FR-4. **Monitoring (`kycMonitoring`).** When an active monitoring item exists for the
caller (ongoing re-verification / periodic re-screening after a granted tier), surface
a dismissible-but-recurring **monitoring banner** at the top of the case list (and the
KYC hub if linked) describing the required action and a deep-link to the relevant case
or the requirements screen (AND-320). Absence of monitoring items renders no banner.

FR-5. **States.** Every screen renders the AND-021 state set: Loading (skeleton/spinner),
Loaded (content), Empty (no cases → friendly empty state with a CTA to start
verification, route to AND-320), Error (retryable), and Offline/Stale (cached content
with a stale indicator + retry; see FR-6).

FR-6. **Offline / stale.** Case list and case detail are idempotent reads; on transport
failure with a cached value present, show the last-known content with a stale badge and
a "Reconnecting / Retry" affordance. With no cache and no network, show Offline. Driven
by the SWR cache (AND-116) where available; if AND-116 is not yet merged, degrade to an
in-memory cache scoped to the ViewModel and flag (R-3).

FR-7. **Refresh.** Pull-to-refresh (and a manual retry on error) re-fetches the list /
case; in-flight refresh shows a non-blocking indicator over existing content.

FR-8. **Navigation.** Add routes `kyc/cases` (list) and `kyc/cases/{caseId}` (detail)
to the authenticated nav graph (AND-024/AND-022). Deep-link from an `evaluate` result
carrying a `case_id` (AND-321) and from the monitoring banner.

FR-9. **No mutation.** This screen is **read-only** monitoring; it does not submit,
appeal, or upload. Any CTA links out to the owning flow (AND-320 requirements /
AND-321 capture). No POST/PUT/DELETE is issued by this ticket.

FR-10. **Auth gating.** All routes are inside the authenticated graph; a hard 401
(after AND-013 single refresh) routes to login per AND-025. The screens assume an
authenticated principal and never send a user id.

## 4. Technical Design

UI in `feature-kyc/src/main/kotlin/com/testlogon/android/feature/kyc/cases/`;
repository + domain in `core-data/src/main/kotlin/com/testlogon/android/core/data/kyc/`.

### 4.1 Domain models + mappers (`core-data`)

DTOs (`KycCase`, `KycStatus`, `KycTierId`) from AND-319 are wire types; map to immutable
domain models with parsed `Instant` timestamps and a derived presentation status.

```kotlin
package com.testlogon.android.core.data.kyc

import com.testlogon.android.core.model.kyc.KycStatus
import com.testlogon.android.core.model.kyc.KycTierId
import java.time.Instant

data class KycCaseSummary(
    val caseId: String,
    val status: KycStatus,
    val targetTier: KycTierId,
    val openedAt: Instant,
    val updatedAt: Instant?,
    val note: String?,
)

enum class KycEventKind { OPENED, STATUS_CHANGE, NOTE, DECISION, MONITORING, UNKNOWN }

data class KycCaseEvent(
    val at: Instant,
    val kind: KycEventKind,
    val status: KycStatus?,     // status the case moved into, when applicable
    val message: String?,       // backend-supplied display string, passed through
)

data class KycCaseDetail(
    val summary: KycCaseSummary,
    val timeline: List<KycCaseEvent>,   // sorted ascending by `at`
)

data class KycMonitoringItem(
    val caseId: String?,        // null when a new case must be opened
    val requiredAction: String, // display string from backend
    val dueAt: Instant?,
    val targetTier: KycTierId?,
)
```

Mappers parse ISO-8601 strings (deferred by AND-319) to `Instant`, with a tolerant
parser that drops malformed timestamps to `Instant.EPOCH`-guarded null rather than
throwing. If `KycCase` carries an inline `history`/`events` array (R-1/Q-1), it maps to
`timeline`; otherwise the timeline is synthesized from `openedAt`/`updatedAt`/`status`
as a two-event fallback (documented to the user via a "limited history" note).

### 4.2 Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.kyc

import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.ApiResult     // AND-018
import kotlinx.coroutines.flow.Flow

interface KycCaseRepository {
    /** SWR list of the caller's cases. Emits cached-then-fresh where AND-116 is wired. */
    fun observeCases(): Flow<ApiResult<List<KycCaseSummary>>>
    suspend fun refreshCases(): ApiResult<List<KycCaseSummary>>
    suspend fun getCase(caseId: String): ApiResult<KycCaseDetail>
    /** Active ongoing-monitoring items, if any. */
    suspend fun getMonitoring(): ApiResult<List<KycMonitoringItem>>
}

class DefaultKycCaseRepository @Inject constructor(
    private val api: KycApi,
    @IoDispatcher private val io: CoroutineDispatcher,
    // private val cache: KycCaseCache,   // AND-116 SWR seam; optional until merged
) : KycCaseRepository { /* wraps api.cases()/case(id)/monitoring in ApiResult, maps DTO->domain */ }
```

All calls run on the injected IO dispatcher; results are wrapped via the AND-018
`apiResult { … }` helper so transport/HTTP/Json failures become `ApiResult.Error(ApiError)`
(mapped by AND-015) and never throw into the ViewModel. The idempotent GETs ride
AND-016 bounded backoff; this ticket adds no retry of its own.

### 4.3 ViewModels (`feature-kyc`)

```kotlin
package com.testlogon.android.feature.kyc.cases

sealed interface KycCaseListUiState {
    data object Loading : KycCaseListUiState
    data class Content(
        val cases: List<KycCaseSummary>,
        val monitoring: List<KycMonitoringItem>,
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
    ) : KycCaseListUiState
    data object Empty : KycCaseListUiState
    data class Error(val message: String, val retryable: Boolean) : KycCaseListUiState
    data object Offline : KycCaseListUiState
}

@HiltViewModel
class KycCaseListViewModel @Inject constructor(
    private val repo: KycCaseRepository,
) : ViewModel() {
    val uiState: StateFlow<KycCaseListUiState> = /* combine(observeCases(), monitoring) */
    fun refresh() { /* sets isRefreshing, calls refreshCases() */ }
    fun retry() { /* re-runs initial load */ }
}

sealed interface KycCaseDetailUiState {
    data object Loading : KycCaseDetailUiState
    data class Content(val case: KycCaseDetail, val isStale: Boolean = false) : KycCaseDetailUiState
    data class Error(val message: String, val retryable: Boolean) : KycCaseDetailUiState
    data object Offline : KycCaseDetailUiState
    data object NotFound : KycCaseDetailUiState   // 404 from case(id)
}

@HiltViewModel
class KycCaseDetailViewModel @Inject constructor(
    private val repo: KycCaseRepository,
    savedStateHandle: SavedStateHandle,    // caseId nav arg
) : ViewModel()
```

`uiState` is exposed via `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`.
`caseId` is read from `SavedStateHandle` (nav arg key `caseId`). `combine` merges the
SWR case-list flow with a one-shot monitoring fetch (re-fetched on refresh).

### 4.4 Compose UI

```kotlin
@Composable fun KycCaseListScreen(
    onOpenCase: (String) -> Unit,
    onStartVerification: () -> Unit,          // -> AND-320 requirements route
    vm: KycCaseListViewModel = hiltViewModel(),
)

@Composable fun KycCaseDetailScreen(
    onBack: () -> Unit,
    onOpenRequirements: (KycTierId) -> Unit,  // CTA when REJECTED/monitoring
    vm: KycCaseDetailViewModel = hiltViewModel(),
)

@Composable private fun CaseRow(case: KycCaseSummary, onClick: () -> Unit)
@Composable private fun StatusChip(status: KycStatus)          // FR-3 color/label mapping
@Composable private fun CaseTimeline(events: List<KycCaseEvent>)   // vertical connector + nodes
@Composable private fun MonitoringBanner(items: List<KycMonitoringItem>, onAction: (KycMonitoringItem) -> Unit)
```

State branches delegate to the shared AND-021 composables (`LoadingState`,
`EmptyState`, `ErrorState`, `OfflineState`) so look-and-feel matches the app. The
timeline uses a `Column` of nodes joined by a `Canvas`/`Divider` connector; long lists
are lazy (`LazyColumn`) — timeline events are bounded per case so no Paging is needed.

### 4.5 Navigation + Gradle

Add to the authenticated nav graph (AND-024):
```kotlin
composable(KycRoute.Cases.path) { KycCaseListScreen(onOpenCase = { nav.navigate(KycRoute.CaseDetail.of(it)) }, …) }
composable(KycRoute.CaseDetail.path, arguments = listOf(navArgument("caseId"){ type = NavType.StringType })) {
    KycCaseDetailScreen(onBack = nav::popBackStack, …)
}
```
where `KycRoute.Cases = "kyc/cases"` and `KycRoute.CaseDetail = "kyc/cases/{caseId}"`.
No new third-party dependency: `feature-kyc` already has Compose/Hilt/Navigation; it
declares `implementation(project(":core-data"))`, `:core-ui`, `:core-network`,
`:core-model`. Source files only.

## 5. API Contract

This ticket issues **no new endpoints**; it consumes the `/v1/kyc/cases*` endpoints
declared by AND-319 plus a monitoring read (see Q-2). Base path (`dev`):
`http://18.222.237.167:8000/`. All require an authenticated session (cookies +
inherited CSRF on any mutating verb — none here). All GETs are idempotent.

### GET `v1/kyc/cases`
Response `200` (per AND-319 `KycCasesResp`):
```json
{ "cases": [
  { "case_id": "case_77", "status": "review", "target_tier": "tier1",
    "opened_at": "2026-06-05T12:01:00Z", "updated_at": "2026-06-05T13:30:00Z",
    "note": "Awaiting document review" }
] }
```

### GET `v1/kyc/cases/{caseId}`
Path: `v1/kyc/cases/case_77`. Response `200`: a single `KycCase`. The timeline is read
from the case's `history`/`events` array if present (consumed shape, pending Q-1):
```json
{ "case_id": "case_77", "status": "verified", "target_tier": "tier1",
  "opened_at": "2026-06-05T12:01:00Z", "updated_at": "2026-06-06T09:00:00Z",
  "note": null,
  "history": [
    { "at": "2026-06-05T12:01:00Z", "kind": "opened",        "status": "review", "message": "Case opened" },
    { "at": "2026-06-05T13:30:00Z", "kind": "note",          "status": "review", "message": "Awaiting document review" },
    { "at": "2026-06-06T09:00:00Z", "kind": "decision",      "status": "verified", "message": "Approved" }
  ] }
```
`404` → `KycCaseDetailUiState.NotFound`. `401` → AND-013 refresh-then-retry once, else login.

### GET `v1/kyc/monitoring` (proposed — confirm via `/openapi.json`, Q-2)
Response `200`:
```json
{ "items": [
  { "case_id": null, "required_action": "Re-verify your ID (expires in 30 days)",
    "due_at": "2026-07-05T00:00:00Z", "target_tier": "tier1" }
] }
```
If no dedicated monitoring endpoint exists, monitoring is derived client-side from
`me`/`cases` (a case in `review`/`rejected`, or a `next_tier` re-verification flag) —
resolved by Q-2 before coding; either way the `KycMonitoringItem` domain model is stable.

**Error envelope (all):** FastAPI `detail` union; mapping owned by AND-015/AND-018. The
repository converts non-2xx/transport failures into `ApiResult.Error`; the ViewModel
maps that to `Error`/`Offline`/`NotFound`.

## 6. Data & State Management

- **Source of truth:** the `KycCaseRepository`. The list uses SWR (AND-116): emit cached
  summaries immediately (`isStale = true`), then the fresh network result; case detail
  fetches on demand and may be cached by `caseId` with a short TTL.
- **Persistence:** Room (AND-116) is the cache backing store where merged — a `kyc_cases`
  table keyed by `caseId` (columns mirror `KycCaseSummary`, timeline serialized as JSON or
  a child table). DataStore is **not** used (no user prefs here). Until AND-116 is wired,
  cache is in-memory in the repository singleton and flagged (R-3); domain API is unchanged.
- **UI state:** `StateFlow<KycCaseListUiState>` / `StateFlow<KycCaseDetailUiState>` via
  `stateIn(WhileSubscribed(5_000))`; `caseId` survives process death through
  `SavedStateHandle`. Refresh and retry are explicit ViewModel intents.
- **Timeline ordering:** events are sorted ascending by `at` in the mapper; the UI may
  reverse for display. Mapping `KycStatus`/`KycEventKind` uses `UNKNOWN` fallbacks so
  additive backend values never break rendering (per AND-319 FR-9).
- **Threading:** all repository I/O on the injected `@IoDispatcher`; Compose collects on
  the main dispatcher via `collectAsStateWithLifecycle()`.

## 7. Error Handling & Resilience

- **HTTP / transport:** wrapped into `ApiResult.Error(ApiError)` by the repository (via
  AND-018 + AND-015). The ViewModel maps: `ApiError.Network`/timeout with cache present →
  `Content(isStale=true)`; with no cache → `Offline`; `404` on detail → `NotFound`; other
  HTTP/server errors → `Error(retryable=true)`.
- **~20s timeouts + bounded backoff** for the idempotent case GETs are owned by
  AND-009/AND-016; this ticket relies on them and adds no per-screen retry loop beyond the
  user-initiated retry/pull-to-refresh.
- **401:** intercepted by AND-013 (one refresh + retry); a second 401 propagates and routes
  to login (AND-025). The screen does not handle session refresh itself.
- **Unknown enum tokens / missing optional fields:** tolerated by AND-319 DTOs and mapped to
  `UNKNOWN`; an `UNKNOWN` *required* status renders the non-silent "Status unavailable"
  presentation (FR-3) rather than a blank or crash.
- **Empty list:** `Empty` state with a "Start verification" CTA (route to AND-320), not an
  error.
- **Partial/limited history:** when no `history` array is returned, render the synthesized
  two-event timeline with a "Limited history available" note (4.1) instead of an empty
  timeline.
- **Idempotent UI:** refresh while content is shown never clears it; failures during refresh
  keep existing content and surface a transient retry affordance.

## 8. Security & Privacy

- **PII exposure.** Case notes, `rejectReason`, and monitoring `requiredAction` are
  backend-supplied and may reference identity verification details. They render only inside
  the authenticated screen and are **never logged** (Section 10). Domain models carrying
  these strings must not be emitted to logcat; `toString()` of `KycCaseEvent`/`KycCaseDetail`
  may be left default (no secret values), but the repository must not log response bodies.
- **No PII sent.** All reads are GETs scoped to the authenticated principal by cookie; no
  user id, name, or document content is sent in any path or query by this ticket.
- **Transport.** On `dev` these ride plaintext HTTP — a known dev-only risk permitted by the
  scoped cleartext config (AND-006); `staging`/`prod` are HTTPS-only. No real PII is exercised
  against the plaintext dev host beyond synthetic fixtures.
- **Cache at rest.** If timeline/case data is persisted via AND-116 Room, it inherits the
  app's standard (unencrypted) cache store; case data is low-sensitivity status metadata, not
  raw documents. Eviction follows AND-118 TTL. No document images are cached by this ticket.
- **Screenshots.** No `FLAG_SECURE` is mandated here (status metadata only); if grooming
  classifies notes/reject reasons as sensitive, apply `FLAG_SECURE` to the detail screen
  (noted as Q-3).

## 9. Accessibility & i18n

- **i18n:** all client-authored strings (state labels, status chip labels, CTA copy,
  "Limited history", relative-time formatting) live in `feature-kyc` `strings.xml` and route
  through the AND-111 i18n plumbing; no hardcoded UI strings. Backend display strings
  (`note`, `requiredAction`, `rejectReason`) are passed through verbatim and are not
  client-localized. Relative timestamps use `android.text.format.DateUtils` /
  locale-aware formatting; RTL is supported via the AND-114 readiness work (timeline connector
  mirrors in RTL).
- **Accessibility:** status chips expose a text `contentDescription` (color is never the sole
  status signal — label text accompanies color, satisfying contrast/colorblind requirements).
  Timeline nodes are grouped with `semantics(mergeDescendants = true)` so each event reads as a
  single unit ("June 5, 12:01, Case opened, in review"). Touch targets ≥48dp; the list and
  timeline are keyboard/TalkBack traversable in chronological order. The monitoring banner is
  announced as an alert (`liveRegion = Assertive`) when it appears.

## 10. Telemetry & Logging

- **HTTP logging** inherited from AND-009's redacting interceptor (debug only); case/monitoring
  response bodies (which may carry PII notes) must be in AND-009's redaction set — add
  `v1/kyc/cases` and `v1/kyc/monitoring` paths to it (constraint flagged for AND-009, R-4-style).
- **Analytics events** (via the app's telemetry layer, redacted): `kyc_case_list_view`,
  `kyc_case_detail_view {status}`, `kyc_monitoring_banner_shown {action_kind}`,
  `kyc_monitoring_banner_tapped`, `kyc_case_refresh`. Event properties carry only
  enum/status tokens and case-id hashes — **never** notes, reject reasons, or
  `required_action` free text.
- **No business logic in logs.** The repository logs failures only as redacted `ApiError`
  categories (network/timeout/http-code), not bodies.

## 11. Testing Strategy

Three layers: mapper unit tests (`core-data`), repository contract tests with MockWebServer
(`core-data`, AND-046 harness + AND-319 fixtures), and Compose UI/state tests (`feature-kyc`,
AND-048-style harness).

**T-1 — mapper: DTO→domain.** `KycCase`→`KycCaseDetail` parses ISO-8601 to `Instant`,
sorts the `history` array ascending, and maps `kind`/`status` enums incl. `UNKNOWN`.

**T-2 — mapper: synthesized timeline.** A `KycCase` with no `history` produces the
two-event fallback timeline and the "limited history" flag.

**T-3 — repository: list happy path.** Enqueue the Section-5 `cases` body; assert
`GET /v1/kyc/cases` and `ApiResult.Success` with summaries ordered by `openedAt` desc.

**T-4 — repository: detail happy + 404.** `getCase("case_77")` decodes the timeline;
`getCase("nope")` (`404`) → `ApiResult.Error` mapped to `NotFound` by the ViewModel.

**T-5 — repository: monitoring.** `getMonitoring()` decodes items (or the client-derived
fallback per Q-2) into `KycMonitoringItem`.

**T-6 — ViewModel: list state machine.** Loading→Content; empty body→`Empty`;
network error with cache→`Content(isStale=true)`; network error without cache→`Offline`;
http 500→`Error(retryable=true)`. Use a fake repository emitting `ApiResult`s.

**T-7 — ViewModel: detail state machine.** Loading→Content; `404`→`NotFound`;
timeout w/ cache→stale; refresh keeps content on failure.

**T-8 — Compose: status + history render (backlog AC).** `KycCaseDetailScreen` fed a
`Content` state asserts the status chip text/`contentDescription` and that each
`KycCaseEvent` node (timestamp + message) is displayed in order. **This is the
acceptance-criterion test.**

**T-9 — Compose: monitoring banner.** Banner renders only when items are non-empty,
announces as a live region, and tap invokes the action callback with the right item.

**T-10 — Compose: state surfaces.** Loading/Empty/Error/Offline each render the shared
AND-021 composable; retry/refresh invoke the ViewModel intents; Empty CTA routes to
verification.

**T-11 — a11y.** Status communicated by text (not color only); timeline nodes merge
descendants; touch targets ≥48dp (Compose semantics assertions).

Fixtures reuse/extend `core-model/src/test/resources/kyc/` (AND-319) plus a
`case_with_history.json` and `monitoring.json`. Coverage target ≥85% on the new
repository + ViewModel + mapper surface; every state branch and every endpoint has a test.
Test classes: `KycCaseMapperTest`, `KycCaseRepositoryTest` (`core-data`),
`KycCaseListViewModelTest`, `KycCaseDetailViewModelTest`, `KycCaseScreensTest` (`feature-kyc`).

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-319** — KYC API + DTOs. Provides `KycApi.cases()/case(id)`, `KycCase`,
  `KycStatus`, `KycTierId`. The only backlog-declared dependency. Blocking.

**Effective upstream (relied on at runtime / for reuse):** AND-018 (`ApiResult`),
AND-015 (`ApiError`/detail mapping), AND-016/AND-009 (timeouts + backoff for the GETs),
AND-021 (loading/empty/error/offline composables), AND-019 (theme), AND-022/AND-024
(nav host + authenticated graph), AND-025 (auth-gated routing), AND-111/AND-114 (i18n/RTL).
AND-116/AND-118 (SWR cache + TTL) are used for offline/stale where merged; if not yet
available, the in-memory fallback (4.1/6) keeps this ticket shippable (R-3).

**Downstream / siblings:** AND-320 (tier status + requirements — link target for CTAs),
AND-321 (document capture / evaluate — produces the `case_id` deep-linked here). These are
siblings in M7/E42, not blockers; align route names during grooming.

**Sequencing within the ticket:** (1) confirm the case `history`/timeline shape and the
monitoring source against `/openapi.json` + `frontend/src/api/endpoints/kyc.ts` (Q-1/Q-2);
(2) domain models + mappers + tests (`core-data`); (3) repository + MockWebServer tests;
(4) ViewModels + state tests; (5) Compose screens + nav wiring + UI/a11y tests.

## 13. Risks & Open Questions

- **R-1 / Q-1 — Timeline shape.** The `KycCase` DTO (AND-319) does not currently declare a
  `history`/`events` array; this ticket consumes one. *Mitigation:* confirm the field name and
  element shape in `/openapi.json`; if absent, AND-319 must add the field (small DTO addition)
  or this ticket synthesizes a minimal timeline (4.1/T-2) — guarded by tests either way.
- **R-2 / Q-2 — Monitoring source.** A dedicated `/v1/kyc/monitoring` endpoint may not exist;
  monitoring may be derived from `me`/`cases`. *Mitigation:* confirm via OpenAPI; the
  `KycMonitoringItem` domain model and `getMonitoring()` signature are stable regardless of
  source.
- **R-3 — SWR availability.** If AND-116 is not merged when this ships, offline/stale uses the
  in-memory fallback; behavior is correct but cache does not survive process death.
  *Mitigation:* gate the Room backing behind the repository interface; swap when AND-116 lands.
- **R-4 — Status enum drift.** Backend may emit case statuses outside the AND-319 set;
  `UNKNOWN`→"Status unavailable" prevents silent/blank rendering (FR-3) but a meaningful new
  status would be mislabeled until modeled. *Mitigation:* enumerate live statuses; extend the
  enum + presentation map.
- **R-5 — PII in logs/screenshots.** Notes/reject reasons are PII; ensure AND-009 redacts
  `v1/kyc/cases`/`monitoring` and confirm whether `FLAG_SECURE` is required (Q-3).
- **Q-3** Should the case-detail screen set `FLAG_SECURE`? *Proposed:* no (status metadata
  only) unless grooming classifies notes as sensitive.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Given a case (by list selection or deep-link `caseId`), the case-detail
  screen **renders the current status and the ordered history/timeline of events**, each with
  timestamp and message. [T-8]
- **AC-2.** `KycCaseListScreen` renders the caller's cases from `GET /v1/kyc/cases` ordered by
  `openedAt` descending, each row showing status chip, target tier, and relative times; tapping
  navigates to `kyc/cases/{caseId}`. [T-3, T-8]
- **AC-3.** Status presentation maps every `KycStatus` per FR-3, communicates status by text
  (not color alone), and renders `UNKNOWN` as a non-silent "Status unavailable" state. [T-8, T-11]
- **AC-4.** The monitoring banner renders only when active `kycMonitoring` items exist, announces
  as a live region, and its action routes to the case/requirements target; absence renders no
  banner. [T-9]
- **AC-5.** All AND-021 states render correctly: Loading, Content, Empty (with verification CTA),
  Error (retryable), Offline; `404` on detail → `NotFound`. [T-6, T-7, T-10]
- **AC-6.** Offline/stale: a transport failure with cached data shows last-known content with a
  stale indicator + retry; refresh never clears existing content on failure. [T-6, T-7]
- **AC-7.** The screen is read-only — it issues no POST/PUT/DELETE; CTAs link out to AND-320/AND-321.
- **AC-8.** Case/monitoring PII (notes, reject reasons, required actions) is never logged and
  never sent in any request; analytics carry only status tokens/hashed ids. [Section 10]
- **AC-9.** All tests pass in CI; `feature-kyc`/`core-data` build clean under AGP 8.7.3 /
  Gradle 8.9 / JDK 17 with no new lint/detekt violations; ≥85% coverage on the new surface.

## 15. Definition of Done

- Domain models + mappers (`core-data/.../kyc`), `KycCaseRepository` +
  `DefaultKycCaseRepository`, `KycCaseListViewModel`/`KycCaseDetailViewModel`, and the
  `KycCaseListScreen`/`KycCaseDetailScreen`/`MonitoringBanner`/`CaseTimeline` composables are
  implemented under package base `com.testlogon.android`, reusing AND-319 DTOs and AND-021
  state composables (no forks).
- Routes `kyc/cases` and `kyc/cases/{caseId}` are wired into the authenticated nav graph
  (AND-024) with `caseId` as a typed nav arg; deep-link entry from an `evaluate` `case_id`
  and the monitoring banner works.
- Open questions Q-1 (timeline shape), Q-2 (monitoring source), Q-3 (`FLAG_SECURE`) are resolved
  against `/openapi.json` and `frontend/src/api/endpoints/kyc.ts`; the consumed shapes/return
  types reflect the confirmed contract.
- `KycCaseMapperTest`, `KycCaseRepositoryTest`, `KycCaseListViewModelTest`,
  `KycCaseDetailViewModelTest`, and `KycCaseScreensTest` (T-1..T-11) are implemented and green in
  CI; ≥85% coverage on the new surface; fixtures committed (incl. `case_with_history.json`,
  `monitoring.json`).
- Offline/stale, Empty, Error, and NotFound states verified; status + history render proven by
  the Compose test (AC-1).
- PII never logged (AND-009 redaction extended to `v1/kyc/cases`/`monitoring`); no mutating
  requests issued; analytics redacted.
- `./gradlew :core-data:testDebugUnitTest :feature-kyc:assembleDebug
  :feature-kyc:testDebugUnitTest :feature-kyc:connectedDebugAndroidTest` passes locally and in CI
  with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; CTAs to AND-320/AND-321 wired (or stubbed with
  TODO + ticket id where those screens are not yet merged).
