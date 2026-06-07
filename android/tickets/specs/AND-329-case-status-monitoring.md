---
id: AND-329
title: Case status + monitoring
milestone: M7
epic: E42
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-319]
blocks: []
---

# AND-329 — Case status + monitoring

## 1. Overview & Goal

This ticket delivers the **KYC case status and ongoing-monitoring** surface of the
TestLogon Android app: the screen(s) and supporting repository/ViewModel layer that
let an authenticated user view the state of any open compliance/KYC case opened on
their behalf (a KYC case is created by `POST /v1/kyc/cases` → `KycCaseEnvelope`
returning `case.kyc_case_id`; see AND-319 — note: tier *evaluation* is a separate
endpoint `POST /v1/kyc/tiers/me/evaluate`, corrected from the original "`POST /v1/kyc/evaluate`")
and the chronological **timeline/history** of that case as it moves through
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
- **Upstream dependency — AND-319 (KYC API + DTOs):** provides the `KycApi` wrappers for
  `GET /v1/kyc/cases` (resp **`KycCaseListEnvelope`** = `{ items: KycCaseOut[], next_cursor: string|null }`)
  and `GET /v1/kyc/cases/{case_id}` (resp **`KycCaseEnvelope`** = `{ case: KycCaseOut }`), plus the
  `KycCaseOut` / `KycCaseStatus` types this ticket consumes. **Corrected:** the original spec named
  `KycCasesResp` / `KycCase` and a `KycTierId` — the verified contract uses `KycCaseListEnvelope` /
  `KycCaseEnvelope` / `KycCaseOut`, and there is **no `target_tier`/`KycTierId` field on a case** (see §5).
  `KycCaseStatus` is the 7-value enum `draft | submitted | under_review | needs_more_info | approved |
  rejected | expired` (NOT `pending/review/verified/unverified/unknown`; see FR-3 correction).
  AND-319 is the **only hard backlog dependency** named on this ticket. **There is no inline
  `history`/`events` array on `KycCaseOut`** — the timeline must be synthesized (confirmed; see R-1/§4.1).
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is plaintext
  HTTP and unreliable: design for ~20s timeouts, bounded backoff on the idempotent
  case GETs (AND-016), and offline/stale UI states (AND-021 / AND-045 patterns).
  Verified schemas: `/v1/kyc/cases*` and `/v1/kyc/monitoring/*`; web reference field
  names confirmed in `src/api/endpoints/kyc.ts` (`listKycCases`/`getKycCase`),
  `src/api/endpoints/kycMonitoring.ts` (`getMySchedule`/`getMyTriggers`), and
  `src/api/types.ts` (`KycSelfServiceCase`, `KycReviewSchedule`, `KycTriggerEvent`).
- **Shared composables:** loading/empty/error/offline state composables (AND-021),
  Material 3 theme (AND-019), navigation host/routes (AND-022). Reuse, do not fork.
- **Auth (verified against `src/api/client.ts`):** the web client sends **three** auth
  artifacts on every call — an `Authorization: Bearer <accessToken>` header, an
  `X-CSRF-Token` header sourced from the `ui_csrf` cookie, and `credentials: include`
  (session cookies). On `401` it calls `POST /ui/session/refresh` **once** then retries the
  original request; a second failure logs out. **Corrected:** the original "cookie-based
  session" description was incomplete — it omitted the Bearer token and the `X-CSRF-Token`/`ui_csrf`
  mechanism, and the refresh endpoint is `/ui/session/refresh`. This transport/refresh
  behavior is **owned by AND-011/012/013** and inherited via the shared OkHttp/Retrofit;
  the exact ticket numbers owning each piece are an unverified assumption (not in these sources).
  Case endpoints 401 without a valid session.

## 3. Functional Requirements

FR-1. **Case list.** `KycCaseListScreen` renders the caller's cases from
`GET /v1/kyc/cases` (`KycCaseListEnvelope.items`), each row showing `kyc_case_id`, a
human-readable status chip (`KycCaseStatus`), and `created_at`/`updated_at` rendered as
relative time. **Corrected:** there is **no `target_tier`/`opened_at` on `KycCaseOut`** —
drop the "target tier" row field and use `created_at` (epoch seconds, integer) as the
"opened" timestamp; sort rows by `created_at` descending. `next_cursor` is present for
pagination but, per §4.4, case counts are bounded so first-page rendering suffices (cursor
follow-up is an enhancement, flagged). Tapping a row navigates to detail.

FR-2. **Case detail + timeline.** `KycCaseDetailScreen(caseId)` renders the current
status prominently and an **ordered, vertical timeline** of history events
(status transitions / notes / decisions) for that case, newest first or oldest first
per design (default: oldest→newest top-to-bottom with the latest emphasized). Each
event shows its timestamp, event kind/status, and any `note`.

FR-3. **Status semantics.** **Corrected** to the verified `KycCaseStatus` enum
(`draft | submitted | under_review | needs_more_info | approved | rejected | expired`).
Map each to a presentation: `draft` → "Not started"/"Draft" (neutral), `submitted` →
"Submitted" (neutral/in-progress), `under_review` → "In review" (amber, in-progress
affordance), `needs_more_info` → "Action needed" (amber, CTA to AND-321/AND-320),
`approved` → "Approved" (positive), `rejected` → "Rejected" (negative — surface the
review `reason_codes` from `KycCaseOut.review.reason_codes`; there is **no top-level
`reject_reason`/`note` field** on the case, corrected), `expired` → "Expired" (negative,
re-verify CTA). Any unrecognized/additive token maps to a non-silent "Status unavailable"
state (never rendered as blank). Note: the original `PENDING/REVIEW/VERIFIED/UNVERIFIED/UNKNOWN`
tokens do **not** exist in the contract.

FR-4. **Monitoring (`kycMonitoring`).** **Corrected/confirmed source:** there is **no
`GET /v1/kyc/monitoring` returning `{items:[]}`**. The caller-scoped monitoring surface is
**two endpoints**: `GET /v1/kyc/monitoring/schedule` → `KycReviewScheduleEnvelope`
(`{ schedule: KycReviewSchedule | null }`) and `GET /v1/kyc/monitoring/triggers` →
`KycTriggerEventListEnvelope` (`{ events: KycTriggerEvent[] }`). An **active monitoring
condition** is derived as: `schedule != null` AND `schedule.status` ∈
{`needs_review`, `grace_period`, `downgraded`} (the `active` state surfaces no banner), or
the presence of recent trigger events. When active, surface a dismissible-but-recurring
**monitoring banner** at the top of the case list describing the required action (derived
from `schedule.status` + `next_review_date`/`grace_deadline`) and a deep-link to
`schedule.case_id` or the requirements screen (AND-320). Absence (schedule null / `active`
and no triggers) renders no banner.

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

DTOs (`KycCaseOut`, `KycCaseStatus`) from AND-319 are wire types; map to immutable
domain models. **Corrected:** `KycCaseOut.created_at`/`updated_at` are **epoch integers
(seconds)**, not ISO-8601 strings — map via `Instant.ofEpochSecond(...)`, not a string
parser. There is no `target_tier` and no top-level `note`/`reject_reason` on the case.

```kotlin
package com.testlogon.android.core.data.kyc

import com.testlogon.android.core.model.kyc.KycCaseStatus
import java.time.Instant

data class KycCaseSummary(
    val caseId: String,          // <- KycCaseOut.kyc_case_id
    val status: KycCaseStatus,
    val createdAt: Instant,      // <- epoch-seconds Int
    val updatedAt: Instant,      // <- epoch-seconds Int (required, not nullable)
    val missingRequirements: List<String>,  // <- KycCaseOut.missing_requirements
)

enum class KycEventKind { OPENED, STATUS_CHANGE, DECISION, MONITORING, UNKNOWN }

data class KycCaseEvent(
    val at: Instant,
    val kind: KycEventKind,
    val status: KycCaseStatus?, // status the case moved into, when applicable
    val message: String?,       // client-composed display string (see note)
)

data class KycCaseDetail(
    val summary: KycCaseSummary,
    val reasonCodes: List<String>,  // <- KycCaseOut.review.reason_codes (rejection detail)
    val timeline: List<KycCaseEvent>,   // sorted ascending by `at`
)

// Derived client-side from KycReviewSchedule + KycTriggerEvent (no single backend item type)
data class KycMonitoringItem(
    val caseId: String?,        // <- KycReviewSchedule.case_id, null when none
    val requiredAction: String, // composed from schedule.status / trigger_type
    val dueAt: Instant?,        // <- next_review_date or grace_deadline (epoch seconds)
)
```

Mappers convert **epoch-second integers** to `Instant` via `Instant.ofEpochSecond`, with a
tolerant guard (non-positive/garbage epoch → drop to null rather than throw). **Confirmed
(R-1/Q-1): `KycCaseOut` carries no `history`/`events` array**, so the timeline is **always
synthesized** from `created_at` (OPENED), `updated_at` + `status` (STATUS_CHANGE/DECISION),
and — for `rejected`/`needs_more_info` — `review.reason_codes` / `review.decided_at`. The UI
shows a "Limited history available" note (4.1) because no transition log is provided. The
`message` strings are **client-composed** from enum tokens + i18n, not backend free text.

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
) : KycCaseRepository {
    /* wraps GET /v1/kyc/cases (KycCaseListEnvelope), GET /v1/kyc/cases/{id}
       (KycCaseEnvelope), GET /v1/kyc/monitoring/schedule (KycReviewScheduleEnvelope)
       and GET /v1/kyc/monitoring/triggers (KycTriggerEventListEnvelope) in ApiResult,
       maps DTO->domain. getMonitoring() fans out schedule+triggers and derives items. */
}
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

This ticket issues **no new endpoints**; it consumes the `/v1/kyc/cases*` and
`/v1/kyc/monitoring/*` endpoints declared by AND-319. Base path (`dev`):
`http://18.222.237.167:8000/`. All paths are **leading-slash absolute** (`/v1/kyc/...`) per
the web client `BASE` constants. All require an authenticated session (Bearer + `ui_csrf`
cookie + session cookies; §2 auth). No mutating verbs here; all GETs are idempotent.
(All paths/shapes below are **verified** against `reference/openapi.index.txt`,
`openapi.pretty.json`, and `src/api/endpoints/*.ts`; the original §5 was substantially wrong.)

### GET `/v1/kyc/cases`  (op `list_my_kyc_cases`)
Response `200` = **`KycCaseListEnvelope`** (`items` + `next_cursor`), each item a `KycCaseOut`:
```json
{ "items": [
  { "contract_version": "2026-03-kyc-v1", "kyc_case_id": "case_77",
    "user_sub": "auth0|abc", "status": "under_review",
    "created_at": 1749124860, "updated_at": 1749129000, "version": 3,
    "missing_requirements": ["proof_of_address"],
    "files": [], "submission": {},
    "questionnaire": { "questionnaire_id": null },
    "signature": { "packet_id": null, "status": null },
    "review": { "decision": null, "reason_codes": [], "assigned_admin_sub": null } }
], "next_cursor": null }
```
Note: timestamps are **epoch-second integers**; there is **no `case_id`/`target_tier`/
`opened_at`/`note`** field (the original example invented all of these).

### GET `/v1/kyc/cases/{case_id}`  (op `get_my_kyc_case`)
Path: `/v1/kyc/cases/case_77`. Response `200` = **`KycCaseEnvelope`** = `{ "case": KycCaseOut }`
(same `KycCaseOut` shape as above). **There is no inline `history`/`events` array** — the
timeline is **synthesized** client-side (§4.1). `KycCaseOut.review.reason_codes` carries
rejection detail. The documented contract declares only `200` and `422:HTTPValidationError`;
a `404` is **not in the documented responses** (an unverified runtime assumption — FastAPI may
still raise it). `401` → session refresh (`POST /ui/session/refresh`) then retry once, else login.

### Monitoring — `/v1/kyc/monitoring/schedule` and `/v1/kyc/monitoring/triggers`
**Corrected:** no `GET /v1/kyc/monitoring` and no `{items:[]}` shape exists. Two GETs:

`GET /v1/kyc/monitoring/schedule` (op `get_my_schedule`) → **`KycReviewScheduleEnvelope`**:
```json
{ "schedule": {
    "user_sub": "auth0|abc", "risk_tier": "tier1",
    "review_frequency_days": 365, "last_review_date": 1717545600,
    "next_review_date": 1749081600, "grace_period_days": 30,
    "grace_deadline": 1751673600, "status": "needs_review",
    "case_id": "case_77", "created_at": 1717545600, "updated_at": 1749081600 } }
```
`schedule` may be `null` (no monitoring). `status` ∈ {`active`,`needs_review`,`grace_period`,`downgraded`};
all timestamps epoch-second integers (frontend `src/api/types.ts: KycReviewSchedule`).

`GET /v1/kyc/monitoring/triggers` (op `list_my_triggers`) → **`KycTriggerEventListEnvelope`**:
```json
{ "events": [
  { "event_id": "evt_1", "user_sub": "auth0|abc", "trigger_type": "periodic_review",
    "details": {}, "created_at": 1749081600, "created_by": "system" }
] }
```
`getMonitoring()` fetches both and derives `KycMonitoringItem`s (FR-4). The OpenAPI types both
envelopes' inner objects as opaque (`additionalProperties: true`); the **richer field set above is
the web client's typed view** in `src/api/types.ts` and is treated as the de-facto contract,
flagged as a typed-from-frontend assumption.

**Error envelope (all):** the `/v1/kyc/*` endpoints declare FastAPI `422:HTTPValidationError`
(`{ "detail": [ ValidationError, ... ] }`) only; other statuses surface as raw
`{ "detail": "..." }`. (The `ErrorEnvelope` shape seen on `/tickets/*` does **not** apply here.)
Mapping owned by AND-015/AND-018. The repository converts non-2xx/transport failures into
`ApiResult.Error`; the ViewModel maps that to `Error`/`Offline`/`NotFound`.

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
  `/v1/kyc/cases`, `/v1/kyc/monitoring/schedule`, and `/v1/kyc/monitoring/triggers` paths to it
  (constraint flagged for AND-009, R-4-style).
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

- **R-1 / Q-1 — Timeline shape. [RESOLVED via review]** Confirmed against
  `openapi.pretty.json: KycCaseOut` and `src/api/types.ts: KycSelfServiceCase`: the case DTO has
  **no `history`/`events` array**. Decision: the timeline is **always synthesized** client-side
  from `created_at`/`updated_at`/`status`/`review.reason_codes` (§4.1, T-2), with a "Limited
  history available" note. No AND-319 DTO change is required. Residual risk: a future backend
  transition log would supersede the synthesized view.
- **R-2 / Q-2 — Monitoring source. [RESOLVED via review]** Confirmed: no `GET /v1/kyc/monitoring`
  `{items}` endpoint. The caller-scoped source is **`GET /v1/kyc/monitoring/schedule`**
  (`KycReviewScheduleEnvelope`) + **`GET /v1/kyc/monitoring/triggers`** (`KycTriggerEventListEnvelope`).
  `getMonitoring()` derives `KycMonitoringItem`s from both. Residual risk: the OpenAPI types the
  envelope inner objects as opaque; the richer field set is taken from the frontend typed view.
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
- **AC-2.** `KycCaseListScreen` renders the caller's cases from `GET /v1/kyc/cases`
  (`KycCaseListEnvelope.items`) ordered by `created_at` descending, each row showing the status
  chip and relative times (no target tier — corrected); tapping navigates to `kyc/cases/{caseId}`.
  [T-3, T-8]
- **AC-3.** Status presentation maps every `KycCaseStatus` value (`draft|submitted|under_review|
  needs_more_info|approved|rejected|expired`) per FR-3, communicates status by text (not color
  alone), and renders any unrecognized/additive token as a non-silent "Status unavailable" state.
  [T-8, T-11]
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **List endpoint is `GET /v1/kyc/cases` returning a `KycCaseListEnvelope`** (`{ items: KycCaseOut[], next_cursor }`).
   VERDICT: **Corrected** (spec said `KycCasesResp` with a `cases` array). SOURCE: OpenAPI `GET /v1/kyc/cases` op=`list_my_kyc_cases` resp=`KycCaseListEnvelope`; schema `KycCaseListEnvelope`; `src/api/endpoints/kyc.ts: listKycCases`; `src/api/types.ts: KycSelfServiceCaseListEnvelope`.
2. **Detail endpoint is `GET /v1/kyc/cases/{case_id}` returning `KycCaseEnvelope`** (`{ case: KycCaseOut }`).
   VERDICT: **Corrected** (spec said a bare single `KycCase`). SOURCE: OpenAPI `GET /v1/kyc/cases/{case_id}` op=`get_my_kyc_case` resp=`KycCaseEnvelope`; schema `KycCaseEnvelope`; `src/api/endpoints/kyc.ts: getKycCase`.
3. **Case id field is `kyc_case_id`** (not `case_id`).
   VERDICT: **Corrected**. SOURCE: schema `KycCaseOut.kyc_case_id` (required); `src/api/types.ts: KycSelfServiceCase.kyc_case_id`.
4. **`created_at`/`updated_at` are epoch-second integers** (not ISO-8601 strings).
   VERDICT: **Corrected**. SOURCE: schema `KycCaseOut` (`created_at`/`updated_at` `type: integer`, both required); `src/api/types.ts: KycSelfServiceCase` (`created_at: number`).
5. **`KycCaseStatus` enum = `draft | submitted | under_review | needs_more_info | approved | rejected | expired`.**
   VERDICT: **Corrected** (spec used `PENDING/REVIEW/VERIFIED/UNVERIFIED/UNKNOWN`, none of which exist). SOURCE: schema `KycCaseOut.status` enum; `src/api/types.ts: KycCaseStatus`.
6. **No `target_tier` / `KycTierId` on a case.**
   VERDICT: **Corrected**. SOURCE: schema `KycCaseOut` properties (absent); `src/api/types.ts: KycSelfServiceCase` (absent).
7. **No top-level `note`/`reject_reason`; rejection detail lives in `review.reason_codes`.**
   VERDICT: **Corrected**. SOURCE: schema `KycCaseReviewRef.reason_codes` (array of string); `src/api/types.ts: KycCaseReviewRef`.
8. **No inline `history`/`events` array on the case → timeline is synthesized.**
   VERDICT: **Corrected/Confirmed** (was R-1/Q-1, now resolved). SOURCE: schema `KycCaseOut` (no such property); `src/api/types.ts: KycSelfServiceCase` (no such property).
9. **List is cursor-paginated via `next_cursor`.**
   VERDICT: **Verified** (added; original spec omitted it). SOURCE: schema `KycCaseListEnvelope.next_cursor`.
10. **Monitoring is `GET /v1/kyc/monitoring/schedule` (`KycReviewScheduleEnvelope`) + `GET /v1/kyc/monitoring/triggers` (`KycTriggerEventListEnvelope`)**, not `GET /v1/kyc/monitoring` `{items}`.
    VERDICT: **Corrected** (was R-2/Q-2, resolved). SOURCE: OpenAPI `GET /v1/kyc/monitoring/schedule` op=`get_my_schedule`, `GET /v1/kyc/monitoring/triggers` op=`list_my_triggers`; `src/api/endpoints/kycMonitoring.ts: getMySchedule, getMyTriggers`.
11. **`KycReviewSchedule` fields (`status`, `next_review_date`, `grace_deadline`, `case_id`, `risk_tier`, …) drive the banner; `status` ∈ {active, needs_review, grace_period, downgraded}.**
    VERDICT: **Verified (frontend typed view)**. SOURCE: `src/api/types.ts: KycReviewSchedule`. NOTE: OpenAPI types `KycReviewScheduleEnvelope.schedule` as opaque object → see Open assumptions.
12. **`KycTriggerEvent` fields (`event_id`, `trigger_type`, `created_at`, `details`).**
    VERDICT: **Verified (frontend typed view)**. SOURCE: `src/api/types.ts: KycTriggerEvent`. NOTE: OpenAPI `events` items opaque → Open assumptions.
13. **Tier evaluation is `POST /v1/kyc/tiers/me/evaluate`; case creation is `POST /v1/kyc/cases`** — the spec's `POST /v1/kyc/evaluate` does not exist.
    VERDICT: **Corrected**. SOURCE: OpenAPI `POST /v1/kyc/tiers/me/evaluate` op=`evaluate_my_tier`; `POST /v1/kyc/cases` op=`create_kyc_case`; `src/api/endpoints/kyc.ts: createKycCase`.
14. **Auth = `Authorization: Bearer <token>` + `X-CSRF-Token` (from `ui_csrf` cookie) + session cookies (`credentials: include`); 401 → `POST /ui/session/refresh` once then retry.**
    VERDICT: **Corrected** (spec described "cookie-based session" only). SOURCE: `src/api/client.ts` (lines ~157-184, 194-221, `refreshSession` → `/ui/session/refresh`).
15. **Error shape on `/v1/kyc/*` is FastAPI `422:HTTPValidationError` (`{detail: ValidationError[]}`); the `/tickets/*` `ErrorEnvelope` does not apply.**
    VERDICT: **Verified / Corrected** (spec vaguely said "FastAPI detail union"). SOURCE: OpenAPI per-path `resp=...;422:HTTPValidationError`; schema `HTTPValidationError`.
16. **Detail `404 → NotFound`.**
    VERDICT: **Unverified-assumption**. SOURCE: OpenAPI `GET /v1/kyc/cases/{case_id}` declares only `200` + `422` (no `404`). FastAPI may raise 404 at runtime, but it is not in the documented contract.
17. **Read-only screen issues no POST/PUT/DELETE.**
    VERDICT: **Verified** (consistent with consuming only GETs above). SOURCE: this ticket's endpoint set is GET-only; mutating KYC verbs (`create_kyc_case`, `submit_kyc_case`, etc.) are out of scope.
18. **Compose + Material 3 + Navigation-Compose + Hilt/KSP + Retrofit/OkHttp/Moshi are appropriate Android choices.**
    VERDICT: **Verified (framework ref)**. SOURCE: https://developer.android.com/jetpack/compose ; https://developer.android.com/guide/navigation ; https://square.github.io/retrofit/ .
19. **`stateIn(WhileSubscribed(5_000))` + `collectAsStateWithLifecycle()` for StateFlow UI.**
    VERDICT: **Verified (framework ref)**. SOURCE: https://developer.android.com/topic/architecture/ui-layer/stateflow ; https://developer.android.com/jetpack/androidx/releases/lifecycle .
20. **Relative time via `android.text.format.DateUtils`; a11y via Compose `semantics`/live region.**
    VERDICT: **Verified (framework ref)**. SOURCE: https://developer.android.com/reference/android/text/format/DateUtils ; https://developer.android.com/jetpack/compose/accessibility .

### Corrections made

- Overview: replaced non-existent `POST /v1/kyc/evaluate` with `POST /v1/kyc/cases` (create) and noted `POST /v1/kyc/tiers/me/evaluate` (tier eval).
- §2: corrected upstream-DTO names to `KycCaseListEnvelope`/`KycCaseEnvelope`/`KycCaseOut`; corrected status enum; corrected auth to Bearer + `X-CSRF-Token`/`ui_csrf` + cookies with `/ui/session/refresh`; corrected reference file pointers.
- FR-1: dropped invented `target_tier`/`opened_at`; use `kyc_case_id` + `created_at`/`updated_at`; sort by `created_at` desc; noted `next_cursor`.
- FR-3: replaced the fictional status tokens with the real 7-value enum and its presentation map; rejection detail from `review.reason_codes`.
- FR-4: replaced the fictional `GET /v1/kyc/monitoring` `{items}` with `schedule` + `triggers` endpoints and a client-side derivation rule.
- §4.1: domain models re-typed (`kyc_case_id`, epoch-second `Instant.ofEpochSecond`, `missingRequirements`, `reasonCodes`); timeline always synthesized; `KycMonitoringItem` documented as derived from schedule+triggers.
- §4.2: repository comment corrected to the four real endpoints.
- §5: rewritten with verified paths, JSON shapes, and error envelope.
- §10: redaction path list corrected to `/v1/kyc/cases`, `/v1/kyc/monitoring/schedule`, `/v1/kyc/monitoring/triggers`.
- §13: R-1 and R-2 marked RESOLVED with the verified outcomes.
- §14: AC-2 (sort key/no target tier) and AC-3 (real enum) corrected.

### Open assumptions

- **Detail `404`** is not in the documented OpenAPI responses for `GET /v1/kyc/cases/{case_id}` (only `200`/`422`); the `NotFound` UI state relies on a runtime FastAPI 404 that we could not confirm from the sources. Verify against a live dev call during implementation.
- **Monitoring inner-object fields** (`KycReviewSchedule`, `KycTriggerEvent`): the OpenAPI schemas type these as opaque `additionalProperties: true`; the field names/types used here come from the frontend `src/api/types.ts` typed view and are treated as the de-facto contract.
- **Ownership of transport tickets** (AND-011 cookie jar, AND-012 CSRF, AND-013 401-refresh, AND-015/AND-018 result mapping, AND-016/AND-009 timeouts/backoff, AND-021 state composables, AND-116/AND-118 SWR cache) is asserted by the spec but those tickets are not in the provided sources — accepted as project-internal assumptions, not independently verifiable here.
- **`intake_profile`, `version`, `files`, `submission`, `questionnaire`, `signature`** on `KycCaseOut` exist but are not consumed by this read-only status surface; ignoring them is a deliberate scope assumption.

## 17. Test Plan

Acceptance criteria referenced are from §14 (AC-1..AC-9). Test targets: **JVM** (local JVM/Robolectric, no device), **emulator** (headless AVD `test35`, API 35 x86_64), **device** (physical Samsung Galaxy A15 5G, SM-A156U, API 34 arm64-v8a). Contract tests use MockWebServer with fixtures mirroring the verified §5 shapes.

- **TC-AND-329-01 — List happy path (contract/MockWebServer).** Target: JVM. Preconditions: MockWebServer enqueues a `KycCaseListEnvelope` with 3 `KycCaseOut` items (varying `created_at`, `status`). Steps: call `repo.refreshCases()` (or collect `observeCases()`). Expected: request path `GET /v1/kyc/cases`; `ApiResult.Success` with 3 `KycCaseSummary` mapped (`kyc_case_id`→`caseId`, epoch→`Instant`) and ordered by `createdAt` desc. Traces: AC-2.
- **TC-AND-329-02 — Mapper: epoch + status + synthesized timeline (unit).** Target: JVM. Preconditions: a `KycCaseOut` fixture (`status=rejected`, `review.reason_codes=["doc_mismatch"]`, no history). Steps: map to `KycCaseDetail`. Expected: `created_at`/`updated_at` are `Instant.ofEpochSecond`; timeline synthesized (OPENED + DECISION) ascending by `at`; `reasonCodes` populated; "limited history" flagged. Traces: AC-1, AC-3.
- **TC-AND-329-03 — Mapper: unknown/additive status token (unit).** Target: JVM. Preconditions: a case JSON with `status="some_new_state"`. Steps: map + present. Expected: no throw; presentation = non-silent "Status unavailable"; never blank. Traces: AC-3.
- **TC-AND-329-04 — Detail happy path (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `KycCaseEnvelope` `{case: KycCaseOut}` for `case_77`. Steps: `repo.getCase("case_77")`. Expected: path `GET /v1/kyc/cases/case_77`; `ApiResult.Success(KycCaseDetail)` with status + synthesized ordered timeline. Traces: AC-1.
- **TC-AND-329-05 — Detail 404 / not-found (contract/MockWebServer).** Target: JVM. Preconditions: enqueue HTTP 404 (or 422) for an unknown id. Steps: `repo.getCase("nope")` then ViewModel maps. Expected: `ApiResult.Error`; `KycCaseDetailUiState.NotFound`. Note: 404 is an unverified-runtime assumption (§16#16) — also assert 422 → `Error(retryable=false)` does not crash. Traces: AC-5.
- **TC-AND-329-06 — Monitoring derivation: schedule + triggers (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `KycReviewScheduleEnvelope` (`schedule.status="needs_review"`, `case_id="case_77"`, `next_review_date` set) and `KycTriggerEventListEnvelope` with one event. Steps: `repo.getMonitoring()`. Expected: paths `GET /v1/kyc/monitoring/schedule` and `GET /v1/kyc/monitoring/triggers`; derives a `KycMonitoringItem` (caseId=`case_77`, dueAt from `next_review_date`). Also assert `schedule=null` + no events → empty list (no banner). Traces: AC-4.
- **TC-AND-329-07 — List ViewModel state machine (unit).** Target: JVM. Preconditions: fake repo emitting `ApiResult`s. Steps/Expected: empty `items` → `Empty`; success → `Content` (sorted); network error w/ cache → `Content(isStale=true)`; network error w/o cache → `Offline`; HTTP 500 → `Error(retryable=true)`; refresh failure keeps existing `Content`. Traces: AC-5, AC-6.
- **TC-AND-329-08 — Status + history render = backlog AC (Compose-UI).** Target: emulator (CI). Preconditions: `KycCaseDetailScreen` fed a `Content` state with status `under_review` and a 3-node synthesized timeline. Steps: assert status chip text + `contentDescription`; assert each event node (timestamp + message) present and in order. Expected: current status and ordered timeline render. Traces: AC-1, AC-2.
- **TC-AND-329-09 — Status presentation by text-not-color + a11y (Compose-UI).** Target: emulator. Preconditions: parametrize all 7 statuses + one unknown token. Steps: assert each renders a distinct text label (not color only) and a `contentDescription`; merged-descendant semantics on timeline nodes; touch targets ≥48dp. Expected: passes for every value incl. "Status unavailable". Traces: AC-3, AC-9 (a11y).
- **TC-AND-329-10 — Monitoring banner visibility + live region + action (Compose-UI).** Target: emulator. Preconditions: (a) non-empty monitoring item, (b) empty. Steps: assert banner shows only in (a), is announced as an assertive live region, and tap invokes the action callback with the right `KycMonitoringItem` (deep-link target). Expected: per FR-4. Traces: AC-4.
- **TC-AND-329-11 — State surfaces + Empty CTA routing (Compose-UI).** Target: emulator. Preconditions: feed Loading / Empty / Error / Offline states. Steps: assert each renders the shared AND-021 composable; retry/refresh invoke ViewModel intents; Empty CTA routes to verification (AND-320). Expected: per FR-5/AC-5. Traces: AC-5.
- **TC-AND-329-12 — Flaky-dev-host / offline + stale (integration).** Target: **device** (real radio toggling against the plaintext dev host `http://18.222.237.167:8000`; arm64/API-34 path). Preconditions: one successful list load cached, then airplane mode ON. Steps: trigger refresh; observe; restore network; refresh. Expected: with cache → last-known content + stale badge + retry (never cleared); with no cache + no network → `Offline`; recovery clears stale. Note: MUST run on the physical device to exercise real connectivity loss/cleartext transport (emulator network is too clean for the flaky-host case). Traces: AC-6.
- **TC-AND-329-13 — Auth: 401 refresh-then-retry; no PII logged; read-only (integration + unit).** Target: JVM (MockWebServer for 401→refresh→retry; log capture) with a device smoke pass. Preconditions: MockWebServer returns 401 then 200 after a `/ui/session/refresh`; logcat/log sink captured. Steps: issue list fetch; inspect outbound verbs and logs. Expected: exactly one refresh + retry; on second 401 routes to login; **no POST/PUT/DELETE** issued by the screen; response bodies / `reason_codes` / monitoring `details` never appear in logs; analytics carry only status tokens/hashed ids. Traces: AC-7, AC-8.
- **TC-AND-329-14 — i18n / RTL + relative-time formatting (Compose-UI).** Target: emulator. Preconditions: locale set to an RTL locale; cases with various `created_at`. Steps: render list + detail. Expected: client strings localized (no hardcoded UI strings), timeline connector mirrors in RTL, relative timestamps locale-formatted via `DateUtils`. Traces: AC-9 (i18n/a11y).

### Coverage matrix

| AC (§14) | Test case(s) |
|---|---|
| AC-1 (status + history render) | TC-02, TC-04, TC-08 |
| AC-2 (list from GET /v1/kyc/cases, sort, nav) | TC-01, TC-08 |
| AC-3 (status enum mapping, text-not-color, unknown) | TC-02, TC-03, TC-09 |
| AC-4 (monitoring banner from schedule+triggers) | TC-06, TC-10 |
| AC-5 (all states + NotFound) | TC-05, TC-07, TC-11 |
| AC-6 (offline/stale, refresh never clears) | TC-07, TC-12 |
| AC-7 (read-only, no mutations) | TC-13 |
| AC-8 (no PII logged/sent; redacted analytics) | TC-13 |
| AC-9 (build/lint/a11y/i18n/coverage) | TC-09, TC-14 (+ all contract/unit tests for coverage) |
