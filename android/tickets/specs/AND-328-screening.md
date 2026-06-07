---
id: AND-328
title: Screening
milestone: M7
epic: E42
priority: P2
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-319]
blocks: []
---

# AND-328 — Screening

## 1. Overview & Goal

This ticket delivers the read-only presentation of the customer's KYC **screening**
results inside the TestLogon native Android app. Screening is the backend's
sanctions (OFAC/EU/UN) / PEP / adverse-media check that runs per KYC case. The user
cannot *act* on screening directly (it is an automated, backend-driven evaluation,
reviewed by compliance admins), but they must be able to *see* where they stand:
whether each screen is `clear`, a `potential_match` (under review), or a
`confirmed_match` (blocked).

> **CORRECTED (review 2026-06-06):** The backend has **no** single `kycScreening`
> status field and **no** `/v1/kyc/me` or `/v1/kyc/requirements` endpoint. The
> owner-facing screening data is fetched from `GET /ui/kyc/screening/cases/{case_id}`,
> which returns `KycScreeningResultsListResponse` — a **list** of per-screen results
> (`KycScreeningResultOut[]`), each carrying its own `result` enum
> (`clear` | `potential_match` | `confirmed_match`). The screen must therefore
> aggregate a list of results into a single user-facing status (see §4/§5). See §16
> for the full citation audit.

The goal is a single, well-tested Compose surface that consumes the typed KYC
screening DTOs from **AND-319** and renders an aggregated screening status with correct
visual treatment, accurate state mapping, and resilient offline/stale behavior against
the unreliable dev backend. No new network endpoints are introduced by this ticket; the
data arrives via the screening results endpoint modeled in AND-319.

Acceptance per backlog: **"Screening status renders."** This spec makes that concrete:
every documented `result` value (plus the empty / no-results case and an `UNKNOWN`
forward-compat fallback) maps to a deterministic, accessible UI state with loading,
error, and stale variants.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- **Namespace:** `com.testlogon.android`. This ticket lives in
  `feature-kyc` (`com.testlogon.android.feature.kyc.screening`) and consumes
  `core-model`, `core-data`, `core-network`, `core-ui`.
- **Upstream dependency — AND-319 (P0):** owns the KYC API client and DTO ↔ domain
  mapping. The owner case list/detail lives at `GET /v1/kyc/cases` and
  `GET /v1/kyc/cases/{case_id}` (frontend `src/api/endpoints/kyc.ts`), and screening
  results at `GET /ui/kyc/screening/cases/{case_id}` (frontend
  `src/api/endpoints/kycScreening.ts`). Screening is a **list of per-screen results**,
  not a single field. AND-328 does **not** define DTOs; it consumes the domain models
  AND-319 exposes and adds only the presentation layer.
  > **CORRECTED:** the prior text referenced `/v1/kyc/*` "tiers/me, requirements,
  > evaluate" — those endpoints do not exist in the OpenAPI index or the frontend. The
  > owner must first obtain a `case_id` from `/v1/kyc/cases`, then fetch screening.
- **Sibling tickets in E42 / M7:** AND-327 (Proof of funds), AND-321 (KYC submission
  flow). Screening is a *status-only* sibling of those interactive sub-flows and shares
  the same KYC repository and the same status-chip visual vocabulary in `core-ui`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext
  HTTP, unreliable). OpenAPI at `/openapi.json`. Auth is cookie-based with `ui_csrf`
  echoed via `X-CSRF-Token`; the OkHttp stack (AND-027 era) already supplies the
  persistent cookie jar, CSRF interceptor, 20s timeouts, and single-shot
  `/ui/session/refresh` on 401.
- **Web reference:** `frontend/src/api/endpoints/kycScreening.ts` and
  `frontend/src/api/types.ts` are the authority for the exact `result` enum spelling
  (`KycScreeningResultStatus = "clear" | "potential_match" | "confirmed_match"`) and
  the per-screen `KycScreeningResultOut` shape. The web review-queue page
  (`src/pages/kyc/KycScreeningReviewQueuePage.tsx`) maps those literals to labels
  "Clear" / "Potential Match" / "Confirmed Match" and badge tones
  default / secondary / destructive. The Android enum mapper (in AND-319) must mirror
  those string literals; this ticket surfaces an explicit `UNKNOWN` fallback for
  forward compatibility.

## 3. Functional Requirements

1. **FR-1 — Render screening status.** Given a loaded screening results list for the
   user's case, the screen displays an **aggregated** status as a labeled status chip
   plus a short human-readable description and (where applicable) a guidance line.
2. **FR-2 — Cover all statuses.** The aggregated `ScreeningStatus` renders a distinct
   label, color token, and description for each of: `NOT_STARTED` (no case / empty
   `results`), `CLEAR` (all results `clear`), `REVIEW` (any `potential_match`, none
   confirmed), `HIT` (any `confirmed_match`), and `UNKNOWN` (unrecognized wire value,
   forward-compat).
   > **CORRECTED:** the backend per-screen `result` enum has exactly three values —
   > `clear`, `potential_match`, `confirmed_match` (`types.ts: KycScreeningResultStatus`,
   > schema `KycScreeningResultOut.result`). There is **no** `PENDING`/`IN_PROGRESS`
   > screening status on the wire; the aggregation derives `REVIEW`/`HIT` from
   > `potential_match`/`confirmed_match`. A transient "in progress" notion only exists
   > as the local "no results yet for a submitted case" condition (see FR-8).
3. **FR-3 — Loading state.** While the first fetch is in flight and no cached data
   exists, show a skeleton/placeholder for the status card.
4. **FR-4 — Empty / not-applicable.** If the user has no KYC case, or the screening
   `results` array is empty, render `NOT_STARTED` with copy explaining screening has not
   yet produced results.
5. **FR-5 — Error state.** On a fetch failure with no cached value, show an error card
   with a **Retry** action.
6. **FR-6 — Stale/offline state.** If cached screening data exists but the latest
   refresh failed or the device is offline, render the last-known status with a
   non-blocking "Showing saved status — last updated {timestamp}" banner.
7. **FR-7 — Pull-to-refresh / manual refresh.** The user can trigger a re-fetch; this
   re-reads `GET /ui/kyc/screening/cases/{case_id}` (idempotent GET) and updates the
   displayed status.
8. **FR-8 — Auto-refresh for transient states.** When the local state is transient — a
   case exists but `results` is still empty (screening submitted, results pending), or
   the aggregated status is `REVIEW` (awaiting analyst decision) — the screen schedules a
   single bounded re-poll on resume (not a tight loop) so a returning user sees fresh
   progress.
9. **FR-9 — Deep-link entry.** The screen is reachable from the KYC hub via a
   Navigation-Compose route `kyc/screening` and as a standalone destination.

## 4. Technical Design

Single-Activity, Navigation-Compose, Hilt-injected MVVM. No new persistence schema:
screening reuses the KYC cache row written by AND-319's repository.

**Domain model (owned by AND-319, referenced here).** The wire is a *list* of
per-screen results; AND-328 aggregates it into one display status.

```kotlin
// core-model — defined in AND-319, consumed by AND-328
// Per-screen result, mirrors KycScreeningResultOut.result on the wire.
enum class KycScreenResult { CLEAR, POTENTIAL_MATCH, CONFIRMED_MATCH, UNKNOWN }

// Per-screen type, mirrors KycScreeningResultOut.screen_type.
enum class KycScreenType {
    SANCTIONS_OFAC, SANCTIONS_EU, SANCTIONS_UN, PEP_CHECK, ADVERSE_MEDIA, UNKNOWN
}

data class KycScreeningResult(
    val screeningId: String,
    val screenType: KycScreenType,
    val result: KycScreenResult,
    val createdAt: Instant,      // wire: epoch SECONDS (integer), not ISO-8601
    val reviewedAt: Instant?,    // wire: epoch SECONDS or null
    val reviewDecision: String?, // "clear" | "confirm" | "escalate" | null
    // review_note / match_details deliberately NOT surfaced to the owner (see §8)
)

// Aggregated, owner-facing status derived by AND-328.
enum class ScreeningStatus { NOT_STARTED, CLEAR, REVIEW, HIT, UNKNOWN }
```

> **CORRECTED:** the prior `KycScreeningStatus { NOT_STARTED, PENDING, IN_PROGRESS,
> CLEAR, REVIEW, HIT, UNKNOWN }` and the `KycScreening(status, updatedAt: Instant,
> reason)` single-object model do not match the backend. The wire model is a list of
> `KycScreeningResultOut` (schema: `screening_id`, `screen_type`, `result`,
> `match_details`, `review_decision`, `review_note`, `created_at`/`reviewed_at` as
> **epoch-second integers**). There is no `reason` field (it is `review_note`, which is
> analyst-internal) and no `updatedAt` ISO string.

**Repository accessor (extends AND-319's `KycRepository`):**

```kotlin
interface KycRepository {
    // AND-319 surface — owner's screening results for their active case.
    fun observeScreening(): Flow<List<KycScreeningResult>>     // cache-backed, hot
    suspend fun refreshScreening(): ApiResult<List<KycScreeningResult>> // network GET
    // case_id resolution (GET /v1/kyc/cases) is owned by AND-319 and assumed here.
}
```

AND-328 adds **no** new repository methods; it derives the aggregated screening
projection in the ViewModel. Aggregation rule: any `CONFIRMED_MATCH` ⇒ `HIT`; else any
`POTENTIAL_MATCH` ⇒ `REVIEW`; else non-empty all-`CLEAR` ⇒ `CLEAR`; empty/no-case ⇒
`NOT_STARTED`; any unmapped wire value ⇒ `UNKNOWN`.

**ViewModel:**

```kotlin
@HiltViewModel
class ScreeningViewModel @Inject constructor(
    private val kycRepository: KycRepository,
    private val clock: Clock,
) : ViewModel() {

    val uiState: StateFlow<ScreeningUiState> =
        kycRepository.observeScreening()
            .map { results -> results.toScreeningUiState(clock) }
            .catch { emit(ScreeningUiState.Error(it.toUserMessage())) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000),
                     ScreeningUiState.Loading)

    fun refresh() { viewModelScope.launch { kycRepository.refreshScreening() } }

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
        val status: ScreeningStatus,
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

This ticket introduces **no new endpoints**. Screening results are delivered by the
owner-facing endpoint owned by **AND-319**:

- `GET /ui/kyc/screening/cases/{case_id}` — idempotent GET — op
  `get_my_case_screening_ui_kyc_screening_cases__case_id__get`, resp
  `200: KycScreeningResultsListResponse`, `422: HTTPValidationError`. Path param
  `case_id`; the impersonation/session headers (`user_sub`, `X-SESSION-ID`,
  `X-IMPERSONATION-TOKEN`) are query/header params used by web admin tooling and are
  **not** set by the regular Android owner flow.
- The `case_id` is obtained upstream from `GET /v1/kyc/cases` /
  `GET /v1/kyc/cases/{case_id}` (frontend `src/api/endpoints/kyc.ts`), owned by AND-319.

> **CORRECTED:** the prior contract listed `GET /v1/kyc/me` / `/v1/kyc/requirements`
> and a single `kycScreening` object — neither the endpoints nor the field exist
> (verified absent from `openapi.index.txt` and the entire frontend). The real response
> is a **list**, `KycScreeningResultsListResponse { results: KycScreeningResultOut[] }`.

Representative response (verified against schema `KycScreeningResultOut`):

```json
{
  "results": [
    {
      "screening_id": "scr_01H...",
      "case_id": "case_abc",
      "screen_key": "sanctions_ofac",
      "screen_type": "sanctions_ofac",
      "result": "potential_match",
      "match_details": [ { "list_name": "OFAC SDN", "matched_name": "…", "match_score": 0.82, "entity_id": "…", "entity_type": "individual" } ],
      "review_decision": null,
      "review_note": null,
      "reviewed_at": null,
      "trigger": "submission",
      "provider": "mock_screening",
      "created_at": 1749057729
    }
  ]
}
```

Note `created_at` / `reviewed_at` are **epoch-second integers**, not ISO-8601 strings.

Per-screen `result` literal mapping (mirrors `frontend/src/api/types.ts:
KycScreeningResultStatus`), implemented in AND-319 and asserted by AND-328's tests:

| Wire value (`result`) | `KycScreenResult`   |
|-----------------------|---------------------|
| `"clear"`             | `CLEAR`             |
| `"potential_match"`   | `POTENTIAL_MATCH`   |
| `"confirmed_match"`   | `CONFIRMED_MATCH`   |
| anything else / absent| `UNKNOWN`           |

Aggregation to the owner-facing `ScreeningStatus` (AND-328 logic):

| Condition over `results`                          | `ScreeningStatus` |
|---------------------------------------------------|-------------------|
| no case / empty `results`                         | `NOT_STARTED`     |
| any `CONFIRMED_MATCH`                              | `HIT`             |
| else any `POTENTIAL_MATCH`                         | `REVIEW`          |
| else non-empty, all `CLEAR`                        | `CLEAR`           |
| any unmapped `result` value                       | `UNKNOWN`         |

Error envelope follows the project-standard FastAPI `detail` mapping
(`string | [{msg}] | {code,...}`); `422` carries `HTTPValidationError` (an array of
`{loc, msg, type}` under `detail`). `core-network`'s `ApiResult<T>` and the shared
`Throwable.toUserMessage()` handle it; no screening-specific error codes are defined.

## 6. Data & State Management

- **Cache:** Reuses AND-319's Room-backed KYC cache (screening results rows for the
  active case, single-user). No new Room entity, DAO, or migration is added by this
  ticket.
- **Source of truth:** `observeScreening()` emits the cached results list immediately,
  then the repository updates the cache on a successful `refreshScreening()`, which
  re-emits.
- **Projection:** `List<KycScreeningResult>.toScreeningUiState(clock)` is a pure
  function (unit-tested in isolation) that aggregates per-screen `result`s into the
  display `ScreeningStatus` → labels, formats the most-recent `createdAt`/`reviewedAt`
  (epoch-second → relative) against `clock`, and sets `isStale` (cache served but last
  refresh failed/older than a freshness window) and `isTransient` (case present but
  `results` empty, or status `REVIEW`).
- **DataStore:** Not used by this ticket. No user-tunable preferences are involved.
- **Process death:** State is fully derived from the cache + repository flow, so it
  rehydrates on recreation; no `SavedStateHandle` keys are required beyond the nav route.

## 7. Error Handling & Resilience

- **Timeouts/retry:** Inherited from the OkHttp stack — ~20s call timeout; bounded
  exponential backoff retry applies to the idempotent screening GET only. AND-328 adds
  no custom retry logic.
- **401:** Handled transparently by the session-refresh interceptor — mirrors the web
  client `src/api/client.ts`, which on 401 calls `POST /ui/session/refresh` exactly once
  (single-flight) then retries the original request; a second 401 logs out. The screen
  never shows an auth error for a recoverable 401.
- **No-cache failure (FR-5):** `ScreeningUiState.Error` with `onRetry` → `refresh()`.
- **Cache + failed refresh (FR-6):** stay on `Content` with `isStale = true`; surface a
  dismissible banner, never block the last-known status.
- **Empty/unknown status:** no case or empty `results` → `NOT_STARTED`; an unrecognized
  `result` wire string → `UNKNOWN`, rendered with neutral tone and generic copy
  (forward-compatibility, no crash).
- **Transient re-poll (FR-8):** a single `refresh()` on resume when transient (empty
  results or `REVIEW`) — explicitly **not** a polling loop, to respect the unreliable
  dev host.

## 8. Security & Privacy

- Screening results can include sensitive compliance signals (PEP/sanctions hits). The
  per-screen `match_details` (list names, matched names/DOB, scores, entity ids) and
  `review_note`/`review_decision` are **analyst-internal** — the owner UI must **not**
  render or log them. Only the aggregated `ScreeningStatus` and generic guidance are
  shown. Do not log raw `result`/`match_details` at non-debug levels.
  > **CORRECTED:** the prior text referenced a `reason` string safe to display — the
  > wire field is `review_note` (analyst note) plus structured `match_details`; both are
  > internal. There is no owner-safe free-text reason field.
- All transport relies on the shared cookie jar + `X-CSRF-Token` header (the `ui_csrf`
  cookie echoed as `X-CSRF-Token`, per `src/api/client.ts`); the web client additionally
  sends `Authorization: Bearer <accessToken>` when present. No new auth surface.
  Screening data is never written to logs, screenshots-in-test, or analytics payloads in
  raw form (see §10).
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
  Status is the aggregated `ScreeningStatus` **enum name only** (never
  `match_details`/`review_note`/PII).
- **Refresh event:** `kyc_screening_refresh { trigger: manual|resume, result: ok|error }`.
- **Logging:** structured `Timber`/`core-ui` logger at `DEBUG` for state transitions;
  `WARN` on refresh failure with the mapped user message only. `match_details` /
  `review_note` are logged at `VERBOSE` in debug builds only and stripped from release.
- Telemetry routes through the app's existing analytics abstraction (no direct SDK calls
  here); if that abstraction is not yet present, events are emitted via a no-op logger and
  the event names above are the contract for the owning analytics ticket.

## 11. Testing Strategy

- **Unit (core-testing + JUnit5/Turbine):**
  - `toScreeningUiState` aggregation: one test per aggregated `ScreeningStatus`
    (`NOT_STARTED`, `CLEAR`, `REVIEW`, `HIT`, `UNKNOWN`) asserting
    title/description/tone/`isTransient`, including precedence (confirmed > potential >
    clear).
  - Empty `results` / no case → `NOT_STARTED`; unknown `result` wire string → `UNKNOWN`.
  - `isStale` logic: cache-served + failed refresh ⇒ `isStale = true`; fresh ⇒ false.
  - `ScreeningViewModel`: `Loading → Content` on emission; `Error` on `observeScreening`
    throw; `onResume()` calls `refresh()` only when transient (verify with a fake repo).
- **Wire-mapping (in AND-319, cross-checked here):** Moshi parse of each documented
  `result` literal (`clear`/`potential_match`/`confirmed_match`) → correct
  `KycScreenResult`, and `created_at`/`reviewed_at` epoch-second integers → `Instant`,
  using fixtures derived from the `KycScreeningResultOut` schema in `openapi.pretty.json`.
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
  `KycRepository` (screening accessor + `case_id` resolution), the `KycScreeningResult`
  DTO, and the `KycScreenResult`/`KycScreenType` enums + Moshi mapping. AND-328 cannot
  start its data layer until those types exist.
- **Soft alignment:** shares the `StatusChip`/`StatusTone` vocabulary with AND-327 (Proof
  of funds) and the KYC hub; whichever lands first should add it to `core-ui` and the
  other reuses it.
- **Blocks:** none recorded in the backlog.
- **Sequencing:** AND-319 → AND-328 (this) in parallel with AND-321/AND-327 under epic
  E42, milestone M7.

## 13. Risks & Open Questions

- **R-1 — Enum spelling (RESOLVED).** The per-screen `result` literals are confirmed as
  `clear` / `potential_match` / `confirmed_match` (`types.ts: KycScreeningResultStatus`;
  schema `KycScreeningResultOut.result`). The data is a list from
  `GET /ui/kyc/screening/cases/{case_id}`, **not** a field under `/v1/kyc/me`
  (which does not exist). Mitigation retained: `UNKNOWN` fallback + fixture-driven
  mapping tests in AND-319. *Open:* exact `case_id` resolution path for the Android
  owner flow (assumed `GET /v1/kyc/cases`, owned by AND-319).
- **R-2 — Status granularity (RESOLVED).** There is **no** `PENDING`/`IN_PROGRESS` wire
  status; "in progress" is purely the local "case exists but `results` empty" condition.
  `confirmed_match` is the terminal blocking status (`HIT`). *Open:* the exact owner CTA
  for `HIT`/`REVIEW` (contact support? wait?) — product to confirm; default to generic
  "compliance is reviewing / will contact you" copy.
- **R-3 — Analyst-note PII (RESOLVED to safe default).** The wire exposes `review_note`
  and structured `match_details` — both analyst-internal. Decision: the owner UI renders
  **neither**; only the aggregated status + generic guidance. (There is no owner-safe
  `reason` field, contrary to the original draft.)
- **R-4 — Refresh cost on unreliable host.** Auto-refresh on resume could repeatedly time
  out. Mitigated by single-shot, transient-only re-poll.

## 14. Acceptance Criteria

1. Navigating to `kyc/screening` with a loaded screening results list renders the
   aggregated `ScreeningStatus` as a labeled, color-and-icon status chip with a
   description (satisfies backlog "Screening status renders").
2. Every aggregated `ScreeningStatus` value (`NOT_STARTED`, `CLEAR`, `REVIEW`, `HIT`,
   `UNKNOWN`) renders a distinct, correct label/tone, and the aggregation precedence
   (confirmed > potential > clear) is honored — covered by parameterized unit + Compose
   tests.
3. Empty `results` / no case renders `NOT_STARTED`; an unrecognized `result` wire value
   renders `UNKNOWN` without crashing.
4. Loading shows a skeleton; error-with-no-cache shows an error card whose Retry triggers
   `refresh()`; cache-with-failed-refresh shows the last status plus a stale banner with a
   formatted "last updated" timestamp.
5. Pull-to-refresh/manual refresh issues exactly one idempotent
   `GET /ui/kyc/screening/cases/{case_id}` and updates the status on success;
   `onResume()` re-polls once only when the current status is transient (empty results or
   `REVIEW`).
6. Status chips expose TalkBack `contentDescription`, color is never the sole signal,
   targets are ≥48dp, and all copy is externalized in `strings.xml`.
7. `match_details`/`review_note` (and other PII) are not rendered to the owner nor logged
   above debug level; telemetry events `kyc_screening_viewed` and `kyc_screening_refresh`
   fire with the documented payloads (aggregated status enum name only).

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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE. Frontend paths are under
`reference/src/`; OpenAPI pointers are `METHOD /path` from `reference/openapi.index.txt`
and schema names from `reference/openapi.pretty.json`.

1. **Owner screening endpoint is `GET /ui/kyc/screening/cases/{case_id}`.**
   VERDICT: Corrected (was `GET /v1/kyc/me` / `/v1/kyc/requirements`).
   SOURCE: OpenAPI `GET /ui/kyc/screening/cases/{case_id}` (op
   `get_my_case_screening_…`, resp `200:KycScreeningResultsListResponse`);
   `src/api/endpoints/kycScreening.ts: getMyKycCaseScreening`.
2. **Response shape is a list `KycScreeningResultsListResponse { results: KycScreeningResultOut[] }`, not a single `kycScreening` object.**
   VERDICT: Corrected. SOURCE: schema `KycScreeningResultsListResponse` and
   `KycScreeningResultOut` in `openapi.pretty.json`; `src/api/types.ts:
   KycScreeningResultsListResponse` / `KycScreeningResultOut`.
3. **Per-screen `result` enum = `clear | potential_match | confirmed_match` (exactly 3 values).**
   VERDICT: Corrected (was 7 values incl. `PENDING`/`IN_PROGRESS`/`passed`/`flagged`).
   SOURCE: schema `KycScreeningResultOut.result` (enum) in `openapi.pretty.json`;
   `src/api/types.ts: KycScreeningResultStatus`.
4. **Web labels/tones: Clear/Potential Match/Confirmed Match → default/secondary/destructive.**
   VERDICT: Verified. SOURCE: `src/pages/kyc/KycScreeningReviewQueuePage.tsx` (lines
   ~42–50).
5. **`screen_type` enum = `sanctions_ofac | sanctions_eu | sanctions_un | pep_check | adverse_media`.**
   VERDICT: Verified. SOURCE: schema `KycScreeningResultOut.screen_type`;
   `src/api/types.ts: KycScreenType`.
6. **`created_at` / `reviewed_at` are epoch-second integers, not ISO-8601 strings.**
   VERDICT: Corrected (draft used `"updatedAt": "2026-…T…Z"`). SOURCE: schema
   `KycScreeningResultOut` (`created_at`: integer default 0; `reviewed_at`: integer|null).
7. **No owner-safe `reason` field; analyst data is `review_note` + structured `match_details`.**
   VERDICT: Corrected. SOURCE: schema `KycScreeningResultOut` (`review_note`,
   `match_details`→`KycScreeningMatchDetail`); `src/api/types.ts: KycScreeningMatchDetail`.
8. **Auth/transport: cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 a single `POST /ui/session/refresh` then retry, second 401 → logout.**
   VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
   `X-CSRF-Token`; `refreshSession()` → `/ui/session/refresh`; single-flight
   `refreshPromise`; 401 retry block).
9. **The web client also sends `Authorization: Bearer <accessToken>` when a token is present.**
   VERDICT: Verified (the draft described auth as cookie-only). SOURCE: `src/api/client.ts`
   (`useAuthStore.getState().accessToken` → `Authorization` header).
10. **Error envelope = FastAPI `detail` (`string | [{msg}] | {code,…}`); 422 = `HTTPValidationError`.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail`; OpenAPI resp
    `422:HTTPValidationError` on the screening endpoint.
11. **Owner `case_id` is obtained from `GET /v1/kyc/cases` / `GET /v1/kyc/cases/{case_id}`.**
    VERDICT: Verified (provenance) / Unverified-assumption (that AND-319 wires this for
    Android). SOURCE: `src/api/endpoints/kyc.ts: listKycCases` / `getKycCase`
    (BASE `/v1/kyc/cases`).
12. **No new endpoints introduced by this ticket; data comes via AND-319.**
    VERDICT: Verified. SOURCE: ticket scope `kycScreening status display`
    (`specs-src/AND-328.md`); endpoints above are pre-existing.
13. **Cleartext dev host `http://18.222.237.167:8000` via `network_security_config` dev allowlist.**
    VERDICT: Unverified-assumption (Android-side config not in the provided sources; it
    is an inherited AND-027 claim). SOURCE: none in reference set — Android infra detail.
14. **MVVM + Hilt + Navigation-Compose + Compose UI choices.**
    VERDICT: Unverified-assumption (framework choice). SOURCE: framework ref —
    https://developer.android.com/jetpack/compose and
    https://developer.android.com/training/dependency-injection/hilt-android .
15. **Relative-time formatting via `DateUtils.getRelativeTimeSpanString`.**
    VERDICT: Unverified-assumption (framework choice). SOURCE: framework ref —
    https://developer.android.com/reference/android/text/format/DateUtils .

### Corrections made

- **Endpoint:** replaced the non-existent `GET /v1/kyc/me` / `/v1/kyc/requirements` with
  the real `GET /ui/kyc/screening/cases/{case_id}` (and noted `case_id` comes from
  `/v1/kyc/cases`). (§1, §2, §5, §7, §14)
- **Data shape:** replaced the single `kycScreening` object with the list
  `KycScreeningResultsListResponse` / `KycScreeningResultOut[]`. (§1, §4, §5, §6)
- **Status enum:** replaced the 7-value `KycScreeningStatus` and bogus literals
  (`pending`, `in_progress`, `passed`, `flagged`) with the real 3-value `result` enum
  (`clear`/`potential_match`/`confirmed_match`) plus an AND-328-derived aggregated
  `ScreeningStatus` (`NOT_STARTED`/`CLEAR`/`REVIEW`/`HIT`/`UNKNOWN`) and an explicit
  aggregation rule. (§3 FR-2, §4, §5, §11, §14)
- **Timestamps:** corrected `updatedAt` ISO-8601 to `created_at`/`reviewed_at`
  epoch-second integers. (§4, §5, §6)
- **PII field:** corrected the owner-displayable `reason` to analyst-internal
  `review_note` + `match_details`, which the owner UI must not render or log. (§8, §10,
  §13 R-3)
- **Auth:** clarified that the web client also sends an `Authorization: Bearer` header in
  addition to cookie + CSRF. (§8)
- **Transient state:** redefined FR-8 transience as "case exists but `results` empty" or
  aggregated `REVIEW`, since there is no `PENDING`/`IN_PROGRESS` wire status. (§3, §6, §7)

### Open assumptions

- **`case_id` resolution for the Android owner flow** — assumed AND-319 exposes the
  active KYC case id (web uses `GET /v1/kyc/cases`); not yet confirmed for the Android
  data layer. (claim 11)
- **AND-319 domain types/cache** (`KycRepository`, screening DTOs, Room rows) — referenced
  but owned by AND-319; their final names/signatures are assumed, not verified here.
- **Android cleartext/network-security-config + 20s OkHttp timeouts + cookie jar/CSRF
  interceptor (AND-027)** — Android infra not present in the reference sources. (claim 13)
- **Framework choices** (Compose, Hilt, Navigation-Compose, `DateUtils` relative time) —
  standard but unverifiable from the provided backend/frontend sources. (claims 14–15)
- **Owner CTA for `HIT`/`REVIEW`** — product decision deferred; generic copy used.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local); **emu35** = headless emulator AVD
`test35` (x86_64, API 35) in CI; **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34, arm64-v8a). This ticket is read-only status UI with no
camera/biometrics/WebRTC/push, so most cases run on JVM/emu35; one ABI/API-parity case is
pinned to the physical device.

- **TC-AND-328-01** — Type: unit (JVM). Target: JVM.
  Test target: `List<KycScreeningResult>.toScreeningUiState` aggregation.
  Preconditions: deterministic `clock`.
  Steps: feed lists exercising each branch — all-`clear`; one `potential_match`+rest
  `clear`; one `confirmed_match`+a `potential_match` (precedence); empty list.
  Expected: `CLEAR`, `REVIEW`, `HIT` (confirmed wins), `NOT_STARTED` respectively, each
  with correct title/description/tone and `isTransient` (`REVIEW`/empty ⇒ true,
  `CLEAR`/`HIT` ⇒ false). Traces: AC-2, AC-3.
- **TC-AND-328-02** — Type: unit (JVM). Target: JVM.
  Test target: unknown-value handling.
  Preconditions: none. Steps: parse a result with `result="sanctions_pending"` (unmapped)
  and a `screen_type` unknown to the enum. Expected: result → `UNKNOWN` (neutral tone,
  generic copy), no exception; aggregated status `UNKNOWN`. Traces: AC-3.
- **TC-AND-328-03** — Type: contract/MockWebServer. Target: JVM (Robolectric/OkHttp).
  Test target: `GET /ui/kyc/screening/cases/{case_id}` request + parse.
  Preconditions: MockWebServer enqueues the §5 sample `KycScreeningResultsListResponse`.
  Steps: call `refreshScreening()`. Expected: exactly one GET to
  `/ui/kyc/screening/cases/{case_id}`; `created_at` epoch-second → `Instant`; `result`
  literals map per table; `match_details`/`review_note` parsed but **not** surfaced.
  Traces: AC-1, AC-5.
- **TC-AND-328-04** — Type: contract/MockWebServer. Target: JVM.
  Test target: 422 validation error envelope.
  Preconditions: MockWebServer returns `422` with `{"detail":[{"loc":["path","case_id"],"msg":"…","type":"…"}]}`.
  Steps: `refreshScreening()` with no cache. Expected: `ApiResult` error mapped via
  `toUserMessage()` (joined `msg`); ViewModel emits `Error`. Traces: AC-4.
- **TC-AND-328-05** — Type: contract/MockWebServer. Target: JVM.
  Test target: 401 → single session refresh → retry.
  Preconditions: enqueue `401`, then a successful `200` for the retry; stub
  `POST /ui/session/refresh` → `200`.
  Steps: `refreshScreening()`. Expected: exactly one `/ui/session/refresh` call, original
  request retried once, success surfaced; no auth error shown. Traces: AC-1, AC-4.
- **TC-AND-328-06** — Type: contract/MockWebServer. Target: JVM.
  Test target: CSRF header propagation.
  Preconditions: `ui_csrf` cookie present in the cookie jar.
  Steps: issue the screening GET. Expected: outgoing request carries
  `X-CSRF-Token: <ui_csrf>` (and `Authorization: Bearer` if a token is set). Traces: AC-7
  (security/transport).
- **TC-AND-328-07** — Type: integration. Target: JVM.
  Test target: ViewModel state machine with fake repository.
  Preconditions: fake `KycRepository`.
  Steps: emit Loading→results; throw from `observeScreening`; toggle stale.
  Expected: `Loading → Content` on emission; `Error` on throw; `isStale=true` when cache
  served + refresh failed. Traces: AC-4.
- **TC-AND-328-08** — Type: integration. Target: JVM.
  Test target: transient re-poll on resume (FR-8).
  Preconditions: fake repo; current status `REVIEW` (and a second run with empty
  `results`). Steps: call `onResume()`; then with status `CLEAR` call `onResume()`.
  Expected: `refresh()` invoked exactly once for transient, zero times for `CLEAR`; never
  a loop. Traces: AC-5.
- **TC-AND-328-09** — Type: Compose-UI. Target: emu35 (createComposeRule).
  Test target: `ScreeningScreen` per-state rendering.
  Preconditions: supply each `ScreeningUiState`.
  Steps: render Loading (skeleton), Content for `CLEAR`/`REVIEW`/`HIT`/`NOT_STARTED`/
  `UNKNOWN`, and Error. Expected: distinct label/description per status; chip shows
  icon+text (color not sole signal); Error shows Retry. Traces: AC-1, AC-2, AC-4, AC-6.
- **TC-AND-328-10** — Type: Compose-UI. Target: emu35.
  Test target: Retry + stale banner behavior.
  Preconditions: Error state, then Content with `isStale=true`.
  Steps: click Retry (assert callback); render stale Content. Expected: Retry invokes
  `onRetry`; banner "Showing saved status — last updated {ts}" shown iff `isStale`, with
  a formatted relative timestamp. Traces: AC-4, AC-5.
- **TC-AND-328-11** — Type: Compose-UI (accessibility). Target: emu35.
  Test target: TalkBack semantics, target size, externalized strings.
  Preconditions: Content `REVIEW`. Steps: assert chip `contentDescription` (e.g.
  "Screening status: under review"); Retry/Refresh ≥48dp; assert strings resolve from
  `strings.xml` (no hardcoded literals). Traces: AC-6.
- **TC-AND-328-12** — Type: integration (offline/flaky host). Target: emu35 (airplane
  mode toggled via `adb`). Test target: cache-served + failed refresh path (FR-6).
  Preconditions: warm cache from a prior success; then network down.
  Steps: trigger refresh while offline. Expected: last-known status remains; `isStale`
  banner appears; no crash, no error card (cache present). Traces: AC-4.
- **TC-AND-328-13** — Type: security. Target: JVM.
  Test target: no-PII logging.
  Preconditions: capture logger output in a release-config test.
  Steps: render `HIT` with populated `match_details`/`review_note`; emit telemetry.
  Expected: logs/telemetry contain only the aggregated `ScreeningStatus` enum name;
  `match_details`/`review_note` never appear above DEBUG; `kyc_screening_viewed` /
  `kyc_screening_refresh` payloads match §10. Traces: AC-7.
- **TC-AND-328-14** — Type: instrumented/e2e (ABI/API parity). Target: **A15 (physical,
  MUST)**. Test target: full screen on arm64-v8a / API 34 vs emu x86_64 / API 35.
  Preconditions: build installed on the device via adb; MockWebServer (or recorded
  fixtures) backing the repository (no live dev host). Steps: navigate `kyc/screening`,
  pull-to-refresh, exercise `REVIEW`/`HIT`/`NOT_STARTED`. Expected: identical rendering,
  timestamp formatting, and TalkBack semantics as emu35; no arm64/x86 or API-34/35
  regressions (e.g. `java.time`/`DateUtils` locale formatting). MUST run on the physical
  device for ABI/API coverage. Traces: AC-1, AC-2, AC-6.

### Coverage matrix

| AC (§14) | Covered by |
|----------|-----------|
| AC-1 | TC-03, TC-05, TC-09, TC-14 |
| AC-2 | TC-01, TC-09, TC-14 |
| AC-3 | TC-01, TC-02 |
| AC-4 | TC-04, TC-05, TC-07, TC-09, TC-10, TC-12 |
| AC-5 | TC-03, TC-08, TC-10 |
| AC-6 | TC-09, TC-11, TC-14 |
| AC-7 | TC-06, TC-13 |
