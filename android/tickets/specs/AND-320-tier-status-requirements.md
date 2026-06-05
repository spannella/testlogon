---
id: AND-320
title: Tier status & requirements
milestone: M7
epic: E42
priority: P0
size: M
status: draft
depends_on: [AND-319]
blocks: []
---

# AND-320 — Tier status & requirements

## 1. Overview & Goal

This ticket delivers the **Tier Status & Requirements** screen of the KYC (Know Your
Customer) flow in the native Android port of TestLogon. The screen shows the user's
**current verification tier**, the **target tier** they may advance to, the concrete
**requirements** that gate that advancement, and an **Evaluate** action that asks the
backend to re-assess the user against the target tier's requirements and reflects the
updated state back into the UI.

Goal: render the user's tier and the requirements for the next (target) tier, and wire an
`evaluate` action that triggers a server-side re-evaluation and updates the on-screen
state (requirements satisfied/unsatisfied, eligibility for promotion) without a manual
refresh. This is a P0 feature in milestone **M7** under epic **E42** (KYC). It depends on
**AND-319** (KYC API + DTOs), which owns the `/v1/kyc/*` DTOs and Retrofit service; this
ticket consumes those DTOs and adds the repository, ViewModel, and Compose UI.

Out of scope: document capture/upload, case detail screens, SMS/email/TOTP MFA (owned by
the auth feature), and any write path beyond `evaluate` (e.g. tier upgrade submission),
which are separate M7 tickets.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lives in `feature-kyc` (Gradle module
  `:feature:kyc`, namespace `com.testlogon.android.feature.kyc`).
- **DTO/API source (AND-319):** Retrofit service `KycApi`, Moshi DTOs, and the
  `ApiResult<T>` wrapper for `/v1/kyc/tiers/me`, `/v1/kyc/requirements`,
  `/v1/kyc/evaluate`, and `/v1/kyc/cases` live in `core-network` + `core-model`. This
  ticket must not duplicate those DTOs; it imports them.
- **Web reference:** `frontend/src/api/endpoints/kyc.ts` and shared types in
  `frontend/src/api/types.ts` (tier/requirement shapes); OpenAPI at
  `http://18.222.237.167:8000/openapi.json` under the `kyc` tag is authoritative for
  field names and enums when web and OpenAPI disagree.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single-Activity),
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore for
  the cached snapshot. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Layering:** `app -> feature-kyc -> core-*`. ViewModel exposes `StateFlow<UiState>`.
  Auth is cookie-based (persistent cookie jar + `X-CSRF-Token`); a 401 triggers one
  `POST /ui/session/refresh` then a single retry — this is handled centrally in the
  OkHttp/auth interceptor from `core-network` and is not re-implemented here.

## 3. Functional Requirements

FR-1. On entering the screen the app loads the user's current tier and the requirements
for the target (next) tier. Until data arrives a loading state is shown.

FR-2. **Current tier** is rendered: tier id/name (e.g. `tier_0`/"Unverified",
`tier_1`/"Basic", `tier_2`/"Verified"), a short status/label, and the tier's enabled
capabilities/limits if present in the payload.

FR-3. **Target tier requirements** are rendered as a list. Each requirement shows: a
human-readable label, its `status` (`satisfied` / `pending` / `action_required` /
`rejected`), and optional helper text. Satisfied requirements are visually distinct
(check affordance) from unsatisfied ones.

FR-4. An **Evaluate** button is shown when a target tier exists. Tapping it calls the
evaluate endpoint, shows an inline progress indicator on the action, and on success
replaces the rendered tier + requirement statuses with the response (FR-6).

FR-5. If the user is already at the maximum tier (no target tier), the requirements list
and Evaluate button are hidden and a terminal "highest tier reached" message is shown.

FR-6. After a successful `evaluate`, the screen reflects the new state: updated current
tier (if promoted), updated per-requirement statuses, and an overall
`eligible_for_target` flag that, when true, surfaces a non-blocking eligibility banner.
The update is in-memory immediate and persisted to the cached snapshot.

FR-7. Pull-to-refresh re-fetches tiers/me + requirements (idempotent GETs).

FR-8. Errors (load failure, evaluate failure) are surfaced per the rules in §7 without
losing previously loaded content where possible (stale-while-error).

## 4. Technical Design

Single feature module `:feature:kyc` (this ticket adds the tier-status surface; sibling
M7 tickets add other KYC surfaces to the same module).

**Navigation.** Route registered in the feature's nav graph:

```kotlin
const val ROUTE_KYC_TIER = "kyc/tier"

fun NavGraphBuilder.kycTierScreen(onOpenCase: (String) -> Unit) {
    composable(ROUTE_KYC_TIER) { TierStatusRoute(onOpenCase = onOpenCase) }
}
```

**Repository** (`feature-kyc/data`), wrapping the AND-319 `KycApi`:

```kotlin
interface KycTierRepository {
    /** Combined snapshot: current tier + target requirements. Cache-then-network. */
    fun observeTierStatus(): Flow<TierStatus>            // emits cached then fresh
    suspend fun refreshTierStatus(): ApiResult<TierStatus>
    suspend fun evaluate(targetTier: String?): ApiResult<TierEvaluation>
}

@Singleton
class KycTierRepositoryImpl @Inject constructor(
    private val api: KycApi,                  // from AND-319
    private val store: KycTierStore,          // DataStore-backed snapshot
    @IoDispatcher private val io: CoroutineDispatcher,
) : KycTierRepository { /* ... */ }
```

`refreshTierStatus()` issues `GET /v1/kyc/tiers/me` and `GET /v1/kyc/requirements`
(with `target_tier` when known) concurrently via `coroutineScope { async {} }`, maps both
DTOs into the domain `TierStatus`, writes it to `KycTierStore`, and returns the merged
result. Network DTO→domain mapping reuses the AND-319 DTOs; this module owns only the
domain models below.

**Domain models** (`core-model` or feature-local `model/`):

```kotlin
enum class TierLevel { TIER_0, TIER_1, TIER_2, UNKNOWN }
enum class ReqStatus { SATISFIED, PENDING, ACTION_REQUIRED, REJECTED, UNKNOWN }

data class Tier(
    val id: String,
    val level: TierLevel,
    val name: String,
    val limits: List<TierLimit> = emptyList(),
)
data class TierLimit(val label: String, val value: String)

data class Requirement(
    val key: String,
    val label: String,
    val status: ReqStatus,
    val helpText: String? = null,
    val caseId: String? = null,        // deep-link to a case if one exists
)

data class TierStatus(
    val current: Tier,
    val target: Tier?,                 // null => at max tier
    val requirements: List<Requirement>,
    val eligibleForTarget: Boolean,
    val asOf: Instant,                 // for stale indication
)

data class TierEvaluation(
    val tierStatus: TierStatus,
    val promoted: Boolean,
)
```

**ViewModel:**

```kotlin
@HiltViewModel
class TierStatusViewModel @Inject constructor(
    private val repo: KycTierRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<TierUiState>(TierUiState.Loading)
    val state: StateFlow<TierUiState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<TierEvent>()        // one-shot snackbars
    val events: SharedFlow<TierEvent> = _events.asSharedFlow()

    init { observe(); refresh() }

    fun onEvaluate() { /* sets evaluating=true on current Content, calls repo.evaluate */ }
    fun onRefresh() { /* refresh() */ }
    fun onRetry() { /* refresh() */ }
}

sealed interface TierUiState {
    data object Loading : TierUiState
    data class Content(
        val current: Tier,
        val target: Tier?,
        val requirements: List<Requirement>,
        val eligibleForTarget: Boolean,
        val evaluating: Boolean = false,
        val refreshing: Boolean = false,
        val stale: Boolean = false,
        val inlineError: String? = null,
    ) : TierUiState
    data class Error(val message: String, val canRetry: Boolean) : TierUiState
}

sealed interface TierEvent {
    data class Snackbar(val message: String) : TierEvent
    data class Promoted(val toTierName: String) : TierEvent
}
```

`onEvaluate()` keeps the existing `Content` visible, sets `evaluating = true`, and on the
`ApiResult` success replaces `current/target/requirements/eligibleForTarget` from the
`TierEvaluation`; on `promoted == true` it emits `TierEvent.Promoted`.

**Compose UI** (`TierStatusScreen`): stateless composable taking `TierUiState` and
callbacks. Sections: `CurrentTierCard`, `RequirementList` (LazyColumn of `RequirementRow`),
`EvaluateBar` (button + inline progress), eligibility banner, max-tier terminal state.
Pull-to-refresh via Material 3 `PullToRefreshBox`. Requirement rows with a `caseId` are
clickable and invoke `onOpenCase(caseId)`.

## 5. API Contract

All endpoints are defined by **AND-319**; this ticket consumes them. Auth/CSRF/refresh is
handled by the shared interceptor. Base dev host (PLAINTEXT HTTP): `http://18.222.237.167:8000`.

**GET `/v1/kyc/tiers/me`** → current tier snapshot.

```json
{
  "current_tier": { "id": "tier_1", "name": "Basic",
    "limits": [{ "label": "Daily transfer", "value": "$1,000" }] },
  "target_tier": { "id": "tier_2", "name": "Verified", "limits": [] },
  "eligible_for_target": false
}
```

**GET `/v1/kyc/requirements?target_tier=tier_2`** → requirements for the target tier.

```json
{
  "target_tier": "tier_2",
  "requirements": [
    { "key": "id_document", "label": "Government ID", "status": "satisfied",
      "help_text": null, "case_id": "case_abc" },
    { "key": "selfie", "label": "Liveness selfie", "status": "action_required",
      "help_text": "Retake in better lighting", "case_id": null },
    { "key": "address", "label": "Proof of address", "status": "pending",
      "help_text": null, "case_id": null }
  ]
}
```

**POST `/v1/kyc/evaluate`** → re-evaluate against a target tier.

Request:
```json
{ "target_tier": "tier_2" }
```
Response (returns the same shape as tiers/me merged with requirements + a `promoted`
flag; field names follow OpenAPI):
```json
{
  "current_tier": { "id": "tier_1", "name": "Basic" },
  "target_tier": { "id": "tier_2", "name": "Verified" },
  "eligible_for_target": true,
  "promoted": false,
  "requirements": [ { "key": "address", "label": "Proof of address",
                      "status": "satisfied", "case_id": null } ]
}
```

`status` enum values: `satisfied | pending | action_required | rejected`. Unknown strings
map to `ReqStatus.UNKNOWN` (forward-compatible). `target_tier` absent/`null` ⇒ at max tier.

**Error shape** (FastAPI `detail`, mapped centrally to `ApiResult.Failure` per project
convention): `detail` may be a string, `[{ "msg": "...", "loc": [...] }]`, or
`{ "code": "...", ... }`. The repository surfaces the resolved human message.

## 6. Data & State Management

- **Single source of truth:** `KycTierStore` (DataStore Preferences or a small
  Proto/JSON DataStore) persists the last `TierStatus` as a Moshi-serialized snapshot so
  the screen renders instantly offline/stale. Key: `kyc_tier_status_json` plus
  `kyc_tier_status_as_of` (epoch millis).
- **Cache-then-network:** `observeTierStatus()` emits the cached snapshot first (with
  `stale = (now - asOf) > 5 min`), then the network result once `refresh` completes.
- **Evaluate write-through:** a successful `evaluate` overwrites the snapshot so a later
  cold start reflects the most recent evaluation.
- **State ownership:** `TierStatusViewModel` holds `StateFlow<TierUiState>`; `evaluating`,
  `refreshing`, `stale`, and transient `inlineError` are fields on `Content` so the screen
  never flips back to full-screen `Loading`/`Error` once content exists. One-shot results
  (promotion, evaluate-failure snackbar) go through `events: SharedFlow`.
- No Room is required for this screen; the snapshot is small and single-row, so DataStore
  is the chosen store. Room (`core-data`) remains available if case lists are added later.

## 7. Error Handling & Resilience

- **Timeouts/backoff:** GETs (`tiers/me`, `requirements`) are idempotent ⇒ use the shared
  client's ~20s timeout and bounded backoff retry (max 2 retries, exponential w/ jitter)
  from `core-network`. `POST /v1/kyc/evaluate` is **not** retried automatically (non-GET);
  on failure the user retries via the button.
- **First load, no cache, failure:** `TierUiState.Error(message, canRetry = true)` with a
  Retry action calling `onRetry()`.
- **Failure with existing content:** keep `Content`, set `stale = true`, and either set
  `inlineError` or emit `TierEvent.Snackbar` ("Couldn't refresh — showing saved status").
- **Evaluate failure:** clear `evaluating`, keep prior content, emit
  `TierEvent.Snackbar(message)`; never partially apply a failed evaluation.
- **401:** handled by the central auth interceptor (one `POST /ui/session/refresh` then
  retry); if refresh fails the failure propagates as an auth error and the app's global
  session handler navigates to login — this screen does not implement auth logic.
- **Unknown enum values** for tier level / requirement status degrade to `UNKNOWN` and
  render with a neutral style rather than crashing.

## 8. Security & Privacy

- KYC tier/requirement data is sensitive PII-adjacent; it must never be written to logcat
  at any level (see §10). The DataStore snapshot lives in app-private storage; do not back
  it up — exclude `kyc_tier_status*` via `data_extraction_rules.xml` / `backup_rules.xml`.
- All requests ride the existing cookie jar + `X-CSRF-Token` header; this ticket adds no
  new auth surface and stores no credentials.
- Dev backend is plaintext HTTP and is dev-only; release builds must point at an HTTPS
  base URL and set `usesCleartextTraffic=false` with a network-security-config that
  whitelists only the dev host in debug. (Owned by the build/config ticket; noted here as
  a constraint.)
- `evaluate` is a state-changing POST and therefore always carries the CSRF header; the
  repository must not issue it on a stale/missing CSRF cookie (the interceptor guarantees
  this).

## 9. Accessibility & i18n

- All strings in `feature-kyc/src/main/res/values/strings.xml`; no hardcoded user-facing
  text. Tier names and requirement labels come from the server and are shown verbatim.
- Requirement status is conveyed by **icon + text + color**, not color alone (WCAG 1.4.1).
  Each `RequirementRow` sets `Modifier.semantics { contentDescription = "<label>, <status>" }`.
- The Evaluate button exposes a `stateDescription` while `evaluating` ("Evaluating…") and
  is disabled (not just visually) during the call. Min touch target 48dp.
- Pull-to-refresh has an accessible equivalent (a refresh action in the top bar overflow)
  for users who cannot perform the gesture.
- Supports dynamic font scaling; cards use `wrapContentHeight`. RTL-safe via
  start/end paddings. Currency/limit values are server-formatted strings (no client
  number formatting in this ticket).

## 10. Telemetry & Logging

- Analytics events via the shared `Analytics` interface (`core-ui`/`core-data`):
  `kyc_tier_viewed { current_tier, target_tier }`,
  `kyc_evaluate_tapped { target_tier }`,
  `kyc_evaluate_result { target_tier, promoted, eligible }`,
  `kyc_tier_load_error { stage: "tiers"|"requirements"|"evaluate", code }`.
- **No PII in events or logs:** emit tier ids and boolean/enum outcomes only — never
  document statuses tied to identity beyond the coarse requirement status enum, and never
  help-text content.
- Network logging uses the OkHttp logging interceptor at `NONE` for KYC in release and at
  `BASIC` (no bodies) in debug to avoid leaking PII bodies.

## 11. Testing Strategy

Unit (JUnit, `core-testing`, MockWebServer):
- DTO→domain mapping incl. unknown enum → `UNKNOWN`; `target_tier == null` ⇒ max-tier.
- `KycTierRepositoryImpl.refreshTierStatus()` merges tiers/me + requirements; concurrent
  fetch; writes snapshot; maps FastAPI `detail` (all 3 shapes) to a message.
- `evaluate()` success updates snapshot and sets `promoted`; failure leaves snapshot intact.
- Retry policy: GETs retried (assert request count) on 503; POST `evaluate` not retried.

ViewModel (Turbine):
- `Loading → Content` on success; `Loading → Error(canRetry)` on first-load failure.
- `onEvaluate()` sets `evaluating=true` then applies result; promotion emits
  `TierEvent.Promoted`; failure emits `TierEvent.Snackbar` and keeps prior content.
- Stale-while-error: refresh failure with cache present keeps `Content`, sets `stale`.

Compose UI (`createComposeRule`):
- Current tier + requirement statuses render; satisfied vs action_required distinguished.
- Max-tier state hides Evaluate + requirements and shows terminal message.
- Evaluate button disabled and shows progress while `evaluating`.
- Requirement with `caseId` invokes `onOpenCase`.

Acceptance test mapping each §14 criterion to at least one of the above. Target ≥80% line
coverage in `feature-kyc` tier package.

## 12. Dependencies & Sequencing

- **Depends on AND-319** (KYC API + DTOs): `KycApi`, Moshi DTOs for `tiers/me`,
  `requirements`, `evaluate`, and `ApiResult` mapping must merge first. This ticket is
  blocked until AND-319's DTO tests pass.
- Transitively depends on `core-network` (auth/CSRF/refresh interceptor, retry policy)
  and `core-model`/`core-ui` (theme, `Analytics`).
- **Blocks:** none recorded in the source backlog. Downstream KYC screens (cases,
  document capture) are separate M7 tickets and consume the same `feature-kyc` module but
  do not depend on this screen's UI.
- Sequencing: land repository + ViewModel + DataStore store, then Compose UI, then wire
  the nav route into the app graph and the entry point (settings/profile → KYC).

## 13. Risks & Open Questions

- **Evaluate response shape:** the exact `evaluate` payload (does it return the full
  requirements array or a delta?) must be confirmed against `/openapi.json`; this spec
  assumes it returns the merged full snapshot + `promoted`. If it returns only a status,
  the ViewModel must re-fetch `tiers/me`+`requirements` after evaluate. **Open.**
- **Target-tier selection:** assumed single linear next tier. If multiple parallel target
  tiers exist, the UI needs a selector — confirm with backend tier model. **Open.**
- **Requirement→case linkage:** whether `case_id` is always present for `action_required`
  items affects deep-linking. **Open**, defaults to optional.
- **Eligibility vs promotion:** `eligible_for_target=true` may or may not auto-promote on
  evaluate; current design treats them as distinct (banner vs `promoted` event). Confirm.
- Dev backend unreliability may make manual QA flaky; rely on MockWebServer for CI.

## 14. Acceptance Criteria

AC-1. On screen entry, the current tier (name + limits if present) renders within one
load cycle; a loading state shows until data or cache is available.

AC-2. When a target tier exists, its requirements render as a list with per-requirement
status (satisfied / pending / action_required / rejected) distinguished by icon+text, not
color alone.

AC-3. Tapping **Evaluate** calls `POST /v1/kyc/evaluate` with the target tier, shows
inline progress, and on success updates the rendered current tier and requirement statuses
from the response (state updates without manual refresh). *(Directly satisfies the source
acceptance: "Tier + requirements render; evaluate updates state.")*

AC-4. A successful evaluate that promotes the user updates the current tier and surfaces a
promotion confirmation; `eligible_for_target=true` surfaces an eligibility banner.

AC-5. When at the maximum tier (no target), the requirements list and Evaluate button are
hidden and a terminal message is shown.

AC-6. Load failure with no cache shows a retryable error; failure with cache present keeps
content visible, marks it stale, and surfaces a non-blocking message. Evaluate failure
keeps prior content unchanged and shows a message.

AC-7. The most recent successful tier status / evaluation persists and is shown on the
next cold start before the network refresh completes.

AC-8. No KYC PII (help text, identity-linked detail) appears in logs or analytics; only
tier ids and coarse status/boolean outcomes are logged.

## 15. Definition of Done

- `:feature:kyc` tier-status screen implemented: repository, `KycTierStore` (DataStore),
  `TierStatusViewModel`, and `TierStatusScreen` Compose UI, wired into the app nav graph.
- Consumes AND-319 DTOs/`KycApi`; no DTO duplication.
- All §14 acceptance criteria met and covered by unit, ViewModel, and Compose tests; CI
  green; ≥80% coverage on the tier package.
- Strings externalized; accessibility (semantics, 48dp targets, non-color status,
  refresh affordance) verified; RTL and font-scaling checked.
- Telemetry events emitted with no PII; logging interceptor configured per §10.
- ktlint/detekt clean; builds on JDK 17 / AGP 8.7.3 / Gradle 8.9; no new cleartext
  exposure in release config.
- Open questions in §13 either resolved with backend or captured as follow-up tickets
  referenced in the PR description.
