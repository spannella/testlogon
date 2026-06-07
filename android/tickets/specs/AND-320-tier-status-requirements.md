---
id: AND-320
title: Tier status & requirements
milestone: M7
epic: E42
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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

> **Review note (corrected):** The backend tier model is **5 integer tiers (0–4)**, not the
> three string-id tiers (`tier_0/1/2`) the original draft assumed. Verified against the web
> reference `src/pages/kyc/KycTierProgress.tsx` (`TIER_NAMES` 0..4 = Unverified / Basic /
> ID Verified / Enhanced / Institutional) and `src/api/types.ts: TierDetails` (`current_tier:
> number`). The max tier is **4 (Institutional)**, and the "next/target tier" the web client
> requests is `min(current_tier + 1, 4)`. All tier identifiers in this spec are integers.

Out of scope: document capture/upload, case detail screens, SMS/email/TOTP MFA (owned by
the auth feature), and any write path beyond `evaluate` (e.g. tier upgrade submission),
which are separate M7 tickets.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lives in `feature-kyc` (Gradle module
  `:feature:kyc`, namespace `com.testlogon.android.feature.kyc`).
- **DTO/API source (AND-319):** Retrofit service `KycApi`, Moshi DTOs, and the
  `ApiResult<T>` wrapper for `/v1/kyc/tiers/me`, `/v1/kyc/tiers/me/requirements/{target_tier}`,
  and `/v1/kyc/tiers/me/evaluate` live in `core-network` + `core-model`. This
  ticket must not duplicate those DTOs; it imports them.
  > **Review note (corrected):** the requirements and evaluate paths were wrong in the draft.
  > The real endpoints are `GET /v1/kyc/tiers/me/requirements/{target_tier}` (target tier is a
  > path segment of type **integer**, not a `?target_tier=` query string) and
  > `POST /v1/kyc/tiers/me/evaluate` (not `/v1/kyc/evaluate`). Verified against the OpenAPI index
  > and `src/api/endpoints/kyc-tiers.ts`. `/v1/kyc/cases` is not used by this screen.
- **Web reference:** `frontend/src/api/endpoints/kyc-tiers.ts` (`getMyTier`,
  `checkRequirements`, `evaluateTier`), shared types in `frontend/src/api/types.ts`
  (`TierDetails`, `TierRequirements`, `TierHistoryEntry`), and screen behavior in
  `frontend/src/pages/kyc/KycTierProgress.tsx`. OpenAPI under the `kyc-tiers` tag is
  authoritative for field names and enums when web and OpenAPI disagree.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single-Activity),
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore for
  the cached snapshot. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Layering:** `app -> feature-kyc -> core-*`. ViewModel exposes `StateFlow<UiState>`.
  Auth uses a **Bearer access token** (`Authorization: Bearer <token>`) **plus** the cookie
  session and a `X-CSRF-Token` header read from the `ui_csrf` cookie; an optional
  `X-IMPERSONATION-TOKEN` is sent when impersonating. A 401 triggers one
  `POST /ui/session/refresh` then a single retry — this is handled centrally in the
  OkHttp/auth interceptor from `core-network` and is not re-implemented here.
  > **Review note (corrected):** the draft described auth as purely "cookie-based"; the web
  > client (`src/api/client.ts`) sends both a `Authorization: Bearer` header from the auth store
  > and the `X-CSRF-Token` cookie value, with cookies (`credentials: include`). The 401 →
  > single `POST /ui/session/refresh` + one retry behavior is confirmed.

## 3. Functional Requirements

FR-1. On entering the screen the app loads the user's current tier and the requirements
for the target (next) tier. Until data arrives a loading state is shown.

FR-2. **Current tier** is rendered: the integer tier and its display name (`0`/"Unverified",
`1`/"Basic", `2`/"ID Verified", `3`/"Enhanced", `4`/"Institutional"). The
`/v1/kyc/tiers/me` payload (`TierDetails`) also carries `updated_at` and a `history[]` of
prior tier transitions, which the screen renders as a secondary "Tier History" section.
> **Review note (corrected):** the draft used tier-id *strings* and a 3-tier ladder, and
> claimed a `limits` array on the tier payload. `TierDetails` has **no** `limits` field; tier
> names are mapped **client-side** from the integer `current_tier` (web `TIER_NAMES`). The
> only per-tier extras are `updated_at` and `history` (`src/api/types.ts: TierDetails` /
> `TierHistoryEntry`). Any limits/capabilities display is dropped as unsupported by the API.

FR-3. **Target tier requirements** are rendered as a checklist. The
`/v1/kyc/tiers/me/requirements/{target_tier}` payload (`TierRequirements`) returns two
string arrays — `met` and `unmet` — of requirement **keys** (e.g. `email_verified`,
`phone_verified`, `kyc_case_approved`, `proof_of_address`, `verification_call`,
`questionnaire_completed`, `business_kyc_approved`, `api_access_approved`,
`tier_1`/`tier_2`/`tier_3`). Each key is mapped to a human-readable label **client-side**
(mirroring web `REQUIREMENT_LABELS`); a `met` item shows a check affordance, an `unmet`
item a neutral/empty affordance. The payload also carries `current_tier` and an `eligible`
boolean.
> **Review note (corrected):** there is **no** per-requirement `status` enum
> (`satisfied/pending/action_required/rejected`), **no** `help_text`, and **no** `case_id` in
> this payload. Requirements are a binary met/unmet split of opaque string keys. Verified
> against `src/api/types.ts: TierRequirements` and `src/pages/kyc/KycTierProgress.tsx`
> (renders `[...met, ...unmet]`, `isMet = met.includes(req)`). The status enum, help text,
> and case deep-link in the draft are unsupported and removed; see §16 corrections.

FR-4. An **Evaluate** button (web label: "Check Eligibility") is shown whenever
`current_tier < 4`. Tapping it calls `POST /v1/kyc/tiers/me/evaluate` **with no request
body**, shows an inline progress indicator on the action, and on success applies the
returned `TierDetails` (FR-6).

FR-5. If the user is already at the maximum tier (`current_tier == 4`, Institutional), the
requirements checklist and Evaluate button are hidden and a terminal "highest verification
tier reached" message is shown.

FR-6. After a successful `evaluate` (which returns a fresh `TierDetails`), the screen
reflects the new state: if `returned.current_tier > previous.current_tier` the user was
**promoted** — update the current tier, surface a promotion confirmation, and re-fetch the
requirements for the new `min(current_tier+1, 4)`; otherwise show a non-blocking
"no upgrade available" message. The updated `TierDetails` is persisted to the cached
snapshot.
> **Review note (corrected):** the evaluate response is **`TierDetails` only** — it does NOT
> return a merged tier+requirements payload, a `promoted` flag, an `eligible_for_target`
> flag, or a `requirements` array. Promotion is derived by comparing the returned
> `current_tier` against the prior one (web `data.current_tier > currentTier`). The
> `eligible` flag lives only on the separate `TierRequirements` payload (FR-3). Because the
> evaluate response has no requirements, the client must **re-fetch requirements** after a
> successful evaluate to refresh the checklist (the web client invalidates the
> `["kyc","tier"]` query cache to do exactly this). See §16.

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
    suspend fun evaluate(): ApiResult<TierEvaluation>   // POST takes NO body
}

@Singleton
class KycTierRepositoryImpl @Inject constructor(
    private val api: KycApi,                  // from AND-319
    private val store: KycTierStore,          // DataStore-backed snapshot
    @IoDispatcher private val io: CoroutineDispatcher,
) : KycTierRepository { /* ... */ }
```

`refreshTierStatus()` first issues `GET /v1/kyc/tiers/me` to learn `current_tier`, computes
`targetTier = min(current_tier + 1, 4)`, and — only when `current_tier < 4` — issues
`GET /v1/kyc/tiers/me/requirements/{targetTier}`. (Unlike the draft's claim, the target tier
must be known *before* the requirements call because it is a required path segment, so the
two GETs cannot be fully parallelized; the requirements call is skipped entirely at max
tier, matching the web `enabled: currentTier < 4`.) It maps both DTOs into the domain
`TierStatus`, writes it to `KycTierStore`, and returns the merged result. Network DTO→domain
mapping reuses the AND-319 DTOs; this module owns only the domain models below.

**Domain models** (`core-model` or feature-local `model/`):

> **Review note (corrected):** the original domain model assumed string tier ids, a per-tier
> `limits` array, and rich `Requirement` objects with a `status` enum / `helpText` / `caseId`.
> None of those exist in the API. The corrected model below mirrors the real `TierDetails` and
> `TierRequirements` shapes: integer tiers (display names mapped client-side), a `met`/`unmet`
> split of string keys, and tier `history`.

```kotlin
// Integer tier; display name mapped client-side (mirrors web TIER_NAMES).
const val MAX_TIER = 4   // 0 Unverified, 1 Basic, 2 ID Verified, 3 Enhanced, 4 Institutional

data class Tier(
    val level: Int,                    // 0..4
    val name: String,                  // resolved client-side from level
)

// A single requirement = a server key + whether it is met. No status enum / help / case.
data class Requirement(
    val key: String,                   // e.g. "email_verified", "kyc_case_approved"
    val label: String,                 // mapped client-side; falls back to key if unknown
    val met: Boolean,
)

data class TierStatus(
    val current: Tier,
    val updatedAt: Instant?,           // TierDetails.updated_at (epoch seconds, nullable)
    val history: List<TierHistory>,    // TierDetails.history[]
    val target: Tier?,                 // null => current == MAX_TIER (no requirements call)
    val requirements: List<Requirement>, // met first, then unmet (web ordering)
    val eligibleForTarget: Boolean,    // TierRequirements.eligible
    val asOf: Instant,                 // local fetch time, for stale indication
)

data class TierHistory(
    val fromTier: Int,
    val toTier: Int,
    val changedAt: Instant,
    val reason: String,
    val caseId: String?,               // TierHistoryEntry.case_id (history only)
)

// evaluate() returns only TierDetails; promotion is derived by comparing tiers.
data class TierEvaluation(
    val tierStatus: TierStatus,        // rebuilt from returned TierDetails (+ re-fetched reqs)
    val promoted: Boolean,             // returned.current_tier > previous.current_tier
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

All endpoints are defined by **AND-319**; this ticket consumes them. Auth (Bearer +
cookie + CSRF) and 401 refresh are handled by the shared interceptor. Base dev host
(PLAINTEXT HTTP): `http://18.222.237.167:8000`. Every endpoint below also accepts optional
`user_sub` query plus `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (server-side
session resolution; the mobile client relies on the cookie/Bearer session and does not set
`user_sub`).

> **Review note (corrected):** the entire API contract below was rewritten. The draft's
> nested `current_tier`/`target_tier` objects, `limits`, per-requirement `status`/`help_text`,
> the `{ "target_tier": "tier_2" }` evaluate request body, and the merged evaluate response
> with a `promoted` flag are all fictitious. Real shapes (from `src/api/types.ts` and OpenAPI
> `kyc-tiers`) follow.

**GET `/v1/kyc/tiers/me`** → `TierDetails`. Current tier snapshot + transition history.

```json
{
  "user_sub": "auth0|abc123",
  "current_tier": 1,
  "tier_name": "Basic",
  "updated_at": 1735689600,
  "history": [
    { "from_tier": 0, "to_tier": 1, "changed_at": 1735603200,
      "reason": "email+phone verified", "actor_sub": "system", "case_id": null }
  ]
}
```

**GET `/v1/kyc/tiers/me/requirements/{target_tier}`** → `TierRequirements`. `target_tier`
is an **integer path segment** (the next tier, `min(current_tier+1, 4)`).

```json
{
  "target_tier": 2,
  "current_tier": 1,
  "met": ["email_verified", "phone_verified", "tier_1"],
  "unmet": ["kyc_case_approved"],
  "eligible": false
}
```

`met` / `unmet` are arrays of opaque requirement **keys**; the client maps each to a label
(falling back to the raw key if unknown — forward-compatible). `eligible == true` means all
requirements for `target_tier` are met. There is no per-requirement status, help text, or
case id in this payload.

**POST `/v1/kyc/tiers/me/evaluate`** → re-evaluate the user's tier.

Request body: **none** (empty POST; only the optional `user_sub` query + session headers).
Response: a fresh **`TierDetails`** (same shape as `GET /v1/kyc/tiers/me`):
```json
{
  "user_sub": "auth0|abc123",
  "current_tier": 2,
  "tier_name": "ID Verified",
  "updated_at": 1735776000,
  "history": [ /* ...updated... */ ]
}
```
Promotion is inferred client-side: `response.current_tier > previous.current_tier`. There is
**no** `promoted`, `eligible_for_target`, or `requirements` field in this response; after a
successful evaluate the client re-fetches `requirements/{new_target}` to refresh the
checklist.

**Error shape** (FastAPI). Validation errors are `422` with
`{ "detail": [ { "msg": "...", "loc": [...], "type": "..." } ] }` (schema
`HTTPValidationError`). Other errors use `{ "detail": "..." }` (string) or
`{ "detail": { "code": "...", ... } }` (object, e.g. auth/permission). The shared client
(`src/api/client.ts: normalizeErrorDetail`) resolves all three forms to a human message;
the repository surfaces that as `ApiResult.Failure`. `target_tier` out of range yields a
`422`.

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
  from `core-network`. `POST /v1/kyc/tiers/me/evaluate` is **not** retried automatically
  (non-GET); on failure the user retries via the button.
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
- Requirement met/unmet state is conveyed by **icon + text + color**, not color alone
  (WCAG 1.4.1). Each `RequirementRow` sets
  `Modifier.semantics { contentDescription = "<label>, met"|"<label>, not met" }`.
- The Evaluate button exposes a `stateDescription` while `evaluating` ("Evaluating…") and
  is disabled (not just visually) during the call. Min touch target 48dp.
- Pull-to-refresh has an accessible equivalent (a refresh action in the top bar overflow)
  for users who cannot perform the gesture.
- Supports dynamic font scaling; cards use `wrapContentHeight`. RTL-safe via
  start/end paddings. Tier names and requirement labels are short text (no client number
  formatting in this ticket; the API exposes no currency/limit values — see §16).

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
- DTO→domain mapping: integer `current_tier` → name; unknown requirement key falls back to
  the raw key; `met`/`unmet` split preserved; `current_tier == 4` ⇒ no requirements call /
  max-tier.
- `KycTierRepositoryImpl.refreshTierStatus()` fetches tiers/me then requirements for
  `min(current+1,4)` (skipped at max tier); writes snapshot; maps FastAPI `detail` (all 3
  shapes) to a message.
- `evaluate()` success updates snapshot and sets `promoted` only when returned
  `current_tier` increased; re-fetches requirements; failure leaves snapshot intact.
- Retry policy: GETs retried (assert request count) on 503; POST `evaluate` not retried.

ViewModel (Turbine):
- `Loading → Content` on success; `Loading → Error(canRetry)` on first-load failure.
- `onEvaluate()` sets `evaluating=true` then applies result; promotion emits
  `TierEvent.Promoted`; failure emits `TierEvent.Snackbar` and keeps prior content.
- Stale-while-error: refresh failure with cache present keeps `Content`, sets `stale`.

Compose UI (`createComposeRule`):
- Current tier + requirement checklist render; met vs unmet rows visually distinguished
  (icon + text + color).
- Max-tier state (`current_tier == 4`) hides Evaluate + requirements and shows terminal message.
- Evaluate button disabled and shows progress while `evaluating`.
- Tier history section renders when `history` is non-empty.

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

- **Evaluate response shape:** **RESOLVED (review).** `POST /v1/kyc/tiers/me/evaluate`
  returns only `TierDetails` (no requirements, no `promoted`). The client therefore
  re-fetches `requirements/{new_target}` after a successful evaluate, exactly as the web
  client invalidates its `["kyc","tier"]` query cache. Promotion is derived by comparing
  `current_tier`. (`src/api/endpoints/kyc-tiers.ts: evaluateTier`,
  `src/pages/kyc/KycTierProgress.tsx`.)
- **Target-tier selection:** **RESOLVED (review).** Tiers are a single linear integer ladder
  0→4; the next/target tier is always `min(current_tier+1, 4)`. No multi-target selector is
  needed. (`src/pages/kyc/KycTierProgress.tsx: nextTier`.)
- **Requirement→case linkage:** **RESOLVED (review).** The `requirements` payload carries no
  `case_id` and no per-requirement status; requirements are opaque met/unmet keys, so there
  is no per-row case deep-link from this screen. (`case_id` exists only on
  `TierHistoryEntry`.) The `onOpenCase` callback is retained for sibling KYC screens but is
  unused by the requirements checklist here.
- **Eligibility vs promotion:** **RESOLVED (review).** `eligible` lives on the
  `TierRequirements` payload and means "all requirements for target met"; it does not by
  itself promote. Promotion happens server-side and is reflected only by a higher
  `current_tier` in the evaluate response. The design keeps them distinct (eligibility hint
  vs promotion confirmation).
- **`updated_at` units / tier-name source — OPEN:** `TierDetails.updated_at` is a nullable
  epoch number; assumed **seconds** (consistent with other `*_at` integer fields), to be
  confirmed. Tier display names are mapped **client-side** (web `TIER_NAMES`); if the backend
  ever returns `tier_name`, prefer the server value (the payload does include `tier_name`,
  so the client SHOULD use `tier_name` for the current tier and the local map only for the
  *target* tier name). **Open.**
- Dev backend unreliability may make manual QA flaky; rely on MockWebServer for CI.

## 14. Acceptance Criteria

AC-1. On screen entry, the current tier (integer + display name, plus tier history when
present) renders within one load cycle; a loading state shows until data or cache is
available.

AC-2. When `current_tier < 4`, the requirements for `min(current_tier+1, 4)` render as a
checklist with each item shown as **met** or **unmet**, distinguished by icon+text, not
color alone. Unknown requirement keys still render (label falls back to the raw key).

AC-3. Tapping **Evaluate** ("Check Eligibility") calls `POST /v1/kyc/tiers/me/evaluate`
**with no body**, shows inline progress, and on success applies the returned `TierDetails`
and re-fetches the requirements checklist (state updates without manual refresh). *(Directly
satisfies the source acceptance: "Tier + requirements render; evaluate updates state.")*

AC-4. A successful evaluate whose returned `current_tier` exceeds the previous one updates
the current tier and surfaces a promotion confirmation; when the requirements payload's
`eligible == true` an eligibility banner is shown. If `current_tier` is unchanged, a
non-blocking "no upgrade available" message is shown.

AC-5. When at the maximum tier (`current_tier == 4`, Institutional), the requirements
checklist and Evaluate button are hidden and a terminal "highest verification tier" message
is shown.

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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer.

1. **`GET /v1/kyc/tiers/me` returns the current tier snapshot.** VERDICT: Verified.
   SOURCE: OpenAPI `GET /v1/kyc/tiers/me` (op `get_my_tier_v1_kyc_tiers_me_get`);
   `src/api/endpoints/kyc-tiers.ts: getMyTier`.
2. **`TierDetails` shape = `{ user_sub, current_tier:int, tier_name, updated_at:int|null,
   history[] }`.** VERDICT: Verified. SOURCE: `src/api/types.ts: TierDetails`. (Draft's
   nested `current_tier`/`target_tier` objects + `limits` were wrong — Corrected.)
3. **Tiers are integers 0–4 (Unverified / Basic / ID Verified / Enhanced / Institutional);
   max tier = 4.** VERDICT: Corrected (draft used `tier_0/1/2` strings, 3 tiers). SOURCE:
   `src/pages/kyc/KycTierProgress.tsx: TIER_NAMES` and `nextTier = min(currentTier+1, 4)`;
   `src/api/types.ts: TierDetails.current_tier: number`.
4. **Requirements endpoint is `GET /v1/kyc/tiers/me/requirements/{target_tier}` with
   `target_tier` an integer PATH segment.** VERDICT: Corrected (draft used
   `GET /v1/kyc/requirements?target_tier=tier_2`). SOURCE: OpenAPI
   `GET /v1/kyc/tiers/me/requirements/{target_tier}` (`target_tier` path param, `type:
   integer`, required); `src/api/endpoints/kyc-tiers.ts: checkRequirements(targetTier:number)`.
5. **`TierRequirements` shape = `{ target_tier:int, current_tier:int, met:string[],
   unmet:string[], eligible:bool }`.** VERDICT: Corrected (draft had a `requirements[]` of
   objects with `key/label/status/help_text/case_id`). SOURCE: `src/api/types.ts:
   TierRequirements`; render in `src/pages/kyc/KycTierProgress.tsx` (`[...met, ...unmet]`,
   `isMet = met.includes(req)`).
6. **No per-requirement `status` enum (`satisfied/pending/action_required/rejected`), no
   `help_text`, no `case_id` on requirements.** VERDICT: Corrected. SOURCE: same as #5
   (`met`/`unmet` are plain string keys). `case_id` exists only on `TierHistoryEntry`
   (`src/api/types.ts`).
7. **Requirement keys are mapped to labels client-side; unknown keys fall back to the raw
   key.** VERDICT: Verified. SOURCE: `src/pages/kyc/KycTierProgress.tsx: REQUIREMENT_LABELS`
   and `REQUIREMENT_LABELS[req] ?? req`.
8. **Evaluate endpoint is `POST /v1/kyc/tiers/me/evaluate` with NO request body.** VERDICT:
   Corrected (draft used `POST /v1/kyc/evaluate` with `{ "target_tier": "tier_2" }`). SOURCE:
   OpenAPI `POST /v1/kyc/tiers/me/evaluate` (no `requestBody`; only `user_sub` query +
   session headers); `src/api/endpoints/kyc-tiers.ts: evaluateTier = () => api.post(...)`
   (no body arg).
9. **Evaluate returns `TierDetails` only (no `promoted`, no `eligible_for_target`, no
   `requirements`).** VERDICT: Corrected (draft claimed a merged snapshot + `promoted`).
   SOURCE: `src/api/endpoints/kyc-tiers.ts: evaluateTier` typed `api.post<TierDetails>`;
   OpenAPI evaluate response schema `{}` (untyped) typed as `TierDetails` by the web client.
10. **Promotion is derived by comparing returned vs prior `current_tier`; the client
    re-fetches requirements after evaluate.** VERDICT: Verified. SOURCE:
    `src/pages/kyc/KycTierProgress.tsx` (`if (data.current_tier > currentTier) toast.success`;
    `queryClient.invalidateQueries({ queryKey: ["kyc","tier"] })`).
11. **`eligible` (all requirements met) lives on `TierRequirements`, not on the evaluate
    response.** VERDICT: Verified/Corrected. SOURCE: `src/api/types.ts: TierRequirements.eligible`.
12. **Max-tier terminal state: when `current_tier >= 4`, requirements + Evaluate hidden,
    "highest verification tier" message shown.** VERDICT: Verified. SOURCE:
    `src/pages/kyc/KycTierProgress.tsx` (`currentTier >= 4` branch; requirements query
    `enabled: currentTier < 4`).
13. **Evaluate button label is "Check Eligibility" and shows a spinner while pending.**
    VERDICT: Verified. SOURCE: `src/pages/kyc/KycTierProgress.tsx` (button text +
    `evaluateMut.isPending`).
14. **Auth = `Authorization: Bearer <token>` + cookie session + `X-CSRF-Token` (from
    `ui_csrf` cookie) + optional `X-IMPERSONATION-TOKEN`.** VERDICT: Corrected (draft said
    "cookie-based only"). SOURCE: `src/api/client.ts` (sets `Authorization` from auth store,
    `X-CSRF-Token` from `ui_csrf`, `X-IMPERSONATION-TOKEN`, `credentials: include`).
15. **401 → single `POST /ui/session/refresh` then one retry; on refresh failure, logout.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` + the 401 branch (single
    `refreshPromise`, one retry, `logout("session_expired")`).
16. **Error/`detail` shape: 422 → `HTTPValidationError` (`detail:[{msg,loc,type}]`); else
    `detail` string or `{code,...}` object; all three normalized to a message.** VERDICT:
    Verified. SOURCE: OpenAPI `422 → HTTPValidationError` on all three tier endpoints;
    `src/api/client.ts: normalizeErrorDetail` (string / array-of-`msg` / object-with-`code`).
17. **Tier endpoints also accept `user_sub` query + `X-SESSION-ID` / `X-IMPERSONATION-TOKEN`
    headers.** VERDICT: Verified. SOURCE: OpenAPI params on `get_my_tier`,
    `evaluate_my_tier`, `check_my_requirements`. (Mobile relies on session; does not set
    `user_sub` — assumption, see Open assumptions.)
18. **`TierHistoryEntry` = `{ from_tier, to_tier, changed_at, reason, actor_sub,
    case_id|null }`.** VERDICT: Verified. SOURCE: `src/api/types.ts: TierHistoryEntry`
    (read at types.ts ~L5585-5595).
19. **Dev base host `http://18.222.237.167:8000` (plaintext HTTP), HTTPS required for
    release.** VERDICT: Unverified-assumption (host string carried over from the draft; not
    cross-checked against a config source in the reference). SOURCE: draft §2/§5; no
    authoritative reference file confirms this exact IP/port.
20. **Android framework choices (Compose `PullToRefreshBox`, DataStore for the cached
    snapshot, Hilt/KSP, Moshi, minSdk 24 / target 35).** VERDICT: Unverified-assumption
    (Android-side design, not derivable from the web reference or OpenAPI). SOURCE: framework
    ref — Jetpack Compose Material3 `PullToRefreshBox`
    (https://developer.android.com/develop/ui/compose/components/pull-to-refresh) and
    Jetpack DataStore (https://developer.android.com/topic/libraries/architecture/datastore).
21. **Client-side retry of GETs (max 2, backoff+jitter) on 5xx/503; POST evaluate not
    retried.** VERDICT: Unverified-assumption (an Android `core-network` policy; the web
    client does NOT implement custom retry — `src/api/client.ts` has none). SOURCE: draft
    §7; no reference source confirms a retry policy.
22. **`updated_at` is epoch seconds.** VERDICT: Unverified-assumption. SOURCE:
    `src/api/types.ts: TierDetails.updated_at: number | null` (unit not stated); inferred
    from sibling `*_at` integer fields.

### Corrections made

- §1/§3/§5/§14: tier identifiers changed from string ids (`tier_0/1/2`, 3 tiers) to
  **integers 0–4 (5 tiers)**; max tier = 4 (Institutional) (claims 3, 12).
- §2/§5/§7/§14: requirements path corrected to
  `GET /v1/kyc/tiers/me/requirements/{target_tier}` (integer **path** segment, not
  `?target_tier=`) (claim 4).
- §2/§5/§14: evaluate path corrected to `POST /v1/kyc/tiers/me/evaluate` and the **request
  body removed** (no `{ "target_tier": ... }`) (claim 8).
- §3/§4/§5: requirements remodeled from objects-with-status to **`met`/`unmet` string-key
  arrays + `eligible`**; removed the `status` enum, `help_text`, and `case_id` from
  requirements; removed `TierLimit`/`limits` (claims 5, 6).
- §5/§6/§FR-6: evaluate response corrected to **`TierDetails` only**; promotion derived by
  comparing `current_tier`; added the **re-fetch-requirements-after-evaluate** step
  (claims 9, 10).
- §2: auth corrected to **Bearer + cookie + CSRF (+ impersonation)**, not cookie-only
  (claim 14).
- §3/§4/§5: added the previously-missing **`history[]` / `TierHistoryEntry`** and
  `updated_at`, and the requirement-label client-side mapping (claims 2, 7, 18).
- §13: four open questions (evaluate shape, target-tier selection, requirement→case linkage,
  eligibility vs promotion) marked **RESOLVED** with sources.

### Open assumptions

- **Dev base URL `http://18.222.237.167:8000`** (claim 19): no reference/config file in the
  provided sources confirms this exact host; treated as carried-over dev config.
- **Android framework/library choices** (claim 20): Compose/DataStore/Hilt/Moshi/SDK levels
  are implementation decisions with no backend/web source to verify against (framework refs
  cited).
- **Client retry policy** (claim 21): the web client implements no retry; the Android retry
  policy is a `core-network` design assumption, not a verified contract.
- **`user_sub` not sent by mobile** (claim 17): assumed the mobile client relies purely on
  the session (cookie/Bearer) and never sets the optional `user_sub` query; not confirmable
  from the web client (which also omits it).
- **`updated_at`/`changed_at` units = epoch seconds** (claim 22): inferred, not documented.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **Emulator** = headless AVD
`test35` (x86_64, API 35); **Device** = physical Samsung Galaxy A15 5G (SM-A156U,
R5CX821TA9R, API 34, arm64-v8a). MockWebServer cases run on JVM. Compose-UI and instrumented
cases run on Emulator unless they exercise hardware/ABI behavior, which MUST run on Device.

- **TC-AND-320-01** — Type: contract/MockWebServer (JVM). Target: `KycTierRepositoryImpl`.
  Preconditions: MockWebServer enqueues `200 TierDetails {current_tier:1}` for
  `GET /v1/kyc/tiers/me` and `200 TierRequirements {target_tier:2, met:[...], unmet:[...],
  eligible:false}` for `GET /v1/kyc/tiers/me/requirements/2`. Steps: call
  `refreshTierStatus()`. Expected: requests hit exactly those paths (requirements path uses
  integer `2` as a path segment); domain `TierStatus` has `current.level==1`,
  `target.level==2`, requirements split met/unmet, `eligibleForTarget==false`; snapshot
  written. Traces: AC-1, AC-2, AC-7.
- **TC-AND-320-02** — Type: unit (JVM). Target: DTO→domain mapper. Preconditions: a
  `TierRequirements` containing an unknown key (e.g. `"future_step"`). Steps: map to domain.
  Expected: unknown key renders with label == raw key (no crash); known keys mapped to
  labels; `met`/`unmet` order preserved (met first). Traces: AC-2.
- **TC-AND-320-03** — Type: contract/MockWebServer (JVM). Target: `KycTierRepositoryImpl`
  max-tier path. Preconditions: `GET /v1/kyc/tiers/me` → `200 {current_tier:4}`. Steps: call
  `refreshTierStatus()`. Expected: **no** request is made to `requirements/...` (skipped at
  max tier); `target == null`; `requirements` empty. Traces: AC-5.
- **TC-AND-320-04** — Type: contract/MockWebServer (JVM). Target: `evaluate()` happy/promote
  path. Preconditions: prior snapshot `current_tier:1`; enqueue
  `POST /v1/kyc/tiers/me/evaluate` → `200 TierDetails {current_tier:2}`, then
  `GET .../requirements/3` → `200 {...}`. Steps: call `evaluate()`. Expected: the POST is
  sent with an **empty body**; `TierEvaluation.promoted == true`; requirements re-fetched for
  tier 3; snapshot updated. Traces: AC-3, AC-4, AC-7.
- **TC-AND-320-05** — Type: contract/MockWebServer (JVM). Target: `evaluate()` no-upgrade
  path. Preconditions: prior `current_tier:1`; evaluate → `200 {current_tier:1}`. Steps:
  call `evaluate()`. Expected: `promoted == false`; no promotion event; snapshot still
  consistent; (web equivalent: "no upgrade available"). Traces: AC-3, AC-4.
- **TC-AND-320-06** — Type: contract/MockWebServer (JVM). Target: error mapping. Precondition
  variants: (a) `422 {detail:[{msg:"...",loc:[...],type:"..."}]}`; (b) `400 {detail:"bad"}`;
  (c) `403 {detail:{code:"role_required"}}`. Steps: trigger each on a tier call. Expected:
  each maps to a non-empty human message in `ApiResult.Failure` (array→joined `msg`,
  string→verbatim, object→mapped/`code`); no crash. Traces: AC-6.
- **TC-AND-320-07** — Type: contract/MockWebServer (JVM). Target: retry policy. Preconditions:
  `GET /v1/kyc/tiers/me` returns `503` then `200`; separately `POST .../evaluate` returns
  `503`. Steps: refresh; then evaluate. Expected: GET retried (request count ≥2, bounded);
  evaluate **not** retried (count ==1) and surfaces failure. Traces: AC-6.
- **TC-AND-320-08** — Type: unit/ViewModel (JVM, Turbine). Target: `TierStatusViewModel`.
  Preconditions: repo returns success then a refresh failure with a cached snapshot present.
  Steps: collect `state`. Expected: `Loading → Content`; on first-load failure with no cache
  `Loading → Error(canRetry=true)`; refresh failure with cache keeps `Content` and sets
  `stale=true` (stale-while-error); evaluate failure clears `evaluating`, keeps content,
  emits `TierEvent.Snackbar`. Traces: AC-1, AC-6.
- **TC-AND-320-09** — Type: unit/ViewModel (JVM, Turbine). Target: promotion event.
  Preconditions: `evaluate()` returns promoted result. Steps: call `onEvaluate()`. Expected:
  `evaluating` toggles true→false; `TierEvent.Promoted(toTierName)` emitted; `Content`
  reflects new tier. Traces: AC-3, AC-4.
- **TC-AND-320-10** — Type: Compose-UI (Emulator). Target: `TierStatusScreen`. Preconditions:
  `Content` with current tier 1 and a met+unmet requirement list. Steps: render. Expected:
  current tier name + history render; met rows show check icon, unmet rows show neutral icon
  (icon+text+color, not color alone); Evaluate ("Check Eligibility") visible. Traces: AC-1,
  AC-2.
- **TC-AND-320-11** — Type: Compose-UI (Emulator). Target: `TierStatusScreen` states.
  Preconditions: (a) max-tier `Content` (tier 4); (b) `Content` with `evaluating=true`.
  Steps: render each. Expected: (a) requirements + Evaluate hidden, terminal message shown;
  (b) Evaluate disabled (not just visually) and shows progress. Traces: AC-5, AC-3.
- **TC-AND-320-12** — Type: Compose-UI accessibility (Emulator). Target: `RequirementRow`,
  Evaluate button. Steps: inspect semantics. Expected: each row exposes
  `contentDescription "<label>, met"|"<label>, not met"`; Evaluate has `stateDescription
  "Evaluating…"` while pending and a ≥48dp touch target; an accessible refresh action exists
  in the top-bar overflow (pull-to-refresh equivalent). Traces: AC-2, AC-8.
- **TC-AND-320-13** — Type: instrumented (Emulator). Target: `KycTierStore` persistence +
  cold-start render. Preconditions: write a `TierStatus` snapshot, then relaunch the screen
  with the network stubbed to hang. Steps: open screen. Expected: cached snapshot renders
  immediately (marked stale after the threshold) before any network result. Traces: AC-7,
  AC-6.
- **TC-AND-320-14** — Type: manual / security (Device — physical, real backend or proxied).
  Target: logging + transport on real hardware. Preconditions: build with debug logging;
  attach to `R5CX821TA9R`; drive load + evaluate against the dev host. Steps: capture logcat
  + a network trace; toggle airplane mode mid-evaluate to hit the offline/flaky-host path.
  Expected: no KYC PII (requirement keys/labels, history reason, identity detail) in logcat
  or analytics — only integer tier ids + boolean outcomes; CSRF + Bearer headers present on
  the POST; offline shows the stale-with-message path and no crash; the DataStore snapshot is
  excluded from backup. Run on Device to validate real-network/offline behavior and
  arm64/API-34 vs the emulator's x86_64/API-35. Traces: AC-6, AC-7, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-08, TC-10 |
| AC-2 | TC-01, TC-02, TC-10, TC-12 |
| AC-3 | TC-04, TC-05, TC-09, TC-11 |
| AC-4 | TC-04, TC-05, TC-09 |
| AC-5 | TC-03, TC-11 |
| AC-6 | TC-06, TC-07, TC-08, TC-13, TC-14 |
| AC-7 | TC-01, TC-04, TC-13, TC-14 |
| AC-8 | TC-12, TC-14 |
