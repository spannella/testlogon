---
id: AND-364
title: Content boost
milestone: M8
epic: E47
priority: P1
size: L
status: draft
depends_on: [AND-363, AND-031]
blocks: []
---

# AND-364 — Content boost

## 1. Overview & Goal

Enable a signed-in user to "boost" (paid-promote) one of their posts directly from
the post detail screen and from the post composer's success state. A boost turns an
organic post into a lightweight advertising campaign: the user selects a budget, a
duration, and a payment method drawn from their ads account, confirms, and the
backend creates a campaign-backed boost record. The UI must immediately reflect the
returned boost status (`pending`, `under_review`, `active`, `rejected`, `completed`)
and continue to poll/refresh that status while the boost screen is visible.

This is the Android port of the web reference behavior in `contentBoost.ts`
(`frontend/src/api/endpoints/contentBoost.ts`). It depends on AND-363 for the ads
accounts/billing/campaign DTOs (budget options and payment methods come from the ads
account) and follows the `StateFlow<UiState>` + result-mapping ViewModel pattern
established in AND-031.

**Done means:** initiating a boost creates a boost server-side and the screen shows
its returned status; budget and payment selection are wired to real ads-account data;
state transitions are unit-tested.

## 2. Context & References

- Web reference endpoint module: `frontend/src/api/endpoints/contentBoost.ts`.
- Shared web types: `frontend/src/api/types.ts` (`BoostRequest`, `Boost`, `BoostStatus`).
- Ads DTOs (this feature reuses them): delivered by **AND-363** — `AdsAccount`,
  `AdsBilling`/`PaymentMethod`, `Campaign` in `core-model`, surfaced by
  `AdsAccountsApi` / `AdsRepository`.
- ViewModel/state pattern: **AND-031** `LoginViewModel` — `StateFlow<UiState>`, submit
  handler, result→navigation/error mapping, loading/disabled handling.
- OpenAPI source of truth: `http://18.222.237.167:8000/openapi.json` (dev, plaintext
  HTTP, unreliable host).
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore.
  minSdk 24 / compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Module layering: `feature-boost` (new) → `core-network`, `core-model`, `core-ui`,
  `core-data`, `core-testing`. App namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. Boost entry points: (a) a "Boost post" action on the post **detail** screen for
posts the current user owns and that are eligible (public, not already actively
boosted); (b) a "Boost this post" CTA on the **composer success** state after a post
is created. Both navigate to `boost/{postId}`.

FR-2. The boost screen loads, in parallel, the post summary (title/thumbnail/author)
and the user's ads account context (available payment methods and currency) so budget
and payment selection are populated from real data (AND-363).

FR-3. Budget selection: user picks a daily-budget amount and a duration in days. The
screen computes and displays the **total spend** = `dailyBudgetMinor × durationDays`
in the ads account currency. Budget must respect a configurable min/max returned with
the ads account (fallback min 100 / max 100000 minor units if absent).

FR-4. Payment selection: user chooses one `PaymentMethod` from the ads account; the
default method is preselected. If the account has **no** payment method, the boost
button is disabled and an inline message links the user to add one (out of scope to
build the add-payment flow here — owned by a future ads ticket).

FR-5. Confirm: pressing "Boost" with a valid budget + duration + payment method
calls `POST /ui/content/boost`. While in flight the button shows a spinner and is
disabled (per AND-031 loading/disabled rule).

FR-6. On success the screen transitions to a **status** view showing the returned
`BoostStatus`, the boost id, total spend, and (if present) review/decline reason.

FR-7. Status freshness: while the status view is visible, refresh the boost via
`GET /ui/content/boost/{boostId}` on resume and on a bounded poll (every 15s, max 20
polls) until a terminal status (`active`, `rejected`, `completed`) is reached.

FR-8. The status of a boost created in this session is cached in Room so re-opening
`boost/{postId}` shows the last known status instead of the create form.

## 4. Technical Design

New module `feature-boost`. Single-Activity Navigation-Compose route registered by the
app graph.

**Navigation**

```kotlin
const val BOOST_ROUTE = "boost/{postId}"
fun NavController.navigateToBoost(postId: String) = navigate("boost/$postId")

fun NavGraphBuilder.boostScreen(onUpClick: () -> Unit) {
    composable(
        route = BOOST_ROUTE,
        arguments = listOf(navArgument("postId") { type = NavType.StringType }),
    ) { BoostRoute(onUpClick = onUpClick) }
}
```

**UI state** (sealed; mirrors AND-031 conventions)

```kotlin
data class BoostFormState(
    val post: PostSummary,
    val currency: String,
    val paymentMethods: List<PaymentMethod>,
    val selectedPaymentId: String?,
    val budgetMinPerDay: Long,
    val budgetMaxPerDay: Long,
    val dailyBudgetMinor: Long,
    val durationDays: Int,
    val submitting: Boolean = false,
    val inlineError: String? = null,
) {
    val totalSpendMinor: Long get() = dailyBudgetMinor * durationDays
    val canSubmit: Boolean get() =
        !submitting && selectedPaymentId != null &&
        dailyBudgetMinor in budgetMinPerDay..budgetMaxPerDay && durationDays > 0
}

sealed interface BoostUiState {
    data object Loading : BoostUiState
    data class Error(val message: String, val retryable: Boolean) : BoostUiState
    data class Form(val form: BoostFormState) : BoostUiState
    data class Status(val boost: Boost, val refreshing: Boolean) : BoostUiState
}
```

**ViewModel**

```kotlin
@HiltViewModel
class BoostViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val boostRepository: BoostRepository,
    private val adsRepository: AdsRepository,      // AND-363
    private val postRepository: PostRepository,
) : ViewModel() {
    private val postId: String = checkNotNull(savedStateHandle["postId"])
    val uiState: StateFlow<BoostUiState>            // StateFlow<UiState> per AND-031

    fun onDailyBudgetChange(minor: Long)
    fun onDurationChange(days: Int)
    fun onPaymentSelected(paymentMethodId: String)
    fun onSubmit()                                  // submit handler per AND-031
    fun onRetry()
    fun refreshStatus()                             // called on resume + poll tick
}
```

`onSubmit()` builds a `BoostRequest`, sets `submitting = true`, calls the repository,
and maps `ApiResult` to `BoostUiState.Status` (success) or `inlineError`/`Error`
(failure), exactly mirroring the result→navigation/error mapping in AND-031.

**Repository** (in `core-data`)

```kotlin
interface BoostRepository {
    suspend fun createBoost(request: BoostRequest): ApiResult<Boost>
    suspend fun getBoost(boostId: String): ApiResult<Boost>
    fun observeBoostForPost(postId: String): Flow<Boost?>   // Room-backed cache
}
```

The status poll lives in the ViewModel as a coroutine launched in `viewModelScope`
driven by `repeatOnLifecycle(STARTED)` from the Compose route, cancelled on stop and
on reaching a terminal status. Polling uses bounded backoff (15s interval, max 20
ticks) and only ever issues idempotent GETs — consistent with the project's
"backoff retry for idempotent GETs only" rule.

**Compose** `BoostScreen` renders Loading / Error (with retry) / Form (budget chips +
duration stepper + payment radio list + total spend + Boost button) / Status (status
chip + details + "Done"). Currency formatting via `NumberFormat.getCurrencyInstance`
keyed on the ads account currency.

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000`. Cookie-based auth
applies: requests carry the session + `ui_csrf` cookie echoed as `X-CSRF-Token`; on
401 the OkHttp authenticator calls `POST /ui/session/refresh` once then retries (shared
infra, not built here). Boost mutations are **non-idempotent POSTs** and must NOT be
auto-retried; only the status GET is retried.

**Create boost** — `POST /ui/content/boost`

Request:
```json
{
  "post_id": "p_8f31",
  "ads_account_id": "acct_2",
  "payment_method_id": "pm_visa_4242",
  "daily_budget_minor": 500,
  "currency": "USD",
  "duration_days": 7
}
```

Response `200`:
```json
{
  "boost_id": "boost_91a",
  "post_id": "p_8f31",
  "campaign_id": "camp_55",
  "status": "pending",
  "daily_budget_minor": 500,
  "duration_days": 7,
  "total_spend_minor": 3500,
  "currency": "USD",
  "review_reason": null,
  "created_at": "2026-06-05T14:02:11Z"
}
```

**Get boost status** — `GET /ui/content/boost/{boostId}` → same `Boost` shape
(idempotent; retryable with bounded backoff, ~20s timeout).

**Moshi DTOs** (in `core-model`):

```kotlin
@JsonClass(generateAdapter = true)
data class BoostRequestDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "ads_account_id") val adsAccountId: String,
    @Json(name = "payment_method_id") val paymentMethodId: String,
    @Json(name = "daily_budget_minor") val dailyBudgetMinor: Long,
    val currency: String,
    @Json(name = "duration_days") val durationDays: Int,
)

@JsonClass(generateAdapter = true)
data class BoostDto(
    @Json(name = "boost_id") val boostId: String,
    @Json(name = "post_id") val postId: String,
    @Json(name = "campaign_id") val campaignId: String?,
    val status: String,
    @Json(name = "daily_budget_minor") val dailyBudgetMinor: Long,
    @Json(name = "duration_days") val durationDays: Int,
    @Json(name = "total_spend_minor") val totalSpendMinor: Long,
    val currency: String,
    @Json(name = "review_reason") val reviewReason: String?,
    @Json(name = "created_at") val createdAt: String,
)
```

`status` maps to `enum class BoostStatus { PENDING, UNDER_REVIEW, ACTIVE, REJECTED, COMPLETED, UNKNOWN }`
with `UNKNOWN` for forward-compatible unrecognized values.

**Retrofit**

```kotlin
interface BoostApi {
    @POST("ui/content/boost")
    suspend fun createBoost(@Body body: BoostRequestDto): Response<BoostDto>

    @GET("ui/content/boost/{boostId}")
    suspend fun getBoost(@Path("boostId") boostId: String): Response<BoostDto>
}
```

**Error mapping:** FastAPI `detail` is parsed via the shared mapper (string |
`[{msg}]` | `{code,...}`) into `ApiResult.Error`. Expected failure cases: `402`
payment required / declined → inline payment error; `409` post already boosted →
load existing boost into Status; `422` validation → inline budget error.

## 6. Data & State Management

- `BoostViewModel` exposes `StateFlow<BoostUiState>` via `stateIn(viewModelScope,
  WhileSubscribed(5_000), Loading)`. The form is a single immutable `BoostFormState`
  updated through `update {}` on a backing `MutableStateFlow`.
- Ads account data (payment methods, currency, budget min/max) is sourced from
  `AdsRepository` (AND-363); no duplicate ads DTOs are defined here.
- Room cache (`core-data`): one row per boosted post.

```kotlin
@Entity(tableName = "boost")
data class BoostEntity(
    @PrimaryKey val postId: String,
    val boostId: String,
    val status: String,
    val totalSpendMinor: Long,
    val currency: String,
    val updatedAtEpochMs: Long,
)

@Dao interface BoostDao {
    @Query("SELECT * FROM boost WHERE postId = :postId")
    fun observe(postId: String): Flow<BoostEntity?>
    @Upsert suspend fun upsert(entity: BoostEntity)
}
```

- On `createBoost` success or a `getBoost` refresh, the entity is upserted; the route
  reads `observeBoostForPost(postId)` first so a returning user sees cached status
  before the network refresh resolves (offline/stale support).
- No DataStore writes here; session/CSRF persistence is handled by the shared cookie
  jar.

## 7. Error Handling & Resilience

- Dev host is unreliable HTTP: OkHttp call timeout ~20s. The status GET retries with
  bounded backoff (e.g., 3 attempts, 1s→2s→4s) since it is idempotent; the create
  POST is never auto-retried (avoids duplicate charges).
- `Error(retryable=true)` is shown for network/timeout/5xx on initial load with a
  "Retry" button; `retryable=false` for 4xx auth/validation that retrying won't fix.
- A `409 already boosted` is treated as success-equivalent: fetch the existing boost
  and render Status rather than an error.
- Polling stops on terminal status, on lifecycle stop, after 20 ticks, or on repeated
  failures; the last cached status remains visible (stale banner) if the network is
  down.
- Submit is debounced/guarded by `submitting` so double-taps cannot create two boosts.

## 8. Security & Privacy

- All calls use the existing authenticated cookie session + `X-CSRF-Token`; the boost
  POST is a state-changing request and must include the CSRF header (enforced by the
  shared OkHttp interceptor). No tokens or cookies are logged or persisted by this
  feature.
- Payment data: only opaque `payment_method_id` and a display masked label
  (e.g., "Visa ****4242") provided by AND-363 are handled; no PAN/CVV ever touches
  this code. Masked labels are not written to logs.
- The Room `boost` table stores no payment identifiers — only boost id, status, and
  total spend.
- Boost actions only appear for posts the current user owns (server is authoritative;
  client gating is UX only).

## 9. Accessibility & i18n

- All strings in `feature-boost/src/main/res/values/strings.xml`; no hardcoded user
  text. Budget chips, duration stepper, payment radios, and the Boost button have
  `contentDescription`/`semantics` labels.
- Currency and totals formatted via `NumberFormat.getCurrencyInstance(Locale, Currency)`
  using the ads account currency code — never string-concatenated.
- Duration stepper exposes increment/decrement as distinct accessible actions; the
  computed total spend is announced via `liveRegion` when budget/duration changes.
- Status chip conveys state by text + icon (not color alone); minimum touch targets
  48dp; supports dynamic font scaling and dark theme via Material 3 tokens.

## 10. Telemetry & Logging

- Analytics events via the shared analytics abstraction: `boost_screen_view`
  (post_id), `boost_submit` (daily_budget_minor, duration_days, currency),
  `boost_create_success` (boost_id, status, total_spend_minor),
  `boost_create_failure` (error_code), `boost_status_change` (boost_id, from, to).
- No PII or payment identifiers in any event; payment method is reported only as a
  boolean `has_payment_method` where needed.
- Diagnostic logging through the project logger at DEBUG for request/response status
  codes only (no bodies); errors logged at WARN with mapped error code, never raw
  `detail` containing user input.

## 11. Testing Strategy

Unit (JVM, `core-testing` + Turbine + MockWebServer):

- `BoostViewModelTest` — state transitions (the AND-031-style coverage): Loading →
  Form on successful parallel load; budget/duration edits recompute `totalSpendMinor`
  and `canSubmit`; payment default preselected; `onSubmit` sets `submitting=true` then
  Status on success; `inlineError` on 402/422; Error(retryable) on timeout; 409 →
  Status of existing boost. Assert button disabled while `submitting`.
- `BoostRepositoryTest` — MockWebServer: POST maps `BoostDto`→`Boost`, GET maps,
  FastAPI `detail` variants map to `ApiResult.Error`, Room upsert occurs on success,
  POST is not retried on 5xx, GET is retried with bounded backoff.
- `BoostDtoTest` — Moshi round-trip incl. null `campaign_id`/`review_reason` and
  unknown `status` → `BoostStatus.UNKNOWN`.
- Poll logic test — stops at terminal status and after max ticks.

Instrumented/Compose (`feature-boost` androidTest):

- `BoostScreenTest` — Loading/Error/Form/Status render; Boost button disabled with no
  payment method and with out-of-range budget; tapping Boost shows spinner; Status
  view shows status chip and total. Accessibility assertions on labels.

Coverage gate: ViewModel + repository ≥ 80% line coverage.

## 12. Dependencies & Sequencing

- **AND-363 (Ads accounts API)** — required: supplies ads account, payment methods,
  currency, and budget bounds consumed by the boost form. Must merge first.
- **AND-031 (LoginViewModel)** — pattern/infra: establishes the `StateFlow<UiState>` +
  submit/result-mapping ViewModel convention and the authenticated session this
  feature rides on.
- Implicit infra (assumed present): cookie jar + CSRF interceptor + session refresh,
  shared `ApiResult`/error mapper, `PostRepository` for post summary, analytics
  abstraction.
- This ticket **blocks**: none recorded in backlog.
- Build order: AND-363 DTOs → `BoostApi`/`BoostRepository`/Room → ViewModel → Compose
  + navigation wiring → entry points on detail/composer screens.

## 13. Risks & Open Questions

- R1. Exact `/ui/content/boost` request/response field names are inferred from
  `contentBoost.ts`; confirm against live `/openapi.json` before locking DTOs.
  *(Mitigation: DTO unit tests + a thin field-name review against OpenAPI.)*
- R2. Whether budget min/max and allowed durations come from the ads account or a
  separate config endpoint — confirm with AND-363's payload. Fallback defaults coded.
- R3. Payment failure semantics (`402` shape, decline codes) need confirmation;
  inline mapping is provisional.
- R4. Does the backend dedupe a repeat boost on the same post, or return 409? Behavior
  for "edit/cancel an existing boost" is **out of scope** here — open follow-up ticket.
- R5. Dev host instability may make status polling flaky in tests; tests use
  MockWebServer, not the live host.

## 14. Acceptance Criteria

AC-1 (from backlog: "Boost creates + shows status"): submitting a valid boost from the
post detail or composer-success entry point issues `POST /ui/content/boost` and, on
success, the screen transitions to the Status view showing the returned `BoostStatus`,
boost id, and total spend. *(BoostViewModelTest + BoostScreenTest.)*

AC-2: Budget total = `dailyBudgetMinor × durationDays` is displayed in the ads account
currency and updates live as inputs change; submit is blocked when budget is out of
the account's min/max range.

AC-3: Payment methods and currency are populated from the AND-363 ads account; default
method is preselected; with no payment method the Boost button is disabled with an
inline message.

AC-4: While the Status view is visible, status is refreshed on resume and via bounded
poll until a terminal status; the POST is never auto-retried.

AC-5: A previously boosted post reopened at `boost/{postId}` shows last known status
from Room before the network refresh.

AC-6: State transitions (loading/disabled, success, error variants 402/409/422/timeout)
are covered by unit tests (per AND-031 convention).

## 15. Definition of Done

- `feature-boost` module created and wired into the app nav graph at `boost/{postId}`
  with entry points on post detail and composer-success.
- `BoostApi`, `BoostRepository` (+ Room cache), `BoostViewModel`, and `BoostScreen`
  implemented per this spec using `com.testlogon.android` packaging.
- Moshi DTOs map the real `/ui/content/boost` payloads (verified against OpenAPI);
  FastAPI `detail` errors mapped via the shared mapper.
- All user strings externalized; accessibility labels and currency formatting in place.
- Unit + Compose tests green; ViewModel/repository ≥ 80% line coverage; analytics
  events emitted with no PII/payment identifiers.
- `./gradlew :feature-boost:detekt :feature-boost:testDebugUnitTest
  :feature-boost:connectedDebugAndroidTest` pass on CI; ktlint/detekt clean.
- Code reviewed and merged to `android-port`; open questions in §13 either resolved or
  filed as follow-up tickets.
