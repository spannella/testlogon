---
id: AND-364
title: Content boost
milestone: M8
epic: E47
priority: P1
size: L
depends_on: [AND-363, AND-031]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-364 — Content boost

## 1. Overview & Goal

Enable a signed-in user to "boost" (paid-promote) one of their posts directly from
the post detail screen and from the post composer's success state. A boost turns an
organic post into a lightweight advertising campaign: the user selects a budget, a
duration, and a payment method drawn from their ads account, confirms, and the
backend creates a boost record. The UI must immediately reflect the returned boost
`status` and continue to refresh that status while the boost screen is visible.

> REVIEW NOTE (2026-06-06): The original draft modelled this feature as an
> ads-account / payment-method / daily-budget campaign flow. That is **not** what the
> backend contract or the web reference implement. The real `ContentBoostCreate`
> input is only `{content_type, content_id, budget_cents, duration_seconds}` — a
> single total budget in cents and a duration in seconds, with **no** ads-account,
> payment-method, currency, or daily-budget fields. Currency is implicitly USD
> (integer cents). Status is a free-form string from the server; the web UI only
> exercises `"active"` (with a Cancel & refund action) — the richer enum
> (`pending/under_review/rejected/completed`) is an **unverified assumption** kept
> only as a forward-compatible mapping. The endpoints live under `/ui/ads/boost`,
> not `/ui/content/boost`. See §16 for the full audit. The spec below has been
> corrected in place to match the contract; the AND-363 dependency is reduced to
> optional UX (see §12).

This is the Android port of the web reference behavior in `contentBoost.ts`
(`frontend/src/api/endpoints/contentBoost.ts`) and the
`ContentBoostPage.tsx` / `ContentBoostDetail.tsx` screens. It follows the
`StateFlow<UiState>` + result-mapping ViewModel pattern established in AND-031.

**Done means:** initiating a boost creates a boost server-side and the screen shows
its returned status; budget (total cents) and duration (seconds) are submitted and
the returned spend/status are shown; state transitions are unit-tested.

## 2. Context & References

- Web reference endpoint module: `frontend/src/api/endpoints/contentBoost.ts`
  (verified: paths under `/ui/ads/boost`).
- Web reference screens: `frontend/src/pages/ads/ContentBoostPage.tsx` (create form +
  list) and `frontend/src/pages/ads/ContentBoostDetail.tsx` (status detail + cancel).
- Shared web types: `frontend/src/api/types.ts` — actual names are
  `ContentBoostCreateInput`, `ContentBoost`, `ContentBoostListResponse`,
  `ContentBoostSpend`, `ContentBoostCancelResponse` (there is no `BoostRequest` /
  `Boost` / `BoostStatus` type; those were assumed by the draft and are corrected
  throughout).
- Ads DTOs from **AND-363** (`AdsAccount`/`PaymentMethod`) are **NOT required** by the
  boost contract — the create payload carries no ads-account or payment-method fields.
  AND-363 is downgraded to an optional UX dependency (a "manage billing / wallet" link);
  see §12.
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

FR-2. The boost screen loads the post summary (title/thumbnail/author) for display
context. (CORRECTED: the original draft also loaded ads-account payment methods and
currency; the contract has no such fields, so no ads-account fetch is required for
submission. An optional billing/wallet link may be shown — see FR-4.)

FR-3. Budget & duration selection: the user picks a **total budget** (entered in USD,
converted to integer `budget_cents`; `budget_cents` must be ≥ 1) and a **duration**
(entered in minutes in the web reference, converted to `duration_seconds`;
`duration_seconds` must be ≥ 1). The screen displays the budget back to the user as
currency. (CORRECTED: there is no daily-budget × duration multiplication and no
per-account min/max in the contract — `budget_cents` is itself the total. A client-side
default — e.g. $5.00 / 60 min, mirroring the web defaults — and a sane client max may
be applied as an UNVERIFIED product choice, not a server-returned bound.)

FR-4. Payment: the contract requires **no** payment-method selection (the server
charges the user's wallet up-front per the web copy). The screen therefore does **not**
gate submission on a payment method. Optionally, an inline "manage wallet / billing"
link (AND-363, UX-only) may be shown; building that flow is out of scope. (CORRECTED:
the draft's payment-method radio list and "no payment method → disabled" rule are
removed — unsupported by the contract.)

FR-5. Confirm: pressing "Boost" with a non-empty `content_id`, `budget_cents` ≥ 1 and
`duration_seconds` ≥ 1 calls `POST /ui/ads/boost`. While in flight the button shows a
spinner and is disabled (per AND-031 loading/disabled rule). The web reference also
disables the button when `content_id` is empty.

FR-6. On success the screen transitions to a **status** view showing the returned
`status`, the `boost_id`, `budget_cents`, `spent_cents`, `remaining_cents`,
`duration_seconds`, and `ends_at`. (CORRECTED: there is no `total_spend_minor`,
`campaign_id`, `currency`, or `review_reason` in the response.)

FR-7. Status freshness: while the status view is visible, refresh the boost via
`GET /ui/ads/boost/{boost_id}` on resume and on a bounded poll. (UNVERIFIED-ASSUMPTION:
the web reference does **not** poll — it refetches via react-query invalidation after
mutations. Bounded polling — e.g. every 15s, max 20 ticks, stopping when `status` is no
longer `active`/in-progress — is an Android design choice, not web-reference parity.
Spend progress may instead/also be read from `GET /ui/ads/boost/{boost_id}/spend`.)

FR-8. Active boosts may be cancelled (with refund of remaining budget) via
`POST /ui/ads/boost/{boost_id}/cancel` → `{boost_id, status, refunded_cents}`, mirroring
the web "Cancel & refund" action shown only while `status == "active"`. (Whether to
ship cancel in this ticket vs. a follow-up is an open question — see §13 R4.)

FR-9. The status of a boost created in this session is cached in Room so re-opening
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
// CORRECTED to match ContentBoostCreate: total budget in cents + duration in seconds.
// No payment method / ads account / currency / daily-budget fields.
data class BoostFormState(
    val post: PostSummary,
    val contentType: String = "post",   // post | video | broadcast (server-accepted)
    val budgetCents: Long = 500L,        // total budget in integer cents (≥ 1)
    val durationSeconds: Int = 3600,     // duration in seconds (≥ 1)
    val submitting: Boolean = false,
    val inlineError: String? = null,
) {
    val canSubmit: Boolean get() =
        !submitting && budgetCents >= 1L && durationSeconds >= 1
}

sealed interface BoostUiState {
    data object Loading : BoostUiState
    data class Error(val message: String, val retryable: Boolean) : BoostUiState
    data class Form(val form: BoostFormState) : BoostUiState
    // ContentBoost (mapped from ContentBoostOut), not a "Boost"/"BoostStatus" type.
    data class Status(val boost: ContentBoost, val refreshing: Boolean) : BoostUiState
}
```

**ViewModel**

```kotlin
@HiltViewModel
class BoostViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val boostRepository: BoostRepository,
    private val postRepository: PostRepository,    // post summary only
) : ViewModel() {
    private val postId: String = checkNotNull(savedStateHandle["postId"])
    val uiState: StateFlow<BoostUiState>            // StateFlow<UiState> per AND-031

    fun onContentTypeChange(type: String)
    fun onBudgetCentsChange(cents: Long)
    fun onDurationSecondsChange(seconds: Int)
    fun onSubmit()                                  // submit handler per AND-031
    fun onRetry()
    fun refreshStatus()                             // called on resume + poll tick
    fun onCancel()                                  // POST .../cancel (active boosts)
}
```

`onSubmit()` builds a `ContentBoostCreateInput` (`content_type`, `content_id`,
`budget_cents`, `duration_seconds`), sets `submitting = true`, calls the repository,
and maps `ApiResult` to `BoostUiState.Status` (success) or `inlineError`/`Error`
(failure), exactly mirroring the result→navigation/error mapping in AND-031.

**Repository** (in `core-data`)

```kotlin
interface BoostRepository {
    suspend fun createBoost(request: ContentBoostCreateInput): ApiResult<ContentBoost>
    suspend fun getBoost(boostId: String): ApiResult<ContentBoost>
    suspend fun cancelBoost(boostId: String): ApiResult<ContentBoostCancel>
    fun observeBoostForPost(postId: String): Flow<ContentBoost?>  // Room-backed cache
}
```

The status poll lives in the ViewModel as a coroutine launched in `viewModelScope`
driven by `repeatOnLifecycle(STARTED)` from the Compose route, cancelled on stop and
on reaching a terminal status. Polling uses bounded backoff (15s interval, max 20
ticks) and only ever issues idempotent GETs — consistent with the project's
"backoff retry for idempotent GETs only" rule.

**Compose** `BoostScreen` renders Loading / Error (with retry) / Form (content-type
selector + budget field in USD + duration field + Boost button, disabled when
`content_id` is blank or budget/duration invalid) / Status (status chip + budget /
spent / remaining / ends-at details + Cancel-when-active + "Done"). Currency formatting
via `NumberFormat.getCurrencyInstance(Locale.US, Currency.getInstance("USD"))` over the
integer cents (the contract has no currency field; USD is implicit — see §16).

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000`. Auth (verified
against `src/api/client.ts`): the web client sends **both** an `Authorization: Bearer
<accessToken>` header (from the auth store) **and** the `ui_csrf` cookie echoed as the
`X-CSRF-Token` header, with cookie credentials included; on `401` it calls
`POST /ui/session/refresh` once then retries the original request. (CORRECTED: the
draft omitted the `Authorization: Bearer` token; it is part of the real transport.) An
optional `X-IMPERSONATION-TOKEN` header exists for admin impersonation (not used by this
feature). Boost mutations (create, cancel) are **non-idempotent POSTs** and must NOT be
auto-retried; only the status/spend GETs are retried.

**Create boost** — `POST /ui/ads/boost` · op `create_boost_ui_ads_boost_post` ·
req `ContentBoostCreate` · resp `200:ContentBoostOut`, `422:HTTPValidationError`.
(CORRECTED path: was `/ui/content/boost`.)

Request (`ContentBoostCreate`):
```json
{
  "content_type": "post",
  "content_id": "post_abc123",
  "budget_cents": 500,
  "duration_seconds": 3600
}
```
- `content_type`: `post | video | broadcast` (server description). For this ticket it
  is `"post"`.
- `content_id`: the post id (non-empty; web maps `postId` → `content_id`).
- `budget_cents`: total budget in integer cents, minimum 1.
- `duration_seconds`: duration in seconds, minimum 1 (web enters minutes × 60).

Response `200` (`ContentBoostOut`):
```json
{
  "boost_id": "boost_91a",
  "owner_sub": "user_123",
  "content_type": "post",
  "content_id": "post_abc123",
  "budget_cents": 500,
  "spent_cents": 0,
  "remaining_cents": 500,
  "duration_seconds": 3600,
  "starts_at": 1749132131,
  "ends_at": 1749135731,
  "status": "active",
  "created_at": 1749132131
}
```
(CORRECTED: response has no `campaign_id`, `total_spend_minor`, `currency`, or
`review_reason`; timestamps `starts_at`/`ends_at`/`created_at` are **integer epoch
seconds**, not ISO-8601 strings. All listed fields are `required` in the schema.)

**Get boost status** — `GET /ui/ads/boost/{boost_id}` · op
`get_boost_ui_ads_boost__boost_id__get` · resp `200:ContentBoostOut`,
`422:HTTPValidationError` (idempotent; retryable with bounded backoff, ~20s timeout).

**Get boost spend** — `GET /ui/ads/boost/{boost_id}/spend` · resp `200:ContentBoostSpendOut`
= `{boost_id, budget_cents, spent_cents, remaining_cents, status}` (idempotent; optional,
useful for cheap progress refresh).

**Cancel boost** — `POST /ui/ads/boost/{boost_id}/cancel` · resp `200:ContentBoostCancelOut`
= `{boost_id, status, refunded_cents}` (non-idempotent; shown only while `status ==
"active"` in the web reference).

**List boosts** — `GET /ui/ads/boost?active_only=<bool>` · resp `200:ContentBoostListOut`
= `{boosts: ContentBoostOut[]}` (used by the web list page; not required by the
single-post boost screen but available for the cache/entry-point).

**Moshi DTOs** (in `core-model`):

```kotlin
@JsonClass(generateAdapter = true)
data class ContentBoostCreateInput(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "duration_seconds") val durationSeconds: Long,
)

@JsonClass(generateAdapter = true)
data class ContentBoostDto(
    @Json(name = "boost_id") val boostId: String,
    @Json(name = "owner_sub") val ownerSub: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "budget_cents") val budgetCents: Long,
    @Json(name = "spent_cents") val spentCents: Long,
    @Json(name = "remaining_cents") val remainingCents: Long,
    @Json(name = "duration_seconds") val durationSeconds: Long,
    @Json(name = "starts_at") val startsAt: Long,     // epoch seconds
    @Json(name = "ends_at") val endsAt: Long,         // epoch seconds
    val status: String,
    @Json(name = "created_at") val createdAt: Long,   // epoch seconds
)

@JsonClass(generateAdapter = true)
data class ContentBoostCancelDto(
    @Json(name = "boost_id") val boostId: String,
    val status: String,
    @Json(name = "refunded_cents") val refundedCents: Long,
)
```

`status` is a free-form server string; map it to
`enum class BoostStatus { ACTIVE, COMPLETED, CANCELLED, PENDING, UNKNOWN }` with
`UNKNOWN` for unrecognized values. (UNVERIFIED-ASSUMPTION: only `"active"` is
demonstrated in the web reference; the other constants are forward-compatible guesses —
do not branch business logic on any value except, per the web UI, `"active"` enabling
the Cancel action.)

**Retrofit**

```kotlin
interface BoostApi {
    @POST("ui/ads/boost")
    suspend fun createBoost(@Body body: ContentBoostCreateInput): Response<ContentBoostDto>

    @GET("ui/ads/boost/{boostId}")
    suspend fun getBoost(@Path("boostId") boostId: String): Response<ContentBoostDto>

    @POST("ui/ads/boost/{boostId}/cancel")
    suspend fun cancelBoost(@Path("boostId") boostId: String): Response<ContentBoostCancelDto>

    @GET("ui/ads/boost/{boostId}/spend")
    suspend fun getSpend(@Path("boostId") boostId: String): Response<ContentBoostSpendDto>
}
```

**Error mapping:** FastAPI `detail` is parsed via the shared mapper (string |
`[{msg}]` | `{code,...}`, mirroring `normalizeErrorDetail` in `src/api/client.ts`) into
`ApiResult.Error`. The **only** documented error response for these endpoints is
`422:HTTPValidationError` (validation) → inline budget/content error. (CORRECTED: the
draft's `402 payment required` and `409 already boosted` cases are **not** in the
contract and are not handled by the web client — they are removed. Generic `401`
triggers the shared refresh-and-retry; `403` surfaces a permission message via the
shared mapper.)

## 6. Data & State Management

- `BoostViewModel` exposes `StateFlow<BoostUiState>` via `stateIn(viewModelScope,
  WhileSubscribed(5_000), Loading)`. The form is a single immutable `BoostFormState`
  updated through `update {}` on a backing `MutableStateFlow`.
- No ads-account data is required (CORRECTED): the create payload has no ads-account,
  payment-method, currency, or budget-bound fields. Budget/duration are plain user
  inputs validated client-side (`budget_cents ≥ 1`, `duration_seconds ≥ 1`).
- Room cache (`core-data`): one row per boosted post. (CORRECTED: `currency` column
  dropped — no currency in the contract; `totalSpendMinor` replaced by the real
  `budgetCents`/`spentCents`/`remainingCents` fields.)

```kotlin
@Entity(tableName = "boost")
data class BoostEntity(
    @PrimaryKey val postId: String,   // == content_id for content_type "post"
    val boostId: String,
    val status: String,
    val budgetCents: Long,
    val spentCents: Long,
    val remainingCents: Long,
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
- (CORRECTED) There is no documented `409 already boosted` response in the contract; the
  draft's "409 → load existing boost" behavior is removed. If the product later needs
  duplicate-boost protection, the client should fall back to `GET /ui/ads/boost`
  (list, optionally `active_only=true`) to find an existing active boost — tracked as an
  open question (§13 R4).
- Polling stops on terminal status, on lifecycle stop, after 20 ticks, or on repeated
  failures; the last cached status remains visible (stale banner) if the network is
  down.
- Submit is debounced/guarded by `submitting` so double-taps cannot create two boosts.

## 8. Security & Privacy

- All calls use the existing authenticated session: `Authorization: Bearer` access
  token **plus** the `ui_csrf` cookie echoed as `X-CSRF-Token` (verified in
  `src/api/client.ts`); the boost create/cancel POSTs are state-changing and must
  include the CSRF header (enforced by the shared OkHttp interceptor). No tokens or
  cookies are logged or persisted by this feature.
- Payment data: (CORRECTED) this feature handles **no** payment-method identifiers at
  all — the contract has none. The server charges the user's wallet up-front (per web
  copy); no PAN/CVV/payment-method id ever touches this code.
- The Room `boost` table stores only boost id, status, and budget/spent/remaining cents
  — no payment identifiers (none exist in the contract).
- Boost actions only appear for posts the current user owns; the server is
  authoritative (it records `owner_sub` and enforces ownership) — client gating is UX
  only.

## 9. Accessibility & i18n

- All strings in `feature-boost/src/main/res/values/strings.xml`; no hardcoded user
  text. The content-type selector, budget field, duration field, and the Boost button
  have `contentDescription`/`semantics` labels. (CORRECTED: no payment radios — that UI
  is removed.)
- Currency and amounts formatted via `NumberFormat.getCurrencyInstance` with
  `Currency.getInstance("USD")` over integer cents — never string-concatenated. (USD is
  implicit; the contract carries no currency code — see §16.)
- The budget/duration fields and the resulting amounts are announced via `liveRegion`
  when they change.
- Status chip conveys state by text + icon (not color alone); minimum touch targets
  48dp; supports dynamic font scaling and dark theme via Material 3 tokens.

## 10. Telemetry & Logging

- Analytics events via the shared analytics abstraction (field names CORRECTED to the
  real contract): `boost_screen_view` (post_id), `boost_submit` (budget_cents,
  duration_seconds, content_type), `boost_create_success` (boost_id, status,
  budget_cents), `boost_create_failure` (error_code), `boost_status_change` (boost_id,
  from, to), `boost_cancel` (boost_id, refunded_cents).
- No PII in any event; there are no payment identifiers to report (the contract has
  none), so the draft's `has_payment_method` flag is removed.
- Diagnostic logging through the project logger at DEBUG for request/response status
  codes only (no bodies); errors logged at WARN with mapped error code, never raw
  `detail` containing user input.

## 11. Testing Strategy

Unit (JVM, `core-testing` + Turbine + MockWebServer):

- `BoostViewModelTest` — state transitions (the AND-031-style coverage): Loading →
  Form on successful load; budget/duration edits recompute `canSubmit`; `onSubmit` sets
  `submitting=true` then Status on success; `inlineError` on `422`; Error(retryable) on
  timeout/5xx. Assert button disabled while `submitting` and while `content_id` is
  blank. (CORRECTED: no `totalSpendMinor`, no payment preselect, no 402/409 cases.)
- `BoostRepositoryTest` — MockWebServer: POST maps `ContentBoostDto`→`ContentBoost`,
  GET maps, cancel maps, FastAPI `detail` variants (string / `[{msg}]` / `{code}`) map
  to `ApiResult.Error`, Room upsert occurs on success, POST is not retried on 5xx, GET
  is retried with bounded backoff.
- `BoostDtoTest` — Moshi round-trip: integer epoch `starts_at`/`ends_at`/`created_at`,
  all `ContentBoostOut` required fields present, unknown `status` → `BoostStatus.UNKNOWN`.
- Poll logic test — stops when status leaves `active`/in-progress and after max ticks.

Instrumented/Compose (`feature-boost` androidTest):

- `BoostScreenTest` — Loading/Error/Form/Status render; Boost button disabled with
  blank `content_id` and with budget/duration < 1; tapping Boost shows spinner; Status
  view shows status chip and budget/spent/remaining. Accessibility assertions on labels.

Coverage gate: ViewModel + repository ≥ 80% line coverage.

## 12. Dependencies & Sequencing

- **AND-363 (Ads accounts API)** — (CORRECTED) **no longer required** for boost
  creation: the contract has no ads-account/payment-method/currency/budget-bound fields.
  Downgraded to an optional UX dependency (a "manage wallet / billing" link). The
  frontmatter `depends_on` is retained for traceability but should be revisited; this
  ticket can ship without AND-363.
- **AND-031 (LoginViewModel)** — pattern/infra: establishes the `StateFlow<UiState>` +
  submit/result-mapping ViewModel convention and the authenticated session this
  feature rides on.
- Implicit infra (assumed present): cookie jar + CSRF interceptor + session refresh,
  shared `ApiResult`/error mapper, `PostRepository` for post summary, analytics
  abstraction.
- This ticket **blocks**: none recorded in backlog.
- Build order: `BoostApi`/`BoostRepository`/Room → ViewModel → Compose + navigation
  wiring → entry points on detail/composer screens. (AND-363 only gates the optional
  billing link, not the core flow.)

## 13. Risks & Open Questions

- R1. RESOLVED in this review: field names verified against OpenAPI
  (`ContentBoostCreate`/`ContentBoostOut`) and `contentBoost.ts`. Paths are
  `/ui/ads/boost`; create input is `{content_type, content_id, budget_cents,
  duration_seconds}`; response is `ContentBoostOut` with epoch-second timestamps. DTOs
  locked accordingly. *(Mitigation retained: DTO unit tests.)*
- R2. RESOLVED: there are no server-returned budget min/max or allowed durations.
  `budget_cents`/`duration_seconds` are plain inputs (min 1). Any client default/max is
  a product choice (UNVERIFIED), not a contract bound.
- R3. RESOLVED/REMOVED: there is no `402` payment-failure path in the contract (no
  payment-method field). The only documented error is `422` validation.
- R4. Repeat-boost dedup: there is no `409` in the contract. Whether the server allows
  multiple concurrent boosts per post is **unconfirmed**; client may use
  `GET /ui/ads/boost?active_only=true` to detect an existing active boost. Cancel
  (`POST .../cancel`) IS in the contract; "edit an existing boost" remains out of scope
  — open follow-up.
- R5. Dev host instability may make status polling flaky; tests use MockWebServer, not
  the live host. (Polling itself is an Android-only addition — the web reference does
  not poll.)

## 14. Acceptance Criteria

AC-1 (from backlog: "Boost creates + shows status"): submitting a valid boost from the
post detail or composer-success entry point issues `POST /ui/ads/boost` with
`{content_type, content_id, budget_cents, duration_seconds}` and, on success, the screen
transitions to the Status view showing the returned `status`, `boost_id`, and budget /
spent / remaining. *(BoostViewModelTest + BoostScreenTest.)*

AC-2: The entered budget is shown back to the user as USD currency over integer cents
and updates live as inputs change; submit is blocked when `budget_cents < 1` or
`duration_seconds < 1`. (CORRECTED: no daily×duration total, no account min/max.)

AC-3: No payment-method or ads-account selection is required (none in the contract);
the Boost button is enabled once `content_id` is non-empty and budget/duration are
valid. An optional billing/wallet link may be shown (AND-363, UX-only).

AC-4: While the Status view is visible, status is refreshed on resume and via bounded
poll (Android-only addition) until the boost is no longer in progress; the create/cancel
POSTs are never auto-retried; only GETs are retried.

AC-5: A previously boosted post reopened at `boost/{postId}` shows last known status
from Room before the network refresh.

AC-6: State transitions (loading/disabled, success, error variants `422`/timeout/5xx)
are covered by unit tests (per AND-031 convention). (CORRECTED: 402/409 removed.)

## 15. Definition of Done

- `feature-boost` module created and wired into the app nav graph at `boost/{postId}`
  with entry points on post detail and composer-success.
- `BoostApi`, `BoostRepository` (+ Room cache), `BoostViewModel`, and `BoostScreen`
  implemented per this spec using `com.testlogon.android` packaging.
- Moshi DTOs map the real `/ui/ads/boost` payloads (`ContentBoostCreate` /
  `ContentBoostOut`, verified against OpenAPI in §16); FastAPI `detail` errors mapped
  via the shared mapper.
- All user strings externalized; accessibility labels and currency formatting in place.
- Unit + Compose tests green; ViewModel/repository ≥ 80% line coverage; analytics
  events emitted with no PII/payment identifiers.
- `./gradlew :feature-boost:detekt :feature-boost:testDebugUnitTest
  :feature-boost:connectedDebugAndroidTest` pass on CI; ktlint/detekt clean.
- Code reviewed and merged to `android-port`; open questions in §13 either resolved or
  filed as follow-up tickets.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Create endpoint is `POST /ui/ads/boost`** (draft said `/ui/content/boost`).
   VERDICT: **Corrected**. SOURCE: OpenAPI `POST /ui/ads/boost`
   (`op=create_boost_ui_ads_boost_post`); `src/api/endpoints/contentBoost.ts: create`.
2. **Get-status endpoint is `GET /ui/ads/boost/{boost_id}`** (draft said
   `/ui/content/boost/{boostId}`). VERDICT: **Corrected**. SOURCE: OpenAPI
   `GET /ui/ads/boost/{boost_id}`; `src/api/endpoints/contentBoost.ts: get`.
3. **Create request body = `ContentBoostCreate {content_type, content_id, budget_cents,
   duration_seconds}`** (draft had `post_id, ads_account_id, payment_method_id,
   daily_budget_minor, currency, duration_days`). VERDICT: **Corrected**. SOURCE:
   OpenAPI `components.schemas.ContentBoostCreate` (required: content_type, content_id,
   budget_cents, duration_seconds; budget_cents/duration_seconds minimum 1);
   `src/api/types.ts: ContentBoostCreateInput`.
4. **`budget_cents` is the TOTAL budget in cents (≥1); `duration_seconds` is seconds
   (≥1)** (draft modelled daily budget × duration in days). VERDICT: **Corrected**.
   SOURCE: `ContentBoostCreate` field descriptions ("total budget in integer cents",
   "boost duration in seconds"); `src/pages/ads/ContentBoostPage.tsx: handleSubmit`
   (`budget_cents = parseFloat(dollars)*100`, `duration_seconds = minutes*60`).
5. **Response = `ContentBoostOut {boost_id, owner_sub, content_type, content_id,
   budget_cents, spent_cents, remaining_cents, duration_seconds, starts_at, ends_at,
   status, created_at}`; no `campaign_id`/`total_spend_minor`/`currency`/`review_reason`;
   timestamps are integer epoch seconds** (draft had ISO `created_at`, plus
   campaign/total/currency/review fields). VERDICT: **Corrected**. SOURCE: OpenAPI
   `components.schemas.ContentBoostOut` (all fields `type:integer` for the timestamps);
   `src/api/types.ts: ContentBoost` (`created_at: number`, `ends_at: number`).
6. **No payment-method / ads-account / currency selection exists** (draft built a
   payment radio list, default-method preselect, and ads-account-sourced currency from
   AND-363). VERDICT: **Corrected**. SOURCE: `ContentBoostCreate` has no such fields;
   `src/pages/ads/ContentBoostPage.tsx` form has only content type/id, budget, duration;
   web copy: "we charge your wallet up-front".
7. **Currency is implicitly USD over integer cents** (draft selected currency from the
   ads account). VERDICT: **Corrected / Unverified-assumption** (no currency field in
   contract; web hardcodes `$` via `dollars(cents)`). SOURCE:
   `src/pages/ads/ContentBoostPage.tsx: dollars()` and label "Budget (USD)".
8. **Only documented error response is `422:HTTPValidationError`; `402` and `409` are
   not in the contract** (draft specified 402 payment-required and 409 already-boosted
   handling). VERDICT: **Corrected**. SOURCE: OpenAPI index lines for all five boost
   endpoints (`resp=...;422:HTTPValidationError` only); `components.schemas.HTTPValidationError`;
   no 402/409 handling in `src/api/client.ts`.
9. **Auth = `Authorization: Bearer <accessToken>` + `ui_csrf` cookie echoed as
   `X-CSRF-Token` + cookie credentials; `401` → one `POST /ui/session/refresh` then
   retry** (draft mentioned cookie + CSRF + refresh but omitted the Bearer token).
   VERDICT: **Corrected (CSRF/refresh Verified; Bearer added)**. SOURCE:
   `src/api/client.ts` (`Authorization: Bearer`, `getCookie("ui_csrf")` →
   `X-CSRF-Token`, `refreshSession()` posting `/ui/session/refresh`); OpenAPI
   `POST /ui/session/refresh` exists.
10. **Cancel endpoint `POST /ui/ads/boost/{boost_id}/cancel` →
    `{boost_id, status, refunded_cents}`, offered only while `status == "active"`.**
    VERDICT: **Verified** (newly surfaced; draft omitted it). SOURCE: OpenAPI
    `components.schemas.ContentBoostCancelOut`; `src/api/endpoints/contentBoost.ts: cancel`;
    `src/pages/ads/ContentBoostDetail.tsx` (cancel button gated on `status === "active"`).
11. **Spend endpoint `GET /ui/ads/boost/{boost_id}/spend` →
    `{boost_id, budget_cents, spent_cents, remaining_cents, status}`.** VERDICT:
    **Verified**. SOURCE: OpenAPI `components.schemas.ContentBoostSpendOut`;
    `src/api/types.ts: ContentBoostSpend`.
12. **List endpoint `GET /ui/ads/boost?active_only=<bool>` → `{boosts: [...]}`.**
    VERDICT: **Verified**. SOURCE: OpenAPI `GET /ui/ads/boost`
    (`params=active_only,...`); `src/api/endpoints/contentBoost.ts: list`;
    `src/api/types.ts: ContentBoostListResponse`.
13. **FastAPI `detail` shapes are string | `[{msg}]` | `{code,...}`.** VERDICT:
    **Verified**. SOURCE: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`.
14. **`status` values: only `"active"` is exercised; richer enum is forward-compat
    guess.** VERDICT: **Unverified-assumption**. SOURCE: `ContentBoostOut.status` is an
    untyped `string`; `src/pages/ads/*` only branch on `"active"`.
15. **Status polling on the Android screen** (every 15s, bounded). VERDICT:
    **Unverified-assumption** (Android design choice; web does not poll — it uses
    react-query `invalidateQueries`). SOURCE: `src/pages/ads/ContentBoostPage.tsx` /
    `ContentBoostDetail.tsx` (no `refetchInterval`; invalidation on mutation only).
16. **Room cache one row per boosted post.** VERDICT: **Unverified-assumption**
    (Android local design; no web equivalent). SOURCE: n/a (client-side).
17. **`X-IMPERSONATION-TOKEN` header exists (admin impersonation), unused here.**
    VERDICT: **Verified**. SOURCE: OpenAPI boost endpoint `params=...,X-IMPERSONATION-TOKEN`;
    `src/api/client.ts` impersonation header.
18. **Framework stack (Compose/Material 3, Navigation-Compose, Hilt, Retrofit/OkHttp/
    Moshi, Room, `repeatOnLifecycle(STARTED)`, `StateFlow` + `WhileSubscribed`).**
    VERDICT: **Unverified-assumption** (project convention from AND-031; not checkable
    against backend/web sources). SOURCE: framework refs —
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/topic/libraries/architecture/coroutines#lifecycle-aware
    (lifecycle-aware flow collection),
    https://developer.android.com/kotlin/flow/stateflow-and-sharedflow .

### Corrections made

- Endpoint base path `/ui/content/boost` → `/ui/ads/boost` (create, get, +cancel/spend/list)
  throughout §1, §5, §11, §14, §15 (claims 1, 2, 10–12).
- Create request fields replaced with `content_type/content_id/budget_cents/duration_seconds`
  and DTO `ContentBoostCreateInput`; removed `post_id/ads_account_id/payment_method_id/
  daily_budget_minor/currency/duration_days` (§4, §5; claims 3, 4, 6).
- Response DTO replaced with `ContentBoostOut` shape, epoch-second timestamps, removed
  `campaign_id/total_spend_minor/currency/review_reason` (§4, §5, §6; claim 5).
- Removed payment-method UI/state, ads-account loading, currency selection, and the
  daily×duration "total spend" computation; AND-363 downgraded to optional UX (§1–§4,
  §6, §8–§10, §12; claims 6, 7).
- Error handling: removed `402` and `409` cases; kept `422` + generic `401/403`
  (§5, §7, §11, §14; claim 8).
- Auth: added the `Authorization: Bearer` access token alongside CSRF/refresh (§5, §8;
  claim 9).
- Type names corrected (`BoostRequest/Boost/BoostStatus` → `ContentBoostCreateInput/
  ContentBoost/...`); Room entity columns corrected; telemetry/analytics fields
  corrected (§2, §4, §6, §10).
- Frontmatter de-duplicated (single `status: reviewed`) and `reviewed_on: 2026-06-06`
  added.

### Open assumptions

- **Status value set** beyond `"active"` (PENDING/COMPLETED/CANCELLED/etc.) — `status`
  is an untyped server string and only `"active"` appears in the web reference; mapped
  defensively with `UNKNOWN`. Why unverifiable: not enumerated in OpenAPI or web source.
- **Polling cadence/strategy** (15s, max 20 ticks) — Android-only; the web client does
  not poll. Why: no backend contract for refresh cadence; product/perf choice.
- **Client-side budget default/max** (e.g. $5.00 / 60 min default) — mirrors web
  defaults; any max is a product choice. Why: contract only enforces a minimum of 1.
- **USD currency** — implicit; no currency field exists. Why: contract carries cents
  only; web hardcodes `$`.
- **Room caching / offline-stale behavior** — local design, no web/back-end analogue.
- **Duplicate-boost handling per post** — server behavior unconfirmed (no `409`); may be
  detected client-side via `active_only=true` list. Why: not specified in sources.
- **Framework choices** (Compose/Hilt/Retrofit/etc.) — project convention (AND-031), not
  verifiable against the backend/web reference; see framework refs in claim 18.

## 17. Test Plan

IDs `TC-AND-364-NN`. "Traces" links to §14 acceptance criteria. Device targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
Samsung Galaxy A15 5G (`SM-A156U`, serial `R5CX821TA9R`, API 34 arm64-v8a). This
feature has no camera/biometrics/WebRTC/FCM/Telecom needs, so most cases run on
JVM/emulator; physical-device cases are limited to real-network HTTP behaviour and the
API-34/arm64-vs-API-35/x86 ABI check.

- **TC-AND-364-01 — Create happy path (ViewModel + contract).**
  Type: contract/MockWebServer (JVM). Target: JVM unit. Preconditions: MockWebServer
  enqueues `200 ContentBoostOut` (`status:"active"`). Steps: set content_id="post_abc123",
  budget=$5.00, duration=60min; `onSubmit()`. Expected: request is `POST /ui/ads/boost`
  with JSON `{content_type:"post", content_id:"post_abc123", budget_cents:500,
  duration_seconds:3600}`; `Authorization: Bearer` + `X-CSRF-Token` headers present;
  state goes `submitting=true` → `Status(boost)` with status/boost_id/budget/spent/
  remaining; Room upsert occurs. Traces: AC-1, AC-2.

- **TC-AND-364-02 — DTO mapping incl. epoch timestamps & unknown status.**
  Type: unit (JVM). Target: JVM unit (Moshi). Preconditions: sample `ContentBoostOut`
  JSON with integer `starts_at/ends_at/created_at` and `status:"frobnicated"`. Steps:
  deserialize → map to domain. Expected: timestamps parse as `Long` epoch seconds (no
  ISO parse), all required fields populated, unknown status → `BoostStatus.UNKNOWN`,
  re-serialization round-trips. Traces: AC-1, AC-6.

- **TC-AND-364-03 — Validation error (422) maps to inline error.**
  Type: contract/MockWebServer (JVM). Target: JVM unit. Preconditions: MockWebServer
  enqueues `422 {detail:[{loc:["body","budget_cents"],msg:"ensure this value is
  greater than or equal to 1",type:"..."}]}`. Steps: submit with budget_cents=0.
  Expected: `ApiResult.Error` mapped via shared `detail` mapper; `inlineError` set with
  the `msg`; state returns to `Form` (not `Status`); POST not retried. Traces: AC-2, AC-6.

- **TC-AND-364-04 — canSubmit / button gating.**
  Type: unit (JVM). Target: JVM unit. Steps: vary content_id (blank vs set), budget_cents
  (0 vs ≥1), duration_seconds (0 vs ≥1), submitting flag. Expected: `canSubmit` true only
  when content_id non-blank AND budget_cents≥1 AND duration_seconds≥1 AND !submitting.
  Traces: AC-2, AC-3, AC-6.

- **TC-AND-364-05 — Double-tap guard (no duplicate POST).**
  Type: unit (JVM). Target: JVM unit. Preconditions: slow MockWebServer response. Steps:
  call `onSubmit()` twice rapidly. Expected: exactly one `POST /ui/ads/boost` is issued;
  button disabled while `submitting`. Traces: AC-1, AC-6.

- **TC-AND-364-06 — Status refresh + bounded poll stop.**
  Type: unit (JVM, virtual time). Target: JVM unit. Preconditions: GET returns
  in-progress then a terminal/non-active status. Steps: drive `refreshStatus()` on the
  poll schedule. Expected: GET `/ui/ads/boost/{id}` retried on cadence; polling stops on
  non-active status and after max ticks; the create POST is never auto-retried. Traces:
  AC-4.

- **TC-AND-364-07 — Idempotent GET retry vs non-retried POST on 5xx.**
  Type: contract/MockWebServer (JVM). Target: JVM unit. Preconditions: GET returns
  `503` twice then `200`; POST returns `503`. Steps: call `getBoost` and `createBoost`.
  Expected: GET retried with bounded backoff (≤3 attempts) then succeeds; POST surfaces
  `Error(retryable=false-for-charge)` after a single attempt (no auto-retry). Traces:
  AC-4, AC-6.

- **TC-AND-364-08 — 401 triggers single session refresh then retry.**
  Type: contract/MockWebServer (JVM). Target: JVM unit. Preconditions: first GET → `401`;
  `POST /ui/session/refresh` → `200`; retried GET → `200`. Steps: call `getBoost`.
  Expected: exactly one refresh call, original GET retried once, success returned; on a
  second `401` after refresh, mapped to auth error (no infinite loop). Traces: AC-4, AC-6.

- **TC-AND-364-09 — Cached status shown before network (offline/stale).**
  Type: integration (Robolectric + in-memory Room). Target: JVM/Robolectric.
  Preconditions: Room has a `BoostEntity` for postId; network unreachable. Steps: open
  `boost/{postId}`. Expected: Status view renders last-known status/budget from Room
  before/without a successful refresh; a stale indicator is shown; no crash on network
  failure. Traces: AC-5.

- **TC-AND-364-10 — Flaky dev-host / offline initial load.**
  Type: instrumented/e2e. Target: **PHYSICAL DEVICE (Galaxy A15, API 34 arm64)** —
  exercises real OkHttp timeout/connection behaviour against an unreachable/slow host.
  Preconditions: device online but host unresponsive (use airplane-mode toggle or a
  black-holed base URL). Steps: open the boost screen with empty cache. Expected:
  `Error(retryable=true)` with a Retry button within the ~20s call timeout; tapping
  Retry re-issues the load; no ANR. Traces: AC-4, AC-5. (Must be physical: validates
  real-network timeout/ABI behaviour, not emulator loopback.)

- **TC-AND-364-11 — CSRF + Bearer headers on state-changing POST (security).**
  Type: contract/MockWebServer (JVM). Target: JVM unit. Preconditions: cookie jar holds
  a `ui_csrf` cookie; auth store holds an access token. Steps: `onSubmit()`. Expected:
  the recorded request carries `X-CSRF-Token` (== cookie value) and `Authorization:
  Bearer <token>`; no cookie/token value appears in any log line. Traces: AC-1.

- **TC-AND-364-12 — No payment/PII in analytics or logs (privacy).**
  Type: unit (JVM). Target: JVM unit. Steps: drive submit/success/failure and capture
  emitted analytics + logs. Expected: events carry only budget_cents/duration_seconds/
  content_type/boost_id/status/error_code; no `Authorization`, cookie, or any
  payment-method identifier (none exist); response bodies are not logged. Traces: AC-1.

- **TC-AND-364-13 — Compose UI states + accessibility.**
  Type: Compose-UI. Target: emulator AVD `test35` (CI). Steps: render Loading / Error
  (Retry visible) / Form / Status; toggle content_id blank vs set and invalid budget.
  Expected: Boost button disabled when content_id blank or budget/duration <1; tapping
  Boost shows spinner; Status shows status chip (text+icon, not colour-only) and
  budget/spent/remaining; all controls have semantics/contentDescription labels; touch
  targets ≥48dp; amounts announced via liveRegion; renders under font scaling + dark
  theme. Traces: AC-1, AC-2, AC-3.

- **TC-AND-364-14 — Cancel active boost.**
  Type: instrumented (Compose-UI + MockWebServer or fake). Target: emulator AVD `test35`.
  Preconditions: Status view with `status=="active"`. Steps: tap "Cancel & refund".
  Expected: `POST /ui/ads/boost/{id}/cancel` issued once (not auto-retried); UI reflects
  returned status + `refunded_cents`; cancel control hidden for non-active statuses.
  Traces: AC-4.

- **TC-AND-364-15 — API-34/arm64 vs API-35/x86 parity.**
  Type: instrumented/e2e. Target: run TC-13 (+TC-01 flow) on BOTH the **physical Galaxy
  A15 (API 34, arm64-v8a)** and emulator `test35` (API 35, x86_64). Expected: identical
  behaviour, currency formatting, and DTO parsing across ABI/API; no arm64-specific
  Moshi/number-format regressions. Traces: AC-1, AC-2. (Physical device required for the
  arm64/API-34 leg.)

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (create → status shown) | TC-01, TC-02, TC-05, TC-11, TC-12, TC-13, TC-15 |
| AC-2 (budget shown as USD, submit gated on validity) | TC-01, TC-03, TC-04, TC-13, TC-15 |
| AC-3 (no payment/ads-account required; gating) | TC-04, TC-13 |
| AC-4 (resume/poll refresh; POST never auto-retried; cancel) | TC-06, TC-07, TC-08, TC-10, TC-14 |
| AC-5 (cached status before network) | TC-09, TC-10 |
| AC-6 (state transitions + error variants unit-tested) | TC-02, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08 |
