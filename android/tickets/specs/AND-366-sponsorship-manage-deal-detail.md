---
id: AND-366
title: Sponsorship manage / deal detail
milestone: M8
epic: E47
priority: P2
size: L
depends_on: [AND-365]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-366 — Sponsorship manage / deal detail

## 1. Overview & Goal

Provide a signed-in user (creator or sponsor) with a **deal detail** screen for a
single sponsorship deal, plus the three management **actions** the backlog requires:
**accept**, **reject** (the backlog's "decline"), and **negotiate** (counter-offer).
The screen opens from the sponsorship list/inbox delivered by AND-365, loads the full
deal — parties (`advertiser_sub`/`creator_sub`), brief, terms (`compensation_cents`,
`deliverables`, `deadline`), current `status`, and the deal **event history** (fetched
from a separate `/history` endpoint) — and lets the user act on a deal that is in an
actionable state. Accepting or rejecting is a single confirmed mutation; negotiating
opens a counter-offer form (new compensation, optional note) that submits a counter and
refreshes the deal.
> CORRECTION (review): the backend action is **`reject`**, not `decline`; verified
> `POST /ui/ads/sponsorships/{deal_id}/reject` and the absence of any `decline` path in
> the OpenAPI index. The frontend calls it `rejectSponsorshipDeal`
> (`src/api/endpoints/sponsorshipDeals.ts`).

After any action the screen must immediately reflect the deal's new server-returned
`status`. The real status set (verified against `SponsorshipDealStatus` in
`src/api/types.ts`) is: `proposed`, `negotiating`, `accepted`, `content_submitted`,
`completed`, `rejected`, `cancelled` (NOT the previously-assumed
`pending/offered/countered/declined/expired`), and update which actions are available.
Actions are
**non-idempotent POSTs** and must never be auto-retried; the deal load/refresh is an
idempotent GET that may be retried with bounded backoff.

This is the Android port of the web reference deal-management behavior. It builds on
AND-365, which delivers the sponsorship list, the `Deal`/`DealStatus` model, the
`SponsorshipApi`/`SponsorshipRepository`, and navigation into this detail route.

**Done means:** the deal detail screen renders a real deal and its history; accept,
reject, and negotiate each issue the correct POST, succeed against the dev backend,
and the screen reflects the returned status and recomputed available actions; state
transitions are unit-tested.

## 2. Context & References

- Predecessor ticket (required): **AND-365** — sponsorship list/inbox, `Deal` and
  `DealStatus` in `core-model`, `SponsorshipApi`/`SponsorshipRepository` in
  `core-data`, and the navigation entry that routes into `deal/{dealId}`.
- ViewModel/state + result-mapping pattern: established `StateFlow<UiState>` + submit
  handler + `ApiResult` mapping convention (same convention referenced across the M8
  feature tickets, e.g. AND-364 `BoostViewModel`).
- Web reference app (`frontend/`): sponsorship API layer at
  `src/api/endpoints/sponsorshipDeals.ts` and shared types in `src/api/types.ts`
  (verified type names: `SponsorshipDeal`, `SponsorshipDealStatus`,
  `SponsorshipDealEvent`, `SponsorshipDealCreate`, `SponsorshipPaymentDetails`). The
  deal-detail screen is `src/pages/ads/SponsorshipDealDetail.tsx`; the creator inbox
  (accept/reject) is `src/pages/ads/SponsorshipInbox.tsx`; the advertiser manager is
  `src/pages/ads/SponsorshipManager.tsx`. NOTE: there is no `Deal`, `DealOffer`,
  `DealStatus`, or `CounterOfferRequest` type in the web app — those names were
  assumptions and are corrected throughout this spec.
- OpenAPI source of truth: `http://18.222.237.167:8000/openapi.json` (dev, plaintext
  HTTP, unreliable host; design for ~20s timeouts, bounded GET retries, stale UI).
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore,
  Paging 3. minSdk 24 / compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Module layering: `feature-sponsorship` (extended here; created by AND-365) →
  `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`. App namespace
  base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. Entry: a deal row in the sponsorship list (AND-365) navigates to
`deal/{dealId}`. The route also supports deep entry (e.g. from a notification) given a
`dealId`. (The `dealId` route arg maps to the API path param `deal_id`; the deal's own
identifier field is `deal_id` — verified `SponsorshipDeal.deal_id` in `src/api/types.ts`.)

FR-2. Load: the detail screen loads the full deal via
`GET /ui/ads/sponsorships/{deal_id}` (CORRECTED path), including parties
(`advertiser_sub`, `creator_sub`), `brief`, current terms (`compensation_cents` in USD
cents, `deliverables` list, `deadline` as `YYYY-MM-DD`, optional `cpm_bonus_cents`,
`platform_commission_bps`), `status`, optional `content_id`, and optional
`payment_details`. The deal **event history** is a SEPARATE call
`GET /ui/ads/sponsorships/{deal_id}/history` returning `SponsorshipDealEvent[]`
(`event_id`, `event_type`, `actor_sub`, `details`, `created_at`). The deal object does
NOT embed an `offers[]` array — that was an assumption and is corrected. (Verified:
`getSponsorshipDeal`/`getSponsorshipDealHistory` in
`src/api/endpoints/sponsorshipDeals.ts`; `SponsorshipDeal`/`SponsorshipDealEvent` in
`src/api/types.ts`.)

FR-3. Action availability is derived from `status` **and** the viewer's role. The deal
has NO `viewerRole`/`authored_by_viewer` field; role is determined client-side by
comparing the current user's `sub` to `advertiser_sub` vs `creator_sub`. Rules
(verified against `SponsorshipInbox.tsx`):
- `accept` and `reject` are available only when `status` is `proposed` or `negotiating`.
  In the web inbox these are the creator-facing actions.
- `negotiate` (counter) is available in the same `proposed`/`negotiating` states; per
  the `SponsorshipCounterRequest` schema description it is the **creator's**
  counter-offer on a proposed deal.
- Terminal/non-actionable states (`accepted`, `content_submitted`, `completed`,
  `rejected`, `cancelled`) expose **no** accept/reject/negotiate actions; the screen is
  read-only with a status banner.
The client gating is UX only; the server is authoritative and may still reject.

FR-4. Accept: tapping "Accept" shows a confirmation dialog; confirming calls
`POST /ui/ads/sponsorships/{deal_id}/accept` (no request body). On success the deal
transitions to `accepted` and actions hide.

FR-5. Reject (backlog "decline"): tapping "Reject" shows a confirmation dialog with an
optional reason field; confirming calls `POST /ui/ads/sponsorships/{deal_id}/reject`
with body `{ "reason": string }` (`SponsorshipRejectRequest`; `reason` defaults to `""`,
maxLength 500). On success the deal transitions to `rejected`.

FR-6. Negotiate: tapping "Negotiate" opens a counter-offer form pre-filled with the
current terms. The user edits the compensation (`compensation_cents`, integer USD
cents, minimum 1000) and an optional `note` (maxLength 2000), then submits
`POST /ui/ads/sponsorships/{deal_id}/counter` with body
`{ "compensation_cents"?: int, "note"?: string }` (`SponsorshipCounterRequest`; both
fields optional). NOTE: the counter body does NOT carry `currency` or a `deliverables`
array — those were assumptions and are corrected; the counter changes compensation (and
an optional note) only. On success the deal transitions to `negotiating`, a
corresponding event appears in the `/history` feed, and action availability recomputes.

FR-7. While any action is in flight the corresponding button shows a spinner and **all**
action buttons are disabled (single-flight guard) so a deal cannot be double-acted.

FR-8. After any successful action the screen refreshes the full deal (or applies the
returned `Deal` if the action endpoints return the updated deal) and recomputes
available actions and the history list without a manual reload.

FR-9. Offline/stale: the last loaded deal is cached in Room; reopening `deal/{dealId}`
shows the cached deal immediately, then refreshes from network. If refresh fails the
cached copy stays visible behind a "couldn't refresh" stale banner.

## 4. Technical Design

Work lands in the existing `feature-sponsorship` module (created by AND-365). New:
`DealDetailViewModel`, `DealDetailScreen`/`DealDetailRoute`, the detail navigation
entry, and the action methods on `SponsorshipRepository`.

**Navigation**

```kotlin
const val DEAL_DETAIL_ROUTE = "deal/{dealId}"
fun NavController.navigateToDeal(dealId: String) = navigate("deal/$dealId")

fun NavGraphBuilder.dealDetailScreen(onUpClick: () -> Unit) {
    composable(
        route = DEAL_DETAIL_ROUTE,
        arguments = listOf(navArgument("dealId") { type = NavType.StringType }),
    ) { DealDetailRoute(onUpClick = onUpClick) }
}
```

**UI state** (sealed; mirrors the project `StateFlow<UiState>` convention)

```kotlin
enum class DealAction { ACCEPT, REJECT, NEGOTIATE }   // REJECT == backlog "decline"

data class DealDetailContent(
    val deal: Deal,                       // from core-model (AND-365)
    val availableActions: Set<DealAction>,
    val inFlight: DealAction? = null,     // non-null while a mutation runs
    val stale: Boolean = false,           // cached shown, refresh failed
    val inlineError: String? = null,      // last action error, dismissible
)

data class CounterFormState(
    val compensationCents: Long,        // SponsorshipCounterRequest.compensation_cents (>= 1000)
    val note: String = "",              // SponsorshipCounterRequest.note (<= 2000 chars)
    val submitting: Boolean = false,
    val inlineError: String? = null,
) {
    // Backend minimum is 1000 cents ($10.00); note is optional. There is no
    // currency or deliverables field on the counter request.
    val canSubmit: Boolean get() =
        !submitting && compensationCents >= 1000 && note.length <= 2000
}

sealed interface DealDetailUiState {
    data object Loading : DealDetailUiState
    data class Error(val message: String, val retryable: Boolean) : DealDetailUiState
    data class Detail(val content: DealDetailContent) : DealDetailUiState
}
```

The counter-offer form is presented as a modal sheet on top of the `Detail` state; its
`CounterFormState` is held in a separate `MutableStateFlow` so the underlying deal stays
rendered behind it.

**ViewModel**

```kotlin
@HiltViewModel
class DealDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val sponsorshipRepository: SponsorshipRepository,   // AND-365
) : ViewModel() {
    private val dealId: String = checkNotNull(savedStateHandle["dealId"])
    val uiState: StateFlow<DealDetailUiState>
    val counterForm: StateFlow<CounterFormState?>

    fun onRetry()
    fun onAccept()                                   // confirm -> POST .../accept
    fun onReject(reason: String?)                    // confirm -> POST .../reject
    fun onOpenNegotiate()                            // seed CounterFormState from deal
    fun onCounterCompensationChange(cents: Long)
    fun onCounterNoteChange(text: String)
    fun onSubmitCounter()                            // POST .../counter
    fun onDismissCounter()
    fun onDismissInlineError()
}
```

Available actions are computed by a pure helper so it is directly unit-testable:

```kotlin
// `currentUserSub` is the signed-in user's sub; the deal has no viewerRole field, so
// role is derived by comparing it to advertiser_sub / creator_sub.
internal fun availableActionsFor(deal: Deal, currentUserSub: String): Set<DealAction> =
    when (deal.status) {
        DealStatus.PROPOSED, DealStatus.NEGOTIATING ->
            setOf(DealAction.ACCEPT, DealAction.REJECT, DealAction.NEGOTIATE)
        else -> emptySet()  // accepted/content_submitted/completed/rejected/cancelled
    }
```
> NOTE: the web inbox surfaces Accept/Reject to the creator on `proposed`/`negotiating`
> deals (`SponsorshipInbox.tsx`). Whether the advertiser sees a distinct action set is
> not expressed in the web UI; `currentUserSub` is threaded through so role-specific
> gating can be added once confirmed (see §16 open assumptions). The server remains
> authoritative.

Each action method sets `inFlight = <action>` (disabling all buttons per FR-7), calls
the repository, and maps `ApiResult`: success → replace `deal`, recompute
`availableActions`, clear `inFlight`; failure → `inlineError` (or `Error` if the deal
could not be (re)loaded). No mutation is retried.

**Repository** (extends `SponsorshipRepository` from AND-365, in `core-data`)

```kotlin
interface SponsorshipRepository {
    // ...from AND-365 (list, etc.)
    fun observeDeal(dealId: String): Flow<Deal?>                       // Room-backed
    suspend fun getDeal(dealId: String): ApiResult<Deal>              // idempotent GET
    suspend fun getDealHistory(dealId: String): ApiResult<List<DealEvent>>  // idempotent GET
    suspend fun acceptDeal(dealId: String): ApiResult<Deal>          // POST, no retry
    suspend fun rejectDeal(dealId: String, reason: String?): ApiResult<Deal>
    suspend fun counterDeal(dealId: String, request: CounterOfferRequest): ApiResult<Deal>
}
```

The route reads `observeDeal(dealId)` first (cached) then triggers `getDeal` to
refresh; every successful GET or action response upserts the Room entity.

**Compose** `DealDetailScreen` renders Loading / Error(retry) / Detail. Detail shows a
counterparty header (`advertiser_sub`/`creator_sub`), status chip (text + icon, not
color alone), terms card (`compensation_cents` formatted as USD via
`NumberFormat.getCurrencyInstance`, `deliverables`, `deadline`, optional
`cpm_bonus_cents`/`payment_details`), an event-history timeline from
`getDealHistory` (most recent first, items are `DealEvent` with `event_type`/`actor_sub`),
and an action bar (`Accept` / `Reject` / `Negotiate`) shown only when `availableActions`
is non-empty. Accept and reject open `AlertDialog` confirmations; negotiate opens a
`ModalBottomSheet` backed by `CounterFormState` (compensation + optional note).
NOTE: amounts are USD cents with no per-deal `currency` field; the spec previously keyed
formatting on a non-existent `currency` field — corrected to fixed USD.

## 5. API Contract

All paths are relative to dev base `http://18.222.237.167:8000`. **CORRECTION:** all
endpoints live under `/ui/ads/sponsorships/...`, NOT `/ui/sponsorship/deals/...`.

Auth/transport (verified against `src/api/client.ts`): the web client sends an
`Authorization: Bearer <accessToken>` header from the auth store, includes cookies
(`credentials: "include"`), echoes the `ui_csrf` cookie as the `X-CSRF-Token` header on
every request, and on a `401` (when already authenticated) calls
`POST /ui/session/refresh` once and retries the original request. The OpenAPI index
additionally lists `user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` as accepted
params on these endpoints (header-based service auth). The Android client should mirror
the web contract: bearer/session cookie + `X-CSRF-Token` + single 401→refresh→retry,
implemented by shared infra (not built here). The three action endpoints are
**state-changing POSTs** that must carry the CSRF header and must NOT be auto-retried;
only the GETs are retried.

**Get deal** — `GET /ui/ads/sponsorships/{deal_id}` (idempotent; ~20s timeout, bounded
backoff retry). Response shape is the `SponsorshipDeal` type (the OpenAPI index lists
no named 200 schema; field names verified from `src/api/types.ts` and
`SponsorshipDealDetail.tsx`).

Response `200` (representative):
```json
{
  "deal_id": "deal_7a2",
  "advertiser_account_id": "acct_19",
  "advertiser_sub": "user_adv_1",
  "creator_sub": "user_cr_2",
  "content_type": "video",
  "brief": "Sponsored 60s video on new launch",
  "deliverables": ["1x YouTube video", "2x story posts"],
  "compensation_cents": 250000,
  "cpm_bonus_cents": 0,
  "platform_commission_bps": 1000,
  "status": "proposed",
  "deadline": "2026-07-31",
  "content_id": null,
  "dm_conversation_id": null,
  "escrow_hold_id": null,
  "created_at": 1749038400,
  "updated_at": 1749038400,
  "completed_at": null,
  "cancelled_at": null,
  "cancel_reason": null,
  "payment_details": null
}
```
NOTE: `created_at`/`updated_at` (and `completed_at`/`cancelled_at`) are **numeric epoch
seconds**, not ISO strings. There is no `currency`, `viewer_role`, `counterparty`,
`amount_minor`, `starts_at`/`ends_at`, or embedded `offers[]` field — all corrected.

**Deal history** — `GET /ui/ads/sponsorships/{deal_id}/history` (idempotent) →
`SponsorshipDealEvent[]`:
```json
[
  {
    "event_id": "evt_1",
    "event_type": "proposed",
    "actor_sub": "user_adv_1",
    "details": {},
    "created_at": 1749038400
  }
]
```

**Accept** — `POST /ui/ads/sponsorships/{deal_id}/accept` (no body) → updated
`SponsorshipDeal` (`status: "accepted"`).

**Reject** (backlog "decline") — `POST /ui/ads/sponsorships/{deal_id}/reject`
```json
{ "reason": "Budget too low" }
```
→ updated `SponsorshipDeal` (`status: "rejected"`). `reason` is optional (defaults to
`""`, maxLength 500) — schema `SponsorshipRejectRequest`.

**Counter** — `POST /ui/ads/sponsorships/{deal_id}/counter`
```json
{
  "compensation_cents": 300000,
  "note": "Can do at this rate"
}
```
→ updated `SponsorshipDeal` (`status: "negotiating"`). Schema
`SponsorshipCounterRequest`: `compensation_cents` is optional integer ≥ 1000; `note` is
optional string (default `""`, maxLength 2000). No `currency`/`deliverables`/`message`
fields.

**Moshi DTOs** (in `core-model`; `DealDto`/`DealStatus` introduced by AND-365 — extend
only if fields are missing):

```kotlin
@JsonClass(generateAdapter = true)
data class DealDto(
    @Json(name = "deal_id") val dealId: String,
    @Json(name = "advertiser_account_id") val advertiserAccountId: String,
    @Json(name = "advertiser_sub") val advertiserSub: String,
    @Json(name = "creator_sub") val creatorSub: String,
    @Json(name = "content_type") val contentType: String,    // post|video|broadcast
    val brief: String,
    val deliverables: List<String>,
    @Json(name = "compensation_cents") val compensationCents: Long,
    @Json(name = "cpm_bonus_cents") val cpmBonusCents: Long,
    @Json(name = "platform_commission_bps") val platformCommissionBps: Int,
    val status: String,
    val deadline: String,                                    // YYYY-MM-DD
    @Json(name = "content_id") val contentId: String?,
    @Json(name = "dm_conversation_id") val dmConversationId: String?,
    @Json(name = "escrow_hold_id") val escrowHoldId: String?,
    @Json(name = "created_at") val createdAt: Long,          // epoch seconds
    @Json(name = "updated_at") val updatedAt: Long,          // epoch seconds
    @Json(name = "completed_at") val completedAt: Long?,
    @Json(name = "cancelled_at") val cancelledAt: Long?,
    @Json(name = "cancel_reason") val cancelReason: String?,
    @Json(name = "payment_details") val paymentDetails: PaymentDetailsDto?,
)

@JsonClass(generateAdapter = true)
data class PaymentDetailsDto(
    @Json(name = "total_cents") val totalCents: Long?,
    @Json(name = "commission_cents") val commissionCents: Long?,
    @Json(name = "creator_cents") val creatorCents: Long?,
    @Json(name = "advertiser_cents") val advertiserCents: Long?,
)

@JsonClass(generateAdapter = true)
data class DealEventDto(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "event_type") val eventType: String,
    @Json(name = "actor_sub") val actorSub: String,
    val details: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: Long,          // epoch seconds
)

@JsonClass(generateAdapter = true)
data class RejectRequestDto(val reason: String? = "")        // SponsorshipRejectRequest

@JsonClass(generateAdapter = true)
data class CounterOfferRequestDto(
    @Json(name = "compensation_cents") val compensationCents: Long?,  // >= 1000, optional
    val note: String? = "",                                          // <= 2000, optional
)
```

`status` maps to
`enum class DealStatus { PROPOSED, NEGOTIATING, ACCEPTED, CONTENT_SUBMITTED, COMPLETED, REJECTED, CANCELLED, UNKNOWN }`
with `UNKNOWN` for forward-compatible unrecognized values. (Verified against
`SponsorshipDealStatus` in `src/api/types.ts`.)

**Retrofit**

```kotlin
interface SponsorshipApi {
    // ...from AND-365 (list: GET ui/ads/sponsorships)
    @GET("ui/ads/sponsorships/{dealId}")
    suspend fun getDeal(@Path("dealId") dealId: String): Response<DealDto>

    @GET("ui/ads/sponsorships/{dealId}/history")
    suspend fun getDealHistory(@Path("dealId") dealId: String): Response<List<DealEventDto>>

    @POST("ui/ads/sponsorships/{dealId}/accept")
    suspend fun acceptDeal(@Path("dealId") dealId: String): Response<DealDto>

    @POST("ui/ads/sponsorships/{dealId}/reject")
    suspend fun rejectDeal(
        @Path("dealId") dealId: String,
        @Body body: RejectRequestDto,
    ): Response<DealDto>

    @POST("ui/ads/sponsorships/{dealId}/counter")
    suspend fun counterDeal(
        @Path("dealId") dealId: String,
        @Body body: CounterOfferRequestDto,
    ): Response<DealDto>
}
```
NOTE: the `{dealId}` Retrofit path placeholder maps to the API's `deal_id` path
parameter; the names differ only in casing convention.

**Error mapping:** FastAPI `detail` is parsed via the shared mapper (string |
`[{msg}]` | `{code,...}`) into `ApiResult.Error`, matching `normalizeErrorDetail` in
`src/api/client.ts` (string detail, array of `{msg}` validation items, or
`{code,...}` object). **Verified failure shape:** the only documented error response in
the OpenAPI index for every sponsorship endpoint is `422 HTTPValidationError`
(`detail: [{loc, msg, type}]`) — e.g. counter `compensation_cents` below the 1000
minimum, or a malformed `deal_id`. Map `422` on the counter form to an inline form
error.

**UNVERIFIED (assumption):** `409` (deal no longer actionable / counterparty already
acted) and `403` (viewer not a party) are NOT documented in the OpenAPI index for these
endpoints — they were assumed by the original draft. The backend may still return them
at runtime (FastAPI commonly raises `HTTPException(409/403)` outside the documented
schema), so the client should defensively handle them: on `409`, refresh the deal and
show an inline "this deal changed" notice then re-render with the server status; on
`403`, surface `Error(retryable=false)`. Confirm against the live host before relying on
these codes (see §16 open assumptions).

## 6. Data & State Management

- `DealDetailViewModel` exposes `StateFlow<DealDetailUiState>` via
  `stateIn(viewModelScope, WhileSubscribed(5_000), Loading)`, built by combining the
  Room-backed `observeDeal(dealId)` flow with an internal mutable status flow
  (`inFlight`, `stale`, `inlineError`). `counterForm` is a separate
  `MutableStateFlow<CounterFormState?>`, non-null only while the sheet is open.
- The deal model, `DealStatus`, and DTO→domain mapping come from AND-365; this ticket
  reuses them and adds the action paths. No duplicate deal models are defined.
- Room cache (`core-data`): one row per deal, storing the serialized deal for offline
  display.

```kotlin
@Entity(tableName = "deal")
data class DealEntity(
    @PrimaryKey val dealId: String,
    val status: String,
    val advertiserSub: String,      // (no viewerRole field exists on the deal)
    val creatorSub: String,
    val payloadJson: String,        // full Deal JSON for offline render
    val updatedAtEpochSeconds: Long, // server updated_at is epoch seconds
)

@Dao interface DealDao {
    @Query("SELECT * FROM deal WHERE dealId = :dealId")
    fun observe(dealId: String): Flow<DealEntity?>
    @Upsert suspend fun upsert(entity: DealEntity)
}
```

- On every successful `getDeal` or action response, the entity is upserted; the route
  reads the cache first so a returning user sees the last known deal before the network
  refresh resolves (offline/stale support).
- No DataStore writes here; session/CSRF persistence is handled by the shared cookie
  jar.

## 7. Error Handling & Resilience

- Dev host is unreliable plaintext HTTP: OkHttp call timeout ~20s. The deal GET retries
  with bounded backoff (3 attempts, 1s→2s→4s) since it is idempotent; accept/decline/
  counter POSTs are **never** auto-retried (avoids duplicate state changes — a
  double-accept or double-counter).
- Single-flight: `inFlight` disables all action buttons while a mutation runs; the
  confirmation dialog/sheet is dismissed only after the result resolves.
- `409 not actionable`: treat as a soft conflict — refresh the deal, surface a brief
  inline notice ("This deal was updated"), and re-render with the server's current
  status and recomputed actions rather than a hard error.
- Initial-load failures show `Error(retryable=true)` with a Retry button for
  network/timeout/5xx; `retryable=false` for `403`/`404` (not a party / deal gone).
- If refresh after an action fails but the action's response body carried the updated
  deal, apply that body; if neither is available keep the cached deal with a stale
  banner.

## 8. Security & Privacy

- All calls use the existing authenticated session (bearer token + session cookie) +
  `X-CSRF-Token` (verified `src/api/client.ts`); accept, reject, and counter are
  state-changing and must include the CSRF header (enforced by the shared OkHttp
  interceptor). No cookies or tokens are logged or persisted by this feature.
- Deal terms (amounts, counterparty identity, messages) are user/partner business data:
  the Room `deal` table is the only at-rest store and lives in app-private storage;
  payload JSON is never written to logs.
- Action eligibility is enforced server-side; client gating (`availableActions`) is UX
  only and never the security boundary. A user who is not a party is expected to receive
  `403` (not documented in OpenAPI — see §16) and the client treats it as a
  non-retryable error.
- Free-text fields (reject `reason`, counter `note`) are sent verbatim to the API; they
  are not echoed into logs or analytics.

## 9. Accessibility & i18n

- All strings in `feature-sponsorship/src/main/res/values/strings.xml`; no hardcoded
  user text. Accept/Decline/Negotiate buttons, the counter form fields, and the
  confirmation dialogs have `contentDescription`/`semantics` labels.
- Amounts (`compensation_cents` and `payment_details`) are USD cents formatted via
  `NumberFormat.getCurrencyInstance` with `Currency.getInstance("USD")` — never
  string-concatenated (the deal has no per-deal `currency` field). The `deadline`
  (`YYYY-MM-DD`) and epoch-second timestamps are rendered via a localized date
  formatter, not raw strings.
- The status chip conveys state by text + icon, not color alone. The event-history
  timeline items are individually focusable with a spoken summary derived from
  `event_type` + `actor_sub` + date (e.g. "Countered by user_cr_2, Jun 4").
- Minimum 48dp touch targets; the action bar supports dynamic font scaling and dark
  theme via Material 3 tokens; the counter `ModalBottomSheet` traps focus and is
  dismissible via the accessibility back action.

## 10. Telemetry & Logging

- Analytics events via the shared analytics abstraction: `deal_detail_view`
  (deal_id, status, role), `deal_action_submit` (deal_id, action), and the
  result events `deal_accept_success` / `deal_reject_success` /
  `deal_counter_success` (deal_id, new_status) and `deal_action_failure`
  (deal_id, action, error_code). (`role` is the client-derived advertiser/creator role,
  since the deal carries no `viewer_role` field.)
- No deal monetary amounts, counterparty PII, or free-text reasons/messages in any
  event — only deal_id, action, status, and mapped error codes.
- Diagnostic logging through the project logger at DEBUG for request/response status
  codes only (no bodies); errors logged at WARN with the mapped error code, never the
  raw `detail` (which may contain user input).

## 11. Testing Strategy

Unit (JVM, `core-testing` + Turbine + MockWebServer):

- `DealDetailViewModelTest` — Loading → Detail on successful load (deal + history);
  `availableActions` computed correctly per status (`proposed`/`negotiating` → all
  three; `accepted`/`content_submitted`/`completed`/`rejected`/`cancelled` → none);
  `onAccept` sets `inFlight=ACCEPT`, disables others, then Detail with `accepted`;
  `onReject(reason)` posts `{reason}` and transitions to `rejected`; `onSubmitCounter`
  posts `{compensation_cents, note}` and transitions to `negotiating`; `inlineError` on
  422; defensive `409` triggers refresh and re-render; `Error(retryable)` on timeout.
  Assert all action buttons disabled while `inFlight != null`.
- `AvailableActionsTest` — table-driven coverage of the pure `availableActionsFor`
  helper across every `DealStatus`.
- `SponsorshipRepositoryDealTest` — MockWebServer: GET maps `DealDto`→`Deal` and
  `/history` maps `DealEventDto[]`→domain; accept/reject/counter map the returned deal;
  FastAPI `422` `detail` variants map to `ApiResult.Error`; Room upsert occurs on every
  success; POSTs are not retried on 5xx; GETs are retried with bounded backoff.
- `DealDtoTest` — Moshi round-trip incl. null `content_id`/`payment_details`/
  `cancel_reason`, epoch-second timestamps parsed as `Long`, and unknown `status` →
  `DealStatus.UNKNOWN`.

Instrumented/Compose (`feature-sponsorship` androidTest):

- `DealDetailScreenTest` — Loading/Error/Detail render; action bar hidden for
  terminal/non-actionable status and shown for `proposed`/`negotiating`; Accept opens
  confirm dialog and shows spinner on confirm; Reject reason dialog; Negotiate opens
  counter sheet pre-filled with current `compensation_cents` and disables submit when
  compensation is below the 1000-cent minimum. Accessibility assertions on labels and
  the status chip.

Coverage gate: ViewModel + repository (deal paths) ≥ 80% line coverage.

## 12. Dependencies & Sequencing

- **AND-365 (Sponsorship list/inbox)** — required: supplies the `Deal`/`DealStatus`
  model, `SponsorshipApi`/`SponsorshipRepository`, the `feature-sponsorship` module,
  and the list-row navigation into `deal/{dealId}`. Must merge first.
- Implicit infra (assumed present): cookie jar + CSRF interceptor + session refresh,
  shared `ApiResult` and FastAPI `detail` error mapper, the `StateFlow<UiState>` +
  submit/result-mapping ViewModel convention, and the analytics abstraction.
- This ticket **blocks**: none recorded in backlog.
- Build order: AND-365 model/api/repo → add `getDeal`/`getDealHistory`/`acceptDeal`/
  `rejectDeal`/`counterDeal` to `SponsorshipApi` + `SponsorshipRepository` (+ Room deal
  cache) → `DealDetailViewModel` → `DealDetailScreen`/route → wire list-row + deep-link
  navigation.

## 13. Risks & Open Questions

- R1. RESOLVED in this review: endpoint paths and request/response shapes are now
  confirmed against the OpenAPI index and web reference — base
  `/ui/ads/sponsorships/{deal_id}`, actions `accept`/`reject`/`counter`, history at
  `/history`, and the `SponsorshipDeal`/`SponsorshipDealEvent` field names. Remaining:
  confirm DTO parsing against a live payload (DTO unit tests still gate this).
- R2. Per the web client every action endpoint returns the full updated `SponsorshipDeal`
  (`api.post<SponsorshipDeal>` in `sponsorshipDeals.ts`), so the ViewModel applies the
  returned body directly; a follow-up `getDeal`/`getDealHistory` refresh is only needed
  for the history feed (history is not embedded in the deal).
- R3. Counter constraints CONFIRMED from `SponsorshipCounterRequest`:
  `compensation_cents` is an optional integer with a 1000-cent minimum; `note` optional,
  maxLength 2000. There is no deliverables edit and no currency field on the counter
  (USD only). Form validates `compensation_cents >= 1000`.
- R4. Concurrency: a `409`-style "not actionable" conflict is plausible at runtime but
  is NOT documented in OpenAPI (only `422` is) — see §16. The exact conflict body/code
  is unverified; the client handles `409` defensively. **Cancel** is a real but separate
  endpoint (`POST /ui/ads/sponsorships/{deal_id}/cancel`, `SponsorshipCancelRequest`)
  and remains out of scope for this ticket (follow-up). Note: `submit-content` and
  `complete` endpoints also exist and are out of scope here.
- R5. Dev host instability may make detail loads flaky; tests use MockWebServer, not
  the live host.

## 14. Acceptance Criteria

AC-1 (from backlog: "Deal actions work" + "deal detail"): opening `deal/{dealId}`
loads and renders the full deal — parties, terms, status — from
`GET /ui/ads/sponsorships/{deal_id}`, plus the event history from
`GET /ui/ads/sponsorships/{deal_id}/history`.
*(DealDetailViewModelTest + DealDetailScreenTest.)*

AC-2: Accept issues `POST /ui/ads/sponsorships/{deal_id}/accept` (no body) after a
confirmation dialog and, on success, the deal shows `accepted` and the action bar hides.

AC-3: Reject (backlog "decline") issues `POST /ui/ads/sponsorships/{deal_id}/reject`
(with optional `reason`) and the deal shows `rejected` on success.

AC-4: Negotiate opens a counter form pre-filled with current compensation; submitting
issues `POST /ui/ads/sponsorships/{deal_id}/counter` with `{compensation_cents, note}`
and on success the deal shows `negotiating`, a new event appears in `/history`, and
available actions recompute.

AC-5: Available actions are correctly derived from status — shown only for
`proposed`/`negotiating`, hidden for `accepted`/`content_submitted`/`completed`/
`rejected`/`cancelled`.

AC-6: While an action is in flight all action buttons are disabled (no double-act), and
no action POST is auto-retried; a (defensive) `409` refreshes the deal and re-renders
with the server's current status.

AC-7: A previously viewed deal reopened at `deal/{dealId}` shows the cached deal from
Room before the network refresh; a failed refresh shows a stale banner over cached data.

AC-8: State transitions (loading/disabled, accept/reject/counter success, error
variants 422 plus defensively-handled 409/403/timeout) are covered by unit tests.

## 15. Definition of Done

- `DealDetailViewModel`, `DealDetailScreen`/`DealDetailRoute`, and the
  `deal/{dealId}` navigation entry implemented in `feature-sponsorship` using
  `com.testlogon.android` packaging, with list-row and deep-link entry wired.
- `SponsorshipApi` extended with `getDeal`/`getDealHistory`/`acceptDeal`/`rejectDeal`/
  `counterDeal`; `SponsorshipRepository` extended with the matching suspend functions
  (+ Room deal cache).
- Moshi DTOs map the real `/ui/ads/sponsorships/*` payloads (verified against OpenAPI +
  web types); FastAPI `detail` errors mapped via the shared mapper; mutations are not
  auto-retried and the GETs use bounded backoff.
- All user strings externalized; accessibility labels, status-chip text+icon, currency
  and date formatting in place.
- Unit + Compose tests green; ViewModel/repository (deal paths) ≥ 80% line coverage;
  analytics events emitted with no monetary/PII/free-text payloads.
- `./gradlew :feature-sponsorship:detekt :feature-sponsorship:testDebugUnitTest
  :feature-sponsorship:connectedDebugAndroidTest` pass on CI; ktlint/detekt clean.
- Code reviewed and merged to `android-port`; open questions in §13 either resolved or
  filed as follow-up tickets.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (components.schemas.<Name>); frontend paths are under
`reference/src/`.

1. **Deal endpoints live under `/ui/ads/sponsorships/...`** — CORRECTED (draft said
   `/ui/sponsorship/deals/...`). Source: OpenAPI index lines 866–877; frontend
   `src/api/endpoints/sponsorshipDeals.ts` (`const BASE = "/ui/ads/sponsorships"`).
2. **Get deal: `GET /ui/ads/sponsorships/{deal_id}`** — Verified. Source: OpenAPI index
   `GET /ui/ads/sponsorships/{deal_id}` (op `get_deal_endpoint_...`);
   `src/api/endpoints/sponsorshipDeals.ts: getSponsorshipDeal`.
3. **History is a separate endpoint `GET /ui/ads/sponsorships/{deal_id}/history`
   returning `SponsorshipDealEvent[]`** — CORRECTED (draft embedded an `offers[]` array
   in the deal). Source: OpenAPI index `GET /ui/ads/sponsorships/{deal_id}/history`;
   `src/api/endpoints/sponsorshipDeals.ts: getSponsorshipDealHistory`;
   `src/api/types.ts: SponsorshipDealEvent`.
4. **Accept: `POST /ui/ads/sponsorships/{deal_id}/accept`, no body, returns updated
   deal** — Verified (path corrected). Source: OpenAPI index
   `POST /ui/ads/sponsorships/{deal_id}/accept` (`req=` empty);
   `src/api/endpoints/sponsorshipDeals.ts: acceptSponsorshipDeal`.
5. **Action is `reject`, not `decline`: `POST /ui/ads/sponsorships/{deal_id}/reject`
   with `SponsorshipRejectRequest`** — CORRECTED. Source: OpenAPI index
   `POST /ui/ads/sponsorships/{deal_id}/reject`; schema
   `components.schemas.SponsorshipRejectRequest` (`reason`, default `""`, maxLength 500);
   `src/api/endpoints/sponsorshipDeals.ts: rejectSponsorshipDeal`. No `decline` path
   exists in the index.
6. **Counter body is `{compensation_cents?: int>=1000, note?: string<=2000}`** —
   CORRECTED (draft used `{amount_minor, currency, deliverables, message}`). Source:
   schema `components.schemas.SponsorshipCounterRequest`;
   `src/api/endpoints/sponsorshipDeals.ts: counterSponsorshipDeal`.
7. **Deal fields: `deal_id, advertiser_account_id, advertiser_sub, creator_sub,
   content_type, brief, deliverables[], compensation_cents, cpm_bonus_cents,
   platform_commission_bps, status, deadline, content_id?, dm_conversation_id?,
   escrow_hold_id?, created_at, updated_at, completed_at?, cancelled_at?, cancel_reason?,
   payment_details?`** — CORRECTED (draft had `viewer_role`, `counterparty`,
   `amount_minor`, `currency`, `starts_at`/`ends_at`, `offers[]`). Source:
   `src/api/types.ts: SponsorshipDeal`; rendered fields confirmed in
   `src/pages/ads/SponsorshipDealDetail.tsx`.
8. **`created_at`/`updated_at` are numeric epoch seconds, not ISO strings** — CORRECTED.
   Source: `src/api/types.ts: SponsorshipDeal` (`created_at: number`).
9. **No per-deal `currency`; amounts are USD cents (`compensation_cents`)** — CORRECTED.
   Source: `src/api/types.ts` (no currency field); `SponsorshipDealDetail.tsx:
   formatCents` divides by 100 with a `$` prefix.
10. **Status enum: `proposed | negotiating | accepted | content_submitted | completed |
    rejected | cancelled`** — CORRECTED (draft: `pending/offered/countered/declined/
    expired/...`). Source: `src/api/types.ts: SponsorshipDealStatus`.
11. **Actionable states for accept/reject/counter are `proposed` and `negotiating`** —
    Verified/Corrected. Source: `src/pages/ads/SponsorshipInbox.tsx` (Accept/Reject
    buttons render when `status === "proposed" || "negotiating"`).
12. **No `viewer_role` / `authored_by_viewer`; role derived from `advertiser_sub` vs
    `creator_sub`** — CORRECTED. Source: `src/api/types.ts: SponsorshipDeal` (no such
    fields); `SponsorshipInbox.tsx` lists with `role: "creator"`,
    `SponsorshipManager.tsx` with `role: "advertiser"`.
13. **`role` query param values are `advertiser` / `creator`** — Verified (draft used
    "sponsor"). Source: `listSponsorshipDeals({ role: "advertiser" | "creator" })` in
    `sponsorshipDeals.ts`; usages in `SponsorshipManager.tsx` / `SponsorshipInbox.tsx`.
14. **Auth: bearer token + session cookie + `X-CSRF-Token` (from `ui_csrf` cookie);
    single 401 → `POST /ui/session/refresh` → retry** — Verified. Source:
    `src/api/client.ts` (`Authorization: Bearer`, `getCookie("ui_csrf")` →
    `X-CSRF-Token`, `refreshSession()` on 401). OpenAPI index additionally lists
    `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` params on these endpoints.
15. **FastAPI `detail` shapes: string | `[{msg}]` | `{code,...}`** — Verified. Source:
    `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`.
16. **Only documented error response for these endpoints is `422 HTTPValidationError`**
    — Verified. Source: OpenAPI index lines 870–875 (`resp=200:;422:HTTPValidationError`
    for every sponsorship path; no 409/403/404 listed).
17. **Action endpoints return the full updated `SponsorshipDeal`** — Verified. Source:
    `sponsorshipDeals.ts` (all action helpers typed `api.post<SponsorshipDeal>`).
18. **`payment_details` fields: `total_cents, commission_cents, creator_cents,
    advertiser_cents` (all optional)** — Verified. Source:
    `src/api/types.ts: SponsorshipPaymentDetails`; rendered in `SponsorshipDealDetail.tsx`.
19. **Counter minimum `compensation_cents` is 1000** — Verified. Source:
    `components.schemas.SponsorshipCounterRequest.compensation_cents.anyOf[0].minimum =
    1000`.
20. **Framework choices (Compose/Material 3, Navigation-Compose, Hilt, Retrofit/OkHttp/
    Moshi, Room, `NumberFormat.getCurrencyInstance`)** — Unverified-assumption (project
    convention, not derived from the web app). framework ref:
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/reference/java/text/NumberFormat#getCurrencyInstance() .

### Corrections made

- Endpoint base path `/ui/sponsorship/deals/{dealId}` → `/ui/ads/sponsorships/{deal_id}`
  across §1–§6, §13–§15 (claims 1–4).
- Action `decline` → `reject` (path, DTO, ViewModel method, enum value, telemetry, ACs)
  (claim 5).
- Counter request body `{amount_minor, currency, deliverables, message}` →
  `{compensation_cents?, note?}` with the 1000-cent minimum (claims 6, 19).
- Deal DTO/field set rewritten to the real `SponsorshipDeal` shape; removed
  `viewer_role`, `counterparty`, `amount_minor`, `currency`, `starts_at`/`ends_at`, and
  embedded `offers[]`; added `advertiser_sub`/`creator_sub`/`compensation_cents`/
  `deadline`/`payment_details`/etc.; timestamps typed as epoch-second `Long`
  (claims 7, 8).
- Offer history modelled as a separate `/history` endpoint returning
  `SponsorshipDealEvent[]` (`DealEventDto`) rather than an embedded array (claim 3).
- Status enum corrected to the real seven values + `UNKNOWN`; actionable-state logic now
  keyed on `proposed`/`negotiating`; terminal set updated (claims 10, 11).
- Role derivation corrected (advertiser/creator from `*_sub` comparison); `role` query
  value "sponsor" → "advertiser"/"creator" (claims 12, 13).
- Currency formatting fixed to USD (no per-deal currency field) in §4/§9 (claim 9).
- Room entity replaced `viewerRole` with `advertiserSub`/`creatorSub`; timestamp renamed
  to epoch seconds.

### Open assumptions

- **`409` (deal no longer actionable) and `403` (not a party) behavior** — Unverifiable
  from the sources: the OpenAPI index documents only `422` for these endpoints (claim
  16). These codes are plausible runtime responses (FastAPI `HTTPException`) but are not
  in the contract; the client handles them defensively. Confirm against the live dev
  host before relying on them.
- **Whether the advertiser (vs creator) gets a distinct action set** — Unverifiable: the
  web UI only surfaces Accept/Reject/Counter to the creator inbox; the advertiser
  manager shows Cancel (out of scope). `availableActionsFor` currently returns the same
  set for both parties on `proposed`/`negotiating`; `currentUserSub` is threaded through
  so role-specific gating can be added once confirmed. Server remains authoritative.
- **Live deal GET response example** — The OpenAPI index lists no named 200 schema for
  `GET /ui/ads/sponsorships/{deal_id}`; the documented response shape is reconstructed
  from `src/api/types.ts: SponsorshipDeal`. The exact runtime JSON (nullable vs absent
  fields) is confirmed only by DTO unit tests against a captured payload.
- **Dev host reliability / 20s timeout / bounded-backoff numbers** — Unverifiable
  operational assumption carried from the ticket context; not derivable from the sources.
- **Stack/framework versions and Android module layering** — Unverified-assumption
  (project convention; framework ref only — see claim 20).

## 17. Test Plan

Test targets: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD
`test35` (x86_64, Android 15 / API 35); DEVICE = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). MockWebServer cases run
on JVM. Most Compose/instrumented cases run on EMU; cases below note where DEVICE is
required.

- **TC-AND-366-01** — Type: contract/MockWebServer (JVM). Target: `SponsorshipApi` +
  `SponsorshipRepository`. Preconditions: MockWebServer enqueues a `200`
  `SponsorshipDeal` JSON for `GET /ui/ads/sponsorships/{deal_id}` and a `200`
  `SponsorshipDealEvent[]` for `/history`. Steps: call `getDeal` then `getDealHistory`.
  Expected: requests hit exactly `ui/ads/sponsorships/{id}` and `.../history` with the
  CSRF header present; `DealDto`→`Deal` maps all fields incl. epoch-second timestamps;
  history maps to `List<DealEvent>`; Room upsert occurs. Traces: AC-1.

- **TC-AND-366-02** — Type: unit (JVM). Target: `availableActionsFor`. Preconditions:
  none. Steps: table-driven over all `DealStatus` values. Expected: `PROPOSED` and
  `NEGOTIATING` → `{ACCEPT, REJECT, NEGOTIATE}`; `ACCEPTED`, `CONTENT_SUBMITTED`,
  `COMPLETED`, `REJECTED`, `CANCELLED`, `UNKNOWN` → empty set. Traces: AC-5.

- **TC-AND-366-03** — Type: unit (JVM, Turbine). Target: `DealDetailViewModel.onAccept`.
  Preconditions: ViewModel in `Detail(proposed)`; repo `acceptDeal` returns
  `Deal(status=accepted)`. Steps: call `onAccept` and confirm. Expected: emits
  `inFlight=ACCEPT` (all action buttons disabled) then `Detail(accepted)` with empty
  `availableActions`; `acceptDeal` called exactly once (no retry). Traces: AC-2, AC-6.

- **TC-AND-366-04** — Type: contract/MockWebServer (JVM). Target: `rejectDeal`.
  Preconditions: MockWebServer returns `200` `Deal(status=rejected)`. Steps: call
  `rejectDeal(id, "Budget too low")`. Expected: `POST .../reject` with body
  `{"reason":"Budget too low"}`; null/empty reason serializes as `{"reason":""}`; result
  maps to `rejected`. Traces: AC-3.

- **TC-AND-366-05** — Type: contract/MockWebServer (JVM). Target: `counterDeal`.
  Preconditions: MockWebServer returns `200` `Deal(status=negotiating)`. Steps: call
  `counterDeal(id, CounterOfferRequest(compensationCents=300000, note="Can do"))`.
  Expected: `POST .../counter` body is exactly `{"compensation_cents":300000,
  "note":"Can do"}` (no `currency`/`deliverables`/`message`); result maps to
  `negotiating`. Traces: AC-4.

- **TC-AND-366-06** — Type: unit (JVM). Target: `DealDetailViewModel.onSubmitCounter`
  validation. Preconditions: counter sheet open. Steps: set `compensationCents=500`
  (< 1000), attempt submit; then set `1000` and submit. Expected: `canSubmit=false` and
  no network call at 500; submit fires once at 1000. Traces: AC-4, AC-8.

- **TC-AND-366-07** — Type: contract/MockWebServer (JVM). Target: error mapping on
  counter. Preconditions: MockWebServer returns `422` with
  `{"detail":[{"loc":["body","compensation_cents"],"msg":"ensure this value is greater
  than or equal to 1000","type":"value_error"}]}`. Steps: submit counter. Expected:
  `ApiResult.Error` with the mapped `msg`; ViewModel surfaces it as `inlineError` on the
  form, deal status unchanged, no retry. Traces: AC-8.

- **TC-AND-366-08** — Type: unit (JVM, Turbine). Target: defensive `409` handling.
  Preconditions: `acceptDeal` returns `409`; a follow-up `getDeal` returns
  `Deal(status=rejected)` (counterparty already acted). Steps: call `onAccept`. Expected:
  no crash; ViewModel triggers a refresh, shows an inline "this deal changed" notice, and
  re-renders with `rejected` and recomputed (empty) actions; accept POST not retried.
  Traces: AC-6, AC-8.

- **TC-AND-366-09** — Type: contract/MockWebServer (JVM). Target: retry policy.
  Preconditions: GET fails twice with `503` then `200`; a POST returns `503` once.
  Steps: call `getDeal`, then `acceptDeal`. Expected: GET retried with bounded backoff
  (≤3 attempts) and ultimately succeeds; POST is NOT retried and returns
  `ApiResult.Error`. Traces: AC-6.

- **TC-AND-366-10** — Type: integration (JVM/Robolectric, Room). Target: offline/stale
  cache. Preconditions: a deal row exists in Room; network refresh fails (timeout).
  Steps: open `deal/{dealId}`. Expected: cached deal renders immediately from
  `observeDeal`, then `stale=true` sets a "couldn't refresh" banner over cached data; no
  data loss. Traces: AC-7.

- **TC-AND-366-11** — Type: Compose-UI (EMU). Target: `DealDetailScreen`. Preconditions:
  fake state `Detail(proposed)`. Steps: render. Expected: action bar shows Accept /
  Reject / Negotiate; tapping Accept opens an `AlertDialog`, confirming shows a spinner
  and disables all buttons; Negotiate opens the `ModalBottomSheet` pre-filled with the
  current compensation. Traces: AC-2, AC-4, AC-6.

- **TC-AND-366-12** — Type: Compose-UI (EMU). Target: `DealDetailScreen` terminal state.
  Preconditions: fake state `Detail(completed)`. Steps: render. Expected: no action bar;
  read-only status banner; status chip shows text + icon (not color alone). Traces: AC-5.

- **TC-AND-366-13** — Type: Compose-UI accessibility (EMU). Target: `DealDetailScreen`.
  Preconditions: `Detail(proposed)` with one history event. Steps: run semantics/TalkBack
  assertions. Expected: Accept/Reject/Negotiate and form fields have content
  descriptions; status chip has a text label; each history item is focusable with a
  spoken summary (event type + actor + date); touch targets ≥ 48dp; amount announced as
  localized USD currency. Traces: AC-1, AC-5.

- **TC-AND-366-14** — Type: manual / instrumented e2e (DEVICE — physical A15 5G).
  Target: full flow against the live dev host. Preconditions: signed-in session with
  valid CSRF cookie; a real `proposed` deal where the device user is a party; deep-link
  `deal/{dealId}` (e.g. from a notification tap). Steps: open the deal, Accept (or
  Counter), observe the result; toggle airplane mode mid-flow to exercise the flaky-host/
  offline path. MUST run on DEVICE because it validates real notification-tap deep entry,
  real network/CSRF behavior against the unreliable plaintext dev host, and arm64 / API
  34 behavior the x86 emulator does not. Expected: action succeeds and the screen
  reflects the server status; offline mid-flow shows the stale banner and no double
  action; no token/CSRF leakage in logcat. Traces: AC-1, AC-2, AC-4, AC-6, AC-7.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (load deal + history) | TC-01, TC-13, TC-14 |
| AC-2 (accept) | TC-03, TC-11, TC-14 |
| AC-3 (reject) | TC-04 |
| AC-4 (counter) | TC-05, TC-06, TC-11, TC-14 |
| AC-5 (action availability) | TC-02, TC-12, TC-13 |
| AC-6 (single-flight, no-retry, 409 refresh) | TC-03, TC-08, TC-09, TC-11, TC-14 |
| AC-7 (cached/stale) | TC-10, TC-14 |
| AC-8 (state transitions + error variants) | TC-06, TC-07, TC-08 |
