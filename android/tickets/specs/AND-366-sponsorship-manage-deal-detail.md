---
id: AND-366
title: Sponsorship manage / deal detail
milestone: M8
epic: E47
priority: P2
size: L
status: draft
depends_on: [AND-365]
blocks: []
---

# AND-366 — Sponsorship manage / deal detail

## 1. Overview & Goal

Provide a signed-in user (creator or sponsor) with a **deal detail** screen for a
single sponsorship deal, plus the three management **actions** the backlog requires:
**accept**, **decline**, and **negotiate** (counter-offer). The screen opens from the
sponsorship list/inbox delivered by AND-365, loads the full deal — parties, brief,
terms (amount, deliverables, timeline), current `status`, and the negotiation/offer
history — and lets the user act on a deal that is in an actionable state. Accepting or
declining is a single confirmed mutation; negotiating opens a counter-offer form (new
amount, deliverables, optional message) that submits a counter and refreshes the deal.

After any action the screen must immediately reflect the deal's new server-returned
`status` (`pending`, `offered`, `countered`, `accepted`, `declined`, `expired`,
`cancelled`, `completed`) and update which actions are available. Actions are
**non-idempotent POSTs** and must never be auto-retried; the deal load/refresh is an
idempotent GET that may be retried with bounded backoff.

This is the Android port of the web reference deal-management behavior. It builds on
AND-365, which delivers the sponsorship list, the `Deal`/`DealStatus` model, the
`SponsorshipApi`/`SponsorshipRepository`, and navigation into this detail route.

**Done means:** the deal detail screen renders a real deal and its history; accept,
decline, and negotiate each issue the correct POST, succeed against the dev backend,
and the screen reflects the returned status and recomputed available actions; state
transitions are unit-tested.

## 2. Context & References

- Predecessor ticket (required): **AND-365** — sponsorship list/inbox, `Deal` and
  `DealStatus` in `core-model`, `SponsorshipApi`/`SponsorshipRepository` in
  `core-data`, and the navigation entry that routes into `deal/{dealId}`.
- ViewModel/state + result-mapping pattern: established `StateFlow<UiState>` + submit
  handler + `ApiResult` mapping convention (same convention referenced across the M8
  feature tickets, e.g. AND-364 `BoostViewModel`).
- Web reference app (`frontend/`): sponsorship API layer under
  `frontend/src/api/endpoints/` (sponsorship/deals module) and shared types in
  `frontend/src/api/types.ts` (`Deal`, `DealOffer`, `DealStatus`,
  `CounterOfferRequest`). Use as the source of truth for field names pending OpenAPI
  confirmation.
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
`dealId`.

FR-2. Load: the detail screen loads the full deal via `GET /ui/sponsorship/deals/{dealId}`,
including parties (counterparty name/avatar/role), brief/description, current terms
(amount in minor units + currency, deliverables list, timeline/dates), `status`, and
the ordered **offer history** (`offers[]`, each with author, amount, deliverables,
message, timestamp, kind `offer|counter|accept|decline`).

FR-3. Action availability is derived from `status` **and** the viewer's role
(`viewerRole` returned by the API). Rules:
- `accept` and `decline` are available only when the deal is in an actionable state
  for the viewer (`offered` or `countered` and the latest offer was authored by the
  **other** party).
- `negotiate` (counter) is available in the same actionable states.
- Terminal states (`accepted`, `declined`, `expired`, `cancelled`, `completed`) expose
  **no** actions; the screen is read-only with a status banner.
The client gating is UX only; the server is authoritative and may still reject.

FR-4. Accept: tapping "Accept" shows a confirmation dialog; confirming calls
`POST /ui/sponsorship/deals/{dealId}/accept`. On success the deal transitions to
`accepted` and actions hide.

FR-5. Decline: tapping "Decline" shows a confirmation dialog with an optional reason
field; confirming calls `POST /ui/sponsorship/deals/{dealId}/decline` with the reason.
On success the deal transitions to `declined`.

FR-6. Negotiate: tapping "Negotiate" opens a counter-offer form pre-filled with the
current terms. The user edits amount (minor units), deliverables, and an optional
message, then submits `POST /ui/sponsorship/deals/{dealId}/counter`. On success the
deal transitions to `countered`, the new offer is appended to history, and action
availability recomputes (now the counterparty must respond).

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
enum class DealAction { ACCEPT, DECLINE, NEGOTIATE }

data class DealDetailContent(
    val deal: Deal,                       // from core-model (AND-365)
    val availableActions: Set<DealAction>,
    val inFlight: DealAction? = null,     // non-null while a mutation runs
    val stale: Boolean = false,           // cached shown, refresh failed
    val inlineError: String? = null,      // last action error, dismissible
)

data class CounterFormState(
    val amountMinor: Long,
    val currency: String,
    val deliverables: List<String>,
    val message: String = "",
    val submitting: Boolean = false,
    val inlineError: String? = null,
) {
    val canSubmit: Boolean get() =
        !submitting && amountMinor > 0 && deliverables.isNotEmpty()
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
    fun onDecline(reason: String?)                   // confirm -> POST .../decline
    fun onOpenNegotiate()                            // seed CounterFormState from deal
    fun onCounterAmountChange(minor: Long)
    fun onCounterDeliverablesChange(items: List<String>)
    fun onCounterMessageChange(text: String)
    fun onSubmitCounter()                            // POST .../counter
    fun onDismissCounter()
    fun onDismissInlineError()
}
```

Available actions are computed by a pure helper so it is directly unit-testable:

```kotlin
internal fun availableActionsFor(deal: Deal): Set<DealAction> = when (deal.status) {
    DealStatus.OFFERED, DealStatus.COUNTERED ->
        if (deal.latestOffer?.authoredByViewer == false)
            setOf(DealAction.ACCEPT, DealAction.DECLINE, DealAction.NEGOTIATE)
        else emptySet()
    else -> emptySet()   // pending/accepted/declined/expired/cancelled/completed
}
```

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
    suspend fun acceptDeal(dealId: String): ApiResult<Deal>          // POST, no retry
    suspend fun declineDeal(dealId: String, reason: String?): ApiResult<Deal>
    suspend fun counterDeal(dealId: String, request: CounterOfferRequest): ApiResult<Deal>
}
```

The route reads `observeDeal(dealId)` first (cached) then triggers `getDeal` to
refresh; every successful GET or action response upserts the Room entity.

**Compose** `DealDetailScreen` renders Loading / Error(retry) / Detail. Detail shows a
counterparty header, status chip (text + icon, not color alone), terms card
(amount via `NumberFormat.getCurrencyInstance` keyed on `currency`, deliverables,
timeline), an offer-history timeline (most recent first), and an action bar
(`Accept` / `Decline` / `Negotiate`) shown only when `availableActions` is non-empty.
Accept and decline open `AlertDialog` confirmations; negotiate opens a `ModalBottomSheet`
backed by `CounterFormState`.

## 5. API Contract

All paths are relative to dev base `http://18.222.237.167:8000`. Cookie-based auth
applies: requests carry the session + `ui_csrf` cookie echoed as `X-CSRF-Token`; on
401 the shared OkHttp authenticator calls `POST /ui/session/refresh` once then retries
(shared infra, not built here). The three action endpoints are **state-changing POSTs**
and must carry the CSRF header and must NOT be auto-retried. Only the GET is retried.

**Get deal** — `GET /ui/sponsorship/deals/{dealId}` (idempotent; ~20s timeout, bounded
backoff retry)

Response `200`:
```json
{
  "deal_id": "deal_7a2",
  "status": "offered",
  "viewer_role": "creator",
  "counterparty": { "id": "org_19", "name": "Acme Co", "role": "sponsor", "avatar_url": null },
  "brief": "Sponsored 60s video on new launch",
  "amount_minor": 250000,
  "currency": "USD",
  "deliverables": ["1x YouTube video", "2x story posts"],
  "starts_at": "2026-07-01",
  "ends_at": "2026-07-31",
  "offers": [
    {
      "offer_id": "off_1",
      "kind": "offer",
      "author_role": "sponsor",
      "authored_by_viewer": false,
      "amount_minor": 250000,
      "currency": "USD",
      "deliverables": ["1x YouTube video", "2x story posts"],
      "message": "Excited to work with you",
      "created_at": "2026-06-04T10:00:00Z"
    }
  ],
  "updated_at": "2026-06-04T10:00:00Z"
}
```

**Accept** — `POST /ui/sponsorship/deals/{dealId}/accept` (no body) → updated `Deal`
(`status: "accepted"`).

**Decline** — `POST /ui/sponsorship/deals/{dealId}/decline`
```json
{ "reason": "Budget too low" }
```
→ updated `Deal` (`status: "declined"`). `reason` optional/nullable.

**Counter** — `POST /ui/sponsorship/deals/{dealId}/counter`
```json
{
  "amount_minor": 300000,
  "currency": "USD",
  "deliverables": ["1x YouTube video", "1x story post"],
  "message": "Can do at this rate"
}
```
→ updated `Deal` (`status: "countered"`, new entry appended to `offers`).

**Moshi DTOs** (in `core-model`; `DealDto`/`DealStatus` introduced by AND-365 — extend
only if fields are missing):

```kotlin
@JsonClass(generateAdapter = true)
data class DealDto(
    @Json(name = "deal_id") val dealId: String,
    val status: String,
    @Json(name = "viewer_role") val viewerRole: String,
    val counterparty: PartyDto,
    val brief: String?,
    @Json(name = "amount_minor") val amountMinor: Long,
    val currency: String,
    val deliverables: List<String>,
    @Json(name = "starts_at") val startsAt: String?,
    @Json(name = "ends_at") val endsAt: String?,
    val offers: List<DealOfferDto>,
    @Json(name = "updated_at") val updatedAt: String,
)

@JsonClass(generateAdapter = true)
data class DealOfferDto(
    @Json(name = "offer_id") val offerId: String,
    val kind: String,                                  // offer|counter|accept|decline
    @Json(name = "author_role") val authorRole: String,
    @Json(name = "authored_by_viewer") val authoredByViewer: Boolean,
    @Json(name = "amount_minor") val amountMinor: Long?,
    val currency: String?,
    val deliverables: List<String>?,
    val message: String?,
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class DeclineRequestDto(val reason: String?)

@JsonClass(generateAdapter = true)
data class CounterOfferRequestDto(
    @Json(name = "amount_minor") val amountMinor: Long,
    val currency: String,
    val deliverables: List<String>,
    val message: String?,
)
```

`status` maps to
`enum class DealStatus { PENDING, OFFERED, COUNTERED, ACCEPTED, DECLINED, EXPIRED, CANCELLED, COMPLETED, UNKNOWN }`
with `UNKNOWN` for forward-compatible unrecognized values.

**Retrofit**

```kotlin
interface SponsorshipApi {
    // ...from AND-365 (list)
    @GET("ui/sponsorship/deals/{dealId}")
    suspend fun getDeal(@Path("dealId") dealId: String): Response<DealDto>

    @POST("ui/sponsorship/deals/{dealId}/accept")
    suspend fun acceptDeal(@Path("dealId") dealId: String): Response<DealDto>

    @POST("ui/sponsorship/deals/{dealId}/decline")
    suspend fun declineDeal(
        @Path("dealId") dealId: String,
        @Body body: DeclineRequestDto,
    ): Response<DealDto>

    @POST("ui/sponsorship/deals/{dealId}/counter")
    suspend fun counterDeal(
        @Path("dealId") dealId: String,
        @Body body: CounterOfferRequestDto,
    ): Response<DealDto>
}
```

**Error mapping:** FastAPI `detail` is parsed via the shared mapper (string |
`[{msg}]` | `{code,...}`) into `ApiResult.Error`. Expected failures: `409` deal no
longer in an actionable state (e.g. counterparty already acted) → refresh deal and show
inline "this deal changed" then re-render with new status; `422` validation on counter
(amount/deliverables) → inline form error; `403` viewer not a party → `Error(retryable=false)`.

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
    val viewerRole: String,
    val payloadJson: String,        // full Deal JSON for offline render
    val updatedAtEpochMs: Long,
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

- All calls use the existing authenticated cookie session + `X-CSRF-Token`; accept,
  decline, and counter are state-changing and must include the CSRF header (enforced by
  the shared OkHttp interceptor). No cookies or tokens are logged or persisted by this
  feature.
- Deal terms (amounts, counterparty identity, messages) are user/partner business data:
  the Room `deal` table is the only at-rest store and lives in app-private storage;
  payload JSON is never written to logs.
- Action eligibility is enforced server-side; client gating (`availableActions`) is UX
  only and never the security boundary. A user who is not a party receives `403` and a
  non-retryable error.
- Free-text fields (decline `reason`, counter `message`) are sent verbatim to the API;
  they are not echoed into logs or analytics.

## 9. Accessibility & i18n

- All strings in `feature-sponsorship/src/main/res/values/strings.xml`; no hardcoded
  user text. Accept/Decline/Negotiate buttons, the counter form fields, and the
  confirmation dialogs have `contentDescription`/`semantics` labels.
- Amounts formatted via `NumberFormat.getCurrencyInstance(Locale, Currency)` keyed on
  the deal `currency` — never string-concatenated. Dates formatted via a localized
  date formatter, not raw ISO strings.
- The status chip conveys state by text + icon, not color alone. The offer-history
  timeline items are individually focusable with a spoken summary ("Counter from Acme
  Co, $3,000, Jun 4").
- Minimum 48dp touch targets; the action bar supports dynamic font scaling and dark
  theme via Material 3 tokens; the counter `ModalBottomSheet` traps focus and is
  dismissible via the accessibility back action.

## 10. Telemetry & Logging

- Analytics events via the shared analytics abstraction: `deal_detail_view`
  (deal_id, status, viewer_role), `deal_action_submit` (deal_id, action), and the
  result events `deal_accept_success` / `deal_decline_success` /
  `deal_counter_success` (deal_id, new_status) and `deal_action_failure`
  (deal_id, action, error_code).
- No deal monetary amounts, counterparty PII, or free-text reasons/messages in any
  event — only deal_id, action, status, and mapped error codes.
- Diagnostic logging through the project logger at DEBUG for request/response status
  codes only (no bodies); errors logged at WARN with the mapped error code, never the
  raw `detail` (which may contain user input).

## 11. Testing Strategy

Unit (JVM, `core-testing` + Turbine + MockWebServer):

- `DealDetailViewModelTest` — Loading → Detail on successful load; `availableActions`
  computed correctly per status × `authoredByViewer` (offered/countered by other party
  → all three; authored by viewer → none; terminal states → none); `onAccept` sets
  `inFlight=ACCEPT`, disables others, then Detail with `accepted`; `onDecline(reason)`
  posts reason and transitions to `declined`; `onSubmitCounter` posts and transitions
  to `countered` with appended offer; `inlineError` on 422; `409` triggers refresh and
  re-render; `Error(retryable)` on timeout. Assert all action buttons disabled while
  `inFlight != null`.
- `AvailableActionsTest` — table-driven coverage of the pure `availableActionsFor`
  helper across every `DealStatus` and both authorship cases.
- `SponsorshipRepositoryDealTest` — MockWebServer: GET maps `DealDto`→`Deal`; accept/
  decline/counter map the returned deal; FastAPI `detail` variants map to
  `ApiResult.Error`; Room upsert occurs on every success; POSTs are not retried on 5xx;
  GET is retried with bounded backoff.
- `DealDtoTest` — Moshi round-trip incl. null `brief`/`avatar_url`/`message`, empty/
  null offer fields, and unknown `status` → `DealStatus.UNKNOWN`.

Instrumented/Compose (`feature-sponsorship` androidTest):

- `DealDetailScreenTest` — Loading/Error/Detail render; action bar hidden for terminal
  status and shown for actionable status; Accept opens confirm dialog and shows spinner
  on confirm; Decline reason sheet; Negotiate opens counter sheet pre-filled with
  current terms and disables submit on empty deliverables. Accessibility assertions on
  labels and the status chip.

Coverage gate: ViewModel + repository (deal paths) ≥ 80% line coverage.

## 12. Dependencies & Sequencing

- **AND-365 (Sponsorship list/inbox)** — required: supplies the `Deal`/`DealStatus`
  model, `SponsorshipApi`/`SponsorshipRepository`, the `feature-sponsorship` module,
  and the list-row navigation into `deal/{dealId}`. Must merge first.
- Implicit infra (assumed present): cookie jar + CSRF interceptor + session refresh,
  shared `ApiResult` and FastAPI `detail` error mapper, the `StateFlow<UiState>` +
  submit/result-mapping ViewModel convention, and the analytics abstraction.
- This ticket **blocks**: none recorded in backlog.
- Build order: AND-365 model/api/repo → add action endpoints to `SponsorshipApi` +
  `SponsorshipRepository` (+ Room deal cache) → `DealDetailViewModel` →
  `DealDetailScreen`/route → wire list-row + deep-link navigation.

## 13. Risks & Open Questions

- R1. Exact action endpoint paths and request/response shapes are inferred from the web
  reference; confirm `/ui/sponsorship/deals/{dealId}/{accept|decline|counter}` and the
  `Deal`/`offers` field names against live `/openapi.json` before locking DTOs.
  *(Mitigation: DTO unit tests + a field-name review against OpenAPI.)*
- R2. Whether accept/decline/counter return the full updated `Deal` or just a status —
  if status-only, the ViewModel must follow with a `getDeal` refresh. Design supports
  both (apply body if a full deal is returned, else refresh).
- R3. Counter-offer constraints (min/max amount, allowed deliverable edits, whether
  `currency` is fixed by the deal) need confirmation; current form treats currency as
  fixed and validates `amount_minor > 0` + non-empty deliverables only.
- R4. Concurrency: if the counterparty acts between load and submit the backend returns
  `409`; the exact `409` body/code shape is provisional. Behavior for **cancel an
  outstanding offer** is out of scope (separate follow-up ticket).
- R5. Dev host instability may make detail loads flaky; tests use MockWebServer, not
  the live host.

## 14. Acceptance Criteria

AC-1 (from backlog: "Deal actions work" + "deal detail"): opening `deal/{dealId}`
loads and renders the full deal — counterparty, terms, status, and offer history —
from `GET /ui/sponsorship/deals/{dealId}`. *(DealDetailViewModelTest + DealDetailScreenTest.)*

AC-2: Accept issues `POST /ui/sponsorship/deals/{dealId}/accept` after a confirmation
dialog and, on success, the deal shows `accepted` and the action bar hides.

AC-3: Decline issues `POST /ui/sponsorship/deals/{dealId}/decline` (with optional
reason) and the deal shows `declined` on success.

AC-4: Negotiate opens a counter form pre-filled with current terms; submitting issues
`POST /ui/sponsorship/deals/{dealId}/counter` and on success the deal shows `countered`
with the new offer appended and recomputed available actions.

AC-5: Available actions are correctly derived from status and authorship — shown only
for actionable states authored by the other party, hidden for terminal states.

AC-6: While an action is in flight all action buttons are disabled (no double-act), and
no action POST is auto-retried; a `409` refreshes the deal and re-renders with the
server's current status.

AC-7: A previously viewed deal reopened at `deal/{dealId}` shows the cached deal from
Room before the network refresh; a failed refresh shows a stale banner over cached data.

AC-8: State transitions (loading/disabled, accept/decline/counter success, error
variants 409/422/403/timeout) are covered by unit tests.

## 15. Definition of Done

- `DealDetailViewModel`, `DealDetailScreen`/`DealDetailRoute`, and the
  `deal/{dealId}` navigation entry implemented in `feature-sponsorship` using
  `com.testlogon.android` packaging, with list-row and deep-link entry wired.
- `SponsorshipApi` extended with `getDeal`/`acceptDeal`/`declineDeal`/`counterDeal`;
  `SponsorshipRepository` extended with the matching suspend functions (+ Room deal
  cache).
- Moshi DTOs map the real `/ui/sponsorship/deals/*` payloads (verified against
  OpenAPI); FastAPI `detail` errors mapped via the shared mapper; mutations are not
  auto-retried and the GET uses bounded backoff.
- All user strings externalized; accessibility labels, status-chip text+icon, currency
  and date formatting in place.
- Unit + Compose tests green; ViewModel/repository (deal paths) ≥ 80% line coverage;
  analytics events emitted with no monetary/PII/free-text payloads.
- `./gradlew :feature-sponsorship:detekt :feature-sponsorship:testDebugUnitTest
  :feature-sponsorship:connectedDebugAndroidTest` pass on CI; ktlint/detekt clean.
- Code reviewed and merged to `android-port`; open questions in §13 either resolved or
  filed as follow-up tickets.
