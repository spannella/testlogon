---
id: AND-260
title: Payout history + status
milestone: M6
epic: E35
priority: P1
size: M
status: draft
depends_on: [AND-258]
blocks: []
---

# AND-260 — Payout history + status

## 1. Overview & Goal

Provide a read-only **Payout History** experience in the TestLogon native Android
app: a paged, reverse-chronological list of the authenticated user's payouts with
a clearly rendered **status** for each entry, plus a **Payout Detail** screen that
expands a single payout into its full breakdown (amount, currency, method,
timestamps, status transitions, and any failure reason).

This ticket owns the *consumption* of payout data. It does **not** own the
networking/DTO layer (that is AND-258, `payouts.ts` endpoints/DTOs ported to
`core-network`/`core-model`), nor payout-method configuration / KYC gating
(AND-259), nor bulk read views (AND-261). Goal: a user can open Payouts, scroll
their full history with correct status chips, tap any row, and see an accurate,
offline-tolerant detail view.

Success = History renders with statuses (the source acceptance bullet), backed by
Paging 3, Room-cached, and verified with unit + UI tests.

## 2. Context & References

- **Repo:** `spannella/testlogon`, branch `android-port`, app under `android/`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Feature module:** `feature-payouts` (shared with AND-258/259/261).
- **Web reference:** `frontend/src/api/endpoints/payouts.ts` (endpoint shapes),
  `frontend/src/api/types.ts` (`Payout`, `PayoutStatus`, `PayoutList`), and the
  web payout history view for status-label parity.
- **Backend:** FastAPI + DynamoDB, OpenAPI at `/openapi.json`; dev host
  `http://18.222.237.167:8000` (plaintext HTTP, unreliable — design for ~20s
  timeouts, bounded retry of idempotent GETs, offline/stale states).
- **Upstream dependency:** **AND-258** supplies `PayoutApi` (Retrofit interface),
  payout DTOs, and `ApiResult<T>` mapping. This ticket consumes them; if AND-258
  field names differ at integration, this spec's DTO names are adjusted to match
  AND-258 (AND-258 is authoritative for wire shapes).
- **Auth:** cookie-based session (`/ui/session/start` → MFA → `/ui/session/finalize`
  → `/ui/me`); `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 the shared OkHttp
  authenticator calls `POST /ui/session/refresh` once then retries. History GETs
  ride that shared client; this ticket adds no auth logic.

## 3. Functional Requirements

FR-1 — **History list.** Display payouts newest-first in a `LazyColumn` backed by
Paging 3. Each row shows: formatted amount + currency, payout method label
(e.g. "Bank ····4321"), the **status chip**, and a relative/absolute date
(`created_at` or `paid_at` when present).

FR-2 — **Statuses.** Map every backend status to a typed
`PayoutStatus` enum and render a color-coded chip with an icon and localized
label. Supported set: `PENDING`, `PROCESSING`, `PAID`, `FAILED`, `CANCELED`,
`ON_HOLD`. Any unknown wire value maps to `UNKNOWN` and renders neutrally
(must not crash).

FR-3 — **Pagination.** Infinite scroll via Paging 3 `PagingSource`/`RemoteMediator`
consuming the cursor/`next` token from AND-258. Append spinner at list end;
prepend/append error footer with retry.

FR-4 — **Detail.** Tapping a row navigates to `payouts/detail/{payoutId}` showing:
amount + fee + net, currency, method, status chip, `created_at`, `paid_at`,
estimated arrival (if provided), failure `reason`/`code` (if `FAILED`), and a
status-transition list when the API returns one.

FR-5 — **Empty / loading / error / offline states.** First-load shimmer;
distinct empty state ("No payouts yet"); full-screen error with retry on
first-page failure; stale banner when serving cached data while offline.

FR-6 — **Pull-to-refresh** invalidates the pager and refetches page 1.

FR-7 — **Read-only.** No create/cancel/edit actions in this ticket.

FR-8 — **Filter by status (optional, behind the same screen).** A status filter
chip-row that re-keys the pager. Ships only if AND-258 exposes a `status` query
param; otherwise deferred and noted in §13.

## 4. Technical Design

Module: `feature-payouts`. Layering `app -> feature-payouts -> core-*`. MVVM with
`StateFlow<UiState>`; networking/DTOs from AND-258 in `core-network`/`core-model`.

Navigation (single-Activity Navigation-Compose):

```kotlin
sealed interface PayoutRoute {
    @Serializable data object History : PayoutRoute
    @Serializable data class Detail(val payoutId: String) : PayoutRoute
}

fun NavGraphBuilder.payoutHistoryGraph(nav: NavController) {
    composable<PayoutRoute.History> {
        PayoutHistoryScreen(onPayoutClick = { nav.navigate(PayoutRoute.Detail(it)) })
    }
    composable<PayoutRoute.Detail> { entry ->
        PayoutDetailScreen(onBack = { nav.popBackStack() })
    }
}
```

Domain model (in `core-model`, defined by AND-258; consumed here):

```kotlin
enum class PayoutStatus { PENDING, PROCESSING, PAID, FAILED, CANCELED, ON_HOLD, UNKNOWN }

data class Payout(
    val id: String,
    val amountMinor: Long,        // integer minor units
    val feeMinor: Long?,
    val netMinor: Long?,
    val currency: String,         // ISO 4217
    val status: PayoutStatus,
    val methodLabel: String?,     // "Bank ····4321"
    val createdAt: Instant,
    val paidAt: Instant?,
    val estimatedArrival: Instant?,
    val failureCode: String?,
    val failureReason: String?,
    val transitions: List<PayoutTransition>,  // empty if none
)

data class PayoutTransition(val status: PayoutStatus, val at: Instant, val note: String?)
```

History ViewModel (Paging 3 → Compose):

```kotlin
@HiltViewModel
class PayoutHistoryViewModel @Inject constructor(
    private val repo: PayoutRepository,
) : ViewModel() {
    private val statusFilter = MutableStateFlow<PayoutStatus?>(null)
    val items: Flow<PagingData<PayoutListItemUi>> =
        statusFilter.flatMapLatest { repo.payoutPager(it) }
            .map { it.map(PayoutListItemUi::from) }
            .cachedIn(viewModelScope)
    fun setFilter(s: PayoutStatus?) { statusFilter.value = s }
}
```

Detail ViewModel uses `SavedStateHandle` to read `payoutId`, exposes
`StateFlow<DetailUiState>` and refetches a single payout (with cache fallback):

```kotlin
sealed interface DetailUiState {
    data object Loading : DetailUiState
    data class Content(val payout: Payout, val stale: Boolean) : DetailUiState
    data class Error(val message: String, val retryable: Boolean) : DetailUiState
}
```

Repository (`core-data`/`feature-payouts`) — single source of truth pattern:
Room is the backing store, `RemoteMediator` writes pages into Room, the pager
reads from Room so cached history shows instantly and offline.

```kotlin
interface PayoutRepository {
    fun payoutPager(status: PayoutStatus?): Flow<PagingData<Payout>>
    suspend fun getPayout(id: String, forceRefresh: Boolean): ApiResult<Payout>
}
```

Compose: `PayoutHistoryScreen` collects `items.collectAsLazyPagingItems()`,
renders `PayoutRow`, drives empty/error/append state off `loadState`, wraps in
`PullToRefreshBox`. `PayoutStatusChip(status: PayoutStatus)` is a `core-ui`-style
shared composable mapping status → (container color, label, icon).

## 5. API Contract

Endpoints are owned/typed by **AND-258**; this ticket pins the shapes it relies
on. All are authenticated cookie GETs carrying `X-CSRF-Token`.

**List** `GET /ui/payouts?limit={n}&cursor={token}&status={status?}`

```json
{
  "items": [
    {
      "id": "po_01HF...",
      "amount": 12500,
      "fee": 250,
      "net": 12250,
      "currency": "USD",
      "status": "paid",
      "method_label": "Bank ····4321",
      "created_at": "2026-05-30T14:02:11Z",
      "paid_at": "2026-06-01T09:15:00Z",
      "estimated_arrival": null
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

`next_cursor: null` ⇒ end of pagination. `status` query param is sent only if FR-8
is enabled.

**Detail** `GET /ui/payouts/{payout_id}`

```json
{
  "id": "po_01HF...",
  "amount": 12500, "fee": 250, "net": 12250, "currency": "USD",
  "status": "failed",
  "method_label": "Bank ····4321",
  "created_at": "2026-05-30T14:02:11Z",
  "paid_at": null,
  "estimated_arrival": null,
  "failure_code": "account_closed",
  "failure_reason": "Destination account is closed.",
  "transitions": [
    {"status": "pending", "at": "2026-05-30T14:02:11Z", "note": null},
    {"status": "processing", "at": "2026-05-31T00:00:00Z", "note": null},
    {"status": "failed", "at": "2026-05-31T06:10:00Z", "note": "account_closed"}
  ]
}
```

Retrofit (from AND-258):

```kotlin
interface PayoutApi {
    @GET("ui/payouts")
    suspend fun list(
        @Query("limit") limit: Int,
        @Query("cursor") cursor: String?,
        @Query("status") status: String? = null,
    ): PayoutListDto

    @GET("ui/payouts/{id}")
    suspend fun detail(@Path("id") id: String): PayoutDto
}
```

Errors use FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`) handled by
the shared `ApiResult` mapper; 404 on detail ⇒ "Payout not found".

## 6. Data & State Management

**Room** (cache; DataStore is for prefs only, not used here):

```kotlin
@Entity(tableName = "payout")
data class PayoutEntity(
    @PrimaryKey val id: String,
    val amountMinor: Long, val feeMinor: Long?, val netMinor: Long?,
    val currency: String, val status: String,
    val methodLabel: String?,
    val createdAtEpoch: Long, val paidAtEpoch: Long?, val estArrivalEpoch: Long?,
    val failureCode: String?, val failureReason: String?,
    val transitionsJson: String?,    // Moshi-serialized List<PayoutTransition>
    val pageSeq: Int,                // monotonic insert order for paging
    val fetchedAtEpoch: Long,
)

@Entity(tableName = "payout_remote_key")
data class PayoutRemoteKey(@PrimaryKey val id: String, val nextCursor: String?)
```

`PayoutDao` exposes `PagingSource<Int, PayoutEntity>` ordered by `pageSeq ASC`
(server returns newest-first, so insertion order preserves it). `RemoteMediator`:
on `REFRESH` clears `payout`+`payout_remote_key` in a transaction and inserts
page 1; on `APPEND` uses stored `nextCursor`, ends when `next_cursor == null`.

**State:** History UI state derives from Paging `CombinedLoadStates`
(`refresh`/`append`). Detail uses the `DetailUiState` sealed interface (§4).
`stale = true` when content is served from Room and the live refetch failed.
Currency formatting via `NumberFormat.getCurrencyInstance` keyed on `currency`;
minor units divided by the currency's default fraction digits.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the shared OkHttp 20s call timeout (dev host is slow).
- **Retry:** list/detail are idempotent GETs ⇒ bounded backoff (max 2 retries,
  250ms → 1s jitter) via the shared interceptor. No retry on 4xx.
- **401:** shared authenticator does one `POST /ui/session/refresh` then retries;
  if refresh fails, surface a re-auth prompt (owned by the session/auth feature) —
  this screen shows a generic "Session expired" error with retry.
- **Offline / first page fails but cache exists:** show cached list + a persistent
  "Showing saved data" banner; pull-to-refresh re-attempts.
- **Offline / no cache:** full-screen error with Retry.
- **Append failure:** inline footer error + Retry (Paging `retry()`); does not
  clear loaded items.
- **Unknown status string:** map to `UNKNOWN`, render neutral chip, never throw.
- **Malformed JSON / null required field:** Moshi failure → mapped `ApiResult.Error`;
  page treated as load error, not a crash.

## 8. Security & Privacy

- All requests are authenticated GETs over the shared cookie jar; no payout
  credentials, no PII beyond a masked method label are requested or stored.
- **No raw bank/account numbers** are ever fetched or cached — only `method_label`
  (already masked server-side). Verify in code review that no full PAN/IBAN field
  is read.
- Room DB holds amounts and masked labels; acceptable for cache. No tokens or
  secrets persisted by this feature (session lives in the cookie jar / OS store).
- `X-CSRF-Token` header attached by shared interceptor; GETs are non-mutating.
- Plaintext HTTP is a **dev-only** constraint inherited from the backend; do not
  log full URLs with cursors at `INFO`. Production base URL must be HTTPS
  (enforced by app config, not this ticket).

## 9. Accessibility & i18n

- Status chips: provide `contentDescription` with the spoken status ("Status:
  Paid"); never rely on color alone — each status has a distinct icon + label.
- All strings in `strings.xml`: status labels (`payout_status_paid`, etc.),
  empty/error/banner copy, "Net", "Fee", "Estimated arrival".
- Amounts/dates localized via `NumberFormat`/`DateTimeFormatter` with device
  locale; currency symbol from ISO code.
- Touch targets ≥ 48dp; list rows expose a single merged semantics node with
  combined amount/status/date for TalkBack; detail uses heading semantics.
- Dynamic type / large fonts: rows must not truncate status; use wrap + ellipsis
  on method label only.

## 10. Telemetry & Logging

- Analytics events (via shared analytics in `core-data`): `payout_history_viewed`,
  `payout_history_refreshed`, `payout_detail_viewed {payout_id_hash, status}`,
  `payout_history_load_failed {stage: refresh|append, code}`. Hash/avoid raw IDs
  in analytics payloads.
- Logging: `Timber` (debug only) for load-state transitions and mediator
  page results (count, hasNext) — **no amounts, no cursors, no method labels** in
  logs. Network logging via shared OkHttp logging interceptor (BODY in debug only).

## 11. Testing Strategy

Use `core-testing` (MockWebServer, Turbine, coroutine test rules).

- **Unit — DTO/status mapping:** `payout` JSON → `Payout`; assert every status
  string (incl. casing) maps correctly and unknown → `UNKNOWN`. Assert
  amount/fee/net minor-unit and currency formatting.
- **Unit — RemoteMediator:** MockWebServer serves page1 (with `next_cursor`) then
  page2 (`next_cursor: null`); assert REFRESH clears + inserts, APPEND appends,
  end-of-pagination reached; assert error page → `MediatorResult.Error`.
- **Unit — Repository:** offline (network error) returns cached list + `stale`;
  detail 404 → not-found error.
- **Unit — ViewModel:** Turbine on `items`/`DetailUiState` covering loading →
  content, content → stale, error → retry.
- **UI (Compose) — History:** renders rows with correct status chip text/desc;
  empty state; first-page error + retry; append footer; pull-to-refresh triggers
  refetch (verify via MockWebServer request count).
- **UI — Detail:** failed payout shows failure reason + transition list; back nav.
- **Acceptance gate:** "History renders with statuses" verified by the History UI
  test asserting a known fixture's status chips.

## 12. Dependencies & Sequencing

- **Depends on AND-258** (Payouts API): `PayoutApi`, DTOs, `ApiResult` mapping,
  `next_cursor` pagination. Hard blocker — this ticket cannot integrate without it,
  though UI/Compose work can proceed in parallel against a stub `PayoutRepository`.
- **Indirect:** AND-027 (transitively via AND-258) for the base Retrofit/OkHttp +
  cookie-jar client; session/auth feature for 401 re-auth UI.
- **Sibling consumers (not blockers):** AND-259 (payout setup + KYC) and AND-261
  (bulk read views) share `feature-payouts` and reuse `PayoutStatusChip` /
  `Payout` model; coordinate to avoid duplicate definitions.
- **Blocks:** none recorded.
- Sequence: AND-258 merged → build models/Room/mediator → ViewModels → Compose →
  tests.

## 13. Risks & Open Questions

- **R1 — Status enum drift.** Backend may emit statuses beyond the documented six.
  Mitigation: `UNKNOWN` fallback; confirm full set against `/openapi.json`. *Open:
  is `ON_HOLD` actually emitted, or is it `held`?*
- **R2 — Pagination contract.** Assumes cursor-based `next_cursor`. If AND-258
  exposes offset/limit instead, swap `RemoteMediator` key strategy (low effort).
- **R3 — Status filter (FR-8).** Depends on a `status` query param existing. *Open:
  does `GET /ui/payouts` support it?* If not, defer filtering to a follow-up.
- **R4 — Transitions field.** Detail `transitions[]` presence unconfirmed in
  `payouts.ts`. If absent, render only current status + timestamps (graceful).
- **R5 — Minor-unit assumption.** Assumes integer minor units. *Open:* confirm vs
  decimal strings in `types.ts`; adjust `amountMinor` mapping accordingly.
- **R6 — Dev host flakiness** may cause noisy append errors; covered by retry +
  inline retry footer.

## 14. Acceptance Criteria

AC-1 — Opening Payouts shows a reverse-chronological list; each row shows amount +
currency, masked method label, date, and a **status chip** with correct
label/color/icon (satisfies source acceptance "History renders with statuses").

AC-2 — All six known statuses render distinctly; an unknown status renders a
neutral `UNKNOWN` chip without crashing.

AC-3 — Scrolling loads subsequent pages via Paging 3; pagination ends cleanly when
`next_cursor` is null; append errors show an inline retry that recovers.

AC-4 — Tapping a row opens `payouts/detail/{id}` showing amount/fee/net, currency,
status, timestamps, and (for FAILED) the failure reason; transitions render when
provided.

AC-5 — With cached data and no network, the list shows cached entries plus a
"Showing saved data" banner; with no cache and no network, a full-screen retry
error is shown.

AC-6 — Pull-to-refresh refetches page 1 (verified by request count in tests).

AC-7 — Status chips expose TalkBack `contentDescription`; all user-facing strings
come from `strings.xml`; amounts/dates are locale-formatted.

AC-8 — All §11 unit and UI tests pass in CI.

## 15. Definition of Done

- Code merged to `android-port` under `feature-payouts`, package
  `com.testlogon.android`, building on Kotlin 2.0.21 / AGP 8.7.3 / compileSdk 35.
- History + Detail screens implemented per §3–§6; Paging 3 + Room mediator wired
  to AND-258's `PayoutApi`.
- All §11 tests written and green; ktlint/detekt clean; no new lint errors.
- Telemetry events (§10) emitted; no amounts/cursors/PII in logs.
- Accessibility checks (§9) pass (TalkBack spot-check + automated semantics test).
- AC-1…AC-8 demonstrably met; PR links this ticket and AND-258.
- Open questions in §13 either resolved against `/openapi.json` or explicitly
  ticketed as follow-ups (esp. FR-8 status filter and R5 minor-unit confirmation).
