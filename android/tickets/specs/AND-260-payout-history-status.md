---
id: AND-260
title: Payout history + status
milestone: M6
epic: E35
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth:** session flow is `POST /ui/session/start` → `POST /ui/session/finalize`
  → `GET /ui/me` (all verified to exist; `src/api/endpoints/auth.ts`). **Correction:**
  the web client (`src/api/client.ts`) authenticates requests with an
  `Authorization: Bearer <accessToken>` header taken from the auth store — it is
  *not* purely cookie-based. It also reads the `ui_csrf` cookie and echoes it as
  `X-CSRF-Token` (verified), and on 401 calls `POST /ui/session/refresh` **once**
  then retries the original request (verified). The Android client should mirror
  this: Bearer token + CSRF header + single refresh-on-401. History GETs ride that
  shared client; this ticket adds no auth logic. NOTE: `GET /ui/payouts` also
  accepts optional `user_sub` query and `X-SESSION-ID` / `X-IMPERSONATION-TOKEN`
  headers (admin/impersonation use); not needed for the normal authenticated user.

## 3. Functional Requirements

FR-1 — **History list.** Display payouts newest-first in a `LazyColumn` backed by
Paging 3. Each row shows: formatted amount (`amount_cents`), the payout **method**
label derived from the `method` enum string (`bank_transfer` → "Bank Transfer",
`paypal` → "PayPal"; **correction:** the wire has no masked `method_label` like
"Bank ····4321" — only `method`), the **status chip**, and a date
(`completed_at` if present else `created_at`, matching the web reference).

FR-2 — **Statuses.** Map every backend status to a typed
`PayoutStatus` enum and render a color-coded chip with an icon and localized
label. **Correction (verified against `src/pages/payouts/PayoutDashboard.tsx`
`STATUS_BADGE_VARIANT`):** the actual wire status set is
`requested`, `approved`, `processing`, `completed`, `rejected`, `cancelled`
(British spelling, two L's) — the prior set (`PENDING`/`PAID`/`FAILED`/`CANCELED`/
`ON_HOLD`) was wrong. `PayoutStatus` enum therefore: `REQUESTED`, `APPROVED`,
`PROCESSING`, `COMPLETED`, `REJECTED`, `CANCELLED`, `UNKNOWN`. The backend
`PayoutOut.status` is an unconstrained `string` (no OpenAPI enum), so any unknown
wire value maps to `UNKNOWN` and renders neutrally (must not crash). Map the wire
strings case-sensitively to the six known values; treat `cancelled`/`canceled`
both as `CANCELLED` defensively.

FR-3 — **Pagination.** Infinite scroll via Paging 3 `PagingSource`/`RemoteMediator`
consuming the cursor/`next` token from AND-258. Append spinner at list end;
prepend/append error footer with retry.

FR-4 — **Detail.** **Correction:** there is **no** `GET /ui/payouts/{payout_id}`
endpoint in the backend (only `GET /ui/payouts`, `GET /ui/payouts/balance`,
`POST /ui/payouts/request`, `POST /ui/payouts/{payout_id}/cancel` exist — verified
in `openapi.index.txt` and `src/api/endpoints/payouts.ts`). The web reference renders
the entire payout in the list row itself with no detail route. Tapping a row therefore
navigates to a **client-side detail screen built from the already-loaded list item**
(read from Room cache by `payout_id`; no extra network call). The detail screen shows
fields that actually exist on `PayoutOut`: `amount_cents` (formatted), `method`
(`bank_transfer` → "Bank Transfer", `paypal` → "PayPal"), status chip, `created_at`,
`updated_at`, `completed_at` (if present), `notes`, and — when `status == rejected` —
`reject_reason`. **Fields that do NOT exist on the wire and must be removed:** `fee`,
`net`, `currency` (no currency on `PayoutOut`; only `PayoutBalanceOut` carries
`currency`), `estimated_arrival`, `failure_code`, and a `transitions[]` array
(see R4). Do not display fee/net/currency from the payout object.

FR-5 — **Empty / loading / error / offline states.** First-load shimmer;
distinct empty state ("No payouts yet"); full-screen error with retry on
first-page failure; stale banner when serving cached data while offline.

FR-6 — **Pull-to-refresh** invalidates the pager and refetches page 1.

FR-7 — **Read-only.** No create/cancel/edit actions in this ticket.

FR-8 — **Filter by status (DEFERRED).** **Correction:** `GET /ui/payouts` does
**not** accept a `status` query param (params are only `limit`, `cursor`, `user_sub`
— verified in `openapi.index.txt` and `src/api/endpoints/payouts.ts`; only the
admin endpoint `GET /v1/admin/payouts` has a `status` filter). Server-side status
filtering is therefore **not available** for the user-facing list and is deferred.
If a status filter is desired in this ticket, it must be implemented as a
**client-side filter over the Room cache** (filter loaded entities by status);
note this is best-effort because it only filters already-paged data. Tracked in §13.

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

**Correction:** the model below is rewritten to match the verified `PayoutOut`
schema (`openapi.pretty.json` components.schemas.PayoutOut) and `types.ts: Payout`.
Removed non-existent fields (`fee`, `net`, `currency`, `estimatedArrival`,
`failureCode`/`failureReason`, `transitions`); corrected the enum; `amount_cents`
is an integer in cents (not ambiguous "minor units"), and timestamps are integer
**epoch seconds** (not ISO-8601 strings).

```kotlin
enum class PayoutStatus { REQUESTED, APPROVED, PROCESSING, COMPLETED, REJECTED, CANCELLED, UNKNOWN }

data class Payout(
    val payoutId: String,          // wire: payout_id
    val userId: String,            // wire: user_id
    val amountCents: Long,         // wire: amount_cents (integer cents)
    val method: String,            // wire: method ("bank_transfer" | "paypal")
    val status: PayoutStatus,      // wire: status (free-form string)
    val createdAt: Instant,        // wire: created_at (epoch seconds)
    val updatedAt: Instant,        // wire: updated_at (epoch seconds)
    val completedAt: Instant?,     // wire: completed_at (epoch seconds | null)
    val notes: String,             // wire: notes (default "")
    val rejectReason: String,      // wire: reject_reason (default ""), shown when REJECTED
    val approvedBy: String,        // wire: approved_by (default "")
)
```

There is **no** `PayoutTransition` type on the wire (R4). If a transition timeline
is desired, derive it locally from `created_at`/`completed_at`/`status`; do not
expect a `transitions[]` array from the API.

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
on. Requests are authenticated GETs carrying `Authorization: Bearer <token>` and the
`X-CSRF-Token` header (per `src/api/client.ts`). **All field names/shapes below are
corrected to match the verified `PayoutOut` / `PayoutListOut` schemas
(`openapi.pretty.json`) — the previous example used fields that do not exist.**

**List** `GET /ui/payouts?limit={n}&cursor={token}` — verified. Default `limit=25`,
`maximum=100`, `minimum=1`. **No `status` query param exists** (see FR-8). Response
is `PayoutListOut`:

```json
{
  "items": [
    {
      "payout_id": "po_01HF...",
      "user_id": "usr_123",
      "amount_cents": 12500,
      "method": "bank_transfer",
      "status": "completed",
      "created_at": 1748613731,
      "updated_at": 1748761500,
      "completed_at": 1748761500,
      "notes": "",
      "reject_reason": "",
      "approved_by": "admin_42"
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

`next_cursor` is `string | null`; `null`/absent ⇒ end of pagination (`PayoutListOut`
requires only `items`; `next_cursor` is optional). Timestamps are **integer epoch
seconds**. `PayoutOut` required fields: `payout_id`, `user_id`, `amount_cents`,
`status`, `created_at`, `updated_at`; `method` defaults to `"bank_transfer"`;
`notes`/`reject_reason`/`approved_by` default to `""`; `completed_at` is
`integer | null`.

**Detail** — **does not exist.** There is no `GET /ui/payouts/{payout_id}`. The
detail screen is hydrated from the cached list item (see FR-4). Cancel is
`POST /ui/payouts/{payout_id}/cancel` (out of scope — read-only ticket, FR-7).

Retrofit (from AND-258) — corrected to remove the non-existent detail call:

```kotlin
interface PayoutApi {
    @GET("ui/payouts")
    suspend fun list(
        @Query("limit") limit: Int = 25,   // server max 100
        @Query("cursor") cursor: String? = null,
    ): PayoutListDto
    // No detail endpoint exists; detail is served from the Room cache.
}
```

Errors use FastAPI `detail` mapping (`string` | `[{msg}]` | `{code,...}`) — verified
in `src/api/client.ts: normalizeErrorDetail`; validation failures return
`422 HTTPValidationError` (array of `{loc,msg,type}`). The shared `ApiResult` mapper
should mirror that. Since there is no detail endpoint, the prior "404 on detail ⇒
'Payout not found'" case does not apply.

## 6. Data & State Management

**Room** (cache; DataStore is for prefs only, not used here):

**Correction:** entity columns rewritten to match the verified `PayoutOut` fields
(no fee/net/currency/transitions/failure columns; `amount_cents`, `method`, and the
epoch-second timestamps `created_at`/`updated_at`/`completed_at`).

```kotlin
@Entity(tableName = "payout")
data class PayoutEntity(
    @PrimaryKey val payoutId: String,
    val userId: String,
    val amountCents: Long,
    val method: String,              // "bank_transfer" | "paypal"
    val status: String,              // raw wire string; mapped to enum at read
    val createdAtEpoch: Long,        // epoch seconds
    val updatedAtEpoch: Long,        // epoch seconds
    val completedAtEpoch: Long?,     // epoch seconds | null
    val notes: String,
    val rejectReason: String,
    val approvedBy: String,
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
**Correction:** `PayoutOut` has **no per-payout `currency`** field. Currency must be
sourced separately — from `PayoutBalanceOut.currency` (`GET /ui/payouts/balance`,
owned by AND-258) or a configured default — and applied when formatting
`amount_cents`. Format via `NumberFormat.getCurrencyInstance(locale)` with that
currency; `amount_cents` is whole cents, divide by the currency's default fraction
digits (the web simply uses `formatCents`).

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

- All requests are authenticated GETs (Bearer token + `X-CSRF-Token`, shared cookie
  jar for the session); no payout credentials or PII are requested or stored.
- **Correction:** the `PayoutOut` schema exposes only a `method` enum string
  (`bank_transfer`/`paypal`) — there is no account-number or masked-`method_label`
  field at all, so there is nothing to mask. **No raw bank/account numbers** are ever
  fetched or cached. Verify in code review that no full PAN/IBAN field is read (none
  exists on the contract today). Note `PayoutOut` does include `user_id` and
  `approved_by` (an admin identifier) — keep these out of analytics/logs.
- Room DB holds amounts and masked labels; acceptable for cache. No tokens or
  secrets persisted by this feature (session lives in the cookie jar / OS store).
- `X-CSRF-Token` header attached by shared interceptor; GETs are non-mutating.
- Plaintext HTTP is a **dev-only** constraint inherited from the backend; do not
  log full URLs with cursors at `INFO`. Production base URL must be HTTPS
  (enforced by app config, not this ticket).

## 9. Accessibility & i18n

- Status chips: provide `contentDescription` with the spoken status ("Status:
  Completed"); never rely on color alone — each status has a distinct icon + label.
- All strings in `strings.xml`: status labels (`payout_status_requested`,
  `payout_status_approved`, `payout_status_processing`, `payout_status_completed`,
  `payout_status_rejected`, `payout_status_cancelled`, `payout_status_unknown`),
  method labels ("Bank Transfer"/"PayPal"), empty/error/banner copy, and
  "Reject reason". (Removed "Net"/"Fee"/"Estimated arrival" — those fields do not
  exist on the contract.)
- Amounts/dates localized via `NumberFormat`/`DateTimeFormatter` with device
  locale; currency symbol from ISO code.
- Touch targets ≥ 48dp; list rows expose a single merged semantics node with
  combined amount/status/date for TalkBack; detail uses heading semantics.
- Dynamic type / large fonts: rows must not truncate status; use wrap + ellipsis
  on the method label only (the short "Bank Transfer"/"PayPal" string).

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

- **Unit — DTO/status mapping:** `PayoutOut` JSON → `Payout`; assert every real
  status string (`requested`/`approved`/`processing`/`completed`/`rejected`/
  `cancelled`) maps correctly and an unknown string → `UNKNOWN`. Assert
  `amount_cents` formatting (whole cents) and epoch-second → `Instant` parsing.
- **Unit — RemoteMediator:** MockWebServer serves page1 (with `next_cursor`) then
  page2 (`next_cursor: null`); assert REFRESH clears + inserts, APPEND appends,
  end-of-pagination reached; assert error page → `MediatorResult.Error`.
- **Unit — Repository:** offline (network error) returns cached list + `stale`;
  detail is read from Room by `payout_id` (no network) — assert it returns the cached
  payout, and returns a not-found state when the id is absent from cache.
- **Unit — ViewModel:** Turbine on `items`/`DetailUiState` covering loading →
  content, content → stale, error → retry.
- **UI (Compose) — History:** renders rows with correct status chip text/desc;
  empty state; first-page error + retry; append footer; pull-to-refresh triggers
  refetch (verify via MockWebServer request count).
- **UI — Detail:** a `rejected` payout shows `reject_reason`; amount/method/status/
  timestamps render from the cached item; back nav works (no network call made).
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

- **R1 — Status enum drift. RESOLVED.** `PayoutOut.status` is an unconstrained
  `string` (no OpenAPI enum). The web reference's `STATUS_BADGE_VARIANT` defines the
  real set: `requested`, `approved`, `processing`, `completed`, `rejected`,
  `cancelled`. `ON_HOLD` is **not** emitted (it does not exist). Mitigation: map to
  the six `PayoutStatus` values + `UNKNOWN` fallback for any future additions.
- **R2 — Pagination contract. RESOLVED.** Cursor-based: `GET /ui/payouts` accepts
  `cursor` and returns `next_cursor` (`string | null`) — confirmed in OpenAPI and
  `payouts.ts`. No offset/limit alternative.
- **R3 — Status filter (FR-8). RESOLVED (deferred).** `GET /ui/payouts` has **no**
  `status` query param (only `limit`, `cursor`, `user_sub`). Server-side filtering is
  not possible; only the admin `GET /v1/admin/payouts` supports it. Client-side
  filtering over cached data is the only option; deferred per FR-8.
- **R4 — Transitions field. RESOLVED.** `PayoutOut` has **no** `transitions[]` array
  and there is no detail endpoint. Render current status + `created_at`/`updated_at`/
  `completed_at` only; synthesize a timeline locally if desired.
- **R5 — Amount units. RESOLVED.** `amount_cents` is an `integer` (whole cents) on
  `PayoutOut`; not decimal strings. Map to `Long amountCents`. There is no per-payout
  `currency`; source it from `PayoutBalanceOut.currency` or a configured default.
- **R6 — Dev host flakiness** may cause noisy append errors; covered by retry +
  inline retry footer. (Unchanged.)
- **R7 — No detail endpoint (NEW).** `GET /ui/payouts/{payout_id}` does not exist;
  detail is hydrated from the Room-cached list item. If the cache is evicted before
  the user taps a row (cold deep-link), detail cannot be fetched standalone — a
  deep-linked detail must first ensure the list page containing the id is loaded, or
  show a "reopen from history" fallback. Tracked as a follow-up if deep-linking is
  required.
- **R8 — Auth header (NEW).** The web client uses `Authorization: Bearer` (auth
  store) plus `X-CSRF-Token`, not pure cookie auth; the Android shared client (AND-027/
  AND-258) must supply the Bearer token. Confirm AND-258's client attaches it.

## 14. Acceptance Criteria

AC-1 — Opening Payouts shows a reverse-chronological list; each row shows amount +
currency, masked method label, date, and a **status chip** with correct
label/color/icon (satisfies source acceptance "History renders with statuses").

AC-2 — All six known statuses (`requested`, `approved`, `processing`, `completed`,
`rejected`, `cancelled`) render distinctly; an unknown status renders a neutral
`UNKNOWN` chip without crashing.

AC-3 — Scrolling loads subsequent pages via Paging 3; pagination ends cleanly when
`next_cursor` is null; append errors show an inline retry that recovers.

AC-4 — Tapping a row opens `payouts/detail/{id}` (hydrated from the Room cache, no
network) showing amount, method, status, and timestamps
(`created_at`/`updated_at`/`completed_at`), and — for a `rejected` payout — the
`reject_reason`. (No fee/net/currency/transitions exist on the contract; AC adjusted.)

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
  ticketed as follow-ups (R1–R5 resolved during review; FR-8 status filter, R7
  cold-deep-link detail, and R8 Bearer-token wiring are the remaining follow-ups).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **List endpoint is `GET /ui/payouts` with `limit` + `cursor`.** VERIFIED.
   OpenAPI `GET /ui/payouts` (op `list_payouts_ui_payouts_get`, resp `200:PayoutListOut`);
   `src/api/endpoints/payouts.ts: listPayouts`.
2. **List response shape is `{ items: PayoutOut[], next_cursor: string|null }`;
   only `items` required, `next_cursor` optional.** VERIFIED.
   OpenAPI schema `PayoutListOut`; `src/api/types.ts: PayoutListResp`.
3. **`status` query param on `GET /ui/payouts`.** CORRECTED — does not exist
   (params are `limit`, `cursor`, `user_sub` query + `X-SESSION-ID`/
   `X-IMPERSONATION-TOKEN` headers). OpenAPI `GET /ui/payouts` params; only
   `GET /v1/admin/payouts` has a `status` filter. (FR-8, R3 updated.)
4. **A detail endpoint `GET /ui/payouts/{payout_id}` exists.** CORRECTED — does
   not exist. The only `/ui/payouts/*` ops are list, `GET /ui/payouts/balance`,
   `POST /ui/payouts/request`, `POST /ui/payouts/{payout_id}/cancel`.
   `openapi.index.txt` lines for `/ui/payouts*`; `src/api/endpoints/payouts.ts`.
   (FR-4, §5, R7 updated.)
5. **Payout fields `amount`/`fee`/`net`/`currency`/`method_label`/`paid_at`/
   `estimated_arrival`/`failure_code`/`failure_reason`/`transitions`/`id`.**
   CORRECTED — none of these exist. Real `PayoutOut` fields: `payout_id`,
   `user_id`, `amount_cents`, `method`, `status`, `created_at`, `updated_at`,
   `completed_at`, `notes`, `reject_reason`, `approved_by`.
   OpenAPI schema `PayoutOut`; `src/api/types.ts: Payout`. (§4, §5, §6 updated.)
6. **Amounts are integer minor units.** CORRECTED to `amount_cents` integer (whole
   cents). OpenAPI `PayoutOut.amount_cents` (`type: integer`);
   `src/api/types.ts: Payout.amount_cents: number`. (R5 resolved.)
7. **Timestamps are ISO-8601 strings.** CORRECTED — integer epoch seconds.
   OpenAPI `PayoutOut.created_at`/`updated_at` (`type: integer`),
   `completed_at` (`integer|null`); web formats them via `formatDate(epoch)`
   in `src/pages/payouts/PayoutDashboard.tsx`. (§4, §6 updated.)
8. **No per-payout `currency`; currency comes from balance.** VERIFIED.
   `PayoutOut` has no currency property; `PayoutBalanceOut.currency` exists.
   OpenAPI schemas `PayoutOut`, `PayoutBalanceOut`; `src/api/types.ts: PayoutBalance`.
9. **Status set `PENDING/PROCESSING/PAID/FAILED/CANCELED/ON_HOLD`.** CORRECTED —
   actual set is `requested`, `approved`, `processing`, `completed`, `rejected`,
   `cancelled` (British spelling). `src/pages/payouts/PayoutDashboard.tsx:
   STATUS_BADGE_VARIANT` (and `status === "requested" | "approved" | "rejected"`
   usages). (FR-2, AC-2, R1 updated.)
10. **`status` is a constrained enum on the wire.** CORRECTED — it is a free-form
    `string` (no OpenAPI enum), hence the mandatory `UNKNOWN` fallback.
    OpenAPI `PayoutOut.status` (`type: string`, no `enum`).
11. **`method` is a masked label like "Bank ····4321".** CORRECTED — `method` is an
    enum string (`bank_transfer` default, or `paypal`); web maps it to
    "Bank Transfer"/"PayPal". OpenAPI `PayoutOut.method` (default `bank_transfer`);
    `src/pages/payouts/PayoutDashboard.tsx` method rendering. (FR-1, §8 updated.)
12. **Pagination is cursor-based via `next_cursor`.** VERIFIED.
    `PayoutListOut.next_cursor` (`string|null`); `payouts.ts: listPayouts` cursor
    param. (R2 resolved.)
13. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERIFIED.
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
14. **On 401 the client refreshes once via `POST /ui/session/refresh` then retries.**
    VERIFIED. `src/api/client.ts: refreshSession` + 401 retry block;
    OpenAPI `POST /ui/session/refresh`.
15. **Auth is "cookie-based session" only.** CORRECTED — requests carry
    `Authorization: Bearer <accessToken>` from the auth store (plus CSRF cookie +
    `credentials: include`). `src/api/client.ts` (`headers.set("Authorization",
    "Bearer "+accessToken)`). (§2 updated, R8 added.)
16. **Session flow `start → finalize → me` exists.** VERIFIED (endpoints exist).
    OpenAPI `POST /ui/session/start` (`UiSessionStartResp`),
    `POST /ui/session/finalize`, `GET /ui/me`; `src/api/endpoints/auth.ts`.
    NOTE: the "→ MFA →" step is not evidenced in `auth.ts`/`client.ts`; treated as an
    unverified narrative detail (does not affect this read-only ticket).
17. **FastAPI error `detail` is `string | [{msg}] | {code,...}`.** VERIFIED.
    `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`; validation
    errors are `422 HTTPValidationError` per OpenAPI on every payout op.
18. **Detail "404 ⇒ Payout not found" error case.** CORRECTED — no detail endpoint,
    so no such network 404; "not found" is now a local cache-miss state. (§5, §11.)
19. **`transitions[]` status timeline.** CORRECTED — absent from the contract; no
    `PayoutTransition` type on the wire. OpenAPI `PayoutOut` (no transitions field).
    (FR-4, §4, R4 updated.)
20. **Read-only scope (no create/cancel/edit here).** VERIFIED feasible — cancel is
    `POST /ui/payouts/{payout_id}/cancel`, intentionally out of scope. OpenAPI
    `POST /ui/payouts/{payout_id}/cancel`; `payouts.ts: cancelPayout`.
21. **Android stack: Paging 3 + RemoteMediator + Room single-source-of-truth;
    Compose `collectAsLazyPagingItems`, `PullToRefreshBox`; Hilt; Navigation-Compose
    type-safe routes.** UNVERIFIED-ASSUMPTION (framework choices, not derivable from
    backend/web). framework ref: developer.android.com/topic/libraries/architecture/paging/v3-paged-data,
    developer.android.com/jetpack/compose/navigation.
22. **Dev host `http://18.222.237.167:8000`, plaintext HTTP, ~20s timeouts.**
    UNVERIFIED-ASSUMPTION — not present in the provided sources (web uses
    `VITE_API_BASE_URL` from env, `src/api/client.ts: API_BASE_URL`). Carried from
    the ticket's environment notes; cannot be confirmed here.

### Corrections made

- §2 Auth: clarified Bearer-token auth (not cookie-only); kept CSRF + single
  refresh-on-401 (both verified). Added `user_sub`/`X-SESSION-ID`/
  `X-IMPERSONATION-TOKEN` note.
- §3 FR-1: `method` enum → label (no masked `method_label`); date = `completed_at`
  else `created_at`.
- §3 FR-2 / §4 enum / AC-2 / R1: real status set
  `requested/approved/processing/completed/rejected/cancelled` (+`UNKNOWN`).
- §3 FR-4 / §5 / AC-4 / R4 / R7: removed the non-existent detail endpoint; detail is
  cache-hydrated; removed fee/net/currency/estimated_arrival/failure_*/transitions.
- §3 FR-8 / R3: removed `status` query param; filtering deferred / client-side only.
- §4 + §6: rewrote `Payout` model and `PayoutEntity` to the real `PayoutOut` fields;
  `amount_cents` integer; epoch-second timestamps.
- §5: rewrote List JSON + Retrofit interface; dropped the detail call and 404 case;
  documented `422 HTTPValidationError`.
- §6: currency sourced from balance/default (no per-payout currency).
- §8: corrected masking claim (no account-number/`method_label` field exists);
  flagged `user_id`/`approved_by` as identifiers to keep out of logs/analytics.
- §9: status-label example + i18n keys updated; removed Net/Fee/Estimated-arrival
  strings; added Reject-reason.
- §11 / §13 / §15: tests, risks, and DoD aligned to the above.

### Open assumptions

- **OA-1 (item 16):** the "MFA" step between `session/start` and `session/finalize`
  is not evidenced in `auth.ts`/`client.ts`; left as narrative. Why unverifiable: not
  represented in the provided frontend/OpenAPI sources.
- **OA-2 (item 21):** all Android framework/library choices (Paging 3, Room, Hilt,
  Compose, Navigation-Compose) are design decisions; only framework refs apply, not
  backend/web sources.
- **OA-3 (item 22):** dev host URL, plaintext-HTTP constraint, and 20s timeout are
  not in the sources; inherited from ticket environment notes.
- **OA-4:** `method` enum membership — `bank_transfer` (schema default) and `paypal`
  (web label) are confirmed; whether additional methods exist is unverifiable from
  the unconstrained `string` schema. Defensive default-label handling required.
- **OA-5:** AND-258's exact Kotlin DTO field names are authoritative at integration;
  if they differ from this spec's mapping, AND-258 wins (per §2).

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric local; **emu35** = headless AVD `test35`
(x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial
R5CX821TA9R, API 34, arm64-v8a). IDs `TC-AND-260-NN`.

- **TC-AND-260-01** — Type: unit (JVM). Target: JVM. Precond: `PayoutOut` JSON
  fixtures for each status. Steps: deserialize list payload; map DTO → `Payout`;
  assert `amount_cents`/`method`/epoch timestamps and that each wire status
  (`requested`/`approved`/`processing`/`completed`/`rejected`/`cancelled`) maps to
  the right enum. Expected: all fields correct; epoch seconds → `Instant` exact.
  Traces: AC-1, AC-2.
- **TC-AND-260-02** — Type: unit (JVM). Target: JVM. Precond: payload with
  `status:"weird_new_state"`. Steps: map DTO. Expected: status = `UNKNOWN`; no
  exception; chip renderable neutrally. Traces: AC-2.
- **TC-AND-260-03** — Type: contract/MockWebServer. Target: JVM (Robolectric ok).
  Precond: MockWebServer serves page1 `{items:[...], next_cursor:"c2"}` then page2
  `{items:[...], next_cursor:null}`. Steps: drive `RemoteMediator` REFRESH then
  APPEND. Expected: REFRESH clears `payout`+`payout_remote_key` and inserts page1;
  APPEND uses stored cursor and appends; `next_cursor:null` ⇒ `endOfPaginationReached`;
  request carries `Authorization: Bearer` + `X-CSRF-Token`. Traces: AC-3, AC-6.
- **TC-AND-260-04** — Type: contract/MockWebServer. Target: JVM. Precond: page1 OK
  in cache, APPEND request returns 500. Steps: scroll to trigger APPEND. Expected:
  `MediatorResult.Error`; loaded items retained; no clear; `retry()` re-issues the
  request and recovers. Traces: AC-3.
- **TC-AND-260-05** — Type: contract/MockWebServer. Target: JVM. Precond: server
  returns `422` with `detail:[{loc,msg,type}]`. Steps: trigger list load. Expected:
  mapped to `ApiResult.Error` with the joined `msg`; treated as a load error, not a
  crash. Traces: AC-3, AC-8.
- **TC-AND-260-06** — Type: integration. Target: JVM/Robolectric. Precond: Room has
  cached payouts; network stubbed to fail (offline). Steps: open history. Expected:
  cached list shown + persistent "Showing saved data" banner (`stale=true`); no
  crash. With cache cleared + offline ⇒ full-screen retry error. Traces: AC-5.
- **TC-AND-260-07** — Type: integration. Target: JVM/Robolectric. Precond: cached
  payout id `po_x` (`status:rejected`, `reject_reason` set) present; no detail
  endpoint. Steps: open detail route for `po_x`; then for an id absent from cache.
  Expected: present id renders amount/method/status/timestamps + `reject_reason`
  with **zero network calls**; absent id shows a "not found / reopen from history"
  state. Traces: AC-4, AC-5.
- **TC-AND-260-08** — Type: Compose-UI. Target: emu35 (fast CI). Precond: paging
  fixture covering all six statuses. Steps: render `PayoutHistoryScreen`; assert each
  row's chip text + `contentDescription` ("Status: Completed", etc.), amount, method
  label ("Bank Transfer"/"PayPal"), and date. Expected: all six chips visually
  distinct; UNKNOWN row neutral. Traces: AC-1, AC-2, AC-7.
- **TC-AND-260-09** — Type: Compose-UI. Target: emu35. Precond: empty list, and a
  first-page-error fixture. Steps: render each. Expected: empty state "No payouts
  yet"; first-page error shows full-screen Retry that re-requests. Traces: AC-1,
  AC-5.
- **TC-AND-260-10** — Type: Compose-UI. Target: emu35. Precond: MockWebServer
  counting requests; loaded list. Steps: perform pull-to-refresh gesture in
  `PullToRefreshBox`. Expected: pager invalidated; exactly one new page-1 request;
  REFRESH clears+reinserts. Traces: AC-6.
- **TC-AND-260-11** — Type: Compose-UI (accessibility). Target: emu35. Precond:
  large font scale (e.g. 1.3x) + TalkBack semantics tree. Steps: assert each row is a
  single merged semantics node combining amount/status/date; status not truncated;
  touch targets ≥48dp; detail uses heading semantics. Expected: semantics + sizing
  pass. Traces: AC-7.
- **TC-AND-260-12** — Type: instrumented/e2e. Target: **A15 (physical, required)**.
  Precond: device on real flaky/plaintext dev host; authenticated session. Steps:
  open Payouts on real network; scroll to paginate; toggle airplane mode mid-append;
  re-enable and retry. Expected: real-network HLS-of-data behavior — append error
  footer on drop, cached rows persist, retry recovers, stale banner appears offline.
  Why physical: real-network/offline transition + arm64/API-34 behavior differs from
  the x86_64/API-35 emulator. Traces: AC-3, AC-5, AC-6.
- **TC-AND-260-13** — Type: manual (security/logging). Target: A15 or emu35. Precond:
  debug build with OkHttp logging. Steps: exercise history+detail; inspect logcat and
  analytics payloads. Expected: no `amount_cents`, no cursors, no `user_id`/
  `approved_by`, no method labels in logs; analytics uses hashed ids; all traffic
  carries `X-CSRF-Token`; no account-number field anywhere (none exists on contract).
  Traces: AC-7 (privacy), DoD §8/§10.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-08, TC-09 |
| AC-2 | TC-01, TC-02, TC-08 |
| AC-3 | TC-03, TC-04, TC-05, TC-12 |
| AC-4 | TC-07 |
| AC-5 | TC-06, TC-07, TC-09, TC-12 |
| AC-6 | TC-03, TC-10, TC-12 |
| AC-7 | TC-08, TC-11, TC-13 |
| AC-8 | TC-05 (+ all JVM/Compose suites green in CI) |
