---
id: AND-244
title: Refund requests
milestone: M5
epic: E33
priority: P1
size: M
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-244 — Refund requests

## 1. Overview & Goal

This ticket delivers the Android-native **refund request** capability: a user can
submit a refund request against a prior billing transaction, see the list of their
refund requests, and track the status of each request as it moves through the
backend lifecycle (e.g. `pending → approved/denied → refunded`). It is the
client-side mirror of the web reference module `frontend/src/api/endpoints/refundRequests.ts`,
which exposes submit/list/status operations.

The goal is a complete, tested vertical slice: a typed API surface in
`core-network`, refund DTOs and domain models in `core-model`/`core-data`, a
`feature-billing` refund UI (submit form + request list + per-request status),
and full unit/UI test coverage. Refund payloads must round-trip correctly against
the FastAPI backend, and the UI must surface offline/stale/error states given the
unreliable dev host.

Out of scope: the base billing API/DTOs and transaction list (owned by
**AND-223**), payment method management, and any web-only admin approval flows.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/refundRequests.ts`
  (submit/list/status), shared types in `frontend/src/api/types.ts`, base billing
  endpoints in `frontend/src/api/endpoints/billing.ts`.
- **Backend:** FastAPI + DynamoDB. OpenAPI at
  `http://18.222.237.167:8000/openapi.json` — confirm exact refund paths/shapes
  against it before finalizing DTOs (web app and OpenAPI are authoritative over
  this spec when they disagree). Dev host is **plaintext HTTP** and unreliable.
- **Auth:** cookie-based session established via `/ui/session/start` → MFA →
  `/ui/session/finalize` → `/ui/me`; `ui_csrf` cookie echoed as `X-CSRF-Token`;
  single `/ui/session/refresh` retry on 401. Refund calls reuse the shared
  authenticated OkHttp client and persistent cookie jar.
- **Upstream dependency — AND-223 (Billing API + DTOs):** provides the
  `BillingApi` Retrofit interface scaffolding, `core-network` error mapping for
  the `/ui/billing/*` namespace, and the `Transaction`/`Charge` domain models
  that a refund references via `transactionId`. This ticket extends that surface;
  it does not duplicate it.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3.
  Module layering `app → feature-billing → core-*`.

## 3. Functional Requirements

FR-1. **Submit a refund request.** From a transaction's detail/billing screen the
user can open a refund form, select/confirm the target transaction, choose a
reason (enum), optionally enter an amount (partial refund) and free-text note, and
submit. On success the new request appears in the list with status `pending`.

FR-2. **List refund requests.** The user can view all of their refund requests,
newest first, with transaction reference, requested amount, reason, status, and
created/updated timestamps. The list supports pull-to-refresh and is backed by
Paging 3 if the backend paginates; otherwise a single bounded fetch.

FR-3. **Track status.** The user can open a single refund request to see its
current status, status history/timeline if provided by the backend, resolved
amount, and decision note. Status is re-fetched on screen open and on
pull-to-refresh.

FR-4. **Validation.** Client validates before submit: amount > 0 and ≤ refundable
transaction amount, reason required, note ≤ 500 chars. Submit button disabled
until valid. Server-side validation errors are surfaced inline.

FR-5. **Offline/stale states.** Cached refund lists render with a "stale" banner
when the network is unavailable or a fetch fails; submit is disabled while
offline with an explanatory message.

FR-6. **Idempotency.** Re-tapping submit while a request is in flight must not
create duplicate refund requests (button disabled + client-generated idempotency
key, see §5).

## 4. Technical Design

Module: **`feature-billing`** (UI + ViewModels), **`core-network`** (API +
DTOs + mappers), **`core-data`** (repository + Room cache), **`core-model`**
(domain models). Package root `com.testlogon.android`.

### 4.1 Retrofit API (`core-network`)

```kotlin
package com.testlogon.android.core.network.api

interface RefundApi {
    @POST("ui/billing/refunds")
    suspend fun submitRefund(
        @Header("X-CSRF-Token") csrf: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: SubmitRefundRequestDto,
    ): RefundRequestDto

    @GET("ui/billing/refunds")
    suspend fun listRefunds(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): RefundListDto

    @GET("ui/billing/refunds/{refundId}")
    suspend fun getRefund(@Path("refundId") refundId: String): RefundRequestDto
}
```

Calls go through the shared authenticated OkHttp client (cookie jar + CSRF
interceptor + `/ui/session/refresh` retry) configured in AND-223 / core-network.
The `X-CSRF-Token` header is also injected by the shared CSRF interceptor; passing
it explicitly here is belt-and-suspenders for the mutating POST and may be dropped
if the interceptor is authoritative.

### 4.2 Domain models (`core-model`)

```kotlin
data class RefundRequest(
    val id: String,
    val transactionId: String,
    val status: RefundStatus,
    val reason: RefundReason,
    val requestedAmountCents: Long?,   // null => full refund
    val resolvedAmountCents: Long?,
    val currency: String,              // ISO-4217, e.g. "USD"
    val note: String?,
    val decisionNote: String?,
    val createdAt: Instant,
    val updatedAt: Instant,
    val history: List<RefundStatusEvent> = emptyList(),
)

enum class RefundStatus { PENDING, APPROVED, DENIED, REFUNDED, FAILED, UNKNOWN }
enum class RefundReason { DUPLICATE, FRAUDULENT, NOT_RECEIVED, REQUESTED_BY_CUSTOMER, OTHER }

data class RefundStatusEvent(val status: RefundStatus, val at: Instant, val note: String?)
```

`UNKNOWN` is the fallback for unrecognized server status strings (forward-compat).

### 4.3 Repository (`core-data`)

```kotlin
interface RefundRepository {
    fun observeRefunds(): Flow<List<RefundRequest>>          // Room-backed, reactive
    suspend fun refreshRefunds(): ApiResult<Unit>
    suspend fun submitRefund(input: SubmitRefundInput): ApiResult<RefundRequest>
    suspend fun getRefund(id: String): ApiResult<RefundRequest>
}

data class SubmitRefundInput(
    val transactionId: String,
    val reason: RefundReason,
    val amountCents: Long?,   // null => full refund
    val note: String?,
)
```

`ApiResult<T>` is the project-standard sealed type (`Success`/`Error`/`Loading`
or equivalent) defined in `core-network`. The repository writes fetched/submitted
refunds into Room so `observeRefunds()` is the single source of truth and
survives process death / offline.

### 4.4 ViewModels (`feature-billing`)

```kotlin
@HiltViewModel
class RefundListViewModel @Inject constructor(
    private val repo: RefundRepository,
) : ViewModel() {
    val uiState: StateFlow<RefundListUiState>
    fun refresh()
}

@HiltViewModel
class RefundSubmitViewModel @Inject constructor(
    private val repo: RefundRepository,
    savedStateHandle: SavedStateHandle,   // carries transactionId
) : ViewModel() {
    val uiState: StateFlow<RefundSubmitUiState>
    fun onReasonChange(r: RefundReason)
    fun onAmountChange(raw: String)
    fun onNoteChange(s: String)
    fun submit()                          // no-op if already submitting
}

@HiltViewModel
class RefundDetailViewModel @Inject constructor(
    private val repo: RefundRepository,
    savedStateHandle: SavedStateHandle,   // carries refundId
) : ViewModel() {
    val uiState: StateFlow<RefundDetailUiState>
    fun refresh()
}
```

### 4.5 Navigation & Compose

Single-Activity Navigation-Compose routes registered in `feature-billing`'s nav
graph: `billing/refunds` (list), `billing/refunds/new?transactionId={id}`
(submit), `billing/refunds/{refundId}` (detail). Screens:
`RefundListScreen`, `RefundSubmitScreen`, `RefundDetailScreen`, all stateless
composables driven by `StateFlow<UiState>` collected with
`collectAsStateWithLifecycle()`.

## 5. API Contract

Base URL `http://18.222.237.167:8000`. Exact paths/fields MUST be reconciled with
`/openapi.json` and `refundRequests.ts` before implementation; shapes below are
the working contract.

**Submit — `POST /ui/billing/refunds`**

Headers: `X-CSRF-Token: <ui_csrf>`, `Idempotency-Key: <uuid-v4>`, cookies.

Request body:
```json
{
  "transaction_id": "txn_01H...",
  "reason": "requested_by_customer",
  "amount_cents": 1299,
  "note": "Charged twice"
}
```
`amount_cents` omitted/`null` ⇒ full refund. `201` (or `200`) returns a
`RefundRequest`:
```json
{
  "id": "rfnd_01H...",
  "transaction_id": "txn_01H...",
  "status": "pending",
  "reason": "requested_by_customer",
  "requested_amount_cents": 1299,
  "resolved_amount_cents": null,
  "currency": "USD",
  "note": "Charged twice",
  "decision_note": null,
  "created_at": "2026-06-05T12:00:00Z",
  "updated_at": "2026-06-05T12:00:00Z",
  "history": [{ "status": "pending", "at": "2026-06-05T12:00:00Z", "note": null }]
}
```

**List — `GET /ui/billing/refunds?limit=50&cursor=`**
```json
{ "items": [ { /* RefundRequest */ } ], "next_cursor": "eyJ..." }
```

**Status/detail — `GET /ui/billing/refunds/{refundId}`** → single `RefundRequest`.

**Moshi DTOs** (`core-network`) use `@Json(name = ...)` for snake_case mapping;
`SubmitRefundRequestDto`, `RefundRequestDto`, `RefundListDto`,
`RefundStatusEventDto`. Mappers `RefundRequestDto.toDomain()` parse timestamps to
`Instant` and map unknown enum strings to `UNKNOWN`/`OTHER`.

**Errors:** FastAPI `detail` may be `string | [{msg}] | {code,...}`; reuse the
shared `core-network` error-detail decoder (from AND-223) to produce
`ApiResult.Error(message, code?)`. `422` ⇒ field validation; `409` ⇒ duplicate
refund (treat as success-equivalent and refresh).

## 6. Data & State Management

- **Room (`core-data`):** table `refund_requests` keyed by `id`, columns
  mirroring the domain model (status/reason stored as strings, amounts as
  `INTEGER` cents). `RefundDao` exposes `observeAll(): Flow<List<RefundEntity>>`,
  `upsertAll`, `upsert`, `clearAll`. List/detail fetches upsert into Room;
  `observeRefunds()` reads from it. DataStore is not used for refund data (no
  user-pref surface here); the persistent cookie jar lives in core-network.
- **UiState** (`feature-billing`):
```kotlin
data class RefundListUiState(
    val refunds: List<RefundRequestUi> = emptyList(),
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: String? = null,
)
sealed interface RefundSubmitUiState {
    data class Editing(
        val reason: RefundReason?, val amountText: String, val note: String,
        val amountError: String?, val submitEnabled: Boolean, val isSubmitting: Boolean,
        val offline: Boolean,
    ) : RefundSubmitUiState
    data class Success(val refundId: String) : RefundSubmitUiState
    data class Failure(val message: String) : RefundSubmitUiState
}
data class RefundDetailUiState(
    val refund: RefundRequestUi? = null,
    val isLoading: Boolean = false, val isStale: Boolean = false, val error: String? = null,
)
```
- **Idempotency key** generated once per submit attempt in the ViewModel
  (`UUID.randomUUID()`), held in `SavedStateHandle` so a config-change/process
  recreation during an in-flight submit reuses the same key.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the shared OkHttp client's ~20s call/connect/read
  timeouts (dev host is slow/unreliable).
- **Retries:** bounded exponential backoff (max 2 retries, jittered) for the
  **idempotent GETs** (`listRefunds`, `getRefund`) only. **No automatic retry**
  on `submitRefund` (non-idempotent at the transport level); the
  `Idempotency-Key` makes a user-initiated retry safe instead.
- **401:** handled centrally by the auth interceptor (`/ui/session/refresh` once,
  then retry). On final auth failure the repository returns
  `ApiResult.Error` and the UI routes to re-authentication.
- **Offline/stale:** if a refresh fails but cache exists, emit `isStale = true`
  and keep showing cached rows; if no cache, show an error/empty state with
  retry. Submit is blocked offline with an inline message.
- **409 duplicate:** treat as benign — refresh the list and navigate to the
  existing request rather than showing an error.
- **Unknown enums / nullable fields:** never crash; map to `UNKNOWN`/`OTHER` and
  render gracefully.

## 8. Security & Privacy

- All refund calls require the authenticated cookie session and `X-CSRF-Token`;
  no refund endpoint is reachable unauthenticated.
- **Transport:** dev backend is plaintext HTTP, permitted only via the existing
  debug `networkSecurityConfig` cleartext allowance for `18.222.237.167`.
  Production builds MUST require HTTPS (no cleartext) — refund payloads contain
  billing/transaction references.
- Do **not** log full request/response bodies for refund endpoints; redact
  `transaction_id`, amounts, and notes in any diagnostic logging (see §10).
- Refund notes are user free-text; treat as untrusted, render as plain text (no
  HTML), enforce the 500-char cap client-side and rely on server validation.
- No card/PAN data is handled by this feature; refunds reference transactions by
  opaque id only.

## 9. Accessibility & i18n

- All strings in `feature-billing/src/main/res/values/strings.xml`
  (`refund_*` keys); no hardcoded UI text. Reason enum labels are localized;
  status labels localized with stable internal enum values.
- Currency/amount formatting via `NumberFormat.getCurrencyInstance(locale)` using
  the response `currency`; timestamps via locale-aware formatters.
- Compose semantics: form fields have `contentDescription`/labels, the submit
  button announces disabled state and reason, status chips include text (not
  color-only) status. Min 48dp touch targets; full TalkBack traversal of list and
  detail. Support dynamic type / large fonts and dark theme (Material 3).
- RTL-safe layouts (use start/end, not left/right).

## 10. Telemetry & Logging

- Emit analytics events via the shared analytics facade (no PII): 
  `refund_submit_attempted`, `refund_submit_succeeded`,
  `refund_submit_failed{reason_code}`, `refund_list_viewed`,
  `refund_detail_viewed{status}`. Include only enum/status/result codes and
  durations — never amounts, notes, or transaction ids.
- Logging via the project logger (e.g. Timber): log at `INFO` for state
  transitions and `WARN`/`ERROR` for failures with the mapped error code and HTTP
  status, **not** bodies. OkHttp `HttpLoggingInterceptor` for refund paths must be
  `HEADERS`-level at most in debug and `NONE` in release.

## 11. Testing Strategy

- **Mapper/DTO unit tests (`core-network`):** Moshi round-trip for
  `SubmitRefundRequestDto`/`RefundRequestDto`/`RefundListDto`; snake_case mapping;
  null `amount_cents` ⇒ full refund; unknown status/reason ⇒ `UNKNOWN`/`OTHER`;
  timestamp parsing. This is the core of the AND-223 "payloads map (tested)"
  lineage applied to refunds.
- **Repository tests (`core-data`):** with `MockWebServer` (`core-testing`) —
  submit success writes to Room and returns domain; list/detail upsert; GET retry
  on transient 5xx; no retry on POST; 409 handled as success; 401→refresh→retry;
  offline ⇒ stale from Room.
- **ViewModel tests:** `RefundSubmitViewModel` validation matrix (amount > max,
  amount ≤ 0, missing reason, note > 500), double-submit guard reuses idempotency
  key, success/failure transitions; `RefundListViewModel` refresh/stale/error;
  `RefundDetailViewModel` load + refresh. Use `kotlinx-coroutines-test` +
  `Turbine` for StateFlow assertions.
- **Compose UI tests:** submit button enablement, inline validation errors, stale
  banner rendering, list empty/loaded/error states, detail status timeline,
  TalkBack/semantics assertions.
- **Acceptance test:** end-to-end against `MockWebServer` proving "refund request
  submits + tracks" — submit a refund, observe it in the list as `pending`, then
  fetch detail showing updated status.

## 12. Dependencies & Sequencing

- **Depends on AND-223 (Billing API + DTOs, P0):** authenticated billing OkHttp
  client, CSRF/refresh interceptors, shared error-detail decoder, `ApiResult`,
  and the `Transaction` model the refund form targets. AND-244 cannot land until
  AND-223's `core-network` billing surface and `/ui/billing/*` wiring exist.
- Transitively depends on the auth/session stack (AND-027 chain via AND-223) and
  on `core-data`/Room and `core-ui` Material 3 components.
- **Blocks:** none listed in the backlog.
- **Sequencing:** implement DTOs+mappers+tests → repository+Room+tests →
  ViewModels+tests → Compose screens+nav → UI tests. Reconcile contract with
  `/openapi.json` at step 1.

## 13. Risks & Open Questions

- **R1 — Exact endpoint shape unknown.** Paths/fields above are inferred from the
  web `refundRequests.ts`; must be verified against `/openapi.json`. Mitigation:
  contract-reconcile task before coding; DTOs isolated behind mappers.
- **R2 — Partial vs full refunds.** Whether the backend accepts `amount_cents`
  for partial refunds and how it validates against the transaction balance is
  unconfirmed. Mitigation: feature-flag partial-amount field; default to
  full-refund-only if backend rejects amounts.
- **R3 — Status enum set.** Backend status vocabulary may differ from the assumed
  set; `UNKNOWN` fallback prevents crashes but labels may be generic until
  confirmed.
- **R4 — Pagination presence.** List may or may not be cursor-paginated; design
  supports both (single fetch vs Paging 3). Confirm from OpenAPI.
- **R5 — Idempotency header support.** If the backend ignores `Idempotency-Key`,
  the in-flight-disable guard is the only duplicate protection; 409 handling
  covers server-side de-dup.
- **OQ:** Is there a per-transaction "refundable amount" field on `Transaction`
  (from AND-223) to validate against, or must the client allow any amount and
  defer to server validation?

## 14. Acceptance Criteria

- AC-1. A user can submit a refund request for a transaction; on success it
  appears in the refund list with status `pending`. (Backlog: "Refund request
  submits.")
- AC-2. The user can view their refund requests and open any request to see its
  current status, which updates on refresh. (Backlog: "+ tracks.")
- AC-3. Refund DTOs round-trip correctly (submit/list/status) with snake_case
  mapping and unknown-value fallbacks, proven by unit tests.
- AC-4. Submit is validated client-side (reason required, amount within bounds,
  note ≤ 500) and disabled until valid and online; double-submit cannot create
  duplicates.
- AC-5. Offline/failed fetch shows cached data with a stale banner; no-cache
  failure shows an error/empty state with retry.
- AC-6. `401` triggers a single session refresh + retry; idempotent GETs retry
  with bounded backoff; submit does not auto-retry.
- AC-7. No refund amounts, notes, or transaction ids appear in logs or analytics.
- AC-8. Screens pass TalkBack traversal and use no hardcoded strings.

## 15. Definition of Done

- `RefundApi`, DTOs, mappers, `RefundRepository`/Room, three ViewModels, and
  three Compose screens implemented under `com.testlogon.android` in the
  `feature-billing`/`core-*` modules.
- Contract reconciled against `/openapi.json` and `refundRequests.ts`; any
  divergences from this spec documented in the PR.
- Unit, repository, ViewModel, and Compose UI tests pass in CI; the end-to-end
  submit-then-track acceptance test passes against `MockWebServer`.
- Lint/detekt/ktlint clean; no cleartext-HTTP allowance leaks into release;
  release logging at `NONE` for refund paths.
- Strings localized; accessibility checks pass.
- PR reviewed and merged to `android-port` with AND-244 referenced; depends-on
  AND-223 satisfied at merge time.
