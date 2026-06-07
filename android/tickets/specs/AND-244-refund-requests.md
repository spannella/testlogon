---
id: AND-244
title: Refund requests
milestone: M5
epic: E33
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
user can open a refund form, select/confirm the target transaction, enter a
free-text **reason** (the only required text field; **10–2000 chars** per the
backend `RefundRequestIn` schema), optionally enter an amount (partial refund),
and submit. On success the new request appears in the list with status `pending`.
**[CORRECTED]** The earlier draft described `reason` as an enum and a separate
`note` field; the authoritative backend schema and web client use a single
free-text `reason` string (min 10 / max 2000) and have **no** `note` field.

FR-2. **List refund requests.** The user can view all of their refund requests
with amount, reason, status, optional `transaction_type`, optional `admin_notes`,
and a `created_at` timestamp. **[CORRECTED]** The backend `GET
/ui/billing/refund-requests` accepts **only a `limit` query param (no cursor)**
and returns `{ "items": [...] }` with **no `next_cursor`** — so this is a single
bounded fetch (web uses `limit=100`), **not** Paging 3. The response carries no
server-side ordering guarantee; the client sorts newest-first by `created_at`. The
list supports pull-to-refresh.

FR-3. **Track status.** The user can open a single refund request to see its
current status, amount, reason, and admin decision note. **[CORRECTED]** The
backend `RefundRequestOut` returns **no status history/timeline** and **no
separate "resolved amount"** field — there is one `amount_cents`, one `status`
string, an optional `admin_notes` (the decision note), and a nullable
`completed_at`. A detail GET endpoint (`GET
/ui/billing/refund-requests/{request_id}`) exists and may be used to re-fetch a
single request; the web reference renders all fields inline in the list card and
has no dedicated detail page. Status is re-fetched on screen open and on
pull-to-refresh.

FR-4. **Validation.** Client validates before submit: **reason length ≥ 10 and
≤ 2000 chars** (the web client disables submit while `reason.length < 10`), and if
a partial amount is entered it must be a positive integer number of cents
(`amount_cents` minimum 1 per schema). **[CORRECTED]** The previous "note ≤ 500
chars" rule does not match the contract; there is no `note` field and the text cap
is on `reason` (10–2000). **[UNVERIFIED ASSUMPTION]** The "amount ≤ refundable
transaction amount" check is **not** enforced by the web client and there is **no
refundable-amount field** on `LedgerEntry`; if implemented it must be a
client-side convenience only, with the server as the source of truth (see OQ in
§13). Submit button disabled until valid. Server-side `422` validation errors are
surfaced inline.

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

// [CORRECTED] path is /ui/billing/refund-requests (not /ui/billing/refunds);
// the list takes only `limit` (no cursor) and returns { items: [...] }.
interface RefundApi {
    @POST("ui/billing/refund-requests")
    suspend fun submitRefund(
        @Body body: RefundRequestInDto,
    ): RefundRequestOutDto                 // 201 Created

    @GET("ui/billing/refund-requests")
    suspend fun listRefunds(
        @Query("limit") limit: Int = 100,
    ): RefundListDto                       // { items: [...] }

    @GET("ui/billing/refund-requests/{requestId}")
    suspend fun getRefund(@Path("requestId") requestId: String): RefundRequestOutDto
}
```

Calls go through the shared authenticated OkHttp client (cookie jar + CSRF
interceptor + `/ui/session/refresh` retry) configured in AND-223 / core-network.
The `X-CSRF-Token` header is injected centrally by the shared CSRF interceptor
(verified: the web client reads the `ui_csrf` cookie and sets `X-CSRF-Token` on
every request, so it does not need to be a per-method `@Header`).
**[UNVERIFIED ASSUMPTION → DROPPED]** No explicit `@Header("Idempotency-Key")` is
shown: the web client sends no idempotency header and the OpenAPI parameters for
`POST /ui/billing/refund-requests` are only `user_sub, X-SESSION-ID,
X-IMPERSONATION-TOKEN` (no `Idempotency-Key`). The header MAY still be added
defensively, but the backend is not known to honor it; duplicate protection must
rely on the in-flight submit guard (§6) rather than server de-dup (see §13 R5).

### 4.2 Domain models (`core-model`)

```kotlin
// [CORRECTED] aligned to backend RefundRequestOut: id field is
// `refund_request_id`; `reason` is free-text (not an enum); the txn ref is
// `transaction_entry_id` and is optional; there is a single `amount_cents` (no
// separate "resolved" amount); decision note is `admin_notes`; timestamps are
// epoch *seconds* numbers; there is no status history array.
data class RefundRequest(
    val id: String,                    // refund_request_id
    val transactionEntryId: String?,   // transaction_entry_id (optional on Out)
    val status: RefundStatus,
    val reason: String,                // free-text, 10..2000 chars
    val amountCents: Long,             // amount_cents (always present on Out)
    val currency: String,              // ISO-4217, e.g. "USD"
    val transactionType: String?,      // transaction_type (optional)
    val adminNotes: String?,           // admin_notes (decision note, nullable)
    val createdAt: Instant,            // from created_at epoch seconds
    val completedAt: Instant?,         // from completed_at epoch seconds, nullable
    val requesterUserId: String?,      // requester_user_id (optional)
)

// [CORRECTED] Observed web status vocabulary: pending, approved, completed,
// denied. (No `refunded`/`failed` seen in the reference app.) UNKNOWN is the
// forward-compat fallback for unrecognized server strings.
enum class RefundStatus { PENDING, APPROVED, COMPLETED, DENIED, UNKNOWN }
```

`UNKNOWN` is the fallback for unrecognized server status strings (forward-compat).
**[CORRECTED]** The previous `RefundReason` enum and `RefundStatusEvent` history
type are removed: `reason` is a plain string and the backend returns no timeline.

### 4.3 Repository (`core-data`)

```kotlin
interface RefundRepository {
    fun observeRefunds(): Flow<List<RefundRequest>>          // Room-backed, reactive
    suspend fun refreshRefunds(): ApiResult<Unit>
    suspend fun submitRefund(input: SubmitRefundInput): ApiResult<RefundRequest>
    suspend fun getRefund(id: String): ApiResult<RefundRequest>
}

// [CORRECTED] mirrors RefundRequestIn: { transaction_entry_id, reason, amount_cents? }
data class SubmitRefundInput(
    val transactionEntryId: String,   // -> transaction_entry_id (required)
    val reason: String,               // -> reason (free-text, 10..2000)
    val amountCents: Long?,           // -> amount_cents; null => full refund
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
    fun onReasonChange(s: String)         // [CORRECTED] reason is free-text, not enum
    fun onAmountChange(raw: String)
    // [CORRECTED] no onNoteChange — there is no `note` field in the contract
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

All paths/shapes below are **verified** against `openapi.index.txt`,
`components.schemas.RefundRequestIn`, and the web client
(`src/api/endpoints/refundRequests.ts`, `src/api/types.ts:RefundRequestOut`).

**Submit — `POST /ui/billing/refund-requests`** (op
`submit_refund_request_ui_billing_refund_requests_post`, `201 Created`,
req=`RefundRequestIn`).

Headers: cookies + `X-CSRF-Token: <ui_csrf>` (set centrally by the CSRF
interceptor). No `Idempotency-Key` (see §4.1).

Request body (`RefundRequestIn`):
```json
{
  "transaction_entry_id": "entry_01H...",
  "reason": "Charged twice for the same item",
  "amount_cents": 1299
}
```
`transaction_entry_id` and `reason` (min 10 / max 2000 chars) are **required**;
`amount_cents` is optional (`minimum: 1`), omitted/`null` ⇒ full refund.
`201` returns a `RefundRequestOut`:
```json
{
  "refund_request_id": "rfnd_01H...",
  "status": "pending",
  "amount_cents": 1299,
  "currency": "USD",
  "reason": "Charged twice for the same item",
  "transaction_type": "charge",
  "transaction_entry_id": "entry_01H...",
  "created_at": 1749124800,
  "admin_notes": null,
  "completed_at": null,
  "requester_user_id": "usr_01H..."
}
```
**[CORRECTED]** `created_at`/`completed_at` are **epoch-seconds integers**, not ISO
strings (web renders `created_at * 1000` via `new Date(...)`). Required Out fields:
`refund_request_id, status, amount_cents, currency, reason, created_at`. Optional:
`transaction_type, transaction_entry_id, admin_notes, completed_at,
requester_user_id`.

**List — `GET /ui/billing/refund-requests?limit=100`** (op
`list_my_refund_requests_ui_billing_refund_requests_get`; **only `limit` param,
no cursor**):
```json
{ "items": [ { /* RefundRequestOut */ } ] }
```
**[CORRECTED]** No `next_cursor` field — response is just `{ items }`.

**Status/detail — `GET /ui/billing/refund-requests/{request_id}`** (op
`get_refund_request_detail_...`) → single `RefundRequestOut`.

**Moshi DTOs** (`core-network`) use `@Json(name = ...)` for snake_case mapping;
`RefundRequestInDto`, `RefundRequestOutDto`, `RefundListDto`. Mappers
`RefundRequestOutDto.toDomain()` convert epoch-seconds to `Instant`
(`Instant.ofEpochSecond(...)`) and map unknown `status` strings to `UNKNOWN`.
(There is no reason-enum or history DTO to map — see §4.2.)

**Errors:** all refund endpoints declare `422:HTTPValidationError` (FastAPI
standard: `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`).
`detail` may also be a `string` or an object `{code, ...}` — reuse the shared
`core-network` error-detail decoder (mirrors web `normalizeErrorDetail`, which
handles `string | [{msg}] | {code,...}`) to produce `ApiResult.Error(message,
code?)`. **[UNVERIFIED ASSUMPTION]** `409 duplicate` is **not** documented in
OpenAPI (only `200/201` and `422`) and the web client has no 409 branch; treat any
409 handling as defensive/optional, not a contract guarantee (see §7, §13 R5).

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
        // [CORRECTED] reason is free-text String (no enum); no separate `note`
        val reasonText: String, val amountText: String,
        val reasonError: String?, val amountError: String?,
        val submitEnabled: Boolean, val isSubmitting: Boolean,
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
- **Duplicate-submit guard.** The primary protection is the in-flight submit
  guard: `submit()` is a no-op while `isSubmitting`, and the button is disabled.
  An optional client-generated key (`UUID.randomUUID()`) may be held in
  `SavedStateHandle` so a config-change/process recreation during an in-flight
  submit reuses it — **but [UNVERIFIED] the backend does not document an
  `Idempotency-Key` header** (see §4.1, §13 R5), so this is best-effort only.

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
- **409 duplicate:** **[UNVERIFIED — defensive only]** OpenAPI documents only
  `200/201` and `422` for these endpoints and the web client has no 409 branch. If
  a 409 is ever returned, treat it as benign — refresh the list rather than
  showing an error — but do not rely on it as a contract.
- **422 validation:** decode `HTTPValidationError.detail[].msg` and surface inline
  on the offending field (`reason` too short, `amount_cents < 1`, etc.).
- **Unknown status strings / nullable fields:** never crash; map unknown `status`
  to `UNKNOWN` and render nullable fields (`admin_notes`, `completed_at`,
  `transaction_entry_id`) gracefully when absent.

## 8. Security & Privacy

- All refund calls require the authenticated cookie session and `X-CSRF-Token`;
  no refund endpoint is reachable unauthenticated.
- **Transport:** dev backend is plaintext HTTP, permitted only via the existing
  debug `networkSecurityConfig` cleartext allowance for `18.222.237.167`.
  Production builds MUST require HTTPS (no cleartext) — refund payloads contain
  billing/transaction references.
- Do **not** log full request/response bodies for refund endpoints; redact
  `transaction_entry_id`, amounts, and the free-text `reason`/`admin_notes` in any
  diagnostic logging (see §10).
- The refund `reason` is user free-text; treat as untrusted, render as plain text
  (no HTML), enforce the 10–2000-char bounds client-side and rely on server
  validation. **[CORRECTED]** Cap is 10–2000 on `reason`, not "500 on a note".
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
  `RefundRequestInDto`/`RefundRequestOutDto`/`RefundListDto`; snake_case mapping
  (`transaction_entry_id`, `amount_cents`, `refund_request_id`, `admin_notes`,
  `completed_at`); omitted `amount_cents` ⇒ full refund; unknown `status` string ⇒
  `UNKNOWN`; **epoch-seconds → `Instant`** parsing; nullable `completed_at`/
  `admin_notes`. This is the AND-223 "payloads map (tested)" lineage applied to
  refunds. **[CORRECTED]** No reason-enum/`OTHER` mapping (reason is free-text).
- **Repository tests (`core-data`):** with `MockWebServer` (`core-testing`) —
  submit success writes to Room and returns domain; list/detail upsert; GET retry
  on transient 5xx; no retry on POST; 409 handled as success; 401→refresh→retry;
  offline ⇒ stale from Room.
- **ViewModel tests:** `RefundSubmitViewModel` validation matrix (reason < 10
  chars, reason > 2000 chars, amount ≤ 0 / non-integer), double-submit guard
  (no-op while submitting), success/failure transitions; `RefundListViewModel`
  refresh/stale/error;
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
- **R3 — Status enum set.** **[PARTIALLY RESOLVED]** The web reference handles
  `pending`, `approved`, `completed`, `denied` (others fall to a neutral badge).
  `RefundRequestOut.status` is a free-form string in the schema, so the full
  vocabulary is not enumerated server-side; `UNKNOWN` fallback prevents crashes and
  labels may be generic for unrecognized values.
- **R4 — Pagination presence.** **[RESOLVED]** Not paginated: `GET
  /ui/billing/refund-requests` takes only `limit` and returns `{ items }` (no
  cursor). Single bounded fetch; **drop Paging 3** for this list.
- **R5 — Idempotency header support.** **[RESOLVED — not supported]** OpenAPI lists
  no `Idempotency-Key` param and the web client sends none; 409 is **not** a
  documented response. The in-flight-disable guard is the only reliable duplicate
  protection. Any `Idempotency-Key`/409 handling is defensive, not contractual.
- **OQ:** **[RESOLVED]** There is **no** per-transaction "refundable amount" field
  — `LedgerEntry` exposes `amount_cents`/`ts`/`entry_id` only, and the web client
  does not validate the requested amount against it. The client should allow any
  positive `amount_cents` (≥ 1) and defer to server `422` validation; an optional
  "≤ transaction amount" hint may use the source `LedgerEntry.amount_cents`.

## 14. Acceptance Criteria

- AC-1. A user can submit a refund request for a transaction; on success it
  appears in the refund list with status `pending`. (Backlog: "Refund request
  submits.")
- AC-2. The user can view their refund requests and open any request to see its
  current status, which updates on refresh. (Backlog: "+ tracks.")
- AC-3. Refund DTOs round-trip correctly (submit/list/status) with snake_case
  mapping and unknown-value fallbacks, proven by unit tests.
- AC-4. Submit is validated client-side (reason 10–2000 chars, optional
  `amount_cents` ≥ 1) and disabled until valid and online; double-submit (re-tap
  while in flight) cannot create duplicate requests. **[CORRECTED]** from "note ≤
  500".
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
`openapi.index.txt` (METHOD /path lines), `openapi.pretty.json`
(`components.schemas.*`), and the web reference under `reference/src/`.

1. **Submit endpoint is `POST /ui/billing/refund-requests` (201).** Verdict:
   **Corrected** (draft had `POST /ui/billing/refunds`). Source: `openapi.index.txt`
   line 1194 `POST /ui/billing/refund-requests | op=submit_refund_request_... |
   req=RefundRequestIn | resp=201:;422:HTTPValidationError`; `src/api/endpoints/
   refundRequests.ts: submitRefundRequest`.
2. **List endpoint is `GET /ui/billing/refund-requests?limit=N`, returns `{ items }`,
   no cursor/pagination.** Verdict: **Corrected** (draft had `?limit&cursor` +
   `next_cursor` + Paging 3). Source: `openapi.index.txt` line 1193
   (`params=limit,...`); `src/api/endpoints/refundRequests.ts: listMyRefundRequests`
   (`api.get<{ items: RefundRequestOut[] }>(..., { limit })`).
3. **Detail endpoint is `GET /ui/billing/refund-requests/{request_id}` → single
   `RefundRequestOut`.** Verdict: **Verified** (path corrected from `/refunds/{id}`).
   Source: `openapi.index.txt` line 1195
   `op=get_refund_request_detail_...`; `src/api/endpoints/refundRequests.ts:
   getRefundRequest`.
4. **Request body `RefundRequestIn` = `{ transaction_entry_id (req), reason (req,
   10–2000), amount_cents? (≥1) }`.** Verdict: **Corrected** (draft had
   `transaction_id`, enum `reason`, and a `note` field). Source:
   `openapi.pretty.json: components.schemas.RefundRequestIn` (required
   `[transaction_entry_id, reason]`; `reason` minLength 10/maxLength 2000;
   `amount_cents` minimum 1, nullable); `src/api/types.ts: RefundRequestIn`.
5. **`reason` is free-text, not an enum; min 10 chars enforced client-side.**
   Verdict: **Corrected**. Source: `src/api/types.ts: RefundRequestIn.reason:
   string`; `src/pages/billing/RefundRequestDialog.tsx` (Textarea, `disabled={reason
   .length < 10 ...}`).
6. **There is no `note` field anywhere in the contract.** Verdict: **Corrected**.
   Source: absence in `components.schemas.RefundRequestIn` and `src/api/types.ts:
   RefundRequestIn`/`RefundRequestOut`.
7. **Response `RefundRequestOut` fields: `refund_request_id, status, amount_cents,
   currency, reason, created_at` (required) + `transaction_type,
   transaction_entry_id, admin_notes, completed_at, requester_user_id` (optional).**
   Verdict: **Corrected** (draft had `id`, `transaction_id`,
   `requested_amount_cents`, `resolved_amount_cents`, `note`, `decision_note`,
   `updated_at`, `history`). Source: `src/api/types.ts: RefundRequestOut`.
8. **`created_at`/`completed_at` are epoch-seconds integers, not ISO-8601 strings.**
   Verdict: **Corrected**. Source: `src/api/types.ts: RefundRequestOut.created_at:
   number`; `src/pages/billing/RefundRequestsPage.tsx: formatDate` (`new Date(ts *
   1000)`).
9. **No status history / timeline and no separate "resolved amount".** Verdict:
   **Corrected** (draft had `history[]` + `resolved_amount_cents`). Source: absence
   in `src/api/types.ts: RefundRequestOut`; `RefundRequestsPage.tsx` renders only
   status/amount/reason/admin_notes/created_at.
10. **Decision note is `admin_notes` (nullable).** Verdict: **Corrected** (draft
    `decision_note`). Source: `src/api/types.ts: RefundRequestOut.admin_notes`;
    `RefundRequestsPage.tsx` ("Admin notes:" block).
11. **Observed status vocabulary: `pending, approved, completed, denied`** (server
    type is free-form string). Verdict: **Verified/Corrected** (draft enum had
    `refunded/failed`, not seen). Source: `RefundRequestsPage.tsx: statusVariant`;
    `src/api/types.ts: RefundRequestOut.status: string`.
12. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` on every request (set
    centrally, not per-method).** Verdict: **Verified**. Source: `src/api/client.ts`
    lines 167–171 (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
13. **401 → single `POST /ui/session/refresh` then retry once; final failure logs
    out.** Verdict: **Verified**. Source: `src/api/client.ts` lines 121–237;
    `openapi.index.txt` line 1847 `POST /ui/session/refresh`.
14. **Cookie session auth via `/ui/session/start` → MFA → `/ui/session/finalize` →
    `/ui/me`.** Verdict: **Verified**. Source: `openapi.index.txt` lines 1848
    (`/ui/session/start`, resp `UiSessionStartResp`), 1845 (`/ui/session/finalize`,
    req `UiSessionFinalizeReq`), 1638 (`/ui/me`).
15. **Errors: `422:HTTPValidationError` with `detail[].msg`; web decoder also handles
    `string` / `{code}`.** Verdict: **Verified**. Source: `resp=...;422:
    HTTPValidationError` on lines 1193–1195; `src/api/client.ts: normalizeErrorDetail`
    (handles `string | [{msg}] | {code}`).
16. **No `Idempotency-Key` header on submit.** Verdict: **Corrected /
    Unverified-assumption removed**. Source: `openapi.index.txt` line 1194
    `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` (no idempotency param);
    `src/api/client.ts` (sends no such header).
17. **No documented `409` response for refund endpoints.** Verdict:
    **Unverified-assumption** (kept only as defensive handling). Source: `resp=`
    column on `openapi.index.txt` lines 1193–1195 lists only `200/201` + `422`;
    `RefundRequestDialog.tsx onError` has no 409 branch.
18. **No per-transaction "refundable amount"; client defers amount validation to
    server.** Verdict: **Verified** (answers §13 OQ). Source: `src/api/types.ts:
    LedgerEntry` (`amount_cents, ts, [key]: unknown`, no refundable field);
    `RefundRequestDialog.tsx` sends amount without local cap.
19. **Transaction reference taken from `LedgerEntry.entry_id`, sent as
    `transaction_entry_id`.** Verdict: **Verified**. Source:
    `RefundRequestDialog.tsx` (`entryId = transaction.entry_id` →
    `transaction_entry_id: entryId`).
20. **Dev host is plaintext HTTP at `18.222.237.167:8000` (cleartext debug-only).**
    Verdict: **Unverified-assumption** (carried from spec/source ticket; no
    independent confirmation in OpenAPI/web for cleartext policy). Treat as a build
    config requirement, not a contract fact.
21. **Stack/framework choices (Compose, Hilt, Retrofit/OkHttp/Moshi, Room, Paging,
    DataStore).** Verdict: **Unverified-assumption (framework ref)** — project
    convention, not derivable from backend/web sources. Android framework refs:
    https://developer.android.com/jetpack/compose,
    https://square.github.io/retrofit/, https://github.com/square/okhttp,
    https://developer.android.com/training/data-storage/room,
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview.
22. **`networkSecurityConfig` cleartext allowance for debug only.** Verdict:
    **Unverified-assumption (framework ref)**. Ref:
    https://developer.android.com/training/articles/security-config.

### Corrections made

- Endpoint base corrected `/ui/billing/refunds` → `/ui/billing/refund-requests`
  (submit/list/detail) — §3, §4.1, §5. (Citations 1–3)
- Request body: `transaction_id` → `transaction_entry_id`; `reason` enum → free-text
  string (10–2000); removed `note`; `amount_cents` ≥ 1 — §3 FR-1/FR-4, §4.1–4.4,
  §5, §6. (Citations 4–6)
- Response shape rebuilt to real `RefundRequestOut`: `id`→`refund_request_id`,
  `requested_amount_cents`→`amount_cents`, dropped `resolved_amount_cents`,
  `note`→(none), `decision_note`→`admin_notes`, dropped `updated_at`/`history`,
  added `transaction_type`/`completed_at`/`requester_user_id` — §3 FR-3, §4.2, §5.
  (Citations 7, 9, 10)
- Timestamps corrected ISO-8601 → epoch-seconds integers (`Instant.ofEpochSecond`)
  — §4.2, §5, §11. (Citation 8)
- List de-paginated: removed `cursor`/`next_cursor`/Paging 3; single `limit` fetch —
  §3 FR-2, §4.1, §5, §13 R4. (Citation 2)
- Status enum trimmed to observed `PENDING/APPROVED/COMPLETED/DENIED/UNKNOWN`
  (removed `REFUNDED/FAILED`) — §4.2, §13 R3. (Citation 11)
- Removed `RefundReason` enum and `RefundStatusEvent` history type — §4.2, §4.4, §6.
- `Idempotency-Key` header and `409`-as-success handling demoted to defensive /
  unverified; primary dedup is the in-flight guard — §4.1, §6, §7, §13 R5.
  (Citations 16, 17)
- Validation rule "note ≤ 500" corrected to "reason 10–2000" — §3 FR-4, §8, §11,
  §14 AC-4. (Citations 4, 5)
- §13 OQ resolved: no refundable-amount field; defer to server. (Citation 18)

### Open assumptions

- **Idempotency-Key honored by backend** — unverifiable: not in OpenAPI params and
  not sent by the web client. Treated as best-effort; relying on in-flight guard.
  (Citation 16)
- **`409` duplicate response** — unverifiable: OpenAPI documents only `200/201`/`422`
  for these ops; kept only as defensive code. (Citation 17)
- **Exact full status vocabulary** — `status` is a free-form server string; only
  four values observed in web. `UNKNOWN` fallback covers the rest. (Citation 11)
- **Partial-refund acceptance/validation rules (§13 R2)** — schema allows
  `amount_cents ≥ 1` but server-side balance validation behavior is undocumented;
  client defers to `422`. (Citations 4, 18)
- **Cleartext-HTTP dev host policy & `networkSecurityConfig`** — environment/build
  assumptions, not derivable from API/web sources. (Citations 20, 22)
- **Android stack choices** — project convention, framework refs only. (Citation 21)

## 17. Test Plan

Test targets: **JVM** = JVM unit / Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35) in CI; **deviceA15** = physical
Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34,
arm64-v8a) on the build host. All HTTP cases use **MockWebServer** (no live dev
host). The refund feature has no camera/biometric/WebRTC/FCM/Telecom surface, so
most cases run on JVM or emu35; one ABI/API-parity case must run on **deviceA15**.

- **TC-AND-244-01 — Submit happy path (contract).** Type: contract/MockWebServer.
  Target: JVM (`RefundRepository` + `RefundApi` over MockWebServer). Preconditions:
  authenticated cookie+CSRF; MockWebServer enqueues `201` with a `RefundRequestOut`
  whose `status="pending"`. Steps: call `submitRefund(SubmitRefundInput(entryId,
  reason≥10, amount=1299))`; capture the recorded request. Expected: outbound
  `POST /ui/billing/refund-requests` with JSON `{transaction_entry_id, reason,
  amount_cents:1299}`, `X-CSRF-Token` header present, **no `cursor`/`note`/`note`
  fields**; result `ApiResult.Success(RefundRequest)` mapped (`id` from
  `refund_request_id`, `createdAt` from epoch seconds); row upserted to Room with
  `status=PENDING`. Traces: AC-1, AC-3.

- **TC-AND-244-02 — Full refund (omit amount).** Type: contract/MockWebServer.
  Target: JVM. Preconditions: as 01, `amount=null`. Steps: submit with null amount.
  Expected: request JSON **omits `amount_cents`** (or sends `null`); server `201`
  accepted; mapped success. Traces: AC-1, AC-3.

- **TC-AND-244-03 — DTO round-trip & epoch/enum/null mapping (unit).** Type: unit.
  Target: JVM (Moshi adapters + `toDomain`). Preconditions: fixture JSON for
  `RefundRequestOut` incl. snake_case keys, `created_at` epoch int, null
  `admin_notes`/`completed_at`/`transaction_entry_id`, and an unrecognized
  `status:"escalated"`. Steps: decode → map → re-encode `RefundRequestIn`. Expected:
  `refund_request_id→id`, `amount_cents→amountCents`, `admin_notes→adminNotes`,
  epoch→`Instant`, unknown status→`UNKNOWN`, nulls preserved; no crash. Traces:
  AC-3.

- **TC-AND-244-04 — List fetch maps `{items}` with no pagination.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: MockWebServer `200` with
  `{ "items": [out1, out2] }` (no `next_cursor`). Steps: `refreshRefunds()`.
  Expected: request is `GET /ui/billing/refund-requests?limit=100` (single fetch,
  **no `cursor` param**); both items upserted to Room; `observeRefunds()` emits 2
  rows sorted newest-first by `createdAt`. Traces: AC-2, AC-3.

- **TC-AND-244-05 — Detail fetch updates status.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: a `pending` row cached; MockWebServer `200` for
  `GET .../refund-requests/{id}` returns same id with `status="approved"` and
  `admin_notes` set. Steps: `getRefund(id)`. Expected: path includes the id; Room
  row updated to `APPROVED` with `adminNotes`; `observeRefunds()`/detail state
  reflect the change on refresh. Traces: AC-2.

- **TC-AND-244-06 — 422 validation surfaces inline.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MockWebServer `422` body `{"detail":[{"loc":["body",
  "reason"],"msg":"String should have at least 10 characters","type":
  "string_too_short"}]}`. Steps: submit. Expected: `ApiResult.Error` carrying the
  decoded `msg`; no Room write; no auto-retry on the POST. Traces: AC-3, AC-4,
  AC-6.

- **TC-AND-244-07 — Submit validation matrix (ViewModel).** Type: unit. Target: JVM
  (`RefundSubmitViewModel`, coroutines-test + Turbine). Preconditions: VM seeded
  with a `transactionEntryId`. Steps: drive `onReasonChange`/`onAmountChange` with
  reason="" , reason of 9 chars, reason of 2001 chars, valid reason + amount "0",
  amount "abc", and a fully valid input. Expected: `submitEnabled=false` until
  reason length ∈ [10,2000] and amount (if present) is a positive integer; matching
  `reasonError`/`amountError`; enabled only when valid. Traces: AC-4.

- **TC-AND-244-08 — Double-submit guard.** Type: unit. Target: JVM
  (`RefundSubmitViewModel`). Preconditions: repo `submitRefund` suspends (in
  flight). Steps: call `submit()` twice before the first completes. Expected: exactly
  **one** repository/network call; second is a no-op while `isSubmitting`; on
  recreation via `SavedStateHandle` no duplicate fires. Traces: AC-4.

- **TC-AND-244-09 — Offline submit blocked.** Type: unit/integration. Target: JVM.
  Preconditions: connectivity reported offline. Steps: open submit form, fill valid
  input, attempt submit. Expected: submit disabled with inline offline message; no
  network call attempted. Traces: AC-4, AC-5.

- **TC-AND-244-10 — Flaky dev-host / offline list → stale cache.** Type:
  contract/MockWebServer. Target: JVM (`RefundRepository` + `RefundListViewModel`).
  Preconditions: Room has cached rows; MockWebServer first returns rows, then is
  shut down / returns `503` (simulating the unreliable dev host). Steps: initial
  refresh succeeds, second refresh fails. Expected: cached rows still emitted,
  `isStale=true`, no crash; GET path retried with bounded backoff (max 2) before
  giving up; with empty cache instead, error/empty state with retry. Traces: AC-5,
  AC-6.

- **TC-AND-244-11 — 401 → single refresh → retry.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: authenticated; MockWebServer scripts `401` on the
  first list call, `200` on `POST /ui/session/refresh`, `200` on the retried list.
  Steps: `refreshRefunds()`. Expected: exactly one `/ui/session/refresh`, original
  request retried once and succeeds; a second consecutive `401` yields
  `ApiResult.Error` and routes to re-auth (no infinite loop). Traces: AC-6.

- **TC-AND-244-12 — No PII in logs/analytics.** Type: unit. Target: JVM (fake logger
  + analytics facade). Preconditions: capture all log lines and analytics events
  across a submit+list+detail flow with a real `reason`, amount, and
  `transaction_entry_id`. Steps: run the flow; assert captured output. Expected:
  no `reason` text, amount value, or `transaction_entry_id`/`refund_request_id`
  appears; only enum/status/result codes and durations; OkHttp logging ≤ `HEADERS`
  in debug, `NONE` in release. Traces: AC-7.

- **TC-AND-244-13 — Compose UI states + inline validation + stale banner.** Type:
  Compose-UI (instrumented). Target: emu35. Preconditions: app under
  `createAndroidComposeRule`. Steps: render submit screen (assert button disabled,
  short-reason error), then list screen in loaded/empty/error+stale variants.
  Expected: submit button reflects enablement; `reason`-too-short error shown; empty
  state and stale banner render; detail shows status chip + admin notes. Traces:
  AC-1, AC-2, AC-4, AC-5.

- **TC-AND-244-14 — Accessibility / TalkBack & no hardcoded strings.** Type:
  Compose-UI (instrumented) + lint. Target: emu35. Preconditions: list + submit +
  detail composables. Steps: assert semantics — form fields have labels, submit
  button announces disabled state/reason, status chips expose text (not color-only),
  touch targets ≥ 48dp, full TalkBack traversal order; run lint to confirm all
  visible text comes from `strings.xml` (`refund_*`). Expected: all assertions pass;
  no hardcoded UI strings. Traces: AC-8.

- **TC-AND-244-15 — ABI/API parity smoke on physical device.** Type:
  instrumented/e2e. Target: **deviceA15 (MUST run on physical device)** — arm64-v8a,
  API 34 vs the emulator's x86_64/API 35. Preconditions: app installed on
  `R5CX821TA9R`; MockWebServer reachable from device (adb reverse). Steps: run the
  submit-then-track e2e (submit → see `pending` in list → fetch detail) on the
  device. Expected: identical behavior to emu35 — no arm64/x86 (Moshi/codegen) or
  API-34/35 differences in JSON mapping, epoch-time formatting, or rendering.
  Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (submit → pending in list) | TC-01, TC-02, TC-13, TC-15 |
| AC-2 (view + track status on refresh) | TC-04, TC-05, TC-13, TC-15 |
| AC-3 (DTO round-trip + fallbacks) | TC-01, TC-02, TC-03, TC-04, TC-06, TC-15 |
| AC-4 (client validation + no dup) | TC-06, TC-07, TC-08, TC-09, TC-13 |
| AC-5 (offline/stale + empty/error) | TC-09, TC-10, TC-13 |
| AC-6 (401 refresh; GET retry; no POST retry) | TC-06, TC-10, TC-11 |
| AC-7 (no PII in logs/analytics) | TC-12 |
| AC-8 (TalkBack + no hardcoded strings) | TC-14 |
