---
id: AND-249
title: Invoices/tax ViewModels
milestone: M5
epic: E33
priority: P2
size: M
depends_on: [AND-243]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-249 — Invoices/tax ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state holders for the Invoices and Tax
surfaces of the TestLogon native Android app: `InvoicesViewModel`,
`InvoiceDetailViewModel`, and `TaxViewModel`. AND-243 (Invoices) wires the network
endpoints, Moshi DTOs, and repository plumbing for `invoices.ts`; this ticket builds
the Compose-facing layer on top of that data layer. The goal is to expose
`StateFlow<UiState>` streams and a `Flow<PagingData<…>>` paging stream that the
feature screens (owned by downstream UI tickets in E33) collect, with all state
transitions, retry semantics, and error mapping centralized in the ViewModels and
covered by unit tests.

Per the source ticket, the **Scope** is "State + paging" and the **Acceptance** is
"Unit-tested." Concretely this means: (a) a list ViewModel backed by Paging 3 over
the paginated invoices endpoint; (b) a detail ViewModel that loads a single invoice
and exposes the "email this invoice" action; (c) a tax ViewModel exposing read-only
tax summary / line items derived from the invoice tax data; and (d) deterministic,
JVM-only unit tests using fake repositories that prove each state machine and the
paging pipeline behave correctly. No new screens, navigation, or Composables are in
scope here — only the ViewModels, their `UiState` models, and tests.

## 2. Context & References

- Module: `feature-invoices` (Compose feature module), depending on `core-data`,
  `core-model`, `core-network`, `core-ui`, and `core-testing` per the project module
  layering (`app -> feature-* -> core-*`).
- Package root: `com.testlogon.android.feature.invoices`.
- Upstream data layer (AND-243): `InvoicesRepository`, `InvoiceDto`/domain models,
  and the Retrofit `InvoicesApi`. This ticket consumes those interfaces; if a method
  needed here is missing, it is added in AND-243's surface and noted in section 12.
- Web reference: `src/api/endpoints/invoices.ts` (`listInvoices`, `getInvoice`,
  `emailInvoice`, `downloadInvoicePdf`), `src/api/types.ts` (`Invoice`,
  `InvoiceList`, `InvoiceEmailResult`, `InvoiceLineItem`), and the screens
  `src/pages/billing/InvoicesPage.tsx` + `src/pages/billing/InvoiceRow.tsx`. Backend
  OpenAPI at `/openapi.json` on the dev host `http://18.222.237.167:8000` (PLAINTEXT,
  unreliable). Note: the web invoice surface has **no separate detail screen** — the
  list row carries all fields and the email/download actions; the Android
  `InvoiceDetailViewModel` is a net-new convenience over the same `getInvoice` call.
- Auth is cookie-based with `X-CSRF-Token` echoing the `ui_csrf` cookie (verified in
  `src/api/client.ts`: the header is set on **every** request when the cookie is
  present, not only on mutations); on 401 the client refreshes via `POST
  /ui/session/refresh` once (verified: op `ui_session_refresh_ui_session_refresh_post`,
  method POST) then retries. All of that is handled in `core-network` and is
  transparent to these ViewModels.
- Conventions: `StateFlow<UiState>`, typed `ApiResult<T>`, FastAPI `detail` mapping
  (`string | [{msg}] | {code,...}`), ~20s timeouts, bounded backoff retry for
  idempotent GETs only.

## 3. Functional Requirements

FR-1. **Invoice list (paged).** `InvoicesViewModel` exposes
`val invoices: Flow<PagingData<InvoiceListItem>>` produced by Paging 3. The stream is
`cachedIn(viewModelScope)` so configuration changes do not re-fetch. Each list item
renders invoice number (`invoice_number`), creation date (`created_at`, epoch
seconds), total amount (`total_cents` + `currency`), and status. **Correction:** the
backend `status` is a free-form string defaulting to `"generated"` (the web app also
shows an `"emailed"` badge); the draft's `paid`/`open`/`void`/`overdue` enum is not
in the contract — model `status` as a string and map known values in the UI.

FR-2. **List load/empty/error/refresh states.** In addition to `PagingData` (which
carries its own `LoadState`), the ViewModel exposes a coarse
`StateFlow<InvoicesUiState>` derived for non-paging concerns (initial gate, global
banner). The screen drives refresh via `refresh()`, which calls `refresh()` on the
`LazyPagingItems` adapter; the ViewModel additionally exposes `retry()` for failed
append/prepend.

FR-3. **Filtering.** **Correction:** the backend filters by `type`
(`tip|unlock|subscription|shop|deposit`) and a `date_from`/`date_to` epoch range —
**not** by `status`, and there is no server-side free-text query. The web client
filters by invoice number **client-side**. `fun setFilter(filter: InvoiceFilter)`
updates a backing `MutableStateFlow` carrying `type` + date range (the server-backed
filters); the paging `Pager` is rebuilt reactively via `flatMapLatest` so changing
those starts a fresh paged stream. Any free-text invoice-number search must be a
client-side filter over loaded items (matching web behavior), not a query param.

FR-4. **Invoice detail.** `InvoiceDetailViewModel` is constructed with an
`invoiceId: String` (via `SavedStateHandle`), loads the invoice on init, and exposes
`StateFlow<InvoiceDetailUiState>` with `Loading`, `Success(invoice)`, and
`Error(message, retryable)`.

FR-5. **Email invoice.** The detail ViewModel exposes `fun emailInvoice()` invoking
`POST /ui/invoices/{invoice_number}/email` (**no request body**; verified against the
OpenAPI op and `src/api/endpoints/invoices.ts`, which calls `api.post(...)` with no
payload). The success response is `InvoiceEmailOut {ok, emailed_to, message}`. Email
send is a one-shot action surfaced as a `Channel`-backed `Flow<InvoiceDetailEvent>`
(`EmailSent(emailedTo)`, `EmailFailed(message)`) so it fires exactly once and survives
recomposition without re-emitting. **Correction:** the `toOverride: String?`
parameter in the draft has no backing in the contract — keep it only as an unverified
forward-looking hook (OQ-3, section 16); do not send it as a body field.

FR-6. **Tax summary.** `TaxViewModel` exposes `StateFlow<TaxUiState>` presenting a
read-only tax breakdown derived from the single invoice. **Correction:** the backend
exposes only scalar tax data on the invoice (`amount_cents`, `tax_cents`,
`total_cents`); there are **no** per-rate tax lines (`name`/`rate`/`amount`) and no
aggregate tax endpoint in the OpenAPI spec. The verified, implementable breakdown is:
taxable subtotal = `amount_cents`, total tax = `tax_cents`, grand total =
`total_cents` (all minor units). The per-rate-line design is an unverified product
assumption retained only as a future extension (section 16); it must not block this
ticket. `TaxViewModel` is constructed with `invoiceId` (the `invoice_number`) and
reuses `getInvoice`; there is no aggregate path.

FR-7. **Idempotent retry only.** GET-backed loads (list, detail, tax) are retryable
via `retry()`. The email POST is **not** auto-retried; the user re-triggers it
manually after `EmailFailed`.

## 4. Technical Design

All three ViewModels are `@HiltViewModel` annotated, constructor-injected with the
repository and a `CoroutineDispatcher` (`@IoDispatcher`) for testability.

```kotlin
@HiltViewModel
class InvoicesViewModel @Inject constructor(
    private val repository: InvoicesRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val filter = MutableStateFlow(InvoiceFilter())

    val invoices: Flow<PagingData<InvoiceListItem>> =
        filter.flatMapLatest { f ->
            Pager(
                config = PagingConfig(pageSize = 20, prefetchDistance = 5, initialLoadSize = 20),
                pagingSourceFactory = { repository.invoicesPagingSource(f) },
            ).flow
        }.cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow(InvoicesUiState())
    val uiState: StateFlow<InvoicesUiState> = _uiState.asStateFlow()

    fun setFilter(f: InvoiceFilter) { filter.value = f }
    fun onLoadStateChanged(states: CombinedLoadStates) { /* maps to banner/empty */ }
}
```

```kotlin
@HiltViewModel
class InvoiceDetailViewModel @Inject constructor(
    private val repository: InvoicesRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val invoiceId: String = checkNotNull(savedState["invoiceId"])

    private val _uiState = MutableStateFlow<InvoiceDetailUiState>(InvoiceDetailUiState.Loading)
    val uiState: StateFlow<InvoiceDetailUiState> = _uiState.asStateFlow()

    private val _events = Channel<InvoiceDetailEvent>(Channel.BUFFERED)
    val events: Flow<InvoiceDetailEvent> = _events.receiveAsFlow()

    init { load() }

    fun load() = viewModelScope.launch {
        _uiState.value = InvoiceDetailUiState.Loading
        _uiState.value = when (val r = repository.getInvoice(invoiceId)) {
            is ApiResult.Success -> InvoiceDetailUiState.Success(r.data)
            is ApiResult.Failure -> InvoiceDetailUiState.Error(r.message, retryable = r.isRetryable)
        }
    }

    // No request body / no `to` override in the backend contract (see §5).
    fun emailInvoice() = viewModelScope.launch {
        when (val r = repository.emailInvoice(invoiceId)) {
            is ApiResult.Success -> _events.send(InvoiceDetailEvent.EmailSent(r.data.emailedTo))
            is ApiResult.Failure -> _events.send(InvoiceDetailEvent.EmailFailed(r.message))
        }
    }
}
```

```kotlin
@HiltViewModel
class TaxViewModel @Inject constructor(
    private val repository: InvoicesRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val invoiceId: String = checkNotNull(savedState["invoiceId"])
    private val _uiState = MutableStateFlow<TaxUiState>(TaxUiState.Loading)
    val uiState: StateFlow<TaxUiState> = _uiState.asStateFlow()
    init { load() }
    fun load() = viewModelScope.launch { /* repository.getInvoiceTax(invoiceId) -> map */ }
}
```

The repository (owned by AND-243) is expected to expose:

```kotlin
interface InvoicesRepository {
    // `invoiceNumber` is the path key (`/ui/invoices/{invoice_number}`), a string number.
    fun invoicesPagingSource(filter: InvoiceFilter): PagingSource<String?, InvoiceListItem>
    suspend fun getInvoice(invoiceNumber: String): ApiResult<InvoiceDetail>
    // Tax is derived from getInvoice (no /tax endpoint); kept for ViewModel convenience.
    suspend fun getInvoiceTax(invoiceNumber: String): ApiResult<InvoiceTax>
    // No body: POST /ui/invoices/{invoice_number}/email -> InvoiceEmailOut.
    suspend fun emailInvoice(invoiceNumber: String): ApiResult<InvoiceEmailResult>
}
```

`PagingSource` lives in `core-data` and translates page tokens/offsets to the list
endpoint. The ViewModels contain zero Retrofit/OkHttp references — they depend only on
the repository abstraction and `core-model` types, which keeps the unit tests pure JVM.

## 5. API Contract

These ViewModels do not call Retrofit directly; the contract below documents the
endpoints reached through `InvoicesRepository` so the state mapping is verifiable.

> **Review note (corrected against OpenAPI + frontend).** Several field/param/shape
> claims in the original draft were wrong. The contract below is corrected against
> `GET /ui/invoices` (`InvoiceListOut`), `GET /ui/invoices/{invoice_number}`
> (`app__models__InvoiceOut`), and `POST /ui/invoices/{invoice_number}/email`
> (`InvoiceEmailOut`), plus `src/api/endpoints/invoices.ts` and
> `src/api/types.ts`. See section 16 for the per-claim audit. The path parameter is
> `invoice_number` (a string number like "2026-0042"), **not** an opaque `id`.

- **List:** `GET /ui/invoices?type={tip|unlock|subscription|shop|deposit}&date_from={epoch}&date_to={epoch}&limit={n}&cursor={c}`
  (op `list_invoices_ui_invoices_get`, resp `200:InvoiceListOut`). **There is no
  `status` filter and no `q`/free-text param** — the web client filters invoice
  number client-side. Additional server params exist (`user_sub`, `X-SESSION-ID`,
  `X-IMPERSONATION-TOKEN`) but are supplied by `core-network`, not these ViewModels.

```json
{
  "invoices": [
    {"invoice_id": "inv_123", "invoice_number": "2026-0042",
     "invoice_type": "subscription", "user_sub": "user_abc",
     "status": "generated", "currency": "usd",
     "amount_cents": 120000, "tax_cents": 9900, "total_cents": 129900,
     "created_at": 1748649600, "seller_name": "Acme", "buyer_email": "ar@acme.example",
     "line_items": [{"description": "Plan", "quantity": 1, "amount_cents": 120000}]}
  ],
  "next_cursor": "eyJrIjoiaW52XzEyMyJ9"
}
```

The list array key is `invoices` (**not** `items`). Monetary values are integer
**minor units** (`*_cents`), `created_at` is an **epoch-seconds integer** (not an
ISO date), and `status` defaults to `"generated"` (the web app additionally renders
an `"emailed"` badge). `next_cursor == null` denotes the last page; the
`PagingSource` returns `nextKey = null` to stop appends.

- **Detail:** `GET /ui/invoices/{invoice_number}` → full invoice
  (`app__models__InvoiceOut`) including `line_items`. **There is no nested `tax`
  object and no per-rate tax lines** — the only tax data is the scalar `tax_cents`.

```json
{
  "invoice_id": "inv_123", "invoice_number": "2026-0042",
  "invoice_type": "subscription", "user_sub": "user_abc",
  "status": "generated", "currency": "usd",
  "amount_cents": 120000, "tax_cents": 9900, "total_cents": 129900,
  "seller_id": "...", "seller_name": "Acme", "buyer_name": "AR Dept",
  "buyer_email": "ar@acme.example", "payment_method_summary": "Visa ····4242",
  "ledger_entry_id": "le_1", "created_at": 1748649600,
  "line_items": [{"description": "Plan", "quantity": 1, "amount_cents": 120000}]
}
```

- **Tax:** **No dedicated `GET /ui/invoices/{id}/tax` endpoint exists** in the
  backend (verified absent from the OpenAPI index), and there is **no embedded `tax`
  object** in the detail response. `TaxViewModel` can only derive a *flat* breakdown
  from the scalar fields available: `amount_cents` (subtotal), `tax_cents` (total
  tax), `total_cents` (grand total). The "per-rate tax lines (name, rate, amount)"
  envisioned in FR-6 are **not** in the contract; treat them as an unverified
  product assumption (see section 16) — implement only the flat fields unless a new
  backend endpoint is added under AND-243.

- **Email:** `POST /ui/invoices/{invoice_number}/email` (op
  `email_invoice_ui_invoices__invoice_number__email_post`, resp
  `200:InvoiceEmailOut`). The shared `X-CSRF-Token: <ui_csrf>` header is added by
  `core-network` to **every** request (the web `client.ts` sets it unconditionally,
  not only on POST). **The endpoint takes no request body** — there is no `to`
  override in the backend contract or the web client; the invoice is emailed to its
  on-record address. The optional `toOverride` parameter in FR-5/§4 is therefore an
  unverified assumption (see OQ-3 and section 16) and should default to a no-op until
  a backend field exists.

```json
// request: NO body
// 200 response (InvoiceEmailOut)
{"ok": true, "emailed_to": "ar@acme.example", "message": ""}
```

Errors follow FastAPI `detail`: `string`, `[{ "msg": "...", "loc": [...] }]`, or
`{ "code": "...", ... }`. `ApiResult.Failure.message` is produced by the shared
`detail` mapper in `core-network`; ViewModels surface it verbatim.

## 6. Data & State Management

Ui models (in `com.testlogon.android.feature.invoices.model`):

```kotlin
data class InvoiceFilter(val status: InvoiceStatus? = null, val query: String = "")

data class InvoicesUiState(
    val isInitialLoading: Boolean = true,
    val isEmpty: Boolean = false,
    val banner: String? = null,   // append/refresh error surfaced as non-blocking banner
)

sealed interface InvoiceDetailUiState {
    data object Loading : InvoiceDetailUiState
    data class Success(val invoice: InvoiceDetail) : InvoiceDetailUiState
    data class Error(val message: String, val retryable: Boolean) : InvoiceDetailUiState
}

sealed interface InvoiceDetailEvent {
    data class EmailSent(val emailedTo: String) : InvoiceDetailEvent  // from InvoiceEmailOut.emailed_to
    data class EmailFailed(val message: String) : InvoiceDetailEvent
}

sealed interface TaxUiState {
    data object Loading : TaxUiState
    data class Success(val tax: InvoiceTax) : TaxUiState
    data class Error(val message: String, val retryable: Boolean) : TaxUiState
}
```

State ownership rules: paging `LoadState` is the single source of truth for
list-content loading/error; `InvoicesUiState` only mirrors derived flags
(`isInitialLoading`, `isEmpty`, `banner`) computed from `CombinedLoadStates` in
`onLoadStateChanged`. Filter is the only mutable driver of the paged stream;
`flatMapLatest` cancels in-flight pages on filter change. `cachedIn(viewModelScope)`
preserves loaded pages across recompositions/rotation. Detail and tax states are plain
`MutableStateFlow` with `Loading` as the initial value; `SavedStateHandle` carries
`invoiceId` so process death restores the correct target. One-shot results
(email) use a `Channel` (capacity `BUFFERED`) consumed as `events` to avoid
re-emitting on collection restart. No Room caching is added here — any caching belongs
to AND-243's repository; these ViewModels are stateless beyond their `StateFlow`s.

## 7. Error Handling & Resilience

- **Mapping.** All failures arrive as `ApiResult.Failure(message, isRetryable)`.
  `isRetryable` is true for timeouts, IO errors, and 5xx on idempotent GETs; false for
  4xx (validation, 404, 403). Detail/Tax map this to `Error(message, retryable)`.
- **Timeouts.** Underlying OkHttp uses ~20s timeouts (configured in `core-network`).
  ViewModels never block; all calls are suspend on `viewModelScope`.
- **Retry.** GET loads expose `load()`/`retry()`. Paging append/prepend failures
  surface via `LoadState.Error`; the screen calls `retry()` which proxies to
  `LazyPagingItems.retry()`. Bounded backoff for GETs is implemented in the network
  interceptor, not here.
- **Email (non-idempotent).** Never auto-retried. On failure, emit
  `EmailFailed(message)`; the user re-invokes `emailInvoice()`. A short in-flight
  guard prevents double-send from rapid taps (`AtomicBoolean`/`isSending` flag).
- **Offline/stale.** When the repository reports no connectivity, the list shows the
  paging empty/error state with a "retry" affordance, and detail shows
  `Error(retryable = true)`. No crash on the unreliable dev host.

## 8. Security & Privacy

No new credentials or storage are introduced. Auth and CSRF are handled transparently
by `core-network` (cookie jar + `X-CSRF-Token` echo + single `POST /ui/session/refresh`
on 401). The email POST must carry the CSRF header — verified by the network layer, not
re-implemented here. Invoice data is financial PII: buyer/seller emails (`buyer_email`), names, and
amounts must never be written to logs (see section 10) and must not be placed in
`SavedStateHandle` beyond the `invoiceId` (the `invoice_number` path key). No invoice
content is persisted by these ViewModels. **Correction:** the contract field is
`buyer_email` (not `customer_email`), and there is no `to` override on the email
endpoint, so no caller-supplied address is transmitted or logged.

## 9. Accessibility & i18n

ViewModels hold no Composables, so a11y semantics are owned by the downstream screen
tickets in E33. However, this ticket ensures the data exposed is i18n-ready:

- Amounts are exposed as raw **`Long` minor units** (the backend `*_cents` integer
  fields — `amount_cents`, `tax_cents`, `total_cents`) plus the `currency` code
  (lowercase ISO-4217 such as `"usd"`; the UI uppercases it), never pre-formatted
  strings, so the UI can format with the device locale
  (`NumberFormat.getCurrencyInstance(locale)` over `cents / 100`, matching the web
  `InvoiceRow.formatCents`). **Correction:** the draft's `BigDecimal`/float framing
  is unnecessary — the contract is already integer cents, so there is no float
  rounding concern (see §13 risk update).
- Dates are exposed as the backend's **epoch-seconds `Long`** (`created_at`), not an
  ISO-8601 string. **Correction:** the draft claimed ISO-8601/`LocalDate`; convert
  `created_at * 1000` to the device locale in the UI (matching web `formatDate`).
  There is no `issued_at` field in the contract.
- All user-facing error text originates from the backend `detail` or from string
  resources resolved in the UI layer; the ViewModel passes message keys/strings
  through without hard-coded English copy where avoidable. Status enums
  (`InvoiceStatus`) are mapped to string resources by the UI.

## 10. Telemetry & Logging

- Emit structured analytics events via the shared `Analytics` interface (from
  `core-ui`/`core-data`): `invoices_list_viewed`, `invoice_detail_viewed`
  (`invoice_id` hashed/opaque only), `invoice_email_attempt`, `invoice_email_result`
  (`success: Boolean`), `invoice_tax_viewed`.
- Logging: use the project logger at `DEBUG` for state transitions in debug builds
  only. **Never** log invoice totals, customer emails, or the email `to` override.
  Log the opaque `invoiceId` and error codes only.
- Paging load states may be logged at `VERBOSE` in debug to diagnose pagination, again
  excluding payload contents.

## 11. Testing Strategy

This is the core acceptance ("Unit-tested"). All tests are pure-JVM under
`feature-invoices/src/test`, using `core-testing` helpers, JUnit4, Turbine for
`Flow`/`StateFlow` assertions, `kotlinx-coroutines-test`
(`MainDispatcherRule` + `StandardTestDispatcher`), and a `FakeInvoicesRepository`.

- `InvoicesViewModelTest`:
  - filter change emits a new `PagingData` stream (collect first page via
    `AsyncPagingDataDiffer` or `PagingData` test util `asSnapshot`).
  - `next_cursor == null` terminates appends.
  - `onLoadStateChanged` maps initial `Loading`/`Error`/empty to `InvoicesUiState`.
- `InvoiceDetailViewModelTest`:
  - init → `Loading` then `Success` on fake success.
  - failure with `isRetryable=false` → `Error(retryable=false)`; `load()` re-loads.
  - `emailInvoice` success emits exactly one `EmailSent` (Turbine `awaitItem` +
    `expectNoEvents`); failure emits `EmailFailed(message)` with mapped detail.
  - double-tap guard: two rapid `emailInvoice` calls produce one repository call.
- `TaxViewModelTest`:
  - projects `tax` lines, totals, and grand total correctly; error path maps message.
- `SavedStateHandle` restoration: ViewModel built with `invoiceId` reads it correctly.
- Edge cases: empty list, single-item list, malformed `detail` shapes (string vs list
  vs object) verified via the fake returning each `ApiResult.Failure` form.

Target: ≥85% line coverage on the three ViewModels and their Ui-model mappers.

## 12. Dependencies & Sequencing

- **Depends on AND-243 (Invoices):** requires `InvoicesRepository` with
  `invoicesPagingSource`, `getInvoice`, `getInvoiceTax`, and `emailInvoice`, plus the
  `InvoiceListItem`/`InvoiceDetail`/`InvoiceTax` domain models in `core-model`. If
  `invoicesPagingSource`/`getInvoiceTax` are absent in AND-243's current surface, they
  are added there (small follow-up) before this ticket completes; this is the only
  cross-ticket coupling.
- **Transitively** depends on `core-network` (AND-223 chain) for `ApiResult`, the CSRF
  cookie jar, and `detail` mapping — already in place.
- **Blocks:** the Invoices/Tax screen/UI tickets in epic E33 that collect these
  `StateFlow`s and `PagingData`. They are out of scope here.
- Sequencing: land after AND-243's repository merge; can proceed in parallel with
  AND-248 (Billing config read), which shares no code.

## 13. Risks & Open Questions

- **OQ-1 (Tax endpoint shape). RESOLVED.** Verified against the OpenAPI index: there
  is **no** `GET /ui/invoices/{id}/tax` endpoint and **no** embedded `tax` object —
  only the scalar `tax_cents`. `TaxViewModel` projects from the detail response. The
  per-rate-line breakdown is not available (now tracked as an open assumption, §16).
- **OQ-2 (Pagination model). RESOLVED.** Verified **cursor-based**: `InvoiceListOut`
  has a nullable `next_cursor` and `GET /ui/invoices` accepts `limit` + `cursor`
  (no `offset`/`page`). The `PagingSource` key type is therefore `String?` (the
  cursor), not `Int`; `nextKey = next_cursor`, terminating when it is null.
- **Risk: dev host flakiness.** ~20s timeouts can make paging appends fail
  intermittently; mitigated by `LoadState.Error` + `retry()` and never auto-retrying
  the email POST.
- **Risk: monetary precision. MITIGATED BY CONTRACT.** The backend already returns
  integer minor units (`*_cents`); there are no floating-point amounts in the JSON, so
  map straight to `Long` (cents). No `BigDecimal` is required. Owned jointly with
  AND-243's DTO mapping.
- **OQ-3 (Email override). RESOLVED — no override.** The `POST .../email` endpoint
  takes **no body** and the web client sends none; the invoice is emailed to its
  on-record address (`InvoiceEmailOut.emailed_to` reports where). There is no `to`
  override in the current contract; `emailInvoice()` takes no address argument. If a
  custom recipient is later required, it needs a backend change first (open
  assumption, §16).

## 14. Acceptance Criteria

1. `InvoicesViewModel` exposes `invoices: Flow<PagingData<InvoiceListItem>>`
   (`cachedIn(viewModelScope)`) and a `StateFlow<InvoicesUiState>`; changing the
   filter via `setFilter` produces a fresh paged stream. (Verified by unit test.)
2. Paging terminates correctly when `next_cursor` is null and surfaces append errors
   as `LoadState.Error` with a working `retry()`.
3. `InvoiceDetailViewModel` transitions `Loading → Success/Error` on load and on
   `load()` retry; `Error.retryable` reflects `ApiResult.Failure.isRetryable`.
4. `emailInvoice()` emits exactly one `EmailSent` on success and `EmailFailed(message)`
   on failure, with the message produced by the FastAPI `detail` mapper; rapid double
   taps cause only one network call.
5. `TaxViewModel` exposes `StateFlow<TaxUiState>` with the correct flat breakdown from
   the invoice's scalar fields: taxable subtotal (`amount_cents`), total tax
   (`tax_cents`), and grand total (`total_cents`). (Corrected: no per-rate lines exist
   in the contract — see §5 and §16.)
6. No ViewModel references Retrofit/OkHttp directly; all depend only on
   `InvoicesRepository` + `core-model`.
7. No invoice amounts or customer emails appear in any log output.
8. Unit tests pass on the JVM with ≥85% coverage of the three ViewModels and mappers.

## 15. Definition of Done

- Three ViewModels and their Ui-model/sealed-interface files implemented under
  `com.testlogon.android.feature.invoices` with `@HiltViewModel` injection.
- All acceptance criteria in section 14 met and demonstrated by green unit tests in
  `feature-invoices/src/test` using `FakeInvoicesRepository`, Turbine, and
  `kotlinx-coroutines-test`.
- `./gradlew :feature-invoices:testDebugUnitTest` and `:feature-invoices:lintDebug`
  pass; ktlint/detekt clean; no new lint baseline entries.
- No direct network types leak into the feature module (verified by module
  dependency check / Konsist or review).
- OQ-1/OQ-2/OQ-3 either resolved against `/openapi.json` or documented as follow-ups
  with the chosen default behavior implemented.
- Code reviewed and merged to `android-port`; downstream E33 UI tickets can collect the
  exposed `StateFlow`s and `PagingData` without further ViewModel changes.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer. OpenAPI
pointers are `METHOD /path` (op) and/or `components.schemas.<Name>`; frontend
pointers are `src/...` paths; framework choices are labelled `framework ref`.

1. **List endpoint is `GET /ui/invoices` returning `InvoiceListOut`.** VERIFIED.
   Source: OpenAPI `GET /ui/invoices` (op `list_invoices_ui_invoices_get`,
   `resp=200:InvoiceListOut`); `src/api/endpoints/invoices.ts: listInvoices`.
2. **List query params are `type`, `date_from`, `date_to`, `limit`, `cursor` (no
   `status`, no `q`).** CORRECTED (draft claimed `status` + `q`). Source: OpenAPI
   `GET /ui/invoices` `params=type,date_from,date_to,limit,cursor,...`;
   `src/api/endpoints/invoices.ts: InvoiceListParams`.
3. **Free-text invoice-number search is client-side only.** VERIFIED. Source:
   `src/pages/billing/InvoicesPage.tsx` (filters `query.data.invoices` by
   `invoice_number` in a `useMemo`; never sent to the server).
4. **List response array key is `invoices` (not `items`) with nullable
   `next_cursor`.** CORRECTED (draft used `items`). Source:
   `components.schemas.InvoiceListOut`; `src/api/types.ts: InvoiceList`.
5. **Detail endpoint is `GET /ui/invoices/{invoice_number}` returning
   `app__models__InvoiceOut`; path key is `invoice_number`, not `id`.** CORRECTED
   (draft used `{id}`). Source: OpenAPI `GET /ui/invoices/{invoice_number}` (op
   `get_invoice_ui_invoices__invoice_number__get`); `src/api/endpoints/invoices.ts:
   getInvoice`.
6. **Invoice fields are `invoice_id`, `invoice_number`, `invoice_type`, `user_sub`,
   `amount_cents`, `tax_cents`, `total_cents`, `currency`, `status`, `seller_id`,
   `seller_name`, `buyer_name`, `buyer_email`, `line_items`,
   `payment_method_summary`, `ledger_entry_id`, `created_at`.** CORRECTED (draft used
   `number`, `issued_at`, `subtotal`, nested `tax`, `customer_email`, `total` float).
   Source: `components.schemas.app__models__InvoiceOut`; `src/api/types.ts: Invoice`.
7. **Amounts are integer minor units (`*_cents`), not floats/BigDecimal.** CORRECTED
   (draft used float `total`/`subtotal` and mandated BigDecimal). Source:
   `app__models__InvoiceOut` (`amount_cents`/`tax_cents`/`total_cents` `type:integer`),
   `InvoiceLineItemOut.amount_cents`; web formatting `src/pages/billing/InvoiceRow.tsx:
   formatCents` (`cents / 100`).
8. **`created_at` is epoch seconds (integer), not an ISO-8601 string.** CORRECTED
   (draft used `issued_at: "2026-05-31"`). Source: `app__models__InvoiceOut.created_at`
   (`type:integer`); `src/pages/billing/InvoiceRow.tsx: formatDate` (`new Date(ts *
   1000)`).
9. **`status` is a free-form string defaulting to `"generated"` (web also shows an
   `"emailed"` badge); the `paid/open/void/overdue` enum is not in the contract.**
   CORRECTED. Source: `app__models__InvoiceOut.status` (`default:"generated"`);
   `src/pages/billing/InvoiceRow.tsx` (`invoice.status === "emailed"`).
10. **No dedicated tax endpoint and no embedded `tax` object; only scalar
    `tax_cents`.** CORRECTED (draft proposed a nested `tax` object with per-rate
    `lines` and a possible `/ui/invoices/{id}/tax`). Source: OpenAPI index has no
    `/invoices/.../tax` route; `app__models__InvoiceOut` has only `tax_cents`; no
    `lines`/`rate` fields exist in any invoice schema.
11. **Email endpoint is `POST /ui/invoices/{invoice_number}/email` returning
    `InvoiceEmailOut {ok, emailed_to, message}` with NO request body.** CORRECTED
    (draft used `{id}`, a `{to}` request body, and a `{sent, to}` response). Source:
    OpenAPI `POST /ui/invoices/{invoice_number}/email` (op
    `email_invoice_ui_invoices__invoice_number__email_post`, `resp=200:InvoiceEmailOut`,
    `req=` empty); `components.schemas.InvoiceEmailOut`; `src/api/endpoints/invoices.ts:
    emailInvoice` (calls `api.post(url)` with no payload); `src/api/types.ts:
    InvoiceEmailResult`.
12. **No `to`/recipient override exists for email.** CORRECTED (draft FR-5/§4 added
    `toOverride`). Source: same as #11 (empty request schema; web `emailInvoice` takes
    only `invoiceNumber`).
13. **Auth: cookie-based, `X-CSRF-Token` echoes the `ui_csrf` cookie on every
    request; 401 triggers a single `POST /ui/session/refresh` then retry.** VERIFIED
    (refined: header is unconditional, not POST-only). Source: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", ...)` on all requests;
    `refreshSession()` does `fetch("/ui/session/refresh", {method:"POST"})`); OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`).
14. **Pagination is cursor-based (`limit` + `cursor` / `next_cursor`), so the
    `PagingSource` key is `String?`, not `Int`.** CORRECTED/RESOLVED (draft OQ-2 left
    it open and defaulted key to `Int`). Source: `GET /ui/invoices` `params=...,limit,
    cursor`; `InvoiceListOut.next_cursor` (`anyOf string|null`).
15. **Errors follow FastAPI `detail` (`string` | `[{msg, loc}]` | `{code,...}`),
    and `422` is the documented validation response.** VERIFIED. Source: every
    invoice op lists `422:HTTPValidationError`; `components.schemas.HTTPValidationError`
    / `ValidationError` (FastAPI standard shape).
16. **There is no web "invoice detail" screen; the Android `InvoiceDetailViewModel`
    is net-new over the same `getInvoice`.** VERIFIED. Source: only
    `src/pages/billing/InvoicesPage.tsx` + `InvoiceRow.tsx` consume the invoice API;
    no detail route exists.
17. **Framework choices: Paging 3 (`Pager`/`PagingSource`/`cachedIn`), Hilt
    (`@HiltViewModel`), `StateFlow`, Turbine + `kotlinx-coroutines-test` for tests.**
    Unverified against backend (architecture decisions, not API contract); standard
    Android Jetpack. `framework ref`: developer.android.com/topic/libraries/architecture/paging/v3-overview,
    developer.android.com/training/dependency-injection/hilt-android,
    developer.android.com/kotlin/flow/stateflow-and-sharedflow.

### Corrections made

- Path parameter changed from `{id}` to `{invoice_number}` for detail and email (#5, #11).
- List query params corrected to `type`/`date_from`/`date_to`/`limit`/`cursor`;
  removed the non-existent `status` and `q` params; clarified number search is
  client-side (#2, #3); FR-3 rewritten.
- List response key corrected `items` → `invoices` (#4); full `InvoiceOut` field set
  substituted for the invented shape (#6).
- Monetary fields corrected to integer `*_cents` (`Long`); dropped the BigDecimal/float
  framing and the floating-point precision risk (#7; §9, §13 updated).
- `created_at` corrected from ISO-8601 string to epoch-seconds integer (#8; §9 updated).
- `status` enum corrected to free-form string default `"generated"` (#9; FR-1, AC-1 area).
- Removed the nested `tax` object / per-rate `lines` / `/tax` endpoint; FR-6 and AC-5
  rewritten to the flat `amount_cents`/`tax_cents`/`total_cents` breakdown (#10).
- Email contract corrected: no body, response `InvoiceEmailOut {ok, emailed_to,
  message}`; `emailInvoice()` signature dropped `toOverride`; `EmailSent` now carries
  `emailedTo` (#11, #12; FR-5, §4, §6 updated).
- `customer_email` corrected to `buyer_email` (#6; §8 updated).
- Repository interface signatures updated (`invoiceNumber` keys, `String?` paging key,
  `InvoiceEmailResult` return).
- OQ-1/OQ-2/OQ-3 marked RESOLVED in §13 with the verified answers.
- CSRF note refined: header applied to all requests, not only mutations (#13).

### Open assumptions

- **Per-rate tax lines (FR-6 original).** Not in any backend schema; cannot be
  implemented from the current contract. Retained only as a future extension; would
  require a new backend field/endpoint. Why unverifiable: absent from OpenAPI.
- **Custom email recipient (`toOverride`, OQ-3).** No backend support today; kept as a
  no-op forward hook. Why unverifiable: email endpoint has an empty request schema.
- **`InvoiceFilter.type` allowed values** (`tip/unlock/subscription/shop/deposit`)
  taken from the web `TYPES` list in `InvoicesPage.tsx`; the OpenAPI `type` param has
  no enum constraint, so the set is an inferred UI convention, not a contract guarantee.
- **`isRetryable` mapping and ~20s timeouts / backoff** live in `core-network`
  (AND-223 chain) and are assumed, not re-verified here; out of this ticket's scope.
- **Exact `detail` error variants surfaced per status** depend on `core-network`'s
  shared mapper; only the FastAPI envelope shape (#15) is contract-verified.

## 17. Test Plan

All cases are JVM/Robolectric-eligible (this is a ViewModel ticket; per §8 acceptance
is "Unit-tested"). Targets: **JVM unit** (local, no device) for the ViewModel state
machines and mappers; **contract/MockWebServer** where the repository's wire mapping
must be pinned to the real DTO shapes. The emulator/physical-device targets are noted
only where a case is later promoted to instrumented coverage; none of the §14 criteria
require hardware, so no case here *must* run on the physical Galaxy A15 — that device
is reserved for hardware-dependent tickets (camera/biometrics/FCM/WebRTC) and is N/A
to invoice ViewModels.

- **TC-AND-249-01** — Type: JVM unit. Target: `InvoicesViewModel`. Preconditions:
  `FakeInvoicesRepository` returns a two-page `PagingSource` (page1 `next_cursor`
  non-null, page2 `next_cursor=null`). Steps: collect `invoices` via
  `PagingData.asSnapshot`; trigger append. Expected: both pages load in order and
  appends stop after the null cursor (`nextKey=null`). Traces: AC-1, AC-2.
- **TC-AND-249-02** — Type: JVM unit. Target: `InvoicesViewModel`. Preconditions: fake
  repo distinguishes filters by `type`/date range. Steps: collect first snapshot,
  call `setFilter(InvoiceFilter(type="subscription"))`, collect again. Expected:
  `flatMapLatest` rebuilds the `Pager`; a fresh `PagingData` reflecting the new
  filter is emitted and the prior stream is cancelled. Traces: AC-1.
- **TC-AND-249-03** — Type: JVM unit. Target: `InvoicesViewModel`. Preconditions: fake
  `PagingSource` throws on append (simulating the flaky dev host / offline). Steps:
  load first page, force append failure, assert `LoadState.Error`, call `retry()`,
  let the next attempt succeed. Expected: append surfaces `LoadState.Error`; `retry()`
  proxies to `LazyPagingItems.retry()` and the page loads; no crash. Traces: AC-2.
  (Offline/flaky-host path.)
- **TC-AND-249-04** — Type: JVM unit. Target: `InvoicesViewModel.onLoadStateChanged`.
  Preconditions: craft `CombinedLoadStates` for initial Loading, empty success, and
  refresh error. Steps: feed each into `onLoadStateChanged`. Expected: `InvoicesUiState`
  derives `isInitialLoading`, `isEmpty`, and a non-null `banner` respectively. Traces:
  AC-1, AC-2.
- **TC-AND-249-05** — Type: JVM unit. Target: `InvoiceDetailViewModel`. Preconditions:
  fake `getInvoice` returns `ApiResult.Success(InvoiceDetail)`; `SavedStateHandle`
  carries `invoiceId="2026-0042"`. Steps: construct VM (init loads); collect `uiState`
  with Turbine. Expected: `Loading` then `Success(invoice)` with the invoice number
  preserved. Traces: AC-3.
- **TC-AND-249-06** — Type: JVM unit. Target: `InvoiceDetailViewModel`. Preconditions:
  `getInvoice` returns `ApiResult.Failure("Not found", isRetryable=false)` (404 →
  non-retryable per §7). Steps: construct VM; then make the fake succeed and call
  `load()`. Expected: first `Error(message="Not found", retryable=false)`; after
  `load()`, `Loading → Success`. Traces: AC-3.
- **TC-AND-249-07** — Type: JVM unit. Target: `InvoiceDetailViewModel.emailInvoice`.
  Preconditions: fake `emailInvoice` returns
  `ApiResult.Success(InvoiceEmailResult(ok=true, emailedTo="ar@acme.example"))`.
  Steps: collect `events` with Turbine; call `emailInvoice()`. Expected: exactly one
  `EmailSent(emailedTo="ar@acme.example")`, then `expectNoEvents()` (no re-emit on
  re-collection); repository called with no body/override. Traces: AC-4.
- **TC-AND-249-08** — Type: JVM unit. Target: `InvoiceDetailViewModel.emailInvoice`.
  Preconditions: fake `emailInvoice` returns `ApiResult.Failure(<mapped detail>)`
  exercising each FastAPI `detail` shape (plain `string`, `[{msg,loc}]`, `{code,...}`).
  Steps: for each shape, call `emailInvoice()`, collect `events`. Expected: one
  `EmailFailed(message)` with the message the `detail` mapper produces; not
  auto-retried. Traces: AC-4. (Validation/error-shape coverage.)
- **TC-AND-249-09** — Type: JVM unit. Target: `InvoiceDetailViewModel.emailInvoice`.
  Preconditions: fake `emailInvoice` suspends on a gate; `StandardTestDispatcher`.
  Steps: call `emailInvoice()` twice in immediate succession before the first
  completes. Expected: the in-flight guard (`isSending`/`AtomicBoolean`) yields exactly
  one repository invocation and one terminal event. Traces: AC-4.
- **TC-AND-249-10** — Type: JVM unit. Target: `TaxViewModel`. Preconditions: fake
  `getInvoice` returns an invoice with `amount_cents=120000`, `tax_cents=9900`,
  `total_cents=129900`. Steps: construct VM (init loads); collect `uiState`. Expected:
  `Success` with taxable subtotal=120000, total tax=9900, grand total=129900 (flat,
  no per-rate lines); arithmetic consistency `amount + tax == total`. Traces: AC-5.
- **TC-AND-249-11** — Type: JVM unit. Target: `TaxViewModel`. Preconditions: fake
  `getInvoice` returns `ApiResult.Failure("offline", isRetryable=true)`. Steps:
  construct VM; assert state; then succeed and `load()`. Expected:
  `Error(message="offline", retryable=true)` → after retry `Loading → Success`.
  Traces: AC-5. (Offline path.)
- **TC-AND-249-12** — Type: contract/MockWebServer. Target: `InvoicesRepository`
  wire mapping (AND-243 surface, exercised here to pin the DTO contract these
  ViewModels depend on). Preconditions: MockWebServer serves a real-shaped
  `InvoiceListOut` body (`{"invoices":[{...invoice_number, total_cents, created_at
  epoch, status:"generated"...}], "next_cursor":"abc"}`) for `GET /ui/invoices`, and a
  real `app__models__InvoiceOut` for `GET /ui/invoices/{invoice_number}`, and
  `InvoiceEmailOut` for `POST .../email`. Steps: call repo list/detail/email; assert
  parsed fields and that `next_cursor` maps to the paging key. Expected: field
  names/types match the OpenAPI schemas (cents as Long, `created_at` epoch Long,
  list key `invoices`); email POST sends no body and the `X-CSRF-Token` header is
  present. Traces: AC-1, AC-2, AC-4, AC-6.
- **TC-AND-249-13** — Type: JVM unit. Target: project logger usage across all three
  ViewModels. Preconditions: capture log output via a test logger/`Timber` test tree.
  Steps: drive load/success/error and email flows. Expected: no `total_cents`/
  `amount_cents`/`buyer_email`/`emailed_to` value appears in any log line; only the
  opaque `invoiceId` and error codes are logged. Traces: AC-7. (Security/PII.)
- **TC-AND-249-14** — Type: JVM unit (Konsist/architecture). Target: `feature-invoices`
  ViewModel sources + coverage. Preconditions: Konsist rule over the module + JaCoCo.
  Steps: assert no `retrofit2.*`/`okhttp3.*` import appears in any ViewModel and that
  ViewModels depend only on `InvoicesRepository`/`core-model`; run
  `:feature-invoices:testDebugUnitTest` with coverage. Expected: zero network imports;
  ≥85% line coverage on the three ViewModels and Ui-model mappers. Traces: AC-6, AC-8.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 (paged stream + filter rebuild + `InvoicesUiState`) | TC-01, TC-02, TC-04, TC-12 |
| AC-2 (cursor termination + append error + `retry()`) | TC-01, TC-03, TC-04, TC-12 |
| AC-3 (detail `Loading→Success/Error`, retry, `retryable`) | TC-05, TC-06 |
| AC-4 (email one-shot success/failure + double-tap guard) | TC-07, TC-08, TC-09, TC-12 |
| AC-5 (`TaxUiState` flat breakdown) | TC-10, TC-11 |
| AC-6 (no Retrofit/OkHttp in ViewModels) | TC-12, TC-14 |
| AC-7 (no amounts/emails in logs) | TC-13 |
| AC-8 (JVM tests pass, ≥85% coverage) | TC-14 (all TCs contribute) |
