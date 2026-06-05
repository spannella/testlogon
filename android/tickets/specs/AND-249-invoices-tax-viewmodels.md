---
id: AND-249
title: Invoices/tax ViewModels
milestone: M5
epic: E33
priority: P2
size: M
status: draft
depends_on: [AND-243]
blocks: []
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
- Web reference: `frontend/src/api/endpoints/invoices.ts` (list/detail/email),
  `frontend/src/api/types.ts` (invoice & tax shapes). Backend OpenAPI at
  `/openapi.json` on the dev host `http://18.222.237.167:8000` (PLAINTEXT, unreliable).
- Auth is cookie-based with `X-CSRF-Token` echoing the `ui_csrf` cookie; on 401 the
  OkHttp authenticator calls `POST /ui/session/refresh` once then retries. All of that
  is handled in `core-network` and is transparent to these ViewModels.
- Conventions: `StateFlow<UiState>`, typed `ApiResult<T>`, FastAPI `detail` mapping
  (`string | [{msg}] | {code,...}`), ~20s timeouts, bounded backoff retry for
  idempotent GETs only.

## 3. Functional Requirements

FR-1. **Invoice list (paged).** `InvoicesViewModel` exposes
`val invoices: Flow<PagingData<InvoiceListItem>>` produced by Paging 3. The stream is
`cachedIn(viewModelScope)` so configuration changes do not re-fetch. Each list item
renders invoice number, issue date, total amount (with currency), and status
(`paid`/`open`/`void`/`overdue`).

FR-2. **List load/empty/error/refresh states.** In addition to `PagingData` (which
carries its own `LoadState`), the ViewModel exposes a coarse
`StateFlow<InvoicesUiState>` derived for non-paging concerns (initial gate, global
banner). The screen drives refresh via `refresh()`, which calls `refresh()` on the
`LazyPagingItems` adapter; the ViewModel additionally exposes `retry()` for failed
append/prepend.

FR-3. **Filtering.** The list supports an optional status filter and free-text query.
`fun setFilter(filter: InvoiceFilter)` updates a backing `MutableStateFlow`; the
paging `Pager` is rebuilt reactively via `flatMapLatest` so changing the filter starts
a fresh paged stream.

FR-4. **Invoice detail.** `InvoiceDetailViewModel` is constructed with an
`invoiceId: String` (via `SavedStateHandle`), loads the invoice on init, and exposes
`StateFlow<InvoiceDetailUiState>` with `Loading`, `Success(invoice)`, and
`Error(message, retryable)`.

FR-5. **Email invoice.** The detail ViewModel exposes
`fun emailInvoice(toOverride: String? = null)` invoking `POST /ui/invoices/{n}/email`.
Email send is a one-shot action surfaced as a `Channel`-backed
`Flow<InvoiceDetailEvent>` (`EmailSent`, `EmailFailed(message)`) so it fires exactly
once and survives recomposition without re-emitting.

FR-6. **Tax summary.** `TaxViewModel` exposes `StateFlow<TaxUiState>` presenting a
read-only tax breakdown: taxable subtotal, per-rate tax lines
(`name`, `rate`, `amount`), total tax, and grand total, derived from the invoice's
tax fields. It supports both "tax for a single invoice" (constructed with
`invoiceId`) and an aggregate path if the backend exposes one (see section 5).

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

    fun emailInvoice(toOverride: String? = null) = viewModelScope.launch {
        when (val r = repository.emailInvoice(invoiceId, toOverride)) {
            is ApiResult.Success -> _events.send(InvoiceDetailEvent.EmailSent)
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
    fun invoicesPagingSource(filter: InvoiceFilter): PagingSource<Int, InvoiceListItem>
    suspend fun getInvoice(id: String): ApiResult<InvoiceDetail>
    suspend fun getInvoiceTax(id: String): ApiResult<InvoiceTax>
    suspend fun emailInvoice(id: String, to: String?): ApiResult<Unit>
}
```

`PagingSource` lives in `core-data` and translates page tokens/offsets to the list
endpoint. The ViewModels contain zero Retrofit/OkHttp references — they depend only on
the repository abstraction and `core-model` types, which keeps the unit tests pure JVM.

## 5. API Contract

These ViewModels do not call Retrofit directly; the contract below documents the
endpoints reached through `InvoicesRepository` so the state mapping is verifiable.

- **List:** `GET /ui/invoices?status={open|paid|void|overdue}&q={text}&limit=20&cursor={c}`

```json
{
  "items": [
    {"id": "inv_123", "number": "2026-0042", "issued_at": "2026-05-31",
     "status": "open", "currency": "USD", "total": 1299.00, "tax_total": 99.00}
  ],
  "next_cursor": "eyJrIjoiaW52XzEyMyJ9"
}
```

`next_cursor == null` denotes the last page; the `PagingSource` returns `nextKey =
null` to stop appends.

- **Detail:** `GET /ui/invoices/{id}` → full invoice including line items and a
  nested `tax` object.

```json
{
  "id": "inv_123", "number": "2026-0042", "issued_at": "2026-05-31",
  "status": "open", "currency": "USD", "subtotal": 1200.00,
  "tax": {"taxable_subtotal": 1200.00, "total_tax": 99.00, "grand_total": 1299.00,
          "lines": [{"name": "State Sales Tax", "rate": 0.0825, "amount": 99.00}]},
  "customer_email": "ar@acme.example"
}
```

- **Tax:** preferred source is the `tax` object embedded in the detail response.
  If a dedicated `GET /ui/invoices/{id}/tax` exists in `/openapi.json`, `TaxViewModel`
  uses it; otherwise it reuses `getInvoice` and projects the `tax` field. The exact
  path is resolved against OpenAPI in AND-243 (open question OQ-1, section 13).

- **Email:** `POST /ui/invoices/{id}/email` with header `X-CSRF-Token: <ui_csrf>`.

```json
// request (optional override)
{"to": "billing@acme.example"}
// 200 response
{"sent": true, "to": "billing@acme.example"}
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
    data object EmailSent : InvoiceDetailEvent
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
re-implemented here. Invoice data is financial PII: customer emails and amounts must
never be written to logs (see section 10) and must not be placed in
`SavedStateHandle` beyond the opaque `invoiceId`. No invoice content is persisted by
these ViewModels. The optional `to` override for email is passed straight through; no
local validation that could leak addresses into telemetry.

## 9. Accessibility & i18n

ViewModels hold no Composables, so a11y semantics are owned by the downstream screen
tickets in E33. However, this ticket ensures the data exposed is i18n-ready:

- Amounts are exposed as raw `BigDecimal`/`Long-minor-units` plus an ISO-4217
  `currency` code, never pre-formatted strings, so the UI can format with the device
  locale (`NumberFormat.getCurrencyInstance(locale)`).
- Dates are exposed as ISO-8601 strings / `LocalDate`, not formatted text.
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

- **OQ-1 (Tax endpoint shape).** Whether tax is a dedicated `GET /ui/invoices/{id}/tax`
  or only embedded in the detail response. Resolve against `/openapi.json`; default to
  projecting from detail to avoid a second round-trip on the unreliable dev host.
- **OQ-2 (Pagination model).** Cursor (`next_cursor`) vs offset/limit. Spec assumes
  cursor; if the backend is offset-based, the `PagingSource` key type stays `Int` and
  cursor handling is dropped — no ViewModel change.
- **Risk: dev host flakiness.** ~20s timeouts can make paging appends fail
  intermittently; mitigated by `LoadState.Error` + `retry()` and never auto-retrying
  the email POST.
- **Risk: monetary precision.** Floating-point totals from JSON; mandate `BigDecimal`
  (or minor-unit `Long`) end-to-end to avoid rounding drift. Owned jointly with
  AND-243's DTO mapping.
- **OQ-3 (Email override).** Whether the UI offers a custom `to` address or always
  uses `customer_email`; the ViewModel supports both via the optional parameter.

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
5. `TaxViewModel` exposes `StateFlow<TaxUiState>` with correct taxable subtotal,
   per-rate lines, total tax, and grand total.
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
