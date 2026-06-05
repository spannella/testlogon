---
id: AND-243
title: Invoices
milestone: M5
epic: E33
priority: P1
size: M
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-243 — Invoices

## 1. Overview & Goal

Deliver the Invoices feature for the TestLogon native Android app: a paginated list of the
authenticated user's billing invoices and a per-invoice detail screen, plus the ability to
trigger an emailed copy of a single invoice via `POST /ui/invoices/{n}/email`. The web
reference implementation lives in `frontend/src/api/endpoints/invoices.ts`; this ticket ports
that surface to Kotlin/Compose with parity on data shapes and behaviors.

The goal is a self-contained `feature-invoices` module that consumes the billing networking and
DTO layer produced by AND-223, renders invoices reliably against the unreliable plaintext dev
backend (offline/stale states, bounded retry for GETs), and lets a user request an email of an
invoice with clear success/failure feedback. Success means: invoices render from live or cached
data, the detail screen shows line items and totals, and the email action completes with an
idempotent, debounced, CSRF-protected request.

## 2. Context & References

- Repo: `spannella/testlogon`, branch `android-port`, Android app under `android/`.
- Namespace / applicationId base: `com.testlogon.android`. This feature: `com.testlogon.android.feature.invoices`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single-Activity), Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3.
  minSdk 24, compile/target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- Module layering: `app -> feature-invoices -> core-network, core-model, core-data, core-ui, core-testing`.
- Web reference: `frontend/src/api/endpoints/invoices.ts` (list/detail/email), `frontend/src/api/types.ts`
  (shared `Invoice`, `InvoiceLineItem` types). Backend OpenAPI: `/openapi.json` on
  `http://18.222.237.167:8000` (PLAINTEXT HTTP dev host, unreliable).
- Auth: cookie-based session established by the auth feature; persistent cookie jar + `ui_csrf`
  cookie echoed as `X-CSRF-Token`; on 401 the network layer performs `POST /ui/session/refresh`
  once then retries (owned by core-network/auth tickets, consumed here).
- Upstream dependency: **AND-223 (Billing API + DTOs)** provides the Retrofit billing service,
  Moshi DTOs, and `ApiResult<T>` mapping that this feature reuses/extends for the invoices endpoints.

## 3. Functional Requirements

FR-1. **Invoice list.** Display a scrollable, paginated list of invoices for the current user,
newest first (sorted by `issued_at` descending, server-ordered). Each row shows invoice number,
issue date, status badge (e.g. `paid`, `open`, `void`, `uncollectible`), and formatted total with
currency.

FR-2. **Pagination.** Use Paging 3 over the backend's cursor/offset list endpoint. Append the next
page on scroll; show an inline footer loading indicator and an inline retry affordance on append error.

FR-3. **Invoice detail.** Tapping a row navigates to a detail screen showing: invoice number,
status, issue date, due date (if present), billing period, line items (description, quantity,
unit amount, line total), subtotal, tax, and total, all currency-formatted.

FR-4. **Email invoice.** The detail screen exposes an "Email invoice" action that calls
`POST /ui/invoices/{n}/email`. The button is disabled while in flight, debounced to prevent
duplicate sends, and shows a success snackbar ("Invoice emailed to <email>") or an error snackbar
on failure.

FR-5. **Empty / loading / error states.** List and detail each render distinct loading, empty
("No invoices yet"), error (with retry), and offline/stale states per the core-ui state contract.

FR-6. **Offline & stale.** When the network is unavailable or times out, render cached invoices
from Room with a "Showing saved data" stale indicator; the email action is disabled offline.

FR-7. **Refresh.** The list supports pull-to-refresh, which re-fetches page 1 and revalidates the cache.

## 4. Technical Design

New module `feature-invoices` with package root `com.testlogon.android.feature.invoices`.

### Networking (extends AND-223 billing surface)

```kotlin
interface InvoicesApi {
    @GET("ui/invoices")
    suspend fun listInvoices(
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 20,
    ): InvoicePageDto

    @GET("ui/invoices/{n}")
    suspend fun getInvoice(@Path("n") invoiceId: String): InvoiceDto

    @POST("ui/invoices/{n}/email")
    suspend fun emailInvoice(@Path("n") invoiceId: String): EmailInvoiceResultDto
}
```

The `X-CSRF-Token` header (echoing the `ui_csrf` cookie) and persistent cookie jar are injected by
the shared OkHttp interceptors from core-network; the email POST is mutating and therefore relies on
CSRF. GET retries (idempotent) are handled by the core-network retry interceptor; the email POST is
**not** auto-retried.

### Repository

```kotlin
class InvoicesRepository @Inject constructor(
    private val api: InvoicesApi,
    private val dao: InvoiceDao,
    private val mapper: InvoiceMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    fun invoicePagingFlow(): Flow<PagingData<Invoice>>        // Paging 3 + RemoteMediator -> Room
    fun observeInvoice(id: String): Flow<Invoice?>            // Room-backed
    suspend fun refreshInvoice(id: String): ApiResult<Invoice>
    suspend fun emailInvoice(id: String): ApiResult<EmailInvoiceResult>
}
```

`InvoicesRemoteMediator : RemoteMediator<Int, InvoiceEntity>` writes pages to Room as the
single source of truth (Paging `pagingSourceFactory = { dao.pagingSource() }`).

### ViewModels

```kotlin
@HiltViewModel
class InvoiceListViewModel @Inject constructor(
    repo: InvoicesRepository,
) : ViewModel() {
    val pagingItems: Flow<PagingData<Invoice>> = repo.invoicePagingFlow().cachedIn(viewModelScope)
    fun refresh()
}

@HiltViewModel
class InvoiceDetailViewModel @Inject constructor(
    private val repo: InvoicesRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val invoiceId: String = checkNotNull(savedState["invoiceId"])
    val uiState: StateFlow<UiState<InvoiceDetail>>
    val emailState: StateFlow<EmailUiState>   // Idle | Sending | Sent(email) | Error(msg)
    fun onEmailClicked()
    fun retry()
}
```

`UiState<T>` is the shared core-ui sealed type: `Loading`, `Success(data, isStale)`, `Empty`,
`Error(message, retryable)`.

### UI (Compose)

- `InvoiceListScreen(onInvoiceClick: (String) -> Unit)` — `LazyColumn` over
  `pagingItems.collectAsLazyPagingItems()`, with `PullToRefreshBox`, footer load/retry, and
  state composables `InvoiceRow`, `InvoicesEmpty`, `InvoicesError`.
- `InvoiceDetailScreen(onBack: () -> Unit)` — `Scaffold` with `TopAppBar` (back), line-item list,
  totals section, and a primary `Button("Email invoice")` wired to `onEmailClicked()`; snackbar host
  for email feedback.

### Navigation

```kotlin
const val INVOICES_ROUTE = "invoices"
const val INVOICE_DETAIL_ROUTE = "invoices/{invoiceId}"

fun NavGraphBuilder.invoicesGraph(nav: NavController) {
    composable(INVOICES_ROUTE) {
        InvoiceListScreen(onInvoiceClick = { id -> nav.navigate("invoices/$id") })
    }
    composable(
        INVOICE_DETAIL_ROUTE,
        arguments = listOf(navArgument("invoiceId") { type = NavType.StringType }),
    ) { InvoiceDetailScreen(onBack = { nav.popBackStack() }) }
}
```

Hilt module `InvoicesModule` provides `InvoicesApi` (from the shared Retrofit instance) and binds
`InvoicesRepository`.

## 5. API Contract

All paths are relative to base `http://18.222.237.167:8000`. Shapes mirror
`frontend/src/api/types.ts`; confirm exact field names against `/openapi.json` at implementation time
and align Moshi `@Json(name=...)` accordingly.

**GET `/ui/invoices?cursor=&limit=20`** → `200`:

```json
{
  "items": [
    {
      "id": "in_1052",
      "number": "INV-2026-001052",
      "status": "paid",
      "currency": "usd",
      "total": 4900,
      "issued_at": "2026-05-01T12:00:00Z",
      "due_at": "2026-05-15T12:00:00Z"
    }
  ],
  "next_cursor": "eyJvIjoyMH0=",
  "has_more": true
}
```

**GET `/ui/invoices/{n}`** → `200`:

```json
{
  "id": "in_1052",
  "number": "INV-2026-001052",
  "status": "paid",
  "currency": "usd",
  "subtotal": 4500,
  "tax": 400,
  "total": 4900,
  "issued_at": "2026-05-01T12:00:00Z",
  "due_at": "2026-05-15T12:00:00Z",
  "period_start": "2026-04-01T00:00:00Z",
  "period_end": "2026-04-30T23:59:59Z",
  "line_items": [
    { "description": "Pro plan — April", "quantity": 1, "unit_amount": 4500, "amount": 4500 }
  ]
}
```

**POST `/ui/invoices/{n}/email`** (headers: `X-CSRF-Token: <ui_csrf>`, cookies) → `200`:

```json
{ "ok": true, "email": "spannella@gmail.com" }
```

Monetary amounts are integer minor units; format using `currency` + `NumberFormat`. Errors follow
the FastAPI `detail` convention — `string | [{msg}] | {code,...}` — mapped by the core-network error
mapper (shared from AND-223) into `ApiResult.Error(message, code)`. Notable statuses: `401`
(triggers single refresh+retry in the interceptor), `404` (invoice not found → detail Error,
non-retryable), `429`/`5xx` (transient → list/email retry guidance).

DTOs (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class InvoicePageDto(
    val items: List<InvoiceSummaryDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
    @Json(name = "has_more") val hasMore: Boolean,
)

@JsonClass(generateAdapter = true)
data class InvoiceSummaryDto(
    val id: String, val number: String, val status: String,
    val currency: String, val total: Long,
    @Json(name = "issued_at") val issuedAt: String,
    @Json(name = "due_at") val dueAt: String?,
)

@JsonClass(generateAdapter = true)
data class InvoiceDto(
    val id: String, val number: String, val status: String, val currency: String,
    val subtotal: Long, val tax: Long, val total: Long,
    @Json(name = "issued_at") val issuedAt: String,
    @Json(name = "due_at") val dueAt: String?,
    @Json(name = "period_start") val periodStart: String?,
    @Json(name = "period_end") val periodEnd: String?,
    @Json(name = "line_items") val lineItems: List<InvoiceLineItemDto>,
)

@JsonClass(generateAdapter = true)
data class InvoiceLineItemDto(
    val description: String, val quantity: Int,
    @Json(name = "unit_amount") val unitAmount: Long, val amount: Long,
)

@JsonClass(generateAdapter = true)
data class EmailInvoiceResultDto(val ok: Boolean, val email: String?)
```

## 6. Data & State Management

Room is the single source of truth for the list (offline/stale). Entities:

```kotlin
@Entity(tableName = "invoices")
data class InvoiceEntity(
    @PrimaryKey val id: String, val number: String, val status: String,
    val currency: String, val total: Long, val issuedAt: Long, val dueAt: Long?,
    val pageOrder: Int, val cachedAt: Long,
)
```

A separate `InvoiceDetailEntity` (+ embedded/relation line items, or JSON column for line items)
caches detail payloads. `InvoiceDao` exposes `pagingSource(): PagingSource<Int, InvoiceEntity>`,
`upsertAll`, `clearAll`, and `observeDetail(id)`. `RemoteMediator` clears+repopulates on `REFRESH`
and appends on `APPEND` using `next_cursor`. Last-sync timestamp lives in DataStore
(`invoices_last_sync_epoch`); `isStale = now - lastSync > 5m` drives the "Showing saved data" badge.

Domain models (`core-model`): `Invoice`, `InvoiceDetail`, `InvoiceLineItem`, `InvoiceStatus`
(enum with `UNKNOWN` fallback for forward-compat), `EmailInvoiceResult`. `InvoiceMapper` converts
DTO ↔ entity ↔ domain. ISO-8601 timestamps parsed to epoch millis at the mapper boundary.

ViewModel state is `StateFlow<UiState<…>>` exposed via `collectAsStateWithLifecycle`. The email
action uses a dedicated `EmailUiState` so it does not clobber the screen's primary state.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call/connect/read timeouts ≈ 20s (shared client). Long spinners are
  acceptable but always interruptible.
- **Retry:** Idempotent GETs (`/ui/invoices`, `/ui/invoices/{n}`) use the shared bounded
  exponential backoff (≈3 attempts, jitter) for transient (`5xx`, timeout, connection) errors. The
  email **POST is not retried automatically**; the user re-triggers via the button.
- **401:** Handled centrally — one `POST /ui/session/refresh` then retry; a second 401 surfaces a
  re-auth error routed to the auth flow.
- **Offline / stale:** On network failure with non-empty cache, list shows cached data + stale
  badge; with empty cache, shows `Error(retryable=true)`. The email button is disabled when offline
  (connectivity observed via core-data) and re-enabled on reconnect.
- **Email failure:** Map to a snackbar with a "Retry" action; success transitions
  `EmailUiState -> Sent(email)`. Duplicate-send protection via in-flight guard + 1s debounce.
- **404 on detail:** Non-retryable Error state with "Invoice not found" and a back affordance.

## 8. Security & Privacy

- All requests carry the session cookies via the persistent cookie jar; mutating
  `POST /ui/invoices/{n}/email` includes the `X-CSRF-Token` header from the `ui_csrf` cookie.
- No invoice PDFs/tokens or credentials are persisted beyond the Room cache; the cache holds only
  invoice metadata already authorized for this session. Clear the invoices cache on logout
  (hook into the session-clear broadcast from the auth module).
- The dev backend is plaintext HTTP; the app permits cleartext **only** for the dev host via the
  network-security-config flag owned by core-network. No invoice data is logged at WARN/ERROR with
  PII; amounts/emails are redacted in release logging (see §10).
- Email recipient is server-determined (the session user's address); the client does not accept a
  free-form recipient, avoiding an exfiltration vector.

## 9. Accessibility & i18n

- All strings in `feature-invoices/src/main/res/values/strings.xml`; no hardcoded UI text.
- Currency and dates formatted via `NumberFormat.getCurrencyInstance(locale)` and locale-aware
  `DateTimeFormatter`; never string-concatenate currency symbols.
- Status badges expose `contentDescription` (e.g., "Status: paid"); the email button has a
  descriptive label and announces result via the snackbar (live region).
- Touch targets ≥48dp; list rows are a single semantics node with a merged content description
  (number, date, total, status). Supports TalkBack focus order list → detail → email.
- Dynamic type respected (Material 3 typography, no fixed `sp` overrides that block scaling);
  light/dark themes from core-ui.

## 10. Telemetry & Logging

- Analytics events via core-data telemetry sink: `invoices_list_viewed`,
  `invoice_detail_viewed { invoice_id }`, `invoice_email_requested { invoice_id }`,
  `invoice_email_succeeded { invoice_id }`, `invoice_email_failed { invoice_id, code }`,
  `invoices_list_load_error { code }`.
- Logging via Timber; release builds redact `email` and monetary `amount`/`total` fields. Log
  network failures at WARN with endpoint + HTTP status + error `code` only (no bodies).
- No invoice numbers or emails sent to crash reporting; only opaque ids and error codes.

## 11. Testing Strategy

- **Unit (core-testing + JUnit5 + Turbine + MockWebServer):**
  - `InvoiceMapperTest` — DTO→entity→domain field mapping, minor-unit handling, null `due_at`,
    unknown `status` → `InvoiceStatus.UNKNOWN`.
  - `InvoicesRepositoryTest` — MockWebServer success, 404, 5xx→retry, offline→cached+stale,
    `emailInvoice` success/failure (asserts `X-CSRF-Token` present, no auto-retry on POST).
  - `InvoiceDetailViewModelTest` — `uiState` transitions; `emailState` Idle→Sending→Sent / →Error;
    debounce/in-flight guard prevents duplicate POSTs.
  - `InvoicesRemoteMediatorTest` — REFRESH clears+loads, APPEND uses `next_cursor`,
    `endOfPaginationReached` when `has_more=false`.
- **Instrumented/Compose (`createAndroidComposeRule`):** list renders rows; empty/error/stale
  states; tap row → detail; email button disabled while sending and shows success snackbar; Paging
  append loading indicator.
- **Contract:** golden JSON fixtures derived from `/openapi.json` and `invoices.ts` fixtures to
  guard against drift.
- Acceptance gate: "Invoices render" → list + detail Compose tests green; "email works" →
  repository + ViewModel email tests green.

## 12. Dependencies & Sequencing

- **Depends on AND-223 (Billing API + DTOs)** — provides the shared Retrofit billing service base,
  Moshi adapters, `ApiResult<T>`, and FastAPI `detail` error mapping that this feature reuses.
  Invoices-specific endpoints/DTOs may extend that surface if AND-223 did not include them.
- Transitively depends on the core-network auth/cookie/CSRF/refresh interceptor stack and the
  core-ui `UiState`/state composables, and on Navigation host wiring in `app`.
- Sequencing: AND-223 must merge first. This ticket then lands `feature-invoices` and registers
  `invoicesGraph` in the app nav host. No tickets currently block on AND-243.

## 13. Risks & Open Questions

- R-1: Exact invoice field names and pagination style (cursor vs offset) are unconfirmed — verify
  against `/openapi.json` and `invoices.ts`; mapper/DTOs may need renaming.
- R-2: The `/ui/invoices/{n}/email` response shape (does it return the recipient `email`?) is
  assumed; if absent, the success snackbar must use the session user's `GET /ui/me` email.
- R-3: Unreliable dev host may cause flaky instrumented tests — mock the network in CI; reserve live
  runs for manual verification.
- R-4: Does the email endpoint enforce server-side rate limiting (`429`)? If so, surface a
  "Please wait before re-sending" message. Open until confirmed.
- R-5: Whether AND-223 already defined invoice DTOs or only billing summary DTOs determines how much
  DTO code lives here vs. core-network.

## 14. Acceptance Criteria

- AC-1 (Invoices render — list): Given a valid session and available backend, the list displays
  invoices (number, date, status, total) newest-first and pages additional results on scroll.
- AC-2 (Invoices render — detail): Tapping an invoice opens a detail screen showing line items,
  subtotal, tax, total, status, and dates, all currency/locale-formatted.
- AC-3 (Email works): Tapping "Email invoice" issues `POST /ui/invoices/{n}/email` with cookies +
  `X-CSRF-Token`, disables the button while in flight, and shows a success snackbar on `200`.
- AC-4 (Email failure): A non-2xx email response shows an error snackbar with retry; no duplicate
  POST is sent for a single tap (debounce/in-flight guard verified).
- AC-5 (Resilience): With no network and a populated cache, the list renders cached invoices with a
  stale indicator and the email button disabled; with an empty cache it shows a retryable error.
- AC-6 (Auth): A `401` triggers exactly one `POST /ui/session/refresh` + retry before surfacing a
  re-auth error.
- AC-7 (Tests): Mapper, repository, ViewModel, RemoteMediator, and Compose tests for the above pass
  in CI.

## 15. Definition of Done

- `feature-invoices` module merged on `android-port` under `com.testlogon.android.feature.invoices`,
  wired into the app nav host via `invoicesGraph`.
- List, detail, and email implemented per FRs with offline/stale and error states.
- All §11 tests written and green in CI; Compose acceptance tests cover AC-1..AC-5.
- No hardcoded strings; a11y content descriptions and dynamic type verified with TalkBack.
- Release logging redacts email/amounts; invoices cache cleared on logout.
- Lint/detekt/ktlint clean; KSP builds with no new warnings; PR reviewed and approved.
- DTO field names reconciled against `/openapi.json` (R-1/R-2 resolved or documented as follow-ups).
