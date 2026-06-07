---
id: AND-243
title: Invoices
milestone: M5
epic: E33
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-223]
blocks: []
---

# AND-243 — Invoices

## 1. Overview & Goal

Deliver the Invoices feature for the TestLogon native Android app: a paginated list of the
authenticated user's billing invoices and a per-invoice detail screen, plus the ability to
trigger an emailed copy of a single invoice via `POST /ui/invoices/{invoice_number}/email` (the
path parameter is the string `invoice_number`, not a numeric id — corrected from `{n}`). The web
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
- Auth (verified against `src/api/client.ts`): the web client sends THREE auth signals on requests:
  (1) `Authorization: Bearer <accessToken>` from the auth store, (2) session cookies via
  `credentials: "include"` (persistent cookie jar on Android), and (3) the `ui_csrf` cookie echoed
  as `X-CSRF-Token`. Correction: `X-CSRF-Token` is sent on **all** requests (GET included), not only
  mutating ones. On `401` (when authenticated) the client performs exactly one
  `POST /ui/session/refresh` then retries the original request once; a second 401 logs out
  (`session_expired`). The invoices endpoints also declare optional `X-SESSION-ID`,
  `X-IMPERSONATION-TOKEN` headers and a `user_sub` query param in OpenAPI (impersonation/admin
  paths; not used by the normal logged-in user flow). The refresh-once-then-retry behavior is owned
  by core-network/auth tickets and consumed here.
- Upstream dependency: **AND-223 (Billing API + DTOs)** provides the Retrofit billing service,
  Moshi DTOs, and `ApiResult<T>` mapping that this feature reuses/extends for the invoices endpoints.

## 3. Functional Requirements

FR-1. **Invoice list.** Display a scrollable list of invoices for the current user. Each row shows
invoice number (`invoice_number`), creation date (`created_at`, epoch seconds), the invoice type
(`invoice_type` — e.g. `tip`, `unlock`, `subscription`, `shop`, `deposit`, per the web type filter),
an `emailed` badge when `status == "emailed"`, and formatted total (`total_cents`) with `currency`.
NOTE (corrected): the backend `InvoiceOut` has no `issued_at` field and no `paid/open/void/
uncollectible` status enum (those were Stripe-style assumptions). The default `status` is
`generated`; the only status surfaced by the web client is `emailed`. The display date is
`created_at`. Server-side "newest first" ordering is **unverified** (no sort param in the OpenAPI
endpoint and the web client applies no client-side sort) — treat ordering as backend-defined.

FR-2. **Pagination.** The list endpoint `GET /ui/invoices` supports cursor pagination
(`limit`, `cursor` query params; response carries `next_cursor: string | null`). NOTE: the web
reference does **not** page — it fetches `limit: 100` once and filters client-side; there is no
`has_more` field (corrected from spec's earlier assumption). The Android app MAY still use Paging 3
over `cursor`/`next_cursor` as a forward-looking improvement: append the next page on scroll while
`next_cursor != null`, with an inline footer loading indicator and inline retry on append error.
`endOfPaginationReached` is driven by `next_cursor == null` (not by a boolean `has_more`).

FR-3. **Invoice detail.** Tapping a row navigates to a detail screen (`GET /ui/invoices/{invoice_number}`
→ `InvoiceOut`) showing: invoice number, `invoice_type`, `status`, creation date (`created_at`),
seller name (`seller_name`), buyer name/email (`buyer_name`, `buyer_email`), payment method
(`payment_method_summary`), line items (`description`, `quantity`, `amount_cents`), `tax_cents`, and
`total_cents`, all currency-formatted. NOTE (corrected): `InvoiceOut` has **no** `subtotal`,
`issued_at`, `due_at`, `period_start`, or `period_end` fields, and line items have **no**
`unit_amount` — each line item is `{description, amount_cents, quantity}` only (`InvoiceLineItemOut`).
There is a separate "amount" (`amount_cents`) vs. `total_cents` (total incl. `tax_cents`). The web
client itself has no detail page (only `getInvoice` exists in `endpoints/invoices.ts`); the Android
detail screen is a net-new surface, so its layout is an Android design choice, not a web port.

FR-4. **Email invoice.** The "Email invoice" action calls `POST /ui/invoices/{invoice_number}/email`
→ `InvoiceEmailOut {ok, emailed_to, message}`. The button is disabled while in flight (in-flight
guard) and shows a success snackbar (`"Invoice emailed to <emailed_to>"`, omitting the recipient
clause when `emailed_to` is empty — the field has a `""` default) or an error snackbar on failure.
NOTE (corrected): the recipient field is `emailed_to`, not `email`; the response also carries a
human-readable `message`. The web client uses only a per-row in-flight flag (no explicit 1s
debounce); the debounce in §7 is an Android-side hardening choice, not a web parity requirement.

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
        @Query("type") type: String? = null,        // tip|unlock|subscription|shop|deposit
        @Query("date_from") dateFrom: Long? = null,  // epoch SECONDS
        @Query("date_to") dateTo: Long? = null,      // epoch SECONDS
    ): InvoiceListDto

    // Path param is the string invoice_number, NOT a numeric id.
    @GET("ui/invoices/{invoice_number}")
    suspend fun getInvoice(@Path("invoice_number") invoiceNumber: String): InvoiceDto

    @POST("ui/invoices/{invoice_number}/email")
    suspend fun emailInvoice(@Path("invoice_number") invoiceNumber: String): InvoiceEmailDto
}
```

The `X-CSRF-Token` header (echoing the `ui_csrf` cookie), `Authorization: Bearer` token, and
persistent cookie jar are injected by the shared OkHttp interceptors from core-network. Per the web
client, `X-CSRF-Token` is attached to **all** requests (GET and POST), though it is functionally
required for the mutating email POST. GET retries (idempotent) are handled by the core-network retry
interceptor; the email POST is **not** auto-retried.

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

All paths are relative to base `http://18.222.237.167:8000`. The shapes below are VERIFIED against
`reference/openapi.pretty.json` (`components.schemas.InvoiceListOut`, `app__models__InvoiceOut`,
`InvoiceLineItemOut`, `InvoiceEmailOut`) and `reference/src/api/types.ts`. The earlier Stripe-style
shapes (`id`/`number`/`total`/`issued_at`/`subtotal`/`has_more`/`unit_amount`/`email`) were WRONG and
are corrected here.

**GET `/ui/invoices?type=&date_from=&date_to=&limit=20&cursor=`** → `200` (`InvoiceListOut`):

```json
{
  "invoices": [
    {
      "invoice_id": "in_1052",
      "invoice_number": "INV-2026-001052",
      "invoice_type": "subscription",
      "user_sub": "user_abc",
      "amount_cents": 4500,
      "tax_cents": 400,
      "total_cents": 4900,
      "currency": "usd",
      "status": "generated",
      "seller_id": "acct_1",
      "seller_name": "TestLogon Inc.",
      "buyer_name": "Sean P.",
      "buyer_email": "spannella@gmail.com",
      "line_items": [
        { "description": "Pro plan — April", "quantity": 1, "amount_cents": 4500 }
      ],
      "payment_method_summary": "Visa •••• 4242",
      "ledger_entry_id": "le_77",
      "created_at": 1746100800
    }
  ],
  "next_cursor": null
}
```

Notes: list field is `invoices` (not `items`); pagination cursor is `next_cursor` (string | null); there
is **no** `has_more`. `date_from`/`date_to` are epoch **seconds**. Required fields per schema:
`invoice_id, invoice_number, invoice_type, user_sub, amount_cents, total_cents`; all others have
server defaults (e.g. `currency="usd"`, `status="generated"`, `quantity=1`, `created_at=0`).

**GET `/ui/invoices/{invoice_number}`** → `200` (`app__models__InvoiceOut`): same object shape as a
list item above. There is **no** `subtotal`, `issued_at`, `due_at`, `period_start`, or `period_end`.
Line items (`InvoiceLineItemOut`) are `{description, amount_cents, quantity}` only — no `unit_amount`,
no per-line `amount`. `created_at` is an integer epoch (seconds), not an ISO-8601 string.

**POST `/ui/invoices/{invoice_number}/email`** (headers: `X-CSRF-Token: <ui_csrf>`,
`Authorization: Bearer`, cookies) → `200` (`InvoiceEmailOut`):

```json
{ "ok": true, "emailed_to": "spannella@gmail.com", "message": "Invoice emailed." }
```

Recipient field is `emailed_to` (not `email`); all three fields have defaults
(`ok=true`, `emailed_to=""`, `message=""`).

Monetary amounts are integer minor units (`*_cents`); format using `currency` + `NumberFormat`,
dividing by 100 (web does `cents / 100`). Errors follow the FastAPI convention: the OpenAPI declares
`422 → HTTPValidationError { detail: [ValidationError{loc, msg, type}] }` for these endpoints, and
the shared client also handles `detail` as `string | {code,...}`. The core-network error mapper
(shared from AND-223) maps to `ApiResult.Error(message, code)`. Notable statuses: `401`
(triggers single refresh+retry in the interceptor), `422` (validation — bad path/query),
`404` (invoice not found → detail Error, non-retryable), `429`/`5xx` (transient → retry guidance;
`429` for the email endpoint is unconfirmed, see R-4).

DTOs (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class InvoiceListDto(
    val invoices: List<InvoiceDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
)

@JsonClass(generateAdapter = true)
data class InvoiceDto(
    @Json(name = "invoice_id") val invoiceId: String,
    @Json(name = "invoice_number") val invoiceNumber: String,
    @Json(name = "invoice_type") val invoiceType: String,
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "tax_cents") val taxCents: Long = 0,
    @Json(name = "total_cents") val totalCents: Long,
    val currency: String = "usd",
    val status: String = "generated",
    @Json(name = "seller_id") val sellerId: String = "",
    @Json(name = "seller_name") val sellerName: String = "",
    @Json(name = "buyer_name") val buyerName: String = "",
    @Json(name = "buyer_email") val buyerEmail: String = "",
    @Json(name = "line_items") val lineItems: List<InvoiceLineItemDto> = emptyList(),
    @Json(name = "payment_method_summary") val paymentMethodSummary: String = "",
    @Json(name = "ledger_entry_id") val ledgerEntryId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,   // epoch SECONDS
)

@JsonClass(generateAdapter = true)
data class InvoiceLineItemDto(
    val description: String,
    @Json(name = "amount_cents") val amountCents: Long,
    val quantity: Int = 1,
)

@JsonClass(generateAdapter = true)
data class InvoiceEmailDto(
    val ok: Boolean = true,
    @Json(name = "emailed_to") val emailedTo: String = "",
    val message: String = "",
)
```

## 6. Data & State Management

Room is the single source of truth for the list (offline/stale). Entities:

```kotlin
@Entity(tableName = "invoices")
data class InvoiceEntity(
    @PrimaryKey val invoiceNumber: String,   // PK = invoice_number (the path param / web row key)
    val invoiceId: String, val invoiceType: String, val status: String,
    val currency: String, val totalCents: Long, val createdAt: Long,  // createdAt = epoch seconds
    val pageOrder: Int, val cachedAt: Long,
)
```

A separate `InvoiceDetailEntity` (+ embedded/relation line items, or JSON column for line items)
caches detail payloads. `InvoiceDao` exposes `pagingSource(): PagingSource<Int, InvoiceEntity>`,
`upsertAll`, `clearAll`, and `observeDetail(invoiceNumber)`. `RemoteMediator` clears+repopulates on
`REFRESH` and appends on `APPEND` using `next_cursor`, treating `next_cursor == null` as
`endOfPaginationReached = true` (there is no `has_more` boolean). Last-sync timestamp lives in
DataStore (`invoices_last_sync_epoch`); `isStale = now - lastSync > 5m` drives the "Showing saved
data" badge.

Domain models (`core-model`): `Invoice`, `InvoiceDetail`, `InvoiceLineItem`, `InvoiceStatus`
(enum with `UNKNOWN` fallback for forward-compat; known values seen so far: `generated`, `emailed`),
`EmailInvoiceResult`. `InvoiceMapper` converts DTO ↔ entity ↔ domain. NOTE (corrected): timestamps
(`created_at`) arrive as integer epoch **seconds**, not ISO-8601 strings — the mapper multiplies by
1000 for epoch millis / formatting (web does `new Date(ts * 1000)`).

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

- R-1: RESOLVED in this review. Field names and shapes confirmed against
  `openapi.pretty.json` (`InvoiceListOut`/`app__models__InvoiceOut`/`InvoiceLineItemOut`/
  `InvoiceEmailOut`) and `src/api/types.ts`; DTOs in §5 corrected accordingly. Pagination is
  cursor-based (`cursor`/`next_cursor`), no `has_more`; the web client does not page (single
  `limit:100` fetch) so Android cursor-paging is a forward-looking choice, not a strict port.
- R-2: RESOLVED. `POST /ui/invoices/{invoice_number}/email` → `InvoiceEmailOut` DOES return the
  recipient as `emailed_to` (plus `message`). Snackbar uses `emailed_to`; the `GET /ui/me` fallback
  is unnecessary but remains a safe guard if `emailed_to` is empty (its schema default is `""`).
- R-3: Unreliable dev host may cause flaky instrumented tests — mock the network in CI; reserve live
  runs for manual verification.
- R-4: Does the email endpoint enforce server-side rate limiting (`429`)? If so, surface a
  "Please wait before re-sending" message. Open until confirmed.
- R-5: Whether AND-223 already defined invoice DTOs or only billing summary DTOs determines how much
  DTO code lives here vs. core-network.

## 14. Acceptance Criteria

- AC-1 (Invoices render — list): Given a valid session and available backend, the list displays
  invoices (`invoice_number`, `created_at` date, `invoice_type`/`emailed` badge, `total_cents`) in
  backend-returned order and pages additional results on scroll while `next_cursor != null`.
- AC-2 (Invoices render — detail): Tapping an invoice opens a detail screen showing line items
  (`description`, `quantity`, `amount_cents`), `tax_cents`, `total_cents`, `status`, and the
  `created_at` date, all currency/locale-formatted. (No subtotal/issued_at/due_at/period fields.)
- AC-3 (Email works): Tapping "Email invoice" issues `POST /ui/invoices/{invoice_number}/email` with
  cookies + `Authorization` + `X-CSRF-Token`, disables the button while in flight, and shows a
  success snackbar (using `emailed_to`) on `200`.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact authoritative source pointer.

1. **List endpoint is `GET /ui/invoices` returning `InvoiceListOut`.** VERIFIED.
   Source: OpenAPI `GET /ui/invoices` (op=`list_invoices_ui_invoices_get`, resp=`200:InvoiceListOut`);
   frontend `src/api/endpoints/invoices.ts: listInvoices`.
2. **List response wrapper field is `invoices` (array), with `next_cursor: string | null`; there is NO
   `has_more` and NO `items` field.** CORRECTED (spec said `items` + `has_more`).
   Source: OpenAPI `components.schemas.InvoiceListOut`; `src/api/types.ts: InvoiceList`.
3. **List query params are `type, date_from, date_to, limit, cursor` (+ `user_sub`, `X-SESSION-ID`,
   `X-IMPERSONATION-TOKEN`); `date_from`/`date_to` are epoch seconds.** CORRECTED (spec listed only
   `cursor,limit`). Source: OpenAPI `GET /ui/invoices` params=`type,date_from,date_to,limit,cursor,
   user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`; `src/api/endpoints/invoices.ts: InvoiceListParams`
   and `src/pages/billing/InvoicesPage.tsx: toEpoch` (`Math.floor(ms/1000)`).
4. **Detail/email path parameter is the string `invoice_number`, NOT a numeric `{n}` id.** CORRECTED.
   Source: OpenAPI `GET /ui/invoices/{invoice_number}` and `POST /ui/invoices/{invoice_number}/email`;
   frontend `src/api/endpoints/invoices.ts: getInvoice`/`emailInvoice` (path uses `invoiceNumber`).
5. **Detail endpoint `GET /ui/invoices/{invoice_number}` returns `app__models__InvoiceOut`.** VERIFIED.
   Source: OpenAPI `GET /ui/invoices/{invoice_number}` (resp=`200:app__models__InvoiceOut`).
6. **Invoice object fields are `invoice_id, invoice_number, invoice_type, user_sub, amount_cents,
   tax_cents, total_cents, currency, status, seller_id, seller_name, buyer_name, buyer_email,
   line_items, payment_method_summary, ledger_entry_id, created_at`.** CORRECTED (spec invented
   `id/number/total/subtotal/issued_at/due_at/period_start/period_end`). Source:
   `components.schemas.app__models__InvoiceOut`; `src/api/types.ts: Invoice`.
7. **Line items are `InvoiceLineItemOut {description, amount_cents, quantity(default 1)}` — no
   `unit_amount`, no per-line `amount`, no separate `subtotal`.** CORRECTED. Source:
   `components.schemas.InvoiceLineItemOut`; `src/api/types.ts: InvoiceLineItem`.
8. **Monetary amounts are integer minor units (`*_cents`), formatted as `cents / 100`.** VERIFIED.
   Source: schema integer `*_cents` fields; `src/pages/billing/InvoiceRow.tsx: formatCents`.
9. **`created_at` is an integer epoch in SECONDS (not ISO-8601).** CORRECTED (spec said ISO-8601).
   Source: `app__models__InvoiceOut.created_at` (type integer); `InvoiceRow.tsx: formatDate`
   (`new Date(ts * 1000)`).
10. **Email endpoint `POST /ui/invoices/{invoice_number}/email` returns `InvoiceEmailOut
    {ok, emailed_to, message}`; recipient field is `emailed_to` (not `email`).** CORRECTED.
    Source: OpenAPI `POST /ui/invoices/{invoice_number}/email` (resp=`200:InvoiceEmailOut`);
    `components.schemas.InvoiceEmailOut`; `src/api/types.ts: InvoiceEmailResult`;
    `src/pages/billing/InvoiceRow.tsx: onEmail` (`res.emailed_to`).
11. **Email POST takes no request body; recipient is server-determined (no free-form recipient).**
    VERIFIED. Source: OpenAPI email op `req=` (empty); `src/api/endpoints/invoices.ts: emailInvoice`
    (`api.post` with no body).
12. **Auth: requests carry `Authorization: Bearer <accessToken>` AND session cookies
    (`credentials: include`) AND `X-CSRF-Token` from the `ui_csrf` cookie, on ALL requests.**
    CORRECTED (spec implied cookie-only and CSRF on mutating requests only). Source:
    `src/api/client.ts` (sets `Authorization` header, `X-CSRF-Token` for every request,
    `credentials: "include"`).
13. **On 401 (when authenticated) the client does exactly one `POST /ui/session/refresh` then retries
    once; a second 401 logs out (`session_expired`).** VERIFIED. Source: `src/api/client.ts:
    refreshSession` + 401 handling block.
14. **FastAPI error shape for these endpoints: `422 → HTTPValidationError {detail:[ValidationError
    {loc,msg,type}]}`; client also handles `detail` as `string | {code,...}`.** VERIFIED. Source:
    OpenAPI invoices ops resp=`422:HTTPValidationError`; `components.schemas.HTTPValidationError` +
    `ValidationError`; `src/api/client.ts: normalizeErrorDetail`.
15. **Invoice `status` has no `paid/open/void/uncollectible` enum; default is `generated`, and the
    only status the web UI surfaces is `emailed`. Invoice `type` values are
    `tip|unlock|subscription|shop|deposit`.** CORRECTED. Source: `app__models__InvoiceOut.status`
    (default `generated`); `InvoiceRow.tsx` (`status === "emailed"`); `InvoicesPage.tsx: TYPES`.
16. **Web client does NOT paginate the list — it fetches `limit:100` once and filters/searches
    client-side; email/download live on each LIST row (the web has no detail page).** VERIFIED.
    Source: `src/pages/billing/InvoicesPage.tsx` (`limit: 100`, client `filter`); `InvoiceRow.tsx`
    (per-row Mail/Download buttons); no `getInvoice` consumer page exists.
17. **A `GET /ui/invoices/{invoice_number}/pdf` download endpoint also exists (out of AND-243
    scope).** VERIFIED, informational. Source: OpenAPI `GET /ui/invoices/{invoice_number}/pdf`;
    `src/api/endpoints/invoices.ts: downloadInvoicePdf`.
18. **Android stack/framework choices: Paging 3 with `RemoteMediator` over Room as single source of
    truth; cursor paging keyed on `next_cursor`.** Unverified-assumption (Android design choice, not
    derivable from web which does not page). framework ref:
    https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data .
19. **Compose `PullToRefreshBox` for pull-to-refresh; `collectAsLazyPagingItems()`; snackbar host
    for email feedback.** Unverified-assumption (Android design choice). framework ref:
    https://developer.android.com/develop/ui/compose/components/pull-to-refresh .
20. **`InvoiceStatus.UNKNOWN` forward-compat fallback and 5-minute staleness window are local design
    choices.** Unverified-assumption (not in any source). No external pointer.

### Corrections made

- C-1: List wrapper `items`→`invoices`; removed nonexistent `has_more`; cursor field is
  `next_cursor` (string|null). (§1, §2 ref, §3 FR-2, §4 DTO, §5, §6) — claims 2.
- C-2: List query params expanded to `type/date_from/date_to/limit/cursor` (epoch-seconds dates).
  (§4 API, §5) — claim 3.
- C-3: Path param `{n}`→`{invoice_number}` (string) across Overview, §4, §5, §14 AC-3. — claim 4.
- C-4: Invoice object/line-item fields replaced with the real `InvoiceOut`/`InvoiceLineItemOut`
  schema (`*_cents`, `created_at`, `buyer_*`, `seller_*`, etc.); removed invented
  `id/number/total/subtotal/issued_at/due_at/period_*/unit_amount`. (§3 FR-1/FR-3, §5, §6, §14
  AC-1/AC-2) — claims 6, 7.
- C-5: `created_at` is epoch SECONDS, not ISO-8601 (mapper ×1000). (§5, §6) — claim 9.
- C-6: Email response `{ok,email}`→`InvoiceEmailOut {ok,emailed_to,message}`; snackbar uses
  `emailed_to`. (§3 FR-4, §5, §14 AC-3) — claim 10.
- C-7: Auth corrected to include `Authorization: Bearer` and `X-CSRF-Token` on ALL requests, plus
  optional `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`/`user_sub`. (§2, §4) — claim 12.
- C-8: Status enum corrected (no `paid/open/void/uncollectible`; defaults `generated`, UI badge
  `emailed`); list display date is `created_at`; "newest-first server sort" downgraded to
  unverified. (§3 FR-1, §14 AC-1) — claim 15.
- C-9: R-1/R-2 in §13 marked RESOLVED with concrete schema findings.

### Open assumptions

- OA-1 (claim 18/19): Paging 3 + `RemoteMediator`, cursor paging, `PullToRefreshBox` are Android
  design choices — the web client does not paginate, so there is no web contract to verify against.
  Verifiable only by Android framework docs (cited), not by the backend/frontend sources.
- OA-2 (claim 20): `InvoiceStatus.UNKNOWN` fallback and the 5-minute staleness threshold are local
  conventions with no source; chosen for forward-compat/UX.
- OA-3 (R-4): Whether the email endpoint enforces `429` rate limiting is not expressed in OpenAPI
  (only `200`/`422` are declared) and cannot be confirmed without hitting the live server.
- OA-4: Backend list ordering ("newest first") is not declared by any sort param and the web applies
  no sort; the Android UI must treat order as backend-defined until confirmed against live data.
- OA-5: Whether AND-223 already ships these invoice DTOs vs. only billing-summary DTOs (R-5) is not
  determinable from these sources (depends on the AND-223 deliverable).

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD
`test35` (x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R,
API 34, arm64-v8a). MockWebServer-based contract/repository tests run on JVM. Compose-UI and
instrumented tests run on EMU unless a case needs real hardware/ABI behavior (then DEVICE).

- **TC-AND-243-01** — Type: contract/MockWebServer (JVM). Target: `InvoicesApi.listInvoices` +
  Moshi `InvoiceListDto`. Preconditions: MockWebServer enqueues a `200` `InvoiceListOut` golden
  body (fields per §5: `invoices[]` with `*_cents`, `created_at` int seconds, `next_cursor:null`).
  Steps: call `listInvoices(cursor=null, limit=20)`; assert request path `GET /ui/invoices?...`,
  query contains `limit=20`; deserialize. Expected: list parses; `invoices[0].totalCents` == body,
  `createdAt` is the integer seconds value, `nextCursor` == null; no field named `items`/`has_more`
  required. Traces: AC-1.
- **TC-AND-243-02** — Type: contract/MockWebServer (JVM). Target: `InvoicesApi.getInvoice` +
  `InvoiceDto`/`InvoiceLineItemDto`. Preconditions: enqueue `200` `app__models__InvoiceOut` with one
  line item `{description, amount_cents, quantity}`. Steps: call
  `getInvoice("INV-2026-001052")`; assert path `GET /ui/invoices/INV-2026-001052`. Expected: parses;
  `lineItems[0].amountCents` set, no `unitAmount` expected; `taxCents`/`totalCents` present; absence
  of `subtotal`/`issued_at`/`period_*` causes no failure. Traces: AC-2.
- **TC-AND-243-03** — Type: unit (JVM). Target: `InvoiceMapper`. Preconditions: DTO fixtures incl.
  unknown `status` value, default `currency`. Steps: map DTO→entity→domain. Expected: `created_at`
  seconds → epoch millis (×1000); `total_cents` preserved as minor units; unknown `status` →
  `InvoiceStatus.UNKNOWN`; PK/key is `invoice_number`. Traces: AC-1, AC-2.
- **TC-AND-243-04** — Type: contract/MockWebServer (JVM). Target: `InvoicesRepository.emailInvoice`
  happy path. Preconditions: enqueue `200` `InvoiceEmailOut {ok:true, emailed_to:"x@y.com",
  message:"..."}`; CSRF cookie set. Steps: call `emailInvoice("INV-...")`; capture request.
  Expected: `POST /ui/invoices/INV-.../email` with `X-CSRF-Token` header present and (when set)
  `Authorization` header; result maps to `EmailInvoiceResult(emailedTo="x@y.com")`; POST has no
  body. Traces: AC-3.
- **TC-AND-243-05** — Type: contract/MockWebServer (JVM). Target: repository email failure + no
  auto-retry on POST. Preconditions: enqueue a single `500` for the email endpoint. Steps: call
  `emailInvoice`; count requests received by MockWebServer. Expected: exactly ONE POST is sent (no
  auto-retry); result is `ApiResult.Error` (transient). Traces: AC-4.
- **TC-AND-243-06** — Type: contract/MockWebServer (JVM). Target: 404 detail handling.
  Preconditions: enqueue `404` (FastAPI `{"detail":"..."}`) for `GET /ui/invoices/{n}`. Steps: call
  `refreshInvoice("missing")`. Expected: `ApiResult.Error` mapped non-retryable ("Invoice not
  found"); detail `UiState.Error(retryable=false)`. Traces: AC-2.
- **TC-AND-243-07** — Type: contract/MockWebServer (JVM). Target: 422 validation shape mapping.
  Preconditions: enqueue `422` `HTTPValidationError {detail:[{loc,msg,type}]}`. Steps: trigger a
  list/detail call. Expected: error mapper extracts `detail[].msg` (per `normalizeErrorDetail`) into
  `ApiResult.Error(message)`. Traces: AC-1, AC-2.
- **TC-AND-243-08** — Type: unit (JVM, Turbine). Target: `InvoiceDetailViewModel` email state +
  in-flight/debounce guard. Preconditions: repo stub with a delayed `emailInvoice`. Steps: invoke
  `onEmailClicked()` twice in rapid succession. Expected: `emailState` Idle→Sending→Sent(emailedTo);
  the second tap during in-flight is swallowed (debounce/guard) so only ONE repository call occurs.
  Traces: AC-3, AC-4.
- **TC-AND-243-09** — Type: unit (JVM, Paging test). Target: `InvoicesRemoteMediator`.
  Preconditions: MockWebServer pages; page 1 `next_cursor="c2"`, page 2 `next_cursor=null`. Steps:
  REFRESH then APPEND. Expected: REFRESH clears+repopulates Room; APPEND uses `cursor=c2`;
  `endOfPaginationReached=true` when `next_cursor==null` (no `has_more` consulted). Traces: AC-1.
- **TC-AND-243-10** — Type: integration (JVM/Robolectric, Room + MockWebServer). Target:
  offline/stale path. Preconditions: seed Room with cached invoices + `last_sync` older than 5m;
  network calls fail/time out. Steps: collect list flow. Expected: cached invoices emitted with
  `isStale=true` ("Showing saved data"); with EMPTY cache instead, emits
  `UiState.Error(retryable=true)`. Traces: AC-5.
- **TC-AND-243-11** — Type: contract/MockWebServer (JVM). Target: 401 refresh-once-then-retry.
  Preconditions: enqueue `401`, then a `200` for `POST /ui/session/refresh`, then a `200` retry of
  the original GET; a SECOND `401` variant for the negative case. Steps: trigger a GET. Expected:
  exactly one `POST /ui/session/refresh` is sent, original request retried once and succeeds; on a
  second consecutive 401 a re-auth error surfaces (logout `session_expired`). Traces: AC-6.
- **TC-AND-243-12** — Type: Compose-UI (EMU). Target: `InvoiceListScreen` rendering + navigation.
  Preconditions: fake paging source with N invoices + an empty case. Steps: assert rows show
  `invoice_number`, formatted `created_at`, `invoice_type`/`emailed` badge, formatted `total_cents`;
  empty state shows "No invoices yet"; tap a row → `onInvoiceClick(invoiceNumber)` fires. Expected:
  all assertions pass; append loading footer appears while next page loads. Traces: AC-1.
- **TC-AND-243-13** — Type: Compose-UI (EMU). Target: `InvoiceDetailScreen` email flow + a11y.
  Preconditions: ViewModel stub. Steps: tap "Email invoice" → button disabled while Sending → on
  Sent show success snackbar "Invoice emailed to <emailed_to>"; on Error show error snackbar with
  Retry; verify status badge `contentDescription` ("Status: ..."), row merged semantics, touch
  targets ≥48dp, and snackbar announced via live region (TalkBack/semantics). Expected: states and
  a11y assertions pass. Traces: AC-3, AC-4.
- **TC-AND-243-14** — Type: instrumented/e2e (DEVICE — physical A15, API 34/arm64-v8a). Target:
  real-network email happy path + cleartext-permitted dev host + ABI/API-34 sanity. Preconditions:
  valid session/cookies on device; reachable dev backend (or on-device MockWebServer if host
  flaky). Steps: open Invoices, open an invoice, tap "Email invoice". Expected: `POST .../email`
  succeeds over cleartext HTTP (network-security-config dev-host exception works on API 34), success
  snackbar shows recipient; verifies arm64 build behaves as on EMU x86_64. MUST run on DEVICE
  (real-network + API-34/arm64 vs EMU API-35/x86_64 difference). Traces: AC-3, AC-5.
- **TC-AND-243-15** — Type: manual (DEVICE or EMU). Target: security/privacy — logout cache clear +
  release log redaction. Preconditions: release/redacting build; populated invoices cache. Steps:
  log out; inspect Room (cache cleared on session-clear broadcast) and logcat. Expected: invoices
  table cleared; no `buyer_email`/amounts/invoice numbers in WARN/ERROR logs (only ids + HTTP
  status + error code). Traces: AC-5, AC-7 (security aspects of §8/§10).

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (list renders + pages) | TC-01, TC-03, TC-09, TC-12 |
| AC-2 (detail renders) | TC-02, TC-03, TC-06 |
| AC-3 (email works) | TC-04, TC-08, TC-13, TC-14 |
| AC-4 (email failure + no dup POST) | TC-05, TC-08, TC-13 |
| AC-5 (resilience offline/stale) | TC-10, TC-14, TC-15 |
| AC-6 (401 refresh-once-retry) | TC-11 |
| AC-7 (tests green in CI) | TC-01..TC-13 (CI suite); TC-15 (security) |
