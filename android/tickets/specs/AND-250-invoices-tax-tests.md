---
id: AND-250
title: Invoices/tax tests
milestone: M5
epic: E33
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-249, AND-243]
blocks: []
---

# AND-250 — Invoices/tax tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the Invoices and
Tax surface of the TestLogon native Android port. It is a pure **Test** ticket
(Type: Test, Priority: P2): no production behavior is added. The goal is to
provide repository-level and UI-level coverage for the invoices/tax feature
whose production code is built in AND-243 (`invoices.ts` list/detail port and
`/ui/invoices/{invoice_number}/email`) and AND-249 (Invoices/tax ViewModels with
state + Paging 3).

> **Reviewer note (AND-250):** This file was reviewed against the backend
> OpenAPI index/spec and the frontend reference app on 2026-06-06. Several
> contract claims in the original draft were corrected in place (path params,
> response field names, the tax-summary path, and the post-refresh CSRF
> behavior). See §16 for the full citation/assumption audit and §17 for the
> test plan. The invoice path parameter is the **string** `invoice_number`
> (e.g. `INV-1001`), **not** an integer `n`.

Concretely, this ticket adds:

- **Repository / data-layer tests** for `InvoiceRepository`, the Retrofit
  service, Moshi adapters, the `PagingSource`, and the FastAPI `detail` error
  mapping for the invoices/tax endpoints.
- **ViewModel tests** for `InvoiceListViewModel`, `InvoiceDetailViewModel`, and
  `TaxSummaryViewModel`, asserting `StateFlow<UiState>` transitions, paging
  emission, the email action, retry/refresh, and cookie/CSRF/401-refresh
  interaction at the boundary.
- **Compose UI tests** for the invoice list, invoice detail (including the
  "Email invoice" flow), and the tax summary screen, covering loading, success,
  empty, offline/stale, and error rendering plus accessibility semantics.

"Acceptance: Pass" — the success condition is that the new test modules compile
and the full suite (unit + instrumented) runs green in CI, with the coverage
thresholds in §11 met. No flaky tests, no disabled tests.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base `com.testlogon.android`.
- **Module layering:** `app -> feature-* -> core-*`. Tests in this ticket live
  in `feature-invoices` (ViewModel + Compose UI tests) and `core-data`
  (repository/PagingSource/error-mapping tests), with shared fakes from
  `core-testing`.
- **Upstream tickets:**
  - **AND-243 — Invoices** (P1): production `invoices.ts` port — list/detail and
    `/ui/invoices/{n}/email`. Owns the API contract and models under test here.
  - **AND-249 — Invoices/tax ViewModels** (P2, depends on AND-243): owns
    `InvoiceListViewModel`, `InvoiceDetailViewModel`, `TaxSummaryViewModel`,
    paging wiring, and `UiState` shapes. This ticket (AND-250) is its direct
    test counterpart and **depends on AND-249** plus transitively AND-243.
- **Web reference:** `frontend/src/api/endpoints/invoices.ts` (list/detail/email/
  pdf), `frontend/src/api/endpoints/taxDocuments.ts` (tax summary lives at
  `/ui/tax-documents/summary`), shared types in `frontend/src/api/types.ts`
  (`Invoice`, `InvoiceList`, `InvoiceEmailResult`, `SpendingSummary`), and the
  transport/CSRF wrapper in `frontend/src/api/client.ts`. Use these to confirm
  field names and response shapes; the OpenAPI spec at
  `http://18.222.237.167:8000/openapi.json` is the schema source of truth.
  (Corrected: there is no `billingConfig.ts` for these endpoints; tax-summary
  is served by `taxDocuments.ts`, not an invoices module.)
- **Stack:** Kotlin 2.0.21, JUnit4, MockWebServer (OkHttp 4.12), Turbine for
  Flow assertions, kotlinx-coroutines-test, Truth/AssertJ, Paging 3 testing
  artifacts, Compose UI Test (`createAndroidComposeRule`), Hilt testing
  (`HiltAndroidRule`, `@HiltAndroidTest`), Robolectric for JVM-side Compose
  where feasible. JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

This is a test ticket; "functional requirements" are the behaviors the tests
must observe and assert, derived from AND-243/AND-249 scope.

FR-1. **Invoice list paging.** Tests assert `InvoiceListViewModel` exposes a
`Flow<PagingData<InvoiceUi>>` backed by `InvoicePagingSource`, that pages load
from `GET /ui/invoices` (query params `type,date_from,date_to,limit,cursor`),
and that `LoadState` transitions (Loading → NotLoading, append, error) are
emitted correctly. **Note (verified):** the response is `InvoiceListOut`
(`{ invoices: [...], next_cursor: string|null }`) — the list array key is
`invoices`, not `items`. **Assumption:** cursor-based Paging 3 is an Android
design choice; the web reference (`InvoicesPage.tsx`) does a single
`limit:100` fetch and never sends `next_cursor`, so cursor advancement is not
demonstrated by the web client (the `next_cursor` field nonetheless exists and
supports it).

FR-2. **Invoice detail.** Tests assert `InvoiceDetailViewModel` fetches
`GET /ui/invoices/{invoice_number}` (path param is the **string** invoice
number, e.g. `INV-1001`) and maps the `InvoiceOut` body into
`InvoiceDetailUiState` (Loading, Content, Error, Offline/Stale).

FR-3. **Email invoice.** Tests assert the "Email invoice" action calls
`POST /ui/invoices/{invoice_number}/email` (no request body), surfaces
in-flight/disabled button state, success confirmation, and error feedback; and
that it is **non-idempotent** so no automatic retry occurs.

FR-4. **Tax summary.** Tests assert `TaxSummaryViewModel` loads tax totals/
breakdown and maps them into `TaxSummaryUiState`, including the empty/no-tax
case.

FR-5. **Error mapping.** Tests assert FastAPI `detail` shapes (string,
`[{msg}]`, `{code,...}`) map to typed `ApiResult.Error` and human-readable UI
errors.

FR-6. **Auth/session resilience.** Tests assert that a 401 on an invoices GET
triggers a single `POST /ui/session/refresh` and one retry, that the
`X-CSRF-Token` header echoes the `ui_csrf` cookie, and that the persistent
cookie jar is exercised. **Correction (verified against `client.ts`):** the web
client de-dupes concurrent refreshes via a shared `refreshPromise`, refreshes
**only if the user was already authenticated** (an unauthenticated 401
propagates directly without a refresh attempt), and on retry it **re-sends the
original `headers` object** — it does NOT re-read `ui_csrf` from the
refreshed-cookie before retrying. Tests should therefore assert that the retry
reuses the original `X-CSRF-Token`, not a "refreshed" one (see also §16). If the
Android `Authenticator` chooses to re-derive CSRF from the post-refresh cookie,
that is a deliberate Android divergence and must be documented, not assumed.

FR-7. **Offline/stale.** Tests assert that on network failure the UI shows
cached/stale content (if Room cache present from AND-243) or an offline state
with a retry affordance.

FR-8. **UI rendering.** Compose tests assert each state renders the correct
nodes with correct content descriptions and that retry/email controls are
clickable and wired to the ViewModel.

## 4. Technical Design

### 4.1 Test module layout

```
core-data/src/test/kotlin/com/testlogon/android/data/invoices/
    InvoiceRepositoryTest.kt
    InvoicePagingSourceTest.kt
    InvoiceServiceTest.kt
    InvoiceErrorMappingTest.kt
core-testing/src/main/kotlin/com/testlogon/android/testing/
    FakeInvoiceRepository.kt
    InvoiceFixtures.kt
    MockWebServerRule.kt
    MainDispatcherRule.kt
feature-invoices/src/test/kotlin/com/testlogon/android/feature/invoices/
    InvoiceListViewModelTest.kt
    InvoiceDetailViewModelTest.kt
    TaxSummaryViewModelTest.kt
feature-invoices/src/androidTest/kotlin/com/testlogon/android/feature/invoices/
    InvoiceListScreenTest.kt
    InvoiceDetailScreenTest.kt
    TaxSummaryScreenTest.kt
```

### 4.2 Shared test infrastructure

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

class MockWebServerRule : TestWatcher() {
    val server = MockWebServer()
    fun invoiceService(): InvoiceService =
        Retrofit.Builder()
            .baseUrl(server.url("/"))
            .client(testOkHttp(cookieJar = TestCookieJar()))
            .addConverterFactory(MoshiConverterFactory.create(testMoshi()))
            .build()
            .create(InvoiceService::class.java)
    override fun starting(d: Description) = server.start()
    override fun finished(d: Description) = server.shutdown()
}
```

`InvoiceFixtures` supplies canonical JSON strings and decoded model instances so
repository and ViewModel tests assert against one source of truth.

### 4.3 ViewModel test pattern

ViewModels are tested in isolation against `FakeInvoiceRepository` (no network).
Flow assertions use Turbine; paging assertions use `AsyncPagingDataDiffer` or
`asSnapshot {}` from `androidx.paging:paging-testing`.

```kotlin
@RunWith(JUnit4::class)
class InvoiceListViewModelTest {
    @get:Rule val main = MainDispatcherRule()
    private val repo = FakeInvoiceRepository()
    private lateinit var vm: InvoiceListViewModel

    @Before fun setup() { vm = InvoiceListViewModel(repo) }

    @Test fun `emits paged invoices on load`() = runTest {
        repo.setInvoices(InvoiceFixtures.page(count = 30))
        val snapshot = vm.invoices.asSnapshot()
        assertThat(snapshot).hasSize(30)
        // domain model field is invoiceNumber (maps the API's invoice_number)
        assertThat(snapshot.first().invoiceNumber).isEqualTo("INV-1001")
    }

    @Test fun `surfaces append error as LoadState_Error`() = runTest {
        repo.failAppendWith(ApiResult.Error.Network)
        val differ = vm.invoices.testDiffer(this)
        differ.refresh()
        assertThat(differ.loadStateFlow.value.append)
            .isInstanceOf(LoadState.Error::class.java)
    }
}
```

### 4.4 Compose UI test pattern

UI tests run with `createAndroidComposeRule<HiltTestActivity>()` and inject a
fake ViewModel (or fake repository through Hilt test module). They drive state
by emitting into a `MutableStateFlow<UiState>` and assert on semantics nodes.

```kotlin
@HiltAndroidTest
class InvoiceDetailScreenTest {
    @get:Rule(order = 0) val hilt = HiltAndroidRule(this)
    @get:Rule(order = 1) val compose = createAndroidComposeRule<HiltTestActivity>()

    @Test fun email_button_invokes_action_and_shows_progress() {
        val state = MutableStateFlow(InvoiceFixtures.detailContent())
        compose.setContent { InvoiceDetailScreen(state, onEmail = { onEmailCalled = true }) }
        compose.onNodeWithContentDescription("Email invoice").performClick()
        assertThat(onEmailCalled).isTrue()
    }
}
```

## 5. API Contract

This ticket defines **no new** endpoints; it asserts the contract owned by
AND-243/AND-249. Tests pin the following request/response shapes via
MockWebServer canned responses and verify the client sends correct method,
path, headers, and body.

> **Reviewer note:** the JSON shapes below were rewritten on 2026-06-06 to match
> the backend schemas (`InvoiceListOut`, `app__models__InvoiceOut`,
> `InvoiceLineItemOut`, `InvoiceEmailOut`, `TaxSpendingSummaryOut`) and the
> frontend `types.ts`. The original draft invented field names (`items`, `id`,
> `number`, `subtotal_cents`, `issued_at`, `due_at`, `sent_to`, a nested `tax`
> object, and the `/ui/tax/summary` path) that do not exist; corrected inline.

**List —** `GET /ui/invoices?type={t}&date_from={epoch}&date_to={epoch}&limit={n}&cursor={c}`
(response schema `InvoiceListOut`; each item is `app__models__InvoiceOut`)

```json
{
  "invoices": [
    {
      "invoice_id": "inv_8f12",
      "invoice_number": "INV-1001",
      "invoice_type": "subscription",
      "user_sub": "user_123",
      "amount_cents": 12000,
      "tax_cents": 960,
      "total_cents": 12960,
      "currency": "usd",
      "status": "generated",
      "seller_id": "seller_1",
      "seller_name": "Acme",
      "buyer_name": "Jane Doe",
      "buyer_email": "buyer@example.test",
      "line_items": [],
      "payment_method_summary": "Visa ****1234",
      "ledger_entry_id": "led_1",
      "created_at": 1746057600
    }
  ],
  "next_cursor": "eyJrIjoiaW52XzhmMTIifQ=="
}
```

Notes (verified): array key is `invoices` (not `items`); identity fields are
`invoice_id` + `invoice_number` (not `id`/`number`); the pre-tax amount is
`amount_cents` (not `subtotal_cents`); there is **no** `issued_at`/`due_at` —
the only timestamp is `created_at`, an **epoch seconds integer** (the web
formats it via `new Date(ts * 1000)`); `currency` defaults to `"usd"` and
`status` defaults to `"generated"` (free-form string, e.g. `"emailed"` after an
email send — both are arbitrary strings, not a fixed enum). Required fields per
schema: `invoice_id, invoice_number, invoice_type, user_sub, amount_cents,
total_cents`.

**Detail —** `GET /ui/invoices/{invoice_number}` returns the same
`app__models__InvoiceOut` object, including `line_items[]`. Each line item is
`InvoiceLineItemOut` = `{ description, quantity (default 1), amount_cents }`.
**Correction:** there is **no** nested `tax` object and no `rate_bps` /
`jurisdiction` fields — tax is a single flat `tax_cents` integer on the invoice.

**Email —** `POST /ui/invoices/{invoice_number}/email` (no request body;
response schema `InvoiceEmailOut`)

```json
{ "ok": true, "emailed_to": "buyer@example.test", "message": "" }
```

**Correction:** the recipient field is `emailed_to` (not `sent_to`), and the
response also carries `message`; `ok` defaults to `true`. The web reads
`res.emailed_to` for its success toast.

**Tax summary —** `GET /ui/tax-documents/summary?year={y}&date_from={epoch}&date_to={epoch}`
(response schema `TaxSpendingSummaryOut`; frontend type `SpendingSummary` via
`taxDocuments.ts: getSpendingSummary`)

```json
{
  "date_from": 1743465600,
  "date_to": 1751328000,
  "categories": [
    { "category": "subscription", "total_cents": 18450, "transaction_count": 7 }
  ],
  "grand_total_cents": 18450,
  "transaction_count": 7,
  "currency": "usd"
}
```

**Correction:** the path is `/ui/tax-documents/summary` (NOT `/ui/tax/summary`);
the body has `date_from`/`date_to` (epoch ints), a `categories[]` array of
`{ category, total_cents, transaction_count }`, `grand_total_cents`,
`transaction_count`, and `currency`. There is **no** `period`,
`total_tax_cents`, or `by_jurisdiction` field. Required: `date_from`, `date_to`.

**Error shapes asserted (FastAPI `detail`):**

```json
{ "detail": "Invoice not found" }
{ "detail": [ { "loc": ["query","limit"], "msg": "Input should be a valid integer", "type": "int_parsing" } ] }
{ "detail": { "code": "role_required", "message": "Permission denied" } }
```

Notes (verified): the `string` and `[{loc,msg,type}]` shapes are the standard
FastAPI patterns (the list form is `HTTPValidationError`, the documented 422 for
these endpoints). The original draft's 422 example claimed the path param `n`
fails integer validation — **this is wrong**: the path param is the string
`invoice_number`, so a 422 here is a query-param error (e.g. `limit`), not a
path-integer error. The object form `{ code, message }` is the real shape the
web client maps in `client.ts: mapAuthorizationError` (codes like
`role_required`, `geo_blocked`); `invoice_locked` was an invented code and is
replaced with a real one — the typed mapping under test is the **structure**
(string vs array vs `{code,message}`), not any specific invented code.

Tests enqueue 200/400/401/404/422/500 responses and a 401-then-200 sequence to
exercise the single refresh-and-retry path; they assert the recorded request to
`/ui/session/refresh` is sent **exactly once** and that the retried request
carries an `X-CSRF-Token`. **Per the web `client.ts`, the retry re-sends the
original headers** (CSRF is not re-derived from the refreshed cookie before the
retry), so assert the retry's `X-CSRF-Token` equals the value sent on the
original request unless AND-243 deliberately re-reads the cookie (document that
divergence if so).

## 6. Data & State Management

Tests assert the `UiState` contracts produced by AND-249. The expected sealed
shapes the tests pin:

```kotlin
sealed interface InvoiceDetailUiState {
    data object Loading : InvoiceDetailUiState
    data class Content(val invoice: InvoiceDetailUi, val stale: Boolean) : InvoiceDetailUiState
    data class Error(val message: String, val retryable: Boolean) : InvoiceDetailUiState
    data object Offline : InvoiceDetailUiState
}

sealed interface TaxSummaryUiState {
    data object Loading : TaxSummaryUiState
    data class Content(val summary: TaxSummaryUi) : TaxSummaryUiState
    data object Empty : TaxSummaryUiState
    data class Error(val message: String) : TaxSummaryUiState
}
```

Assertions:

- **List paging:** verify `PagingData` snapshots, cursor advancement (second
  page request carries `cursor=next_cursor` from the first response), and that
  `RemoteMediator`/Room cache (if present from AND-243) yields cached items
  first, then `stale = true` when the network fails.
- **Detail:** Loading → Content on 200; Loading → Error on 4xx/5xx; Loading →
  Offline on `IOException`. `email` action does not mutate detail state except
  the transient sending flag.
- **Tax:** Content vs Empty discrimination on a zero/empty `categories[]`
  (corrected: the array is `categories`, not `by_jurisdiction`; emptiness can be
  driven by `categories == []` and/or `grand_total_cents == 0`).
- **Money formatting:** assert `*_cents` integers map to formatted currency via
  the shared formatter; no float rounding drift (e.g. `12960` → `$129.60`).
- **State restoration:** a `SavedStateHandle`-backed test confirms the detail
  `invoice_number` argument (a String) and selected tab survive process-death
  simulation.

## 7. Error Handling & Resilience

The suite is the primary guard for resilience behavior. Required cases:

- **Timeout:** MockWebServer with a delayed body beyond the ~20s budget;
  assert the client surfaces `ApiResult.Error.Timeout` and the ViewModel emits
  `Error(retryable = true)` (use a shortened test timeout, e.g. 200ms, via the
  injected OkHttp config so the test is fast).
- **Bounded retry on idempotent GET only:** assert the GET list/detail/tax
  requests retry with backoff up to the configured cap, and that the
  **non-idempotent** `POST /ui/invoices/{invoice_number}/email` is **never**
  auto-retried (verify exactly one recorded POST after a 500).
- **401 refresh once:** 401 → one `/ui/session/refresh` → retry; a second 401
  after refresh propagates as auth error (no infinite loop). Assert exactly one
  refresh request via `server.requestCount` / recorded paths.
- **Malformed JSON / wrong content-type:** assert a typed parse error rather
  than a crash.
- **Empty page / last page:** `next_cursor = null` ends paging without error.
- **CSRF missing:** if `ui_csrf` cookie absent, assert the request still sends
  no bogus header and the mapped error is actionable.

## 8. Security & Privacy

- Tests must use **fixture credentials and a fake cookie jar only**; no real
  dev-backend calls and no real session cookies committed. The dev host
  `http://18.222.237.167:8000` is never contacted from tests.
- Assert that `X-CSRF-Token` is populated from the `ui_csrf` cookie and that the
  cookie jar persists across the simulated refresh (cookie-based auth contract).
- Assert no PII (invoice email recipient, amounts) is written to logcat in the
  code paths under test — a Robolectric `ShadowLog` assertion confirms sensitive
  fields are absent from emitted log lines.
- Fixture emails use a non-routable example value; `sent_to` is asserted by
  structure, not by contacting any mail system.

## 9. Accessibility & i18n

Compose UI tests assert accessibility, since this is where regressions hide:

- Every actionable control (Email invoice, Retry, Pay, list rows) has a
  non-empty `contentDescription`/`onNodeWithText` target; assert via
  `onNodeWithContentDescription(...).assertHasClickAction()`.
- Invoice status and money values are exposed to TalkBack as combined,
  meaningful semantics (e.g. "Invoice INV-1001, paid, total $129.60").
- Touch targets meet 48dp (assert `assertHeightIsAtLeast(48.dp)` on row/button).
- i18n: assert no hardcoded user-facing strings — money/date use locale-aware
  formatters; a test runs the detail screen under a non-US locale
  (`appContext.createConfigurationContext` with `Locale.GERMANY`) and asserts the
  currency separator changes, confirming formatting is not hardcoded.

> **Reviewer note (i18n divergence):** the web reference is NOT a precedent here.
> `InvoiceRow.tsx: formatCents` hardcodes `Intl.NumberFormat("en-US", …)` and
> `formatDate` uses `toLocaleDateString(undefined, …)` (host locale). So
> locale-aware *currency* formatting is an Android **design improvement**, not a
> ported behavior — treat the German-locale assertion as validating the Android
> formatter, and expect amounts to use `created_at * 1000` for dates (epoch
> seconds → ms). Logged as an assumption in §16.

## 10. Telemetry & Logging

This ticket adds no production telemetry. It asserts that the analytics hooks
introduced by AND-243/AND-249 fire correctly using a `FakeAnalytics` recorder:

- `invoice_list_viewed`, `invoice_detail_viewed`, `invoice_email_tapped`,
  `invoice_email_succeeded` / `_failed` events are emitted once per action with
  the expected params (invoice id present, amounts absent).
- Assert no duplicate events on recomposition or rotation.
- Assert error events carry the mapped error code, not raw `detail` text.

If AND-243/AND-249 did not wire analytics, this section is N/A and is owned by a
future telemetry ticket; the test file leaves a documented TODO rather than a
disabled test.

## 11. Testing Strategy

This ticket **is** the testing strategy. Layers and targets:

- **JVM unit (core-data):** `InvoiceServiceTest` (MockWebServer, request/header/
  body verification), `InvoicePagingSourceTest` (load/append/refresh,
  cursor logic, error LoadResult), `InvoiceRepositoryTest` (mapping, cache,
  401-refresh), `InvoiceErrorMappingTest` (all three `detail` shapes).
- **JVM unit (feature-invoices):** the three ViewModel tests with Turbine +
  paging-testing + `MainDispatcherRule`. Robolectric used only where Compose
  state needs Android types.
- **Instrumented / Compose UI (feature-invoices androidTest):** list, detail
  (email flow), tax summary across Loading/Content/Empty/Error/Offline states.
- **Tooling:** JUnit4, MockWebServer, Turbine, kotlinx-coroutines-test,
  `androidx.paging:paging-testing`, Truth, Hilt testing, Compose UI Test.
- **Coverage gate:** JaCoCo line coverage ≥ 80% for
  `com.testlogon.android.*.invoices` and the tax classes; the build fails below
  threshold. No `@Ignore`/`@Disabled` tests permitted in the merged suite.
- **Determinism:** all suspending work runs on injected `TestDispatcher`; no
  real `delay`; MockWebServer for all I/O. Target: ViewModel/repo suite < 10s on
  CI; instrumented suite green on the available CI targets.

> **Reviewer note (CI targets):** the original "API 24 + API 35 matrix" is not
> backed by an available device. The actual CI/dev targets are: JVM/Robolectric
> (local), the headless emulator AVD **`test35`** (x86_64, **API 35 / Android
> 15**), and a **physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R,
> arm64-v8a, API 34 / Android 14)**. There is no API 24 emulator provisioned. The
> instrumented suite runs on `test35`; the physical device is reserved for cases
> that need real hardware (none of the invoices/tax cases strictly require it —
> see §17). Treat "minSdk-floor" coverage as an unverified assumption (§16) until
> a low-API AVD is actually provisioned.

## 12. Dependencies & Sequencing

- **Depends on AND-249** (Invoices/tax ViewModels) — provides the ViewModels,
  `UiState` shapes, and paging wiring under test. **Hard blocker.**
- **Transitively depends on AND-243** (Invoices) — provides `InvoiceService`,
  models, repository, and the `/ui/invoices/{invoice_number}/email` endpoint.
- **Uses core-testing** fakes/rules; if `MainDispatcherRule`/`MockWebServerRule`
  do not yet exist there, add them in this ticket (they are test-only).
- **Blocks:** nothing in the backlog directly, but it is a CI gate for the M5
  release readiness of the invoices/tax surface.
- **Sequencing:** land after AND-249 merges; the data-layer tests can begin once
  AND-243 service/models are stable, with ViewModel/UI tests following AND-249.

## 13. Risks & Open Questions

- **Q1. RESOLVED (2026-06-06).** Exact tax-summary endpoint path is
  `GET /ui/tax-documents/summary` (schema `TaxSpendingSummaryOut`; frontend
  `taxDocuments.ts: getSpendingSummary`). The draft's `GET /ui/tax/summary` does
  not exist and has been corrected throughout. Fixtures must use the
  `{date_from,date_to,categories[],grand_total_cents,transaction_count,currency}`
  shape.
- **Q2.** Does AND-243 persist invoices in Room (enabling the `stale = true`
  offline assertion), or is the list network-only? If network-only, FR-7 offline
  test asserts the `Offline` state instead of cached content.
- **Q3.** Whether analytics hooks exist (affects §10). Resolve with AND-249
  owner; otherwise mark N/A.
- **Risk:** Paging 3 flow tests can be flaky if `asSnapshot`/differ scopes are
  misused — mitigate by using `paging-testing` `asSnapshot {}` and the
  `MainDispatcherRule`, never raw `runBlocking`.
- **Risk:** Compose UI test instability on the unreliable dev host — mitigated
  because tests never hit the network; all responses are MockWebServer/fakes.
- **Risk:** 401-refresh interception ordering depends on OkHttp `Authenticator`/
  interceptor placement from AND-243; if that differs, adjust the request-count
  assertions accordingly.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`), or frontend
(`reference/src/...`). "framework ref" = Android docs.

1. **List endpoint is `GET /ui/invoices` with params `type,date_from,date_to,
   limit,cursor`.** VERIFIED. OpenAPI `GET /ui/invoices` (op
   `list_invoices_ui_invoices_get`, resp `200:InvoiceListOut`); frontend
   `src/api/endpoints/invoices.ts: listInvoices`.
2. **List response key is `invoices` (array) + `next_cursor`, NOT `items`.**
   CORRECTED. Schema `InvoiceListOut` (`invoices: app__models__InvoiceOut[]`,
   `next_cursor: string|null`); `src/api/types.ts: InvoiceList`.
3. **Invoice identity/amount fields: `invoice_id`, `invoice_number`,
   `amount_cents`, `tax_cents`, `total_cents`, `currency`, `status`,
   `created_at` (epoch int). No `id`/`number`/`subtotal_cents`/`issued_at`/
   `due_at`.** CORRECTED. Schema `app__models__InvoiceOut`; `src/api/types.ts:
   Invoice`; date handling in `src/pages/billing/InvoiceRow.tsx: formatDate`
   (`new Date(ts * 1000)`).
4. **Detail endpoint is `GET /ui/invoices/{invoice_number}` with a STRING path
   param (e.g. `INV-1001`), not an integer `n`.** CORRECTED. OpenAPI
   `GET /ui/invoices/{invoice_number}` (op `get_invoice_...`,
   resp `200:app__models__InvoiceOut`, `params=invoice_number,...`); frontend
   `src/api/endpoints/invoices.ts: getInvoice` passes the string number.
5. **Detail has `line_items[]` of `{description, quantity, amount_cents}` and a
   flat `tax_cents` — there is NO nested `tax` object with
   `rate_bps`/`jurisdiction`.** CORRECTED. Schemas `app__models__InvoiceOut`,
   `InvoiceLineItemOut`; `src/api/types.ts: InvoiceLineItem`.
6. **Email endpoint is `POST /ui/invoices/{invoice_number}/email` with NO request
   body, response `InvoiceEmailOut`.** VERIFIED (path/method) / CORRECTED (shape).
   OpenAPI `POST /ui/invoices/{invoice_number}/email` (op
   `email_invoice_...`, `req=` empty, `resp=200:InvoiceEmailOut`); frontend
   `src/api/endpoints/invoices.ts: emailInvoice` (`api.post`, no body).
7. **Email response field is `emailed_to` (+ `ok`, `message`), NOT `sent_to`.**
   CORRECTED. Schema `InvoiceEmailOut`; `src/api/types.ts: InvoiceEmailResult`;
   usage `src/pages/billing/InvoiceRow.tsx: onEmail` reads `res.emailed_to`.
8. **Tax-summary endpoint is `GET /ui/tax-documents/summary`, NOT
   `/ui/tax/summary`.** CORRECTED. OpenAPI `GET /ui/tax-documents/summary` (op
   `get_summary_...`, resp `200:TaxSpendingSummaryOut`,
   `params=year,date_from,date_to,...`); frontend
   `src/api/endpoints/taxDocuments.ts: getSpendingSummary`.
9. **Tax-summary body is `{date_from,date_to,categories[],grand_total_cents,
   transaction_count,currency}` with `categories[]` of
   `{category,total_cents,transaction_count}`; NO `period`/`total_tax_cents`/
   `by_jurisdiction`.** CORRECTED. Schemas `TaxSpendingSummaryOut`,
   `SpendingCategoryOut`; `src/api/types.ts: SpendingSummary`,
   `SpendingCategory`.
10. **`X-CSRF-Token` request header is populated from the `ui_csrf` cookie.**
    VERIFIED. `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
11. **A 401 triggers exactly one `POST /ui/session/refresh` then one retry; a
    concurrent-refresh dedup via a shared promise; unauthenticated 401s do NOT
    refresh.** VERIFIED. OpenAPI `POST /ui/session/refresh` (op
    `ui_session_refresh_...`, `resp=200:`); `src/api/client.ts`
    (`refreshPromise`, `refreshSession`, `isAuthenticated` guard).
12. **The retry re-sends the ORIGINAL headers; CSRF is NOT re-read from the
    refreshed cookie before retry.** CORRECTED (draft claimed retry carries the
    "refreshed" `ui_csrf`). `src/api/client.ts` reuses the same `headers` object
    in the retry `fetch(url, { ...init, headers, credentials:"include" })`.
13. **FastAPI `detail` takes three shapes: string, `[{loc,msg,type}]`
    (`HTTPValidationError`), and `{code,message}` objects.** VERIFIED (string +
    array shapes via the `422:HTTPValidationError` on every invoices/tax op;
    object shape via `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError`). The draft's specific `invoice_locked` code and the
    "path `n` not a valid integer" 422 were invented — CORRECTED to a real
    query-param 422 and a real `{code,message}` (`role_required`).
14. **Email button content description / a11y label is "Email invoice".**
    VERIFIED. `src/pages/billing/InvoiceRow.tsx` (`aria-label="Email invoice"`);
    the in-flight disabled spinner state is also real there (`emailing` flag,
    `disabled={emailing}`).
15. **Money is `*_cents` integer → divide by 100 for display
    (`12960 → $129.60`).** VERIFIED. `src/pages/billing/InvoiceRow.tsx:
    formatCents` (`cents / 100`).
16. **Cookie-based auth via `credentials:"include"` plus `Authorization: Bearer`
    and `X-IMPERSONATION-TOKEN`.** VERIFIED. `src/api/client.ts` (auth header
    from `useAuthStore`, impersonation header, `credentials:"include"`).
    (Android port likely uses a persistent `CookieJar` + token store; the exact
    Android transport is owned by AND-243 — see assumptions.)
17. **Robolectric for JVM-side Compose, Compose UI Test
    `createAndroidComposeRule`, Paging 3 `paging-testing` `asSnapshot`/
    `AsyncPagingDataDiffer`, Turbine, MockWebServer, Hilt testing.** VERIFIED
    (framework ref): Compose testing
    https://developer.android.com/develop/ui/compose/testing ; Paging testing
    https://developer.android.com/topic/libraries/architecture/paging/test ;
    Robolectric https://robolectric.org/ . These are tool choices, not backend
    claims.
18. **CI targets: JVM/Robolectric (local), emulator AVD `test35` (API 35 /
    Android 15, x86_64), physical Galaxy A15 5G (API 34 / Android 14,
    arm64-v8a).** VERIFIED against the provided environment (build-host targets).
    The draft's "API 24 + API 35 matrix" is NOT backed — CORRECTED.

### Corrections made

- **Tax-summary path** `/ui/tax/summary` → `/ui/tax-documents/summary` (§1, §5,
  §6, §13-Q1). [#8/#9]
- **List response shape** `items[]` → `invoices[]`; per-invoice fields renamed to
  the real schema (`invoice_id`/`invoice_number`/`amount_cents`/`created_at`
  epoch int; removed `subtotal_cents`/`issued_at`/`due_at`) (§5, §4.3). [#2/#3]
- **Detail tax** removed the invented nested `tax {rate_bps,jurisdiction,...}`;
  tax is a flat `tax_cents`; line items are `{description,quantity,amount_cents}`
  (§5). [#5]
- **Email response** `sent_to` → `emailed_to` (+ `ok`, `message`); endpoint takes
  no body (§5, FR-3). [#6/#7]
- **Path param** integer `{n}` → string `{invoice_number}` everywhere (§1, §3,
  §5, §6, §7, §12); fixed the bogus "path `n` not a valid integer" 422 (§5). [#4/#13]
- **Post-refresh CSRF** corrected: retry reuses the ORIGINAL `X-CSRF-Token`, not
  a refreshed one (FR-6, §5). [#12]
- **Error `detail` object code** `invoice_locked` → real `role_required` (§5). [#13]
- **CI matrix** "API 24 + API 35" → actual `test35` (API 35) emulator + physical
  API 34 device; flagged minSdk-floor coverage as unverified (§11, §15). [#18]
- **i18n** noted the web hardcodes `en-US` currency formatting, so locale-aware
  formatting is an Android improvement, not a ported behavior (§9). [#15]

### Open assumptions

- **Android `UiState` sealed shapes** (`InvoiceDetailUiState`,
  `TaxSummaryUiState`) and ViewModel/PagingSource class names are owned by
  AND-249/AND-243 and are NOT verifiable from the web reference (web uses
  React Query + a flat list page, no ViewModel/Paging layer). UNVERIFIED-
  ASSUMPTION — tests pin whatever AND-249 ships; adjust if names differ.
- **Cursor-based Paging 3** for the list is an Android design choice. The web
  `InvoicesPage.tsx` does a single `limit:100` fetch and never sends
  `next_cursor`, so cursor advancement / append `LoadState` is not demonstrated
  upstream. UNVERIFIED-ASSUMPTION (the `next_cursor` field exists and supports
  it). If AND-249 ships network-only-single-fetch instead, FR-1/AC-2 collapse to
  a single-page load test.
- **Room cache / `stale = true` offline path** (FR-7, §6) depends on whether
  AND-243 persists invoices in Room. UNVERIFIED-ASSUMPTION (no web equivalent;
  open Q2). If network-only, the offline case asserts `Offline` instead of
  cached content.
- **Analytics hooks** (`invoice_list_viewed`, etc., §10) are NOT present in the
  web reference (`InvoicesPage.tsx`/`InvoiceRow.tsx` emit none).
  UNVERIFIED-ASSUMPTION — if AND-243/AND-249 did not wire analytics, §10 is N/A
  with a documented TODO (open Q3).
- **No-PII-in-logcat** guarantee (§8) is an Android-side contract not observable
  from the backend/web; UNVERIFIED until the production logging in AND-243 exists.
- **minSdk-floor (low-API) coverage** is UNVERIFIED — no low-API AVD is
  provisioned; only `test35` (API 35) and a physical API 34 device exist.
- **`Authenticator`/interceptor ordering** for the 401-refresh-once behavior on
  Android is owned by AND-243; the request-count assertions assume the web
  semantics (one refresh, then retry). UNVERIFIED for the Android transport.

## 17. Test Plan

IDs `TC-AND-250-NN`. Targets per the available CI/dev fleet: **JVM** =
local JVM/Robolectric (no device); **test35** = headless emulator AVD (x86_64,
API 35); **device** = physical Galaxy A15 5G (SM-A156U, arm64-v8a, API 34).
None of these cases require real hardware (no camera/biometric/WebRTC/FCM/
Telecom/streaming), so instrumented cases run on **test35**; one ABI/API
smoke case is also run on **device** to catch arm64-vs-x86 / API-34-vs-35
drift. No test contacts the real dev host `18.222.237.167:8000`.

- **TC-AND-250-01 — Invoice list happy path (first page).**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: `MockWebServerRule`; enqueue 200 `InvoiceListOut` with 30
  `invoices` and a non-null `next_cursor`.
  Steps: call `InvoiceService.listInvoices(limit=30)`; inspect `RecordedRequest`
  and decoded body.
  Expected: request is `GET /ui/invoices?...limit=30`; body decodes to 30 items;
  `invoices[0].invoice_number == "INV-1001"`, `total_cents == 12960`,
  `created_at` parsed as Long epoch; `next_cursor` non-null.
  Traces: AC-1, AC-2.

- **TC-AND-250-02 — PagingSource cursor advancement + last page.**
  Type: unit (JVM, `paging-testing`).
  Target: JVM.
  Preconditions: enqueue page-1 (200, `next_cursor="c2"`), page-2 (200,
  `next_cursor=null`).
  Steps: load via `InvoicePagingSource` / `asSnapshot {}`; assert the page-2
  request carries `cursor=c2`.
  Expected: items concatenate across both pages; second request query contains
  `cursor=c2`; `next_cursor=null` terminates paging with no append error.
  Traces: AC-2.

- **TC-AND-250-03 — List append error surfaces as `LoadState.Error`.**
  Type: unit (JVM, `paging-testing`).
  Target: JVM.
  Preconditions: page-1 200 (`next_cursor="c2"`), page-2 500.
  Steps: snapshot then trigger append; read `loadStateFlow.append`.
  Expected: `append` is `LoadState.Error`; no crash; retry re-issues the page-2
  request.
  Traces: AC-2, AC-7.

- **TC-AND-250-04 — Invoice detail state machine.**
  Type: unit (JVM, Turbine).
  Target: JVM.
  Preconditions: `FakeInvoiceRepository`/MockWebServer for
  `GET /ui/invoices/{invoice_number}`.
  Steps: drive three scenarios — 200 `InvoiceOut`; 404/500; injected
  `IOException`.
  Expected: Loading → Content (200, line_items mapped, flat `tax_cents` mapped,
  no nested tax object); Loading → Error (4xx/5xx); Loading → Offline
  (`IOException`). Path param is the string number.
  Traces: AC-3.

- **TC-AND-250-05 — Email invoice happy path (exactly one POST, no body).**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue 200 `InvoiceEmailOut` `{ok:true, emailed_to:
  "buyer@example.test", message:""}`.
  Steps: invoke email action; inspect `RecordedRequest` and
  `server.requestCount`.
  Expected: exactly one `POST /ui/invoices/INV-1001/email` with empty body;
  success state exposes `emailed_to`; in-flight disabled flag toggles true→false.
  Traces: AC-4.

- **TC-AND-250-06 — Email failure does NOT auto-retry (non-idempotent).**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue a single 500 for the email POST.
  Steps: invoke email action; assert error feedback; check recorded POST count.
  Expected: exactly ONE recorded POST (no auto-retry); ViewModel surfaces a
  retryable-by-user error, button re-enabled.
  Traces: AC-4, AC-7.

- **TC-AND-250-07 — Error-mapping for all three `detail` shapes.**
  Type: unit (JVM).
  Target: JVM.
  Preconditions: three canned error bodies — `{"detail":"Invoice not found"}`
  (404); `{"detail":[{"loc":["query","limit"],"msg":"Input should be a valid
  integer","type":"int_parsing"}]}` (422); `{"detail":{"code":"role_required",
  "message":"Permission denied"}}` (403).
  Steps: run each through the error mapper.
  Expected: each maps to a typed `ApiResult.Error` and a human-readable message
  (string passthrough; joined `msg`s; `{code,message}` → mapped/`message`); no
  crash on the array/object forms.
  Traces: AC-6.

- **TC-AND-250-08 — 401 → single refresh → retry with original CSRF.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: pre-seed cookie jar with `ui_csrf=abc`; enqueue 401 for the GET,
  200 for `/ui/session/refresh`, 200 for the retried GET.
  Steps: issue an authenticated invoices GET; record all requests.
  Expected: exactly one `POST /ui/session/refresh`; the retried GET carries
  `X-CSRF-Token: abc` (the ORIGINAL value, per web `client.ts`); a second 401
  after refresh propagates as an auth error with no infinite loop.
  Traces: AC-7.

- **TC-AND-250-09 — GET timeout → retryable error.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: MockWebServer delays the body beyond a shortened OkHttp timeout
  (e.g. 200ms test config).
  Steps: issue the list/detail GET.
  Expected: client surfaces `ApiResult.Error.Timeout`; ViewModel emits
  `Error(retryable=true)`; bounded retry/backoff applies to idempotent GET only.
  Traces: AC-7.

- **TC-AND-250-10 — Tax summary Content vs Empty + currency formatting.**
  Type: unit (JVM, Robolectric for formatter).
  Target: JVM.
  Preconditions: enqueue 200 `TaxSpendingSummaryOut` with non-empty
  `categories[]` (Content) and a second with `categories:[]`,
  `grand_total_cents:0` (Empty).
  Steps: load `TaxSummaryViewModel` against `/ui/tax-documents/summary`.
  Expected: Content vs Empty discrimination; `grand_total_cents 18450 → $184.50`;
  category rows map `{category,total_cents,transaction_count}`.
  Traces: AC-5.

- **TC-AND-250-11 — Malformed JSON / wrong content-type does not crash.**
  Type: contract/MockWebServer (JVM).
  Target: JVM.
  Preconditions: enqueue 200 with a truncated/garbage body and `text/html`.
  Steps: issue list + detail GET.
  Expected: a typed parse error (mapped `ApiResult.Error`), not an exception
  escaping to the ViewModel; UI shows an actionable error.
  Traces: AC-3, AC-6.

- **TC-AND-250-12 — Compose UI: states render with a11y + 48dp targets.**
  Type: Compose-UI / instrumented.
  Target: test35 (API 35).
  Preconditions: `createAndroidComposeRule<HiltTestActivity>()`; fake VM driven
  by `MutableStateFlow<UiState>`.
  Steps: drive Loading/Content/Empty/Error/Offline for list, detail, tax;
  query semantics nodes.
  Expected: each state renders expected nodes;
  `onNodeWithContentDescription("Email invoice").assertHasClickAction()`; Retry
  clickable; row/button `assertHeightIsAtLeast(48.dp)`; status+money exposed as
  combined TalkBack semantics.
  Traces: AC-8.

- **TC-AND-250-13 — Compose UI: email click invokes action + shows progress;
  offline shows retry.**
  Type: Compose-UI / instrumented.
  Target: test35 (API 35).
  Preconditions: fake VM; email action latch; offline state fixture.
  Steps: click "Email invoice"; assert callback fired + spinner/disabled; switch
  to Offline state; assert retry affordance present and clickable.
  Expected: `onEmail` invoked once; in-flight disabled; Offline renders retry
  that re-invokes load. No network is touched (fakes only).
  Traces: AC-4, AC-8, AC-10.

- **TC-AND-250-14 — Non-US-locale currency formatting.**
  Type: instrumented (Robolectric or test35).
  Target: test35 (API 35).
  Preconditions: render detail/tax under `Locale.GERMANY` via
  `createConfigurationContext`.
  Expected: currency separators reflect the locale (e.g. `184,50 €`-style
  grouping), confirming formatting is not hardcoded `en-US` (an Android
  improvement over the web reference). Dates derive from `created_at * 1000`.
  Traces: AC-5, AC-8.

- **TC-AND-250-15 — Security/privacy: no real backend, no PII in logcat, CSRF
  from cookie.**
  Type: unit + Robolectric (`ShadowLog`).
  Target: JVM.
  Preconditions: fixture cookie jar (`ui_csrf` set); `FakeAnalytics`.
  Steps: exercise list/detail/email/tax happy + error paths; capture
  `ShadowLog` lines; assert request headers.
  Expected: no request URL targets `18.222.237.167`; no `buyer_email`/
  `emailed_to`/amount strings appear in logcat; `X-CSRF-Token` equals the
  cookie value; analytics carry invoice id but not amounts.
  Traces: AC-7, AC-10.

- **TC-AND-250-16 — ABI/API smoke on physical device.**
  Type: instrumented/e2e.
  Target: **device** (must run on the physical Galaxy A15 5G — arm64-v8a, API
  34) to catch arm64-vs-x86 ABI and API-34-vs-35 differences not seen on
  `test35`.
  Preconditions: subset of TC-12/TC-13 (list + detail + email-flow Compose
  tests) installed on the device; all responses via MockWebServer on the host
  (adb reverse), no real backend.
  Steps: run the Compose list/detail/email suite on-device.
  Expected: identical green result to `test35`; no ABI-specific crash, no
  formatting/locale drift on API 34.
  Traces: AC-1, AC-8.

### Coverage matrix (section-14 AC → TCs)

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-16 |
| AC-2 | TC-01, TC-02, TC-03 |
| AC-3 | TC-04, TC-11 |
| AC-4 | TC-05, TC-06, TC-13 |
| AC-5 | TC-10, TC-14 |
| AC-6 | TC-07, TC-11 |
| AC-7 | TC-03, TC-06, TC-08, TC-09, TC-15 |
| AC-8 | TC-12, TC-13, TC-14, TC-16 |
| AC-9 | (coverage gate — enforced by the full suite TC-01..TC-16 + JaCoCo) |
| AC-10 | TC-13, TC-15 |

## 14. Acceptance Criteria

AC-1. All new test classes in §4.1 exist, compile, and run; the JVM unit suite
and the instrumented suite both pass green in CI ("Acceptance: Pass").

AC-2. `InvoicePagingSource`/list paging is verified: first page loads, cursor
advances to the second page, last page (`next_cursor = null`) terminates, and
append errors surface as `LoadState.Error`.

AC-3. Invoice detail state machine verified for Loading → Content (200),
Loading → Error (4xx/5xx), Loading → Offline (`IOException`).

AC-4. Email flow verified: exactly one `POST /ui/invoices/{n}/email`, in-flight
disabled state, success and error feedback, and **no** auto-retry on failure.

AC-5. Tax summary verified for Content and Empty cases with correct currency
formatting.

AC-6. Error mapping verified for all three FastAPI `detail` shapes → typed
`ApiResult.Error` → user-facing message.

AC-7. Resilience verified: GET timeout → retryable error; bounded retry on
idempotent GETs only; 401 → exactly one `/ui/session/refresh` → retry, with
`X-CSRF-Token` carrying the refreshed `ui_csrf`.

AC-8. Compose tests verify rendering and accessibility for every state, with
clickable controls and 48dp touch targets, plus a non-US-locale formatting
assertion.

AC-9. JaCoCo coverage ≥ 80% on the invoices/tax packages; build fails below
threshold; zero ignored/disabled tests.

AC-10. No test contacts a real backend, persists real cookies, or logs PII.

## 15. Definition of Done

- All §14 acceptance criteria met; CI green on the JVM suite plus the
  instrumented suite on the `test35` emulator (API 35). (Corrected from the
  unbacked "API 24 + API 35 matrix" — see §11 reviewer note and §16.)
- Test files placed per §4.1 under `com.testlogon.android.*`; shared rules/fakes
  added to `core-testing` if missing.
- Coverage gate wired into the Gradle `check`/`verification` task and enforced.
- No flaky tests across 3 consecutive CI runs; no `@Ignore`/`@Disabled`.
- Open questions Q1–Q3 either resolved or recorded as tracked follow-ups with
  the owning ticket noted; any N/A sections (telemetry) explicitly justified.
- PR opened against `android-port` from a feature branch, linked to AND-250 and
  referencing AND-249/AND-243, reviewed and approved.
