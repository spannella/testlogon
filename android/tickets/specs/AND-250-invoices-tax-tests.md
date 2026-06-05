---
id: AND-250
title: Invoices/tax tests
milestone: M5
epic: E33
priority: P2
size: M
status: draft
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
`/ui/invoices/{n}/email`) and AND-249 (Invoices/tax ViewModels with state +
Paging 3).

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
- **Web reference:** `frontend/src/api/endpoints/invoices.ts`,
  `frontend/src/api/endpoints/billingConfig.ts`, shared types in
  `frontend/src/api/types.ts`. Use these to confirm field names and the
  `/ui/invoices` response shapes; the OpenAPI spec at
  `http://18.222.237.167:8000/openapi.json` is the schema source of truth.
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
from `GET /ui/invoices`, and that `LoadState` transitions (Loading → NotLoading,
append, error) are emitted correctly.

FR-2. **Invoice detail.** Tests assert `InvoiceDetailViewModel` fetches
`GET /ui/invoices/{n}` and maps it into `InvoiceDetailUiState` (Loading,
Content, Error, Offline/Stale).

FR-3. **Email invoice.** Tests assert the "Email invoice" action calls
`POST /ui/invoices/{n}/email`, surfaces in-flight/disabled button state,
success confirmation, and error feedback; and that it is **non-idempotent** so
no automatic retry occurs.

FR-4. **Tax summary.** Tests assert `TaxSummaryViewModel` loads tax totals/
breakdown and maps them into `TaxSummaryUiState`, including the empty/no-tax
case.

FR-5. **Error mapping.** Tests assert FastAPI `detail` shapes (string,
`[{msg}]`, `{code,...}`) map to typed `ApiResult.Error` and human-readable UI
errors.

FR-6. **Auth/session resilience.** Tests assert that a 401 on an invoices GET
triggers a single `POST /ui/session/refresh` and one retry, that the
`X-CSRF-Token` header echoes the `ui_csrf` cookie, and that the persistent
cookie jar is exercised.

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
        assertThat(snapshot.first().number).isEqualTo("INV-1001")
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

**List —** `GET /ui/invoices?cursor={c}&limit={n}`

```json
{
  "items": [
    {
      "id": "inv_8f12",
      "number": "INV-1001",
      "issued_at": "2026-05-01T00:00:00Z",
      "due_at": "2026-05-15T00:00:00Z",
      "status": "paid",
      "currency": "USD",
      "subtotal_cents": 12000,
      "tax_cents": 960,
      "total_cents": 12960
    }
  ],
  "next_cursor": "eyJrIjoiaW52XzhmMTIifQ=="
}
```

**Detail —** `GET /ui/invoices/{n}` returns the full invoice plus
`line_items[]` and a `tax` object (`{ rate_bps, jurisdiction, tax_cents }`).

**Email —** `POST /ui/invoices/{n}/email`

```json
{ "ok": true, "sent_to": "spannella@gmail.com" }
```

**Tax summary —** `GET /ui/tax/summary` (or the equivalent path confirmed from
`openapi.json` during AND-243) returns
`{ "period": "2026-Q2", "total_tax_cents": 18450, "by_jurisdiction": [ { "jurisdiction": "CA-US", "tax_cents": 18450 } ] }`.

**Error shapes asserted (FastAPI `detail`):**

```json
{ "detail": "Invoice not found" }
{ "detail": [ { "loc": ["path","n"], "msg": "value is not a valid integer", "type": "type_error.integer" } ] }
{ "detail": { "code": "invoice_locked", "message": "Invoice is finalized" } }
```

Tests enqueue 200/400/401/404/422/500 responses and a 401-then-200 sequence to
exercise the single refresh-and-retry path; they assert the recorded request to
`/ui/session/refresh` is sent exactly once and that the retried request carries
the refreshed `ui_csrf` value as `X-CSRF-Token`.

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
- **Tax:** Content vs Empty discrimination on a zero/empty `by_jurisdiction`.
- **Money formatting:** assert `*_cents` integers map to formatted currency via
  the shared formatter; no float rounding drift (e.g. `12960` → `$129.60`).
- **State restoration:** a `SavedStateHandle`-backed test confirms the detail
  `n` argument and selected tab survive process-death simulation.

## 7. Error Handling & Resilience

The suite is the primary guard for resilience behavior. Required cases:

- **Timeout:** MockWebServer with a delayed body beyond the ~20s budget;
  assert the client surfaces `ApiResult.Error.Timeout` and the ViewModel emits
  `Error(retryable = true)` (use a shortened test timeout, e.g. 200ms, via the
  injected OkHttp config so the test is fast).
- **Bounded retry on idempotent GET only:** assert the GET list/detail/tax
  requests retry with backoff up to the configured cap, and that the
  **non-idempotent** `POST /ui/invoices/{n}/email` is **never** auto-retried
  (verify exactly one recorded POST after a 500).
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
  CI; instrumented suite green on an API 24 and API 35 emulator matrix.

## 12. Dependencies & Sequencing

- **Depends on AND-249** (Invoices/tax ViewModels) — provides the ViewModels,
  `UiState` shapes, and paging wiring under test. **Hard blocker.**
- **Transitively depends on AND-243** (Invoices) — provides `InvoiceService`,
  models, repository, and the `/ui/invoices/{n}/email` endpoint.
- **Uses core-testing** fakes/rules; if `MainDispatcherRule`/`MockWebServerRule`
  do not yet exist there, add them in this ticket (they are test-only).
- **Blocks:** nothing in the backlog directly, but it is a CI gate for the M5
  release readiness of the invoices/tax surface.
- **Sequencing:** land after AND-249 merges; the data-layer tests can begin once
  AND-243 service/models are stable, with ViewModel/UI tests following AND-249.

## 13. Risks & Open Questions

- **Q1.** Exact tax-summary endpoint path — `GET /ui/tax/summary` is assumed;
  confirm against `frontend/src/api/endpoints/*.ts` and `/openapi.json` before
  finalizing fixtures (owned by AND-243).
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

- All §14 acceptance criteria met; CI green on the API 24 + API 35 matrix.
- Test files placed per §4.1 under `com.testlogon.android.*`; shared rules/fakes
  added to `core-testing` if missing.
- Coverage gate wired into the Gradle `check`/`verification` task and enforced.
- No flaky tests across 3 consecutive CI runs; no `@Ignore`/`@Disabled`.
- Open questions Q1–Q3 either resolved or recorded as tracked follow-ups with
  the owning ticket noted; any N/A sections (telemetry) explicitly justified.
- PR opened against `android-port` from a feature branch, linked to AND-250 and
  referencing AND-249/AND-243, reviewed and approved.
