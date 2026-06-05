---
id: AND-263
title: Payouts tests
milestone: M6
epic: E35
priority: P2
size: M
status: draft
depends_on: [AND-262, AND-258]
blocks: []
---

# AND-263 — Payouts tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Payouts feature of the
TestLogon native Android app (`com.testlogon.android`). The Payouts feature is
built across upstream tickets in epic `E35` (milestone `M6`): the network/DTO
layer (`AND-258`, the `payouts.ts`-equivalent Retrofit service plus Moshi DTOs),
the payout history + status screens (`AND-260`), the KYC/setup gate
(`AND-259`), the read-only bulk payout tools (`AND-261`,
`bulkPayoutTools.ts`-equivalent views), and the `PayoutsViewModel` (`AND-262`)
that owns the state and the **gating logic** (whether payouts are available
given KYC/onboarding/method status) and exposes `StateFlow<PayoutsUiState>`.

The goal of `AND-263` is **not** to add product behavior but to lock the
behavior of those layers with fast, deterministic tests so regressions are
caught in CI. The backlog scope is explicitly "Repo + UI tests" and the
acceptance bar is "Pass." Concretely we deliver: (a) **repository/unit tests**
covering DTO deserialization, DTO→domain mapping, query parameterization and
paging for history, FastAPI `detail` error mapping, gating-state derivation, and
offline/stale paths; and (b) **UI/instrumentation tests** covering
`PayoutsViewModel` state transitions, the gating decision surfaced to the UI,
and the Compose `PayoutsScreen` / history list / bulk read views rendering for
each `PayoutsUiState` variant. The suite must be green and run under CI as part
of the `feature-payouts` module's `test` and `connectedAndroidTest` (or
Robolectric) checks.

## 2. Context & References

- **Backlog ticket:** `AND-263 — Payouts tests`, Type: Test, Priority: P2,
  Deps: `AND-262`. Scope: "Repo + UI tests." Acceptance: "Pass."
- **Upstream feature tickets under test:**
  - `AND-258` — Payouts API + DTOs (`payouts.ts` endpoints/DTOs; Acceptance:
    "Payout data maps (tested)").
  - `AND-259` — Payout setup / KYC gate.
  - `AND-260` — Payout history + status (history list, statuses, detail).
  - `AND-261` — Bulk payout tools (read) (`bulkPayoutTools.ts` read-only views).
  - `AND-262` — Payouts ViewModel (state + gating logic; Acceptance:
    "Unit-tested") — the direct dependency.
  - `AND-258` transitively depends on `AND-027` (core-network/Retrofit/OkHttp +
    persistent cookie jar + CSRF interceptor + `ApiResult` plumbing).
- **Module:** `feature-payouts` (layer: `app -> feature-payouts -> core-*`).
  Tests in this ticket live in `feature-payouts/src/test` (JVM/Robolectric) and
  `feature-payouts/src/androidTest` (instrumented Compose), using shared fakes
  from `core-testing`.
- **Web reference:** `frontend/src/api/endpoints/payouts.ts`,
  `frontend/src/api/endpoints/bulkPayoutTools.ts`, and shared types in
  `frontend/src/api/types.ts` define the canonical request/response shapes
  mirrored by the Kotlin DTOs; the FastAPI source of truth is `/openapi.json` on
  the dev backend `http://18.222.237.167:8000` (plaintext HTTP, unreliable dev
  host).
- **Auth context:** Payout endpoints are authenticated and ride the cookie-based
  session (`ui_csrf` echoed as `X-CSRF-Token`; single `POST /ui/session/refresh`
  retry on 401). Tests use a stubbed `MockWebServer` and never hit the live
  backend.

## 3. Functional Requirements

The test suite (the deliverable) must verify the following production behaviors.
Each is testable and maps to assertions below.

- **FR-1 (Summary/status mapping):** A well-formed `GET /ui/payouts/summary` body
  deserializes into `PayoutSummaryDto` and maps to the `PayoutSummary` domain
  model with available/pending balances in currency minor-units and the next
  scheduled payout date preserved.
- **FR-2 (History mapping + ordering):** A well-formed
  `GET /ui/payouts/history` body deserializes into `PayoutHistoryPageDto` and
  maps to `List<Payout>` ordered by `createdAt` descending; the cursor/`next`
  token is preserved for Paging 3.
- **FR-3 (Status enum mapping):** Each backend payout status string
  (`pending`, `in_transit`, `paid`, `failed`, `canceled`, `on_hold`) maps to the
  `PayoutStatus` enum; an unknown value maps to `PayoutStatus.UNKNOWN` (no
  crash).
- **FR-4 (Gating logic — AND-262):** Given KYC/onboarding/method inputs, the
  ViewModel derives the correct `PayoutGate` and surfaces it: KYC incomplete →
  `Gate.KycRequired`; no payout method → `Gate.SetupRequired`; account on hold →
  `Gate.Blocked`; otherwise → `Gate.Allowed`. Gating is asserted as a pure
  function and via state.
- **FR-5 (Error mapping):** FastAPI `detail` in all three shapes
  (`string` | `[{msg}]` | `{code,...}`) maps to a typed `ApiError`, and the
  ViewModel surfaces `PayoutsUiState.Error` with a user-facing message.
- **FR-6 (Offline/stale):** With no network and a cached prior payload, the
  ViewModel emits `Content(isStale = true)`; with no cache it emits
  `Error(offline = true)`.
- **FR-7 (Resilience):** A 401 triggers exactly one `session/refresh` then one
  retry; a transient 503 on an idempotent GET triggers bounded backoff retry;
  the bulk read endpoints (GET only) participate in the same retry policy.
- **FR-8 (Paging):** History `PagingSource` returns the correct
  `LoadResult.Page` with `prevKey`/`nextKey` for first and subsequent loads and
  surfaces `LoadResult.Error` on failure.
- **FR-9 (Bulk read rendering):** The read-only bulk payout tools views
  (`AND-261`) render their list/summary from a mapped DTO and expose no mutating
  actions (read-only is enforced — no write affordances present).
- **FR-10 (Screen rendering):** `PayoutsScreen` and the history list render the
  loading skeleton, the populated content (summary + history), each gate banner
  (`KycRequired`/`SetupRequired`/`Blocked`), the empty state, the error state
  with retry, and the stale banner — one Compose test per state.

## 4. Technical Design

### 4.1 Production surface under test (as built by AND-258/259/260/261/262)

The tests are written against these signatures. They are reproduced here so the
test code compiles against the agreed contract; if upstream signatures drift,
the tests are the failing tripwire.

```kotlin
// core-model
enum class PayoutStatus { PENDING, IN_TRANSIT, PAID, FAILED, CANCELED, ON_HOLD, UNKNOWN }

data class PayoutSummary(
    val availableMinor: Long,
    val pendingMinor: Long,
    val currency: String,             // ISO-4217, e.g. "USD"
    val nextScheduledAt: Instant?,
)
data class Payout(
    val id: String,
    val amountMinor: Long,
    val currency: String,
    val status: PayoutStatus,
    val createdAt: Instant,
    val arrivedAt: Instant?,
    val methodLast4: String?,
)
sealed interface PayoutGate {
    data object Allowed : PayoutGate
    data object KycRequired : PayoutGate
    data object SetupRequired : PayoutGate
    data class Blocked(val reason: String) : PayoutGate
}

// feature-payouts (repository)
interface PayoutsRepository {
    suspend fun summary(): ApiResult<PayoutSummary>
    fun historyPagingSource(): PagingSource<String, Payout>
    suspend fun gateInputs(): ApiResult<PayoutGateInputs>      // KYC/method/hold flags
    suspend fun bulkTools(): ApiResult<BulkPayoutToolsView>    // read-only (AND-261)
}

// feature-payouts (viewmodel — AND-262)
sealed interface PayoutsUiState {
    data object Loading : PayoutsUiState
    data class Content(
        val summary: PayoutSummary,
        val gate: PayoutGate,
        val isStale: Boolean = false,
    ) : PayoutsUiState
    data object Empty : PayoutsUiState
    data class Error(val message: String, val offline: Boolean = false) : PayoutsUiState
}
class PayoutsViewModel @Inject constructor(
    private val repo: PayoutsRepository,
) : ViewModel() {
    val uiState: StateFlow<PayoutsUiState>
    val history: Flow<PagingData<Payout>>
    fun retry()
    // pure gating helper exercised directly by tests:
    // fun deriveGate(inputs: PayoutGateInputs): PayoutGate
}
```

### 4.2 Test architecture

- **Repository / mapping tests (JVM, `src/test`):** Use **JUnit4**,
  **MockWebServer (OkHttp 4.12)**, the real Moshi 1.15 adapters and the real
  Retrofit `PayoutsApi`, so deserialization, query-param construction, and
  cursor handling are exercised end-to-end against canned HTTP. Fixtures are JSON
  files in `feature-payouts/src/test/resources/fixtures/payouts/`. Use
  `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher`.
- **ViewModel / gating tests (JVM, `src/test`):** Inject a
  `FakePayoutsRepository` (in `core-testing`) implementing `PayoutsRepository`
  with programmable `ApiResult` outcomes and emission delays. Collect `uiState`
  with **Turbine** to assert ordered emissions. Test `deriveGate` as a pure
  function with a parameterized truth table over KYC/method/hold inputs. Replace
  `Dispatchers.Main` via `MainDispatcherRule` (JUnit `TestRule` wrapping
  `Dispatchers.setMain`).
- **Paging tests (JVM, `src/test`):** Drive `historyPagingSource()` directly with
  `PagingSource.load(LoadParams.Refresh/Append)` and assert `LoadResult.Page`
  keys and item ordering; use `AsyncPagingDataDiffer`/`TestPager` (Paging 3 test
  artifact) for end-to-end `PagingData` collection.
- **UI tests (`src/androidTest` or Robolectric `src/test`):** Use
  `createComposeRule()` and drive `PayoutsScreen(state, onRetry)` and the bulk
  read view directly with each state, asserting via `onNodeWithTag` /
  `onNodeWithText`. Prefer Robolectric-backed Compose tests so the suite runs on
  CI without an emulator; keep one true instrumented smoke test.

### 4.3 Determinism

- Fix the clock: inject a `Clock.fixed(...)` (or a `TimeProvider` fake) so
  `nextScheduledAt`/relative-time rendering and any date math are deterministic.
- No real network, no real DataStore/Room: use in-memory Room
  (`Room.inMemoryDatabaseBuilder`) for the stale-cache test and a temp-folder
  DataStore where gating inputs are persisted.

## 5. API Contract

This is a **test** ticket; it does not define new endpoints. It validates the
contract owned by `AND-258` (and the bulk read contract owned by `AND-261`). The
DTO/endpoint truth is reproduced here as the basis for fixtures.

`GET /ui/payouts/summary` (auth required; cookies + `X-CSRF-Token`):
```json
{
  "currency": "USD",
  "available_minor": 542300,
  "pending_minor": 118000,
  "next_scheduled_at": "2026-06-12T00:00:00Z"
}
```

`GET /ui/payouts/history?limit=20&cursor=` (cursor-paged):
```json
{
  "items": [
    {
      "id": "po_01H...",
      "amount_minor": 250000,
      "currency": "USD",
      "status": "in_transit",
      "created_at": "2026-06-01T09:00:00Z",
      "arrived_at": null,
      "method_last4": "4242"
    }
  ],
  "next": "eyJjcmVhdGVkX2F0..."
}
```

`GET /ui/payouts/bulk-tools` (read-only, owned by `AND-261`): returns a
read-only aggregate view (e.g. grouped batch summaries); tests assert it maps to
`BulkPayoutToolsView` and that no mutating endpoint is referenced.

Gate inputs (e.g. via `GET /ui/payouts/setup` / `GET /ui/me` KYC flags, owned by
`AND-259`):
```json
{ "kyc_status": "incomplete", "has_payout_method": false, "account_hold": false }
```

FastAPI error body (tested in all three `detail` shapes), e.g. 422:
```json
{ "detail": [ { "loc": ["query", "cursor"], "msg": "invalid cursor", "type": "value_error" } ] }
```
and `{ "detail": "payouts unavailable: kyc required" }` and
`{ "detail": { "code": "PAYOUT_ON_HOLD", "message": "account on hold" } }`.

Tests assert: query params (`limit`, `cursor`), header presence
(`X-CSRF-Token`), status-string→enum mapping, and that each error body maps to
the expected `ApiError` subtype.

## 6. Data & State Management

The suite verifies the data/state contract rather than introducing it.

- **DTO→domain:** Moshi adapters parse `available_minor`/`pending_minor`/
  `amount_minor` as `Long` (no float rounding), `next_scheduled_at`/`arrived_at`
  as nullable `Instant` via a registered `InstantAdapter`, and `status` via a
  custom enum adapter with `UNKNOWN` fallback. Test asserts a `null`
  `arrived_at` maps to `null` and an unrecognized status string maps to
  `PayoutStatus.UNKNOWN`.
- **Ordering & paging:** `PayoutHistoryPageDto.items` → `List<Payout>` sorted by
  `createdAt` descending; `next` token preserved and threaded into the next
  `LoadParams.Append`. Test feeds two pages and asserts the second `load`
  appends correctly and that `nextKey == null` on the final page.
- **Gating state:** `deriveGate` truth table — KYC incomplete → `KycRequired`
  (highest precedence after hold), `account_hold = true` → `Blocked`, no method →
  `SetupRequired`, all clear → `Allowed`. Precedence order is asserted
  explicitly (hold > KYC > setup).
- **Stale/cache:** Repository returns cached summary/history with
  `isStale = true` when the network call fails but a Room row exists. Test seeds
  in-memory Room, fails the `MockWebServer` response (socket disconnect), asserts
  `Content(isStale = true)`.
- **Empty:** `items = []` and zero balances with `Allowed` gate →
  `PayoutsUiState.Empty` (or `Content` with empty history, per AND-262 contract —
  asserted to match the merged ViewModel).

## 7. Error Handling & Resilience

Tested production behaviors (assertions in repository/ViewModel tests):

- **Timeout:** `MockWebServer` `setBodyDelay(25, SECONDS)` against a ~20s OkHttp
  read timeout → `ApiResult.Failure(NetworkError.Timeout)` →
  `Error(offline = false)` (or stale if cache present). Test uses a shortened
  timeout client to keep the suite fast.
- **401 → refresh once:** Enqueue `401`, then `200` for `session/refresh`, then
  `200` for the retried payouts GET. Assert exactly **one** refresh request was
  recorded and the final result is `Content`. A second `401` must surface as
  `Error` (no infinite loop).
- **Bounded backoff:** Enqueue `503` twice then `200` for the idempotent GET
  (summary, history, bulk-tools); assert success after retries and that retry
  count does not exceed the configured cap.
- **Malformed JSON:** Body with wrong types → `ApiResult.Failure(ParseError)`,
  not a crash.
- **Paging error:** A failing `load` returns `LoadResult.Error`, and the UI
  surfaces a retry affordance (asserted in the UI test via the append-error
  state).
- **detail mapping:** Parameterized JUnit test over the three `detail` shapes
  asserting the mapped `ApiError`.

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf`
  cookie value on outgoing payout requests (validates the `AND-027` CSRF
  interceptor is in the chain for this feature).
- Tests assert the persistent cookie jar replays the session cookie on the
  history request after the summary request (same `MockWebServer` instance).
- No secrets, real credentials, or production hosts appear in fixtures or test
  config; the dev host `18.222.237.167` is never contacted. Fixture amounts,
  `method_last4`, and payout ids are synthetic.
- Tests assert that financial PII (full amounts beyond display, `method_last4`,
  payout ids) and auth cookies are **not** emitted at non-debug log levels (see
  §10). The bulk read view test asserts no write/mutation request is ever issued
  (read-only enforcement, FR-9).

## 9. Accessibility & i18n

- **A11y (UI tests):** Each Compose state test asserts meaningful semantics:
  payout status chips expose a `contentDescription`/`stateDescription` conveying
  the status (not color-only); the gate banners are announced as alerts with
  actionable button labels (e.g. "Complete identity verification"); the retry
  button is reachable via merged semantics; history rows expose a combined
  semantics description (amount + status + date).
- **i18n:** Tests assert no hardcoded user-facing strings in `PayoutsScreen`/
  bulk views by resolving via `stringResource`; currency/amounts formatted
  through a locale-aware formatter. A `Locale.GERMANY` UI test asserts amounts
  render with locale grouping/decimal separators and the configured currency
  symbol, guarding against `String.format` hardcoding. Dates use a locale-aware
  formatter under the fixed clock.

## 10. Telemetry & Logging

- A `FakeAnalytics` (from `core-testing`) is injected; tests assert the
  ViewModel logs `payouts_viewed`, `payout_gate_shown { gate }` when a non-Allowed
  gate is surfaced, and `payouts_load_failed { reason }` on error, and does
  **not** double-log on retry/cancellation.
- A test installs a capturing `Timber`/log tree and asserts that error paths log
  at `WARN`/`ERROR` without including cookie values, `method_last4`, or full
  response bodies containing the session/financial data.

## 11. Testing Strategy

This ticket *is* the testing strategy deliverable. Concrete test classes:

- `feature-payouts/src/test/.../PayoutsApiMappingTest.kt`
  — MockWebServer + real Moshi/Retrofit: FR-1, FR-2, FR-3 (status→enum incl.
  UNKNOWN), malformed JSON.
- `feature-payouts/src/test/.../PayoutsHistoryPagingTest.kt`
  — `TestPager`/`PagingSource.load`: FR-2 ordering, FR-8 keys, append-error.
- `feature-payouts/src/test/.../PayoutsErrorMappingTest.kt`
  — parameterized FastAPI `detail` (FR-5), timeout, 401-refresh, 503-backoff
  (FR-7).
- `feature-payouts/src/test/.../PayoutsRepositoryStaleTest.kt`
  — in-memory Room cache, offline/stale (FR-6).
- `feature-payouts/src/test/.../PayoutsGateTest.kt`
  — parameterized `deriveGate` truth table and precedence (FR-4).
- `feature-payouts/src/test/.../PayoutsViewModelTest.kt`
  — Turbine + Fake repo + `MainDispatcherRule`: state ordering, gate surfacing,
  Empty, Error, `retry()`, telemetry (FR-4/FR-5/FR-6/§10).
- `feature-payouts/src/test/.../BulkPayoutToolsReadTest.kt`
  — mapping + read-only enforcement (FR-9).
- `feature-payouts/src/androidTest/.../PayoutsScreenTest.kt` (or Robolectric)
  — Compose rule, one test per `PayoutsUiState` and per gate banner, history row
  semantics, a11y, German-locale formatting (FR-10, §9).

Tooling: JUnit4, `kotlinx-coroutines-test`, Turbine, MockWebServer, Truth (or
JUnit assertions), Compose UI Test, Paging 3 testing artifact, Robolectric (for
JVM Compose), Room in-memory. All wired via `core-testing` dependencies and KSP
test processors where Hilt test injection is used (`@HiltAndroidTest` only for
the instrumented smoke test; ViewModel tests construct the VM directly to stay
fast).

Coverage target: every public method of `PayoutsRepository` and
`PayoutsViewModel`, every `PayoutGate` branch, every `PayoutStatus` mapping, and
every `PayoutsUiState` branch exercised. No flakiness: all time and dispatchers
are controlled; no `Thread.sleep`; no real I/O.

## 12. Dependencies & Sequencing

- **Hard deps:** `AND-262` (ViewModel + gating logic) and, transitively,
  `AND-258` (API + DTOs) must be merged — they provide the types under test.
  `AND-259` (gate inputs), `AND-260` (history/status + screen), and `AND-261`
  (bulk read views) provide the remaining surfaces; their merge gates the
  corresponding test classes. `AND-027` provides `core-network`, the cookie jar,
  CSRF interceptor, and `ApiResult`.
- **Shared infra:** `core-testing` must expose `MainDispatcherRule`,
  `FakePayoutsRepository`, `FakeAnalytics`, the Paging test helpers, and the
  in-memory Room/DataStore helpers; if any are missing, add them in
  `core-testing` as part of this ticket (they are reusable across feature test
  suites).
- **Sequencing:** Land after `AND-262`. This ticket blocks nothing functionally
  but gates the milestone-`M6` Payouts epic (`E35`) "done" definition by proving
  the feature is regression-protected.

## 13. Risks & Open Questions

- **R-1 (signature drift):** Exact field names (`available_minor` vs
  `availableMinor`, `items` vs `payouts`, the cursor field `next` vs `cursor`)
  and the `PayoutStatus` string set are inferred from
  `frontend/src/api/types.ts` and `AND-258`. **Open:** confirm against
  `/openapi.json`; align fixtures before merge. Mitigation: a contract test that
  diffs fixture keys against the committed OpenAPI snapshot.
- **R-2 (gate precedence):** The precedence among KYC/hold/setup gates is
  assumed `hold > KYC > setup`. **Open:** confirm the canonical order with the
  `AND-262`/`AND-259` owners; the truth table is the single place to update.
- **R-3 (paging vs simple list):** Whether history uses Paging 3 cursors or a
  bounded simple list affects FR-8 assertions. Assume Paging 3 cursor
  (`AND-260`); demote to list-based assertions if implemented otherwise.
- **R-4 (refresh semantics):** "Single refresh on 401" location (interceptor in
  `core-network` vs repository) determines where the refresh-once test asserts.
  Assume `core-network` (`AND-027`).
- **R-5 (Robolectric vs emulator):** If any Compose rendering needs a real GPU
  canvas, demote that test to instrumented-only and keep state/semantics tests on
  Robolectric.

## 14. Acceptance Criteria

The backlog acceptance is "Pass." Operationalized as testable criteria:

- **AC-1:** `./gradlew :feature-payouts:testDebugUnitTest` passes with all
  classes in §11 present and green; zero ignored/flaky tests.
- **AC-2:** `./gradlew :feature-payouts:connectedDebugAndroidTest` (or the
  Robolectric Compose task) passes for `PayoutsScreenTest`.
- **AC-3:** Mapping tests prove FR-1, FR-2 (descending order + cursor), and FR-3
  (every status string → enum, unknown → `UNKNOWN`).
- **AC-4:** Gating tests prove FR-4 across the full truth table including
  precedence (hold > KYC > setup).
- **AC-5:** Error tests prove FR-5 (all three `detail` shapes), timeout, 401→
  single-refresh→retry with exactly one refresh request, and bounded 503 backoff
  (FR-7).
- **AC-6:** Paging tests prove FR-8 (`prevKey`/`nextKey`, terminal page,
  append-error).
- **AC-7:** Stale/offline tests prove `Content(isStale=true)` with cache and
  `Error(offline=true)` without (FR-6).
- **AC-8:** Bulk read tests prove FR-9 mapping and that no mutation request is
  issued.
- **AC-9:** UI tests prove rendering of every `PayoutsUiState` and gate banner,
  history row a11y semantics, and German-locale amount formatting (FR-10, §9).
- **AC-10:** Security assertions confirm `X-CSRF-Token` echoes `ui_csrf`, the
  cookie jar replays the session, and no financial PII/cookies are logged (§8).
- **AC-11:** Suite is hermetic: no live network, controlled clock/dispatchers, no
  `Thread.sleep`; CI run is green.

## 15. Definition of Done

- All test classes in §11 implemented under `com.testlogon.android` package
  paths in `feature-payouts`, compiling against the merged
  `AND-262`/`AND-258`/`AND-259`/`AND-260`/`AND-261` signatures.
- AC-1 through AC-11 satisfied; suite green locally and in CI on the
  `android-port` branch.
- Required `core-testing` fakes/rules/Paging helpers added or confirmed present
  and reused (no duplication in `feature-payouts`).
- Fixtures stored under `src/test/resources/fixtures/payouts/` and validated
  against `/openapi.json` (R-1 closed or explicitly deferred with an owner).
- No new lint/Detekt violations; KSP test processors build cleanly; no live dev
  host contacted.
- Open questions R-1..R-5 resolved or filed as follow-up tickets and linked.
- Code reviewed and merged to `android/feature-payouts`; CI badge green.
