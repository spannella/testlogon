---
id: AND-263
title: Payouts tests
milestone: M6
epic: E35
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
(`AND-259`), the bulk payout tools (`AND-261`, `bulkPayoutTools.ts`-equivalent views), and the
`PayoutsViewModel` (`AND-262`) that owns the state and the **gating logic**
(whether the user may request a payout given balance/minimum status) and exposes
`StateFlow<PayoutsUiState>`.

> **Reviewer note (AND-263 review, 2026-06-06):** The original draft of this spec
> assumed a KYC/onboarding "gate" model, a `GET /ui/payouts/summary` endpoint,
> `*_minor` field names, ISO-8601 timestamps, a `next` cursor token, and
> **read-only** bulk tools. None of these match the authoritative sources. The
> web client (`frontend/src/api/endpoints/payouts.ts`,
> `frontend/src/api/endpoints/bulkPayoutTools.ts`, `src/api/types.ts`) and the
> backend OpenAPI show: balance via `GET /ui/payouts/balance`
> (`PayoutBalanceOut`), history via `GET /ui/payouts` (`PayoutListOut`),
> `*_cents` integer fields, Unix-epoch-**seconds** integer timestamps, a
> `next_cursor` token, no KYC/gate concept at all (gating is balance/minimum-based),
> and bulk tools that are admin-only and **mutating** (`preview`/`execute` POST).
> Corrections are applied inline below and audited in §16.

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

- **FR-1 (Balance/summary mapping):** *(Corrected — endpoint/fields)* A
  well-formed `GET /ui/payouts/balance` body (`PayoutBalanceOut`) deserializes
  into `PayoutBalanceDto` and maps to the `PayoutBalance` domain model with
  `available_cents`, `pending_cents`, `hold_cents`, `total_earned_cents`,
  `minimum_payout_cents` (all integer cents) and `currency` preserved. There is
  **no** `GET /ui/payouts/summary` endpoint and **no** `next_scheduled_at` field.
- **FR-2 (History mapping + ordering):** *(Corrected — endpoint/fields)* A
  well-formed `GET /ui/payouts` body (`PayoutListOut`) deserializes into
  `PayoutListDto` and maps to `List<Payout>` ordered by `createdAt` descending;
  the `next_cursor` token (nullable string) is preserved for Paging 3. The list
  field is `items`; the cursor field is `next_cursor` (not `next`).
- **FR-3 (Status enum mapping):** *(Corrected — status set)* Each backend payout
  status string observed in the web client
  (`requested`, `approved`, `processing`, `completed`, `rejected`, `cancelled`)
  maps to the `PayoutStatus` enum; an unknown/unmapped value maps to
  `PayoutStatus.UNKNOWN` (no crash). The status strings are free-form `string` in
  OpenAPI (`PayoutOut.status`), so `UNKNOWN`-fallback is the contract guard.
  (The draft's `pending`/`in_transit`/`paid`/`failed`/`canceled`/`on_hold` set is
  not what the web client renders — see `STATUS_BADGE_VARIANT` in
  `PayoutDashboard.tsx`.)
- **FR-4 (Gating logic — AND-262):** *(Corrected — gate model is unverified
  against sources)* The web payouts feature has **no** KYC/onboarding/method gate.
  Eligibility to request a payout is purely balance/minimum based: a request is
  permitted only when `amount_cents >= minimum_payout_cents` and
  `amount_cents <= available_cents` (see `PayoutDashboard.tsx` `canSubmit`).
  Tests therefore assert the balance-derived `PayoutGate`:
  `available_cents < minimum_payout_cents` → `Gate.BelowMinimum`; otherwise
  `Gate.Allowed`. The original `KycRequired`/`SetupRequired`/`Blocked` model is an
  **unverified Android-side assumption** (no `/ui/payouts/setup`, no KYC flag
  endpoint exists in OpenAPI); if AND-262/AND-259 introduce one it must be added
  to the truth table, but it cannot be sourced today. Gating is asserted as a
  pure function and via state.
- **FR-5 (Error mapping):** FastAPI `detail` in all three shapes
  (`string` | `[{msg}]` | `{code,...}`) maps to a typed `ApiError`, and the
  ViewModel surfaces `PayoutsUiState.Error` with a user-facing message.
- **FR-6 (Offline/stale):** With no network and a cached prior payload, the
  ViewModel emits `Content(isStale = true)`; with no cache it emits
  `Error(offline = true)`.
- **FR-7 (Resilience):** A 401 triggers exactly one `POST /ui/session/refresh`
  then one retry of the original request; a second 401 logs the user out (no
  loop) — this matches the web client (`src/api/client.ts` `refreshSession`/
  retry). *(Unverified Android assumption)* a transient 503 on an idempotent GET
  triggers bounded backoff retry: the web client does **not** implement 503
  backoff, so this is a net-new Android policy and must be marked as such. The
  bulk-tools endpoints are **admin** GETs (`/ui/admin/bulk-payouts/...`); if
  AND-261 surfaces them they participate in the same retry policy.
- **FR-8 (Paging):** History `PagingSource` returns the correct
  `LoadResult.Page` with `prevKey`/`nextKey` for first and subsequent loads and
  surfaces `LoadResult.Error` on failure.
- **FR-9 (Bulk tools rendering):** *(Corrected — bulk tools are NOT read-only)*
  The bulk payout tools (`AND-261`, mirroring `bulkPayoutTools.ts` /
  `BulkPayoutConsole.tsx`) are an **admin** feature backed by
  `GET /ui/admin/bulk-payouts/eligible`, `GET .../batches`,
  `GET .../batches/{batch_id}` **and the mutating** `POST .../preview` and
  `POST .../execute` (`BulkPreviewIn`/`BulkExecuteIn` → `BulkBatchOut`). If
  AND-261 ships a read-only Android view, tests assert it maps `BulkBatchOut`/
  `BulkEligibleItem` and issues only the GET endpoints; the "no mutation issued"
  assertion is then a *scope guard for the Android view*, not a property of the
  backend contract (which exposes write endpoints). Whether the Android port
  includes the admin write actions is an **open question** for AND-261.
- **FR-10 (Screen rendering):** `PayoutsScreen` and the history list render the
  loading skeleton, the populated content (balance cards + history), the
  balance-based gate banner (`BelowMinimum`/`Allowed` — see FR-4 correction), the
  empty state ("No payout requests yet"), the error state with retry, and the
  stale banner — one Compose test per state.

## 4. Technical Design

### 4.1 Production surface under test (as built by AND-258/259/260/261/262)

The tests are written against these signatures. They are reproduced here so the
test code compiles against the agreed contract; if upstream signatures drift,
the tests are the failing tripwire.

> **Corrected against sources.** Field names/types below now mirror
> `PayoutBalanceOut`, `PayoutOut`, `PayoutListOut` (OpenAPI) and `src/api/types.ts`.
> Timestamps are Unix **epoch-seconds integers** in the wire DTOs (web does
> `new Date(ts * 1000)` in `PayoutDashboard.tsx`); the domain model converts to
> `Instant`. The original draft's `*_minor`/`id`/`arrivedAt`/`methodLast4`/
> `nextScheduledAt` and the KYC gate were not in any source.

```kotlin
// core-model
// status is a free-form string in OpenAPI (PayoutOut.status); the enum mirrors
// the values the web client styles (PayoutDashboard.tsx STATUS_BADGE_VARIANT).
enum class PayoutStatus { REQUESTED, APPROVED, PROCESSING, COMPLETED, REJECTED, CANCELLED, UNKNOWN }

data class PayoutBalance(                 // <- PayoutBalanceOut
    val availableCents: Long,             // available_cents
    val pendingCents: Long,               // pending_cents
    val holdCents: Long,                  // hold_cents
    val totalEarnedCents: Long,           // total_earned_cents
    val minimumPayoutCents: Long,         // minimum_payout_cents
    val currency: String,                 // ISO-4217, e.g. "USD"
)
data class Payout(                         // <- PayoutOut
    val payoutId: String,                 // payout_id
    val userId: String,                   // user_id
    val amountCents: Long,                // amount_cents
    val method: String,                   // "bank_transfer" | "paypal" | ...
    val status: PayoutStatus,             // status (string -> enum, UNKNOWN fallback)
    val createdAt: Instant,               // created_at (epoch seconds)
    val updatedAt: Instant,               // updated_at (epoch seconds)
    val completedAt: Instant?,            // completed_at (nullable epoch seconds)
    val notes: String,                    // notes
    val rejectReason: String,             // reject_reason
    val approvedBy: String,               // approved_by
)
// Balance-based gate (no KYC/setup gate exists in sources — see FR-4).
sealed interface PayoutGate {
    data object Allowed : PayoutGate          // available_cents >= minimum_payout_cents
    data object BelowMinimum : PayoutGate     // available_cents < minimum_payout_cents
}

// feature-payouts (repository)
interface PayoutsRepository {
    suspend fun balance(): ApiResult<PayoutBalance>            // GET /ui/payouts/balance
    fun historyPagingSource(): PagingSource<String, Payout>    // GET /ui/payouts (next_cursor)
    suspend fun bulkTools(): ApiResult<BulkPayoutToolsView>    // GET /ui/admin/bulk-payouts/* (admin)
    // Note: gate is derived from PayoutBalance (BelowMinimum/Allowed); there is
    // no separate KYC/method "gateInputs" source in OpenAPI/web (see FR-4).
}

// feature-payouts (viewmodel — AND-262)
sealed interface PayoutsUiState {
    data object Loading : PayoutsUiState
    data class Content(
        val balance: PayoutBalance,
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
    // fun deriveGate(balance: PayoutBalance): PayoutGate   // BelowMinimum vs Allowed
}
```

### 4.2 Test architecture

- **Repository / mapping tests (JVM, `src/test`):** Use **JUnit4**,
  **MockWebServer (OkHttp 4.12)**, the real Moshi 1.15 adapters and the real
  Retrofit `PayoutsApi` (`GET /ui/payouts/balance`, `GET /ui/payouts`), so
  deserialization, query-param construction, and cursor (`next_cursor`) handling
  are exercised end-to-end against canned HTTP. Fixtures are JSON
  files in `feature-payouts/src/test/resources/fixtures/payouts/`. Use
  `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher`.
- **ViewModel / gating tests (JVM, `src/test`):** Inject a
  `FakePayoutsRepository` (in `core-testing`) implementing `PayoutsRepository`
  with programmable `ApiResult` outcomes and emission delays. Collect `uiState`
  with **Turbine** to assert ordered emissions. Test `deriveGate` as a pure
  function with a parameterized table over `available_cents` vs
  `minimum_payout_cents` boundary inputs (see FR-4 correction). Replace
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

`GET /ui/payouts/balance` (`PayoutBalanceOut`; auth required; cookies +
`X-CSRF-Token`) — *corrected: not `/ui/payouts/summary`, fields are `*_cents`*:
```json
{
  "available_cents": 542300,
  "pending_cents": 118000,
  "hold_cents": 0,
  "total_earned_cents": 1820000,
  "minimum_payout_cents": 1000,
  "currency": "USD"
}
```

`GET /ui/payouts?limit=20&cursor=` (`PayoutListOut`; cursor-paged) — *corrected:
path is `/ui/payouts`, item fields are `payout_id`/`amount_cents`, timestamps are
epoch-seconds integers, cursor field is `next_cursor`*:
```json
{
  "items": [
    {
      "payout_id": "po_01H...",
      "user_id": "usr_01H...",
      "amount_cents": 250000,
      "method": "bank_transfer",
      "status": "processing",
      "created_at": 1748768400,
      "updated_at": 1748768400,
      "completed_at": null,
      "notes": "",
      "reject_reason": "",
      "approved_by": ""
    }
  ],
  "next_cursor": "eyJjcmVhdGVkX2F0..."
}
```
(Params per OpenAPI `list_payouts_ui_payouts_get`: `limit`, `cursor`,
`user_sub`, plus `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` headers.)

Bulk payout tools (owned by `AND-261`) — *corrected: admin-scoped and NOT
read-only*: `GET /ui/admin/bulk-payouts/eligible?kind=` → `BulkEligibleItem[]`;
`GET /ui/admin/bulk-payouts/batches` → `BulkBatchOut[]`;
`GET /ui/admin/bulk-payouts/batches/{batch_id}` → `BulkBatchOut`; plus mutating
`POST /ui/admin/bulk-payouts/preview` (`BulkPreviewIn`) and
`POST /ui/admin/bulk-payouts/execute` (`BulkExecuteIn`), both → `BulkBatchOut`.
If AND-261 ships only a read view on Android, tests assert mapping of
`BulkBatchOut`/`BulkEligibleItem` and that the Android view issues only the GET
endpoints (scope guard, not a backend property).

Payout *request* (creator action, present in the web client; not strictly under
this test ticket but part of the same `payouts.ts` contract):
`POST /ui/payouts/request` (`PayoutRequestIn`: `amount_cents` (min 100), `method`,
`notes`) → 201 `PayoutCreateOut`; `POST /ui/payouts/{payout_id}/cancel` (no body)
→ `PayoutActionOut`.

There is **no** KYC/`/ui/payouts/setup`/`/ui/me`-flag gate input endpoint in the
sources; the gate is derived from `PayoutBalanceOut` (see FR-4). The draft's
`{kyc_status, has_payout_method, account_hold}` body is an unverified assumption.

FastAPI error body (tested in all three `detail` shapes the web client handles in
`normalizeErrorDetail`, `src/api/client.ts`). The 422 array shape matches OpenAPI
`HTTPValidationError` (`detail: [{loc, msg, type}]`):
```json
{ "detail": [ { "loc": ["query", "cursor"], "msg": "invalid cursor", "type": "value_error" } ] }
```
and the string shape `{ "detail": "insufficient available balance" }` and the
object shape `{ "detail": { "code": "PAYOUT_MINIMUM", "message": "below minimum" } }`.
(The original `kyc required` / `PAYOUT_ON_HOLD` codes are illustrative only — no
KYC/hold gate exists; the three *shapes*, not specific codes, are what is tested.)

Tests assert: query params (`limit`, `cursor`), header presence
(`X-CSRF-Token`), status-string→enum mapping, and that each error body maps to
the expected `ApiError` subtype.

## 6. Data & State Management

The suite verifies the data/state contract rather than introducing it.

- **DTO→domain:** *(Corrected field names/types)* Moshi adapters parse
  `available_cents`/`pending_cents`/`hold_cents`/`total_earned_cents`/
  `minimum_payout_cents`/`amount_cents` as `Long` (no float rounding),
  `created_at`/`updated_at`/`completed_at` as epoch-**seconds** integers converted
  to `Instant` (`completed_at` nullable) via a registered adapter, and `status`
  via a custom enum adapter with `UNKNOWN` fallback. Test asserts a `null`
  `completed_at` maps to `null` and an unrecognized status string maps to
  `PayoutStatus.UNKNOWN`.
- **Ordering & paging:** *(Corrected field names)* `PayoutListDto.items` →
  `List<Payout>` sorted by `createdAt` descending; the `next_cursor` token (not
  `next`) is preserved and threaded into the next `LoadParams.Append`. Test feeds
  two pages and asserts the second `load` appends correctly and that
  `nextKey == null` when `next_cursor` is `null` on the final page.
- **Gating state:** *(Corrected — balance-based, no KYC/hold/setup precedence)*
  `deriveGate(balance)` table: `available_cents < minimum_payout_cents` →
  `BelowMinimum`; otherwise → `Allowed`. Boundary cases asserted explicitly
  (`available == minimum` → `Allowed`; `available == minimum - 1` →
  `BelowMinimum`). The original `hold > KYC > setup` precedence is not in any
  source and is removed.
- **Stale/cache:** Repository returns cached balance/history with
  `isStale = true` when the network call fails but a Room row exists. Test seeds
  in-memory Room, fails the `MockWebServer` response (socket disconnect), asserts
  `Content(isStale = true)`.
- **Empty:** `items = []` (empty history) with an `Allowed` gate →
  `PayoutsUiState.Empty` (or `Content` with empty history, per AND-262 contract —
  asserted to match the merged ViewModel). Mirrors web "No payout requests yet".

## 7. Error Handling & Resilience

Tested production behaviors (assertions in repository/ViewModel tests):

- **Timeout:** `MockWebServer` `setBodyDelay(25, SECONDS)` against a ~20s OkHttp
  read timeout → `ApiResult.Failure(NetworkError.Timeout)` →
  `Error(offline = false)` (or stale if cache present). Test uses a shortened
  timeout client to keep the suite fast.
- **401 → refresh once:** Enqueue `401`, then `200` for `POST /ui/session/refresh`,
  then `200` for the retried payouts GET. Assert exactly **one** refresh request
  was recorded and the final result is `Content`. A second `401` must surface as
  `Error` and trigger logout (no infinite loop) — matches `src/api/client.ts`.
- **Bounded backoff** *(net-new Android policy; not in web client)*: Enqueue
  `503` twice then `200` for the idempotent GET (`/ui/payouts/balance`,
  `/ui/payouts`, and the admin bulk GETs); assert success after retries and that
  retry count does not exceed the configured cap. Marked as an Android-side
  resilience addition since the web reference does not retry 503.
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
  history (`GET /ui/payouts`) request after the balance (`GET /ui/payouts/balance`)
  request (same `MockWebServer` instance).
- No secrets, real credentials, or production hosts appear in fixtures or test
  config; the dev host `18.222.237.167` is never contacted. Fixture amounts,
  `method`, `payout_id`, and `user_id` values are synthetic.
- Tests assert that financial PII (full amounts beyond display, `payout_id`,
  `user_id`) and auth cookies are **not** emitted at non-debug log levels (see
  §10). *(Corrected — bulk tools are not read-only at the backend.)* The Android
  bulk-tools view test asserts the *view as built* issues only the GET bulk
  endpoints and no `POST .../preview` or `POST .../execute` mutation (scope guard
  for a read-only Android surface, FR-9).

## 9. Accessibility & i18n

- **A11y (UI tests):** Each Compose state test asserts meaningful semantics:
  payout status chips expose a `contentDescription`/`stateDescription` conveying
  the status (not color-only); the gate banner (`BelowMinimum`) is announced as an
  alert with an actionable label (e.g. "Minimum payout is $10.00"); the retry
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
  at `WARN`/`ERROR` without including cookie values, `payout_id`/`user_id`, or full
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

- **R-1 (signature drift):** *(Resolved in this review.)* Field names/types are
  now confirmed against OpenAPI (`PayoutBalanceOut`, `PayoutOut`, `PayoutListOut`)
  and `frontend/src/api/types.ts`: `*_cents` Long fields, `payout_id`, epoch-seconds
  integer timestamps, list field `items`, cursor field `next_cursor`. Fixtures must
  use these exact keys. Mitigation retained: a contract test that diffs fixture
  keys against the committed OpenAPI snapshot.
- **R-2 (gate model):** *(Resolved/corrected.)* There is **no** KYC/hold/setup
  gate in the sources; gating is balance vs `minimum_payout_cents` only
  (`BelowMinimum`/`Allowed`). **Open only if** AND-262/AND-259 introduce a real
  KYC/onboarding gate not yet in the backend — if so, file a follow-up and extend
  the table; do not assume it today.
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
- **AC-4:** Gating tests prove FR-4 across the balance/minimum boundary table
  (`available_cents` vs `minimum_payout_cents` → `BelowMinimum`/`Allowed`). *(No
  KYC/hold/setup precedence exists — corrected.)*
- **AC-5:** Error tests prove FR-5 (all three `detail` shapes), timeout, 401→
  single-refresh→retry with exactly one refresh request, and bounded 503 backoff
  (FR-7).
- **AC-6:** Paging tests prove FR-8 (`prevKey`/`nextKey`, terminal page,
  append-error).
- **AC-7:** Stale/offline tests prove `Content(isStale=true)` with cache and
  `Error(offline=true)` without (FR-6).
- **AC-8:** Bulk tools tests prove FR-9 mapping (`BulkBatchOut`/`BulkEligibleItem`)
  and that the Android read view issues only the GET bulk endpoints (no
  `preview`/`execute` POST) — scope guard, not a backend read-only property.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. "OpenAPI"
refers to `reference/openapi.index.txt` / `reference/openapi.pretty.json`
(`components.schemas.<Name>`); "frontend" paths are under `reference/src/`.

1. **Balance endpoint is `GET /ui/payouts/balance` returning `PayoutBalanceOut`.**
   VERDICT: Corrected (draft said `GET /ui/payouts/summary`). SOURCE: OpenAPI
   `GET /ui/payouts/balance | resp=200:PayoutBalanceOut`;
   `frontend/src/api/endpoints/payouts.ts: getPayoutBalance`.
2. **Balance fields are `available_cents`, `pending_cents`, `hold_cents`,
   `total_earned_cents`, `minimum_payout_cents`, `currency` (integer cents).**
   VERDICT: Corrected (draft said `available_minor`/`pending_minor`,
   `next_scheduled_at`). SOURCE: OpenAPI schema `PayoutBalanceOut`;
   `frontend/src/api/types.ts: PayoutBalance`.
3. **No `next_scheduled_at`/next-scheduled-payout-date field exists.** VERDICT:
   Corrected. SOURCE: OpenAPI `PayoutBalanceOut` (absent); `types.ts: PayoutBalance`.
4. **History endpoint is `GET /ui/payouts` returning `PayoutListOut`.** VERDICT:
   Corrected (draft said `GET /ui/payouts/history`). SOURCE: OpenAPI
   `GET /ui/payouts | op=list_payouts_ui_payouts_get | resp=200:PayoutListOut`;
   `frontend/src/api/endpoints/payouts.ts: listPayouts`.
5. **History list field is `items`; cursor field is `next_cursor` (nullable
   string).** VERDICT: Corrected (draft said cursor `next`). SOURCE: OpenAPI
   `PayoutListOut` (`items`, `next_cursor`); `types.ts: PayoutListResp`.
6. **History query params are `limit`, `cursor` (plus `user_sub` and
   `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`).** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/payouts | params=limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`;
   `frontend/src/api/endpoints/payouts.ts: listPayouts` (sends `limit`,`cursor`).
7. **Payout item fields: `payout_id`, `user_id`, `amount_cents`, `method`,
   `status`, `created_at`, `updated_at`, `completed_at?`, `notes`,
   `reject_reason`, `approved_by`.** VERDICT: Corrected (draft used `id`,
   `amount_minor`, `arrived_at`, `method_last4`). SOURCE: OpenAPI schema
   `PayoutOut`; `frontend/src/api/types.ts: Payout`.
8. **Timestamps (`created_at`/`updated_at`/`completed_at`) are Unix epoch-seconds
   integers, not ISO-8601 strings.** VERDICT: Corrected. SOURCE: OpenAPI `PayoutOut`
   (`type: integer`); `PayoutDashboard.tsx: formatDate`/`formatDateTime` do
   `new Date(ts * 1000)`.
9. **Payout status string set is `requested`, `approved`, `processing`,
   `completed`, `rejected`, `cancelled`.** VERDICT: Corrected (draft said
   `pending`/`in_transit`/`paid`/`failed`/`canceled`/`on_hold`). SOURCE:
   `frontend/src/pages/payouts/PayoutDashboard.tsx: STATUS_BADGE_VARIANT` and the
   `status === "requested"/"approved"/"rejected"` checks. NOTE: OpenAPI types
   `PayoutOut.status` as free-form `string`, so `UNKNOWN`-fallback remains the
   contract guard.
10. **There is no KYC/onboarding/method gate; eligibility is balance vs
    `minimum_payout_cents`.** VERDICT: Corrected (draft's `KycRequired`/
    `SetupRequired`/`Blocked` model and `/ui/payouts/setup`/`/ui/me` KYC flags are
    unverifiable). SOURCE: no payout-gate/KYC endpoint in `openapi.index.txt`;
    `PayoutDashboard.tsx: canSubmit` (uses `minimum_payout_cents`,
    `available_cents`); no `kyc`/`gate` token in `PayoutDashboard.tsx`.
11. **Auth: cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERDICT:
    Verified. SOURCE: `frontend/src/api/client.ts` lines 168-170
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`), `credentials:
    "include"`.
12. **401 → single `POST /ui/session/refresh` then one retry; second 401 logs
    out (no loop).** VERDICT: Verified. SOURCE: `frontend/src/api/client.ts`
    `refreshSession()` (POST `/ui/session/refresh`) and the 401 block
    (single `refreshPromise`, one `retryRes`, `logout("session_expired")` on
    repeat 401).
13. **FastAPI `detail` appears in three shapes (string | `[{msg,...}]` |
    `{...}` object) and maps to a single message.** VERDICT: Verified. SOURCE:
    `frontend/src/api/client.ts: normalizeErrorDetail`; OpenAPI
    `HTTPValidationError` (`detail: [ValidationError{loc,msg,type}]`) for the 422
    array shape.
14. **Bulk payout tools are admin-scoped under `/ui/admin/bulk-payouts/*` and
    include mutating `POST .../preview` and `POST .../execute`.** VERDICT:
    Corrected (draft said read-only `GET /ui/payouts/bulk-tools`). SOURCE: OpenAPI
    `GET /ui/admin/bulk-payouts/eligible|batches|batches/{batch_id}`,
    `POST /ui/admin/bulk-payouts/preview` (`BulkPreviewIn`),
    `POST /ui/admin/bulk-payouts/execute` (`BulkExecuteIn`);
    `frontend/src/api/endpoints/bulkPayoutTools.ts` (`preview`,`execute`);
    `frontend/src/pages/admin/BulkPayoutConsole.tsx`.
15. **Payout request/cancel exist: `POST /ui/payouts/request`
    (`PayoutRequestIn`, `amount_cents` min 100) → 201 `PayoutCreateOut`;
    `POST /ui/payouts/{payout_id}/cancel` (no body) → `PayoutActionOut`.**
    VERDICT: Verified. SOURCE: OpenAPI lines for those ops; schema
    `PayoutRequestIn` (`amount_cents minimum:100`), `PayoutCreateOut`,
    `PayoutActionOut`; `frontend/src/api/endpoints/payouts.ts: requestPayout`,
    `cancelPayout`.
16. **Amounts rendered by dividing cents by 100 with locale formatting; dates via
    locale formatter.** VERDICT: Verified (supports the i18n test). SOURCE:
    `PayoutDashboard.tsx: formatCents` (`cents/100`, `toLocaleString`),
    `formatDate`.
17. **503 bounded-backoff retry (FR-7).** VERDICT: Unverified-assumption
    (Android-only). SOURCE: not present in `frontend/src/api/client.ts` (only 401
    refresh is implemented); framework ref for OkHttp/retry policy is an Android
    implementation choice, not a backend/web contract.
18. **Offline/stale model: `Content(isStale=true)` from cache, else
    `Error(offline=true)`.** VERDICT: Unverified-assumption (Android-side; web
    uses react-query `staleTime`/`refetchInterval`, no Room cache). SOURCE:
    `PayoutDashboard.tsx` `useQuery({ staleTime, refetchInterval })` — no
    offline-cache fallback; the Android Room-stale behavior is owned by AND-262.
19. **Paging 3 cursor paging for history (FR-8).** VERDICT: Unverified-assumption
    (Android-side). SOURCE: web client uses a single `listPayouts({limit:25})` with
    a non-wired "Load more" button (`PayoutDashboard.tsx` line ~515); the cursor
    field `next_cursor` is real (OpenAPI `PayoutListOut`) so Paging 3 is feasible,
    but the web app does not implement cursor paging.
20. **Test tooling choices (JUnit4, MockWebServer, Turbine, Robolectric, Paging 3
    test artifact, Compose UI Test).** VERDICT: Unverified-assumption (framework
    ref). SOURCE: standard AndroidX test stack — framework ref
    `https://developer.android.com/training/testing` and
    `https://developer.android.com/topic/libraries/architecture/paging/test`. Not
    derivable from backend/web sources.

### Corrections made

- §1/§3/§4/§5/§6: endpoint `summary`→`balance` (`GET /ui/payouts/balance`),
  `history`→`GET /ui/payouts`.
- Field renames: `available_minor`/`pending_minor`/`amount_minor`→`*_cents`;
  `id`→`payout_id`; `arrived_at`/`method_last4`→`completed_at`/`method`; cursor
  `next`→`next_cursor`; removed `next_scheduled_at`.
- Timestamps corrected from ISO-8601 strings to Unix epoch-seconds integers.
- `PayoutStatus` enum replaced with the real web status set
  (`REQUESTED/APPROVED/PROCESSING/COMPLETED/REJECTED/CANCELLED/UNKNOWN`).
- Gate model corrected: KYC/setup/hold gate (and `hold>KYC>setup` precedence)
  removed; replaced with balance-vs-`minimum_payout_cents` (`BelowMinimum`/
  `Allowed`).
- Bulk tools corrected from "read-only `GET /ui/payouts/bulk-tools`" to admin
  `GET/POST /ui/admin/bulk-payouts/*` (with mutating preview/execute); the
  "no mutation" assertion re-scoped to the Android view.
- §13 R-1/R-2 marked resolved; 503 backoff, offline-cache, and Paging-3 flagged
  as Android-side assumptions in §7/§16.
- Domain/DTO/ViewModel signatures in §4.1 updated (`PayoutBalance`, `Payout`,
  `PayoutGate`, repository methods, `Content(balance=...)`).

### Open assumptions

- **503 bounded backoff (claim 17):** not in the web client; net-new Android
  resilience policy. Cannot be verified against sources; owned by AND-027/AND-262.
- **Offline/stale via Room (claim 18):** web has no offline cache; Android-side
  behavior owned by AND-262 — unverifiable here.
- **Paging 3 cursor paging (claim 19):** `next_cursor` exists but the web app
  does not paginate; whether AND-260 uses Paging 3 vs a bounded list is open.
- **A KYC/onboarding gate (claim 10):** none exists in current sources; if
  AND-259/AND-262 add one beyond the balance check it must be sourced from a real
  endpoint and a follow-up filed.
- **Whether the Android bulk-tools view is read-only (claim 14):** the backend is
  not; whether AND-261 ships the admin write actions on Android is an open product
  decision.
- **Test tooling (claim 20):** standard AndroidX stack assumed; not derivable
  from backend/web sources (framework ref only).

## 17. Test Plan

Acceptance-criteria references trace to §14 (AC-1..AC-11). "MWS" = MockWebServer.
Unless noted, JVM/Robolectric cases run on the **JVM unit/Robolectric** target
(no device); Compose-UI cases run on the **headless emulator AVD `test35`**
(API 35) in CI; no case in this ticket requires the physical device (no camera /
biometrics / FCM / WebRTC / Telecom / streaming behavior is involved — those
belong to other epics). The optional instrumented smoke test (TC-13) may run on
either `test35` or the **physical Samsung Galaxy A15 (SM-A156U, API 34)**; running
it on the physical device additionally exercises the arm64-v8a ABI / API-34
path versus the x86_64/API-35 emulator.

- **TC-AND-263-01 — Balance DTO maps to domain.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: MWS enqueues a
  200 `PayoutBalanceOut` fixture (`available_cents:542300, pending_cents:118000,
  hold_cents:0, total_earned_cents:1820000, minimum_payout_cents:1000,
  currency:"USD"`). Steps: call `PayoutsApi.balance()` through real
  Retrofit/Moshi. Expected: `PayoutBalance` has matching Long cents fields and
  `currency=="USD"`; no float rounding. Traces: AC-3.
- **TC-AND-263-02 — History DTO maps, descending order, cursor preserved.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: MWS enqueues a
  200 `PayoutListOut` with two items (`created_at` 1748850000 then 1748768400) and
  `next_cursor:"abc"`. Steps: call history endpoint; map to `List<Payout>`.
  Expected: items mapped with `payout_id`/`amount_cents`/`method`; list sorted by
  `createdAt` descending; `next_cursor=="abc"` preserved; `completed_at:null`→
  `null`. Traces: AC-3, AC-6.
- **TC-AND-263-03 — Status string→enum incl. UNKNOWN fallback.**
  Type: unit (parameterized). Target: JVM unit. Preconditions: status strings
  `requested, approved, processing, completed, rejected, cancelled` plus
  `"future_state"`. Steps: run the Moshi enum adapter for each. Expected: each
  known string maps to its `PayoutStatus`; the unknown maps to
  `PayoutStatus.UNKNOWN` with no exception. Traces: AC-3.
- **TC-AND-263-04 — Epoch-seconds timestamp conversion.**
  Type: unit. Target: JVM unit. Preconditions: fixture `created_at:1748768400`,
  `completed_at:null`. Steps: deserialize. Expected: `createdAt ==
  Instant.ofEpochSecond(1748768400)`; `completedAt == null`. Traces: AC-3.
- **TC-AND-263-05 — Gate derivation (balance vs minimum) boundaries.**
  Type: unit (parameterized). Target: JVM unit. Preconditions: balances
  `(available, minimum)` = `(1000,1000)`, `(999,1000)`, `(0,1000)`,
  `(5000,1000)`. Steps: call `deriveGate(balance)`. Expected:
  `1000>=1000`→`Allowed`; `999<1000`→`BelowMinimum`; `0`→`BelowMinimum`;
  `5000`→`Allowed`. Traces: AC-4.
- **TC-AND-263-06 — FastAPI `detail` three shapes → typed `ApiError`.**
  Type: unit (parameterized). Target: JVM unit. Preconditions: bodies (a) 422
  `{"detail":[{"loc":["query","cursor"],"msg":"invalid cursor","type":"value_error"}]}`,
  (b) `{"detail":"insufficient available balance"}`, (c)
  `{"detail":{"code":"PAYOUT_MINIMUM","message":"below minimum"}}`. Steps: run the
  error mapper. Expected: each maps to an `ApiError` whose message is the array
  `msg`, the string, and the object `message`/`code` respectively (mirrors
  `normalizeErrorDetail`). Traces: AC-5.
- **TC-AND-263-07 — 401 triggers exactly one refresh then retry; second 401
  fails.** Type: contract/MockWebServer. Target: JVM unit. Preconditions: MWS
  enqueues `401`, then `200` for `POST /ui/session/refresh`, then `200`
  `PayoutBalanceOut`. Steps: call balance; inspect `RecordedRequest` queue.
  Expected: result is `Content`; exactly one request hit `/ui/session/refresh`;
  exactly one retry of the original GET. Then a second scenario enqueues
  `401`→refresh `200`→`401`: expected `Error` and no further retry (no loop).
  Traces: AC-5.
- **TC-AND-263-08 — Bounded 503 backoff on idempotent GET (Android policy).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: MWS enqueues
  `503,503,200` for `GET /ui/payouts/balance` with a shortened backoff clock.
  Steps: call balance. Expected: success after retries; total attempts <= the
  configured cap; non-idempotent calls are not retried. NOTE: this validates a
  net-new Android resilience policy (not in the web client, §16 claim 17).
  Traces: AC-5.
- **TC-AND-263-09 — Malformed JSON → ParseError, no crash.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: MWS returns 200
  with `amount_cents:"not-a-number"`. Steps: call history. Expected:
  `ApiResult.Failure(ParseError)`; no uncaught exception. Traces: AC-3, AC-11.
- **TC-AND-263-10 — Paging source keys + terminal page + append error.**
  Type: unit (Paging 3 `TestPager`). Target: JVM unit. Preconditions: page 1 →
  `next_cursor:"c2"`; append with `c2` → `next_cursor:null`; a third append
  enqueues a 500. Steps: `refresh`, then `append`, then `append`. Expected:
  refresh `LoadResult.Page(prevKey=null, nextKey="c2")`; second page
  `nextKey=null` (terminal); failing append → `LoadResult.Error`. Traces: AC-6.
- **TC-AND-263-11 — Offline with cache → stale; without cache → offline error.**
  Type: integration (Robolectric + in-memory Room + MWS). Target: JVM/Robolectric.
  Preconditions: (a) seed Room with a prior balance row, MWS disconnects socket;
  (b) empty Room, MWS disconnects. Steps: load via repository/ViewModel. Expected:
  (a) `Content(isStale=true)` from cache; (b) `Error(offline=true)`. NOTE:
  Android-side behavior (§16 claim 18). Traces: AC-7.
- **TC-AND-263-12 — Bulk tools map + Android view issues only GET (no
  mutation).** Type: contract/MockWebServer. Target: JVM unit. Preconditions: MWS
  enqueues 200 `BulkEligibleItem[]` and `BulkBatchOut[]` for
  `GET /ui/admin/bulk-payouts/eligible` and `.../batches`. Steps: load the
  Android bulk read view/repository. Expected: DTOs map to `BulkPayoutToolsView`;
  the `RecordedRequest` queue contains only GET paths and no
  `POST .../preview` or `POST .../execute`. NOTE: scope guard for a read-only
  Android surface; backend itself exposes write endpoints (§16 claim 14).
  Traces: AC-8.
- **TC-AND-263-13 — ViewModel state ordering, gate surfacing, retry, telemetry.**
  Type: unit (Turbine + FakeRepository + MainDispatcherRule). Target: JVM unit.
  Preconditions: fake repo emits Loading→balance below minimum, then on `retry()`
  emits a populated `Allowed`. Steps: collect `uiState` with Turbine. Expected:
  ordered `Loading`→`Content(gate=BelowMinimum)`→(after retry)
  `Content(gate=Allowed)`; `FakeAnalytics` recorded `payouts_viewed` and
  `payout_gate_shown{gate=BelowMinimum}` once (no double-log on retry);
  `payouts_load_failed{reason}` on an error variant. Traces: AC-4, AC-7, AC-10.
- **TC-AND-263-14 — CSRF header echoes `ui_csrf`; cookie jar replays session; no
  PII logged.** Type: contract/MockWebServer + security. Target: JVM unit.
  Preconditions: MWS sets a `ui_csrf` cookie and a session cookie on a priming
  response; capturing log tree installed. Steps: issue balance then history on the
  same client. Expected: both outgoing requests carry `X-CSRF-Token` equal to the
  `ui_csrf` value and replay the session cookie; logs at WARN/ERROR contain no
  cookie values, `payout_id`, or `user_id`. Traces: AC-10.
- **TC-AND-263-15 — Compose rendering of every `PayoutsUiState` + gate banner +
  a11y.** Type: Compose-UI. Target: headless emulator `test35` (or Robolectric
  Compose). Preconditions: `PayoutsScreen(state,onRetry)` driven with Loading,
  Content(Allowed), Content(BelowMinimum), Empty, Error. Steps: assert via
  `onNodeWithTag`/`onNodeWithText`. Expected: skeleton on Loading; balance cards +
  history on Content; the `BelowMinimum` banner announced as an alert with an
  actionable label; "No payout requests yet" on Empty; error + reachable Retry on
  Error; status chips expose non-color-only `stateDescription`; history rows expose
  combined amount+status+date semantics. Traces: AC-9.
- **TC-AND-263-16 — German-locale amount/date formatting.** Type: Compose-UI.
  Target: headless emulator `test35`. Preconditions: configuration `Locale.GERMANY`,
  fixed clock; `amount_cents:250000`. Steps: render a history row. Expected: amount
  formatted with German grouping/decimal separators and configured currency symbol
  (guards against hardcoded `String.format`); date via locale-aware formatter under
  the fixed clock. Traces: AC-9.
- **TC-AND-263-17 — Instrumented smoke (Hilt) on device/emulator.** Type:
  instrumented/e2e. Target: **physical Samsung Galaxy A15 (SM-A156U, API 34,
  arm64-v8a)** preferred, else emulator `test35`. Preconditions: `@HiltAndroidTest`
  graph with the fake repository; app launches the Payouts screen. Steps: launch,
  assert the screen composes and the balance cards render. Expected: green on a
  real device, additionally exercising the arm64-v8a/API-34 path vs the
  x86_64/API-35 emulator. Traces: AC-2, AC-11.

### Coverage matrix

| AC (from §14) | Covered by |
| --- | --- |
| AC-1 (unit suite present/green) | TC-01..TC-14 (all JVM cases) |
| AC-2 (Compose/instrumented task green) | TC-15, TC-16, TC-17 |
| AC-3 (FR-1/FR-2/FR-3 mapping) | TC-01, TC-02, TC-03, TC-04, TC-09 |
| AC-4 (FR-4 gate table) | TC-05, TC-13 |
| AC-5 (FR-5 detail shapes, timeout, 401-once, 503) | TC-06, TC-07, TC-08 |
| AC-6 (FR-8 paging keys/terminal/error) | TC-02, TC-10 |
| AC-7 (FR-6 stale/offline) | TC-11, TC-13 |
| AC-8 (FR-9 bulk map + no mutation) | TC-12 |
| AC-9 (FR-10 UI states, a11y, i18n) | TC-15, TC-16 |
| AC-10 (CSRF/cookie/no-PII-log) | TC-07, TC-13, TC-14 |
| AC-11 (hermetic, green CI) | TC-09, TC-17 (and all JVM cases run without network/sleep) |
