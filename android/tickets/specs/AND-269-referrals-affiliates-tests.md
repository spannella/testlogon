---
id: AND-269
title: Referrals/affiliates tests
milestone: M6
epic: E36
priority: P2
size: M
status: draft
depends_on: [AND-268, AND-264, AND-265, AND-266, AND-267]
blocks: []
---

# AND-269 — Referrals/affiliates tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks the behavior of the
**Referrals & Affiliates** epic (`E36`, milestone `M6`) of the TestLogon native
Android app (`com.testlogon.android`). It adds no product behavior; it proves the
already-built feature surfaces are correct and regression-protected in CI.

The surfaces under test were built upstream: `AND-264` (Referrals — the
`referrals.ts`-equivalent `ReferralsApi`, DTOs, `ReferralsRepository`, Room cache,
and the Compose Referrals screen), `AND-265` (Affiliates dashboard — `AffiliateApi`,
`AffiliateRepository`, the links + earnings screen), `AND-266` (Promo codes —
`PromoCodesApi`, create/list/redeem flows), `AND-267` (Affiliate discounts — the
discount catalog screen extending the affiliates module), and `AND-268` (the
Referrals/affiliates **ViewModels** — `ReferralViewModel`, `AffiliateViewModel`,
their `UiState`/`Intent`/`Effect` sealed contracts, paging, and `SavedStateHandle`
restoration). `AND-268` is the direct dependency.

The backlog scope is exactly **"Repo + UI tests"** and the acceptance bar is
**"Pass."** Concretely we deliver two test tiers: (a) **repository / mapping /
network unit tests** (JVM, MockWebServer) covering DTO deserialization, DTO→domain
mapping, query/cursor parameterization, paging, FastAPI `detail` error mapping, the
401-refresh and bounded-backoff resilience paths, and offline/stale cache reads; and
(b) **ViewModel + Compose UI tests** covering every `UiState` transition, one-shot
effects (copy/share), empty/ineligible/session-expired states, and Compose
rendering of each state for the Referrals screen, the Affiliates dashboard, the
Promo screen, and the Discounts screen. The suite must be hermetic (no live dev
host), deterministic (controlled clock + dispatchers), and green under the
`feature-referrals`, `feature-affiliates`, and `feature-promo` module test tasks
in CI.

## 2. Context & References

- **Backlog ticket:** `AND-269 — Referrals/affiliates tests`. Type: Test ·
  Priority: P2 · Deps: `AND-268`. Scope: "Repo + UI tests." Acceptance: "Pass."
- **Upstream tickets under test (epic E36):**
  - `AND-264` — Referrals (`ReferralsApi`, `ReferralDto`/`ReferralStatsDto`,
    `ReferralsRepository`, Room `ReferralEntity`, `ReferralsScreen`).
  - `AND-265` — Affiliates dashboard (`AffiliateApi`, `AffiliateRepository`,
    `AffiliatesViewModel`/`AffiliatesUiState`, links + earnings screen).
  - `AND-266` — Promo codes (`PromoCodesApi`, `PromoCodesRepository`,
    create/list/redeem, paged list screen).
  - `AND-267` — Affiliate discounts (discount catalog mapping + Discounts screen).
  - `AND-268` — Referrals/affiliates ViewModels (**direct dep**): `ReferralViewModel`,
    `AffiliateViewModel`, `ReferralUiState`/`ReferralIntent`/`ReferralEffect`,
    `AffiliateUiState`/`AffiliateTab`, paging via `cachedIn`, `SavedStateHandle`.
  - Transitively `AND-027` (core-network: authenticated Retrofit/OkHttp, persistent
    cookie jar, CSRF interceptor echoing `ui_csrf` as `X-CSRF-Token`, single
    `POST /ui/session/refresh` retry on 401, shared `ApiResult` + `detail` mapper).
- **Modules / test source sets:**
  - `feature-referrals/src/test` (JVM/Robolectric), `feature-referrals/src/androidTest`.
  - `feature-affiliates/src/test`, `feature-affiliates/src/androidTest`
    (hosts AND-265 and AND-267 surfaces and the AND-268 ViewModels).
  - `feature-promo/src/test`, `feature-promo/src/androidTest`.
  - Shared fakes/rules from `core-testing`.
- **Web reference (contract truth):** `frontend/src/api/endpoints/referrals.ts`,
  `affiliates.ts`, `promoCodes.ts`, `adCreativeAffiliate` discount endpoints, and
  shared types in `frontend/src/api/types.ts`; the FastAPI source of truth is
  `/openapi.json` on dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable dev host). Tests use stubbed `MockWebServer` and never contact it.
- **Namespaces:** `com.testlogon.android.feature.referrals`,
  `com.testlogon.android.feature.affiliates`, `com.testlogon.android.feature.promo`.

## 3. Functional Requirements

The deliverable is the suite; each FR is a production behavior the suite must verify.

- **FR-1 (Referral mapping):** A well-formed `GET /ui/referrals` body deserializes
  into `ReferralDto`/`ReferralStatsDto` and maps to `Referral`; missing `stats` →
  all counters `0`; `enabled = false` or `link = null` → `Ineligible`; null
  `reward_credits`/`pending_credits` → hidden reward tiles (not `0`).
- **FR-2 (Referral ViewModel states):** `ReferralViewModel` emits
  `Loading → Content` on success, `Loading → Error(retryable)` on transient failure,
  `Content(isEmpty = true)` when `total_referrals == 0`, and refresh preserves
  visible `Content` while toggling `isRefreshing` (no full-screen spinner flash).
- **FR-3 (Referral effects):** `CopyLink` emits `ReferralEffect.CopyToClipboard(url)`
  with the current referral URL; `ShareLink` emits
  `ReferralEffect.ShowShareSheet(text)`. Each effect is delivered exactly once.
- **FR-4 (In-flight guard):** A second `Load`/`Refresh` while a load is in flight
  calls the repository exactly once (FR-10 of AND-268).
- **FR-5 (Affiliate summary mapping + states):** `GET /ui/affiliates/summary`
  maps to `AffiliateSummary` (clicks, signups, conversions, pending/paid earnings
  minor-units, currency); `AffiliateViewModel` emits `Loading → Content`/`Error`
  and `Content(isEmpty = true)` on zero activity.
- **FR-6 (Affiliate paging):** `GET /ui/affiliates/conversions?cursor=&limit=20`
  drives a cursor `PagingSource`; `conversions` Paging flow emits the expected
  item snapshot ordered as served, threads `next_cursor` into the next append, and
  surfaces `LoadResult.Error` on failure.
- **FR-7 (Tab restoration):** The selected `AffiliateTab` is persisted/restored via
  `SavedStateHandle` across ViewModel re-creation.
- **FR-8 (Promo create/list/redeem):** `PromoCodesRepository` lists codes (paged),
  creates a code via `POST`, and redeems via `POST`; success/validation-error paths
  map to the correct `ApiResult`/UI state. Create + list is the must-pass MVP.
- **FR-9 (Discounts mapping + render):** Affiliate discount offers deserialize and
  map to the discount domain model (code, value, scope, validity window, affiliate
  link); the Discounts screen renders the list, empty, and offline states.
- **FR-10 (Error mapping):** FastAPI `detail` in all three shapes (`string` |
  `[{msg}]` | `{code,...}`) maps to a typed `ApiError`/`ApiResult.Error` carrying a
  user-facing message and a `retryable` flag (network/timeout/5xx retryable; 4xx
  validation not retryable).
- **FR-11 (Resilience):** A 401 triggers exactly one `POST /ui/session/refresh`
  then one retry; a transient 503 on an idempotent GET triggers bounded backoff
  (capped) retry; a ~20s timeout maps to a network error / stale fallback.
- **FR-12 (Offline/stale):** With a Room-cached prior payload and no network, the
  Referrals/Discounts repository returns `Content(isStale = true)`; with no cache it
  returns a retryable `Error` (or `Error(offline = true)`).
- **FR-13 (Compose rendering):** Each feature screen renders one Compose test per
  state — loading, content (link + stats / links + earnings / promo list / discount
  list), empty/ineligible, session-expired, error-with-retry, and stale banner.

## 4. Technical Design

### 4.1 Production surface under test

Tests compile against these agreed signatures (from AND-264/265/266/267/268); if a
signature drifts the test is the failing tripwire.

```kotlin
// core-model (AND-264 / AND-268)
data class Referral(val link: String, val code: String?, val enabled: Boolean, val stats: ReferralStats)
data class ReferralStats(val invitesSent: Int, val signups: Int, val conversions: Int,
                         val rewardCredits: Int?, val pendingCredits: Int?)
data class AffiliateSummary(val clicks: Int, val signups: Int, val conversions: Int,
                            val earningsPendingMinor: Long, val earningsPaidMinor: Long, val currency: String)
data class AffiliateConversion(val id: String, val createdAt: Instant, val amountMinor: Long,
                               val currency: String, val status: String)

// feature ViewModels (AND-268)
sealed interface ReferralUiState { /* Loading; Content(overview,isEmpty,isRefreshing); Error(message,retryable) */ }
sealed interface ReferralIntent  { /* Load; Refresh; Retry; CopyLink; ShareLink */ }
sealed interface ReferralEffect  { data class CopyToClipboard(val url: String); data class ShowShareSheet(val shareText: String) }
sealed interface AffiliateUiState { /* Loading; Content(summary,isRefreshing); Error(message,retryable) */ }
enum class AffiliateTab { Overview, Conversions }

// repositories
interface ReferralRepository {
    suspend fun getReferralOverview(): ApiResult<ReferralOverview>
    suspend fun getAffiliateSummary(): ApiResult<AffiliateSummary>
    fun affiliateConversionsPager(): Pager<Int, AffiliateConversion>
}
interface PromoCodesRepository {
    fun listPagingSource(): PagingSource<String, PromoCode>
    suspend fun create(req: CreatePromoRequest): ApiResult<PromoCode>
    suspend fun redeem(code: String): ApiResult<PromoRedemption>
}
```

### 4.2 Test architecture

- **Repository / mapping / network tests (JVM, `src/test`):** JUnit4 +
  **MockWebServer (OkHttp 4.12)** + the real Moshi 1.15 adapters and real Retrofit
  interfaces (`ReferralsApi`, `AffiliateApi`, `PromoCodesApi`), so snake_case
  decoding, query-param/cursor construction, and `X-CSRF-Token` header presence are
  exercised end-to-end against canned HTTP. Fixtures are JSON under
  `src/test/resources/fixtures/{referrals,affiliates,promo,discounts}/`. Coroutines
  driven by `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher`.
- **ViewModel tests (JVM, `src/test`):** Construct the ViewModel directly (no Hilt)
  with a `FakeReferralRepository` / `FakeAffiliateRepository` (in `core-testing`)
  exposing programmable `ApiResult` outcomes and a call counter (for FR-4). Collect
  `uiState` and the `effects` `Flow` with **Turbine** to assert ordered emissions
  and one-shot delivery. Replace `Dispatchers.Main` via `MainDispatcherRule`
  (`Dispatchers.setMain(StandardTestDispatcher())`). Restoration (FR-7) is tested
  by building a second ViewModel from the same `SavedStateHandle`.
- **Paging tests (JVM, `src/test`):** Drive `affiliateConversionsPager()`’s
  `PagingSource.load(LoadParams.Refresh/Append)` directly and assert `LoadResult.Page`
  keys/order; use the **Paging 3 testing artifact** (`TestPager` /
  `AsyncPagingDataDiffer.asSnapshot`) for end-to-end `PagingData` collection. Same
  pattern for `PromoCodesRepository.listPagingSource()`.
- **UI tests (`src/androidTest` or Robolectric `src/test`):** `createComposeRule()`
  drives each screen's stateless Composable
  (`ReferralsScreen(state, onShare, onCopy, onRetry, onRefresh)`, the affiliates
  dashboard, the promo list, the discounts screen) with each state, asserting via
  `onNodeWithTag`/`onNodeWithText`. Prefer Robolectric-backed Compose tests so the
  bulk of the suite runs on CI without an emulator; keep one true instrumented
  smoke test per module (`@HiltAndroidTest`) per the AND-264 acceptance check.
- **Effect/side-effect tests:** the share path asserts a `text/plain`
  `Intent.ACTION_SEND` is built from `ShowShareSheet` text via a fake intent
  launcher / `LocalClipboard` capture, mirroring AND-264 §11.

### 4.3 Determinism

- Fix the clock with `Clock.fixed(...)` / a `TimeProvider` fake so relative-time
  rendering of `created_at` / validity windows is stable.
- No real I/O: in-memory Room (`Room.inMemoryDatabaseBuilder`) for stale-cache
  tests; temp-folder DataStore where any prefs are read; a shortened-timeout OkHttp
  client for the timeout test (`setBodyDelay`) to keep the suite fast.
- No `Thread.sleep`, no real dispatchers, no live host (`18.222.237.167` never hit).

## 5. API Contract

This is a **test** ticket; it defines no endpoints. It validates contracts owned by
AND-264/265/266/267. The shapes below are the fixture basis (mirroring the web
reference and `/openapi.json`); all requests are authenticated (cookies +
`X-CSRF-Token`, single `POST /ui/session/refresh` retry on 401).

`GET /ui/referrals` →
```json
{ "link": "https://testlogon.app/r/AB12CD", "code": "AB12CD", "enabled": true,
  "stats": { "invites_sent": 12, "signups": 5, "conversions": 3,
             "reward_credits": 30, "pending_credits": 10 } }
```

`GET /ui/affiliates/summary` →
```json
{ "clicks": 184, "signups": 23, "conversions": 9,
  "earnings_pending_cents": 4500, "earnings_paid_cents": 12000, "currency": "USD" }
```

`GET /ui/affiliates/conversions?cursor=&limit=20` (cursor-paged) →
```json
{ "items": [ { "id": "ac_01H...", "created_at": "2026-06-01T09:00:00Z",
               "amount_cents": 1500, "currency": "USD", "status": "pending" } ],
  "next_cursor": "eyJjcmVhdGVkX2F0..." }
```

`GET /ui/promo-codes?cursor=&limit=20` (paged list), `POST /ui/promo-codes`
(create, body `{ "code": "...", "discount_percent": 10, ... }`), and
`POST /ui/promo-codes/redeem` (body `{ "code": "..." }`) — promo create/list/redeem.

Affiliate discounts (`adCreativeAffiliate`) — list of offers with `code`, `value`
(`percent`/`amount_cents`), `scope`, `valid_from`/`valid_until`, and an
affiliate-attributed `link`.

FastAPI error envelope, tested in all three `detail` shapes:
```json
{ "detail": "Referral program not available" }
{ "detail": [ { "loc": ["body","code"], "msg": "code already exists", "type": "value_error" } ] }
{ "detail": { "code": "PROMO_EXPIRED", "message": "promo code expired" } }
```

Tests assert: query params (`cursor`, `limit`), `X-CSRF-Token` header presence and
equality with the `ui_csrf` cookie, cursor threading, status-string preservation,
and that each error body maps to the expected typed error / `retryable` flag.

## 6. Data & State Management

The suite verifies the data/state contract rather than introducing it.

- **DTO→domain:** Moshi adapters parse `@Json(name = "...")` snake_case fields;
  `amount_cents`/`earnings_*_cents` decode as `Long` (no float rounding);
  timestamps via a registered `InstantAdapter`. Tests assert: missing `stats` →
  zero counters; null reward fields → hidden tiles; `enabled = false`/`link = null`
  → `Ineligible`; null `arrived/valid_until` → `null` (no crash).
- **ViewModel state:** `ReferralViewModel`/`AffiliateViewModel` hold domain models
  directly inside `Content`; tests assert the full `Loading → Content/Error`
  ordering, `isEmpty` derivation (`total_referrals == 0`, zero conversions), and
  `isRefreshing` toggling without dropping `Content` (refresh preserves content;
  refresh failure keeps `Content` and emits an error effect, not an `Error` state).
- **Paging:** `AffiliateConversion`/`PromoCode` cursor pages map preserving server
  order; `next_cursor` threaded into the next `LoadParams.Append`; `nextKey == null`
  on the terminal page; `cachedIn(viewModelScope)` so snapshots are stable.
- **Saved state:** only the non-sensitive `AffiliateTab` enum is persisted; the last
  successful overview is re-fetched on re-creation. Restoration test rebuilds the VM
  from the same `SavedStateHandle` and asserts the persisted tab.
- **Stale/cache:** Referrals/Discounts use a single-row Room cache; the stale test
  seeds in-memory Room, fails the `MockWebServer` response (socket disconnect), and
  asserts `Content(isStale = true)`; with no cache, a retryable `Error`.

## 7. Error Handling & Resilience

Tested production behaviors (assertions in repository/ViewModel tests):

- **Timeout:** `MockWebServer.setBodyDelay(25, SECONDS)` against a shortened read
  timeout → `ApiResult` network/timeout error → `Error(retryable = true)` (or stale
  if cache present). Uses a short-timeout client to stay fast.
- **401 → refresh once:** Enqueue `401`, then `200` for `session/refresh`, then
  `200` for the retried GET; assert exactly **one** refresh request recorded and a
  final `Content`. A second `401` surfaces as `SessionExpired`/`Error` (no loop).
- **Bounded backoff:** Enqueue `503` twice then `200` for an idempotent GET
  (`/ui/referrals`, `/ui/affiliates/summary`, conversions, promo list); assert
  success after retries and that the retry count never exceeds the configured cap.
  Non-idempotent `POST` (create/redeem) is **not** retried — asserted.
- **Malformed JSON:** wrong-typed body → `ApiResult` parse error, not a crash.
- **Paging error:** a failing `load` returns `LoadResult.Error`; the UI exposes a
  retry affordance (asserted via the append-error state in the Compose test).
- **`detail` mapping:** parameterized JUnit test over the three `detail` shapes →
  expected typed error + `retryable` flag (FR-10).
- **Effect loss:** assert one-shot effects are delivered exactly once and not
  re-fired across a simulated config change / re-collection.

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf` cookie
  value on outgoing referral/affiliate/promo requests (validates the AND-027 CSRF
  interceptor is in the chain for these features).
- Tests assert the persistent cookie jar replays the session cookie across a
  second request on the same `MockWebServer` instance.
- Tests assert that the referral URL/code, earnings amounts, and promo code strings
  are **not** emitted at non-debug log levels, and never appear in analytics
  payloads (only event names/categories/counts) — via a capturing log tree and a
  `FakeAnalytics`. The referral link, if logged at DEBUG, is redacted to its code
  suffix (`…/r/AB12CD`).
- No secrets, real credentials, or the production/dev host appear in fixtures or
  test config; the dev host `18.222.237.167` is never contacted. Fixture URLs,
  codes, ids, and amounts are synthetic.
- Share/clipboard effect tests assert only the referral URL + app-supplied marketing
  text are placed into the intent — no cookies, tokens, user id, or other PII.

## 9. Accessibility & i18n

- **A11y (Compose tests):** each state test asserts meaningful semantics — metric
  tiles use `mergeDescendants` so TalkBack reads "Signups, 5" as one node; Share /
  Copy / Retry buttons expose `contentDescription`s and meet the 48dp touch target;
  discount/conversion rows expose a combined semantics description (code/amount +
  status + date); the stale banner is announced; the referral link field is
  announced as selectable text and the copy action announces "Referral link copied".
- **i18n:** tests assert no hardcoded user-facing strings — all copy resolves via
  `stringResource`/`pluralStringResource`; amounts format through a locale-aware
  formatter from raw minor-units + ISO currency code. A `Locale.GERMANY` UI test
  asserts amounts render with locale grouping/decimal separators and the configured
  currency symbol (guards against `String.format` hardcoding); dates render via a
  locale-aware formatter under the fixed clock. RTL readiness is smoke-checked by
  rendering one screen with a forced RTL layout direction.

## 10. Telemetry & Logging

- A `FakeAnalytics` (from `core-testing`) is injected/observed; tests assert the
  ViewModels emit `referral_overview_viewed`, `referral_link_copied`,
  `referral_link_shared`, `affiliate_dashboard_viewed`,
  `affiliate_tab_selected { tab }`, and `referral_load_failed { reason, retryable }`
  (plus promo/discount equivalents), and that they do **not** double-log on
  retry/cancellation.
- A test installs a capturing `Timber`/project-logger tree and asserts error paths
  log at `WARN`/`ERROR` with the FastAPI error *category* (not raw `detail` that may
  echo identifiers) and without cookies, full referral URLs, codes, or amounts.

## 11. Testing Strategy

This ticket *is* the testing-strategy deliverable. Concrete test classes:

- `feature-referrals/src/test/.../ReferralsApiMappingTest.kt` — MockWebServer +
  real Moshi/Retrofit: FR-1 (snake_case, null stats → zeros, null rewards hidden,
  `enabled=false` → ineligible), malformed JSON.
- `feature-referrals/src/test/.../ReferralViewModelTest.kt` — Turbine + Fake repo +
  `MainDispatcherRule`: FR-2 ordering, `isEmpty`, refresh-preserves-content,
  refresh-failure-keeps-content, retry; FR-3 effects (copy/share, exactly once);
  FR-4 in-flight guard (call count == 1); §10 telemetry.
- `feature-referrals/src/test/.../ReferralsRepositoryStaleTest.kt` — in-memory Room,
  FR-12 offline/stale + no-cache error.
- `feature-affiliates/src/test/.../AffiliateApiMappingTest.kt` — summary +
  conversions decode, cursor/query params, `X-CSRF-Token` (FR-5/FR-6/§8).
- `feature-affiliates/src/test/.../AffiliateConversionsPagingTest.kt` —
  `TestPager`/`PagingSource.load`: FR-6 keys, order, terminal page, append-error.
- `feature-affiliates/src/test/.../AffiliateViewModelTest.kt` — FR-5 states, empty,
  retry, `conversions` snapshot; FR-7 `SavedStateHandle` tab restoration;
  `affiliate_tab_selected` analytics.
- `feature-affiliates/src/test/.../AffiliateDiscountsMappingTest.kt` — FR-9 discount
  decode/map (value/scope/validity/link), null validity.
- `feature-promo/src/test/.../PromoCodesApiTest.kt` — FR-8 list (paged), create
  (`POST`), redeem (`POST`); validation-error mapping; POST **not** retried (FR-11).
- `feature-*/src/test/.../E36ErrorMappingTest.kt` — parameterized FastAPI `detail`
  (FR-10), timeout, 401-single-refresh-retry, bounded 503 backoff (FR-11), shared
  across features via `core-testing` helpers.
- `feature-referrals/src/androidTest/.../ReferralsScreenTest.kt`,
  `feature-affiliates/src/androidTest/.../AffiliatesScreenTest.kt` &
  `.../DiscountsScreenTest.kt`, `feature-promo/src/androidTest/.../PromoScreenTest.kt`
  (or Robolectric) — FR-13: one test per state, a11y semantics, share-intent build,
  German-locale formatting (§9); one `@HiltAndroidTest` instrumented smoke test per
  module asserting the link + at least the core stat tiles render (AND-264 bar).

Tooling: JUnit4, `kotlinx-coroutines-test`, Turbine, MockWebServer, Truth (or JUnit
assertions), Compose UI Test, Paging 3 testing artifact, Robolectric (for JVM
Compose), Room in-memory, `core-testing` fakes/rules (`MainDispatcherRule`,
`FakeReferralRepository`, `FakeAffiliateRepository`, `FakePromoCodesRepository`,
`FakeAnalytics`, Paging + Room/DataStore helpers). KSP test processors only for the
Hilt instrumented smoke tests; ViewModel tests construct the VM directly to stay fast.

Coverage target: every public method of each E36 repository and ViewModel, every
`UiState` branch, every DTO field/null path, and every screen state exercised;
ViewModel line coverage ≥ 90%. No flakiness: controlled clock/dispatchers, no
`Thread.sleep`, no real I/O.

## 12. Dependencies & Sequencing

- **Hard dep — AND-268** (ViewModels + UiState/Intent/Effect contracts): provides
  the types the ViewModel/UI tests assert against; must merge first.
- **Hard deps — AND-264/265/266/267:** provide the APIs, DTOs, repositories, Room
  cache, and Compose screens under test. Each ticket's merge gates its test classes;
  a not-yet-merged surface means its test file is added but `@Ignore`d with a linked
  follow-up rather than blocking the rest of the suite.
- **Transitively — AND-027:** core-network (authenticated client, cookie jar, CSRF
  interceptor, refresh-on-401, `ApiResult` + shared `detail` mapper).
- **Shared infra — `core-testing`:** must expose `MainDispatcherRule`, the feature
  fakes, `FakeAnalytics`, Paging test helpers, and in-memory Room/DataStore helpers;
  any missing helper is added here in `core-testing` (reused across feature suites,
  no duplication in feature modules).
- **Sequencing within ticket:** (1) add/confirm `core-testing` fakes & fixtures →
  (2) repository/mapping/network tests → (3) ViewModel tests → (4) paging tests →
  (5) Compose UI + a11y/locale tests → (6) wire into CI test tasks.
- **Blocks:** none recorded; this ticket gates the E36 (M6) "done" definition by
  proving the Referrals/Affiliates epic is regression-protected.

## 13. Risks & Open Questions

- **R-1 (signature/field drift):** field names (`reward_credits` vs `rewardCredits`,
  `amount_cents` vs `amount_minor`, cursor `next_cursor` vs `next`) and endpoint
  paths (`/ui/referrals` vs `/ui/me/referrals`) are inferred from the web reference
  and AND-264/265 §5. **Open:** reconcile fixtures with `/openapi.json` before merge.
  *Mitigation:* a contract test that diffs fixture keys against a committed OpenAPI
  snapshot; DTO `@Json` rename is a one-line change.
- **R-2 (overview vs referrals shape):** AND-264 returns `Referral` (`stats`) while
  AND-268 assumes a `ReferralOverview` with `stats.totalReferrals`. **Open:** confirm
  the merged domain shape with the AND-264/AND-268 owners; align `isEmpty` derivation
  before asserting (single place to update).
- **R-3 (paging vs simple list):** whether affiliate conversions / promo lists use
  Paging 3 cursors or a bounded list affects FR-6/FR-8 assertions. Assume Paging 3
  cursor; demote to list-based assertions if implemented otherwise.
- **R-4 (effect channel vs shared flow):** AND-264 uses `MutableSharedFlow`
  (`ReferralsEvent`) while AND-268 uses a `Channel`-backed effect flow. Tests target
  the merged ViewModel's exposed type; confirm which lands and assert exactly-once
  delivery accordingly.
- **R-5 (entitlement gating):** open question (AND-268 Q1) whether affiliate features
  are gated by a `/ui/me` entitlement flag → a `NotEligible` state. If added, a
  rendering + state test is appended; otherwise dropped from scope.
- **R-6 (Robolectric vs emulator):** if any Compose rendering needs a real GPU
  canvas, demote that case to instrumented-only and keep state/semantics tests on
  Robolectric.

## 14. Acceptance Criteria

The backlog acceptance is "Pass." Operationalized:

- **AC-1:** `./gradlew :feature-referrals:testDebugUnitTest
  :feature-affiliates:testDebugUnitTest :feature-promo:testDebugUnitTest` passes with
  all §11 classes present and green; zero ignored (except deferred-with-ticket)/flaky.
- **AC-2:** The Compose UI task (`connectedDebugAndroidTest` or Robolectric) passes
  for `ReferralsScreenTest`, `AffiliatesScreenTest`, `DiscountsScreenTest`,
  `PromoScreenTest`.
- **AC-3:** Mapping tests prove FR-1, FR-5, FR-9 (null/empty paths included) and that
  malformed JSON yields a parse error, not a crash.
- **AC-4:** ViewModel tests prove FR-2 (full ordering, `isEmpty`, refresh-preserves
  & refresh-failure-keeps content), FR-3 (effects exactly once), FR-4 (repo called
  once under concurrent load), FR-7 (tab restoration).
- **AC-5:** Paging tests prove FR-6 (`next_cursor` threading, order, terminal page,
  append-error) for affiliate conversions and the promo list.
- **AC-6:** Promo tests prove FR-8 create + list (MVP) plus redeem, with validation
  errors mapped and POST not retried.
- **AC-7:** Error/resilience tests prove FR-10 (all three `detail` shapes + retryable
  flag), timeout, 401→single-refresh→retry with exactly one refresh request, and
  bounded 503 backoff (FR-11).
- **AC-8:** Stale/offline tests prove `Content(isStale=true)` with cache and a
  retryable `Error` without (FR-12).
- **AC-9:** Compose tests prove rendering of every state (FR-13), row/tile a11y
  semantics, the share `ACTION_SEND`/`text/plain` intent build, and German-locale
  amount formatting (§9).
- **AC-10:** Security assertions confirm `X-CSRF-Token` echoes `ui_csrf`, the cookie
  jar replays the session, and no referral URL/code/earnings/promo strings or cookies
  are logged or sent to analytics (§8, §10).
- **AC-11:** Suite is hermetic: no live network, controlled clock/dispatchers, no
  `Thread.sleep`; CI run on `android-port` is green.

## 15. Definition of Done

- All §11 test classes implemented under `com.testlogon.android` package paths in
  `feature-referrals`, `feature-affiliates`, and `feature-promo`, compiling against
  the merged AND-264/265/266/267/268 signatures.
- AC-1 through AC-11 satisfied; suite green locally and in CI on the `android-port`
  branch with the project toolchain (Kotlin 2.0.21, AGP 8.7.3, JDK 17, Gradle 8.9,
  compileSdk 35).
- Required `core-testing` fakes/rules/Paging/Room helpers added or confirmed present
  and reused (no duplication in feature modules).
- Fixtures stored under `src/test/resources/fixtures/{referrals,affiliates,promo,
  discounts}/` and validated against `/openapi.json` (R-1 closed or explicitly
  deferred with an owner and a linked follow-up ticket).
- No new ktlint/detekt/Android Lint violations; KSP test processors build cleanly;
  no live dev host (`18.222.237.167`) contacted by any test.
- Open questions R-1..R-6 resolved or filed as follow-ups and linked; any
  surface-not-yet-merged test files are `@Ignore`d with a referenced ticket.
- Code reviewed and merged; CI badge green; spec status moved `draft` → `accepted`.
