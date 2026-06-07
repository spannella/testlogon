---
id: AND-269
title: Referrals/affiliates tests
milestone: M6
epic: E36
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

- **FR-1 (Referral mapping):** A well-formed `GET /ui/referrals/dashboard` body
  (`ReferralDashboardStats`) deserializes into the referral DTO and maps to the
  referral domain model. **[CORRECTED]** Verified field names are
  `total_referrals`, `confirmed_referrals`, `pending_referrals`,
  `total_earned_cents`, `pending_commission_cents`, `paid_commission_cents`,
  `available_for_withdrawal_cents`, and a `referral_codes: ReferralCode[]` array
  (each code: `code`, `active`, `commission_tier`, `referral_count?`,
  `created_at` ISO string). There is **no** top-level `link`/`code`/`enabled`/
  `stats` object on the dashboard payload (those were inferred and are wrong); the
  shareable link is produced by `POST /ui/referrals/code` →
  `ReferralCodeCreateResp { code, link, commission_tier, created_at }`. Tests
  assert: empty `referral_codes` → `Ineligible`/no-link state; `total_referrals == 0`
  → empty; absent optional `referral_count` → `null`/zero per the mapper; malformed
  body → parse error not crash.
- **FR-2 (Referral ViewModel states):** `ReferralViewModel` emits
  `Loading → Content` on success, `Loading → Error(retryable)` on transient failure,
  `Content(isEmpty = true)` when `total_referrals == 0` (verified field), and refresh preserves
  visible `Content` while toggling `isRefreshing` (no full-screen spinner flash).
- **FR-3 (Referral effects):** `CopyLink` emits `ReferralEffect.CopyToClipboard(url)`
  with the current referral URL; `ShareLink` emits
  `ReferralEffect.ShowShareSheet(text)`. Each effect is delivered exactly once.
- **FR-4 (In-flight guard):** A second `Load`/`Refresh` while a load is in flight
  calls the repository exactly once (FR-10 of AND-268).
- **FR-5 (Affiliate links mapping + states):** **[CORRECTED]** There is **no**
  `GET /ui/affiliates/summary` endpoint. The affiliates dashboard is link-based:
  `GET /ui/affiliates/links` → `AffiliateLinkListOut { links: AffiliateLinkOut[] }`,
  where each `AffiliateLinkOut` carries its own aggregate stats (`tracking_code`,
  `short_url`, `destination_url`, `commission_percent`, `status`, `click_count`,
  `unique_click_count`, `conversion_count`, `revenue_cents`,
  `commission_earned_cents`, `conversion_rate_pct`, `created_at`/`updated_at` epoch
  ints). Per-link detail/stats: `GET /ui/affiliates/links/{link_id}` and
  `GET /ui/affiliates/links/{link_id}/stats` (`AffiliateLinkStatsOut`). Any
  "summary" object the dashboard shows must be derived client-side by aggregating
  the `links` array. `AffiliateViewModel` emits `Loading → Content`/`Error` and
  `Content(isEmpty = true)` on an empty `links` array.
- **FR-6 (Affiliate paging):** **[CORRECTED]** There is **no**
  `GET /ui/affiliates/conversions?cursor=&limit=20` endpoint. The only cursor-paged
  feed in E36 is **referral commissions**: `GET /ui/referrals/commissions?limit=&cursor=`
  → `CommissionListResp { commissions: AffiliateCommission[], next_cursor }` (each
  `AffiliateCommission`: `source_type`, `referred_user_id`, `gross_amount_cents`,
  `net_amount_cents`, `commission_cents`, `commission_rate_bps`, `status`,
  `created_at` ISO string). This drives the cursor `PagingSource`; the Paging flow
  emits the expected item snapshot ordered as served, threads `next_cursor` into the
  next append (param name `cursor`, also `limit`), and surfaces `LoadResult.Error` on
  failure. `GET /ui/affiliates/links` is **not** paged. (Affiliate per-link
  conversions are *recorded* via `POST /ui/affiliates/links/{link_id}/conversions`,
  not listed via a cursor feed.)
- **FR-7 (Tab restoration):** The selected `AffiliateTab` is persisted/restored via
  `SavedStateHandle` across ViewModel re-creation.
- **FR-8 (Promo create/list/redeem):** `PromoCodesRepository` lists codes via
  `GET /ui/promo-codes` → `PromoCodeListOut { items: PromoCodeOut[], next_cursor }`,
  creates via `POST /ui/promo-codes` (`PromoCodeCreateIn` → **201** `PromoCodeOut`),
  and redeems via `POST /ui/promo-codes/redeem`; success/validation-error paths map
  to the correct `ApiResult`/UI state. Create + list is the must-pass MVP.
  **[CORRECTED]** The create body is **not** `{ code, discount_percent }`; verified
  `PromoCodeCreateIn` is `{ code (3–30 chars), discount_type:
  "percentage"|"fixed_amount"|"free_trial", discount_value?, free_trial_days?,
  applies_to?: string[], min_purchase_cents?, max_uses?, max_uses_per_user?,
  expires_at? (epoch int) }` (required: `code`, `discount_type`). `PromoCodeOut`
  carries `code_id`, `code`, `discount_type`, `current_uses`, `active`, etc. The
  redeem body is **not** `{ code }`; verified `POST /ui/promo-codes/redeem` body is
  `{ code_id, original_price_cents, final_price_cents, checkout_type,
  checkout_item_id? }`. A separate `POST /ui/promo-codes/validate` (`PromoValidateIn`
  → `PromoValidateOut { valid, code_id, discount_type, discount_cents,
  final_price_cents, free_trial_days, message }`) covers pre-checkout validation.
- **FR-9 (Discounts mapping + render):** Affiliate discount offers come from
  `GET /ui/ads/affiliate/discounts` → `AdAffiliateDiscountListOut { items:
  AdAffiliateDiscountOut[] }` and map to the discount domain model; the Discounts
  screen renders the list, empty, and offline states. **[CORRECTED]** Verified
  `AdAffiliateDiscountOut` fields are `creative_id`, `campaign_id`, `owner_sub`
  (required), plus nullable `affiliate_code`, `promo_code`, `promo_value_display`
  (a display **string**, not a numeric value), `click_through_url`, and counters
  `click_count`/`redemption_count`, with `created_at`/`updated_at` epoch ints.
  There are **no** `value`/`scope`/`valid_from`/`valid_until`/`link` fields — those
  were inferred and are wrong; the displayed offer value is `promo_value_display`
  and the click-out URL is `click_through_url`. Redemption is
  `POST /ui/ads/affiliate/redeem` (`AdAffiliateRedeemIn` → `AdAffiliateRedeemOut`).
- **FR-10 (Error mapping):** FastAPI `detail` in all three shapes (`string` |
  `[{msg}]` | object) maps to a typed `ApiError`/`ApiResult.Error` carrying a
  user-facing message and a `retryable` flag (network/timeout/5xx retryable; 4xx
  validation not retryable). **[VERIFIED w/ caveat]** The web `normalizeErrorDetail`
  handles `string`, an array of `{msg}` (joined with ", "), and object `detail` via
  `mapAuthorizationError` (recognizes `code: role_required* | helpdesk_* |
  geo_blocked`) or a bare `{msg}` object; a generic `{code, message}` that matches
  none of those known codes falls back to the caller's fallback string (it does
  **not** auto-surface `message`). The Android mapper should therefore read `message`
  explicitly for object-shaped `detail` (this is a deliberate Android-side
  improvement, flagged as an assumption, not copied from the web client).
- **FR-11 (Resilience):** A 401 triggers exactly one `POST /ui/session/refresh`
  then one retry; a ~20s timeout maps to a network error / stale fallback.
  **[VERIFIED — refresh]** The web client (`client.ts`) performs exactly one
  refresh-and-retry on 401 (the retry replays the same method, incl. POST), and a
  second 401 calls `logout("session_expired")`. **[ASSUMPTION — backoff]** The web
  reference has **no** automatic 5xx/503 backoff-retry (only the 401 path retries);
  the "bounded 503 backoff on idempotent GETs" and the "POST not backoff-retried"
  rules are Android-side resilience behavior assumed from AND-027, not verifiable
  against the web client. Tests still assert them against the Android client's own
  config but the spec marks them as an assumption pending AND-027 confirmation.
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

**[CORRECTED]** The illustrative signatures below were realigned to the verified
contract: referrals are a *dashboard* (counters + `referral_codes[]`), affiliates
are a *list of links* (no summary endpoint), and the only cursor-paged feed is
referral commissions. `*_cents` are integers (the API uses cents, not generic
"minor units"); commission `created_at` is an ISO-8601 string, link/promo/discount
timestamps are epoch-second integers.

```kotlin
// core-model (AND-264 / AND-268) — names mirror the verified DTO fields
data class ReferralCode(val code: String, val active: Boolean, val commissionTier: String,
                        val referralCount: Int?, val createdAt: Instant)
data class ReferralDashboard(val totalReferrals: Int, val confirmedReferrals: Int,
                             val pendingReferrals: Int, val totalEarnedCents: Long,
                             val pendingCommissionCents: Long, val paidCommissionCents: Long,
                             val availableForWithdrawalCents: Long, val codes: List<ReferralCode>)
data class AffiliateLink(val linkId: String, val trackingCode: String, val shortUrl: String,
                         val destinationUrl: String, val commissionPercent: Double, val status: String,
                         val clickCount: Int, val uniqueClickCount: Int, val conversionCount: Int,
                         val revenueCents: Long, val commissionEarnedCents: Long, val conversionRatePct: Double)
data class ReferralCommission(val sourceType: String, val referredUserId: String,
                              val grossAmountCents: Long, val netAmountCents: Long,
                              val commissionCents: Long, val commissionRateBps: Int,
                              val status: String, val createdAt: Instant)

// feature ViewModels (AND-268)
sealed interface ReferralUiState { /* Loading; Content(overview,isEmpty,isRefreshing); Error(message,retryable) */ }
sealed interface ReferralIntent  { /* Load; Refresh; Retry; CopyLink; ShareLink */ }
sealed interface ReferralEffect  { data class CopyToClipboard(val url: String); data class ShowShareSheet(val shareText: String) }
sealed interface AffiliateUiState { /* Loading; Content(summary,isRefreshing); Error(message,retryable) */ }
enum class AffiliateTab { Overview, Conversions }

// repositories
interface ReferralRepository {
    suspend fun getReferralDashboard(): ApiResult<ReferralDashboard>      // GET /ui/referrals/dashboard
    suspend fun getAffiliateLinks(): ApiResult<List<AffiliateLink>>       // GET /ui/affiliates/links
    fun commissionsPager(): Pager<String, ReferralCommission>            // GET /ui/referrals/commissions (cursor)
}
interface PromoCodesRepository {
    fun listPagingSource(): PagingSource<String, PromoCode>               // GET /ui/promo-codes (next_cursor)
    suspend fun create(req: PromoCodeCreateIn): ApiResult<PromoCode>      // POST /ui/promo-codes -> 201 PromoCodeOut
    suspend fun redeem(req: PromoRedeemIn): ApiResult<PromoRedemption>    // POST /ui/promo-codes/redeem ({code_id, ...})
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
AND-264/265/266/267. The shapes below are the fixture basis, **corrected against the
OpenAPI index/spec and the frontend `src/api/endpoints/*`**; all requests are
authenticated. **[VERIFIED auth]** The web client sends `Authorization: Bearer
<accessToken>` + an `X-CSRF-Token` header copied from the `ui_csrf` cookie + the
session cookie (`credentials: include`), and performs a single
`POST /ui/session/refresh` then one retry on 401 (second 401 → logout). The Android
client mirrors this (cookies + `X-CSRF-Token`). The dev-host OpenAPI also lists
`user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` params on these routes;
mobile uses the cookie/CSRF/bearer path, and impersonation is out of scope.

`GET /ui/referrals/dashboard` → (`ReferralDashboardStats`)
```json
{ "total_referrals": 12, "confirmed_referrals": 5, "pending_referrals": 7,
  "total_earned_cents": 4000, "pending_commission_cents": 1000,
  "paid_commission_cents": 3000, "available_for_withdrawal_cents": 2500,
  "referral_codes": [ { "code": "AB12CD", "active": true,
    "commission_tier": "standard", "referral_count": 5,
    "created_at": "2026-06-01T09:00:00Z" } ] }
```
The shareable link is created via `POST /ui/referrals/code` →
`{ "code": "AB12CD", "link": "https://testlogon.app/r/AB12CD",
   "commission_tier": "standard", "created_at": "..." }`.

`GET /ui/affiliates/links` → (`AffiliateLinkListOut`, **not** paged, **no** summary endpoint)
```json
{ "links": [ { "link_id": "al_01H...", "tracking_code": "TRK123",
    "short_url": "https://tl.app/a/TRK123", "destination_url": "https://...",
    "commission_percent": 10.0, "status": "active", "click_count": 184,
    "unique_click_count": 150, "conversion_count": 9, "revenue_cents": 12000,
    "commission_earned_cents": 1200, "conversion_rate_pct": 4.9,
    "created_at": 1717230000, "updated_at": 1717233600 } ] }
```

`GET /ui/referrals/commissions?limit=20&cursor=` (cursor-paged; the **only** cursor
feed in E36) → (`CommissionListResp`)
```json
{ "commissions": [ { "source_type": "subscription",
    "referred_user_id": "u_01H...", "gross_amount_cents": 1500,
    "net_amount_cents": 1400, "commission_cents": 150,
    "commission_rate_bps": 1000, "status": "pending",
    "created_at": "2026-06-01T09:00:00Z" } ],
  "next_cursor": "eyJjcmVhdGVkX2F0..." }
```

`GET /ui/promo-codes` → `PromoCodeListOut { items: PromoCodeOut[], next_cursor }`;
`POST /ui/promo-codes` (create → **201** `PromoCodeOut`) body
`{ "code": "SUMMER", "discount_type": "percentage", "discount_value": 10,
   "applies_to": ["subscription"], "max_uses": 100, "expires_at": 0 }`;
`POST /ui/promo-codes/redeem` body
`{ "code_id": "pc_01H...", "original_price_cents": 1000,
   "final_price_cents": 900, "checkout_type": "shop" }`; and (pre-checkout)
`POST /ui/promo-codes/validate` (`PromoValidateIn` → `PromoValidateOut`).
**Note:** create body uses `discount_type`/`discount_value`, **not**
`discount_percent`; redeem keys on `code_id` + price fields, **not** `{ code }`.

Affiliate discounts → `GET /ui/ads/affiliate/discounts` →
`AdAffiliateDiscountListOut { items: AdAffiliateDiscountOut[] }`; each offer:
```json
{ "creative_id": "cr_01H...", "campaign_id": "cmp_01H...", "owner_sub": "u_01H...",
  "affiliate_code": "AFF50", "promo_code": "SAVE10",
  "promo_value_display": "10% off", "click_through_url": "https://...",
  "click_count": 42, "redemption_count": 7,
  "created_at": 1717230000, "updated_at": 1717233600 }
```
**Note:** fields are `promo_value_display` (display **string**) and
`click_through_url`; there is **no** `value`/`scope`/`valid_from`/`valid_until`/
`link`. Redemption is `POST /ui/ads/affiliate/redeem`.

FastAPI error envelope, tested in all three `detail` shapes (**verified** against
`normalizeErrorDetail` in `src/api/client.ts`):
```json
{ "detail": "Referral program not available" }
{ "detail": [ { "loc": ["body","code"], "msg": "code already exists", "type": "value_error" } ] }
{ "detail": { "code": "PROMO_EXPIRED", "message": "promo code expired" } }
```
**[VERIFIED w/ caveat]** The web mapper resolves `string` directly, joins an array's
`{msg}` values, and for object `detail` only special-cases known `code`s
(`role_required*`, `helpdesk_*`, `geo_blocked`) or a `{msg}` object — a generic
`{code, message}` like `PROMO_EXPIRED` falls back to the caller fallback unless the
mapper is extended. The Android mapper reads `message`/`msg` for object `detail`
explicitly (assumption; see §16). 422 validation `detail` is the array shape above.

Tests assert: query params (`cursor`, `limit`), `X-CSRF-Token` header presence and
equality with the `ui_csrf` cookie value (**verified**: header is set from that
cookie in `client.ts`), cursor threading (`next_cursor` → `cursor`),
status-string preservation, and that each error body maps to the expected typed
error / `retryable` flag.

## 6. Data & State Management

The suite verifies the data/state contract rather than introducing it.

- **DTO→domain:** Moshi adapters parse `@Json(name = "...")` snake_case fields;
  verified cents fields (`total_earned_cents`, `*_commission_cents`,
  `revenue_cents`, `commission_earned_cents`, `gross_amount_cents`,
  `net_amount_cents`, `commission_cents`, `discount_cents`) decode as `Long` (no
  float rounding). **[CORRECTED]** Timestamps are mixed: commission/referral-item
  `created_at`/`attributed_at` are ISO-8601 strings (→ `InstantAdapter`), while
  link/promo/discount `created_at`/`updated_at`/`expires_at` are epoch-second
  integers (→ a numeric epoch adapter). Tests assert: empty `referral_codes` →
  `Ineligible`/no-link; `total_referrals == 0` → empty; nullable discount fields
  (`affiliate_code`/`promo_code`/`promo_value_display`/`click_through_url`) → `null`
  (no crash). (There is no `stats`/`enabled`/`reward_credits`/`valid_until` field in
  the real contract — see §5/§16.)
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
  (`/ui/referrals/dashboard`, `/ui/affiliates/links`, `/ui/referrals/commissions`,
  `/ui/promo-codes`); assert success after retries and that the retry count never
  exceeds the configured cap. Non-idempotent `POST` (create/redeem) is **not**
  backoff-retried — asserted. **[ASSUMPTION]** This 5xx backoff is Android/AND-027
  behavior; the web reference performs **no** 5xx retry (only the 401 refresh
  retry, which does replay POSTs). Validate against AND-027 before relying on it.
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

- **R-1 (signature/field drift):** **[RESOLVED in this review]** The endpoint paths
  and field names were reconciled against the OpenAPI index and
  `src/api/endpoints/*` — see §5/§16 for the corrections (`/ui/referrals/dashboard`
  not `/ui/referrals`; `/ui/affiliates/links` not `/ui/affiliates/summary`;
  `/ui/referrals/commissions` not `/ui/affiliates/conversions`; cents not "minor";
  `discount_type`/`discount_value` not `discount_percent`; `next_cursor` is
  confirmed). *Mitigation retained:* a contract test that diffs fixture keys against
  a committed OpenAPI snapshot; DTO `@Json` rename is a one-line change.
- **R-2 (dashboard vs codes shape):** **[RESOLVED]** `GET /ui/referrals/dashboard`
  returns counters (`total_referrals`, etc.) plus `referral_codes[]`; the share link
  comes from `POST /ui/referrals/code`. `isEmpty` derives from
  `total_referrals == 0`; the no-link/`Ineligible` state derives from an empty
  `referral_codes`. Confirm the merged domain wrapper name with AND-264/AND-268
  owners (single place to update).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Referral dashboard endpoint is `GET /ui/referrals/dashboard`.** Verdict:
   **Corrected** (spec said `GET /ui/referrals`). Source: OpenAPI
   `GET /ui/referrals/dashboard` (op `dashboard_ui_referrals_dashboard_get`);
   `src/api/endpoints/referrals.ts: getReferralDashboard`.
2. **Referral dashboard shape = counters + `referral_codes[]`** (`total_referrals`,
   `confirmed_referrals`, `pending_referrals`, `total_earned_cents`,
   `pending_commission_cents`, `paid_commission_cents`,
   `available_for_withdrawal_cents`, `referral_codes`). Verdict: **Corrected** (spec
   claimed `{link, code, enabled, stats:{invites_sent,...,reward_credits}}`). Source:
   `src/api/types.ts: ReferralDashboardStats` and `ReferralCode`.
3. **Share link comes from `POST /ui/referrals/code` → `{code, link,
   commission_tier, created_at}`.** Verdict: **Corrected/added** (spec put `link` on
   the GET). Source: OpenAPI `POST /ui/referrals/code`;
   `src/api/types.ts: ReferralCodeCreateResp`; `referrals.ts: createReferralCode`.
4. **Cursor-paged feed is `GET /ui/referrals/commissions?limit=&cursor=` →
   `CommissionListResp {commissions, next_cursor}`.** Verdict: **Corrected** (spec
   used `GET /ui/affiliates/conversions`). Source: OpenAPI
   `GET /ui/referrals/commissions | params=limit,cursor`;
   `src/api/types.ts: CommissionListResp`, `AffiliateCommission`;
   `referrals.ts: getReferralCommissions`.
5. **`AffiliateCommission` fields** (`source_type`, `referred_user_id`,
   `gross_amount_cents`, `net_amount_cents`, `commission_cents`,
   `commission_rate_bps`, `status`, `created_at` ISO string). Verdict: **Verified**.
   Source: `src/api/types.ts: AffiliateCommission`.
6. **No `GET /ui/affiliates/summary` exists; affiliates dashboard = `GET
   /ui/affiliates/links` → `{links: AffiliateLinkOut[]}` with per-link aggregate
   stats.** Verdict: **Corrected**. Source: OpenAPI `GET /ui/affiliates/links`
   (op `list_links_...`); `src/api/endpoints/affiliates.ts:
   listAffiliateLinks`, `AffiliateLinkOut`, `AffiliateLinkListOut`.
7. **`AffiliateLinkOut` fields** (`link_id`, `tracking_code`, `short_url`,
   `destination_url`, `commission_percent`, `status`, `click_count`,
   `unique_click_count`, `conversion_count`, `revenue_cents`,
   `commission_earned_cents`, `conversion_rate_pct`, `created_at`/`updated_at`
   epoch ints). Verdict: **Verified**. Source: `affiliates.ts: AffiliateLinkOut`.
8. **No `GET /ui/affiliates/conversions` cursor feed; per-link conversions are
   recorded via `POST /ui/affiliates/links/{link_id}/conversions`, and per-link
   stats via `GET /ui/affiliates/links/{link_id}/stats`.** Verdict: **Corrected**.
   Source: OpenAPI `POST /ui/affiliates/links/{link_id}/conversions` and
   `GET /ui/affiliates/links/{link_id}/stats`; `affiliates.ts: getAffiliateLinkStats`.
9. **`amount_cents`/"earnings minor-units"/`currency` on affiliate items.** Verdict:
   **Corrected** — fields are `*_cents` integers (revenue/commission); there is no
   per-item `currency` field on links/commissions. Source: `types.ts: AffiliateLink*`,
   `AffiliateCommission`.
10. **Promo list = `GET /ui/promo-codes` → `PromoCodeListOut {items, next_cursor}`.**
    Verdict: **Verified** (path; the spec's `?cursor=&limit=20` query is **Corrected**
    — the web client calls it with no params, though `next_cursor` is returned).
    Source: OpenAPI `GET /ui/promo-codes` (resp `PromoCodeListOut`);
    `promoCodes.ts: listPromoCodes`; `openapi schemas.PromoCodeListOut`.
11. **Promo create = `POST /ui/promo-codes` → 201 `PromoCodeOut`, body
    `PromoCodeCreateIn {code, discount_type, discount_value?, ...}`.** Verdict:
    **Corrected** (spec said body `{code, discount_percent}`). Source:
    `schemas.PromoCodeCreateIn` (required `code`,`discount_type`; enum
    `percentage|fixed_amount|free_trial`); `promoCodes.ts: createPromoCode`;
    OpenAPI `POST /ui/promo-codes | resp=201:PromoCodeOut`.
12. **`PromoCodeOut` includes `code_id`, `current_uses`, `active`.** Verdict:
    **Verified**. Source: `schemas.PromoCodeOut` (required `code_id`,`code`,
    `discount_type`).
13. **Promo redeem = `POST /ui/promo-codes/redeem` body `{code_id,
    original_price_cents, final_price_cents, checkout_type, checkout_item_id?}`.**
    Verdict: **Corrected** (spec said body `{code}`). Source:
    `promoCodes.ts: redeemPromoCode`; OpenAPI `POST /ui/promo-codes/redeem`.
14. **Pre-checkout validation = `POST /ui/promo-codes/validate` (`PromoValidateIn`
    → `PromoValidateOut`).** Verdict: **Verified/added**. Source: OpenAPI
    `POST /ui/promo-codes/validate`; `types.ts: PromoValidateOut`;
    `promoCodes.ts: validatePromoCode`.
15. **Affiliate discounts = `GET /ui/ads/affiliate/discounts` →
    `AdAffiliateDiscountListOut {items: AdAffiliateDiscountOut[]}`.** Verdict:
    **Verified** (path/wrapper). Source: OpenAPI `GET /ui/ads/affiliate/discounts`;
    `adCreativeAffiliate.ts: listAdAffiliateDiscounts`;
    `schemas.AdAffiliateDiscountListOut`.
16. **`AdAffiliateDiscountOut` fields = `creative_id`, `campaign_id`, `owner_sub`,
    nullable `affiliate_code`/`promo_code`/`promo_value_display`/`click_through_url`,
    `click_count`/`redemption_count`, `created_at`/`updated_at` epoch ints.**
    Verdict: **Corrected** (spec claimed `code`, `value`(percent/amount_cents),
    `scope`, `valid_from`/`valid_until`, `link`). Source:
    `schemas.AdAffiliateDiscountOut`; `types.ts: AdAffiliateDiscount`.
17. **Discount redemption = `POST /ui/ads/affiliate/redeem` (`AdAffiliateRedeemIn`
    → `AdAffiliateRedeemOut`).** Verdict: **Verified**. Source: OpenAPI
    `POST /ui/ads/affiliate/redeem`; `schemas.AdAffiliateRedeemIn`;
    `adCreativeAffiliate.ts: redeemAdAffiliateDiscount`.
18. **CSRF: `X-CSRF-Token` header is set from the `ui_csrf` cookie on every
    request.** Verdict: **Verified**. Source: `src/api/client.ts` (`getCookie
    ("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, lines ~167–171).
19. **401 → single `POST /ui/session/refresh` then exactly one retry; a second 401
    triggers logout(`session_expired`).** Verdict: **Verified**. Source:
    `client.ts: refreshSession` + the 401 branch (single `refreshPromise`, one
    `retryRes`, `logout("session_expired")` on retry 401, lines ~119–237).
20. **FastAPI `detail` three shapes (string | `[{msg}]` | object) map to a typed
    error.** Verdict: **Verified (w/ caveat)**. Source: `client.ts:
    normalizeErrorDetail` + `mapAuthorizationError`. Caveat: object `detail` is only
    auto-messaged for known `code`s or a `{msg}` object; a generic `{code, message}`
    falls back unless the mapper reads `message` (Android extension — assumption).
21. **Bearer auth + cookie session (`credentials: include`).** Verdict: **Verified**.
    Source: `client.ts` (`Authorization: Bearer <accessToken>`, `credentials:
    "include"`). Note the OpenAPI routes also list `user_sub`/`X-SESSION-ID`/
    `X-IMPERSONATION-TOKEN`; mobile uses the cookie+CSRF+bearer path.
22. **Bounded 5xx/503 backoff retry on idempotent GETs; POST not backoff-retried.**
    Verdict: **Unverified-assumption**. The web client performs **no** 5xx retry
    (only the 401 refresh retry, which replays POSTs too). Treated as AND-027/
    Android-side behavior. Source (negative): `client.ts` has no 5xx retry branch.
23. **Test frameworks/targets** (JUnit4, kotlinx-coroutines-test, Turbine,
    MockWebServer, Compose UI Test, Paging 3 testing artifact, Robolectric, Room
    in-memory). Verdict: **Unverified-assumption** (framework choices; standard
    AndroidX testing stack). Source: framework ref —
    https://developer.android.com/training/testing , Paging test framework ref —
    https://developer.android.com/topic/libraries/architecture/paging/test ,
    Compose testing ref — https://developer.android.com/jetpack/compose/testing .
24. **Physical-device-only behaviors** (real clipboard/share `ACTION_SEND` chooser,
    API-34 vs API-35 rendering). Verdict: **Unverified-assumption** for device
    specifics; share-intent build itself is testable on emulator/Robolectric.
    Source: framework ref —
    https://developer.android.com/training/sharing/send (ACTION_SEND).

### Corrections made

- §3 FR-1, FR-5, FR-6, FR-8, FR-9, FR-10, FR-11; §4.1 model/repository signatures;
  §5 (all endpoint paths, JSON examples, auth note, error-envelope caveat); §6
  DTO/timestamp notes; §7 bounded-backoff caveat; §13 R-1/R-2 resolutions.
- Endpoint path fixes: `/ui/referrals` → `/ui/referrals/dashboard`;
  `/ui/affiliates/summary` (nonexistent) → `/ui/affiliates/links`;
  `/ui/affiliates/conversions` (nonexistent) → `/ui/referrals/commissions`.
- Field fixes: referral `stats/enabled/reward_credits` → dashboard counters +
  `referral_codes[]`; affiliate "minor-units"/`currency`/conversions → link
  `*_cents` aggregates; promo create `discount_percent` →
  `discount_type`/`discount_value`; promo redeem `{code}` → `{code_id, *_price_cents,
  checkout_type}`; discount `value/scope/valid_from/valid_until/link` →
  `promo_value_display`/`click_through_url` + counts; mixed ISO-string vs epoch-int
  timestamps clarified.

### Open assumptions

- **A-1 (5xx backoff):** bounded 503 backoff-retry and "POST not retried" are
  inferred from AND-027, not present in the web client (only 401 refresh retries).
  *Why:* no Android core-network source in the reference set; confirm with AND-027.
- **A-2 (object `detail` messaging):** Android mapper reading `message`/`code` from
  object `detail` for E36 errors (e.g. `PROMO_EXPIRED`) is an extension beyond the
  web `normalizeErrorDetail`. *Why:* web client falls back for unknown codes.
- **A-3 (cents → display currency):** the API returns `*_cents` integers with no
  per-item currency; locale-aware formatting assumes a single account currency.
  *Why:* no currency field on links/commissions/promo in the verified shapes.
- **A-4 (Kotlin domain wrapper names):** `ReferralDashboard`/`AffiliateLink`/
  `ReferralCommission`/`PromoCode`/`Discount` domain type names are illustrative;
  the actual AND-264/265/266/267/268 type names may differ. *Why:* Android source
  not in the reference set; tests are the tripwire.
- **A-5 (framework/test-target choices):** AndroidX test stack and device-vs-emulator
  routing are engineering choices (framework refs in §16), not contract-verifiable.
- **A-6 (promo list query params):** the web client calls `listPromoCodes()` with no
  query params though `next_cursor` is returned; whether the Android paging passes
  `cursor`/`limit` is assumed from the `PromoCodeListOut` shape.

## 17. Test Plan

Test target legend per case. IDs trace to §14 ACs. Unless noted, cases run as JVM
unit / Robolectric / contract (MockWebServer) and need **no device**; Compose-UI
cases run on the **headless emulator AVD `test35` (API 35)** in CI; cases that must
exercise real hardware/OS behavior name the **physical Samsung Galaxy A15 5G
(SM-A156U, API 34)**.

- **TC-AND-269-01 — Referral dashboard mapping (happy path).** Type:
  contract/MockWebServer. Target: JVM (`ReferralsApiMappingTest`). Preconditions:
  MockWebServer enqueues the verified `GET /ui/referrals/dashboard` body (citation
  #2). Steps: call the real Retrofit `ReferralsApi` + Moshi; assert decoded
  `total_referrals=12`, `*_cents` as `Long`, `referral_codes[0].code="AB12CD"`,
  `created_at` parsed as `Instant`. Expected: domain `ReferralDashboard` with exact
  values; request path is `/ui/referrals/dashboard`. Traces: AC-3.
- **TC-AND-269-02 — Referral empty / ineligible derivation.** Type: unit. Target:
  JVM (`ReferralsApiMappingTest`/mapper). Preconditions: body with
  `total_referrals=0` and `referral_codes: []`. Steps: map; assert `isEmpty=true`
  and the no-link/`Ineligible` flag. Expected: empty + ineligible states derived,
  no crash. Traces: AC-3, AC-4.
- **TC-AND-269-03 — Malformed referral JSON.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue a wrong-typed body (`total_referrals:
  "many"`). Steps: call API. Expected: `ApiResult.Error` parse error, **no** crash.
  Traces: AC-3.
- **TC-AND-269-04 — Referral ViewModel ordering + refresh-preserves-content.**
  Type: unit (Turbine). Target: JVM (`ReferralViewModelTest`, Fake repo,
  `MainDispatcherRule`). Steps: emit `Load` (success), then `Refresh` (success then
  a failure). Expected: `Loading → Content`; on refresh `isRefreshing` toggles
  without dropping `Content`; refresh failure keeps `Content` + emits error effect
  (not an `Error` state). Traces: AC-4.
- **TC-AND-269-05 — Referral effects exactly-once + in-flight guard.** Type: unit
  (Turbine). Target: JVM (`ReferralViewModelTest`). Steps: send `CopyLink` and
  `ShareLink`; assert `CopyToClipboard(url)`/`ShowShareSheet(text)` each delivered
  once and not re-fired on re-collection; fire two concurrent `Load`s and assert
  repo call count == 1. Expected: one-shot effects; single repo call. Traces: AC-4.
- **TC-AND-269-06 — Affiliate links mapping + empty state.** Type:
  contract/MockWebServer. Target: JVM (`AffiliateApiMappingTest`). Preconditions:
  enqueue `GET /ui/affiliates/links` body (citation #7). Steps: decode; assert
  `links[0]` aggregate fields (`click_count`, `revenue_cents` Long,
  `conversion_rate_pct`); then enqueue `{ "links": [] }` and assert
  `Content(isEmpty=true)`. Expected: list mapped; empty handled; request path
  `/ui/affiliates/links` (no `summary`/`conversions` path issued). Traces: AC-3.
- **TC-AND-269-07 — Referral commissions cursor paging.** Type: unit (Paging 3
  `TestPager`). Target: JVM (`AffiliateConversionsPagingTest` → commissions pager).
  Preconditions: two pages; page 1 has `next_cursor="C2"`, page 2 has
  `next_cursor=null`. Steps: `load(Refresh)` then `load(Append)`; assert order
  preserved, `cursor=C2` threaded into the append request, terminal page →
  `nextKey=null`; then a failing load → `LoadResult.Error`. Expected: keys/order
  correct; terminal + error handled. Traces: AC-5.
- **TC-AND-269-08 — Affiliate tab `SavedStateHandle` restoration.** Type: unit.
  Target: JVM (`AffiliateViewModelTest`). Steps: set `AffiliateTab.Conversions`,
  rebuild VM from same `SavedStateHandle`. Expected: restored tab ==
  `Conversions`; `affiliate_tab_selected{tab}` analytics emitted once. Traces:
  AC-4.
- **TC-AND-269-09 — Promo create + list (MVP) and validation error.** Type:
  contract/MockWebServer. Target: JVM (`PromoCodesApiTest`). Preconditions:
  enqueue 201 `PromoCodeOut` for `POST /ui/promo-codes`, then a paged
  `PromoCodeListOut`, then a 422 `{detail:[{loc,msg,type}]}` for a duplicate code.
  Steps: `create(PromoCodeCreateIn{code,discount_type:"percentage",discount_value})`,
  `list`, then `create` dup. Expected: create body serializes
  `discount_type`/`discount_value` (no `discount_percent`); 201 → `PromoCode` with
  `code_id`; list returns `items`+`next_cursor`; 422 → non-retryable validation
  error with `"code already exists"`. Traces: AC-3, AC-6.
- **TC-AND-269-10 — Promo redeem body + POST not backoff-retried.** Type:
  contract/MockWebServer. Target: JVM (`PromoCodesApiTest`). Preconditions: enqueue
  `503` then `200` for `POST /ui/promo-codes/redeem`. Steps: `redeem(PromoRedeemIn{
  code_id, original_price_cents, final_price_cents, checkout_type})`. Expected:
  request body keys on `code_id` (not `code`); the POST is **not** auto-retried on
  503 (single request recorded) → `Error`. Traces: AC-6, AC-7.
- **TC-AND-269-11 — Affiliate discounts mapping + null fields.** Type:
  contract/MockWebServer. Target: JVM (`AffiliateDiscountsMappingTest`).
  Preconditions: enqueue `GET /ui/ads/affiliate/discounts` body (citation #16) plus
  a second item with `affiliate_code/promo_code/promo_value_display/
  click_through_url = null`. Steps: decode. Expected: `promo_value_display` mapped
  as display string, `click_through_url` mapped; nulls → `null` (no crash); epoch
  `created_at`/`updated_at` decoded as instants; no `value/scope/valid_until`
  expected. Traces: AC-3.
- **TC-AND-269-12 — `detail` mapping (3 shapes) + retryable flag.** Type:
  parameterized unit/contract. Target: JVM (`E36ErrorMappingTest`). Preconditions:
  bodies `string`, `[{msg}]`, `{code,message}`; statuses 400/422/500/503/timeout.
  Steps: map each. Expected: string→message; array→joined `msg`; object→`message`
  (Android extension, A-2); 4xx validation `retryable=false`; 5xx/timeout/network
  `retryable=true`. Traces: AC-7.
- **TC-AND-269-13 — 401 → single refresh → one retry; second 401 → session
  expired.** Type: contract/MockWebServer. Target: JVM (`E36ErrorMappingTest`).
  Preconditions: enqueue `401`, `200` (for `POST /ui/session/refresh`), `200` (the
  retried GET); separately `401`,`200`,`401`. Steps: call a GET repo method.
  Expected: exactly **one** recorded `/ui/session/refresh`; final `Content`;
  double-401 surfaces `SessionExpired`/`Error` with no loop; `X-CSRF-Token` present
  on the retried request and equal to `ui_csrf`. Traces: AC-7, AC-10.
- **TC-AND-269-14 — Timeout + offline/stale cache fallback.** Type:
  contract/MockWebServer + in-memory Room. Target: JVM
  (`ReferralsRepositoryStaleTest`). Preconditions: short read timeout client +
  `setBodyDelay(25s)`; (a) Room seeded with a prior dashboard payload, (b) empty
  Room. Steps: trigger the timeout/socket disconnect. Expected: (a)
  `Content(isStale=true)` from cache; (b) retryable `Error`(offline). Traces:
  AC-7, AC-8.
- **TC-AND-269-15 — Compose render per state + a11y + share intent + de-DE
  formatting.** Type: Compose-UI (Robolectric in CI; one instrumented pass on AVD
  `test35`). Target: `ReferralsScreenTest`, `AffiliatesScreenTest`,
  `DiscountsScreenTest`, `PromoScreenTest`. Preconditions: stateless Composables fed
  each state (loading, content, empty/ineligible, session-expired, error+retry,
  stale banner). Steps: assert nodes via tags/text; assert metric tiles merge
  semantics (TalkBack reads "Signups, 9" as one node), Share/Copy/Retry expose
  `contentDescription` and 48dp targets, stale banner announced; build the
  `text/plain ACTION_SEND` intent from `ShowShareSheet` text via a fake launcher;
  render under `Locale.GERMANY` and assert grouped/comma-decimal currency from
  raw `*_cents`. Expected: every state renders; a11y semantics + share intent +
  locale formatting correct. Traces: AC-2, AC-9.
- **TC-AND-269-16 — Security/PII: CSRF echo, cookie replay, no-leak logging/
  analytics.** Type: contract/MockWebServer + capturing log/analytics. Target: JVM
  (`E36ErrorMappingTest`/security helper + `FakeAnalytics`). Steps: issue two
  requests on one MockWebServer; assert `X-CSRF-Token == ui_csrf` on both, the
  session cookie is replayed on the 2nd, and that referral URL/code, earnings
  amounts, and promo strings never appear in non-debug logs or analytics payloads
  (only event names/categories/counts); a DEBUG referral log is redacted to its
  code suffix. Traces: AC-10, AC-11.
- **TC-AND-269-17 — Real share-sheet + clipboard on physical device.** Type:
  instrumented/e2e. Target: **PHYSICAL DEVICE — Samsung Galaxy A15 5G (SM-A156U,
  API 34)** (MUST run on device, not emulator: exercises the real Android chooser
  and `ClipboardManager`). Preconditions: app on device; a referral with a link.
  Steps: tap Share → assert an `ACTION_SEND` `text/plain` chooser launches with the
  marketing text + link (no cookies/token/PII); tap Copy → assert the clipboard
  primary clip equals the referral URL and the "Referral link copied" announcement.
  Expected: real chooser + clipboard behave as specified. Traces: AC-9, AC-10.

### Coverage matrix

| AC (§14) | Covered by |
|----------|------------|
| AC-1 (unit tasks green) | TC-01..TC-14, TC-16 (all JVM/contract suites) |
| AC-2 (Compose UI task) | TC-15 |
| AC-3 (mapping FR-1/5/9 + malformed) | TC-01, TC-02, TC-03, TC-06, TC-09, TC-11 |
| AC-4 (ViewModel FR-2/3/4/7) | TC-02, TC-04, TC-05, TC-08 |
| AC-5 (paging FR-6) | TC-07 |
| AC-6 (promo FR-8) | TC-09, TC-10 |
| AC-7 (error/resilience FR-10/11) | TC-10, TC-12, TC-13, TC-14 |
| AC-8 (stale/offline FR-12) | TC-14 |
| AC-9 (Compose render + a11y + share + de-DE) | TC-15, TC-17 |
| AC-10 (CSRF/cookie/no-leak) | TC-13, TC-15, TC-16, TC-17 |
| AC-11 (hermetic suite) | TC-12, TC-13, TC-16 (+ all JVM cases run with no live host) |
