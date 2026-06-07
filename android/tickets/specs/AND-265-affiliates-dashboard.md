---
id: AND-265
title: Affiliates dashboard
milestone: M6
epic: E36
priority: P2
size: M
depends_on: [AND-027]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-265 — Affiliates dashboard

## 1. Overview & Goal

Build the **Affiliates dashboard** screen for the TestLogon native Android app:
the creator-facing surface that shows a user's affiliate/referral program
performance. The screen presents two coordinated regions — (a) **referral
links** (the user's shareable affiliate links with copy/share affordances and
per-link click/conversion counts) and (b) **affiliate earnings** (commission
totals, pending vs. paid balances, and a recent-referral activity list).

This ticket owns a new `feature-affiliates` UI module: the Retrofit `AffiliateApi`
service and its DTOs/domain mappers, a thin `AffiliateRepository`, the
`AffiliatesViewModel` + `AffiliatesUiState`, and the Compose screen with its
sub-composables. It is the Android counterpart of the web reference module
`frontend/src/api/endpoints/affiliates.ts` (shared types in
`frontend/src/api/types.ts`).

Scope, verbatim from the backlog: *`affiliates.ts`; links + earnings.* The
single acceptance criterion is: *Affiliate dashboard renders.* The acceptance
bar is therefore that the screen fetches real affiliate data from the dev
backend and renders both the links region and the earnings region, with correct
loading / empty / error / offline states.

> **Reviewer correction (2026-06-06, AND-265 amend).** The original draft assumed
> a dedicated `GET /ui/affiliates/summary` endpoint returning an aggregated
> earnings object plus a `recent_referrals` list. **No such endpoint exists.** The
> affiliates domain exposes only the *links* endpoints (`/ui/affiliates/links*`);
> see §5/§16. The web reference (`src/pages/affiliates/AffiliateDashboard.tsx`)
> renders **only** the links list and derives every per-link earnings figure from
> the `AffiliateLinkOut` fields (`commission_earned_cents`, `revenue_cents`,
> `click_count`, `conversion_count`). The "earnings region" of this screen is
> therefore a **client-side aggregation over the links payload**, not a second API
> call. The aggregated-earnings/recent-referrals concept the draft described
> actually belongs to a *separate* feature, the **Referrals** domain
> (`/ui/referrals/dashboard` → `ReferralDashboardStats`, `/ui/referrals/commissions`,
> `/ui/referrals/referrals`), which is out of scope for AND-265. The body below
> has been corrected accordingly; remaining `summary`/`recent_referrals` mentions
> are flagged in §16.

Out of scope: payout initiation / withdrawal of affiliate balances (Payouts
epic E35), affiliate program enrollment/onboarding flows, creating or editing
custom referral codes, deep per-referral attribution drill-down screens, and
CSV/export. The cross-cutting Earnings dashboard (E34, AND-251/AND-252) is a
separate surface; affiliate commission figures here are independent of that and
are not aggregated into it.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. New module **`feature-affiliates`**; all packages under
  `com.testlogon.android.feature.affiliates`. The `AffiliateApi` interface and
  its Hilt provider live in this module's `data` package (it is a leaf
  consumer-owned API; cf. AND-251 which placed shared finance APIs in
  `core-network` — affiliates is self-contained and does not need to be shared,
  so it stays module-local).
- **Canonical package:** `com.testlogon.android` everywhere.
- **Module layering:** `app -> feature-affiliates -> core-network, core-model,
  core-ui, core-data, core-testing`. No `feature-*`/`app` symbols leak into
  `core-*`. This ticket creates `feature-affiliates` and registers it in
  `settings.gradle.kts` and the `app` module dependencies.
- **Stack pins:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit **2.11.0** / OkHttp
  **4.12.0** / Moshi **1.15.x** (codegen via KSP), Room 2.6 (cache snapshot),
  DataStore (prefs, not required here), Coil (no media here). minSdk 24 /
  compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes
  the shared session `Retrofit`, the cookie-based session, and the Hilt provider
  pattern this ticket mirrors. All `/ui/affiliates/*` calls are session-gated
  (cookies + `X-CSRF-Token`) and require an authenticated principal; the
  dependency guarantees that machinery exists before affiliate calls are made.
- **Cross-cutting infra (already planned):** persistent cookie jar (AND-011),
  CSRF interceptor (AND-012), 401→refresh authenticator (AND-013), `ApiResult<T>`
  (AND-018), FastAPI `detail` error mapping (AND-015), idempotent-GET
  retry/backoff (AND-016), connectivity probe (AND-017), shared state composables
  loading/empty/error/offline (AND-021), Material 3 theme (AND-019),
  authenticated nav graph + bottom-nav/More-hub entry (AND-024), logout cleanup
  hook (AND-032), MockWebServer harness (AND-046).
- **Backend contract:** FastAPI + DynamoDB, OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (dev, **plaintext HTTP**,
  unreliable — design for ~20s timeouts, bounded backoff retry on idempotent GETs
  only, offline/stale UI). Web reference: `frontend/src/api/endpoints/affiliates.ts`.

## 3. Functional Requirements

1. **Links region.** Display the authenticated user's affiliate referral links.
   Each row shows a human label (e.g. "Default link", or a campaign name), the
   full referral URL (truncated with ellipsis), and per-link metrics: clicks and
   conversions (sign-ups/purchases attributed). Each row has a **Copy** action
   (copies URL to clipboard, shows a snackbar confirmation) and a **Share**
   action (Android `ACTION_SEND` chooser). If the user has no links, the region
   shows an inline empty message.
2. **Earnings region.** Display affiliate commission summary: *Total earned*
   (lifetime), *Pending* (accrued, not yet paid), and *Paid* (already paid out),
   each as a localized currency value with currency code. Show aggregate
   referral counts (total referrals, total clicks, total conversions).
3. **Recent referral activity.** A short list (server-paginated, first page
   only on this screen) of recent attributed referrals: who/what (a non-PII
   display label such as a referred display name or masked identifier), the
   commission amount, the status (`pending`|`paid`|`reversed`), and a relative
   timestamp. A "View all" affordance is a no-op stub link in this ticket
   (full list is a future E36 ticket).
4. **Loading state.** First load shows skeleton placeholders for the links list,
   the earnings summary cards, and the activity list (via AND-021 primitives).
5. **Empty state.** When the account is not enrolled or has no affiliate data
   (no links, zero earnings, no referrals), show a friendly full-screen empty
   state explaining the affiliate program is available with no data yet.
6. **Error state.** On a non-recoverable failure, show the shared error state
   with a Retry action that re-triggers the load.
7. **Offline / stale state.** If the network is unavailable but a cached
   snapshot exists, render cached data with a "Showing saved data" banner + a
   timestamp; if no cache exists, show the offline state.
8. **Pull-to-refresh** re-fetches the dashboard, bypassing cache.
9. **Navigation.** Reachable from the authenticated graph via the More hub
   ("Affiliates" entry, AND-024/AND-067). Route: `affiliates`. No arguments.

## 4. Technical Design

New module `feature-affiliates`, packages under
`com.testlogon.android.feature.affiliates`.

**Retrofit interface** (`feature-affiliates/.../data/AffiliateApi.kt`).
**Corrected:** a *single* idempotent GET (`/ui/affiliates/links`) backs the whole
dashboard. There is no `/ui/affiliates/summary` endpoint (verified against the
OpenAPI index and `src/api/endpoints/affiliates.ts`); the earnings region is
aggregated client-side from the links payload. The link list endpoint takes **no
query params** in the web contract (only the operator params `user_sub` /
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN`, which the mobile client does not send).

```kotlin
package com.testlogon.android.feature.affiliates.data

import retrofit2.http.GET

interface AffiliateApi {

    /** Affiliate links + per-link metrics. OpenAPI: list_links_ui_affiliates_links_get */
    @GET("ui/affiliates/links")
    suspend fun getLinks(): AffiliateLinksDto
}
```

The session cookie + CSRF header are attached uniformly by the shared
OkHttp stack (AND-011/012); no per-call auth code here. Operator/impersonation
params (`user_sub`, `X-IMPERSONATION-TOKEN`) present in the OpenAPI spec are
deliberately not exposed on the mobile interface.

**Hilt provider** (`feature-affiliates/.../data/AffiliateNetworkModule.kt`):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object AffiliateNetworkModule {
    @Provides @Singleton
    fun provideAffiliateApi(retrofit: Retrofit): AffiliateApi =
        retrofit.create(AffiliateApi::class.java)
}
```

`Retrofit` is the qualified session-scoped instance built in the network
baseline (AND-010/AND-027), already carrying cookie jar, CSRF interceptor,
authenticator, and the Moshi converter.

**Repository** (thin orchestration; no business logic).

```kotlin
package com.testlogon.android.feature.affiliates.data

interface AffiliateRepository {
    fun observeDashboard(): Flow<ApiResult<AffiliateDashboard>>
    suspend fun refresh(): ApiResult<AffiliateDashboard>
    suspend fun clear()                       // logout cleanup (AND-032)
}

data class AffiliateDashboard(
    val links: List<AffiliateLink>,
    val earnings: AffiliateEarnings,     // derived client-side from links
    val asOf: Instant,                   // client fetch time (no server as_of)
    val isStale: Boolean = false,
)
```

`AffiliateRepositoryImpl` (Hilt `@Singleton`) calls the single `getLinks()`
endpoint, maps the DTO to domain models, **computes the aggregated earnings
client-side** by summing the per-link fields (`commission_earned_cents` →
`totalEarned`, plus summed `click_count`/`conversion_count`/link count), combines
into `AffiliateDashboard`, writes the result to a Room snapshot, and emits
**cache-first then network** via `observeDashboard()`. (Corrected: the draft's
two-call concurrent `coroutineScope { async … }` fan-out is removed because the
`/ui/affiliates/summary` call it depended on does not exist.) The `apiCall {}`
wrapper (AND-018) converts throwables/HTTP errors into `ApiResult.Failure` with
`detail` mapping (AND-015).

> Note on "recent referral activity": the draft sourced this from the
> non-existent summary endpoint. The affiliate links payload contains no
> per-referral activity list. For AND-265 the "recent activity" region renders
> the links sorted by recency (`created_at`/`updated_at`) — OR is dropped — and a
> true attributed-referral feed is left to the Referrals epic
> (`/ui/referrals/referrals`, `/ui/referrals/commissions`). Treated as an open
> assumption (§16) pending product confirmation.

**Caching.** Room entity in module-local DAO (`core-data` style):
`AffiliateSnapshotEntity(id: String = "self" PK, payloadJson: String,
currency: String, fetchedAtEpochMs: Long)`. `observeDashboard()` emits the
cached snapshot immediately (flagged `isStale = true` if older than 15 min),
then fetches fresh and re-emits. `clear()` empties the table; invoked by the
central logout cleanup (AND-032).

**ViewModel.**

```kotlin
@HiltViewModel
class AffiliatesViewModel @Inject constructor(
    private val repo: AffiliateRepository,
) : ViewModel() {
    val uiState: StateFlow<AffiliatesUiState>     // see §6
    fun onRefresh()                                // pull-to-refresh, force network
    fun onRetry()
    fun onCopyLink(link: AffiliateLinkUi)          // emits a one-shot Ui effect
    fun onShareLink(link: AffiliateLinkUi)         // emits a one-shot Ui effect
}
```

The VM exposes `uiState` from `repo.observeDashboard()` mapped into
`AffiliatesUiState` (`stateIn(WhileSubscribed(5_000), Loading)`). `onRefresh`
launches `repo.refresh()` and toggles `isRefreshing`. Copy/share are surfaced as
one-shot UI effects (a `Channel<AffiliateEffect>`-backed `Flow`) so the screen
performs the clipboard/intent side effect; the VM never touches Android UI APIs.

**Screen.**

```kotlin
@Composable
fun AffiliatesRoute(
    viewModel: AffiliatesViewModel = hiltViewModel(),
    onBack: () -> Unit,
)

@Composable
fun AffiliatesScreen(
    state: AffiliatesUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCopyLink: (AffiliateLinkUi) -> Unit,
    onShareLink: (AffiliateLinkUi) -> Unit,
)
```

Sub-composables: `EarningsSummaryCards(earnings, modifier)` (three KPI cards +
referral counts), `AffiliateLinksSection(links, onCopy, onShare)`
(`AffiliateLinkRow` per item), `RecentReferralsSection(referrals)`
(`ReferralRow` per item with status chip). `AffiliatesRoute` collects the
effect flow in a `LaunchedEffect` and performs clipboard copy
(`ClipboardManager`/`LocalClipboardManager`) and the `ACTION_SEND` chooser
(`Intent.createChooser`).

**Money handling.** Amounts are integer minor units (`amountMinorCents: Long`)
from the backend; convert to major units only at format time
(`NumberFormat.getCurrencyInstance(locale)`) — never `Float`/`Double` in the
data graph.

**Navigation registration** (in authenticated nav graph, AND-024):

```kotlin
composable(route = "affiliates") {
    AffiliatesRoute(onBack = navController::popBackStack)
}
```

## 5. API Contract

Base URL: runtime-selected host (dev `http://18.222.237.167:8000`). All paths
relative to that base; all calls session-authenticated (cookies +
`X-CSRF-Token`). All money fields are integer **minor units (cents)**. The
operation is an **idempotent GET** → eligible for bounded backoff retry
(AND-016) and the 401→refresh→retry path (AND-013).

> **Corrected contract.** The earlier draft listed two endpoints with invented
> field names. The verified single endpoint and its real schema (from
> `src/api/endpoints/affiliates.ts: AffiliateLinkOut` / `AffiliateLinkListOut`;
> the OpenAPI 200 body is declared untyped `{}`, so the frontend types are the
> authoritative shape) are below. **There is no `summary` endpoint, no `label`,
> `url`, `code`, `clicks`, `conversions`, or `is_default` field, and no
> `currency`/`as_of`/`recent_referrals` object.**

**GET `/ui/affiliates/links`** → `200 AffiliateLinkListOut` (OpenAPI op
`list_links_ui_affiliates_links_get`; query/header params `user_sub`,
`X-SESSION-ID`, `X-IMPERSONATION-TOKEN` are all optional and NOT sent by mobile)

```json
{
  "links": [
    {
      "link_id": "afl_01H...",
      "affiliate_user_id": "usr_...",
      "product_owner_id": "usr_...",
      "target_type": "catalog_item",
      "target_id": "cat_...",
      "target_name": "My Product",
      "tracking_code": "abc123",
      "short_url": "/r/abc123",
      "destination_url": "https://testlogon.com/p/cat_...",
      "commission_percent": 10,
      "status": "active",
      "click_count": 1840,
      "unique_click_count": 1502,
      "conversion_count": 92,
      "revenue_cents": 4827310,
      "commission_earned_cents": 482731,
      "conversion_rate_pct": 5.0,
      "created_at": 1748000000,
      "updated_at": 1748100000
    }
  ]
}
```

Field notes (verified against the frontend types):
- Money fields: `revenue_cents`, `commission_earned_cents` are integer cents.
  `commission_percent` and `conversion_rate_pct` are **percentages, not money**
  (the web renders `commission_percent` as `…%`). `conversion_rate_pct` is a
  fractional/`number` percentage — the only legitimately non-integer numeric on
  the wire; it is display-only and never enters the money graph.
- The shareable link is `short_url` (the web copies `window.location.origin +
  short_url`, i.e. it is a **relative path** like `/r/{tracking_code}` and must be
  prefixed with the app's web origin before copy/share, not the API base host).
  `destination_url` is the underlying product URL.
- The human label is `target_name`; the code is `tracking_code`. `status` is a
  string (web treats `"active"` specially; others render as a secondary badge) —
  lenient mapping, unknown → `OTHER`.
- There is no per-link `is_default` flag. Telemetry/`AffiliateLinkUi` fields that
  referenced `is_default` are dropped (see §10/§16).

**Per-link stats (out of scope for the dashboard list, available for drill-down):**
`GET /ui/affiliates/links/{link_id}/stats` → `200 AffiliateLinkStatsOut`
(`link_id, click_count, unique_click_count, conversion_count, revenue_cents,
commission_earned_cents, conversion_rate_pct`). Not called by AND-265; noted for
the future per-link detail ticket.

**Aggregated earnings (client-side, derived — no endpoint):** the earnings region
sums over `links[]`: `totalEarnedCents = Σ commission_earned_cents`,
`totalRevenueCents = Σ revenue_cents`, `totalClicks = Σ click_count`,
`totalConversions = Σ conversion_count`, `linkCount = links.size`. There is **no
server-provided `pending`/`paid` split, currency code, or `as_of`** for
affiliates (the web hardcodes `$` and `cents/100`). A pending-vs-paid breakdown
exists only in the *Referrals* domain (`ReferralDashboardStats`), out of scope.

**Error envelope** (FastAPI `detail`, mapped by AND-015): `401` (handled
transparently by the refresh authenticator), `422` validation
(`detail: [{msg}]` array — verified in `src/api/client.ts: normalizeErrorDetail`),
`403` permission/geo-block (`detail.code` e.g. `geo_blocked`/`role_required`),
`5xx`/timeout → recoverable error surfaced as Retry. Empty data (no links) is a
**200 with an empty `links` array**, not an error → empty state. This ticket
relies on the shared error adapter and does not re-map errors.

## 6. Data & State Management

**DTOs** (`com.testlogon.android.feature.affiliates.data.dto`, Moshi codegen;
every field defaulted so partial payloads still decode):

**Corrected** to the verified `AffiliateLinkOut` shape. There is a single
list DTO; earnings are derived in the mapper (no earnings/referral DTOs).

```kotlin
@JsonClass(generateAdapter = true)
data class AffiliateLinksDto(
    val links: List<AffiliateLinkDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AffiliateLinkDto(
    @Json(name = "link_id") val linkId: String,
    @Json(name = "affiliate_user_id") val affiliateUserId: String = "",
    @Json(name = "product_owner_id") val productOwnerId: String = "",
    @Json(name = "target_type") val targetType: String = "",
    @Json(name = "target_id") val targetId: String = "",
    @Json(name = "target_name") val targetName: String = "",
    @Json(name = "tracking_code") val trackingCode: String = "",
    @Json(name = "short_url") val shortUrl: String = "",
    @Json(name = "destination_url") val destinationUrl: String = "",
    // commission_percent / conversion_rate_pct are percentages, display-only.
    // Decoded as Double ONLY here at the DTO edge; never propagated into the
    // money graph. (See §16 money-invariant note.)
    @Json(name = "commission_percent") val commissionPercent: Double = 0.0,
    val status: String = "",
    @Json(name = "click_count") val clickCount: Long = 0,
    @Json(name = "unique_click_count") val uniqueClickCount: Long = 0,
    @Json(name = "conversion_count") val conversionCount: Long = 0,
    @Json(name = "revenue_cents") val revenueCents: Long = 0,
    @Json(name = "commission_earned_cents") val commissionEarnedCents: Long = 0,
    @Json(name = "conversion_rate_pct") val conversionRatePct: Double = 0.0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)
```

The aggregated `AffiliateEarnings` domain model (below) is **computed in the
mapper** from `links[]`; there is no earnings DTO and no `recent_referrals` DTO.

**Domain models** (`com.testlogon.android.feature.affiliates.model`; money as
`Money(amountCents, currencyCode)`):

```kotlin
data class Money(val amountCents: Long, val currencyCode: String)  // currencyCode defaults to device/"USD"; not server-provided

data class AffiliateLink(
    val id: String, val label: String,            // label = target_name
    val shortUrl: String,                          // relative; prefix with web origin to share
    val destinationUrl: String, val trackingCode: String,
    val commissionPercent: Double,                 // percentage, display-only
    val status: LinkStatus, val rawStatus: String,
    val clicks: Long, val uniqueClicks: Long, val conversions: Long,
    val revenue: Money, val commissionEarned: Money,
    val conversionRatePct: Double,                 // percentage, display-only
    val createdAtEpochSeconds: Long, val updatedAtEpochSeconds: Long,
)

// Corrected: affiliates has NO pending/paid split, total_referrals, or
// server currency. These figures are SUMMED over links[] in the mapper.
data class AffiliateEarnings(
    val totalEarned: Money,        // Σ commission_earned_cents
    val totalRevenue: Money,       // Σ revenue_cents
    val totalClicks: Long,         // Σ click_count
    val totalConversions: Long,    // Σ conversion_count
    val linkCount: Long,
)

enum class LinkStatus { ACTIVE, INACTIVE, REVOKED, OTHER;
    companion object { fun from(raw: String): LinkStatus = /* lenient */ }
}
```

(Removed: `AffiliateReferral` / `ReferralStatus` — those modelled the
non-existent affiliate-summary referrals feed. If product confirms a referral
activity feed is wanted, it is sourced from the **Referrals** domain
(`/ui/referrals/referrals` → `ReferralItem{referred_user_id, referral_code,
status, attributed_at}`) in a separate ticket.)

**UI state** (`com.testlogon.android.feature.affiliates.ui`):

```kotlin
sealed interface AffiliatesUiState {
    data object Loading : AffiliatesUiState
    data object Empty : AffiliatesUiState
    data class Error(val message: String, val recoverable: Boolean) : AffiliatesUiState
    data object Offline : AffiliatesUiState
    data class Ready(
        val links: List<AffiliateLinkUi>,
        val earnings: EarningsSummaryUi,
        val isStale: Boolean,
        val asOfLabel: String,                     // formatted client fetch time (no server as_of)
        val isRefreshing: Boolean,
    ) : AffiliatesUiState
}

// Corrected: label = target_name; shareUrl = short_url (relative — prefix with
// web origin before share); no is_default. commission/conversion-rate shown as %.
data class AffiliateLinkUi(val id: String, val label: String, val shareUrl: String,
    val displayUrl: String, val statusLabel: String, val status: LinkStatus,
    val clicks: String, val conversions: String, val commissionPercent: String,
    val earned: String)
// Corrected: earnings are derived sums; no pending/paid (affiliates has no split).
data class EarningsSummaryUi(val totalEarned: String, val totalRevenue: String,
    val linkCount: String, val clicks: String, val conversions: String)

sealed interface AffiliateEffect {
    data class CopyToClipboard(val url: String) : AffiliateEffect
    data class ShareUrl(val url: String) : AffiliateEffect
}
```

- VM exposes a single `StateFlow<AffiliatesUiState>` (`WhileSubscribed(5_000)`,
  initial `Loading`). `Ready.isStale` drives the "Showing saved data" banner;
  `asOfLabel` is the formatted **client fetch time** (the affiliate payload has no
  server `as_of` — corrected).
- The Room snapshot is the single source of truth for offline.
- Mapping is pure/total; per-link `created_at`/`updated_at` are epoch **seconds**
  (web does `new Date(ts * 1000)`), parsed inside `runCatching`.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the global OkHttp ~20s timeouts (AND-009); a timeout
  surfaces as recoverable `Error`, or `Offline` if the connectivity probe
  (AND-017) reports no network.
- **Retry/backoff:** the single `getLinks()` call is an idempotent GET and passes
  through the AND-016 retry interceptor; the user-facing Retry/refresh is the
  fallback after automatic retries are exhausted.
- **401:** handled transparently by the refresh authenticator (AND-013, which
  mirrors the web `POST /ui/session/refresh` flow in `src/api/client.ts`); a
  second 401 propagates as auth failure and the auth-gated router (AND-025)
  ejects to login — the affiliates VM does not special-case it.
- **403:** permission/geo-block; surfaced via shared `detail.code` mapping
  (AND-015) as a non-recoverable `Error` (no Retry for `role_required`). See §13
  enrollment open question.
- **Failure fallback** (corrected — there is no second call to partially fail):
  if `getLinks()` fails after retries, fall back to the cached snapshot if present
  (stale `Ready`) else `Error`/`Offline`.
- **Stale data:** a cached snapshot older than 15 min renders with the stale
  banner while a background refresh runs; success replaces it silently.
- **Malformed/missing fields:** Moshi defaults absent numeric fields to 0 and
  arrays to empty, so a partially-populated `200` still decodes; only `link_id`
  is treated as required (every other `AffiliateLinkOut` field is defaulted, since
  the OpenAPI body is untyped and field presence is not guaranteed).
- **Empty vs. error:** an empty `links` `200` maps to `Empty` (full-screen).
  There is no separate earnings region to be independently empty; with ≥1 link,
  the derived earnings card always renders (sums may be zero).
- **Unreliable dev host:** plaintext HTTP with intermittent 5xx is covered by
  shared retry + the offline/stale path; mapping is side-effect-free and safe to
  call repeatedly.

## 8. Security & Privacy

- All affiliate endpoints are session-gated; auth rides on the persistent cookie
  jar (AND-011) and the `X-CSRF-Token` header (AND-012). No tokens or
  credentials are handled in this ticket.
- Affiliate **commission/revenue amounts are sensitive financial data** and MUST
  NOT be logged (see §10) or placed in URLs.
- The links payload also carries `affiliate_user_id` / `product_owner_id`
  (account identifiers). These are not displayed and MUST NOT be logged.
  (Corrected: the draft's `display_label` PII concern belonged to the referrals
  feed, which is not part of this payload.)
- The Room snapshot persists affiliate JSON on-device in app-private storage;
  `AffiliateRepository.clear()` is invoked by the central logout cleanup
  (AND-032) so no affiliate cache survives a session change.
- Referral **URLs** are user-shareable by design; copy/share are the only
  egress and are explicit user actions. No automatic sharing.
- The `user_sub` / `X-IMPERSONATION-TOKEN` operator params are deliberately not
  exposed, preventing a client from requesting another principal's affiliate data.
- Dev backend is plaintext HTTP (cleartext permitted only for the dev flavor per
  AND-006); release builds target HTTPS. No cleartext exemption is widened here.
- The screen is a candidate for `FLAG_SECURE` screenshot suppression; deferred
  to a security-hardening ticket (noted §13), consistent with E34.

## 9. Accessibility & i18n

- All KPI cards and link rows expose `contentDescription` / `semantics`. A totals
  card reads as "Total earned, 4,827 dollars 31 cents".
  Copy/Share `IconButton`s have descriptive labels ("Copy referral link",
  "Share referral link") and ≥48dp touch targets.
- The link **status** chip is not color-only: a glyph/text label accompanies the
  color (active/inactive/revoked). Contrast meets 4.5:1 on Material 3 tokens
  (AND-019).
- All UI strings live in `strings.xml` (`feature-affiliates`); no hardcoded text.
  Status labels are mapped through a localized table, not raw API enums.
- Currency: the affiliate payload carries **no currency code** (web hardcodes
  `$`). Format via `NumberFormat.getCurrencyInstance(locale)` with the device
  default currency (assumption — see §16); never hard-code `$`. Counts formatted
  via
  `NumberFormat.getIntegerInstance(locale)`. Relative timestamps via a localized
  relative-time formatter.
- Dynamic type / large font scaling supported without truncating KPI values
  (auto-size or wrap). Layouts use logical start/end paddings (RTL-safe). Long
  referral URLs truncate with `TextOverflow.Ellipsis` while the full URL remains
  available to the Copy/Share actions and to TalkBack.

## 10. Telemetry & Logging

Events via the app analytics facade (no raw monetary values, no PII labels):

- `affiliates_view_opened {}`
- `affiliates_load_result { outcome: success|empty|error|offline|stale, latency_ms, link_count }`
  (corrected: no `referral_count` — there is no referral feed in this payload)
- `affiliates_refresh_invoked { trigger: pull|retry }`
- `affiliates_link_copied { status }`   (corrected: no `is_default`; never URL/code)
- `affiliates_link_shared { status }`   (corrected: no `is_default`; never URL/code)

Logging: redacted structured logs at `Timber` debug for cache hit/miss and stale
decisions; **amounts, revenue, link URLs, tracking codes, and account ids
(`affiliate_user_id`/`product_owner_id`) are never logged** (only presence/counts). Network logging follows the OkHttp interceptor
policy (AND-009/AND-052): `BASIC` in debug, `NONE` in release — bodies are never
emitted. A single non-PII debug line on decode failure
(`AffiliateApi: decode failed for <endpoint>`, no body) is permitted.

## 11. Testing Strategy

**MockWebServer (AND-046 harness + fixtures), JVM unit:**
golden JSON fixtures `links_full.json`, `links_empty.json`,
`links_missing_optional.json` (only `link_id` present), plus `422`, `403`, and
`500` bodies. (Corrected: removed the `summary_*` fixtures — no summary endpoint.)
- **T-1 Path/verb:** assert exactly `GET /ui/affiliates/links` is issued (no
  query params; no `summary` request).
- **T-2 Mapping:** `links_full.json` decodes and maps with every field asserted,
  including `Money` cents (`commission_earned_cents`, `revenue_cents`) and
  `LinkStatus.from` (unknown status → `OTHER`).
- **T-3 Earnings aggregation:** a multi-link `links_full.json` maps to
  `AffiliateEarnings` whose sums equal Σ of the per-link fields.
- **T-4 Defaults tolerance:** `links_missing_optional.json` decodes with defaulted
  zeroed numerics and empty strings, no throw.
- **T-5 Money invariant:** reflection guard — no `Float`/`Double` in the **money
  graph** (`Money`/`AffiliateEarnings`/domain cents fields). Exemption: the
  display-only `commissionPercent`/`conversionRatePct` percentages are `Double`
  by contract and are explicitly allow-listed by the guard.

**Unit (JUnit/Turbine/MockK):**
- `AffiliateRepositoryImplTest`: single `getLinks()` call + client-side earnings
  aggregation; cache-first emission then network re-emit; failure → falls back to
  cache/error; 15-min stale threshold; `clear()` empties the DAO.
- `AffiliatesViewModelTest`: initial `Loading` → `Ready` on success;
  empty links → `Empty`; error → `Error(recoverable=true)`; offline-with-cache →
  stale `Ready` + banner; refresh sets then clears `isRefreshing`; `onCopyLink`
  / `onShareLink` emit the correct one-shot effects with the web-origin-prefixed
  `short_url`.

**Compose UI tests (AND-051 headless emulator):**
`AffiliatesScreen` renders the earnings card and link rows for `Ready` (satisfies
"Affiliate dashboard renders"); skeletons for `Loading`; empty/error/offline
states show correct affordances; Retry invokes its callback; Copy/Share buttons
invoke their callbacks; semantics nodes present for a11y.

**CI:** runs under unit (AND-050) and instrumented (AND-051) jobs.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints) — provides the shared
  session `Retrofit`, cookie jar, CSRF, 401-refresh, and the Hilt provider
  pattern reused here. Transitively depends on AND-010 (Retrofit+Moshi), AND-009
  (OkHttp), AND-011/012/013 (cookies/CSRF/refresh), AND-015 (error mapping),
  AND-016 (idempotent-GET retry), AND-017 (connectivity), AND-018 (`ApiResult`),
  AND-019 (theme), AND-021 (state composables), AND-024 (authenticated nav graph
  / More-hub entry), AND-032 (logout cleanup), AND-046 (MockWebServer harness),
  AND-050/051 (CI).
- **Blocks:** nothing in the source bullets (no downstream AND-### lists this
  ticket as a dependency). A future per-link detail ticket would build on
  `GET /ui/affiliates/links/{link_id}/stats`; a referral-activity feed would build
  on the separate Referrals domain (`/ui/referrals/*`). (Corrected: there is no
  affiliate `next_cursor` to build on — that was part of the removed summary.)
- **Sequencing:** land `AffiliateApi` + DTOs + mappers + `AffiliateRepository`
  + ViewModel + screen + tests together; merge to `android-port` after the auth
  network baseline (AND-027) and the shared UI/nav primitives (AND-019/021/024).

## 13. Risks & Open Questions

- **Endpoint shape — now confirmed (2026-06-06 review).** Verified: a single
  `GET /ui/affiliates/links` (`AffiliateLinkListOut`), no summary endpoint. The
  draft's two-endpoint design and field names were wrong and have been corrected
  throughout (§4–§11, §16). The OpenAPI 200 body for the endpoint is untyped
  (`schema: {}`), so the *frontend* `AffiliateLinkOut` interface is the
  authoritative shape — there is residual risk the backend adds/renames fields,
  so DTO fields are all defaulted.
- **Recent referral activity — does not exist on this payload.** Whether the
  product wants a referral activity feed on this screen is open; if so it is
  sourced from the Referrals domain (`/ui/referrals/referrals`,
  `/ui/referrals/commissions`) in a separate ticket. AND-265 either omits it or
  shows links-by-recency.
- **Enrollment gate.** Whether a non-enrolled user gets `200` empty vs. `403`/`404`
  is unspecified. Current design treats empty `200` (empty `links`) as the `Empty`
  state; a `403` would surface as `Error` — confirm and, if needed, add an
  explicit "not enrolled / join program" empty variant (deferred to E36).
- **Currency.** The affiliate payload has no currency code (web hardcodes `$`).
  Design assumes device-default currency formatting; confirm with product whether
  affiliate amounts are always account-currency, and whether the backend should
  add an explicit code.
- **Pending vs. paid semantics.** Affiliates exposes only `commission_earned_cents`
  / `revenue_cents` per link — there is no pending/paid split here (that lives in
  the Referrals/Payouts domains, E35). The UI renders earned/revenue totals only.
- **`FLAG_SECURE`** screenshot suppression on this financial screen is deferred
  to a hardening ticket.

## 14. Acceptance Criteria

1. Navigating to `affiliates` from the authenticated graph (More hub) fetches
   and **renders the affiliate dashboard** from the dev backend: the derived
   earnings summary (total earned + total revenue + link/click/conversion counts,
   aggregated client-side over the links payload) and the referral links list —
   satisfying *Affiliate dashboard renders*. (Corrected: no server pending/paid
   split and no recent-referral feed — see §16.)
2. Each link row shows label (`target_name`), the (truncated) share URL, clicks,
   conversions, commission %, and earned; **Copy** copies the full shareable URL
   (web-origin + `short_url`) to the clipboard with a snackbar confirmation, and
   **Share** launches the Android share chooser with that URL.
3. Loading shows skeletons; an empty `links` `200` shows the empty state; a
   `5xx`/timeout shows a recoverable error with a working Retry;
   offline-with-cache shows stale data + "Showing saved data" banner + timestamp;
   offline-no-cache shows the offline state.
4. Pull-to-refresh forces a network fetch bypassing cache.
5. Money (`revenue_cents`, `commission_earned_cents`) is carried as integer cents
   end-to-end and only formatted to major units at display with locale-correct
   currency formatting; no `Float`/`Double` exists in the money graph (guard test
   passes; display-only percentages are allow-listed).
6. No monetary values, link URLs, tracking codes, or account ids
   (`affiliate_user_id`/`product_owner_id`) appear in logs or telemetry (verified
   by a redaction test); the affiliate cache is cleared on logout (AND-032).
7. The single `GET /ui/affiliates/links` is called as an idempotent GET with no
   query params on the wire (proved by `MockWebServer` `RecordedRequest`).
8. Unit, MockWebServer, and Compose UI tests (§11) pass in CI (AND-050/AND-051).

## 15. Definition of Done

- `feature-affiliates` module created, wired into `settings.gradle.kts` and the
  `app` module, building under AGP 8.7.3 / Gradle 8.9 / JDK 17 under the
  canonical `com.testlogon.android.feature.affiliates` package.
- `AffiliateApi`, `AffiliateNetworkModule`, all DTOs, domain models,
  `LinkStatus`, mappers, `AffiliateRepository`(+Impl), the Room snapshot
  DAO/entity, `AffiliatesViewModel`, `AffiliatesUiState`, and `AffiliatesScreen`
  + sub-composables implemented per §4–§6.
- All five UI states (loading / ready / empty / error / offline+stale),
  pull-to-refresh, and copy/share function against the dev backend.
- Telemetry events emitted per §10 with redaction; cache-clear-on-logout wired
  (AND-032).
- Accessibility: semantics on all interactive/data nodes, status chip not
  color-only, dynamic type safe, localized strings — verified.
- Tests in §11 written and green in CI; ktlint/detekt (AND-005) clean; no new
  lint baselines added.
- KDoc on `AffiliateApi` methods links each endpoint to its OpenAPI operationId;
  mapper functions documented as pure/total.
- Code reviewed and merged to `android-port`; PR references AND-265 and AND-027
  and notes the §13 open questions for the E36 onboarding/list and E35 payouts
  owners. Spec acceptance criteria (§14) demonstrably met.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`), and frontend (`reference/src/...`).

1. **Affiliate links endpoint is `GET /ui/affiliates/links`.** VERIFIED —
   OpenAPI `GET /ui/affiliates/links` (op `list_links_ui_affiliates_links_get`);
   `src/api/endpoints/affiliates.ts: listAffiliateLinks` →
   `api.get<AffiliateLinkListOut>("/ui/affiliates/links")`.
2. **A `GET /ui/affiliates/summary` endpoint returns aggregated earnings +
   recent referrals.** CORRECTED — **no such endpoint exists.** No
   `/ui/affiliates/summary` in `reference/openapi.index.txt` (only
   `/ui/affiliates/links`, `…/links/{link_id}`, `…/links/{link_id}/stats`,
   `…/links/{link_id}/conversions`); not present in
   `src/api/endpoints/affiliates.ts`. Endpoint and its DTOs removed.
3. **`AffiliateLinkOut` field shape** (`link_id, affiliate_user_id,
   product_owner_id, target_type, target_id, target_name, tracking_code,
   short_url, destination_url, commission_percent, status, click_count,
   unique_click_count, conversion_count, revenue_cents, commission_earned_cents,
   conversion_rate_pct, created_at, updated_at`). VERIFIED —
   `src/api/endpoints/affiliates.ts: AffiliateLinkOut`. (OpenAPI 200 body is
   untyped `schema: {}` at `openapi.pretty.json` op `list_links_ui_affiliates_links_get`,
   so the frontend interface is authoritative.)
4. **Draft link fields `label`, `url`, `code`, `clicks`, `conversions`,
   `is_default`.** CORRECTED — none of these exist; real equivalents are
   `target_name`, `short_url`/`destination_url`, `tracking_code`, `click_count`,
   `conversion_count`, and there is no default flag. Source as #3.
5. **List response wrapper is `{ links: [...] }` (`AffiliateLinkListOut`).**
   VERIFIED — `src/api/endpoints/affiliates.ts: AffiliateLinkListOut`;
   `AffiliateDashboard.tsx` reads `data?.links ?? []`.
6. **Earnings (total earned / revenue / counts) are derived client-side from
   the links payload.** VERIFIED (behavior) — `AffiliateDashboard.tsx` renders
   per-link `commission_earned_cents` via `formatCents` and has no summary call;
   aggregation across links is the Android-side design choice extending that.
7. **Pending/paid commission split + total_referrals exist for affiliates.**
   CORRECTED — that shape is `ReferralDashboardStats`
   (`src/api/types.ts: ReferralDashboardStats` — `total_earned_cents`,
   `pending_commission_cents`, `paid_commission_cents`,
   `available_for_withdrawal_cents`, …) served by `GET /ui/referrals/dashboard`
   (OpenAPI op `dashboard_ui_referrals_dashboard_get`) — a different domain, out
   of scope.
8. **"Recent referral activity" feed (`recent_referrals.items`,
   `display_label`, `amount_cents`, `status`, `ts`, `next_cursor`).** CORRECTED —
   not in any affiliate payload. The nearest real data is the Referrals domain:
   `GET /ui/referrals/referrals` → `ReferralItem{referred_user_id,
   referral_code, status, attributed_at}` and `GET /ui/referrals/commissions` →
   `CommissionListResp{commissions, next_cursor}` (`src/api/types.ts`;
   `src/api/endpoints/referrals.ts`). Out of scope for AND-265.
9. **Calls are session-authenticated with cookies + `X-CSRF-Token`.** VERIFIED —
   `src/api/client.ts`: reads `ui_csrf` cookie and sets `X-CSRF-Token` header,
   `credentials: "include"`. (Note: web also sends `Authorization: Bearer` from
   the auth store; the Android plan relies on the cookie session per AND-011 —
   see Open assumptions.)
10. **401 is handled by a refresh-then-retry flow.** VERIFIED — `src/api/client.ts`
    refreshes via `POST /ui/session/refresh` once on 401, then retries; second
    401 → logout. Matches the AND-013 authenticator design.
11. **422 validation error is a FastAPI `detail` array of `{msg}`.** VERIFIED —
    `src/api/client.ts: normalizeErrorDetail` maps `Array<{msg}>`; OpenAPI lists
    `422: HTTPValidationError` for the links op.
12. **403 (permission/geo) is possible and carries `detail.code`.** VERIFIED —
    `src/api/client.ts` 403 branch handles `detail.code` (`geo_blocked`,
    `role_required`, …).
13. **Operator params `user_sub` / `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` exist
    on the endpoint and are optional; mobile omits them.** VERIFIED — OpenAPI
    `list_links_ui_affiliates_links_get` `parameters` (all `required: false`,
    `anyOf string|null`) in `openapi.pretty.json`.
14. **Route is `affiliates` in the authenticated graph.** VERIFIED —
    `src/App.tsx`: `<Route path="affiliates" element={<AffiliateDashboard />} />`.
15. **Web copies `window.location.origin + short_url` (so `short_url` is a
    relative path needing a web-origin prefix).** VERIFIED —
    `AffiliateDashboard.tsx: handleCopy` does
    `navigator.clipboard.writeText(window.location.origin + url)` with
    `url = link.short_url`.
16. **Timestamps are epoch seconds.** VERIFIED — `AffiliateDashboard.tsx:
    formatDate` does `new Date(ts * 1000)` on `created_at`.
17. **Money fields are integer minor units (cents).** VERIFIED — `revenue_cents`,
    `commission_earned_cents` are `number` cents; web `formatCents` does
    `cents/100` (`src/api/endpoints/affiliates.ts`; `AffiliateDashboard.tsx`).
18. **`commission_percent` / `conversion_rate_pct` are percentages (not money,
    legitimately non-integer).** VERIFIED — web renders `commission_percent`
    as `…%`; both typed `number` in `AffiliateLinkOut`.
19. **Per-link stats endpoint exists for future drill-down.** VERIFIED —
    `GET /ui/affiliates/links/{link_id}/stats` (op
    `link_stats_ui_affiliates_links__link_id__stats_get`) →
    `AffiliateLinkStatsOut` (`src/api/endpoints/affiliates.ts`).
20. **Framework choices** (Jetpack Compose + Material 3, Hilt, Retrofit/OkHttp/
    Moshi, Room, Coroutines/Flow, `NumberFormat`, `ACTION_SEND` chooser,
    `LocalClipboard`). UNVERIFIED-assumption (framework ref) — standard Android
    platform/Jetpack APIs (developer.android.com/jetpack/compose,
    developer.android.com/training/data-storage/room,
    developer.android.com/reference/java/text/NumberFormat,
    developer.android.com/reference/android/content/Intent#ACTION_SEND); inherited
    from the AND-265 stack pins, not contradicted by any source.

### Corrections made

- Removed the fabricated `GET /ui/affiliates/summary` endpoint and `getSummary()`
  method; the dashboard now uses a single `GET /ui/affiliates/links` (§4, §5).
- Replaced the entire invented links DTO/schema with the real `AffiliateLinkOut`
  shape; dropped non-existent `label`/`url`/`code`/`clicks`/`conversions`/
  `is_default`; added the real fields (§5, §6).
- Removed the `AffiliateSummaryDto`/`AffiliateEarningsDto`/`AffiliateReferralsDto`/
  `AffiliateReferralDto` DTOs and the `AffiliateReferral`/`ReferralStatus` domain
  types; `AffiliateEarnings` is now a client-side aggregation; added `LinkStatus`
  (§6).
- Removed the server `currency`/`as_of`/pending-paid split (don't exist); earnings
  are derived sums; `asOfLabel` is now the client fetch time (§5, §6, §9, §13).
- Repository: two-call concurrent fan-out → single call + client-side aggregation
  (§4, §7). Error/partial-failure logic updated accordingly (§7).
- Clarified that `short_url` is relative and must be prefixed with the web origin
  before copy/share (§5, §6, §14).
- Telemetry: dropped `referral_count` and `is_default`; PII note retargeted from
  `display_label` (referrals) to account ids on the links payload (§8, §10).
- Tests: removed `summary_*` fixtures; added earnings-aggregation and percent
  allow-list cases; T-1 asserts a single no-query request (§11).
- Acceptance criteria 1, 2, 5, 6, 7 reworded to the real contract (§14).
- Frontmatter `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **No server currency code.** The affiliate payload omits currency (web hardcodes
  `$`). Assumed device-default currency formatting; unverifiable from sources
  whether amounts are always account-currency. (§9, §13)
- **Cookie-only auth on Android.** Web sends both the `ui_csrf`/cookie session and
  an `Authorization: Bearer` token (`src/api/client.ts`). The Android plan assumes
  the cookie+CSRF session (AND-011/012) suffices for `/ui/*`; whether the backend
  also requires a bearer for these endpoints is not provable from the spec/types
  and must be confirmed against a live call.
- **Enrollment behavior** (`200` empty vs `403`/`404` for non-enrolled users) is
  not expressed in the OpenAPI/frontend; assumed empty `200` → `Empty`. (§13)
- **Whether a referral-activity feed belongs on this screen.** Product decision;
  data would come from the separate Referrals domain. (§13)
- **15-min stale threshold and Room snapshot caching** are Android-side design,
  not derivable from the web reference (which uses react-query in-memory caching).

## 17. Test Plan

Acceptance-criteria references (AC-#) point at §14. Test targets: JVM =
JVM/Robolectric local; Emu = headless AVD `test35` (x86_64, API 35); Device =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build host.

- **TC-AND-265-01 — Links endpoint path/verb, no query params.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200 links_full.json`. Steps: call `AffiliateApi.getLinks()`; capture
  `RecordedRequest`. Expected: method `GET`, path exactly `/ui/affiliates/links`
  (no `?`), no `summary` request issued. Traces: AC-7.

- **TC-AND-265-02 — Happy-path decode + mapping.**
  Type: unit. Target: JVM. Preconditions: `links_full.json` (multi-link).
  Steps: decode → map to domain. Expected: all `AffiliateLink` fields populated;
  `revenue`/`commissionEarned` are `Money(cents)`; `commissionPercent`/
  `conversionRatePct` preserved as percentages; `createdAt` treated as epoch
  seconds; unknown `status` → `LinkStatus.OTHER`. Traces: AC-1, AC-2, AC-5.

- **TC-AND-265-03 — Client-side earnings aggregation.**
  Type: unit. Target: JVM. Preconditions: links fixture with 3 links of known
  cents/counts. Steps: build `AffiliateEarnings`. Expected: `totalEarned` =
  Σ `commission_earned_cents`, `totalRevenue` = Σ `revenue_cents`, `totalClicks`/
  `totalConversions`/`linkCount` correct; result is `Money` with no `Double` in
  the sum path. Traces: AC-1, AC-5.

- **TC-AND-265-04 — Defaults tolerance for sparse payload.**
  Type: contract/MockWebServer. Target: JVM. Preconditions:
  `links_missing_optional.json` (only `link_id` present per link). Steps: decode +
  map. Expected: no throw; numerics default to 0, strings to ""; row still
  renders. Traces: AC-1, AC-3.

- **TC-AND-265-05 — Money invariant guard.**
  Type: unit. Target: JVM. Preconditions: none. Steps: reflect over `Money`,
  `AffiliateEarnings`, and domain cents fields. Expected: no `Float`/`Double` in
  the money graph; the display-only `commissionPercent`/`conversionRatePct`
  percentages are the only `Double`s and are explicitly allow-listed. Traces: AC-5.

- **TC-AND-265-06 — ViewModel state machine.**
  Type: unit. Target: JVM (Turbine/MockK). Preconditions: fake repo. Steps:
  emit Loading → success / empty `links` / failure. Expected: `Loading` →
  `Ready` (with derived earnings) on success; empty `links` → `Empty`; failure →
  `Error(recoverable=true)`. Traces: AC-1, AC-3.

- **TC-AND-265-07 — Offline/stale with cache (flaky dev host).**
  Type: unit. Target: JVM. Preconditions: Room snapshot present + aged > 15 min;
  connectivity probe = offline (AND-017) / network call fails. Steps: observe
  dashboard. Expected: stale `Ready` emitted with `isStale=true` (drives "Showing
  saved data" banner + timestamp); no cache + offline → `Offline`. Traces: AC-3.

- **TC-AND-265-08 — Error envelope mapping (422/403/500).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `422`
  (`detail:[{msg}]`), `403` (`detail.code=role_required`), `500`. Steps: call +
  map via shared adapter (AND-015). Expected: 422/403 → non-recoverable `Error`
  with mapped message; 500 → recoverable `Error` (Retry). Traces: AC-3.

- **TC-AND-265-09 — Copy uses web-origin-prefixed short_url.**
  Type: unit. Target: JVM. Preconditions: link with `short_url="/r/abc123"`.
  Steps: invoke `onCopyLink`. Expected: `AffiliateEffect.CopyToClipboard` carries
  the full URL (configured web origin + `short_url`), not the raw relative path or
  the API host. Traces: AC-2.

- **TC-AND-265-10 — Dashboard renders (Compose).**
  Type: Compose-UI. Target: Emu. Preconditions: `Ready` state with links +
  derived earnings. Steps: set content; assert nodes. Expected: earnings card and
  each link row (label, truncated URL, clicks, conversions, %, earned) visible;
  satisfies "Affiliate dashboard renders". Skeletons shown for `Loading`. Traces:
  AC-1.

- **TC-AND-265-11 — Empty/error/offline affordances + Retry (Compose).**
  Type: Compose-UI. Target: Emu. Preconditions: each of `Empty`/`Error`/`Offline`.
  Steps: render; tap Retry on `Error`. Expected: correct state UI; Retry invokes
  its callback once. Traces: AC-3.

- **TC-AND-265-12 — Pull-to-refresh forces network (Compose).**
  Type: Compose-UI. Target: Emu. Preconditions: `Ready`. Steps: trigger pull
  gesture. Expected: `onRefresh` invoked; `isRefreshing` toggles; a network fetch
  bypassing cache is issued. Traces: AC-4.

- **TC-AND-265-13 — Real Share chooser + clipboard on device.**
  Type: instrumented/e2e. Target: **Device (must)** — `ACTION_SEND` chooser and
  real clipboard behavior should be exercised on physical hardware, not the
  headless emulator. Preconditions: app on `Ready`. Steps: tap Share, then Copy.
  Expected: system share sheet appears with the full referral URL as
  `EXTRA_TEXT`; Copy places the full URL on the clipboard and shows the snackbar.
  Traces: AC-2.

- **TC-AND-265-14 — Redaction & logout cache-clear.**
  Type: unit + instrumented. Target: JVM (log capture) + Emu (Room). Preconditions:
  a load with non-zero amounts; then trigger logout cleanup (AND-032). Steps:
  scan captured logs/telemetry; query the snapshot DAO after `clear()`. Expected:
  no amounts, URLs, tracking codes, or account ids in logs/telemetry; snapshot
  table empty after logout. Traces: AC-6.

- **TC-AND-265-15 — Accessibility semantics.**
  Type: Compose-UI (a11y). Target: Emu. Preconditions: `Ready`. Steps: assert
  semantics. Expected: KPI cards and link rows have content descriptions; Copy/
  Share buttons have labels + ≥48dp targets; status chip conveys state by
  text/glyph (not color only). Traces: AC-1, AC-2.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (dashboard renders: derived earnings + links) | TC-02, TC-03, TC-06, TC-10, TC-15 |
| AC-2 (link row fields; copy/share full URL) | TC-02, TC-09, TC-13, TC-15 |
| AC-3 (loading/empty/error/offline + Retry) | TC-04, TC-06, TC-07, TC-08, TC-11 |
| AC-4 (pull-to-refresh bypasses cache) | TC-12 |
| AC-5 (integer cents end-to-end; no Float/Double in money graph) | TC-02, TC-03, TC-05 |
| AC-6 (redaction; cache cleared on logout) | TC-14 |
| AC-7 (single idempotent GET, no query params on wire) | TC-01 |
| AC-8 (unit/MockWebServer/Compose tests green in CI) | TC-01..TC-12, TC-14, TC-15 (CI suites) |
