---
id: AND-265
title: Affiliates dashboard
milestone: M6
epic: E36
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: []
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

**Retrofit interface** (`feature-affiliates/.../data/AffiliateApi.kt`). Two
idempotent GETs cover links + earnings; the dashboard issues both concurrently.

```kotlin
package com.testlogon.android.feature.affiliates.data

import retrofit2.http.GET
import retrofit2.http.Query

interface AffiliateApi {

    /** Affiliate links + per-link metrics. OpenAPI: affiliate_links_ui_affiliates_links_get */
    @GET("ui/affiliates/links")
    suspend fun getLinks(): AffiliateLinksDto

    /** Affiliate earnings summary + recent referrals. OpenAPI: affiliate_summary_ui_affiliates_summary_get */
    @GET("ui/affiliates/summary")
    suspend fun getSummary(
        @Query("limit") recentLimit: Int = 10,
        @Query("cursor") cursor: String? = null,
    ): AffiliateSummaryDto
}
```

Retrofit omits `@Query` params whose value is `null`, so `cursor=null` is never
serialised. The session cookie + CSRF header are attached uniformly by the shared
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
    val earnings: AffiliateEarnings,
    val recentReferrals: List<AffiliateReferral>,
    val currency: String,
    val asOf: Instant,
    val isStale: Boolean = false,
)
```

`AffiliateRepositoryImpl` (Hilt `@Singleton`) calls `getLinks()` and
`getSummary()` concurrently (`coroutineScope { val a = async {…}; val b =
async {…} }`), maps both DTOs to domain models, combines into
`AffiliateDashboard`, writes the result to a Room snapshot, and emits
**cache-first then network** via `observeDashboard()`. Both sub-calls must
resolve; a partial failure falls back to cache (stale) else error — no
half-rendered dashboard. The `apiCall {}` wrapper (AND-018) converts
throwables/HTTP errors into `ApiResult.Failure` with `detail` mapping (AND-015).

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
`X-CSRF-Token`). All money fields are integer **minor units (cents)**. Both
operations are **idempotent GETs** → eligible for bounded backoff retry
(AND-016) and the 401→refresh→retry path (AND-013).

**GET `/ui/affiliates/links`** → `200 AffiliateLinksOut`

```json
{
  "links": [
    {
      "link_id": "afl_01H...",
      "label": "Default link",
      "url": "https://testlogon.com/r/abc123",
      "code": "abc123",
      "clicks": 1840,
      "conversions": 92,
      "is_default": true
    }
  ]
}
```

**GET `/ui/affiliates/summary?limit={1..50}&cursor={opaque}`** →
`200 AffiliateSummaryOut`

```json
{
  "currency": "USD",
  "as_of": "2026-06-05T12:00:00Z",
  "earnings": {
    "total_earned_cents": 482731,
    "pending_cents": 120000,
    "paid_cents": 362731,
    "total_referrals": 92,
    "total_clicks": 1840,
    "total_conversions": 92
  },
  "recent_referrals": {
    "items": [
      {
        "referral_id": "afr_01H...",
        "display_label": "@fan_eric",
        "amount_cents": 1500,
        "status": "pending",
        "ts": 1748000000
      }
    ],
    "next_cursor": "eyJrIjoiYWZyXzAxSCJ9"
  }
}
```

`status` ∈ `pending | paid | reversed` (lenient: unknown → `OTHER`).

**Error envelope** (FastAPI `detail`, mapped by AND-015): `401` (handled
transparently by the refresh authenticator), `422` validation
(`detail: [{msg}]`), `5xx`/timeout → recoverable error surfaced as Retry.
Empty/zero data (no links, zeroed earnings, empty `items`) is a **200 with
empty arrays / zeroed totals**, not an error → empty/empty-region state. This
ticket relies on the shared error adapter and does not re-map errors.

## 6. Data & State Management

**DTOs** (`com.testlogon.android.feature.affiliates.data.dto`, Moshi codegen;
every field defaulted so partial payloads still decode):

```kotlin
@JsonClass(generateAdapter = true)
data class AffiliateLinksDto(
    val links: List<AffiliateLinkDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AffiliateLinkDto(
    @Json(name = "link_id") val linkId: String,
    val label: String = "",
    val url: String,
    val code: String = "",
    val clicks: Long = 0,
    val conversions: Long = 0,
    @Json(name = "is_default") val isDefault: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class AffiliateSummaryDto(
    val currency: String = "USD",
    @Json(name = "as_of") val asOf: String? = null,
    val earnings: AffiliateEarningsDto = AffiliateEarningsDto(),
    @Json(name = "recent_referrals") val recentReferrals: AffiliateReferralsDto = AffiliateReferralsDto(),
)

@JsonClass(generateAdapter = true)
data class AffiliateEarningsDto(
    @Json(name = "total_earned_cents") val totalEarnedCents: Long = 0,
    @Json(name = "pending_cents") val pendingCents: Long = 0,
    @Json(name = "paid_cents") val paidCents: Long = 0,
    @Json(name = "total_referrals") val totalReferrals: Long = 0,
    @Json(name = "total_clicks") val totalClicks: Long = 0,
    @Json(name = "total_conversions") val totalConversions: Long = 0,
)

@JsonClass(generateAdapter = true)
data class AffiliateReferralsDto(
    val items: List<AffiliateReferralDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class AffiliateReferralDto(
    @Json(name = "referral_id") val referralId: String,
    @Json(name = "display_label") val displayLabel: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    val status: String = "",
    val ts: Long = 0,
)
```

**Domain models** (`com.testlogon.android.feature.affiliates.model`; money as
`Money(amountCents, currencyCode)`):

```kotlin
data class Money(val amountCents: Long, val currencyCode: String)

data class AffiliateLink(
    val id: String, val label: String, val url: String, val code: String,
    val clicks: Long, val conversions: Long, val isDefault: Boolean,
)
data class AffiliateEarnings(
    val totalEarned: Money, val pending: Money, val paid: Money,
    val totalReferrals: Long, val totalClicks: Long, val totalConversions: Long,
)
data class AffiliateReferral(
    val id: String, val displayLabel: String, val amount: Money,
    val status: ReferralStatus, val rawStatus: String, val timestampEpochSeconds: Long,
)
enum class ReferralStatus { PENDING, PAID, REVERSED, OTHER;
    companion object { fun from(raw: String): ReferralStatus = /* lenient */ }
}
```

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
        val recentReferrals: List<ReferralRowUi>,
        val isStale: Boolean,
        val asOfLabel: String,
        val isRefreshing: Boolean,
    ) : AffiliatesUiState
}

data class AffiliateLinkUi(val id: String, val label: String, val url: String,
    val clicks: String, val conversions: String, val isDefault: Boolean)
data class EarningsSummaryUi(val totalEarned: String, val pending: String, val paid: String,
    val referrals: String, val clicks: String, val conversions: String)
data class ReferralRowUi(val id: String, val label: String, val amount: String,
    val status: ReferralStatus, val whenLabel: String)

sealed interface AffiliateEffect {
    data class CopyToClipboard(val url: String) : AffiliateEffect
    data class ShareUrl(val url: String) : AffiliateEffect
}
```

- VM exposes a single `StateFlow<AffiliatesUiState>` (`WhileSubscribed(5_000)`,
  initial `Loading`). `Ready.isStale` drives the "Showing saved data" banner;
  `asOfLabel` is the formatted `asOf` (or fetch time).
- The Room snapshot is the single source of truth for offline. The repo never
  returns a partial dashboard (both links + summary must resolve).
- Mapping is pure/total; `as_of` parsed inside `runCatching`, degrading to the
  device fetch time when absent/malformed.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the global OkHttp ~20s timeouts (AND-009); a timeout
  surfaces as recoverable `Error`, or `Offline` if the connectivity probe
  (AND-017) reports no network.
- **Retry/backoff:** both endpoints are idempotent GETs and pass through the
  AND-016 retry interceptor; the user-facing Retry/refresh is the fallback after
  automatic retries are exhausted.
- **401:** handled transparently by the refresh authenticator (AND-013); a
  second 401 propagates as auth failure and the auth-gated router (AND-025)
  ejects to login — the affiliates VM does not special-case it.
- **Partial failure:** if `getLinks()` succeeds but `getSummary()` fails (or
  vice versa), the combined call fails → fall back to cached snapshot if present
  (stale `Ready`) else `Error`/`Offline`. No half-rendered dashboard.
- **Stale data:** a cached snapshot older than 15 min renders with the stale
  banner while a background refresh runs; success replaces it silently.
- **Malformed/missing fields:** Moshi defaults absent numeric fields to 0 and
  arrays to empty, so a partially-populated `200` still decodes; only
  `link_id`/`url` (links) and `referral_id` (referrals) are required, matching
  the backend `required` lists.
- **Empty vs. error:** an all-zero / empty-array `200` maps to `Empty`
  (full-screen) when nothing exists at all, or to per-region inline empties when
  only one region is empty (e.g. earnings present but no links yet).
- **Unreliable dev host:** plaintext HTTP with intermittent 5xx is covered by
  shared retry + the offline/stale path; mapping is side-effect-free and safe to
  call repeatedly.

## 8. Security & Privacy

- All affiliate endpoints are session-gated; auth rides on the persistent cookie
  jar (AND-011) and the `X-CSRF-Token` header (AND-012). No tokens or
  credentials are handled in this ticket.
- Affiliate **commission amounts and balances are sensitive financial PII** and
  MUST NOT be logged (see §10) or placed in URLs.
- Referral `display_label` may contain another user's handle/identifier (PII).
  It is rendered only as supplied (the backend is responsible for masking) and
  MUST NOT be logged. Do not derive or expand it client-side.
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

- All KPI cards, link rows, and referral rows expose `contentDescription` /
  `semantics`. A totals card reads as "Total earned, 4,827 dollars 31 cents".
  Copy/Share `IconButton`s have descriptive labels ("Copy referral link",
  "Share referral link") and ≥48dp touch targets.
- The status chip is not color-only: a glyph/text label accompanies the color
  (pending/paid/reversed). Contrast meets 4.5:1 on Material 3 tokens (AND-019).
- All UI strings live in `strings.xml` (`feature-affiliates`); no hardcoded text.
  Status labels are mapped through a localized table, not raw API enums.
- Currency formatted via `NumberFormat.getCurrencyInstance(locale)` using the
  payload `currency`; never hard-code `$`. Counts formatted via
  `NumberFormat.getIntegerInstance(locale)`. Relative timestamps via a localized
  relative-time formatter.
- Dynamic type / large font scaling supported without truncating KPI values
  (auto-size or wrap). Layouts use logical start/end paddings (RTL-safe). Long
  referral URLs truncate with `TextOverflow.Ellipsis` while the full URL remains
  available to the Copy/Share actions and to TalkBack.

## 10. Telemetry & Logging

Events via the app analytics facade (no raw monetary values, no PII labels):

- `affiliates_view_opened {}`
- `affiliates_load_result { outcome: success|empty|error|offline|stale, latency_ms, link_count, referral_count }`
- `affiliates_refresh_invoked { trigger: pull|retry }`
- `affiliates_link_copied { is_default }`   (no URL, no code)
- `affiliates_link_shared { is_default }`   (no URL, no code)

Logging: redacted structured logs at `Timber` debug for cache hit/miss and stale
decisions; **amounts, balances, referral labels, link URLs, and codes are never
logged** (only presence/counts). Network logging follows the OkHttp interceptor
policy (AND-009/AND-052): `BASIC` in debug, `NONE` in release — bodies are never
emitted. A single non-PII debug line on decode failure
(`AffiliateApi: decode failed for <endpoint>`, no body) is permitted.

## 11. Testing Strategy

**MockWebServer (AND-046 harness + fixtures), JVM unit:**
golden JSON fixtures `links_full.json`, `links_empty.json`, `summary_full.json`,
`summary_empty.json` (zeroed + empty items), `summary_missing_optional.json`,
plus `422` and `500` bodies.
- **T-1 Path/verb/query:** assert `GET /ui/affiliates/links` and
  `GET /ui/affiliates/summary?limit=10`; assert `cursor=null` is **absent** from
  the query string.
- **T-2 Mapping:** `links_full.json` and `summary_full.json` decode and map with
  every field asserted, including `Money` cents + currency and
  `ReferralStatus.from` (unknown status → `OTHER`).
- **T-3 Defaults tolerance:** `summary_missing_optional.json` decodes with
  zeroed earnings, empty `items`, `currency == "USD"`, no throw.
- **T-4 Money invariant:** reflection guard — no `Float`/`Double` anywhere in the
  DTO/domain graph.

**Unit (JUnit/Turbine/MockK):**
- `AffiliateRepositoryImplTest`: concurrent links+summary combine; cache-first
  emission then network re-emit; partial failure → falls back to cache/error;
  15-min stale threshold; `clear()` empties the DAO.
- `AffiliatesViewModelTest`: initial `Loading` → `Ready` on success;
  all-empty → `Empty`; error → `Error(recoverable=true)`; offline-with-cache →
  stale `Ready` + banner; refresh sets then clears `isRefreshing`; `onCopyLink`
  / `onShareLink` emit the correct one-shot effects.

**Compose UI tests (AND-051 headless emulator):**
`AffiliatesScreen` renders earnings cards, link rows, and referral rows for
`Ready` (satisfies "Affiliate dashboard renders"); skeletons for `Loading`;
empty/error/offline states show correct affordances; Retry invokes its callback;
Copy/Share buttons invoke their callbacks; semantics nodes present for a11y.

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
  ticket as a dependency). A future "affiliate referrals — full paginated list"
  E36 ticket, if created, would build on the cursor surfaced here.
- **Sequencing:** land `AffiliateApi` + DTOs + mappers + `AffiliateRepository`
  + ViewModel + screen + tests together; merge to `android-port` after the auth
  network baseline (AND-027) and the shared UI/nav primitives (AND-019/021/024).

## 13. Risks & Open Questions

- **Endpoint shape unconfirmed.** Exact `/ui/affiliates/*` paths and field names
  must be verified against `/openapi.json` and `frontend/src/api/endpoints/affiliates.ts`
  before implementation; the DTOs here mirror the web reference and the sibling
  earnings contract (AND-251) but are provisional. If the backend returns links
  and earnings from a single combined endpoint, collapse to one GET (one `async`).
- **Enrollment gate.** Whether a non-enrolled user gets `200` empty vs. `403`/`404`
  is unspecified. Current design treats empty `200` as the `Empty` state; a
  `403` would surface as `Error` — confirm and, if needed, add an explicit
  "not enrolled / join program" empty variant (deferred to E36 onboarding).
- **Referral label PII.** Assumes the backend masks/limits `display_label`. If it
  returns full PII, product must confirm it is acceptable to display; client does
  no additional masking in this ticket.
- **Currency mixing.** Assumes a single account currency for affiliate earnings;
  multi-currency commissions would require model revision (flag for product).
- **Pending vs. paid semantics** (is `paid` included in `total_earned`? does
  `pending` become a Payouts balance?) are unspecified — flag for the Payouts
  epic (E35); the UI faithfully renders whatever the payload states.
- **`FLAG_SECURE`** screenshot suppression on this financial screen is deferred
  to a hardening ticket.

## 14. Acceptance Criteria

1. Navigating to `affiliates` from the authenticated graph (More hub) fetches
   and **renders the affiliate dashboard** from the dev backend: the earnings
   summary (total earned / pending / paid + referral counts), the referral
   links list, and the recent-referral activity list — satisfying *Affiliate
   dashboard renders*.
2. Each link row shows label, (truncated) URL, clicks, and conversions; **Copy**
   copies the full URL to the clipboard with a snackbar confirmation, and
   **Share** launches the Android share chooser with the full URL.
3. Loading shows skeletons; an all-empty `200` shows the empty state; a
   `5xx`/timeout shows a recoverable error with a working Retry;
   offline-with-cache shows stale data + "Showing saved data" banner + timestamp;
   offline-no-cache shows the offline state.
4. Pull-to-refresh forces a network fetch bypassing cache.
5. Money is carried as integer cents end-to-end and only formatted to major
   units at display with locale-correct currency formatting; no `Float`/`Double`
   exists in the DTO/domain graph (guard test passes).
6. No monetary values, referral labels, link URLs, or codes appear in logs or
   telemetry (verified by a redaction test); the affiliate cache is cleared on
   logout (AND-032).
7. Both endpoints are called as idempotent GETs with `null` query params omitted
   from the wire request (proved by `MockWebServer` `RecordedRequest`).
8. Unit, MockWebServer, and Compose UI tests (§11) pass in CI (AND-050/AND-051).

## 15. Definition of Done

- `feature-affiliates` module created, wired into `settings.gradle.kts` and the
  `app` module, building under AGP 8.7.3 / Gradle 8.9 / JDK 17 under the
  canonical `com.testlogon.android.feature.affiliates` package.
- `AffiliateApi`, `AffiliateNetworkModule`, all DTOs, domain models,
  `ReferralStatus`, mappers, `AffiliateRepository`(+Impl), the Room snapshot
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
