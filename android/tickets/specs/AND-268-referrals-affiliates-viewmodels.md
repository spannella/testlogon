---
id: AND-268
title: Referrals/affiliates ViewModels
milestone: M6
epic: E36
priority: P2
size: M
depends_on: [AND-264]
blocks: [AND-269]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-268 — Referrals/affiliates ViewModels

## 1. Overview & Goal

This ticket delivers the state layer (ViewModels + UI state contracts) for the
Referrals/Affiliates feature of the TestLogon native Android app. AND-264 builds
the Referrals data path (repository, DTOs, mappers, screen skeleton mirroring the
web reference `referrals.ts`); this ticket owns the **ViewModel** tier that sits
between that repository and Compose UI.

The goal is to expose lifecycle-aware, test-driven `StateFlow<UiState>` holders
for the two referrals surfaces — the **referral overview** (link + stats + share)
and the **affiliate dashboard** (payout/conversion stats and history) — together
with the user intents that drive them (load, refresh, copy link, share link,
retry, page affiliate history). All asynchronous work is performed off the main
thread via Coroutines, surfaces are restored after process death via
`SavedStateHandle`, and every state transition is unit-tested per the ticket's
acceptance bullet (`Unit-tested`). No Composable rendering, navigation wiring, or
repository implementation is in scope here — those belong to AND-264 (data/UI
skeleton) and AND-269 (repo + UI tests).

Concretely, "done" means: `ReferralViewModel` and `AffiliateViewModel` exist in
`feature-referrals`, each exposing an immutable sealed `UiState` via `StateFlow`,
each consuming `ReferralRepository` through `ApiResult<T>`, and each covered by
deterministic JVM unit tests using `core-testing` (fake repository +
`MainDispatcherRule` + Turbine).

## 2. Context & References

- **Module:** `feature-referrals` (layer: `app -> feature-referrals -> core-*`).
- **Depends on AND-264 — Referrals:** provides `ReferralRepository`,
  `core-model` DTO/domain types mirroring the web reference DTOs
  (`ReferralDashboardStats`, `ReferralCode`, `AffiliateCommission`,
  `AffiliateLinkOut`), Moshi adapters, and the FastAPI error `detail`
  mapping into `ApiResult.Error`. AND-268 must not redefine these; it
  consumes them. (CORRECTED: earlier draft cited `ReferralOverview`,
  `ReferralStats`, `AffiliateSummary`, `AffiliateConversion`, which do
  not exist in the web reference `src/api/types.ts`; the canonical names
  are as listed here. Kotlin domain names may differ but must map to
  these wire shapes.)
- **Blocks AND-269 — Referrals/affiliates tests:** AND-269 adds repository and
  Compose UI tests. The ViewModel-level unit tests required by *this* ticket's
  acceptance criteria are written here; AND-269 builds on top, it does not
  replace them.
- **Web reference:** `frontend/src/api/endpoints/referrals.ts` and shared types
  in `frontend/src/api/types.ts` define the canonical request/response shapes and
  field names; Kotlin DTOs (owned by AND-264) mirror these.
- **Platform conventions:** ViewModels expose `StateFlow<UiState>`; all repo
  calls return typed `ApiResult<T>`; Hilt (KSP) provides dependencies;
  `core-testing` provides `MainDispatcherRule` and fakes. Stack per project
  context: Kotlin 2.0.21, Coroutines/Flow, Hilt, Paging 3 (affiliate history),
  Retrofit/OkHttp/Moshi behind the repository, minSdk 24 / compileSdk 35.
- **Namespace:** `com.testlogon.android.feature.referrals`.

## 3. Functional Requirements

FR-1 **Referral overview load.** On first collection the `ReferralViewModel`
loads the user's referral link and aggregate stats and emits `Loading` then
`Content` or `Error`.

FR-2 **Pull-to-refresh.** A `Refresh` intent re-fetches overview data. While
refreshing with existing content, the prior `Content` remains visible and a
`isRefreshing` flag is true (no full-screen spinner flash).

FR-3 **Copy link.** A `CopyLink` intent surfaces the canonical referral URL to
the UI as a one-shot effect for clipboard handling (the actual `ClipboardManager`
call is a UI concern; the ViewModel emits the payload + a confirmation effect).

FR-4 **Share link.** A `ShareLink` intent emits a one-shot effect carrying the
share text (link + short message) for the Android share sheet. No share intent is
built inside the ViewModel.

FR-5 **Affiliate dashboard load.** `AffiliateViewModel` loads affiliate summary
stats (clicks, signups, conversions, pending/paid earnings) and the paged
conversion history.

FR-6 **Affiliate history paging.** Conversion history is exposed as a
`Flow<PagingData<AffiliateConversion>>` (Paging 3), cached in `viewModelScope`.

FR-7 **Retry.** From an `Error` state, a `Retry` intent re-runs the failed load.

FR-8 **Empty states.** When the user has no referrals/affiliate activity, the
ViewModel emits a `Content` with `isEmpty = true` (not an error).

FR-9 **State restoration.** The selected dashboard tab/segment and last
successful overview are restored after process death via `SavedStateHandle`.

FR-10 **No duplicate in-flight loads.** A second load/refresh intent while a load
is in flight is ignored (guarded), preventing redundant network calls against the
unreliable dev backend.

## 4. Technical Design

Two ViewModels in `feature-referrals`, both Hilt-injected and constructed with the
AND-264 repository and a `SavedStateHandle`.

```kotlin
package com.testlogon.android.feature.referrals

@HiltViewModel
class ReferralViewModel @Inject constructor(
    private val repository: ReferralRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<ReferralUiState>(ReferralUiState.Loading)
    val uiState: StateFlow<ReferralUiState> = _uiState.asStateFlow()

    private val _effects = Channel<ReferralEffect>(Channel.BUFFERED)
    val effects: Flow<ReferralEffect> = _effects.receiveAsFlow()

    private var loadJob: Job? = null

    init { onIntent(ReferralIntent.Load) }

    fun onIntent(intent: ReferralIntent) {
        when (intent) {
            ReferralIntent.Load    -> load(refresh = false)
            ReferralIntent.Refresh -> load(refresh = true)
            ReferralIntent.Retry   -> load(refresh = false)
            ReferralIntent.CopyLink  -> emitLinkEffect(share = false)
            ReferralIntent.ShareLink -> emitLinkEffect(share = true)
        }
    }

    private fun load(refresh: Boolean) {
        if (loadJob?.isActive == true) return            // FR-10 guard
        val current = _uiState.value
        if (refresh && current is ReferralUiState.Content) {
            _uiState.value = current.copy(isRefreshing = true)
        } else if (current !is ReferralUiState.Content) {
            _uiState.value = ReferralUiState.Loading
        }
        loadJob = viewModelScope.launch {
            // GET /ui/referrals/dashboard -> ReferralDashboardStats
            // (includes referral_codes[]). There is NO /ui/referrals/overview
            // endpoint and no single referral_url field; the share/copy link is
            // derived per code as "<origin>/?ref=<code>" (see web reference).
            when (val r = repository.getReferralDashboard()) {
                is ApiResult.Success -> _uiState.value =
                    ReferralUiState.Content(
                        dashboard = r.data,
                        isEmpty = r.data.referralCodes.isEmpty() &&
                            r.data.totalReferrals == 0,
                        isRefreshing = false,
                    )
                is ApiResult.Error -> _uiState.value = current.toErrorOrReplace(r.error)
            }
        }
    }
    // emitLinkEffect / toErrorOrReplace omitted for brevity
}
```

```kotlin
sealed interface ReferralUiState {
    data object Loading : ReferralUiState
    data class Content(
        val dashboard: ReferralDashboardStats, // maps GET /ui/referrals/dashboard
        val isEmpty: Boolean = false,
        val isRefreshing: Boolean = false,
    ) : ReferralUiState
    data class Error(val message: UiText, val retryable: Boolean) : ReferralUiState
}

sealed interface ReferralIntent {
    data object Load : ReferralIntent
    data object Refresh : ReferralIntent
    data object Retry : ReferralIntent
    data object CopyLink : ReferralIntent
    data object ShareLink : ReferralIntent
}

sealed interface ReferralEffect {
    data class CopyToClipboard(val url: String) : ReferralEffect
    data class ShowShareSheet(val shareText: String) : ReferralEffect
}
```

`AffiliateViewModel` follows the same shape.

> CORRECTED: The earlier draft modeled affiliates as an aggregate
> `AffiliateSummary` plus a paged `Flow<PagingData<AffiliateConversion>>`
> from `affiliateConversionsPager()`. Neither exists in the backend nor the
> web reference. The affiliate surface (`src/pages/affiliates/AffiliateDashboard.tsx`)
> is a **list of affiliate links** fetched via `GET /ui/affiliates/links`
> (`AffiliateLinkListOut { links: AffiliateLinkOut[] }`); each link embeds its
> own counters (`click_count`, `conversion_count`, `commission_earned_cents`,
> `conversion_rate_pct`, …). The only **cursor-paged** list in this feature is
> referral **commission** history: `GET /ui/referrals/commissions?limit&cursor`
> → `CommissionListResp { commissions: AffiliateCommission[], next_cursor }`.
> The Paging 3 flow below therefore drives referral commissions, and the
> affiliate dashboard holds a plain list of links (small, not paged).

```kotlin
@HiltViewModel
class AffiliateViewModel @Inject constructor(
    private val repository: ReferralRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AffiliateUiState>(AffiliateUiState.Loading)
    val uiState: StateFlow<AffiliateUiState> = _uiState.asStateFlow()

    val selectedTab: StateFlow<AffiliateTab> =
        savedState.getStateFlow(KEY_TAB, AffiliateTab.Overview)

    fun selectTab(tab: AffiliateTab) { savedState[KEY_TAB] = tab }

    fun onIntent(intent: AffiliateIntent) { /* Load / Refresh / Retry */ }

    private companion object { const val KEY_TAB = "affiliate_tab" }
}

sealed interface AffiliateUiState {
    data object Loading : AffiliateUiState
    data class Content(
        val links: List<AffiliateLinkOut>, // GET /ui/affiliates/links -> AffiliateLinkListOut.links
        val isEmpty: Boolean = false,       // links.isEmpty()
        val isRefreshing: Boolean = false,
    ) : AffiliateUiState
    data class Error(val message: UiText, val retryable: Boolean) : AffiliateUiState
}
```

The cursor-paged commission history lives on `ReferralViewModel` (or a
dedicated holder) since it is a **referral** endpoint:

```kotlin
val commissions: Flow<PagingData<AffiliateCommission>> =
    repository.referralCommissionsPager()   // GET /ui/referrals/commissions
        .flow
        .cachedIn(viewModelScope)
```

Design notes:
- **State vs. effects.** Persistent screen state is in `StateFlow<UiState>`;
  transient one-shot actions (clipboard, share sheet, toast) go through a
  `Channel`-backed `Flow<Effect>` consumed once. This avoids re-firing the share
  sheet on recomposition/config change.
- **Refresh preserves content.** `Content.copy(isRefreshing = true)` keeps the
  list visible during refresh; `toErrorOrReplace` keeps existing content on
  refresh failure (degrade gracefully) but transitions to full `Error` when there
  was no prior content (FR-2, FR-7).
- **Single source of stats.** Summary fields come from the domain model emitted by
  AND-264's repository; the ViewModel does no arithmetic beyond `isEmpty`.
- **Hilt:** both ViewModels use `@HiltViewModel` + constructor injection; obtained
  in Compose via `hiltViewModel()` (call sites added in AND-264/UI wiring).

## 5. API Contract

This ticket does **not** define or call HTTP endpoints directly — all network
access is via `ReferralRepository`, owned by **AND-264**. The repository surface
this ViewModel depends on (consumed, not declared here):

```kotlin
interface ReferralRepository {
    suspend fun getReferralDashboard(): ApiResult<ReferralDashboardStats>
    suspend fun createReferralCode(): ApiResult<ReferralCodeCreateResp>
    suspend fun deactivateReferralCode(code: String): ApiResult<Unit>
    fun referralCommissionsPager(): Pager<String, AffiliateCommission> // cursor-keyed
    suspend fun listAffiliateLinks(): ApiResult<List<AffiliateLinkOut>>
}
```

For traceability, the **actual** backend endpoints behind that repository
(verified against `openapi.index.txt` and `src/api/endpoints/referrals.ts` /
`affiliates.ts`) are below. CORRECTED: the earlier draft listed
`GET /ui/referrals/overview`, `GET /ui/affiliates/summary`, and
`GET /ui/affiliates/conversions` — none of these paths exist in the OpenAPI
index. The real endpoints are:

- `GET /ui/referrals/dashboard` → `ReferralDashboardStats`:
  ```json
  {
    "total_referrals": 7,
    "confirmed_referrals": 5,
    "pending_referrals": 2,
    "total_earned_cents": 2500,
    "pending_commission_cents": 800,
    "paid_commission_cents": 1700,
    "available_for_withdrawal_cents": 1700,
    "referral_codes": [
      { "code": "AB12CD", "active": true, "commission_tier": "standard",
        "referral_count": 3, "created_at": "2026-01-02T10:00:00Z" }
    ]
  }
  ```
  There is **no** `referral_url` field; the web client derives the share link
  per code as `"<origin>/?ref=<code>"` (`ReferralDashboard.tsx: copyLink`).
- `GET /ui/referrals/commissions?limit=<n>&cursor=<c>` → `CommissionListResp`:
  ```json
  {
    "commissions": [
      { "source_type": "purchase", "referred_user_id": "u_123",
        "gross_amount_cents": 5000, "net_amount_cents": 4500,
        "commission_cents": 250, "commission_rate_bps": 500,
        "status": "confirmed", "created_at": "2026-02-01T12:00:00Z" }
    ],
    "next_cursor": null
  }
  ```
  This `cursor`/`next_cursor` pair is the cursor key for the Paging 3
  `PagingSource` (AND-264).
- `POST /ui/referrals/code` (201) → `ReferralCodeCreateResp {code, link,
  commission_tier, created_at}`; `DELETE /ui/referrals/codes/{code}` →
  `{ok: boolean}`; `GET /ui/referrals/codes` → `ReferralCode[]`;
  `GET /ui/referrals/referrals` → `ReferralItem[]`;
  `GET /ui/referrals/attribution` → `ReferralAttribution`.
- `GET /ui/affiliates/links` → `AffiliateLinkListOut {links: AffiliateLinkOut[]}`
  (each link embeds `tracking_code`, `short_url`, `click_count`,
  `conversion_count`, `commission_earned_cents`, `conversion_rate_pct`, …).
  Related: `POST /ui/affiliates/links` (201), `GET/DELETE
  /ui/affiliates/links/{link_id}`, `GET /ui/affiliates/links/{link_id}/stats`
  → `AffiliateLinkStatsOut`.

Auth/transport (verified against `src/api/client.ts`): every request is sent
with `credentials: "include"` (cookie session) AND, when present, an
`Authorization: Bearer <accessToken>` header and an optional
`X-IMPERSONATION-TOKEN`; the CSRF token is read from the `ui_csrf` cookie and
sent as the `X-CSRF-Token` header. On a 401 *for an already-authenticated
user*, the client performs a single `POST /ui/session/refresh` and retries the
original request once; a second 401 logs out. (CORRECTED: the earlier draft
described only "cookie session + X-CSRF-Token" and omitted the Bearer token /
impersonation header and the "only-if-authenticated" refresh guard.) These
concerns live in `core-network`/AND-264 and are transparent to the ViewModel,
which only sees `ApiResult.Success`/`ApiResult.Error`.

## 6. Data & State Management

- **Domain models** (`core-model`, from AND-264, mirroring web `types.ts`):
  `ReferralDashboardStats`, `ReferralCode`, `AffiliateCommission` (commission
  history rows), `AffiliateLinkOut` (affiliate link rows). ViewModels hold
  these directly inside `Content` states; no UI-only duplication. (CORRECTED:
  earlier `ReferralOverview`/`ReferralStats`/`AffiliateSummary`/
  `AffiliateConversion` names do not exist in the reference contract.)
- **`UiText`** (`core-ui`): error and label strings are `UiText` (resource id or
  literal) so the ViewModel stays free of `Context`/localized strings —
  formatting happens at render time.
- **Saved state keys:** `affiliate_tab` (`AffiliateTab` enum). The last
  successful `ReferralOverview` is *not* persisted in `SavedStateHandle` (may
  exceed parcel-size comfort and is cheaply re-fetched); on process death the
  ViewModel re-issues `Load`. The cheap UI selection state (tab) is persisted.
- **Caching:** offline/stale reads are the repository's responsibility (Room
  cache per AND-264). The ViewModel treats a `Success` carrying stale data the
  same as fresh; if AND-264 exposes a `stale: Boolean`, it is mapped to
  `Content.isStale` (additive field) for a UI banner.
- **Paging:** the cursor-keyed `commissions` flow (referral commission history,
  `GET /ui/referrals/commissions`) is `cachedIn(viewModelScope)` so scroll
  position and loaded pages survive recomposition and config changes;
  `LoadState` is owned by the Compose `LazyPagingItems` collector (UI), not
  duplicated in `UiState`. The affiliate links list is not paged (single
  `GET /ui/affiliates/links` response).
- **Threading:** every suspend call runs in `viewModelScope` on the default
  dispatcher provided by the repository; the ViewModel itself does no blocking
  work. Tests override `Dispatchers.Main` via `MainDispatcherRule`.

## 7. Error Handling & Resilience

- `ApiResult.Error` carries the mapped FastAPI `detail` (string | `[{msg}]` |
  `{code,...}`) produced by AND-264. The ViewModel converts it to
  `UiText` and a `retryable` flag (network/timeout/5xx → retryable; 4xx
  validation → not retryable, shown inline).
- **Unreliable dev host:** ~20s timeouts and bounded backoff retry for idempotent
  GETs are configured in `core-network` (AND-264). At the ViewModel level
  resilience means: (a) never block UI, (b) keep last good content on refresh
  failure, (c) the in-flight guard (FR-10) prevents request storms, (d) `Retry`
  is always offered for retryable errors.
- **Refresh failure:** if a refresh fails while `Content` is shown, state reverts
  to `Content(isRefreshing = false)` and a transient `ReferralEffect`/
  `AffiliateEffect.ShowMessage(error)` is emitted rather than wiping the screen.
- **Empty vs. error:** zero referrals/conversions is `Content(isEmpty = true)`,
  never `Error` (FR-8).
- **Cancellation:** `viewModelScope` cancels in-flight loads on clear; `loadJob`
  is re-nullable so a cancelled job does not wedge the guard.

## 8. Security & Privacy

- The ViewModel never logs the derived referral share link (`<origin>/?ref=<code>`),
  the referral `code`, the affiliate `tracking_code`/`short_url`, or any earnings
  amounts; the referral code is treated as user-identifying and excluded from
  telemetry payloads (only event names/counts are logged). (Note: there is no
  server-supplied `referral_url`; the link is built client-side from `code`.)
- No tokens, cookies, or CSRF values are visible to or stored by the ViewModel —
  session/cookie handling is entirely in `core-network`'s persistent cookie jar.
- Clipboard/share effects carry only the user's own referral URL and an
  app-supplied marketing sentence; no PII beyond the referral code the user is
  intentionally sharing.
- `SavedStateHandle` persists only the non-sensitive `AffiliateTab` enum.

## 9. Accessibility & i18n

- This is a state-tier ticket; rendering and `contentDescription`/semantics live
  in AND-264's Composables. The ViewModel supports a11y/i18n by emitting `UiText`
  (resource-backed) rather than hardcoded strings, so all user-facing copy is
  localizable and screen-reader friendly downstream.
- Currency/amount fields are exposed as raw integer cents + ISO currency code so
  the UI can format with locale-aware `NumberFormat`; the ViewModel does no
  locale-specific formatting.
- Share/copy confirmation messages are `UiText` resource ids, enabling
  translation and TalkBack announcement at the call site.

## 10. Telemetry & Logging

- Emit analytics events via the injected `Analytics` abstraction (core, no PII):
  `referral_overview_viewed`, `referral_link_copied`, `referral_link_shared`,
  `affiliate_dashboard_viewed`, `affiliate_tab_selected` (param: tab name),
  `referral_load_failed` (param: error category enum, retryable boolean).
- Logs use the structured `Logger` from `core-ui`/`core-data` at `DEBUG` for
  state transitions and `WARN` for `ApiResult.Error`; never log URLs, codes, or
  amounts (see §8). Error logs include the FastAPI error *category*, not raw
  `detail` text that might echo identifiers.

## 11. Testing Strategy

The acceptance bullet for this ticket is **Unit-tested**, so JVM unit tests are
the primary deliverable here (Compose/repo tests are AND-269).

Tooling: JUnit4, `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher`),
`MainDispatcherRule` and a `FakeReferralRepository` from `core-testing`, Turbine
for `StateFlow`/effect assertions, Paging 3 `AsyncPagingDataDiffer`/`asSnapshot`.

Required `ReferralViewModel` cases:
1. init → emits `Loading` then `Content` on repo success
   (`getReferralDashboard()` → `ReferralDashboardStats`).
2. success with `total_referrals == 0` and empty `referral_codes` →
   `Content(isEmpty = true)`.
3. repo error (retryable) from cold start → `Error(retryable = true)`.
4. `Refresh` from `Content` → `isRefreshing = true` then back to `Content`
   (content preserved throughout).
5. `Refresh` failure from `Content` → stays `Content`, emits error effect/message
   (no `Error` state).
6. `Retry` from `Error` re-invokes repo and reaches `Content`.
7. `CopyLink` emits `ReferralEffect.CopyToClipboard(url)` with correct URL.
8. `ShareLink` emits `ReferralEffect.ShowShareSheet(text)`.
9. Concurrent `Load`/`Refresh` while in flight → repository called exactly once
   (FR-10 guard), verified via fake call count.

Required `AffiliateViewModel` cases:
10. affiliate links list success/error/empty mirror cases 1-3
    (`listAffiliateLinks()` → `Content(links)`, empty list → `isEmpty = true`).
11. referral commission paging (`referralCommissionsPager()`,
    `Flow<PagingData<AffiliateCommission>>`) emits expected items snapshot from
    the fake cursor-keyed pager.
12. `selectTab` updates `selectedTab` and survives a new ViewModel built from the
    same `SavedStateHandle` (restoration) → emits persisted tab.
13. `affiliate_tab_selected` analytics event fired on `selectTab`.

Determinism: no real dispatchers, no `delay` on the test thread, all repo
responses driven by the fake. Target ViewModel line coverage ≥ 90%.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-264 (Referrals):** must land first; provides
  `ReferralRepository`, `core-model` domain types, error mapping, and the
  `referralCommissionsPager()` cursor-keyed `PagingSource`
  (`GET /ui/referrals/commissions`). AND-268 cannot compile without it.
- **Transitively — AND-027** (auth/session, via AND-264): a valid cookie session
  is required for the underlying GETs; not directly touched here.
- **Blocks — AND-269 (Referrals/affiliates tests):** repo + Compose UI tests
  build on these ViewModels and the UiState contracts defined here.
- **Sequencing within ticket:** define `UiState`/`Intent`/`Effect` sealed types →
  implement `ReferralViewModel` → `AffiliateViewModel` (+ paging) →
  `SavedStateHandle` wiring → unit tests. UI collection of `effects`/`uiState`
  is wired by AND-264's screen code.

## 13. Risks & Open Questions

- **R1 — AND-264 model/field drift.** If the repository's domain field names
  (e.g., `total_referrals`, earnings cents) differ from §5 assumptions, the
  `isEmpty`/mapping logic needs adjustment. *Mitigation:* depend only on the
  domain interface; treat §5 JSON as illustrative of AND-264's contract.
- **R2 — Paging ownership.** Whether the `Pager` is constructed in the repository
  or the ViewModel. *Decision:* repository exposes the `Pager`/`PagingSource`
  (AND-264); ViewModel only `cachedIn`. Confirm with AND-264 owner.
- **R3 — Stale/offline signaling.** Open question whether AND-264 exposes a
  `stale` flag on success. If not, the `isStale` UI banner is dropped from scope.
- **R4 — Effect vs. state for copy/share.** Using a `Channel` effect risks loss
  if the UI is not collecting; mitigated with `Channel.BUFFERED` and lifecycle-
  aware collection (documented contract for AND-264 UI).
- **Q1 — Are affiliate features gated by an entitlement flag on `/ui/me`?** If so
  a `NotEligible` state may be needed; pending product confirmation.

## 14. Acceptance Criteria

- AC-1 `ReferralViewModel` and `AffiliateViewModel` exist in
  `com.testlogon.android.feature.referrals`, are `@HiltViewModel`, and expose
  `StateFlow<UiState>` (no mutable state leaked).
- AC-2 Referral overview load emits `Loading → Content` on success and
  `Loading → Error` on retryable failure, verified by unit test.
- AC-3 Refresh preserves visible `Content` (`isRefreshing` toggles) and never
  flashes a full-screen spinner; refresh failure keeps `Content`.
- AC-4 `CopyLink`/`ShareLink` emit the correct one-shot effects carrying the
  referral URL / share text.
- AC-5 Affiliate links load (`GET /ui/affiliates/links`) + referral commission
  Paging flow (`GET /ui/referrals/commissions`) emit expected data from the fake
  repository; empty data yields `Content(isEmpty = true)`, not `Error`.
- AC-6 Selected affiliate tab is persisted/restored via `SavedStateHandle`.
- AC-7 Duplicate in-flight load/refresh calls the repository exactly once.
- AC-8 All unit tests in §11 pass deterministically (no real dispatchers/network);
  ViewModel coverage ≥ 90%.
- AC-9 No referral URL/code/earnings values appear in logs or analytics payloads.

## 15. Definition of Done

- Code merged to `android-port` under `android/feature-referrals/` using namespace
  `com.testlogon.android.feature.referrals`, building with the project toolchain
  (Kotlin 2.0.21, AGP 8.7.3, JDK 17, Gradle 8.9, compileSdk 35).
- `UiState`/`Intent`/`Effect` sealed contracts and both ViewModels reviewed and
  merged; no Compose/UI or repository implementation added here.
- All §11 unit tests green in CI; coverage gate met; ktlint/detekt and Android
  Lint clean for the touched module.
- Public ViewModel APIs documented with KDoc; effects-collection contract noted
  for AND-264 UI wiring.
- No new direct Retrofit/OkHttp usage in `feature-referrals` (all I/O via the
  AND-264 repository); Hilt graph compiles via KSP.
- AND-269 can consume these ViewModels without contract changes.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Referral overview/stats endpoint.** Claim (original draft):
   `GET /ui/referrals/overview`. VERDICT: **Corrected** → the real endpoint is
   `GET /ui/referrals/dashboard`. SOURCE: OpenAPI `GET /ui/referrals/dashboard`
   (op `dashboard_ui_referrals_dashboard_get`); `src/api/endpoints/referrals.ts:
   getReferralDashboard`.
2. **Referral dashboard response shape.** Claim: fields
   `total_referrals, confirmed_referrals, pending_referrals, total_earned_cents,
   pending_commission_cents, paid_commission_cents,
   available_for_withdrawal_cents, referral_codes[]`. VERDICT: **Verified /
   Corrected** (original `referral_url`+`stats{pending,rewarded,reward_currency,
   reward_total_cents}` was wrong). SOURCE: `src/api/types.ts:
   ReferralDashboardStats` and `ReferralCode`.
3. **No server `referral_url`; link derived client-side.** Claim: share link is
   `<origin>/?ref=<code>`. VERDICT: **Verified**. SOURCE:
   `src/pages/referrals/ReferralDashboard.tsx: copyLink` (`const link =
   \`${window.location.origin}/?ref=${code}\``).
4. **Affiliate "summary" aggregate endpoint.** Claim (original):
   `GET /ui/affiliates/summary` with `clicks/signups/conversions/earnings_*`.
   VERDICT: **Corrected** → no such endpoint/schema exists; the affiliate surface
   is a list of links. SOURCE: OpenAPI has `GET /ui/affiliates/links` (op
   `list_links_ui_affiliates_links_get`) but no `/ui/affiliates/summary`;
   `src/api/endpoints/affiliates.ts: listAffiliateLinks`.
5. **Affiliate links response shape.** Claim: `AffiliateLinkListOut {links:
   AffiliateLinkOut[]}`, each link with `tracking_code, short_url, click_count,
   unique_click_count, conversion_count, revenue_cents,
   commission_earned_cents, conversion_rate_pct, status, …`. VERDICT:
   **Verified**. SOURCE: `src/api/endpoints/affiliates.ts: AffiliateLinkOut /
   AffiliateLinkListOut`.
6. **Affiliate paged "conversions" endpoint.** Claim (original):
   `GET /ui/affiliates/conversions?cursor&limit` → `items[]`+`next_cursor`.
   VERDICT: **Corrected** → no such endpoint. The only cursor-paged list is
   referral commission history `GET /ui/referrals/commissions?limit&cursor` →
   `CommissionListResp {commissions[], next_cursor}`. SOURCE: OpenAPI
   `GET /ui/referrals/commissions` (params `limit,cursor`);
   `src/api/endpoints/referrals.ts: getReferralCommissions`;
   `src/api/types.ts: CommissionListResp / AffiliateCommission`.
7. **Commission row shape.** Claim: `AffiliateCommission {source_type,
   referred_user_id, gross_amount_cents, net_amount_cents, commission_cents,
   commission_rate_bps, status, created_at}`. VERDICT: **Verified**. SOURCE:
   `src/api/types.ts: AffiliateCommission`.
8. **Create/deactivate referral code.** Claim: `POST /ui/referrals/code` (201)
   → `ReferralCodeCreateResp`; `DELETE /ui/referrals/codes/{code}` → `{ok}`.
   VERDICT: **Verified**. SOURCE: OpenAPI `POST /ui/referrals/code`
   (`create_code_..._post`, resp 201), `DELETE /ui/referrals/codes/{code}`
   (`deactivate_code_...`); `src/api/endpoints/referrals.ts: createReferralCode,
   deactivateReferralCode`.
9. **CSRF transport.** Claim: requests send `X-CSRF-Token` from the `ui_csrf`
   cookie. VERDICT: **Verified**. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")`
   → `headers.set("X-CSRF-Token", csrf)`).
10. **Additional auth headers.** Claim (original omitted): besides the cookie
    session (`credentials: "include"`), the client also sends
    `Authorization: Bearer <accessToken>` and optional `X-IMPERSONATION-TOKEN`.
    VERDICT: **Corrected** (added). SOURCE: `src/api/client.ts` (Authorization /
    X-IMPERSONATION-TOKEN header logic); OpenAPI params on `/ui/...` ops list
    `X-SESSION-ID, X-IMPERSONATION-TOKEN`.
11. **401 refresh-and-retry.** Claim: on 401 the layer does a single
    `POST /ui/session/refresh` then retries. VERDICT: **Verified** with nuance:
    refresh only runs if the user was already authenticated; a second 401 logs
    out. SOURCE: `src/api/client.ts: refreshSession` + 401 branch.
12. **FastAPI error `detail` shapes.** Claim: `detail` is `string | [{msg}] |
    {code,...}`. VERDICT: **Verified**. SOURCE: `src/api/client.ts:
    normalizeErrorDetail / mapAuthorizationError`; OpenAPI `HTTPValidationError`
    (`detail: ValidationError[]`, each with `loc, msg, type`) returned as 422 on
    every referral/affiliate op.
13. **Network-error / offline handling.** Claim: offline surfaces a network
    error (mapped to retryable `ApiResult.Error`). VERDICT: **Verified** at the
    web layer. SOURCE: `src/api/client.ts` catch block → `ApiError(0, "Network
    error")` + toast. (Android mapping to `ApiResult.Error(retryable=true)` is
    AND-264/core-network's job — see Open assumptions.)
14. **ViewModel / StateFlow / SavedStateHandle / Paging-3 framework choices.**
    VERDICT: **Verified (framework ref)**. SOURCES:
    `https://developer.android.com/topic/libraries/architecture/viewmodel`,
    `https://developer.android.com/kotlin/flow/stateflow-and-sharedflow`,
    `https://developer.android.com/topic/libraries/architecture/saving-states`,
    `https://developer.android.com/topic/libraries/architecture/paging/v3-overview`,
    Hilt `@HiltViewModel`:
    `https://developer.android.com/training/dependency-injection/hilt-jetpack`.

### Corrections made

- §2, §5, §6: replaced non-existent DTO names (`ReferralOverview`,
  `ReferralStats`, `AffiliateSummary`, `AffiliateConversion`) with the real
  reference types (`ReferralDashboardStats`, `ReferralCode`,
  `AffiliateCommission`, `AffiliateLinkOut`).
- §4, §5: replaced fictitious endpoints `GET /ui/referrals/overview`,
  `GET /ui/affiliates/summary`, `GET /ui/affiliates/conversions` with the real
  `GET /ui/referrals/dashboard`, `GET /ui/affiliates/links`, and the
  cursor-paged `GET /ui/referrals/commissions`.
- §4: `ReferralUiState.Content` now holds `ReferralDashboardStats`; `isEmpty`
  computed from `referralCodes.isEmpty() && totalReferrals == 0`.
  `AffiliateUiState.Content` now holds `List<AffiliateLinkOut>`; the paged flow
  is referral commissions (`AffiliateCommission`), not affiliate "conversions".
- §5: documented the full auth/transport (cookie + Bearer + impersonation +
  CSRF) and the "only-if-authenticated" 401 refresh guard.
- §5: clarified there is no server `referral_url`; the link is derived
  client-side as `<origin>/?ref=<code>`. §8 logging note updated accordingly.
- §11, §12, AC-5: test/AC wording updated to the corrected shapes.

### Open assumptions

- **Kotlin domain/field naming.** The exact Kotlin domain class and property
  names (e.g. `dashboard.referralCodes`, `totalReferrals`) are owned by AND-264
  and could not be verified from the sources (no Android code exists yet). Marked
  as **Unverified-assumption**; this spec depends on the interface, not names.
- **Repository surface (`getReferralDashboard`, `referralCommissionsPager`,
  `listAffiliateLinks`).** These method signatures are this spec's proposed
  contract for AND-264; not yet present in any source. **Unverified-assumption.**
- **`ApiResult.Error` retryability mapping** (network/5xx → retryable; 4xx → not)
  is a core-network/AND-264 convention; not directly observable in the web client
  beyond network-vs-HTTP error separation. **Unverified-assumption.**
- **Affiliate entitlement gating (Q1).** Whether affiliate features are gated by
  an entitlement flag on `/ui/me` could not be confirmed; no such gate is visible
  in `AffiliateDashboard.tsx`. **Unverified-assumption** (pending product).
- **Stale/offline `stale` flag (R3).** No `stale` field exists in the verified
  response schemas; the `isStale` banner remains conditional on AND-264.
  **Unverified-assumption.**

## 17. Test Plan

JVM unit tests are the primary deliverable (acceptance: *Unit-tested*). A few
contract/instrumented cases are included to pin the wire shapes and
process-death behavior that the ViewModel contracts depend on. IDs trace to the
§14 Acceptance Criteria.

- **TC-AND-268-01** — Type: unit (Robolectric not required; JVM + Turbine).
  Target: JVM unit/Robolectric. Preconditions: `FakeReferralRepository`
  returns `ApiResult.Success(ReferralDashboardStats(totalReferrals=7,
  referralCodes=[1]))`; `MainDispatcherRule` installed.
  Steps: construct `ReferralViewModel`; collect `uiState` with Turbine.
  Expected: emits `Loading` then `Content(dashboard=…, isEmpty=false,
  isRefreshing=false)`. Traces: AC-1, AC-2.
- **TC-AND-268-02** — Type: unit. Target: JVM. Preconditions: fake returns
  `Success` with `totalReferrals=0` and empty `referralCodes`.
  Steps: construct VM; collect `uiState`. Expected: `Loading → Content(isEmpty =
  true)` (NOT `Error`). Traces: AC-5 (empty-not-error), AC-2.
- **TC-AND-268-03** — Type: unit. Target: JVM. Preconditions: fake returns
  `ApiResult.Error` mapped from a network/timeout failure (retryable).
  Steps: construct VM; collect `uiState`. Expected: `Loading →
  Error(retryable = true)`. Traces: AC-2.
- **TC-AND-268-04** — Type: unit. Target: JVM. Preconditions: VM already in
  `Content`; fake set to succeed on refresh. Steps: send `ReferralIntent.Refresh`;
  collect `uiState`. Expected: `Content(isRefreshing=true)` (same dashboard data
  retained) then `Content(isRefreshing=false)`; no `Loading` re-emitted. Traces:
  AC-3.
- **TC-AND-268-05** — Type: unit. Target: JVM. Preconditions: VM in `Content`;
  fake set to fail on the refresh call (retryable error). Steps: send `Refresh`;
  collect `uiState` and `effects`. Expected: state stays `Content(isRefreshing=
  false)` (last good data preserved); an error effect/message is emitted; no
  transition to `Error`. Traces: AC-3.
- **TC-AND-268-06** — Type: unit. Target: JVM. Preconditions: VM in
  `Error(retryable=true)`; fake flipped to succeed. Steps: send
  `ReferralIntent.Retry`; collect `uiState`. Expected: `Error → Loading →
  Content`. Traces: AC-2.
- **TC-AND-268-07** — Type: unit. Target: JVM. Preconditions: VM in `Content`
  with a code `AB12CD`. Steps: send `ReferralIntent.CopyLink` (for that code);
  collect `effects`. Expected: exactly one `ReferralEffect.CopyToClipboard(url)`
  where `url` == derived `"<origin>/?ref=AB12CD"`; no PII beyond the code.
  Traces: AC-4, AC-9.
- **TC-AND-268-08** — Type: unit. Target: JVM. Preconditions: VM in `Content`.
  Steps: send `ReferralIntent.ShareLink`; collect `effects`. Expected: one
  `ReferralEffect.ShowShareSheet(shareText)` containing the derived link + the
  app marketing sentence; effect fires once (not re-emitted on re-collection).
  Traces: AC-4.
- **TC-AND-268-09** — Type: unit. Target: JVM. Preconditions: fake with a
  call-count spy and a suspended (in-flight) `getReferralDashboard`. Steps: send
  `Load`, then a second `Load`/`Refresh` while the first is in flight; advance
  the dispatcher. Expected: repository `getReferralDashboard` invoked exactly
  once (FR-10 guard). Traces: AC-7.
- **TC-AND-268-10** — Type: unit. Target: JVM. Preconditions:
  `FakeReferralRepository.listAffiliateLinks()` returns
  `Success([AffiliateLinkOut…])` / `Error` / empty list across sub-cases.
  Steps: construct `AffiliateViewModel`; collect `uiState`. Expected: success →
  `Content(links=…, isEmpty=false)`; error → `Error`; empty list →
  `Content(isEmpty=true)`. Traces: AC-1, AC-5.
- **TC-AND-268-11** — Type: unit (Paging 3). Target: JVM. Preconditions: fake
  cursor-keyed `referralCommissionsPager()` backed by two pages
  (`next_cursor` then `null`). Steps: collect the `commissions`
  `Flow<PagingData<AffiliateCommission>>` via `asSnapshot()`/
  `AsyncPagingDataDiffer`. Expected: snapshot equals the concatenated fake items
  in order; `cachedIn(viewModelScope)` survives a re-collection without
  re-fetching. Traces: AC-5.
- **TC-AND-268-12** — Type: unit. Target: JVM. Preconditions: `SavedStateHandle`
  seeded empty. Steps: call `selectTab(AffiliateTab.Links)`; build a NEW
  `AffiliateViewModel` from the SAME `SavedStateHandle`; collect `selectedTab`.
  Expected: second VM emits `AffiliateTab.Links` (restoration). Traces: AC-6.
- **TC-AND-268-13** — Type: unit. Target: JVM. Preconditions: fake `Analytics`
  spy injected. Steps: call `selectTab(...)`; trigger a load failure.
  Expected: `affiliate_tab_selected` (param: tab name) and
  `referral_load_failed` (param: error category, retryable) events fired; assert
  NO event payload contains a referral code, share link, `tracking_code`,
  `short_url`, or earnings amount. Traces: AC-9.
- **TC-AND-268-14** — Type: contract/MockWebServer. Target: JVM (OkHttp
  MockWebServer; pins the wire contract this VM depends on). Preconditions:
  MockWebServer enqueues a `200` with the §5 `dashboard` JSON and a `422`
  `HTTPValidationError` body (`{"detail":[{"loc":["query","limit"],"msg":"...",
  "type":"..."}]}`). Steps: drive the AND-264 repo (or a thin test repo) against
  the mock for `GET /ui/referrals/dashboard` and `GET /ui/referrals/commissions`;
  assert request method/path/headers (`X-CSRF-Token` present) and that the 422 is
  mapped to a non-retryable `ApiResult.Error` carrying the `msg`. Expected:
  paths/methods/fields match §5; 422 → non-retryable error; happy path →
  populated domain models. Traces: AC-2, AC-5. (Note: this is technically
  AND-264's transport but is included to lock the contract the ViewModel asserts
  against; if AND-264 owns it, treat as a shared regression gate.)
- **TC-AND-268-15** — Type: instrumented/e2e (process-death restoration).
  Target: **Headless emulator AVD `test35` (API 35)** — process death /
  `SavedStateHandle` restore is reliably reproducible via `adb` and does not need
  real hardware. Preconditions: a minimal host Activity/Compose harness collecting
  `AffiliateViewModel.selectedTab`. Steps: select a non-default tab; trigger
  process death (`adb shell am kill` / "Don't keep activities"); relaunch.
  Expected: restored tab matches the pre-death selection; overview re-issues
  `Load` (not persisted). Traces: AC-6. (May also run on the physical Galaxy A15
  to confirm API-34/arm64 parity, but the emulator is the primary target.)

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 | TC-AND-268-01, TC-AND-268-10 |
| AC-2 | TC-AND-268-01, -02, -03, -06, -14 |
| AC-3 | TC-AND-268-04, TC-AND-268-05 |
| AC-4 | TC-AND-268-07, TC-AND-268-08 |
| AC-5 | TC-AND-268-02, -10, -11, -14 |
| AC-6 | TC-AND-268-12, TC-AND-268-15 |
| AC-7 | TC-AND-268-09 |
| AC-8 | TC-AND-268-01 … -13 (all run deterministically, no real dispatchers/network) |
| AC-9 | TC-AND-268-07, TC-AND-268-13 |
