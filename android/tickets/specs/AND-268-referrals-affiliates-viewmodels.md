---
id: AND-268
title: Referrals/affiliates ViewModels
milestone: M6
epic: E36
priority: P2
size: M
status: draft
depends_on: [AND-264]
blocks: [AND-269]
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
  `core-model` DTO/domain types (`ReferralOverview`, `ReferralStats`,
  `AffiliateSummary`, `AffiliateConversion`), Moshi adapters, and the
  FastAPI error `detail` mapping into `ApiResult.Error`. AND-268 must not
  redefine these; it consumes them.
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
            when (val r = repository.getReferralOverview()) {
                is ApiResult.Success -> _uiState.value =
                    ReferralUiState.Content(
                        overview = r.data,
                        isEmpty = r.data.stats.totalReferrals == 0,
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
        val overview: ReferralOverview,
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

`AffiliateViewModel` follows the same shape and adds Paging 3:

```kotlin
@HiltViewModel
class AffiliateViewModel @Inject constructor(
    private val repository: ReferralRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AffiliateUiState>(AffiliateUiState.Loading)
    val uiState: StateFlow<AffiliateUiState> = _uiState.asStateFlow()

    val conversions: Flow<PagingData<AffiliateConversion>> =
        repository.affiliateConversionsPager()
            .flow
            .cachedIn(viewModelScope)

    val selectedTab: StateFlow<AffiliateTab> =
        savedState.getStateFlow(KEY_TAB, AffiliateTab.Overview)

    fun selectTab(tab: AffiliateTab) { savedState[KEY_TAB] = tab }

    fun onIntent(intent: AffiliateIntent) { /* Load / Refresh / Retry */ }

    private companion object { const val KEY_TAB = "affiliate_tab" }
}

sealed interface AffiliateUiState {
    data object Loading : AffiliateUiState
    data class Content(
        val summary: AffiliateSummary,
        val isRefreshing: Boolean = false,
    ) : AffiliateUiState
    data class Error(val message: UiText, val retryable: Boolean) : AffiliateUiState
}
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
    suspend fun getReferralOverview(): ApiResult<ReferralOverview>
    suspend fun getAffiliateSummary(): ApiResult<AffiliateSummary>
    fun affiliateConversionsPager(): Pager<Int, AffiliateConversion>
}
```

For traceability, the backend endpoints behind that repository (canonical shapes
owned by AND-264, mirroring `frontend/src/api/endpoints/referrals.ts`) are:

- `GET /ui/referrals/overview` →
  ```json
  {
    "referral_url": "https://testlogon.com/r/AB12CD",
    "code": "AB12CD",
    "stats": { "total_referrals": 7, "pending": 2, "rewarded": 5,
               "reward_currency": "USD", "reward_total_cents": 2500 }
  }
  ```
- `GET /ui/affiliates/summary` →
  ```json
  {
    "clicks": 184, "signups": 23, "conversions": 9,
    "earnings_pending_cents": 4500, "earnings_paid_cents": 12000,
    "currency": "USD"
  }
  ```
- `GET /ui/affiliates/conversions?cursor=<c>&limit=20` → page object with
  `items[]` and `next_cursor` (drives the Paging 3 `PagingSource` in AND-264).

All requests ride the cookie session + `X-CSRF-Token` header; on 401 the
network layer performs a single `POST /ui/session/refresh` and retries. These
concerns live in `core-network`/AND-264 and are transparent to the ViewModel,
which only sees `ApiResult.Success`/`ApiResult.Error`.

## 6. Data & State Management

- **Domain models** (`core-model`, from AND-264): `ReferralOverview`,
  `ReferralStats`, `AffiliateSummary`, `AffiliateConversion`. ViewModels hold
  these directly inside `Content` states; no UI-only duplication.
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
- **Paging:** `conversions` is `cachedIn(viewModelScope)` so scroll position and
  loaded pages survive recomposition and config changes; `LoadState` is owned by
  the Compose `LazyPagingItems` collector (UI), not duplicated in `UiState`.
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

- The ViewModel never logs the full `referral_url`, referral `code`, or any
  earnings amounts; the referral code is treated as user-identifying and excluded
  from telemetry payloads (only event names/counts are logged).
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
1. init → emits `Loading` then `Content` on repo success.
2. success with `total_referrals == 0` → `Content(isEmpty = true)`.
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
10. summary success/error/empty mirror cases 1-3.
11. `conversions` paging emits expected items snapshot from the fake pager.
12. `selectTab` updates `selectedTab` and survives a new ViewModel built from the
    same `SavedStateHandle` (restoration) → emits persisted tab.
13. `affiliate_tab_selected` analytics event fired on `selectTab`.

Determinism: no real dispatchers, no `delay` on the test thread, all repo
responses driven by the fake. Target ViewModel line coverage ≥ 90%.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-264 (Referrals):** must land first; provides
  `ReferralRepository`, `core-model` domain types, error mapping, and the
  `affiliateConversionsPager()` `PagingSource`. AND-268 cannot compile without it.
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
- AC-5 Affiliate summary load + `conversions` Paging flow emit expected data from
  the fake repository; empty data yields `Content(isEmpty = true)`, not `Error`.
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
