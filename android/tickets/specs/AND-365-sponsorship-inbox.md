---
id: AND-365
title: Sponsorship inbox
milestone: M8
epic: E47
priority: P1
size: M
status: draft
depends_on: [AND-363]
blocks: [AND-366]
---

# AND-365 — Sponsorship inbox

## 1. Overview & Goal

Creators on TestLogon receive inbound sponsorship offers ("deals") from brands and
agencies. This ticket delivers the **read-only inbox** that lists those offers inside the
native Android app: a paginated, filterable list of sponsorship deals with their status,
sponsor, headline terms, and timestamps, plus the loading / empty / error / offline states
mandated by the platform UX baseline.

The goal is strictly the **inbox surface and its data plumbing**. Acting on a deal
(accept/decline/negotiate) and the full deal-detail screen are owned by the downstream
ticket **AND-366 (Sponsorship manage / deal detail)**. This ticket must, however, ship the
domain model, repository, paging source, list UI, and a tap-through navigation event that
AND-366 will consume, so that AND-366 is purely additive.

Concretely, by the end of this ticket: opening **More → Sponsorships** shows the list of
sponsorship offers returned by the backend, paged with Paging 3, backed by an SWR cache,
resilient to the unreliable dev host, and covered by ViewModel and Compose UI tests. The
single acceptance bullet — "Inbox lists offers" — is satisfied with verifiable, tested
behavior.

## 2. Context & References

- **Module:** new `feature-sponsorship` module under `com.testlogon.android.feature.sponsorship`,
  layered `app -> feature-sponsorship -> core-*`.
- **Web reference scope (from backlog):** `sponsorshipDeals.ts` — the web app's sponsorship
  deal endpoint client. The Android `SponsorshipApi` mirrors its endpoint shapes and the
  shared types in `frontend/src/api/types.ts`. Where the OpenAPI doc (`/openapi.json`) and
  `sponsorshipDeals.ts` disagree on field names, the OpenAPI doc wins; discrepancies are
  logged in §13.
- **Depends on AND-363 (Ads accounts API):** AND-363 establishes the `core-network`
  `AdsApi`/Retrofit wiring, the ads/sponsorship Moshi adapters, and the
  `com.testlogon.android.core.model.ads` package. Sponsorship deals are scoped to an ads
  account, so AND-365 reuses the account-id context surfaced by AND-363.
- **Blocks AND-366 (Sponsorship manage / deal detail):** AND-366 adds accept/decline/
  negotiate actions and the detail screen, consuming the `dealId` navigation argument and
  the cached `SponsorshipDeal` model defined here.
- **Platform building blocks reused:** OkHttp client + timeouts (AND-009), Retrofit/Moshi
  (AND-010), persistent cookie jar (AND-011), CSRF interceptor (AND-012), 401 refresh
  authenticator (AND-013), `ApiResult<T>` + FastAPI `detail` mapping (AND-015, AND-018),
  retry/backoff for idempotent GETs (AND-016), Room/SWR cache repository (AND-115, AND-116),
  state composables (AND-021), navigation host (AND-022/AND-024), More hub (AND-067).
- **Milestone exit criterion (M8):** "boost/sponsorship usable."

## 3. Functional Requirements

FR-1. A **Sponsorship Inbox** screen is reachable from the More hub at route
`sponsorship/inbox`. The route registers in the authenticated nav graph.

FR-2. The screen lists sponsorship deals, newest first (server default ordering preserved),
using Paging 3 with page size 20. Each row shows: sponsor display name + avatar, deal title,
status chip, payout amount (formatted currency), and a relative "received" timestamp.

FR-3. **Status filter:** a filter row lets the user scope the list by deal status
(`all`, `pending`, `negotiating`, `accepted`, `declined`, `expired`). `all` is the default.
Changing the filter resets paging and re-queries.

FR-4. **Unread emphasis:** deals with `read_at == null` render with a leading unread dot and
heavier title weight. (Marking-as-read is a write action owned by AND-366; this ticket only
displays the flag.)

FR-5. **States:** the screen renders Loading (skeleton list), Empty ("No sponsorship offers
yet"), Error (message + Retry), and Offline/Stale (cached list + stale banner) per the
shared state composables. Pull-to-refresh re-fetches the first page.

FR-6. **Tap-through:** tapping a row emits navigation to `sponsorship/deal/{dealId}` (the
destination is a placeholder owned by AND-366). The inbox must pass the full `dealId` and not
crash if the destination is not yet registered (guarded nav).

FR-7. **Pagination:** scrolling to the end loads the next page via the cursor returned by the
API. Append errors show an inline footer with Retry without discarding loaded items.

FR-8. **No write actions** in this ticket. Accept/decline/negotiate controls are explicitly
out of scope and deferred to AND-366.

## 4. Technical Design

New module `feature-sponsorship`. Package root `com.testlogon.android.feature.sponsorship`.

```
feature-sponsorship/
  data/SponsorshipApi.kt            // Retrofit interface
  data/SponsorshipRepository.kt     // SWR + Paging
  data/SponsorshipRemoteMediator.kt // Paging 3 RemoteMediator (Room-backed)
  data/dto/SponsorshipDealDto.kt
  data/db/SponsorshipDealEntity.kt  // Room entity + DAO (cache)
  domain/SponsorshipDeal.kt         // domain model
  domain/SponsorshipDealStatus.kt   // enum
  ui/SponsorshipInboxScreen.kt
  ui/SponsorshipInboxViewModel.kt
  ui/SponsorshipDealRow.kt
  di/SponsorshipModule.kt           // Hilt
```

**Domain model**

```kotlin
enum class SponsorshipDealStatus { PENDING, NEGOTIATING, ACCEPTED, DECLINED, EXPIRED, UNKNOWN }

data class SponsorshipDeal(
    val id: String,
    val accountId: String,
    val sponsorName: String,
    val sponsorAvatarUrl: String?,
    val title: String,
    val status: SponsorshipDealStatus,
    val payoutMinor: Long,        // amount in minor units
    val currency: String,         // ISO 4217
    val receivedAt: Instant,
    val expiresAt: Instant?,
    val readAt: Instant?,
)
```

**ViewModel** exposes a `StateFlow<UiState>` plus a `Flow<PagingData<SponsorshipDeal>>`. The
non-paging `UiState` carries filter, refresh, and connectivity/stale state; the paging flow
carries the items. This split keeps Paging 3's own `LoadState` authoritative for list-body
loading/append while the screen-level `UiState` covers banners.

```kotlin
@HiltViewModel
class SponsorshipInboxViewModel @Inject constructor(
    private val repository: SponsorshipRepository,
    private val connectivity: ConnectivityObserver,
) : ViewModel() {

    data class UiState(
        val filter: SponsorshipDealStatus? = null, // null == "all"
        val isStale: Boolean = false,
        val isOffline: Boolean = false,
    )

    private val filter = MutableStateFlow<SponsorshipDealStatus?>(null)
    val uiState: StateFlow<UiState>

    @OptIn(ExperimentalCoroutinesApi::class)
    val deals: Flow<PagingData<SponsorshipDeal>> =
        filter.flatMapLatest { repository.dealsPager(it) }
            .cachedIn(viewModelScope)

    fun setFilter(status: SponsorshipDealStatus?) { filter.value = status }
    fun refresh() { /* triggers repository invalidate + first-page fetch */ }
}
```

**Repository** combines a Room-backed `PagingSource` (offline truth) with a
`RemoteMediator` (network append/refresh), implementing SWR via AND-116's pattern.

```kotlin
class SponsorshipRepository @Inject constructor(
    private val api: SponsorshipApi,
    private val dao: SponsorshipDealDao,
    private val db: SponsorshipDatabase,
) {
    @OptIn(ExperimentalPagingApi::class)
    fun dealsPager(filter: SponsorshipDealStatus?): Flow<PagingData<SponsorshipDeal>> =
        Pager(
            config = PagingConfig(pageSize = 20, prefetchDistance = 10, enablePlaceholders = false),
            remoteMediator = SponsorshipRemoteMediator(filter, api, dao, db),
            pagingSourceFactory = { dao.pagingSource(filter?.wire) },
        ).flow.map { it.map(SponsorshipDealEntity::toDomain) }
}
```

**Screen** uses `collectAsLazyPagingItems()`; renders the filter row, then dispatches on the
combined `loadState.refresh` + `UiState` to choose Loading / Empty / Error / Offline-stale /
Content, reusing `LoadingState`, `EmptyState`, `ErrorState`, `OfflineBanner` from `core-ui`
(AND-021). Row tap calls `onOpenDeal(dealId)` provided by the nav graph.

## 5. API Contract

All endpoints are cookie-authenticated GETs (idempotent → eligible for AND-016 retry/backoff)
and require the `X-CSRF-Token` header echoed from the `ui_csrf` cookie (AND-012). Base URL
is the runtime-selected host (AND-014); dev host is plaintext HTTP `http://18.222.237.167:8000`.

**List sponsorship deals**

```
GET /ui/ads/sponsorship/deals?status={status}&cursor={cursor}&limit=20
```

- `status` (optional): one of `pending|negotiating|accepted|declined|expired`; omit for all.
- `cursor` (optional): opaque pagination token from the previous page.
- `limit` (optional, default 20, max 50).

Response `200`:

```json
{
  "items": [
    {
      "id": "deal_01HXYZ...",
      "account_id": "acct_01H...",
      "sponsor": { "name": "Acme Corp", "avatar_url": "https://.../a.png" },
      "title": "Q3 product placement",
      "status": "pending",
      "payout": { "amount_minor": 250000, "currency": "USD" },
      "received_at": "2026-06-01T14:22:00Z",
      "expires_at": "2026-06-15T00:00:00Z",
      "read_at": null
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ=="
}
```

`next_cursor` is `null` on the last page. Unknown `status` strings map to
`SponsorshipDealStatus.UNKNOWN` (forward-compatible). `Retrofit` interface:

```kotlin
interface SponsorshipApi {
    @GET("ui/ads/sponsorship/deals")
    suspend fun listDeals(
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): SponsorshipDealPageDto
}
```

**Errors** follow the FastAPI `detail` shape (string | `[{msg}]` | `{code,...}`) mapped by
AND-015 into `ApiError`. Notable codes: `401` → Authenticatorrefreshthenretryonce
(AND-013); `403` (account lacks sponsorship feature) → typed `Forbidden` rendered as an
informational empty state; `404` (account scope) → empty.

This ticket consumes **no mutating endpoints**. Accept/decline/negotiate
(`POST /ui/ads/sponsorship/deals/{id}/accept` etc.) and detail
(`GET /ui/ads/sponsorship/deals/{id}`) are owned by **AND-366**.

## 6. Data & State Management

**Room cache** (core-data / AND-115). Entity keyed by `(id)` with an index on
`(status, received_at)` to back the filtered `PagingSource`. A `RemoteKeys`-style table stores
the per-filter `next_cursor` for the `RemoteMediator`.

```kotlin
@Entity(tableName = "sponsorship_deal")
data class SponsorshipDealEntity(
    @PrimaryKey val id: String,
    val accountId: String,
    val sponsorName: String,
    val sponsorAvatarUrl: String?,
    val title: String,
    val status: String,
    val payoutMinor: Long,
    val currency: String,
    val receivedAtEpochMs: Long,
    val expiresAtEpochMs: Long?,
    val readAtEpochMs: Long?,
    val cachedAtEpochMs: Long,
)

@Dao
interface SponsorshipDealDao {
    @Query("""SELECT * FROM sponsorship_deal
              WHERE (:status IS NULL OR status = :status)
              ORDER BY receivedAtEpochMs DESC""")
    fun pagingSource(status: String?): PagingSource<Int, SponsorshipDealEntity>

    @Upsert suspend fun upsertAll(items: List<SponsorshipDealEntity>)
    @Query("DELETE FROM sponsorship_deal WHERE :status IS NULL OR status = :status")
    suspend fun clear(status: String?)
}
```

**SWR semantics:** on screen open, the cached page renders immediately (if present) while the
`RemoteMediator` `REFRESH` fetches page 1. On success, the filtered slice is replaced
transactionally (`clear(status)` + `upsertAll` inside `db.withTransaction`). `cachedAtEpochMs`
drives the stale banner: data older than 10 minutes while online shows a "Refreshing…" hint;
data shown while offline shows the offline-stale banner (AND-117). TTL eviction follows
AND-118 (cache entries older than 7 days purged on app start).

**State flow split:** Paging `LoadState` → list body (refresh skeleton, append footer, empty
detection via `loadState.refresh is NotLoading && itemCount == 0`); `UiState` → top-of-screen
banners (offline/stale) and the active filter. Filter changes flow through `MutableStateFlow`
→ `flatMapLatest` → new `Pager`, so each filter has an independent paging stream.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (AND-009) given the unreliable dev host.
- **Retry/backoff:** the list GET is idempotent → bounded exponential backoff (AND-016),
  max 3 attempts, jittered, only for transient `IOException`/`5xx`. The `RemoteMediator`
  surfaces final failures as `MediatorResult.Error`, rendered by Paging `LoadState`.
- **401:** handled transparently by the refresh Authenticator (AND-013) — single refresh +
  retry; a second 401 propagates to auth-gated routing (AND-025) which kicks to login.
- **403/404:** mapped to a benign empty state, not an error (account simply has no
  sponsorship access / no deals), to avoid alarming creators without the feature.
- **Append failure:** preserves loaded items; shows inline footer with Retry
  (`lazyPagingItems.retry()`).
- **Refresh failure with cache present:** keep cached list, show error snackbar + stale
  banner rather than blanking the screen.
- **Refresh failure with empty cache:** full-screen `ErrorState` with Retry.
- **Malformed/unknown fields:** unknown `status` → `UNKNOWN`; missing optional fields tolerated
  by Moshi adapters (AND-026 pattern); a row that fails to parse is skipped, not fatal.

## 8. Security & Privacy

- All requests ride the persistent cookie jar (AND-011) and CSRF header (AND-012); no tokens
  are logged.
- Sponsorship deals contain commercially sensitive payout figures. The Room cache lives in
  app-private storage; no external/world-readable writes. Cache is cleared on logout via the
  existing logout cache-purge hook (AND-032/AND-109).
- Coil image loads of `sponsor.avatar_url` go through the authenticated OkHttp stack so
  cookie-gated avatars resolve; no credentials are placed in URLs.
- Plaintext HTTP is a **dev-host-only** posture; production uses HTTPS via host selection
  (AND-014). Cleartext is permitted only for the dev flavor's network-security-config.
- No PII beyond sponsor display name/avatar is rendered; payout amounts are shown only to the
  authenticated account owner (server-enforced scoping by account).

## 9. Accessibility & i18n

- All strings live in `feature-sponsorship/src/main/res/values/strings.xml` (AND-111); no
  hardcoded UI text. Keys: `sponsorship_inbox_title`, `sponsorship_empty`,
  `sponsorship_status_pending`, etc.
- Status chips and filter chips expose `contentDescription`; the unread dot adds a
  `stateDescription` of "Unread" so TalkBack announces it.
- Currency formatted via `NumberFormat.getCurrencyInstance(locale)` from `payoutMinor` +
  `currency`; relative timestamps via the shared `RelativeTime` util (locale-aware).
- Minimum 48dp touch targets on rows and filter chips; dynamic type respected (Compose
  `sp` text). Layout is RTL-ready (AND-114): start/end paddings, no hardcoded left/right.
- Color is not the sole status signal — each status chip pairs an icon/label with its color
  to meet contrast and color-blind requirements.

## 10. Telemetry & Logging

- Screen view event `sponsorship_inbox_viewed`.
- Filter change event `sponsorship_inbox_filter_changed` with `{ status }`.
- Row tap event `sponsorship_deal_opened` with `{ deal_id, status }` (deal_id is an opaque id,
  not PII).
- Load outcomes: `sponsorship_inbox_load` with `{ result: success|error|offline, page,
  duration_ms }`; on error include the mapped `ApiError.code` only (never response bodies or
  cookies).
- Logging uses the redacted logger (AND-052); payout amounts and sponsor names are **not**
  logged. OkHttp logging interceptor stays at `BASIC`/headers-redacted in dev, `NONE` in
  release.

## 11. Testing Strategy

**Unit / repository (core-testing, MockWebServer — AND-046):**
- DTO → domain mapping incl. unknown status → `UNKNOWN`, null `avatar_url`, null `read_at`.
- `next_cursor` paging: two-page fixture appends and de-dupes by `id`.
- Filter passes correct `status` query param; `all` omits it.
- 403/404 → empty (not error); 5xx → retried then error after max attempts.
- Transactional refresh: `clear(status)` + `upsertAll` replaces the filtered slice only.

**ViewModel tests (Turbine + coroutine test rule):**
- `setFilter` swaps the paging stream (new `flatMapLatest` emission).
- `UiState.isOffline`/`isStale` reflect connectivity + `cachedAtEpochMs` age.
- `refresh()` invalidates and re-emits.

**Compose UI tests (AND-048 pattern):**
- **Acceptance — "Inbox lists offers":** seed MockWebServer with N deals → assert N rows with
  sponsor name + status chip visible.
- Empty fixture → empty state node displayed.
- Error fixture → error state + Retry; tapping Retry re-requests.
- Offline (no network) with cache → cached rows + offline banner.
- Row tap invokes `onOpenDeal` with the correct `dealId` (verified via test nav callback).

**Instrumented (CI headless emulator, AND-051):** smoke that the screen renders against
fixtures and survives configuration change (paging `cachedIn` retains items).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-363 (Ads accounts API).** Provides the ads/sponsorship network
  module, Moshi adapter registration, and the `accountId` context. AND-365 cannot start its
  data layer until AND-363's DTO/adapter scaffolding merges.
- **Indirect platform deps (already landed by M8):** AND-009–AND-018 (network stack +
  ApiResult + retry), AND-021 (state composables), AND-022/AND-024 (nav), AND-067 (More hub),
  AND-115/AND-116/AND-117/AND-118 (cache/SWR/stale/eviction), AND-111/AND-114 (i18n/RTL),
  AND-052 (redacted logging).
- **Blocks: AND-366 (Sponsorship manage / deal detail).** AND-366 registers the
  `sponsorship/deal/{dealId}` destination, adds the detail GET and mutate endpoints, and the
  accept/decline/negotiate UI. The `onOpenDeal(dealId)` hook and cached `SponsorshipDeal`
  model defined here are its contract.
- **Sequencing:** model + DTO + adapters → Room entity/DAO + RemoteMediator → repository →
  ViewModel → screen → tests. Land behind no feature flag (read-only, safe).

## 13. Risks & Open Questions

- **R1 — Endpoint path unverified.** `/ui/ads/sponsorship/deals` is inferred from the
  `/ui/ads/accounts*` convention (AND-363) and `sponsorshipDeals.ts`; confirm exact path,
  query params, and cursor vs. offset paging against `/openapi.json` before implementation.
  *Mitigation:* path centralized in `SponsorshipApi`; one-line change if it differs.
- **R2 — Account scoping.** Whether deals are global to the user or require an explicit
  `account_id` query param is unknown. *Mitigation:* repository accepts an optional
  `accountId` from AND-363's context; default to user-scoped if the param is absent.
- **R3 — Status enum drift.** Backend status vocabulary may exceed the six listed values.
  Handled by `UNKNOWN` fallback; surface unknowns in telemetry to catch drift.
- **R4 — Unread semantics.** `read_at` may be set server-side on detail open (AND-366) or via
  an explicit mark-read call. Display-only here; the write owner is AND-366.
- **Open question:** Is there a real-time push (FCM/SSE) for new sponsorship offers? If so a
  future ticket wires invalidation; out of scope here (pull-to-refresh only).

## 14. Acceptance Criteria

AC-1. Navigating **More → Sponsorships** opens the Sponsorship Inbox at route
`sponsorship/inbox`.

AC-2. **(Source bullet) Inbox lists offers:** given a backend (or MockWebServer) returning a
non-empty `items` array, the screen renders one row per deal showing sponsor name, title,
status chip, formatted payout, and relative received time — verified by Compose UI test.

AC-3. Scrolling past the first page loads the next page via `next_cursor`; the last page
(`next_cursor == null`) stops paging without error.

AC-4. The status filter scopes the list and resets paging; `all` shows every deal.

AC-5. Empty, Error (+ working Retry), and Offline-stale (cached rows + banner) states each
render under their respective conditions.

AC-6. Tapping a row navigates toward `sponsorship/deal/{dealId}` with the correct id and does
not crash when the destination is not yet registered.

AC-7. No accept/decline/negotiate controls appear (deferred to AND-366).

AC-8. DTO↔domain mapping (incl. unknown status, null avatar/read_at), paging, filter-param,
and 403/404→empty behaviors are covered by passing unit tests.

## 15. Definition of Done

- `feature-sponsorship` module created under `com.testlogon.android.feature.sponsorship`,
  layered `app -> feature-sponsorship -> core-*`, Hilt-wired via `SponsorshipModule`.
- `SponsorshipApi`, `SponsorshipRepository`, `SponsorshipRemoteMediator`, Room entity/DAO,
  domain model, ViewModel, and Compose screen implemented per §4–§6.
- All UI strings externalized; RTL-ready; TalkBack-verified status/unread semantics.
- Unit, ViewModel, and Compose UI tests in §11 pass locally and in CI (AND-050/AND-051),
  including the acceptance test for "Inbox lists offers."
- Telemetry events (§10) emitted through the redacted logger; no secrets/PII logged.
- ktlint/detekt clean (AND-005); no new lint baseline suppressions without justification.
- `onOpenDeal(dealId)` navigation hook and cached `SponsorshipDeal` model documented as the
  AND-366 contract in the module README.
- PR targets branch `android-port`; reviewed and merged with green CI.
