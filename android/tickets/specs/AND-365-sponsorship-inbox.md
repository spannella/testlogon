---
id: AND-365
title: Sponsorship inbox
milestone: M8
epic: E47
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-2. **[CORRECTED]** The screen lists sponsorship deals, newest first (sorted client-side
by `created_at` desc; the endpoint returns a bare unordered array). Each row shows: the
counterparty `advertiser_sub` (an opaque subject id — a display-name lookup is out of scope,
see §16 Open assumptions; rendered as "From <sub>" like the web inbox), a `brief` snippet,
a status chip, formatted compensation (`compensation_cents` / 100 as USD), the `deadline`,
and a relative "received" timestamp derived from `created_at`. There is **no** sponsor
avatar on the wire, so no avatar is shown (the draft's avatar requirement is dropped).

> **[CORRECTED] Pagination.** The endpoint returns the full array with no `cursor`/`limit`
> and no `next_cursor`; there is **no server-side paging**. Paging 3 is therefore *optional*
> and, if retained, is purely a local (in-memory/Room) windowing of the already-fetched list
> for smooth scrolling — it does NOT drive network fetches. The simplest correct design is a
> single GET that loads all of the creator's deals into the Room cache; "page size 20" is a
> local rendering window only. FR-7 is amended accordingly.

FR-3. **[CORRECTED] Status filter:** a filter row lets the user scope the list by deal
status. The valid values are the verified backend set
(`proposed`, `negotiating`, `accepted`, `content_submitted`, `completed`, `rejected`,
`cancelled`) plus an `all` default — **not** the draft's `pending/declined/expired`. The web
inbox groups these into Pending (`proposed`+`negotiating`), Active
(`accepted`+`content_submitted`), Completed, and Cancelled (`rejected`+`cancelled`) tabs and
filters **client-side**; Android may either filter client-side (matching the web app) or pass
a single `status` query param. Changing the filter re-queries / re-windows the list.

FR-4. **[CORRECTED] Unread emphasis: DROPPED.** The wire DTO has **no** `read_at`/unread
flag (verified: `src/api/types.ts: SponsorshipDeal` has no such field). There is no read/unread
concept in this contract, so no unread dot is rendered. (If product still wants unread
emphasis, it needs a backend field that does not currently exist — tracked as an open
question, §16.)

FR-5. **States:** the screen renders Loading (skeleton list), Empty ("No sponsorship offers
yet"), Error (message + Retry), and Offline/Stale (cached list + stale banner) per the
shared state composables. Pull-to-refresh re-fetches the first page.

FR-6. **Tap-through:** tapping a row emits navigation to `sponsorship/deal/{dealId}` (the
destination is a placeholder owned by AND-366). The inbox must pass the full `dealId` and not
crash if the destination is not yet registered (guarded nav).

FR-7. **[CORRECTED] Pagination:** since the API returns the full list in one response (no
cursor), there is no network "next page." If Paging 3 is kept for local windowing, append is
purely in-memory and cannot fail with a network error; the only network failure is the
initial/refresh GET, handled by FR-5's Error/Retry. The original "load next page via cursor /
inline append-error footer" behavior is not applicable to this endpoint.

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

**[CORRECTED]** Enum values and fields realigned to the verified backend/web contract
(`src/api/types.ts: SponsorshipDealStatus`, `SponsorshipDeal`). The draft's
`PENDING/DECLINED/EXPIRED`, `sponsorName/sponsorAvatarUrl`, `title`, `payoutMinor+currency`,
`receivedAt(Instant)`, `expiresAt`, and `readAt` do not exist on the wire.

```kotlin
enum class SponsorshipDealStatus {
    PROPOSED, NEGOTIATING, ACCEPTED, CONTENT_SUBMITTED, COMPLETED, REJECTED, CANCELLED, UNKNOWN
}

data class SponsorshipDeal(
    val id: String,                 // wire: deal_id
    val advertiserAccountId: String,
    val advertiserSub: String,      // counterparty subject id (NOT a display name)
    val creatorSub: String,
    val contentType: String,        // post | video | broadcast
    val brief: String,              // headline terms
    val deliverables: List<String>,
    val compensationCents: Long,    // USD cents (no currency field on the wire)
    val cpmBonusCents: Long,
    val platformCommissionBps: Int,
    val status: SponsorshipDealStatus,
    val deadline: String,           // "YYYY-MM-DD" date string
    val createdAt: Instant,         // wire: created_at, Unix epoch SECONDS
    val updatedAt: Instant,         // wire: updated_at, Unix epoch SECONDS
    val completedAt: Instant?,
    val cancelledAt: Instant?,
    val cancelReason: String?,
)
```

> Note: because the wire carries no sponsor display name (only `advertiser_sub`) and no
> avatar URL, FR-2's "sponsor display name + avatar" cannot be satisfied from this endpoint
> alone — see corrected FR-2 and §16 Open assumptions (sponsor-profile resolution).

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

> **[CORRECTED]** `SponsorshipRemoteMediator` and the `next_cursor`/cursor machinery shown
> above are unnecessary given the verified non-paged API (§5). A simpler, correct shape is:
> repository does one `api.listDeals(status, role="creator")` GET, writes the result to Room
> via `clear()+upsertAll()` in a transaction, and exposes either `dao.pagingSource(...)`
> (Paging 3 used only as a local Room window) or a plain `Flow<List<SponsorshipDeal>>`. The
> `RemoteMediator` row in the module tree (§4) and `remoteMediator = ...` argument should be
> dropped in implementation. All other repository wiring (SWR, transactional replace) stands.

**Screen** uses `collectAsLazyPagingItems()`; renders the filter row, then dispatches on the
combined `loadState.refresh` + `UiState` to choose Loading / Empty / Error / Offline-stale /
Content, reusing `LoadingState`, `EmptyState`, `ErrorState`, `OfflineBanner` from `core-ui`
(AND-021). Row tap calls `onOpenDeal(dealId)` provided by the nav graph.

## 5. API Contract

All endpoints are GETs (idempotent → eligible for AND-016 retry/backoff — an Android-side
choice; the web client does not retry). **Auth transport (verified against
`src/api/client.ts`):** the web client sends, on *every* request including GETs, (a) the
session cookies via `credentials: "include"` (the persistent cookie jar, AND-011), (b) an
`X-CSRF-Token` header echoed from the `ui_csrf` cookie (AND-012 — **verified**, `client.ts`
sets it unconditionally), and (c) an `Authorization: Bearer <accessToken>` header from the
auth store, plus an optional `X-IMPERSONATION-TOKEN`. The OpenAPI additionally documents
optional `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers on this endpoint. Android must
replicate the cookie + CSRF + Bearer combination, not cookie+CSRF alone. Base URL is the
runtime-selected host (AND-014); dev host is plaintext HTTP `http://18.222.237.167:8000`.

**List sponsorship deals**

> **[CORRECTED]** The original draft assumed `GET /ui/ads/sponsorship/deals` with
> cursor/limit pagination and an `{items, next_cursor}` envelope. Verified against the
> backend OpenAPI (`GET /ui/ads/sponsorships`, op `list_deals_ui_ads_sponsorships_get`) and
> the web client (`src/api/endpoints/sponsorshipDeals.ts: listSponsorshipDeals`), the real
> contract is different: the path is `/ui/ads/sponsorships` (no `/deals` segment), there is
> **no server-side pagination** (no `cursor`/`limit` params), and the response is a **bare
> JSON array** `SponsorshipDeal[]` — there is no envelope, no `next_cursor`. The query
> parameters are `status`, `role` (`^(advertiser|creator)$`), and `user_sub`. The web inbox
> calls it with `role=creator`.

```
GET /ui/ads/sponsorships?status={status}&role=creator
```

- `status` (optional): a single `SponsorshipDealStatus` value (see below); omit for all.
- `role` (optional): `advertiser` | `creator`. The inbox uses `creator` (deals received by
  this creator), mirroring the web client.
- `user_sub` (optional): caller subject; normally resolved server-side from the session, so
  Android omits it.

Response `200` (**bare array**, no envelope — `resp=200:{}` is untyped in OpenAPI; field
shape is taken from the web client's `SponsorshipDeal` type in `src/api/types.ts`):

```json
[
  {
    "deal_id": "deal_01HXYZ...",
    "advertiser_account_id": "acct_01H...",
    "advertiser_sub": "user_abc",
    "creator_sub": "user_self",
    "content_type": "post",
    "brief": "Q3 product placement, 1 sponsored post + 1 story...",
    "deliverables": ["1 feed post", "1 story"],
    "compensation_cents": 250000,
    "cpm_bonus_cents": 0,
    "platform_commission_bps": 1000,
    "status": "proposed",
    "deadline": "2026-06-15",
    "content_id": null,
    "dm_conversation_id": null,
    "escrow_hold_id": null,
    "created_at": 1748787720,
    "updated_at": 1748787720,
    "completed_at": null,
    "cancelled_at": null,
    "cancel_reason": null,
    "payment_details": null
  }
]
```

> **[CORRECTED] field shapes:** there is no `sponsor {name, avatar_url}` object, no `payout
> {amount_minor, currency}` object, no `title`, no `received_at`, no `expires_at`, and no
> `read_at`. Instead: the counterparty is `advertiser_sub` (an opaque subject id, **not a
> display name** — display-name resolution is a separate concern, see R5/Open assumptions);
> headline terms come from `brief` + `deliverables`; compensation is the flat integer
> `compensation_cents` (USD cents, no currency field — currency is implicitly USD) plus
> `cpm_bonus_cents`; "received" time is the Unix-epoch-**seconds** integer `created_at`
> (not an ISO-8601 string); there is no `expires_at` and no unread/`read_at` flag at all.
> The domain model (§4) and entity (§6) below are corrected to match.

`status` (verified from `src/api/types.ts: SponsorshipDealStatus`) is one of
`proposed | negotiating | accepted | content_submitted | completed | rejected | cancelled`.
The draft's `pending`/`declined`/`expired` values do **not** exist; the closest are
`proposed` (initial offer), `rejected`, and `cancelled`. Unknown/new strings still map to
`SponsorshipDealStatus.UNKNOWN` (forward-compatible). `Retrofit` interface:

```kotlin
interface SponsorshipApi {
    @GET("ui/ads/sponsorships")
    suspend fun listDeals(
        @Query("status") status: String? = null,
        @Query("role") role: String? = "creator",
    ): List<SponsorshipDealDto>   // bare array, no page envelope
}
```

**Errors** follow the FastAPI `detail` shape (string | `[{msg}]` | `{code,...}`) mapped by
AND-015 into `ApiError` — **verified** against `src/api/client.ts: normalizeErrorDetail`,
which handles exactly those three shapes. Notable codes: `401` → single session refresh via
`POST /ui/session/refresh` then retry once (**verified**: `client.ts: refreshSession` + the
401 branch; AND-013); `422` → `HTTPValidationError` (the only declared non-200 in OpenAPI for
this endpoint). **[CORRECTED/UNVERIFIED]** The draft's `403` (account lacks sponsorship
feature) and `404` (account scope) handling is **not** how the web client behaves — `client.ts`
maps 403 to an `ApiError` + toast (not an empty state), and the OpenAPI declares no 403/404 for
this endpoint at all. Treating 403/404 as a benign empty state is an **Android UX choice**, not
a verified backend contract; it is retained as a defensive design decision but flagged as an
assumption (see §16 Open assumptions).

This ticket consumes **no mutating endpoints**. The detail and mutate endpoints are owned by
**AND-366**. **[CORRECTED]** Their real paths (verified in OpenAPI index lines 870–877 /
`src/api/endpoints/sponsorshipDeals.ts`) are `GET /ui/ads/sponsorships/{deal_id}` (detail) and
`POST /ui/ads/sponsorships/{deal_id}/{accept|reject|counter|cancel|complete|submit-content}`
— note `reject`/`cancel`, not `decline`, and `counter`, not `negotiate`; there is no
`.../deals/...` segment.

## 6. Data & State Management

**Room cache** (core-data / AND-115). Entity keyed by `(id)` with an index on
`(status, createdAtEpochMs)` to back the filtered `PagingSource`.

> **[CORRECTED]** The draft's `RemoteKeys`/`next_cursor` table is **not needed** — the API
> has no cursor (verified §5). A `RemoteMediator` is unnecessary; a plain Room `PagingSource`
> (or even a non-paged `Flow<List<...>>`) over the cached rows suffices, refreshed by a single
> `clear()+upsertAll()` from one GET. Entity fields below are corrected to the real DTO.

```kotlin
@Entity(tableName = "sponsorship_deal")
data class SponsorshipDealEntity(
    @PrimaryKey val id: String,            // deal_id
    val advertiserAccountId: String,
    val advertiserSub: String,
    val creatorSub: String,
    val contentType: String,
    val brief: String,
    val deliverablesJson: String,          // List<String> serialized
    val compensationCents: Long,
    val cpmBonusCents: Long,
    val platformCommissionBps: Int,
    val status: String,
    val deadline: String,                  // YYYY-MM-DD
    val createdAtEpochMs: Long,            // from created_at (seconds) * 1000
    val updatedAtEpochMs: Long,
    val completedAtEpochMs: Long?,
    val cancelledAtEpochMs: Long?,
    val cancelReason: String?,
    val cachedAtEpochMs: Long,
)

@Dao
interface SponsorshipDealDao {
    @Query("""SELECT * FROM sponsorship_deal
              WHERE (:status IS NULL OR status = :status)
              ORDER BY createdAtEpochMs DESC""")
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
- **[CORRECTED]** There is no `sponsor.avatar_url` (or any avatar) on this endpoint, so no
  Coil avatar loading happens in this ticket. If a future ticket resolves sponsor profiles to
  avatars, those loads must go through the authenticated OkHttp stack so cookie-gated avatars
  resolve, with no credentials placed in URLs.
- Plaintext HTTP is a **dev-host-only** posture; production uses HTTPS via host selection
  (AND-014). Cleartext is permitted only for the dev flavor's network-security-config.
- No PII beyond sponsor display name/avatar is rendered; payout amounts are shown only to the
  authenticated account owner (server-enforced scoping by account).

## 9. Accessibility & i18n

- All strings live in `feature-sponsorship/src/main/res/values/strings.xml` (AND-111); no
  hardcoded UI text. Keys: `sponsorship_inbox_title`, `sponsorship_empty`,
  `sponsorship_status_pending`, etc.
- Status chips and filter chips expose `contentDescription`. **[CORRECTED]** The unread-dot
  `stateDescription` is removed — there is no `read_at`/unread flag on the wire (see FR-4).
- Currency formatted via `NumberFormat.getCurrencyInstance(locale)` from `compensationCents`
  (USD cents → divide by 100; currency is implicitly USD as the wire carries no currency
  field); relative timestamps via the shared `RelativeTime` util (locale-aware) from
  `created_at`.
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
- DTO → domain mapping incl. unknown status → `UNKNOWN`, `created_at` seconds→`Instant`,
  null `completed_at`/`cancelled_at`, `deliverables` array. *(Corrected: no `avatar_url`/
  `read_at` fields exist.)*
- **[CORRECTED]** Bare-array parsing (no `items`/`next_cursor` envelope); list sorted by
  `created_at` desc; de-dupe by `id` on refresh.
- Filter passes correct `status` query param (and `role=creator`); `all` omits `status`.
- 403/404 → empty (not error); 5xx → retried then error after max attempts.
- Transactional refresh: `clear(status)` + `upsertAll` replaces the filtered slice only.

**ViewModel tests (Turbine + coroutine test rule):**
- `setFilter` swaps the paging stream (new `flatMapLatest` emission).
- `UiState.isOffline`/`isStale` reflect connectivity + `cachedAtEpochMs` age.
- `refresh()` invalidates and re-emits.

**Compose UI tests (AND-048 pattern):**
- **Acceptance — "Inbox lists offers":** seed MockWebServer with a JSON array of N deals →
  assert N rows with counterparty (`advertiser_sub`) + status chip visible.
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

- **R1 — Endpoint path/shape [RESOLVED via review].** Verified: path is
  `GET /ui/ads/sponsorships` (no `/deals`), query params `status`/`role`/`user_sub`, and the
  response is a **bare array** with **no pagination** (no cursor/limit/next_cursor). The
  original `/ui/ads/sponsorship/deals` + cursor envelope was wrong and is corrected throughout
  (§4–§6). *Mitigation retained:* path centralized in `SponsorshipApi`.
- **R2 — Account scoping [PARTIALLY RESOLVED].** The endpoint is scoped by `role` (the inbox
  uses `role=creator`) and the session subject; there is **no** `account_id` query param.
  Deals carry `advertiser_account_id`/`creator_sub` but the list is filtered server-side by
  the caller's role/session, so AND-363's `accountId` context is **not** required to list.
- **R3 — Status enum drift.** Backend status vocabulary is the verified seven values
  (`proposed/negotiating/accepted/content_submitted/completed/rejected/cancelled`); `UNKNOWN`
  fallback still guards future additions; surface unknowns in telemetry to catch drift.
- **R4 — Unread semantics [RESOLVED: feature does not exist].** There is **no** `read_at` or
  any unread flag on the wire DTO. FR-4 (unread emphasis) is dropped. Any unread feature
  requires new backend support; out of scope.
- **R5 — Sponsor display name/avatar [NEW].** The list returns only `advertiser_sub` (an
  opaque id), no display name or avatar. Rendering a friendly sponsor name/avatar needs a
  separate profile-resolution endpoint that is not in scope here; the inbox shows the raw
  subject ("From <sub>") like the web app until a follow-up wires profile lookup.
- **Open question:** Is there a real-time push (FCM/SSE) for new sponsorship offers? If so a
  future ticket wires invalidation; out of scope here (pull-to-refresh only).

## 14. Acceptance Criteria

AC-1. Navigating **More → Sponsorships** opens the Sponsorship Inbox at route
`sponsorship/inbox`.

AC-2. **(Source bullet) Inbox lists offers:** given a backend (or MockWebServer) returning a
non-empty **JSON array** of deals, the screen renders one row per deal showing the
counterparty (`advertiser_sub`), `brief` snippet, status chip, formatted compensation
(`compensation_cents`), and relative received time (`created_at`) — verified by Compose UI
test. *(Corrected: bare array, not `items` envelope; no sponsor display name/avatar/title.)*

AC-3. **[CORRECTED]** The full list is returned in a single response (no server pagination);
scrolling renders all returned deals smoothly. There is no `next_cursor` follow-up request.
*(The original cursor-paging criterion does not apply to this endpoint.)*

AC-4. The status filter scopes the list and resets paging; `all` shows every deal.

AC-5. Empty, Error (+ working Retry), and Offline-stale (cached rows + banner) states each
render under their respective conditions.

AC-6. Tapping a row navigates toward `sponsorship/deal/{dealId}` with the correct id and does
not crash when the destination is not yet registered.

AC-7. No accept/decline/negotiate controls appear (deferred to AND-366).

AC-8. DTO↔domain mapping (incl. unknown status → `UNKNOWN`, `created_at` seconds→`Instant`,
null `completed_at`/`cancelled_at`, bare-array parsing), filter-param (`status`+`role`), and
403/404→empty behaviors are covered by passing unit tests. *(Corrected: no avatar/read_at
fields; no cursor paging.)*

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **List endpoint path is `GET /ui/ads/sponsorships`.** VERDICT: Corrected (draft said
   `/ui/ads/sponsorship/deals`). SOURCE: OpenAPI `GET /ui/ads/sponsorships`
   (op `list_deals_ui_ads_sponsorships_get`); frontend `src/api/endpoints/sponsorshipDeals.ts`
   (`const BASE = "/ui/ads/sponsorships"`, `listSponsorshipDeals`).
2. **HTTP method is GET.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/ads/sponsorships`;
   `src/api/endpoints/sponsorshipDeals.ts: listSponsorshipDeals` (`api.get`).
3. **Query params are `status`, `role` (`^(advertiser|creator)$`), `user_sub`; the inbox uses
   `role=creator`.** VERDICT: Corrected (draft used `cursor`+`limit`). SOURCE: OpenAPI
   `GET /ui/ads/sponsorships` parameters; `src/pages/ads/SponsorshipInbox.tsx`
   (`listSponsorshipDeals({ role: "creator" })`).
4. **No server-side pagination; response is a bare JSON array `SponsorshipDeal[]` (no
   `items`/`next_cursor` envelope).** VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/ads/sponsorships` `responses.200.content.application/json.schema = {}` (untyped);
   `src/api/endpoints/sponsorshipDeals.ts` (`api.get<SponsorshipDeal[]>`);
   `src/pages/ads/SponsorshipInbox.tsx` (`useQuery<SponsorshipDeal[]>`, client-side `.filter`).
5. **Deal DTO field names/shapes.** VERDICT: Corrected (draft had `id/account_id/sponsor{}/
   title/payout{}/received_at/expires_at/read_at`). SOURCE: `src/api/types.ts: SponsorshipDeal`
   — real fields `deal_id, advertiser_account_id, advertiser_sub, creator_sub, content_type,
   brief, deliverables, compensation_cents, cpm_bonus_cents, platform_commission_bps, status,
   deadline, content_id?, dm_conversation_id?, escrow_hold_id?, created_at, updated_at,
   completed_at?, cancelled_at?, cancel_reason?, payment_details?`.
6. **`created_at`/`updated_at` are Unix epoch seconds (integers), not ISO-8601 strings.**
   VERDICT: Corrected. SOURCE: `src/api/types.ts: SponsorshipDeal` (`created_at: number`).
7. **Compensation is integer `compensation_cents` (USD cents); no currency field on the wire.**
   VERDICT: Corrected (draft had `payout.amount_minor` + `currency`). SOURCE:
   `src/api/types.ts: SponsorshipDeal`; `src/pages/ads/SponsorshipInbox.tsx: formatCents`
   (`$${(cents/100).toFixed(2)}`); OpenAPI `SponsorshipDealCreate.compensation_cents`
   (`type: integer, minimum: 1000`).
8. **Status vocabulary = `proposed | negotiating | accepted | content_submitted | completed |
   rejected | cancelled`.** VERDICT: Corrected (draft had `pending/declined/expired`). SOURCE:
   `src/api/types.ts: SponsorshipDealStatus`.
9. **No unread/`read_at` field exists; FR-4 unread emphasis dropped.** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: SponsorshipDeal` (no `read_at`/unread member).
10. **No sponsor display name or avatar on the list; only `advertiser_sub`.** VERDICT:
    Corrected. SOURCE: `src/api/types.ts: SponsorshipDeal`; `src/pages/ads/SponsorshipInbox.tsx`
    renders `From {d.advertiser_sub}` (no name/avatar).
11. **Counterparty is shown as the raw subject id ("From <sub>").** VERDICT: Verified (web
    parity). SOURCE: `src/pages/ads/SponsorshipInbox.tsx` line ~96 (`From {d.advertiser_sub}`).
12. **CSRF: `X-CSRF-Token` echoed from `ui_csrf` cookie on every request incl. GETs.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); headers.set(
    "X-CSRF-Token", csrf)`).
13. **Auth transport also sends session cookies (`credentials:"include"`) and an
    `Authorization: Bearer` header (plus optional `X-IMPERSONATION-TOKEN`).** VERDICT: Verified
    (draft mentioned only cookie+CSRF). SOURCE: `src/api/client.ts` (Bearer from `useAuthStore`,
    `credentials: "include"`, impersonation header); OpenAPI documents optional `X-SESSION-ID`/
    `X-IMPERSONATION-TOKEN` headers on `GET /ui/ads/sponsorships`.
14. **401 → single session refresh (`POST /ui/session/refresh`) then retry once; second 401
    logs out.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` + 401 branch
    (`refreshPromise`, retry, `logout("session_expired")`).
15. **FastAPI error `detail` shape: string | `[{msg}]` | `{code,...}`.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` (string / array-of-`{msg}` / object-with-
    `code` via `mapAuthorizationError`); OpenAPI `422 → HTTPValidationError`.
16. **403 → empty-state mapping.** VERDICT: Unverified-assumption (Android UX choice). SOURCE:
    contradicted by `src/api/client.ts` (403 → `ApiError` + toast); OpenAPI declares no 403 for
    this endpoint. Kept as defensive design, not contract.
17. **404 → empty-state mapping.** VERDICT: Unverified-assumption. SOURCE: OpenAPI declares no
    404 for `GET /ui/ads/sponsorships` (only 200 + 422). Defensive design only.
18. **422 (validation) is the only declared non-200 response.** VERDICT: Verified. SOURCE:
    OpenAPI `GET /ui/ads/sponsorships` `responses` (200 + 422:`HTTPValidationError`).
19. **Web routes: inbox `ads/sponsorships`, detail `ads/sponsorships/:dealId`, manage
    `ads/sponsorships/manage`.** VERDICT: Verified (Android route names are the app's own
    choice). SOURCE: `src/App.tsx` lines ~320–322.
20. **Mutate endpoints (AND-366): `POST /ui/ads/sponsorships/{deal_id}/{accept|reject|counter|
    cancel|complete|submit-content}`; detail `GET /ui/ads/sponsorships/{deal_id}`.** VERDICT:
    Corrected (draft used `/sponsorship/deals/{id}/accept`, "decline"/"negotiate"). SOURCE:
    OpenAPI index lines 870–877; `src/api/endpoints/sponsorshipDeals.ts`.
21. **Paging 3 / `RemoteMediator` / `RemoteKeys` cursor table.** VERDICT:
    Unverified-assumption / not-needed. SOURCE: follows from claim 4 (no cursor) — a plain Room
    `PagingSource` or `Flow<List<...>>` suffices; the mediator is an over-design, not a contract
    requirement.
22. **Dev host `http://18.222.237.167:8000` (cleartext, dev-only).** VERDICT:
    Unverified-assumption. SOURCE: not present in OpenAPI/frontend reference; inherited from
    AND-014 host-selection convention. Carried as a deployment assumption.
23. **Cleartext HTTP permitted only via dev network-security-config; prod HTTPS.** VERDICT:
    Unverified-assumption (framework posture). SOURCE: framework ref —
    https://developer.android.com/privacy-and-security/security-config
24. **Paging 3 `cachedIn`/`collectAsLazyPagingItems` survive config change.** VERDICT: Verified
    (framework). SOURCE: framework ref — https://developer.android.com/topic/libraries/architecture/paging/v3-overview
25. **Currency via `NumberFormat.getCurrencyInstance(locale)`.** VERDICT: Verified (framework).
    SOURCE: framework ref — https://developer.android.com/reference/java/text/NumberFormat#getCurrencyInstance()
26. **TalkBack `contentDescription`/`stateDescription` semantics.** VERDICT: Verified
    (framework); the unread `stateDescription` is removed (claim 9). SOURCE: framework ref —
    https://developer.android.com/jetpack/compose/accessibility

### Corrections made

- §5: list path `/ui/ads/sponsorship/deals` → `/ui/ads/sponsorships`; removed `cursor`/`limit`,
  added `role`(`creator`)/`user_sub`; response envelope `{items,next_cursor}` → bare array;
  rewrote the JSON example and Retrofit interface to the real DTO.
- §5: corrected detail/mutate paths (`/ui/ads/sponsorships/{deal_id}` and `/accept|reject|
  counter|cancel|complete|submit-content`); noted the full cookie+CSRF+Bearer auth transport;
  reframed 403/404→empty as an Android UX choice, not contract.
- §4: rewrote domain model (real fields), enum values
  (`PROPOSED/NEGOTIATING/ACCEPTED/CONTENT_SUBMITTED/COMPLETED/REJECTED/CANCELLED/UNKNOWN`),
  and flagged `RemoteMediator`/cursor machinery as unnecessary.
- §6: rewrote Room entity to real fields; ordered by `createdAtEpochMs`; dropped the
  `RemoteKeys`/`next_cursor` table.
- §3: FR-2 (counterparty/brief/compensation, no avatar), FR-3 (real status values; client-side
  filtering), FR-4 (unread dropped), FR-7 (no cursor append).
- §8/§9: dropped avatar Coil loading and unread `stateDescription`; currency from
  `compensation_cents`.
- §13: R1/R2/R4 resolved; added R5 (sponsor name/avatar gap).
- §11/§14: acceptance/test text realigned to bare-array, real fields, no cursor paging.
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **403/404 → empty state** (claims 16–17): the backend does not declare these for this
  endpoint and the web client surfaces 403 as an error toast; treating them as a benign empty
  state is an unverified Android UX decision. Confirm with backend before relying on it.
- **Sponsor display name/avatar** (R5/claim 10): not resolvable from this endpoint; needs a
  separate profile-lookup endpoint that is not in the reference. Until then the inbox shows the
  raw `advertiser_sub`.
- **Dev host / cleartext posture** (claims 22–23): not in the OpenAPI/frontend sources;
  inherited from platform tickets (AND-014). Verify the host/port at integration time.
- **`status` query-param vs. client-side filtering**: OpenAPI exposes a `status` param but the
  web app filters client-side over grouped tabs; whether passing `status` server-side returns
  the same set as client filtering is unverified. Default to client-side filtering for web
  parity until confirmed.
- **`role` semantics**: assumed `creator` returns deals where the caller is the creator
  (matching the web inbox); not independently documented in OpenAPI beyond the regex pattern.

## 17. Test Plan

Test targets: **JVM/Robolectric** (local, no device), **emulator AVD `test35`** (API 35,
x86_64, headless CI), **physical device** (Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a).
This ticket is a read-only list screen with no camera/biometric/push/WebRTC/Telecom needs, so
most cases run on JVM or the emulator; the physical-device case exists only to validate the
real flaky cleartext dev host over a real cellular/Wi-Fi network and arm64/API-34 behavior.

- **TC-AND-365-01 — Happy path: inbox lists offers.** Type: contract/MockWebServer +
  Compose-UI. Target: emulator `test35`. Preconditions: MockWebServer enqueues `200` with a
  JSON **array** of 3 `SponsorshipDeal` objects (varied statuses). Steps: open
  `sponsorship/inbox`; let refresh complete. Expected: 3 rows render, each showing
  `advertiser_sub` ("From …"), `brief` snippet, a status chip, formatted compensation
  ($X.XX from `compensation_cents`), and relative time from `created_at`; no
  accept/reject/submit controls present. Traces: AC-2, AC-7.

- **TC-AND-365-02 — DTO→domain mapping.** Type: unit. Target: JVM/Robolectric. Preconditions:
  fixture JSON array with one deal having an unknown `status` ("archived"), null
  `completed_at`/`cancelled_at`, multi-element `deliverables`, and `created_at` as epoch
  seconds. Steps: parse via the Moshi adapter → map to domain. Expected: unknown status →
  `SponsorshipDealStatus.UNKNOWN`; `created_at` seconds → correct `Instant` (×1000 to ms);
  nullables map to null; `deliverables` preserved; `compensation_cents` → `Long`. Traces: AC-8.

- **TC-AND-365-03 — Bare-array parsing & sort.** Type: unit. Target: JVM/Robolectric.
  Preconditions: array of 2 deals out of `created_at` order, plus a payload that is NOT an
  `{items}` envelope. Steps: parse and sort. Expected: parser accepts a top-level array (would
  fail if it expected an envelope); list sorted by `created_at` desc; de-dupe by `deal_id` on
  refresh. Traces: AC-2, AC-3, AC-8.

- **TC-AND-365-04 — Filter passes correct query params.** Type: contract/MockWebServer.
  Target: JVM/Robolectric. Preconditions: MockWebServer recording requests. Steps: load with
  filter `all`; then set filter `accepted`. Expected: first request has `role=creator` and no
  `status`; second request has `role=creator` and `status=accepted` (or, if client-side
  filtering is chosen, exactly one request with `role=creator` and the UI filters locally —
  assert whichever the implementation declares). Traces: AC-4, AC-8.

- **TC-AND-365-05 — Filter scopes the list.** Type: Compose-UI. Target: emulator `test35`.
  Preconditions: fixture with mixed statuses (e.g., 2 `proposed`, 1 `accepted`, 1 `rejected`).
  Steps: select the filter for `accepted`. Expected: only the `accepted` row(s) shown; `all`
  restores the full set. Traces: AC-4.

- **TC-AND-365-06 — Empty state.** Type: Compose-UI. Target: emulator `test35`. Preconditions:
  MockWebServer returns `200` with `[]`. Steps: open inbox. Expected: empty state ("No
  sponsorship offers yet") node displayed; no rows; no error UI. Traces: AC-5.

- **TC-AND-365-07 — Error + working Retry.** Type: contract/MockWebServer + Compose-UI.
  Target: emulator `test35`. Preconditions: empty cache; MockWebServer returns `500` once,
  then `200` with 2 deals. Steps: open inbox (full-screen ErrorState appears); tap Retry.
  Expected: first load shows ErrorState + Retry; Retry re-requests; after the `200` the 2 rows
  render. Traces: AC-5.

- **TC-AND-365-08 — 403/404 → empty (not error).** Type: contract/MockWebServer. Target:
  JVM/Robolectric. Preconditions: MockWebServer returns `403` (then a separate run `404`).
  Steps: trigger load. Expected: repository/ViewModel maps to the benign empty state, not an
  error. NOTE: this encodes the **unverified §16 assumption**; if backend behavior is later
  confirmed to differ, update this case. Traces: AC-5, AC-8.

- **TC-AND-365-09 — Offline with cache → cached rows + stale/offline banner.** Type:
  integration. Target: emulator `test35`. Preconditions: prior successful load populated Room;
  connectivity reports offline (no network). Steps: reopen inbox offline. Expected: cached rows
  render immediately; offline/stale banner shown; no full-screen error; screen does not blank.
  Traces: AC-5.

- **TC-AND-365-10 — Flaky/offline real dev host.** Type: instrumented/e2e. Target: **PHYSICAL
  DEVICE (SM-A156U, API 34, arm64)** — MUST run on hardware. Preconditions: app pointed at the
  cleartext dev host `http://18.222.237.167:8000` over a real network; cleartext allowed only
  in the dev network-security-config. Steps: open inbox; toggle airplane mode mid-refresh; then
  restore and pull-to-refresh. Expected: transient `IOException`/5xx are retried (bounded
  backoff, AND-016) without crashing; offline shows cached/banner; on recovery the list
  refreshes. This validates real-network flakiness and arm64/API-34 behavior the x86 emulator
  cannot. Traces: AC-5.

- **TC-AND-365-11 — Tap-through navigation (guarded).** Type: Compose-UI. Target: emulator
  `test35`. Preconditions: inbox rendered with ≥1 deal; AND-366 destination NOT yet registered;
  test nav callback captures `onOpenDeal`. Steps: tap a row. Expected: `onOpenDeal` invoked with
  the exact `deal_id`; guarded nav does not crash when the `sponsorship/deal/{dealId}`
  destination is absent. Traces: AC-6.

- **TC-AND-365-12 — Route registration / More → Sponsorships.** Type: instrumented. Target:
  emulator `test35`. Preconditions: authenticated nav graph; More hub present. Steps: open More
  → Sponsorships. Expected: the inbox opens at route `sponsorship/inbox`. Traces: AC-1.

- **TC-AND-365-13 — Security: no secrets logged; cache app-private; cookie/CSRF/Bearer sent.**
  Type: integration. Target: JVM/Robolectric (transport assertions) + emulator (storage).
  Preconditions: redacted logger + log capture; MockWebServer recording headers. Steps: perform
  a load and a logout. Expected: outgoing GET carries session cookie, `X-CSRF-Token`, and
  `Authorization: Bearer`; logs contain no cookies/tokens/payout amounts/sponsor ids; Room DB
  lives in app-private storage; logout purges the cache. Traces: AC-2 (transport correctness),
  AC-5.

- **TC-AND-365-14 — Accessibility: TalkBack, touch targets, dynamic type, RTL.** Type:
  Compose-UI (a11y). Target: emulator `test35`. Preconditions: fixture with ≥2 deals.
  Steps: enable accessibility checks; inspect chips, rows, filter chips; switch to an RTL
  locale and large font scale. Expected: status/filter chips expose `contentDescription`;
  rows/chips ≥48dp; text scales with system font size; layout mirrors correctly in RTL; no
  unread-dot `stateDescription` (feature removed). Traces: AC-2, AC-4.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (More→Sponsorships opens `sponsorship/inbox`) | TC-AND-365-12 |
| AC-2 (Inbox lists offers, correct fields) | TC-AND-365-01, -03, -13, -14 |
| AC-3 (full list returned in one response, no cursor follow-up) | TC-AND-365-03 |
| AC-4 (status filter scopes list; `all` shows everything) | TC-AND-365-04, -05, -14 |
| AC-5 (Empty / Error+Retry / Offline-stale states) | TC-AND-365-06, -07, -08, -09, -10, -13 |
| AC-6 (guarded tap-through with correct `deal_id`) | TC-AND-365-11 |
| AC-7 (no accept/decline/negotiate controls) | TC-AND-365-01 |
| AC-8 (DTO↔domain, parsing, filter-param, 403/404→empty unit-tested) | TC-AND-365-02, -03, -04, -08 |
