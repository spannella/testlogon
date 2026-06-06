---
id: AND-197
title: VOD/video ViewModels
milestone: M4
epic: E26
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-189, AND-191]
blocks: []
---

# AND-197 — VOD/video ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer logic for the videos and VOD
surfaces of the TestLogon native Android port: the `ViewModel` classes that own
screen state, drive data loads through the repositories built in AND-189
(Videos library) and AND-191 (VOD catalog), and perform **entitlement / access
checks** before exposing a playable video to the UI. The deliverable is purely
the state machinery and gating logic; Compose screens, the ExoPlayer/Media3
playback surface, and the purchase flow are owned by separate downstream
tickets and are out of scope here.

Concretely, AND-197 produces three `ViewModel`s living in the
`feature-video` module:

- `VideoLibraryViewModel` — paged browse/grid state for the videos library.
- `VodCatalogViewModel` — VOD list + catalog-section state.
- `VideoDetailViewModel` — single-video detail state **plus** the entitlement
  decision that determines whether the detail screen renders a "Play",
  "Purchase", or "Locked" affordance.

The acceptance bar for the ticket is narrow and explicit: the logic must be
**unit-tested**. Every state transition, entitlement outcome, and error mapping
described below must be covered by JVM unit tests in `core-testing`'s harness
with no instrumented (device) dependency.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`,
  branch `android-port`.
- **Namespace:** `com.testlogon.android` (module package
  `com.testlogon.android.feature.video`).
- **Module layering:** `app -> feature-video -> core-{network,model,data,ui,testing}`.
  `ViewModel`s in this ticket depend only on repository interfaces and
  `core-model` types; they never touch Retrofit/OkHttp directly.
- **Upstream tickets (hard deps):**
  - **AND-189 (Videos library)** owns `videos.ts`-equivalent browse/grid data —
    provides `VideoRepository` + `VideoSummary` paging source consumed here.
  - **AND-191 (VOD catalog)** owns `vod.ts`-equivalent catalog + detail data —
    provides `VodRepository` and `VideoDetail`.
- **Web reference:** `frontend/src/api/endpoints/videos.ts`, `vod.ts`, and
  shared types in `frontend/src/api/types.ts` (not present in this checkout;
  treat the OpenAPI schema as authoritative when they disagree).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based session
  (`ui_csrf` echoed as `X-CSRF-Token`); 401 triggers one
  `POST /ui/session/refresh` + retry via the OkHttp authenticator from the
  networking ticket. This ticket assumes that infrastructure exists and does not
  re-implement it.
- **Relevant endpoints** (verified against `openapi.index.txt`):
  `GET /ui/videos` (`list_own_videos`, resp `VideoListOut`),
  `GET /ui/videos/gallery` (`browse_gallery_endpoint`, resp `GalleryListOut`),
  `GET /ui/videos/{video_id}` (`get_video_detail`, resp `VideoDetailOut`),
  `GET /ui/videos/{video_id}/access` (`check_video_access`, resp `VodAccessOut`).
  **Correction:** there is **no** `GET /ui/videos/{video_id}/pricing` endpoint — that
  claim was removed. The only `/pricing` route is `PATCH /ui/videos/{video_id}/pricing`
  (`set_video_pricing`, req `VodPricingIn`), which is creator-side and out of scope.
  Pricing/entitlement fields are returned **inline** on `VideoDetailOut`
  (`price_cents`, `access_mode`, `purchase_available`, `subscription_available`,
  `subscription_upsell`, `is_entitled`, `access_reason`); there is no separate
  pricing read. **Note:** `GET /ui/videos` is the caller's *own* videos
  (`list_own_videos`); the public browse surface is `GET /ui/videos/gallery`,
  `GET /ui/videos/public`, or `GET /ui/videos/by-creator/{creator_id}` — the
  dependency tickets (AND-189/191) choose the exact list endpoint.

## 3. Functional Requirements

FR-1. **Library state.** `VideoLibraryViewModel` exposes a paged stream of
`VideoSummary` items for the videos grid, surfaced as
`Flow<PagingData<VideoListItemUi>>`, plus a non-paged `StateFlow<LibraryUiState>`
carrying refresh/empty/error chrome.

FR-2. **VOD catalog state.** `VodCatalogViewModel` exposes
`StateFlow<VodCatalogUiState>` containing the ordered catalog sections
(e.g. featured, categories, continue-watching as supplied by AND-191) and the
flat VOD list for grid rendering.

FR-3. **Detail load.** `VideoDetailViewModel` accepts a `videoId: String`
(via `SavedStateHandle`), loads `VideoDetail` from the repository, and exposes
`StateFlow<VideoDetailUiState>`.

FR-4. **Entitlement check (core of this ticket).** On detail load the
`ViewModel` resolves the user's access to the video by combining (a) the
`VideoDetail` pricing/visibility flags and (b) `GET /ui/videos/{video_id}/access`.
The result is a sealed `Entitlement` value that maps to exactly one playable
state: `Granted`, `PurchaseRequired(price)`, `LoginRequired`, or
`Unavailable(reason)`.

FR-5. **No premature playback.** The detail state MUST NOT emit a playable
state (`Granted`) unless the entitlement check returned access. The UI gating
contract is: only `Entitlement.Granted` exposes a non-null `playbackVideoId`.

FR-6. **Refresh & retry.** Each `ViewModel` exposes `refresh()` (full reload)
and `retry()` (re-run only the failed operation). Library paging exposes
`retry()` via the Paging 3 `LoadState` mechanism.

FR-7. **Lifecycle safety.** All loads run in `viewModelScope`; in-flight loads
are cancelled and superseded on a newer `refresh()`/`load(videoId)`. State is
restored across process death for `videoId` and the last successful detail via
`SavedStateHandle`.

FR-8. **Deterministic, injectable time/dispatch.** Dispatchers are injected
(`@IoDispatcher CoroutineDispatcher`) so tests run on a `TestDispatcher`.

## 4. Technical Design

Module: `feature-video`. Hilt-injected `@HiltViewModel` classes. No Android
framework types leak into testable logic except `SavedStateHandle` (which is a
plain in-memory map under unit test).

> **Correction (model fields).** The field names below were aligned to the real
> backend DTOs `VideoListItem` / `VideoDetailOut` (verified in `openapi.pretty.json`
> and `src/api/endpoints/videos.ts`). Notable fixes: the id field is `video_id`
> (not `id`); duration is `duration_seconds` (a number, not `durationSec: Int`);
> the API has **no nested `pricing` object**, **no `currency` field anywhere**, and
> **no `purchased` boolean** — pricing/entitlement are *flat fields on the detail*
> (`price_cents`, `access_mode`, `purchase_available`, `subscription_available`,
> `subscription_upsell`, `is_entitled`, `access_reason`). There is no `isPremium`
> flag; "premium-ness" is inferred from `access_mode`/`price_cents`/
> `purchase_available`. `visibility` and `status` are **free-form strings** in the
> schema (no fixed enum) — the enum below is a client-side normalization
> (unverified assumption, see §16). Below is the corrected core-model shape AND-189/
> AND-191 should produce; this ticket consumes it.

```kotlin
// core-model (provided by AND-189/AND-191; referenced, not defined here).
// Field names mirror the backend DTOs (snake_case server -> camelCase via Moshi).
data class VideoSummary(
    val videoId: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSeconds: Double?,        // server: duration_seconds (number, nullable)
    val accessMode: String?,             // server: access_mode (nullable, free string)
    val priceCents: Int?,                // server: price_cents (nullable)
)

data class VideoDetail(
    val videoId: String,
    val title: String,
    val description: String?,
    val thumbnailUrl: String?,
    val durationSeconds: Double?,
    val visibility: String,              // free-form server string (e.g. "public")
    val status: String,                  // free-form server string (e.g. "ready")
    // Flat pay-per-view / subscription gating fields (no nested pricing object):
    val isEntitled: Boolean,             // server: is_entitled (default false)
    val accessMode: String?,             // server: access_mode (e.g. "ppv","subscriber_only")
    val accessReason: String,            // server: access_reason (default "none")
    val priceCents: Int?,                // server: price_cents (nullable)
    val purchaseAvailable: Boolean,      // server: purchase_available
    val subscriptionAvailable: Boolean,  // server: subscription_available
    val subscriptionUpsell: Boolean,     // server: subscription_upsell
)
```

> Currency is **not** modeled because the backend never returns it; price is a bare
> `price_cents` integer. Locale/currency formatting is deferred to the Compose layer
> (see §9), which must assume a single configured currency or fetch it elsewhere.

```kotlin
// feature-video — entitlement model owned by THIS ticket
sealed interface Entitlement {
    data class Granted(val playbackVideoId: String) : Entitlement
    data object SubscriptionRequired : Entitlement       // access_mode == "subscriber_only"
    data class PurchaseRequired(val priceCents: Int?) : Entitlement  // ppv / purchase_available
    data class PurchaseOrSubscribe(val priceCents: Int?) : Entitlement // subscription_upsell
    data object LoginRequired : Entitlement
    data class Unavailable(val reason: UnavailableReason) : Entitlement
}

enum class UnavailableReason { NOT_FOUND, REGION_BLOCKED, NOT_READY, UNKNOWN }
```

> **Correction (resolver inputs & precedence).** The original precedence keyed off
> `access.status == NOT_FOUND / REGION_BLOCKED / MODERATION_HELD` and `access.granted`.
> **None of those fields exist.** Verified: `VodAccessOut` exposes only `entitled`
> (bool, required), `reason` (free-form string, required), `access_mode`,
> `price_cents`, `purchase_available`, `subscription_available`, `subscription_upsell`,
> `purchase_type`, `expires_at`, `views_remaining`, `ads_enabled`, `download_allowed`
> — there is **no `status` enum, no `granted` field, no `video_id` in the response,
> and no nested pricing**. Region/geo blocking is **not** an access-status value: the
> web client detects it from an **HTTP 403 whose `detail.code == "geo_blocked"`**
> (`src/api/client.ts`), so REGION_BLOCKED is derived from the transport error, not
> the access body. `MODERATION_HELD` is not surfaced by the access DTO; the closest
> real signal is `VideoDetailOut.status` / `review_status` not being a playable state
> (modeled here as `NOT_READY`). The web reference (`VideoPlayerPage.tsx
> VideoAccessGate`) actually gates **entirely off the inline `VideoDetail` flags and
> never calls `/access`** — its precedence is: `is_entitled` → play; else
> `access_mode == "subscriber_only"` → subscribe; else `subscription_upsell` →
> purchase-or-subscribe; else `access_mode == "ppv" || purchase_available` → purchase.
> The corrected resolver below mirrors that web contract, treating the `/access`
> call as an optional authoritative confirmation of entitlement (fail-closed).

```kotlin
// Pure, side-effect-free resolver — the most heavily unit-tested unit.
object EntitlementResolver {
    fun resolve(
        detail: VideoDetail,
        access: VideoAccess?,       // from GET .../access; null/failed => fail closed
        isAuthenticated: Boolean,
    ): Entitlement
}
```

Resolution precedence (deterministic, top-down) — mirrors the web `VideoAccessGate`:

1. `detail.status` not in the playable set (e.g. not `"ready"`, or `review_status`
   pending) → `Unavailable(NOT_READY)`.
2. Entitled — `access?.entitled == true` **or** (`access == null && detail.isEntitled`)
   → `Granted(detail.videoId)`. (When the access call failed we fall back to the
   inline `is_entitled` flag but never *upgrade* a non-entitled result.)
3. `detail.accessMode == "subscriber_only"` →
   if `!isAuthenticated` → `LoginRequired` else `SubscriptionRequired`.
4. `detail.subscriptionUpsell` →
   if `!isAuthenticated` → `LoginRequired` else `PurchaseOrSubscribe(detail.priceCents)`.
5. `detail.accessMode == "ppv" || detail.purchaseAvailable` →
   if `!isAuthenticated` → `LoginRequired` else `PurchaseRequired(detail.priceCents)`.
6. fallback → `Unavailable(UNKNOWN)`.

> NOT_FOUND and REGION_BLOCKED are produced by the **error-mapping layer** (404 →
> `Unavailable(NOT_FOUND)`; 403 with `code == "geo_blocked"` →
> `Unavailable(REGION_BLOCKED)`), not by `EntitlementResolver`, because the access
> body carries no such status (see §5/§7).

```kotlin
@HiltViewModel
class VideoDetailViewModel @Inject constructor(
    private val vodRepository: VodRepository,        // AND-191
    private val accessRepository: VideoAccessRepository,
    private val sessionState: SessionStateProvider,   // exposes isAuthenticated: StateFlow<Boolean>
    @IoDispatcher private val io: CoroutineDispatcher,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedState["videoId"])
    private val _state = MutableStateFlow<VideoDetailUiState>(VideoDetailUiState.Loading)
    val state: StateFlow<VideoDetailUiState> = _state.asStateFlow()

    init { load() }

    fun load() { /* cancel prior job; launch in viewModelScope(io) */ }
    fun retry() = load()
    fun onPurchaseClicked() { /* emits navigation effect; purchase owned downstream */ }
}
```

```kotlin
@HiltViewModel
class VideoLibraryViewModel @Inject constructor(
    private val videoRepository: VideoRepository,    // AND-189
) : ViewModel() {
    val items: Flow<PagingData<VideoListItemUi>> =
        videoRepository.pagedLibrary().cachedIn(viewModelScope)
    private val _chrome = MutableStateFlow(LibraryUiState())
    val chrome: StateFlow<LibraryUiState> = _chrome.asStateFlow()
}
```

`VodCatalogViewModel` mirrors the detail pattern but loads catalog sections from
`VodRepository.catalog()` and exposes `StateFlow<VodCatalogUiState>`.

## 5. API Contract

This ticket consumes endpoints; the Retrofit `VideoApi` interface is owned by
AND-189/AND-191. The one DTO this ticket is responsible for binding to the
entitlement decision is the access check:

`GET /ui/videos/{video_id}/access` (op `check_video_access`, resp `VodAccessOut`)
Query: `user_sub?` (omitted — server resolves identity from session).
Headers: the web transport (`src/api/client.ts`) sends, in order: cookie session
(`credentials: include`), `Authorization: Bearer <accessToken>` when an access
token is present, `X-CSRF-Token` (echoed from the `ui_csrf` cookie), and
`X-IMPERSONATION-TOKEN` only while impersonating. **Correction:** the original spec
listed only "cookies + X-CSRF-Token"; the Bearer header (and the impersonation
header) were missing. The OkHttp layer (AND-027) must replicate this set.
Timeout: 20s; this is an idempotent GET, so bounded backoff retry applies.

**Corrected success response — actual `VodAccessOut` shape** (verified in
`openapi.pretty.json`; required fields are `entitled` and `reason`):

```json
{
  "entitled": false,
  "reason": "purchase_required",
  "access_mode": "ppv",
  "price_cents": 499,
  "purchase_type": "permanent",
  "purchase_available": true,
  "subscription_available": false,
  "subscription_upsell": false,
  "expires_at": null,
  "views_remaining": -1,
  "ads_enabled": false,
  "download_allowed": false
}
```

> Differences from the original (fabricated) example: there is no `video_id`,
> no `granted`, no `status` enum, and no nested `pricing`/`currency`/`purchased`.
> The boolean field is `entitled`; `reason` is a **free-form string** (e.g.
> `"purchase_required"`, `"none"`); pricing is flat (`price_cents`, no currency).

```kotlin
data class VideoAccess(
    val entitled: Boolean,              // server: entitled (required)
    val reason: String,                 // server: reason (required, free-form string)
    val accessMode: String?,            // server: access_mode (nullable)
    val priceCents: Int?,               // server: price_cents (nullable)
    val purchaseType: String,           // server: purchase_type (default "permanent")
    val purchaseAvailable: Boolean,     // server: purchase_available (default false)
    val subscriptionAvailable: Boolean, // server: subscription_available (default false)
    val subscriptionUpsell: Boolean,    // server: subscription_upsell (default false)
    val expiresAt: Long?,               // server: expires_at (epoch, nullable)
    val viewsRemaining: Int,            // server: views_remaining (default -1)
)
```

`reason` is a free string carried through verbatim (never thrown on); the resolver
keys off `entitled` + `access_mode` + the purchase/subscription flags, not `reason`.
FastAPI errors surface in `detail` and are mapped per the project convention
(`string | [{msg}] | {code,...}` — verified in `src/api/client.ts`
`normalizeErrorDetail`) by the shared `ApiResult` mapper. **Error → entitlement
mapping (done in the repository/mapper, not the resolver):** a 404 maps to
`Unavailable(NOT_FOUND)`; a 403 with `detail.code == "geo_blocked"` maps to
`Unavailable(REGION_BLOCKED)`; any other 403 → `LoginRequired` if unauthenticated,
else surfaced as a retryable `Error`.

Detail and list payloads (`GET /ui/videos/{video_id}`, `GET /ui/videos`,
`GET /ui/videos/gallery`) are defined in the dependency tickets; this spec
treats their mapped `core-model` types as the contract.

## 6. Data & State Management

UI state types (this ticket):

```kotlin
sealed interface VideoDetailUiState {
    data object Loading : VideoDetailUiState
    data class Ready(
        val detail: VideoDetail,
        val entitlement: Entitlement,
        val isStale: Boolean = false,
    ) : VideoDetailUiState
    data class Error(val error: UiError, val canRetry: Boolean) : VideoDetailUiState
}

data class VodCatalogUiState(
    val isLoading: Boolean = true,
    val sections: List<VodSection> = emptyList(),
    val error: UiError? = null,
    val isStale: Boolean = false,
)

data class LibraryUiState(val isRefreshing: Boolean = false, val error: UiError? = null)
```

- **Source of truth:** repositories (Room-backed cache from `core-data`).
  `ViewModel`s never cache business data themselves beyond the current
  `StateFlow` snapshot.
- **Offline / stale:** when the repository returns cached data while the network
  fetch fails, `Ready.isStale = true` / `VodCatalogUiState.isStale = true` so
  the UI can show a stale banner. The library exposes staleness through Paging
  `LoadState`.
- **Process death:** `videoId` is persisted in `SavedStateHandle`; on
  restoration the detail reloads (cache-first) rather than serializing the whole
  `VideoDetail`.
- **`StateFlow` sharing:** detail/catalog use `MutableStateFlow`; paging uses
  `cachedIn(viewModelScope)`. No `stateIn` with `WhileSubscribed` is required
  because state is push-driven by explicit `load()`.

## 7. Error Handling & Resilience

- All repository calls return `ApiResult<T>`; `ViewModel`s exhaustively `when`
  over `Success`/`Error` and never throw to the collector.
- **Detail composite load:** `VideoDetail` and `VideoAccess` load concurrently
  via `async`/`awaitAll`. If `VideoDetail` fails → `Error`. If only the access
  check fails, the resolver is invoked with `access = null` (per the corrected
  `resolve(detail, access: VideoAccess?, …)` signature), so it falls back to the
  inline `detail.isEntitled` flag but never *upgrades* a non-entitled detail to
  `Granted` — failing closed on entitlement.
- **Timeouts:** 20s per call (OkHttp layer). Bounded exponential backoff
  (max 2 retries, idempotent GETs only) is applied in the repository, not the
  `ViewModel`.
- **401:** handled transparently by the OkHttp authenticator
  (`POST /ui/session/refresh` once, then retry). A persistent post-refresh 401
  surfaces as `LoginRequired` for the detail screen.
- **Cancellation:** superseded loads are cancelled; cancellation is never mapped
  to an `Error` state.
- `retry()` re-runs only the failed leg; `refresh()` re-runs everything.

## 8. Security & Privacy

- **Fail-closed entitlement:** the client treats the server access check as
  authoritative but never upgrades to `Granted` on a missing/ambiguous response.
  Client-side `pricing.purchased` is a UI hint only; playback authorization is
  re-validated server-side at playback-URL issuance (downstream ticket).
- No tokens or credentials are read or logged here; session lives in the
  encrypted cookie jar from the networking ticket.
- The `user_sub` query param is intentionally omitted so the server derives
  identity from the session cookie (prevents client identity spoofing).
- Plaintext HTTP dev backend: no secrets are transmitted in this ticket's
  requests beyond the session cookie already managed upstream. No PII is cached
  in `SavedStateHandle`.

## 9. Accessibility & i18n

Largely deferred to the Compose screen tickets, but this layer enforces two
things that affect a11y/i18n correctness:

- All user-facing strings (entitlement reasons, error messages) are exposed as
  **string resource ids / typed enums**, never hardcoded English, so the UI
  layer resolves localized text. `UnavailableReason` and `AccessStatus` are
  enums precisely so copy can be localized downstream.
- Price formatting is **not** done in the `ViewModel`; the raw `priceCents: Int`
  is passed through verbatim for locale-aware formatting in Compose. This keeps
  currency/locale concerns out of testable logic and avoids baking `$` into state.
  **Correction:** the backend returns **no currency code** (`VideoDetailOut` /
  `VodAccessOut` expose only `price_cents`); the original "`amountCents` + `currency`"
  pair was inaccurate. The Compose layer must therefore assume a single configured
  storefront currency (the web reference hard-codes `$` in `VideoPlayerPage.tsx`)
  or obtain currency from another source — flagged as an open assumption in §16.

## 10. Telemetry & Logging

- Emit structured analytics events through the injected `Analytics` facade:
  `video_detail_viewed { videoId, entitlement: <name> }`,
  `entitlement_resolved { videoId, status }`,
  `video_load_failed { videoId, errorKind }`.
- Logging uses the project logger at `DEBUG` for state transitions and `WARN`
  for mapped errors; **never** log cookies, CSRF tokens, or full response
  bodies.
- Entitlement outcomes are logged by `status` enum name only (no pricing
  amounts at `INFO`+), to avoid leaking purchase intent in shared logs.

## 11. Testing Strategy

Acceptance requires **unit-tested**; this is the bulk of the work. JVM tests in
`feature-video` using JUnit4, `kotlinx-coroutines-test`
(`runTest` + `StandardTestDispatcher`), Turbine for `StateFlow` assertions, and
fakes from `core-testing` (`FakeVodRepository`, `FakeVideoAccessRepository`,
`FakeSessionStateProvider`). No MockWebServer needed at this layer.

`EntitlementResolver` (pure) — table-driven tests covering every branch. Columns
reflect the corrected inputs (`detail` flags + optional `access`, `isAuthenticated`);
`access.entitled` is the only access field consulted:

| detail.status | access | detail flags | authed | expected |
|---|---|---|---|---|
| ready | entitled=true | — | any | `Granted` |
| ready | null | isEntitled=true | any | `Granted` (inline fallback) |
| ready | entitled=false | accessMode="ppv", price=499 | true | `PurchaseRequired(499)` |
| ready | entitled=false | accessMode="ppv" | false | `LoginRequired` |
| ready | entitled=false | accessMode="subscriber_only" | true | `SubscriptionRequired` |
| ready | entitled=false | subscriptionUpsell=true, price=499 | true | `PurchaseOrSubscribe(499)` |
| ready | null | isEntitled=false, purchaseAvailable=true | true | `PurchaseRequired(price)` (fail-closed: access failed) |
| not_ready/pending | any | — | any | `Unavailable(NOT_READY)` |
| ready | entitled=false | no gating flags set | any | `Unavailable(UNKNOWN)` |

The 404 → `Unavailable(NOT_FOUND)` and 403/`geo_blocked` → `Unavailable(REGION_BLOCKED)`
mappings are tested at the repository/mapper layer (contract tests), not in the
pure resolver, since they derive from HTTP status not the access body.

`VideoDetailViewModel`:
- Loading → Ready emits in order (Turbine).
- Detail success + access failure → Ready with non-`Granted` entitlement (fail-closed).
- Detail failure → Error(canRetry=true); `retry()` re-emits Loading → Ready.
- Stale: repository returns cached + network error → `Ready.isStale = true`.
- `SavedStateHandle["videoId"]` drives the load; missing id → `IllegalState`.
- Superseded load: rapid double `load()` cancels the first (assert single final emission).

`VideoLibraryViewModel` / `VodCatalogViewModel`:
- Paging emits non-empty `PagingData` (AsyncPagingDataDiffer in test).
- Catalog success orders sections as repository supplies; error → error state;
  `refresh()` clears prior error.

Coverage target: 100% of `EntitlementResolver` branches; ≥85% line coverage of
the three `ViewModel`s (enforced via JaCoCo in `core-testing` gradle config).

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):**
  - **AND-189** — `VideoRepository` + library paging source.
  - **AND-191** — `VodRepository`, `VideoDetail`/`VideoSummary` models, and the
    `VideoApi` Retrofit interface incl. `.../access`.
- **Transitive:** AND-027 (API/networking + cookie jar + CSRF + refresh
  authenticator), AND-103 (paging/grid infrastructure) — pulled in via 189/191.
- **Sequencing:** Land after 189 and 191. This ticket BLOCKS the VOD/video
  Compose screen and playback (Media3) tickets, which consume these
  `ViewModel`s and the `Entitlement` model. If `VideoAccessRepository` does not
  yet exist in 191, this ticket adds it (thin wrapper over the existing
  `VideoApi.checkAccess`) rather than waiting.

## 13. Risks & Open Questions

- **R1.** `VodAccessOut.reason` (and `VideoDetailOut.access_reason`/`status`/
  `visibility`) are typed as **open free-form strings** in the OpenAPI schema, so
  their canonical value sets are not enumerated. Mitigation: the resolver ignores
  `reason` entirely and keys off the typed booleans (`entitled`,
  `purchase_available`, `subscription_available`, `subscription_upsell`) plus
  `access_mode` string comparisons (`"ppv"`, `"subscriber_only"`), exactly as the
  web `VideoAccessGate` does; unknown `access_mode` falls through to
  `Unavailable(UNKNOWN)`. *Open: confirm the canonical `access_mode`/`status` string
  set and the playable `status` set with the backend.*
- **R2.** Whether `VideoDetail.is_entitled` and `VodAccessOut.entitled` can ever
  disagree (e.g. refund, or detail cached). Resolver trusts `access.entitled` when
  the access call succeeds and only falls back to `detail.isEntitled` when access
  is null/failed (and never upgrades). *Open: confirm the access check is
  authoritative over the inline detail flag.*
- **R3.** Continue-watching / progress for VOD sections may require a separate
  endpoint not in scope; AND-197 renders only sections AND-191 supplies.
- **R4.** Unreliable dev host may make "stale" the common path; test fixtures
  must explicitly exercise the cache-hit + network-fail combination.

## 14. Acceptance Criteria

AC-1. `feature-video` contains `VideoLibraryViewModel`, `VodCatalogViewModel`,
and `VideoDetailViewModel`, all `@HiltViewModel`, exposing `StateFlow`/
`Flow<PagingData>` as specified — no business logic in Compose.

AC-2. `EntitlementResolver.resolve(...)` is implemented and **fails closed**:
no input combination produces `Granted` unless access is genuinely granted; an
absent/`UNKNOWN` access result never yields `Granted`.

AC-3. `VideoDetailUiState.Ready` exposes a non-null `playbackVideoId` **only**
via `Entitlement.Granted`.

AC-4. Concurrent detail+access load, supersession/cancellation, `refresh()`,
`retry()`, and stale-cache behavior all work as specified.

AC-5. **Unit tests** (the ticket's stated acceptance) exist and pass: full
branch coverage of `EntitlementResolver` and the `ViewModel` state-transition
tests from §11, runnable via `./gradlew :feature-video:testDebugUnitTest` with
no device/emulator.

AC-6. No Retrofit/OkHttp/Android-framework type (other than `SavedStateHandle`)
is referenced from the resolver or testable `ViewModel` logic.

## 15. Definition of Done

- All §14 acceptance criteria met; CI green on branch `android-port`.
- `./gradlew :feature-video:testDebugUnitTest` passes; JaCoCo thresholds
  (100% resolver branches, ≥85% `ViewModel` lines) enforced and met.
- `ktlint`/`detekt` clean; no new lint baseline entries.
- Public APIs (`Entitlement`, `VideoAccess`, the three `ViewModel`s) have KDoc.
- PR links AND-189 and AND-191, notes the downstream Compose/playback tickets it
  unblocks, and records resolved answers to R1/R2 (or carries them forward as
  tracked follow-ups).
- No secrets, cookies, or CSRF tokens logged; analytics events from §10 emitted
  and verified in a unit test via the fake `Analytics` facade.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **`GET /ui/videos/{video_id}/access` exists, op `check_video_access`, resp
   `VodAccessOut`.** VERIFIED — OpenAPI `GET /ui/videos/{video_id}/access`
   (`openapi.index.txt` line 2011).
2. **`GET /ui/videos/{video_id}` returns `VideoDetailOut`, op `get_video_detail`.**
   VERIFIED — OpenAPI `GET /ui/videos/{video_id}` (index line 2009);
   `src/api/endpoints/videos.ts: getVideoDetail`.
3. **`GET /ui/videos` (list), `GET /ui/videos/gallery` (browse).** VERIFIED —
   OpenAPI `GET /ui/videos` (`VideoListOut`, index 1994) and `GET /ui/videos/gallery`
   (`GalleryListOut`, index 1999). Note: `/ui/videos` is `list_own_videos`, not a
   public browse list.
4. **`GET /ui/videos/{video_id}/pricing` exists.** CORRECTED (removed) — no such
   route in `openapi.index.txt`; only `PATCH /ui/videos/{video_id}/pricing`
   (`set_video_pricing`, req `VodPricingIn`, index 2029). Pricing is inline on
   `VideoDetailOut`.
5. **Access response has `granted`, `status` enum, and nested
   `pricing{amount_cents,currency,purchased}`.** CORRECTED — `VodAccessOut`
   (`openapi.pretty.json` lines 82127-82212) has required `entitled` (bool) +
   `reason` (free string), plus flat `access_mode`, `price_cents`, `purchase_type`,
   `purchase_available`, `subscription_available`, `subscription_upsell`,
   `expires_at`, `views_remaining`, `ads_enabled`, `download_allowed`. No
   `granted`, no `status`, no `video_id`, no nested pricing, no currency.
6. **`VideoDetail` uses `id`, `durationSec: Int`, nested `pricing` with `currency`
   and `purchased`, and an `isPremium` flag.** CORRECTED — `VideoDetailOut`
   (`openapi.pretty.json` 80693-81192; `src/api/endpoints/videos.ts: VideoDetail`)
   uses `video_id`, `duration_seconds` (number), and flat fields `is_entitled`,
   `access_mode`, `access_reason`, `price_cents`, `purchase_available`,
   `subscription_available`, `subscription_upsell`. No `id`, no `currency`, no
   `purchased`, no `isPremium`.
7. **Entitlement precedence keyed on `access.status == NOT_FOUND/REGION_BLOCKED/
   MODERATION_HELD` and `access.granted`.** CORRECTED — those fields do not exist
   (see #5). Real gating contract is `src/pages/videos/VideoPlayerPage.tsx:
   VideoAccessGate` (lines 215-278): `is_entitled` → play; `access_mode ==
   "subscriber_only"` → subscribe; `subscription_upsell` → purchase-or-subscribe;
   `access_mode == "ppv" || purchase_available` → purchase.
8. **REGION_BLOCKED is an access status value.** CORRECTED — geo blocking is an
   HTTP 403 whose `detail.code == "geo_blocked"`, handled in
   `src/api/client.ts` (lines 240-255), not an access-body field.
9. **`status` parsed via Moshi with `UNKNOWN` fallback; error detail shape is
   `string | [{msg}] | {code,...}`.** Error-shape claim VERIFIED —
   `src/api/client.ts: normalizeErrorDetail` (lines 66-102). The `status` Moshi
   adapter is moot since the enum was removed (CORRECTED); the same
   never-throw/fallback principle now applies to the free-form `reason`/
   `access_mode` strings.
10. **Auth/CSRF: cookie session + `X-CSRF-Token` (from `ui_csrf`); 401 →
    one `POST /ui/session/refresh` + retry.** VERIFIED but INCOMPLETE/CORRECTED —
    `src/api/client.ts` (lines 121-237) confirms `ui_csrf` cookie → `X-CSRF-Token`,
    `credentials: include`, and the single `POST /ui/session/refresh`-then-retry on
    401. It ALSO sends `Authorization: Bearer <accessToken>` (lines 157-160) and
    `X-IMPERSONATION-TOKEN` while impersonating (lines 162-165), which the spec
    omitted — added in §5. The OpenAPI params also list `X-SESSION-ID` /
    `X-IMPERSONATION-TOKEN` on these routes (index 2009/2011).
11. **List/paging is cursor-based (`items` + `cursor`).** VERIFIED — `VideoListOut`
    (`openapi.pretty.json` 81310-81336: `items` required, nullable `cursor`);
    `src/api/endpoints/videos.ts: VideoListResponse`.
12. **The web client calls `/access` for the detail/player screen.** UNVERIFIED →
    CORRECTED to "not used by web" — no reference to `/ui/videos/{id}/access` exists
    in `src/` (grep); the only `/access` call is `vodRental.ts:18`
    (`/ui/vod/rental/{id}/access`, a different feature). The web player gates purely
    off inline `VideoDetail` flags. The Android resolver still consumes `/access`
    (it exists in OpenAPI) as optional authoritative confirmation, but its behavior
    cannot be validated against web behavior.
13. **`@HiltViewModel`, `viewModelScope`, `SavedStateHandle`, Paging 3
    `cachedIn`/`LoadState`, `StateFlow`/`Flow<PagingData>`.** VERIFIED (framework
    ref) — Android Architecture Components / Hilt / Paging 3 standard APIs
    (developer.android.com/topic/libraries/architecture/viewmodel,
    developer.android.com/topic/libraries/architecture/paging/v3-overview).
14. **`kotlinx-coroutines-test` `runTest`/`StandardTestDispatcher`, Turbine for
    Flow assertions, JaCoCo coverage.** VERIFIED (framework ref) — standard test
    tooling (github.com/cashapp/turbine; kotlinlang.org coroutines test guide).

### Corrections made

- §2: removed the non-existent `GET /ui/videos/{video_id}/pricing`; relabeled the
  access op (`check_video_access` → `VodAccessOut`) and clarified `/ui/videos`
  vs. gallery/public browse.
- §4: rewrote `VideoSummary`/`VideoDetail` to the real DTO fields (`video_id`,
  `duration_seconds`, flat `is_entitled`/`access_mode`/`price_cents`/
  `purchase_available`/`subscription_available`/`subscription_upsell`); removed the
  fabricated nested `VideoPricing`/`currency`/`purchased` and `isPremium`.
- §4: replaced the entitlement model and resolver precedence (built on the
  non-existent `access.status`/`access.granted`) with the real web-mirrored contract
  using `entitled` + `access_mode` + purchase/subscription flags; moved NOT_FOUND /
  REGION_BLOCKED to the HTTP error-mapping layer; renamed `UnavailableReason`
  members (dropped `MODERATION_HELD`, added `NOT_READY`); made `access` nullable for
  fail-closed fallback.
- §5: corrected the access JSON example and `VideoAccess` Kotlin model to the real
  `VodAccessOut` shape; added the missing `Authorization: Bearer` and
  `X-IMPERSONATION-TOKEN` headers; corrected the 403/`geo_blocked` mapping.
- §7: synthesized-access fallback changed from
  `VideoAccess(status=UNKNOWN, granted=false)` to `access = null`.
- §9: removed the `currency` claim (API returns only `price_cents`).
- §11: rewrote the resolver test table to the corrected inputs/outcomes.
- §13: R1/R2 updated to reference real fields (`reason`/`access_mode` free strings;
  `entitled` vs `is_entitled`).

### Open assumptions

- **Playable `status` set / `access_mode` value set.** `VideoDetailOut.status`,
  `visibility`, `access_reason`, and `VodAccessOut.reason`/`access_mode` are
  free-form strings in OpenAPI; the resolver assumes `"ready"` is playable and
  `"ppv"`/`"subscriber_only"` are the gating modes (matching the web). Unverifiable
  beyond the two `access_mode` literals seen in `VideoPlayerPage.tsx`. Mitigated by
  fail-closed fallback to `Unavailable(UNKNOWN)`.
- **Currency.** No currency code anywhere in the API; the chosen storefront
  currency is an external/UI assumption (web hard-codes `$`).
- **`VideoSummary` paging fields** (`access_mode`/`price_cents` on list items):
  present on `CreatorVideoListItem`/gallery items but the exact list endpoint and
  its item fields are owned by AND-189/AND-191 — assumed, not fixed here.
- **`MODERATION_HELD` surfacing.** No access/detail field directly exposes a
  moderation-hold state to viewers; modeled indirectly via `status`/`review_status`
  not being playable (`NOT_READY`). Unverified.
- **`/access` runtime behavior.** The endpoint exists in OpenAPI but is exercised by
  no frontend code, so its live semantics (when `entitled` flips, `reason` values)
  cannot be confirmed against the reference app — only against the schema.

## 17. Test Plan

All cases are JVM/local unless noted. This ticket's acceptance is "unit-tested,"
so the core suite is JVM unit/Robolectric on the **JVM unit/Robolectric** target
(no device). Contract cases use **MockWebServer** to pin the real DTO wire shapes.
A small number of device cases exist only to guard ABI/API-level differences in the
pure logic; none of this ticket's logic needs camera/biometrics/WebRTC, so the
physical Galaxy A15 is used only for the ABI-difference smoke (TC-12). AC IDs refer
to §14.

- **TC-AND-197-01** — Type: unit (JVM). Target: JVM unit/Robolectric. Test target:
  `EntitlementResolver`. Preconditions: `detail.status="ready"`,
  `access.entitled=true`. Steps: call `resolve(detail, access, isAuthenticated=any)`.
  Expected: `Entitlement.Granted(detail.videoId)`; `playbackVideoId == videoId`.
  Traces: AC-2, AC-3.
- **TC-AND-197-02** — Type: unit (JVM). Target: JVM unit. Test target:
  `EntitlementResolver` fail-closed fallback. Preconditions: `access = null`
  (access call failed), `detail.isEntitled=true`. Steps: `resolve(detail, null, any)`.
  Expected: `Granted` (inline fallback). Then with `detail.isEntitled=false,
  purchaseAvailable=true` → `PurchaseRequired`, never `Granted`. Traces: AC-2.
- **TC-AND-197-03** — Type: unit (JVM). Target: JVM unit. Test target:
  `EntitlementResolver` PPV branch. Preconditions: `entitled=false`,
  `accessMode="ppv"`, `priceCents=499`. Steps: resolve with `isAuthenticated=true`,
  then `false`. Expected: `PurchaseRequired(499)` when authed; `LoginRequired` when
  not. Traces: AC-2.
- **TC-AND-197-04** — Type: unit (JVM). Target: JVM unit. Test target:
  `EntitlementResolver` subscription branches. Preconditions: (a)
  `accessMode="subscriber_only"`; (b) `subscriptionUpsell=true, priceCents=499`.
  Steps: resolve (authed). Expected: (a) `SubscriptionRequired`; (b)
  `PurchaseOrSubscribe(499)`. With `isAuthenticated=false` both → `LoginRequired`.
  Traces: AC-2.
- **TC-AND-197-05** — Type: unit (JVM). Target: JVM unit. Test target:
  `EntitlementResolver` NOT_READY + UNKNOWN fallback. Preconditions: (a)
  `detail.status="pending"` / non-playable; (b) `status="ready"`, `entitled=false`,
  no gating flags, unknown `access_mode`. Steps: resolve. Expected: (a)
  `Unavailable(NOT_READY)`; (b) `Unavailable(UNKNOWN)` — never `Granted`.
  Traces: AC-2, AC-3.
- **TC-AND-197-06** — Type: unit (JVM, coroutines-test + Turbine). Target: JVM unit.
  Test target: `VideoDetailViewModel` happy path. Preconditions:
  `FakeVodRepository` returns detail; `FakeVideoAccessRepository` returns
  `entitled=true`; `SavedStateHandle["videoId"]="vid_1"`. Steps: construct VM,
  collect `state` via Turbine on `StandardTestDispatcher`. Expected: emits
  `Loading` then `Ready(detail, Granted, isStale=false)`; `playbackVideoId` non-null.
  Traces: AC-1, AC-3, AC-4.
- **TC-AND-197-07** — Type: unit (JVM). Target: JVM unit. Test target:
  `VideoDetailViewModel` access-failure fail-closed. Preconditions: detail succeeds,
  access repo returns `Error`. Steps: construct VM, collect. Expected: `Ready` with a
  non-`Granted` entitlement (resolver invoked with `access=null`); never emits
  `Granted`. Traces: AC-2, AC-4.
- **TC-AND-197-08** — Type: unit (JVM). Target: JVM unit. Test target:
  `VideoDetailViewModel` error + retry, supersession, missing id. Preconditions:
  detail repo returns `Error` first, success on retry. Steps: (a) collect →
  `Error(canRetry=true)`; call `retry()` → `Loading`→`Ready`. (b) call `load()`
  twice rapidly; assert a single final emission (first job cancelled, not surfaced as
  `Error`). (c) construct with no `videoId` in `SavedStateHandle`; assert
  `IllegalStateException` from `checkNotNull`. Traces: AC-4.
- **TC-AND-197-09** — Type: unit (JVM). Target: JVM unit. Test target:
  `VideoDetailViewModel` stale-cache (flaky/offline dev host). Preconditions: repo
  emits cached detail then a network error. Steps: collect. Expected: `Ready` with
  `isStale=true`; cancellation/network error never mapped to a crash. Traces: AC-4.
- **TC-AND-197-10** — Type: unit (JVM, Paging test). Target: JVM unit. Test target:
  `VideoLibraryViewModel` + `VodCatalogViewModel`. Preconditions: fakes supply a
  `PagingData` page and ordered catalog sections; one fake returns error. Steps: use
  `AsyncPagingDataDiffer` to snapshot library items; collect catalog `StateFlow`;
  trigger error then `refresh()`. Expected: non-empty `PagingData`; catalog sections
  in repository order; error state set then cleared by `refresh()`. Traces: AC-1,
  AC-4.
- **TC-AND-197-11** — Type: contract/MockWebServer. Target: JVM unit (Robolectric
  not required; OkHttp + MockWebServer on JVM). Test target: `VideoAccessRepository`
  / `VodAccessOut` + `VideoDetailOut` deserialization and error mapping.
  Preconditions: MockWebServer enqueues (a) a real `VodAccessOut` body (the §5 JSON),
  (b) a 404, (c) a 403 with `{"detail":{"code":"geo_blocked","message":"..."}}`,
  (d) a 422 `HTTPValidationError` (`[{"msg":...}]`). Steps: call the repo for each.
  Expected: (a) parses to `VideoAccess(entitled=false, reason="purchase_required",
  priceCents=499, …)` with unknown fields tolerated; (b) → `Unavailable(NOT_FOUND)`;
  (c) → `Unavailable(REGION_BLOCKED)` via `detail.code=="geo_blocked"`; (d) →
  retryable `Error` with the `msg` surfaced (matches `normalizeErrorDetail`).
  Traces: AC-2, AC-6.
- **TC-AND-197-12** — Type: contract/MockWebServer. Target: JVM unit. Test target:
  transport header contract for the access GET. Preconditions: cookie jar holds a
  `ui_csrf` cookie + session; an access token is set; not impersonating. Steps:
  issue the `/access` GET through the configured OkHttp stack; capture the recorded
  request. Expected: request carries the session cookie, `X-CSRF-Token` echoing
  `ui_csrf`, and `Authorization: Bearer <token>`; no `X-IMPERSONATION-TOKEN` when not
  impersonating; `user_sub` query param absent (server derives identity). Traces:
  AC-6 (and §5/§8 security contract).
- **TC-AND-197-13** — Type: unit (JVM). Target: JVM unit. Test target: security /
  no-secret-logging + telemetry. Preconditions: fake `Analytics` + capturing logger.
  Steps: drive a full detail load with a `PurchaseRequired` outcome. Expected:
  `video_detail_viewed` and `entitlement_resolved` events emitted with enum/status
  names only (no `price_cents`, no cookies/CSRF/Authorization values in any log line).
  Traces: AC-2 (fail-closed/security), supports §8/§10.
- **TC-AND-197-14** — Type: instrumented (ABI/API smoke). Target: **physical device
  Samsung Galaxy A15 5G (SM-A156U, R5CX821TA9R, arm64-v8a, API 34)** — and re-run on
  emulator AVD `test35` (x86_64, API 35). Test target: `EntitlementResolver` +
  Moshi/number parsing of `duration_seconds`/`price_cents`. Preconditions: built test
  APK installed via adb. Steps: run the resolver + DTO-parse suite as an instrumented
  test on each device. Expected: identical results on arm64-v8a/API 34 and
  x86_64/API 35 (guards against ABI/JSON-number/`Double` rounding differences in the
  pure logic). MUST run on the physical device for the arm64 leg; emulator covers the
  API-35 leg. Traces: AC-5 (cross-device determinism of the unit logic).

> No camera/biometrics/FCM/WebRTC/Telecom/HLS cases: this ticket is pure presentation
> + entitlement logic with no hardware surface, so those device capabilities are not
> exercised here (they belong to the downstream Compose/playback tickets).
> Accessibility: this layer has no UI, but TC-09/TC-10 assert that user-facing reasons
> are exposed as typed enums/string-resource keys (not hardcoded English), which is the
> a11y/i18n contract this ticket owns (§9); full Compose a11y checks are downstream.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC-1 (the three `@HiltViewModel`s, correct exposed types) | TC-06, TC-10 |
| AC-2 (`EntitlementResolver` fails closed; no spurious `Granted`) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-07, TC-11, TC-13 |
| AC-3 (`playbackVideoId` only via `Granted`) | TC-01, TC-05, TC-06 |
| AC-4 (concurrent load, supersession, refresh/retry, stale) | TC-06, TC-07, TC-08, TC-09, TC-10 |
| AC-5 (unit tests exist and pass, no device) | TC-01..TC-11, TC-13; TC-14 cross-device |
| AC-6 (no Retrofit/OkHttp/Android types in resolver/VM logic) | TC-11, TC-12 (transport isolated in repo layer) |
