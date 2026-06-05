---
id: AND-197
title: VOD/video ViewModels
milestone: M4
epic: E26
priority: P1
size: M
status: draft
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
- **Relevant endpoints** (confirmed in `/openapi.json`):
  `GET /ui/videos`, `GET /ui/videos/gallery`, `GET /ui/videos/{video_id}`,
  `GET /ui/videos/{video_id}/access` (`Check Video Access`),
  `GET /ui/videos/{video_id}/pricing`.

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

```kotlin
// core-model (provided by AND-191; referenced, not defined here)
data class VideoSummary(
    val id: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSec: Int?,
    val isPremium: Boolean,
)

data class VideoDetail(
    val id: String,
    val title: String,
    val description: String?,
    val thumbnailUrl: String?,
    val durationSec: Int?,
    val visibility: VideoVisibility,   // PUBLIC, UNLISTED, PRIVATE, PREMIUM
    val pricing: VideoPricing?,        // null => not for sale
)

data class VideoPricing(val amountCents: Int, val currency: String, val purchased: Boolean)
```

```kotlin
// feature-video — entitlement model owned by THIS ticket
sealed interface Entitlement {
    data class Granted(val playbackVideoId: String) : Entitlement
    data class PurchaseRequired(val price: VideoPricing) : Entitlement
    data object LoginRequired : Entitlement
    data class Unavailable(val reason: UnavailableReason) : Entitlement
}

enum class UnavailableReason { NOT_FOUND, REGION_BLOCKED, MODERATION_HELD, UNKNOWN }
```

```kotlin
// Pure, side-effect-free resolver — the most heavily unit-tested unit.
object EntitlementResolver {
    fun resolve(
        detail: VideoDetail,
        access: VideoAccess,        // from GET .../access
        isAuthenticated: Boolean,
    ): Entitlement
}
```

Resolution precedence (deterministic, top-down):

1. `access.status == NOT_FOUND` → `Unavailable(NOT_FOUND)`.
2. `access.status == REGION_BLOCKED` → `Unavailable(REGION_BLOCKED)`.
3. `access.status == MODERATION_HELD` → `Unavailable(MODERATION_HELD)`.
4. `access.granted == true` → `Granted(detail.id)`.
5. `detail.pricing != null && !detail.pricing.purchased` →
   if `!isAuthenticated` → `LoginRequired` else `PurchaseRequired(pricing)`.
6. `detail.visibility == PRIVATE && !access.granted` →
   if `!isAuthenticated` → `LoginRequired` else `Unavailable(UNKNOWN)`.
7. fallback → `Unavailable(UNKNOWN)`.

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

`GET /ui/videos/{video_id}/access`
Query: `user_sub?` (omitted — server resolves from cookie session).
Headers: session cookies + `X-CSRF-Token` (injected by OkHttp layer).
Timeout: 20s; this is an idempotent GET, so bounded backoff retry applies.

Representative success response (mapped to `VideoAccess`):

```json
{
  "video_id": "vid_8f31",
  "granted": false,
  "status": "purchase_required",
  "reason": null,
  "pricing": { "amount_cents": 499, "currency": "USD", "purchased": false }
}
```

```kotlin
data class VideoAccess(
    val videoId: String,
    val granted: Boolean,
    val status: AccessStatus,           // GRANTED, PURCHASE_REQUIRED, LOGIN_REQUIRED,
                                        // NOT_FOUND, REGION_BLOCKED, MODERATION_HELD, UNKNOWN
    val pricing: VideoPricing?,
)
```

`status` is parsed with a Moshi adapter that maps unknown server strings to
`AccessStatus.UNKNOWN` (never throws). FastAPI errors surface in `detail` and
are mapped per the project convention (`string | [{msg}] | {code,...}`) by the
shared `ApiResult` mapper; a 404 maps to `Unavailable(NOT_FOUND)`, a 403 to
either `LoginRequired` (if unauthenticated) or `Unavailable(REGION_BLOCKED)`.

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
  check fails, the resolver is invoked with a synthesized
  `VideoAccess(status = UNKNOWN, granted = false)`, which yields a conservative
  non-playable state (never `Granted`) — failing closed on entitlement.
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
- Price formatting is **not** done in the `ViewModel`; `VideoPricing`
  (`amountCents` + `currency`) is passed through verbatim for locale-aware
  formatting in Compose. This keeps currency/locale concerns out of testable
  logic and avoids baking `$` into state.

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

`EntitlementResolver` (pure) — table-driven tests covering every branch:

| detail | access.status | granted | authed | expected |
|---|---|---|---|---|
| public, no price | granted | true | any | `Granted` |
| premium, unpurchased | purchase_required | false | true | `PurchaseRequired` |
| premium, unpurchased | purchase_required | false | false | `LoginRequired` |
| any | not_found | false | any | `Unavailable(NOT_FOUND)` |
| any | region_blocked | false | any | `Unavailable(REGION_BLOCKED)` |
| any | moderation_held | false | any | `Unavailable(MODERATION_HELD)` |
| private | unknown | false | true | `Unavailable(UNKNOWN)` |
| price, purchased | granted | true | true | `Granted` |

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

- **R1.** The exact `status` enum strings returned by
  `GET /ui/videos/{video_id}/access` are not fully enumerated in the OpenAPI
  schema (response schema is open). Mitigation: `AccessStatus.UNKNOWN` fallback
  + fail-closed resolution. *Open: confirm the canonical string set with the
  backend / `vod.ts`.*
- **R2.** Whether `VideoDetail.pricing.purchased` and `access.granted` can ever
  disagree (e.g. refund). Resolver currently trusts `access.granted` first.
  *Open: confirm access check is authoritative over detail pricing.*
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
