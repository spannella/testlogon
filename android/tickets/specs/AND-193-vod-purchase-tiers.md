---
id: AND-193
title: VOD purchase tiers
milestone: M4
epic: E26
priority: P2
size: M
status: draft
depends_on: [AND-191, AND-031]
blocks: []
---

# AND-193 — VOD purchase tiers

## 1. Overview & Goal

Deliver **tiered purchase** for VOD (video-on-demand) content in the TestLogon native Android app. A VOD item exposed by the catalog (AND-191) may be locked behind one or more purchase **tiers** (e.g. *Rent 48h*, *Buy*, *Premium bundle*). This ticket lets a signed-in user view the available tiers for a locked VOD, select one, complete the purchase against the backend, and — on success — have the content **unlock in place** so playback / full detail becomes available without leaving the screen.

The concrete success bar is: **purchasing a tier unlocks the content.** After a successful purchase, the previously-locked VOD detail transitions from a paywalled state to an entitled state (play affordance enabled, tier offer hidden) within the same session, and the entitlement survives navigation away and back, and app relaunch (server is authoritative; local cache reflects it).

This ticket owns: (a) the tier-offer + purchase UI inside the `feature-videos` detail surface (the locked overlay, tier list sheet, confirm/processing/result states); (b) the purchase API (`GET` tiers, `POST` purchase) and its DTO/domain mapping; (c) the `PurchaseViewModel` state machine modeled on the `LoginViewModel` pattern from AND-031; and (d) entitlement reconciliation that flips the catalog/detail UI to "unlocked." It does **not** own the catalog/detail browse rendering itself (AND-191), the media player (AND-168/AND-190), generic feed paywall display (AND-101/AND-177), or a real payment-processor integration (see §13).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`. Code lands primarily in `feature-videos` (purchase UI, `PurchaseViewModel`) with model/data in `core-model` and `core-data`/`core-network`.
- **Namespace:** `com.testlogon.android` everywhere a package appears (e.g. `com.testlogon.android.feature.videos.purchase`).
- **Web reference:** the scope names `vodPurchaseTiers.ts`; the web API layer (`frontend/src/api/endpoints/vodPurchaseTiers.ts`, shared types in `frontend/src/api/types.ts`) is the source of truth for field names and endpoint paths. The web `vod.ts` (AND-191) reference describes the entitlement/lock shape on catalog items. Confirm the exact tier and purchase field set against `/openapi.json` during implementation (see §13).
- **Upstream deps:**
  - **AND-191 (VOD catalog):** owns `vod.ts`-equivalent catalog + detail list/detail rendering and the `Vod`/`VodDetail` domain model that carries a `locked`/`entitlement` indicator. This ticket reads that lock flag to decide whether to show the tier offer, and writes back the unlocked state.
  - **AND-031 (LoginViewModel):** the canonical `StateFlow<UiState>` + submit-handler + result→state-mapping pattern (loading/disabled handling, error mapping). `PurchaseViewModel` mirrors that shape exactly.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable; design for ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale states). OpenAPI at `/openapi.json`. FastAPI error `detail` is `string | [{msg}] | {code,...}` and is normalized by the existing `core-network` error mapper.
- **Auth:** cookie-based session (`/ui/session/*`) with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; one `/ui/session/refresh` retry on 401. Both the tiers GET and the purchase POST ride this authenticated session and **must** carry the CSRF header (the POST is a state-changing call).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24 / target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

1. **Tier offer surfacing.** When a VOD detail (from AND-191) is `locked` for the current user, the screen renders a purchase entry point ("Unlock" / price-from button) instead of an enabled play affordance.
2. **Tier list.** Tapping the entry point opens a tier chooser (Material 3 `ModalBottomSheet`) listing each available tier: title, optional subtitle/description, formatted price (currency + amount), and tier kind (e.g. `RENT` vs `BUY`) with rental window where applicable.
3. **Tier fetch.** Tiers are fetched on demand via `GET /vod/{id}/purchase-tiers` (path to be confirmed, §13). While loading, the sheet shows a skeleton; on error it shows an inline message + Retry.
4. **Selection & confirm.** Selecting a tier moves to a confirm state showing the chosen tier and total. A primary "Confirm purchase" button is enabled only when a tier is selected and no request is in flight.
5. **Purchase submit.** Confirm issues `POST /vod/{id}/purchase` with the selected `tier_id`. The button shows a processing state and is disabled to prevent double-submit. An idempotency key is sent (§5) to make accidental resubmits safe.
6. **Unlock on success.** On a successful purchase the entitlement is applied: the sheet shows a brief success state then dismisses, and the underlying VOD detail flips to **unlocked** (play affordance enabled, tier offer removed). The local cache (Room) and in-memory state both reflect entitlement.
7. **Already-entitled handling.** If the backend reports the user already owns/has access (e.g. `409`/entitlement-exists or the purchase returns an entitled body), the UI treats it as success (idempotent unlock) rather than an error.
8. **Failure handling.** Purchase failures (payment declined, validation, server/transient error) surface a clear, recoverable message. The user can retry or pick a different tier; the content stays locked.
9. **Auth requirement.** Purchasing requires an authenticated session. If the session is invalid and refresh fails, the flow routes to re-authentication (does not silently fail).
10. **No partial unlock.** The UI never enables playback unless a server-confirmed entitlement exists. Optimistic UI is not used for the unlock itself.

## 4. Technical Design

### Package & files (`com.testlogon.android.feature.videos.purchase`)
- `PurchaseTierSheet.kt` — stateless Composable rendering `PurchaseUiState` (tier list / confirm / processing / success / error) as a `ModalBottomSheet`.
- `PurchaseViewModel.kt` — Hilt ViewModel exposing `StateFlow<PurchaseUiState>` (AND-031 pattern).
- `PurchaseUiState.kt` — UI model + `PurchaseEvent` one-shot effects (e.g. `Unlocked`, `RequireReauth`).
- `LockedVodOverlay.kt` — the locked entry point composable consumed by AND-191/AND-190 detail.

### State machine (mirrors AND-031 `LoginViewModel`)
```kotlin
@HiltViewModel
class PurchaseViewModel @Inject constructor(
    private val repository: VodPurchaseRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val vodId: String = checkNotNull(savedStateHandle[ARG_VOD_ID])

    private val _uiState = MutableStateFlow(PurchaseUiState())
    val uiState: StateFlow<PurchaseUiState> = _uiState.asStateFlow()

    private val _events = Channel<PurchaseEvent>(Channel.BUFFERED)
    val events: Flow<PurchaseEvent> = _events.receiveAsFlow()

    fun loadTiers() { /* emit Loading; collect ApiResult<List<PurchaseTier>> -> Tiers | Error */ }
    fun onTierSelected(tierId: String) { _uiState.update { it.copy(selectedTierId = tierId) } }
    fun onConfirm() { /* guard: selectedTierId != null && !isSubmitting; submitPurchase() */ }
    fun retry() = loadTiers()
    fun dismiss() { /* reset transient state */ }

    private fun submitPurchase() = viewModelScope.launch {
        val tierId = _uiState.value.selectedTierId ?: return@launch
        _uiState.update { it.copy(isSubmitting = true, purchaseError = null) }
        when (val r = repository.purchase(vodId, tierId, idempotencyKey())) {
            is ApiResult.Success -> {
                _uiState.update { it.copy(isSubmitting = false, isPurchased = true) }
                _events.send(PurchaseEvent.Unlocked(r.data)) // entitlement
            }
            is ApiResult.AlreadyEntitled ->                  // 409/own -> idempotent success
                _events.send(PurchaseEvent.Unlocked(r.data))
            is ApiResult.Unauthorized ->
                _events.send(PurchaseEvent.RequireReauth)
            is ApiResult.Error ->
                _uiState.update { it.copy(isSubmitting = false, purchaseError = r.message.toUiMessage()) }
        }
    }
}
```
(`ApiResult.AlreadyEntitled`/`Unauthorized` may be modeled as specific `code` values on `ApiResult.Error` rather than new variants, depending on the existing `core-network` `ApiResult` from AND-018; either is acceptable — keep it consistent with that type.)

### Repository (`core-data`)
```kotlin
interface VodPurchaseRepository {
    /** Idempotent GET; eligible for bounded backoff retry. */
    suspend fun getTiers(vodId: String): ApiResult<List<PurchaseTier>>
    /** State-changing POST; NOT auto-retried by the network layer. */
    suspend fun purchase(vodId: String, tierId: String, idempotencyKey: String): ApiResult<Entitlement>
}
```
`VodPurchaseRepositoryImpl` calls `VodPurchaseApi`, maps DTO → `core-model`, and on a successful purchase **updates the cached VOD entity** (`VodEntity.locked = false`, store `entitlement`/`expiresAt`) so AND-191's catalog/detail observers re-emit an unlocked item. The `PurchaseEvent.Unlocked` effect is consumed by the detail screen to refresh its `VodRepository.observeVod(id)` stream (or the repository write triggers re-emission automatically via Room `Flow`).

### Integration with AND-191 detail
The locked overlay is shown when `VodDetailUiState.vod.locked == true`. It hoists `PurchaseViewModel` (keyed by `vodId`). On `PurchaseEvent.Unlocked`, the detail screen relies on the Room-backed `observeVod` flow re-emitting `locked = false` (no manual UI mutation), which removes the overlay and enables the play control owned by AND-190.

## 5. API Contract

> Paths/field names below are provisional and confirmed against `/openapi.json` and `frontend/src/api/endpoints/vodPurchaseTiers.ts` during implementation (§13).

### List tiers (idempotent GET)
`GET /vod/{id}/purchase-tiers` — authenticated (cookies + `X-CSRF-Token`). Eligible for bounded backoff retry (transient/5xx/timeout only).

```kotlin
interface VodPurchaseApi {
    @GET("vod/{id}/purchase-tiers")
    suspend fun getTiers(@Path("id") vodId: String): VodPurchaseTiersDto

    @POST("vod/{id}/purchase")
    suspend fun purchase(
        @Path("id") vodId: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: PurchaseRequestDto,
    ): PurchaseResultDto
}
```

200 response (tiers):
```json
{
  "vod_id": "vod_123",
  "currency": "USD",
  "tiers": [
    { "id": "tier_rent_48", "kind": "RENT", "title": "Rent 48 hours",
      "description": "Watch as often as you like for 48h", "price_cents": 499,
      "rental_window_hours": 48 },
    { "id": "tier_buy", "kind": "BUY", "title": "Buy",
      "description": "Own it forever", "price_cents": 1499, "rental_window_hours": null }
  ]
}
```

### Purchase (state-changing POST — NOT auto-retried)
`POST /vod/{id}/purchase` with `Idempotency-Key` header.
Request:
```json
{ "tier_id": "tier_buy" }
```
200 response (entitlement granted):
```json
{
  "entitlement": {
    "vod_id": "vod_123", "tier_id": "tier_buy", "status": "ACTIVE",
    "granted_at": "2026-06-05T12:00:00Z", "expires_at": null
  }
}
```

### DTO + mapping
```kotlin
@JsonClass(generateAdapter = true)
data class PurchaseTierDto(
    val id: String,
    val kind: String?,                                   // "RENT" | "BUY" | ...
    val title: String,
    val description: String?,
    @Json(name = "price_cents") val priceCents: Long,
    @Json(name = "rental_window_hours") val rentalWindowHours: Int?,
)
@JsonClass(generateAdapter = true)
data class VodPurchaseTiersDto(
    @Json(name = "vod_id") val vodId: String,
    val currency: String,
    val tiers: List<PurchaseTierDto>,
)
@JsonClass(generateAdapter = true)
data class PurchaseRequestDto(@Json(name = "tier_id") val tierId: String)
@JsonClass(generateAdapter = true)
data class EntitlementDto(
    @Json(name = "vod_id") val vodId: String,
    @Json(name = "tier_id") val tierId: String?,
    val status: String,
    @Json(name = "granted_at") val grantedAt: String?,
    @Json(name = "expires_at") val expiresAt: String?,
)
@JsonClass(generateAdapter = true)
data class PurchaseResultDto(val entitlement: EntitlementDto)
```

### Error mapping
FastAPI `detail` normalized by the existing mapper into `ApiResult.Error(message, code)`:
- `401` → single `/ui/session/refresh` + retry (auth interceptor, AND-013); if still failing → `RequireReauth`.
- `402` / `{code:"payment_declined"}` → "Payment was declined. Try another method or tier."
- `409` / `{code:"already_entitled"}` → treat as idempotent **success** → unlock.
- `404` → "This title is no longer available."
- `422` (validation `[{msg}]`) → surface first `msg`.
- `5xx`/timeout on POST → "Couldn't complete your purchase. Please try again." (manual Retry only; not auto-retried).

## 6. Data & State Management

### UI state
```kotlin
data class PurchaseUiState(
    val isLoadingTiers: Boolean = false,
    val currency: String = "USD",
    val tiers: List<PurchaseTier> = emptyList(),
    val selectedTierId: String? = null,
    val isSubmitting: Boolean = false,         // confirm disabled while true
    val isPurchased: Boolean = false,
    val tiersError: UiMessage? = null,         // tier-list level Retry
    val purchaseError: UiMessage? = null,      // confirm-level message
) {
    val canConfirm: Boolean get() = selectedTierId != null && !isSubmitting && !isPurchased
}

sealed interface PurchaseEvent {
    data class Unlocked(val entitlement: Entitlement) : PurchaseEvent
    data object RequireReauth : PurchaseEvent
}
```

### Domain model (`core-model`)
```kotlin
enum class TierKind { RENT, BUY, UNKNOWN }
data class PurchaseTier(
    val id: String, val kind: TierKind, val title: String,
    val description: String?, val priceCents: Long, val currency: String,
    val rentalWindowHours: Int?,
)
enum class EntitlementStatus { ACTIVE, EXPIRED, UNKNOWN }
data class Entitlement(
    val vodId: String, val tierId: String?, val status: EntitlementStatus,
    val grantedAt: Instant?, val expiresAt: Instant?,
)
```

### Cache (`core-data`, Room 2.6)
Reuse/extend AND-191's `VodEntity`: on successful purchase set `locked = false` and persist `entitlementTierId`/`entitlementExpiresAt`. Because catalog/detail observers read the entity via a Room `Flow`, the unlock propagates without manual UI mutation. Tiers themselves are **not** cached (prices are server-authoritative and may change); they are fetched fresh each time the sheet opens. No new DataStore prefs.

### Idempotency
`idempotencyKey()` generates a stable UUID per confirm attempt, reused across automatic UI-level retries of the *same* selection so the server can dedupe; a fresh key is generated when the user changes the selected tier.

## 7. Error Handling & Resilience

- **Tiers GET (idempotent):** ~20s OkHttp timeout; bounded exponential backoff (≈3 attempts, 500ms→2s, jittered) for transient `IOException`/`5xx`/timeout only (AND-016). `4xx` is never retried. Failure → `tiersError` with Retry in the sheet; underlying content stays locked.
- **Purchase POST (non-idempotent):** **no automatic retry** — the network retry interceptor must exclude this call (POST). Failures are surfaced for explicit user retry. The `Idempotency-Key` makes a deliberate retry safe server-side.
- **Double-submit guard:** `isSubmitting` disables Confirm; rapid taps are ignored.
- **Already-entitled / race:** `409`/`already_entitled` is success (unlock), covering the case where the user bought on another device meanwhile.
- **Offline:** sheet open with no connectivity → `tiersError` (offline variant) + Retry; purchases are blocked offline (no optimistic unlock).
- **401 mid-flow:** one `/ui/session/refresh` + retry handled by the auth interceptor; persistent failure → `RequireReauth` event routed to the session flow; the sheet preserves the selected tier where possible.
- **Partial/garbled response:** if the success body lacks a usable entitlement, treat as failure (do not unlock) and prompt retry.

## 8. Security & Privacy

- The purchase POST is **state-changing** and MUST include the `X-CSRF-Token` header (from the `ui_csrf` cookie via the CSRF interceptor, AND-012); both calls use the shared OkHttp client + persistent cookie jar so they are authenticated.
- Entitlement is **server-authoritative**: the client never grants access from local state alone; play is enabled only after a confirmed entitlement (server response or Room reflecting the server write). This prevents trivial paywall bypass via local tampering.
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev host via scoped `network-security-config` (no app-wide cleartext). Production must be HTTPS.
- No payment instrument data is handled by this ticket (the dev backend simulates the charge; real PSP integration is out of scope, §13). No card/PAN data is logged or stored.
- Logs never include cookies, CSRF tokens, or the `Idempotency-Key`. Price/tier ids may be logged; user identity is not attached beyond what telemetry already captures.
- Cached entitlement in Room contains only `vodId`/`tierId`/`expiresAt`/`status` — no sensitive financial data.

## 9. Accessibility & i18n

- All controls (Unlock entry, tier rows, Confirm, Retry, dismiss) have `contentDescription`; tier rows expose a combined semantic label ("Buy, 14.99 US dollars, own forever") and are selectable via TalkBack with a clear selected state (not color-only).
- Touch targets ≥ 48dp; the bottom sheet is reachable and dismissible with TalkBack and supports back-gesture dismiss.
- **Prices are locale- and currency-aware:** format `price_cents` + `currency` via `NumberFormat.getCurrencyInstance(locale)` (or `java.util.Currency`); never hardcode `$` or assume 2 decimal places. Rental windows formatted via locale-aware plurals ("48 hours").
- All user-facing strings live in `strings.xml` (incl. tier-kind labels, error messages, success copy); plurals via `<plurals>`. No hardcoded literals. RTL-ready layout (mirrors with AND-114 plumbing).
- Color is never the sole signal for selection/error; pair with icon/check + text. Verify contrast against the Material 3 theme.

## 10. Telemetry & Logging

Emit via the shared analytics abstraction:
- `vod_tiers_viewed` { vodId, tierCount }
- `vod_tier_selected` { vodId, tierId, kind }
- `vod_purchase_started` { vodId, tierId }
- `vod_purchase_succeeded` { vodId, tierId, priceCents, currency, latencyMs }
- `vod_purchase_failed` { vodId, tierId, httpStatus|null, code|cause }
- `vod_purchase_already_entitled` { vodId } (idempotent-unlock path)
- `vod_content_unlocked` { vodId, tierId } (entitlement applied to UI/cache)

Logging: structured debug logs gated behind `BuildConfig.DEBUG`; redact cookies/CSRF/Idempotency-Key. Never log full request bodies in release.

## 11. Testing Strategy

**Unit (`core-testing`, JUnit + Turbine + MockWebServer, harness from AND-046):**
- `PurchaseViewModel`: `loadTiers()` emits `Loading → Tiers` on success and `tiersError` on failure; `onTierSelected` sets `selectedTierId` and enables `canConfirm`; `onConfirm` is a no-op while `isSubmitting`; success emits `isPurchased = true` + `PurchaseEvent.Unlocked`; `already_entitled`/`409` maps to `Unlocked`; `401`/refresh-failure emits `RequireReauth`; declined/`402` sets `purchaseError` and leaves content locked. Double-`onConfirm` issues exactly one POST.
- `VodPurchaseRepositoryImpl`: tiers DTO→domain mapping incl. null `kind`/`rental_window_hours`; purchase success updates `VodEntity.locked = false` and persists entitlement; idempotency key forwarded as header.
- Moshi adapters: snake_case mapping, missing optionals, unknown fields ignored; `price_cents` parsed as `Long`.
- Network: confirm the purchase POST is excluded from the idempotent-GET backoff interceptor (no auto-retry on 5xx); confirm `X-CSRF-Token` present on both calls.

**Instrumented / Compose UI:**
- Locked detail shows Unlock entry, not play; entitled detail shows play, no entry.
- Opening the sheet shows skeleton → tier list; selecting a tier enables Confirm.
- Tapping Confirm shows processing (Confirm disabled), then success → sheet dismisses and the overlay disappears (content unlocked) on a stubbed success.
- Tiers error renders Retry; tapping invokes `loadTiers`. Purchase error renders message with retry; content stays locked.

**Acceptance gate:** against the dev backend (or stubbed MockWebServer), a purchase request that returns an entitlement results in the VOD rendering as unlocked and playable.

## 12. Dependencies & Sequencing

- **Hard deps:** **AND-191** (VOD catalog + detail, `Vod`/`VodEntity` with `locked` flag, the detail surface that hosts the overlay) and **AND-031** (the `LoginViewModel` `StateFlow<UiState>` + submit/result-mapping pattern this ViewModel follows).
- **Transitive (assumed already merged from M1):** AND-018 (`ApiResult`), AND-015 (FastAPI error mapping), AND-012 (CSRF interceptor), AND-013 (401 refresh authenticator), AND-016 (idempotent-GET backoff), AND-011 (persistent cookie jar), AND-027 (session endpoints), AND-046 (MockWebServer harness). Play enabling is owned by AND-190; this ticket only flips the lock state.
- **Sequencing:** land `VodPurchaseApi` + DTOs + `VodPurchaseRepositoryImpl` (+ `VodEntity` unlock write) first (testable in isolation), then `PurchaseViewModel`, then the `PurchaseTierSheet`/`LockedVodOverlay` UI and integration into the AND-191 detail, then the acceptance gate.
- **Blocks:** none currently recorded (related-content purchase reuse may build on this later).

## 13. Risks & Open Questions

1. **Endpoint shape (OQ):** Are tiers and purchase under `/vod/{id}/purchase-tiers` + `/vod/{id}/purchase`, or a different resource (e.g. `/purchases`, `/entitlements`)? Confirm against `/openapi.json` and `frontend/src/api/endpoints/vodPurchaseTiers.ts`.
2. **Field names/types (OQ):** `price_cents` vs `price`/`amount`+`currency`; `kind` enum values; whether the lock flag on the catalog item is `locked`, `entitled`, or an `entitlement` object. DTOs above are provisional.
3. **Payment processor:** Real PSP / Google Play Billing is **out of scope** — the dev backend simulates the charge. If a redirect/3-D Secure or Play Billing flow is required for prod, that is a separate ticket; design keeps the purchase call abstracted behind the repository so it can be swapped.
4. **Idempotency support (OQ):** Does the backend honor an `Idempotency-Key` header? If not, rely on `409 already_entitled` to make retries safe; confirm behavior.
5. **Entitlement expiry:** RENT tiers carry `expires_at`; the client should re-lock when expired. Refresh/expiry-driven re-lock UX may extend into a follow-up; this ticket persists `expires_at` and treats expired entitlements as locked on read.
6. **Unreliable backend:** ~20s latency on the POST means a long processing state; ensure clear processing UI and that the user cannot double-charge (guarded by `isSubmitting` + idempotency key).
7. **Cache/host scoping:** ensure the purchase write re-emits through the same Room `Flow` AND-191's detail observes (single source of truth) to avoid a stale-locked UI after success.

## 14. Acceptance Criteria

1. **Purchasing a tier unlocks the content** — completing a successful purchase against the backend flips the VOD detail from locked to unlocked (play affordance enabled, tier offer removed) in the same session.
2. A locked VOD shows a purchase entry point and the tier chooser (`GET /vod/{id}/purchase-tiers`) listing each tier with locale-/currency-formatted price and kind; an entitled VOD shows no entry point.
3. Selecting a tier enables Confirm; tapping Confirm issues exactly one `POST /vod/{id}/purchase` with `tier_id`, `Idempotency-Key`, and `X-CSRF-Token`, disabling the button while in flight (no double-submit).
4. On success the entitlement is persisted (Room `locked = false` + entitlement) so the unlock survives navigation away/back and app relaunch (server authoritative).
5. `409`/`already_entitled` is treated as an idempotent success (unlock); `402`/declined and other errors surface a clear message and leave content locked with the ability to retry or choose another tier.
6. Tiers-fetch failure shows an inline Retry; the purchase POST is never auto-retried by the network layer.
7. A 401 during the flow triggers exactly one `/ui/session/refresh` + retry; persistent failure routes to re-authentication rather than silently failing.
8. No hardcoded user-facing strings or currency symbols; tier rows and controls are labeled for TalkBack; no cookies/CSRF/Idempotency-Key appear in logs.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.videos.purchase` (+ `core-model`/`core-data` changes), passing CI (lint, detekt, unit + Compose tests).
- All §14 acceptance criteria verified, including the unlock acceptance gate against the dev backend or a stubbed manifest/response.
- `PurchaseViewModel`, `VodPurchaseRepositoryImpl`, and DTO mapping covered by unit tests (success, already-entitled, declined, 401/reauth, double-submit, idempotency-key forwarding); key UI states covered by Compose tests.
- Endpoint/field Open Questions (§13.1–13.2, 13.4) resolved against `/openapi.json` and `vodPurchaseTiers.ts`, with DTOs updated or explicitly tracked with a stub fallback.
- Purchase POST confirmed excluded from automatic GET-retry backoff; CSRF header confirmed present on both calls.
- Scoped cleartext config confirmed for the dev host only; no app-wide cleartext.
- Telemetry events (§10) emitted and verified in debug; no cookies/CSRF/Idempotency-Key/financial data logged.
- Strings + currency formatting externalized and locale-aware; basic TalkBack pass on the tier sheet and Confirm completed.
- No regression to AND-191 catalog/detail rendering or AND-190 playback when content transitions locked → unlocked.
