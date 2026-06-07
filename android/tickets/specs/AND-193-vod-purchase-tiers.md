---
id: AND-193
title: VOD purchase tiers
milestone: M4
epic: E26
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-191, AND-031]
blocks: []
---

# AND-193 — VOD purchase tiers

## 1. Overview & Goal

Deliver **tiered purchase** for VOD (video-on-demand) content in the TestLogon native Android app. A VOD item exposed by the catalog (AND-191) may be locked behind one or more purchase **tiers** (e.g. *Rent 48h*, *Buy*, *Premium bundle*). This ticket lets a signed-in user view the available tiers for a locked VOD, select one, complete the purchase against the backend, and — on success — have the content **unlock in place** so playback / full detail becomes available without leaving the screen.

The concrete success bar is: **purchasing a tier unlocks the content.** After a successful purchase, the previously-locked VOD detail transitions from a paywalled state to an entitled state (play affordance enabled, tier offer hidden) within the same session, and the entitlement survives navigation away and back, and app relaunch (server is authoritative; local cache reflects it).

This ticket owns: (a) the tier-offer + purchase UI inside the `feature-videos` detail surface (the locked overlay, tier list sheet, confirm/processing/result states); (b) the purchase API (`GET` access/offer, `POST` purchase) and its DTO/domain mapping; (c) the `PurchaseViewModel` state machine modeled on the `LoginViewModel` pattern from AND-031; and (d) entitlement reconciliation that flips the catalog/detail UI to "unlocked." It does **not** own the catalog/detail browse rendering itself (AND-191), the media player (AND-168/AND-190), generic feed paywall display (AND-101/AND-177), or a real payment-processor integration (see §13).

> **CORRECTED MODEL (verified against `openapi.index.txt` + `src/api/endpoints/vodPurchaseTiers.ts`).** The backend does **not** expose a list of discrete tier objects each with its own `id`/`tier_id`. A VOD has a single offer described by `GET /ui/videos/{video_id}/access` (`VodAccessOut`: `entitled`, `purchase_available`, `price_cents`, `purchase_type`, `subscription_available`, `subscription_upsell`, `views_remaining`, `reason`), and the "tiers" the user chooses among are the **purchase-type variants** `view_once | rental | permanent | download` (a fixed enum from `VodPurchaseIn.purchase_type`, pattern `^(view_once|rental|permanent|download)$`). Purchase is `POST /ui/videos/{video_id}/purchase` with body `{ purchase_type, payment_method_id?, idempotency_key? }`. Throughout this spec, read "tier" as "purchase-type option" and `tier_id` as `purchase_type`. See §5 for the verified contract and §16 for the full audit.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`. Code lands primarily in `feature-videos` (purchase UI, `PurchaseViewModel`) with model/data in `core-model` and `core-data`/`core-network`.
- **Namespace:** `com.testlogon.android` everywhere a package appears (e.g. `com.testlogon.android.feature.videos.purchase`).
- **Web reference:** the scope names `vodPurchaseTiers.ts`; the web API layer (`frontend/src/api/endpoints/vodPurchaseTiers.ts`, shared types in `frontend/src/api/types.ts`) is the source of truth for field names and endpoint paths. The web `vod.ts` (AND-191) reference describes the entitlement/lock shape on catalog items. Confirm the exact tier and purchase field set against `/openapi.json` during implementation (see §13).
- **Upstream deps:**
  - **AND-191 (VOD catalog):** owns `vod.ts`-equivalent catalog + detail list/detail rendering and the `Vod`/`VodDetail` domain model that carries a `locked`/`entitlement` indicator. This ticket reads that lock flag to decide whether to show the tier offer, and writes back the unlocked state.
  - **AND-031 (LoginViewModel):** the canonical `StateFlow<UiState>` + submit-handler + result→state-mapping pattern (loading/disabled handling, error mapping). `PurchaseViewModel` mirrors that shape exactly.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable; design for ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale states). OpenAPI at `/openapi.json`. FastAPI error `detail` is `string | [{msg}] | {code,...}` and is normalized by the existing `core-network` error mapper.
- **Auth:** cookie-based session (`/ui/session/*`) with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; one `/ui/session/refresh` retry on 401. **Verified** against `src/api/client.ts`: the web client sets `X-CSRF-Token` (from the `ui_csrf` cookie) on **every** request — GET and POST alike, not only mutating calls — and sends `credentials: "include"` plus a `Bearer` `Authorization` header when an access token is present; on 401 (only when already authenticated) it performs exactly one `/ui/session/refresh` then retries once. NOTE: the OpenAPI param list for these `/ui/videos/...` operations advertises `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN` and does **not** itemize `X-CSRF-Token`; the web nonetheless attaches CSRF universally, so the Android client should send `X-CSRF-Token` on both the access GET and the purchase POST (matching the web contract).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24 / target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

1. **Tier offer surfacing.** When a VOD detail (from AND-191) is `locked` for the current user, the screen renders a purchase entry point ("Unlock" / price-from button) instead of an enabled play affordance.
2. **Tier list.** Tapping the entry point opens a tier chooser (Material 3 `ModalBottomSheet`) listing each available tier: title, optional subtitle/description, formatted price (currency + amount), and tier kind (e.g. `RENT` vs `BUY`) with rental window where applicable.
3. **Tier fetch.** The offer is fetched on demand via `GET /ui/videos/{video_id}/access` (**corrected**; the previously-claimed `GET /vod/{id}/purchase-tiers` does not exist — see §16). The response (`VodAccessOut`) yields `entitled`, `purchase_available`, `price_cents`, the default `purchase_type`, and the `view_once|rental|permanent|download` options the UI offers. While loading, the sheet shows a skeleton; on error it shows an inline message + Retry.
4. **Selection & confirm.** Selecting a tier moves to a confirm state showing the chosen tier and total. A primary "Confirm purchase" button is enabled only when a tier is selected and no request is in flight.
5. **Purchase submit.** Confirm issues `POST /ui/videos/{video_id}/purchase` (**corrected** path) with the selected `purchase_type` (**corrected**; not `tier_id`). The button shows a processing state and is disabled to prevent double-submit. An idempotency key is sent (§5) as the **body field** `idempotency_key` (**corrected** — `VodPurchaseIn` carries it in the body, not an `Idempotency-Key` header) to make accidental resubmits safe.
6. **Unlock on success.** On a successful purchase the entitlement is applied: the sheet shows a brief success state then dismisses, and the underlying VOD detail flips to **unlocked** (play affordance enabled, tier offer removed). The local cache (Room) and in-memory state both reflect entitlement.
7. **Already-entitled handling.** If the backend reports the user already owns access, the UI treats it as success (idempotent unlock) rather than an error. **Corrected mechanism:** this is signalled by `already_owned: true` in the **200** `VodPurchaseOut` body — there is **no** `409`/`already_entitled` status declared for this endpoint (responses are `200` and `422` only). The client must inspect the success body's `already_owned` flag rather than a 409 code.
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
            // NOTE: "already owned" is NOT a 409 — it is `already_owned == true` in the 200
            // body. The repository maps that 200 to ApiResult.Success with an Entitlement whose
            // alreadyOwned flag is set; both Success branches drive Unlocked. (No AlreadyEntitled
            // variant is required; kept here only if AND-018's ApiResult already models it.)
            is ApiResult.Unauthorized ->
                _events.send(PurchaseEvent.RequireReauth)
            is ApiResult.Error ->
                _uiState.update { it.copy(isSubmitting = false, purchaseError = r.message.toUiMessage()) }
        }
    }
}
```
(`ApiResult.Unauthorized` may be modeled as a specific `code` value on `ApiResult.Error` rather than a new variant, depending on the existing `core-network` `ApiResult` from AND-018; either is acceptable — keep it consistent with that type. There is **no** "already entitled" error variant: that case is a normal 200 with `already_owned == true`, handled on the Success branch.)

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

> **VERIFIED 2026-06-06** against `reference/openapi.index.txt`, `reference/openapi.pretty.json` (`VodAccessOut`, `VodPurchaseIn`, `VodPurchaseOut`), and `reference/src/api/endpoints/vodPurchaseTiers.ts`. The original draft's paths/fields were materially wrong; the verified contract follows. See §16 for the audit.

### Get offer / access state (idempotent GET)
`GET /ui/videos/{video_id}/access` — authenticated (cookies + `X-CSRF-Token` + Bearer). Eligible for bounded backoff retry (transient/5xx/timeout only). op=`check_video_access_ui_videos__video_id__access_get`, resp `200:VodAccessOut; 422:HTTPValidationError`.

```kotlin
interface VodPurchaseApi {
    @GET("ui/videos/{video_id}/access")
    suspend fun getAccess(@Path("video_id") videoId: String): VodAccessDto

    @POST("ui/videos/{video_id}/purchase")
    suspend fun purchase(
        @Path("video_id") videoId: String,
        @Body body: VodPurchaseDto,           // idempotency_key travels in the BODY
    ): VodPurchaseResultDto
}
```

200 response (`VodAccessOut`; required: `entitled`, `reason`):
```json
{
  "entitled": false,
  "purchase_available": true,
  "price_cents": 1499,
  "purchase_type": "permanent",
  "subscription_available": false,
  "subscription_upsell": false,
  "views_remaining": -1,
  "expires_at": null,
  "download_allowed": false,
  "access_mode": null,
  "ads_enabled": false,
  "reason": "not_purchased"
}
```
There is **no** server-returned per-tier list and **no** `currency` field on this response. The selectable "tiers" are the fixed `purchase_type` enum values (`view_once | rental | permanent | download`); price is the single `price_cents`. Currency is **not** returned by the backend (assume USD / minor-unit cents — flagged in §16 Open assumptions).

### Purchase (state-changing POST — NOT auto-retried)
`POST /ui/videos/{video_id}/purchase`. op=`purchase_video_endpoint_ui_videos__video_id__purchase_post`, resp `200:VodPurchaseOut; 422:HTTPValidationError`.
Request (`VodPurchaseIn` — all fields optional; `purchase_type` defaults to `"permanent"`, pattern `^(view_once|rental|permanent|download)$`):
```json
{ "purchase_type": "permanent", "idempotency_key": "uuid-...", "payment_method_id": null }
```
200 response (`VodPurchaseOut`; required: `video_id`, `already_owned`, `granted_at`, `grant_type`, `amount_cents`):
```json
{
  "video_id": "vid_123",
  "already_owned": false,
  "granted_at": 1749120000,
  "grant_type": "purchase",
  "amount_cents": 1499,
  "purchase_id": "...",
  "purchase_type": "permanent",
  "views_remaining": -1,
  "expires_at": null,
  "download_allowed": false
}
```
Note the timestamps `granted_at`/`expires_at` are **Unix epoch integers (seconds)**, not ISO-8601 strings, and the entitlement fields are **flat on the body** — there is no nested `entitlement` object and no `status` enum. `already_owned: true` is the idempotent-success signal (see §3.7).

### DTO + mapping
```kotlin
@JsonClass(generateAdapter = true)
data class VodAccessDto(
    val entitled: Boolean,
    @Json(name = "purchase_available") val purchaseAvailable: Boolean = false,
    @Json(name = "price_cents") val priceCents: Long? = null,
    @Json(name = "purchase_type") val purchaseType: String = "permanent",
    @Json(name = "subscription_available") val subscriptionAvailable: Boolean = false,
    @Json(name = "subscription_upsell") val subscriptionUpsell: Boolean = false,
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "expires_at") val expiresAt: Long? = null,        // epoch seconds
    @Json(name = "download_allowed") val downloadAllowed: Boolean = false,
    @Json(name = "access_mode") val accessMode: String? = null,
    @Json(name = "ads_enabled") val adsEnabled: Boolean = false,
    val reason: String,
)
@JsonClass(generateAdapter = true)
data class VodPurchaseDto(
    @Json(name = "purchase_type") val purchaseType: String,        // enum value
    @Json(name = "idempotency_key") val idempotencyKey: String?,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)
@JsonClass(generateAdapter = true)
data class VodPurchaseResultDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "already_owned") val alreadyOwned: Boolean,
    @Json(name = "granted_at") val grantedAt: Long,               // epoch seconds
    @Json(name = "grant_type") val grantType: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "purchase_id") val purchaseId: String = "",
    @Json(name = "purchase_type") val purchaseType: String = "permanent",
    @Json(name = "views_remaining") val viewsRemaining: Int = -1,
    @Json(name = "expires_at") val expiresAt: Long? = null,       // epoch seconds
    @Json(name = "download_allowed") val downloadAllowed: Boolean = false,
)
```

### Error mapping
FastAPI `detail` normalized by the existing mapper into `ApiResult.Error(message, code)`. The backend declares **only `200` and `422`** for both video endpoints, so the codes below other than 401/422 are **defensive** mappings (the transport may still surface 401/404/5xx from the gateway/auth layer even though the OpenAPI op does not enumerate them):
- `401` → single `/ui/session/refresh` + retry (auth interceptor, AND-013); if still failing → `RequireReauth`. (Matches `client.ts` refresh-once behavior.)
- `200` with `already_owned: true` → treat as idempotent **success** → unlock (NOT a 409; see §3.7).
- `422` (validation `[{msg}]`) → surface first `msg` (e.g. invalid `purchase_type`).
- `404` (defensive — not declared) → "This title is no longer available."
- `402`/payment-declined → **UNVERIFIED**: no `402` and no `payment_declined` code is declared for this endpoint. Keep a generic decline string but do not key UI on a specific code until confirmed (§16 Open assumptions).
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
> **Corrected to the real contract.** `PurchaseTier` is a *purchase-type option* the client constructs from the enum + `VodAccessOut.price_cents` (the server returns no tier list, no per-tier `id`/`title`/`description`/`rental_window_hours`, and no `currency`). `Entitlement` mirrors the **flat** `VodPurchaseOut` (epoch-seconds timestamps, no nested object, `already_owned` flag, no server `status` enum — derive `EXPIRED` locally from `expiresAt`).
```kotlin
enum class PurchaseTypeOption { VIEW_ONCE, RENTAL, PERMANENT, DOWNLOAD, UNKNOWN }
data class PurchaseTier(                       // a purchase-type *option*, not a server object
    val type: PurchaseTypeOption,             // maps to purchase_type enum value
    val priceCents: Long?,                    // single price from VodAccessOut.price_cents
    val titleRes: Int,                        // localized label from strings.xml (client-side)
    val descriptionRes: Int?,                 // localized blurb (client-side)
)
enum class EntitlementStatus { ACTIVE, EXPIRED, UNKNOWN }   // derived client-side
data class Entitlement(
    val videoId: String,
    val purchaseType: PurchaseTypeOption,
    val alreadyOwned: Boolean,
    val grantType: String,
    val amountCents: Long,
    val purchaseId: String,
    val viewsRemaining: Int,                  // -1 = unlimited
    val grantedAt: Instant?,                  // parsed from epoch-seconds Long
    val expiresAt: Instant?,                  // parsed from epoch-seconds Long; null = no expiry
    val downloadAllowed: Boolean,
) {
    val status: EntitlementStatus
        get() = when {
            expiresAt != null && expiresAt < Instant.now() -> EntitlementStatus.EXPIRED
            else -> EntitlementStatus.ACTIVE
        }
}
```

### Cache (`core-data`, Room 2.6)
Reuse/extend AND-191's `VodEntity`: on successful purchase set `locked = false` and persist `entitlementTierId`/`entitlementExpiresAt`. Because catalog/detail observers read the entity via a Room `Flow`, the unlock propagates without manual UI mutation. Tiers themselves are **not** cached (prices are server-authoritative and may change); they are fetched fresh each time the sheet opens. No new DataStore prefs.

### Idempotency
`idempotencyKey()` generates a stable UUID per confirm attempt, reused across deliberate user retries of the *same* selection so the server can dedupe; a fresh key is generated when the user changes the selected purchase-type. **Corrected transport:** the key is sent as the request **body field** `idempotency_key` (`VodPurchaseIn`), **not** as an `Idempotency-Key`/`X-Idempotency-Key` header. (Other backend endpoints — cart purchase, purchase-history transactions — do use an `X-Idempotency-Key` header, but the video purchase endpoint does not; do not copy that pattern here.)

## 7. Error Handling & Resilience

- **Tiers GET (idempotent):** ~20s OkHttp timeout; bounded exponential backoff (≈3 attempts, 500ms→2s, jittered) for transient `IOException`/`5xx`/timeout only (AND-016). `4xx` is never retried. Failure → `tiersError` with Retry in the sheet; underlying content stays locked.
- **Purchase POST (non-idempotent):** **no automatic retry** — the network retry interceptor must exclude this call (POST). Failures are surfaced for explicit user retry. The `idempotency_key` body field makes a deliberate retry safe server-side.
- **Double-submit guard:** `isSubmitting` disables Confirm; rapid taps are ignored.
- **Already-entitled / race:** `already_owned: true` in the 200 body is success (unlock), covering the case where the user bought on another device meanwhile. (Corrected — not a `409`.)
- **Offline:** sheet open with no connectivity → `tiersError` (offline variant) + Retry; purchases are blocked offline (no optimistic unlock).
- **401 mid-flow:** one `/ui/session/refresh` + retry handled by the auth interceptor; persistent failure → `RequireReauth` event routed to the session flow; the sheet preserves the selected tier where possible.
- **Partial/garbled response:** if the success body lacks a usable entitlement, treat as failure (do not unlock) and prompt retry.

## 8. Security & Privacy

- The purchase POST is **state-changing** and MUST include the `X-CSRF-Token` header (from the `ui_csrf` cookie via the CSRF interceptor, AND-012); both calls use the shared OkHttp client + persistent cookie jar so they are authenticated. (Verified: `client.ts` attaches `X-CSRF-Token` on every request including GETs, so the access GET carries it too.)
- Entitlement is **server-authoritative**: the client never grants access from local state alone; play is enabled only after a confirmed entitlement (server response or Room reflecting the server write). This prevents trivial paywall bypass via local tampering.
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev host via scoped `network-security-config` (no app-wide cleartext). Production must be HTTPS.
- No payment instrument data is handled by this ticket (the dev backend simulates the charge; real PSP integration is out of scope, §13). No card/PAN data is logged or stored.
- Logs never include cookies, CSRF tokens, the Bearer access token, or the `idempotency_key`. Price/purchase-type values may be logged; user identity is not attached beyond what telemetry already captures.
- Cached entitlement in Room contains only `videoId`/`purchaseType`/`expiresAt`/derived-status — no sensitive financial data (`payment_method_id` is never persisted or logged).

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
- `PurchaseViewModel`: `loadTiers()` (access GET) emits `Loading → Tiers` on success and `tiersError` on failure; `onTierSelected` sets the selected `purchase_type` and enables `canConfirm`; `onConfirm` is a no-op while `isSubmitting`; success emits `isPurchased = true` + `PurchaseEvent.Unlocked`; a 200 with `already_owned == true` maps to `Unlocked`; `401`/refresh-failure emits `RequireReauth`; a generic decline/error sets `purchaseError` and leaves content locked. Double-`onConfirm` issues exactly one POST.
- `VodPurchaseRepositoryImpl`: `VodAccessOut` DTO→domain mapping incl. null `price_cents` and default `purchase_type`; purchase success updates `VodEntity.locked = false` and persists the flat entitlement (epoch-seconds → `Instant`); `idempotency_key` forwarded in the request **body**.
- Moshi adapters: snake_case mapping, missing optionals (all `VodPurchaseIn` fields optional), unknown fields ignored; `price_cents`/`amount_cents` parsed as `Long`; `granted_at`/`expires_at` parsed as epoch-seconds `Long` (not ISO strings).
- Network: confirm the purchase POST is excluded from the idempotent-GET backoff interceptor (no auto-retry on 5xx); confirm `X-CSRF-Token` present on both calls (access GET + purchase POST).

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

1. **Endpoint shape (RESOLVED):** Confirmed against `openapi.index.txt` + `vodPurchaseTiers.ts`: offer/access is `GET /ui/videos/{video_id}/access` (`VodAccessOut`) and purchase is `POST /ui/videos/{video_id}/purchase` (`VodPurchaseIn`→`VodPurchaseOut`). The draft's `/vod/{id}/purchase-tiers` + `/vod/{id}/purchase` were wrong and have been corrected throughout. (Adjacent endpoints exist for the rental sub-flow — `/ui/vod/rental/{video_id}/start|status|access` — used when `purchase_type=rental`; reuse is optional, out of base scope.)
2. **Field names/types (RESOLVED):** Confirmed `price_cents` (single `Long`, may be null) on `VodAccessOut`; there is **no** server-returned `currency`, **no** per-tier `kind`/`title`/`description`/`rental_window_hours`. The "tier kind" is the `purchase_type` enum `view_once|rental|permanent|download`. The lock flag is `VodAccessOut.entitled` (boolean) + `purchase_available`/`reason` — not `locked` and not a nested `entitlement` object. Timestamps are epoch-seconds integers. DTOs in §5 are now verified, not provisional.
3. **Payment processor:** Real PSP / Google Play Billing is **out of scope** — the dev backend simulates the charge. If a redirect/3-D Secure or Play Billing flow is required for prod, that is a separate ticket; design keeps the purchase call abstracted behind the repository so it can be swapped.
4. **Idempotency support (PARTIALLY RESOLVED):** `VodPurchaseIn` accepts an `idempotency_key` **body field** (the web sets it). Whether the backend actually dedupes on it is not provable from the schema; in any case `already_owned: true` in the 200 body makes a deliberate retry safe. (The endpoint does **not** accept an `Idempotency-Key`/`X-Idempotency-Key` header — that pattern is used only by cart/transaction endpoints.)
5. **Entitlement expiry:** `rental`/`view_once` purchases carry a non-null `expires_at` (epoch seconds) and/or a finite `views_remaining`; the client should re-lock when expired/consumed (`views_remaining == 0`). Refresh/expiry-driven re-lock UX may extend into a follow-up; this ticket persists `expires_at`/`views_remaining` and treats expired/consumed entitlements as locked on read.
6. **Unreliable backend:** ~20s latency on the POST means a long processing state; ensure clear processing UI and that the user cannot double-charge (guarded by `isSubmitting` + idempotency key).
7. **Cache/host scoping:** ensure the purchase write re-emits through the same Room `Flow` AND-191's detail observes (single source of truth) to avoid a stale-locked UI after success.

## 14. Acceptance Criteria

1. **Purchasing a tier unlocks the content** — completing a successful purchase against the backend flips the VOD detail from locked to unlocked (play affordance enabled, tier offer removed) in the same session.
2. A locked VOD (`VodAccessOut.entitled == false`, `purchase_available == true`) shows a purchase entry point and the purchase-type chooser sourced from `GET /ui/videos/{video_id}/access`, listing each `purchase_type` option with locale-/currency-formatted `price_cents`; an entitled VOD (`entitled == true`) shows no entry point.
3. Selecting an option enables Confirm; tapping Confirm issues exactly one `POST /ui/videos/{video_id}/purchase` with body `{ purchase_type, idempotency_key }` and the `X-CSRF-Token` header, disabling the button while in flight (no double-submit).
4. On success the entitlement is persisted (Room `locked = false` + entitlement fields from the flat `VodPurchaseOut`) so the unlock survives navigation away/back and app relaunch (server authoritative).
5. A 200 response with `already_owned == true` is treated as an idempotent success (unlock); validation/declined and other errors surface a clear message and leave content locked with the ability to retry or choose another option.
6. Tiers-fetch failure shows an inline Retry; the purchase POST is never auto-retried by the network layer.
7. A 401 during the flow triggers exactly one `/ui/session/refresh` + retry; persistent failure routes to re-authentication rather than silently failing.
8. No hardcoded user-facing strings or currency symbols; purchase-type rows and controls are labeled for TalkBack; no cookies/CSRF/Bearer token/`idempotency_key` appear in logs.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.videos.purchase` (+ `core-model`/`core-data` changes), passing CI (lint, detekt, unit + Compose tests).
- All §14 acceptance criteria verified, including the unlock acceptance gate against the dev backend or a stubbed manifest/response.
- `PurchaseViewModel`, `VodPurchaseRepositoryImpl`, and DTO mapping covered by unit tests (success, already-entitled, declined, 401/reauth, double-submit, idempotency-key forwarding); key UI states covered by Compose tests.
- Endpoint/field Open Questions (§13.1–13.2, 13.4) resolved against `/openapi.json` and `vodPurchaseTiers.ts`, with DTOs updated or explicitly tracked with a stub fallback.
- Purchase POST confirmed excluded from automatic GET-retry backoff; CSRF header confirmed present on both calls.
- Scoped cleartext config confirmed for the dev host only; no app-wide cleartext.
- Telemetry events (§10) emitted and verified in debug; no cookies/CSRF/Bearer token/`idempotency_key`/financial data logged.
- Strings + currency formatting externalized and locale-aware; basic TalkBack pass on the tier sheet and Confirm completed.
- No regression to AND-191 catalog/detail rendering or AND-190 playback when content transitions locked → unlocked.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec (`reference/openapi.pretty.json`, `components.schemas.<Name>`), and frontend (`reference/src/...`).

1. **Offer/tiers fetched via `GET /vod/{id}/purchase-tiers`.** VERDICT: **Corrected** → real endpoint is `GET /ui/videos/{video_id}/access`. SOURCE: OpenAPI `GET /ui/videos/{video_id}/access` (op `check_video_access_ui_videos__video_id__access_get`, `resp 200:VodAccessOut`); no `purchase-tiers` path exists anywhere in `openapi.index.txt`.
2. **Purchase via `POST /vod/{id}/purchase`.** VERDICT: **Corrected** → real endpoint is `POST /ui/videos/{video_id}/purchase`. SOURCE: OpenAPI `POST /ui/videos/{video_id}/purchase` (op `purchase_video_endpoint_ui_videos__video_id__purchase_post`, `req=VodPurchaseIn`, `resp 200:VodPurchaseOut`); `src/api/endpoints/vodPurchaseTiers.ts: purchaseVideo` posts to `/ui/videos/${videoId}/purchase`.
3. **Tiers are discrete server objects each with `id`/`tier_id`, `title`, `description`, `kind`, `rental_window_hours`.** VERDICT: **Corrected** → no such list exists; the choices are the fixed `purchase_type` enum `view_once|rental|permanent|download`. SOURCE: `components.schemas.VodPurchaseIn.purchase_type` (pattern `^(view_once|rental|permanent|download)$`); `src/api/endpoints/vodPurchaseTiers.ts: PurchaseType`.
4. **Request field is `tier_id`.** VERDICT: **Corrected** → request field is `purchase_type`. SOURCE: `components.schemas.VodPurchaseIn`; `src/api/endpoints/vodPurchaseTiers.ts: VodPurchaseRequest.purchase_type`.
5. **Idempotency key sent as `Idempotency-Key` HTTP header.** VERDICT: **Corrected** → sent as the request **body field** `idempotency_key`. SOURCE: `components.schemas.VodPurchaseIn.idempotency_key`; `src/api/endpoints/vodPurchaseTiers.ts: VodPurchaseRequest.idempotency_key`. (Header `X-Idempotency-Key` exists only on `POST /ui/purchase-history/transactions` and `POST /ui/shoppingcart/carts/{cart_id}/purchase` per `openapi.index.txt`, not on the video endpoint.)
6. **Tiers response has `vod_id`, `currency`, `tiers[]`.** VERDICT: **Corrected** → `VodAccessOut` has `entitled`, `purchase_available`, `price_cents`, `purchase_type`, `subscription_available`, `subscription_upsell`, `views_remaining`, `expires_at`, `download_allowed`, `access_mode`, `ads_enabled`, `reason` (required: `entitled`, `reason`). No `vod_id` and no `currency`. SOURCE: `components.schemas.VodAccessOut`.
7. **Purchase 200 wraps a nested `entitlement` object with ISO-8601 `granted_at`/`expires_at` and a `status` enum.** VERDICT: **Corrected** → `VodPurchaseOut` is **flat** with `video_id`, `already_owned`, `granted_at` (int epoch), `grant_type`, `amount_cents`, `purchase_id`, `purchase_type`, `views_remaining`, `expires_at` (int epoch|null), `download_allowed` (required: `video_id, already_owned, granted_at, grant_type, amount_cents`). No nested object, no `status`. SOURCE: `components.schemas.VodPurchaseOut`.
8. **Already-owned signalled by `409`/`already_entitled`.** VERDICT: **Corrected** → signalled by `already_owned: true` in the **200** body; the endpoint declares only `200`/`422`. SOURCE: `components.schemas.VodPurchaseOut.already_owned`; OpenAPI index line for the purchase op shows `resp=200:VodPurchaseOut;422:HTTPValidationError`; `src/api/endpoints/vodPurchaseTiers.ts: VodPurchaseResponse.already_owned`.
9. **`402` / `payment_declined` error code.** VERDICT: **Unverified-assumption** → no `402` response and no `payment_declined` code is declared for this endpoint (only `200`/`422`). SOURCE: OpenAPI purchase op response set (`200;422`). Kept as a defensive generic-decline string only.
10. **Lock flag on the catalog/detail item is `locked`/`entitlement`.** VERDICT: **Corrected** (for the access surface) → entitlement state is `VodAccessOut.entitled` (bool) + `purchase_available` + `reason`. SOURCE: `components.schemas.VodAccessOut`. (The Room `VodEntity.locked` field is an AND-191-owned local cache flag derived from `!entitled`; that mapping is this ticket's responsibility.)
11. **`price_cents` is an integer (cents).** VERDICT: **Verified** (and is nullable on access). SOURCE: `components.schemas.VodAccessOut.price_cents` (`anyOf integer|null`); `VodPurchaseOut.amount_cents` (integer, required).
12. **Currency is returned and must be formatted locale-aware.** VERDICT: **Unverified-assumption** (currency code) — no `currency` field is returned by either schema. Locale-aware formatting of the cents value is still correct practice; the ISO currency code is assumed USD. SOURCE: absence in `components.schemas.VodAccessOut`/`VodPurchaseOut`.
13. **Auth: cookie session + `ui_csrf` echoed as `X-CSRF-Token`, single `/ui/session/refresh` retry on 401.** VERDICT: **Verified** (with refinements). SOURCE: `src/api/client.ts` — `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`; `refreshSession()` POSTs `/ui/session/refresh`; 401 path refreshes once then retries once. Refinements: CSRF is attached to **all** methods (not only mutating); a `Bearer` `Authorization` token is also attached when present. Per `openapi.index.txt`, the video ops advertise params `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`.
14. **`expires_at` / `granted_at` are timestamps the client parses.** VERDICT: **Verified** as **epoch-seconds integers** (not ISO strings). SOURCE: `components.schemas.VodPurchaseOut` (`granted_at`/`expires_at` typed integer); `src/api/endpoints/vodPurchaseTiers.ts` comments ("Unix timestamp").
15. **`views_remaining` semantics (`-1` unlimited / `0` consumed).** VERDICT: **Verified.** SOURCE: `src/api/endpoints/vodPurchaseTiers.ts: EntitlementStatus.views_remaining` comment; `components.schemas.VodAccessOut.views_remaining` default `-1`.
16. **A rental sub-flow exists (`start`/`status`/`access`).** VERDICT: **Verified** (informational; reuse optional). SOURCE: OpenAPI `POST /ui/vod/rental/{video_id}/start` (`VodRentalStartIn`→`VodRentalStartOut`), `GET /ui/vod/rental/{video_id}/status` (`VodRentalStatusOut`), `GET /ui/vod/rental/{video_id}/access` (`VodRentalAccessOut`).
17. **Owned-content listing endpoint exists.** VERDICT: **Verified** (informational, for relaunch reconciliation). SOURCE: OpenAPI `GET /ui/videos/purchases/list` (`resp 200:VodPurchaseListOut`, items `VodPurchaseListItem`).
18. **FastAPI `422` validation shape `[{msg}]`.** VERDICT: **Verified.** SOURCE: every video op lists `422:HTTPValidationError`; `components.schemas.HTTPValidationError` (standard FastAPI `detail: [ValidationError]`).
19. **Framework: Compose `ModalBottomSheet`, Hilt `@HiltViewModel`, `StateFlow`/`Channel` one-shot events, Moshi `@JsonClass`, Room `Flow`.** VERDICT: **Verified (framework ref)** — standard, current Android APIs. SOURCE (framework ref): Material 3 `ModalBottomSheet` https://developer.android.com/reference/kotlin/androidx/compose/material3/package-summary ; Hilt + ViewModel https://developer.android.com/training/dependency-injection/hilt-jetpack ; `NumberFormat.getCurrencyInstance` https://developer.android.com/reference/java/text/NumberFormat .

### Corrections made

- **Endpoint paths** (§1, §2, §3.3, §3.5, §5, §13.1, §14): `GET /vod/{id}/purchase-tiers` → `GET /ui/videos/{video_id}/access`; `POST /vod/{id}/purchase` → `POST /ui/videos/{video_id}/purchase`.
- **Tier model** (§1, §3, §5, §6, §13.2): discrete tier list with `tier_id` → fixed `purchase_type` enum (`view_once|rental|permanent|download`) + single `price_cents`.
- **Request field** (§3.5, §5, §14): `tier_id` → `purchase_type`.
- **Idempotency transport** (§3.5, §5, §6, §7, §8, §13.4, §15): `Idempotency-Key` header → `idempotency_key` body field.
- **Already-owned** (§3.7, §5, §7, §11, §14, §4 comments): `409`/`already_entitled` → `already_owned == true` in the 200 body.
- **Response shape** (§5, §6): nested `entitlement` + ISO timestamps + `status` enum → flat `VodPurchaseOut` with epoch-seconds integers and no `status`; access response field set corrected (`entitled`/`purchase_available`/`reason`, no `vod_id`, no `currency`).
- **CSRF scope / auth** (§2, §8): clarified CSRF is sent on all requests, plus a Bearer token; noted the op param list.
- **Error mapping** (§5): `402 payment_declined` demoted to unverified defensive string; mapping table annotated that only `200`/`422` are declared.

### Open assumptions

- **Currency code (USD).** No `currency` field is returned by `VodAccessOut`/`VodPurchaseOut`; amounts are in minor units (cents). We assume USD for `NumberFormat` formatting. Why unverifiable: field absent from both schemas and from `vodPurchaseTiers.ts`. Action: confirm with backend or surface a configurable default.
- **`402` / payment-declined behavior.** Endpoint declares only `200`/`422`; whether a decline yields `402`, a `422`, or a `200` with a failure flag is unknown. Why unverifiable: not in the OpenAPI response set or frontend types. Action: probe dev backend with a failing payment method.
- **Server-side idempotency dedupe.** `VodPurchaseIn.idempotency_key` is accepted, but dedupe behavior is not provable from the schema. Why unverifiable: behavioral, not schema-encoded. Mitigation: rely on `already_owned` for safe retries.
- **Whether `payment_method_id` is required for non-simulated charges.** It is optional in `VodPurchaseIn`; the dev backend simulates the charge. Why unverifiable: prod PSP integration is out of scope (§13.3).
- **Exact `VodEntity.locked` mapping ownership.** This spec derives `locked = !entitled`, but the `VodEntity` schema is owned by AND-191 and not present in these reference sources. Why unverifiable: Android module source is not in the reference tree. Action: align with AND-191 during implementation.

## 17. Test Plan

Test targets: **JVM** (JVM unit/Robolectric, no device); **EMU** (headless emulator AVD `test35`, x86_64, API 35); **DEVICE** (physical Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a). MockWebServer (AND-046 harness) backs contract/unit cases. IDs trace to §14 acceptance criteria (AC-1…AC-8).

- **TC-AND-193-01 — Access mapping happy path (contract/MockWebServer).** Target: JVM. Preconditions: MockWebServer enqueues `200 VodAccessOut` `{entitled:false, purchase_available:true, price_cents:1499, purchase_type:"permanent", views_remaining:-1, reason:"not_purchased"}`. Steps: call `VodPurchaseRepositoryImpl.getAccess(videoId)`. Expected: domain offer exposes the `permanent` option with `priceCents=1499`, `entitled=false`; request hit `GET /ui/videos/{video_id}/access` and carried `X-CSRF-Token`. Traces: AC-2.
- **TC-AND-193-02 — Purchase happy path → unlock (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `200 VodPurchaseOut` `{video_id, already_owned:false, granted_at:1749120000, grant_type:"purchase", amount_cents:1499, purchase_type:"permanent", views_remaining:-1, expires_at:null}`. Steps: select `permanent`, `onConfirm()`. Expected: exactly one `POST /ui/videos/{video_id}/purchase` with body `{purchase_type:"permanent", idempotency_key:<uuid>}`; `isPurchased=true`; `PurchaseEvent.Unlocked` emitted; `granted_at` parsed as epoch-seconds `Instant`; `VodEntity.locked` set false. Traces: AC-1, AC-3, AC-4.
- **TC-AND-193-03 — Idempotent already-owned (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `200 VodPurchaseOut` with `already_owned:true`. Steps: `onConfirm()`. Expected: treated as success → `PurchaseEvent.Unlocked`, content unlocks, no error surfaced. Traces: AC-1, AC-5.
- **TC-AND-193-04 — `idempotency_key` in body + single key per selection (unit).** Target: JVM. Preconditions: stubbed repo capturing request body. Steps: confirm once, observe key; change `purchase_type`, confirm again. Expected: key is in the JSON **body** field `idempotency_key` (no `Idempotency-Key`/`X-Idempotency-Key` header present); same key reused for a same-selection retry; a new key after selection change. Traces: AC-3.
- **TC-AND-193-05 — Double-submit guard (unit).** Target: JVM. Preconditions: repo suspends on first purchase call. Steps: invoke `onConfirm()` twice rapidly while `isSubmitting`. Expected: exactly one POST issued; second call is a no-op. Traces: AC-3.
- **TC-AND-193-06 — `422` validation error leaves content locked (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `422 HTTPValidationError` `{detail:[{msg:"invalid purchase_type"}]}`. Steps: confirm. Expected: `purchaseError` shows first `msg`; content stays locked; retry/another-option available; no unlock. Traces: AC-5, AC-6.
- **TC-AND-193-07 — Purchase POST not auto-retried; access GET is (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `503` then `200` for both an access GET and a purchase POST. Steps: trigger each. Expected: access GET retries within bounded backoff and ultimately succeeds; purchase POST is **not** auto-retried (single request observed, error surfaced for manual retry). Traces: AC-6.
- **TC-AND-193-08 — 401 mid-flow: one refresh + retry, else RequireReauth (contract/MockWebServer).** Target: JVM. Preconditions: enqueue `401`, then `200 /ui/session/refresh`, then `200 VodPurchaseOut`; a second scenario keeps returning `401`. Steps: confirm. Expected: first scenario performs exactly one `/ui/session/refresh` then retried purchase succeeds; second scenario emits `PurchaseEvent.RequireReauth` and does not silently fail. Traces: AC-7.
- **TC-AND-193-09 — Offline access fetch (integration).** Target: EMU (airplane mode toggled via adb). Preconditions: no connectivity. Steps: open the sheet. Expected: `tiersError` (offline variant) + Retry shown; no purchase possible; no optimistic unlock. Traces: AC-6.
- **TC-AND-193-10 — Locked vs entitled detail rendering (Compose-UI).** Target: EMU. Preconditions: stub offer `entitled=false` then `entitled=true`. Steps: render detail in each state. Expected: locked shows the Unlock entry (no play); entitled shows play and no entry point. Traces: AC-1, AC-2.
- **TC-AND-193-11 — Confirm flow UI: processing → success → unlock (Compose-UI).** Target: EMU. Preconditions: stubbed delayed `200` success. Steps: open sheet, select an option, tap Confirm. Expected: skeleton → option list → option selectable → Confirm enabled → Confirm disabled during processing → success → sheet dismisses → overlay gone (content unlocked via Room `Flow` re-emit). Traces: AC-1, AC-3, AC-4.
- **TC-AND-193-12 — Accessibility on the purchase sheet (Compose-UI/instrumented).** Target: EMU (+ DEVICE for a real TalkBack pass). Preconditions: sheet open with ≥2 options. Steps: enable accessibility checks / TalkBack; traverse rows, selection, Confirm, Retry, dismiss. Expected: each control has a content description; option rows expose a combined label incl. localized price; selected state is conveyed non-color (icon/check + text); touch targets ≥48dp; sheet dismissible via back gesture and TalkBack. Traces: AC-8.
- **TC-AND-193-13 — Locale/currency + no hardcoded strings (instrumented).** Target: DEVICE (real locale/`NumberFormat` behavior on API 34/arm64). Preconditions: device locale set to e.g. `de-DE`; offer `price_cents=1499`. Steps: open sheet. Expected: price formatted via `NumberFormat.getCurrencyInstance(locale)` (no hardcoded `$`/decimal assumptions); all labels from `strings.xml`/`<plurals>`; rental window via locale plurals. Traces: AC-2, AC-8.
- **TC-AND-193-14 — Entitlement survives relaunch; no secrets logged (instrumented/e2e + security).** Target: DEVICE. Preconditions: real session against dev host; logcat capture on. Steps: purchase to success, kill and relaunch the app, reopen the VOD; inspect logcat. Expected: VOD renders unlocked/playable after relaunch (Room-persisted, server-authoritative); logcat contains **no** cookies, `X-CSRF-Token`, Bearer token, or `idempotency_key`; no card/PAN data. Traces: AC-4, AC-8.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (purchase unlocks content) | TC-02, TC-03, TC-10, TC-11 |
| AC-2 (locked shows offer w/ formatted price; entitled shows none) | TC-01, TC-10, TC-13 |
| AC-3 (select→one POST w/ purchase_type, idempotency_key, CSRF; in-flight disable) | TC-02, TC-04, TC-05, TC-11 |
| AC-4 (persist entitlement; survives relaunch) | TC-02, TC-11, TC-14 |
| AC-5 (already_owned success; errors keep locked) | TC-03, TC-06 |
| AC-6 (tiers Retry; POST never auto-retried) | TC-06, TC-07, TC-09 |
| AC-7 (one refresh+retry on 401; else reauth) | TC-08 |
| AC-8 (no hardcoded strings/currency; TalkBack labels; no secrets logged) | TC-12, TC-13, TC-14 |
