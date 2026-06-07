---
id: AND-266
title: Promo codes
milestone: M6
epic: E36
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-266 — Promo codes

## 1. Overview & Goal

This ticket delivers the Android client surface for **promo codes**: the data,
network, and presentation layers that let an authenticated TestLogon user (with
the appropriate role) **create** and **list** promotional codes, with
secondary **deactivate**/**stats** parity and a thin **redeem** client.
It is the native parity port of the web reference module
`src/api/endpoints/promoCodes.ts` (consumed by `src/pages/promo/PromoCodesPage.tsx`).

> REVIEW NOTE (2026-06-06): The web reference page (`PromoCodesPage.tsx`)
> exposes Create, List, Deactivate, and Stats — it does NOT expose a
> user-facing "redeem by code" affordance. The backend `POST
> /ui/promo-codes/redeem` is documented as *"Record a redemption after
> payment. Typically called internally."* The original draft modeled redeem as
> a primary user flow with a `{"code": ...}` body; that is INCORRECT (see §5
> and §16). Redeem is retained here as a thin API client for completeness but
> is NOT a gating MVP surface; the parity surfaces that must be green are
> create + list (matching the backlog "Promo create/list works").

The deliverable is end-to-end but intentionally bounded: a `PromoCodesApi`
Retrofit interface, a `PromoCodesRepository` that maps `ApiResult<T>`, a Hilt
module wiring, and a minimal Compose feature (`feature-promo`) exposing a list
screen and create/redeem flows backed by a `StateFlow<PromoCodesUiState>`
ViewModel. The authoritative acceptance bar from the backlog is narrow —
"Promo create/list works" — so redeem is implemented as a first-class path but
the gating MVP behaviour that must be demonstrably green is create + list.

Goal: an authorized user can open the Promo screen, see a list of existing
codes, and create a new code via a form, with both operations resilient to the
unreliable dev backend. (Deactivate, stats, and the internal redeem client are
parity extras, not the gating bar.)

> REVIEW NOTE: `GET /ui/promo-codes` is NOT paged — it accepts no `cursor`/
> `limit` query params and returns the full `PromoCodeListOut { items[],
> next_cursor }` in one shot (the web client renders `data.items` directly with
> React Query `staleTime: 30s`). The original "paged list" design below is a
> forward-looking enhancement, not current contract; it is flagged inline.

## 2. Context & References

- **Web reference:** `src/api/endpoints/promoCodes.ts` (CRUD-style surface),
  shared DTO shapes in `src/api/types.ts`, screen in
  `src/pages/promo/PromoCodesPage.tsx`, transport in `src/api/client.ts`.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — the `promo-codes`
  tag is the source of truth. CORRECTED: the actual base path is
  **`/ui/promo-codes`** (not `/promo-codes`). Endpoints (verified against the
  index): `GET /ui/promo-codes` (list), `POST /ui/promo-codes` (create, 201),
  `POST /ui/promo-codes/redeem` (redeem, internal), `POST
  /ui/promo-codes/validate` (validate), `GET /ui/promo-codes/{code_id}`
  (stats), `PATCH /ui/promo-codes/{code_id}` (update), `DELETE
  /ui/promo-codes/{code_id}` (deactivate). DTO shapes here have been
  reconciled against the live schema (see §16); diff again before code freeze.
- **Auth dependency:** AND-027 (`AuthApi` + session/CSRF infrastructure). All
  promo endpoints are authenticated. CORRECTED: the web transport
  (`src/api/client.ts`) sends THREE auth-related pieces, not just a cookie jar:
  (1) `Authorization: Bearer <accessToken>` from the auth store, (2) the
  `ui_csrf` cookie echoed as the `X-CSRF-Token` header, and (3) `credentials:
  include` (cookie jar). It also forwards `X-IMPERSONATION-TOKEN` when an
  impersonation session is active. The OpenAPI further declares optional
  `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` headers and a `user_sub` query
  param on every promo endpoint. This ticket does **not** re-implement session
  handling; it consumes the configured `OkHttpClient`/`Retrofit` from AND-027,
  which MUST attach the Bearer token + CSRF header + cookies (verify AND-027
  provides all three).
- **Module layering:** `app -> feature-promo -> core-*`
  (`core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 /
  OkHttp 4.12 / Moshi 1.15, Paging 3, Coroutines/Flow. `applicationId` /
  namespace base **`com.testlogon.android`**.

## 3. Functional Requirements

FR-1 **List.** The Promo screen displays existing promo codes. Each row shows
the code string, discount summary, usage (`current_uses` / `max_uses`, with
`max_uses == 0` rendered as unlimited), active/inactive/expired badge, and
expiry date (`expires_at == 0` => "Never"). CORRECTED: `GET /ui/promo-codes`
is NOT paginated (no `cursor`/`limit` params; full `items[]` returned in one
call). For MVP parity the screen loads the full list once (mirroring the web
client's single React-Query fetch with `staleTime: 30s`). The Paging-3 design
in §4/§6 is retained as an OPTIONAL forward-looking enhancement and is clearly
labeled as such; it is not required to satisfy AC-2. Ordering is whatever the
server returns (the web client does not re-sort; "newest first" is NOT a
verified contract — treat as a server concern).

FR-2 **Create.** A "Create code" affordance opens a form. CORRECTED fields
(per `PromoCodeCreateIn`): `code` (**REQUIRED**, 3–30 chars; web client
uppercases it — server does NOT auto-generate), `discount_type`
(`percentage` | `fixed_amount` | `free_trial` — note `fixed_amount`, not
`fixed`, and a third `free_trial` value), `discount_value` (**integer**;
percent for `percentage`, cents for `fixed_amount`, 0 for `free_trial`),
`free_trial_days` (integer, used only for `free_trial`), `applies_to`
(array subset of `subscription`/`vod`/`shop`, default `["subscription"]`),
`max_uses` (integer, `0` = unlimited — there is NO `max_redemptions` field),
`max_uses_per_user` (integer, default 1), `min_purchase_cents` (integer),
`expires_at` (**epoch seconds integer**, `0` = never). Submitting POSTs the
code; on success the list invalidates and the new code appears.

FR-3 **Redeem (internal/secondary).** CORRECTED: `POST /ui/promo-codes/redeem`
is documented as *"Record a redemption after payment. Typically called
internally."* Its body is NOT `{"code": ...}`; the web client sends
`{ code_id, original_price_cents, final_price_cents, checkout_type,
checkout_item_id? }` and the response is untyped (web treats it as
`{ ok, redeemed_at }`). The web promo page has NO redeem-by-code UI. This
ticket therefore ships redeem only as a thin `PromoCodesApi.redeem(...)`
client mapped through `ApiResult`; it is NOT wired to a user-facing
"enter a code" flow. Domain rejections surface the server `detail` message.

FR-4 **Empty / loading / error states.** The list renders distinct empty,
loading (initial + append), and error (with retry) states per Paging 3
`LoadState`.

FR-5 **CSRF/auth transparency.** Create and redeem (mutations) must carry the
`X-CSRF-Token` header; this is handled by the shared OkHttp interceptor from
AND-027 and requires no per-call code here, but the feature MUST handle the
401 → refresh → retry outcome surfaced as `ApiResult.Error`.

Out of scope: editing/deleting promo codes, admin analytics, bulk import.

## 4. Technical Design

New module `feature-promo` plus DTOs in `core-model` and the API in
`core-network`.

**DTOs (`core-model`, Moshi `@JsonClass(generateAdapter = true)`):**

> CORRECTED to match `components.schemas.PromoCodeOut` / `PromoCodeCreateIn` /
> `PromoCodeListOut` / `PromoValidateIn` / `PromoValidateOut` /
> `PromoDeactivateOut` in the live OpenAPI (the original draft DTOs used wrong
> field names — `id`, `max_redemptions`, `redemption_count` — wrong types
> (`Double`/ISO-8601 strings instead of integer/epoch-seconds), an incomplete
> discount enum, and a fabricated `total`).

```kotlin
@JsonClass(generateAdapter = true)
data class PromoCodeDto(
    @Json(name = "code_id") val codeId: String,
    @Json(name = "code") val code: String,
    @Json(name = "discount_type") val discountType: String,   // "percentage" | "fixed_amount" | "free_trial"
    @Json(name = "discount_value") val discountValue: Int = 0, // percent or cents
    @Json(name = "free_trial_days") val freeTrialDays: Int = 0,
    @Json(name = "applies_to") val appliesTo: List<String> = emptyList(),
    @Json(name = "min_purchase_cents") val minPurchaseCents: Int = 0,
    @Json(name = "max_uses") val maxUses: Int = 0,            // 0 = unlimited
    @Json(name = "max_uses_per_user") val maxUsesPerUser: Int = 1,
    @Json(name = "current_uses") val currentUses: Int = 0,
    @Json(name = "active") val active: Boolean = true,
    @Json(name = "expires_at") val expiresAt: Long = 0,       // epoch SECONDS, 0 = never
    @Json(name = "created_at") val createdAt: Long = 0,       // epoch SECONDS
    @Json(name = "creator_user_id") val creatorUserId: String = "",
)

@JsonClass(generateAdapter = true)
data class PromoCodeListOut(
    @Json(name = "items") val items: List<PromoCodeDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String?,      // present in schema; server currently has no cursor input
)

@JsonClass(generateAdapter = true)
data class CreatePromoRequest(
    @Json(name = "code") val code: String,                    // REQUIRED, 3..30 chars
    @Json(name = "discount_type") val discountType: String,   // REQUIRED enum (see above)
    @Json(name = "discount_value") val discountValue: Int = 0,
    @Json(name = "free_trial_days") val freeTrialDays: Int = 0,
    @Json(name = "applies_to") val appliesTo: List<String> = listOf("subscription"),
    @Json(name = "min_purchase_cents") val minPurchaseCents: Int = 0,
    @Json(name = "max_uses") val maxUses: Int = 0,
    @Json(name = "max_uses_per_user") val maxUsesPerUser: Int = 1,
    @Json(name = "expires_at") val expiresAt: Long = 0,
)

// Redeem — internal/post-payment; OpenAPI body is a free-form object, the web
// client sends the fields below and reads back { ok, redeemed_at }.
@JsonClass(generateAdapter = true)
data class RedeemPromoRequest(
    @Json(name = "code_id") val codeId: String,
    @Json(name = "original_price_cents") val originalPriceCents: Int,
    @Json(name = "final_price_cents") val finalPriceCents: Int,
    @Json(name = "checkout_type") val checkoutType: String,
    @Json(name = "checkout_item_id") val checkoutItemId: String? = null,
)

@JsonClass(generateAdapter = true)
data class RedeemPromoResponse(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "redeemed_at") val redeemedAt: Long = 0,     // epoch seconds (untyped in OpenAPI)
)

// Deactivate (DELETE /ui/promo-codes/{code_id}) → PromoDeactivateOut
@JsonClass(generateAdapter = true)
data class PromoDeactivateOut(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "code_id") val codeId: String,
    @Json(name = "active") val active: Boolean = false,
)
```

A domain model `PromoCode` (in `core-model`) decouples UI from wire types; a
`PromoCodeDto.toDomain()` mapper converts `expiresAt`/`createdAt` from epoch
SECONDS to `kotlinx.datetime.Instant?` (treat `0` as null/"never") and derives
an `isExpired` flag (`expiresAt > 0 && expiresAt < now`) against the device
clock, mirroring `PromoCodesPage.tsx#isExpired`.

**Repository (`core-data`):**

> CORRECTED: `redeem` takes a `RedeemPromoRequest` (not a bare `code` string),
> and the MVP list is a single non-paged fetch. The paged variant is optional.

```kotlin
interface PromoCodesRepository {
    // MVP (matches the non-paged GET /ui/promo-codes):
    suspend fun listCodes(): ApiResult<List<PromoCode>>
    suspend fun create(request: CreatePromoRequest): ApiResult<PromoCode>
    suspend fun deactivate(codeId: String): ApiResult<Unit>
    suspend fun redeem(request: RedeemPromoRequest): ApiResult<RedeemPromoResponse>

    // OPTIONAL forward-looking enhancement (NOT required for AC-2):
    fun pagedCodes(): Flow<PagingData<PromoCode>>
    suspend fun refreshList()   // invalidates the PagingSource
}
```

The MVP `listCodes()` issues a single `GET /ui/promo-codes` and maps
`PromoCodeListOut.items` to domain. The list refreshes after a successful
create/deactivate by re-invoking `listCodes()` (the web client invalidates its
`["promo-codes","list"]` query the same way).

OPTIONAL (only if/when the backend gains cursor support): `pagedCodes()` backed
by a `Pager(PagingConfig(pageSize = 20, prefetchDistance = 5))` whose
`PromoCodePagingSource` would call a future cursored list endpoint. As of this
review the endpoint accepts no `cursor`/`limit`, so a single-page PagingSource
(or plain in-memory list) is the only correct implementation today.

**ViewModel (`feature-promo`):**

```kotlin
@HiltViewModel
class PromoCodesViewModel @Inject constructor(
    private val repo: PromoCodesRepository,
) : ViewModel() {
    val codes: Flow<PagingData<PromoCode>> =
        repo.pagedCodes().cachedIn(viewModelScope)

    private val _uiState = MutableStateFlow(PromoCodesUiState())
    val uiState: StateFlow<PromoCodesUiState> = _uiState.asStateFlow()

    fun onCreate(form: CreatePromoForm)            // validates, calls repo.create
    fun onDeactivate(codeId: String)               // calls repo.deactivate, refreshes
    // onRedeem is internal-only; if exposed it takes a RedeemPromoRequest, NOT a code string.
    fun consumeMessage()                           // clears transient banner
}
```

**UI state:**

```kotlin
data class PromoCodesUiState(
    val isSubmitting: Boolean = false,
    val createSheet: CreateSheetState = CreateSheetState.Hidden,
    val redeemResult: RedeemResult? = null,
    val message: UiMessage? = null,                // success/error banner
)
```

**Compose surface:** `PromoCodesScreen(viewModel)` renders the list in a
`LazyColumn` (MVP: from `ApiResult<List<PromoCode>>` UI state; optional Paging
variant via `collectAsLazyPagingItems()`); a FAB opens a Material 3
`ModalBottomSheet` create form mirroring `CreatePromoDialog` (code, discount
type incl. `free_trial`, applies_to checkboxes, max uses, max per user, min
purchase). Each row offers Deactivate (DELETE) and Stats, matching the web
page. CORRECTED: there is NO user-facing "redeem a code" dialog (redeem is an
internal post-payment call). Nav entry registered in app graph as route `promo`
(Navigation-Compose), reachable once the user is authenticated.

**Hilt wiring (`core-network`):**

```kotlin
@Module @InstallIn(SingletonComponent::class)
object PromoNetworkModule {
    @Provides @Singleton
    fun providePromoCodesApi(retrofit: Retrofit): PromoCodesApi =
        retrofit.create(PromoCodesApi::class.java)
}
```

The injected `Retrofit` is the shared instance from AND-027 (same `OkHttpClient`
with cookie jar + CSRF interceptor + 20s timeouts).

## 5. API Contract

Base: dev `http://18.222.237.167:8000` (PLAINTEXT — see §8). All calls
authenticated; the shared client attaches `Authorization: Bearer <token>`, the
`X-CSRF-Token` header (from the `ui_csrf` cookie), and cookies (handled
upstream in AND-027).

> CORRECTED: every path is under **`/ui/`** and the list endpoint is NOT
> paginated. Verified against `openapi.index.txt` lines 1754–1760 and the path
> objects in `openapi.pretty.json`.

```kotlin
interface PromoCodesApi {
    // GET /ui/promo-codes — no cursor/limit params (full list returned)
    @GET("ui/promo-codes")
    suspend fun list(): Response<PromoCodeListOut>

    // POST /ui/promo-codes → 201
    @POST("ui/promo-codes")
    suspend fun create(@Body body: CreatePromoRequest): Response<PromoCodeDto>

    // POST /ui/promo-codes/redeem → 200 (internal/post-payment; untyped body+resp)
    @POST("ui/promo-codes/redeem")
    suspend fun redeem(@Body body: RedeemPromoRequest): Response<RedeemPromoResponse>

    // DELETE /ui/promo-codes/{code_id} → 200 PromoDeactivateOut (deactivate)
    @DELETE("ui/promo-codes/{code_id}")
    suspend fun deactivate(@Path("code_id") codeId: String): Response<PromoDeactivateOut>

    // GET /ui/promo-codes/{code_id} → 200 PromoCodeStatsOut (optional, stats)
    @GET("ui/promo-codes/{code_id}")
    suspend fun stats(@Path("code_id") codeId: String): Response<PromoCodeStatsOut>
}
```

All endpoints also accept an optional `user_sub` query param and optional
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (declared in OpenAPI); the
shared client supplies these as applicable — no per-call code here.

**List — `GET /ui/promo-codes` → 200** (`PromoCodeListOut`)

```json
{
  "items": [
    {
      "code_id": "pc_01HZ...",
      "code": "SUMMER25",
      "discount_type": "percentage",
      "discount_value": 25,
      "free_trial_days": 0,
      "applies_to": ["subscription"],
      "min_purchase_cents": 0,
      "max_uses": 100,
      "max_uses_per_user": 1,
      "current_uses": 12,
      "active": true,
      "expires_at": 1788307200,
      "created_at": 1780308000,
      "creator_user_id": "usr_..."
    }
  ],
  "next_cursor": null
}
```

**Create — `POST /ui/promo-codes` → 201**, body `PromoCodeCreateIn` (`code` and
`discount_type` required; all other fields integer/array with defaults), returns
a single `PromoCodeOut`. Example body:

```json
{
  "code": "SUMMER25",
  "discount_type": "percentage",
  "discount_value": 25,
  "free_trial_days": 0,
  "applies_to": ["subscription"],
  "max_uses": 100,
  "max_uses_per_user": 1,
  "min_purchase_cents": 0
}
```

**Redeem — `POST /ui/promo-codes/redeem` → 200**, free-form JSON object body;
web client sends
`{"code_id":...,"original_price_cents":...,"final_price_cents":...,"checkout_type":...,"checkout_item_id"?:...}`
and reads back an untyped object treated as `{"ok":true,"redeemed_at":<epoch>}`.
NOT `{"code":...}`. Documented as internal/post-payment.

**Deactivate — `DELETE /ui/promo-codes/{code_id}` → 200** (`PromoDeactivateOut`
`{ok, code_id, active}`).

**Errors (FastAPI `detail`):** the shared `ApiResult` mapper (mirrors
`normalizeErrorDetail` in `src/api/client.ts`) handles three `detail` shapes —
`string`, `[{ "msg": ... }]` (422 validation array), and
`{ "code": ... }` (authorization codes such as `role_required`,
`role_required_scope`, `geo_blocked`). VERIFIED status: every promo endpoint
documents only `422 HTTPValidationError` in OpenAPI. The other statuses the
original draft enumerated (`400/409` duplicate/exhausted/expired, `404` unknown
code, `403` insufficient role) are NOT documented per-endpoint and are
UNVERIFIED assumptions about FastAPI runtime behavior — the mapper must still
handle them defensively, but tests should not assert specific non-422 codes as
contract. `401` → upstream single refresh (`POST /ui/session/refresh`) then one
retry; a second 401 logs out.

> NOTE: paths/verbs/bodies above are now reconciled to the live schema. Re-diff
> against `/openapi.json` before code freeze — only this feature depends on
> these shapes.

## 6. Data & State Management

- **Source of truth:** the network. No Room persistence for promo codes in this
  ticket (low value, role-gated, mutable counts). Paging 3 holds the in-memory
  list; `DataStore` is not used here.
- **Paging:** CORRECTED — `GET /ui/promo-codes` takes no cursor/limit input, so
  MVP is a single fetch of `PromoCodeListOut.items`. The cursor-based
  `PromoCodePagingSource` (returning `LoadResult.Page(data, prevKey = null,
  nextKey = page.nextCursor)`, end-of-pagination on `next_cursor == null`) is an
  OPTIONAL future enhancement contingent on the server adding a cursor input;
  today it would always return a single page.
- **Invalidation:** after `create`/`deactivate` success the repo re-fetches the
  list (web parity: invalidates the `["promo-codes","list"]` query). If the
  optional Paging path is used, `refreshList()` →
  `pagingSourceFactory.invalidate()` refetches.
- **ViewModel state:** transient UI concerns (submitting flag, sheet
  visibility, banner message, last redeem result) live in
  `PromoCodesUiState` via `StateFlow`; the list itself stays in the cold
  `Flow<PagingData>` `cachedIn(viewModelScope)` to survive config changes.
- **Form state:** `CreatePromoForm` is plain Compose state hoisted in the sheet;
  validation (discountValue > 0; percentage ≤ 100; expiresAt in future)
  happens client-side before the network call and again server-side.

## 7. Error Handling & Resilience

- **Timeouts:** inherit the 20s connect/read/write timeouts from the shared
  client (dev host is unreliable).
- **Retries:** GET `list` is idempotent → eligible for the shared bounded
  exponential backoff (max 3 attempts) defined in AND-027's interceptor.
  `create` and `redeem` are **non-idempotent POSTs** → NO automatic retry; the
  user retries manually. (A create with an explicit `code` is naturally
  idempotent server-side via the duplicate-code 409, which we surface, not
  retry.)
- **Paging LoadStates:** `loadState.refresh`/`append` errors render an inline
  retry row/button calling `retry()`. Initial error shows a full-screen error
  with retry.
- **Offline/stale:** on `IOException` the list shows an offline banner with
  retry; existing loaded pages remain visible (stale-while-error).
- **Domain rejections:** expired/exhausted/duplicate map from `detail` to a
  user-facing `UiMessage` shown as a `Snackbar`; the form/dialog stays open so
  the user can correct input.
- **401:** handled transparently by the upstream single-refresh-then-retry; a
  second 401 surfaces as `ApiResult.Error(Unauthorized)` → navigate to auth.

## 8. Security & Privacy

- All requests authenticated; promo creation is typically role-restricted —
  the client treats `403` as "not permitted". UNVERIFIED: `GET /ui/me` exists
  but returns an untyped 200 in OpenAPI (no documented schema), so a specific
  "promo-admin capability" flag to hide the create FAB cannot be confirmed.
  Safer behavior (matching the web client, which always shows "Create Code"):
  show the FAB and surface `403`/`role_required*` via the `detail` mapper. Any
  FAB-hiding based on `/ui/me` is best-effort and must degrade gracefully;
  server remains the enforcer.
- **Plaintext dev host:** the dev backend is HTTP. A scoped
  `network_security_config.xml` cleartext exception for the dev host is owned by
  the network bootstrap ticket; this feature adds nothing — production MUST be
  HTTPS. No promo data is written to disk (no Room/DataStore), so no at-rest
  exposure.
- **CSRF:** mutations rely on the `ui_csrf` cookie echoed as `X-CSRF-Token`
  (AND-027); never log the token or cookies.
- **No PII:** promo codes are not personal data; redemption responses contain no
  user identifiers beyond the authenticated session.

## 9. Accessibility & i18n

- All actionable controls (FAB, redeem action, retry) carry
  `contentDescription`; min touch target 48dp.
- List rows expose a merged semantics node summarizing code + discount + status
  for TalkBack (e.g. "SUMMER25, 25 percent off, 12 of 100 redeemed, expires
  September 1").
- Active/expired status communicated by text + badge, not colour alone.
- All strings in `strings.xml` (`feature-promo`); discount values formatted via
  `NumberFormat`/`java.text` respecting locale; dates via the device locale.
  No hardcoded user-facing literals in Kotlin/Compose.

## 10. Telemetry & Logging

- **Events** (via the app's analytics abstraction, no PII):
  `promo_list_viewed`, `promo_create_submitted{discount_type}`,
  `promo_create_succeeded`, `promo_create_failed{reason}`,
  `promo_redeem_submitted`, `promo_redeem_succeeded`,
  `promo_redeem_failed{reason}`.
- **Logging:** debug-only `Timber` logs of request paths and HTTP status; OkHttp
  `HttpLoggingInterceptor` at `BODY` only in debug builds. Never log cookies,
  `X-CSRF-Token`, or full promo codes at `INFO`+ in release.

## 11. Testing Strategy

- **API (MockWebServer, `core-testing`):** CORRECTED paths/bodies — assert
  `list` issues `GET /ui/promo-codes` (NO `cursor`/`limit` query); `create`
  issues `POST /ui/promo-codes` with the exact `PromoCodeCreateIn` JSON
  (integer fields, `code` present); `deactivate` issues `DELETE
  /ui/promo-codes/{code_id}`; `redeem` issues `POST /ui/promo-codes/redeem`
  with the `{code_id, original_price_cents, ...}` body (NOT `{"code":...}`).
  Parse the §5 fixtures into DTOs. Mirrors AND-027's MockWebServer acceptance
  pattern and covers the backlog "create/list works" bar at the contract layer.
- **Repository (unit):** success → `ApiResult.Ok(domain)`; `422` (the only
  documented error) and defensively-handled `400/403/404/409` → mapped
  `ApiResult.Error` carrying the correct `detail` (string / `[{msg}]` array /
  `{code}`) message; verify the list re-fetches after create/deactivate.
- **PagingSource (unit):** cursor threading, end-of-pagination on
  `next_cursor == null`, error → `LoadResult.Error`.
- **ViewModel (unit, Turbine):** `onCreate` toggles `isSubmitting`, emits
  success banner, triggers invalidation; `onRedeem` populates `redeemResult`;
  validation rejects bad input without a network call.
- **Compose UI tests:** list renders rows; empty/loading/error states; create
  sheet submit happy path; redeem dialog error surfaces snackbar.
- **Coverage target:** repository + mapper + PagingSource ≥ 85% line.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi + cookie jar + CSRF interceptor + shared
  `Retrofit`/`OkHttpClient`/`ApiResult` mapper). Promo calls are unauthenticated
  -fail without it.
- Transitively depends on the network/DI bootstrap that AND-027 itself depends
  on (AND-026) for the base Retrofit/Moshi configuration.
- **Blocks:** nothing in the current backlog.
- **Sequencing:** land DTOs in `core-model` → `PromoCodesApi` + MockWebServer
  tests in `core-network` → repository + PagingSource in `core-data` →
  `feature-promo` ViewModel/Compose → app nav wiring.

## 13. Risks & Open Questions

- **R1 (schema drift):** RESOLVED in this review — endpoints live under
  `/ui/promo-codes`, the list is non-cursor, and field names/types are
  reconciled (see §5/§16). Residual risk: dev backend may still drift; re-diff
  before freeze; DTOs are isolated to this feature.
- **R2 (auto-generated vs. user code):** RESOLVED — `code` is **REQUIRED**
  (`PromoCodeCreateIn.required = ["code","discount_type"]`, 3–30 chars); the
  server does NOT auto-generate. The form must require a code.
- **R3 (role gating):** the capability flag on `GET /ui/me` that should hide the
  create FAB may not exist; fallback is to show the FAB and surface `403`.
- **R4 (dev host flakiness):** create/redeem are non-retryable POSTs on an
  unreliable host → users may double-submit. Mitigation: disable the submit
  button while `isSubmitting`, rely on server duplicate-code 409.
- **OQ (redeem):** PARTIALLY RESOLVED — OpenAPI labels redeem *"Record a
  redemption after payment. Typically called internally."* and the web promo
  page has no redeem UI, so it is treated as an internal post-payment call, not
  a user-facing redeem-by-code flow. The exact required body fields are
  unverifiable (free-form object in OpenAPI); we mirror the web client's fields.

## 14. Acceptance Criteria

AC-1 (**authoritative**) Creating a promo code via the form (with a required
`code` of 3–30 chars and a valid `discount_type`) results in a `201
PromoCodeOut`, the new code appears in the list after the list re-fetch, and a
success banner shows.

AC-2 (**authoritative**) The Promo screen lists existing codes from
`GET /ui/promo-codes` (single non-paged fetch of `items[]`), with correct
discount label (`X% off` / `$Y off` from cents / `N-day trial`),
active/inactive/expired status, usage `current_uses/max_uses` (0 = unlimited),
and expiry (epoch `0` = "Never") rendering.

AC-3 MockWebServer tests confirm `list` (`GET /ui/promo-codes`, no query),
`create` (`POST /ui/promo-codes`, `PromoCodeCreateIn` body), `deactivate`
(`DELETE /ui/promo-codes/{code_id}`), and `redeem` (`POST
/ui/promo-codes/redeem`, `{code_id,...}` body) use the exact paths, verbs, and
JSON bodies in §5 (mirrors AND-027 acceptance).

AC-4 The redeem client (`POST /ui/promo-codes/redeem`) succeeds on a valid
request and, on a domain rejection or `422`, surfaces the server `detail`
message (string / `[{msg}]` / `{code}`) without crashing. (Redeem is internal;
no user-facing redeem-by-code screen is required.) Deactivating a code via
`DELETE` flips its badge to Inactive after the list re-fetch.

AC-5 List empty, initial-loading, and error-with-retry states each render
correctly (verified by Compose tests). Append-loading applies only if the
optional Paging variant is implemented; for the non-paged MVP it is N/A.

AC-6 Non-idempotent POSTs are not auto-retried; GET list participates in the
shared bounded backoff; 20s timeouts apply.

AC-7 No cookies/CSRF token/full codes logged at `INFO`+ in release builds.

## 15. Definition of Done

- `feature-promo` module builds under AGP 8.7.3 / Gradle 8.9 / JDK 17, namespace
  `com.testlogon.android.feature.promo`.
- `PromoCodesApi` (under `ui/promo-codes`), DTOs, `PromoCodesRepository`,
  `PromoCodesViewModel`, and `PromoCodesScreen` implemented and Hilt-wired.
  (`PromoCodePagingSource` only if the optional paged variant is built.)
- AC-1…AC-7 met; all unit/MockWebServer/Compose tests green in CI; coverage
  target met.
- DTO shapes reconciled against `/openapi.json` (R1/R2 resolved) and any
  divergences reflected in code + fixtures.
- No new lint/detekt errors; strings localized; accessibility semantics present.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index `reference/openapi.index.txt`, OpenAPI full
`reference/openapi.pretty.json` (`components.schemas.<Name>`), and frontend
files under `reference/src/`.

1. **Base path is `/ui/promo-codes`, not `/promo-codes`.** — Corrected.
   Source: OpenAPI index lines 1754–1760 (`GET/POST /ui/promo-codes`, `POST
   /ui/promo-codes/redeem`, etc.); `src/api/endpoints/promoCodes.ts`
   (`api.post("/ui/promo-codes", ...)`).
2. **`GET /ui/promo-codes` lists all codes; returns 200 `PromoCodeListOut`.** —
   Verified. Source: OpenAPI index 1754 (`op=list_codes...`,
   `resp=200:PromoCodeListOut`); path object `openapi.pretty.json` line 234110;
   `src/api/endpoints/promoCodes.ts: listPromoCodes`.
3. **List endpoint has NO `cursor`/`limit` query params (not paginated).** —
   Corrected (draft claimed `?cursor=&limit=20`). Source: GET params at
   `openapi.pretty.json` 234112–234160 (only `user_sub`, `X-SESSION-ID`,
   `X-IMPERSONATION-TOKEN`); `listPromoCodes` sends no params;
   `PromoCodesPage.tsx` renders `data.items` directly.
4. **`PromoCodeListOut = { items: PromoCodeOut[], next_cursor: string|null }`
   (no `total`).** — Corrected (draft added `total`). Source:
   `components.schemas.PromoCodeListOut` `openapi.pretty.json` 59308–59331;
   `src/api/types.ts: PromoCodeListOut` (3941).
5. **`PromoCodeOut` id field is `code_id` (not `id`).** — Corrected. Source:
   `PromoCodeOut.required = ["code_id","code","discount_type"]`
   `openapi.pretty.json` 59406–59410; `src/api/types.ts: PromoCodeOut` (3924).
6. **`discount_type` enum is `percentage|fixed_amount|free_trial` (3 values).**
   — Corrected (draft had `percentage|fixed`). Source:
   `PromoCodeCreateIn.discount_type.enum` `openapi.pretty.json` 59261–59269;
   `promoCodes.ts: createPromoCode` body type; `PromoCodesPage.tsx` Select items.
7. **`discount_value`/`max_uses`/etc. are integers; values are cents/percent;
   timestamps are epoch SECONDS integers (not `Double`/ISO-8601 strings).** —
   Corrected. Source: `PromoCodeOut`/`PromoCodeCreateIn` property `type:
   integer` `openapi.pretty.json` 59270–59299, 59356–59404;
   `PromoCodesPage.tsx#formatDate` (`new Date(ts*1000)`) and `#isExpired`
   (`expires_at < Date.now()/1000`).
8. **Usage fields are `max_uses` / `current_uses` (not `max_redemptions` /
   `redemption_count`); `max_uses == 0` = unlimited.** — Corrected. Source:
   `PromoCodeOut` props 59390–59404, 59366–59370; `PromoCodesPage.tsx`
   (`{c.current_uses}/{c.max_uses || "∞"}`).
9. **Create `code` is REQUIRED (3–30 chars); server does NOT auto-generate.** —
   Corrected (draft: optional/server-generated). Source:
   `PromoCodeCreateIn.required = ["code","discount_type"]` + `code.minLength 3 /
   maxLength 30` `openapi.pretty.json` 59255–59259, 59301–59304;
   `CreatePromoDialog` submit `disabled={... || !code.trim()}`.
10. **Create extra fields: `free_trial_days`, `applies_to`
    (`subscription|vod|shop`, default `["subscription"]`), `min_purchase_cents`,
    `max_uses_per_user` (default 1).** — Verified. Source:
    `PromoCodeCreateIn` props `openapi.pretty.json` 59240–59299;
    `promoCodes.ts: createPromoCode` body; `CreatePromoDialog`.
11. **`POST /ui/promo-codes` → 201 `PromoCodeOut`.** — Verified. Source:
    OpenAPI index 1755; path object `openapi.pretty.json` 234251–234261.
12. **Redeem is `POST /ui/promo-codes/redeem`, free-form object body, untyped
    200; web sends `{code_id, original_price_cents, final_price_cents,
    checkout_type, checkout_item_id?}` and reads `{ok, redeemed_at}` — NOT
    `{"code":...}`.** — Corrected. Source: path object
    `openapi.pretty.json` 234279–234369 (requestBody `additionalProperties:
    true`, response `schema: {}`, description "Record a redemption after
    payment. Typically called internally."); `promoCodes.ts: redeemPromoCode`.
13. **Web promo page exposes Create, List, Deactivate (DELETE), Stats — NO
    user-facing redeem-by-code UI.** — Corrected (draft modeled redeem as a
    primary flow). Source: `src/pages/promo/PromoCodesPage.tsx` (imports
    `listPromoCodes/createPromoCode/deletePromoCode/getPromoCodeStats`; no
    redeem import; no redeem control).
14. **Deactivate is `DELETE /ui/promo-codes/{code_id}` → `PromoDeactivateOut
    {ok, code_id, active}`.** — Verified. Source: OpenAPI index 1758;
    `components.schemas.PromoDeactivateOut` `openapi.pretty.json` 59546–59567;
    `promoCodes.ts: deletePromoCode`; `src/api/types.ts: PromoDeactivateOut`.
15. **Stats is `GET /ui/promo-codes/{code_id}` → `PromoCodeStatsOut` (extends
    `PromoCodeOut` with optional `stats`).** — Verified. Source: OpenAPI index
    1759; schema 59414–59506; `promoCodes.ts: getPromoCodeStats`;
    `src/api/types.ts: PromoCodeStatsOut`.
16. **Auth: web client sends `Authorization: Bearer <accessToken>` AND
    `X-CSRF-Token` (from `ui_csrf` cookie) AND cookies (`credentials:
    include`), plus `X-IMPERSONATION-TOKEN` when impersonating.** — Corrected
    (draft said cookie jar + CSRF only). Source: `src/api/client.ts` lines
    157–171, 183.
17. **401 handling: single-flight `POST /ui/session/refresh`, retry once, then
    logout.** — Verified. Source: `src/api/client.ts: refreshSession` (121–130)
    and 401 branch (194–237).
18. **Error `detail` shapes handled: `string`, `[{msg}]` array, `{code}`
    (authorization codes incl. `role_required*`, `geo_blocked`).** — Verified.
    Source: `src/api/client.ts: normalizeErrorDetail` (66–102) and
    `mapAuthorizationError` (34–64).
19. **Only `422 HTTPValidationError` is documented per promo endpoint; the
    `400/409/404/403` statuses the draft enumerated are not in the schema.** —
    Corrected to "unverified, handle defensively". Source: every promo path
    object lists only `200/201` + `422` (e.g. `openapi.pretty.json`
    234162–234182, 234251–234271, 234345–234363).
20. **`GET /ui/me` exists but returns an untyped 200 (no documented capability
    field).** — Unverified-assumption (FAB-hiding by capability cannot be
    confirmed). Source: OpenAPI index 1638 (`resp=200:` empty schema).
21. **Stack/tooling (Kotlin 2.0.21, Compose+M3, Hilt/KSP, Retrofit 2.11 /
    OkHttp 4.12 / Moshi 1.15, Paging 3, AGP 8.7.3, JDK 17).** —
    Unverified-assumption (framework refs; not derivable from backend/frontend
    sources). framework ref: Android developer docs for Paging 3
    (`developer.android.com/topic/libraries/architecture/paging/v3-overview`),
    Hilt (`developer.android.com/training/dependency-injection/hilt-android`),
    Compose Material 3 (`developer.android.com/jetpack/compose`). Reconcile with
    AND-026/AND-027 module conventions before freeze.

### Corrections made

- §2/§5/§11/§14: base path `/promo-codes` → **`/ui/promo-codes`** for all verbs.
- §3/§6: list is **not paginated** (no `cursor`/`limit`); Paging 3 demoted to an
  optional future enhancement; "newest first" downgraded to a server concern.
- §4/§5: DTOs rebuilt to schema — `code_id` (not `id`); integers (not `Double`);
  epoch-seconds timestamps (not ISO-8601); `discount_type` 3-value enum incl.
  `fixed_amount`/`free_trial`; `max_uses`/`current_uses` (not
  `max_redemptions`/`redemption_count`); removed fabricated `total`; added
  `free_trial_days`, `applies_to`, `min_purchase_cents`, `max_uses_per_user`,
  `creator_user_id`; added `PromoDeactivateOut`.
- §3/§13: create `code` is **required** (3–30 chars), not optional/auto-generated.
- §1/§3/§5/§4: redeem corrected to an **internal post-payment** call with a
  `{code_id, ...prices, checkout_type}` body and untyped response; removed the
  `{"code":...}` body and the user-facing redeem dialog. Added Deactivate/Stats.
- §2: auth corrected to **Bearer token + CSRF header + cookies** (+ impersonation).
- §5/§11/§14: only `422` is a documented error; other statuses flagged unverified.
- §8: `/ui/me` capability gating flagged unverifiable; default to showing the FAB.
- §14 AC-1…AC-5 reworded to the corrected contract.

### Open assumptions

- **Exact redeem request body** — OpenAPI body is `additionalProperties: true`
  (free-form); we mirror the web client's fields (`code_id`, price cents,
  `checkout_type`, optional `checkout_item_id`). Cannot be schema-verified.
- **Redeem response shape** — OpenAPI response is `{}` (untyped); `{ok,
  redeemed_at}` is inferred from `promoCodes.ts: redeemPromoCode`'s generic.
- **Non-422 error statuses** (`400/403/404/409` for duplicate/exhausted/
  expired/unknown/role) — not documented per endpoint; handled defensively but
  not asserted as contract.
- **Role/capability gating via `/ui/me`** — endpoint untyped; no confirmable
  promo-admin flag. Default behavior = show FAB, surface `403`.
- **List ordering ("newest first")** — server-determined; not a verified contract.
- **`next_cursor` semantics** — present in the schema but unreachable (no cursor
  input today); assumed always `null` until the backend adds pagination.
- **Android stack/versions and the AND-027 shared client behavior** (that it
  attaches Bearer+CSRF+cookies, applies 20s timeouts, and does bounded GET
  backoff) — depend on AND-026/AND-027, not these sources; verify there.

## 17. Test Plan

IDs `TC-AND-266-NN`. "Traces" link to §14 acceptance criteria. Test targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Promo codes involve no
camera/biometric/WebRTC/FCM hardware, so most cases run on JVM or the emulator;
two cases call out the physical device for real-network and ABI/API coverage.

- **TC-AND-266-01 — Create happy path (contract).** Type: contract/MockWebServer
  (JVM). Target: JVM unit/Robolectric. Preconditions: MockWebServer enqueues
  `201` with a valid `PromoCodeOut` JSON fixture (§5). Steps: call
  `PromoCodesApi.create(CreatePromoRequest("SUMMER25","percentage",
  discountValue=25, ...))`. Expected: request is `POST /ui/promo-codes`,
  `Content-Type: application/json`, body has `code`,`discount_type` and integer
  fields; response parses to `PromoCodeDto` with `codeId` populated; repo maps
  to `ApiResult.Ok`. Traces: AC-1, AC-3.

- **TC-AND-266-02 — List happy path, no query params (contract).** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `200`
  `PromoCodeListOut` with 2 items + `next_cursor: null`. Steps: call
  `PromoCodesApi.list()`. Expected: recorded request path is exactly
  `/ui/promo-codes` with NO `cursor`/`limit` query; both items deserialize;
  `nextCursor == null`. Traces: AC-2, AC-3.

- **TC-AND-266-03 — Create validation: missing/short code rejected client-side.**
  Type: unit (JVM). Target: JVM. Preconditions: ViewModel + fake repo.
  Steps: `onCreate` with blank code, then a 2-char code. Expected: no network
  call issued; `uiState.message` carries a validation error; submit stays
  disabled. Traces: AC-1.

- **TC-AND-266-04 — Server 422 validation maps to detail message.** Type:
  contract/MockWebServer + repo unit (JVM). Target: JVM. Preconditions: enqueue
  `422` with `{"detail":[{"loc":["body","code"],"msg":"ensure this value has at
  least 3 characters"}]}`. Steps: call `create`. Expected: repo returns
  `ApiResult.Error` whose message equals the joined `msg` (mirrors
  `normalizeErrorDetail` array branch); no crash. Traces: AC-1, AC-4.

- **TC-AND-266-05 — Redeem contract (internal body shape).** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue `200`
  `{"ok":true,"redeemed_at":1788307200}`. Steps: call `redeem(
  RedeemPromoRequest(codeId="pc_1", originalPriceCents=1000,
  finalPriceCents=750, checkoutType="subscription"))`. Expected: request is
  `POST /ui/promo-codes/redeem` with body containing `code_id`,
  `original_price_cents`, `final_price_cents`, `checkout_type` (NOT `code`);
  response parses to `RedeemPromoResponse(ok=true,...)`. Traces: AC-4.

- **TC-AND-266-06 — Deactivate contract.** Type: contract/MockWebServer (JVM).
  Target: JVM. Preconditions: enqueue `200` `PromoDeactivateOut
  {ok:true,code_id:"pc_1",active:false}`. Steps: call `deactivate("pc_1")`.
  Expected: request is `DELETE /ui/promo-codes/pc_1`; response parses; repo
  triggers a list re-fetch. Traces: AC-4.

- **TC-AND-266-07 — Repository: create/deactivate trigger list re-fetch.** Type:
  unit (JVM, Turbine). Target: JVM. Preconditions: fake API counting list
  calls. Steps: `listCodes()`, then `create(...)` success, then assert list
  re-fetched; repeat for `deactivate`. Expected: list re-fetched after each
  successful mutation (web parity: query invalidation). Traces: AC-1, AC-2, AC-4.

- **TC-AND-266-08 — Domain mapping: epoch + discount label + isExpired.** Type:
  unit (JVM). Target: JVM. Preconditions: DTOs with `expires_at=0` (never),
  a past epoch, and the three discount types. Steps: run `toDomain()` /
  label/format helpers. Expected: `expires_at=0` → "Never" and not expired;
  past epoch → expired; labels render `25% off`, `$7.50 off` (cents/100),
  `7-day trial`. Traces: AC-2.

- **TC-AND-266-09 — Auth headers attached on promo calls.** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: shared OkHttp
  client (AND-027) configured with a Bearer token + `ui_csrf` cookie. Steps:
  issue `create`. Expected: recorded request carries `Authorization: Bearer
  <token>` and `X-CSRF-Token` matching the cookie. (If AND-027 wiring is
  unavailable, mark blocked on AND-027.) Traces: AC-1, AC-7.

- **TC-AND-266-10 — 401 → single refresh → retry.** Type: contract/MockWebServer
  (JVM). Target: JVM. Preconditions: enqueue `401`, then a `200` for
  `/ui/session/refresh`, then a `201` for the retried create. Steps: call
  `create`. Expected: exactly one refresh, one retry, final `ApiResult.Ok`; a
  second consecutive `401` instead surfaces `Unauthorized` and signals logout.
  Traces: AC-1, AC-6.

- **TC-AND-266-11 — POSTs not auto-retried; GET list backoff; 20s timeout.**
  Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: server delays
  beyond timeout / returns 503. Steps: (a) `create` against a 503 — assert a
  single attempt (no auto-retry); (b) `list` against transient failure — assert
  bounded retries (≤3) per AND-027; (c) a >20s stall surfaces a timeout
  `ApiResult.Error`. Traces: AC-6.

- **TC-AND-266-12 — Compose list: empty, loading, error+retry states.** Type:
  Compose-UI (instrumented). Target: emulator `test35`. Preconditions: ViewModel
  fed empty list / loading / error states. Steps: render `PromoCodesScreen`;
  in error state tap Retry. Expected: empty placeholder, loading indicator, and
  error view with a working Retry that re-invokes the load; rows render with
  code/label/usage/status/expiry. Traces: AC-2, AC-5.

- **TC-AND-266-13 — Compose create flow + accessibility.** Type: Compose-UI
  (instrumented) + a11y checks. Target: emulator `test35`. Preconditions: fake
  repo returning `201`. Steps: tap Create FAB; enter code, pick each
  `discount_type` (incl. `free_trial` revealing the days field), toggle
  `applies_to`, submit. Expected: sheet validates required code, submit disabled
  while submitting, success banner, list refreshes; every actionable control has
  a non-empty `contentDescription`, touch targets ≥48dp, status conveyed by
  text+badge (not colour alone), enable AccessibilityChecks. Traces: AC-1, AC-5.

- **TC-AND-266-14 — Real-network smoke + ABI/API coverage (physical device).**
  Type: instrumented/e2e (manual-assisted). Target: **PHYSICAL Samsung Galaxy
  A15 5G (SM-A156U, API 34, arm64-v8a) — MUST run on device**, not emulator,
  to exercise the real flaky dev host (`http://18.222.237.167:8000`) over a
  real network and verify arm64-v8a/API-34 behavior vs emulator x86_64/API-35.
  Preconditions: authenticated session; cleartext exception covers the dev host.
  Steps: launch app → open Promo → create a code → confirm it appears in the
  list → toggle airplane mode and pull-to-refresh. Expected: create+list
  succeed against the live backend; offline shows the offline/error banner with
  retry while previously-loaded rows stay visible; on reconnect, retry succeeds;
  no ABI/API-specific crash. Traces: AC-1, AC-2, AC-5, AC-6.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (create → 201, appears, banner) | TC-01, TC-03, TC-04, TC-07, TC-09, TC-10, TC-13, TC-14 |
| AC-2 (list from GET /ui/promo-codes, rendering) | TC-02, TC-07, TC-08, TC-12, TC-14 |
| AC-3 (MockWebServer exact paths/verbs/bodies) | TC-01, TC-02 |
| AC-4 (redeem/deactivate + detail on rejection) | TC-04, TC-05, TC-06, TC-07 |
| AC-5 (empty/loading/error states) | TC-12, TC-13, TC-14 |
| AC-6 (no POST auto-retry; GET backoff; 20s timeout; 401) | TC-10, TC-11, TC-14 |
| AC-7 (no cookies/CSRF/full codes logged in release) | TC-09 (plus a release-log review; see §10) |
