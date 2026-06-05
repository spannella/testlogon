---
id: AND-266
title: Promo codes
milestone: M6
epic: E36
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-266 — Promo codes

## 1. Overview & Goal

This ticket delivers the Android client surface for **promo codes**: the data,
network, and presentation layers that let an authenticated TestLogon user (with
the appropriate role) **create**, **list**, and **redeem** promotional codes.
It is the native parity port of the web reference module
`frontend/src/api/endpoints/promoCodes.ts`.

The deliverable is end-to-end but intentionally bounded: a `PromoCodesApi`
Retrofit interface, a `PromoCodesRepository` that maps `ApiResult<T>`, a Hilt
module wiring, and a minimal Compose feature (`feature-promo`) exposing a list
screen and create/redeem flows backed by a `StateFlow<PromoCodesUiState>`
ViewModel. The authoritative acceptance bar from the backlog is narrow —
"Promo create/list works" — so redeem is implemented as a first-class path but
the gating MVP behaviour that must be demonstrably green is create + list.

Goal: a user can open the Promo screen, see a paged list of existing codes,
create a new code via a form, and redeem an existing code by its string value,
with all three operations resilient to the unreliable dev backend.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/promoCodes.ts` (CRUD-style
  surface), shared DTO shapes in `frontend/src/api/types.ts`.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — the `/promo-codes`
  tag is the source of truth for paths/verbs/bodies; this spec encodes the
  expected shapes but the implementer MUST diff against the live schema before
  freezing DTOs (see §13).
- **Auth dependency:** AND-027 (`AuthApi` + cookie/CSRF infrastructure). All
  promo endpoints are authenticated and ride the persistent cookie jar +
  `X-CSRF-Token` header established there. This ticket does **not** re-implement
  session handling; it consumes the configured `OkHttpClient`/`Retrofit`.
- **Module layering:** `app -> feature-promo -> core-*`
  (`core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 /
  OkHttp 4.12 / Moshi 1.15, Paging 3, Coroutines/Flow. `applicationId` /
  namespace base **`com.testlogon.android`**.

## 3. Functional Requirements

FR-1 **List.** The Promo screen displays existing promo codes, newest first,
paged (Paging 3) with `pageSize = 20`. Each row shows the code string, discount
summary, redemption count vs. max, active/expired badge, and expiry date.

FR-2 **Create.** A "New code" affordance opens a form capturing: `code`
(optional — server may auto-generate when blank), `discountType`
(`percentage` | `fixed`), `discountValue`, `maxRedemptions` (nullable =
unlimited), and `expiresAt` (nullable). Submitting POSTs the code; on success
the list invalidates and the new code appears at the top.

FR-3 **Redeem.** A "Redeem" action accepts a code string and POSTs a redemption.
On success the UI shows the resulting discount and increments the row's
redemption count (via list invalidation). On a domain rejection (expired,
exhausted, not found) the specific server `detail` message is surfaced.

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

```kotlin
@JsonClass(generateAdapter = true)
data class PromoCodeDto(
    @Json(name = "id") val id: String,
    @Json(name = "code") val code: String,
    @Json(name = "discount_type") val discountType: String,   // "percentage" | "fixed"
    @Json(name = "discount_value") val discountValue: Double,
    @Json(name = "max_redemptions") val maxRedemptions: Int?,  // null = unlimited
    @Json(name = "redemption_count") val redemptionCount: Int,
    @Json(name = "active") val active: Boolean,
    @Json(name = "expires_at") val expiresAt: String?,         // ISO-8601 UTC
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class PromoCodePage(
    @Json(name = "items") val items: List<PromoCodeDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
    @Json(name = "total") val total: Int?,
)

@JsonClass(generateAdapter = true)
data class CreatePromoRequest(
    @Json(name = "code") val code: String?,                    // null => server-generated
    @Json(name = "discount_type") val discountType: String,
    @Json(name = "discount_value") val discountValue: Double,
    @Json(name = "max_redemptions") val maxRedemptions: Int?,
    @Json(name = "expires_at") val expiresAt: String?,
)

@JsonClass(generateAdapter = true)
data class RedeemPromoRequest(@Json(name = "code") val code: String)

@JsonClass(generateAdapter = true)
data class RedeemPromoResponse(
    @Json(name = "code") val code: String,
    @Json(name = "discount_type") val discountType: String,
    @Json(name = "discount_value") val discountValue: Double,
    @Json(name = "redemption_count") val redemptionCount: Int,
)
```

A domain model `PromoCode` (in `core-model`) decouples UI from wire types; a
`PromoCodeDto.toDomain()` mapper parses `expiresAt`/`createdAt` to
`kotlinx.datetime.Instant?` and derives an `isExpired` flag against the device
clock.

**Repository (`core-data`):**

```kotlin
interface PromoCodesRepository {
    fun pagedCodes(): Flow<PagingData<PromoCode>>
    suspend fun create(request: CreatePromoRequest): ApiResult<PromoCode>
    suspend fun redeem(code: String): ApiResult<RedeemResult>
    suspend fun refreshList()   // invalidates the PagingSource
}
```

`pagedCodes()` is backed by a `Pager(PagingConfig(pageSize = 20, prefetchDistance = 5))`
whose `PromoCodePagingSource` calls `PromoCodesApi.list(cursor, limit)`. A held
`InvalidatingPagingSourceFactory` lets `refreshList()` force invalidation after
a successful create/redeem.

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
    fun onRedeem(code: String)                     // calls repo.redeem
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

**Compose surface:** `PromoCodesScreen(viewModel)` collects
`codes.collectAsLazyPagingItems()` into a `LazyColumn`; a FAB opens a Material 3
`ModalBottomSheet` create form; a top-bar action opens a redeem dialog. Nav
entry registered in app graph as route `promo` (Navigation-Compose), reachable
once the user is authenticated.

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
authenticated via cookies; mutations carry `X-CSRF-Token` (handled upstream).

```kotlin
interface PromoCodesApi {
    @GET("promo-codes")
    suspend fun list(
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = 20,
    ): Response<PromoCodePage>

    @POST("promo-codes")
    suspend fun create(@Body body: CreatePromoRequest): Response<PromoCodeDto>

    @POST("promo-codes/redeem")
    suspend fun redeem(@Body body: RedeemPromoRequest): Response<RedeemPromoResponse>
}
```

**List — `GET /promo-codes?cursor=&limit=20` → 200**

```json
{
  "items": [
    {
      "id": "pc_01HZ...",
      "code": "SUMMER25",
      "discount_type": "percentage",
      "discount_value": 25.0,
      "max_redemptions": 100,
      "redemption_count": 12,
      "active": true,
      "expires_at": "2026-09-01T00:00:00Z",
      "created_at": "2026-06-01T10:00:00Z"
    }
  ],
  "next_cursor": "eyJpZCI6...",
  "total": 37
}
```

**Create — `POST /promo-codes` → 201**, body `CreatePromoRequest`, returns a
single `PromoCodeDto`.

**Redeem — `POST /promo-codes/redeem` → 200**, body `{"code":"SUMMER25"}`,
returns `RedeemPromoResponse`.

**Errors (FastAPI `detail`):** the shared `ApiResult` mapper handles the three
`detail` shapes — `string`, `[{ "msg": ... }]` (422 validation), and
`{ "code": ... }`. Relevant statuses: `400/409` exhausted/expired/duplicate
code, `404` unknown code on redeem, `403` insufficient role, `422` invalid
form, `401` → upstream refresh-and-retry.

> NOTE: paths/verbs above MUST be diffed against `/openapi.json` before code
> freeze; if the live schema differs (e.g. `redeem` nested under
> `promo-codes/{id}`), update DTOs/paths and the MockWebServer fixtures here —
> no other module depends on these shapes.

## 6. Data & State Management

- **Source of truth:** the network. No Room persistence for promo codes in this
  ticket (low value, role-gated, mutable counts). Paging 3 holds the in-memory
  list; `DataStore` is not used here.
- **Paging:** cursor-based via `next_cursor`; `PromoCodePagingSource` returns
  `LoadResult.Page(data, prevKey = null, nextKey = page.nextCursor)`. End of
  pagination when `next_cursor == null`.
- **Invalidation:** after `create`/`redeem` success the repo calls
  `refreshList()` → `pagingSourceFactory.invalidate()`, causing the
  `LazyPagingItems` to refetch page 1.
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
  the client treats `403` as "not permitted" and hides the create FAB when
  `GET /ui/me` indicates the user lacks the promo-admin capability (best-effort;
  server remains the enforcer).
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

- **API (MockWebServer, `core-testing`):** assert `list` issues
  `GET /promo-codes?cursor=...&limit=20`; `create` issues `POST /promo-codes`
  with the exact JSON body; `redeem` issues `POST /promo-codes/redeem` with
  `{"code":...}`. Parse the §5 fixtures into DTOs. This is the direct mirror of
  AND-027's MockWebServer acceptance pattern and covers the backlog
  "create/list works" bar at the contract layer.
- **Repository (unit):** success → `ApiResult.Ok(domain)`; 409/404/422 →
  mapped `ApiResult.Error` with the correct `detail` message; verify
  `refreshList()` invalidates after create/redeem.
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

- **R1 (schema drift):** the exact promo endpoints are assumed from the web
  reference; the live `/openapi.json` may use different paths (e.g. redeem under
  `/{id}`), field names, or a non-cursor list. Mitigation: diff before freeze;
  DTOs are isolated to this feature.
- **R2 (auto-generated vs. user code):** unclear whether `code` is required on
  create. Spec treats it as optional/server-generated; confirm against schema.
- **R3 (role gating):** the capability flag on `GET /ui/me` that should hide the
  create FAB may not exist; fallback is to show the FAB and surface `403`.
- **R4 (dev host flakiness):** create/redeem are non-retryable POSTs on an
  unreliable host → users may double-submit. Mitigation: disable the submit
  button while `isSubmitting`, rely on server duplicate-code 409.
- **OQ:** does redeem require auth as the redeeming user, or is it an admin
  simulation? Affects whether redeem is exposed to all roles.

## 14. Acceptance Criteria

AC-1 (**authoritative**) Creating a promo code via the form results in a `201`,
the new code appears at the top of the list after invalidation, and a success
banner shows.

AC-2 (**authoritative**) The Promo screen lists existing codes paged from
`GET /promo-codes`, newest first, with correct discount/status/expiry rendering.

AC-3 MockWebServer tests confirm `list`, `create`, and `redeem` use the exact
paths, verbs, and JSON bodies in §5 (mirrors AND-027 acceptance).

AC-4 Redeeming a valid code returns the discount and increments the row's
redemption count after invalidation; redeeming an expired/exhausted/unknown code
surfaces the server `detail` message without crashing.

AC-5 Paging empty, initial-loading, append-loading, and error-with-retry states
each render correctly (verified by Compose tests).

AC-6 Non-idempotent POSTs are not auto-retried; GET list participates in the
shared bounded backoff; 20s timeouts apply.

AC-7 No cookies/CSRF token/full codes logged at `INFO`+ in release builds.

## 15. Definition of Done

- `feature-promo` module builds under AGP 8.7.3 / Gradle 8.9 / JDK 17, namespace
  `com.testlogon.android.feature.promo`.
- `PromoCodesApi`, DTOs, `PromoCodesRepository`, `PromoCodePagingSource`,
  `PromoCodesViewModel`, and `PromoCodesScreen` implemented and Hilt-wired.
- AC-1…AC-7 met; all unit/MockWebServer/Compose tests green in CI; coverage
  target met.
- DTO shapes reconciled against `/openapi.json` (R1/R2 resolved) and any
  divergences reflected in code + fixtures.
- No new lint/detekt errors; strings localized; accessibility semantics present.
- Code reviewed and merged to `android-port`.
