---
id: AND-267
title: Affiliate discounts
milestone: M6
epic: E36
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-265]
blocks: []
---

# AND-267 — Affiliate discounts

## 1. Overview & Goal

Add an **Affiliate Discounts** surface to the TestLogon native Android app that
renders the affiliate/promo discounts that have been **attached to the user's ad
creatives** through the affiliate program. The data is sourced from the web
reference's `adCreativeAffiliate` endpoints
(`src/api/endpoints/adCreativeAffiliate.ts`, `BASE = "/ui/ads/affiliate"`) — i.e.
the affiliate *ad-creative* discount records. **VERIFIED SHAPE (corrected from an
earlier assumption):** each record is keyed by `creative_id` and carries an
optional `affiliate_code` (affiliate tracking code), an optional `promo_code` +
`promo_value_display` (the badge text, e.g. "20% OFF"), an optional
`click_through_url`, attribution counters `click_count` / `redemption_count`, and
`created_at` / `updated_at` (epoch seconds). There is **no** per-discount value
catalog (no percent/amount/currency/free-trial fields), **no** validity window
(`starts_at`/`ends_at`), **no** redemption cap, **no** `enabled` flag, and **no**
`share_url` field on the wire — see §5 and §16. The "share link" surfaced by this
ticket is the affiliate `click_through_url` (or the affiliate redirect built from
`affiliate_code`), not a server `share_url`.

This ticket owns **consumption and presentation** of affiliate discounts. It does
**not** own the affiliates networking/DTO base or the dashboard shell — that is
**AND-265** (`affiliates.ts`; links + earnings), the hard dependency that supplies
the `feature-affiliates` module, the `AffiliateApi` Retrofit interface, the shared
cookie client wiring, and the `Affiliate*` domain models this ticket extends. Promo
code create/list/redeem is a separate surface owned by **AND-266** (`promoCodes.ts`)
and is explicitly out of scope here.

Goal: from the Affiliates area, a user can open a **Discounts** tab/screen and see
a list of attached ad-creative affiliate discounts — each showing its `creative_id`,
the affiliate/promo codes, the promo badge text (`promo_value_display`), attribution
counts (clicks / redemptions), and a copy/share action for the affiliate code or
`click_through_url` — backed by `ApiResult<T>`, Room-cached for offline/stale, and
verified by unit + Compose UI tests.

Success = **Discounts render** (the source acceptance bullet), correctly formatted,
with offline tolerance, and covered by CI tests.

## 2. Context & References

- **Repo:** `spannella/testlogon`, branch `android-port`, app under `android/`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Feature module:** `feature-affiliates` (created by AND-265; shared with AND-264
  referrals-adjacent and AND-266 promo where relevant).
- **Web reference (CORRECTED):** the ad-creative affiliate discount calls live in
  `src/api/endpoints/adCreativeAffiliate.ts` (NOT `affiliates.ts` — that file owns
  links/earnings for AND-265). Shared types in `src/api/types.ts` are
  `AdAffiliateDiscount`, `AdAffiliateDiscountList`, `AdAffiliateStats`,
  `AdAffiliateClickResult`, `AdAffiliateRedeemResult` (there is **no**
  `AffiliateDiscount`, `DiscountKind`, `AffiliateDiscountList`, or
  `AdCreativeAffiliate` type — those names were assumed and are wrong). The web
  view is `src/pages/ads/AdAffiliateDiscountPage.tsx`; note it is an
  **owner/management** screen (attach/remove/stats), so use it for label/format
  parity but not 1:1 behavior parity (this Android ticket is read-only display).
- **Backend:** FastAPI + DynamoDB, OpenAPI at `/openapi.json`; dev host
  `http://18.222.237.167:8000` (plaintext HTTP, unreliable — design for ~20s
  timeouts, bounded retry of idempotent GETs only, offline/stale UI states).
- **Upstream dependency:** **AND-265** supplies `AffiliateApi`, the affiliate DTO
  base, `ApiResult<T>` mapping, and the dashboard navigation entry into which this
  Discounts surface is hung. If AND-265's wire field names differ at integration,
  AND-265 is authoritative and this spec's DTO names are adjusted to match.
- **Auth (VERIFIED against `src/api/client.ts` + openapi index):** cookie-based
  session (`POST /ui/session/start` → MFA → `POST /ui/session/finalize` →
  `GET /ui/me`); the `ui_csrf` cookie is echoed as the `X-CSRF-Token` header **on
  every request, including GETs** (confirmed in `client.ts`). The web client ALSO
  sends `Authorization: Bearer <accessToken>` when an access token is present and may
  send `X-IMPERSONATION-TOKEN`; the Android client should reuse AND-265's shared
  client wiring rather than re-deriving these. On 401 (only when already
  authenticated) the client does **one** `POST /ui/session/refresh` then retries the
  original request once; a second 401 logs out. Discount GETs ride that shared
  client; this ticket adds **no** auth logic. (Note: the `/ui/ads/affiliate/*`
  endpoints additionally take `user_sub` + `X-SESSION-ID` params per the OpenAPI
  index; these are injected by the shared transport layer, not by this feature.)

## 3. Functional Requirements

> **Review note (model corrected):** FR-1…FR-3 were written against an assumed
> per-code value/validity catalog (`code`/`kind`/value/expiry/`used/max`). The
> **verified** wire shape (§5/§16) has no `kind`, no value fields, no validity
> window, and no redemption cap — only `affiliate_code`, `promo_code`,
> `promo_value_display` (free-text badge), `click_through_url`, `click_count`,
> `redemption_count`, and `created_at`/`updated_at` epoch ints. The requirements
> below are retained but must be implemented against that real shape: "value"
> renders `promo_value_display` verbatim; "code" is `promo_code` (and/or
> `affiliate_code`); there is no expiry/`max` to render; `DiscountKind`/status are
> **client-derived, best-effort** (R3/R5 are now resolved as "no server field").

FR-1 — **Discounts list.** Display affiliate discounts in a `LazyColumn`. Each row
shows: the discount **code**, the **value** (e.g. "20% off" or "$5.00 off"), the
**scope** (creator/product/site-wide label), the **validity window** (active /
"Expires {date}" / "Expired"), and a redemption/usage hint when supplied
(`used / max`). An affiliate-attributed link/code is exposed for sharing.

FR-2 — **Discount kinds.** Map every backend kind to a typed `DiscountKind` enum
and format the value accordingly: `PERCENT` (value rendered as `n%`), `FIXED`
(rendered as localized currency from minor units), `FREE_TRIAL` (rendered as a
duration). Any unknown wire value maps to `UNKNOWN` and renders the raw
server-provided display string without crashing.

FR-3 — **Status / validity.** Derive an `AffiliateDiscountStatus`
(`ACTIVE`, `SCHEDULED`, `EXPIRED`, `EXHAUSTED`, `DISABLED`) from
`starts_at`/`ends_at`/`max_redemptions`/`enabled`, and render a color-coded chip
with icon + localized label. Status is computed client-side from the fields if the
backend does not return an explicit status.

FR-4 — **Copy & share.** Each row has a **Copy code** action (clipboard) for
`promo_code` (or `affiliate_code` when no promo code) and a **Share link** action
that shares the affiliate-attributed `click_through_url` via the Android share sheet.
(There is no server `share_url` field — corrected; use `click_through_url`.) If
`click_through_url` is absent, fall back to sharing the available code text.

FR-5 — **Empty / loading / error / offline states.** First-load shimmer; a distinct
empty state ("No affiliate discounts yet"); a full-screen error with Retry on
first-load failure; a "Showing saved data" stale banner when serving cache while
offline.

FR-6 — **Pull-to-refresh** re-fetches the discount list.

FR-7 — **Detail (lightweight).** Tapping a row opens a bottom sheet (or detail
route) showing the full breakdown: code, value, kind, scope/target name, full
validity window with absolute timestamps, redemption counts, terms/description text
(if provided), and the copy/share actions. No edit/create actions.

FR-8 — **Read-only.** This ticket performs no mutations (no create/disable/redeem).
Redemption belongs to AND-266 (promo codes) and is out of scope.

FR-9 — **Filter (optional).** A kind/status chip-row filter applied client-side
over the loaded list (the dataset is small and fully fetched; no server paging
assumed). Ships only if it does not complicate the acceptance gate; otherwise
deferred per §13.

## 4. Technical Design

Module: `feature-affiliates`. Layering `app -> feature-affiliates -> core-*`. MVVM
with `StateFlow<UiState>`. Networking/DTOs and the `AffiliateApi` base come from
AND-265 in `core-network`/`core-model`; this ticket adds the discounts endpoint
methods, models, mapper, repository surface, ViewModel, and Compose UI.

Navigation (single-Activity Navigation-Compose, type-safe routes):

```kotlin
sealed interface AffiliateRoute {
    @Serializable data object Dashboard : AffiliateRoute   // AND-265
    @Serializable data object Discounts : AffiliateRoute   // this ticket
    @Serializable data class DiscountDetail(val discountId: String) : AffiliateRoute
}

fun NavGraphBuilder.affiliateDiscountsGraph(nav: NavController) {
    composable<AffiliateRoute.Discounts> {
        AffiliateDiscountsScreen(
            onDiscountClick = { nav.navigate(AffiliateRoute.DiscountDetail(it)) },
        )
    }
    composable<AffiliateRoute.DiscountDetail> { AffiliateDiscountDetailScreen(onBack = { nav.popBackStack() }) }
}
```

Domain models (`core-model`) — **CORRECTED to the verified `AdAffiliateDiscountOut`
shape** (§5/§16). The previous model (`id`/`kind`/`percentBps`/`amountMinor`/
`startsAt`/`endsAt`/`maxRedemptions`/`enabled`/`shareUrl`/`description`) was
fabricated and is replaced:

```kotlin
// No server "kind"; this is a best-effort client-derived bucket for chip styling
// parsed from promo_value_display (e.g. "20% OFF" -> PERCENT). Not authoritative.
enum class DiscountKind { PERCENT, FIXED, FREE_TRIAL, UNKNOWN }

data class AffiliateDiscount(
    val creativeId: String,        // primary key (no separate discount id exists)
    val campaignId: String,
    val ownerSub: String,
    val affiliateCode: String?,    // affiliate tracking code (nullable)
    val promoCode: String?,        // promo code (nullable)
    val promoValueDisplay: String?,// free-text badge, rendered verbatim (e.g. "20% OFF")
    val clickThroughUrl: String?,  // affiliate landing link to share (nullable)
    val clickCount: Int,           // defaults to 0
    val redemptionCount: Int,      // defaults to 0
    val createdAt: Instant,        // from created_at epoch seconds
    val updatedAt: Instant,        // from updated_at epoch seconds
) {
    // Best-effort, derived from promoValueDisplay; NOT a server field.
    val derivedKind: DiscountKind get() = deriveKind(promoValueDisplay)
}
```

> **Removed:** `AffiliateDiscountStatus` (ACTIVE/SCHEDULED/EXPIRED/EXHAUSTED/
> DISABLED) and `computeStatus` — the wire has no `starts_at`/`ends_at`/
> `max_redemptions`/`enabled`, so no validity/status can be computed. FR-3 and the
> status-chip work are descoped to "no status chip" (or a static "Active" badge if
> product still wants one); see §16 Corrections.

Repository (extends AND-265's affiliate repo; SWR / single-source-of-truth):

```kotlin
interface AffiliateDiscountRepository {
    fun discounts(forceRefresh: Boolean = false): Flow<ApiResult<List<AffiliateDiscount>>>
    // keyed by creative_id; backed by GET /ui/ads/affiliate/creatives/{creativeId}/discount
    suspend fun discount(creativeId: String): ApiResult<AffiliateDiscount>
}
```

Implementation: Room is the backing cache; `discounts()` emits cached rows
immediately (if any) then triggers a network refresh that upserts and re-emits.
On network failure with cache present, emit cached + `stale=true` flag (carried in
the UI state, see §6). Discount detail reads from Room then refreshes the single
row.

ViewModel:

```kotlin
@HiltViewModel
class AffiliateDiscountsViewModel @Inject constructor(
    private val repo: AffiliateDiscountRepository,
) : ViewModel() {

    private val filter = MutableStateFlow<DiscountKind?>(null)
    private val refresh = MutableSharedFlow<Boolean>(replay = 1).apply { tryEmit(false) }

    val uiState: StateFlow<DiscountsUiState> =
        combine(refresh.flatMapLatest { repo.discounts(it) }, filter) { result, k ->
            result.toUiState(filterKind = k)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DiscountsUiState.Loading)

    fun onRefresh() { refresh.tryEmit(true) }
    fun setFilter(k: DiscountKind?) { filter.value = k }
    fun shareUrlFor(id: String): String? = /* current state lookup */ TODO()
}

sealed interface DiscountsUiState {
    data object Loading : DiscountsUiState
    data object Empty : DiscountsUiState
    data class Content(val items: List<AffiliateDiscountUi>, val stale: Boolean) : DiscountsUiState
    data class Error(val message: String, val retryable: Boolean) : DiscountsUiState
}
```

Compose: `AffiliateDiscountsScreen(state, onRefresh, onCopy, onShare, onClick)`
renders `DiscountRow` items wrapped in `PullToRefreshBox`, driving
loading/empty/error/stale off `DiscountsUiState` and the shared `core-ui` state
composables (AND-021). `AffiliateDiscountStatusChip(status)` is a `core-ui`-style
chip mapping status → (container color, label, icon). `DiscountValueText` formats
percent/fixed/free-trial. Copy uses `ClipboardManager`; share uses an
`ACTIONSEND` intent built in the screen layer (no business logic in the ViewModel).

## 5. API Contract

Endpoints are owned/typed by **AND-265**; this ticket pins the discount shapes it
relies on. All are authenticated GETs riding the shared client (cookie session +
`X-CSRF-Token`). The contract below is **VERIFIED** against the OpenAPI index and
`components.schemas.AdAffiliateDiscountOut` / `AdAffiliateDiscountListOut`, and
against `src/api/endpoints/adCreativeAffiliate.ts` + `src/api/types.ts`. The
earlier `/ui/affiliates/discounts` path, the per-`{id}` detail route, and the
`kind`/`percent_bps`/`amount`/validity-window JSON were all **incorrect** and are
corrected here (see §16).

**List** `GET /ui/ads/affiliate/discounts`
(op `list_discounts_ui_ads_affiliate_discounts_get`, resp `200:AdAffiliateDiscountListOut`).
Returns the affiliate/promo discounts attached to the caller's ad creatives:

```json
{
  "items": [
    {
      "creative_id": "cr_01HF...",
      "campaign_id": "camp_01HF...",
      "owner_sub": "user_abc",
      "affiliate_code": "ABC12345",
      "promo_code": "SUMMER20",
      "promo_value_display": "20% OFF",
      "click_through_url": "https://shop.com/sale",
      "click_count": 137,
      "redemption_count": 12,
      "created_at": 1746057600,
      "updated_at": 1748736000
    }
  ]
}
```

Field notes (from `AdAffiliateDiscountOut`): `creative_id`, `campaign_id`,
`owner_sub` are **required**; `affiliate_code`, `promo_code`, `promo_value_display`,
`click_through_url` are nullable; `click_count`, `redemption_count`, `created_at`,
`updated_at` default to `0`. **Timestamps are epoch integers (seconds), not ISO-8601
strings.** There is **no** discount `id`, `kind`, `percent_bps`, `amount`,
`currency`, `free_trial_days`, `display_value`, `scope_label`, `target_type`,
`starts_at`, `ends_at`, `max_redemptions`, `enabled`, `share_url`, or `description`
field on the wire. The list item key for UI/Room is `creative_id`.

**Detail:** there is **no** `GET /ui/affiliates/discounts/{discount_id}`. The only
single-record GET is `GET /ui/ads/affiliate/creatives/{creative_id}/discount`
(op `get_discount_...`, resp `200:AdAffiliateDiscountOut`), keyed by
**`creative_id`** and returning the same `AdAffiliateDiscountOut` shape. The Android
detail/sheet (FR-7) should fetch by `creative_id` via this endpoint, or simply
reuse the already-loaded list row (the list already contains every field).

**Out of scope but in the same namespace** (do NOT call from this read-only ticket):
`POST/PATCH/DELETE /ui/ads/affiliate/creatives/{creative_id}/discount`
(attach/update/remove), `GET /ui/ads/affiliate/creatives/{creative_id}/stats`
(`AdAffiliateStatsOut`), `POST /ui/ads/affiliate/redeem` (`AdAffiliateRedeemOut`),
and `GET /ui/ads/affiliate/click/{creative_id}/preview` (`AdAffiliateClickResult`).
Redemption (`/redeem`) and promo create/list are AND-266 territory.

There is **no** typed discount "kind" enum on the wire — value display is the
free-text `promo_value_display` string (the web renders it verbatim as a badge,
see `AdAffiliateDiscountPage.tsx` `PromoBadge`). The Android UI should likewise
render `promo_value_display` verbatim. If a `DiscountKind`-style enum is desired
for chips it must be **derived client-side** from `promo_value_display` heuristics
and treated as best-effort, not authoritative.

Retrofit (added on AND-265's `AffiliateApi`):

```kotlin
interface AffiliateApi {            // base from AND-265
    @GET("ui/ads/affiliate/discounts")
    suspend fun adAffiliateDiscounts(): AdAffiliateDiscountListDto

    // detail is keyed by creative_id, not a discount id
    @GET("ui/ads/affiliate/creatives/{creativeId}/discount")
    suspend fun adAffiliateDiscount(@Path("creativeId") creativeId: String): AdAffiliateDiscountDto
}
```

Errors: the documented error response is `422 HTTPValidationError`. FastAPI `detail`
mapping (string | `[{msg}]` | `{code,...}`) is handled by the shared `ApiResult`
mapper (parity with `normalizeErrorDetail` in `client.ts`, which also maps
`{code: "role_required*"|"geo_blocked"|...}` objects to friendly text). 401 ⇒ one
session refresh + retry (shared authenticator). 403 ⇒ render the dedicated
not-enrolled / no-access state. A 404 on the per-creative detail ⇒ "Discount not
found". (Whether non-affiliate access returns 403 vs an empty `items` list is not
documented in the OpenAPI spec — see §16 Open assumptions.)

## 6. Data & State Management

**Room** (cache; DataStore is for prefs only and unused here). **CORRECTED to the
verified wire shape** (§5/§16):

```kotlin
@Entity(tableName = "affiliate_discount")
data class AffiliateDiscountEntity(
    @PrimaryKey val creativeId: String,   // no separate discount id on the wire
    val campaignId: String,
    val ownerSub: String,
    val affiliateCode: String?,
    val promoCode: String?,
    val promoValueDisplay: String?,
    val clickThroughUrl: String?,
    val clickCount: Int,
    val redemptionCount: Int,
    val createdAtEpoch: Long,     // created_at (epoch seconds)
    val updatedAtEpoch: Long,     // updated_at (epoch seconds)
    val sortSeq: Int,             // server response order (items[] index)
    val fetchedAtEpoch: Long,     // local fetch time for TTL
)
```

`AffiliateDiscountDao` exposes `Flow<List<AffiliateDiscountEntity>>` ordered by
`sortSeq ASC` plus a single-row `suspend fun byCreativeId(creativeId)`. Refresh path replaces the
whole table in a transaction (the list is small and fully fetched each refresh — no
paging). `fetchedAtEpoch` drives a TTL (default 5 min) used by the SWR repo to
decide background refresh; stale-but-present cache is shown immediately.

**State:** `DiscountsUiState` (§4) is derived from `ApiResult<List<AffiliateDiscount>>`:
`Success(empty)` → `Empty`; `Success(items)` → `Content(items, stale=false)`;
`Error` with cache present → `Content(cached, stale=true)`; `Error` with no cache →
`Error`. **Value display is the verbatim `promo_value_display` string** (no
client-side currency/percent math, since the wire carries no numeric value/currency
fields). `created_at`/`updated_at` are epoch seconds → `Instant`; render via
locale-aware `DateTimeFormatter` only as "Created {date}" / "Updated {date}" (no
expiry exists). The optional `derivedKind` (parsed from `promo_value_display`) only
drives chip styling/icon and is best-effort.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the shared OkHttp ~20s call timeout (dev host is slow).
- **Retry:** list/detail are idempotent GETs ⇒ bounded backoff (max 2 retries,
  250ms → ~1s with jitter) via the shared interceptor (AND-016). No retry on 4xx.
- **401:** shared authenticator does one `POST /ui/session/refresh` then retries; if
  refresh fails, this screen shows a generic "Session expired" error with Retry
  (re-auth UI is owned by the auth feature).
- **403 (non-affiliate):** render a dedicated "Not enrolled in affiliate program"
  empty/error state rather than a generic error.
- **Offline / refresh fails but cache exists:** show cached list + persistent
  "Showing saved data" banner; pull-to-refresh re-attempts.
- **Offline / no cache:** full-screen error with Retry.
- **Unknown `kind`:** map to `UNKNOWN`, render `display_value` verbatim, never throw.
- **Malformed JSON / null required field:** Moshi failure → mapped `ApiResult.Error`;
  treated as a load error, not a crash.
- **Copy/share with missing `click_through_url`:** disable Share or fall back to
  sharing the code text; never crash on a null intent payload.

## 8. Security & Privacy

- All requests are authenticated GETs over the shared cookie jar; no affiliate
  payout credentials or PII are requested or stored — only discount metadata,
  codes, and a shareable affiliate link.
- `share_url` is an affiliate-attributed referral link intended for sharing; it is
  user-shareable by design. Do **not** log it at `INFO`; treat the discount `code`
  as low-sensitivity but avoid emitting it in analytics payloads (hash the id
  instead).
- Room holds discount metadata + codes + share URLs; acceptable for cache. No
  tokens/secrets persisted by this feature (session lives in the cookie jar / OS
  store).
- `X-CSRF-Token` header attached by the shared interceptor; GETs are non-mutating.
- Plaintext HTTP is a **dev-only** constraint inherited from the backend; production
  base URL must be HTTPS (enforced by app config, not this ticket). Do not log full
  URLs containing referral tokens.

## 9. Accessibility & i18n

- Status chips provide a `contentDescription` with the spoken status ("Status:
  Active"); never rely on color alone — each status has a distinct icon + label.
- Copy and Share actions are real focusable controls with `contentDescription`
  ("Copy code CREATOR20", "Share discount link"); after Copy, announce a Snackbar /
  live-region confirmation ("Code copied").
- All strings in `strings.xml`: status labels, kind labels, empty/error/banner copy,
  "Expires {date}", "Expired", redemption count ("{count} of {max} used"). Use
  plurals (`quantityString`) for free-trial days and redemption counts.
- Values/dates localized: `NumberFormat` for currency, `n%` via locale-aware percent
  formatting, `DateTimeFormatter` with device locale and zone for windows.
- Touch targets ≥ 48dp; each row exposes a merged semantics node combining
  code/value/status/expiry for TalkBack; copy/share remain independently actionable.
- RTL-ready (AND-114): no hardcoded start/end paddings; mirror chevrons.

## 10. Telemetry & Logging

- Analytics (shared analytics in `core-data`): `affiliate_discounts_viewed`,
  `affiliate_discounts_refreshed`, `affiliate_discount_detail_viewed {discount_id_hash, kind, status}`,
  `affiliate_discount_code_copied {discount_id_hash}`,
  `affiliate_discount_link_shared {discount_id_hash}`,
  `affiliate_discounts_load_failed {code}`. Hash ids; never send raw codes or
  share URLs.
- Logging: `Timber` (debug only) for load-state transitions and refresh results
  (item count, stale flag) — **no codes, no share URLs, no PII** in logs. Network
  logging via the shared OkHttp logging interceptor (BODY in debug builds only).

## 11. Testing Strategy

Use `core-testing` (MockWebServer, Turbine, coroutine test rules, Compose test).

- **Unit — DTO/mapping:** discount JSON → `AffiliateDiscount` for each kind
  (`percent`, `fixed`, `free_trial`) and unknown kind → `UNKNOWN` rendering
  `display_value`. Assert percent-from-bps, fixed currency formatting, and
  free-trial duration formatting.
- **Unit — status computation:** `computeStatus` covers ACTIVE (now within window,
  redemptions remaining, enabled), SCHEDULED (`starts_at` future), EXPIRED
  (`ends_at` past), EXHAUSTED (`redemption_count >= max_redemptions`), DISABLED
  (`enabled=false`). Boundary cases at exactly `starts_at`/`ends_at`.
- **Unit — Repository (SWR):** cache-then-network emits cached first then refreshed;
  network error with cache → `stale=true` content; no cache + error → error; detail
  404 → not-found.
- **Unit — ViewModel:** Turbine on `uiState` covering Loading → Content,
  Content → stale, Empty, Error → Retry; filter re-applies client-side.
- **UI (Compose) — list:** renders rows with correct value text, status chip
  text/desc, and expiry label; empty state; first-load error + Retry; stale banner;
  pull-to-refresh triggers refetch (verify via MockWebServer request count). Copy
  action writes to clipboard and shows confirmation; Share action launches the share
  intent (verify via Espresso-Intents / intent capture).
- **UI — detail:** opens with full breakdown including redemption counts and
  description; back navigation works.
- **Acceptance gate:** "Discounts render" verified by the list UI test asserting a
  known fixture's value + status chips are displayed.

## 12. Dependencies & Sequencing

- **Depends on AND-265** (Affiliates dashboard / `affiliates.ts`): supplies
  `feature-affiliates`, `AffiliateApi` base, affiliate DTO/`ApiResult` mapping, and
  the dashboard nav entry that hosts the Discounts tab/route. **Hard blocker** for
  integration; Compose/ViewModel work may proceed in parallel against a stub
  `AffiliateDiscountRepository`.
- **Indirect:** AND-027 (transitively via AND-265) for the base Retrofit/OkHttp +
  persistent cookie jar (AND-011) + CSRF interceptor (AND-012) + 401 refresh
  authenticator (AND-013) + retry/backoff (AND-016); core-ui state composables
  (AND-021); i18n/RTL plumbing (AND-111/AND-114).
- **Siblings (not blockers):** AND-266 (promo codes) — keep discount *display* here
  distinct from promo create/list/redeem there; AND-264 (referrals) shares the
  affiliate area. Coordinate to avoid duplicate `DiscountKind`/chip definitions.
- **Blocks:** none recorded.
- Sequence: AND-265 merged → add discount API methods + models/Room + mapper →
  repository (SWR) → ViewModel → Compose (list + detail/sheet) → tests.

## 13. Risks & Open Questions

- **R1 — Value/units shape. RESOLVED.** There are no numeric value/percent/amount
  fields on the wire; "value" is the free-text `promo_value_display` string. No bps
  or minor-unit mapping is needed (the earlier assumption was wrong — see §16).
- **R2 — Endpoint path. RESOLVED.** Verified path is `GET /ui/ads/affiliate/discounts`
  (list) and `GET /ui/ads/affiliate/creatives/{creative_id}/discount` (single, keyed
  by creative_id). The assumed `/ui/affiliates/discounts` and `/{discount_id}` detail
  do not exist. Path is centralized in `AffiliateApi`.
- **R3 — Explicit vs computed status. RESOLVED.** No `status` and no validity fields
  exist on the wire, so no status can be computed; status chips are descoped.
- **R4 — Pagination.** `AdAffiliateDiscountListOut` is a bare `{items: [...]}` with
  no cursor/total fields, so no server paging is exposed today. If the backend later
  paginates, add cursor handling (mirror AND-260's mediator) — flagged, not assumed.
- **R5 — Free-trial representation. RESOLVED.** No `free_trial_days` field exists;
  any "free trial" semantics would be embedded in `promo_value_display` text only.
- **R6 — Non-affiliate access.** *Still open:* the OpenAPI spec documents only
  `200` and `422` for the list endpoint; whether a non-enrolled user gets `403` vs
  an empty `items` list is not specified. §7 handles both defensively. Confirm with
  AND-265 / backend.
- **R7 — Dev host flakiness** may cause noisy refresh errors; covered by retry +
  stale-cache banner.

## 14. Acceptance Criteria

AC-1 — Opening the Affiliate **Discounts** surface shows a list where each row
renders the code, a correctly formatted **value** (percent / fixed currency /
free-trial), scope label, validity/expiry label, and a **status chip** with correct
label/color/icon (satisfies source acceptance "Discounts render").

AC-2 — All three known kinds (`PERCENT`, `FIXED`, `FREE_TRIAL`) format correctly;
an unknown kind renders the server `display_value` verbatim without crashing.

AC-3 — Status is correct for ACTIVE / SCHEDULED / EXPIRED / EXHAUSTED / DISABLED,
including window boundary cases.

AC-4 — Copy writes the code to the clipboard and shows a confirmation; Share opens
the Android share sheet with the affiliate `share_url` (or code fallback when
absent).

AC-5 — Tapping a row opens the detail/bottom sheet with the full breakdown
(code, value, kind, scope/target, full window, redemption counts, description) and
copy/share actions.

AC-6 — With cached data and no network, the list shows cached entries plus a
"Showing saved data" banner; with no cache and no network, a full-screen Retry error
is shown; non-affiliate (403) shows the dedicated not-enrolled state.

AC-7 — Pull-to-refresh re-fetches the list (verified by request count in tests).

AC-8 — Status/kind chips expose TalkBack `contentDescription`; all user-facing
strings come from `strings.xml`; values/dates are locale-formatted; copy/share are
accessible controls.

AC-9 — All §11 unit and UI tests pass in CI.

## 15. Definition of Done

- Code merged to `android-port` under `feature-affiliates`, package
  `com.testlogon.android`, building on Kotlin 2.0.21 / AGP 8.7.3 / compileSdk 35 /
  JDK 17.
- Discounts list + detail/sheet implemented per §3–§6; discount API methods added to
  AND-265's `AffiliateApi`; SWR repository + Room cache wired.
- All §11 tests written and green; ktlint/detekt clean; no new lint errors.
- Telemetry events (§10) emitted with hashed ids; no codes/share URLs/PII in logs.
- Accessibility checks (§9) pass (TalkBack spot-check + automated semantics test).
- AC-1…AC-9 demonstrably met; PR links this ticket and AND-265.
- Open questions in §13 either resolved against `/openapi.json` / `types.ts` or
  explicitly ticketed as follow-ups (esp. R1 units, R2 endpoint path, R4 pagination).

## 16. Citations & Assumption Audit

Each key technical claim below lists the **claim**, a **VERDICT** (Verified /
Corrected / Unverified-assumption), and the **SOURCE** (OpenAPI `METHOD /path`
and/or schema name, or a frontend path, or a framework ref).

1. **List endpoint is `GET /ui/ads/affiliate/discounts`.** VERDICT: Corrected (spec
   originally said `GET /ui/affiliates/discounts`). SOURCE: OpenAPI index
   `GET /ui/ads/affiliate/discounts` (op `list_discounts_ui_ads_affiliate_discounts_get`,
   resp `200:AdAffiliateDiscountListOut`); `src/api/endpoints/adCreativeAffiliate.ts:
   listAdAffiliateDiscounts` (`${BASE}/discounts`, `BASE="/ui/ads/affiliate"`).

2. **There is NO `GET /ui/affiliates/discounts/{discount_id}` detail route.**
   VERDICT: Corrected. SOURCE: OpenAPI index — the only single-record GET is
   `GET /ui/ads/affiliate/creatives/{creative_id}/discount`
   (op `get_discount_...`, resp `200:AdAffiliateDiscountOut`); no `{discount_id}`
   path exists. `src/api/endpoints/adCreativeAffiliate.ts: getAdAffiliateDiscount`
   confirms the key is `creativeId`.

3. **The discount DTO is `AdAffiliateDiscountOut`** with fields `creative_id`,
   `campaign_id`, `owner_sub` (required), `affiliate_code?`, `promo_code?`,
   `promo_value_display?`, `click_through_url?`, `click_count`, `redemption_count`,
   `created_at`, `updated_at`. VERDICT: Corrected (the spec's
   `id`/`code`/`kind`/`percent_bps`/`amount`/`currency`/`free_trial_days`/
   `display_value`/`scope_label`/`target_type`/`starts_at`/`ends_at`/
   `max_redemptions`/`enabled`/`share_url`/`description` shape was fabricated; none
   of those fields exist). SOURCE: `components.schemas.AdAffiliateDiscountOut`
   (openapi.pretty.json, required=[creative_id,campaign_id,owner_sub]);
   `src/api/types.ts: AdAffiliateDiscount` (lines 10610–10622).

4. **List response wrapper is `{ items: AdAffiliateDiscount[] }` with no
   cursor/total (no pagination).** VERDICT: Verified. SOURCE:
   `components.schemas.AdAffiliateDiscountListOut` (single `items` array);
   `src/api/types.ts: AdAffiliateDiscountList`.

5. **Timestamps `created_at`/`updated_at` are epoch integers, not ISO-8601.**
   VERDICT: Corrected (spec used ISO strings in `starts_at`/`ends_at`). SOURCE:
   `AdAffiliateDiscountOut` (`created_at`/`updated_at` `type: integer`, default 0);
   `src/api/types.ts` (`created_at: number; updated_at: number`).

6. **No typed discount "kind" / no numeric value fields exist on the wire; value is
   the free-text `promo_value_display` rendered verbatim.** VERDICT: Corrected
   (spec's `DiscountKind` PERCENT/FIXED/FREE_TRIAL + bps/minor-units was assumed).
   SOURCE: `AdAffiliateDiscountOut` (no kind/value fields);
   `src/pages/ads/AdAffiliateDiscountPage.tsx` renders `promo_value_display` verbatim
   via `PromoBadge`.

7. **No validity window / `max_redemptions` / `enabled` ⇒ no server status; status
   chips descoped.** VERDICT: Corrected (spec's `AffiliateDiscountStatus` +
   `computeStatus` had no backing fields). SOURCE: `AdAffiliateDiscountOut`
   (absence of `starts_at`/`ends_at`/`max_redemptions`/`enabled`).

8. **Auth: cookie session + `X-CSRF-Token` (from `ui_csrf` cookie) on every request
   including GETs; one `POST /ui/session/refresh` + retry on 401-while-authenticated.**
   VERDICT: Verified. SOURCE: `src/api/client.ts` (sets `X-CSRF-Token` from
   `getCookie("ui_csrf")` unconditionally; `refreshSession()` →
   `POST /ui/session/refresh`; 401 path refreshes once then retries, second 401
   logs out); OpenAPI index `POST /ui/session/refresh`.

9. **Session bootstrap endpoints exist: `POST /ui/session/start`,
   `POST /ui/session/finalize`, `GET /ui/me`.** VERDICT: Verified. SOURCE: OpenAPI
   index lines for `/ui/session/start` (`UiSessionStartReq`→`UiSessionStartResp`),
   `/ui/session/finalize` (`UiSessionFinalizeReq`), `/ui/me`;
   `src/api/endpoints/auth.ts: sessionStart / sessionFinalize`.

10. **Web client also sends `Authorization: Bearer <accessToken>` and may send
    `X-IMPERSONATION-TOKEN`.** VERDICT: Verified (spec omitted these; minor — handled
    by AND-265 shared client). SOURCE: `src/api/client.ts` (sets `Authorization`
    from `useAuthStore`, `X-IMPERSONATION-TOKEN` from `useImpersonationStore`).

11. **`/ui/ads/affiliate/*` endpoints declare `user_sub` + `X-SESSION-ID` (and
    optional `X-IMPERSONATION-TOKEN`) params.** VERDICT: Verified. SOURCE: OpenAPI
    index `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` on all
    `/ui/ads/affiliate/*` rows.

12. **Error handling: documented errors are `200`/`422 HTTPValidationError`; FastAPI
    `detail` may be `string | [{msg}] | {code,...}`.** VERDICT: Verified. SOURCE:
    OpenAPI index (`resp=200:...;422:HTTPValidationError`); `src/api/client.ts:
    normalizeErrorDetail` (handles string, array-of-`{msg}`, and `{code}` objects
    incl. `role_required*`, `geo_blocked`).

13. **Redemption / attach / update / remove / stats / click-preview are separate
    endpoints, out of scope for this read-only ticket.** VERDICT: Verified. SOURCE:
    OpenAPI index `POST /ui/ads/affiliate/redeem` (`AdAffiliateRedeemOut`),
    `POST|PATCH|DELETE /ui/ads/affiliate/creatives/{creative_id}/discount`,
    `GET .../stats` (`AdAffiliateStatsOut`), `GET .../click/{creative_id}/preview`
    (`AdAffiliateClickResult`); `src/api/endpoints/adCreativeAffiliate.ts`.

14. **The web `AdAffiliateDiscountPage` is an owner management screen
    (attach/remove/stats), not a read-only viewer.** VERDICT: Verified (affects
    parity expectations). SOURCE: `src/pages/ads/AdAffiliateDiscountPage.tsx`
    (`attachMut`, `removeMut`, stats query; "Attach Discount" form).

15. **Shareable link = affiliate `click_through_url` (no `share_url` field).**
    VERDICT: Corrected. SOURCE: `AdAffiliateDiscountOut.click_through_url`;
    `AdAffiliateDiscountPage.tsx` (`click_through_url` placeholder
    `https://shop.com/sale`).

16. **Android stack: Compose Navigation type-safe routes, Hilt, Room, StateFlow.**
    VERDICT: Unverified-assumption (framework choice, not contract-bound).
    SOURCE: framework ref — Jetpack Compose Navigation
    (https://developer.android.com/guide/navigation), Room
    (https://developer.android.com/training/data-storage/room). Consistent with
    AND-265's stated module conventions but not independently verifiable here.

17. **Non-affiliate / non-enrolled access returns 403 (vs empty list).** VERDICT:
    Unverified-assumption. SOURCE: OpenAPI documents only `200`/`422` for
    `GET /ui/ads/affiliate/discounts`; 403 behavior is not in the spec — handled
    defensively in §7.

### Corrections made

- **§1 / §2:** Rewrote the data-model description; the surface shows
  affiliate/promo codes **attached to ad creatives**, not a per-code value/validity
  catalog. Fixed the web reference to `adCreativeAffiliate.ts` (not `affiliates.ts`)
  and the type names to `AdAffiliateDiscount*` (the `AffiliateDiscount`/`DiscountKind`
  names do not exist).
- **§2 Auth:** Noted CSRF on all GETs, the `Authorization: Bearer` + impersonation
  headers, and the `user_sub`/`X-SESSION-ID` endpoint params.
- **§5 API Contract:** Corrected list path to `GET /ui/ads/affiliate/discounts`;
  removed the nonexistent `/{discount_id}` detail route (detail is keyed by
  `creative_id` via `.../creatives/{creative_id}/discount`); replaced the fabricated
  JSON with the verified `AdAffiliateDiscountOut` shape; removed the
  percent/fixed/free-trial kind examples; documented epoch-int timestamps and the
  out-of-scope sibling endpoints.
- **§3 / §4 / §6:** Replaced the fabricated `AffiliateDiscount` domain model, Room
  entity, and repository key with the verified `creative_id`-keyed shape; descoped
  `AffiliateDiscountStatus`/`computeStatus` and currency/bps value math (no backing
  fields); `DiscountKind` retained only as a best-effort client-derived chip helper.
- **§4 / §7:** Replaced `share_url` with `click_through_url` for the share action.
- **§13:** Marked R1, R2, R3, R5 RESOLVED with verified findings; refined R4
  (no cursor in `AdAffiliateDiscountListOut`) and R6 (403-vs-empty still open).

### Open assumptions

- **Non-enrolled access (403 vs empty list)** — unverifiable: OpenAPI documents only
  `200`/`422` for the list endpoint (audit #17). §7 handles both.
- **Per-creative detail necessity** — the list already returns every field, so the
  `.../creatives/{creative_id}/discount` call may be redundant; whether the detail
  sheet should re-fetch or reuse the loaded row is a UX choice, not contract-bound.
- **`DiscountKind` derivation from `promo_value_display`** — heuristic only (e.g.
  "20% OFF" → PERCENT); no server field validates it, so it is best-effort.
- **Android framework choices (Compose Nav, Hilt, Room)** — convention-based
  (audit #16), inherited from AND-265; not verifiable from the backend/web sources.
- **Field-name parity with AND-265's eventual Kotlin DTOs** — AND-265 is authoritative
  if its generated names differ from the Retrofit names sketched here.

## 17. Test Plan

Test targets: **JVM/Robolectric** (local, no device); **emulator AVD `test35`**
(x86_64, API 35) for CI Compose/instrumented suites; **physical device** Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) only where real hardware/behavior is
required. This is a read-only, data-display feature with no camera/biometrics/push/
WebRTC, so most cases run on JVM or the emulator; the physical device is used only
to validate the real Android **share sheet** + **clipboard** behavior and the
arm64/API-34 build (the emulator is x86_64/API-35).

- **TC-AND-267-01 — List happy path (DTO → UI).** Type: contract/MockWebServer +
  unit (JVM). Target: JVM/Robolectric. Preconditions: MockWebServer enqueues a
  `200` `AdAffiliateDiscountListOut` fixture with 2 items (one with `promo_code`+
  `promo_value_display`, one with only `affiliate_code`). Steps: call
  `AffiliateApi.adAffiliateDiscounts()` through the repo; collect mapped
  `List<AffiliateDiscount>`. Expected: 2 items mapped with correct `creativeId`,
  `campaignId`, `ownerSub`, nullable codes, `promoValueDisplay`, counts, and
  `createdAt`/`updatedAt` parsed from epoch seconds to `Instant`. Traces: AC-1, AC-9.

- **TC-AND-267-02 — `promo_value_display` rendered verbatim + null-code handling.**
  Type: unit (JVM). Target: JVM/Robolectric. Preconditions: items with
  `promo_value_display="20% OFF"`, another with `promo_value_display=null` and only
  `affiliate_code`. Steps: map and format the value/code cells. Expected: badge text
  equals the raw `promo_value_display`; when null, no badge is shown and the code
  cell falls back to `affiliate_code`; no crash on any null field. Traces: AC-2.

- **TC-AND-267-03 — `derivedKind` heuristic is best-effort, never throws.** Type:
  unit (JVM). Target: JVM/Robolectric. Preconditions: inputs "20% OFF", "$5 OFF",
  "FREE TRIAL", "BOGO", null. Steps: call `deriveKind`. Expected: returns
  PERCENT/FIXED/FREE_TRIAL where parseable, UNKNOWN otherwise (incl. null/"BOGO");
  no exception. (Best-effort per §16 audit #6.) Traces: AC-2.

- **TC-AND-267-04 — Epoch timestamp formatting/localization.** Type: unit (JVM).
  Target: JVM/Robolectric. Preconditions: `created_at=1746057600`,
  `updated_at=1748736000`; test locale + zone fixed. Steps: format "Created {date}".
  Expected: locale/zone-correct date string from the `Instant`; no expiry label
  rendered (no validity field exists). Traces: AC-1, AC-8.

- **TC-AND-267-05 — Repository SWR: cache-then-network + stale flag.** Type: unit
  (JVM, Turbine). Target: JVM/Robolectric (in-memory Room). Preconditions: Room
  pre-seeded with 1 row; MockWebServer returns an updated 2-row list. Steps: collect
  `repo.discounts()`. Expected: first emission = cached (1 row); second = network
  (2 rows, `stale=false`), table replaced in a transaction ordered by `sortSeq`.
  Then with MockWebServer set to error and cache present: emission = cached +
  `stale=true`. Traces: AC-6, AC-7, AC-9.

- **TC-AND-267-06 — Error mapping for 422 / FastAPI `detail` shapes.** Type:
  contract/MockWebServer (JVM). Target: JVM/Robolectric. Preconditions: enqueue
  `422` with `detail` as (a) string, (b) `[{"msg":"..."}]`, (c) `{"code":"role_required"}`.
  Steps: invoke repo; inspect `ApiResult.Error.message`. Expected: each normalizes to
  a friendly message mirroring `client.ts: normalizeErrorDetail` (string passthrough,
  joined `msg`, code-mapped text); no crash. Traces: AC-6, AC-9.

- **TC-AND-267-07 — 401 → single refresh + retry, second 401 surfaces session
  error.** Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: first GET → `401`; `POST /ui/session/refresh` → `200`; retried GET
  → `200` list. Then a variant where refresh → `401`. Steps: invoke repo; count
  requests. Expected: variant 1 succeeds after exactly one refresh + one retry;
  variant 2 yields a "Session expired"/retryable error and does not loop. Traces:
  AC-6, AC-9.

- **TC-AND-267-08 — No-cache + offline → full-screen Retry error.** Type: unit/
  Compose-UI. Target: emulator `test35`. Preconditions: empty Room; network call
  fails (simulated `IOException`). Steps: render `AffiliateDiscountsScreen`; tap
  Retry (now succeeds). Expected: full-screen error with Retry shown first; after
  Retry, list content renders; request count increments. Traces: AC-6, AC-7.

- **TC-AND-267-09 — Empty + stale-banner states.** Type: Compose-UI. Target:
  emulator `test35`. Preconditions: (a) `200` with `items: []`; (b) error with cache
  present. Steps: render screen for each. Expected: (a) distinct "No affiliate
  discounts yet" empty state; (b) cached rows + persistent "Showing saved data"
  banner. Traces: AC-6.

- **TC-AND-267-10 — Pull-to-refresh refetches.** Type: Compose-UI +
  MockWebServer. Target: emulator `test35`. Preconditions: list rendered.
  Steps: perform pull-to-refresh gesture. Expected: a new `GET /ui/ads/affiliate/
  discounts` request is issued (verify via MockWebServer request count); list
  re-renders. Traces: AC-7, AC-9.

- **TC-AND-267-11 — Detail/bottom-sheet open + back.** Type: Compose-UI. Target:
  emulator `test35`. Preconditions: list rendered with a known row. Steps: tap row →
  sheet opens (reusing loaded row or fetching `.../creatives/{creative_id}/discount`);
  press back. Expected: sheet shows full breakdown (creative_id, campaign_id, codes,
  `promo_value_display`, click/redemption counts, created/updated) and copy/share
  actions; back dismisses; no mutate/redeem actions present (read-only). Traces:
  AC-5, AC-2.

- **TC-AND-267-12 — Copy code writes clipboard + confirmation (REAL hardware).**
  Type: instrumented/e2e. Target: **physical device (SM-A156U, API 34)** —
  validates real `ClipboardManager` + Android 14 clipboard-access toast/announce
  behavior, which differs from emulator. Preconditions: list rendered. Steps: tap
  Copy on a row with `promo_code="SUMMER20"`. Expected: clipboard primary clip text =
  "SUMMER20"; a Snackbar/live-region "Code copied" confirmation is announced.
  Traces: AC-4, AC-8.

- **TC-AND-267-13 — Share opens Android share sheet with `click_through_url`, code
  fallback when absent (REAL hardware).** Type: instrumented/e2e. Target: **physical
  device (SM-A156U, API 34)** — exercises the real `ACTION_SEND` chooser; emulator
  lacks share targets. Preconditions: row A has `click_through_url`, row B has none.
  Steps: tap Share on each (use Espresso-Intents to capture intent before chooser, or
  manual confirm on-device). Expected: row A share intent `EXTRA_TEXT` =
  `click_through_url`; row B falls back to sharing the code text; never a null/crash
  payload. Traces: AC-4.

- **TC-AND-267-14 — Accessibility semantics.** Type: Compose-UI (semantics
  assertions) + manual TalkBack spot-check. Target: emulator `test35` (automated) +
  physical device (TalkBack manual). Preconditions: list + a derived-kind chip
  rendered. Steps: assert merged row semantics and control `contentDescription`s;
  TalkBack pass on-device. Expected: each row exposes a merged semantics node
  (code/value/counts); Copy/Share are independently focusable with descriptions
  ("Copy code SUMMER20", "Share discount link"); any derived-kind chip carries a
  spoken label and is not color-only; touch targets ≥ 48dp; strings sourced from
  `strings.xml`. Traces: AC-8.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-04 |
| AC-2 | TC-02, TC-03, TC-11 |
| AC-3 | *Descoped — no server validity/status fields (see §16 audit #7); no TC.* |
| AC-4 | TC-12, TC-13 |
| AC-5 | TC-11 |
| AC-6 | TC-05, TC-06, TC-07, TC-08, TC-09 |
| AC-7 | TC-05, TC-08, TC-10 |
| AC-8 | TC-04, TC-12, TC-14 |
| AC-9 | TC-01, TC-05, TC-06, TC-07, TC-10 |

> Note on **AC-3**: it asserts ACTIVE/SCHEDULED/EXPIRED/EXHAUSTED/DISABLED status
> correctness, but the verified wire shape carries no validity/redemption-cap/enabled
> fields (§16 audit #7), so this criterion is **not satisfiable as written** and is
> recommended for removal or rewrite (e.g. to cover the best-effort `derivedKind`
> chip, already tested by TC-03). Flagged for product/AND-265 reconciliation.
