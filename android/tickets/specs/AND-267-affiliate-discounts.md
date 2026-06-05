---
id: AND-267
title: Affiliate discounts
milestone: M6
epic: E36
priority: P2
size: M
status: draft
depends_on: [AND-265]
blocks: []
---

# AND-267 — Affiliate discounts

## 1. Overview & Goal

Add an **Affiliate Discounts** surface to the TestLogon native Android app that
renders the discount offers a user can promote (or has been granted) through the
affiliate program. The data is sourced from the web reference's
`adCreativeAffiliate` / `ad-affiliate` discount endpoints — i.e. the affiliate
*ad-creative* discount catalog: per-creator or per-product discount codes,
percentages/amounts, validity windows, and the affiliate-attributed share/landing
links that carry the discount.

This ticket owns **consumption and presentation** of affiliate discounts. It does
**not** own the affiliates networking/DTO base or the dashboard shell — that is
**AND-265** (`affiliates.ts`; links + earnings), the hard dependency that supplies
the `feature-affiliates` module, the `AffiliateApi` Retrofit interface, the shared
cookie client wiring, and the `Affiliate*` domain models this ticket extends. Promo
code create/list/redeem is a separate surface owned by **AND-266** (`promoCodes.ts`)
and is explicitly out of scope here.

Goal: from the Affiliates area, a user can open a **Discounts** tab/screen and see
a list of affiliate discount offers — each with its code, value, scope, expiry, and
a copy/share affiliate link action — backed by `ApiResult<T>`, Room-cached for
offline/stale, and verified by unit + Compose UI tests.

Success = **Discounts render** (the source acceptance bullet), correctly formatted,
with offline tolerance, and covered by CI tests.

## 2. Context & References

- **Repo:** `spannella/testlogon`, branch `android-port`, app under `android/`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Feature module:** `feature-affiliates` (created by AND-265; shared with AND-264
  referrals-adjacent and AND-266 promo where relevant).
- **Web reference:** affiliate ad-creative discount endpoints behind
  `frontend/src/api/endpoints/affiliates.ts` (the `adCreativeAffiliate` /
  `ad-affiliate` discount calls), shared types in `frontend/src/api/types.ts`
  (`AffiliateDiscount`, `DiscountKind`, `AffiliateDiscountList`, `AdCreativeAffiliate`),
  and the web affiliate discounts view for label/format parity.
- **Backend:** FastAPI + DynamoDB, OpenAPI at `/openapi.json`; dev host
  `http://18.222.237.167:8000` (plaintext HTTP, unreliable — design for ~20s
  timeouts, bounded retry of idempotent GETs only, offline/stale UI states).
- **Upstream dependency:** **AND-265** supplies `AffiliateApi`, the affiliate DTO
  base, `ApiResult<T>` mapping, and the dashboard navigation entry into which this
  Discounts surface is hung. If AND-265's wire field names differ at integration,
  AND-265 is authoritative and this spec's DTO names are adjusted to match.
- **Auth:** cookie-based session (`POST /ui/session/start` → MFA →
  `POST /ui/session/finalize` → `GET /ui/me`); `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header; on 401 the shared OkHttp authenticator does one
  `POST /ui/session/refresh` then retries. Discount GETs ride that shared client;
  this ticket adds **no** auth logic.

## 3. Functional Requirements

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

FR-4 — **Copy & share.** Each row has a **Copy code** action (clipboard) and a
**Share link** action that shares the affiliate-attributed `share_url` via the
Android share sheet. If `share_url` is absent, fall back to sharing the code text.

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

Domain models (`core-model`):

```kotlin
enum class DiscountKind { PERCENT, FIXED, FREE_TRIAL, UNKNOWN }
enum class AffiliateDiscountStatus { ACTIVE, SCHEDULED, EXPIRED, EXHAUSTED, DISABLED }

data class AffiliateDiscount(
    val id: String,
    val code: String,
    val kind: DiscountKind,
    val percentBps: Int?,          // basis points when PERCENT (2000 = 20%)
    val amountMinor: Long?,        // minor units when FIXED
    val currency: String?,         // ISO 4217 when FIXED
    val freeTrialDays: Int?,       // when FREE_TRIAL
    val displayValue: String?,     // server fallback string for UNKNOWN
    val scopeLabel: String?,       // "Site-wide", product/creator name
    val targetType: String?,       // "creator" | "product" | "global"
    val startsAt: Instant?,
    val endsAt: Instant?,
    val maxRedemptions: Int?,
    val redemptionCount: Int?,
    val enabled: Boolean,
    val shareUrl: String?,         // affiliate-attributed landing link
    val description: String?,
) {
    val status: AffiliateDiscountStatus get() = computeStatus(this)
}
```

Repository (extends AND-265's affiliate repo; SWR / single-source-of-truth):

```kotlin
interface AffiliateDiscountRepository {
    fun discounts(forceRefresh: Boolean = false): Flow<ApiResult<List<AffiliateDiscount>>>
    suspend fun discount(id: String): ApiResult<AffiliateDiscount>
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
relies on. All are authenticated cookie GETs carrying `X-CSRF-Token`. Paths mirror
the web `adCreativeAffiliate` / `ad-affiliate` discount calls; exact paths to be
confirmed against `/openapi.json` (see §13 R2).

**List** `GET /ui/affiliates/discounts` (a.k.a. `ad-affiliate` discounts)

```json
{
  "items": [
    {
      "id": "afd_01HF...",
      "code": "CREATOR20",
      "kind": "percent",
      "percent_bps": 2000,
      "amount": null,
      "currency": null,
      "free_trial_days": null,
      "display_value": "20% off",
      "scope_label": "All creator content",
      "target_type": "creator",
      "starts_at": "2026-05-01T00:00:00Z",
      "ends_at": "2026-07-01T00:00:00Z",
      "max_redemptions": 500,
      "redemption_count": 137,
      "enabled": true,
      "share_url": "https://testlogon.example/r/aff/abc123?d=CREATOR20",
      "description": "20% off any subscription tier."
    }
  ]
}
```

**Detail** `GET /ui/affiliates/discounts/{discount_id}` returns a single object of
the same shape as a list item.

A `FIXED` item example: `"kind":"fixed","amount":500,"currency":"USD"` →
"$5.00 off". A `FREE_TRIAL` item: `"kind":"free_trial","free_trial_days":7"` →
"7-day free trial". Unknown `kind` ⇒ render `display_value` verbatim.

Retrofit (added on AND-265's `AffiliateApi`):

```kotlin
interface AffiliateApi {            // base from AND-265
    @GET("ui/affiliates/discounts")
    suspend fun discounts(): AffiliateDiscountListDto

    @GET("ui/affiliates/discounts/{id}")
    suspend fun discount(@Path("id") id: String): AffiliateDiscountDto
}
```

Errors use FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`) handled by
the shared `ApiResult` mapper. 404 on detail ⇒ "Discount not found"; 403 ⇒ "You
don't have access to affiliate discounts" (non-affiliate accounts).

## 6. Data & State Management

**Room** (cache; DataStore is for prefs only and unused here):

```kotlin
@Entity(tableName = "affiliate_discount")
data class AffiliateDiscountEntity(
    @PrimaryKey val id: String,
    val code: String,
    val kind: String,
    val percentBps: Int?, val amountMinor: Long?, val currency: String?,
    val freeTrialDays: Int?, val displayValue: String?,
    val scopeLabel: String?, val targetType: String?,
    val startsAtEpoch: Long?, val endsAtEpoch: Long?,
    val maxRedemptions: Int?, val redemptionCount: Int?,
    val enabled: Boolean,
    val shareUrl: String?, val description: String?,
    val sortSeq: Int,            // server insertion order (active-first)
    val fetchedAtEpoch: Long,
)
```

`AffiliateDiscountDao` exposes `Flow<List<AffiliateDiscountEntity>>` ordered by
`sortSeq ASC` plus a single-row `suspend fun byId(id)`. Refresh path replaces the
whole table in a transaction (the list is small and fully fetched each refresh — no
paging). `fetchedAtEpoch` drives a TTL (default 5 min) used by the SWR repo to
decide background refresh; stale-but-present cache is shown immediately.

**State:** `DiscountsUiState` (§4) is derived from `ApiResult<List<AffiliateDiscount>>`:
`Success(empty)` → `Empty`; `Success(items)` → `Content(items, stale=false)`;
`Error` with cache present → `Content(cached, stale=true)`; `Error` with no cache →
`Error`. `status` is computed in the domain (`computeStatus`) from validity fields,
so cache and live data render identically. Currency formatting via
`NumberFormat.getCurrencyInstance` keyed on `currency`; percent from basis points
(`percentBps / 100.0`); free-trial via a localized quantity string.

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
- **Copy/share with missing `share_url`:** disable Share or fall back to sharing the
  code text; never crash on a null intent payload.

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

- **R1 — Value/units shape.** Assumes percent in basis points and fixed amounts in
  integer minor units. *Open:* confirm against `types.ts` whether percent is a
  whole number or decimal string and whether amount is minor units or a decimal —
  adjust `percentBps`/`amountMinor` mapping accordingly.
- **R2 — Endpoint path.** The `adCreativeAffiliate` / `ad-affiliate` discount path
  is assumed `/ui/affiliates/discounts`. *Open:* confirm exact path/grouping in
  `/openapi.json`; it may live under an ad-creative namespace
  (e.g. `/ui/ad-creative/affiliate/discounts`). Path is centralized in `AffiliateApi`,
  so a change is low-effort.
- **R3 — Explicit vs computed status.** If the backend returns an authoritative
  `status`, prefer it over `computeStatus`; keep `computeStatus` as a fallback.
- **R4 — Pagination.** Assumes the discount set is small and fully returned. If the
  backend paginates, add cursor handling (mirror AND-260's mediator) — flagged but
  not assumed.
- **R5 — Free-trial representation.** Assumes `free_trial_days` integer. If trials
  are expressed differently (e.g. ISO-8601 duration), adjust formatting.
- **R6 — Non-affiliate access.** Behavior for users not enrolled in the affiliate
  program (403 vs empty list) is unconfirmed; §7 handles both, but confirm intended
  UX with AND-265.
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
