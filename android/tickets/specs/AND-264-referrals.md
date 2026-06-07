---
id: AND-264
title: Referrals
milestone: M6
epic: E36
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-264 — Referrals

## 1. Overview & Goal

Implement the **Referrals** feature for the TestLogon native Android app: a screen that
fetches the signed-in user's referral program state from the backend, renders the user's
referral **codes** (and a client-constructed share **link** per code), displays **referral
statistics** (referral counts and commission/earnings totals, all monetary amounts denominated
in **cents**), and lets the user **share** a link via the Android system share sheet
(`ACTION_SEND`) or copy it to the clipboard.

> **REVIEW NOTE (2026-06-06):** The original draft assumed a single `GET /ui/referrals`
> endpoint returning a top-level `link` and stats fields `invitesSent/signups/conversions/
> rewardCredits/pendingCredits`. This is **incorrect**. The real backend exposes a *family* of
> endpoints under `/ui/referrals/*` (no plain `GET /ui/referrals`), the stats live on
> `GET /ui/referrals/dashboard` with entirely different (cents-denominated) field names, and the
> shareable link is **client-constructed** from a referral *code* (`<origin>/?ref=<code>`) — the
> dashboard payload has no top-level `link`. All affected sections (§2, §4, §5, §6, §7, §13, §14)
> have been corrected in place; see §16 for the full audit.

This is the Android port of the web reference module `src/api/endpoints/referrals.ts`
(reference app) and the screen `src/pages/referrals/ReferralDashboard.tsx`. The goal is
functional parity with the web app's referral surface: identical endpoint paths, verbs, and JSON
shapes, surfaced through the project's standard architecture
(ViewModel → `StateFlow<UiState>` → Compose). The single hard requirement from the backlog —
"Referral link + stats render" — is met when an authenticated user opens the screen, the
referral code(s)/link and stats load from the live API, and offline/error states are handled
gracefully.

The feature lives in a new `feature-referrals` module and a new `ReferralsApi` Retrofit
interface inside `core-network`. It reuses the authenticated, cookie-bearing `OkHttpClient`
and CSRF/refresh interceptors delivered by **AND-027** (AuthApi / session endpoints); no
referral data is reachable without an established session.

## 2. Context & References

- **Backlog ticket:** AND-264 — Referrals · Type: Feature · Priority: P1 · Deps: AND-027.
  Scope: `referrals.ts`; referral link/stats, share. Acceptance: Referral link + stats render.
- **Web reference (VERIFIED):** `src/api/endpoints/referrals.ts` (endpoint definitions) and
  shared DTOs in `src/api/types.ts`, plus the screen `src/pages/referrals/ReferralDashboard.tsx`.
  These are the source of truth for path/verb/shape. NOTE: the backend OpenAPI declares these
  endpoints with an **empty** `200` response schema (`"schema": {}`), so the frontend TypeScript
  types are the **authoritative** shape, not the OpenAPI body — confirmed
  (`openapi.pretty.json: dashboard_ui_referrals_dashboard_get` → `responses.200.content.
  application/json.schema = {}`).
- **Dependency AND-027 (AuthApi, session endpoints):** provides the persistent cookie jar,
  the `X-CSRF-Token` echo of the `ui_csrf` cookie, the `Authorization: Bearer <accessToken>`
  header, and the single-shot `POST /ui/session/refresh` retry on `401`. **VERIFIED** against
  `src/api/client.ts`: every request sets `credentials: "include"` (cookies), adds
  `Authorization: Bearer <accessToken>` from the auth store when present, sets `X-CSRF-Token`
  from the `ui_csrf` cookie, and on `401` (only if already authenticated) calls a single shared
  `POST /ui/session/refresh` (no body) then retries the original request once; a second `401`
  logs out (→ `SessionExpired`). The referral endpoints also accept optional `user_sub` (query)
  and `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (OpenAPI `params=user_sub,X-SESSION-ID,
  X-IMPERSONATION-TOKEN`); the web client does not send `X-SESSION-ID` and relies on the session
  cookie, so the Android client should do the same. `ReferralsApi` is mounted on the **same**
  authenticated Retrofit instance, so it inherits session, CSRF, Bearer, and refresh behavior.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24,
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext, unreliable):
  ~20s timeouts, bounded backoff retry on idempotent GETs only, offline/stale UI states.
- **Module layering:** `app → feature-referrals → core-{network,model,data,ui,testing}`.
- **Package base:** `com.testlogon.android` (used verbatim throughout).

## 3. Functional Requirements

- **FR-1 — Load referral state.** On screen entry the app issues `GET /ui/referrals/dashboard`
  (see §5), which returns both the stats AND the user's `referral_codes[]`. A loading indicator
  shows while the first request is in flight. (Optionally `GET /ui/referrals/commissions?limit=50`
  for the commission-history list, mirroring the web dashboard; the backlog acceptance only
  requires link + stats, so commissions are a secondary surface — see §13.)
- **FR-2 — Render referral codes/link.** Display each referral **code** from
  `dashboard.referral_codes[]` (code text, active/inactive badge, `referral_count`). For each
  active code the share/copy **link** is **client-constructed** as `<origin>/?ref=<code>`
  (VERIFIED: `ReferralDashboard.tsx` `copyLink()` builds `${window.location.origin}/?ref=${code}`;
  there is **no** top-level `link` field on the dashboard payload). The Android `<origin>` is the
  public web base URL (a build config value, e.g. `https://testlogon.app`), NOT the dev API host.
- **FR-3 — Render stats.** Display referral statistics as labeled metric tiles using the REAL
  dashboard fields: **Total Referrals** (`total_referrals`, with `confirmed_referrals` /
  `pending_referrals` as a sub-label), **Total Earned** (`total_earned_cents`), **Pending**
  (`pending_commission_cents`), and **Available** (`available_for_withdrawal_cents`).
  `paid_commission_cents` is also available. All `*_cents` fields are **monetary integers in
  cents** and MUST be rendered as currency (e.g. `$30.00`) via the web rule `cents/100`
  (VERIFIED: `formatCents` in `ReferralDashboard.tsx`). Absent/null numeric fields render as `0`
  (web uses `?? 0`).
- **FR-4 — Share.** A primary "Share" action launches the system share sheet via
  `Intent.ACTION_SEND` (`type = "text/plain"`) with the referral link (plus an optional
  localized invite message). A secondary "Copy link" action copies the link to the clipboard
  and shows a confirmation `Snackbar`.
- **FR-5 — Pull-to-refresh.** The user can re-fetch state via a Material 3 pull-to-refresh
  gesture; this re-runs `GET /ui/referrals` and updates the tiles.
- **FR-6 — Empty/ineligible state.** There is **no** `enabled` flag and no documented `404` on
  the dashboard endpoint (VERIFIED: dashboard response has no `enabled` field; OpenAPI declares
  only `200` and `422` for `/ui/referrals/dashboard`). "No program / nothing to share" is
  therefore represented by an **empty `referral_codes[]`** array: render the web's empty state
  ("No referral codes yet…") with a **"New Code"** action (`POST /ui/referrals/code`) and no
  per-code Copy/Share actions. (Optional: a "Generate code" CTA mirrors `ReferralDashboard.tsx`'s
  create dialog. If the create flow is descoped, the empty state is informational only — see §13
  OQ-2.)
- **FR-7 — Auth gating.** The screen is only reachable for an authenticated session. On a
  hard `401` that survives the AND-027 refresh-and-retry, surface a "session expired" state
  and route the user back toward sign-in (navigation owned by the app shell).
- **FR-8 — Offline/stale.** If a cached copy exists and the network is unavailable, render the
  cached link/stats with a "showing saved data" banner (see §6).

## 4. Technical Design

New Gradle module `:feature-referrals` (namespace `com.testlogon.android.feature.referrals`)
plus a `ReferralsApi` and DTOs in `:core-network` / `:core-model`. The screen follows the
standard unidirectional pattern: ViewModel owns a `StateFlow<ReferralsUiState>`; the
Composable renders state and emits intents.

```kotlin
// core-model — shapes mirror src/api/types.ts (CORRECTED to real contract)
data class ReferralDashboard(
    val stats: ReferralStats,
    val codes: List<ReferralCode>,
)

data class ReferralStats(
    val totalReferrals: Int,
    val confirmedReferrals: Int,
    val pendingReferrals: Int,
    val totalEarnedCents: Long,
    val pendingCommissionCents: Long,
    val paidCommissionCents: Long,
    val availableForWithdrawalCents: Long,
)

data class ReferralCode(
    val code: String,
    val active: Boolean,
    val commissionTier: String,
    val referralCount: Int,        // null -> 0
    val createdAt: String,
) {
    /** Client-constructed share link: <webOrigin>/?ref=<code> (see FR-2). */
    fun shareLink(webOrigin: String): String = "$webOrigin/?ref=$code"
}
```

```kotlin
// core-network — Retrofit interface, mounted on the authenticated client (AND-027).
// CORRECTED: there is NO plain GET /ui/referrals; this is a family under /ui/referrals/*.
interface ReferralsApi {
    @GET("ui/referrals/dashboard")          // -> ReferralDashboardStats (stats + referral_codes[])
    suspend fun getDashboard(): Response<ReferralDashboardDto>

    @GET("ui/referrals/codes")              // -> ReferralCode[]   (codes only)
    suspend fun getCodes(): Response<List<ReferralCodeDto>>

    @POST("ui/referrals/code")              // 201 -> ReferralCodeCreateResp (has `link`)
    suspend fun createCode(): Response<ReferralCodeCreateRespDto>

    @DELETE("ui/referrals/codes/{code}")    // -> { ok: boolean }
    suspend fun deactivateCode(@Path("code") code: String): Response<Unit>

    @GET("ui/referrals/commissions")        // -> CommissionListResp (cursor-paginated)
    suspend fun getCommissions(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): Response<CommissionListRespDto>
}
```

> The backlog acceptance ("link + stats render") is satisfied by `getDashboard()` alone. The
> create/deactivate/commissions methods mirror the web dashboard and are included for parity;
> `createCode`/`deactivateCode` are **mutations** and require the `X-CSRF-Token` header (already
> supplied by the AND-027 client). See §13 for scope decisions.

```kotlin
// feature-referrals
sealed interface ReferralsUiState {
    data object Loading : ReferralsUiState
    data class Content(
        val dashboard: ReferralDashboard,
        val webOrigin: String,                          // for shareLink(); from build config
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : ReferralsUiState
    data object Ineligible : ReferralsUiState           // FR-6: empty referral_codes[]
    data object SessionExpired : ReferralsUiState        // FR-7
    data class Error(val message: String, val retryable: Boolean) : ReferralsUiState
}

sealed interface ReferralsEvent {
    data class CopyToClipboard(val link: String) : ReferralsEvent
    data class Share(val text: String) : ReferralsEvent
    data class ShowSnackbar(val message: String) : ReferralsEvent
}
```

```kotlin
// feature-referrals
interface ReferralsRepository {
    fun observe(): Flow<ReferralDashboard?>              // Room-backed cache (FR-8)
    suspend fun refresh(): ApiResult<ReferralDashboard>  // network -> cache
}

@HiltViewModel
class ReferralsViewModel @Inject constructor(
    private val repository: ReferralsRepository,
) : ViewModel() {
    val uiState: StateFlow<ReferralsUiState>             // = combine(cache, network)
    private val _events = MutableSharedFlow<ReferralsEvent>()
    val events: SharedFlow<ReferralsEvent> = _events.asSharedFlow()

    fun onRefresh()                                      // FR-5
    fun onShareClicked()                                 // emits Share event (FR-4)
    fun onCopyClicked()                                  // emits CopyToClipboard (FR-4)
    fun onRetry()
}
```

`ApiResult<T>` is the project's typed result wrapper; the repository maps Retrofit/OkHttp
outcomes into `ApiResult.Success`, `ApiResult.Error(detail)`, or `ApiResult.NetworkError`
using the shared FastAPI `detail` mapper (string | `[{msg}]` | `{code,...}`; see §7).

Composables (Material 3):

```kotlin
@Composable
fun ReferralsRoute(viewModel: ReferralsViewModel = hiltViewModel())   // collects state+events

@Composable
fun ReferralsScreen(
    state: ReferralsUiState,
    onRefresh: () -> Unit,
    onShare: () -> Unit,
    onCopy: () -> Unit,
    onRetry: () -> Unit,
)
```

Side effects (clipboard, share sheet) are driven by `ReferralsEvent`s collected in
`ReferralsRoute` with `LocalContext`/`LocalClipboardManager`, keeping the ViewModel free of
Android framework types and unit-testable. Navigation registers a `referrals` route in the
app's `NavGraphBuilder` extension `referralsScreen()`.

Hilt wiring: a `ReferralsModule` `@Provides` the `ReferralsApi` from the existing authenticated
`Retrofit`, and binds `ReferralsRepositoryImpl` to `ReferralsRepository`.

## 5. API Contract

Authenticated, cookie-based; requests carry the session cookies, the `Authorization: Bearer
<accessToken>` header, and the `X-CSRF-Token` header provided by the AND-027 client. Base URL
`http://18.222.237.167:8000`. Endpoints also accept optional `user_sub` (query) and
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers) per OpenAPI; the Android client, like the web
client, omits these and relies on the session cookie.

> **CONTRACT CORRECTION (VERIFIED):** There is **no** `GET /ui/referrals`. The referral surface
> is a family of endpoints (OpenAPI `openapi.index.txt` lines 1783–1789):
> `GET /ui/referrals/dashboard`, `GET /ui/referrals/codes`, `POST /ui/referrals/code` (201),
> `DELETE /ui/referrals/codes/{code}`, `GET /ui/referrals/commissions`,
> `GET /ui/referrals/attribution`, `GET /ui/referrals/referrals`. The primary screen call is the
> **dashboard**. All OpenAPI bodies are untyped (`"schema": {}`); shapes below come from
> `src/api/types.ts` (VERIFIED).

**Primary request — dashboard**

```
GET /ui/referrals/dashboard
Cookie: <session>; ui_csrf=<token>
Authorization: Bearer <accessToken>
X-CSRF-Token: <token>
Accept: application/json
```

**Response 200** (`ReferralDashboardStats`, all `*_cents` are integer cents)

```json
{
  "total_referrals": 12,
  "confirmed_referrals": 5,
  "pending_referrals": 7,
  "total_earned_cents": 3000,
  "pending_commission_cents": 1000,
  "paid_commission_cents": 2000,
  "available_for_withdrawal_cents": 1500,
  "referral_codes": [
    {
      "code": "AB12CD34",
      "active": true,
      "commission_tier": "standard",
      "referral_count": 5,
      "created_at": "2026-05-01T12:00:00Z"
    }
  ]
}
```

`POST /ui/referrals/code` → **201** `ReferralCodeCreateResp` (the only payload with a server
`link`):

```json
{ "code": "EF56GH78", "link": "https://testlogon.app/?ref=EF56GH78",
  "commission_tier": "standard", "created_at": "2026-06-06T00:00:00Z" }
```

`GET /ui/referrals/commissions` → `CommissionListResp`:
`{ "commissions": AffiliateCommission[], "next_cursor": string|null }` where each
`AffiliateCommission` = `{ source_type, referred_user_id, gross_amount_cents, net_amount_cents,
commission_cents, commission_rate_bps, status, created_at }`.

Moshi DTOs use `@Json(name = "...")` for snake_case mapping:

```kotlin
@JsonClass(generateAdapter = true)
data class ReferralDashboardDto(
    @Json(name = "total_referrals") val totalReferrals: Int?,
    @Json(name = "confirmed_referrals") val confirmedReferrals: Int?,
    @Json(name = "pending_referrals") val pendingReferrals: Int?,
    @Json(name = "total_earned_cents") val totalEarnedCents: Long?,
    @Json(name = "pending_commission_cents") val pendingCommissionCents: Long?,
    @Json(name = "paid_commission_cents") val paidCommissionCents: Long?,
    @Json(name = "available_for_withdrawal_cents") val availableForWithdrawalCents: Long?,
    @Json(name = "referral_codes") val referralCodes: List<ReferralCodeDto>?,
)

@JsonClass(generateAdapter = true)
data class ReferralCodeDto(
    val code: String,
    val active: Boolean,
    @Json(name = "commission_tier") val commissionTier: String,
    @Json(name = "referral_count") val referralCount: Int?,   // optional in web type
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class ReferralCodeCreateRespDto(
    val code: String,
    val link: String,
    @Json(name = "commission_tier") val commissionTier: String,
    @Json(name = "created_at") val createdAt: String,
)
```

Mapping: missing/null numeric fields → `0` (web `?? 0`); empty/missing `referral_codes` →
`Ineligible` (FR-6). The share link is **derived** from each code (`<webOrigin>/?ref=<code>`),
NOT read from the dashboard.

**Error responses** follow the FastAPI envelope; the documented failure on these endpoints is
`422 HTTPValidationError` (`{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }`), plus
runtime `401`/`403`. There is **no documented `404`** for the dashboard.

```json
{ "detail": [ { "loc": ["query", "user_sub"], "msg": "...", "type": "..." } ] }
```

`401` → handled upstream (single `POST /ui/session/refresh` + retry, then `SessionExpired`);
empty `referral_codes` → `Ineligible`; `422`/malformed → non-retryable `Error`; `5xx`/timeout →
retryable `Error`. (A `404`, if it ever occurs, is treated as `Ineligible` — UNVERIFIED, see §16.)

> **OQ-1 (RESOLVED):** Paths and field names are now confirmed against `openapi.index.txt`
> (lines 1783–1789) and `src/api/types.ts`. The Moshi DTOs above are frozen to that contract.
> **OQ-2 (scope):** A server-side **create-code** mutation (`POST /ui/referrals/code`) and
> **deactivate** (`DELETE /ui/referrals/codes/{code}`) DO exist and are used by the web dashboard;
> whether the Android MVP includes the create/deactivate flow or ships read+share only is a scope
> call (see §13). There is no "send invite" endpoint.

## 6. Data & State Management

- **In-memory state:** `ReferralsUiState` exposed as `StateFlow` with
  `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`.
- **Cache (Room 2.6, via core-data):** a single-row `ReferralDashboardEntity` keyed by the
  current user id (holding the stats columns) plus a child `ReferralCodeEntity` table for the
  `referral_codes[]`, written after every successful dashboard fetch. The repository's `observe()`
  emits the cached aggregate so the UI can render instantly and the `Content.isStale` flag is set
  when displayed data came from cache without a fresh network confirmation (FR-8). No `DataStore`
  use is required; Room is the cache and there are no user-tunable prefs for this screen.
- **Refresh policy:** fetch the dashboard on first composition and on explicit pull-to-refresh
  (FR-5). The dashboard itself is low-cardinality and non-paginated — **Paging 3 is N/A** for it.
  (The optional commission *history* (`/ui/referrals/commissions`) IS cursor-paginated
  (`next_cursor`); if that surface is built, it may use Paging 3, but it is out of the core
  acceptance.)
- **Single source of truth:** network writes Room; UI reads Room; this keeps share/copy actions
  operating on the same code(s) the user sees. The share **link** is derived at render time from
  the cached `code` via `<webOrigin>/?ref=<code>`.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the AND-027 OkHttp client's ~20s call timeout. `GET /ui/referrals/
  dashboard` is idempotent, so it is eligible for **bounded exponential backoff** (max 2 retries,
  e.g. 0.5s/1s with jitter) on transient network/`5xx` failures. The mutations
  (`POST /ui/referrals/code`, `DELETE /ui/referrals/codes/{code}`) are **not** auto-retried.
- **401:** the AND-027 interceptor performs a single `POST /ui/session/refresh` then retries;
  if it still fails, the repository returns an auth error mapped to `SessionExpired` (FR-7).
- **Offline:** `UnknownHostException`/`SocketTimeoutException` with a cached entity →
  `Content(isStale = true)` with a banner; with no cache → retryable `Error` empty state.
- **FastAPI `detail` mapping:** use the shared mapper to coerce `string`, `[{msg}]`, and
  `{code,...}` into a single user-facing message; unknown shapes fall back to a generic
  localized error string.
- **No infinite spinners:** every terminal outcome resolves to a non-`Loading` state.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; the app's network-security-config already
  permits this cleartext host for dev builds only (owned by core-network). The shared referral
  **link** uses the public `webOrigin` (an HTTPS site, e.g. `https://testlogon.app`), which is
  distinct from the cleartext dev API host — never share/copy an `http://18.222.237.167:8000/...`
  URL. Release builds must not ship cleartext for either host.
- **Session/CSRF:** all requests authenticated via the persistent cookie jar; `X-CSRF-Token`
  echoed from `ui_csrf` — inherited from AND-027, not re-implemented here.
- **Sharing:** only the referral link (and a non-sensitive invite message) is placed into the
  share/clipboard intent. **No** session cookies, tokens, user id, or PII are ever shared.
- **Logging:** never log full cookies/CSRF; the referral link is low-sensitivity but is
  redacted to its code suffix in logs (see §10).
- **Clipboard:** on API 33+ the system shows its own copy notification; do not duplicate
  sensitive content into persistent storage.

## 9. Accessibility & i18n

- All actionable elements (Share, Copy, Retry) have `contentDescription`/`semantics` and meet
  the 48dp minimum touch target.
- Metric tiles use `mergeDescendants` semantics so TalkBack reads "Signups, 5" as one node.
- The referral link field is announced as selectable text; the copy action announces
  "Referral link copied".
- All strings live in `feature-referrals/src/main/res/values/strings.xml` (no hardcoded UI
  text); numbers formatted via `NumberFormat`/`pluralStringResource` for invite counts.
- Layout supports dynamic font scaling and RTL via Compose defaults; tiles use a
  `FlowRow`/grid that reflows at large font sizes.

## 10. Telemetry & Logging

- Emit analytics events via the project's existing analytics abstraction (no new SDK):
  `referrals_viewed`, `referrals_load_failed{reason}`, `referral_shared{channel:"system_sheet"}`,
  `referral_copied`, `referrals_refreshed`.
- Structured debug logs at `Timber`/project logger: request start, HTTP status, mapped error
  category, cache hit/miss. Redact the link to its trailing code (`…/?ref=AB12CD34`).
- No analytics payload contains the full link, cookies, or user PII.

## 11. Testing Strategy

- **Unit (core-testing + JUnit + Turbine):**
  - `ReferralsViewModel` state transitions: `Loading → Content`, `→ Ineligible`,
    `→ SessionExpired`, `→ Error(retryable)`; `onRefresh` sets/clears `isRefreshing`.
  - DTO→domain mapping: snake_case decode, null numeric fields → zeros, empty `referral_codes[]`
    → `Ineligible`, `*_cents` formatted as currency, share link derived `<webOrigin>/?ref=<code>`.
  - Event emission: `onShareClicked`/`onCopyClicked` emit the correct `ReferralsEvent` with the
    current link.
- **Network (MockWebServer):** `ReferralsApi.getDashboard()` hits `GET /ui/referrals/dashboard`,
  parses the 200 body, and surfaces `401`/`422`/`500`/timeout into the right `ApiResult` (mirrors
  the AND-027 MockWebServer pattern). Where create/deactivate are in scope, also assert
  `POST /ui/referrals/code` (201) and `DELETE /ui/referrals/codes/{code}` paths/verbs and that
  they send `X-CSRF-Token`.
- **Repository:** cache-then-network ordering; offline path returns cached `ReferralDashboard`
  with stale flag; backoff retry invoked on transient failure for the GET only (not mutations).
- **Compose UI tests:** link text rendered, stat tiles show expected values, Share/Copy buttons
  present and disabled in `Ineligible`, error state shows Retry. Verify the share `Intent` is
  built with `ACTION_SEND`/`text/plain` (via a fake intent launcher).
- **Acceptance check:** an instrumented test against a stubbed 200 asserts both the link and at
  least the three core stat tiles render (satisfies the backlog acceptance).

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-027** (AuthApi / session endpoints) — supplies the authenticated
  Retrofit/OkHttp client, cookie jar, CSRF header, and refresh-on-401. `ReferralsApi` cannot
  function without it. Must merge first.
- **Soft prerequisites:** core-ui (Material 3 theming, metric-tile/Snackbar primitives) and
  core-network (network-security-config, shared `detail` mapper, `ApiResult`). The app shell must
  expose a navigation entry point that calls `referralsScreen()`.
- **Blocks:** none recorded in the backlog.
- **Sequencing:** (1) add DTOs + `ReferralsApi` in core-network and verify against `/openapi.json`;
  (2) repository + Room entity in core-data/feature; (3) ViewModel + state; (4) Compose UI +
  share/copy side effects; (5) tests; (6) wire navigation in app.

## 13. Risks & Open Questions

- **OQ-1 (contract) — RESOLVED:** endpoint paths and field names confirmed against
  `openapi.index.txt` (lines 1783–1789) and `src/api/types.ts`. DTOs in §5 are frozen.
  **Mitigation retained:** decoding isolated in DTOs so a rename is a one-line `@Json` change.
- **OQ-2 (scope) — RESOLVED + DECISION NEEDED:** there is no "send invite" endpoint, but
  server-side **create** (`POST /ui/referrals/code`) and **deactivate**
  (`DELETE /ui/referrals/codes/{code}`) DO exist and the web dashboard uses them. **Open decision:**
  does the Android MVP include create/deactivate (full parity) or ship read+share only? The
  backlog acceptance ("link + stats render") is met by read-only; create/deactivate can be a
  fast-follow. Recommend read+share+create for the empty-state CTA, deactivate optional.
- **OQ-3 (reward semantics) — RESOLVED:** earnings are **monetary, in integer cents**
  (`*_cents` fields; web renders `cents/100` as USD). Tiles must format as currency, not raw ints.
- **Risk — derived link origin:** the share link is built client-side as `<webOrigin>/?ref=<code>`.
  `webOrigin` must be the **public web URL**, not the dev API host (`18.222.237.167:8000`).
  **Mitigation:** make `webOrigin` a build-config constant per flavor; cover with a unit test.
- **Risk — unreliable dev host:** flaky `/ui/referrals/dashboard` could mask real bugs.
  **Mitigation:** MockWebServer-driven tests are authoritative; offline/stale UI covers flakiness.
- **Risk — share deep-link:** if the referral link is itself an app deep link, attribution wiring
  is owned elsewhere; this ticket only shares the URL string.

## 14. Acceptance Criteria

- **AC-1:** For an authenticated user, opening Referrals issues `GET /ui/referrals/dashboard` and
  renders the **referral code(s)/link** and **stats** tiles on success, with `*_cents` shown as
  currency (the backlog acceptance — "Referral link + stats render").
- **AC-2:** "Share" launches the system share sheet (`ACTION_SEND`, `text/plain`) containing the
  referral link; "Copy link" copies the link and shows a confirmation Snackbar.
- **AC-3:** An empty `referral_codes[]` renders the **Ineligible** empty state with per-code
  Share/Copy actions absent (optionally offering a "New Code" CTA).
- **AC-4:** A hard `401` (after AND-027 refresh+retry) renders **SessionExpired** and routes
  toward sign-in; transient `5xx`/timeout renders a retryable **Error**.
- **AC-5:** With a cached entity and no network, the screen renders cached link/stats with a
  "saved data" banner.
- **AC-6:** Pull-to-refresh re-fetches and updates the tiles, toggling `isRefreshing`.
- **AC-7:** MockWebServer tests confirm `ReferralsApi` path/verb (`GET /ui/referrals/dashboard`)
  and that 200/401/422/500/timeout map to the correct `ApiResult`/state. All new strings are
  localized; actions are TalkBack-labeled.

## 15. Definition of Done

- `:feature-referrals` module and `ReferralsApi`/DTOs merged on the `android-port` branch under
  `com.testlogon.android.*`; navigation entry wired in `app`.
- All §14 acceptance criteria pass; unit, MockWebServer, repository, and Compose UI tests are
  green in CI.
- `./gradlew :feature-referrals:test :feature-referrals:lint` clean; no hardcoded strings; no
  cleartext referral host in release config.
- Telemetry events (§10) emitted and verified; logs redact the link.
- OQ-1/OQ-3 resolved against the OpenAPI index and frontend types (done in this review);
  OQ-2 create/deactivate scope decision recorded; code review approved; spec status moved to
  `accepted`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index
(`reference/openapi.index.txt`), OpenAPI spec (`reference/openapi.pretty.json`), and frontend
reference app (`reference/src/...`).

1. **Endpoint for stats/codes is `GET /ui/referrals/dashboard` (not `GET /ui/referrals`).**
   VERDICT: **Corrected.** SOURCE: `openapi.index.txt` line 1788
   (`GET /ui/referrals/dashboard | op=dashboard_ui_referrals_dashboard_get`);
   `src/api/endpoints/referrals.ts: getReferralDashboard` → `api.get("/ui/referrals/dashboard")`.
   No `GET /ui/referrals` exists anywhere in the index.
2. **Full endpoint family under `/ui/referrals/*`.** VERDICT: **Verified.** SOURCE:
   `openapi.index.txt` lines 1783–1789: `/ui/referrals/attribution` (GET),
   `/ui/referrals/code` (POST, 201), `/ui/referrals/codes` (GET),
   `/ui/referrals/codes/{code}` (DELETE), `/ui/referrals/commissions` (GET),
   `/ui/referrals/dashboard` (GET), `/ui/referrals/referrals` (GET); mirrored 1:1 in
   `src/api/endpoints/referrals.ts`.
3. **Dashboard stats fields are `total_referrals, confirmed_referrals, pending_referrals,
   total_earned_cents, pending_commission_cents, paid_commission_cents,
   available_for_withdrawal_cents, referral_codes[]`** (NOT `invites_sent/signups/conversions/
   reward_credits/pending_credits`). VERDICT: **Corrected.** SOURCE:
   `src/api/types.ts: ReferralDashboardStats` (lines 3724–3733).
4. **Earnings are monetary, denominated in integer cents (render `cents/100` as currency).**
   VERDICT: **Corrected** (resolves OQ-3). SOURCE: `src/api/types.ts` `*_cents` fields;
   `src/pages/referrals/ReferralDashboard.tsx: formatCents` (`$${(cents/100).toFixed(2)}`).
5. **Dashboard payload has NO top-level `link`; the share link is client-constructed as
   `<origin>/?ref=<code>`.** VERDICT: **Corrected.** SOURCE:
   `src/pages/referrals/ReferralDashboard.tsx: copyLink` (`${window.location.origin}/?ref=${code}`);
   `ReferralDashboardStats` has no `link` field.
6. **`POST /ui/referrals/code` returns 201 with a `{code, link, commission_tier, created_at}`
   body (the only payload carrying a server `link`).** VERDICT: **Verified.** SOURCE:
   `openapi.index.txt` line 1784 (`resp=201:`); `src/api/types.ts: ReferralCodeCreateResp`
   (lines 3717–3722).
7. **`ReferralCode` shape `{code, active, commission_tier, referral_count?, created_at}`.**
   VERDICT: **Verified.** SOURCE: `src/api/types.ts: ReferralCode` (lines 3709–3715).
8. **`GET /ui/referrals/commissions` is cursor-paginated → `{commissions[], next_cursor}`;
   each `AffiliateCommission` has `*_cents` and `commission_rate_bps`.** VERDICT: **Verified.**
   SOURCE: `openapi.index.txt` line 1787 (`params=limit,cursor,...`);
   `src/api/types.ts: CommissionListResp` / `AffiliateCommission` (lines 3735–3749).
9. **No `enabled` flag; "ineligible" = empty `referral_codes[]`.** VERDICT: **Corrected.**
   SOURCE: `ReferralDashboardStats` has no `enabled` field; empty-state branch in
   `ReferralDashboard.tsx` keys off `stats.referral_codes.length > 0`.
10. **Auth carries `Authorization: Bearer <accessToken>` AND cookie session AND `X-CSRF-Token`
    from the `ui_csrf` cookie.** VERDICT: **Corrected** (spec omitted the Bearer header).
    SOURCE: `src/api/client.ts` lines 157–171 (sets `Authorization: Bearer`, `X-CSRF-Token`
    from `getCookie("ui_csrf")`, `credentials: "include"`).
11. **On `401`: single shared `POST /ui/session/refresh` (no body) then one retry; second `401`
    logs out.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` lines 121–237
    (`refreshSession` → `/ui/session/refresh`; retry; `logout("session_expired")`);
    `openapi.index.txt` line 1847 (`POST /ui/session/refresh | req= | resp=200:`).
12. **Referral endpoints accept optional `user_sub` (query), `X-SESSION-ID`,
    `X-IMPERSONATION-TOKEN` (headers); web client omits `X-SESSION-ID`.** VERDICT: **Verified.**
    SOURCE: `openapi.pretty.json: dashboard_ui_referrals_dashboard_get.parameters` (lines
    237393–237441); `src/api/client.ts` never sets `X-SESSION-ID` (only `X-IMPERSONATION-TOKEN`
    when impersonating, lines 162–165).
13. **OpenAPI declares an empty `200` body schema for these endpoints (frontend types are
    authoritative).** VERDICT: **Verified.** SOURCE:
    `openapi.pretty.json` lines 237443–237451 (`responses.200.content.application/json.schema
    = {}`).
14. **Documented error on dashboard is `422 HTTPValidationError`; no `404` declared.**
    VERDICT: **Corrected** (spec claimed a `404`→Ineligible path). SOURCE: `openapi.index.txt`
    line 1788 (`resp=200:;422:HTTPValidationError`).
15. **FastAPI `detail` may be `string`, `[{msg}]`, or `{code,...}` and is normalized to one
    message.** VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail`
    (lines 66–102) and `mapAuthorizationError` (lines 34–64).
16. **Copy/Share text content is only the referral link (no cookies/PII).** VERDICT: **Verified.**
    SOURCE: `src/pages/referrals/ReferralDashboard.tsx: copyLink` writes only the derived URL.
17. **Per-code "Copy Link" with `aria-label`; create dialog states "5% commission" / "up to 5
    active codes".** VERDICT: **Verified.** SOURCE: `ReferralDashboard.tsx` lines 156–202, 276–278.
18. **Android architecture (ViewModel + `StateFlow`, Compose Material 3, Hilt, Retrofit/Moshi,
    Room cache, `ACTION_SEND` share sheet, `ClipboardManager`).** VERDICT: **Unverified-assumption**
    (framework/project-convention choices, not in the API/frontend sources). SOURCE: framework ref
    — Android `Intent.ACTION_SEND` (developer.android.com/training/sharing/send),
    Compose Material 3 pull-to-refresh, Jetpack Room; consistent with sibling AND-* specs.

### Corrections made

- **C1 — Endpoint.** Replaced the nonexistent `GET /ui/referrals` with the real family; primary
  call is `GET /ui/referrals/dashboard`. (§1 note, §2, §3 FR-1, §4 `ReferralsApi`, §5, §6, §7,
  §11, §14 AC-1/AC-7.)
- **C2 — Stats fields.** Replaced `invites_sent/signups/conversions/reward_credits/
  pending_credits` with the real `total_referrals/confirmed_referrals/pending_referrals/
  total_earned_cents/pending_commission_cents/paid_commission_cents/
  available_for_withdrawal_cents`. (§3 FR-3, §4 model, §5 DTOs.)
- **C3 — Monetary semantics.** Earnings are integer **cents** rendered as currency (`Long`
  fields, `cents/100`). Resolved OQ-3. (§1, §3 FR-3, §13.)
- **C4 — Link is derived.** No top-level `link`; share link built as `<webOrigin>/?ref=<code>`
  from a referral code. Added `webOrigin` build-config requirement. (§3 FR-2, §4, §5, §6, §8, §13.)
- **C5 — Ineligible semantics.** No `enabled` flag and no `404`; ineligible = empty
  `referral_codes[]`. (§3 FR-6, §5, §14 AC-3.)
- **C6 — Auth.** Added the `Authorization: Bearer` header (spec previously listed only cookie +
  CSRF). (§2, §5, §8.)
- **C7 — Error codes.** Dashboard errors are `422`, not `404`/`5xx`-only; corrected error mapping
  and MockWebServer test matrix. (§5, §7, §11, §14 AC-7.)
- **C8 — Scope clarity.** Documented the real `POST /ui/referrals/code` (create) and
  `DELETE /ui/referrals/codes/{code}` (deactivate) mutations and made their MVP inclusion an
  explicit decision (OQ-2). (§4, §5, §13.)
- **C9 — Path/reference hygiene.** Corrected frontend paths from `frontend/src/...` to the actual
  `src/...` reference layout; fixed the redaction example link. (§1, §2, §10.)

### Open assumptions

- **OA-1 — `webOrigin` value.** The exact public web origin used to build share links
  (e.g. `https://testlogon.app`) is not in the reviewed sources (the web app uses
  `window.location.origin`). Must be supplied as a per-flavor build constant. *Why unverifiable:*
  no deployment/config source provided. (UNVERIFIED-ASSUMPTION.)
- **OA-2 — `404` → Ineligible.** The dashboard endpoint declares no `404`; treating a hypothetical
  `404` as Ineligible is a defensive assumption, not contract-backed. *Why:* only `200`/`422`
  documented. (UNVERIFIED-ASSUMPTION.)
- **OA-3 — Offline/cache + Room.** Caching, stale banner, and the Room schema are Android-side
  design; the web client has no offline path. *Why:* no parity source. (UNVERIFIED-ASSUMPTION.)
- **OA-4 — `commission_tier` display semantics.** The string values (`"standard"`, etc.) and
  whether to surface tier in the UI are not specified by sources. *Why:* enum not enumerated in
  reviewed files. (UNVERIFIED-ASSUMPTION.)
- **OA-5 — Telemetry event names.** §10 analytics event names are project conventions, not present
  in the reference sources. (UNVERIFIED-ASSUMPTION.)

## 17. Test Plan

Test-case IDs `TC-AND-264-NN`. Targets: **JVM** (local JVM/Robolectric unit), **MWS**
(contract via MockWebServer, JVM), **EMU** (headless emulator AVD `test35`, API 35, x86_64),
**DEVICE** (physical Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a). Most cases run on
**EMU**; the physical device is preferred only for real-hardware behavior (system share-sheet
chooser, clipboard with the OS toast, real-network flakiness).

- **TC-AND-264-01 — Happy-path dashboard load & render.** Type: contract/MWS + JVM. Target: MWS
  (JVM). Preconditions: authenticated session; MockWebServer enqueues a `200` dashboard body
  (stats + one active code). Steps: open Referrals → ViewModel calls `getDashboard()`. Expected:
  request hits `GET /ui/referrals/dashboard`; state → `Content`; stats mapped (`*_cents` →
  currency), code present, `Loading` cleared. Traces: AC-1, AC-7.

- **TC-AND-264-02 — Stat tiles & currency formatting render.** Type: Compose-UI. Target: EMU.
  Preconditions: `Content` with `total_referrals=12, confirmed=5, pending=7,
  total_earned_cents=3000, pending_commission_cents=1000, available_for_withdrawal_cents=1500`.
  Steps: render `ReferralsScreen`. Expected: tiles show "12" (sub "5 confirmed, 7 pending"),
  "$30.00", "$10.00", "$15.00"; code text and a derived link `…/?ref=<code>` visible. Traces:
  AC-1.

- **TC-AND-264-03 — DTO→domain mapping incl. nulls & cents.** Type: unit. Target: JVM.
  Preconditions: dashboard JSON with null numeric fields and `referral_count` absent. Steps:
  decode with Moshi → map to domain. Expected: null numerics → `0`; `referralCount` → `0`;
  `*_cents` typed `Long`; `shareLink(origin)` = `origin + "/?ref=" + code`. Traces: AC-1.

- **TC-AND-264-04 — Empty referral_codes → Ineligible.** Type: unit + Compose-UI. Target: JVM
  (mapping) + EMU (UI). Preconditions: `200` dashboard with `referral_codes: []`. Steps: load,
  then render. Expected: state → `Ineligible`; empty-state copy shown; no per-code Copy/Share
  actions; optional "New Code" CTA visible. Traces: AC-3.

- **TC-AND-264-05 — Copy link to clipboard.** Type: instrumented/e2e. Target: **DEVICE**
  (preferred — real `ClipboardManager` + API-33+ OS copy toast; A15 is API 34). Preconditions:
  `Content` with active code. Steps: tap "Copy link". Expected: clipboard contains
  `<webOrigin>/?ref=<code>` (no cookies/PII); confirmation Snackbar/announcement shown. Traces:
  AC-2. (Mapping-only variant can run JVM via fake clipboard.)

- **TC-AND-264-06 — Share via ACTION_SEND.** Type: instrumented/e2e. Target: **DEVICE**
  (preferred — real system share-sheet chooser). Preconditions: `Content` with active code.
  Steps: tap "Share"; inspect launched intent. Expected: `Intent.ACTION_SEND`, `type="text/plain"`,
  `EXTRA_TEXT` contains the referral link (plus optional invite message); chooser appears. Traces:
  AC-2. (Intent-construction assertion can also run on EMU with a fake launcher.)

- **TC-AND-264-07 — 401 → refresh+retry → SessionExpired.** Type: contract/MWS. Target: MWS
  (JVM). Preconditions: authenticated; MWS enqueues `401`, then a `401` on the refreshed retry
  (or refresh fails). Steps: load dashboard. Expected: client issues one
  `POST /ui/session/refresh`, retries once; persistent `401` → state `SessionExpired` and a
  navigate-to-sign-in signal. Traces: AC-4.

- **TC-AND-264-08 — 401 → refresh succeeds → Content.** Type: contract/MWS. Target: MWS (JVM).
  Preconditions: MWS enqueues `401`, then `200` on retry after refresh. Steps: load. Expected:
  exactly one refresh call; retried `GET /ui/referrals/dashboard` returns `200`; state →
  `Content`. Traces: AC-4.

- **TC-AND-264-09 — 422 / malformed body → non-retryable Error.** Type: contract/MWS. Target:
  MWS (JVM). Preconditions: MWS enqueues `422` with `{"detail":[{"msg":"..."}]}`. Steps: load.
  Expected: `detail` normalized to a single message; state `Error(retryable=false)`; no backoff
  retries. Traces: AC-4, AC-7.

- **TC-AND-264-10 — 5xx/timeout → retryable Error with bounded backoff.** Type: contract/MWS.
  Target: MWS (JVM). Preconditions: MWS returns `500` (or a body-delay past the call timeout)
  for all attempts. Steps: load. Expected: GET retried with bounded backoff (max 2); terminal
  state `Error(retryable=true)`; mutations would NOT be retried. Traces: AC-4.

- **TC-AND-264-11 — Offline with cache → stale Content + banner.** Type: integration. Target:
  EMU (toggle airplane mode / dispatcher throws `UnknownHostException`). Preconditions: Room has
  a prior dashboard; network unavailable. Steps: open screen. Expected: cached stats/code render
  immediately; `Content(isStale=true)`; "showing saved data" banner; no infinite spinner.
  Traces: AC-5.

- **TC-AND-264-12 — Offline with no cache → retryable empty Error.** Type: integration. Target:
  EMU. Preconditions: empty Room; network unavailable. Steps: open screen, then tap Retry once
  online (MWS `200`). Expected: first → `Error(retryable=true)`; Retry → `Content`. Traces:
  AC-4, AC-5, AC-6.

- **TC-AND-264-13 — Pull-to-refresh toggles isRefreshing and updates tiles.** Type: Compose-UI.
  Target: EMU. Preconditions: `Content` rendered. Steps: trigger pull-to-refresh; MWS returns
  updated stats. Expected: `isRefreshing` true during fetch then false; tiles update to new
  values; one new `GET /ui/referrals/dashboard`. Traces: AC-6.

- **TC-AND-264-14 — Security: no secrets in share/clipboard/logs; HTTPS link only.** Type: unit
  + Compose-UI. Target: JVM (+ EMU for intent). Preconditions: `Content`. Steps: invoke
  share/copy; capture intent text, clipboard, and logger output. Expected: payload is only the
  `<webOrigin>/?ref=<code>` URL (HTTPS, not the `http://18.222…` API host); no cookies, CSRF,
  Bearer token, or `user_sub`; logs redact to `…/?ref=<code>`. Traces: AC-2.

- **TC-AND-264-15 — Accessibility: TalkBack labels, merged tile semantics, touch targets.**
  Type: Compose-UI (accessibility). Target: EMU (Accessibility checks / Espresso a11y).
  Preconditions: `Content` and `Ineligible`. Steps: run the Compose a11y assertions. Expected:
  Share/Copy/Retry have `contentDescription` and ≥48dp targets; each metric tile is one merged
  node ("Total Referrals, 12"); link field announced as selectable; copy announces "Referral
  link copied"; all strings come from resources. Traces: AC-7.

- **TC-AND-264-16 — ABI/API parity smoke (arm64 / API 34 vs x86_64 / API 35).** Type:
  instrumented/e2e. Target: **DEVICE** (arm64-v8a, API 34) vs EMU (x86_64, API 35).
  Preconditions: stubbed `200`. Steps: run TC-01/02 happy path on both. Expected: identical
  render and Moshi/`Long`-cents formatting on both ABIs/API levels (no `Int` overflow, no
  locale-currency divergence). Traces: AC-1. (MUST include the physical device for the
  arm64/API-34 leg.)

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 (load dashboard; link + stats render, cents as currency) | TC-01, TC-02, TC-03, TC-16 |
| AC-2 (Share `ACTION_SEND`/`text/plain`; Copy + Snackbar) | TC-05, TC-06, TC-14 |
| AC-3 (empty `referral_codes` → Ineligible, actions hidden) | TC-04 |
| AC-4 (hard 401 → SessionExpired; transient → retryable Error) | TC-07, TC-08, TC-09, TC-10, TC-12 |
| AC-5 (cache + no network → stale render + banner) | TC-11, TC-12 |
| AC-6 (pull-to-refresh re-fetches; toggles isRefreshing) | TC-12, TC-13 |
| AC-7 (MWS path/verb + 200/401/422/500/timeout mapping; localized; TalkBack) | TC-01, TC-07, TC-08, TC-09, TC-10, TC-15 |
