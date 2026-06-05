---
id: AND-264
title: Referrals
milestone: M6
epic: E36
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-264 — Referrals

## 1. Overview & Goal

Implement the **Referrals** feature for the TestLogon native Android app: a screen that
fetches the signed-in user's referral program state from the backend, renders the user's
unique **referral link/code**, displays **referral statistics** (invites sent, signups,
conversions, and any reward/credit totals), and lets the user **share** the link via the
Android system share sheet (`ACTION_SEND`) or copy it to the clipboard.

This is the Android port of the web reference module `frontend/src/api/endpoints/referrals.ts`.
The goal is functional parity with the web app's referral surface: identical endpoint paths,
verbs, and JSON shapes, surfaced through the project's standard architecture
(ViewModel → `StateFlow<UiState>` → Compose). The single hard requirement from the backlog —
"Referral link + stats render" — is met when an authenticated user opens the screen, the link
and stats load from the live API, and offline/error states are handled gracefully.

The feature lives in a new `feature-referrals` module and a new `ReferralsApi` Retrofit
interface inside `core-network`. It reuses the authenticated, cookie-bearing `OkHttpClient`
and CSRF/refresh interceptors delivered by **AND-027** (AuthApi / session endpoints); no
referral data is reachable without an established session.

## 2. Context & References

- **Backlog ticket:** AND-264 — Referrals · Type: Feature · Priority: P1 · Deps: AND-027.
  Scope: `referrals.ts`; referral link/stats, share. Acceptance: Referral link + stats render.
- **Web reference:** `frontend/src/api/endpoints/referrals.ts` (endpoint definitions) and
  shared DTOs in `frontend/src/api/types.ts`. These are the source of truth for path/verb/shape;
  confirm exact field names against the live `/openapi.json` before freezing the Moshi models
  (see §5, Open Question OQ-1).
- **Dependency AND-027 (AuthApi, session endpoints):** provides the persistent cookie jar,
  the `X-CSRF-Token` echo of the `ui_csrf` cookie, and the single-shot `POST /ui/session/refresh`
  retry on `401`. `ReferralsApi` is mounted on the **same** authenticated Retrofit instance, so
  it inherits session, CSRF, and refresh behavior for free.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24,
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext, unreliable):
  ~20s timeouts, bounded backoff retry on idempotent GETs only, offline/stale UI states.
- **Module layering:** `app → feature-referrals → core-{network,model,data,ui,testing}`.
- **Package base:** `com.testlogon.android` (used verbatim throughout).

## 3. Functional Requirements

- **FR-1 — Load referral state.** On screen entry the app issues `GET /ui/referrals` (see §5)
  for the authenticated user and renders the result. A loading indicator shows while the first
  request is in flight.
- **FR-2 — Render referral link/code.** Display the user's referral **link** (full URL) and,
  if present, the short **code**. The link is presented in a selectable, single-line,
  middle-ellipsized field.
- **FR-3 — Render stats.** Display referral statistics as labeled metric tiles:
  `invitesSent`, `signups`, `conversions`, and reward totals (`rewardCredits` /
  `pendingCredits`) when the backend supplies them. Absent/null numeric fields render as `0`;
  absent reward fields hide their tile rather than showing `0`.
- **FR-4 — Share.** A primary "Share" action launches the system share sheet via
  `Intent.ACTION_SEND` (`type = "text/plain"`) with the referral link (plus an optional
  localized invite message). A secondary "Copy link" action copies the link to the clipboard
  and shows a confirmation `Snackbar`.
- **FR-5 — Pull-to-refresh.** The user can re-fetch state via a Material 3 pull-to-refresh
  gesture; this re-runs `GET /ui/referrals` and updates the tiles.
- **FR-6 — Empty/ineligible state.** If the backend reports the user has no referral program
  (e.g., `enabled = false` or a `404`/empty payload), render an informative empty state instead
  of an error, with no Share/Copy actions enabled.
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
// core-model
data class Referral(
    val link: String,
    val code: String?,
    val enabled: Boolean,
    val stats: ReferralStats,
)

data class ReferralStats(
    val invitesSent: Int,
    val signups: Int,
    val conversions: Int,
    val rewardCredits: Int?,   // null -> hide tile
    val pendingCredits: Int?,  // null -> hide tile
)
```

```kotlin
// core-network — Retrofit interface, mounted on the authenticated client (AND-027)
interface ReferralsApi {
    @GET("ui/referrals")
    suspend fun getReferrals(): Response<ReferralDto>
}
```

```kotlin
// feature-referrals
sealed interface ReferralsUiState {
    data object Loading : ReferralsUiState
    data class Content(
        val referral: Referral,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : ReferralsUiState
    data object Ineligible : ReferralsUiState           // FR-6
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
    fun observe(): Flow<Referral?>                       // Room-backed cache (FR-8)
    suspend fun refresh(): ApiResult<Referral>           // network -> cache
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

Authenticated, cookie-based; requests carry the session cookies and `X-CSRF-Token` header
provided by the AND-027 client. Base URL `http://18.222.237.167:8000`.

**Request**

```
GET /ui/referrals
Cookie: <session>; ui_csrf=<token>
X-CSRF-Token: <token>
Accept: application/json
```

**Response 200**

```json
{
  "link": "https://testlogon.app/r/AB12CD",
  "code": "AB12CD",
  "enabled": true,
  "stats": {
    "invites_sent": 12,
    "signups": 5,
    "conversions": 3,
    "reward_credits": 30,
    "pending_credits": 10
  }
}
```

Moshi DTOs use `@Json(name = "...")` for snake_case mapping:

```kotlin
@JsonClass(generateAdapter = true)
data class ReferralDto(
    val link: String?,
    val code: String?,
    val enabled: Boolean = true,
    val stats: ReferralStatsDto?,
)

@JsonClass(generateAdapter = true)
data class ReferralStatsDto(
    @Json(name = "invites_sent") val invitesSent: Int?,
    val signups: Int?,
    val conversions: Int?,
    @Json(name = "reward_credits") val rewardCredits: Int?,
    @Json(name = "pending_credits") val pendingCredits: Int?,
)
```

Mapping: missing `stats` → all counters `0`; `enabled = false` or `link = null` → `Ineligible`.

**Error responses** follow the FastAPI envelope:

```json
{ "detail": "Referral program not available" }
```

`401` → handled upstream (refresh+retry, then `SessionExpired`); `404`/`enabled:false` →
`Ineligible`; `5xx`/timeout → retryable `Error`.

> **OQ-1:** Exact path (`/ui/referrals` vs `/ui/me/referrals`), field names, and whether a
> share/invite mutation endpoint exists must be confirmed against `referrals.ts` and
> `/openapi.json` before freezing DTOs. This ticket implements **read + client-side share only**;
> any server-side "send invite" endpoint is out of scope and would be a follow-up ticket.

## 6. Data & State Management

- **In-memory state:** `ReferralsUiState` exposed as `StateFlow` with
  `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), Loading)`.
- **Cache (Room 2.6, via core-data):** a single-row `ReferralEntity` keyed by the current user
  id, written after every successful fetch. The repository's `observe()` emits the cached entity
  so the UI can render instantly and the `Content.isStale` flag is set when displayed data came
  from cache without a fresh network confirmation (FR-8). No `DataStore` use is required; Room is
  the cache and there are no user-tunable prefs for this screen.
- **Refresh policy:** fetch on first composition and on explicit pull-to-refresh (FR-5). Stats
  are low-cardinality and non-paginated — **Paging 3 is N/A** here.
- **Single source of truth:** network writes Room; UI reads Room; this keeps share/copy actions
  operating on the same `link` the user sees.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the AND-027 OkHttp client's ~20s call timeout. `GET /ui/referrals` is
  idempotent, so it is eligible for **bounded exponential backoff** (max 2 retries, e.g. 0.5s/1s
  with jitter) on transient network/`5xx` failures.
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
  permits this cleartext host for dev builds only (owned by core-network). Release builds must
  not ship a cleartext referral link host.
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
  category, cache hit/miss. Redact the link to its trailing code (`…/r/AB12CD`).
- No analytics payload contains the full link, cookies, or user PII.

## 11. Testing Strategy

- **Unit (core-testing + JUnit + Turbine):**
  - `ReferralsViewModel` state transitions: `Loading → Content`, `→ Ineligible`,
    `→ SessionExpired`, `→ Error(retryable)`; `onRefresh` sets/clears `isRefreshing`.
  - DTO→domain mapping: snake_case decode, null `stats` → zeros, `enabled=false` → `Ineligible`,
    null reward fields hidden.
  - Event emission: `onShareClicked`/`onCopyClicked` emit the correct `ReferralsEvent` with the
    current link.
- **Network (MockWebServer):** `ReferralsApi.getReferrals()` hits `GET /ui/referrals`, parses the
  200 body, and surfaces `401`/`404`/`500`/timeout into the right `ApiResult` (mirrors the
  AND-027 MockWebServer pattern).
- **Repository:** cache-then-network ordering; offline path returns cached `Referral` with stale
  flag; backoff retry invoked on transient failure for the GET only.
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

- **OQ-1 (contract):** exact endpoint path and field names are inferred from `referrals.ts`;
  must be reconciled with `/openapi.json`. **Mitigation:** isolate decoding in DTOs so a rename
  is a one-line `@Json` change.
- **OQ-2 (scope):** does a server-side invite-send/track endpoint exist? Current scope is
  read + client-side share; a send endpoint would be a follow-up ticket.
- **OQ-3 (reward semantics):** are credits monetary or points? Affects formatting/units in tiles.
  Default to plain integer count + label until confirmed.
- **Risk — unreliable dev host:** flaky `/ui/referrals` could mask real bugs. **Mitigation:**
  MockWebServer-driven tests are authoritative; offline/stale UI covers live flakiness.
- **Risk — share deep-link:** if the referral link is itself an app deep link, attribution wiring
  is owned elsewhere; this ticket only shares the URL string.

## 14. Acceptance Criteria

- **AC-1:** For an authenticated user, opening Referrals issues `GET /ui/referrals` and renders
  the **referral link** and **stats** tiles on success (the backlog acceptance — "Referral link +
  stats render").
- **AC-2:** "Share" launches the system share sheet (`ACTION_SEND`, `text/plain`) containing the
  referral link; "Copy link" copies the link and shows a confirmation Snackbar.
- **AC-3:** `enabled=false`/`404`/empty payload renders the **Ineligible** empty state with
  Share/Copy disabled.
- **AC-4:** A hard `401` (after AND-027 refresh+retry) renders **SessionExpired** and routes
  toward sign-in; transient `5xx`/timeout renders a retryable **Error**.
- **AC-5:** With a cached entity and no network, the screen renders cached link/stats with a
  "saved data" banner.
- **AC-6:** Pull-to-refresh re-fetches and updates the tiles, toggling `isRefreshing`.
- **AC-7:** MockWebServer tests confirm `ReferralsApi` path/verb and that 200/401/404/500/timeout
  map to the correct `ApiResult`/state. All new strings are localized; actions are TalkBack-labeled.

## 15. Definition of Done

- `:feature-referrals` module and `ReferralsApi`/DTOs merged on the `android-port` branch under
  `com.testlogon.android.*`; navigation entry wired in `app`.
- All §14 acceptance criteria pass; unit, MockWebServer, repository, and Compose UI tests are
  green in CI.
- `./gradlew :feature-referrals:test :feature-referrals:lint` clean; no hardcoded strings; no
  cleartext referral host in release config.
- Telemetry events (§10) emitted and verified; logs redact the link.
- OQ-1/OQ-2 resolved against `/openapi.json` (or explicitly deferred with follow-up tickets
  filed); code review approved; spec status moved from `draft` to `accepted`.
