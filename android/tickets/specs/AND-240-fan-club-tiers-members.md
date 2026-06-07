---
id: AND-240
title: Fan-club tiers / members
milestone: M5
epic: E32
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-238, AND-234, AND-027]
blocks: []
---

# AND-240 — Fan-club tiers / members

## 1. Overview & Goal

This ticket delivers the **Fan-club tier members** screen for the native Android port of TestLogon. Within a fan club, content is organized into **tiers** (subscription levels). Each tier has an associated set of **members** — the users who are currently subscribed at that tier. This screen renders the member roster for a single tier, identified by tier `id`, backed by the endpoint `GET /ui/fan-club/tiers/{tier_id}/members` (verified: OpenAPI `GET /ui/fan-club/tiers/{tier_id}/members`, op `api_tier_members_ui_fan_club_tiers__tier_id__members_get`; the path parameter is named `tier_id`, not `id`).

The goal is a paginated, scrollable list of tier members with avatar, display name, tier badge, and join/subscription metadata, with correct loading / empty / error / offline states. The list must render correctly against the live dev backend, including its unreliable-host characteristics (slow responses, transient 5xx, plaintext HTTP). This is a **read-only** feature in this ticket: no member management (kick/promote/invite) is in scope; those are deferred (see §3, §13).

Success is defined narrowly by the backlog acceptance: **the members list renders**. This spec expands that into testable criteria (§14) covering pagination, state handling, and accessibility while keeping write-path features out of scope.

## 2. Context & References

- **Repo:** `spannella/testlogon`, monorepo; Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Feature module:** `feature-fanclub` (shared with AND-238 channels list and AND-239 channel messages). This ticket adds a `tiers/members` package within that module.
- **Dependency AND-238 (Fan-club channels list):** establishes the `feature-fanclub` module, fan-club navigation graph, the `FanClubApi` Retrofit interface skeleton, and the fan-club repository pattern. AND-240 builds on those structures and reuses navigation entry points (a tier row in the channels/tiers overview navigates here).
- **Dependency AND-234 (Subscriptions API + DTOs):** defines the canonical `Tier`/subscription DTOs and the tier↔subscription mapping (`subscriptions.ts` parity). AND-240 reuses `Tier` identifiers and tier-badge presentation from there; member DTOs in this ticket reference the same tier model.
- **Transitive AND-027:** core network/session scaffolding (cookie jar, CSRF header, `ApiResult<T>`, error mapping).
- **Web reference:** `frontend/src/api/endpoints/*.ts` (fan-club endpoints) and shared types in `frontend/src/api/types.ts`. The members endpoint shape MUST be confirmed against `frontend/` and `/openapi.json` during implementation.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil, Paging 3. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

**FR-1 — Entry & arguments.** The screen is reachable via a typed route carrying the tier `id` (and, for header display, an optional `tierName`). Navigated to from the fan-club tiers/channels overview (AND-238) by tapping a tier's "members" affordance.

**FR-2 — Member list render.** Display members of the tier as a vertical list. Each row shows: avatar (Coil, circular, placeholder on load/failure), display name, optional handle/`@username`, the tier badge/label, and a subscription-since/join label when present.

**FR-3 — Pagination.** The list is paginated via Paging 3 using the backend's cursor/offset scheme (confirmed against OpenAPI). Scrolling near the end loads the next page; a footer shows an inline progress indicator while appending and an inline retry control on append failure.

**FR-4 — Member count.** If the response (or tier metadata) exposes a total member count, render it in the screen header (e.g., "128 members"). A reliable source exists: `TierOut.member_count` (non-optional `number`) — **VERIFIED** in `src/api/types.ts: TierOut` and rendered by the web app as "{n} member(s)" in `src/pages/fan-club/FanClubPage.tsx`. The screen may pass `member_count` via the route (alongside `tierName`) and/or read `total` from the members response if present. If unavailable, omit the count rather than showing a placeholder number.

**FR-5 — Loading state.** Initial load shows a skeleton/placeholder list or centered progress indicator.

**FR-6 — Empty state.** When the tier has zero members, show an explicit empty state ("No members yet") rather than a blank screen.

**FR-7 — Error & offline states.** Network/HTTP failures on the first page show a full-screen error state with a **Retry** action. Append failures show an inline footer error with retry (FR-3). Stale cached data, when present, is shown with a non-blocking "offline / showing cached" indicator.

**FR-8 — Refresh.** Pull-to-refresh re-fetches page 1 and invalidates the Paging source.

**FR-9 — Member row tap (deferred target).** Tapping a member row navigates to a member/profile detail if such a route exists; otherwise the row is non-interactive in this ticket. No write actions (remove/promote) are implemented here.

**Out of scope:** member management mutations, tier creation/editing, subscription purchase flows (AND-234 owns subscription DTOs/business logic), real-time member presence.

## 4. Technical Design

### 4.1 Module & package layout

```
feature-fanclub/
  src/main/kotlin/com/testlogon/android/feature/fanclub/
    tiers/members/
      TierMembersRoute.kt          // route + nav arg type
      TierMembersScreen.kt         // Compose UI
      TierMembersViewModel.kt
      TierMembersUiState.kt
      TierMembersPagingSource.kt
      model/TierMember.kt          // UI model
core-network/.../fanclub/
    FanClubApi.kt                  // shared Retrofit interface (extended here)
    dto/TierMemberDto.kt
    dto/TierMembersPageDto.kt
core-data/.../fanclub/
    FanClubRepository.kt           // extended with tierMembers(...)
```

### 4.2 Navigation

```kotlin
@Serializable
data class TierMembersRoute(val tierId: String, val tierName: String? = null)

fun NavGraphBuilder.tierMembersScreen(onMemberClick: (memberId: String) -> Unit) {
    composable<TierMembersRoute> { TierMembersScreen(onMemberClick = onMemberClick) }
}
```

The fan-club overview (AND-238) calls `navController.navigate(TierMembersRoute(tierId = tier.id, tierName = tier.name))`.

### 4.3 ViewModel & state

```kotlin
@HiltViewModel
class TierMembersViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: FanClubRepository,
) : ViewModel() {
    private val args = savedStateHandle.toRoute<TierMembersRoute>()

    val tierName: String? = args.tierName

    // Paging stream of members
    val members: Flow<PagingData<TierMember>> =
        repository.tierMembersPager(args.tierId)
            .flow
            .cachedIn(viewModelScope)

    // Header/aux state (member count, offline flag) separate from paging
    private val _header = MutableStateFlow(TierMembersHeaderState())
    val header: StateFlow<TierMembersHeaderState> = _header.asStateFlow()
}
```

```kotlin
data class TierMembersHeaderState(
    val totalCount: Int? = null,
    val isStale: Boolean = false,
)
```

Page-level load/empty/error states are derived in the Composable from `LoadState` of the `LazyPagingItems`, so we avoid duplicating a hand-rolled `UiState` for the list body. The `StateFlow` carries only header/auxiliary state, consistent with the project's "ViewModels expose StateFlow<UiState>" rule (here `TierMembersHeaderState` is the `UiState`).

### 4.4 Paging

```kotlin
class TierMembersPagingSource(
    private val api: FanClubApi,
    private val tierId: String,
) : PagingSource<String, TierMember>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, TierMember> {
        val cursor = params.key
        return when (val r = api.getTierMembersResult(tierId, cursor, params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = r.data.items.map { it.toUiModel() },
                prevKey = null,
                nextKey = r.data.nextCursor,
            )
            is ApiResult.Error -> LoadResult.Error(r.toThrowable())
        }
    }

    override fun getRefreshKey(state: PagingState<String, TierMember>) = null
}
```

Repository exposes:

```kotlin
fun tierMembersPager(tierId: String): Pager<String, TierMember> =
    // pageSize = 50 matches the server's documented `limit` default (max 200).
    Pager(PagingConfig(pageSize = 50, prefetchDistance = 10, enablePlaceholders = false)) {
        TierMembersPagingSource(api, tierId)
    }
```

### 4.5 UI

```kotlin
@Composable
fun TierMembersScreen(
    viewModel: TierMembersViewModel = hiltViewModel(),
    onMemberClick: (String) -> Unit,
    onBack: () -> Unit = {},
)
```

Body uses `LazyColumn` over `members.collectAsLazyPagingItems()`:
- `loadState.refresh` → `Loading` (skeleton), `Error` (full-screen error + Retry → `retry()`), `NotLoading` + `itemCount == 0` → empty state.
- `loadState.append` → footer progress / footer error (`Loading`/`Error`).
- Top app bar shows `tierName ?: "Members"` and, when `header.totalCount != null`, a subtitle with the count.
- Pull-to-refresh wraps the list and calls `refresh()` on the paging items.

Member row composable:

```kotlin
@Composable
fun TierMemberRow(member: TierMember, onClick: () -> Unit)
```

## 5. API Contract

**Endpoint:** `GET /ui/fan-club/tiers/{tier_id}/members` — **VERIFIED** against OpenAPI (`GET /ui/fan-club/tiers/{tier_id}/members`, op `api_tier_members_ui_fan_club_tiers__tier_id__members_get`).

Path param: `tier_id` = tier id (string). **VERIFIED** query params (OpenAPI `params=tier_id,limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`):
- `cursor` (string, optional, nullable) — opaque pagination cursor; omitted for first page. **VERIFIED** (param `cursor`).
- `limit` (int, optional) — page size. **VERIFIED** param `limit`; OpenAPI schema: `default: 50, minimum: 1, maximum: 200`. (Corrected: the original draft said default 30; the *server* default is 50. We intentionally send an explicit `limit` from the client, so the Paging config below pins `pageSize = 50` to match the server default and stay ≤ 200.)
- Server also accepts `user_sub` (query) and `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers) — all optional; the mobile client does not set `user_sub`/`X-SESSION-ID` directly (see auth note).

Headers / auth: the web reference client (`src/api/client.ts`) sends `Authorization: Bearer <accessToken>`, the `X-CSRF-Token` header (value from the `ui_csrf` cookie), and `credentials: "include"` (cookie jar), plus `X-IMPERSONATION-TOKEN` when impersonating. **Correction:** the original draft listed only "cookie session + `X-CSRF-Token`" and omitted the `Authorization: Bearer` token; the Android client must replicate the *full* set (Bearer + cookie jar + `X-CSRF-Token`) via the shared OkHttp interceptor (AND-027). This is an idempotent GET → eligible for bounded backoff retry.

**Expected 200 response** — **UNVERIFIED ASSUMPTION.** The OpenAPI 200 response schema for this operation is empty (`"schema": {}`, i.e. untyped `Successful Response`), and there is **no** frontend caller for this endpoint (`src/api/endpoints/fan-club.ts` has no `getTierMembers`; the web app only renders `TierOut.member_count` on `FanClubPage.tsx`, never a roster). The shape below (envelope with `items` / `next_cursor` / `total`, and the per-member field names) is therefore a *proposed* contract that MUST be confirmed against a captured live response before finalizing DTOs (see §13 R1, §16 Open assumptions). Field names are illustrative:

```json
{
  "items": [
    {
      "user_id": "usr_8f3a",
      "username": "kestrel",
      "display_name": "Kestrel",
      "avatar_url": "https://.../avatar.jpg",
      "tier_id": "tier_gold",
      "tier_name": "Gold",
      "subscribed_since": "2026-01-14T09:22:00Z"
    }
  ],
  "next_cursor": "eyJrIjoiMzAifQ==",
  "total": 128
}
```

If the backend returns a bare list (no envelope), the repository wraps it into a single non-paged result with `next_cursor = null` and `total = items.size`; Paging then yields a single page.

**DTOs (Moshi):**

```kotlin
@JsonClass(generateAdapter = true)
data class TierMembersPageDto(
    @Json(name = "items") val items: List<TierMemberDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)

@JsonClass(generateAdapter = true)
data class TierMemberDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "username") val username: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    @Json(name = "tier_id") val tierId: String? = null,
    @Json(name = "tier_name") val tierName: String? = null,
    @Json(name = "subscribed_since") val subscribedSince: String? = null,
)
```

**Retrofit:**

```kotlin
interface FanClubApi {
    // Path placeholder name must be {tier_id} to match the OpenAPI path param.
    @GET("ui/fan-club/tiers/{tier_id}/members")
    suspend fun getTierMembersResult(
        @Path("tier_id") tierId: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int,   // send explicit page size (≤ 200; default 50)
    ): ApiResult<TierMembersPageDto>
}
```

**Error mapping:** FastAPI `detail` may be `string | [{msg}] | {code,...}` → mapped via the shared error mapper (AND-027) to a user-facing message. **VERIFIED** against `src/api/client.ts: normalizeErrorDetail` (handles string detail, array-of-`{msg}`, and object detail with a `code` field via `mapAuthorizationError`). `401` triggers the single `POST /ui/session/refresh` + retry — **VERIFIED** in `client.ts` (single in-flight `refreshPromise`, then one retry; on retry-401 it logs out). **Caveat (unverified for this endpoint):** the OpenAPI declares only `200` and `422:HTTPValidationError` for this operation — `404` and `403` are **not** documented here. We still defensively map `404`→"Tier not found" and `403`→permission message (403 handling is generic in the web client, `client.ts`), but these specific codes for this path are an assumption, not a documented contract. `422` (validation, e.g. bad `cursor`) maps to a generic error via the `detail` array shape.

## 6. Data & State Management

- **UI model:**
```kotlin
data class TierMember(
    val userId: String,
    val displayName: String,     // displayName ?: username ?: userId
    val handle: String?,         // "@username"
    val avatarUrl: String?,
    val tierLabel: String?,
    val subscribedSince: Instant?,
)
```
`TierMemberDto.toUiModel()` resolves the display-name fallback chain and parses `subscribed_since` (ISO-8601) leniently — unparseable/null dates yield `null` and the row omits the join label.

- **Paging state** owned by Paging 3 / `LazyPagingItems`; not duplicated in the ViewModel.
- **Header state** (`TierMembersHeaderState`) is a `StateFlow`, surviving config changes via the ViewModel.
- **Caching (Room 2.6):** optional in this ticket. If AND-238 established a fan-club Room cache, members for a tier MAY be cached keyed by `tierId` to support offline render with an `isStale` flag (FR-7). If no cache infra exists yet, this is deferred and `isStale` stays `false`; the full-screen error state is the offline behavior. Do not build new Room infra solely for this screen — reuse only.
- **Process death:** `tierId`/`tierName` survive via `SavedStateHandle.toRoute`. Paging restarts cleanly on recreation.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the global OkHttp ~20s call timeout (AND-027). No per-call override.
- **Retry:** GET is idempotent → bounded exponential backoff (e.g., 3 attempts, capped) via the shared retry interceptor for transient `5xx`/IO. UI **Retry** (`refresh()`) and footer retry (`retry()`) cover exhausted/initial failures.
- **State matrix:**
  - Refresh `Loading` → skeleton.
  - Refresh `Error` → full-screen error + Retry.
  - Refresh `NotLoading` & empty → empty state.
  - Append `Loading` → footer spinner.
  - Append `Error` → footer error + retry (preserves already-loaded rows).
- **401:** single `POST /ui/session/refresh` then retry (auth interceptor); persistent failure surfaces as error state and, upstream, may route to re-auth.
- **Malformed JSON / partial rows:** Moshi non-strict; missing optional fields tolerated. A row missing `user_id` is dropped during mapping (filterNotNull) rather than crashing the page.
- **Unreliable host:** assume slow first byte; skeleton must appear immediately; no ANR-inducing main-thread work (all I/O on `Dispatchers.IO` via Retrofit suspend).

## 8. Security & Privacy

- Member rosters are personal data (usernames, avatars, subscription dates). Render only fields the endpoint authorizes for the current session; do not log PII (no full member payloads in logs — see §10).
- Auth is cookie-based; the persistent cookie jar + `X-CSRF-Token` echo is provided by AND-027. This screen issues only authenticated GETs.
- **Plaintext HTTP dev caveat:** the dev backend is `http://`; cleartext is permitted only for the dev build's network-security-config (inherited from core-network). Release builds MUST NOT allow cleartext to this host. No new cleartext exemptions are added by this ticket.
- Avatar images load over Coil from backend-provided URLs; treat as untrusted (no special handling beyond Coil defaults). No member data is persisted beyond the optional reuse of existing encrypted-at-rest-by-OS Room cache.

## 9. Accessibility & i18n

- All strings in `feature-fanclub` `strings.xml`: screen title, "members" count (use a plurals resource `R.plurals.fanclub_member_count`), empty/error/retry, footer states. No hardcoded UI text.
- Avatar `Image` uses a `contentDescription` derived from display name (e.g., "Avatar for Kestrel"); decorative-only placeholder is `null`.
- Each member row exposes a single merged semantics node (`Modifier.semantics(mergeDescendants = true)`) reading "Kestrel, @kestrel, Gold tier, member since January 2026".
- Touch targets ≥ 48dp; supports dynamic type / font scaling; row layout reflows without truncation loss at large scale.
- Material 3 color tokens for contrast; verified in light/dark. Date labels formatted via `java.time` + locale-aware formatter.

## 10. Telemetry & Logging

- **Screen view:** log `fanclub_tier_members_viewed` with `tier_id` (no member identities).
- **Load outcomes:** log refresh success with `item_count` and `total` (counts only), and refresh/append errors with `error_kind` + `http_status` (no payload bodies, no PII).
- Use the project's existing analytics abstraction (if present from earlier tickets); otherwise gate behind the standard logging facade. Debug-only OkHttp `HttpLoggingInterceptor` at `BASIC`/`HEADERS` (never `BODY` in shipped builds, to avoid logging member PII).
- No new telemetry SDK is introduced by this ticket.

## 11. Testing Strategy

**Unit (core-testing, JVM):**
- `TierMemberDto.toUiModel()` — display-name fallback chain (display_name → username → user_id), date parsing (valid, null, garbage), handle formatting.
- Envelope vs. bare-list response handling in the repository.
- Error mapping: `404`→tier-not-found, `403`→permission, `5xx`→generic, FastAPI `detail` variants.

**PagingSource tests:**
- `load()` first page (null cursor) returns `Page` with `nextKey` = `next_cursor`.
- `load()` last page (`next_cursor == null`) returns `nextKey = null`.
- `load()` on `ApiResult.Error` returns `LoadResult.Error`.
- Use a fake `FanClubApi` returning canned `ApiResult`.

**Repository test:** `tierMembersPager` wired to fake api yields expected `PagingData` (via `AsyncPagingDataDiffer` or snapshot helper).

**Compose UI tests (instrumented or Robolectric):**
- List renders rows for a fake page (asserts display name + tier label nodes) — covers the backlog acceptance.
- Empty state shown for empty page.
- Full-screen error + Retry shown on refresh error; Retry invokes reload.
- Footer error/retry on append failure.
- Pull-to-refresh triggers reload.

**Test data:** MockWebServer fixture JSON mirroring §5; one multi-page fixture to exercise cursor pagination. Validate field names against a captured live `/ui/fan-club/tiers/{tier_id}/members` response before finalizing (the 200 body shape is an unverified assumption — see §16).

## 12. Dependencies & Sequencing

- **Hard dep AND-238** — fan-club module, navigation graph, `FanClubApi`/repository scaffolding, tier overview entry point. Must merge first.
- **Hard dep AND-234** — `Tier` DTOs and tier-badge presentation reused for member tier labels.
- **Transitive AND-027** — cookie jar, CSRF, `ApiResult<T>`, error mapper, OkHttp client (timeouts/retry/logging).
- **Sequencing:** implement DTOs + Retrofit method → repository pager + PagingSource (unit-tested) → ViewModel → Compose screen → wire nav from AND-238 overview → instrumented UI tests.
- **Blocks:** none currently. A future member-profile detail ticket (if created) would depend on this screen's row-tap callback (FR-9).

## 13. Risks & Open Questions

- **R1 — Endpoint shape unconfirmed.** Pagination param names (`cursor` vs `page`/`offset`), envelope vs. bare list, and `total` presence must be verified against `/openapi.json` and `frontend/`. *Mitigation:* confirm before finalizing DTOs; repository normalizes both shapes.
- **R2 — Member detail navigation.** No confirmed member-profile route; FR-9 is conditional. *Open question:* does a profile screen exist/should rows be tappable? Default: non-interactive rows.
- **R3 — Large rosters.** Very large tiers stress Paging/avatars. *Mitigation:* `pageSize=30`, `prefetchDistance=10`, Coil memory cache, no placeholders.
- **R4 — Unreliable dev host** may cause flaky instrumented tests. *Mitigation:* tests use MockWebServer, not the live host.
- **R5 — Caching scope.** Offline render depends on whether AND-238 built a fan-club Room cache. *Open question:* reuse vs. defer; default defer (error state offline).

## 14. Acceptance Criteria

1. Navigating to `TierMembersRoute(tierId)` issues `GET /ui/fan-club/tiers/{tier_id}/members` with the correct id and renders a scrollable list of member rows (avatar, display name, tier label). **(Backlog: "Members list renders.")**
2. Each row shows the resolved display name (fallback chain) and tier label; join date shown when parseable, omitted otherwise.
3. Initial load shows a loading state; populated list replaces it on success.
4. Empty tier shows the explicit empty state, not a blank screen.
5. Refresh failure shows a full-screen error with a working **Retry**; append failure shows a footer error with a working retry that preserves loaded rows.
6. Pagination loads subsequent pages on scroll using the cursor, terminating cleanly when `next_cursor` is null.
7. Pull-to-refresh reloads page 1.
8. `401` triggers a single session refresh + retry transparently (no duplicate refreshes).
9. Member count rendered in header when `total` is present; omitted otherwise (locale-aware plurals).
10. No PII in logs; no `BODY`-level HTTP logging in shipped builds.
11. Accessibility: avatar content descriptions present, rows expose merged semantics, targets ≥ 48dp.
12. All listed unit, PagingSource, repository, and Compose UI tests pass.

## 15. Definition of Done

- Code merged to `android-port` under `feature-fanclub` with package base `com.testlogon.android`.
- DTOs, Retrofit method, repository pager, PagingSource, ViewModel, and Compose screen implemented per §4–§6.
- Navigation wired from the AND-238 fan-club overview; route is type-safe.
- Endpoint field names verified against `/openapi.json` and `frontend/` reference.
- All §11 tests written and green in CI; module builds with AGP 8.7.3 / Gradle 8.9 / JDK 17; KSP/Hilt compile clean.
- Lint passes; no hardcoded strings; a11y checks satisfied; no new cleartext exemptions; no PII logging.
- Verified rendering against the live dev backend (or captured fixture) including loading/empty/error/offline states.
- Spec acceptance criteria (§14) demonstrably met; PR description links AND-240 and notes resolution of open questions R1–R2.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict (Verified / Corrected / Unverified-assumption), and the exact source pointer.

1. **Endpoint path is `GET /ui/fan-club/tiers/{tier_id}/members`.** — **Corrected** (draft said `{id}`; param is `tier_id`). Source: OpenAPI `GET /ui/fan-club/tiers/{tier_id}/members`, op `api_tier_members_ui_fan_club_tiers__tier_id__members_get`.
2. **HTTP method is GET, idempotent.** — **Verified.** Source: OpenAPI `GET /ui/fan-club/tiers/{tier_id}/members`.
3. **Query param `cursor` (string, nullable, optional).** — **Verified.** Source: OpenAPI op params `...,cursor,...`; full spec param `cursor` `anyOf:[string,null]`.
4. **Query param `limit` (int).** — **Verified (name)**; **Corrected (default).** Draft said default 30; OpenAPI schema is `default: 50, minimum: 1, maximum: 200`. Source: OpenAPI full spec, `limit` schema for this op.
5. **Server also accepts `user_sub` (query), `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` (headers), all optional.** — **Verified.** Source: OpenAPI op `params=tier_id,limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`.
6. **Auth/transport: Bearer token + cookie jar + `X-CSRF-Token` (from `ui_csrf` cookie), `credentials: include`; impersonation via `X-IMPERSONATION-TOKEN`.** — **Corrected** (draft omitted the `Authorization: Bearer` token, listing only "cookie session + X-CSRF-Token"). Source: `src/api/client.ts` (`api()` sets `Authorization: Bearer <accessToken>`, `X-CSRF-Token` from `getCookie("ui_csrf")`, `credentials:"include"`, and `X-IMPERSONATION-TOKEN`).
7. **401 → single in-flight `POST /ui/session/refresh`, then one retry; persistent 401 logs out.** — **Verified.** Source: `src/api/client.ts` (`refreshPromise` single-flight, `refreshSession()` → `POST /ui/session/refresh`, retry once, logout on retry-401).
8. **FastAPI `detail` may be `string | [{msg}] | {code,...}`; mapped to a user-facing message.** — **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` and `mapAuthorizationError`.
9. **403 produces a permission/denied message (generic handling).** — **Verified (generic), Unverified for this path.** 403 handling is generic in `src/api/client.ts` (403 branch, incl. `geo_blocked`), but the OpenAPI for this op declares only `200` and `422`, so a 403 specifically from this endpoint is not a documented contract.
10. **404 → "Tier not found" error state.** — **Unverified-assumption.** OpenAPI declares only `200`/`422` for this op; no `404` documented. Defensive mapping only.
11. **422 validation error shape is `HTTPValidationError`.** — **Verified.** Source: OpenAPI op `resp=...;422:HTTPValidationError`.
12. **200 response body shape (envelope `{items, next_cursor, total}` and per-member fields `user_id`/`username`/`display_name`/`avatar_url`/`tier_id`/`tier_name`/`subscribed_since`).** — **Unverified-assumption.** OpenAPI 200 schema is empty (`"schema": {}`); no frontend caller exists (`src/api/endpoints/fan-club.ts` has no members function). Must be confirmed against a captured live response. Source: OpenAPI full spec (empty 200 schema); `src/api/endpoints/fan-club.ts` (absence).
13. **Tier identity/name/badge come from `TierOut` (`tier_id`, `name`, `level`, `color`, `badge_emoji`, `badge_image_url`).** — **Verified.** Source: `src/api/types.ts: TierOut`; badge presentation `src/api/types.ts: MemberBadgeData` and `src/pages/fan-club/FanClubPage.tsx` (`MemberBadge`).
14. **A reliable total member count exists as `TierOut.member_count` (non-optional).** — **Verified.** Source: `src/api/types.ts: TierOut.member_count`; rendered "{n} member(s)" in `src/pages/fan-club/FanClubPage.tsx`.
15. **No web member-roster screen / no member-profile navigation target (FR-9 conditional).** — **Verified (absence).** Source: `src/api/endpoints/fan-club.ts` (no members call) and `src/pages/fan-club/FanClubPage.tsx` (renders count only, no roster/route).
16. **Sibling fan-club endpoints used by deps AND-238/AND-239 exist (`GET /ui/fan-club/channels`, `GET /ui/fan-club/channels/{channel_id}/messages`).** — **Verified.** Source: OpenAPI `GET /ui/fan-club/channels`, `GET /ui/fan-club/channels/{channel_id}/messages` (params `channel_id,limit,before,...`); `src/api/endpoints/fan-club.ts: listChannels/getChannelMessages`.
17. **Plurals for member count are appropriate (locale-aware `R.plurals.fanclub_member_count`).** — **Verified (behavioral parity).** Web uses singular/plural switch on `member_count` in `src/pages/fan-club/FanClubPage.tsx`; Android plurals resource is the framework-correct equivalent. (framework ref: https://developer.android.com/guide/topics/resources/string-resource#Plurals)
18. **Paging 3 with `PagingSource`/`Pager`/`cachedIn`/`collectAsLazyPagingItems` and `LoadState`-driven refresh/append states.** — **Verified (framework choice).** (framework ref: https://developer.android.com/topic/libraries/architecture/paging/v3-overview and https://developer.android.com/topic/libraries/architecture/paging/load-state)
19. **Type-safe Navigation-Compose routes via `@Serializable` data class + `composable<Route>` + `savedStateHandle.toRoute()`.** — **Verified (framework choice).** (framework ref: https://developer.android.com/guide/navigation/design/type-safety)
20. **Cleartext HTTP to the dev host requires a network-security-config exemption; release must not allow cleartext.** — **Verified (framework behavior).** Android blocks cleartext by default since API 28. (framework ref: https://developer.android.com/privacy-and-security/security-config)

### Corrections made

- **§1, §5, §4 (Retrofit):** path param `{id}` → `{tier_id}`; `@Path("id")` → `@Path("tier_id")`; URL template updated. (Audit #1)
- **§5, §4.4:** `limit`/`pageSize` server default corrected from 30 to **50** (max 200); Paging `pageSize` set to 50. (Audit #4)
- **§5 auth note:** added the missing `Authorization: Bearer <accessToken>` token to the documented header/auth set (draft listed only cookie + CSRF). (Audit #6)
- **§5 response:** the 200 envelope is now explicitly labeled an **unverified, proposed contract** (empty OpenAPI schema + no frontend caller), not a confirmed shape. (Audit #12)
- **§5 error mapping:** added caveat that `404`/`403` are **not** documented for this op (only `200`/`422`); these mappings are defensive assumptions. (Audit #9, #10)
- **§3 FR-4:** cited `TierOut.member_count` as the verified count source. (Audit #14)

### Open assumptions

- **Members response body shape** (envelope vs bare list; `items`/`next_cursor`/`total`; member field names and date format of `subscribed_since`). *Why:* OpenAPI 200 schema is empty and no web client calls this endpoint, so no authoritative shape exists. Resolve by capturing a live `/ui/fan-club/tiers/{tier_id}/members` response before locking DTOs. The repository already normalizes envelope-vs-bare-list (§5) to limit blast radius.
- **Pagination scheme** (cursor vs offset/page). *Why:* the `cursor` query param is documented, but whether the *response* carries a `next_cursor` is unverified (same root cause as above). If the server instead paginates by offset, `TierMembersPagingSource` key type/derivation must change.
- **404/403 emission by this endpoint.** *Why:* undocumented for this op; behavior (e.g., 404 for unknown tier, 403 for non-entitled viewer) must be confirmed empirically.
- **Whether a member-profile detail route exists (FR-9).** *Why:* no such route/screen exists in the web reference; row-tap remains a no-op until a detail ticket is created.
- **Whether AND-238 actually built a fan-club Room cache** (drives offline render / `isStale`). *Why:* depends on the as-merged AND-238 implementation, not inspectable from these sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). MockWebServer/contract and Compose-UI cases run on emu35 (fast, KVM) or Robolectric; cases needing real arm64/API-34 behavior or real-network/offline radios run on **A15**.

- **TC-AND-240-01 — Happy path: list renders.** Type: Compose-UI (Robolectric or emu35). Target: JVM/emu35. Preconditions: `FanClubApi` faked / MockWebServer serves a one-page fixture (envelope with 3 `items`, `next_cursor=null`, `total=3`) mirroring §5. Steps: navigate to `TierMembersRoute(tierId="tier_gold", tierName="Gold")`; let refresh complete. Expected: 3 member rows render with resolved display name + tier label nodes; no loading/empty/error UI. Traces: AC-1, AC-2, AC-3.
- **TC-AND-240-02 — DTO→UI mapping (display-name fallback, date parsing, handle).** Type: unit. Target: JVM. Preconditions: none. Steps: map DTOs covering (a) full `display_name`, (b) only `username`, (c) only `user_id`; (d) valid ISO `subscribed_since`, (e) null, (f) garbage string. Expected: display name = display_name→username→user_id; `handle="@username"` only when username present; `subscribedSince` parsed for (d), `null` for (e)/(f) and the join label omitted; a row missing `user_id` is dropped, not crashing. Traces: AC-2.
- **TC-AND-240-03 — PagingSource cursor paging.** Type: unit. Target: JVM. Preconditions: fake `FanClubApi` returns page1 (`next_cursor="c2"`) then page2 (`next_cursor=null`). Steps: call `load()` with `key=null`, then `key="c2"`. Expected: page1 → `LoadResult.Page(nextKey="c2", prevKey=null)`; page2 → `nextKey=null`; the second request sent `cursor=c2` and an explicit `limit` (≤200). Traces: AC-6.
- **TC-AND-240-04 — PagingSource error path.** Type: unit. Target: JVM. Preconditions: fake api returns `ApiResult.Error`. Steps: call `load()`. Expected: returns `LoadResult.Error` carrying the mapped throwable (does not throw). Traces: AC-5, AC-6.
- **TC-AND-240-05 — Contract: request line + headers (MockWebServer).** Type: contract/MockWebServer. Target: JVM/emu35. Preconditions: MockWebServer enqueues a 200 page. Steps: trigger first load via the repository. Expected: recorded request path is `/ui/fan-club/tiers/tier_gold/members?...`, method GET, `limit` present (1..200), no `cursor` on first page; headers include `Authorization: Bearer ...`, `X-CSRF-Token`, and the session cookie (per §5 auth correction). Traces: AC-1, AC-8.
- **TC-AND-240-06 — Empty state.** Type: Compose-UI. Target: JVM/emu35. Preconditions: fixture returns `items=[]`, `next_cursor=null`. Steps: open screen. Expected: explicit "No members yet" empty state shown (not a blank list, not an error). Traces: AC-4.
- **TC-AND-240-07 — Refresh error + Retry.** Type: Compose-UI/contract. Target: emu35. Preconditions: MockWebServer returns 503 for the first request, then a valid page on the next. Steps: open screen (see full-screen error), tap **Retry**. Expected: full-screen error with Retry on first failure; Retry issues a new request and the list populates. Traces: AC-5.
- **TC-AND-240-08 — Append error + footer retry preserves rows.** Type: Compose-UI/contract. Target: emu35. Preconditions: MockWebServer returns page1 (`next_cursor="c2"`) then 503 for the page2 request, then a valid page2. Steps: scroll to end (triggers append → footer error), tap footer retry. Expected: page1 rows remain visible throughout; footer shows error then progress then page2 rows append. Traces: AC-5, AC-6.
- **TC-AND-240-09 — Pull-to-refresh reloads page 1.** Type: Compose-UI. Target: emu35. Preconditions: page fixture; refresh count observable on the fake api/MockWebServer. Steps: perform pull-to-refresh gesture. Expected: paging source invalidated; a fresh first-page request (no `cursor`) is issued and list re-renders. Traces: AC-7.
- **TC-AND-240-10 — 401 single refresh + retry.** Type: contract/MockWebServer. Target: JVM/emu35. Preconditions: MockWebServer returns 401 once, expects exactly one `POST /ui/session/refresh`, then 200 on the retried members request. Steps: trigger load. Expected: exactly one refresh call and one retry of the members GET; final 200 renders; no duplicate refreshes (single-flight). Traces: AC-8.
- **TC-AND-240-11 — Member count header (plurals) & omission.** Type: Compose-UI (with locale variants). Target: JVM/emu35. Preconditions: (a) total/`member_count`=128, (b) =1, (c) absent. Steps: render header for each. Expected: (a) "128 members", (b) "1 member" via `R.plurals.fanclub_member_count`, (c) count omitted (no placeholder); correct under at least one non-English locale. Traces: AC-9.
- **TC-AND-240-12 — Accessibility: content descriptions, merged semantics, touch targets, font scale.** Type: Compose-UI (a11y assertions). Target: emu35. Preconditions: page fixture. Steps: assert semantics tree; render at large font scale. Expected: avatar has `contentDescription` derived from display name; each row is one merged semantics node reading name/handle/tier/since; touch targets ≥ 48dp; rows reflow without loss at large font scale. Traces: AC-11.
- **TC-AND-240-13 — No PII / no BODY logging in release.** Type: unit + build-config inspection. Target: JVM. Preconditions: release build config. Steps: assert `HttpLoggingInterceptor` level is not `BODY` in release; assert telemetry events (`fanclub_tier_members_viewed`, load outcomes) carry only `tier_id`/counts/`error_kind`/`http_status` and never member payloads. Expected: no PII fields and no `BODY`-level logging in shipped builds. Traces: AC-10.
- **TC-AND-240-14 — Offline / flaky dev-host behavior (real radios).** Type: instrumented/e2e (manual toggle of connectivity). Target: **A15 (physical device — MUST)**. Rationale: exercises the real arm64-v8a/API-34 networking stack and airplane-mode radio transitions that the x86 emulator does not faithfully reproduce, and validates the plaintext-HTTP dev-host path end-to-end. Preconditions: dev/debug build with the cleartext network-security-config; device reachable via adb. Steps: load the screen once online (cache populated if AND-238 cache exists); enable airplane mode; re-open / pull-to-refresh; re-enable connectivity and retry. Expected: with cache → stale rows shown with a non-blocking "offline / showing cached" indicator; without cache → full-screen error + working Retry; on reconnect, Retry/refresh repopulates. No ANR/crash; cleartext call succeeds only in the dev build. Traces: AC-5, AC-7.

### Coverage matrix (AC § → TC)

| AC (§14) | Covered by |
|---|---|
| AC-1 list renders + correct GET | TC-01, TC-05 |
| AC-2 display-name fallback + tier label + join date | TC-01, TC-02 |
| AC-3 loading→populated | TC-01 |
| AC-4 empty state | TC-06 |
| AC-5 refresh error+Retry / append error+retry preserving rows | TC-04, TC-07, TC-08, TC-14 |
| AC-6 cursor pagination terminates on null | TC-03, TC-04, TC-08 |
| AC-7 pull-to-refresh reloads page 1 | TC-09, TC-14 |
| AC-8 401 single refresh + retry | TC-05, TC-10 |
| AC-9 member count header / plurals / omission | TC-11 |
| AC-10 no PII / no BODY logging | TC-13 |
| AC-11 accessibility | TC-12 |
| AC-12 all unit/Paging/repo/Compose tests pass | TC-01–TC-13 (suite) |
