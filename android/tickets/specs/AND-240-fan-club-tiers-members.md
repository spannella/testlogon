---
id: AND-240
title: Fan-club tiers / members
milestone: M5
epic: E32
priority: P2
size: M
status: draft
depends_on: [AND-238, AND-234, AND-027]
blocks: []
---

# AND-240 — Fan-club tiers / members

## 1. Overview & Goal

This ticket delivers the **Fan-club tier members** screen for the native Android port of TestLogon. Within a fan club, content is organized into **tiers** (subscription levels). Each tier has an associated set of **members** — the users who are currently subscribed at that tier. This screen renders the member roster for a single tier, identified by tier `id`, backed by the endpoint `GET /ui/fan-club/tiers/{id}/members`.

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

**FR-4 — Member count.** If the response (or AND-234 tier metadata) exposes a total member count, render it in the screen header (e.g., "128 members"). If unavailable, omit the count rather than showing a placeholder number.

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
    Pager(PagingConfig(pageSize = 30, prefetchDistance = 10, enablePlaceholders = false)) {
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

**Endpoint:** `GET /ui/fan-club/tiers/{id}/members`

Path param: `id` = tier id (string). Query params (confirm exact names against `/openapi.json` and `frontend/src/api/endpoints`):
- `cursor` (string, optional) — opaque pagination cursor; omitted for first page.
- `limit` (int, optional) — page size (default 30).

Headers: cookie session + `X-CSRF-Token` (from `ui_csrf` cookie) applied by the shared OkHttp interceptor (AND-027). This is an idempotent GET → eligible for bounded backoff retry.

**Expected 200 response** (cursor-paginated; adapt field names to actual schema):

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
    @GET("ui/fan-club/tiers/{id}/members")
    suspend fun getTierMembersResult(
        @Path("id") tierId: String,
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int,
    ): ApiResult<TierMembersPageDto>
}
```

**Error mapping:** FastAPI `detail` may be `string | [{msg}] | {code,...}` → mapped via the shared error mapper (AND-027) to a user-facing message. `401` triggers the single `POST /ui/session/refresh` + retry handled by the auth interceptor; `404` (tier not found) maps to a dedicated "Tier not found" error state; `403` (not entitled to view members) maps to a permission error message.

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

**Test data:** MockWebServer fixture JSON mirroring §5; one multi-page fixture to exercise cursor pagination. Validate field names against a captured live `/ui/fan-club/tiers/{id}/members` response before finalizing.

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

1. Navigating to `TierMembersRoute(tierId)` issues `GET /ui/fan-club/tiers/{id}/members` with the correct id and renders a scrollable list of member rows (avatar, display name, tier label). **(Backlog: "Members list renders.")**
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
