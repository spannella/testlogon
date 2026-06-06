---
id: AND-358
title: Collaborations + revenue
milestone: M7
epic: E46
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-358 — Collaborations + revenue

## 1. Overview & Goal

This ticket delivers the **Collaborations** feature surface for the TestLogon native
Android client: a read-and-act experience that lets an authenticated user view the
collaborations they participate in (joint projects/agreements between two or more
parties) and, for each collaboration, the **revenue split** that governs how proceeds
are distributed among collaborators.

The web reference implements this against `frontend/src/api/endpoints/collaborations.ts`.
The Android port mirrors that contract through a new `feature-collaborations` module that
plugs into the established module layering (`app -> feature-* -> core-*`). The user can:

1. List collaborations they belong to (Paging 3 backed, cookie-authenticated).
2. Open a collaboration detail screen showing participants, status, and the revenue
   split breakdown (per-party shares that sum to 100%).
3. See clear offline/stale/empty/error states given the unreliable dev backend.

**Definition of success (from backlog acceptance):** *"Collaboration + revenue render."*
Concretely: the list and detail screens render real data fetched from the backend, the
revenue split is displayed with correct per-party percentages/amounts, and all four UI
states (loading, content, empty, error) are exercised under test. Mutations
(create/edit collaboration, propose split changes) are explicitly **out of scope** and
deferred (see §3, §12).

## 2. Context & References

- **Epic E46 — Orgs, groups, syndicates, collaborations, delegates.** Sibling tickets:
  AND-353 (Orgs API + members/roles), AND-359 (Delegates / delegation API). This ticket
  reuses the org/party identity types those tickets and the core model expose.
- **Dependency AND-027 — AuthApi (session endpoints).** Provides the cookie-based
  session lifecycle (`/ui/session/start|finalize|refresh|logout`, `/ui/me`), the
  persistent cookie jar, the `ui_csrf` -> `X-CSRF-Token` echo, and the single-retry
  401 -> `/ui/session/refresh` behaviour. AND-358 consumes that authenticated OkHttp
  stack; it does not re-implement session handling.
- **Web reference:** `frontend/src/api/endpoints/collaborations.ts` (endpoint shapes,
  query params) and `frontend/src/api/types.ts` (Collaboration/RevenueSplit shapes).
  These are authoritative for field names and JSON structure.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (cache),
  Paging 3, Coil. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Error `detail` may be `string`,
  `[{msg}]`, or `{code,...}` — mapped via the shared error mapper from core-network.
- **Namespace:** all packages rooted at `com.testlogon.android`.

## 3. Functional Requirements

FR-1 **List collaborations.** The Collaborations list screen displays collaborations the
current user participates in, newest/most-recently-active first, paged via Paging 3. Each
row shows: collaboration title, status badge (`active` / `pending` / `closed`), the
participant count, and the user's own share percentage if present.

FR-2 **Collaboration detail.** Tapping a row navigates to a detail screen showing:
title, description, status, created/updated timestamps, the full participant list (each
with display name, party id, role), and the **revenue split** section.

FR-3 **Revenue split rendering.** The revenue split section renders one row per party with
that party's percentage (basis points or percent — see §5) and, when the backend supplies
monetary figures, the computed/known amount and currency. The UI shows a total row that
asserts the sum of percentages equals 100% (10000 bps); if it does not, a non-blocking
"split does not total 100%" warning is shown rather than failing the screen.

FR-4 **UI states.** Both screens implement loading, content, empty ("You have no
collaborations yet"), and error states. The detail screen additionally surfaces a
**stale** indicator when content is served from the Room cache while a refresh is in
flight or has failed.

FR-5 **Pull-to-refresh** on the list re-fetches page 1 and invalidates the Paging source.
Detail screen supports manual retry on error.

FR-6 **Auth gating.** All requests ride the authenticated cookie session from AND-027. An
unrecoverable 401 (after the one refresh retry) surfaces a "session expired" state that
routes the user back to sign-in via the app-level nav contract; AND-358 does not own that
routing logic, only the signal.

**Out of scope (deferred):** creating/editing collaborations, inviting parties, accepting
or proposing revenue-split changes, and payout execution. These are write paths owned by
later E46 tickets; AND-358 is read + render only.

## 4. Technical Design

New Gradle module **`feature-collaborations`** depending on `core-network`, `core-model`,
`core-data`, `core-ui`, and (test) `core-testing`. Package root
`com.testlogon.android.feature.collaborations`.

### 4.1 Layers

```
feature.collaborations.ui        Compose screens + ViewModels
feature.collaborations.domain    Repository interface, use cases
feature.collaborations.data      Repository impl, Retrofit API, Paging source, mappers
feature.collaborations.di        Hilt module
```

### 4.2 Retrofit API

```kotlin
package com.testlogon.android.feature.collaborations.data

interface CollaborationsApi {
    @GET("ui/collaborations")
    suspend fun list(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
        @Query("status") status: String? = null,
    ): CollaborationPageDto

    @GET("ui/collaborations/{id}")
    suspend fun detail(@Path("id") id: String): CollaborationDto

    @GET("ui/collaborations/{id}/revenue-split")
    suspend fun revenueSplit(@Path("id") id: String): RevenueSplitDto
}
```

All calls return through the core-network `ApiResult<T>` wrapper at the repository
boundary (Retrofit declares the raw DTO; the repository catches and maps).

### 4.3 Repository & domain

```kotlin
interface CollaborationsRepository {
    fun pagedCollaborations(status: CollaborationStatus? = null):
        Flow<PagingData<Collaboration>>
    suspend fun collaboration(id: String): ApiResult<Collaboration>
    suspend fun revenueSplit(id: String): ApiResult<RevenueSplit>
    fun observeCollaboration(id: String): Flow<Collaboration?>   // Room-backed, stale reads
}
```

`CollaborationsRepositoryImpl` is `@Singleton`, constructor-injected with
`CollaborationsApi`, the `CollaborationDao`, a `RemoteMediator`-free `PagingSource`
(`CollaborationPagingSource`) using the backend cursor, and the shared `ApiErrorMapper`.

### 4.4 ViewModels

```kotlin
@HiltViewModel
class CollaborationsListViewModel @Inject constructor(
    private val repo: CollaborationsRepository,
) : ViewModel() {
    val items: Flow<PagingData<CollaborationListItemUi>> =
        repo.pagedCollaborations().map { it.map(::toListItemUi) }.cachedIn(viewModelScope)
}

@HiltViewModel
class CollaborationDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: CollaborationsRepository,
) : ViewModel() {
    private val id: String = checkNotNull(savedStateHandle["collaborationId"])
    private val _state = MutableStateFlow<CollaborationDetailUiState>(Loading)
    val state: StateFlow<CollaborationDetailUiState> = _state.asStateFlow()
    fun load() { /* fetch detail + split concurrently, merge, emit */ }
    fun retry() = load()
}
```

`load()` launches `repo.collaboration(id)` and `repo.revenueSplit(id)` concurrently with
`async`, merges into the content state, and emits `Stale` when serving cached data while a
network refresh is pending or failed.

### 4.5 Navigation

Routes registered in app NavGraph:
`collaborations` (list) and `collaborations/{collaborationId}` (detail). Type-safe nav arg
`collaborationId: String`.

## 5. API Contract

Base: `http://18.222.237.167:8000`. All requests carry session cookies + `X-CSRF-Token`
(echo of `ui_csrf`) injected by the AND-027 OkHttp interceptor. These are idempotent GETs
and are therefore eligible for the bounded backoff retry policy.

### 5.1 List — `GET /ui/collaborations?cursor=&limit=20&status=active`

200 response:

```json
{
  "items": [
    {
      "id": "collab_01HZX...",
      "title": "Spring Campaign Joint Venture",
      "status": "active",
      "participant_count": 3,
      "viewer_share_bps": 3333,
      "updated_at": "2026-05-30T14:02:11Z"
    }
  ],
  "next_cursor": "eyJwayI6..."
}
```

`next_cursor` is `null`/absent on the last page.

### 5.2 Detail — `GET /ui/collaborations/{id}`

```json
{
  "id": "collab_01HZX...",
  "title": "Spring Campaign Joint Venture",
  "description": "Co-produced Q2 campaign.",
  "status": "active",
  "created_at": "2026-04-01T09:00:00Z",
  "updated_at": "2026-05-30T14:02:11Z",
  "participants": [
    { "party_id": "org_123", "display_name": "Acme Studio", "role": "lead" },
    { "party_id": "org_456", "display_name": "Bright Media", "role": "partner" },
    { "party_id": "usr_789", "display_name": "Sam P.", "role": "contributor" }
  ]
}
```

### 5.3 Revenue split — `GET /ui/collaborations/{id}/revenue-split`

```json
{
  "collaboration_id": "collab_01HZX...",
  "currency": "USD",
  "total_amount_minor": 1500000,
  "shares": [
    { "party_id": "org_123", "share_bps": 5000, "amount_minor": 750000 },
    { "party_id": "org_456", "share_bps": 3334, "amount_minor": 500100 },
    { "party_id": "usr_789", "share_bps": 1666, "amount_minor": 249900 }
  ]
}
```

`share_bps` is basis points (10000 = 100%). `total_amount_minor` and `amount_minor` are
minor currency units (cents) and **may be null** when no revenue has accrued; the UI then
renders percentages only. If `share_bps` values do not sum to 10000, the client renders
the warning from FR-3.

Moshi DTOs use `@Json(name=...)` for snake_case fields. Unknown JSON fields are ignored
(default Moshi behaviour) for forward-compatibility.

## 6. Data & State Management

- **Room cache (`core-data` schema):** `CollaborationEntity` (id PK, title, status,
  participant_count, viewer_share_bps, updated_at, json_blob, cached_at) plus
  `RevenueSplitEntity` (collaboration_id PK, currency, total_amount_minor, json_blob,
  cached_at). Detail + split are cached on successful fetch and read back via
  `observeCollaboration`/DAO flows for stale rendering. The **list** is served via a
  Paging 3 cursor `PagingSource` directly against the network (no `RemoteMediator` for v1)
  — cache covers detail/split where stale UX matters most.
- **DataStore (prefs):** stores last-selected status filter; no auth tokens (those live in
  the cookie jar from AND-027).
- **UI state types:**

```kotlin
sealed interface CollaborationDetailUiState {
    data object Loading : CollaborationDetailUiState
    data class Content(
        val collaboration: Collaboration,
        val split: RevenueSplit?,
        val splitTotalsValid: Boolean,
        val stale: Boolean,
    ) : CollaborationDetailUiState
    data object Empty : CollaborationDetailUiState           // detail unexpectedly absent
    data class Error(val message: String, val sessionExpired: Boolean) :
        CollaborationDetailUiState
}
```

- **Domain models** (`core-model`): `Collaboration`, `CollaborationStatus` enum
  (`ACTIVE`, `PENDING`, `CLOSED`, `UNKNOWN`), `Participant`, `RevenueSplit`,
  `RevenueShare`. Percentages are derived from bps in mappers
  (`bps / 100.0`) and formatted in the UI layer, never stored pre-formatted.

## 7. Error Handling & Resilience

- **Timeouts:** inherit the ~20s call timeout from the AND-027 OkHttp client (the dev host
  is slow/unreliable).
- **Retry:** GETs here are idempotent, so they use the shared bounded exponential backoff
  (e.g. 3 attempts, jittered) for transient failures (IO, 5xx). Non-idempotent calls do
  not exist in this ticket.
- **401:** the AND-027 interceptor performs the single `/ui/session/refresh` + retry. If it
  still fails, the repository maps to `ApiResult.AuthError`; ViewModels set
  `sessionExpired = true` so the app shell can route to sign-in.
- **Error mapping:** the FastAPI `detail` field (`string | [{msg}] | {code,...}`) is parsed
  by the shared `ApiErrorMapper` into a user-facing message; the detail screen shows it
  with a Retry button.
- **Stale-while-error:** when a refresh fails but a cached detail/split exists,
  `Content(stale = true)` is emitted instead of `Error`, with a subtle "Showing saved
  copy" banner.
- **Empty vs error:** a 200 with no items is `Empty`; a 404 on detail is `Empty`; network
  failure with no cache is `Error`.

## 8. Security & Privacy

- No new credentials introduced. Authentication is entirely the cookie session from
  AND-027; the persistent cookie jar and `X-CSRF-Token` echo apply to every request here.
- Revenue figures are financial PII-adjacent data: **never** log amounts, shares, or party
  identifiers at any level above `DEBUG`, and never in release builds (see §10). Room data
  is app-private storage; no export flag.
- The dev backend is plaintext HTTP — acceptable only for the dev `18.222.237.167:8000`
  host via the existing network-security-config cleartext allow-list; production builds
  must use HTTPS (enforced by the base config, not this ticket).
- No data is shared with third parties; Coil image loads (if avatars are added later) use
  the same authenticated client.

## 9. Accessibility & i18n

- All strings (titles, status labels, empty/error copy, "Showing saved copy") live in
  `feature-collaborations` `strings.xml`; no hardcoded UI text.
- Percentages and currency formatted with `NumberFormat`/`java.text` honoring the device
  locale; bps -> percent shown with at most 2 decimals.
- Status badges convey state with text + color (not color alone); each badge has a
  `contentDescription`.
- Revenue split rows are exposed to TalkBack as a single semantic unit per party
  ("Acme Studio, 50 percent, 7,500 dollars 00 cents"); the total row announces validity.
- Minimum 48dp touch targets on list rows and retry/refresh controls; supports dynamic
  font scaling without truncation in detail.

## 10. Telemetry & Logging

- **Events** (via core analytics facade): `collaborations_list_viewed`,
  `collaboration_detail_viewed { has_split: Boolean }`, `revenue_split_total_invalid`
  (fires when shares != 10000), `collaborations_refresh`, `collaborations_load_error
  { code }`. No financial values or party ids in event payloads.
- **Logging:** structured `Timber` tags `CollabRepo` / `CollabVM`. Network errors logged
  at `WARN` without bodies. Financial data redacted per §8. Release builds strip
  `DEBUG`/`VERBOSE` via the existing Timber release tree.

## 11. Testing Strategy

- **API contract (MockWebServer):** for each of the three endpoints, assert path/verb,
  query params, header presence (`X-CSRF-Token`), and Moshi deserialization of the §5
  shapes including null amounts and absent `next_cursor`.
- **Mapper unit tests:** bps -> percent rounding; split-totals-valid detection (10000 vs
  9999); `CollaborationStatus` fallback to `UNKNOWN` for unrecognized values; minor-unit
  -> currency formatting across locales.
- **Repository tests (`core-testing` fakes):** success caches to Room; network failure
  with cache yields stale content; 401 -> `AuthError`; paging cursor advancement and
  end-of-list.
- **PagingSource tests:** `load()` returns correct `LoadResult.Page` keys; refresh
  invalidation.
- **ViewModel tests (Turbine):** state sequence Loading -> Content; Loading -> Error ->
  retry -> Content; concurrent detail+split merge; `sessionExpired` propagation.
- **Compose UI tests:** list renders rows + empty state; detail renders participants +
  split with correct percentage text; invalid-total warning visible; stale banner visible;
  retry button invokes reload.
- **Acceptance gate:** an instrumentation/Robolectric test proves "Collaboration + revenue
  render" against canned responses — the list shows ≥1 collaboration and the detail shows
  all split shares with percentages.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-027 (AuthApi + authenticated OkHttp/cookie stack). This ticket
  cannot make authenticated requests without it.
- **Soft/shared:** `core-model` party/identity types overlap with AND-353 (Orgs); align
  `party_id` semantics to avoid duplicate models. Coordinate `Participant`/party id naming
  with AND-353 and AND-359.
- **Sequencing:** land after AND-027 is merged and the network module is stable. Can
  proceed in parallel with AND-353/AND-359 provided shared model fields are agreed first.
- **Blocks:** none currently; future write-path collaboration tickets (create/edit/payout)
  will depend on the DTOs and repository introduced here.

## 13. Risks & Open Questions

- **R1 — Endpoint shape uncertainty.** The §5 JSON is reconstructed from the web
  `collaborations.ts` contract and project conventions; the live `/openapi.json` must be
  diffed before implementation. *Action:* validate against OpenAPI; adjust Moshi `@Json`
  names. (Owner: implementer.)
- **R2 — bps vs percent vs decimal.** Backend unit for shares is assumed basis points; if
  it is actually a decimal fraction or percent, mappers and totals validation change.
  *Open question for backend.*
- **R3 — Split totals not summing to 100%.** Real data may legitimately not total 10000
  (rounding, withheld fees). Decided: warn, do not error. Confirm desired behaviour.
- **R4 — Unreliable dev host** may make UI test flakiness; mitigated by MockWebServer-based
  tests and stale-cache UX.
- **R5 — Currency/amount nullability** when no revenue accrued — handled by percent-only
  rendering; confirm no endpoint omits the `shares` array entirely.

## 14. Acceptance Criteria

AC-1 The Collaborations list screen loads via `GET /ui/collaborations`, renders rows with
title/status/participant count, pages with the backend cursor, and shows an empty state
when there are none. (Backlog: "Collaboration … render.")

AC-2 The detail screen loads `GET /ui/collaborations/{id}` and
`GET /ui/collaborations/{id}/revenue-split`, rendering participants and a revenue-split
breakdown with per-party percentages (and amounts when present). (Backlog: "… + revenue
render.")

AC-3 Revenue-split percentages are derived from `share_bps` correctly; a split not totaling
100% shows a non-blocking warning and still renders.

AC-4 Loading, content, empty, error, and stale states are all reachable and verified by
tests.

AC-5 All three endpoints are MockWebServer-tested for path/verb/headers/body mapping,
including null amounts and end-of-list cursor.

AC-6 A 401 after one `/ui/session/refresh` retry surfaces a session-expired signal; no
session logic is re-implemented in this module.

AC-7 No financial values or party identifiers appear in analytics payloads or release-build
logs.

## 15. Definition of Done

- `feature-collaborations` module created under `com.testlogon.android.feature.collaborations`,
  wired into the app NavGraph and Hilt graph, building on AGP 8.7.3 / Gradle 8.9 / JDK 17.
- All FRs (§3) and ACs (§14) implemented and green; non-scope write paths explicitly
  excluded.
- Unit, repository, paging, ViewModel, and Compose UI tests (§11) pass in CI; coverage on
  mappers and state logic.
- DTOs verified against live `/openapi.json`; any deviations from §5 documented in the PR.
- No new Detekt/lint warnings; strings externalized; accessibility checks (§9) pass.
- PR references AND-358 and its dependency AND-027; reviewed and merged to `android-port`.
