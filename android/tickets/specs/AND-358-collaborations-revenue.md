---
id: AND-358
title: Collaborations + revenue
milestone: M7
epic: E46
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-358 — Collaborations + revenue

## 1. Overview & Goal

This ticket delivers the **Collaborations** feature surface for the TestLogon native
Android client: a read-and-act experience that lets an authenticated user view the
collaborations they participate in and, for each collaboration, the **revenue split**
that governs how proceeds are distributed among collaborators.

> REVIEW NOTE (corrected): A collaboration is a **two-party agreement** between an
> `initiator_id` and a `recipient_id` (verified `CollaborationOut`,
> `GET /ui/collaborations/{collab_id}`), not an arbitrary N-party project. The
> revenue split is an inline `split` map (user_id -> integer **percent**, 0-100) on
> the collaboration object — there is **no** standalone `/revenue-split` endpoint.
> Per-split *distributions* (with `amount_cents`) live in the split-history endpoint
> `GET /ui/collaborations/{collab_id}/splits` (`CollabSplitHistoryOut`).

The web reference implements this against `frontend/src/api/endpoints/collaborations.ts`.
The Android port mirrors that contract through a new `feature-collaborations` module that
plugs into the established module layering (`app -> feature-* -> core-*`). The user can:

1. List collaborations they belong to (Paging 3 backed, cookie-authenticated).
2. Open a collaboration detail screen showing the two parties (initiator/recipient),
   status, and the revenue split breakdown (per-party percent shares; the two shares
   are expected to sum to 100).
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
- **Dependency AND-027 — AuthApi (session endpoints).** Provides the session lifecycle
  and authenticated transport. Per the web reference (`src/api/client.ts`), every
  request carries **both** an `Authorization: Bearer <accessToken>` header (from the
  auth store) **and** the `ui_csrf` cookie echoed as `X-CSRF-Token`, sent with cookies
  (`credentials: include`). The `/ui/session/refresh` endpoint is verified; on `401`
  the client refreshes the session **once** and retries the original request a single
  time before logging out. AND-358 consumes that authenticated OkHttp stack; it does
  not re-implement session handling.
  > REVIEW NOTE: the original spec described auth as "entirely cookie session". That
  > is incomplete — a Bearer access token is also attached (`src/api/client.ts`).
  > NOTE: the exact session-start/finalize/logout paths and the OkHttp cookie-jar
  > details are owned by AND-027 and are treated here as an **unverified assumption**
  > beyond `/ui/session/refresh` (the only one this ticket directly relies on).
- **Web reference:** `src/api/endpoints/collaborations.ts` (endpoint shapes, query
  params) and `src/api/types.ts` (`CollaborationOut`, `CollaborationListOut`,
  `CollabSplitHistoryOut`, `CollabSplitRecord`, `CollabSplitDistribution`). These are
  authoritative for field names and JSON structure. Note: `collaborations.ts` exposes
  **no** `getRevenueSplit` function — there is no dedicated revenue-split endpoint
  (see §5). Field names verified against `openapi.pretty.json` `components.schemas`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (cache),
  Paging 3, Coil. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Error `detail` may be `string`,
  `[{msg}]`, or `{code,...}` — mapped via the shared error mapper from core-network.
- **Namespace:** all packages rooted at `com.testlogon.android`.

## 3. Functional Requirements

FR-1 **List collaborations.** The Collaborations list screen displays collaborations the
current user participates in, paged via Paging 3 using `next_cursor`. Each row shows:
collaboration `title`, a status badge, and the viewer's own share percent derived from
the `split` map (the entry keyed by the current user's id, if present).
> REVIEW NOTE: `CollaborationOut` has **no `participant_count`** field. Collaborations
> are two-party; show the parties or omit a count. Server-side ordering is not
> documented — do not assert "newest first" as a contract (see §13 R6). The exact
> `status` enum values are not enumerated in the schema (`status` is a free `string`);
> treat unknown values as `UNKNOWN` (see §6).

FR-2 **Collaboration detail.** Tapping a row navigates to a detail screen showing:
`title`, `description`, `status`, created/updated timestamps (epoch seconds), the two
parties (`initiator_id`, `recipient_id`), and the **revenue split** section derived from
the `split` map. There is no `participants[]` array and no per-party `display_name`/
`role` in `CollaborationOut`; the screen renders party **ids** (resolution to display
names depends on the shared identity model from AND-353 — unverified, see §12/§13).

FR-3 **Revenue split rendering.** The revenue split section renders one row per party
in the `split` map with that party's percent (integer 0-100; **not** basis points).
When per-content distributions are loaded from `GET /ui/collaborations/{collab_id}/splits`
(`CollabSplitHistoryOut`), the screen may additionally show `amount_cents` per
distribution. The UI shows a total row that checks the sum of `split` percents equals
**100**; if it does not, a non-blocking "split does not total 100%" warning is shown
rather than failing the screen.
> REVIEW NOTE: the previous "basis points / sum to 10000" model was **incorrect**.
> `CollaborationOut.split` is `Record<string,integer>` of **percent** values
> (verified `openapi.pretty.json: CollaborationOut.split` and the create/counter
> contract `split_pct`/`counter_split_pct` with min 1 / max 99). Distributions use
> integer `percentage` + `amount_cents`.

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
        @Query("role") role: String? = null,
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): CollaborationListDto

    @GET("ui/collaborations/{collab_id}")
    suspend fun detail(@Path("collab_id") collabId: String): CollaborationDto

    // Per-content split history (distributions w/ amount_cents). Optional for v1.
    @GET("ui/collaborations/{collab_id}/splits")
    suspend fun splits(
        @Path("collab_id") collabId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): CollabSplitHistoryDto
}
```

> REVIEW NOTE (corrected): the original interface declared
> `GET ui/collaborations/{id}/revenue-split -> RevenueSplitDto`. **That endpoint does
> not exist.** The inline split is on `CollaborationDto.split` (returned by `detail`);
> historical per-content distributions are at `GET /ui/collaborations/{collab_id}/splits`
> (`CollabSplitHistoryOut`). The path parameter is `collab_id`, the list query params
> are `role,status,cursor,limit` (verified
> `openapi.index.txt: GET /ui/collaborations` and `.../{collab_id}`,
> `.../{collab_id}/splits`).

All calls return through the core-network `ApiResult<T>` wrapper at the repository
boundary (Retrofit declares the raw DTO; the repository catches and maps).

### 4.3 Repository & domain

```kotlin
interface CollaborationsRepository {
    fun pagedCollaborations(status: CollaborationStatus? = null):
        Flow<PagingData<Collaboration>>
    suspend fun collaboration(id: String): ApiResult<Collaboration>
    // RevenueSplit is derived from Collaboration.split (no network call); splitHistory
    // optionally fetches per-content distributions from the /splits endpoint.
    suspend fun splitHistory(id: String): ApiResult<List<RevenueSplitRecord>>
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

`load()` fetches `repo.collaboration(id)` (which already contains the inline `split`
map used to render the revenue split) and, optionally and concurrently with `async`,
`repo.splitHistory(id)` for per-content distribution amounts. It merges into the content
state and emits `Content(stale = true)` when serving cached data while a network refresh
is pending or failed.
> REVIEW NOTE: the original text fetched a non-existent `repo.revenueSplit(id)`. The
> primary split data is inline on the collaboration detail; only the optional
> distribution history requires the second call.

### 4.5 Navigation

Routes registered in app NavGraph:
`collaborations` (list) and `collaborations/{collaborationId}` (detail). Type-safe nav arg
`collaborationId: String`.

## 5. API Contract

Base: `http://18.222.237.167:8000`. All requests carry the authenticated transport from
AND-027: an `Authorization: Bearer <accessToken>` header **and** the `ui_csrf` cookie
echoed as `X-CSRF-Token`, sent with cookies (verified `src/api/client.ts`). These are
idempotent GETs and are therefore eligible for the bounded backoff retry policy.

> REVIEW NOTE (corrected throughout §5): the JSON shapes below were rewritten to match
> the authoritative schemas. Verified against `openapi.pretty.json`
> (`CollaborationOut`, `CollaborationListOut`, `CollabSplitHistoryOut`,
> `CollabSplitRecord`, `CollabSplitDistribution`) and `src/api/types.ts`. Key fixes:
> id field is `collaboration_id`; no `participants[]`/`participant_count`/`currency`/
> `total_amount_minor`/`viewer_share_bps`/`share_bps`; timestamps are **epoch integers**;
> split is an inline integer-**percent** map; the `/revenue-split` endpoint does not exist.

### 5.1 List — `GET /ui/collaborations?role=&status=&cursor=&limit=20`

Query params (all optional): `role`, `status`, `cursor`, `limit` (plus server-injected
auth params `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`). 200 →
`CollaborationListOut`. Each item is a full `CollaborationOut`:

```json
{
  "items": [
    {
      "collaboration_id": "collab_01HZX...",
      "initiator_id": "usr_789",
      "recipient_id": "org_123",
      "status": "active",
      "content_types": ["vod", "post"],
      "split": { "usr_789": 60, "org_123": 40 },
      "title": "Spring Campaign Joint Venture",
      "description": "Co-produced Q2 campaign.",
      "content_count": 4,
      "total_revenue_cents": 1500000,
      "revision": 2,
      "created_at": 1743500400,
      "updated_at": 1748613731
    }
  ],
  "next_cursor": "eyJwayI6..."
}
```

`next_cursor` is `null`/absent on the last page. `422` → `HTTPValidationError`.

### 5.2 Detail — `GET /ui/collaborations/{collab_id}`

200 → `CollaborationOut` (same shape as a list item above). Required fields:
`collaboration_id`, `initiator_id`, `recipient_id`, `status`. Optional/nullable:
`description`, `terms_text`, `valid_from`, `valid_until`, `max_content_items`,
`accepted_at`, `terminated_at`, `terminated_by`, `termination_reason`,
`last_proposed_by`. Defaulted: `content_count=0`, `total_revenue_cents=0`, `revision=1`,
`title=""`, `created_at=0`, `updated_at=0`, `split={}`. `422` → `HTTPValidationError`.

### 5.3 Revenue split

There is **no** `GET /ui/collaborations/{id}/revenue-split` endpoint. The split that
governs distribution is the inline `split` object on `CollaborationOut`:

```json
"split": { "usr_789": 60, "org_123": 40 }
```

Keys are party/user ids; values are **integer percent** (0-100). The UI checks the
values sum to **100** and otherwise shows the FR-3 warning.

Per-content realized distributions (with money amounts) come from
`GET /ui/collaborations/{collab_id}/splits` → `CollabSplitHistoryOut` (optional for v1):

```json
{
  "items": [
    {
      "split_id": "split_01...",
      "content_id": "vod_01...",
      "content_type": "vod",
      "gross_amount_cents": 1500000,
      "source": "vod_purchase",
      "distributions": [
        { "user_id": "usr_789", "percentage": 60, "amount_cents": 900000 },
        { "user_id": "org_123", "percentage": 40, "amount_cents": 600000 }
      ],
      "created_at": 1748613731,
      "dispute_status": null
    }
  ],
  "next_cursor": null
}
```

`amount_cents`/`gross_amount_cents` are minor currency units (cents); `percentage` is
integer percent. Currency code is **not** returned by these schemas — assume the
account default (USD) for formatting (unverified, see §13 R5). `CollabSplitDistribution`
requires only `user_id`; `amount_cents`/`percentage` default to 0.

Moshi DTOs use `@Json(name=...)` for snake_case fields and `Map<String,Int>` for
`split`. Epoch-integer timestamps map to `Long` and are formatted in the UI. Unknown
JSON fields are ignored (default Moshi behaviour) for forward-compatibility.

## 6. Data & State Management

- **Room cache (`core-data` schema):** `CollaborationEntity` (collaboration_id PK,
  title, status, initiator_id, recipient_id, content_count, total_revenue_cents,
  updated_at (epoch), json_blob, cached_at). The inline `split` map is persisted inside
  `json_blob` (or a serialized `Map<String,Int>` column); there is no separate
  `RevenueSplitEntity` required for v1 since the split is part of the collaboration.
  Detail (incl. split) is cached on successful fetch and read back via
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

- **Domain models** (`core-model`): `Collaboration` (with `initiatorId`, `recipientId`,
  `split: Map<String,Int>`), `CollaborationStatus` enum (`UNKNOWN` fallback; concrete
  values mapped from the free-string `status` — the backend does not enumerate them, so
  map the observed values and default the rest to `UNKNOWN`), `RevenueSplit`/`RevenueShare`
  derived from the `split` map, and `RevenueSplitRecord`/`RevenueDistribution` for the
  optional `/splits` history. Percent values are **integers already** (0-100) — no
  bps-to-percent division; amounts are minor units (`cents / 100.0` for display only),
  formatted in the UI layer, never stored pre-formatted.
  > REVIEW NOTE: removed the `bps / 100.0` derivation; the source values are percent,
  > not basis points. `Participant`-with-role/display-name does not exist in the API;
  > the model exposes the two party ids instead.

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
  locale; split percent values are integers (0-100) shown as whole percents; amounts
  (`amount_cents`) formatted as currency from minor units.
- Status badges convey state with text + color (not color alone); each badge has a
  `contentDescription`.
- Revenue split rows are exposed to TalkBack as a single semantic unit per party
  ("Acme Studio, 50 percent, 7,500 dollars 00 cents"); the total row announces validity.
- Minimum 48dp touch targets on list rows and retry/refresh controls; supports dynamic
  font scaling without truncation in detail.

## 10. Telemetry & Logging

- **Events** (via core analytics facade): `collaborations_list_viewed`,
  `collaboration_detail_viewed { has_split: Boolean }`, `revenue_split_total_invalid`
  (fires when the `split` percents != 100), `collaborations_refresh`, `collaborations_load_error
  { code }`. No financial values or party ids in event payloads.
- **Logging:** structured `Timber` tags `CollabRepo` / `CollabVM`. Network errors logged
  at `WARN` without bodies. Financial data redacted per §8. Release builds strip
  `DEBUG`/`VERBOSE` via the existing Timber release tree.

## 11. Testing Strategy

- **API contract (MockWebServer):** for each endpoint (`list`, `detail`, optional
  `splits`), assert path/verb, query params (`role,status,cursor,limit`), header presence
  (`Authorization: Bearer ...` and `X-CSRF-Token`), and Moshi deserialization of the §5
  shapes including the inline `split` map, epoch-integer timestamps, nullable fields, and
  absent/`null` `next_cursor`.
- **Mapper unit tests:** split-totals-valid detection (sum == 100 vs 99/101);
  `CollaborationStatus` fallback to `UNKNOWN` for unrecognized values; `amount_cents`
  -> currency formatting across locales; epoch-second -> localized date formatting.
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

- **R1 — Endpoint shape uncertainty. [RESOLVED by this review]** §5 was diffed against
  `openapi.pretty.json` and `src/api/types.ts`. The original reconstruction was wrong on
  several fields (see §16 Corrections). Moshi `@Json` names corrected. Remaining residual
  risk: live `/openapi.json` on the dev host may drift from the captured snapshot;
  re-diff at implementation time.
- **R2 — bps vs percent vs decimal. [RESOLVED: percent].** The split values are integer
  **percent** (0-100), confirmed by `CollaborationOut.split` (`additionalProperties:
  integer`) and the create/counter `split_pct`/`counter_split_pct` constraints
  (min 1, max 99). The earlier basis-points assumption was incorrect and has been removed.
- **R3 — Split totals not summing to 100%.** Real data may legitimately not total 100
  (rounding, withheld fees). Decided: warn, do not error. Confirm desired behaviour.
- **R4 — Unreliable dev host** may make UI test flakiness; mitigated by MockWebServer-based
  tests and stale-cache UX.
- **R5 — Currency/amount nullability** when no revenue accrued — handled by percent-only
  rendering. Note the schemas do **not** return a currency code; the UI must assume a
  default (USD) until a currency source is confirmed. *Open question for backend.*
- **R6 — List ordering & status enum (unverified).** The OpenAPI does not document a
  default sort order for `GET /ui/collaborations`, nor does it enumerate `status` values
  (`status` is a free `string`). Do not rely on "newest first"; treat unknown statuses
  as `UNKNOWN`. *Open question for backend.*
- **R7 — Party display names (unverified).** `CollaborationOut` exposes only
  `initiator_id`/`recipient_id` (and `split` keys); resolving these to human-readable
  names depends on the shared identity model from AND-353. Until then render ids.

## 14. Acceptance Criteria

AC-1 The Collaborations list screen loads via `GET /ui/collaborations`, renders rows with
title/status (and the viewer's share percent when present), pages with the backend
`next_cursor`, and shows an empty state when there are none. (Backlog: "Collaboration …
render.")

AC-2 The detail screen loads `GET /ui/collaborations/{collab_id}`, rendering the two
parties (`initiator_id`/`recipient_id`) and a revenue-split breakdown from the inline
`split` map with per-party percentages (and, when the optional
`GET /ui/collaborations/{collab_id}/splits` is loaded, per-distribution amounts).
(Backlog: "… + revenue render.")

AC-3 Revenue-split percentages are read from the integer-percent `split` map correctly; a
split whose values do not sum to 100 shows a non-blocking warning and still renders.

AC-4 Loading, content, empty, error, and stale states are all reachable and verified by
tests.

AC-5 The list, detail, and (optional) splits endpoints are MockWebServer-tested for
path/verb/headers/body mapping, including the inline `split` map, nullable fields,
epoch timestamps, and end-of-list (`next_cursor` null/absent).

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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption) and
SOURCE pointer.

1. **List endpoint is `GET /ui/collaborations`.** VERDICT: Verified.
   SOURCE: `openapi.index.txt: GET /ui/collaborations`
   (`op=list_collabs_ui_collaborations_get`); `src/api/endpoints/collaborations.ts:
   listCollaborations`.
2. **List query params are `role, status, cursor, limit`.** VERDICT: Corrected (spec had
   only `cursor, limit, status`; `role` was missing). SOURCE: `openapi.index.txt: GET
   /ui/collaborations | params=role,status,cursor,limit,...`; `src/api/endpoints/
   collaborations.ts: listCollaborations` (`{ role?, status?, cursor?, limit? }`).
3. **List response is `CollaborationListOut { items: CollaborationOut[], next_cursor? }`.**
   VERDICT: Verified (envelope) / Corrected (item shape — see #5). SOURCE:
   `openapi.pretty.json: CollaborationListOut`; `src/api/types.ts: CollaborationListOut`.
4. **Detail endpoint is `GET /ui/collaborations/{collab_id}` → `CollaborationOut`.**
   VERDICT: Corrected (spec used path param `{id}`; real is `{collab_id}`). SOURCE:
   `openapi.index.txt: GET /ui/collaborations/{collab_id}`
   (`op=get_collab_ui_collaborations__collab_id__get`); `src/api/endpoints/
   collaborations.ts: getCollaboration`.
5. **`CollaborationOut` fields.** VERDICT: Corrected. The id field is `collaboration_id`
   (not `id`); the object carries `initiator_id` + `recipient_id` (two parties — NOT a
   `participants[]` array with `display_name`/`role`); `split` is an inline
   `Record<string,integer>` map; `status`, `title`, `description`, `content_types`,
   `content_count`, `total_revenue_cents`, `revision`, `created_at`, `updated_at`
   (and nullable `terms_text/valid_from/valid_until/max_content_items/accepted_at/
   terminated_at/terminated_by/termination_reason/last_proposed_by`). No
   `participant_count`, `viewer_share_bps`, or `currency`. SOURCE:
   `openapi.pretty.json: CollaborationOut`; `src/api/types.ts: CollaborationOut`.
6. **Revenue split is the inline `split` map (integer percent 0-100), not a `share_bps`
   array.** VERDICT: Corrected. `split` is `additionalProperties: integer`; the
   create/counter contracts constrain `split_pct`/`counter_split_pct` to integers
   min 1 / max 99. SOURCE: `openapi.pretty.json: CollaborationOut.split`,
   `CollaborationCounterIn.counter_split_pct`; `src/api/types.ts: CollaborationCreateIn.
   split_pct`.
7. **There is NO `GET /ui/collaborations/{id}/revenue-split` endpoint.** VERDICT:
   Corrected (the original §4.2/§5.3 invented it). No such path exists in the index and
   `collaborations.ts` exposes no `getRevenueSplit`. SOURCE: absence in
   `openapi.index.txt` (collaboration routes lines for `/ui/collaborations*`);
   `src/api/endpoints/collaborations.ts` (no such export).
8. **Per-content distributions come from `GET /ui/collaborations/{collab_id}/splits` →
   `CollabSplitHistoryOut`.** VERDICT: Verified. Items are `CollabSplitRecord`
   (`split_id`, `content_id`, `gross_amount_cents`, `source`, `distributions[]`,
   `created_at`, `dispute_status?`); each `CollabSplitDistribution` has `user_id`,
   integer `percentage`, integer `amount_cents`. SOURCE:
   `openapi.index.txt: GET /ui/collaborations/{collab_id}/splits`
   (`op=get_collab_split_history...`); `openapi.pretty.json: CollabSplitHistoryOut,
   CollabSplitRecord, CollabSplitDistribution`; `src/api/types.ts: CollabSplitHistoryOut`.
9. **Timestamps are epoch integers, money is in cents (`*_cents`).** VERDICT: Corrected
   (spec used ISO-8601 strings and `*_amount_minor`). SOURCE: `openapi.pretty.json:
   CollaborationOut.created_at/updated_at (integer)`, `CollabSplitRecord.gross_amount_cents`,
   `CollabSplitDistribution.amount_cents`.
10. **Auth: requests carry `Authorization: Bearer <accessToken>` AND `X-CSRF-Token`
    (echo of `ui_csrf` cookie) with cookies included.** VERDICT: Corrected (spec said
    auth was "entirely cookie session"; a Bearer token is also attached). SOURCE:
    `src/api/client.ts` (sets `Authorization: Bearer`, `X-CSRF-Token` from `getCookie
    ("ui_csrf")`, `credentials: "include"`).
11. **401 → single `/ui/session/refresh` then one retry, else logout.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (`refreshSession()` posts
    `/ui/session/refresh`; `refreshPromise` guard; single `retryRes` then
    `logout("session_expired")`).
12. **FastAPI error `detail` may be `string | [{msg}] | {code,...}`.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` (handles string, array-of-`{msg}`,
    object-with-`code`); `openapi.pretty.json: HTTPValidationError` (`detail:
    ValidationError[]`, each with `loc/msg/type`). 422 is the documented validation code
    on these endpoints (`openapi.index.txt: ...resp=...;422:HTTPValidationError`).
13. **Android stack/framework choices (Compose + Material 3, Paging 3 PagingSource,
    Hilt, Retrofit/Moshi, Room).** VERDICT: Unverified-assumption (project convention;
    not derivable from backend/web sources). SOURCE: framework ref —
    https://developer.android.com/jetpack/androidx/releases/paging (Paging 3
    `PagingSource`), https://developer.android.com/jetpack/compose, and the §2 stack list.
14. **List default ordering ("newest/most-recently-active first").** VERDICT:
    Unverified-assumption. SOURCE: not specified in `openapi.pretty.json` (no documented
    sort); see §13 R6.
15. **`status` enum values (`active/pending/closed`).** VERDICT: Unverified-assumption —
    backend `status` is a free `string`, values not enumerated. SOURCE:
    `openapi.pretty.json: CollaborationOut.status (type: string, no enum)`; mapped with an
    `UNKNOWN` fallback (§6).
16. **Currency code for amount formatting.** VERDICT: Unverified-assumption (no currency
    field in the split schemas; assume USD). SOURCE: `openapi.pretty.json:
    CollabSplitRecord / CollabSplitDistribution` (no currency property); see §13 R5.
17. **Party display-name resolution.** VERDICT: Unverified-assumption — only ids are
    returned; display names depend on AND-353 identity model. SOURCE:
    `openapi.pretty.json: CollaborationOut` (`initiator_id`/`recipient_id` only); §12/§13 R7.

### Corrections made

- Path param `{id}` → `{collab_id}`; id field `id` → `collaboration_id` (§4.2, §5).
- Removed the non-existent `GET .../{id}/revenue-split` endpoint and `RevenueSplitDto`;
  revenue split is the inline `split` map; added optional `GET .../{collab_id}/splits`
  (`CollabSplitHistoryOut`) for distributions (§1, §4.2, §4.3, §4.4, §5.3, §11, §14).
- Basis-points model removed: split values are **integer percent (0-100)**, total target
  100 (not 10000); dropped `bps/100.0` mapper and `share_bps` (§3 FR-3, §6, §9, §10, §13).
- Replaced `participants[]`/`participant_count`/`display_name`/`role` with the two-party
  `initiator_id`/`recipient_id` model (§1, §3, §5.2, §6, §14).
- Timestamps corrected from ISO-8601 strings to epoch integers; money fields from
  `*_amount_minor` to `*_cents` (§5, §6).
- Added missing `role` list query param (§4.2, §5.1).
- Auth corrected to Bearer token + `X-CSRF-Token` (not cookie-only) (§2, §5).
- Removed `currency`/`viewer_share_bps`/`total_amount_minor` fields that the schemas do
  not return (§5, §6).

### Open assumptions

- **Android framework choices** (Compose/Paging3/Hilt/Retrofit/Moshi/Room): project
  convention, not verifiable from backend sources. (Citation 13.)
- **List sort order**: not documented in OpenAPI; cannot assert "newest first". (14, R6.)
- **`status` enum membership**: backend field is a free string; concrete values inferred,
  with `UNKNOWN` fallback. (15, R6.)
- **Currency code**: not present in split schemas; USD assumed for formatting. (16, R5.)
- **Party display names**: not in `CollaborationOut`; depend on AND-353. (17, R7.)
- **AND-027 transport internals** (cookie jar, exact session-start/finalize/logout paths,
  retry/backoff implementation): owned by AND-027; only `/ui/session/refresh` and the
  single-retry behaviour are directly verified here. (§2 note.)

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Most cases here are non-hardware
(network/UI), so JVM/emu35 suffice; the ABI/API-difference case must run on **A15**.

- **TC-AND-358-01** — Type: contract/MockWebServer. Target: JVM. Precondition:
  `CollaborationsApi` wired to MockWebServer; auth interceptor supplies a Bearer token and
  `X-CSRF-Token`. Steps: enqueue a `CollaborationListOut` body (§5.1) with one item and a
  `next_cursor`; call `list(role=null, status="active", cursor=null, limit=20)`. Expected:
  request path is `/ui/collaborations`, method GET, query contains `status=active&limit=20`,
  headers include `Authorization: Bearer ...` and `X-CSRF-Token`; response deserializes
  with `collaboration_id`, `split` map, epoch `updated_at`, and `next_cursor`. Traces: AC-1,
  AC-5, AC-6.
- **TC-AND-358-02** — Type: contract/MockWebServer. Target: JVM. Precondition: as 01.
  Steps: enqueue a `CollaborationOut` detail body (§5.2) including the inline `split`
  map and nullable fields omitted; call `detail("collab_01")`. Expected: path
  `/ui/collaborations/collab_01`, GET; Moshi maps `split` to `Map<String,Int>`, epoch
  ints to `Long`, absent nullable fields to null without error. Traces: AC-2, AC-5.
- **TC-AND-358-03** — Type: contract/MockWebServer. Target: JVM. Precondition: as 01.
  Steps: enqueue a `CollabSplitHistoryOut` (§5.3) with one record (two distributions,
  `amount_cents` present) and `next_cursor: null`; call `splits("collab_01")`. Expected:
  path `/ui/collaborations/collab_01/splits`, GET; distributions map to `user_id`,
  integer `percentage`, `amount_cents`; null `next_cursor` → end-of-list. Traces: AC-2,
  AC-5.
- **TC-AND-358-04** — Type: unit. Target: JVM. Precondition: split mapper available.
  Steps: map `split = {"a":60,"b":40}`; then `{"a":60,"b":39}`; then `{"a":50,"b":51}`.
  Expected: first → `splitTotalsValid = true` (sum 100); others → false (warning flag);
  percentages rendered as whole integers, no bps division. Traces: AC-3.
- **TC-AND-358-05** — Type: unit. Target: JVM. Precondition: status + money mappers.
  Steps: map `status` values `"active"/"pending"/"closed"/"weird_new_value"`; format
  `amount_cents = 600000` under `en-US` and `de-DE` locales; format `created_at` epoch.
  Expected: known statuses map to enum, unknown → `UNKNOWN`; currency formatted from
  minor units per locale; epoch → localized date. Traces: AC-2, AC-3.
- **TC-AND-358-06** — Type: integration (repository, `core-testing` fakes). Target: JVM.
  Precondition: fake API + in-memory Room. Steps: successful `detail` fetch; then force a
  network failure on refresh while a cached row exists. Expected: first fetch caches to
  Room; on failure repo returns `Content(stale = true)` from cache rather than `Error`.
  Traces: AC-4.
- **TC-AND-358-07** — Type: integration (repository). Target: JVM. Precondition: fake API
  returns 401 then a failing `/ui/session/refresh`. Steps: call `collaboration(id)`.
  Expected: after the single refresh+retry fails, repo maps to `ApiResult.AuthError` and
  the ViewModel sets `sessionExpired = true`; no session logic re-implemented in module.
  Traces: AC-6.
- **TC-AND-358-08** — Type: unit (PagingSource). Target: JVM. Precondition:
  `CollaborationPagingSource` over fake API. Steps: load page 1 (returns `next_cursor`),
  then page 2 (returns `next_cursor: null`). Expected: `LoadResult.Page` with correct
  `nextKey` for page 1 and `nextKey = null` at end; refresh invalidation re-queries page
  1. Traces: AC-1.
- **TC-AND-358-09** — Type: ViewModel (Turbine). Target: JVM. Precondition: fake repo.
  Steps: drive detail load happy path; then an error path with `retry()`. Expected: state
  sequence `Loading → Content`; and `Loading → Error → (retry) → Content`; concurrent
  detail+optional-splits merge into one `Content`. Traces: AC-2, AC-4.
- **TC-AND-358-10** — Type: Compose-UI. Target: emu35 (Robolectric acceptable). Steps:
  render list with ≥1 item and assert title/status/viewer-share text; render empty state
  ("You have no collaborations yet"); render detail with the `split` map and assert each
  party percent text and the total row. Expected: rows + percentages render; empty state
  shown when items empty. Traces: AC-1, AC-2, AC-3, AC-4.
- **TC-AND-358-11** — Type: Compose-UI. Target: emu35. Steps: render detail whose `split`
  sums to 99; render a detail served from cache during a failed refresh. Expected: the
  non-blocking "split does not total 100%" warning is visible and the screen still
  renders; the stale "Showing saved copy" banner is visible in the cached case. Traces:
  AC-3, AC-4.
- **TC-AND-358-12** — Type: Compose-UI (accessibility). Target: emu35. Steps: enable
  TalkBack semantics assertions; inspect a split row and a status badge; set font scale to
  largest. Expected: each split row is a single semantic node announcing party + percent
  (+ amount when present); status badge has a non-color `contentDescription`; touch
  targets ≥ 48dp; no truncation at max font scale. Traces: AC-2, AC-3.
- **TC-AND-358-13** — Type: unit (security/logging). Target: JVM. Precondition: Timber
  test tree + analytics fake; release-config flag. Steps: trigger a load error and the
  `revenue_split_total_invalid` event; capture logs/payloads. Expected: no `split`
  values, `amount_cents`, party ids, or `total_revenue_cents` appear in analytics
  payloads or in release-build logs; financial data redacted. Traces: AC-7.
- **TC-AND-358-14** — Type: instrumented/e2e. Target: **A15 (physical device required)**.
  Precondition: arm64 release-candidate build installed on the A15 (API 34) pointed at a
  canned/mock backend. Steps: launch app, navigate to Collaborations, open a detail with a
  known split; also run the same flow on emu35 (API 35, x86_64). Expected: "Collaboration
  + revenue render" — list shows ≥1 collaboration and detail shows all split shares with
  percentages identically on arm64/API-34 and x86_64/API-35 (no ABI/API regression). This
  case MUST run on the physical device for the arm64-vs-x86 / API-34-vs-35 comparison.
  Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (list loads/renders/pages/empty) | TC-01, TC-08, TC-10, TC-14 |
| AC-2 (detail + split + amounts) | TC-02, TC-03, TC-05, TC-09, TC-10, TC-12, TC-14 |
| AC-3 (percent derivation + non-100 warning) | TC-04, TC-05, TC-10, TC-11, TC-12, TC-14 |
| AC-4 (loading/content/empty/error/stale) | TC-06, TC-09, TC-10, TC-11 |
| AC-5 (endpoints MockWebServer-tested) | TC-01, TC-02, TC-03 |
| AC-6 (401 → refresh+retry → session-expired) | TC-01, TC-07 |
| AC-7 (no financial/PII in analytics/logs) | TC-13 |
