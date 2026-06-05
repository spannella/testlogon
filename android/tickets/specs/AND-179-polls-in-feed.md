---
id: AND-179
title: Polls in feed
milestone: M4
epic: E24
priority: P2
size: M
status: draft
depends_on: [AND-099]
blocks: []
---

# AND-179 — Polls in feed

## 1. Overview & Goal

Render and vote on **polls** attached to posts in the TestLogon native Android
newsfeed. A post may carry an optional poll block (a question plus 2–N options);
this ticket renders that block inside the existing `PostItem` composable
(AND-099), lets an authenticated user cast a single vote, and updates the
displayed results (per-option counts/percentages, total votes, and the user's
selected option) in response. The web reference for this behavior lives in the
poll API/render module (`polls.ts`).

The deliverable is the full vertical slice for **one** poll surface: the Moshi
DTOs for the poll block and the vote response, a `core-model` `Poll` domain type
and mapper, a `PollRepository.vote(...)` mutation returning a typed
`ApiResult<Poll>`, the per-poll vote state held by `FeedViewModel`, and a
`PollCard` Compose component embedded in `PostItem`. The single acceptance bullet
— "Vote updates results" — is interpreted concretely as: after a successful vote,
the option a user tapped is marked selected, each option's count and percentage
reflect the server-confirmed tallies, the total-votes label increments, and the
options become non-revotable (read-only results state) per the poll's rules.

Out of scope: poll **creation/authoring**, poll closing/expiry administration,
multi-select polls beyond what the backend reports, post rendering itself
(AND-099), feed paging (AND-098), and the feed container/detail screens (AND-100,
AND-102). Those are owned by sibling/upstream tickets named in §12.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt DI (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12
  + Moshi 1.15 (codegen), Room 2.6, DataStore, Coil, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- **Modules / layering:** `app -> feature-feed -> core-*`. This ticket touches
  `core-network` (Retrofit `PollApi`, DTOs, FastAPI `detail` mapping),
  `core-model` (`Poll`/`PollOption`/`PollVoteState`), `core-data` (`PollRepository`),
  `feature-feed` (`FeedViewModel` per-poll vote state + `PollCard` composable wired
  into `PostItem`), `core-ui` (selectable option row visuals), `core-testing`
  (MockWebServer harness, Turbine, fakes).
- **Package base:** `com.testlogon.android` everywhere
  (`com.testlogon.android.core.network.poll`,
  `com.testlogon.android.core.model.poll`,
  `com.testlogon.android.core.data.poll`,
  `com.testlogon.android.feature.feed`).
- **Backend:** FastAPI + DynamoDB, OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (plaintext HTTP, unreliable dev host:
  ~20s timeouts, bounded backoff for idempotent GETs only). Web reference:
  `frontend/src/api/endpoints/polls.ts` (vote endpoint + params) and
  `frontend/src/api/types.ts` (`Poll`, `PollOption`). These are authoritative for
  shapes; §5 wins on divergence.
- **Auth/session:** cookie-based; the authenticated OkHttp/Retrofit instance
  (persistent cookie jar AND-011, CSRF interceptor AND-012, 401→refresh
  authenticator AND-013) is reused. Polls are an authenticated, cookie-gated
  resource and voting requires the `X-CSRF-Token` header.
- **Dependency AND-099 (Post item composable):** supplies the `PostItem`
  composable and its rendering slots. The poll is rendered as an additional,
  optional content block within `PostItem`.

## 3. Functional Requirements

FR-1. When a feed `Post` carries a non-null `poll`, `PostItem` renders a
`PollCard` showing the question, all options, and a total-votes label.

FR-2. **Pre-vote (open, not yet voted):** each option renders as a tappable row.
Counts/percentages may be hidden until the user votes if the backend reports
`showResultsBeforeVote = false`; otherwise they show alongside selectable rows.

FR-3. **Voting:** tapping an option submits a single vote for that option. While
the request is in flight, the tapped option shows a busy affordance and all
options are disabled to prevent double submission.

FR-4. **Post-vote (acceptance core):** on success, the chosen option is visually
marked as the user's selection; every option displays its server-confirmed count
and percentage (percentage = `round(count / max(total,1) * 100)`); the
total-votes label reflects the new total; and rows become read-only (no further
voting) unless the poll's rules permit vote changes.

FR-5. **Already-voted on load:** if the feed payload indicates the user already
voted (`viewerVotedOptionId` present), the card renders directly in the post-vote
read-only results state with that option marked selected — no extra request.

FR-6. **Closed/expired poll:** if `closed = true` (or `closesAt` is in the past),
options are non-interactive and results are shown read-only; a "Poll closed"
label is displayed.

FR-7. **Failure:** a failed vote restores the pre-vote selectable state, leaves
tallies unchanged, and surfaces an inline, retry-friendly error message scoped to
the card (the rest of the feed item remains usable).

FR-8. State is **per-poll** and keyed by poll id, so multiple polls in the feed
vote and update independently and survive Compose recomposition and list scroll.

FR-9. Unknown JSON fields and unknown enum values (e.g. a new poll type) are
tolerated without throwing; an unrecognized poll type degrades to read-only
results rather than crashing.

## 4. Technical Design

Package roots: `core-network → com.testlogon.android.core.network.poll`,
`core-model → com.testlogon.android.core.model.poll`,
`core-data → com.testlogon.android.core.data.poll`,
`feature-feed → com.testlogon.android.feature.feed`.

### Domain model (`core-model`)

```kotlin
package com.testlogon.android.core.model.poll

data class Poll(
    val id: String,
    val postId: String,
    val question: String,
    val options: List<PollOption>,
    val totalVotes: Int,
    val viewerVotedOptionId: String?,   // null => viewer has not voted
    val closed: Boolean,
    val closesAt: Instant?,             // null => no expiry
    val showResultsBeforeVote: Boolean,
    val allowVoteChange: Boolean,
) {
    val hasVoted: Boolean get() = viewerVotedOptionId != null
    val isInteractive: Boolean get() = !closed && (!hasVoted || allowVoteChange)
}

data class PollOption(
    val id: String,
    val label: String,
    val voteCount: Int,
) {
    fun percentOf(total: Int): Int =
        if (total <= 0) 0 else Math.round(voteCount * 100f / total)
}
```

### Retrofit interface (`core-network`)

```kotlin
package com.testlogon.android.core.network.poll

interface PollApi {
    // Idempotency NOT assumed: this is a state-changing POST; no GET retry/backoff.
    @POST("ui/posts/{postId}/poll/vote")
    suspend fun vote(
        @Path("postId") postId: String,
        @Body body: PollVoteRequestDto,
    ): PollDto
}
```

`PollApi` is provided via Hilt from the `@Named("authenticated")` Retrofit
(AND-027), inheriting the cookie jar, CSRF header, and 401→refresh. The exact path
is verified against `/openapi.json` + `polls.ts` at implementation time; §5 is
authoritative on divergence.

### Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.poll

interface PollRepository {
    suspend fun vote(postId: String, optionId: String): ApiResult<Poll>
}

class DefaultPollRepository @Inject constructor(
    private val api: PollApi,
    private val errorMapper: ApiErrorMapper,   // AND-015 FastAPI detail mapping
) : PollRepository {
    override suspend fun vote(postId: String, optionId: String): ApiResult<Poll> =
        runApiCatching(errorMapper) {                       // AND-018 helper
            api.vote(postId, PollVoteRequestDto(optionId)).toDomain()
        }
}
```

### ViewModel state (`feature-feed`)

`PollCard` is stateless; per-poll UI state is owned by the existing
`FeedViewModel` (AND-102) so it survives scroll/recomposition and is testable
without Compose.

```kotlin
sealed interface PollCardState {
    data class Idle(val poll: Poll) : PollCardState           // pre-vote selectable
    data class Voting(val poll: Poll, val pendingOptionId: String) : PollCardState
    data class Results(val poll: Poll) : PollCardState         // read-only post-vote/closed
    data class Error(val poll: Poll, val message: String) : PollCardState
}

// In FeedViewModel:
private val pollStates = MutableStateFlow<Map<String, PollCardState>>(emptyMap())
val pollUiStates: StateFlow<Map<String, PollCardState>> = pollStates.asStateFlow()

fun onPollOptionSelected(postId: String, pollId: String, optionId: String) {
    val current = pollStates.value[pollId] ?: return
    val poll = current.pollOrNull() ?: return
    if (!poll.isInteractive) return
    if (current is PollCardState.Voting) return               // FR-3 double-submit guard
    pollStates.update { it + (pollId to PollCardState.Voting(poll, optionId)) }
    viewModelScope.launch {
        when (val r = pollRepository.vote(postId, optionId)) {
            is ApiResult.Success ->
                pollStates.update { it + (pollId to PollCardState.Results(r.data)) }
            is ApiResult.Error ->
                pollStates.update { it + (pollId to PollCardState.Error(poll, r.error.userMessage())) }
        }
    }
}
```

Initial mapping: when feed pages load, each post with a poll seeds `pollStates`
via `initialStateFor(poll)` = `Results` if `poll.hasVoted || poll.closed` else
(`showResultsBeforeVote` does not change interactivity) `Idle`.

### Compose (`feature-feed` + `core-ui`)

```kotlin
@Composable
fun PollCard(
    state: PollCardState,
    onOptionClick: (optionId: String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)
```

`PollCard` renders the question, a column of `PollOptionRow`s (`core-ui`
selectable visual: label + animated horizontal results bar + percent/count), the
total-votes label, and, when applicable, "Poll closed" / inline error + retry.
`PostItem` (AND-099) calls `PollCard` from its optional content slot when
`post.poll != null`, hoisting `onOptionClick` up to `FeedViewModel`.

## 5. API Contract

**Vote** — `POST /ui/posts/{postId}/poll/vote`
Headers: session cookies + `X-CSRF-Token` (auto via interceptors).

Request body:

```json
{ "option_id": "opt_2" }
```

Success `200`:

```json
{
  "id": "poll_88",
  "post_id": "post_123",
  "question": "Best release window?",
  "options": [
    { "id": "opt_1", "label": "Morning",   "vote_count": 12 },
    { "id": "opt_2", "label": "Afternoon", "vote_count": 41 },
    { "id": "opt_3", "label": "Evening",   "vote_count": 7  }
  ],
  "total_votes": 60,
  "viewer_voted_option_id": "opt_2",
  "closed": false,
  "closes_at": "2026-06-30T12:00:00Z",
  "show_results_before_vote": false,
  "allow_vote_change": false
}
```

The **poll block** is also embedded in each feed `PostDto` (from AND-097) under
`poll` using the identical object shape (sans `post_id`, which is inferred), so no
separate poll GET is required on the feed path. DTOs:

```kotlin
@JsonClass(generateAdapter = true)
data class PollDto(
    @Json(name = "id") val id: String,
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "question") val question: String,
    @Json(name = "options") val options: List<PollOptionDto> = emptyList(),
    @Json(name = "total_votes") val totalVotes: Int = 0,
    @Json(name = "viewer_voted_option_id") val viewerVotedOptionId: String? = null,
    @Json(name = "closed") val closed: Boolean = false,
    @Json(name = "closes_at") val closesAt: String? = null,
    @Json(name = "show_results_before_vote") val showResultsBeforeVote: Boolean = true,
    @Json(name = "allow_vote_change") val allowVoteChange: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class PollOptionDto(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String,
    @Json(name = "vote_count") val voteCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class PollVoteRequestDto(@Json(name = "option_id") val optionId: String)
```

Error responses use the FastAPI `detail` shape mapped by AND-015
(`string | [{msg}] | {code,...}`):

- `401` → 401→refresh authenticator retries once; if still 401, mapped to an auth
  error (card shows generic retry; refresh/expiry UX is AND-044).
- `403` (CSRF/forbidden) / `409` (already voted) / `410` (poll closed) /
  `422` (invalid `option_id`) → mapped to a typed `ApiError`; the card shows an
  inline message and restores the selectable state (FR-7). A `409`/`410` SHOULD
  re-render the latest server poll if the body carries one; otherwise it falls
  back to read-only `Results` for the known poll.

## 6. Data & State Management

- **No persistence.** Poll state is in-memory only, derived from the live feed
  page (Paging 3, AND-098) plus the vote response. No Room table and no DataStore
  key are introduced. Room caching of feed pages, if/when added (AND-097 family),
  may carry the embedded poll block; this ticket does not own that schema.
- **Source of truth:** the server. The post-vote `Results` state is built solely
  from the `PollDto` returned by the vote call (or the embedded poll for the
  already-voted case). No client-side tally arithmetic is trusted; the client only
  computes display percentages from server counts (`PollOption.percentOf`).
- **Keying & lifecycle:** `pollStates: Map<pollId, PollCardState>` in
  `FeedViewModel`, surviving recomposition and scroll. On feed refresh/invalidate,
  entries are reconciled by id; a poll already in `Results`/`Error` is reseeded
  from the freshest server poll. Stable `key(pollId)`/`key(optionId)` are used in
  the Compose `LazyColumn` and option `Column` to preserve animation/scroll state.
- **No optimistic mutation of tallies.** The UI shows a busy `Voting` state, not a
  predicted result; counts change only after the server response (avoids showing
  wrong numbers on the unreliable dev host).

## 7. Error Handling & Resilience

- **Timeouts:** the shared OkHttp client (AND-009) governs ~20s timeouts. Voting
  is a POST and is **not** auto-retried (non-idempotent; double-vote risk). The GET
  idempotent-only backoff policy (AND-016) explicitly does not apply.
- **Failure UX (FR-7):** `ApiResult.Error` → `PollCardState.Error(poll, message)`;
  options restored to selectable, tallies unchanged, inline message + "Retry"
  re-issuing the same vote. The error is card-scoped; the rest of the `PostItem`
  and feed stay interactive.
- **Offline:** if the connectivity probe (AND-017) reports offline, the option tap
  short-circuits to an offline message without a network call; the card stays in
  the selectable state.
- **401 handling:** delegated to the 401→refresh authenticator (AND-013); a single
  transparent refresh+retry occurs before an error reaches the ViewModel.
- **Concurrent/duplicate taps:** the `Voting` guard (FR-3) drops taps while a vote
  is in flight; rapid taps on different options are ignored until the first
  resolves.
- **Malformed/partial payloads:** lenient Moshi + safe defaults (empty options,
  `totalVotes = 0`); a poll with zero options renders read-only with no rows
  rather than crashing. Unknown poll-type values degrade to read-only (FR-9).

## 8. Security & Privacy

- All poll traffic rides the authenticated, cookie-based session; the vote POST
  carries the `X-CSRF-Token` header echoed from the `ui_csrf` cookie (AND-012). A
  vote MUST never be sent without it (server returns `403` otherwise).
- The dev backend is plaintext HTTP; the production build MUST use HTTPS and the
  app retains its cleartext policy only for the dev flavor/base URL (AND-006). No
  poll-specific cleartext exception is added.
- No PII is introduced; only opaque ids (`poll_*`, `opt_*`, `post_*`) and counts.
  Vote selections are not logged (see §10). `viewer_voted_option_id` reveals the
  current user's own vote only and is not persisted to disk.
- No new permissions, exported components, deep links, or `WebView` are added.

## 9. Accessibility & i18n

- Each option row is a single focusable, min-48dp target with
  `Role.RadioButton` semantics and `selectableGroup()` around the option column;
  TalkBack announces "Option X, N votes, P percent, selected/not selected".
- The busy/`Voting` state sets a `stateDescription` ("submitting vote") and
  disabled options expose `disabled` semantics so they are not announced as
  actionable.
- Results bars convey percentage by both width **and** a visible numeric label
  (no color-only meaning); contrast meets Material 3 / WCAG AA against the theme
  (AND-019). Closed/error states have text labels, not icon-only cues.
- All strings (`poll_total_votes`, `poll_closed`, `poll_vote_error`,
  `poll_percent_format`, `poll_submitting`) live in `strings.xml`; percentages and
  counts are formatted via `NumberFormat`/plurals (`<plurals name="poll_votes">`)
  for locale-correct grouping and pluralization. No hardcoded user-facing text.

## 10. Telemetry & Logging

- Reuse the app analytics façade (no new SDK). Events:
  `poll_view` (props: `poll_id`, `closed`, `has_voted`),
  `poll_vote_submit` (`poll_id`, `option_id`),
  `poll_vote_result` (`poll_id`, `outcome` ∈ {`success`,`error`}, `error_code`,
  `latency_ms`).
- Logging is via the shared `Logger`/Timber wrapper at `debug` level only; **no**
  vote selection, poll content, or ids are logged at `info`+ in release builds.
  OkHttp body logging stays restricted to debug builds (AND-009) and MUST NOT leak
  cookies or the CSRF token.
- A single `error`-level breadcrumb (code + latency, no body) is emitted on
  unexpected (`5xx`/parse) failures to aid dev-host debugging.

## 11. Testing Strategy

- **Mapper unit tests** (`core-model`): `PollDto.toDomain()` maps all fields;
  `closes_at` parses to `Instant`; `percentOf` rounds correctly (incl. `total = 0`
  → 0); missing/unknown fields use safe defaults; `isInteractive`/`hasVoted`
  derive correctly for open/voted/closed permutations.
- **Repository contract tests** (`core-data` + MockWebServer, AND-046): `200` →
  `ApiResult.Success` with updated tallies; `409`/`410`/`422` → typed
  `ApiResult.Error` with mapped FastAPI `detail`; verifies `X-CSRF-Token` header
  and JSON body `{"option_id": ...}` are sent; verifies **no** automatic retry on
  POST failure.
- **ViewModel tests** (Turbine): `Idle → Voting → Results` on success and the
  acceptance assertion that the chosen option is selected, counts/percentages and
  total reflect the server body, and the poll becomes non-interactive;
  `Idle → Voting → Error → Idle(restored)` on failure with tallies unchanged;
  double-tap while `Voting` issues exactly one network call; already-voted/closed
  seed directly into `Results`.
- **Compose UI tests** (AND-104 feed test harness): tapping an option triggers the
  hoisted callback; post-vote shows selected marker + percentages + incremented
  total (the literal "vote updates results" check); closed poll renders read-only;
  error renders inline retry; semantics/role assertions for accessibility.
- **Fakes:** `FakePollRepository` in `core-testing` for ViewModel/Compose tests.

## 12. Dependencies & Sequencing

- **Depends on (hard):** AND-099 (Post item composable) — provides the `PostItem`
  surface and content slot the `PollCard` is embedded in.
- **Consumes (soft, reused):** AND-097 (feed DTOs — embedded `poll` block),
  AND-098 (Paging feed list), AND-102 (`FeedViewModel`), AND-011/012/013/027
  (auth/session client), AND-015 (`detail` mapping), AND-016/017 (backoff/
  connectivity), AND-018 (`ApiResult`), AND-019/020/021 (theme/state composables),
  AND-046 (MockWebServer harness), AND-104 (feed tests).
- **Related (not owned here):** AND-178 (tips on posts), AND-176 (share/bookmark)
  — sibling per-post interactions; AND-100 (post detail) may later host the same
  `PollCard` but is not modified by this ticket.
- **Blocks:** none recorded.
- **Sequencing:** land DTOs + mapper + repository (`core-network`/`core-model`/
  `core-data`) first, then `FeedViewModel` state, then `PollCard` + `PostItem`
  wiring, then UI tests.

## 13. Risks & Open Questions

- **Endpoint shape (OQ):** exact vote path and whether the poll is embedded in the
  post payload vs fetched separately must be confirmed against `/openapi.json` +
  `polls.ts`. The contract in §5 is the working assumption.
- **Multi-select polls (OQ):** backend may support choosing multiple options. This
  ticket assumes single-select; if multi-select exists, `option_id` becomes
  `option_ids` and the UI uses checkboxes — tracked as a follow-up.
- **Vote changes / un-voting (OQ):** `allow_vote_change` handling assumes a re-POST
  replaces the prior vote; needs server confirmation.
- **Result visibility rule:** `show_results_before_vote = false` hides tallies
  pre-vote; confirm whether option labels alone are shown (assumed yes).
- **Dev-host flakiness (Risk):** non-idempotent POST on an unreliable host means a
  vote may succeed server-side but time out client-side, leaving the user on
  `Error`; a manual retry could `409`. Mitigation: `409` re-renders the latest
  server poll into `Results` rather than surfacing a hard error.
- **Race with feed refresh (Risk):** a background page refresh could overwrite a
  fresh `Results` state; mitigation is id-keyed reconciliation favoring the newest
  server poll.

## 14. Acceptance Criteria

AC-1. A post whose payload includes a `poll` renders a `PollCard` (question,
options, total-votes label) inside its `PostItem`; a post without a poll renders
unchanged.

AC-2. **(Source bullet — "Vote updates results.")** Tapping an option on an open,
not-yet-voted poll submits `POST /ui/posts/{postId}/poll/vote` with body
`{"option_id": ...}` and the CSRF header; on `200`, the tapped option is marked as
the viewer's selection, each option shows its server-confirmed count and computed
percentage, and the total-votes label reflects the new total.

AC-3. After a successful vote, options become read-only (no re-vote) unless
`allow_vote_change = true`.

AC-4. A poll the viewer already voted on (`viewer_voted_option_id` set) or a
`closed`/expired poll renders directly in read-only results with the correct
option marked / "Poll closed" label, issuing no vote request on load.

AC-5. While a vote is in flight, options are disabled and a busy affordance shows;
duplicate/rapid taps result in exactly one network call.

AC-6. A failed vote restores the selectable pre-vote state with tallies unchanged
and shows an inline, card-scoped retry; the rest of the feed remains usable.

AC-7. Multiple polls in the feed vote and update independently and survive scroll/
recomposition (state keyed by poll id).

AC-8. Mapper, repository (MockWebServer), ViewModel (Turbine), and Compose UI
tests for the above all pass in CI (AND-050/AND-104).

## 15. Definition of Done

- `PollApi`, `PollDto`/`PollOptionDto`/`PollVoteRequestDto`, `Poll`/`PollOption`
  domain types + mapper, `PollRepository`/`DefaultPollRepository`, `FeedViewModel`
  poll state, and `PollCard` (wired into `PostItem`) are merged under
  `com.testlogon.android.*` in the correct modules.
- All §11 tests are implemented and green in CI; lint/detekt/ktlint (AND-005) pass
  with no new warnings; no new public API is undocumented.
- Endpoint path/shape verified against `/openapi.json` and `polls.ts`, or the
  divergence is recorded in §13 and reconciled.
- Acceptance criteria §14 (esp. AC-2) demonstrably pass on the dev backend; voting
  is non-idempotent and never auto-retried; CSRF header verified on the wire.
- Accessibility (radio semantics, 48dp targets, non-color-only results) and i18n
  (all strings externalized, plurals/number formatting) verified; no PII or
  cookies/CSRF logged in release builds.
- PR reviewed and approved on branch `android-port`; spec status moves
  `draft → done` on merge.
