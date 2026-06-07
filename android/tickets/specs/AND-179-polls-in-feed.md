---
id: AND-179
title: Polls in feed
milestone: M4
epic: E24
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
poll API/render modules (`src/api/endpoints/polls.ts`,
`src/pages/feed/PollCard.tsx`).

> **REVIEW NOTE (data shape correction):** Against the authoritative sources, a
> poll is **not** a flat question+options object. A poll (`PollData`) is a
> *list of questions* (`questions: PollQuestion[]`), and EACH question carries
> its own `options`, `choice_mode` (`"single" | "multi"`) and optional
> `max_selections`. Vote counts and the viewer's own votes are reported
> **per-question**, keyed by `question_id`. This ticket's DTOs/domain model and
> the vote contract have been corrected throughout to match
> (`src/api/types.ts: PollData/PollQuestion/PollOption/PollVoteCounts/PollMyVotes`).
> The single-question case is the common one in the feed, but the model MUST
> support the multi-question, per-question shape the backend actually returns.

The deliverable is the full vertical slice for **one** poll surface: the Moshi
DTOs for the embedded poll block (`poll_data`/`poll_vote_counts`/`poll_my_votes`)
and the vote response (`VoteResponse`), a `core-model` `Poll`/`PollQuestion`
domain type and mapper, a `PollRepository.vote(...)` mutation returning a typed
`ApiResult<PollVoteResult>`, the per-poll/per-question vote state held by
`FeedViewModel`, and a `PollCard` Compose component embedded in `PostItem`. The
single acceptance bullet
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
  `src/api/endpoints/polls.ts` (vote/remove/results/close endpoints + params),
  `src/api/types.ts` (`PollData`, `PollQuestion`, `PollOption`, `VoteResponse`,
  `PollVoteCounts`, `PollMyVotes`), and `src/pages/feed/PollCard.tsx` (render +
  vote behavior). These are authoritative for shapes; §5 wins on divergence.
- **Auth/session:** the web client sends BOTH a cookie session (`credentials:
  "include"`) AND `Authorization: Bearer <accessToken>` + `X-SESSION-ID` headers,
  plus `X-CSRF-Token` from the `ui_csrf` cookie on every request
  (`src/api/client.ts`); the OpenAPI vote route additionally lists
  `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` params. The Android port reuses its
  authenticated OkHttp/Retrofit instance (persistent cookie jar AND-011, CSRF
  interceptor AND-012, 401→refresh authenticator AND-013), which MUST attach
  `X-CSRF-Token` and the session credential the backend expects. **Verified:**
  CSRF is `X-CSRF-Token` echoed from the `ui_csrf` cookie; the 401→single-refresh
  retry matches the web client (`src/api/client.ts`).
- **Dependency AND-099 (Post item composable):** supplies the `PostItem`
  composable and its rendering slots. The poll is rendered as an additional,
  optional content block within `PostItem`.

## 3. Functional Requirements

FR-1. When a feed `Post` carries a non-null `poll`, `PostItem` renders a
`PollCard` showing the question, all options, and a total-votes label.

FR-2. **Pre-vote (open, not yet voted):** each option of each question renders as
a tappable row. (CORRECTED: there is no `show_results_before_vote` field upstream;
the web client `PollCard.tsx` always renders the results bar + count/percent
alongside selectable rows, so the Android port does the same. A hide-before-vote
mode is not part of the contract.)

FR-3. **Voting:** tapping an option submits a single vote for that option. While
the request is in flight, the tapped option shows a busy affordance and all
options are disabled to prevent double submission.

FR-4. **Post-vote (acceptance core):** on success, the chosen option is visually
marked as the user's selection; every option displays its server-confirmed count
and percentage computed against the **question** total
(percentage = `round(count / max(questionTotal,1) * 100)`, matching
`PollCard.tsx`); the total-votes label reflects the new poll total; and rows
become read-only (no further voting) unless `allow_vote_change = true`.

FR-5. **Already-voted on load:** if the feed payload's per-question
`poll_my_votes[question_id]` is non-empty, that question renders in read-only
results with the voted option(s) marked selected — no extra request.

FR-6. **Closed/expired poll:** if `poll_data.closed = true` (or `closes_at`,
epoch seconds, is in the past), options are non-interactive and results are shown
read-only; a "Poll closed" label is displayed.

FR-7. **Failure:** a failed vote restores the pre-vote selectable state, leaves
tallies unchanged, and surfaces an inline, retry-friendly error message scoped to
the card (the rest of the feed item remains usable).

FR-8. State is **per-poll** and keyed by poll id, so multiple polls in the feed
vote and update independently and survive Compose recomposition and list scroll.

FR-9. Unknown JSON fields and unknown enum values are tolerated without throwing.
An unrecognized `choice_mode` (the real enum is `"single" | "multi"`) degrades to
single-select behavior; a malformed/empty poll renders read-only rather than
crashing. NOTE: `choice_mode = "multi"` (with `max_selections`) is a real backend
mode; full multi-select UX is tracked in §13 — this slice ships single-select
voting and renders multi polls read-only if encountered.

## 4. Technical Design

Package roots: `core-network → com.testlogon.android.core.network.poll`,
`core-model → com.testlogon.android.core.model.poll`,
`core-data → com.testlogon.android.core.data.poll`,
`feature-feed → com.testlogon.android.feature.feed`.

### Domain model (`core-model`)

> **CORRECTED** to the real per-question shape. There is no single `question`
> string, no flat `options` list on the poll, and no `viewerVotedOptionId`/
> `showResultsBeforeVote` fields on the backend. Vote counts and the viewer's
> own votes are reported per question via separate maps that travel alongside the
> poll in the post payload (`poll_vote_counts`, `poll_my_votes`).

```kotlin
package com.testlogon.android.core.model.poll

data class Poll(
    val postId: String,
    val questions: List<PollQuestion>,
    val totalVotes: Int,                // poll-wide total (PollData.total_votes)
    val closed: Boolean,
    val closesAt: Instant?,             // null => no expiry (epoch seconds upstream)
    val anonymous: Boolean,
    val allowVoteChange: Boolean,
) {
    // A poll has no single "voted" flag; voted-ness is per question.
    val isInteractive: Boolean get() = !closed
}

data class PollQuestion(
    val id: String,                     // question_id
    val text: String,
    val choiceMode: ChoiceMode,         // SINGLE | MULTI (default SINGLE on unknown, FR-9)
    val maxSelections: Int?,            // multi only; null otherwise
    val options: List<PollOption>,
    val counts: Map<String, Int>,       // optionId -> count (poll_vote_counts[question_id])
    val myVoteOptionIds: List<String>,  // poll_my_votes[question_id]
) {
    val questionTotal: Int get() = counts.values.sum()
    val hasVoted: Boolean get() = myVoteOptionIds.isNotEmpty()
    fun isOptionSelected(optionId: String) = optionId in myVoteOptionIds
}

enum class ChoiceMode { SINGLE, MULTI }

data class PollOption(
    val id: String,                     // option_id
    val text: String,                   // server field is `text`, NOT `label`
) {
    // Percentage is computed against the QUESTION total, not the poll total
    // (matches PollCard.tsx: count / questionTotal * 100).
    fun percentOf(questionTotal: Int, count: Int): Int =
        if (questionTotal <= 0) 0 else Math.round(count * 100f / questionTotal)
}
```

### Retrofit interface (`core-network`)

> **CORRECTED PATH/BODY/RESPONSE.** The spec previously claimed
> `POST /ui/posts/{postId}/poll/vote` returning the full poll — that route does
> **not** exist. The real endpoints (verified against the OpenAPI index and
> `src/api/endpoints/polls.ts`) are:
> - `POST /posts/{post_id}/vote` (req `VoteIn = {question_id, option_id}`,
>   resp `VoteResponse`) — cast a vote.
> - `DELETE /posts/{post_id}/vote` (body `{question_id}`) — remove a vote
>   (used for vote-change / un-vote).
> - `GET /posts/{post_id}/poll-results?question_id=...` (resp
>   `PollResultsResponse`) — fetch per-question results.
> - `POST /posts/{post_id}/close-poll` — author-only close (out of scope here;
>   see §3 scope).
> The vote response is `VoteResponse` (per-question counts), **not** the full
> poll object.

```kotlin
package com.testlogon.android.core.network.poll

interface PollApi {
    // Idempotency NOT assumed: this is a state-changing POST; no GET retry/backoff.
    @POST("posts/{postId}/vote")
    suspend fun vote(
        @Path("postId") postId: String,
        @Body body: PollVoteRequestDto,   // {question_id, option_id}
    ): PollVoteResponseDto                 // VoteResponse, per-question counts

    // Vote-change / un-vote (allow_vote_change == true). Retrofit @HTTP allows a body on DELETE.
    @HTTP(method = "DELETE", path = "posts/{postId}/vote", hasBody = true)
    suspend fun removeVote(
        @Path("postId") postId: String,
        @Body body: PollRemoveVoteRequestDto,  // {question_id}
    ): PollVoteResponseDto

    // Per-question results refresh (GET => eligible for AND-016 idempotent backoff).
    @GET("posts/{postId}/poll-results")
    suspend fun results(
        @Path("postId") postId: String,
        @Query("question_id") questionId: String,
    ): PollResultsResponseDto
}
```

`PollApi` is provided via Hilt from the `@Named("authenticated")` Retrofit
(AND-027), inheriting the cookie jar, CSRF header, and 401→refresh. Paths/shapes
above are **verified** against the OpenAPI index and `src/api/endpoints/polls.ts`;
§5 is authoritative on any future divergence.

### Repository (`core-data`)

> **CORRECTED** signatures: voting is keyed by `(postId, questionId, optionId)`
> and returns a `PollVoteResult` (the updated per-question counts + the viewer's
> votes), since `VoteResponse` is per-question, not the whole poll.

```kotlin
package com.testlogon.android.core.data.poll

// Domain projection of VoteResponse (per-question result of a cast/remove).
data class PollVoteResult(
    val questionId: String,
    val voteCounts: Map<String, Int>,   // optionId -> count
    val totalVotes: Int,
    val myVoteOptionIds: List<String>,  // my_votes (multi) / [my_vote] (single)
)

interface PollRepository {
    suspend fun vote(postId: String, questionId: String, optionId: String): ApiResult<PollVoteResult>
    suspend fun removeVote(postId: String, questionId: String): ApiResult<PollVoteResult>
}

class DefaultPollRepository @Inject constructor(
    private val api: PollApi,
    private val errorMapper: ApiErrorMapper,   // AND-015 FastAPI detail mapping
) : PollRepository {
    override suspend fun vote(postId: String, questionId: String, optionId: String) =
        runApiCatching(errorMapper) {                       // AND-018 helper
            api.vote(postId, PollVoteRequestDto(questionId, optionId)).toDomain()
        }

    override suspend fun removeVote(postId: String, questionId: String) =
        runApiCatching(errorMapper) {
            api.removeVote(postId, PollRemoveVoteRequestDto(questionId)).toDomain()
        }
}
```

### ViewModel state (`feature-feed`)

`PollCard` is stateless; per-poll UI state is owned by the existing
`FeedViewModel` (AND-102) so it survives scroll/recomposition and is testable
without Compose.

> **CORRECTED:** voting state is per **question** (a poll may have several), so
> the in-flight/error key is `(pollKey = postId, questionId)`. The success path
> merges the returned `PollVoteResult` into that question's counts/myVotes rather
> than replacing a whole poll object. There is no `showResultsBeforeVote` field
> upstream — that branch is removed.

```kotlin
sealed interface PollCardState {
    data class Idle(val poll: Poll) : PollCardState            // selectable (open)
    data class Voting(val poll: Poll, val questionId: String, val pendingOptionId: String) : PollCardState
    data class Results(val poll: Poll) : PollCardState          // read-only (closed / showing tallies)
    data class Error(val poll: Poll, val questionId: String, val message: String) : PollCardState
}

// In FeedViewModel, keyed by post id (the poll lives on the post):
private val pollStates = MutableStateFlow<Map<String, PollCardState>>(emptyMap())
val pollUiStates: StateFlow<Map<String, PollCardState>> = pollStates.asStateFlow()

fun onPollOptionSelected(postId: String, questionId: String, optionId: String) {
    val current = pollStates.value[postId] ?: return
    val poll = current.pollOrNull() ?: return
    if (!poll.isInteractive) return                            // closed => no-op (FR-6)
    if (current is PollCardState.Voting) return                // FR-3 double-submit guard
    pollStates.update { it + (postId to PollCardState.Voting(poll, questionId, optionId)) }
    viewModelScope.launch {
        when (val r = pollRepository.vote(postId, questionId, optionId)) {
            is ApiResult.Success ->                            // merge per-question result into the poll
                pollStates.update { it + (postId to PollCardState.Results(poll.applyVote(r.data))) }
            is ApiResult.Error ->
                pollStates.update { it + (postId to PollCardState.Error(poll, questionId, r.error.userMessage())) }
        }
    }
}
```

`Poll.applyVote(result: PollVoteResult)` replaces the matching question's
`counts`/`myVoteOptionIds` and recomputes `totalVotes` from the response.

Initial mapping: when feed pages load, each post with a poll seeds `pollStates`
via `initialStateFor(poll)` = `Results` if `poll.closed` or every question has
been voted on, else `Idle`. (There is no poll-wide `viewerVotedOptionId`;
voted-ness is evaluated per `PollQuestion.hasVoted`.)

### Compose (`feature-feed` + `core-ui`)

```kotlin
@Composable
fun PollCard(
    state: PollCardState,
    onOptionClick: (questionId: String, optionId: String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)
```

`PollCard` renders each question's text, a column of `PollOptionRow`s (`core-ui`
selectable visual: option `text` + animated horizontal results bar + percent/count
against the question total), the poll-wide total-votes label, and, when
applicable, "Poll closed" / inline error + retry. `PostItem` (AND-099) calls
`PollCard` from its optional content slot when the post carries `poll_data`,
hoisting `onOptionClick(questionId, optionId)` up to `FeedViewModel`. (Mirrors the
web `PollCard.tsx`, which maps over `pollData.questions` and computes percentages
per question.)

## 5. API Contract

> **CORRECTED throughout.** Path, request body, response shape, field names, and
> the embedded-poll shape were all wrong in the original draft. The contract
> below is verified against the OpenAPI index (`POST /posts/{post_id}/vote`,
> `req=VoteIn`), `components.schemas.VoteIn`, `src/api/endpoints/polls.ts`, and
> `src/api/types.ts`.

**Vote** — `POST /posts/{postId}/vote`
Headers: session credential (cookie + `X-SESSION-ID`/Bearer per the auth client)
+ `X-CSRF-Token` (auto via interceptors). OpenAPI params also list
`user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`.

Request body (`VoteIn`, **both fields required**, each 1–64 chars):

```json
{ "question_id": "q_1", "option_id": "opt_2" }
```

Success `200` (`VoteResponse` — **per question**, not the full poll):

```json
{
  "ok": true,
  "question_id": "q_1",
  "option_id": "opt_2",
  "vote_counts": { "opt_1": 12, "opt_2": 41, "opt_3": 7 },
  "total_votes": 60,
  "my_vote": "opt_2",
  "my_votes": ["opt_2"]
}
```

**Remove vote** — `DELETE /posts/{postId}/vote` with body `{ "question_id": "q_1" }`,
also returning `VoteResponse` (used when `allow_vote_change` is true).

**Per-question results** (optional refresh) — `GET /posts/{postId}/poll-results?question_id=q_1`
returns `PollResultsResponse` (`options[{option_id,text,count,percentage,voters[]}]`,
`total_votes`, `closed`, `closes_at`, `my_vote`).

The **poll** is embedded in each feed `PostDto` (AND-097) across THREE fields —
not a single `poll` object: `poll_data` (`PollData`), `poll_vote_counts`
(`PollVoteCounts`), and `poll_my_votes` (`PollMyVotes`); present when the post's
`post_type` is `"poll"` or `"survey"`. So no separate poll GET is required on the
feed path. Note `closes_at` is an **epoch-seconds number**, not an ISO string.
DTOs:

```kotlin
@JsonClass(generateAdapter = true)
data class PollDataDto(                                         // PostDto.poll_data
    @Json(name = "questions") val questions: List<PollQuestionDto> = emptyList(),
    @Json(name = "closes_at") val closesAt: Long? = null,       // epoch seconds
    @Json(name = "closed") val closed: Boolean = false,
    @Json(name = "anonymous") val anonymous: Boolean = false,
    @Json(name = "allow_vote_change") val allowVoteChange: Boolean = false,
    @Json(name = "total_votes") val totalVotes: Int = 0,
)

@JsonClass(generateAdapter = true)
data class PollQuestionDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "text") val text: String,
    @Json(name = "choice_mode") val choiceMode: String = "single", // "single" | "multi"
    @Json(name = "options") val options: List<PollOptionDto> = emptyList(),
    @Json(name = "max_selections") val maxSelections: Int? = null,
)

@JsonClass(generateAdapter = true)
data class PollOptionDto(
    @Json(name = "option_id") val optionId: String,
    @Json(name = "text") val text: String,                      // field is `text`, NOT `label`
)

// poll_vote_counts: { questionId: { optionId: count } }; poll_my_votes: { questionId: [optionId] }
// Modeled as Map<String, Map<String, Int>> / Map<String, List<String>> (Moshi map adapters).

@JsonClass(generateAdapter = true)
data class PollVoteResponseDto(                                 // VoteResponse
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "question_id") val questionId: String,
    @Json(name = "option_id") val optionId: String? = null,
    @Json(name = "vote_counts") val voteCounts: Map<String, Int> = emptyMap(),
    @Json(name = "total_votes") val totalVotes: Int = 0,
    @Json(name = "my_vote") val myVote: String? = null,
    @Json(name = "my_votes") val myVotes: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class PollVoteRequestDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "option_id") val optionId: String,
)

@JsonClass(generateAdapter = true)
data class PollRemoveVoteRequestDto(@Json(name = "question_id") val questionId: String)
```

Error responses use the FastAPI `detail` shape mapped by AND-015
(`string | [{msg}] | {code,...}`). **Verified upstream:** every poll route
documents `422 HTTPValidationError`; other status codes below are the standard
FastAPI/auth conventions assumed by the error mapper (see §16 open assumptions —
only `422` is contract-confirmed):

- `401` → 401→refresh authenticator retries once; if still 401, mapped to an auth
  error (card shows generic retry; refresh/expiry UX is AND-044).
- `403` (CSRF/forbidden) / `409` (already voted, assumed) / `410` (poll closed,
  assumed) / `422` (invalid/missing `question_id`/`option_id` — **confirmed**) →
  mapped to a typed `ApiError`; the card shows an inline message and restores the
  selectable state (FR-7). On a conflict the card SHOULD reconcile from the
  freshest server data (re-fetch via `GET /posts/{postId}/poll-results`) rather
  than surfacing a hard error.

## 6. Data & State Management

- **No persistence.** Poll state is in-memory only, derived from the live feed
  page (Paging 3, AND-098) plus the vote response. No Room table and no DataStore
  key are introduced. Room caching of feed pages, if/when added (AND-097 family),
  may carry the embedded poll block; this ticket does not own that schema.
- **Source of truth:** the server. The post-vote `Results` state is built by
  merging the per-question `VoteResponse` (`vote_counts`, `total_votes`,
  `my_vote(s)`) returned by the vote call into the embedded poll (or the embedded
  `poll_data`/`poll_vote_counts`/`poll_my_votes` for the already-voted case). No
  client-side tally arithmetic is trusted; the client only computes display
  percentages from server counts against the question total
  (`PollOption.percentOf`).
- **Keying & lifecycle:** `pollStates: Map<postId, PollCardState>` in
  `FeedViewModel` (the poll is owned by the post; in-flight tracking is per
  `questionId` within the state), surviving recomposition and scroll. On feed
  refresh/invalidate, entries are reconciled by post id; a poll already in
  `Results`/`Error` is reseeded from the freshest server poll. Stable
  `key(questionId)`/`key(optionId)` are used in the Compose `LazyColumn` and option
  `Column` to preserve animation/scroll state.
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
- No PII is introduced; only opaque ids (`question_id`, `option_id`, `post_id`)
  and counts. Vote selections are not logged (see §10). `poll_my_votes` /
  `my_vote(s)` reveal the current user's own vote only and are not persisted to
  disk. NOTE: `PollResultsResponse.options[].voters[]` and `poll_data.anonymous`
  exist upstream; this ticket does not request or display voter identities.
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

- **Mapper unit tests** (`core-model`): `PollDataDto.toDomain()` maps questions +
  options + per-question `poll_vote_counts`/`poll_my_votes`; `closes_at`
  (epoch-seconds `Long`) parses to `Instant`; `percentOf` rounds correctly against
  the question total (incl. `questionTotal = 0` → 0); missing/unknown fields use
  safe defaults; unknown `choice_mode` → `SINGLE`; `isInteractive`/`hasVoted`
  derive correctly for open/voted/closed permutations.
- **Repository contract tests** (`core-data` + MockWebServer, AND-046): `200` →
  `ApiResult.Success` with the per-question `VoteResponse` tallies;
  `403`/`409`/`422` → typed `ApiResult.Error` with mapped FastAPI `detail`;
  verifies `X-CSRF-Token` header and JSON body
  `{"question_id": ..., "option_id": ...}` are sent to `POST /posts/{id}/vote`;
  verifies **no** automatic retry on POST failure; verifies `removeVote` issues
  `DELETE /posts/{id}/vote` with `{"question_id": ...}`.
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

- **Endpoint shape (RESOLVED):** vote path is `POST /posts/{post_id}/vote`
  (`VoteIn = {question_id, option_id}` → `VoteResponse`); the poll is embedded in
  the post payload via `poll_data`/`poll_vote_counts`/`poll_my_votes`. Confirmed
  against the OpenAPI index, `VoteIn`/`VoteResponse` schemas, and
  `src/api/endpoints/polls.ts`. No separate poll GET is needed on the feed path.
- **Multi-select polls (CONFIRMED real, deferred):** backend `choice_mode` is
  `"single" | "multi"` with `max_selections`, and `VoteResponse.my_votes` is a
  list. This slice ships single-select voting; full multi-select checkbox UX
  (multiple votes per question, honoring `max_selections`) is a tracked follow-up.
  Multi polls encountered now render read-only.
- **Vote changes / un-voting (RESOLVED):** the web client exposes `removeVote`
  (`DELETE /posts/{post_id}/vote` with `{question_id}`); a re-cast `POST` updates
  the existing vote. `allow_vote_change` gates the UI affordance.
- **Result visibility rule (RESOLVED):** there is no `show_results_before_vote`
  field; `PollCard.tsx` always shows counts/percentages, so the Android port does
  too. The earlier hide-before-vote assumption was incorrect and is removed.
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
not-yet-voted question submits `POST /posts/{postId}/vote` with body
`{"question_id": ..., "option_id": ...}` and the CSRF header; on `200`
(`VoteResponse`), the tapped option is marked as the viewer's selection, each
option shows its server-confirmed count and computed percentage (against the
question total), and the total-votes label reflects the new poll total.

AC-3. After a successful vote, options become read-only (no re-vote) unless
`allow_vote_change = true` (in which case re-voting / `DELETE /posts/{postId}/vote`
is permitted).

AC-4. A question the viewer already voted on (non-empty
`poll_my_votes[question_id]`) or a `closed`/expired poll renders directly in
read-only results with the correct option(s) marked / "Poll closed" label,
issuing no vote request on load.

AC-5. While a vote is in flight, options are disabled and a busy affordance shows;
duplicate/rapid taps result in exactly one network call.

AC-6. A failed vote restores the selectable pre-vote state with tallies unchanged
and shows an inline, card-scoped retry; the rest of the feed remains usable.

AC-7. Multiple polls in the feed vote and update independently and survive scroll/
recomposition (state keyed by poll id).

AC-8. Mapper, repository (MockWebServer), ViewModel (Turbine), and Compose UI
tests for the above all pass in CI (AND-050/AND-104).

## 15. Definition of Done

- `PollApi`, `PollDataDto`/`PollQuestionDto`/`PollOptionDto`/`PollVoteRequestDto`/
  `PollRemoveVoteRequestDto`/`PollVoteResponseDto`, `Poll`/`PollQuestion`/
  `PollOption` domain types + mapper, `PollRepository`/`DefaultPollRepository`,
  `FeedViewModel` poll state, and `PollCard` (wired into `PostItem`) are merged
  under `com.testlogon.android.*` in the correct modules.
- All §11 tests are implemented and green in CI; lint/detekt/ktlint (AND-005) pass
  with no new warnings; no new public API is undocumented.
- Endpoint path/shape verified against `/openapi.json` and
  `src/api/endpoints/polls.ts` (done in this review — see §16); any future
  divergence is recorded in §13 and reconciled.
- Acceptance criteria §14 (esp. AC-2) demonstrably pass on the dev backend; voting
  is non-idempotent and never auto-retried; CSRF header verified on the wire.
- Accessibility (radio semantics, 48dp targets, non-color-only results) and i18n
  (all strings externalized, plurals/number formatting) verified; no PII or
  cookies/CSRF logged in release builds.
- PR reviewed and approved on branch `android-port`; spec status moves
  `draft → done` on merge.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index `reference/openapi.index.txt`, full spec
`reference/openapi.pretty.json` (`components.schemas.<Name>`), and frontend under
`reference/src/`.

1. **Vote endpoint is `POST /posts/{postId}/vote`.** VERDICT: Corrected (was
   `POST /ui/posts/{postId}/poll/vote`, which does not exist). SOURCE: OpenAPI
   `POST /posts/{post_id}/vote` (op `vote_on_poll_posts__post_id__vote_post`,
   `req=VoteIn`); `src/api/endpoints/polls.ts: castVote`.
2. **Vote request body is `{question_id, option_id}`, both required (1–64 chars).**
   VERDICT: Corrected (was `{option_id}` only). SOURCE:
   `components.schemas.VoteIn` (required `[question_id, option_id]`);
   `src/api/endpoints/polls.ts: castVote`.
3. **Vote response is `VoteResponse` (per-question counts), not the full poll.**
   VERDICT: Corrected. SOURCE: OpenAPI `resp=200:` (untyped in index, body shape
   from frontend) + `src/api/types.ts: VoteResponse`
   (`{ok, question_id, option_id, vote_counts, total_votes, my_vote, my_votes}`).
4. **A poll is a list of questions, each with its own options/`choice_mode`/
   `max_selections`.** VERDICT: Corrected (draft modeled a flat question+options).
   SOURCE: `src/api/types.ts: PollData`, `PollQuestion`, `PollOption`.
5. **Option field is `text`, not `label`.** VERDICT: Corrected. SOURCE:
   `src/api/types.ts: PollOption {option_id, text}`; `src/pages/feed/PollCard.tsx`
   (`opt.text`).
6. **Poll embeds in the post via `poll_data` + `poll_vote_counts` +
   `poll_my_votes` (present for `post_type` "poll"/"survey").** VERDICT: Corrected
   (draft claimed a single embedded `poll` object). SOURCE: `src/api/types.ts`
   feed-post fields lines ~2270-2275 (`poll_data?: PollData`,
   `poll_vote_counts?: PollVoteCounts`, `poll_my_votes?: PollMyVotes`).
7. **Percentage is computed against the QUESTION total, not the poll total.**
   VERDICT: Corrected. SOURCE: `src/pages/feed/PollCard.tsx`
   (`questionTotal = sum(counts)`, `pct = count / questionTotal * 100`).
8. **`closes_at` is epoch-seconds (number), not an ISO-8601 string.** VERDICT:
   Corrected. SOURCE: `src/api/types.ts: PollData.closes_at?: number`;
   `PollCard.tsx` (`new Date(pollData.closes_at * 1000)`).
9. **No `show_results_before_vote` / `viewer_voted_option_id` fields exist.**
   VERDICT: Corrected (both invented by the draft). Voted-ness is per question via
   `poll_my_votes[question_id]`; results always render. SOURCE: absence in
   `src/api/types.ts: PollData/PollQuestion`; `PollCard.tsx` always renders bars.
10. **Vote can be removed / changed via `DELETE /posts/{postId}/vote` with
    `{question_id}`.** VERDICT: Verified. SOURCE: OpenAPI `DELETE /posts/{post_id}/vote`
    (op `remove_poll_vote_posts__post_id__vote_delete`);
    `src/api/endpoints/polls.ts: removeVote`.
11. **Per-question results available via `GET /posts/{postId}/poll-results?
    question_id=...` → `PollResultsResponse`.** VERDICT: Verified. SOURCE: OpenAPI
    `GET /posts/{post_id}/poll-results` (params `question_id`);
    `src/api/endpoints/polls.ts: getPollResults`; `src/api/types.ts:
    PollResultsResponse`.
12. **Author-only `POST /posts/{postId}/close-poll` exists (out of scope here).**
    VERDICT: Verified. SOURCE: OpenAPI `POST /posts/{post_id}/close-poll`;
    `src/api/endpoints/polls.ts: closePoll`; `PollCard.tsx` (`isAuthor` gate).
13. **CSRF is `X-CSRF-Token` echoed from the `ui_csrf` cookie.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
14. **Cookie session is sent (`credentials: "include"`).** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`credentials: "include"` on every fetch).
15. **401 → single transparent session refresh + one retry.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (refresh-once-then-retry on `res.status === 401`).
16. **`choice_mode` enum is `"single" | "multi"` with optional `max_selections`;
    multi-vote returns `my_votes[]`.** VERDICT: Verified. SOURCE: `src/api/types.ts:
    PollQuestion.choice_mode/max_selections`, `VoteResponse.my_votes`.
17. **`422` is the documented validation error for the vote route.** VERDICT:
    Verified. SOURCE: OpenAPI `POST /posts/{post_id}/vote`
    (`resp=...;422:HTTPValidationError`).
18. **POST vote is non-idempotent and must not be auto-retried; GET backoff
    (AND-016) does not apply.** VERDICT: Verified-by-design (Android-side policy,
    consistent with the endpoint being a state-changing POST). SOURCE: OpenAPI
    method = POST; framework ref (Android networking guidance —
    https://developer.android.com/topic/architecture/data-layer).
19. **Option row uses `Role.RadioButton` + `selectableGroup()`, 48dp targets.**
    VERDICT: Unverified-assumption (Android UI choice; web uses `<button>`).
    SOURCE: framework ref —
    https://developer.android.com/develop/ui/compose/accessibility.

### Corrections made

- Vote path `POST /ui/posts/{postId}/poll/vote` → `POST /posts/{postId}/vote`
  (§4 Retrofit, §5, AC-2, §11, §13, §15).
- Request body `{option_id}` → `{question_id, option_id}` (§4, §5, AC-2, §11).
- Vote response: full-poll object → per-question `VoteResponse` (§4 repo/VM, §5,
  §6, §11).
- Domain/DTO model: flat poll → poll = list of `PollQuestion`, each with options,
  `choice_mode`, `max_selections`; per-question `counts`/`myVoteOptionIds` (§1,
  §4, §5, §6).
- Option field `label` → `text`; `vote_count` per-option object → per-question
  `vote_counts` map (§4, §5, §11).
- Embedded poll: single `poll` object → `poll_data` + `poll_vote_counts` +
  `poll_my_votes` (§1, §5, §6).
- Removed invented fields `show_results_before_vote` and `viewer_voted_option_id`;
  rewrote FR-2/FR-5 and the initial-state logic accordingly (§3, §4, §13).
- `closes_at` ISO string → epoch-seconds `Long` (§4, §5, §6, FR-6, §11).
- Percentage base: poll total → question total (FR-4, §4, AC-2).
- State keying: `pollId` → `postId` with per-question in-flight tracking (§4, §6).
- Added `removeVote` / `poll-results` / `close-poll` to the documented contract
  (§4, §5, §13); auth note now reflects cookie + Bearer + `X-SESSION-ID` (§2).

### Open assumptions

- **Non-`422` error codes (`401/403/409/410`):** only `422 HTTPValidationError`
  is documented per route in the OpenAPI index; `403` (CSRF), `409` (already
  voted), `410` (closed) are conventional assumptions for the FastAPI error
  mapper (AND-015) and are not individually confirmed by the sources. Why
  unverifiable: per-route non-validation responses are not enumerated in the
  index, and the live dev host is unreliable for probing.
- **Behavior of re-`POST` when `allow_vote_change = true`:** assumed to replace
  the prior vote (vs. requiring `DELETE` first). Web client calls `castVote`
  again without a preceding delete, supporting the assumption, but the server's
  exact semantics are not documented. Why: not specified in OpenAPI.
- **Whether the feed payload always includes `poll_vote_counts`/`poll_my_votes`
  alongside `poll_data`:** the types mark all three optional. Assumed present for
  poll posts (mirrors `PollCard` props). Why: optionality in `src/api/types.ts`.
- **Compose accessibility specifics** (radio role, 48dp, stateDescription
  strings): Android-platform decisions with no web/back-end equivalent. Framework
  ref only.
- **Exact Android session credential** (cookie jar vs. `X-SESSION-ID`/Bearer
  header parity with web): the Android auth client (AND-011/012/013/027) governs
  this; this ticket assumes it already sends whatever the backend requires.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device);
**Emu35** = headless AVD `test35` (x86_64, API 35); **Phys** = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). UI/instrumented cases run on Emu35
in CI unless a row says otherwise; no poll case requires camera/biometrics/WebRTC,
so the physical device is needed only for the ABI/API-parity smoke (TC-13).

- **TC-AND-179-01 — Mapper maps the per-question poll shape.** Type: unit (JVM).
  Target: `PollDataDto.toDomain()`. Preconditions: a JSON fixture with 2 questions,
  one `single` + one `multi`, `poll_vote_counts`/`poll_my_votes` per question,
  `closes_at` epoch-seconds. Steps: deserialize via Moshi, map to domain.
  Expected: questions/options/`text`, per-question counts + `myVoteOptionIds`,
  `closesAt` Instant, `totalVotes`, `anonymous`, `allowVoteChange` all correct;
  `choiceMode` parses SINGLE/MULTI. Traces: AC-1, AC-8.

- **TC-AND-179-02 — Percentage + safe-default math.** Type: unit (JVM). Target:
  `PollOption.percentOf` / `PollQuestion.questionTotal`. Preconditions: counts
  {opt_1:12,opt_2:41,opt_3:7} (questionTotal 60); plus an empty-counts question.
  Steps: compute percentages. Expected: 20/68/12 (rounded) for the first;
  questionTotal 0 → all 0, no divide-by-zero. Traces: AC-2, AC-8.

- **TC-AND-179-03 — Lenient parsing / unknown enum.** Type: unit (JVM). Target:
  mapper. Preconditions: JSON with an unknown top-level field, `choice_mode:
  "ranked"`, a question with empty `options`. Steps: map. Expected: no throw;
  unknown `choice_mode` → SINGLE; empty-option question maps to a read-only,
  zero-row question. Traces: AC-1 (FR-9).

- **TC-AND-179-04 — Vote contract: request/headers/response.** Type:
  contract/MockWebServer (JVM). Target: `DefaultPollRepository.vote`.
  Preconditions: MockWebServer enqueues `200` with a `VoteResponse` body. Steps:
  call `vote(postId, questionId, optionId)`; inspect recorded request. Expected:
  `POST /posts/{postId}/vote`; body exactly `{"question_id":...,"option_id":...}`;
  `X-CSRF-Token` header present; result is `ApiResult.Success` carrying
  `vote_counts`/`total_votes`/`my_vote(s)`. Traces: AC-2, AC-8.

- **TC-AND-179-05 — Vote 422 validation error mapping.** Type:
  contract/MockWebServer (JVM). Target: repository + `ApiErrorMapper`.
  Preconditions: MockWebServer enqueues `422` with FastAPI
  `{"detail":[{"msg":"...","loc":[...]}]}`. Steps: call `vote`. Expected:
  `ApiResult.Error` with the mapped detail message; no crash. Traces: AC-6, AC-8.

- **TC-AND-179-06 — No auto-retry on POST failure.** Type: contract/MockWebServer
  (JVM). Target: repository transport. Preconditions: enqueue a single `500`
  (or socket drop). Steps: call `vote`; count `takeRequest()` invocations.
  Expected: exactly ONE request reaches the server (POST is non-idempotent; GET
  backoff AND-016 not applied); returns `ApiResult.Error`. Traces: AC-6.

- **TC-AND-179-07 — Remove-vote contract.** Type: contract/MockWebServer (JVM).
  Target: `DefaultPollRepository.removeVote`. Preconditions: `200` VoteResponse
  enqueued. Steps: call `removeVote(postId, questionId)`. Expected:
  `DELETE /posts/{postId}/vote` with body `{"question_id":...}`; success mapped.
  Traces: AC-3.

- **TC-AND-179-08 — ViewModel happy path Idle→Voting→Results.** Type: unit/Turbine
  (JVM). Target: `FeedViewModel.onPollOptionSelected` with `FakePollRepository`.
  Preconditions: poll seeded `Idle`, fake returns updated `VoteResponse`. Steps:
  emit option tap; collect states. Expected: ordered `Idle → Voting → Results`;
  in Results the tapped option is selected, counts/percentages and poll total
  reflect the response, question becomes non-interactive. Traces: AC-2, AC-3, AC-8.

- **TC-AND-179-09 — ViewModel failure restores selectable state.** Type:
  unit/Turbine (JVM). Target: ViewModel. Preconditions: fake returns
  `ApiResult.Error`. Steps: tap, observe. Expected: `Idle → Voting → Error`;
  tallies unchanged from seed; an inline message is exposed; a `Retry` re-issues
  the same `(question,option)` vote. Traces: AC-6, AC-8.

- **TC-AND-179-10 — Double-tap guard issues exactly one call.** Type: unit/Turbine
  (JVM). Target: ViewModel. Preconditions: fake suspends mid-vote. Steps: emit two
  rapid taps (same and different options) while `Voting`. Expected: second tap
  is dropped; the fake records exactly one `vote()` call. Traces: AC-5.

- **TC-AND-179-11 — Already-voted / closed seed directly to Results.** Type:
  unit/Turbine (JVM). Target: `initialStateFor`. Preconditions: (a) poll with
  non-empty `poll_my_votes`; (b) poll with `closed = true`. Steps: seed feed.
  Expected: both start in `Results` (read-only), correct options marked / closed;
  tapping issues no network call. Traces: AC-4.

- **TC-AND-179-12 — Compose: vote updates results + a11y.** Type: Compose-UI
  (Emu35). Target: `PollCard` in the AND-104 harness. Preconditions: open,
  not-yet-voted poll. Steps: assert each option exposes `Role.RadioButton` and a
  >=48dp target; tap an option; let the fake return updated tallies. Expected:
  hoisted `onOptionClick(questionId, optionId)` fires; selected marker shown;
  per-option percent/count and the incremented total render (the literal "vote
  updates results"); TalkBack semantics announce votes/percent/selected; results
  conveyed by width AND numeric label (not color-only). Traces: AC-2, AC-5, AC-8.

- **TC-AND-179-13 — Closed/error Compose states + independence on scroll.** Type:
  Compose-UI (Emu35). Target: `PollCard` / feed list. Preconditions: a feed with
  a closed poll, an errored poll, and two open polls. Steps: render; scroll the
  list past and back; trigger an error on one poll. Expected: closed poll
  read-only with "Poll closed" label; errored poll shows inline card-scoped
  retry while siblings stay interactive; the two open polls vote independently and
  retain state across scroll/recomposition. Traces: AC-1, AC-6, AC-7.

- **TC-AND-179-14 — Offline short-circuit (no network call).** Type: integration
  (Emu35, airplane mode / AND-017 probe stubbed offline). Target: ViewModel +
  connectivity probe. Preconditions: probe reports offline. Steps: tap an option.
  Expected: an offline message is shown without any HTTP request; card stays
  selectable; tapping again after "reconnect" succeeds. Traces: AC-6.

- **TC-AND-179-15 — Security: vote never sent without CSRF; nothing sensitive
  logged.** Type: contract/MockWebServer (JVM) + manual log inspection.
  Preconditions: authenticated client with CSRF interceptor; debug + release
  builds. Steps: cast a vote; inspect the wire and Logcat. Expected: every vote
  carries `X-CSRF-Token`; release logs contain no vote selection, poll content,
  cookies, or CSRF token (only debug-level breadcrumbs with code+latency).
  Traces: AC-2 (§8/§10).

- **TC-AND-179-16 — ABI/API parity smoke (MUST run on physical device).** Type:
  instrumented/e2e (Phys — SM-A156U, arm64-v8a, API 34). Target: end-to-end vote
  against the dev backend (or MockWebServer on host). Preconditions: app
  installed on the A15 via adb. Steps: open a feed poll, cast a vote, observe
  results. Expected: identical behavior to Emu35 (x86_64/API 35) — no
  arm64-vs-x86 or API-34-vs-35 Moshi/Compose differences; vote succeeds and
  results update. Traces: AC-2, AC-8. (Physical device required to catch
  ABI/API-level regressions per the test-targets note; no camera/biometrics
  needed here.)

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (poll renders; no-poll unchanged) | TC-01, TC-03, TC-13 |
| AC-2 (vote updates results; correct path/body/CSRF) | TC-02, TC-04, TC-08, TC-12, TC-15, TC-16 |
| AC-3 (read-only post-vote unless allow_vote_change) | TC-07, TC-08 |
| AC-4 (already-voted / closed seed read-only, no request) | TC-11 |
| AC-5 (in-flight disable; exactly one call) | TC-10, TC-12 |
| AC-6 (failure restores state; card-scoped retry; offline) | TC-05, TC-06, TC-09, TC-13, TC-14 |
| AC-7 (multiple polls independent across scroll) | TC-13 |
| AC-8 (mapper/repo/VM/Compose tests green in CI) | TC-01, TC-02, TC-04, TC-05, TC-08, TC-09, TC-12, TC-16 |
