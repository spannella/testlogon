---
id: AND-284
title: Q&A
milestone: M6
epic: E38
priority: P2
size: M
status: draft
depends_on: [AND-280]
blocks: []
---

# AND-284 — Q&A

## 1. Overview & Goal

Add a live **Q&A** surface to the TestLogon Android viewer experience: while an
authorized viewer watches a live stream (the HLS player delivered by AND-280),
they can **ask a question**, **upvote** existing questions, and see the
broadcaster-/moderator-**featured** question rendered prominently. Questions are
served from the live-Q&A endpoints under `/ui/live-qa/*` (web reference scope
`qa/questions` + upvote), ordered by community upvotes, and refreshed on a
bounded polling cadence so the list stays reasonably live without a dedicated
stream transport.

This ticket owns: the `feature-live-qa` module's data layer
(`LiveQaApi`, DTOs/adapters, `LiveQaRepository`), the `LiveQaViewModel`
(`StateFlow<LiveQaUiState>`), and the Compose Q&A panel that mounts inside the
live viewer (ask composer, upvotable question list, featured banner). It does
**not** own: HLS playback or stream/playback authorization (AND-280), live chat
or its SSE transport (AND-281), tips/goals (AND-282), or the products shelf
(AND-283). It reuses the established session/cookie/CSRF network stack and the
shared `ApiResult`/error-mapping primitives — no new auth handling.

Success: an authorized viewer on a live stream submits a question and sees it
appear; upvotes a question and sees its count increment (optimistically, with
rollback on failure); and when the broadcaster features a question, that
question renders in a distinct "Featured" banner above the list.

## 2. Context & References

- **Module:** `feature-live-qa` (new), namespace
  `com.testlogon.android.feature.liveqa`. Depends on `core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`. App layering
  `app -> feature-live-qa -> core-*`.
- **Upstream (AND-280 — Viewer playback / HLS):** owns the live viewer screen,
  the stream/`streamId` context, and `playback-url` + `playback/verify`
  authorization. This ticket's Q&A panel is hosted **inside** the AND-280 viewer
  and receives the active `streamId` (and the viewer's authorized state) from it;
  Q&A is shown only for an authorized viewer of a live stream.
- **Siblings (same epic E38 / M6):** AND-281 live chat (SSE), AND-282 tips &
  goals, AND-283 products shelf. Q&A is intentionally a **separate, pollable**
  surface and must not depend on the chat SSE transport.
- **Auth:** cookie-based session (`POST /ui/session/start` -> MFA ->
  `/ui/session/finalize` -> `GET /ui/me`). All Q&A requests ride the persistent
  cookie jar; mutations (ask, upvote) send the `X-CSRF-Token` header echoed from
  the `ui_csrf` cookie. On `401`, the shared OkHttp authenticator performs one
  `POST /ui/session/refresh` then retries; Q&A code treats a persisting `401` as
  terminal (signed-out), not a retry loop.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; design for ~20s timeouts, bounded backoff retry
  for idempotent GETs only, offline/stale UI states). OpenAPI at
  `/openapi.json`. Web reference: `frontend/src/api/endpoints/` (live-qa
  endpoints), shared types `frontend/src/api/types.ts`. **Confirm exact paths,
  field names, and the featured/upvote contract against `/openapi.json` and the
  web client during implementation** (see §13).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, DataStore (no Room cache needed here). minSdk 24, compile/target
  35, JDK 17.

## 3. Functional Requirements

FR-1. **List questions.** On entering the Q&A panel for a `streamId`, load the
question list via `GET /ui/live-qa/{streamId}/questions`, ordered by upvote count
descending (then recency). Show loading, loaded, empty, and error states.

FR-2. **Polling refresh.** While the panel is on-screen (lifecycle
`STARTED`/`RESUMED`), re-fetch the list on a bounded interval (default 8s,
configurable) to approximate live behavior. Polling stops when the panel is
backgrounded/disposed and resumes on return. No SSE/WebSocket in this ticket.

FR-3. **Pull-to-refresh.** A manual refresh gesture re-fetches immediately and
resets the polling timer.

FR-4. **Ask a question.** A composer (multiline text field + Submit) posts
`POST /ui/live-qa/{streamId}/questions` with the body text. On success the new
question is inserted/merged into the list and the composer clears. Enforce a
client-side max length (default 280 chars) with a live counter; Submit is
disabled for empty/whitespace-only or over-limit input and while a submit is
in-flight.

FR-5. **Upvote / un-upvote.** Each question row shows an upvote control with the
current count and the viewer's voted state. Tapping toggles the vote
**optimistically** (count +/-1, state flips immediately) and calls
`POST /ui/live-qa/{streamId}/questions/{questionId}/upvote` (and the
corresponding un-upvote, per the confirmed contract — see §5/§13). On failure,
roll back to the prior count/state and surface a transient error. Repeated taps
are debounced/coalesced; a viewer cannot upvote their own already-voted question
twice (idempotent on the server; UI reflects toggle state).

FR-6. **Featured question.** If the payload marks a question `featured == true`
(or returns a dedicated `featured` object), render it in a distinct **Featured**
banner pinned above the list. The featured question is de-duplicated from the
main list (or visually tagged in place, per the confirmed shape). When featuring
changes between polls, the banner updates without losing scroll position.

FR-7. **Empty / unauthorized states.** Empty list -> non-error empty state ("No
questions yet — be the first to ask"). If the viewer is not authorized for the
stream (per AND-280) the panel renders a disabled/explanatory state and does not
poll.

FR-8. **State preservation.** List, scroll position, composer draft text, and
optimistic vote state survive configuration changes (held in
`ViewModel`/`SavedStateHandle`).

## 4. Technical Design

### 4.1 Layering

```
LiveQaPanel (Composable)              feature-live-qa/ui   (hosted by AND-280 viewer)
  -> LiveQaViewModel (Hilt)           feature-live-qa/ui
       -> LiveQaRepository            feature-live-qa/data
            -> LiveQaApi (Retrofit)   feature-live-qa/data  (shared OkHttp from core-network)
```

The panel is a self-contained composable the AND-280 viewer screen embeds (e.g.
in a bottom sheet / tab alongside chat). It is parameterized by `streamId` and an
`isAuthorized: Boolean`.

### 4.2 API + Repository

```kotlin
interface LiveQaApi {
    @GET("ui/live-qa/{streamId}/questions")
    suspend fun getQuestions(
        @Path("streamId") streamId: String,
    ): Response<QaQuestionsResponseDto>

    @POST("ui/live-qa/{streamId}/questions")
    suspend fun ask(
        @Path("streamId") streamId: String,
        @Body body: AskQuestionRequestDto,
    ): Response<QaQuestionDto>

    @POST("ui/live-qa/{streamId}/questions/{questionId}/upvote")
    suspend fun upvote(
        @Path("streamId") streamId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    @DELETE("ui/live-qa/{streamId}/questions/{questionId}/upvote")
    suspend fun removeUpvote(
        @Path("streamId") streamId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>
}
```

```kotlin
class LiveQaRepository @Inject constructor(
    private val api: LiveQaApi,
    private val errorMapper: ApiErrorMapper,   // core-network detail mapping
) {
    suspend fun questions(streamId: String): ApiResult<QaSnapshot>
    suspend fun ask(streamId: String, text: String): ApiResult<QaQuestion>
    suspend fun setUpvote(
        streamId: String, questionId: String, voted: Boolean,
    ): ApiResult<QaQuestion>
}
```

`setUpvote` dispatches to `upvote`/`removeUpvote` based on the target state.
Responses are mapped to domain `QaQuestion`/`QaSnapshot`; failures go through the
shared FastAPI `detail` mapper (`string | [{msg}] | {code,...}`) into
`ApiResult.Failure` carrying a user-facing message + `isRetryable`.

### 4.3 ViewModel & State

```kotlin
@HiltViewModel
class LiveQaViewModel @Inject constructor(
    private val repository: LiveQaRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val streamId: String = savedState["streamId"] ?: error("streamId required")

    private val _uiState = MutableStateFlow(LiveQaUiState())
    val uiState: StateFlow<LiveQaUiState> = _uiState.asStateFlow()

    fun onComposerChange(text: String)
    fun submitQuestion()
    fun toggleUpvote(questionId: String)
    fun refresh()
    fun startPolling()   // called from a DisposableEffect / repeatOnLifecycle
    fun stopPolling()
}

data class LiveQaUiState(
    val phase: Phase = Phase.Loading,           // Loading | Content | Error | Unauthorized
    val featured: QaQuestion? = null,
    val questions: List<QaQuestion> = emptyList(),
    val composerText: String = "",
    val composerError: String? = null,
    val isSubmitting: Boolean = false,
    val isRefreshing: Boolean = false,
    val transientMessage: String? = null,        // snackbar (e.g. upvote rollback)
) {
    val canSubmit: Boolean
        get() = composerText.isNotBlank() &&
            composerText.length <= MAX_LEN && !isSubmitting
    enum class Phase { Loading, Content, Error, Unauthorized }
    companion object { const val MAX_LEN = 280 }
}
```

```kotlin
data class QaQuestion(
    val id: String,
    val text: String,
    val authorDisplayName: String,
    val upvotes: Int,
    val viewerHasUpvoted: Boolean,
    val featured: Boolean,
    val createdAt: Instant,
)
data class QaSnapshot(val featured: QaQuestion?, val questions: List<QaQuestion>)
```

Polling: `startPolling()` launches a `viewModelScope` job looping `refresh()`
every `POLL_INTERVAL` (8s) with `delay`; `stopPolling()` cancels it. The panel
drives this via `LifecycleResumeEffect`/`repeatOnLifecycle(STARTED)` so it never
polls in the background. Merge strategy on refresh: replace by `id`, preserving
any in-flight optimistic vote not yet confirmed.

### 4.4 Compose

```kotlin
@Composable
fun LiveQaPanel(
    streamId: String,
    isAuthorized: Boolean,
    viewModel: LiveQaViewModel = hiltViewModel(),
    modifier: Modifier = Modifier,
)

@Composable private fun FeaturedQuestionBanner(q: QaQuestion)
@Composable private fun QuestionRow(q: QaQuestion, onUpvote: () -> Unit)
@Composable private fun UpvoteButton(count: Int, voted: Boolean, onClick: () -> Unit)
@Composable private fun AskComposer(
    text: String, error: String?, isSubmitting: Boolean, canSubmit: Boolean,
    onChange: (String) -> Unit, onSubmit: () -> Unit,
)
@Composable private fun QaEmpty()
@Composable private fun QaError(message: String, onRetry: () -> Unit)
```

`LiveQaPanel` collects `uiState` with `collectAsStateWithLifecycle()`, hosts a
`PullToRefreshBox`, renders `FeaturedQuestionBanner` (when non-null) above a
`LazyColumn` of `QuestionRow`s keyed by `q.id`, with `AskComposer` pinned at the
bottom. Phase dispatch -> loading / content / error / unauthorized.

### 4.5 Hilt wiring

A `LiveQaModule` provides `LiveQaApi` via the shared Retrofit (built on the
core-network OkHttp with cookie jar + CSRF + refresh authenticator). No new
network client. `LiveQaRepository` and `LiveQaViewModel` use constructor
injection (`@HiltViewModel`).

## 5. API Contract

Paths use the `/ui/live-qa/*` namespace; **exact paths/fields must be confirmed
against `/openapi.json` and the web client** (§13). All requests carry session
cookies; mutations carry `X-CSRF-Token`.

**List** — `GET /ui/live-qa/{streamId}/questions`

```json
{
  "featured": {
    "id": "q_01HZ...",
    "text": "When does the next drop go live?",
    "author": { "display_name": "Ravi" },
    "upvotes": 42,
    "viewer_has_upvoted": true,
    "featured": true,
    "created_at": "2026-06-05T17:02:10Z"
  },
  "questions": [
    {
      "id": "q_01J0...",
      "text": "Can you show the setup?",
      "author": { "display_name": "Mira" },
      "upvotes": 12,
      "viewer_has_upvoted": false,
      "featured": false,
      "created_at": "2026-06-05T17:05:44Z"
    }
  ]
}
```

If the API returns a flat `questions[]` with a `featured` boolean per item (no
top-level `featured`), the repository derives `QaSnapshot.featured` as the first
`featured == true` item and excludes it from the list. Either shape is supported
behind the mapper.

**Ask** — `POST /ui/live-qa/{streamId}/questions`

```json
// request
{ "text": "Can you show the setup?" }
// response 201 -> single QaQuestionDto (same shape as a list item)
```

**Upvote** — `POST /ui/live-qa/{streamId}/questions/{questionId}/upvote`
returns the updated `QaQuestionDto` (with new `upvotes`, `viewer_has_upvoted: true`).
**Un-upvote** — `DELETE .../upvote` (or `POST .../downvote` if the backend uses a
single toggle/verb — confirm in §13) returns the question with
`viewer_has_upvoted: false`. The UI sends the *intended* target state and trusts
the server count in the response (replacing the optimistic value).

**Errors.** FastAPI `detail` (`string | [{msg}] | {code,...}`) -> shared mapper.
Relevant codes: `401` -> single refresh then retry (else terminal/sign-out);
`403` -> not authorized for stream / Q&A closed -> Unauthorized phase or
transient message; `404` -> stream/question gone -> remove from list + transient
message; `409`/`422` on upvote (already/not voted) -> reconcile to server state,
no error toast; `429` -> back off polling.

## 6. Data & State Management

- **Source of truth:** `StateFlow<LiveQaUiState>` in `LiveQaViewModel`. No Room
  cache (live, ephemeral data); polling is the freshness mechanism.
- **Persistence:** only the composer **draft text** is persisted across config
  changes via `SavedStateHandle` (key `qa_draft`). No questions persisted to
  disk; no PII at rest.
- **Optimistic updates:** `toggleUpvote` immediately mutates the in-memory item
  (`upvotes +/-1`, `viewerHasUpvoted` flipped) and records the prior value; on
  `ApiResult.Success` it adopts the server-returned count, on `Failure` it rolls
  back and sets `transientMessage`. A per-question in-flight guard coalesces rapid
  taps (latest-wins via a `Map<String, Job>` cancel-and-replace).
- **Merge on poll:** new snapshot replaces by `id`; questions with an in-flight
  optimistic vote keep the optimistic value until that request resolves.
- **Featured:** stored as a nullable `QaQuestion` separate from `questions` so
  banner and list recompose independently; list excludes the featured id.

## 7. Error Handling & Resilience

- **Timeouts:** rely on core-network ~20s call timeout. List GET failures show
  inline error (empty list -> full error state with Retry; non-empty -> keep list
  + transient message, polling continues).
- **Idempotent GET retry:** list polling uses the shared bounded-backoff retry
  interceptor for GETs only. On repeated failures, **increase the poll interval**
  (exponential backoff up to e.g. 60s) instead of hammering the unreliable host;
  reset to base interval on first success.
- **Mutations (ask/upvote) are NOT auto-retried** at the network layer
  (non-idempotent ask; upvote toggled by explicit user intent). Ask failure
  re-enables Submit and keeps the draft; upvote failure rolls back.
- **401:** shared authenticator does one `POST /ui/session/refresh` + retry; a
  persisting `401` => terminal: stop polling, surface signed-out state (defer to
  global auth handling).
- **Offline/stale:** no connectivity -> immediate failure; show offline error
  state with Retry; pause polling until connectivity returns (observe the
  core connectivity signal where available).
- **429 / backoff:** widen poll interval; show no error spam.
- **Empty vs error:** empty only when a successful response yields zero
  questions and no featured.

## 8. Security & Privacy

- All requests use the shared cookie-authenticated OkHttp client; mutations send
  `X-CSRF-Token` from the `ui_csrf` cookie. This ticket adds no bespoke auth and
  must not bypass the shared client.
- Dev backend is **plaintext HTTP** (known dev-only posture); cleartext is gated
  to debug/dev flavors by the build/network tickets. Production uses HTTPS.
- **Input handling:** question text is user-generated; render as plain text (no
  HTML/Markdown rendering) to avoid injection/spoofing in the UI. Enforce length
  client-side; the server is authoritative.
- **Abuse surface:** upvote is server-idempotent per viewer; the client never
  fabricates counts (always reconciles to server response). Rate limiting is a
  server concern; client honors `429` via backoff.
- **Privacy/logging:** never log question text, author identifiers, cookies, or
  CSRF tokens (see §10). No question data persisted to disk; only the local draft
  in `SavedStateHandle`.

## 9. Accessibility & i18n

- All strings externalized in `feature-live-qa/res/values/strings.xml`:
  `qa_title`, `qa_empty`, `qa_error_generic`, `qa_retry`, `qa_ask_hint`,
  `qa_ask_submit`, `qa_char_counter` (plurals), `qa_featured_label`,
  `qa_upvote_cd`, `qa_upvoted_cd`, `qa_unauthorized`. No hardcoded literals.
- Upvote control: min 48x48dp touch target; `contentDescription` reflects state
  and count ("Upvote, 12 votes" / "Remove upvote, 13 votes"); use
  `Role.Button`/toggleable semantics so TalkBack announces checked state.
- Featured banner exposes a merged semantics node prefixed with the localized
  "Featured" label.
- Composer field has a label/hint, an associated live character counter with
  `liveRegion` for over-limit feedback, and an IME submit action.
- Upvote counts use `pluralStringResource`; numbers are locale-formatted. RTL via
  start/end padding only.

## 10. Telemetry & Logging

- Debug logs (Timber, debug builds only), **no content/PII**:
  `qa_list_result{success,count,featuredPresent,durationMs}`,
  `qa_poll_backoff{intervalMs}`, `qa_ask_result{success}`,
  `qa_upvote_result{success,toggledTo}`, `qa_load_error{type,httpStatus}`.
- Analytics (if the core analytics facade is available): `qa_panel_viewed`,
  `qa_question_asked`, `qa_question_upvoted{voted}`, `qa_featured_shown`,
  `qa_load_failed{stage,errorType}`. Counts/flags only — never question text,
  author names, ids, cookies, or CSRF tokens.

## 11. Testing Strategy

**Unit — `LiveQaRepository` (JUnit + MockWebServer, core-testing):**
- List success maps top-level `featured` + `questions`; flat-shape fallback
  derives featured from `featured == true` and excludes it from the list.
- Ask success returns the new `QaQuestion`; `422`/`detail` array maps to a
  user-facing failure.
- `setUpvote(voted=true)` calls `POST .../upvote`; `voted=false` calls `DELETE`;
  both adopt the server-returned count. `409` reconciles without error.
- `401` then post-refresh `200` succeeds; persistent `401` => terminal failure.

**Unit — `LiveQaViewModel` (Turbine + coroutines-test):**
- Optimistic upvote increments immediately; success keeps server count; failure
  rolls back and sets `transientMessage`.
- Rapid double-tap coalesces to a single in-flight request (latest-wins).
- Submit disabled for blank/over-limit; success clears composer and merges item;
  failure keeps draft and re-enables Submit.
- Polling emits periodic refreshes while started and stops on `stopPolling()`;
  repeated failures widen the interval (backoff) and a success resets it.
- Poll merge preserves an in-flight optimistic vote.

**Compose UI (`createComposeRule`, fake ViewModel/repository):**
- Loading -> list with N rows; featured row renders in the banner and not in the
  list.
- Upvote tap flips checked state and increments count; rollback path shows prior
  count after induced failure.
- Composer counter/disable behavior; submit clears field.
- Empty state vs error state are distinct; Retry re-invokes load.
- Unauthorized phase renders the explanatory state and the composer is disabled.

**Manual / live (acceptance):** against `http://18.222.237.167:8000`, signed in
and authorized for a live stream: ask a question (appears), upvote one (count
increments and persists across a poll), and confirm a broadcaster-featured
question renders in the banner.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-280 (Viewer playback / HLS):** provides the live viewer
  host, the authorized `streamId` context, and stream authorization. The Q&A
  panel mounts inside that screen and consumes its `streamId`/`isAuthorized`.
  AND-280 must land first.
- **Transitive:** core-network session stack (cookie jar, CSRF interceptor, 401
  refresh authenticator), `ApiResult` + FastAPI `detail` mapper, and core-ui
  state composables (loading/empty/error/offline) — all in place by M1.
- **Adjacent (no code dependency):** AND-281 chat (SSE), AND-282 tips/goals,
  AND-283 products shelf share the viewer surface but are independent; Q&A
  deliberately avoids the chat SSE transport.
- **Blocks:** none in the source backlog.
- **Sequencing:** AND-280 -> **AND-284**.

## 13. Risks & Open Questions

- **OQ-1 (endpoint shape):** exact `/ui/live-qa/*` paths, the ask body field name
  (`text` vs `body`/`content`), and the upvote contract — separate `POST`/`DELETE`
  vs a single toggle/`downvote` verb — must be confirmed against `/openapi.json`
  and the web client. The mapper/`setUpvote` indirection isolates this change.
- **OQ-2 (featured representation):** whether `featured` is a top-level object or
  a per-item boolean (or multiple featured allowed). Repository supports both;
  multi-featured would require a banner list.
- **OQ-3 (vote ownership):** whether a viewer may upvote their own question and
  whether un-upvote is permitted; UI assumes a toggle, server is authoritative.
- **Risk-1 (no realtime):** polling (default 8s) means Q&A is near-live, not
  instant; acceptable for P2. If a realtime feed is later required it becomes a
  follow-up (reuse AND-281's SSE infra).
- **Risk-2 (flaky dev host):** ~20s timeouts make polling failure-prone;
  mitigated by GET retry + exponential poll backoff and clear retriable error UI.
  Mutations are not auto-retried to avoid duplicate questions.
- **OQ-4 (moderation/visibility):** whether asked questions are pending
  moderation before appearing; if so, an "awaiting review" state is needed —
  treat as a small follow-up if the API exposes a status field.

## 14. Acceptance Criteria

AC-1. An authorized viewer can **ask a question**; on success it appears in the
list and the composer clears. *(maps to source Acceptance: "Ask … questions")*

AC-2. A viewer can **upvote** a question; the count increments immediately
(optimistic) and reflects the server count after the response; a failed upvote
rolls back to the prior count/state with a transient error. *(maps to: "upvote
questions")*

AC-3. A broadcaster-**featured** question renders in a distinct Featured banner
above the list and is not duplicated in the list. *(maps to: "featured render")*

AC-4. The list loads, polls on a bounded interval while visible, stops polling
when backgrounded/disposed, and supports pull-to-refresh.

AC-5. Empty, error (retriable), and unauthorized states are distinct and render
correctly; non-empty refresh failures preserve the list with a transient error.

AC-6. Submit is disabled for empty/whitespace/over-limit input and while a
submit is in-flight; an accurate character counter is shown.

AC-7. Composer draft, list, scroll position, and optimistic vote state survive a
configuration change.

AC-8. Unit (repository + ViewModel), MockWebServer (401-refresh, upvote
toggle/409, error mapping), and Compose tests (loading/empty/error/unauthorized,
optimistic upvote + rollback, featured banner) pass in CI.

## 15. Definition of Done

- `feature-live-qa` module created (`com.testlogon.android.feature.liveqa`) with
  `LiveQaApi`, DTOs/adapters, `LiveQaRepository`, `LiveQaViewModel`, and
  `LiveQaPanel` + child composables (`FeaturedQuestionBanner`, `QuestionRow`,
  `UpvoteButton`, `AskComposer`, empty/error states).
- Mounts inside the AND-280 viewer via `LiveQaPanel(streamId, isAuthorized)`;
  uses the shared cookie/CSRF OkHttp client only (no new network client).
- All FR-1..FR-8 implemented; AC-1..AC-8 verified.
- Optimistic upvote with rollback, bounded polling with backoff, and the
  featured banner all working against the dev backend.
- All user-facing strings externalized; a11y semantics, toggle states, and
  touch targets in place; counts use plurals.
- No question content, ids, author names, cookies, or CSRF tokens logged; only
  the composer draft persisted (`SavedStateHandle`).
- Unit + MockWebServer + Compose tests added and green:
  `./gradlew :feature-live-qa:test :feature-live-qa:connectedDebugAndroidTest`
  (or instrumented equivalent) passes.
- Endpoint paths/field names reconciled against `/openapi.json` and the web
  client; any deviation from §5 documented in code (KDoc) and this spec updated.
- Lint/detekt clean; merged to `android-port` with a passing review against this
  spec.
