---
id: AND-284
title: Q&A
milestone: M6
epic: E38
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-07
depends_on: [AND-280]
blocks: []
---

# AND-284 — Q&A

## 1. Overview & Goal

Add a live **Q&A** surface to the TestLogon Android viewer experience: while an
authorized viewer watches a live stream (the HLS player delivered by AND-280),
they can **ask a question**, **upvote** existing questions, and see the
broadcaster-/moderator-**featured** question rendered prominently. Questions are
served from the live-Q&A endpoints under `/ui/live-qa/sessions/{session_id}/*`
(web reference scope `qa/questions` + upvote), ordered by community upvotes, and
refreshed on a bounded polling cadence so the list stays reasonably live without
a dedicated stream transport.

> **Corrected (review 2026-06-06):** the live-Q&A surface is keyed by the
> **broadcast `session_id`**, not a `streamId`, and the endpoints live under
> `/ui/live-qa/sessions/{session_id}/...` (verified against the OpenAPI index and
> `src/api/endpoints/liveQa.ts`). The AND-280 viewer must therefore hand the Q&A
> panel the active **broadcast session id**. References to `streamId` below are
> retained for continuity but denote that session id. A server-side **Q&A mode**
> gate (`qa_mode_enabled`) also governs whether the surface is open — see §5.

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

FR-1. **List questions.** On entering the Q&A panel for a session, load the
question list via `GET /ui/live-qa/sessions/{session_id}/questions` (optional
`status` + `limit` query params; server defaults `status=pending`, `limit=50`,
`limit` clamped to `1..200`). The list is **sorted by votes (descending)** by the
**server** (verified in the OpenAPI endpoint description), so the client renders
in server order and does not re-sort. The response is
`{ questions: LiveQaQuestion[], has_more: boolean }` — handle `has_more` for
future pagination. Show loading, loaded, empty, and error states.
> **Corrected (review 2026-06-07):** the server default `status=pending` is **NOT
> appropriate for a viewer panel.** The OpenAPI list description states *"Pending
> questions are restricted to the host/moderators; featured and answered
> questions are visible to any authenticated viewer."* A regular viewer querying
> `status=pending` will be denied/empty. The viewer panel MUST therefore request
> the viewer-visible statuses — `status=featured` and/or `status=answered`
> (issuing one request per status, since the param is a single value) — and MUST
> NOT default to `pending`. The original "default `status=pending`" framing is
> corrected here and in §4.2/§5/§13. *(Earlier review also corrected the path:
> was `/ui/live-qa/{streamId}/questions`.)*

FR-2. **Polling refresh.** While the panel is on-screen (lifecycle
`STARTED`/`RESUMED`), re-fetch the list on a bounded interval (default 8s,
configurable) to approximate live behavior. Polling stops when the panel is
backgrounded/disposed and resumes on return. No SSE/WebSocket in this ticket.

FR-3. **Pull-to-refresh.** A manual refresh gesture re-fetches immediately and
resets the polling timer.

FR-4. **Ask a question.** A composer (multiline text field + Submit) posts
`POST /ui/live-qa/sessions/{session_id}/questions` with body `{ "text": "..." }`
(`LiveQaQuestionSubmitIn`; resp `200` with a single `LiveQaQuestion`). On success
the new question is inserted/merged into the list and the composer clears. The
**server** enforces `text` length `1..500`; enforce a client-side max length with
a live counter (default 280 chars, but it MUST NOT exceed the server's 500-char
limit) — Submit is disabled for empty/whitespace-only or over-limit input and
while a submit is in-flight. *(Corrected: path; response is `200` not `201`;
server max length is 500.)*

FR-5. **Upvote / un-upvote.** Each question row shows an upvote control with the
current `vote_count`. Tapping toggles the vote **optimistically** (count +/-1,
state flips immediately) and calls
`POST /ui/live-qa/sessions/{session_id}/questions/{question_id}/vote`; un-upvote
calls `DELETE` on the **same** `.../vote` path (both verified in
`src/api/endpoints/liveQa.ts` and the OpenAPI index). Both return the updated
`LiveQaQuestion`. On failure, roll back to the prior count/state and surface a
transient error. Repeated taps are debounced/coalesced. *(Corrected: verb path is
`.../vote`, not `.../upvote`/`.../downvote`.)*

> **Unverified assumption (review):** the `LiveQaQuestion` DTO has **no
> `viewer_has_upvoted` field**, and the web client does not derive voted state
> from the server (its `hasVoted` prop defaults to `false` and is never set from
> the payload). Per-viewer voted state therefore **cannot be hydrated from this
> contract**. The Android client must track voted state **locally** (the toggle
> is driven by user intent; the server count in the response is authoritative).
> Whether the server rejects a duplicate upvote with `409` vs. silently
> no-ops is unconfirmed — handle both (see §5).

FR-6. **Featured question.** The featured question is fetched from the dedicated
`GET /ui/live-qa/sessions/{session_id}/featured` endpoint, which returns a single
`LiveQaQuestion | null` (verified: `getLiveQaFeatured` in
`src/api/endpoints/liveQa.ts`; the web client polls it on an 8s interval). Render
it in a distinct **Featured** banner pinned above the list, guarded on a non-null
`question_id` (as the web does). Within the list itself, a question is "featured"
when `status == "featured"` (the DTO has **no boolean `featured` field** — featured
state is the `status` enum value plus an optional `featured_at` epoch ts). The
featured question is de-duplicated from the main list by `question_id`. When
featuring changes between polls, the banner updates without losing scroll
position. *(Corrected: featured is a separate endpoint + `status` enum, not a
top-level `featured` object or per-item boolean.)*

FR-7. **Empty / disabled / unauthorized states.** Empty list -> non-error empty
state ("No questions yet — be the first to ask"). **Q&A mode gate:** the panel
SHOULD read `GET /ui/live-qa/sessions/{session_id}/mode` (-> `qa_mode_enabled`);
when Q&A mode is **off**, render a disabled state ("Q&A is currently off") and do
not poll the question list — this mirrors the web `LiveQaPage`, which hides the
audience composer/queue until `qa_mode_enabled` is true. If the viewer is not
authorized for the session (per AND-280, or a `403` from the Q&A endpoints) the
panel renders a disabled/explanatory state and does not poll. *(Added: the
`qa_mode_enabled` gate was missing from the original draft; verified against
`getLiveQaMode`/`LiveQaModeResponse` and `LiveQaPage.tsx`.)*

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

Corrected to the verified contract (path param `session_id`, list returns an
envelope with `has_more`, featured + mode are separate endpoints, vote uses the
`.../vote` verb):

```kotlin
interface LiveQaApi {
    @GET("ui/live-qa/sessions/{sessionId}/questions")
    suspend fun getQuestions(
        @Path("sessionId") sessionId: String,
        // VIEWER default is NOT "pending" (host/moderator-only per OpenAPI).
        // The repository requests viewer-visible statuses ("featured"/"answered").
        @Query("status") status: String = "featured",
        @Query("limit") limit: Int = 50,   // server clamps to 1..200
    ): Response<QaQuestionsResponseDto>   // { questions: [...], has_more: Boolean }

    @GET("ui/live-qa/sessions/{sessionId}/featured")
    suspend fun getFeatured(
        @Path("sessionId") sessionId: String,
    ): Response<QaQuestionDto?>           // single LiveQaQuestion or null

    @GET("ui/live-qa/sessions/{sessionId}/mode")
    suspend fun getMode(
        @Path("sessionId") sessionId: String,
    ): Response<QaModeDto>                // { ok, session_id, qa_mode_enabled }

    @POST("ui/live-qa/sessions/{sessionId}/questions")
    suspend fun ask(
        @Path("sessionId") sessionId: String,
        @Body body: AskQuestionRequestDto,   // { text: String }  (1..500)
    ): Response<QaQuestionDto>               // 200 -> single LiveQaQuestion

    @POST("ui/live-qa/sessions/{sessionId}/questions/{questionId}/vote")
    suspend fun upvote(
        @Path("sessionId") sessionId: String,
        @Path("questionId") questionId: String,
    ): Response<QaQuestionDto>

    @DELETE("ui/live-qa/sessions/{sessionId}/questions/{questionId}/vote")
    suspend fun removeUpvote(
        @Path("sessionId") sessionId: String,
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
    val id: String,                  // <- DTO field `question_id`
    val text: String,
    val authorDisplayName: String,   // <- DTO field `submitter_display_name`
    val upvotes: Int,                // <- DTO field `vote_count`
    val viewerHasUpvoted: Boolean,   // LOCAL ONLY — not in the server DTO; tracked client-side
    val featured: Boolean,           // derived: DTO `status == "featured"`
    val pinned: Boolean,             // DTO `pinned`
    val createdAt: Instant,          // DTO `created_at` is an epoch NUMBER -> Instant.ofEpochSecond/Milli
)
data class QaSnapshot(val featured: QaQuestion?, val questions: List<QaQuestion>)
```

> **Adapter notes (verified against `src/api/types.ts: LiveQaQuestion`):** map
> `question_id -> id`, `submitter_display_name -> authorDisplayName`,
> `vote_count -> upvotes`, `status == "featured" -> featured`, and `created_at`
> (an **epoch number**, not an ISO-8601 string) -> `Instant`. Confirm whether
> `created_at`/`featured_at` are seconds or milliseconds before wiring (the
> OpenAPI types them as plain numbers); pick the conversion accordingly and unit
> test it. `viewerHasUpvoted` has **no server source** and is maintained locally.

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

Paths use the `/ui/live-qa/sessions/{session_id}/*` namespace (verified against
the OpenAPI index and `src/api/endpoints/liveQa.ts`). All requests carry the
session credential; mutations carry `X-CSRF-Token` (the web client also sends an
`Authorization: Bearer` token — see the auth note below). The actual response
field names are taken from `src/api/types.ts: LiveQaQuestion` /
`LiveQaQueueResponse`.

**List** — `GET /ui/live-qa/sessions/{session_id}/questions?status=pending&limit=50`
returns a `LiveQaQueueResponse`:

```json
{
  "questions": [
    {
      "question_id": "q_01J0...",
      "session_id": "sess_...",
      "submitter_id": "usr_...",
      "submitter_display_name": "Mira",
      "text": "Can you show the setup?",
      "status": "pending",
      "vote_count": 12,
      "pinned": false,
      "featured_at": null,
      "answered_at": null,
      "created_at": 1749142544,
      "featured_by": null
    }
  ],
  "has_more": false
}
```

There is **no** top-level `featured` object and **no per-item boolean `featured`**
field — a question is featured when `status == "featured"`. The repository derives
`QaSnapshot.featured` from the dedicated featured endpoint (below) and/or the first
list item with `status == "featured"`, and excludes it from the main list by
`question_id`. `created_at`/`featured_at`/`answered_at` are **epoch numbers**, not
ISO-8601 strings.

**Featured** — `GET /ui/live-qa/sessions/{session_id}/featured` returns a single
`LiveQaQuestion` **or `null`** (web polls this every 8s; guards on a non-null
`question_id`).

**Q&A mode** — `GET /ui/live-qa/sessions/{session_id}/mode` returns
`{ "ok": true, "session_id": "...", "qa_mode_enabled": false }`
(`LiveQaModeResponse`). Toggling mode (`POST .../mode`, body `{ "enabled": bool }`,
`LiveQaModeToggleIn`) is a **host/broadcaster** action, out of scope for the
viewer panel but the GET is consumed to gate the surface.

**Ask** — `POST /ui/live-qa/sessions/{session_id}/questions`

```json
// request  (LiveQaQuestionSubmitIn — text length 1..500)
{ "text": "Can you show the setup?" }
// response 200 -> single LiveQaQuestion (same shape as a list item)
```

**Upvote** — `POST /ui/live-qa/sessions/{session_id}/questions/{question_id}/vote`
returns the updated `LiveQaQuestion` (new `vote_count`).
**Un-upvote** — `DELETE` on the **same** `.../vote` path returns the updated
`LiveQaQuestion`. There is no separate `/upvote` or `/downvote` verb. The response
carries no per-viewer voted flag, so the UI sends the *intended* target state,
tracks `viewerHasUpvoted` **locally**, and trusts the server `vote_count` in the
response (replacing the optimistic value).

> **Auth note (verified `src/api/client.ts`):** the web transport sends BOTH the
> session cookie (`credentials: include`) **and** `Authorization: Bearer
> <accessToken>`, plus `X-CSRF-Token` from the `ui_csrf` cookie on every request.
> The OpenAPI also lists an `X-SESSION-ID` param on these routes. The original
> spec's "purely cookie-based" framing is therefore an oversimplification; the
> Android client must reuse whatever the core-network/AND-280 session stack
> actually presents (cookie and/or bearer and/or `X-SESSION-ID`). CSRF-from-cookie
> and the single-refresh-on-401 behavior are **verified** (see §7).

**Errors.** FastAPI surfaces `detail` (`string | [{msg}] | {code,...}`); the
only error response the OpenAPI **schematizes** for these routes is `422`
(`HTTPValidationError`, the `[{msg,loc,type}]` array shape) for validation — the
`200` success bodies are typed as empty `{}` in the OpenAPI, so the field shapes
in this section come from the **frontend `src/api/types.ts`**, not the OpenAPI.
**Real domain error codes (verified in `src/pages/broadcast/LiveQaQuestionInput.tsx`)**
are returned as `detail.code` on a 4xx for the **ask** endpoint and MUST be
mapped: `LIVE_QA_RATE_LIMITED` ("please wait before submitting again"),
`BROADCAST_CHAT_MUTED` ("you are currently muted"), `LIVE_QA_DISABLED` ("Q&A is
not active right now"). Map via the shared mapper, falling back to a generic
message. Behavioral handling: `401` -> single
`POST /ui/session/refresh` then retry (else terminal/sign-out — verified in
`client.ts`); `403` -> not authorized / geo-blocked / Q&A closed -> Unauthorized
phase or transient message (web special-cases `detail.code == "geo_blocked"`);
`404` -> session/question gone -> remove from list + transient message; `409`/`422`
on vote (already/not voted) -> reconcile to server state, no error toast (note:
`409` is an **assumption** — only `422` is documented for these routes); `429` ->
back off polling.

## 6. Data & State Management

- **Source of truth:** `StateFlow<LiveQaUiState>` in `LiveQaViewModel`. No Room
  cache (live, ephemeral data); polling is the freshness mechanism.
- **Persistence:** only the composer **draft text** is persisted across config
  changes via `SavedStateHandle` (key `qa_draft`). No questions persisted to
  disk; no PII at rest.
- **Optimistic updates (Android enhancement):** note the web client is **not**
  optimistic — it refetches (`invalidateQueries`) after a vote mutation. The
  optimistic-with-rollback behavior below is an Android UX choice, not a contract
  requirement. `toggleUpvote` immediately mutates the in-memory item
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

- All requests use the shared session-authenticated OkHttp client; mutations send
  `X-CSRF-Token` from the `ui_csrf` cookie (CSRF-from-cookie **verified** in
  `src/api/client.ts`). Note the web client additionally sends `Authorization:
  Bearer` and the routes accept `X-SESSION-ID`; the Android client must present
  whatever the core-network/AND-280 session stack uses. This ticket adds no
  bespoke auth and must not bypass the shared client.
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
- List success maps the `{questions[], has_more}` envelope; the adapter maps
  `question_id/submitter_display_name/vote_count/created_at(epoch)` correctly and
  derives `featured` from `status == "featured"`, excluding the featured id from
  the list.
- Featured endpoint maps a single `LiveQaQuestion` and tolerates a `null` body.
- Ask success returns the new `QaQuestion` (resp `200`, body `{text}`); a `422`
  `HTTPValidationError` `detail` array maps to a user-facing failure.
- `setUpvote(voted=true)` calls `POST .../vote`; `voted=false` calls
  `DELETE .../vote`; both adopt the server-returned `vote_count`. `409` (assumed)
  reconciles without error.
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

- **OQ-1 (endpoint shape) — RESOLVED (review 2026-06-06):** paths are
  `/ui/live-qa/sessions/{session_id}/...`; ask body field is `text` (1..500);
  upvote/un-upvote are `POST`/`DELETE` on the same `.../vote` path. Verified
  against the OpenAPI index and `src/api/endpoints/liveQa.ts`.
- **OQ-2 (featured representation) — RESOLVED (review):** featured is a **separate
  endpoint** (`GET .../featured` -> `LiveQaQuestion | null`) and, within the list,
  the `status == "featured"` enum value (no boolean/top-level object). Single
  featured; no banner list needed.
- **OQ-3 (vote ownership) — PARTIALLY RESOLVED:** the DTO carries no
  `viewer_has_upvoted`, so per-viewer voted state is tracked locally and the
  server `vote_count` is authoritative. Whether the server rejects a duplicate
  vote (`409`) or no-ops, and whether un-upvote is always permitted, remains
  **unconfirmed** from the sources (only `422` is documented).
- **Risk-1 (no realtime):** polling (default 8s) means Q&A is near-live, not
  instant; acceptable for P2. If a realtime feed is later required it becomes a
  follow-up (reuse AND-281's SSE infra).
- **Risk-2 (flaky dev host):** ~20s timeouts make polling failure-prone;
  mitigated by GET retry + exponential poll backoff and clear retriable error UI.
  Mutations are not auto-retried to avoid duplicate questions.
- **OQ-4 (moderation/visibility) — RESOLVED (review):** the DTO exposes a
  `status` enum (`pending | featured | answered | dismissed | removed`) and the
  list GET takes a `status` filter (web defaults to `status=pending`). New
  questions land as `pending`; the viewer surface should decide which statuses to
  show. **Corrected (review 2026-06-07):** `pending` is **host/moderator-only**
  per the OpenAPI list description, so the **viewer** panel must show `featured`
  and `answered` (NOT `pending`); a viewer querying `pending` is denied/empty. No
  separate "awaiting review" flag is needed beyond the `status` value.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI full spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`), and frontend
(`reference/src/...`).

1. **Path namespace `/ui/live-qa/sessions/{session_id}/...`** — Verified.
   OpenAPI `GET /ui/live-qa/sessions/{session_id}/questions` (index lines
   1625–1637); frontend `src/api/endpoints/liveQa.ts` `base = /ui/live-qa/sessions/${sessionId}`.
2. **List endpoint `GET .../questions` returns `{ questions: LiveQaQuestion[], has_more: boolean }`** —
   Verified (shape). `src/api/types.ts: LiveQaQueueResponse`. (The OpenAPI `200`
   body is typed empty `{}`, so the shape is authoritative only from the frontend
   type, not the OpenAPI — see #15.)
3. **List query params `status` (default `pending`) + `limit` (default 50, range 1..200)** —
   Verified. OpenAPI `list_questions_...` parameters (`openapi.pretty.json`
   ~line 223861: `status` default `pending`; `limit` default 50, min 1, max 200);
   `src/api/endpoints/liveQa.ts: listLiveQaQuestions(status="pending", limit=50)`.
4. **List is sorted by votes (descending) server-side; client does not re-sort** —
   Verified. OpenAPI list `description`: *"List questions filtered by status,
   sorted by votes (descending)."* (`openapi.pretty.json` ~line 223849). Frontend
   renders in server order (`LiveQaQueuePanel.tsx` maps `data.questions` as-is).
5. **`status=pending` is host/moderator-only; `featured`/`answered` visible to any
   authenticated viewer** — Verified (and triggers Correction C-1). OpenAPI list
   `description`: *"Pending questions are restricted to the host/moderators;
   featured and answered questions are visible to any authenticated viewer."*
   (`openapi.pretty.json` ~line 223849).
6. **Ask `POST .../questions`, body `{ text }` length `1..500`, resp 200 single
   `LiveQaQuestion`** — Verified. OpenAPI `submit_question_...`
   (`req=LiveQaQuestionSubmitIn`, `resp=200`); schema `LiveQaQuestionSubmitIn`
   `text` `minLength:1, maxLength:500` (`openapi.pretty.json` ~line 48052); POST
   description *"any authenticated, non-muted user"* (~line 223958);
   `src/api/endpoints/liveQa.ts: submitLiveQaQuestion` posts `{ text }` and is
   typed `LiveQaQuestion`.
7. **Upvote `POST .../questions/{question_id}/vote`; un-upvote `DELETE` on the same
   `.../vote` path; both return the updated `LiveQaQuestion`** — Verified. OpenAPI
   index lines 1635 (`DELETE .../vote`) and 1636 (`POST .../vote`);
   `src/api/endpoints/liveQa.ts: upvoteLiveQaQuestion` (POST) / `removeLiveQaVote`
   (DELETE), both typed `LiveQaQuestion`. No `/upvote` or `/downvote` verb exists.
8. **Featured `GET .../featured` returns a single `LiveQaQuestion | null`; web polls
   every 8s and guards on a non-null `question_id`** — Verified. OpenAPI index
   line 1625; `src/api/endpoints/liveQa.ts: getLiveQaFeatured` typed
   `LiveQaQuestion | null`; `LiveQaPage.tsx` `featuredQuery refetchInterval: 8_000`
   and render guard `featured && featured.question_id`.
9. **Q&A mode `GET .../mode` -> `{ ok, session_id, qa_mode_enabled }`; gates the
   surface; toggle `POST .../mode { enabled }` is a host action** — Verified.
   OpenAPI index lines 1626 (GET) / 1627 (POST, `req=LiveQaModeToggleIn`); schema
   `LiveQaModeToggleIn { enabled: boolean (required) }` (`openapi.pretty.json`
   ~line 48028); `src/api/types.ts: LiveQaModeResponse`; gate logic in
   `LiveQaPage.tsx` (`enabled = modeQuery.data?.qa_mode_enabled ?? false`, off ->
   "Q&A mode is currently off").
10. **`LiveQaQuestion` field names: `question_id`, `submitter_display_name`,
    `vote_count`, `status`, `pinned`, `created_at`, `featured_at`, `answered_at`,
    `featured_by`** — Verified. `src/api/types.ts: LiveQaQuestion` (lines
    8735–8748).
11. **`created_at` / `featured_at` / `answered_at` are epoch NUMBERS, not ISO
    strings** — Verified (type). `src/api/types.ts: LiveQaQuestion`
    (`created_at: number`, `featured_at?: number | null`, `answered_at?: number | null`).
    Whether seconds vs milliseconds is **Unverified-assumption** (frontend never
    formats these; OpenAPI types them as plain numbers) — see Open assumptions.
12. **`status` enum is `pending | featured | answered | dismissed | removed`;
    "featured" is the enum value (no boolean `featured` field, no top-level
    `featured` object)** — Verified. `src/api/types.ts: LiveQaStatus` (lines
    8728–8733); card uses `question.status === "featured"`
    (`LiveQaQuestionCard.tsx`).
13. **No `viewer_has_upvoted` field; per-viewer voted state is not derivable from
    the contract** — Verified. `src/api/types.ts: LiveQaQuestion` has no such
    field; `LiveQaQuestionCard.tsx` `hasVoted?: boolean` **defaults to `false`**
    and is never set from the payload (callers in `LiveQaQueuePanel.tsx` do not
    pass it). Voted state must be tracked locally on Android.
14. **Web vote flow is NOT optimistic — it refetches via `invalidateQueries`** —
    Verified. `LiveQaQueuePanel.tsx` (`onSuccess: invalidate`). The Android
    optimistic-with-rollback behavior (§6) is correctly labelled an Android UX
    enhancement, not a contract requirement.
15. **Auth/transport: cookie (`credentials: include`) + `Authorization: Bearer
    <accessToken>` + `X-CSRF-Token` from the `ui_csrf` cookie on every request;
    single `POST /ui/session/refresh` on 401 then one retry; logout if refresh or
    retry still 401; `X-SESSION-ID` (and `user_sub`) accepted on these routes** —
    Verified. `src/api/client.ts` (Authorization header lines 157–160; CSRF
    lines 168–171; `credentials: "include"` line 183; refresh-on-401 lines
    194–237); `X-SESSION-ID`/`user_sub` params in OpenAPI index lines 1625–1637.
    The "purely cookie-based" framing in earlier drafts is an oversimplification
    (corrected previously in §5/§8).
16. **Error contract: only `422` `HTTPValidationError` is schematized; ask returns
    domain `detail.code` values `LIVE_QA_RATE_LIMITED`, `BROADCAST_CHAT_MUTED`,
    `LIVE_QA_DISABLED`; 403 `detail.code == "geo_blocked"` is special-cased** —
    Verified. OpenAPI routes list `422:HTTPValidationError` only (index lines
    1625–1637); ask error codes in `src/pages/broadcast/LiveQaQuestionInput.tsx`
    `onError`; geo-block handling in `src/api/client.ts` (lines 244–250).
17. **Vote `409` (duplicate/no-such-vote) behavior** — Unverified-assumption.
    Neither the OpenAPI (only `422` documented) nor the frontend exercises a vote
    `409`; handle defensively (reconcile to server `vote_count`, no error toast).
18. **Client char limit 280 (Android) vs web `maxLength=500`/`{n}/500` counter** —
    Verified that the web uses 500 (`LiveQaQuestionInput.tsx maxLength={500}` and
    `{text.length}/500`). The Android 280-char choice is a deliberate product
    decision (must stay <= server 500); labelled as such in §FR-4.
19. **Framework choices (Compose Material 3, `collectAsStateWithLifecycle`,
    `repeatOnLifecycle`/`LifecycleResumeEffect`, `PullToRefreshBox`,
    `SavedStateHandle`, Hilt/KSP, Retrofit/OkHttp/Moshi)** — Unverified-assumption
    (framework ref). Standard AndroidX/Jetpack APIs; not verifiable from the
    backend/frontend sources. See https://developer.android.com/jetpack/compose
    and https://developer.android.com/topic/libraries/architecture/coroutines
    (framework ref). Consistent with the project stack stated in §2.

### Corrections made

- **C-1 (viewer status filter):** Earlier drafts had the viewer panel default to
  `status=pending`. The OpenAPI list description proves `pending` is
  host/moderator-only and only `featured`/`answered` are viewer-visible. Corrected
  §FR-1, §4.2 (`LiveQaApi.getQuestions` default changed `"pending" -> "featured"`,
  with a note to also fetch `answered`), and §13 OQ-4. (Citation #5.)
- **C-2 (list ordering provenance):** Upgraded "ordered by upvote count descending
  (then recency)" (previously an implicit assumption) to a **verified** server
  behavior ("sorted by votes (descending)") and dropped the unverified
  "(then recency)" qualifier in §FR-1. (Citation #4.)
- **C-3 (ask error codes):** §5 previously listed only generic `422`/`409`. Added
  the real domain `detail.code` values for the ask endpoint
  (`LIVE_QA_RATE_LIMITED`, `BROADCAST_CHAT_MUTED`, `LIVE_QA_DISABLED`) and noted
  that the `200` success bodies are typed empty `{}` in the OpenAPI (field shapes
  come from the frontend types). (Citations #16, #2.)
- Prior-review corrections retained and re-verified: path `streamId -> session_id`
  (#1), ask response `200` not `201` and max length 500 (#6), vote verb `.../vote`
  not `.../upvote` (#7), featured as separate endpoint + `status` enum (#8, #12),
  `created_at` epoch number not ISO (#11), no `viewer_has_upvoted` (#13), auth not
  "purely cookie-based" (#15), `qa_mode_enabled` gate (#9).

### Open assumptions

- **Epoch unit (seconds vs milliseconds)** for `created_at`/`featured_at`/
  `answered_at` — the OpenAPI types them as plain numbers and the frontend never
  renders them, so the unit cannot be confirmed from the sources. Decide at
  implementation by inspecting a live payload (a 10-digit value ~1.7e9 => seconds;
  13-digit => millis) and unit-test the chosen conversion. (Citation #11.)
- **Vote `409` vs silent no-op on duplicate upvote / un-upvote-when-not-voted** —
  not documented (only `422`) and not exercised by the web client; handle both
  defensively. (Citation #17.)
- **`has_more` pagination semantics / cursor** — the envelope exposes `has_more`
  but the contract has no documented `offset`/cursor param (only `limit`); how to
  fetch the next page is unspecified. Treated as future work; client handles a
  single page. (Citation #2/#3.)
- **Framework/Jetpack API choices** — not verifiable from backend/frontend
  sources; standard AndroidX usage (framework ref, Citation #19).

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit (no device); **emu-test35** =
headless AVD `test35` (x86_64, API 35) on the CI build server; **A15** = physical
Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34,
arm64-v8a) attached to the build host via adb. Contract tests use OkHttp
MockWebServer. Q&A has no camera/biometric/WebRTC/Telecom/FCM surface, so most
cases run fine on JVM/emulator; physical-device cases are limited to real
arm64/API-34 sanity and real-flaky-network behavior against the dev host.

- **TC-AND-284-01 — Ask happy path (repository contract).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues
  `200` with a single `LiveQaQuestion` JSON body for
  `POST /ui/live-qa/sessions/{sid}/questions`. Steps: call
  `repository.ask(sid, "Can you show the setup?")`; capture the recorded request.
  Expected: request method `POST`, path ends `/questions`, body `{"text":"..."}`,
  `Content-Type: application/json`, `X-CSRF-Token` present; result is
  `ApiResult.Success<QaQuestion>` with mapped `id<-question_id`,
  `upvotes<-vote_count`, `authorDisplayName<-submitter_display_name`. Traces: AC-1.

- **TC-AND-284-02 — Ask validation/error mapping.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue (a) `422`
  `HTTPValidationError` `{"detail":[{"msg":"...","loc":["body","text"],"type":"..."}]}`,
  then (b) a 4xx with `{"detail":{"code":"LIVE_QA_RATE_LIMITED"}}`, then (c)
  `{"detail":{"code":"LIVE_QA_DISABLED"}}`. Steps: call `ask(...)` for each. Expected:
  each maps to `ApiResult.Failure` with the correct user-facing message
  (validation `msg`; rate-limited; Q&A-not-active), `isRetryable=false`; composer
  draft is preserved by the ViewModel (see TC-09). Traces: AC-1, AC-8.

- **TC-AND-284-03 — Upvote toggle uses correct verbs and adopts server count.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200`
  `LiveQaQuestion` with `vote_count:13` for the POST, and `200` with
  `vote_count:12` for the DELETE. Steps: call `setUpvote(sid, qid, voted=true)`
  then `setUpvote(sid, qid, voted=false)`; inspect recorded requests. Expected:
  first request `POST .../questions/{qid}/vote`, second `DELETE` on the **same**
  path; results carry server counts 13 then 12 (client does not fabricate).
  Traces: AC-2.

- **TC-AND-284-04 — Vote 409 reconciles without error (assumption-hardening).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `409` for
  `POST .../vote`. Steps: `setUpvote(voted=true)`. Expected: no crash; repository
  surfaces a non-fatal result that the ViewModel reconciles to server state with
  no error toast (covers the documented-only-`422`, assumed-`409` path). Traces:
  AC-2, AC-8.

- **TC-AND-284-05 — List maps envelope, derives featured, excludes featured id.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `200`
  `{"questions":[...],"has_more":false}` including one item with
  `status:"featured"`; enqueue the `GET .../featured` body as that same question.
  Steps: load snapshot. Expected: `QaSnapshot.featured` is non-null and equals the
  featured question; the main `questions` list excludes that `question_id`; epoch
  `created_at` maps to `Instant`; `has_more` parsed. Traces: AC-3, AC-8.

- **TC-AND-284-06 — Viewer status filter is NOT `pending` (regression for C-1).**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer records
  requests. Steps: trigger a viewer list load via the repository/ViewModel.
  Expected: recorded `GET .../questions` query has `status=featured` (and/or a
  second request `status=answered`); it must **never** request `status=pending`
  from the viewer surface. Traces: AC-3, AC-5.

- **TC-AND-284-07 — 401 triggers single refresh + retry; persistent 401 terminal.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: enqueue `401`, then a
  `200` `POST /ui/session/refresh`, then `200` for the retried GET; second
  scenario enqueues `401` -> refresh -> `401`. Steps: load list under both.
  Expected: scenario 1 succeeds after exactly one refresh+retry; scenario 2 yields
  a terminal/signed-out result, polling stopped, no retry loop. Traces: AC-5,
  AC-8.

- **TC-AND-284-08 — Optimistic upvote + rollback (ViewModel).**
  Type: unit (Turbine + coroutines-test). Target: JVM. Preconditions: seeded list
  with a question at `upvotes=10, viewerHasUpvoted=false`; fake repo returns
  Success then (2nd case) Failure. Steps: `toggleUpvote(qid)`. Expected: count
  increments to 11 and state flips **immediately**; on Success adopts server count;
  on Failure rolls back to 10/false and sets `transientMessage`. Rapid double-tap
  coalesces to one in-flight request (latest-wins). Traces: AC-2.

- **TC-AND-284-09 — Composer validation/disable + submit lifecycle (ViewModel).**
  Type: unit (Turbine). Target: JVM. Preconditions: empty composer. Steps: type
  blank/whitespace, then a 281-char string (> MAX_LEN 280), then a valid string;
  submit valid (fake repo Success), then submit again with fake Failure. Expected:
  `canSubmit=false` for blank/whitespace and over-limit and while `isSubmitting`;
  on Success composer clears and item merges into list; on Failure draft is
  preserved and Submit re-enabled. Traces: AC-1, AC-6.

- **TC-AND-284-10 — Polling lifecycle + backoff + merge (ViewModel).**
  Type: unit (coroutines-test virtual time). Target: JVM. Preconditions: fake repo
  with controllable success/failure and a `TestScope`. Steps: `startPolling()`;
  advance virtual time across several 8s intervals; inject consecutive failures
  then a success; have one question mid-optimistic-vote during a poll; then
  `stopPolling()`. Expected: refresh fires per interval while started; repeated
  failures widen the interval (exponential up to ~60s) and a success resets to 8s;
  poll merge preserves the in-flight optimistic vote; no emissions after
  `stopPolling()`. Traces: AC-4, AC-2.

- **TC-AND-284-11 — Phase states + featured banner (Compose UI).**
  Type: Compose-UI (`createComposeRule`, fake ViewModel). Target: emu-test35.
  Preconditions: drive `LiveQaUiState` through Loading -> Content (N rows + a
  featured question) -> Error -> Unauthorized -> empty Content. Steps: assert each
  render. Expected: Loading indicator; featured renders in `FeaturedQuestionBanner`
  and **not** in the `LazyColumn`; Error shows Retry that re-invokes load; empty
  shows the "be the first to ask" copy distinct from Error; Unauthorized shows the
  explanatory state with the composer disabled. Traces: AC-3, AC-5.

- **TC-AND-284-12 — Q&A mode gate + pull-to-refresh (Compose UI).**
  Type: Compose-UI. Target: emu-test35. Preconditions: state with
  `qa_mode_enabled=false`, then `=true`. Steps: render off-state; flip to on;
  perform the pull-to-refresh gesture. Expected: off-state shows "Q&A is currently
  off" and no list/composer and no polling; on-state shows list + composer;
  pull-to-refresh triggers an immediate reload and resets the poll timer.
  Traces: AC-4, AC-5.

- **TC-AND-284-13 — Accessibility semantics (Compose UI).**
  Type: Compose-UI (instrumented, semantics + a11y assertions). Target:
  emu-test35. Preconditions: Content state with a votable question. Steps: inspect
  upvote control and featured banner semantics. Expected: upvote control exposes a
  toggleable/`Role.Button` node with a state+count `contentDescription` ("Upvote,
  12 votes" / "Remove upvote, 13 votes"), min 48x48dp touch target; counter is a
  `liveRegion`; featured banner is a merged node prefixed with the localized
  "Featured" label; no hardcoded strings (all from `strings.xml`). Traces: AC-6
  (and the §9 a11y requirements).

- **TC-AND-284-14 — Flaky-dev-host / offline resilience (manual + device).**
  Type: manual + instrumented/e2e. Target: **A15 (physical device required)** —
  must exercise real arm64/API-34 behavior and real cellular/Wi-Fi loss against
  the plaintext dev host `http://18.222.237.167:8000`. Preconditions: signed in,
  authorized for a live session with Q&A mode ON. Steps: (1) ask a question and
  upvote one over a healthy connection; (2) toggle airplane mode mid-poll; (3)
  restore connectivity; (4) induce slow/timed-out responses. Expected: (1) question
  appears and upvote count increments and persists across a poll; (2) the panel
  shows a retriable offline/error state and pauses polling (non-empty list is
  preserved with a transient message, not wiped); (3) polling resumes and the list
  reconciles; (4) ~20s timeouts surface retriable errors and poll backoff widens —
  no duplicate questions from non-retried mutations. (Run on A15 because emulator
  NAT masks real radio loss / arm64 timeout behavior.) Traces: AC-2, AC-4, AC-5.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (ask -> appears, composer clears) | TC-01, TC-02, TC-09 |
| AC-2 (upvote optimistic + server reconcile + rollback) | TC-03, TC-04, TC-08, TC-10, TC-14 |
| AC-3 (featured banner, de-duped from list) | TC-05, TC-06, TC-11 |
| AC-4 (load/poll/stop/pull-to-refresh) | TC-10, TC-12, TC-14 |
| AC-5 (empty/error/unauthorized distinct; non-empty refresh preserved) | TC-06, TC-07, TC-11, TC-12, TC-14 |
| AC-6 (submit disable + char counter; a11y on UI) | TC-09, TC-13 |
| AC-7 (config-change survival: draft/list/scroll/vote) | TC-08, TC-09 (state in ViewModel/SavedStateHandle; exercised via ViewModel-retention assertions) |
| AC-8 (unit + MockWebServer + Compose green in CI) | TC-01–TC-13 |
