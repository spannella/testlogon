---
id: AND-383
title: Report flows
milestone: M8
epic: E50
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027, AND-163]
blocks: []
---

# AND-383 — Report flows

## 1. Overview & Goal

This ticket delivers the Trust & Safety **report flows** for the TestLogon native
Android client: a reusable, Compose-based experience that lets a signed-in user
report a **user**, a **content** item (post / media), or a **message** (or
conversation) for abuse, with a structured **reason** selection and an explicit
**confirmation** of submission.

The deliverable is a single feature module, `feature-report`, that exposes one
public entry point (a bottom-sheet flow) parameterized by the *kind* of subject
being reported. It is reused from multiple call sites (profile screens, content
feed, message thread) rather than reimplemented per surface. AND-163 already
covers the message-specific `/report` integration in the messaging epic (E22);
this ticket generalizes that pattern into the cross-cutting Trust & Safety
surface (E50) so users/content/messages all share one report UI, one reason
taxonomy, one submit/confirm contract, and one error/resilience policy.

**Goal (testable):** From any supported call site, a user can open the report
sheet, pick a reason (and optional free-text detail), submit, and receive an
inline confirmation; the network call uses the cookie + CSRF session from
AND-027 and degrades gracefully on the unreliable dev backend.

## 2. Context & References

- **Module layering:** `app -> feature-report -> core-*`
  (`core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`).
- **Auth/session:** AND-027 `AuthApi` provides the cookie-based session
  (`/ui/session/start|finalize|refresh|logout`, `/ui/me`). The persistent cookie
  jar, `ui_csrf` cookie → `X-CSRF-Token` header echo, and the single-shot
  `POST /ui/session/refresh`-then-retry on `401` are owned by `core-network`'s
  OkHttp interceptors. This ticket **consumes** that infrastructure and adds no
  new auth logic.
- **Messaging report (AND-163, E22):** owns the message-thread `/report` action,
  message report *status* surfacing, and the thread-level call site. This ticket
  reuses AND-163's `ReportApi.reportMessage` shape and the shared reason
  taxonomy; the two must not diverge. Where message-specific status display is
  needed, AND-163 owns it.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. FastAPI error
  `detail` may be `string | [{msg}] | {code,...}`; mapping lives in
  `core-network` (`ApiResult<T>` / `ApiError`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 + DataStore. minSdk 24,
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Namespace:** `com.testlogon.android` (module namespace
  `com.testlogon.android.feature.report`).

## 3. Functional Requirements

FR-1. A single public composable opens the report flow as a Material 3
`ModalBottomSheet`, parameterized by `ReportTarget` (subject kind + id).

FR-2. Supported subject kinds map to backend `content_type` values (verified
against `CreateModerationReportIn`/`ReportFeedContentReq` and the message-scoped
endpoint): a **user**/profile → `profile_photo`; **content** → one of
`feed_post`, `feed_comment`, `feed_media`; a **message** → `message` /
`message_media`. Topic taxonomy is shared across kinds.
[CORRECTED: the prior draft's `user`/`content`/`message` enum is not the wire
contract — see §5.]

FR-3. The user selects **one or more topics** from a multi-select list
(checkboxes, not a single-select radio group). [CORRECTED: the web client
(`ReportContentModal`) uses a multi-select topic set, not a single reason.] At
least one topic is required to submit. Topics are localized labels backed by
stable wire codes.

FR-4. A **required** multi-line **reason** free-text field (`reason_text`,
**5–2000 chars** after trim) is shown. [CORRECTED: it is required and bounded
5–2000, not an optional ≤1000 "detail" field — see `CreateModerationReportIn`.]
Character counter updates live; under-min or over-max blocks submit.

FR-5. The **Submit** button is disabled until a reason is selected; it shows a
busy/disabled state while the request is in flight (no double-submit).

FR-6. On success, the sheet shows an explicit **confirmation** state
("Report submitted") with a Done action that dismisses; the originating call
site is notified via a result callback so it can update local UI (e.g., toast,
hide reported item).

FR-7. On failure, an inline error with a **Retry** affordance is shown without
losing the user's reason/detail selection. Retry re-issues the same submit.

FR-8. Submitting a duplicate report is treated as a benign success/idempotent
confirmation ("You've already reported this"). [CORRECTED: the backend does
**not** return `409`. `POST /moderation/reports` returns `200` with
`CreateModerationReportOut.status == "deduplicated"`; the app maps that status
flag to the "already reported" confirmation. The message-scoped endpoint returns
`status == "submitted"` only.]

FR-9. The flow requires an authenticated session. If unauthenticated
(`401` after the single refresh), the flow surfaces a "Sign in to report" error
state; it does not attempt to drive the login flow itself.

## 4. Technical Design

Module `feature-report` (namespace `com.testlogon.android.feature.report`).

### 4.1 Public entry point

```kotlin
package com.testlogon.android.feature.report

sealed interface ReportTarget {
    val id: String
    data class User(override val id: String, val displayName: String? = null) : ReportTarget
    data class Content(override val id: String, val contentType: String) : ReportTarget // "feed_post" | "feed_comment" | "feed_media"
    data class Message(override val id: String, val conversationId: String? = null) : ReportTarget
}

enum class ReportKind { USER, CONTENT, MESSAGE }

@Composable
fun ReportSheet(
    target: ReportTarget,
    onDismiss: () -> Unit,
    onCompleted: (ReportOutcome) -> Unit,
    viewModel: ReportViewModel = hiltViewModel(),
)

enum class ReportOutcome { SUBMITTED, ALREADY_REPORTED, CANCELLED }
```

Call sites (profile, feed, message thread) hold a `var reportTarget by remember`
and render `ReportSheet` when non-null. AND-163's thread call site uses the same
component with `ReportTarget.Message`.

### 4.2 ViewModel & UiState

```kotlin
@HiltViewModel
class ReportViewModel @Inject constructor(
    private val repository: ReportRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ReportUiState())
    val state: StateFlow<ReportUiState> = _state.asStateFlow()

    fun start(target: ReportTarget)              // loads topic options for kind
    fun onTopicToggled(topic: ReportTopic, checked: Boolean)
    fun onReasonTextChanged(text: String)
    fun submit()                                 // idempotent re-entry safe
    fun retry()
}

// NOTE [CORRECTED]: fields renamed to match the real contract — a multi-select
// topic set plus a required reason_text (5–2000 chars), not a single reason +
// optional ≤1000 detail.
data class ReportUiState(
    val kind: ReportKind = ReportKind.USER,
    val topics: List<ReportTopic> = emptyList(),
    val selectedTopics: Set<ReportTopic> = emptySet(),
    val reasonText: String = "",
    val reasonMin: Int = 5,
    val reasonMax: Int = 2000,
    val phase: Phase = Phase.Editing,
) {
    val canSubmit: Boolean
        get() = selectedTopics.isNotEmpty() &&
            reasonText.trim().length in reasonMin..reasonMax &&
            phase == Phase.Editing

    sealed interface Phase {
        data object Editing : Phase
        data object Submitting : Phase
        data class Success(val alreadyReported: Boolean) : Phase
        data class Error(val message: String, val retryable: Boolean) : Phase
    }
}
```

### 4.3 Topic taxonomy (`core-model`)

[CORRECTED: the authoritative taxonomy is the web client's `MODERATION_TOPICS`
set, **not** the invented `spam/harassment/hate_speech/...` enum. The five wire
codes are exactly `sexual`, `extortion`, `criminal`, `spam`, `racist`
(`src/components/shared/ReportContentModal.tsx`; mirrored by the
`listModerationTickets` `topic` filter). There is no `OTHER` topic. Selection is
multi-select.]

```kotlin
enum class ReportTopic(val code: String) {
    SEXUAL("sexual"),
    EXTORTION("extortion"),
    CRIMINAL("criminal"),
    SPAM("spam"),
    RACIST("racist");
}

object ReportTopics {
    // All five topics are offered for every kind in the web client; if a kind
    // ever needs filtering, do it here. Returns a stable ordering.
    fun forKind(kind: ReportKind): List<ReportTopic>
}
```

For **message** reports the message-scoped endpoint takes a single
`reason_code` (string, 2–64 chars) rather than a topic array; the web client
sends the **first selected topic** as `reason_code` (`MessageBubble.tsx`:
`reason_code: topics[0]`). The Android client mirrors this mapping.

Labels resolved from string resources keyed by `code` (see §9); the `code`
string is the wire value, decoupled from display text.

### 4.4 Repository

```kotlin
// [CORRECTED] The repository takes the resolved domain request and routes to one
// of the two real endpoints (see §5), normalizing both responses to a common
// ReportResult { reportId, alreadyReported }.
interface ReportRepository {
    suspend fun submit(
        kind: ReportKind,
        target: ReportTarget,
        topics: Set<ReportTopic>,
        reasonText: String,
    ): ApiResult<ReportResult>
}

class ReportRepositoryImpl @Inject constructor(
    private val api: ReportApi,
) : ReportRepository {
    override suspend fun submit(
        kind: ReportKind,
        target: ReportTarget,
        topics: Set<ReportTopic>,
        reasonText: String,
    ): ApiResult<ReportResult> = when (kind) {
        ReportKind.MESSAGE -> {
            val m = target as ReportTarget.Message
            api.reportMessage(
                conversationId = requireNotNull(m.conversationId),
                messageId = m.id,
                body = ReportMessageRequest(topics.first().code, reasonText),
            ).toApiResult().map { ReportResult(it.reportId, alreadyReported = false) }
        }
        else -> api.reportModeration(buildModerationRequest(kind, target, topics, reasonText))
            .toApiResult()
            .map { ReportResult(it.reportId, alreadyReported = it.status == "deduplicated") }
    }
}
```

`submit()` is **not** retried automatically (it is a non-idempotent POST); retry
is user-initiated only (§7), consistent with the project rule that bounded
backoff applies to idempotent GETs only.

### 4.5 Composition

`ReportSheet` renders three visual states off `phase`: an editing form
(reason list + details + submit), a submitting state (progress, controls
disabled), and a terminal success/error state. State is hoisted; the composable
is stateless aside from the injected ViewModel.

## 5. API Contract

[MAJOR CORRECTION: there is **no `/ui/report` endpoint** in the backend OpenAPI.
The real contract is **two** authenticated POSTs, selected by kind:]

1. **User / content reports** → `POST /moderation/reports`
   (op `create_moderation_report_compat_moderation_reports_post`,
   req `CreateModerationReportIn`, resp `200:CreateModerationReportOut`,
   `422:HTTPValidationError`). This is the exact path the web client uses for
   feed content (`reportFeedContent`) **and** profile reports
   (`createModerationReport`). A `/v1/moderation/reports` alias exists with the
   same schema.
2. **Message reports** → `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`
   (op `report_message_...`, req `ReportMessageIn`, resp `200:ReportMessageOut`,
   errors `401|403|404|422|429:MessageControlsErrorOut`). This is AND-163's
   endpoint; the repository routes `MESSAGE` here.

The flow uses the existing `core-network` Retrofit/OkHttp client (cookie jar +
`X-CSRF-Token` header + single-refresh interceptor), so no auth params appear in
the signatures. Note the web client additionally sends `Authorization: Bearer`
from its auth store alongside the cookie; on Android the cookie-jar session from
AND-027 is authoritative.

```kotlin
interface ReportApi {
    @POST("moderation/reports")
    suspend fun reportModeration(@Body body: ModerationReportRequest): Response<ModerationReportResponse>

    @POST("messaging/conversations/{cid}/messages/{mid}/report")
    suspend fun reportMessage(
        @Path("cid") conversationId: String,
        @Path("mid") messageId: String,
        @Body body: ReportMessageRequest,
    ): Response<ReportMessageResponse>
}
```

**Request — `POST /moderation/reports`** (`CreateModerationReportIn`)

```json
{
  "content_type": "feed_post",        // feed_post|feed_comment|feed_media|message|message_media|profile_photo (required)
  "content_id": "post_8131",          // required, 1..256
  "topics": ["spam", "criminal"],     // required, 1..5 items
  "reason_text": "repeated spam links",  // required, 5..2000 chars
  "post_id": "post_8131",             // optional disambiguators below
  "comment_id": null,
  "media_index": null,
  "conversation_id": null,
  "message_id": null,
  "profile_user_id": null             // present for profile_photo (user) reports
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class ModerationReportRequest(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "topics") val topics: List<String>,          // 1..5
    @Json(name = "reason_text") val reasonText: String,       // 5..2000
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "comment_id") val commentId: String? = null,
    @Json(name = "media_index") val mediaIndex: Int? = null,
    @Json(name = "conversation_id") val conversationId: String? = null,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "profile_user_id") val profileUserId: String? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationReportResponse(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "report_id") val reportId: String,
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "status") val status: String,   // "submitted" | "deduplicated"
    @Json(name = "created_at") val createdAt: Long,
)
```

**Request — `POST .../messages/{message_id}/report`** (`ReportMessageIn`)

```json
{
  "reason_code": "spam",              // required, 2..64 chars (web sends topics[0])
  "statement": "repeated unwanted DMs"   // required, 5..2000 chars
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class ReportMessageRequest(
    @Json(name = "reason_code") val reasonCode: String,  // 2..64
    @Json(name = "statement") val statement: String,     // 5..2000
)

@JsonClass(generateAdapter = true)
data class ReportMessageResponse(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "report_id") val reportId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "reason_code") val reasonCode: String,
    @Json(name = "status") val status: String,   // const "submitted"
    @Json(name = "created_at") val createdAt: Long,
)
```

**Responses**

- `200` → success.
  - moderation: `status == "submitted"` → `Phase.Success(alreadyReported = false)`;
    `status == "deduplicated"` → `Phase.Success(alreadyReported = true)` (FR-8).
  - message: `status == "submitted"` → `Phase.Success(alreadyReported = false)`.
    [CORRECTED: there is **no `201`** and **no `409`** in either contract.]
- `401` → handled by refresh interceptor; if still `401`,
  `Phase.Error("Sign in to report", retryable = false)`. (Message endpoint
  returns `MessageControlsErrorOut` on `401`; moderation does not document `401`
  but the interceptor handles it uniformly.)
- `403`/`404`/`429` (message endpoint only, `MessageControlsErrorOut`) → mapped
  via `ApiError`; `429` is treated as retryable, `403`/`404` non-retryable.
- `422` → `HTTPValidationError` (moderation) or `MessageControlsErrorOut`
  (message) mapped via `ApiError`; non-retryable validation message shown inline.
- `5xx` / timeout / IO → `Phase.Error(..., retryable = true)`.

> Routing: the repository selects the endpoint by `ReportKind`. `USER` →
> `moderation/reports` with `content_type = "profile_photo"` and
> `profile_user_id`; `CONTENT` → `moderation/reports` with the feed
> `content_type` + `post_id`/`comment_id`/`media_index`; `MESSAGE` →
> the message-scoped endpoint (AND-163), mapping `reason_code = topics.first()`
> and `statement = reasonText`.

## 6. Data & State Management

- **No persistence.** Reports are fire-and-forget submissions; nothing is cached
  in Room or DataStore. The in-flight form lives only in `ReportUiState`
  (process-scoped via `SavedStateHandle` so reason/detail survive config
  changes; the sheet itself is recreated by the host).
- **State exposure:** `ReportViewModel.state: StateFlow<ReportUiState>`, collected
  with `collectAsStateWithLifecycle()`. Single source of truth; UI is a pure
  function of `phase`.
- **Result propagation:** `onCompleted(ReportOutcome)` is the only outward data
  flow to call sites; no shared global state. Call sites decide local UI updates
  (e.g., optimistic hide of a reported item) — that local mutation is owned by
  the call-site feature module, not here.
- **Reason options** are computed synchronously from `ReportReasons.forKind`; no
  network fetch, so there is no loading state for the form itself, only for
  submit.

## 7. Error Handling & Resilience

- **Timeouts:** inherit the `core-network` ~20s timeout policy for the dev host.
- **Retry policy:** submit is a POST → **no automatic retry**. On retryable
  failure (`5xx`, timeout, IO) `Phase.Error(retryable = true)` exposes a manual
  **Retry** that re-runs `submit()` with the unchanged request.
- **401 handling:** delegated entirely to the OkHttp refresh interceptor
  (single `POST /ui/session/refresh` then retry). A terminal `401` becomes a
  non-retryable "Sign in to report" error.
- **Deduplicated (already reported):** moderation `status == "deduplicated"`
  mapped to success, not error (FR-8). [CORRECTED: not a `409`.]
- **State preservation:** errors never clear `selectedTopics`/`reasonText`.
- **No double submit:** entering `Phase.Submitting` disables Submit and ignores
  re-entrant `submit()` calls.
- **Offline:** if no connectivity, the same retryable error path is used with a
  message indicating connection trouble; the dev host being down is
  indistinguishable from offline and handled identically.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; cleartext is permitted only for
  the dev host via the existing network-security-config allowlist owned by
  `core-network`. No new cleartext exemptions are added here.
- **Session/CSRF:** the report POST is a state-changing request and **must**
  carry the `X-CSRF-Token` header echoed from the `ui_csrf` cookie; this is
  applied by the shared interceptor — verify in tests (§11) that it is present.
- **PII minimization:** only the `content_id`/ids, selected topic codes, and the
  user-entered `reason_text` (message: `statement`) are transmitted. The
  free-text reason is user-authored; do not log its contents (§10). No reporter
  identity is sent in the body — it is derived server-side from the session.
- **No local retention:** report content is never written to disk/logs/cache.
- **Authorization:** the flow is gated on an authenticated session (FR-9);
  reporting is not exposed to anonymous users.

## 9. Accessibility & i18n

- All topic labels, the reason field label/placeholder, error and confirmation
  copy come from `strings.xml` keyed as `report_topic_<code>`,
  `report_reason_label`, `report_submit`, `report_confirm_title`,
  `report_already_reported`, etc. No hardcoded user-facing strings. (The web
  client hardcodes these labels in `ReportContentModal`; Android externalizes
  them — there are no existing i18n keys to reuse, see §16 open assumptions.)
- The topic list is a **multi-select checkbox group** with proper
  `Role.Checkbox` toggleable semantics; each row exposes a content description
  combining label + checked state. [CORRECTED: it is a checkbox group, not a
  single-select radio group.]
- Submit button exposes disabled-state semantics; the busy state announces
  "Submitting report" via `liveRegion`. Success and error states use
  `Modifier.semantics { liveRegion = LiveRegionMode.Polite }` so screen readers
  announce the confirmation.
- Touch targets ≥ 48dp; character counter is associated with the details field
  via semantics, not color alone (over-limit also shows text). Supports dynamic
  font scaling and dark theme via `core-ui` Material 3 theme.

## 10. Telemetry & Logging

- **Events** (via the shared analytics interface in `core-data`, no PII):
  - `report_opened` — props: `kind`.
  - `report_submitted` — props: `kind`, `topics` (codes), `has_reason` (bool),
    `result` (`submitted` | `deduplicated`).
  - `report_failed` — props: `kind`, `topics`, `error_type`
    (`network` | `auth` | `validation` | `server`), `http_status`.
  - `report_cancelled` — props: `kind`.
- **Logging:** structured logs at `Log.w` for failures with `error_type` and
  status only. **Never** log `reason_text`/`statement` text; `content_id`/ids
  logged only at debug.
- No raw request/response bodies are logged in release builds.

## 11. Testing Strategy

- **Unit (ViewModel):** with a fake `ReportRepository` and
  `core-testing` `MainDispatcherRule` + `Turbine`:
  - `canSubmit` toggles correctly on topic selection and reason_text length
    (under-5 / over-2000 blocks).
  - `submit()` transitions Editing → Submitting → Success(false) on
    `status == "submitted"`.
  - moderation `status == "deduplicated"` → Success(alreadyReported = true).
  - terminal `401` → Error(retryable = false); `5xx`/timeout/`429` →
    Error(retryable = true); `retry()` re-issues and recovers.
  - re-entrant `submit()` while Submitting is a no-op (no second repo call).
- **API (MockWebServer):** assert `POST moderation/reports` (user/content) and
  `POST messaging/conversations/{cid}/messages/{mid}/report` (message)
  path/verb, request JSON shape (`content_type`, `content_id`, `topics`,
  `reason_text`; message: `reason_code`, `statement`), and that the
  `X-CSRF-Token` header is attached; assert error `detail` mapping for `422`
  variants (`string`, `[{msg}]`, `{code}`) and `MessageControlsErrorOut`.
- **Compose UI (`createAndroidComposeRule`):** topic selection (multi-select)
  enables Submit; submitting disables controls; success state shows confirmation
  + Done invokes `onCompleted(SUBMITTED)`; error shows Retry; semantics/role
  assertions for the topic checkbox group and live regions.
- **Topic taxonomy:** `ReportTopics.forKind` returns the five stable wire codes
  (`sexual`, `extortion`, `criminal`, `spam`, `racist`) in a stable order
  (guards wire-compat).

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session, cookie jar + CSRF + refresh
  interceptor) — hard dependency; the report POST cannot authenticate without it.
- **Depends on / coordinates with AND-163** (message `/report` shape via
  `ReportMessageIn`, topic taxonomy, thread call site). This ticket generalizes
  AND-163's pattern; the shared `ReportTopic` enum and request shapes are the
  contract boundary. If AND-163 lands first, reuse its message `ReportApi`; if
  this lands first, AND-163 consumes `feature-report`'s `ReportSheet` for the
  message kind.
- **Blocks:** none recorded. Downstream Trust & Safety surfacing (report status,
  moderation outcomes) is out of scope for this ticket.
- **Sequencing:** implement `core-model` topic enum → `ReportApi`/repository →
  ViewModel → Compose sheet → call-site wiring (profile/feed reuse; message reuse
  coordinated with AND-163).

## 13. Risks & Open Questions

- **R-1 (endpoint shape):** RESOLVED by this review. There is no `/ui/report`;
  user/content reports use `POST /moderation/reports`, message reports use
  `POST /messaging/conversations/{cid}/messages/{mid}/report`. §5 now reflects
  the verified two-endpoint contract with kind routing.
- **R-2 (taxonomy authority):** RESOLVED. The canonical topic codes are
  `sexual`, `extortion`, `criminal`, `spam`, `racist` (web `MODERATION_TOPICS`,
  mirrored by the `listModerationTickets` `topic` filter). §4.3 updated.
- **R-3 (already-reported semantics):** RESOLVED. The backend returns `200` with
  `CreateModerationReportOut.status == "deduplicated"` (not `409`); the app maps
  that flag to `alreadyReported`. The message endpoint only returns `submitted`.
- **R-4 (dev host flakiness):** intermittent timeouts may make the flow feel
  broken; mitigated by clear retryable error + manual Retry, no auto-retry.
- **OQ-1:** RESOLVED (partially): there is no conversation-level report endpoint;
  messages are reported via the message-scoped endpoint, which **requires** both
  `conversation_id` and `message_id` in the path. Therefore
  `ReportTarget.Message.conversationId` is **mandatory** (not optional) for the
  MESSAGE kind — update §4.1 callers accordingly. Conversation-as-target is out
  of scope.
- **OQ-2:** Should successfully reporting a content item optimistically hide it?
  Out of scope here (call-site decision) — confirm UX with feed owners.

## 14. Acceptance Criteria

AC-1. From a supported call site, opening `ReportSheet` shows the topic list for
the correct `ReportKind`. (UI test)

AC-2. Submit is disabled until at least one topic is selected and a valid
`reason_text` (5–2000) is entered, enabled thereafter, and disabled while in
flight. (UI + unit) [CORRECTED: gated on topic(s) + reason_text, not a single
reason.]

AC-3. A successful submit issues `POST moderation/reports` (user/content) or the
message-scoped `POST .../messages/{id}/report` (message) with the correct JSON
body and `X-CSRF-Token` header, then shows the confirmation state and invokes
`onCompleted(ReportOutcome.SUBMITTED)`. (MockWebServer + UI) [CORRECTED: real
endpoints, not `/ui/report`.]

AC-4. A moderation `200` with `status == "deduplicated"` shows the "already
reported" confirmation and reports `ReportOutcome.ALREADY_REPORTED`. (unit)
[CORRECTED: `200`/deduplicated, not `409`.]

AC-5. A retryable failure (`5xx`/timeout) shows an inline error with Retry that,
on success, transitions to confirmation without re-entering reason/detail.
(unit + UI)

AC-6. A terminal `401` (after the single refresh) shows a non-retryable
"Sign in to report" state and does not auto-loop refresh. (unit)

AC-7. The free-text `reason_text`/`statement` never appears in logs (release) or
analytics props. (code review + unit on telemetry props)

AC-8. Topic labels, errors, and confirmation copy are fully resourced and
announced to screen readers (checkbox group + live region semantics). (UI a11y
test)

## 15. Definition of Done

- `feature-report` module created under `com.testlogon.android.feature.report`,
  wired into the Hilt graph (KSP), layered `feature-report -> core-*` only.
- `ReportSheet`, `ReportViewModel`, `ReportRepository`, `ReportApi`, and the
  `ReportTopic`/`ReportTarget` models implemented per §4–§5.
- At least one real call site reuses `ReportSheet` (profile or feed), and the
  message kind is reconciled with AND-163.
- All §11 test suites pass in CI; unit + MockWebServer + Compose UI coverage for
  AC-1…AC-8.
- No new cleartext exemptions; CSRF header verified on the report POST; no PII /
  `detail` logging.
- Strings externalized; a11y semantics verified; dark theme + font scaling
  validated.
- OpenAPI reconciliation (R-1, R-2, R-3) completed in this review (see §16); the
  verified two-endpoint contract in §5 is reflected in code.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Report endpoint for user/content is `POST /moderation/reports`.**
   VERDICT: Corrected (draft claimed `POST /ui/report`, which does not exist).
   SOURCE: OpenAPI `POST /moderation/reports`
   (op `create_moderation_report_compat_moderation_reports_post`,
   req `CreateModerationReportIn`); frontend
   `src/api/endpoints/moderation.ts: createModerationReport` and
   `src/api/endpoints/newsfeed.ts: reportFeedContent` (both POST `/moderation/reports`).
   A `/v1/moderation/reports` alias exists (OpenAPI `POST /v1/moderation/reports`).

2. **Message reports use `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`.**
   VERDICT: Verified (and clarified — draft hand-waved `/messages/{id}/report`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`
   (req `ReportMessageIn`, resp `200:ReportMessageOut`); frontend
   `src/api/endpoints/messaging.ts: reportMessage`.

3. **Moderation request body fields: `content_type`, `content_id`, `topics[]`,
   `reason_text` (required) + optional `post_id`/`comment_id`/`media_index`/
   `conversation_id`/`message_id`/`profile_user_id`.**
   VERDICT: Corrected (draft used `target_type`/`target_id`/`reason`/`detail`/`context`).
   SOURCE: OpenAPI `components.schemas.CreateModerationReportIn` (required:
   `content_type`, `content_id`, `topics`, `reason_text`);
   `src/api/endpoints/moderation.ts: CreateModerationReportReq`.

4. **`content_type` enum = `feed_post | feed_comment | feed_media | message |
   message_media | profile_photo`.**
   VERDICT: Corrected (draft used `user | content | message`).
   SOURCE: OpenAPI `CreateModerationReportIn.content_type` enum.

5. **`reason_text` is REQUIRED, length 5–2000.**
   VERDICT: Corrected (draft said optional, ≤1000, named "detail").
   SOURCE: OpenAPI `CreateModerationReportIn.reason_text`
   (`minLength: 5`, `maxLength: 2000`, in `required`); web textarea
   `src/components/shared/ReportContentModal.tsx` (minLength 5 / maxLength 2000,
   "Required (5–2000 characters)").

6. **`topics` is a multi-select array (1–5 items), not a single reason.**
   VERDICT: Corrected (draft used single-select `reason`).
   SOURCE: OpenAPI `CreateModerationReportIn.topics` (`minItems:1, maxItems:5`);
   `src/components/shared/ReportContentModal.tsx` (checkbox set).

7. **Topic vocabulary = `sexual, extortion, criminal, spam, racist`.**
   VERDICT: Corrected (draft invented `spam, harassment, hate_speech,
   sexual_content, violence, self_harm, impersonation, scam_fraud, other`).
   SOURCE: `src/components/shared/ReportContentModal.tsx: MODERATION_TOPICS`;
   mirrored by `src/api/endpoints/moderation.ts: listModerationTickets` `topic`
   filter (`sexual|extortion|criminal|spam|racist`).

8. **Moderation success response: `{ ok, report_id, ticket_id, status,
   created_at }`, `status ∈ {submitted, deduplicated}`.**
   VERDICT: Corrected (draft response was `{ report_id, status:"received" }`).
   SOURCE: OpenAPI `CreateModerationReportOut` (all five fields required;
   `status` enum `submitted|deduplicated`).

9. **"Already reported" is `200` + `status == "deduplicated"`, NOT HTTP `409`.**
   VERDICT: Corrected (FR-8/§5/§7/AC-4 all said `409`).
   SOURCE: OpenAPI `CreateModerationReportOut.status` enum; the moderation
   endpoint documents only `200` and `422` responses (no `409`, no `201`).

10. **Message request body: `reason_code` (2–64) + `statement` (5–2000), both
    required.**
    VERDICT: Verified.
    SOURCE: OpenAPI `ReportMessageIn` (required `reason_code`, `statement`);
    `src/api/types.ts: ReportMessageReq`.

11. **Web maps message `reason_code = topics[0]`, `statement = reason_text`.**
    VERDICT: Verified.
    SOURCE: `src/pages/messages/MessageBubble.tsx` reportMut
    (`reason_code: topics[0], statement: reason_text`).

12. **Message success response: `{ ok, report_id, conversation_id, message_id,
    reason_code, status:"submitted", created_at }`.**
    VERDICT: Verified.
    SOURCE: OpenAPI `ReportMessageOut` (`status` const `submitted`);
    `src/api/types.ts: ReportMessageResp`.

13. **Message endpoint error responses use `MessageControlsErrorOut` for
    `401/403/404/422/429`.**
    VERDICT: Verified.
    SOURCE: OpenAPI index line for the report-message op; schema
    `MessageControlsErrorOut` (`{ detail, error_code? }`).

14. **Auth/transport: cookie session + `X-CSRF-Token` echoed from `ui_csrf`
    cookie + single `POST /ui/session/refresh`-then-retry on `401`.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`; `refreshSession()` POSTs
    `/ui/session/refresh`; single-flight `refreshPromise`, retry once on 401);
    OpenAPI `POST /ui/session/refresh`, `POST /ui/session/start`
    (`UiSessionStartReq`/`UiSessionStartResp`), `GET /ui/me`. Note: web also
    sends `Authorization: Bearer` from its auth store; Android relies on the
    cookie jar from AND-027 (unverified-assumption that Bearer is not required —
    see Open assumptions).

15. **Profile/user report uses `content_type:"profile_photo"` + `profile_user_id`.**
    VERDICT: Verified.
    SOURCE: `src/pages/contacts/ContactsPage.tsx` reportMut
    (`content_type:"profile_photo", profile_user_id: ...`).

16. **Feed content report sets `content_type:"feed_post"` + `post_id`.**
    VERDICT: Verified.
    SOURCE: `src/pages/feed/PostActions.tsx` (and `PostCard.tsx`,
    `CommentsThread.tsx`) reportMut → `reportFeedContent`.

17. **Compose `ModalBottomSheet` / Material 3 for the report UI; checkbox group
    semantics; live-region announcements.**
    VERDICT: Unverified-assumption (Android UI framework choice; web uses a
    Dialog, not a bottom sheet). Material 3 `ModalBottomSheet` and
    `Role.Checkbox`/`liveRegion` semantics are standard.
    SOURCE: framework ref —
    https://developer.android.com/develop/ui/compose/components/bottom-sheets ,
    https://developer.android.com/develop/ui/compose/accessibility .

18. **No automatic retry on POST; manual user retry only.**
    VERDICT: Unverified-assumption (project policy; not derivable from sources).
    SOURCE: project rule cited in §4.4/§7; no contradicting evidence in OpenAPI/frontend.

### Corrections made

- §5 rewritten: removed the non-existent `POST /ui/report`; documented the two
  real endpoints (`POST /moderation/reports` for user/content,
  message-scoped endpoint for messages) with verified request/response schemas.
- Request fields corrected: `content_type`/`content_id`/`topics`/`reason_text`
  (+ optional disambiguators) instead of `target_type`/`target_id`/`reason`/
  `detail`/`context`.
- `content_type` enum corrected to the six backend values.
- "Reason" model corrected: multi-select **topics** (`sexual, extortion,
  criminal, spam, racist`) + **required** `reason_text` (5–2000), replacing the
  invented single-select reason enum and optional ≤1000 "detail".
- Already-reported semantics corrected: `200` + `status=="deduplicated"`, not
  `409`. Removed `201`/`409` from the response table.
- Response schema corrected to `CreateModerationReportOut` / `ReportMessageOut`
  shapes (added `ok`, `ticket_id`, `created_at`, etc.).
- §4.2 UiState, §4.3 taxonomy, §4.4 repository, §7, §9 (radio→checkbox), §10
  telemetry, §11 tests, §13 risks, §14 AC-2/3/4/7/8 updated to match.
- `ReportTarget.Message.conversationId` clarified as **mandatory** for MESSAGE
  (path requires `conversation_id`).
- Frontmatter `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **Bearer token alongside cookie:** the web client sends `Authorization: Bearer`
  in addition to the cookie/CSRF. Whether the moderation/message endpoints
  require Bearer or accept the cookie session alone is not determinable from the
  sources; assumed the AND-027 cookie jar suffices on Android. (Why: OpenAPI
  shows no explicit security scheme detail for these ops; only the web transport
  behavior is observable.)
- **`ModalBottomSheet` vs Dialog:** web uses a `Dialog`; the Android bottom-sheet
  presentation is a product/UX choice, not contract-driven.
- **Per-kind topic filtering:** the web offers all five topics for every kind;
  `ReportTopics.forKind` is provided for future filtering but currently returns
  all five. (Why: no backend constraint on topic-per-content_type observed.)
- **`200` vs `201`:** OpenAPI documents `200` only for both endpoints; assumed no
  `201` is ever returned.
- **No automatic retry on POST:** project policy assumption (see citation 18).
- **String resource keys** (`report_topic_<code>`, etc.) are new Android keys;
  the web hardcodes labels, so there are no existing i18n keys to reuse.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device);
EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build host. UI/instrumented
cases run on EMU unless a case calls out DEV.

- **TC-AND-383-01** — Type: unit (JVM). Target: `ReportViewModel` with fake
  `ReportRepository`. Preconditions: kind=CONTENT, no topics selected.
  Steps: (1) `start()`; (2) assert `canSubmit==false`; (3) toggle one topic on,
  enter 10-char reason_text; (4) assert `canSubmit==true`; (5) clear topics;
  assert `false`; (6) re-select topic, set reason_text to 4 chars; assert
  `false`; (7) set reason_text to 2001 chars; assert `false`.
  Expected: `canSubmit` true only with ≥1 topic AND trimmed reason_text in 5..2000.
  Traces: AC-2.

- **TC-AND-383-02** — Type: unit (JVM). Target: `ReportViewModel`.
  Preconditions: kind=CONTENT, valid topic + reason_text; repo returns
  `ModerationReportResponse(status="submitted")`. Steps: call `submit()`,
  collect state with Turbine. Expected: phase Editing → Submitting →
  `Success(alreadyReported=false)`; `onCompleted` would carry SUBMITTED.
  Traces: AC-3.

- **TC-AND-383-03** — Type: unit (JVM). Target: `ReportViewModel`.
  Preconditions: repo returns `status="deduplicated"`. Steps: `submit()`.
  Expected: `Success(alreadyReported=true)`; outcome ALREADY_REPORTED.
  Traces: AC-4.

- **TC-AND-383-04** — Type: unit (JVM). Target: `ReportViewModel`.
  Preconditions: repo first returns `5xx` then (on retry) `submitted`.
  Steps: `submit()` → assert `Error(retryable=true)` with topics/reason_text
  preserved → `retry()` → assert `Success(false)`. Expected: retryable error
  keeps form state; retry recovers without re-entry. Traces: AC-5.

- **TC-AND-383-05** — Type: unit (JVM). Target: `ReportViewModel`.
  Preconditions: repo returns terminal `401` (after interceptor refresh).
  Steps: `submit()`. Expected: `Error("Sign in to report", retryable=false)`;
  no refresh loop (repo called once). Traces: AC-6.

- **TC-AND-383-06** — Type: unit (JVM). Target: `ReportViewModel` no-double-submit.
  Preconditions: repo `submit` suspends (in-flight). Steps: call `submit()`
  twice while in Submitting. Expected: exactly one repo invocation; second call
  is a no-op. Traces: AC-2, AC-3.

- **TC-AND-383-07** — Type: contract/MockWebServer (JVM/Robolectric). Target:
  `ReportApi.reportModeration` via real Retrofit/OkHttp + `core-network`
  interceptors; `ui_csrf` cookie seeded in the jar. Preconditions: kind=CONTENT
  (feed_post). Steps: enqueue `200` `CreateModerationReportOut`; submit; inspect
  recorded request. Expected: `POST /moderation/reports`; JSON has
  `content_type:"feed_post"`, `content_id`, `topics:[...]`, `reason_text`,
  `post_id`; request carries `X-CSRF-Token` matching `ui_csrf`. Traces: AC-3, and
  CSRF requirement (§8).

- **TC-AND-383-08** — Type: contract/MockWebServer (JVM). Target:
  `ReportApi.reportMessage`. Preconditions: kind=MESSAGE with conversationId +
  messageId; two topics selected, reason_text set. Steps: enqueue `200`
  `ReportMessageOut`; submit. Expected: `POST
  /messaging/conversations/{cid}/messages/{mid}/report`; body
  `{reason_code:<topics.first>, statement:<reason_text>}`; `X-CSRF-Token` present.
  Traces: AC-3.

- **TC-AND-383-09** — Type: contract/MockWebServer (JVM). Target: error mapping.
  Preconditions: enqueue `422` with FastAPI `detail` in three shapes —
  `"msg"` (string), `[{ "msg": "..." }]` (list), `{ "code": "..." }` (object) —
  and a `MessageControlsErrorOut` `{detail, error_code}` for the message path.
  Steps: submit each. Expected: each maps via `ApiError` to a non-retryable
  inline validation message; no crash on any shape. Traces: AC-5 (error
  surfacing), §5/§7.

- **TC-AND-383-10** — Type: Compose-UI (EMU, `createAndroidComposeRule`).
  Target: `ReportSheet`. Preconditions: kind=CONTENT. Steps: (1) open sheet,
  assert five topic checkboxes shown; (2) assert Submit disabled; (3) check a
  topic + type valid reason_text; assert Submit enabled; (4) tap Submit (fake
  repo `submitted`); assert confirmation state + Done invokes
  `onCompleted(SUBMITTED)`. Expected: full happy-path UI flow. Traces: AC-1,
  AC-2, AC-3.

- **TC-AND-383-11** — Type: Compose-UI (EMU). Target: `ReportSheet` error/retry.
  Preconditions: fake repo returns retryable error then success. Steps: submit →
  assert inline error + Retry visible and topics/reason_text still populated →
  tap Retry → assert confirmation. Expected: error state with Retry; state
  preserved; recovery. Traces: AC-5.

- **TC-AND-383-12** — Type: Compose-UI accessibility (EMU). Target: `ReportSheet`
  semantics. Preconditions: kind=USER. Steps: assert each topic row has
  `Role.Checkbox` + content description (label + checked state); Submit exposes
  disabled-state semantics; on submit the busy state and the success/error
  states carry `liveRegion = Polite`; all visible copy resolves from string
  resources (no hardcoded literals). Run once with large font scale + dark
  theme. Expected: a11y semantics + live regions present; layout holds at large
  font scale. Traces: AC-8.

- **TC-AND-383-13** — Type: unit (JVM) security/telemetry. Target:
  analytics + logging. Preconditions: submit a report with a distinctive
  `reason_text` sentinel. Steps: trigger success and failure; capture emitted
  analytics props and (release-config) logs. Expected: `report_submitted`/
  `report_failed` props contain `topics`/`has_reason` but **never** the
  `reason_text`/`statement` text; no log line contains the sentinel.
  Traces: AC-7.

- **TC-AND-383-14** — Type: instrumented/e2e (DEV — physical device REQUIRED).
  Target: full flow against the flaky dev host `http://18.222.237.167:8000` over
  real network on arm64/API-34. Preconditions: signed-in session (AND-027 cookie
  jar populated). Steps: open ReportSheet from a real call site, select topic +
  reason, submit; then enable airplane mode and submit again. Expected: online →
  real `200` confirmation with `X-CSRF-Token` sent over the actual connection;
  offline/host-down → retryable connection-trouble error with Retry (identical
  path). MUST run on the physical device to exercise real-network behavior and
  arm64/API-34 vs emulator x86/API-35 differences (cleartext-HTTP
  network-security-config, cookie persistence). Traces: AC-3, AC-5, AC-6 (auth
  gating), §7 offline/flaky-host.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (topic list for kind) | TC-10 |
| AC-2 (submit enable/disable, no double-submit) | TC-01, TC-06, TC-10 |
| AC-3 (correct endpoint + body + CSRF + confirm + SUBMITTED) | TC-02, TC-07, TC-08, TC-10, TC-14 |
| AC-4 (deduplicated → ALREADY_REPORTED) | TC-03 |
| AC-5 (retryable error + Retry, state preserved) | TC-04, TC-09, TC-11, TC-14 |
| AC-6 (terminal 401 → "Sign in to report", no loop) | TC-05, TC-14 |
| AC-7 (reason text never logged / in analytics) | TC-13 |
| AC-8 (resourced copy + checkbox/live-region a11y) | TC-12 |
