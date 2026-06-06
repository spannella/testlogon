---
id: AND-383
title: Report flows
milestone: M8
epic: E50
priority: P1
size: M
status: draft
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

FR-2. Supported subject kinds: `USER`, `CONTENT`, `MESSAGE` (a message id; a
conversation is reported by reporting a representative message or by a
conversation id when provided). Reason taxonomy is shared across kinds but the
*available* reasons may be filtered per kind.

FR-3. The user selects exactly one **reason** from a single-select list. Reasons
are presented as localized labels backed by stable enum codes sent to the API.

FR-4. An optional multi-line **details** field (free text, ≤ 1000 chars,
trimmed) is shown. Character counter updates live; over-limit blocks submit.

FR-5. The **Submit** button is disabled until a reason is selected; it shows a
busy/disabled state while the request is in flight (no double-submit).

FR-6. On success, the sheet shows an explicit **confirmation** state
("Report submitted") with a Done action that dismisses; the originating call
site is notified via a result callback so it can update local UI (e.g., toast,
hide reported item).

FR-7. On failure, an inline error with a **Retry** affordance is shown without
losing the user's reason/detail selection. Retry re-issues the same submit.

FR-8. Submitting the same `(targetKind, targetId)` that the backend reports as
already reported (HTTP `409`) is treated as a benign success/idempotent
confirmation ("You've already reported this").

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
    data class Content(override val id: String, val contentType: String) : ReportTarget // "post" | "media"
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

    fun start(target: ReportTarget)              // loads reason options for kind
    fun onReasonSelected(reason: ReportReason)
    fun onDetailChanged(text: String)
    fun submit()                                 // idempotent re-entry safe
    fun retry()
}

data class ReportUiState(
    val kind: ReportKind = ReportKind.USER,
    val reasons: List<ReportReason> = emptyList(),
    val selectedReason: ReportReason? = null,
    val detail: String = "",
    val detailMax: Int = 1000,
    val phase: Phase = Phase.Editing,
) {
    val canSubmit: Boolean
        get() = selectedReason != null && detail.length <= detailMax && phase == Phase.Editing

    sealed interface Phase {
        data object Editing : Phase
        data object Submitting : Phase
        data class Success(val alreadyReported: Boolean) : Phase
        data class Error(val message: String, val retryable: Boolean) : Phase
    }
}
```

### 4.3 Reason taxonomy (`core-model`)

```kotlin
enum class ReportReason(val code: String) {
    SPAM("spam"),
    HARASSMENT("harassment"),
    HATE_SPEECH("hate_speech"),
    SEXUAL_CONTENT("sexual_content"),
    VIOLENCE("violence"),
    SELF_HARM("self_harm"),
    IMPERSONATION("impersonation"),
    SCAM_FRAUD("scam_fraud"),
    OTHER("other");
}

object ReportReasons {
    fun forKind(kind: ReportKind): List<ReportReason> // filters per kind, OTHER always last
}
```

Labels resolved from string resources keyed by `code` (see §9); the `code`
string is the wire value, decoupled from display text.

### 4.4 Repository

```kotlin
interface ReportRepository {
    suspend fun submit(request: ReportRequest): ApiResult<ReportResponse>
}

class ReportRepositoryImpl @Inject constructor(
    private val api: ReportApi,
) : ReportRepository {
    override suspend fun submit(request: ReportRequest): ApiResult<ReportResponse> =
        api.report(request).toApiResult()
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

Reporting is a single authenticated POST. The flow uses the existing
`core-network` Retrofit/OkHttp client (cookie jar + CSRF header + refresh
interceptor), so no auth params appear in the signatures.

```kotlin
interface ReportApi {
    @POST("ui/report")
    suspend fun report(@Body body: ReportRequest): Response<ReportResponse>
}
```

**Request — `POST /ui/report`**

```json
{
  "target_type": "user",          // "user" | "content" | "message"
  "target_id": "usr_8131",
  "reason": "harassment",         // ReportReason.code
  "detail": "repeated unwanted DMs",   // optional, may be omitted/empty
  "context": {                    // optional disambiguation
    "content_type": "post",       // present for content
    "conversation_id": "cnv_42"   // present for message when known
  }
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class ReportRequest(
    @Json(name = "target_type") val targetType: String,
    @Json(name = "target_id") val targetId: String,
    @Json(name = "reason") val reason: String,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "context") val context: Map<String, String>? = null,
)

@JsonClass(generateAdapter = true)
data class ReportResponse(
    @Json(name = "report_id") val reportId: String,
    @Json(name = "status") val status: String, // e.g. "received"
)
```

**Responses**

- `201`/`200` → `ReportResponse` → `Phase.Success(alreadyReported = false)`.
- `409` (already reported) → `Phase.Success(alreadyReported = true)`.
- `401` → handled by refresh interceptor; if still `401`,
  `Phase.Error("Sign in to report", retryable = false)`.
- `400`/`422` → FastAPI `detail` mapped via `ApiError`; non-retryable validation
  message shown inline.
- `5xx` / timeout / IO → `Phase.Error(..., retryable = true)`.

> Note: `MESSAGE` reports may alternatively route through AND-163's
> message-scoped `/messages/{id}/report` endpoint. The single `/ui/report`
> endpoint above is the canonical Trust & Safety path for this ticket; if the
> backend exposes only the message-scoped path for messages, `ReportApi` adds
> `@POST("messages/{id}/report")` and the repository selects by kind. Confirm
> against `/openapi.json` before implementation (see §13).

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
- **409 (already reported):** mapped to success, not error (FR-8).
- **State preservation:** errors never clear `selectedReason`/`detail`.
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
- **PII minimization:** only the `target_id`, reason code, and the user-entered
  detail are transmitted. The free-text `detail` is user-authored; do not log its
  contents (§10). No reporter identity is sent in the body — it is derived
  server-side from the session.
- **No local retention:** report content is never written to disk/logs/cache.
- **Authorization:** the flow is gated on an authenticated session (FR-9);
  reporting is not exposed to anonymous users.

## 9. Accessibility & i18n

- All reason labels, the details field label/placeholder, error and confirmation
  copy come from `strings.xml` keyed as `report_reason_<code>`,
  `report_detail_label`, `report_submit`, `report_confirm_title`,
  `report_already_reported`, etc. No hardcoded user-facing strings.
- The reason list is a single-select radio group with proper
  `Modifier.selectableGroup()` / `Role.RadioButton` semantics; each row exposes a
  content description combining label + selected state.
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
  - `report_submitted` — props: `kind`, `reason` (code), `has_detail` (bool),
    `result` (`success` | `already_reported`).
  - `report_failed` — props: `kind`, `reason`, `error_type`
    (`network` | `auth` | `validation` | `server`), `http_status`.
  - `report_cancelled` — props: `kind`.
- **Logging:** structured logs at `Log.w` for failures with `error_type` and
  status only. **Never** log `detail` text, `target_id` is logged only at debug.
- No raw request/response bodies are logged in release builds.

## 11. Testing Strategy

- **Unit (ViewModel):** with a fake `ReportRepository` and
  `core-testing` `MainDispatcherRule` + `Turbine`:
  - `canSubmit` toggles correctly on reason selection and over-limit detail.
  - `submit()` transitions Editing → Submitting → Success(false) on `2xx`.
  - `409` → Success(alreadyReported = true).
  - terminal `401` → Error(retryable = false); `5xx`/timeout →
    Error(retryable = true); `retry()` re-issues and recovers.
  - re-entrant `submit()` while Submitting is a no-op (no second repo call).
- **API (MockWebServer):** assert `POST ui/report` path/verb, request JSON shape
  (`target_type`, `target_id`, `reason`, optional `detail`/`context`), and that
  the `X-CSRF-Token` header is attached; assert `detail` mapping for `422`
  variants (`string`, `[{msg}]`, `{code}`).
- **Compose UI (`createAndroidComposeRule`):** reason selection enables Submit;
  submitting disables controls; success state shows confirmation + Done invokes
  `onCompleted(SUBMITTED)`; error shows Retry; semantics/role assertions for the
  radio group and live regions.
- **Reason taxonomy:** `ReportReasons.forKind` returns expected per-kind sets
  with `OTHER` last and stable `code`s (guards wire-compat).

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session, cookie jar + CSRF + refresh
  interceptor) — hard dependency; the report POST cannot authenticate without it.
- **Depends on / coordinates with AND-163** (message `/report` shape, reason
  taxonomy, thread call site). This ticket generalizes AND-163's pattern;
  the shared `ReportReason` enum and request shape are the contract boundary.
  If AND-163 lands first, reuse its `ReportApi`; if this lands first, AND-163
  consumes `feature-report`'s `ReportSheet` for the message kind.
- **Blocks:** none recorded. Downstream Trust & Safety surfacing (report status,
  moderation outcomes) is out of scope for this ticket.
- **Sequencing:** implement `core-model` reason enum → `ReportApi`/repository →
  ViewModel → Compose sheet → call-site wiring (profile/feed reuse; message reuse
  coordinated with AND-163).

## 13. Risks & Open Questions

- **R-1 (endpoint shape):** `/ui/report` vs. per-kind endpoints
  (`/messages/{id}/report`) is unconfirmed. **Action:** verify against
  `/openapi.json` before coding; §5 documents both and a kind-routing fallback.
- **R-2 (reason taxonomy authority):** the canonical reason codes must match the
  backend's accepted values. **Action:** confirm enum values from OpenAPI /
  AND-163; treat §4.3 list as provisional pending confirmation.
- **R-3 (already-reported semantics):** assumed `409`. If the backend instead
  returns `200` with a status flag, map that field to `alreadyReported` instead.
- **R-4 (dev host flakiness):** intermittent timeouts may make the flow feel
  broken; mitigated by clear retryable error + manual Retry, no auto-retry.
- **OQ-1:** Is a conversation reportable as a first-class target, or only via a
  representative message id? Current design uses `Message` with optional
  `conversationId` in `context`.
- **OQ-2:** Should successfully reporting a content item optimistically hide it?
  Out of scope here (call-site decision) — confirm UX with feed owners.

## 14. Acceptance Criteria

AC-1. From a supported call site, opening `ReportSheet` shows the reason list for
the correct `ReportKind`. (UI test)

AC-2. Submit is disabled until a reason is selected and enabled thereafter, and
disabled while in flight. (UI + unit)

AC-3. A successful submit issues `POST ui/report` with the correct JSON body and
`X-CSRF-Token` header, then shows the confirmation state and invokes
`onCompleted(ReportOutcome.SUBMITTED)`. (MockWebServer + UI)

AC-4. A `409` response shows the "already reported" confirmation and reports
`ReportOutcome.ALREADY_REPORTED`. (unit)

AC-5. A retryable failure (`5xx`/timeout) shows an inline error with Retry that,
on success, transitions to confirmation without re-entering reason/detail.
(unit + UI)

AC-6. A terminal `401` (after the single refresh) shows a non-retryable
"Sign in to report" state and does not auto-loop refresh. (unit)

AC-7. The free-text `detail` never appears in logs (release) or analytics props.
(code review + unit on telemetry props)

AC-8. Reason labels, errors, and confirmation copy are fully resourced and
announced to screen readers (radio group + live region semantics). (UI a11y test)

## 15. Definition of Done

- `feature-report` module created under `com.testlogon.android.feature.report`,
  wired into the Hilt graph (KSP), layered `feature-report -> core-*` only.
- `ReportSheet`, `ReportViewModel`, `ReportRepository`, `ReportApi`, and the
  `ReportReason`/`ReportTarget` models implemented per §4–§5.
- At least one real call site reuses `ReportSheet` (profile or feed), and the
  message kind is reconciled with AND-163.
- All §11 test suites pass in CI; unit + MockWebServer + Compose UI coverage for
  AC-1…AC-8.
- No new cleartext exemptions; CSRF header verified on the report POST; no PII /
  `detail` logging.
- Strings externalized; a11y semantics verified; dark theme + font scaling
  validated.
- `/openapi.json` reconciliation (R-1, R-2, R-3) completed and any deviations
  from §5 reflected in code and this spec.
- Code reviewed and merged to `android-port`.
