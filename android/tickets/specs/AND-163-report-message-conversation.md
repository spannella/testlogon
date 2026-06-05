---
id: AND-163
title: Report message / conversation
milestone: M3
epic: E22
priority: P1
size: M
status: draft
depends_on: [AND-140]
blocks: [E50]
---

# AND-163 — Report message / conversation

## 1. Overview & Goal

This ticket delivers the user-initiated **abuse reporting** flow for messaging: the
ability to report an individual message or an entire conversation from the
TestLogon Android client, submit that report to the FastAPI backend, surface a
clear confirmation, and reflect the resulting **report status** on the reported
entity. It is the first Android touch-point into the Trust & Safety domain
(epic **E50**), which owns downstream moderation, appeals, and admin tooling;
this ticket only covers the reporter-facing client surface.

The single normative acceptance bullet from the backlog is: *"Report submits +
confirmation."* The goal is therefore a robust, idempotent report-submission
path with a confirmation UX and a persisted, queryable report status, built on
the messaging thread surface introduced by **AND-140** (reactions, pins, edits,
delete/revoke, hide). Reporting is added as an additional message/conversation
overflow action alongside those existing actions.

Out of scope: moderator review queues, report adjudication, automated content
removal, blocking/muting (separate tickets in E50/E22), and any admin UI. Those
are explicitly deferred to E50 tickets and noted where relevant below.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app in `android/`, branch
  `android-port`. Namespace/applicationId base: `com.testlogon.android`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12
  / Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compile/target 35.
- **Module placement:** new code lives in `feature-messaging`
  (existing from AND-123/AND-140), with the API contract in `core-network`,
  DTO/domain types in `core-model`, and report persistence in `core-data`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based session
  with `ui_csrf` echoed as `X-CSRF-Token`; 401 triggers one
  `POST /ui/session/refresh` then retry. Persistent cookie jar required.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (look for `report`
  endpoints under the messaging/moderation modules) and shared types in
  `frontend/src/api/types.ts`. The Android contract MUST be reconciled against
  `/openapi.json` at implementation time; shapes below are the working contract.
- **Upstream dependency:** **AND-140** provides the message overflow/action menu,
  the `MessageActionsSheet`, and the thread `StateFlow` that this ticket extends
  with a report action and report-status badge.

## 3. Functional Requirements

FR-1. From a message's overflow menu (the `MessageActionsSheet` from AND-140),
the user can select **Report message**. From the conversation header overflow,
the user can select **Report conversation**.

FR-2. Selecting either entry opens a `ReportSheet` (Material 3
`ModalBottomSheet`) presenting a required **reason category** (single-select)
and an optional free-text **details** field (max 1,000 chars, counter shown).

FR-3. Reason categories are enumerated client-side from a fixed set mirroring the
backend enum: `SPAM`, `HARASSMENT`, `HATE_SPEECH`, `SEXUAL_CONTENT`,
`VIOLENCE`, `SELF_HARM`, `IMPERSONATION`, `OTHER`. `OTHER` makes the details
field required (non-blank). The canonical list MUST be validated against
`/openapi.json` and fall back gracefully if the backend returns an unknown code.

FR-4. The **Submit** button is disabled until a reason is selected (and details
present when required). On tap it issues the report request, disables the form,
and shows an in-sheet progress indicator.

FR-5. On success the sheet dismisses and a confirmation is shown (Snackbar:
"Report submitted. Thanks - our team will review it."). The reported message/
conversation shows a subtle **"Reported"** status badge/affordance afterward.

FR-6. Reporting is **idempotent per (target, reporter)**: re-reporting an already-
reported target is allowed but surfaces "You've already reported this" rather
than an error, and does not create a duplicate UX state.

FR-7. Report status MUST persist locally so the "Reported" affordance survives
process death and is visible offline (cached in Room, see §6).

FR-8. The flow MUST be reachable for both `message` and `conversation` target
types via the same sheet, parameterized by target kind.

FR-9. Cancelling/dismissing the sheet discards the draft (no autosave required
for this ticket).

## 4. Technical Design

New feature surface in `feature-messaging`, MVVM with a `StateFlow<ReportUiState>`.

```kotlin
// core-model
enum class ReportTargetType { MESSAGE, CONVERSATION }

enum class ReportReason {
    SPAM, HARASSMENT, HATE_SPEECH, SEXUAL_CONTENT,
    VIOLENCE, SELF_HARM, IMPERSONATION, OTHER, UNKNOWN
}

data class ReportTarget(
    val type: ReportTargetType,
    val id: String,                 // messageId or conversationId
    val conversationId: String,     // always present for routing/context
)

enum class ReportStatus { NONE, PENDING, SUBMITTED, ALREADY_REPORTED }

data class Report(
    val reportId: String,
    val target: ReportTarget,
    val reason: ReportReason,
    val details: String?,
    val status: ReportStatus,
    val createdAtEpochMs: Long,
)
```

```kotlin
// feature-messaging UI state
data class ReportUiState(
    val target: ReportTarget,
    val availableReasons: List<ReportReason>,
    val selectedReason: ReportReason? = null,
    val details: String = "",
    val detailsMax: Int = 1000,
    val isSubmitting: Boolean = false,
    val canSubmit: Boolean = false,
    val error: UiText? = null,            // mapped FastAPI detail
    val result: SubmitResult? = null,     // one-shot, consumed by UI
) {
    enum class SubmitResult { SUBMITTED, ALREADY_REPORTED }
}
```

```kotlin
@HiltViewModel
class ReportViewModel @Inject constructor(
    private val repo: ReportRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<ReportUiState>
    fun onReasonSelected(reason: ReportReason)
    fun onDetailsChanged(text: String)
    fun submit()
    fun consumeResult()
    fun dismissError()
}
```

```kotlin
// core-data
interface ReportRepository {
    suspend fun submitReport(
        target: ReportTarget,
        reason: ReportReason,
        details: String?,
    ): ApiResult<Report>

    fun observeReportStatus(targetId: String): Flow<ReportStatus>
    suspend fun reasonCatalog(): List<ReportReason>   // backend-validated, cached
}
```

```kotlin
// Compose entry points
@Composable
fun ReportSheet(
    state: ReportUiState,
    onReason: (ReportReason) -> Unit,
    onDetails: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
)
```

The sheet is launched as a transient UI host inside the thread screen rather than
a Navigation destination, to keep it modal over the conversation. Target is
passed via `SavedStateHandle` so the in-flight selection survives
config/process recreation. The `MessageActionsSheet` (AND-140) gains a "Report"
row gated to non-own messages; the conversation header overflow gains "Report
conversation". Repository writes the optimistic `PENDING` row to Room, performs
the network call, then reconciles to `SUBMITTED`/`ALREADY_REPORTED` or rolls
back to `NONE` on hard failure.

## 5. API Contract

Authenticated, cookie-based. CSRF: `X-CSRF-Token` from the `ui_csrf` cookie.
Mutating, therefore **not** eligible for the idempotent-GET backoff retry policy;
on 401 the OkHttp authenticator performs one `POST /ui/session/refresh` + retry.

**Submit a message report**
```
POST /ui/messages/{message_id}/report
Content-Type: application/json
X-CSRF-Token: <ui_csrf>

{ "reason": "HARASSMENT", "details": "optional free text" }
```

**Submit a conversation report**
```
POST /ui/conversations/{conversation_id}/report
{ "reason": "SPAM", "details": null }
```

**Success 201**
```json
{
  "report_id": "rpt_01HY...",
  "target_type": "message",
  "target_id": "msg_01HX...",
  "reason": "HARASSMENT",
  "status": "submitted",
  "created_at": "2026-06-05T12:00:00Z"
}
```

**Already reported 200 / 409** (treat both as success-equivalent):
```json
{ "report_id": "rpt_...", "status": "already_reported" }
```

**Reason catalog (optional, cached)**
```
GET /ui/reports/reasons  ->  { "reasons": ["SPAM","HARASSMENT", ...] }
```
This GET *is* idempotent and uses the bounded-backoff retry policy. If the
endpoint is absent in `/openapi.json`, the client uses the hard-coded enum.

**Retrofit:**
```kotlin
interface ReportApi {
    @POST("ui/messages/{id}/report")
    suspend fun reportMessage(@Path("id") id: String, @Body body: ReportRequestDto): Response<ReportDto>

    @POST("ui/conversations/{id}/report")
    suspend fun reportConversation(@Path("id") id: String, @Body body: ReportRequestDto): Response<ReportDto>

    @GET("ui/reports/reasons")
    suspend fun reasons(): Response<ReasonCatalogDto>
}
```

Error body follows the shared FastAPI `detail` shape (string | `[{msg}]` |
`{code,...}`) and is mapped by the existing `ApiResult`/error mapper.

## 6. Data & State Management

Report status is cached in Room (`core-data`) so the "Reported" affordance is
durable and offline-visible (FR-7).

```kotlin
@Entity(tableName = "report_status")
data class ReportStatusEntity(
    @PrimaryKey val targetId: String,    // message_id or conversation_id
    val targetType: String,              // "message" | "conversation"
    val reportId: String?,
    val status: String,                  // NONE/PENDING/SUBMITTED/ALREADY_REPORTED
    val updatedAtEpochMs: Long,
)

@Dao
interface ReportStatusDao {
    @Query("SELECT status FROM report_status WHERE targetId = :id")
    fun observeStatus(id: String): Flow<String?>

    @Upsert suspend fun upsert(entity: ReportStatusEntity)
}
```

The thread/message Paging 3 layer (from AND-123/AND-140) joins or cross-refs this
status by `targetId` so each rendered message can expose its badge via a
`Flow<ReportStatus>` without a per-row network call. The reason catalog is
cached in DataStore with a short TTL (24h) keyed by build; on cache miss the
hard-coded enum is used. Optimistic write order: `upsert(PENDING)` ->
network -> `upsert(SUBMITTED|ALREADY_REPORTED)` or `upsert(NONE)` on rollback.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s per project standard. POST reports do
  **not** auto-retry (non-idempotent); failure rolls the Room row back to `NONE`
  and shows an inline retryable error in the sheet. The reasons GET uses bounded
  backoff retry.
- **Offline:** Submit is disabled / shows "No connection - try again" when the
  network is unavailable; the optimistic `PENDING` row is rolled back. No
  background queue/outbox in this ticket (candidate E50 follow-up; noted in §13).
- **409 / already reported:** mapped to `SubmitResult.ALREADY_REPORTED`, treated
  as success, status persisted as `ALREADY_REPORTED`.
- **401:** handled by the shared authenticator (one refresh + retry); a second
  401 surfaces a session-expired error and aborts.
- **422 validation** (e.g. missing reason): surface field-level message from the
  `detail` array; client-side validation should normally prevent this.
- **Unknown reason from backend:** decoded to `ReportReason.UNKNOWN`, filtered
  out of the selectable list but tolerated in status reconciliation.

## 8. Security & Privacy

- Report submission requires an authenticated session; the persistent cookie jar
  and `X-CSRF-Token` header are mandatory on every POST.
- Free-text `details` is user-authored and may contain sensitive content: it is
  sent over the (dev) plaintext channel only because the dev host is HTTP;
  production MUST be HTTPS. Do not log `details` contents (see §10).
- Do not expose the reporter's identity in any client-visible state of the
  reported entity; "Reported" status is private to the reporter on-device.
- The reasons catalog and report responses contain no PII beyond IDs; store only
  IDs and status locally, never the report body, in Room.
- Reporting own messages is hidden in UI; backend remains source of truth.

## 9. Accessibility & i18n

- All reason labels, the details hint, counter, submit/cancel buttons, and the
  confirmation Snackbar are externalized to `strings.xml`; no hard-coded copy.
- `ReportSheet` reason rows are exposed as a single-choice
  `selectableGroup()` with `Role.RadioButton` semantics and proper
  `contentDescription`; the character counter is announced via `liveRegion`.
- Touch targets >= 48dp; sheet is dismissible via back gesture and scrim;
  focus moves to the sheet title on open and returns to the originating message
  on close. Supports TalkBack, dynamic font scaling, and dark theme (Material 3).
- The "Reported" badge has a text/`contentDescription` ("Reported"), not color-
  only signaling.

## 10. Telemetry & Logging

- Emit analytics events through the existing app analytics interface:
  `report_opened {target_type}`, `report_submitted {target_type, reason}`,
  `report_already_reported {target_type}`, `report_failed {target_type,
  error_code}`. **Never** include `details` text or target content.
- Logging via the standard Timber/`core-*` logger at `DEBUG`; redact `details`
  and any cookie/CSRF values. Network logging uses the OkHttp interceptor at
  `HEADERS` level in debug builds only (bodies suppressed for the report
  endpoints to avoid leaking free text).

## 11. Testing Strategy

- **Unit (ViewModel):** reason selection enables submit; `OTHER` requires
  details; submit -> `isSubmitting` true -> `SUBMITTED` result; 409 maps to
  `ALREADY_REPORTED`; network error rolls back to `NONE` and surfaces error.
  Use a fake `ReportRepository` and a test dispatcher.
- **Repository:** optimistic `PENDING` write, success reconciliation, rollback
  on failure; reason catalog cache hit/miss + fallback to hard-coded enum.
  Use MockWebServer (`core-testing`) with canned 201/409/422/401 responses,
  asserting the `X-CSRF-Token` header and request JSON body.
- **DAO:** `observeStatus` emits on upsert; survives across instances (in-memory
  Room).
- **Compose UI test:** open sheet from message overflow, select reason, type
  details, submit, assert Snackbar + "Reported" badge; assert submit disabled
  state and 1,000-char cap; assert single-choice semantics for TalkBack.
- **Acceptance verification:** the backlog bullet "Report submits + confirmation"
  is covered by the end-to-end Compose test (submit -> 201 -> confirmation +
  badge) plus the MockWebServer repository test.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-140** - provides `MessageActionsSheet`, thread
  `StateFlow`, and the message-row rendering this ticket extends. Conversation/
  thread plumbing originates from AND-123 (transitive).
- **Blocks / feeds into:** epic **E50 (Trust & Safety)** - moderation review,
  report adjudication, blocking/muting, and any report-history surface consume
  the report records produced here. An offline report outbox (if desired) is an
  E50 follow-up.
- **Reconciliation task:** confirm endpoint paths, the reason enum, and 409
  semantics against `/openapi.json` and the web reference
  (`frontend/src/api/endpoints/*`) before merging.
- Sequencing: implement after AND-140 lands on `android-port`; no other Android
  ticket must land first.

## 13. Risks & Open Questions

- **Endpoint shape unconfirmed:** report paths and the reasons catalog are
  inferred; must be verified against `/openapi.json`. Mitigation: thin
  Retrofit/DTO layer, hard-coded enum fallback.
- **409 vs 200 for duplicates:** backend behavior for re-reporting is uncertain;
  client treats both 200(`already_reported`) and 409 as success.
- **No outbox:** offline submit currently fails fast; is a durable retry queue
  required for M3, or deferred to E50? (Open question.)
- **Conversation report semantics:** does a conversation report imply reporting
  all messages, or a separate entity? Assumed separate (`target_type=conversation`).
- **Plaintext dev host:** free-text details transit HTTP in dev; acceptable for
  dev only, must be HTTPS in prod.

## 14. Acceptance Criteria

AC-1. A user can open the report sheet from a message overflow action and from
the conversation header overflow action. **(FR-1, FR-8)**

AC-2. Submit is disabled until a valid reason is selected (and details provided
when reason is `OTHER`); details field enforces the 1,000-char cap with a
visible counter. **(FR-2, FR-3, FR-4)**

AC-3. A successful submit issues the correct authenticated POST (with
`X-CSRF-Token`), dismisses the sheet, and shows a confirmation Snackbar.
**(Backlog: "Report submits + confirmation"; FR-5)**

AC-4. After submission, the reported message/conversation shows a persisted
"Reported" status that survives process death and is visible offline. **(FR-5,
FR-7)**

AC-5. Re-reporting an already-reported target surfaces "already reported" without
an error and without duplicate UI state. **(FR-6)**

AC-6. Network/timeout failure rolls back optimistic status and shows a retryable
inline error; 401 triggers a single refresh+retry. **(§7)**

AC-7. All copy is localized; the sheet is fully TalkBack-navigable with
single-choice semantics and 48dp targets. **(§9)**

## 15. Definition of Done

- All ACs met; code merged to `android-port` under `com.testlogon.android`.
- New code resides in `feature-messaging` / `core-network` / `core-model` /
  `core-data` per layering; `app -> feature-* -> core-*` respected.
- Unit, repository (MockWebServer), DAO, and Compose UI tests added and green in
  CI; `core-testing` utilities reused.
- Endpoint paths, reason enum, and duplicate-report semantics reconciled against
  `/openapi.json`; DTOs Moshi-annotated with no reflection fallback.
- ktlint/detekt clean; no hard-coded strings; no logging of `details`/cookies/CSRF.
- Telemetry events wired and verified in debug build.
- Spec acceptance bullet "Report submits + confirmation" demonstrably satisfied
  by the end-to-end test and a manual run against the dev backend.
- Open questions in §13 either resolved or filed as E50 follow-up tickets.
