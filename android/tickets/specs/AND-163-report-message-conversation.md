---
id: AND-163
title: Report message / conversation
milestone: M3
epic: E22
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-140]
blocks: [E50]
---

# AND-163 — Report message / conversation

## 1. Overview & Goal

This ticket delivers the user-initiated **abuse reporting** flow for messaging: the
ability to report an individual message from the TestLogon Android client, submit
that report to the FastAPI backend, and surface a clear confirmation.

> **REVIEW CORRECTION (2026-06-06):** The backend exposes only a **message-level**
> report endpoint (`POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`).
> There is **no conversation-level report endpoint** in `/openapi.json`, and the web
> reference reports messages only (the same endpoint is reused for image/attachment
> reports). The "report an entire conversation" capability and the server-backed
> "report status reflected on the entity" capability are therefore **not supported by
> the current backend**. They are retained below as explicit *unverified assumptions*
> (see §16) — conversation reporting must either be dropped from M3 scope or backed by
> a new E50 endpoint before it can be built. The "Reported" status badge, if kept, is
> purely client-side (no GET report-status endpoint exists; the only status endpoint,
> `PATCH .../reports/{report_id}/status`, is moderator-facing). It is the first Android touch-point into the Trust & Safety domain
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

FR-2. Selecting the entry opens a `ReportSheet` (Material 3
`ModalBottomSheet`) presenting a required **reason category** (single-select)
and a **required** free-text **statement** field. **CORRECTED:** per the backend
schema `ReportMessageIn`, the statement (`statement`) is **required**, min 5 /
max 2,000 chars (not optional, not 1,000). Show a live character counter against
the 2,000 cap and disable submit until at least 5 chars are present. The web
reference enforces the same client-side rule ("Reason must be at least 5
characters", `maxLength={2000}`).

FR-3. **CORRECTED — reason values.** The backend field is `reason_code`
(string, 2–64 chars), NOT a fixed uppercase enum. The web client populates
`reason_code` from a fixed **lowercase topic** set:
`sexual`, `extortion`, `criminal`, `spam`, `racist`
(`src/components/shared/ReportContentModal.tsx: MODERATION_TOPICS`). The Android
client SHOULD mirror this list as the selectable reason set and send the chosen
value verbatim as `reason_code`. The previously-listed `SPAM`/`HARASSMENT`/
`HATE_SPEECH`/`SEXUAL_CONTENT`/`VIOLENCE`/`SELF_HARM`/`IMPERSONATION`/`OTHER`
enum is **wrong** and is not what the backend or web client uses. There is **no
reasons-catalog endpoint** in `/openapi.json` (`GET /ui/reports/reasons` does not
exist), so the list is hard-coded client-side; `reason_code` is a free string of
length 2–64, so unknown/extra codes are tolerated by the API.

FR-4. The **Submit** button is disabled until a reason is selected **and** the
statement has >= 5 characters. On tap it issues the report request, disables the
form, and shows an in-sheet progress indicator.

FR-5. **CORRECTED — confirmation copy.** On success the sheet dismisses and a
confirmation is shown. The web reference uses the toast "Report received"; the
Android Snackbar copy should be localized (suggested: "Report received - thanks,
our team will review it"). NOTE: a persisted **"Reported"** status badge is an
*unverified assumption* — no backend report-status query endpoint exists, so any
badge is client-side-only (see §16, Overview correction).

FR-6. **UNVERIFIED ASSUMPTION.** Idempotency per `(target, reporter)` and an
"already reported" affordance are **not supported by the verified contract**: the
report endpoint returns `200:ReportMessageOut` with `status` const `"submitted"`
only; there is **no `409`/`already_reported`** response shape in `/openapi.json`
and the web client does no duplicate handling. Treat re-report behavior as
backend-defined; do not build `ALREADY_REPORTED` handling unless/until the backend
confirms it (E50 follow-up).

FR-7. Report status MUST persist locally so the "Reported" affordance survives
process death and is visible offline (cached in Room, see §6).

FR-8. **CORRECTED.** Only the **message** target type is backed by the verified
backend (and by the web reference, which also reuses it for attachment/image
reports). A `conversation` target type is an *unverified assumption* (no endpoint;
see Overview correction + §16). Keep the sheet parameterized by target kind for
forward-compat, but ship message-only for M3.

FR-9. Cancelling/dismissing the sheet discards the draft (no autosave required
for this ticket).

## 4. Technical Design

New feature surface in `feature-messaging`, MVVM with a `StateFlow<ReportUiState>`.

> **REVIEW NOTE (2026-06-06):** The model below predates verification. `reason_code`
> is a backend **string** (2–64 chars), not an enum, and the verified reason set is
> the lowercase topics `sexual/extortion/criminal/spam/racist`. `CONVERSATION` and
> `ALREADY_REPORTED` are unverified (no backing endpoint/status). The corrected
> reason model is shown immediately after.

```kotlin
// core-model — CORRECTED reason model
// reason_code is a free string (2..64); use a small sealed set matching the web client.
enum class ReportReason(val code: String) {
    SEXUAL("sexual"), EXTORTION("extortion"), CRIMINAL("criminal"),
    SPAM("spam"), RACIST("racist");
}

enum class ReportTargetType { MESSAGE /* CONVERSATION: unverified, no endpoint */ }

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

Authenticated. The web transport sends both an `Authorization: Bearer <token>`
header (from the auth store) **and** cookies (`credentials: include`), plus CSRF:
`X-CSRF-Token` from the `ui_csrf` cookie (`src/api/client.ts`). The report
endpoint's declared params include `authorization` and `X-SESSION-ID`. Mutating,
therefore **not** eligible for the idempotent-GET backoff retry policy; on 401 the
client performs one `POST /ui/session/refresh` (verified: `op=ui_session_refresh`,
resp 200) + retry, then logs out on a second 401.

> **REVIEW CORRECTION (2026-06-06):** The previous paths/shape in this section were
> wrong. Verified against `/openapi.json` and the web reference below.

**Submit a message report — VERIFIED**
```
POST /messaging/conversations/{conversation_id}/messages/{message_id}/report
Content-Type: application/json
Authorization: Bearer <token>
X-CSRF-Token: <ui_csrf>

{ "reason_code": "sexual", "statement": "min 5 chars, max 2000" }
```
Request schema `ReportMessageIn`: `reason_code` (string, 2–64, required),
`statement` (string, 5–2000, required). Both fields required. The path requires
BOTH `conversation_id` and `message_id` (the old `/ui/messages/{id}/report` does
not exist).

**Conversation report — DOES NOT EXIST (unverified assumption).** There is no
`POST /ui/conversations/{id}/report` (or any conversation-level report path) in
`/openapi.json`. Deferred / blocked on an E50 endpoint.

**Success 200 — VERIFIED** (`ReportMessageOut`; note `200`, not `201`):
```json
{
  "ok": true,
  "report_id": "rpt_01HY...",
  "conversation_id": "c1",
  "message_id": "m1",
  "reason_code": "sexual",
  "status": "submitted",
  "created_at": 1717588800
}
```
Note: `created_at` is an **integer** (epoch), not an ISO-8601 string; `status`
is the const `"submitted"`; there are no `target_type`/`target_id` fields.

**Already reported / 409 — NOT IN CONTRACT (removed).** No `409` response and no
`already_reported` status exist for this endpoint. Do not implement.

**Reason catalog — DOES NOT EXIST.** `GET /ui/reports/reasons` is not in
`/openapi.json`. The reason list is hard-coded client-side (see FR-3); no network
fetch and no cache.

**Error responses — VERIFIED:** `401 / 403 / 404 / 422 / 429` all return
`MessageControlsErrorOut` `{ detail: string, error_code?: string|null }` (NOT the
generic FastAPI validation array for 422 on this route — the route maps validation
to `MessageControlsErrorOut` per the index). Map `detail` for display and
`error_code` for branching.

**Retrofit — CORRECTED:**
```kotlin
interface ReportApi {
    @POST("messaging/conversations/{conversationId}/messages/{messageId}/report")
    suspend fun reportMessage(
        @Path("conversationId") conversationId: String,
        @Path("messageId") messageId: String,
        @Body body: ReportMessageRequestDto,   // { reason_code, statement }
    ): Response<ReportMessageResponseDto>       // ReportMessageOut shape
}
// No reportConversation / reasons endpoints — neither exists in /openapi.json.
```

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
`Flow<ReportStatus>` without a per-row network call. **CORRECTED:** there is no
reason-catalog endpoint, so the DataStore reason cache is dropped — the reason
list is a compile-time constant (`sexual/extortion/criminal/spam/racist`).
Optimistic write order: `upsert(PENDING)` ->
network -> `upsert(SUBMITTED|ALREADY_REPORTED)` or `upsert(NONE)` on rollback.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s per project standard. POST reports do
  **not** auto-retry (non-idempotent); failure rolls the Room row back to `NONE`
  and shows an inline retryable error in the sheet. (There is no reasons GET — the
  reason list is hard-coded; the prior "reasons GET uses bounded backoff retry"
  line was removed.)
- **Offline:** Submit is disabled / shows "No connection - try again" when the
  network is unavailable; the optimistic `PENDING` row is rolled back. No
  background queue/outbox in this ticket (candidate E50 follow-up; noted in §13).
- **409 / already reported:** **REMOVED — not in contract.** No `409` and no
  `already_reported` status exist for this endpoint (verified). Do not map it.
- **401:** handled by the shared refresh path (one `POST /ui/session/refresh` +
  retry); a second 401 surfaces a session-expired error and aborts (matches
  `src/api/client.ts`).
- **403 / 404 / 429:** return `MessageControlsErrorOut` `{detail, error_code?}`;
  map `detail` to an inline error (e.g. 403 not permitted, 404 message gone,
  429 rate-limited). 429 is plausible (declared) and should show a "try again
  shortly" message.
- **422 validation** (e.g. statement < 5 chars, missing `reason_code`): the route
  returns `MessageControlsErrorOut` (a single `detail` string) for 422 — NOT the
  generic `[{msg}]` array. Surface `detail`; client-side validation should
  normally prevent this.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend paths are
under `reference/src/`.

1. **Message-report endpoint is `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`.**
   VERDICT: Corrected (spec said `POST /ui/messages/{message_id}/report`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`
   (op=`report_message_...`); `src/api/endpoints/messaging.ts: reportMessage`.
2. **Success status is `200` returning `ReportMessageOut`.** VERDICT: Corrected
   (spec said `201`). SOURCE: OpenAPI index `resp=200:ReportMessageOut`;
   schema `ReportMessageOut`.
3. **Request body is `{ reason_code: string(2..64), statement: string(5..2000) }`, both required.**
   VERDICT: Corrected (spec said `{reason, details}` with optional 1000-char
   details). SOURCE: schema `ReportMessageIn` (`reason_code` minLength 2/maxLength
   64; `statement` minLength 5/maxLength 2000; both in `required`);
   `src/api/endpoints/messaging.ts: reportMessage`; `src/api/types.ts: ReportMessageReq`.
4. **Response fields: `ok, report_id, conversation_id, message_id, reason_code, status("submitted" const), created_at(integer epoch)`.**
   VERDICT: Corrected (spec had `target_type`, `target_id`, ISO-string
   `created_at`, no `ok`). SOURCE: schema `ReportMessageOut`; `src/api/types.ts:
   ReportMessageResp`.
5. **Reason values are lowercase topics `sexual, extortion, criminal, spam, racist`.**
   VERDICT: Corrected (spec listed an 8-value uppercase enum). SOURCE:
   `src/components/shared/ReportContentModal.tsx: MODERATION_TOPICS`; usage
   `src/pages/messages/MessageBubble.tsx` (`reason_code: topics[0]`);
   `src/pages/messages/MessageBubble.report.test.tsx` (asserts `reason_code: "sexual"`).
6. **No conversation-level report endpoint exists.** VERDICT: Corrected /
   Unverified-assumption (spec defined `POST /ui/conversations/{id}/report`).
   SOURCE: no such path in `reference/openapi.index.txt` (only the message-report
   and the moderator `PATCH .../reports/{report_id}/status` exist); web reports
   messages only (`src/pages/messages/MessageBubble.tsx`).
7. **No reasons-catalog endpoint (`GET /ui/reports/reasons`).** VERDICT: Corrected
   (spec proposed it as optional). SOURCE: absent in `reference/openapi.index.txt`;
   reasons are a frontend constant (`ReportContentModal.tsx`).
8. **No `409` / `already_reported` response or idempotency contract.** VERDICT:
   Corrected (spec mapped 200/409 to `ALREADY_REPORTED`). SOURCE: OpenAPI index
   responses for the route are `200;401;403;404;422;429`; `status` const is
   `"submitted"` (`ReportMessageOut`); web does no duplicate handling
   (`MessageBubble.tsx` reportMut).
9. **Error responses (401/403/404/422/429) use `MessageControlsErrorOut {detail:string, error_code?:string|null}`.**
   VERDICT: Corrected (spec assumed generic FastAPI `detail` array for 422 on this
   route). SOURCE: OpenAPI index (all error codes -> `MessageControlsErrorOut`);
   schema `MessageControlsErrorOut`.
10. **Auth/CSRF: `Authorization: Bearer` + cookies + `X-CSRF-Token` from `ui_csrf`; 401 -> one `POST /ui/session/refresh` + retry, logout on 2nd 401.**
    VERDICT: Verified (spec's CSRF + single-refresh claim correct; amended to add
    the Bearer header). SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` ->
    `X-CSRF-Token`, `Authorization: Bearer`, `refreshSession()` -> `/ui/session/refresh`);
    OpenAPI `POST /ui/session/refresh` (resp 200); route params `authorization,X-SESSION-ID`.
11. **Confirmation copy.** VERDICT: Corrected (spec: "Report submitted. Thanks - our
    team will review it."). SOURCE: web uses toast "Report received"
    (`MessageBubble.tsx`; `MessageBubble.report.test.tsx`). Android copy localized.
12. **Statement validation is min 5 / max 2000 chars, required.** VERDICT: Corrected
    (spec: optional, max 1000). SOURCE: schema `ReportMessageIn`;
    `ReportContentModal.tsx` (`minLength={5}`, `maxLength={2000}`, "at least 5
    characters").
13. **Attachment/image reports reuse the same message endpoint.** VERDICT: Verified
    (added context). SOURCE: `src/pages/messages/MessageBubble.tsx` (report-image /
    report-attachment paths call `reportMessage` with the same body).
14. **Stack/module/framework choices** (Compose Material 3 `ModalBottomSheet`,
    Room, Hilt, Retrofit/Moshi, `selectableGroup()`/`Role.RadioButton`, `liveRegion`,
    48dp targets, Paging 3). VERDICT: Unverified-assumption (framework ref — not
    derivable from backend/frontend sources; consistent with project conventions in
    §2). SOURCE (framework ref): Android Compose Material 3 `ModalBottomSheet`
    https://developer.android.com/develop/ui/compose/components/bottom-sheets ;
    accessibility semantics https://developer.android.com/develop/ui/compose/accessibility .

### Corrections made

- Endpoint path: `/ui/messages/{id}/report` -> `/messaging/conversations/{conversation_id}/messages/{message_id}/report` (claim 1).
- Success code `201` -> `200` (claim 2).
- Request body `{reason, details?}` (details optional, 1000) -> `{reason_code(req,2..64), statement(req,5..2000)}` (claims 3, 12).
- Response shape: replaced `target_type/target_id` + ISO `created_at` with verified `ReportMessageOut` (claim 4).
- Reason enum (8 uppercase + UNKNOWN) -> 5 lowercase topic codes; reason model rewritten (claim 5).
- Removed conversation-report endpoint, reasons-catalog endpoint, and 409/`already_reported` idempotency from the contract; FR-6/FR-8 demoted to assumptions; §6 reason cache dropped; §7 error map rewritten to `MessageControlsErrorOut` (claims 6, 7, 8, 9).
- Confirmation copy aligned to "Report received" (claim 11).
- Auth section amended to include `Authorization: Bearer` alongside cookie/CSRF (claim 10).

### Open assumptions

- **Conversation-level reporting** (FR-8, §1, AC-1's "conversation header overflow").
  Why unverifiable: no endpoint in `/openapi.json` and no web usage. Must be dropped
  from M3 or backed by a new E50 endpoint.
- **Persisted "Reported" status badge / report-status read** (FR-5, FR-7, AC-4).
  Why unverifiable: no client-facing report-status GET endpoint; the only status
  endpoint (`PATCH .../reports/{report_id}/status`, `ReportStatusUpdateIn`) is
  moderator-facing. Any badge is client-side-only state with no server source of truth.
- **Idempotency / "already reported" UX** (FR-6, AC-5). Why unverifiable: no `409`
  or `already_reported` in the contract; backend re-report behavior is unknown.
- **Android framework/library choices** (claim 14). Why unverifiable from the given
  sources: they are client-architecture decisions, not backend/web contract; cited
  as framework refs and consistent with §2 conventions.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung
Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Use MockWebServer
for contract tests. Most cases here are non-hardware and run on JVM/emu35; UI/e2e
cases are noted for emu35 with one cross-ABI confirmation on deviceA15.

- **TC-AND-163-01** — Type: unit (ViewModel). Target: JVM.
  Preconditions: fake `ReportRepository`; test dispatcher; message target.
  Steps: select reason `SEXUAL`; type 10-char statement; read `uiState`.
  Expected: `canSubmit == true` only when a reason is selected AND statement length
  >= 5; with no reason or <5 chars `canSubmit == false`. Traces: AC-2.

- **TC-AND-163-02** — Type: unit (ViewModel). Target: JVM.
  Preconditions: fake repo returning success.
  Steps: select reason + valid statement; call `submit()`.
  Expected: `isSubmitting` flips true then false; `result == SUBMITTED`; repo called
  once with `reason_code` = selected topic code and the exact statement text.
  Traces: AC-3.

- **TC-AND-163-03** — Type: contract/MockWebServer (repository). Target: JVM.
  Preconditions: MockWebServer enqueues `200` with a valid `ReportMessageOut` body.
  Steps: call `submitReport(message, SEXUAL, "looks sexual")`.
  Expected: request method POST to
  `/messaging/conversations/{cid}/messages/{mid}/report`; JSON body exactly
  `{"reason_code":"sexual","statement":"looks sexual"}`; headers include
  `X-CSRF-Token` and `Authorization: Bearer`; response parsed to `report_id`,
  `status="submitted"`, integer `created_at`; Room row reconciled PENDING->SUBMITTED.
  Traces: AC-3, AC-4.

- **TC-AND-163-04** — Type: contract/MockWebServer (repository). Target: JVM.
  Preconditions: MockWebServer enqueues `422` with `MessageControlsErrorOut`
  `{"detail":"statement too short"}`.
  Steps: submit with a borderline body that the server rejects.
  Expected: `ApiResult` error carrying `detail` string (not the `[{msg}]` array
  path); optimistic Room row rolled back to NONE; no crash on the non-array detail.
  Traces: AC-2, AC-6.

- **TC-AND-163-05** — Type: contract/MockWebServer (repository). Target: JVM.
  Preconditions: enqueue `429` `MessageControlsErrorOut`
  `{"detail":"rate limited","error_code":"rate_limited"}`.
  Steps: submit.
  Expected: mapped to a retryable inline error using `detail`; `error_code`
  available for branching; no auto-retry (POST is non-idempotent); Room -> NONE.
  Traces: AC-6.

- **TC-AND-163-06** — Type: contract/MockWebServer (repository). Target: JVM.
  Preconditions: enqueue `401`, then a `200` for `/ui/session/refresh`, then a
  `200` `ReportMessageOut` for the retried report.
  Steps: submit once.
  Expected: exactly one refresh `POST /ui/session/refresh` then one retry of the
  original POST; final result SUBMITTED. Traces: AC-6.

- **TC-AND-163-07** — Type: contract/MockWebServer (repository). Target: JVM.
  Preconditions: enqueue `401`, refresh `200`, then a second `401` on retry.
  Steps: submit.
  Expected: aborts with a session-expired error (no infinite refresh loop); Room ->
  NONE. Traces: AC-6.

- **TC-AND-163-08** — Type: unit/integration (repository, offline). Target: JVM.
  Preconditions: connectivity reported unavailable (fake) OR socket failure to the
  flaky dev host `18.222.237.167:8000` simulated via MockWebServer
  `SocketPolicy.DISCONNECT_AT_START`.
  Steps: attempt submit while offline.
  Expected: submit blocked / fails fast with "No connection - try again"; optimistic
  PENDING row rolled back to NONE; no outbox enqueue (out of scope). Traces: AC-6.

- **TC-AND-163-09** — Type: unit (DAO, in-memory Room). Target: JVM (Robolectric if
  needed). Preconditions: in-memory `ReportStatusDao`.
  Steps: `observeStatus(id)`; upsert PENDING then SUBMITTED.
  Expected: Flow emits null -> PENDING -> SUBMITTED; value survives a new DAO
  instance over the same DB (process-death proxy). Traces: AC-4.

- **TC-AND-163-10** — Type: Compose-UI. Target: emu35.
  Preconditions: thread screen with a non-own message; `MessageActionsSheet` (AND-140).
  Steps: open overflow -> "Report message"; assert submit disabled; pick reason;
  type statement; observe character counter approaching 2000; submit; backend (fake
  ApiResult) returns SUBMITTED.
  Expected: sheet shows reason single-select + required statement; submit enabled only
  after reason + >=5 chars; on success sheet dismisses and confirmation Snackbar
  ("Report received...") shows; "Reported" affordance appears (client-side).
  Traces: AC-1, AC-2, AC-3, AC-4.

- **TC-AND-163-11** — Type: Compose-UI (accessibility). Target: emu35 with TalkBack
  enabled. Preconditions: report sheet open.
  Steps: traverse reason rows with TalkBack; check counter announcement; check focus
  order and touch-target sizes.
  Expected: reason rows expose single-choice `Role.RadioButton` semantics in a
  `selectableGroup()`; counter announced via `liveRegion`; targets >= 48dp; all copy
  from `strings.xml` (no hard-coded text); "Reported" badge has a text
  contentDescription (not color-only). Traces: AC-7.

- **TC-AND-163-12** — Type: Compose-UI (security/permission). Target: emu35.
  Preconditions: one own message and one other-user message in the thread.
  Steps: open overflow on each.
  Expected: "Report message" hidden on own messages, shown on others (mirrors web
  `!isOwn` gating). Traces: AC-1, §8.

- **TC-AND-163-13** — Type: instrumented/e2e. Target: deviceA15 (physical; confirms
  arm64-v8a / API-34 behavior vs the x86_64/API-35 emulator).
  Preconditions: app pointed at a MockWebServer or stub returning `200`
  `ReportMessageOut`; authenticated session with `ui_csrf` cookie present.
  Steps: full flow open sheet -> reason -> statement -> submit -> confirmation.
  Expected: on real arm64/API-34 hardware the POST carries `X-CSRF-Token` +
  `Authorization`, body matches `ReportMessageIn`, confirmation Snackbar shows, no
  ABI/Moshi codegen issues. Traces: AC-3, AC-4 (backlog "Report submits + confirmation").

- **TC-AND-163-14** — Type: manual. Target: deviceA15 against the live dev host
  `http://18.222.237.167:8000` (flaky/plaintext).
  Preconditions: real logged-in session.
  Steps: report a real test message; observe confirmation; retry on transient host
  failure.
  Expected: report submits and confirms against the real backend; transient dev-host
  failures surface the retryable inline error and roll back the badge; `details`/
  statement text never appears in logs (HEADERS-level logging only). Traces: AC-3,
  AC-6, §10.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (open sheet from message overflow; conversation overflow*) | TC-10, TC-12 (*conversation overflow not testable — endpoint does not exist; see §16 open assumptions) |
| AC-2 (submit gating, statement validation, counter/cap) | TC-01, TC-04, TC-10 |
| AC-3 (correct authenticated POST + confirmation) | TC-02, TC-03, TC-10, TC-13, TC-14 |
| AC-4 (persisted "Reported" status, survives death / offline) | TC-03, TC-09, TC-10, TC-13 |
| AC-5 (already-reported, no duplicate state) | Not covered — no `409`/`already_reported` contract exists (see §16 open assumptions); revisit when E50 defines it |
| AC-6 (failure rollback + 401 single refresh+retry) | TC-04, TC-05, TC-06, TC-07, TC-08, TC-14 |
| AC-7 (localized, TalkBack single-choice, 48dp) | TC-11 |
