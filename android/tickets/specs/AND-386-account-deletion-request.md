---
id: AND-386
title: Account deletion request
milestone: M8
epic: E50
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-385]
blocks: []
---

# AND-386 — Account deletion request

## 1. Overview & Goal

This ticket delivers the in-app **account deletion request** flow for the TestLogon
native Android app. Users must be able to (a) request deletion of their account,
(b) observe the pending/scheduled state of that request, and (c) cancel a pending
request before it is executed by the backend. Because deletion is irreversible once
it lands, the defining requirement is a **strong, multi-step confirmation** UX that
makes accidental deletion practically impossible while keeping the legitimate path
completable.

The feature lives in the existing Privacy area introduced by AND-385 (Privacy / data
export). AND-385 owns the `requests list` and the deletion-export endpoints; this
ticket adds the *request* and *cancel* mutations plus the confirmation choreography
on top of that surface. The goal is met when an authenticated user can move their
account into a `pending_deletion` state and back to `active` again, each transition
gated behind explicit, deliberate confirmation, with correct UI state for the
unreliable dev backend (offline / stale / in-flight).

Out of scope: actually purging data (server-side), the data export feature itself
(AND-385), re-authentication step-up if the backend requires it on a 401 (handled by
the shared session refresh in core-network), and post-deletion logout/teardown
beyond clearing local session state.

## 2. Context & References

- **Module:** `feature-privacy` (created in AND-385) → consumes `core-data`,
  `core-network`, `core-model`, `core-ui`, `core-testing`.
- **Namespace / applicationId base:** `com.testlogon.android`. Code in this ticket
  lives under `com.testlogon.android.feature.privacy.deletion`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single
  Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15,
  DataStore for prefs, minSdk 24 / compileSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext,
  unreliable; ~20s timeouts, bounded backoff on idempotent GETs only). OpenAPI at
  `/openapi.json`.
- **Auth:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`. Mutating
  calls (POST) here MUST carry the CSRF header (supplied by the shared
  `CsrfInterceptor`). On 401, the shared client performs one `POST /ui/session/refresh`
  then retries.
- **Web reference:** `src/api/endpoints/accountDeletion.ts` (the actual user +
  admin deletion endpoint calls), `src/api/types.ts` for the DTO shapes
  (`AccountDeletionStatus`, `AccountDeletionRequestBody`, `AccountDeletionListResp`,
  `AccountDeletionCancelResp`), `src/api/client.ts` for CSRF/refresh transport, and
  `src/pages/settings/AccountDeletionPage.tsx` for screen behavior.
- **Upstream ticket:** AND-385 — provides `PrivacyApi`, the requests-list screen,
  the `feature-privacy` module, and the deletion-export endpoints. This ticket extends
  that API surface; it does not re-create the module or list.

## 3. Functional Requirements

FR-1. **Entry point.** From the Privacy screen (AND-385), a "Delete account" row
navigates to a dedicated `AccountDeletionRoute`. The row shows the current status
when a request is already pending ("Deletion scheduled — tap to manage").

FR-2. **Request deletion (multi-step confirm).** Initiating deletion requires THREE
deliberate gates that cannot all be satisfied by a single accidental tap:
  1. A warning screen describing consequences and the grace/cooldown window returned
     by the backend, with a primary "Continue" button.
  2. A typed-confirmation step: the user must type the exact phrase
     **`DELETE MY ACCOUNT`** (locale-independent, case-sensitive sentinel) into a
     text field AND re-enter their account **password**; the destructive button
     stays disabled until the phrase matches AND the password field is non-empty.
     [CORRECTED: the server requires `confirm_text == "DELETE MY ACCOUNT"` and a
     non-empty `password`, per `AccountDeletionRequestIn` and the web client's
     `CONFIRM_TEXT` constant — see §16. The earlier draft used the word "DELETE"
     and omitted the password.]
  3. A final Material 3 `AlertDialog` ("This cannot be undone") with the destructive
     action labeled "Delete my account" and a neutral "Cancel".
Only after all three does the app issue the request mutation, sending
`{ password, confirm_text, reason? }`.

FR-3. **Pending state.** After a successful request the screen switches to a
"Deletion scheduled" state showing the scheduled execution date (`scheduled_for`,
epoch seconds) and the `grace_days_remaining` countdown, plus a "Cancel deletion
request" action. The Cancel action is shown only when the server reports
`can_cancel == true` (mirrors the web client, which disables Cancel on
`!can_cancel`).

FR-4. **Cancel deletion (single explicit confirm).** Cancelling restores the account
to `active`. Cancel is also destructive-of-intent but reversible, so it is gated by a
single `AlertDialog` confirm ("Keep my account?" / "Cancel deletion").

FR-5. **Idempotent / re-entrant.** Re-entering the screen reflects the authoritative
server state; if a request already exists, the request flow is hidden and only Cancel
is offered. Double-submission must be prevented (button disabled while in-flight).

FR-6. **Offline / stale.** When status cannot be fetched, show the last-known state
with a stale banner; mutations are disabled while offline and surface a ret
"Can't reach server" message rather than silently failing.

FR-7. **Success feedback.** Both request and cancel show a confirming snackbar and
update in-place without a full navigation pop.

## 4. Technical Design

State is exposed via a single `StateFlow<AccountDeletionUiState>` from a Hilt
`@HiltViewModel`. The screen is a stateless Composable driven by that state plus an
event lambda.

```kotlin
package com.testlogon.android.feature.privacy.deletion

sealed interface AccountDeletionUiState {
    data object Loading : AccountDeletionUiState
    data class Ready(
        val status: DeletionStatus,            // Active | Pending
        val confirmStep: ConfirmStep = ConfirmStep.None,
        val typedConfirmation: String = "",     // must equal "DELETE MY ACCOUNT"
        val password: String = "",              // re-entered; required by server
        val mutationInFlight: Boolean = false,
        val isStale: Boolean = false,
        val transient: TransientMessage? = null // snackbar/error
    ) : AccountDeletionUiState
    data class Error(val message: String, val retryable: Boolean) : AccountDeletionUiState
}

enum class ConfirmStep { None, Warning, TypeToConfirm, FinalDialog, CancelDialog }

sealed interface DeletionStatus {
    data object Active : DeletionStatus
    data class Pending(
        val requestId: String,
        val createdAt: Instant,                 // server: created_at (epoch SECONDS)
        val scheduledFor: Instant?,             // server: scheduled_for (epoch SECONDS | null)
        val graceDaysRemaining: Int?,           // server: grace_days_remaining
        val canCancel: Boolean                  // server: can_cancel — gates the Cancel CTA
    ) : DeletionStatus
}
// NOTE [CORRECTED]: the server has no `requested_at`; the creation timestamp is
// `created_at`, and ALL timestamps are epoch-second INTEGERS, not ISO-8601 strings.
// "Pending" maps to the server status string "pending" (NOT "pending_deletion").

data class TransientMessage(val text: String, val isError: Boolean)
```

```kotlin
@HiltViewModel
class AccountDeletionViewModel @Inject constructor(
    private val repo: AccountDeletionRepository
) : ViewModel() {
    val uiState: StateFlow<AccountDeletionUiState>

    fun onEvent(event: AccountDeletionEvent)
}

sealed interface AccountDeletionEvent {
    data object Refresh : AccountDeletionEvent
    data object StartRequest : AccountDeletionEvent            // -> Warning
    data object AdvanceFromWarning : AccountDeletionEvent      // -> TypeToConfirm
    data class TypedConfirmationChanged(val text: String) : AccountDeletionEvent
    data class PasswordChanged(val text: String) : AccountDeletionEvent
    data object ShowFinalDialog : AccountDeletionEvent         // enabled only if text == "DELETE MY ACCOUNT" && password.isNotEmpty()
    data object ConfirmDelete : AccountDeletionEvent           // fires mutation
    data object StartCancel : AccountDeletionEvent             // -> CancelDialog
    data object ConfirmCancel : AccountDeletionEvent           // fires mutation
    data object Dismiss : AccountDeletionEvent                 // back to ConfirmStep.None
    data object ConsumeTransient : AccountDeletionEvent
}
```

Repository (in `core-data`, behind an interface so feature code stays test-friendly):

```kotlin
interface AccountDeletionRepository {
    suspend fun getStatus(): ApiResult<DeletionStatus>           // GET .../requests, derive pending
    suspend fun requestDeletion(
        password: String,
        confirmText: String,                                     // must be "DELETE MY ACCOUNT"
        reason: String? = null
    ): ApiResult<DeletionStatus.Pending>
    suspend fun cancelDeletion(requestId: String): ApiResult<DeletionStatus> // 200 + AccountDeletionCancelOut
}
```

The Retrofit service extends the AND-385 `PrivacyApi` (same module):

```kotlin
interface PrivacyApi {
    // ...AND-385 export + requests-list methods...

    // [CORRECTED] No GET /ui/privacy/account-deletion exists. Status is read from
    // the requests LIST and the pending entry is derived (status == "pending").
    @GET("ui/privacy/account-deletion/requests")
    suspend fun listDeletions(): Response<AccountDeletionListDto>

    // Optional single-record fetch (e.g., after a mutation):
    @GET("ui/privacy/account-deletion/requests/{requestId}")
    suspend fun getDeletion(@Path("requestId") requestId: String): Response<AccountDeletionStatusDto>

    // [CORRECTED] Requires a JSON body (AccountDeletionRequestIn); returns 201.
    @POST("ui/privacy/account-deletion/request")
    suspend fun requestDeletion(@Body body: AccountDeletionRequestDto): Response<AccountDeletionStatusDto>

    // [CORRECTED] Path includes /requests/; returns 200 + AccountDeletionCancelOut (NOT 204/Unit).
    @POST("ui/privacy/account-deletion/requests/{requestId}/cancel")
    suspend fun cancelDeletion(@Path("requestId") requestId: String): Response<AccountDeletionCancelDto>
}
```

> Endpoint paths and shapes above were RECONCILED against `openapi.index.txt` /
> `openapi.pretty.json` and `src/api/endpoints/accountDeletion.ts` during the
> 2026-06-06 review (see §16). AND-385 establishes the `/ui/privacy/account-deletion`
> prefix; the user-facing operations live under `.../requests`, `.../request`, and
> `.../requests/{request_id}/cancel`. Any further live-contract drift should be
> re-verified and noted in the PR.

**Navigation.** Add a typed route to the privacy nav graph:

```kotlin
@Serializable data object AccountDeletionRoute
fun NavGraphBuilder.accountDeletion(onBack: () -> Unit) {
    composable<AccountDeletionRoute> { AccountDeletionScreen(onBack = onBack) }
}
```

The Composable renders one of: `Loading`, the request-CTA + multi-step confirm
overlay, or the pending/cancel surface. The typed-confirm gate uses a Material 3
`OutlinedTextField` plus a password field (`KeyboardType.Password`,
`PasswordVisualTransformation`); the destructive button derives `enabled` from
`state.typedConfirmation == DELETE_SENTINEL && state.password.isNotEmpty() && !state.mutationInFlight`,
where `DELETE_SENTINEL == "DELETE MY ACCOUNT"`.

## 5. API Contract

> [CORRECTED] The earlier draft assumed a single `GET /ui/privacy/account-deletion`
> returning `{status, request}` with ISO-8601 timestamps and a `pending_deletion`
> status. None of that matches the live contract. The real shapes follow.

**GET `/ui/privacy/account-deletion/requests`** — lists the caller's deletion
requests (idempotent; eligible for bounded backoff retry). Response
`AccountDeletionListOut`. There is NO dedicated status endpoint — the client derives
the active state by finding the entry whose `status == "pending"` (this is exactly
what the web client does: `requests.find(r => r.status === "pending")`).

```json
{
  "requests": [
    {
      "request_id": "del_01J9...",
      "status": "pending",
      "created_at": 1749132131,
      "scheduled_for": 1750341731,
      "grace_days_remaining": 14,
      "can_cancel": true,
      "retention_hold": false,
      "reason": null
    }
  ],
  "total": 1
}
```

When no request exists, `requests` is empty and the UI shows the "active" surface.
Single-record refresh after a mutation is available via **GET
`/ui/privacy/account-deletion/requests/{request_id}`** → `AccountDeletionStatusOut`.

**POST `/ui/privacy/account-deletion/request`** — requires `X-CSRF-Token` AND a JSON
body `AccountDeletionRequestIn` `{ password (required, 1..200), confirm_text
(required), reason? (≤500) }`. Returns **201** with `AccountDeletionStatusOut`
(status `"pending"`). Treated as NON-idempotent → no automatic retry. The server
validates `password` and `confirm_text`; on failure the documented response is **422
HTTPValidationError** (the web client surfaces "Could not schedule deletion. Check
your password." on any error).

**POST `/ui/privacy/account-deletion/requests/{request_id}/cancel`** — requires
`X-CSRF-Token`; empty body. Returns **200** with `AccountDeletionCancelOut`
`{ ok, request_id, status, cancelled_at }` (NOT 204/empty). Non-idempotent → no
automatic retry; the client guards against double submit. After success the client
re-fetches the list to obtain the authoritative active state.

DTOs (Moshi). All timestamps are epoch-SECOND integers (`Long`):

```kotlin
@JsonClass(generateAdapter = true)
data class AccountDeletionRequestDto(           // request body (AccountDeletionRequestIn)
    @Json(name = "password") val password: String,
    @Json(name = "confirm_text") val confirmText: String,   // "DELETE MY ACCOUNT"
    @Json(name = "reason") val reason: String? = null
)
@JsonClass(generateAdapter = true)
data class AccountDeletionStatusDto(            // AccountDeletionStatusOut
    @Json(name = "request_id") val requestId: String,       // required
    @Json(name = "status") val status: String,              // required: "pending" | "completed" | "cancelled" | ...
    @Json(name = "created_at") val createdAt: Long,         // required, epoch seconds
    @Json(name = "scheduled_for") val scheduledFor: Long? = null,
    @Json(name = "grace_days_remaining") val graceDaysRemaining: Int? = null,
    @Json(name = "can_cancel") val canCancel: Boolean = false,
    @Json(name = "retention_hold") val retentionHold: Boolean = false,
    @Json(name = "retention_hold_reason") val retentionHoldReason: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "user_sub") val userSub: String? = null
)
@JsonClass(generateAdapter = true)
data class AccountDeletionListDto(              // AccountDeletionListOut
    @Json(name = "requests") val requests: List<AccountDeletionStatusDto> = emptyList(),
    @Json(name = "total") val total: Int = 0
)
@JsonClass(generateAdapter = true)
data class AccountDeletionCancelDto(           // AccountDeletionCancelOut
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "request_id") val requestId: String,
    @Json(name = "status") val status: String,
    @Json(name = "cancelled_at") val cancelledAt: Long
)
```

FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`) is handled by the
shared `ApiResult` error mapper in core-network; this ticket adds no bespoke parsing.
The only error response documented in OpenAPI for these endpoints is **422
HTTPValidationError** (`{ detail: [ValidationError, ...] }`); a wrong password is
expected to land here (or as a 4xx auth failure) — mapped to a friendly inline
message and a forced status re-fetch. [UNVERIFIED-ASSUMPTION] 409 (already pending /
nothing to cancel) and 404 (request gone) are NOT documented in the spec; if the
backend emits them, treat them as recoverable → re-fetch and show "Request already
resolved". See §16 Open assumptions.

## 6. Data & State Management

- **Source of truth:** the server. The ViewModel calls `getStatus()` on entry and after
  every successful mutation; it does not optimistically flip status before the server
  confirms (deletion is too consequential for optimistic UI).
- **Caching:** no Room table is required for this single record. The last successful
  `DeletionStatus` is cached in-memory in the repository and mirrored to a small
  **DataStore** key (`privacy_deletion_status_json`) so the Privacy row and this
  screen can render a last-known value while offline (FR-6). DataStore writes are
  best-effort; a read failure falls back to `Loading` → fetch.
- **Confirm progress** (`confirmStep`, `typedConfirmation`) is pure UI state held in
  the ViewModel and is reset to `None`/empty on `Dismiss`, on success, and on screen
  leave. It is intentionally NOT persisted across process death — re-entering restarts
  the confirmation from the warning step.
- **Timestamps:** [CORRECTED] the server sends epoch-SECOND integers, not ISO-8601
  strings. Convert via `Instant.ofEpochSecond(value)` and render with the
  locale/zone formatter from core-ui. `scheduled_for == null` renders "soon"; prefer
  `grace_days_remaining` for the countdown when present.

## 7. Error Handling & Resilience

- **Timeouts:** GET status uses the shared 20s OkHttp timeout and bounded exponential
  backoff (max 2 retries, jittered) since it is idempotent. POST request/cancel use a
  single attempt — **no retry** to avoid duplicate side effects.
- **Offline:** `ApiResult.NetworkError` → `Ready(isStale = true)` over last-known
  status; mutation events while stale produce a `TransientMessage(isError=true,
  "Can't reach server — try again")` and do not call the API.
- **401:** handled by the shared authenticator (one `POST /ui/session/refresh` then
  retry). If refresh fails, surface `Error(message, retryable=false)` and let the host
  route to re-auth.
- **409 / 404 on mutation:** swallow as a recoverable case → re-fetch status and show
  an explanatory snackbar; never leave the UI showing a stale action button.
- **Double-submit:** `mutationInFlight` disables both destructive buttons and the
  dialog confirm; events received while in-flight are ignored.
- **Partial confirm abandonment:** navigating back mid-confirm cancels the flow with
  no network effect.

## 8. Security & Privacy

- All mutating calls ride the persistent cookie jar + `X-CSRF-Token` header (the
  `ui_csrf` cookie echoed as `X-CSRF-Token`, verified in `src/api/client.ts`). The
  deletion *request* body carries the user's `password` and `confirm_text`
  [CORRECTED — the body is NOT empty]; the cancel body is empty.
- **No PII / secrets in logs.** Never log the `password`, and do not log `request_id`,
  `created_at`, `scheduled_for`, `cancelled_at`, `user_sub`, or any account identifier
  at any level; redact to a boolean/enum status at most (see §10).
- [CORRECTED] The typed-confirmation phrase (`DELETE MY ACCOUNT`) IS sent to the
  server as `confirm_text`, and the re-entered `password` is sent in the same body;
  the server enforces both. The password is held only in transient UI/ViewModel state
  for the duration of the dialog, sent over the (dev-only plaintext) channel, then
  cleared on success/dismiss — it is NEVER persisted to DataStore, logs, or analytics
  and is never echoed back. (The cookie session alone is insufficient for this
  endpoint; password re-entry is required.)
- Transport is plaintext HTTP **only** against the known dev host via the existing
  network-security-config exception; production builds MUST require HTTPS (inherited
  config, not changed here).
- On a successful, irreversible *execution* (not request), local session/cookie state
  would be cleared — that teardown is owned by the session layer and only triggers if
  the backend reports the account gone on a subsequent call; this ticket only requests
  and cancels.

## 9. Accessibility & i18n

- All strings in `feature-privacy/src/main/res/values/strings.xml` (no hardcoded text),
  keyed `privacy_deletion_*`. The `DELETE MY ACCOUNT` sentinel is exposed as a
  non-translated string constant referenced in copy so localized instructions say
  'type DELETE MY ACCOUNT'. [CORRECTED] The sentinel must match the server's
  `confirm_text` value exactly and is therefore intentionally NOT localized.
- Destructive buttons use Material 3 `error` color roles AND a text label (never color
  alone) to satisfy non-color signaling.
- `AlertDialog`s set proper title/text semantics; the typed-confirm field has a
  `contentDescription`/label and announces the enabled/disabled state of the confirm
  button via `Modifier.semantics`.
- Touch targets ≥ 48dp; the multi-step flow is fully operable with TalkBack and the
  software keyboard. Dynamic font scaling up to 200% must not clip the warning copy
  (scrollable column).
- RTL-safe layouts via start/end paddings.

## 10. Telemetry & Logging

Emit analytics through the core telemetry interface (no PII):

- `privacy_deletion_request_started` — user entered the confirm flow.
- `privacy_deletion_request_confirmed` — mutation succeeded; props: `had_schedule:Boolean`.
- `privacy_deletion_request_abandoned` — flow dismissed at step `{warning|type|final}`.
- `privacy_deletion_cancelled` — cancel mutation succeeded.
- `privacy_deletion_error` — props: `op:{status|request|cancel}`, `kind:{network|http|parse}`,
  `http_status:Int?`. No identifiers.

Debug logs at `DEBUG` only; status reduced to the enum name. No request ids or
timestamps in any log statement.

## 11. Testing Strategy

**Unit (core-testing + Turbine + MockWebServer):**
- ViewModel: entry fetch → `Ready(Active)`; entry with pending → `Ready(Pending)`.
- Multi-step gating: `ShowFinalDialog` is a no-op unless
  `typedConfirmation == "DELETE MY ACCOUNT"` AND `password` is non-empty;
  case sensitivity asserted (`"delete my account"` does not unlock).
- `ConfirmDelete` calls `requestDeletion()` exactly once; `mutationInFlight` blocks a
  second `ConfirmDelete`.
- Cancel happy path; 404/409 on cancel triggers re-fetch and recoverable message.
- Offline: mutation while `isStale` does not hit MockWebServer and emits an error
  `TransientMessage`.
- DTO mapping: active/pending JSON → domain; null `scheduled_for` handled.
- No-retry guarantee: MockWebServer 500 on POST request results in a single recorded
  request (assert `takeRequest` count).

**Repository:** `ApiResult` mapping for 200/204/401/404/409/network; DataStore
last-known persistence round-trip.

**Compose UI (createAndroidComposeRule):**
- Destructive button disabled until "DELETE MY ACCOUNT" typed AND password entered;
  enabled after both.
- Final `AlertDialog` appears and "Delete my account" invokes the event.
- Pending state shows scheduled date and Cancel; Cancel dialog confirm fires event.
- Stale banner visible and mutation buttons disabled when offline.

**Acceptance mapping:** see §14. Target ≥ 80% line coverage on ViewModel + repository.

## 12. Dependencies & Sequencing

- **Depends on AND-385** (hard): provides `feature-privacy` module, `PrivacyApi`
  scaffold, the requests-list/Privacy entry screen, and the
  `/ui/privacy/account-deletion` endpoint prefix. This ticket extends those artifacts;
  it must not fork a second privacy module or duplicate the list.
- Transitively depends on the core-network session/CSRF/refresh stack and the
  `ApiResult` error mapper (delivered earlier in the milestone chain via AND-027 →
  AND-385).
- **Blocks:** none recorded in the backlog.
- **Sequencing:** land AND-385 first; this ticket adds three service methods, one
  repository, one ViewModel, one screen + nav route, and strings/tests.

## 13. Risks & Open Questions

- **R1 — Endpoint shape (RESOLVED in review 2026-06-06).** Paths, body, and response
  codes are now verified against OpenAPI + the web client (see §16): list at
  `.../requests`, create at `.../request` (body required, **201**), cancel at
  `.../requests/{request_id}/cancel` returning **200 + `AccountDeletionCancelOut`**
  (NOT 204). Residual risk is only future contract drift; re-verify before merge.
- **R2 — Grace window semantics.** Does `scheduled_for` always exist, and is cancel
  allowed up to that instant? *Open question for backend.* UI degrades to "soon" if null.
- **R3 — Step-up auth (PARTIALLY RESOLVED).** The deletion *request* already requires
  password re-entry (`AccountDeletionRequestIn.password`), so basic step-up is in
  scope. Whether the backend additionally demands MFA is unverified; if a 401/403 with
  a challenge body is returned, routing to an MFA flow becomes a follow-up ticket.
- **R4 — Unreliable dev host** may make the GET flaky; bounded backoff + stale state
  mitigate, but manual QA must test offline and timeout paths explicitly.
- **R5 — Localization of the typed sentinel.** The sentinel is a fixed English
  "DELETE MY ACCOUNT" because it must byte-match the server's required `confirm_text`;
  it cannot be localized without a backend change. Confirm copy treatment with product.

## 14. Acceptance Criteria

AC-1. From the Privacy screen, a user can open the account-deletion screen and see the
authoritative status (active vs pending).

AC-2. Requesting deletion REQUIRES passing all three gates (warning → type
`DELETE MY ACCOUNT` case-sensitive AND enter password → final dialog); skipping or
mistyping any gate, or leaving the password empty, leaves the destructive action
unavailable and issues no network call.

AC-3. A confirmed request issues exactly one `POST .../account-deletion/request` with
body `{password, confirm_text, reason?}`, transitions the UI to the pending state
showing the scheduled date / grace-days-remaining, and shows a success snackbar.

AC-4. From the pending state, "Cancel deletion request" → single confirm dialog →
exactly one `POST .../requests/{request_id}/cancel`, returning the UI to active with a
success snackbar.

AC-5. Re-entering the screen reflects server state; if a request already exists, the
request flow is hidden and only Cancel is shown.

AC-6. Offline/timeout shows last-known status with a stale banner; mutations are
disabled and produce a clear error message rather than a silent failure or duplicate
request.

AC-7. 409 (already pending / nothing to cancel) and 404 (request gone) are handled by
re-fetching status and showing an explanatory message; the UI never gets stuck on a
stale button.

AC-8. No PII (request id / timestamps / identifiers) appears in logs or analytics.

## 15. Definition of Done

- All AC met; code merged to `android-port` under
  `com.testlogon.android.feature.privacy.deletion`.
- `PrivacyApi` extended with the three methods; `AccountDeletionRepository` +
  ViewModel + Compose screen + typed nav route implemented; strings externalized.
- Unit, repository, and Compose UI tests pass in CI; ViewModel + repository ≥ 80%
  line coverage; the no-retry-on-mutation assertion is present.
- Endpoint paths/DTOs verified against `/openapi.json` (and any divergence noted in the
  PR description).
- Detekt/ktlint clean; no hardcoded strings; TalkBack pass on the full flow; layout
  verified at 200% font scale and in RTL.
- Manual QA on the dev host covering happy path, cancel, offline, timeout, and the
  422/wrong-password error path.
- PR links AND-385 and references this spec.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI pointers
are `METHOD /path` (from `reference/openapi.index.txt`) and/or
`components.schemas.<Name>` (from `reference/openapi.pretty.json`). Frontend pointers
are repo-relative paths under `reference/`.

1. **Deletion request status is read from a list endpoint, not a singleton GET.**
   VERDICT: Corrected (draft assumed `GET /ui/privacy/account-deletion`).
   SOURCE: `GET /ui/privacy/account-deletion/requests` → `AccountDeletionListOut`;
   `src/api/endpoints/accountDeletion.ts: listAccountDeletions`. No
   `GET /ui/privacy/account-deletion` exists in the index.

2. **Pending request is derived by `status == "pending"` (not `"pending_deletion"`).**
   VERDICT: Corrected.
   SOURCE: `src/pages/settings/AccountDeletionPage.tsx` (`requests.find(r => r.status === "pending")`);
   `AccountDeletionStatus.status: string` in `src/api/types.ts`.

3. **Create-deletion path and method.** `POST /ui/privacy/account-deletion/request`.
   VERDICT: Verified (path/method correct in draft).
   SOURCE: `POST /ui/privacy/account-deletion/request`; `src/api/endpoints/accountDeletion.ts: requestAccountDeletion`.

4. **Create-deletion requires a JSON body with `password` + `confirm_text` (+ optional `reason`).**
   VERDICT: Corrected (draft said "body empty").
   SOURCE: `components.schemas.AccountDeletionRequestIn` (required: `password`,
   `confirm_text`; `password` 1..200, `reason` ≤500); requestBody `required: true` on
   `POST /ui/privacy/account-deletion/request`; `src/api/types.ts: AccountDeletionRequestBody`.

5. **`confirm_text` literal value is `"DELETE MY ACCOUNT"` (not `"DELETE"`).**
   VERDICT: Corrected.
   SOURCE: `src/pages/settings/AccountDeletionPage.tsx` (`const CONFIRM_TEXT = "DELETE MY ACCOUNT"`,
   validity gate `confirmText === CONFIRM_TEXT`).

6. **Create-deletion returns 201 with `AccountDeletionStatusOut`.**
   VERDICT: Corrected (draft said "200/201 with the same `request` shape").
   SOURCE: `POST /ui/privacy/account-deletion/request | resp=201:AccountDeletionStatusOut`.

7. **Cancel path is `.../requests/{request_id}/cancel` (draft omitted `/requests/`).**
   VERDICT: Corrected.
   SOURCE: `POST /ui/privacy/account-deletion/requests/{request_id}/cancel`;
   `src/api/endpoints/accountDeletion.ts: cancelAccountDeletion`.

8. **Cancel returns 200 + `AccountDeletionCancelOut` body, not 204/empty.**
   VERDICT: Corrected (draft said 200-with-`{status,request}` "or 204", typed `Response<Unit>`).
   SOURCE: `...cancel | resp=200:AccountDeletionCancelOut`;
   `components.schemas.AccountDeletionCancelOut` (`ok`, `request_id`, `status`, `cancelled_at`);
   `src/api/types.ts: AccountDeletionCancelResp`.

9. **All timestamps are epoch-second integers, not ISO-8601 strings; field is `created_at` (no `requested_at`).**
   VERDICT: Corrected.
   SOURCE: `components.schemas.AccountDeletionStatusOut` (`created_at`, `scheduled_for`,
   `completed_at` typed `integer`); `AccountDeletionCancelOut.cancelled_at: integer`;
   `src/api/types.ts: AccountDeletionStatus` (`created_at: number`, `scheduled_for?: number`);
   `AccountDeletionPage.tsx` renders `new Date(r.created_at * 1000)`.

10. **Cancel availability is gated by the server `can_cancel` flag.**
    VERDICT: Verified (added to spec).
    SOURCE: `AccountDeletionStatusOut.can_cancel: boolean`;
    `AccountDeletionPage.tsx` (`disabled={!activeRequest.can_cancel || ...}`).

11. **`grace_days_remaining` is provided for the countdown.**
    VERDICT: Verified (added to spec).
    SOURCE: `AccountDeletionStatusOut.grace_days_remaining: integer|null`;
    `AccountDeletionPage.tsx` (`grace-days-remaining`).

12. **Auth: cookie session + `ui_csrf` cookie echoed as `X-CSRF-Token` on mutating calls.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`,
    `credentials: "include"`).

13. **On 401, the client performs one `POST /ui/session/refresh` then retries; on refresh failure it logs out.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`refreshSession()` fetches `/ui/session/refresh`, single-flight
    `refreshPromise`, `logout("session_expired")` on failure); `POST /ui/session/refresh` in the index.

14. **The only error response documented for these endpoints is 422 `HTTPValidationError`.**
    VERDICT: Verified.
    SOURCE: `POST .../request` and `...cancel` index lines show `resp=...;422:HTTPValidationError`
    only; `components.schemas.HTTPValidationError` (`detail: ValidationError[]`).

15. **409 (already pending / nothing to cancel) and 404 (request gone) handling.**
    VERDICT: Unverified-assumption — neither status is declared in OpenAPI for these
    operations. SOURCE: absence in `POST .../request` / `...cancel` index entries (only
    201/200 + 422). Retained as a defensive code path; see Open assumptions.

16. **Wrong-password failure surfaces a generic "check your password" message.**
    VERDICT: Verified (web behavior); exact HTTP status Unverified-assumption.
    SOURCE: `AccountDeletionPage.tsx` (`onError: () => toast.error("Could not schedule
    deletion. Check your password.")`). The web client does not branch on status code.

17. **Multi-step (3-gate) Android confirmation UX.**
    VERDICT: Unverified-assumption (ticket-driven design choice, not a backend contract).
    The web client uses a single dialog (password + phrase + reason). The native 3-gate
    flow is a stricter superset and is acceptable as long as the same body is sent.
    SOURCE: ticket AND-386 "strong multi-step confirmation"; `AccountDeletionPage.tsx`
    (single `Dialog`).

18. **Dev host plaintext HTTP + ~20s timeout + bounded backoff on idempotent GETs.**
    VERDICT: Unverified-assumption (environment/infra detail, not in the provided sources).
    SOURCE: §2/§7 of this spec; no OpenAPI/frontend artifact pins the host or timeouts.
    Treat as project convention inherited from core-network (AND-027/AND-385).

19. **Framework choices (Compose, Hilt, Retrofit/Moshi, Navigation-Compose typed routes,
    DataStore).** VERDICT: Unverified-assumption (no Android sources in the reference set);
    standard AndroidX. SOURCE (framework ref):
    https://developer.android.com/develop/ui/compose ,
    https://developer.android.com/training/data-storage/datastore ,
    https://developer.android.com/guide/navigation/design/type-safety .

### Corrections made

- **C1** Replaced the nonexistent `GET /ui/privacy/account-deletion` with the real
  `GET .../requests` (`AccountDeletionListOut`) + derive-pending logic, and added the
  optional `GET .../requests/{request_id}` single-record fetch. (§4, §5)
- **C2** Status string `pending_deletion`/`active` → server uses `"pending"` (others:
  `completed`, `cancelled`); "active" is the empty/no-pending state. (§4, §5, §6)
- **C3** Deletion-request body is required (`password`, `confirm_text`, optional
  `reason`) — was "body empty"; added password collection to UX, state, repo, and DTOs.
  (§3 FR-2, §4, §5, §8)
- **C4** Typed sentinel `DELETE` → `DELETE MY ACCOUNT`. (§3, §4, §8, §9, §11, §13, §14)
- **C5** Create returns 201 (not 200/201); cancel path gains `/requests/` and returns
  200 + `AccountDeletionCancelOut` (not 204/`Unit`). (§4, §5)
- **C6** Timestamps are epoch-second integers (`created_at`, not `requested_at`); fixed
  domain model, DTOs, and Instant conversion. (§4, §5, §6)
- **C7** Added `can_cancel` and `grace_days_remaining` to the model/UX. (§3 FR-3, §4, §5)
- **C8** Security: corrected the false "body empty / does NOT cache password" claim;
  documented transient password handling and no-log rules. (§8, §10)
- **C9** Reframed 409/404 as undocumented defensive cases; promoted 422 as the
  documented error path. (§5, §7, §13 R1, §15)

### Open assumptions

- **OA1 (claims 15, 16):** 409/404 on the mutations and the exact HTTP status for a
  wrong password are NOT in the OpenAPI (only 201/200 + 422). The defensive handling is
  retained but must be confirmed against the live dev host; if only 422 occurs, the
  409/404 branches are dead code and should be dropped.
- **OA2 (claim 17):** The 3-gate native UX is a product/ticket choice; confirm with
  product that it is desired over mirroring the web's single dialog.
- **OA3 (claim 18):** Dev-host URL, plaintext-HTTP exception, and timeout/backoff
  numbers come from project convention, not the provided sources — verify against
  core-network config (AND-027/AND-385).
- **OA4 (claim 19):** All Android framework/library versions are unverifiable from the
  reference set (web + OpenAPI only); they inherit from the module scaffold of AND-385.
- **OA5:** Whether the backend additionally requires MFA/step-up beyond password
  (§13 R3) is unknown; no challenge schema is present in the sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit / Robolectric (local, no device); **emu35** = headless
emulator AVD `test35` (x86_64, Android 15 / API 35); **A15** = physical Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Contract tests
use OkHttp MockWebServer. "Traces" link to §14 acceptance criteria.

- **TC-AND-386-01** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `200 AccountDeletionListOut` with one entry
  `{status:"pending", created_at, scheduled_for, grace_days_remaining:14, can_cancel:true}`.
  Steps: call `repo.getStatus()`. Expected: maps to `DeletionStatus.Pending` with
  `createdAt`/`scheduledFor` from epoch-SECOND ints, `graceDaysRemaining==14`,
  `canCancel==true`; recorded request is `GET /ui/privacy/account-deletion/requests`.
  Traces: AC-1, AC-5.

- **TC-AND-386-02** — Type: unit (DTO mapping). Target: JVM.
  Preconditions: empty list JSON `{"requests":[],"total":0}` and a one-pending list JSON.
  Steps: deserialize via Moshi + map. Expected: empty → `DeletionStatus.Active`;
  pending entry → `Pending`; `scheduled_for:null` maps to `scheduledFor==null` ("soon").
  Traces: AC-1.

- **TC-AND-386-03** — Type: unit (ViewModel gating). Target: JVM + Turbine.
  Preconditions: `Ready(Active)`. Steps: `StartRequest` → `AdvanceFromWarning` →
  `TypedConfirmationChanged("delete my account")` (wrong case), empty password →
  `ShowFinalDialog`. Expected: `ShowFinalDialog` is a no-op (confirm button disabled);
  no MockWebServer request. Then set `TypedConfirmationChanged("DELETE MY ACCOUNT")` +
  `PasswordChanged("pw")` → `ShowFinalDialog` advances to `FinalDialog`.
  Traces: AC-2.

- **TC-AND-386-04** — Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `201 AccountDeletionStatusOut(status:"pending")`.
  Steps: drive through all gates then `ConfirmDelete`. Expected: exactly ONE recorded
  `POST /ui/privacy/account-deletion/request`; request body JSON ==
  `{"password":"pw","confirm_text":"DELETE MY ACCOUNT","reason":...}`; header
  `X-CSRF-Token` present; state becomes `Ready(Pending)` with a success `TransientMessage`.
  Traces: AC-2, AC-3.

- **TC-AND-386-05** — Type: unit (double-submit guard). Target: JVM.
  Preconditions: in-flight mutation (MockWebServer delays response). Steps: dispatch
  `ConfirmDelete` twice. Expected: `mutationInFlight` blocks the second; MockWebServer
  records exactly ONE POST. Traces: AC-3.

- **TC-AND-386-06** — Type: contract/MockWebServer (no-retry guarantee). Target: JVM.
  Preconditions: enqueue `422 HTTPValidationError` (e.g., wrong password) for the POST.
  Steps: `ConfirmDelete`. Expected: exactly ONE recorded POST (NO retry on mutation);
  `TransientMessage(isError=true)` shown; status not flipped to pending. Traces: AC-3.

- **TC-AND-386-07** — Type: contract/MockWebServer (cancel happy path). Target: JVM.
  Preconditions: `Ready(Pending requestId="del_x", canCancel=true)`; enqueue
  `200 AccountDeletionCancelOut{ok:true,status:"cancelled",cancelled_at}` then a
  follow-up `200` list with no pending entry. Steps: `StartCancel` → `ConfirmCancel`.
  Expected: exactly ONE `POST /ui/privacy/account-deletion/requests/del_x/cancel`
  with `X-CSRF-Token`; UI re-fetches and returns to `Active` with success snackbar.
  Traces: AC-4.

- **TC-AND-386-08** — Type: contract/MockWebServer (recoverable cancel error). Target: JVM.
  Preconditions: enqueue `404` (or `409`) for cancel, then `200` list. Steps:
  `ConfirmCancel`. Expected: single POST, error swallowed → status re-fetched →
  explanatory message; UI never stuck on a stale Cancel button. (Covers the
  undocumented-but-defensive path, OA1.) Traces: AC-7.

- **TC-AND-386-09** — Type: contract/MockWebServer (offline/flaky host). Target: JVM.
  Preconditions: MockWebServer returns a network failure / socket close on
  `getStatus()` after a prior good fetch cached last-known. Steps: enter screen offline,
  then attempt `ConfirmDelete`. Expected: `Ready(isStale=true)` over last-known status;
  mutation event does NOT hit the network (zero recorded POSTs) and emits
  `TransientMessage(isError=true,"Can't reach server …")`. Traces: AC-6.

- **TC-AND-386-10** — Type: contract/MockWebServer (401 refresh). Target: JVM.
  Preconditions: enqueue `401` for `getStatus()`, then `200` for
  `POST /ui/session/refresh`, then `200` list. Steps: `Refresh`. Expected: exactly one
  refresh call to `/ui/session/refresh`, original request retried once, state resolves;
  if refresh returns 401, state becomes `Error(retryable=false)`. Traces: AC-1, AC-6.

- **TC-AND-386-11** — Type: Compose-UI. Target: emu35 (createAndroidComposeRule).
  Preconditions: `Ready(Active)` fake VM. Steps: open confirm flow; type
  `"DELETE MY ACCOUNT"` and a password. Expected: destructive button disabled until
  BOTH the exact phrase and a non-empty password are present; final `AlertDialog`
  appears and "Delete my account" emits `ConfirmDelete`. Traces: AC-2, AC-3.

- **TC-AND-386-12** — Type: Compose-UI. Target: emu35.
  Preconditions: `Ready(Pending, canCancel=true, scheduledFor set, grace=14)`.
  Steps: render. Expected: scheduled date + "14 days remaining" shown; Cancel CTA
  visible; with `canCancel=false` the Cancel CTA is disabled; Cancel dialog confirm
  emits `ConfirmCancel`. Also assert request-flow CTA is hidden when pending.
  Traces: AC-4, AC-5.

- **TC-AND-386-13** — Type: Compose-UI (offline state + a11y). Target: emu35.
  Preconditions: `Ready(isStale=true)`. Steps: render; run accessibility assertions.
  Expected: stale banner visible; both destructive buttons disabled; destructive
  controls expose a text label (non-color signaling) and a `contentDescription`; the
  typed-confirm field announces enabled/disabled confirm state; touch targets ≥48dp;
  copy remains scrollable/unclipped at 200% font scale. Traces: AC-6, AC-2.

- **TC-AND-386-14** — Type: unit (no-PII telemetry/logging). Target: JVM (Robolectric
  log capture). Preconditions: fakes for telemetry + logger. Steps: run request +
  cancel + error flows. Expected: no `password`, `request_id`, `created_at`,
  `scheduled_for`, `cancelled_at`, or `user_sub` appears in any emitted log line or
  analytics prop; analytics carry only enum/boolean fields (`op`, `kind`,
  `http_status`, `had_schedule`). Traces: AC-8.

- **TC-AND-386-15** — Type: instrumented/e2e (manual-assisted). Target: **A15
  (physical device, REQUIRED)**. Rationale: validates real plaintext-HTTP transport to
  the flaky dev host, real cookie jar + `X-CSRF-Token`, real `/ui/session/refresh` on
  401, and arm64-v8a / API-34 behavior that the x86_64 / API-35 emulator does not
  exercise. Preconditions: signed-in session against dev host
  `http://18.222.237.167:8000`; adb to serial R5CX821TA9R. Steps: full happy path
  (request with real password → pending → cancel), then toggle airplane mode to verify
  the stale/offline path and timeout/backoff against the live host. Expected: behavior
  matches AC-1..AC-7 on real hardware/network; no crash on ABI/API differences.
  Traces: AC-1, AC-3, AC-4, AC-6, AC-7.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-10, TC-15 |
| AC-2 | TC-03, TC-04, TC-11, TC-13 |
| AC-3 | TC-04, TC-05, TC-06, TC-11, TC-15 |
| AC-4 | TC-07, TC-12, TC-15 |
| AC-5 | TC-01, TC-12 |
| AC-6 | TC-09, TC-10, TC-13, TC-15 |
| AC-7 | TC-08, TC-15 |
| AC-8 | TC-14 |
