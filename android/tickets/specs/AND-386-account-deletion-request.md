---
id: AND-386
title: Account deletion request
milestone: M8
epic: E50
priority: P1
size: M
status: draft
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
- **Web reference:** `frontend/src/api/endpoints/*.ts` (privacy/account-deletion
  endpoints), `frontend/src/api/types.ts` for request/response shapes.
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
  2. A typed-confirmation step: the user must type the exact word **DELETE**
     (locale-independent, case-sensitive sentinel) into a text field; the destructive
     button stays disabled until the input matches.
  3. A final Material 3 `AlertDialog` ("This cannot be undone") with the destructive
     action labeled "Delete my account" and a neutral "Cancel".
Only after all three does the app issue the request mutation.

FR-3. **Pending state.** After a successful request the screen switches to a
"Deletion scheduled" state showing the scheduled execution date (`scheduled_for`) and
a "Cancel deletion request" action.

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
        val typedConfirmation: String = "",     // for the "DELETE" gate
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
        val requestedAt: Instant,
        val scheduledFor: Instant?
    ) : DeletionStatus
}

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
    data object ShowFinalDialog : AccountDeletionEvent         // enabled only if text == "DELETE"
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
    suspend fun getStatus(): ApiResult<DeletionStatus>
    suspend fun requestDeletion(): ApiResult<DeletionStatus.Pending>
    suspend fun cancelDeletion(requestId: String): ApiResult<Unit>
}
```

The Retrofit service extends the AND-385 `PrivacyApi` (same module):

```kotlin
interface PrivacyApi {
    // ...AND-385 export + requests-list methods...
    @GET("ui/privacy/account-deletion")
    suspend fun getDeletionStatus(): Response<DeletionStatusDto>

    @POST("ui/privacy/account-deletion/request")
    suspend fun requestDeletion(): Response<DeletionStatusDto>

    @POST("ui/privacy/account-deletion/{requestId}/cancel")
    suspend fun cancelDeletion(@Path("requestId") requestId: String): Response<Unit>
}
```

> Endpoint paths MUST be reconciled against `/openapi.json` and
> `frontend/src/api/endpoints` before merge; AND-385 establishes the
> `/ui/privacy/account-deletion` prefix, and this ticket follows it. If the live
> contract differs, update the DTOs/paths here and note it in the PR.

**Navigation.** Add a typed route to the privacy nav graph:

```kotlin
@Serializable data object AccountDeletionRoute
fun NavGraphBuilder.accountDeletion(onBack: () -> Unit) {
    composable<AccountDeletionRoute> { AccountDeletionScreen(onBack = onBack) }
}
```

The Composable renders one of: `Loading`, the request-CTA + multi-step confirm
overlay, or the pending/cancel surface. The typed-confirm gate uses a Material 3
`OutlinedTextField`; the destructive button derives `enabled` from
`state.typedConfirmation == DELETE_SENTINEL && !state.mutationInFlight`.

## 5. API Contract

**GET `/ui/privacy/account-deletion`** — current deletion state (idempotent; eligible
for bounded backoff retry).

```json
{
  "status": "active",
  "request": null
}
```
or, when pending:
```json
{
  "status": "pending_deletion",
  "request": {
    "request_id": "del_01J9...",
    "requested_at": "2026-06-05T14:02:11Z",
    "scheduled_for": "2026-06-19T14:02:11Z"
  }
}
```

**POST `/ui/privacy/account-deletion/request`** — body empty; requires
`X-CSRF-Token`. Returns 200/201 with the same `request` shape (status
`pending_deletion`). Treated as NON-idempotent → no automatic retry.

**POST `/ui/privacy/account-deletion/{request_id}/cancel`** — requires
`X-CSRF-Token`. Returns 200 with `{ "status": "active", "request": null }` (or 204).
Non-idempotent → no automatic retry; the client guards against double submit.

DTOs (Moshi):

```kotlin
@JsonClass(generateAdapter = true)
data class DeletionStatusDto(
    @Json(name = "status") val status: String,        // "active" | "pending_deletion"
    @Json(name = "request") val request: DeletionRequestDto?
)
@JsonClass(generateAdapter = true)
data class DeletionRequestDto(
    @Json(name = "request_id") val requestId: String,
    @Json(name = "requested_at") val requestedAt: String,
    @Json(name = "scheduled_for") val scheduledFor: String?
)
```

FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`) is handled by the
shared `ApiResult` error mapper in core-network; this ticket adds no bespoke parsing.
Relevant statuses: **409** (already pending / nothing to cancel) → mapped to a
friendly inline message and a forced status refresh; **404** on cancel (request gone)
→ refresh and show "Request already resolved".

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
- **Timestamps:** parsed from ISO-8601 to `java.time.Instant`; rendered with the
  locale/zone formatter from core-ui. `scheduled_for == null` renders "soon".

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

- All three mutating calls ride the persistent cookie jar + `X-CSRF-Token` header; the
  request body for the deletion mutation is empty (no credentials echoed).
- **No PII in logs.** Do not log `request_id`, `requested_at`, `scheduled_for`, or any
  account identifier at INFO; redact to a boolean status at most (see §10).
- The typed-confirmation sentinel (`DELETE`) is a literal UI guard, never sent to the
  server; the server enforces its own authorization. The app treats the cookie session
  as sufficient and does NOT cache the user's password to re-confirm.
- Transport is plaintext HTTP **only** against the known dev host via the existing
  network-security-config exception; production builds MUST require HTTPS (inherited
  config, not changed here).
- On a successful, irreversible *execution* (not request), local session/cookie state
  would be cleared — that teardown is owned by the session layer and only triggers if
  the backend reports the account gone on a subsequent call; this ticket only requests
  and cancels.

## 9. Accessibility & i18n

- All strings in `feature-privacy/src/main/res/values/strings.xml` (no hardcoded text),
  keyed `privacy_deletion_*`. The `DELETE` sentinel is exposed as a non-translated
  string constant referenced in copy so localized instructions say "type DELETE".
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
- Multi-step gating: `ShowFinalDialog` is a no-op unless `typedConfirmation == "DELETE"`;
  case sensitivity asserted (`"delete"` does not unlock).
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
- Destructive button disabled until "DELETE" typed; enabled after.
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

- **R1 — Endpoint shape unverified.** The exact `request`/`cancel` paths and whether
  cancel returns 200-with-body vs 204 must be confirmed against `/openapi.json`. *Mitigation:*
  DTOs and `Response<Unit>` tolerate 204; reconcile in PR.
- **R2 — Grace window semantics.** Does `scheduled_for` always exist, and is cancel
  allowed up to that instant? *Open question for backend.* UI degrades to "soon" if null.
- **R3 — Step-up auth.** Backend may demand re-auth/MFA for deletion; current design
  relies on the cookie session only. If a 401/403 with a challenge body is returned,
  routing to the MFA flow becomes a follow-up ticket.
- **R4 — Unreliable dev host** may make the GET flaky; bounded backoff + stale state
  mitigate, but manual QA must test offline and timeout paths explicitly.
- **R5 — Localization of the typed sentinel.** Using a fixed English "DELETE" across
  locales is intentional for testability; confirm with product that this is acceptable.

## 14. Acceptance Criteria

AC-1. From the Privacy screen, a user can open the account-deletion screen and see the
authoritative status (active vs pending).

AC-2. Requesting deletion REQUIRES passing all three gates (warning → type `DELETE`
case-sensitive → final dialog); skipping or mistyping any gate leaves the destructive
action unavailable and issues no network call.

AC-3. A confirmed request issues exactly one `POST .../account-deletion/request`,
transitions the UI to the pending state showing the scheduled date, and shows a success
snackbar.

AC-4. From the pending state, "Cancel deletion request" → single confirm dialog →
exactly one `POST .../{request_id}/cancel`, returning the UI to active with a success
snackbar.

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
- Manual QA on the dev host covering happy path, cancel, offline, timeout, and 409/404.
- PR links AND-385 and references this spec.
