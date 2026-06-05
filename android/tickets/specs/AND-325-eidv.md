---
id: AND-325
title: eIDV
milestone: M7
epic: E42
priority: P2
size: M
status: draft
depends_on: [AND-319]
blocks: []
---

# AND-325 — eIDV

## 1. Overview & Goal

Implement the electronic identity verification (eIDV) flow inside the KYC feature
module. eIDV is a non-document, data-only verification path: the user supplies (or
confirms) personal identity attributes — legal name, date of birth, residential
address, and optionally a government identifier — which are submitted to the
backend's third-party identity bureau integration (`kycEidv`). The bureau returns
a pass / fail / referred decision asynchronously, so the client must submit a
verification request, persist the returned case/verification id, and then poll (or
re-fetch) status until the bureau resolves.

The scope of this ticket is bounded by its acceptance bullet: **eIDV submits +
status returns.** Concretely the user can open the eIDV screen, review/confirm the
prefilled identity attributes, submit, and then observe a live status that
transitions from `pending` to a terminal outcome (`approved`, `declined`,
`referred`, or `expired`). This ticket does **not** cover document capture, ID
scanning, facial comparison, liveness, residency proof, or screening — those are
owned by AND-321/322/323/324/326/328 respectively. eIDV is one selectable
requirement among several surfaced by the tier-requirements screen (AND-320); this
ticket only wires the eIDV requirement type.

Goal: a user whose target KYC tier requires `kyc_eidv` can complete that single
requirement end-to-end on device, with the resulting status reflected back into the
requirements list so AND-320 can re-evaluate tier eligibility.

## 2. Context & References

- Feature module: `feature-kyc` (created by AND-319/AND-320). This ticket adds the
  `eidv` sub-package: `com.testlogon.android.feature.kyc.eidv`.
- DTOs and the `KycApi` Retrofit interface are owned by **AND-319 — KYC API + DTOs**
  (`/v1/kyc/*` DTOs: tiers/me, requirements, evaluate, cases). This ticket extends
  that surface with the eIDV-specific endpoints and DTOs, reusing AND-319's Moshi
  setup, `ApiResult<T>` wrapping, and FastAPI `detail` error mapping.
- Tier/requirements host: **AND-320 — Tier status & requirements**. The eIDV screen
  is launched from a requirement row whose type is `eidv`; on completion this ticket
  triggers AND-320's `evaluate` re-fetch.
- Networking conventions: `core-network` (Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15),
  cookie-based session with `X-CSRF-Token` echo, single `POST /ui/session/refresh`
  retry on 401, persistent cookie jar. Dev backend `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable — 20s timeouts, bounded backoff retry for idempotent
  GETs only.
- Web reference: `frontend/src/api/endpoints/kyc*.ts` (eIDV module) and shared types
  in `frontend/src/api/types.ts`. The OpenAPI document at `/openapi.json` is the
  authoritative source for exact field names; the JSON shapes below are derived from
  the KYC family conventions and MUST be reconciled against `/openapi.json` during
  implementation (see Open Questions).
- Stack baseline: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  single-Activity Navigation-Compose, minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

FR-1. The eIDV screen displays the identity attributes required for verification,
prefilled from `GET /ui/me` / KYC profile where available (legal first/last name,
date of birth, address lines, country, optional national-id type + value).

FR-2. The user can edit each attribute before submitting. Client-side validation
runs on every field: required fields non-empty, DOB a valid past date (age ≥ 18 by
default, configurable via requirement metadata), country an ISO-3166 alpha-2 code.

FR-3. A "Verify identity" button is enabled only when validation passes and no
submission is in flight. Tapping it issues the eIDV submit request (FR section 5).

FR-4. On successful submit the screen transitions to a status view showing the
current `EidvStatus`. While status is `pending`/`processing` the client polls
status until a terminal state or the poll budget is exhausted.

FR-5. Terminal states render distinct UI:
- `approved`: success state, "Continue" returns to requirements and triggers
  AND-320 re-evaluate.
- `declined`: failure state with bureau reason (if provided) and, when
  `retryable=true`, a "Try again" action that resets to the form.
- `referred`: neutral "under manual review" state; the requirement is shown as
  in-progress in AND-320.
- `expired`: the verification id is no longer valid; user restarts.

FR-6. If an eIDV verification already exists for the user (in-flight or terminal),
opening the screen resumes it: the client fetches latest status first and skips the
form when a non-expired verification is active.

FR-7. The screen survives configuration changes (rotation, process death) — the
active `verificationId` and form draft persist via `SavedStateHandle`.

FR-8. Offline / unreachable backend yields an explicit error state with retry; no
silent failures. Submit (a POST) is never auto-retried.

## 4. Technical Design

Single-Activity Navigation-Compose route registered in `feature-kyc` navigation:

```kotlin
const val EIDV_ROUTE = "kyc/eidv"

fun NavGraphBuilder.eidvScreen(onDone: (EidvOutcome) -> Unit) {
    composable(EIDV_ROUTE) { EidvRoute(onDone = onDone) }
}
```

MVVM with a `StateFlow<EidvUiState>` per project convention:

```kotlin
@HiltViewModel
class EidvViewModel @Inject constructor(
    private val repo: EidvRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<EidvUiState> // .stateIn(viewModelScope, WhileSubscribed(5_000), Loading)

    fun onFieldChanged(field: EidvField, value: String)
    fun submit()                 // POST; single attempt, no auto-retry
    fun refreshStatus()          // idempotent GET; bounded backoff
    fun retryAfterDecline()      // resets to Form if retryable
}
```

```kotlin
sealed interface EidvUiState {
    data object Loading : EidvUiState
    data class Form(
        val draft: EidvDraft,
        val errors: Map<EidvField, String> = emptyMap(),
        val submitting: Boolean = false,
        val canSubmit: Boolean = false,
    ) : EidvUiState
    data class Status(
        val verificationId: String,
        val status: EidvStatus,
        val reason: String? = null,
        val retryable: Boolean = false,
        val polling: Boolean = false,
    ) : EidvUiState
    data class Error(val message: String, val retry: Retry) : EidvUiState {
        enum class Retry { LOAD, STATUS }
    }
}

enum class EidvStatus { PENDING, PROCESSING, APPROVED, DECLINED, REFERRED, EXPIRED }

enum class EidvField { FIRST_NAME, LAST_NAME, DOB, LINE1, LINE2, CITY, REGION, POSTAL, COUNTRY, NATIONAL_ID }
```

Repository (in `feature-kyc`, depends on `KycApi` from AND-319):

```kotlin
interface EidvRepository {
    suspend fun loadProfile(): ApiResult<EidvDraft>
    suspend fun latestVerification(): ApiResult<EidvVerification?>
    suspend fun submit(draft: EidvDraft): ApiResult<EidvVerification>
    suspend fun status(verificationId: String): ApiResult<EidvVerification>
}
```

Polling: `refreshStatus()` runs a coroutine that re-calls `status()` with bounded
exponential backoff (2s, 4s, 8s, capped 8s) for up to ~90s wall-clock while the
state is non-terminal; each call is an idempotent GET so it is eligible for
`core-network`'s GET-retry policy. Polling is cancelled when the screen leaves
composition (tied to `viewModelScope`) and resumed on `refreshStatus()`/return.

The draft and `verificationId` are mirrored into `SavedStateHandle` keys
`eidv_draft` (a `@Parcelize` `EidvDraft`) and `eidv_verification_id` for
process-death survival (FR-7).

Compose layer: `EidvRoute(onDone)` collects `uiState` with
`collectAsStateWithLifecycle()` and renders `EidvFormScreen`, `EidvStatusScreen`, or
`EidvErrorScreen` from `core-ui` building blocks. Form fields use Material 3
`OutlinedTextField`; DOB uses `DatePickerDialog`; country uses an exposed dropdown.

## 5. API Contract

All paths are under `/v1/kyc/`. Exact field names MUST be confirmed against
`/openapi.json`; shapes below follow the KYC family conventions.

Submit eIDV (POST, not retried):
```
POST /v1/kyc/eidv/verify
X-CSRF-Token: <ui_csrf cookie value>
Content-Type: application/json

{
  "first_name": "Ada",
  "last_name": "Lovelace",
  "date_of_birth": "1990-12-10",
  "address": {
    "line1": "12 Analytical Way",
    "line2": null,
    "city": "London",
    "region": null,
    "postal_code": "EC1A 1BB",
    "country": "GB"
  },
  "national_id": { "type": "passport", "value": "123456789" }   // optional
}
```
Response `200`:
```json
{
  "verification_id": "eidv_01HQ...",
  "status": "pending",
  "reason": null,
  "retryable": false,
  "created_at": "2026-06-05T12:00:00Z",
  "expires_at": "2026-06-05T12:30:00Z"
}
```

Get eIDV status (GET, idempotent, retryable):
```
GET /v1/kyc/eidv/{verification_id}
```
Response `200`: same shape as submit, with `status` advancing to `approved` /
`declined` / `referred` / `expired` and `reason` populated on `declined`.

Latest verification for current user (GET, idempotent):
```
GET /v1/kyc/eidv/me
```
Response `200`: `EidvVerification` or `204`/`{ "verification": null }` when none
exists. Used by FR-6 resume logic.

Moshi DTOs (added alongside AND-319's KYC DTOs):
```kotlin
@JsonClass(generateAdapter = true)
data class EidvVerifyRequest(
    @Json(name = "first_name") val firstName: String,
    @Json(name = "last_name") val lastName: String,
    @Json(name = "date_of_birth") val dateOfBirth: String,   // ISO-8601 date
    val address: EidvAddressDto,
    @Json(name = "national_id") val nationalId: EidvNationalIdDto? = null,
)

@JsonClass(generateAdapter = true)
data class EidvVerificationDto(
    @Json(name = "verification_id") val verificationId: String,
    val status: String,
    val reason: String? = null,
    val retryable: Boolean = false,
    @Json(name = "expires_at") val expiresAt: String? = null,
)
```

Retrofit (extends `KycApi`):
```kotlin
@POST("v1/kyc/eidv/verify")
suspend fun submitEidv(@Body body: EidvVerifyRequest): Response<EidvVerificationDto>

@GET("v1/kyc/eidv/{id}")
suspend fun eidvStatus(@Path("id") id: String): Response<EidvVerificationDto>

@GET("v1/kyc/eidv/me")
suspend fun latestEidv(): Response<EidvVerificationDto?>
```

`status` is mapped to `EidvStatus` via a tolerant `when` that defaults unknown
strings to `PROCESSING` (forward-compatibility) and logs the unknown value.

## 6. Data & State Management

- No Room persistence: eIDV verifications are short-lived and authoritative on the
  server. The only persisted client state is the in-progress `verificationId` and
  form `draft` in `SavedStateHandle` (FR-7). No DataStore key is required.
- `EidvUiState` is the single source of truth; the ViewModel reduces API results
  into it. `Form.canSubmit` is recomputed on each `onFieldChanged` from the
  validator output (`errors.isEmpty() && !submitting`).
- Polling state (`Status.polling`) is derived from the active poll coroutine job;
  starting `refreshStatus()` sets it true, terminal status or budget exhaustion sets
  it false.
- On `approved`/`referred`, the ViewModel emits an `EidvOutcome` (one-shot via
  `Channel`/`SharedFlow`) that `EidvRoute` forwards to `onDone`, which the KYC
  navigator uses to pop back and invoke AND-320's evaluate re-fetch. The
  requirements list is not owned here; this ticket only signals completion.
- DOB and address are validated locally before submit to avoid round-trips to the
  unreliable backend.

## 7. Error Handling & Resilience

- All calls return `ApiResult<T>` (from `core-network`); FastAPI `detail` is mapped
  (string | `[{msg}]` | `{code,...}`) to a user-facing message via AND-319's shared
  error mapper.
- Timeouts: rely on the global 20s OkHttp timeout. Submit (`POST`) failures surface
  as a `Form` with a non-blocking error banner and the button re-enabled — **never
  auto-retried** (non-idempotent).
- Status `GET` failures during polling do not crash the poll loop: a single failed
  poll is retried per the bounded GET backoff; if the whole budget (~90s) elapses
  without resolution, the UI shows "Still processing — check back later" with a
  manual "Refresh status" action (keeps `verificationId`).
- `401`: handled transparently by `core-network` (single `POST /ui/session/refresh`
  then retry). A second 401 surfaces as a re-auth required error routed to the
  session gate; the eIDV draft is preserved.
- `409`/duplicate-active-verification on submit: treat as resume — fetch
  `GET /v1/kyc/eidv/me` and move to `Status`.
- `expired`: drop the stored `verificationId`, return to `Form`.
- Offline (no connectivity): `Error(message, Retry.LOAD)` with retry; no partial
  submission is assumed to have succeeded — on retry the client first calls
  `latestEidv()` to detect a verification that may have been created server-side.

## 8. Security & Privacy

- eIDV submits highly sensitive PII (legal name, DOB, address, national id). The PII
  is held only in memory and `SavedStateHandle` (encrypted at rest by the OS on
  modern devices); it is **not** written to Room, DataStore, or logs.
- `national_id.value` is masked in any telemetry/log surface (only `type` and a
  boolean `present` are ever recorded) and is masked in the UI field after entry
  except for the last 4 characters.
- All requests carry the session cookies + `X-CSRF-Token` header per project auth;
  the persistent cookie jar is reused. The mutating `POST /v1/kyc/eidv/verify` MUST
  include the CSRF header.
- The dev backend is plaintext HTTP — flagged as a known dev-only risk; production
  must be HTTPS (network-security-config disallows cleartext outside the dev host).
  No eIDV PII should be sent to the plaintext dev host with real personal data.
- `SavedStateHandle` PII is cleared when the flow reaches a terminal state or the
  user navigates away after success.

## 9. Accessibility & i18n

- All form fields have `contentDescription`/labels; error text is associated via
  Compose semantics (`error = true` + supporting text) so TalkBack announces
  validation failures.
- Status transitions announce via `liveRegion = LiveRegionMode.Polite` so screen
  readers hear "Verification approved/declined/under review".
- Touch targets ≥ 48dp; supports dynamic font scaling and dark theme via Material 3.
- All strings live in `feature-kyc` `strings.xml`; no hardcoded UI text. Bureau
  `reason` strings come from the server and are displayed as-is (already localized by
  backend i18n per `/v1/kyc/i18n`); a generic fallback string is shown if `reason`
  is null. DOB and dates render via locale-aware formatters; country names via
  `Locale.getDisplayCountry`.

## 10. Telemetry & Logging

Events (via the app analytics facade; no PII in payloads):
- `kyc_eidv_opened` { resumed: Boolean }
- `kyc_eidv_submitted` { national_id_present: Boolean }
- `kyc_eidv_result` { status: String, retryable: Boolean, elapsed_ms: Long }
- `kyc_eidv_error` { stage: "load"|"submit"|"status", code: String? }

Logging: debug-level only, via `core` logger; request/response bodies for eIDV are
**redacted** (the OkHttp logging interceptor must exclude `/v1/kyc/eidv/*` bodies or
mask them). `verification_id` may be logged; PII fields must not be.

## 11. Testing Strategy

Unit (JUnit + Turbine + coroutines-test, `core-testing`):
- Validator: required-field, DOB-in-past/age, ISO country-code cases.
- `EidvViewModel` reduces submit success → `Status(pending)`; poll advances
  `pending → processing → approved` and emits `EidvOutcome.Approved`.
- `declined(retryable=true)` → `retryAfterDecline()` returns to `Form` preserving
  draft; `retryable=false` shows terminal failure.
- Poll budget exhaustion → manual-refresh status, polling stops, no crash.
- Submit failure does not auto-retry; button re-enabled.
- Resume path: `latestEidv()` returns active verification → screen opens in
  `Status`, form skipped.

DTO mapping (extends AND-319 tests): JSON fixtures for submit and each status value
deserialize correctly; unknown status string defaults to `PROCESSING`.

Network: MockWebServer covers 200/401-then-refresh/409-duplicate/timeout for submit
and status.

Compose UI tests: form validation surfaces errors; status screens render per state;
"Verify identity" disabled until valid. **Acceptance test:** scripted MockWebServer
returns `pending` on submit then `approved` on the next status poll, asserting the
UI reaches the approved state and `onDone(Approved)` fires — proving "eIDV submits +
status returns."

## 12. Dependencies & Sequencing

- **Depends on AND-319** (KYC API + DTOs): provides `KycApi`, base KYC DTOs, the
  Moshi/`ApiResult` plumbing, and the FastAPI error mapper this ticket extends. Hard
  blocker.
- **Integrates with AND-320** (Tier status & requirements): the eIDV requirement row
  launches `EIDV_ROUTE`; on success this ticket signals AND-320 to re-run evaluate.
  Soft dependency — eIDV can be developed in parallel against a stub launcher but the
  end-to-end requirement wiring needs AND-320.
- Transitively relies on AND-027 (network/session foundation, via AND-319) and the
  `feature-kyc` module scaffolding.
- Independent of the camera/vendor-SDK KYC tickets (AND-321/322/323/324/326) — eIDV
  is data-only and ships without CameraX.
- Sequencing: land after AND-319; can merge before or alongside AND-320 behind the
  requirement-type switch.

## 13. Risks & Open Questions

- OQ-1: Exact eIDV endpoint paths and request/response field names — confirm against
  `/openapi.json` and `frontend/src/api/endpoints/kyc*.ts`. Shapes here are derived
  from KYC conventions and may need renaming.
- OQ-2: Is eIDV synchronous (decision in the submit response) or asynchronous
  (poll)? This spec assumes async-with-poll and degrades gracefully if the submit
  response already carries a terminal status (poll loop exits immediately).
- OQ-3: Whether a webhook/push or only polling is available for status; if push
  exists later, the poll loop becomes a fallback.
- OQ-4: Required vs optional attributes and which (if any) national-id types the
  bureau accepts per country — drives validation rules.
- Risk: unreliable plaintext dev host makes manual verification flaky; mitigate with
  MockWebServer-based tests as the source of truth for acceptance.
- Risk: PII handling/compliance correctness — mitigated by no-persist/no-log policy
  (section 8) and security review before merge.

## 14. Acceptance Criteria

AC-1. From a KYC requirement of type `eidv`, the user opens the eIDV screen with
identity attributes prefilled and editable. (FR-1, FR-2)

AC-2. With valid input, tapping "Verify identity" issues
`POST /v1/kyc/eidv/verify`, the screen transitions to a status view, and the
returned `verification_id` is retained across rotation/process death. (FR-3, FR-4,
FR-7) — **"eIDV submits."**

AC-3. The client fetches status via `GET /v1/kyc/eidv/{id}`, advancing the UI from
`pending`/`processing` to a terminal state, and renders the correct UI for
`approved` / `declined` / `referred` / `expired`. (FR-4, FR-5) — **"status
returns."**

AC-4. On `approved`/`referred`, the flow signals completion (`onDone`) so the
requirements screen (AND-320) can re-evaluate. (FR-5)

AC-5. `declined(retryable=true)` offers retry returning to the form with draft
intact; `retryable=false` shows a terminal failure. (FR-5)

AC-6. An existing active verification is resumed (form skipped) when reopening the
screen. (FR-6)

AC-7. Submit is never auto-retried; status polling uses bounded backoff and stops
on terminal state or after the ~90s budget with a manual refresh available. (FR-8,
section 7)

AC-8. No eIDV PII is written to Room/DataStore/logs; `national_id.value` is masked
everywhere. (Section 8)

AC-9. The automated acceptance test (MockWebServer: submit→`pending`, poll→
`approved`) passes. (Section 11)

## 15. Definition of Done

- Code merged to `android-port` under
  `com.testlogon.android.feature.kyc.eidv` with the route registered in
  `feature-kyc` navigation.
- `EidvViewModel`, `EidvRepository`, DTOs, Retrofit methods, and Compose screens
  implemented per sections 4–6.
- All unit, DTO-mapping, network (MockWebServer), and Compose tests in section 11
  pass in CI; the section 11 acceptance test is green.
- Lint/detekt/ktlint clean; no hardcoded strings (all in `strings.xml`); TalkBack
  pass on form and status screens.
- OkHttp logging redacts `/v1/kyc/eidv/*` PII; no PII in analytics events.
- Open questions OQ-1/OQ-2 resolved against `/openapi.json` (or explicitly deferred
  with tracking notes) before merge.
- Code review + security review (PII handling) approved.
