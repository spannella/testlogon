---
id: AND-325
title: eIDV
milestone: M7
epic: E42
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-319]
blocks: []
---

# AND-325 — eIDV

## 1. Overview & Goal

Implement the electronic identity verification (eIDV / eID) flow inside the KYC
feature module.

> **REVIEW CORRECTION (major):** This spec was originally written assuming eIDV is a
> "non-document, data-only" form where the client *submits* the user's legal name,
> DOB, and address to a bureau and polls a pass/fail/referred decision. That model is
> **wrong** per the authoritative sources. The real flow is a **redirect-based
> government eID scheme** flow (`src/api/endpoints/kycEidv.ts`, OpenAPI
> `StartEidVerificationIn`/`StartEidVerificationOut`/`EidStatusOut`): the client lists
> supported eID schemes, the user *picks a scheme* (one of `eidas | digid | bankid |
> aadhaar`), the client starts a session and hands the user off to the scheme's
> `redirect_url`; the government provider authenticates the user and returns verified
> identity fields. The client submits **no PII** — it only sends `{ scheme }`. Status
> is read back as an `eid_verification` object (or `null` while not yet completed),
> which carries the government-verified fields and any discrepancies vs the profile.
> The body of this spec below has been corrected accordingly; original incorrect
> claims are called out in §16.

eID is a non-document verification path that leverages a national/government
electronic-identity scheme. The user selects an eID scheme; the client starts a
verification session against a **draft KYC case** and opens the returned
`redirect_url` (browser-redirect / mobile-app-QR / OTP+biometric, per the scheme's
`auth_flow`). After the provider authenticates the user and the callback completes,
the client polls the case's eID status until an `eid_verification` assertion is
present (or the session expires). The verified identity attributes come *back from*
the provider; the client never transmits the user's name/DOB/address for this flow.

The scope of this ticket is bounded by its acceptance bullet: **eIDV submits +
status returns.** Concretely the user can open the eID screen, see the eID schemes
available for their country, start a scheme (the "submit"), complete the provider
hand-off, and then observe status returning an `eid_verification` (with its
assertion, assurance level, verified fields, and any discrepancies) or remaining
`null`/expired until completion. This ticket does **not** cover document capture, ID
scanning, facial comparison, liveness, residency proof, or screening — those are
owned by AND-321/322/323/324/326/328 respectively. eID is one selectable
requirement among several surfaced by the tier-requirements screen (AND-320); this
ticket only wires the eID requirement type.

Goal: a user whose target KYC tier requires the eID requirement can complete that
single requirement end-to-end on device, with the resulting `eid_verification`
status reflected back into the requirements list so AND-320 can re-evaluate tier
eligibility (note `auto_tier_upgrade` may already advance the tier server-side).

## 2. Context & References

- Feature module: `feature-kyc` (created by AND-319/AND-320). This ticket adds the
  `eidv` sub-package: `com.testlogon.android.feature.kyc.eidv`.
- DTOs and the `KycApi` Retrofit interface are owned by **AND-319 — KYC API + DTOs**
  (`/v1/kyc/*` DTOs: tiers/me, requirements, evaluate, cases). This ticket extends
  that surface with the eID-specific endpoints and DTOs, reusing AND-319's Moshi
  setup, `ApiResult<T>` wrapping, and FastAPI `detail` error mapping. **Note:** the
  eID flow is **case-scoped** — start/status are under `/v1/kyc/cases/{case_id}/...`,
  so a draft KYC case (`POST /v1/kyc/cases`, owned by AND-319) must exist or be
  created before starting eID; the scheme list (`GET /v1/kyc/eid/schemes`) is not
  case-scoped.
- Tier/requirements host: **AND-320 — Tier status & requirements**. The eIDV screen
  is launched from a requirement row whose type is `eidv`; on completion this ticket
  triggers AND-320's `evaluate` re-fetch.
- Networking conventions: `core-network` (Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15).
  **CORRECTED auth model** (verified against `src/api/client.ts`): the web client
  sends an `Authorization: Bearer <accessToken>` header as the primary credential,
  echoes the `ui_csrf` cookie value in an `X-CSRF-Token` header, optionally sends
  `X-IMPERSONATION-TOKEN`, and uses `credentials: include` (so cookies ride along).
  On 401 it makes a single `POST /ui/session/refresh` then retries once. The Android
  port should reproduce: Bearer token + `X-CSRF-Token` + persistent cookie jar +
  single refresh-then-retry on 401. (The original spec's "cookie-only session" framing
  understated the Bearer header; see §16.) Dev backend `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable — 20s timeouts, bounded backoff retry for idempotent
  GETs only.
- Web reference: `src/api/endpoints/kycEidv.ts` (the eID module — note file is
  `kycEidv.ts`, not `kyc*.ts` glob) and shared types in `src/api/types.ts`
  (`EidScheme`, `EidSchemesList`, `StartEidVerificationResult`, `EidStatus`,
  `EidVerification`, `EidVerifiedFields`, `MockEidAssertion`). The OpenAPI document at
  `/openapi.json` is the authoritative source for exact field names; the field shapes
  below have been reconciled against it during this review (schemas
  `StartEidVerificationIn/Out`, `EidStatusOut`, `EidVerificationOut`, `EidSchemeOut`,
  `EidSchemesListOut`, `EidDiscrepancyOut`, `EidVerifiedFieldsOut`,
  `MockEidRequest/Response`).
- Stack baseline: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  single-Activity Navigation-Compose, minSdk 24 / target 35, JDK 17.

## 3. Functional Requirements

> **REVIEW CORRECTION (major):** FR-1..FR-3 originally described a PII data-entry form
> (name/DOB/address fields with client-side validation submitted to a bureau). That is
> not the real flow — eID submits only a chosen `scheme` string and hands off to a
> government provider. FRs rewritten below to the scheme-selection / redirect model;
> see §16.

FR-1. The eID screen lists the eID schemes available to the user via
`GET /v1/kyc/eid/schemes` (optionally filtered by `country`). Each scheme row shows
`name`, `assurance_level` (`low | substantial | high`), `auth_flow`
(`browser_redirect | mobile_app_qr | otp_biometric`), supported `countries`, and
`description`. The user selects exactly one scheme.

FR-2. The client requires a draft KYC `case_id` before starting eID. If none is in
context, it creates/reuses one via AND-319's case API (`POST /v1/kyc/cases`). No
identity-attribute entry or client-side PII validation is performed in this flow —
the only "input" is the scheme selection, validated against the allowed set
`^(eidas|digid|bankid|aadhaar)$`.

FR-3. A "Verify with eID" / "Start" action is enabled only when a scheme is selected
and no start request is in flight. Tapping it issues
`POST /v1/kyc/cases/{case_id}/eid/start` with `{ scheme }` (FR section 5) and, on
success, opens the returned `redirect_url` to hand off to the provider.

FR-4. After the provider hand-off (and callback completion), the screen polls
`GET /v1/kyc/cases/{case_id}/eid/status`. While `eid_verification` is `null` (not yet
completed) and the session has not expired, the client polls until an
`eid_verification` is present or the poll budget / `expires_at` is reached.

FR-5. Outcome states render distinct UI, derived from the `eid_verification` object
(there is no `status` enum field on the wire — see §5/§16):
- **Verified, no critical discrepancies** (`eid_verification` present; all
  `discrepancies` severities `match`/`warning`): success state. "Continue" returns to
  requirements and triggers AND-320 re-evaluate. (`auto_tier_upgrade` may already have
  advanced the tier server-side; the client surfaces this.)
- **Verified with `critical` discrepancies**: cautionary state listing the
  conflicting fields (`field`, `profile_value` vs `eid_value`); requirement may show
  as needing review per AND-320 (server decides outcome — client does not invent a
  pass/fail).
- **Not yet completed** (`eid_verification` is `null`): neutral "in progress / open
  your eID app" state; keep polling within budget.
- **Expired** (`expires_at` elapsed with `eid_verification` still `null`): the session
  is no longer valid; the user restarts by starting a new session.

FR-6. If a completed `eid_verification` already exists for the case, opening the
screen resumes it: the client fetches status first
(`GET /v1/kyc/cases/{case_id}/eid/status`) and shows the result, skipping the
scheme-selection step when a verification is already present.

FR-7. The screen survives configuration changes (rotation, process death) — the
active `case_id`, `session_id`, and selected `scheme` persist via `SavedStateHandle`.

FR-8. Offline / unreachable backend yields an explicit error state with retry; no
silent failures. The start request (a POST) is never auto-retried.

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

    fun onSchemeSelected(scheme: EidScheme)
    fun start()                  // POST eid/start; single attempt, no auto-retry
    fun onProviderReturned()     // called when redirect/callback flow returns
    fun refreshStatus()          // idempotent GET eid/status; bounded backoff
    fun restart()                // clears session, returns to scheme selection
}
```

> **REVIEW CORRECTION:** the original ViewModel exposed `onFieldChanged`/`submit`/
> `retryAfterDecline` for a PII form. Replaced with scheme-selection + start +
> provider-return + status-poll operations to match the real flow (§16).

```kotlin
sealed interface EidvUiState {
    data object Loading : EidvUiState
    // Scheme selection (replaces the former PII "Form")
    data class SchemeSelection(
        val schemes: List<EidScheme>,
        val selected: EidScheme? = null,
        val starting: Boolean = false,
        val canStart: Boolean = false,    // selected != null && !starting
    ) : EidvUiState
    // Provider hand-off in progress (redirect opened, awaiting return/callback)
    data class AwaitingProvider(
        val caseId: String,
        val sessionId: String,
        val scheme: String,
        val redirectUrl: String,
        val expiresAt: Long,              // epoch seconds (StartEidVerificationOut.expires_at)
        val polling: Boolean = false,
    ) : EidvUiState
    // Result derived from EidStatusOut.eid_verification
    data class Result(
        val caseId: String,
        val verification: EidVerification,   // assertion_id, assurance_level, verified_at, discrepancies, ...
        val hasCriticalDiscrepancy: Boolean, // any discrepancy.severity == "critical"
        val autoTierUpgrade: Boolean,
    ) : EidvUiState
    data object Expired : EidvUiState
    data class Error(val message: String, val retry: Retry) : EidvUiState {
        enum class Retry { LOAD, START, STATUS }
    }
}

// Scheme identifiers per StartEidVerificationIn pattern ^(eidas|digid|bankid|aadhaar)$
enum class EidScheme { EIDAS, DIGID, BANKID, AADHAAR }

// auth_flow values from EidSchemeOut: browser_redirect | mobile_app_qr | otp_biometric
enum class EidAuthFlow { BROWSER_REDIRECT, MOBILE_APP_QR, OTP_BIOMETRIC }

// assurance_level values: low | substantial | high
enum class EidAssuranceLevel { LOW, SUBSTANTIAL, HIGH }

// discrepancy severity from EidDiscrepancyOut: match | warning | critical
enum class EidDiscrepancySeverity { MATCH, WARNING, CRITICAL }
```

> **REVIEW CORRECTION:** the original state model used a PII `Form`, a `Status` with
> `verificationId`/`status`/`reason`/`retryable`, and an `EidvStatus` enum
> (`PENDING/APPROVED/DECLINED/REFERRED/EXPIRED`) plus an `EidvField` enum — **none of
> which exist on the wire.** Replaced with scheme selection + provider hand-off + a
> `Result` derived from `EidStatusOut.eid_verification` (§16).

Repository (in `feature-kyc`, depends on `KycApi` from AND-319):

```kotlin
interface EidvRepository {
    suspend fun listSchemes(country: String?): ApiResult<List<EidScheme>>
    suspend fun ensureDraftCase(): ApiResult<String>           // case_id (AND-319 case API)
    suspend fun start(caseId: String, scheme: String): ApiResult<StartEidSession>  // session_id, redirect_url, expires_at
    suspend fun status(caseId: String): ApiResult<EidVerification?>  // null until completed
    // Dev-only mock provider hand-off (POST /mock/eid/verify -> assertion+signature,
    // then GET /v1/kyc/eid/callback). Used to exercise the flow against the dev host.
    suspend fun mockComplete(sessionId: String): ApiResult<Unit>
}
```

> **REVIEW CORRECTION:** original repo signatures (`loadProfile`,
> `latestVerification`, `submit(draft)`, `status(verificationId)`) assumed a
> user-scoped, id-addressed verification. Real flow is case-scoped: list schemes →
> ensure case → start(scheme) → poll status(caseId). There is **no** `eidv/me`
> endpoint; resume is by re-reading the case's `eid/status` (§16).

Polling: `refreshStatus()` runs a coroutine that re-calls `status(caseId)`
(`GET .../eid/status`) with bounded exponential backoff (2s, 4s, 8s, capped 8s) for
up to ~90s wall-clock (or until `expires_at`) while `eid_verification` is still
`null`; each call is an idempotent GET so it is eligible for `core-network`'s
GET-retry policy. Polling is cancelled when the screen leaves composition (tied to
`viewModelScope`) and resumed on `refreshStatus()`/return.

The `case_id`, `session_id`, and selected `scheme` are mirrored into
`SavedStateHandle` keys `eidv_case_id`, `eidv_session_id`, and `eidv_scheme` for
process-death survival (FR-7). No PII is placed in `SavedStateHandle` (there is no PII
draft in this flow).

Provider hand-off: `start()` returns a `redirect_url`. The client opens it via a
Custom Tab / browser intent (or, for `mobile_app_qr`/`otp_biometric` schemes, follows
the provider's app flow). On return — via deep link to the `/v1/kyc/eid/callback`
result or simply when the user comes back to the app — the client calls
`onProviderReturned()` and begins polling status. In dev, the `mockComplete()` path
drives `POST /mock/eid/verify` then `GET /v1/kyc/eid/callback?session_id&assertion&signature`
to simulate the provider without a real eID account.

Compose layer: `EidvRoute(onDone)` collects `uiState` with
`collectAsStateWithLifecycle()` and renders `EidvSchemeScreen`,
`EidvAwaitingScreen`, `EidvResultScreen`, or `EidvErrorScreen` from `core-ui`
building blocks. The scheme list uses Material 3 list/`Card` rows (no
`OutlinedTextField`/`DatePickerDialog` — there is no PII form in this flow).

## 5. API Contract

> **REVIEW CORRECTION (major, verified against OpenAPI + `src/api/endpoints/kycEidv.ts`):**
> The original §5 invented endpoints `POST /v1/kyc/eidv/verify`, `GET /v1/kyc/eidv/{id}`,
> and `GET /v1/kyc/eidv/me` with PII request bodies and a
> `verification_id/status/reason/retryable` response. **None of these exist.** The path
> segment is `eid` (not `eidv`), the flow is case-scoped, the request body is just
> `{ scheme }`, and the status response is `{ eid_verification: {...} | null }`. Real
> contract below.

All real eID paths and exact field names below are verified against the OpenAPI
index/spec and the web client `src/api/endpoints/kycEidv.ts`.

### 5.1 List eID schemes (GET, idempotent, retryable)
```
GET /v1/kyc/eid/schemes?country=GB        # country optional
```
OpenAPI: `GET /v1/kyc/eid/schemes` → `200: EidSchemesListOut`. Response:
```json
{
  "schemes": [
    {
      "id": "eidas",
      "name": "eIDAS",
      "countries": ["DE", "FR", "GB"],
      "assurance_level": "high",
      "auth_flow": "browser_redirect",
      "description": "EU eIDAS cross-border scheme"
    }
  ]
}
```
(`EidSchemeOut` required fields: `id`, `name`, `countries`, `assurance_level`,
`auth_flow`; `description` defaults to "".)

### 5.2 Start eID verification (POST, not retried)
```
POST /v1/kyc/cases/{case_id}/eid/start
Authorization: Bearer <accessToken>
X-CSRF-Token: <ui_csrf cookie value>
Content-Type: application/json

{ "scheme": "eidas" }
```
OpenAPI: req `StartEidVerificationIn` = `{ scheme: string }` only, constrained by
`pattern ^(eidas|digid|bankid|aadhaar)$`. → `200: StartEidVerificationOut`:
```json
{
  "session_id": "sess_...",
  "redirect_url": "https://eid-provider.example/auth?...",
  "expires_at": 1749126000,
  "scheme": "eidas"
}
```
(`expires_at` is an **integer** epoch timestamp, not an ISO string. All four fields
required.) The client opens `redirect_url` to hand the user off to the provider.

### 5.3 Get eID status (GET, idempotent, retryable)
```
GET /v1/kyc/cases/{case_id}/eid/status
```
OpenAPI: `200: EidStatusOut` = `{ eid_verification: EidVerificationOut | null }`.
When not yet completed, `eid_verification` is `null`. When completed:
```json
{
  "eid_verification": {
    "scheme": "eidas",
    "assertion_id": "assn_...",
    "assurance_level": "high",
    "verified_at": 1749126120,
    "auto_tier_upgrade": false,
    "discrepancies": [
      { "field": "last_name", "profile_value": "Smith", "eid_value": "Smyth", "severity": "warning" }
    ],
    "verified_fields": {
      "first_name": "Ada", "last_name": "Lovelace", "date_of_birth": "1990-12-10",
      "nationality": "GB", "document_number": "...", "document_type": "...",
      "issuing_country": "GB"
    }
  }
}
```
(`EidVerificationOut` required: `scheme`, `assertion_id`, `assurance_level`,
`verified_at` [integer epoch]. `discrepancies[]` each require `field`,
`profile_value`, `eid_value`, `severity ∈ {match,warning,critical}`.
`verified_fields` is nullable; its sub-fields all default to "".)

### 5.4 eID callback (GET) — provider return
```
GET /v1/kyc/eid/callback?session_id=...&assertion=...&signature=...
```
OpenAPI: `200` (empty schema). This is the provider/redirect return target that
completes the session server-side; the mobile client typically reaches it via a deep
link or lets the Custom Tab follow it, then polls §5.3.

### 5.5 Dev-only mock provider (GET schemes shows `auth_flow`; this simulates the IdP)
```
POST /mock/eid/verify        # req MockEidRequest { session_id }
                             # → 200 MockEidResponse { assertion, signature }
```
Used in dev to obtain a signed assertion for a `session_id`, which is then fed into
§5.4's callback (`completeEidCallback(session_id, assertion, signature)` in the web
client). This is the only way to drive the flow end-to-end against the unreliable dev
host without a real government eID account.

### 5.6 Moshi DTOs (added alongside AND-319's KYC DTOs)
```kotlin
@JsonClass(generateAdapter = true)
data class StartEidVerificationRequest(
    val scheme: String,                                   // eidas|digid|bankid|aadhaar
)

@JsonClass(generateAdapter = true)
data class StartEidVerificationDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "redirect_url") val redirectUrl: String,
    @Json(name = "expires_at") val expiresAt: Long,       // epoch seconds (INTEGER)
    val scheme: String,
)

@JsonClass(generateAdapter = true)
data class EidSchemesListDto(val schemes: List<EidSchemeDto>)

@JsonClass(generateAdapter = true)
data class EidSchemeDto(
    val id: String,
    val name: String,
    val countries: List<String>,
    @Json(name = "assurance_level") val assuranceLevel: String,
    @Json(name = "auth_flow") val authFlow: String,
    val description: String = "",
)

@JsonClass(generateAdapter = true)
data class EidStatusDto(
    @Json(name = "eid_verification") val eidVerification: EidVerificationDto? = null,
)

@JsonClass(generateAdapter = true)
data class EidVerificationDto(
    val scheme: String,
    @Json(name = "assertion_id") val assertionId: String,
    @Json(name = "assurance_level") val assuranceLevel: String,
    @Json(name = "verified_at") val verifiedAt: Long,     // epoch seconds (INTEGER)
    @Json(name = "auto_tier_upgrade") val autoTierUpgrade: Boolean = false,
    val discrepancies: List<EidDiscrepancyDto> = emptyList(),
    @Json(name = "verified_fields") val verifiedFields: EidVerifiedFieldsDto? = null,
)

@JsonClass(generateAdapter = true)
data class EidDiscrepancyDto(
    val field: String,
    @Json(name = "profile_value") val profileValue: String,
    @Json(name = "eid_value") val eidValue: String,
    val severity: String,                                 // match|warning|critical
)

@JsonClass(generateAdapter = true)
data class EidVerifiedFieldsDto(
    @Json(name = "first_name") val firstName: String = "",
    @Json(name = "last_name") val lastName: String = "",
    @Json(name = "date_of_birth") val dateOfBirth: String = "",
    val nationality: String = "",
    @Json(name = "document_number") val documentNumber: String = "",
    @Json(name = "document_type") val documentType: String = "",
    @Json(name = "issuing_country") val issuingCountry: String = "",
)

@JsonClass(generateAdapter = true)
data class MockEidRequest(@Json(name = "session_id") val sessionId: String)

@JsonClass(generateAdapter = true)
data class MockEidResponse(val assertion: String, val signature: String)
```

### 5.7 Retrofit (extends `KycApi`)
```kotlin
@GET("v1/kyc/eid/schemes")
suspend fun eidSchemes(@Query("country") country: String?): Response<EidSchemesListDto>

@POST("v1/kyc/cases/{caseId}/eid/start")
suspend fun startEid(
    @Path("caseId") caseId: String,
    @Body body: StartEidVerificationRequest,
): Response<StartEidVerificationDto>

@GET("v1/kyc/cases/{caseId}/eid/status")
suspend fun eidStatus(@Path("caseId") caseId: String): Response<EidStatusDto>

@GET("v1/kyc/eid/callback")
suspend fun eidCallback(
    @Query("session_id") sessionId: String,
    @Query("assertion") assertion: String,
    @Query("signature") signature: String,
): Response<Unit>

// dev only
@POST("mock/eid/verify")
suspend fun mockEidVerify(@Body body: MockEidRequest): Response<MockEidResponse>
```

`scheme`, `assurance_level`, `auth_flow`, and discrepancy `severity` strings are
mapped to the §4 enums via tolerant `when`s that default unknown values to a safe
"unknown/other" bucket and log the raw value (forward-compatibility). The outcome is
**derived** from `eid_verification` presence + discrepancy severities — there is no
`status`/`reason`/`retryable` field to map.

## 6. Data & State Management

- No Room persistence: eID verifications are short-lived and authoritative on the
  server. The only persisted client state is the in-progress `case_id`, `session_id`,
  and selected `scheme` in `SavedStateHandle` (FR-7). No DataStore key is required.
  (No PII is persisted — there is no PII draft in this flow.)
- `EidvUiState` is the single source of truth; the ViewModel reduces API results into
  it. `SchemeSelection.canStart` is recomputed on each selection
  (`selected != null && !starting`).
- Polling state (`AwaitingProvider.polling`) is derived from the active poll
  coroutine job; starting `refreshStatus()` sets it true; a present `eid_verification`
  or budget/`expires_at` exhaustion sets it false.
- On a present `eid_verification` (the success/result case), the ViewModel emits an
  `EidvOutcome` (one-shot via `Channel`/`SharedFlow`) carrying the assertion outcome
  and `auto_tier_upgrade`; `EidvRoute` forwards it to `onDone`, which the KYC navigator
  uses to pop back and invoke AND-320's evaluate re-fetch. The requirements list is not
  owned here; this ticket only signals completion.
- There is no local PII validation in this flow (no name/DOB/address entry); the only
  client-side check is that a `scheme` is selected and is within the allowed set.

## 7. Error Handling & Resilience

- All calls return `ApiResult<T>` (from `core-network`); FastAPI `detail` is mapped
  (string | `[{msg}]` | `{code,...}`) to a user-facing message via AND-319's shared
  error mapper. Note all eID endpoints declare `422: HTTPValidationError` (e.g. a
  `scheme` not matching `^(eidas|digid|bankid|aadhaar)$`), which maps to the standard
  FastAPI `detail: [{loc, msg, type}]` shape.
- Timeouts: rely on the global 20s OkHttp timeout. `eid/start` (`POST`) failures
  surface on the scheme-selection screen with a non-blocking error banner and the
  Start button re-enabled — **never auto-retried** (non-idempotent).
- Status `GET` failures during polling do not crash the poll loop: a single failed
  poll is retried per the bounded GET backoff; if the whole budget (~90s) or
  `expires_at` elapses without an `eid_verification`, the UI shows "Still processing —
  check back later" with a manual "Refresh status" action (keeps `case_id`/
  `session_id`).
- `401`: handled transparently by `core-network` (single `POST /ui/session/refresh`
  then retry — matches `src/api/client.ts`). A second 401 surfaces as a re-auth
  required error routed to the session gate; the `case_id`/`session_id`/`scheme` are
  preserved.
- `422` on `eid/start` (invalid/unsupported scheme): surface the validation message
  and keep the user on scheme selection.
- Session expiry (`expires_at` elapsed, still no `eid_verification`): move to the
  `Expired` state; the user starts a new session (new `eid/start`). There is no
  `409`/duplicate semantics defined for this endpoint — do **not** assume one.
- Offline (no connectivity): `Error(message, Retry.LOAD)` with retry; no partial
  start is assumed to have succeeded — on retry the client first re-reads
  `GET /v1/kyc/cases/{case_id}/eid/status` to detect a verification that may have
  completed server-side (replaces the non-existent `latestEidv()`).

## 8. Security & Privacy

> **REVIEW CORRECTION:** the original §8 assumed the client *submits* PII. It does
> not — the start request body is `{ scheme }` only. PII (`verified_fields`) and
> `discrepancies` (which echo `profile_value`/`eid_value`) come **back** from the
> provider in the status response, so the sensitivity concern shifts to the
> *response* surface, not the request.
- The eID **request** carries no PII — only `{ scheme }`. No legal name / DOB /
  address / national-id is transmitted by this flow.
- The eID **status response** is highly sensitive: `verified_fields` (name, DOB,
  document number, nationality, issuing country) and `discrepancies[]`
  (`profile_value` vs `eid_value`, which can include name/DOB). This data is held only
  in memory; it is **not** written to Room, DataStore, or logs. Only `case_id`,
  `session_id`, and `scheme` are persisted in `SavedStateHandle`.
- `verified_fields.document_number` and any discrepancy `profile_value`/`eid_value`
  are masked in any telemetry/log surface (never logged) and, where shown, masked in
  the UI except for the last 4 characters.
- All requests carry `Authorization: Bearer <token>` + the session cookies +
  `X-CSRF-Token` header per project auth (verified against `src/api/client.ts`); the
  persistent cookie jar is reused. The mutating `POST /v1/kyc/cases/{case_id}/eid/start`
  MUST include the CSRF header.
- The dev backend is plaintext HTTP — flagged as a known dev-only risk; production
  must be HTTPS (network-security-config disallows cleartext outside the dev host).
  Because `verified_fields`/`discrepancies` return real PII over the wire, **real eID
  verification must not run against the plaintext dev host** — use the mock provider
  (`POST /mock/eid/verify`) for dev exercise.
- The `redirect_url` is opened in a Custom Tab / system browser (not an embedded
  WebView with JS bridges) so provider credentials are never exposed to the app.
- `SavedStateHandle` session state and any in-memory `verified_fields` are cleared
  when the flow reaches a result and the user navigates away after success.

## 9. Accessibility & i18n

- Scheme list rows have `contentDescription`/labels announcing the scheme `name`,
  `assurance_level`, and `auth_flow`; the selected row exposes a selected semantics
  state. Any error text is associated via Compose semantics (`error = true` +
  supporting text) so TalkBack announces failures.
- Outcome transitions announce via `liveRegion = LiveRegionMode.Polite` so screen
  readers hear "Identity verified" / "Verification in progress — open your eID app" /
  "Verification session expired" / "Identity verified with discrepancies to review".
- Touch targets ≥ 48dp; supports dynamic font scaling and dark theme via Material 3.
- All strings live in `feature-kyc` `strings.xml`; no hardcoded UI text. Scheme
  `name`/`description` come from the server (`EidSchemeOut`) and are displayed as-is
  (localizable via the `/v1/kyc/i18n/*` family, e.g.
  `GET /v1/kyc/i18n/translations/{language}`); a generic fallback is shown when a
  scheme description is empty. `verified_at`/dates render via locale-aware formatters;
  country codes via `Locale.getDisplayCountry`. There is no free-text bureau `reason`
  field on the wire (corrected — see §16); discrepancy fields are rendered from
  localized field-name strings, not a server `reason`.

## 10. Telemetry & Logging

Events (via the app analytics facade; no PII in payloads — note: scheme id and
assurance level are not PII):
- `kyc_eid_opened` { resumed: Boolean }
- `kyc_eid_started` { scheme: String, auth_flow: String }
- `kyc_eid_result` { scheme: String, assurance_level: String,
  has_critical_discrepancy: Boolean, auto_tier_upgrade: Boolean, elapsed_ms: Long }
- `kyc_eid_error` { stage: "schemes"|"start"|"status"|"callback", code: String? }

Logging: debug-level only, via `core` logger; request/response bodies for eID are
**redacted** (the OkHttp logging interceptor must exclude `/v1/kyc/cases/*/eid/*`,
`/v1/kyc/eid/*`, and `/mock/eid/*` bodies or mask them, since status responses carry
`verified_fields`/`discrepancies` PII). `session_id`/`assertion_id`/`scheme` may be
logged; `verified_fields` and discrepancy values must not be.

## 11. Testing Strategy

Unit (JUnit + Turbine + coroutines-test, `core-testing`):
- Scheme list mapping/filtering: schemes load from `EidSchemesListDto`; selecting a
  scheme sets `canStart = true`; `start` disabled until a scheme is selected.
- `EidvViewModel` reduces `eid/start` success → `AwaitingProvider`; poll advances
  `eid_verification == null → present` and emits the success `EidvOutcome` (incl.
  `auto_tier_upgrade`).
- Discrepancy handling: a `critical` severity in `discrepancies` sets
  `hasCriticalDiscrepancy = true`; `warning`/`match` only do not.
- Session expiry: `expires_at` elapsed with `eid_verification` still null → `Expired`
  state; `restart()` returns to scheme selection (clears `session_id`).
- Poll budget exhaustion → manual-refresh status, polling stops, no crash.
- `eid/start` failure does not auto-retry; Start button re-enabled.
- Resume path: opening with a case whose `eid/status` already returns a present
  `eid_verification` → screen opens in `Result`, scheme selection skipped.

DTO mapping (extends AND-319 tests): JSON fixtures for `StartEidVerificationOut`
(`expires_at` as integer), `EidStatusOut` with `eid_verification == null`, and with a
populated `EidVerificationOut` (incl. `discrepancies` of each severity and
`verified_fields`) deserialize correctly; unknown `scheme`/`auth_flow`/`severity`
strings map to the safe "unknown" enum bucket.

Network (MockWebServer): covers `200`/`401-then-refresh`/`422-invalid-scheme`/timeout
for `eid/start`, and `200(null)` then `200(present)` for `eid/status`. Verifies the
`X-CSRF-Token` and `Authorization: Bearer` headers are sent on `eid/start`.

Compose UI tests: scheme list renders rows with name/assurance/auth_flow; Start
disabled until a scheme is selected; result/awaiting/expired/error screens render per
state. **Acceptance test:** scripted MockWebServer returns a session on `eid/start`,
then `eid_verification == null` on the first status poll and a present
`eid_verification` on the next, asserting the UI reaches the result state and
`onDone(success)` fires — proving "eIDV submits + status returns." The provider
redirect is stubbed (or driven via the mock provider) so no real browser hand-off is
needed in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-319** (KYC API + DTOs): provides `KycApi`, base KYC DTOs, the
  Moshi/`ApiResult` plumbing, and the FastAPI error mapper this ticket extends. Hard
  blocker.
- **Integrates with AND-320** (Tier status & requirements): the eID requirement row
  launches `EIDV_ROUTE`; on success this ticket signals AND-320 to re-run evaluate.
  Soft dependency — eID can be developed in parallel against a stub launcher but the
  end-to-end requirement wiring needs AND-320.
- **Needs a draft KYC case**: the eID start/status endpoints are case-scoped, so this
  flow depends on AND-319's case API (`POST /v1/kyc/cases`, `GET .../cases/{id}`) to
  obtain a `case_id` before starting. (Correction: original spec omitted the case
  dependency.)
- Transitively relies on AND-027 (network/session foundation, via AND-319) and the
  `feature-kyc` module scaffolding.
- Independent of the camera/vendor-SDK KYC tickets (AND-321/322/323/324/326) — eID is
  non-document and ships without CameraX. (Browser/Custom-Tabs dependency is required
  for the provider redirect.)
- Sequencing: land after AND-319; can merge before or alongside AND-320 behind the
  requirement-type switch.

## 13. Risks & Open Questions

- OQ-1: **RESOLVED in this review.** Endpoint paths/fields are now verified against
  OpenAPI and `src/api/endpoints/kycEidv.ts`: `GET /v1/kyc/eid/schemes`,
  `POST /v1/kyc/cases/{case_id}/eid/start` (`{scheme}`), `GET .../eid/status`
  (`{eid_verification|null}`), `GET /v1/kyc/eid/callback`, dev `POST /mock/eid/verify`.
  See §5 and §16.
- OQ-2: **RESOLVED — asynchronous.** Start returns a `session_id`/`redirect_url`;
  status returns `eid_verification == null` until the provider completes, then the
  assertion. There is no synchronous decision in the start response and no
  `status`/`reason`/`retryable` field.
- OQ-3: Whether a webhook/push (`/v1/kyc/webhooks`, `/v1/kyc/eid/callback`) can drive
  status without polling on mobile — the callback is a redirect target; deep-link
  return is the likely trigger, otherwise polling. Confirm the mobile redirect/
  deep-link scheme with backend before implementation.
- OQ-4: Which eID schemes are enabled per environment/country (the allowed set is
  `eidas | digid | bankid | aadhaar`; availability is driven by
  `GET /v1/kyc/eid/schemes` per `country`). How the app reaches the
  `redirect_url`/`callback` for `mobile_app_qr` vs `otp_biometric` `auth_flow`s — may
  need per-scheme UX (still open).
- Risk: unreliable plaintext dev host makes manual verification flaky; mitigate with
  MockWebServer-based tests as the source of truth for acceptance, and use the mock
  provider (`/mock/eid/verify`) rather than a real eID account in dev.
- Risk: PII handling/compliance correctness — mitigated by no-persist/no-log policy
  (section 8) and security review before merge.

## 14. Acceptance Criteria

> **REVIEW CORRECTION:** ACs rewritten to the verified contract (real endpoints/
> fields/flow). The acceptance *intent* — "eIDV submits + status returns" — is
> preserved; the mechanism (scheme start + status with `eid_verification`) is corrected.

AC-1. From a KYC requirement of type `eid`, the user opens the eID screen and sees the
schemes available for their country (`GET /v1/kyc/eid/schemes`) with name, assurance
level, and auth flow; exactly one scheme is selectable. (FR-1, FR-2)

AC-2. With a scheme selected, tapping "Verify with eID" / "Start" issues
`POST /v1/kyc/cases/{case_id}/eid/start` with `{ "scheme": <id> }`, the screen
transitions to the provider hand-off (opening `redirect_url`), and the returned
`session_id`/`case_id`/`scheme` are retained across rotation/process death. (FR-3,
FR-4, FR-7) — **"eIDV submits."**

AC-3. The client fetches status via `GET /v1/kyc/cases/{case_id}/eid/status`,
advancing the UI from `eid_verification == null` (awaiting) to a present
`eid_verification`, and renders the correct UI for verified / verified-with-critical-
discrepancy / expired. (FR-4, FR-5) — **"status returns."**

AC-4. On a present `eid_verification` (success), the flow signals completion
(`onDone`, including `auto_tier_upgrade`) so the requirements screen (AND-320) can
re-evaluate. (FR-5)

AC-5. A returned `eid_verification` with a `critical` discrepancy renders the
cautionary review state listing conflicting fields; with only `match`/`warning`
discrepancies it renders the plain success state. (FR-5)

AC-6. An existing completed verification is resumed (scheme selection skipped) when
reopening the screen, by reading `GET .../eid/status`. (FR-6)

AC-7. `eid/start` is never auto-retried; status polling uses bounded backoff and stops
on a present `eid_verification`, on `expires_at`, or after the ~90s budget with a
manual refresh available. (FR-8, section 7)

AC-8. No eID PII is written to Room/DataStore/logs; `verified_fields` and discrepancy
values (`profile_value`/`eid_value`) are never logged and masked where displayed.
(Section 8)

AC-9. The automated acceptance test (MockWebServer: `eid/start`→session, poll→
`eid_verification == null` then present) passes. (Section 11)

## 15. Definition of Done

- Code merged to `android-port` under
  `com.testlogon.android.feature.kyc.eidv` with the route registered in
  `feature-kyc` navigation.
- `EidvViewModel`, `EidvRepository`, DTOs, Retrofit methods, and Compose screens
  implemented per sections 4–6.
- All unit, DTO-mapping, network (MockWebServer), and Compose tests in section 11
  pass in CI; the section 11 acceptance test is green.
- Lint/detekt/ktlint clean; no hardcoded strings (all in `strings.xml`); TalkBack
  pass on scheme-selection and result screens.
- OkHttp logging redacts `/v1/kyc/cases/*/eid/*`, `/v1/kyc/eid/*`, and `/mock/eid/*`
  PII (status responses carry `verified_fields`/`discrepancies`); no PII in analytics
  events.
- Open questions OQ-1/OQ-2 resolved in review against OpenAPI + `kycEidv.ts`; OQ-3/OQ-4
  (mobile redirect/deep-link + per-environment scheme availability) tracked before
  merge.
- Code review + security review (PII handling) approved.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **eID scheme list endpoint** is `GET /v1/kyc/eid/schemes` (optional `country`
   query), returning `EidSchemesListOut { schemes: EidSchemeOut[] }`.
   VERDICT: **Verified.** SOURCE: OpenAPI `GET /v1/kyc/eid/schemes` (resp
   `EidSchemesListOut`); schema `EidSchemeOut`; `src/api/endpoints/kycEidv.ts:
   getEidSchemes`; `src/api/types.ts: EidSchemesList`, `EidSchemeInfo`.

2. **Start endpoint** is `POST /v1/kyc/cases/{case_id}/eid/start` with body
   `StartEidVerificationIn { scheme }` (pattern `^(eidas|digid|bankid|aadhaar)$`),
   returning `StartEidVerificationOut { session_id, redirect_url, expires_at:int,
   scheme }`.
   VERDICT: **Verified (and Corrected from spec).** Spec originally claimed
   `POST /v1/kyc/eidv/verify` with a PII body. SOURCE: OpenAPI
   `POST /v1/kyc/cases/{case_id}/eid/start`; schemas `StartEidVerificationIn`,
   `StartEidVerificationOut`; `src/api/endpoints/kycEidv.ts: startEidVerification`;
   `src/api/types.ts: StartEidVerificationResult`.

3. **`expires_at` is an integer epoch**, not an ISO-8601 string.
   VERDICT: **Corrected.** Spec showed `"expires_at": "2026-06-05T12:30:00Z"`. SOURCE:
   OpenAPI `StartEidVerificationOut.expires_at` (`type: integer`);
   `src/api/types.ts: StartEidVerificationResult.expires_at: number`.

4. **Status endpoint** is `GET /v1/kyc/cases/{case_id}/eid/status`, returning
   `EidStatusOut { eid_verification: EidVerificationOut | null }`.
   VERDICT: **Verified (and Corrected from spec).** Spec claimed
   `GET /v1/kyc/eidv/{verification_id}` with a `verification_id/status/reason/retryable`
   body. SOURCE: OpenAPI `GET /v1/kyc/cases/{case_id}/eid/status` (resp `EidStatusOut`);
   schema `EidVerificationOut`; `src/api/endpoints/kycEidv.ts: getEidStatus`;
   `src/api/types.ts: EidStatus`, `EidVerification`.

5. **`EidVerificationOut` fields** are `scheme`, `assertion_id`, `assurance_level`,
   `verified_at:int`, `auto_tier_upgrade:bool`, `discrepancies: EidDiscrepancyOut[]`,
   `verified_fields: EidVerifiedFieldsOut | null`. There is **no** `status`, `reason`,
   `retryable`, or `verification_id` field.
   VERDICT: **Corrected.** SOURCE: OpenAPI schemas `EidVerificationOut`,
   `EidVerifiedFieldsOut`, `EidDiscrepancyOut`; `src/api/types.ts: EidVerification`,
   `EidVerifiedFields`, `EidDiscrepancy`.

6. **Discrepancy severity enum** is `match | warning | critical` (with `field`,
   `profile_value`, `eid_value`).
   VERDICT: **Verified (new, replaces invented `approved/declined/referred/expired`
   status enum).** SOURCE: OpenAPI `EidDiscrepancyOut.severity` enum;
   `src/api/types.ts: EidDiscrepancySeverity`.

7. **Scheme set** is exactly `eidas | digid | bankid | aadhaar`.
   VERDICT: **Verified.** SOURCE: OpenAPI `StartEidVerificationIn.scheme.pattern`;
   `src/api/types.ts: EidScheme`.

8. **Assurance levels** `low | substantial | high`; **auth flows**
   `browser_redirect | mobile_app_qr | otp_biometric`.
   VERDICT: **Verified.** SOURCE: `src/api/types.ts: EidAssuranceLevel`,
   `EidAuthFlow`; OpenAPI `EidSchemeOut.assurance_level`/`auth_flow` (typed as string).

9. **Callback** is `GET /v1/kyc/eid/callback?session_id&assertion&signature`.
   VERDICT: **Verified.** SOURCE: OpenAPI `GET /v1/kyc/eid/callback` (params
   `session_id, assertion, signature`); `src/api/endpoints/kycEidv.ts:
   completeEidCallback`.

10. **Dev mock provider** is `POST /mock/eid/verify` with `MockEidRequest
    { session_id }` → `MockEidResponse { assertion, signature }`.
    VERDICT: **Verified.** SOURCE: OpenAPI `POST /mock/eid/verify`; schemas
    `MockEidRequest`, `MockEidResponse`; `src/api/endpoints/kycEidv.ts: mockEidVerify`;
    `src/api/types.ts: MockEidAssertion`.

11. **No `GET /v1/kyc/eidv/me`** (or any user-scoped "latest verification") endpoint
    exists; resume is via the case's `eid/status`.
    VERDICT: **Corrected.** Spec invented `GET /v1/kyc/eidv/me` / `latestEidv()`.
    SOURCE: absence in OpenAPI index (`grep eid` shows only the four eid endpoints +
    case-scoped status); `src/api/endpoints/kycEidv.ts` (no `me` call).

12. **The flow is case-scoped** — a draft `case_id` (from `POST /v1/kyc/cases`) is
    required before start/status.
    VERDICT: **Corrected (omission).** SOURCE: OpenAPI path params on
    `.../cases/{case_id}/eid/start` and `.../eid/status`; `src/api/endpoints/
    kycEidv.ts: startEidVerification(caseId, ...)`; usage in
    `src/pages/kyc/KycWizardPage.tsx` (`<EidVerificationPanel caseId={caseId} />`).

13. **Auth/CSRF transport**: `Authorization: Bearer <accessToken>` (primary) +
    `X-CSRF-Token` from the `ui_csrf` cookie + `credentials: include`, with a single
    `POST /ui/session/refresh` retry on 401, plus optional `X-IMPERSONATION-TOKEN`.
    VERDICT: **Verified (and Corrected nuance).** Spec framed auth as cookie-only with
    CSRF; the Bearer header is the primary credential. SOURCE: `src/api/client.ts`
    (lines ~157-171 Bearer + CSRF, ~122 refresh, ~162-165 impersonation).

14. **eID flow submits no PII** — only `{ scheme }`. PII (`verified_fields`) and
    discrepancies are returned in the status response.
    VERDICT: **Corrected.** Spec asserted the client submits name/DOB/address/national-
    id. SOURCE: OpenAPI `StartEidVerificationIn` (only `scheme`); `EidVerificationOut`/
    `EidVerifiedFieldsOut` are response-only.

15. **eID requirement is one of several KYC requirements** surfaced by AND-320, shown
    alongside ID upload in the wizard.
    VERDICT: **Verified.** SOURCE: `src/pages/kyc/KycWizardPage.tsx` (eID panel offered
    as alternative to ID upload at step 1).

16. **i18n family** exists under `/v1/kyc/i18n/*` (e.g.
    `GET /v1/kyc/i18n/translations/{language}`).
    VERDICT: **Verified (Corrected path).** Spec referenced a bare `/v1/kyc/i18n`;
    actual paths are namespaced. SOURCE: OpenAPI index lines for `/v1/kyc/i18n/...`.

17. **All eID endpoints declare `422: HTTPValidationError`** for invalid input.
    VERDICT: **Verified.** SOURCE: OpenAPI index `resp=...;422:HTTPValidationError` on
    each eid path.

18. **Android stack choices** (Custom Tabs for the provider redirect instead of an
    embedded WebView; Compose + Navigation; `SavedStateHandle` for process death).
    VERDICT: **Unverified-assumption (framework ref).** SOURCE (framework ref):
    Android Custom Tabs — https://developer.chrome.com/docs/android/custom-tabs ;
    `SavedStateHandle` — https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate .
    Justification, not contract: the API does not dictate the client redirect mechanism.

### Corrections made

- **C1.** Replaced invented endpoints `POST /v1/kyc/eidv/verify`,
  `GET /v1/kyc/eidv/{id}`, `GET /v1/kyc/eidv/me` with the real
  `GET /v1/kyc/eid/schemes`, `POST /v1/kyc/cases/{case_id}/eid/start`,
  `GET /v1/kyc/cases/{case_id}/eid/status`, `GET /v1/kyc/eid/callback`, and dev
  `POST /mock/eid/verify`. (§2, §5, §7, §14)
- **C2.** Reframed the whole flow from "PII data-entry form submitted to a bureau,
  poll pass/fail/referred" to "select a government eID scheme → redirect hand-off →
  poll `eid_verification`." (§1, §3, §4, §6)
- **C3.** Replaced the request body (`first_name/last_name/date_of_birth/address/
  national_id`) with `{ scheme }` only. (§5, §8)
- **C4.** Replaced the response model (`verification_id/status/reason/retryable/
  created_at/expires_at:string`) with `EidStatusOut { eid_verification | null }` and
  `EidVerificationOut`/`EidVerifiedFieldsOut`/`EidDiscrepancyOut`. (§5)
- **C5.** Replaced the `EidvStatus` enum and `EidvField` PII enum with `EidScheme`,
  `EidAuthFlow`, `EidAssuranceLevel`, `EidDiscrepancySeverity`; reworked the UI state
  machine (SchemeSelection / AwaitingProvider / Result / Expired / Error). (§4)
- **C6.** Fixed `expires_at` type to integer epoch. (§4, §5)
- **C7.** Reworked DTOs and Retrofit signatures to the real shapes. (§5)
- **C8.** Corrected security framing: client transmits no PII; PII risk is on the
  status *response*; Bearer + CSRF auth; Custom Tab for redirect; redact
  `.../eid/*` bodies. (§8, §10, §15)
- **C9.** Added the case-scoping dependency on AND-319's case API. (§2, §12)
- **C10.** Resolved OQ-1/OQ-2; reframed OQ-3/OQ-4. (§13)
- **C11.** Telemetry/a11y/test/AC text updated to the corrected flow. (§9, §10, §11,
  §14)

### Open assumptions

- **OA-1.** How the mobile app receives the provider return for each `auth_flow`
  (deep link vs Custom Tab redirect to `/v1/kyc/eid/callback` vs manual return + poll).
  The API defines the callback but not the mobile redirect URI / deep-link scheme —
  not derivable from the sources. (Tracked as OQ-3.)
- **OA-2.** Whether `auto_tier_upgrade=true` means the client must NOT separately call
  AND-320 evaluate (to avoid a redundant re-fetch). Server semantics not specified in
  the schema description beyond the field name.
- **OA-3.** Exact outcome policy for `critical` discrepancies (does the backend mark
  the case failed/needs-review, or is it advisory only?). The schema exposes the
  discrepancy but not the resulting case decision; the client must not invent a
  pass/fail and instead reflect the case status from AND-319/AND-320.
- **OA-4.** Which schemes are enabled per environment/country at runtime — only
  discoverable at runtime via `GET /v1/kyc/eid/schemes`; not statically verifiable.
- **OA-5.** Client redirect mechanism (Custom Tabs) is an Android framework choice,
  not dictated by the contract (see citation 18).

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emulator** =
headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). MockWebServer is used for contract tests on JVM.

- **TC-AND-325-01** — Type: unit (JVM). Target: JVM. Preconditions: `EidvViewModel`
  with a fake repo returning a scheme list. Steps: load screen; assert
  `SchemeSelection` with the schemes; assert `canStart == false` before selection;
  select `eidas`; assert `canStart == true`. Expected: schemes render; Start gated on
  selection. Traces: AC-1.

- **TC-AND-325-02** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  MockWebServer enqueues `200` for `GET /v1/kyc/eid/schemes` with two
  `EidSchemeOut`s. Steps: call `eidSchemes("GB")`; assert request path/query
  `?country=GB`; assert deserialization of `id/name/countries/assurance_level/
  auth_flow/description`. Expected: correct path, query, and parsed scheme fields.
  Traces: AC-1.

- **TC-AND-325-03** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  draft `case_id` known; MockWebServer enqueues `200 StartEidVerificationOut`
  (`expires_at` as integer). Steps: `start(caseId, "eidas")`; assert
  `POST /v1/kyc/cases/{caseId}/eid/start`, JSON body `{"scheme":"eidas"}`, headers
  `Authorization: Bearer ...` and `X-CSRF-Token` present; assert parsed
  `session_id/redirect_url/expires_at:Long/scheme`. Expected: correct method/path/
  body/headers; integer `expires_at` parses. Traces: AC-2, AC-8 (header/PII).

- **TC-AND-325-04** — Type: unit (JVM). Target: JVM. Preconditions: ViewModel with
  fake repo. Steps: after a successful `start`, assert state → `AwaitingProvider` with
  `redirectUrl`/`sessionId`; assert `case_id`/`session_id`/`scheme` written to
  `SavedStateHandle`; simulate process recreation from the same `SavedStateHandle` and
  assert state is restored to `AwaitingProvider`. Expected: hand-off state survives
  rotation/process death. Traces: AC-2, AC-7.

- **TC-AND-325-05** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  MockWebServer enqueues for `eid/status`: first `200 {"eid_verification":null}`, then
  `200` with a present `EidVerificationOut` (no critical discrepancies). Steps: start
  polling; advance virtual time per backoff. Expected: UI advances awaiting → `Result`
  (success); `onDone(success)` emitted; `auto_tier_upgrade` propagated. Traces: AC-3,
  AC-4, AC-9.

- **TC-AND-325-06** — Type: unit (JVM). Target: JVM. Preconditions: fake repo returns
  an `EidVerificationOut` with a `discrepancies` entry `severity="critical"`. Steps:
  reduce status. Expected: `Result.hasCriticalDiscrepancy == true`; UI renders the
  review state listing `field`/`profile_value`/`eid_value`; with only
  `warning`/`match` it renders plain success. Traces: AC-5.

- **TC-AND-325-07** — Type: unit (JVM). Target: JVM. Preconditions: fake repo keeps
  returning `eid_verification == null`; `expires_at` set to a near-past epoch. Steps:
  poll until budget/`expires_at`. Expected: polling stops, state → `Expired`, no
  crash; `restart()` returns to `SchemeSelection` and clears `session_id`. Traces:
  AC-7.

- **TC-AND-325-08** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  MockWebServer enqueues `422 HTTPValidationError` (`detail:[{loc,msg,type}]`) for
  `eid/start` (e.g. unsupported scheme). Steps: `start(caseId,"bogus")`. Expected:
  mapped validation message surfaced on scheme selection; Start re-enabled; **no
  auto-retry** of the POST (assert exactly one request). Traces: AC-7, AC-2.

- **TC-AND-325-09** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions:
  authenticated session; MockWebServer enqueues `401` then expects
  `POST /ui/session/refresh` then a retried `200` for `eid/status`. Steps: poll once.
  Expected: single refresh-then-retry; `session_id`/`case_id`/`scheme` preserved; a
  second consecutive `401` surfaces a re-auth error (no infinite loop). Traces: AC-7.

- **TC-AND-325-10** — Type: unit (JVM). Target: JVM. Preconditions: repo `start`
  throws a connection failure (offline). Steps: tap Start. Expected:
  `Error(Retry.START)`; on retry the ViewModel first re-reads `eid/status` to detect a
  server-side completion before re-issuing `start`; no duplicate verification assumed.
  Traces: AC-7.

- **TC-AND-325-11** — Type: unit + DTO mapping (JVM). Target: JVM. Preconditions: JSON
  fixtures. Steps: deserialize `EidStatusOut` with `eid_verification:null`; with a full
  `EidVerificationOut` (each discrepancy severity + `verified_fields`); feed unknown
  `scheme`/`auth_flow`/`severity` strings. Expected: null and populated cases map
  correctly; unknown enum strings fall to the safe "unknown" bucket and are logged (no
  exception). Traces: AC-3.

- **TC-AND-325-12** — Type: Compose-UI (emulator). Target: emulator `test35`.
  Preconditions: ViewModel backed by scripted MockWebServer (start→session, status
  null→present), provider redirect stubbed. Steps: render `EidvRoute`; select scheme;
  tap Start; let status resolve. Expected: scheme list renders rows; Start disabled
  until selection; awaiting screen then success result render; `onDone` invoked. This
  is the **automated acceptance test**. Traces: AC-1, AC-2, AC-3, AC-9.

- **TC-AND-325-13** — Type: Compose-UI / accessibility (emulator). Target: emulator
  `test35` (with TalkBack assertions via `SemanticsMatcher`). Preconditions: scheme
  and result screens. Steps: assert each scheme row has a contentDescription incl.
  name/assurance/auth_flow and a selected-state semantics; assert outcome uses
  `liveRegion = Polite`; assert touch targets ≥ 48dp; verify dynamic font scaling and
  dark theme render without truncation. Expected: a11y semantics present and announced.
  Traces: AC-1, AC-3.

- **TC-AND-325-14** — Type: instrumented/e2e (device). Target: **physical device A15
  (must run on device)**. Preconditions: app pointed at dev host with the **mock
  provider** enabled; a draft KYC case created. Steps: start `eidas`; the app opens the
  `redirect_url` in a **Custom Tab** (real browser hand-off — validates the actual
  redirect/return path and deep-link callback that the emulator/CI cannot fully
  exercise); drive the mock provider (`/mock/eid/verify` → `/v1/kyc/eid/callback`);
  return to the app; poll status. Expected: real Custom Tab opens, callback completes,
  status returns a present `eid_verification`, success renders. Also confirms behavior
  on arm64-v8a / API 34 (vs the x86_64/API 35 emulator). Why device: real browser
  Custom Tab + deep-link return + arm64/API-34 coverage. Traces: AC-2, AC-3, AC-4.

- **TC-AND-325-15** — Type: manual / security (device or emulator). Target: emulator
  `test35` (or device). Preconditions: a status response containing `verified_fields`
  and a discrepancy with real-looking values; OkHttp logging at DEBUG. Steps: inspect
  logcat and any analytics sink during a full run. Expected: no `verified_fields` or
  `profile_value`/`eid_value` in logs/analytics; `.../eid/*` bodies redacted;
  `session_id`/`assertion_id`/`scheme` may appear; nothing persisted to Room/DataStore.
  Traces: AC-8.

- **TC-AND-325-16** — Type: unit + contract/MockWebServer (JVM). Target: JVM.
  Preconditions: open the screen for a `case_id` whose `GET .../eid/status` already
  returns a present `eid_verification` (completed). Steps: launch `EidvRoute`; observe
  initial load. Expected: the ViewModel reads status first and opens directly in
  `Result`, **skipping** `SchemeSelection`; no `eid/start` request is issued. Traces:
  AC-6.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-12, TC-13 |
| AC-2 | TC-03, TC-04, TC-08, TC-12, TC-14 |
| AC-3 | TC-05, TC-11, TC-12, TC-13, TC-14 |
| AC-4 | TC-05, TC-14 |
| AC-5 | TC-06 |
| AC-6 | TC-16 (resume into Result, scheme selection skipped); TC-11 (null vs present) |
| AC-7 | TC-04, TC-07, TC-08, TC-09, TC-10 |
| AC-8 | TC-03 (headers/no-PII body), TC-15 |
| AC-9 | TC-05, TC-12 |
