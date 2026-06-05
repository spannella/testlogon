---
id: AND-327
title: Proof of funds
milestone: M7
epic: E42
priority: P2
size: M
status: draft
depends_on: [AND-321]
blocks: []
---

# AND-327 — Proof of funds

## 1. Overview & Goal

This ticket delivers in-app **proof-of-funds (PoF) document submission** for the
TestLogon native Android client. A signed-in user who is required to evidence the
source of their funds — typically as part of advancing a KYC tier or satisfying a
compliance case (E42) — must be able to (a) see what proof-of-funds evidence is
required, (b) provide one or more supporting documents (bank statement, payslip,
deposit confirmation, etc.) by capturing or picking files, (c) optionally annotate
the submission with the declared source and amount, and (d) submit the
`kycProofOfFunds` record to the backend and observe its review status.

The functional bar from the backlog is exact and narrow: **`kycProofOfFunds`
document submission; proof submits + status.** This spec therefore scopes a single
PoF feature surface inside `feature-kyc`: a requirements/summary screen, a small
submission form, the wiring that uploads each supporting document, the
`kycProofOfFunds` registration call, and the status display that reflects the
backend review state (pending / approved / rejected / more-info).

This ticket does **not** re-specify document capture, the camera surface, image
compression, or the generic presign→PUT→confirm uploader — all of that is owned by
**AND-321 (Document capture + upload)** and is consumed here verbatim. It also does
not own the KYC transport DTOs (AND-319) nor tier/status requirements display
(AND-320); it consumes those types and patterns.

Success definition: a user who needs to prove source of funds can attach the
required supporting document(s) via the AND-321 capture/upload pipeline, submit a
`kycProofOfFunds` record with the declared source and amount, and then see an
accurate, refreshable submission status — with full test coverage of the
submit-then-status path.

## 2. Context & References

- Repo `spannella/testlogon`; Android app in `android/` (monorepo subfolder);
  branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android` (used everywhere a
  package appears).
- Feature module: **`feature-kyc`** (`com.testlogon.android.feature.kyc`). PoF
  code lives under `feature-kyc/prooffunds/` (screens, ViewModel) with repository
  surface added to `core-data` (`com.testlogon.android.core.data.kyc`).
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6 (cache), DataStore (prefs), Coil, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable — design for ~20 s timeouts, bounded backoff for idempotent GETs only,
  offline/stale UI). OpenAPI at `/openapi.json`; KYC endpoints under `/v1/kyc/*`.
- Web reference: `frontend/src/api/endpoints/kyc.ts` (look for the
  `proofOfFunds` / `proof_of_funds` calls) and shared types in
  `frontend/src/api/types.ts` — mirror snake_case wire keys; do not invent
  camelCase.
- **Dependency ticket — AND-321 (Document capture + upload):** provides the camera
  capture surface, `CaptureImageProcessor`, the navigation-result contract that
  returns confirmed `attachmentId`s, and the AND-129 `AttachmentUploader`
  (presign→PUT→confirm, progress/cancel/retry). PoF reuses this end to end to turn
  a captured/picked file into a confirmed `attachmentId`; this ticket only adds the
  PoF metadata form, the `kycProofOfFunds` registration call, and status display.
- **Consumed (not redefined):** AND-319 (`KycApi` + KYC DTOs, error enums,
  `@AppMoshiAdapter` hook), AND-320 (tier/status requirements UX patterns).
- Cross-cutting infra consumed: persistent cookie jar (AND-011), CSRF interceptor
  (AND-012), 401-refresh authenticator (AND-013), error/`detail` mapping (AND-015),
  retry-backoff for idempotent GETs (AND-016), connectivity probe (AND-017),
  `ApiResult<T>` (AND-018), Material 3 theme (AND-019), input composables
  (AND-020), state composables loading/empty/error/offline (AND-021), telemetry
  facade (AND-052), MockWebServer harness (AND-046).

## 3. Functional Requirements

FR-1 **Entry & requirement summary.** On entering the PoF flow the user sees a
summary screen describing the proof-of-funds requirement (sourced from
`GET /v1/kyc/proof-of-funds`, which returns the current submission if any, plus
the accepted document types and required metadata). If a submission already exists,
its current status is shown (Section FR-7) instead of an empty form.

FR-2 **Declared source & amount.** The submission form collects: a **source**
selection (an enum of accepted sources from the requirement, e.g.
`salary | savings | business_income | investment | gift | other`), an optional
free-text **source description** (required only when source is `other`), a
**declared amount** (decimal) and **currency** (ISO-4217 code, defaulted from the
requirement). Inputs reuse AND-020 core input composables and are validated client
side before submit (Section 7).

FR-3 **Supporting documents.** The user attaches one or more supporting documents.
Each attachment is produced by launching the AND-321 capture/upload flow (camera or
file pick) and receiving back a confirmed `attachmentId` via the navigation-result
contract. The PoF screen lists attached documents with a label, thumbnail (Coil),
and a remove action. At least one supporting document is required to submit
(server-driven minimum honored; default 1).

FR-4 **Submit.** When at least the required metadata and the minimum number of
confirmed attachments are present, **Submit** is enabled. Submit calls
`POST /v1/kyc/proof-of-funds` with the source, description, declared amount,
currency, and the ordered list of confirmed `attachmentId`s. The call is
non-idempotent and excluded from the AND-016 GET retry policy.

FR-5 **Submission feedback.** On `201`, the screen transitions to the status view
showing the returned submission (id + status). On validation failure (`422`),
field-level errors are mapped from the FastAPI `detail` list and rendered inline.

FR-6 **Status display & refresh.** The status view renders the current
`kycProofOfFunds` status as one of: `pending_review`, `approved`, `rejected`,
`more_info_required`. For `rejected` / `more_info_required` the backend
`review_note` is shown and a **Resubmit / Provide more** affordance re-enters the
form (pre-filled where possible). The view supports pull-to-refresh re-reading
`GET /v1/kyc/proof-of-funds`.

FR-7 **Idempotent read on return.** Re-entering the flow always reads the latest
submission state first (cache-then-network, Section 6) so status is current after
backend review without requiring re-submission.

FR-8 **No duplicate submit.** While a submission is `pending_review` or `approved`,
the form is not re-openable for a fresh submit; only `rejected` /
`more_info_required` enable resubmission. This prevents accidental duplicate PoF
records.

## 4. Technical Design

Single-Activity Navigation-Compose. New routes registered in `feature-kyc`:

```
kyc/proof-of-funds            -> ProofOfFundsScreen (summary + status host)
kyc/proof-of-funds/submit     -> ProofOfFundsFormScreen
```

The PoF capture/file-pick is **not** a new route here; it deep-links into the
AND-321 capture route (`kyc/capture/{templateId}` with a `proof_of_funds`
template id) and consumes its `attachmentId` navigation result.

ViewModel exposes `StateFlow<UiState>` per layering rules:

```kotlin
@HiltViewModel
class ProofOfFundsViewModel @Inject constructor(
    private val repository: ProofOfFundsRepository,   // added here, types from AND-319
    private val connectivity: ConnectivityObserver,   // AND-017
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<ProofOfFundsUiState>
    fun load(forceRefresh: Boolean = false)
    fun onSourceChanged(source: PoFSource)
    fun onSourceDescriptionChanged(text: String)
    fun onAmountChanged(raw: String)
    fun onCurrencyChanged(code: String)
    fun onAttachmentAdded(attachmentId: String, label: String)
    fun onAttachmentRemoved(attachmentId: String)
    fun submit()
    fun onResubmit()
    fun retry()
}

sealed interface ProofOfFundsUiState {
    data object Loading : ProofOfFundsUiState
    data class Status(                                  // existing submission
        val submission: ProofOfFunds,
        val canResubmit: Boolean,
        val refreshing: Boolean = false,
    ) : ProofOfFundsUiState
    data class Form(                                    // new / resubmission
        val requirement: PoFRequirement,
        val source: PoFSource? = null,
        val sourceDescription: String = "",
        val amountRaw: String = "",
        val currency: String,
        val attachments: List<PoFAttachment> = emptyList(),
        val fieldErrors: Map<String, String> = emptyMap(),
        val submitting: Boolean = false,
        val submitEnabled: Boolean = false,
    ) : ProofOfFundsUiState
    data class Error(val error: UiError, val retryable: Boolean) : ProofOfFundsUiState
    data object Offline : ProofOfFundsUiState
}

data class PoFAttachment(val attachmentId: String, val label: String)
enum class PoFSource(val token: String) {
    SALARY("salary"), SAVINGS("savings"), BUSINESS_INCOME("business_income"),
    INVESTMENT("investment"), GIFT("gift"), OTHER("other");
    companion object { fun fromToken(t: String) = entries.firstOrNull { it.token == t } ?: OTHER }
}
```

Domain models (`core-model`, mapped from AND-319-style DTOs by the repository):

```kotlin
enum class PoFStatus { PENDING_REVIEW, APPROVED, REJECTED, MORE_INFO_REQUIRED, UNKNOWN }

data class ProofOfFunds(
    val id: String,
    val status: PoFStatus,
    val source: PoFSource,
    val declaredAmountMinor: Long,      // amount in minor units
    val currency: String,
    val attachmentIds: List<String>,
    val reviewNote: String? = null,
    val submittedAt: String,            // ISO-8601
    val reviewedAt: String? = null,
)

data class PoFRequirement(
    val acceptedSources: List<PoFSource>,
    val minDocuments: Int,
    val defaultCurrency: String,
    val acceptedFormats: List<String>,
)
```

Repository surface (added here; DTOs and `KycApi` extension from AND-319):

```kotlin
interface ProofOfFundsRepository {
    /** Cache-then-network read of the current PoF requirement + submission. */
    fun observe(): Flow<ApiResult<ProofOfFundsState>>
    suspend fun refresh(): ApiResult<ProofOfFundsState>
    suspend fun submit(req: SubmitProofOfFunds): ApiResult<ProofOfFunds>
}

data class ProofOfFundsState(
    val requirement: PoFRequirement,
    val submission: ProofOfFunds?,      // null when nothing submitted yet
)

data class SubmitProofOfFunds(
    val source: PoFSource,
    val sourceDescription: String?,
    val declaredAmountMinor: Long,
    val currency: String,
    val attachmentIds: List<String>,
)
```

Amount handling: the form captures a decimal string; the ViewModel parses to minor
units using the selected currency's fraction digits (`java.util.Currency
.getInstance(code).defaultFractionDigits`) and rejects malformed/negative input
client side. The wire field is `declared_amount_minor` (integer) plus `currency`,
avoiding float rounding.

Adding/removing attachments mutates `Form.attachments`. The capture/upload itself
runs entirely inside the AND-321 flow; PoF only stores returned `attachmentId`s in
`SavedStateHandle` so they survive process death before submit.

## 5. API Contract

This ticket adds two PoF operations to the KYC surface (declared as extra methods
on `KycApi` / a thin `ProofOfFundsApi`, DTOs in `core-model`, owned by AND-319's
serialization conventions). Upload mechanics (presign→PUT→confirm) are AND-321 /
AND-129 and are not redefined here.

**GET `v1/kyc/proof-of-funds`** — requirement + current submission (idempotent;
eligible for AND-016 backoff).

```
Response 200:
{
  "requirement": {
    "accepted_sources": ["salary", "savings", "business_income", "gift", "other"],
    "min_documents": 1,
    "default_currency": "USD",
    "accepted_formats": ["jpeg", "png", "pdf"]
  },
  "submission": {
    "id": "pof_a1b2",
    "status": "more_info_required",
    "source": "salary",
    "declared_amount_minor": 250000,
    "currency": "USD",
    "attachments": ["att_9f2c", "att_0b71"],
    "review_note": "Statement is older than 90 days; please upload a recent one.",
    "submitted_at": "2026-06-01T09:00:00Z",
    "reviewed_at": "2026-06-03T11:20:00Z"
  }
}
```
`submission` is `null` when nothing has been submitted. `401` → AND-013
refresh-then-retry once.

**POST `v1/kyc/proof-of-funds`** — submit / resubmit (non-idempotent; **not**
retried by AND-016).

```
Headers: X-CSRF-Token: <ui_csrf cookie value>   (cookie-based session, AND-012)
Content-Type: application/json
Request:
{
  "source": "salary",
  "source_description": null,            // required only when source == "other"
  "declared_amount_minor": 250000,
  "currency": "USD",
  "attachments": ["att_9f2c", "att_3d4e"]   // ordered, confirmed attachment ids
}
Response 201:
{
  "id": "pof_a1b2",
  "status": "pending_review",
  "source": "salary",
  "declared_amount_minor": 250000,
  "currency": "USD",
  "attachments": ["att_9f2c", "att_3d4e"],
  "review_note": null,
  "submitted_at": "2026-06-05T12:00:00Z",
  "reviewed_at": null
}
```

Error envelope: FastAPI `detail` union (`string | [{msg,type,loc}] | {code,...}`)
mapped by AND-015. `422` validation maps `detail[].loc` to the corresponding form
field (e.g. `loc: ["body","declared_amount_minor"]` → amount field error).
`409` (a non-resubmittable submission already exists) maps to a friendly
"already submitted" state. DTOs (`PoFRequirementDto`, `PoFSubmissionDto`,
`PoFStateResp`, `SubmitPoFReq`) follow AND-319 conventions:
`@JsonClass(generateAdapter = true)`, snake_case `@Json(name=…)`, enum tokens via
a `PoFStatus`/`PoFSource` Moshi adapter with `UNKNOWN`/`OTHER` fallback registered
on the shared `Moshi` via `@AppMoshiAdapter`.

## 6. Data & State Management

- **Transient form state** lives in `ProofOfFundsViewModel` (`StateFlow`) plus
  `SavedStateHandle` for: selected source, description, amount string, currency,
  and the list of confirmed `attachmentId`s (to survive process death before
  submit). No image bytes are held — only ids.
- **Read caching (SWR):** `ProofOfFundsState` is cached in Room via the AND-116
  cache-repository pattern under a single-row `kyc_proof_of_funds` table keyed by
  user id, with a short TTL (e.g. 5 min) and stale-allowed reads. `observe()`
  emits cached-then-network; `refresh()` forces a network read. This satisfies the
  offline/stale baseline (status visible offline, marked stale).
- **No DataStore keys** are added. Currency default comes from the requirement, not
  a persisted pref.
- **Mappers:** DTO→domain mapping (`PoFSubmissionDto.toDomain()`,
  `PoFRequirementDto.toDomain()`) lives in `core-data`; ISO-8601 timestamps stay
  `String` at the DTO layer and are parsed for display in the ViewModel.
- **Attachment ids** are the only cross-flow state shared with AND-321; they are
  passed back via the Navigation-Compose `savedStateHandle` result pattern on
  returning from the capture route.
- **Cache invalidation:** a successful `submit()` writes the returned submission
  into the Room row immediately (optimistic-after-confirm), so the status view is
  correct without an extra round trip.

## 7. Error Handling & Resilience

- **Client validation (pre-submit):** source required; `source_description`
  required when source is `OTHER`; amount must parse to a positive integer in minor
  units; currency must be a valid ISO-4217 code; attachments ≥ `min_documents`.
  Failures populate `Form.fieldErrors` and disable Submit; no network call is made.
- **`422` server validation:** mapped via AND-015 from `detail[].loc` to field
  errors; non-field `detail` strings surface as a form-level banner.
- **`409` already-submitted:** transition to the `Status` view with
  `canResubmit=false` and an explanatory message; never silently duplicate.
- **Submit timeout / transport failure:** `POST /v1/kyc/proof-of-funds` is
  non-idempotent → **not** auto-retried (per AND-016 policy). On
  `SocketTimeoutException`/`IOException` (~20 s OkHttp timeout) show a retry-able
  error; the user re-taps Submit. Confirmed `attachmentId`s remain in state so
  resubmission does **not** re-upload documents.
- **`401`:** handled transparently by the AND-013 authenticator (one refresh +
  retry); a second `401` routes to an auth-expired state (AND-025).
- **Offline:** the AND-017 connectivity probe gates Submit (disabled offline with
  an offline banner from AND-021). The status read still renders cached data marked
  stale; a reconnect re-reads via `refresh()`.
- **Read failures:** `GET` failures fall back to cached `ProofOfFundsState` if
  present (stale badge); if no cache, render the AND-021 error state with retry.
- **Attachment flow failures** (capture/upload) are owned and surfaced by AND-321;
  PoF simply does not receive an `attachmentId` and the document is not added.

## 8. Security & Privacy

- Proof-of-funds documents and the declared source/amount are sensitive financial
  PII. **No document bytes ever pass through this ticket** — only confirmed
  `attachmentId`s; capture/storage hygiene (internal-cache-only, delete-after-
  confirm, no `MediaStore`) is enforced by AND-321.
- **Request bodies must not be logged.** The `v1/kyc/proof-of-funds` POST path is
  added to the AND-009 redacting `HttpLoggingInterceptor` redaction list (declared
  here as a constraint for AND-009). `SubmitPoFReq.toString()` masks amount and
  description:
  `"SubmitPoFReq(source=$source, amount=***, currency=$currency, attachments=$attachmentIds)"`.
- Session is cookie-based; the CSRF token rides as `X-CSRF-Token` (AND-012). No
  manual `Cookie`/`Authorization` headers are declared.
- On `dev` these calls ride plaintext HTTP — a known dev-only risk permitted by the
  scoped cleartext config (AND-006); only synthetic data is exercised against the
  dev host. `staging`/`prod` are HTTPS-only.
- Telemetry (Section 10) records metadata only — never the amount value, source
  description text, document content, or signed attachment URLs.
- Recommend `FLAG_SECURE` on the PoF form/status surfaces (financial PII visible
  on-screen); flagged as an open question pending product decision (Section 13).

## 9. Accessibility & i18n

- All static UI strings live in `strings.xml` (no hardcoded copy in composables);
  server-supplied strings (`review_note`, source labels if server-provided) are
  passed through. Source enum tokens map to localized labels in
  `strings.xml` (`pof_source_salary`, etc.).
- Form fields have associated labels and error text exposed via Compose semantics
  (`error` semantics on invalid fields); the amount field uses a numeric/decimal
  keyboard and announces currency.
- Status changes (e.g. submit success, refresh result) are announced via a
  `liveRegion`; the status chip has a `contentDescription` conveying the textual
  status, not color alone.
- All interactive controls (Submit, Add document, Remove, Resubmit, refresh) have
  `contentDescription`s and ≥48 dp touch targets; operable under TalkBack.
- Respects dynamic font scaling, dark theme, and RTL readiness via the Material 3
  theme (AND-019); no fixed-width text containers that clip translations.

## 10. Telemetry & Logging

Use the redacted telemetry facade (AND-052 pattern). Events (metadata only):

- `pof_viewed` { has_submission, status }
- `pof_form_opened` { resubmission }
- `pof_document_added` { document_count }
- `pof_document_removed` { document_count }
- `pof_submit_attempted` { source, document_count, currency }
- `pof_submit_succeeded` { pof_id, status }
- `pof_submit_failed` { error_code }
- `pof_status_refreshed` { status }

No amount values, description text, document bytes, signed URLs, or raw response
bodies are logged. Failures log the mapped `ApiError.code` only. HTTP logging is
inherited from the AND-009 redacting interceptor (debug builds), with the PoF POST
body redacted (Section 8).

## 11. Testing Strategy

Acceptance: **proof submits + status** — proven end to end with MockWebServer +
Compose, on the headless emulator (AND-051) and JVM (AND-050).

**Unit (JVM, core-testing + MockWebServer):**
- `ProofOfFundsViewModel` state machine: load with existing `more_info_required`
  submission → `Status(canResubmit=true)`; `onResubmit` → `Form` pre-filled;
  add attachment + fill metadata → `submitEnabled=true`; `submit()` success →
  `Status(pending_review)`. Assert `StateFlow` transitions.
- Validation: missing source / `other` without description / non-positive amount /
  zero attachments each set `fieldErrors` and keep `submitEnabled=false`; no
  network call.
- Amount conversion: decimal string → `declared_amount_minor` using currency
  fraction digits (USD `2.50` → `250`; JPY `250` → `250`); malformed rejected.
- Resubmit-without-reupload: after a submit timeout, confirmed `attachmentId`s
  remain in state and a second `submit()` sends the same ids (no upload invoked).
- `ProofOfFundsRepository`: `GET /v1/kyc/proof-of-funds` and
  `POST /v1/kyc/proof-of-funds` request/response shapes — POST body contains
  ordered `attachments`, `source`, `declared_amount_minor`, `currency`; 201 maps to
  `ProofOfFunds`; `null` submission maps to `ProofOfFundsState(submission=null)`;
  `422`/`409`/`401` mapped via AND-015. SWR cache: cached-then-network emission and
  write-through on submit.
- DTO round-trip: `PoFStateResp`/`SubmitPoFReq` (de)serialize snake_case keys and
  lowercase enum tokens; unknown status → `UNKNOWN`; committed fixtures under
  `core-model/src/test/resources/kyc/pof_*.json`.
- Redaction: `SubmitPoFReq.toString()` does not contain the amount or description.

**Instrumented / Compose UI tests:**
- Status view renders each status (pending/approved/rejected/more-info) with the
  correct label and `review_note` where present; resubmit affordance only for
  rejected/more-info.
- Form: filling required fields and adding a (fake) attachment enables Submit;
  tapping Submit issues the POST to MockWebServer and the UI reaches the status
  view. Attachment add is simulated by injecting an `attachmentId` via the
  navigation-result seam (no real camera).
- Offline state disables Submit and shows the offline banner; cached status still
  renders with a stale badge.
- `422` from the POST renders the mapped field error inline.

**Definition of "tested submit + status":** an instrumented test that fills the
PoF form, simulates an attached `attachmentId`, asserts the
`POST /v1/kyc/proof-of-funds` request body (ordered attachments + metadata) hits
MockWebServer, and the UI transitions to a `pending_review` status view; plus a
test that a subsequent `GET` reflecting `approved` updates the status on refresh.

## 12. Dependencies & Sequencing

- **Hard dep (must merge first):**
  - **AND-321 (Document capture + upload)** — provides the capture/file-pick flow,
    the AND-129 `AttachmentUploader`, and the navigation-result contract that yields
    confirmed `attachmentId`s. PoF cannot attach documents without it.
- **Transitively relied on:** AND-319 (`KycApi` + KYC DTO/adapter conventions and
  `@AppMoshiAdapter` hook), AND-320 (tier/requirements UX patterns), AND-116 (SWR
  cache pattern), AND-011/AND-012/AND-013 (cookie/CSRF/refresh), AND-015 (error
  mapping), AND-016 (GET backoff), AND-017 (connectivity), AND-018 (`ApiResult`),
  AND-019 (theme), AND-020 (inputs), AND-021 (state composables), AND-046
  (MockWebServer harness), AND-052 (telemetry).
- **New library:** none. PoF adds source files to `feature-kyc` and `core-data`,
  plus PoF DTOs/methods following AND-319 conventions.
- **Blocks:** none listed in the backlog. Downstream KYC tier-advancement /
  compliance-case screens (E42) may surface the PoF entry point but are not gated by
  a declared id here.
- **Sequencing within ticket:** (1) PoF DTOs + Moshi enum adapter + `KycApi`
  PoF methods, (2) `ProofOfFundsRepository` + mappers + Room cache row, (3)
  `ProofOfFundsViewModel` state machine + amount conversion, (4) Compose status +
  form screens wired to the AND-321 capture result, (5) tests.

## 13. Risks & Open Questions

- **R-1 Endpoint shape.** The PoF path (`/v1/kyc/proof-of-funds`) and field names
  (`declared_amount_minor`, `source`, `attachments`) are inferred from the KYC
  surface and the web reference. Confirm against `/openapi.json` and
  `frontend/src/api/endpoints/kyc.ts` before merge. Open.
- **R-2 Amount representation.** Assumes integer minor units + ISO-4217 currency.
  If the backend expects a decimal string or major-unit float, the conversion and
  DTO change. Open — verify schema.
- **R-3 Source enum set.** The accepted-sources list is assumed; the `OTHER`
  fallback prevents crashes but the UI must label unmodeled sources gracefully.
  Confirm the canonical set from the requirement response. Open.
- **R-4 Resubmission semantics.** Assumes resubmit reuses the same endpoint and
  supersedes the prior submission. If the backend exposes a distinct resubmit /
  more-info endpoint or requires a `case_id`, the submit call changes. Open —
  verify with AND-319/backend.
- **R-5 Single vs. multiple submissions.** Assumes one active PoF submission per
  user; `409` guards duplicates. If multiple concurrent submissions are allowed,
  the status view becomes a list. Open.
- **R-6 `FLAG_SECURE`.** Financial PII on-screen suggests screenshot blocking on
  the PoF surfaces; not specified — needs product decision. Open.
- **R-7 PII redaction gap.** If AND-009's redaction list lacks
  `v1/kyc/proof-of-funds`, the POST body could leak to logcat in debug. Mitigation:
  add the path to AND-009's redaction set; assert via `toString()` redaction test.

## 14. Acceptance Criteria

AC-1 A signed-in user with a proof-of-funds requirement can open the PoF flow and
see either the submission form (no prior submission) or the current submission
status. (Backlog: "`kycProofOfFunds` document submission.")

AC-2 The user can declare a source, optional description (required for `other`),
declared amount, and currency, and attach ≥ `min_documents` supporting documents
via the AND-321 capture/upload flow, receiving confirmed `attachmentId`s.

AC-3 With required metadata and the minimum attachments present, Submit issues
`POST /v1/kyc/proof-of-funds` with the correct `source`, `declared_amount_minor`,
`currency`, and ordered `attachments`; on `201` the UI shows the returned
submission in a status view. (Backlog: "proof submits.")

AC-4 The status view accurately renders `pending_review`, `approved`, `rejected`,
and `more_info_required`, shows `review_note` for the latter two, supports refresh,
and offers resubmission only for `rejected` / `more_info_required`. (Backlog:
"+ status.")

AC-5 Client validation, `422` (field errors), `409` (already submitted), timeout,
offline, and `401` each produce a non-crashing, retry-able/appropriate state; a
resubmit after a submit failure does **not** re-upload already-confirmed documents.

AC-6 No document bytes, amount values, source-description text, or signed URLs
appear in logs or telemetry; the `v1/kyc/proof-of-funds` POST body is redacted.

AC-7 An automated test (MockWebServer + Compose, headless emulator) fills the form,
simulates an attached `attachmentId`, asserts the submit request shape, and asserts
the UI reaches a `pending_review` status view, plus a refresh reflecting `approved`.
(Backlog: "tested submit + status.")

## 15. Definition of Done

- All Acceptance Criteria (Section 14) met and demonstrated.
- PoF flow implemented in `feature-kyc` (`com.testlogon.android.feature.kyc`):
  `ProofOfFundsViewModel`, `ProofOfFundsScreen`, `ProofOfFundsFormScreen`, the
  routes in Section 4, and the navigation-result wiring into the AND-321 capture
  flow; `ProofOfFundsRepository` + mappers + Room cache row in `core-data`.
- PoF DTOs/`KycApi` methods + the `PoFStatus`/`PoFSource` Moshi adapter follow
  AND-319 conventions (snake_case, `@JsonClass`, `@AppMoshiAdapter` registration);
  no new networking client/Retrofit/Moshi instance.
- No new third-party library; capture/upload reused from AND-321/AND-129 with no
  duplication.
- Unit tests (ViewModel state machine, amount conversion, repository
  request/response + SWR cache, DTO round-trip, redaction) and instrumented
  Compose/UI tests pass locally and in CI (AND-050 / AND-051); committed fixtures
  under `core-model/src/test/resources/kyc/`.
- Lint, ktlint/detekt (AND-005) clean; no new warnings.
- No financial PII (amount, description, document bytes) or signed URLs in
  logs/telemetry; `v1/kyc/proof-of-funds` POST body added to AND-009 redaction list.
- Open questions in Section 13 resolved against `/openapi.json` /
  `frontend/src/api/endpoints/kyc.ts` / product, or tracked as follow-ups.
- Code reviewed and merged to `android-port`.
