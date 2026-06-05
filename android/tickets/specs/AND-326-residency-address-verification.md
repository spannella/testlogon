---
id: AND-326
title: Residency / address verification
milestone: M7
epic: E42
priority: P2
size: M
status: draft
depends_on: [AND-321, AND-319, AND-129]
blocks: []
---

# AND-326 — Residency / address verification

## 1. Overview & Goal

This ticket delivers the residency / address-verification step of the TestLogon
native Android KYC flow. The user must be able to (a) enter or confirm their
structured residential address, (b) select a residency proof document type from a
server-driven list (utility bill, bank statement, government letter, tenancy
agreement, etc.), (c) capture or pick a proof document image/PDF, (d) upload it
through the reusable attachment pipeline, and (e) submit the address + proof for
verification, then observe the resulting verification status (`pending_review`,
`verified`, `rejected`).

The functional bar from the backlog is: **address proof submits and verifies.**
The backend exposes this as the `kycResidency` / `kycAddressVerification` surface.
This spec scopes the address-entry form, the proof-type picker, the capture/pick +
upload wiring, the submit call, and the verification-status surface. It does **not**
re-specify the camera capture surface (AND-321), the generic uploader (AND-129), nor
the KYC DTOs/Retrofit base (AND-319); it consumes all three.

Success: a signed-in user at the residency tier can fill in a valid address, attach
a proof document (captured via AND-321 or picked from files), upload it, submit via
the `kycAddressVerification` endpoint, and see the case reach `pending_review` (and,
on a later read, `verified` or `rejected`).

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/`, branch `android-port`.
  Namespace / applicationId base `com.testlogon.android`. Feature module
  `feature-kyc` (`com.testlogon.android.feature.kyc`); residency screens under
  `feature-kyc/residency/`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore,
  Coil, Paging 3. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable — ~20 s timeouts, bounded backoff retry for idempotent GETs only,
  offline/stale states). OpenAPI at `/openapi.json`. KYC endpoints under `/v1/kyc/*`.
  Web reference `frontend/src/api/endpoints/kyc.ts`; shared types in
  `frontend/src/api/types.ts` (`kycResidency` / `kycAddressVerification`).
- Dependency tickets:
  - **AND-321 — Document capture + upload**: provides `DocumentCaptureController`
    (CameraX capture seam) and `CaptureImageProcessor` (EXIF fix, downsize ≤4 MB /
    2048 px / q85), reused for the proof capture/processing path.
  - **AND-319 — KYC API + DTOs**: provides `KycApi`, `KycRequirementsDto`, and the
    `/v1/kyc/*` Retrofit surface. Residency DTOs/methods are added following its
    conventions; the base is not redefined.
  - **AND-129 — Attachment pipeline (presign→PUT→confirm)**: provides
    `AttachmentUploader` (progress/cancel/retry), invoked once for the proof file.
- Cross-cutting infra: cookie jar (AND-011), CSRF (AND-012), 401-refresh (AND-013),
  `ApiResult<T>` (AND-018), error mapping (AND-015), GET retry/backoff (AND-016),
  connectivity (AND-017), theme (AND-019), inputs (AND-020), state composables
  (AND-021), SWR cache (AND-116), MockWebServer (AND-046), telemetry (AND-052).

## 3. Functional Requirements

FR-1 **Address entry.** Present a structured form: `line1`, `line2` (optional),
`city`, `state/region`, `postal_code`, `country` (ISO-3166 alpha-2, dropdown). The
form pre-fills from any existing `kycResidency` record returned by the read endpoint.
Required-field and format validation runs client-side before submit (FR-7).

FR-2 **Proof-type selection.** Present the list of accepted residency proof types
sourced from `KycRequirementsDto.residency.acceptedProofTypes` (AND-319), e.g.
"Utility bill", "Bank statement", "Government letter", "Tenancy agreement". The
user picks exactly one before attaching a document.

FR-3 **Proof attachment — capture or pick.** The user attaches one proof document
via either (a) camera capture using the AND-321 `DocumentCaptureController`
(single page, processed through `CaptureImageProcessor`), or (b) the system
document picker (`ACTION_OPEN_DOCUMENT`) for an existing image or PDF. A thumbnail
(image) or file chip (PDF) preview is shown with a **Replace** / **Remove** action.

FR-4 **Accepted formats & size.** Accepted MIME types: `image/jpeg`, `image/png`,
`application/pdf`. Captured images are JPEG (AND-321 processor output). Picked files
must be ≤ 10 MB; oversized or unsupported files are rejected inline with a prompt to
choose another.

FR-5 **Upload.** On attach, the proof file uploads via the AND-129
`AttachmentUploader` (presign → PUT → confirm), yielding a single `attachmentId`.
Progress is shown; upload is cancelable. No submit is possible until upload confirms.

FR-6 **Submit for verification.** With a valid address, a selected proof type, and a
confirmed `attachmentId`, the user submits via
`POST /v1/kyc/residency/verifications`. Success returns a verification record whose
`status` is typically `pending_review`; the UI shows a submitted/pending state.

FR-7 **Validation.** Required fields enforced: `line1`, `city`, `postal_code`,
`country`, proof type, and a confirmed proof attachment. `postal_code` validated
against a country-aware non-empty pattern (lenient; server is authoritative).
`country` must be a valid ISO-3166 alpha-2 code from the dropdown. The submit button
is disabled until all are satisfied.

FR-8 **Status surface.** On entry and after submit, the screen reads the current
residency record (`GET /v1/kyc/residency`) and renders one of: `none` (no record →
show form), `pending_review` (submitted, awaiting review), `verified` (success,
read-only summary), `rejected` (show `rejection_reason` and allow re-submit).

FR-9 **Re-submit.** From `rejected`, the user can edit the address and/or attach a
new proof and submit again, producing a new verification record.

## 4. Technical Design

Single-Activity Navigation-Compose. New routes registered in `feature-kyc`:

```
kyc/residency            -> ResidencyScreen        (form + status host)
kyc/residency/capture    -> reuses AND-321 DocumentCaptureScreen (single page)
```

ViewModel exposes `StateFlow<UiState>` per layering rules.

```kotlin
@HiltViewModel
class ResidencyViewModel @Inject constructor(
    private val kycRepository: KycRepository,            // AND-319 surface, extended here
    private val uploader: AttachmentUploader,            // AND-129
    private val imageProcessor: CaptureImageProcessor,   // AND-321
    private val contentResolverFiles: FileResolver,      // SAF uri -> cache file
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<ResidencyUiState>
    fun onScreenEntered()
    fun onFieldChanged(field: AddressField, value: String)
    fun onProofTypeSelected(proofType: String)
    fun onProofCaptured(file: java.io.File)             // from AND-321 capture
    fun onProofPicked(uri: android.net.Uri)             // from ACTION_OPEN_DOCUMENT
    fun onRemoveProof()
    fun cancelUpload()
    fun submit()
    fun retrySubmit()
}

sealed interface ResidencyUiState {
    data object Loading : ResidencyUiState
    data class Editing(
        val form: AddressForm,
        val acceptedProofTypes: List<ProofType>,
        val selectedProofType: String?,
        val proof: ProofAttachment?,        // null until attached
        val validation: ValidationErrors,
        val submitEnabled: Boolean,
    ) : ResidencyUiState
    data class UploadingProof(val progress: Float) : ResidencyUiState
    data class Submitting(val form: AddressForm) : ResidencyUiState
    data class Pending(val record: KycResidencyDto) : ResidencyUiState
    data class Verified(val record: KycResidencyDto) : ResidencyUiState
    data class Rejected(val record: KycResidencyDto, val reason: String?) : ResidencyUiState
    data class Error(val error: UiError, val retryable: Boolean) : ResidencyUiState
    data class Offline(val cached: KycResidencyDto?) : ResidencyUiState
}

data class AddressForm(
    val line1: String = "", val line2: String = "",
    val city: String = "", val region: String = "",
    val postalCode: String = "", val country: String = "",
)

data class ProofAttachment(
    val localFile: java.io.File?,   // null for picked PDFs streamed directly
    val mime: String,
    val displayName: String,
    val attachmentId: String?,      // set once AND-129 confirm completes
)
```

Repository surface (added here, DTOs from AND-319 conventions):

```kotlin
interface KycRepository {
    suspend fun residency(): ApiResult<KycResidencyDto?>          // GET, idempotent
    suspend fun submitResidency(
        address: KycAddressDto,
        proofType: String,
        attachmentId: String,
    ): ApiResult<KycResidencyDto>                                 // POST, non-idempotent
}
```

Attach flow:
- **Capture path**: reuse AND-321 `DocumentCaptureScreen` for a single page; the
  captured `File` is run through `CaptureImageProcessor` (EXIF fix, downsize to
  ≤4 MB / 2048 px / q85) before upload.
- **Pick path**: `ACTION_OPEN_DOCUMENT` with MIME filter
  `["image/jpeg","image/png","application/pdf"]`; `FileResolver` copies the SAF
  `Uri` into `cacheDir/kyc-residency/<sessionId>/` (persisting a stable file for
  upload + retry) and reads `displayName` + size for the size cap (FR-4).

Upload uses the AND-129 `AttachmentUploader` with the file's MIME type, surfacing
progress into `UploadingProof`. On confirm the `attachmentId` is stored in
`ProofAttachment` and the screen returns to `Editing` with `submitEnabled`
recomputed.

Submit builds `KycAddressDto` from `AddressForm`, calls
`KycRepository.submitResidency(...)`, and maps the returned `KycResidencyDto.status`
to `Pending`/`Verified`/`Rejected`. Cache files for the session are deleted after a
successful submit and on screen exit; an orphan sweeper (shared with AND-321)
deletes session dirs older than 24 h.

## 5. API Contract

This ticket adds two residency calls to the AND-319 `/v1/kyc/*` surface and reuses
the AND-129 attachment pipeline for the proof file.

**Read current residency record** (idempotent GET; eligible for AND-016
retry/backoff):

```
GET /v1/kyc/residency
Headers: X-CSRF-Token: <ui_csrf cookie value>   (cookie-based session)
Response 200 (existing record):
{
  "id": "kycres_7a1d",
  "status": "pending_review",            // none | pending_review | verified | rejected
  "address": {
    "line1": "221B Baker Street", "line2": null,
    "city": "London", "region": null,
    "postal_code": "NW1 6XE", "country": "GB"
  },
  "proof_type": "utility_bill",
  "attachment_id": "att_9f2c...",
  "rejection_reason": null,
  "submitted_at": "2026-06-05T12:00:00Z",
  "updated_at": "2026-06-05T12:00:00Z"
}
Response 200 (no record yet): { "status": "none", "address": null }
```

**Submit address + proof for verification** (non-idempotent POST; **excluded** from
the AND-016 GET retry policy):

```
POST /v1/kyc/residency/verifications
Headers: X-CSRF-Token: <ui_csrf cookie value>
Request:
{
  "address": {
    "line1": "221B Baker Street", "line2": null,
    "city": "London", "region": null,
    "postal_code": "NW1 6XE", "country": "GB"
  },
  "proof_type": "utility_bill",
  "attachment_id": "att_9f2c..."
}
Response 201:
{
  "id": "kycres_7a1d",
  "status": "pending_review",
  "address": { ...echoed... },
  "proof_type": "utility_bill",
  "attachment_id": "att_9f2c...",
  "rejection_reason": null,
  "submitted_at": "2026-06-05T12:00:00Z"
}
```

**Accepted proof types** come from `GET /v1/kyc/requirements`
(`requirements.residency.accepted_proof_types: [{ "key": "utility_bill",
"label": "Utility bill" }, ...]`), owned by AND-319 and consumed here.

**Attachment pipeline (AND-129)** — invoked once: input = local file + its MIME
(`image/jpeg` | `image/png` | `application/pdf`); output = confirmed
`attachment_id: String`. Presign/PUT/confirm shapes are owned by AND-129.

FastAPI error bodies follow the standard `detail` mapping (string | `[{msg}]` |
`{code,...}`) handled by AND-015. Field-level 422 validation errors (`[{loc,msg}]`)
are mapped back onto the corresponding `AddressField` where `loc` identifies the
field, otherwise shown as a form-level error.

## 6. Data & State Management

- **Form + transient state** live in `ResidencyViewModel` (`StateFlow`). The
  `AddressForm`, `selectedProofType`, and proof cache file path are mirrored into
  `SavedStateHandle` to survive process death/config changes during entry.
- **Proof file bytes** live as files in `cacheDir/kyc-residency/<sessionId>/`, never
  in memory beyond streaming and never in Room. Deleted on successful submit, on
  remove/replace, on screen exit, and via the shared 24 h orphan sweeper (AND-321).
- **Read caching**: the `KycResidencyDto` from `GET /v1/kyc/residency` may be cached
  via the AND-116 SWR/cache-repository pattern keyed `kyc_residency:<userId>` to
  serve a stale read in the `Offline` state; the cached record is the source for
  `Offline(cached)`. Submit invalidates/refreshes this key on success.
- **No new DataStore keys.** Selected proof type and form are not persisted across
  app launches (only within the SavedStateHandle lifecycle).
- Navigation result: on `verified`/`pending_review` the residency record id is
  returned to the calling KYC hub via the Navigation-Compose `savedStateHandle`
  result pattern, so the tier/requirements screen (E42) can refresh.

## 7. Error Handling & Resilience

- **Validation errors**: rendered inline per field (`ValidationErrors`), submit
  disabled until resolved; server 422 field errors map back onto fields.
- **Unsupported / oversized proof**: rejected inline (FR-4) before upload.
- **Upload failure**: AND-129 retries presign/PUT/confirm internally; a final
  failure returns to `Editing` with the proof un-confirmed and a retry affordance —
  the cached file is retained so retry does not re-pick.
- **Submit failure** after a confirmed upload: `attachment_id` and form are kept so
  `retrySubmit()` re-POSTs without re-uploading the proof.
- **Timeouts**: OkHttp ~20 s. GET `/v1/kyc/residency` is idempotent → bounded
  backoff retry (AND-016); the non-idempotent POST is **not** auto-retried (user
  retries via the error state).
- **401**: AND-013 authenticator does one refresh + retry; on refresh failure,
  propagate to an auth-expired error state.
- **Offline**: connectivity probe (AND-017) gates upload and submit. On offline
  entry, render `Offline(cached)` from the last cached record if present; the form
  stays editable but submit queues no work.
- **Process death** mid-entry: form and proof file path restore from
  `SavedStateHandle` + cache file; if the file is gone the proof is cleared for
  re-attach.

## 8. Security & Privacy

- Address and proof documents are sensitive PII. Proof files are written only to
  app-internal `cacheDir` (no external/shared storage, no `MediaStore`, no gallery
  write); SAF reads use a one-shot `Uri` permission, copied immediately into cache.
- Proof cache files are deleted after successful submit, on remove/replace, on exit,
  and via the orphan sweeper; never retained beyond the session.
- No address field values, proof bytes, file contents, or signed presign URLs are
  logged. Telemetry (Section 10) records metadata only (proof type, byte size,
  durations, status) — never address contents, document names with PII, or URLs
  containing signed query params.
- Session is cookie-based; the CSRF token rides as `X-CSRF-Token` (AND-012). Presign
  PUT URLs from AND-129 are short-lived and never persisted.
- Recommend `FLAG_SECURE` on the residency screen (PII on display); flagged as an
  open question for product (Section 13), consistent with AND-321.

## 9. Accessibility & i18n

- All form fields have associated labels and `contentDescription`s; error text is
  associated via semantics so TalkBack announces field + error together.
- Proof type picker is a labeled selection control; capture/pick/replace/remove
  controls have `contentDescription`s and ≥48 dp touch targets.
- Upload progress and status transitions (`pending_review`, `verified`, `rejected`)
  are announced via a `liveRegion` semantics modifier.
- All static UI strings live in `strings.xml`; proof-type labels and rejection
  reasons are server-provided (`label` / `rejection_reason`). No hardcoded UI copy
  in composables.
- Country dropdown uses localized country display names; supports RTL layout
  mirroring (AND-114 readiness). Respects dynamic font scaling and dark theme via
  the Material 3 theme (AND-019).

## 10. Telemetry & Logging

Use the redacted telemetry facade (AND-052 pattern). Events:

- `kyc_residency_opened` { status }
- `kyc_residency_proof_attached` { proof_type, source }   // source: capture | pick
- `kyc_residency_proof_type` { proof_type, mime, byte_size }
- `kyc_residency_upload_started` { proof_type, byte_size }
- `kyc_residency_upload_failed` { proof_type, error_code }
- `kyc_residency_submitted` { proof_type, kyc_residency_id }
- `kyc_residency_submit_failed` { error_code }
- `kyc_residency_status_changed` { from_status, to_status }

Logging is metadata-only and redacted: no address field values, no proof bytes, no
signed URLs, no PII. Failures log the mapped `ApiError.code`, not raw response
bodies.

## 11. Testing Strategy

Acceptance requires that address proof **submits and verifies**.

**Unit (JVM, core-testing + MockWebServer):**
- `ResidencyViewModel` state machine: load (`none` → `Editing`); field changes
  update validation and `submitEnabled`; attach proof (mocked `AttachmentUploader`
  → `attachment_id`) → `Editing` with confirmed proof; `submit()` →
  `POST /v1/kyc/residency/verifications` → `Pending`. Assert `StateFlow` transitions.
- Status mapping: `GET /v1/kyc/residency` returning `verified` → `Verified`;
  `rejected` with `rejection_reason` → `Rejected(reason)`; re-submit from `Rejected`
  produces a new submit request.
- Failure paths: upload failure returns to `Editing` retryable without re-pick;
  submit failure after confirmed upload → `retrySubmit()` re-POSTs without
  re-uploading (same `attachment_id`).
- `KycRepository.submitResidency`: request body shape (`address`, `proof_type`,
  `attachment_id`), 201 → `KycResidencyDto`, and 422 field-error `detail` mapping to
  per-field validation via MockWebServer.
- Validation unit tests: required fields, ISO country code, postal-code non-empty.

**Instrumented / Compose UI tests:**
- Form renders, submit disabled until valid; entering required fields + selecting a
  proof type + a (fake) confirmed proof enables submit.
- Proof pick path uses a fake `FileResolver`/launcher returning a fixture file;
  capture path uses the AND-321 fake `DocumentCaptureController` seam so tests run on
  a headless emulator without a real camera.
- Upload progress, `Pending`, `Verified`, and `Rejected` states render; cancel
  during upload returns to `Editing` without a submit request.

**Definition of "submits and verifies":** an instrumented test that fills a valid
address, attaches a fixture proof (fake uploader → `attachment_id`), submits, asserts
the `POST /v1/kyc/residency/verifications` request body, and asserts the UI reaches
`Pending`; a follow-up `GET` returning `verified` drives the UI to `Verified`.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):**
  - **AND-321 (Document capture + upload)** — declared backlog dependency; provides
    the `DocumentCaptureController` capture seam and `CaptureImageProcessor` reused
    for the proof capture/processing path.
  - **AND-319 (KYC API + DTOs)** — provides the `/v1/kyc/*` Retrofit surface and DTO
    conventions; residency DTOs/methods are added following it.
  - **AND-129 (Attachment pipeline)** — provides `AttachmentUploader` for the single
    proof upload.
- **Transitively relied on:** AND-011 cookie jar, AND-012 CSRF, AND-013 refresh,
  AND-015 error mapping, AND-016 GET retry, AND-017 connectivity, AND-018
  `ApiResult`, AND-019 theme, AND-020 inputs, AND-021 state composables, AND-116 SWR
  cache (optional, for offline read), AND-046 MockWebServer, AND-052 telemetry.
- **New library:** none — reuses CameraX brought in by AND-321 within `feature-kyc`.
- **Blocks:** none listed in the backlog. The KYC tier/requirements surface (E42,
  e.g. AND-320) consumes the produced residency record but is not gated by a declared
  id here.
- Sequencing within ticket: (1) residency DTOs + repo methods on the AND-319 surface,
  (2) `FileResolver` (SAF→cache) + proof attach wiring, (3) ViewModel state machine +
  validation, (4) Compose form/status screens, (5) tests.

## 13. Risks & Open Questions

- **Endpoint shape**: `POST /v1/kyc/residency/verifications` and
  `GET /v1/kyc/residency` field names (`address`, `proof_type`, `attachment_id`,
  `status`, `rejection_reason`) are inferred from the web reference
  (`kycResidency`/`kycAddressVerification`) and `/openapi.json`; confirm against
  AND-319's finalized DTOs before merge. Open.
- **Single vs. multiple proof attachments**: assumes one proof document per
  submission. If the backend accepts multiple proofs (e.g. multi-page statements),
  the request changes to an `attachment_ids` array. Open — verify with AND-319.
- **PDF capture vs. image only**: assumes images via capture and images/PDF via
  pick. Confirm the backend accepts PDF proofs and the review pipeline can render
  them. Open.
- **Proof size cap (10 MB)** and image processing reuse: values are assumptions;
  confirm storage limits and KYC-review minimum resolution. Open.
- **Postal-code / address validation strictness**: client validation is lenient and
  server-authoritative; confirm whether per-country structured validation is
  required. Open.
- **`FLAG_SECURE` / screenshot blocking** on the residency PII screen: recommended;
  needs product decision (consistent with AND-321). Open.
- **Idempotency**: submission treated as non-idempotent; if the backend supports an
  idempotency key, add it to avoid duplicate verification records on retry. Open.

## 14. Acceptance Criteria

AC-1 A signed-in user at the residency tier can open the residency screen, see the
structured address form (pre-filled from any existing record) and the server-driven
list of accepted proof types. (Backlog: `kycResidency`/`kycAddressVerification`.)

AC-2 The user can attach exactly one proof document via either CameraX capture
(AND-321 seam) or the system document picker, restricted to `image/jpeg`,
`image/png`, `application/pdf`, with size and format enforced (FR-4) and a working
replace/remove.

AC-3 The proof uploads via the AND-129 presign→PUT→confirm pipeline with visible
progress and a working cancel, yielding a single confirmed `attachment_id`. (Backlog:
"proof upload.")

AC-4 With a valid address, a selected proof type, and a confirmed attachment, the
user can submit; `POST /v1/kyc/residency/verifications` is sent with the correct
`address`, `proof_type`, and `attachment_id`, and on 201 the UI reaches a
`pending_review`/submitted state. (Backlog: "submits.")

AC-5 The screen reads `GET /v1/kyc/residency` on entry and after submit and renders
`none`/`pending_review`/`verified`/`rejected` correctly, including
`rejection_reason` on rejection and a re-submit path. (Backlog: "verifies.")

AC-6 Validation, upload failure, submit failure, 401, and offline each produce a
non-crashing, retry-able state; retry after a confirmed upload does not re-upload the
proof, and retry after a confirmed upload + failed submit re-POSTs the same
`attachment_id`.

AC-7 Proof files never leave app-internal storage and are deleted on
submit/remove/exit; no address values, proof bytes, or signed URLs appear in
logs/telemetry.

AC-8 An automated test (MockWebServer + Compose, headless emulator) fills a valid
address, attaches a fixture proof via the fake seams, submits, asserts the
verification request body, reaches `Pending`, and on a follow-up `verified` read
reaches `Verified`. (Backlog: "verifies"; tested.)

## 15. Definition of Done

- All Acceptance Criteria (Section 14) met and demonstrated.
- `feature-kyc` residency flow implemented with the route, ViewModel, repository
  methods, `FileResolver`, and composables described in Section 4, namespaced
  `com.testlogon.android.feature.kyc`.
- Residency DTOs + repository methods added to the AND-319 `/v1/kyc/*` surface
  following its conventions; no duplication of the base Retrofit/DTO setup. Proof
  capture reuses AND-321; upload reuses AND-129; no new third-party library.
- Unit tests (ViewModel state machine, validation, repository request/response and
  422 mapping) and instrumented Compose/UI tests pass locally and in CI (AND-050 /
  AND-051).
- Lint, ktlint/detekt (AND-005) clean; no new warnings introduced.
- No address values, proof bytes, signed URLs, or PII in logs/telemetry; proof cache
  files swept.
- Open questions in Section 13 either resolved with AND-319/product or explicitly
  tracked as follow-ups before merge.
- Code reviewed and merged to `android-port`.
