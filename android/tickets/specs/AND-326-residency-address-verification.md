---
id: AND-326
title: Residency / address verification
milestone: M7
epic: E42
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-321, AND-319, AND-129]
blocks: []
---

# AND-326 — Residency / address verification

## 1. Overview & Goal

This ticket delivers the residency / address-verification step of the TestLogon
native Android KYC flow. Per the verified backend/web contract there are **two
distinct surfaces** the user moves through: (1) a **proof-of-residency document**
surface (`kycResidency`, `POST/GET /ui/kyc/residency`) where the user picks a
`document_type` from a **fixed enum** (utility bill, bank statement, government
letter, tax document, lease agreement), supplies `issuing_entity` + `document_date`
+ `file_name`, attaches the document bytes (sent inline as base64 `content_b64`),
and uploads + verifies it; and (2) a **structured-address verification** surface
(`kycAddressVerification`, `POST /v1/kyc/address-verification/cases/{case_id}/verify`)
that runs an existing KYC `case_id`'s entered address through the verifier. The user
then observes status (`pending`, `verified`, `rejected`, `expired` for the residency
document; `pending`/`partial_match`/`unverifiable`/`verified`/`error` plus a
`decision` of `verified`/`needs_review`/`failed` for the address verification).

> CORRECTION (review AND-326): the original draft assumed a single
> `POST /v1/kyc/residency/verifications` submit endpoint that took an `attachment_id`
> from an AND-129 presign→PUT→confirm pipeline and returned a `pending_review`/`none`
> status. None of that matches the sources. The real residency upload is
> `POST /ui/kyc/residency` with the document carried **inline** as base64
> (`content_b64`) — there is no presign/PUT/confirm and no `attachment_id`. Address
> verification is a **separate**, `case_id`-scoped endpoint. Status enums, field
> names, the "server-driven proof-type list", and the requirements endpoint were all
> wrong and are corrected throughout. See §16 for the full audit.

The functional bar from the backlog is: **address proof submits and verifies.**
This spec scopes the residency-document form (type/issuer/date/file + inline upload),
the proof-type picker, the capture/pick wiring, the residency upload + re-extract
calls, the structured-address verify call, and the verification-status surface. It
reuses the camera capture surface (AND-321) and the KYC DTOs/Retrofit base (AND-319);
note that AND-129 (presign pipeline) is **not** used by this contract (see §12).

Success: a signed-in user can fill in residency-document metadata, attach a proof
document (captured via AND-321 or picked from files) sent inline as base64, upload it
via `POST /ui/kyc/residency`, see the document reach `pending` (and, on a later
read/re-extract, `verified`/`rejected`/`expired`), and run their structured address
through `POST /v1/kyc/address-verification/cases/{case_id}/verify`.

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
  offline/stale states). OpenAPI at `/openapi.json`. Verified endpoints used here:
  the residency-document surface under `/ui/kyc/residency*` and the address-verify
  surface under `/v1/kyc/address-verification/*`. (Note: the draft's blanket
  "`/v1/kyc/*`" was imprecise — the residency document endpoints are under `/ui/kyc/`,
  not `/v1/kyc/`.) Web reference: `src/api/endpoints/kycResidency.ts` and
  `src/api/endpoints/kycAddressVerification.ts`; shared types in `src/api/types.ts`
  (`KycResidency*`, `AddressInput`, `AddressVerification*`); transport/auth in
  `src/api/client.ts`.
- Dependency tickets:
  - **AND-321 — Document capture + upload**: provides `DocumentCaptureController`
    (CameraX capture seam) and `CaptureImageProcessor` (EXIF fix, downsize ≤4 MB /
    2048 px / q85), reused for the proof capture/processing path.
  - **AND-319 — KYC API + DTOs**: provides `KycApi`, `KycRequirementsDto`, and the
    `/v1/kyc/*` Retrofit surface. Residency DTOs/methods are added following its
    conventions; the base is not redefined.
  - **AND-129 — Attachment pipeline (presign→PUT→confirm)**: declared as a backlog
    dep, but **the verified residency contract does not use it** — `POST /ui/kyc/residency`
    carries the document inline as base64 (`content_b64`), so there is no
    presign/PUT/confirm step and no `attachment_id`. AND-129 is therefore reduced to
    an optional/unused dependency for this ticket (see §12 / §16); the base64-encode +
    size-cap logic is implemented locally instead.
- Cross-cutting infra: cookie jar (AND-011), CSRF (AND-012), 401-refresh (AND-013),
  `ApiResult<T>` (AND-018), error mapping (AND-015), GET retry/backoff (AND-016),
  connectivity (AND-017), theme (AND-019), inputs (AND-020), state composables
  (AND-021), SWR cache (AND-116), MockWebServer (AND-046), telemetry (AND-052).

## 3. Functional Requirements

FR-1 **Address entry.** Present a structured form mapping to the verified
`AddressInput` schema: `line_1`, `line_2` (optional), `city`, `state` (optional),
`postal_code`, `country` (ISO-3166 alpha-2, dropdown). (CORRECTED: the draft used
`line1`/`line2`/`region`; the wire field names are `line_1`/`line_2`/`state`.) This
address feeds the address-verify call (FR-6b); it is **not** part of the residency
document upload body. Required-field and format validation runs client-side before
submit (FR-7).

FR-2 **Document-type selection.** Present the accepted residency document types from
the **fixed `document_type` enum** (CORRECTED: the draft claimed a server-driven
`KycRequirementsDto.residency.acceptedProofTypes`; no such requirements endpoint or
field exists — the web client hardcodes the list from the enum). The enum is exactly:
`utility_bill`, `bank_statement`, `government_letter`, `tax_document`,
`lease_agreement` (note: `tax_document` and `lease_agreement`, not the draft's
"tenancy agreement"). Labels are client-side display strings. The user picks exactly
one before uploading a document.

FR-3 **Proof attachment — capture or pick.** The user attaches one proof document
via either (a) camera capture using the AND-321 `DocumentCaptureController`
(single page, processed through `CaptureImageProcessor`), or (b) the system
document picker (`ACTION_OPEN_DOCUMENT`) for an existing image or PDF. A thumbnail
(image) or file chip (PDF) preview is shown with a **Replace** / **Remove** action.

FR-4 **Accepted formats & size.** Accepted MIME types: `image/jpeg`, `image/png`,
`application/pdf`. Captured images are JPEG (AND-321 processor output). Picked files
must be ≤ 10 MB; oversized or unsupported files are rejected inline with a prompt to
choose another.

FR-5 **Upload (residency document).** (CORRECTED: no AND-129 presign pipeline / no
`attachmentId`.) On submit, the proof file is **base64-encoded locally** and sent
inline as `content_b64` in the single `POST /ui/kyc/residency` request, alongside
`document_type`, `issuing_entity`, `document_date`, and `file_name`. Because the bytes
ride in the request body, "upload progress" maps to the single POST's request-body
upload; the request is cancelable by cancelling the call. The 201 response is a
`KycResidencyDocumentOut` record.

FR-6 **Submit residency document for verification.** With a selected document type, a
non-empty `issuing_entity`, a valid `document_date` (`YYYY-MM-DD`), a `file_name`, and
attached bytes, the user submits via `POST /ui/kyc/residency` (CORRECTED endpoint).
Success (HTTP **201**) returns a `KycResidencyDocumentOut` whose `status` is typically
`pending`; the UI shows a submitted/pending state. Re-running checks uses
`POST /ui/kyc/residency/{document_id}/extract`.

FR-6b **Address verification.** Separately, the structured address (FR-1) is verified
against an existing KYC `case_id` via
`POST /v1/kyc/address-verification/cases/{case_id}/verify` with body
`{ "address": AddressInput }` (HTTP **200**, returns
`AddressVerificationResponse { verification: AddressVerificationOut }`). The optional
standalone postal-code check is `POST /v1/kyc/address-verification/validate-postal-code`
(`{ postal_code, country }` → `{ valid, normalized, format_hint }`). NOTE: the
`case_id` is produced by the broader KYC case lifecycle (out of scope here) — see the
open assumption in §16 about where this screen obtains `case_id`.

FR-7 **Validation.** Residency-document required fields enforced (matching the
`KycResidencyUploadRequest` `required` set): `document_type`, `issuing_entity`
(1–200 chars), `document_date` (`^\d{4}-\d{2}-\d{2}$`), `file_name` (1–255 chars),
plus attached bytes. For the address-verify path: `line_1`, `city`, `postal_code`,
`country` non-empty; `postal_code` lenient/country-aware (server authoritative;
optionally pre-checked via `validate-postal-code`); `country` a valid ISO-3166 alpha-2
code (`maxLength` 2). The submit button is disabled until the relevant set is
satisfied.

FR-8 **Status surface.** On entry and after submit, the screen reads the user's
residency documents via `GET /ui/kyc/residency` (CORRECTED path; returns
`KycResidencyListResponse { documents: KycResidencyDocumentOut[] }`, an array — there
is no single-record read and no `none` sentinel). Empty array → show the upload form.
Each document renders by its `status`: `pending` (awaiting review), `verified`
(success), `rejected` / `expired`. (CORRECTED status enum: `pending` not
`pending_review`; `expired` added; no `none`.) Rejection detail is surfaced via
`review_note` / `review_decision` (CORRECTED: there is no `rejection_reason` field).
The address-verify result is read via
`GET /v1/kyc/address-verification/cases/{case_id}` returning
`AddressVerificationOut` (`status` + `decision`, `discrepancies`, `confidence_score`,
`standardized_address`).

FR-9 **Re-submit.** From `rejected`/`expired`, the user can upload a new residency
document (new `POST /ui/kyc/residency`, producing a new `KycResidencyDocumentOut`) or
re-run `POST /ui/kyc/residency/{document_id}/extract`; for the address path, re-POST
the verify call. Each produces a new record/attempt.

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
    data class Pending(val record: KycResidencyDocumentDto) : ResidencyUiState
    data class Verified(val record: KycResidencyDocumentDto) : ResidencyUiState
    // reason is surfaced from review_note (CORRECTED: no rejection_reason field)
    data class Rejected(val record: KycResidencyDocumentDto, val reason: String?) : ResidencyUiState
    data class Error(val error: UiError, val retryable: Boolean) : ResidencyUiState
    data class Offline(val cached: List<KycResidencyDocumentDto>) : ResidencyUiState
}

// Maps to the verified AddressInput wire schema (line_1/line_2/state/...):
data class AddressForm(
    val line1: String = "", val line2: String = "",   // -> line_1 / line_2
    val city: String = "", val state: String = "",     // -> state (CORRECTED from "region")
    val postalCode: String = "", val country: String = "",
)

// CORRECTED: no AND-129 attachment_id; document bytes go inline as base64 in the
// single POST /ui/kyc/residency request.
data class ProofAttachment(
    val localFile: java.io.File,    // local cache file holding the document bytes
    val mime: String,
    val displayName: String,        // -> file_name
    val byteSize: Long,             // for the size cap (FR-4)
    // contentB64 is computed at submit time from localFile (not held in UI state)
)
```

Repository surface (added here, DTOs from AND-319 conventions):

```kotlin
interface KycRepository {
    // CORRECTED: GET /ui/kyc/residency returns a LIST, not a single nullable record.
    suspend fun residencyDocuments(): ApiResult<List<KycResidencyDocumentDto>>     // GET, idempotent
    // CORRECTED: POST /ui/kyc/residency with inline base64; no attachmentId/proofType.
    suspend fun uploadResidency(
        documentType: String,        // -> document_type (enum)
        issuingEntity: String,       // -> issuing_entity (required, 1..200)
        documentDate: String,        // -> document_date (YYYY-MM-DD, required)
        fileName: String,            // -> file_name (required, 1..255)
        contentB64: String,          // -> content_b64 (the document bytes, base64)
        caseId: String? = null,      // -> case_id (optional)
    ): ApiResult<KycResidencyDocumentDto>                                          // POST 201, non-idempotent
    suspend fun extractResidency(documentId: String): ApiResult<KycResidencyDocumentDto> // POST .../extract

    // Address-verify surface (separate, case-scoped):
    suspend fun verifyAddress(caseId: String, address: AddressInputDto): ApiResult<AddressVerificationOutDto> // POST 200
    suspend fun getAddressVerification(caseId: String): ApiResult<AddressVerificationOutDto>                  // GET
    suspend fun validatePostalCode(postalCode: String, country: String): ApiResult<PostalCodeValidationDto>   // POST
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

Upload (CORRECTED): there is no separate upload step. At submit, the cache file is
base64-encoded (streaming/chunked to bound memory; reject if > size cap before
encoding, FR-4) and sent as `content_b64` in the single `POST /ui/kyc/residency`. The
in-flight POST surfaces into `UploadingProof`/`Submitting`; cancelling cancels the
call. On 201 the screen moves to `Pending` from the returned
`KycResidencyDocumentDto.status`.

Submit (residency document) maps the returned `KycResidencyDocumentDto.status`
(`pending`/`verified`/`rejected`/`expired`) to `Pending`/`Verified`/`Rejected` (with
`expired` treated like `rejected` for re-upload). The separate address-verify submit
builds `AddressInputDto` (`line_1`/`line_2`/`city`/`state`/`postal_code`/`country`)
from `AddressForm` and calls `verifyAddress(caseId, …)`. Cache files for the session
are deleted after a successful submit and on screen exit; an orphan sweeper (shared
with AND-321) deletes session dirs older than 24 h.

## 5. API Contract

> This entire section was rewritten in review: the verified contract differs
> substantially from the draft. All shapes below are taken from `openapi.pretty.json`
> and `src/api/endpoints/*.ts` + `src/api/types.ts`.

This ticket uses the residency-document surface (`/ui/kyc/residency*`) and the
address-verify surface (`/v1/kyc/address-verification/*`). All requests carry the
cookie session + `X-CSRF-Token: <ui_csrf cookie value>` (verified in
`src/api/client.ts`). The `/ui/kyc/residency*` and `verify`/GET endpoints also accept
optional `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` params (impersonation; not
used by the owner flow).

**List my residency documents** (idempotent GET; eligible for AND-016 retry/backoff):

```
GET /ui/kyc/residency
-> 200 KycResidencyListResponse:
{ "documents": [ KycResidencyDocumentOut, ... ] }     // empty array if none

KycResidencyDocumentOut (required: document_id, document_type, file_name, status):
{
  "document_id": "doc_7a1d",
  "case_id": "case_123",                 // nullable
  "user_sub": "user_…",                  // nullable
  "document_type": "utility_bill",       // utility_bill|bank_statement|government_letter|tax_document|lease_agreement
  "issuing_entity": "Pacific Gas & Electric",  // nullable on out
  "document_date": "2026-04-15",         // nullable on out
  "file_name": "utility_bill.pdf",
  "status": "pending",                   // pending|verified|rejected|expired
  "provider": null, "document_url": null, "extraction_id": null,
  "recency_valid": false, "recency_days": 0,
  "extracted_address": null,             // map<string,string> | null
  "address_match": null,                 // KycResidencyAddressMatch | null
  "review_decision": null, "review_note": null,   // rejection detail lives here
  "created_at": 0, "updated_at": 0       // epoch ints, NOT ISO strings
}
```

**Upload a residency document for verification** (non-idempotent POST; **excluded**
from the AND-016 GET retry policy):

```
POST /ui/kyc/residency
Request KycResidencyUploadRequest (required: document_type, issuing_entity, document_date, file_name):
{
  "document_type": "utility_bill",
  "issuing_entity": "Pacific Gas & Electric",   // 1..200
  "document_date": "2026-04-15",                 // pattern ^\d{4}-\d{2}-\d{2}$
  "file_name": "utility_bill.pdf",               // 1..255
  "content_b64": "<base64 document bytes>",      // optional in schema, sent by app
  "case_id": "case_123"                          // optional
}
-> 201 KycResidencyDocumentOut (status typically "pending")
-> 422 HTTPValidationError on bad body
```

**Re-run extraction/verification on an existing document** (POST):

```
POST /ui/kyc/residency/{document_id}/extract  -> 200 KycResidencyDocumentOut
GET  /ui/kyc/residency/{document_id}          -> 200 KycResidencyDocumentOut
```

**Address verification** (separate, case-scoped surface):

```
POST /v1/kyc/address-verification/cases/{case_id}/verify
Request VerifyAddressRequest:
{ "address": { "line_1": "221B Baker Street", "line_2": "", "city": "London",
               "state": "", "postal_code": "NW1 6XE", "country": "GB" } }
-> 200 AddressVerificationResponse:
{ "verification": AddressVerificationOut }

AddressVerificationOut (key fields):
{
  "verification_id": "...",  "kyc_case_id": "case_123",
  "status": "pending",       // verified|partial_match|unverifiable|pending|error
  "decision": "needs_review",// verified|needs_review|failed
  "confidence_score": 0.0,   "country": "GB", "country_format_valid": true,
  "postal_format_hint": "", "input_address": AddressInput, "standardized_address": AddressInput|null,
  "geocoding": {lat,lng}|null, "discrepancies": [], "cross_reference": null, "override": null,
  "provider": null, "verified_at": null, "created_at": 0, "updated_at": 0
}

GET  /v1/kyc/address-verification/cases/{case_id}            -> 200 AddressVerificationResponse
GET  /v1/kyc/address-verification/cases/{case_id}/attempts   -> 200 { "attempts": [AddressVerificationOut,…] }
POST /v1/kyc/address-verification/validate-postal-code
  Request PostalCodeValidationRequest: { "postal_code": "NW1 6XE", "country": "GB" }  // country len==2
  -> 200 PostalCodeValidationOut: { "valid": false, "normalized": "", "format_hint": "" }
```

**Document types** are a **fixed client-side enum** (CORRECTED: there is no
`GET /v1/kyc/requirements` / `accepted_proof_types`; the closest endpoint is
`GET /v1/kyc/tiers/me/requirements/{tier}` returning `TierRequirements`, which does
NOT carry a residency proof-type list). The enum is the five `document_type` values
above with locally-defined labels.

FastAPI error bodies follow the standard `detail` mapping (string | `[{loc,msg}]` |
`{code,...}`) handled by AND-015 / `normalizeErrorDetail` (`src/api/client.ts`).
Field-level 422 validation errors (`[{loc,msg}]`) are mapped back onto the
corresponding field where `loc` identifies it, otherwise shown as a form-level error.
401 triggers one session refresh (`POST /ui/session/refresh`) + retry (see §7).

## 6. Data & State Management

- **Form + transient state** live in `ResidencyViewModel` (`StateFlow`). The
  `AddressForm`, `selectedProofType`, and proof cache file path are mirrored into
  `SavedStateHandle` to survive process death/config changes during entry.
- **Proof file bytes** live as files in `cacheDir/kyc-residency/<sessionId>/`, never
  in memory beyond streaming and never in Room. Deleted on successful submit, on
  remove/replace, on screen exit, and via the shared 24 h orphan sweeper (AND-321).
- **Read caching**: the `List<KycResidencyDocumentDto>` from `GET /ui/kyc/residency`
  (CORRECTED path + list shape) may be cached via the AND-116 SWR/cache-repository
  pattern keyed `kyc_residency:<userId>` to serve a stale read in the `Offline` state;
  the cached list is the source for `Offline(cached)`. A successful upload
  invalidates/refreshes this key.
- **No new DataStore keys.** Selected proof type and form are not persisted across
  app launches (only within the SavedStateHandle lifecycle).
- Navigation result: on `verified`/`pending` the residency `document_id` (CORRECTED:
  `document_id`, status `pending` not `pending_review`) is returned to the calling KYC
  hub via the Navigation-Compose `savedStateHandle` result pattern, so the tier
  screen (E42) can refresh.

## 7. Error Handling & Resilience

- **Validation errors**: rendered inline per field (`ValidationErrors`), submit
  disabled until resolved; server 422 field errors map back onto fields.
- **Unsupported / oversized proof**: rejected inline (FR-4) before base64-encoding.
- **Upload/submit failure** (CORRECTED: single inline POST, no AND-129 pipeline): a
  failed `POST /ui/kyc/residency` returns to `Editing` with a retry affordance — the
  cached file + form metadata are retained so `retrySubmit()` re-POSTs without
  re-picking/re-encoding from scratch. Because the bytes ride in the same request,
  there is no separate "confirmed upload then failed submit" split; retry re-sends the
  whole body. NOTE: blind auto-retry of this non-idempotent POST risks duplicate
  documents — retry is user-initiated; see the idempotency open question (§13/§16).
- **Timeouts**: OkHttp ~20 s. GET `/ui/kyc/residency` (CORRECTED path) is idempotent
  → bounded backoff retry (AND-016); the non-idempotent POSTs (upload, address verify)
  are **not** auto-retried (user retries via the error state).
- **401**: AND-013 authenticator does one refresh + retry (mirrors the web client,
  which refreshes via `POST /ui/session/refresh` once then retries — verified in
  `src/api/client.ts`); on refresh failure, propagate to an auth-expired error state.
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
- No address field values, proof bytes, or `content_b64` payloads are logged.
  (CORRECTED: there are no signed presign URLs in this contract; the relevant secret
  is the inline base64 body, which must never be logged.) Telemetry (Section 10)
  records metadata only (document type, byte size, durations, status) — never address
  contents, document names with PII, or document bytes.
- Session is cookie-based; the CSRF token rides as `X-CSRF-Token` from the `ui_csrf`
  cookie (AND-012, verified in `src/api/client.ts`). The `document_url` returned in
  `KycResidencyDocumentOut` may be a signed read URL — treat it as sensitive, do not
  log it, and do not persist it beyond display.
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
  reasons are surfaced from server fields (`review_note` / `review_decision` —
  CORRECTED: no `rejection_reason`); document-type labels are client-side enum labels
  (CORRECTED: not server-provided). No other hardcoded UI copy in composables.
- Country dropdown uses localized country display names; supports RTL layout
  mirroring (AND-114 readiness). Respects dynamic font scaling and dark theme via
  the Material 3 theme (AND-019).

## 10. Telemetry & Logging

Use the redacted telemetry facade (AND-052 pattern). Events:

(Field names corrected: `document_type`/`document_id`, not `proof_type`/`kyc_residency_id`.)

- `kyc_residency_opened` { status }                          // pending|verified|rejected|expired
- `kyc_residency_proof_attached` { document_type, source }   // source: capture | pick
- `kyc_residency_proof_meta` { document_type, mime, byte_size }
- `kyc_residency_upload_started` { document_type, byte_size }
- `kyc_residency_upload_failed` { document_type, error_code }
- `kyc_residency_submitted` { document_type, document_id }
- `kyc_residency_submit_failed` { error_code }
- `kyc_residency_status_changed` { from_status, to_status }
- `kyc_address_verify` { decision, status }                  // address-verify surface

Logging is metadata-only and redacted: no address field values, no proof bytes, no
signed URLs, no PII. Failures log the mapped `ApiError.code`, not raw response
bodies.

## 11. Testing Strategy

Acceptance requires that address proof **submits and verifies**.

**Unit (JVM, core-testing + MockWebServer):**
- `ResidencyViewModel` state machine: load (empty `documents` list → `Editing`);
  field changes update validation and `submitEnabled`; attach proof (cache file) →
  `Editing`; `submit()` → `POST /ui/kyc/residency` with inline `content_b64` →
  `Pending`. Assert `StateFlow` transitions. (CORRECTED endpoint + inline-base64.)
- Status mapping: `GET /ui/kyc/residency` whose document `status` is `verified` →
  `Verified`; `rejected`/`expired` with `review_note` → `Rejected(reason)`; re-upload
  from `Rejected` produces a new POST.
- Failure paths: upload/submit failure returns to `Editing` retryable without re-pick;
  `retrySubmit()` re-POSTs the same body (no separate confirmed-upload step exists).
- `KycRepository.uploadResidency`: request body shape (`document_type`,
  `issuing_entity`, `document_date`, `file_name`, `content_b64`), 201 →
  `KycResidencyDocumentDto`, and 422 field-error `detail` (`[{loc,msg}]`) mapping to
  per-field validation via MockWebServer.
- `KycRepository.verifyAddress`: body `{address:{line_1,…,state,…}}`, 200 →
  `AddressVerificationOutDto` (assert `status`/`decision`).
- Validation unit tests: required fields, `document_date` pattern, ISO country code,
  postal-code non-empty.

**Instrumented / Compose UI tests:**
- Form renders, submit disabled until valid; entering required fields + selecting a
  proof type + a (fake) confirmed proof enables submit.
- Proof pick path uses a fake `FileResolver`/launcher returning a fixture file;
  capture path uses the AND-321 fake `DocumentCaptureController` seam so tests run on
  a headless emulator without a real camera.
- Upload progress, `Pending`, `Verified`, and `Rejected` states render; cancel
  during upload returns to `Editing` without a submit request.

**Definition of "submits and verifies":** an instrumented test that fills valid
residency-document metadata, attaches a fixture proof, submits, asserts the
`POST /ui/kyc/residency` request body (`document_type`, `issuing_entity`,
`document_date`, `file_name`, `content_b64`), and asserts the UI reaches `Pending`; a
follow-up `GET /ui/kyc/residency` returning a `verified` document drives the UI to
`Verified`. (CORRECTED endpoints/shapes.)

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):**
  - **AND-321 (Document capture + upload)** — declared backlog dependency; provides
    the `DocumentCaptureController` capture seam and `CaptureImageProcessor` reused
    for the proof capture/processing path.
  - **AND-319 (KYC API + DTOs)** — provides the KYC Retrofit surface and DTO
    conventions; residency (`/ui/kyc/residency*`) and address-verify
    (`/v1/kyc/address-verification/*`) DTOs/methods are added following it.
    (CORRECTED: the surface is not uniformly `/v1/kyc/*`.)
  - **AND-129 (Attachment pipeline)** — NOT a hard dependency for this ticket
    (CORRECTED): the verified residency upload is inline base64 (`content_b64`), not a
    presigned PUT. Downgrade to soft/optional; if AND-129 ships first it is simply
    unused here.
- **Transitively relied on:** AND-011 cookie jar, AND-012 CSRF, AND-013 refresh,
  AND-015 error mapping, AND-016 GET retry, AND-017 connectivity, AND-018
  `ApiResult`, AND-019 theme, AND-020 inputs, AND-021 state composables, AND-116 SWR
  cache (optional, for offline read), AND-046 MockWebServer, AND-052 telemetry.
- **New library:** none — reuses CameraX brought in by AND-321 within `feature-kyc`.
- **Blocks:** none listed in the backlog. The KYC tier/requirements surface (E42,
  e.g. AND-320) consumes the produced residency record but is not gated by a declared
  id here.
- Sequencing within ticket: (1) residency + address-verify DTOs/repo methods on the
  AND-319 surface, (2) `FileResolver` (SAF→cache) + base64-encode + proof attach
  wiring, (3) ViewModel state machine + validation, (4) Compose form/status screens,
  (5) tests.

## 13. Risks & Open Questions

- **Endpoint shape**: RESOLVED in review against `openapi.pretty.json` +
  `src/api/endpoints/*.ts`. The real surface is `POST/GET /ui/kyc/residency`
  (`KycResidencyUploadRequest`/`KycResidencyDocumentOut`, inline `content_b64`, no
  `attachment_id`) plus the separate `/v1/kyc/address-verification/*` surface. Field
  names, status enums, and the proof-type source were all corrected — see §16.
- **`case_id` provenance**: OPEN — `POST /v1/kyc/address-verification/cases/{case_id}/verify`
  and the `case_id` field on the upload request require a KYC `case_id` that this
  screen does not create. Confirm with E42/AND-319 how/whether this screen obtains a
  `case_id` (and whether address-verify is in scope for AND-326 at all, vs. residency
  upload only). See §16 open assumptions.
- **Single vs. multiple proof documents**: the contract is one document per
  `POST /ui/kyc/residency` call, but a user may upload several documents (the GET
  returns a list). UX for multi-document is open. Verify with product.
- **PDF vs. image bytes / `content_b64` size**: the schema accepts arbitrary
  `content_b64`; the app restricts to `image/jpeg|image/png|application/pdf` locally.
  Confirm the backend/review pipeline accepts PDF and any base64 body-size limit.
  Open.
- **Proof size cap (10 MB)** and base64 overhead (~33%): cap is a local assumption;
  confirm any server body-size limit on the inline POST (base64 inflates the payload).
  Open.
- **Postal-code / address validation strictness**: client validation is lenient and
  server-authoritative; confirm whether per-country structured validation is
  required. Open.
- **`FLAG_SECURE` / screenshot blocking** on the residency PII screen: recommended;
  needs product decision (consistent with AND-321). Open.
- **Idempotency**: submission treated as non-idempotent; if the backend supports an
  idempotency key, add it to avoid duplicate verification records on retry. Open.

## 14. Acceptance Criteria

AC-1 A signed-in user can open the residency screen, see the residency-document form
(document-type picker from the fixed enum, `issuing_entity`, `document_date`,
`file_name`) and the structured address form (`line_1`/`line_2`/`city`/`state`/
`postal_code`/`country`). (CORRECTED: document-type list is the fixed enum, not a
server-driven list.) (Backlog: `kycResidency`/`kycAddressVerification`.)

AC-2 The user can attach exactly one proof document via either CameraX capture
(AND-321 seam) or the system document picker, restricted to `image/jpeg`,
`image/png`, `application/pdf`, with size and format enforced (FR-4) and a working
replace/remove.

AC-3 The attached document is base64-encoded and sent inline as `content_b64` in the
single `POST /ui/kyc/residency` request, with visible in-flight progress and a working
cancel. (CORRECTED: no AND-129 presign pipeline / no `attachment_id`.) (Backlog:
"proof upload.")

AC-4 With a selected document type, valid `issuing_entity`/`document_date`/`file_name`,
and attached bytes, the user can submit; `POST /ui/kyc/residency` is sent with the
correct `document_type`, `issuing_entity`, `document_date`, `file_name`, `content_b64`,
and on **201** the UI reaches a `pending`/submitted state. (CORRECTED endpoint/body;
201, status `pending`.) (Backlog: "submits.")

AC-5 The screen reads `GET /ui/kyc/residency` on entry and after submit and renders
each document's status (`pending`/`verified`/`rejected`/`expired`) correctly,
including `review_note` on rejection and a re-upload path; the address path can verify
via `POST /v1/kyc/address-verification/cases/{case_id}/verify` and render
`status`/`decision`. (CORRECTED path, enum, list shape, no `rejection_reason`.)
(Backlog: "verifies.")

AC-6 Validation, upload/submit failure, 401, and offline each produce a non-crashing,
retry-able state; retry re-POSTs the same body (document metadata + `content_b64`)
without re-picking. (CORRECTED: single inline POST — no separate confirmed-upload
step.)

AC-7 Proof files never leave app-internal storage and are deleted on
submit/remove/exit; no address values, proof bytes, `content_b64`, or `document_url`
appear in logs/telemetry.

AC-8 An automated test (MockWebServer + Compose, headless emulator) fills valid
residency-document metadata, attaches a fixture proof via the fake seams, submits,
asserts the `POST /ui/kyc/residency` request body (incl. `content_b64`), reaches
`Pending`, and on a follow-up `GET /ui/kyc/residency` with a `verified` document
reaches `Verified`. (CORRECTED endpoint/body.) (Backlog: "verifies"; tested.)

## 15. Definition of Done

- All Acceptance Criteria (Section 14) met and demonstrated.
- `feature-kyc` residency flow implemented with the route, ViewModel, repository
  methods, `FileResolver`, and composables described in Section 4, namespaced
  `com.testlogon.android.feature.kyc`.
- Residency (`/ui/kyc/residency*`) and address-verify (`/v1/kyc/address-verification/*`)
  DTOs + repository methods added to the AND-319 surface following its conventions; no
  duplication of the base Retrofit/DTO setup. Proof capture reuses AND-321; upload is
  inline base64 (no AND-129); no new third-party library. (CORRECTED.)
- Unit tests (ViewModel state machine, validation, repository request/response and
  422 mapping) and instrumented Compose/UI tests pass locally and in CI (AND-050 /
  AND-051).
- Lint, ktlint/detekt (AND-005) clean; no new warnings introduced.
- No address values, proof bytes, signed URLs, or PII in logs/telemetry; proof cache
  files swept.
- Open questions in Section 13 either resolved with AND-319/product or explicitly
  tracked as follow-ups before merge.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and SOURCE. Sources: OpenAPI =
`reference/openapi.index.txt` / `reference/openapi.pretty.json` (`components.schemas`);
frontend = `reference/src/...`; framework ref = Android docs URL.

1. **Residency document list is read via `GET /ui/kyc/residency` returning
   `KycResidencyListResponse { documents: [...] }` (a list).** VERDICT: Corrected
   (draft said `GET /v1/kyc/residency` returning a single record with a `none`
   sentinel). SOURCE: OpenAPI `GET /ui/kyc/residency` resp=200:KycResidencyListResponse;
   `src/api/endpoints/kycResidency.ts: listMyKycResidencyDocuments`;
   `src/api/types.ts: KycResidencyListResponse`.
2. **Residency document is uploaded via `POST /ui/kyc/residency` (201) with body
   `KycResidencyUploadRequest`.** VERDICT: Corrected (draft said
   `POST /v1/kyc/residency/verifications`). SOURCE: OpenAPI
   `POST /ui/kyc/residency req=KycResidencyUploadRequest resp=201:KycResidencyDocumentOut`;
   `src/api/endpoints/kycResidency.ts: uploadKycResidencyDocument`.
3. **Document bytes are sent INLINE as base64 `content_b64`; there is NO
   presign→PUT→confirm pipeline and NO `attachment_id`.** VERDICT: Corrected (draft
   used the AND-129 `attachment_id` pipeline). SOURCE: OpenAPI
   `components.schemas.KycResidencyUploadRequest.content_b64` (string|null);
   `src/api/types.ts: KycResidencyUploadRequest` (line ~8418, `content_b64`); no
   attachment fields anywhere in the request.
4. **Residency upload required fields are `document_type`, `issuing_entity`,
   `document_date`, `file_name`.** VERDICT: Corrected (draft required `address`,
   `proof_type`, `attachment_id`). SOURCE: OpenAPI
   `KycResidencyUploadRequest.required = [document_type, issuing_entity, document_date,
   file_name]`; `document_date` pattern `^\d{4}-\d{2}-\d{2}$`; `issuing_entity` 1..200;
   `file_name` 1..255.
5. **`document_type` is a fixed enum: `utility_bill | bank_statement |
   government_letter | tax_document | lease_agreement` — NOT server-driven.** VERDICT:
   Corrected (draft sourced it from `KycRequirementsDto.residency.acceptedProofTypes`
   via a `GET /v1/kyc/requirements` that does not exist). SOURCE: OpenAPI
   `KycResidencyUploadRequest.document_type.enum`; `src/api/types.ts:
   KycResidencyDocumentType`; client hardcodes labels in
   `src/pages/kyc/KycResidencyVerificationPage.tsx: DOC_TYPE_LABELS`. (Nearest real
   requirements endpoint is `GET /v1/kyc/tiers/me/requirements/{tier}` →
   `TierRequirements`, which carries no proof-type list — `src/api/endpoints/kyc-tiers.ts`.)
6. **Residency document status enum is `pending | verified | rejected | expired`.**
   VERDICT: Corrected (draft used `none | pending_review | verified | rejected`).
   SOURCE: OpenAPI `KycResidencyDocumentOut.status.enum`; `src/api/types.ts:
   KycResidencyStatus`.
7. **Rejection detail is surfaced via `review_note` / `review_decision`; there is no
   `rejection_reason`.** VERDICT: Corrected. SOURCE: OpenAPI
   `KycResidencyDocumentOut.review_note` / `.review_decision`; no `rejection_reason`
   key exists in the schema.
8. **`KycResidencyDocumentOut` timestamps `created_at`/`updated_at` are epoch
   integers, not ISO strings.** VERDICT: Corrected (draft used ISO strings like
   `2026-06-05T12:00:00Z`). SOURCE: OpenAPI `KycResidencyDocumentOut.created_at`/
   `updated_at` (type integer, default 0).
9. **Re-running verification on a document is `POST /ui/kyc/residency/{document_id}/extract`.**
   VERDICT: Verified (added; not in draft). SOURCE: OpenAPI
   `POST /ui/kyc/residency/{document_id}/extract`;
   `src/api/endpoints/kycResidency.ts: extractKycResidencyDocument`.
10. **Structured-address verification is a SEPARATE, case-scoped endpoint
    `POST /v1/kyc/address-verification/cases/{case_id}/verify` (200) with body
    `VerifyAddressRequest { address: AddressInput }`.** VERDICT: Corrected (draft
    folded address into the residency submit body). SOURCE: OpenAPI
    `POST /v1/kyc/address-verification/cases/{case_id}/verify req=VerifyAddressRequest
    resp=200:AddressVerificationResponse`; `src/api/endpoints/kycAddressVerification.ts:
    verifyKycCaseAddress`; `components.schemas.VerifyAddressRequest`.
11. **`AddressInput` fields are `line_1`, `line_2`, `city`, `state`, `postal_code`,
    `country` (country `maxLength` 2).** VERDICT: Corrected (draft used
    `line1`/`line2`/`region`). SOURCE: OpenAPI `components.schemas.AddressInput`;
    `src/api/types.ts: AddressInput` (line ~12205).
12. **Address-verify response is `AddressVerificationResponse { verification:
    AddressVerificationOut }`, with `status` (`verified|partial_match|unverifiable|
    pending|error`) and `decision` (`verified|needs_review|failed`).** VERDICT:
    Verified. SOURCE: OpenAPI `components.schemas.AddressVerificationResponse` +
    `AddressVerificationOut`; `src/api/types.ts: AddressVerificationOut`.
13. **Standalone postal-code check is `POST /v1/kyc/address-verification/validate-postal-code`
    with `{ postal_code, country }` → `{ valid, normalized, format_hint }`.** VERDICT:
    Verified. SOURCE: OpenAPI
    `POST /v1/kyc/address-verification/validate-postal-code
    req=PostalCodeValidationRequest resp=200:PostalCodeValidationOut`;
    `src/api/endpoints/kycAddressVerification.ts: validateKycPostalCode`.
14. **Auth is cookie-session + `X-CSRF-Token` from the `ui_csrf` cookie + optional
    `Authorization: Bearer`.** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; Bearer from auth
    store; `credentials: "include"`).
15. **On 401, the client refreshes once via `POST /ui/session/refresh` then retries.**
    VERDICT: Verified (matches the AND-013 assumption). SOURCE: `src/api/client.ts:
    refreshSession` + the 401 branch.
16. **422 error bodies use FastAPI `detail` shapes (string | `[{loc,msg}]` |
    `{code,...}`).** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail`; OpenAPI `HTTPValidationError` is the 422 schema on every
    residency/address endpoint.
17. **Verify endpoint returns 200, residency upload returns 201.** VERDICT: Corrected
    (draft showed the residency submit returning 201 with an address echo and the
    verify path conflated). SOURCE: OpenAPI resp codes on the two ops (verify=200,
    upload=201).
18. **Accepted client-side MIME set `image/jpeg|image/png|application/pdf` and the
    10 MB cap.** VERDICT: Unverified-assumption (local UX policy). SOURCE: none in
    backend (schema accepts arbitrary `content_b64`); app-side decision consistent with
    AND-321.
19. **CameraX capture seam + EXIF/downsize processing (≤4 MB / 2048 px / q85).**
    VERDICT: Unverified-assumption (owned by AND-321, not re-verified here). SOURCE:
    framework ref https://developer.android.com/training/camerax ; dependency AND-321.
20. **SAF `ACTION_OPEN_DOCUMENT` for the pick path + app-internal `cacheDir` storage.**
    VERDICT: Verified (framework). SOURCE: framework ref
    https://developer.android.com/training/data-storage/shared/documents-files and
    https://developer.android.com/training/data-storage/app-specific .
21. **`FLAG_SECURE` on the PII screen.** VERDICT: Unverified-assumption (product
    decision, §13). SOURCE: framework ref
    https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE .
22. **`liveRegion` / TalkBack semantics for status announcements.** VERDICT: Verified
    (framework). SOURCE: framework ref
    https://developer.android.com/jetpack/compose/accessibility .

### Corrections made

- Endpoint paths: residency upload/read corrected from `POST /v1/kyc/residency/verifications`
  + `GET /v1/kyc/residency` to `POST /ui/kyc/residency` (201) + `GET /ui/kyc/residency`
  (list). (claims 1, 2, 17)
- Upload mechanism: removed the AND-129 presign→PUT→confirm pipeline and `attachment_id`;
  replaced with inline base64 `content_b64`. Downgraded AND-129 from hard dep to
  optional/unused. (claims 3, 4; §2, §3 FR-5/6, §4, §7, §12)
- Request body: `proof_type`+`attachment_id`+`address` replaced with `document_type`,
  `issuing_entity`, `document_date`, `file_name`, `content_b64` (+ optional `case_id`).
  (claim 4)
- Proof-type list: corrected from "server-driven `acceptedProofTypes`" to the fixed
  `document_type` enum; the `tenancy agreement` example replaced with the real
  `tax_document`/`lease_agreement`. (claim 5)
- Status enum: `none|pending_review|verified|rejected` → `pending|verified|rejected|expired`;
  `none` handled as empty list. (claim 6)
- Rejection field: `rejection_reason` → `review_note`/`review_decision`. (claim 7)
- Timestamps: ISO strings → epoch integers in the sample bodies. (claim 8)
- Address: split out as a separate `/v1/kyc/address-verification/*` surface; fields
  `line1/line2/region` → `line_1/line_2/state`. (claims 10, 11)
- Added the `extract` re-run endpoint, the `validate-postal-code` endpoint, and the
  address-verify GET/attempts endpoints. (claims 9, 12, 13)
- DTO names in §4 updated (`KycResidencyDto` → `KycResidencyDocumentDto`; repository
  methods rewritten); telemetry field names `proof_type`/`kyc_residency_id` →
  `document_type`/`document_id`.

### Open assumptions

- **`case_id` provenance (highest risk).** Both the address-verify endpoint and the
  optional `case_id` on the residency upload need a KYC `case_id`, but no endpoint in
  this ticket's scope creates one (case lifecycle is E42/AND-319). Whether AND-326
  includes the address-verify path at all, or only the residency-document upload, is
  unresolved — the web reference page (`KycResidencyVerificationPage.tsx`) only does
  the residency upload + extract and never calls the address-verify endpoint. Cannot
  be resolved from the sources; needs product/AND-319.
- **MIME allow-list + 10 MB cap.** Local UX policy; backend accepts arbitrary
  `content_b64`. No server limit is documented in the OpenAPI spec.
- **Base64 body-size limit.** Inline base64 inflates the payload ~33%; any server/proxy
  request-size cap on the inline POST is undocumented. Needs backend confirmation.
- **AND-321 capture processing parameters** (≤4 MB / 2048 px / q85) are inherited from
  AND-321 and not independently verified here.
- **`FLAG_SECURE`** on the PII screen is a recommended product decision, not a backend
  requirement.
- **Multi-document UX.** The GET returns a list and a user may upload multiple
  documents; the per-submission "exactly one" rule is a UX assumption, not a backend
  constraint.

## 17. Test Plan

IDs `TC-AND-326-NN`. "Traces" links to §14 acceptance criteria. Targets per the CI/dev
inventory: JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Camera/biometric/real-network
cases that need actual hardware MUST run on the physical device; deterministic UI/contract
cases run on the emulator or JVM.

**TC-AND-326-01 — Happy path: residency upload submits and reaches Pending.**
Type: contract/MockWebServer (JVM). Target: JVM unit/Robolectric.
Preconditions: MockWebServer stubs `POST /ui/kyc/residency` → 201 `KycResidencyDocumentOut`
{status:"pending"}; fake capture/file seams.
Steps: select `document_type=utility_bill`, set `issuing_entity`, `document_date`
(`2026-04-15`), `file_name`, attach fixture bytes; call `submit()`.
Expected: exactly one `POST /ui/kyc/residency`; request JSON contains `document_type`,
`issuing_entity`, `document_date`, `file_name`, and non-empty `content_b64`; UI state →
`Pending`. Traces: AC-3, AC-4.

**TC-AND-326-02 — Submit-and-verify end-to-end (definition of done).**
Type: Compose-UI + MockWebServer. Target: emulator `test35`.
Preconditions: stub upload → 201 {status:"pending"}; then stub `GET /ui/kyc/residency`
→ 200 {documents:[{...,status:"verified"}]}.
Steps: fill metadata, attach fixture proof via fake seams, tap Upload & verify, then
trigger the post-submit read.
Expected: UI reaches `Pending`, then `Verified`; status badge announced via liveRegion.
Traces: AC-4, AC-5, AC-8.

**TC-AND-326-03 — Read renders list statuses (pending/verified/rejected/expired).**
Type: unit (state mapping). Target: JVM.
Preconditions: `GET /ui/kyc/residency` returns four documents, one per status, the
`rejected` one carrying `review_note`.
Steps: `onScreenEntered()`.
Expected: each document maps to the correct sub-state; `rejected` exposes
`reason == review_note`; empty list → `Editing`. Traces: AC-1, AC-5.

**TC-AND-326-04 — Client validation gates submit.**
Type: unit. Target: JVM.
Preconditions: none.
Steps: leave `issuing_entity` blank / `document_date` not matching `^\d{4}-\d{2}-\d{2}$`
/ no document type / no attachment, vary one at a time.
Expected: `submitEnabled=false` and the corresponding `ValidationErrors` entry set; no
network call. Traces: AC-1, AC-6.

**TC-AND-326-05 — Server 422 maps to per-field errors.**
Type: contract/MockWebServer. Target: JVM.
Preconditions: `POST /ui/kyc/residency` → 422 `{detail:[{loc:["body","document_date"],
msg:"invalid date"}]}`.
Steps: submit otherwise-valid form.
Expected: error mapped onto the `document_date` field (form-level fallback otherwise);
state returns to `Editing`, retryable; no crash. Traces: AC-6.

**TC-AND-326-06 — Unsupported / oversized proof rejected before encoding.**
Type: unit. Target: JVM.
Preconditions: pick a fixture that is 12 MB / `text/plain`.
Steps: `onProofPicked(uri)`.
Expected: rejected inline (FR-4) with a "choose another" prompt; no base64 encode, no
network. Traces: AC-2, AC-6.

**TC-AND-326-07 — Cancel during in-flight upload.**
Type: Compose-UI + MockWebServer (delayed response). Target: emulator `test35`.
Preconditions: `POST /ui/kyc/residency` stubbed with a throttled/delayed body.
Steps: submit, then tap cancel while `UploadingProof`.
Expected: the POST is cancelled; UI returns to `Editing` with metadata + file retained;
no `Pending` reached. Traces: AC-3, AC-6.

**TC-AND-326-08 — Submit failure then user retry re-POSTs same body.**
Type: contract/MockWebServer. Target: JVM.
Preconditions: first `POST /ui/kyc/residency` → 503; second → 201.
Steps: submit (fails → `Error`/`Editing` retryable), then `retrySubmit()`.
Expected: second request carries the identical body incl. the same `content_b64`
(no re-pick/re-encode required); UI → `Pending`. Traces: AC-6.

**TC-AND-326-09 — 401 triggers one refresh + retry.**
Type: contract/MockWebServer. Target: JVM.
Preconditions: `POST /ui/kyc/residency` → 401 once; `POST /ui/session/refresh` → 200;
retry → 201.
Steps: submit.
Expected: one refresh call, then the original POST retried once and succeeds; on refresh
failure → auth-expired error state (no crash). Traces: AC-6.

**TC-AND-326-10 — Offline path (flaky/unreachable dev host).**
Type: integration. Target: physical device (toggle airplane mode for a real radio-off
network error; emulator network-off is an acceptable fallback).
Preconditions: AND-116 cache holds a prior documents list; connectivity probe reports
offline.
Steps: open screen offline.
Expected: `Offline(cached)` renders the cached list; form stays editable; submit is
gated (queues no work); recovering connectivity allows submit. MUST exercise a real
radio-off transition on the physical device to confirm the OkHttp/connectivity behavior
matches API-34 arm64. Traces: AC-6.

**TC-AND-326-11 — CSRF + cookie session headers on every mutating call.**
Type: contract/MockWebServer. Target: JVM.
Preconditions: cookie jar holds `ui_csrf`; MockWebServer captures headers.
Steps: perform upload and (if in scope) address-verify.
Expected: each request carries `X-CSRF-Token: <ui_csrf>` and the session cookie; no
`content_b64`, address values, or `document_url` appear in any emitted log/telemetry
record. Traces: AC-7.

**TC-AND-326-12 — Proof file stays app-internal and is swept.**
Type: instrumented. Target: emulator `test35`.
Preconditions: pick/capture a proof.
Steps: attach (file lands in `cacheDir/kyc-residency/<session>/`), then submit /
remove / exit; also simulate a stale dir for the 24 h sweeper.
Expected: file written only under app `cacheDir` (never `MediaStore`/external); deleted
on submit/remove/exit; sweeper removes >24 h dirs. Traces: AC-7.

**TC-AND-326-13 — Real camera capture of a proof document.**
Type: instrumented/e2e. Target: physical device (REQUIRED — real CameraX hardware).
Preconditions: camera permission granted.
Steps: choose capture, photograph a sample bill, confirm; observe EXIF-fixed downsized
JPEG fed to the attach path; submit.
Expected: a real JPEG ≤ the AND-321 cap is attached, base64-encoded, and uploaded;
preview thumbnail + replace/remove work. MUST run on the physical device because the
emulator has no real camera sensor. Traces: AC-2, AC-3.

**TC-AND-326-14 — Accessibility: labels, touch targets, live status.**
Type: Compose-UI (with semantics assertions). Target: emulator `test35`.
Preconditions: none.
Steps: traverse the form with TalkBack semantics; inspect capture/pick/replace/remove
controls; transition to `Pending`/`Verified`.
Expected: every field has a label + error association; controls have
`contentDescription` and ≥48 dp targets; status changes are announced via `liveRegion`;
dynamic font scaling + RTL mirror correctly. Traces: AC-1, AC-5.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-03, TC-04, TC-14 |
| AC-2 | TC-06, TC-13 |
| AC-3 | TC-01, TC-02, TC-07, TC-13 |
| AC-4 | TC-01, TC-02 |
| AC-5 | TC-02, TC-03, TC-14 |
| AC-6 | TC-04, TC-05, TC-06, TC-07, TC-08, TC-09, TC-10 |
| AC-7 | TC-11, TC-12 |
| AC-8 | TC-02 |
