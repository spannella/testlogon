---
id: AND-322
title: ID scanner
milestone: M7
epic: E42
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-321]
blocks: [AND-323]
---

# AND-322 — ID scanner

## 1. Overview & Goal

This ticket delivers `kycIdScanner`: a guided, on-device identity-document capture
flow for the TestLogon Android app. The user is walked through capturing the **front**
of a government ID, the **back**, and (for documents that carry a machine-readable
zone) the **MRZ** strip. Each frame is captured with CameraX, validated locally for
basic quality (focus, glare, edge detection, MRZ line count), uploaded to the KYC
document store, and the resulting document references are submitted to the backend as
a single ID-scan packet.

The goal is a flow a non-technical user can complete unattended: per-step guidance,
automatic edge/MRZ detection, retake affordances, and a deterministic submit that
returns a verification result. It builds on the camera capture and presigned-upload
plumbing from **AND-321 (Document capture + upload)**. It does not implement
selfie/liveness — that is **AND-323 (Facial comparison)**, which depends on this
ticket for the established KYC document set.

Acceptance in one line (from backlog): *ID scan captures + submits.*

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app in `android/`, branch
  `android-port`.
- **Package base:** `com.testlogon.android`. This feature lives in module
  `feature-kyc` under package `com.testlogon.android.feature.kyc.idscanner`.
- **Module layering:** `app -> feature-kyc -> core-*`. Networking, presigned upload,
  and the `KycRepository` come from **AND-321**; this ticket extends them rather than
  re-implementing them.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, CameraX, ML Kit (text +
  on-device document/face mesh not used here; text recognition for MRZ optional).
  minSdk 24, compileSdk/targetSdk 35, JDK 17.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Error `detail` is `string | [{msg}] |
  {code,...}`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (KYC endpoints) and
  `frontend/src/api/types.ts` for canonical request/response shapes; mirror field
  names exactly in Moshi DTOs.
- **Upstream dependency:** **AND-321** — provides `CameraCaptureController`,
  `PresignUploader`, `KycRepository.uploadDocument(...)`, and document templates.
- **Downstream:** **AND-323** consumes the completed KYC ID document set.

## 3. Functional Requirements

FR-1. **Guided multi-step capture.** The flow has ordered steps:
`FRONT -> BACK -> MRZ (conditional) -> REVIEW -> SUBMIT`. The MRZ step is included only
when `validate-document` reports `has_mrz = true` for the chosen type (e.g. passport,
national ID card). Driver-license-style documents skip MRZ. **Note (corrected):** the MRZ
"step" does not produce a separate uploaded *document* — there is no `id_mrz` upload type.
It captures/OCRs the MRZ strip into `mrz_lines` text that is attached to the relevant
side's `scan-document` request (front for passports/TD3, the MRZ-bearing side for TD1).

FR-2. **Document type selection.** Before capture, the user picks a document type from
the fixed enum (`passport | national_id_card | driving_license | residence_permit`).
**CORRECTED:** there is no backend template list (`GET /ui/kyc/id/templates` does not
exist); the web app hardcodes the same four types. Authoritative side/MRZ requirements
are fetched per type from `POST /ui/kyc/id-scanner/cases/{case_id}/validate-document`
(`KycIdScannerValidationOut`: `sides_required`, `has_mrz`, `mrz_format`). Overlay aspect
ratio/inset are client-side constants (not API-supplied).

FR-3. **Per-step overlay guidance.** Each capture step shows a framed overlay sized
to the template aspect ratio, a one-line instruction, and live status hints
("Hold steady", "Reduce glare", "Move closer", "MRZ detected").

FR-4. **Automatic + manual capture.** Capture fires automatically when local quality
checks pass for N consecutive frames (default 3); a manual shutter is always
available as a fallback after a 4s timeout or on user tap.

FR-5. **Local quality gates.** Each captured still must pass: minimum resolution
(>= 1280px on the long edge), focus/sharpness (Laplacian variance threshold), glare
ratio below threshold, and detected document edges within the overlay. MRZ frames
additionally require >= 2 OCR-detected MRZ lines (TD1 = 3 lines, TD3 = 2 lines).

FR-6. **Review + retake.** The REVIEW step shows thumbnails of every captured side
with a per-side "Retake" action that returns to that capture step without losing the
other sides.

FR-7. **Upload via presign.** On confirm, each side is uploaded using the AND-321
presigned-upload path, yielding stable `documentId`s. Uploads are concurrent but the
flow waits for all to complete before submit.

FR-8. **Scan each side.** **CORRECTED:** there is no single packet submit. After each
side is uploaded (base64, §5.2) the flow calls the **per-side** case-scoped
`POST /ui/kyc/id-scanner/cases/{case_id}/scan-document` with `document_type`, `file_type`
(`id_front`/`id_back`), the uploaded `image_ref` (`document_id`), and — for MRZ documents —
the OCR'd `mrz_lines`. Each call returns a `KycIdScannerScanOut` status surfaced to the
user. A `case_id` (`kyc_...`) from the upstream KYC case is required.

FR-9. **Result presentation.** **CORRECTED status enum** (`KycIdScannerScanOut.status`):
`matched | flagged | rejected | approved | declined` (the draft's `verified/pending/
rejected` is wrong). UI grouping: `matched`/`approved` = success; `flagged` = manual review
(pending); `rejected`/`declined` = failure with a retry affordance that restarts capture.
Because there is no `decision_reason` field, surface `expiry_check.message`,
`review_note`, and `cross_reference.mismatches` as the reason.

FR-10. **Cancel & resume.** The user may cancel at any point. In-progress (un-uploaded)
captures are discarded from cache on cancel. Resume within the same Activity session
restores captured-but-not-submitted state from the ViewModel.

## 4. Technical Design

### 4.1 Navigation

Single nested graph route `kyc/id-scan` registered in `feature-kyc`'s nav module:

```kotlin
const val ROUTE_ID_SCAN = "kyc/id-scan"

fun NavGraphBuilder.idScannerGraph(navController: NavController) {
    composable(ROUTE_ID_SCAN) { IdScannerRoute(onDone = { navController.popBackStack() }) }
}
```

`IdScannerRoute` hosts a single `IdScannerViewModel` and renders the current step via
a `when (uiState.step)` switch over Composables; it does not push a new back-stack
entry per step (steps are internal state) so that system-back unwinds steps, then
exits.

### 4.2 State model

```kotlin
enum class IdSide { FRONT, BACK, MRZ }

enum class IdScanStep { TYPE_SELECT, CAPTURE, REVIEW, UPLOADING, SUBMITTING, RESULT }

data class CapturedSide(
    val side: IdSide,
    val localUri: Uri,            // app-cache file
    val widthPx: Int,
    val heightPx: Int,
    val quality: QualityReport,
    val documentId: String? = null // set after upload
)

data class QualityReport(
    val sharpnessOk: Boolean,
    val glareOk: Boolean,
    val edgesOk: Boolean,
    val mrzLineCount: Int = 0,
    val passed: Boolean
)

data class IdScannerUiState(
    val step: IdScanStep = IdScanStep.TYPE_SELECT,
    val templates: List<IdTemplate> = emptyList(),
    val selectedTemplate: IdTemplate? = null,
    val currentSide: IdSide = IdSide.FRONT,
    val captured: Map<IdSide, CapturedSide> = emptyMap(),
    val liveHint: CaptureHint = CaptureHint.NONE,
    val result: IdScanResult? = null,
    val error: UiError? = null,
    val isOffline: Boolean = false
)
```

### 4.3 ViewModel

```kotlin
@HiltViewModel
class IdScannerViewModel @Inject constructor(
    private val kycRepository: KycRepository,        // from AND-321
    private val frameAnalyzer: IdFrameAnalyzer,
    private val savedState: SavedStateHandle
) : ViewModel() {

    val uiState: StateFlow<IdScannerUiState>

    fun loadTemplates()
    fun selectType(template: IdTemplate)
    fun onFrame(image: ImageProxy)                   // analysis callback -> liveHint
    fun onAutoOrManualCapture(image: ImageProxy)     // persist still to cache + QualityReport
    fun retake(side: IdSide)
    fun confirmAndUpload()                            // step UPLOADING
    fun submit()                                      // step SUBMITTING -> RESULT
    fun cancel()
    fun retryAfterReject()
}
```

The ViewModel owns the ordered side list derived from
`selectedTemplate.requiredSides`. After all required sides are captured and pass
quality, it transitions to `REVIEW`.

### 4.4 Camera & analysis

CameraX use cases reuse AND-321's `CameraCaptureController`:
`Preview + ImageAnalysis (YUV, STRATEGY_KEEP_ONLY_LATEST) + ImageCapture`. A new
analyzer is added:

```kotlin
class IdFrameAnalyzer @Inject constructor(
    private val mrzTextRecognizer: TextRecognizer   // ML Kit, MRZ step only
) {
    fun analyze(image: ImageProxy, side: IdSide, template: IdTemplate): QualityReport
}
```

- **Sharpness:** Laplacian variance over the overlay ROI luminance plane; threshold
  configurable (`BuildConfig`-overridable, default 120.0).
- **Glare:** fraction of ROI pixels above luma 240; reject if > 0.06.
- **Edges:** lightweight gradient-based rectangle presence within ROI bounds.
- **MRZ:** ML Kit text recognition restricted to bottom ROI; count lines matching the
  MRZ charset regex `^[A-Z0-9<]{30,44}$`. Full MRZ parsing/checksum is **out of
  scope** — only line presence is gated client-side; authoritative parse is backend.

### 4.5 Capture persistence

Stills are written to `context.cacheDir/kyc/<sessionId>/<side>.jpg` (JPEG, quality 92,
EXIF stripped). Files are deleted on cancel, on successful submit, and on app process
exit cleanup (best-effort `onCleared`). On upload, each side is read back and base64-encoded
into `content_b64` for `POST /ui/kyc/documents` with `document_type = id_front | id_back`
(**there is no `id_mrz`** — corrected from the draft's `id_<side>` claim).

### 4.6 Compose surfaces

`IdScannerScreen` is stateless and renders sub-Composables per step:
`DocTypePicker`, `CaptureSurface` (CameraX `PreviewView` via `AndroidView` + overlay +
hint chip + shutter), `ReviewGrid`, `UploadProgress`, `ResultPanel`. Live hints map to
localized strings.

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000`. Auth model
(**verified** against `src/api/client.ts`): cookie session + `X-CSRF-Token` header read
from the `ui_csrf` cookie, **plus** an `Authorization: Bearer <accessToken>` header from
the auth store and an optional `X-IMPERSONATION-TOKEN` header when impersonation is
active. On 401 the web client refreshes once via `POST /ui/session/refresh` then retries
the original request; the Android OkHttp authenticator mirrors this. Mutating calls
(the per-side `scan-document` POST and the document upload POST) are **not** retried on
transient failure; only idempotent GETs are.

> **CORRECTION (review):** the original draft claimed dedicated `GET /ui/kyc/id/templates`
> and `POST /ui/kyc/id/scan` endpoints and a presigned-S3 KYC upload. None of those exist
> in the live OpenAPI or the web reference. The real contract is: per-side
> base64 upload to `POST /ui/kyc/documents`, an optional requirement check via
> `POST /ui/kyc/id-scanner/cases/{case_id}/validate-document`, and a **per-side** scan
> `POST /ui/kyc/id-scanner/cases/{case_id}/scan-document`. All of §5 below is rewritten to
> the verified shapes. The flow is **case-scoped**: a `case_id` (`kyc_...`) is required and
> comes from the upstream KYC case (AND-321 / KYC wizard), not minted here.

### 5.1 Document type selection + requirement validation

**CORRECTED — there is no `GET /ui/kyc/id/templates`.** No template-list endpoint exists in
the live OpenAPI or the web reference. The web app (`src/pages/kyc/KycIdScannerPage.tsx`)
uses a **hardcoded** document-type list and a static side hint. Mirror this on Android:

- Document types (enum `KycIdScannerDocumentType`): `passport`, `national_id_card`,
  `driving_license`, `residence_permit`. Side rule used by the web app: passport = front
  only; others = front + back.
- Authoritative per-type requirements (sides required, whether an MRZ is expected, MRZ
  format) come from `POST /ui/kyc/id-scanner/cases/{case_id}/validate-document`
  (req `KycIdScannerValidateRequest { document_type }`, resp `KycIdScannerValidationOut`):

```json
{
  "document_type": "passport",
  "sides_required": ["id_front"],
  "sides_present": ["id_front"],
  "has_mrz": true,
  "mrz_format": "TD3",
  "all_sides_present": true
}
```

> The Android overlay aspect ratio / inset values are a **client-side UX concern**: they are
> NOT supplied by the backend (no `aspect_ratio` / `overlay_inset_pct` fields exist). Keep a
> local per-document-type geometry table in the app and document it as an app constant, not
> an API field. (Unverified-assumption: exact aspect ratios.)

### 5.2 Upload sides (base64 to `POST /ui/kyc/documents`)

**CORRECTED — KYC document upload is NOT a presigned-S3 PUT.** There is no
`/ui/kyc/documents/presign` endpoint. The live endpoint is `POST /ui/kyc/documents`
(req `KycDocumentUploadRequest`, resp 201 `KycDocumentOut`) and it takes the image inline
as **base64** (`content_b64`). Request fields (verified):

```json
{
  "case_id": "kyc_01HZX...",
  "document_type": "id_front",
  "file_name": "id_front.jpg",
  "content_b64": "<base64 JPEG bytes>"
}
```

- `document_type` enum is **only** `id_front | id_back` — there is **no `id_mrz`**. MRZ is
  not uploaded as a separate document; it is passed as text in the scan request (§5.3).
- Response `KycDocumentOut` returns `document_id` (the stable id), plus `status`
  (`pending|extracted|failed|approved|rejected`), `file_name`, and optional
  `extracted_fields`, `image_url`, `overall_confidence`.
- An optional `POST /ui/kyc/documents/{document_id}/extract` triggers field extraction on
  an uploaded document (resp `KycDocumentOut`); not required for the scan flow but available.

> Implication for AND-321 reuse: if AND-321's `KycRepository.uploadDocument(...)` already
> wraps `POST /ui/kyc/documents` with base64, reuse it unchanged. If AND-321 actually built
> generic presigned upload for a *different* document domain, it is **not** applicable to KYC
> and must not be used here. Confirm with the AND-321 owner (OQ-3). Because the body is
> base64, downscale aggressively before encode to keep payloads small over the flaky HTTP
> dev host.

### 5.3 Scan a document side (POST, non-idempotent, **per side**)

**CORRECTED — endpoint, path, request and response all differ from the original draft.**
The real endpoint is **per-side** and **case-scoped**, returns **201**:

`POST /ui/kyc/id-scanner/cases/{case_id}/scan-document`
(req `KycIdScannerScanRequest`, resp 201 `KycIdScannerScanOut`)

There is **no single "submit the whole packet" call** and no `template_id` / `documents`
map. The flow calls this once per captured side (and once more, or together with the front,
for MRZ text). `case_id` is a path param.

Request (`KycIdScannerScanRequest`, verified):

```json
{
  "document_type": "passport",
  "file_type": "id_front",
  "mrz_lines": ["P<USASMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<", "X12345678USA8001012M3004017<<<<<<<<<<<<<<06"],
  "image_ref": "doc_01HZX..."
}
```

- `document_type`: enum `passport | national_id_card | driving_license | residence_permit`
  (**not** template ids like `passport_td3`). Required.
- `file_type`: enum `id_front | id_back`, default `id_front`. **No `mrz` value exists.**
- `mrz_lines`: optional `string[]` — manual MRZ lines (2 for TD3 passport, 3 for TD1 ID
  card). This is how MRZ reaches the backend; the client OCRs the strip into these lines
  (or the user/back end parses from the image). MRZ is **not** a separate document upload.
- `image_ref`: optional string (max 512) — reference to a previously uploaded document
  image (the `document_id` from §5.2). Either `image_ref` or `mrz_lines` carries the
  evidence; the web reference sends `mrz_lines` and omits `image_ref` for manual testing.

Response 201 (`KycIdScannerScanOut`, verified):

```json
{
  "scan_id": "scan_01J2A...",
  "case_id": "kyc_01HZX...",
  "document_type": "passport",
  "file_type": "id_front",
  "status": "matched",
  "mrz_valid": true,
  "extraction": {
    "document_number": "X1234567",
    "expiry_date": "2030-04-01",
    "given_names": "JOHN",
    "surname": "SMITH",
    "nationality": "USA",
    "date_of_birth": "1980-01-01",
    "sex": "M",
    "issuing_state": "USA",
    "checksums": { "document_number": true, "date_of_birth": true, "expiry_date": true, "composite": true }
  },
  "expiry_check": { "status": "valid", "message": "Valid", "expiry_date": "2030-04-01", "days_until_expiry": 1400 },
  "cross_reference": { "match_score": 100, "total_fields_checked": 5, "fields_matched": 5, "matches": {}, "mismatches": {} },
  "review_decision": null,
  "review_note": null,
  "image_url": null
}
```

**CORRECTED status enum:** `status` ∈ `matched | flagged | rejected | approved | declined`
(the original draft's `verified | pending | rejected` is wrong). There is **no
`decision_reason`** and **no top-level `extracted` map**: extracted fields live in the
nested `extraction` object (`KycIdScannerExtraction`), and the human/auto disposition is in
`review_decision` / `review_note`. Expiry is its own `expiry_check`
(`status` ∈ `valid | expired | expiring_soon | unknown`), and `mrz_valid` is a top-level
boolean. Required fields: `scan_id, case_id, document_type, file_type, status, mrz_valid,
extraction, expiry_check`.

UI mapping (replaces the draft's `verified/pending/rejected`): treat `matched`/`approved`
as success, `flagged` as needs-review/pending, `rejected`/`declined` as failure (offer
restart). Surface `expiry_check.message` and `cross_reference.mismatches` keys as the
human-readable reason since there is no `decision_reason` field.

### 5.3a List / fetch prior scans (GET, idempotent)

- `GET /ui/kyc/id-scanner/cases/{case_id}/scans` -> `KycIdScannerScanListResponse`
  (`{ scans: KycIdScannerScanSummary[] }`).
- `GET /ui/kyc/id-scanner/cases/{case_id}/scans/{scan_id}` -> `KycIdScannerScanOut`.

Useful for the REVIEW/RESULT screens and for resume.

### 5.4 DTOs (Moshi)

**CORRECTED DTOs — mirror the verified backend schemas exactly** (`KycDocumentUploadRequest`,
`KycDocumentOut`, `KycIdScannerScanRequest`, `KycIdScannerScanOut`, and nested types). The
draft's `IdTemplateDto` / `IdScanRequestDto` (template_id + documents map) are removed; no
template DTO exists.

```kotlin
// Upload — POST /ui/kyc/documents
@JsonClass(generateAdapter = true)
data class KycDocumentUploadRequestDto(
    @Json(name = "document_type") val documentType: String,   // "id_front" | "id_back"
    @Json(name = "file_name") val fileName: String,
    @Json(name = "case_id") val caseId: String? = null,
    @Json(name = "content_b64") val contentB64: String? = null
)

@JsonClass(generateAdapter = true)
data class KycDocumentOutDto(
    @Json(name = "document_id") val documentId: String,
    @Json(name = "document_type") val documentType: String,
    @Json(name = "file_name") val fileName: String,
    @Json(name = "status") val status: String,               // pending|extracted|failed|approved|rejected
    @Json(name = "case_id") val caseId: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "extracted_fields") val extractedFields: Map<String, String>? = null,
    @Json(name = "overall_confidence") val overallConfidence: String? = null
)

// Scan — POST /ui/kyc/id-scanner/cases/{case_id}/scan-document
@JsonClass(generateAdapter = true)
data class KycIdScannerScanRequestDto(
    @Json(name = "document_type") val documentType: String,  // passport|national_id_card|driving_license|residence_permit
    @Json(name = "file_type") val fileType: String = "id_front", // id_front|id_back
    @Json(name = "mrz_lines") val mrzLines: List<String>? = null,
    @Json(name = "image_ref") val imageRef: String? = null   // a document_id from upload
)

@JsonClass(generateAdapter = true)
data class KycIdScannerScanOutDto(
    @Json(name = "scan_id") val scanId: String,
    @Json(name = "case_id") val caseId: String,
    @Json(name = "document_type") val documentType: String,
    @Json(name = "file_type") val fileType: String,
    @Json(name = "status") val status: String,               // matched|flagged|rejected|approved|declined
    @Json(name = "mrz_valid") val mrzValid: Boolean,
    @Json(name = "extraction") val extraction: KycIdScannerExtractionDto,
    @Json(name = "expiry_check") val expiryCheck: KycIdScannerExpiryCheckDto,
    @Json(name = "cross_reference") val crossReference: KycIdScannerCrossReferenceDto? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "review_decision") val reviewDecision: String? = null,
    @Json(name = "review_note") val reviewNote: String? = null
)

@JsonClass(generateAdapter = true)
data class KycIdScannerExtractionDto(
    @Json(name = "document_number") val documentNumber: String? = null,
    @Json(name = "given_names") val givenNames: String? = null,
    @Json(name = "surname") val surname: String? = null,
    @Json(name = "nationality") val nationality: String? = null,
    @Json(name = "date_of_birth") val dateOfBirth: String? = null,
    @Json(name = "sex") val sex: String? = null,
    @Json(name = "expiry_date") val expiryDate: String? = null,
    @Json(name = "issuing_state") val issuingState: String? = null,
    @Json(name = "format") val format: String? = null,
    @Json(name = "valid") val valid: Boolean? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "checksums") val checksums: Map<String, Boolean>? = null
)

@JsonClass(generateAdapter = true)
data class KycIdScannerExpiryCheckDto(
    @Json(name = "status") val status: String,               // valid|expired|expiring_soon|unknown
    @Json(name = "message") val message: String,
    @Json(name = "expiry_date") val expiryDate: String? = null,
    @Json(name = "days_until_expiry") val daysUntilExpiry: Int? = null
)

@JsonClass(generateAdapter = true)
data class KycIdScannerCrossReferenceDto(
    @Json(name = "match_score") val matchScore: Int,
    @Json(name = "total_fields_checked") val totalFieldsChecked: Int,
    @Json(name = "fields_matched") val fieldsMatched: Int,
    @Json(name = "matches") val matches: Map<String, Any?> = emptyMap(),
    @Json(name = "mismatches") val mismatches: Map<String, Any?> = emptyMap()
)

// Validate — POST /ui/kyc/id-scanner/cases/{case_id}/validate-document
@JsonClass(generateAdapter = true)
data class KycIdScannerValidateRequestDto(
    @Json(name = "document_type") val documentType: String
)

@JsonClass(generateAdapter = true)
data class KycIdScannerValidationOutDto(
    @Json(name = "document_type") val documentType: String,
    @Json(name = "sides_required") val sidesRequired: List<String>,
    @Json(name = "sides_present") val sidesPresent: List<String> = emptyList(),
    @Json(name = "has_mrz") val hasMrz: Boolean,
    @Json(name = "all_sides_present") val allSidesPresent: Boolean,
    @Json(name = "mrz_format") val mrzFormat: String? = null
)
```

> Verified against the live OpenAPI components.schemas and `src/api/types.ts` /
> `src/api/endpoints/kycIdScanner.ts` + `kycDocuments.ts`. OQ-1 from the draft (whether the
> guessed endpoints exist) is now **resolved: they did not**; see §13 and §16.

## 6. Data & State Management

- **Single source of truth:** `IdScannerViewModel` `StateFlow<IdScannerUiState>`.
  Captured-but-unsubmitted state survives configuration changes via the ViewModel and
  a `SavedStateHandle` index of side -> cache-file path (paths only, not bitmaps).
- **Repository:** `KycRepository` (AND-321) gains:

```kotlin
// CORRECTED to the real endpoints (no template list; per-side, case-scoped scan).
suspend fun validateIdRequirements(caseId: String, docType: String): ApiResult<IdValidation>
suspend fun uploadIdSide(caseId: String, side: String, fileName: String, contentB64: String): ApiResult<String> // -> document_id
suspend fun scanIdSide(caseId: String, req: IdScanRequest): ApiResult<IdScanResult>
suspend fun listIdScans(caseId: String): ApiResult<List<IdScanSummary>>
```

  If AND-321's `uploadDocument` already wraps `POST /ui/kyc/documents` (base64), reuse it as
  `uploadIdSide`. All return the project-standard `ApiResult<T>`.
- **No Room persistence** of the scan itself. There is **no template endpoint to cache**
  (corrected from the draft's `kyc_id_templates` DataStore plan); the document-type list is a
  compile-time constant, so no network cache is needed for it. `validate-document` results may
  optionally be cached per (case_id, doc_type) for the session to tolerate the flaky dev host.
  Captured images are cache-dir only and never enter Room.
- **Mapping:** DTO -> domain (`IdTemplate`, `IdScanResult`) in a `KycMappers.kt`;
  domain models live in `core-model`.

## 7. Error Handling & Resilience

- **Requirement-validation failure (`validate-document`):** the document-type list itself
  never fails (it is a local constant — corrected from the draft's "template load failure").
  If `validate-document` fails or is offline, fall back to the static side rule (passport =
  front only; others = front+back) and an optimistic `has_mrz` per type, show an
  "Offline — using defaults" banner (`isOffline = true`), and let the backend be
  authoritative at scan time.
- **Timeouts:** OkHttp call timeout 20s (project default). Idempotent GETs
  (`scans`, and a `validate-document` POST treated as safe-to-retry since it has no side
  effects) use bounded exponential backoff (max 3 tries, 0.5s/1s caps, jitter). The
  per-side `scan-document` POST and the `POST /ui/kyc/documents` upload are **not**
  auto-retried — surface an error with a manual "Try again" action to avoid duplicate
  scans/uploads.
- **Upload partial failure:** if any side upload fails, do not submit; mark the failed
  side in `REVIEW` with a per-side retry; already-uploaded sides keep their
  `documentId`.
- **401 mid-flow:** handled transparently by the OkHttp authenticator (one
  `/ui/session/refresh` then retry). If refresh fails, route to re-auth and preserve
  captured cache files for resume.
- **FastAPI `detail` mapping:** parse `string | [{msg}] | {code,...}` via the shared
  `ErrorBodyAdapter` (core-network) into `UiError`. Every KYC endpoint here advertises
  `422:HTTPValidationError` in the OpenAPI; on `422` (e.g. unreadable MRZ, bad case_id) show
  the first `msg`.
- **Camera errors:** permission denied -> rationale + settings deep-link;
  `CameraUnavailable` -> non-camera fallback message (no manual file picker here —
  capture is required for ID integrity).
- **`rejected`/`declined` status:** a 201 with a negative `status` is treated as success
  transport-wise; UI shows the reason (`expiry_check.message` / `review_note` /
  `cross_reference.mismatches`) + restart.

## 8. Security & Privacy

- **No plaintext leak:** the dev backend is HTTP; treat all ID imagery as sensitive.
  Cache files are in app-internal `cacheDir` (not external storage), excluded from
  auto-backup via `android:fullBackupContent` rules and `dataExtractionRules`
  (`<exclude domain="file" path="kyc/"/>`).
- **Lifespan:** captured stills deleted on submit, cancel, and best-effort on
  `onCleared`; never written to the gallery `MediaStore`.
- **EXIF/geo:** strip EXIF (including GPS) from JPEGs before upload.
- **No logging of imagery or extracted PII** (document number, expiry) — see §10.
  Telemetry carries only non-PII identifiers (`scan_id`, `status`, `case_id`,
  `document_type`).
- **Screenshots:** set `FLAG_SECURE` on the hosting window while in the ID scan flow.
- **CSRF/cookies:** ride the existing persistent cookie jar; send `X-CSRF-Token` (from
  `ui_csrf`) plus `Authorization: Bearer` on every mutating call (`POST /ui/kyc/documents`,
  `validate-document`, `scan-document`) — matching `src/api/client.ts`.
- **Permissions:** request `CAMERA` only; no storage permission needed (cache-dir + inline
  base64 upload, no MediaStore).

## 9. Accessibility & i18n

- All instructions, hints, and result text are string resources in `feature-kyc`
  `strings.xml`; no concatenated user-facing strings. Default locale `en`; layout is
  RTL-safe (overlay/inset logic mirrors).
- **Live hints announced** via `liveRegion` semantics so screen-reader users hear
  "MRZ detected", "Reduce glare", etc.
- **Manual shutter** carries a content description and is always reachable by
  TalkBack, so the auto-capture path is never the only way to proceed.
- Touch targets >= 48dp; color is not the sole signal for pass/fail (icon + text).
- Dynamic type respected; overlay text scales without clipping.

## 10. Telemetry & Logging

Events via the app analytics facade (`Analytics.log(event, props)`); **never** log
image bytes, MRZ contents, or extracted PII.

| Event | Properties |
|---|---|
| `kyc_id_scan_started` | `template_id` |
| `kyc_id_side_captured` | `side`, `auto: Boolean`, `sharpness_ok`, `glare_ok`, `mrz_lines` |
| `kyc_id_side_retake` | `side` |
| `kyc_id_upload_failed` | `side`, `http_status` |
| `kyc_id_scan_submitted` | `template_id`, `side_count` |
| `kyc_id_scan_result` | `scan_id`, `status`, `expiry_status`, `mrz_valid` (no PII; **corrected** — there is no `decision_reason` field) |

Debug logs (`Timber`, debug builds only) cover quality thresholds and HTTP status
codes — no payload bodies. Crashlytics breadcrumbs use `IdScanStep` names only.

## 11. Testing Strategy

**Unit (JVM, core-testing + Turbine):**
- `IdScannerViewModel` step machine: type select -> capture order respects
  `required_sides`; MRZ skipped when `has_mrz=false`.
- Retake restores to the correct side without dropping other sides.
- Quality gating: a `QualityReport` with `passed=false` blocks auto-capture.
- Error mapping: 422/`detail` variants -> `UiError`; offline `validate-document` fallback
  to static side rules.
- `scanIdSide` / `uploadIdSide` not retried on `5xx`; `validateIdRequirements` /
  `listIdScans` (GETs/safe POST) retried with backoff (fake clock).

**Analyzer unit tests:**
- `IdFrameAnalyzer` sharpness/glare/edge thresholds against fixture YUV frames.
- MRZ line counting against synthetic MRZ text fixtures (regex behavior).

**Repository tests:** MockWebServer for `POST /ui/kyc/documents` (201/422/500),
`POST /ui/kyc/id-scanner/cases/{case_id}/validate-document`, and
`POST /ui/kyc/id-scanner/cases/{case_id}/scan-document` (201/422/500), verifying request
JSON shape (`document_type`/`file_type`/`mrz_lines`/`content_b64`) and `X-CSRF-Token` +
`Authorization` header presence.

**Instrumented / UI (Compose test + fake VM):**
- Full happy path with a fake camera source emitting a passing frame -> capture ->
  upload (MockWebServer) -> per-side scan -> `matched`/`approved` panel. This is the backlog
  acceptance test: *ID scan captures + submits.*
- `rejected`/`declined` -> reason shown + restart returns to TYPE_SELECT.
- TalkBack semantics: live hint region present; shutter has content description.

**Manual QA matrix:** passport (front + MRZ lines), national ID (front+back + MRZ lines),
driving license (front+back, no MRZ), residence permit; glare/low-light retake;
airplane-mode offline `validate-document` fallback to static side rules; cancel mid-upload
clears cache.

## 12. Dependencies & Sequencing

- **Blocked by AND-321** (Document capture + upload): provides
  `CameraCaptureController`, `PresignUploader`, `KycRepository.uploadDocument`, and
  the document-template pattern. This ticket must not duplicate that plumbing.
- **Transitively** relies on AND-321's deps (AND-319 camera scaffolding, AND-129
  presign/upload infra).
- **Blocks AND-323** (Facial comparison): AND-323 reuses the completed KYC ID document
  set and the established `feature-kyc` capture surface.
- **Within this ticket, order:** (1) DTOs + `KycRepository` extensions +
  MockWebServer tests; (2) `IdFrameAnalyzer` + unit tests; (3) ViewModel state
  machine; (4) Compose surfaces + overlay; (5) wire CameraX analysis; (6) e2e
  acceptance test.

## 13. Risks & Open Questions

- **OQ-1 (API): RESOLVED during this review.** The draft's `GET /ui/kyc/id/templates` and
  `POST /ui/kyc/id/scan` do **not** exist. Verified live endpoints: `POST /ui/kyc/documents`
  (base64 upload), `POST /ui/kyc/id-scanner/cases/{case_id}/validate-document`,
  `POST /ui/kyc/id-scanner/cases/{case_id}/scan-document` (per side), and
  `GET /ui/kyc/id-scanner/cases/{case_id}/scans[/{scan_id}]`. See §5 and §16.
- **OQ-2 (MRZ scope): partially RESOLVED.** The backend explicitly accepts `mrz_lines`
  (optional `string[]`) in `KycIdScannerScanRequest`, and `KycIdScannerExtraction.checksums`
  shows it does its own MRZ parse/checksum. Open part: whether the backend can parse MRZ from
  the uploaded image alone (via `image_ref`) when `mrz_lines` is omitted — the web reference
  always sends `mrz_lines` for testing and omits `image_ref`. Decide whether the Android
  client must OCR MRZ into `mrz_lines` or may rely on `image_ref` only.
- **Risk — flaky dev host:** uploads/submit over a 20s-timeout HTTP host may fail
  often; mitigated by per-side retry on upload and manual retry on submit, with no
  auto-retry on the non-idempotent POST.
- **Risk — ML Kit text recognition size/latency:** MRZ OCR adds a model dependency and
  per-frame cost. Restrict to the MRZ ROI and the MRZ step only; consider gating
  behind document `has_mrz`.
- **Risk — quality thresholds:** Laplacian/glare thresholds are device-dependent;
  expose them as tunable `BuildConfig`/remote-config values and validate on the QA
  device matrix.
- **OQ-3:** Maximum image dimension/file-size limits for the **base64** `content_b64` body of
  `POST /ui/kyc/documents` (the schema sets no explicit max, but the flaky HTTP dev host and
  request-size limits matter) — confirm with the AND-321 owner to set downscale/JPEG-quality
  targets. **(Corrected: upload is base64, not presigned PUT.)**

## 14. Acceptance Criteria

AC-1. From the KYC entry point (with a `case_id`), the user can open the ID scanner, select
a document type from the fixed enum, and is guided through the required sides reported by
`POST /ui/kyc/id-scanner/cases/{case_id}/validate-document` (front, back as applicable, MRZ
capture when `has_mrz`). **(Corrected: no `GET /ui/kyc/id/templates`.)**

AC-2. Each side can be captured automatically (on passing quality for N consecutive
frames) or via the manual shutter; failing-quality frames do not auto-capture and a
corrective hint is shown.

AC-3. The REVIEW step shows all captured sides with working per-side retake.

AC-4. On confirm, each side uploads via `POST /ui/kyc/documents` (base64) and the flow calls
`POST /ui/kyc/id-scanner/cases/{case_id}/scan-document` per side with `document_type`,
`file_type`, the uploaded `image_ref` (`document_id`), and `mrz_lines` when applicable.
**(Corrected: no presign, no single `/scan` packet.)**

AC-5. The scan result (`matched`/`approved` success, `flagged` review, `rejected`/`declined`
failure with reason from `expiry_check.message` / `review_note` / `cross_reference`) is
displayed; failure offers restart. **(Backlog: ID scan captures + submits.)**

AC-6. Cancel discards un-submitted cache files; captured imagery never enters the
gallery/MediaStore and EXIF is stripped before upload.

AC-7. Live capture hints are announced to TalkBack and the manual shutter has a content
description.

AC-8. `validate-document` failure/offline falls back to the static side rule with an offline
banner; `scan-document` and `POST /ui/kyc/documents` are never auto-retried.
**(Corrected: there is no template list to cache.)**

## 15. Definition of Done

- All Acceptance Criteria (§14) met; backlog acceptance ("ID scan captures +
  submits") covered by an automated instrumented e2e test using MockWebServer + a fake
  camera frame source.
- Code in `feature-kyc` under `com.testlogon.android.feature.kyc.idscanner`; domain
  models in `core-model`; respects `app -> feature -> core` layering with no upward
  deps.
- Unit + repository + analyzer + Compose UI tests pass in CI; new code coverage meets
  module gate.
- No PII or image bytes in logs/telemetry; `FLAG_SECURE` set; backup-exclusion rules
  in place; EXIF stripped.
- Strings externalized and RTL-safe; minimum 48dp targets; live-region semantics
  verified.
- Lint/Detekt/ktlint clean; KSP (Hilt/Moshi/Room) builds with no warnings introduced.
- OQ-1/OQ-2/OQ-3 resolved against `/openapi.json` + `frontend/` reference, or
  explicitly deferred with an owner noted in the PR.
- PR reviewed and merged to `android-port`; AND-323 unblocked.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. OpenAPI references
cite `METHOD /path` and/or the `components.schemas.<Name>`; frontend references cite a file
path + symbol; framework choices are labelled "framework ref".

1. **ID-scanner scan endpoint is `POST /ui/kyc/id-scanner/cases/{case_id}/scan-document`,
   per-side, returns 201.** VERDICT: Corrected (draft said `POST /ui/kyc/id/scan`, single
   packet). SOURCE: OpenAPI `POST /ui/kyc/id-scanner/cases/{case_id}/scan-document`
   (op `scan_document_..._scan_document_post`, resp `201:KycIdScannerScanOut`);
   `src/api/endpoints/kycIdScanner.ts: scanKycIdDocument`.
2. **No `GET /ui/kyc/id/templates` (no template-list endpoint exists).** VERDICT: Corrected.
   SOURCE: absent from `reference/openapi.index.txt` (grep `/ui/kyc` shows only
   documents / id-scanner / liveness-call / proof-of-funds / residency / screening /
   webhooks); `src/pages/kyc/KycIdScannerPage.tsx` hardcodes `DOC_TYPES`.
3. **Document types are the enum `passport | national_id_card | driving_license |
   residence_permit`.** VERDICT: Corrected (draft used template ids `passport_td3`, etc.).
   SOURCE: schema `KycIdScannerScanRequest.document_type` enum;
   `src/api/types.ts: KycIdScannerDocumentType`.
4. **Scan request fields: `document_type` (req), `file_type` (`id_front|id_back`, default
   `id_front`), `mrz_lines` (`string[]?`), `image_ref` (`string?`, max 512).** VERDICT:
   Corrected (draft had `template_id` + `documents` map). SOURCE: schema
   `components.schemas.KycIdScannerScanRequest`; `src/api/types.ts: KycIdScannerScanRequest`.
5. **There is NO `mrz` file_type / `id_mrz` document; MRZ travels as `mrz_lines` text.**
   VERDICT: Corrected (draft treated MRZ as a separate uploaded side `id_mrz`). SOURCE:
   `KycIdScannerScanRequest.file_type` enum = `{id_front, id_back}` only;
   `KycDocumentUploadRequest.document_type` enum = `{id_front, id_back}` only.
6. **Scan response status enum is `matched | flagged | rejected | approved | declined`.**
   VERDICT: Corrected (draft said `verified | pending | rejected`). SOURCE: schema
   `KycIdScannerScanOut.status` enum; `src/api/types.ts: KycIdScannerStatus`.
7. **Scan response has no `decision_reason` and no top-level `extracted` map; it exposes
   nested `extraction`, `expiry_check`, `cross_reference`, `mrz_valid`, `review_decision`,
   `review_note`.** VERDICT: Corrected. SOURCE: schema `KycIdScannerScanOut` (required:
   `scan_id, case_id, document_type, file_type, status, mrz_valid, extraction, expiry_check`);
   nested `KycIdScannerExtraction`, `KycIdScannerExpiryCheck`, `KycIdScannerCrossReference`;
   `src/pages/kyc/KycIdScannerPage.tsx` renders `scan.extraction` / `scan.expiry_check` /
   `scan.cross_reference`.
8. **`expiry_check.status` enum is `valid | expired | expiring_soon | unknown`.** VERDICT:
   Verified (new detail). SOURCE: schema `KycIdScannerExpiryCheck.status`;
   `src/api/types.ts: KycIdScannerExpiryStatus`.
9. **KYC document upload is `POST /ui/kyc/documents` with inline base64 (`content_b64`),
   not a presigned-S3 PUT; returns `KycDocumentOut`.** VERDICT: Corrected (draft said
   `POST /ui/kyc/documents/presign` -> S3 PUT). SOURCE: OpenAPI `POST /ui/kyc/documents`
   (req `KycDocumentUploadRequest`, resp `201:KycDocumentOut`); schema
   `KycDocumentUploadRequest.content_b64`; `src/api/endpoints/kycDocuments.ts: uploadKycDocument`.
   No `/ui/kyc/documents/presign` exists in the index (grep `presign` finds only messages /
   messaging / videos / fs domains).
10. **Upload returns a stable id in `KycDocumentOut.document_id`.** VERDICT: Verified.
    SOURCE: schema `KycDocumentOut` (required includes `document_id`).
11. **Per-type side/MRZ requirements come from
    `POST /ui/kyc/id-scanner/cases/{case_id}/validate-document` ->
    `KycIdScannerValidationOut { document_type, sides_required, sides_present, has_mrz,
    all_sides_present, mrz_format? }`.** VERDICT: Verified (replaces the draft's template
    fields). SOURCE: OpenAPI `POST /ui/kyc/id-scanner/cases/{case_id}/validate-document`;
    schema `KycIdScannerValidationOut`; `src/api/endpoints/kycIdScanner.ts: validateKycIdDocument`.
12. **Prior scans: `GET /ui/kyc/id-scanner/cases/{case_id}/scans` (list) and
    `.../scans/{scan_id}` (one).** VERDICT: Verified. SOURCE: OpenAPI those two GET ops
    (`KycIdScannerScanListResponse`, `KycIdScannerScanOut`);
    `src/api/endpoints/kycIdScanner.ts: listKycIdScans, getKycIdScan`.
13. **Auth model = cookie session + `X-CSRF-Token` (from `ui_csrf` cookie) + `Authorization:
    Bearer` + optional `X-IMPERSONATION-TOKEN`; 401 -> single `POST /ui/session/refresh`
    then retry.** VERDICT: Corrected/extended (draft mentioned only cookie+CSRF and the
    refresh). SOURCE: `src/api/client.ts` (lines ~157-170 set Authorization/CSRF/imp headers;
    `refreshSession()` posts `/ui/session/refresh`; 401 branch retries once).
14. **All these KYC endpoints advertise `422:HTTPValidationError`; FastAPI `detail` is
    `string | [{msg}] | {code,...}`.** VERDICT: Verified. SOURCE: `reference/openapi.index.txt`
    lines for `/ui/kyc/documents` and `/ui/kyc/id-scanner/*` all show `422:HTTPValidationError`.
15. **`KycIdScannerExtraction.checksums` (`KycIdScannerChecksums`) implies backend does MRZ
    checksum/parse.** VERDICT: Verified. SOURCE: schema `KycIdScannerExtraction.checksums`;
    `src/api/types.ts: KycIdScannerChecksums`.
16. **Android stack choices (CameraX, ML Kit Text Recognition for MRZ OCR, Compose, Hilt,
    Moshi, OkHttp authenticator, `FLAG_SECURE`, `dataExtractionRules` backup exclusion).**
    VERDICT: Unverified-assumption (framework ref — not derivable from backend/frontend
    sources). SOURCE (framework ref): Android docs — CameraX `developer.android.com/training/
    camerax`; ML Kit Text Recognition `developers.google.com/ml-kit/vision/text-recognition`;
    `FLAG_SECURE` `developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE`;
    backup rules `developer.android.com/guide/topics/data/autobackup`.

### Corrections made

- C1. Scan endpoint/path: `POST /ui/kyc/id/scan` (single packet) -> per-side
  `POST /ui/kyc/id-scanner/cases/{case_id}/scan-document` (claims 1, 4). §3 FR-8, §5.3, §5.4,
  §6, §14 AC-4.
- C2. Removed nonexistent `GET /ui/kyc/id/templates` and the whole template DTO/caching plan;
  replaced with the fixed doc-type enum + `validate-document` (claims 2, 3, 11). §3 FR-2,
  §5.1, §5.4, §6, §7, §11, §13 OQ-1, §14 AC-1/AC-8.
- C3. Upload: presigned-S3 PUT -> base64 `POST /ui/kyc/documents` (claim 9). §4.5, §5.2, §5.4,
  §6, §8, §13 OQ-3, §14 AC-4.
- C4. Status enum: `verified|pending|rejected` -> `matched|flagged|rejected|approved|declined`,
  and removed `decision_reason`/`extracted` in favor of `extraction`/`expiry_check`/
  `cross_reference`/`review_note` (claims 6, 7). §3 FR-9, §5.3, §7, §10, §14 AC-5.
- C5. MRZ: separate `id_mrz` uploaded side -> `mrz_lines` text on the side's scan request
  (claim 5). §3 FR-1, §4.5.
- C6. Auth: added `Authorization: Bearer` + impersonation header to the cookie+CSRF model
  (claim 13). §5 intro, §8.

### Open assumptions

- OA-1. **Overlay aspect ratios / inset geometry** per document type are not in any source
  (no `aspect_ratio`/`overlay_inset_pct` field exists). Treated as app-side UX constants;
  exact values unverifiable from backend/frontend — must be tuned on the QA device matrix.
- OA-2. **Whether the backend can parse MRZ from the uploaded image alone (`image_ref` only,
  no `mrz_lines`).** The web reference always sends `mrz_lines` and omits `image_ref`, so the
  image-only path is unverified. Decide whether Android must OCR MRZ client-side. (OQ-2.)
- OA-3. **Max base64 body size / image dimension limits** for `POST /ui/kyc/documents` — the
  schema sets none; the flaky HTTP dev host makes this a real constraint. Confirm with the
  AND-321 owner. (OQ-3.)
- OA-4. **`case_id` provenance.** The flow is case-scoped (`kyc_...`) but no source here mints
  a case; it is assumed to come from the upstream KYC wizard/AND-321. Unverified in this repo
  slice.
- OA-5. **OkHttp `Authenticator` re-applying the same single-refresh semantics as the web
  client** is an Android implementation assumption (framework ref), not a backend contract.

## 17. Test Plan

Test-target legend: JVM = local JVM/Robolectric unit; MWS = contract test against
MockWebServer; emulator = headless AVD `test35` (x86_64, API 35); device = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Cases needing a real camera MUST run on the
physical device; pure-UI/logic Compose/instrumented cases run on the emulator in CI.

- **TC-AND-322-01 — Step machine respects validated sides.** Type: unit (JVM). Target:
  `IdScannerViewModel`. Preconditions: fake `KycRepository.validateIdRequirements` returns
  `sides_required=[id_front]`, `has_mrz=true` for passport. Steps: select `passport`; advance.
  Expected: capture order = FRONT then MRZ capture, no BACK; `has_mrz=false` type (e.g.
  driving_license front+back) yields FRONT->BACK and no MRZ step. Traces: AC-1, AC-2.
- **TC-AND-322-02 — Quality gate blocks auto-capture.** Type: unit (JVM). Target:
  `IdScannerViewModel` + `IdFrameAnalyzer`. Preconditions: analyzer returns
  `QualityReport(passed=false)` (e.g. glare). Steps: feed N frames. Expected: no auto-capture;
  corrective `liveHint` emitted; manual shutter still enabled. Traces: AC-2.
- **TC-AND-322-03 — Analyzer thresholds & MRZ line count.** Type: unit (JVM/Robolectric).
  Target: `IdFrameAnalyzer`. Preconditions: fixture YUV frames (sharp/blurry, glare/no-glare)
  and synthetic MRZ text (2-line TD3, 3-line TD1, 1-line). Steps: run `analyze`. Expected:
  sharpness/glare/edge booleans match fixtures; `mrzLineCount` matches charset regex
  `^[A-Z0-9<]{30,44}$`. Traces: AC-2.
- **TC-AND-322-04 — Upload contract (`POST /ui/kyc/documents`).** Type: contract/MWS. Target:
  `KycRepository.uploadIdSide`. Preconditions: MWS returns 201 `KycDocumentOut{document_id}`.
  Steps: upload a front side. Expected: request body has `document_type=id_front`,
  `file_name`, `case_id`, `content_b64` (base64); headers include `X-CSRF-Token` +
  `Authorization`; parsed result exposes `document_id`. Traces: AC-4, AC-6.
- **TC-AND-322-05 — Scan contract (`scan-document`) happy path.** Type: contract/MWS. Target:
  `KycRepository.scanIdSide`. Preconditions: MWS returns 201 `KycIdScannerScanOut{status:
  "matched", mrz_valid:true, extraction, expiry_check}`. Steps: scan front of passport with
  `mrz_lines` + `image_ref`. Expected: POST path = `/ui/kyc/id-scanner/cases/{case_id}/
  scan-document`; body has `document_type=passport`, `file_type=id_front`, `mrz_lines`,
  `image_ref`; mapped result `status=matched`. Traces: AC-4, AC-5.
- **TC-AND-322-06 — Scan validation error (422).** Type: contract/MWS. Target: error mapping.
  Preconditions: MWS returns 422 `HTTPValidationError{detail:[{msg:"mrz unreadable"}]}` for
  scan. Steps: scan. Expected: first `msg` surfaced as `UiError`; scan NOT auto-retried (single
  request observed on MWS). Traces: AC-5, AC-8.
- **TC-AND-322-07 — Non-idempotent calls not auto-retried; GETs are.** Type: unit (JVM, fake
  clock) + MWS. Target: repository retry policy. Preconditions: MWS returns 500 then 201.
  Steps: (a) `scanIdSide`/`uploadIdSide` on 500; (b) `validateIdRequirements`/`listIdScans`
  on 500-then-201. Expected: (a) single request, error surfaced with manual retry; (b)
  retried with backoff and eventually succeeds. Traces: AC-8.
- **TC-AND-322-08 — Offline `validate-document` fallback.** Type: integration (JVM) + MWS.
  Target: ViewModel + repository. Preconditions: `validate-document` fails / network error.
  Steps: select national_id_card offline. Expected: `isOffline=true`, offline banner shown,
  static side rule applied (front+back), flow still proceeds; backend authoritative at scan.
  Traces: AC-8.
- **TC-AND-322-09 — Result rendering for all status groups.** Type: Compose-UI (emulator,
  fake VM). Target: `ResultPanel`. Preconditions: inject `KycIdScannerScanOut` with
  `status` in {matched, flagged, rejected}. Steps: render each. Expected: matched/approved =
  success UI; flagged = review/pending UI; rejected/declined = failure UI showing
  `expiry_check.message` / `review_note` / `cross_reference.mismatches` keys and a restart
  action returning to TYPE_SELECT. Traces: AC-5.
- **TC-AND-322-10 — Per-side retake preserves other sides.** Type: Compose-UI (emulator,
  fake VM). Target: `ReviewGrid` + ViewModel. Preconditions: front+back captured. Steps: tap
  Retake on BACK. Expected: returns to BACK capture; FRONT capture + any `document_id`
  retained. Traces: AC-3.
- **TC-AND-322-11 — Accessibility: live hints + shutter semantics.** Type: instrumented/
  Compose-UI (emulator). Target: `CaptureSurface`. Preconditions: capture step active. Steps:
  assert semantics. Expected: hint node is a `liveRegion`; manual shutter has a content
  description and is TalkBack-focusable; touch targets >= 48dp; pass/fail conveyed by
  icon+text (not color alone). Traces: AC-7.
- **TC-AND-322-12 — Security: FLAG_SECURE, no MediaStore, EXIF stripped, backup excluded.**
  Type: instrumented (emulator) + JVM. Target: host window + capture persistence. Steps:
  enter flow; capture; inspect window flags, cache file EXIF, MediaStore, and
  `dataExtractionRules`. Expected: `FLAG_SECURE` set while in flow; JPEG has no EXIF/GPS; no
  gallery/MediaStore entry; `kyc/` excluded from backup; cache files deleted on cancel/submit.
  Traces: AC-6.
- **TC-AND-322-13 — Camera permission denied path.** Type: instrumented (emulator, permission
  revoked). Target: `CaptureSurface`. Steps: deny CAMERA. Expected: rationale + settings
  deep-link shown; no crash; no file picker fallback (capture required). Traces: AC-2, AC-6.
- **TC-AND-322-14 — Real-device e2e capture + scan (backlog acceptance).** Type:
  instrumented/e2e — **MUST run on the physical device** (SM-A156U) for real CameraX capture
  on arm64/API 34. Target: full flow with MWS-backed `documents`/`scan-document`. Pre:
  passport selected, good lighting. Steps: capture front (auto on passing quality) -> OCR MRZ
  -> upload -> scan -> result. Expected: `matched` result panel; backlog acceptance "ID scan
  captures + submits" satisfied. Also note arm64-vs-x86 ABI: ML Kit + CameraX behavior
  verified on real hardware where the emulator's synthetic camera cannot exercise focus/glare.
  Traces: AC-1, AC-2, AC-4, AC-5.

### Coverage matrix

| AC | Covered by |
|---|---|
| AC-1 | TC-01, TC-14 |
| AC-2 | TC-01, TC-02, TC-03, TC-13, TC-14 |
| AC-3 | TC-10 |
| AC-4 | TC-04, TC-05, TC-14 |
| AC-5 | TC-05, TC-06, TC-09, TC-14 |
| AC-6 | TC-04, TC-12, TC-13 |
| AC-7 | TC-11 |
| AC-8 | TC-06, TC-07, TC-08 |
