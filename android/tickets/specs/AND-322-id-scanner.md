---
id: AND-322
title: ID scanner
milestone: M7
epic: E42
priority: P1
size: L
status: draft
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
`FRONT -> BACK -> MRZ (conditional) -> REVIEW -> SUBMIT`. The MRZ step is included
only when the selected document type declares `hasMrz = true` (e.g. passport,
national ID card). Driver-license-style documents skip MRZ.

FR-2. **Document type selection.** Before capture, the user picks a document type
from a backend-supplied template list (`GET /ui/kyc/id/templates`). Each template
defines aspect ratio, whether back/MRZ are required, and the overlay frame geometry.

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

FR-8. **Submit ID scan.** After uploads succeed, the flow POSTs the collected
`documentId`s and document type to `POST /ui/kyc/id/scan`. The response carries a
verification status that is surfaced to the user.

FR-9. **Result presentation.** Terminal states: `verified`, `pending` (manual review),
and `rejected` (with a reason and a retry affordance that restarts capture).

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
exit cleanup (best-effort `onCleared`).

### 4.6 Compose surfaces

`IdScannerScreen` is stateless and renders sub-Composables per step:
`DocTypePicker`, `CaptureSurface` (CameraX `PreviewView` via `AndroidView` + overlay +
hint chip + shutter), `ReviewGrid`, `UploadProgress`, `ResultPanel`. Live hints map to
localized strings.

## 5. API Contract

All paths are relative to the dev base `http://18.222.237.167:8000`. Cookie session +
`X-CSRF-Token` (from `ui_csrf` cookie) per project auth model; on 401 the OkHttp
authenticator does one `POST /ui/session/refresh` then retries. Mutating calls
(`/scan`) are **not** retried on transient failure; only idempotent GETs are.

### 5.1 List ID templates (GET, idempotent)

`GET /ui/kyc/id/templates`

```json
{
  "templates": [
    {
      "id": "passport_td3",
      "label": "Passport",
      "aspect_ratio": 1.42,
      "required_sides": ["front", "mrz"],
      "has_mrz": true,
      "overlay_inset_pct": 0.06
    },
    {
      "id": "national_id_td1",
      "label": "National ID card",
      "aspect_ratio": 1.586,
      "required_sides": ["front", "back", "mrz"],
      "has_mrz": true,
      "overlay_inset_pct": 0.05
    },
    {
      "id": "drivers_license",
      "label": "Driver's license",
      "aspect_ratio": 1.586,
      "required_sides": ["front", "back"],
      "has_mrz": false,
      "overlay_inset_pct": 0.05
    }
  ]
}
```

### 5.2 Upload sides (presigned — reused from AND-321)

For each captured side the flow calls `KycRepository.uploadDocument(...)`, which
performs the AND-321 two-step presign:
`POST /ui/kyc/documents/presign` -> S3 `PUT` -> returns `documentId`. No new endpoint
is introduced here; `documentType` is sent as `id_<side>` (e.g. `id_front`).

### 5.3 Submit ID scan (POST, non-idempotent)

`POST /ui/kyc/id/scan`

Request:

```json
{
  "template_id": "passport_td3",
  "documents": {
    "front": "doc_01HZX...",
    "mrz": "doc_01HZY..."
  }
}
```

Response 200:

```json
{
  "scan_id": "scan_01J2A...",
  "status": "verified",
  "decision_reason": null,
  "extracted": {
    "document_number": "X1234567",
    "expiry_date": "2030-04-01",
    "country": "USA"
  }
}
```

`status` ∈ `verified | pending | rejected`. On `rejected`, `decision_reason` is a
non-null short code (e.g. `mrz_unreadable`, `expired`, `mismatch`).

### 5.4 DTOs (Moshi)

```kotlin
@JsonClass(generateAdapter = true)
data class IdTemplateDto(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String,
    @Json(name = "aspect_ratio") val aspectRatio: Float,
    @Json(name = "required_sides") val requiredSides: List<String>,
    @Json(name = "has_mrz") val hasMrz: Boolean,
    @Json(name = "overlay_inset_pct") val overlayInsetPct: Float
)

@JsonClass(generateAdapter = true)
data class IdScanRequestDto(
    @Json(name = "template_id") val templateId: String,
    @Json(name = "documents") val documents: Map<String, String>
)

@JsonClass(generateAdapter = true)
data class IdScanResultDto(
    @Json(name = "scan_id") val scanId: String,
    @Json(name = "status") val status: String,
    @Json(name = "decision_reason") val decisionReason: String?,
    @Json(name = "extracted") val extracted: Map<String, String>?
)
```

> If `/ui/kyc/id/templates` or `/ui/kyc/id/scan` are absent from the live
> `/openapi.json` at implementation time, confirm exact paths/shapes against
> `frontend/src/api/endpoints/*.ts` before coding; treat the web app as authoritative
> (Open Question OQ-1).

## 6. Data & State Management

- **Single source of truth:** `IdScannerViewModel` `StateFlow<IdScannerUiState>`.
  Captured-but-unsubmitted state survives configuration changes via the ViewModel and
  a `SavedStateHandle` index of side -> cache-file path (paths only, not bitmaps).
- **Repository:** `KycRepository` (AND-321) gains:

```kotlin
suspend fun listIdTemplates(): ApiResult<List<IdTemplate>>
suspend fun submitIdScan(req: IdScanRequest): ApiResult<IdScanResult>
```

  `uploadDocument` already exists. All return the project-standard `ApiResult<T>`.
- **No Room persistence** of the scan itself; templates may be cached for the session
  via DataStore `kyc_id_templates` with a 1h TTL to tolerate the flaky dev host
  (stale-while-revalidate). Captured images are cache-dir only and never enter Room.
- **Mapping:** DTO -> domain (`IdTemplate`, `IdScanResult`) in a `KycMappers.kt`;
  domain models live in `core-model`.

## 7. Error Handling & Resilience

- **Template load failure:** show a retry panel; if a DataStore-cached template set
  exists, render it with an "Offline — using saved list" banner (`isOffline = true`).
- **Timeouts:** OkHttp call timeout 20s (project default). `listIdTemplates` (GET) uses
  bounded exponential backoff (max 3 tries, 0.5s/1s caps, jitter). `submitIdScan`
  (POST) and presigned uploads are **not** auto-retried — surface an error with a
  manual "Try again" action to avoid duplicate submissions.
- **Upload partial failure:** if any side upload fails, do not submit; mark the failed
  side in `REVIEW` with a per-side retry; already-uploaded sides keep their
  `documentId`.
- **401 mid-flow:** handled transparently by the OkHttp authenticator (one
  `/ui/session/refresh` then retry). If refresh fails, route to re-auth and preserve
  captured cache files for resume.
- **FastAPI `detail` mapping:** parse `string | [{msg}] | {code,...}` via the shared
  `ErrorBodyAdapter` (core-network) into `UiError`. `422` on `/scan` -> show the first
  `msg`.
- **Camera errors:** permission denied -> rationale + settings deep-link;
  `CameraUnavailable` -> non-camera fallback message (no manual file picker here —
  capture is required for ID integrity).
- **rejected status:** treated as success transport-wise; UI shows reason + restart.

## 8. Security & Privacy

- **No plaintext leak:** the dev backend is HTTP; treat all ID imagery as sensitive.
  Cache files are in app-internal `cacheDir` (not external storage), excluded from
  auto-backup via `android:fullBackupContent` rules and `dataExtractionRules`
  (`<exclude domain="file" path="kyc/"/>`).
- **Lifespan:** captured stills deleted on submit, cancel, and best-effort on
  `onCleared`; never written to the gallery `MediaStore`.
- **EXIF/geo:** strip EXIF (including GPS) from JPEGs before upload.
- **No logging of imagery or extracted PII** (document number, expiry) — see §10.
  Telemetry carries only non-PII identifiers (`scan_id`, `status`, `template_id`).
- **Screenshots:** set `FLAG_SECURE` on the hosting window while in the ID scan flow.
- **CSRF/cookies:** ride the existing persistent cookie jar; `X-CSRF-Token` header on
  the `/scan` POST.
- **Permissions:** request `CAMERA` only; no storage permission needed (cache-dir +
  presigned PUT).

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
| `kyc_id_scan_result` | `scan_id`, `status`, `decision_reason` |

Debug logs (`Timber`, debug builds only) cover quality thresholds and HTTP status
codes — no payload bodies. Crashlytics breadcrumbs use `IdScanStep` names only.

## 11. Testing Strategy

**Unit (JVM, core-testing + Turbine):**
- `IdScannerViewModel` step machine: type select -> capture order respects
  `required_sides`; MRZ skipped when `has_mrz=false`.
- Retake restores to the correct side without dropping other sides.
- Quality gating: a `QualityReport` with `passed=false` blocks auto-capture.
- Error mapping: 422/`detail` variants -> `UiError`; offline template fallback.
- `submitIdScan` not retried on `5xx`; `listIdTemplates` retried with backoff (fake
  clock).

**Analyzer unit tests:**
- `IdFrameAnalyzer` sharpness/glare/edge thresholds against fixture YUV frames.
- MRZ line counting against synthetic MRZ text fixtures (regex behavior).

**Repository tests:** MockWebServer for `/ui/kyc/id/templates` and `/ui/kyc/id/scan`
(200/422/500), verifying request JSON shape and `X-CSRF-Token` header presence.

**Instrumented / UI (Compose test + fake VM):**
- Full happy path with a fake camera source emitting a passing frame -> capture ->
  upload (MockWebServer) -> submit -> `verified` panel. This is the backlog
  acceptance test: *ID scan captures + submits.*
- `rejected` -> reason shown + restart returns to TYPE_SELECT.
- TalkBack semantics: live hint region present; shutter has content description.

**Manual QA matrix:** passport (front+MRZ), national ID (front+back+MRZ), driver's
license (front+back, no MRZ); glare/low-light retake; airplane-mode offline templates;
cancel mid-upload clears cache.

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

- **OQ-1 (API):** `GET /ui/kyc/id/templates` and `POST /ui/kyc/id/scan` shapes are
  inferred. Confirm exact paths/fields against `/openapi.json` and
  `frontend/src/api/endpoints/*.ts` before implementation. Fallback: if no dedicated
  scan endpoint exists, submit via the generic KYC document grouping used by AND-321.
- **OQ-2 (MRZ scope):** Client gates on MRZ line count only; backend owns
  parse/checksum. Confirm the backend tolerates MRZ images without client OCR (i.e.
  raw image is sufficient). If client-side MRZ text must be sent, add an `mrz_lines`
  field to the request.
- **Risk — flaky dev host:** uploads/submit over a 20s-timeout HTTP host may fail
  often; mitigated by per-side retry on upload and manual retry on submit, with no
  auto-retry on the non-idempotent POST.
- **Risk — ML Kit text recognition size/latency:** MRZ OCR adds a model dependency and
  per-frame cost. Restrict to the MRZ ROI and the MRZ step only; consider gating
  behind document `has_mrz`.
- **Risk — quality thresholds:** Laplacian/glare thresholds are device-dependent;
  expose them as tunable `BuildConfig`/remote-config values and validate on the QA
  device matrix.
- **OQ-3:** Maximum image dimension/file-size limits enforced by presign — confirm
  with AND-321 owner to set downscale targets.

## 14. Acceptance Criteria

AC-1. From the KYC entry point, the user can open the ID scanner, select a document
type from `GET /ui/kyc/id/templates`, and is guided through the template's required
sides (front, back as applicable, MRZ when `has_mrz`).

AC-2. Each side can be captured automatically (on passing quality for N consecutive
frames) or via the manual shutter; failing-quality frames do not auto-capture and a
corrective hint is shown.

AC-3. The REVIEW step shows all captured sides with working per-side retake.

AC-4. On confirm, all sides upload via the AND-321 presign path and the flow POSTs
`POST /ui/kyc/id/scan` with the collected `documentId`s and `template_id`.

AC-5. The scan result (`verified` / `pending` / `rejected` with reason) is displayed;
`rejected` offers restart. **(Backlog: ID scan captures + submits.)**

AC-6. Cancel discards un-submitted cache files; captured imagery never enters the
gallery/MediaStore and EXIF is stripped before upload.

AC-7. Live capture hints are announced to TalkBack and the manual shutter has a content
description.

AC-8. Template load failure falls back to the cached list with an offline banner when
available; `/scan` is never auto-retried.

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
