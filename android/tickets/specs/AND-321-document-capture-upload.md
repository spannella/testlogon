---
id: AND-321
title: Document capture + upload
milestone: M7
epic: E42
priority: P0
size: L
status: draft
depends_on: [AND-319, AND-129]
blocks: []
---

# AND-321 — Document capture + upload

## 1. Overview & Goal

This ticket delivers in-app KYC document capture and upload for the TestLogon
native Android client. The user must be able to (a) pick a required document type
from a server-driven template list, (b) capture one or more pages of that document
using the device camera, (c) review and retake captured pages, and (d) upload each
captured image to backend storage via the reusable attachment pipeline, after
which the document is registered against the user's KYC case as a `kycDocuments`
entry.

The functional bar from the backlog is: **capture and upload a document, end to
end, with test coverage.** This spec scopes the camera capture surface (CameraX),
the document-template picker that drives capture requirements, and the wiring of
the upload to the existing presign → PUT → confirm uploader plus the KYC document
registration call. It does not re-specify the KYC payload DTOs (owned by AND-319)
nor the generic uploader mechanics (owned by AND-129); it consumes both.

Goal definition of success: a signed-in user in the KYC flow can select a document
template (e.g. "Passport — single page", "Driver's licence — front & back"),
capture each required page with the camera, and have all pages uploaded and
confirmed to the backend, producing a `kycDocuments` record the case can evaluate
against.

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-kyc` (`com.testlogon.android.feature.kyc`). Capture
  composables live under `feature-kyc/capture/`, document picker under
  `feature-kyc/documents/`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore,
  Coil, Paging 3. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- New dependency: AndroidX CameraX 1.4.x (`camera-core`, `camera-camera2`,
  `camera-lifecycle`, `camera-view`). Added to the version catalog under a
  `camerax` bundle and consumed only by `feature-kyc`.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. KYC endpoints under `/v1/kyc/*`.
- Web reference: `frontend/src/api/endpoints/kyc.ts` and the attachment endpoints;
  shared types in `frontend/src/api/types.ts`.
- Dependency tickets:
  - **AND-319 — KYC API + DTOs**: provides `KycApi`, `KycDocumentDto`,
    `KycDocumentTemplateDto`, `KycRequirementsDto`, and the `/v1/kyc/*` Retrofit
    surface. This ticket consumes those types; it does not redefine them.
  - **AND-129 — Attachment pipeline (presign→PUT→confirm)**: provides
    `AttachmentUploader` with progress, cancel, and retry. This ticket calls it
    once per captured page.
- Cross-cutting infra consumed: persistent cookie jar (AND-011), CSRF interceptor
  (AND-012), 401-refresh authenticator (AND-013), `ApiResult<T>` (AND-018),
  error/detail mapping (AND-015), state composables (AND-021).

## 3. Functional Requirements

FR-1 **Template selection.** On entering the capture flow the user is presented
with the list of required documents for their current KYC tier/case, sourced from
`KycRequirementsDto` (AND-319). Each template names a document type and the pages
it requires (e.g. front, back). The user selects one template to begin capture.

FR-2 **Camera permission.** The flow requests `CAMERA` runtime permission on first
entry. If denied, show a rationale state with a button to retry or open app
settings. The screen never crashes when permission is absent.

FR-3 **Live capture.** Show a CameraX preview with a document-shaped overlay/guide,
a capture (shutter) button, a flash toggle, and a page indicator ("Page 1 of 2").
Tapping shutter captures a still image to app-internal storage.

FR-4 **Per-page review.** After each capture, show the captured frame full-screen
with **Retake** and **Use photo** actions. Retake discards the file and returns to
the preview for the same page. Use photo advances to the next required page or, if
all pages captured, to the upload step.

FR-5 **Upload.** When all required pages are captured, each page is uploaded via
the AND-129 `AttachmentUploader` (presign → PUT → confirm). A combined progress
indicator reflects aggregate bytes across pages. Upload is cancelable; on cancel
no `kycDocuments` registration occurs.

FR-6 **KYC registration.** After all pages are confirmed (each yielding an
`attachmentId`), the flow calls `POST /v1/kyc/documents` with the template's
document type and the ordered list of attachment ids to create the `kycDocuments`
record. Success returns a `KycDocumentDto`; the flow shows a success state and
returns the created document id to the caller via navigation result.

FR-7 **Resumability within session.** Captured page files persist in
internal cache until upload succeeds, so a process death during the review step can
restore captured pages (best effort, in-memory `SavedStateHandle` + cache files).

FR-8 **Constraints.** Images are JPEG, max edge resized to 2048 px, quality 85,
target ≤ 4 MB per page. Files exceeding the cap after compression are rejected with
an inline error prompting a retake.

## 4. Technical Design

Single-Activity Navigation-Compose. New routes registered in `feature-kyc`:

```
kyc/capture/{templateId}        -> DocumentCaptureScreen
kyc/capture/{templateId}/review -> CapturePreviewScreen (per-page)
kyc/capture/{templateId}/upload -> DocumentUploadScreen
```

ViewModel exposes `StateFlow<UiState>` per layering rules.

```kotlin
@HiltViewModel
class DocumentCaptureViewModel @Inject constructor(
    private val kycRepository: KycRepository,            // AND-319
    private val uploader: AttachmentUploader,            // AND-129
    private val imageProcessor: CaptureImageProcessor,
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<DocumentCaptureUiState>
    fun onTemplateLoaded(templateId: String)
    fun onPageCaptured(file: java.io.File)
    fun onRetakeCurrentPage()
    fun onConfirmCurrentPage()
    fun startUpload()
    fun cancelUpload()
    fun retryUpload()
}

sealed interface DocumentCaptureUiState {
    data object Loading : DocumentCaptureUiState
    data class Capturing(
        val template: KycDocumentTemplate,
        val currentPageIndex: Int,
        val capturedPages: List<CapturedPage>,
        val flashOn: Boolean,
    ) : DocumentCaptureUiState
    data class Reviewing(val page: CapturedPage, val pageIndex: Int) : DocumentCaptureUiState
    data class Uploading(val progress: Float, val pageStatus: List<PageUploadStatus>) : DocumentCaptureUiState
    data class Success(val document: KycDocumentDto) : DocumentCaptureUiState
    data class Error(val error: UiError, val retryable: Boolean) : DocumentCaptureUiState
    data class PermissionRequired(val permanentlyDenied: Boolean) : DocumentCaptureUiState
}

data class CapturedPage(val pageKey: String, val file: File, val attachmentId: String? = null)
```

CameraX is driven from Compose via an `AndroidView` wrapping `PreviewView`:

```kotlin
@Composable
fun DocumentCaptureScreen(
    state: DocumentCaptureUiState.Capturing,
    onCaptured: (File) -> Unit,
    onToggleFlash: () -> Unit,
)

class DocumentCaptureController(context: Context, lifecycleOwner: LifecycleOwner) {
    fun bind(previewView: PreviewView)              // binds Preview + ImageCapture use cases
    fun setFlash(enabled: Boolean)
    suspend fun capture(outputFile: File): Result<File>   // ImageCapture.takePicture wrapped in suspendCancellableCoroutine
    fun release()
}
```

Capture writes to `context.cacheDir/kyc-capture/<sessionId>/<pageKey>.jpg`.
`CaptureImageProcessor` reads the captured file, fixes EXIF orientation, downsizes
to the 2048 px / quality-85 / ≤4 MB constraint, and rewrites the file in place,
returning its byte size.

Upload step iterates captured pages and calls the AND-129 uploader. Pages upload
sequentially (the dev host is unreliable; sequential keeps progress legible and
bounds concurrent failures). Aggregate progress = sum(uploaded bytes) / sum(total
bytes). After all pages confirm, call `KycRepository.createDocument(...)`.

```kotlin
interface KycRepository {                            // surface added here, types from AND-319
    suspend fun requirements(): ApiResult<KycRequirementsDto>
    suspend fun createDocument(
        documentType: String,
        attachmentIds: List<String>,
    ): ApiResult<KycDocumentDto>
}
```

Cancellation cancels the active uploader job and any in-flight CameraX capture
coroutine; cache files for the session are deleted on successful registration and
on explicit cancel/discard.

## 5. API Contract

This ticket consumes two pre-existing surfaces and adds one KYC call.

**Attachment pipeline (AND-129)** — invoked per page; exact presign/PUT/confirm
shapes are owned by AND-129. This ticket only relies on its contract: input = a
local file + MIME `image/jpeg`; output = a confirmed `attachmentId: String` with
progress callbacks.

**KYC document registration** — added here, DTOs from AND-319:

```
POST /v1/kyc/documents
Headers: X-CSRF-Token: <ui_csrf cookie value>   (cookie-based session)
Request:
{
  "document_type": "passport",
  "attachments": ["att_9f2c...", "att_0b71..."]   // ordered: page 1, page 2
}
Response 201:
{
  "id": "kycdoc_a1b2",
  "document_type": "passport",
  "status": "pending_review",
  "attachments": ["att_9f2c...", "att_0b71..."],
  "created_at": "2026-06-05T12:00:00Z"
}
```

**Requirements / templates (read)** — from AND-319, used to populate the picker:

```
GET /v1/kyc/requirements
Response 200:
{
  "tier": "tier_2",
  "documents": [
    { "document_type": "passport", "label": "Passport",
      "pages": [{ "key": "main", "label": "Photo page" }] },
    { "document_type": "drivers_license", "label": "Driver's licence",
      "pages": [{ "key": "front", "label": "Front" }, { "key": "back", "label": "Back" }] }
  ]
}
```

FastAPI error bodies follow the standard `detail` mapping (string |
`[{msg}]` | `{code,...}`) handled by AND-015. `POST /v1/kyc/documents` is **not**
idempotent and therefore is excluded from the AND-016 GET retry/backoff policy.

## 6. Data & State Management

- **Transient capture state** lives in `DocumentCaptureViewModel` (`StateFlow`)
  plus `SavedStateHandle` for the template id, current page index, and the list of
  captured page keys (to survive process death during review).
- **Captured image bytes** live as files in `cacheDir/kyc-capture/<sessionId>/`,
  not in memory and not in Room. Files are deleted on success, cancel, or discard;
  a startup sweeper deletes orphaned session dirs older than 24 h.
- **No Room caching** of capture state — capture is a one-shot flow, not a cached
  read surface. The resulting `KycDocumentDto` is owned by AND-319's cache layer if
  KYC lists are cached there; this ticket only hands off the created record.
- **No new DataStore keys.** Flash preference is not persisted (resets per session).
- Navigation result: the created `kycDocumentId` is returned to the calling KYC
  screen via the Navigation-Compose `savedStateHandle` result pattern on back.

## 7. Error Handling & Resilience

- **Permission denied / permanently denied**: render `PermissionRequired`; offer
  "Open settings" when `shouldShowRequestPermissionRationale` is false after denial.
- **Camera bind/capture failure** (no camera, device busy, `ImageCaptureException`):
  surface a retake-able inline error; do not advance the page.
- **Compression over cap**: reject with "Image too large, retake" — never upload an
  oversized file.
- **Upload failures**: the AND-129 uploader handles presign/PUT/confirm retry. At
  this layer, a failed page leaves the flow in `Uploading` with that page marked
  `Failed`; `retryUpload()` resumes from the first non-confirmed page (already
  confirmed pages keep their `attachmentId`, no re-upload).
- **Registration failure** after all pages confirmed: keep the confirmed
  `attachmentId`s in state so `createDocument` can be retried without re-uploading.
- **Timeouts**: OkHttp client timeout ~20 s (per project policy). The
  non-idempotent `POST /v1/kyc/documents` is **not** auto-retried; the user retries
  explicitly via the error state.
- **401**: handled transparently by the AND-013 authenticator (one refresh +
  retry); if refresh fails, propagate to an auth-expired error state.
- **Offline**: connectivity probe (AND-017) gates the upload step; capture is
  allowed offline, upload shows an offline state and a retry affordance.

## 8. Security & Privacy

- Captured documents are sensitive PII. Files are written only to app-internal
  `cacheDir` (no external/shared storage, no `MediaStore`, no gallery write).
- Captured files are deleted immediately after successful registration, on cancel,
  and via the orphan sweeper; never retained beyond the session.
- No capture image bytes are logged. Telemetry (Section 10) records only metadata
  (page count, byte sizes, durations, document type) — never image content,
  filenames with user data, or attachment URLs containing signed query params.
- Session is cookie-based; the CSRF token rides as `X-CSRF-Token` (AND-012). Presign
  PUT URLs are short-lived storage URLs from AND-129 and are not persisted.
- `FileProvider` is used if any file URI must be shared with the camera; capture via
  CameraX `ImageCapture` writes directly to our file, avoiding broad URI grants.
- No screenshots prevention requirement specified; leave default (flag as open
  question in Section 13 if the case demands `FLAG_SECURE`).

## 9. Accessibility & i18n

- Shutter, flash, retake, use-photo, and cancel controls have
  `contentDescription`s and ≥48 dp touch targets.
- Capture guide overlay is decorative (`contentDescription = null`); page progress
  is announced via a `liveRegion` semantics on the "Page X of N" text.
- The flow is operable via TalkBack: capture button is reachable and labeled;
  permission rationale is focusable and readable.
- All user-facing strings (template labels are server-provided; static UI strings
  are local) live in `strings.xml` for translation; no hardcoded UI copy in
  composables. Document-type labels come from the backend `label` field.
- Respects dynamic font scaling and dark theme via Material 3 theme (AND-019).

## 10. Telemetry & Logging

Use the redacted telemetry facade (AND-052 pattern). Events:

- `kyc_capture_started` { document_type, required_pages }
- `kyc_page_captured` { document_type, page_index, byte_size, capture_ms }
- `kyc_page_retaken` { document_type, page_index }
- `kyc_upload_started` { document_type, page_count, total_bytes }
- `kyc_upload_progress` (sampled) { percent }
- `kyc_upload_failed` { document_type, page_index, error_code }
- `kyc_document_registered` { document_type, kyc_document_id }
- `kyc_capture_cancelled` { document_type, stage }

Logging is metadata-only and redacted; no image bytes, no signed URLs, no PII
field values. Failures log the mapped `ApiError.code`, not raw response bodies.

## 11. Testing Strategy

Acceptance requires the capture+upload path be **tested**.

**Unit (JVM, core-testing + MockWebServer):**
- `DocumentCaptureViewModel` state machine: load template → capture N pages →
  retake → confirm → upload (mocked `AttachmentUploader` returning attachment ids)
  → `createDocument` success → `Success`. Assert `StateFlow` transitions.
- Failure paths: upload failure leaves page `Failed`, `retryUpload` resumes from
  first unconfirmed page without re-uploading confirmed pages; registration failure
  retries without re-upload.
- `CaptureImageProcessor`: EXIF orientation fix and downsize-to-cap on a fixture
  JPEG; oversized image rejected.
- `KycRepository.createDocument`: `POST /v1/kyc/documents` request body shape
  (ordered `attachments`), 201 mapping to `KycDocumentDto`, error `detail` mapping
  via MockWebServer.

**Instrumented / Compose UI tests:**
- Permission-denied state renders rationale and "Open settings".
- Review screen Retake/Use-photo navigation advances pages.
- Upload progress and success states render; cancel returns without registration.
- CameraX preview is bound behind a fake `DocumentCaptureController` (interface
  seam) so tests run on a headless emulator without a real camera; capture is
  simulated by invoking `onCaptured(fixtureFile)`.

**Definition of "tested document upload":** an instrumented test that simulates
capturing the required pages and asserts a `kycDocuments` registration request is
sent to MockWebServer with the correct ordered attachment ids and the UI reaches
`Success`.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):**
  - AND-319 (KYC API + DTOs) — provides `KycApi`, document/template/requirements
    DTOs, and `KycRepository` types consumed here.
  - AND-129 (Attachment pipeline) — provides `AttachmentUploader` (presign→PUT→
    confirm, progress/cancel/retry) used per page.
- **Transitively relied on:** AND-011 cookie jar, AND-012 CSRF, AND-013 refresh,
  AND-015 error mapping, AND-018 `ApiResult`, AND-019 theme, AND-021 state
  composables, AND-017 connectivity, AND-046 MockWebServer harness, AND-052
  telemetry facade.
- **New library:** CameraX 1.4.x added to the version catalog and `feature-kyc`
  Gradle module only.
- **Blocks:** none listed in the backlog. Downstream KYC case-evaluation/review
  screens (E42) consume the produced `kycDocuments` records but are not gated by a
  declared id here.
- Sequencing within ticket: (1) CameraX catalog + module wiring, (2)
  `DocumentCaptureController` + processor, (3) ViewModel state machine + repo call,
  (4) Compose screens, (5) tests.

## 13. Risks & Open Questions

- **Headless-emulator camera**: real CameraX cannot run on CI's headless emulator;
  mitigated by the `DocumentCaptureController` interface seam and a fake. Risk: the
  real bind path stays manually tested only. (Accepted.)
- **Backend document endpoint shape**: the exact `POST /v1/kyc/documents` request
  field names (`document_type`, `attachments`) are inferred from the web reference
  and `/openapi.json`; confirm against AND-319's finalized DTOs before merge. Open.
- **Per-page vs. multi-page documents**: assumes the template enumerates discrete
  pages with keys. If the backend expects a single multi-image attachment instead
  of N attachment ids, the registration call changes. Open — verify with AND-319.
- **Compression cap (4 MB / 2048 px)**: values are assumptions; confirm storage and
  KYC-review minimum resolution requirements. Open.
- **`FLAG_SECURE` / screenshot blocking** on the capture surface: not specified;
  recommend enabling for PII screens — needs product decision. Open.
- **Idempotency**: registration is treated as non-idempotent; if the backend
  supports an idempotency key, add it to avoid duplicate documents on retry. Open.

## 14. Acceptance Criteria

AC-1 A signed-in user can open the capture flow, see the server-driven list of
required documents, and select one template. (Backlog: "templates.")

AC-2 With camera permission granted, the user can capture each required page using
CameraX, review each captured page, and retake or accept it. (Backlog: "CameraX
capture.")

AC-3 On accepting all pages, every page uploads via the AND-129 presign→PUT→confirm
pipeline with visible aggregate progress and a working cancel. (Backlog:
"`kycDocuments` upload via presign.")

AC-4 After all pages confirm, `POST /v1/kyc/documents` is sent with the correct
`document_type` and ordered `attachments`, and on 201 the UI reaches a success
state exposing the created `kycDocumentId`.

AC-5 Camera permission denial, capture failure, upload failure, and registration
failure each produce a non-crashing, retry-able state; retry after a partial upload
does not re-upload already-confirmed pages.

AC-6 Captured image files never leave app-internal storage and are deleted on
success/cancel; no image bytes or signed URLs appear in logs/telemetry.

AC-7 An automated test (MockWebServer + Compose, on the headless emulator)
simulates capturing the required pages and asserts the `kycDocuments` registration
request and a `Success` UI state. (Backlog: "tested.")

## 15. Definition of Done

- All Acceptance Criteria (Section 14) met and demonstrated.
- `feature-kyc` capture flow implemented with the routes, ViewModel, controller,
  processor, and composables described in Section 4, namespaced
  `com.testlogon.android.feature.kyc`.
- CameraX added to the version catalog and `feature-kyc` only; no leakage to other
  modules.
- Unit tests (ViewModel state machine, image processor, repository request/response
  mapping) and instrumented Compose/UI tests pass locally and in CI (AND-050 /
  AND-051).
- Lint, ktlint/detekt (AND-005) clean; no new warnings introduced.
- No image bytes, signed URLs, or PII in logs/telemetry; capture files swept.
- Open questions in Section 13 either resolved with AND-319/product or explicitly
  tracked as follow-ups before merge.
- Code reviewed and merged to `android-port`.
