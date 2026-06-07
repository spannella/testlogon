---
id: AND-321
title: Document capture + upload
milestone: M7
epic: E42
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-319, AND-129]
blocks: []
---

# AND-321 — Document capture + upload

## 1. Overview & Goal

This ticket delivers in-app KYC document capture and upload for the TestLogon
native Android client. The user must be able to (a) pick a required document type
from a server-driven template list, (b) capture one or more pages of that document
using the device camera, (c) review and retake captured pages, and (d) upload each
captured image to the KYC service, which registers it as a `kycDocuments` entry
against the user's KYC case.

> CORRECTION (review 2026-06-06): the live backend uploads each KYC image **inline
> as base64 to `POST /ui/kyc/documents`** — there is **no presign→PUT→confirm
> attachment pipeline for KYC documents**, and no list of attachment ids. The
> AND-129 uploader as described does not apply to this endpoint. The capture and
> review UX below is sound; the upload/registration wiring is corrected throughout
> (see §5 and §16). Each captured image is one `POST /ui/kyc/documents` call.

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

FR-1 **Document-type selection.** On entering the capture flow the user picks which
ID image to capture. CORRECTION: the backend exposes no `kycRequirements` document
list with pages; the selectable `document_type` values are the fixed enum
`id_front` and `id_back` (verified: `KycDocumentUploadRequest.document_type`).
Labels are static/localized app strings. `GET /v1/kyc/document-templates/required/list`
may optionally be used to gate which ID is required for the user's tier, but it
returns PDF form-template versions, not an ID capture-page spec.

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

FR-5 **Upload.** When all required images are captured, each image is base64-encoded
and uploaded via `POST /ui/kyc/documents`. CORRECTION: there is no AND-129
presign→PUT→confirm step and no `attachmentId`; the image bytes ride inline as
`content_b64`. A progress indicator reflects per-call request progress (and, for a
two-image id_front/id_back capture, aggregate completion across the two calls).
Upload is cancelable; on cancel, any not-yet-sent images are not posted.

FR-6 **KYC registration.** Each captured image is registered by its own
`POST /ui/kyc/documents` call carrying `{ document_type, file_name, content_b64 }`.
On 201 the call returns a `KycDocumentOut` (note `document_id`, not `id`; `status`
in `pending|extracted|failed|approved|rejected`). The flow shows a success state and
returns the created `document_id` (last/primary image) to the caller via navigation
result. There is no separate "register the set of attachments" step — registration
and upload are the same call. (Because each call is independent and non-idempotent,
a retry after a successful call would create a duplicate document — see §7/§16.)

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

Upload step iterates captured images and POSTs each to `/ui/kyc/documents` with the
image base64-encoded. CORRECTION: there is no AND-129 uploader call and no
presign/confirm; the repository sends `content_b64` directly. Images upload
sequentially (the dev host is unreliable; sequential keeps progress legible and
bounds concurrent failures). Aggregate progress = completed calls / total calls
(byte-level progress is best-effort from the OkHttp request body).

```kotlin
interface KycRepository {                            // surface added here, types from AND-319
    // Optional tier gate; returns PDF template versions, not a capture-page list:
    suspend fun requiredTemplates(tier: String): ApiResult<KycRequiredTemplatesDto>
    // One call per captured image; image carried inline as base64:
    suspend fun uploadDocument(
        documentType: String,        // "id_front" | "id_back"
        fileName: String,
        contentB64: String,
        caseId: String? = null,
    ): ApiResult<KycDocumentDto>     // KycDocumentOut: document_id, status, ...
}
```

Cancellation cancels any in-flight upload call and in-flight CameraX capture
coroutine; cache files for the session are deleted on successful registration and
on explicit cancel/discard. Base64 of large images is done off the main thread.

## 5. API Contract

This ticket adds one KYC call. CORRECTION: it does **not** consume the AND-129
attachment pipeline — the KYC upload endpoint takes the image inline as base64, so
there is no presign/PUT/confirm and no `attachmentId`. AND-129 should be removed
from the hard-dependency list for this ticket (see §12/§16); it remains relevant
only if the team later migrates KYC to a presigned-upload backend.

> ~~**Attachment pipeline (AND-129)** — invoked per page; presign/PUT/confirm with
> a confirmed `attachmentId`.~~ Removed: not used by `POST /ui/kyc/documents`.

**KYC document upload** — added here, DTOs from AND-319.

> CORRECTION (review 2026-06-06): The authoritative contract differs materially
> from the original draft. The real endpoint is **`POST /ui/kyc/documents`** (NOT
> `/v1/kyc/documents`), it takes the **image inline as base64** (NOT a list of
> pre-uploaded attachment ids), and it registers **one image per call** (NOT a
> multi-page document with N attachment ids). There is therefore **no
> presign→PUT→confirm step for KYC documents** — see the §16 audit and the revised
> §1/§3/§4 notes. Verified against `openapi.index.txt` line 1533
> (`POST /ui/kyc/documents | req=KycDocumentUploadRequest | resp=201:KycDocumentOut`),
> schema `KycDocumentUploadRequest`/`KycDocumentOut`, and
> `src/api/endpoints/kycDocuments.ts: uploadKycDocument`.

```
POST /ui/kyc/documents
Headers: X-CSRF-Token: <ui_csrf cookie value>   (cookie-based session; verified)
Request (KycDocumentUploadRequest):
{
  "document_type": "id_front",      // enum: "id_front" | "id_back" ONLY
  "file_name": "id_front.jpg",      // required, 1..255 chars
  "content_b64": "<base64 jpeg>",   // optional in schema, but required to upload bytes
  "case_id": "case_..."             // optional
}
Response 201 (KycDocumentOut):
{
  "document_id": "...",             // NOT "id"
  "document_type": "id_front",
  "file_name": "id_front.jpg",
  "status": "pending",              // enum: pending|extracted|failed|approved|rejected
  "image_url": null,                // single image ref; NO "attachments" array
  "extracted_fields": {},
  "case_id": null,
  "user_sub": null,
  "created_at": 0,                  // integer epoch seconds, NOT an ISO string
  "updated_at": 0
}
```

A front-and-back ID is therefore **two separate `POST /ui/kyc/documents` calls**
(`id_front`, then `id_back`), each carrying its own base64 image — not one
registration call with two attachment ids.

**Templates / tier requirements (read)** — from AND-319.

> CORRECTION: There is **no** `GET /v1/kyc/requirements` endpoint. The closest
> real endpoint is **`GET /v1/kyc/document-templates/required/list?tier=<tier>`**
> (`op=required_for_tier`, resp `200:KycRequiredTemplatesOut`). However these
> "document templates" are **server-side PDF form templates** (fields:
> `template_id, slug, display_name, s3_key, placeholder_fields, versions`) keyed
> by `required_tier` — they are **not** a per-page ID-image capture spec and carry
> **no `pages[]` array**. The capture-page model in this spec is an Android-side
> construct, not a backend contract.

```
GET /v1/kyc/document-templates/required/list?tier=tier_2
Response 200 (KycRequiredTemplatesOut):
{
  "tier": "tier_2",
  "items": [ /* KycDocumentTemplateVersionOut[] — PDF template versions */ ]
}
```

Because the backend offers no per-tier list of *ID-image* document types with
page breakdowns, the Android picker derives its choices from the fixed
`document_type` enum (`id_front`, `id_back`) plus static, localized labels. Any
richer "template with pages" UX is an app-side affordance, not a server contract.
This is flagged as an open assumption in §16.

FastAPI error bodies follow the standard `detail` mapping (string |
`[{msg}]` | `{code,...}`) handled by AND-015; validation errors return
`422 HTTPValidationError` (verified in the endpoint index). `POST /ui/kyc/documents`
is **not** idempotent and is excluded from the AND-016 GET retry/backoff policy.
(Unlike `/api/v1/kyc/applications/*`, this endpoint accepts **no** `Idempotency-Key`
header — see §13/§16.)

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
- **Upload failures**: CORRECTION — there is no AND-129 retry layer. A failed
  `POST /ui/kyc/documents` leaves the flow in `Uploading` with that image marked
  `Failed`; `retryUpload()` resumes from the first image that did **not** return a
  `document_id` (images that already returned a `document_id` are skipped, since the
  endpoint is non-idempotent and re-posting would duplicate the document).
- **Partial success** of a two-image (id_front + id_back) capture: the
  already-registered `document_id` is retained in state so only the failed image is
  re-posted on retry — never the one that succeeded.
- **Timeouts**: OkHttp client timeout ~20 s (per project policy). Base64 payloads
  inflate request size ~33%, so the read/write timeout must comfortably exceed the
  largest expected ≤4 MB image. The non-idempotent `POST /ui/kyc/documents` is
  **not** auto-retried; the user retries explicitly via the error state.
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
- Session is cookie-based; the CSRF token rides as `X-CSRF-Token` from the `ui_csrf`
  cookie (AND-012) — verified against `src/api/client.ts`. CORRECTION: there are no
  presign PUT URLs (no AND-129 path); the base64 image is posted over the
  authenticated session connection. The base64 payload must never be logged.
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
- `KycRepository.uploadDocument`: `POST /ui/kyc/documents` request body shape
  (`document_type`, `file_name`, `content_b64`), 201 mapping to `KycDocumentDto`
  (`document_id`), and `422`/`detail` error mapping via MockWebServer. (CORRECTION:
  was `createDocument`/`/v1/kyc/documents`/`attachments`.)

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
  - ~~AND-129 (Attachment pipeline)~~ — CORRECTION: removed as a hard dep. The
    verified KYC endpoint uploads images inline as base64 (`content_b64`); it does
    not use presign→PUT→confirm. AND-129 is not consumed by this ticket.
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
- **Backend document endpoint shape**: RESOLVED during review (2026-06-06). Verified
  endpoint is `POST /ui/kyc/documents` with `KycDocumentUploadRequest`
  (`document_type` enum id_front/id_back, `file_name`, inline `content_b64`,
  optional `case_id`) → `201 KycDocumentOut` (`document_id`, `status`, `image_url`,
  integer `created_at`). The original draft's `/v1/kyc/documents` + `attachments[]`
  shape was wrong and has been corrected throughout. (Closed.)
- **Per-page vs. multi-page documents**: RESOLVED. The backend has no multi-attachment
  document; each image is its own document record. A front/back ID is two
  `POST /ui/kyc/documents` calls (id_front, id_back). (Closed.)
- **Template/requirements model**: the `pages[{key,label}]` template model has no
  backend counterpart; the only tier endpoint
  (`/v1/kyc/document-templates/required/list`) returns PDF form-template versions.
  The capture-page UX is an app-side construct. Open — confirm with product whether
  a richer ID-requirements service is planned, else keep the id_front/id_back model.
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

AC-3 On accepting all captured images, every image uploads via
`POST /ui/kyc/documents` (image inline as `content_b64`) with visible progress and
a working cancel. (Backlog: "`kycDocuments` upload." CORRECTION: the backlog's "via
presign" wording does not match the live endpoint, which is base64-inline; see §16.)

AC-4 Each `POST /ui/kyc/documents` is sent with a valid `document_type`
(`id_front`/`id_back`), `file_name`, and `content_b64`, and on 201 the UI reaches a
success state exposing the returned `document_id` (note: field is `document_id`, not
`id`; `status` ∈ pending|extracted|failed|approved|rejected).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Claim:** KYC document registration is `POST /v1/kyc/documents`.
   **VERDICT: Corrected.** Real endpoint is `POST /ui/kyc/documents`.
   **Source:** OpenAPI index `POST /ui/kyc/documents | op=upload_document_ui_kyc_documents_post | req=KycDocumentUploadRequest | resp=201:KycDocumentOut`; `src/api/endpoints/kycDocuments.ts: uploadKycDocument`.

2. **Claim:** Request body is `{ document_type, attachments: [attachmentId...] }`.
   **VERDICT: Corrected.** Real body is `KycDocumentUploadRequest` =
   `{ document_type, file_name, content_b64?, case_id? }`; image is inline base64,
   no attachment ids, one image per call.
   **Source:** schema `components.schemas.KycDocumentUploadRequest`;
   `src/api/types.ts: KycDocumentUploadRequest`; `src/api/endpoints/kycDocuments.ts`.

3. **Claim:** Pages are uploaded via the AND-129 presign→PUT→confirm pipeline,
   yielding `attachmentId`s.
   **VERDICT: Corrected.** No presign step exists for KYC documents; bytes ride
   inline as `content_b64`. AND-129 is not consumed.
   **Source:** absence of any presign/confirm op under `/ui/kyc/documents*` in the
   OpenAPI index; `KycDocumentUploadRequest` carries `content_b64`, not a URL/id.

4. **Claim:** `document_type` may be `"passport"` / `"drivers_license"`.
   **VERDICT: Corrected.** Enum is exactly `id_front | id_back`.
   **Source:** schema `KycDocumentUploadRequest.document_type` (enum);
   `src/api/types.ts: KycDocumentType = "id_front" | "id_back"`;
   `src/pages/kyc/KycDocumentVerificationPage.tsx` (Select options id_front/id_back).
   (Note: `passport`/`driving_license` exist only on the separate
   `KycIdScannerScanRequest` for `/ui/kyc/id-scanner/.../scan-document`.)

5. **Claim:** 201 response body is `{ id, document_type, status:"pending_review", attachments, created_at: ISO8601 }`.
   **VERDICT: Corrected.** Real `KycDocumentOut` = `{ document_id, document_type,
   file_name, status, image_url?, extracted_fields, case_id?, user_sub?,
   created_at:int, updated_at:int, ... }`. Key field is `document_id` (not `id`),
   `status` ∈ `pending|extracted|failed|approved|rejected` (no `pending_review`),
   `created_at` is an integer epoch (not ISO), and there is no `attachments` array.
   **Source:** schema `components.schemas.KycDocumentOut`; `src/api/types.ts: KycDocumentOut`.

6. **Claim:** Templates/requirements come from `GET /v1/kyc/requirements` returning
   `{ tier, documents:[{document_type,label,pages:[{key,label}]}] }`.
   **VERDICT: Corrected.** No `/v1/kyc/requirements` endpoint exists. Closest is
   `GET /v1/kyc/document-templates/required/list?tier=` → `KycRequiredTemplatesOut`
   = `{ tier, items: KycDocumentTemplateVersionOut[] }`. These are PDF form
   templates (`template_id, slug, display_name, s3_key, placeholder_fields,
   versions`), with no `pages[]` and no ID-image capture spec.
   **Source:** OpenAPI index `GET /v1/kyc/document-templates/required/list | op=required_for_tier | resp=200:KycRequiredTemplatesOut`; schema `KycRequiredTemplatesOut`; `src/api/types.ts: KycDocumentTemplate`, `KycRequiredTemplates`; `src/api/endpoints/kycDocumentTemplates.ts: getRequiredKycTemplates`.

7. **Claim:** Session is cookie-based; CSRF rides as `X-CSRF-Token`.
   **VERDICT: Verified.** Header `X-CSRF-Token` is set from the `ui_csrf` cookie;
   requests use `credentials: "include"`.
   **Source:** `src/api/client.ts` (lines ~124, ~167-170: `getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).

8. **Claim:** Validation/error bodies use FastAPI `detail` mapping (AND-015).
   **VERDICT: Verified.** All KYC endpoints list `422:HTTPValidationError`.
   **Source:** OpenAPI index lines for `/ui/kyc/documents` and
   `/v1/kyc/document-templates/required/list` (`422:HTTPValidationError`);
   schema `HTTPValidationError`.

9. **Claim:** `POST /ui/kyc/documents` is non-idempotent and takes no idempotency key.
   **VERDICT: Verified.** Its `params=` lists no `Idempotency-Key`, unlike
   `/api/v1/kyc/applications` (`params=Idempotency-Key`).
   **Source:** OpenAPI index `POST /ui/kyc/documents` (params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN — no Idempotency-Key) vs `POST /api/v1/kyc/applications`.

10. **Claim:** CameraX `1.4.x` (camera-core/camera2/lifecycle/view) is the capture API.
    **VERDICT: Unverified-assumption (framework choice).** Not derivable from
    backend/frontend sources; standard Android choice for in-app camera capture.
    **Source:** framework ref — developer.android.com/training/camerax /
    developer.android.com/media/camera/camerax. (Version pin to confirm at impl.)

11. **Claim:** `CAMERA` runtime permission flow / `shouldShowRequestPermissionRationale`.
    **VERDICT: Unverified-assumption (framework choice).** Standard Android runtime
    permission behavior; not in backend/frontend sources.
    **Source:** framework ref — developer.android.com/training/permissions/requesting.

12. **Claim:** Image constraints JPEG, 2048 px max edge, quality 85, ≤4 MB.
    **VERDICT: Unverified-assumption.** No backend min/max resolution or size cap is
    expressed in the OpenAPI spec for `/ui/kyc/documents`.
    **Source:** none — app-side heuristic; needs product/KYC-review confirmation.

13. **Claim:** Dev host `http://18.222.237.167:8000`, OpenAPI at `/openapi.json`.
    **VERDICT: Unverified-assumption.** Frontend base URL is injected via
    `VITE_API_BASE_URL` env, not hardcoded; the IP is not present in sources.
    **Source:** `src/api/client.ts` (`API_BASE_URL = import.meta.env.VITE_API_BASE_URL`).

### Corrections made

- §1, §3 (FR-1, FR-5, FR-6), §4 (`KycRepository`, upload prose), §5, §7, §8, §11,
  §12, §13, §14 (AC-3, AC-4): endpoint corrected `/v1/kyc/documents` →
  `/ui/kyc/documents`.
- Request shape corrected from `{document_type, attachments[]}` to
  `KycDocumentUploadRequest {document_type, file_name, content_b64?, case_id?}`
  (inline base64, one image per call).
- Removed the AND-129 presign→PUT→confirm pipeline and `attachmentId` model; AND-129
  dropped from hard deps (§12).
- `document_type` enum corrected to `id_front|id_back` only; a front/back ID is two
  separate calls.
- Response corrected to `KycDocumentOut` (`document_id`, integer `created_at`,
  `status` enum without `pending_review`, no `attachments`).
- Requirements corrected: no `/v1/kyc/requirements`; tier endpoint returns PDF
  template versions, not capture pages; picker derives types from the fixed enum.
- CSRF/cookie behavior confirmed and cited (not changed).

### Open assumptions

- **CameraX version & API surface** (claim 10): framework choice, version to pin at
  implementation; cannot be verified from repo sources.
- **Runtime `CAMERA` permission semantics** (claim 11): standard Android behavior,
  not in sources.
- **Image size/resolution caps (4 MB / 2048 px / q85)** (claim 12): no backend-stated
  limit; must be confirmed with KYC-review/storage owners.
- **Dev host IP / `/openapi.json` path** (claim 13): host is env-injected in the web
  client; the literal IP is unverifiable from sources.
- **Tier-gated ID requirements**: whether `document-templates/required/list` should
  gate which ID is required is a product question; current model uses the static
  id_front/id_back enum.
- **`case_id` linkage**: whether the Android flow must pass `case_id` (optional in
  the schema) to attach the document to an open KYC case is unverified; the web page
  omits it. Confirm with AND-319.

## 17. Test Plan

Test target keys: **JVM** (local JVM/Robolectric, no device), **EMU**
(headless AVD `test35`, x86_64, API 35), **DEV** (physical Samsung Galaxy A15 5G,
SM-A156U, serial R5CX821TA9R, arm64-v8a, API 34). Hardware-dependent cases that need
a real camera MUST run on **DEV**.

- **TC-AND-321-01 — Happy path: capture + upload id_front (state machine)**
  Type: unit (JVM) + contract/MockWebServer. Target: JVM.
  Preconditions: fake `DocumentCaptureController` returns a fixture JPEG; MockWebServer
  enqueues `201 KycDocumentOut {document_id:"doc_1", status:"pending"}`.
  Steps: select `id_front` → simulate capture → confirm → startUpload.
  Expected: ViewModel emits Loading→Capturing→Reviewing→Uploading→Success; the
  recorded request is `POST /ui/kyc/documents` with body
  `{document_type:"id_front", file_name, content_b64:<non-empty>}` and header
  `X-CSRF-Token`; `Success.document.document_id == "doc_1"`.
  Traces: AC-2, AC-3, AC-4.

- **TC-AND-321-02 — Two-image id_front + id_back sequence**
  Type: unit (JVM) + contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues two 201s (`doc_front`, `doc_back`).
  Steps: capture id_front, confirm; capture id_back, confirm; startUpload.
  Expected: exactly two sequential `POST /ui/kyc/documents` calls with
  `document_type` `id_front` then `id_back`, each with its own `content_b64`; UI
  reaches Success; aggregate progress hits 2/2.
  Traces: AC-2, AC-3, AC-4.

- **TC-AND-321-03 — Validation error (422) mapping**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `422 HTTPValidationError`
  `{"detail":[{"loc":["body","file_name"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: upload with an empty `file_name`.
  Expected: `ApiResult` maps to a non-crashing `Error` with the AND-015 `detail`
  mapping; no Success; image file retained for retake/retry.
  Traces: AC-4, AC-5.

- **TC-AND-321-04 — Upload failure then retry without duplicating**
  Type: unit (JVM) + contract/MockWebServer. Target: JVM.
  Preconditions: id_front returns 201 (`doc_front`); id_back first returns
  `500`, then on retry `201 (doc_back)`.
  Steps: upload both → id_back fails → `retryUpload()`.
  Expected: after failure, id_back marked `Failed`, id_front keeps `doc_front`;
  retry posts ONLY id_back (id_front not re-posted, since endpoint is
  non-idempotent); UI reaches Success.
  Traces: AC-5.

- **TC-AND-321-05 — Cancel mid-upload sends no further documents**
  Type: unit (JVM). Target: JVM.
  Preconditions: uploader call suspended (MockWebServer throttled/no response).
  Steps: startUpload → cancelUpload before the call completes.
  Expected: in-flight call is cancelled; no additional `POST /ui/kyc/documents` is
  recorded; flow leaves Uploading without Success; cache files preserved or swept per
  cancel policy.
  Traces: AC-3, AC-5.

- **TC-AND-321-06 — Image processing: EXIF + downsize to cap; oversized rejected**
  Type: unit (Robolectric/JVM). Target: JVM (EMU if Bitmap decode needs device).
  Preconditions: fixture JPEGs — one rotated (EXIF orientation 6), one >4 MB after
  compression.
  Steps: run `CaptureImageProcessor` on each.
  Expected: rotated image is normalized upright; downsized image ≤4 MB and ≤2048 px
  max edge at q85; the un-shrinkable oversized image is rejected with the "Image too
  large, retake" error and is not uploaded.
  Traces: AC-2, AC-5 (and AC-6: oversized never sent).

- **TC-AND-321-07 — Camera permission denied renders rationale + Open settings**
  Type: Compose-UI / instrumented. Target: EMU.
  Preconditions: deny `CAMERA`; `shouldShowRequestPermissionRationale` false.
  Steps: enter capture flow, deny permission.
  Expected: `PermissionRequired(permanentlyDenied=true)` renders a focusable
  rationale and an "Open settings" button; no crash; capture surface not shown.
  Traces: AC-2, AC-5.

- **TC-AND-321-08 — Review screen Retake/Use-photo navigation**
  Type: Compose-UI / instrumented. Target: EMU.
  Preconditions: capture simulated via fake controller `onCaptured(fixtureFile)`.
  Steps: capture → on review tap Retake (returns to preview, file discarded);
  capture again → tap Use photo.
  Expected: Retake discards file and returns to same page; Use photo advances to
  next page/upload; page indicator ("Page X of N") updates.
  Traces: AC-2.

- **TC-AND-321-09 — End-to-end "tested upload" (DoD case)**
  Type: instrumented/e2e (Compose + MockWebServer). Target: EMU.
  Preconditions: MockWebServer returns 201s; fake controller supplies fixtures.
  Steps: drive the full flow (select type → capture required image(s) → confirm →
  upload).
  Expected: the `POST /ui/kyc/documents` request(s) are asserted (path, method,
  body `content_b64`/`document_type`, `X-CSRF-Token`) and the UI reaches `Success`.
  Traces: AC-7 (and AC-3, AC-4).

- **TC-AND-321-10 — Offline gate on upload**
  Type: instrumented. Target: EMU (toggle airplane mode / fake connectivity).
  Preconditions: AND-017 connectivity reports offline.
  Steps: capture image(s) offline → attempt upload → restore connectivity → retry.
  Expected: capture works offline; upload step shows an offline state with a retry
  affordance; on reconnect, retry uploads successfully without re-capture.
  Traces: AC-3, AC-5.

- **TC-AND-321-11 — Flaky dev-host: timeout then explicit retry (non-idempotent)**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: first response delayed beyond the ~20 s OkHttp timeout, then a 201.
  Steps: upload → timeout error → user taps retry.
  Expected: timeout surfaces a retry-able error; `POST /ui/kyc/documents` is NOT
  auto-retried (no GET-retry policy); explicit retry succeeds. (Documents the
  duplicate-on-double-submit risk from §16 claim 9.)
  Traces: AC-5.

- **TC-AND-321-12 — Security: no PII/bytes/URLs in logs, files stay internal, swept**
  Type: instrumented. Target: EMU.
  Preconditions: logcat capture; telemetry facade in test mode.
  Steps: run a full capture+upload, then cancel a second session.
  Expected: capture files exist only under app-internal `cacheDir/kyc-capture/`
  (none in MediaStore/external); no `content_b64`, image bytes, or signed URLs in
  logs/telemetry (only metadata events); files deleted on success and on cancel;
  orphan sweeper removes >24 h dirs.
  Traces: AC-6.

- **TC-AND-321-13 — Accessibility: TalkBack labels, touch targets, live region**
  Type: Compose-UI / instrumented (accessibility). Target: EMU.
  Preconditions: accessibility checks enabled.
  Steps: traverse capture and review screens with semantics assertions.
  Expected: shutter/flash/retake/use-photo/cancel have `contentDescription` and
  ≥48 dp targets; capture-guide overlay is `contentDescription=null`; "Page X of N"
  is a `liveRegion`; no accessibility violations.
  Traces: AC-2.

- **TC-AND-321-14 — Real-hardware camera capture + live upload (MUST be physical device)**
  Type: instrumented/e2e (manual-assisted). Target: **DEV** (Samsung A15, API 34,
  arm64-v8a) — required; the headless emulator has no real camera, and this also
  covers the arm64 vs x86 / API-34 vs API-35 difference.
  Preconditions: real CameraX bind on device; backend (or MockWebServer on host).
  Steps: bind preview, capture a real ID image with the shutter, confirm, upload.
  Expected: real `ImageCapture.takePicture` writes a valid JPEG to internal cache;
  EXIF/orientation correct; upload produces a 201 with `document_id`; no crash on the
  real bind path (the seam-faked CI cases cannot exercise this).
  Traces: AC-2, AC-3, AC-7.

### Coverage matrix (§14 AC → TC)

| AC   | Covered by |
|------|------------|
| AC-1 | (Document-type selection: TC-AND-321-09 drives the picker; see note) |
| AC-2 | TC-01, TC-02, TC-06, TC-07, TC-08, TC-13, TC-14 |
| AC-3 | TC-01, TC-02, TC-05, TC-09, TC-10, TC-14 |
| AC-4 | TC-01, TC-02, TC-03, TC-09 |
| AC-5 | TC-03, TC-04, TC-05, TC-07, TC-10, TC-11 |
| AC-6 | TC-06 (oversized never sent), TC-12 |
| AC-7 | TC-09, TC-14 |

Note on AC-1: the original "server-driven template list" is corrected (§16 claim 6)
to a fixed `id_front`/`id_back` selection; TC-09 exercises the selection step. If a
tier-gated picker via `document-templates/required/list` is adopted, add a dedicated
contract test for `GET /v1/kyc/document-templates/required/list?tier=`.
