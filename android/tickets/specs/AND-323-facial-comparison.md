---
id: AND-323
title: Facial comparison
milestone: M7
epic: E42
priority: P1
size: L
status: draft
depends_on: [AND-321]
blocks: []
---

# AND-323 — Facial comparison

## 1. Overview & Goal

Implement the `kycFacialComparison` flow in the TestLogon native Android app: capture a
live selfie with the front-facing camera, upload it as a `selfie` file against the user's
active KYC case, run the server-side face-comparison engine against the previously
submitted ID document, and present the result (`pass` / `review` / `fail`) including
anti-spoof outcome and remaining attempts.

The goal is a self-contained, idempotent-where-possible selfie capture and submission
journey that reuses the document capture/upload primitives delivered in AND-321
(`kycDocuments` presign + attach), adds front-camera selfie capture, and surfaces the
bounded (max 3) attempt model enforced by the backend. The acceptance bar is: a selfie
capture submits and returns a `FaceComparisonResultOut` rendered in the UI.

This ticket owns the `:feature-kyc` facial-comparison screen, ViewModel, and the
face-comparison repository methods. It does not own the KYC DTO layer (AND-319) or the
generic document capture stack (AND-321); it consumes both.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `:feature-kyc` (shared with AND-319/321/322), package
  `com.testlogon.android.feature.kyc.facial`.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable;
  ~20s timeouts, bounded backoff retry for idempotent GETs only). OpenAPI at `/openapi.json`.
- Web reference: `frontend/src/api/endpoints/*.ts`, types in `frontend/src/api/types.ts`.
- Relevant OpenAPI operations (all under cookie+CSRF session auth):
  - `POST /v1/fs/presign-upload` → `PresignUploadOut` (reused from AND-321).
  - `POST /v1/kyc/cases/{case_id}/files` → `KycCaseEnvelope` (attach with `file_type: "selfie"`).
  - `POST /v1/kyc/cases/{case_id}/compare-face` → `FaceComparisonResultOut`.
  - `GET  /v1/kyc/cases/{case_id}/face-comparisons` → `FaceComparisonListOut`.
- Upstream deps: **AND-321** (CameraX capture pipeline, presign + attach helpers,
  `KycFileRepository`), which in turn depends on **AND-319** (KYC DTOs) and **AND-129**
  (camera permission/scaffold). AND-322 (ID scanner) is a sibling that produces the
  `id_front`/`id_back` files the comparison runs against.

## 3. Functional Requirements

FR-1 The user can open the facial-comparison screen from the KYC case detail when the case
has at least one ID file attached and face comparison is required/available.

FR-2 The screen requests `CAMERA` runtime permission (reusing the AND-129 permission
gate). If denied, show a rationale + settings deep link; capture controls are disabled.

FR-3 The screen shows a live front-camera (`LENS_FACING_FRONT`) preview with an oval face
guide overlay and a capture button. A still selfie image is captured on tap.

FR-4 After capture, the user sees a review state (captured frame, Retake / Submit). No
network call is made until Submit.

FR-5 On Submit, the app: (a) requests a presigned upload URL, (b) PUTs the JPEG bytes to
the presigned URL, (c) attaches the file to the case as `file_type = "selfie"`, (d) invokes
the compare-face endpoint, and (e) renders the result.

FR-6 The result view shows: `result` (Pass/Review/Fail), `confidence_score` (0–100),
anti-spoof pass/fail with `passed_checks/total_checks`, `attempt_number`, and
`remaining_attempts`.

FR-7 When `result == "fail"` and `remaining_attempts > 0`, a "Try again" action returns to
capture. When `remaining_attempts == 0`, retry is disabled and the user is told to contact
support / await manual review.

FR-8 When `result == "pass"`, show success and a "Done" action returning to case detail.
`result == "review"` shows a neutral pending-review message; the case proceeds.

FR-9 Prior attempts are viewable: a collapsed history list backed by
`GET .../face-comparisons` showing each attempt's result, score, and timestamp.

FR-10 The captured selfie image is never persisted to durable storage; it is held in
memory / a `cacheDir` temp file deleted after submission completes or on screen exit.

## 4. Technical Design

Module: `:feature-kyc`, package `com.testlogon.android.feature.kyc.facial`.

Screen + nav (single-Activity Navigation-Compose). Route registered by the KYC nav graph:

```kotlin
const val ROUTE_KYC_FACE = "kyc/{caseId}/face-comparison"
fun NavController.navigateToFaceComparison(caseId: String) =
    navigate("kyc/$caseId/face-comparison")

fun NavGraphBuilder.faceComparisonScreen(onDone: () -> Unit) {
    composable(
        route = ROUTE_KYC_FACE,
        arguments = listOf(navArgument("caseId") { type = NavType.StringType }),
    ) { FaceComparisonRoute(onDone = onDone) }
}
```

ViewModel (Hilt, KSP) exposing `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class FaceComparisonViewModel @Inject constructor(
    private val repo: FaceComparisonRepository,
    private val kycFiles: KycFileRepository,      // from AND-321 (presign + attach)
    savedState: SavedStateHandle,
) : ViewModel() {
    private val caseId: String = checkNotNull(savedState["caseId"])

    private val _state = MutableStateFlow(FaceComparisonUiState(caseId = caseId))
    val state: StateFlow<FaceComparisonUiState> = _state.asStateFlow()

    fun onSelfieCaptured(jpeg: CapturedImage) { /* -> Review */ }
    fun onRetake() { /* discard frame -> Capture */ }
    fun submit() { /* presign -> PUT -> attach -> compare; updates _state */ }
    fun loadHistory() { /* GET face-comparisons */ }
}
```

UI state:

```kotlin
data class FaceComparisonUiState(
    val caseId: String,
    val phase: Phase = Phase.Capture,                 // Capture, Review, Submitting, Result
    val capturedUri: Uri? = null,
    val submitting: Boolean = false,
    val result: FaceComparison? = null,               // core-model domain type
    val history: List<FaceComparison> = emptyList(),
    val error: KycError? = null,
) {
    enum class Phase { Capture, Review, Submitting, Result }
    val canRetry: Boolean get() = result?.let { it.result == FaceResult.FAIL && it.remainingAttempts > 0 } ?: true
}
```

Capture stack: reuse the AND-321 CameraX wrapper, parameterized to
`CameraSelector.DEFAULT_FRONT_CAMERA` and `ImageCapture` configured
`CAPTURE_MODE_MINIMIZE_LATENCY`. The captured `ImageProxy` is encoded to a JPEG in
`context.cacheDir/kyc-selfie-<uuid>.jpg`. Compose preview via `AndroidView { PreviewView(...) }`
with an oval guide drawn in an overlay `Canvas`.

Submission orchestration (in repository / ViewModel), strictly sequential because each
step depends on the previous and all are POSTs (non-idempotent — no auto-retry):

1. `presignUpload(path = "/kyc/<caseId>/selfie-<uuid>.jpg", contentType = "image/jpeg")`.
2. `PUT upload_url` with the JPEG bytes (OkHttp, `image/jpeg` body).
3. `attachFile(caseId, path = presign.path, fileType = "selfie", expectedVersion = <case.version>)`.
4. `compareFace(caseId)`.

`expected_version` is the case optimistic-concurrency token obtained from the case
envelope returned by step 3's predecessor (the KYC case detail loaded via AND-319/321);
a `409`/version conflict re-fetches the case and prompts the user to retry submit.

## 5. API Contract

All calls carry the persistent cookie jar; mutating calls echo the `ui_csrf` cookie as
`X-CSRF-Token`. On `401`, the OkHttp authenticator calls `POST /ui/session/refresh` once,
then retries (shared client behavior, not owned here).

Retrofit service (`:feature-kyc`):

```kotlin
interface FaceComparisonApi {
    @POST("v1/kyc/cases/{caseId}/compare-face")
    suspend fun compareFace(@Path("caseId") caseId: String): FaceComparisonResultDto

    @GET("v1/kyc/cases/{caseId}/face-comparisons")
    suspend fun listComparisons(@Path("caseId") caseId: String): FaceComparisonListDto
}
```

Presign + attach reuse AND-321 services:

```kotlin
@POST("v1/fs/presign-upload")
suspend fun presign(@Body body: PresignUploadInDto): PresignUploadOutDto

@POST("v1/kyc/cases/{caseId}/files")
suspend fun attachFile(@Path("caseId") caseId: String, @Body body: KycFileAttachmentDto): KycCaseEnvelopeDto
```

Request/response shapes (Moshi DTOs mirror these):

`POST /v1/fs/presign-upload`
```json
// request
{ "path": "/kyc/<case_id>/selfie-<uuid>.jpg", "content_type": "image/jpeg" }
// 200
{ "upload_url": "https://...", "bucket": "...", "key": "...",
  "ticket_id": "...", "path": "/kyc/.../selfie-...jpg", "content_type": "image/jpeg" }
```

`PUT {upload_url}` — raw JPEG bytes, header `Content-Type: image/jpeg`. Bare OkHttp call
(presigned URL is not under the API base; do not attach cookies/CSRF). Expect 200/204.

`POST /v1/kyc/cases/{case_id}/files`
```json
// request
{ "expected_version": 7, "path": "/kyc/<case_id>/selfie-<uuid>.jpg", "file_type": "selfie" }
// 200 -> { "case": { ... KycCaseOut ... } }
```
`file_type` enum: `selfie | id_front | id_back | proof_of_address`. This ticket uses `selfie`.

`POST /v1/kyc/cases/{case_id}/compare-face` — empty body.
```json
// 200 FaceComparisonResultOut
{
  "comparison_id": "cmp_...",
  "confidence_score": 92,                 // 0..100
  "result": "pass",                       // pass | review | fail
  "anti_spoof": {
    "passed": true,
    "checks": [ { /* AntiSpoofCheckOut */ } ],
    "total_checks": 4, "passed_checks": 4
  },
  "attempt_number": 1,                     // 1..3
  "max_attempts": 3,
  "remaining_attempts": 2,                 // 0..3
  "created_at": 1733356800,                // epoch seconds (int)
  "admin_override": null                   // FaceComparisonAdminOverrideOut | null
}
```

`GET /v1/kyc/cases/{case_id}/face-comparisons`
```json
// 200 FaceComparisonListOut
{ "comparisons": [ { /* FaceComparisonResultOut */ } ] }
```

Errors: FastAPI `422` → `HTTPValidationError`; `detail` mapped via the shared mapper
(`string | [{msg}] | {code,...}`).

## 6. Data & State Management

Domain model (`:core-model`):

```kotlin
enum class FaceResult { PASS, REVIEW, FAIL }

data class FaceComparison(
    val comparisonId: String,
    val confidenceScore: Int,            // 0..100
    val result: FaceResult,
    val antiSpoofPassed: Boolean,
    val antiSpoofPassedChecks: Int,
    val antiSpoofTotalChecks: Int,
    val attemptNumber: Int,              // 1..3
    val maxAttempts: Int,                // default 3
    val remainingAttempts: Int,          // 0..3
    val createdAt: Instant,              // from created_at epoch seconds
    val overridden: Boolean,
)
```

`FaceComparisonResultDto.toDomain()` lives in `:feature-kyc`; DTOs in
`com.testlogon.android.feature.kyc.data`.

Repository:

```kotlin
interface FaceComparisonRepository {
    suspend fun runComparison(caseId: String): ApiResult<FaceComparison>
    suspend fun history(caseId: String): ApiResult<List<FaceComparison>>
}
```

`runComparison` performs presign → PUT → attach → compare and returns the typed
`ApiResult<FaceComparison>`. `history` is the only safe-to-retry (idempotent GET) call and
may use the shared bounded-backoff GET policy.

Persistence: **no Room caching** of selfies or comparison results — these are PII / sensitive
and the result list is small and always re-fetched on screen open. DataStore stores only a
non-sensitive flag `kyc_face_last_result_<caseId>` (enum) used by case-detail to render a
status chip without holding the image. The captured JPEG temp file in `cacheDir` is deleted
in a `try/finally` around submission and in `onCleared()`.

## 7. Error Handling & Resilience

- **Timeouts:** ~20s per call (shared OkHttp config). The full submit sequence shows a
  single "Submitting…" spinner with the active step labeled (Uploading / Comparing).
- **POST non-idempotency:** none of presign/PUT/attach/compare are auto-retried. On failure
  the UI returns to the Review phase keeping the captured frame so the user can re-Submit
  manually; the temp JPEG is retained until success or explicit retake.
- **Partial failure:** if PUT or attach succeeds but compare fails, re-Submit re-runs the
  full sequence (a fresh presign+upload), which is acceptable — the backend keys attempts on
  the compare call. Attach version conflicts (`409`) trigger a case re-fetch then prompt.
- **Attempts exhausted:** when `remaining_attempts == 0` the retry CTA is hidden regardless
  of `result`; show the manual-review message.
- **Offline / unreliable host:** detect `IOException`/no-connectivity and show an offline
  banner with a Retry that re-attempts only when connectivity returns; capture remains usable
  offline (no network needed to capture/review).
- **Anti-spoof fail:** a `fail` driven by `anti_spoof.passed == false` shows specific guidance
  ("Use a live photo, ensure good lighting") distinct from a low-confidence mismatch.
- **422:** mapped via shared `detail` mapper to a user-facing `KycError` message.

## 8. Security & Privacy

- The selfie is biometric-adjacent PII. It is captured to `cacheDir` only, uploaded over the
  presigned URL, and the local temp file is deleted immediately after submission (success or
  failure) and on `onCleared()`. No copy is written to MediaStore, gallery, or app
  `filesDir`.
- `android:allowBackup` excludes `cacheDir` by default; verify no FileProvider path exposes
  the temp dir externally.
- Session is cookie-based; the persistent cookie jar plus `X-CSRF-Token` header are applied
  to all `*.testlogon` API calls. The presigned `PUT` goes to S3-style storage and MUST NOT
  carry session cookies or CSRF headers (use a cookie-jar-free OkHttp call / `@Url` against
  the bare client).
- Screenshots: set `FLAG_SECURE` on the facial-comparison screen while the preview/captured
  selfie is on-screen to prevent capture in screenshots and recents.
- Do not log image bytes, presigned URLs, or `comparison_id` at INFO+; redact in telemetry.

## 9. Accessibility & i18n

- Camera preview is decorative; the capture button has `contentDescription` "Capture selfie".
  The oval guide has an off-screen live-region hint ("Center your face in the oval").
- Result screen uses text + iconography (not color alone) to convey pass/review/fail; the
  result, score, and remaining attempts are exposed via `semantics` for TalkBack and announced
  as a live region when the result resolves.
- Minimum 48dp touch targets for Capture/Retake/Submit/Retry.
- All strings in `:feature-kyc` `strings.xml` (no hardcoded literals); pluralized
  remaining-attempts string via `plurals`. RTL-safe layouts. Respect large font scales.
- Confidence score formatted via locale-aware number formatting.

## 10. Telemetry & Logging

Events emitted through the shared analytics interface (`:core-data`), no PII:

- `kyc_face_capture_started { case_id_hash }`
- `kyc_face_selfie_captured { }`
- `kyc_face_submit_started { }`
- `kyc_face_submit_result { result, confidence_bucket, anti_spoof_passed, attempt_number, remaining_attempts }`
  (confidence reported as a coarse bucket, e.g. <60/60-79/80-100, not raw score).
- `kyc_face_submit_error { step: presign|upload|attach|compare, error_code }`
- `kyc_face_attempts_exhausted { }`

Logging: structured `Timber`/`KycLogger` at DEBUG for step transitions; never log image
bytes, presigned URLs, raw scores, or cookies. Network logging uses the redacting OkHttp
interceptor (Authorization/Cookie/X-CSRF-Token stripped).

## 11. Testing Strategy

Unit (`:core-testing`, JUnit + Turbine + MockWebServer):
- DTO → domain mapping: `created_at` epoch→`Instant`; enum parsing of `result`; null
  `admin_override` → `overridden = false`; bounds (`confidence_score`, `remaining_attempts`).
- `FaceComparisonViewModel.submit()` happy path: presign→PUT→attach→compare emits
  `Submitting` then `Result` with the mapped `FaceComparison`.
- Failure at each step returns to `Review` and surfaces a `KycError`; temp file deletion
  asserted via a fake file source.
- `canRetry` logic: fail+remaining>0 ⇒ true; fail+remaining==0 ⇒ false; pass ⇒ no retry CTA.
- `history()` uses GET and tolerates empty list.

Integration (MockWebServer with canned `FaceComparisonResultOut` for pass/review/fail and a
422): verifies request path, `X-CSRF-Token` header presence on POSTs, absence of cookies on
the presigned PUT, and `file_type: "selfie"` in the attach body.

UI/Compose (`createAndroidComposeRule`): capture→review→submit→result phases render;
Retake returns to Capture; Retry hidden when attempts exhausted; permission-denied state.
CameraX is faked behind the AND-321 capture interface (no real camera in instrumentation).

Acceptance test (gates the ticket): a fake-captured selfie submits through the full chain
and a `FaceComparisonResultOut` is parsed and rendered.

## 12. Dependencies & Sequencing

- **Blocks on AND-321** (`document-capture-upload`): provides the CameraX capture wrapper,
  `KycFileRepository` (presign + attach), and presign DTOs. This ticket extends capture to
  the front camera and adds the selfie `file_type` + compare-face calls.
- Transitively requires **AND-319** (KYC DTOs / `KycCaseOut`, case version) and **AND-129**
  (camera permission scaffold), satisfied via AND-321.
- Sibling **AND-322** (ID scanner) produces the `id_front`/`id_back` images that face
  comparison runs against; not a hard build dependency but required for an end-to-end pass in
  manual QA.
- Shared session/CSRF/refresh OkHttp stack and `ApiResult`/`detail` mapper are pre-existing
  (`:core-network`). No new third-party libraries beyond the existing CameraX dependency
  introduced in AND-321.

## 13. Risks & Open Questions

- **R1 — compare-face request body:** OpenAPI documents no request body for
  `POST /v1/kyc/cases/{case_id}/compare-face`; the server appears to resolve the latest
  `selfie` + ID files attached to the case. Confirm with backend/web reference
  (`frontend/src/api/endpoints/`) that no `selfie_path`/`file_id` body is expected. Design
  assumes empty body; adjust DTO if the contract differs.
- **R2 — attach `expected_version`:** the exact source of the optimistic-concurrency
  version must be confirmed (KYC case envelope `version` field). Mishandling yields `409`.
- **R3 — anti-spoof on-device vs server:** assumed entirely server-side (the API returns
  `anti_spoof`). If on-device liveness is later required it is a separate ticket; note the
  unrelated `/ui/kyc/liveness-call/*` endpoints are a human video-call feature, NOT this flow.
- **R4 — presigned PUT verb/headers:** confirm storage expects `PUT` with `image/jpeg` and no
  extra signed headers; some presign schemes require exact `Content-Type` match to the
  presign request.
- **R5 — image size/format constraints:** unknown max dimensions/bytes; default to ~1080px
  long edge JPEG q85 and confirm against `files/validation` requirements.

## 14. Acceptance Criteria

AC-1 From a KYC case with an attached ID, the user can open the facial-comparison screen and
see a live front-camera preview with a face guide (camera permission honored).

AC-2 Capturing a selfie shows a Review state with Retake and Submit; no network call occurs
before Submit.

AC-3 Submit performs presign → PUT(JPEG) → attach(`file_type:"selfie"`) → compare-face and,
on success, renders a `FaceComparisonResultOut` showing result, confidence, anti-spoof, and
remaining attempts. **(Primary acceptance: "Selfie compare submits + returns result.")**

AC-4 `result == fail` with `remaining_attempts > 0` offers Try again returning to capture;
`remaining_attempts == 0` hides retry and shows the manual-review message.

AC-5 `result == pass` shows success + Done; `result == review` shows the pending-review state.

AC-6 Prior attempts load via `GET .../face-comparisons` and display result, score, timestamp.

AC-7 The captured selfie temp file is deleted after submission and on screen exit; no selfie
is written to gallery/`filesDir`. `FLAG_SECURE` is set while a selfie is on-screen.

AC-8 POST calls carry `X-CSRF-Token`; the presigned PUT carries no session cookies/CSRF; a
`401` triggers exactly one `session/refresh` + retry (shared behavior).

AC-9 422 and network/offline failures return to Review with a clear, localized message and a
manual Retry; no auto-retry of POSTs.

## 15. Definition of Done

- `:feature-kyc` facial-comparison screen, `FaceComparisonViewModel`,
  `FaceComparisonRepository`/`FaceComparisonApi`, and DTO↔domain mappers implemented under
  `com.testlogon.android.feature.kyc.facial` / `.data`.
- Nav route wired into the KYC graph and reachable from case detail.
- All AC-1…AC-9 met and demonstrated; the primary acceptance (selfie compare submits +
  returns result) verified against the dev backend or MockWebServer fixtures.
- Unit, integration (MockWebServer), and Compose UI tests added and green in CI; coverage
  includes mapping, the four-step submit chain, error/attempt-exhaustion paths, and temp-file
  cleanup.
- No hardcoded strings; a11y semantics and `plurals` in place; `FLAG_SECURE` applied.
- Telemetry events emitted with no PII; redacting network logging confirmed.
- Lint/detekt/ktlint clean; KSP/Hilt graph compiles; no new permissions beyond `CAMERA`.
- Open questions R1–R5 resolved or explicitly tracked with backend before merge; PR reviewed
  and merged to `android-port`.
