---
id: AND-323
title: Facial comparison
milestone: M7
epic: E42
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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

All calls carry the persistent cookie jar; calls echo the `ui_csrf` cookie as
`X-CSRF-Token` whenever the cookie is present. (Verified against the web reference
`src/api/client.ts`: the header is set on *every* request when `ui_csrf` exists, not only
on mutating verbs — earlier drafts said "mutating calls only"; corrected.) The web client
additionally sends `Authorization: Bearer <accessToken>` from its auth store and an optional
`X-IMPERSONATION-TOKEN`; the Android shared `:core-network` stack is assumed cookie-jar +
CSRF only (Bearer/impersonation are web-session concepts — flagged as an open assumption in
§16). On `401`, the OkHttp authenticator calls `POST /ui/session/refresh` once, then retries
(shared client behavior, not owned here — matches `client.ts` `refreshSession()` exactly).

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
// 200 -> KycCaseEnvelope: { "case": { ... KycCaseOut ... } }
```
Response is `KycCaseEnvelope` (wraps `case: KycCaseOut`). The optimistic-concurrency token
is `case.version` (integer, required); the case id field on `KycCaseOut` is `kyc_case_id`
(not `case_id` — `case_id` is only the path/query param name). `expected_version` is
required and `minimum: 1` per `KycFileAttachmentRequest`. (Verified: §16 #6/#9.)
`file_type` enum: `selfie | id_front | id_back | proof_of_address` (exact, verified). This ticket uses `selfie`.

`POST /v1/kyc/cases/{case_id}/compare-face` — empty body.
```json
// 200 FaceComparisonResultOut
{
  "comparison_id": "cmp_...",
  "confidence_score": 92,                 // 0..100
  "result": "pass",                       // pass | review | fail
  "anti_spoof": {                          // AntiSpoofResultOut (not inline)
    "passed": true,
    "checks": [ { "check": "not_screenshot", "passed": true, "detail": "..." } ], // AntiSpoofCheckOut[]: {check,passed,detail}
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

- **R1 — compare-face request body: RESOLVED.** OpenAPI shows `req=` (no request body) for
  `POST /v1/kyc/cases/{case_id}/compare-face`, and the web reference confirms it: `src/api/
  endpoints/kycFacialComparison.ts` calls `api.post(.../compare-face, {})` with an empty body
  object and no `selfie_path`/`file_id`. The server resolves the latest `selfie` + ID files
  attached to the case. Android Retrofit signature takes no `@Body` — correct. (§16 #4.)
- **R2 — attach `expected_version`: RESOLVED.** Confirmed the source is `KycCaseOut.version`
  (integer, required) returned inside `KycCaseEnvelope.case` (verified in `openapi.pretty.json`
  `KycCaseOut`/`KycCaseEnvelope`). `KycFileAttachmentRequest.expected_version` is required,
  `minimum: 1`. Mishandling yields `409`. (§16 #6/#9.) Note: the comparison history endpoint
  comment in the web client states results are returned newest-first (`comparisons[0]` is the
  latest), though the OpenAPI schema does not formally guarantee ordering — treat order as a
  soft contract and sort defensively by `created_at` desc on the Android side.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **`POST /v1/fs/presign-upload` returns `PresignUploadOut`; request is `PresignUploadIn`.**
   VERIFIED. OpenAPI `POST /v1/fs/presign-upload` (op=`presign_fs_upload_v1_fs_presign_upload_post`, req=`PresignUploadIn`, resp=`200:PresignUploadOut`). Schemas: `PresignUploadIn` requires `path` (string), optional nullable `content_type`; `PresignUploadOut` requires `upload_url, bucket, key, ticket_id, path, content_type` — exactly the fields the spec's §5 JSON lists. Web usage pattern confirmed in `src/hooks/useCallRecording.ts: apiPresignUpload` (presign → bare `fetch PUT` → complete).

2. **Presigned `PUT` uses `Content-Type: image/jpeg`, raw bytes, and carries NO session cookies/CSRF.**
   VERIFIED. `src/hooks/useCallRecording.ts` (lines ~286-290): `fetch(presignData.upload_url, { method: "PUT", body: blob, headers: { "Content-Type": mimeType } })` — a bare `fetch` with NO `credentials: "include"`, so no cookies/CSRF, and an exact-match `Content-Type`. Mirrors spec §5/§8 and answers R4.

3. **`POST /v1/kyc/cases/{case_id}/files` attaches a file; request `KycFileAttachmentRequest`, response `KycCaseEnvelope`; `file_type` enum = `selfie|id_front|id_back|proof_of_address`; `expected_version` required (min 1).**
   VERIFIED. OpenAPI `POST /v1/kyc/cases/{case_id}/files` (op=`attach_kyc_file...`, req=`KycFileAttachmentRequest`, resp=`200:KycCaseEnvelope`). Schema `KycFileAttachmentRequest`: required `expected_version` (int, minimum 1), `path` (1..1024), `file_type` (the exact 4-value enum). (Spec's Retrofit/DTO names `KycFileAttachmentDto`/`...InDto` are local Moshi mirrors of these — naming only.)

4. **`POST /v1/kyc/cases/{case_id}/compare-face` takes an EMPTY body and returns `FaceComparisonResultOut`.**
   VERIFIED (resolves R1). OpenAPI op=`run_face_comparison...`, `req=` (no body), `resp=200:FaceComparisonResultOut`. Frontend: `src/api/endpoints/kycFacialComparison.ts: compareFace` → `api.post(.../compare-face, {})` (empty object, no `selfie_path`/`file_id`).

5. **`FaceComparisonResultOut` fields: `comparison_id`, `confidence_score` (0..100 int), `result` (pass|review|fail), `anti_spoof`, `attempt_number` (1..3), `max_attempts` (default 3), `remaining_attempts` (0..3), `created_at` (epoch-seconds int), `admin_override` (nullable).**
   VERIFIED. Schema `FaceComparisonResultOut` in `openapi.pretty.json`: `confidence_score` int min 0 max 100; `attempt_number` int min 1 max 3; `remaining_attempts` int min 0 max 3; `max_attempts` int default 3; `created_at` int (epoch seconds — spec maps to `Instant`); `result` enum [pass,review,fail]; `admin_override` anyOf `FaceComparisonAdminOverrideOut`|null. Frontend mirror: `src/api/types.ts: FaceComparisonResult` (lines ~11566-11576). The spec §6 domain `overridden: Boolean` is derived from `admin_override != null` — a local convenience, not a wire field.

6. **`anti_spoof` is `AntiSpoofResultOut` with `passed` (bool), `checks[]` (`AntiSpoofCheckOut` = {check,passed,detail}), `total_checks`, `passed_checks`.**
   CORRECTED. The spec §5 originally implied an inline object containing `AntiSpoofCheckOut`; the actual wrapper schema is `AntiSpoofResultOut` (`openapi.pretty.json` line ~5298) and each check is `AntiSpoofCheckOut` with required `check, passed, detail` (line ~5273; `check` ∈ {file_size, image_format, not_screenshot, ...}). Fixed inline in §5. Frontend: `src/api/types.ts: AntiSpoofResult`/`AntiSpoofCheck` (lines ~11546-11557). The spec's §6 domain `antiSpoofPassed/PassedChecks/TotalChecks` flattening is a valid mapping.

7. **`GET /v1/kyc/cases/{case_id}/face-comparisons` returns `FaceComparisonListOut { comparisons: FaceComparisonResultOut[] }`.**
   VERIFIED. OpenAPI op=`list_face_comparisons...`, `resp=200:FaceComparisonListOut`. Schema `FaceComparisonListOut` requires `comparisons` (array of `FaceComparisonResultOut`). Frontend: `src/api/endpoints/kycFacialComparison.ts: listFaceComparisons`; its doc comment says "newest first" (soft ordering contract — see Open assumptions). Frontend `FaceComparisonResult.tsx` reads `list.comparisons[0]` as the latest.

8. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token`.**
   CORRECTED (scope). VERIFIED that the mechanism exists, but the spec said "mutating calls only". `src/api/client.ts` (lines ~167-171) sets `X-CSRF-Token` on EVERY request whenever the `ui_csrf` cookie is present, regardless of HTTP verb. Spec §5 corrected.

9. **`expected_version` source is the KYC case `version` field; conflict → 409.**
   VERIFIED (resolves R2). `KycCaseOut.version` (int, required) nested under `KycCaseEnvelope.case` (`openapi.pretty.json` lines ~41484/41612). The case identifier on the body is `kyc_case_id` (the `case_id` token is only the URL path param). 409 conflict semantics are inferred from optimistic-concurrency design (not an explicitly documented response code in the index — see Open assumptions).

10. **401 → `POST /ui/session/refresh` once, then retry; shared transport.**
    VERIFIED. `src/api/client.ts: refreshSession()` POSTs `/ui/session/refresh` with `credentials: include`; the 401 handler (lines ~194-237) refreshes at most once (single shared `refreshPromise`) then retries the original request, logging out on a second 401. Matches spec §5/AC-8.

11. **Error handling: `422 → HTTPValidationError`; `detail` may be `string | [{msg}] | {code,...}`; offline → network error.**
    VERIFIED. Every KYC/fs op in the index lists `422:HTTPValidationError`. `src/api/client.ts: normalizeErrorDetail` handles all three `detail` shapes (string; array of `{msg}`; object with `code`/`msg`), and a thrown `fetch` becomes `ApiError(0, "Network error")` — matching spec §7's offline/`IOException` path.

12. **CameraX front-camera selfie capture (`DEFAULT_FRONT_CAMERA`, `CAPTURE_MODE_MINIMIZE_LATENCY`).**
    UNVERIFIED-ASSUMPTION (framework ref). Not derivable from backend/frontend sources (web uses a browser `getUserMedia`/file input, not CameraX). Android API names are correct per CameraX docs: `CameraSelector.DEFAULT_FRONT_CAMERA` and `ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY` (framework ref: developer.android.com/training/camerax + reference for `androidx.camera.core.CameraSelector` / `ImageCapture`). Concrete wrapper API depends on AND-321's implementation.

13. **Hilt+KSP ViewModel, Navigation-Compose route, `SavedStateHandle` arg, `StateFlow` UI state.**
    UNVERIFIED-ASSUMPTION (framework ref). Android architecture choices; APIs are valid (framework ref: developer.android.com/jetpack/compose/navigation, .../topic/libraries/architecture/viewmodel/viewmodel-savedstate, dagger.dev/hilt). Concrete module/package conventions depend on AND-319/321.

13b. **`FLAG_SECURE` blocks screenshots/recents while the selfie is on screen.**
    VERIFIED (framework ref). `WindowManager.LayoutParams.FLAG_SECURE` (developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE) prevents screenshots and excludes the window from non-secure displays/recents. Sound for §8/AC-7.

### Corrections made
- **§5 CSRF scope (claim #8):** changed "mutating calls echo `ui_csrf`" → "every request echoes `ui_csrf` when present", per `src/api/client.ts`.
- **§5 anti-spoof schema (claim #6):** the result wrapper is `AntiSpoofResultOut` (not an inline object); each check is `AntiSpoofCheckOut {check,passed,detail}`. Inline JSON example corrected.
- **§5 attach response (claims #3/#9):** annotated response as `KycCaseEnvelope`, identified `case.version` as the concurrency token and `kyc_case_id` as the case-id field; noted `expected_version` is required (min 1).
- **§5 auth model:** added that the web client also sends `Authorization: Bearer` + optional `X-IMPERSONATION-TOKEN`; flagged the Android cookie-only assumption.
- **§13 R1/R2:** marked RESOLVED with exact citations; added the history newest-first soft-ordering note.

### Open assumptions
- **A1 — Android shared-network auth model.** The web client sends BOTH session cookies and an `Authorization: Bearer <accessToken>` (plus optional `X-IMPERSONATION-TOKEN`). The spec assumes the Android `:core-network` stack is cookie-jar + CSRF only. Unverifiable from these sources (no Android stack in the reference); must be confirmed against the actual `:core-network` implementation / AND-321.
- **A2 — 409 on version conflict.** Optimistic-concurrency 409 is a design inference; the OpenAPI index only enumerates `200`/`422` for the attach op. Confirm the backend actually returns 409 (vs 422/409) for a stale `expected_version`.
- **A3 — history ordering.** "Newest first" is stated only in a web-client doc comment, not the OpenAPI schema. Sort defensively by `created_at` desc on Android.
- **A4 — presigned PUT success status & extra signed headers (R4 residual).** Web code does not assert the PUT response status or send extra signed headers; spec assumes 200/204 and no extra headers. Storage-backend-specific; confirm against the dev backend.
- **A5 — image size/format constraints (R5).** No max-dimension/byte limits found in sources; `GET .../files/validation` (`KycFileValidationEnvelope`) exists and may carry constraints — query it to confirm rather than hardcoding 1080px/q85.
- **A6 — CameraX capture wrapper API (claim #12).** Concrete capture interface is owned by AND-321; only the standard CameraX symbol names are verified.
- **A7 — anti-spoof is fully server-side (R3).** Assumed; the API returns `anti_spoof` and no on-device liveness contract exists in sources. The `/ui/kyc/liveness-call/*` endpoints are a separate human video-call feature.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **MWS** = MockWebServer contract; **emu(test35)** = headless AVD API 35 x86_64; **device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Camera-dependent cases MUST run on **device(A15)** for real front-camera/selfie behavior; faked-camera UI cases run on **emu(test35)**.

- **TC-AND-323-01 — DTO→domain mapping (happy).** Type: unit (JVM). Target: `FaceComparisonResultDto.toDomain()`. Preconditions: canned `FaceComparisonResultOut` JSON (result=pass, confidence_score=92, attempt_number=1, max_attempts=3, remaining_attempts=2, created_at=1733356800, anti_spoof.passed=true 4/4, admin_override=null). Steps: deserialize (Moshi) → map. Expected: `FaceComparison(result=PASS, confidenceScore=92, antiSpoofPassed=true, antiSpoofPassedChecks=4, antiSpoofTotalChecks=4, attemptNumber=1, maxAttempts=3, remainingAttempts=2, createdAt=Instant.ofEpochSecond(1733356800), overridden=false)`. Traces: AC-3, AC-6.

- **TC-AND-323-02 — DTO edge mapping.** Type: unit (JVM). Target: `toDomain()`. Preconditions: variants — (a) `result=review`; (b) `result=fail` with `remaining_attempts=0`; (c) non-null `admin_override` ⇒ `overridden=true`; (d) boundary values confidence_score=0/100, attempt_number=3. Steps: map each. Expected: enum parses correctly; `overridden` reflects null-ness; no exceptions at bounds. Traces: AC-4, AC-5.

- **TC-AND-323-03 — Full submit chain happy path (contract).** Type: contract/MockWebServer (JVM/MWS). Target: `FaceComparisonRepository.runComparison()` + `FaceComparisonViewModel.submit()`. Preconditions: MWS enqueues, in order: presign 200 (`PresignUploadOut`), PUT 200 (presigned), attach 200 (`KycCaseEnvelope`), compare 200 (`FaceComparisonResultOut` pass). A fake captured JPEG temp file. Steps: invoke submit; collect state via Turbine. Expected: requests issued in order POST `/v1/fs/presign-upload` → PUT `{upload_url}` → POST `/v1/kyc/cases/{caseId}/files` → POST `/v1/kyc/cases/{caseId}/compare-face`; attach body `{expected_version, path, file_type:"selfie"}`; UI state `Submitting`→`Result(PASS)`. Traces: AC-2, AC-3.

- **TC-AND-323-04 — CSRF/cookie + presigned-PUT isolation (security/contract).** Type: contract/MockWebServer (JVM/MWS). Target: OkHttp transport for the 4 calls. Preconditions: `ui_csrf` cookie set in the jar; MWS for API base + a separate MWS (or recorded dispatcher) for the presigned URL. Steps: run submit; inspect recorded requests. Expected: every API-base request (presign/attach/compare) carries `X-CSRF-Token` equal to `ui_csrf` and the session cookie; the presigned PUT carries `Content-Type: image/jpeg`, the raw JPEG bytes, and NO `Cookie`/`X-CSRF-Token` header. Traces: AC-8.

- **TC-AND-323-05 — 401 single refresh + retry.** Type: contract/MockWebServer (JVM/MWS). Target: shared authenticator + compare call. Preconditions: MWS returns 401 once for compare, then 200 on retry; a `POST /ui/session/refresh` 200 enqueued. Steps: run submit. Expected: exactly one `/ui/session/refresh` POST occurs, the compare is retried once and succeeds; a second consecutive 401 would surface auth failure (assert no infinite loop). Traces: AC-8.

- **TC-AND-323-06 — 422 validation error → Review with localized message.** Type: contract/MockWebServer (JVM/MWS). Target: `submit()` error path + `detail` mapper. Preconditions: MWS returns 422 `HTTPValidationError` on attach (detail as `[{msg:"path: field required"}]`); also a variant with `detail` as a `{code,...}` object. Steps: run submit. Expected: state returns to `Review` (captured frame retained), `KycError` carries the mapped message; NO auto-retry of the POST; temp file retained for manual re-submit. Traces: AC-9.

- **TC-AND-323-07 — 409 version conflict re-fetch + prompt.** Type: contract/MockWebServer (JVM/MWS). Target: attach conflict handling. Preconditions: MWS returns 409 on attach. Steps: run submit. Expected: app re-fetches the case (new `version`) and prompts the user to retry Submit; no auto-PUT loop. (If backend actually returns 422 not 409 — see Open assumption A2 — this case documents the expected mapping; adjust dispatcher once confirmed.) Traces: AC-9.

- **TC-AND-323-08 — Offline / flaky dev-host path.** Type: integration (emu(test35), airplane mode toggled) + MWS unit variant. Target: connectivity handling in `submit()`/repository. Preconditions: network disabled (or MWS socket policy DISCONNECT_AT_START to simulate `IOException`). Steps: capture selfie offline (must still work), tap Submit. Expected: capture/review usable with no network; Submit shows an offline banner with a manual Retry; no POST auto-retry; on reconnect, Retry re-runs the full chain. Traces: AC-9. (Capture-offline portion is hardware-independent; the airplane-mode integration variant is most realistic on device(A15) but acceptable on emu(test35).)

- **TC-AND-323-09 — Partial-failure re-submit (resilience).** Type: contract/MockWebServer (JVM/MWS). Target: `runComparison()` retry semantics. Preconditions: first run — presign 200, PUT 200, attach 200, compare 500; second run — full fresh chain 200 (pass). Steps: submit, fail at compare, return to Review, Submit again. Expected: second Submit issues a fresh presign+PUT+attach+compare (a new attempt is keyed on the compare call); final state Result(PASS). Traces: AC-3, AC-9.

- **TC-AND-323-10 — Capture → Review → Result UI phases (Compose-UI).** Type: Compose-UI (emu(test35), CameraX faked behind AND-321 interface). Target: `FaceComparisonRoute`/screen. Preconditions: fake capture interface returns a canned frame; MWS canned pass result. Steps: tap Capture → assert Review (Retake/Submit, no network yet) → tap Submit → assert Result shows result label, confidence, anti-spoof `passed_checks/total_checks`, attempt N of max, remaining attempts. Steps cont.: tap Retake from Review → returns to Capture. Expected: phase transitions render; no network call before Submit. Traces: AC-1, AC-2, AC-3.

- **TC-AND-323-11 — Attempt-model CTAs (Compose-UI).** Type: Compose-UI (emu(test35)). Target: result-screen CTA logic / `canRetry`. Preconditions: three canned results — fail+remaining=1; fail+remaining=0; pass; review. Steps: render each. Expected: fail+remaining>0 shows "Try again" returning to Capture; fail+remaining=0 hides retry and shows the manual-review message; pass shows success+Done; review shows neutral pending-review. Traces: AC-4, AC-5.

- **TC-AND-323-12 — History list (Compose-UI + contract).** Type: Compose-UI (emu(test35)) backed by MWS. Target: `loadHistory()` + history UI. Preconditions: MWS `FaceComparisonListOut` with 2 attempts; also an empty-list variant. Steps: open screen, expand history. Expected: rows show result, score, timestamp; ordering is newest-first (sorted by `created_at` desc defensively); empty list renders an empty state without error. Traces: AC-6.

- **TC-AND-323-13 — Camera permission gate (security/permission).** Type: instrumented (emu(test35) for grant/deny via UiAutomator; device(A15) for the real system dialog). Target: AND-129 permission gate on the screen. Preconditions: `CAMERA` permission not yet granted. Steps: open screen → deny → assert rationale + Settings deep link, capture controls disabled; grant → assert live preview appears. Expected: denied state blocks capture with rationale; granted state enables capture; no permission beyond `CAMERA`. Traces: AC-1.

- **TC-AND-323-14 — Real selfie capture + temp-file lifecycle + FLAG_SECURE (e2e, device).** Type: instrumented/e2e (MUST run on device(A15) — real front camera). Target: end-to-end capture→submit against MWS (or dev backend) + privacy invariants. Preconditions: `CAMERA` granted; MWS canned pass; file observer on `cacheDir`, `filesDir`, MediaStore. Steps: capture a real front-camera selfie, Submit, reach Result, then leave the screen. Expected: a `cacheDir/kyc-selfie-*.jpg` exists transiently and is deleted after submission completes and on `onCleared()`; nothing written to `filesDir`/gallery/MediaStore; `FLAG_SECURE` is set while preview/selfie is on-screen (screenshot attempt yields a black frame). Traces: AC-3, AC-7. (Front-camera + FLAG_SECURE black-frame behavior is hardware/real-display dependent → device only.)

- **TC-AND-323-15 — Accessibility (TalkBack/semantics).** Type: Compose-UI/instrumented (emu(test35); spot-check TalkBack on device(A15)). Target: a11y semantics on capture + result screens. Preconditions: canned pass and fail results. Steps: assert Capture button `contentDescription` "Capture selfie"; oval-guide live-region hint present; result/score/remaining-attempts exposed via `semantics` and announced as a live region on resolve; pass/fail conveyed by text+icon (not color alone); touch targets ≥48dp; remaining-attempts uses `plurals`. Expected: all semantics present; no hardcoded strings. Traces: AC-3, AC-4, AC-5 (a11y aspects).

### Coverage matrix
| AC | Description | Covered by |
| --- | --- | --- |
| AC-1 | Open screen, live front preview + guide, permission honored | TC-10, TC-13 |
| AC-2 | Capture → Review (Retake/Submit), no network before Submit | TC-03, TC-10 |
| AC-3 | Submit chain → renders `FaceComparisonResultOut` (primary) | TC-01, TC-03, TC-10, TC-14, TC-15 |
| AC-4 | fail+remaining>0 Try again; remaining==0 hides retry + manual-review | TC-02, TC-11, TC-15 |
| AC-5 | pass → success+Done; review → pending-review | TC-02, TC-11, TC-15 |
| AC-6 | History loads via GET; result/score/timestamp | TC-01, TC-12 |
| AC-7 | Temp selfie deleted; nothing to gallery/filesDir; FLAG_SECURE | TC-14 |
| AC-8 | POST carry `X-CSRF-Token`; presigned PUT no cookies/CSRF; 401→refresh once | TC-04, TC-05 |
| AC-9 | 422/offline → Review + localized message + manual Retry; no POST auto-retry | TC-06, TC-07, TC-08, TC-09 |
