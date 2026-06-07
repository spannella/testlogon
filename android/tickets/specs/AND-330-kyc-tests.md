---
id: AND-330
title: KYC tests
milestone: M7
epic: E42
priority: P1
size: M
depends_on: [AND-320, AND-321]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-330 — KYC tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the KYC (Know Your
Customer) feature slice in the TestLogon native Android port. It is a **Test**
ticket (P1, milestone **M7**, epic **E42**); it ships no production UI or runtime
behavior of its own. Its goal is to convert the acceptance bullets of the two
upstream KYC feature tickets into deterministic, repeatable, mostly-headless
verification:

- **AND-320 — Tier status & requirements** (Repo layer): the `KycTierRepository`
  cache-then-network merge of `GET /v1/kyc/tiers/me` + `GET /v1/kyc/tiers/me/requirements/{target_tier}`
  (CORRECTED — see §16; the prior `GET /v1/kyc/requirements` query-param form does
  not exist), the `POST /v1/kyc/tiers/me/evaluate` write-through (CORRECTED from
  `POST /v1/kyc/evaluate`), the `TierStatusViewModel` state machine, and the
  `TierStatusScreen` Compose surface.
- **AND-321 — Document capture + upload** (capture flow): the
  `DocumentCaptureViewModel` capture → review → upload → register state machine,
  the `CaptureImageProcessor` resize/EXIF logic, the `KycRepository.uploadDocument`
  request/response mapping against `POST /ui/kyc/documents` (CORRECTED from
  `KycRepository.createDocument` / `POST /v1/kyc/documents`; see §16), and the
  capture/upload Compose surfaces driven behind a fake `DocumentCaptureController`
  seam.

The backlog scope is **"Repo + capture-flow tests"** and the acceptance is a single
binding word: **"Pass."** Concretely, the full suite must execute green via
`./gradlew :feature:kyc:test :feature:kyc:connectedDebugAndroidTest` — the JVM unit
+ Robolectric layer with no device or network, and the instrumented Compose layer
on a headless emulator with no live backend (all traffic mocked via MockWebServer).
This ticket also wires the suite into CI (AND-050 unit job, AND-051 instrumented
job) so it is part of the standard gate, never hitting `18.222.237.167`.

This is a test-only ticket. No new production source is authored except, where a
seam is missing, small **test-visibility** refactors (e.g. ensuring
`DocumentCaptureController` is an interface with an injectable fake, or injecting a
`Clock` for `asOf` staleness assertions) coordinated with the owning feature
tickets and landing with no behavior change.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base `com.testlogon.android`. All tests
  live in `feature-kyc` (Gradle module `:feature:kyc`, namespace
  `com.testlogon.android.feature.kyc`).
- **Subjects under test (authoritative requirements):**
  - **AND-320** — `KycTierRepository` / `KycTierRepositoryImpl`, `KycTierStore`
    (DataStore snapshot), `TierStatusViewModel`, `TierUiState`/`TierEvent`,
    `TierStatusScreen`.
  - **AND-321** — `DocumentCaptureViewModel`, `DocumentCaptureUiState`,
    `CapturedPage`, `CaptureImageProcessor`, `DocumentCaptureController` (interface
    seam), `KycRepository.createDocument`, and the capture/review/upload composables.
- **Consumed (not re-tested here):** AND-319 (`KycApi`, KYC DTOs, `ApiResult`,
  `detail` mapping), AND-129 (`AttachmentUploader` presign→PUT→confirm), AND-011/012/013
  (cookie jar, CSRF, 401-refresh), AND-015 error mapping, AND-018 `ApiResult`,
  AND-046 MockWebServer harness, AND-052 telemetry facade. These are exercised
  through fakes/mocks; their own coverage stays with their tickets.
- **Web reference (fixture source of truth):** tier calls live in
  `frontend/src/api/endpoints/kyc-tiers.ts` and document calls in
  `frontend/src/api/endpoints/kycDocuments.ts` (CORRECTED — there is no single
  `kyc.ts`; see §16), shared DTOs in `frontend/src/api/types.ts`, and transport in
  `frontend/src/api/client.ts`; backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json` under the `kyc` tag. Fixtures are
  captured once and committed; **tests never hit the live dev host.**
- **Shared test infra (`core-testing`):** `MainDispatcherRule`, Turbine helpers,
  JSON fixture loader, `FakeAnalyticsLogger`, MockWebServer harness. This ticket
  adds KYC-specific fakes (`FakeAttachmentUploader`, `FakeDocumentCaptureController`)
  and fixtures under `feature-kyc/src/test/resources/fixtures/kyc/`.
- **Stack constraints:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore, CameraX
  1.4.x (capture, faked in test). minSdk 24, compile/target 35, JDK 17, AGP 8.7.3,
  Gradle 8.9.

## 3. Functional Requirements

**FR-1 — Tier repository tests (AND-320).** Cover `KycTierRepositoryImpl`:
- `refreshTierStatus()` fetches `GET /v1/kyc/tiers/me` and
  `GET /v1/kyc/tiers/me/requirements/{target_tier}` (CORRECTED path — `target_tier`
  is a **path segment integer**, not a `?target_tier=` query param; see §16)
  concurrently, merges the `TierDetails` + `TierRequirements` DTOs into the domain
  `TierStatus`, writes the snapshot to `KycTierStore`, and returns the merged
  `ApiResult.Success`. The next target tier is derived client-side as
  `min(current_tier + 1, 4)` (web reference behavior).
- `observeTierStatus()` emits the cached snapshot first (with `stale` derived from
  `asOf`) then the fresh network result.
- `evaluate()` POSTs `/v1/kyc/tiers/me/evaluate` **with no request body** (CORRECTED
  — the prior `/v1/kyc/evaluate` with a `{target_tier}` body is wrong; the real op
  takes no body and the server re-evaluates the caller's tier), maps the returned
  `TierDetails` snapshot, and write-throughs on success; on failure leaves the
  snapshot intact. **Promotion is detected client-side** as
  `response.current_tier > previous.current_tier` (CORRECTED — there is no `promoted`
  field in any KYC response; the web client compares `current_tier`; see §16).
- DTO→domain mapping: `current_tier` / `target_tier` are **integers** (0–4), not
  nested `{id,name,limits}` objects (CORRECTED; see §16). `tier_name` is a string on
  `TierDetails`. `TierRequirements` carries flat `met: string[]` / `unmet: string[]`
  arrays plus `eligible: boolean` — there are **no** per-requirement
  status/help_text/case_id objects (CORRECTED). Unknown / out-of-range tier integers
  degrade to a neutral `TierLevel.UNKNOWN` rendering without crashing.
- All three FastAPI `detail` shapes (string, `[{msg,…}]`, `{code,…}`) resolve to a
  non-crashing human message via the AND-015 mapping (mirrors
  `normalizeErrorDetail` in `client.ts`).

**FR-2 — Tier ViewModel tests (AND-320).** `TierStatusViewModel` exposes
`StateFlow<TierUiState>` + `SharedFlow<TierEvent>`. Tests assert: `Loading → Content`
on success; `Loading → Error(canRetry)` on first-load failure with no cache;
`onEvaluate()` sets `evaluating = true` then applies the result; `promoted == true`
emits `TierEvent.Promoted`; `eligibleForTarget == true` is reflected in `Content`;
evaluate failure clears `evaluating`, keeps prior `Content`, emits
`TierEvent.Snackbar`; refresh failure with cache present keeps `Content` and sets
`stale = true` (stale-while-error).

**FR-3 — Tier Compose tests (AND-320).** Robolectric-hosted `TierStatusScreen` tests
assert: current tier + limits render; requirement rows render with status conveyed by
icon+text (not color alone); satisfied vs `action_required` are visually
distinguished and exposed via merged semantics; the max-tier terminal state hides the
Evaluate button and requirements; the Evaluate button is disabled and shows progress
while `evaluating`; a requirement row carrying a `caseId` invokes `onOpenCase`.

**FR-4 — Capture repository / processor tests (AND-321).** Cover:
- `KycRepository.uploadDocument(request: KycDocumentUploadRequest)` issues
  `POST /ui/kyc/documents` (CORRECTED endpoint — the prior `POST /v1/kyc/documents`
  does not exist; see §16) with a JSON body of `{ document_type, file_name,
  case_id?, content_b64? }` where `document_type` is one of the **only two** allowed
  values `id_front` | `id_back` (CORRECTED — `passport` is not a valid
  `KycDocumentType`; the multi-page "ordered `attachments` array" model is NOT how
  this endpoint works — there is no `attachments` field at all). The body carries the
  image **inline as base64 `content_b64`**, not pre-uploaded attachment ids. Maps a
  201 to `KycDocumentOut` and maps error `detail` variants — verified against
  MockWebServer.
- `CaptureImageProcessor`: fixes EXIF orientation, downsizes a fixture JPEG to the
  (assumed) 2048 px / quality-85 / ≤4 MB constraint, returns the resulting byte size,
  base64-encodes the result for `content_b64`, and rejects an image still over the cap
  after compression. (Cap values unverified — see §16 / §13.)

**FR-5 — Capture ViewModel state-machine tests (AND-321).**
`DocumentCaptureViewModel` exposes `StateFlow<DocumentCaptureUiState>`. The capture
flow captures the two required pages (`id_front`, then `id_back`), each uploaded as a
separate `POST /ui/kyc/documents` call (one `KycDocumentOut` per page; CORRECTED —
there is no single multi-attachment "register" call, see §16). Tests pin the full
happy path (`Loading → Capturing(id_front) → Reviewing → Capturing(id_back) →
Reviewing → Uploading → Success`) and failure paths: permission denied →
`PermissionRequired`; the second page upload failing marks that page `Failed` and
`retryUpload()` re-issues **only** the failed page's `POST` (the already-succeeded
page's returned `document_id` is retained and not re-uploaded); cancel deletes cache
files and performs no upload.

**FR-6 — Capture Compose / instrumented tests (AND-321).** With a
`FakeDocumentCaptureController`, simulate capturing each required page (invoke
`onCaptured(fixtureFile)`), assert Retake/Use-photo navigation advances pages, the
upload progress + success states render, cancel returns without any upload, and the
permission-denied rationale + "Open settings" render. The binding instrumented test
asserts a `POST /ui/kyc/documents` request per page is sent to MockWebServer with the
correct `document_type` (`id_front`/`id_back`) and `file_name` and the UI reaches
`Success`.

**FR-7 — CI execution.** The JVM/Robolectric tests run in the AND-050 `test` job with
no device and no network; the instrumented capture tests run in the AND-051
headless-emulator job against MockWebServer. The whole KYC suite is green in CI on
`android-port`.

## 4. Technical Design

**Source layout (test source sets + shared fakes only):**

```
feature-kyc/src/test/kotlin/com/testlogon/android/feature/kyc/
  tier/KycTierRepositoryTest.kt          // MockWebServer
  tier/KycTierMapperTest.kt
  tier/TierStatusViewModelTest.kt        // Turbine + StandardTestDispatcher
  tier/TierStatusScreenTest.kt           // Robolectric + Compose
  capture/KycRepositoryTest.kt           // MockWebServer
  capture/CaptureImageProcessorTest.kt
  capture/DocumentCaptureViewModelTest.kt
feature-kyc/src/androidTest/kotlin/com/testlogon/android/feature/kyc/
  capture/DocumentCaptureFlowTest.kt     // instrumented Compose + MockWebServer
  tier/TierStatusScreenInstrumentedTest.kt   // optional, if Robolectric insufficient
core-testing/src/main/kotlin/com/testlogon/android/core/testing/kyc/
  FakeAttachmentUploader.kt
  FakeDocumentCaptureController.kt
  KycFixtures.kt
feature-kyc/src/test/resources/fixtures/kyc/      // committed JSON + a fixture JPEG
  tiers_me.json  requirements.json  evaluate_promoted.json  evaluate_not_promoted.json
  documents_201.json  detail_string.json  detail_loc.json  detail_code.json
  sample_landscape_exif6.jpg
```

**MockWebServer harness.** Tier-repo and capture-repo request/response tests use the
AND-046 MockWebServer harness rather than hand-rolled fakes so the real Retrofit/Moshi
stack (and AND-015 `detail` mapping) is exercised end-to-end. Each test enqueues a
fixture body, runs the call on a `StandardTestDispatcher`, then asserts on the
`RecordedRequest` (path, method, body JSON, `X-CSRF-Token` header presence on POSTs).

**Fakes (in `core-testing`, reusable downstream).**

```kotlin
class FakeAttachmentUploader : AttachmentUploader {            // AND-129 seam
    var behavior: (File) -> ApiResult<String> = { ok("att_${it.name}") }
    val uploaded = mutableListOf<File>()
    val confirmed = mutableSetOf<String>()
    override fun upload(file: File, mime: String): Flow<UploadProgress> = /* emits Progress→Done(attachmentId) or Failure per `behavior` */
}

class FakeDocumentCaptureController : DocumentCaptureController {
    val released = AtomicBoolean(false)
    var captureResult: (File) -> Result<File> = { Result.success(it) }
    override fun bind(previewView: PreviewView) { /* no-op */ }
    override fun setFlash(enabled: Boolean) { /* records last value */ }
    override suspend fun capture(outputFile: File): Result<File> = captureResult(outputFile)
    override fun release() { released.set(true) }
}
```

`behavior`/`captureResult` lambdas let a single test force success, partial failure
(one page fails, others confirm), or `ApiResult.Failure(NetworkError.Timeout)`, all
deterministically.

**Coroutine/time control.** Every ViewModel and repository test uses
`MainDispatcherRule(StandardTestDispatcher())` from `core-testing` and `runTest {}`.
`advanceUntilIdle()` drives `Capturing → Uploading → Success` transitions and the
tier `Loading → Content` transition without real delays. A fixed
`Clock.fixed(Instant.parse("2026-06-05T00:00:00Z"), UTC)` removes wall-clock
flakiness in `TierStatus.asOf` / `stale` assertions; if the production `asOf` is
server-supplied this is asserted from the fixture instead.

**Flow assertions.** Turbine (`state.test { }`) asserts the ordered `UiState`
emission sequence; `events.test { }` asserts one-shot `TierEvent`s. Because both
ViewModels expose `StateFlow`, tests use `skipItems`/`awaitItem` precisely so a
conflated state never hides an intermediate (`evaluating`/`Uploading`) emission —
intermediate states are asserted via a `MutableStateFlow` recorder where conflation
would drop them.

**Compose tests.** Tier-screen tests run under `@RunWith(RobolectricTestRunner::class)`
`@Config(sdk = [34])` with `createComposeRule()` and a ViewModel wired to fakes — kept
in the JVM `test` source set so no emulator is needed. The capture flow, which touches
CameraX preview binding, runs as an instrumented `androidTest` with a
`createAndroidComposeRule` and the `FakeDocumentCaptureController`, so capture is
simulated by invoking `onCaptured(fixtureFile)` and no real camera is required on the
headless emulator.

**Test-seam adjustments.** If `DocumentCaptureController` is currently a concrete
class, AND-321's owner makes it an interface (already designed as such in AND-321 §4).
If `cacheDir` paths are computed internally, the ViewModel must accept an injectable
`CaptureFileFactory`/`File` root so tests write to a JUnit `@TempDir`. These land
behind existing constructors with no production behavior change.

## 5. API Contract

This ticket defines **no new endpoints**. It validates the AND-320/AND-321 consumption
of the AND-319 contract by enqueuing committed fixtures in MockWebServer and asserting
the real DTO mapping. **All JSON below has been corrected to the authoritative backend
schemas and web reference (see §16); the prior nested-object/`promoted`/`attachments`
shapes were fabricated and have been replaced.**

`GET /v1/kyc/tiers/me` → `TierDetails`:
```json
{ "user_sub": "user_123", "current_tier": 1, "tier_name": "Verified",
  "updated_at": 1749081600, "history": [] }
```
(`current_tier` is an **integer** tier level 0–4, not an object; `updated_at` is an
epoch-seconds integer or null.)

`GET /v1/kyc/tiers/me/requirements/{target_tier}` (e.g. `/2`) → `TierRequirements`:
```json
{ "target_tier": 2, "current_tier": 1,
  "met": ["email_verified", "phone_verified"],
  "unmet": ["id_document", "selfie"],
  "eligible": false }
```
(Flat `met`/`unmet` string arrays + `eligible` boolean — **no** per-requirement
status/help_text/case_id objects.)

`POST /v1/kyc/tiers/me/evaluate` — **request body: none**; response is a fresh
`TierDetails` (same shape as `tiers/me`). Promotion is inferred by the client as
`response.current_tier > previous.current_tier` (there is no `promoted` field).
Fixtures `evaluate_promoted.json` (e.g. `current_tier: 2`) and
`evaluate_not_promoted.json` (`current_tier` unchanged).

`POST /ui/kyc/documents` — request body `KycDocumentUploadRequest`
(required: `document_type`, `file_name`):
```json
{ "document_type": "id_front", "file_name": "id_front.jpg",
  "case_id": null, "content_b64": "<base64 image bytes>" }
```
response `documents_201.json` → `KycDocumentOut` (required: `document_id`,
`document_type`, `file_name`, `status`):
```json
{ "document_id": "kycdoc_a1b2", "case_id": null, "user_sub": "user_123",
  "document_type": "id_front", "file_name": "id_front.jpg", "status": "pending",
  "extracted_fields": {}, "created_at": 1749081600, "updated_at": 1749081600 }
```
(`status` enum: `pending` | `extracted` | `failed` | `approved` | `rejected` — note
`pending`, not `pending_review`; `created_at`/`updated_at` are epoch-seconds
**integers**, not ISO strings. There is no `attachments` array.)

Error fixtures cover the FastAPI `detail` variants the KYC layer must tolerate:
`{"detail":"Not found"}`,
`{"detail":[{"msg":"field required","loc":["body","file_name"]}]}`, and
`{"detail":{"code":"tier_locked"}}`. Each is asserted to resolve (via AND-015,
mirroring `normalizeErrorDetail`) to a non-empty, non-crashing message string — the
mapping is exercised, not re-implemented. The AND-129 presign/PUT/confirm flow is
**not** part of this endpoint (the image is sent inline as `content_b64`); if AND-321
instead routes large files through AND-129, that uploader is faked and asserted
separately.

## 6. Data & State Management

UI/domain state shapes asserted by tests (owned upstream; reproduced for assertions):

```kotlin
sealed interface TierUiState {
    data object Loading : TierUiState
    data class Content(
        val current: Tier, val target: Tier?, val requirements: List<Requirement>,
        val eligibleForTarget: Boolean, val evaluating: Boolean = false,
        val refreshing: Boolean = false, val stale: Boolean = false,
        val inlineError: String? = null,
    ) : TierUiState
    data class Error(val message: String, val canRetry: Boolean) : TierUiState
}

sealed interface DocumentCaptureUiState {
    data object Loading; data class Capturing(/*…*/); data class Reviewing(/*…*/)
    data class Uploading(val progress: Float, val pageStatus: List<PageUploadStatus>)
    data class Success(val document: KycDocumentDto)
    data class Error(val error: UiError, val retryable: Boolean)
    data class PermissionRequired(val permanentlyDenied: Boolean)
}
data class CapturedPage(val pageKey: String, val file: File, val attachmentId: String? = null)
```

**Tier state assertions.** `KycTierStore` is backed in tests by an in-memory
DataStore (`PreferenceDataStoreFactory.create` over a `@TempDir` file) so the
cache-then-network and write-through paths are real. Tests pin: (1) cached snapshot
emitted before network; (2) `stale` true when the fixture `asOf` is older than the
staleness window; (3) a successful `evaluate` overwrites the snapshot so a fresh
`observeTierStatus()` returns the evaluated state (cold-start persistence).

**Capture state machine assertions.** The `CapturedPage.attachmentId` is the
reconciliation key for retry: a partial-upload test seeds page 1 confirmed
(`attachmentId != null`) and page 2 `Failed`, then asserts `retryUpload()` uploads
**only** page 2 (`FakeAttachmentUploader.uploaded.size == 1` for the retry) and that
`createDocument` is finally called with both ids in capture order. A separate test
asserts cache files (written under `@TempDir`) are deleted on `Success` and on
`cancelUpload()`, and that no `POST /v1/kyc/documents` request reaches MockWebServer
after cancel.

No Room is involved on either surface (tier uses DataStore; capture uses cache files),
so no DAO fakes are needed.

## 7. Error Handling & Resilience

Although this is a test ticket, proving the KYC layer's resilience is its primary
value:

- **GET retry vs. POST no-retry.** Enqueue a 503 then a 200 for `GET /v1/kyc/tiers/me`
  / `requirements`; assert the AND-016 backoff retries and the call ultimately
  succeeds (`RecordedRequest` count ≥ 2). For `POST /v1/kyc/evaluate` and
  `POST /v1/kyc/documents`, enqueue a single failure and assert the repository issues
  the request **exactly once** (no auto-retry of non-idempotent writes); recovery is
  only via explicit user action.
- **Stale-while-error (tier).** Network `Failure` with a seeded `KycTierStore`
  snapshot keeps `Content` visible, sets `stale = true`, and surfaces a non-blocking
  message — not a full-screen `Error`.
- **First-load error (tier).** No cache + `Failure` ⇒ `TierUiState.Error(canRetry = true)`;
  a subsequent enqueued success transitions to `Content`.
- **Evaluate failure.** Clears `evaluating`, keeps prior `Content`, emits
  `TierEvent.Snackbar`; the failed evaluation is never partially applied.
- **Capture failures.** Permission denied ⇒ `PermissionRequired`; `captureResult`
  returning failure leaves the current page un-advanced; oversized-after-compression
  image is rejected; upload failure marks the page `Failed` and is resumable;
  registration failure keeps confirmed `attachmentId`s for retry-without-re-upload.
- **Unknown enums.** Unknown tier level / requirement status fixtures degrade to
  `UNKNOWN` and render with neutral style — asserted, not crashing.

Determinism is enforced by `StandardTestDispatcher` + fixed `Clock` and MockWebServer
queues; no real delays, no real timeouts, no `Thread.sleep`. The suite must be stable
across 10 consecutive CI runs.

## 8. Security & Privacy

No production security surface is added. Test-specific guarantees mirror the PII
sensitivity of KYC:

- **No live calls / no secrets.** All fixtures are synthetic — no real cookies,
  `ui_csrf` tokens, credentials, signed presign URLs, or identity PII appear in
  committed JSON or the sample JPEG (a blank generated image, not a real document).
  Tests must not read environment auth or contact `18.222.237.167`; MockWebServer
  binds to localhost only.
- **CSRF assertion.** Tests assert that `POST /v1/kyc/tiers/me/evaluate` and
  `POST /ui/kyc/documents` carry an `X-CSRF-Token` header sourced from the `ui_csrf`
  cookie (CORRECTED endpoint paths; see §16). Per `client.ts` the web client sets
  this header on **every** request whenever the cookie is present (not only POSTs), so
  the parallel assertion on the GET tier calls is also valid; the POSTs are the
  load-bearing case. This validates the AND-012 interceptor path through the real
  client. Cookie-jar / `/ui/session/refresh` 401-retry behavior itself stays owned by
  AND-011/013.
- **Capture-file confinement.** A test asserts captured files are written only under
  the injected cache root (`@TempDir`) and never to external/shared storage, and are
  deleted on success/cancel/discard — guarding the AND-321 "files never leave
  app-internal storage" rule.
- **Log/telemetry hygiene assertion.** Using `FakeAnalyticsLogger`, tests verify KYC
  PII never appears in events or logs: tier events carry only tier ids and
  boolean/enum outcomes (no help-text); capture events carry only metadata (page
  count, byte sizes, durations, document type) — never image bytes, filenames with
  user data, or signed URLs. A test scans captured log/event payloads for the fixture
  help-text string and asserts it is absent.

## 9. Accessibility & i18n

No new shipping UI, so no new a11y or localized surface is introduced. The Compose
tests **assert existing a11y contracts** so regressions are caught:

- Requirement rows expose merged semantics conveying `"<label>, <status>"` and status
  is conveyed by icon+text (WCAG 1.4.1) — a test asserts the merged semantics node
  exists and is not color-only.
- The Evaluate button exposes a `stateDescription` while `evaluating` and is disabled
  (not merely visually) during the call; touch target ≥ 48 dp.
- Capture controls (shutter, flash, retake, use-photo, cancel) expose non-empty
  `contentDescription`s located by `onNodeWithContentDescription`; the capture guide
  overlay is decorative (`contentDescription == null`); "Page X of N" is a
  `liveRegion`.
- Tests resolve copy via `context.getString(R.string.…)` rather than hardcoded English
  literals, so i18n coverage stays owned by the feature tickets; no new strings are
  added here.

## 10. Telemetry & Logging

This ticket uses (does not produce) telemetry via `core-testing`'s
`FakeAnalyticsLogger` to assert the AND-320/AND-321 event contracts:

- Tier: `kyc_tier_viewed`, `kyc_evaluate_tapped`, `kyc_evaluate_result
  { target_tier, promoted, eligible }`, and `kyc_tier_load_error { stage, code }`
  each fire on the expected transitions, once per occurrence, with no PII.
- Capture: `kyc_capture_started`, `kyc_page_captured { byte_size, capture_ms }`,
  `kyc_page_retaken`, `kyc_upload_started`, `kyc_upload_failed { error_code }`,
  `kyc_document_registered { kyc_document_id }`, `kyc_capture_cancelled { stage }`
  fire correctly; reconciliation/retry does not double-count
  (`kyc_document_registered` fires exactly once on success).
- Failures log the mapped `ApiError.code`, not raw response bodies — asserted against
  the `detail` error fixtures.

Test logging itself uses Robolectric `ShadowLog` / JUnit output; failures print the
captured `UiState` emission list, the MockWebServer `RecordedRequest` log, and the
`FakeAttachmentUploader.uploaded` list to make CI failures diagnosable.

## 11. Testing Strategy

**Frameworks:** JUnit4; MockWebServer (AND-046) for the real Retrofit/Moshi path;
Robolectric (`@Config(sdk=[34])`) for tier Compose-on-JVM; instrumented
`androidTest` Compose for the capture flow; Truth/AssertK assertions; Turbine for
Flow; `kotlinx-coroutines-test`; MockK only where a fake is impractical.

**Representative cases:**

| Area | Test | Asserts |
|---|---|---|
| Tier mapper | `unknownTierIntDegradesToUnknown` | out-of-range tier int → neutral `UNKNOWN`, no throw |
| Tier mapper | `maxTierHasNoNextTarget` | `current_tier == 4` ⇒ no requirements fetch (`min(c+1,4)==c`) |
| Tier repo | `refreshMergesConcurrently` | tiers/me + tiers/me/requirements/{n} merged, snapshot written |
| Tier repo | `evaluateWriteThroughOnSuccess` | snapshot overwritten; promotion = `current_tier` increased |
| Tier repo | `evaluateFailureKeepsSnapshot` | snapshot intact; one POST only |
| Tier repo | `getRetriedPostNotRetried` | 503→200 GET retried; POST count == 1 |
| Tier repo | `detailVariantsMapToMessage` | all 3 `detail` shapes → message |
| Tier VM | `loadingToContentToErrorPaths` | full state sequence + `canRetry` |
| Tier VM | `evaluatePromotedEmitsEvent` | `evaluating` then `Content`; `TierEvent.Promoted` |
| Tier VM | `refreshFailureKeepsStaleContent` | `Content` + `stale` |
| Tier UI | `statusByIconTextNotColor` | merged semantics; satisfied≠action_required |
| Tier UI | `maxTierHidesEvaluate` | terminal state; no Evaluate/requirements |
| Tier UI | `caseRowInvokesOpenCase` | `onOpenCase(caseId)` fired |
| Capture proc | `exifFixAndDownsizeToCap` | orientation corrected; ≤4 MB / 2048 px |
| Capture proc | `oversizedRejected` | over-cap image rejected |
| Capture repo | `uploadDocumentBodyAndMapping` | `POST /ui/kyc/documents` body (`document_type`,`file_name`,`content_b64`) + 201→`KycDocumentOut` |
| Capture VM | `happyPathCaptureToSuccess` | `Loading→…→Uploading→Success` (id_front then id_back) |
| Capture VM | `secondPageUploadRetryNoReupload` | retry re-POSTs only the failed page |
| Capture VM | `cancelDeletesFilesNoUpload` | files gone; no POST |
| Capture UI | `permissionDeniedShowsRationale` | rationale + "Open settings" |
| Capture UI (instr) | `simulatedCaptureReachesSuccess` | binding: `POST /ui/kyc/documents` per page + `Success` |

**Coverage gate:** target ≥ 80% line coverage on `KycTierRepositoryImpl`,
`TierStatusViewModel`, `DocumentCaptureViewModel`, and `CaptureImageProcessor`
(JaCoCo, reported in CI, advisory not blocking for this ticket).

**Headless commands:**
`./gradlew :feature:kyc:testDebugUnitTest` (no emulator/ADB/network) and
`./gradlew :feature:kyc:connectedDebugAndroidTest` (headless emulator, MockWebServer
only) must both pass.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):** **AND-320** (tier status/requirements feature —
  repository, ViewModel, screen) and **AND-321** (document capture + upload feature —
  ViewModel, controller seam, processor, repository call). Both are the direct
  subjects of this suite; their public types and UI must exist for tests to compile.
- **Transitive deps:** AND-319 (`KycApi` + DTOs), AND-129 (`AttachmentUploader`
  contract, faked), AND-011/012/013 (cookie/CSRF/refresh — engaged via the real
  client in MockWebServer tests), AND-015 (`detail` mapping), AND-018 (`ApiResult`),
  AND-046 (MockWebServer harness), AND-052 (telemetry facade), AND-050/051 (CI unit +
  instrumented jobs). Practically this ticket sequences **after the whole E42 KYC
  base slice (AND-319, AND-320, AND-321) is code-complete.**
- **Shared infra added here:** `FakeAttachmentUploader`, `FakeDocumentCaptureController`,
  and `KycFixtures` in `core-testing`, reusable by later KYC tickets (AND-322 ID
  scanner, AND-323 facial comparison, AND-324 liveness, AND-326 residency, etc.).
- **Blocks:** none recorded in the backlog; serves as a quality gate before the
  remaining M7 KYC surfaces build on the base.

## 13. Risks & Open Questions

- **`StateFlow` conflation hiding intermediate states.** Conflated `StateFlow` can
  drop the transient `evaluating` / `Uploading` emission before Turbine observes it.
  Mitigation: drive transitions with `StandardTestDispatcher` + `advanceUntilIdle()`
  stepwise, or record emissions through a non-conflated collector. If a transient is
  genuinely unobservable, assert the side effect (button disabled / progress node)
  instead. **Resolve during implementation.**
- **CameraX cannot run on a headless emulator.** The real `bind()` preview path stays
  manually tested only; the instrumented suite uses `FakeDocumentCaptureController`
  and simulated capture. Accepted (matches AND-321 §13).
- **`evaluate` response shape.** AND-320 §13 flags whether `/v1/kyc/evaluate` returns
  the full merged snapshot or a delta. The repo test must mirror whatever AND-320
  finalizes; if a re-fetch is required after evaluate, the test asserts the extra
  GETs. **Open against AND-320 owner.**
- **`POST /v1/kyc/documents` field names.** `document_type` / `attachments` are
  inferred from the web reference + OpenAPI; the binding capture test asserts the
  finalized AND-319/AND-321 shape — confirm before merge. **Open.**
- **Multi-page vs. single multi-image attachment.** If the backend expects one
  multi-image attachment instead of N ordered ids, the ordered-attachments assertion
  changes. **Open, verify with AND-319.**
- **Compression cap (4 MB / 2048 px).** Assumed values; the processor test asserts
  whatever AND-321 finalizes. **Open.**

## 14. Acceptance Criteria

1. **Suite passes (binding backlog criterion "Pass").**
   `./gradlew :feature:kyc:testDebugUnitTest` and
   `./gradlew :feature:kyc:connectedDebugAndroidTest` both complete green in CI on
   `android-port`, with the unit layer using no emulator/ADB/network and the
   instrumented layer using a headless emulator with MockWebServer only.
2. **Tier repo coverage.** Concurrent merge of tiers/me + requirements, snapshot
   write, cache-then-network emission, evaluate write-through (incl. `promoted`),
   evaluate-failure snapshot integrity, unknown-enum degradation, max-tier
   (`target == null`), GET-retried-vs-POST-not-retried, and all three `detail`
   variants are each tested and passing.
3. **Tier ViewModel coverage.** `Loading→Content`, first-load `Error(canRetry)`,
   `onEvaluate` `evaluating→Content`, `TierEvent.Promoted` on promotion,
   eligibility reflected, evaluate-failure snackbar with content retained, and
   stale-while-error are asserted.
4. **Tier UI coverage.** Robolectric tests assert status by icon+text (not color),
   satisfied≠action_required, max-tier terminal state, Evaluate disabled+progress
   while evaluating, and `caseId` row → `onOpenCase`.
5. **Capture coverage.** Image processor (EXIF + downsize-to-cap + oversize reject),
   `createDocument` ordered-`attachments` request + 201 mapping, the full capture
   state machine, partial-upload retry-without-re-upload, registration-retry-without-
   re-upload, and cancel-deletes-files-no-register are each tested.
6. **Binding capture test.** An instrumented Compose test with
   `FakeDocumentCaptureController` simulates capturing the required pages and asserts a
   `kycDocuments` registration request with the correct ordered attachment ids and a
   `Success` UI state.
7. **No-network / no-PII guarantee.** No KYC test contacts `18.222.237.167`; CSRF
   headers are asserted on POSTs; captured files stay under the injected cache root
   and are swept; KYC PII (help-text, image bytes, signed URLs) never appears in
   logs/telemetry.
8. **Determinism.** Suite uses `StandardTestDispatcher` (+ fixed `Clock` where time is
   client-derived); no `Thread.sleep`/real delays; stable across 10 consecutive CI
   runs.

## 15. Definition of Done

- All §14 criteria met; both Gradle commands green in CI on `android-port`.
- New fakes (`FakeAttachmentUploader`, `FakeDocumentCaptureController`,
  `KycFixtures`) live in `core-testing`, and committed fixtures live under
  `feature-kyc/src/test/resources/fixtures/kyc/`, reusable by downstream KYC tickets
  (AND-322 … AND-328).
- Any required test-seam refactors (e.g. `DocumentCaptureController` interface, an
  injectable cache-file root / `Clock`) merged with the owning feature tickets, with
  no production behavior change.
- Test names are descriptive and failures print diagnostic state (emission list,
  `RecordedRequest` log, uploader log).
- No new production strings, endpoints, or security surfaces introduced; sections
  genuinely N/A (new shipping UI / i18n strings / new API endpoints) are explicitly
  delegated to AND-320 / AND-321 / AND-319.
- CI runs the KYC unit tests in the AND-050 job and the capture instrumented tests in
  the AND-051 headless-emulator job; documented in the `feature-kyc` README test
  section.
- ktlint/detekt (AND-005) clean; builds on JDK 17 / AGP 8.7.3 / Gradle 8.9.
- Open questions in §13 either resolved with AND-319/AND-320/AND-321 owners or tracked
  as follow-ups referenced in the PR description; code reviewed and merged.

## 16. Citations & Assumption Audit

Every concrete API/web claim in this spec was checked against the backend OpenAPI
(`reference/openapi.index.txt`, `reference/openapi.pretty.json`) and the frontend
reference (`reference/src/...`). Verdicts below.

1. **Claim:** Tier status is fetched from `GET /v1/kyc/tiers/me`.
   **VERDICT: Verified.**
   **Source:** OpenAPI `GET /v1/kyc/tiers/me` (op `get_my_tier_v1_kyc_tiers_me_get`);
   `src/api/endpoints/kyc-tiers.ts: getMyTier`.

2. **Claim (original):** Requirements come from `GET /v1/kyc/requirements?target_tier=…`.
   **VERDICT: Corrected.** Real endpoint is `GET /v1/kyc/tiers/me/requirements/{target_tier}`
   with `target_tier` an **integer path segment**.
   **Source:** OpenAPI `GET /v1/kyc/tiers/me/requirements/{target_tier}` (op
   `check_my_requirements_...`); `src/api/endpoints/kyc-tiers.ts: checkRequirements(targetTier: number)`.

3. **Claim (original):** Evaluate is `POST /v1/kyc/evaluate` with body `{target_tier}`.
   **VERDICT: Corrected.** Real endpoint is `POST /v1/kyc/tiers/me/evaluate` and it takes
   **no request body** (server re-evaluates the caller's own tier).
   **Source:** OpenAPI `POST /v1/kyc/tiers/me/evaluate` (op `evaluate_my_tier_...`,
   `req=` empty); `src/api/endpoints/kyc-tiers.ts: evaluateTier = () => api.post(...)` (no body arg).

4. **Claim (original):** The evaluate/tier response contains a `promoted` boolean.
   **VERDICT: Corrected.** No `promoted` field exists in any KYC tier response. The web
   client infers promotion as `response.current_tier > previous.current_tier`.
   **Source:** `src/api/types.ts: TierDetails` (no `promoted` field);
   `src/pages/kyc/KycTierProgress.tsx` (`if (data.current_tier > currentTier) … "Upgraded"`).

5. **Claim (original):** `tiers/me` returns nested `{current_tier:{id,name,limits}, target_tier:{…}, eligible_for_target}`.
   **VERDICT: Corrected.** `TierDetails = { user_sub, current_tier: int, tier_name: string, updated_at: int|null, history: [] }`.
   Tiers are integers 0–4, not objects; there are no `limits`.
   **Source:** `src/api/types.ts: TierDetails` (lines ~5597–5603);
   `openapi.pretty.json` components.schemas.TierDetails.

6. **Claim (original):** Requirements payload is `requirements: [{key,label,status,help_text,case_id}]` with per-row `satisfied`/`action_required` status and `caseId → onOpenCase`.
   **VERDICT: Corrected.** `TierRequirements = { target_tier:int, current_tier:int, met: string[], unmet: string[], eligible: bool }`.
   No per-requirement status/help_text/case_id objects exist, so the `onOpenCase`/`caseId`-row
   behavior (FR-3, §11 `caseRowInvokesOpenCase`, AC-4) is **unverified** and likely not
   part of the real contract; the web UI just renders met/unmet checklist rows.
   **Source:** `src/api/types.ts: TierRequirements`;
   `src/pages/kyc/KycTierProgress.tsx` (`[...requirements.met, ...requirements.unmet].map(...)`).

7. **Claim:** Next target tier is `min(current_tier + 1, 4)`.
   **VERDICT: Verified.**
   **Source:** `src/pages/kyc/KycTierProgress.tsx` (`const nextTier = Math.min(currentTier + 1, 4)`).

8. **Claim (original):** Document registration is `POST /v1/kyc/documents` with an ordered `attachments: ["att_main","att_back"]` array, document_type `passport`, response `{id, status:"pending_review", attachments, created_at:"<ISO>"}`.
   **VERDICT: Corrected (multiple).** Real endpoint is `POST /ui/kyc/documents` taking
   `KycDocumentUploadRequest { document_type, file_name, case_id?, content_b64? }`
   (required: `document_type`, `file_name`). There is **no `attachments` field**; the
   image goes inline as base64 `content_b64`. `document_type` is restricted to
   `id_front` | `id_back` (no `passport`). Response is `KycDocumentOut { document_id,
   case_id?, user_sub?, document_type, file_name, status, extracted_fields,
   match_results?, overall_confidence?, review_decision?, review_note?, created_at,
   updated_at }` (required: `document_id`,`document_type`,`file_name`,`status`).
   `status` enum = `pending|extracted|failed|approved|rejected` (not `pending_review`);
   `created_at`/`updated_at` are **epoch-second integers**, not ISO strings.
   **Source:** OpenAPI `POST /ui/kyc/documents` (op `upload_document_ui_kyc_documents_post`,
   `req=KycDocumentUploadRequest`, `resp=201:KycDocumentOut`);
   `openapi.pretty.json` components.schemas.KycDocumentUploadRequest / KycDocumentOut;
   `src/api/types.ts: KycDocumentUploadRequest / KycDocumentOut / KycDocumentType / KycDocumentStatus`;
   `src/api/endpoints/kycDocuments.ts: uploadKycDocument`;
   `src/pages/kyc/KycDocumentVerificationPage.tsx`.

9. **Claim (original):** A separate `KycRepository.requirements()` fetches a templates/pages payload that drives a document-type picker.
   **VERDICT: Corrected / removed.** No such per-document templates endpoint feeds the
   consumer upload flow. (`GET /v1/kyc/document-templates` exists but is an admin/signing
   templates surface, unrelated to the id_front/id_back capture picker.) The picker is
   simply the two fixed `KycDocumentType` values.
   **Source:** OpenAPI `GET /v1/kyc/document-templates` (admin templates);
   `src/api/types.ts: KycDocumentType = "id_front" | "id_back"`.

10. **Claim:** POSTs carry an `X-CSRF-Token` header from a cookie-based session.
    **VERDICT: Verified (with nuance).** The header is read from the `ui_csrf` cookie and
    set on **every** request (not only POSTs) when the cookie is present; requests use
    cookie credentials.
    **Source:** `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `credentials: "include"`).

11. **Claim:** A 401 triggers exactly one session refresh against `/ui/session/refresh` then a single retry.
    **VERDICT: Verified.**
    **Source:** `src/api/client.ts: refreshSession()` posts `/ui/session/refresh`; single
    `refreshPromise`-guarded retry; on second 401 → `logout("session_expired")`.

12. **Claim:** FastAPI `detail` has three shapes — string, `[{msg,…}]`, `{code,…}` — and all must map to a non-crashing human message.
    **VERDICT: Verified.**
    **Source:** `src/api/client.ts: normalizeErrorDetail` handles `typeof detail === "string"`,
    `Array.isArray(detail)` mapping `item.msg`, and object `detail` (code-based via
    `mapAuthorizationError`); OpenAPI error responses are `HTTPValidationError`
    (the `[{msg,loc,type}]` shape).

13. **Claim:** GETs may retry on 5xx; non-idempotent POSTs must not auto-retry (FR/§7).
    **VERDICT: Unverified-assumption.** The web client (`client.ts`) does **not**
    implement 5xx backoff/retry at all — only the 401-refresh retry. GET-retry is an
    Android-side AND-016 design choice, not a contract fact; the "POST issued exactly
    once" assertion remains a valid Android-layer guarantee but cannot be cited to the
    web reference.
    **Source:** absence of retry logic in `src/api/client.ts`; AND-016 (Android backoff,
    framework ref, not in these sources).

14. **Claim:** Robolectric Compose tests run under `@Config(sdk=[34])`.
    **VERDICT: Unverified-assumption (framework ref).** Robolectric's max supported SDK
    must be ≥34 in the pinned version; API-34 is a reasonable Robolectric target but is a
    tooling choice, not derivable from these sources.
    **Source:** framework ref — Robolectric supported-SDK matrix
    (https://robolectric.org/supported-sdks/).

15. **Claim:** Compression cap is 2048 px / quality 85 / ≤4 MB.
    **VERDICT: Unverified-assumption.** Not present in OpenAPI or web reference
    (`content_b64` has no documented size bound beyond `file_name maxLength 255`). Owned
    by AND-321; tests assert whatever AND-321 finalizes. (See §13.)

16. **Claim:** All KYC `/ui/kyc/*` and `/v1/kyc/*` errors include `422:HTTPValidationError`.
    **VERDICT: Verified.**
    **Source:** OpenAPI index lines 1533/2391/2392/2393 each list `422:HTTPValidationError`.

### Corrections made
- §1, §2, §3 (FR-1, FR-4, FR-5, FR-6), §5, §8, §11: replaced
  `GET /v1/kyc/requirements?target_tier=` → `GET /v1/kyc/tiers/me/requirements/{target_tier}`
  (path-int param); `POST /v1/kyc/evaluate {target_tier}` → `POST /v1/kyc/tiers/me/evaluate`
  (no body); `POST /v1/kyc/documents` + `attachments[]` model → `POST /ui/kyc/documents`
  with `KycDocumentUploadRequest`/`content_b64`.
- Removed the fabricated `promoted` field; promotion now defined as a client-side
  `current_tier` comparison.
- Replaced nested tier/limits objects with integer tiers + `tier_name`; replaced
  per-requirement status objects with flat `met`/`unmet` arrays.
- Corrected `document_type` enum to `id_front`/`id_back` (dropped `passport`), `status`
  to `pending` (not `pending_review`), and `created_at`/`updated_at` to epoch integers.
- Corrected web-reference file references (`kyc-tiers.ts` + `kycDocuments.ts`, not a
  single `kyc.ts`) and the CSRF "POST-only" claim (header is set on all requests).
- Renamed/retargeted the affected §11 representative test rows.

### Open assumptions
- **Per-requirement `caseId`/`onOpenCase` and `satisfied`/`action_required` status rows**
  (FR-3, §11 `caseRowInvokesOpenCase`, AC-4): not in the real `TierRequirements`
  contract (flat met/unmet). Flagged as likely-removable; confirm with AND-320 owner —
  if AND-320 ships a richer requirements model than the web reference, re-verify.
- **GET-retry-vs-POST-no-retry** (§7, AC-2): an Android AND-016 design choice, not a
  contract fact (web client has no 5xx retry). Keep as an Android-layer assertion.
- **Compression cap (2048 px / Q85 / ≤4 MB)** (FR-4, §13): not in sources; owned by AND-321.
- **`evaluate` returns full snapshot vs delta** (§13): the op returns `TierDetails`
  (full snapshot), so no extra GET is required; confirm AND-320 maps it as such.
- **Whether the capture flow uploads two separate `id_front`/`id_back` documents or one**:
  the contract is one `KycDocumentOut` per `POST /ui/kyc/documents` call and
  `document_type` is single-valued, implying one call per page; confirm AND-321's
  required-page set.
- **Robolectric `@Config(sdk=[34])`** and **CI emulator AVD `test35` (API 35)**: tooling
  choices, not contract facts.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device); **EMU** =
headless emulator AVD `test35` (x86_64, API 35) in CI; **DEVICE** = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). MockWebServer binds to localhost; no test
contacts `18.222.237.167`.

- **TC-AND-330-01 — Tier refresh merges tiers/me + requirements (happy path)**
  Type: contract/MockWebServer (JVM). Target: `KycTierRepositoryImpl`.
  Preconditions: MockWebServer enqueues `tiers_me.json` (`current_tier:1`) for
  `GET /v1/kyc/tiers/me` and `requirements.json` (`target_tier:2`) for
  `GET /v1/kyc/tiers/me/requirements/2`; empty `KycTierStore`.
  Steps: call `refreshTierStatus()` on `StandardTestDispatcher`; `advanceUntilIdle()`.
  Expected: both `RecordedRequest`s seen with the exact paths (path-int `…/2`, no query
  string); merged `TierStatus` has integer `current_tier==1`, `tier_name`, flat
  met/unmet, `eligible==false`; snapshot written to store; `ApiResult.Success`.
  Traces: AC-2.

- **TC-AND-330-02 — Cache-then-network emission + stale flag**
  Type: unit (JVM). Target: `KycTierRepositoryImpl.observeTierStatus()` + in-memory
  DataStore over `@TempDir`.
  Preconditions: store seeded with a snapshot whose `asOf` precedes the fixed
  `Clock` staleness window; MockWebServer enqueues a fresh `tiers_me.json`.
  Steps: collect `observeTierStatus()` via Turbine.
  Expected: first emission is the cached snapshot with `stale==true`; second is the
  fresh network result with `stale==false`.
  Traces: AC-2, AC-3.

- **TC-AND-330-03 — Evaluate write-through, promotion inferred from current_tier**
  Type: contract/MockWebServer (JVM). Target: `KycTierRepositoryImpl.evaluate()`.
  Preconditions: store seeded `current_tier:1`; MockWebServer enqueues
  `evaluate_promoted.json` (`current_tier:2`) for `POST /v1/kyc/tiers/me/evaluate`.
  Steps: call `evaluate()`; `advanceUntilIdle()`.
  Expected: recorded request is `POST /v1/kyc/tiers/me/evaluate` with **empty body**;
  promotion computed as `2 > 1 == true`; snapshot overwritten to `current_tier:2`;
  exactly one POST recorded.
  Traces: AC-2, AC-3.

- **TC-AND-330-04 — Evaluate failure keeps snapshot, single POST, snackbar event**
  Type: contract/MockWebServer + Turbine (JVM). Target: `KycTierRepositoryImpl` +
  `TierStatusViewModel`.
  Preconditions: store seeded `current_tier:1`; MockWebServer enqueues one 500 for
  `POST /v1/kyc/tiers/me/evaluate`.
  Steps: invoke `onEvaluate()`; collect state + events.
  Expected: `evaluating` toggles true then false; prior `Content` retained unchanged;
  `TierEvent.Snackbar` emitted; **exactly one** POST recorded (no auto-retry of the
  non-idempotent write).
  Traces: AC-2, AC-3.

- **TC-AND-330-05 — GET 503→200 retry vs POST single-shot**
  Type: contract/MockWebServer (JVM). Target: `KycTierRepositoryImpl` + AND-016 backoff.
  Preconditions: enqueue 503 then 200 for `GET /v1/kyc/tiers/me`; enqueue a single 500
  for `POST /v1/kyc/tiers/me/evaluate`.
  Steps: `refreshTierStatus()` then `evaluate()`; `advanceUntilIdle()`.
  Expected: GET recorded ≥2 times and ultimately succeeds; POST recorded exactly once.
  (Asserts the Android-layer assumption #13 in §16, not a web-contract fact.)
  Traces: AC-2, AC-8.

- **TC-AND-330-06 — FastAPI `detail` variants map to a non-empty message**
  Type: contract/MockWebServer (JVM). Target: AND-015 mapping via `KycTierRepositoryImpl`.
  Preconditions: enqueue, in turn, `detail_string.json` (`{"detail":"Not found"}`),
  `detail_loc.json` (`{"detail":[{"msg":"field required","loc":["body","file_name"]}]}`),
  `detail_code.json` (`{"detail":{"code":"tier_locked"}}`).
  Steps: drive a failing call per fixture.
  Expected: each yields `ApiResult.Failure` with a non-empty, non-crashing message
  string (string → as-is; array → joined `msg`; object → code-mapped/fallback),
  mirroring `normalizeErrorDetail`.
  Traces: AC-2, AC-7.

- **TC-AND-330-07 — Tier ViewModel state sequence (Loading→Content, first-load Error, stale-while-error)**
  Type: unit + Turbine (JVM). Target: `TierStatusViewModel`.
  Preconditions: (a) success fixtures, empty cache; (b) failure, empty cache;
  (c) failure, seeded cache.
  Steps: run each variant; collect `StateFlow<TierUiState>`.
  Expected: (a) `Loading→Content`; (b) `Loading→Error(canRetry=true)` and a subsequent
  enqueued success → `Content`; (c) `Content` retained with `stale=true` (no full-screen
  Error).
  Traces: AC-3.

- **TC-AND-330-08 — Tier screen renders met/unmet by icon+text, max tier hides Evaluate**
  Type: Compose-UI (Robolectric, JVM). Target: `TierStatusScreen`.
  Preconditions: ViewModel wired to fakes; one `Content` with met+unmet rows, one
  `current_tier==4` terminal state.
  Steps: render via `createComposeRule()`; query semantics.
  Expected: each requirement row exposes merged semantics conveying label + met/unmet
  state by icon **and** text (not color alone, WCAG 1.4.1); the Evaluate button exposes a
  `stateDescription` and is disabled (not merely greyed) while `evaluating`, touch
  target ≥48 dp; at `current_tier==4` the Evaluate button and requirements checklist are
  absent. NOTE: this case drops the prior `caseId → onOpenCase` assertion (unverified —
  see §16 open assumptions); if AND-320 confirms a richer model, re-add.
  Traces: AC-4.

- **TC-AND-330-09 — Image processor: EXIF fix + downsize-to-cap + base64; oversize reject**
  Type: unit (JVM/Robolectric for Bitmap). Target: `CaptureImageProcessor`.
  Preconditions: fixture `sample_landscape_exif6.jpg` (EXIF orientation 6); a synthetic
  over-cap image.
  Steps: process both.
  Expected: orientation corrected, output ≤ assumed 2048 px / ≤4 MB, byte size returned
  and base64-encodable for `content_b64`; the over-cap image is rejected after
  compression. (Cap values per AND-321; see §16 #15.)
  Traces: AC-5.

- **TC-AND-330-10 — uploadDocument request body + 201 mapping**
  Type: contract/MockWebServer (JVM). Target: `KycRepository.uploadDocument`.
  Preconditions: MockWebServer enqueues `documents_201.json` for `POST /ui/kyc/documents`.
  Steps: call `uploadDocument(KycDocumentUploadRequest(document_type="id_front",
  file_name="id_front.jpg", content_b64="…"))`.
  Expected: recorded request is `POST /ui/kyc/documents` carrying JSON
  `document_type:"id_front"`, non-empty `file_name`, and `content_b64`; response maps to
  `KycDocumentOut` with `document_id`, `status=="pending"` (enum), integer
  `created_at`/`updated_at`; an `X-CSRF-Token` header is present (from the seeded
  `ui_csrf` cookie).
  Traces: AC-5, AC-6, AC-7.

- **TC-AND-330-11 — Capture VM happy path (id_front then id_back → Success)**
  Type: unit + Turbine (JVM). Target: `DocumentCaptureViewModel` with
  `FakeDocumentCaptureController` + MockWebServer (2× 201).
  Preconditions: permission granted; controller returns fixture files.
  Steps: simulate `onCaptured` for id_front, confirm; `onCaptured` for id_back, confirm;
  upload; `advanceUntilIdle()`.
  Expected: `Loading→Capturing(id_front)→Reviewing→Capturing(id_back)→Reviewing→
  Uploading→Success`; two `POST /ui/kyc/documents` recorded with `document_type`
  `id_front` then `id_back`.
  Traces: AC-5, AC-6.

- **TC-AND-330-12 — Second-page upload retry re-POSTs only the failed page; cancel deletes files**
  Type: unit + Turbine (JVM). Target: `DocumentCaptureViewModel`.
  Preconditions: page 1 upload returns 201 (document_id retained); page 2 first attempt
  returns 500, retry returns 201; cache files under `@TempDir`.
  Steps: run upload, then `retryUpload()`; separately run `cancelUpload()`.
  Expected: page 2 marked `Failed` then resolved; retry issues exactly one additional
  `POST` (page 2 only — page 1 not re-uploaded); on `cancelUpload()` the `@TempDir` cache
  files are deleted and **no** `POST /ui/kyc/documents` is recorded.
  Traces: AC-5, AC-7.

- **TC-AND-330-13 — Capture permission denied shows rationale + Open settings**
  Type: Compose-UI (instrumented, EMU). Target: capture composable +
  `FakeDocumentCaptureController`.
  Preconditions: camera permission denied (permanently) state injected.
  Steps: render via `createAndroidComposeRule`; query nodes.
  Expected: `PermissionRequired(permanentlyDenied=true)` renders a rationale and an
  "Open settings" action; capture controls (shutter/flash/retake/use-photo/cancel) each
  expose a non-empty `contentDescription`; the guide overlay is decorative
  (`contentDescription == null`); "Page X of N" is a `liveRegion`.
  Traces: AC-4, AC-5, AC-7.

- **TC-AND-330-14 — Binding instrumented capture flow reaches Success against MockWebServer**
  Type: instrumented/e2e (EMU). Target: full capture Compose flow +
  `FakeDocumentCaptureController` + MockWebServer.
  Preconditions: MockWebServer enqueues `documents_201.json` per page; localhost only.
  Steps: drive simulated capture of both required pages and confirm/upload.
  Expected: a `POST /ui/kyc/documents` per page is recorded with correct
  `document_type`/`file_name` and an `X-CSRF-Token` header; UI reaches `Success`; no
  request targets `18.222.237.167`. The CameraX `bind()` preview path is NOT exercised
  here (faked).
  Traces: AC-1, AC-6, AC-7.

- **TC-AND-330-15 — Real CameraX capture + EXIF on physical device (manual gate)**
  Type: manual (DEVICE — Galaxy A15, API 34, arm64-v8a). Target: real
  `DocumentCaptureController.bind()`/`capture()` + `CaptureImageProcessor`.
  Preconditions: signed debug build on device; real rear camera; camera permission
  granted at runtime.
  Steps: capture an id_front frame with the device tilted (to produce a non-default EXIF
  orientation), confirm, and observe the upload payload via a debug log of the
  base64-decoded dimensions.
  Expected: real capture succeeds on arm64/API-34; EXIF orientation is corrected and the
  image is downsized to the cap before `content_b64` encoding. MUST run on the physical
  device — CameraX preview/capture cannot run on the headless emulator (see §13). This
  case is the manual counterpart to the faked TC-14 and is not part of the green CI gate.
  Traces: AC-5.

- **TC-AND-330-16 — No-PII in telemetry/logs**
  Type: unit (JVM). Target: `FakeAnalyticsLogger` capture across tier + capture flows.
  Preconditions: run TC-07/TC-11 flows with the fake logger attached; fixtures include a
  recognizable string (e.g. a synthetic extracted-field value).
  Steps: scan all captured event params and log lines.
  Expected: tier events carry only tier integers + boolean/enum outcomes; capture events
  carry only metadata (byte size, capture_ms, document_type, document_id); the synthetic
  PII string, image bytes, and `content_b64` never appear; failures log mapped
  `ApiError.code`, not raw bodies.
  Traces: AC-7, AC-8.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 — suite passes green (both gradle commands) | TC-14 (instrumented gate) + all JVM cases (TC-01…12, TC-16) run in unit job |
| AC-2 — tier repo coverage | TC-01, TC-03, TC-04, TC-05, TC-06 |
| AC-3 — tier ViewModel coverage | TC-02, TC-03, TC-04, TC-07 |
| AC-4 — tier UI coverage | TC-08 (note: `caseId→onOpenCase` flagged unverified in §16), TC-13 |
| AC-5 — capture coverage | TC-09, TC-10, TC-11, TC-12, TC-13, TC-15 |
| AC-6 — binding capture test | TC-11, TC-14 |
| AC-7 — no-network / no-PII / CSRF / file confinement | TC-06, TC-10, TC-12, TC-13, TC-14, TC-16 |
| AC-8 — determinism | TC-05 (single-shot/retry), TC-16; enforced suite-wide via `StandardTestDispatcher` + fixed `Clock` |
