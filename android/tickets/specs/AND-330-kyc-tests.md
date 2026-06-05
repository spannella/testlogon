---
id: AND-330
title: KYC tests
milestone: M7
epic: E42
priority: P1
size: M
status: draft
depends_on: [AND-320, AND-321]
blocks: []
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
  cache-then-network merge of `GET /v1/kyc/tiers/me` + `GET /v1/kyc/requirements`,
  the `POST /v1/kyc/evaluate` write-through, the `TierStatusViewModel` state
  machine, and the `TierStatusScreen` Compose surface.
- **AND-321 — Document capture + upload** (capture flow): the
  `DocumentCaptureViewModel` capture → review → upload → register state machine,
  the `CaptureImageProcessor` resize/EXIF logic, the `KycRepository.createDocument`
  request/response mapping, and the capture/upload Compose surfaces driven behind a
  fake `DocumentCaptureController` seam.

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
- **Web reference (fixture source of truth):** `frontend/src/api/endpoints/kyc.ts`
  and shared types in `frontend/src/api/types.ts`; backend OpenAPI at
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
  `GET /v1/kyc/requirements?target_tier=…` concurrently, merges both DTOs into the
  domain `TierStatus`, writes the snapshot to `KycTierStore`, and returns the merged
  `ApiResult.Success`.
- `observeTierStatus()` emits the cached snapshot first (with `stale` derived from
  `asOf`) then the fresh network result.
- `evaluate(targetTier)` POSTs `/v1/kyc/evaluate`, maps the response into
  `TierEvaluation` (including `promoted`), and write-throughs the snapshot on success;
  on failure leaves the snapshot intact.
- DTO→domain mapping: tier-level and requirement-status enums map correctly; unknown
  strings degrade to `TierLevel.UNKNOWN` / `ReqStatus.UNKNOWN`; `target_tier == null`
  ⇒ `target == null` (max tier).
- All three FastAPI `detail` shapes (string, `[{msg}]`, `{code,…}`) resolve to a
  non-crashing human message.

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
- `KycRepository.createDocument(documentType, attachmentIds)` issues
  `POST /v1/kyc/documents` with an **ordered** `attachments` array, maps a 201 to
  `KycDocumentDto`, and maps error `detail` variants — verified against MockWebServer.
- `KycRepository.requirements()` maps the templates/pages payload used to drive the
  picker.
- `CaptureImageProcessor`: fixes EXIF orientation, downsizes a fixture JPEG to the
  2048 px / quality-85 / ≤4 MB constraint, returns the resulting byte size, and
  rejects an image still over the cap after compression.

**FR-5 — Capture ViewModel state-machine tests (AND-321).**
`DocumentCaptureViewModel` exposes `StateFlow<DocumentCaptureUiState>`. Tests pin the
full happy path (`Loading → Capturing → Reviewing → Capturing(next page) → Uploading
→ Success`) and failure paths: permission denied → `PermissionRequired`; upload
failure marks the page `Failed` and `retryUpload()` resumes from the first
non-confirmed page **without** re-uploading confirmed pages; registration failure
after all pages confirm is retryable without re-upload; cancel deletes cache files
and performs no registration.

**FR-6 — Capture Compose / instrumented tests (AND-321).** With a
`FakeDocumentCaptureController`, simulate capturing each required page (invoke
`onCaptured(fixtureFile)`), assert Retake/Use-photo navigation advances pages, the
upload progress + success states render, cancel returns without registration, and the
permission-denied rationale + "Open settings" render. The binding instrumented test
asserts a `kycDocuments` registration request is sent to MockWebServer with the
correct ordered attachment ids and the UI reaches `Success`.

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
the real DTO mapping. The shapes validated:

`GET /v1/kyc/tiers/me` →
```json
{ "current_tier": { "id": "tier_1", "name": "Basic",
    "limits": [{ "label": "Daily transfer", "value": "$1,000" }] },
  "target_tier": { "id": "tier_2", "name": "Verified", "limits": [] },
  "eligible_for_target": false }
```

`GET /v1/kyc/requirements?target_tier=tier_2` →
```json
{ "target_tier": "tier_2",
  "requirements": [
    { "key": "id_document", "label": "Government ID", "status": "satisfied", "case_id": "case_abc" },
    { "key": "selfie", "label": "Liveness selfie", "status": "action_required",
      "help_text": "Retake in better lighting", "case_id": null } ] }
```

`POST /v1/kyc/evaluate` — request `{ "target_tier": "tier_2" }`; response asserted
against `evaluate_promoted.json` / `evaluate_not_promoted.json`:
```json
{ "current_tier": { "id": "tier_2", "name": "Verified" }, "target_tier": null,
  "eligible_for_target": true, "promoted": true, "requirements": [] }
```

`GET /v1/kyc/requirements` (templates form, drives the picker) and
`POST /v1/kyc/documents` — the binding capture assertion checks the recorded request:
```json
{ "document_type": "passport", "attachments": ["att_main", "att_back"] }
```
response `documents_201.json`:
```json
{ "id": "kycdoc_a1b2", "document_type": "passport", "status": "pending_review",
  "attachments": ["att_main", "att_back"], "created_at": "2026-06-05T12:00:00Z" }
```

Error fixtures cover the FastAPI `detail` variants the KYC layer must tolerate:
`{"detail":"Not found"}`, `{"detail":[{"msg":"field required","loc":["body","target_tier"]}]}`,
and `{"detail":{"code":"tier_locked"}}`. Each is asserted to resolve (via AND-015) to a
non-empty, non-crashing message string — the mapping is exercised, not re-implemented.
The AND-129 presign/PUT/confirm shapes are **not** asserted here (owned by AND-129);
the uploader is faked.

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
- **CSRF assertion.** Tests assert that `POST /v1/kyc/evaluate` and
  `POST /v1/kyc/documents` carry an `X-CSRF-Token` header (cookie-based session
  contract), validating that the AND-012 interceptor path is engaged through the real
  client. Cookie-jar / `/ui/session/refresh` behavior itself stays owned by AND-011/013.
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
| Tier mapper | `unknownEnumsDegradeToUnknown` | unknown level/status → `UNKNOWN`, no throw |
| Tier mapper | `nullTargetTierMeansMaxTier` | `target_tier:null` ⇒ `target == null` |
| Tier repo | `refreshMergesConcurrently` | tiers/me + requirements merged, snapshot written |
| Tier repo | `evaluateWriteThroughOnSuccess` | snapshot overwritten; `promoted` mapped |
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
| Capture repo | `createDocumentOrderedAttachments` | POST body order + 201 mapping |
| Capture VM | `happyPathCaptureToSuccess` | `Loading→…→Uploading→Success` |
| Capture VM | `partialUploadRetryNoReupload` | retry uploads only failed page |
| Capture VM | `registrationFailureRetryable` | confirmed ids kept; no re-upload |
| Capture VM | `cancelDeletesFilesNoRegister` | files gone; no POST |
| Capture UI | `permissionDeniedShowsRationale` | rationale + "Open settings" |
| Capture UI (instr) | `simulatedCaptureReachesSuccess` | binding: ordered `kycDocuments` POST + `Success` |

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
