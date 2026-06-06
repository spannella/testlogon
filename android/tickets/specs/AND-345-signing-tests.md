---
id: AND-345
title: Signing tests
milestone: M7
epic: E44
priority: P2
size: M
status: draft
depends_on: [AND-344]
blocks: []
---

# AND-345 — Signing tests

## 1. Overview & Goal

This ticket delivers the automated test suite that validates the document-signing
feature shipped across epic **E44** (AND-339 → AND-344). It is a **Test** ticket
(P2) whose sole acceptance bar is that the suite is green and exercises the
behaviours those feature tickets introduced: signing DTO mapping, the
`SigningRepository`, the signing ViewModel state machine, and the Compose UI for
the packet list, packet detail, PDF rendering, signature capture/placement, and
submit/sign flows.

The goal is to lock down the contract and user-visible behaviour of the signing
modules so that regressions in serialization, repository caching/refresh,
ViewModel state transitions, and screen rendering are caught in CI before merge.
This ticket adds **no production code**. It only adds test sources under the
existing `feature-signing`, `core-data`, `core-network`, and `core-model`
modules, plus shared fixtures in `core-testing`. Where a test reveals a defect in
the code under test, the fix lands in the owning feature ticket, not here; this
ticket may add a `@Ignore("AND-###")` annotation referencing the owning ticket
rather than silently weakening an assertion.

Scope per backlog: **"Repo + UI tests."** Acceptance per backlog: **"Pass."**
We interpret "Repo" as the repository + DTO/data layer (JVM unit tests) and "UI"
as Compose instrumented/Robolectric tests for the signing screens.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Media3, Paging 3.
  minSdk 24, compileSdk/targetSdk 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- Module layering: `app → feature-signing → core-*`
  (`core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`).
- Upstream tickets under test:
  - **AND-339** Signing API + DTOs — `signaturePackets`, `signatureTemplates` DTOs.
  - **AND-340** Packet list + detail screens and status rendering.
  - **AND-341** PDF rendering (PdfRenderer-backed page composables).
  - **AND-342** Signature capture + placement (draw/adopt, field placement).
  - **AND-343** Submit / sign + licenses (`licenseAgreements`).
  - **AND-344** Signing ViewModels — the state machine (direct dependency).
- Web reference: `frontend/src/api/endpoints/signaturePackets.ts`,
  `signatureTemplates.ts`, `licenseAgreements.ts`; shared types
  `frontend/src/api/types.ts`. Backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (PLAINTEXT dev host, unreliable).
- Test infra baseline assumed present from earlier milestones: `core-testing`
  provides `MainDispatcherRule`, a `MockWebServer` harness, Hilt test runner, and
  Turbine for Flow assertions.

## 3. Functional Requirements

FR-1. Provide **JVM unit tests** for all signing DTOs (AND-339): round-trip Moshi
serialize/deserialize, null/optional field handling, enum decoding for packet and
field status, and mapping DTO → `core-model` domain types.

FR-2. Provide **JVM unit tests** for `SigningRepository`: success path, cache
read-through (Room), stale/offline fallback, single `/ui/session/refresh` retry on
401, and `ApiResult` error mapping (FastAPI `detail` variants).

FR-3. Provide **JVM unit tests** for the signing ViewModel state machine (AND-344):
every documented `UiState` transition for packet detail, signature capture/adopt,
field placement, and submit/sign — including loading, success, error, and
optimistic-then-rollback paths.

FR-4. Provide **Compose UI tests** (Robolectric `@Config(sdk=[34])` under the
`testDebugUnitTest` source set, or `androidTest` for device-only PdfRenderer paths)
for: packet list rendering and empty/error states (AND-340); packet detail open
(AND-340); multi-page PDF render + scroll (AND-341); signature draw/adopt and
placement onto a document field (AND-342); submit produces a confirmation state
(AND-343).

FR-5. Tests must be **hermetic**: no network to the real dev host. All HTTP is
served via `MockWebServer`; all time/dispatch is controlled via injected test
dispatchers and `runTest`.

FR-6. Tests must be **deterministic and CI-runnable** via
`./gradlew :feature-signing:testDebugUnitTest :core-data:testDebugUnitTest
:core-network:testDebugUnitTest :core-model:testDebugUnitTest` (plus the
instrumented subset where PdfRenderer cannot be shadowed).

FR-7. Shared fixtures (sample packet JSON, sample 2-page PDF byte[], fake
repositories) live in `core-testing` so other epics can reuse them.

## 4. Technical Design

Test source layout (no production changes):

```
core-testing/src/main/kotlin/com/testlogon/android/core/testing/signing/
  SigningFixtures.kt          // JSON + domain fixtures, sample PDF bytes
  FakeSigningRepository.kt    // in-memory ApiResult-returning fake
  SignaturePacketBuilder.kt   // test data builders

core-model/src/test/kotlin/com/testlogon/android/core/model/signing/
  SigningMappersTest.kt

core-network/src/test/kotlin/com/testlogon/android/core/network/signing/
  SigningDtoJsonTest.kt
  SigningApiTest.kt           // Retrofit + MockWebServer

core-data/src/test/kotlin/com/testlogon/android/core/data/signing/
  SigningRepositoryTest.kt
  SigningRepositoryRefreshTest.kt

feature-signing/src/test/kotlin/com/testlogon/android/feature/signing/
  PacketListViewModelTest.kt
  PacketDetailViewModelTest.kt
  SignViewModelTest.kt        // capture/placement/submit state machine
  ui/PacketListScreenTest.kt  // Robolectric + createComposeRule
  ui/PacketDetailScreenTest.kt
  ui/SignatureCaptureScreenTest.kt
feature-signing/src/androidTest/kotlin/com/testlogon/android/feature/signing/
  ui/PdfDocumentScreenTest.kt // real PdfRenderer (device/emulator)
```

Key shared fixture signatures:

```kotlin
object SigningFixtures {
    const val PACKET_LIST_JSON: String        // GET /ui/signing/packets body
    const val PACKET_DETAIL_JSON: String      // GET /ui/signing/packets/{id}
    const val TEMPLATE_JSON: String
    const val DETAIL_ERROR_DETAIL_LIST: String // 422 {"detail":[{"msg":...}]}
    fun samplePdfBytes(pages: Int = 2): ByteArray
    fun packet(
        id: String = "pkt_1",
        status: PacketStatus = PacketStatus.PENDING,
        fields: List<SignatureField> = listOf(signatureField()),
    ): SignaturePacket
    fun signatureField(
        id: String = "fld_1",
        page: Int = 0,
        rect: NormalizedRect = NormalizedRect(0.1f, 0.8f, 0.4f, 0.9f),
    ): SignatureField
}

class FakeSigningRepository : SigningRepository {
    var listResult: ApiResult<List<SignaturePacket>> = ApiResult.Success(emptyList())
    var detailResult: ApiResult<SignaturePacket> = ApiResult.Success(SigningFixtures.packet())
    var submitResult: ApiResult<SubmitReceipt> = ApiResult.Success(SubmitReceipt("rcpt_1"))
    val submitted = mutableListOf<SignedPacket>()
    override fun observePackets(): Flow<List<SignaturePacket>> = ...
    override suspend fun refreshPackets(): ApiResult<Unit> = ...
    override suspend fun getPacket(id: String): ApiResult<SignaturePacket> = detailResult
    override suspend fun submitSigned(packet: SignedPacket): ApiResult<SubmitReceipt> = ...
}
```

ViewModel tests use Turbine over `StateFlow<UiState>` with a
`MainDispatcherRule(StandardTestDispatcher())`:

```kotlin
@get:Rule val mainDispatcherRule = MainDispatcherRule()

@Test fun `submit emits Submitting then Confirmed`() = runTest {
    val repo = FakeSigningRepository()
    val vm = SignViewModel(repo, SigningFixtures.packet(), testDispatcherProvider)
    vm.uiState.test {
        assertThat(awaitItem()).isInstanceOf(SignUiState.Ready::class.java)
        vm.onSubmit()
        assertThat(awaitItem()).isInstanceOf(SignUiState.Submitting::class.java)
        assertThat(awaitItem()).isInstanceOf(SignUiState.Confirmed::class.java)
        cancelAndIgnoreRemainingEvents()
    }
}
```

Compose tests use `createComposeRule()` (Robolectric) and drive the screen with a
`FakeSigningRepository` / fixed `UiState`, asserting via `onNodeWithTag` /
`onNodeWithText` and semantics. PdfRenderer cannot be Robolectric-shadowed
reliably, so the multi-page render+scroll assertion (AND-341) runs as an
instrumented `androidTest` using `createAndroidComposeRule`; the unit-test layer
asserts page-count/placeholder logic against a fake `PdfPageProvider`.

Libraries: JUnit4, `kotlinx-coroutines-test`, Turbine, Truth (or Kotest
assertions), MockWebServer, Robolectric, `androidx.compose.ui:ui-test-junit4`,
`androidx.compose.ui:ui-test-manifest`, Hilt testing for any DI-graph tests. All
declared in version catalog under `[libraries]` test entries; no new production
deps.

## 5. API Contract

No new API is defined here; this ticket **consumes** the AND-339 contract via
`MockWebServer`. Tests assert the client correctly issues and parses these:

- `GET /ui/signing/packets` → `200 [SignaturePacketDto, …]`
- `GET /ui/signing/packets/{packetId}` → `200 SignaturePacketDto`
- `GET /ui/signing/templates` → `200 [SignatureTemplateDto, …]`
- `POST /ui/signing/packets/{packetId}/submit` with signed-packet body →
  `200 {"receipt_id": "...", "status": "submitted"}`
- `GET /ui/license-agreements` → `200 [...]` (AND-343)

Representative fixture body asserted in `SigningDtoJsonTest`:

```json
{
  "packet_id": "pkt_1",
  "status": "pending",
  "document_url": "/ui/signing/packets/pkt_1/document.pdf",
  "fields": [
    {"field_id": "fld_1", "type": "signature", "page": 0,
     "rect": {"x": 0.1, "y": 0.8, "w": 0.3, "h": 0.1}, "required": true}
  ],
  "license_agreements": [{"id": "lic_1", "version": "2025-01"}]
}
```

Header/CSRF behaviour under test: requests carry the `X-CSRF-Token` header echoed
from the `ui_csrf` cookie; a `401` on a GET triggers exactly one
`POST /ui/session/refresh` followed by a retry. `SigningApiTest` enqueues a `401`
then `200` and asserts the recorded request sequence
(`packets`, `session/refresh`, `packets`) and a single refresh. Error-detail
mapping is asserted for the three FastAPI shapes: `"detail": "msg"`,
`"detail": [{"msg": ...}]`, and `"detail": {"code": ...}`.

## 6. Data & State Management

The suite verifies, not introduces, data/state behaviour:

- **Room cache (core-data):** `SigningRepositoryTest` uses an in-memory Room DB
  (`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()` only in tests) to
  assert that `refreshPackets()` upserts and `observePackets()` emits the cached
  list; that a failed refresh keeps prior cached rows (stale-but-usable); and that
  detail fetch falls back to cache when the network returns an error.
- **DataStore prefs:** if signing stores last-viewed packet or draft signature
  prefs, a `PreferencesDataStore` backed by a temp file
  (`PreferenceDataStoreFactory.create { tmp.resolve("test.preferences_pb") }`) is
  used; the test asserts read/write/clear.
- **ViewModel state:** `SignUiState` transitions asserted exhaustively —
  `Loading → Ready → Capturing → Placed → Submitting → Confirmed`, plus
  `→ Error(retryable)` branches and the optimistic-submit rollback to `Ready`
  on `ApiResult.Failure`. Normalized rect placement math (clamping to 0..1,
  page-relative coordinates) is unit-tested independently of Compose.

## 7. Error Handling & Resilience

The tests are the resilience guarantee for the signing feature. Required cases:

- 20s timeout path: enqueue a `MockWebServer` dispatcher that sleeps beyond the
  configured timeout (or `SocketPolicy.NO_RESPONSE`) and assert the repository
  yields `ApiResult.Failure(Timeout)` and the ViewModel surfaces a retryable
  `Error` state — not a crash.
- Bounded backoff retry applies to idempotent GETs only; assert
  `POST .../submit` is **never** auto-retried on 5xx/timeout.
- Single-refresh-on-401 invariant (see §5): two consecutive 401s must surface an
  auth error, not loop.
- Malformed JSON / missing required field → `ApiResult.Failure(Parse)` mapped to
  a non-crashing error state; assert the user-facing message is non-empty.
- Offline (network `IOException`) with warm cache → stale UI state rendered with a
  staleness indicator semantics node.

Within the test harness itself: tests must not depend on wall-clock sleeps
(`runTest` virtual time only) and must close `MockWebServer` / Room in `@After`.

## 8. Security & Privacy

- Tests must use only synthetic fixtures: no real credentials, no real signature
  images, no PII. Sample username/password in any session fixture is
  `test-user` / `test-pass`.
- A test asserts the signed-packet submit body does **not** log raw signature
  bitmap bytes or cookie values (verify the logging interceptor redacts; see §10).
- A test asserts the `X-CSRF-Token` header is present on the mutating
  `POST .../submit` request (CSRF protection regression guard).
- No plaintext secrets committed; fixtures contain no secrets. The dev host is
  HTTP, but tests never hit it — `MockWebServer` runs on loopback, so no plaintext
  data leaves the test JVM.

## 9. Accessibility & i18n

- Compose UI tests assert content-description / semantics on key controls: the
  signature capture canvas (`contentDescription`), the "Adopt", "Clear", and
  "Submit" buttons, and each placed signature field (focusable, labelled).
- A test asserts no user-facing string is a hard-coded literal in the asserted
  nodes by referencing `R.string.*` resource ids in the assertions (e.g.
  `onNodeWithText(context.getString(R.string.signing_submit))`), guarding i18n.
- A touch-target test asserts interactive nodes meet the ≥48dp minimum via
  `assertWidthIsAtLeast(48.dp)` / `assertHeightIsAtLeast(48.dp)`.

## 10. Telemetry & Logging

- The suite includes a redaction test: install the app's OkHttp logging
  interceptor with a captured logger and assert that `Cookie`, `Set-Cookie`,
  `X-CSRF-Token`, and signature image payloads are masked in emitted log lines.
- A test asserts the signing analytics events documented by AND-340/343
  (`signing_packet_opened`, `signing_submitted`) are dispatched through the
  injected `Analytics` fake exactly once per action with the expected packet id
  property. If analytics is not yet wired by the feature tickets, this assertion
  is marked `@Ignore("AND-343")` referencing the owning ticket rather than
  removed.

## 11. Testing Strategy

This ticket *is* the testing strategy for E44. Layers:

1. **DTO/serialization (JVM, fast):** `SigningDtoJsonTest`, `SigningMappersTest`.
2. **Network client (JVM + MockWebServer):** `SigningApiTest` — request shape,
   headers, refresh-retry, error mapping.
3. **Repository (JVM + in-memory Room):** `SigningRepositoryTest`,
   `SigningRepositoryRefreshTest` — cache, stale, offline, ApiResult mapping.
4. **ViewModel (JVM + Turbine + virtual time):** exhaustive state-machine
   coverage for AND-344.
5. **Compose UI (Robolectric, `testDebugUnitTest`):** list/detail/capture rendering
   and interaction with a `FakeSigningRepository`.
6. **Instrumented UI (`androidTest`):** real-PdfRenderer multi-page render+scroll
   (AND-341) which cannot be shadowed.

Coverage target: ViewModel + repository ≥ 85% line coverage (JaCoCo report via
`testDebugUnitTest`); every public ViewModel intent and every `UiState` subtype
exercised. Run locally:
`./gradlew :feature-signing:testDebugUnitTest :core-data:testDebugUnitTest
:core-network:testDebugUnitTest :core-model:testDebugUnitTest` and, for the
device subset, `:feature-signing:connectedDebugAndroidTest`.

## 12. Dependencies & Sequencing

- **Hard dependency (backlog):** AND-344 (Signing ViewModels). The ViewModel
  state machine must exist to be tested; AND-344's own acceptance is "unit-tested,"
  so this ticket extends and deepens that coverage and adds repo + UI layers.
- **Transitive feature coverage:** AND-339 (DTOs), AND-340 (list/detail UI),
  AND-341 (PDF), AND-342 (capture/placement), AND-343 (submit/licenses) must be
  merged so their code exists to test; this ticket should be sequenced **last** in
  E44.
- **Infra prerequisites:** `core-testing` harness (MainDispatcherRule,
  MockWebServer wrapper, Hilt test runner) from earlier milestones; version
  catalog test entries (Robolectric, Turbine, compose ui-test). If any are
  missing, add them in this ticket's catalog change (test-only).
- **Blocks:** nothing downstream; this is the terminal QA gate for E44.

## 13. Risks & Open Questions

- **PdfRenderer shadowing:** Robolectric does not faithfully shadow
  `android.graphics.pdf.PdfRenderer`; the multi-page render assertion may have to
  stay instrumented-only, which slows CI. Mitigation: keep page-count/placeholder
  logic behind a `PdfPageProvider` interface that can be faked in JVM tests.
- **Flaky timeout tests:** sleep/`NO_RESPONSE` based timeout tests can be slow or
  flaky if real timeouts are large. Mitigation: inject a short test `OkHttpClient`
  timeout via the test DI module rather than relying on the 20s prod value.
- **State-machine drift:** if AND-344 lands a different `UiState` shape than
  assumed here, tests must track the actual sealed hierarchy. Open question:
  confirm final `SignUiState` subtypes and intent method names with AND-344.
- **Analytics/redaction readiness:** telemetry assertions (§10) depend on those
  hooks existing; if not, they ship `@Ignore` with the owning ticket id.
- **Open question:** does the backend submit endpoint accept a multipart signature
  image or base64-in-JSON? Confirm against `/openapi.json` so the request-body
  assertion in `SigningApiTest` matches the real contract.

## 14. Acceptance Criteria

AC-1. New tests exist in the modules/paths in §4 and compile under JDK 17 / AGP
8.7.3.

AC-2. `./gradlew :feature-signing:testDebugUnitTest :core-data:testDebugUnitTest
:core-network:testDebugUnitTest :core-model:testDebugUnitTest` passes with **zero
failures** and zero non-`@Ignore` skips. (Backlog acceptance: "Pass.")

AC-3. DTO round-trip, null/optional, and enum-decode tests pass for
`signaturePackets` and `signatureTemplates` (AND-339 coverage).

AC-4. Repository tests prove: cache read-through, stale-on-failed-refresh,
offline fallback, single-refresh-on-401, and the three FastAPI `detail` error
mappings.

AC-5. ViewModel tests cover every `SignUiState` subtype and every documented
transition, including submit success, error, and optimistic rollback.

AC-6. Compose tests assert: packet list renders + empty/error states; detail
opens; signature draw/adopt + placement; submit reaches a confirmation state.
Instrumented test asserts a multi-page PDF renders and scrolls (AND-341).

AC-7. Tests are hermetic (no real-host network), deterministic across 3
consecutive CI runs, and complete in CI without manual intervention.

AC-8. No production source files under `feature-signing`/`core-*` are modified
except test sources, `core-testing` fixtures, and version-catalog test entries.

## 15. Definition of Done

- All acceptance criteria (§14) met; suite green in CI on `android-port`.
- JaCoCo coverage report generated; ViewModel + repository ≥ 85% lines; report
  attached to the PR.
- `core-testing` exposes reusable `SigningFixtures` and `FakeSigningRepository`
  consumed by at least the repo and UI tests.
- Any `@Ignore` carries an `AND-###` reason pointing at the owning feature ticket;
  no assertions weakened to force a pass.
- No new production dependencies; only test/catalog entries added, package
  `com.testlogon.android.*` throughout.
- PR description lists which E44 behaviours are covered and the run command; at
  least one reviewer from the signing feature owners approves.
- CI job runs both `testDebugUnitTest` and the instrumented PDF subset (or the
  PDF subset is documented as nightly-only with rationale).
