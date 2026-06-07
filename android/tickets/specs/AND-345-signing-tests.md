---
id: AND-345
title: Signing tests
milestone: M7
epic: E44
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  `signatureTemplates.ts`, `licenseAgreements.ts`; shared transport/CSRF/refresh in
  `frontend/src/api/client.ts`; screen behaviour in
  `frontend/src/pages/signing/SigningPage.tsx` (which renders only a
  `SignaturePacketComposer` + `SignatureTemplateManager` — there is **no** packet-list
  screen) and `frontend/src/pages/files/SignaturePacketComposer.tsx`. Backend OpenAPI
  at `http://18.222.237.167:8000/openapi.json` (PLAINTEXT dev host, unreliable). The
  signing API lives under `/v1/signature-packets/*` (not `/ui/signing/packets/*`).
- Test infra baseline assumed present from earlier milestones: `core-testing`
  provides `MainDispatcherRule`, a `MockWebServer` harness, Hilt test runner, and
  Turbine for Flow assertions.

## 3. Functional Requirements

FR-1. Provide **JVM unit tests** for all signing DTOs (AND-339): round-trip Moshi
serialize/deserialize, null/optional field handling, enum decoding for packet and
field status, and mapping DTO → `core-model` domain types.

FR-2. Provide **JVM unit tests** for `SigningRepository`: success path, cache
read-through (Room), stale/offline fallback, single `POST /ui/session/refresh`
retry on 401 (only when already authenticated; verified in `client.ts`), and
`ApiResult` error mapping (FastAPI `detail` variants — string, ValidationError
array, and `{code}` object).

FR-3. Provide **JVM unit tests** for the signing ViewModel state machine (AND-344):
every documented `UiState` transition for packet detail, signature capture/adopt,
field placement, and submit/sign — including loading, success, error, and
optimistic-then-rollback paths.

FR-4. Provide **Compose UI tests** (Robolectric `@Config(sdk=[34])` under the
`testDebugUnitTest` source set, or `androidTest` for device-only PdfRenderer paths)
for: packet detail open + status rendering (AND-340); multi-page PDF render +
scroll from `/final-pdf` bytes (AND-341); signature draw/adopt and placement onto a
document field, producing a `fill` payload (AND-342); completion (`send`/`mark-done`)
produces a confirmation state (AND-343).
> **CORRECTED (review 2026-06-06):** "packet list rendering" was removed as a
> required screen because the backend exposes **no list endpoint** and the web
> reference has **no packet-list screen** (`SigningPage.tsx`). If AND-340 actually
> shipped an Android-only packet-list backed by a local Room cache (no server list
> call), test that against `FakeSigningRepository`; otherwise this is descoped.
> Confirm with the AND-340 owner (see §16 Open assumptions).

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
// NOTE (review 2026-06-06): shapes below were corrected to the real contract —
// no PACKET_LIST_JSON (no list endpoint), detail JSON is /v1/signature-packets/{id}
// (SignaturePacketDetailOut), packet status is the real enum, and fields use flat
// x/y/width/height + field_type (not a nested NormalizedRect/type).
object SigningFixtures {
    const val PACKET_DETAIL_JSON: String      // GET /v1/signature-packets/{packet_id}
    const val CREATE_PACKET_JSON: String      // POST /v1/signature-packets resp
    const val TEMPLATE_JSON: String           // GET /ui/signing/templates item
    const val DETAIL_ERROR_DETAIL_LIST: String // 422 {"detail":[{"loc":..,"msg":..,"type":..}]}
    fun samplePdfBytes(pages: Int = 2): ByteArray // for /final-pdf path
    fun packet(
        id: String = "pkt_1",
        status: PacketStatus = PacketStatus.SENT,   // not PENDING — real enum
        fields: List<SignatureField> = listOf(signatureField()),
    ): SignaturePacket
    fun signatureField(
        id: String = "fld_1",
        page: Int = 0,
        fieldType: FieldType = FieldType.SIGNATURE,
        x: Float = 0.1f, y: Float = 0.8f, width: Float = 0.3f, height: Float = 0.1f,
    ): SignatureField
}

class FakeSigningRepository : SigningRepository {
    // Detail fetch + the fill/send/mark-done flow that replaces the imaginary "submit".
    var detailResult: ApiResult<SignaturePacket> = ApiResult.Success(SigningFixtures.packet())
    var markDoneResult: ApiResult<MarkDoneResult> = ApiResult.Success(MarkDoneResult(/* SignaturePacketMarkDoneOut */))
    val filledFields = mutableListOf<FieldFill>()
    override suspend fun getPacket(id: String): ApiResult<SignaturePacket> = detailResult
    override suspend fun fillField(packetId: String, fieldId: String, fill: FieldFill): ApiResult<Unit> = ...
    override suspend fun send(packetId: String): ApiResult<SendResult> = ...
    override suspend fun markDone(packetId: String): ApiResult<MarkDoneResult> = markDoneResult
    // If the repo locally caches viewed packets, observe/refresh those rows; there is
    // no server list endpoint to back a global observePackets() stream.
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
`MockWebServer`. Tests assert the client correctly issues and parses these.

> **CORRECTED (review 2026-06-06):** the original draft listed `/ui/signing/packets`
> paths, a `/submit` endpoint, a `document_url`/`rect`/`license_agreements`-in-packet
> body, and `/ui/license-agreements`. **None of those exist.** The real backend
> contract (OpenAPI index + `frontend/src/api/endpoints/signaturePackets.ts`) is the
> `/v1/signature-packets` family below. There is **no packet-list endpoint** and the
> web reference has **no packet-list screen** (`SigningPage.tsx` renders only a
> `SignaturePacketComposer` + `SignatureTemplateManager`). See §16 for the audit.

Real endpoints (verified against OpenAPI and the web client):

- `POST /v1/signature-packets` `req=CreateSignaturePacketIn` →
  `200 CreateSignaturePacketOut` (create; body `source_path`, `origin_channel`,
  optional `origin_ref`).
- `GET /v1/signature-packets/{packet_id}` → `200 SignaturePacketDetailOut`.
- `POST /v1/signature-packets/{packet_id}/fields` `req=SignaturePacketFieldMutationIn`
  → `200 SignaturePacketFieldMutationOut` (field create/update/delete, `action` enum).
- `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill`
  `req=SignaturePacketFieldFillIn` → `200 SignaturePacketFieldFillOut`
  (fill: `value`, `input_mode` typed|drawn, `drawn_strokes: number[][]`, optional
  `notary_stamp`).
- `POST /v1/signature-packets/{packet_id}/send` → `200 SendSignaturePacketOut`.
- `POST /v1/signature-packets/{packet_id}/mark-done` → `200 SignaturePacketMarkDoneOut`.
- `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice` →
  `200 SignaturePacketLegalNoticeAckOut`.
- `GET /v1/signature-packets/{packet_id}/events` → `200 SignaturePacketEventsOut`.
- `GET /v1/signature-packets/{packet_id}/final-pdf` → `200` (PDF bytes; this is the
  document/PDF source, **not** a `document_url` field on the packet).
- `GET /ui/signing/templates` → `200 SignatureTemplateListOut` (verified — this one
  path was correct).
- License agreements (AND-343) live at `GET /ui/licenses/agreements` →
  `200 LicenseAgreementListOut` (**not** `/ui/license-agreements`).

There is **no submit endpoint** returning `{receipt_id, status}`. The "submit"
flow in the AND-343 sense maps to filling required fields then
`POST .../send` (sender) / `POST .../mark-done` (signer); the ViewModel
"Confirmed" state corresponds to a successful `mark-done`/`send`, not a synthetic
receipt. The `SubmitReceipt`/`submitSigned` fixtures in §4 must be renamed to wrap
`SignaturePacketMarkDoneOut` (or removed) to match the real contract.

Representative `SignaturePacketDetailOut` body asserted in `SigningDtoJsonTest`
(required keys: `packet_id, status, owner_user_id, source_path, role, signers,
fields, capabilities`; field geometry is flat `x/y/width/height` with
`field_type`, **not** a nested `rect`/`type`):

```json
{
  "packet_id": "pkt_1",
  "status": "sent",
  "owner_user_id": "usr_1",
  "source_path": "/files/contract.pdf",
  "role": "signer",
  "signer_status": "pending",
  "signers": [{"signer_id": "sgr_1", "status": "pending"}],
  "fields": [
    {"field_id": "fld_1", "field_type": "signature", "page": 0,
     "x": 0.1, "y": 0.8, "width": 0.3, "height": 0.1, "required": true}
  ],
  "capabilities": {"can_edit_fields": false, "can_send": false, "can_fill_fields": true},
  "legal_notice": {"required": true, "accepted": false, "version": "2025-01", "text": "..."}
}
```

`status` is one of `draft | sent | partially_signed | completed | cancelled |
expired` (web `SignaturePacketStatus`), **not** `pending` — `pending` is only a
per-signer/per-field status. Enum-decode tests must use the real packet-status set.

Header/CSRF behaviour under test (verified in `frontend/src/api/client.ts`):
the `X-CSRF-Token` header is set from the `ui_csrf` cookie on **every** request
(GET and mutating), not only mutations; `Authorization: Bearer <token>` is added
from the auth store; requests run with cookies (`credentials: include`). A `401`
triggers **at most one** `POST /ui/session/refresh` **only if the user is already
authenticated** (an unauthenticated 401 propagates straight through), then the
original request is retried once; a second 401 on the retry logs the user out
rather than looping. Concurrent 401s share a single in-flight refresh promise.
`SigningApiTest` enqueues `401` then `200` and asserts the recorded sequence
(`<packet req>`, `session/refresh`, `<packet req>`) with exactly one refresh, and
a separate test enqueues `401`,`401` and asserts an auth error (no loop).
Error-detail mapping (verified in `normalizeErrorDetail`) is asserted for the
three shapes the client actually handles: `"detail": "msg"` (string),
`"detail": [{"msg": ...}]` (FastAPI `HTTPValidationError`/`ValidationError`
array — the real 422 shape), and `"detail": {"code": ...}` (authorization-error
object, e.g. `role_required`).

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
- **RESOLVED (review 2026-06-06):** there is no "submit endpoint" and no image
  upload. Signatures are submitted as **JSON** via
  `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill` with
  `SignaturePacketFieldFillIn` = `{value?, input_mode: "typed"|"drawn",
  drawn_strokes: number[][], notary_stamp?}` — i.e. vector stroke arrays, **not**
  multipart and **not** a base64 bitmap. Completion is `POST .../send`
  (sender) / `POST .../mark-done` (signer). `SigningApiTest` asserts this JSON body
  shape and that no multipart/`Content-Type: multipart/*` request is ever issued.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and an exact source pointer.
OpenAPI pointers are `METHOD /path` and/or `components.schemas.<Name>` from
`reference/openapi.index.txt` / `reference/openapi.pretty.json`. Frontend pointers
are `reference/src/...`. Framework choices are labelled `framework ref`.

1. **Create-packet endpoint is `POST /v1/signature-packets` (`CreateSignaturePacketIn`
   → `CreateSignaturePacketOut`).** VERDICT: Corrected (draft had
   `GET /ui/signing/packets`). SOURCE: OpenAPI `POST /v1/signature-packets`;
   `src/api/endpoints/signaturePackets.ts: createSignaturePacket`.
2. **Packet detail is `GET /v1/signature-packets/{packet_id}` →
   `SignaturePacketDetailOut`.** VERDICT: Corrected (draft had
   `GET /ui/signing/packets/{packetId}`). SOURCE: OpenAPI
   `GET /v1/signature-packets/{packet_id}`; `components.schemas.SignaturePacketDetailOut`;
   `src/api/endpoints/signaturePackets.ts: getSignaturePacketDetail`.
3. **There is no packet-list endpoint and no list response array.** VERDICT:
   Corrected (draft asserted `GET /ui/signing/packets → 200 [SignaturePacketDto…]`).
   SOURCE: absence in `reference/openapi.index.txt` (only create + `{packet_id}`
   sub-resources exist); `src/pages/signing/SigningPage.tsx` renders no list.
4. **There is no `/submit` endpoint and no `{receipt_id,status:"submitted"}`
   response.** VERDICT: Corrected. Completion = `POST .../send` and/or
   `POST .../mark-done`. SOURCE: OpenAPI `POST /v1/signature-packets/{packet_id}/send`
   (`SendSignaturePacketOut`), `POST /v1/signature-packets/{packet_id}/mark-done`
   (`SignaturePacketMarkDoneOut`); `src/api/endpoints/signaturePackets.ts:
   sendSignaturePacket, markSignaturePacketDone`.
5. **Signature submission is JSON field-fill, not multipart/base64.**
   `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill` with
   `{value?, input_mode, drawn_strokes: number[][], notary_stamp?}`. VERDICT:
   Corrected/Resolved (§13 open question). SOURCE:
   `components.schemas.SignaturePacketFieldFillIn`; `src/api/endpoints/
   signaturePackets.ts: fillSignaturePacketField`.
6. **Field geometry is flat `x/y/width/height` + `field_type`, not a nested
   `rect{x,y,w,h}` + `type`.** VERDICT: Corrected. SOURCE:
   `src/api/endpoints/signaturePackets.ts: SignaturePacketField` (lines 23-38);
   `SignaturePacketDetailOut.fields` (free-form objects) in OpenAPI.
7. **Packet status enum is `draft|sent|partially_signed|completed|cancelled|
   expired`; `pending` is per-signer/per-field only.** VERDICT: Corrected (draft
   used `pending` as packet status). SOURCE:
   `src/api/endpoints/signaturePackets.ts: SignaturePacketStatus` (lines 7-13) and
   `SignaturePacketSigner.status`.
8. **Packet has no `document_url`; the PDF is `GET /v1/signature-packets/
   {packet_id}/final-pdf` (bytes).** VERDICT: Corrected. SOURCE: OpenAPI
   `GET /v1/signature-packets/{packet_id}/final-pdf`; `src/api/endpoints/
   signaturePackets.ts: downloadSignaturePacketFinalPdf`.
9. **License agreements list is `GET /ui/licenses/agreements →
   LicenseAgreementListOut`, not `/ui/license-agreements`.** VERDICT: Corrected.
   SOURCE: OpenAPI `GET /ui/licenses/agreements`; `src/api/endpoints/
   licenseAgreements.ts` (lines 40-52).
10. **Templates list is `GET /ui/signing/templates → SignatureTemplateListOut`.**
    VERDICT: Verified (the one path the draft got right). SOURCE: OpenAPI
    `GET /ui/signing/templates`; `src/api/endpoints/signatureTemplates.ts`.
11. **CSRF: `X-CSRF-Token` is set from the `ui_csrf` cookie on every request (not
    only mutations).** VERDICT: Corrected (draft implied only "echoed" / on
    mutating requests). SOURCE: `src/api/client.ts` lines 167-171.
12. **401 handling: single `POST /ui/session/refresh` then one retry, only if the
    user is already authenticated; concurrent 401s share one refresh promise; a
    second 401 logs out (no loop).** VERDICT: Verified (with nuance added). SOURCE:
    `src/api/client.ts` `refreshSession` + 401 block (lines 119-237).
13. **Error `detail` has three handled shapes: string, ValidationError array
    `[{loc,msg,type}]` (real 422 = `HTTPValidationError`), and `{code,...}` object
    (auth errors).** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` + `mapAuthorizationError`;
    `components.schemas.HTTPValidationError` / `ValidationError`.
14. **Auth transport is `Authorization: Bearer <token>` plus cookies
    (`credentials: include`); optional `X-IMPERSONATION-TOKEN`.** VERDICT: Verified.
    SOURCE: `src/api/client.ts` lines 156-184; `params=...X-IMPERSONATION-TOKEN` in
    OpenAPI index entries.
15. **Field mutation endpoint `POST .../fields` uses `action: create|update|delete`
    (`SignaturePacketFieldMutationIn`).** VERDICT: Verified. SOURCE:
    `components.schemas.SignaturePacketFieldMutationIn`; `src/api/endpoints/
    signaturePackets.ts: createSignaturePacketField / deleteSignaturePacketField`.
16. **Robolectric Compose tests with `@Config(sdk=[34])` and instrumented-only
    PdfRenderer.** VERDICT: Unverified-assumption re: Robolectric's PdfRenderer
    shadow fidelity (genuinely unreliable). Framework basis is sound. SOURCE:
    framework ref — Robolectric docs (robolectric.org) and
    developer.android.com/jetpack/compose/testing; PdfRenderer instrumented-only is
    a known limitation, treated as an assumption pending the AND-341 spike.
17. **Test execution targets (JVM/Robolectric local; emulator AVD `test35` API 35
    x86_64; physical Samsung A15 5G API 34 arm64 for device PdfRenderer).** VERDICT:
    Unverified-assumption (CI matrix capability, not derivable from sources).
    SOURCE: provided CI/dev target list; framework ref
    developer.android.com/studio/test for `connectedAndroidTest`.

### Corrections made

- §2: fixed web-reference pointers; noted no packet-list screen; noted signing API
  is `/v1/signature-packets/*`.
- §3 FR-2: clarified `POST /ui/session/refresh`, authenticated-only refresh, and the
  three real `detail` shapes. FR-4: removed "packet list rendering" as a required
  screen (no server list / no web screen) and reframed completion as `send`/`mark-done`.
- §4: corrected `SigningFixtures` (dropped `PACKET_LIST_JSON`, real status enum, flat
  field geometry) and `FakeSigningRepository` (dropped `submitSigned`/`SubmitReceipt`/
  global `observePackets`; added `fillField`/`send`/`markDone`).
- §5: replaced the entire endpoint list, fixture JSON, status enum, and submit/CSRF
  narrative with the verified contract; corrected `/ui/license-agreements` →
  `/ui/licenses/agreements`.
- §13: resolved the multipart-vs-base64 open question (JSON `drawn_strokes`).

### Open assumptions

- **Android packet-list screen (AND-340):** if it exists, it must be a local
  (Room-backed) Android affordance — the backend has no list endpoint. Cannot be
  verified from sources; confirm with the AND-340 owner. Affects FR-4 and the §6/§11
  `observePackets` caching claims.
- **`SignUiState` sealed hierarchy / intent names (AND-344):** the exact subtypes
  (`Ready/Capturing/Placed/Submitting/Confirmed/Error`) are assumed from the draft;
  not present in the reference sources (web ViewModel ≠ Android ViewModel). Confirm
  against AND-344's merged code.
- **Analytics events (`signing_packet_opened`, `signing_submitted`) and the OkHttp
  redaction interceptor:** not present in the backend/web sources; assumed from
  AND-340/343. Ship behind `@Ignore("AND-343")` if unwired.
- **Coverage tooling/threshold (JaCoCo ≥85%) and CI 3-run determinism:** process
  assumptions, not verifiable from API/frontend sources.
- **Robolectric PdfRenderer fidelity / CI device matrix:** see citations 16-17.

## 17. Test Plan

Acceptance-criterion traces refer to §14 (AC-1…AC-8). "MWS" = MockWebServer.
Test targets: JVM/Robolectric run locally or on the headless emulator AVD
`test35` (API 35); instrumented PdfRenderer cases note where the **physical
Samsung Galaxy A15 5G (API 34, arm64)** is required vs the emulator.

- **TC-AND-345-01 — DTO round-trip + enum/optional decode (happy path).**
  Type: unit (JVM). Target: `SigningDtoJsonTest`, `SigningMappersTest` (JVM local).
  Preconditions: `SigningFixtures.PACKET_DETAIL_JSON` matching
  `SignaturePacketDetailOut`. Steps: Moshi-decode the JSON to the DTO and back;
  decode `status` to the packet-status enum; decode a field with flat
  `x/y/width/height`+`field_type`; omit optional `legal_notice`/`signer_status`.
  Expected: round-trips byte-stable; `status` ∈ {draft,sent,partially_signed,
  completed,cancelled,expired}; unknown enum value maps to a safe `Unknown`, not a
  crash; absent optionals decode to null/defaults; DTO→domain mapping preserves
  geometry. Traces: AC-3.

- **TC-AND-345-02 — Detail GET request shape + CSRF/auth headers (contract).**
  Type: contract/MWS (JVM). Target: `SigningApiTest` (JVM local). Preconditions:
  MWS enqueues `200 SignaturePacketDetailOut`; `ui_csrf` cookie + bearer token in
  test DI. Steps: call `getPacket("pkt_1")`; inspect the recorded request.
  Expected: `GET /v1/signature-packets/pkt_1`; headers include
  `X-CSRF-Token: <cookie>` and `Authorization: Bearer <token>`; body parses to the
  domain packet. Traces: AC-2, AC-3, AC-7.

- **TC-AND-345-03 — Field-fill submits JSON drawn_strokes, never multipart
  (contract + security).** Type: contract/MWS (JVM). Target: `SigningApiTest`
  (JVM local). Preconditions: MWS enqueues `200 SignaturePacketFieldFillOut`.
  Steps: call `fillField(pkt,fld, FieldFill(inputMode="drawn",
  drawnStrokes=[[...]]))`; inspect recorded request. Expected: `POST
  /v1/signature-packets/pkt/fields/fld/fill`; `Content-Type: application/json`;
  body has `input_mode:"drawn"`, `drawn_strokes:[[...]]`; **no** `multipart/*`
  content type and no base64 bitmap key; `X-CSRF-Token` present (CSRF guard).
  Traces: AC-2, AC-4 (error-mapping sibling), AC-7; security §8.

- **TC-AND-345-04 — Single refresh-on-401 then retry succeeds (happy auth path).**
  Type: contract/MWS (JVM). Target: `SigningApiTest` (JVM local). Preconditions:
  authenticated session; MWS enqueues `401`, then `200` for the refreshed retry,
  with a `200` for `POST /ui/session/refresh`. Steps: call `getPacket`; capture the
  recorded request sequence. Expected: exactly three requests in order
  (`GET .../pkt`, `POST /ui/session/refresh`, `GET .../pkt`); result is Success;
  refresh invoked once. Traces: AC-4.

- **TC-AND-345-05 — Two consecutive 401s surface auth error, no loop (security/
  resilience).** Type: contract/MWS (JVM). Target: `SigningApiTest` (JVM local).
  Preconditions: authenticated; MWS enqueues `401`, refresh `200`, then `401`
  again. Steps: call `getPacket`. Expected: result is `ApiResult.Failure(Auth)`;
  refresh attempted once; no infinite retry; logout/session-expired signalled.
  Also assert an **unauthenticated** 401 propagates without any refresh attempt.
  Traces: AC-4, AC-7; security §8.

- **TC-AND-345-06 — Three FastAPI `detail` error shapes map correctly (validation/
  error responses).** Type: unit/contract (JVM). Target: `SigningApiTest` error
  mapper (JVM local). Preconditions: MWS enqueues, across three runs:
  `{"detail":"msg"}` (400), `{"detail":[{"loc":["body","value"],"msg":"field
  required","type":"value_error"}]}` (422), `{"detail":{"code":"role_required"}}`
  (403). Steps: call an API per shape. Expected: messages map to "msg", the joined
  validation msg, and the humanized role-required string respectively; never a
  crash; user-facing message non-empty. Traces: AC-4.

- **TC-AND-345-07 — Repository cache read-through + stale-on-failed-refresh +
  offline fallback (integration).** Type: integration (JVM + in-memory Room).
  Target: `SigningRepositoryTest`, `SigningRepositoryRefreshTest` (JVM local).
  Preconditions: in-memory Room DB; MWS. Steps: (a) detail fetch `200` upserts row
  and emits cached packet; (b) refresh fails (`500`) → prior cached row retained
  (stale-but-usable); (c) detail fetch with network `IOException` and warm cache →
  returns cached packet flagged stale. Expected: each assertion holds; no row loss
  on failure; `ApiResult` reflects stale source. Traces: AC-4, AC-7.

- **TC-AND-345-08 — Timeout yields retryable failure, submit never auto-retried
  (resilience).** Type: integration (JVM + MWS). Target: `SigningRepositoryTest`
  (JVM local, short injected OkHttp timeout). Preconditions: MWS dispatcher with
  `SocketPolicy.NO_RESPONSE`. Steps: (a) GET detail under NO_RESPONSE →
  `ApiResult.Failure(Timeout)`; (b) `POST .../fields/{id}/fill` or `.../send`
  returns `503`/timeout. Expected: GET surfaces a retryable error (no crash);
  mutating POST is **not** auto-retried (recorded exactly once). Traces: AC-4, AC-7.

- **TC-AND-345-09 — Malformed/missing-required JSON → non-crashing parse error
  (validation).** Type: unit/contract (JVM). Target: `SigningDtoJsonTest` /
  `SigningApiTest` (JVM local). Preconditions: MWS enqueues a body missing the
  required `packet_id`/`capabilities`. Steps: call `getPacket`. Expected:
  `ApiResult.Failure(Parse)`; ViewModel maps to an error state with a non-empty
  user-facing message; no exception escapes. Traces: AC-4, AC-5, AC-7.

- **TC-AND-345-10 — ViewModel state machine: fill → send/mark-done → Confirmed,
  plus optimistic rollback (state coverage).** Type: unit (JVM + Turbine + virtual
  time). Target: `SignViewModelTest` (JVM local). Preconditions:
  `FakeSigningRepository`; `MainDispatcherRule(StandardTestDispatcher())`. Steps:
  drive `onCapture/onPlace/onSubmit`; in a second case set `markDoneResult =
  Failure`. Expected: emissions `Ready → Submitting → Confirmed` on success; on
  failure `Ready → Submitting → Error(retryable)` with optimistic state rolled back
  to `Ready`; every `SignUiState` subtype exercised. Traces: AC-5.

- **TC-AND-345-11 — Normalized placement math clamps to 0..1, page-relative
  (unit).** Type: unit (JVM). Target: `SignViewModelTest`/placement util (JVM
  local). Preconditions: none. Steps: feed out-of-range and in-range placement
  coords for given page. Expected: x/y/width/height clamped to [0,1]; coordinates
  resolve page-relative; produces a valid `fill`/field-mutation payload. Traces:
  AC-5.

- **TC-AND-345-12 — Packet detail + signature capture/adopt/placement renders
  (Compose-UI).** Type: Compose-UI (Robolectric `@Config(sdk=[34])`). Target:
  `PacketDetailScreenTest`, `SignatureCaptureScreenTest` (JVM/Robolectric or
  emulator `test35`). Preconditions: `FakeSigningRepository` / fixed `UiState`.
  Steps: open detail (assert status text); draw on the capture canvas, tap
  "Adopt", place onto a field; assert empty + error states render. Expected: nodes
  present via `onNodeWithTag`/`onNodeWithText`; capture→adopt→place transitions the
  UI; error/empty states show their semantics. Traces: AC-6.

- **TC-AND-345-13 — Accessibility: content-descriptions, string resources, 48dp
  touch targets (a11y).** Type: Compose-UI (Robolectric). Target:
  `SignatureCaptureScreenTest` (JVM/Robolectric or emulator `test35`).
  Preconditions: capture screen rendered. Steps: assert the canvas has a
  `contentDescription`; "Adopt"/"Clear"/"Submit" resolved via
  `context.getString(R.string.*)` (no hard-coded literals); placed fields are
  focusable + labelled; `assertWidthIsAtLeast(48.dp)`/`assertHeightIsAtLeast(48.dp)`
  on interactive nodes. Expected: all assertions pass. Traces: AC-6 (§9).

- **TC-AND-345-14 — Multi-page PDF renders + scrolls from real PdfRenderer
  (instrumented/e2e).** Type: instrumented (`androidTest`,
  `createAndroidComposeRule`). Target: `PdfDocumentScreenTest`. **MUST run on the
  physical Samsung Galaxy A15 5G (API 34, arm64-v8a)** because Robolectric does not
  faithfully shadow `android.graphics.pdf.PdfRenderer` and arm64/API-34 rendering
  differs from x86 API-35; the emulator `test35` is the fallback only if the device
  is unavailable. Preconditions: `SigningFixtures.samplePdfBytes(pages = 2)` (or
  bytes from `/final-pdf` via MWS on-device). Steps: render the document screen;
  assert page 1 visible; scroll; assert page 2 visible. Expected: both pages render
  via real PdfRenderer; scroll reveals page 2; page count = 2. Traces: AC-6.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (tests exist/compile, JDK17/AGP) | all TCs (compiled in CI) |
| AC-2 (suite passes, zero failures) | TC-02, TC-03, TC-04 (and full green run) |
| AC-3 (DTO round-trip/null/enum for packets + templates) | TC-01, TC-02 |
| AC-4 (cache, stale, offline, single-refresh-401, 3 detail mappings) | TC-04, TC-05, TC-06, TC-07, TC-08, TC-09 |
| AC-5 (every SignUiState + transitions, submit/error/rollback) | TC-09, TC-10, TC-11 |
| AC-6 (list*/detail/capture/placement/submit + instrumented PDF) | TC-12, TC-13, TC-14 |
| AC-7 (hermetic, deterministic, CI-runnable) | TC-02, TC-05, TC-07, TC-08, TC-09 |
| AC-8 (no prod source modified) | enforced by review; no test asserts prod edits |

\*Packet-list rendering is descoped pending the §16 Open assumption (no server list
endpoint / no web list screen); if AND-340 shipped a local list, add a Robolectric
case mirroring TC-12 against `FakeSigningRepository`.
