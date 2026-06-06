---
id: AND-344
title: Signing ViewModels
milestone: M7
epic: E44
priority: P1
size: L
status: draft
depends_on: [AND-339]
blocks: [AND-345]
---

# AND-344 — Signing ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-logic layer for the e-signature ("signing") feature: the
Jetpack Compose `ViewModel`s and their `UiState` state machines that drive packet browsing, packet
detail, document/PDF viewing, signature capture and field placement, and final submission. The
scope, per the backlog, is *"State machine"* with acceptance *"Unit-tested"* — therefore the
deliverable is **the orchestration layer only**, not new Composable screens (those belong to
AND-340/341/342/343) and not the API/DTO layer (AND-339).

The goal is a deterministic, side-effect-free-where-possible set of ViewModels that:

- consume the typed `ApiResult<T>` repository methods established by AND-339,
- model the multi-step signing journey as an explicit, testable state machine,
- expose immutable `StateFlow<UiState>` to the UI, and
- be fully exercised by JVM unit tests with a fake repository (no Android instrumentation).

Success means: every state transition in the signing flow is reachable and observable in a unit
test; the UI layer (sibling tickets) can bind to these ViewModels without any business logic of its
own; and the signing repository contract from AND-339 is the only collaborator.

## 2. Context & References

- **Epic E44 (Signing), Milestone M7.** Sibling tickets:
  - AND-339 — Signing API + DTOs (`signaturePackets.ts`, `signatureTemplates.ts` parity). **This
    ticket's only hard dependency.** Provides `SigningRepository`, DTOs, and domain models.
  - AND-340 — Packet list + detail screens (consumes `PacketListViewModel`, `PacketDetailViewModel`).
  - AND-341 — PDF rendering (consumes `DocumentViewerViewModel`).
  - AND-342 — Signature capture + placement (consumes `SignatureEditorViewModel`).
  - AND-343 — Submit / sign + licenses (consumes `SignSubmitViewModel`; adds `licenseAgreements.ts`).
  - AND-345 — Signing tests (repo + UI tests); builds on the unit tests delivered here.
- **Module placement:** `feature-signing` (Gradle module `:feature:signing`), namespace
  `com.testlogon.android.feature.signing`. Depends on `:core:model`, `:core:data`, `:core:network`,
  `:core:ui`, `:core:testing`.
- **Architecture conventions (project-wide):** ViewModels expose `StateFlow<UiState>`; data flows
  through `ApiResult<T>`; FastAPI error `detail` is mapped (string | `[{msg}]` | `{code,...}`) by
  `core-network` and surfaced as a typed `AppError`. Cookie-based session + `X-CSRF-Token`, single
  silent `POST /ui/session/refresh` on 401, persistent cookie jar — all handled below this layer by
  the OkHttp interceptor stack from `core-network`; ViewModels never touch cookies.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (plaintext, unreliable):
  ~20s timeouts, bounded backoff retry for idempotent GETs only, offline/stale UI states required.
  OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/signaturePackets.ts`,
  `signatureTemplates.ts`, `licenseAgreements.ts`; shared types `frontend/src/api/types.ts`.

## 3. Functional Requirements

FR-1 — **Packet list.** `PacketListViewModel` loads the signer's assigned packets via the
repository, supports pull-to-refresh, and exposes loading / content / empty / error states. The list
is filterable by status (`PENDING`, `IN_PROGRESS`, `COMPLETED`, `DECLINED`, `EXPIRED`). Filtering is
a pure in-memory transform of the last successful load (no refetch).

FR-2 — **Packet detail.** `PacketDetailViewModel` loads one packet (`packetId`) and its documents,
recipients, and per-document signing status. Exposes a derived flag `canSign` (true iff the packet is
actionable by the current user and not terminal).

FR-3 — **Document viewing handoff.** `DocumentViewerViewModel` resolves a downloadable document URL
/ bytes reference for a `documentId` so AND-341's renderer can page through it. This ViewModel owns
loading/error state for the *fetch of the document descriptor*, not the rendering itself.

FR-4 — **Signature editor state machine.** `SignatureEditorViewModel` models capture (draw or adopt
a saved signature), and placement of one or more signature/initial/date fields onto document
coordinates. It tracks a working set of `PlacedField` objects, supports add/move/remove, and computes
a `isComplete` flag when all *required* fields for the current recipient are placed and have content.

FR-5 — **Submission state machine.** `SignSubmitViewModel` validates that all required fields are
satisfied, accepts required license agreement(s) (from AND-343's `licenseAgreements.ts`), then
submits the signed packet and surfaces a confirmation or a typed failure. Submission is a one-shot,
non-idempotent action: it must guard against double-submit and must **not** be auto-retried.

FR-6 — **Single source of truth.** Every ViewModel exposes exactly one `StateFlow<…UiState>`.
One-shot effects (navigation, snackbars) are exposed via a separate `Channel`/`SharedFlow` of
`…Effect` to avoid re-emitting on configuration change.

FR-7 — **No UI, no Android framework deps in logic.** All transition logic is expressed in
pure Kotlin functions or in coroutines over the repository so it is unit-testable on the JVM.

## 4. Technical Design

### 4.1 Module & files

```
feature/signing/src/main/kotlin/com/testlogon/android/feature/signing/
  packetlist/PacketListViewModel.kt
  packetlist/PacketListUiState.kt
  detail/PacketDetailViewModel.kt
  detail/PacketDetailUiState.kt
  viewer/DocumentViewerViewModel.kt
  editor/SignatureEditorViewModel.kt
  editor/SigningEditorState.kt        // shared sealed state machine
  submit/SignSubmitViewModel.kt
  model/PlacedField.kt
  model/SigningEffect.kt
```

### 4.2 UiState definitions

A shared envelope is used so list-bearing screens distinguish empty vs. stale-with-error:

```kotlin
sealed interface PacketListUiState {
    data object Loading : PacketListUiState
    data class Content(
        val packets: List<SignaturePacket>,   // domain model from AND-339
        val filter: PacketStatusFilter,
        val isRefreshing: Boolean = false,
        val staleError: AppError? = null,      // last refresh failed but cache shown
    ) : PacketListUiState
    data object Empty : PacketListUiState
    data class Error(val error: AppError) : PacketListUiState
}

enum class PacketStatusFilter { ALL, PENDING, IN_PROGRESS, COMPLETED, DECLINED, EXPIRED }
```

```kotlin
sealed interface PacketDetailUiState {
    data object Loading : PacketDetailUiState
    data class Content(
        val packet: SignaturePacket,
        val documents: List<SignatureDocument>,
        val recipient: SignatureRecipient,
        val canSign: Boolean,
    ) : PacketDetailUiState
    data class Error(val error: AppError) : PacketDetailUiState
}
```

### 4.3 The editor state machine

The signing-editor flow is the core "state machine" called out by the ticket. It is modeled
explicitly so AND-345 can assert each edge:

```kotlin
sealed interface SigningEditorState {
    data object Loading : SigningEditorState
    data class Capturing(                       // drawing or choosing a signature
        val mode: CaptureMode,                  // DRAW | ADOPT_SAVED | TYPE
        val savedSignature: SavedSignature?,    // from prefs/DataStore, may be null
    ) : SigningEditorState
    data class Placing(                          // dropping fields onto pages
        val signature: CapturedSignature,
        val placed: List<PlacedField>,
        val activeFieldId: String?,
        val isComplete: Boolean,                // all required fields satisfied
    ) : SigningEditorState
    data class ReadyToSubmit(
        val signature: CapturedSignature,
        val placed: List<PlacedField>,
    ) : SigningEditorState
    data class Error(val error: AppError) : SigningEditorState
}

enum class CaptureMode { DRAW, ADOPT_SAVED, TYPE }
```

Legal transitions (enforced in the ViewModel, asserted in tests):

```
Loading ──load ok──> Capturing
Loading ──load err─> Error
Capturing ──onSignatureCaptured──> Placing
Placing ──onFieldPlaced/Moved/Removed──> Placing (recompute isComplete)
Placing ──onContinue (only if isComplete)──> ReadyToSubmit
ReadyToSubmit ──onEditAgain──> Placing
Error ──onRetry──> Loading
```

`PlacedField` is the unit of placement:

```kotlin
data class PlacedField(
    val id: String,                 // template field id or generated for ad-hoc
    val documentId: String,
    val pageIndex: Int,
    val type: FieldType,            // SIGNATURE | INITIALS | DATE | TEXT
    val required: Boolean,
    val normRect: NormRect,         // 0f..1f page-relative rect, renderer-agnostic
    val value: String?,             // text/date content; signature carries bitmap ref
)

data class NormRect(val x: Float, val y: Float, val w: Float, val h: Float)
```

`isComplete = placed.filter { it.required }.all { it.hasContent() } &&
 requiredFieldIds.all { id -> placed.any { it.id == id } }`. Page-relative `NormRect`
keeps the logic independent of AND-341's pixel renderer (unit-testable on JVM).

### 4.4 ViewModel skeletons

```kotlin
@HiltViewModel
class SignatureEditorViewModel @Inject constructor(
    private val repo: SigningRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val packetId: String = checkNotNull(savedStateHandle["packetId"])
    private val recipientId: String = checkNotNull(savedStateHandle["recipientId"])

    private val _state = MutableStateFlow<SigningEditorState>(SigningEditorState.Loading)
    val state: StateFlow<SigningEditorState> = _state.asStateFlow()

    private val _effects = Channel<SigningEffect>(Channel.BUFFERED)
    val effects: Flow<SigningEffect> = _effects.receiveAsFlow()

    fun onSignatureCaptured(sig: CapturedSignature) { /* Capturing -> Placing */ }
    fun onFieldPlaced(field: PlacedField) { /* recompute isComplete */ }
    fun onFieldMoved(id: String, rect: NormRect) { … }
    fun onFieldRemoved(id: String) { … }
    fun onContinue() { /* guard isComplete -> ReadyToSubmit */ }
    fun onRetry() { … }
}
```

`SignSubmitViewModel` mirrors this with a `Submitting`/`Submitted`/`SubmitError` tail and a
`submitGuard: Boolean` so repeated `onSubmit()` calls during an in-flight request are ignored.

### 4.5 Dispatchers & coroutines

All repository calls run in `viewModelScope` on an injected `@IoDispatcher CoroutineDispatcher`
(provided by `core-data`) so tests inject `StandardTestDispatcher`/`UnconfinedTestDispatcher`.
No `Dispatchers.Main`/`IO` is referenced directly.

## 5. API Contract

This ticket **calls** the signing repository defined by AND-339 and does not define HTTP endpoints
itself; the wire contract is owned by AND-339. The repository surface consumed here (for reference,
mapping the web `signaturePackets.ts` / `signatureTemplates.ts`) is:

```kotlin
interface SigningRepository {
    suspend fun listPackets(): ApiResult<List<SignaturePacket>>
    suspend fun getPacket(packetId: String): ApiResult<SignaturePacketDetail>
    suspend fun getDocument(documentId: String): ApiResult<SignatureDocumentRef>
    suspend fun getTemplateFields(packetId: String, recipientId: String): ApiResult<List<TemplateField>>
    suspend fun submitSignedPacket(req: SubmitSignatureRequest): ApiResult<SignatureSubmitResult>
}
```

These map to backend routes (authoritative shapes in `/openapi.json`; mirrored from `frontend/`):

- `GET /ui/signing/packets` → `[SignaturePacket]`
- `GET /ui/signing/packets/{packetId}` → `SignaturePacketDetail`
- `GET /ui/signing/documents/{documentId}` → document descriptor (download URL + page count)
- `GET /ui/signing/packets/{packetId}/recipients/{recipientId}/fields` → `[TemplateField]`
- `POST /ui/signing/packets/{packetId}/sign` → `SignatureSubmitResult`

Representative submit request body assembled by `SignSubmitViewModel`:

```json
{
  "recipient_id": "rec_123",
  "fields": [
    { "field_id": "f_sig_1", "document_id": "doc_1", "page_index": 0,
      "rect": { "x": 0.62, "y": 0.81, "w": 0.20, "h": 0.06 },
      "type": "SIGNATURE", "signature_id": "sig_abc" },
    { "field_id": "f_date_1", "document_id": "doc_1", "page_index": 0,
      "rect": { "x": 0.62, "y": 0.88, "w": 0.15, "h": 0.04 },
      "type": "DATE", "value": "2026-06-05" }
  ],
  "accepted_license_ids": ["lic_eula_v3"]
}
```

Representative success response:

```json
{ "packet_id": "pkt_9", "status": "COMPLETED", "completed_at": "2026-06-05T17:22:09Z",
  "certificate_url": "/ui/signing/packets/pkt_9/certificate" }
```

All requests ride cookies + `X-CSRF-Token` and the 401→`refresh`→retry behavior transparently via
`core-network`. The submit `POST` is non-idempotent and is **excluded** from any GET-only retry
policy.

## 6. Data & State Management

- **State holder:** `MutableStateFlow` per ViewModel, exposed read-only as `StateFlow`. Effects via
  `Channel(Channel.BUFFERED)` → `receiveAsFlow()`.
- **Process death:** `packetId`, `recipientId`, and the active filter persist via `SavedStateHandle`.
  The in-progress `placed` field set is also serialized to `SavedStateHandle` (it is plain data;
  signature bitmaps are referenced by id, not embedded) so an editing session survives recreation.
- **Caching / stale data:** the list ViewModel keeps the last successful `List<SignaturePacket>`;
  a failed refresh transitions to `Content(staleError = …)` rather than discarding data, satisfying
  the "offline/stale UI states" requirement. `core-data` may back this with Room; this layer only
  observes the repository result.
- **Filtering** is a pure function `fun List<SignaturePacket>.applyFilter(f): List<SignaturePacket>`
  in the `packetlist` package, separately unit-tested.
- **Derived state** (`canSign`, `isComplete`) is computed in the ViewModel from inputs only — never
  stored as independent mutable truth — to keep transitions deterministic.

## 7. Error Handling & Resilience

- All repository results are `ApiResult<T>` = `Success | Failure(AppError)`. ViewModels translate
  `Failure` into the relevant `…UiState.Error` / `staleError` and an optional `SigningEffect.ShowError`.
- `AppError` taxonomy (from `core-network`): `Network` (timeout/offline), `Http(code, detail)`,
  `Unauthorized` (after refresh failed), `Validation(messages)`, `Unknown`.
- **GET screens** (list, detail, document descriptor, fields) expose `onRetry()`; the underlying
  bounded-backoff retry for idempotent GETs lives in `core-network`, so the ViewModel simply
  re-invokes the suspend call.
- **Submit** maps `Validation` to inline field errors via `SignSubmitUiState.SubmitError(validation)`
  and **never** auto-retries; the user must explicitly re-tap, and `submitGuard` prevents concurrent
  submits.
- Timeouts (~20s) are an OkHttp concern; the ViewModel treats them as `AppError.Network` and shows a
  retryable error. No infinite spinners: every `Loading` has a terminal transition.

## 8. Security & Privacy

- ViewModels hold no credentials, cookies, or CSRF tokens; the session is entirely managed by the
  `core-network` cookie jar + interceptor. This layer must not log packet contents, signature
  bitmaps, or PII.
- Captured signature bitmaps are referenced by id (`signature_id` / `SavedSignature`); raw bitmap
  bytes are never placed in `SavedStateHandle` or in `UiState` (only an opaque reference), limiting
  exposure on process-death serialization and in logs.
- License acceptance ids are sent only on explicit user action; `accepted_license_ids` is built from
  user-toggled state, never defaulted to accepted.
- No new permissions. Document/PDF byte handling and any file caching are owned by AND-341; this
  ticket passes through descriptors only.

## 9. Accessibility & i18n

- This is a non-UI logic ticket, so it renders nothing. Two obligations apply:
  - **String externalization:** any user-facing text the ViewModel selects (e.g. mapping an
    `AppError` to a message key) must reference `core-ui` string resource ids, not literals — so the
    consuming screens (AND-340/341/342/343) localize correctly.
  - **Semantic state:** `UiState` must carry enough structure (distinct `Empty` vs `Error` vs
    `Content`) for the UI to announce status changes via Compose semantics. Status enums are
    machine-readable; their display strings live in resources.
- Date field values (`DATE` type) are serialized in ISO-8601 (`YYYY-MM-DD`) regardless of locale;
  locale-formatted display is the UI's responsibility.

## 10. Telemetry & Logging

- Inject the project `Analytics` abstraction (from `core-data`) and emit structured, **PII-free**
  events at each major transition:
  - `signing_packet_list_loaded` (count, hadError)
  - `signing_packet_opened` (packetId-hash, status)
  - `signing_editor_state_changed` (from, to) — drives funnel analysis
  - `signing_submit_attempted` / `signing_submit_succeeded` / `signing_submit_failed` (errorType)
- Use `Timber` at `d`/`w` only; never log signature bitmaps, field values, names, or raw `detail`
  bodies. Error logs carry the `AppError` type and HTTP code, not response payloads.
- Identifiers in analytics are hashed/opaque, consistent with project telemetry conventions.

## 11. Testing Strategy

Acceptance is *"Unit-tested"*; this is the heart of the ticket. All tests are JVM unit tests under
`feature/signing/src/test/…`, using `core-testing`, `kotlinx-coroutines-test`
(`runTest`, `TestDispatcher`), Turbine for `StateFlow`/`Flow` assertions, and a hand-written
`FakeSigningRepository` (no MockK requirement, though MockK is available).

Required coverage:

1. **PacketListViewModel:** Loading→Content; Loading→Empty (empty list); Loading→Error;
   refresh success updates content; refresh failure → `Content(staleError)` (cache retained);
   each `PacketStatusFilter` yields the correct subset (pure-function test).
2. **PacketDetailViewModel:** load success computes `canSign` correctly for actionable vs terminal
   vs not-this-recipient packets; load failure → Error; retry re-loads.
3. **DocumentViewerViewModel:** descriptor success/failure; retry.
4. **SignatureEditorViewModel (state machine):** assert **every legal edge** in §4.3 and assert
   illegal edges are no-ops (e.g. `onContinue()` while `isComplete == false` does not leave
   `Placing`); `isComplete` recomputation on place/move/remove; required-vs-optional field logic.
5. **SignSubmitViewModel:** happy-path submit → `Submitted`; validation failure → `SubmitError`
   with messages; network failure → retryable error; **double-submit guard** (second `onSubmit()`
   during in-flight is ignored — assert repository `submitSignedPacket` invoked exactly once);
   submit is never auto-retried.
6. **Effects:** one-shot `SigningEffect`s are emitted once and not replayed after a simulated
   recreation (collect `effects` before/after re-subscribe).

Target ≥ 90% line coverage of the `feature-signing` ViewModel/state classes. Tests must be
deterministic (controlled dispatcher, no real delays). Repository + UI/instrumentation tests are
explicitly **out of scope** here and owned by AND-345.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-339 — provides `SigningRepository`, DTOs, domain models, and `ApiResult`
  mapping. This ticket cannot start until AND-339's repository interface is merged. (Per backlog,
  `Deps: AND-339`.)
- **Blocks:** AND-345 (Signing tests) builds on the unit tests and ViewModel contracts here.
- **Consumed downstream (not blocking this ticket):** AND-340/341/342/343 bind their screens to
  these ViewModels; their UI work can proceed in parallel against the `UiState` contracts once those
  are merged. Coordinate the `SigningEditorState` shape with AND-342 (capture/placement) and the
  submit request shape with AND-343 (licenses).
- **Platform/build deps** (already present from earlier milestones): Hilt + KSP, `viewModelScope`,
  `kotlinx-coroutines-test`, Turbine, `:core:testing`.

## 13. Risks & Open Questions

- **R1 — Template field source.** Whether required fields come from a template
  (`signatureTemplates.ts` / `getTemplateFields`) or are freely placed affects `isComplete`. Assumed:
  a template defines required field ids; ad-hoc fields are optional. *Confirm with AND-339 DTOs.*
- **R2 — Submit endpoint/shape.** The exact `POST .../sign` body and license-acceptance mechanism
  depend on AND-343 + `/openapi.json`. Shapes above are representative; align before freezing
  `SubmitSignatureRequest`.
- **R3 — Signature persistence.** Whether an adopted/saved signature lives in DataStore prefs vs.
  is re-uploaded per submit (`signature_id` vs inline bytes) is unresolved. Assumed: opaque
  `signature_id`. *Owner: AND-342/AND-339.*
- **R4 — Coordinate system.** `NormRect` (0..1 page-relative) must match what AND-341's renderer and
  the backend expect. If the backend uses PDF points, add a conversion at the repository boundary
  (AND-339), keeping ViewModels page-relative.
- **R5 — Unreliable dev host.** Frequent timeouts could make manual verification flaky; mitigated by
  fully fake-backed unit tests, but downstream UI verification (AND-345) needs stable fixtures.

## 14. Acceptance Criteria

- **AC-1** `feature-signing` exposes `PacketListViewModel`, `PacketDetailViewModel`,
  `DocumentViewerViewModel`, `SignatureEditorViewModel`, and `SignSubmitViewModel`, each with a
  single `StateFlow<…UiState>` and a one-shot `SigningEffect` stream, all under
  `com.testlogon.android.feature.signing`.
- **AC-2** The signing editor is implemented as the explicit `SigningEditorState` state machine in
  §4.3; all legal transitions are reachable and all illegal transitions are no-ops.
- **AC-3** `isComplete` / `canSign` derivations are pure and correct for required-vs-optional and
  terminal-vs-actionable cases.
- **AC-4** List refresh failure retains cached content via `Content(staleError)`; submit failures are
  never auto-retried and double-submit is guarded (repo called exactly once).
- **AC-5** All ViewModels depend only on `SigningRepository` (AND-339) and an injected dispatcher;
  no Android UI/framework types in logic; no cookie/CSRF handling in this layer.
- **AC-6** Unit tests cover every state transition and the cases in §11, are deterministic, pass in
  CI, and reach ≥ 90% line coverage of the ViewModel/state classes. (Backlog acceptance:
  "Unit-tested.")
- **AC-7** No PII or signature bytes are logged or stored in `SavedStateHandle`; only opaque ids.

## 15. Definition of Done

- All files in §4.1 implemented in `:feature:signing`, package `com.testlogon.android.feature.signing`.
- `./gradlew :feature:signing:testDebugUnitTest` green locally and in CI; coverage gate met.
- `./gradlew :feature:signing:lintDebug` and detekt/ktlint clean; no new warnings.
- ViewModels reviewed for the AC-5 boundary (no framework leakage) and AC-7 (no PII logging).
- `UiState`/`SigningEditorState`/`SigningEffect`/`PlacedField` contracts documented in KDoc so
  AND-340–343 can bind without reading implementation.
- Open questions R1–R4 resolved or explicitly carried into AND-345 / AND-343 with owners noted.
- Merged to `android-port` behind the existing signing feature module; no changes outside
  `feature-signing` except additive test utilities in `:core:testing` if required.
