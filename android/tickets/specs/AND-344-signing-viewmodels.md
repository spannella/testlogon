---
id: AND-344
title: Signing ViewModels
milestone: M7
epic: E44
priority: P1
size: L
depends_on: [AND-339]
blocks: [AND-345]
status: reviewed
reviewed_on: 2026-06-06
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
is filterable by status (`draft`, `sent`, `partially_signed`, `completed`, `cancelled`, `expired`).
Filtering is a pure in-memory transform of the last successful load (no refetch).

> **[CORRECTED 2026-06-06]** The backend `SignaturePacketStatus` enum is lowercase
> `draft | sent | partially_signed | completed | cancelled | expired` (verified:
> `src/api/endpoints/signaturePackets.ts: SignaturePacketStatus`; OpenAPI `SignaturePacketDetailOut`).
> The original `PENDING/IN_PROGRESS/COMPLETED/DECLINED/EXPIRED` set is **wrong** (no `PENDING`,
> `IN_PROGRESS`, or `DECLINED` exist). `PacketStatusFilter` in §4.2 is corrected to match. **Also
> (unverified-assumption):** there is **no** GET list-of-packets endpoint in the backend or web
> client; the web composer loads a single packet by id. `listPackets()` is an assumed AND-339
> aggregation — flagged in §16 Open assumptions.

FR-2 — **Packet detail.** `PacketDetailViewModel` loads one packet (`packetId`). The detail response
(`SignaturePacketDetail`) **embeds** `signers[]` and a flat `fields[]` array inline; there are **no**
separate documents/recipients sub-resources. Exposes a derived flag `canSign` mapped from
`capabilities.can_fill_fields` plus `role == "signer"` and a non-terminal `status`.

> **[CORRECTED 2026-06-06]** The original FR-2 referenced "documents, recipients, and per-document
> signing status" as separate collaborators. The real contract has no per-document collection: a
> packet has one `source_path`, a `signers[]` array, and a flat `fields[]` array (each field carries
> `page`, `x`, `y`, `width`, `height`, `field_type`, `required`, `assigned_signer_id`,
> `is_assigned_to_viewer`, `filled_at`, `value`, `capture_mode`). Web reference derives
> `signerCanFill = role === "signer" && capabilities.can_fill_fields`. Verified:
> `src/api/endpoints/signaturePackets.ts: SignaturePacketDetail`; `src/pages/files/SignaturePacketComposer.tsx`.

FR-3 — **Document viewing handoff.** `DocumentViewerViewModel` exposes the packet's `source_path` and
(for completed packets) the final-PDF reference so AND-341's renderer can page through it. It owns
loading/error state for resolving those references, not the rendering itself.

> **[CORRECTED 2026-06-06]** There is **no** `GET /ui/signing/documents/{documentId}` descriptor
> endpoint and no per-document id in this domain. The web client downloads rendered output via
> `GET /v1/signature-packets/{packet_id}/final-pdf` (returns PDF bytes directly, gated on
> `status == "completed"`); the source is referenced by the packet's `source_path` string. Verified:
> `src/api/endpoints/signaturePackets.ts: downloadSignaturePacketFinalPdf`; OpenAPI
> `GET /v1/signature-packets/{packet_id}/final-pdf`.

FR-4 — **Signature editor state machine.** `SignatureEditorViewModel` models capture (draw or adopt
a saved signature), and placement of one or more signature/initial/date fields onto document
coordinates. It tracks a working set of `PlacedField` objects, supports add/move/remove, and computes
a `isComplete` flag when all *required* fields for the current recipient are placed and have content.

FR-5 — **Submission state machine.** `SignSubmitViewModel` validates that all required assigned
fields are filled, ensures any required legal notice has been acknowledged, then **marks the packet
done** and surfaces a confirmation or a typed failure. The "mark done" call is a one-shot,
non-idempotent action: it must guard against double-submit and must **not** be auto-retried.

> **[CORRECTED 2026-06-06]** There is **no** single `POST .../sign` submit endpoint and **no**
> `accepted_license_ids` array / `licenseAgreements.ts` mechanism in the verified contract. The web
> signer flow is: fill each assigned field individually via
> `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill`
> (`{ value?, input_mode?: "typed"|"drawn", drawn_strokes?: number[][] }`); if the packet's
> `legal_notice.required` is true, call `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice`
> (empty body); then `POST /v1/signature-packets/{packet_id}/mark-done` (empty body), which is enabled
> only when zero required assigned fields remain unfilled and the legal notice is no longer required.
> Verified: `src/pages/files/SignaturePacketComposer.tsx` (`submitFill`, `acknowledgeLegalNotice`,
> `markDone`, `remainingRequiredCount`); OpenAPI `SignaturePacketFieldFillIn`,
> `SignaturePacketMarkDoneOut`. `SignSubmitViewModel` therefore orchestrates per-field fills + an
> ack + a final mark-done, not one atomic submit. The double-submit guard applies to `mark-done`.

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

// CORRECTED 2026-06-06: lowercase backend statuses (SignaturePacketStatus); no PENDING/IN_PROGRESS/DECLINED.
enum class PacketStatusFilter { ALL, DRAFT, SENT, PARTIALLY_SIGNED, COMPLETED, CANCELLED, EXPIRED }
```

```kotlin
sealed interface PacketDetailUiState {
    data object Loading : PacketDetailUiState
    // CORRECTED 2026-06-06: detail embeds signers[] and a flat fields[]; there is no separate
    // documents/recipient collection. canSign derives from capabilities.can_fill_fields.
    data class Content(
        val packet: SignaturePacketDetail,     // includes signers[], fields[], capabilities, legal_notice
        val signers: List<SignatureSigner>,    // == packet.signers
        val fields: List<SignaturePacketField>,// flat; filter is_assigned_to_viewer for this signer
        val canSign: Boolean,                  // capabilities.can_fill_fields && role==signer && !terminal
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

// NOTE 2026-06-06: editor-side modes. Wire `input_mode` is only typed|drawn:
// DRAW -> "drawn"; TYPE/ADOPT_SAVED -> "typed". See §4.3 correction note.
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
    val id: String,                 // == backend field_id (server-created; see note)
    val pageIndex: Int,             // maps to backend `page` (NOTE: backend `page` is 1-based)
    val type: FieldType,            // signature | initials | date | text | notary_stamp
    val required: Boolean,
    val normRect: NormRect,         // 0f..1f page-relative; maps to backend x,y,width,height
    val captureMode: CaptureMode?,  // typed | drawn (signature/initials only)
    val value: String?,             // typed value; drawn signatures carry drawn_strokes ref
)

data class NormRect(val x: Float, val y: Float, val w: Float, val h: Float)

enum class FieldType { SIGNATURE, INITIALS, DATE, TEXT, NOTARY_STAMP }
```

`isComplete = placed.filter { it.required }.all { it.hasContent() } &&
 requiredFieldIds.all { id -> placed.any { it.id == id } }`. Page-relative `NormRect`
keeps the logic independent of AND-341's pixel renderer (unit-testable on JVM).

> **[VERIFIED / CORRECTED 2026-06-06]** The backend already stores fields normalized 0..1
> (`x`, `y`, `width`, `height`), so `NormRect` matches the wire model — **R4 is resolved: no
> point-conversion is needed** (web reference clamps to `0..0.98` and renders with `* 100%`;
> drawn-signature stroke points are also `0..1`). Map `NormRect.w/h` → backend `width/height` and
> `pageIndex` (0-based UI) → backend `page` (1-based) at the repository boundary. Field types are
> lowercase wire values with an extra `notary_stamp` member (corrected above). The
> editor-only `TYPE` `CaptureMode` is **not** in the wire enum — the backend `input_mode` is only
> `typed | drawn`; treat `TYPE`→`typed`. Verified: `src/api/endpoints/signaturePackets.ts`
> (`SignaturePacketField`, `SignatureFieldType`, `SignatureInputMode`); OpenAPI
> `SignaturePacketFieldFillIn` (`input_mode` enum `["typed","drawn"]`).

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

> **[CORRECTED 2026-06-06]** The repository surface and route table below were rewritten to match the
> verified backend/web contract. The previous version invented a list endpoint, a document-descriptor
> endpoint, a per-recipient fields endpoint, and a single atomic `POST .../sign` with an
> `accepted_license_ids` body — **none of these exist**. The real signing model is: load one packet
> detail (with embedded `fields[]`/`signers[]`), fill fields one at a time, acknowledge a legal notice
> if required, then mark the packet done. Sources cited inline and in §16.

```kotlin
interface SigningRepository {
    // No backend list endpoint exists; listPackets() is an AND-339 aggregation (see §16 Open assumptions).
    suspend fun listPackets(): ApiResult<List<SignaturePacketDetail>>
    suspend fun getPacket(packetId: String): ApiResult<SignaturePacketDetail>      // GET .../{id}
    suspend fun fillField(packetId: String, fieldId: String, req: FillFieldRequest)
        : ApiResult<FillFieldResult>                                                // POST .../fields/{id}/fill
    suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit>          // POST .../acknowledge-legal-notice
    suspend fun markDone(packetId: String): ApiResult<MarkDoneResult>              // POST .../mark-done
    suspend fun finalPdfRef(packetId: String): ApiResult<PdfRef>                   // GET  .../final-pdf (completed only)
}
```

These map to backend routes (authoritative shapes in `/openapi.json`; mirrored from
`frontend/src/api/endpoints/signaturePackets.ts`):

- `GET  /v1/signature-packets/{packet_id}` → `SignaturePacketDetailOut` (embeds `signers[]`, `fields[]`,
  `capabilities`, optional `legal_notice`)
- `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill` → `SignaturePacketFieldFillOut`
- `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice` → `SignaturePacketLegalNoticeAckOut`
- `POST /v1/signature-packets/{packet_id}/mark-done` → `SignaturePacketMarkDoneOut`
- `GET  /v1/signature-packets/{packet_id}/final-pdf` → PDF bytes (download; gated on `status=="completed"`)

Sender-side (not exercised by the signer flow in this ticket, but part of the same module):
`POST /v1/signature-packets` (create), `POST .../fields` (create/update/delete field),
`POST .../send`, plus template management at `GET|POST /ui/signing/templates` and
`.../templates/{template_key}/versions[/{version}]`, `.../templates/migration-check`.

Representative per-field **fill** request body (`SignaturePacketFieldFillIn`):

```json
// typed signature/text/date:
{ "value": "Jane Q. Signer", "input_mode": "typed" }
// drawn signature/initials (points normalized 0..1, 2..20 points):
{ "input_mode": "drawn", "drawn_strokes": [[0.10,0.20],[0.20,0.30]] }
```

Representative **mark-done** success response (`SignaturePacketMarkDoneOut`):

```json
{ "packet_id": "pkt_9", "signer_id": "sgn_3", "signer_status": "completed",
  "packet_status": "completed", "completed_at": "2026-06-05T17:22:09Z" }
```

(There is **no** `certificate_url`; the completed document is fetched via the `final-pdf` GET above.)

All requests ride cookies + `X-CSRF-Token` and the 401→`refresh`→retry behavior transparently via
`core-network`. The `fill`/`mark-done` `POST`s are non-idempotent and are **excluded** from any
GET-only retry policy.

> **[VERIFIED 2026-06-06]** CSRF/session behavior confirmed in `src/api/client.ts`: the CSRF token is
> read from the `ui_csrf` cookie and sent as the `X-CSRF-Token` header on every request; a `401`
> (only when already authenticated) triggers a **single** `POST /ui/session/refresh`, then the original
> request is retried once; a failed refresh logs out. (Minor: the web client also attaches an
> `Authorization: Bearer <accessToken>` header alongside cookies — the spec's "cookie-based session"
> framing is otherwise accurate; this layer touches none of it.)

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
3. **DocumentViewerViewModel:** resolves `source_path` / final-PDF ref success/failure; gates
   final-PDF on `status == "completed"`; retry.
4. **SignatureEditorViewModel (state machine):** assert **every legal edge** in §4.3 and assert
   illegal edges are no-ops (e.g. `onContinue()` while `isComplete == false` does not leave
   `Placing`); `isComplete` recomputation on place/move/remove; required-vs-optional field logic.
5. **SignSubmitViewModel:** happy-path → fills all required assigned fields, acknowledges the legal
   notice when required, then `markDone()` → `Submitted` (maps `SignaturePacketMarkDoneOut`);
   validation failure (422 `HTTPValidationError`) → `SubmitError` with messages; network failure →
   retryable error; **double-submit guard** (second `onSubmit()` during in-flight is ignored — assert
   repository `markDone` invoked exactly once);
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

- **R1 — Template field source. [RESOLVED 2026-06-06]** The signer does **not** fetch template
  fields; required fields are the packet's own `fields[]` (each has a `required` flag and
  `is_assigned_to_viewer`). `isComplete` = all required fields with `is_assigned_to_viewer == true`
  have `filled_at` set (web reference `remainingRequiredCount`). The `/ui/signing/templates` family is
  sender-side template management only. Source: `SignaturePacketComposer.tsx`,
  `signatureTemplates.ts`.
- **R2 — Submit endpoint/shape. [RESOLVED 2026-06-06]** No `POST .../sign` and no license-id body.
  Submission = per-field `fill` + optional `acknowledge-legal-notice` + `mark-done`. See corrected §5.
  `SubmitSignatureRequest` is dropped; `FillFieldRequest` (`value?`, `input_mode?`, `drawn_strokes?`)
  + `markDone(packetId)` replace it.
- **R3 — Signature persistence. [PARTIALLY RESOLVED 2026-06-06]** There is **no** `signature_id` in
  the verified contract. A drawn signature is sent inline as `drawn_strokes: number[][]` (0..1 points,
  2..20 of them); a typed signature is sent as `value` with `input_mode: "typed"`. Whether a saved
  signature is cached in DataStore for re-use across packets is a UI/AND-342 concern (unverified).
- **R4 — Coordinate system. [RESOLVED 2026-06-06]** Backend stores normalized `x,y,width,height`
  (0..1); `NormRect` matches directly. No PDF-point conversion needed. Map `pageIndex` (0-based UI) ↔
  `page` (1-based backend) at the repo boundary. Source: `SignaturePacketField`,
  `getDefaultDimensions`/canvas math in `SignaturePacketComposer.tsx`.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI" = the index/spec under
`reference/openapi.*`; frontend paths are under `reference/src/`.

1. **Packet detail endpoint is `GET /v1/signature-packets/{packet_id}` returning `SignaturePacketDetail`
   (embeds `signers[]`, `fields[]`, `capabilities`, optional `legal_notice`).** — **Verified.**
   `src/api/endpoints/signaturePackets.ts: getSignaturePacketDetail` / `SignaturePacketDetail`;
   OpenAPI `GET /v1/signature-packets/{packet_id}` → `SignaturePacketDetailOut`.
2. **Field fill is `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill` with body
   `{ value?, input_mode?: "typed"|"drawn", drawn_strokes?: number[][] }`.** — **Verified.**
   `src/api/endpoints/signaturePackets.ts: fillSignaturePacketField`; OpenAPI schema
   `SignaturePacketFieldFillIn` (`input_mode` enum `["typed","drawn"]`).
3. **Completion is `POST /v1/signature-packets/{packet_id}/mark-done` → `SignaturePacketMarkDoneOut`
   (`packet_id, signer_id, signer_status, packet_status, completed_at`); enabled only when no required
   assigned fields remain and legal notice is not still required.** — **Verified.**
   `src/pages/files/SignaturePacketComposer.tsx: markDone` + `remainingRequiredCount` + button
   `disabled` logic; OpenAPI `POST .../mark-done`, schema `SignaturePacketMarkDoneOut`.
4. **Legal notice is acknowledged via `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice`
   (empty body), gated on `packet.legal_notice.required`.** — **Verified.**
   `src/api/endpoints/signaturePackets.ts: acknowledgeSignaturePacketLegalNotice`;
   `SignaturePacketComposer.tsx: acknowledgeLegalNotice`; OpenAPI `POST .../acknowledge-legal-notice`.
5. **Completed document is fetched via `GET /v1/signature-packets/{packet_id}/final-pdf` (PDF bytes,
   gated on `status == "completed"`); there is no document-descriptor endpoint and no
   `certificate_url`.** — **Corrected** (original claimed `GET /ui/signing/documents/{documentId}` and a
   `certificate_url`). `src/api/endpoints/signaturePackets.ts: downloadSignaturePacketFinalPdf`;
   OpenAPI `GET /v1/signature-packets/{packet_id}/final-pdf`.
6. **Status enum is lowercase `draft|sent|partially_signed|completed|cancelled|expired`.** —
   **Corrected** (original `PENDING|IN_PROGRESS|COMPLETED|DECLINED|EXPIRED`).
   `src/api/endpoints/signaturePackets.ts: SignaturePacketStatus`; OpenAPI `SignaturePacketDetailOut`.
7. **Field types are lowercase `signature|initials|date|text|notary_stamp`.** — **Corrected**
   (original `SIGNATURE|INITIALS|DATE|TEXT`, missing `notary_stamp`).
   `src/api/endpoints/signaturePackets.ts: SignatureFieldType`; `signatureTemplates.ts:
   SignatureTemplateFieldType`.
8. **Field coordinates are normalized 0..1 (`x,y,width,height`) with a 1-based `page`; no PDF-point
   conversion needed.** — **Verified / Corrected** (NormRect concept kept, but field uses
   `width/height` not `w/h`, plus a 1-based `page`). `SignaturePacketField` in
   `src/api/endpoints/signaturePackets.ts`; canvas clamp/render math in `SignaturePacketComposer.tsx`.
9. **There is NO single atomic submit `POST .../sign` and NO `accepted_license_ids` body.** —
   **Corrected.** Verified by absence in OpenAPI index (the only `/sign`-named routes are messaging/
   call signaling, unrelated) and by the web flow being per-field `fill` + `mark-done`.
10. **Drawn signatures are sent inline as `drawn_strokes` (0..1 points, 2..20); there is no
    `signature_id`.** — **Corrected** (original assumed an opaque `signature_id`).
    `SignaturePacketComposer.tsx: validateFieldInput` (2..20 points, 0..1 range) + `submitFill`;
    OpenAPI `SignaturePacketFieldFillIn.drawn_strokes`.
11. **Required-field completeness = required, viewer-assigned fields all have `filled_at`.** —
    **Verified.** `SignaturePacketComposer.tsx: remainingRequiredCount` /
    `isFieldAssignedToSigner` (`is_assigned_to_viewer`).
12. **CSRF token from `ui_csrf` cookie sent as `X-CSRF-Token`; single `POST /ui/session/refresh`
    on 401 then one retry; failed refresh logs out.** — **Verified.** `src/api/client.ts`
    (`getCookie("ui_csrf")`, `X-CSRF-Token` header, `refreshSession`, 401 retry block).
13. **FastAPI error `detail` is string | `[{msg}]` | `{code,...}`, normalized to a message.** —
    **Verified.** `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`; validation
    errors are `422 HTTPValidationError` across OpenAPI.
14. **Sender-side template management lives at `GET|POST /ui/signing/templates` and
    `.../templates/{template_key}/versions[/{version}]`, `.../templates/migration-check`.** —
    **Verified.** `src/api/endpoints/signatureTemplates.ts`; OpenAPI lines for
    `list_signature_templates`, `create_signature_template_version`, `signature_template_migration_check`.
15. **ViewModel framework choices: `StateFlow` for state, `Channel`/`receiveAsFlow` for one-shot
    effects, `SavedStateHandle` for process death, Hilt `@HiltViewModel` injection.** — **Verified
    (framework ref).** Android docs: StateFlow/UI state
    `https://developer.android.com/topic/architecture/ui-layer/state-production`; one-shot events guidance
    `https://developer.android.com/topic/architecture/ui-layer/events`; `SavedStateHandle`
    `https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate`;
    Hilt + ViewModel `https://developer.android.com/training/dependency-injection/hilt-jetpack`.
16. **JVM-only coroutine testing with injected dispatcher, `runTest`, Turbine.** — **Verified
    (framework ref).** `https://developer.android.com/kotlin/coroutines/test`.

### Corrections made

- §3 FR-1: status filter values changed to the real lowercase enum; noted absence of a list endpoint.
- §3 FR-2: removed "documents/recipients" sub-resources; `canSign` now derives from
  `capabilities.can_fill_fields`.
- §3 FR-3: removed the non-existent document-descriptor endpoint; replaced with `source_path` +
  `final-pdf`.
- §3 FR-5: replaced the atomic `POST .../sign` + `accepted_license_ids` model with per-field `fill` +
  `acknowledge-legal-notice` + `mark-done`.
- §4.2: `PacketStatusFilter` enum corrected; `PacketDetailUiState.Content` reshaped to embedded
  `signers`/`fields`.
- §4.3: added `FieldType` enum (lowercase + `notary_stamp`); `PlacedField` adjusted (no `documentId`,
  no `signature_id`, `captureMode` added, 1-based `page` note); added coordinate/`input_mode` note.
- §5: full repository surface + route table rewrite; fill/mark-done request & response examples
  replace the invented submit examples; added CSRF verification note.
- §11: SignSubmit test now asserts `markDone` called once (was `submitSignedPacket`); DocumentViewer
  test reframed to source/final-PDF; added 422 validation reference.
- §13: R1, R2, R4 resolved; R3 marked partially resolved (drawn strokes inline, no `signature_id`).
- Frontmatter: removed duplicate `status: draft`; set `status: reviewed`, added `reviewed_on`.

### Open assumptions

- **`listPackets()` aggregation.** No backend or web endpoint returns a list of signature packets;
  the web composer loads one packet by id. The Android packet-list screen (AND-340) needs a source —
  assumed to be an AND-339 aggregation (e.g. derived from files/share listings or a future endpoint).
  *Unverifiable from current sources; owner AND-339/AND-340.*
- **`canSign` "terminal" set.** Mapping which statuses are non-actionable (`completed|cancelled|expired`
  assumed terminal) is inferred from web chip logic, not an explicit backend flag. *Confirm with AND-339.*
- **Saved-signature reuse / DataStore.** Whether an adopted signature is cached for reuse across packets
  is a UI/AND-342 concern; not present in the verified wire contract.
- **`licenseAgreements.ts` relevance.** A `licenseAgreements.ts` module exists in the web app but
  belongs to a separate content-licensing domain (`src/pages/licenses/*`), unrelated to signature-packet
  legal notices. The signing flow's only legal step is `acknowledge-legal-notice`. The §1/§2/§12
  references to AND-343 "licenses" feeding signing are therefore an **unverified cross-ticket
  assumption**; signing completion does not consume license-agreement ids.
- **`SavedSignature`/`CapturedSignature` domain types** are AND-339/AND-342 inventions (not in the wire
  contract); their exact shape is assumed.

## 17. Test Plan

All cases are JVM-side unless a target is named otherwise. This ticket is logic-only, so the bulk are
JVM unit / contract tests; a few instrumented/Compose-UI/manual cases are included where downstream
binding or real-network/offline behavior must be validated (those run on the **headless emulator
AVD `test35`** unless real-hardware/ABI behavior is required, in which case the **physical Samsung
Galaxy A15 5G, serial `R5CX821TA9R`, API 34/arm64** is named explicitly).

- **TC-AND-344-01 — Packet detail happy path → Content.**
  Type: unit. Target: `PacketDetailViewModel` + `FakeSigningRepository` (JVM/Robolectric-free).
  Preconditions: fake returns a `SignaturePacketDetail` with `role="signer"`, `status="sent"`,
  `capabilities.can_fill_fields=true`, one required signature field assigned to viewer (unfilled).
  Steps: construct VM with `packetId`; advance dispatcher; collect `state` via Turbine.
  Expected: `Loading` → `Content` with `canSign == true`, `fields` exposed, `signers` populated.
  Traces: AC-1, AC-3.

- **TC-AND-344-02 — `canSign` false for terminal/non-viewer/non-signer packets.**
  Type: unit. Target: `PacketDetailViewModel` derivation (pure).
  Preconditions: three fixtures — (a) `status="completed"`, (b) `role="sender"`, (c) `role="signer"`
  but `capabilities.can_fill_fields=false`.
  Steps: load each; read `Content.canSign`.
  Expected: `canSign == false` in all three.
  Traces: AC-3.

- **TC-AND-344-03 — Status filter is a pure subset transform.**
  Type: unit. Target: `List<SignaturePacketDetail>.applyFilter(PacketStatusFilter)`.
  Preconditions: in-memory list spanning every status (`draft, sent, partially_signed, completed,
  cancelled, expired`).
  Steps: apply each `PacketStatusFilter` value incl. `ALL`.
  Expected: each filter yields exactly the matching subset; `ALL` returns all; no refetch occurs.
  Traces: AC-1, AC-3.

- **TC-AND-344-04 — Editor state machine: all legal edges reachable.**
  Type: unit. Target: `SignatureEditorViewModel` / `SigningEditorState`.
  Preconditions: fake repo returns fields for the recipient.
  Steps: drive `Loading→Capturing→Placing` (place required field) `→ReadyToSubmit` (`onContinue`) and
  `ReadyToSubmit→Placing` (`onEditAgain`); also `Loading→Error→(onRetry)→Loading`.
  Expected: each documented transition observed in order via Turbine; `isComplete` flips true only when
  all required fields are placed with content.
  Traces: AC-2, AC-3.

- **TC-AND-344-05 — Editor illegal transitions are no-ops.**
  Type: unit. Target: `SignatureEditorViewModel`.
  Preconditions: VM in `Placing` with `isComplete == false`.
  Steps: call `onContinue()`.
  Expected: state remains `Placing` (no emission to `ReadyToSubmit`); no effect emitted.
  Traces: AC-2.

- **TC-AND-344-06 — `isComplete` recompute on add/move/remove + required vs optional.**
  Type: unit. Target: `isComplete` pure logic + `PlacedField`.
  Preconditions: one required + one optional field id for the recipient.
  Steps: place optional only → expect false; place required with content → true; move required
  (`onFieldMoved`) → stays true; remove required (`onFieldRemoved`) → false.
  Expected: transitions match; optional fields never block completeness.
  Traces: AC-3.

- **TC-AND-344-07 — Submit happy path: fill → ack → mark-done → Submitted.**
  Type: contract/MockWebServer. Target: `SignSubmitViewModel` over a repo wired to MockWebServer.
  Preconditions: enqueue 200 for each `POST .../fields/{id}/fill`, 200 for
  `POST .../acknowledge-legal-notice` (legal_notice.required=true), 200
  `SignaturePacketMarkDoneOut` for `POST .../mark-done`.
  Steps: call `onSubmit()`; advance dispatcher.
  Expected: requests issued in order with `X-CSRF-Token` header and JSON bodies matching
  `SignaturePacketFieldFillIn`; state → `Submitted` mapping `packet_status="completed"`,
  `completed_at`. Verify recorded request paths/methods/bodies.
  Traces: AC-1, AC-4.

- **TC-AND-344-08 — Submit validation failure (422) → SubmitError with messages.**
  Type: contract/MockWebServer. Target: `SignSubmitViewModel`.
  Preconditions: enqueue `422` with `HTTPValidationError` body `{"detail":[{"msg":"value is not a
  valid date","loc":["body","value"]}]}` for a `fill`.
  Steps: call `onSubmit()`.
  Expected: error mapped via `normalizeErrorDetail` to a `Validation` `AppError`; state →
  `SubmitError` carrying the message; **not** auto-retried.
  Traces: AC-4.

- **TC-AND-344-09 — Double-submit guard: `mark-done` called exactly once.**
  Type: unit. Target: `SignSubmitViewModel` + counting fake repo, `StandardTestDispatcher`.
  Preconditions: fake `markDone` suspends until released.
  Steps: call `onSubmit()` twice while the first is in flight; release; advance.
  Expected: `markDone` invocation count == 1; second call ignored (`submitGuard`); single `Submitted`.
  Traces: AC-4.

- **TC-AND-344-10 — List refresh failure retains cache via `Content(staleError)`.**
  Type: unit. Target: `PacketListViewModel`.
  Preconditions: first load succeeds (non-empty); second (refresh) fails with `AppError.Network`.
  Steps: load; `refresh()`; collect states.
  Expected: after failed refresh, state is `Content` with prior `packets` retained and `staleError`
  set, `isRefreshing=false`; data not discarded.
  Traces: AC-4.

- **TC-AND-344-11 — Flaky-dev-host / offline GET path is retryable, no infinite spinner.**
  Type: contract/MockWebServer. Target: `PacketDetailViewModel`.
  Preconditions: MockWebServer set to `NO_RESPONSE`/socket-timeout (simulating the ~20s dev-host
  timeout), then a 200 on retry.
  Steps: load → expect `Error(AppError.Network)` (terminal, not stuck on `Loading`); call `onRetry()`
  with server now responding.
  Expected: `Loading→Error→Loading→Content`; every `Loading` has a terminal transition.
  Traces: AC-4.

- **TC-AND-344-12 — No framework/PII leakage (boundary + logging).**
  Type: unit. Target: all ViewModels + a fake `Analytics`/`Timber` tree.
  Preconditions: run a full editor+submit cycle with a drawn signature (`drawn_strokes`) and a date
  value.
  Steps: capture all analytics events and log lines; inspect `SavedStateHandle` contents after
  simulated recreation.
  Expected: no `drawn_strokes` points, field `value`s, names, or raw `detail` bodies appear in logs/
  analytics (only hashed ids + `AppError` type/HTTP code); `SavedStateHandle` holds only ids + plain
  placement data, never raw bitmap/stroke bytes. Also assert no `android.*`/Compose types in the
  ViewModel public API (reflection check or ArchUnit-style test).
  Traces: AC-5, AC-7.

- **TC-AND-344-13 — One-shot effects emitted once, not replayed after recreation.**
  Type: unit. Target: `SigningEffect` channel.
  Preconditions: VM emits a `ShowError`/navigation effect.
  Steps: collect `effects`; drop the collector; re-subscribe (simulating config change) and collect.
  Expected: effect delivered exactly once; no replay to the new collector.
  Traces: AC-1.

- **TC-AND-344-14 — Downstream Compose binding + accessibility of distinct Ui states.**
  Type: Compose-UI (instrumented). Target: a thin test Composable bound to `PacketListViewModel`,
  run on **emulator AVD `test35`** (API 35, x86_64).
  Preconditions: fake repo drives `Loading`, `Empty`, `Error`, `Content` in turn.
  Steps: assert each state renders a distinct, semantically labeled node (e.g. `Empty` vs `Error` vs
  list) and that status changes are announced via Compose semantics (`liveRegion`/`contentDescription`),
  using string-resource ids (no hard-coded literals).
  Expected: distinct semantics per state; no missing content descriptions; passes accessibility
  assertions. (Logic-only ticket — this validates the contract is bindable/announceable; the real
  screens ship in AND-340.) Traces: AC-1, AC-6.

> **Device note:** This ticket is pure presentation logic with no camera/biometric/FCM/WebRTC/Telecom/
> streaming behavior, so **no case requires the physical device**; the emulator `test35` is sufficient
> for the instrumented/Compose cases. If AND-345 later exercises real drawn-signature touch capture or
> ABI-specific (arm64 vs x86) serialization of `drawn_strokes`, run that on the physical Galaxy A15 5G
> (`R5CX821TA9R`, API 34/arm64); that is out of scope here.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (VMs expose single StateFlow + effects) | TC-01, TC-07, TC-13, TC-14 |
| AC-2 (explicit editor state machine; illegal edges no-op) | TC-04, TC-05 |
| AC-3 (`isComplete`/`canSign` pure & correct) | TC-01, TC-02, TC-03, TC-04, TC-06 |
| AC-4 (stale cache on refresh fail; no auto-retry; double-submit guard) | TC-07, TC-08, TC-09, TC-10, TC-11 |
| AC-5 (repo+dispatcher only; no framework/CSRF in layer) | TC-12 |
| AC-6 (deterministic unit coverage ≥90%; CI) | TC-01–TC-13 (all JVM cases), TC-14 |
| AC-7 (no PII/signature bytes logged or in SavedStateHandle) | TC-12 |
