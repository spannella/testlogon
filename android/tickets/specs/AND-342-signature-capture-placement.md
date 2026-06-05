---
id: AND-342
title: Signature capture + placement
milestone: M7
epic: E44
priority: P1
size: L
status: draft
depends_on: [AND-341]
blocks: [AND-343]
---

# AND-342 — Signature capture + placement

## 1. Overview & Goal

This ticket delivers in-app signature capture and field placement for document packets in the TestLogon native Android port. The user must be able to (a) **draw** a signature with a finger/stylus on a touch canvas, or **adopt** a typed/styled signature, persist that signature as a reusable asset, and (b) **place** the captured signature (and initials) into the signature fields rendered on top of a PDF document page produced by AND-341 (`PdfRenderer`-backed rendering).

The deliverable is the editing surface and local state only: capturing the signature image, positioning it onto each required field overlay anchored to PDF page coordinates, and producing a validated, in-memory model of the signed packet. Network submission of the signed packet is explicitly **out of scope** and owned by AND-343 (Submit / sign + licenses). The acceptance bar for this ticket is: a signature is captured and visibly placed on the document at a field location, and the resulting placement model is complete and consistent with the document's field schema.

Success means a `feature-signing` flow where every required signature/initial/date field on the active document is satisfiable by a captured signature, the placements survive rotation/scroll/recomposition, and the produced `SignedPacketDraft` passes validation that AND-343 can submit unchanged.

## 2. Context & References

- **Module:** new Gradle module `feature-signing` (namespace `com.testlogon.android.feature.signing`) layered as `app -> feature-signing -> core-{model,ui,data,network,testing}`.
- **Upstream (AND-341, PDF rendering):** provides `PdfDocumentRenderer`, per-page `PageRenderState` (bitmap + page pixel size + display rect), and the scrollable pager host. AND-342 consumes its page geometry to anchor field overlays. This ticket must not re-render PDF pages itself.
- **Upstream (AND-340):** provides `PacketDetail` including the list of documents and their `fields[]` schema. Field definitions (id, type, page index, normalized rect, required, assigned recipient) originate here.
- **Downstream (AND-343):** consumes `SignedPacketDraft` and the persisted signature asset; owns the `POST` submit call and `licenseAgreements.ts` parity. Any field that this ticket marks `satisfied = true` must carry enough data for AND-343 to serialize.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (document + field fetch), `frontend/src/api/types.ts` (`SignatureField`, `FieldType`, `SignaturePlacement` shapes). Mirror field-type enums and normalized-coordinate convention (top-left origin, 0..1 within page).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Field/document metadata is fetched via AND-340/341; OpenAPI at `/openapi.json`. Cookie-based session with `X-CSRF-Token` header applies to any GET this ticket issues for an existing signature asset.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Room 2.6 + DataStore, Coil. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.

## 3. Functional Requirements

FR-1 **Draw signature.** A full-screen `SignaturePadScreen` exposes a drawing canvas. Strokes are captured via `pointerInput`/`detectDragGestures`, stored as a list of polylines, rendered live, and rasterized to a transparent-background PNG on confirm. Provide Clear and Undo (last stroke) controls.

FR-2 **Adopt typed signature.** The user may instead type their name and pick from >= 3 bundled signature-style fonts; the rendered text is rasterized to the same PNG asset format. A toggle switches between Draw and Type modes.

FR-3 **Persist & reuse.** On confirm, the signature PNG and a separate initials PNG are stored locally (file + DataStore pointer) as the user's default signature asset, so re-entry pre-fills "Use saved signature" without redrawing.

FR-4 **Field discovery.** On opening a document, enumerate `SignatureField`s from `PacketDetail`. Group by `page`, classify by `type` (SIGNATURE, INITIALS, DATE_SIGNED, TEXT, CHECKBOX — only the first three are auto-fillable here), and compute per-field "required/optional" and "satisfied" status.

FR-5 **Place signature.** Tapping an unsatisfied SIGNATURE/INITIALS field stamps the captured asset into that field's rect, scaled to fit while preserving aspect ratio, centered. DATE_SIGNED fields auto-fill the current date (`2026-06-05` format per locale). Placed fields render an overlay image on top of the AND-341 page bitmap.

FR-6 **Adjust / remove.** A placed signature can be removed (tap → Clear field) returning it to unsatisfied. No free-form drag/resize is required for v1 (placement snaps to field rect); document this as a deliberate constraint.

FR-7 **Progress & guard.** A persistent progress chip shows "N of M required fields complete." The "Continue" action (handing off to AND-343) is disabled until all required fields are satisfied.

FR-8 **Geometry stability.** Placements are stored in **normalized page coordinates**, so they remain correct across scroll, zoom, device rotation, and recomposition. Overlays re-project from normalized rect × current `PageRenderState.displayRect` each frame.

## 4. Technical Design

New module `feature-signing`. Public entry is a Navigation-Compose destination `signing/{packetId}/{documentId}`.

```kotlin
// core-model
enum class FieldType { SIGNATURE, INITIALS, DATE_SIGNED, TEXT, CHECKBOX }

data class NormalizedRect(           // top-left origin, 0f..1f within page
    val left: Float, val top: Float, val right: Float, val bottom: Float
)

data class SignatureField(
    val id: String,
    val documentId: String,
    val page: Int,                   // 0-based page index
    val type: FieldType,
    val rect: NormalizedRect,
    val required: Boolean,
    val recipientId: String?
)

enum class SignatureSource { DRAWN, TYPED, SAVED }

data class SignatureAsset(
    val signaturePngPath: String,
    val initialsPngPath: String,
    val source: SignatureSource,
    val widthPx: Int, val heightPx: Int
)

data class FieldPlacement(
    val fieldId: String,
    val page: Int,
    val rect: NormalizedRect,
    val assetPath: String?,          // null for DATE_SIGNED/TEXT
    val textValue: String?,          // date string, etc.
    val satisfied: Boolean
)

data class SignedPacketDraft(
    val packetId: String,
    val documentId: String,
    val asset: SignatureAsset,
    val placements: List<FieldPlacement>
) {
    val unsatisfiedRequired: List<String>     // field ids
    val isComplete: Boolean get() = unsatisfiedRequired.isEmpty()
}
```

```kotlin
// feature-signing
@HiltViewModel
class SigningViewModel @Inject constructor(
    private val signatureRepo: SignatureRepository,
    private val packetRepo: PacketRepository,        // from AND-340
    savedState: SavedStateHandle
) : ViewModel() {
    val uiState: StateFlow<SigningUiState>
    fun onCaptureDrawn(strokes: List<Stroke>)
    fun onCaptureTyped(name: String, fontId: String)
    fun onUseSaved()
    fun onPlaceField(fieldId: String)
    fun onClearField(fieldId: String)
    fun onContinue(): SignedPacketDraft?            // null if !isComplete
}

sealed interface SigningUiState {
    data object Loading : SigningUiState
    data class Error(val message: String, val retryable: Boolean) : SigningUiState
    data class Ready(
        val asset: SignatureAsset?,                 // null until captured
        val pages: List<PageFields>,                // joined w/ AND-341 geometry
        val requiredTotal: Int,
        val requiredDone: Int,
        val canContinue: Boolean
    ) : SigningUiState
}
```

**Rasterization.** `SignatureRasterizer.fromStrokes(strokes, size): Bitmap` draws polylines onto an `ARGB_8888` `Canvas` with a `Paint` (`STROKE`, `ROUND` cap/join, anti-alias). `fromText(name, typeface, size)` measures and centers text. Both crop to ink bounds + padding and compress to PNG via `Bitmap.compress(PNG, 100, out)`. Target max edge 1024px to bound memory.

**Overlay rendering.** Inside the AND-341 page composable, an overlay `Box` is drawn per page:
```kotlin
@Composable
fun FieldOverlay(
    pageFields: PageFields,
    pageRender: PageRenderState,    // from AND-341: displayRect in px
    onTapField: (String) -> Unit
)
```
For each field, project `NormalizedRect` to pixels: `x = displayRect.left + rect.left * displayRect.width`, etc. Unsatisfied fields draw a dashed accent border + tap target (>=48dp); satisfied fields draw the asset bitmap via Coil `AsyncImage(model = File(assetPath))` clipped to the projected rect.

**Coordinate convention.** Normalized, top-left origin, identical to web `frontend/src/api/types.ts`. All persistence and the `SignedPacketDraft` use normalized coords; pixel math never leaves the composable layer.

## 5. API Contract

This ticket performs **no signing/submit network call** — that is owned by **AND-343**. Field/document metadata is fetched upstream by **AND-340/AND-341**; this module consumes already-fetched `PacketDetail`/`SignatureField`s in memory.

One optional GET may be used to hydrate a server-side saved signature if present (otherwise local-only):

```
GET /ui/documents/{documentId}/fields
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>
200 -> { "fields": [
  { "id":"f_92","page":0,"type":"signature",
    "rect":{"left":0.12,"top":0.78,"right":0.42,"bottom":0.86},
    "required":true,"recipient_id":"r_1" }, ... ] }
```

Moshi maps `type` (lowercase server enum) -> `FieldType`, `recipient_id` -> `recipientId`. If the field list is already present from AND-340's `PacketDetail`, skip the call. Errors map through the shared FastAPI `detail` decoder (`string | [{msg}] | {code,...}`) into `ApiResult<List<SignatureField>>`. This GET is idempotent: it is eligible for the bounded backoff retry policy (max 2 retries, ~20s timeout) and a 401 triggers a single `POST /ui/session/refresh` then one retry, per project auth rules.

No request body is produced by this ticket. The `SignedPacketDraft` it emits is the **input** to AND-343's `POST /ui/packets/{packetId}/sign`.

## 6. Data & State Management

- **In-memory:** `SigningViewModel` holds the single source of truth as `StateFlow<SigningUiState>`. Placements are a `Map<fieldId, FieldPlacement>` reduced into `pages`/counters on each mutation.
- **Saved signature (DataStore):** `signing_prefs` Preferences DataStore stores `default_signature_path`, `default_initials_path`, `signature_source`, `asset_w`, `asset_h`. Enables FR-3 reuse across sessions.
- **Asset files:** PNGs written to `context.filesDir/signatures/{uuid}.png` (app-private). Old default is deleted when replaced.
- **Room (cache, optional):** `signed_draft` table keyed by `(packetId, documentId)` persists in-progress placements (JSON column of `List<FieldPlacement>`) so an interrupted signing session resumes. TTL/cleanup on successful AND-343 submit (AND-343 clears it).
- **SavedStateHandle:** retains `packetId`, `documentId`, and active capture mode across process death; bitmaps are reloaded from file paths, never held in `SavedStateHandle`.
- **Re-projection** is pure/derived (normalized rect × current display rect); never persisted in pixels.

## 7. Error Handling & Resilience

- **Empty signature:** confirming a blank canvas or empty typed name is blocked with inline validation ("Draw or type a signature first"); no asset is produced.
- **Rasterization failure / OOM:** `SignatureRasterizer` runs on `Dispatchers.Default`; `OutOfMemoryError` and `IOException` are caught, surfaced as a retryable snackbar, and never crash the flow. Max edge 1024px and `inSampleSize`-style downscaling keep memory bounded on minSdk 24 devices.
- **File write failure:** if PNG write fails, fall back to in-memory bitmap for the current session and warn that the signature won't persist.
- **Field/page mismatch:** if a field references a `page` index absent in the AND-341 render set, the field is logged and excluded from required counts to avoid a permanently-unsatisfiable packet; emit a non-fatal warning.
- **Network (optional GET only):** ~20s timeout, bounded backoff (idempotent GET), single `session/refresh`-then-retry on 401, then `SigningUiState.Error(retryable = true)` with a Retry action. Stale/offline: fall back to in-memory `PacketDetail` fields if the network fetch fails.
- **Continue guard:** `onContinue()` returns null and keeps the user on-screen if `!isComplete`, highlighting the first unsatisfied required field.

## 8. Security & Privacy

- The signature is biometric-adjacent PII. Store PNGs only in **app-private** `filesDir` (no external storage, no `MediaStore`, no scoped-storage export). Never log the bitmap, strokes, or file bytes.
- No signature data is transmitted in this ticket; when AND-343 submits, it rides the existing cookie session + `X-CSRF-Token` over the (plaintext dev) channel — flag in Risks that production must be HTTPS before real signatures transit.
- DataStore pointers store only file paths and dimensions, not image content.
- Provide a "Delete saved signature" affordance that removes the files and clears the DataStore pointer.
- Disable Android auto-backup for the `signatures/` dir and `signing_prefs` via `fullBackupContent`/`dataExtractionRules` exclusions so signatures are not copied to cloud backup.
- No clipboard, no screenshots suppression required, but the signing screen sets `FLAG_SECURE` is **not** required for v1 (note as open question).

## 9. Accessibility & i18n

- Drawing is inherently visual; provide the **Type** mode as the accessible equivalent path so signing is possible without fine motor drawing (TalkBack-friendly text entry + font picker with `contentDescription`).
- All controls (Clear, Undo, Use saved, Place, Clear field, Continue) have `contentDescription` and >=48dp targets. Field overlays expose `semantics { contentDescription = "Signature field, required, not signed" }` updated on placement.
- Progress chip announced via `liveRegion = Polite` on count change.
- Strings externalized to `res/values/strings.xml`; date in DATE_SIGNED fields formatted with `java.time` + `LocalContext` locale (not hard-coded `2026-06-05`). Support RTL: overlay projection uses absolute page coords (origin top-left) and is layout-direction independent; chrome respects RTL.
- Respect system font scale for typed-signature preview vs. the rasterized fixed-size output (rasterization uses its own paint size, independent of UI font scale).

## 10. Telemetry & Logging

Use the project analytics façade (`Analytics.track(event, params)`); no PII in params.

- `signing_opened` { packetId, documentId, requiredFields }
- `signature_captured` { source: drawn|typed|saved, strokeCount? }
- `field_placed` { fieldType, page }
- `field_cleared` { fieldType }
- `signing_completed` { requiredFields, durationMs } (on `onContinue` success)
- `signing_error` { stage: rasterize|file|network, retryable }

Logging via Timber at DEBUG for stroke/render counts (never image data); WARN for excluded fields and rasterization fallbacks. No signature bytes, names, or file contents are ever logged.

## 11. Testing Strategy

- **Unit (JVM, core-testing):**
  - `NormalizedRect` <-> pixel projection round-trips within tolerance across display rects and rotations.
  - `SignedPacketDraft.unsatisfiedRequired` / `isComplete` correct for mixed required/optional, multi-page, and date fields.
  - `SigningViewModel` reducer: capture → place → clear transitions; `onContinue` returns null until complete (`StateFlow` asserted via Turbine).
  - Field-type mapping (lowercase server enum → `FieldType`) and Moshi adapter for `recipient_id`.
- **Rasterizer (Robolectric / instrumented):** `fromStrokes` and `fromText` produce non-empty, correctly-bounded PNGs; blank input rejected; max-edge clamp at 1024.
- **Compose UI tests:** tapping an unsatisfied field stamps the asset (node has placed `contentDescription`); Continue disabled until all required placed; Clear field reverts; overlay re-projects after a simulated rotation (config change) leaving placements visually anchored.
- **Persistence:** DataStore default-signature reuse; Room draft resume after process death (SavedStateHandle + file reload).
- **Acceptance harness:** load a fixture 3-page `PacketDetail` with 2 required signature + 1 initials + 1 date field; assert a captured signature can satisfy all and produce a complete `SignedPacketDraft`.

## 12. Dependencies & Sequencing

- **Depends on AND-341 (PDF rendering):** requires `PageRenderState`/`displayRect` geometry and the page pager host to draw overlays. Hard dependency — overlay coordinates are meaningless without it.
- **Transitively depends on AND-340:** for `PacketDetail` + field schema.
- **Blocks AND-343 (Submit / sign + licenses):** AND-343 consumes the `SignedPacketDraft` and persisted `SignatureAsset` produced here and owns the submit endpoint + license-agreement parity.
- **Sequencing:** land `core-model` field/placement types first (sharable with AND-343), then `SignatureRasterizer` + capture screen, then overlay/placement integrated against AND-341's page host, then validation/Continue handoff.
- **No new third-party libs** beyond stack (Coil for overlay image, Compose graphics for capture). Bundled signature fonts added to `res/font/`.

## 13. Risks & Open Questions

- **R1:** AND-341's geometry contract (`displayRect`, page index base) must be finalized; if it exposes zoom/transform, overlay projection must incorporate it. *Mitigation:* define a thin `PageGeometry` interface jointly with AND-341.
- **R2:** Plaintext dev HTTP — real signatures must not transit until HTTPS. Tracked for AND-343/infra, but note signatures are captured here.
- **R3:** Memory on minSdk 24 low-end devices with large multi-page bitmaps + signature overlays. *Mitigation:* 1024px cap, recycle off-screen overlays.
- **OQ-1:** Should v1 support drag/resize of placements, or snap-to-field only? (Spec assumes snap-to-field; FR-6.)
- **OQ-2:** Do server field rects use top-left or bottom-left origin? Must confirm against `/openapi.json` + `frontend/src/api/types.ts` before integration. (Spec assumes top-left.)
- **OQ-3:** Is `FLAG_SECURE` required on the signing screen to block screenshots of signatures?
- **OQ-4:** Multi-recipient packets — does this device's user sign only fields where `recipientId` matches the session user? (Spec scopes to current user; needs confirmation from AND-340 detail.)

## 14. Acceptance Criteria

- AC-1: A user can draw a signature, clear/undo strokes, and confirm; a transparent PNG asset is produced and persisted.
- AC-2: A user can instead type a name, pick a styled font, and confirm; an equivalent PNG asset is produced.
- AC-3: Tapping a required SIGNATURE/INITIALS field places the captured asset into that field, scaled to fit and anchored to the page; **a signature is visibly placed on the document** (primary acceptance from backlog).
- AC-4: DATE_SIGNED fields auto-fill the current locale-formatted date on placement.
- AC-5: Placements remain correctly anchored after scroll, rotation, and recomposition (normalized-coordinate re-projection).
- AC-6: Progress shows "N of M required complete"; Continue is disabled until all required fields are satisfied and then emits a complete, valid `SignedPacketDraft`.
- AC-7: A placed field can be cleared, reverting it to unsatisfied and decrementing progress.
- AC-8: Saved signature is reused on re-entry without redrawing; "Delete saved signature" removes files + pointer.
- AC-9: Blank/empty captures are rejected with inline validation; rasterization/file errors surface non-fatally.
- AC-10: No signature bytes/PII are logged; assets live only in app-private storage and are excluded from auto-backup.

## 15. Definition of Done

- `feature-signing` module builds (AGP 8.7.3, JDK 17) and is wired into the single-Activity Nav graph at `signing/{packetId}/{documentId}`.
- All FR-1..FR-8 implemented; all AC-1..AC-10 verified by automated tests where feasible (rasterizer, projection, ViewModel reducer, Compose overlay, persistence) plus the acceptance harness fixture.
- `core-model` signing types (`SignatureField`, `FieldPlacement`, `SignedPacketDraft`, `SignatureAsset`) shared and consumed cleanly by AND-343 (verified by a compile-time integration stub).
- StateFlow-based `SigningUiState`, typed `ApiResult` for the optional GET, FastAPI `detail` error mapping, ~20s timeout + bounded backoff + single refresh-retry on 401 all in place.
- Accessibility: TalkBack pass on Type-mode signing path; all controls labeled, >=48dp; progress announced.
- Telemetry events emitted and verified PII-free; Timber logging gated.
- Lint/ktlint/detekt clean; unit + instrumented tests green in CI on `android-port` branch.
- Backup exclusions (`dataExtractionRules`, `fullBackupContent`) cover `signatures/` and `signing_prefs`.
- Code reviewed and merged to `android-port`; downstream AND-343 unblocked.
