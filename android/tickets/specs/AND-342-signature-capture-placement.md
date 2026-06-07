---
id: AND-342
title: Signature capture + placement
milestone: M7
epic: E44
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (CORRECTED):** the real signing client is `src/api/endpoints/signaturePackets.ts` (packet detail, field create/delete, **fill**, send, mark-done, legal-notice, final-pdf) and the screen `src/pages/files/SignaturePacketComposer.tsx`. There is **no** `frontend/src/api/types.ts` `SignatureField`/`SignaturePlacement`/`FieldType` triad as the spec originally claimed; field DTOs live inline in `signaturePackets.ts` as `SignaturePacketField`. Mirror its field-type enum and **normalized x/y/width/height** convention (0..1 within page, top-left origin), **not** a `left/top/right/bottom` rect.
- **Field shape (CORRECTED):** the backend `SignaturePacketField` uses `field_id`, `page` (**1-based** — web sends `page: 1`), `x`, `y`, `width`, `height`, `field_type`, `required`, `assigned_signer_id` / `is_assigned_to_viewer`, `filled_at`, `value`, `capture_mode`, `render_payload`. There is **no** `recipient_id` and **no** `rect{left,top,right,bottom}`.
- **Field-type enum (CORRECTED):** server `SignatureFieldType` = `signature | initials | date | text | notary_stamp`. The spec's `DATE_SIGNED` and `CHECKBOX` do **not** exist; `date` is the date type and `notary_stamp` exists. Auto-fillable here: `signature`, `initials`, `date`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Packet + field metadata is fetched via `GET /v1/signature-packets/{packet_id}` (consumed in this module or upstream); OpenAPI at `/openapi.json`. Cookie-based session with `X-CSRF-Token` header (sourced from the `ui_csrf` cookie — verified in `src/api/client.ts`) applies to every request, including any GET this ticket issues.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Room 2.6 + DataStore, Coil. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.

## 3. Functional Requirements

FR-1 **Draw signature.** A full-screen `SignaturePadScreen` exposes a drawing canvas. Strokes are captured via `pointerInput`/`detectDragGestures`, stored as a list of polylines, rendered live, and rasterized to a transparent-background PNG on confirm. Provide Clear and Undo (last stroke) controls.

FR-2 **Adopt typed signature.** The user may instead type their name and pick from >= 3 bundled signature-style fonts; the rendered text is rasterized to the same PNG asset format. A toggle switches between Draw and Type modes.

FR-3 **Persist & reuse.** On confirm, the signature PNG and a separate initials PNG are stored locally (file + DataStore pointer) as the user's default signature asset, so re-entry pre-fills "Use saved signature" without redrawing.

FR-4 **Field discovery.** On opening a document, enumerate signature fields from the packet detail (`GET /v1/signature-packets/{packet_id}`). Group by `page`, classify by `field_type` (CORRECTED to server enum: `signature`, `initials`, `date`, `text`, `notary_stamp` — only `signature`, `initials`, `date` are auto-fillable here; `notary_stamp`/`text` are out of scope for v1 placement), and compute per-field "required/optional" and "satisfied" status. Treat a field as the viewer's to fill when `is_assigned_to_viewer == true` (CORRECTED — the web client scopes signer fields by `is_assigned_to_viewer`, not by matching a `recipient_id`).

FR-5 **Place signature.** Tapping an unsatisfied `signature`/`initials` field stamps the captured asset into that field's box (`x,y,width,height`, normalized 0..1), scaled to fit while preserving aspect ratio, centered. `date` fields auto-fill the current date in **`YYYY-MM-DD`** format (CORRECTED — the backend validates `date` values against `^\d{4}-\d{2}-\d{2}$`, e.g. `2026-06-05`; render localized for display but submit `YYYY-MM-DD`). Placed fields render an overlay image on top of the AND-341 page bitmap.

FR-6 **Adjust / remove.** A placed signature can be removed (tap → Clear field) returning it to unsatisfied. No free-form drag/resize is required for v1 (placement snaps to field rect); document this as a deliberate constraint.

FR-7 **Progress & guard.** A persistent progress chip shows "N of M required fields complete." The "Continue" action (handing off to AND-343) is disabled until all required fields are satisfied.

FR-8 **Geometry stability.** Placements are stored in **normalized page coordinates**, so they remain correct across scroll, zoom, device rotation, and recomposition. Overlays re-project from normalized rect × current `PageRenderState.displayRect` each frame.

## 4. Technical Design

New module `feature-signing`. Public entry is a Navigation-Compose destination `signing/{packetId}/{documentId}`.

> **CORRECTED to match backend wire contract.** The server enum is `signature | initials | date | text | notary_stamp` (not `DATE_SIGNED`/`CHECKBOX`), fields are `x/y/width/height` (not a 4-corner rect), `page` is **1-based**, and viewer assignment is `is_assigned_to_viewer` (no `recipient_id`). The Kotlin model below keeps an internal `NormalizedRect` for projection convenience, but the Moshi DTO must serialize/deserialize `x/y/width/height` and `field_type` exactly as the backend expects.

```kotlin
// core-model
enum class FieldType { SIGNATURE, INITIALS, DATE, TEXT, NOTARY_STAMP }   // wire: lowercase

data class NormalizedRect(           // top-left origin, 0f..1f within page
    val left: Float, val top: Float, val right: Float, val bottom: Float
) {
    // Wire form is x/y/width/height; convert at the DTO boundary.
    companion object {
        fun fromXywh(x: Float, y: Float, w: Float, h: Float) =
            NormalizedRect(x, y, x + w, y + h)
    }
    val x get() = left; val y get() = top
    val width get() = right - left; val height get() = bottom - top
}

data class SignatureField(
    val id: String,                  // wire: field_id
    val documentId: String,          // local join key (packet detail has no per-field documentId)
    val page: Int,                   // 1-based page index (CORRECTED; web sends page:1)
    val type: FieldType,
    val rect: NormalizedRect,        // built from wire x/y/width/height
    val required: Boolean,
    val assignedSignerId: String?,   // wire: assigned_signer_id (CORRECTED; was recipientId)
    val isAssignedToViewer: Boolean  // wire: is_assigned_to_viewer
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

**Coordinate convention.** Normalized, top-left origin, 0..1 within page — verified against the web client (`src/pages/files/SignaturePacketComposer.tsx` projects `field.x/field.y/field.width/field.height` as CSS `%`, and clamps tap-to-create to `x,y` in 0..0.98). Wire form is `x/y/width/height` (CORRECTED — not `left/top/right/bottom`, and not in `frontend/src/api/types.ts`, which does not define these). All persistence and the internal `SignedPacketDraft` use normalized coords; pixel math never leaves the composable layer.

## 5. API Contract

> **CORRECTED — the originally-cited endpoints do not exist.** The spec claimed `GET /ui/documents/{documentId}/fields` for field hydration and `POST /ui/packets/{packetId}/sign` for downstream submit. **Neither path exists** in the backend. The real, authoritative signing surface is the `/v1/signature-packets/*` family (verified in OpenAPI index lines 2413–2421 and `src/api/endpoints/signaturePackets.ts`). There is also no single "submit the whole signed packet" call: signing is **server-driven, field-by-field**.

**Packet/field hydration (this module or upstream):**
```
GET /v1/signature-packets/{packet_id}                      // op=get_signature_packet_detail
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>; Authorization: Bearer <token>
200 -> SignaturePacketDetailOut {
  packet_id, status, owner_user_id, source_path, role: "sender"|"signer",
  signer_status?, created_at?, sent_at?, completed_at?,
  signers: [...], fields: [ SignaturePacketField ], capabilities: { ... }, legal_notice?
}
// SignaturePacketField: { field_id, page, x, y, width, height, field_type,
//   required, assigned_signer_id?, is_assigned_to_viewer?, filled_at?, value?,
//   capture_mode?, render_payload? }   (normalized 0..1; page is 1-based)
```
Moshi maps `field_type` (lowercase) -> `FieldType`, `assigned_signer_id` -> `assignedSignerId`, `is_assigned_to_viewer` -> `isAssignedToViewer`, and converts `x/y/width/height` -> internal `NormalizedRect`. Errors map through the shared FastAPI `detail` decoder (`string | [{msg}] | {code,...}`; verified in `src/api/client.ts: normalizeErrorDetail`) into `ApiResult<...>`. 422 returns `HTTPValidationError` (`{detail:[{loc,msg,type}]}`). This GET is idempotent: eligible for bounded backoff (max 2 retries, ~20s timeout). A 401 (only when already authenticated) triggers a single `POST /ui/session/refresh` then one retry — confirmed in `src/api/client.ts` (the web wrapper applies refresh-then-retry to **all** methods, not GET only).

**Field fill (CORRECTED — this is how a placement actually persists server-side).** The web client does not upload a rasterized PNG; it posts per-field values:
```
POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill   // op=fill_signature_packet_field
Body (SignaturePacketFieldFillIn): {
  "input_mode": "typed"|"drawn"|null,
  "value": "<string>"|null,             // typed signature/initials, date (YYYY-MM-DD), text
  "drawn_strokes": number[][]|null,     // drawn mode: array of [x,y] points, normalized 0..1
  "notary_stamp": NotaryStampFieldIn|null
}
200 -> SignaturePacketFieldFillOut { packet_id, field_id, value, filled_at, filled_by_signer_id, capture_mode? }
```
Web validation (mirror in `SigningViewModel`): typed signature/initials non-empty and <= 64 chars; drawn mode requires 2..20 points, each `[x,y]` within 0..1; `date` must match `YYYY-MM-DD`; `text` <= 500 chars (required only if `field.required`).

**Other packet operations (owned by AND-343 / sender flows, listed for accuracy):** `POST /v1/signature-packets/{packet_id}/fields` (create/update/delete field; `action` enum), `POST .../send`, `POST .../mark-done` (finalize signer — gated by zero remaining required + legal-notice accepted), `POST .../acknowledge-legal-notice`, `GET .../final-pdf` (binary). **AND-343 does NOT own a `POST /ui/packets/{packetId}/sign` — that endpoint is fictional; the real finalize is `POST /v1/signature-packets/{packet_id}/mark-done`.**

**Scope reconciliation (assumption flagged).** This ticket's stated scope is a local, offline editing surface emitting an in-memory `SignedPacketDraft`. The backend has **no** equivalent "draft blob" submit; the contract is incremental `fill` calls. The local `SignedPacketDraft` model is therefore an *internal* representation only; whoever performs server persistence (this module's repo or AND-343) must translate each `FieldPlacement` into a `fill` call. This divergence is an **unverified design assumption** — see §16 Open assumptions.

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
  - Field-type mapping (lowercase server enum `signature|initials|date|text|notary_stamp` → `FieldType`) and Moshi adapter for `assigned_signer_id`/`is_assigned_to_viewer` and `x/y/width/height` → `NormalizedRect` (CORRECTED — no `recipient_id`/`rect` on the wire).
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
- **OQ-2:** ~~Do server field rects use top-left or bottom-left origin?~~ **RESOLVED:** verified top-left origin, normalized 0..1, wire shape `x/y/width/height` (web `SignaturePacketComposer.tsx` renders these directly as CSS top/left %). Also resolved: `page` is **1-based**, not 0-based.
- **OQ-3:** Is `FLAG_SECURE` required on the signing screen to block screenshots of signatures?
- **OQ-4:** Multi-signer packets — does this device's user sign only their fields? **RESOLVED:** the web client scopes signer-fillable fields by `is_assigned_to_viewer == true` (server-computed), not by client-side matching of `assigned_signer_id` to the session user. Mirror that.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec (`reference/openapi.pretty.json`, `components.schemas.<Name>`), or frontend (`reference/src/...`).

1. **Field/document fields fetched via `GET /ui/documents/{documentId}/fields`.** VERDICT: **Corrected.** No such endpoint exists. SOURCE: absent from OpenAPI index; real detail endpoint is `GET /v1/signature-packets/{packet_id}` (op=`get_signature_packet_detail`, index line 2414) returning `SignaturePacketDetailOut` with embedded `fields[]`, and `src/api/endpoints/signaturePackets.ts: getSignaturePacketDetail`.
2. **Downstream submit is `POST /ui/packets/{packetId}/sign`.** VERDICT: **Corrected.** Fictional path. SOURCE: absent from OpenAPI index. Real finalize is `POST /v1/signature-packets/{packet_id}/mark-done` (op=`mark_signature_packet_done`, index line 2420) and per-field `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill` (index line 2418); `src/api/endpoints/signaturePackets.ts: markSignaturePacketDone, fillSignaturePacketField`.
3. **Field coordinate convention is `rect{left,top,right,bottom}`.** VERDICT: **Corrected.** Wire shape is `x, y, width, height` (normalized 0..1). SOURCE: `components.schemas.SignaturePacketFieldMutationIn` (`x,y,width,height` props, openapi.pretty.json L67506–67609); `src/api/endpoints/signaturePackets.ts: SignaturePacketField` (L23–38); `src/pages/files/SignaturePacketComposer.tsx` (L619–624) renders `field.x/y/width/height` as CSS %.
4. **Coordinate origin is top-left, normalized 0..1.** VERDICT: **Verified.** SOURCE: `SignaturePacketComposer.tsx` L230–231 clamps tap to `(clientX-left)/width` and `(clientY-top)/height` in 0..0.98; overlay L619–624 maps x→left%, y→top%.
5. **Page index is 0-based.** VERDICT: **Corrected → 1-based.** SOURCE: `SignaturePacketComposer.tsx` L240 sends `page: 1` for the first page; `SignaturePacketFieldMutationIn.page` is an integer with no documented 0-base (openapi.pretty.json L67560).
6. **Field-type enum = `SIGNATURE, INITIALS, DATE_SIGNED, TEXT, CHECKBOX`.** VERDICT: **Corrected.** Real enum = `signature, initials, date, text, notary_stamp`. SOURCE: `components.schemas.SignatureFieldType` (openapi.pretty.json L67191–67201); `src/api/endpoints/signaturePackets.ts: SignatureFieldType` (L5). No `DATE_SIGNED`/`CHECKBOX`; `date` and `notary_stamp` exist.
7. **Field carries `recipient_id`; viewer signs fields matching their recipient id.** VERDICT: **Corrected.** Field uses `assigned_signer_id`; viewer scoping is the server-computed `is_assigned_to_viewer`. SOURCE: `src/api/endpoints/signaturePackets.ts: SignaturePacketField` (L32–33) and `SignaturePacketComposer.tsx: isFieldAssignedToSigner` (L86–88) which checks `is_assigned_to_viewer`.
8. **Date fields format as locale string like `2026-06-05`.** VERDICT: **Corrected/clarified.** Submitted value must match `YYYY-MM-DD`. SOURCE: `SignaturePacketComposer.tsx: validateFieldInput` (L73–77) regex `^\d{4}-\d{2}-\d{2}$`. Display may be localized; wire value is ISO date.
9. **Auth uses cookie session + `X-CSRF-Token` header.** VERDICT: **Verified.** SOURCE: `src/api/client.ts` L168–171 sets `X-CSRF-Token` from the `ui_csrf` cookie on every request; `credentials: "include"` L183.
10. **401 triggers one `POST /ui/session/refresh` then a single retry.** VERDICT: **Verified (with nuance).** SOURCE: `src/api/client.ts: refreshSession` (L121–130) posts `/ui/session/refresh`; L194–237 performs refresh-then-single-retry. Nuance: applies to **all** methods (not GET-only as spec implied) and **only when already authenticated** (L196); unauthenticated 401 propagates.
11. **FastAPI `detail` decoder handles `string | [{msg}] | {code,...}`.** VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail` (L66–102); 422 body is `HTTPValidationError {detail:[{loc,msg,type}]}` per OpenAPI 422 responses.
12. **Drawn signature is a rasterized transparent PNG submitted to the server.** VERDICT: **Corrected (contract mismatch).** The backend `fill` accepts `drawn_strokes: number[][]` (array of `[x,y]` points), not a PNG. SOURCE: `components.schemas.SignaturePacketFieldFillIn` (openapi.pretty.json L67403–67460, `drawn_strokes` = array of array of number); `src/api/endpoints/signaturePackets.ts: fillSignaturePacketField` (L112–120). The PNG is a valid local rendering choice, but server persistence uses strokes/typed value — see Open assumptions.
13. **Drawn-stroke validation bounds.** VERDICT: **Verified.** SOURCE: `SignaturePacketComposer.tsx: validateFieldInput` (L62–71): 2..20 points, each `[x,y]` in 0..1. Typed signature/initials non-empty and <= 64 chars (L57–60); text <= 500 (L78–82).
14. **`mark-done` gated until all required fields filled + legal notice accepted.** VERDICT: **Verified.** SOURCE: `SignaturePacketComposer.tsx` L451–457 disables Mark done when `remainingRequiredCount > 0 || legalNoticeRequired`; `remainingRequiredCount` (L133–136) counts `required && !filled_at` over viewer fields.
15. **A legal-notice acknowledgement step exists before completion.** VERDICT: **Verified.** SOURCE: `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice` (op=`acknowledge_signature_packet_legal_notice`, index L2415); `acknowledgeSignaturePacketLegalNotice` and `legal_notice` panel (`SignaturePacketComposer.tsx` L461–474). Note: the spec omits the legal-notice gate entirely — flagged in Open assumptions as a scope gap for AND-343.
16. **Signature PNGs are biometric-adjacent PII → app-private `filesDir` only, excluded from auto-backup.** VERDICT: **Unverified-assumption (Android framework policy).** No backend/frontend source governs on-device storage. Framework ref: app-specific internal storage (developer.android.com/training/data-storage/app-specific#internal) and backup exclusion via `android:dataExtractionRules`/`fullBackupContent` (developer.android.com/guide/topics/data/autobackup#IncludingFiles). Reasonable, kept as assumption.
17. **`PdfRenderer` / `PageRenderState.displayRect` geometry comes from AND-341.** VERDICT: **Unverified-assumption (cross-ticket).** No source in this repo defines AND-341's contract; depends on AND-341 deliverable. Framework ref: `android.graphics.pdf.PdfRenderer` (developer.android.com/reference/android/graphics/pdf/PdfRenderer).
18. **Min/compile/target SDK 24/35/35, Kotlin 2.0.21, AGP 8.7.3, Compose/Hilt/Room.** VERDICT: **Unverified-assumption (project stack).** Declared by the Android port program, not derivable from backend/frontend sources. Carried as project-wide given.

### Corrections made
- §2/§4/§5/§11: Endpoint family corrected from non-existent `/ui/documents/.../fields` + `/ui/packets/.../sign` to the real `/v1/signature-packets/*` set (detail, fields, fill, send, mark-done, acknowledge-legal-notice, final-pdf).
- §2/§4/§5/§11: Field shape corrected from `rect{left,top,right,bottom}` + `recipient_id` to `x/y/width/height` + `assigned_signer_id`/`is_assigned_to_viewer`.
- §2/§3/§4: Field-type enum corrected (`DATE_SIGNED`/`CHECKBOX` removed; `date`/`notary_stamp` added; lowercase wire values).
- §3/§4/§13: Page index corrected to 1-based.
- §3/§5: Date format corrected to `YYYY-MM-DD` wire value.
- §5: Documented the real field-fill contract (`SignaturePacketFieldFillIn`: `input_mode`, `value`, `drawn_strokes`) and noted the PNG-vs-strokes divergence.
- §5: Clarified 401 refresh-retry applies to all methods and only when authenticated.
- §13: OQ-2 (origin) and OQ-4 (multi-signer scoping) resolved against sources.

### Open assumptions (unverifiable from sources)
- **Local `SignedPacketDraft` "draft blob" model.** The backend has no whole-packet submit; signing is incremental `fill` calls. The in-memory draft is an internal convenience only; the mapping from `FieldPlacement` → `fill` request (typed `value` vs `drawn_strokes`) must be implemented by this module's repo or AND-343. Cannot verify a "submit unchanged" contract because none exists server-side. (Source: absence of any draft-submit endpoint in OpenAPI index.)
- **PNG rasterization for drawn signatures.** Server persists `drawn_strokes` (points) and typed `value`, not PNGs. A locally-rendered PNG is fine for on-device preview/overlay but is not the wire format; if server-rendered rendering is required, only strokes/value transit. Whether the Android app should also retain a PNG is a product decision, unverifiable here.
- **Legal-notice gate not modeled in this spec.** The real flow requires `acknowledge-legal-notice` before `mark-done` when `legal_notice.required`. This ticket scopes to capture/placement and defers finalize to AND-343, so the gate is noted but not implemented; confirm ownership with AND-343.
- **On-device PII storage / backup exclusion** (claim 16) — Android policy choice, no source authority.
- **AND-341 geometry contract** (claim 17) and **project SDK/library stack** (claim 18) — external to the verifiable sources.
- **`FLAG_SECURE` on the signing screen** (OQ-3) — no source mandates it; product/security decision.

## 17. Test Plan

Test target keys: **JVM** (local JVM unit/Robolectric, no device); **EMU** (headless AVD `test35`, x86_64, Android 15/API 35); **DEV** (physical Samsung Galaxy A15 5G `SM-A156U`, serial `R5CX821TA9R`, Android 14/API 34, arm64-v8a). Contract tests use MockWebServer. Error shapes use the real `HTTPValidationError`/FastAPI `detail` forms verified in §16.

- **TC-AND-342-01** — Type: unit (JVM). Target: JVM. Preconditions: `NormalizedRect.fromXywh` + projection helper. Steps: round-trip a set of `(x,y,w,h)` boxes through `NormalizedRect` → pixels (across several `displayRect` sizes and a rotated/landscape rect) → back to normalized. Expected: values equal within float tolerance; `x==left`, `width==right-left`; no drift after rotation. Traces: AC-5.
- **TC-AND-342-02** — Type: unit (JVM). Target: JVM. Preconditions: `SignedPacketDraft` with mixed required/optional, multi-page, and a `date` field. Steps: assert `unsatisfiedRequired` and `isComplete` before/after placing each required field. Expected: optional fields never block; `isComplete` flips true only when all required satisfied. Traces: AC-6.
- **TC-AND-342-03** — Type: unit (JVM, Turbine). Target: JVM. Preconditions: `SigningViewModel` with fake repos. Steps: capture → `onPlaceField` (signature) → `onPlaceField` (initials) → `onClearField`; collect `uiState`. Expected: `requiredDone` increments/decrements correctly; `canContinue` false until all required placed; `onContinue()` returns null while incomplete, non-null complete draft when done. Traces: AC-3, AC-6, AC-7.
- **TC-AND-342-04** — Type: unit (JVM). Target: JVM. Preconditions: Moshi adapters for `SignaturePacketField`. Steps: decode a real `SignaturePacketDetailOut` fixture (lowercase `field_type`, `x/y/width/height`, `assigned_signer_id`, `is_assigned_to_viewer`, `page:1`). Expected: `field_type` → `FieldType` enum; `x/y/width/height` → `NormalizedRect`; `is_assigned_to_viewer` mapped; unknown `field_type` (`notary_stamp`) handled without crash (mapped or skipped). Traces: AC-3, AC-4.
- **TC-AND-342-05** — Type: unit (JVM). Target: JVM. Preconditions: fill-request builder + validators mirroring web rules. Steps: build fill bodies for typed signature (>64 chars rejected), drawn (1 point rejected, 2..20 accepted, point outside 0..1 rejected), date (`YYYY-MM-DD` accepted, `06/05/2026` rejected), text (>500 rejected). Expected: validators match §16 claim 13; typed→`{input_mode:"typed",value}`, drawn→`{input_mode:"drawn",drawn_strokes:[[x,y]...]}`. Traces: AC-1, AC-2, AC-4, AC-9.
- **TC-AND-342-06** — Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns a valid `SignaturePacketDetailOut`. Steps: call packet-detail GET; assert request path `/v1/signature-packets/{id}`, `X-CSRF-Token` header present, `Cookie`/credentials sent; parse response. Expected: correct path/method/headers; fields hydrated. Traces: AC-3.
- **TC-AND-342-07** — Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns 422 `HTTPValidationError {detail:[{loc,msg,type}]}` then (separate case) 403 with `{detail:{code:"role_required"}}`. Steps: issue detail GET; map error. Expected: 422 surfaces joined `msg` strings; 403 maps via `normalizeErrorDetail`; result is `ApiResult` error, no crash. Traces: AC-9.
- **TC-AND-342-08** — Type: contract/MockWebServer. Target: JVM. Preconditions: first GET → 401, `/ui/session/refresh` → 200, retried GET → 200. Steps: issue detail GET while "authenticated". Expected: exactly one `POST /ui/session/refresh`, then a single retry that succeeds; only-when-authenticated guard honored (unauthenticated 401 case propagates without refresh). Traces: AC-9.
- **TC-AND-342-09** — Type: contract/MockWebServer (offline/flaky-host). Target: JVM. Preconditions: MockWebServer set to drop connection / delay beyond ~20s timeout for N attempts. Steps: issue idempotent detail GET. Expected: bounded backoff (max 2 retries), ~20s timeout enforced; on exhaustion → `SigningUiState.Error(retryable=true)`; falls back to in-memory packet fields if available; no crash. Traces: AC-9.
- **TC-AND-342-10** — Type: Robolectric/instrumented. Target: EMU (Robolectric on JVM acceptable; EMU for true Canvas). Preconditions: `SignatureRasterizer`. Steps: `fromStrokes` with a polyline and `fromText` with a name+font produce PNGs; feed blank strokes and empty name. Expected: non-empty, ink-bounded PNGs; blank input rejected (no asset); max edge clamped at 1024px. Traces: AC-1, AC-2, AC-9.
- **TC-AND-342-11** — Type: Compose-UI. Target: EMU. Preconditions: fixture packet (2 required signature + 1 initials + 1 date), captured asset. Steps: tap each unsatisfied field → assert overlay placed (node gains "signed" `contentDescription`); assert Continue disabled until all required placed; tap Clear field → reverts to unsatisfied and decrements progress chip. Expected: placement visible (AC-3), date auto-fills `YYYY-MM-DD` (AC-4), Continue gating (AC-6), clear/revert (AC-7). Traces: AC-3, AC-4, AC-6, AC-7.
- **TC-AND-342-12** — Type: Compose-UI (config change). Target: EMU. Preconditions: placements made on multi-page doc. Steps: trigger rotation/recompose (recreate activity), scroll. Expected: overlays re-project from normalized rect × current `displayRect` and stay anchored to the same field box; no pixel-persisted drift. Traces: AC-5.
- **TC-AND-342-13** — Type: Compose-UI (accessibility). Target: EMU. Preconditions: TalkBack/semantics assertions. Steps: traverse Type-mode path; assert all controls (Clear, Undo, Use saved, Place, Clear field, Continue) have `contentDescription` and >=48dp targets; field overlay exposes "Signature field, required, not signed" → updates on placement; progress chip `liveRegion = Polite`. Expected: full a11y labels and live announcement; Type mode is a complete non-drawing path. Traces: AC-2, AC-3, AC-7.
- **TC-AND-342-14** — Type: instrumented (persistence + security). Target: DEV (physical device preferred — validates real app-private storage + auto-backup exclusion on API 34/arm64; EMU acceptable as smoke). Preconditions: capture + save default signature. Steps: confirm PNGs written under `filesDir/signatures/` (not external/MediaStore); kill+relaunch → "Use saved signature" pre-fills without redraw; "Delete saved signature" removes files + clears DataStore pointer; inspect Logcat during capture/place. Expected: assets app-private only; reuse works; delete clears; **no** signature bytes/strokes/names/file contents in logs; `signatures/` + `signing_prefs` excluded from auto-backup. Traces: AC-8, AC-10.
- **TC-AND-342-15** — Type: integration (acceptance harness). Target: EMU. Preconditions: fixture 3-page packet (2 required signature + 1 initials + 1 date). Steps: capture one signature, auto-satisfy all required fields, build draft, then map placements to per-field `fill` request bodies (typed/drawn/date) and assert each matches `SignaturePacketFieldFillIn`. Expected: a complete, valid internal `SignedPacketDraft`; every required field translates to a valid `fill` body (confirming the §16 draft→fill assumption is implementable). Traces: AC-3, AC-4, AC-6.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (draw → PNG asset) | TC-05, TC-10 |
| AC-2 (type → PNG asset) | TC-05, TC-10, TC-13 |
| AC-3 (place signature visibly anchored) | TC-03, TC-04, TC-06, TC-11, TC-13, TC-15 |
| AC-4 (date auto-fill `YYYY-MM-DD`) | TC-04, TC-05, TC-11, TC-15 |
| AC-5 (anchored after scroll/rotation/recompose) | TC-01, TC-12 |
| AC-6 (progress + Continue gate → valid draft) | TC-02, TC-03, TC-11, TC-15 |
| AC-7 (clear field reverts + decrements) | TC-03, TC-11, TC-13 |
| AC-8 (saved signature reuse + delete) | TC-14 |
| AC-9 (blank rejected; errors non-fatal) | TC-05, TC-07, TC-08, TC-09, TC-10 |
| AC-10 (no PII logged; app-private; backup-excluded) | TC-14 |
