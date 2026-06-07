---
id: AND-343
title: Submit / sign + licenses
milestone: M7
epic: E44
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-342, AND-339, AND-340, AND-341]
blocks: [AND-344]
---

# AND-343 — Submit / sign + licenses

## 1. Overview & Goal

> **REVIEW CORRECTION (2026-06-06):** This spec was originally written against an
> assumed `/ui/signing/packets/{packetId}/submit` + `/licenses` + `/licenses/accept`
> contract that **does not exist** in the backend. The real signature-packet API is
> the `/v1/signature-packets/{packet_id}/...` family (see §5). The terminal "submit /
> sign" action is **`POST /v1/signature-packets/{packet_id}/mark-done`** (empty body),
> not a bulk submit with `field_values` + `accepted_licenses`. Fields are filled
> **individually** via `POST .../fields/{field_id}/fill` (upstream AND-342), not
> flushed as one array on submit. The legal/consent gate is the packet's
> **`legal_notice`** object plus **`POST .../acknowledge-legal-notice`**, NOT a
> separate "license agreements" endpoint. The backlog ticket's `licenseAgreements.ts`
> reference points at an **unrelated content-licensing CRUD module** (royalty-free /
> creative-commons licenses for video/post/broadcast content) — see §16 audit. The
> sections below have been corrected in place; original incorrect claims are noted.

This ticket delivers the terminal step of the e-signing flow: taking a fully
prepared signature packet — document(s) rendered (AND-341), signature drawn or
adopted and placed onto required fields (AND-342) — and **submitting the signed
packet to the backend, surfacing license/consent agreements that gate that
submission, and confirming the signed/completed result** to the user.

The user-visible outcome: from a packet whose required signature and data fields
are satisfied, the user accepts any outstanding **legal notice** (the per-packet
legal consent required before completing is binding; the `legal_notice` object on
the packet detail), taps **Mark done**, and receives an explicit, durable
confirmation that the packet is now in a terminal state (`completed`).
[Corrected: backend terminal/completed status is `completed`; there is no `signed`
status — the status enum is `draft | sent | partially_signed | completed |
cancelled | expired`. See §16.]

Scope per the backlog ticket is narrow and additive: (a) the **mark-done (submit /
sign)** action and confirmation UX, and (b) the per-packet **legal-notice
acceptance** data path. [Corrected: the backlog literally names `licenseAgreements.ts`,
but that frontend module is an unrelated *content-licensing CRUD* surface
(`/ui/licenses/agreements`, license types like royalty_free/commercial) and is NOT
part of the signing flow. The signing legal gate is `legal_notice` +
`acknowledge-legal-notice`. This is flagged as the headline correction in §16; if
the backlog truly intends content-licensing CRUD, this ticket is mis-scoped and
needs product clarification.] It does **not** include packet
listing (AND-340), PDF rendering (AND-341), signature capture/placement
(AND-342), or the orchestrating `SigningViewModel` (AND-344) — it exposes
repository methods and a focused submit/confirm Compose surface that AND-344
wires into the full state machine.

## 2. Context & References

- Epic **E44** (Signing / e-sign), milestone **M7**.
- Upstream:
  - **AND-339** — `signaturePackets.ts` / `signatureTemplates.ts` DTO port. Owns
    `SignaturePacketDto`, `SignatureFieldDto`, status enums, Moshi adapters.
  - **AND-340** — packet list + detail; provides `packetId` and the loaded
    `SignaturePacket` domain object this ticket submits.
  - **AND-341** — PDF rendering of document pages.
  - **AND-342** — signature capture + field placement; produces the
    in-memory/uploaded signature artifacts and per-field placement payloads that
    this ticket flushes on submit. **Hard dependency (Deps: AND-342).**
- Downstream:
  - **AND-344** — `SigningViewModel` state machine consumes
    `SigningRepository.submitPacket(...)` and license methods defined here.
- Web reference: `src/api/endpoints/signaturePackets.ts` (authoritative for this
  ticket — `fillSignaturePacketField`, `markSignaturePacketDone`,
  `acknowledgeSignaturePacketLegalNotice`, `downloadSignaturePacketFinalPdf`) and
  the signer flow in `src/pages/files/SignaturePacketComposer.tsx`. Shared types in
  `src/api/types.ts`. [Corrected: `licenseAgreements.ts` is NOT relevant — it is
  content-licensing CRUD, not signing consent; see §16.] Backend OpenAPI at
  `/openapi.json` (dev host `http://18.222.237.167:8000`, plaintext, unreliable —
  design accordingly). Auth verified in `src/api/client.ts`: Bearer access token +
  `X-CSRF-Token` (from `ui_csrf` cookie) + cookies (`credentials: include`); a
  single 401 → `POST /ui/session/refresh` retry.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. Cookie + `X-CSRF-Token` auth with
  401→`/ui/session/refresh` retry (AND-011/012/013), `ApiResult<T>` (AND-018),
  FastAPI `detail` mapping (AND-015). Module: `feature-signing` →
  `core-network`, `core-model`, `core-data`, `core-ui`.
- Canonical namespace: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **Legal notice presentation.** [Corrected from "license agreement fetch".]
The legal notice applicable to the packet is **not fetched separately** — it is
carried inline on the packet detail (`SignaturePacketDetail.legal_notice`) loaded
by AND-340: `{ required: boolean, accepted: boolean, version: string, text: string }`.
When the submit surface is presented, the app reads this object. The notice has a
`version`, full `text`, and `required`/`accepted` flags. It is shown only when
`role == "signer"` and `legal_notice` is present.

FR-2. **Legal notice acceptance UI.** [Corrected from multi-checkbox license UI.]
When `legal_notice.required` is true, the notice text (full, scrollable) and its
`version` are displayed with a single **"I acknowledge and agree"** action. The
**Mark done** action is disabled until the legal notice is acknowledged (i.e.,
until `legal_notice.required` is no longer true after re-load).

FR-3. **Legal notice acknowledgement recording.** [Corrected: there is no
`/licenses/accept`.] On acknowledge, the app calls
`POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice` (empty body),
then re-loads the packet detail so `legal_notice.required`/`accepted` reflect the
new state. The endpoint takes **no body** (no id/version array is sent — the server
records the current notice version). Re-acknowledging is treated as idempotent at
the UI level (button hidden once accepted).

FR-4. **Mark done (submit / sign signed packet).** [Corrected from a bulk
`/submit` with `field_values` + `accepted_licenses`.] Field values are filled
**individually upstream** by AND-342 via
`POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill`
(`{ value?, input_mode?: "typed"|"drawn", drawn_strokes?, notary_stamp? }`). When all
required fields are filled (`remaining_required == 0`) and any required legal notice
is acknowledged, **Mark done** calls
`POST /v1/signature-packets/{packet_id}/mark-done` with an **empty body** to commit
the signer's completion. There is no aggregate field-values payload on this call.

FR-5. **In-flight UX.** During submission the action shows a non-cancellable
progress state (button → spinner, surface blocks duplicate taps). Submission is
**non-idempotent** (a sign action) and must not auto-retry.

FR-6. **Confirmation.** On success (`mark-done` → `200 SignaturePacketMarkDoneOut`
`{ packet_id, signer_id, signer_status, packet_status, completed_at }`) the app
shows an explicit confirmation: terminal `packet_status` (`completed`), the
`completed_at` timestamp, and a **"Download completed PDF"** affordance that calls
`GET /v1/signature-packets/{packet_id}/final-pdf` (binary stream). [Corrected:
there is **no** `certificate_url` field; the final-PDF endpoint is the download
reference, available only when `status == "completed"`.] The packet transitions to
its terminal state in cache. The confirmation is dismissible back to the packet
list (AND-340).

FR-7. **Failure handling.** On failure the submit surface returns to the
actionable state with a mapped, human-readable error and a manual **Retry**
affordance (see §7). Field/validation errors (e.g., missing required field) are
surfaced inline where possible.

FR-8. **Already-completed / non-actionable guard.** If the packet is already
terminal (`completed` / `cancelled` / `expired`) [Corrected: real enum — no
`signed`/`declined`/`voided`] or the signer's own `signer_status == "completed"`,
the Mark-done action is hidden and the confirmation/terminal view is shown instead.

## 4. Technical Design

Package root: `com.testlogon.android.feature.signing`.

### 4.1 Legal-notice + result DTOs / domain (CORRECTED)

[Corrected: the original `LicenseAgreement`/`LicenseAcceptanceDto`/`SubmitPacket*`
DTOs do not match the backend. The legal notice is an inline object on the packet
detail (owned by AND-340's `SignaturePacketDetailOut` port), and the result is
`SignaturePacketMarkDoneOut`. Field names below are taken verbatim from the OpenAPI
schemas.]

```kotlin
// core-model :: com.testlogon.android.core.model.signing
// Read off SignaturePacketDetail.legal_notice (loaded by AND-340).
data class LegalNotice(
    val required: Boolean,
    val accepted: Boolean,
    val version: String,
    val text: String,
)

// Result of mark-done (the terminal submit/sign).
data class SubmitResult(
    val packetId: String,
    val signerId: String,
    val signerStatus: String,        // e.g. "completed"
    val packetStatus: PacketStatus,  // from AND-339; terminal = "completed"
    val completedAt: Instant,        // required, non-null in MarkDoneOut
)
```

```kotlin
// core-network :: com.testlogon.android.core.network.signing.dto
// legal_notice is part of SignaturePacketDetailOut (AND-340). Shape:
@JsonClass(generateAdapter = true)
data class LegalNoticeDto(
    @Json(name = "required") val required: Boolean,
    @Json(name = "accepted") val accepted: Boolean,
    @Json(name = "version") val version: String,
    @Json(name = "text") val text: String,
)

// POST .../acknowledge-legal-notice — NO request body. Response:
@JsonClass(generateAdapter = true)
data class LegalNoticeAckDto(                  // SignaturePacketLegalNoticeAckOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "signer_id") val signerId: String,
    @Json(name = "accepted") val accepted: Boolean,
    @Json(name = "notice_version") val noticeVersion: String,
)

// POST .../mark-done — NO request body. Response (all fields required):
@JsonClass(generateAdapter = true)
data class MarkDoneDto(                        // SignaturePacketMarkDoneOut
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "signer_id") val signerId: String,
    @Json(name = "signer_status") val signerStatus: String,
    @Json(name = "packet_status") val packetStatus: String,
    @Json(name = "completed_at") val completedAt: String,
)

// Per-field fill is upstream (AND-342) but the shape is shown for traceability.
// POST .../fields/{field_id}/fill — SignaturePacketFieldFillIn:
@JsonClass(generateAdapter = true)
data class FieldFillRequestDto(
    @Json(name = "value") val value: String? = null,
    @Json(name = "input_mode") val inputMode: String? = null, // "typed"|"drawn"
    @Json(name = "drawn_strokes") val drawnStrokes: List<List<Double>>? = null,
    // @Json(name="notary_stamp") notaryStamp: NotaryStampFieldIn? (notary fields)
)
```

Field-fill DTOs are owned by AND-339/342; this ticket consumes the resulting filled
state. All field names above are verified against `/openapi.json`
(`SignaturePacketMarkDoneOut`, `SignaturePacketLegalNoticeAckOut`,
`SignaturePacketFieldFillIn`); adapters live with the other signing DTOs from AND-339.

### 4.2 API surface (Retrofit)

```kotlin
// core-network :: com.testlogon.android.core.network.signing
// [Corrected: real paths are /v1/signature-packets/{packet_id}/...; legal notice
// is acknowledged (no body), there is no GET-licenses or accept-licenses-array.]
interface SigningApi {           // extended from AND-339; new methods here
    // Legal-notice acknowledgement (empty body).
    @POST("v1/signature-packets/{packetId}/acknowledge-legal-notice")
    suspend fun acknowledgeLegalNotice(
        @Path("packetId") packetId: String,
    ): Response<LegalNoticeAckDto>

    // Terminal submit / sign (empty body).
    @POST("v1/signature-packets/{packetId}/mark-done")
    suspend fun markDone(
        @Path("packetId") packetId: String,
    ): Response<MarkDoneDto>

    // Completed-PDF download (binary; only when status == "completed").
    @Streaming
    @GET("v1/signature-packets/{packetId}/final-pdf")
    suspend fun getFinalPdf(
        @Path("packetId") packetId: String,
    ): Response<ResponseBody>

    // NOTE: per-field fill (POST .../fields/{fieldId}/fill) and detail GET (which
    // carries legal_notice) belong to AND-342 / AND-340 respectively.
}
```

### 4.3 Repository

```kotlin
// core-data :: com.testlogon.android.core.data.signing
// [Corrected: legal-notice acknowledge (no body) + mark-done (no body) + final-pdf.
// No loadLicenses/acceptLicenses array, no idempotencyKey, no fieldValues payload.]
interface SigningRepository {     // partial — submit/legal-notice additions
    suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit>
    suspend fun submitPacket(packetId: String): ApiResult<SubmitResult> // mark-done
    suspend fun downloadFinalPdf(packetId: String): ApiResult<ByteArray> // or Uri/stream
}
```

`SigningRepositoryImpl` (Hilt `@Singleton`, `@Inject constructor`) maps DTO↔domain
via mappers in `core-network`, wraps calls in the shared
`Response<T>.toApiResult { map }` helper (AND-018), and on `mark-done` success writes
the terminal `PacketStatus` (`completed`) and `completedAt` into the Room cache row
created by AND-340 so the list reflects the new state offline. [Corrected: there is
**no** `idempotency_key` parameter on `mark-done` in the backend contract. The
"defend against timeout-after-commit" concern is instead handled by re-loading the
packet detail on retry and treating an already-`completed` packet as success — see
§7. A client-generated idempotency key would be silently ignored.]

### 4.4 Compose submit surface (this ticket's UI)

A self-contained, stateless composable consumed by AND-344's screen:

```kotlin
// feature-signing :: com.testlogon.android.feature.signing.submit
@Composable
fun SubmitSignSection(
    state: SubmitUiState,
    onAcknowledgeLegalNotice: () -> Unit,
    onSubmit: () -> Unit,            // "Mark done"
    onRetry: () -> Unit,
    onDownloadFinalPdf: () -> Unit,
    onDoneToList: () -> Unit,
    modifier: Modifier = Modifier,
)

// [Corrected: single legal-notice gate (not a list of license checkboxes).]
data class SubmitUiState(
    val legalNotice: LegalNotice?,       // null if none on this packet
    val remainingRequiredFields: Int,    // from AND-342 fill state
    val phase: Phase,
    val canSubmit: Boolean,              // remainingRequiredFields==0 &&
                                         // (legalNotice==null || !legalNotice.required) &&
                                         // phase==IDLE
    val result: SubmitResult? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { LOADING, IDLE, ACKNOWLEDGING, SUBMITTING, CONFIRMED, ERROR }
}
```

`canSubmit` is derived in AND-344's reducer; this ticket defines the contract
and renders accordingly. The submit button is the only enabled control while
`SUBMITTING`. The `CONFIRMED` phase swaps the section for a confirmation card with
the **Download completed PDF** action.

## 5. API Contract

Base URL from build flavor (AND-006). All requests carry the session cookies +
`X-CSRF-Token` + Bearer access token (verified in `src/api/client.ts`, AND-012);
401 triggers a single `POST /ui/session/refresh` retry (AND-013). Endpoints below
are **verified** against `/openapi.json` and `signaturePackets.ts`.

[Corrected: the original endpoints `/ui/signing/packets/{packetId}/licenses`,
`/licenses/accept`, and `/submit` **do not exist**. The real surface is the
`/v1/signature-packets/{packet_id}/...` family.]

**Legal notice** — carried inline on the packet detail loaded by AND-340
(`GET /v1/signature-packets/{packet_id}` → `SignaturePacketDetailOut`). There is
**no** separate license-fetch call. Shape of the embedded object:
```json
"legal_notice": {
  "required": true,
  "accepted": false,
  "version": "2024-11-01",
  "text": "By completing this packet you agree..."
}
```

**Acknowledge legal notice** — `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice`
(**empty body**; write — no auto-retry). Response `200` `SignaturePacketLegalNoticeAckOut`:
```json
{ "packet_id": "pkt_123", "signer_id": "sgn_1", "accepted": true, "notice_version": "2024-11-01" }
```

**Fill field** (upstream AND-342, shown for traceability) —
`POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill`, body
`SignaturePacketFieldFillIn`:
```json
{ "input_mode": "typed", "value": "Jane Doe" }
```
or `{ "input_mode": "drawn", "drawn_strokes": [[x,y],[x,y]] }`. Response `200`
`SignaturePacketFieldFillOut` `{ packet_id, field_id, value, filled_at, filled_by_signer_id, capture_mode? }`.

**Mark done (submit / sign)** — `POST /v1/signature-packets/{packet_id}/mark-done`
(**empty body**; **non-idempotent sign action; never auto-retry**). Response `200`
`SignaturePacketMarkDoneOut`:
```json
{
  "packet_id": "pkt_123",
  "signer_id": "sgn_1",
  "signer_status": "completed",
  "packet_status": "completed",
  "completed_at": "2026-06-05T17:42:10Z"
}
```
[Corrected: response has **no** `certificate_url` and no top-level `status`; the
completed-status field is `packet_status`, and the download is a separate endpoint.]

**Download completed PDF** — `GET /v1/signature-packets/{packet_id}/final-pdf`
(binary stream; opened only when `packet_status == "completed"`). This is the
"certificate/download reference."

**Error shape** (FastAPI `HTTPValidationError`, mapped per AND-015 — `detail` is
`string` | `[{loc,msg,type}]` | `{code,...}`):
```json
{ "detail": [ { "loc": ["body","value"], "msg": "field required", "type": "missing" } ] }
```
The OpenAPI documents only `200` and `422` for these signing endpoints; the global
client (`client.ts`) additionally maps `401` (refresh) and `403` (permission/geo).
[Unverified: `400` and `409 already completed`/version-conflict are **not** in the
OpenAPI for these endpoints — treat the 409/terminal handling as a defensive
assumption rather than a documented contract. See §16.]

## 6. Data & State Management

- **Source of truth:** `SigningRepository` over `SigningApi` + Room (`core-data`).
  The legal-notice object is **not** persisted separately — it is read fresh from
  the packet detail (AND-340) on each presentation to ensure the current version.
- **Cache write on success:** the packet's Room row (AND-340 schema) is updated
  with terminal `packet_status` (`completed`) and `completedAt` so the list/detail
  reflect completion without a refetch and survive offline. [Corrected: no
  `certificateUrl` — the final PDF is fetched on demand from `/final-pdf`.]
- **UI state:** `SubmitUiState` (above) is produced by AND-344's `StateFlow`
  reducer; this ticket only defines the type and consuming composable. The single
  `legalNotice` object (plus `remainingRequiredFields` from AND-342) drives
  `canSubmit`, recomputed whenever the packet detail re-loads.
- [Corrected: **no idempotency key.** `mark-done` accepts no body and the backend
  exposes no idempotency parameter for it. Timeout-after-commit is handled by
  re-loading detail on retry (§7).]
- **Field values** are filled per-field upstream (AND-342) and reflected in the
  packet detail; this ticket does not own their persistence.

## 7. Error Handling & Resilience

- **Timeouts:** dev host is unreliable; OkHttp ~20s timeouts (AND-009). `mark-done`
  is a write — **no automatic retry**. On timeout, present the manual **Retry**
  affordance; because there is no idempotency key, the retry path first **re-loads
  the packet detail** (AND-340) — if it is already `completed`, treat it as success
  and show confirmation rather than re-POSTing `mark-done` (avoids confusing
  double-complete errors).
- **Packet detail GET** (carrying `legal_notice`) is idempotent → bounded
  exponential backoff (AND-016) is owned by AND-340; while detail is unloaded the
  submit button stays disabled. [Corrected: there is no separate license GET to
  retry.]
- **401:** handled transparently by the refresh authenticator (AND-013); a second
  401 surfaces as a session-expired error routed to re-auth.
- **422 validation:** map `detail[].loc`/`msg`/`type` to the offending field where
  the `loc` path resolves (e.g. `["body","value"]` on a fill); otherwise show a
  top-level error. Missing-required-field errors instruct the user to return to
  placement/fill (AND-342). [Corrected: `400` is not documented for these endpoints;
  `field_values` is not a body key — fill validation is per-field.]
- **409 already completed / version conflict:** [Unverified — not in OpenAPI for
  these endpoints.] Defensive handling: if a `409` ever occurs, treat as terminal —
  refresh packet detail (AND-340) and show confirmation if completed.
- **403 CSRF/permission:** force a CSRF/cookie refresh and prompt manual retry.
- **Duplicate-tap protection:** button disabled and surface gated for the entire
  `SUBMITTING` phase.
- All network failures normalize through `ApiResult.Error` with a typed reason and
  a localized message (§9); no raw exceptions reach the UI.

## 8. Security & Privacy

- Transport is plaintext HTTP on the dev host (project constraint); production
  base URL is HTTPS via flavor config (AND-006). No credentials or signature
  bytes are placed in URLs — drawn signatures travel as `drawn_strokes` / typed
  `value` in the fill body (AND-342); this ticket sends no signature bytes.
- Auth via session cookies + `X-CSRF-Token` + Bearer token (verified in
  `client.ts`); the persistent cookie jar (AND-011) is required so the sign action
  authenticates correctly. CSRF header is mandatory on both write calls
  (`acknowledge-legal-notice`, `mark-done`).
- **Legal consent integrity:** the legal notice `version`+`text` are displayed
  exactly as returned; the app never mutates them. The server records the version on
  acknowledge (the client sends no version). Acknowledge and mark-done are explicit,
  user-initiated actions — never triggered automatically.
- The final/completed PDF is not cached to external storage by this ticket; the
  `/final-pdf` stream is fetched through the authenticated client only.
- Logs must redact legal-notice text, signature stroke/value data, and any PII in
  field/fill payloads (§10).

## 9. Accessibility & i18n

- All controls reachable via TalkBack: the legal-notice panel has a merged
  semantics node announcing its purpose + version + accepted state; the
  "I acknowledge and agree" action and the scrollable notice text are labelled.
  [Corrected: single legal-notice gate, not a list of license checkboxes.]
- **Mark done** button exposes its disabled reason via state description
  (e.g., "Fill all required fields and accept the legal notice to continue");
  minimum 48dp touch target.
- `SUBMITTING` announces a progress live-region; `CONFIRMED` announces success via
  an assertive live region.
- All strings via `core-ui` string resources (AND-111); server-provided license
  titles/bodies are displayed as-is (server-localized per AND-113). Layout is
  RTL-safe (AND-114); no truncation of legal text — bodies scroll.
- Date values rendered with the user's locale formatting; ISO sent on the wire.

## 10. Telemetry & Logging

Per AND-052 redacted telemetry conventions. Emit structured events (no PII, no
legal text, no signature bytes):

- `signing_legal_notice_viewed` { packetId, required, version }
- `signing_legal_notice_accepted` { packetId, noticeVersion }
- `signing_submit_started` { packetId, remainingRequiredFields }   // mark-done
- `signing_submit_succeeded` { packetId, packetStatus, durationMs }
- `signing_submit_failed` { packetId, errorKind (timeout|validation|conflict|auth|server), httpStatus }

[Corrected: events renamed from license-list semantics; no `idempotencyKeyHash`.]
Logging: request/response logging via OkHttp interceptor (AND-009) at BODY level
only in debug builds, with redaction of legal-notice `text`, fill `value`, and
`drawn_strokes`. The `/final-pdf` response body is never logged.

## 11. Testing Strategy

Unit / repository (JUnit + MockWebServer harness, AND-046; `core-testing`):

[Corrected to the real contract; the enumerated, ID'd test plan is in §17.]

- `acknowledgeLegalNotice` POSTs empty body to `.../acknowledge-legal-notice`;
  `200 SignaturePacketLegalNoticeAckOut` → success; maps `accepted`/`notice_version`.
- `submitPacket` (mark-done) happy path → `SubmitResult` with `packetStatus="completed"`
  and `completedAt`, and writes the terminal status to the Room row (fake DAO).
- `submitPacket` does **not** auto-retry on timeout/5xx (assert single request).
- Retry-after-timeout path re-loads detail; already-`completed` → success without a
  second `mark-done` POST.
- Error mapping: 422 with `detail[].loc`/`msg`/`type` → field/top-level error;
  401 path delegates to authenticator (AND-013).
- `downloadFinalPdf` only attempted when status is `completed`.

Compose UI (AND-048 conventions, instrumented):

- Mark-done button disabled until required fields filled AND required legal notice
  acknowledged; enabled afterward.
- Tapping submit shows `SUBMITTING` (button replaced by spinner, controls gated).
- `CONFIRMED` renders confirmation card with completion time, Download-PDF, and
  Done-to-list.
- `ERROR` renders mapped message + Retry; Retry re-invokes `onRetry`.
- Already-terminal packet shows confirmation, hides Mark-done.

CI: unit on build server (AND-050); instrumented on headless emulator (AND-051).
Coverage target: repository submit/license logic ≥ 85% lines.

## 12. Dependencies & Sequencing

- **Hard dep:** AND-342 (signature capture + placement) — supplies
  `SignatureFieldValue`s and uploaded signature artifact ids the submit payload
  references.
- **Transitive deps:** AND-339 (DTOs/status enums, `SignatureFieldValueDto`),
  AND-340 (packet detail + Room row updated on success), AND-341 (rendered doc the
  user is signing). Infra: AND-009/011/012/013/015/016/018, AND-006.
- **Blocks:** AND-344 (`SigningViewModel` state machine) which composes
  `SubmitSignSection` and drives `SubmitUiState` via the repository methods
  defined here. This ticket ships the repository contract + stateless UI; AND-344
  owns `StateFlow` orchestration, process-death restoration, and navigation to the
  list on Done.
- Sequencing: implement after AND-342 lands; can proceed in parallel with AND-344
  once the `SigningRepository` submit/license signatures here are merged as the
  interface contract.

## 13. Risks & Open Questions

- **Q1 — RESOLVED (corrected).** There is no `licenses/accept` call and no
  `accepted_licenses` array on submit. The consent gate is the packet's
  `legal_notice` + `POST .../acknowledge-legal-notice` (empty body). The
  `licenseAgreements.ts` module named in the backlog is unrelated content-licensing
  CRUD — see §16 headline correction. **Action: confirm with product whether the
  backlog scope line truly means content-licensing CRUD or was a mislabel for the
  signing legal notice.**
- **Q2 — RESOLVED (corrected).** `mark-done` exposes no `idempotency_key`. Mitigate
  timeout-after-commit by re-loading detail on retry and treating an already
  `completed` packet as success.
- **Q3 — RESOLVED (corrected).** Legal-notice body is delivered inline as
  `legal_notice.text` on the packet detail; there is no `document_url`. UI renders
  the inline (scrollable) text.
- **Q4 — Field validation authority:** required-field readiness comes from the
  packet detail (`remaining_required`/filled state, AND-342); server `422` on
  `mark-done`/`fill` is the backstop with inline mapping.
- **Risk — unreliable dev host:** flaky `mark-done` during testing; mitigated by
  manual retry + detail re-load, and MockWebServer-based deterministic tests.
- **Q5 — Process-death durability** of the in-flight phase is deferred to AND-344's
  `SavedStateHandle` handling.

## 14. Acceptance Criteria

AC-1. From a packet with all required signature/data fields filled (AND-342), the
required **legal notice** (`legal_notice` on the packet detail) is displayed with
its full text and version. [Corrected from "license agreements are fetched".]
AC-2. **Mark done** is disabled until all required fields are filled **and** any
required legal notice is acknowledged, then becomes enabled. [Corrected.]
AC-3. Marking a valid packet done POSTs (empty body) to
`/v1/signature-packets/{packet_id}/mark-done` and, on `200`, **the signed packet
submits and a confirmation is shown** (`packet_status == "completed"`, completion
time, and a Download-completed-PDF affordance via `/final-pdf`) — satisfying the
backlog acceptance "Signed packet submits + confirms." [Corrected path/fields.]
AC-4. The packet's terminal status is persisted to the Room cache and reflected in
the list/detail (AND-340) without a manual refresh.
AC-5. Mark-done performs **no** automatic retry; on failure a mapped error and
manual Retry are shown (retry re-loads detail first; no idempotency key). [Corrected.]
AC-6. An already-terminal packet (`completed`/`cancelled`/`expired`, or own
`signer_status == "completed"`) resolves to the confirmation/terminal view rather
than an error. (`409` handling is defensive — not documented; see §16.) [Corrected.]
AC-7. Validation `422` errors map to field-scoped messages where `loc` resolves.
AC-8. The legal-notice acknowledge + mark-done + final-PDF surface is ported: DTOs,
mappers, and repository methods exist and are unit-tested. [Corrected: original
"`licenseAgreements.ts` ported" AC was incorrect — that module is out of scope; if
content-licensing CRUD is genuinely required, it is a separate ticket (§16).]
AC-9. All listed unit and Compose tests pass in CI (AND-050/051).

## 15. Definition of Done

- `SigningApi` acknowledge-legal-notice / mark-done / final-pdf methods,
  matching `SigningRepository` methods, DTOs, mappers, domain models
  (`LegalNotice`, `SubmitResult`), and `SubmitSignSection` composable +
  `SubmitUiState` implemented under `com.testlogon.android` in `feature-signing` /
  `core-*` per layering. [Corrected from license DTOs.]
- Endpoint paths and DTO field names verified against `/openapi.json` (done in this
  review, §16); Q1/Q3 resolved.
- Success path persists terminal status to Room; confirmation UX implemented.
- Error mapping (AND-015), no-auto-retry-on-write, and terminal/already-completed
  handling implemented. [Corrected: no idempotency key.]
- Telemetry events (§10) emitted with redaction; debug logging redacts sensitive
  fields.
- Accessibility (TalkBack semantics, 48dp targets, live regions) and i18n
  (resourced strings, RTL-safe) verified.
- Unit + Compose tests (§11) authored and green in CI on build server and headless
  emulator; repository submit/license coverage ≥ 85%.
- KtLint/Detekt clean (AND-005); merged to `android-port`; AND-344 can consume the
  repository contract and composable.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Terminal submit action is `POST /v1/signature-packets/{packet_id}/mark-done`
   with an empty body.** — **Corrected** (spec originally said
   `POST /ui/signing/packets/{packetId}/submit`). Source: OpenAPI
   `POST /v1/signature-packets/{packet_id}/mark-done` (req empty, resp
   `200:SignaturePacketMarkDoneOut`); `src/api/endpoints/signaturePackets.ts:
   markSignaturePacketDone`.
2. **Mark-done response shape is `{packet_id, signer_id, signer_status,
   packet_status, completed_at}` (all required); no `certificate_url`, no top-level
   `status`.** — **Corrected.** Source: OpenAPI schema
   `SignaturePacketMarkDoneOut`.
3. **The endpoints `/ui/signing/packets/{packetId}/licenses` and
   `/licenses/accept` do not exist.** — **Corrected.** Source: absence in
   `reference/openapi.index.txt` (grep `/ui/signing`, `/signing/packets` → only
   `/ui/signing/templates*`; no per-packet submit/licenses route).
4. **Consent gate is the packet's inline `legal_notice {required, accepted,
   version, text}`, acknowledged via
   `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice` (empty body) →
   `SignaturePacketLegalNoticeAckOut {packet_id, signer_id, accepted,
   notice_version}`.** — **Corrected/Verified.** Source: OpenAPI
   `POST /v1/signature-packets/{packet_id}/acknowledge-legal-notice`, schemas
   `SignaturePacketLegalNoticeAckOut`; `SignaturePacketDetail.legal_notice` in
   `src/api/endpoints/signaturePackets.ts`; web behavior in
   `src/pages/files/SignaturePacketComposer.tsx: acknowledgeLegalNotice` (mark-done
   disabled while `legal_notice.required`).
5. **`licenseAgreements.ts` is content-licensing CRUD (royalty_free /
   creative_commons / commercial etc.) over `/ui/licenses/agreements`, NOT a signing
   consent path.** — **Corrected (headline).** Source:
   `src/api/endpoints/licenseAgreements.ts` (`createLicenseAgreement`,
   `LICENSE_TYPES`, `CONTENT_TYPES=[video,post,broadcast]`); OpenAPI
   `GET/POST /ui/licenses/agreements`. The backlog ticket's scope line
   (`licenseAgreements.ts`) appears to be a mislabel for the signing legal notice.
6. **Fields are filled individually via
   `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill` with
   `SignaturePacketFieldFillIn {value?, input_mode?: "typed"|"drawn", drawn_strokes?,
   notary_stamp?}`; there is no bulk `field_values`/`accepted_licenses` submit
   payload.** — **Corrected.** Source: OpenAPI
   `POST /v1/signature-packets/{packet_id}/fields/{field_id}/fill`, schema
   `SignaturePacketFieldFillIn`; `src/api/endpoints/signaturePackets.ts:
   fillSignaturePacketField`; `SignaturePacketComposer.tsx: submitFill`.
7. **`mark-done` has no `idempotency_key`.** — **Corrected** (spec invented one).
   Source: OpenAPI `mark-done` `req=` empty, `params=packet_id,user_sub,X-SESSION-ID,
   X-IMPERSONATION-TOKEN` (no `Idempotency-Key`). Contrast: `Idempotency-Key` IS a
   param on `POST /api/v1/kyc/applications/{application_id}/submit` — a different
   endpoint — confirming the absence on mark-done is intentional.
8. **Packet status enum is `draft | sent | partially_signed | completed |
   cancelled | expired`; there is no `signed`/`declined`/`voided`.** — **Corrected.**
   Source: `src/api/endpoints/signaturePackets.ts: SignaturePacketStatus`.
9. **Completed-PDF download is `GET /v1/signature-packets/{packet_id}/final-pdf`
   (binary), used only when `status == "completed"`.** — **Verified** (replaces the
   invented `certificate_url`). Source: OpenAPI
   `GET /v1/signature-packets/{packet_id}/final-pdf`;
   `src/api/endpoints/signaturePackets.ts: downloadSignaturePacketFinalPdf`;
   `SignaturePacketComposer.tsx: downloadFinal` (guarded by `status==="completed"`).
10. **Auth = Bearer access token + `X-CSRF-Token` (from `ui_csrf` cookie) +
    cookies (`credentials:include`); single 401 → `POST /ui/session/refresh`
    retry.** — **Verified.** Source: `src/api/client.ts` (lines ~157-171 headers;
    ~194-237 refresh-on-401; ~121-130 `refreshSession`). (Spec's cookie+CSRF claim
    correct; Bearer token added.)
11. **Error body is FastAPI `HTTPValidationError {detail: [{loc, msg, type}]}`;
    `detail` may also be a string or `{code,...}`.** — **Verified.** Source: OpenAPI
    schemas `HTTPValidationError` + `ValidationError`; `src/api/client.ts:
    normalizeErrorDetail` / `mapAuthorizationError`.
12. **403 is mapped (permission / `geo_blocked`) by the global client.** —
    **Verified.** Source: `src/api/client.ts` (403 branch, ~240-255).
13. **`400` and `409 already-completed`/version-conflict for these signing
    endpoints.** — **Unverified-assumption.** Source: OpenAPI documents only
    `200`/`422` for `mark-done`, `fill`, and `acknowledge-legal-notice`. Retained as
    defensive handling only.
14. **Per-field readiness (`remaining_required`) comes from packet detail / fill
    state.** — **Verified (web behavior).** Source:
    `SignaturePacketComposer.tsx: remainingRequiredCount`, mark-done `disabled`
    predicate.
15. **Stack/framework choices (Retrofit `@Streaming` for binary PDF, OkHttp,
    Moshi, Compose Material 3, Hilt).** — **Unverified-assumption (framework ref).**
    `@Streaming` for large/binary responses: framework ref
    https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Streaming.html .
    Compose accessibility semantics: framework ref
    https://developer.android.com/jetpack/compose/accessibility . These are Android
    implementation choices, not backend contract.

### Corrections made

- Replaced the non-existent `/ui/signing/packets/{packetId}/submit` +
  `/licenses` + `/licenses/accept` contract with the real
  `/v1/signature-packets/{packet_id}/{mark-done,acknowledge-legal-notice,final-pdf}`
  family (§1, §2, §3, §4.1-4.4, §5, §14, §15).
- Replaced the license-agreement list/checkbox model with the single inline
  `legal_notice` consent gate (§3 FR-1/2/3, §4, §9, §10).
- Removed the invented `idempotency_key` everywhere; replaced timeout mitigation
  with detail-reload + already-`completed`-is-success (§3 FR-5, §4.3, §6, §7).
- Removed `certificate_url`; the completed PDF is the `/final-pdf` stream (§4.1,
  §5, §6).
- Fixed the status enum to `draft|sent|partially_signed|completed|cancelled|expired`
  (§1, FR-8, AC-6).
- Corrected response field names to `packet_status`/`signer_status`/`completed_at`
  and request bodies to empty for `mark-done` and `acknowledge-legal-notice` (§4,
  §5).
- Renamed telemetry events and redaction targets to match the real flow (§10).
- Re-pointed web references to `signaturePackets.ts` + `SignaturePacketComposer.tsx`
  and flagged `licenseAgreements.ts` as out of scope (§2, AC-8).

### Open assumptions

- **Backlog scope mislabel (high impact):** the ticket line "Scope: …
  `licenseAgreements.ts`" cannot be reconciled with the signing flow — that module
  is content-licensing CRUD. Assumed it is a mislabel for the per-packet legal
  notice. **Needs product confirmation**; if content-licensing CRUD is genuinely
  intended, this ticket is mis-scoped and should be split.
- **`400`/`409`/`5xx` behavior** for the signing endpoints is not in the OpenAPI
  (only `200`/`422` documented). 409/terminal handling is defensive only and cannot
  be verified from sources.
- **Idempotency / double-complete semantics of `mark-done`** on the server (does a
  second call on a `completed` packet 200 or error?) is not documented; the spec
  assumes the client must guard via detail re-load.
- **`legal_notice` exact shape** is taken from `SignaturePacketDetail` in the
  frontend types (`signaturePackets.ts`); it is embedded in
  `SignaturePacketDetailOut` whose full JSON shape was not exhaustively read here —
  the four fields (`required, accepted, version, text`) are from the TS interface.
- **Hardware/runtime behaviors** (ABI/API-level differences, real-network flakiness
  on physical device) are environmental assumptions covered by the test plan, not
  derived from the backend sources.

## 17. Test Plan

IDs `TC-AND-343-NN`. "Traces" link to §14 acceptance criteria. Targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or PHYSICAL DEVICE
(Samsung Galaxy A15 5G, SM-A156U, API 34 arm64, serial R5CX821TA9R).

- **TC-AND-343-01 — Mark-done happy path (contract).**
  Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: MockWebServer enqueues `200 SignaturePacketMarkDoneOut`
  (`packet_status:"completed"`, `completed_at` set); fake DAO row exists for packet.
  Steps: call `SigningRepository.submitPacket(packetId)`.
  Expected: request is `POST /v1/signature-packets/{packetId}/mark-done` with empty
  body; result `ApiResult.Success(SubmitResult(packetStatus=completed, completedAt
  != null))`; DAO row updated to `completed` + `completedAt`. Traces: AC-3, AC-4.

- **TC-AND-343-02 — Acknowledge legal notice (contract).**
  Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: enqueue `200 SignaturePacketLegalNoticeAckOut {accepted:true,
  notice_version}`.
  Steps: call `acknowledgeLegalNotice(packetId)`.
  Expected: request is `POST .../acknowledge-legal-notice` with empty body; success;
  no version string sent by client. Traces: AC-1, AC-2.

- **TC-AND-343-03 — Mark-done does NOT auto-retry on timeout/5xx (contract).**
  Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: MockWebServer responds `503` (or socket timeout).
  Steps: call `submitPacket`; inspect `RecordedRequest` count.
  Expected: exactly **one** POST to `mark-done`; `ApiResult.Error` with transient
  reason; no second request. Traces: AC-5.

- **TC-AND-343-04 — Retry-after-timeout reloads detail; already-completed is
  success (integration).**
  Type: integration (JVM). Target: JVM/Robolectric.
  Preconditions: first `mark-done` times out; on retry, detail GET returns
  `status:"completed"`.
  Steps: submit → timeout → user Retry → repository re-loads detail.
  Expected: no second `mark-done` POST; flow resolves to CONFIRMED from the
  re-loaded `completed` detail. Traces: AC-5, AC-6.

- **TC-AND-343-05 — 422 validation maps to field/top-level error (contract).**
  Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: enqueue `422 {detail:[{loc:["body","value"],msg:"field required",
  type:"missing"}]}`.
  Steps: call the relevant write; map error via AND-015 mapper.
  Expected: `ApiResult.Error` carries the mapped message; `loc` resolving into a
  field → field-scoped error, else top-level. Traces: AC-7.

- **TC-AND-343-06 — 401 triggers single session refresh then retry (contract).**
  Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: enqueue `401`, then `200` for `/ui/session/refresh`, then `200`
  mark-done on retry.
  Steps: call `submitPacket` while authenticated.
  Expected: one refresh POST, original request retried once, success; a second
  consecutive 401 → session-expired error. Traces: AC-3, AC-5.

- **TC-AND-343-07 — Mark-done button enablement gate (Compose-UI).**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: render `SubmitSignSection` with `remainingRequiredFields>0` or
  `legalNotice.required==true`.
  Steps: assert button disabled; set fields filled + notice acknowledged
  (`canSubmit=true`); assert enabled.
  Expected: disabled until both conditions met, then enabled; disabled-reason state
  description present. Traces: AC-2.

- **TC-AND-343-08 — Submitting / Confirmed / Download UX (Compose-UI).**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: drive phases IDLE→SUBMITTING→CONFIRMED with a `SubmitResult`.
  Steps: tap Mark done; assert spinner + controls gated in SUBMITTING; on CONFIRMED
  assert completion time, Download-completed-PDF, and Done-to-list controls.
  Expected: phase transitions render correctly; tapping Download invokes
  `onDownloadFinalPdf`; Done invokes `onDoneToList`. Traces: AC-3.

- **TC-AND-343-09 — Already-terminal packet hides Mark-done (Compose-UI).**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: state with packet `completed` (or `signer_status=="completed"`).
  Steps: render section.
  Expected: confirmation/terminal view shown; Mark-done hidden; no error. Traces:
  AC-6.

- **TC-AND-343-10 — Error phase + Retry (Compose-UI).**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: state `phase=ERROR`, `errorMessage` set.
  Steps: assert mapped message shown; tap Retry.
  Expected: `onRetry` invoked once. Traces: AC-5.

- **TC-AND-343-11 — CSRF header present on writes; missing CSRF surfaces 403
  (contract/security).**
  Type: contract/MockWebServer (JVM). Target: JVM/Robolectric.
  Preconditions: cookie jar holds `ui_csrf`; enqueue `200`, then a `403` case with
  no CSRF.
  Steps: issue `mark-done` and `acknowledge-legal-notice`.
  Expected: both requests carry `X-CSRF-Token` (and Authorization/Cookie); the 403
  path maps to a permission/CSRF error prompting manual retry. Traces: AC-3, AC-5.

- **TC-AND-343-12 — Final-PDF download gated to completed (integration).**
  Type: integration (JVM). Target: JVM/Robolectric.
  Preconditions: packet not completed.
  Steps: invoke `downloadFinalPdf`.
  Expected: not attempted (or no-op) unless `status=="completed"`; when completed,
  `GET .../final-pdf` issued with `@Streaming`. Traces: AC-3.

- **TC-AND-343-13 — Legal-notice accessibility (accessibility/Compose-UI).**
  Type: Compose-UI accessibility (instrumented). Target: emulator `test35`.
  Preconditions: render legal-notice panel and Mark-done button.
  Steps: assert merged semantics announce notice purpose + version + accepted state;
  Mark-done exposes disabled-reason state description; touch targets >= 48dp; notice
  text scrollable, not truncated.
  Expected: all semantics/contentDescriptions present; RTL-safe. Traces: AC-1, AC-2.

- **TC-AND-343-14 — Real-device flaky-host submit + completed-PDF open
  (instrumented/e2e).**
  Type: instrumented/e2e. Target: **PHYSICAL DEVICE** (SM-A156U, API 34 arm64) —
  MUST run on the physical device to exercise real-network flakiness against the
  unreliable plaintext dev host and the system PDF viewer/Download handling on
  arm64/API 34 (vs emulator x86/API 35).
  Preconditions: app pointed at dev flavor; a real packet with required fields filled
  and a required legal notice; device on network.
  Steps: acknowledge notice → Mark done over the flaky host (retry if it times out)
  → on confirmation tap Download completed PDF.
  Expected: packet reaches `completed`; retry after a timeout does not double-submit
  (detail-reload path); completed PDF opens via the authenticated client. Traces:
  AC-3, AC-4, AC-5, AC-6.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-02, TC-13 |
| AC-2 | TC-02, TC-07, TC-13 |
| AC-3 | TC-01, TC-06, TC-08, TC-11, TC-12, TC-14 |
| AC-4 | TC-01, TC-14 |
| AC-5 | TC-03, TC-04, TC-06, TC-10, TC-11, TC-14 |
| AC-6 | TC-04, TC-09, TC-14 |
| AC-7 | TC-05 |
| AC-8 | TC-01, TC-02, TC-12 (DTO/mapper/repository exercised); §16 audit confirms scope |
| AC-9 | All TC-01..TC-14 (the CI unit + Compose + instrumented suites) |
