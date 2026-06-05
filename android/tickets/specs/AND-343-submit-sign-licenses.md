---
id: AND-343
title: Submit / sign + licenses
milestone: M7
epic: E44
priority: P1
size: M
status: draft
depends_on: [AND-342, AND-339, AND-340, AND-341]
blocks: [AND-344]
---

# AND-343 — Submit / sign + licenses

## 1. Overview & Goal

This ticket delivers the terminal step of the e-signing flow: taking a fully
prepared signature packet — document(s) rendered (AND-341), signature drawn or
adopted and placed onto required fields (AND-342) — and **submitting the signed
packet to the backend, surfacing license/consent agreements that gate that
submission, and confirming the signed/completed result** to the user.

The user-visible outcome: from a packet whose required signature and data fields
are satisfied, the user accepts any outstanding **license agreements** (legal
consents required before signing is binding), taps **Sign & Submit**, and
receives an explicit, durable confirmation that the packet is now in a terminal
state (`completed` / `signed`).

Scope per the backlog ticket is narrow and additive: (a) the **submit signed
packet** action and confirmation UX, and (b) the **`licenseAgreements`** data
path (the Kotlin port of `licenseAgreements.ts`). It does **not** include packet
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
- Web reference: `frontend/src/api/endpoints/signaturePackets.ts`,
  `frontend/src/api/endpoints/licenseAgreements.ts`, shared types in
  `frontend/src/api/types.ts`. Backend OpenAPI at `/openapi.json` (dev host
  `http://18.222.237.167:8000`, plaintext, unreliable — design accordingly).
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15. Cookie + `X-CSRF-Token` auth with
  401→`/ui/session/refresh` retry (AND-011/012/013), `ApiResult<T>` (AND-018),
  FastAPI `detail` mapping (AND-015). Module: `feature-signing` →
  `core-network`, `core-model`, `core-data`, `core-ui`.
- Canonical namespace: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **License agreement fetch.** When the submit surface is presented, the app
fetches the license agreements applicable to the packet (those required and not
yet accepted by the current user). Each agreement has a stable id, title, body
(or a URL to a viewable document), version, and a `required` flag.

FR-2. **License acceptance UI.** Each required, unaccepted agreement is rendered
as a checkbox row with its title and an affordance to read the full text
(expandable body or a link opening the license document). The **Sign & Submit**
action is disabled until every `required` agreement is checked.

FR-3. **License acceptance recording.** On acceptance, the app records each
accepted agreement (id + version) against the user/packet via the licenses
endpoint **before** (or atomically as part of) submitting the packet, depending
on backend contract (§5). Acceptance is idempotent — re-accepting an
already-accepted version is a no-op success.

FR-4. **Submit signed packet.** When fields are satisfied (validated by AND-342
placement output) and licenses accepted, **Sign & Submit** POSTs the signed
packet. The submit payload references the placed signature field values /
uploaded signature artifact ids produced upstream.

FR-5. **In-flight UX.** During submission the action shows a non-cancellable
progress state (button → spinner, surface blocks duplicate taps). Submission is
**non-idempotent** (a sign action) and must not auto-retry.

FR-6. **Confirmation.** On success the app shows an explicit confirmation
(completed status, completion timestamp, and any returned certificate/download
reference) and transitions the packet to its terminal state in cache. The
confirmation is dismissible back to the packet list (AND-340).

FR-7. **Failure handling.** On failure the submit surface returns to the
actionable state with a mapped, human-readable error and a manual **Retry**
affordance (see §7). Field/validation errors (e.g., missing required field) are
surfaced inline where possible.

FR-8. **Already-completed guard.** If the packet is already terminal
(`completed`/`signed`/`declined`/`voided`) the submit action is hidden and the
confirmation/terminal view is shown instead.

## 4. Technical Design

Package root: `com.testlogon.android.feature.signing`.

### 4.1 License DTOs / domain (port of `licenseAgreements.ts`)

```kotlin
// core-model :: com.testlogon.android.core.model.signing
data class LicenseAgreement(
    val id: String,
    val title: String,
    val version: String,
    val required: Boolean,
    val body: String?,        // inline text if provided
    val documentUrl: String?, // else a viewable URL
    val accepted: Boolean,    // accepted by current user at this version
)

data class SubmitResult(
    val packetId: String,
    val status: PacketStatus,        // from AND-339
    val completedAt: Instant?,
    val certificateUrl: String?,
)
```

```kotlin
// core-network :: com.testlogon.android.core.network.signing.dto
@JsonClass(generateAdapter = true)
data class LicenseAgreementDto(
    @Json(name = "id") val id: String,
    @Json(name = "title") val title: String,
    @Json(name = "version") val version: String,
    @Json(name = "required") val required: Boolean = true,
    @Json(name = "body") val body: String? = null,
    @Json(name = "document_url") val documentUrl: String? = null,
    @Json(name = "accepted") val accepted: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class LicenseAcceptanceDto(
    @Json(name = "agreement_id") val agreementId: String,
    @Json(name = "version") val version: String,
)

@JsonClass(generateAdapter = true)
data class SubmitPacketRequestDto(
    @Json(name = "field_values") val fieldValues: List<SignatureFieldValueDto>, // from AND-342
    @Json(name = "accepted_licenses") val acceptedLicenses: List<LicenseAcceptanceDto>,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

@JsonClass(generateAdapter = true)
data class SubmitPacketResponseDto(
    @Json(name = "packet_id") val packetId: String,
    @Json(name = "status") val status: String,
    @Json(name = "completed_at") val completedAt: String? = null,
    @Json(name = "certificate_url") val certificateUrl: String? = null,
)
```

`SignatureFieldValueDto` is owned by AND-339/342; this ticket consumes it. Final
DTO field names are confirmed against `/openapi.json` during implementation
(see §13 Open Questions); adapters live with the other signing DTOs from AND-339.

### 4.2 API surface (Retrofit)

```kotlin
// core-network :: com.testlogon.android.core.network.signing
interface SigningApi {           // extended from AND-339; new methods here
    @GET("ui/signing/packets/{packetId}/licenses")
    suspend fun getPacketLicenses(
        @Path("packetId") packetId: String,
    ): Response<List<LicenseAgreementDto>>

    @POST("ui/signing/packets/{packetId}/licenses/accept")
    suspend fun acceptLicenses(
        @Path("packetId") packetId: String,
        @Body body: List<LicenseAcceptanceDto>,
    ): Response<Unit>

    @POST("ui/signing/packets/{packetId}/submit")
    suspend fun submitPacket(
        @Path("packetId") packetId: String,
        @Body body: SubmitPacketRequestDto,
    ): Response<SubmitPacketResponseDto>
}
```

### 4.3 Repository

```kotlin
// core-data :: com.testlogon.android.core.data.signing
interface SigningRepository {     // partial — submit/licenses additions
    suspend fun loadLicenses(packetId: String): ApiResult<List<LicenseAgreement>>
    suspend fun acceptLicenses(
        packetId: String,
        accepted: List<LicenseAgreement>,
    ): ApiResult<Unit>
    suspend fun submitPacket(
        packetId: String,
        fieldValues: List<SignatureFieldValue>,
        acceptedLicenses: List<LicenseAgreement>,
        idempotencyKey: String,
    ): ApiResult<SubmitResult>
}
```

`SigningRepositoryImpl` (Hilt `@Singleton`, `@Inject constructor`) maps DTO↔domain
via mappers in `core-network`, wraps calls in the shared
`Response<T>.toApiResult { map }` helper (AND-018), and on submit success writes
the terminal `PacketStatus` and `completedAt` into the Room cache row created by
AND-340 so the list reflects the new state offline. `idempotencyKey` is a
client-generated UUID stable across user-initiated retries of the *same* submit
attempt (defends against a backend that timed out after committing).

### 4.4 Compose submit surface (this ticket's UI)

A self-contained, stateless composable consumed by AND-344's screen:

```kotlin
// feature-signing :: com.testlogon.android.feature.signing.submit
@Composable
fun SubmitSignSection(
    state: SubmitUiState,
    onToggleLicense: (agreementId: String, checked: Boolean) -> Unit,
    onViewLicense: (LicenseAgreement) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    onDoneToList: () -> Unit,
    modifier: Modifier = Modifier,
)

data class SubmitUiState(
    val licenses: List<LicenseAgreement>,
    val acceptedIds: Set<String>,
    val phase: Phase,             // Idle, LicensesLoading, Submitting, Confirmed, Error
    val canSubmit: Boolean,       // all required licenses accepted && fields valid && phase==Idle
    val result: SubmitResult? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { LICENSES_LOADING, IDLE, SUBMITTING, CONFIRMED, ERROR }
}
```

`canSubmit` is derived in AND-344's reducer; this ticket defines the contract
and renders accordingly. The submit button is the only enabled control while
`SUBMITTING`. The `CONFIRMED` phase swaps the section for a confirmation card.

## 5. API Contract

Base URL from build flavor (AND-006). All requests carry the session cookies and
`X-CSRF-Token` (AND-012); 401 triggers a single `/ui/session/refresh` retry
(AND-013). Endpoints are confirmed against `/openapi.json` at implementation
time; `signaturePackets.ts` / `licenseAgreements.ts` are the cross-check.

**Fetch licenses** — `GET /ui/signing/packets/{packetId}/licenses` (idempotent;
eligible for bounded backoff retry per AND-016).
```json
[
  {
    "id": "lic_w2_consent",
    "title": "Electronic Records & Signature Consent",
    "version": "2024-11-01",
    "required": true,
    "body": "By checking this box you agree...",
    "document_url": null,
    "accepted": false
  }
]
```

**Accept licenses** — `POST /ui/signing/packets/{packetId}/licenses/accept`
(non-idempotent write; **no** auto-retry). Request:
```json
[ { "agreement_id": "lic_w2_consent", "version": "2024-11-01" } ]
```
Response: `204 No Content` (or `200` with empty/echo body).

**Submit signed packet** — `POST /ui/signing/packets/{packetId}/submit`
(**non-idempotent sign action; never auto-retry**). Request:
```json
{
  "field_values": [
    { "field_id": "f_sig_1", "type": "signature", "value_ref": "sigimg_abc123" },
    { "field_id": "f_date_1", "type": "date", "value": "2026-06-05" }
  ],
  "accepted_licenses": [ { "agreement_id": "lic_w2_consent", "version": "2024-11-01" } ],
  "idempotency_key": "f1d2c3b4-..."
}
```
Response `200`:
```json
{
  "packet_id": "pkt_123",
  "status": "completed",
  "completed_at": "2026-06-05T17:42:10Z",
  "certificate_url": "/ui/signing/packets/pkt_123/certificate.pdf"
}
```

**Error shape** (FastAPI, mapped per AND-015 — `detail` is `string` |
`[{msg,...}]` | `{code,...}`):
```json
{ "detail": [ { "loc": ["body","field_values",0], "msg": "required field missing" } ] }
```
Relevant statuses: `400/422` validation (map to inline/field errors where `loc`
allows), `403` CSRF/permission, `409` packet already completed or version
conflict (treat as terminal/refresh state), `5xx`/timeout transient.

If the backend folds license acceptance into `submit` (acceptance accepted in the
`accepted_licenses` array only, no separate accept endpoint), the repository
**skips** `acceptLicenses` and relies solely on `submitPacket`. This branch is
resolved against `/openapi.json` (§13).

## 6. Data & State Management

- **Source of truth:** `SigningRepository` over `SigningApi` + Room (`core-data`).
  License lists are session-scoped and **not** persisted (legal text is fetched
  fresh each presentation to ensure current versions).
- **Cache write on success:** the packet's Room row (AND-340 schema) is updated
  with terminal `status`, `completedAt`, and `certificateUrl` so the list/detail
  reflect completion without a refetch and survive offline.
- **UI state:** `SubmitUiState` (above) is produced by AND-344's `StateFlow`
  reducer; this ticket only defines the type and consuming composable. The
  `acceptedIds: Set<String>` is the single source for checkbox state; `canSubmit`
  is recomputed on every toggle.
- **Idempotency key** is generated once when the submit surface first enters
  `IDLE` for a given packet and reused across retries of that attempt; it is held
  in UI/VM state (not persisted across process death for this ticket — see §13).
- **Field values** are passed in from AND-342's placement output; this ticket
  does not own their persistence.

## 7. Error Handling & Resilience

- **Timeouts:** dev host is unreliable; OkHttp ~20s timeouts (AND-009). Submit is
  a write — **no automatic retry**. On timeout, present the manual **Retry**
  affordance carrying the same `idempotency_key` so a server that committed before
  the timeout returns the existing terminal state (ideally `409`/`200` idempotent)
  rather than double-signing.
- **License GET** is idempotent → bounded exponential backoff (AND-016); on
  exhaustion show an error state with manual reload; the submit button stays
  disabled while licenses are unloaded.
- **401:** handled transparently by the refresh authenticator (AND-013); a second
  401 surfaces as a session-expired error routed to re-auth.
- **422/400 validation:** map `detail[].loc` to the offending field where the path
  resolves into `field_values`; otherwise show a top-level error. Missing-field
  errors instruct the user to return to placement (AND-342).
- **409 already completed / version conflict:** treat as terminal — refresh packet
  detail (AND-340), show confirmation if completed, or show the
  "agreement updated, re-review" state if a license version changed.
- **403 CSRF:** force a CSRF/cookie refresh and prompt manual retry.
- **Duplicate-tap protection:** button disabled and surface gated for the entire
  `SUBMITTING` phase.
- All network failures normalize through `ApiResult.Error` with a typed reason and
  a localized message (§9); no raw exceptions reach the UI.

## 8. Security & Privacy

- Transport is plaintext HTTP on the dev host (project constraint); production
  base URL is HTTPS via flavor config (AND-006). No credentials or signature
  bytes are placed in URLs — signatures travel as `value_ref` artifact ids
  (uploaded by AND-342) or opaque body payloads.
- Auth via httpOnly session cookies + `X-CSRF-Token`; the persistent cookie jar
  (AND-011) is required so the sign action authenticates correctly. CSRF header is
  mandatory on both write calls (`accept`, `submit`).
- **Legal consent integrity:** accepted license `id`+`version` are recorded
  exactly as fetched; the app never mutates version strings. Acceptance and signing
  are an explicit, user-initiated action — never triggered automatically.
- Signature images / certificates are not cached to external storage by this
  ticket. `certificate_url` is opened through the authenticated client only.
- Logs must redact license body text, signature artifacts, and any PII in
  `field_values` (§10).

## 9. Accessibility & i18n

- All controls reachable via TalkBack: each license checkbox row has a merged
  semantics node announcing title + accepted state + `required`; the
  read-full-text affordance has a `contentDescription`.
- **Sign & Submit** button exposes its disabled reason via state description
  (e.g., "Accept all required agreements to continue"); minimum 48dp touch target.
- `SUBMITTING` announces a progress live-region; `CONFIRMED` announces success via
  an assertive live region.
- All strings via `core-ui` string resources (AND-111); server-provided license
  titles/bodies are displayed as-is (server-localized per AND-113). Layout is
  RTL-safe (AND-114); no truncation of legal text — bodies scroll.
- Date values rendered with the user's locale formatting; ISO sent on the wire.

## 10. Telemetry & Logging

Per AND-052 redacted telemetry conventions. Emit structured events (no PII, no
legal text, no signature bytes):

- `signing_licenses_viewed` { packetId, requiredCount, alreadyAcceptedCount }
- `signing_license_accepted` { packetId, agreementId, version }
- `signing_submit_started` { packetId, fieldCount, idempotencyKeyHash }
- `signing_submit_succeeded` { packetId, status, durationMs }
- `signing_submit_failed` { packetId, errorKind (timeout|validation|conflict|auth|server), httpStatus }

Logging: request/response logging via OkHttp interceptor (AND-009) at BODY level
only in debug builds, with redaction of `body`, `value`, `value_ref`,
`certificate_url`. The `idempotency_key` is logged only as a short hash.

## 11. Testing Strategy

Unit / repository (JUnit + MockWebServer harness, AND-046; `core-testing`):

- `loadLicenses` maps DTO→domain, including `body`-only and `document_url`-only
  agreements and `accepted=true` filtering.
- `acceptLicenses` posts the correct `[{agreement_id,version}]` body; 204 → success.
- `submitPacket` happy path → `SubmitResult` with terminal status, and writes the
  terminal status to the Room row (verify via fake DAO).
- `submitPacket` does **not** auto-retry on timeout/5xx (assert single request).
- License GET retries with backoff on 5xx (assert N attempts, AND-016).
- Error mapping: 422 with `detail[].loc` into `field_values` → field-scoped error;
  409 → terminal/conflict result; 401 path delegates to authenticator (AND-013).
- Idempotency key reused across retry of the same attempt; regenerated for a fresh
  attempt.

Compose UI (AND-048 conventions, instrumented):

- Submit button disabled until all `required` licenses checked; enabled afterward.
- Tapping submit shows `SUBMITTING` (button replaced by spinner, controls gated).
- `CONFIRMED` renders confirmation card with completion time and Done-to-list.
- `ERROR` renders mapped message + Retry; Retry re-invokes `onRetry`.
- Already-terminal packet shows confirmation, hides submit.

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

- **Q1 — Acceptance coupling:** Does the backend require a separate
  `licenses/accept` call, or are accepted licenses passed inside `submit` only?
  Resolve via `/openapi.json` + `licenseAgreements.ts`. Repository is written to
  support both; the unused branch is removed on confirmation.
- **Q2 — Idempotency support:** Does `submit` honor `idempotency_key`? If not, a
  timeout-after-commit risks a confusing duplicate-submit error; mitigate by
  refetching detail on retry and treating `409 already completed` as success.
- **Q3 — License body delivery:** inline `body` vs `document_url` (or both). UI
  handles both; if only URLs, the read affordance opens the authenticated doc.
- **Q4 — Field validation authority:** whether final required-field validation is
  client-side (from AND-342 placement) or server-only. Plan: trust AND-342 for
  enablement, rely on server `422` as the backstop with inline mapping.
- **Risk — unreliable dev host:** flaky submits during testing; mitigated by
  manual retry + idempotency, and MockWebServer-based deterministic tests.
- **Q5 — Process-death durability** of `idempotency_key`/draft accepts is deferred
  to AND-344's `SavedStateHandle` handling.

## 14. Acceptance Criteria

AC-1. From a packet with all required signature/data fields placed (AND-342),
required license agreements are fetched and displayed with read affordances.
AC-2. **Sign & Submit** is disabled until **every** `required` license is
accepted, then becomes enabled.
AC-3. Submitting a valid signed packet POSTs to
`/ui/signing/packets/{packetId}/submit` with `field_values` + `accepted_licenses`
and, on `200`, **the signed packet submits and a confirmation is shown** (status
`completed`, completion time, certificate reference if returned) — satisfying the
backlog acceptance "Signed packet submits + confirms."
AC-4. The packet's terminal status is persisted to the Room cache and reflected in
the list/detail (AND-340) without a manual refresh.
AC-5. Submit performs **no** automatic retry; on failure a mapped error and manual
Retry (reusing the idempotency key) are shown.
AC-6. `409 already completed` and an already-terminal packet both resolve to the
confirmation/terminal view rather than an error.
AC-7. Validation `422` errors map to field-scoped messages where `loc` resolves.
AC-8. `licenseAgreements.ts` is ported: license fetch/accept DTOs, mappers, and
repository methods exist and are unit-tested.
AC-9. All listed unit and Compose tests pass in CI (AND-050/051).

## 15. Definition of Done

- `SigningApi` license/submit methods, `SigningRepository` license/submit methods,
  DTOs, mappers, domain models (`LicenseAgreement`, `SubmitResult`), and
  `SubmitSignSection` composable + `SubmitUiState` implemented under
  `com.testlogon.android` in `feature-signing` / `core-*` per layering.
- Endpoint paths and DTO field names verified against `/openapi.json`; Q1/Q3
  resolved and the unused acceptance branch removed.
- Success path persists terminal status to Room; confirmation UX implemented.
- Error mapping (AND-015), no-auto-retry-on-write, idempotency key, and 409/terminal
  handling implemented.
- Telemetry events (§10) emitted with redaction; debug logging redacts sensitive
  fields.
- Accessibility (TalkBack semantics, 48dp targets, live regions) and i18n
  (resourced strings, RTL-safe) verified.
- Unit + Compose tests (§11) authored and green in CI on build server and headless
  emulator; repository submit/license coverage ≥ 85%.
- KtLint/Detekt clean (AND-005); merged to `android-port`; AND-344 can consume the
  repository contract and composable.
