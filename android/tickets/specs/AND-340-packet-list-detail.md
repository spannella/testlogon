---
id: AND-340
title: Packet list + detail
milestone: M7
epic: E44
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-339]
blocks: [AND-341]
---

# AND-340 — Packet list + detail

> **REVIEWER NOTE (2026-06-06, AND-340 amendment):** This spec was written against an
> assumed `GET /ui/signing/packets` list contract that **does not exist** in the backend
> or the web reference app. Verified against `openapi.index.txt`, `openapi.pretty.json`,
> and `src/api/endpoints/signaturePackets.ts`, the signing surface exposes **no
> packet-list endpoint** — only single-packet operations under `/v1/signature-packets`
> (create + `GET /v1/signature-packets/{packet_id}` detail). The web reference app
> (`SignaturePacketComposer.tsx`) has **no browse/list screen**: a user creates a draft
> or pastes a Packet ID to load one packet at a time. The detail DTO is
> `SignaturePacketDetailOut` (`packet_id`, `signers[]`, `fields[]`, `source_path`,
> `capabilities`, `role`), **not** the `recipients[]` / `documents[]` / `title` /
> `updated_at` shape assumed below. Status enum is
> `draft|sent|partially_signed|completed|cancelled|expired`. Inline corrections are
> applied throughout; see §16 for the full audit and §17 for the test plan. The "list"
> half of this ticket is **blocked pending a backend list endpoint** (see §16 Open
> assumptions / §13 R1).

## 1. Overview & Goal

Build the entry surfaces for the e-signature ("signing") feature area on Android:
a **packet list** screen that shows every signature packet visible to the
authenticated user, and a **packet detail** screen that opens when a list row is
tapped. A *packet* is a signing envelope — a bundle of one or more documents plus
a set of recipients/signers and an overall workflow status (draft, sent, in
progress, completed, declined, voided, expired). This ticket owns the
list-and-detail UI, their ViewModels and `UiState` types, the `SignatureRepository`
read paths that back them, and a clear, accurate rendering of **packet status**
for both the list rows and the detail header.

This ticket explicitly does **not** render document pages (that is **AND-341 — PDF
rendering**, which consumes the document references surfaced by this detail screen)
and does **not** implement signature capture or field placement (**AND-342**). It
also does not define the wire DTOs or Retrofit `SignatureApi`; those are owned by
the dependency **AND-339 — Signing API + DTOs** (`signaturePackets.ts` /
`signatureTemplates.ts` equivalents). Here we consume AND-339's DTOs and API
surface, map them to UI models, and present them.

Success means: a signed-in user opens the Signing area, sees a scrollable list of
their packets each showing title, counterparty/recipient summary, a status chip,
and a relative timestamp; tapping a row navigates to a detail screen that loads
and renders the full packet — metadata, ordered recipient list with per-recipient
status, the document manifest (as a placeholder list ready for AND-341), and a
status-driven primary action affordance. Loading, empty, offline, and retriable
error states are handled against the unreliable dev backend.

## 2. Context & References

- **Module:** `feature-signing` (new), namespace
  `com.testlogon.android.feature.signing`. Depends on `core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`. The DTOs/API from
  AND-339 live in `core-network`/`core-model` and are imported, not redefined.
- **Upstream (AND-339):** provides Moshi DTOs and the Retrofit `SignatureApi`
  interface plus DTO→domain adapters. **[CORRECTED]** The DTO names assumed here
  (`PacketDto`, `PacketSummaryDto`, `RecipientDto`, `DocumentRefDto`,
  `PacketListResponseDto`) do not match the backend; the real detail DTO is
  `SignaturePacketDetailOut` and create is `CreateSignaturePacketIn`/`Out`
  (verified `openapi.pretty.json` and `src/api/endpoints/signaturePackets.ts`).
  There is **no** `PacketListResponseDto` / list DTO because there is no list
  endpoint. This ticket adds the repository read methods and the UI on top.
- **Downstream (AND-341):** PDF rendering consumes
  `PacketDetail.documents: List<DocumentRef>` (id + download/stream URL +
  page count) surfaced by this screen. **AND-342** consumes recipient + field
  metadata for capture/placement.
- **Auth:** **[CORRECTED]** the web client (`src/api/client.ts`) sends **three**
  things on every call: an `Authorization: Bearer <accessToken>` header (from the
  auth store), the `X-CSRF-Token` header echoed from the `ui_csrf` cookie, and
  `credentials: "include"` (session cookie). The Android port must mirror whichever
  of these AND-011/AND-012 standardize on; do not assume cookie-only. The single-shot
  `POST /ui/session/refresh` on 401 (AND-013) is **verified** in `client.ts`
  (`refreshSession`), including the de-duped in-flight `refreshPromise` and
  logout-on-second-401. UI treats a post-refresh failure as terminal `Error`, never a
  loop. Note: at the OpenAPI layer these endpoints declare params
  `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`, which the web client does not all
  send directly — reconcile the exact header set in AND-339/AND-011.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff on idempotent GETs
  only — AND-016). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/signaturePackets.ts`, shared types
  `frontend/src/api/types.ts`.
- **Shared infra:** `ApiResult<T>` (AND-018), FastAPI `detail` error mapping
  (AND-015), state composables `LoadingState`/`EmptyState`/`ErrorState`/
  `OfflineState` (AND-021), Material 3 theme (AND-019), Navigation host (AND-022).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (optional read cache),
  Coil. minSdk 24, compile/target 35.

## 3. Functional Requirements

FR-1. **List load.** Entering the Signing area issues a list fetch; a full-screen
centered progress indicator shows while the first load is in flight.

FR-2. **List rendering.** **[CORRECTED — depends on a non-existent list endpoint; see
§5/§13 R1.]** If a list endpoint is added, each row renders: a packet label
(**from `source_path`**, since there is no `title`), a signer-count summary (the DTO
returns only `signers[]` of `{signer_id,status}` — **no names/emails**, so "You + N
others" cannot be built without more data), a **status chip** with status-specific
label/color, and a timestamp derived from `created_at`/`sent_at` (**there is no
`updatedAt`**). Until then this requirement is not implementable.

FR-3. **Status filtering.** **[CORRECTED — no list endpoint and no `status` query
param exist; see §5.]** Server-side filtering is impossible and client-side filtering
has nothing to filter until a list endpoint lands. If/when one exists, the buckets
*All / Action required / Waiting / Completed* would map onto the real enum
(`draft|sent|partially_signed|completed|cancelled|expired`) + `role`/`signer_status`,
not the assumed states. Deferred with the list surface.

FR-4. **Empty state.** When the (filtered) list is empty, render `EmptyState` with
copy appropriate to the active filter ("No packets yet" vs "Nothing needs your
action").

FR-5. **Open detail.** Tapping a row navigates to `signing/packet/{packetId}` and
the detail screen loads that packet by id.

FR-6. **Detail rendering.** **[CORRECTED to the real DTO.]** Detail shows: a header
with a label derived from `source_path` (no `title`) + a large status chip + a
timeline of `created_at`/`sent_at`/`completed_at` (no `updated_at`); a **signers** list
of `{signer_id, status: pending|completed}` (the DTO has no name/email/order — render
ids/status, not "ordered recipients with names"); the **`source_path`** document
reference (single path, not a multi-document manifest with page counts/URLs); and a
status-driven primary action region driven by `role`/`signer_status`/`capabilities`.

FR-7. **Primary action affordance.** When the packet status and the current
user's recipient state imply an action ("Review & sign"), detail shows an enabled
primary button. This ticket renders the affordance and routes toward AND-341/342;
when the user has no pending action (completed/declined/waiting on others) the
button is hidden or disabled with an explanatory caption. No signing is performed
here.

FR-8. **Pull-to-refresh.** Both screens support pull-to-refresh that re-issues the
GET and reconciles state without clearing already-shown content on success.

FR-9. **Resilience states.** Both screens distinguish *offline* (no connectivity)
from *backend error* (reachable but failed/timed out) and each offers retry.

## 4. Technical Design

New package layout under `com.testlogon.android.feature.signing`:

```
feature-signing/
 ├─ data/    SignatureRepository (interface) + SignatureRepositoryImpl
 ├─ model/   PacketSummary, PacketDetail, Recipient, DocumentRef, PacketStatus
 ├─ list/    PacketListViewModel, PacketListUiState, PacketListScreen
 ├─ detail/  PacketDetailViewModel, PacketDetailUiState, PacketDetailScreen
 └─ nav/     SigningNavGraph (routes + typed args)
```

Domain models (mapped from AND-339 DTOs; UI never touches DTOs directly):

**[CORRECTED]** `PacketStatus` must mirror the real backend enum
(`draft|sent|partially_signed|completed|cancelled|expired`). `IN_PROGRESS`,
`DECLINED`, and `VOIDED` are **not** backend states; `partially_signed` and
`cancelled` were missing. `RecipientStatus` below should be `SignerStatus { PENDING,
COMPLETED }` — the DTO has no `viewed`/`signed`/`declined`/`sent` signer states.

```kotlin
enum class PacketStatus { DRAFT, SENT, PARTIALLY_SIGNED, COMPLETED, CANCELLED, EXPIRED, UNKNOWN }

// [CORRECTED] PacketSummary is speculative — no list endpoint returns it. If a list
// endpoint is added, fields available will depend on that endpoint; the detail DTO has
// no title/updatedAt/recipientCount and signers carry no names, so counterpartyLabel
// cannot be built from current data. Keep this as a placeholder pending §13 R1.
data class PacketSummary(
    val packetId: String,            // [CORRECTED] was id
    val label: String,               // [CORRECTED] derive from source_path; no title
    val status: PacketStatus,
    val createdAt: Instant?,         // [CORRECTED] no updatedAt exists
)

// [CORRECTED] The detail DTO returns signers as { signer_id, status } only — no
// displayName/email/order/isCurrentUser. Model accordingly:
data class Signer(
    val signerId: String,
    val status: SignerStatus,        // PENDING, COMPLETED  (only these exist)
)

// [CORRECTED] No documents[] in the DTO — there is a single source_path string and a
// fields[] overlay. AND-341 renders source_path; there is no per-document name/url/
// pageCount available from this endpoint.
data class SourceDocument(val sourcePath: String)

data class PacketDetail(
    val packetId: String,                 // [CORRECTED] was id
    // [CORRECTED] no title in DTO; derive a label from sourcePath in the UI layer
    val status: PacketStatus,
    val createdAt: Instant?,              // [CORRECTED] nullable
    val sentAt: Instant?,                 // [CORRECTED] replaces updatedAt (no updatedAt exists)
    val completedAt: Instant?,
    val signers: List<Signer>,            // [CORRECTED] was recipients
    val sourcePath: String,               // [CORRECTED] was documents: List<DocumentRef>
    val role: PacketRole,                 // SENDER, SIGNER  (server-provided)
    val signerStatus: SignerStatus?,      // server-provided
    val capabilities: PacketCapabilities, // can_edit_fields, can_send, can_fill_fields
    val currentUserAction: PacketAction,  // derived from role/signerStatus/capabilities
)
// Note: createdAt/sentAt/completedAt are nullable; there is no updatedAt.
```

Repository:

```kotlin
interface SignatureRepository {
    suspend fun listPackets(filter: PacketFilter): ApiResult<List<PacketSummary>>
    suspend fun getPacket(packetId: String): ApiResult<PacketDetail>
}
```

`SignatureRepositoryImpl` (`@Singleton`, `@Inject`) calls `SignatureApi`, maps
DTO→domain via AND-339 adapters, and computes derived fields (`counterpartyLabel`,
`actionRequired`, `currentUserAction`) using the current user id from the
auth-state store (AND-029). Errors are funneled through `ApiResult` with
`detail`-mapped messages (AND-015). Bound backoff retry applies only to these GETs
(AND-016).

ViewModels expose `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class PacketListViewModel @Inject constructor(
    private val repo: SignatureRepository,
    private val connectivity: ConnectivityObserver,
) : ViewModel() {
    val uiState: StateFlow<PacketListUiState>
    fun onFilterSelected(filter: PacketFilter)
    fun refresh()
    fun retry()
}

@HiltViewModel
class PacketDetailViewModel @Inject constructor(
    private val repo: SignatureRepository,
    savedStateHandle: SavedStateHandle,   // packetId nav arg
) : ViewModel() {
    val uiState: StateFlow<PacketDetailUiState>
    fun refresh()
    fun retry()
}
```

Composables: `PacketListScreen(onPacketClick: (String) -> Unit)`,
`PacketDetailScreen(onBack: () -> Unit, onOpenDocument: (packetId: String, documentId: String) -> Unit)`.
`onOpenDocument` is the seam handed to AND-341. A shared `StatusChip(status: PacketStatus)`
and `RecipientRow(recipient: Recipient)` live in `feature-signing` (promote to
`core-ui` only if reused elsewhere).

Navigation (AND-022): `SigningNavGraph` registers
`signing/packets` (list) and `signing/packet/{packetId}` (detail) inside the
authenticated graph; `packetId` is a non-null `String` nav arg read via
`SavedStateHandle`.

## 5. API Contract

**[CORRECTED — verified against `openapi.index.txt` lines 2413–2421,
`components.schemas.SignaturePacketDetailOut` / `CreateSignaturePacketIn` /
`CreateSignaturePacketOut` in `openapi.pretty.json`, and
`src/api/endpoints/signaturePackets.ts`.]** The paths, methods, and DTO shapes
originally written here were wrong on every count. The real contract:

**List — DOES NOT EXIST.** There is no `GET /ui/signing/packets` (or any list/browse
endpoint) in the backend OpenAPI, and `signaturePackets.ts` exposes no list call. The
web reference (`SignaturePacketComposer.tsx`) provides no browse screen: the user
either creates a draft (`POST /v1/signature-packets`) or pastes a known Packet ID and
calls detail. **The list half of this ticket cannot be implemented against the current
backend.** Options (decide in AND-339 / with backend): (a) get a list endpoint added,
(b) descope this ticket to detail-only + a "load by ID / create draft" entry surface
mirroring the web app, or (c) source packet IDs from an adjacent feature
(e.g. KYC links `POST /v1/kyc/cases/{case_id}/signature-packet`). Tracked in §13 R1
and §16 Open assumptions.

**Detail — `GET /v1/signature-packets/{packet_id}`** (verified). Response
`SignaturePacketDetailOut`:

```json
{
  "packet_id": "pkt_01HX...",
  "status": "partially_signed",
  "owner_user_id": "usr_123",
  "source_path": "/contracts/nda.pdf",
  "role": "signer",
  "signer_status": "pending",
  "created_at": "2026-06-01T09:00:00Z",
  "sent_at": "2026-06-02T10:00:00Z",
  "completed_at": null,
  "origin_channel": "share",
  "origin_ref": null,
  "signers": [
    { "signer_id": "sgn_1", "status": "pending" },
    { "signer_id": "sgn_2", "status": "completed" }
  ],
  "fields": [
    { "field_id": "fld_1", "page": 1, "x": 0.1, "y": 0.2, "width": 0.22, "height": 0.06,
      "field_type": "signature", "required": true, "assigned_signer_id": "sgn_1",
      "is_assigned_to_viewer": true, "filled_at": null }
  ],
  "capabilities": { "can_edit_fields": false, "can_send": false, "can_fill_fields": true },
  "legal_notice": { "required": true, "accepted": false, "version": "v2", "text": "..." }
}
```

Key shape corrections vs. the original draft:
- Id field is **`packet_id`**, not `id`.
- There is **no `title`** and **no `updated_at`** — timeline is `created_at` /
  `sent_at` / `completed_at` (web shows exactly these three). Title fallback must come
  from `source_path` (the PDF path), not a packet title.
- Recipients are **`signers[]`** with only `{ signer_id, status: "pending"|"completed" }`
  (plus arbitrary extra keys; the schema is `additionalProperties: true`). There is
  **no** `name`, `email`, `order`, or `is_self`. PII (names/emails) is **not** returned
  by this endpoint — adjust §8/§10 accordingly.
- There are **no `documents[]`** with `name`/`page_count`/`url`. The document is a
  single **`source_path`** string. Per-document page counts and a download URL are not
  in this DTO; the final combined PDF is `GET /v1/signature-packets/{packet_id}/final-pdf`
  (only when `status == "completed"`). AND-341 must render from `source_path` (+ overlay
  `fields[]`), not from a `documents` manifest.
- Status enum is **`draft|sent|partially_signed|completed|cancelled|expired`** — there
  is no `in_progress`, `declined`, `voided`, or `expired→viewed`. Map the domain
  `PacketStatus` to these. Signer status is only `pending|completed` (no `viewed`/`sent`/
  `declined`).
- `role` (`sender|signer`), `signer_status`, and `capabilities` (`can_edit_fields`,
  `can_send`, `can_fill_fields`) drive the "current user action" — these are
  **server-provided**, resolving §13 R2 in favour of trusting the server, not a client
  predicate. The web app's `statusChip()` derives the display label from
  `status` + `role` + `signer_status` (e.g. signer + `signer_status==pending` →
  "awaiting your signature").

**Create (entry surface, if descoping to web-parity)** —
`POST /v1/signature-packets`, body `CreateSignaturePacketIn`
`{ source_path (req), origin_channel: "share"|"message" (req), origin_ref? }`,
response `CreateSignaturePacketOut`
`{ packet_id, status, owner_user_id, source_path, origin_channel, created_at }`.

Headers/auth: see corrected §2 (Bearer + `X-CSRF-Token` + session cookie). The detail
call is an idempotent GET (eligible for bounded backoff retry). On `401` the client
performs one `POST /ui/session/refresh` then retries; post-refresh failure is terminal
`Error` (verified `client.ts`). Error bodies follow the FastAPI `detail` contract
(`string | [{msg}] | {code,...}`) — verified in `client.ts: normalizeErrorDetail` and
mapped by AND-015. **[UNVERIFIED]** A `404 → "Packet not found"` terminal state is a
reasonable design, but the OpenAPI only documents `200` and `422` for this path
(no `404` declared); treat 404-handling as a defensive assumption and any non-2xx as a
generic mapped error until confirmed.

## 6. Data & State Management

`PacketListUiState` (sealed): `Loading`, `Content(items, activeFilter, refreshing)`,
`Empty(activeFilter)`, `Offline`, `Error(message, retryable=true)`.
`PacketDetailUiState` (sealed): `Loading`, `Content(packet, refreshing)`,
`NotFound`, `Offline`, `Error(message)`.

State is derived in the ViewModel via `stateIn(viewModelScope, WhileSubscribed(5_000), Loading)`.
The active filter is held in `SavedStateHandle` (key `signing_filter`) so it
survives process death and config changes. `refresh()` sets `refreshing=true` on
the existing `Content` rather than collapsing to `Loading`, preserving on-screen
rows during pull-to-refresh.

**Caching (optional, recommended):** persist the last successful list and each
opened detail to Room (`PacketSummaryEntity`, `PacketDetailEntity` in `core-data`)
keyed by id, with a fetched-at timestamp, to power the offline/stale baseline
(consistent with AND-045's pattern). On `Offline`, emit cached content tagged
*stale* with a banner instead of a blank error when a cache row exists. If Room
caching is deferred, `Offline` shows the offline state directly; the cache is then
the responsibility of a follow-up and must be noted in §13.

Relative timestamps are computed in the composable layer from the available
timestamps — **[CORRECTED]** `createdAt`/`sentAt`/`completedAt`, **not** `updatedAt`
(which the DTO does not provide) — using a `DateUtils`-style formatter to avoid stale
strings.

## 7. Error Handling & Resilience

- **Timeouts:** rely on the 20s OkHttp timeouts (AND-009); a timeout surfaces as
  retryable `Error("Server timed out")`.
- **Bounded backoff:** both GETs are idempotent and use the AND-016 retry policy;
  no retry on `404`/`401`-after-refresh.
- **Offline vs error:** `ConnectivityObserver` (AND-017) distinguishes the two so
  copy and iconography differ; both expose retry.
- **Partial detail:** if `documents` is empty but the packet is otherwise valid,
  detail renders metadata and shows an inline "No documents attached" note rather
  than failing.
- **Refresh failure:** a failed pull-to-refresh keeps existing content and shows a
  transient snackbar ("Couldn't refresh"), never wiping the list.
- **Unknown status:** any unrecognized status string maps to `PacketStatus.UNKNOWN`
  rendered as a neutral chip labeled "Unknown" — forward-compatible with new
  backend states.

## 8. Security & Privacy

- All traffic is cookie-authenticated; the persistent cookie jar (AND-011) and
  CSRF header (AND-012) are mandatory. No tokens or credentials are logged.
- **[CORRECTED]** The detail DTO does **not** return recipient names or emails
  (`signers[]` is `{signer_id, status}` only — verified `SignaturePacketDetailOut`),
  so there is no recipient-PII rendering in this ticket. `source_path` (a file path)
  and `signer_id`/`owner_user_id` are still sensitive identifiers: never log them.
  Keep the no-PII-logging rule (§10) as forward-protection if a future list endpoint
  adds names/emails.
- Document URLs are relative API paths resolved through the authenticated OkHttp
  client; they are not exposed to external intents in this ticket (AND-341 streams
  them through the same client).
- The dev backend is plaintext HTTP, tolerated only for the dev flavor's
  cleartext-permitted host (AND-006); release builds disallow cleartext.
- No packet content is written to external/shared storage; optional Room cache is
  app-private internal storage.

## 9. Accessibility & i18n

- All actionable rows/buttons have `contentDescription`/`semantics`; status chips
  expose their textual status to TalkBack (color is never the sole signal — chips
  carry a label).
- Touch targets ≥ 48dp; list rows are a single merged semantics node with a clear
  "Open packet, {title}, status {status}" description.
- Dynamic type respected via Material 3 typography; layouts reflow at large font
  scales without clipping.
- All user-facing strings live in `res/values/strings.xml` (no hardcoded copy);
  status labels and filter names are string resources. Relative timestamps use
  locale-aware formatting. RTL supported via start/end padding.

## 10. Telemetry & Logging

- Structured debug logs (redacted) for `list_loaded{count,filter,ms}`,
  `detail_loaded{packetId_hashed,recipientCount,ms}`, `list_error{type}`,
  `detail_error{type}` via the app logger (AND-052 redaction conventions).
- **Never** log `source_path`, `owner_user_id`, `signer_id`, or (if ever added) any
  recipient names/emails. **[CORRECTED]** the DTO has no packet title or document
  names/URLs to leak, but the rule stands for `source_path`. `packetId` is
  hashed/truncated in logs.
- Latency timings captured for the two GETs to monitor the unreliable dev host.
- No third-party analytics added by this ticket.

## 11. Testing Strategy

**Unit (JVM, `core-testing` + MockWebServer per AND-046):**
- `SignatureRepositoryImpl` maps list/detail JSON fixtures → domain, including
  `counterpartyLabel`, `actionRequired`, and `currentUserAction` derivation.
- Unknown status string → `PacketStatus.UNKNOWN`.
- Error fixtures: 401-then-refresh-then-200 retry path; 404 → `NotFound`; timeout
  → retryable error; FastAPI `detail` shapes → mapped message.
- ViewModel tests (Turbine): `Loading → Content`, `Loading → Empty`,
  `Loading → Offline`, `Loading → Error → retry → Content`; filter change
  re-queries and survives `SavedStateHandle` restore; refresh keeps content on
  failure.

**Compose UI tests (AND-049 harness style):**
- List renders rows with title/status/timestamp; tapping a row invokes
  `onPacketClick` with the correct id.
- Filter chips switch state and trigger reload.
- Empty/offline/error states render with retry.
- Detail renders header, recipient rows, document manifest, and shows/hides the
  primary action per `currentUserAction`.

**Acceptance smoke:** against the live dev backend, list loads and detail opens
for at least one real packet.

## 12. Dependencies & Sequencing

- **Depends on AND-339** (Signing API + DTOs) — hard dependency; provides
  `SignatureApi` + DTOs + adapters this ticket consumes. Cannot start the data
  layer until AND-339's DTO shapes are stable, though UI scaffolding can proceed
  against fixtures.
- **Depends transitively** on session/network stack: AND-011 (cookie jar),
  AND-012 (CSRF), AND-013 (401 refresh), AND-015 (error mapping), AND-016
  (retry), AND-017 (connectivity), AND-018 (`ApiResult`), AND-021 (state
  composables), AND-022 (nav host), AND-029 (current-user store).
- **Blocks AND-341** (PDF rendering) — **[CORRECTED]** consumes
  `PacketDetail.sourcePath` (single PDF path) + `fields[]` overlay, not a
  `PacketDetail.documents` manifest; the `onOpenDocument` seam should pass
  `(packetId, sourcePath)`. **AND-342** (signature capture) follows AND-341 and reuses
  `signers`/`role`/`capabilities`/action state from this detail screen.

## 13. Risks & Open Questions

- **R1 — [RESOLVED/ESCALATED] No list endpoint exists.** Verified: there is no
  packet-list API and no list DTO (`openapi.index.txt` 2413–2421;
  `signaturePackets.ts` has no list call). The §5 detail shape is now confirmed
  (`SignaturePacketDetailOut`). **Blocker:** the "packet list" half of AND-340 cannot
  be built until either a backend list endpoint lands or the ticket is descoped to
  detail + load-by-ID/create entry (web-parity). Raise with backend before starting.
- **R2 — [RESOLVED] action derivation is server-provided.** The detail DTO carries
  `role`, `signer_status`, and `capabilities.{can_fill_fields,can_send,can_edit_fields}`;
  the web app derives the action/chip from `status` + `role` + `signer_status`
  (`SignaturePacketComposer.tsx: statusChip`). Use these server fields rather than a
  client `is_self`/ordering predicate (those fields don't exist). "Awaiting your
  signature" = `role=="signer" && signer_status=="pending"`; sender + `sent`/
  `partially_signed` = "waiting on others".
- **R3 — Pagination.** **[CORRECTED]** moot: there is no list endpoint, so no
  `next_cursor` / `limit` and nothing to paginate. The `next_cursor` field shown in the
  original §5 was fabricated. Re-evaluate only if/when a list endpoint is added.
- **R4 — Caching scope.** Room offline cache (§6) is recommended but may be
  deferred to keep this ticket M-sized; if deferred, `Offline` shows the plain
  offline state and a follow-up ticket owns stale caching.
- **R5 — Unreliable dev host** may make acceptance smoke flaky; rely on
  MockWebServer fixtures for deterministic CI and treat live smoke as best-effort.

## 14. Acceptance Criteria

AC-1. Signed-in user opening the Signing area sees their packets rendered as a
list with title, recipient summary, status chip, and relative timestamp
(satisfies source acceptance "Packets render").
AC-2. Tapping a packet row navigates to the detail screen and the full packet
loads and renders (satisfies "detail opens").
AC-3. Status is shown correctly on both list rows and the detail header, including
a neutral fallback for unknown statuses.
AC-4. Status filter (All / Action required / Waiting / Completed) re-queries the
list and the selection survives rotation/process death.
AC-5. Loading, empty, offline, and retriable error states render on both screens;
retry recovers when the backend returns 200.
AC-6. Pull-to-refresh re-fetches without clearing already-shown content on
success and keeps content with a snackbar on failure.
AC-7. Detail surfaces ordered recipients with per-recipient status and a document
manifest, and exposes an `onOpenDocument` seam for AND-341.
AC-8. No PII (recipient names/emails, titles, document names/URLs) appears in
logs; `packetId` is hashed.
AC-9. Repository mapping and both ViewModels' state transitions are covered by
unit tests; list and detail have Compose UI tests; all green in CI.

## 15. Definition of Done

- `feature-signing` module created under namespace
  `com.testlogon.android.feature.signing`, wired into the authenticated nav graph
  with routes `signing/packets` and `signing/packet/{packetId}`.
- `SignatureRepository` + impl, ViewModels, `UiState` types, and both screens
  implemented per §4 against AND-339's DTOs/API.
- All 15 functional requirements and all acceptance criteria met.
- Unit + Compose UI tests written and passing in CI (AND-050/AND-051 pipelines);
  no decrease in module coverage gate.
- Lint/Detekt/ktlint clean (AND-005); no hardcoded user-facing strings.
- Accessibility checks (TalkBack labels, 48dp targets, dynamic type) verified.
- No PII logged; cleartext restricted to dev flavor host.
- PR notes any deferred items (pagination R3, caching R4) and links AND-341 as the
  downstream consumer of `documents` / `onOpenDocument`.
- Reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`openapi.index.txt` (OpenAPI endpoint index), `openapi.pretty.json`
(`components.schemas.*`), and the frontend reference under `reference/src/`.

1. **List endpoint `GET /ui/signing/packets?status=&limit=`.** VERDICT: **Corrected
   (does not exist).** No such path in the OpenAPI index and no list call in
   `src/api/endpoints/signaturePackets.ts`. Source: `openapi.index.txt` (only signing
   paths are `/ui/signing/templates*` and `/v1/signature-packets*`, lines 1871–1875,
   2413–2421); `src/api/endpoints/signaturePackets.ts` (exports create/getDetail/
   fields/send/fill/mark-done/ack-legal-notice/final-pdf only — no list).
2. **Detail endpoint `GET /ui/signing/packets/{packet_id}`.** VERDICT: **Corrected →
   `GET /v1/signature-packets/{packet_id}`.** Source: `openapi.index.txt` line 2414
   (`GET /v1/signature-packets/{packet_id} | op=get_signature_packet_detail | resp=200:SignaturePacketDetailOut`);
   `src/api/endpoints/signaturePackets.ts: getSignaturePacketDetail`.
3. **Detail response shape (id/title/recipients/documents/updated_at).** VERDICT:
   **Corrected.** Real schema fields: `packet_id, status, owner_user_id, source_path,
   role, signer_status, created_at, sent_at, completed_at, signers[], fields[],
   capabilities, legal_notice, origin_channel, origin_ref`. No `id`/`title`/`recipients`/
   `documents`/`updated_at`. Source: `openapi.pretty.json` →
   `components.schemas.SignaturePacketDetailOut`;
   `src/api/endpoints/signaturePackets.ts: SignaturePacketDetail`.
4. **Recipients are `recipients[]` with name/email/order/is_self/status
   (sent|viewed|signed|declined|pending).** VERDICT: **Corrected.** Real field is
   `signers[]` of `{ signer_id, status: "pending"|"completed" }` (plus
   `additionalProperties`); no name/email/order/is_self. Source:
   `SignaturePacketDetailOut.signers` (`openapi.pretty.json`);
   `src/api/endpoints/signaturePackets.ts: SignaturePacketSigner`.
5. **Documents are `documents[]` with name/page_count/url.** VERDICT: **Corrected.**
   Single `source_path` string; combined output is `GET /v1/signature-packets/
   {packet_id}/final-pdf` (completed only). Source: `SignaturePacketDetailOut.source_path`;
   `openapi.index.txt` line 2419; `src/api/endpoints/signaturePackets.ts:
   downloadSignaturePacketFinalPdf`.
6. **Packet status enum draft|sent|in_progress|completed|declined|voided|expired.**
   VERDICT: **Corrected →** `draft|sent|partially_signed|completed|cancelled|expired`.
   Source: `src/api/endpoints/signaturePackets.ts: SignaturePacketStatus` (the
   OpenAPI status field is an open `string`, so the TS union is authoritative).
7. **Current-user action is derivable / may need a client predicate (is_self +
   ordering).** VERDICT: **Corrected → server-provided.** Driven by `role`
   (`sender|signer`), `signer_status` (`pending|completed`), and `capabilities`
   (`can_edit_fields|can_send|can_fill_fields`). Source: `SignaturePacketDetailOut`
   (`role`, `signer_status`, `capabilities`); display mapping in
   `src/pages/files/SignaturePacketComposer.tsx: statusChip`.
8. **Auth = cookie jar + `X-CSRF-Token` only.** VERDICT: **Corrected/clarified.** Web
   client sends `Authorization: Bearer <accessToken>` **and** `X-CSRF-Token` (from
   `ui_csrf` cookie) **and** `credentials: "include"`. Source:
   `src/api/client.ts` (lines ~157–171). OpenAPI declares params
   `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN` for these ops (`openapi.index.txt`
   2413–2421) — reconcile in AND-011/AND-339.
9. **401 → single-shot `POST /ui/session/refresh`, then retry; terminal on
   second failure.** VERDICT: **Verified.** Source: `src/api/client.ts:
   refreshSession` + 401 branch (de-duped `refreshPromise`, `logout("session_expired")`
   on retry-401).
10. **FastAPI `detail` error contract `string | [{msg}] | {code,...}`.** VERDICT:
    **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` and
    `mapAuthorizationError`; OpenAPI `HTTPValidationError` (422) on all signing ops.
11. **`404 → "Packet not found"` terminal state.** VERDICT: **Unverified-assumption.**
    OpenAPI documents only `200` and `422` for `GET /v1/signature-packets/{packet_id}`
    (`openapi.index.txt` line 2414); no `404` is declared. Reasonable defensive design
    but unconfirmed. Source: `openapi.index.txt` line 2414.
12. **Pagination via `next_cursor`/`limit`.** VERDICT: **Corrected (fabricated).** No
    list endpoint, hence no cursor/limit. Source: absence in `openapi.index.txt` /
    `signaturePackets.ts`.
13. **Bounded backoff retry on idempotent GET detail.** VERDICT:
    **Unverified-assumption (Android-side policy).** Governed by AND-016, not the web
    client (web does no backoff retry — `src/api/client.ts` only retries once after a
    refresh). Carry as an Android design choice.
14. **Create draft = `POST /v1/signature-packets` with `{source_path, origin_channel,
    origin_ref?}`.** VERDICT: **Verified.** Source: `openapi.index.txt` line 2413;
    `components.schemas.CreateSignaturePacketIn`/`CreateSignaturePacketOut`;
    `src/api/endpoints/signaturePackets.ts: createSignaturePacket`.
15. **Web app has a packet "list/browse" screen.** VERDICT: **Corrected (none).** The
    only signing UI is a single-packet composer where the user creates a draft or pastes
    a Packet ID to `Load`. Source: `src/pages/signing/SigningPage.tsx`,
    `src/pages/files/SignaturePacketComposer.tsx`.
16. **Compose / Material 3 / Hilt / Coroutines stack (§2).** VERDICT:
    **Unverified-assumption (framework ref).** Not derivable from backend/frontend
    sources; standard modern Android stack. Framework refs:
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/training/dependency-injection/hilt-android .
17. **MockWebServer for contract tests; Robolectric/JVM for unit; instrumented on
    emulator/device.** VERDICT: **Unverified-assumption (framework ref).** Test-infra
    choice. Framework refs: https://github.com/square/okhttp/tree/master/mockwebserver ,
    https://developer.android.com/training/testing/instrumented-tests .

### Corrections made

- §5 rewritten: list endpoint removed (does not exist); detail path corrected to
  `GET /v1/signature-packets/{packet_id}`; JSON replaced with the real
  `SignaturePacketDetailOut` shape; create endpoint documented; 404 handling marked
  unverified.
- Status enum corrected throughout to
  `draft|sent|partially_signed|completed|cancelled|expired` (§4, §5, §7-by-reference).
- `recipients[]`→`signers[]` ({signer_id,status}); `documents[]`→single `source_path`;
  `title`/`updated_at` removed; domain models in §4 updated (`Signer`, `SourceDocument`,
  `PacketDetail`, `PacketSummary`).
- Auth clarified (§2): Bearer + CSRF + cookie, not cookie-only.
- FR-2, FR-3, FR-6 flagged: list/filter unbuildable without a list endpoint; detail
  rendering re-scoped to the real DTO. R1/R2/R3 updated. §8/§10 PII corrected (no
  recipient names/emails in the DTO; `source_path` is the sensitive field). §12 AND-341
  seam corrected to `(packetId, sourcePath)`.

### Open assumptions

- **No backend packet-list endpoint exists** — the entire "list" half of AND-340 is
  blocked. Cannot be verified into existence; needs a backend decision (add endpoint vs.
  descope to detail + load-by-ID/create). (Why: confirmed absent in OpenAPI and
  frontend.)
- **404 on detail** is not in the OpenAPI; "Packet not found" handling is defensive
  only. (Why: only 200/422 documented.)
- **Bounded-backoff retry policy** for the detail GET is an Android-side (AND-016)
  choice; the web client does not do it. (Why: not in shared sources.)
- **Stack/test-infra choices** (Compose, Hilt, MockWebServer, Robolectric, emulator/
  device split) are framework conventions, not derivable from the backend/frontend.
  (Why: out of scope of the cited sources; labeled framework refs above.)

## 17. Test Plan

Test targets: **JVM/Robolectric** (local, no device); **emulator** = headless AVD
`test35` (x86_64, API 35) for fast UI/instrumented CI; **physical device** = Samsung
Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a) for real-hardware/ABI
behavior. Most of this ticket is plain Compose + Retrofit with no camera/biometrics/
WebRTC/FCM, so the physical device is needed only for the ABI/API-level smoke
(TC-AND-340-12) and the real-flaky-host smoke (TC-AND-340-09).

- **TC-AND-340-01 — Detail happy path mapping.** Type: contract/MockWebServer (JVM).
  Target: JVM/Robolectric. Preconditions: MockWebServer enqueues a valid
  `SignaturePacketDetailOut` (per §5) for `GET /v1/signature-packets/{id}`. Steps: call
  `SignatureRepository.getPacket("pkt_1")`. Expected: `ApiResult.Success` with
  `packetId`, mapped `PacketStatus`, `signers[].status`, `sourcePath`, `role`,
  `signerStatus`, `capabilities` populated; no `title`/`updatedAt` referenced. Traces:
  AC-2, AC-7.
- **TC-AND-340-02 — Status enum mapping incl. all six values.** Type: unit (JVM).
  Target: JVM. Preconditions: fixtures for `draft|sent|partially_signed|completed|
  cancelled|expired`. Steps: map each status string. Expected: each maps to the matching
  `PacketStatus`; verify `partially_signed`/`cancelled` are handled (the corrected
  enum). Traces: AC-3.
- **TC-AND-340-03 — Unknown status → UNKNOWN chip.** Type: unit + Compose-UI. Target:
  JVM (map) + emulator (chip render). Preconditions: detail fixture with
  `status:"some_future_state"`. Steps: map, then render `StatusChip`. Expected:
  `PacketStatus.UNKNOWN`, neutral chip labeled "Unknown", no crash. Traces: AC-3.
- **TC-AND-340-04 — Current-user action from role/signer_status/capabilities.** Type:
  unit (JVM). Target: JVM. Preconditions: fixtures: (a) `role=signer,
  signer_status=pending, can_fill_fields=true`; (b) `role=signer,
  signer_status=completed`; (c) `role=sender, status=sent`. Steps: derive action/chip
  label. Expected: (a) "awaiting your signature"/action enabled; (b) "waiting on
  others"; (c) "waiting on others" — matching `SignaturePacketComposer.tsx: statusChip`.
  Traces: AC-7.
- **TC-AND-340-05 — Detail ViewModel state flow Loading→Content / →Error→retry→
  Content.** Type: unit (Turbine, JVM). Target: JVM. Preconditions: fake repo emits
  error then success. Steps: collect `uiState`; call `retry()`. Expected:
  `Loading → Error(retryable) → (retry) → Content`. Traces: AC-2, AC-5.
- **TC-AND-340-06 — FastAPI `detail` error-shape mapping.** Type: contract/MockWebServer
  (JVM). Target: JVM. Preconditions: enqueue 400 with `{"detail":"x"}`,
  `{"detail":[{"msg":"y"}]}`, and `{"detail":{"code":"role_required"}}`. Steps: call
  `getPacket`. Expected: messages normalized exactly as `client.ts: normalizeErrorDetail`
  (string passthrough; `[{msg}]` joined; `code` mapped to human text). Traces: AC-5.
- **TC-AND-340-07 — 401 → single refresh → retry success.** Type: contract/MockWebServer
  (JVM). Target: JVM. Preconditions: enqueue 401, then 200 for
  `POST /ui/session/refresh`, then 200 detail. Steps: call `getPacket` while
  authenticated. Expected: exactly one refresh, then `Content`; verify no refresh loop.
  Traces: AC-5.
- **TC-AND-340-08 — 401 → refresh fails → terminal Error (no loop).** Type:
  contract/MockWebServer (JVM). Target: JVM. Preconditions: enqueue 401, then 401 on
  refresh. Steps: call `getPacket`. Expected: terminal `Error`/logout, single refresh
  attempt only. Traces: AC-5, AC-8(security: session teardown).
- **TC-AND-340-09 — Offline vs backend-error distinction + flaky-host retry.** Type:
  integration / manual smoke. Target: **physical device** (toggle real airplane mode +
  hit the real flaky dev host `http://18.222.237.167:8000`); emulator acceptable for the
  airplane-mode half. Preconditions: signed-in session, a known real `packet_id`. Steps:
  (a) airplane mode → open detail; (b) re-enable, retry; (c) repeat against the live host
  to exercise timeout/backoff. Expected: (a) `Offline` state with retry (distinct copy/
  icon from error); (b) recovers to `Content`; (c) timeout surfaces retryable
  `Error("Server timed out")`, not a crash. Traces: AC-5, AC-6. MUST use physical device
  for the real-host timing leg.
- **TC-AND-340-10 — Detail Compose render + signers + source document.** Type:
  Compose-UI (instrumented). Target: emulator. Preconditions: `Content` with 2 signers
  (pending/completed) and one `source_path`, plus `fields[]`. Steps: render
  `PacketDetailScreen`. Expected: header label (derived from `source_path`, no title),
  status chip, timeline (created/sent/completed), signer rows showing
  `signer_id`+status, single source-document row; `onOpenDocument(packetId, sourcePath)`
  fired on tap. Traces: AC-2, AC-7.
- **TC-AND-340-11 — Accessibility on detail.** Type: Compose-UI / instrumented
  (accessibility). Target: emulator (TalkBack/`AccessibilityChecks`). Preconditions:
  `Content` rendered. Steps: enable `AccessibilityChecks.enable()`; assert semantics.
  Expected: status chip exposes text status (color not sole signal); actionable controls
  have `contentDescription`; touch targets ≥48dp; no a11y violations. Traces: AC-3,
  AC-9.
- **TC-AND-340-12 — ABI/API-level smoke (arm64 API 34 vs x86_64 API 35).** Type:
  instrumented/e2e. Target: **physical device** (arm64-v8a, API 34) AND emulator
  (x86_64, API 35). Preconditions: signed-in, real `packet_id`. Steps: load detail on
  both. Expected: identical mapping/render; no ABI- or API-34-vs-35-specific failures
  (e.g. `java.time`/`Instant` parsing of nullable timestamps). Traces: AC-2, AC-3. MUST
  run on physical device for the arm64/API-34 leg.
- **TC-AND-340-13 — No-PII / sensitive-field logging.** Type: unit (JVM, log capture).
  Target: JVM. Preconditions: load detail with a `source_path` and `owner_user_id`.
  Steps: trigger `detail_loaded`/`detail_error` logs; capture logger output. Expected:
  logs contain hashed `packetId` only; `source_path`, `owner_user_id`, `signer_id`
  never appear. Traces: AC-8.
- **TC-AND-340-14 — Create-draft entry surface (web-parity fallback) + send
  capability gating.** Type: contract/MockWebServer + Compose-UI. Target: JVM + emulator.
  Preconditions: enqueue `CreateSignaturePacketOut` for `POST /v1/signature-packets`,
  then a detail with `capabilities.can_send=false`. Steps: submit `{source_path,
  origin_channel}`; load resulting packet. Expected: draft created, detail loads, the
  "Send" affordance is disabled when `can_send=false` (mirrors web). Marks the
  list-less entry path that substitutes for the missing list endpoint. Traces: AC-1
  (entry surface), AC-2, AC-7.

### Coverage matrix

| AC (section 14) | Covered by |
| --- | --- |
| AC-1 (packets render / entry surface) | TC-AND-340-14 (+ blocked list: see §13 R1) |
| AC-2 (tap row → detail loads) | TC-AND-340-01, 05, 10, 12, 14 |
| AC-3 (status shown incl. unknown fallback) | TC-AND-340-02, 03, 11, 12 |
| AC-4 (status filter + survives rotation/death) | None — **blocked** (no list endpoint; §13 R1). Re-add tests when endpoint lands. |
| AC-5 (loading/empty/offline/error + retry) | TC-AND-340-05, 06, 07, 08, 09 |
| AC-6 (pull-to-refresh keeps content) | TC-AND-340-09 (and re-issue-GET assertions in 05) |
| AC-7 (signers + source doc + onOpenDocument seam) | TC-AND-340-01, 04, 10, 14 |
| AC-8 (no PII logged; packetId hashed) | TC-AND-340-08, 13 |
| AC-9 (unit + Compose UI coverage green in CI) | TC-AND-340-01..14 (whole suite) |

> **AC coverage caveat:** AC-1 and AC-4 presuppose a packet **list**; with no list
> endpoint they are only partially satisfiable (AC-1 via the create/load entry surface;
> AC-4 not at all). These ACs should be re-scoped alongside §13 R1 before sign-off.
