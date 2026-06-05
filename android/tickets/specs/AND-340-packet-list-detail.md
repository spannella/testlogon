---
id: AND-340
title: Packet list + detail
milestone: M7
epic: E44
priority: P1
size: M
status: draft
depends_on: [AND-339]
blocks: [AND-341]
---

# AND-340 — Packet list + detail

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
- **Upstream (AND-339):** provides Moshi DTOs (`PacketDto`, `PacketSummaryDto`,
  `RecipientDto`, `DocumentRefDto`, `PacketListResponseDto`) and the Retrofit
  `SignatureApi` interface plus DTO→domain adapters. This ticket adds the
  repository read methods and the UI on top.
- **Downstream (AND-341):** PDF rendering consumes
  `PacketDetail.documents: List<DocumentRef>` (id + download/stream URL +
  page count) surfaced by this screen. **AND-342** consumes recipient + field
  metadata for capture/placement.
- **Auth:** cookie-authenticated surface. All requests ride the persistent cookie
  jar + `X-CSRF-Token` header (AND-011/AND-012) and the single-shot
  `POST /ui/session/refresh` on 401 (AND-013). UI treats a post-refresh failure as
  terminal `Error`, never a loop.
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

FR-2. **List rendering.** Each row renders: packet title (fallback to the first
document name when title is null), a recipient summary (e.g. "You + 2 others" or a
single counterparty name), a **status chip** with status-specific label/color, and
a relative timestamp ("Updated 2h ago") derived from `updatedAt`.

FR-3. **Status filtering.** A horizontally scrollable filter row exposes the
buckets *All*, *Action required*, *Waiting*, *Completed*. Selecting a filter
re-queries the list (server-side `status` param when supported, else client-side
predicate). Default selection is *All*. The selected filter survives config
changes.

FR-4. **Empty state.** When the (filtered) list is empty, render `EmptyState` with
copy appropriate to the active filter ("No packets yet" vs "Nothing needs your
action").

FR-5. **Open detail.** Tapping a row navigates to `signing/packet/{packetId}` and
the detail screen loads that packet by id.

FR-6. **Detail rendering.** Detail shows: a header with title + large status
chip + created/updated timestamps; an ordered recipient list, each with name,
role/order, and per-recipient status (sent / viewed / signed / declined); a
document manifest list (one row per document: name, page count placeholder);
and a status-driven primary action region.

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

```kotlin
enum class PacketStatus { DRAFT, SENT, IN_PROGRESS, COMPLETED, DECLINED, VOIDED, EXPIRED, UNKNOWN }

data class PacketSummary(
    val id: String,
    val title: String?,
    val status: PacketStatus,
    val recipientCount: Int,
    val counterpartyLabel: String,   // precomputed "You + 2 others"
    val updatedAt: Instant,
    val actionRequired: Boolean,     // derived for current user
)

data class Recipient(
    val id: String,
    val displayName: String,
    val email: String?,
    val order: Int,
    val status: RecipientStatus,     // SENT, VIEWED, SIGNED, DECLINED, PENDING
    val isCurrentUser: Boolean,
)

data class DocumentRef(val id: String, val name: String, val pageCount: Int?, val url: String)

data class PacketDetail(
    val id: String,
    val title: String?,
    val status: PacketStatus,
    val createdAt: Instant,
    val updatedAt: Instant,
    val recipients: List<Recipient>,
    val documents: List<DocumentRef>,
    val currentUserAction: PacketAction,  // SIGN, VIEW_ONLY, NONE
)
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

Read-only endpoints (paths/DTOs owned by AND-339; reproduced here for the
consuming UI). Exact paths to be confirmed against `/openapi.json` /
`signaturePackets.ts` during AND-339.

**List** — `GET /ui/signing/packets?status={bucket}&limit=50`

```json
{
  "packets": [
    {
      "id": "pkt_01HX...",
      "title": "NDA - Acme Corp",
      "status": "in_progress",
      "recipients": [{ "id": "rcp_1", "name": "You", "status": "pending", "order": 1, "is_self": true }],
      "updated_at": "2026-06-04T18:20:11Z"
    }
  ],
  "next_cursor": null
}
```

**Detail** — `GET /ui/signing/packets/{packet_id}`

```json
{
  "id": "pkt_01HX...",
  "title": "NDA - Acme Corp",
  "status": "in_progress",
  "created_at": "2026-06-01T09:00:00Z",
  "updated_at": "2026-06-04T18:20:11Z",
  "recipients": [
    { "id": "rcp_1", "name": "You", "email": "spannella@gmail.com", "order": 1, "status": "pending", "is_self": true },
    { "id": "rcp_2", "name": "Jane Roe", "email": "jane@acme.test", "order": 2, "status": "viewed", "is_self": false }
  ],
  "documents": [
    { "id": "doc_1", "name": "nda.pdf", "page_count": 3, "url": "/ui/signing/packets/pkt_01HX.../documents/doc_1" }
  ]
}
```

Headers: cookie session + `X-CSRF-Token` echoed from the `ui_csrf` cookie. Both
calls are idempotent GETs (eligible for bounded backoff retry). On `401` the
OkHttp authenticator performs one `POST /ui/session/refresh` then retries;
post-refresh failure surfaces as terminal `Error`. Error bodies follow the FastAPI
`detail` contract (`string | [{msg}] | {code,...}`) mapped by AND-015. A `404`
on detail maps to a "Packet not found" terminal state (no retry).

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

Relative timestamps are computed in the composable layer from `updatedAt`
(`Instant`) using a `DateUtils`-style formatter to avoid stale strings.

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
- Recipient emails are PII: never logged (see §10), and shown in detail only.
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
- **Never** log packet titles, recipient names/emails, or document names/URLs.
  `packetId` is hashed/truncated in logs.
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
- **Blocks AND-341** (PDF rendering) — consumes `PacketDetail.documents` and the
  `onOpenDocument` seam. **AND-342** (signature capture) follows AND-341 and reuses
  recipient/action state from this detail screen.

## 13. Risks & Open Questions

- **R1 — API shape uncertainty.** Exact packet/recipient/document field names and
  the list status-filter param depend on AND-339 / `/openapi.json`. The JSON in §5
  is a best-effort projection from `signaturePackets.ts`; reconcile during AND-339.
- **R2 — `actionRequired`/`currentUserAction` derivation.** Whether "needs my
  signature" is server-provided or must be computed from recipient `status` +
  `is_self` + ordering is open. Prefer a server flag; otherwise implement the
  client predicate and cover it with tests.
- **R3 — Pagination.** Backend may paginate (`next_cursor` in §5). This ticket
  loads the first page (limit 50); full Paging-3 pagination is out of scope and a
  follow-up if packet volumes are large. Note in PR if deferred.
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
