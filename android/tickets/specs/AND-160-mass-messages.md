---
id: AND-160
title: Mass messages
milestone: M3
epic: E22
priority: P2
size: M
depends_on: [AND-120]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-160 — Mass messages

## 1. Overview & Goal

This ticket delivers the **creator-facing mass-messages (broadcast campaign) feature** for the TestLogon native Android app. A mass message is a one-to-many campaign authored by a creator and fanned out to an **explicit list of existing conversations** (`conversation_ids`, 1–100 per campaign) as individual direct messages. *(CORRECTED: the prior draft described follower/subscriber/segment "audiences"; the live backend `MassMessageCreateCampaignRequest` takes an explicit `conversation_ids` array — there is no audience/segment model, no PPV price, and no media-attachment fields on this endpoint. See §16.)* The web reference app does **not** ship a mass-messages screen (verified: no matches in `reference/src`), so there is no route-parity contract to mirror; the backend OpenAPI is the sole authoritative contract.

The Android scope is deliberately bounded by the backlog acceptance criterion: a creator can **list** existing campaigns, **create** a new campaign, and **cancel** a pending/scheduled/processing campaign before it finishes sending. Editing in flight, rich analytics dashboards, and the per-recipient delivery drill-down (the `GET /messaging/mass-messages/{campaign_id}` detail/`destinations` endpoint) are explicitly **out of scope** for AND-160 and are deferred to later epic E22 tickets.

The goal is a `feature-messaging` screen pair (list + create sheet) backed by a Hilt-injected repository over the existing `MessagingApi` (AND-120), exposing a `StateFlow<UiState>` from a ViewModel, with the create and cancel mutations wired to the cookie-authenticated backend and verified against fixtures. Success = a creator can create a campaign and cancel a campaign, and both actions are reflected in the list with correct status transitions, offline/stale handling, and CSRF-protected writes.

## 2. Context & References

- **Route parity:** *(CORRECTED — none.)* The web reference app has **no** mass-messages screen or endpoint usage (verified: zero matches for `mass-messages`/`MassMessage` under `reference/src`). There is no `frontend/src/api/endpoints/messaging.ts` mass-message call to mirror. The contract is defined exclusively by the backend OpenAPI under operations `list_mass_message_campaigns_*`, `create_mass_message_campaign_*`, `cancel_mass_message_campaign_*`.
- **Dependency AND-120 (Messaging API + DTOs):** Provides the `MessagingApi` Retrofit interface and the shared messaging DTO/Moshi infrastructure (`core-network`, `core-model`). AND-160 **extends** that interface with mass-message endpoints and DTOs rather than creating a parallel API client. AND-160 must not duplicate the conversation/message DTOs already defined there.
- **Auth model:** Cookie-based session (`POST /ui/session/start` → MFA → `/ui/session/finalize` → `/ui/me`). All mutating calls in this ticket are writes and therefore require the `X-CSRF-Token` header echoed from the `ui_csrf` cookie; the shared OkHttp interceptor chain (cookie jar + CSRF + single 401→`/ui/session/refresh`→retry) from `core-network` applies unchanged.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Confirm exact field names against `/openapi.json` and the web `messaging.ts` during implementation; the JSON shapes in §5 are the contract to validate, with discrepancies resolved in favour of the live OpenAPI.
- **Module layering:** `app -> feature-messaging -> core-network/core-model/core-data/core-ui/core-testing`.
- **Stack pins:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3, Coroutines/Flow. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1. **List campaigns.** When a creator opens the Mass Messages screen, the app fetches and displays a paged list of the creator's campaigns, newest first. *(CORRECTED field set:* the list item is `MassMessageCampaignSummary`, which does **not** carry the message text, an audience label, or a single recipient count.) Each row shows: `campaign_id`, status (one of `pending`, `scheduled`, `processing`, `completed`, `failed`, `cancelled`), `mode` (`immediate` | `scheduled`), the `send_at` timestamp (epoch seconds, nullable), the `created_at` timestamp, and a progress summary derived from `counters` (`sent`/`queued`/`failed`/`cancelled` out of `total`). List supports server-side `status` and `mode` filter query params.

FR-2. **Empty / loading / error states.** Distinct UI for first-load spinner, empty list (no campaigns), full-screen error (initial load failure with retry), and inline page-append error (Paging 3 `LoadState.Error` footer with retry).

FR-3. **Create campaign.** A "New campaign" FAB opens a modal create sheet capturing: message **text** (required, non-blank, **1–4000 chars** — bound is from `MassMessageContentPayload.text` `minLength:1`/`maxLength:4000`, *not* from `/messaging/config`, which exposes no length field), the **recipient conversations** (`conversation_ids`, **required, 1–100 items**), **mode** (`immediate` default, or `scheduled`), and **`send_at`** (epoch seconds, required when mode = `scheduled`). An optional **`idempotency_key`** (8–128 chars) SHOULD be generated client-side and reused across retries of the same create. *(CORRECTED: there is no `audience`, `price_cents`/PPV, or `media_ids` field on `MassMessageCreateCampaignRequest`; those were invented by the prior draft and are removed.)* Submit is disabled until required fields validate. Note: recipient selection is by existing conversation id — picking conversations (e.g. via the AND-120 conversations list / `GET /messaging/contacts/search`) is the input mechanism; there is no follower/subscriber/segment selector.

FR-4. **Create result.** The endpoint returns **201 `MassMessageCreateCampaignResponse`** with `campaign_id`, server-assigned `status` (typically `pending` for immediate or `scheduled` for scheduled), `mode`, `accepted_count`, `accepted_conversation_ids`, `counters`, and a **`rejected[]`** array of `{conversation_id, reason}` for destinations that were dropped (e.g. `not_a_participant`). On success the sheet dismisses, a confirmation snackbar shows the accepted count, and the new campaign is refreshed into the list. If `rejected[]` is non-empty the UI surfaces a partial-acceptance notice (accepted N, rejected M).

FR-5. **Cancel campaign.** A row whose status is non-terminal (`pending`, `scheduled`, or `processing`) exposes a "Cancel" action behind a confirmation dialog. Confirming calls `POST /messaging/mass-messages/{campaign_id}/cancel`; on success (**200 `MassMessageCancelCampaignResponse`**) the row reconciles to the returned `status` (typically `cancelled`) and shows `cancelled_destinations`. Rows in terminal states (`completed`, `failed`, `cancelled`) do not show the action. *(CORRECTED: status names `draft`/`sending`/`sent` do not exist in the API; terminal "sent" is `completed`.)*

FR-6. **Optimistic + reconciled state.** Cancel updates the row optimistically to a `cancelling` transient state and reconciles to the server-returned status; on failure it rolls back and surfaces an error snackbar.

FR-7. **Refresh.** Pull-to-refresh and a manual retry re-query the first page. After any successful create/cancel the list invalidates so the data source reloads.

FR-8. **Feature/role gate.** The screen is reachable only when the mass-send capability is enabled for the user. The authoritative client-side gate is the **`messaging_mass_send_enabled` boolean** returned by `GET /messaging/config` (`MessagingConfigOut`), combined with the `/ui/me` creator-capability flag. *(CORRECTED: the prior draft implied a length field on `/messaging/config`; config carries only feature-flag booleans — relevant here is `messaging_mass_send_enabled`.)* When the flag is false or the user is not a creator, no navigation entry is shown; deep-linking renders a "not available" state rather than crashing. Authorization is always enforced server-side.

## 4. Technical Design

New module package root: `com.testlogon.android.feature.messaging.mass`.

### 4.1 Navigation

Single-Activity Navigation-Compose. Add a typed destination:

```kotlin
@Serializable
data object MassMessagesRoute

fun NavGraphBuilder.massMessagesScreen(onBack: () -> Unit) {
    composable<MassMessagesRoute> { MassMessagesScreen(onBack = onBack) }
}
```

The create flow is an in-screen `ModalBottomSheet`, not a separate route, to keep state local to the ViewModel.

### 4.2 ViewModel & UiState

```kotlin
@HiltViewModel
class MassMessagesViewModel @Inject constructor(
    private val repo: MassMessagesRepository,
    private val configRepo: MessagingConfigRepository, // from AND-120
) : ViewModel() {

    val campaigns: Flow<PagingData<MassCampaignUi>> =
        repo.campaignsPager().cachedIn(viewModelScope)

    private val _ui = MutableStateFlow(MassMessagesUiState())
    val uiState: StateFlow<MassMessagesUiState> = _ui.asStateFlow()

    fun openCreate() { ... }
    fun updateDraft(transform: (CreateCampaignDraft) -> CreateCampaignDraft) { ... }
    fun submitCreate() { ... }   // validate -> repo.create -> refresh -> snackbar
    fun requestCancel(id: String) { ... }       // opens confirm dialog
    fun confirmCancel(id: String) { ... }        // optimistic -> repo.cancel -> reconcile
    fun refresh() { ... }
    fun consumeEvent() { ... }    // one-shot snackbar/dismiss events
}

data class MassMessagesUiState(
    val createSheet: CreateSheetState = CreateSheetState.Hidden,
    val pendingCancelId: String? = null,
    val inFlightCancelIds: Set<String> = emptySet(),
    val event: MassMessagesEvent? = null,
    val isCreator: Boolean = true,
)

sealed interface CreateSheetState {
    data object Hidden : CreateSheetState
    data class Visible(
        val draft: CreateCampaignDraft,
        val config: MessagingConfig,
        val submitting: Boolean = false,
        val errors: Map<CampaignField, String> = emptyMap(),
    ) : CreateSheetState
}

// CORRECTED to match MassMessageCreateCampaignRequest: explicit conversation_ids,
// mode/send_at, idempotency_key. No audience / price / media fields exist on the API.
data class CreateCampaignDraft(
    val text: String = "",                       // 1..4000
    val conversationIds: List<String> = emptyList(), // 1..100, required
    val mode: CampaignMode = CampaignMode.Immediate, // Immediate | Scheduled
    val sendAtEpochSec: Long? = null,            // required when mode == Scheduled
    val idempotencyKey: String = newIdempotencyKey(), // 8..128, stable across retries
)

sealed interface MassMessagesEvent {
    data class Snack(val messageRes: Int, val args: List<String> = emptyList()) : MassMessagesEvent
    data object Created : MassMessagesEvent
}
```

Pagination uses Paging 3 with a `RemoteMediator`-free `PagingSource` (network-only, page-token based). Cancel/create mutate via repository, then call `pagingSource.invalidate()` (or expose an `invalidate` channel) so the list reloads from page 1.

### 4.3 Repository

```kotlin
interface MassMessagesRepository {
    fun campaignsPager(): Flow<PagingData<MassCampaignUi>>
    suspend fun create(req: CreateMassMessageRequest): ApiResult<MassCampaign>
    suspend fun cancel(id: String): ApiResult<MassCampaign>
}

class MassMessagesRepositoryImpl @Inject constructor(
    private val api: MessagingApi,           // extended in this ticket
    private val mapper: MassCampaignMapper,
    @IoDispatcher private val io: CoroutineDispatcher,
) : MassMessagesRepository { ... }
```

`ApiResult<T>` is the project's typed result (`Success | Error(detail) | NetworkError`); FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is normalised by the shared error mapper in `core-network`.

### 4.4 MessagingApi extension (AND-120)

```kotlin
// added to the existing MessagingApi interface
// Schema names match OpenAPI components.schemas exactly.
@GET("/messaging/mass-messages")
suspend fun listMassMessages(
    @Query("limit") limit: Int = 20,
    @Query("cursor") cursor: String? = null,
    @Query("status") status: String? = null, // server-side filter (enum value)
    @Query("mode") mode: String? = null,     // immediate | scheduled
): Response<MassMessageCampaignListResponseDto>

@POST("/messaging/mass-messages")
suspend fun createMassMessage(
    @Body body: MassMessageCreateCampaignRequestDto,
): Response<MassMessageCreateCampaignResponseDto>

// CORRECTED: path param is {campaign_id}; cancel returns 200 with a
// dedicated MassMessageCancelCampaignResponse, NOT the campaign summary.
@POST("/messaging/mass-messages/{campaign_id}/cancel")
suspend fun cancelMassMessage(
    @Path("campaign_id") campaignId: String,
): Response<MassMessageCancelCampaignResponseDto>
```

### 4.5 UI (Compose)

`MassMessagesScreen` collects `campaigns.collectAsLazyPagingItems()` and `uiState`. A `LazyColumn` of `MassCampaignRow` composables; `PullToRefreshBox` (Material 3) wraps it; `ExtendedFloatingActionButton` triggers `openCreate()`. `CreateCampaignSheet(ModalBottomSheet)` renders text field with live char counter, audience `SegmentedButton`/dropdown, optional price field, and a date/time picker for scheduling. `CancelConfirmDialog` is an `AlertDialog`. One-shot events drive a `SnackbarHostState`.

## 5. API Contract

All paths are relative to the dev base URL. Cookies + `X-CSRF-Token` are applied by the shared interceptor; writes (POST) require CSRF. **The shapes below are transcribed directly from `reference/openapi.pretty.json` (`components.schemas.MassMessage*`) and corrected against the prior draft.** Note: **all timestamps are integer Unix epoch *seconds*, not ISO-8601 strings.** The web app has no equivalent to validate against.

**List — `GET /messaging/mass-messages?limit=20&cursor=&status=&mode=`** → `200 MassMessageCampaignListResponse`. Items are `MassMessageCampaignSummary` (no message text, no audience, no recipient_count — those fields were invented by the prior draft).
```json
{
  "items": [
    {
      "campaign_id": "mmc_123",
      "status": "processing",
      "mode": "scheduled",
      "send_at": 1760003600,
      "created_at": 1760003500,
      "updated_at": 1760003600,
      "counters": { "total": 3, "queued": 1, "sent": 1, "failed": 0, "cancelled": 1 }
    }
  ],
  "next_cursor": "eyJjYW1wYWlnbl9pZCI6Im1tY18xMjMi..."
}
```

**Create — `POST /messaging/mass-messages`** → `201 MassMessageCreateCampaignResponse`.
```json
// request — MassMessageCreateCampaignRequest (required: conversation_ids, content)
{
  "conversation_ids": ["c1", "c2"],          // 1..100
  "content": { "kind": "text", "text": "New set just dropped 🔥" }, // text 1..4000
  "mode": "immediate",                        // immediate (default) | scheduled
  "send_at": null,                            // epoch seconds; required if mode=scheduled
  "idempotency_key": "a1b2c3d4e5f6g7h8"       // optional, 8..128 chars
}
// 201 response — MassMessageCreateCampaignResponse
{
  "campaign_id": "mmc_123",
  "status": "pending",
  "mode": "immediate",
  "accepted_count": 2,
  "accepted_conversation_ids": ["c1", "c2"],
  "rejected": [ { "conversation_id": "c3", "reason": "not_a_participant" } ],
  "send_at": null,
  "created_at": 1760000000,
  "updated_at": 1760000000,
  "counters": { "total": 2, "queued": 2, "sent": 0, "failed": 0, "cancelled": 0 }
}
```

**Cancel — `POST /messaging/mass-messages/{campaign_id}/cancel`** (no body) → `200 MassMessageCancelCampaignResponse`.
```json
{
  "campaign_id": "mmc_123",
  "status": "cancelled",
  "cancelled_destinations": 4,
  "updated_at": 1760005000,
  "counters": { "total": 10, "queued": 0, "sent": 6, "failed": 0, "cancelled": 4 }
}
```

**Status enum (all responses):** `pending | scheduled | processing | completed | failed | cancelled`. **Mode enum:** `immediate | scheduled`. **Per-destination state enum** (detail endpoint, out of scope): `pending | sent | failed | skipped | cancelled`.

**Error envelope (FastAPI):** the OpenAPI documents **only `422 HTTPValidationError`** for all three endpoints (`{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`). 422 covers empty/over-length text, empty or >100 `conversation_ids`, missing `send_at` when `mode=scheduled`, and a bad `idempotency_key`. *(CORRECTED: the prior draft's specific `403`/`404`/`409` codes are NOT documented for these operations.)* 401 (auth/CSRF) is handled at the transport layer by the shared interceptor and is not part of these operations' documented responses. The client must still defensively handle undocumented non-2xx via the shared `ApiResult` error mapper. Rejected (but non-fatal) destinations come back in the 201 body's `rejected[]`, not as an error.

Moshi DTOs (names mirror schemas): `MassMessageCampaignListResponseDto`, `MassMessageCampaignSummaryDto`, `MassMessageCampaignCountersDto`, `MassMessageCreateCampaignRequestDto`, `MassMessageContentPayloadDto`, `MassMessageCreateCampaignResponseDto`, `MassMessageRejectedDestinationDto`, `MassMessageCancelCampaignResponseDto`. `@Json(name=...)` aligns snake_case JSON to camelCase Kotlin. Timestamps are **epoch-second `Long`s** (use a `Long`→`Instant.ofEpochSecond` mapping in the mapper layer; do **not** use the ISO-8601 `Instant` adapter for these fields).

## 6. Data & State Management

- **Source of truth:** server. The list is network-backed via a Paging 3 `PagingSource<String, MassCampaignUi>` keyed by `next_cursor`. No Room persistence in this ticket — campaign volume is small, freshness matters, and the cancel/create flows demand immediate reload. (A Room-backed `RemoteMediator` for offline campaign history is a deferred E22 enhancement.)
- **DataStore:** none new; reuse the existing creator-profile cache from `/ui/me` for the FR-8 role gate.
- **Domain vs UI models:** `MassMessageCampaignSummaryDto` → `MassCampaign` (domain, in `core-model`) → `MassCampaignUi` (formatted strings, derived `isCancellable = status in {pending, scheduled, processing}`, localized status label, `counters`-derived progress). Mapping in `MassCampaignMapper`, which converts epoch-second `Long`s to `Instant`.
- **Transient mutation state:** `inFlightCancelIds` and the optimistic `cancelling` overlay live in `MassMessagesUiState`, applied at render time over the paged item (paged items are immutable, so the optimistic status is a UI-layer overlay keyed by id, then resolved by invalidation after the server responds).
- **Invalidation:** after a successful create or cancel, the repository signals invalidation; `LazyPagingItems` reloads page 1. Pull-to-refresh calls `refresh()` on the lazy paging items.
- **Process death:** `CreateCampaignDraft` text/audience/price are held in the ViewModel; for resilience the draft is mirrored to `SavedStateHandle` so an in-progress compose survives configuration changes and process death.

## 7. Error Handling & Resilience

- **Timeouts:** rely on `core-network`'s ~20s OkHttp call timeout for the unreliable dev host.
- **Retry policy:** the **GET list** is idempotent → bounded exponential backoff (e.g. 2 retries, 500ms→2s, jitter) via the shared retry interceptor. **POST create** carries a stable client-generated **`idempotency_key`** (per `MassMessageCreateCampaignRequest`), so a user-initiated retry of a create reuses the same key and is therefore safe against duplicate campaigns — but is still **not auto-retried** (network ambiguity is surfaced via a snackbar action that re-submits with the same key). **POST cancel** has no idempotency token and is **not auto-retried**; cancel is naturally idempotent server-side (re-cancelling an already-cancelled campaign returns the cancelled status), so a user retry is safe.
- **401:** handled by the shared single-shot `/ui/session/refresh` + retry interceptor; on second 401 the global auth state routes to re-login.
- **Offline:** if the device is offline, the list shows a full-screen offline state (initial) or an inline append error (subsequent pages); create/cancel are blocked with a "no connection" snackbar before issuing the call.
- **Domain conflicts:** the OpenAPI documents no `409`/`404`/`403` for these operations (only `422`). If the server *does* return a non-2xx on cancel (e.g. cancelling a `completed` campaign), the client rolls back optimistic state, refreshes the row, and shows "This campaign can no longer be cancelled." `422` on create → field-level errors parsed from `detail[].loc`/`msg` and mapped into `CreateSheetState.errors` (e.g. empty/over-length text → `CampaignField.Text`; empty/over-100 ids → `CampaignField.Recipients`; missing `send_at` → `CampaignField.SendAt`).
- **Optimistic rollback:** any non-success on cancel removes the id from `inFlightCancelIds` and the overlay reverts.

## 8. Security & Privacy

- **CSRF:** every create/cancel POST carries `X-CSRF-Token` (echoed `ui_csrf` cookie) via the shared interceptor; missing/expired CSRF yields a 403 surfaced as a generic error and triggers refresh.
- **Authorization:** the backend enforces creator-only and ownership on these endpoints; the client also gates the entry point (FR-8) but never relies on client gating for authorization.
- **PII:** campaign bodies and recipient counts are creator content; do not log message text or recipient identifiers (see §10). No recipient PII is fetched in this ticket.
- **Transport:** dev host is plaintext HTTP; production must be HTTPS. The network module's cleartext allowance is dev-flavor only (owned by `core-network`), not introduced here.
- **No secrets** are stored in this feature; the cookie jar is the existing persistent encrypted jar from `core-network`.

## 9. Accessibility & i18n

- All strings in `feature-messaging` `strings.xml`; no hardcoded text. Status labels, audience labels, char-counter, and error messages are resources.
- **Content descriptions:** FAB ("Create mass message"), per-row Cancel action, and status chips have semantics. Cancel confirmation dialog is fully focus-trapped and screen-reader announced.
- **Touch targets** ≥ 48dp; create-sheet fields use `Modifier.semantics` with labels and error `stateDescription`.
- **Dynamic type / RTL:** Compose Material 3 typography scales; layouts use start/end paddings (RTL-safe). The emoji-capable text field supports multi-line growth.
- **Numbers/dates:** recipient counts use locale number formatting; timestamps use the app's locale-aware relative/absolute formatter.

## 10. Telemetry & Logging

- **Analytics events** via the shared analytics facade: `mass_message_list_viewed`, `mass_message_create_opened`, `mass_message_create_submitted` (params: `audience_type`, `is_scheduled`, `is_paid` — **no text, no recipient ids**), `mass_message_create_succeeded` / `_failed` (`error_code`), `mass_message_cancel_confirmed`, `mass_message_cancel_succeeded` / `_failed`.
- **Logging:** debug-only request/response logging via the existing OkHttp logging interceptor with the messaging-text body redacted. No campaign text or recipient data in logs at any level.
- **Crash reporting:** repository/mapper failures are caught into `ApiResult` and not crashed; unexpected mapping errors report a non-fatal with the endpoint name only.

## 11. Testing Strategy

- **DTO/mapping (core-testing + fixtures):** JSON fixtures for list page, single campaign (each status), and error envelopes; assert `MassMessageDto` → `MassCampaign` → `MassCampaignUi` mapping, `isCancellable` derivation, and `next_cursor` paging key. Mirrors the AND-120 fixture pattern.
- **Repository (MockWebServer):** create returns 201 → `ApiResult.Success`; cancel 409 → typed error; list 500 then 200 verifies GET retry; verify `X-CSRF-Token` header present on POSTs.
- **ViewModel (Turbine):** `submitCreate` validation gates submit; success emits `Created` event + invalidation; `confirmCancel` adds then removes `inFlightCancelIds` and rolls back on error; refresh reloads.
- **Paging:** `PagingSource.load` returns `LoadResult.Page` with correct `nextKey`; error → `LoadResult.Error`.
- **Compose UI tests:** empty/loading/error states render; FAB opens sheet; submit disabled until valid; cancel shows confirm dialog then transitions row to cancelled; non-creator deep-link shows unavailable state.
- **Coverage target:** repository + ViewModel + mapper ≥ 80% line coverage; both acceptance flows (create, cancel) covered end-to-end against MockWebServer.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-120 (Messaging API + DTOs)** must land first; AND-160 extends `MessagingApi` and reuses its Moshi/error infrastructure and `/messaging/config`. AND-120 transitively depends on AND-027 (auth/session + interceptors).
- **Implied platform deps (already in place per project context):** `core-network` cookie jar + CSRF + 401-refresh interceptors, Paging 3 setup, the analytics facade, and Navigation-Compose host.
- **Blocks:** none recorded in the backlog. Future E22 mass-message analytics/edit tickets will build on this feature module.
- **Sequencing within ticket:** (1) DTOs + `MessagingApi` extension + fixtures; (2) repository + mapper + tests; (3) ViewModel + paging + tests; (4) Compose UI + nav wiring; (5) UI tests + accessibility pass.

## 13. Risks & Open Questions

- **R1 — Endpoint shape (RESOLVED in this review).** Field names, paths, methods, status codes and enums are now confirmed against `reference/openapi.pretty.json` (`MassMessage*` schemas) and corrected in §1, §3, §4, §5. The cancel path is `{campaign_id}` and returns 200 `MassMessageCancelCampaignResponse`.
- **R2 — Audience model (RESOLVED — does not exist).** There is no audience/segment concept on this endpoint; recipients are an explicit `conversation_ids` array (1–100). The follower/subscriber/segment picker from the prior draft is removed. *Remaining UX question:* how the creator selects those conversation ids (manual multi-select from the AND-120 conversations list vs. `GET /messaging/contacts/search`) — a UI decision, not an API blocker.
- **R3 — Cancellable states (RESOLVED).** Client `isCancellable` = status ∈ {`pending`, `scheduled`, `processing`}; terminal = {`completed`, `failed`, `cancelled`}. The OpenAPI documents no conflict (409) response, so a defensive rollback path is retained but expected to be rare.
- **R4 — Paid broadcast (PPV) pricing (RESOLVED — out of scope).** No price/PPV fields exist on `MassMessageCreateCampaignRequest`; PPV is not part of this endpoint and is dropped from AND-160.
- **R5 — Unreliable dev host** can make UI flows flaky in manual QA; mitigated by timeouts, offline states, MockWebServer-based automated tests, and (for create) the `idempotency_key` guarding against duplicate campaigns on ambiguous retries.
- **R6 — Web parity (RESOLVED — none).** The web app does not implement this feature; OpenAPI is the sole contract. No `messaging.ts` frontend behavior to mirror.

## 14. Acceptance Criteria

AC-1. A creator can open the Mass Messages screen and see a paged list of their campaigns with correct status (`pending`/`scheduled`/`processing`/`completed`/`failed`/`cancelled`), mode, counters-derived progress, and timestamps (epoch-second → locale-formatted); empty/loading/error/offline states each render correctly. *(FR-1, FR-2)*
AC-2. A creator can **create** a campaign from the sheet: required validation enforced, `POST /messaging/mass-messages` issued with `X-CSRF-Token`, success dismisses the sheet, shows confirmation, and the new campaign appears in the list. *(FR-3, FR-4 — backlog: "Create … a campaign")*
AC-3. A creator can **cancel** a cancellable campaign (status ∈ {pending, scheduled, processing}) via confirmation; `POST /messaging/mass-messages/{campaign_id}/cancel` returns 200 and the row reconciles to the returned `status` (`cancelled`); terminal-state rows (completed/failed/cancelled) offer no cancel. *(FR-5, FR-6 — backlog: "cancel a campaign")*
AC-4. Optimistic cancel rolls back on any non-2xx with an error snackbar; `422` create errors surface as field-level messages parsed from `detail[].loc`/`msg`. *(FR-6, §7)*
AC-5. GET list retries (idempotent) on transient failure; create/cancel never auto-retry. *(§7)*
AC-6. Non-creators have no nav entry; deep-link renders an unavailable state without crashing. *(FR-8)*
AC-7. Unit tests: DTO mapping verified against fixtures (consistent with AND-120) and both create + cancel flows pass against MockWebServer. *(§11)*

## 15. Definition of Done

- `feature-messaging` mass-messages list + create sheet + cancel implemented under `com.testlogon.android.feature.messaging.mass`, wired into the Navigation-Compose host with the creator role gate.
- `MessagingApi` extended with list/create/cancel; Moshi DTOs and `MassCampaignMapper` complete with `@Json` mappings and ISO-8601 timestamps.
- `MassMessagesRepository(Impl)` and `MassMessagesViewModel` exposing `StateFlow<MassMessagesUiState>` + `Flow<PagingData>`, with CSRF-protected writes and the shared error/`ApiResult` mapping.
- All seven acceptance criteria demonstrably met; unit, repository (MockWebServer), ViewModel (Turbine), paging, and Compose UI tests green at ≥80% coverage on repo/VM/mapper.
- No hardcoded strings; accessibility (content descriptions, 48dp targets, RTL, dynamic type) verified; telemetry events emitted without logging message text or recipient PII.
- Open questions R1–R6 resolved against the OpenAPI spec (see §16) or explicitly documented as deferred before merge; code passes ktlint/detekt and builds on the `android-port` branch with AGP 8.7.3 / Gradle 8.9 / JDK 17.

## 16. Citations & Assumption Audit

Sources: OpenAPI index `reference/openapi.index.txt` (lines cited), full spec `reference/openapi.pretty.json` (`components.schemas.*`), and the frontend reference app `reference/src/`. Framework choices are labeled "framework ref".

1. **Endpoints exist with these methods/paths.** GET/POST `/messaging/mass-messages`, GET `/messaging/mass-messages/{campaign_id}`, POST `/messaging/mass-messages/{campaign_id}/cancel`. **VERIFIED.** Source: `openapi.index.txt` lines 395–398 (ops `list_mass_message_campaigns_*`, `create_mass_message_campaign_*`, `get_mass_message_campaign_*`, `cancel_mass_message_campaign_*`).
2. **Cancel path param name is `{campaign_id}` (not `{id}`).** **CORRECTED.** Source: `openapi.index.txt` line 398 `params=campaign_id`.
3. **Cancel returns 200 `MassMessageCancelCampaignResponse` with `campaign_id`, `status`, `cancelled_destinations`, `updated_at`, `counters` — not the campaign summary.** **CORRECTED.** Source: `openapi.index.txt` line 398; schema `MassMessageCancelCampaignResponse` (`openapi.pretty.json` 49472–49528).
4. **Create returns 201 `MassMessageCreateCampaignResponse` with `accepted_count`, `accepted_conversation_ids`, `rejected[]{conversation_id,reason}`, `counters`, `status`, `mode`.** **CORRECTED** (prior draft said "single MassMessageDto same shape as list item"). Source: `MassMessageCreateCampaignResponse` (49607–49714); `MassMessageRejectedDestination` (49815–49835).
5. **Create request is `MassMessageCreateCampaignRequest = {conversation_ids[1..100], content{kind:"text", text[1..4000]}, mode(immediate|scheduled, default immediate), send_at(epoch int|null), idempotency_key(8..128|null)}`; required = `conversation_ids`, `content`.** **CORRECTED.** Source: `MassMessageCreateCampaignRequest` (49551–49606); `MassMessageContentPayload` (49529–49550).
6. **There is NO `audience`/`segment_id`, NO `price_cents`/PPV, NO `media_ids` on these endpoints.** **CORRECTED (claims removed).** Source: absence in `MassMessageCreateCampaignRequest`/`MassMessageCampaignSummary`/`MassMessageCampaignDetailResponse` schemas (49248–49714).
7. **List item shape is `MassMessageCampaignSummary = {campaign_id, mode, status, created_at, updated_at, send_at?, counters}` — no text, no audience, no recipient_count.** **CORRECTED.** Source: `MassMessageCampaignSummary` (49411–49471); `MassMessageCampaignListResponse` (49364–49410).
8. **Campaign status enum = `pending|scheduled|processing|completed|failed|cancelled` (not `draft|sending|sent`).** **CORRECTED.** Source: enum in `MassMessageCampaignSummary.status` (49445–49456) and detail/create/cancel schemas.
9. **Mode enum = `immediate|scheduled`.** **VERIFIED/CLARIFIED** (prior draft used informal "send now"). Source: `MassMessageCreateCampaignRequest.mode` (49579–49587).
10. **Counters object = `{total,queued,sent,failed,cancelled}` (all int ≥0, default 0).** **VERIFIED.** Source: `MassMessageCampaignCounters` (49211–49247).
11. **All timestamps are integer Unix epoch seconds (not ISO-8601 strings).** **CORRECTED.** Source: `created_at`/`updated_at`/`send_at` typed `integer` across all `MassMessage*` schemas; example values like `1760003600`.
12. **List query params = `limit, cursor, status, mode` (server-side status/mode filtering).** **CORRECTED** (prior draft listed only cursor/limit). Source: `openapi.index.txt` line 395 `params=limit,cursor,status,mode`.
13. **Cursor pagination via `next_cursor` (nullable string).** **VERIFIED.** Source: `MassMessageCampaignListResponse.next_cursor` (49396–49405).
14. **Documented error response for all three ops is `422 HTTPValidationError` only; no 403/404/409 documented.** **CORRECTED** (prior draft asserted specific 403/404/409 semantics). Source: `openapi.index.txt` lines 395–398 (`resp=...;422:HTTPValidationError`).
15. **The `/messaging/config` (`MessagingConfigOut`) feature flag for this feature is `messaging_mass_send_enabled` (boolean); config carries NO message-length field.** **CORRECTED** (prior draft sourced max-length from config). Source: `MessagingConfigOut` (51378–51420); text length bound is `MassMessageContentPayload.text` maxLength 4000 (49538–49543).
16. **Auth/session model: POST `/ui/session/start` (`UiSessionStartReq`→`UiSessionStartResp`), POST `/ui/session/finalize`, POST `/ui/session/refresh`, GET `/ui/me`.** **VERIFIED.** Source: `openapi.index.txt` lines 1638, 1845, 1847, 1848.
17. **The web reference app does NOT implement mass messages (no route, no endpoint call, no DTO).** **CORRECTED** (prior draft claimed route parity + `frontend/src/api/endpoints/messaging.ts` usage). Source: zero matches for `mass-messages`/`MassMessage`/`mass_messages` under `reference/src/` (the only `mass` hits were `customAssignee` in `reference/src/pages/tickets/TicketSpaceDetailPage.tsx`).
18. **Create is safely retryable via client `idempotency_key`; cancel is naturally idempotent server-side.** **VERIFIED** (idempotency_key present); the "no auto-retry, user-initiated only" policy retained. Source: `MassMessageCreateCampaignRequest.idempotency_key` (49566–49578).
19. **CSRF: writes carry `X-CSRF-Token` echoed from `ui_csrf` cookie via the shared `core-network` interceptor.** **UNVERIFIED-ASSUMPTION** — this is inherited from AND-027/AND-120 infrastructure and not re-derivable from the mass-message schemas; the OpenAPI does not enumerate cookie/CSRF headers per operation. Carried forward as a platform assumption.
20. **Stack/tooling pins (Kotlin 2.0.21, Compose+M3, Paging 3, Hilt/KSP, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, minSdk 24/target 35, AGP 8.7.3/Gradle 8.9/JDK 17).** **UNVERIFIED-ASSUMPTION (framework ref)** — project conventions, not checkable against backend sources. Material 3 `ModalBottomSheet`/`PullToRefreshBox` and Paging 3 `PagingSource` are standard AndroidX APIs (framework ref: developer.android.com/jetpack/compose, developer.android.com/topic/libraries/architecture/paging/v3-overview).

### Corrections made

- §1, §2: removed false "follower/subscriber/segment audience" and "web route parity / `messaging.ts`" claims; recipients are explicit `conversation_ids`; web app has no implementation.
- §3 FR-1: list field set corrected (summary fields + counters; removed text/audience/recipient_count); status enum corrected; added server-side status/mode filters.
- §3 FR-3: create inputs corrected to `conversation_ids` + `content.text` (1–4000) + `mode`/`send_at` + `idempotency_key`; removed audience/price/media; text length sourced from `MassMessageContentPayload`, not config.
- §3 FR-4: create response corrected to `MassMessageCreateCampaignResponse` with accepted/rejected detail.
- §3 FR-5: cancellable/terminal status sets corrected; cancel path `{campaign_id}`; cancel returns dedicated response.
- §3 FR-8: gate corrected to `messaging_mass_send_enabled` flag from `MessagingConfigOut`.
- §4.2/§4.4: `CreateCampaignDraft` and `MessagingApi` signatures/DTO names corrected to match schemas; cancel path param renamed.
- §5: full contract rewrite (paths, methods, request/response JSON, enums, epoch-second timestamps, error codes, DTO names).
- §6: domain mapping source DTO and epoch→Instant conversion corrected.
- §7: retry/idempotency and error-code handling corrected (no documented 409; idempotency_key for create).
- §13: R1–R4 marked resolved; added R6 (no web parity); R2/R4 scope reductions.
- §14: AC-1/AC-3/AC-4 updated for correct enums, path, and error handling.

### Open assumptions

- **CSRF/cookie/401-refresh interceptor behavior** (claim 19): inherited platform contract from AND-027/AND-120; not expressible in the per-operation OpenAPI, so unverifiable here. Validate against the live dev host and `core-network` during implementation.
- **AND-120 `MessagingApi`/Moshi/error infrastructure exists to be extended** (per §2/§12): assumed from the dependency; not in the provided sources.
- **Toolchain/version pins** (claim 20): project convention, framework ref only.
- **Exact `rejected[].reason` value set** (only `not_a_participant` shown by example): the schema types `reason` as a free string with no enum, so the UI must treat it as an opaque, possibly-unknown code and fall back to a generic message.
- **Whether `processing` campaigns accept full vs. partial cancel** at the server: `cancelled_destinations` implies partial cancel of already-queued recipients, but exact server semantics are not specified in the schema; client only reconciles to the returned `status`/`counters`.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **MWS** = MockWebServer contract test (JVM); **emulator(test35)** = headless AVD x86_64 API 35; **device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Compose-UI/instrumented cases run on emulator(test35) unless they need real hardware; none of this feature's cases require device camera/biometrics/WebRTC/FCM, so the physical device is used only to validate arm64 + API-34 parity (see TC-AND-160-13).

- **TC-AND-160-01 — Create happy path (contract).** Type: contract/MWS. Target: MWS. Preconditions: enqueue 201 `MassMessageCreateCampaignResponse` (status `pending`, accepted_count 2, empty `rejected`). Steps: build `MassMessageCreateCampaignRequestDto{conversation_ids:[c1,c2], content{kind:text,text:"hi"}, mode:immediate, idempotency_key:k}`; call `createMassMessage`. Expected: `ApiResult.Success`; parsed DTO has `campaign_id`, `accepted_count==2`; request body JSON matches schema (snake_case keys `conversation_ids`/`content.text`/`idempotency_key`); `X-CSRF-Token` header present on the POST. Traces: AC-2, AC-7.
- **TC-AND-160-02 — Create with rejected destinations (contract+mapping).** Type: contract/MWS + unit. Target: MWS/JVM. Preconditions: 201 body with `accepted_count:2`, `rejected:[{conversation_id:c3, reason:not_a_participant}]`. Steps: call create; map response. Expected: `Success`; UI model exposes accepted=2 and a non-empty rejected list; partial-acceptance notice shown. Traces: AC-2.
- **TC-AND-160-03 — Create validation 422 → field errors.** Type: contract/MWS + unit. Target: MWS/JVM. Preconditions: 422 `HTTPValidationError` `detail:[{loc:["body","content","text"],msg:"...",type:"string_too_short"}]`. Steps: submit; map error. Expected: typed validation error; `CreateSheetState.errors[CampaignField.Text]` populated from `loc`/`msg`; sheet stays open. Traces: AC-4, AC-7.
- **TC-AND-160-04 — Client-side create validation gating.** Type: unit (ViewModel, Turbine). Target: JVM. Preconditions: empty draft. Steps: set text="" then valid text; set conversation_ids=[] then [c1]; set mode=scheduled with send_at=null. Expected: submit disabled while text blank OR ids empty OR (scheduled && send_at null); enabled when text in 1..4000, ids in 1..100, and send_at present for scheduled; no network call while invalid. Traces: AC-2, AC-4.
- **TC-AND-160-05 — List happy path + cursor paging (contract+paging).** Type: contract/MWS + unit. Target: MWS/JVM. Preconditions: page1 `{items:[summary], next_cursor:"X"}`, page2 `{items:[...], next_cursor:null}`. Steps: `PagingSource.load(refresh)` then append with cursor. Expected: `LoadResult.Page` with `nextKey=="X"` then `nextKey==null`; epoch-second timestamps mapped to `Instant`; status/mode/counters mapped. Traces: AC-1, AC-7.
- **TC-AND-160-06 — List GET retries then succeeds.** Type: contract/MWS. Target: MWS. Preconditions: 500 then 200. Steps: load first page. Expected: shared retry interceptor retries the idempotent GET and yields `Success` with one page. Traces: AC-5.
- **TC-AND-160-07 — Create/cancel are not auto-retried.** Type: contract/MWS. Target: MWS. Preconditions: enqueue a single 500 for POST create; one for POST cancel. Steps: call create, then cancel. Expected: exactly ONE request reaches the server per call (no interceptor auto-retry); `ApiResult.Error`; on user re-submit of create the SAME `idempotency_key` is sent. Traces: AC-5.
- **TC-AND-160-08 — Cancel happy path + path/param/shape.** Type: contract/MWS. Target: MWS. Preconditions: 200 `MassMessageCancelCampaignResponse{status:cancelled, cancelled_destinations:4}`. Steps: `cancelMassMessage("mmc_123")`. Expected: request path == `/messaging/mass-messages/mmc_123/cancel`, method POST, no body, `X-CSRF-Token` present; `Success` with status `cancelled`. Traces: AC-3, AC-7.
- **TC-AND-160-09 — Optimistic cancel reconcile + rollback.** Type: unit (ViewModel, Turbine). Target: JVM. Preconditions: row status `processing`. Steps: confirmCancel(id) with (a) success → reconcile, (b) non-2xx → rollback. Expected: id added to `inFlightCancelIds` immediately (optimistic `cancelling` overlay); on success removed and row reconciles to `cancelled` + list invalidation; on error removed, overlay reverts to `processing`, error snackbar emitted. Traces: AC-3, AC-4.
- **TC-AND-160-10 — isCancellable derivation across all statuses.** Type: unit (mapper). Target: JVM. Preconditions: summaries for each of pending/scheduled/processing/completed/failed/cancelled. Steps: map to UI. Expected: `isCancellable` true for {pending,scheduled,processing}, false for {completed,failed,cancelled}; localized status label resolved for each. Traces: AC-3.
- **TC-AND-160-11 — List/empty/error/offline UI states + create flow.** Type: Compose-UI. Target: emulator(test35). Preconditions: fake repo emitting loading→empty, loading→error, and a populated page; airplane/offline simulated for the offline branch. Steps: render screen; trigger FAB→sheet→submit; assert states. Expected: distinct spinner/empty/full-screen-error(retry)/offline states; FAB opens `ModalBottomSheet`; submit disabled until valid; on success sheet dismisses + snackbar + list refreshes; offline blocks create with "no connection" snackbar before any call. Traces: AC-1, AC-2, AC-4.
- **TC-AND-160-12 — Cancel confirm dialog + role/feature gate.** Type: Compose-UI. Target: emulator(test35). Preconditions: (a) creator with `messaging_mass_send_enabled=true`; (b) flag false / non-creator. Steps: tap row Cancel → `AlertDialog` → confirm; separately deep-link with gate off. Expected: (a) confirm dialog shown, on confirm row transitions to `cancelled`; terminal rows show no Cancel action; (b) no nav entry and deep-link renders "not available" without crash. Traces: AC-3, AC-6.
- **TC-AND-160-13 — ABI/API parity smoke on physical device.** Type: instrumented/e2e. Target: **device(A15)** (MUST run on physical device — validates arm64-v8a + API 34 vs. the x86_64/API-35 emulator). Preconditions: app installed on SM-A156U; backend (or MWS over adb-forwarded port) reachable. Steps: open Mass Messages, create an immediate campaign to 1 conversation, then cancel it. Expected: create→list-refresh→cancel→`cancelled` works identically to emulator; no arm64-only Moshi/Paging crashes; epoch-second timestamps render with device locale. Traces: AC-2, AC-3.
- **TC-AND-160-14 — Accessibility audit.** Type: Compose-UI (accessibility) + manual. Target: emulator(test35) for automated semantics; manual TalkBack pass on device(A15). Preconditions: populated list + open create sheet. Steps: run accessibility checks (Espresso/Compose `AccessibilityChecks`); TalkBack-navigate FAB, row Cancel, status chips, confirm dialog, and create-sheet fields. Expected: FAB content description "Create mass message"; per-row Cancel and status chips have semantics; touch targets ≥48dp; create-sheet fields expose labels + error `stateDescription`; confirm dialog focus-trapped and announced. Traces: AC-1, AC-3 (UI), supports AC-6.
- **TC-AND-160-15 — No PII in logs/telemetry.** Type: unit + manual. Target: JVM (+ manual logcat on device(A15)). Preconditions: debug logging interceptor on. Steps: run create/cancel; inspect emitted analytics params and logs. Expected: analytics carry only non-PII (`is_scheduled`, `error_code`, accepted/rejected counts) — never message `text` or `conversation_id`s; OkHttp body logging redacts `content.text`. Traces: supports §8/§10 (security/privacy), AC-2.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (list + states) | TC-05, TC-11, TC-14 |
| AC-2 (create flow) | TC-01, TC-02, TC-04, TC-11, TC-13, TC-15 |
| AC-3 (cancel flow) | TC-08, TC-09, TC-10, TC-12, TC-13, TC-14 |
| AC-4 (optimistic rollback / 422 field errors) | TC-03, TC-04, TC-09, TC-11 |
| AC-5 (GET retries; create/cancel no auto-retry) | TC-06, TC-07 |
| AC-6 (role/feature gate + deep-link) | TC-12, TC-14 |
| AC-7 (DTO mapping + create/cancel vs MWS) | TC-01, TC-03, TC-05, TC-08 |
