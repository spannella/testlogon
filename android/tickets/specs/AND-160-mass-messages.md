---
id: AND-160
title: Mass messages
milestone: M3
epic: E22
priority: P2
size: M
status: draft
depends_on: [AND-120]
blocks: []
---

# AND-160 — Mass messages

## 1. Overview & Goal

This ticket delivers the **creator-facing mass-messages (broadcast campaign) feature** for the TestLogon native Android app. A mass message is a one-to-many campaign authored by a creator and delivered to many recipients (followers, subscribers, or a saved segment) as individual direct conversations. The web reference app surfaces this under the route `/messaging/mass-messages`.

The Android scope is deliberately bounded by the backlog acceptance criterion: a creator can **list** existing campaigns, **create** a new campaign, and **cancel** a queued/scheduled campaign before it finishes sending. Editing in flight, recipient-segment authoring beyond what the API already exposes, rich analytics dashboards, and per-recipient delivery drill-down are explicitly **out of scope** for AND-160 and are deferred to later epic E22 tickets.

The goal is a `feature-messaging` screen pair (list + create sheet) backed by a Hilt-injected repository over the existing `MessagingApi` (AND-120), exposing a `StateFlow<UiState>` from a ViewModel, with the create and cancel mutations wired to the cookie-authenticated backend and verified against fixtures. Success = a creator can create a campaign and cancel a campaign, and both actions are reflected in the list with correct status transitions, offline/stale handling, and CSRF-protected writes.

## 2. Context & References

- **Route parity:** Web `/messaging/mass-messages` (creator role only). Web API layer: `frontend/src/api/endpoints/messaging.ts`; shared types in `frontend/src/api/types.ts`.
- **Dependency AND-120 (Messaging API + DTOs):** Provides the `MessagingApi` Retrofit interface and the shared messaging DTO/Moshi infrastructure (`core-network`, `core-model`). AND-160 **extends** that interface with mass-message endpoints and DTOs rather than creating a parallel API client. AND-160 must not duplicate the conversation/message DTOs already defined there.
- **Auth model:** Cookie-based session (`POST /ui/session/start` → MFA → `/ui/session/finalize` → `/ui/me`). All mutating calls in this ticket are writes and therefore require the `X-CSRF-Token` header echoed from the `ui_csrf` cookie; the shared OkHttp interceptor chain (cookie jar + CSRF + single 401→`/ui/session/refresh`→retry) from `core-network` applies unchanged.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Confirm exact field names against `/openapi.json` and the web `messaging.ts` during implementation; the JSON shapes in §5 are the contract to validate, with discrepancies resolved in favour of the live OpenAPI.
- **Module layering:** `app -> feature-messaging -> core-network/core-model/core-data/core-ui/core-testing`.
- **Stack pins:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3, Coroutines/Flow. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1. **List campaigns.** When a creator opens the Mass Messages screen, the app fetches and displays a paged list of the creator's campaigns, newest first. Each row shows: title/preview text, status (`draft`, `scheduled`, `sending`, `sent`, `cancelled`, `failed`), recipient audience label, recipient count, and scheduled/sent timestamp.

FR-2. **Empty / loading / error states.** Distinct UI for first-load spinner, empty list (no campaigns), full-screen error (initial load failure with retry), and inline page-append error (Paging 3 `LoadState.Error` footer with retry).

FR-3. **Create campaign.** A "New campaign" FAB opens a modal create sheet capturing: message **text** (required, non-blank, max length enforced by `MessagingConfig` from AND-120 `/messaging/config`), **audience** selection (e.g. `all_followers`, `subscribers`, or a `segment_id`), optional **price** (for paid PPV broadcasts; null = free), optional **media attachment ids**, and optional **schedule time** (null = send now). Submit is disabled until required fields validate.

FR-4. **Create result.** On success the sheet dismisses, a confirmation snackbar shows, and the new campaign is prepended/refreshed into the list with its server-assigned status (`scheduled` or `sending`).

FR-5. **Cancel campaign.** A row whose status is `cancellable` (`draft`, `scheduled`, or `sending`) exposes a "Cancel" action behind a confirmation dialog. Confirming calls the cancel endpoint; on success the row transitions to `cancelled`. Rows in terminal states (`sent`, `failed`, `cancelled`) do not show the action.

FR-6. **Optimistic + reconciled state.** Cancel updates the row optimistically to a `cancelling` transient state and reconciles to the server-returned status; on failure it rolls back and surfaces an error snackbar.

FR-7. **Refresh.** Pull-to-refresh and a manual retry re-query the first page. After any successful create/cancel the list invalidates so the data source reloads.

FR-8. **Role gate.** The screen is reachable only for users whose `/ui/me` profile indicates creator capability. Non-creators are not given the navigation entry; deep-linking renders a "not available" state rather than crashing.

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

data class CreateCampaignDraft(
    val text: String = "",
    val audience: Audience = Audience.AllFollowers,
    val priceCents: Long? = null,
    val mediaIds: List<String> = emptyList(),
    val scheduledAt: Instant? = null,
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
@GET("/messaging/mass-messages")
suspend fun listMassMessages(
    @Query("cursor") cursor: String? = null,
    @Query("limit") limit: Int = 20,
): Response<MassMessagePageDto>

@POST("/messaging/mass-messages")
suspend fun createMassMessage(@Body body: CreateMassMessageDto): Response<MassMessageDto>

@POST("/messaging/mass-messages/{id}/cancel")
suspend fun cancelMassMessage(@Path("id") id: String): Response<MassMessageDto>
```

### 4.5 UI (Compose)

`MassMessagesScreen` collects `campaigns.collectAsLazyPagingItems()` and `uiState`. A `LazyColumn` of `MassCampaignRow` composables; `PullToRefreshBox` (Material 3) wraps it; `ExtendedFloatingActionButton` triggers `openCreate()`. `CreateCampaignSheet(ModalBottomSheet)` renders text field with live char counter, audience `SegmentedButton`/dropdown, optional price field, and a date/time picker for scheduling. `CancelConfirmDialog` is an `AlertDialog`. One-shot events drive a `SnackbarHostState`.

## 5. API Contract

All paths are relative to the dev base URL. Cookies + `X-CSRF-Token` are applied by the shared interceptor; writes (POST) require CSRF. Field names below are the contract to validate against `/openapi.json` and `frontend/src/api/endpoints/messaging.ts`.

**List — `GET /messaging/mass-messages?cursor=&limit=20`**
```json
{
  "items": [
    {
      "id": "mm_01HXYZ",
      "text": "New set just dropped 🔥",
      "status": "scheduled",
      "audience": { "type": "all_followers", "segment_id": null },
      "recipient_count": 1842,
      "price_cents": 0,
      "media_ids": [],
      "scheduled_at": "2026-06-06T18:00:00Z",
      "sent_at": null,
      "created_at": "2026-06-05T12:01:00Z",
      "sent_count": 0,
      "failed_count": 0
    }
  ],
  "next_cursor": "eyJrIjoiMSJ9"
}
```

**Create — `POST /messaging/mass-messages`**
```json
// request
{
  "text": "New set just dropped 🔥",
  "audience": { "type": "subscribers", "segment_id": null },
  "price_cents": 500,
  "media_ids": ["med_123"],
  "scheduled_at": "2026-06-06T18:00:00Z"
}
// 201 response: a single MassMessageDto (same shape as a list item)
```

**Cancel — `POST /messaging/mass-messages/{id}/cancel`**
```json
// no body required; returns updated MassMessageDto
{ "id": "mm_01HXYZ", "status": "cancelled", "...": "..." }
```

**Error envelope (FastAPI):** `{"detail": "..."}` or `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`. Notable codes: `403` (not a creator / cannot cancel terminal campaign), `404` (campaign id unknown), `409` (already sent/cancelled), `422` (validation: empty text, text over max, invalid audience). All map through the shared `ApiResult` error mapper.

Moshi DTOs: `MassMessagePageDto`, `MassMessageDto`, `AudienceDto`, `CreateMassMessageDto`. `@Json(name=...)` aligns snake_case JSON to camelCase Kotlin. Timestamps use the project `Instant` adapter (ISO-8601).

## 6. Data & State Management

- **Source of truth:** server. The list is network-backed via a Paging 3 `PagingSource<String, MassCampaignUi>` keyed by `next_cursor`. No Room persistence in this ticket — campaign volume is small, freshness matters, and the cancel/create flows demand immediate reload. (A Room-backed `RemoteMediator` for offline campaign history is a deferred E22 enhancement.)
- **DataStore:** none new; reuse the existing creator-profile cache from `/ui/me` for the FR-8 role gate.
- **Domain vs UI models:** `MassMessageDto` → `MassCampaign` (domain, in `core-model`) → `MassCampaignUi` (formatted strings, derived `isCancellable`, localized status label). Mapping in `MassCampaignMapper`.
- **Transient mutation state:** `inFlightCancelIds` and the optimistic `cancelling` overlay live in `MassMessagesUiState`, applied at render time over the paged item (paged items are immutable, so the optimistic status is a UI-layer overlay keyed by id, then resolved by invalidation after the server responds).
- **Invalidation:** after a successful create or cancel, the repository signals invalidation; `LazyPagingItems` reloads page 1. Pull-to-refresh calls `refresh()` on the lazy paging items.
- **Process death:** `CreateCampaignDraft` text/audience/price are held in the ViewModel; for resilience the draft is mirrored to `SavedStateHandle` so an in-progress compose survives configuration changes and process death.

## 7. Error Handling & Resilience

- **Timeouts:** rely on `core-network`'s ~20s OkHttp call timeout for the unreliable dev host.
- **Retry policy:** the **GET list** is idempotent → bounded exponential backoff (e.g. 2 retries, 500ms→2s, jitter) via the shared retry interceptor. **POST create** and **POST cancel** are **non-idempotent → no automatic retry**; user-initiated retry only, surfaced via snackbar action.
- **401:** handled by the shared single-shot `/ui/session/refresh` + retry interceptor; on second 401 the global auth state routes to re-login.
- **Offline:** if the device is offline, the list shows a full-screen offline state (initial) or an inline append error (subsequent pages); create/cancel are blocked with a "no connection" snackbar before issuing the call.
- **Domain conflicts:** `409` on cancel (campaign already sent/cancelled) → roll back optimistic state and refresh the row; show "This campaign can no longer be cancelled." `422` on create → field-level errors mapped into `CreateSheetState.errors` (e.g. empty text → `CampaignField.Text`).
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

- **R1 — Endpoint shape unverified.** The exact `/messaging/mass-messages` request/response field names and the cancel path are inferred from the web app and must be confirmed against `/openapi.json`. *Mitigation:* validate during step (1); the spec's JSON is the contract to reconcile.
- **R2 — Audience model ambiguity.** Whether audience is an enum, a free segment id, or a composite is unclear. *Open question:* confirm allowed `audience.type` values and whether `segment_id` selection requires a separate segments endpoint (if so, segment picker is deferred and only enum audiences ship in AND-160).
- **R3 — Cancellable states.** Backend rules for which statuses accept `/cancel` (does `sending` allow partial cancel?) need confirmation; client `isCancellable` must match server to avoid 409s.
- **R4 — Paid broadcast (PPV) pricing** may require currency/limits from `/messaging/config`; if config lacks them, price field uses safe client bounds until clarified.
- **R5 — Unreliable dev host** can make UI flows flaky in manual QA; mitigated by timeouts, offline states, and MockWebServer-based automated tests.

## 14. Acceptance Criteria

AC-1. A creator can open `/messaging/mass-messages` and see a paged list of their campaigns with correct status, audience, recipient count, and timestamp; empty/loading/error/offline states each render correctly. *(FR-1, FR-2)*
AC-2. A creator can **create** a campaign from the sheet: required validation enforced, `POST /messaging/mass-messages` issued with `X-CSRF-Token`, success dismisses the sheet, shows confirmation, and the new campaign appears in the list. *(FR-3, FR-4 — backlog: "Create … a campaign")*
AC-3. A creator can **cancel** a cancellable campaign via confirmation; `POST /messaging/mass-messages/{id}/cancel` succeeds and the row transitions to `cancelled`; terminal-state rows offer no cancel. *(FR-5, FR-6 — backlog: "cancel a campaign")*
AC-4. Optimistic cancel rolls back on `409`/error with an error snackbar; `422` create errors surface as field-level messages. *(FR-6, §7)*
AC-5. GET list retries (idempotent) on transient failure; create/cancel never auto-retry. *(§7)*
AC-6. Non-creators have no nav entry; deep-link renders an unavailable state without crashing. *(FR-8)*
AC-7. Unit tests: DTO mapping verified against fixtures (consistent with AND-120) and both create + cancel flows pass against MockWebServer. *(§11)*

## 15. Definition of Done

- `feature-messaging` mass-messages list + create sheet + cancel implemented under `com.testlogon.android.feature.messaging.mass`, wired into the Navigation-Compose host with the creator role gate.
- `MessagingApi` extended with list/create/cancel; Moshi DTOs and `MassCampaignMapper` complete with `@Json` mappings and ISO-8601 timestamps.
- `MassMessagesRepository(Impl)` and `MassMessagesViewModel` exposing `StateFlow<MassMessagesUiState>` + `Flow<PagingData>`, with CSRF-protected writes and the shared error/`ApiResult` mapping.
- All seven acceptance criteria demonstrably met; unit, repository (MockWebServer), ViewModel (Turbine), paging, and Compose UI tests green at ≥80% coverage on repo/VM/mapper.
- No hardcoded strings; accessibility (content descriptions, 48dp targets, RTL, dynamic type) verified; telemetry events emitted without logging message text or recipient PII.
- Open questions R1–R4 resolved against `/openapi.json` (or explicitly documented as deferred) before merge; code passes ktlint/detekt and builds on the `android-port` branch with AGP 8.7.3 / Gradle 8.9 / JDK 17.
