---
id: AND-398
title: Webhooks config (light)
milestone: M8
epic: E52
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-398 — Webhooks config (light)

## 1. Overview & Goal

Deliver a lightweight Webhooks configuration surface in the TestLogon native Android
app: a screen that lists the authenticated account's configured outbound webhook
endpoints, lets the user open a single endpoint to view its full configuration, and
supports a constrained ("light") create flow for registering a new endpoint. The
goal is read-and-register parity with the web reference layer `webhooks.ts`, not full
lifecycle management — update, secret rotation, delivery-log inspection, and bulk
operations are explicitly out of scope and deferred to a future heavyweight ticket.

The acceptance bar for this ticket is intentionally narrow: **webhooks render**. A
user who has configured webhooks on the web app must see those same endpoints,
correctly mapped, in the Android app, and must be able to create a basic endpoint
(target URL + subscribed event types) that subsequently appears in the list. Success
is measured by a correctly populated list backed by real API data, a functional
detail view, and a create path that round-trips through the backend.

This is a feature ticket in milestone M8 (settings/admin surfaces) under epic E52.
It depends on AND-027 (AuthApi session endpoints) because every webhooks call is an
authenticated, cookie-bearing, CSRF-protected request that reuses the session
infrastructure established there.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/webhooks.ts` (endpoint definitions),
  `frontend/src/api/types.ts` (shared `Webhook`, `WebhookEvent` types). The Android
  implementation mirrors these paths and field names exactly; any divergence is a bug.
- **OpenAPI:** `/openapi.json` on the dev backend (`http://18.222.237.167:8000`) is
  the authoritative source for request/response shapes. Field names below are derived
  from the web reference and MUST be reconciled against `/openapi.json` during
  implementation (see Open Questions §13).
- **Auth dependency (AND-027):** [CORRECTED] the web client (`src/api/client.ts`)
  authenticates with **three** mechanisms combined: an `Authorization: Bearer
  <accessToken>` header from the auth store (primary), the `ui_csrf` cookie echoed as
  `X-CSRF-Token` (on every request, not only unsafe ones), and `credentials: include`
  (the cookie jar). The earlier draft mentioned only the cookie jar + CSRF and omitted
  the Bearer token; the Android port must replicate all three. On `401` (only when the
  user was already authenticated) the client calls `POST /ui/session/refresh` once,
  then retries the original request; a second `401` logs the user out. The OpenAPI
  declares optional `user_sub` (query), `X-SESSION-ID` and `X-IMPERSONATION-TOKEN`
  (headers) on these routes — these are server-side/impersonation concerns and are NOT
  set by the normal web client for a self-service caller. This ticket consumes the
  AND-027 machinery and adds no new auth logic.
- **Module layering:** `app -> feature-webhooks -> core-network, core-model,
  core-data, core-ui, core-testing`. ViewModels expose `StateFlow<UiState>`; all API
  calls return `ApiResult<T>`.
- **Namespace:** all packages are under `com.testlogon.android`.

## 3. Functional Requirements

FR-1 — **List.** On entering the Webhooks screen the app fetches the caller's
webhook endpoints via `GET /ui/webhooks` and renders each as a row showing: target
URL (primary), subscribed event-type count or chips (secondary), and active/disabled
status. An empty result renders an empty-state with a "Create webhook" affordance.

FR-2 — **View / detail.** Tapping a row navigates to a detail screen for that
endpoint showing target URL, full list of subscribed event types, enabled flag
(`enabled`), creation timestamp, and (if present) a masked secret indicator. Detail
data is taken from the list payload where complete; otherwise it is fetched via
`GET /ui/webhooks/{endpoint_id}`. [CORRECTED: the path param is `endpoint_id`, not
`id`; the status field is `enabled` (boolean), not `active`.]

FR-3 — **Light create.** A create screen collects a target URL and a multi-select of
event types. [CORRECTED/RESOLVED: the allowed event-type set is enumerable from the
backend via `GET /ui/webhooks/event-types`, which returns `{ event_types:
[{ type, description }] }`. Use this rather than a static enum; resolves OQ-2.]
Submitting issues `POST /ui/webhooks` with a `WebhookEndpointCreateReq` body whose
required fields are `url` and `event_types` (note: `event_types`, not `events`). On
success (HTTP **201**) the user returns to the list, which refreshes and shows the new
endpoint. "Light" means: no custom headers editor, no per-delivery `retry_policy` UI,
no `signature_version`/`circuit_failure_threshold` controls (these optional fields are
left at backend defaults), no manual secret entry — the backend generates the signing
secret.

FR-4 — **Validation.** The target URL must be a syntactically valid `https://` URL
(plaintext `http://` is rejected client-side for safety even though the dev backend
is HTTP); at least one event type must be selected. The submit button is disabled
until both constraints are met.

FR-5 — **Refresh & stale state.** The list supports pull-to-refresh and surfaces
offline/stale indicators consistent with the app-wide resilience pattern (the dev
host is unreliable; see §7).

FR-6 — **Out of scope (must NOT be built here):** edit/PATCH, delete, secret
rotation, test-ping/send, delivery history, pagination beyond a single page (the
endpoint is assumed to return the full small set). These are named for the future
heavyweight webhooks ticket and are not implemented.

## 4. Technical Design

New Gradle module `feature-webhooks` with package
`com.testlogon.android.feature.webhooks`. Single-Activity Navigation-Compose; three
destinations registered on the app nav graph.

**Navigation routes**

```kotlin
sealed interface WebhooksRoute {
    @Serializable data object List : WebhooksRoute
    @Serializable data class Detail(val id: String) : WebhooksRoute
    @Serializable data object Create : WebhooksRoute
}

fun NavGraphBuilder.webhooksGraph(nav: NavController)
```

**Retrofit API** (in `core-network`, alongside `AuthApi` from AND-027):

```kotlin
interface WebhooksApi {
    // CORRECTED: list returns a BARE ARRAY of endpoints, not a {webhooks:[...]} envelope.
    @GET("ui/webhooks")
    suspend fun list(): Response<List<WebhookEndpointDto>>

    // CORRECTED: path param is endpoint_id; response is WebhookEndpointOut.
    @GET("ui/webhooks/{endpointId}")
    suspend fun get(@Path("endpointId") endpointId: String): Response<WebhookEndpointDto>

    @POST("ui/webhooks")
    suspend fun create(@Body body: CreateWebhookRequest): Response<WebhookEndpointDto>

    // RESOLVES OQ-2: backend enumerates the subscribable event types.
    @GET("ui/webhooks/event-types")
    suspend fun eventTypes(): Response<EventTypesDto>  // { event_types: [{type, description}] }
}
```

[CORRECTED] Auth wiring: the shared OkHttp interceptor attaches `Authorization:
Bearer <token>` AND `X-CSRF-Token` (from the `ui_csrf` cookie) on **every** request,
and the cookie jar supplies session cookies via `credentials: include` parity. The
earlier draft implied CSRF only on the unsafe `POST`; the web client sends it on all
verbs. No per-call header wiring is added here.

**Repository** (in `core-data`):

```kotlin
interface WebhooksRepository {
    suspend fun list(forceRefresh: Boolean = false): ApiResult<List<Webhook>>
    suspend fun get(id: String): ApiResult<Webhook>
    suspend fun create(targetUrl: String, events: List<String>): ApiResult<Webhook>
}

@Singleton
class DefaultWebhooksRepository @Inject constructor(
    private val api: WebhooksApi,
    private val errorMapper: ApiErrorMapper,
) : WebhooksRepository
```

`list` reads from Room cache first (offline support) then refreshes; `create`
write-through invalidates the cached list. `get` prefers the cached list entry,
falling back to the network.

**ViewModels** (Hilt, KSP) expose `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class WebhooksListViewModel @Inject constructor(
    private val repo: WebhooksRepository,
) : ViewModel() {
    val uiState: StateFlow<WebhooksListUiState>
    fun refresh()
}

@HiltViewModel
class WebhookDetailViewModel @Inject constructor(
    private val repo: WebhooksRepository,
    savedState: SavedStateHandle,
) : ViewModel() { val uiState: StateFlow<WebhookDetailUiState> }

@HiltViewModel
class CreateWebhookViewModel @Inject constructor(
    private val repo: WebhooksRepository,
) : ViewModel() {
    val form: StateFlow<CreateWebhookForm>
    fun onUrlChange(v: String); fun toggleEvent(e: String); fun submit()
}
```

**Composables** (Compose + Material 3): `WebhooksListScreen`, `WebhookRow`,
`WebhookDetailScreen`, `CreateWebhookScreen` (with `OutlinedTextField` for URL and
`FilterChip` group for events). All hoisted state-down / events-up; previews use
fake `UiState` instances from `core-testing`.

## 5. API Contract

Base URL: `http://18.222.237.167:8000/`. All calls authenticated (`Authorization:
Bearer` + cookies + `X-CSRF-Token`). [CORRECTED throughout this section against
`components.schemas.WebhookEndpointOut` / `WebhookEndpointCreateReq` and
`src/api/endpoints/webhooks.ts`.]

**List** — `GET /ui/webhooks` → `200`. The response is a **bare JSON array** of
`WebhookEndpointOut` objects (schema title "Response List Webhook Endpoints Ui
Webhooks Get", `type: array`). There is **no** `{ "webhooks": [...] }` envelope.

```json
[
  {
    "endpoint_id": "wh_01HX...",
    "url": "https://example.com/hooks/tl",
    "description": "",
    "event_types": ["session.finalized", "mfa.verified"],
    "enabled": true,
    "secret": null,
    "created_at": 1747072651,
    "updated_at": 1747072651,
    "last_delivery_at": null,
    "failure_count": 0,
    "disabled_reason": null,
    "signature_version": "v2"
  }
]
```

Field corrections vs the draft: identifier is **`endpoint_id`** (not `id`); event list
is **`event_types`** (not `events`); status flag is **`enabled`** (not `active`);
**`created_at`/`updated_at` are integer epoch seconds** (not ISO-8601 strings — map to
`Instant.ofEpochSecond`). There is **no `secret_set` boolean**; instead a nullable
**`secret`** string field exists (typically `null` on list/detail; only populated on
creation/rotation). Required fields per schema: `endpoint_id`, `url`. Additional
optional fields exist (`retry_policy`, circuit-breaker fields) and are ignored by this
light feature.

**Detail** — `GET /ui/webhooks/{endpoint_id}` → `200:WebhookEndpointOut`, same shape
as a list element. [CORRECTED: param name is `endpoint_id`.] Note: the OpenAPI lists
only `200` and `422` for this route; a `404` for an unknown id is an **unverified
assumption** (not declared in the spec) — implementation should handle the
not-declared case defensively but not rely on `404` semantics.

**Event types** — `GET /ui/webhooks/event-types` → `200`
```json
{ "event_types": [ { "type": "session.finalized", "description": "..." } ] }
```
Used to populate the create-screen multi-select (resolves OQ-2).

**Create** — `POST /ui/webhooks` with `WebhookEndpointCreateReq`:

```json
{ "url": "https://example.com/hooks/tl",
  "event_types": ["session.finalized"] }
```

Required: `url`, `event_types`. → **`201`** (confirmed; the draft's "201 or 200"
ambiguity is resolved — only `201` is declared). The OpenAPI 201 response schema is
empty (`{}`), but the web client types the body as `WebhookEndpointOut`
(`api.post<WebhookEndpointOut>`), so the Android client deserializes the created
endpoint. The signing **`secret`**, if returned, appears in this create response and
is shown once.

**Error envelope** — FastAPI `detail`, mapped by the shared `ApiErrorMapper`. Per
`src/api/client.ts::normalizeErrorDetail`, `detail` may be a `string`, an array of
`{ "msg": ... }` items (422 `HTTPValidationError`), or an object with a `code` field
(e.g. `role_required_scope`, `geo_blocked` for 403). All webhooks routes declare
`422:HTTPValidationError`.

## 6. Data & State Management

**Domain model** (`core-model`):

```kotlin
// CORRECTED to match WebhookEndpointOut: id<-endpoint_id, events<-event_types,
// active<-enabled, secretSet derived from nullable `secret`, createdAt from epoch int.
data class Webhook(
    val id: String,          // maps from DTO `endpoint_id`
    val url: String,
    val description: String,  // present in DTO (default "")
    val events: List<String>, // maps from DTO `event_types`
    val enabled: Boolean,     // maps from DTO `enabled` (NOT `active`)
    val secretSet: Boolean,   // derived: dto.secret != null
    val secret: String?,      // one-time value on create; null otherwise
    val createdAt: Instant,   // DTO `created_at` is epoch SECONDS -> Instant.ofEpochSecond
)
```

**UiState** (sealed; one per screen):

```kotlin
sealed interface WebhooksListUiState {
    data object Loading : WebhooksListUiState
    data class Content(
        val items: List<Webhook>,
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
    ) : WebhooksListUiState
    data object Empty : WebhooksListUiState
    data class Error(val message: String, val retryable: Boolean) : WebhooksListUiState
}

data class CreateWebhookForm(
    val url: String = "",
    val selectedEvents: Set<String> = emptySet(),
    val submitting: Boolean = false,
    val urlError: String? = null,
    val submitError: String? = null,
    val canSubmit: Boolean = false,
)
```

**Caching:** Room entity `WebhookEntity` in `core-data` with the webhook fields plus
a `fetched_at` epoch column for staleness. A single DAO
(`WebhooksDao.observeAll()/upsertAll()/clear()`) backs offline display. DataStore is
not used for webhooks (no user prefs). The create flow performs write-through:
`upsertAll(listOf(new))` then a background list refresh.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (shared client config from core-network),
  consistent with the unreliable dev host.
- **Retry:** the idempotent `GET /ui/webhooks` and `GET /ui/webhooks/{endpoint_id}` are
  eligible for the shared bounded exponential backoff (max 2 retries). `POST
  /ui/webhooks` is **never** auto-retried (non-idempotent); a failed create surfaces
  inline with a manual "Try again".
- **401:** handled transparently by the AND-027 interceptor — single
  `POST /ui/session/refresh` then retry; on second 401 the user is routed to re-auth.
- **Offline / network failure:** list falls back to last cached page rendered with
  `isStale = true` and a banner ("Showing saved data"); if cache is empty, an
  `Error(retryable = true)` state with a retry button.
- **422 on create:** validation `detail` array mapped to `submitError` and, when the
  `loc` points at `url`, to the field-level `urlError`.
- **404 detail:** detail screen shows a not-found state with back navigation.
  [NOTE: `404` is NOT declared in the OpenAPI for `GET /ui/webhooks/{endpoint_id}`
  (only `200`/`422`). Treat any non-2xx other than `422`/`401` as a generic
  retryable/not-found error; do not depend on a `404` contract — unverified.]

## 8. Security & Privacy

- All requests are authenticated via the existing cookie jar; no credentials or
  tokens are persisted by this feature beyond the shared session store.
- **CSRF:** the `X-CSRF-Token` header (from the `ui_csrf` cookie) is required on
  `POST /ui/webhooks` and is applied by the shared interceptor.
- **URL safety:** client-side validation rejects non-`https://` target URLs to avoid
  guiding users into insecure webhook delivery, even though the TestLogon dev backend
  itself is plaintext HTTP.
- **Secret handling:** the webhook signing secret is never requested from or stored
  by the app. If the create response includes a one-time `secret`, it is displayed
  once in-session, never written to Room/DataStore/logs, and copyable to clipboard
  with a "store this now" warning.
- No webhook URLs or secrets are written to logs (see §10 redaction).

## 9. Accessibility & i18n

- All strings live in `strings.xml` (`feature-webhooks`); no hardcoded UI text. RTL
  layouts supported via Compose defaults.
- Webhook rows expose merged `contentDescription` ("Webhook to {url}, {n} events,
  {active|disabled}"). Status is conveyed by text/icon, not color alone.
- `FilterChip` event selectors are individually focusable with toggle semantics
  (`Role.Checkbox`); minimum 48dp touch targets.
- The URL field declares `KeyboardType.Uri`, an `imeAction = Done`, and announces
  validation errors via `Modifier.semantics { error(...) }`.
- Supports Dynamic Type / font scaling and Material 3 dynamic color.

## 10. Telemetry & Logging

- Emit analytics events through the app's existing tracker: `webhooks_list_viewed`
  (with `count`), `webhook_detail_viewed`, `webhook_create_started`,
  `webhook_create_succeeded`, `webhook_create_failed` (with mapped `error_code`).
- Structured debug logs at the repository boundary: request path, HTTP status,
  latency, retry count. **Redact** the `url`, any `secret`, and webhook ids beyond a
  short prefix. No PII or secret material in logcat or crash reports.
- Network logging uses the shared OkHttp logging interceptor (BASIC in release,
  redacting interceptor active for these paths).

## 11. Testing Strategy

- **API (MockWebServer):** assert verbs/paths/bodies — `GET /ui/webhooks`,
  `GET /ui/webhooks/{id}`, `POST /ui/webhooks` with correct JSON body and presence of
  `X-CSRF-Token`; deserialize the sample payloads in §5; verify 401→refresh→retry
  reuses the AND-027 path; verify 422 detail mapping.
- **Repository:** cache-then-network for `list`, write-through on `create`, offline
  fallback returns stale data, GETs retry / POST does not.
- **ViewModel (Turbine):** `Loading → Content/Empty/Error` transitions; create form
  `canSubmit` gating (invalid URL, no events selected, valid); submit success
  triggers list refresh; submit failure populates `submitError`.
- **Compose UI tests:** list renders rows from fake state (the core acceptance —
  "webhooks render"); empty-state shows create CTA; detail shows event list; create
  screen disables submit until valid. Roboelectric/AndroidTest for nav round-trip
  (list → create → back → refreshed list).
- **Fakes** provided by `core-testing` (`FakeWebhooksRepository`).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-027 (AuthApi session endpoints) — supplies the
  authenticated OkHttp client, persistent cookie jar, CSRF interceptor, and
  401-refresh authenticator that every webhooks call relies on. This ticket adds no
  new auth/network plumbing; it registers `WebhooksApi` on the same Retrofit instance.
- **Implicit:** the `ApiResult<T>` type, `ApiErrorMapper`, base Retrofit/Moshi setup,
  Room infrastructure, and `core-ui` components are assumed present from core-network /
  core-data foundation tickets (transitively via AND-027 → AND-026).
- **Blocks:** none recorded. The future heavyweight webhooks ticket (edit/delete/
  rotate/delivery-log) will depend on this one but is not yet ticketed.
- **Sequencing within ticket:** (1) DTOs + `WebhooksApi` + MockWebServer tests; (2)
  Room entity/DAO + repository; (3) list ViewModel + screen (satisfies acceptance);
  (4) detail; (5) light create.

## 13. Risks & Open Questions

- **OQ-1 (field names / path):** [RESOLVED during review.] Path is `/ui/webhooks`
  (flat, not org-nested). Field names are `url`, `event_types` (not `events`),
  `enabled` (not `active`), `endpoint_id` (not `id`). Confirmed against
  `components.schemas.WebhookEndpointOut` and `src/api/types.ts: WebhookEndpointOut`.
  The list payload is a bare array, not an envelope. See §5 and §16.
- **OQ-2 (allowed event types):** [RESOLVED.] The backend enumerates them via
  `GET /ui/webhooks/event-types` → `{ event_types: [{ type, description }] }`
  (`src/api/endpoints/webhooks.ts: listWebhookEventTypes`, `types.ts:
  WebhookEventType`). Use the dynamic source; a static fallback is only a last resort
  if the metadata call fails.
- **OQ-3 (create response status & secret):** [RESOLVED.] `POST /ui/webhooks` returns
  **`201`** (only status declared). The 201 body schema is empty in OpenAPI but the web
  client deserializes it as `WebhookEndpointOut`; the one-time signing `secret` (nullable
  string) may appear in that response. UI handles `201` and the optional `secret`.
- **Risk:** dev host instability may cause flaky integration tests — mitigated by
  MockWebServer-based testing for CI; live calls used only for manual verification.
- **Risk:** scope creep toward full CRUD — guarded by the explicit out-of-scope list
  in FR-6.

## 14. Acceptance Criteria

AC-1 — Given a session with one or more configured webhooks, opening the Webhooks
screen renders each endpoint as a row (URL, event summary, status) sourced from
`GET /ui/webhooks`. **(Primary acceptance: "webhooks render".)**

AC-2 — Given zero configured webhooks, the screen shows an empty-state with a working
"Create webhook" affordance.

AC-3 — Tapping a row opens a detail screen showing the endpoint's URL, full event
list, active flag, and creation time.

AC-4 — The create screen rejects submission until the target URL is a valid
`https://` URL and at least one event type is selected; a valid submission issues
`POST /ui/webhooks` and, on success, returns to a refreshed list containing the new
endpoint.

AC-5 — MockWebServer tests confirm correct paths/verbs/bodies and that `POST`
carries `X-CSRF-Token`; a 401 triggers exactly one refresh-and-retry.

AC-6 — On network failure with a populated cache, the list renders stale data with a
"saved data" indicator; with an empty cache it shows a retryable error.

AC-7 — No webhook URL or secret appears in logcat; the create secret (if any) is
shown once and never persisted.

## 15. Definition of Done

- `feature-webhooks` module created under `com.testlogon.android.feature.webhooks`
  with `WebhooksApi`, DTOs, repository, three ViewModels, and three Compose screens.
- All sections §3–§8 implemented; FR-6 scope boundaries respected.
- Unit, ViewModel (Turbine), API (MockWebServer), and Compose UI tests green in CI;
  coverage for the list/create/repository paths.
- Strings externalized; a11y semantics and 48dp targets verified; redacting logging
  confirmed.
- OQ-1..OQ-3 resolved against `/openapi.json` (or tracked as follow-ups with code
  comments) before merge.
- Lint/detekt/ktlint clean; builds on Gradle 8.9 / AGP 8.7.3 / JDK 17, compileSdk 35,
  minSdk 24.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. OpenAPI sources
are `reference/openapi.index.txt` (route index) and `reference/openapi.pretty.json`
(`components.schemas.*`). Frontend sources are under `reference/src/`.

1. **List endpoint is `GET /ui/webhooks`.** VERIFIED. OpenAPI `GET /ui/webhooks`
   (op=`list_webhook_endpoints_ui_webhooks_get`); `src/api/endpoints/webhooks.ts:
   listWebhookEndpoints`.
2. **List returns a bare array, not a `{ webhooks: [...] }` envelope.** CORRECTED
   (draft claimed an envelope). OpenAPI `GET /ui/webhooks` 200 schema = `type: array`
   of `#/components/schemas/WebhookEndpointOut` ("Response List Webhook Endpoints Ui
   Webhooks Get"); `src/api/endpoints/webhooks.ts` types it `WebhookEndpointOut[]`.
3. **Identifier field is `endpoint_id`, not `id`.** CORRECTED. Schema
   `WebhookEndpointOut` (required `endpoint_id`); `src/api/types.ts: WebhookEndpointOut`.
4. **Event list field is `event_types`, not `events`.** CORRECTED. Schemas
   `WebhookEndpointOut.event_types` and `WebhookEndpointCreateReq.event_types`;
   `src/api/types.ts: WebhookEndpointOut / WebhookEndpointCreateReq`.
5. **Status field is `enabled` (boolean), not `active`.** CORRECTED. Schema
   `WebhookEndpointOut.enabled` (default `true`); `src/api/types.ts`.
6. **`created_at`/`updated_at` are integer epoch seconds, not ISO-8601 strings.**
   CORRECTED. Schema `WebhookEndpointOut.created_at`/`updated_at` (`type: integer`);
   `src/api/types.ts: created_at: number`.
7. **There is no `secret_set` boolean; a nullable `secret` string exists instead.**
   CORRECTED. Schema `WebhookEndpointOut.secret` (`anyOf [string, null]`);
   `src/api/types.ts: secret: string | null`. `secretSet` is derived (`secret != null`).
8. **Detail endpoint param is `endpoint_id` (path `GET /ui/webhooks/{endpoint_id}`).**
   CORRECTED (draft used `{id}`). OpenAPI `GET /ui/webhooks/{endpoint_id}` (resp
   `200:WebhookEndpointOut`); `src/api/endpoints/webhooks.ts: getWebhookEndpoint`.
9. **Detail `404` for unknown id.** UNVERIFIED-ASSUMPTION. OpenAPI declares only
   `200`/`422` for this route; no `404` is documented. Kept as a defensive, non-load-
   bearing assumption.
10. **Create is `POST /ui/webhooks` with body `WebhookEndpointCreateReq` (required
    `url`, `event_types`).** VERIFIED. OpenAPI `POST /ui/webhooks`
    (req=`WebhookEndpointCreateReq`); schema `required: [url, event_types]`;
    `src/api/endpoints/webhooks.ts: createWebhookEndpoint`.
11. **Create returns `201`, not "200 or 201".** CORRECTED. OpenAPI `POST /ui/webhooks`
    resp=`201` only. The 201 body schema is empty (`{}`) but the web client
    deserializes `WebhookEndpointOut` (`api.post<WebhookEndpointOut>`).
12. **A one-time signing `secret` may be returned on create.** VERIFIED (shape) /
    PARTIALLY UNVERIFIED (timing). The `secret` field exists on `WebhookEndpointOut`;
    that it is populated specifically on create (and null elsewhere) is inferred from
    `rotateWebhookSecret` returning `{ secret }` and the field's nullability — treated
    as a best-effort assumption.
13. **Allowed event types are enumerable via `GET /ui/webhooks/event-types`.** VERIFIED
    (resolves OQ-2). OpenAPI `GET /ui/webhooks/event-types`;
    `src/api/endpoints/webhooks.ts: listWebhookEventTypes` → `{ event_types:
    WebhookEventType[] }`; `src/api/types.ts: WebhookEventType { type, description }`.
14. **Auth = `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) +
    cookies, on every request.** CORRECTED (draft omitted the Bearer token and implied
    CSRF only on unsafe verbs). `src/api/client.ts` sets `Authorization: Bearer
    <accessToken>` (lines ~157-160), `X-CSRF-Token` from `getCookie("ui_csrf")` on all
    requests (~167-171), and `credentials: "include"` (~183).
15. **`401` triggers one `POST /ui/session/refresh` then a single retry; second `401`
    logs out.** VERIFIED. `src/api/client.ts: refreshSession` (`POST
    /ui/session/refresh`) and the 401 branch (~194-237); refresh is de-duplicated via a
    shared `refreshPromise`.
16. **OpenAPI route params `user_sub` (query), `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`
    (headers) are optional and not set by a normal self-service web caller.** VERIFIED.
    All three are `required: false` with `anyOf [..., null]` on `GET/POST /ui/webhooks`;
    `src/api/client.ts` sets `X-IMPERSONATION-TOKEN` only when impersonation is active
    (~162-165) and never sets `user_sub`/`X-SESSION-ID` for self-service.
17. **Error envelope is FastAPI `detail`: string | `[{msg}]` (422) | `{code, ...}`.**
    VERIFIED. `src/api/client.ts: normalizeErrorDetail` and `mapAuthorizationError`;
    every webhooks route declares `422:HTTPValidationError` in the index.
18. **Out-of-scope ops (edit/delete/rotate/test/deliveries/dead-letters) exist on the
    backend.** VERIFIED. OpenAPI `PATCH/DELETE /ui/webhooks/{endpoint_id}`,
    `POST .../rotate-secret`, `POST .../test`, `GET .../deliveries`, `.../dead-letters*`
    (index lines for `/ui/webhooks/{endpoint_id}/*`). Correctly excluded by FR-6.
19. **Framework choices: Navigation-Compose type-safe routes, Hilt+KSP, Material 3,
    Room, Turbine, MockWebServer.** UNVERIFIED here (not derivable from backend/web
    sources); standard AND-port stack assumptions. Framework refs: Navigation Compose
    (developer.android.com/jetpack/compose/navigation), Hilt
    (developer.android.com/training/dependency-injection/hilt-android), Room
    (developer.android.com/training/data-storage/room). Labeled framework ref.

### Corrections made

- §2: auth description now includes the `Authorization: Bearer` token and notes CSRF is
  sent on all requests; clarified `user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` are
  optional/impersonation-only (claims 14, 16).
- §3 FR-2: path param `{id}` → `{endpoint_id}`; `active` → `enabled` (claims 5, 8).
- §3 FR-3: event source resolved to `GET /ui/webhooks/event-types`; body field
  `events` → `event_types`; success status fixed to `201` (claims 4, 11, 13).
- §4 `WebhooksApi`: list return type `WebhookListDto` → `List<WebhookEndpointDto>`;
  path `{id}` → `{endpointId}`; added `eventTypes()`; auth note corrected (claims 2, 8,
  13, 14).
- §5 API Contract: rewrote list payload to a bare array with corrected field names and
  integer epoch timestamps; removed `secret_set`; added `secret`; documented
  event-types endpoint; fixed create status to `201`; noted undeclared `404` (claims
  2-13, 17).
- §6 domain model: `active` → `enabled`; `secretSet` derived from `secret`; added
  `secret` and `description`; `createdAt` mapped from epoch seconds (claims 5, 6, 7).
- §7: `{id}` → `{endpoint_id}`; flagged `404` as undeclared/unverified (claims 8, 9).
- §13: OQ-1/OQ-2/OQ-3 marked resolved with pointers (claims 1-13).

### Open assumptions

- **Detail `404` semantics** (claim 9): not declared in OpenAPI; cannot be verified
  from sources. Handle defensively as a generic error.
- **`secret` populated only on create/rotation** (claim 12): inferred from field
  nullability and the rotate endpoint; the exact create-time population is not provable
  from the static schema (the 201 body schema is empty `{}`). Verify against a live
  create response during implementation.
- **Create 201 body is a full `WebhookEndpointOut`** (claim 11): the web client types
  it so, but the OpenAPI 201 schema is empty; confirm the live shape so the list can be
  refreshed/merged from the response rather than re-fetched.
- **Android framework stack** (claim 19): not sourced from backend/web; standard
  AND-port conventions, framework refs cited above.

## 17. Test Plan

Acceptance criteria referenced are §14 AC-1..AC-7. Each case names the CI/dev target.
"physical device (SM-A156U)" = Samsung Galaxy A15 5G, API 34, arm64-v8a; "emulator
test35" = headless AVD API 35 x86_64; "JVM/Robolectric" = local no-device.

- **TC-AND-398-01 — List happy path renders rows.** Type: contract/MockWebServer +
  ViewModel (Turbine). Target: JVM/Robolectric. Preconditions: MockWebServer enqueues
  `200` with a **bare array** of two `WebhookEndpointOut` objects (fields
  `endpoint_id`, `url`, `event_types`, `enabled`, `created_at` epoch int, `secret:
  null`). Steps: invoke `WebhooksRepository.list(forceRefresh=true)`; collect
  `WebhooksListViewModel.uiState`. Expected: GET path is exactly `/ui/webhooks`; DTO
  deserializes the bare array (no envelope); state goes `Loading → Content` with 2
  items; `createdAt` equals `Instant.ofEpochSecond(...)`; `enabled`/`events` mapped
  correctly. Traces: AC-1.

- **TC-AND-398-02 — Compose list renders endpoints ("webhooks render").** Type:
  Compose-UI. Target: emulator test35. Preconditions: `WebhooksListScreen` fed a fake
  `Content` state with 2 webhooks. Steps: assert two `WebhookRow`s display URL, event
  count/chips, and enabled/disabled status. Expected: both rows visible with correct
  URL and status text; tapping a row emits the detail nav event. Traces: AC-1.

- **TC-AND-398-03 — Empty state with create CTA.** Type: Compose-UI. Target: emulator
  test35. Preconditions: list returns `200` empty array → `Empty` state. Steps: render
  `WebhooksListScreen`. Expected: empty-state message + enabled "Create webhook"
  affordance; activating it emits the Create nav event. Traces: AC-2.

- **TC-AND-398-04 — Detail screen shows full config.** Type: ViewModel + Compose-UI.
  Target: JVM/Robolectric (VM) + emulator test35 (UI). Preconditions: cached list entry
  present for `endpoint_id=wh_x`. Steps: open `WebhookDetailViewModel` with that id via
  `SavedStateHandle`; render `WebhookDetailScreen`. Expected: shows URL, full
  `event_types` list, `enabled` flag, and creation time; when the id is absent from
  cache the VM fetches `GET /ui/webhooks/{endpoint_id}` (assert exact path incl.
  `endpoint_id`). Traces: AC-3.

- **TC-AND-398-05 — Create validation gating.** Type: ViewModel (Turbine). Target:
  JVM/Robolectric. Preconditions: fresh `CreateWebhookViewModel`. Steps: (a) set
  `url="http://x"` → expect `canSubmit=false`, `urlError` set (non-https rejected);
  (b) `url="https://ok.test/h"` but no events → `canSubmit=false`; (c) add one event →
  `canSubmit=true`. Expected: gating transitions as described; submit disabled until
  valid. Traces: AC-4.

- **TC-AND-398-06 — Create happy path round-trips + list refresh.** Type:
  contract/MockWebServer + ViewModel. Target: JVM/Robolectric. Preconditions:
  MockWebServer enqueues `201` returning the created `WebhookEndpointOut`, then a list
  `200` array including it. Steps: submit a valid form. Expected: request is `POST
  /ui/webhooks`, JSON body `{ "url": ..., "event_types": [...] }` (field name
  `event_types`), `Content-Type: application/json`; on `201` the VM navigates back and
  the list shows the new endpoint (write-through `upsertAll` + refresh). Traces: AC-4.

- **TC-AND-398-07 — Event-types metadata populates create chips.** Type:
  contract/MockWebServer + Compose-UI. Target: JVM/Robolectric (contract) + emulator
  test35 (UI). Preconditions: `GET /ui/webhooks/event-types` returns `{ event_types:
  [{type, description}, ...] }`. Steps: open create screen. Expected: request path is
  `/ui/webhooks/event-types`; one `FilterChip` per returned `type`; selecting toggles
  membership in `selectedEvents`. Traces: AC-4.

- **TC-AND-398-08 — `POST` carries CSRF + Bearer; 401 → single refresh → retry.**
  Type: contract/MockWebServer. Target: JVM/Robolectric. Preconditions: client
  configured with the AND-027 interceptor/authenticator; `ui_csrf` cookie + access
  token present; server enqueues `401`, then `200` for the retried list, and `200` for
  `POST /ui/session/refresh`. Steps: call `list()` (or `create()`). Expected: first
  request carries `Authorization: Bearer ...` and `X-CSRF-Token`; on `401` exactly one
  `POST /ui/session/refresh` is issued, then the original request is retried once and
  succeeds; no second refresh. Traces: AC-5.

- **TC-AND-398-09 — `POST` is never auto-retried; GETs use bounded retry.** Type:
  contract/MockWebServer + Repository. Target: JVM/Robolectric. Preconditions: server
  returns a transient `503` for create, and `503`-then-`200` for list. Steps: call
  `create()` then `list()`. Expected: `create()` surfaces an inline error after a
  single attempt (no auto-retry); `list()` retries within the bounded backoff (max 2)
  and succeeds. Traces: AC-5, AC-6.

- **TC-AND-398-10 — Offline/flaky-host fallback to stale cache; empty-cache error.**
  Type: Repository + ViewModel. Target: JVM/Robolectric. Preconditions: Room cache has
  prior webhooks; network call fails (simulate `ApiError(0)` / connection drop). Steps:
  (a) with populated cache, call `list(forceRefresh=true)`; (b) clear cache and repeat.
  Expected: (a) returns cached data, state `Content(isStale=true)` with "saved data"
  banner; (b) state `Error(retryable=true)` with a retry button that re-issues the GET.
  Traces: AC-6.

- **TC-AND-398-11 — 422 validation maps to field + form errors.** Type:
  contract/MockWebServer + ViewModel. Target: JVM/Robolectric. Preconditions: create
  returns `422 HTTPValidationError` with `detail=[{loc:["body","url"], msg:"invalid
  url"}]`. Steps: submit a form the server rejects. Expected: `ApiErrorMapper` produces
  `submitError`, and because `loc` ends in `url` the `urlError` field is populated; no
  navigation occurs. Traces: AC-4, AC-5.

- **TC-AND-398-12 — Secret shown once, never persisted; no URL/secret in logs.** Type:
  unit + instrumented. Target: JVM/Robolectric (redaction unit) + physical device
  (SM-A156U) for real logcat/clipboard. Preconditions: create response includes
  `secret`. Steps: complete a create; capture logcat over the flow; inspect Room and
  DataStore. Expected: `secret` and full `url` never appear in logcat (only a short id
  prefix); `secret` is not written to Room/DataStore; the one-time secret is shown
  in-session and copyable with a "store this now" warning. MUST run on the physical
  device to validate real logcat output and clipboard behavior. Traces: AC-7.

- **TC-AND-398-13 — Accessibility: list row + create chips + URL field semantics.**
  Type: Compose-UI (a11y). Target: emulator test35. Preconditions: list and create
  screens rendered. Steps: assert merged row `contentDescription` ("Webhook to {url},
  {n} events, {enabled|disabled}"); `FilterChip`s expose `Role.Checkbox` toggle
  semantics and ≥48dp targets; the URL field declares `KeyboardType.Uri` and announces
  validation errors via `semantics { error(...) }`; status conveyed by text/icon not
  color alone. Expected: all semantics/targets present. Traces: AC-1, AC-2, AC-4.

- **TC-AND-398-14 — End-to-end nav round-trip on real device + ABI/API check.** Type:
  instrumented/e2e. Target: physical device (SM-A156U). Preconditions: app built for
  arm64-v8a, API 34; MockWebServer or staging backing the calls. Steps: list → tap
  Create → fill valid form → submit → back to refreshed list containing the new
  endpoint; repeat list/detail navigation. Expected: full flow works on arm64/API 34
  with no crashes or ABI/serialization regressions vs the x86_64/API 35 emulator suite.
  Run on the physical device to catch arm64-vs-x86 / API-34-vs-35 differences. Traces:
  AC-1, AC-2, AC-3, AC-4.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (list renders) | TC-01, TC-02, TC-13, TC-14 |
| AC-2 (empty state + CTA) | TC-03, TC-13, TC-14 |
| AC-3 (detail view) | TC-04, TC-14 |
| AC-4 (create validation + round-trip) | TC-05, TC-06, TC-07, TC-11, TC-13, TC-14 |
| AC-5 (CSRF/Bearer, 401 refresh, paths/verbs/bodies) | TC-06, TC-08, TC-09, TC-11 |
| AC-6 (offline stale / empty-cache error) | TC-09, TC-10 |
| AC-7 (no secret/URL in logs; secret shown once) | TC-12 |
