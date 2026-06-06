---
id: AND-398
title: Webhooks config (light)
milestone: M8
epic: E52
priority: P2
size: M
status: draft
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
- **Auth dependency (AND-027):** webhooks requests ride the persistent cookie jar
  plus the `ui_csrf` cookie echoed as `X-CSRF-Token`. On `401` the shared OkHttp
  authenticator/interceptor calls `POST /ui/session/refresh` once and retries. This
  ticket consumes that machinery and adds no new auth logic.
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
endpoint showing target URL, full list of subscribed event types, active flag,
creation timestamp, and (if present) a masked secret indicator. Detail data is taken
from the list payload where complete; otherwise it is fetched via
`GET /ui/webhooks/{id}`.

FR-3 — **Light create.** A create screen collects a target URL and a multi-select of
event types (the allowed set is taken from the list/me metadata or a static enum
fallback; see §13). Submitting issues `POST /ui/webhooks`. On success the user
returns to the list, which refreshes and shows the new endpoint. "Light" means: no
custom headers editor, no per-delivery retry policy UI, no manual secret entry — the
backend generates the signing secret.

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
    @GET("ui/webhooks")
    suspend fun list(): Response<WebhookListDto>

    @GET("ui/webhooks/{id}")
    suspend fun get(@Path("id") id: String): Response<WebhookDto>

    @POST("ui/webhooks")
    suspend fun create(@Body body: CreateWebhookRequest): Response<WebhookDto>
}
```

`X-CSRF-Token` is attached by the shared OkHttp interceptor for the unsafe `POST`;
the cookie jar supplies the session. No per-call header wiring is added here.

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

Base URL: `http://18.222.237.167:8000/`. All calls authenticated (cookies +
`X-CSRF-Token`).

**List** — `GET /ui/webhooks` → `200`

```json
{
  "webhooks": [
    {
      "id": "wh_01HX...",
      "url": "https://example.com/hooks/tl",
      "events": ["session.finalized", "mfa.verified"],
      "active": true,
      "secret_set": true,
      "created_at": "2026-05-12T18:04:11Z"
    }
  ]
}
```

**Detail** — `GET /ui/webhooks/{id}` → `200` returns a single object with the same
shape as a list element. `404` when the id is unknown.

**Create** — `POST /ui/webhooks`

```json
{ "url": "https://example.com/hooks/tl",
  "events": ["session.finalized"] }
```

→ `201` (or `200`) returns the created `WebhookDto` including server-generated `id`,
`created_at`, and `secret_set: true`. The signing secret value itself, if returned at
all, appears only in this create response (`secret` field) and is shown once.

**Error envelope** — FastAPI `detail`, mapped by the shared `ApiErrorMapper`:
`string`, `[{ "msg": ... }]` (422 validation), or `{ "code": ..., ... }`.

> Field names (`webhooks`/`url`/`events`/`active`/`secret_set`) are taken from the
> web `webhooks.ts`; confirm against `/openapi.json` before merge (§13). The DTO ↔
> domain mapping isolates any rename to `core-model`.

## 6. Data & State Management

**Domain model** (`core-model`):

```kotlin
data class Webhook(
    val id: String,
    val url: String,
    val events: List<String>,
    val active: Boolean,
    val secretSet: Boolean,
    val createdAt: Instant,
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
- **Retry:** the idempotent `GET /ui/webhooks` and `GET /ui/webhooks/{id}` are
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

- **OQ-1 (field names / path):** the exact path (`/ui/webhooks` vs nested under an
  account/org segment) and field names (`url` vs `target_url`, `events` vs
  `event_types`, `active` vs `enabled`) must be confirmed against `/openapi.json` and
  `webhooks.ts`. DTO mapping localizes the fix; resolve before merge.
- **OQ-2 (allowed event types):** is the set of subscribable events enumerated by the
  backend (e.g. via the create schema or a `/ui/webhooks/events` metadata call) or
  free-form? Fallback: a static enum mirrored from the web app, with a follow-up to
  source it dynamically.
- **OQ-3 (create response status & secret):** does `POST` return `200` or `201`, and
  does it include a one-time `secret`? UI must handle both status codes and the
  optional secret field.
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
