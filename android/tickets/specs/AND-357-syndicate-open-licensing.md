---
id: AND-357
title: Syndicate open licensing
milestone: M7
epic: E46
priority: P2
size: M
depends_on: [AND-356]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-357 — Syndicate open licensing

## 1. Overview & Goal

Add an "open licensing" surface to the Syndicate feature: an authenticated user
viewing a syndicate can browse the content the syndicate has registered under open
licensing and register a piece of content so it is auto-licensed to other members.
"Open licensing" here is a syndicate-level config (enable/disable + revenue/profit
terms) under which a member's **registered content** is automatically licensed to
every other member. Registering does NOT create a single claimable "license
instance"; it triggers the backend to mint auto-licenses (the response reports a
`licenses_created` count). [CORRECTED — see §16] This ticket delivers two concrete
capabilities backed by the backend
`/ui/syndicates/open-licensing/{syndicate_id}/*` endpoints (NOT
`/ui/syndicates/{id}/licenses`, which does not exist):

1. **List** the syndicate's open-licensing content via
   `GET /ui/syndicates/open-licensing/{syndicate_id}/content` (read side).
2. **Register** content for open licensing via
   `POST /ui/syndicates/open-licensing/{syndicate_id}/register` (the mutating
   side), with form input, CSRF-protected submission, and result feedback (the web
   client refetches the list on success rather than inserting a returned row).

The feature lives in `feature-syndicate` (the module introduced by **AND-356**,
Syndicates) as a sub-screen reachable from the syndicate overview. It reuses the
syndicate session/networking plumbing already established: `AuthApi`/syndicate
Retrofit service, the persistent cookie jar, the CSRF interceptor, and the
401-refresh authenticator. AND-356 owns the syndicate overview/feed/treasury
views and the base `SyndicateApi`; this ticket extends that service with the
licensing endpoints and adds the licensing list + register screens.

Success means: the content list renders from
`GET /ui/syndicates/open-licensing/{syndicate_id}/content`, registering content
issues a CSRF-protected `POST .../register` (200, body `{content_id, content_type}`),
the list refreshes to show the newly-registered content on success (the register
response carries only `{content_id, syndicate_id, licenses_created}`, not a full
row, so the screen refetches rather than optimistically prepending a returned
entity), and all of this is covered by deterministic MockWebServer + ViewModel +
Compose tests so the AC "Licensing flow works" is provably satisfied.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-syndicate` (owned by AND-356) → consumes
  `core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`.
- **AND-356** owns the `feature-syndicate` module, navigation entry for a
  syndicate, and the base `SyndicateApi` (`/ui/syndicates/*` feed, treasury,
  revenue-split). This ticket extends `SyndicateApi` with the licensing methods;
  it must not redefine or fork the service or duplicate the syndicate nav graph.
- **AND-027** (transitive via AND-356) established the cookie-based `AuthApi`
  session endpoints and the network chain (cookie jar, CSRF interceptor,
  401-refresh authenticator). The licensing endpoints ride that same chain.
- Cookie-based session: every request carries the session cookies +
  `X-CSRF-Token` echoed from the `ui_csrf` cookie. On `401`, the OkHttp
  authenticator performs `POST /ui/session/refresh` once then retries. The
  register `POST` is a mutation, requires the CSRF header, and is **not**
  eligible for idempotent-GET backoff retry. (CSRF read from the `ui_csrf` cookie
  and the single-refresh-then-retry-on-401 behavior are verified against the web
  client `src/api/client.ts`; see §16.)
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, bounded backoff only for idempotent GETs, offline/stale UI
  states. Verify exact field names against `/openapi.json` at build time.
- Web reference: `src/api/endpoints/syndicateOpenLicensing.ts` (the exact endpoint
  calls), `src/api/types.ts` (DTO interfaces), and the screens
  `src/pages/syndicates/SyndicateOpenLicensingTab.tsx`,
  `SyndicateOpenLicensingContentList.tsx`,
  `SyndicateOpenLicensingRegisterDialog.tsx`. The JSON shapes in §5 have been
  reconciled against these and against OpenAPI `components.schemas.*`; see §16.

## 3. Functional Requirements

FR-1. From a syndicate context, the user can open an "Open licensing" screen
(reached from the syndicate overview built in AND-356) scoped to a `syndicateId`.

FR-2. On entry the screen calls
`GET /ui/syndicates/open-licensing/{syndicateId}/content` and shows loading →
list. [CORRECTED path] This endpoint is **not paginated** (no cursor/limit
params; returns `{ items: [...] }`), so render a bounded single-page list. There
is no Paging 3 source. [CORRECTED — see §16]

FR-3. Each content row shows: `content_id`, `content_type` (one of `video` |
`music` | `image` | `post` | `broadcast` | `clip`), `creator_id`, status
(`exempt` → "Exempt" vs not-exempt → "Auto-licensed"), and `registered_at`
(epoch-seconds int, rendered as relative time). [CORRECTED — no SPDX type,
no `open/claimed/expired` status, no `registrant_sub`/`title`/`notes`; see §16]

FR-4. A "Register content" affordance opens a register form collecting exactly
the two fields the backend requires (`SyndicateOpenLicensingRegisterIn`):
`content_id` (string, 1–200 chars) and `content_type` (the fixed 6-value enum
above). [CORRECTED — there is no license `type`/label/notes input; see §16]

FR-5. Submitting the form issues
`POST /ui/syndicates/open-licensing/{syndicateId}/register` with `X-CSRF-Token`
and body `{ "content_id": ..., "content_type": ... }`. The response
(`SyndicateOpenLicensingRegistrationOut`) is `{ content_id, syndicate_id,
licenses_created }` — NOT a list row. On success, show the `licenses_created`
count and **refetch** the content list (the web client invalidates and refetches
rather than optimistically prepending a returned entity). On failure, keep the
form open and show an error. [CORRECTED — no optimistic-prepend of a returned
row; see §16]

FR-6. Client-side validation: `content_id` must be non-empty (trimmed) and
`content_type` must be one of the six allowed values before the submit button is
enabled. Server-side validation errors (422) map to per-field inline messages
keyed by the `loc` tail (`content_id` / `content_type`).

FR-7. The list supports pull-to-refresh; refresh re-fetches and replaces the
list (server is source of truth).

FR-8. Empty state (no content registered yet) shows an explanatory message (web:
"No content registered under open licensing yet.") plus a prominent "Register
content" call to action.

FR-9. Errors (network/offline, 401-after-refresh-failure, 403 forbidden/CSRF,
422 validation, 5xx, timeout) surface a non-blocking, retryable message and leave
the list in a consistent state. [NOTE: 404 and 409 are not documented for these
endpoints — the OpenAPI index lists only `200` and `422:HTTPValidationError`; see
§16 Open assumptions.]

## 4. Technical Design

Module: `feature-syndicate`. MVVM with Hilt; `StateFlow<UiState>`; typed
`ApiResult<T>`.

```kotlin
// core-model
// [CORRECTED] Domain models reflect the real SyndicateOpenLicensingContent /
// RegisterIn / RegistrationOut shapes — there is no SPDX type or open/claimed/
// expired status; "status" is just the exempt flag. See §16.
enum class ContentType { VIDEO, MUSIC, IMAGE, POST, BROADCAST, CLIP, UNKNOWN }

data class OpenLicensingContent(
    val contentId: String,
    val contentType: String,     // raw string; one of the 6 known values
    val creatorId: String,
    val exempt: Boolean,         // true → "Exempt", false → "Auto-licensed"
    val registeredAt: Instant,   // mapped from epoch-seconds Long
)

data class RegisterContentRequest(
    val contentId: String,       // 1..200 chars
    val contentType: String,     // must be one of ContentType (lowercase wire value)
)

// Register response: NOT a content row — just a summary counter.
data class RegistrationResult(
    val contentId: String,
    val syndicateId: String,
    val licensesCreated: Int,
)
```

```kotlin
// core-network — extends SyndicateApi (owned by AND-356)
// [CORRECTED] Real base path is /ui/syndicates/open-licensing/{syndicateId};
// list is the /content sub-resource (unpaginated); register is the /register
// sub-resource returning a RegistrationOut counter. See §16.
interface SyndicateApi {
    // ... existing AND-356 feed / treasury / revenue-split methods ...

    @GET("ui/syndicates/open-licensing/{syndicateId}/content")
    suspend fun listOpenLicensingContent(
        @Path("syndicateId") syndicateId: String,
    ): Response<OpenLicensingContentListDto>   // { items: [...] }, no cursor/limit

    @POST("ui/syndicates/open-licensing/{syndicateId}/register")
    suspend fun registerOpenLicensingContent(
        @Path("syndicateId") syndicateId: String,
        @Body body: RegisterContentDto,         // { content_id, content_type }
    ): Response<OpenLicensingRegistrationDto>    // { content_id, syndicate_id, licenses_created }

    // Optional (AND-356 may own config/enable/disable/terms); if this ticket
    // also reads config to gate the register affordance:
    @GET("ui/syndicates/open-licensing/{syndicateId}")
    suspend fun getOpenLicensingConfig(
        @Path("syndicateId") syndicateId: String,
    ): Response<OpenLicensingConfigDto>          // { syndicate_id, open_licensing_enabled, ... }
}
```

Repository in `core-data` wraps the API, maps DTO → domain + `ApiResult<T>`:

```kotlin
class SyndicateLicensingRepository @Inject constructor(
    private val api: SyndicateApi,
    private val dispatchers: AppDispatchers,
) {
    // [CORRECTED] No cursor/pagination; returns the full content list.
    suspend fun listContent(
        syndicateId: String,
    ): ApiResult<List<OpenLicensingContent>>

    // [CORRECTED] Returns the RegistrationResult counter, not a content row.
    suspend fun registerContent(
        syndicateId: String,
        request: RegisterContentRequest,
    ): ApiResult<RegistrationResult>

    // Fixed enum from the web client (CONTENT_TYPES), NOT a server-supplied list.
    fun allowedContentTypes(): List<String> =
        listOf("video", "music", "image", "post", "broadcast", "clip")
}
```

ViewModel:

```kotlin
@HiltViewModel
class SyndicateLicensingViewModel @Inject constructor(
    private val repo: SyndicateLicensingRepository,
    savedStateHandle: SavedStateHandle,       // syndicateId nav arg
) : ViewModel() {

    private val syndicateId: String = checkNotNull(savedStateHandle["syndicateId"])

    data class UiState(
        val isLoading: Boolean = false,
        val isRefreshing: Boolean = false,
        val content: List<OpenLicensingContent> = emptyList(),
        val form: RegisterFormState = RegisterFormState(),
        val showRegister: Boolean = false,
        val isSubmitting: Boolean = false,
        val lastLicensesCreated: Int? = null,  // surfaced on successful register
        val error: UiError? = null,
    )
    // [CORRECTED] No nextCursor/isLoadingMore — the /content endpoint is not paged.

    data class RegisterFormState(
        val contentId: String = "",
        val contentType: String = "post",      // web default
        val fieldErrors: Map<String, String> = emptyMap(),
        val allowedTypes: List<String> =
            listOf("video", "music", "image", "post", "broadcast", "clip"),
    ) { val isValid: Boolean get() = contentId.isNotBlank() && contentType in allowedTypes }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load()                                 // initial + retry
    fun refresh()                              // pull-to-refresh
    fun openRegister(); fun dismissRegister()
    fun onContentId(v: String); fun onContentType(v: String)
    fun submitRegister()                       // validates then POSTs, then refetches
    fun dismissError()
}
```

Composables (Material 3, `core-ui` components):

```kotlin
@Composable
fun SyndicateLicensingRoute(
    viewModel: SyndicateLicensingViewModel = hiltViewModel(),
    onBack: () -> Unit,
)

@Composable
fun SyndicateLicensingScreen(
    state: SyndicateLicensingViewModel.UiState,
    onRefresh: () -> Unit,
    onOpenRegister: () -> Unit,
    onDismissRegister: () -> Unit,
    onContentId: (String) -> Unit,
    onContentType: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)
// [CORRECTED] No onLoadMore — the list is unpaged.
```

Navigation: register a `syndicateLicensing/{syndicateId}` route in the syndicate
nav graph (Navigation-Compose) introduced by AND-356; the register form is a
modal `ModalBottomSheet` (or full-screen dialog) within this route rather than a
separate destination, keeping `syndicateId` scope intact. The DTO→domain mapper
maps `registered_at` (epoch-seconds int) to `Instant`, defaults `exempt` to false
when absent, and maps an unrecognized `content_type` string to
`ContentType.UNKNOWN` while preserving the raw string for display. [CORRECTED —
there are no `title`/`registrantSub`/`notes`/`status` fields to tolerate.]

## 5. API Contract

[CORRECTED §5 — the previous shapes (license_id/SPDX type/status/registrant_sub,
cursor pagination, 201 created-entity) were fabricated. The real contract from
OpenAPI `components.schemas.*` and `src/api/endpoints/syndicateOpenLicensing.ts`
follows. See §16 for per-claim citations.]

`GET /ui/syndicates/open-licensing/{syndicateId}/content` (no query params) → 200
(response schema is unnamed in OpenAPI; the web client types it as
`{ items: SyndicateOpenLicensingContent[] }`):

```json
{
  "items": [
    {
      "content_id": "vid_123",
      "content_type": "video",
      "creator_id": "usr_01HW...",
      "registered_at": 1748774400,
      "exempt": false
    }
  ]
}
```

`POST /ui/syndicates/open-licensing/{syndicateId}/register` (requires
`X-CSRF-Token`) body (`SyndicateOpenLicensingRegisterIn`; both fields required;
`content_id` 1..200 chars; `content_type` ∈ {video, music, image, post,
broadcast, clip}):

```json
{ "content_id": "vid_123", "content_type": "video" }
```

→ **200** (NOT 201) with `SyndicateOpenLicensingRegistrationOut` — a summary
counter, NOT a content row:

```json
{
  "content_id": "vid_123",
  "syndicate_id": "syn_01HW...",
  "licenses_created": 4
}
```

Related (config gating + exempt toggle; may be partly owned by AND-356):
`GET /ui/syndicates/open-licensing/{syndicateId}` → `SyndicateOpenLicensingConfigOut`
`{ syndicate_id, open_licensing_enabled, open_licensing_terms, enabled_at,
disabled_at }`; `POST .../exempt/{content_id}` and `DELETE .../exempt/{content_id}`
→ `SyndicateOpenLicensingExemptionOut` `{ content_id, syndicate_id, exempt,
revoked_count, licenses_created }`.

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`):

```json
{ "detail": "Invalid CSRF token" }
{ "detail": [{ "loc": ["body", "type"], "msg": "field required" }] }
{ "detail": { "code": "license_type_not_allowed", "message": "..." } }
```

Status handling: **200** success (register is 200, not 201 — [CORRECTED]); 401 →
authenticator refresh-once-then-retry (transparent, verified vs `client.ts`); 403
→ forbidden/CSRF surfaced as retryable error; 422 → map `detail` array entries to
per-field `fieldErrors` (by `loc` tail: `content_id` / `content_type`); 5xx /
timeout → retryable error, list unchanged. **404 and 409 are NOT documented for
these endpoints** (OpenAPI lists only `200` and `422` for both list and register),
so treat any 404/4xx/5xx defensively as a generic retryable/terminal error rather
than relying on specific duplicate-registration or not-found semantics — see §16
Open assumptions. [CORRECTED] Moshi DTOs use `@Json(name=...)` for snake_case
mapping. The `SyndicateApi` host service is owned by AND-356; field names verified
against OpenAPI `components.schemas.SyndicateOpenLicensing*`.

## 6. Data & State Management

- No Room persistence in this ticket: content data is fetched on demand and held
  in `StateFlow` memory. (If AND-356 establishes a syndicate Room cache, a
  follow-up may add an open-licensing content table; out of scope here.)
- Pagination: **none.** [CORRECTED] `GET .../content` takes no cursor/limit and
  returns the full `{ items: [...] }` set in one response; there is no
  `next_cursor`, no `loadMore()`, and no Paging 3 source.
- Register feedback: on submit success, capture `licenses_created` for a feedback
  message and **refetch** the content list (matches the web client, which
  invalidates the `open-licensing-content` query). [CORRECTED — there is no
  returned content row to prepend; the `RegistrationOut` is just a counter.] On
  submit failure, no list change is made and the form stays open with the error.
- Refresh replaces the entire list (server is source of truth). De-dupe naturally
  by `content_id` if a refetch overlaps a just-registered item.
- Form state lives in `RegisterFormState` inside `UiState`; `allowedTypes` is the
  fixed six-value `content_type` enum from `repo.allowedContentTypes()` (hardcoded
  to match the web client's `CONTENT_TYPES`; the server does not return a type
  list). [CORRECTED]

## 7. Error Handling & Resilience

- Timeouts ~20s (OkHttp config from core-network). The list GET is idempotent and
  MAY use the existing bounded-backoff retry for GETs; the register `POST` MUST
  NOT auto-retry (no duplicate license creation).
- 401: handled by the OkHttp authenticator (single `POST /ui/session/refresh`
  then retry). If refresh fails, the call returns 401 → map to "Session expired"
  and delegate re-auth to the existing auth flow.
- 403 (CSRF mismatch): surface "Couldn't verify your session, try again"; retry
  re-reads the `ui_csrf` cookie via the existing interceptor and re-issues.
- 409 duplicate: NOT documented by the backend for these endpoints (only 200/422).
  [CORRECTED] If the server nonetheless returns 409, treat it defensively as a
  non-fatal "already registered" message and refetch; do not depend on it.
- 422 validation: map `detail` entries to `fieldErrors` keyed by the last element
  of each `loc` (here `content_id` or `content_type`); keep the form open with
  inline messages. [CORRECTED field names]
- Network offline: show an offline banner with Retry; keep the last-rendered list
  (clearly marked stale) rather than blanking the screen.
- Submit guard: the submit button is disabled while `isSubmitting` and while the
  form is invalid, preventing double-submit and empty payloads.

## 8. Security & Privacy

- All calls ride the existing authenticated cookie jar with `X-CSRF-Token`; no
  session tokens or cookies are logged or persisted by this feature.
- `creator_id` is a user identifier (PII-adjacent): never logged in release,
  never included in analytics payloads, never placed in crash breadcrumbs.
  [CORRECTED — the field is `creator_id`; there is no `registrant_sub`.]
- The register `POST` is CSRF-protected and never auto-retried; destructive/state
  -changing intent is explicit (user taps Submit).
- `content_id` is user-entered text bounded to 1..200 chars client-side (matching
  the server `maxLength`) before submit to avoid oversized payloads.
  [CORRECTED — there are no free-text `notes`/`title` fields.]
- Dev backend is plaintext HTTP; production must be HTTPS. This screen adds no new
  cleartext exemptions beyond the existing dev `network_security_config`.

## 9. Accessibility & i18n

- All strings in `feature-syndicate` `strings.xml`; no hardcoded text. Relative
  times via a locale-aware formatter (`DateUtils.getRelativeTimeSpanString`).
- Content rows expose a merged `contentDescription` summarizing content id, type,
  creator, and exempt/auto-licensed status (e.g. "vid_123, video, by usr_01HW,
  auto-licensed"). [CORRECTED example to real fields.]
- The register form: both fields (`content_id`, `content_type`) have associated
  labels and, on error, an accessible error description; the `content_type`
  selector is a labeled exposed dropdown of the six allowed values; the submit
  button announces enabled/disabled state.
- Touch targets ≥ 48dp; the register bottom sheet is focus-trapped and TalkBack
  announceable; supports dynamic font scaling and dark theme via Material 3.
- RTL-safe layouts (start/end paddings, no hardcoded left/right); status pills use
  text + color, not color alone.

## 10. Telemetry & Logging

- Events (no PII; ids hashed or omitted): `syndicate_licenses_viewed`
  (`{syndicate_hash}`), `license_register_opened`,
  `content_registered` (`{content_type, licenses_created}`),
  `content_register_error` (`{content_type, http}`),
  `syndicate_licenses_load_error` (`{http}`). [CORRECTED — dimension is
  `content_type`, not an SPDX license `type`.]
- Logging via the project Timber wrapper; debug-only request/response metadata,
  never cookies, `X-CSRF-Token`, or `creator_id`. [CORRECTED — `registrant_sub`
  and `notes` do not exist; the PII-adjacent field is `creator_id`.]
- Error mapping records the normalized `UiError.type`
  (network/auth/csrf/validation/server) for triage, not raw `detail` strings that
  may contain identifiers.

## 11. Testing Strategy

- **MockWebServer (core-testing)** [CORRECTED paths/shapes]: enqueue
  `GET .../open-licensing/{id}/content` fixtures (empty `{items:[]}`, populated
  `{items:[...]}`), `POST .../open-licensing/{id}/register` **200** returning
  `{content_id, syndicate_id, licenses_created}`, and error responses (403, 422
  with `loc=["body","content_id"|"content_type"]`, 500, timeout). Assert verbs,
  the exact paths, that the `POST` carries `X-CSRF-Token`, and the request body
  `{content_id, content_type}`. (No paginated/`next_cursor` fixture — the list is
  unpaged.)
- **ViewModel unit tests** (Turbine + coroutine test rule):
  - list maps DTO→domain; `registered_at` epoch→`Instant`; unknown
    `content_type` → `UNKNOWN` (raw string preserved); `exempt` default false.
  - `submitRegister()` blocked when form invalid (no API call).
  - successful register surfaces `licenses_created`, closes the form, and triggers
    a content refetch (no optimistic prepend of a returned row).
  - failed register keeps form open, shows error, makes no list change.
  - 422 maps to per-field `fieldErrors` keyed by `content_id`/`content_type`.
  - refresh replaces list (de-dupe by `content_id`).
- **Repository tests**: DTO→domain mapping, `{items}` unwrap, error envelope
  mapping (string / array-with-`loc` / object-with-`code` forms) →
  `ApiResult.Error` variants.
- **Compose UI test**: empty state shows the explanatory message + Register CTA;
  opening register reveals the form; submit with a valid `content_id` +
  `content_type` causes the list to refetch and the registered content to appear;
  submit is disabled for empty `content_id`. These directly exercise the AC
  "Licensing flow works" (register + list).
- Tests are deterministic (no real network); coverage focus matches the
  Acceptance Criteria.

## 12. Dependencies & Sequencing

- **Depends on AND-356** (Syndicates): provides the `feature-syndicate` module,
  the syndicate nav graph + overview entry point, and the base `SyndicateApi`
  over `/ui/syndicates/*`. Hard blocker. This ticket extends that service with
  the two open-licensing methods (`.../open-licensing/{id}/content` and
  `.../open-licensing/{id}/register`) and adds the licensing route/screens.
- Transitively relies on AND-027's cookie-based `AuthApi` chain (cookie jar, CSRF
  interceptor, 401-refresh authenticator), assumed present via AND-356.
- Blocks: none currently tracked.
- Sequencing: add DTOs + mapper + `SyndicateApi` license methods first
  (MockWebServer + repository tested), then the ViewModel (unit tested), then the
  Compose list + register sheet + nav wiring, then the Compose UI test.

## 13. Risks & Open Questions

- Q1: [RESOLVED] Register requires exactly `content_id` (string 1..200) and
  `content_type` (a fixed free-string the server documents as one of video,
  music, image, post, broadcast, clip). It is NOT a server-returned enum list;
  `allowedContentTypes()` hardcodes the six values to match the web client.
  (`SyndicateOpenLicensingRegisterIn`; `SyndicateOpenLicensingRegisterDialog.tsx`.)
- Q2: [RESOLVED] `GET .../content` is a flat, unpaginated list (`{items:[...]}`,
  no cursor/limit). No `loadMore()`.
- Q3: [RESOLVED] Register returns **200** with `SyndicateOpenLicensingRegistrationOut`
  = `{content_id, syndicate_id, licenses_created}` — a counter, not the created
  entity. The screen refetches the content list on success (web invalidates the
  query); there is no optimistic-prepend of a returned row.
- Q4: [PARTIALLY OPEN] Eligibility is not expressed in OpenAPI; the web client
  only renders the register affordance when open licensing is enabled and (for
  terms/admin actions) when `isAdmin`. Membership/role enforcement is server-side
  and surfaces as 403. Treat 403 as a retryable forbidden error and, if a
  `detail.code` like `role_required*` is present, map it to a clearer message
  (the web client's `mapAuthorizationError` does this). See §16 Open assumptions.
- Q5: [RESOLVED as far as the contract allows] No 409 is documented (only 200/422).
  Duplicate handling is best-effort/defensive only.
- Risk: unreliable dev host makes manual QA flaky; mitigated by MockWebServer
  coverage being the source of truth for correctness.

## 14. Acceptance Criteria

AC-1. Opening the syndicate open-licensing screen issues
`GET /ui/syndicates/open-licensing/{syndicateId}/content` and renders the returned
content rows; empty results (`{items:[]}`) show the explanatory empty state with a
Register CTA. [CORRECTED path] (MockWebServer + Compose UI test.)

AC-2. Registering content issues
`POST /ui/syndicates/open-licensing/{syndicateId}/register` with `X-CSRF-Token`
and body `{content_id, content_type}` (response 200 with `licenses_created`), and
on success the list refetches and shows the registered content. [CORRECTED
path/body/flow — no optimistic top-insertion of a returned entity.]
(MockWebServer + ViewModel + Compose UI test — satisfies "Licensing flow works".)

AC-3. The register form blocks submission until required fields (`content_id`
non-empty and `content_type` ∈ the six allowed values) are valid; the submit
control is disabled otherwise and issues no API call. [CORRECTED fields]
(ViewModel + UI test.)

AC-4. A 422 server validation response maps to per-field inline errors
(`content_id`/`content_type`) and leaves the form open with entered values intact.
(ViewModel + MockWebServer test.)

AC-5. A failed register (403/422/5xx/timeout) makes no list change, keeps the list
consistent, and surfaces a retryable message; the register `POST` is never
auto-retried. [CORRECTED — 404/409 are undocumented; covered defensively.]
(MockWebServer test.)

AC-6. The content list is unpaged: it renders the full `{items}` set in one
response (no `loadMore()`/cursor). Pull-to-refresh re-fetches and replaces the
list, de-duped by `content_id`. [CORRECTED — pagination removed.] (ViewModel test.)

AC-7. List GET errors (offline/5xx) show a retryable banner and preserve any
previously rendered list as stale rather than blanking. (MockWebServer + UI test.)

## 15. Definition of Done

- `feature-syndicate` open-licensing list + register screen, ViewModel,
  repository, DTOs/mapper, and nav wiring implemented under
  `com.testlogon.android`.
- `SyndicateApi` license methods added (coordinated with AND-356) and consumed;
  no duplicate service or nav-graph definitions.
- All AC-1…AC-7 tests green; MockWebServer, ViewModel/repository unit, and at
  least one Compose UI test included and passing in CI.
- No cookie/CSRF/`creator_id`/`content_id` leakage in logs or telemetry; strings
  externalized; TalkBack and dynamic-type verified. [CORRECTED field names]
- Lint/detekt/ktlint clean; builds on `compileSdk 35` / AGP 8.7.3 / JDK 17 /
  Kotlin 2.0.21 with the Gradle 8.9 wrapper.
- PR on `android-port` references AND-357 and links AND-356.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT (Verified / Corrected / Unverified-assumption),
and the exact source pointer.

1. **List endpoint is `GET /ui/syndicates/open-licensing/{syndicate_id}/content`.**
   VERDICT: Corrected (spec originally said `GET /ui/syndicates/{id}/licenses`,
   which does not exist).
   SOURCE: OpenAPI `GET /ui/syndicates/open-licensing/{syndicate_id}/content`
   (op=list_content...); `src/api/endpoints/syndicateOpenLicensing.ts:
   listOpenLicensingContent`.

2. **List is unpaginated; takes no cursor/limit; returns `{ items: [...] }`.**
   VERDICT: Corrected (spec assumed cursor/`next_cursor`/Paging 3).
   SOURCE: OpenAPI index params for the `/content` op show only
   `syndicate_id,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` (no cursor/limit);
   `src/api/endpoints/syndicateOpenLicensing.ts: listOpenLicensingContent` types
   the response `{ items: SyndicateOpenLicensingContent[] }`.

3. **List item shape = `SyndicateOpenLicensingContent` `{content_id, content_type,
   creator_id, registered_at (int epoch), exempt (bool)}`.**
   VERDICT: Corrected (spec had `license_id, title, type(SPDX), status, registrant_sub,
   notes, created_at/updated_at` ISO strings).
   SOURCE: `src/api/types.ts: SyndicateOpenLicensingContent`;
   `src/pages/syndicates/SyndicateOpenLicensingContentList.tsx` (renders
   content_id, content_type, creator_id, exempt → "Exempt"/"Auto-licensed").

4. **Register endpoint is `POST /ui/syndicates/open-licensing/{syndicate_id}/register`.**
   VERDICT: Corrected (spec said `POST /ui/syndicates/{id}/licenses`).
   SOURCE: OpenAPI `POST /ui/syndicates/open-licensing/{syndicate_id}/register`
   (op=register...); `src/api/endpoints/syndicateOpenLicensing.ts:
   registerOpenLicensingContent`.

5. **Register request body = `SyndicateOpenLicensingRegisterIn` `{content_id
   (string 1..200), content_type}` where content_type ∈ {video, music, image,
   post, broadcast, clip}.**
   VERDICT: Corrected (spec had `{type, title, notes}`).
   SOURCE: OpenAPI `components.schemas.SyndicateOpenLicensingRegisterIn` (required
   content_id+content_type; content_id minLength 1/maxLength 200; content_type
   description "One of: video, music, image, post, broadcast, clip");
   `src/pages/syndicates/SyndicateOpenLicensingRegisterDialog.tsx`
   (`CONTENT_TYPES = ["video","music","image","post","broadcast","clip"]`).

6. **Register response = `SyndicateOpenLicensingRegistrationOut` `{content_id,
   syndicate_id, licenses_created}`, HTTP 200 (not 201), NOT a content row.**
   VERDICT: Corrected (spec returned a full license entity at 201 and prepended it).
   SOURCE: OpenAPI `components.schemas.SyndicateOpenLicensingRegistrationOut` and
   the index line `resp=200:SyndicateOpenLicensingRegistrationOut`;
   `src/api/types.ts: SyndicateOpenLicensingRegistration`.

7. **On register success the web client refetches the content list (does not
   insert a returned row).**
   VERDICT: Corrected/Verified (matches web behavior).
   SOURCE: `src/pages/syndicates/SyndicateOpenLicensingRegisterDialog.tsx`
   (`onSuccess` → toast `licenses_created` + `qc.invalidateQueries(["open-licensing-content", syndicateId])`).

8. **`allowedTypes` is a fixed client-side list of six content types, not a
   server-returned enum/whitelist.**
   VERDICT: Corrected.
   SOURCE: `src/pages/syndicates/SyndicateOpenLicensingRegisterDialog.tsx:
   CONTENT_TYPES`; no enum in `SyndicateOpenLicensingRegisterIn` (it is a plain
   string with a description).

9. **CSRF: every request carries `X-CSRF-Token` echoed from the `ui_csrf` cookie.**
   VERDICT: Verified.
   SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`).

10. **On 401, a single `POST /ui/session/refresh` is performed then the request is
    retried once; if refresh fails the user is logged out.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`refreshSession()` posts `/ui/session/refresh`;
    `refreshPromise` guards a single in-flight refresh; retry then
    `logout("session_expired")` on repeated 401).

11. **Error envelope is FastAPI `detail` (string | array of `{msg,loc}` | object
    with `code`); 422 validation maps by `loc` tail.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`;
    OpenAPI `422:HTTPValidationError` on both endpoints.

12. **Register POST is a state-changing mutation that must not auto-retry; list GET
    may use idempotent-GET backoff.**
    VERDICT: Unverified-assumption (Android-side network-policy decision; the web
    client does not auto-retry either, but Android backoff config is owned by
    core-network / AND-027 and not visible here). Reasonable and retained.
    SOURCE: framework ref — OkHttp Authenticator/retry semantics
    (https://square.github.io/okhttp/recipes/#handling-authentication-kt-java).

13. **Open licensing is config-gated (enable/disable + revenue/profit terms,
    admin-gated); register affordance shown only when enabled.**
    VERDICT: Verified (web behavior; relevant context for this screen).
    SOURCE: `src/pages/syndicates/SyndicateOpenLicensingTab.tsx` (Switch gated by
    `isAdmin`; `SyndicateOpenLicensingRegisterDialog` rendered only when
    `enabled`); OpenAPI `GET /ui/syndicates/open-licensing/{syndicate_id}` →
    `SyndicateOpenLicensingConfigOut` (`open_licensing_enabled`).

14. **Exempt/unexempt content actions exist (`POST`/`DELETE
    .../exempt/{content_id}` → `SyndicateOpenLicensingExemptionOut`).**
    VERDICT: Verified (out of core scope but informs the row "status" and possible
    owner actions).
    SOURCE: OpenAPI those two ops; `src/api/endpoints/syndicateOpenLicensing.ts:
    exemptOpenLicensingContent / removeOpenLicensingExemption`;
    `SyndicateOpenLicensingContentList.tsx` (owner-gated Exempt / Remove Exemption).

15. **Compose/Material 3, Hilt, MVVM `StateFlow`, Navigation-Compose.**
    VERDICT: Unverified-assumption (framework choices consistent with the wider
    Android port; no in-repo Android source to confirm).
    SOURCE: framework ref — Jetpack Compose / Navigation-Compose / Hilt
    (https://developer.android.com/jetpack/compose,
    https://developer.android.com/develop/ui/compose/navigation,
    https://developer.android.com/training/dependency-injection/hilt-android).

### Corrections made

- §1, §3 (FR-2..FR-8), §4, §5, §6, §11, §14 (AC-1, AC-2, AC-6): endpoint paths
  changed from `/ui/syndicates/{id}/licenses` to
  `/ui/syndicates/open-licensing/{id}/content` (list) and `.../register` (POST).
- Register body corrected `{type,title,notes}` → `{content_id, content_type}`
  (content_type enum of 6 values); response corrected to the
  `RegistrationOut` counter at HTTP 200 (was a full license entity at 201).
- Removed cursor pagination / `next_cursor` / `loadMore()` / Paging 3 (endpoint is
  unpaged); removed optimistic-prepend in favor of refetch-on-success.
- Domain/DTO models, ViewModel `UiState`/`RegisterFormState`, repository methods,
  and Composable signatures rewritten to the real fields (content_id,
  content_type, creator_id, exempt, registered_at).
- PII field corrected from `registrant_sub` → `creator_id` across §8, §10, §15;
  removed nonexistent free-text `notes`/`title` and SPDX `type` references in §3,
  §8, §9, §10.
- §5/§7/§13/§14: 404 and 409 demoted to undocumented/defensive (OpenAPI only
  documents 200 and 422 for these endpoints).

### Open assumptions

- **Eligibility/authorization for register** (any member vs admin/role) is not in
  OpenAPI; enforced server-side and surfaced as 403. We map 403 (and any
  `detail.code` of `role_required*`) defensively. (Q4.)
- **404/409 behavior**: not documented; handled generically rather than with
  specific not-found/duplicate semantics. (Q5.)
- **Android network/backoff policy** (idempotent-GET retry, ~20s timeout) is owned
  by core-network/AND-027 and not present in these sources; treated as inherited.
- **Framework choices** (Compose/Hilt/Navigation/MockWebServer/Turbine) cannot be
  confirmed against in-repo Android code (none provided); standard for the port.
- **`/content` response is unnamed in OpenAPI**; the `{items:[...]}` envelope and
  item shape are taken from the web client types, which are authoritative for the
  client contract but not independently schema-named on the backend.

## 17. Test Plan

Test targets: JVM = JVM unit/Robolectric (local, no device); EMU = headless
emulator AVD `test35` (x86_64, Android 15 / API 35); DEV = physical Samsung Galaxy
A15 5G (SM-A156U, API 34, arm64-v8a). MockWebServer/contract and ViewModel/repo
unit tests run on JVM; Compose-UI and instrumented tests run on EMU unless a case
needs real hardware/ABI behavior, in which case it runs on DEV.

- **TC-AND-357-01 — List happy path renders content rows.**
  Type: contract/MockWebServer + ViewModel (JVM).
  Target: JVM. Preconditions: MockWebServer enqueues 200
  `{items:[{content_id:"vid_123",content_type:"video",creator_id:"usr_1",registered_at:1748774400,exempt:false}]}`.
  Steps: call `load()`. Expected: a single `GET
  /ui/syndicates/open-licensing/{id}/content` (no query params); state.content has
  1 item mapped (epoch→Instant, exempt=false → "Auto-licensed"); isLoading false.
  Traces: AC-1, AC-6.

- **TC-AND-357-02 — Empty state shows explanatory message + Register CTA.**
  Type: Compose-UI (EMU).
  Target: EMU. Preconditions: repo returns empty list (`{items:[]}`).
  Steps: render `SyndicateLicensingScreen` with empty content. Expected: empty
  message ("No content registered under open licensing yet.") and an enabled
  "Register content" CTA are displayed; no rows. Traces: AC-1.

- **TC-AND-357-03 — Register happy path: POST body, CSRF header, refetch.**
  Type: contract/MockWebServer + ViewModel (JVM).
  Target: JVM. Preconditions: MockWebServer enqueues 200
  `{content_id:"vid_9",syndicate_id:"syn_1",licenses_created:3}` for the POST, then
  a populated `{items:[...vid_9...]}` for the follow-up GET; a `ui_csrf` cookie is
  present in the jar. Steps: set form contentId="vid_9", contentType="video";
  `submitRegister()`. Expected: exactly one `POST
  /ui/syndicates/open-licensing/{id}/register` with body
  `{"content_id":"vid_9","content_type":"video"}` and header `X-CSRF-Token`
  present; on 200, form closes, `lastLicensesCreated==3`, and a follow-up GET
  refetches the list so vid_9 appears. No optimistic row inserted before the GET.
  Traces: AC-2.

- **TC-AND-357-04 — Submit disabled / blocked until form valid.**
  Type: ViewModel unit (JVM) + Compose-UI (EMU).
  Target: JVM + EMU. Preconditions: empty form. Steps: assert `form.isValid==false`
  with blank contentId; call `submitRegister()`. Expected: no API call is made;
  in UI the submit button is disabled until contentId is non-empty AND contentType
  is one of the six allowed values. Traces: AC-3.

- **TC-AND-357-05 — 422 validation maps to per-field errors, form retained.**
  Type: contract/MockWebServer + ViewModel (JVM).
  Target: JVM. Preconditions: POST returns 422
  `{"detail":[{"loc":["body","content_id"],"msg":"field required"}]}`.
  Steps: submit. Expected: `form.fieldErrors["content_id"]` set from `msg`; form
  stays open with entered values intact; no list change. Traces: AC-4.

- **TC-AND-357-06 — Register failure (403) makes no list change, retryable, no
  auto-retry.**
  Type: contract/MockWebServer + ViewModel (JVM).
  Target: JVM. Preconditions: POST returns 403 `{"detail":"Permission denied"}`.
  Steps: submit. Expected: exactly ONE POST is sent (no automatic retry of the
  mutation); state shows a retryable error; content list unchanged; form stays
  open. Traces: AC-5.

- **TC-AND-357-07 — Register failure (500 / timeout) handled defensively.**
  Type: contract/MockWebServer + ViewModel (JVM).
  Target: JVM. Preconditions: POST returns 500, then a separate run with a socket
  timeout (~20s, simulated via MockWebServer `setBodyDelay`/no-response).
  Steps: submit. Expected: mutation not auto-retried; retryable error surfaced;
  list consistent. (404/409 are undocumented; if encountered, mapped to a generic
  retryable error.) Traces: AC-5.

- **TC-AND-357-08 — Mapper: unknown content_type and exempt rendering.**
  Type: ViewModel/repo unit (JVM).
  Target: JVM. Preconditions: list fixture with `content_type:"hologram"` and
  `exempt:true`. Steps: map DTO→domain. Expected: raw string preserved for
  display, `ContentType.UNKNOWN` resolved; exempt row labeled "Exempt".
  Traces: AC-1, AC-6.

- **TC-AND-357-09 — Pull-to-refresh replaces list, de-dupes by content_id.**
  Type: ViewModel unit (JVM).
  Target: JVM. Preconditions: initial list [vid_1]; refresh returns [vid_1, vid_2].
  Steps: `refresh()`. Expected: list replaced with exactly [vid_1, vid_2] (no
  duplicate vid_1); a fresh GET issued. Traces: AC-6.

- **TC-AND-357-10 — List GET error preserves stale list + retryable banner.**
  Type: contract/MockWebServer + Compose-UI (JVM + EMU).
  Target: JVM (logic) + EMU (UI). Preconditions: first GET 200 populated; second
  GET (refresh) 500. Steps: load, then refresh. Expected: previously rendered rows
  remain visible (marked stale), a retryable banner appears, screen not blanked.
  Traces: AC-7.

- **TC-AND-357-11 — Offline path on the flaky dev host.**
  Type: instrumented/e2e (DEV).
  Target: **DEV (physical device — MUST)**: exercises real radio/connectivity and
  the unreliable plaintext dev host `http://18.222.237.167:8000`. Preconditions:
  app pointed at dev backend; device airplane mode toggled. Steps: open the screen
  offline, then re-enable network and tap Retry. Expected: offline banner with
  Retry shown; no crash; on reconnect the list loads. Note: run on DEV because it
  needs real network transitions and cleartext-HTTP dev config behavior on API 34
  / arm64. Traces: AC-7.

- **TC-AND-357-12 — Security: CSRF header presence + no PII/secret leakage in logs.**
  Type: contract/MockWebServer + unit (JVM).
  Target: JVM. Preconditions: register submitted with `ui_csrf` cookie set; Timber
  test tree capturing logs. Steps: submit, inspect captured request and logs.
  Expected: request carries `X-CSRF-Token`; logs contain no cookie values, no
  `X-CSRF-Token` value, and no `creator_id`/`content_id` in release-mode logging.
  Traces: AC-2, AC-5.

- **TC-AND-357-13 — Accessibility: row contentDescription, labeled form,
  TalkBack/dynamic type.**
  Type: Compose-UI / instrumented accessibility (EMU; spot-check DEV).
  Target: EMU. Preconditions: populated list + open register sheet. Steps: run
  Compose semantics assertions; toggle large font scale. Expected: each row has a
  merged contentDescription (content_id, content_type, creator, exempt/auto-licensed
  status); both form fields are labeled and announce errors; submit announces
  enabled/disabled; touch targets ≥48dp; layout holds at large font scale.
  Traces: AC-1, AC-3.

- **TC-AND-357-14 — Register affordance gated by open_licensing_enabled config.**
  Type: ViewModel + Compose-UI (JVM + EMU).
  Target: JVM + EMU. Preconditions: config GET returns
  `open_licensing_enabled:false` then `true`. Steps: load screen for each.
  Expected: when disabled, the Register CTA is hidden/disabled and a "disabled"
  status is shown; when enabled, the CTA is available. (Mirrors web Tab gating.)
  Traces: AC-2 (precondition), AC-1.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-08, TC-13, TC-14 |
| AC-2 | TC-03, TC-12, TC-14 |
| AC-3 | TC-04, TC-13 |
| AC-4 | TC-05 |
| AC-5 | TC-06, TC-07, TC-12 |
| AC-6 | TC-01, TC-08, TC-09 |
| AC-7 | TC-10, TC-11 |
