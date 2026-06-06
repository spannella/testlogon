---
id: AND-357
title: Syndicate open licensing
milestone: M7
epic: E46
priority: P2
size: M
status: draft
depends_on: [AND-356]
blocks: []
---

# AND-357 — Syndicate open licensing

## 1. Overview & Goal

Add an "open licensing" surface to the Syndicate feature: an authenticated user
viewing a syndicate can browse the syndicate's open license offers and register a
new open license against the syndicate's catalog. "Open licensing" here is the
syndicate-level mechanism by which a syndicate publishes content/IP under a
publicly-claimable license, and a member or eligible viewer registers (claims) a
license instance. This ticket delivers two concrete capabilities backed by the
backend `/ui/syndicates/*` license endpoints:

1. **List** existing open licenses for a syndicate (`register/list` read side).
2. **Register** a new open license (the mutating create side), with form input,
   CSRF-protected submission, optimistic insertion, and result feedback.

The feature lives in `feature-syndicate` (the module introduced by **AND-356**,
Syndicates) as a sub-screen reachable from the syndicate overview. It reuses the
syndicate session/networking plumbing already established: `AuthApi`/syndicate
Retrofit service, the persistent cookie jar, the CSRF interceptor, and the
401-refresh authenticator. AND-356 owns the syndicate overview/feed/treasury
views and the base `SyndicateApi`; this ticket extends that service with the
licensing endpoints and adds the licensing list + register screens.

Success means: the licensing list renders from `GET /ui/syndicates/{id}/licenses`,
registering a license issues a CSRF-protected `POST`, the new license appears in
the list on success (and rolls back on failure), and all of this is covered by
deterministic MockWebServer + ViewModel + Compose tests so the AC "Licensing flow
works" is provably satisfied.

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
  eligible for idempotent-GET backoff retry.
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, bounded backoff only for idempotent GETs, offline/stale UI
  states. Verify exact field names against `/openapi.json` at build time.
- Web reference: `frontend/src/api/endpoints/*.ts` (syndicate licensing
  endpoints) and `frontend/src/api/types.ts`. The JSON shapes below are the
  contract this ticket implements; reconcile names against OpenAPI before merge.

## 3. Functional Requirements

FR-1. From a syndicate context, the user can open an "Open licensing" screen
(reached from the syndicate overview built in AND-356) scoped to a `syndicateId`.

FR-2. On entry the screen calls `GET /ui/syndicates/{syndicateId}/licenses` and
shows loading → list. The list is paged via Paging 3 if the endpoint is
paginated, otherwise rendered as a bounded single-page list.

FR-3. Each license row shows: title/name, license type/SPDX-style identifier
(e.g. `CC-BY-4.0`), status (`open` | `claimed` | `expired`), the registrant (if
claimed), and created/updated time (relative).

FR-4. A "Register license" affordance opens a register form collecting the
fields the backend requires to create an open license (at minimum a license
`type` selection and an optional human label/notes; exact required set verified
against OpenAPI — see §13 Q1).

FR-5. Submitting the form issues `POST /ui/syndicates/{syndicateId}/licenses`
with `X-CSRF-Token`. On success the returned license is inserted at the top of
the list optimistically; on failure the optimistic row is removed and an error
is shown.

FR-6. Client-side validation: required fields must be non-empty and the selected
`type` must be one of the allowed values before the submit button is enabled.
Server-side validation errors (422) map to per-field inline messages.

FR-7. The list supports pull-to-refresh; refresh re-fetches and replaces the
list (server is source of truth, reconciling any optimistic rows).

FR-8. Empty state (no open licenses yet) shows an explanatory message plus a
prominent "Register license" call to action.

FR-9. Errors (network/offline, 401-after-refresh-failure, 403 CSRF, 404 syndicate
not found, 5xx, timeout) surface a non-blocking, retryable message and leave the
list in a consistent state.

## 4. Technical Design

Module: `feature-syndicate`. MVVM with Hilt; `StateFlow<UiState>`; typed
`ApiResult<T>`.

```kotlin
// core-model
enum class LicenseStatus { OPEN, CLAIMED, EXPIRED, UNKNOWN }

data class OpenLicense(
    val licenseId: String,
    val syndicateId: String,
    val title: String?,         // human label; may be null
    val type: String,           // e.g. "CC-BY-4.0", "MIT", "CUSTOM"
    val status: LicenseStatus,
    val registrantSub: String?, // who claimed it, if any
    val notes: String?,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class RegisterLicenseRequest(
    val type: String,
    val title: String? = null,
    val notes: String? = null,
)
```

```kotlin
// core-network — extends SyndicateApi (owned by AND-356)
interface SyndicateApi {
    // ... existing AND-356 feed / treasury / revenue-split methods ...

    @GET("ui/syndicates/{syndicateId}/licenses")
    suspend fun listLicenses(
        @Path("syndicateId") syndicateId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): Response<LicenseListDto>

    @POST("ui/syndicates/{syndicateId}/licenses")
    suspend fun registerLicense(
        @Path("syndicateId") syndicateId: String,
        @Body body: RegisterLicenseDto,
    ): Response<OpenLicenseDto>
}
```

Repository in `core-data` wraps the API, maps DTO → domain + `ApiResult<T>`:

```kotlin
class SyndicateLicensingRepository @Inject constructor(
    private val api: SyndicateApi,
    private val dispatchers: AppDispatchers,
) {
    suspend fun listLicenses(
        syndicateId: String,
        cursor: String? = null,
    ): ApiResult<LicensePage>                 // items + nextCursor

    suspend fun registerLicense(
        syndicateId: String,
        request: RegisterLicenseRequest,
    ): ApiResult<OpenLicense>

    fun allowedTypes(): List<String>          // static/whitelisted license types
}

data class LicensePage(val items: List<OpenLicense>, val nextCursor: String?)
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
        val licenses: List<OpenLicense> = emptyList(),
        val nextCursor: String? = null,
        val isLoadingMore: Boolean = false,
        val form: RegisterFormState = RegisterFormState(),
        val showRegister: Boolean = false,
        val isSubmitting: Boolean = false,
        val error: UiError? = null,
    )

    data class RegisterFormState(
        val type: String = "",
        val title: String = "",
        val notes: String = "",
        val fieldErrors: Map<String, String> = emptyMap(),
        val allowedTypes: List<String> = emptyList(),
    ) { val isValid: Boolean get() = type.isNotBlank() }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load()                                 // initial + retry
    fun refresh()                              // pull-to-refresh
    fun loadMore()                             // cursor pagination
    fun openRegister(); fun dismissRegister()
    fun onType(v: String); fun onTitle(v: String); fun onNotes(v: String)
    fun submitRegister()                       // validates then POSTs
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
    onLoadMore: () -> Unit,
    onOpenRegister: () -> Unit,
    onDismissRegister: () -> Unit,
    onType: (String) -> Unit,
    onTitle: (String) -> Unit,
    onNotes: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)
```

Navigation: register a `syndicateLicensing/{syndicateId}` route in the syndicate
nav graph (Navigation-Compose) introduced by AND-356; the register form is a
modal `ModalBottomSheet` (or full-screen dialog) within this route rather than a
separate destination, keeping `syndicateId` scope intact. The DTO→domain mapper
tolerates nulls (`title`, `registrantSub`, `notes`) and maps unknown `status`
strings to `LicenseStatus.UNKNOWN`.

## 5. API Contract

`GET /ui/syndicates/{syndicateId}/licenses?cursor=&limit=20` → 200:

```json
{
  "items": [
    {
      "license_id": "lic_01HX...",
      "syndicate_id": "syn_01HW...",
      "title": "Season 3 master",
      "type": "CC-BY-4.0",
      "status": "open",
      "registrant_sub": null,
      "notes": null,
      "created_at": "2026-06-01T14:02:11Z",
      "updated_at": "2026-06-05T09:31:44Z"
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ=="
}
```

`POST /ui/syndicates/{syndicateId}/licenses` (requires `X-CSRF-Token`) body:

```json
{ "type": "CC-BY-4.0", "title": "Season 3 master", "notes": "optional" }
```

→ 201 (or 200) with the created license:

```json
{
  "license_id": "lic_01HY...",
  "syndicate_id": "syn_01HW...",
  "title": "Season 3 master",
  "type": "CC-BY-4.0",
  "status": "open",
  "registrant_sub": null,
  "notes": "optional",
  "created_at": "2026-06-05T10:00:00Z",
  "updated_at": "2026-06-05T10:00:00Z"
}
```

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`):

```json
{ "detail": "Invalid CSRF token" }
{ "detail": [{ "loc": ["body", "type"], "msg": "field required" }] }
{ "detail": { "code": "license_type_not_allowed", "message": "..." } }
```

Status handling: 200/201 success; 401 → authenticator refresh-once-then-retry
(transparent); 403 → CSRF/forbidden surfaced as retryable error; 404 → syndicate
or endpoint not found, surfaced as terminal "not found"; 409 → conflict
(duplicate registration) mapped to a non-fatal message + refresh; 422 → map
`detail` array entries to per-field `fieldErrors` (by `loc` tail); 5xx / timeout
→ retryable error, list unchanged. Moshi DTOs use `@Json(name=...)` for
snake_case mapping. The `SyndicateApi` host service is owned by AND-356; field
names MUST be verified against `/openapi.json`.

## 6. Data & State Management

- No Room persistence in this ticket: license data is fetched on demand and held
  in `StateFlow` memory. (If AND-356 establishes a syndicate Room cache, a
  follow-up may add a `licenses` table; out of scope here.)
- Pagination: cursor-based via `next_cursor`; `loadMore()` appends `items` and
  updates `nextCursor`. If the endpoint is not paginated, `next_cursor` is null
  and `loadMore()` is a no-op. Paging 3 may back the list source if AND-356
  already wires a `PagingSource` pattern for syndicate lists; otherwise a simple
  cursor-append in the ViewModel is acceptable for this list's expected size.
- Optimistic register: on submit success, prepend the returned `OpenLicense` to
  `licenses`. On submit failure, no row is committed (the form stays open with
  the error). An optional in-flight placeholder may be shown while
  `isSubmitting`, removed on completion either way.
- Refresh replaces the entire list (server is source of truth) and reconciles by
  `licenseId` so a just-registered row is not duplicated.
- Form state lives in `RegisterFormState` inside `UiState`; `allowedTypes` is
  populated from `repo.allowedTypes()` (or from a `meta` field on the list
  response if the backend supplies one — see §13 Q1).

## 7. Error Handling & Resilience

- Timeouts ~20s (OkHttp config from core-network). The list GET is idempotent and
  MAY use the existing bounded-backoff retry for GETs; the register `POST` MUST
  NOT auto-retry (no duplicate license creation).
- 401: handled by the OkHttp authenticator (single `POST /ui/session/refresh`
  then retry). If refresh fails, the call returns 401 → map to "Session expired"
  and delegate re-auth to the existing auth flow.
- 403 (CSRF mismatch): surface "Couldn't verify your session, try again"; retry
  re-reads the `ui_csrf` cookie via the existing interceptor and re-issues.
- 409 duplicate: treat as "already registered", close the form, refresh the list
  so the existing license is shown.
- 422 validation: map `detail` entries to `fieldErrors` keyed by the last element
  of each `loc` (e.g. `type`); keep the form open with inline messages.
- Network offline: show an offline banner with Retry; keep the last-rendered list
  (clearly marked stale) rather than blanking the screen.
- Submit guard: the submit button is disabled while `isSubmitting` and while the
  form is invalid, preventing double-submit and empty payloads.

## 8. Security & Privacy

- All calls ride the existing authenticated cookie jar with `X-CSRF-Token`; no
  session tokens or cookies are logged or persisted by this feature.
- `registrant_sub` is a user identifier (PII-adjacent): never logged in release,
  never included in analytics payloads, never placed in crash breadcrumbs.
- The register `POST` is CSRF-protected and never auto-retried; destructive/state
  -changing intent is explicit (user taps Submit).
- License `notes`/`title` are user-entered free text: not logged verbatim; lengths
  bounded client-side before submit to avoid oversized payloads.
- Dev backend is plaintext HTTP; production must be HTTPS. This screen adds no new
  cleartext exemptions beyond the existing dev `network_security_config`.

## 9. Accessibility & i18n

- All strings in `feature-syndicate` `strings.xml`; no hardcoded text. Relative
  times via a locale-aware formatter (`DateUtils.getRelativeTimeSpanString`).
- License rows expose a merged `contentDescription` summarizing title, type,
  status, and registrant state (e.g. "Season 3 master, CC-BY-4.0, open").
- The register form: every field has an associated label and, on error, an
  accessible error description; the type selector is a labeled exposed dropdown;
  the submit button announces enabled/disabled state.
- Touch targets ≥ 48dp; the register bottom sheet is focus-trapped and TalkBack
  announceable; supports dynamic font scaling and dark theme via Material 3.
- RTL-safe layouts (start/end paddings, no hardcoded left/right); status pills use
  text + color, not color alone.

## 10. Telemetry & Logging

- Events (no PII; ids hashed or omitted): `syndicate_licenses_viewed`
  (`{syndicate_hash}`), `license_register_opened`,
  `license_registered` (`{type}`), `license_register_error` (`{type, http}`),
  `syndicate_licenses_load_error` (`{type}`).
- Logging via the project Timber wrapper; debug-only request/response metadata,
  never cookies, `X-CSRF-Token`, `registrant_sub`, or free-text `notes`.
- Error mapping records the normalized `UiError.type`
  (network/auth/csrf/validation/server) for triage, not raw `detail` strings that
  may contain identifiers.

## 11. Testing Strategy

- **MockWebServer (core-testing)**: enqueue `GET .../licenses` fixtures (empty,
  single page, paginated with `next_cursor`), `POST .../licenses` 201, and error
  responses (403 CSRF, 404, 409, 422 with `loc`, 500, timeout). Assert verbs,
  paths, that the `POST` carries `X-CSRF-Token`, and the request body shape.
- **ViewModel unit tests** (Turbine + coroutine test rule):
  - list maps DTO→domain; unknown status → `UNKNOWN`; nulls tolerated.
  - `loadMore()` appends the next page and updates `nextCursor`; no-op when null.
  - `submitRegister()` blocked when form invalid (no API call).
  - successful register prepends the returned license to the list and closes form.
  - failed register keeps form open, shows error, commits no row.
  - 422 maps to per-field `fieldErrors`.
  - refresh replaces list and de-dupes by `licenseId`.
- **Repository tests**: DTO→domain mapping, cursor paging, error envelope mapping
  (string / array-with-`loc` / object forms) → `ApiResult.Error` variants.
- **Compose UI test**: empty state shows CTA; opening register reveals the form;
  submit with valid input results in the new row appearing; submit is disabled
  for empty `type`. These directly exercise the AC "Licensing flow works"
  (register + list).
- Tests are deterministic (no real network); coverage focus matches the
  Acceptance Criteria.

## 12. Dependencies & Sequencing

- **Depends on AND-356** (Syndicates): provides the `feature-syndicate` module,
  the syndicate nav graph + overview entry point, and the base `SyndicateApi`
  over `/ui/syndicates/*`. Hard blocker. This ticket extends that service with
  the two licensing methods and adds the licensing route/screens.
- Transitively relies on AND-027's cookie-based `AuthApi` chain (cookie jar, CSRF
  interceptor, 401-refresh authenticator), assumed present via AND-356.
- Blocks: none currently tracked.
- Sequencing: add DTOs + mapper + `SyndicateApi` license methods first
  (MockWebServer + repository tested), then the ViewModel (unit tested), then the
  Compose list + register sheet + nav wiring, then the Compose UI test.

## 13. Risks & Open Questions

- Q1: Exact required fields and allowed `type` values for registering an open
  license — confirm against `/openapi.json` (is `type` an enum the server
  returns, or a free string?). `allowedTypes()` and validation depend on this.
- Q2: Is `GET .../licenses` paginated (cursor/limit) or a flat list? §6 handles
  both; confirm so `loadMore()` is wired correctly.
- Q3: Does register return 201 with the created entity, or 200/empty requiring a
  follow-up GET? The optimistic-prepend in §6 assumes the entity is returned;
  fall back to a refresh if not.
- Q4: Eligibility — can any authenticated viewer register, or only syndicate
  members? If 403 is membership-based, surface a clear "not eligible" message
  rather than a generic CSRF/forbidden error.
- Q5: Duplicate-registration semantics (409 vs idempotent 200) — confirm so the
  conflict handling in §7 aligns with backend behavior.
- Risk: unreliable dev host makes manual QA flaky; mitigated by MockWebServer
  coverage being the source of truth for correctness.

## 14. Acceptance Criteria

AC-1. Opening the syndicate licensing screen issues
`GET /ui/syndicates/{syndicateId}/licenses` and renders the returned licenses;
empty results show the explanatory empty state with a Register CTA. (MockWebServer
+ Compose UI test.)

AC-2. Registering a license issues `POST /ui/syndicates/{syndicateId}/licenses`
with `X-CSRF-Token` and the correct body, and on success the new license appears
at the top of the list. (MockWebServer + ViewModel + Compose UI test — satisfies
"Licensing flow works".)

AC-3. The register form blocks submission until required fields (`type`) are
valid; the submit control is disabled otherwise and issues no API call.
(ViewModel + UI test.)

AC-4. A 422 server validation response maps to per-field inline errors and leaves
the form open with entered values intact. (ViewModel + MockWebServer test.)

AC-5. A failed register (403/404/409/5xx/timeout) commits no list row, keeps the
list consistent, and surfaces a retryable message; the register `POST` is never
auto-retried. (MockWebServer test.)

AC-6. Pagination (when `next_cursor` present) loads further pages via `loadMore()`
without duplicating rows; pull-to-refresh replaces the list de-duped by
`licenseId`. (ViewModel test.)

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
- No cookie/CSRF/`registrant_sub`/free-text leakage in logs or telemetry; strings
  externalized; TalkBack and dynamic-type verified.
- Lint/detekt/ktlint clean; builds on `compileSdk 35` / AGP 8.7.3 / JDK 17 /
  Kotlin 2.0.21 with the Gradle 8.9 wrapper.
- PR on `android-port` references AND-357 and links AND-356.
