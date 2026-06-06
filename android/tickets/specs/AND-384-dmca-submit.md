---
id: AND-384
title: DMCA submit
milestone: M8
epic: E50
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-388, AND-389]
---

# AND-384 — DMCA submit

## 1. Overview & Goal

Provide a native Android flow that lets an authenticated user file a DMCA
(Digital Millennium Copyright Act) takedown notice against infringing content
hosted on TestLogon. This ports the web reference `frontend/src/api/endpoints/dmca.ts`
into a typed Kotlin data layer plus a Compose UI that collects the legally
required fields (identification of the copyrighted work, identification of the
infringing material, claimant contact information, the good-faith and
accuracy/penalty-of-perjury statements, and an electronic signature) and POSTs
them to the FastAPI backend.

The acceptance bar from the backlog is narrow and concrete: **a DMCA request
submits.** Interpreted here: the user opens the DMCA form (standalone or
pre-targeted from content), fills the mandatory legal fields, submits, receives a
server-issued reference/case id, and sees a confirmed success state — with
deterministic validation, a non-retryable single POST, and graceful handling of
the unreliable dev backend. This ticket owns the `core-network` DTOs/`DmcaApi`,
the `core-data` repository, the `feature-trust` screen + form state, and the
wiring to launch it from content/profile overflow menus. ViewModel state
contracts and irreversible-action guards are shared across the epic and
formalized in **AND-388**; the test matrix is owned by **AND-389** but this
ticket ships its own first-pass unit and UI tests.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/dmca.ts` (authoritative endpoint
  paths + request body shape), `frontend/src/api/types.ts` (shared DTO field
  names), and the FastAPI OpenAPI document at `http://18.222.237.167:8000/openapi.json`
  (search tags `dmca` / `legal`). Field names below MUST be reconciled against
  `openapi.json` at implementation time; where the web client and OpenAPI differ,
  OpenAPI wins.
- **Dependency AND-027 — AuthApi (session endpoints):** supplies the
  cookie-based session, the persistent cookie jar, the `X-CSRF-Token` echo of the
  `ui_csrf` cookie, and the 401 → `POST /ui/session/refresh` → retry interceptor.
  DMCA submission is an authenticated, CSRF-protected mutation and reuses that
  OkHttp stack directly.
- **Sibling tickets:** AND-382 (block), AND-383 (report flows) — DMCA shares the
  E50 "embedded action launched from content overflow" UX pattern and the
  `feature-trust` module. AND-388 (ViewModels), AND-389 (tests).
- **Project conventions:** namespace `com.testlogon.android`; module layering
  `app -> feature-* -> core-*`; ViewModels expose `StateFlow<UiState>`; typed
  `ApiResult<T>`; FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Retrofit 2.11 +
  OkHttp 4.12 + Moshi 1.15, Coroutines/Flow, DataStore. minSdk 24 / target 35.

## 3. Functional Requirements

FR-1. **Entry points.** The DMCA form is reachable two ways:
(a) standalone from a "Report copyright infringement / File a DMCA notice" item
in Settings → Privacy & Safety; (b) pre-targeted from the overflow (`⋮`) menu of
a post, comment, profile, or media item, which prepopulates the infringing-URL /
content-reference fields and disables editing of the resolved target id.

FR-2. **Mandatory fields** (all required to enable Submit):
- Identification of the copyrighted work (`work_description`, free text).
- Identification of infringing material (`infringing_url` and/or
  `content_ref { content_type, content_id }`). At least one locator required.
- Claimant legal name (`claimant_name`).
- Claimant email (`claimant_email`, RFC-5322-ish format check).
- Claimant address (`claimant_address`, free text; required by statute).
- Optional claimant phone (`claimant_phone`).
- Good-faith statement checkbox (`good_faith_statement` must be `true`).
- Accuracy / penalty-of-perjury statement checkbox
  (`accuracy_statement` must be `true`).
- Electronic signature (`signature`, non-empty typed full name).

FR-3. **Client validation** runs before any network call: empty/whitespace
required fields, malformed email, both legal checkboxes unchecked, and a
signature that does not match `claimant_name` (a soft warning, not a hard block)
each surface inline `supportingText` errors. Submit is disabled until all hard
requirements pass.

FR-4. **Single submission.** Submit is a single, **non-idempotent** `POST`. The
button shows a loading state, is disabled while in flight, and is NOT
auto-retried on network failure (the user must explicitly retry to avoid
duplicate legal notices).

FR-5. **Success.** On `200/201` the screen transitions to a confirmation state
showing the server `reference` / `case_id` and a "We received your notice"
message; the form is cleared and locked. Back navigation returns to the origin.

FR-6. **Failure.** Validation (`422`), auth (`401`, after one refresh attempt),
rate-limit (`429`), and server/transport errors each map to a distinct,
human-readable message; the form retains entered values so the user can correct
and resubmit.

FR-7. **Draft persistence (best-effort).** Because the dev backend is unreliable,
the in-progress form (excluding signature + checkboxes, which must be re-affirmed)
is cached to DataStore keyed by target so a process death / submit failure does
not lose typed text.

## 4. Technical Design

Module placement: DTOs + `DmcaApi` in **core-network**; `DmcaRepository` +
draft DataStore in **core-data**; screen, form state, and ViewModel in
**feature-trust**; entry-point menu items live with their host features and call
a shared navigation route.

Navigation route (single-Activity Navigation-Compose):

```kotlin
// feature-trust/navigation/TrustRoutes.kt
const val DMCA_ROUTE = "dmca?contentType={contentType}&contentId={contentId}&url={url}"

fun NavController.navigateToDmca(
    contentType: String? = null,
    contentId: String? = null,
    url: String? = null,
)
```

DTOs (Moshi, `@JsonClass(generateAdapter = true)`):

```kotlin
// core-network/dmca/DmcaDtos.kt
@JsonClass(generateAdapter = true)
data class DmcaContentRef(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
)

@JsonClass(generateAdapter = true)
data class DmcaSubmitRequest(
    @Json(name = "work_description") val workDescription: String,
    @Json(name = "infringing_url") val infringingUrl: String?,
    @Json(name = "content_ref") val contentRef: DmcaContentRef?,
    @Json(name = "claimant_name") val claimantName: String,
    @Json(name = "claimant_email") val claimantEmail: String,
    @Json(name = "claimant_address") val claimantAddress: String,
    @Json(name = "claimant_phone") val claimantPhone: String?,
    @Json(name = "good_faith_statement") val goodFaithStatement: Boolean,
    @Json(name = "accuracy_statement") val accuracyStatement: Boolean,
    @Json(name = "signature") val signature: String,
)

@JsonClass(generateAdapter = true)
data class DmcaSubmitResponse(
    @Json(name = "case_id") val caseId: String?,
    @Json(name = "reference") val reference: String?,
    @Json(name = "status") val status: String?,        // e.g. "received"
    @Json(name = "created_at") val createdAt: String?, // ISO-8601
)
```

Retrofit API:

```kotlin
// core-network/dmca/DmcaApi.kt
interface DmcaApi {
    @POST("ui/dmca/takedown")
    suspend fun submitTakedown(
        @Body body: DmcaSubmitRequest,
    ): Response<DmcaSubmitResponse>
}
```

Repository (returns the project-standard `ApiResult<T>`; performs no retry):

```kotlin
// core-data/dmca/DmcaRepository.kt
interface DmcaRepository {
    suspend fun submit(request: DmcaSubmitRequest): ApiResult<DmcaSubmitResponse>
    suspend fun loadDraft(targetKey: String): DmcaDraft?
    suspend fun saveDraft(targetKey: String, draft: DmcaDraft)
    suspend fun clearDraft(targetKey: String)
}

@Singleton
class DefaultDmcaRepository @Inject constructor(
    private val api: DmcaApi,
    private val draftStore: DmcaDraftStore,           // DataStore-backed
    @IoDispatcher private val io: CoroutineDispatcher,
) : DmcaRepository
```

ViewModel + UI state:

```kotlin
// feature-trust/dmca/DmcaViewModel.kt
data class DmcaFormState(
    val workDescription: String = "",
    val infringingUrl: String = "",
    val contentRef: DmcaContentRef? = null,
    val claimantName: String = "",
    val claimantEmail: String = "",
    val claimantAddress: String = "",
    val claimantPhone: String = "",
    val goodFaith: Boolean = false,
    val accuracy: Boolean = false,
    val signature: String = "",
    val fieldErrors: Map<DmcaField, String> = emptyMap(),
) {
    val isSubmittable: Boolean get() = /* all hard validations pass */ false
}

sealed interface DmcaUiState {
    data class Editing(val form: DmcaFormState, val submitting: Boolean = false) : DmcaUiState
    data class Error(val form: DmcaFormState, val message: String, val kind: DmcaErrorKind) : DmcaUiState
    data class Submitted(val reference: String) : DmcaUiState
}

@HiltViewModel
class DmcaViewModel @Inject constructor(
    private val repository: DmcaRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<DmcaUiState>
    fun onFieldChanged(field: DmcaField, value: String)
    fun onToggle(field: DmcaField, checked: Boolean)
    fun submit()
}
```

Compose screen `DmcaSubmitScreen(state, onEvent)` renders a scrollable
Material 3 `Scaffold` with grouped sections (Copyrighted work, Infringing
material, Your contact info, Legal statements), `OutlinedTextField`s with
`supportingText` for errors, two `Checkbox` rows wrapping the verbatim statutory
statements, a signature field, and a primary `Button("Submit DMCA notice")`
gated on `isSubmittable`. The success state replaces the form with a
`DmcaConfirmation` composable showing the reference id and a Done button.

Hilt: a `DmcaNetworkModule` (`@Provides` `DmcaApi` from the shared
authenticated Retrofit) and `DmcaDataModule` (`@Binds` `DefaultDmcaRepository`).

## 5. API Contract

Endpoint (reconcile exact path/casing against `/openapi.json`; web client
`dmca.ts` is the cross-check):

`POST /ui/dmca/takedown`

Headers: session cookies (auto via cookie jar from AND-027) +
`X-CSRF-Token: <ui_csrf>` (auto via the CSRF interceptor). `Content-Type:
application/json`.

Request body:

```json
{
  "work_description": "Original photograph 'Sunset #4', registration VA-1-234-567",
  "infringing_url": "https://testlogon.app/p/abc123",
  "content_ref": { "content_type": "post", "content_id": "abc123" },
  "claimant_name": "Jane Doe",
  "claimant_email": "jane@example.com",
  "claimant_address": "123 Main St, Springfield, IL 62701, USA",
  "claimant_phone": "+1-555-0100",
  "good_faith_statement": true,
  "accuracy_statement": true,
  "signature": "Jane Doe"
}
```

Success `201 Created` (also accept `200`):

```json
{ "case_id": "dmca_01HY...", "reference": "DMCA-2026-000482", "status": "received", "created_at": "2026-06-05T14:21:09Z" }
```

Error `422 Unprocessable Entity` (FastAPI validation):

```json
{ "detail": [ { "loc": ["body", "claimant_email"], "msg": "value is not a valid email address", "type": "value_error.email" } ] }
```

Other error shapes per project convention: `detail` may also be a plain
`string` or `{ "code": "rate_limited", "message": "..." }`. The
`detail` mapper in `core-network` converts all three forms to a user message;
`422` field errors are routed to `DmcaFormState.fieldErrors` by matching the last
element of each `loc` array to a `DmcaField`.

## 6. Data & State Management

- **Source of truth:** `DmcaViewModel.uiState: StateFlow<DmcaUiState>`; the
  Compose screen is stateless and collects with
  `collectAsStateWithLifecycle()`.
- **Process-death survival:** field values are mirrored into `SavedStateHandle`;
  the two legal checkboxes and the signature are intentionally NOT restored and
  must be re-affirmed, so a restored draft can never be auto-submitted.
- **DataStore draft cache:** `DmcaDraftStore` (Preferences DataStore, file
  `dmca_drafts.preferences_pb`) keyed by `targetKey` (= `contentType:contentId`
  or `standalone`). Drafts hold only non-attestation text fields, are written
  debounced (~500 ms) on edit, and are cleared on successful submit (FR-7).
- **No Room.** DMCA is a fire-and-once mutation with no list/history surface in
  scope; there is no local cache table. A "my DMCA requests" list, if needed
  later, is out of scope and not owned here.
- **Caching policy:** the POST is never cached and never replayed from cache;
  the success `reference` lives only in `DmcaUiState.Submitted` for the screen
  lifetime.

## 7. Error Handling & Resilience

- **Timeouts:** the submit POST uses the shared OkHttp ~20s call timeout. On
  `SocketTimeout`/`IOException` the state becomes `Error(kind = Network)` with
  "Couldn't reach TestLogon. Your notice was not submitted — check your
  connection and try again." The form is preserved.
- **No automatic retry.** Bounded backoff retry is for **idempotent GETs only**.
  This POST is non-idempotent and a duplicate DMCA notice is a real harm, so
  retry is **manual** via an explicit "Try again" button; Submit is
  disabled while `submitting == true` to prevent double taps.
- **401 handling:** delegated to the AND-027 auth interceptor, which performs a
  single `POST /ui/session/refresh` then retries the original POST once. If it
  still returns `401`, surface `Error(kind = Auth)` "Your session expired. Sign
  in again to file this notice." and do not silently resubmit.
- **429:** `Error(kind = RateLimited)` "Too many requests — wait a moment and
  try again," honoring `Retry-After` if present to disable Submit for that span.
- **422:** field-level errors mapped to `fieldErrors`; if a `422` has no usable
  `loc`, fall back to a form-level banner.
- **Offline/stale:** the entry-point control remains enabled offline; failure is
  reported at submit time rather than blocking the form, so a user can compose a
  notice offline and submit when connectivity returns.

## 8. Security & Privacy

- **Transport:** the dev backend is **plaintext HTTP**; this is a known dev-only
  posture. The app MUST require HTTPS in release builds via
  `network_security_config.xml` (cleartext permitted only for the dev host).
- **CSRF:** every submit carries `X-CSRF-Token` echoing the `ui_csrf` cookie
  (AND-027 interceptor). A submit without a valid CSRF token must fail closed.
- **PII handling:** the request body contains real claimant identity and contact
  data (name, email, postal address, phone) and a legal signature. This data is
  NOT logged (see §10), NOT included in crash/analytics payloads, and the
  DataStore draft cache excludes the signature. Drafts are cleared on success and
  should be cleared on sign-out (hook into the AND-027 logout broadcast).
- **No screenshots redaction required**, but the signature field uses
  `KeyboardOptions(autoCorrect = false)` and is not persisted.
- **Legal integrity:** the two attestation booleans and the typed signature are
  mandatory and cannot be pre-filled or restored, ensuring the user affirms them
  each submission.

## 9. Accessibility & i18n

- All fields have programmatic labels; error `supportingText` is associated via
  `Modifier.semantics { error(message) }` so TalkBack announces validation
  failures. Checkbox rows expose `Role.Checkbox` and the full statutory text as
  the content description; tapping the row (not only the box) toggles state, with
  a touch target ≥ 48 dp.
- Submit button announces its disabled/loading state; on success, the
  confirmation is sent to the live region via `liveRegion = Assertive` so the
  reference id is read aloud.
- All visible strings (labels, the verbatim legal statements, errors, success
  copy) live in `feature-trust` `strings.xml` with no concatenation; the long
  legal statements are single resources to keep them translatable verbatim.
  Layout is RTL-safe via `start/end` modifiers. Dynamic type / font scaling is
  supported (no fixed text heights).

## 10. Telemetry & Logging

- **Events** (via the shared analytics façade, no PII): `dmca_form_opened`
  `{ source: "settings"|"content_overflow", has_target: Bool }`,
  `dmca_submit_attempted`, `dmca_submit_succeeded` `{ http_status }`,
  `dmca_submit_failed` `{ http_status, error_kind }`. The `reference`/`case_id`
  and any claimant fields are **never** attached.
- **Logging:** network logging redacts the request body for this endpoint —
  OkHttp `HttpLoggingInterceptor` is at `BASIC` (or body-redacted) for
  `ui/dmca/*` so claimant PII and signature never hit Logcat. Only method, path,
  and status code are logged.
- **Crash reporting:** the `DmcaSubmitRequest` instance is excluded from
  non-fatal breadcrumbs.

## 11. Testing Strategy

Unit (`core-network` / `core-data`, JUnit + MockWebServer + Moshi):
- `DmcaApi` serializes the full request body with correct snake_case JSON keys;
  optional null fields are omitted/serialized per Moshi config.
- `200`/`201` → `ApiResult.Success` with parsed `reference`/`case_id`.
- `422` with `detail` array → mapped field errors keyed by `loc` tail.
- `401` path exercises the AND-027 refresh-once-then-fail behavior (fake interceptor).
- `429` → `RateLimited`; `IOException`/timeout → `Network`; repository performs
  **zero** retries on the POST (assert single MockWebServer request).
- Draft store: save/load/clear round-trip; signature + checkboxes never persisted.

ViewModel (Turbine over `StateFlow`):
- Submit disabled until all hard validations pass; email and empty-field
  validation; both checkboxes required.
- `submit()` emits `Editing(submitting=true)` → `Submitted` on success and
  clears the draft; double-tap while submitting issues only one network call.
- Failure preserves the form and surfaces the correct `DmcaErrorKind`.

UI (Compose + `createAndroidComposeRule`, Hilt test):
- Filling all fields enables Submit; tapping shows loading then the confirmation
  with the reference id (backed by MockWebServer) — this is the literal backlog
  acceptance ("DMCA request submits").
- Pre-targeted entry locks the content-reference field.
- TalkBack semantics: error text and the assertive success announcement assert.

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-027** (AuthApi / session) — required for the
  authenticated cookie jar, CSRF header, and 401-refresh interceptor that this
  POST rides on. Cannot integration-test before AND-027 lands.
- **Shared module:** `feature-trust` is established alongside AND-382/AND-383;
  if this ticket is sequenced first within E50 it stands up the module skeleton.
- **Downstream / blocks:** **AND-388** (trust & safety ViewModels + irreversible
  -action guards) consolidates `DmcaUiState` patterns; **AND-389** (trust &
  safety tests) extends the test matrix. The first-pass tests in §11 ship here.
- **External:** confirm the exact `POST /ui/dmca/takedown` path and field schema
  against `/openapi.json` and `frontend/src/api/endpoints/dmca.ts` before coding
  the DTOs (see §13 OQ-1).

## 13. Risks & Open Questions

- **OQ-1 (path/schema).** The endpoint path and field names above are inferred
  from naming conventions; `dmca.ts` + `/openapi.json` are authoritative and may
  use e.g. `/ui/legal/dmca` or different field keys. Verify first; DTOs are a
  thin mechanical change once confirmed.
- **OQ-2 (attachments).** Some DMCA flows accept evidence files/screenshots.
  Backlog scope says "takedown submission" with no upload mention; file upload is
  **out of scope** unless `openapi.json` shows a required multipart field.
- **OQ-3 (auth requirement).** Does the backend allow anonymous DMCA notices?
  This ticket assumes authenticated submission (Deps: AND-027). If anonymous is
  supported, an unauthenticated entry path is a follow-up.
- **Risk-1 (duplicate notices).** Network ambiguity on a non-idempotent POST
  could double-file. Mitigated by no auto-retry + disabled-while-submitting; a
  server-side idempotency key would be more robust (raise with backend).
- **Risk-2 (dev backend flakiness).** ~20s timeouts can read as failure after a
  successful write; failure copy warns the notice may already be received before
  re-filing.

## 14. Acceptance Criteria

AC-1. From Settings → Privacy & Safety and from a content overflow menu, the user
can open the DMCA form; the content-targeted path prefills and locks the
content reference.
AC-2. Submit is disabled until all mandatory fields are valid, both legal
attestation checkboxes are checked, and a signature is entered.
AC-3. A valid submission issues exactly one `POST /ui/dmca/takedown` with cookies
+ `X-CSRF-Token`, and on `200/201` the UI shows a confirmation containing the
server `reference`/`case_id` (**"DMCA request submits"**).
AC-4. The POST is never auto-retried; double-tapping Submit produces a single
network call.
AC-5. `422`, `401` (after one refresh), `429`, and network/timeout errors each
produce a distinct user message and preserve entered form values.
AC-6. No claimant PII or signature appears in Logcat, analytics, or crash
breadcrumbs; the DataStore draft excludes the signature and checkboxes and is
cleared on success and on sign-out.
AC-7. Form fields, errors, and the success confirmation are accessible via
TalkBack and fully localized; checkbox rows have ≥48 dp targets.

## 15. Definition of Done

- `DmcaApi`, DTOs, `DmcaRepository` (+ draft store), `DmcaViewModel`, and
  `DmcaSubmitScreen` implemented in the correct modules under
  `com.testlogon.android`, wired via Hilt, reachable through `navigateToDmca`.
- Endpoint path and field schema verified against `/openapi.json` and `dmca.ts`;
  any deltas reflected in the DTOs.
- Unit, ViewModel, and UI tests from §11 pass in CI; the happy-path UI test
  asserts the rendered reference id.
- Network logging redaction for `ui/dmca/*` and release-build cleartext
  restriction verified.
- Strings externalized; accessibility checks (TalkBack labels, live-region
  success, touch targets) pass.
- Code review approved on branch `android-port`; no new lint/Detekt regressions;
  ticket demoed end-to-end against the dev backend.
