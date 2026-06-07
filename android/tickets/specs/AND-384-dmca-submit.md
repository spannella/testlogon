---
id: AND-384
title: DMCA submit
milestone: M8
epic: E50
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Dependency AND-027 — AuthApi (session endpoints):** supplies the session
  transport, the persistent cookie jar, the `X-CSRF-Token` echo of the
  `ui_csrf` cookie, and the 401 → `POST /ui/session/refresh` → retry interceptor
  (path **verified**: `POST /ui/session/refresh`, `openapi.index.txt` line 1847).
  DMCA submission is an authenticated, CSRF-protected mutation and reuses that
  OkHttp stack directly. **Corrected:** the web client (`src/api/client.ts`) is
  not purely cookie-based — it sends BOTH `Authorization: Bearer <accessToken>`
  (from its auth store) AND credentials/cookies (`credentials: "include"`), and
  echoes the `ui_csrf` cookie via `X-CSRF-Token`. The Android port must mirror
  whatever AND-027 standardizes (cookie jar and/or bearer); do not assume cookies
  alone. Note the web 401-refresh only fires when the user is already
  authenticated — an unauthenticated 401 propagates directly.
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
a post, comment, profile, or media item, which prepopulates `content_url`,
`content_type`, and `content_id`. **Unverified-assumption:** the web reference
(`src/pages/dmca/DmcaClaimForm.tsx`) exposes ONLY the standalone form — there is
no content-overflow entry point and the form does not collect `content_id` (it
sends `content_url` + a `content_type` dropdown defaulting to `"other"`). The
pre-targeted entry path and `content_id` prefill are an Android-only design
addition; the backend `DmcaClaimIn.content_id` field exists and is optional, so
this is schema-compatible but not exercised by the web client.

FR-2. **Mandatory fields** — field names CORRECTED against `DmcaClaimIn`
(`openapi.pretty.json` / `src/api/endpoints/dmca.ts`). The `DmcaClaimIn.required`
set is: `claimant_name`, `claimant_email`, `claimant_address`, `content_url`,
`original_work_description`, `sworn_statement`, `good_faith_belief`, `signature`.
- Identification of the copyrighted work (`original_work_description`, free text;
  **server minLength 20, maxLength 5000** — was incorrectly `work_description`).
- Identification of infringing material: **`content_url` (REQUIRED string,
  minLength 5, maxLength 2000)** plus `content_type` (enum, defaults `"other"`)
  and optional `content_id` (string, default `""`). **Corrected:** there is no
  nested `content_ref` object and no `infringing_url` field; `content_url` is a
  flat required URL string and `content_type`/`content_id` are flat siblings.
  `content_type` enum values: `feed_post | feed_media | message_media | video |
  other`.
- Claimant legal name (`claimant_name`, minLength 2, maxLength 256).
- Claimant email (`claimant_email`, minLength 5, maxLength 320; client-side
  format check; the web app uses `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`).
- Claimant address (`claimant_address`, minLength 10, maxLength 1000).
- Optional claimant phone (`claimant_phone`, maxLength 30, default `""`).
- Sworn statement checkbox (**`sworn_statement`** must be `true` — was
  incorrectly `accuracy_statement`).
- Good-faith belief checkbox (**`good_faith_belief`** must be `true` — was
  incorrectly `good_faith_statement`).
- Electronic signature (`signature`, minLength 2, maxLength 256).

FR-3. **Client validation** runs before any network call: empty/whitespace
required fields, malformed email, both legal checkboxes unchecked, and a
signature that does not match `claimant_name` (a soft warning, not a hard block)
each surface inline `supportingText` errors. Submit is disabled until all hard
requirements pass.

FR-4. **Single submission.** Submit is a single, **non-idempotent** `POST`. The
button shows a loading state, is disabled while in flight, and is NOT
auto-retried on network failure (the user must explicitly retry to avoid
duplicate legal notices).

FR-5. **Success.** The endpoint returns **`201 Created`** with
`DmcaClaimCreateOut`. **Corrected:** the response has NO `reference` and NO
`case_id` field — it is `{ ok: bool, claim_id: string, status: string,
content_removed: bool, strike_number: int, created_at: int (epoch seconds) }`.
The confirmation state shows the server **`claim_id`** (and may surface `status`
and `content_removed`) and a "We received your notice" message; the form is
cleared and locked. Back navigation returns to the origin. (Web reference only
shows a success toast and navigates home; displaying `claim_id` is an app-side
enhancement and is unverified against the web UI.)

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

DTOs below are CORRECTED to match `DmcaClaimIn` / `DmcaClaimCreateOut`
(`openapi.pretty.json`, schemas `DmcaClaimIn` lines 28803-28887,
`DmcaClaimCreateOut` lines 28723-28760; cross-checked with
`src/api/endpoints/dmca.ts`). Flat `content_url`/`content_type`/`content_id`
(no nested object); response uses `claim_id` and integer epoch `created_at`.

```kotlin
// core-network/dmca/DmcaDtos.kt
@JsonClass(generateAdapter = true)
data class DmcaClaimRequest(
    @Json(name = "claimant_name") val claimantName: String,
    @Json(name = "claimant_email") val claimantEmail: String,
    @Json(name = "claimant_address") val claimantAddress: String,
    @Json(name = "claimant_phone") val claimantPhone: String? = null,
    @Json(name = "content_url") val contentUrl: String,
    @Json(name = "content_type") val contentType: String = "other", // enum: feed_post|feed_media|message_media|video|other
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "original_work_description") val originalWorkDescription: String,
    @Json(name = "sworn_statement") val swornStatement: Boolean,
    @Json(name = "good_faith_belief") val goodFaithBelief: Boolean,
    @Json(name = "signature") val signature: String,
)

@JsonClass(generateAdapter = true)
data class DmcaClaimCreateResponse(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "claim_id") val claimId: String,
    @Json(name = "status") val status: String,
    @Json(name = "content_removed") val contentRemoved: Boolean,
    @Json(name = "strike_number") val strikeNumber: Int,
    @Json(name = "created_at") val createdAt: Long, // epoch seconds (integer), NOT ISO-8601
)
```

Retrofit API:

```kotlin
// core-network/dmca/DmcaApi.kt
// CORRECTED path: POST /v1/dmca/claims (was /ui/dmca/takedown — that path does
// not exist). Verified: openapi.index.txt line 2193, op=submit_dmca_claim,
// req=DmcaClaimIn, resp=201:DmcaClaimCreateOut;422:HTTPValidationError.
interface DmcaApi {
    @POST("v1/dmca/claims")
    suspend fun submitClaim(
        @Body body: DmcaClaimRequest,
    ): Response<DmcaClaimCreateResponse>
}
```

Repository (returns the project-standard `ApiResult<T>`; performs no retry):

```kotlin
// core-data/dmca/DmcaRepository.kt
interface DmcaRepository {
    suspend fun submit(request: DmcaClaimRequest): ApiResult<DmcaClaimCreateResponse>
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
    val originalWorkDescription: String = "",
    val contentUrl: String = "",
    val contentType: String = "other",   // enum default per DmcaClaimIn
    val contentId: String? = null,
    val claimantName: String = "",
    val claimantEmail: String = "",
    val claimantAddress: String = "",
    val claimantPhone: String = "",
    val swornStatement: Boolean = false,
    val goodFaithBelief: Boolean = false,
    val signature: String = "",
    val fieldErrors: Map<DmcaField, String> = emptyMap(),
) {
    val isSubmittable: Boolean get() = /* all hard validations pass */ false
}

sealed interface DmcaUiState {
    data class Editing(val form: DmcaFormState, val submitting: Boolean = false) : DmcaUiState
    data class Error(val form: DmcaFormState, val message: String, val kind: DmcaErrorKind) : DmcaUiState
    data class Submitted(val claimId: String, val status: String, val contentRemoved: Boolean) : DmcaUiState
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
`DmcaConfirmation` composable showing the server `claim_id` and a Done button.

Hilt: a `DmcaNetworkModule` (`@Provides` `DmcaApi` from the shared
authenticated Retrofit) and `DmcaDataModule` (`@Binds` `DefaultDmcaRepository`).

## 5. API Contract

Endpoint — **VERIFIED** against `openapi.index.txt` line 2193 and
`src/api/endpoints/dmca.ts: submitDmcaClaim` (line 97-98):

`POST /v1/dmca/claims`  (req=`DmcaClaimIn`, resp `201:DmcaClaimCreateOut`,
`422:HTTPValidationError`).

**Corrected:** the spec previously stated `POST /ui/dmca/takedown` — that path
does not exist in the OpenAPI index. The DMCA *submit* endpoints under `/v1/dmca`
are: `POST /v1/dmca/claims` (this ticket), `GET /v1/dmca/claims/{claim_id}`,
`POST /v1/dmca/claims/{claim_id}/counter-notice`, `GET /v1/dmca/agent-info`.

Headers: session credentials (auto via AND-027 transport; web sends cookies via
`credentials: "include"` AND a bearer token) + `X-CSRF-Token: <ui_csrf>` (auto via
the CSRF interceptor, set from the `ui_csrf` cookie — verified in
`src/api/client.ts`). `Content-Type: application/json`.

Request body (`DmcaClaimIn`):

```json
{
  "claimant_name": "Jane Doe",
  "claimant_email": "jane@example.com",
  "claimant_address": "123 Main St, Springfield, IL 62701, USA",
  "claimant_phone": "+1-555-0100",
  "content_url": "https://testlogon.app/p/abc123",
  "content_type": "feed_post",
  "content_id": "abc123",
  "original_work_description": "Original photograph 'Sunset #4', registration VA-1-234-567",
  "sworn_statement": true,
  "good_faith_belief": true,
  "signature": "Jane Doe"
}
```

Required: `claimant_name`, `claimant_email`, `claimant_address`, `content_url`,
`original_work_description`, `sworn_statement`, `good_faith_belief`, `signature`.
Optional with defaults: `claimant_phone` (`""`), `content_type` (`"other"`),
`content_id` (`""`). Length bounds per schema: name 2-256, email 5-320, address
10-1000, phone ≤30, content_url 5-2000, content_id ≤256, description 20-5000,
signature 2-256.

Success `201 Created` (`DmcaClaimCreateOut`). **Corrected:** no `reference`, no
`case_id`; `created_at` is an INTEGER epoch, not an ISO string:

```json
{ "ok": true, "claim_id": "dmca_01HY...", "status": "received", "content_removed": false, "strike_number": 1, "created_at": 1749132069 }
```

Error `422 Unprocessable Entity` (FastAPI validation):

```json
{ "detail": [ { "loc": ["body", "claimant_email"], "msg": "value is not a valid email address", "type": "value_error.email" } ] }
```

Other error shapes per project convention: `detail` may also be a plain
`string` or an object with a `code` (e.g. `{ "code": "...", "message": "..." }`).
**Verified** against `src/api/client.ts: normalizeErrorDetail` — it handles three
forms: a plain string, an array of `{ msg }` items (joined with ", "), and an
object (mapped via `mapAuthorizationError` for known `code`s, else falls back to
`detail.msg` or a default). The Android `detail` mapper in `core-network` must
cover all three; `422` field errors are routed to `DmcaFormState.fieldErrors` by
matching the last element of each `loc` array to a `DmcaField`. **Note:** the
OpenAPI documents only `201` and `422` for this endpoint; `401`/`429`/`5xx` are
transport-level realities, not documented per-op responses, so their exact body
shapes are unverified-assumptions (treat generically via the detail mapper).

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
  the success `claim_id` lives only in `DmcaUiState.Submitted` for the screen
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
  **Unverified-assumption:** `429` is not a documented response for this op and
  the web client (`src/api/client.ts`) has no 429-specific branch or
  `Retry-After` handling (429 falls through to its generic non-2xx path). The
  `RateLimited` kind and `Retry-After` honoring are Android-side hardening, not a
  contract guaranteed by the backend or mirrored by the web app.
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
  `dmca_submit_failed` `{ http_status, error_kind }`. The `claim_id`
  and any claimant fields are **never** attached.
- **Logging:** network logging redacts the request body for this endpoint —
  OkHttp `HttpLoggingInterceptor` is at `BASIC` (or body-redacted) for
  `v1/dmca/*` (path CORRECTED from `ui/dmca/*`) so claimant PII and signature
  never hit Logcat. Only method, path, and status code are logged.
- **Crash reporting:** the `DmcaSubmitRequest` instance is excluded from
  non-fatal breadcrumbs.

## 11. Testing Strategy

Unit (`core-network` / `core-data`, JUnit + MockWebServer + Moshi):
- `DmcaApi` serializes the full request body with correct snake_case JSON keys;
  optional null fields are omitted/serialized per Moshi config.
- `201` → `ApiResult.Success` with parsed `claim_id` (and `status`,
  `content_removed`, `strike_number`, integer `created_at`).
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
  with the server `claim_id` (backed by MockWebServer) — this is the literal
  backlog acceptance ("DMCA request submits").
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
- **External:** path and field schema CONFIRMED in this review —
  `POST /v1/dmca/claims` / `DmcaClaimIn` / `DmcaClaimCreateOut` (see §13 OQ-1,
  §16). No external blocker remains for the DTOs.

## 13. Risks & Open Questions

- **OQ-1 (path/schema) — RESOLVED in this review.** Endpoint is
  `POST /v1/dmca/claims` with body `DmcaClaimIn`; the previously assumed
  `/ui/dmca/takedown` was wrong and is corrected throughout. DTO field names and
  the response shape have been reconciled against the OpenAPI schemas and
  `src/api/endpoints/dmca.ts`. No further verification needed before coding.
- **OQ-2 (attachments).** Some DMCA flows accept evidence files/screenshots.
  **Resolved:** `DmcaClaimIn` has no file/multipart field; `submit_dmca_claim`
  takes a JSON body only. File upload is confirmed **out of scope**.
- **OQ-3 (auth requirement).** Does the backend allow anonymous DMCA notices?
  This ticket assumes authenticated submission (Deps: AND-027). **Unverified:**
  the OpenAPI index does not expose a per-op security requirement in the index
  line, and `submitDmcaClaim` is grouped under "Public endpoints" in the web
  client (vs "Admin endpoints"), but the web client still attaches the bearer
  token + CSRF + cookies to all calls. Whether the backend hard-rejects an
  unauthenticated DMCA POST is not confirmable from these sources; assume
  authenticated. If anonymous is later supported, an unauthenticated entry path
  is a follow-up.
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
AC-3. A valid submission issues exactly one `POST /v1/dmca/claims` with session
credentials + `X-CSRF-Token`, and on `201` the UI shows a confirmation containing
the server `claim_id` (and may show `status`/`content_removed`)
(**"DMCA request submits"**).
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
  asserts the rendered `claim_id`.
- Network logging redaction for `v1/dmca/*` and release-build cleartext
  restriction verified.
- Strings externalized; accessibility checks (TalkBack labels, live-region
  success, touch targets) pass.
- Code review approved on branch `android-port`; no new lint/Detekt regressions;
  ticket demoed end-to-end against the dev backend.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`, `components.schemas.*`), and frontend
(`reference/src/...`).

1. **Endpoint is `POST /v1/dmca/claims`.** VERIFIED.
   `openapi.index.txt` line 2193 (`op=submit_dmca_claim_v1_dmca_claims_post`,
   `req=DmcaClaimIn`, `resp=201:DmcaClaimCreateOut;422:HTTPValidationError`);
   `src/api/endpoints/dmca.ts: submitDmcaClaim` (`api.post("/v1/dmca/claims")`).
   (Originally claimed `POST /ui/dmca/takedown` — CORRECTED; no such path exists.)
2. **HTTP method is POST with JSON body.** VERIFIED.
   `openapi.index.txt` line 2193; `src/api/endpoints/dmca.ts: submitDmcaClaim`.
3. **Request schema = `DmcaClaimIn`; required fields.** VERIFIED/CORRECTED.
   `openapi.pretty.json: components.schemas.DmcaClaimIn` (lines 28803-28887);
   `required = [claimant_name, claimant_email, claimant_address, content_url,
   original_work_description, sworn_statement, good_faith_belief, signature]`.
4. **Copyright-work field is `original_work_description` (min 20 / max 5000).**
   CORRECTED (was `work_description`). `DmcaClaimIn.original_work_description`;
   web minLength 20 in `src/pages/dmca/DmcaClaimForm.tsx` (line 227-230).
5. **Infringing material = flat `content_url` (required), `content_type`
   (enum, default "other"), `content_id` (optional).** CORRECTED (was nested
   `content_ref { content_type, content_id }` + `infringing_url`).
   `DmcaClaimIn.content_url/content_type/content_id`;
   `src/api/endpoints/dmca.ts: DmcaClaimIn` (lines 9-12).
6. **`content_type` enum = feed_post|feed_media|message_media|video|other.**
   VERIFIED. `DmcaClaimIn.content_type.enum` (lines 28838-28845);
   `src/pages/dmca/DmcaClaimForm.tsx` SelectItems (lines 200-204).
7. **Attestation fields are `sworn_statement` and `good_faith_belief`
   (both bool).** CORRECTED (were `accuracy_statement` /
   `good_faith_statement`). `DmcaClaimIn.sworn_statement`,
   `DmcaClaimIn.good_faith_belief`; `src/api/endpoints/dmca.ts` (lines 13-14).
8. **`signature` (min 2 / max 256), `claimant_*` bounds.** VERIFIED.
   `DmcaClaimIn` property `maxLength`/`minLength` (lines 28805-28873).
9. **Success response = `DmcaClaimCreateOut`, status 201, fields
   `{ok, claim_id, status, content_removed, strike_number, created_at}`;
   `created_at` is INTEGER epoch; NO `reference`/`case_id`.** CORRECTED.
   `openapi.pretty.json: components.schemas.DmcaClaimCreateOut` (lines
   28723-28760); `src/api/endpoints/dmca.ts: DmcaClaimCreateOut` (lines 38-45).
10. **Documented error response = `422 HTTPValidationError` only.** VERIFIED.
    `openapi.index.txt` line 2193 (`resp=...;422:HTTPValidationError`).
11. **CSRF via `X-CSRF-Token` echoing the `ui_csrf` cookie.** VERIFIED.
    `src/api/client.ts` (lines 167-171: `getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
12. **Transport is not cookie-only: web also sends `Authorization: Bearer` +
    `credentials: "include"`.** CORRECTED (spec said "cookie-based session").
    `src/api/client.ts` (lines 157-159 bearer; line 183 `credentials:"include"`).
13. **401 → single `POST /ui/session/refresh` → retry once; refresh only when
    already authenticated.** VERIFIED. `src/api/client.ts` (lines 121-130
    `refreshSession`; 194-237 the 401 branch); `/ui/session/refresh` exists in
    `openapi.index.txt` line 1847.
14. **`detail` mapper handles string | array-of-`{msg}` | object-with-`code`.**
    VERIFIED. `src/api/client.ts: normalizeErrorDetail` (lines 66-102) and
    `mapAuthorizationError` (lines 34-64).
15. **422 `loc` array tail → field mapping.** VERIFIED (shape).
    `HTTPValidationError`/`ValidationError` (`loc`/`msg`/`type`) is the standard
    FastAPI body; mapping last `loc` element to a field is an app convention.
16. **Network failure surfaces a non-2xx/transport error (web throws
    `ApiError(0, ...)`).** VERIFIED. `src/api/client.ts` (lines 185-189).
17. **No file/attachment field on submit.** VERIFIED. `DmcaClaimIn` has no
    binary/multipart property; `submit_dmca_claim` is JSON-only.
18. **Single non-idempotent POST, no auto-retry.** UNVERIFIED-ASSUMPTION
    (app design). Backend exposes no idempotency key in `DmcaClaimIn`; web app
    relies on a disabled button while `mutation.isPending`
    (`src/pages/dmca/DmcaClaimForm.tsx` line 306). Android-side hardening.
19. **Content-overflow pre-targeted entry + `content_id` prefill.**
    UNVERIFIED-ASSUMPTION. Web exposes only a standalone form with no overflow
    entry and does not collect `content_id` (`src/pages/dmca/DmcaClaimForm.tsx`).
    Schema-compatible (field is optional) but Android-only.
20. **Showing `claim_id` in a confirmation screen.** UNVERIFIED-ASSUMPTION
    (web only shows a success toast then navigates home —
    `src/pages/dmca/DmcaClaimForm.tsx` lines 75-78). The `claim_id` IS in the
    response, so displaying it is contract-safe.
21. **429 / `Retry-After` handling.** UNVERIFIED-ASSUMPTION. Not a documented
    response; web client has no 429 branch (`src/api/client.ts`). Android-side.
22. **Draft persistence to DataStore.** UNVERIFIED-ASSUMPTION (app design); no
    web equivalent.
23. **Stack/module choices (Kotlin/Compose/Hilt/Retrofit/Moshi/DataStore,
    `SavedStateHandle`, `collectAsStateWithLifecycle`).** Android framework
    refs, not backend contract: Hilt `SavedStateHandle`
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate
    (framework ref); DataStore
    https://developer.android.com/topic/libraries/architecture/datastore
    (framework ref); Compose lifecycle collection
    https://developer.android.com/jetpack/compose/lifecycle (framework ref);
    accessibility semantics/live region
    https://developer.android.com/jetpack/compose/accessibility (framework ref).
24. **Network security config requiring HTTPS in release / cleartext for dev
    host.** Framework ref:
    https://developer.android.com/training/articles/security-config
    (framework ref). Plaintext dev backend is the project posture (spec §8).

### Corrections made

- Endpoint path `POST /ui/dmca/takedown` → **`POST /v1/dmca/claims`**
  (§2, §4, §5, §12, §14 AC-3, §15). [claim 1]
- Request DTO renamed/reshaped to `DmcaClaimIn`: `work_description` →
  `original_work_description`; `infringing_url` + nested `content_ref` →
  flat `content_url` (required) + `content_type` + `content_id`;
  `accuracy_statement` → `sworn_statement`; `good_faith_statement` →
  `good_faith_belief` (§2, §3 FR-2, §4 DTOs/ViewModel, §5). [claims 4,5,7]
- Response DTO corrected to `DmcaClaimCreateOut`: removed `reference`/`case_id`,
  added `ok`/`content_removed`/`strike_number`, `created_at` is integer epoch;
  success status is `201` (§4, §5, §6, §10, §11, §14 AC-3, §4 `Submitted`).
  [claims 9]
- Auth description corrected from "cookie-based session" to bearer + cookies +
  CSRF (§2). [claim 12]
- Logging/redaction path glob `ui/dmca/*` → `v1/dmca/*` (§10, §15). [claim 1]
- OQ-1/OQ-2 marked resolved; OQ-3 refined to unverified (§13).

### Open assumptions

- **Auth requirement for anonymous DMCA (OQ-3):** cannot confirm from sources
  whether the backend rejects an unauthenticated POST; index line carries no
  per-op security flag. Assumed authenticated. [claim 18-context]
- **Content-overflow entry + `content_id` prefill:** Android-only; no web
  precedent. [claim 19]
- **`claim_id` confirmation display:** contract-safe but not mirrored by web.
  [claim 20]
- **429/`Retry-After`, no-auto-retry, draft persistence:** Android-side
  hardening with no documented backend contract or web behavior. [claims 18,21,22]
- **Exact `401`/`429`/`5xx` body shapes:** undocumented for this op; handled
  generically via the detail mapper. [claim 10]

## 17. Test Plan

Test targets: **JVM** = local JUnit/Robolectric (no device); **emu35** =
headless AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy
A15 5G (SM-A156U, API 34, arm64-v8a). Cases are sized to a single-screen,
single-POST form ticket. Most run on JVM or emu35; physical-device cases are
called out where real hardware/behavior matters.

- **TC-AND-384-01** — Type: contract/MockWebServer. Target: JVM. Precondition:
  `DmcaApi` + Moshi wired to a MockWebServer base URL. Steps: build a fully
  populated `DmcaClaimRequest` and call `submitClaim`; capture the recorded
  request. Expected: method `POST`, path `/v1/dmca/claims`, `Content-Type:
  application/json`, body JSON keys exactly `claimant_name, claimant_email,
  claimant_address, claimant_phone, content_url, content_type, content_id,
  original_work_description, sworn_statement, good_faith_belief, signature`
  (snake_case); null optionals omitted/handled per Moshi config. Traces: AC-3.
- **TC-AND-384-02** — Type: contract/MockWebServer. Target: JVM. Precondition:
  MockWebServer queued with `201` body `{ "ok": true, "claim_id": "dmca_x",
  "status": "received", "content_removed": false, "strike_number": 1,
  "created_at": 1749132069 }`. Steps: call repository `submit`. Expected:
  `ApiResult.Success` with `claimId == "dmca_x"`, `createdAt` parsed as Long
  epoch, no crash on missing `reference`/`case_id`. Traces: AC-3.
- **TC-AND-384-03** — Type: contract/MockWebServer. Target: JVM. Precondition:
  MockWebServer queued with `422` body `{ "detail": [ { "loc": ["body",
  "claimant_email"], "msg": "value is not a valid email address", "type":
  "value_error" } ] }`. Steps: submit; map error. Expected: `ApiResult` error of
  kind `Validation`; `fieldErrors[claimant_email]` populated from `loc` tail;
  form values preserved. Traces: AC-5.
- **TC-AND-384-04** — Type: contract/MockWebServer. Target: JVM. Precondition:
  MockWebServer returns `429` (optionally with `Retry-After: 30`), then a `5xx`,
  then an `IOException`/socket close in separate runs. Steps: submit for each.
  Expected: `429` → `DmcaErrorKind.RateLimited` (honor `Retry-After` if present);
  `5xx` → server error message; transport failure → `DmcaErrorKind.Network`
  ("not submitted") with form preserved. Traces: AC-5.
- **TC-AND-384-05** — Type: contract/MockWebServer. Target: JVM. Precondition:
  fake auth interceptor (AND-027 contract) that on `401` calls
  `POST /ui/session/refresh` once then retries. Steps: queue `401`, then
  refresh `200`, then original `201`; in a second run queue `401`, refresh `200`,
  retried `401`. Expected: run 1 → success after exactly one refresh + one retry;
  run 2 → `DmcaErrorKind.Auth` ("session expired"), no silent resubmit. Assert
  exactly the expected request count. Traces: AC-5.
- **TC-AND-384-06** — Type: unit. Target: JVM. Precondition: repository with
  MockWebServer. Steps: trigger a transport failure on submit and confirm the
  repository performs NO retry; then a duplicate `submit()` is only issued by an
  explicit caller action. Expected: exactly ONE recorded request per `submit()`
  call; zero automatic retries on the non-idempotent POST. Traces: AC-4.
- **TC-AND-384-07** — Type: unit. Target: JVM. Precondition: `DmcaViewModel` with
  fake repository, Turbine on `uiState`. Steps: drive validation — empty/blank
  required fields, malformed email, `content_url` empty, description < 20 chars,
  either attestation unchecked, empty signature. Expected: `isSubmittable`/Submit
  stays disabled until ALL hard rules pass and BOTH `sworn_statement` and
  `good_faith_belief` are `true`; inline `fieldErrors` set appropriately.
  Traces: AC-2.
- **TC-AND-384-08** — Type: unit. Target: JVM. Precondition: ViewModel, Turbine,
  fake repo returning `201`. Steps: fill valid form, call `submit()`; while
  in-flight call `submit()` again (double-tap). Expected: emits
  `Editing(submitting=true)` → `Submitted(claimId=...)`; only ONE repository
  call occurs; draft cleared on success. Traces: AC-4, AC-3, AC-6.
- **TC-AND-384-09** — Type: unit. Target: JVM (Robolectric for DataStore).
  Precondition: `DmcaDraftStore` (Preferences DataStore). Steps: save a draft
  with all fields, reload, then clear. Expected: text fields round-trip;
  `signature`, `sworn_statement`, `good_faith_belief` are NEVER persisted; clear
  removes the entry; sign-out hook clears drafts. Traces: AC-6.
- **TC-AND-384-10** — Type: Compose-UI. Target: emu35 (CI). Precondition:
  `createAndroidComposeRule` + Hilt test, MockWebServer queued `201`. Steps:
  enter all valid fields, check both attestations, type signature, tap "Submit
  DMCA notice". Expected: loading state shown, then `DmcaConfirmation` renders
  the server `claim_id`; this is the literal backlog acceptance ("DMCA request
  submits"); form cleared/locked. Traces: AC-3, AC-2.
- **TC-AND-384-11** — Type: Compose-UI. Target: emu35. Precondition: navigate via
  `navigateToDmca(contentType, contentId, url)` (pre-targeted). Steps: open the
  form from a simulated content-overflow route. Expected: `content_url`/
  `content_type`/`content_id` prefilled; the resolved content reference field is
  read-only/locked. (Android-only path; see §16 open assumption.) Traces: AC-1.
- **TC-AND-384-12** — Type: Compose-UI / accessibility. Target: emu35 (TalkBack
  semantics assertable headless). Precondition: form rendered. Steps: assert
  semantics — each field has a label; an invalid field exposes
  `SemanticsProperties.Error`; checkbox rows expose `Role.Checkbox`, full
  statutory text as content description, and a ≥48 dp touch target (tapping the
  row toggles); on success the confirmation uses an assertive live region.
  Expected: all assertions pass; strings come from resources (no concatenation).
  Traces: AC-7.
- **TC-AND-384-13** — Type: instrumented (security/logging). Target: deviceA15
  (preferred) / emu35. Precondition: release-like build with
  `network_security_config.xml`; `HttpLoggingInterceptor` body-redacted for
  `v1/dmca/*`. Steps: submit a claim; capture Logcat and any analytics/crash
  breadcrumb payloads. Expected: NO claimant PII or signature in Logcat/analytics
  /breadcrumbs (only method/path/status); cleartext to the dev host allowed but
  HTTPS enforced for other hosts in release; a submit with a missing/invalid
  CSRF token fails closed. Traces: AC-6.
- **TC-AND-384-14** — Type: integration/e2e (flaky-host / offline). Target:
  deviceA15 (preferred — real radio toggling) / emu35. Precondition: app pointed
  at the dev backend; ability to toggle connectivity. Steps: compose a full
  notice offline; tap Submit with no network; restore network; tap "Try again".
  Expected: offline attempt → `Network` error ("not submitted"), form values
  retained, NO duplicate POST queued; retry after reconnect succeeds with `201`
  and confirmation. Also verify a ~20s timeout reads as failure without
  auto-resubmitting. Traces: AC-5, AC-4.

### Coverage matrix

- **AC-1** (entry points; pre-target locks reference): TC-AND-384-11.
- **AC-2** (Submit gated on validity + both attestations + signature):
  TC-AND-384-07, TC-AND-384-10.
- **AC-3** (one `POST /v1/dmca/claims` w/ CSRF; `201` shows `claim_id`):
  TC-AND-384-01, TC-AND-384-02, TC-AND-384-08, TC-AND-384-10.
- **AC-4** (no auto-retry; double-tap = single call): TC-AND-384-06,
  TC-AND-384-08, TC-AND-384-14.
- **AC-5** (`422`/`401`-after-refresh/`429`/network distinct + preserve form):
  TC-AND-384-03, TC-AND-384-04, TC-AND-384-05, TC-AND-384-14.
- **AC-6** (no PII/signature in logs/analytics/crash; draft excludes
  signature+checkboxes; cleared on success/sign-out): TC-AND-384-08,
  TC-AND-384-09, TC-AND-384-13.
- **AC-7** (accessible + localized + ≥48 dp checkbox targets): TC-AND-384-12.
