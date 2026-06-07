---
id: AND-349
title: Submit + PDF (public respond)
milestone: M7
epic: E45
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-348, AND-022]
blocks: []
---

# AND-349 — Submit + PDF (public respond)

## 1. Overview & Goal

This ticket completes the respondent-facing questionnaire flow for the TestLogon
native Android app. It adds three capabilities on top of the dynamic renderer
(AND-347) and the respondent session machinery (AND-348):

1. **Submit** — finalize an in-progress respondent session, transitioning a
   draft set of answers into a completed submission against the public
   `POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit`
   endpoint (verified — path params are `published_slug` / `response_session_id`,
   not `slug` / `session_id`), with server-side validation surfacing and a terminal
   confirmation state. Note: this endpoint returns a 200 envelope whose `result`
   carries the server validation outcome (`can_submit`/`errors`); it does NOT return
   a discrete `submission_id` (see Section 5, corrected).
2. **PDF export** — download/render the completed submission as a PDF document and
   hand it to the user via the system share/open chooser (no in-app PDF viewer is
   built here).
3. **Public App Link entry** — register and route the public deep link
   `https://<host>/questionnaires/published/{slug}/respond` so an external tap
   (browser, email, QR) opens the respondent renderer directly, even when the user
   is anonymous (cookie-less) and the app was cold-started by the link.

The deliverable closes the public-respond loop end-to-end: a respondent can open a
published questionnaire from an outside link, fill it (AND-347), save/resume
(AND-348), **submit**, and **export the result as a PDF**.

Out of scope: questionnaire authoring/publishing (separate epic), authenticated
"my responses" history, in-app PDF rendering/annotation, and offline submission
queueing (submit is online-only here; offline draft save is owned by AND-348).

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose typed routes, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 +
  OkHttp 4.12 + Moshi 1.15. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP
  8.7.3, Gradle 8.9 wrapper.
- **Module:** `feature-respond` (the renderer + session feature module introduced
  by AND-347/AND-348). This ticket extends it; no new module is created.
  Layering: `app -> feature-respond -> core-network, core-model, core-data,
  core-ui`.
- **Namespace / applicationId base:** `com.testlogon.android`. The respond feature
  lives in `com.testlogon.android.feature.respond`.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is
  plaintext HTTP and unreliable; OpenAPI at `/openapi.json`. Web reference under
  `frontend/` (`frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`)
  is the canonical contract source — confirm exact field names there before
  freezing the Moshi DTOs.
- **Auth context:** The public respond/submit endpoints are **anonymous** (no
  authenticated session required). [VERIFIED against `src/api/client.ts`] The web
  client attaches the `X-CSRF-Token` header only when a `ui_csrf` cookie is present;
  an anonymous respondent has no such cookie, so no CSRF header is sent — Android
  should likewise omit `X-CSRF-Token` for these calls. They operate on an opaque
  `response_session_id` minted by AND-348's session-start call
  (`POST /questionnaires/published/{published_slug}/sessions`). The cookie jar
  (AND-009) still applies so any per-session cookies the backend sets are persisted.
- **Dependencies:**
  - **AND-348 — Respondent session** (start/save/validate session). Provides the
    `session_id`, the answer model, and `RespondRepository`. This ticket adds the
    `submit` and `pdf` calls to that repository and consumes its draft state.
  - **AND-022 — Navigation host & routes** (typed `NavHost`). Provides the
    `NavHost`, route-registration pattern, and `composable<T>` typed-route helpers
    that the App Link `navDeepLink` plugs into.

## 3. Functional Requirements

FR-1. **Submit action.** The respondent screen (from AND-347/348) exposes a
"Submit" affordance, enabled only when local required-field validation passes
(reusing AND-348's validation) and a `session_id` exists.

FR-2. **Submit flow.** Tapping Submit (a) flushes any unsaved answers via AND-348's
save call, then (b) POSTs to the submit endpoint. The button shows a loading state
and is disabled during the in-flight request to prevent double-submit.

FR-3. **Server validation surfacing.** [CORRECTED] Per-field questionnaire
validation errors are NOT returned as a FastAPI 422. The submit endpoint returns
**200** `SessionSubmitEnvelope` `{ session, result }`, where `result` is a
`QuestionnaireValidationResponse` with `is_valid`, `can_submit`,
`has_blocking_form_error`, and `errors` — a map keyed by `question_id` (and by
`group:<id>` / `form:<id>` for group/form-level rules) → array of
`ValidationIssue{ code, message, blocking, rule_id }`. When `result.can_submit`
is `false` (blocking errors present), the UI maps `result.errors` onto the
corresponding rendered fields (field-keyed messages from `ValidationIssue.message`)
and scrolls the first errored field into view; no terminal confirmation is shown.
A genuine FastAPI 422 (`HTTPValidationError` → `detail:[{loc,msg,type}]`) only
occurs on malformed request shape and is handled as a generic error (Section 7),
not mapped to fields.

FR-4. **Confirmation state.** On a successful submit (200 with
`result.can_submit == true` / `is_valid == true`), the screen transitions to a
terminal `Submitted` state showing a confirmation message and a **"Download PDF"**
action. [CORRECTED] Because the API returns no `submission_id`, the confirmation
shows session-derived identity (the `response_session_id`) and/or status read from
the returned `session` object — there is no server submission id to display. The
form is no longer editable. A 200 whose `result.can_submit == false` is treated as
a validation failure (FR-3), NOT a successful submit.

FR-5. **PDF export.** "Download PDF" requests the submission PDF for the
`session_id`/submission, writes the bytes to app cache, and launches the system
chooser (`ACTION_VIEW` / share) via a `FileProvider` content URI so any installed
PDF viewer / share target can open it.

FR-6. **Public App Link.** Tapping
`https://<host>/questionnaires/published/{slug}/respond` (verified Android App
Link) opens the app directly into the respondent route for `{slug}`. This works on
cold start and when anonymous. If the app is not installed, normal web fallback
applies (handled by the OS, not us).

FR-7. **Re-submit guard.** A session that is already submitted (server reports a
terminal status, or local terminal state is persisted) reopens directly to the
`Submitted` confirmation state with PDF export available, not the editable form.

FR-8. **Resilience.** Submit and PDF failures (timeout, 5xx, offline) present a
retryable error without losing the draft.

## 4. Technical Design

### Routes & deep link (AND-022 integration)

The respondent route is typed (introduced by AND-347/348); AND-349 attaches the
public App Link to it:

```kotlin
@Serializable
data class RespondRoute(val slug: String, val sessionId: String? = null)

// In feature-respond's NavGraphBuilder extension, registered into the AND-022 NavHost:
fun NavGraphBuilder.respondGraph(navController: NavController) {
    composable<RespondRoute>(
        deepLinks = listOf(
            navDeepLink {
                uriPattern =
                    "https://{host}/questionnaires/published/{slug}/respond"
                action = Intent.ACTION_VIEW
            }
        )
    ) { backStackEntry ->
        val args = backStackEntry.toRoute<RespondRoute>()
        RespondScreen(slug = args.slug)
    }
}
```

`AndroidManifest.xml` (app module) declares the App Link with
`autoVerify="true"` on the single `MainActivity`:

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https"
          android:host="@string/applink_host"
          android:pathPrefix="/questionnaires/published" />
</intent-filter>
```

`applink_host` is a build-config/string resource so dev/prod hosts differ. Domain
verification requires `/.well-known/assetlinks.json` on the host (see Risks —
the dev host is plaintext HTTP, which **cannot** satisfy App Links autoVerify;
dev uses a manual "verify links" toggle or a fallback custom-scheme path).

### Submit + PDF in the ViewModel

`RespondViewModel` (owned by AND-348) is extended with submit/export actions and
two new fields on its `RespondUiState`:

```kotlin
// [CORRECTED] No server submission_id exists; the terminal state carries the
// session id (and any status read from the returned `session` object) instead.
sealed interface SubmitPhase {
    data object Idle : SubmitPhase
    data object Submitting : SubmitPhase
    data class Submitted(val sessionId: String, val status: String?) : SubmitPhase
    data class Error(val message: String) : SubmitPhase
}

data class RespondUiState(
    val slug: String,
    val sessionId: String?,
    val fields: List<RenderedField>,          // from AND-347
    val fieldErrors: Map<String, String>,     // server-mapped errors (FR-3)
    val submit: SubmitPhase = SubmitPhase.Idle,
    val pdfExport: PdfExportState = PdfExportState.Idle,
)

sealed interface PdfExportState {
    data object Idle : PdfExportState
    data object Downloading : PdfExportState
    data class Ready(val contentUri: Uri) : PdfExportState
    data class Error(val message: String) : PdfExportState
}

@HiltViewModel
class RespondViewModel @Inject constructor(
    private val repo: RespondRepository,
    private val pdfExporter: PdfExporter,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<RespondUiState> = /* AND-348 base + this ticket */

    fun onSubmit() = viewModelScope.launch {
        val sid = uiState.value.sessionId ?: return@launch
        if (!validateLocally()) return@launch          // AND-348 validation
        setSubmitPhase(SubmitPhase.Submitting)
        repo.saveDraft(sid, currentAnswers())          // FR-2(a)
        // [CORRECTED] submit returns a 200 SessionSubmitEnvelope; success vs.
        // validation-failure is decided by result.can_submit, NOT by HTTP 422.
        when (val r = repo.submit(uiState.value.slug, sid, currentAnswers())) {
            is ApiResult.Success -> {
                val result = r.data.result               // QuestionnaireValidationResponse
                if (result.canSubmit && result.isValid) {
                    setSubmitPhase(
                        SubmitPhase.Submitted(sid, status = r.data.statusFromSession())
                    )
                } else {
                    applyFieldErrors(result.errors)      // map<questionId, [ValidationIssue]> (FR-3)
                    setSubmitPhase(SubmitPhase.Idle)     // stay editable, no confirmation
                }
            }
            is ApiResult.HttpError ->                    // genuine 4xx/5xx (e.g. 422 malformed shape)
                setSubmitPhase(SubmitPhase.Error(/* retryable / generic */))
            is ApiResult.NetworkError, is ApiResult.Timeout ->
                setSubmitPhase(SubmitPhase.Error(/* retryable */))
        }
    }

    fun onDownloadPdf() = viewModelScope.launch {
        val sid = uiState.value.sessionId ?: return@launch
        setPdfState(PdfExportState.Downloading)
        when (val r = repo.fetchPdf(uiState.value.slug, sid)) {
            is ApiResult.Success ->
                setPdfState(PdfExportState.Ready(pdfExporter.persist(sid, r.data)))
            else -> setPdfState(PdfExportState.Error(/* retryable */))
        }
    }
}
```

### Repository (extends AND-348's `RespondRepository`)

```kotlin
interface RespondRepository {
    // ... start/save/validate from AND-348 ...
    // [CORRECTED] submit requires answers + final_submit in the body and returns
    // the SessionSubmitEnvelope (session + validation result), not a SubmissionResult.
    suspend fun submit(
        slug: String,
        sessionId: String,
        answers: Map<String, Any?>,
    ): ApiResult<SessionSubmitEnvelope>
    // PDF is keyed by response_session_id (verified). Two server variants exist:
    //   POST .../pdf -> SessionPdfEnvelope{artifact}  (generate/produce artifact)
    //   GET  .../pdf -> binary application/pdf         (download bytes)
    suspend fun fetchPdf(slug: String, sessionId: String): ApiResult<ResponseBody>
}
```

### PDF persistence & sharing

`PdfExporter` is a `core-data`/feature-local helper. Streaming `ResponseBody` is
written to `context.cacheDir/respond-pdfs/<sessionId>.pdf`; a content URI is
produced via a `FileProvider` (authority
`com.testlogon.android.fileprovider`, `cache-path` `respond-pdfs/`).

```kotlin
class PdfExporter @Inject constructor(@ApplicationContext private val ctx: Context) {
    suspend fun persist(sessionId: String, body: ResponseBody): Uri =
        withContext(Dispatchers.IO) {
            val dir = File(ctx.cacheDir, "respond-pdfs").apply { mkdirs() }
            val file = File(dir, "$sessionId.pdf")
            body.byteStream().use { input -> file.outputStream().use { input.copyTo(it) } }
            FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", file)
        }
}
```

The Compose layer collects `PdfExportState.Ready` (one-shot event) and launches:

```kotlin
val intent = Intent(Intent.ACTION_VIEW).apply {
    setDataAndType(uri, "application/pdf")
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
}
context.startActivity(Intent.createChooser(intent, stringResource(R.string.open_pdf)))
```

## 5. API Contract

All paths are public (anonymous; the web client omits `X-CSRF-Token` when no
`ui_csrf` cookie exists — verified in `src/api/client.ts`). Path params are
**`{published_slug}`** and **`{response_session_id}`** (verified against the
OpenAPI index), supplied by AND-348. Field names below are reconciled against
`src/api/endpoints/questionnaires.ts`, `src/pages/questionnaires/QuestionnaireRespondentPage.tsx`,
and `openapi.pretty.json`.

### Submit  [CORRECTED]

```
POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit
Content-Type: application/json

Request body (QuestionnaireValidationRequest — NOT optional/empty; the web client
sends the answers and final_submit=true here even though save also ran):
{
  "answers_by_question_id": { "q1": "...", "q3": ["a","b"] },
  "final_submit": true,
  "contract_version": "2026-03-validation-v1",   // const default; may be omitted
  "form_rules": [],                               // optional
  "group_rules": []                               // optional
}

200 Response (SessionSubmitEnvelope — NO submission_id/submitted_at):
{
  "session": { ... },                             // opaque session object (status lives here)
  "result": {                                     // QuestionnaireValidationResponse
    "is_valid": true,
    "can_submit": true,
    "has_blocking_form_error": false,
    "errors": { },                                // map<key, ValidationIssue[]>
    "contract_version": "2026-03-validation-v1"
  }
}
```

`errors` is keyed by `question_id`, or by `group:<id>` / `form:<id>` for
group/form-level rules (verified in `QuestionnaireRespondentPage.tsx`). Each
`ValidationIssue` is `{ code, message, blocking?, rule_id? }`.

```kotlin
@JsonClass(generateAdapter = true)
data class SessionSubmitEnvelope(
    @Json(name = "session") val session: Map<String, Any?>,          // status read from here
    @Json(name = "result") val result: QuestionnaireValidationResponse,
)

@JsonClass(generateAdapter = true)
data class QuestionnaireValidationResponse(
    @Json(name = "is_valid") val isValid: Boolean,
    @Json(name = "can_submit") val canSubmit: Boolean,
    @Json(name = "has_blocking_form_error") val hasBlockingFormError: Boolean,
    @Json(name = "errors") val errors: Map<String, List<ValidationIssue>>,
    @Json(name = "contract_version") val contractVersion: String? = null,
)

@JsonClass(generateAdapter = true)
data class ValidationIssue(
    @Json(name = "code") val code: String,
    @Json(name = "message") val message: String,
    @Json(name = "blocking") val blocking: Boolean? = null,
    @Json(name = "rule_id") val ruleId: String? = null,
)
```

The request body maps to `QuestionnaireValidationRequest`:

```kotlin
@JsonClass(generateAdapter = true)
data class SubmitRequest(
    @Json(name = "answers_by_question_id") val answers: Map<String, Any?>,
    @Json(name = "final_submit") val finalSubmit: Boolean = true,
)
```

**Genuine 422** (only on malformed request shape) is the standard FastAPI
`HTTPValidationError` → `detail: [{ loc, msg, type }]` (verified: schema
`ValidationError` has `loc`/`msg`/`type`, all required). This is handled as a
generic error, NOT mapped to fields — field-level questionnaire validation arrives
in the 200 `result.errors` map above.

### PDF export  [CORRECTED — keyed by response_session_id; resolves Q-2/R-2]

Two PDF endpoints exist on the backend (both keyed by `response_session_id`, not a
submission id — verified in the OpenAPI index, lines 550–551):

```
POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/pdf
  -> 200 SessionPdfEnvelope { "artifact": { ... } }   (generate / produce artifact descriptor)

GET  /questionnaires/published/{published_slug}/sessions/{response_session_id}/pdf
  -> 200 binary application/pdf                        (download bytes)
```

Android uses the **GET** variant to stream bytes for sharing. If the backend
requires the artifact to be produced first, call POST (returns
`SessionPdfEnvelope.artifact`) before GET — confirm ordering at integration time
(Open Question Q-2, narrowed: keying is resolved; generate-before-download
ordering is the remaining unknown).

```kotlin
@GET("questionnaires/published/{publishedSlug}/sessions/{responseSessionId}/pdf")
@Streaming
suspend fun getSubmissionPdf(
    @Path("publishedSlug") publishedSlug: String,
    @Path("responseSessionId") responseSessionId: String,
): Response<ResponseBody>
```

Note: the web reference app does NOT call either PDF endpoint
(`src/api/endpoints/questionnaires.ts` has no PDF function), so PDF UX has no web
precedent — it is an Android-only addition driven by the backend's PDF endpoints.

## 6. Data & State Management

- **State holder:** `RespondViewModel.uiState: StateFlow<RespondUiState>`. Submit
  and PDF phases are part of this single state object (Section 4).
- **One-shot effects:** PDF chooser launch and "scroll to first error" are
  modeled as effects (a `Channel<RespondEffect>` exposed as `Flow`, collected in
  a `LaunchedEffect`) so they don't re-fire on recomposition/rotation.
- **Persisted terminal state (FR-7):** the submitted status is persisted by
  AND-348's session store (Room/DataStore). On screen entry, if the stored
  session status is terminal, `uiState.submit` is seeded with
  `SubmitPhase.Submitted(sessionId, status)`. [CORRECTED] Since the API returns no
  `submission_id`, no submission-id column is needed; AND-349 persists only a
  terminal `status` flag (derived from the submit response's `session` object) as a
  column/DataStore key on the existing session record (coordinate with AND-348).
- **PDF cache:** files in `cacheDir/respond-pdfs/`; OS may evict. No DB row — the
  file is re-fetched on demand. Stale PDFs for a session are overwritten by id.
- **Process death:** `slug` is in the typed route (survives via SavedState);
  `sessionId` is restored from the persisted session record, so a killed-then-
  resumed submitted session lands on the confirmation state.

## 7. Error Handling & Resilience

- **Typed results:** `submit`/`fetchPdf` return `ApiResult<T>` (core-network).
  `detail` mapping per project convention (string | `[{msg}]` | `{code,...}`).
- **Timeouts:** 20s OkHttp call timeout (dev host is unreliable). PDF download
  uses `@Streaming` and the same call timeout; a partial download deletes the
  temp file before surfacing the error.
- **Retry policy:** Submit is a **POST (non-idempotent) — NO automatic retry**;
  failures show a user-driven "Retry" button. PDF `GET` is idempotent and uses the
  project's bounded backoff retry (e.g. 2 retries, jittered) at the OkHttp
  interceptor level.
- **Double-submit guard:** button disabled during `Submitting`; the ViewModel
  ignores `onSubmit()` when phase != `Idle`/`Error`.
- **Validation vs 5xx:** [CORRECTED] field-level questionnaire errors arrive in a
  **200** `result.errors` map with `can_submit == false` (stay editable, FR-3) —
  not a 422. A genuine 422 (`HTTPValidationError`, malformed request) and 5xx/
  network → retryable banner, draft preserved (FR-8).
- **Offline:** if `NetworkError`, message "You're offline — your answers are
  saved. Try submitting again when connected." Draft already saved locally by
  AND-348.
- **PDF open failure:** if no PDF viewer is installed (`ActivityNotFoundException`
  from the chooser), show a snackbar with a "Share file" fallback.

## 8. Security & Privacy

- **Anonymous endpoints:** submit/PDF require no auth session; do not attach the
  authenticated `X-CSRF-Token` header to these calls. The persistent cookie jar
  (AND-009) still stores any session cookie the backend sets.
- **FileProvider:** PDFs are shared only via per-grant `FLAG_GRANT_READ_URI_PERMISSION`
  content URIs; the `cache-path` is not world-readable. No `WRITE_EXTERNAL_STORAGE`
  permission is requested.
- **PII:** submission PDFs may contain respondent answers/PII. They live only in
  app cache, are never logged, and are not synced/backed up
  (`android:allowBackup` exclusion for `respond-pdfs/` via `data_extraction_rules`).
- **App Link verification:** `autoVerify` requires HTTPS + a valid `assetlinks.json`;
  on production this prevents arbitrary apps from claiming the link. The dev
  plaintext host cannot be a verified App Link (Risk R-1).
- **Cleartext:** dev build keeps `usesCleartextTraffic`/network-security-config
  domain allowlist for `18.222.237.167` only (project-wide config, not new here).

## 9. Accessibility & i18n

- Submit button, confirmation message, and "Download PDF" carry
  `contentDescription`/semantics; loading states announce via `Modifier.semantics
  { stateDescription = ... }` and `liveRegion` for the submit result.
- Server-mapped field errors set `error = true` semantics on the offending field
  and are read by TalkBack; first-error scroll uses `BringIntoViewRequester`.
- Touch targets >= 48dp; the confirmation screen is fully keyboard/switch-access
  navigable.
- All user-facing strings (confirmation text, error messages, chooser titles) are
  in `strings.xml` (no hardcoded text); supports RTL. Dates from `submitted_at`
  are formatted with the device locale.

## 10. Telemetry & Logging

- Events (via the app's analytics abstraction, no PII in params):
  `respond_submit_started{slug}`, `respond_submit_succeeded{slug}`,
  `respond_submit_failed{slug, error_kind}`, `respond_pdf_export_started`,
  `respond_pdf_export_succeeded`, `respond_pdf_export_failed{error_kind}`,
  `respond_applink_opened{slug, cold_start}`.
- Logging: Timber at `debug` for request lifecycle; never log answer payloads,
  PDF bytes, cookies, or `session_id` at `info`+. Submit/PDF HTTP failures logged
  with status code + sanitized `detail` only.

## 11. Testing Strategy

- **Unit (JUnit + Turbine + MockWebServer, core-testing):**
  - `RespondViewModel.onSubmit` happy path → `SubmitPhase.Submitted`.
  - 422 response → populates `fieldErrors` keyed correctly from `loc`; stays
    editable; emits scroll-to-first-error effect.
  - Network error → `SubmitPhase.Error`, no auto-retry, draft save still called.
  - Double-tap submit → second call ignored while `Submitting`.
  - `onDownloadPdf` → writes file, emits `PdfExportState.Ready` with content URI.
  - Reopen of terminal session seeds `Submitted` state (FR-7).
- **Repository:** MockWebServer asserts correct path/method
  (`POST .../submit`, `GET .../pdf` streaming), `detail` parsing, PDF byte
  integrity.
- **Instrumented / deep link:** `androidx.test` intent with the
  `https://.../questionnaires/published/{slug}/respond` URI launches `MainActivity`
  and lands on `RespondScreen(slug)` (cold start). `FileProvider` URI resolves and
  an `ACTION_VIEW pdf` chooser intent is fired (Espresso-Intents `intended`).
- **Compose UI:** submit button enabled/disabled by validation; confirmation state
  renders submission id + Download PDF; field-error display.
- **Manual/dev:** verify App Link via `adb shell pm verify-app-links` /
  `adb shell am start -a android.intent.action.VIEW -d "<url>"`; PDF opens in a
  real viewer.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-348 (session id, save/validate, `RespondRepository`,
  persisted session store) and AND-022 (typed `NavHost` + route registration the
  `navDeepLink` attaches to). Both must merge first.
- **Soft/coordination:** AND-347 (rendered field model + per-field error display
  surface used for FR-3); AND-009 cookie jar (pre-existing); FileProvider/network-
  security-config from app-shell tickets.
- **Blocks:** none listed in backlog (terminal node of the E45 public-respond
  chain).
- **Sequencing within ticket:** (1) Retrofit/DTO + repo methods, (2) ViewModel
  submit phase + 422 mapping, (3) PDF exporter + chooser, (4) App Link manifest +
  navDeepLink + assetlinks/dev fallback, (5) tests.

## 13. Risks & Open Questions

- **R-1 (App Link on dev host):** `autoVerify` App Links require HTTPS and a
  served `assetlinks.json`; the dev backend is plaintext HTTP at an IP, so
  autoVerify **will fail** in dev. Mitigation: gate `autoVerify` per build type and
  rely on manual link-handling in dev; production needs a real HTTPS host +
  `/.well-known/assetlinks.json` with the app's SHA-256 signing cert.
- **R-2 (PDF identifier):** [RESOLVED] PDF is keyed by `response_session_id`
  (verified in OpenAPI index lines 550–551; both GET and POST `/pdf` take
  `published_slug,response_session_id`). Residual unknown: whether POST (generate)
  must precede GET (download) — see Q-2.
- **R-3 (submit idempotency):** if the network drops after the server commits but
  before the response, a user retry may double-submit. Mitigation: if the backend
  returns the existing submission on resubmit of a terminal session, treat that as
  success; otherwise file a backend idempotency-key request (Q-3).
- **Q-1:** [RESOLVED] Submit DOES require the answers in the body. The web client
  sends `{ answers_by_question_id, final_submit: true }` to the submit endpoint
  (verified in `QuestionnaireRespondentPage.tsx` submitMutation); body is mapped to
  `QuestionnaireValidationRequest`, not an empty object.
- **Q-2:** [NARROWED] PDF keying resolved to `response_session_id`; remaining
  question is whether POST `/pdf` (generate `SessionPdfEnvelope.artifact`) must run
  before GET `/pdf` (download bytes).
- **Q-3:** Server-side submit idempotency guarantee (no Idempotency-Key param on
  this endpoint in OpenAPI, unlike `/api/v1/kyc/.../submit` which has one).
- **Q-4:** Exact `host` value(s) for production App Link string resource.

## 14. Acceptance Criteria

- **AC-1 (backlog):** Submitting a fully-completed, locally-valid session
  completes successfully (200 with `result.can_submit == true`) and the screen
  shows the terminal confirmation state. [CORRECTED] No server submission id is
  returned; the confirmation reflects the terminal session (and any status from the
  returned `session` object). (Covered by unit + Compose tests.)
- **AC-2 (backlog):** The public link
  `https://<host>/questionnaires/published/{slug}/respond` opens the respondent
  screen for `{slug}` — verified on cold start via an instrumented intent test and
  manual `adb am start`.
- **AC-3:** [CORRECTED] A submit response with `result.can_submit == false`
  (returned as HTTP 200, with `result.errors` keyed by question id / `group:` /
  `form:`) maps server errors to the correct fields, keeps the form editable, and
  scrolls the first error into view; no confirmation is shown.
- **AC-4:** Submit is disabled while in-flight and a double-tap cannot create two
  submissions.
- **AC-5:** "Download PDF" on the confirmation state downloads the PDF, persists it
  to app cache, and launches a chooser that opens it in a PDF viewer; a missing
  viewer falls back to share without crashing.
- **AC-6:** Submit/PDF network failures show a retryable error and never lose the
  saved draft; PDF GET retries (idempotent), POST submit does not auto-retry.
- **AC-7:** Reopening an already-submitted session lands on the confirmation/PDF
  state, not the editable form.

## 15. Definition of Done

- Code merged to `android-port` under `feature-respond`
  (`com.testlogon.android.feature.respond`) with `submit`/`fetchPdf` repo methods,
  `RespondViewModel` submit/PDF phases, `PdfExporter`, FileProvider config, and the
  App Link `navDeepLink` + manifest intent-filter.
- DTO field names reconciled against `/openapi.json` and `frontend/src/api`.
- All unit, repository (MockWebServer), Compose UI, and instrumented deep-link/
  intent tests pass in CI; coverage for the submit/422/PDF/deep-link paths.
- `ktlint`/`detekt` clean; no hardcoded strings (all in `strings.xml`); a11y
  semantics present and TalkBack-spot-checked.
- App Link build-type gating documented; production `assetlinks.json` requirement
  and Open Questions Q-1..Q-4 recorded in the ticket for backend follow-up.
- No PII (answers, PDF bytes, cookies, session id) in logs; PDFs excluded from
  backup.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Submit endpoint path** — `POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit`.
   VERDICT: Corrected (spec said `{slug}`/`{session_id}`).
   SOURCE: OpenAPI `POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit` (index line 552; op `submit_response_session_...`); `src/api/endpoints/questionnaires.ts: submitPublishedResponseSession`.
2. **Submit request body** — requires `{ answers_by_question_id, final_submit: true }` (schema `QuestionnaireValidationRequest`; also optional `contract_version`/`form_rules`/`group_rules`). NOT optional/empty.
   VERDICT: Corrected (spec modeled body as optional `{}`).
   SOURCE: schema `QuestionnaireValidationRequest` (openapi.pretty.json); `src/pages/questionnaires/QuestionnaireRespondentPage.tsx: submitMutation` (sends `answers_by_question_id` + `final_submit: true`).
3. **Submit success response** — `SessionSubmitEnvelope { session, result }`, where `result` is `QuestionnaireValidationResponse`; there is **no** `submission_id`, `status`, or `submitted_at`.
   VERDICT: Corrected (spec invented `SubmissionResult{submission_id,status,submitted_at}`).
   SOURCE: schema `SessionSubmitEnvelope` (required `session`,`result`); `src/api/endpoints/questionnaires.ts: submitPublishedResponseSession` (`<{ session, result }>`).
4. **Field-level validation transport** — questionnaire errors come back in a **200** `result.errors` map (key=question_id or `group:<id>`/`form:<id>`, value=`ValidationIssue[]`), gated by `result.can_submit`/`is_valid`/`has_blocking_form_error`. NOT a FastAPI 422.
   VERDICT: Corrected (spec claimed 422 `detail[]` carries field errors).
   SOURCE: schema `QuestionnaireValidationResponse` + `ValidationIssue`; `src/pages/questionnaires/QuestionnaireRespondentPage.tsx` (`errorMap`, `group:`/`form:` prefixes, `hasBlocking = !can_submit`).
5. **Genuine 422 shape** — `HTTPValidationError { detail: [ ValidationError{loc,msg,type} ] }`, occurs only on malformed request shape.
   VERDICT: Verified (and re-scoped to "request-shape only").
   SOURCE: schemas `HTTPValidationError`, `ValidationError` (openapi.pretty.json).
6. **PDF endpoints exist and are keyed by `response_session_id`** — `GET .../pdf` (binary) and `POST .../pdf` (→ `SessionPdfEnvelope{artifact}`).
   VERDICT: Corrected/Resolved (spec listed only GET and was unsure of keying; R-2/Q-2).
   SOURCE: OpenAPI index lines 550 (`download_response_session_pdf...`, resp 200 binary) and 551 (`generate_response_session_pdf...`, resp `SessionPdfEnvelope`); schema `SessionPdfEnvelope` (required `artifact`).
7. **Web app has no PDF call** — PDF is an Android-only feature with no web precedent.
   VERDICT: Verified.
   SOURCE: `src/api/endpoints/questionnaires.ts` (no `pdf` function present; grep over file).
8. **Anonymous / CSRF behavior** — web client sets `X-CSRF-Token` only when a `ui_csrf` cookie is present; anonymous respondents send no CSRF header. Header name is `X-CSRF-Token`.
   VERDICT: Verified.
   SOURCE: `src/api/client.ts` lines 167–171 (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`); `credentials: "include"` (cookie jar).
9. **Session-start endpoint (dependency origin of session id)** — `POST /questionnaires/published/{published_slug}/sessions` → `ResponseSessionEnvelope { session }`; start req `ResponseSessionStartReq` (web posts `{}`).
   VERDICT: Verified.
   SOURCE: OpenAPI index line 547; `src/api/endpoints/questionnaires.ts: startPublishedResponseSession`.
10. **Save endpoint** — `PUT .../sessions/{response_session_id}` with `SessionSaveReq{answers_by_question_id,current_section_index?,current_question_id?}`.
    VERDICT: Verified (context for FR-2 flush-before-submit).
    SOURCE: OpenAPI index line 549; schema `SessionSaveReq`; `src/api/endpoints/questionnaires.ts: savePublishedResponseSessionState`.
11. **Public App Link path prefix** — `/questionnaires/published/.../respond`.
    VERDICT: Unverified-assumption (no `/respond` route exists in OpenAPI; it is a client-side web SPA route, and there is no frontend source confirming the exact `respond` suffix from the supplied files).
    SOURCE: ticket scope text only (specs-src/AND-349.md line 10). See Open assumptions.
12. **App Links require HTTPS + assetlinks.json; plaintext dev IP cannot autoVerify** (R-1).
    VERDICT: Verified (framework ref).
    SOURCE: framework ref — Android App Links / Digital Asset Links (developer.android.com/training/app-links/verify-android-applinks).
13. **FileProvider per-grant content URIs via `FLAG_GRANT_READ_URI_PERMISSION`; no `WRITE_EXTERNAL_STORAGE`.**
    VERDICT: Verified (framework ref).
    SOURCE: framework ref — androidx FileProvider (developer.android.com/reference/androidx/core/content/FileProvider).
14. **`navDeepLink` typed-route deep linking in Navigation-Compose.**
    VERDICT: Verified (framework ref).
    SOURCE: framework ref — Navigation Compose deep links (developer.android.com/jetpack/compose/navigation#deeplinks).
15. **Submit idempotency** — this endpoint has no `Idempotency-Key` param (unlike KYC submit).
    VERDICT: Verified (absence) / open guarantee.
    SOURCE: OpenAPI index line 552 (`params=published_slug,response_session_id` only) vs. line 115 (`/api/v1/kyc/applications/{application_id}/submit` has `Idempotency-Key`).

### Corrections made

- Path params corrected to `{published_slug}` / `{response_session_id}` throughout (Sections 1, 4, 5).
- Submit request body corrected from optional `{}` to required `QuestionnaireValidationRequest` (`answers_by_question_id` + `final_submit`) (Sections 4, 5).
- Submit response corrected from invented `SubmissionResult{submission_id,status,submitted_at}` to `SessionSubmitEnvelope{session,result}`; removed all reliance on a server `submission_id` (Sections 1, 4, 5, 6, 14 AC-1).
- Validation-error transport corrected from "422 `detail[]`" to "200 `result.errors` map gated by `can_submit`", including `group:`/`form:` keys and `ValidationIssue` shape (Sections 4, 5, 7, 14 AC-3).
- PDF clarified: two endpoints, keyed by `response_session_id` (R-2 resolved); Android uses GET; web has no PDF precedent (Section 5, 13).
- Open Questions updated: Q-1 resolved (body required), Q-2 narrowed (generate-before-download ordering), R-2 resolved.

### Open assumptions

- **Public `/respond` App Link suffix (claim 11):** the literal `.../published/{slug}/respond` path is a web SPA client route, not a backend API route; it is not present in OpenAPI and the respondent page route was not confirmable from the supplied frontend files. Treated as an unverified assumption carried from the ticket; confirm the exact web URL before freezing the `navDeepLink` `uriPattern` and `assetlinks.json` path prefix.
- **PDF generate-before-download ordering (Q-2):** whether `POST .../pdf` must run before `GET .../pdf` is not derivable from the OpenAPI index alone; verify against a live dev response.
- **`session.status` field name (FR-7 / confirmation):** the terminal status is read from the opaque `session` object (`additionalProperties: true` in `SessionSubmitEnvelope.session` / `SessionStateEnvelope.session`); the exact status field name/value is not in the schema and must be confirmed from a live response.
- **Production App Link host(s) (Q-4):** not present in any source; product/infra input required.

## 17. Test Plan

Targets: JVM = JVM unit/Robolectric (local); test35 = headless emulator AVD (x86_64, API 35); A15 = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Most cases here are JVM/contract/Compose and run on the emulator or locally; the App Link + real PDF-viewer cases note where the physical device adds value.

- **TC-AND-349-01** — Submit happy path.
  Type: unit (JVM + MockWebServer). Target: JVM. Preconditions: valid `response_session_id`, local validation passes.
  Steps: enqueue 200 `SessionSubmitEnvelope` with `result.is_valid=true, can_submit=true, errors={}`; call `onSubmit()`.
  Expected: repo POSTs to `.../sessions/{response_session_id}/submit` with body `{answers_by_question_id, final_submit:true}`; phase → `SubmitPhase.Submitted(sessionId, status)`; no field errors. Traces: AC-1.
- **TC-AND-349-02** — Server validation failure (200 with blocking errors).
  Type: unit (JVM + MockWebServer). Target: JVM. Preconditions: session exists.
  Steps: enqueue 200 `SessionSubmitEnvelope` with `result.can_submit=false`, `errors={"q3":[{"code":"required","message":"Field required","blocking":true}]}`; call `onSubmit()`.
  Expected: phase stays editable (`Idle`, no `Submitted`); `fieldErrors["q3"]` populated from `ValidationIssue.message`; scroll-to-first-error effect emitted; group:/form: keys handled. Traces: AC-3.
- **TC-AND-349-03** — Genuine 422 (malformed request) is a generic error, not field mapping.
  Type: contract/MockWebServer. Target: JVM. Preconditions: session exists.
  Steps: enqueue 422 `{"detail":[{"loc":["body","final_submit"],"msg":"...","type":"..."}]}`; call `onSubmit()`.
  Expected: phase → `SubmitPhase.Error` (retryable/generic banner); NO per-field mapping; draft preserved. Traces: AC-3, AC-6.
- **TC-AND-349-04** — Submit network/timeout failure preserves draft, no auto-retry.
  Type: unit (JVM + MockWebServer). Target: JVM. Preconditions: session exists; draft saved.
  Steps: simulate socket timeout / no response on POST submit.
  Expected: `repo.saveDraft` was still invoked (FR-2a); phase → `Error` (retryable); POST is NOT auto-retried (assert single request). Traces: AC-6.
- **TC-AND-349-05** — Double-submit guard.
  Type: unit (JVM). Target: JVM. Preconditions: session exists.
  Steps: invoke `onSubmit()` twice rapidly (first in-flight).
  Expected: only one POST issued; second call ignored while phase is `Submitting`; button disabled state reflected in `uiState`. Traces: AC-4.
- **TC-AND-349-06** — Reopen terminal session seeds confirmation state.
  Type: unit (JVM + Robolectric for DataStore/Room). Target: JVM. Preconditions: persisted session record marked terminal.
  Steps: construct `RespondViewModel` for that session.
  Expected: initial `uiState.submit == SubmitPhase.Submitted(sessionId, status)`; form not editable; Download PDF available. Traces: AC-7.
- **TC-AND-349-07** — PDF download persists bytes and yields content URI.
  Type: unit/Robolectric (JVM) + MockWebServer. Target: JVM. Preconditions: terminal session.
  Steps: enqueue 200 `application/pdf` byte body on `GET .../pdf`; call `onDownloadPdf()`.
  Expected: `GET .../sessions/{response_session_id}/pdf` (streaming) issued; bytes written to `cacheDir/respond-pdfs/<sessionId>.pdf`; byte integrity matches; `PdfExportState.Ready(contentUri)` via FileProvider authority `${packageName}.fileprovider`. Traces: AC-5.
- **TC-AND-349-08** — PDF GET retries (idempotent) on transient failure; submit POST does not.
  Type: contract/MockWebServer. Target: JVM. Preconditions: session exists.
  Steps: enqueue one 503 then 200 on `GET .../pdf`; separately one 503 on `POST .../submit`.
  Expected: GET retried per bounded backoff and ultimately succeeds; POST submit makes exactly one attempt then surfaces error. Traces: AC-6.
- **TC-AND-349-09** — Compose UI: submit enabled/disabled + confirmation render.
  Type: Compose-UI. Target: test35. Preconditions: rendered respondent screen.
  Steps: with local validation failing then passing, observe Submit button; drive to `Submitted` state.
  Expected: button disabled when invalid/in-flight, enabled when valid; confirmation shows message + Download PDF (no submission-id label, since none returned); field-error text shown for `result.errors`. Traces: AC-1, AC-3, AC-4.
- **TC-AND-349-10** — Compose-UI accessibility checks.
  Type: Compose-UI (semantics). Target: test35. Preconditions: confirmation + error states rendered.
  Steps: assert semantics tree.
  Expected: Submit/confirmation/Download-PDF have contentDescription/semantics; submit result announced via `liveRegion`; errored fields carry `error=true` semantics; touch targets ≥48dp; all strings from `strings.xml`. Traces: AC-1, AC-3, AC-5.
- **TC-AND-349-11** — Deep link cold-start routing.
  Type: instrumented/e2e (Espresso-Intents). Target: A15 (preferred — real cold start / package-manager App Link behavior and API-34 vs API-35 intent handling) or test35 for CI.
  Steps: from killed app, `adb shell am start -a android.intent.action.VIEW -d "https://<host>/questionnaires/published/<slug>/respond"`.
  Expected: `MainActivity` launches and lands on `RespondScreen(slug=<slug>)` while anonymous; `respond_applink_opened{slug, cold_start=true}` logged. Traces: AC-2.
- **TC-AND-349-12** — PDF chooser launch + missing-viewer fallback.
  Type: instrumented/e2e. Target: A15 (preferred — real installed PDF viewers / share targets; emulator may lack a PDF handler). Preconditions: terminal session, PDF ready.
  Steps: tap Download PDF; (a) with a PDF viewer installed; (b) with none (assert `ActivityNotFoundException` path).
  Expected: (a) `ACTION_VIEW` chooser with `application/pdf` + `FLAG_GRANT_READ_URI_PERMISSION` opens the file (Espresso `intended`); (b) snackbar "Share file" fallback, no crash. Traces: AC-5.
- **TC-AND-349-13** — App Link autoVerify behavior dev vs prod (manual).
  Type: manual. Target: A15 (real on-device verification status). Preconditions: dev build (plaintext host) and a prod-config build.
  Steps: `adb shell pm verify-app-links --re-verify <pkg>`; `adb shell pm get-app-links <pkg>`.
  Expected: dev host shows unverified (R-1) and relies on manual handling; prod build with served `assetlinks.json` shows `verified`. Traces: AC-2.
- **TC-AND-349-14** — Offline submit messaging + draft safety.
  Type: integration. Target: A15 (toggle real airplane mode for genuine `NetworkError`) or test35 with network off. Preconditions: editable session with unsaved answers.
  Steps: disable network; tap Submit.
  Expected: offline message "You're offline — your answers are saved…"; draft persisted locally (AND-348); retry succeeds once network restored. Traces: AC-6.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (submit success → confirmation, no server id) | TC-01, TC-09 |
| AC-2 (public link opens respondent, cold start) | TC-11, TC-13 |
| AC-3 (validation errors mapped, form editable) | TC-02, TC-03, TC-09, TC-10 |
| AC-4 (in-flight disable / double-submit guard) | TC-05, TC-09 |
| AC-5 (PDF download → cache → chooser; viewer-missing fallback) | TC-07, TC-10, TC-12 |
| AC-6 (network failures retryable, draft preserved; GET retries, POST not) | TC-03, TC-04, TC-08, TC-14 |
| AC-7 (reopen terminal session → confirmation) | TC-06 |
