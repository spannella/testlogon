---
id: AND-349
title: Submit + PDF (public respond)
milestone: M7
epic: E45
priority: P1
size: L
status: draft
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
   `/questionnaires/published/{slug}/sessions/{session_id}/submit` endpoint, with
   server-side validation surfacing and a terminal confirmation state.
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
  authenticated `ui_csrf` session required); they operate on an opaque
  `session_id` minted by AND-348's session-start call. The cookie jar (AND-009)
  still applies so any per-session cookies the backend sets are persisted.
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

FR-3. **Server validation surfacing.** If the backend returns a 422 with per-field
validation errors, the UI maps them back onto the corresponding rendered fields
(field-keyed error messages) and scrolls the first errored field into view; no
terminal confirmation is shown.

FR-4. **Confirmation state.** On a successful submit (2xx), the screen transitions
to a terminal `Submitted` state showing a confirmation message, the submission id,
and a **"Download PDF"** action. The form is no longer editable.

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
sealed interface SubmitPhase {
    data object Idle : SubmitPhase
    data object Submitting : SubmitPhase
    data class Submitted(val submissionId: String) : SubmitPhase
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
        when (val r = repo.submit(uiState.value.slug, sid)) {
            is ApiResult.Success ->
                setSubmitPhase(SubmitPhase.Submitted(r.data.submissionId))
            is ApiResult.HttpError ->
                handleSubmitError(r)                    // 422 -> fieldErrors (FR-3)
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
    suspend fun submit(slug: String, sessionId: String): ApiResult<SubmissionResult>
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

All paths are public (anonymous, no `X-CSRF-Token` required). `{slug}` and
`{session_id}` come from AND-348. **Field names must be reconciled against
`frontend/src/api/endpoints/*.ts` and `/openapi.json` before freezing DTOs.**

### Submit

```
POST /questionnaires/published/{slug}/sessions/{session_id}/submit
Content-Type: application/json

Request body (optional — answers already saved by AND-348's save call):
{ }

200/201 Response:
{
  "submission_id": "sub_8f3a...",
  "status": "submitted",
  "submitted_at": "2026-06-05T14:22:10Z"
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class SubmissionResult(
    @Json(name = "submission_id") val submissionId: String,
    @Json(name = "status") val status: String,
    @Json(name = "submitted_at") val submittedAt: String?,
)
```

**422 validation error** uses the standard FastAPI `detail` shape (string |
`[{msg, loc}]` | `{code,...}`); the array form is mapped to `fieldErrors` keyed by
the field id parsed from `loc`:

```json
{ "detail": [ { "loc": ["body", "answers", "q3"], "msg": "Field required" } ] }
```

### PDF export

```
GET /questionnaires/published/{slug}/sessions/{session_id}/pdf
Accept: application/pdf

200 Response: binary PDF (application/pdf)
```

```kotlin
@GET("questionnaires/published/{slug}/sessions/{sessionId}/pdf")
@Streaming
suspend fun getSubmissionPdf(
    @Path("slug") slug: String,
    @Path("sessionId") sessionId: String,
): Response<ResponseBody>
```

If the backend exposes PDF under a submission id rather than session id (verify in
OpenAPI), the path becomes `/.../submissions/{submission_id}/pdf` and `fetchPdf`
takes the `submissionId` from `SubmissionResult` — this is an Open Question (Q-2).

## 6. Data & State Management

- **State holder:** `RespondViewModel.uiState: StateFlow<RespondUiState>`. Submit
  and PDF phases are part of this single state object (Section 4).
- **One-shot effects:** PDF chooser launch and "scroll to first error" are
  modeled as effects (a `Channel<RespondEffect>` exposed as `Flow`, collected in
  a `LaunchedEffect`) so they don't re-fire on recomposition/rotation.
- **Persisted terminal state (FR-7):** the submitted status is persisted by
  AND-348's session store (Room/DataStore). On screen entry, if the stored
  session status is terminal, `uiState.submit` is seeded with
  `SubmitPhase.Submitted(submissionId)`. No new table is introduced; AND-349 adds
  a `submission_id` / `status` column or DataStore key to the existing session
  record (coordinate with AND-348).
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
- **422 vs 5xx:** 422 → field-level errors, stay editable (FR-3); 5xx/network →
  retryable banner, draft preserved (FR-8).
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
- **R-2 (PDF identifier):** unclear whether PDF is keyed by `session_id` or
  `submission_id`. Q-2 — confirm in `/openapi.json` / `frontend` endpoints.
- **R-3 (submit idempotency):** if the network drops after the server commits but
  before the response, a user retry may double-submit. Mitigation: if the backend
  returns the existing submission on resubmit of a terminal session, treat that as
  success; otherwise file a backend idempotency-key request (Q-3).
- **Q-1:** Does submit require the answers in the body, or only the prior save?
  (Body modeled as optional; confirm.)
- **Q-2:** PDF path keying (session vs submission id).
- **Q-3:** Server-side submit idempotency guarantee.
- **Q-4:** Exact `host` value(s) for production App Link string resource.

## 14. Acceptance Criteria

- **AC-1 (backlog):** Submitting a fully-completed, locally-valid session
  completes successfully and the screen shows the terminal confirmation state with
  the returned submission id. (Covered by unit + Compose tests.)
- **AC-2 (backlog):** The public link
  `https://<host>/questionnaires/published/{slug}/respond` opens the respondent
  screen for `{slug}` — verified on cold start via an instrumented intent test and
  manual `adb am start`.
- **AC-3:** A 422 from submit maps server errors to the correct fields, keeps the
  form editable, and scrolls the first error into view; no confirmation is shown.
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
