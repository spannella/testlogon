---
id: AND-395
title: Public questionnaire respond
milestone: M8
epic: E51
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-349]
blocks: []
---

# AND-395 — Public questionnaire respond

## 1. Overview & Goal

This ticket wires up the **public (unauthenticated) respondent entry point** for
the TestLogon native Android app: the path by which an anonymous, cookie-less user
arrives at a published questionnaire by `slug`, is minted/handed an anonymous
respondent session, and is dropped into the existing respondent renderer +
submit/PDF flow so that **a public respondent submits**.

AND-349 already delivered the *terminal* half of the public-respond loop inside
`feature-respond`: the dynamic renderer (AND-347), the respondent session machinery
(AND-348), the **Submit** action, **PDF export**, and the public App Link
`navDeepLink` attached to the `RespondRoute`. What AND-349 assumes — and what this
ticket owns — is the **unauthenticated *entry*** that precedes the editable form:
the public entry screen/route that resolves a `slug` to a published questionnaire,
starts an anonymous session when none exists, and guarantees the whole chain works
with **no authenticated `ui_csrf` session present** (cold app, never-logged-in
user, no auth cookies in the jar).

Concretely, AND-395 delivers:

1. A **public entry composable + route** (`PublicRespondRoute`) reachable from the
   unauthenticated nav graph (AND-023) and from the App Link deep link, that loads
   the published questionnaire metadata for a `slug` and starts/resumes an anonymous
   session before handing off to AND-347/348/349's `RespondScreen`.
2. **Anonymous session bootstrapping** — calling AND-348's session-start with no
   auth context, persisting only the opaque `session_id` and any per-session cookie,
   and ensuring the CSRF interceptor (AND-012) and 401-refresh authenticator
   (AND-013) do **not** fire for these anonymous public calls.
3. The **end-to-end acceptance**: a public respondent (unauth) opens the link/route,
   fills, and **submits** successfully, reaching AND-349's `Submitted` confirmation
   state.

Out of scope (owned elsewhere): the renderer itself (AND-347), session save/validate
(AND-348), submit/PDF/App-Link verification (AND-349), questionnaire DTOs (AND-346),
questionnaire authoring/publishing (separate epic), and authenticated "my responses"
history.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose typed routes, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 +
  OkHttp 4.12 + Moshi 1.15, Room 2.6 + DataStore. minSdk 24, compileSdk/targetSdk 35,
  JDK 17, AGP 8.7.3, Gradle 8.9 wrapper.
- **Module:** extends `feature-respond` (introduced by AND-347/348, completed by
  AND-349). No new module is created. The public entry lives in
  `com.testlogon.android.feature.respond.public`. Layering:
  `app → feature-respond → core-network, core-model, core-data, core-ui`.
- **Namespace / applicationId base:** `com.testlogon.android` (used everywhere a
  package or authority appears).
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` is plaintext
  HTTP and **unreliable** — design for ~20s timeouts, bounded backoff retry for
  idempotent GETs only, and offline/stale UI states. OpenAPI at `/openapi.json`. Web
  reference under `frontend/` (`frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts`) is the canonical contract source — reconcile exact
  field names there before freezing DTOs.
- **Auth context:** the public respond endpoints are **anonymous**. No authenticated
  session, no `X-CSRF-Token` header on these calls. The persistent cookie jar
  (AND-011) still persists any per-session cookie the backend sets for the anonymous
  session. The 401-refresh authenticator (AND-013) must be suppressed for these
  requests (a 401 here means "session expired / not found", not "refresh the auth
  session").
- **Dependencies:**
  - **AND-349 — Submit + PDF (public respond)** (hard dep). Provides `RespondScreen`,
    `RespondViewModel`/`RespondUiState`, `RespondRepository` (start/save/validate/
    submit/fetchPdf), the persisted session store, and the App Link `navDeepLink` on
    `RespondRoute`. AND-395 builds the *entry* that feeds these.
  - **AND-348 / AND-347 / AND-346** (transitive via AND-349): session model + repo,
    renderer field model, questionnaire DTOs and `QuestionnaireApi`.
  - **AND-023 — Unauthenticated nav graph**: the public entry route is registered in
    the unauth graph so it is reachable without a login gate (AND-025 must not block
    it).
  - **AND-018 / AND-015**: `ApiResult<T>` and FastAPI `detail` mapping.

## 3. Functional Requirements

FR-1. **Public entry route.** A typed route `PublicRespondRoute(slug)` is reachable
(a) from the unauthenticated nav graph and (b) via the AND-349 App Link
`https://<host>/questionnaires/published/{slug}/respond`. It requires no login.

FR-2. **Published-questionnaire load.** On entry, the screen GETs the published
questionnaire by `slug` to confirm it exists and is published, showing a loading
state, then a `NotFound` state for 404/422 (not found / unpublished) or an error state
for transport failure.

FR-3. **Anonymous session bootstrap.** If no persisted session exists for the `slug`,
the screen starts an anonymous session (AND-348's start call) with **no auth
context**, persists the returned `session_id`, then hands off to the renderer. If a
non-terminal persisted session exists, it is resumed. If a terminal (submitted)
session exists, it routes to AND-349's `Submitted` confirmation (per AND-349 FR-7).

FR-4. **Hand-off to renderer.** Once a `session_id` is available, the public entry
navigates/forwards into AND-349's `RespondScreen(slug, sessionId)` so the user can
fill, save, validate, **submit**, and export a PDF. The public entry does not
re-implement form rendering.

FR-5. **Unauthenticated guarantee.** The entire flow works with an empty/auth-less
cookie jar and a cold-started app. No call in this path attaches `X-CSRF-Token`, and
a 401 does not trigger the auth-session refresh (AND-013) or bounce to login.

FR-6. **End-to-end submit (backlog AC).** A public respondent who opens the
link/route, fills required fields, and taps Submit reaches AND-349's terminal
`Submitted` state with a submission id — with no prior authentication.

FR-7. **Resilience.** Slug-load and session-start failures (timeout, 5xx, offline)
present a **retryable** error without crashing; the load GET is idempotent and uses
the project's bounded backoff retry, session-start (POST) does not auto-retry.

FR-8. **Re-entry idempotency.** Re-opening the same `slug` while a session is in
progress resumes the existing session rather than starting a duplicate one.

## 4. Technical Design

### Route & nav wiring (AND-023 / AND-349 integration)

AND-349's `RespondRoute` is the renderer route and carries the App Link deep link.
AND-395 introduces a thin **public entry** route that resolves the `slug` and
session before forwarding to it. The App Link can target `PublicRespondRoute`
directly (it is the unauth landing); the deep link declared in AND-349 is re-pointed
here, with `RespondRoute` reached internally once a `sessionId` exists.

```kotlin
@Serializable
data class PublicRespondRoute(val slug: String)

// Registered into the AND-022 NavHost via the unauthenticated graph (AND-023):
fun NavGraphBuilder.publicRespondGraph(navController: NavController) {
    composable<PublicRespondRoute>(
        deepLinks = listOf(
            navDeepLink {
                uriPattern = "https://{host}/questionnaires/published/{slug}/respond"
                action = Intent.ACTION_VIEW
            }
        )
    ) { backStackEntry ->
        val args = backStackEntry.toRoute<PublicRespondRoute>()
        PublicRespondScreen(
            slug = args.slug,
            onSessionReady = { sessionId ->
                navController.navigate(RespondRoute(args.slug, sessionId)) {
                    popUpTo<PublicRespondRoute> { inclusive = true }
                }
            },
            onSubmittedSession = { sessionId ->          // FR-3 terminal case
                navController.navigate(RespondRoute(args.slug, sessionId)) {
                    popUpTo<PublicRespondRoute> { inclusive = true }
                }
            },
        )
    }
}
```

This route is added to the **unauthenticated** graph so AND-025's auth gate does not
redirect it to login. `RespondRoute` remains the editable/terminal form route owned
by AND-347/348/349.

### Entry ViewModel

```kotlin
sealed interface PublicEntryState {
    data object Loading : PublicEntryState
    data class Ready(val sessionId: String, val terminal: Boolean) : PublicEntryState
    data object NotFound : PublicEntryState          // 404 / unpublished
    data class Error(val message: String) : PublicEntryState
}

@HiltViewModel
class PublicRespondViewModel @Inject constructor(
    private val repo: RespondRepository,             // from AND-348/349
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val slug: String = savedStateHandle.toRoute<PublicRespondRoute>().slug
    private val _state = MutableStateFlow<PublicEntryState>(PublicEntryState.Loading)
    val state: StateFlow<PublicEntryState> = _state.asStateFlow()

    init { bootstrap() }

    fun retry() = bootstrap()

    private fun bootstrap() = viewModelScope.launch {
        _state.value = PublicEntryState.Loading
        when (val meta = repo.loadPublished(slug)) {            // FR-2 (idempotent GET)
            is ApiResult.Success -> resolveSession()
            is ApiResult.HttpError ->
                _state.value = if (meta.code == 404 || meta.code == 422) PublicEntryState.NotFound
                               else PublicEntryState.Error(meta.detailMessage())  // 404 or 422 → not found (see §16)
            is ApiResult.NetworkError, is ApiResult.Timeout ->
                _state.value = PublicEntryState.Error(/* offline/retryable */)
        }
    }

    private suspend fun resolveSession() {
        val existing = repo.persistedSession(slug)              // FR-8 / FR-3
        if (existing != null) {
            _state.value = PublicEntryState.Ready(existing.id, existing.isTerminal)
            return
        }
        when (val started = repo.startAnonymousSession(slug)) { // POST, no auto-retry
            is ApiResult.Success ->
                _state.value = PublicEntryState.Ready(
                    started.data.session.responseSessionId, terminal = false)   // see §5/§16: response_session_id
            else ->
                _state.value = PublicEntryState.Error(/* retryable */)
        }
    }
}
```

`startAnonymousSession` is AND-348's existing session-start; AND-395 only guarantees
it is invoked **with no auth/CSRF context**. If AND-348 already exposes a generic
`startSession`, AND-395 calls it; the "anonymous" semantics come from the request
not carrying auth (Section 8), not from a separate endpoint.

### Composable

```kotlin
@Composable
fun PublicRespondScreen(
    slug: String,
    onSessionReady: (sessionId: String) -> Unit,
    onSubmittedSession: (sessionId: String) -> Unit,
    vm: PublicRespondViewModel = hiltViewModel(),
) {
    val state by vm.state.collectAsStateWithLifecycle()
    when (val s = state) {
        PublicEntryState.Loading  -> LoadingState()                       // core-ui (AND-021)
        is PublicEntryState.Ready ->
            LaunchedEffect(s.sessionId) {
                if (s.terminal) onSubmittedSession(s.sessionId)
                else onSessionReady(s.sessionId)
            }
        PublicEntryState.NotFound -> NotFoundState(slug)                  // empty/error variant
        is PublicEntryState.Error -> ErrorState(s.message, onRetry = vm::retry)
    }
}
```

The hand-off is a one-time navigation effect keyed on `sessionId`; the entry route is
popped so the Back button from the form does not return to the loading shim.

## 5. API Contract

This ticket adds **no new endpoints**; it consumes AND-346/348/349 contracts in an
anonymous context. Field names must be reconciled against
`frontend/src/api/endpoints/*.ts` and `/openapi.json` before freezing DTOs.

> **Reviewer note (AND-395 review 2026-06-06):** the path parameter is
> `{published_slug}` (not `{slug}`), the published GET and submit responses are
> **enveloped**, the start-session response carries the id as
> `session.response_session_id` (NOT a top-level `session_id`), and start returns
> **HTTP 200** (not 201). Corrected below; see §16 for source pointers.

### Load published questionnaire (FR-2, idempotent GET)

```
GET /questionnaires/published/{published_slug}
Accept: application/json

200 Response (envelope; version owned by AND-346):
{ "version": {
    "questionnaire_id": "...", "version_id": "...", "version_number": 1,
    "published_slug": "onboarding-2026",
    "visibility": "public" | "unlisted" | "private",
    "allow_anonymous": true,
    "schema_json": { ... }, "published_at": "..." } }

422 Response: HTTPValidationError (the only documented non-200; a missing/unpublished
slug surfaces as 422 or a runtime 404 — see Q-1/§16). "Published & anonymous-allowed"
is read from version.visibility / version.allow_anonymous, not a top-level `status`.
```

The published-load returns `PublishedQuestionnaireEnvelope` = `{ version: ... }`
(verified against the OpenAPI spec and `frontend/src/api/endpoints/questionnaires.ts:
getPublishedQuestionnaireBySlug`, which types it as `{ version: PublishedQuestionnaireVersion }`).
There is **no** top-level `slug`/`title`/`status`/`fields`.

### Start anonymous session (FR-3, owned by AND-348)

```
POST /questionnaires/published/{published_slug}/sessions
Content-Type: application/json
(no X-CSRF-Token, no auth cookies required)
Body: {}    # web posts an empty object; ResponseSessionStartReq.questionnaire_id is optional

200 Response (envelope; ResponseSessionEnvelope):
{ "session": {
    "response_session_id": "...", "questionnaire_id": "...", "version_id": "...",
    "status": "in_progress", "started_at": "...",
    "current_section_index": 0, "respondent_id": null } }
```

```kotlin
// Envelope: ResponseSessionEnvelope = { "session": { ... } }
@JsonClass(generateAdapter = true)
data class RespondSessionEnvelope(
    @Json(name = "session") val session: RespondSessionState,
)

@JsonClass(generateAdapter = true)
data class RespondSessionState(
    @Json(name = "response_session_id") val responseSessionId: String,  // NOT "session_id"
    @Json(name = "questionnaire_id") val questionnaireId: String,
    @Json(name = "version_id") val versionId: String,
    @Json(name = "status") val status: String,                          // "in_progress" | "submitted"
    @Json(name = "started_at") val startedAt: String,
    @Json(name = "current_section_index") val currentSectionIndex: Int? = null,
    @Json(name = "current_question_id") val currentQuestionId: String? = null,
    @Json(name = "respondent_id") val respondentId: String? = null,
)
```

### Submit (terminal, owned by AND-349) — referenced for the end-to-end AC

```
POST /questionnaires/published/{published_slug}/sessions/{response_session_id}/submit
Content-Type: application/json
Body: the validation request (QuestionnaireValidationRequest; web sends the answer map)

200 Response (envelope; SessionSubmitEnvelope):
{ "session": { ... "status": "submitted" ... }, "result": QuestionnaireValidationResponse }
```

There is **no** `submission_id` or `submitted_at` field; terminality is derived from
`session.status == "submitted"`. (Verified: OpenAPI `SessionSubmitEnvelope` and
`frontend/src/api/endpoints/questionnaires.ts: submitPublishedResponseSession` typed
as `{ session, result }`.)

Errors use the FastAPI `detail` union (string | `[{msg, loc}]` | `{code,...}`) mapped
per AND-015. AND-395 confirms these endpoints are callable anonymously and freezes the
field names above against `/openapi.json` and `frontend/src/api` (Open Question Q-1
narrowed — see §16).

## 6. Data & State Management

- **Entry state holder:** `PublicRespondViewModel.state: StateFlow<PublicEntryState>`
  — a small loading/ready/not-found/error machine separate from the rich
  `RespondUiState` (which is owned by AND-349 on `RespondRoute`).
- **Session persistence:** reuses AND-348's persisted session store (Room/DataStore)
  keyed by `slug`; AND-395 reads it (`persistedSession(slug)`) for resume/terminal
  routing (FR-3/FR-8) and writes the `session_id` returned by start. No new table is
  introduced.
- **Process death:** `slug` is in the typed route (survives via SavedState). On
  re-entry the ViewModel re-runs `bootstrap()`; an already-persisted session resumes
  without a duplicate start (FR-8).
- **One-shot hand-off:** the `Ready → navigate` transition is a navigation effect in
  a `LaunchedEffect` keyed on `sessionId`, not re-fired on recomposition/rotation,
  and pops the entry route off the back stack.
- **No PDF/cache logic here** — PDF persistence is AND-349's `PdfExporter`.

## 7. Error Handling & Resilience

- **Typed results:** `loadPublished`/`startAnonymousSession` return `ApiResult<T>`;
  `detail` mapping per project convention (string | `[{msg}]` | `{code,...}`).
- **Timeouts:** 20s OkHttp call timeout (dev host unreliable).
- **Retry policy:** the published-load **GET is idempotent** → project bounded
  backoff retry (≈2 jittered retries) at the OkHttp interceptor (AND-016). Session
  **start is a POST → no auto-retry**; a user-driven "Retry" re-runs `bootstrap()`.
- **Not-found vs 5xx:** the OpenAPI declares only `200`/`422` for the published GET, so
  a missing/unpublished slug arrives as **422** (HTTPValidationError) or a runtime
  **404** (the dev backend is not fully documented — see §16/Q-1). Treat **both 404 and
  422** as `NotFound` ("This questionnaire isn't available"); 5xx/network/timeout →
  retryable `Error` state.
- **Offline:** `NetworkError` → "You're offline — connect to open this
  questionnaire," with Retry. (Offline *draft* save remains AND-348's; submit is
  online-only per AND-349.)
- **No login bounce:** a 401 on these anonymous calls is surfaced as a retryable
  error, **not** routed through AND-013 refresh or the login gate (Section 8).
- **Duplicate-start guard:** resume-before-start ordering (FR-8) prevents two
  sessions for the same `slug`.

## 8. Security & Privacy

- **Anonymous endpoints:** the published-load and session-start calls require no auth
  session and must **not** attach the authenticated `X-CSRF-Token` header. Implement
  via an opt-out marker so AND-012's CSRF interceptor and AND-013's refresh
  authenticator skip these requests, e.g. a Retrofit `@Tag`. **Note:** the web
  reference does not use a per-request tag — `src/api/client.ts` attaches
  `X-CSRF-Token` only when a `ui_csrf` cookie is present and only fires the
  `POST /ui/session/refresh` 401-refresh when `isAuthenticated` is true (an
  unauthenticated 401 propagates directly). The `Anonymous` tag below is the
  equivalent Android-side mechanism, not a mirror of a web tag (see §16).

  ```kotlin
  object Anonymous                                  // request tag marker (Android-side; see §16)
  @GET("questionnaires/published/{published_slug}")
  suspend fun getPublished(@Path("published_slug") slug: String, @Tag anon: Anonymous = Anonymous):
      Response<PublishedQuestionnaireEnvelope>
  // CsrfInterceptor / RefreshAuthenticator: if request.tag(Anonymous::class.java) != null -> pass through
  ```

- **Cookie jar:** the persistent jar (AND-011) still stores any per-session cookie
  the backend sets for the anonymous session; no auth cookies are required or
  expected.
- **PII:** respondent answers are not entered on this entry screen and are never
  logged; do not log `session_id` at `info`+.
- **App Link verification:** `autoVerify` requires HTTPS + a served
  `/.well-known/assetlinks.json`; the dev plaintext-HTTP IP host cannot satisfy this
  (inherited Risk from AND-349 R-1). Per-build-type gating applies.
- **Cleartext:** dev build keeps the network-security-config allowlist for
  `18.222.237.167` only (project-wide config, not new here).

## 9. Accessibility & i18n

- Loading, NotFound, and Error states (from core-ui AND-021) carry semantics; the
  Error state's Retry button has a `contentDescription` and a ≥48dp touch target.
- The loading/handoff transition announces via `liveRegion` so TalkBack users hear
  the questionnaire is opening; the entry shim is fully keyboard/switch-accessible.
- All user-facing strings (loading label, "not available" message, offline/retry
  copy) live in `strings.xml` (no hardcoded text); supports RTL.
- The entry screen renders no locale-sensitive data itself; form/date formatting is
  the renderer's (AND-347/349) responsibility.

## 10. Telemetry & Logging

- Events (app analytics abstraction, no PII in params):
  `public_respond_opened{slug, cold_start}`,
  `public_respond_load_failed{slug, error_kind}`,
  `public_respond_session_started{slug}`,
  `public_respond_session_resumed{slug, terminal}`,
  `public_respond_not_found{slug}`.
- The end-to-end submit success continues to fire AND-349's
  `respond_submit_succeeded{slug}` from `RespondRoute`.
- Logging: Timber at `debug` for the entry request lifecycle; never log `session_id`,
  cookies, or answer payloads at `info`+. Load/start HTTP failures logged with status
  code + sanitized `detail` only.

## 11. Testing Strategy

- **Unit (JUnit + Turbine + MockWebServer, core-testing):**
  - `bootstrap` happy path: 200 published + 201 session-start → `Ready(sessionId,
    terminal=false)`.
  - Resume: persisted non-terminal session → `Ready` with the existing id, **no**
    session-start POST issued (FR-8).
  - Terminal resume: persisted submitted session → `Ready(terminal=true)` → routes to
    `Submitted` (FR-3).
  - 404 published → `NotFound`; 5xx/network/timeout → retryable `Error`; `retry()`
    re-runs and succeeds.
  - **Anonymous guarantee:** MockWebServer asserts the load + start requests carry
    **no `X-CSRF-Token` header** and that a 401 does **not** trigger a
    `POST /ui/session/refresh` (AND-013) nor a login navigation.
- **Repository:** asserts correct path/verb (`GET .../published/{published_slug}`,
  `POST .../published/{published_slug}/sessions` with empty `{}` body), `detail`
  parsing, and `RespondSessionEnvelope`/`RespondSessionState` mapping (id read from
  `session.response_session_id`).
- **Instrumented / deep link:** an `androidx.test` intent with
  `https://.../questionnaires/published/{slug}/respond` on a **cold-started,
  logged-out** app launches `MainActivity`, hits `PublicRespondScreen`, and forwards
  into `RespondScreen(slug, sessionId)` (Espresso-Intents `intended` /
  `composeTestRule` assertions).
- **Compose UI:** loading → ready hand-off; NotFound copy; Error + Retry restores
  loading then content.
- **End-to-end (AC, backlog):** from the public link with an empty cookie jar, fill +
  Submit reaches AND-349's `Submitted` state (instrumented, against MockWebServer
  fixtures).
- **Manual/dev:** `adb shell am start -a android.intent.action.VIEW -d "<url>"` with
  the app logged out; confirm no login prompt and a successful submit.

## 12. Dependencies & Sequencing

- **Hard dep:** **AND-349** (and transitively AND-346/347/348/022/023) — provides the
  renderer, `RespondRepository` (load/start/save/validate/submit/fetchPdf), persisted
  session store, `RespondRoute`, and the App Link `navDeepLink`. AND-349 must merge
  first.
- **Soft/coordination:** AND-012 (CSRF interceptor) and AND-013 (401-refresh
  authenticator) must honor the `Anonymous` request tag opt-out (Section 8); AND-023
  must register `PublicRespondRoute` in the unauth graph and AND-025 must not gate it.
- **Blocks:** none (backlog lists no downstream blockers; terminal node of the E51
  public-respond entry chain).
- **Sequencing within ticket:** (1) `Anonymous` tag opt-out in CSRF/refresh +
  `loadPublished`/`startAnonymousSession` repo surface (or confirm AND-348's
  existing methods suffice), (2) `PublicRespondViewModel` entry state machine,
  (3) `PublicRespondScreen` + unauth-graph route + deep-link re-point + hand-off,
  (4) tests.

## 13. Risks & Open Questions

- **R-1 (App Link on dev host):** inherited from AND-349 — `autoVerify` needs HTTPS +
  `assetlinks.json`; the plaintext-HTTP dev IP cannot be verified. Mitigation: gate
  `autoVerify` per build type; dev uses manual `adb` link launch.
- **R-2 (anonymous interceptor leakage):** if the `Anonymous` tag opt-out is missed,
  a 401 could trigger AND-013 refresh and bounce a public user toward login.
  Mitigation: explicit MockWebServer test asserting no refresh/no CSRF on these calls.
- **R-3 (duplicate sessions):** a race between cold-start deep link and a stored
  session could double-start. Mitigation: resume-before-start ordering (FR-8) +
  single-flight in the ViewModel.
- **Q-1 (RESOLVED in this review):** Paths/shapes confirmed against `/openapi.json`
  and `frontend/src/api` — `GET /questionnaires/published/{published_slug}` →
  `{ version: PublishedQuestionnaireVersion }`; `POST .../sessions` →
  `{ session: { response_session_id, status, ... } }` at HTTP 200. The one residual
  unknown is whether a missing/unpublished slug returns 404 or 422 at runtime (OpenAPI
  only documents 200/422); we handle both as `NotFound`. See §16.
- **Q-2 (RESOLVED):** Session-start body is **empty** — the web client posts `{}` and
  `ResponseSessionStartReq` exposes only an optional `questionnaire_id`. Modeled empty.
- **Q-3:** Should the App Link land on `PublicRespondRoute` (this ticket) or stay on
  `RespondRoute` (AND-349) with entry resolution inline? (Spec routes via
  `PublicRespondRoute`; reconcile with AND-349 owner.)

## 14. Acceptance Criteria

- **AC-1 (backlog):** A public, unauthenticated respondent opens the
  link/route for a published `slug`, fills required fields, and **submits
  successfully**, reaching AND-349's terminal `Submitted` state with a submission id —
  with no prior login and an empty auth cookie jar. (Covered by end-to-end
  instrumented + unit tests.)
- **AC-2:** The public entry resolves a `slug`: 200 → starts/resumes an anonymous
  session and forwards to the renderer; 404 → `NotFound` state; transport failure →
  retryable `Error` state.
- **AC-3:** The published-load GET and session-start POST carry **no `X-CSRF-Token`**,
  and a 401 on these calls does **not** trigger AND-013 refresh or a login bounce
  (asserted via MockWebServer).
- **AC-4:** Re-entering the same `slug` with an in-progress persisted session resumes
  it without issuing a second session-start (no duplicate session).
- **AC-5:** A persisted *terminal* (submitted) session re-opens directly to AND-349's
  confirmation/PDF state, not the loading shim or editable form.
- **AC-6:** The route is reachable from the unauthenticated nav graph and via the App
  Link on a cold-started, logged-out app (instrumented intent test + `adb am start`).
- **AC-7:** Load/start failures show a retryable error and never crash; the
  idempotent load GET retries, the session-start POST does not auto-retry.

## 15. Definition of Done

- Code merged to `android-port` under `feature-respond`
  (`com.testlogon.android.feature.respond.public`) with `PublicRespondRoute`
  registered in the unauthenticated graph, `PublicRespondViewModel` entry state
  machine, `PublicRespondScreen`, the App Link hand-off, and the `Anonymous` request
  tag opt-out honored by the CSRF interceptor (AND-012) and refresh authenticator
  (AND-013).
- DTO field names / paths reconciled against `/openapi.json` and `frontend/src/api`
  (Q-1/Q-2 resolved or recorded for backend follow-up).
- All unit, repository (MockWebServer), Compose UI, and instrumented deep-link/
  end-to-end submit tests pass in CI; the anonymous-no-CSRF/no-refresh path is
  explicitly covered.
- `ktlint`/`detekt` clean; no hardcoded strings (all in `strings.xml`); a11y
  semantics present and TalkBack-spot-checked on the entry states.
- App Link build-type gating documented (inherited from AND-349 R-1); Open Questions
  Q-1..Q-3 recorded in the ticket for backend/AND-349-owner follow-up.
- No PII or `session_id` in logs; public flow verified to work with an empty auth
  cookie jar on a cold start.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend = `reference/src/...`.

1. **Published-load endpoint is `GET /questionnaires/published/{slug}`.** — **Corrected.**
   Path param is `{published_slug}`, not `{slug}`.
   Source: OpenAPI `GET /questionnaires/published/{published_slug}`
   (op `get_published_by_slug_...`); `frontend/src/api/endpoints/questionnaires.ts:
   getPublishedQuestionnaireBySlug`.
2. **Published-load 200 shape is `{ slug, title, status, fields }`.** — **Corrected.**
   It is an envelope `{ version: PublishedQuestionnaireVersion }`; the version has
   `questionnaire_id, version_id, version_number, published_slug, visibility,
   allow_anonymous, schema_json, published_at`. No top-level `slug`/`title`/`status`/`fields`.
   Source: schema `PublishedQuestionnaireEnvelope`; `frontend/src/api/types.ts:
   PublishedQuestionnaireVersion`; `getPublishedQuestionnaireBySlug` (`{ version: ... }`).
3. **"Published" is signaled by a top-level `status: "published"`.** — **Corrected.**
   Publication/anonymity is read from `version.visibility` (`public|unlisted|private`)
   and `version.allow_anonymous`. Source: `frontend/src/api/types.ts:
   PublishedQuestionnaireVersion`.
4. **Session-start path `POST /questionnaires/published/{slug}/sessions`.** — **Corrected.**
   Param is `{published_slug}`. Source: OpenAPI
   `POST /questionnaires/published/{published_slug}/sessions` (op `start_response_session_...`);
   `frontend/src/api/endpoints/questionnaires.ts: startPublishedResponseSession`.
5. **Session-start returns HTTP 201.** — **Corrected.** It returns **200** with
   `ResponseSessionEnvelope`. Source: OpenAPI index line for the endpoint
   (`resp=200:ResponseSessionEnvelope;422:HTTPValidationError`).
6. **Session-start response is `{ session_id, status }` (top-level).** — **Corrected.**
   It is `{ session: { response_session_id, status, ... } }`; the id field is
   `response_session_id` nested under `session`, NOT a top-level `session_id`. The web
   client reads `res.session.response_session_id`. Source: schema
   `ResponseSessionEnvelope` + `QuestionnaireSessionState`; `frontend/src/api/types.ts:
   QuestionnaireSessionState`; `startPublishedResponseSession` onSuccess in
   `frontend/src/pages/questionnaires/QuestionnaireRespondentPage.tsx`.
7. **`RespondSessionResult` with `@Json(name="session_id")`.** — **Corrected** to
   `RespondSessionEnvelope`/`RespondSessionState` with `@Json(name="response_session_id")`.
   Source: as #6.
8. **Session-start requires no body / body shape unknown (Q-2).** — **Verified
   (resolved).** Web posts an empty `{}`; `ResponseSessionStartReq` has only an optional
   `questionnaire_id`. Source: schema `ResponseSessionStartReq`;
   `startPublishedResponseSession` (`api.post(..., {})`).
9. **Submit path/shape `.../submit` → `{ submission_id, status, submitted_at }`.** —
   **Corrected.** Param is `{response_session_id}`; response is `SessionSubmitEnvelope`
   = `{ session, result }` at HTTP 200; there is no `submission_id`/`submitted_at`.
   Terminality = `session.status == "submitted"`. The submit **body** is the validation
   request (`QuestionnaireValidationRequest`), not empty. Source: OpenAPI
   `POST .../sessions/{response_session_id}/submit` (`req=QuestionnaireValidationRequest`,
   `resp=200:SessionSubmitEnvelope`); schema `SessionSubmitEnvelope`;
   `frontend/src/api/endpoints/questionnaires.ts: submitPublishedResponseSession`.
10. **Session status enum is `in_progress`/`submitted`.** — **Verified.** Source:
    `frontend/src/api/types.ts: QuestionnaireSessionState.status`.
11. **Get-session-state is `GET .../sessions/{id}` → `{ session, answers_by_question_id }`.**
    — **Verified** (used for resume/terminal routing, FR-3/FR-8). Source: OpenAPI
    `GET .../sessions/{response_session_id}` (`resp=200:SessionStateEnvelope`); schema
    `SessionStateEnvelope`; `frontend/src/api/types.ts: QuestionnaireSessionStateResp`.
12. **A 404 distinguishes not-found/unpublished.** — **Unverified-assumption (partially
    corrected).** OpenAPI documents only `200`/`422` for these endpoints; a runtime 404 is
    plausible but undocumented. Spec now treats **both 404 and 422** as `NotFound`.
    Source: OpenAPI index resp columns for the published GET/sessions endpoints (no 404 listed).
13. **CSRF: web attaches `X-CSRF-Token` from a cookie and refreshes on 401.** —
    **Verified, with mechanism clarified.** `src/api/client.ts` adds `X-CSRF-Token` only
    when a `ui_csrf` cookie exists, and fires `POST /ui/session/refresh` on 401 **only if
    `isAuthenticated`**; an unauthenticated 401 propagates directly (no refresh, no login
    bounce). Source: `frontend/src/api/client.ts` (`getCookie("ui_csrf")`, `refreshSession`,
    the `if (!useAuthStore.getState().isAuthenticated)` 401 branch).
14. **A per-request `Anonymous` Retrofit `@Tag` opt-out for CSRF/refresh.** —
    **Unverified-assumption (Android-side design choice).** The web client has no
    equivalent per-call tag; it gates on cookie presence + auth state (see #13). The tag
    is a reasonable Android equivalent but is not mirrored in the reference app.
    Source: absence in `frontend/src/api/client.ts`; framework ref:
    https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Tag.html
15. **Refresh endpoint is `POST /ui/session/refresh` (AND-013).** — **Verified.**
    Source: `frontend/src/api/client.ts: refreshSession` (`fetch(withApiBase("/ui/session/refresh"), { method: "POST" })`).
16. **Public respondent route exists in the web app as
    `/questionnaires/published/:publishedSlug/respond` and is public/unauth.** —
    **Verified.** Source: `frontend/src/App.tsx` route definition (in the public route
    block, alongside `/share/:linkId`, `/donate/:fundraiserId`).
17. **The web app carries the session id in a `?session_id=` query param, not the path.**
    — **Verified** (context for the Android route, which uses a typed `sessionId` arg).
    Source: `frontend/src/pages/questionnaires/QuestionnaireRespondentPage.tsx`
    (`searchParams.get("session_id")`, `setSearchParams({ session_id: ... })`).
18. **Errors use the FastAPI `detail` union mapped per AND-015.** — **Verified** (422
    bodies are `HTTPValidationError` with `detail: [{msg, loc, type}]`). Source: OpenAPI
    `422:HTTPValidationError` on every questionnaire endpoint; schema `HTTPValidationError`.
19. **Compose / Navigation / typed routes / `navDeepLink` (framework choices).** —
    **Verified (framework refs).** Sources: https://developer.android.com/guide/navigation/design/type-safety
    and https://developer.android.com/guide/navigation/design/deep-link .
20. **App Link `autoVerify` needs HTTPS + `/.well-known/assetlinks.json` (R-1).** —
    **Verified (framework ref).** Source:
    https://developer.android.com/training/app-links/verify-android-applinks .

### Corrections made

- §5 published-load: path `{slug}` → `{published_slug}`; 200 body rewritten as the
  `{ version: PublishedQuestionnaireVersion }` envelope; "published" derived from
  `visibility`/`allow_anonymous` rather than a top-level `status`.
- §5 session-start: status code 201 → 200; response rewritten as
  `{ session: { response_session_id, status, ... } }`; DTO `RespondSessionResult`
  (`session_id`) → `RespondSessionEnvelope`/`RespondSessionState` (`response_session_id`);
  documented the empty `{}` request body (Q-2).
- §5 submit: path param `{session_id}` → `{response_session_id}`; response
  `{ submission_id, status, submitted_at }` → `SessionSubmitEnvelope { session, result }`;
  terminality via `session.status`; noted the validation-request submit body.
- §4 ViewModel: id read changed to `session.responseSessionId`; not-found branch now
  treats 404 **or** 422 as `NotFound`.
- §7 / §3 (FR-2): "404" not-found handling broadened to "404/422".
- §8: clarified that the `Anonymous` `@Tag` is an Android-side mechanism, not a web
  mirror; web gates CSRF/refresh on cookie presence + `isAuthenticated`. Retrofit
  interface example updated to the corrected path and `PublishedQuestionnaireEnvelope`.
- §13: Q-1 and Q-2 marked resolved with the confirmed shapes.

### Open assumptions

- **Runtime not-found code (404 vs 422):** OpenAPI documents only 200/422 for the
  published GET and session endpoints, so the exact code for a missing/unpublished slug
  is unverifiable from the sources. Mitigation: handle both as `NotFound`. (Audit #12)
- **`Anonymous` request-tag opt-out:** an Android-side design with no web counterpart;
  its correctness depends on AND-012/AND-013 honoring the tag, which is unverifiable here
  and must be enforced by the TC-AND-395-04/05 MockWebServer tests. (Audit #14)
- **Per-session cookie on the anonymous session:** the spec assumes the backend may set a
  per-session cookie persisted by the AND-011 jar; no `Set-Cookie` contract is visible in
  the OpenAPI or frontend sources, so this remains an assumption (harmless — the jar
  persists whatever is or isn't set).
- **`allow_anonymous == false` handling:** the version exposes `allow_anonymous`, but
  whether the backend rejects anonymous start for a public-but-non-anonymous slug (and
  with which code) is not documented. Treated as a backend follow-up.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **Emulator** =
headless AVD `test35` (x86_64, API 35); **Device** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). MockWebServer (MWS) runs in-process on JVM/Emulator.

- **TC-AND-395-01 — Bootstrap happy path (load + start → Ready)**
  Type: unit (JVM, Turbine + MWS). Target: `PublicRespondViewModel` + `RespondRepository`.
  Preconditions: empty persisted-session store; MWS enqueues `200 { version: ... }` for the
  published GET and `200 { session: { response_session_id:"rs1", status:"in_progress" } }`
  for the start POST. Steps: construct VM with `slug="onboarding-2026"`; collect `state`.
  Expected: states emit `Loading → Ready(sessionId="rs1", terminal=false)`; the GET hit
  `/questionnaires/published/onboarding-2026` and the POST hit `.../sessions` with body `{}`.
  Traces: AC-2.

- **TC-AND-395-02 — Resume in-progress persisted session (no second start)**
  Type: unit (JVM, MWS). Target: `PublicRespondViewModel`.
  Preconditions: persisted non-terminal session id `rs1` for the slug; MWS enqueues only the
  `200 { version }` published GET (no start response). Steps: run `bootstrap()`.
  Expected: `Ready(sessionId="rs1", terminal=false)`; **no** `POST .../sessions` request is
  recorded by MWS (assert `takeRequest` count / paths). Traces: AC-4.

- **TC-AND-395-03 — Terminal (submitted) persisted session routes to confirmation**
  Type: unit (JVM). Target: `PublicRespondViewModel` + `PublicRespondScreen`.
  Preconditions: persisted session `rs9` with `status == "submitted"`. Steps: run
  `bootstrap()`; render screen. Expected: `Ready(terminal=true)`; the screen invokes
  `onSubmittedSession("rs9")`, not `onSessionReady`. Traces: AC-5.

- **TC-AND-395-04 — No `X-CSRF-Token` on anonymous calls**
  Type: contract/MWS. Target: `RespondRepository` + OkHttp CSRF interceptor (AND-012) with
  the `Anonymous` tag. Preconditions: empty cookie jar; MWS records request headers.
  Steps: run the happy-path load + start. Expected: neither the published GET nor the start
  POST carries an `X-CSRF-Token` header. Traces: AC-3.

- **TC-AND-395-05 — 401 does not trigger refresh or login bounce**
  Type: contract/MWS. Target: `RespondRepository` + refresh authenticator (AND-013).
  Preconditions: empty auth state; MWS returns `401` for the published GET, then would
  return `200` on retry. Steps: run `bootstrap()`. Expected: state becomes retryable
  `Error` (or `NotFound` if mapped so); MWS records **no** `POST /ui/session/refresh` and
  no navigation to login is requested. Traces: AC-3, AC-7.

- **TC-AND-395-06 — Not found / unpublished (404 and 422) → NotFound**
  Type: unit (JVM, MWS). Target: `PublicRespondViewModel`. Preconditions: MWS returns
  `422 { detail:[{msg,loc,type}] }` for the published GET in one run and `404` in a second
  run. Steps: run `bootstrap()` for each. Expected: both yield `NotFound` (not `Error`).
  Traces: AC-2, AC-7.

- **TC-AND-395-07 — Transport failure → retryable Error, then retry() succeeds**
  Type: unit (JVM, MWS). Target: `PublicRespondViewModel`. Preconditions: MWS first
  returns a 503/socket-timeout for the published GET, then `200 { version }` + `200 { session }`.
  Steps: run `bootstrap()`; observe `Error`; call `retry()`. Expected: `Loading → Error →
  (retry) Loading → Ready`; idempotent GET is retried by the bounded-backoff interceptor;
  the start POST is **not** auto-retried (assert single POST). Traces: AC-7.

- **TC-AND-395-08 — Offline / flaky dev host path**
  Type: instrumented (Device preferred; airplane mode toggling needs real radio).
  Target: `PublicRespondScreen` end-to-end against MWS reachable only intermittently.
  Preconditions: app logged out, empty jar; toggle device offline before entry.
  Steps: open `PublicRespondRoute`; observe offline error; re-enable network; tap Retry.
  Expected: "You're offline…" error with Retry; after reconnect, load+start succeed and the
  screen forwards to `RespondScreen`. Must run on **Device** (real connectivity transitions).
  Traces: AC-7, AC-2.

- **TC-AND-395-09 — Cold-start App Link launches public entry (logged out)**
  Type: instrumented/e2e. Target: `MainActivity` + nav graph + deep link.
  Preconditions: app freshly installed/cleared, no auth cookies. Steps:
  `adb shell am start -a android.intent.action.VIEW -d
  "https://<host>/questionnaires/published/onboarding-2026/respond"`. Expected: app opens to
  `PublicRespondScreen` (no login gate), resolves the session, and forwards into
  `RespondScreen("onboarding-2026", sessionId)`. Run on **Emulator** for CI; spot-check on
  **Device** for API-34 deep-link/verification behavior. Traces: AC-6, AC-1.

- **TC-AND-395-10 — End-to-end public submit reaches Submitted (empty cookie jar)**
  Type: instrumented/e2e (against MWS fixtures). Target: full entry → AND-349 renderer →
  submit. Preconditions: logged out, empty jar; MWS serves published GET, start, save,
  validate, and submit (`200 { session:{status:"submitted"}, result }`). Steps: open via
  route/App Link; fill required fields; tap Submit. Expected: reaches AND-349 terminal
  `Submitted` state derived from `session.status == "submitted"`; no login was ever shown.
  Run on **Emulator** (CI) and confirm on **Device**. Traces: AC-1.

- **TC-AND-395-11 — Re-entry idempotency under cold-start deep-link race**
  Type: integration (JVM/Robolectric or instrumented). Target: `PublicRespondViewModel`
  single-flight + resume-before-start. Preconditions: a persisted in-progress session and a
  simultaneous deep-link entry for the same slug. Steps: trigger two bootstraps concurrently.
  Expected: at most one `POST .../sessions` is issued; both resolve to the same session id.
  Traces: AC-4.

- **TC-AND-395-12 — Compose UI states (loading / NotFound / Error+Retry)**
  Type: Compose-UI. Target: `PublicRespondScreen`. Preconditions: VM stubbed to emit each
  state. Steps: render `Loading`, `NotFound`, `Error`; tap Retry on `Error`. Expected:
  loading indicator shown; NotFound copy ("isn't available"); Error shows message + Retry,
  and Retry re-invokes `vm::retry`. Traces: AC-2, AC-7.

- **TC-AND-395-13 — Accessibility on entry states**
  Type: Compose-UI (a11y) + manual TalkBack spot-check on **Device**. Target:
  `PublicRespondScreen`. Preconditions: each state rendered. Steps: assert the Retry button
  has a non-empty `contentDescription` and ≥48dp touch target; assert the loading/handoff
  `liveRegion` announcement; verify all strings come from `strings.xml` (no hardcoded text);
  TalkBack reads the "opening" announcement on Device. Expected: all assertions pass; RTL
  layout renders. Traces: AC-2 (a11y dimension of the entry states), DoD a11y.

- **TC-AND-395-14 — Security: no auth cookie required & none leaked to logs**
  Type: contract/MWS + unit. Target: `RespondRepository`, cookie jar (AND-011), logging.
  Preconditions: empty jar. Steps: run load+start; capture jar contents and Timber output.
  Expected: flow succeeds with zero auth cookies; any backend `Set-Cookie` is stored by the
  jar; `response_session_id`, cookies, and answer payloads never appear at `info`+ level.
  Traces: AC-3, AC-1 (empty-jar guarantee), DoD (no PII/session_id in logs).

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (e2e public submit → Submitted, no login, empty jar) | TC-09, TC-10, TC-14 |
| AC-2 (resolve slug: 200→start/resume, 404/422→NotFound, transport→Error) | TC-01, TC-06, TC-08, TC-12 |
| AC-3 (no X-CSRF-Token; 401 no refresh/no login bounce) | TC-04, TC-05, TC-14 |
| AC-4 (re-entry resumes, no duplicate start) | TC-02, TC-11 |
| AC-5 (terminal session opens to confirmation) | TC-03 |
| AC-6 (reachable from unauth graph + App Link, cold/logged-out) | TC-09 |
| AC-7 (failures retryable, never crash; GET retries, start POST does not) | TC-05, TC-06, TC-07, TC-08, TC-12 |
