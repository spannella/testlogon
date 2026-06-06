---
id: AND-395
title: Public questionnaire respond
milestone: M8
epic: E51
priority: P2
size: M
status: draft
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
state, then an error state for 404 (not found / unpublished) or transport failure.

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
                _state.value = if (meta.code == 404) PublicEntryState.NotFound
                               else PublicEntryState.Error(meta.detailMessage())
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
                _state.value = PublicEntryState.Ready(started.data.sessionId, terminal = false)
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

### Load published questionnaire (FR-2, idempotent GET)

```
GET /questionnaires/published/{slug}
Accept: application/json

200 Response (shape owned by AND-346):
{ "slug": "onboarding-2026", "title": "...", "status": "published", "fields": [ ... ] }

404 Response: questionnaire not found or not published.
```

### Start anonymous session (FR-3, owned by AND-348)

```
POST /questionnaires/published/{slug}/sessions
Content-Type: application/json
(no X-CSRF-Token, no auth cookies required)

201 Response:
{ "session_id": "sess_b21c...", "status": "in_progress" }
```

```kotlin
@JsonClass(generateAdapter = true)
data class RespondSessionResult(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "status") val status: String,
)
```

### Submit (terminal, owned by AND-349) — referenced for the end-to-end AC

```
POST /questionnaires/published/{slug}/sessions/{session_id}/submit
200/201: { "submission_id": "sub_...", "status": "submitted", "submitted_at": "..." }
```

Errors use the FastAPI `detail` union (string | `[{msg, loc}]` | `{code,...}`) mapped
per AND-015. The exact `GET /questionnaires/published/{slug}` shape and the session
start path are owned by AND-346/AND-348 — AND-395 only confirms they are callable
anonymously (Open Question Q-1).

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
- **404 vs 5xx:** 404 → `NotFound` state ("This questionnaire isn't available");
  5xx/network/timeout → retryable `Error` state.
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
  authenticator skip these requests, e.g. a Retrofit `@Tag`:

  ```kotlin
  object Anonymous                                  // request tag marker
  @GET("questionnaires/published/{slug}")
  suspend fun getPublished(@Path("slug") slug: String, @Tag anon: Anonymous = Anonymous):
      Response<PublishedQuestionnaire>
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
- **Repository:** asserts correct path/verb (`GET .../published/{slug}`,
  `POST .../sessions`), `detail` parsing, and `RespondSessionResult` mapping.
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
- **Q-1:** Exact published-load path/shape and session-start path — confirm in
  `/openapi.json` / `frontend/src/api` (owned by AND-346/348; AND-395 only verifies
  anonymous callability).
- **Q-2:** Does session-start require a body (e.g. respondent metadata) when
  anonymous, or is it empty? (Modeled empty; confirm.)
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
