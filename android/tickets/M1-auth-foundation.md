# M1 — Auth Foundation — Tickets

Decomposition of milestone **M1** (epics **E01–E07**) into executable tickets, following the repo's
`TKT-###` convention. See [`../MILESTONES_AND_EPICS.md`](../MILESTONES_AND_EPICS.md) and
[`../PORT_PLAN.md`](../PORT_PLAN.md).

**Milestone exit criteria:** real end-to-end login + MFA + logout against the dev backend on the
headless emulator; session persists across process death; configurable server URL; unit + UI tests;
`assembleDebug` + tests green in CI on the build server.

Priority: **P0** blocks the milestone · **P1** important · **P2** nice-to-have.

---

## Epic E01 — Project scaffolding & build tooling

### AND-001 — Gradle project skeleton
**Type:** Chore · **Priority:** P0 · **Dependencies:** None
**Scope**
- Create `android/` Gradle project: `settings.gradle.kts`, root `build.gradle.kts`, `gradle.properties`.
- Add a Gradle **version catalog** (`gradle/libs.versions.toml`) for all dependencies/plugins.
- Pin AGP 8.7.x, Kotlin 2.0.x, Gradle 8.9 wrapper (matches build-server toolchain).
**Deliverables**
- Project syncs; `./gradlew help` succeeds.
**Acceptance Criteria**
- Fresh clone builds the empty project; version catalog is the single source of dependency versions.

### AND-002 — Application module configuration
**Type:** Chore · **Priority:** P0 · **Dependencies:** AND-001
**Scope**
- `app` module: `compileSdk 35`, `minSdk 24`, `targetSdk 35`, Kotlin + Compose enabled, Compose
  compiler plugin (Kotlin 2.0), Java 17.
- `AndroidManifest.xml`, `Application` placeholder, launcher `MainActivity` with empty Compose host.
**Acceptance Criteria**
- `./gradlew :app:assembleDebug` produces an APK that launches to a blank Compose screen.

### AND-003 — Core module structure
**Type:** Chore · **Priority:** P0 · **Dependencies:** AND-001
**Scope**
- Create `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing` library modules with
  namespaces and minimal build files; wire `app` dependencies.
**Acceptance Criteria**
- All modules compile and are consumable by `app`.

### AND-004 — Hilt DI baseline
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-002
**Scope**
- Add Hilt + KSP; `@HiltAndroidApp` Application; verify component graph builds.
**Acceptance Criteria**
- App runs with Hilt; a trivial injected dependency resolves.

### AND-005 — Lint, format & static analysis
**Type:** Chore · **Priority:** P1 · **Dependencies:** AND-001
**Scope**
- Add Spotless/ktlint + detekt with an agreed config; Gradle tasks `spotlessCheck`, `detekt`.
**Acceptance Criteria**
- `./gradlew spotlessCheck detekt` runs clean on the scaffold; documented in README.

### AND-006 — Build flavors & base-URL BuildConfig
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-002
**Scope**
- Define `dev`/`staging`/`prod` flavors (or buildConfigField) with `API_BASE_URL`
  (`dev` → `http://18.222.237.167:8000`).
**Acceptance Criteria**
- `BuildConfig.API_BASE_URL` resolves per flavor; default dev points at the dev host.

### AND-007 — Wrapper, .gitignore, module README
**Type:** Chore · **Priority:** P1 · **Dependencies:** AND-001
**Scope**
- Commit Gradle wrapper, Android `.gitignore`, `android/README.md` (setup, run, test, base-URL notes).
**Acceptance Criteria**
- Clean clone builds with no extra setup; README documents flavors and the flaky-host base-URL switch.

### AND-008 — CI: build + unit test on build server
**Type:** Chore · **Priority:** P0 · **Dependencies:** AND-002
**Scope**
- Script/job on `andrioiddev` running `assembleDebug` + `testDebugUnitTest`; cache Gradle.
**Acceptance Criteria**
- CI runs green on the scaffold and is reproducible on a fresh checkout.

---

## Epic E02 — Core networking & session transport

### AND-009 — OkHttp client + timeouts + logging
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-003,AND-004
**Scope**
- Provide `OkHttpClient` via Hilt: connect/read/write timeouts ~20s, `HttpLoggingInterceptor`
  (debug only, redacting auth/cookies).
**Acceptance Criteria**
- A test request against MockWebServer succeeds; logs redact sensitive headers.

### AND-010 — Retrofit + Moshi setup
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-009,AND-006
**Scope**
- Retrofit with Moshi converter; base URL from `BuildConfig`; Moshi with Kotlin codegen.
**Acceptance Criteria**
- A sample typed endpoint round-trips JSON in a unit test.

### AND-011 — Persistent cookie jar
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-009
**Scope**
- Implement `CookieJar` persisting cookies to **EncryptedSharedPreferences/DataStore**; restore on
  startup; correct domain/path/expiry matching; clear-on-logout API.
**Acceptance Criteria**
- Cookies set by a response are sent on the next request and **survive process restart** (tested).

### AND-012 — CSRF interceptor
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-011
**Scope**
- Read `ui_csrf` cookie; set `X-CSRF-Token` header on requests (mirroring web client).
**Acceptance Criteria**
- Mutating requests include `X-CSRF-Token` equal to the `ui_csrf` cookie value (tested).

### AND-013 — 401 refresh authenticator
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-011
**Scope**
- OkHttp `Authenticator`: on `401` for an authenticated user, call `POST /ui/session/refresh` once
  (single-flight), then retry; on failure → emit logged-out. No retry for unauthenticated 401.
**Acceptance Criteria**
- Simulated expiry triggers exactly one refresh+retry; repeated failure logs the user out (tested).

### AND-014 — Host selection interceptor (runtime base URL)
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-010
**Scope**
- Interceptor rewrites scheme/host/port from a runtime setting (default = BuildConfig); changes take
  effect without restart.
**Acceptance Criteria**
- Changing the stored base URL routes subsequent requests to the new host (tested).

### AND-015 — API error model & detail mapping
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-010
**Scope**
- `ApiError(status, detail, body)`; parse FastAPI `detail` (string | `[{msg}]` | `{code,...}`);
  port `normalizeErrorDetail` + auth-code messages (`role_required`, `geo_blocked`, helpdesk codes).
**Acceptance Criteria**
- Representative error bodies map to expected user-facing messages (unit-tested).

### AND-016 — Retry/backoff for idempotent GETs
**Type:** Feature · **Priority:** P1 · **Dependencies:** AND-009
**Scope**
- Bounded exponential backoff retry for safe GETs on network/5xx; never retry mutations.
**Acceptance Criteria**
- Transient 503 then 200 yields success; POSTs are never retried (tested).

### AND-017 — Connectivity & backend health probe
**Type:** Feature · **Priority:** P1 · **Dependencies:** AND-010
**Scope**
- Reachability monitor (network + lightweight backend ping); expose `Flow<BackendStatus>`.
**Acceptance Criteria**
- Status flips to unreachable when host is down and recovers when back (tested with MockWebServer).

### AND-018 — Result/ApiResult types
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-003
**Scope**
- `sealed ApiResult<T>` (Success/Failure(ApiError)/NetworkError) + helpers in `core-model`.
**Acceptance Criteria**
- Repositories can return typed results; helpers covered by unit tests.

---

## Epic E03 — Design system & navigation shell

### AND-019 — Material 3 theme
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-003
**Scope**
- Color scheme (light/dark + dynamic color), typography, shapes in `core-ui`.
**Acceptance Criteria**
- Theme applies app-wide; dark mode verified via preview + UI test.

### AND-020 — Core input composables (incl. OTP)
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-019
**Scope**
- Reusable `Button`, `TextField` (with error/helper), password field (show/hide), **OTP input**.
**Acceptance Criteria**
- Components render states correctly; OTP supports 6-digit entry + paste (tested).

### AND-021 — State composables (loading/empty/error/offline)
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-019
**Scope**
- Standard Loading, Empty, Error (with retry), Offline/stale banners; app `Scaffold` wrapper.
**Acceptance Criteria**
- Each state composable renders + retry callback fires (tested).

### AND-022 — Navigation host & routes
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-002
**Scope**
- Single-activity `NavHost`, typed route definitions, transitions.
**Acceptance Criteria**
- Navigation between two placeholder screens works (tested).

### AND-023 — Unauthenticated nav graph
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-022
**Scope**
- Graph: Login → MFA → (Register/Recovery/Magic-link placeholders).
**Acceptance Criteria**
- Graph wired; login is the start destination when logged out.

### AND-024 — Authenticated nav graph + bottom nav skeleton
**Type:** Feature · **Priority:** P1 · **Dependencies:** AND-022
**Scope**
- Bottom-nav scaffold (Home placeholder + Profile/Me) as the post-login destination.
**Acceptance Criteria**
- After login, the authenticated graph shows; bottom nav switches tabs.

### AND-025 — Auth-gated routing
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-023,AND-024,AND-029
**Scope**
- Observe auth state; route to unauth/auth graph; handle logout/expiry redirects.
**Acceptance Criteria**
- Auth state changes drive navigation correctly (tested).

---

## Epic E04 — Login (password) & session bootstrap

### AND-026 — Auth DTOs + adapters
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-010
**Scope**
- Moshi DTOs for `SessionStartReq/Resp`, `SessionFinalizeReq/Resp`, `MeResp`, `SessionInfo`,
  `Mfa*`, `Challenge/Ok/StatusResp` (per Appendix A).
**Acceptance Criteria**
- DTOs (de)serialize the documented JSON exactly (unit-tested with captured samples).

### AND-027 — AuthApi (session endpoints)
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-026
**Scope**
- Retrofit `AuthApi`: `session/start|finalize|refresh|logout`, `me`, `sessions(+revoke)`.
**Acceptance Criteria**
- Endpoints callable; paths/verbs/bodies match the contract (MockWebServer tested).

### AND-028 — AuthRepository: session start + branching
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-027,AND-018
**Scope**
- `login(username,password)` → `session/start` with `challenge_context`; branch
  Authenticated vs `MfaRequired(challengeId, factors)`.
**Acceptance Criteria**
- Both branches return correct typed results for representative responses (tested).

### AND-029 — getMe + auth state store
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-028,AND-011
**Scope**
- `getMe()`; persistent auth state (authenticated flag, user_sub) backed by DataStore; reflects
  cookie session.
**Acceptance Criteria**
- After successful login, `me` populates and auth state persists across restart (tested).

### AND-030 — Login screen UI
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-020,AND-023
**Scope**
- Email/password form, validation, show/hide password, links to recovery/register, server-URL entry
  point, error display.
**Acceptance Criteria**
- Valid input enables submit; errors surface; matches web behavior/IA (UI-tested).

### AND-031 — LoginViewModel
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-028,AND-030
**Scope**
- `StateFlow<LoginUiState>`, submit handler, map results to navigation (MFA vs home) + errors.
**Acceptance Criteria**
- State transitions covered by unit tests; loading/disabled handled.

### AND-032 — Logout flow
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-029
**Scope**
- `session/logout`, clear cookies + auth state + caches, route to login.
**Acceptance Criteria**
- Logout clears session; protected calls afterward 401 → login (tested).

---

## Epic E05 — Multi-factor authentication

### AND-033 — MFA API + DTOs
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-026,AND-027
**Scope**
- `AuthApi` MFA methods: totp/verify, sms/begin+verify, email/begin+verify, recovery/{factor}.
**Acceptance Criteria**
- All MFA endpoints callable and contract-correct (tested).

### AND-034 — TOTP verify flow
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-033
**Scope**
- Repository `verifyTotp(challengeId, code)` → `MfaVerifyResp`; surface remaining factors.
**Acceptance Criteria**
- Correct/incorrect code produce expected results (tested).

### AND-035 — SMS begin/verify flow
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-033
**Scope**
- `beginSms` (returns `sent_to`), `verifySms`; resend support.
**Acceptance Criteria**
- Begin sends challenge; verify advances/finishes (tested).

### AND-036 — Email begin/verify flow
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-033
**Scope**
- `beginEmail`, `verifyEmail`; resend support.
**Acceptance Criteria**
- Begin/verify behave per contract (tested).

### AND-037 — Recovery code flow
**Type:** Feature · **Priority:** P1 · **Dependencies:** AND-033
**Scope**
- `useRecoveryCode(factor, code)`; entry UI affordance.
**Acceptance Criteria**
- Valid recovery code passes the factor (tested).

### AND-038 — Finalize + multi-factor sequencing
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-034,AND-035,AND-036
**Scope**
- After factors pass (empty `remaining_factors`) call `session/finalize`; handle multiple required
  factors in sequence; `remember_device`.
**Acceptance Criteria**
- Single- and multi-factor challenge sequences reach an authenticated session (tested).

### AND-039 — MFA screen UI
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-020,AND-038
**Scope**
- Factor selection, OTP entry, resend, switch-factor, recovery option, errors/timers.
**Acceptance Criteria**
- Each factor path is completable from the UI (UI-tested for TOTP + SMS).

### AND-040 — MfaViewModel (challenge state machine)
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-038,AND-039
**Scope**
- State machine over challengeId/required/remaining factors; events → repository; nav on success.
**Acceptance Criteria**
- State machine transitions covered by unit tests; error recovery handled.

---

## Epic E06 — Session management & resilience

### AND-041 — Server-URL settings screen
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-014
**Scope**
- Screen to view/edit/persist base URL (validation, reset to default); reachable pre-login.
**Acceptance Criteria**
- Edited URL persists and is used immediately; invalid input rejected (tested).

### AND-042 — Backend health banner
**Type:** Feature · **Priority:** P1 · **Dependencies:** AND-017,AND-021
**Scope**
- Global banner when backend unreachable/degraded; auto-dismiss on recovery.
**Acceptance Criteria**
- Banner shows when host down, hides on recovery (UI-tested).

### AND-043 — Active sessions list + revoke
**Type:** Feature · **Priority:** P1 · **Dependencies:** AND-027,AND-029
**Scope**
- `GET /ui/sessions` list (current highlighted), revoke one / revoke others.
**Acceptance Criteria**
- Sessions render; revoke updates list; current session marked (tested).

### AND-044 — Session refresh wiring & expiry UX
**Type:** Feature · **Priority:** P0 · **Dependencies:** AND-013,AND-029
**Scope**
- Connect authenticator to auth state; on unrecoverable expiry show "session expired" + route to
  login with reason.
**Acceptance Criteria**
- Expiry path produces a clean re-login experience (tested).

### AND-045 — Offline/stale baseline for auth-area reads
**Type:** Feature · **Priority:** P2 · **Dependencies:** AND-017,AND-018
**Scope**
- Cache `me`/sessions last-good; show stale + reconnecting affordance when host flaky.
**Acceptance Criteria**
- With host down, cached data shows with a stale indicator (tested).

---

## Epic E07 — Auth QA, CI & test harness

### AND-046 — MockWebServer harness + fixtures
**Type:** Chore · **Priority:** P0 · **Dependencies:** AND-010
**Scope**
- `core-testing` helpers; JSON fixtures captured from the real backend's auth responses.
**Acceptance Criteria**
- Reusable harness; fixtures match live shapes.

### AND-047 — AuthRepository contract tests
**Type:** Test · **Priority:** P0 · **Dependencies:** AND-028,AND-038,AND-046
**Scope**
- Cover login (no-MFA + MFA), each factor, finalize, refresh, logout, error mapping.
**Acceptance Criteria**
- All auth repository paths covered; tests deterministic.

### AND-048 — Compose UI tests: login
**Type:** Test · **Priority:** P0 · **Dependencies:** AND-031,AND-046
**Scope**
- Happy path + validation + server-error rendering.
**Acceptance Criteria**
- Login UI tests pass headlessly.

### AND-049 — Compose UI tests: MFA
**Type:** Test · **Priority:** P0 · **Dependencies:** AND-040,AND-046
**Scope**
- TOTP + SMS flows incl. wrong-code error.
**Acceptance Criteria**
- MFA UI tests pass headlessly.

### AND-050 — CI: unit tests
**Type:** Chore · **Priority:** P0 · **Dependencies:** AND-008,AND-047
**Scope**
- Wire unit tests into CI; fail build on test failure; publish results.
**Acceptance Criteria**
- CI runs and reports unit tests on every change.

### AND-051 — CI: instrumented tests on headless emulator
**Type:** Chore · **Priority:** P1 · **Dependencies:** AND-008,AND-048
**Scope**
- Boot `test35` AVD headless on the build server; run `connectedDebugAndroidTest`.
**Acceptance Criteria**
- Instrumented suite runs on the KVM emulator in CI.

### AND-052 — Auth telemetry/logging (redacted)
**Type:** Feature · **Priority:** P2 · **Dependencies:** AND-031,AND-040
**Scope**
- Structured, redacted logging of login/MFA success/failure + network diagnostics for the flaky host.
**Acceptance Criteria**
- No secrets logged; diagnostics help triage dev-host issues.

---

### M1 ticket count: 52 (E01:8, E02:10, E03:7, E04:7, E05:8, E06:5, E07:7)
**Critical path:** AND-001→002→003→{009,010}→011→{012,013}→026→027→028→029→{030,031}→
{033…038}→{039,040} → milestone demoable. CI (008,050,051) parallel once 002/047/048 land.
