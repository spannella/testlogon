---
id: AND-041
title: Server-URL settings screen
milestone: M1
epic: E06
priority: P0
size: S
depends_on: [AND-014]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-041 — Server-URL settings screen

## 1. Overview & Goal

TestLogon must talk to a backend whose host is not fixed. The default dev backend
(`http://18.222.237.167:8000`) is plaintext HTTP and unreliable, and QA, developers, and
field testers routinely need to point the app at a different host (a local FastAPI instance,
a staging IP, a teammate's tunnel) without rebuilding the APK. AND-014 already provides a
runtime base-URL mechanism: an OkHttp `HostSelectionInterceptor` that rewrites the
scheme/host/port of every outbound request from a value stored in DataStore, defaulting to
`BuildConfig.BASE_URL`, with changes taking effect without an app restart.

This ticket delivers the **user-facing surface** for that mechanism: a Compose settings
screen that lets a user view the current base URL, edit it, validate it, persist it, and
reset it to the compiled-in default. The screen must be **reachable before login** (the dev
host being wrong is precisely why a user cannot reach the login flow), so it is wired into
navigation outside the authenticated graph.

Goal: an edited, valid URL is persisted and used by the very next network call, and invalid
input is rejected at the UI with an actionable message and never written to storage.

Out of scope: the interceptor and the DataStore-backed `HostRepository` itself (owned by
AND-014); auth/session behavior (E05); certificate pinning or cleartext policy changes.

## 2. Context & References

- **Project:** `spannella/testlogon`, monorepo; Android app under `android/`, branch
  `android-port`. Namespace / applicationId base: `com.testlogon.android`.
- **Module placement:** new feature module `feature-settings`
  (`com.testlogon.android.feature.settings`), depending on `core-ui`, `core-data`,
  `core-model`, and `core-testing` (test). The settings screen does **not** depend on
  `core-network` directly; it talks to the host store abstraction exposed by `core-data`.
- **Upstream (AND-014):** provides the runtime base-URL store and interceptor. This ticket
  consumes the store via a repository interface (see §4). If AND-014 exposes
  `HostSelectionRepository` with a different name, this spec's `HostRepository` is an alias to
  it — do not duplicate the DataStore.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single Activity),
  Hilt (KSP), Coroutines/Flow, DataStore (prefs). minSdk 24, compileSdk/targetSdk 35,
  JDK 17, AGP 8.7.3, Gradle 8.9.
- **Pattern:** ViewModel exposes `StateFlow<UiState>`; immutable state; events as method calls.
- **Default value:** the compiled-in default is `BuildConfig.BASE_URL`
  (`http://18.222.237.167:8000` in the dev variant). "Reset to default" restores exactly this.

## 3. Functional Requirements

FR-1. **View current URL.** On entry, the screen shows the currently persisted base URL
(the effective value the interceptor is using). If nothing has been persisted, it shows the
`BuildConfig.BASE_URL` default.

FR-2. **Edit URL.** A single-line text field, pre-filled with the current value, lets the
user edit the URL. Keyboard type is URI; auto-correct and capitalization are disabled.

FR-3. **Validate on input and on save.** Validation runs as the user types (to drive
inline error + Save enablement) and again at save time. Rules (see §6 for the validator):
must be a syntactically valid absolute URL; scheme must be `http` or `https`; host must be
non-empty; an explicit port, if present, must be in `1..65535`; no path/query/fragment is
required, but a trailing `/` is tolerated and normalized off. Whitespace is trimmed.

FR-4. **Persist on save.** Save is enabled only when the current input is valid and differs
from the persisted value. Tapping Save normalizes and writes the value through
`HostRepository.setBaseUrl(...)`. Persistence is the single source of truth; the interceptor
(AND-014) reads the same store, so the change takes effect on the next request with no restart.

FR-5. **Immediate effect.** No "restart required" messaging. After a successful save, the
displayed "current" value and the field reflect the new persisted value, and a confirmation
(snackbar) is shown.

FR-6. **Reset to default.** A "Reset to default" action restores `BuildConfig.BASE_URL`,
persists it, and updates the field. Reset is disabled when the persisted value already equals
the default.

FR-7. **Reject invalid input.** Invalid input produces an inline error under the field,
keeps Save disabled, and is never persisted. The previously persisted value remains in effect.

FR-8. **Reachable pre-login.** The screen is registered on the root nav graph (not the
authenticated sub-graph) and is reachable from the login screen (overflow/"Settings" affordance)
and from app settings entry points, with no session required.

FR-9. **Insecure-host hint.** When the entered scheme is `http` (cleartext), show a
non-blocking warning ("Connection is not encrypted (HTTP)") below the field. This is advisory,
not an error — the dev host is plaintext by design — and does not block Save.

## 4. Technical Design

Module: `feature-settings`. Files under
`android/feature-settings/src/main/kotlin/com/testlogon/android/feature/settings/`.

### 4.1 Repository contract (consumed; defined by AND-014 / core-data)

```kotlin
package com.testlogon.android.core.data.host

interface HostRepository {
    /** Effective base URL; emits default (BuildConfig.BASE_URL) until overridden. */
    val baseUrl: Flow<String>
    suspend fun setBaseUrl(url: String)
    suspend fun resetToDefault()
    /** Compiled-in default, i.e. BuildConfig.BASE_URL. */
    val default: String
}
```

If AND-014 names this differently, add a thin `typealias`/binding in `core-data`; do not add a
second DataStore key.

### 4.2 URL validation/normalization (core, pure, unit-testable)

```kotlin
package com.testlogon.android.feature.settings

sealed interface UrlValidation {
    data class Valid(val normalized: String, val cleartext: Boolean) : UrlValidation
    data class Invalid(val reason: UrlError) : UrlValidation
}

enum class UrlError { BLANK, MALFORMED, BAD_SCHEME, NO_HOST, BAD_PORT }

object BaseUrlValidator {
    fun validate(raw: String): UrlValidation
}
```

`validate` trims input, parses with the OkHttp Kotlin extension
`String.toHttpUrlOrNull()` (from `okhttp3.HttpUrl.Companion`; robust, already on the
classpath via OkHttp 4.x; avoids `java.net.URI` quirks). Note: the legacy static
`okhttp3.HttpUrl.parse(...)` form is deprecated in OkHttp 4.x in favor of the
`toHttpUrlOrNull()` extension — use the extension. It enforces scheme ∈ {http, https},
non-empty host, port range, and returns a normalized form
`"$scheme://$host" + (explicitPort?.let { ":$it" } ?: "") ` with no trailing slash. `cleartext`
is `scheme == "http"`.

### 4.3 UI state & ViewModel

```kotlin
data class ServerUrlUiState(
    val input: String = "",
    val persistedUrl: String = "",
    val defaultUrl: String = "",
    val error: UrlError? = null,
    val cleartextWarning: Boolean = false,
    val canSave: Boolean = false,
    val canReset: Boolean = false,
    val saving: Boolean = false,
    val message: SettingsMessage? = null, // one-shot snackbar
)

sealed interface SettingsMessage {
    data object Saved : SettingsMessage
    data object ResetDone : SettingsMessage
    data class Failed(val reason: String) : SettingsMessage
}

@HiltViewModel
class ServerUrlViewModel @Inject constructor(
    private val hostRepository: HostRepository,
) : ViewModel() {
    val state: StateFlow<ServerUrlUiState>
    fun onInputChange(value: String)
    fun onSave()
    fun onResetToDefault()
    fun onMessageShown()
}
```

Behavior: on init, collect `hostRepository.baseUrl`; seed `input`, `persistedUrl`, and
`defaultUrl = hostRepository.default`. `onInputChange` runs `BaseUrlValidator.validate`,
updates `error`/`cleartextWarning`, and sets `canSave = validation is Valid &&
normalized != persistedUrl`. `onSave` re-validates, sets `saving = true`, calls
`setBaseUrl(normalized)` inside `viewModelScope` (Dispatchers handled by repo), emits `Saved`.
`onResetToDefault` calls `resetToDefault()` and emits `ResetDone`. `canReset = persistedUrl != defaultUrl`.

### 4.4 Composable

```kotlin
@Composable
fun ServerUrlSettingsScreen(
    onNavigateBack: () -> Unit,
    viewModel: ServerUrlViewModel = hiltViewModel(),
)
```

Material 3 `Scaffold` with `TopAppBar` (title "Server URL", back nav), `SnackbarHost`,
`OutlinedTextField` (URI keyboard, `singleLine`, `isError`, `supportingText`), a "Current:"
`Text`, a primary `Button("Save")` gated by `canSave`/`saving`, and a `TextButton("Reset to default")`
gated by `canReset`. State collected via `collectAsStateWithLifecycle()`.

### 4.5 Navigation & DI

- Nav: add a route to the **root** `NavHost`:
  `const val SERVER_URL_ROUTE = "settings/server-url"`, exposed via
  `fun NavGraphBuilder.serverUrlScreen(onBack: () -> Unit)` and
  `fun NavController.navigateToServerUrl()`. Login screen gains a "Settings" entry that calls it.
- DI: `ServerUrlViewModel` via `@HiltViewModel`; `HostRepository` is bound in `core-data`
  (AND-014). No new Hilt module is required in `feature-settings` beyond the screen wiring.

## 5. API Contract

No new HTTP endpoints. This screen reads/writes a local DataStore value (via `HostRepository`)
and has no request/response payloads of its own. Its sole network-facing effect is **indirect**:
the persisted value becomes the host that AND-014's `HostSelectionInterceptor` applies to all
subsequent calls (e.g. `POST /ui/session/start` → `UiSessionStartResp`, `GET /ui/me`). Both
endpoints are confirmed in the backend OpenAPI (see §16). Endpoint contracts for those flows are
owned by their respective tickets (E02 networking, E05 auth).

For manual verification the screen pairs with the connectivity probe (if present) or any
existing GET; the simplest verified app endpoint for a smoke probe is `GET /health` (op
`health_health_get`, returns 200, no params/auth). The previously-cited `GET /openapi.json`
is a FastAPI documentation default and does **not** appear in the backend route index — do not
rely on it; prefer `GET /health`. An optional "Test connection" affordance is **out of scope**
here and noted as an open question (§13).

## 6. Data & State Management

- **Storage:** Preferences DataStore key `host_base_url` (owned by AND-014). This screen never
  touches DataStore directly; all reads/writes go through `HostRepository`.
- **Source of truth:** `hostRepository.baseUrl` (a `Flow<String>`). The ViewModel mirrors it
  into `persistedUrl`. The editable `input` is local UI state; it is reseeded from `persistedUrl`
  on a successful save/reset but otherwise tracks user typing.
- **Normalization rules:** trim; require absolute URL; scheme lowercased to `http`/`https`;
  strip trailing `/`; drop empty path/query/fragment; keep explicit non-default port. Examples:
  `  HTTP://18.222.237.167:8000/  ` → `http://18.222.237.167:8000`;
  `https://api.example.com` → `https://api.example.com`;
  `https://api.example.com:443/` → `https://api.example.com:443` (explicit port preserved).
- **Validation matrix (drives unit tests):**

  | Input | Result |
  |---|---|
  | `` (blank) | Invalid(BLANK) |
  | `not a url` | Invalid(MALFORMED) |
  | `ftp://h:21` | Invalid(BAD_SCHEME) |
  | `http://` | Invalid(NO_HOST) |
  | `http://h:0` / `http://h:70000` | Invalid(BAD_PORT) |
  | `http://18.222.237.167:8000` | Valid(cleartext=true) |
  | `https://api.example.com` | Valid(cleartext=false) |

- **Process death:** `input` survives via `SavedStateHandle` (key `"server_url_input"`) so an
  in-progress edit is not lost; persisted value is always recoverable from DataStore.

## 7. Error Handling & Resilience

- **Invalid input** is a UI-layer concern: surfaced as `error: UrlError` mapped to a localized
  string in `supportingText`; Save stays disabled; nothing is persisted (FR-7).
- **Persistence failure:** `setBaseUrl`/`resetToDefault` are local DataStore writes and rarely
  fail, but the calls are wrapped so an `IOException` results in `SettingsMessage.Failed` (snackbar
  "Could not save server URL") and `saving = false`; the persisted value is unchanged.
- **No network coupling:** this screen does not perform network requests, so backend timeouts,
  the 20s/backoff policy, and offline/stale states do not apply here. Changing the URL to an
  unreachable host is permitted by design; surfacing reachability is downstream (E02/E05) and
  the screen does not block on it.
- **Idempotent operations:** Save and Reset are idempotent against the store; double-taps while
  `saving` are ignored (Save disabled during the write).

## 8. Security & Privacy

- **Cleartext by design:** the default host is plaintext HTTP. The app's network-security config
  (owned by AND-014/E02) must permit cleartext for the configured host; this screen surfaces an
  advisory `http` warning (FR-9) but does not enforce TLS.
- **Injection surface:** the persisted value is fed to OkHttp as a base URL only; it is never
  used in shell/SQL/WebView contexts. Validation rejects non-http(s) schemes, preventing
  `file://`, `content://`, `javascript:` etc. from being stored.
- **No secrets:** the base URL is not sensitive; it is stored in plain Preferences DataStore,
  not encrypted storage. No credentials are entered or shown on this screen.
- **Pre-login exposure:** the screen is intentionally reachable without a session; it exposes
  only the configurable host, which is non-sensitive. No auth state is read or mutated.

## 9. Accessibility & i18n

- All strings live in `feature-settings/src/main/res/values/strings.xml`
  (`settings_server_url_title`, `settings_server_url_label`, `settings_server_url_current`,
  `settings_save`, `settings_reset_default`, error strings `settings_url_err_*`,
  `settings_http_warning`, `settings_saved`, `settings_reset_done`, `settings_save_failed`).
- `OutlinedTextField` uses `supportingText` for errors so TalkBack announces them; `isError`
  sets the accessibility error state. The text field has a content description via its label.
- Touch targets ≥ 48dp; buttons use Material 3 defaults. Layout reflows under font scale
  (no fixed heights on text). Back navigation has a `contentDescription`.
- RTL-safe (standard Compose layout, no hardcoded start/end). The URL field itself stays LTR.

## 10. Telemetry & Logging

- **Events** (via the app's analytics abstraction if available, else no-op): `settings_server_url_opened`,
  `settings_server_url_saved` (property: `scheme` ∈ {http, https}; **never log the host/full URL**),
  `settings_server_url_reset`, `settings_server_url_validation_failed` (property: `reason` = `UrlError` name).
- **Logging:** debug-only `Timber.d` on save/reset transitions; do not log the full URL at
  `INFO`+ in release (it can reveal internal infra). No PII is involved.

## 11. Testing Strategy

- **Unit — validator (`BaseUrlValidatorTest`):** cover the full §6 matrix plus normalization
  (trailing slash, scheme case, whitespace, explicit port preservation). Pure JVM, no Android.
- **Unit — ViewModel (`ServerUrlViewModelTest`):** with a fake `HostRepository`
  (`FakeHostRepository` in `core-testing`) backed by a `MutableStateFlow`:
  - init seeds `input`/`persistedUrl`/`defaultUrl` from the repo.
  - `onInputChange` toggles `error`, `cleartextWarning`, and `canSave` correctly (valid+changed → true;
    valid+unchanged → false; invalid → false).
  - `onSave` calls `setBaseUrl(normalized)` exactly once, emits `Saved`, and reseeds state.
    **Asserts the acceptance criterion: a saved valid URL is persisted to the repo** (the fake's
    stored value equals the normalized input) — proxy for "used immediately" since the interceptor
    reads the same store.
  - `onSave` with invalid input never calls `setBaseUrl` (asserts "invalid input rejected").
  - `onResetToDefault` calls `resetToDefault`, sets `input` to `default`, emits `ResetDone`,
    and `canReset` flips to false.
  - persistence `IOException` → `Failed` message, value unchanged.
  - Use `kotlinx-coroutines-test` `runTest` + `StandardTestDispatcher` (set via `core-testing`
    `MainDispatcherRule`) and Turbine for `StateFlow` assertions.
- **UI — Compose (`ServerUrlSettingsScreenTest`, `createAndroidComposeRule`):** entering an
  invalid URL shows the error and disables Save; entering a valid different URL enables Save;
  tapping Save shows the confirmation snackbar; Reset restores the default text.
- **Integration (optional, lightweight):** with a real DataStore-backed `HostRepository` in a
  Robolectric/instrumented test, save a URL and assert `baseUrl.first()` emits the normalized value,
  proving the persisted change is observable by the interceptor (closing the loop with AND-014).
- Coverage target for the validator and ViewModel: 100% of branches in the validation matrix and
  state transitions.

## 12. Dependencies & Sequencing

- **Depends on AND-014** (host selection interceptor + runtime base-URL store). This ticket is
  the UI over that store; it must consume AND-014's `HostRepository`/DataStore key rather than
  introducing its own. AND-014 transitively depends on AND-010 (Retrofit/Moshi) and AND-009/006.
- **Blocks:** none in the current backlog declare a hard dependency on AND-041. It is a
  standalone tool screen; auth (E05) and connectivity flows benefit from it operationally but do
  not import it.
- **Sequencing:** implement after AND-014 merges so the repository contract is final. The
  feature module, navigation route, and login "Settings" affordance can be scaffolded in parallel
  using a fake `HostRepository`, then bound to the real one.

## 13. Risks & Open Questions

- **R1 — Contract drift with AND-014.** If AND-014's store API differs from §4.1, a thin adapter
  in `core-data` is required. Mitigation: agree the `HostRepository` signature with the AND-014
  owner before coding; keep this screen depending only on the interface.
- **R2 — "Used immediately" verification.** The acceptance criterion's "used immediately" is
  proven indirectly (persisted value == interceptor's source). A true end-to-end assertion needs
  a live request, deferred to E02 integration tests. Open question: should this screen include a
  "Test connection" button (one `GET /health` — the verified unauthenticated probe endpoint,
  `op=health_health_get`, 200 with no params — against the candidate URL) for instant feedback?
  Proposed: **out of scope here**, track as a follow-up.
- **R3 — Port/IPv6 edge cases.** `HttpUrl` parsing (`toHttpUrlOrNull()`) handles IPv6 brackets;
  ensure the validator and normalizer round-trip `http://[::1]:8000`. Add a test case.
- **R4 — Cleartext policy.** If the network-security config does not allow the user-entered host,
  requests will fail despite a "valid" URL. Out of scope (E02 owns the config) but worth a doc note.

## 14. Acceptance Criteria

AC-1. (Source) **Edited URL persists and is used immediately.** Entering a valid URL different
from the current value enables Save; tapping Save writes the normalized URL through
`HostRepository.setBaseUrl`, and `hostRepository.baseUrl` subsequently emits that value (the same
store the interceptor reads), with no app restart. Covered by `ServerUrlViewModelTest` and the
optional DataStore integration test.

AC-2. (Source) **Invalid input is rejected (tested).** Each row of the §6 invalid matrix
produces the mapped `UrlError`, an inline error message, a disabled Save button, and **no write**
to the repository. Covered by `BaseUrlValidatorTest` and `ServerUrlViewModelTest`.

AC-3. **Reset to default** restores `BuildConfig.BASE_URL`, persists it, updates the field, and
disables itself when already at default.

AC-4. **Reachable pre-login:** the screen opens from the login screen with no session and
performs no auth calls.

AC-5. **Normalization:** whitespace trimmed, scheme lowercased, trailing slash removed, explicit
port preserved, per §6 examples.

AC-6. **Cleartext advisory** shown for `http` schemes without blocking Save (FR-9).

## 15. Definition of Done

- `feature-settings` module created with `ServerUrlSettingsScreen`, `ServerUrlViewModel`,
  `BaseUrlValidator`, and nav wiring; package `com.testlogon.android.feature.settings`.
- Login screen exposes a "Settings" affordance navigating to `SERVER_URL_ROUTE`.
- Consumes AND-014's `HostRepository`; no duplicate DataStore key introduced.
- Unit tests (validator + ViewModel) and at least one Compose UI test pass; validator/ViewModel
  branch coverage meets §11 target. CI green on the `android-port` branch.
- All user-facing strings externalized; TalkBack announces errors; targets ≥ 48dp; font-scale safe.
- No full-URL logging at `INFO`+; telemetry events emit scheme only.
- `ktlint`/`detekt` clean; `./gradlew :feature-settings:testDebugUnitTest
  :feature-settings:lintDebug` passes.
- Manual smoke: change host to a reachable alternate, observe next request hits the new host
  (verified with AND-014 in place); reset returns to default.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Claim:** The persisted base URL feeds subsequent backend calls including `POST /ui/session/start`.
   **VERDICT: Verified.** SOURCE: OpenAPI `POST /ui/session/start` (`op=ui_session_start_ui_session_start_post`, `req=UiSessionStartReq`, `resp=200:UiSessionStartResp;422:HTTPValidationError`) — openapi.index.txt line 1848.

2. **Claim:** `GET /ui/me` is an authenticated endpoint behind the same host.
   **VERDICT: Verified.** SOURCE: OpenAPI `GET /ui/me` (`op=ui_me_ui_me_get`, `resp=200:;422:HTTPValidationError`, `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`) — openapi.index.txt line 1638.

3. **Claim (original spec §5/§13):** A "Test connection" probe could hit `GET /openapi.json`.
   **VERDICT: Corrected.** `/openapi.json` does NOT appear anywhere in the backend route index or references; it is only a FastAPI documentation default and is not a guaranteed app route. Corrected to `GET /health`. SOURCE: OpenAPI `GET /health` (`op=health_health_get`, `resp=200:`, no params/auth) — openapi.index.txt line 273; absence of `/openapi.json` confirmed by Grep over the entire `reference/` tree (0 matches).

4. **Claim:** The base-URL normalization should strip a trailing `/`.
   **VERDICT: Verified (matches web client behavior).** The web client computes `API_BASE_URL` as `(VITE_API_BASE_URL ?? "").replace(/\/$/, "")` — i.e. trailing slash stripped — and `withApiBase` joins paths with a single slash. SOURCE: `src/api/client.ts:7` and `src/api/client.ts:9-14` (`withApiBase`). Mirrored in `src/api/endpoints/profile.ts:63,71-72`.

5. **Claim (original spec §4.2):** Validate by parsing with `okhttp3.HttpUrl.parse(...)`.
   **VERDICT: Corrected.** The static `HttpUrl.parse(String)` form is deprecated in OkHttp 4.x (Kotlin-first API); the supported form is the extension `String.toHttpUrlOrNull()` on `okhttp3.HttpUrl.Companion`. Corrected in §4.2 and §13/R3. SOURCE: framework ref — OkHttp 4.x upgrade guide, https://square.github.io/okhttp/upgrading_to_okhttp_4/ (HttpUrl moved to Kotlin companion extensions). Stack is OkHttp 4.x via AND-010 (Retrofit/Moshi), Kotlin 2.0.21 — spec §2.

6. **Claim:** Backend 422 validation errors use the `HTTPValidationError` shape (`{ detail: ValidationError[] }`, each `{ loc, msg, type }`).
   **VERDICT: Verified.** SOURCE: OpenAPI `components.schemas.HTTPValidationError` (openapi.pretty.json line 37133) and `components.schemas.ValidationError` (line 80337; required `loc`, `msg`, `type`). Note: this shape is only relevant to downstream E02/E05 calls, not to this local-only screen.

7. **Claim:** The web client uses CSRF (`ui_csrf` cookie → `X-CSRF-Token` header) and Bearer auth, with 401→refresh.
   **VERDICT: Verified — but out of scope for AND-041.** This screen performs no network calls, so it neither sends nor depends on these. SOURCE: `src/api/client.ts:157-171` (Authorization + `ui_csrf` → `X-CSRF-Token`), `src/api/client.ts:121-130,194-237` (refresh-on-401). Recorded here so the §5 "no auth/CSRF on this screen" claim is verified against the real transport.

8. **Claim:** This ticket introduces no new HTTP endpoints; it reads/writes a local DataStore value via `HostRepository` (AND-014).
   **VERDICT: Verified (scope) / Unverified-assumption (AND-014 internals).** No endpoint maps to this screen's behavior in the OpenAPI index. The `HostRepository`/DataStore key `host_base_url` and the `HostSelectionInterceptor` are owned by AND-014, which is not present in the provided sources — see Open assumptions.

9. **Claim (framework choices §2):** Compose + Material 3, Navigation-Compose, Hilt (KSP), DataStore (Preferences), `collectAsStateWithLifecycle()`, `SavedStateHandle` for process death.
   **VERDICT: Unverified-assumption (framework ref).** These are standard AndroidX choices consistent with the stated stack; no project source was provided to confirm module wiring. Framework refs: Compose state collection https://developer.android.com/jetpack/compose/state ; DataStore https://developer.android.com/topic/libraries/architecture/datastore ; SavedStateHandle https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate .

10. **Claim:** Default dev host is `http://18.222.237.167:8000` (cleartext), surfaced via `BuildConfig.BASE_URL`.
    **VERDICT: Unverified-assumption.** This value is not present in the provided backend/frontend sources (the web client reads `VITE_API_BASE_URL` from env, not a hardcoded IP). Plausible as a build-config default but not verifiable here.

### Corrections made

- **§5 & §13/R2:** Replaced the `GET /openapi.json` probe reference with the verified `GET /health` endpoint; `/openapi.json` is not in the backend route index (claim #3).
- **§5:** Tied the example downstream calls to verified OpenAPI entries (`POST /ui/session/start` → `UiSessionStartResp`, `GET /ui/me`) and removed the unverifiable `GET /openapi.json` example (claims #1, #2, #3).
- **§4.2 & §13/R3:** Replaced deprecated static `okhttp3.HttpUrl.parse(...)` with the OkHttp 4.x extension `String.toHttpUrlOrNull()` (claim #5).

### Open assumptions

- **AND-014 contract (`HostRepository`, DataStore key `host_base_url`, `HostSelectionInterceptor`):** not present in the provided sources; this spec consumes an interface it cannot verify. Risk tracked as §13/R1. If AND-014 names the type/key differently, an alias/adapter is required (no second DataStore key).
- **`BuildConfig.BASE_URL = http://18.222.237.167:8000`:** the concrete default host is an assumption; the web client uses an env var, not a hardcoded IP (claim #10).
- **Android framework module wiring** (Hilt/KSP, Navigation-Compose route registration, Material 3 versions): assumed from the stated stack; no Android project source was provided to confirm (claim #9).
- **Telemetry/analytics abstraction (§10):** existence is conditional ("if available, else no-op"); not verifiable from sources.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device); **EMU** = headless emulator AVD `test35` (x86_64, API 35) for fast CI UI/instrumented suites; **DEVICE** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). This ticket is a local-only Compose settings screen with no hardware dependencies, so most cases run on JVM/EMU; one ABI-difference case is noted for DEVICE.

- **TC-AND-041-01** — Type: unit (JVM). Target: `BaseUrlValidatorTest` (`BaseUrlValidator.validate`).
  Preconditions: none. Steps: feed each §6 matrix row (blank, `not a url`, `ftp://h:21`, `http://`, `http://h:0`, `http://h:70000`, `http://18.222.237.167:8000`, `https://api.example.com`). Expected: `BLANK`, `MALFORMED`, `BAD_SCHEME`, `NO_HOST`, `BAD_PORT`, `BAD_PORT`, `Valid(cleartext=true)`, `Valid(cleartext=false)` respectively. Traces: AC-2, AC-6.

- **TC-AND-041-02** — Type: unit (JVM). Target: `BaseUrlValidatorTest` normalization.
  Preconditions: none. Steps: validate `"  HTTP://18.222.237.167:8000/  "`, `"https://api.example.com"`, `"https://api.example.com:443/"`. Expected normalized: `http://18.222.237.167:8000`, `https://api.example.com`, `https://api.example.com:443` (trim, scheme lowercased, trailing slash stripped, explicit port preserved — matches web client `replace(/\/$/, "")`, `src/api/client.ts:7`). Traces: AC-5.

- **TC-AND-041-03** — Type: unit (JVM). Target: `BaseUrlValidatorTest` IPv6 round-trip (§13/R3).
  Preconditions: none. Steps: validate `http://[::1]:8000`. Expected: `Valid`, normalized preserves bracketed IPv6 host and port (`http://[::1]:8000`), via `toHttpUrlOrNull()`. Traces: AC-5.

- **TC-AND-041-04** — Type: unit (JVM). Target: `ServerUrlViewModelTest` init seeding (fake `HostRepository` over `MutableStateFlow`, `MainDispatcherRule`, Turbine).
  Preconditions: fake repo `baseUrl` emits `http://18.222.237.167:8000`, `default = http://18.222.237.167:8000`. Steps: construct VM, collect first non-empty state. Expected: `input == persistedUrl == defaultUrl == http://18.222.237.167:8000`; `canSave=false`, `canReset=false`. Traces: AC-1, AC-3.

- **TC-AND-041-05** — Type: unit (JVM). Target: `ServerUrlViewModelTest` `onInputChange` gating.
  Preconditions: persisted = `http://18.222.237.167:8000`. Steps: (a) input a valid different URL `https://staging.example.com`; (b) input the unchanged persisted value; (c) input `ftp://h:21`. Expected: (a) `error=null`, `cleartextWarning=false`, `canSave=true`; (b) `canSave=false`; (c) `error=BAD_SCHEME`, `canSave=false`. Traces: AC-1, AC-2, AC-6.

- **TC-AND-041-06** — Type: unit (JVM). Target: `ServerUrlViewModelTest` `onSave` happy path.
  Preconditions: valid changed input `https://staging.example.com`, `canSave=true`. Steps: call `onSave()`. Expected: `setBaseUrl("https://staging.example.com")` called exactly once on the fake; fake's stored value equals normalized input; `SettingsMessage.Saved` emitted; state reseeds (`persistedUrl` updated, `canSave=false`). This proves "persisted and used immediately" (interceptor reads the same store). Traces: AC-1.

- **TC-AND-041-07** — Type: unit (JVM). Target: `ServerUrlViewModelTest` invalid save guard.
  Preconditions: input `http://` (NO_HOST). Steps: call `onSave()`. Expected: `setBaseUrl` never invoked; repo value unchanged; `error=NO_HOST` retained; no `Saved` message. Traces: AC-2.

- **TC-AND-041-08** — Type: unit (JVM). Target: `ServerUrlViewModelTest` reset.
  Preconditions: persisted `https://staging.example.com`, default `http://18.222.237.167:8000`, so `canReset=true`. Steps: call `onResetToDefault()`. Expected: `resetToDefault()` called; `input` becomes the default; `SettingsMessage.ResetDone` emitted; `canReset` flips to false. Traces: AC-3.

- **TC-AND-041-09** — Type: unit (JVM). Target: `ServerUrlViewModelTest` persistence failure.
  Preconditions: fake repo configured so `setBaseUrl` throws `IOException`; valid changed input. Steps: call `onSave()`. Expected: `SettingsMessage.Failed("Could not save server URL")` emitted; `saving=false`; persisted value unchanged. (Local DataStore offline/flaky-write analog — no network.) Traces: AC-1 (negative path).

- **TC-AND-041-10** — Type: Compose-UI (EMU; `createAndroidComposeRule`). Target: `ServerUrlSettingsScreenTest`.
  Preconditions: screen launched with fake repo at default. Steps: type an invalid URL → observe; clear and type a valid different URL → observe; tap Save → observe; tap Reset → observe. Expected: invalid shows inline `supportingText` error and Save disabled; valid-different enables Save; Save shows confirmation snackbar and updates "Current:"; Reset restores default text. Traces: AC-1, AC-2, AC-3, AC-5.

- **TC-AND-041-11** — Type: Compose-UI (EMU). Target: `ServerUrlSettingsScreenTest` cleartext advisory + accessibility.
  Preconditions: screen at default. Steps: enter `http://newhost:9000`; inspect supporting/warning text and Save state; run accessibility checks (enable `AccessibilityChecks`/Espresso a11y; assert TalkBack semantics). Expected: non-blocking "Connection is not encrypted (HTTP)" warning shown, Save still enabled (valid+changed); error semantics set via `isError`+`supportingText`; back button has `contentDescription`; touch targets ≥ 48dp; layout reflows under font scale. Traces: AC-6, AC-2 (a11y of error state).

- **TC-AND-041-12** — Type: integration (JVM/Robolectric or EMU instrumented). Target: real DataStore-backed `HostRepository` (closing loop with AND-014).
  Preconditions: real Preferences DataStore in a temp dir. Steps: call `setBaseUrl("https://staging.example.com")` via the VM/repo, then read `baseUrl.first()`. Expected: emits the normalized value, proving the persisted change is observable by the interceptor's source of truth (no restart). Traces: AC-1.

- **TC-AND-041-13** — Type: instrumented/e2e (EMU). Target: pre-login navigation + no-auth assertion.
  Preconditions: app launched, unauthenticated. Steps: from the login screen, open the "Settings" affordance → land on `settings/server-url`; assert no session/auth call occurred (e.g. no `Authorization` header, no `/ui/session/start` issued from this flow — MockWebServer/interceptor recorder). Expected: screen opens without a session and performs no auth calls. Traces: AC-4.

- **TC-AND-041-14** — Type: instrumented (DEVICE — physical Samsung A15, API 34/arm64-v8a). Target: ABI/API parity of validator + persistence.
  Preconditions: app installed on device serial R5CX821TA9R. Steps: run the validator/normalizer and a save+read round-trip (`http://[::1]:8000`, `https://api.example.com:443/`) on-device. Expected: identical normalization/validation results and persisted values as JVM/EMU runs (guards against arm64-vs-x86 and API-34-vs-35 differences in `HttpUrl` parsing and DataStore). MUST run on the physical device for the arm64/API-34 dimension; EMU `test35` covers x86_64/API-35. Traces: AC-1, AC-2, AC-5.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (edited URL persists & used immediately) | TC-04, TC-05, TC-06, TC-09, TC-10, TC-12, TC-14 |
| AC-2 (invalid input rejected, tested) | TC-01, TC-05, TC-07, TC-10, TC-11, TC-14 |
| AC-3 (reset to default) | TC-04, TC-08, TC-10 |
| AC-4 (reachable pre-login, no auth) | TC-13 |
| AC-5 (normalization) | TC-02, TC-03, TC-10, TC-14 |
| AC-6 (cleartext advisory, non-blocking) | TC-01, TC-05, TC-11 |
