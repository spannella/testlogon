---
id: AND-387
title: Account closure / suspend / reactivate
milestone: M8
epic: E50
priority: P1
size: L
status: draft
depends_on: [AND-082]
blocks: []
---

# AND-387 — Account closure / suspend / reactivate

## 1. Overview & Goal

Implement the destructive and lifecycle account-state transitions for the TestLogon
native Android app: **closure** (a two-step start/finalize flow), **suspend** (a
self-service temporary hold), **reactivate** (lifting a suspension or recalling a
pending closure), and **status** (the read that drives which actions are offered).

The entry points (links, deep links, account status read) are owned by **AND-082**
(`Account settings & status entry`), which "hands off to E50" for the actual
destructive flows. This ticket (E50) owns the flow screens, the repository/API layer
for the four account-lifecycle endpoints, the ViewModel state machine, and the strong
confirmation UX (typed confirmation for irreversible closure, re-auth gate, undo
window display).

Goal: a user can close, suspend, or reactivate their account through guarded,
reversible-where-possible flows that are resilient to the unreliable dev backend, with
explicit confirmations on every destructive transition and a clear post-action state
(signed out on closure/suspend; returned to active on reactivate).

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-account` (shared with AND-082). New package
  `com.testlogon.android.feature.account.closure`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/account.ts`, `frontend/src/api/types.ts`.
- Reused infrastructure: cookie jar (AND-011), CSRF interceptor (AND-012), 401
  refresh authenticator (AND-013), `ApiResult<T>` (AND-018), FastAPI `detail`
  mapping (AND-015), retry/backoff for idempotent GETs (AND-016), state composables
  (AND-021), core input composables incl. OTP/typed field (AND-020), auth state
  store / `getMe` (AND-029), logout teardown (AND-032).
- Upstream: **AND-082** provides nav destinations `account/closure`,
  `account/suspend`, `account/reactivate`, and the cached `AccountStatus` shown on
  the settings screen.

## 3. Functional Requirements

**FR-1 Status gating.** Before rendering any lifecycle action, fetch `GET
/ui/account/status`. The returned `state` (`active | suspended | pending_closure |
closed`) determines available actions:
- `active` → Suspend, Close.
- `suspended` → Reactivate (and Close, if backend allows).
- `pending_closure` → Reactivate (cancel pending closure); show
  `closure_effective_at` countdown.
- `closed` → no actions; informational terminal screen only.

**FR-2 Closure start.** `POST /ui/account/closure/start` with an optional `reason`.
Returns a `closure_id`, the `grace_period_days`, and `effective_at`. The UI must show
a summary of consequences (data retention window, undo window) before enabling
finalize.

**FR-3 Closure finalize.** `POST /ui/account/closure/finalize` with `closure_id`.
Gated behind a **typed confirmation** ("Type CLOSE to confirm") AND a re-auth
confirmation (password re-entry surfaced via the existing challenge primitive when the
backend responds `auth_required`). On success the client performs full logout teardown
(AND-032): clear cookie jar, clear auth state store, navigate to the unauthenticated
graph.

**FR-4 Suspend.** `POST /ui/account/suspend` with optional `reason` and optional
`duration_days`. Single strong confirm (no typed token; suspend is reversible). On
success, sign the user out (session no longer valid) and route to a "Account
suspended" terminal screen with a Reactivate affordance reachable from the login area.

**FR-5 Reactivate.** `POST /ui/account/reactivate`. Used to (a) lift a suspension or
(b) cancel a pending closure. Single confirm. On success, refresh
`AccountStatus`/`getMe` and route back to account settings showing `active`.

**FR-6 Confirmations.** Every destructive transition shows a Material 3
`AlertDialog`-style confirmation. Closure-finalize additionally requires the typed
token to be exactly `CLOSE` (case-sensitive) before its confirm button enables.

**FR-7 Idempotency / double-submit guard.** All four mutations are POSTs and MUST NOT
be auto-retried. The confirm button disables while in flight (`Submitting` state).

**FR-8 Status read resilience.** The status read is an idempotent GET and uses the
AND-016 backoff; failures render an offline/error state (AND-021) with retry, never a
crash and never optimistic action enablement.

## 4. Technical Design

Module: `feature-account`. New files under
`com.testlogon.android.feature.account.closure`.

### State model

```kotlin
enum class AccountState { ACTIVE, SUSPENDED, PENDING_CLOSURE, CLOSED, UNKNOWN }

data class AccountStatus(
    val state: AccountState,
    val suspendedUntil: Instant?,        // nullable
    val closureId: String?,              // present when PENDING_CLOSURE
    val closureEffectiveAt: Instant?,    // present when PENDING_CLOSURE
    val gracePeriodDays: Int?,
)

sealed interface AccountLifecycleUiState {
    data object Loading : AccountLifecycleUiState
    data class Offline(val cached: AccountStatus?) : AccountLifecycleUiState
    data class Error(val message: String, val cached: AccountStatus?) : AccountLifecycleUiState
    data class Ready(
        val status: AccountStatus,
        val action: ActionState = ActionState.Idle,
    ) : AccountLifecycleUiState
}

sealed interface ActionState {
    data object Idle : ActionState
    data class ConfirmClosureStart(val reason: String) : ActionState
    data class ConfirmClosureFinalize(val closureId: String, val typed: String) : ActionState
    data object Submitting : ActionState
    data class ReAuthRequired(val challengeId: String) : ActionState  // closure finalize re-auth
    data class Failed(val message: String) : ActionState
    data class Done(val outcome: Outcome) : ActionState
}

enum class Outcome { CLOSED_SIGNED_OUT, SUSPENDED_SIGNED_OUT, REACTIVATED }
```

### Repository

```kotlin
interface AccountLifecycleRepository {
    suspend fun status(): ApiResult<AccountStatus>
    suspend fun startClosure(reason: String?): ApiResult<ClosureStartResult>
    suspend fun finalizeClosure(closureId: String): ApiResult<Unit>          // may return auth_required
    suspend fun suspend(reason: String?, durationDays: Int?): ApiResult<Unit>
    suspend fun reactivate(): ApiResult<AccountStatus>
}

data class ClosureStartResult(
    val closureId: String,
    val effectiveAt: Instant,
    val gracePeriodDays: Int,
)
```

`AccountLifecycleRepositoryImpl` injects `AccountApi` (Retrofit) + `AuthStateStore`
(AND-029) + `SessionTeardown` (AND-032). It maps DTOs to domain via Moshi adapters
and `ApiErrorMapper` (AND-015). `finalizeClosure` and `suspend`, on `ApiResult.Success`,
invoke `SessionTeardown.clear()` (cookie jar + DataStore auth state) before returning.

### ViewModel

```kotlin
@HiltViewModel
class AccountLifecycleViewModel @Inject constructor(
    private val repo: AccountLifecycleRepository,
) : ViewModel() {
    val uiState: StateFlow<AccountLifecycleUiState> // backed by MutableStateFlow, initial Loading

    fun load()                                   // GET status, idempotent, backoff
    fun requestSuspend(reason: String?, days: Int?)
    fun confirmSuspend()
    fun requestClosure(reason: String?)          // -> closure/start, then ConfirmClosureFinalize
    fun onTypedTokenChange(value: String)
    fun confirmClosureFinalize()
    fun submitReAuth(password: String)           // when ReAuthRequired
    fun reactivate()
    fun dismissDialog()
}
```

The ViewModel is the single state machine: `load → Ready(Idle)`; an action moves to a
`Confirm*` state (renders dialog); confirm moves to `Submitting`; success moves to
`Done(outcome)` (the screen observes and triggers navigation/teardown) or
`ReAuthRequired`; failure moves to `Failed(message)` while keeping the prior status.

### Compose screens

- `AccountClosureScreen(viewModel, onClosed: () -> Unit)` — start summary +
  finalize. Uses `OutlinedTextField` for `reason`, `ConfirmTokenField` (from AND-020)
  for the typed `CLOSE` token, and `StateScaffold` (AND-021) for Loading/Offline/Error.
- `AccountSuspendScreen(viewModel, onSuspended: () -> Unit)`.
- `AccountReactivateScreen(viewModel, onReactivated: () -> Unit)`.
- `AccountClosedScreen()` — terminal, no actions.

Navigation routes (defined by AND-082, consumed here):
`account/closure`, `account/suspend`, `account/reactivate`. On `Done`, the screen
calls the appropriate callback; closure/suspend callbacks pop to the unauthenticated
graph root (`auth/login`), reactivate pops back to `account/settings`.

## 5. API Contract

All paths are relative to the active base URL. Cookies + `X-CSRF-Token` header are
applied by interceptors; do not set them manually. All four mutations send
`Content-Type: application/json` and are **non-idempotent** (no auto-retry).

**GET `/ui/account/status`** (idempotent; AND-016 backoff)
```json
{ "state": "active",
  "suspended_until": null,
  "closure": null,
  "grace_period_days": 30 }
```
When pending closure:
```json
{ "state": "pending_closure",
  "suspended_until": null,
  "closure": { "closure_id": "clo_8f2a", "effective_at": "2026-07-05T00:00:00Z" },
  "grace_period_days": 30 }
```

**POST `/ui/account/closure/start`**
```json
// request
{ "reason": "no longer using" }
// 200
{ "closure_id": "clo_8f2a",
  "effective_at": "2026-07-05T00:00:00Z",
  "grace_period_days": 30 }
```

**POST `/ui/account/closure/finalize`**
```json
// request
{ "closure_id": "clo_8f2a" }
// 200 (immediate close)
{ "state": "closed", "closed_at": "2026-06-05T12:00:00Z" }
// 200 (re-auth challenge)
{ "auth_required": true, "challenge_id": "ch_re_19", "required_factors": ["password"] }
```
When `auth_required` is returned, the client posts the password through the existing
challenge verify primitive against `challenge_id`, then re-calls finalize.

**POST `/ui/account/suspend`**
```json
// request
{ "reason": "taking a break", "duration_days": 14 }
// 200
{ "state": "suspended", "suspended_until": "2026-06-19T00:00:00Z" }
```

**POST `/ui/account/reactivate`**
```json
// request  (empty body permitted)
{}
// 200
{ "state": "active" }
```

**Error mapping.** FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is decoded by
`ApiErrorMapper` (AND-015). Notable codes to surface specifically:
`409 closure_already_pending`, `409 already_suspended`, `403 reactivation_window_expired`,
`401` (handled by the AND-013 authenticator one refresh, then bubbled as Failed).

## 6. Data & State Management

- **Source of truth:** `AccountStatus` is fetched fresh on each entry into a flow
  screen (`load()` in `init`). The cached value from AND-082 may be passed via nav arg
  to render an immediate skeleton, but the action gate (FR-1) MUST use the freshly
  fetched status; never enable a destructive action off stale cache.
- **No Room caching** of lifecycle status — it is short-lived and security-sensitive;
  it is held only in the `StateFlow` for the screen's lifetime. (The settings-level
  snapshot cache is AND-082's concern.)
- **DataStore:** on successful closure or suspend, `AuthStateStore` (AND-029) is
  cleared via `SessionTeardown` (AND-032), which also wipes the persistent cookie jar
  (AND-011). On reactivate, re-trigger `getMe` so the auth state reflects `active`.
- **Process death:** `Confirm*` and typed-token state are held in `SavedStateHandle`
  so a dialog/typed token survives recreation; `Submitting` is NOT persisted (on
  recreate, re-fetch status to learn the true outcome rather than re-submitting).

## 7. Error Handling & Resilience

- **Timeouts:** rely on the OkHttp ~20s client (AND-009). Status GET uses bounded
  backoff (AND-016); mutations get a single attempt with no retry.
- **Offline status read:** render `AccountLifecycleUiState.Offline` with a Retry
  button (AND-021 composable); actions hidden until a successful status load.
- **Mutation failure:** transition `ActionState.Failed(message)` while keeping the
  current `Ready.status`; show an inline error in the dialog, keep confirm enabled for
  a manual retry. The user is never silently signed out on failure.
- **Partial/ambiguous (timeout after submit):** because mutations are not retried,
  on a network failure during `Submitting` show "We could not confirm the action —
  check your account status" and call `load()` to reconcile actual state.
- **409 already-in-state:** treat `already_suspended` / `closure_already_pending` as
  recoverable — refresh status and route to the matching state screen rather than
  showing a hard error.
- **401:** AND-013 authenticator refreshes once; if still 401, surface a re-auth
  prompt (for finalize) or bubble Failed (for others).

## 8. Security & Privacy

- Destructive transitions are CSRF-protected automatically via the `X-CSRF-Token`
  header (AND-012); confirm the header is present on all four POSTs in tests.
- **Closure finalize requires re-authentication** when the backend returns
  `auth_required`; the password is sent only to the challenge verify endpoint and is
  never logged or persisted. Use `androidx.compose` password masking and never echo it
  into `SavedStateHandle`.
- The typed `CLOSE` token and any free-text `reason` are not PII-sensitive but are
  excluded from telemetry payloads.
- After closure/suspend, all session material (cookies, CSRF cookie, DataStore auth
  state) is purged; no residual `ui_csrf` or session cookie remains in the jar.
- All traffic is plaintext HTTP against the dev host; document this as a known dev-only
  posture (production base URL must be HTTPS). No new cleartext exception is added
  beyond the existing dev flavor allowance.

## 9. Accessibility & i18n

- All strings (action labels, consequence summaries, dialog copy, countdown text) in
  `res/values/strings.xml`; no hardcoded literals. Countdown uses
  plurals (`grace_period_days`).
- Confirmation dialogs use `Modifier.semantics` with role and a clear
  `contentDescription`; the destructive confirm button has `stateDescription`
  reflecting enabled/disabled (typed-token gate).
- Typed-token field announces requirement ("Type CLOSE to confirm") via
  `semantics { contentDescription = ... }`; error/enabled state announced live.
- Minimum 48dp touch targets; destructive actions visually distinguished
  (`MaterialTheme.colorScheme.error`) but not relying on color alone — include a
  warning icon + text.
- Dynamic type and RTL verified; countdown timestamps formatted with the device locale.

## 10. Telemetry & Logging

- Emit structured events (no PII): `account_status_viewed{state}`,
  `closure_start_requested`, `closure_start_succeeded{grace_period_days}`,
  `closure_finalize_confirmed`, `closure_finalize_succeeded`,
  `closure_reauth_required`, `suspend_requested{duration_days}`,
  `suspend_succeeded`, `reactivate_requested`, `reactivate_succeeded`, plus
  `*_failed{error_code}` for each.
- Logging via the app logger; **never** log password, cookies, CSRF token, `reason`
  text, or full `closure_id` (log a truncated prefix only). HTTP body logging for
  these endpoints is redacted at the OkHttp logging interceptor (AND-009) level.
- Event names align with the web reference where one exists; otherwise namespaced
  `android.account.*`.

## 11. Testing Strategy

- **Repository contract tests (MockWebServer, AND-046 harness):** for each endpoint —
  success mapping, `detail` string/list/object error mapping (AND-015), 409
  already-in-state, 403 reactivation_window_expired, and the finalize `auth_required`
  branch. Assert `X-CSRF-Token` present and that mutations are issued exactly once (no
  retry); assert status GET retries per AND-016.
- **Teardown test:** after a 200 from finalize/suspend, assert `SessionTeardown.clear()`
  was invoked and the cookie jar is empty.
- **ViewModel state-machine tests (Turbine):** `load` → Ready by state; typed-token
  gate (confirm disabled until exactly `CLOSE`); `Submitting` non-retriable; failure
  retains prior status; ambiguous-timeout reconciliation re-calls `load()`.
- **Compose UI tests (AND-048/049 patterns):** confirm dialogs render per action; the
  finalize confirm button is disabled until `CLOSE` typed; closed/suspended terminal
  screens expose no destructive actions; offline state shows Retry.
- **Accessibility test:** assert semantics/stateDescription on the gated confirm
  button.

## 12. Dependencies & Sequencing

- **Depends on AND-082** (account settings & status entry) for nav destinations and
  the cached status snapshot, which in turn depends on AND-077 and AND-043.
- **Reuses (must be merged first):** AND-011 (cookie jar), AND-012 (CSRF),
  AND-013 (401 refresh), AND-015 (error mapping), AND-016 (GET backoff),
  AND-018 (ApiResult), AND-020 (input/typed-token field), AND-021 (state composables),
  AND-029 (auth state store / getMe), AND-032 (logout teardown).
- **Sequencing:** (1) DTOs + Moshi adapters + `AccountApi`; (2)
  `AccountLifecycleRepository` + contract tests; (3) ViewModel state machine + unit
  tests; (4) Compose screens wired into AND-082 routes + UI tests.
- **Blocks:** none currently in backlog.

## 13. Risks & Open Questions

- **Q1 (re-auth shape):** Confirm whether closure finalize re-auth reuses the full
  MFA challenge primitive or a password-only sub-flow. Spec assumes a `challenge_id`
  with `required_factors:["password"]`; verify against `/openapi.json`.
- **Q2 (reactivate scope):** Does `/ui/account/reactivate` both lift suspension and
  cancel pending closure, or are these distinct? Spec assumes one endpoint
  disambiguated by current `state`.
- **Q3 (suspend duration):** Is `duration_days` accepted/required, or is suspend
  indefinite until reactivate? Spec treats it as optional.
- **Q4 (session validity after suspend):** Confirm the backend invalidates the session
  on suspend (driving forced sign-out). If not, adjust FR-4 to keep the user signed in
  with a banner.
- **Risk:** ambiguous mutation outcomes on the unreliable dev host; mitigated by
  no-retry + status reconciliation, but a user could perceive a failed action that
  actually succeeded server-side. Reconciliation `load()` is the safeguard.

## 14. Acceptance Criteria

1. From `active`, a user can complete **suspend** with a single strong confirm and is
   signed out to the suspended terminal screen.
2. From `active`, a user can complete **closure** only after `closure/start` succeeds,
   the typed token equals `CLOSE`, and (when prompted) re-auth succeeds; on success the
   session is fully torn down and the app lands on the login screen with an empty cookie
   jar.
3. The closure finalize confirm button is disabled until the typed token is exactly
   `CLOSE`.
4. From `suspended` or `pending_closure`, **reactivate** returns the account to
   `active` and routes to account settings reflecting the new status.
5. `GET /ui/account/status` drives which actions appear; a `closed` account shows the
   terminal screen with no actions.
6. All four mutations carry the `X-CSRF-Token` header, are sent exactly once (no
   auto-retry), and disable their confirm button while in flight.
7. Status-read failure shows an offline/error state with Retry and never enables a
   destructive action.
8. 409 already-in-state responses reconcile to the matching state screen rather than
   erroring.
9. No password, cookie, CSRF token, or `reason` text appears in logs/telemetry.

## 15. Definition of Done

- `AccountApi`, DTOs/adapters, `AccountLifecycleRepository(+Impl)`,
  `AccountLifecycleViewModel`, and the four Compose screens are merged to
  `android-port` under `com.testlogon.android.feature.account.closure`.
- Screens are wired into the AND-082 nav routes; closure/suspend trigger AND-032
  teardown; reactivate refreshes `getMe`.
- Repository contract tests, ViewModel state-machine tests, and Compose UI tests pass
  in CI (AND-050); coverage includes error/`detail` mapping, the re-auth branch, the
  typed-token gate, and teardown verification.
- All strings externalized; accessibility semantics on gated/destructive controls
  verified; ktlint/detekt clean (AND-005).
- Open questions Q1–Q4 either resolved against `/openapi.json` or filed as follow-ups
  with the assumed behavior documented in code comments.
