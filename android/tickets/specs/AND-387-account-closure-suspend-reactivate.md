---
id: AND-387
title: Account closure / suspend / reactivate
milestone: M8
epic: E50
priority: P1
size: L
depends_on: [AND-082]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
/ui/account/status`. The returned `status` field (CORRECTED: the JSON key is `status`,
not `state`; values `active | suspended | closed | closure_pending` — CORRECTED:
`closure_pending`, not `pending_closure`) determines available actions:
- `active` → Suspend, Close.
- `suspended` → Reactivate (and Close, if backend allows).
- `closure_pending` → Reactivate (cancel pending closure). NOTE: the verified
  `AccountState` shape exposes no `effective_at`/`grace_period_days`, so a precise
  countdown is not derivable from the contract; show a generic "closure pending" notice
  unless/until the backend adds those fields (see §16 Open assumptions).
- `closed` → no actions; informational terminal screen only (`closed_at` epoch-seconds
  may be shown).

**FR-2 Closure start.** `POST /ui/account/closure/start` with **NO request body**
(CORRECTED: the OpenAPI declares no requestBody and the web client sends none; the
earlier `reason` field is not part of the contract). Returns
`{ auth_required, challenge_id, required_factors }` (web return type) — i.e. the re-auth
challenge is issued **at start**. The UI must show a summary of consequences (data
retention, irreversibility) before proceeding to finalize.

**FR-3 Closure finalize.** `POST /ui/account/closure/finalize` with **`challenge_id`**
(CORRECTED: the required field of `AccountClosureFinalizeReq` is `challenge_id`, not
`closure_id`) — the value obtained from `closure/start` after the user satisfies the
re-auth challenge. The client additionally gates this behind a **typed confirmation**
("Type CLOSE to confirm"). NOTE: the typed-`CLOSE` token is an Android-only client-side
guard with no backend basis (the web app instead surfaces/echoes the challenge ID); it
is an additive UX decision, not a verified contract requirement (see §16). On success
(`{ "status": "closed" }`) the client performs full logout teardown (AND-032): clear
cookie jar, clear auth state store, navigate to the unauthenticated graph.

**FR-4 Suspend.** `POST /ui/account/suspend` with optional `reason` only (CORRECTED:
`AccountStatusReq` has no `duration_days` field; suspend is indefinite-until-reactivate).
Single strong confirm (no typed token; suspend is reversible). On success
(`{ "status": "suspended" }`) the Android app signs the user out and routes to an
"Account suspended" terminal screen with a Reactivate affordance reachable from the
login area. NOTE: forced sign-out on suspend is an Android design choice — the web
client merely refreshes the status query and does NOT log the user out (see §16
Open assumptions / Q4).

**FR-5 Reactivate.** `POST /ui/account/reactivate` (optional `AccountStatusReq` body
`{reason?}`; the web client sends no body — both are accepted). Used to (a) lift a
suspension or (b) cancel a pending closure. Single confirm. On success
(`{ "status": "active" }`) refresh `AccountStatus`/`getMe` and route back to account
settings showing `active`. NOTE Q2: a single endpoint disambiguated by current `status`
is consistent with the web client (one `reactivateAccount()` call) but the dual purpose
is not explicitly documented in OpenAPI (see §16).

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

> **Review note:** the verified backend `AccountState` JSON is only
> `{ status, reason?, updated_at?, closed_at? }` (epoch-seconds timestamps). The domain
> model below keeps richer fields for forward-compat, but the nullable closure/grace
> fields are NOT currently populated by the backend — map them only if the backend
> begins returning them. The wire `status` strings are `active | suspended | closed |
> closure_pending` (note `CLOSURE_PENDING` ↔ wire `closure_pending`).

```kotlin
enum class AccountState { ACTIVE, SUSPENDED, CLOSURE_PENDING, CLOSED, UNKNOWN }
// wire mapping: "active"->ACTIVE, "suspended"->SUSPENDED,
//               "closure_pending"->CLOSURE_PENDING, "closed"->CLOSED, else->UNKNOWN

data class AccountStatus(
    val state: AccountState,
    val reason: String?,                 // from AccountState.reason
    val updatedAt: Instant?,             // from AccountState.updated_at (epoch SECONDS)
    val closedAt: Instant?,              // from AccountState.closed_at (epoch SECONDS)
    // The following are NOT in the verified contract; populate only if backend adds them:
    val suspendedUntil: Instant? = null,
    val closureChallengeId: String? = null,   // re-auth challenge from closure/start
    val closureEffectiveAt: Instant? = null,
    val gracePeriodDays: Int? = null,
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
    data object ConfirmClosureStart : ActionState  // start takes no body
    data class ConfirmClosureFinalize(val challengeId: String, val typed: String) : ActionState  // CORRECTED: challengeId
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
    suspend fun startClosure(): ApiResult<ClosureStartResult>                 // CORRECTED: no body; returns re-auth challenge
    suspend fun finalizeClosure(challengeId: String): ApiResult<AccountStatus> // CORRECTED: challengeId; returns {status}
    suspend fun suspend(reason: String?): ApiResult<AccountStatus>            // CORRECTED: no durationDays
    suspend fun reactivate(reason: String? = null): ApiResult<AccountStatus>
}

// CORRECTED: closure/start returns the re-auth challenge, not closure_id/grace fields.
data class ClosureStartResult(
    val authRequired: Boolean,
    val challengeId: String,
    val requiredFactors: List<String>,
)
```

`AccountLifecycleRepositoryImpl` injects `AccountApi` (Retrofit) + `AuthStateStore`
(AND-029) + `SessionTeardown` (AND-032). It maps DTOs to domain via Moshi adapters
and `ApiErrorMapper` (AND-015). `finalizeClosure` and `suspend`, on `ApiResult.Success`,
invoke `SessionTeardown.clear()` (cookie jar + DataStore auth state) before returning.
(CORRECTED: the re-auth challenge is surfaced by `startClosure`, whose result carries
`authRequired`/`challengeId`; `finalizeClosure` consumes that `challengeId`.)

### ViewModel

```kotlin
@HiltViewModel
class AccountLifecycleViewModel @Inject constructor(
    private val repo: AccountLifecycleRepository,
) : ViewModel() {
    val uiState: StateFlow<AccountLifecycleUiState> // backed by MutableStateFlow, initial Loading

    fun load()                                   // GET status, idempotent, backoff
    fun requestSuspend(reason: String?)          // CORRECTED: no duration_days in contract
    fun confirmSuspend()
    fun requestClosure()                         // CORRECTED: no body -> closure/start -> re-auth challenge -> ConfirmClosureFinalize
    fun onTypedTokenChange(value: String)
    fun confirmClosureFinalize()
    fun submitReAuth(password: String)           // when ReAuthRequired
    fun reactivate()
    fun dismissDialog()
}
```

The ViewModel is the single state machine: `load → Ready(Idle)`; an action moves to a
`Confirm*` state (renders dialog); confirm moves to `Submitting`; success moves to
`Done(outcome)` (the screen observes and triggers navigation/teardown); failure moves to
`Failed(message)` while keeping the prior status. CORRECTED flow for closure: the
re-auth challenge is returned by **`closure/start`** (not finalize) as
`{auth_required, challenge_id, required_factors}`; `requestClosure()` therefore moves to
`ReAuthRequired(challengeId)` when `auth_required` is true, the user satisfies the
challenge (re-auth primitive), and `confirmClosureFinalize()` then posts that
`challenge_id` to finalize.

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

> **Review note (2026-06-06):** the field shapes below were CORRECTED against
> `reference/openapi.pretty.json` and `reference/src/api/endpoints/account.ts` +
> `types.ts`. The backend OpenAPI declares only `200` (empty/unspecified response
> schema, `schema: {}`) and `422 HTTPValidationError` for all five endpoints — it does
> NOT document the response field names. The concrete response shapes shown here are
> taken from the **web client's declared TypeScript return types** (the contract the web
> app actually consumes) and are labelled accordingly. There are NO documented `409`,
> `403`, or `401` responses in the OpenAPI for these endpoints (see §16).

**GET `/ui/account/status`** (idempotent; AND-016 backoff)
op `account_status_ui_account_status_get`. Returns `AccountState` (web type):
```json
// 200  (AccountState: { status, reason?, updated_at?, closed_at? })
{ "status": "active",
  "reason": null,
  "updated_at": 1749081600,
  "closed_at": null }
```
`status` is one of `active | suspended | closed | closure_pending` (web string values —
note `closure_pending`, NOT `pending_closure`). `updated_at` / `closed_at` are **epoch
SECONDS** (the web multiplies by 1000 for `Date`), not ISO-8601 strings. There is no
`suspended_until`, `closure` object, `grace_period_days`, or `effective_at` field in the
verified contract; treat any countdown/grace-period UI as derived only from data the
backend actually returns (see §16 Open assumptions).

**POST `/ui/account/closure/start`** (op `account_closure_start_..._post`)
```json
// request: NO request body (OpenAPI declares no requestBody; web calls it with no args)
// 200  (web return type)
{ "auth_required": true,
  "challenge_id": "ch_re_19",
  "required_factors": ["password"] }
```
The re-auth challenge originates **here at START** (not at finalize). The web client
captures `challenge_id` from this response and carries it into finalize.

**POST `/ui/account/closure/finalize`** (op `account_closure_finalize_..._post`)
```json
// request  (AccountClosureFinalizeReq — required field is challenge_id, NOT closure_id)
{ "challenge_id": "ch_re_19" }
// 200  (web return type)
{ "status": "closed" }
```
`AccountClosureFinalizeReq` in both the OpenAPI components and `types.ts` has a single
**required** `challenge_id: string`. The client passes the `challenge_id` obtained from
`closure/start` (after the user satisfies the re-auth challenge).

**POST `/ui/account/suspend`** (op `account_suspend_..._post`)
```json
// request  (AccountStatusReq — optional reason ONLY; no duration_days)
{ "reason": "taking a break" }
// 200  (AccountState)
{ "status": "suspended", "reason": "taking a break", "updated_at": 1749081600 }
```
`AccountStatusReq` is `{ reason?: string | null }`. There is **no `duration_days`** field
in the schema; suspend is indefinite-until-reactivate in the verified contract.

**POST `/ui/account/reactivate`** (op `account_reactivate_..._post`)
```json
// request  (AccountStatusReq; web calls with no body — body is optional in practice)
{}
// 200  (AccountState)
{ "status": "active" }
```
Note: OpenAPI marks `requestBody.required: true`, but the web client (`reactivateAccount()`)
calls it with no body and the request-body schema has no required properties, so an empty
or omitted body is accepted in practice.

**Error mapping.** FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is decoded by
`ApiErrorMapper` (AND-015), mirroring the web `normalizeErrorDetail` in
`src/api/client.ts` (string → as-is; array of `{msg}` → joined; object with `code` →
mapped/`msg`). The **only** documented non-2xx for these endpoints is `422
HTTPValidationError`. The previously-listed `409 closure_already_pending`, `409
already_suspended`, and `403 reactivation_window_expired` codes are **not present in the
OpenAPI** and are treated as unverified assumptions (see §16); handle them defensively if
the backend emits them, but do not depend on them. `401` is handled by the AND-013
authenticator (one `POST /ui/session/refresh` + single retry, matching `src/api/client.ts`),
then bubbled as Failed if still unauthorized. A transport/offline failure surfaces as
`ApiError(0, ...)` equivalent (network error).

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
- **Closure requires re-authentication**: `closure/start` returns
  `auth_required: true` with a `challenge_id`; the password (or other factor) is sent
  only to the challenge verify endpoint and is never logged or persisted. The verified
  `challenge_id` is then posted to `closure/finalize`. Use `androidx.compose` password
  masking and never echo the secret into `SavedStateHandle`. (CORRECTED: re-auth is
  triggered at start, not finalize.)
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
  `closure_start_requested`, `closure_start_succeeded` (no `grace_period_days` in the
  verified response — omit it),
  `closure_finalize_confirmed`, `closure_finalize_succeeded`,
  `closure_reauth_required`, `suspend_requested`,
  `suspend_succeeded`, `reactivate_requested`, `reactivate_succeeded`, plus
  `*_failed{error_code}` for each.
- Logging via the app logger; **never** log password, cookies, CSRF token, `reason`
  text, or full `challenge_id` (log a truncated prefix only). HTTP body logging for
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

- **Q1 (re-auth shape):** RESOLVED (partially). `closure/start` returns
  `{auth_required, challenge_id, required_factors}` (web `startAccountClosure` return
  type); `closure/finalize` consumes `challenge_id` (`AccountClosureFinalizeReq`). The
  exact `required_factors` values and the verify endpoint are not documented in OpenAPI
  (response schema is empty `{}`) — reuse the existing challenge primitive and treat the
  factor list as backend-driven. (Note: re-auth is at START, not finalize.)
- **Q2 (reactivate scope):** Likely RESOLVED — the web client uses a single
  `reactivateAccount()` call disambiguated by current `status`, consistent with the spec.
  Not explicitly stated in OpenAPI; carry as a low-risk assumption.
- **Q3 (suspend duration):** RESOLVED — `AccountStatusReq` has only optional `reason`;
  there is **no** `duration_days`. Suspend is indefinite-until-reactivate. FR-4 updated.
- **Q4 (session validity after suspend):** UNVERIFIED — OpenAPI does not document
  session invalidation, and the **web client does NOT sign out** on suspend/closure (it
  only refreshes the status query). The Android forced-sign-out behavior is a deliberate
  product choice; confirm with backend whether the session is actually invalidated. If
  not, FR-4/FR-3 may need a "signed-in with banner" variant.
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
4. From `suspended` or `closure_pending`, **reactivate** returns the account to
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **Endpoints exist:** `GET /ui/account/status`, `POST /ui/account/closure/start`,
   `POST /ui/account/closure/finalize`, `POST /ui/account/suspend`,
   `POST /ui/account/reactivate`. **Verified.** Source: OpenAPI index lines for ops
   `account_status_..._get`, `account_closure_start_..._post`,
   `account_closure_finalize_..._post`, `account_suspend_..._post`,
   `account_reactivate_..._post`; mirrored in `src/api/endpoints/account.ts`
   (`getAccountStatus`, `startAccountClosure`, `finalizeAccountClosure`,
   `suspendAccount`, `reactivateAccount`).
2. **HTTP methods** (status=GET; other four=POST). **Verified.** Source: OpenAPI index
   methods; `src/api/endpoints/account.ts` (`api.get`/`api.post`).
3. **`closure/finalize` request field is `challenge_id` (required string)** — NOT
   `closure_id`. **Corrected.** Source: OpenAPI `components.schemas.AccountClosureFinalizeReq`
   (`required: ["challenge_id"]`); `src/api/types.ts: AccountClosureFinalizeReq`.
4. **`closure/start` takes NO request body** (earlier spec sent `{reason}`).
   **Corrected.** Source: OpenAPI `/ui/account/closure/start` has no `requestBody`;
   `src/api/endpoints/account.ts: startAccountClosure` is called with no args.
5. **`closure/start` returns the re-auth challenge `{auth_required, challenge_id,
   required_factors}`; re-auth originates at START, not finalize.** **Corrected.**
   Source: `src/api/endpoints/account.ts: startAccountClosure` return type; web flow in
   `src/pages/settings/Account.tsx` (start mutation → `setChallengeId(data.challenge_id)`
   → finalize step). NOTE: OpenAPI declares the 200 response schema as empty `{}`, so the
   field names come from the web client's declared return type, not OpenAPI.
6. **`suspend`/`reactivate` request body = `AccountStatusReq` = `{reason?}` only; no
   `duration_days`.** **Corrected.** Source: OpenAPI
   `components.schemas.AccountStatusReq` (single optional `reason`); `src/api/types.ts:
   AccountStatusReq`; `src/api/endpoints/account.ts` (`suspendAccount`/`reactivateAccount`
   take optional `AccountStatusReq`).
7. **Status response shape is `AccountState = {status, reason?, updated_at?,
   closed_at?}`; `status` values `active|suspended|closed|closure_pending`; timestamps
   are epoch SECONDS.** **Corrected** (spec had `state`, `suspended_until`, `closure{}`,
   `grace_period_days`, `effective_at`, ISO strings, value `pending_closure`). Source:
   `src/api/types.ts: AccountState`; `src/pages/settings/Account.tsx`
   (`statusQuery.data?.status`, `new Date(updated_at * 1000)`, status cases
   `suspended`/`closure_pending`/`closed`).
8. **`closure/finalize` returns `{status: string}`; `suspend`/`reactivate` return
   `AccountState`.** **Corrected** (spec invented `{state, closed_at}` and an
   `auth_required` finalize branch). Source: `src/api/endpoints/account.ts` return types.
   OpenAPI 200 schemas are empty `{}` for all five (`reference/openapi.pretty.json`
   lines 137603-137611, 137682-137690, 137771-137779, 137850-137858, 137939-137947).
9. **CSRF via `X-CSRF-Token` header sourced from `ui_csrf` cookie.** **Verified.**
   Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token",
   csrf)`). NOTE: the web applies CSRF to ALL requests (incl. GET), not only POSTs.
10. **401 handling = single `POST /ui/session/refresh` then one retry, else logout.**
    **Verified.** Source: `src/api/client.ts` (`refreshSession()` posts
    `/ui/session/refresh`; retries original once; `logout("session_expired")` on repeat
    401). Matches the AND-013 authenticator description.
11. **FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`).**
    **Verified.** Source: `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError`; OpenAPI `422` → `HTTPValidationError` on all five endpoints.
12. **Network/offline error surfaces as a transport error (status 0).** **Verified.**
    Source: `src/api/client.ts` catch block → `throw new ApiError(0, "Network error")`.
13. **Specific error codes `409 closure_already_pending`, `409 already_suspended`,
    `403 reactivation_window_expired`.** **Unverified-assumption.** Source: NOT present
    in OpenAPI (the five endpoints document only `200` and `422 HTTPValidationError`) and
    not referenced in the frontend. Handle defensively; do not depend on them.
14. **Typed `CLOSE` confirmation token.** **Unverified-assumption** (Android-only UX).
    Source: no backend field; the web `src/pages/settings/Account.tsx` instead surfaces a
    read-only Challenge ID input. Additive client guard, not a contract requirement.
15. **Forced sign-out / session teardown on suspend and closure.**
    **Unverified-assumption** (Android product choice). Source: web
    `src/pages/settings/Account.tsx` only calls
    `queryClient.invalidateQueries(["account-status"])` on success — it does NOT log the
    user out. OpenAPI does not document session invalidation. See Q4.
16. **`reactivate` accepts an empty/omitted body** despite OpenAPI `requestBody.required:
    true`. **Verified (in practice).** Source: `src/pages/settings/Account.tsx` calls
    `reactivateAccount()` with no body; `AccountStatusReq` has no required properties.
17. **Single reactivate endpoint disambiguated by current `status` (lifts suspension OR
    cancels pending closure).** **Unverified-assumption (low risk).** Source: web uses
    one `reactivateAccount()` call (`src/api/endpoints/account.ts`); not explicitly
    documented in OpenAPI. See Q2.
18. **Framework choices** (Compose Material 3 `AlertDialog`, `Modifier.semantics`,
    `stateDescription`, plurals, 48dp targets, DataStore). **Framework ref** —
    https://developer.android.com/jetpack/compose/accessibility ,
    https://m3.material.io/components/dialogs/overview ,
    https://developer.android.com/topic/libraries/architecture/datastore . Not
    verifiable against backend/frontend; standard Android guidance.

### Corrections made

- §5 API Contract rewritten to the verified shapes: `closure/finalize` uses
  `challenge_id` (not `closure_id`); `closure/start` has no body and returns the re-auth
  challenge; `suspend`/`reactivate` use `AccountStatusReq {reason?}` (removed
  `duration_days`); status response is `AccountState {status, reason?, updated_at?,
  closed_at?}` with epoch-seconds timestamps and value `closure_pending` (not
  `pending_closure`); finalize returns `{status}`. Removed the fabricated `409`/`403`
  codes from "notable codes" and flagged them as unverified.
- §3 FR-1..FR-5 updated: `status` key/value names, no-body start, `challenge_id`
  finalize, no `duration_days`, reactivate optional body, re-auth at start.
- §4 state/repository/ViewModel signatures corrected: `AccountState.CLOSURE_PENDING`,
  `AccountStatus` fields aligned to wire, `ClosureStartResult` now
  `{authRequired, challengeId, requiredFactors}`, `finalizeClosure(challengeId)`,
  `suspend(reason)`, re-auth state-machine note.
- §8/§10 corrected: re-auth at start; telemetry dropped `duration_days`/`grace_period_days`;
  log redaction references `challenge_id` not `closure_id`.
- §13 Q1–Q4 updated with resolutions/verdicts.
- §14 AC-4 value `pending_closure` → `closure_pending`.

### Open assumptions

- **No grace-period / effective-at / suspended-until data** is returned by the verified
  `AccountState`, so any countdown or "undo window" UI is not derivable from the
  contract. Why unverifiable: OpenAPI 200 schema is empty `{}` and `types.ts:
  AccountState` omits these fields. Mitigation: show generic notices; gate richer UI on
  backend adding the fields.
- **Forced sign-out on suspend/closure** (Q4): web does not sign out; backend session
  invalidation undocumented. Why unverifiable: no OpenAPI/auth doc and contradicting web
  behavior. Mitigation: confirm with backend; keep a "signed-in with banner" fallback.
- **Specific 409/403 business-error codes** (item 13): not in OpenAPI/frontend. Why
  unverifiable: undocumented. Mitigation: defensive handling only.
- **Re-auth `required_factors` values and the verify endpoint**: `closure/start` returns
  the list but values/verify route are undocumented (200 schema empty). Mitigation:
  reuse existing challenge primitive; treat factors as backend-driven.
- **Typed `CLOSE` token** (item 14): Android-only; no backend basis.

## 17. Test Plan

Acceptance Criteria are referenced as AC-1..AC-9 (numbered list in §14). Test targets:
**JVM** (local JVM/Robolectric, no device), **emu35** (headless AVD `test35`, API 35
x86_64), **A15** (physical Samsung Galaxy A15 5G, SM-A156U, API 34 arm64, serial
R5CX821TA9R).

- **TC-AND-387-01 — Status read happy path & action gating.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer returns `200 {"status":"active","updated_at":1749081600}`.
  Steps: call `repo.status()`; observe ViewModel `load()`.
  Expected: maps to `AccountStatus(state=ACTIVE, updatedAt=epoch-sec)`; UI exposes
  Suspend + Close; GET issued with no body; request retried per AND-016 on transient 5xx.
  Traces: AC-5.

- **TC-AND-387-02 — Suspend happy path.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: queue `200 {"status":"suspended","reason":"taking a break"}` for
  `POST /ui/account/suspend`.
  Steps: `requestSuspend("taking a break")` → `confirmSuspend()`.
  Expected: request body is exactly `{"reason":"taking a break"}` (no `duration_days`);
  `X-CSRF-Token` header present; request sent exactly once (no retry); on success
  `SessionTeardown.clear()` invoked and outcome `SUSPENDED_SIGNED_OUT`.
  Traces: AC-1, AC-6.

- **TC-AND-387-03 — Closure start returns re-auth challenge.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: queue `200 {"auth_required":true,"challenge_id":"ch_re_19",
  "required_factors":["password"]}` for `POST /ui/account/closure/start`.
  Steps: `requestClosure()`.
  Expected: start request has NO body; result parsed to
  `ClosureStartResult(authRequired=true, challengeId="ch_re_19", requiredFactors=["password"])`;
  ViewModel transitions to `ReAuthRequired("ch_re_19")`.
  Traces: AC-2.

- **TC-AND-387-04 — Closure finalize happy path (challenge_id, teardown).**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: prior start yielded `ch_re_19`; queue `200 {"status":"closed"}` for
  `POST /ui/account/closure/finalize`.
  Steps: satisfy re-auth, type `CLOSE`, `confirmClosureFinalize()`.
  Expected: finalize body is exactly `{"challenge_id":"ch_re_19"}` (NOT `closure_id`);
  `X-CSRF-Token` present; sent once; on success `SessionTeardown.clear()` invoked, cookie
  jar empty, outcome `CLOSED_SIGNED_OUT`.
  Traces: AC-2, AC-6.

- **TC-AND-387-05 — Reactivate happy path (empty body).**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: status `suspended`; queue `200 {"status":"active"}` for
  `POST /ui/account/reactivate`.
  Steps: `reactivate()`.
  Expected: request sent with empty/omitted body and `X-CSRF-Token`; `getMe` re-fetched;
  status reflects `active`; nav returns to account settings.
  Traces: AC-4.

- **TC-AND-387-06 — 422 validation error mapping.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: queue `422 {"detail":[{"msg":"challenge_id is required"}]}` for finalize.
  Steps: `confirmClosureFinalize()`.
  Expected: `ApiErrorMapper` joins `{msg}` list → `ActionState.Failed("challenge_id is
  required")`; prior `Ready.status` retained; NO teardown; NO sign-out.
  Traces: AC-2.

- **TC-AND-387-07 — `detail` string and object/code mapping.**
  Type: unit (JVM). Target: JVM.
  Preconditions: feed `detail` as (a) plain string, (b) `{"code":"role_required",...}`.
  Steps: invoke `ApiErrorMapper`.
  Expected: (a) string surfaced as-is; (b) object with `code` mapped to a human message
  (mirrors `normalizeErrorDetail`/`mapAuthorizationError`). No crash on unknown shapes.
  Traces: AC-8.

- **TC-AND-387-08 — Undocumented 409 already-in-state is handled defensively.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: queue `409 {"detail":{"code":"already_suspended"}}` for suspend (note:
  not in OpenAPI — defensive path only).
  Steps: `confirmSuspend()`.
  Expected: instead of a hard crash/error, ViewModel calls `load()` to reconcile and
  routes to the matching state screen; no teardown if action did not succeed.
  Traces: AC-8.

- **TC-AND-387-09 — Mutations are never auto-retried; in-flight disables confirm.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer records request count; slow response to observe
  `Submitting`.
  Steps: trigger each of suspend/finalize/reactivate.
  Expected: exactly ONE request per action (no retry); during `Submitting` the confirm
  button is disabled; status GET (separate) may retry per AND-016.
  Traces: AC-6.

- **TC-AND-387-10 — Offline/flaky-dev-host status read.**
  Type: integration (Robolectric/JVM); confirm on device for real radio. Target: JVM,
  then A15.
  Preconditions: status endpoint times out / connection refused (simulate dev host
  18.222.237.167 down).
  Steps: enter a flow screen; `load()`.
  Expected: `AccountLifecycleUiState.Offline` with Retry; NO destructive actions enabled;
  no crash. On A15: toggle airplane mode to confirm real transport-error path and Retry
  recovery once network returns.
  Traces: AC-7.

- **TC-AND-387-11 — Ambiguous mutation timeout reconciliation.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: finalize submitted; server never responds (socket timeout).
  Steps: `confirmClosureFinalize()` then timeout.
  Expected: no auto-retry; message "We could not confirm the action — check your account
  status"; `load()` re-fetches to reconcile real state.
  Traces: AC-6, AC-7.

- **TC-AND-387-12 — Compose UI: typed-token gate + terminal screens + a11y.**
  Type: Compose-UI / instrumented. Target: emu35.
  Preconditions: closure finalize step rendered with a valid `challenge_id`.
  Steps: type `clo`, then `CLOSE`; inspect confirm button; render `closed` and
  `suspended` terminal screens; render offline state.
  Expected: finalize confirm disabled until typed token is exactly `CLOSE`
  (case-sensitive); `closed`/`suspended` screens expose no destructive actions; offline
  shows Retry. Accessibility: gated confirm button has `stateDescription` reflecting
  enabled/disabled and the typed field announces "Type CLOSE to confirm"; 48dp targets;
  destructive control not color-only (warning icon + text).
  Traces: AC-3, AC-5, AC-7.

- **TC-AND-387-13 — CSRF header + redaction security check.**
  Type: contract/MockWebServer + unit (JVM). Target: JVM.
  Preconditions: `ui_csrf` cookie present in jar; logging interceptor enabled.
  Steps: issue all four mutations; capture recorded requests and emitted logs/telemetry.
  Expected: every POST carries `X-CSRF-Token` (value = `ui_csrf` cookie); logs/telemetry
  contain NO password, cookie, CSRF token, `reason` text, or full `challenge_id` (only a
  truncated prefix). After teardown, no residual `ui_csrf`/session cookie in the jar.
  Traces: AC-6, AC-9.

- **TC-AND-387-14 — End-to-end closure with real re-auth on device.**
  Type: instrumented/e2e. Target: A15 (physical device — re-auth may invoke biometrics /
  Credential Manager and exercises the real cookie jar/teardown on arm64/API-34).
  Preconditions: signed-in test account on dev host; account `active`.
  Steps: Begin closure → start returns challenge → complete re-auth (password/biometric)
  → type `CLOSE` → finalize.
  Expected: on `{status:"closed"}` the app tears down session, lands on `auth/login` with
  empty cookie jar; re-entry shows unauthenticated state. MUST run on A15 because re-auth
  via biometrics/Credential Manager is hardware-dependent.
  Traces: AC-2, AC-6, AC-9.

- **TC-AND-387-15 — Process-death survival of confirm/typed-token state.**
  Type: instrumented (JVM/Robolectric ok; confirm on emu35). Target: emu35.
  Preconditions: closure finalize dialog open, partial typed token.
  Steps: trigger config change / process recreation.
  Expected: `Confirm*` and typed-token restored from `SavedStateHandle`; `Submitting` NOT
  persisted (on recreate, `load()` reconciles rather than re-submitting); the re-auth
  password is never written to `SavedStateHandle`.
  Traces: AC-2, AC-9.

### Coverage matrix

| AC | Description | Covered by |
|----|-------------|------------|
| AC-1 | Suspend → signed out to suspended screen | TC-02, TC-14 (sign-out path) |
| AC-2 | Closure only after start + `CLOSE` + re-auth; full teardown | TC-03, TC-04, TC-06, TC-14, TC-15 |
| AC-3 | Finalize confirm disabled until typed `CLOSE` | TC-12 |
| AC-4 | Reactivate from suspended/closure_pending → active | TC-05 |
| AC-5 | Status drives actions; closed = terminal no-actions | TC-01, TC-12 |
| AC-6 | All mutations: CSRF, sent once, confirm disabled in-flight | TC-02, TC-04, TC-09, TC-11, TC-13, TC-14 |
| AC-7 | Status-read failure → offline/error + Retry, no destructive enable | TC-10, TC-11, TC-12 |
| AC-8 | 409 already-in-state reconciles to matching screen | TC-07, TC-08 |
| AC-9 | No password/cookie/CSRF/`reason` in logs/telemetry | TC-13, TC-14, TC-15 |
