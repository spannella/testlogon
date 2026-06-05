---
id: AND-038
title: Finalize + multi-factor sequencing
milestone: M1
epic: E05
priority: P0
size: M
status: draft
depends_on: [AND-034, AND-035, AND-036]
blocks: [AND-039]
---

# AND-038 — Finalize + multi-factor sequencing

## 1. Overview & Goal

This ticket implements the **orchestration layer** that drives a TestLogon login
challenge to completion across one *or more* MFA factors and then calls
`POST /ui/session/finalize` to mint an authenticated cookie session. The
individual per-factor verify calls (TOTP — AND-034, SMS — AND-035, Email —
AND-036, Recovery — AND-037) already exist as repository methods. What is
missing, and what this ticket delivers, is the **state machine** that:

1. Reads `required_factors` / `remaining_factors` from each challenge response.
2. Selects the next factor to satisfy and routes the user (or the test harness)
   to it.
3. Detects the terminal condition (`remaining_factors` empty) and invokes
   `finalize`, optionally carrying a `remember_device` flag.
4. Confirms the session by reading `GET /ui/me` and emitting an authenticated
   `UiState`.

The deliverable is a `MfaSequencer` (domain orchestrator) plus a
`FinalizeUseCase`, both exercised by single-factor and multi-factor integration
tests against the dev backend / MockWebServer. This is a logic/orchestration
ticket: there is no new screen here (the screen is AND-039), but the orchestrator
exposes a `StateFlow<MfaFlowState>` that AND-039 binds to directly.

**Done = a `username/password` login that requires `[totp]`, and one that
requires `[totp, sms]`, both reach `GET /ui/me` returning 200 with a populated
user, driven entirely by the sequencer.**

## 2. Context & References

- Module: `feature-auth` (orchestrator + use case), depending on `core-data`
  (repository), `core-network`, `core-model`. Package root
  `com.testlogon.android.feature.auth.mfa`.
- Auth flow (project-authoritative):
  `POST /ui/session/start` → `{auth_required, challenge_id, required_factors[]}`
  → per-factor `begin`/`verify` → `POST /ui/session/finalize` → `GET /ui/me`.
- Session rides on cookies + `ui_csrf` cookie echoed as `X-CSRF-Token`. A
  persistent cookie jar (AND-027) is required; `finalize` must run on the same
  OkHttp client so the challenge cookies are present.
- Upstream tickets supplying the verify primitives this ticket sequences:
  - **AND-033** — `AuthApi` MFA endpoints + DTOs.
  - **AND-034** — `verifyTotp(challengeId, code) → MfaVerifyResp`.
  - **AND-035** — `beginSms`/`verifySms` (+ resend).
  - **AND-036** — `beginEmail`/`verifyEmail` (+ resend).
  - **AND-037** — `useRecoveryCode(factor, code)` (P1; sequencer must tolerate
    its absence behind a feature check but treat `recovery` as a valid factor id).
- Downstream consumer: **AND-039** (MFA screen UI) renders from this
  orchestrator's `StateFlow`.
- Web reference: `frontend/src/api/endpoints/session.ts` and `mfa.ts`;
  shared types in `frontend/src/api/types.ts`. OpenAPI at `/openapi.json`.

## 3. Functional Requirements

FR-1 **Challenge ingestion.** Given a `StartSessionResp` with `auth_required ==
true`, the sequencer initializes its working set from `required_factors`
(ordered) and `challenge_id`.

FR-2 **Next-factor selection.** At each step the sequencer computes the *active
factor* = first entry of `remaining_factors` that the client can satisfy. The
authoritative remaining set always comes from the **latest server response**
(`MfaVerifyResp.remaining_factors`), never a client-side counter.

FR-3 **Begin dispatch.** For factors that require a server-issued challenge
(`sms`, `email`), the sequencer calls the corresponding `begin*` before
accepting a code, surfacing `sent_to` for display. `totp` and `recovery` need no
begin step.

FR-4 **Verify dispatch.** Submitting a code routes to the active factor's verify
method. On success the response's `remaining_factors` replaces the working set.

FR-5 **Multi-factor sequencing.** When `remaining_factors` is non-empty after a
successful verify, the sequencer advances to the next factor (emitting
`AwaitingFactor`) and does **not** finalize.

FR-6 **Finalize trigger.** When `remaining_factors` is empty, the sequencer
calls `finalize(rememberDevice)` exactly once, then `GET /ui/me`, then emits
`Authenticated(user)`.

FR-7 **`remember_device`.** A boolean carried from UI (default `false`) is sent
in the finalize body; it is read once at finalize time, not per factor.

FR-8 **Switch factor.** The UI may request switching to another factor present
in `remaining_factors` (e.g. user can't get SMS, uses recovery). The sequencer
re-points the active factor and runs `begin*` if needed.

FR-9 **Idempotent re-finalize guard.** If `finalize` succeeds but `/ui/me`
fails transiently, retry `/ui/me` (idempotent GET) without re-calling finalize.

FR-10 **Cancellation.** The flow is scoped to `viewModelScope`; navigating away
cancels in-flight begin/verify/finalize coroutines cleanly.

## 4. Technical Design

### 4.1 State model (`core-model` / feature-local)

```kotlin
enum class MfaFactor(val wire: String) {
    TOTP("totp"), SMS("sms"), EMAIL("email"), RECOVERY("recovery");
    companion object { fun from(wire: String): MfaFactor? = entries.find { it.wire == wire } }
}

sealed interface MfaFlowState {
    data object Idle : MfaFlowState
    data class AwaitingFactor(
        val challengeId: String,
        val active: MfaFactor,
        val remaining: List<MfaFactor>,
        val sentTo: String? = null,      // populated after begin (sms/email)
        val submitting: Boolean = false,
        val resendCooldownSec: Int = 0,
        val error: AuthError? = null,
    ) : MfaFlowState
    data class Finalizing(val rememberDevice: Boolean) : MfaFlowState
    data class Authenticated(val user: MeResp) : MfaFlowState
    data class Failed(val error: AuthError) : MfaFlowState
}
```

### 4.2 Orchestrator

```kotlin
class MfaSequencer @Inject constructor(
    private val authRepository: AuthRepository,   // AND-033..037 methods
) {
    private val _state = MutableStateFlow<MfaFlowState>(MfaFlowState.Idle)
    val state: StateFlow<MfaFlowState> = _state.asStateFlow()

    private var rememberDevice: Boolean = false

    /** Seed from /ui/session/start (AND-031). */
    fun begin(start: StartSessionResp, rememberDevice: Boolean) { … }

    /** User submits a code for the active factor. */
    suspend fun submitCode(code: String)

    /** Switch active factor (must be in remaining). */
    suspend fun switchFactor(target: MfaFactor)

    /** Re-issue a begin challenge for sms/email. */
    suspend fun resend()

    private suspend fun advanceOrFinalize(remaining: List<MfaFactor>)
    private suspend fun finalizeAndLoadMe()
}
```

`advanceOrFinalize` is the heart of the machine:

```kotlin
private suspend fun advanceOrFinalize(remaining: List<MfaFactor>) {
    val cid = currentChallengeId
    if (remaining.isEmpty()) { finalizeAndLoadMe(); return }
    val next = remaining.first()
    val sentTo = when (next) {
        MfaFactor.SMS   -> authRepository.beginSms(cid).getOrNull()?.sentTo
        MfaFactor.EMAIL -> authRepository.beginEmail(cid).getOrNull()?.sentTo
        else            -> null
    }
    _state.value = MfaFlowState.AwaitingFactor(cid, next, remaining, sentTo)
}
```

```kotlin
private suspend fun finalizeAndLoadMe() {
    _state.value = MfaFlowState.Finalizing(rememberDevice)
    when (val fin = authRepository.finalizeSession(rememberDevice)) {
        is ApiResult.Success -> loadMeWithRetry()
        is ApiResult.Failure -> _state.value = MfaFlowState.Failed(fin.error)
    }
}
```

`loadMeWithRetry` applies bounded backoff (idempotent GET) per the project
resilience rules; finalize itself is **not** retried (mutation).

### 4.3 ViewModel surface (for AND-039)

```kotlin
@HiltViewModel
class MfaViewModel @Inject constructor(
    private val sequencer: MfaSequencer,
) : ViewModel() {
    val uiState: StateFlow<MfaFlowState> = sequencer.state
    fun onCodeSubmit(code: String) = viewModelScope.launch { sequencer.submitCode(code) }
    fun onResend() = viewModelScope.launch { sequencer.resend() }
    fun onSwitchFactor(f: MfaFactor) = viewModelScope.launch { sequencer.switchFactor(f) }
}
```

### 4.4 Repository contract consumed (already defined upstream)

```kotlin
interface AuthRepository {
    suspend fun verifyTotp(challengeId: String, code: String): ApiResult<MfaVerifyResp>      // AND-034
    suspend fun beginSms(challengeId: String): ApiResult<MfaBeginResp>                        // AND-035
    suspend fun verifySms(challengeId: String, code: String): ApiResult<MfaVerifyResp>        // AND-035
    suspend fun beginEmail(challengeId: String): ApiResult<MfaBeginResp>                      // AND-036
    suspend fun verifyEmail(challengeId: String, code: String): ApiResult<MfaVerifyResp>      // AND-036
    suspend fun useRecoveryCode(factor: String, code: String): ApiResult<MfaVerifyResp>       // AND-037
    suspend fun finalizeSession(rememberDevice: Boolean): ApiResult<FinalizeResp>             // THIS ticket
    suspend fun me(): ApiResult<MeResp>
}
```

The only new repository method introduced here is `finalizeSession`; everything
else is reused. `submitCode` selects the verify call by `active` factor.

## 5. API Contract

This ticket *owns* the finalize call and *sequences* the verify calls.

### 5.1 `POST /ui/session/finalize`

Headers: cookies (session + challenge) + `X-CSRF-Token: <ui_csrf cookie value>`.

Request:
```json
{ "challenge_id": "chl_8f3a…", "remember_device": false }
```
Response 200:
```json
{ "ok": true, "session": { "id": "sess_…", "expires_at": "2026-06-12T18:04:00Z" } }
```
DTO:
```kotlin
@JsonClass(generateAdapter = true)
data class FinalizeReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "remember_device") val rememberDevice: Boolean = false,
)
@JsonClass(generateAdapter = true)
data class FinalizeResp(
    val ok: Boolean = true,
    val session: SessionInfo? = null,
)
```

### 5.2 Verify responses (consumed, from AND-033)

```json
{ "ok": true, "remaining_factors": ["sms"] }
```
```kotlin
@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val ok: Boolean,
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
)
@JsonClass(generateAdapter = true)
data class MfaBeginResp(@Json(name = "sent_to") val sentTo: String? = null)
```

### 5.3 `GET /ui/me`

Response 200 → `MeResp` (username, email, factors). Used only to confirm the
session is live; mapped to `Authenticated`.

### 5.4 Error envelope

FastAPI `detail` is mapped (per `core-network` `ErrorMapper`) from the three
shapes `string | [{msg}] | {code,…}` into `AuthError`. A finalize `409`
(`challenge_not_complete`) maps to `AuthError.ChallengeIncomplete` and forces
the sequencer back to `AwaitingFactor` using the server's `remaining_factors` if
present in `detail`.

## 6. Data & State Management

- **Single source of truth:** `remaining_factors` from the latest server
  response. No client-maintained count of completed factors.
- **`challenge_id`** is held in the sequencer for the life of the flow and
  passed to every verify/finalize call.
- **`remember_device`** is captured at `begin()` and stored in the sequencer
  (not persisted to DataStore here; device-remember token persistence, if any,
  is a cookie set by the server and handled by the persistent cookie jar from
  AND-027).
- **No Room/cache writes** in this ticket. Session identity is cookie-based;
  `GET /ui/me` result is held transiently in `Authenticated` and consumed by the
  app session holder (AND-032/owner of session state).
- **Ordering:** server order of `required_factors` is preserved; `switchFactor`
  is the only client-driven reordering and only within `remaining`.
- Configuration changes: state survives via `viewModelScope` + `StateFlow`
  retained by `MfaViewModel`.

## 7. Error Handling & Resilience

- **Timeouts:** ~20s per call (OkHttp config from `core-network`); dev host is
  unreliable.
- **Retries:** only idempotent GETs — i.e. `GET /ui/me` after finalize — get
  bounded backoff (max 3 attempts, 0.5s→2s). `finalize`, `verify*`, `begin*` are
  **not** auto-retried (state-mutating); user-initiated resend covers `begin*`.
- **401 during the flow:** the `core-network` authenticator performs the single
  `POST /ui/session/refresh` + retry. If refresh fails on finalize, emit
  `Failed(SessionExpired)` and require restart from `session/start`.
- **Wrong code:** verify returns 4xx with `detail` → stay in `AwaitingFactor`
  with `error` set and `remaining`/`active` unchanged so the user can re-enter.
- **`finalize` 409 (incomplete):** resync `remaining_factors` and return to
  `AwaitingFactor` rather than failing hard.
- **finalize succeeded but `/ui/me` failed:** retry `/ui/me` (FR-9); never
  re-call finalize.
- **Offline:** map IO failure to `AuthError.Network`; UI (AND-039) shows
  retry affordance that re-invokes the current step.
- **Cancellation:** structured concurrency in `viewModelScope`; partial
  in-flight begin does not corrupt state because state is only written on
  success.

## 8. Security & Privacy

- All calls go to the **plaintext HTTP dev host**; this is a known dev
  constraint. Production base URL must be HTTPS (cleartext disabled in release
  `network-security-config`). No mitigation owned here beyond using the shared
  client.
- **CSRF:** finalize is a mutating POST and must carry `X-CSRF-Token` echoing
  the `ui_csrf` cookie (interceptor from AND-027). The sequencer must not bypass
  the shared OkHttp client.
- **Code material:** OTP / recovery codes are passed to repository methods and
  never logged, never written to DataStore/Room, never placed in
  `MfaFlowState`. `submitting` is the only echo of an in-flight submit.
- **`remember_device`** results in a server-set persistent cookie; treat that
  cookie like a credential — stored only in the persistent cookie jar
  (EncryptedSharedPreferences-backed per AND-027), never surfaced to logs.
- Recovery-code success should not reveal how many codes remain in any
  user-visible string sourced from this layer.

## 9. Accessibility & i18n

- This ticket has **no UI of its own** (owned by AND-039). It must, however,
  emit user-facing error/status content as *string resource keys / typed
  `AuthError`*, never hardcoded English, so AND-039 can localize.
- `sent_to` from begin responses is server-provided (masked phone/email) and is
  passed through verbatim for the screen to announce; the sequencer does not
  format it.
- Factor names exposed to UI use the `MfaFactor` enum (stable ids), letting the
  screen map to localized labels and content descriptions.

## 10. Telemetry & Logging

- Structured events (no PII, no codes): `mfa_begin` `{factor}`,
  `mfa_verify_result` `{factor, ok, remaining_count}`, `mfa_switch_factor`
  `{from, to}`, `mfa_finalize_result` `{ok, remember_device}`,
  `mfa_session_confirmed` `{me_ok}`.
- Log challenge_id only as a hashed/truncated correlation id at DEBUG; never at
  INFO in release.
- Timing: record duration from `begin()` to `Authenticated` as
  `mfa_flow_duration_ms` to monitor the unreliable dev host.
- All logging via the project Timber tree; release tree strips DEBUG.

## 11. Testing Strategy

Primary deliverable (acceptance is "tested").

**Unit (sequencer, MockWebServer + fake `AuthRepository`):**
- `single_factor_totp_reaches_authenticated`: start `required=[totp]`, verify
  returns `remaining=[]`, finalize 200, `/ui/me` 200 → `Authenticated`.
- `multi_factor_totp_then_sms`: start `required=[totp,sms]`; totp verify →
  `remaining=[sms]` emits `AwaitingFactor(SMS)` and triggers `beginSms`; sms
  verify → `remaining=[]` → finalize → `Authenticated`. Assert finalize called
  **exactly once** and only after the last factor.
- `finalize_not_called_while_factors_remain`.
- `wrong_code_keeps_awaiting_factor` (verify 401, state unchanged + error set).
- `switch_factor_runs_begin_for_email`.
- `remember_device_true_sets_request_flag` (capture `FinalizeReq`).
- `finalize_409_resyncs_remaining`.
- `me_retry_after_transient_500_no_second_finalize` (verify finalize call count
  == 1, `/ui/me` attempted twice).
- `factor_order_preserved`.

**Integration (against dev host, opt-in / CI-tagged):**
- Drive `session/start` (real test creds) through a TOTP-only account to
  `/ui/me` 200.

Coverage gate: sequencer branch coverage ≥ 85%. Tests use Turbine to assert the
`StateFlow` emission sequence. No instrumented UI tests here (those are AND-039).

## 12. Dependencies & Sequencing

- **Depends on:** AND-034 (TOTP verify), AND-035 (SMS begin/verify), AND-036
  (Email begin/verify) — these supply the verify primitives the sequencer
  orchestrates. Transitively requires AND-033 (MFA API/DTOs), AND-027 (cookie
  jar + CSRF interceptor), AND-031 (`session/start`).
- **Soft dependency:** AND-037 (recovery) is P1; the sequencer treats
  `recovery` as a valid factor and calls `useRecoveryCode` when present. If
  AND-037 lands later, `switchFactor(RECOVERY)`/recovery verify can be guarded
  behind a capability check, but `MfaFactor.RECOVERY` must already exist.
- **Blocks:** AND-039 (MFA screen UI) — it binds to `MfaViewModel.uiState` and
  calls `onCodeSubmit`/`onResend`/`onSwitchFactor`.
- Adds `finalizeSession` to `AuthRepository` + its `AuthApi.finalize` Retrofit
  method and `FinalizeReq/Resp` DTOs.

## 13. Risks & Open Questions

- **R1:** Does the server include `remaining_factors` in finalize 409 detail? If
  not, the sequencer cannot resync and must restart from `session/start`.
  *Action:* confirm via `/openapi.json` / web reference before implementation.
- **R2:** Is `begin` required again after `switchFactor` back to a previously
  begun factor (does the prior challenge still exist)? Assume yes (re-begin) for
  safety; verify against backend.
- **R3:** `remember_device` cookie semantics (TTL, name) are server-defined;
  this ticket only sends the flag. Persistence correctness depends on AND-027's
  jar honoring `Set-Cookie` `Max-Age`.
- **R4:** Ordering of `required_factors` — is it server-prioritized or
  arbitrary? We preserve server order; if the product wants TOTP-first
  regardless, that becomes a `switchFactor` default in AND-039, not here.
- **R5:** Dev host flakiness may make integration tests non-deterministic; keep
  them CI-tagged/opt-in, rely on MockWebServer for the gate.

## 14. Acceptance Criteria

AC-1 A challenge with `required_factors=[totp]` reaches `Authenticated` with
`/ui/me` 200 (covered by `single_factor_totp_reaches_authenticated`).

AC-2 A challenge with `required_factors=[totp, sms]` completes both factors *in
sequence* and reaches `Authenticated`; `beginSms` fires only after totp passes
(covered by `multi_factor_totp_then_sms`).

AC-3 `finalize` is invoked exactly once, only when `remaining_factors` is empty,
and never while factors remain (covered by
`finalize_not_called_while_factors_remain` + call-count assertions).

AC-4 `remember_device` is transmitted in the finalize body when set true
(captured request assertion).

AC-5 An incorrect code leaves the user on the active factor with an error and
does not advance or finalize.

AC-6 After finalize succeeds, a transient `/ui/me` failure is retried without a
second finalize call.

AC-7 The orchestrator exposes a `StateFlow<MfaFlowState>` whose emission order
for the multi-factor path is
`AwaitingFactor(TOTP) → AwaitingFactor(SMS) → Finalizing → Authenticated`
(Turbine-asserted).

## 15. Definition of Done

- `MfaSequencer`, `MfaViewModel`, `FinalizeUseCase` (if extracted),
  `FinalizeReq/Resp` DTOs, and `AuthRepository.finalizeSession` implemented in
  `feature-auth` under `com.testlogon.android.feature.auth.mfa`.
- All Section 11 unit tests pass; sequencer branch coverage ≥ 85%.
- Single- and multi-factor sequences verified green (MockWebServer gate +
  at least one opt-in dev-host integration run).
- No OTP/recovery codes appear in logs or state (verified by a logging test /
  review checklist).
- Finalize carries `X-CSRF-Token` and runs on the shared OkHttp client
  (verified via captured request headers).
- `ktlint`/`detekt` clean; Hilt graph compiles (KSP); `MfaViewModel` injectable.
- AND-039 can bind to `uiState` without further sequencer changes (API reviewed
  and signed off by the AND-039 owner).
- Merged to `android-port` with CI green.
