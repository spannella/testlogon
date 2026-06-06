---
id: AND-038
title: Finalize + multi-factor sequencing
milestone: M1
epic: E05
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  - **AND-037** — `useRecoveryCode(factor, code)` → `POST /ui/mfa/recovery/{factor}`
    with body `RecoveryReq {challenge_id, recovery_code, factor?}` (P1; sequencer
    must tolerate its absence behind a feature check but treat `recovery` as a
    valid factor id). Note: the field is `recovery_code`, not `code`.
- Downstream consumer: **AND-039** (MFA screen UI) renders from this
  orchestrator's `StateFlow`.
- Web reference: all login-flow session + MFA verify calls live in
  `frontend/src/api/endpoints/auth.ts` (there is no separate `session.ts`/`mfa.ts`);
  the sequencing/finalize logic the web client uses is in
  `frontend/src/pages/Login.tsx`; shared types in `frontend/src/api/types.ts`.
  OpenAPI at `/openapi.json`. (Corrected during review — see §16.)

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
        val sentTo: List<String> = emptyList(), // masked targets from begin (sms/email); server returns an array
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
    val sentTo: List<String> = when (next) {
        MfaFactor.SMS   -> authRepository.beginSms(cid).getOrNull()?.sentTo.orEmpty()
        MfaFactor.EMAIL -> authRepository.beginEmail(cid).getOrNull()?.sentTo.orEmpty()
        else            -> emptyList()
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

Request (OpenAPI `UiSessionFinalizeReq`; `remember_device` defaults `false`,
only `challenge_id` is required):
```json
{ "challenge_id": "chl_8f3a…", "remember_device": false }
```
Response 200 — **CORRECTED**. The OpenAPI response schema for this route is
untyped (`resp=200:` with no schema), but the web client (`auth.ts:
sessionFinalize → SessionFinalizeResp`, `types.ts: SessionFinalizeResp`) reads:
```json
{ "status": "ok", "session_id": "sess_…", "required_factors": [], "passed": { "totp": true } }
```
There is **no** `ok` boolean and **no** nested `session.id`/`expires_at` object
(those were fabricated in the original draft). Success is signaled by
`status == "ok"` **and** a non-null `session_id`. If finalize is called while
factors remain, the server responds `status: "pending"` with a populated
`required_factors` (this — not a 409 — is how the web client resyncs; see §5.4).
DTO:
```kotlin
@JsonClass(generateAdapter = true)
data class FinalizeReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "remember_device") val rememberDevice: Boolean = false,
)
@JsonClass(generateAdapter = true)
data class FinalizeResp(
    val status: String,                                            // "ok" | "pending"
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
)
```

### 5.2 Verify + begin responses (consumed, from AND-033) — **CORRECTED**

Verify request field names differ per factor (verified against OpenAPI schemas
and `types.ts`):
- TOTP `POST /ui/mfa/totp/verify` body `TotpVerifyReq {challenge_id, totp_code}`
  — the field is `totp_code`, **not** `code`.
- SMS `POST /ui/mfa/sms/verify` body `SmsVerifyReq {challenge_id, code}`.
- Email `POST /ui/mfa/email/verify` body `EmailVerifyReq {challenge_id, code}`.

All three verify routes return `MfaVerifyResp` (web ref `auth.ts`,
`types.ts: MfaVerifyResp`). The real shape has **no `ok` field**:
```json
{ "status": "ok", "session_id": null, "required_factors": ["sms"], "passed": { "totp": true }, "remaining_factors": ["sms"] }
```
```kotlin
@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
)
```
Begin responses (`POST /ui/mfa/sms/begin` / `email/begin`, bodies
`SmsBeginReq`/`EmailBeginReq` = `{challenge_id}`) return `ChallengeResp`
(web ref `auth.ts: beginSms/beginEmail → ChallengeResp`). **`sent_to` is a
string ARRAY**, not a single string, and `challenge_id` is also returned:
```kotlin
@JsonClass(generateAdapter = true)
data class MfaBeginResp(                                   // == web ChallengeResp
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: List<String> = emptyList(),
)
```
Because `sent_to` is a list, `AwaitingFactor.sentTo` (§4.1) should be
`List<String>` (or the sequencer joins/picks the first masked target); the
original `String?` is a shape error.

### 5.3 `GET /ui/me`

Response 200 → `MeResp`. **CORRECTED**: the real shape (web ref `types.ts:
MeResp`) is `{user_sub, session_id, ip}` — there is **no** `username`, `email`,
or `factors` field. Used only to confirm the session is live; mapped to
`Authenticated`. The web client calls `login(me.user_sub, "")` after a
successful `/ui/me` (`Login.tsx`), i.e. it keys identity off `user_sub`.
```kotlin
@JsonClass(generateAdapter = true)
data class MeResp(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "session_id") val sessionId: String,
    val ip: String,
)
```

### 5.4 Error envelope

FastAPI `detail` is mapped (per `core-network` `ErrorMapper`) from the three
shapes `string | [{msg,…}] | {code,…}` into `AuthError`. This is **verified**
against the web client's `normalizeErrorDetail` (`client.ts`), which handles a
string detail, an array of `{msg}`/string items (FastAPI 422
`HTTPValidationError`), and an object with a `code` field. All MFA/session routes
declare `422:HTTPValidationError` in OpenAPI for bad input.

**CORRECTED — finalize-incomplete handling.** The original draft's "finalize
`409 challenge_not_complete` → `AuthError.ChallengeIncomplete`" is an *unverified
assumption*: no such status/code appears in the OpenAPI spec or the web client.
The contract actually observed in `Login.tsx` is that calling `finalize` while
factors remain returns **HTTP 200** with `status: "pending"` and a populated
`required_factors`/`passed`. The sequencer must therefore treat
`FinalizeResp.status != "ok"` (or null `session_id`) as "more factors required",
resync its working set from `FinalizeResp.required_factors`, and return to
`AwaitingFactor` — not branch on a 409. (In practice FR-6 already only finalizes
when `remaining_factors` is empty, so this is a defensive resync path.)

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
- **`finalize` returns `status:"pending"` (incomplete):** this arrives as HTTP
  **200**, not a 409 (corrected — see §5.4). Resync from
  `FinalizeResp.required_factors` and return to `AwaitingFactor` rather than
  failing hard.
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
- `finalize_pending_resyncs_remaining` (finalize 200 + `status:"pending"` +
  non-empty `required_factors` → back to `AwaitingFactor`; renamed from
  `finalize_409_resyncs_remaining` — the server uses `status:"pending"`, not 409).
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

- **R1 (RESOLVED during review):** There is no finalize 409. Calling finalize
  early returns HTTP 200 with `status:"pending"` and `required_factors`, so the
  sequencer can always resync without restarting `session/start`. Confirmed via
  web reference `Login.tsx` + `types.ts: SessionFinalizeResp`. (OpenAPI leaves
  the 200 body untyped, so the field-level shape is sourced from the web client.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI full spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`), or frontend
(`reference/src/...`). "framework ref" = external Android docs.

1. **`POST /ui/session/finalize` is the finalize endpoint.** Verified.
   OpenAPI `POST /ui/session/finalize` (op=`ui_session_finalize_...`, req=`UiSessionFinalizeReq`);
   frontend `src/api/endpoints/auth.ts: sessionFinalize`.
2. **Finalize request body = `{challenge_id (required), remember_device (default false)}`.**
   Verified. Schema `UiSessionFinalizeReq` (only `challenge_id` required,
   `remember_device` default `false`); `src/api/types.ts: SessionFinalizeReq`.
3. **Finalize 200 response shape.** Corrected. Draft claimed
   `{ok, session:{id, expires_at}}`. Actual: `{status: "ok"|"pending", session_id?,
   required_factors[], passed: map}`. Source: `src/api/types.ts: SessionFinalizeResp`
   + `src/pages/Login.tsx` (reads `finalResp.status === "ok" && finalResp.session_id`).
   OpenAPI leaves the 200 body untyped (`resp=200:` only), so the field shape is
   sourced from the frontend.
4. **Success criterion for finalize = `status=="ok"` AND non-null `session_id`.**
   Verified. `src/pages/Login.tsx` line ~229.
5. **Finalize-while-incomplete returns HTTP 200 `status:"pending"` + `required_factors`
   (NOT a 409 `challenge_not_complete`).** Corrected. The 409/code path was a draft
   assumption with no source. Actual: `src/pages/Login.tsx` (`else if
   finalResp.required_factors.length > 0`) + `SessionFinalizeResp`.
6. **`GET /ui/me` confirms the session.** Verified. OpenAPI `GET /ui/me`
   (op=`ui_me_ui_me_get`); `src/api/endpoints/auth.ts: getMe`.
7. **`MeResp` shape.** Corrected. Draft claimed `(username, email, factors)`.
   Actual: `{user_sub, session_id, ip}`. Source: `src/api/types.ts: MeResp`;
   `src/pages/Login.tsx` uses `me.user_sub`. (OpenAPI `/ui/me` 200 body untyped.)
8. **`POST /ui/session/start` → `{auth_required, challenge_id?, required_factors[], session_id?}`.**
   Verified, with a clarification: the start response carries `required_factors`
   only (no `remaining_factors`). Source: schema `UiSessionStartResp`
   (required: `auth_required`); `src/api/types.ts: SessionStartResp`.
9. **TOTP verify: `POST /ui/mfa/totp/verify`, body field `totp_code`.** Corrected
   (draft repository signature implied a generic `code`). Source: OpenAPI
   `POST /ui/mfa/totp/verify` req=`TotpVerifyReq`; schema `TotpVerifyReq`
   {`challenge_id`,`totp_code`}; `src/api/types.ts: TotpVerifyReq`;
   `src/pages/Login.tsx` (`verifyTotp({challenge_id, totp_code})`).
10. **SMS verify body field is `code`; Email verify body field is `code`.** Verified.
    Schemas `SmsVerifyReq`/`EmailVerifyReq` = {`challenge_id`,`code`};
    `src/api/types.ts`.
11. **SMS/Email begin: `POST /ui/mfa/sms/begin` & `/ui/mfa/email/begin`, body `{challenge_id}`.**
    Verified. OpenAPI `SmsBeginReq`/`EmailBeginReq` = {`challenge_id`};
    `src/api/endpoints/auth.ts: beginSms/beginEmail`.
12. **Begin response (`ChallengeResp`) `sent_to` is a string ARRAY (+ `challenge_id`).**
    Corrected. Draft modeled `sent_to: String?`. Source: `src/api/types.ts:
    ChallengeResp` (`sent_to?: string[]`) and `SmsDeviceBeginResp`/`EmailDeviceBeginResp`
    (`sent_to: string[]`); `src/api/endpoints/auth.ts` types begin calls as
    `ChallengeResp`.
13. **TOTP/recovery need no begin step.** Verified. No `totp/begin` route in
    OpenAPI index; `src/pages/Login.tsx` only calls `beginSms`/`beginEmail`.
14. **`MfaVerifyResp` shape (consumed).** Corrected. Draft claimed
    `{ok, remaining_factors}`. Actual: `{status, session_id?, required_factors[],
    passed: map, remaining_factors[]}` — no `ok`. Source: `src/api/types.ts:
    MfaVerifyResp`; `src/pages/Login.tsx` reads `resp.remaining_factors` /
    `resp.passed` / `resp.required_factors`.
15. **Multi-factor advance is driven by server `remaining_factors`.** Verified.
    `src/pages/Login.tsx` (`if (resp.remaining_factors.length === 0) finalize else
    setRequiredFactors(resp.required_factors)`).
16. **Recovery: `POST /ui/mfa/recovery/{factor}`, body `RecoveryReq{challenge_id,
    recovery_code, factor?(default "totp")}`.** Corrected (draft §2 located it in a
    nonexistent `mfa.ts` and implied a `code` field). Source: OpenAPI
    `POST /ui/mfa/recovery/{factor}` req=`RecoveryReq`; schema `RecoveryReq`;
    `src/api/endpoints/auth.ts: useRecoveryCode` (path `/ui/mfa/recovery/${factor}`).
    Note a sibling `POST /ui/recovery/{factor}` also exists; the login flow uses the
    `/ui/mfa/...` one.
17. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** Verified.
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
    Clarification: the web client sets it on *every* request that has the cookie,
    not only mutating ones.
18. **401 → single `POST /ui/session/refresh` then retry; on refresh failure, log
    out / session expired.** Verified. `src/api/client.ts` (`refreshSession()` posts
    `/ui/session/refresh`; on `!res.ok` → `logout("session_expired")`; 401 path
    refreshes once then retries). OpenAPI `POST /ui/session/refresh` exists
    (resp=200, untyped — frontend treats it as `StatusResp`).
19. **Error `detail` shapes `string | [{msg}] | {code,...}` mapped to `AuthError`.**
    Verified. `src/api/client.ts: normalizeErrorDetail` (handles string, array of
    string/`{msg}`, and object with `code`). All MFA/session routes declare
    `422:HTTPValidationError` (OpenAPI index).
20. **Finalize must run on the same client carrying challenge cookies + CSRF.**
    Verified (web parity). The web client uses one `fetch` wrapper with
    `credentials:"include"` for all calls (`src/api/client.ts`); the Android
    equivalent is the shared OkHttp client + persistent cookie jar (AND-027 —
    cross-ticket assumption, not independently verifiable here).
21. **Kotlin orchestration choices** (`StateFlow`, `viewModelScope` structured
    concurrency/cancellation, Turbine for emission-order assertions, MockWebServer
    for contract tests). Unverified-assumption at the source level (no Android code
    in the reference repo) but standard framework usage. framework ref:
    Kotlin coroutines `StateFlow` (https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/-state-flow/),
    Android `viewModelScope`
    (https://developer.android.com/topic/libraries/architecture/coroutines#viewmodelscope),
    MockWebServer (https://github.com/square/okhttp/tree/master/mockwebserver),
    Turbine (https://github.com/cashapp/turbine).

### Corrections made

- §2: web-reference pointer fixed — login session/MFA calls live in
  `src/api/endpoints/auth.ts` and the sequencing logic in `src/pages/Login.tsx`;
  there is no `session.ts`/`mfa.ts`. Recovery clarified as
  `POST /ui/mfa/recovery/{factor}` with `recovery_code`.
- §4.1 / §4.2: `AwaitingFactor.sentTo` changed `String?` → `List<String>` (server
  returns an array); `advanceOrFinalize` snippet updated accordingly.
- §5.1: `FinalizeResp` corrected to `{status, session_id?, required_factors[],
  passed}`; removed fabricated `{ok, session:{id, expires_at}}`. Documented the
  `status:"pending"` resync contract.
- §5.2: `MfaVerifyResp` corrected (removed `ok`; added `status/session_id/
  required_factors/passed`); `MfaBeginResp.sentTo` corrected to `List<String>`;
  documented per-factor verify field names (`totp_code` vs `code`).
- §5.3: `MeResp` corrected to `{user_sub, session_id, ip}`.
- §5.4 / §7 / §13-R1 / §11: replaced the "finalize 409 challenge_not_complete"
  assumption with the verified HTTP-200 `status:"pending"` resync; renamed test
  `finalize_409_resyncs_remaining` → `finalize_pending_resyncs_remaining`.

### Open assumptions

- **Untyped 200 bodies.** OpenAPI declares no response schema for `finalize`,
  the verify/begin routes, `/ui/me`, and `refresh` (all `resp=200:`). Their field
  shapes are taken from the frontend types, which mirror the backend Pydantic
  models per the `types.ts` header comment, but are not independently confirmable
  from the OpenAPI document itself.
- **Cookie/CSRF transport on Android (AND-027).** Persistent cookie jar,
  `EncryptedSharedPreferences` backing, and the `X-CSRF-Token` interceptor are
  owned by AND-027; assumed correct. No Android source exists in the reference
  repo to verify.
- **`remember_device` cookie semantics** (name, `Max-Age`/TTL) are server-defined
  and not exposed in OpenAPI or the frontend types; only the request flag is
  verifiable. (§13-R3.)
- **Re-`begin` after `switchFactor` back to a previously-begun factor** (§13-R2):
  the web client always re-issues begin via explicit user action; whether a prior
  challenge is reusable server-side is not documented. Sequencer assumes re-begin.
- **`refreshSession` return body** is treated as `StatusResp` by the frontend but
  the OpenAPI body is untyped; the sequencer only cares about success/failure.
- **Android testing stack** (Robolectric/AVD/device matrix) is environmental, not
  derivable from the sources; see §17 target annotations.

## 17. Test Plan

Test targets (per case): **JVM** = JVM/Robolectric unit, local no device;
**MockWebServer** = JVM contract test with a scripted HTTP server;
**emulator(test35)** = headless AVD x86_64 Android 15/API 35;
**device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a).
This ticket is orchestration/logic with no UI of its own (UI is AND-039), so most
cases are JVM/MockWebServer; device/emulator cases cover real cookie+CSRF
transport, the flaky-dev-host/offline path, and the ABI/API-level matrix.

- **TC-AND-038-01** — Single-factor TOTP happy path.
  - Type: contract/MockWebServer. Target: MockWebServer + JVM.
  - Preconditions: MockWebServer scripts `session/start`→`required_factors=[totp]`;
    `totp/verify`→200 `{status:"ok", remaining_factors:[], passed:{totp:true}}`;
    `finalize`→200 `{status:"ok", session_id:"sess_1", required_factors:[]}`;
    `/ui/me`→200 `{user_sub, session_id, ip}`.
  - Steps: seed sequencer with start resp; `submitCode("123456")`.
  - Expected: verify body is `{challenge_id, totp_code:"123456"}`; finalize called
    once; terminal state `Authenticated(MeResp(user_sub=...))`.
  - Traces: AC-1.

- **TC-AND-038-02** — Multi-factor TOTP→SMS sequence + emission order.
  - Type: contract/MockWebServer (Turbine). Target: MockWebServer + JVM.
  - Preconditions: start `required_factors=[totp,sms]`; totp verify→`remaining=[sms]`;
    `sms/begin`→200 `{challenge_id, sent_to:["+1 (***) ***-1234"]}`; sms verify→
    `remaining=[]`; finalize→`status:"ok"`+`session_id`; `/ui/me`→200.
  - Steps: seed start; `submitCode(totp)`; assert `AwaitingFactor(SMS)` with
    `sentTo=["+1 (***) ***-1234"]`; `submitCode(sms)`.
  - Expected: Turbine emission order
    `AwaitingFactor(TOTP) → AwaitingFactor(SMS) → Finalizing → Authenticated`;
    `beginSms` fires only after totp passes; finalize called exactly once.
  - Traces: AC-2, AC-7.

- **TC-AND-038-03** — Finalize not called while factors remain.
  - Type: unit. Target: JVM + fake `AuthRepository`.
  - Preconditions: fake repo; start `[totp,sms]`; totp verify→`remaining=[sms]`.
  - Steps: `submitCode(totp)`; do not submit sms.
  - Expected: `finalizeSession` call count == 0; state is `AwaitingFactor(SMS)`.
  - Traces: AC-3.

- **TC-AND-038-04** — Finalize invoked exactly once at terminal condition.
  - Type: unit. Target: JVM + fake `AuthRepository` with call counters.
  - Preconditions: start `[totp]`; verify→`remaining=[]`; finalize→ok; me→200.
  - Steps: `submitCode(totp)`.
  - Expected: `finalizeSession` count == 1, invoked only after `remaining` empty.
  - Traces: AC-3.

- **TC-AND-038-05** — `remember_device=true` propagated in finalize body.
  - Type: contract/MockWebServer (request capture). Target: MockWebServer + JVM.
  - Preconditions: start `[totp]`; sequencer seeded with `rememberDevice=true`.
  - Steps: `submitCode(totp)`; capture finalize `RecordedRequest`.
  - Expected: finalize JSON body == `{"challenge_id":"...","remember_device":true}`;
    default case (not set) serializes `remember_device:false`.
  - Traces: AC-4.

- **TC-AND-038-06** — Wrong code keeps user on active factor (error shape).
  - Type: contract/MockWebServer. Target: MockWebServer + JVM.
  - Preconditions: start `[totp]`; `totp/verify`→422 `HTTPValidationError`
    `{detail:[{msg:"invalid code", loc:["body","totp_code"], type:"value_error"}]}`
    (and a 401 string-detail variant in a second run).
  - Steps: `submitCode("000000")`.
  - Expected: state remains `AwaitingFactor(TOTP)` with `error` set from mapped
    `detail`; `active`/`remaining` unchanged; finalize never called.
  - Traces: AC-5.

- **TC-AND-038-07** — Finalize `status:"pending"` resync (no 409).
  - Type: contract/MockWebServer. Target: MockWebServer + JVM.
  - Preconditions: start `[totp]`; verify→`remaining=[]`; finalize→200
    `{status:"pending", required_factors:["sms"], passed:{totp:true}}`.
  - Steps: `submitCode(totp)`.
  - Expected: sequencer does NOT emit `Failed`; resyncs to `AwaitingFactor(SMS)`
    using `required_factors` from the finalize body; no second finalize yet.
  - Traces: AC-3, AC-5.

- **TC-AND-038-08** — `/ui/me` transient failure retried without re-finalize.
  - Type: contract/MockWebServer. Target: MockWebServer + JVM.
  - Preconditions: start `[totp]`; verify→`remaining=[]`; finalize→ok once;
    `/ui/me` first→500, second→200.
  - Steps: `submitCode(totp)`.
  - Expected: `finalizeSession` count == 1; `/ui/me` attempted twice (bounded
    backoff); terminal `Authenticated`. finalize is never retried.
  - Traces: AC-6.

- **TC-AND-038-09** — Switch factor runs begin for the target.
  - Type: unit. Target: JVM + fake `AuthRepository`.
  - Preconditions: start `[sms,email]` (or `remaining=[sms,email]`); user can't get
    SMS.
  - Steps: `switchFactor(EMAIL)`.
  - Expected: `beginEmail` invoked (not `beginSms`); state `AwaitingFactor(EMAIL)`
    with `sentTo` from begin; switching only allowed to a factor in `remaining`
    (switch to a non-remaining factor is rejected / no-op).
  - Traces: AC-2 (sequencing), AC-7.

- **TC-AND-038-10** — Factor order preserved from server.
  - Type: unit. Target: JVM + fake `AuthRepository`.
  - Preconditions: start `required_factors=[sms, totp]` (deliberately non-default).
  - Steps: inspect first `AwaitingFactor`.
  - Expected: active factor == `SMS` (server order honored; no client TOTP-first
    reordering).
  - Traces: AC-2.

- **TC-AND-038-11** — No OTP/recovery codes in state or logs (security).
  - Type: unit. Target: JVM (capture Timber tree + serialize `MfaFlowState`).
  - Preconditions: in-memory log capture; start `[totp]`.
  - Steps: `submitCode("654321")`; run a recovery `submitCode` with a recovery code.
  - Expected: no emitted `MfaFlowState` contains the code; no captured log line
    contains the code (TOTP/SMS/email/recovery); telemetry events carry only
    `{factor, ok, remaining_count}`, never code material.
  - Traces: AC-1, AC-5 (security cross-cut).

- **TC-AND-038-12** — Finalize carries `X-CSRF-Token` on the shared client (real
  transport).
  - Type: instrumented/integration. Target: emulator(test35) (cookie jar +
    interceptor are device/runtime behavior, not pure JVM).
  - Preconditions: app built with AND-027 cookie jar + CSRF interceptor pointed at
    MockWebServer (or dev host) that issues a `Set-Cookie: ui_csrf=...` during the
    challenge.
  - Steps: drive start→verify→finalize; capture the finalize request headers.
  - Expected: finalize request includes `X-CSRF-Token` == the `ui_csrf` cookie
    value and the challenge session cookies; the call uses the shared OkHttp client.
  - Traces: AC-3 (finalize correctness) — security/permission case.

- **TC-AND-038-13** — Flaky dev-host / offline resilience.
  - Type: instrumented/integration. Target: device(A15) (PREFERRED — exercises
    real radio/connectivity drop on arm64/API 34; toggle airplane mode mid-flow).
  - Preconditions: TOTP-only account against the dev host; ability to drop the
    network after finalize but before `/ui/me`.
  - Steps: complete totp verify + finalize; disable connectivity so first `/ui/me`
    yields an IO error; re-enable; allow retry.
  - Expected: IO failure maps to `AuthError.Network`; `/ui/me` retried (idempotent
    GET) without a second finalize; flow reaches `Authenticated` once connectivity
    returns. If connectivity stays down, terminal `Failed(Network)` with a retry
    affordance (consumed by AND-039). MUST run on the physical device for true
    radio-level offline behavior; emulator airplane-mode is an acceptable smoke.
  - Traces: AC-6.

- **TC-AND-038-14** — Real-backend single- and multi-factor e2e (dev host).
  - Type: instrumented/e2e (CI-tagged, opt-in). Target: device(A15) for the
    arm64/API-34 acceptance run; also run on emulator(test35) for the x86_64/API-35
    matrix to catch ABI/API-level differences.
  - Preconditions: seeded dev-host test accounts — one requiring `[totp]`, one
    requiring `[totp, sms]`; valid test OTP source.
  - Steps: run the sequencer end-to-end for both accounts through real
    `session/start → verify(s) → finalize → /ui/me`.
  - Expected: both reach `Authenticated` with `/ui/me` 200 and a populated
    `MeResp.user_sub`; multi-factor `beginSms` fires only after totp; no behavioral
    delta between API 34 (device) and API 35 (emulator).
  - Traces: AC-1, AC-2, AC-7.

### Coverage matrix

| AC | Description | Covered by |
| --- | --- | --- |
| AC-1 | `[totp]` → Authenticated, `/ui/me` 200 | TC-01, TC-11, TC-14 |
| AC-2 | `[totp,sms]` in sequence; beginSms after totp | TC-02, TC-09, TC-10, TC-14 |
| AC-3 | finalize exactly once, only when remaining empty | TC-03, TC-04, TC-07, TC-12 |
| AC-4 | `remember_device` sent when true | TC-05 |
| AC-5 | wrong code stays on active factor, no advance/finalize | TC-06, TC-07, TC-11 |
| AC-6 | transient `/ui/me` failure retried, no 2nd finalize | TC-08, TC-13 |
| AC-7 | StateFlow emission order (Turbine) | TC-02, TC-09, TC-14 |
