---
id: AND-057
title: "Password recovery: start"
milestone: M2
epic: E08
priority: P1
size: M
status: draft
depends_on: [AND-030]
blocks: [AND-058]
---

# AND-057 — Password recovery: start

## 1. Overview & Goal

This ticket delivers the **entry point of the password-recovery flow**: a "Forgot your password?" recovery screen that takes a username, calls `POST /ui/password-recovery/start`, and advances the UI by rendering the challenge the backend returns — the delivery medium (SMS/email), the masked destination (e.g. `+1 ••• ••• 4821`), and the factors the user must satisfy to confirm a reset. It is reached from the recovery link on the login screen (AND-030).

The scope is the **start** step only. AND-057 owns (a) the recovery-entry Compose screen and its `PasswordRecoveryStartViewModel`, (b) the `PasswordRecoveryApi` Retrofit surface + DTOs for `start`, (c) client-side username validation and the in-flight/error/offline UI states, and (d) the navigation effect that hands the resulting challenge (`challenge_id`, delivery descriptor, required factors) to the confirm/verify step. AND-057 does **not** implement the per-factor begin/verify calls (`/ui/password-recovery/challenge/...`), `POST /ui/password-recovery/confirm` (the actual password change), or the login screen — those are downstream in AND-058 (which this ticket blocks).

Success: from the recovery screen a user enters a username, taps "Continue," and on a `200` the app renders the returned delivery medium/destination and required factors and emits a navigation effect carrying the challenge to the next step — proven by an automated test asserting "start returns challenge/delivery and advances the UI."

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo Android app under `android/`, branch `android-port`. Code lands in `:feature-auth` (`android/feature-auth/src/main/kotlin/com/testlogon/android/feature/auth/recovery/`) and `:core-network` (`com.testlogon.android.core.network.recovery` for the API + DTOs).
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Upstream dependency — AND-030 (Login screen UI):** provides the "links to recovery/register" affordance and the unauthenticated nav graph (`:feature-auth` auth `NavGraphBuilder`, AND-023) into which the recovery destination is registered, plus shared core input composables (AND-020) and state composables — loading/empty/error/offline (AND-021) reused here.
- **Cross-cutting (assumed merged):** persistent cookie jar (AND-011), `CsrfInterceptor` (AND-012), single-`401`→refresh `Authenticator` (AND-013), ~20s OkHttp timeouts + logging (AND-009), Retrofit/Moshi setup (AND-010), `ApiResult<T>` (AND-018), `ApiError` + FastAPI `detail` mapping (AND-015), bounded backoff for idempotent GETs (AND-016). Note: `start` is a **POST** and therefore not auto-retried (Section 7).
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Contract source: `/openapi.json` (verified live for this ticket). Web reference app: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Sibling / pattern source:** the MFA challenge flow (AND-033/AND-040 challenge state machine; AND-037 recovery-code flow) establishes the `challengeId` + `requiredFactors` + delivery-descriptor patterns reused here; password-recovery is a parallel, distinct challenge namespace.

## 3. Functional Requirements

FR-1. Provide a recovery-entry Compose screen reachable from the login "Forgot your password?" link (route `recovery/start`). It presents a single **username** field (label, helper text "Enter the username for the account you want to recover"), a primary **Continue** action, and a back affordance returning to login.

FR-2. Client-side validation: trim the username, require non-blank, and disable **Continue** until non-blank. The field accepts the same identifier the login screen uses (username or email); no email-format enforcement (the backend resolves the identity). Validation never calls the network.

FR-3. On **Continue**, call `PasswordRecoveryApi.start(PasswordRecoveryStartReq(username))` (`POST /ui/password-recovery/start`). The session cookie jar and `X-CSRF-Token` header are attached automatically by the shared OkHttp chain even though the user is unauthenticated (a `ui_csrf` cookie is issued on first contact).

FR-4. On a `200`, parse the returned challenge descriptor and **render it**: the `delivery.medium` (sms/email/totp), the masked `delivery.destination`, and the list of `required_factors`. Then emit a navigation effect `ProceedToConfirm` carrying `challengeId`, `requiredFactors`, and the delivery descriptor to the downstream confirm/verify step (AND-058).

FR-5. If the `200` response indicates no challenge is required (`required_factors` empty / `delivery` absent — e.g. a backend that emails a reset link directly), render a terminal "Check your <medium> for instructions" confirmation state and offer "Back to sign in" rather than navigating to a factor step. (Defensive: the contract is open-typed; see Section 5 / R1.)

FR-6. Account enumeration safety: the screen must behave **identically** whether or not the username exists. If the backend returns a generic `200` for unknown accounts, render the same neutral "If an account exists, we've started recovery…" path. The client must not branch UI on "user not found" (Section 8).

FR-7. While the request is in flight, **Continue** shows a loading state and the field is disabled, preventing double submission.

FR-8. On error (`422` validation, `429` throttle, `5xx`/timeout, network unavailable), surface a localized, user-readable inline message; the screen stays on the username field for retry. No auto-retry (Section 7).

## 4. Technical Design

All new feature code lives under `com.testlogon.android.feature.auth.recovery`; the network surface under `com.testlogon.android.core.network.recovery`. The screen follows the project MVI-ish convention: a `StateFlow<UiState>` plus a one-shot `Channel`/`Flow` of effects for navigation.

**DTOs (`:core-network`, Moshi):**

```kotlin
package com.testlogon.android.core.network.recovery

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class PasswordRecoveryStartReq(
    val username: String,
)

@JsonClass(generateAdapter = true)
data class PasswordRecoveryStartResp(
    @Json(name = "challenge_id") val challengeId: String?,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    val delivery: DeliveryDescriptor? = null,
    // Backends that mail a link directly may omit the above; tolerate extra keys.
    @Json(name = "auth_required") val authRequired: Boolean = true,
)

@JsonClass(generateAdapter = true)
data class DeliveryDescriptor(
    val medium: String,                 // "sms" | "email" | "totp"
    @Json(name = "destination") val destinationMasked: String?, // e.g. "+1 ••• ••• 4821"
)
```

**Retrofit API (`:core-network`):**

```kotlin
interface PasswordRecoveryApi {
    @POST("ui/password-recovery/start")
    suspend fun start(@Body body: PasswordRecoveryStartReq): retrofit2.Response<PasswordRecoveryStartResp>
}
```

A thin client wraps it into the typed `ApiResult` and maps `detail` via the shared `ApiErrorMapper` (AND-015):

```kotlin
class PasswordRecoveryApiClient @Inject constructor(
    private val api: PasswordRecoveryApi,
    private val errorMapper: ApiErrorMapper,
) {
    suspend fun start(username: String): ApiResult<PasswordRecoveryStartResp> =
        safeApiCall(errorMapper) { api.start(PasswordRecoveryStartReq(username.trim())) }
}
```

**State / effect (`:feature-auth`):**

```kotlin
package com.testlogon.android.feature.auth.recovery

data class RecoveryStartUiState(
    val username: String = "",
    val canContinue: Boolean = false,
    val isSubmitting: Boolean = false,
    val sentConfirmation: DeliverySummary? = null,   // FR-5 terminal "check your X" state
    val error: RecoveryStartError? = null,
)

data class DeliverySummary(val medium: String, val destinationMasked: String?)

sealed interface RecoveryStartError {
    data class Message(val text: String) : RecoveryStartError
    data object Throttled : RecoveryStartError                 // 429
    data object NetworkUnavailable : RecoveryStartError
}

sealed interface RecoveryStartEffect {
    data class ProceedToConfirm(
        val challengeId: String,
        val requiredFactors: List<String>,
        val delivery: DeliverySummary?,
    ) : RecoveryStartEffect
}
```

**ViewModel:**

```kotlin
@HiltViewModel
class PasswordRecoveryStartViewModel @Inject constructor(
    private val client: PasswordRecoveryApiClient,
    private val errorPresenter: AuthErrorPresenter,   // ApiError -> string res id (shared)
) : ViewModel() {

    private val _state = MutableStateFlow(RecoveryStartUiState())
    val state: StateFlow<RecoveryStartUiState> = _state.asStateFlow()

    private val _effects = Channel<RecoveryStartEffect>(Channel.BUFFERED)
    val effects: Flow<RecoveryStartEffect> = _effects.receiveAsFlow()

    fun onUsernameChanged(value: String) = _state.update {
        it.copy(username = value, canContinue = value.isNotBlank(), error = null)
    }

    fun onContinue() {
        val s = _state.value
        if (!s.canContinue || s.isSubmitting) return
        viewModelScope.launch {
            _state.update { it.copy(isSubmitting = true, error = null) }
            when (val r = client.start(s.username)) {
                is ApiResult.Success    -> handleSuccess(r.value)
                is ApiResult.HttpError  -> handleHttpError(r.error)
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isSubmitting = false, error = RecoveryStartError.NetworkUnavailable) }
            }
        }
    }

    private suspend fun handleSuccess(resp: PasswordRecoveryStartResp) {
        _state.update { it.copy(isSubmitting = false) }
        val summary = resp.delivery?.let { DeliverySummary(it.medium, it.destinationMasked) }
        val cid = resp.challengeId
        if (cid != null && resp.requiredFactors.isNotEmpty()) {
            _effects.send(RecoveryStartEffect.ProceedToConfirm(cid, resp.requiredFactors, summary))
        } else {
            _state.update { it.copy(sentConfirmation = summary ?: DeliverySummary("email", null)) }
        }
    }

    private fun handleHttpError(e: ApiError) = _state.update {
        when (e.code) {
            "recovery_throttled", "too_many_requests" ->
                it.copy(isSubmitting = false, error = RecoveryStartError.Throttled)
            else -> it.copy(isSubmitting = false, error = RecoveryStartError.Message(errorPresenter.message(e)))
        }
    }
}
```

**Screen + route:**

```kotlin
@Composable
fun RecoveryStartRoute(
    vm: PasswordRecoveryStartViewModel = hiltViewModel(),
    onProceed: (challengeId: String, factors: List<String>, delivery: DeliverySummary?) -> Unit,
    onBackToLogin: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) {
        vm.effects.collect { e ->
            when (e) {
                is RecoveryStartEffect.ProceedToConfirm ->
                    onProceed(e.challengeId, e.requiredFactors, e.delivery)
            }
        }
    }
    RecoveryStartScreen(state, vm::onUsernameChanged, vm::onContinue, onBackToLogin)
}
```

The destination is registered in the unauthenticated auth `NavGraphBuilder` (AND-023): `composable("recovery/start") { RecoveryStartRoute(...) }`. The login screen's "Forgot your password?" link navigates to `recovery/start`. `onProceed` navigates to the downstream confirm route owned by AND-058 (placeholder route until that ticket lands). Delivery medium/destination and required factors are rendered with `:core-ui` state composables; no new module is introduced.

## 5. API Contract

`POST /ui/password-recovery/start`. Session/`ui_csrf` cookies + `X-CSRF-Token` header attached by the shared chain. Verified against `/openapi.json` on the dev host.

Request (`PasswordRecoveryStartReq`, `username` required):
```json
{ "username": "alice@example.com" }
```

Response `200` — challenge issued (the documented schema is an open object, `additionalProperties: true`; the app tolerates extra keys and reads the fields below):
```json
{
  "auth_required": true,
  "challenge_id": "pwr_9c4ad21e",
  "required_factors": ["sms"],
  "delivery": { "medium": "sms", "destination": "+1 ••• ••• 4821" }
}
```

Response `200` — direct-link / no-challenge variant (FR-5):
```json
{ "auth_required": false, "required_factors": [], "delivery": { "medium": "email", "destination": "a•••@example.com" } }
```

Errors (FastAPI `detail` polymorph, normalized by `ApiErrorMapper` — string | `[{msg}]` | `{code,...}`):
- `422` validation → `{ "detail": [{ "loc": ["body","username"], "msg": "field required", "type": "value_error.missing" }] }`
- `429` throttled → `{ "detail": { "code": "recovery_throttled", "retry_after": 30 } }`
- `5xx` / timeout (dev host instability) → mapped to `HttpError`/`NetworkError`, surfaced as retryable inline message.

The OpenAPI document only enumerates `200` and `422` for this operation; `429`/`5xx` are handled defensively. Downstream `POST /ui/password-recovery/confirm` (`{username, confirmation_code, new_password, challenge_id?}`) and the per-factor `/ui/password-recovery/challenge/{totp|sms|email}/{begin|verify}` calls are **owned by AND-058**; this ticket only emits the challenge to that flow.

## 6. Data & State Management

- **Transient screen state:** `RecoveryStartUiState` in `PasswordRecoveryStartViewModel.state` (`StateFlow`), recreated per screen instance. The username lives only in this in-memory state and the Compose `TextField`.
- **Challenge hand-off:** the returned `challengeId`, `requiredFactors`, and delivery summary are passed forward via the `ProceedToConfirm` effect (nav arguments) to AND-058. This ticket does **not** persist them; the downstream confirm flow owns any shared `PasswordRecoveryChallengeStore`.
- **No new persistence:** no Room tables, no DataStore keys. The session/`ui_csrf` cookies are managed by the existing persistent cookie jar (AND-011); recovery start relies on that jar so the same session carries into the confirm step.
- **Process death:** `username` survives via `rememberSaveable`/`SavedStateHandle` (it is not a secret). An in-flight request is not resumed; on recreation the user re-taps Continue.
- **State transitions:** `Idle → Editing (onUsernameChanged) → Submitting (onContinue) → { challenge→ProceedToConfirm effect | no-challenge→sentConfirmation terminal | error→Editing }`. `canContinue` is derived purely from `username.isNotBlank()`.

## 7. Error Handling & Resilience

- **Validation before network:** blank username never reaches the network; Continue stays disabled.
- **POST → no auto-retry:** `start` mutates server state (issues/refreshes a challenge, may send an SMS/email) and is therefore **not** eligible for the idempotent-GET backoff (AND-016). Retry is user-driven only.
- **Error mapping:** `429`/`recovery_throttled` → `Throttled` inline message ("Too many attempts. Please wait a moment and try again."); `422` and any other `HttpError` → generic localized message via `AuthErrorPresenter`; `NetworkError` (timeout/connection) → `NetworkUnavailable` ("Couldn't reach the server. Check your connection and try again."), field re-enabled.
- **Dev host instability:** ~20s OkHttp timeout (AND-009); flaky `5xx`/timeouts map to retryable inline messaging — no crash, no silent hang.
- **401 on an unauthenticated screen:** not expected here, but if it occurs the shared `Authenticator` (AND-013) attempts a single refresh+retry; a surviving 401 surfaces as a generic `HttpError`.
- **Double-submit guard:** `isSubmitting` short-circuits re-entry into `onContinue()` and disables the field/button.
- **Offline:** if connectivity is known-down (AND-017 probe), the offline state composable (AND-021) is shown and Continue maps to `NetworkUnavailable` without a doomed request.

## 8. Security & Privacy

- **Account enumeration resistance:** the UI must render identically for existing and non-existing usernames (FR-6). The client never surfaces a distinct "user not found" message and never branches navigation on account existence; it trusts the backend's uniform `200`. If the backend does return a distinguishing error, it is mapped to the same generic message (flagged R3).
- **Username is PII, not a credential.** It may appear in `rememberSaveable` state but must never be written to logs/analytics in raw form (Section 10 hashes/omits it). No password is collected on this screen.
- **Masked destination only:** the screen renders the server-provided **masked** `destination`; the client never unmasks or reconstructs full phone/email values.
- **CSRF:** the mandatory `X-CSRF-Token` header (from the `ui_csrf` cookie) is attached automatically by `CsrfInterceptor` (AND-012); no manual handling.
- **Cleartext in dev only:** the dev backend is plaintext HTTP, so the username traverses the wire unencrypted in dev. Release builds reject cleartext via network-security-config (owned by the build/config tickets); flagged here.
- **No body logging of recovery requests:** OkHttp body logging for `/ui/password-recovery/**` is capped at `Level.BASIC` per the network config; this ticket adds no `Log.*`/println of the username or response body.

## 9. Accessibility & i18n

- **All user-facing strings localized** in `:feature-auth` `strings.xml`: `recovery_start_title` ("Reset your password"), `recovery_username_label`, `recovery_username_helper`, `recovery_continue`, `recovery_back_to_login`, the delivery render strings (`recovery_delivery_sms`/`_email`/`_totp` with a `%s` masked-destination placeholder), the terminal `recovery_sent_check_<medium>` messages, and error strings (`recovery_error_throttled`, `recovery_error_network`, `recovery_error_generic`). No hardcoded UI text.
- **TalkBack:** the username field has a label/`contentDescription` association; inline errors are exposed via `Modifier.semantics { error(text) }` and announced through `liveRegion = LiveRegionMode.Assertive`. The loading state announces "Submitting." The rendered delivery/destination is read as a single descriptive node.
- **Touch targets** ≥ 48dp for Continue and the back/login link.
- **Dynamic type / RTL:** Material 3 components with `start/end` padding; honors font scaling and RTL; masked destinations use directionally-neutral rendering.
- **Focus & IME:** entering the screen moves focus to the username field; IME action is `Done`/`Go` wired to `onContinue()`; `KeyboardOptions(autoCorrect = false, capitalization = KeyboardCapitalization.None, keyboardType = KeyboardType.Email)`.

## 10. Telemetry & Logging

Emit via the shared analytics façade — **no raw username, no destination, no challenge_id, no PII**:
- `pwrecovery_start_open {}` — recovery screen shown.
- `pwrecovery_start_attempt {}` — Continue pressed (after client validation).
- `pwrecovery_start_result { has_challenge: Boolean, medium: String? }` — on `200`; `medium` is the non-PII delivery enum (`sms`/`email`/`totp`), never the destination.
- `pwrecovery_start_error { code: String }` — `code` is the non-secret `ApiError.code`/`"throttled"`/`"network"`.

Logging: on error, log only the mapped `ApiError.code` and HTTP status — never the username or response body. These events feed the auth-funnel dashboards owned by the telemetry ticket; AND-057 only emits.

## 11. Testing Strategy

Unit + ViewModel tests in `:feature-auth` (JVM, `core-testing` harness, `PasswordRecoveryApiClient` faked or MockWebServer-backed); one instrumented/Compose UI test for the field→advance path.

1. **Acceptance — start returns challenge/delivery and advances (primary):** fake client returns `PasswordRecoveryStartResp(challengeId="pwr_1", requiredFactors=["sms"], delivery=DeliveryDescriptor("sms","+1 ••• ••• 4821"))`; call `onContinue()` with a valid username; assert a `ProceedToConfirm("pwr_1", ["sms"], DeliverySummary("sms","+1 ••• ••• 4821"))` effect is emitted. (Maps to source AC: "Start returns challenge/delivery and advances UI (tested).")
2. **Path/body via MockWebServer:** enqueue `200`; invoke through the real `PasswordRecoveryApiClient`; assert `RecordedRequest.path == /ui/password-recovery/start`, method `POST`, body exactly `{"username":"alice@example.com"}`, and that `X-CSRF-Token` is present.
3. **No-challenge variant (FR-5):** `200` with empty `required_factors`/null `challenge_id` → no effect emitted; state has `sentConfirmation` populated; UI shows the terminal "check your <medium>" message.
4. **Validation gate:** `onContinue()` with blank username makes **zero** network calls and emits no effect; `canContinue` is false.
5. **Error mapping:** `429`/`recovery_throttled` → `Throttled`; `422` → generic `Message`; `NetworkError` → `NetworkUnavailable`; in all cases the screen stays put and re-enables for retry.
6. **Double-submit guard:** invoking `onContinue()` twice while `isSubmitting` records exactly one request.
7. **Enumeration safety:** a `200` for an unknown user and for a known user produce indistinguishable UI states/effects (parametrized).
8. **No-PII guarantee:** capture analytics events and assert no payload key contains the raw username, destination, or `challenge_id`.
9. **Compose UI test:** render `RecoveryStartScreen`, assert Continue disabled until text entered, type a username, tap Continue (fake success), assert the `onProceed` callback fired with the challenge; assert delivery render and error live-region semantics.
10. **Coverage:** ≥85% line coverage on `PasswordRecoveryStartViewModel`.

## 12. Dependencies & Sequencing

- **Blocked by:** **AND-030** (login screen UI) — provides the "Forgot your password?" link and the unauthenticated nav graph (AND-023) into which `recovery/start` is registered, plus shared input/state composables (AND-020/AND-021). Must merge first.
- **Implicit shared deps (assumed merged):** Retrofit/Moshi (AND-010), `ApiResult`/`ApiError`/detail-mapping (AND-018/AND-015), cookie jar + CSRF (AND-011/AND-012), OkHttp timeouts (AND-009), `401`→refresh `Authenticator` (AND-013), connectivity probe (AND-017).
- **Blocks:** **AND-058** (password recovery: confirm/verify) — consumes the `ProceedToConfirm` effect (challenge id, factors, delivery) emitted here and owns `/ui/password-recovery/confirm` and the per-factor begin/verify calls.
- **Sequencing:** AND-030 → **AND-057** → AND-058. AND-057 can be built against a placeholder downstream route until AND-058 lands.
- **No new third-party dependencies** — all libraries already on the classpath.

## 13. Risks & Open Questions

- **R1 — Open response shape:** `/openapi.json` types the `200` body as an open object (`additionalProperties: true`) with no documented properties. The `challenge_id` / `required_factors` / `delivery` field names here are reconstructed from the MFA challenge pattern and the `PasswordRecoveryConfirmReq` (which has an optional `challenge_id`). Confirm exact keys against a live `200` and `frontend/src/api/endpoints`; adjust the `@Json` names if they differ (e.g. `medium` vs `channel`, `destination` vs `destination_masked`). DTO uses defaults/nullables so unexpected keys do not crash parsing.
- **R2 — Factor source of truth:** whether `required_factors` is returned by `start` or is derived only at `confirm` time. If `start` does not return factors, AND-058 obtains them; AND-057 still renders the delivery descriptor and advances.
- **R3 — Enumeration behavior:** unknown-account handling (uniform `200` vs an error code) is unconfirmed. Design assumes uniform `200`; if an error is returned it is mapped to the generic message and the same path. Confirm with product/security.
- **R4 — Throttle copy/route:** the `retry_after` value and whether repeated throttling should hard-lock the screen are unspecified; current design shows a generic throttle message and allows retry. Confirm copy.
- **R5 — Identifier semantics:** the request field is `username`; the login screen labels it email/username. Confirm whether email addresses are accepted as `username` (assumed yes — no client-side email enforcement).

## 14. Acceptance Criteria

AC-1. From the recovery screen, submitting a valid username calls `POST /ui/password-recovery/start` with body `{ "username": "<value>" }`; on a `200` carrying a challenge the app renders the delivery medium and masked destination and emits a `ProceedToConfirm(challengeId, requiredFactors, delivery)` effect — verified by automated test. (Maps to source AC: "Start returns challenge/delivery and advances UI (tested).")
AC-2. `PasswordRecoveryStartViewModel.onContinue()` is exposed and delegates to `PasswordRecoveryApiClient.start(username)`; the challenge/delivery from the response is forwarded to the downstream confirm step (not persisted by this ticket).
AC-3. The recovery-entry screen is reachable from the login "Forgot your password?" link, renders a username field + Continue + back-to-login, and (on the no-challenge variant) renders a terminal "check your <medium>" state.
AC-4. Client validation disables Continue until the username is non-blank; blank input makes zero network calls.
AC-5. Errors map correctly: `429`/throttle → throttle message, `422`/other HTTP → generic message, network/timeout → retryable network message; the screen stays put and the request is never auto-retried.
AC-6. Account-enumeration safe: identical UI/effects for known and unknown usernames; no raw username, destination, or `challenge_id` appears in logs or analytics payloads.
AC-7. Accessibility: field/labels/roles correct, errors announced via a live region, touch targets ≥48dp, and all strings localized.

## 15. Definition of Done

- `PasswordRecoveryStartReq`/`PasswordRecoveryStartResp`/`DeliveryDescriptor`, `PasswordRecoveryApi`, and `PasswordRecoveryApiClient` implemented under `com.testlogon.android.core.network.recovery`; `PasswordRecoveryStartViewModel`, `RecoveryStartUiState`/`RecoveryStartError`/`RecoveryStartEffect`, `RecoveryStartScreen`/`RecoveryStartRoute` under `com.testlogon.android.feature.auth.recovery`; Hilt-wired; nav destination `recovery/start` registered in the unauthenticated graph and linked from the login screen.
- Wire format (R1/R2) verified against `/openapi.json` and a live `200`; `@Json` field names finalized.
- Tests from Section 11 pass with ≥85% coverage on the ViewModel; the primary "start returns challenge/delivery and advances" test is green; CI green.
- Account-enumeration and no-PII-logging constraints (Sections 8/10) implemented and asserted by test.
- All user-facing strings localized; TalkBack/a11y checks pass.
- No new dependencies; module layering preserved (`:feature-auth` → `:core-network`/`:core-*`; no direct Retrofit use in the feature module).
- KDoc on `PasswordRecoveryStartViewModel.onContinue` documenting the no-retry (POST), enumeration-safety, and PII/logging contract; the `ProceedToConfirm` hand-off to AND-058 documented.
- Code reviewed and merged to `android-port`.
