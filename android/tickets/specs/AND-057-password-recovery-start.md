---
id: AND-057
title: "Password recovery: start"
milestone: M2
epic: E08
priority: P1
size: M
depends_on: [AND-030]
blocks: [AND-058]
status: reviewed
reviewed_on: 2026-06-06
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

FR-3. On **Continue**, call `PasswordRecoveryApi.start(PasswordRecoveryStartReq(username))` (`POST /ui/password-recovery/start`). The session cookie jar and `X-CSRF-Token` header are attached automatically by the shared OkHttp chain even though the user is unauthenticated. **Note:** per the web client (`src/api/client.ts`), `X-CSRF-Token` is attached only **if** a `ui_csrf` cookie is already present (`getCookie("ui_csrf")`); the client does not itself force-issue one. Whether the backend sets `ui_csrf` on first unauthenticated contact is an **unverified assumption** — if no cookie exists yet, no CSRF header is sent (matching web behavior).

FR-4. On a `200`, parse the returned response and **render it**: the `delivery_medium` (e.g. sms/email), the masked `delivery_destination`, and the list of `required_factors` (CORRECTED: these are flat top-level fields, not a nested `delivery` object). Then emit a navigation effect `ProceedToConfirm` carrying `challengeId`, `requiredFactors`, and the delivery summary to the downstream confirm/verify step (AND-058).

FR-5. If the `200` response indicates no challenge is required (`required_factors` empty / `challenge_id` absent — e.g. a backend that emails a reset link directly), render a terminal "Check your <medium> for instructions" confirmation state and offer "Back to sign in" rather than navigating to a factor step. (Defensive: the contract is open-typed; see Section 5 / R1.) **Divergence note:** the web reference (`src/pages/PasswordRecovery.tsx`) does **not** implement a terminal state — it always advances to the in-page confirm step regardless of `delivery_*` presence, falling back to a generic "sent to your registered contact method" message. The terminal-state behavior here is an Android UX choice, not a mirror of the web flow.

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
    // CORRECTED: the response is a FLAT object (per frontend src/api/types.ts:
    // PasswordRecoveryStartResp and src/pages/PasswordRecovery.tsx). There is NO
    // nested `delivery` object and NO `auth_required` field. The real fields are:
    val status: String? = null,                                  // present in web DTO (required there); tolerated/optional here
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,        // "sms" | "email" | ... (web treats as free string)
    @Json(name = "delivery_destination") val deliveryDestination: String? = null, // masked destination, e.g. "+1 ••• ••• 4821"
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)
// NOTE: OpenAPI types the 200 body as an open object (additionalProperties: true,
// no documented properties); the field names above come from the frontend contract,
// not OpenAPI. All fields are nullable/defaulted so extra/missing keys never crash parsing.
// The former nested `DeliveryDescriptor` / `medium` / `destination` / `auth_required`
// shape was an unverified reconstruction and has been removed.
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
        // CORRECTED: read the flat delivery_medium / delivery_destination fields.
        val summary = resp.deliveryMedium?.let { DeliverySummary(it, resp.deliveryDestination) }
        val cid = resp.challengeId
        if (cid != null && resp.requiredFactors.isNotEmpty()) {
            _effects.send(RecoveryStartEffect.ProceedToConfirm(cid, resp.requiredFactors, summary))
        } else {
            _state.update { it.copy(sentConfirmation = summary ?: DeliverySummary("email", null)) }
        }
    }

    private fun handleHttpError(e: ApiError) = _state.update {
        // CORRECTED: throttling is detected by HTTP status 429, not by a
        // `recovery_throttled` detail code (no such code exists in the backend
        // contract or web reference; the web client keys throttle handling off
        // err.status === 429). If the backend ever returns a structured throttle
        // detail, its retry field is `retry_after_seconds` (per frontend
        // src/api/endpoints/profile.ts), not `retry_after`.
        when {
            e.httpStatus == 429 -> it.copy(isSubmitting = false, error = RecoveryStartError.Throttled)
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

Response `200` — challenge issued. **CORRECTED:** OpenAPI documents the 200 body only as an open object (`additionalProperties: true`, no properties), but the **frontend contract** (`src/api/types.ts: PasswordRecoveryStartResp` and `src/pages/PasswordRecovery.tsx`) defines a **flat** shape — `status` (string, required in the web DTO), plus optional `delivery_medium`, `delivery_destination`, `challenge_id`, and required `required_factors`. There is **no** nested `delivery` object and **no** `auth_required` field (those were unverified reconstructions and are removed). Real shape:
```json
{
  "status": "challenge_sent",
  "challenge_id": "pwr_9c4ad21e",
  "required_factors": ["sms"],
  "delivery_medium": "sms",
  "delivery_destination": "+1 ••• ••• 4821"
}
```

Response `200` — direct-link / no-challenge variant (FR-5); `delivery_*`/`challenge_id` may be absent (the web app then shows a generic "sent to your registered contact method" message):
```json
{ "status": "ok", "required_factors": [], "delivery_medium": "email", "delivery_destination": "a•••@example.com" }
```

Errors (FastAPI `detail` polymorph; the web client's `normalizeErrorDetail` in `src/api/client.ts` flattens it — `string` | `[{msg}]` | `{code,...}` (authorization codes) | `{msg}`). The Android `ApiErrorMapper` (AND-015) mirrors this:
- `422` validation → `{ "detail": [{ "loc": ["body","username"], "msg": "field required", "type": "value_error.missing" }] }` (HTTPValidationError, the only non-200 OpenAPI documents for this op).
- `429` throttled → detected by **HTTP status 429** (the web client keys throttle handling off `err.status === 429`). **CORRECTED:** there is no `recovery_throttled` detail code in the contract or web reference; where a structured retry value exists elsewhere the field is `retry_after_seconds` (see `src/api/endpoints/profile.ts`), not `retry_after`. The exact 429 body for *this* op is **unverified** (not in OpenAPI).
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
- **Error mapping:** HTTP `429` → `Throttled` inline message ("Too many attempts. Please wait a moment and try again.") — keyed on HTTP status, **not** a `recovery_throttled` detail code (corrected; no such code exists); `422` and any other `HttpError` → generic localized message via `AuthErrorPresenter`; `NetworkError` (timeout/connection) → `NetworkUnavailable` ("Couldn't reach the server. Check your connection and try again."), field re-enabled.
- **Dev host instability:** ~20s OkHttp timeout (AND-009); flaky `5xx`/timeouts map to retryable inline messaging — no crash, no silent hang.
- **401 on an unauthenticated screen:** not expected here. **CORRECTED per web reference:** the web client (`src/api/client.ts`) explicitly does **not** refresh+retry a 401 when the user is unauthenticated — it propagates the 401 directly to the caller (only authenticated sessions trigger `/ui/session/refresh`). Android should match this: a 401 on the recovery screen surfaces as a generic `HttpError` and is **not** sent through the AND-013 refresh `Authenticator`. (The earlier claim that the Authenticator would attempt a refresh here was wrong.)
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

1. **Acceptance — start returns challenge/delivery and advances (primary):** fake client returns `PasswordRecoveryStartResp(challengeId="pwr_1", requiredFactors=["sms"], deliveryMedium="sms", deliveryDestination="+1 ••• ••• 4821")` (CORRECTED to flat fields); call `onContinue()` with a valid username; assert a `ProceedToConfirm("pwr_1", ["sms"], DeliverySummary("sms","+1 ••• ••• 4821"))` effect is emitted. (Maps to source AC: "Start returns challenge/delivery and advances UI (tested).")
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

- **R1 — Open response shape (RESOLVED against frontend):** `/openapi.json` types the `200` body as an open object (`additionalProperties: true`) with no documented properties, so OpenAPI alone cannot confirm fields. The frontend contract (`src/api/types.ts: PasswordRecoveryStartResp`, consumed in `src/pages/PasswordRecovery.tsx`) **does** define them: `status` (string), `delivery_medium?`, `delivery_destination?`, `challenge_id?`, `required_factors: string[]`. The DTO has been corrected to this **flat** shape; the previously assumed nested `delivery: {medium, destination}` object and `auth_required` flag were wrong and removed. Residual risk: the *runtime* values of `status`/medium and whether the dev backend actually populates these on a live `200` are still unverified (no captured live response). DTO uses defaults/nullables so unexpected/missing keys do not crash parsing.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. "OpenAPI" = `reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Endpoint is `POST /ui/password-recovery/start`.** — **Verified.** OpenAPI `POST /ui/password-recovery/start` (op=`password_recovery_start_ui_password_recovery_start_post`); frontend `src/api/endpoints/auth.ts: passwordRecoveryStart` → `api.post("/ui/password-recovery/start", body)`.
2. **Request body is `{ "username": "<string>" }`, username required.** — **Verified.** OpenAPI schema `PasswordRecoveryStartReq` (`properties.username: string`, `required: ["username"]`); frontend `src/api/types.ts: PasswordRecoveryStartReq { username: string }`.
3. **200 response shape (`status`, `delivery_medium?`, `delivery_destination?`, `challenge_id?`, `required_factors[]`), FLAT not nested.** — **Corrected.** OpenAPI types the 200 only as an open object (`additionalProperties: true`, no properties — `openapi.pretty.json` "Response Password Recovery Start..."), so the field names come from frontend `src/api/types.ts: PasswordRecoveryStartResp` and their use in `src/pages/PasswordRecovery.tsx` (`resp.challenge_id`, `resp.delivery_medium`, `resp.delivery_destination`). Original spec used a nested `delivery: {medium, destination}` object plus an `auth_required` flag — both wrong; removed.
4. **`status` field exists in the 200 response.** — **Verified (frontend).** `src/api/types.ts: PasswordRecoveryStartResp.status: string` (required in web DTO). Original spec omitted it; added (nullable on Android for tolerance).
5. **Throttling is HTTP `429`; there is no `recovery_throttled` detail code.** — **Corrected.** No `recovery_throttled` / `too_many_requests` code occurs anywhere in `reference/src` (grep). Web clients key throttle handling off `err.status === 429` (e.g. `src/pages/Register.tsx:319`, `src/api/endpoints/profile.ts:189`). Original spec matched on a non-existent `recovery_throttled` string code; corrected to status-based detection.
6. **Retry-delay field name (where present) is `retry_after_seconds`, not `retry_after`.** — **Corrected.** Frontend `src/api/endpoints/profile.ts:127` reads `retry_after_seconds`. Original spec used `retry_after`. (Note: no throttle body is documented for *this* op — see Open assumptions.)
7. **Error `detail` polymorph: `string | [{msg}] | {code,...} | {msg}`, normalized to a display string.** — **Verified.** `src/api/client.ts: normalizeErrorDetail` handles exactly these shapes; `422` uses `HTTPValidationError` per OpenAPI (`resp=...;422:HTTPValidationError`).
8. **CSRF: `X-CSRF-Token` header is attached automatically from the `ui_csrf` cookie.** — **Verified (with nuance).** `src/api/client.ts` lines 168-171: `const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token", csrf)`. The header is sent only **if** the cookie exists.
9. **The backend issues a `ui_csrf` cookie on first unauthenticated contact.** — **Unverified-assumption.** Not observable from frontend source (it only reads an existing cookie) nor from OpenAPI. Flagged inline in FR-3.
10. **On a 401 on an unauthenticated screen, NO refresh+retry occurs.** — **Corrected.** `src/api/client.ts:194-203`: when `!isAuthenticated`, the 401 is thrown directly; only authenticated sessions call `/ui/session/refresh`. Original spec claimed the AND-013 Authenticator would attempt a refresh here; corrected.
11. **Session refresh endpoint is `POST /ui/session/refresh`.** — **Verified.** `src/api/client.ts:122` `fetch(withApiBase("/ui/session/refresh"), { method: "POST" })`.
12. **Login screen links to the recovery flow at `/password-recovery` (link text "Forgot password?").** — **Verified.** `src/pages/Login.tsx:560-563` `to="/password-recovery" ... Forgot password?`. (The Android route `recovery/start` is an internal nav choice, not from the web.)
13. **Downstream confirm body is `{username, confirmation_code, new_password, challenge_id?}`.** — **Verified.** OpenAPI `PasswordRecoveryConfirmReq` (required: username, confirmation_code, new_password; `challenge_id` is `anyOf string|null`); frontend `src/pages/PasswordRecovery.tsx: handleConfirm` and `src/api/endpoints/auth.ts: passwordRecoveryConfirm`. (Owned by AND-058.)
14. **Per-factor challenge endpoints exist (`/ui/password-recovery/challenge/{sms,email,totp,recovery}/{begin,verify}`).** — **Verified.** OpenAPI lines for `password_recovery_*_begin/verify` ops; schemas `PasswordRecoveryChallengeReq`, `PasswordRecoverySmsVerifyReq` (`code`), `PasswordRecoveryEmailVerifyReq` (`code`), `PasswordRecoveryTotpVerifyReq` (`totp_code`), `PasswordRecoveryRecoveryCodeReq` (`factor`,`recovery_code`). (Owned by AND-058.)
15. **Only `200` and `422` are documented for the start op.** — **Verified.** OpenAPI index: `resp=200:;422:HTTPValidationError`; `429`/`5xx` are handled defensively (not in the contract).
16. **Account-enumeration safety via a uniform `200` for unknown accounts.** — **Unverified-assumption.** The backend's unknown-account behavior is not described in OpenAPI; the web app shows a generic error toast on `start` failure (`src/pages/PasswordRecovery.tsx:76-81`) and does not branch on "user not found", but uniform-200 is a backend/product assumption (R3).
17. **Web reference always advances to an in-page confirm step (no terminal "check your medium" state).** — **Verified.** `src/pages/PasswordRecovery.tsx: handleRequest` always `setStep("confirm")`. The Android terminal-state (FR-5) is a deliberate divergence, flagged inline.
18. **Framework/tooling choices (Kotlin 2.0.21, Compose + Material 3, Hilt/KSP, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, minSdk 24 / compileSdk 35, JDK 17, AGP 8.7.3).** — **Unverified-assumption (framework ref).** Not derivable from backend/frontend sources; inherited from cross-cutting Android tickets (AND-009/010/011/012/013/015/016/018). Treated as project-standard; validate against the Android module's `libs.versions.toml` at build time. Compose `semantics`/live-region a11y APIs: framework ref `https://developer.android.com/jetpack/compose/accessibility`.

### Corrections made
- **C1.** Response DTO changed from nested `delivery: DeliveryDescriptor(medium, destination)` + `auth_required` to the real **flat** fields `status`, `delivery_medium`, `delivery_destination`, `challenge_id`, `required_factors` (claims 3, 4). Updated DTO block, `handleSuccess`, Section 5 examples, R1, and test #1.
- **C2.** Throttle detection changed from a non-existent `recovery_throttled`/`too_many_requests` detail code to **HTTP status 429** (claim 5). Updated `handleHttpError`, Section 5 errors, Section 7.
- **C3.** Retry field corrected `retry_after` → `retry_after_seconds` where referenced (claim 6).
- **C4.** 401 behavior corrected: no refresh+retry on the unauthenticated recovery screen — matches `src/api/client.ts` (claim 10). Updated Section 7.
- **C5.** FR-3 CSRF wording corrected to "attached only if a `ui_csrf` cookie exists" and the "issued on first contact" claim downgraded to an explicit assumption (claims 8, 9).
- **C6.** FR-5 annotated with the web-vs-Android divergence (web always proceeds to confirm) (claim 17).

### Open assumptions
- **OA1.** Backend issues `ui_csrf` on first unauthenticated contact (claim 9) — not observable from sources; if absent, the first `start` call goes out with no CSRF header (as the web client would).
- **OA2.** Exact `200` runtime payload on the dev host (`status` value, whether `delivery_*` is populated, the medium enum domain) — OpenAPI is open-typed and no live capture was available; field *names* are confirmed via frontend, values are not (R1 residual).
- **OA3.** The shape/existence of a `429` throttle body for the start op specifically (claim 6) — not in OpenAPI; Android handles 429 generically by status. Throttle copy/hard-lock policy (R4) unconfirmed.
- **OA4.** Uniform-`200` account-enumeration behavior (claim 16 / R3) — a backend/product assumption; Android is designed to be safe either way.
- **OA5.** Whether `required_factors` is authoritative at `start` vs only at `confirm` (R2) — unconfirmed; Android forwards whatever `start` returns.
- **OA6.** Android framework/tooling versions (claim 18) — inherited project standards, not verifiable from the provided sources.

## 17. Test Plan

IDs `TC-AND-057-NN`. Targets: **JVM** (local JVM unit/Robolectric, no device), **emulator** (headless AVD `test35`, x86_64 / API 35, CI), **device** (physical Samsung Galaxy A15 5G, SM-A156U / serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). This ticket is pure-Kotlin UI + network with no hardware dependency, so most cases run on JVM/emulator; the physical device is used only to confirm real-network/flaky-host and arm64/API-34 parity.

**TC-AND-057-01 — Happy path: start returns challenge → advances.**
Type: unit (ViewModel). Target: JVM. Preconditions: fake `PasswordRecoveryApiClient.start` returns `Success(PasswordRecoveryStartResp(status="challenge_sent", challengeId="pwr_1", requiredFactors=["sms"], deliveryMedium="sms", deliveryDestination="+1 ••• ••• 4821"))`. Steps: `onUsernameChanged("alice@example.com")`; `onContinue()`; collect effects. Expected: exactly one `ProceedToConfirm("pwr_1", ["sms"], DeliverySummary("sms","+1 ••• ••• 4821"))`; `isSubmitting` returns false; no error; no `sentConfirmation`. Traces: AC-1, AC-2.

**TC-AND-057-02 — Contract: request path/method/body/CSRF.**
Type: contract/MockWebServer. Target: JVM. Preconditions: real `PasswordRecoveryApi`/client against MockWebServer; a `ui_csrf` cookie seeded in the jar. Steps: enqueue `200` `{"status":"ok","challenge_id":"pwr_1","required_factors":["sms"],"delivery_medium":"sms","delivery_destination":"+1 ••• ••• 4821"}`; call `start("alice@example.com")`; inspect `RecordedRequest`. Expected: `method == POST`, `path == /ui/password-recovery/start`, body exactly `{"username":"alice@example.com"}` (trimmed), `Content-Type: application/json`, `X-CSRF-Token` header present and equal to the cookie value; parsed resp maps flat fields correctly. Traces: AC-1.

**TC-AND-057-03 — DTO tolerance: flat fields + unknown keys + missing optionals.**
Type: unit (Moshi). Target: JVM. Preconditions: Moshi adapter for `PasswordRecoveryStartResp`. Steps: parse (a) the flat challenge JSON, (b) `{"status":"ok","required_factors":[]}` (no delivery/challenge), (c) a body with extra unknown keys. Expected: (a) maps `deliveryMedium`/`deliveryDestination`/`challengeId`; (b) yields null delivery/challenge and empty factors; (c) parses without throwing. Confirms the C1 correction. Traces: AC-1, AC-2.

**TC-AND-057-04 — No-challenge variant → terminal state, no effect (FR-5).**
Type: unit (ViewModel). Target: JVM. Preconditions: fake returns `Success` with `requiredFactors=[]`, `challengeId=null`, `deliveryMedium="email"`, `deliveryDestination="a•••@example.com"`. Steps: valid username; `onContinue()`. Expected: **no** `ProceedToConfirm` effect; `state.sentConfirmation == DeliverySummary("email","a•••@example.com")`; UI shows "check your email". Traces: AC-3.

**TC-AND-057-05 — Validation gate: blank username makes zero network calls.**
Type: unit (ViewModel). Target: JVM. Preconditions: spy client. Steps: leave username blank (and try whitespace-only); read `canContinue`; call `onContinue()`. Expected: `canContinue == false`; client `start` invoked **0** times; no effect; no state change to submitting. Traces: AC-4.

**TC-AND-057-06 — Error mapping (parametrized).**
Type: unit (ViewModel). Target: JVM. Preconditions: fake returns, per case: `HttpError(status=429)`, `HttpError(status=422, HTTPValidationError detail)`, `HttpError(status=500)`, `NetworkError`. Steps: valid username; `onContinue()` each. Expected: 429 → `RecoveryStartError.Throttled`; 422 & 500 → `RecoveryStartError.Message(...)` (generic, localized); NetworkError → `RecoveryStartError.NetworkUnavailable`; in every case `isSubmitting==false`, no effect, field re-enabled, **no auto-retry** (client called once). Confirms C2 (status-based throttle). Traces: AC-5.

**TC-AND-057-07 — Double-submit guard.**
Type: unit (ViewModel). Target: JVM. Preconditions: fake `start` suspends on a latch. Steps: valid username; call `onContinue()` twice before the first completes; release latch. Expected: client `start` invoked exactly **once**; field/button reported disabled while `isSubmitting`. Traces: AC-5 (resilience), AC-1.

**TC-AND-057-08 — Account-enumeration indistinguishability.**
Type: unit (ViewModel), parametrized. Target: JVM. Preconditions: two fakes — "known user" `200` and "unknown user" `200` (same neutral shape per OA4). Steps: run start for each. Expected: identical resulting `UiState`/effect (no distinct "user not found" branch). If a distinguishing error is injected, it maps to the same generic `Message`. Traces: AC-6.

**TC-AND-057-09 — No-PII telemetry & logging.**
Type: unit. Target: JVM. Preconditions: in-memory analytics + log capture. Steps: drive open → attempt → success(`medium="sms"`) and an error path. Expected: emitted events are `pwrecovery_start_*` only; **no** payload/log entry contains the raw username, `delivery_destination`, or `challenge_id`; `pwrecovery_start_result` carries only `has_challenge`/`medium`; error log carries only `ApiError.code`/HTTP status. Traces: AC-6.

**TC-AND-057-10 — Compose UI: enable→submit→advance + a11y.**
Type: Compose-UI. Target: emulator (`test35`). Preconditions: `RecoveryStartScreen` with a fake VM (success path). Steps: assert Continue disabled with empty field; type username → Continue enabled; tap Continue; assert `onProceed` fired with the challenge; assert delivery medium/destination rendered. A11y assertions: username field has a label/contentDescription; Continue and back-to-login expose ≥48dp touch targets; inline error node exposes `semantics { error(...) }` with an assertive live region; focus moves to the username field on entry. Traces: AC-1, AC-3, AC-7.

**TC-AND-057-11 — Compose UI: error live-region announcement.**
Type: Compose-UI. Target: emulator (`test35`). Preconditions: fake VM emits `Throttled` then `NetworkUnavailable`. Steps: trigger each; inspect semantics tree. Expected: localized throttle/network strings shown; error node has `liveRegion = Assertive`; screen stays on the username field and the field re-enables. Traces: AC-5, AC-7.

**TC-AND-057-12 — i18n/RTL/dynamic-type render.**
Type: Compose-UI. Target: emulator (`test35`). Preconditions: locale set to a pseudo/RTL locale and font scale 1.3. Steps: render the screen and the delivery/terminal states. Expected: no hardcoded strings (all from `strings.xml`), layout mirrors under RTL, masked destination renders directionally-neutral, no truncation/overlap at 1.3x. Traces: AC-7.

**TC-AND-057-13 — Real-network / flaky-host & offline (on hardware).**
Type: instrumented/e2e. Target: **device (must run on physical Samsung A15)** — exercises real OkHttp over the unreliable plaintext dev host (`http://18.222.237.167:8000`) and real radio/airplane-mode offline, which the emulator's virtual NIC does not faithfully reproduce; also validates arm64-v8a / API-34 parity vs the x86_64/API-35 emulator. Preconditions: debug build pointing at the dev host on the device. Steps: (a) submit a valid username and observe a real `200`/timeout; (b) toggle airplane mode and submit; (c) retry after re-enabling network. Expected: (a) success advances or a `5xx`/timeout maps to a retryable inline message with no crash/hang within the ~20s timeout; (b) `NetworkUnavailable` shown, no doomed long hang; (c) user-driven retry succeeds — confirming no auto-retry on the POST. Traces: AC-5, AC-1.

**TC-AND-057-14 — CSRF-absent first-contact behavior (assumption probe).**
Type: contract/MockWebServer. Target: JVM. Preconditions: empty cookie jar (no `ui_csrf`). Steps: call `start(...)`; inspect `RecordedRequest`; then enqueue a Set-Cookie `ui_csrf=...` on the response and repeat. Expected: first request carries **no** `X-CSRF-Token` (matching web `src/api/client.ts`); after the cookie is set, the subsequent request includes it. Documents OA1 (no crash either way). Traces: AC-1 (transport correctness).

### Coverage matrix
| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (POST body, render delivery, ProceedToConfirm effect) | TC-01, TC-02, TC-03, TC-07, TC-10, TC-13, TC-14 |
| AC-2 (onContinue → client.start, forward not persist) | TC-01, TC-03 |
| AC-3 (screen reachable, fields, terminal no-challenge state) | TC-04, TC-10 |
| AC-4 (validation disables Continue, zero network on blank) | TC-05 |
| AC-5 (error mapping, stays put, no auto-retry) | TC-06, TC-07, TC-11, TC-13 |
| AC-6 (enumeration-safe, no PII in logs/analytics) | TC-08, TC-09 |
| AC-7 (a11y: labels/roles, live-region errors, ≥48dp, localized) | TC-10, TC-11, TC-12 |
