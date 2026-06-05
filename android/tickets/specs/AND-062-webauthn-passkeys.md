---
id: AND-062
title: WebAuthn (passkeys)
milestone: M2
epic: E08
priority: P2
size: L
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-062 — WebAuthn (passkeys)

## 1. Overview & Goal

Add platform passkey (FIDO2 / WebAuthn) support to the TestLogon native Android app so a user can (a) register a platform passkey bound to their authenticated session and (b) authenticate with that passkey as a first-factor or step-up factor. The flow uses AndroidX **Credential Manager** (`androidx.credentials`) wired to the backend's four WebAuthn endpoints: `POST /ui/webauthn/register/begin`, `POST /ui/webauthn/register/finish`, `POST /ui/webauthn/authenticate/begin`, and `POST /ui/webauthn/authenticate/finish`.

The backend speaks the standard WebAuthn "options JSON" that Credential Manager consumes verbatim. The Android responsibility is: request options from the backend, hand the raw JSON to Credential Manager, marshal the resulting registration/assertion response JSON back to the `finish` endpoint, and surface the result. Every WebAuthn call rides the **same cookie-based session and `X-CSRF-Token` header** established by `AuthApi` (AND-027); register requires an authenticated session, and the assertion `finish` participates in session establishment like other factors.

Goal: on a supported device (Android 9+ with a screen lock / Google Password Manager passkey provider), a user can register a passkey from Account/Security settings and subsequently sign in with that passkey, with all failure modes (no provider, user cancellation, unsupported device, RP-ID mismatch, timeout) handled gracefully.

## 2. Context & References

- **Project stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.
- **New dependency:** `androidx.credentials:credentials:1.3.0` and `androidx.credentials:credentials-play-services-auth:1.3.0` (the latter routes WebAuthn to Google Play services / GMS as the credential provider on devices without a system-level provider).
- **Namespace:** all code under `com.testlogon.android`. This feature lives in a new module `feature-passkey` (`com.testlogon.android.feature.passkey`) plus a thin `WebAuthnApi` + repository in `core-network` / `core-data`.
- **Depends on AND-027** (`AuthApi` session endpoints) for: the shared OkHttp client, the persistent cookie jar, the `X-CSRF-Token` interceptor, the 401 → `POST /ui/session/refresh` → retry interceptor, and `ApiResult<T>` / FastAPI `detail` error mapping. `WebAuthnApi` reuses the identical OkHttp instance so cookies/CSRF apply unchanged.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts` (WebAuthn endpoints) and shared types in `frontend/src/api/types.ts`.
- **RP ID & origin:** the Relying Party ID is the backend's web domain (the value returned in the `rp.id` field of begin options). Android passkeys require a verified app-to-web association via a Digital Asset Links file (`/.well-known/assetlinks.json`) on the RP-ID host, declaring the app's package `com.testlogon.android` and its signing SHA-256 fingerprint. This is an external/backend dependency tracked as an Open Question (§13).
- **Standards:** W3C WebAuthn Level 2 JSON serialization; Credential Manager `CreatePublicKeyCredentialRequest` / `GetCredentialRequest` (`GetPublicKeyCredentialOption`) consume and return the registration/assertion JSON strings directly.

## 3. Functional Requirements

FR-1. **Capability detection.** Before showing any passkey affordance, determine whether the device supports platform passkeys. Expose `suspend fun isPasskeySupported(): Boolean` (Android API >= 28 AND a Credential Manager provider available). On unsupported devices the registration entry point is hidden; the authenticate entry point degrades silently (no passkey button shown on the sign-in screen).

FR-2. **Registration.** From an authenticated context (Security settings), the user taps "Add a passkey". The app calls `register/begin`, passes the returned creation-options JSON to `CredentialManager.createCredential`, then posts the resulting `RegistrationResponseJSON` to `register/finish`. On success the UI shows a confirmation and the new credential metadata (created date, optional nickname).

FR-3. **Authentication.** On the sign-in screen, if `isPasskeySupported()` is true, show a "Sign in with a passkey" action. It calls `authenticate/begin` (unauthenticated, may take an optional username hint), passes the request-options JSON to `CredentialManager.getCredential`, and posts the `AuthenticationResponseJSON` to `authenticate/finish`. A successful `finish` establishes/advances the session identically to other factors; the app then proceeds to `GET /ui/me` and navigates to the authenticated graph.

FR-4. **Step-up.** When the backend's MFA flow lists `webauthn` in `required_factors`, the passkey assertion flow is invoked with the active `challenge_id` (see §5) and on success the caller resumes the existing finalize sequence (`POST /ui/session/finalize`). Reuse the same assertion code path as FR-3.

FR-5. **Cancellation & errors.** User cancellation, no-credential-available, and provider errors must not crash and must return the user to the prior screen with a non-blocking, actionable message (§7). No partial/orphaned state is persisted on the client.

FR-6. **Idempotency / re-entrancy.** While a Credential Manager dialog is in flight, the trigger button is disabled to prevent concurrent requests. Begin requests are GET-like in spirit but are POSTs with server-issued challenges; the client never retries `begin` or `finish` automatically (challenges are single-use) — only the AND-027 401-refresh interceptor may retry once.

## 4. Technical Design

### Module & layering
```
feature-passkey  ->  core-data (PasskeyRepository)  ->  core-network (WebAuthnApi)  ->  core-model
```

### Credential Manager wrapper (`core-data`)
A thin, injectable wrapper isolates the AndroidX API for testability:

```kotlin
package com.testlogon.android.core.data.passkey

interface PasskeyManager {
    suspend fun isPasskeySupported(): Boolean
    /** @param requestJson the raw creation-options JSON from register/begin. */
    suspend fun createCredential(activity: Context, requestJson: String): PasskeyOutcome<String>
    /** @param requestJson the raw request-options JSON from authenticate/begin. */
    suspend fun getCredential(activity: Context, requestJson: String): PasskeyOutcome<String>
}

sealed interface PasskeyOutcome<out T> {
    data class Success<T>(val responseJson: T) : PasskeyOutcome<T>
    data object Cancelled : PasskeyOutcome<Nothing>
    data object NoCredential : PasskeyOutcome<Nothing>
    data class Failure(val type: PasskeyErrorType, val cause: Throwable) : PasskeyOutcome<Nothing>
}

enum class PasskeyErrorType { UNSUPPORTED, INTERRUPTED, PROVIDER, DOM_EXCEPTION, UNKNOWN }
```

```kotlin
class CredentialManagerPasskeyManager @Inject constructor(
    @ApplicationContext private val appContext: Context,
) : PasskeyManager {
    private val cm = CredentialManager.create(appContext)

    override suspend fun createCredential(activity: Context, requestJson: String): PasskeyOutcome<String> =
        runCatching {
            val req = CreatePublicKeyCredentialRequest(requestJson = requestJson)
            val resp = cm.createCredential(activity, req) as CreatePublicKeyCredentialResponse
            resp.registrationResponseJson
        }.fold(
            onSuccess = { PasskeyOutcome.Success(it) },
            onFailure = { it.toPasskeyOutcome() },
        )
    // getCredential analogous, building GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson)))
}
```

`createCredential`/`getCredential` must be invoked with an **Activity `Context`** (Credential Manager renders system UI); the ViewModel receives the Activity via a Compose `LocalContext`/`LocalActivity` and passes it through, never holding a long-lived reference.

### Repository (`core-data`)
```kotlin
class PasskeyRepository @Inject constructor(
    private val api: WebAuthnApi,
    private val passkeyManager: PasskeyManager,
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    suspend fun registerPasskey(activity: Context, nickname: String?): ApiResult<RegisteredPasskey>
    suspend fun authenticateWithPasskey(
        activity: Context,
        usernameHint: String?,
        challengeId: String?,   // non-null for step-up; null for first-factor
    ): ApiResult<WebAuthnFinishResult>
}
```
Each method: (1) call `*/begin` → `ApiResult`; (2) on success, invoke the matching `PasskeyManager` call with the returned `optionsJson`; (3) map `PasskeyOutcome` to either an `ApiResult.Success` continuation or a typed `ApiResult.Error`; (4) call `*/finish` with the response JSON; (5) return the finish result. The intermediate Credential Manager step is **not** an HTTP call and is never subject to OkHttp retry.

### ViewModel & UI (`feature-passkey`)
```kotlin
@HiltViewModel
class PasskeyRegisterViewModel @Inject constructor(
    private val repo: PasskeyRepository,
) : ViewModel() {
    val uiState: StateFlow<PasskeyUiState>            // Idle | InProgress | Success(RegisteredPasskey) | Error(msg)
    fun register(activity: Context, nickname: String?)
}
```
`PasskeyUiState` is a sealed interface exposed as `StateFlow<PasskeyUiState>` per the project convention. Compose screens: `AddPasskeyScreen` (settings) and a `PasskeySignInButton` composable embedded by the sign-in feature. The sign-in/step-up integration is consumed by the auth feature; this ticket provides the button + a `authenticateWithPasskey` entry point that returns a result the auth flow acts on.

## 5. API Contract

All endpoints share the AND-027 OkHttp client (cookies + `X-CSRF-Token` header). Base URL `http://18.222.237.167:8000`. Authoritative shapes are derived from `/openapi.json` and `frontend/src/api/endpoints`; field names below match the WebAuthn JSON spec the backend emits.

```kotlin
interface WebAuthnApi {
    @POST("ui/webauthn/register/begin")
    suspend fun registerBegin(@Body body: RegisterBeginRequest): Response<WebAuthnBeginResponse>

    @POST("ui/webauthn/register/finish")
    suspend fun registerFinish(@Body body: RegisterFinishRequest): Response<RegisteredPasskey>

    @POST("ui/webauthn/authenticate/begin")
    suspend fun authenticateBegin(@Body body: AuthenticateBeginRequest): Response<WebAuthnBeginResponse>

    @POST("ui/webauthn/authenticate/finish")
    suspend fun authenticateFinish(@Body body: AuthenticateFinishRequest): Response<WebAuthnFinishResult>
}
```

**register/begin** — request (authenticated session required):
```json
{ "nickname": "Pixel 8" }
```
response (`WebAuthnBeginResponse`) — `options` is the verbatim creation-options JSON forwarded to Credential Manager:
```json
{
  "challenge_id": "wac_01H...",
  "options": {
    "rp": { "id": "testlogon.example.com", "name": "TestLogon" },
    "user": { "id": "dXNlcklk", "name": "spannella@gmail.com", "displayName": "Sean" },
    "challenge": "Y2hhbGxlbmdl",
    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 }],
    "timeout": 60000,
    "attestation": "none",
    "authenticatorSelection": { "authenticatorAttachment": "platform", "residentKey": "required", "userVerification": "required" },
    "excludeCredentials": []
  }
}
```
Note: Moshi models `options` as a raw passthrough (`@Json String` of the serialized object, or `Map<String, Any?>` re-serialized) so the exact JSON reaches Credential Manager without lossy re-encoding. Implementation uses a custom adapter that captures the `options` subtree as its source string.

**register/finish** — request:
```json
{ "challenge_id": "wac_01H...", "credential": { /* RegistrationResponseJSON from Credential Manager */ } }
```
response (`RegisteredPasskey`): `{ "credential_id": "...", "nickname": "Pixel 8", "created_at": "2026-06-05T12:00:00Z" }`.

**authenticate/begin** — request (no session needed; optional hint and optional `challenge_id` for step-up):
```json
{ "username": "spannella@gmail.com", "challenge_id": null }
```
response: same `WebAuthnBeginResponse` shape with request-options JSON (contains `allowCredentials`, `rpId`, `challenge`, `userVerification`, `timeout`).

**authenticate/finish** — request:
```json
{ "challenge_id": "wac_01H...", "credential": { /* AuthenticationResponseJSON */ } }
```
response (`WebAuthnFinishResult`): `{ "auth_required": false, "required_factors": [], "session_established": true }` (first-factor) or, in step-up, the finalize-eligible shape consumed by the existing session sequence.

**Errors:** FastAPI `detail` may be `string | [{msg}] | {code,...}`; reuse AND-027's `detail` mapper. Expected statuses: 400 (malformed credential), 401 (no/invalid session on register; triggers one refresh+retry via interceptor), 404 (no matching credential), 409 (credential already registered → maps to user message), 410/422 (expired/invalid challenge → "Please try again").

## 6. Data & State Management

- **No new persistent store on device.** Passkey private keys never touch the app; they live in the platform credential provider. The app persists nothing about the credential locally beyond what the backend returns for display.
- **Session/cookies:** entirely owned by AND-027's persistent cookie jar + DataStore-backed CSRF handling. This ticket adds no new DataStore keys.
- **Registered-credential list** (display of existing passkeys in Security settings) is a backend read; if a list endpoint exists it is consumed read-only and may be cached in Room only if AND-027/account-management owns that table — this ticket does not introduce a Room entity.
- **UI state** is transient `StateFlow<PasskeyUiState>` held in the ViewModel; `challenge_id` is kept in-memory only for the duration of a single begin→finish round trip and discarded after `finish` (single-use). No challenge or response JSON is logged or persisted.

## 7. Error Handling & Resilience

Map `PasskeyOutcome` and `ApiResult.Error` to user-facing states:

| Condition | Source | UI message / behavior |
|---|---|---|
| Device < API 28 or no provider | `isPasskeySupported()` false | Entry point hidden; no error shown |
| User dismissed system sheet | `GetCredentialCancellationException` / `CreateCredentialCancellationException` → `Cancelled` | Silent return to prior screen, no toast |
| No passkey on device (auth) | `NoCredentialException` → `NoCredential` | "No passkey found for this account on this device." |
| RP-ID / asset-links mismatch | `CreateCredentialUnknownException` / DOM error | "Passkeys aren't set up for this app yet." + log |
| Provider/GMS error | `*ProviderConfigurationException` → `PROVIDER` | "Passkey service unavailable. Try again." |
| `begin`/`finish` network failure | `ApiResult.Error` | Generic retry message; **no auto-retry** of begin/finish |
| 401 on register `begin` | interceptor | One refresh+retry (AND-027); if still 401 → "Please sign in again." |
| 409 already registered | `finish` 409 | "This device already has a passkey for your account." |
| Expired challenge (410/422) | `finish` | "That took too long. Try again." (re-runs full begin→finish) |

Resilience: the unreliable dev host means `begin` uses the global ~20s timeout. Because challenges are single-use, **bounded backoff retry is NOT applied** to any WebAuthn call (they are non-idempotent POSTs); the only permitted retry is the single 401-refresh. A `withTimeout` guard wraps the Credential Manager call (e.g. matching the options `timeout`, default 60s) to avoid an indefinitely hung dialog state.

## 8. Security & Privacy

- Passkey key material is hardware/provider-backed and never exposed to the app; the app only handles opaque challenge/response JSON.
- **CSRF:** register endpoints are state-changing and authenticated; the `X-CSRF-Token` header (from AND-027) must be present. Verify the CSRF interceptor applies to `WebAuthnApi` (it does, since the same OkHttp client is reused).
- **Transport:** the dev backend is plaintext HTTP. Passkey assertions are origin-bound and challenge-signed, so interception cannot replay them, but this is a dev-only posture — production requires HTTPS and a valid asset-links association. Document the cleartext exception is dev-only (`networkSecurityConfig`).
- **RP-ID binding / asset links:** correct `assetlinks.json` on the RP host is a hard security control — without it Credential Manager refuses to mint/return platform passkeys for the app. SHA-256 signing fingerprints for debug and release builds must be registered (Open Question §13).
- **Privacy:** never log `challenge`, `credential`, raw response JSON, user handle, or `user.id`. Telemetry uses event names and error categories only (§10). No PII in crash reports.
- Use `userVerification: "required"` for both ceremonies (server-driven, but the app must not weaken it).

## 9. Accessibility & i18n

- The passkey action buttons (`AddPasskeyScreen`, `PasskeySignInButton`) have `contentDescription`s and meet the 48dp minimum touch target. The Credential Manager system sheet is OS-owned and inherits platform accessibility.
- All copy (button labels, every error message in §7, success confirmation) is in `strings.xml` under keys prefixed `passkey_*` — no hardcoded strings. Support RTL via standard Compose layout.
- Loading/in-progress state is announced (`Modifier.semantics { stateDescription = ... }`) and the trigger is disabled (not just visually) while a request is in flight so TalkBack users don't double-activate.
- Error messages are concrete and actionable, not raw exception text.

## 10. Telemetry & Logging

Emit structured analytics events (via the project's telemetry abstraction; PII-free):
- `passkey_register_started`, `passkey_register_succeeded`, `passkey_register_failed { error_type }`
- `passkey_auth_started { context: "signin"|"stepup" }`, `passkey_auth_succeeded`, `passkey_auth_failed { error_type }`
- `passkey_unsupported_device` (once per session when detection fails)

`error_type` is the `PasskeyErrorType` enum or an HTTP-status bucket. Debug logging via Timber at `d`/`w` level may record event names, HTTP status, and `PasskeyErrorType` — **never** challenges, credential JSON, or user identifiers. Verify ProGuard/R8 strips verbose logs in release.

## 11. Testing Strategy

**Unit (JVM, `core-testing`):**
- `PasskeyRepository` with a fake `WebAuthnApi` (MockWebServer) + fake `PasskeyManager`:
  - register happy path: begin → manager.Success → finish → `ApiResult.Success`.
  - authenticate happy path (first-factor and step-up with `challenge_id`).
  - `PasskeyOutcome.Cancelled` → repository returns a `Cancelled`-mapped error and **does not** call `finish`.
  - `NoCredential`, `Failure(PROVIDER)`, `Failure(DOM_EXCEPTION)` mappings.
  - begin 401 → verify single refresh+retry (interceptor) then success/terminal failure; assert begin/finish are never retried beyond that.
  - finish 409/410 → correct user-message mapping.
- **Options passthrough test:** assert the raw `options` JSON from `begin` is forwarded byte-equivalent (semantically) to `PasskeyManager.createCredential`/`getCredential` (no field loss via Moshi).
- `ViewModel` state transitions Idle→InProgress→Success/Error via Turbine on `StateFlow`.

**Instrumented / integration:**
- MockWebServer-driven end-to-end of `WebAuthnApi` verifying paths, verbs, bodies, headers (`X-CSRF-Token` present, cookies sent).
- Capability detection branch on emulators (API 24 → unsupported; API 34 with GMS → supported).
- Manual device test (acceptance): real register + authenticate with a platform passkey on a Pixel (API 34) signed with a fingerprint registered in asset-links — this is the literal acceptance criterion and cannot be fully automated in CI (system credential UI). Documented manual test plan attached to the PR.

**Negative:** user-cancel on the system sheet returns cleanly; airplane mode during `begin` shows network error with no crash.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-027** (AuthApi session endpoints) — provides the shared OkHttp client, cookie jar, CSRF interceptor, 401-refresh interceptor, and `ApiResult`/`detail` mapping that `WebAuthnApi` reuses. This ticket must not duplicate that wiring.
- **New libraries:** add `androidx.credentials:credentials:1.3.0` and `:credentials-play-services-auth:1.3.0` to the version catalog and `feature-passkey`/`core-data` build files.
- **Backend prerequisite (external):** `assetlinks.json` published on the RP-ID host with the app's release + debug SHA-256 fingerprints; WebAuthn endpoints live and returning standard options JSON. Without these, manual acceptance cannot pass (Open Question).
- **Consumers:** the sign-in / MFA step-up feature integrates `PasskeySignInButton` + `authenticateWithPasskey` (it depends on the session/MFA flow tickets in E04/E08); Security/Account settings hosts `AddPasskeyScreen`. Sequence: land `WebAuthnApi` + `PasskeyRepository` first, then UI, then sign-in integration.

## 13. Risks & Open Questions

1. **Asset-links / RP-ID association** (highest risk): platform passkeys require a verified Digital Asset Links file on the RP host bound to `com.testlogon.android` + signing fingerprints. If the dev RP host (`18.222.237.167` / its domain) cannot serve `/.well-known/assetlinks.json` over the correct origin, Credential Manager will reject all ceremonies. **Open:** confirm RP-ID domain and who publishes asset-links.
2. **`options` JSON fidelity:** the backend must emit Credential Manager-compatible options JSON (correct base64url, field names). Any deviation breaks the opaque passthrough. **Open:** confirm backend serialization matches WebAuthn Level 2 JSON exactly (validate against `/openapi.json` and a live sample).
3. **Step-up contract:** exact `authenticate/finish` response when `webauthn` is a step-up factor vs. first-factor (does it return finalize-ready state or require a separate `finalize`?). **Open:** confirm with backend / web reference.
4. **GMS dependency:** non-GMS devices (no Google Play services) won't have a passkey provider via `credentials-play-services-auth`; treat as unsupported. Acceptable for M2.
5. Plaintext HTTP in dev weakens transport but not the passkey ceremony's cryptographic binding; production HTTPS is mandatory.

## 14. Acceptance Criteria

1. On a supported device (API >= 28 with a passkey provider), a signed-in user can register a platform passkey from Security settings: app calls `register/begin`, Credential Manager creates the credential, app posts to `register/finish`, and a success confirmation with credential metadata is shown. (Maps to source acceptance: "Register … with a platform passkey on a supported device.")
2. A user can authenticate with that passkey: `authenticate/begin` → Credential Manager assertion → `authenticate/finish` establishes the session, `GET /ui/me` succeeds, and the app navigates to the authenticated graph. (Maps to: "… authenticate with a platform passkey on a supported device.")
3. `WebAuthnApi` paths, verbs, bodies, and headers (`X-CSRF-Token`, cookies) match the contract, verified by MockWebServer tests.
4. The raw `options` JSON from `begin` reaches Credential Manager without field loss (verified by test).
5. All §7 failure modes (cancel, no-credential, unsupported, provider error, 401, 409, expired challenge) produce the specified non-crashing behavior; cancellation never calls `finish`.
6. Unsupported devices hide the registration entry point and omit the passkey sign-in button with no error.
7. No challenge, credential JSON, or user identifier appears in logs/telemetry.

## 15. Definition of Done

- `feature-passkey` module + `WebAuthnApi` + `PasskeyRepository` + `PasskeyManager` wrapper implemented under `com.testlogon.android`, wired via Hilt, reusing AND-027's OkHttp/cookie/CSRF stack.
- `androidx.credentials` (1.3.0) + `credentials-play-services-auth` added to the version catalog and module build files; app builds (AGP 8.7.3, JDK 17, Gradle 8.9) with no new lint/baseline regressions.
- Unit + MockWebServer tests in §11 pass in CI; manual device register+authenticate verified on a Pixel (API 34) and recorded in the PR.
- All user-facing copy in `strings.xml` (`passkey_*`); buttons accessible (48dp, content descriptions, in-flight disabled + announced).
- Telemetry events emitted; no PII/secret logging confirmed by review; release R8 strips verbose logs.
- Open Questions §13 (asset-links host, options fidelity, step-up contract) resolved or explicitly deferred with backend sign-off; code reviewed and merged to `android-port`.
