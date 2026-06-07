---
id: AND-062
title: WebAuthn (passkeys)
milestone: M2
epic: E08
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-062 — WebAuthn (passkeys)

## 1. Overview & Goal

Add platform passkey (FIDO2 / WebAuthn) support to the TestLogon native Android app so a user can (a) register a platform passkey bound to their authenticated session and (b) authenticate with that passkey as a first-factor or step-up factor. The flow uses AndroidX **Credential Manager** (`androidx.credentials`) wired to the backend's four WebAuthn endpoints: `POST /ui/webauthn/register/begin`, `POST /ui/webauthn/register/finish`, `POST /ui/webauthn/authenticate/begin`, and `POST /ui/webauthn/authenticate/finish`.

The backend speaks the standard WebAuthn "options JSON" that Credential Manager consumes verbatim. The Android responsibility is: request options from the backend, hand the raw JSON to Credential Manager, marshal the resulting registration/assertion response JSON back to the `finish` endpoint, and surface the result. **[CORRECTED]** Register endpoints (`register/begin|finish`) ride the **same authenticated transport** established by `AuthApi` (AND-027) — verified against the web client (`src/api/client.ts`), that transport is `Authorization: Bearer <accessToken>` + the persistent session cookie + the `X-CSRF-Token` header (from the `ui_csrf` cookie) + `credentials: include`; the spec's earlier "cookie-based session and `X-CSRF-Token`" wording was incomplete (it omitted the Bearer token). The OpenAPI declares the register endpoints' auth-bearing parameters as `user_sub` (query) + `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers) — see `POST /ui/webauthn/register/begin` params; the Android client must supply whatever AND-027's interceptor stack already attaches and must not re-implement it. **[CORRECTED]** The authenticate endpoints (`authenticate/begin|finish`) are **public/unauthenticated** (OpenAPI lists no security params) and require a `username` in the body; on success `authenticate/finish` returns `{status, session_id}` and the client establishes the session directly (it is NOT routed through the MFA `required_factors`/`finalize` flow — see §5 and the §16 correction).

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

FR-3. **Authentication.** On the sign-in screen, if `isPasskeySupported()` is true, show a "Sign in with a passkey" action. **[CORRECTED]** It calls `authenticate/begin` (unauthenticated) with a **required** `username` field — verified against `WebAuthnAuthBeginReq` (`username` is `required`) and the web client (`src/pages/Login.tsx`, which disables the button until a non-empty username is entered). There is no usernameless/discoverable-credential flow in this contract, so the UI must collect a username/email first (mirroring the web "Security key" step). It passes the request-options JSON to `CredentialManager.getCredential`, then posts `{username, credential}` to `authenticate/finish`. **[CORRECTED]** A successful `finish` returns `{status, session_id}`; the web client treats `status === "ok" && session_id` as success, then calls `GET /ui/me` and navigates to the authenticated graph. The app must do the same — do not assume `session_established`/`auth_required` fields (they do not exist on this response; see §5/§16).

FR-4. **Step-up — NOT SUPPORTED by this contract. [CORRECTED]** The OpenAPI/web reference shows no `challenge_id` field on any WebAuthn schema and no path that feeds a WebAuthn assertion into `POST /ui/session/finalize`. WebAuthn is its own top-level passwordless **first-factor** login step (web: a dedicated "Security key" step in `Login.tsx`), not an MFA factor listed in `required_factors`. The `/ui/session/finalize` flow is driven by `sessionStart` → TOTP/SMS/email/recovery factors (see `auth.ts`/`Login.tsx`), never by webauthn. Therefore this ticket implements WebAuthn only as a standalone authenticate flow (FR-3) and registration (FR-2). If product later wants passkey-as-step-up, that requires a backend contract change and a new ticket. (Previously this FR described a `challenge_id`-based step-up resuming `finalize`; that was an unverified assumption and is removed.)

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
    // [CORRECTED] register/begin takes an optional `label` (not `nickname`); finish returns only { credential_id }.
    suspend fun registerPasskey(activity: Context, label: String?): ApiResult<RegisteredPasskey>
    // [CORRECTED] `username` is REQUIRED by the contract (not an optional hint); no challengeId/step-up exists.
    suspend fun authenticateWithPasskey(
        activity: Context,
        username: String,                // REQUIRED — WebAuthnAuthBeginReq.username
    ): ApiResult<WebAuthnAuthFinishResp> // { status: String, session_id: String? }
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

Register endpoints share the AND-027 authenticated transport (Bearer + session cookie + `X-CSRF-Token`); authenticate endpoints are public. Base URL `http://18.222.237.167:8000`. **[CORRECTED]** All shapes below are verified against `components.schemas` in `reference/openapi.pretty.json` and `reference/src/api/types.ts`. The DTO names and field shapes used by the spec previously were largely invented — they are replaced with the real schema names (`WebAuthnRegisterBeginReq/Resp`, `WebAuthnRegisterFinishReq/Resp`, `WebAuthnAuthBeginReq/Resp`, `WebAuthnAuthFinishReq/Resp`). **There is no `challenge_id` field on any WebAuthn schema.**

```kotlin
interface WebAuthnApi {
    @POST("ui/webauthn/register/begin")
    suspend fun registerBegin(@Body body: WebAuthnRegisterBeginReq): Response<WebAuthnRegisterBeginResp>

    @POST("ui/webauthn/register/finish")
    suspend fun registerFinish(@Body body: WebAuthnRegisterFinishReq): Response<WebAuthnRegisterFinishResp>

    @POST("ui/webauthn/authenticate/begin")
    suspend fun authenticateBegin(@Body body: WebAuthnAuthBeginReq): Response<WebAuthnAuthBeginResp>

    @POST("ui/webauthn/authenticate/finish")
    suspend fun authenticateFinish(@Body body: WebAuthnAuthFinishReq): Response<WebAuthnAuthFinishResp>
}
```

**register/begin** — `WebAuthnRegisterBeginReq` request (authenticated). **[CORRECTED]** Field is optional `label` (nullable), NOT `nickname`. The web client (`WebAuthnDevices.tsx`) sends an **empty body** `{}` and only attaches the label at `finish`:
```json
{}
```
response (`WebAuthnRegisterBeginResp`) — **[CORRECTED]** the schema has exactly ONE field, `options` (`type: object`, `additionalProperties: true`); there is **no `challenge_id`** wrapper. `options` is the verbatim creation-options JSON forwarded to Credential Manager:
```json
{
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
(The interior `options` fields above are an illustrative WebAuthn-spec shape; the backend OpenAPI declares `options` only as an open object, so the exact interior is opaque to the contract — treat it as pass-through.) Note: Moshi models `options` as a raw passthrough (a `Map<String, Any?>` re-serialized, or a custom adapter capturing the `options` subtree as its source string) so the exact JSON reaches Credential Manager without lossy re-encoding.

**register/finish** — `WebAuthnRegisterFinishReq` request. **[CORRECTED]** Fields are `credential` (required object) + optional `label`; there is **no `challenge_id`**:
```json
{ "credential": { /* RegistrationResponseJSON from Credential Manager */ }, "label": "Pixel 8" }
```
response (`WebAuthnRegisterFinishResp`): **[CORRECTED]** exactly `{ "credential_id": "..." }` — the schema has ONLY `credential_id`. There is **no `nickname` and no `created_at`** field. Any UI showing a label/created-date must source them locally (the web app does exactly this — it keeps label + an client-side `registered_at` in local React state) or from a separate list endpoint (none exists in this contract — see §6).

**authenticate/begin** — `WebAuthnAuthBeginReq` request (public/unauthenticated). **[CORRECTED]** `username` is the only field and is **required**; there is no `challenge_id` and no optional/usernameless variant:
```json
{ "username": "spannella@gmail.com" }
```
response (`WebAuthnAuthBeginResp`): **[CORRECTED]** same single-field `{ "options": { ... } }` shape (open object) — no `challenge_id` wrapper.

**authenticate/finish** — `WebAuthnAuthFinishReq` request. **[CORRECTED]** Fields are `username` (required) + `credential` (required object); **no `challenge_id`**:
```json
{ "username": "spannella@gmail.com", "credential": { /* AuthenticationResponseJSON */ } }
```
response (`WebAuthnAuthFinishResp`): **[CORRECTED]** `{ "status": "ok", "session_id": "..." }` — `status` is required (string), `session_id` is nullable/optional. The previous `{ auth_required, required_factors, session_established }` shape does NOT exist. The web client treats success as `status === "ok" && session_id` present, then calls `GET /ui/me` and navigates.

**Errors:** **[CORRECTED]** The OpenAPI declares ONLY `200` and `422 HTTPValidationError` for all four WebAuthn endpoints. `422` carries the standard FastAPI validation shape `{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }` (see `components.schemas.HTTPValidationError` / `ValidationError`). The 400/404/409/410 statuses the spec previously enumerated are NOT documented in the OpenAPI for these paths — treat them as **unverified assumptions** (the backend may still return them at runtime, but the contract does not promise them). Handle defensively: map any non-2xx via AND-027's `detail` normalizer (`src/api/client.ts: normalizeErrorDetail`, which handles `string | [{msg}] | {code,...}`). `401` on register triggers the AND-027 one-shot `POST /ui/session/refresh` + retry interceptor; a still-401 surfaces "Please sign in again." Challenges are single-use, so any failed `begin`/`finish` requires re-running the whole ceremony.

## 6. Data & State Management

- **No new persistent store on device.** Passkey private keys never touch the app; they live in the platform credential provider. The app persists nothing about the credential locally beyond what the backend returns for display.
- **Session/cookies:** entirely owned by AND-027's persistent cookie jar + DataStore-backed CSRF handling. This ticket adds no new DataStore keys.
- **Registered-credential list** (display of existing passkeys in Security settings): **[CORRECTED]** no WebAuthn list/delete endpoint exists in the OpenAPI (only the four begin/finish paths). The web reference (`WebAuthnDevices.tsx`) keeps the just-registered key in local component state only and does not fetch a list. So this ticket can show only the credential(s) registered in the current session (label held client-side + `credential_id` from `register/finish`); a persistent list requires a future backend endpoint. No Room entity is introduced.
- **UI state** is transient `StateFlow<PasskeyUiState>` held in the ViewModel. **[CORRECTED]** There is no `challenge_id` to retain — the contract has no such field; the server-issued challenge lives inside the opaque `options` blob and is consumed by Credential Manager within a single begin→finish round trip. No challenge or response JSON is logged or persisted.

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
| 422 validation (documented) | `begin`/`finish` 422 `HTTPValidationError` | "That took too long. Try again." / "Couldn't complete — please retry." (re-runs full begin→finish; challenges are single-use) |
| 409 already registered (assumed) | `finish` 409 — **[CORRECTED]** not in OpenAPI; defensive only | "This device already has a passkey for your account." |
| Other non-2xx (400/404/410, assumed) | **[CORRECTED]** not documented in OpenAPI; map via `normalizeErrorDetail` | Show normalized `detail`; no crash |

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
  - authenticate happy path (first-factor; **[CORRECTED]** no step-up/`challenge_id` path — that contract does not exist, see §5/FR-4).
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
3. **Step-up contract — RESOLVED (no step-up). [CORRECTED]** Verified against OpenAPI + web reference: WebAuthn is a standalone passwordless first-factor flow whose `authenticate/finish` returns `{status, session_id}` and establishes the session directly. It is not a `required_factors` MFA factor and does not feed `/ui/session/finalize`. No further backend confirmation needed for the documented contract; a future passkey-as-step-up feature would need a new backend contract + ticket.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Four endpoints exist at the stated paths/verb (`POST`).** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/webauthn/register/begin`, `POST /ui/webauthn/register/finish`, `POST /ui/webauthn/authenticate/begin`, `POST /ui/webauthn/authenticate/finish` (openapi.index.txt); frontend `src/api/endpoints/webauthn.ts` (`registerBegin`/`registerFinish`/`authenticateBegin`/`authenticateFinish`).
2. **`register/begin` request body.** Claimed `{ "nickname": ... }`. VERDICT: Corrected → optional `label` (nullable); web sends empty `{}`. SOURCE: schema `WebAuthnRegisterBeginReq` (only `label`, no required fields); `src/api/types.ts: WebAuthnRegisterBeginReq`; `src/pages/security/WebAuthnDevices.tsx` (`registerBegin({})`).
3. **`register/begin` / `authenticate/begin` response carries a `challenge_id` alongside `options`.** VERDICT: Corrected → response is a single `options` object only; no `challenge_id` on any WebAuthn schema. SOURCE: `WebAuthnRegisterBeginResp`, `WebAuthnAuthBeginResp` (each: `options` only, required); `src/api/types.ts` same.
4. **`options` is an opaque pass-through object.** VERDICT: Verified. SOURCE: `WebAuthnRegisterBeginResp.options` / `WebAuthnAuthBeginResp.options` declared `type: object, additionalProperties: true`; web forwards `beginResp.options` directly to `navigator.credentials.create/get` (`WebAuthnDevices.tsx`, `Login.tsx`).
5. **`register/finish` request body.** Claimed `{ challenge_id, credential }`. VERDICT: Corrected → `{ credential (required), label? }`; no `challenge_id`. SOURCE: `WebAuthnRegisterFinishReq`; `src/pages/security/WebAuthnDevices.tsx` (`registerFinish({ credential, label })`).
6. **`register/finish` response.** Claimed `{ credential_id, nickname, created_at }`. VERDICT: Corrected → `{ credential_id }` only. SOURCE: `WebAuthnRegisterFinishResp` (single required field `credential_id`); `src/api/types.ts: WebAuthnRegisterFinishResp`. Web synthesizes label + `registered_at` client-side (`WebAuthnDevices.tsx`).
7. **`authenticate/begin` request — username optional + optional `challenge_id`.** VERDICT: Corrected → `username` is the only field and is REQUIRED; no `challenge_id`. SOURCE: `WebAuthnAuthBeginReq` (`required: ["username"]`); `src/pages/Login.tsx` (button disabled until `webauthnUsername.trim()`).
8. **`authenticate/finish` request.** Claimed `{ challenge_id, credential }`. VERDICT: Corrected → `{ username (required), credential (required) }`; no `challenge_id`. SOURCE: `WebAuthnAuthFinishReq`; `src/pages/Login.tsx` (`authenticateFinish({ username, credential })`).
9. **`authenticate/finish` response.** Claimed `{ auth_required, required_factors, session_established }`. VERDICT: Corrected → `{ status (required string), session_id? }`. SOURCE: `WebAuthnAuthFinishResp`; `src/api/types.ts: WebAuthnAuthFinishResp`; success check `status === "ok" && session_id` in `src/pages/Login.tsx`.
10. **WebAuthn participates in MFA step-up via `required_factors` + `/ui/session/finalize` with a `challenge_id`.** VERDICT: Corrected (removed) → unsupported by the contract; WebAuthn is a standalone first-factor passwordless flow that establishes the session in its own `finish`. SOURCE: no `challenge_id`/factor field on any WebAuthn schema; `/ui/session/finalize` (`UiSessionFinalizeReq`) is fed by `sessionStart`→TOTP/SMS/email/recovery in `src/pages/Login.tsx` / `src/api/endpoints/auth.ts`, never by webauthn; `Login.tsx` models `webauthn` as its own `LoginStep`.
11. **After a successful assertion the app calls `GET /ui/me` then navigates.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/me`; `src/api/endpoints/auth.ts: getMe` (`/ui/me`); `src/pages/Login.tsx` (`getMe()` after success).
12. **Register endpoints are authenticated; transport = cookie session + `X-CSRF-Token`.** VERDICT: Corrected (incomplete) → transport also includes `Authorization: Bearer <accessToken>` and `credentials: include`; CSRF is read from the `ui_csrf` cookie into `X-CSRF-Token`. OpenAPI additionally documents register-endpoint params `user_sub` (query) + `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers). SOURCE: `src/api/client.ts` (Bearer header, `X-CSRF-Token` from `ui_csrf`, `X-IMPERSONATION-TOKEN`, `credentials: "include"`); OpenAPI params on `POST /ui/webauthn/register/begin|finish` (`user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`).
13. **Authenticate endpoints are public/unauthenticated.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/webauthn/authenticate/begin|finish` declare no `parameters` (no auth params); `webauthn.ts` comment "Authentication (public)".
14. **401 triggers one `POST /ui/session/refresh` + retry; no other auto-retry.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/refresh`; `src/api/client.ts` (`refreshSession()` → single retry on 401, `refreshPromise` guard).
15. **FastAPI `detail` may be `string | [{msg}] | {code,...}`; reuse AND-027 mapper.** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`.
16. **Documented error responses for the four endpoints are only `200` and `422`.** VERDICT: Verified (and the spec's 400/404/409/410 are now flagged as assumptions). SOURCE: OpenAPI responses for each path (`200`; `422:HTTPValidationError`); schema `HTTPValidationError`/`ValidationError`.
17. **Network failure surfaces as a non-crashing error (status 0).** VERDICT: Verified (web parallel). SOURCE: `src/api/client.ts` catch → `ApiError(0, "Network error")`. (Android equivalent is AND-027's `ApiResult.Error`; mapping is an AND-027 dependency.)
18. **Use AndroidX Credential Manager (`androidx.credentials` 1.3.0 + `credentials-play-services-auth`), `CreatePublicKeyCredentialRequest`/`GetPublicKeyCredentialOption` consuming/returning JSON strings.** VERDICT: Unverified-assumption (framework choice; not in repo sources). SOURCE: framework ref — Android developer docs, Credential Manager passkeys (developer.android.com/training/sign-in/passkeys) and `androidx.credentials` API reference.
19. **Platform passkeys require API >= 28 + a provider; capability gating.** VERDICT: Unverified-assumption (framework behavior). SOURCE: framework ref — Credential Manager docs (passkey/`createCredential` minimum effective support via Play services). Not derivable from backend/web sources.
20. **Digital Asset Links (`/.well-known/assetlinks.json`) on the RP host binding the package + SHA-256 fingerprints is required for platform passkeys.** VERDICT: Unverified-assumption (framework + external backend dependency). SOURCE: framework ref — Android passkeys / Digital Asset Links docs; RP host content not in repo.

### Corrections made

- §1 Overview, §5 contract: register transport is Bearer + session cookie + `X-CSRF-Token` (Bearer was missing); register-endpoint OpenAPI params (`user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`) documented; authenticate endpoints clarified as public.
- §5 DTO names replaced invented names with real schemas; `register/begin` body `nickname`→optional `label`; begin responses lost the nonexistent `challenge_id` wrapper (now `{options}` only); `register/finish` body now `{credential, label?}`, response now `{credential_id}` only (no `nickname`/`created_at`); `authenticate/begin` body `{username}` required; `authenticate/finish` body `{username, credential}` and response `{status, session_id?}` (replacing the nonexistent `{auth_required, required_factors, session_established}`).
- FR-3: `username` is required (not an optional hint); success keyed on `status === "ok" && session_id`.
- FR-4 / §13-Q3 / §11: removed the WebAuthn-as-MFA-step-up (`challenge_id` + `/ui/session/finalize`) design — not supported by the contract.
- §6: no list/delete endpoint exists; list is session-local; no `challenge_id` to retain.
- §7: error table re-tiered — only `401`/`422` are contract-documented; `400/404/409/410` marked defensive/assumed.

### Open assumptions

- Credential Manager API surface, minimum-supported API level for platform passkeys, and exact exception types (§7) are framework behavior, not derivable from the backend/web sources — verified only against Android docs, to be re-confirmed against the pinned `androidx.credentials` 1.3.0 at implementation time.
- `assetlinks.json` host/content and signing fingerprints are an external backend/ops dependency not present in any provided source (§13-Q1).
- The interior structure of the `options` object (exact `rp.id`, `authenticatorSelection`, `pubKeyCredParams`) is opaque in the OpenAPI (`additionalProperties: true`); the illustrative JSON in §5 is NOT a verified field list — only that `options` is forwarded verbatim is verified. Validate against a live sample (§13-Q2).
- Runtime non-2xx statuses beyond `200`/`422` (e.g. 401 on register, 409 duplicate) are not in the OpenAPI; handled defensively. To be confirmed against the live backend.
- The `user_sub`/`X-SESSION-ID` register params in OpenAPI vs the web client's Bearer/cookie usage are not fully reconciled in sources; the Android client should attach whatever AND-027's interceptor stack provides and confirm during integration.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit (no device); **emu35** = headless AVD `test35` (x86_64, Android 15/API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14/API 34, arm64-v8a) via adb. Credential Manager system UI, real biometrics/screen-lock, and ABI/API-34 behavior MUST run on **device**.

- **TC-AND-062-01** — Register happy path (repository, mocked CM). Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer queued: `register/begin`→`200 {options:{...}}`, `register/finish`→`200 {credential_id:"cred_1"}`; fake `PasskeyManager` returns `Success(registrationJson)`. Steps: call `PasskeyRepository.registerPasskey(activity, label="Pixel 8")`. Expected: `register/begin` POSTed (body `{}` or `{label}`), CM `createCredential` invoked with the begin `options`, `register/finish` POSTed with `{credential, label:"Pixel 8"}`, result `ApiResult.Success(RegisteredPasskey(credentialId="cred_1"))`; response has no `nickname`/`created_at` fields consumed. Traces: AC-1, AC-3.
- **TC-AND-062-02** — Options pass-through fidelity. Type: unit. Target: JVM. Preconditions: `register/begin` returns a non-trivial nested `options` (unicode, base64url, nested arrays). Steps: capture the `requestJson` handed to fake `PasskeyManager.createCredential`. Expected: forwarded JSON is semantically equal to the server `options` subtree (no Moshi field loss/reordering that changes values). Traces: AC-4.
- **TC-AND-062-03** — Authenticate happy path (first-factor). Type: contract/MockWebServer. Target: JVM. Preconditions: `authenticate/begin`→`200 {options}`, `authenticate/finish`→`200 {status:"ok", session_id:"sess_1"}`; fake CM returns `Success(assertionJson)`. Steps: `authenticateWithPasskey(activity, username="spannella@gmail.com")`. Expected: begin POST body `{username}`; finish POST body `{username, credential}`; result success with `status=="ok"` and `session_id` present; repository signals caller to proceed to `GET /ui/me`. Traces: AC-2.
- **TC-AND-062-04** — Auth finish non-ok status. Type: unit. Target: JVM. Preconditions: `authenticate/finish`→`200 {status:"failed"}` (no `session_id`). Steps: run auth flow. Expected: mapped to a typed error (not treated as success); no navigation; non-crashing user message. Traces: AC-2, AC-5.
- **TC-AND-062-05** — Cancellation never calls finish. Type: unit. Target: JVM. Preconditions: fake CM returns `Cancelled` (`GetCredentialCancellationException`). Steps: run register and auth flows. Expected: `*/finish` is NEVER requested (assert MockWebServer received only the `begin`); repository returns a `Cancelled`-mapped result; no persisted state. Traces: AC-5.
- **TC-AND-062-06** — Error-type mappings. Type: unit. Target: JVM. Preconditions: fake CM yields `NoCredential`, `Failure(PROVIDER)`, `Failure(DOM_EXCEPTION)` across runs. Steps: run auth/register. Expected: each maps to the §7 user message; none reach `finish`; none crash. Traces: AC-5.
- **TC-AND-062-07** — 401 on register triggers single refresh+retry. Type: contract/MockWebServer. Target: JVM. Preconditions: `register/begin`→`401`, then `POST /ui/session/refresh`→`200`, then retried `register/begin`→`200`. Steps: run register. Expected: exactly one refresh + one retry; success; assert `begin` is not retried more than once and `finish` is never auto-retried. A second consecutive 401 → terminal "Please sign in again." Traces: AC-3, AC-5.
- **TC-AND-062-08** — 422 validation handling. Type: contract/MockWebServer. Target: JVM. Preconditions: `authenticate/finish`→`422 {detail:[{loc,msg,type}]}`. Steps: run auth. Expected: `normalizeErrorDetail` produces a readable message; non-crashing; full ceremony must be re-run (challenge single-use); no auto-retry. Traces: AC-5.
- **TC-AND-062-09** — Request transport: headers/cookies/CSRF on register; public on authenticate. Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer records requests; AND-027 interceptor stack wired. Steps: run register then authenticate against recorded server. Expected: register requests carry `X-CSRF-Token` and session/Bearer credentials (whatever AND-027 attaches) and target exact paths/verb `POST`; authenticate requests succeed without requiring auth; bodies match §5 shapes. Traces: AC-3.
- **TC-AND-062-10** — Capability detection gating. Type: instrumented. Target: emu35 (supported) + **device** for the supported/API-34 path; an API-24 AVD (or Robolectric `Build.VERSION` shim on JVM) for the unsupported branch. Preconditions: GMS present on emu35/device. Steps: call `isPasskeySupported()`; render sign-in + settings. Expected: supported → passkey buttons shown; unsupported (API<28 / no provider) → registration entry hidden and sign-in passkey button omitted, no error toast. Traces: AC-6.
- **TC-AND-062-11** — Real register + authenticate on hardware (acceptance). Type: instrumented/e2e (manual-assisted). Target: **device** (MUST — real Credential Manager UI, screen-lock/biometric user verification, GMS passkey provider; cannot run on emulator reliably, and validates arm64/API-34). Preconditions: device has a screen lock + Google Password Manager; valid `assetlinks.json` published on the RP host for the build's SHA-256; backend live. Steps: from Security settings tap "Add a passkey", complete the system sheet; sign out; on sign-in enter username, tap "Sign in with a passkey", complete the sheet. Expected: register shows confirmation with `credential_id`; authenticate establishes session, `GET /ui/me` succeeds, app lands on authenticated graph. Traces: AC-1, AC-2.
- **TC-AND-062-12** — Flaky-host / offline path. Type: integration. Target: emu35 (airplane mode toggled) and/or MockWebServer with socket drop. Preconditions: network disabled during `begin`. Steps: trigger register and auth. Expected: non-crashing network error, generic retry message, no partial state, no auto-retry of begin/finish; recovers cleanly when network restored (fresh ceremony). Traces: AC-5.
- **TC-AND-062-13** — Security/no-PII logging. Type: unit. Target: JVM. Preconditions: capture Timber/log + telemetry sinks during full register+auth. Steps: run flows incl. errors. Expected: no `challenge`, `credential`/response JSON, `user.id`/user handle, or `session_id` appears in logs/telemetry; only event names + `PasskeyErrorType`/HTTP-status buckets. Traces: AC-7.
- **TC-AND-062-14** — Accessibility of passkey UI. Type: Compose-UI. Target: emu35 (functional) + **device** with TalkBack for the manual a11y pass. Preconditions: `AddPasskeyScreen` + `PasskeySignInButton` rendered. Steps: assert content descriptions, >=48dp touch targets, in-flight `disabled` + `stateDescription` announced; toggle RTL. Expected: buttons labeled and reachable; disabled (not just visually) while a ceremony is in flight so TalkBack can't double-activate; RTL layout correct. Traces: AC-5, AC-6.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 Register on supported device + confirmation | TC-01, TC-11 |
| AC-2 Authenticate establishes session → `/ui/me` → navigate | TC-03, TC-04, TC-11 |
| AC-3 `WebAuthnApi` paths/verbs/bodies/headers (CSRF, cookies) | TC-01, TC-07, TC-09 |
| AC-4 `options` reaches CM without field loss | TC-02 |
| AC-5 All §7 failure modes non-crashing; cancel never calls finish | TC-04, TC-05, TC-06, TC-07, TC-08, TC-12, TC-14 |
| AC-6 Unsupported devices hide entry points, no error | TC-10, TC-14 |
| AC-7 No challenge/credential/user identifier in logs/telemetry | TC-13 |
