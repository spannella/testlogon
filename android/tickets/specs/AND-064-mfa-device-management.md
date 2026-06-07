---
id: AND-064
title: MFA device management
milestone: M2
epic: E08
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-033, AND-077]
blocks: []
---

# AND-064 — MFA device management

## 1. Overview & Goal

Give the authenticated user a self-service screen to manage the multi-factor
authentication (MFA) devices/factors enrolled on their account: list currently
enrolled factors, enroll a new TOTP authenticator (showing the server-supplied QR
image and the manually-enterable secret, then confirming with **two consecutive**
generated codes), add SMS and email factors (request a code to the destination,
then confirm), and remove any enrolled factor by id (single-step + re-auth for
TOTP; a two-step begin/confirm code challenge for SMS/email).

> **REVIEW NOTE (2026-06-06):** Several API claims in the original draft were
> reconstructed from the backlog scope and were **wrong**. They have been
> corrected inline against `reference/openapi.index.txt`,
> `reference/openapi.pretty.json`, and the web client
> (`src/api/endpoints/account.ts`, `src/api/types.ts`). Key fixes: there is **no**
> unified `GET /ui/mfa/devices` (three per-type list endpoints instead); TOTP
> confirm needs `totp_code` **and** `totp_code2`; confirm responses return
> `{ok, recovery_codes[]}` not a device object; SMS/email begin uses
> `phone_e164`/`email` (not `destination`) and confirm uses `challenge_id` (not
> `device_id`); the QR is delivered server-side as `qr_code_uri` (no local ZXing
> generation); and SMS/email removal is a **two-step** begin/confirm flow. See §16. This is the *enrollment/management* counterpart to the
*challenge-time* MFA verification owned by AND-033/AND-034/035/036/037: those
tickets step a logging-in user through factors that already exist; AND-064 is how
those factors get created and deleted in the first place.

The feature lives in `feature-account` under Settings → Security → "Two-factor
authentication" (the Settings hub IA from AND-077 provides the entry point). It
talks to the backend exclusively through the `/ui/mfa/**/devices/**` endpoints,
reusing the cookie-based session, `X-CSRF-Token` interceptor, and 401-refresh
authenticator already in `core-network`. All factor network calls are issued
through the typed, `ApiResult<T>`-returning `MfaApiClient` extended in AND-033 —
this ticket adds the device-management methods to that surface and the UI/VM/repo
on top.

Success means: the user sees every enrolled factor; can enroll TOTP end-to-end
(begin → render server QR image + secret → enter **two** consecutive codes →
confirm → factor appears in list, recovery codes shown if returned); can add an
SMS factor and an email factor (begin → enter delivered code → confirm); can
remove any factor with confirmation (TOTP via re-entered code; SMS/email via a
delivered remove-challenge code); and every one of these paths is covered
by deterministic tests (MockWebServer + ViewModel/repository unit tests + a
Compose UI test).

## 2. Context & References

- Repo `spannella/testlogon`; Android app under `android/`; branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android` (used for every package
  below).
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, DataStore.
  minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Module layering: `feature-account` → `core-network`, `core-model`, `core-data`,
  `core-ui`, `core-testing`.
- **AND-033 (depends_on, hard blocker)** — owns `MfaApi`/`MfaApiClient` and the
  `Mfa*` DTOs plus `ApiErrorMapper` reuse. This ticket *extends* `MfaApi`/
  `MfaApiClient` with the `devices/**` methods; it MUST NOT redefine the existing
  challenge methods. If a device method requires a shape not yet present, add it
  in coordination with AND-033's package layout (`com.testlogon.android.core.network.auth`).
- **AND-077 (depends_on)** — Settings hub IA. Provides the "Security" section and
  the navigation entry that routes into this screen. AND-064 registers its route
  under the security subsection; it does not own the hub itself.
- Cross-cutting infra (assumed merged via AND-033's chain): persistent cookie jar,
  `CsrfInterceptor` (echoes `ui_csrf` → `X-CSRF-Token`), ~20s OkHttp timeouts, the
  single `401`→`POST /ui/session/refresh`→retry `Authenticator`, `ApiResult<T>`,
  and `safeApiCall`.
- Backend: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext,
  unreliable — design for timeouts, no auto-retry on mutations, offline states).
  Contract source of truth: `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- This screen requires an already-authenticated session (post-finalize). It is
  not part of the login challenge flow.

## 3. Functional Requirements

FR-1. On entry, the screen fetches enrolled factors from the **three per-type**
list endpoints and renders a loading state, then a unified list grouped by factor
type (TOTP | SMS | email): **CORRECTED** — there is no single `GET /ui/mfa/devices`.
The real endpoints are `GET /ui/mfa/totp/devices`, `GET /ui/mfa/sms/devices`,
`GET /ui/mfa/email/devices`, each returning `{ "devices": [...] }`. The client
issues all three (in parallel) and merges results, tagging each with its type
client-side (the wire objects carry no `type` field). Each row shows a `label`
(optional), the destination for SMS/email (`phone_e164` / `email` — the client
masks these for display; the wire is **not** pre-masked, contrary to the original
draft), an enabled/active indicator (`enabled`; SMS/email also expose `pending`),
and a created date parsed from `created_at` (**a numeric epoch**, not an ISO-8601
string). The id field name differs per type: `device_id` (TOTP),
`sms_device_id` (SMS), `email_device_id` (email).

FR-2. **Enroll TOTP**: an "Add authenticator app" action calls
`POST /ui/mfa/totp/devices/begin` (optional body `{label?}`), which returns
`{device_id, secret, qr_code_uri}`. **CORRECTED**: the response field is
`qr_code_uri` (a server-rendered QR **image** URI — the web client uses it
directly as an `<img src>`), **not** an `otpauth://` provisioning URI; there is no
`issuer`/`account` field. The screen displays the `qr_code_uri` image and the
base32 `secret` in copyable, grouped text with a "can't scan?" reveal. The user
then enters **two consecutive** 6-digit codes from their authenticator and the
screen calls `POST /ui/mfa/totp/devices/confirm` with
`{device_id, totp_code, totp_code2}`. **CORRECTED**: confirm requires `totp_code`
**and** `totp_code2` (two consecutive windows, both required per
`TotpDeviceConfirmReq`), and the success response is
`{ok: true, recovery_codes: string[]}` — **not** a device object. If
`recovery_codes` is non-empty the screen surfaces them once for the user to save.
On success the new factor appears in the list (via re-list).

> **NOTE:** `qr_code_uri` is rendered as an image; if it is an `otpauth://` value
> rather than a data/image URI, the client falls back to local QR rendering. This
> ambiguity is an open assumption (§16) since the OpenAPI response schema is `{}`
> (untyped) and only the web client's `<img src>` usage is observable.

FR-3. **Add SMS factor**: an "Add phone" action collects a phone number, calls
`POST /ui/mfa/sms/devices/begin` with **`{phone_e164, label?}`** → returns
**`{challenge_id, sent_to: string[], sms_device_id}`**. **CORRECTED**: request key
is `phone_e164` (not `destination`); the begin response carries a `challenge_id`
and `sent_to` is a **string array**; there are **no** `expires_in` /
`resend_available_in` fields in the observed contract. A code-entry step calls
`POST /ui/mfa/sms/devices/confirm` with **`{challenge_id, code}`** → returns
`{ok, sms_device_id, recovery_codes: string[]}`. **CORRECTED**: confirm keys on
`challenge_id`, not `device_id`. On success the factor appears in the list.

FR-4. **Add email factor**: an "Add email" action collects an email address, calls
`POST /ui/mfa/email/devices/begin` with **`{email, label?}`** → returns
`{challenge_id, sent_to: string[], email_device_id}`; confirm via
`POST /ui/mfa/email/devices/confirm` with **`{challenge_id, code}`** →
`{ok, email_device_id, recovery_codes: string[]}` — same shape family as SMS with
the email destination.

FR-5. **Remove factor**: **CORRECTED — removal is not uniform across factor
types.**
  - **TOTP**: single-step. After the destructive-action confirmation dialog, which
    also collects a current TOTP code, call
    `POST /ui/mfa/totp/devices/{device_id}/remove` with body **`{totp_code}`**
    (`TotpDeviceRemoveReq` requires `totp_code`; this is a re-auth, not a no-body
    call). Returns `{ok}`.
  - **SMS / email**: **two-step** challenge. Call
    `POST /ui/mfa/{sms|email}/devices/{id}/remove/begin` (no body) →
    `{challenge_id, sent_to: string[]}`; the user enters the delivered code; then
    call `POST /ui/mfa/{sms|email}/devices/remove/confirm` with
    **`{challenge_id, code}`** (`DeviceRemoveConfirmReq`) → `{ok}`.

  On success the row is removed.

FR-6. SMS/email begin steps surface a resend control. **CORRECTED**: the observed
begin response does **not** include `resend_available_in`/`expires_in`, so the
cooldown cannot be server-driven from those fields. The client applies a
fixed client-side cooldown (e.g. 30s) between resends; resend re-issues the `begin`
call. If the backend later returns cooldown metadata or a `429` with `retry_after`,
honor it (see §16 Open assumptions).

FR-7. Code-entry fields use the shared OTP composable (AND-020): 6-digit numeric
for SMS/email confirm and for SMS/email remove-confirm; **two** 6-digit fields for
TOTP confirm (`totp_code` then `totp_code2`, two consecutive codes) and one for
TOTP remove (`totp_code`). Auto-advance, paste support, and an inline "verifying"
state on submit.

FR-8. Errors at every step (invalid/expired code, throttled resend, network,
401-after-refresh-failure, 403 CSRF, 5xx) surface a non-blocking, retryable
message and leave the screen in a consistent state. Invalid-code errors show
`attempts_remaining` when provided.

FR-9. The enrollment flows are modeled as a multi-step state machine (idle →
begin-in-flight → awaiting-code → confirm-in-flight → done/error). Cancelling an
in-progress enrollment discards the pending `device_id` client-side; the
unconfirmed device is left to backend TTL expiry (no client cleanup call assumed).

FR-10. The TOTP secret/`otpauth` URI is shown only during enrollment, never
persisted to disk, and cleared from memory when the enrollment step completes or
is cancelled.

## 4. Technical Design

Module: `feature-account`. MVVM with Hilt; `StateFlow<UiState>`. Network methods
extend AND-033's `MfaApi`/`MfaApiClient`; mapping + orchestration live in
`core-data`; QR generation is a local concern in `core-ui`/`feature-account`.

```kotlin
// core-model — com.testlogon.android.core.model.mfa
enum class MfaFactorType(val wire: String) { TOTP("totp"), SMS("sms"), EMAIL("email") }

data class MfaDevice(
    val deviceId: String,             // device_id | sms_device_id | email_device_id (per type)
    val type: MfaFactorType,          // assigned client-side by which endpoint returned it
    val label: String?,               // "Authenticator app", "Personal phone", null
    val destination: String?,         // phone_e164 / email for sms/email; null for totp (client masks for display)
    val enabled: Boolean,             // wire `enabled`
    val pending: Boolean,             // wire `pending` (sms/email only; false for totp)
    val createdAt: Instant,           // parsed from numeric epoch `created_at`
    val lastUsedAt: Instant?,         // optional `last_used_at` (epoch)
)

data class TotpEnrollment(
    val deviceId: String,             // device_id
    val qrCodeUri: String,            // qr_code_uri — server QR IMAGE uri (sensitive, transient)
    val secret: String,               // base32, grouped for display (sensitive)
)

data class DeviceChallenge(           // sms/email begin AND remove/begin result
    val challengeId: String,          // challenge_id (confirm keys on THIS, not a device id)
    val sentTo: List<String>,         // sent_to: string[]
    val deviceId: String? = null,     // sms_device_id/email_device_id (begin only; absent on remove/begin)
)

data class EnrollResult(              // totp/sms/email confirm result
    val ok: Boolean,
    val deviceId: String?,            // sms_device_id/email_device_id when present
    val recoveryCodes: List<String>,  // shown once if non-empty
)
```

`MfaApi` additions (Retrofit; same package as AND-033):

```kotlin
// com.testlogon.android.core.network.auth.MfaApi (extended in coordination with AND-033)
// CORRECTED: three per-type list endpoints (no unified /ui/mfa/devices).
@GET("ui/mfa/totp/devices")
suspend fun listTotpDevices(): Response<TotpDeviceListDto>

@GET("ui/mfa/sms/devices")
suspend fun listSmsDevices(): Response<SmsDeviceListDto>

@GET("ui/mfa/email/devices")
suspend fun listEmailDevices(): Response<EmailDeviceListDto>

// TOTP enroll: begin takes optional {label}; confirm needs device_id + TWO codes.
@POST("ui/mfa/totp/devices/begin")
suspend fun beginTotpDevice(@Body body: TotpDeviceBeginReq): Response<TotpEnrollDto>

@POST("ui/mfa/totp/devices/confirm")
suspend fun confirmTotpDevice(@Body body: TotpDeviceConfirmReq): Response<EnrollResultDto>

// SMS/email enroll: begin keys on phone_e164/email; confirm keys on challenge_id.
@POST("ui/mfa/sms/devices/begin")
suspend fun beginSmsDevice(@Body body: SmsDeviceBeginReq): Response<DeviceChallengeDto>

@POST("ui/mfa/email/devices/begin")
suspend fun beginEmailDevice(@Body body: EmailDeviceBeginReq): Response<DeviceChallengeDto>

@POST("ui/mfa/{type}/devices/confirm")                // type = "sms" | "email"
suspend fun confirmCodeDevice(
    @Path("type") type: String,
    @Body body: DeviceConfirmReq,                      // {challenge_id, code}
): Response<EnrollResultDto>

// REMOVE — TOTP single-step (re-auth code), SMS/email two-step.
@POST("ui/mfa/totp/devices/{deviceId}/remove")
suspend fun removeTotpDevice(
    @Path("deviceId") deviceId: String,
    @Body body: TotpDeviceRemoveReq,                  // {totp_code}
): Response<OkDto>

@POST("ui/mfa/{type}/devices/{deviceId}/remove/begin") // type = "sms" | "email"
suspend fun beginRemoveCodeDevice(
    @Path("type") type: String,
    @Path("deviceId") deviceId: String,
): Response<DeviceChallengeDto>                        // {challenge_id, sent_to[]}

@POST("ui/mfa/{type}/devices/remove/confirm")          // type = "sms" | "email"
suspend fun confirmRemoveCodeDevice(
    @Path("type") type: String,
    @Body body: DeviceConfirmReq,                      // {challenge_id, code}
): Response<OkDto>
```

`MfaApiClient` façade additions (typed, `ApiResult`-returning, via `safeApiCall`):

```kotlin
suspend fun listTotpDevices(): ApiResult<TotpDeviceListDto>
suspend fun listSmsDevices(): ApiResult<SmsDeviceListDto>
suspend fun listEmailDevices(): ApiResult<EmailDeviceListDto>
suspend fun beginTotpDevice(label: String? = null): ApiResult<TotpEnrollDto>
suspend fun confirmTotpDevice(deviceId: String, totpCode: String, totpCode2: String): ApiResult<EnrollResultDto>
suspend fun beginCodeDevice(type: MfaFactorType, destination: String, label: String? = null): ApiResult<DeviceChallengeDto>
suspend fun confirmCodeDevice(type: MfaFactorType, challengeId: String, code: String): ApiResult<EnrollResultDto>
suspend fun removeTotpDevice(deviceId: String, totpCode: String): ApiResult<OkDto>
suspend fun beginRemoveCodeDevice(type: MfaFactorType, deviceId: String): ApiResult<DeviceChallengeDto>
suspend fun confirmRemoveCodeDevice(type: MfaFactorType, challengeId: String, code: String): ApiResult<OkDto>
```

Repository in `core-data`:

```kotlin
// com.testlogon.android.core.data.mfa
class MfaDeviceRepository @Inject constructor(
    private val mfa: MfaApiClient,
    private val dispatchers: AppDispatchers,
) {
    // list() fans out to the THREE per-type endpoints, merges + tags type, sorts.
    suspend fun list(): ApiResult<List<MfaDevice>>
    suspend fun beginTotp(label: String? = null): ApiResult<TotpEnrollment>
    suspend fun confirmTotp(deviceId: String, totpCode: String, totpCode2: String): ApiResult<EnrollResult>
    suspend fun beginCode(type: MfaFactorType, destination: String, label: String? = null): ApiResult<DeviceChallenge>
    suspend fun confirmCode(type: MfaFactorType, challengeId: String, code: String): ApiResult<EnrollResult>
    suspend fun removeTotp(deviceId: String, totpCode: String): ApiResult<Unit>
    suspend fun beginRemoveCode(type: MfaFactorType, deviceId: String): ApiResult<DeviceChallenge>
    suspend fun confirmRemoveCode(type: MfaFactorType, challengeId: String, code: String): ApiResult<Unit>
}
```

QR rendering. **CORRECTED**: the backend returns `qr_code_uri`, which the web
client consumes directly as an `<img src>` (`src/pages/security/MfaDevices.tsx`).
The most likely shape is a **data/image URI** rendered as-is — in which case the
Android client just displays it (decode base64 PNG to a bitmap, or load via Coil),
with **no ZXing dependency required**. A `QrCodeGenerator` (ZXing core) is retained
**only as a fallback** for the case where `qr_code_uri` turns out to carry an
`otpauth://` value instead of an image (unverifiable from the untyped `{}` OpenAPI
response — see §16 Open assumptions). No network call is made to render the QR; the
QR data never leaves the device. If the fallback path is confirmed unnecessary,
drop the ZXing dependency.

ViewModel:

```kotlin
@HiltViewModel
class MfaDevicesViewModel @Inject constructor(
    private val repo: MfaDeviceRepository,
) : ViewModel() {

    data class UiState(
        val isLoading: Boolean = false,
        val devices: List<MfaDevice> = emptyList(),
        val enroll: EnrollState = EnrollState.None,
        val pendingRemoveId: String? = null,        // confirm dialog target
        val removingIds: Set<String> = emptySet(),
        val error: UiError? = null,
    )

    sealed interface EnrollState {
        data object None : EnrollState
        data class Totp(
            val step: Step,
            val enrollment: TotpEnrollment? = null,  // present in AwaitingCode (qrCodeUri + secret)
            val code: String = "",                   // totp_code
            val code2: String = "",                  // totp_code2 (CORRECTED: two codes required)
            val recoveryCodes: List<String> = emptyList(), // shown once after confirm
            val attemptsRemaining: Int? = null,
        ) : EnrollState
        data class Code(
            val type: MfaFactorType,                 // SMS | EMAIL
            val step: Step,
            val destination: String = "",            // phone_e164 / email
            val challenge: DeviceChallenge? = null,  // holds challenge_id used by confirm
            val code: String = "",
            val resendInSeconds: Int = 0,            // client-side cooldown (no server field)
            val recoveryCodes: List<String> = emptyList(),
            val attemptsRemaining: Int? = null,
        ) : EnrollState
    }
    enum class Step { Collecting, BeginInFlight, AwaitingCode, ConfirmInFlight }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load()
    fun startTotpEnroll()
    fun startCodeEnroll(type: MfaFactorType)
    fun onDestinationChange(value: String)
    fun submitBegin()                 // sms/email begin
    fun onCodeChange(value: String)
    fun submitConfirm()               // totp or code confirm (dispatches on EnrollState)
    fun resend()
    fun cancelEnroll()                // clears enrollment + secret from memory
    fun requestRemove(deviceId: String)   // opens confirm dialog (RemoveState below)
    fun onRemoveCodeChange(value: String) // totp_code (TOTP) or delivered code (sms/email)
    fun confirmRemove()                   // CORRECTED: TOTP -> single remove({totp_code});
                                          // SMS/email -> remove/begin then remove/confirm({challenge_id, code})
    fun dismissRemove()
    fun dismissError()
}

// CORRECTED: removal is no longer a single confirm-and-call. Model it explicitly:
//   sealed interface RemoveState {
//     data object None
//     data class Totp(val deviceId: String, val code: String = "", val inFlight: Boolean = false)
//     data class Code(val type: MfaFactorType, val deviceId: String, val step: Step,
//                     val challenge: DeviceChallenge? = null, val code: String = "")
//   }
// The optimistic-hide behavior in §6 still applies once the final (confirm) call succeeds.
```

Composables (Material 3, `core-ui` building blocks):

```kotlin
@Composable
fun MfaDevicesRoute(viewModel: MfaDevicesViewModel = hiltViewModel(), onBack: () -> Unit)

@Composable
fun MfaDevicesScreen(
    state: MfaDevicesViewModel.UiState,
    onStartTotp: () -> Unit,
    onStartCode: (MfaFactorType) -> Unit,
    onDestinationChange: (String) -> Unit,
    onSubmitBegin: () -> Unit,
    onCodeChange: (String) -> Unit,
    onSubmitConfirm: () -> Unit,
    onResend: () -> Unit,
    onCancelEnroll: () -> Unit,
    onRemove: (String) -> Unit,
    onConfirmRemove: () -> Unit,
    onDismissRemove: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)
```

Enrollment is presented as a `ModalBottomSheet`/full-screen dialog driven by
`EnrollState`; the TOTP variant renders `TotpEnrollContent` (QR + secret +
OTP field), the code variant renders `CodeEnrollContent` (destination field →
OTP field + resend). Navigation: register route `accountMfaDevices` in the account
nav graph, reached from AND-077's Security section.

A resend countdown is driven by a `viewModelScope` ticker that decrements
`resendInSeconds`/`resendAvailableIn` once per second while `> 0`; the resend
control is enabled only at `0`.

## 5. API Contract

Base URL `http://18.222.237.167:8000/`. All calls carry session cookies +
`X-CSRF-Token` (auto). Mutations are `POST`; lists are `GET`. **CORRECTED**: there
is no single `{type}` device-management surface — endpoints are spelled out
per-type below, verified against `reference/openapi.index.txt` and the web client
(`src/api/endpoints/account.ts`, `src/api/types.ts`). Moshi DTOs map snake_case via
`@Json(name=...)` and tolerate unknown keys.

> **WIRE-CONTRACT CAVEAT:** The OpenAPI **response** schemas for every one of these
> operations are `{}` (untyped) — only `200` and `422` are declared (no `400`/`409`/
> `429`). The response field names below come from the **web client's TypeScript
> types** (`types.ts`), the only observable source of truth for response shapes;
> request shapes are confirmed against the named OpenAPI request schemas
> (`TotpDeviceConfirmReq`, `SmsDeviceBeginReq`, etc.).

**List (THREE endpoints, merged client-side)** —
`GET /ui/mfa/totp/devices`, `GET /ui/mfa/sms/devices`, `GET /ui/mfa/email/devices`,
each → 200 `{ "devices": [...] }`. Per-type element shapes (note `created_at` is a
**numeric epoch**, and the id key differs per type; there is no `type` or `verified`
field):
```json
// totp:  { "device_id": "dev_totp_01", "label": "Authenticator app",
//          "enabled": true, "created_at": 1746180000, "last_used_at": 1746200000 }
// sms:   { "sms_device_id": "dev_sms_07", "phone_e164": "+15551231234",
//          "label": "Personal phone", "enabled": true, "pending": false,
//          "created_at": 1746902520, "last_used_at": null }
// email: { "email_device_id": "dev_em_03", "email": "user@example.com",
//          "label": null, "enabled": true, "pending": false,
//          "created_at": 1746902520, "last_used_at": null }
```

**TOTP begin** — `POST /ui/mfa/totp/devices/begin`, body `{ "label": "…" }`
(optional) → 200:
```json
{ "device_id": "dev_totp_02", "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_uri": "data:image/png;base64,iVBORw0KGgo…" }
```
(`qr_code_uri` is a server-rendered QR image URI, not `otpauth://`; no
`issuer`/`account`.)

**TOTP confirm** — `POST /ui/mfa/totp/devices/confirm`:
```json
{ "device_id": "dev_totp_02", "totp_code": "482915", "totp_code2": "194820" }
```
→ 200: `{ "ok": true, "recovery_codes": ["…", "…"] }`
(CORRECTED: requires `totp_code` AND `totp_code2`; returns ok + recovery codes, not
a device object.)

**SMS begin** — `POST /ui/mfa/sms/devices/begin`:
```json
{ "phone_e164": "+15551234567", "label": "My phone" }
```
→ 200: `{ "challenge_id": "chal_…", "sent_to": ["+1•••••4567"], "sms_device_id": "dev_sms_08" }`

**Email begin** — `POST /ui/mfa/email/devices/begin`:
```json
{ "email": "user@example.com", "label": "Work email" }
```
→ 200: `{ "challenge_id": "chal_…", "sent_to": ["u•••@example.com"], "email_device_id": "dev_em_04" }`

**SMS/email confirm** — `POST /ui/mfa/{sms|email}/devices/confirm`:
```json
{ "challenge_id": "chal_…", "code": "204815" }
```
→ 200: `{ "ok": true, "sms_device_id": "dev_sms_08", "recovery_codes": [] }`
(email returns `email_device_id`). CORRECTED: confirm keys on `challenge_id`, not
`device_id`.

**Remove — TOTP (single-step, re-auth)** —
`POST /ui/mfa/totp/devices/{device_id}/remove`, body `{ "totp_code": "482915" }`
→ 200 `{ "ok": true }`. CORRECTED: TOTP remove requires a `totp_code` body
(`TotpDeviceRemoveReq`), it is **not** a no-body call.

**Remove — SMS/email (two-step challenge)** —
1. `POST /ui/mfa/{sms|email}/devices/{id}/remove/begin` (no body) → 200
   `{ "challenge_id": "chal_…", "sent_to": ["+1•••••4567"] }`
2. `POST /ui/mfa/{sms|email}/devices/remove/confirm`, body
   `{ "challenge_id": "chal_…", "code": "551133" }` → 200 `{ "ok": true }`
   (`DeviceRemoveConfirmReq`). CORRECTED: there is **no**
   `POST /ui/mfa/{sms|email}/devices/{id}/remove` single-step endpoint.

**Errors** (FastAPI `detail` polymorph: string | `[{msg}]` | `{code,...}`,
normalized by `ApiErrorMapper`). **CORRECTED/UNVERIFIED**: OpenAPI declares only
`200` and `422` for these ops; the `400`/`409`/`429` shapes below are *assumed*
conventions (consistent with AND-033's mapper) and are **not** in the contract —
treat them as defensive handling, not guarantees:
- `422` validation (bad phone/email) → `{ "detail": [{ "loc": ["body","phone_e164"], "msg": "invalid phone number", "type": "value_error" }] }` (VERIFIED shape — `HTTPValidationError`).
- `400` invalid/expired confirm code → assumed `{ "detail": { "code": "mfa_invalid_code", "attempts_remaining": 2 } }` (UNVERIFIED).
- `409` already-enrolled / duplicate destination → assumed `{ "detail": { "code": "mfa_device_exists" } }` (UNVERIFIED).
- `429` resend throttled → assumed `{ "detail": { "code": "mfa_resend_throttled", "retry_after": 22 } }` (UNVERIFIED).
- `401` → transparent refresh-once-then-retry via the shared `Authenticator`
  (VERIFIED against `src/api/client.ts`: 401 → `POST /ui/session/refresh` → retry once).

DTOs (`com.testlogon.android.core.network.auth.dto`, Moshi codegen):
```kotlin
// ── List DTOs (one per type; created_at is epoch seconds → Long) ──
@JsonClass(generateAdapter = true)
data class TotpDeviceListDto(val devices: List<TotpDeviceDto> = emptyList())
@JsonClass(generateAdapter = true)
data class SmsDeviceListDto(val devices: List<SmsDeviceDto> = emptyList())
@JsonClass(generateAdapter = true)
data class EmailDeviceListDto(val devices: List<EmailDeviceDto> = emptyList())

@JsonClass(generateAdapter = true)
data class TotpDeviceDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,        // epoch seconds
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class SmsDeviceDto(
    @Json(name = "sms_device_id") val deviceId: String,
    @Json(name = "phone_e164") val phoneE164: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "pending") val pending: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class EmailDeviceDto(
    @Json(name = "email_device_id") val deviceId: String,
    @Json(name = "email") val email: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "pending") val pending: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class TotpEnrollDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "secret") val secret: String,
    @Json(name = "qr_code_uri") val qrCodeUri: String,
)

@JsonClass(generateAdapter = true)
data class DeviceChallengeDto(                                  // begin & remove/begin
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: List<String> = emptyList(),
    @Json(name = "sms_device_id") val smsDeviceId: String? = null,
    @Json(name = "email_device_id") val emailDeviceId: String? = null,
)

@JsonClass(generateAdapter = true)
data class EnrollResultDto(                                     // totp/sms/email confirm
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "sms_device_id") val smsDeviceId: String? = null,
    @Json(name = "email_device_id") val emailDeviceId: String? = null,
    @Json(name = "recovery_codes") val recoveryCodes: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class OkDto(@Json(name = "ok") val ok: Boolean = false)

// ── Request DTOs (names verified against OpenAPI request schemas) ──
@JsonClass(generateAdapter = true)
data class TotpDeviceBeginReq(@Json(name = "label") val label: String? = null)

@JsonClass(generateAdapter = true)
data class TotpDeviceConfirmReq(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "totp_code") val totpCode: String,
    @Json(name = "totp_code2") val totpCode2: String,
)

@JsonClass(generateAdapter = true)
data class TotpDeviceRemoveReq(@Json(name = "totp_code") val totpCode: String)

@JsonClass(generateAdapter = true)
data class SmsDeviceBeginReq(
    @Json(name = "phone_e164") val phoneE164: String,
    @Json(name = "label") val label: String? = null,
)

@JsonClass(generateAdapter = true)
data class EmailDeviceBeginReq(
    @Json(name = "email") val email: String,
    @Json(name = "label") val label: String? = null,
)

@JsonClass(generateAdapter = true)
data class DeviceConfirmReq(                                    // confirm + remove/confirm
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
)
```

## 6. Data & State Management

- **No persistence of factor data, secrets, or codes.** The device list is
  security-sensitive and must reflect live server state, so it is fetched on
  demand (three parallel per-type GETs, merged) and held only in `StateFlow`
  memory; no Room/DataStore caching. The TOTP `secret`/`qr_code_uri` and any
  returned `recovery_codes` live only inside `EnrollState.Totp` for the duration of
  the enrollment sheet and are dropped on `cancelEnroll`, successful confirm
  dismissal, or process death.
- The only persisted state relied upon is the OkHttp cookie jar (session +
  `ui_csrf`), owned by the core-network tickets; AND-064 neither reads nor writes
  auth/DataStore state.
- **Optimistic remove**: on confirmed remove, add the id to `removingIds` and hide
  the row; on API success drop it permanently; on failure re-insert at its
  original index and show an error. Enrollment is *not* optimistic — the new
  factor is added to the list only from the confirm response (or by re-`list()`).
- After a successful enroll/remove, the VM re-fetches `list()` to reconcile with
  the server (source of truth), avoiding drift from partial/edge responses.
- The DTO→domain mapper parses `created_at`/`last_used_at` as a **numeric epoch
  (seconds)** to `Instant` (CORRECTED from ISO-8601), assigns `MfaFactorType` by
  **which endpoint** returned the element (the wire carries no `type` field — three
  typed DTOs are merged), and sorts the merged list (TOTP first, then by
  `createdAt` desc). Unknown/garbled elements are dropped rather than crashing
  (forward-compat). The destination shown for SMS/email is masked **client-side**
  from `phone_e164`/`email` (the list wire is not pre-masked; only the begin/
  remove-begin `sent_to` arrays are masked server-side).

## 7. Error Handling & Resilience

- Every call funnels through `safeApiCall` → `ApiResult.Success` /
  `ApiResult.HttpError(status, ApiError)` / `ApiResult.NetworkError`. No exception
  escapes to the UI.
- **Idempotency / retries**: the three list GETs (`GET /ui/mfa/totp|sms|email/
  devices`) are idempotent reads and MAY use the existing bounded-backoff GET
  retry; a partial failure (one of three) is surfaced as a degraded/stale list, not
  a full blank. All `begin`/`confirm`/`remove`/`remove/begin`/`remove/confirm`
  calls are non-idempotent mutating POSTs and MUST issue exactly one attempt — no
  auto-retry (no duplicate enrollments, no double SMS sends).
- **Invalid/expired code** (`400 mfa_invalid_code`): keep the user on the
  awaiting-code step, clear the field, show the message and `attempts_remaining`
  when present; expired-code maps to a "code expired — resend" affordance.
- **Throttled resend** (`429 mfa_resend_throttled` with `retry_after`): disable
  resend and start/extend the cooldown countdown; do not auto-retry.
- **Duplicate** (`409 mfa_device_exists`): surface "This factor is already added"
  and return to the list.
- **401**: shared `Authenticator` does one `POST /ui/session/refresh` then retries;
  if refresh fails, map to "Session expired" and route to re-auth (delegated, not
  re-implemented here).
- **403 (CSRF)**: surface "Couldn't verify your session, try again"; retry re-reads
  the `ui_csrf` cookie via the existing interceptor.
- **Offline / timeout** (~20s): show an offline/retry state; keep the
  last-rendered list (marked stale) rather than blanking. In-flight enrollment
  shows a retryable error without losing entered data where safe.
- **Cancel during enroll**: discards the pending `device_id` client-side; no
  cleanup call is assumed (backend TTL handles unconfirmed devices).

## 8. Security & Privacy

- **Secrets never logged, never persisted**: TOTP `secret`, `qr_code_uri`,
  `recovery_codes`, and all confirm/remove codes (`totp_code`, `totp_code2`,
  `code`) are secrets. OkHttp body logging is prohibited for `/ui/mfa/**/devices/**`
  in every build type (BASIC-level method+URL+status, or a redacting interceptor —
  consistent with AND-033). The `secret`/`qr_code_uri`/recovery codes are held only
  in transient VM state and cleared per §6/FR-10.
- `device_id` and masked destinations are sensitive — redact from telemetry and
  crash breadcrumbs (§10).
- The QR is supplied by the backend as `qr_code_uri` and rendered in-app; it is not
  sent to any third party or external image service. If a local-generation fallback
  is needed (see §4), the QR data still never leaves the device.
- Consider setting `FLAG_SECURE` on the enrollment sheet/screen to block
  screenshots of the QR/secret (open question Q3); at minimum the secret is not
  written to clipboard history beyond the user's explicit copy action.
- **CSRF mandatory** on every mutating POST (`X-CSRF-Token` from `ui_csrf`),
  asserted in tests.
- Dev backend is plaintext HTTP → codes/secret traverse the wire unencrypted *in
  dev only*; production MUST be HTTPS. This screen adds no new cleartext exemption
  beyond the existing dev `network_security_config` (enforcement owned by the
  manifest/build tickets).
- All actions require an authenticated session; the screen is only reachable
  behind auth-gated routing.

## 9. Accessibility & i18n

- All strings in `feature-account` `strings.xml`; no hardcoded text. Dates via a
  locale-aware formatter.
- The QR `Image` has a `contentDescription` and is paired with the always-available
  text secret so non-sighted users can enroll without scanning ("Or enter this
  code in your authenticator app: …", read in grouped, speakable chunks).
- OTP entry uses the AND-020 accessible OTP composable: labeled fields,
  `KeyboardType.NumberPassword`, per-digit and aggregate TalkBack semantics, and
  error text announced via `liveRegion`.
- Each device row has a merged `contentDescription` (type, label, masked
  destination, created date); the remove button has an explicit description
  ("Remove <label>"). Confirmation dialogs are focus-trapped and announceable.
- Touch targets ≥ 48dp; supports dynamic font scaling, dark theme (Material 3),
  and RTL (start/end paddings, no hardcoded left/right). Phone/email inputs use the
  correct `KeyboardType` and autofill hints.

## 10. Telemetry & Logging

- Structured events via the shared analytics façade — **no PII, no secrets, no
  codes, no `device_id`, no destinations**:
  `mfa_device_list_viewed { count }`,
  `mfa_device_enroll_start { type }`,
  `mfa_device_enroll_result { type, success }`,
  `mfa_device_remove { type, success }`,
  `mfa_device_error { type, code }` (where `code` is the non-secret `ApiError.code`
  enum), `mfa_device_resend { type }`.
- Logging via the project Timber wrapper; debug-only request/response *metadata*,
  never bodies, codes, secrets, cookies, or `X-CSRF-Token`. Error logs record the
  normalized `ApiError.code` + HTTP status only.
- These events feed the account-security funnel owned by the telemetry ticket;
  AND-064 only emits them.

## 11. Testing Strategy

All tests deterministic (no real network). MockWebServer + fixtures from
`core-testing`.

1. **API/DTO (core-network)**: enqueue 200 fixtures for the three list endpoints,
   `beginTotpDevice`, `confirmTotpDevice`, `beginSmsDevice`/`beginEmailDevice`,
   `confirmCodeDevice`, `removeTotpDevice`, `beginRemoveCodeDevice`,
   `confirmRemoveCodeDevice`; assert `RecordedRequest` path/verb (e.g.
   `/ui/mfa/totp/devices/begin` POST, `/ui/mfa/totp/devices/dev_totp_02/remove`
   POST, `/ui/mfa/sms/devices/dev_sms_08/remove/begin` POST,
   `/ui/mfa/sms/devices/remove/confirm` POST), and that request bodies contain
   exactly the **corrected** keys: `phone_e164`/`email` (+ optional `label`) on
   begin; `device_id`+`totp_code`+`totp_code2` on TOTP confirm; `challenge_id`+
   `code` on SMS/email confirm and remove/confirm; `totp_code` on TOTP remove.
   Assert `X-CSRF-Token` + `Cookie` present on every mutation. Assert DTOs
   (de)serialize fixtures field-by-field (including numeric-epoch `created_at`),
   tolerate unknown keys, and round-trip.
2. **No-retry guarantee**: enqueue `429`→`200` for a `begin`; assert exactly one
   recorded request (mutations not retried). Confirm the list GETs MAY retry per
   the GET policy.
3. **Repository (core-data)**: DTO→domain mapping (type enum, `Instant` parsing,
   sort order, unknown-type drop); error-envelope mapping for the three `detail`
   shapes including `attempts_remaining`/`retry_after`.
4. **ViewModel unit tests** (Turbine + coroutine test rule):
   - `load()` populates and sorts the list.
   - TOTP enroll happy path: `startTotpEnroll` → `BeginInFlight` → `AwaitingCode`
     with `enrollment` present (`secret`/`qrCodeUri` in state) → enter two codes →
     `submitConfirm` → factor in list, recovery codes surfaced, `EnrollState.None`,
     secret/recovery cleared.
   - SMS enroll happy path: destination → `submitBegin` → `AwaitingCode` →
     `submitConfirm` → factor in list. Same for email.
   - invalid code keeps the awaiting-code step and surfaces `attemptsRemaining`.
   - resend gating: resend disabled until countdown hits 0; `429` extends cooldown.
   - `cancelEnroll` clears the pending `device_id` and the secret from state.
   - remove: optimistic hide → success drops row; failure restores at original
     index; no API call without confirmation; dismiss makes no call.
5. **Compose UI test (core-testing + Compose rule)** — satisfies the source AC:
   - TOTP enroll renders the QR image and the copyable secret; entering a code and
     confirming shows the new factor in the list.
   - Adding an SMS factor and an email factor (begin → enter code → confirm) each
     adds a row.
   - Removing a factor shows the confirm dialog and, on confirm, removes the row.
6. Coverage focus matches Acceptance Criteria; ≥85% line coverage on the new
   `core-data`/VM/mapper code and the added `MfaApi`/`MfaApiClient` methods.

## 12. Dependencies & Sequencing

- **Depends on AND-033** (hard blocker): `MfaApi`/`MfaApiClient`, `Mfa*` DTOs,
  `ApiErrorMapper`, `safeApiCall`/`ApiResult`, and the MockWebServer harness. This
  ticket extends — does not duplicate — that surface, coordinated within
  `com.testlogon.android.core.network.auth`.
- **Depends on AND-077** (Settings hub IA): provides the Security section entry
  point and navigation host into `accountMfaDevices`.
- **Transitively relies on** the cookie jar, CSRF interceptor, 401-refresh
  authenticator (core-network chain, assumed merged via AND-033), the AND-020 OTP
  composable, and AND-019 Material 3 theme / AND-021 state composables.
- **Possible new dependency**: ZXing core (`com.google.zxing:core`) — needed
  **only** if `qr_code_uri` is an `otpauth://` value requiring local QR generation.
  If it is a data/image URI (expected, per the web client's `<img src>` usage),
  no new dependency is added; the existing image stack (e.g. Coil) renders it.
- **Blocks**: none currently tracked.
- **Sequencing**: extend `MfaApi`/`MfaApiClient` + DTOs (tested) → repository +
  mapper (tested) → ViewModel state machine (tested) → Compose screen + enroll
  sheets + QR + nav wiring → Compose UI test.

## 13. Risks & Open Questions

- **R1 — Exact device endpoints/shapes** — *RESOLVED in this review* against
  `openapi.index.txt` + `src/api/endpoints/account.ts` + `src/api/types.ts`. Net
  corrections: per-type list endpoints (no `/ui/mfa/devices`); `qr_code_uri` (image)
  not `otpauth_uri`; `phone_e164`/`email` not `destination`; confirm keys on
  `challenge_id` (sms/email) / `device_id` (totp); TOTP confirm needs two codes;
  SMS/email removal is two-step. Remaining unknown: response *types* are `{}` in
  OpenAPI; field names taken from the web client (see §16 Open assumptions).
- **R2 — TOTP confirm requirement** — *RESOLVED*: confirm is required and takes
  `device_id` + `totp_code` + `totp_code2`; it returns `{ok, recovery_codes[]}`
  (not a device object). Whether the device is "active" is observed via a re-list
  (`enabled: true`).
- **R3 — Screenshot protection**: decide whether to apply `FLAG_SECURE` to the
  enrollment sheet to hide the QR/secret from screenshots/recents.
- **R4 — Duplicate/last-factor policy**: does the backend block removing the last
  remaining factor or duplicate destinations (`409 mfa_device_exists`)? If
  last-factor removal is blocked, surface that error; if not, this client does not
  enforce a minimum.
- **R5 — Resend metadata variance**: `resend_available_in`/`expires_in` presence
  may vary by factor; defaulted to `0` to avoid deserialization failure — verify
  with fixtures.
- **R6 — Unverified-device cleanup**: assumed handled by backend TTL on cancel; if
  the API exposes a cancel/abort call, wire `cancelEnroll` to it.
- **R7 — Dev host instability**: flaky 5xx/timeouts during live validation; rely on
  MockWebServer for deterministic CI and treat live calls as smoke-only.

## 14. Acceptance Criteria

AC-1. The screen fetches `GET /ui/mfa/totp/devices`, `GET /ui/mfa/sms/devices`,
`GET /ui/mfa/email/devices`, merges them, and renders every enrolled factor
typed/grouped with label, client-masked destination, and created date (from numeric
epoch); loading/empty/error/partial states present. (MockWebServer + Compose UI
test.)

AC-2. **TOTP enrollment** works end-to-end: `POST /ui/mfa/totp/devices/begin`
returns `secret` + `qr_code_uri`; the screen renders the QR image and the copyable
secret; entering **two consecutive** codes and `POST /ui/mfa/totp/devices/confirm`
with `{device_id, totp_code, totp_code2}` succeeds, returns `{ok, recovery_codes}`,
recovery codes are surfaced once, and the factor then appears in the list.
(Satisfies source AC: "User can enroll a TOTP device (QR/secret)." — ViewModel +
Compose UI test.)

AC-3. **Add SMS factor** works: `POST /ui/mfa/sms/devices/begin` with
`{phone_e164}` → confirm with `POST /ui/mfa/sms/devices/confirm`
`{challenge_id, code}` → factor appears. (Satisfies "add SMS devices (tested)".)

AC-4. **Add email factor** works via the analogous `email/devices/begin` with
`{email}` → `email/devices/confirm` with `{challenge_id, code}` → factor appears.
(Satisfies "add email devices (tested)".)

AC-5. **Remove** removes the row after explicit confirmation; failure rolls it
back. TOTP: `POST /ui/mfa/totp/devices/{device_id}/remove` with `{totp_code}`.
SMS/email: two-step `POST /ui/mfa/{type}/devices/{id}/remove/begin` then
`POST /ui/mfa/{type}/devices/remove/confirm` with `{challenge_id, code}`.
(Satisfies "remove SMS+email devices (tested)" — MockWebServer + ViewModel test.)

AC-6. Every mutating call carries `X-CSRF-Token` + session cookies and is issued
exactly once (no auto-retry); the list GET may retry per the GET backoff policy.
(MockWebServer test.)

AC-7. Invalid/expired code, `429` throttled resend (with cooldown), `409`
duplicate, network/401/403/5xx all surface retryable messages and leave the
screen consistent; `attempts_remaining` shown when provided. (MockWebServer +
ViewModel test.)

AC-8. No TOTP secret, `qr_code_uri`, `recovery_codes`, code (`totp_code`/
`totp_code2`/`code`), `device_id`/`challenge_id`, or destination appears in logs or
analytics; body logging disabled for `/ui/mfa/**/devices/**`; the secret and
recovery codes are cleared from state on cancel/success. (Unit test + code review.)

## 15. Definition of Done

- `MfaApi`/`MfaApiClient` device methods + DTOs added (coordinated with AND-033),
  `MfaDeviceRepository`, `MfaDevicesViewModel`, the screen + TOTP/code enrollment
  sheets, `qr_code_uri` rendering (with optional local fallback per §4), the
  TOTP single-step and SMS/email two-step remove flows, and nav wiring implemented
  under `com.testlogon.android` and registered in AND-077's Security section.
- Live wire shapes verified against the contract (R1/R2 resolved this review — see
  §16); `@Json` names and verbs finalized to the corrected shapes.
- AC-1…AC-8 tests green: MockWebServer (paths/verbs/CSRF/no-retry), repository/VM
  unit tests, and at least one Compose UI test for TOTP/SMS/email enroll + remove;
  ≥85% coverage on new code; CI green.
- Redaction/logging constraints implemented and asserted (no secret/code/`device_id`
  leakage); body logging disabled for the device paths.
- Strings externalized; TalkBack, dynamic-type, dark-theme, and RTL verified;
  touch targets ≥ 48dp.
- QR rendering wired to the server `qr_code_uri` (image decode/Coil); ZXing core
  added **only** if the local-generation fallback is required (see §4) — otherwise
  no new third-party dependency; module layering (`feature-account` → `core-*`)
  preserved.
- Lint/detekt/ktlint clean; builds on compileSdk 35 / AGP 8.7.3 / JDK 17.
- KDoc on the new public surfaces documenting endpoints, the no-retry/secret-handling
  contract, and the enrollment state machine.
- PR on `android-port` references AND-064 and links AND-033, AND-077; reviewed and
  merged.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`reference/openapi.index.txt` (endpoint index), `reference/openapi.pretty.json`
(`components.schemas.*`), and the web client under `reference/src/`.

1. **List endpoints are three per-type GETs, not one `GET /ui/mfa/devices`.**
   VERDICT: **Corrected.** SOURCE: OpenAPI `GET /ui/mfa/totp/devices`,
   `GET /ui/mfa/sms/devices`, `GET /ui/mfa/email/devices`; `src/api/endpoints/account.ts:
   getTotpDevices / getSmsDevices / getEmailDevices`. No `/ui/mfa/devices` path exists
   in the index.
2. **List response is `{ devices: [...] }` per type; element id key differs
   (`device_id` / `sms_device_id` / `email_device_id`); no `type`/`verified` field;
   `created_at` is a numeric epoch.** VERDICT: **Corrected.** SOURCE:
   `src/api/types.ts: TotpDevice / SmsDevice / EmailDevice` (`created_at: number`,
   `enabled`, `pending`); `src/api/endpoints/account.ts` (`<{ devices: TotpDevice[] }>`).
3. **TOTP begin: `POST /ui/mfa/totp/devices/begin`, optional body `{label?}`.**
   VERDICT: **Corrected** (draft said "no body"). SOURCE: OpenAPI
   `POST /ui/mfa/totp/devices/begin | req=TotpDeviceBeginReq`; schema
   `TotpDeviceBeginReq` has only optional `label`; `src/api/types.ts: TotpDeviceBeginReq`.
4. **TOTP begin response is `{device_id, secret, qr_code_uri}` — `qr_code_uri` is a
   QR image URI, not `otpauth_uri`; no `issuer`/`account`.** VERDICT: **Corrected.**
   SOURCE: `src/api/types.ts: TotpDeviceBeginResp`; `src/pages/security/MfaDevices.tsx`
   uses `<img src={enrollData.qr_code_uri}>`. (OpenAPI response schema is `{}` — see
   Open assumptions for whether the URI is an image vs `otpauth://`.)
5. **TOTP confirm requires `device_id` + `totp_code` + `totp_code2` (two codes).**
   VERDICT: **Corrected** (draft said single `code`). SOURCE: OpenAPI schema
   `TotpDeviceConfirmReq` (`required: [device_id, totp_code, totp_code2]`);
   `src/api/types.ts: TotpDeviceConfirmReq`; `MfaDevices.tsx:100` passes both.
6. **TOTP/SMS/email confirm returns `{ok, recovery_codes[]}` (+ `*_device_id` for
   sms/email), not a device object.** VERDICT: **Corrected.** SOURCE:
   `src/api/endpoints/account.ts: confirmTotpEnrollment` (`<{ ok; recovery_codes[] }>`),
   `confirmSmsEnrollment` / `confirmEmailEnrollment` (`<{ ok; *_device_id; recovery_codes[] }>`);
   `MfaDevices.tsx:105` reads `data.recovery_codes`.
7. **SMS begin request key is `phone_e164` (+ optional `label`), not `destination`.**
   VERDICT: **Corrected.** SOURCE: OpenAPI schema `SmsDeviceBeginReq`
   (`required: [phone_e164]`); `src/api/types.ts: SmsDeviceBeginReq`.
8. **Email begin request key is `email` (+ optional `label`), not `destination`.**
   VERDICT: **Corrected.** SOURCE: OpenAPI schema `EmailDeviceBeginReq`
   (`required: [email]`); `src/api/types.ts: EmailDeviceBeginReq`.
9. **SMS/email begin response is `{challenge_id, sent_to: string[], *_device_id}`;
   `sent_to` is an array; there is no `expires_in` / `resend_available_in`.**
   VERDICT: **Corrected.** SOURCE: `src/api/types.ts: SmsDeviceBeginResp /
   EmailDeviceBeginResp`.
10. **SMS/email confirm keys on `challenge_id` + `code`, not `device_id` + `code`.**
    VERDICT: **Corrected.** SOURCE: OpenAPI schemas `SmsDeviceConfirmReq` /
    `EmailDeviceConfirmReq` (`required: [challenge_id, code]`); `src/api/types.ts`.
11. **TOTP remove is single-step `POST /ui/mfa/totp/devices/{device_id}/remove` with
    body `{totp_code}`.** VERDICT: **Corrected** (draft said no-body). SOURCE: OpenAPI
    `POST /ui/mfa/totp/devices/{device_id}/remove | req=TotpDeviceRemoveReq`; schema
    `TotpDeviceRemoveReq` (`required: [totp_code]`); `src/api/endpoints/account.ts:
    removeTotpDevice`.
12. **SMS/email removal is a two-step challenge: `.../{id}/remove/begin` (no body) →
    `{challenge_id, sent_to[]}`, then `.../remove/confirm` with `{challenge_id, code}`.**
    VERDICT: **Corrected** (draft used a uniform single-step `.../{id}/remove`).
    SOURCE: OpenAPI `POST /ui/mfa/sms/devices/{sms_device_id}/remove/begin`,
    `POST /ui/mfa/sms/devices/remove/confirm | req=SmsDeviceRemoveConfirmReq` (and
    email equivalents); `src/api/endpoints/account.ts: beginSmsRemoval /
    confirmSmsRemoval`; `src/api/types.ts: DeviceRemoveConfirmReq`.
13. **CSRF: `ui_csrf` cookie echoed to `X-CSRF-Token` on mutations; cookie-based
    session.** VERDICT: **Verified.** SOURCE: `src/api/client.ts:168-170`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`), `credentials:
    "include"`.
14. **401 → refresh once via `POST /ui/session/refresh` then retry the original
    request.** VERDICT: **Verified.** SOURCE: `src/api/client.ts:121-236`
    (`refreshSession()` posts `/ui/session/refresh`; 401 path refreshes once then
    retries; second 401 throws).
15. **Only `200` and `422` responses are declared for these ops; `422` is
    `HTTPValidationError` (`detail: [{loc,msg,type}]`).** VERDICT: **Verified.**
    SOURCE: OpenAPI index lines for every `/ui/mfa/{totp,sms,email}/devices/**` op
    (`resp=200:;422:HTTPValidationError`); component schema `HTTPValidationError`.
16. **`OkResp` is `{ ok: boolean }` (remove/confirm success shape).** VERDICT:
    **Verified.** SOURCE: `src/api/types.ts: OkResp`; `account.ts` remove/confirm
    endpoints typed `<OkResp>`.
17. **Local ZXing QR generation from an `otpauth://` URI.** VERDICT: **Corrected →
    fallback-only.** SOURCE: `MfaDevices.tsx:276` renders `qr_code_uri` directly as an
    image (`<img src=…>`), so the server supplies the QR; local generation is not the
    primary path.
18. **Recovery codes shown after enrollment.** VERDICT: **Verified.** SOURCE:
    `src/pages/security/MfaDevices.tsx:105-106,396-397,642-643`
    (`if (data.recovery_codes.length > 0) setRecoveryCodes(...)`).
19. **MVVM + Hilt + Compose + Retrofit/OkHttp/Moshi stack and module layering.**
    VERDICT: **Unverified-assumption** (project convention; consistent with AND-033
    chain). SOURCE: framework ref — Android app architecture guidance
    (https://developer.android.com/topic/architecture).
20. **`FLAG_SECURE` to block screenshots of QR/secret.** VERDICT:
    **Unverified-assumption** (open question Q3/R3). SOURCE: framework ref —
    https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE.

### Corrections made

- Replaced the non-existent unified `GET /ui/mfa/devices` with the three per-type
  list endpoints, merged client-side; removed the wire `type`/`verified` fields and
  changed `created_at` to a numeric epoch; id key now varies per type. (#1, #2)
- TOTP begin now sends optional `{label}` and the response field is `qr_code_uri`
  (image), not `otpauth_uri`; dropped `issuer`/`account`. (#3, #4)
- TOTP confirm now requires `totp_code` AND `totp_code2`; all confirm responses are
  `{ok, recovery_codes[]}` (not device objects), and recovery codes are surfaced. (#5, #6)
- SMS/email begin requests use `phone_e164`/`email` (+ `label`); begin responses use
  `challenge_id` + `sent_to: string[]`; removed non-existent `expires_in` /
  `resend_available_in` (resend cooldown is now client-side). (#7, #8, #9)
- SMS/email confirm and remove-confirm key on `challenge_id` + `code`. (#10, #12)
- TOTP remove now sends `{totp_code}`; SMS/email removal split into a two-step
  begin/confirm challenge (no single-step `.../{id}/remove` for those types). (#11, #12)
- Reframed QR rendering around the server `qr_code_uri`, making ZXing a conditional
  fallback rather than a guaranteed dependency. (#17)
- Updated affected DTOs, API/repo signatures, ViewModel state (`code2`,
  `recoveryCodes`, remove-challenge state), §5 examples, §6 mapping, §7 retry text,
  §8 secret list, §11 tests, §13 R1/R2, and §14 acceptance criteria accordingly.

### Open assumptions

- **`qr_code_uri` exact form.** The OpenAPI response schema is `{}` (untyped); only
  the web client's `<img src>` usage is observable. Assumed a data/image URI (render
  as-is); if it is actually an `otpauth://` value, the ZXing fallback in §4 applies.
  Cannot be resolved without a live response or backend source.
- **Error envelopes for `400`/`409`/`429`.** OpenAPI declares only `200`/`422` for
  these ops; the `mfa_invalid_code` (+`attempts_remaining`), `mfa_device_exists`, and
  `mfa_resend_throttled` (+`retry_after`) shapes are assumed conventions (per AND-033's
  mapper) and are defensive only. Verify with live fixtures.
- **Resend cooldown.** No server-provided cooldown field exists on begin; the
  client-side fixed cooldown is an assumption pending a live `429`/`retry_after`.
- **Device "active" semantics post-confirm.** Confirm returns `{ok}`; activation is
  inferred from a re-list (`enabled: true`). The exact enable/pending transition is
  not described by the contract.
- **`last_used_at`/`pending` rendering.** Present in the web types; their exact UI
  treatment is a product decision, not a contract item.
- **Recovery-codes UX (when shown, storage).** The web client surfaces them when
  non-empty; whether the backend always returns them on first enroll vs only for the
  first factor is not specified.
- **Last-factor / duplicate removal policy (R4).** Whether the backend blocks
  removing the last factor or duplicate destinations is not in the contract.
- **Stack/`FLAG_SECURE` choices** are framework/product decisions, not contract
  items (#19, #20).

## 17. Test Plan

Acceptance criteria referenced are from §14 (AC-1…AC-8). Test targets: **JVM**
(local JVM/Robolectric unit), **MWS** (MockWebServer contract), **emu test35**
(headless API 35 x86_64 emulator), **A15** (physical Samsung Galaxy A15 5G,
SM-A156U, API 34, arm64). Most cases are deterministic and run on JVM/MWS/emulator;
the physical device is called out only where real hardware/behavior matters.

- **TC-AND-064-01 — List merges three per-type endpoints.**
  Type: contract/MockWebServer. Target: MWS + JVM (repository).
  Preconditions: MWS enqueues 200 for `/ui/mfa/totp/devices`, `/ui/mfa/sms/devices`,
  `/ui/mfa/email/devices` with one device each.
  Steps: call `repo.list()`.
  Expected: three `RecordedRequest`s (all GET, correct paths); merged domain list has
  3 devices, types assigned by source endpoint, `created_at` epoch parsed to
  `Instant`, sorted TOTP-first then `createdAt` desc; SMS/email destinations masked.
  Traces: AC-1.

- **TC-AND-064-02 — Partial list failure degrades, not blanks.**
  Type: contract/MockWebServer. Target: MWS + JVM (VM).
  Preconditions: TOTP+SMS GET return 200; email GET returns 500.
  Steps: `load()`.
  Expected: list shows TOTP+SMS rows; a non-blocking "couldn't load email factors"
  state; previously rendered rows not blanked; retry available.
  Traces: AC-1, AC-7.

- **TC-AND-064-03 — TOTP enroll happy path (begin → 2 codes → confirm).**
  Type: integration (VM+repo+MWS). Target: MWS + JVM.
  Preconditions: begin → 200 `{device_id, secret, qr_code_uri}`; confirm → 200
  `{ok:true, recovery_codes:[...]}`; subsequent list shows the new TOTP device.
  Steps: `startTotpEnroll()`; enter `totp_code` + `totp_code2`; `submitConfirm()`.
  Expected: begin body is `{}` or `{label}`; confirm body is exactly
  `{device_id, totp_code, totp_code2}`; recovery codes surfaced once; `EnrollState`
  returns to `None`; secret/qr/recovery cleared; new factor appears.
  Traces: AC-2, AC-8.

- **TC-AND-064-04 — TOTP confirm rejects single code / sends both.**
  Type: unit + contract. Target: JVM + MWS.
  Preconditions: VM in `AwaitingCode` with `enrollment` present.
  Steps: enter only the first code and attempt submit; then enter both and submit.
  Expected: submit is disabled / no request until both 6-digit codes present; when
  sent, the recorded JSON contains both `totp_code` and `totp_code2`.
  Traces: AC-2, AC-6.

- **TC-AND-064-05 — SMS enroll happy path (phone_e164 → challenge_id confirm).**
  Type: integration (VM+repo+MWS). Target: MWS + JVM.
  Preconditions: begin → 200 `{challenge_id, sent_to:["+1•••••4567"], sms_device_id}`;
  confirm → 200 `{ok:true, sms_device_id, recovery_codes:[]}`.
  Steps: enter phone; `submitBegin()`; enter code; `submitConfirm()`.
  Expected: begin body `{phone_e164, label?}`; confirm body `{challenge_id, code}`
  (NOT `device_id`); factor appears after re-list.
  Traces: AC-3, AC-6.

- **TC-AND-064-06 — Email enroll happy path (email → challenge_id confirm).**
  Type: integration (VM+repo+MWS). Target: MWS + JVM.
  Preconditions: email begin/confirm 200 fixtures analogous to TC-05.
  Steps: enter email; begin; enter code; confirm.
  Expected: begin body `{email, label?}`; confirm body `{challenge_id, code}`;
  factor appears.
  Traces: AC-4, AC-6.

- **TC-AND-064-07 — TOTP remove (single-step, totp_code re-auth).**
  Type: contract/MockWebServer. Target: MWS + JVM (VM).
  Preconditions: list has a TOTP device; remove → 200 `{ok:true}`.
  Steps: `requestRemove(id)`; enter current TOTP code; `confirmRemove()`.
  Expected: exactly one POST to `/ui/mfa/totp/devices/{id}/remove` with body
  `{totp_code}`; row removed; no call before confirmation.
  Traces: AC-5, AC-6.

- **TC-AND-064-08 — SMS/email remove (two-step challenge).**
  Type: contract/MockWebServer. Target: MWS + JVM (VM).
  Preconditions: remove/begin → 200 `{challenge_id, sent_to[]}`; remove/confirm →
  200 `{ok:true}`.
  Steps: `requestRemove(sms_id)`; `confirmRemove()` triggers remove/begin; enter
  delivered code; final confirm.
  Expected: POST `/ui/mfa/sms/devices/{id}/remove/begin` (no body), then POST
  `/ui/mfa/sms/devices/remove/confirm` with `{challenge_id, code}`; row removed;
  optimistic hide restored on failure.
  Traces: AC-5, AC-6, AC-7.

- **TC-AND-064-09 — Invalid/expired confirm code.**
  Type: contract/MockWebServer. Target: MWS + JVM (VM).
  Preconditions: confirm → 400 `{detail:{code:"mfa_invalid_code",attempts_remaining:2}}`
  (defensive; mapper-normalized).
  Steps: submit a wrong code in any confirm flow.
  Expected: stays on awaiting-code step; field cleared; message shown;
  `attemptsRemaining=2` surfaced; exactly one request (no retry).
  Traces: AC-7, AC-6.

- **TC-AND-064-10 — Resend throttling / no auto-retry on mutations.**
  Type: contract/MockWebServer. Target: MWS + JVM (VM).
  Preconditions: begin enqueued 429 then 200.
  Steps: trigger begin; observe; trigger resend after cooldown.
  Expected: exactly ONE recorded request for the throttled begin (POST not retried);
  resend disabled during the client-side cooldown countdown, enabled at 0;
  429 (with `retry_after` if present) extends the cooldown.
  Traces: AC-6, AC-7.

- **TC-AND-064-11 — CSRF + session cookie on every mutation.**
  Type: contract/MockWebServer. Target: MWS + JVM.
  Preconditions: cookie jar seeded with session + `ui_csrf`; fixtures for each
  mutating op.
  Steps: exercise begin/confirm/remove (+ remove/begin, remove/confirm).
  Expected: each recorded mutation carries `X-CSRF-Token` (= `ui_csrf`) and `Cookie`;
  GETs carry the session cookie.
  Traces: AC-6.

- **TC-AND-064-12 — Offline / flaky-dev-host path.**
  Type: integration. Target: MWS (SocketPolicy/timeout) + JVM (VM).
  Preconditions: list GET times out / returns disconnect; then an in-flight confirm
  hits a 20s timeout.
  Steps: `load()` offline; retry; then a confirm during simulated outage.
  Expected: offline/retry state; last-rendered list retained (marked stale) not
  blanked; confirm surfaces a retryable error without losing entered code where safe;
  no duplicate mutation issued.
  Traces: AC-7.

- **TC-AND-064-13 — Secret/code/recovery never logged or in analytics.**
  Type: unit + code review. Target: JVM.
  Preconditions: capture Timber/analytics sinks; OkHttp logging configured.
  Steps: run enroll/remove flows against fakes; inspect emitted logs + analytics
  events; assert body logging disabled for `/ui/mfa/**/devices/**`.
  Expected: no `secret`, `qr_code_uri`, `recovery_codes`, `totp_code`/`totp_code2`/
  `code`, `device_id`/`challenge_id`, `phone_e164`/`email` in any sink; analytics
  events carry only `{type, success, code}`; state cleared on cancel/success.
  Traces: AC-8.

- **TC-AND-064-14 — Compose UI: enroll TOTP/SMS/email + remove (accessibility).**
  Type: Compose-UI / instrumented. Target: **emu test35** (and re-run on **A15** for
  the QR/secret + `FLAG_SECURE` screenshot check, which depends on real window flags).
  Preconditions: fake repo serving deterministic begin/confirm/list responses.
  Steps: open screen; enroll TOTP (QR image + secret render, enter two codes, confirm,
  recovery shown); add SMS and email rows; remove a row via the confirmation dialog;
  run with TalkBack semantics assertions and large-font/RTL configs.
  Expected: QR `Image` has `contentDescription`; secret is exposed as speakable text;
  remove button labeled "Remove <label>"; dialog focus-trapped; touch targets ≥48dp;
  rows added/removed correctly. On A15: `FLAG_SECURE` (if adopted) blocks the
  enrollment-sheet screenshot/recents thumbnail.
  Traces: AC-1, AC-2, AC-3, AC-4, AC-5, AC-8.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02, TC-14 |
| AC-2 | TC-03, TC-04, TC-14 |
| AC-3 | TC-05, TC-14 |
| AC-4 | TC-06, TC-14 |
| AC-5 | TC-07, TC-08, TC-14 |
| AC-6 | TC-04, TC-05, TC-06, TC-07, TC-08, TC-09, TC-10, TC-11 |
| AC-7 | TC-02, TC-08, TC-09, TC-10, TC-12 |
| AC-8 | TC-03, TC-13, TC-14 |
