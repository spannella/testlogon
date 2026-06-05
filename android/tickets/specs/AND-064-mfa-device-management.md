---
id: AND-064
title: MFA device management
milestone: M2
epic: E08
priority: P1
size: L
status: draft
depends_on: [AND-033, AND-077]
blocks: []
---

# AND-064 — MFA device management

## 1. Overview & Goal

Give the authenticated user a self-service screen to manage the multi-factor
authentication (MFA) devices/factors enrolled on their account: list currently
enrolled factors, enroll a new TOTP authenticator (showing a QR code and the
manually-enterable secret, then confirming with a generated code), add SMS and
email factors (request a code to the destination, then confirm), and remove any
enrolled factor by id. This is the *enrollment/management* counterpart to the
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
(begin → render QR + secret → enter code → confirm → factor appears in list); can
add an SMS factor and an email factor (begin → enter delivered code → confirm);
can remove any factor with confirmation; and every one of these paths is covered
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

FR-1. On entry, the screen calls `GET /ui/mfa/devices` and renders a loading
state, then a list of enrolled factors grouped/typed by `type` (`totp` | `sms` |
`email`), each showing a label, masked destination where applicable
(`sent_to`/`label`, e.g. `+1•••••1234`, `j•••@example.com`, "Authenticator app"),
created date, and a "verified/active" indicator.

FR-2. **Enroll TOTP**: an "Add authenticator app" action calls
`POST /ui/mfa/totp/devices/begin`, which returns an `otpauth://` provisioning URI,
a base32 `secret`, and a `device_id`. The screen renders a scannable QR code
(generated locally from the URI) and the secret in copyable, grouped text, with a
"can't scan?" reveal. The user enters the 6-digit code from their authenticator
and the screen calls `POST /ui/mfa/totp/devices/confirm` with `{device_id, code}`.
On success the new factor appears in the list.

FR-3. **Add SMS factor**: an "Add phone" action collects a phone number, calls
`POST /ui/mfa/sms/devices/begin` with `{destination}` → returns `{device_id,
sent_to, expires_in, resend_available_in}`. A code-entry step calls
`POST /ui/mfa/sms/devices/confirm` with `{device_id, code}`. On success the factor
appears in the list.

FR-4. **Add email factor**: an "Add email" action collects an email address, calls
`POST /ui/mfa/email/devices/begin` → confirm via
`POST /ui/mfa/email/devices/confirm` — identical flow to SMS with the email
destination.

FR-5. **Remove factor**: each row exposes a remove affordance that, after an
explicit destructive-action confirmation dialog, calls
`POST /ui/mfa/{type}/devices/{device_id}/remove`. On success the row is removed.

FR-6. SMS/email begin steps surface a resend control gated by
`resend_available_in` (cooldown countdown); resend re-issues the `begin` call.

FR-7. Code-entry fields use the shared OTP composable (AND-020): 6-digit numeric
for TOTP/SMS/email confirm; auto-advance, paste support, and an inline "verifying"
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
    val deviceId: String,
    val type: MfaFactorType,
    val label: String?,        // "Authenticator app", "Personal phone", null
    val maskedDestination: String?, // sent_to for sms/email; null for totp
    val verified: Boolean,
    val createdAt: Instant,
)

data class TotpEnrollment(
    val deviceId: String,
    val otpauthUri: String,    // otpauth://totp/...  (sensitive, transient)
    val secret: String,        // base32, grouped for display (sensitive)
    val issuer: String?,
    val account: String?,
)

data class DeviceChallenge(           // sms/email begin result
    val deviceId: String,
    val sentTo: String,               // masked
    val expiresIn: Int,
    val resendAvailableIn: Int,
)
```

`MfaApi` additions (Retrofit; same package as AND-033):

```kotlin
// com.testlogon.android.core.network.auth.MfaApi (extended in coordination with AND-033)
@GET("ui/mfa/devices")
suspend fun listDevices(): Response<MfaDeviceListDto>

@POST("ui/mfa/totp/devices/begin")
suspend fun beginTotpDevice(): Response<TotpEnrollDto>

@POST("ui/mfa/totp/devices/confirm")
suspend fun confirmTotpDevice(@Body body: DeviceConfirmReq): Response<MfaDeviceDto>

@POST("ui/mfa/{type}/devices/begin")
suspend fun beginCodeDevice(
    @Path("type") type: String,                 // "sms" | "email"
    @Body body: DeviceBeginReq,
): Response<DeviceChallengeDto>

@POST("ui/mfa/{type}/devices/confirm")
suspend fun confirmCodeDevice(
    @Path("type") type: String,
    @Body body: DeviceConfirmReq,
): Response<MfaDeviceDto>

@POST("ui/mfa/{type}/devices/{deviceId}/remove")
suspend fun removeDevice(
    @Path("type") type: String,
    @Path("deviceId") deviceId: String,
): Response<Unit>
```

`MfaApiClient` façade additions (typed, `ApiResult`-returning, via `safeApiCall`):

```kotlin
suspend fun listDevices(): ApiResult<MfaDeviceListDto>
suspend fun beginTotpDevice(): ApiResult<TotpEnrollDto>
suspend fun confirmTotpDevice(deviceId: String, code: String): ApiResult<MfaDeviceDto>
suspend fun beginCodeDevice(type: MfaFactorType, destination: String): ApiResult<DeviceChallengeDto>
suspend fun confirmCodeDevice(type: MfaFactorType, deviceId: String, code: String): ApiResult<MfaDeviceDto>
suspend fun removeDevice(type: MfaFactorType, deviceId: String): ApiResult<Unit>
```

Repository in `core-data`:

```kotlin
// com.testlogon.android.core.data.mfa
class MfaDeviceRepository @Inject constructor(
    private val mfa: MfaApiClient,
    private val dispatchers: AppDispatchers,
) {
    suspend fun list(): ApiResult<List<MfaDevice>>            // DTO -> domain, sorted
    suspend fun beginTotp(): ApiResult<TotpEnrollment>
    suspend fun confirmTotp(deviceId: String, code: String): ApiResult<MfaDevice>
    suspend fun beginCode(type: MfaFactorType, destination: String): ApiResult<DeviceChallenge>
    suspend fun confirmCode(type: MfaFactorType, deviceId: String, code: String): ApiResult<MfaDevice>
    suspend fun remove(type: MfaFactorType, deviceId: String): ApiResult<Unit>
}
```

QR generation is local and dependency-light: render the `otpauthUri` to a bitmap
with ZXing core (`com.google.zxing:core`) via a small `QrCodeGenerator` helper in
`core-ui`, drawn in a Compose `Image`/`Canvas`. No network call is made to render
the QR; the URI never leaves the device beyond what the user scans.

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
            val enrollment: TotpEnrollment? = null,  // present in AwaitingCode
            val code: String = "",
            val attemptsRemaining: Int? = null,
        ) : EnrollState
        data class Code(
            val type: MfaFactorType,                 // SMS | EMAIL
            val step: Step,
            val destination: String = "",
            val challenge: DeviceChallenge? = null,
            val code: String = "",
            val resendInSeconds: Int = 0,
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
    fun requestRemove(deviceId: String)
    fun confirmRemove()
    fun dismissRemove()
    fun dismissError()
}
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
`X-CSRF-Token` (auto). Mutations are `POST`; the list is `GET`. The `{type}` path
segment is `totp` | `sms` | `email`. Exact field names MUST be confirmed against
`/openapi.json`; Moshi DTOs map snake_case via `@Json(name=...)` and tolerate
unknown keys.

**List** — `GET /ui/mfa/devices` → 200:
```json
{
  "devices": [
    { "device_id": "dev_totp_01", "type": "totp", "label": "Authenticator app",
      "sent_to": null, "verified": true, "created_at": "2026-05-02T10:00:00Z" },
    { "device_id": "dev_sms_07", "type": "sms", "label": "Personal phone",
      "sent_to": "+1•••••1234", "verified": true, "created_at": "2026-05-10T18:22:00Z" }
  ]
}
```

**TOTP begin** — `POST /ui/mfa/totp/devices/begin` (no body) → 200:
```json
{
  "device_id": "dev_totp_02",
  "otpauth_uri": "otpauth://totp/TestLogon:spannella@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=TestLogon&digits=6&period=30",
  "secret": "JBSWY3DPEHPK3PXP",
  "issuer": "TestLogon",
  "account": "spannella@gmail.com"
}
```

**TOTP confirm** — `POST /ui/mfa/totp/devices/confirm`:
```json
{ "device_id": "dev_totp_02", "code": "482915" }
```
→ 200: an `MfaDeviceDto` (the now-verified device, same shape as a list element).

**SMS/email begin** — `POST /ui/mfa/{sms|email}/devices/begin`:
```json
{ "destination": "+15551234567" }
```
→ 200:
```json
{ "device_id": "dev_sms_08", "sent_to": "+1•••••4567",
  "expires_in": 300, "resend_available_in": 30 }
```

**SMS/email confirm** — `POST /ui/mfa/{sms|email}/devices/confirm`:
```json
{ "device_id": "dev_sms_08", "code": "204815" }
```
→ 200: `MfaDeviceDto`.

**Remove** — `POST /ui/mfa/{type}/devices/{device_id}/remove` (no body) → 200
(or 204) on success.

**Errors** (FastAPI `detail` polymorph: string | `[{msg}]` | `{code,...}`,
normalized by `ApiErrorMapper`):
- `400` invalid/expired confirm code → `{ "detail": { "code": "mfa_invalid_code", "attempts_remaining": 2 } }`
- `409` already-enrolled / duplicate destination → `{ "detail": { "code": "mfa_device_exists" } }`
- `422` validation (bad phone/email) → `{ "detail": [{ "loc": ["body","destination"], "msg": "invalid phone number", "type": "value_error" }] }`
- `429` resend throttled → `{ "detail": { "code": "mfa_resend_throttled", "retry_after": 22 } }`
- `401` → transparent refresh-once-then-retry via the shared `Authenticator`.

DTOs (`com.testlogon.android.core.network.auth.dto`, Moshi codegen):
```kotlin
@JsonClass(generateAdapter = true)
data class MfaDeviceListDto(val devices: List<MfaDeviceDto> = emptyList())

@JsonClass(generateAdapter = true)
data class MfaDeviceDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "type") val type: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "sent_to") val sentTo: String? = null,
    @Json(name = "verified") val verified: Boolean = false,
    @Json(name = "created_at") val createdAt: String,
)

@JsonClass(generateAdapter = true)
data class TotpEnrollDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "otpauth_uri") val otpauthUri: String,
    @Json(name = "secret") val secret: String,
    @Json(name = "issuer") val issuer: String? = null,
    @Json(name = "account") val account: String? = null,
)

@JsonClass(generateAdapter = true)
data class DeviceChallengeDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "sent_to") val sentTo: String,
    @Json(name = "expires_in") val expiresIn: Int = 0,
    @Json(name = "resend_available_in") val resendAvailableIn: Int = 0,
)

@JsonClass(generateAdapter = true)
data class DeviceBeginReq(@Json(name = "destination") val destination: String)

@JsonClass(generateAdapter = true)
data class DeviceConfirmReq(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "code") val code: String,
)
```

## 6. Data & State Management

- **No persistence of factor data, secrets, or codes.** The device list is
  security-sensitive and must reflect live server state, so it is fetched on
  demand and held only in `StateFlow` memory; no Room/DataStore caching. The TOTP
  `secret`/`otpauth_uri` live only inside `EnrollState.Totp` for the duration of
  the enrollment sheet and are dropped on `cancelEnroll`, successful confirm, or
  process death.
- The only persisted state relied upon is the OkHttp cookie jar (session +
  `ui_csrf`), owned by the core-network tickets; AND-064 neither reads nor writes
  auth/DataStore state.
- **Optimistic remove**: on confirmed remove, add the id to `removingIds` and hide
  the row; on API success drop it permanently; on failure re-insert at its
  original index and show an error. Enrollment is *not* optimistic — the new
  factor is added to the list only from the confirm response (or by re-`list()`).
- After a successful enroll/remove, the VM re-fetches `list()` to reconcile with
  the server (source of truth), avoiding drift from partial/edge responses.
- The DTO→domain mapper parses `created_at` (ISO-8601) to `Instant`, maps the
  `type` string to `MfaFactorType` (unknown types are dropped from the list rather
  than crashing — forward-compat), and sorts the list (TOTP first, then by
  `createdAt` desc).

## 7. Error Handling & Resilience

- Every call funnels through `safeApiCall` → `ApiResult.Success` /
  `ApiResult.HttpError(status, ApiError)` / `ApiResult.NetworkError`. No exception
  escapes to the UI.
- **Idempotency / retries**: `GET /ui/mfa/devices` is an idempotent read and MAY
  use the existing bounded-backoff GET retry. All `begin`/`confirm`/`remove`
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

- **Secrets never logged, never persisted**: TOTP `secret`, `otpauth_uri`, and all
  confirm codes are secrets. OkHttp body logging is prohibited for
  `/ui/mfa/**/devices/**` in every build type (BASIC-level method+URL+status, or a
  redacting interceptor — consistent with AND-033). The `secret`/URI are held only
  in transient VM state and cleared per §6/FR-10.
- `device_id` and masked destinations are sensitive — redact from telemetry and
  crash breadcrumbs (§10).
- The QR is generated locally; the `otpauth_uri` is not sent to any third party or
  image service.
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

1. **API/DTO (core-network)**: enqueue 200 fixtures for `listDevices`,
   `beginTotpDevice`, `confirmTotpDevice`, `beginCodeDevice`, `confirmCodeDevice`,
   `removeDevice`; assert `RecordedRequest` path/verb (e.g.
   `/ui/mfa/totp/devices/begin` POST, `/ui/mfa/sms/devices/dev_sms_08/remove`
   POST), and that request bodies contain exactly the expected keys
   (`destination`, `device_id`, `code`). Assert `X-CSRF-Token` + `Cookie` present
   on every mutation. Assert DTOs (de)serialize fixtures field-by-field, tolerate
   unknown keys, and round-trip.
2. **No-retry guarantee**: enqueue `429`→`200` for a `begin`; assert exactly one
   recorded request (mutations not retried). Confirm `GET /ui/mfa/devices` MAY
   retry per the GET policy.
3. **Repository (core-data)**: DTO→domain mapping (type enum, `Instant` parsing,
   sort order, unknown-type drop); error-envelope mapping for the three `detail`
   shapes including `attempts_remaining`/`retry_after`.
4. **ViewModel unit tests** (Turbine + coroutine test rule):
   - `load()` populates and sorts the list.
   - TOTP enroll happy path: `startTotpEnroll` → `BeginInFlight` → `AwaitingCode`
     with `enrollment` present (secret/URI in state) → `submitConfirm` →
     factor in list, `EnrollState.None`, secret cleared.
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
- **New dependency**: ZXing core (`com.google.zxing:core`) for local QR rendering —
  small, no Play Services, added to the `core-ui`/`feature-account` Gradle module.
  This is the only new third-party library.
- **Blocks**: none currently tracked.
- **Sequencing**: extend `MfaApi`/`MfaApiClient` + DTOs (tested) → repository +
  mapper (tested) → ViewModel state machine (tested) → Compose screen + enroll
  sheets + QR + nav wiring → Compose UI test.

## 13. Risks & Open Questions

- **R1 — Exact device endpoints/shapes**: paths and field names
  (`devices/begin|confirm|{id}/remove`, `otpauth_uri` vs `provisioning_uri`,
  `destination` vs `phone`/`email`, remove via `POST .../remove` vs `DELETE`) are
  reconstructed from the backlog scope + web reference. Confirm against
  `/openapi.json` and `frontend/src/api/endpoints` before merge; adjust `@Json`
  names and verbs accordingly.
- **R2 — TOTP confirm requirement**: confirm whether the backend requires a
  successful TOTP `confirm` to activate the device (assumed yes) and what it
  returns (assumed the verified `MfaDeviceDto`).
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

AC-1. The screen calls `GET /ui/mfa/devices` and renders every enrolled factor
typed/grouped with label, masked destination, and created date; loading/empty/
error states present. (MockWebServer + Compose UI test.)

AC-2. **TOTP enrollment** works end-to-end: `POST /ui/mfa/totp/devices/begin`
returns the URI + secret; the screen renders a scannable QR and the copyable
secret; entering the generated code and `POST /ui/mfa/totp/devices/confirm`
succeeds; the factor then appears in the list. (Satisfies source AC: "User can
enroll a TOTP device (QR/secret)." — ViewModel + Compose UI test.)

AC-3. **Add SMS factor** works: `POST /ui/mfa/sms/devices/begin` with
`{destination}` → confirm with `POST /ui/mfa/sms/devices/confirm` `{device_id,
code}` → factor appears. (Satisfies "add SMS devices (tested)".)

AC-4. **Add email factor** works via the analogous `email/devices/begin|confirm`
flow → factor appears. (Satisfies "add email devices (tested)".)

AC-5. **Remove** any factor via `POST /ui/mfa/{type}/devices/{device_id}/remove`
after explicit confirmation removes the row; failure rolls it back. (Satisfies
"remove SMS+email devices (tested)" — MockWebServer + ViewModel test.)

AC-6. Every mutating call carries `X-CSRF-Token` + session cookies and is issued
exactly once (no auto-retry); the list GET may retry per the GET backoff policy.
(MockWebServer test.)

AC-7. Invalid/expired code, `429` throttled resend (with cooldown), `409`
duplicate, network/401/403/5xx all surface retryable messages and leave the
screen consistent; `attempts_remaining` shown when provided. (MockWebServer +
ViewModel test.)

AC-8. No TOTP secret, `otpauth_uri`, code, `device_id`, or destination appears in
logs or analytics; body logging disabled for `/ui/mfa/**/devices/**`; the secret
is cleared from state on cancel/success. (Unit test + code review.)

## 15. Definition of Done

- `MfaApi`/`MfaApiClient` device methods + DTOs added (coordinated with AND-033),
  `MfaDeviceRepository`, `MfaDevicesViewModel`, the screen + TOTP/code enrollment
  sheets, local QR generation, and nav wiring implemented under
  `com.testlogon.android` and registered in AND-077's Security section.
- Live wire shapes verified against `/openapi.json` (R1/R2 resolved); `@Json`
  names and verbs finalized.
- AC-1…AC-8 tests green: MockWebServer (paths/verbs/CSRF/no-retry), repository/VM
  unit tests, and at least one Compose UI test for TOTP/SMS/email enroll + remove;
  ≥85% coverage on new code; CI green.
- Redaction/logging constraints implemented and asserted (no secret/code/`device_id`
  leakage); body logging disabled for the device paths.
- Strings externalized; TalkBack, dynamic-type, dark-theme, and RTL verified;
  touch targets ≥ 48dp.
- ZXing core dependency added cleanly; no other new dependencies; module layering
  (`feature-account` → `core-*`) preserved.
- Lint/detekt/ktlint clean; builds on compileSdk 35 / AGP 8.7.3 / JDK 17.
- KDoc on the new public surfaces documenting endpoints, the no-retry/secret-handling
  contract, and the enrollment state machine.
- PR on `android-port` references AND-064 and links AND-033, AND-077; reviewed and
  merged.
