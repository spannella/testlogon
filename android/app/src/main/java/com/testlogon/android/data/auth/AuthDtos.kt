package com.testlogon.android.data.auth

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientLong

/**
 * Wire DTOs for the cookie-based auth + MFA surface (AND-026, AND-033).
 *
 * Shapes are the corrected/verified contracts from the reviewed specs:
 *  - `GET /ui/me` = {user_sub, session_id, ip}
 *  - session/start carries a free-form `challenge_context` map (the web client puts
 *    {username, password} in it)
 *  - TOTP verify field is `totp_code`; SMS/email verify use `code`; recovery uses `recovery_code`
 *  - verify/finalize responses signal completion via `remaining_factors.isEmpty()`, not a boolean
 *
 * All DTOs use Moshi codegen (`@JsonClass(generateAdapter = true)`). Secret-bearing request DTOs
 * override `toString()` so accidental logging cannot leak credentials / OTP codes.
 */

// ── session/start ──

@JsonClass(generateAdapter = true)
data class SessionStartReq(
    @Json(name = "challenge_context") val challengeContext: Map<String, String>? = null,
) {
    override fun toString() = "SessionStartReq(challengeContext=***)"
}

@JsonClass(generateAdapter = true)
data class SessionStartResp(
    @Json(name = "auth_required") val authRequired: Boolean,
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    @Json(name = "session_id") val sessionId: String? = null,
)

// ── session/finalize ──

@JsonClass(generateAdapter = true)
data class SessionFinalizeReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "remember_device") val rememberDevice: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class SessionFinalizeResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
)

// ── me / sessions ──

@JsonClass(generateAdapter = true)
data class MeResp(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "session_id") val sessionId: String,
    // cpp GET /ui/me returns only {user_sub, session_id} (no ip); the Python backend also sends ip.
    // Nullable + defaulted so BOTH shapes deserialize without a JsonDataException. (A1b DTO-drift fix.)
    val ip: String? = null,
)

/**
 * One active session row.
 *
 * A1b DTO-drift fix (app<->cpp). The two backends disagree on the WIRE shape of this row:
 *  - Python sends `is_current` (bool), NUMERIC `created_at`/`last_seen_at`, and `ip`/`user_agent`.
 *  - cpp GET /ui/sessions sends `current` (bool) INSTEAD OF `is_current`, STRINGIFIED
 *    `created_at`/`last_seen_at` (e.g. "1784811816"), and OMITS `ip`/`user_agent` (+ `revoked_at`).
 *
 * To tolerate BOTH without a JsonDataException — and WITHOUT touching any of the ~6 UI/repo call
 * sites or the two constructor-based tests — the wire fields are modelled as nullable + defaulted
 * codegen params, and the app-facing shape the rest of the code already reads
 * ([isCurrent]/[createdAt]/[lastSeenAt]/[ip]/[userAgent], all NON-NULL) is re-exposed as computed
 * properties that coalesce the two spellings / supply the cpp-omitted defaults:
 *  - timestamps use the existing @LenientLong adapter (already on NetworkModule.provideMoshi), which
 *    accepts a JSON number (Python) OR a numeric string (cpp) OR null -> Long?.
 *  - `is_current` (Python) and `current` (cpp) are BOTH mapped (distinct keys) and OR-folded.
 *  - ip/user_agent default to "" when the server omits them.
 * No new Moshi adapter or module dependency is introduced (core-network cannot see this app-module
 * type); the reflective KotlinJsonAdapterFactory + the existing @LenientLong qualifier do the work.
 */
@JsonClass(generateAdapter = true)
data class SessionInfo(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "is_current") val isCurrentWire: Boolean? = null,
    @Json(name = "current") val currentWire: Boolean? = null,
    @LenientLong @Json(name = "created_at") val createdAtWire: Long? = null,
    @LenientLong @Json(name = "last_seen_at") val lastSeenAtWire: Long? = null,
    @Json(name = "ip") val ipWire: String? = null,
    @Json(name = "user_agent") val userAgentWire: String? = null,
    val revoked: Boolean = false,
    @Json(name = "revoked_at") val revokedAt: Long? = null,
) {
    /** True if this is the caller's own session - Python `is_current` OR cpp `current`. */
    val isCurrent: Boolean get() = isCurrentWire ?: currentWire ?: false

    /** Session creation epoch (seconds). cpp sends it stringified; @LenientLong normalises both. */
    val createdAt: Long get() = createdAtWire ?: 0L

    /** Last-seen epoch (seconds). cpp sends it stringified; @LenientLong normalises both. */
    val lastSeenAt: Long get() = lastSeenAtWire ?: 0L

    /** Client IP. cpp omits it on /ui/sessions -> "". */
    val ip: String get() = ipWire ?: ""

    /** Client user-agent. cpp omits it on /ui/sessions -> "". */
    val userAgent: String get() = userAgentWire ?: ""
}

@JsonClass(generateAdapter = true)
data class SessionsResp(
    val sessions: List<SessionInfo> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class RevokeSessionReq(
    @Json(name = "session_id") val sessionId: String,
)

// ── generic envelopes ──

@JsonClass(generateAdapter = true)
data class OkResp(val ok: Boolean)

@JsonClass(generateAdapter = true)
data class StatusResp(val status: String)

// ── MFA begin (sms/email) ──

@JsonClass(generateAdapter = true)
data class SmsBeginReq(
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class EmailBeginReq(
    @Json(name = "challenge_id") val challengeId: String,
)

@JsonClass(generateAdapter = true)
data class ChallengeResp(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: List<String>? = null,
)

// ── MFA verify (per-factor request bodies) ──

@JsonClass(generateAdapter = true)
data class TotpVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "totp_code") val totpCode: String,
) {
    override fun toString() = "TotpVerifyReq(challengeId=$challengeId, totpCode=***)"
}

@JsonClass(generateAdapter = true)
data class SmsVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
) {
    override fun toString() = "SmsVerifyReq(challengeId=$challengeId, code=***)"
}

@JsonClass(generateAdapter = true)
data class EmailVerifyReq(
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
) {
    override fun toString() = "EmailVerifyReq(challengeId=$challengeId, code=***)"
}

@JsonClass(generateAdapter = true)
data class RecoveryReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "recovery_code") val recoveryCode: String,
    val factor: String? = null,
) {
    override fun toString() = "RecoveryReq(challengeId=$challengeId, recoveryCode=***, factor=$factor)"
}

@JsonClass(generateAdapter = true)
data class MfaVerifyResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
    val passed: Map<String, Boolean> = emptyMap(),
    @Json(name = "remaining_factors") val remainingFactors: List<String> = emptyList(),
)

// ── register/start (AND-053) ──
//
// Verified shapes (OpenAPI RegisterStartReq/Resp + frontend src/api/types.ts):
//  - delivery_method is optional (server default "email"); the web omits it, so we send null.
//  - phone is sent only when enable_sms_mfa is true (web rule).
//  - the response carries a free-form `status`, a verification flag, masked delivery fields, and a
//    nullable session_id (present only on the no-verification auto-login path).

@JsonClass(generateAdapter = true)
data class RegisterStartReq(
    @Json(name = "full_name") val fullName: String,
    val email: String,
    val password: String,
    @Json(name = "confirm_password") val confirmPassword: String,
    @Json(name = "delivery_method") val deliveryMethod: String? = null,
    val phone: String? = null,
    @Json(name = "enable_sms_mfa") val enableSmsMfa: Boolean = false,
    @Json(name = "enable_totp_mfa") val enableTotpMfa: Boolean = false,
) {
    override fun toString() =
        "RegisterStartReq(fullName=***, email=***, password=***, confirmPassword=***, " +
            "deliveryMethod=$deliveryMethod, phone=***, enableSmsMfa=$enableSmsMfa, " +
            "enableTotpMfa=$enableTotpMfa)"
}

@JsonClass(generateAdapter = true)
data class RegisterStartResp(
    val status: String,
    @Json(name = "verification_required") val verificationRequired: Boolean = false,
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,
    @Json(name = "delivery_destination") val deliveryDestination: String? = null,
    @Json(name = "session_id") val sessionId: String? = null,
)

// ── register/confirm (AND-054) ──
// Keyed on the registrant EMAIL (no challenge/registration id). Success may carry a session_id
// (auto-login) and an mfa_setup directive driving the MFA-enrollment handoff (AND-056).

@JsonClass(generateAdapter = true)
data class RegisterConfirmReq(
    val email: String,
    @Json(name = "confirmation_code") val confirmationCode: String,
) {
    override fun toString() = "RegisterConfirmReq(email=***, confirmationCode=***)"
}

@JsonClass(generateAdapter = true)
data class RegisterConfirmResp(
    val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "mfa_setup") val mfaSetup: List<String>? = null,
    @Json(name = "sms_phone") val smsPhone: String? = null,
)

// ── register/resend (AND-054) ──
// Re-sends the verification code; carries the MFA flags/phone captured at start (web parity).

@JsonClass(generateAdapter = true)
data class RegisterResendReq(
    val email: String,
    @Json(name = "delivery_method") val deliveryMethod: String = "email",
    val phone: String? = null,
    @Json(name = "enable_sms_mfa") val enableSmsMfa: Boolean = false,
    @Json(name = "enable_totp_mfa") val enableTotpMfa: Boolean = false,
) {
    override fun toString() =
        "RegisterResendReq(email=***, deliveryMethod=$deliveryMethod, phone=***, " +
            "enableSmsMfa=$enableSmsMfa, enableTotpMfa=$enableTotpMfa)"
}

@JsonClass(generateAdapter = true)
data class RegisterResendResp(
    val status: String,
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,
    @Json(name = "delivery_destination") val deliveryDestination: String? = null,
)

// ── register/check (AND-055) — email availability ──

@JsonClass(generateAdapter = true)
data class RegisterEmailCheckReq(val email: String) {
    override fun toString() = "RegisterEmailCheckReq(email=***)"
}

@JsonClass(generateAdapter = true)
data class RegisterEmailCheckResp(
    val available: Boolean,
    val status: String,
)

// ── passwordless / magic-link (AND-060/061) ──
//
// Verified shapes (OpenAPI PasswordlessStartReq/Resp + PasswordlessVerifyReq/Resp, frontend
// src/api/types.ts):
//  - start: request key is `username` (NOT `email`); response carries a required `status` plus an
//    optional `sent_to` array of opaque strings. There is NO resend_after / expires_in.
//  - verify: request is `{token}`; response carries a required `status`, an optional `session_id`,
//    `auth_required` (default false), an optional `challenge_id`, and `required_factors[]`.
// The token/username are PII-ish; request DTOs redact them in toString so logging can't leak them.

@JsonClass(generateAdapter = true)
data class PasswordlessStartReq(
    @Json(name = "username") val username: String,
) {
    override fun toString() = "PasswordlessStartReq(username=***)"
}

@JsonClass(generateAdapter = true)
data class PasswordlessStartResp(
    @Json(name = "status") val status: String,
    @Json(name = "sent_to") val sentTo: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class PasswordlessVerifyReq(
    @Json(name = "token") val token: String,
) {
    override fun toString() = "PasswordlessVerifyReq(token=***)"
}

@JsonClass(generateAdapter = true)
data class PasswordlessVerifyResp(
    @Json(name = "status") val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "auth_required") val authRequired: Boolean = false,
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)

// ── password-recovery/start (AND-057) ──
//
// Verified shapes (frontend src/api/types.ts: PasswordRecoveryStartReq/Resp). OpenAPI types the 200
// body as an open object, so every response field is nullable/defaulted — extra/missing keys never
// crash parsing. The response is FLAT (no nested delivery object, no auth_required flag).

@JsonClass(generateAdapter = true)
data class PasswordRecoveryStartReq(
    val username: String,
) {
    override fun toString() = "PasswordRecoveryStartReq(username=***)"
}

@JsonClass(generateAdapter = true)
data class PasswordRecoveryStartResp(
    val status: String? = null,
    @Json(name = "delivery_medium") val deliveryMedium: String? = null,
    @Json(name = "delivery_destination") val deliveryDestination: String? = null,
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)

// ── password-recovery/challenge (AND-058) ──
//
// Every body requires `username` AND `challenge_id` (OpenAPI). Code field names differ by factor:
// email/sms use `code`, totp uses `totp_code`, recovery uses `recovery_code` (+ `factor`). The
// begin step reuses ChallengeResp; verify reuses MfaVerifyResp (both already defined above).

@JsonClass(generateAdapter = true)
data class RecoveryChallengeBeginReq(
    val username: String,
    @Json(name = "challenge_id") val challengeId: String,
) {
    override fun toString() = "RecoveryChallengeBeginReq(username=***, challengeId=$challengeId)"
}

@JsonClass(generateAdapter = true)
data class RecoveryEmailSmsVerifyReq(
    val username: String,
    @Json(name = "challenge_id") val challengeId: String,
    val code: String,
) {
    override fun toString() = "RecoveryEmailSmsVerifyReq(username=***, challengeId=$challengeId, code=***)"
}

@JsonClass(generateAdapter = true)
data class RecoveryTotpVerifyReq(
    val username: String,
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "totp_code") val totpCode: String,
) {
    override fun toString() = "RecoveryTotpVerifyReq(username=***, challengeId=$challengeId, totpCode=***)"
}

@JsonClass(generateAdapter = true)
data class RecoveryCodeVerifyReq(
    val username: String,
    @Json(name = "challenge_id") val challengeId: String,
    val factor: String,
    @Json(name = "recovery_code") val recoveryCode: String,
) {
    override fun toString() =
        "RecoveryCodeVerifyReq(username=***, challengeId=$challengeId, factor=$factor, recoveryCode=***)"
}

// ── password-recovery/confirm (AND-059) ──
//
// Verified (OpenAPI PasswordRecoveryConfirmReq + frontend): required = username, confirmation_code,
// new_password; challenge_id optional/nullable. Success is OkResp ({ "ok": boolean }).

@JsonClass(generateAdapter = true)
data class PasswordRecoveryConfirmReq(
    val username: String,
    @Json(name = "confirmation_code") val confirmationCode: String,
    @Json(name = "new_password") val newPassword: String,
    @Json(name = "challenge_id") val challengeId: String? = null,
) {
    override fun toString() =
        "PasswordRecoveryConfirmReq(username=***, confirmationCode=***, newPassword=***, " +
            "challengeId=$challengeId)"
}

// ── WebAuthn / passkeys (AND-062) ──
//
// Verified shapes (OpenAPI WebAuthn schemas + frontend src/api/types.ts):
//  - register endpoints are authenticated (Bearer + cookie + X-CSRF-Token via the shared client);
//    authenticate endpoints are public. There is NO challenge_id on any WebAuthn schema.
//  - the begin responses carry a single opaque `options` object (additionalProperties:true) that is
//    forwarded verbatim to Credential Manager — modeled as a raw Map so Moshi never drops fields.
//  - register/begin sends an empty body; the label rides on register/finish only.
//  - register/finish responds with only `credential_id`; authenticate/finish responds with
//    `{status, session_id?}` (success keyed on status == "ok" && session_id present).
// The credential / options payloads are sensitive: request DTOs redact them in toString.

@JsonClass(generateAdapter = true)
data class WebAuthnRegisterBeginReq(
    @Json(name = "label") val label: String? = null,
) {
    override fun toString() = "WebAuthnRegisterBeginReq(label=$label)"
}

@JsonClass(generateAdapter = true)
data class WebAuthnRegisterBeginResp(
    @Json(name = "options") val options: Map<String, Any?> = emptyMap(),
) {
    override fun toString() = "WebAuthnRegisterBeginResp(options=***)"
}

@JsonClass(generateAdapter = true)
data class WebAuthnRegisterFinishReq(
    @Json(name = "credential") val credential: Map<String, Any?>,
    @Json(name = "label") val label: String? = null,
) {
    override fun toString() = "WebAuthnRegisterFinishReq(credential=***, label=$label)"
}

@JsonClass(generateAdapter = true)
data class WebAuthnRegisterFinishResp(
    @Json(name = "credential_id") val credentialId: String? = null,
)

@JsonClass(generateAdapter = true)
data class WebAuthnAuthBeginReq(
    @Json(name = "username") val username: String,
) {
    override fun toString() = "WebAuthnAuthBeginReq(username=***)"
}

@JsonClass(generateAdapter = true)
data class WebAuthnAuthBeginResp(
    @Json(name = "options") val options: Map<String, Any?> = emptyMap(),
) {
    override fun toString() = "WebAuthnAuthBeginResp(options=***)"
}

@JsonClass(generateAdapter = true)
data class WebAuthnAuthFinishReq(
    @Json(name = "username") val username: String,
    @Json(name = "credential") val credential: Map<String, Any?>,
) {
    override fun toString() = "WebAuthnAuthFinishReq(username=***, credential=***)"
}

@JsonClass(generateAdapter = true)
data class WebAuthnAuthFinishResp(
    @Json(name = "status") val status: String,
    @Json(name = "session_id") val sessionId: String? = null,
)

// ── SSO / SAML discovery (AND-063) ──
//
// Verified shapes (frontend src/api/types.ts: SsoInfoOut). OpenAPI types the 200 body as an open
// object, so every field is nullable/defaulted. The browser authorization endpoint (/saml/login) is
// NOT a Retrofit call — only discovery (getSsoInfo) lives on AuthApi.

@JsonClass(generateAdapter = true)
data class SsoInfoDto(
    @Json(name = "sso_available") val ssoAvailable: Boolean = false,
    @Json(name = "sso_only") val ssoOnly: Boolean = false,
    @Json(name = "sso_login_url") val ssoLoginUrl: String? = null,
    @Json(name = "provider_display_name") val providerDisplayName: String? = null,
    @Json(name = "provider_protocol") val providerProtocol: String? = null,
)

// ── MFA device management (AND-064) ──
//
// Verified shapes (OpenAPI request schemas + frontend src/api/types.ts). Per-type list endpoints (no
// unified /ui/mfa/devices); created_at is a numeric epoch (Long); the id field differs per type.
// Confirm keys differ: TOTP confirm carries device_id + two codes; SMS/email confirm carries
// challenge_id + code. SMS/email removal is a two-step begin/confirm challenge. Code/secret-bearing
// request DTOs redact in toString.

@JsonClass(generateAdapter = true)
data class TotpDeviceDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class SmsDeviceDto(
    @Json(name = "sms_device_id") val deviceId: String,
    @Json(name = "phone_e164") val phoneE164: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "pending") val pending: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class EmailDeviceDto(
    @Json(name = "email_device_id") val deviceId: String,
    @Json(name = "email") val email: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "pending") val pending: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class TotpDeviceListDto(val devices: List<TotpDeviceDto> = emptyList())

@JsonClass(generateAdapter = true)
data class SmsDeviceListDto(val devices: List<SmsDeviceDto> = emptyList())

@JsonClass(generateAdapter = true)
data class EmailDeviceListDto(val devices: List<EmailDeviceDto> = emptyList())

@JsonClass(generateAdapter = true)
data class TotpDeviceBeginReq(@Json(name = "label") val label: String? = null)

@JsonClass(generateAdapter = true)
data class TotpEnrollDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "secret") val secret: String,
    @Json(name = "qr_code_uri") val qrCodeUri: String,
) {
    override fun toString() = "TotpEnrollDto(deviceId=$deviceId, secret=***, qrCodeUri=***)"
}

@JsonClass(generateAdapter = true)
data class TotpDeviceConfirmReq(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "totp_code") val totpCode: String,
    @Json(name = "totp_code2") val totpCode2: String,
) {
    override fun toString() = "TotpDeviceConfirmReq(deviceId=$deviceId, totpCode=***, totpCode2=***)"
}

@JsonClass(generateAdapter = true)
data class TotpDeviceRemoveReq(@Json(name = "totp_code") val totpCode: String) {
    override fun toString() = "TotpDeviceRemoveReq(totpCode=***)"
}

@JsonClass(generateAdapter = true)
data class SmsDeviceBeginReq(
    @Json(name = "phone_e164") val phoneE164: String,
    @Json(name = "label") val label: String? = null,
) {
    override fun toString() = "SmsDeviceBeginReq(phoneE164=***, label=$label)"
}

@JsonClass(generateAdapter = true)
data class EmailDeviceBeginReq(
    @Json(name = "email") val email: String,
    @Json(name = "label") val label: String? = null,
) {
    override fun toString() = "EmailDeviceBeginReq(email=***, label=$label)"
}

@JsonClass(generateAdapter = true)
data class DeviceChallengeDto(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "sent_to") val sentTo: List<String> = emptyList(),
    @Json(name = "sms_device_id") val smsDeviceId: String? = null,
    @Json(name = "email_device_id") val emailDeviceId: String? = null,
)

@JsonClass(generateAdapter = true)
data class DeviceConfirmReq(
    @Json(name = "challenge_id") val challengeId: String,
    @Json(name = "code") val code: String,
) {
    override fun toString() = "DeviceConfirmReq(challengeId=$challengeId, code=***)"
}

@JsonClass(generateAdapter = true)
data class EnrollResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "sms_device_id") val smsDeviceId: String? = null,
    @Json(name = "email_device_id") val emailDeviceId: String? = null,
    @Json(name = "recovery_codes") val recoveryCodes: List<String> = emptyList(),
) {
    override fun toString() =
        "EnrollResultDto(ok=$ok, smsDeviceId=$smsDeviceId, emailDeviceId=$emailDeviceId, recoveryCodes=***)"
}
