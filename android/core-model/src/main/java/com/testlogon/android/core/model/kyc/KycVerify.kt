package com.testlogon.android.core.model.kyc

/**
 * Batch-9 (#18) - transport DTOs for the Tier-1 email/phone verification flow under the `verify` namespace.
 *
 * RECONCILIATION NOTE (same as the rest of the kyc package): core-model has NO Moshi dependency and NO Moshi
 * codegen, so these DTOs carry NO annotations and are decoded reflectively (KotlinJsonAdapterFactory) with
 * property names mapped VERBATIM to the snake_case wire keys.
 *
 * Wire contract (B-KYC3, verified on prod):
 *   POST v1/kyc/tiers/me/verify/email/start   { email? }  -> { ok, channel, target, expires_in_seconds, dev_code? }
 *   POST v1/kyc/tiers/me/verify/email/confirm { code }    -> { ok, channel, email_verified }
 *   POST v1/kyc/tiers/me/verify/phone/start   { phone }   -> { ok, channel, target, expires_in_seconds, dev_code? }
 *   POST v1/kyc/tiers/me/verify/phone/confirm { code }    -> { ok, channel, phone_verified }
 *
 * The server returns a `dev_code` ONLY in dev_mode so the app can complete the flow with no real inbox / SMS
 * gateway. Every response field is OPTIONAL (nullable + default) so a shape change never throws on decode.
 */

/** Body for POST .../verify/email/start (email optional: server falls back to the account email). */
data class KycVerifyEmailStartRequestDto(
    val email: String? = null,
)

/** Body for POST .../verify/phone/start (phone required, 4..32 chars). */
data class KycVerifyPhoneStartRequestDto(
    val phone: String,
)

/** Body for both .../verify/{email,phone}/confirm (code required, 4..10 chars). */
data class KycVerifyConfirmRequestDto(
    val code: String,
)

/** 200 response for a verify START call. All fields optional (server response is open-shaped). */
data class KycVerifyStartOutDto(
    val ok: Boolean? = null,
    val channel: String? = null,
    val target: String? = null,
    val expires_in_seconds: Int? = null,
    val dev_code: String? = null,
)

/** 200 response for a verify CONFIRM call. The relevant verified flag is set on success. */
data class KycVerifyConfirmOutDto(
    val ok: Boolean? = null,
    val channel: String? = null,
    val email_verified: Boolean? = null,
    val phone_verified: Boolean? = null,
)
