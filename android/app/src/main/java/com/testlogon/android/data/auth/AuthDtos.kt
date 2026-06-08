package com.testlogon.android.data.auth

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

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
    val ip: String,
)

@JsonClass(generateAdapter = true)
data class SessionInfo(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "is_current") val isCurrent: Boolean,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "last_seen_at") val lastSeenAt: Long,
    val ip: String,
    @Json(name = "user_agent") val userAgent: String,
    val revoked: Boolean,
    @Json(name = "revoked_at") val revokedAt: Long? = null,
)

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
