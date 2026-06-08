package com.testlogon.android.core.data.telemetry

/** Coarse stage of the auth flow an event belongs to. */
enum class AuthStage { LOGIN, MFA_BEGIN, MFA_VERIFY, FINALIZE, REFRESH, LOGOUT, ME }

/** Lifecycle phase of an auth step. */
enum class AuthOutcome { ATTEMPT, SUCCESS, FAILURE }

/** MFA factor, used only as a coarse (non-secret) label. */
enum class AuthFactor { TOTP, SMS, EMAIL, RECOVERY, UNKNOWN }

/**
 * Typed failure classification derived from the network/HTTP outcome — never carries raw error
 * text or `detail` strings (only this enum + numeric status are ever logged).
 */
enum class AuthFailureReason {
    INVALID_CREDENTIALS,
    MFA_REJECTED,
    CSRF_MISSING,
    SESSION_EXPIRED,
    TIMEOUT,
    CONNECT_FAILED,
    DNS_FAILED,
    SERVER_5XX,
    MALFORMED_RESPONSE,
    UNKNOWN,
}

/**
 * AND-052 — sealed hierarchy of redacted auth telemetry events.
 *
 * Events carry ONLY non-secret, coarse data. No password, OTP/SMS/email code, cookie value, CSRF
 * token, raw `challenge_id`, or raw username is ever placed on an event. The raw `challenge_id` is
 * always reduced to a short salted hash ([challengeRef]); the username is reduced to a presence
 * boolean. Attribute maps are assembled by [toRecord] and pass through the [Redactor] before any
 * sink sees them.
 */
sealed interface AuthEvent {
    val stage: AuthStage
    val outcome: AuthOutcome
    val elapsedMs: Long?

    data class LoginAttempt(val userPresent: Boolean) : AuthEvent {
        override val stage = AuthStage.LOGIN
        override val outcome = AuthOutcome.ATTEMPT
        override val elapsedMs: Long? = null
    }

    data class LoginSuccess(
        val requiredFactors: List<AuthFactor>,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.LOGIN
        override val outcome = AuthOutcome.SUCCESS
    }

    data class LoginFailure(
        val reason: AuthFailureReason,
        val httpStatus: Int? = null,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.LOGIN
        override val outcome = AuthOutcome.FAILURE
    }

    data class MfaBegin(val factor: AuthFactor, val challengeId: String) : AuthEvent {
        override val stage = AuthStage.MFA_BEGIN
        override val outcome = AuthOutcome.ATTEMPT
        override val elapsedMs: Long? = null
    }

    data class MfaVerifyAttempt(val factor: AuthFactor, val challengeId: String) : AuthEvent {
        override val stage = AuthStage.MFA_VERIFY
        override val outcome = AuthOutcome.ATTEMPT
        override val elapsedMs: Long? = null
    }

    data class MfaSuccess(
        val factor: AuthFactor,
        val challengeId: String,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.MFA_VERIFY
        override val outcome = AuthOutcome.SUCCESS
    }

    data class MfaFailure(
        val factor: AuthFactor,
        val reason: AuthFailureReason,
        val remainingFactors: Int,
        val httpStatus: Int? = null,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.MFA_VERIFY
        override val outcome = AuthOutcome.FAILURE
    }

    data class FinalizeResult(
        override val outcome: AuthOutcome,
        val reason: AuthFailureReason? = null,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.FINALIZE
    }

    data class RefreshResult(
        override val outcome: AuthOutcome,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.REFRESH
    }

    data class LogoutResult(
        override val outcome: AuthOutcome,
        override val elapsedMs: Long? = null,
    ) : AuthEvent {
        override val stage = AuthStage.LOGOUT
    }
}
