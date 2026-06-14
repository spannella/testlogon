package com.testlogon.android.data.auth

/**
 * Typed MFA factor token. Unknown server tokens are retained as [Unknown] so an unrecognized
 * required factor is never silently dropped (forward-compatibility; fail-closed for security).
 */
sealed interface MfaFactor {
    data object Totp : MfaFactor
    data object Sms : MfaFactor
    data object Email : MfaFactor
    data object Recovery : MfaFactor
    data class Unknown(val raw: String) : MfaFactor

    /** Lowercase wire token used in request paths / bodies. */
    val wire: String
        get() = when (this) {
            Totp -> "totp"
            Sms -> "sms"
            Email -> "email"
            Recovery -> "recovery"
            is Unknown -> raw
        }

    companion object {
        fun fromWire(raw: String): MfaFactor = when (raw.trim().lowercase()) {
            "totp" -> Totp
            "sms" -> Sms
            "email" -> Email
            "recovery" -> Recovery
            else -> Unknown(raw)
        }
    }
}

/** Domain principal mapped from `GET /ui/me`. */
data class User(
    val userSub: String,
    val sessionId: String,
    val ip: String,
)

/**
 * Outcome of [AuthRepository.login] — the session/start branch (AND-028).
 *
 * - [Authenticated]: session completed in one step (`!auth_required && session_id` present);
 *   `getMe()` has already populated the auth state store.
 * - [MfaRequired]: the caller must drive the MFA sub-flow keyed by [challengeId].
 */
sealed interface LoginOutcome {
    data class Authenticated(val user: User) : LoginOutcome
    data class MfaRequired(
        val challengeId: String,
        val factors: List<MfaFactor>,
    ) : LoginOutcome
}

/**
 * Outcome of an MFA verify/begin-verify/recovery step (AND-034..038).
 *
 * - [Authenticated]: the last factor passed, finalize + getMe succeeded.
 * - [FactorsRemaining]: at least one factor is still required; continue the flow.
 */
sealed interface MfaVerifyOutcome {
    data class Authenticated(val user: User) : MfaVerifyOutcome
    data class FactorsRemaining(val factors: List<MfaFactor>) : MfaVerifyOutcome
}
