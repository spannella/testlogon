package com.testlogon.android.data.auth

/**
 * Domain types for the password-recovery flow (AND-057/058/059).
 *
 * These translate the wire DTOs into typed outcomes the feature layer branches on, so recovery
 * ViewModels never touch raw HTTP/Moshi shapes. The flow is unauthenticated and is bound together by
 * the start-issued `challenge_id` PLUS the `username` (both required on every challenge/confirm body).
 */

/** Recovery challenge factor. Unknown server tokens are retained so they are never silently dropped. */
sealed interface RecoveryFactor {
    data object Email : RecoveryFactor
    data object Sms : RecoveryFactor
    data object Totp : RecoveryFactor
    data object Recovery : RecoveryFactor
    data class Unknown(val raw: String) : RecoveryFactor

    /** Whether this factor delivers a code (email/sms call `begin`); totp/recovery do not. */
    val requiresBegin: Boolean get() = this == Email || this == Sms

    /** Lowercase wire token used in request paths / bodies. */
    val wire: String
        get() = when (this) {
            Email -> "email"
            Sms -> "sms"
            Totp -> "totp"
            Recovery -> "recovery"
            is Unknown -> raw
        }

    companion object {
        fun fromWire(raw: String): RecoveryFactor = when (raw.trim().lowercase()) {
            "email" -> Email
            "sms" -> Sms
            "totp" -> Totp
            "recovery" -> Recovery
            else -> Unknown(raw)
        }
    }
}

/**
 * Outcome of [PasswordRecoveryRepository.start] (AND-057).
 *
 * - [Challenge]: the backend issued a challenge → drive the per-factor verify step (AND-058).
 * - [Sent]: no challenge required (e.g. emailed-link variant) → show a terminal "check your X" state.
 */
sealed interface RecoveryStartOutcome {
    data class Challenge(
        val challengeId: String,
        val requiredFactors: List<RecoveryFactor>,
        val deliveryMedium: String?,
        val deliveryDestination: String?,
    ) : RecoveryStartOutcome

    data class Sent(
        val deliveryMedium: String?,
        val deliveryDestination: String?,
    ) : RecoveryStartOutcome
}

/**
 * Outcome of [PasswordRecoveryRepository.beginChallenge] (AND-058). The masked destination, when the
 * backend echoes one, is surfaced so the code-entry screen can render it.
 */
data class RecoveryBeginOutcome(
    val maskedDestinations: List<String> = emptyList(),
)

/**
 * Outcome of [PasswordRecoveryRepository.verifyChallenge] (AND-058). On a passing verification the
 * (now-verified) challenge is handed to AND-059; the optional [recoveryToken] is forwarded in-memory.
 */
data class RecoveryVerifyOutcome(
    val challengeId: String,
    val recoveryToken: String?,
)
