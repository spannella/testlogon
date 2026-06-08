package com.testlogon.android.data.auth

/**
 * Domain types for the self-service registration flow (AND-053..056).
 *
 * These translate the wire DTOs ([RegisterStartResp] / [RegisterConfirmResp] / …) into typed
 * outcomes the feature layer branches on, so ViewModels never touch raw HTTP/Moshi shapes.
 */

/** Outcome of [RegisterRepository.registerStart] (AND-053). */
sealed interface RegisterStartOutcome {
    /**
     * The backend sent a verification code; the confirm step (AND-054) must collect it.
     * Carries the registrant [email] (the confirm handle) plus the server-resolved delivery hints.
     */
    data class VerificationRequired(
        val email: String,
        val deliveryMedium: String?,
        val deliveryDestination: String?,
    ) : RegisterStartOutcome

    /** No verification needed and a session was established — the user is already authenticated. */
    data class Authenticated(val user: User) : RegisterStartOutcome

    /** No verification needed and no session — show success and route the user to sign in. */
    data object VerifiedSignIn : RegisterStartOutcome
}

/** Outcome of [RegisterRepository.confirm] (AND-054 + AND-056 handoff). */
sealed interface RegisterConfirmOutcome {
    /**
     * Confirm succeeded and a session was established. [handoff] describes any pending MFA
     * enrollment the user opted into; [MfaSetupHandoff.isRequired] is false when none remains.
     */
    data class Authenticated(val user: User, val handoff: MfaSetupHandoff) : RegisterConfirmOutcome

    /** Confirm succeeded but no session was established — route to sign in (web parity). */
    data class VerifiedSignIn(val email: String) : RegisterConfirmOutcome
}

/** A single ordered MFA factor the freshly-confirmed account must enroll (AND-056). */
enum class MfaSetupFactor(val wire: String) {
    Totp("totp"),
    Sms("sms"),
    Email("email"),
    ;

    companion object {
        /** Maps a wire token to a factor, or null for an unknown token (dropped, forward-compat). */
        fun fromWireOrNull(raw: String): MfaSetupFactor? = when (raw.trim().lowercase()) {
            "totp", "authenticator" -> Totp
            "sms" -> Sms
            "email" -> Email
            else -> null
        }
    }
}

/**
 * Ordered MFA-enrollment directive derived from a confirm response (AND-056). Empty [factors]
 * means "no pending MFA" → route straight into the app.
 */
data class MfaSetupHandoff(
    val factors: List<MfaSetupFactor> = emptyList(),
    val smsPhone: String? = null,
    val email: String? = null,
) {
    val isRequired: Boolean get() = factors.isNotEmpty()
}

/**
 * Pure mapper from the wire `mfa_setup`/`sms_phone` to the typed handoff (AND-056 FR-7).
 * Unknown factor tokens are dropped; duplicates de-duped; order preserved. Blank phone → null.
 */
fun RegisterConfirmResp.toMfaSetupHandoff(registeredEmail: String?): MfaSetupHandoff {
    val factors = mfaSetup
        ?.mapNotNull(MfaSetupFactor::fromWireOrNull)
        ?.distinct()
        .orEmpty()
    return MfaSetupHandoff(
        factors = factors,
        smsPhone = smsPhone?.takeIf { it.isNotBlank() },
        email = registeredEmail?.takeIf { it.isNotBlank() },
    )
}

/** Advisory email-availability state for the inline register check (AND-055). */
enum class EmailAvailability { Unknown, Checking, Available, Taken, Error }
