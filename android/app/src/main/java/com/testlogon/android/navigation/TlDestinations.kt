package com.testlogon.android.navigation

import android.net.Uri

/**
 * Typed route catalogue for the single-Activity NavHost.
 *
 * Routes are string-based (Navigation-Compose), wrapped in objects so call sites never use bare
 * string literals. Argument-bearing routes expose a `build(...)` helper.
 *
 * SECURITY: never encode passwords, OTP codes, or session/CSRF tokens into route args (they can be
 * persisted to the saved-state Bundle). The MFA `challengeId` is an opaque, non-secret correlation
 * id and is acceptable.
 */

/** Top-level graphs the auth gate switches between. */
object TlGraphs {
    const val UNAUTHENTICATED = "graph_unauthenticated"
    const val AUTHENTICATED = "graph_authenticated"
}

/** Destinations inside the unauthenticated graph (AND-023). */
sealed class AuthDest(val route: String) {
    data object Login : AuthDest("auth/login?reason={reason}") {
        const val ARG_REASON = "reason"

        /** Builds the login route, optionally carrying a [LogoutReason] name (AND-044). */
        fun build(reason: String? = null): String =
            if (reason.isNullOrBlank()) "auth/login" else "auth/login?reason=${Uri.encode(reason)}"
    }

    data object Mfa : AuthDest("auth/mfa/{challengeId}?factors={factors}") {
        const val ARG_CHALLENGE_ID = "challengeId"
        const val ARG_FACTORS = "factors"

        /** [factors] is a comma-joined list of lowercase factor tokens (e.g. "totp,sms"). */
        fun build(challengeId: String, factors: List<String> = emptyList()): String {
            val joined = Uri.encode(factors.joinToString(","))
            return "auth/mfa/${Uri.encode(challengeId)}?factors=$joined"
        }
    }

    data object Register : AuthDest("auth/register")

    /**
     * Registration confirm/verify step (AND-054). Keyed on the registrant email (the confirm
     * handle); carries the server-resolved delivery hints and the MFA opt-in flags/phone captured
     * at start so Resend can re-send the same request shape.
     *
     * SECURITY: no password/OTP is encoded here. `email`/`phone` are non-secret contact handles
     * the user just typed; they ride as route args like the MFA `challengeId` does.
     */
    data object RegisterConfirm : AuthDest(
        "auth/register/confirm/{email}" +
            "?medium={medium}&destination={destination}" +
            "&smsMfa={smsMfa}&totpMfa={totpMfa}&phone={phone}",
    ) {
        const val ARG_EMAIL = "email"
        const val ARG_MEDIUM = "medium"
        const val ARG_DESTINATION = "destination"
        const val ARG_SMS_MFA = "smsMfa"
        const val ARG_TOTP_MFA = "totpMfa"
        const val ARG_PHONE = "phone"

        fun build(
            email: String,
            deliveryMedium: String? = null,
            deliveryDestination: String? = null,
            enableSmsMfa: Boolean = false,
            enableTotpMfa: Boolean = false,
            phone: String? = null,
        ): String {
            val q = buildString {
                append("?medium=").append(Uri.encode(deliveryMedium.orEmpty()))
                append("&destination=").append(Uri.encode(deliveryDestination.orEmpty()))
                append("&smsMfa=").append(enableSmsMfa)
                append("&totpMfa=").append(enableTotpMfa)
                append("&phone=").append(Uri.encode(phone.orEmpty()))
            }
            return "auth/register/confirm/${Uri.encode(email)}$q"
        }
    }

    /**
     * Placeholder MFA-enrollment destination for the registration → MFA-setup handoff (AND-056).
     * The real enrollment screens are owned by AND-064; this destination accepts the ordered factor
     * CSV + optional sms phone so the handoff can land here until AND-064 lands.
     */
    data object MfaSetup : AuthDest("auth/mfa-setup?factors={factors}&phone={phone}") {
        const val ARG_FACTORS = "factors"
        const val ARG_PHONE = "phone"

        fun build(factors: List<String>, smsPhone: String? = null): String {
            val joined = Uri.encode(factors.joinToString(","))
            return "auth/mfa-setup?factors=$joined&phone=${Uri.encode(smsPhone.orEmpty())}"
        }
    }

    data object Recovery : AuthDest("auth/recovery")
    data object MagicLink : AuthDest("auth/magic_link")

    /** Server-URL settings (AND-041); reachable pre-login from the Login screen. */
    data object ServerUrl : AuthDest("settings/server-url")
}

/** Destinations inside the authenticated graph (AND-024). */
sealed class MainDest(val route: String) {
    /** The bottom-nav shell host. */
    data object Shell : MainDest("main/shell")

    /** Active sessions list + revoke (AND-043), reached from Profile/Security. */
    data object ActiveSessions : MainDest("main/sessions")
}
