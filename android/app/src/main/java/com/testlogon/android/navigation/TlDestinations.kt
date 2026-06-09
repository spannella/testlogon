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

    /**
     * Password-recovery entry / start step (AND-057). Username-only; no args.
     * (The legacy `auth/recovery` placeholder route is replaced by `recovery/start`.)
     */
    data object Recovery : AuthDest("recovery/start")

    /**
     * Password-recovery challenge step (AND-058). Carries the start-issued, non-secret handles:
     * `username`, `challengeId`, the required-factor CSV, and the masked delivery descriptor.
     *
     * SECURITY: no password/OTP code is encoded here — only the same class of non-secret correlation
     * handles the MFA route already carries. The verified code is handed to the confirm step via the
     * back-stack entry's SavedStateHandle, never via a route arg.
     */
    data object RecoveryChallenge : AuthDest(
        "recovery/challenge/{username}/{challengeId}" +
            "?factors={factors}&medium={medium}&destination={destination}",
    ) {
        const val ARG_USERNAME = "username"
        const val ARG_CHALLENGE_ID = "challengeId"
        const val ARG_FACTORS = "factors"
        const val ARG_MEDIUM = "medium"
        const val ARG_DESTINATION = "destination"

        fun build(
            username: String,
            challengeId: String,
            factors: List<String> = emptyList(),
            deliveryMedium: String? = null,
            deliveryDestination: String? = null,
        ): String {
            val q = buildString {
                append("?factors=").append(Uri.encode(factors.joinToString(",")))
                append("&medium=").append(Uri.encode(deliveryMedium.orEmpty()))
                append("&destination=").append(Uri.encode(deliveryDestination.orEmpty()))
            }
            return "recovery/challenge/${Uri.encode(username)}/${Uri.encode(challengeId)}$q"
        }
    }

    /**
     * Password-recovery confirm step (AND-059). Carries the non-secret `username` + `challengeId`.
     *
     * SECURITY: the verified `confirmation_code` is NOT a route arg — it is set on this entry's
     * SavedStateHandle by the challenge step (key [KEY_CODE]) so it is never persisted into a route.
     */
    data object RecoveryConfirm : AuthDest("recovery/confirm/{username}/{challengeId}") {
        const val ARG_USERNAME = "username"
        const val ARG_CHALLENGE_ID = "challengeId"

        /** SavedStateHandle key for the verified confirmation code passed in from the challenge step. */
        const val KEY_CODE = "recovery_confirmation_code"

        fun build(username: String, challengeId: String): String =
            "recovery/confirm/${Uri.encode(username)}/${Uri.encode(challengeId)}"
    }

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
