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
