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
    data object Login : AuthDest("auth/login")

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
}

/** Destinations inside the authenticated graph (AND-024). */
sealed class MainDest(val route: String) {
    /** The bottom-nav shell host. */
    data object Shell : MainDest("main/shell")
}
