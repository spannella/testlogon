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

    /** Passwordless / magic-link start (AND-060). Reached from the Login screen affordance. */
    data object MagicLink : AuthDest("auth/magic-link")

    /**
     * Passwordless / magic-link deep-link verify (AND-061). Carries the one-time `token` query arg
     * extracted from the email link's URI; the screen exchanges it for a session / MFA challenge.
     *
     * SECURITY: the one-time token is sensitive but is unavoidably a deep-link query param (the link
     * the user taps). It lives only in the nav arg / SavedStateHandle, is never logged, and the
     * destination is popped after a successful verify so it cannot be replayed from the back stack.
     */
    data object MagicLinkVerify : AuthDest("auth/magic-link-verify?token={token}") {
        const val ARG_TOKEN = "token"

        /** The deep-link path the email link points at, on both the prod (HTTPS) and dev (HTTP) hosts. */
        const val DEEP_LINK_PATH = "/magic-link-verify"

        fun build(token: String): String = "auth/magic-link-verify?token=${Uri.encode(token)}"
    }

    /** Server-URL settings (AND-041); reachable pre-login from the Login screen. */
    data object ServerUrl : AuthDest("settings/server-url")

    /**
     * SSO / SAML callback deep-link target (AND-063). The ACS redirect returns here; the Login screen
     * forwards the URI to LoginViewModel.onSsoRedirect, which finalizes via getMe or maps ?error=.
     *
     * SECURITY: the backend does not echo a client `state`; the local `state` lives in SsoStateStore,
     * never in a route arg. Only the `error` code (if any) rides as a query param.
     */
    data object SsoCallback : AuthDest("auth/sso/callback?error={error}") {
        const val ARG_ERROR = "error"

        /** Shared callback path for both the prod App Link (HTTPS) and the dev custom scheme. */
        const val DEEP_LINK_PATH = "/auth/sso/callback"
    }
}

/** Destinations inside the authenticated graph (AND-024). */
sealed class MainDest(val route: String) {
    /** The bottom-nav shell host. */
    data object Shell : MainDest("main/shell")

    /** Active sessions list + revoke (AND-043), reached from Profile/Security. */
    data object ActiveSessions : MainDest("main/sessions")

    /** MFA device management (AND-064), reached from Profile → Security. */
    data object MfaDevices : MainDest("main/mfa-devices")

    /** Edit own profile (AND-072), reached from the Profile tab's own-profile screen. */
    data object EditProfile : MainDest("profile/edit")

    /** Settings hub landing (AND-077), reached from the More hub / Profile. */
    data object Settings : MainDest("settings")

    /** Settings → Account status & lifecycle entry (AND-082). */
    data object SettingsAccount : MainDest("settings/account")

    /** Settings → Security aggregation (links to sessions / MFA). (AND-077) */
    data object SettingsSecurity : MainDest("settings/security")

    /** Settings → Notification preferences (AND-080). */
    data object SettingsNotifications : MainDest("settings/notifications")

    /** Settings → Media (call) preferences (AND-079). */
    data object SettingsMedia : MainDest("settings/media")

    /** Settings → Appearance / theme (AND-081). */
    data object SettingsAppearance : MainDest("settings/appearance")

    /** Settings → Privacy & data export entry (handoff). (AND-082) */
    data object SettingsPrivacy : MainDest("settings/privacy")

    /** Notification center — paged list of notifications (AND-085). */
    data object Notifications : MainDest("notifications")

    /** Alert preferences — email/SMS alert TARGET management (AND-088). */
    data object SettingsAlerts : MainDest("settings/alerts")
}

/**
 * Public profile by identifier (AND-073), `/u/{identifier}`.
 *
 * Registered in both graphs so a shared link opens whether or not the viewer is signed in (the public
 * read is auth-optional). Reached in-app via [build] and by an App Link / custom-scheme deep link.
 */
data object PublicProfileDest {
    const val ROUTE = "profile/public/{identifier}"
    const val ARG_IDENTIFIER = "identifier"

    /** Web path the App Link mirrors: https://HOST/u/:identifier. */
    const val DEEP_LINK_PATH = "/u"

    fun build(identifier: String): String = "profile/public/${Uri.encode(identifier)}"
}
