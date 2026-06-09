package com.testlogon.android.navigation

import com.testlogon.android.feature.shell.AuthedTab

/**
 * AND-067 — route constants the "More" hub links to, plus the set the authenticated graph registers.
 *
 * Tab routes (Profile) are handled inside the shell's inner NavController; full-screen destinations
 * (Sessions, MFA devices) are outer authenticated-graph routes. Coming-soon destinations are listed
 * so the hub can surface them Disabled; truly-absent routes are simply omitted (→ Hidden).
 */
object MoreRoutes {
    const val PROFILE = "more/profile"
    val SESSIONS: String get() = MainDest.ActiveSessions.route
    val MFA_DEVICES: String get() = MainDest.MfaDevices.route

    // AND-080: notification prefs now live under the Settings hub.
    val NOTIFICATIONS: String get() = MainDest.SettingsNotifications.route

    // AND-077: the Settings hub landing.
    val SETTINGS: String get() = MainDest.Settings.route
    const val HELP = "more/help"
    const val ABOUT = "more/about"

    /** Routes the hub treats as registered (real destinations or intentionally-surfaced stubs). */
    val REGISTERED: Set<String>
        get() = setOf(
            PROFILE,
            SESSIONS,
            MFA_DEVICES,
            NOTIFICATIONS,
            SETTINGS,
            HELP,
            ABOUT,
        )
}

/** Resolves a [MoreRoutes] target to an in-shell tab where applicable. */
fun moreRouteToTab(route: String): AuthedTab? = when (route) {
    MoreRoutes.PROFILE -> AuthedTab.ME
    else -> null
}
