package com.testlogon.android.navigation

import com.testlogon.android.feature.messaging.nav.MessagingRoutes
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

    // AND-085: the notification center (inbox list).
    val NOTIFICATION_CENTER: String get() = MainDest.Notifications.route

    // AND-120..124: the messaging conversation list (inbox), first M3 two-user feature.
    val MESSAGES: String get() = MessagingRoutes.LIST

    // AND-088: alert preferences (email/SMS target management).
    val ALERT_PREFS: String get() = MainDest.SettingsAlerts.route

    // AND-091: account activity feed.
    val ACTIVITY: String get() = MainDest.Activity.route

    // AND-092: saved / bookmarks.
    val SAVED: String get() = MainDest.Saved.route

    // AND-093: achievements (earned/locked + progress).
    val ACHIEVEMENTS: String get() = MainDest.Achievements.route

    // AND-077: the Settings hub landing.
    val SETTINGS: String get() = MainDest.Settings.route
    const val HELP = "more/help"
    const val ABOUT = "more/about"

    /** Routes the hub treats as registered (real destinations or intentionally-surfaced stubs). */
    val REGISTERED: Set<String>
        get() = setOf(
            PROFILE,
            MESSAGES,
            SESSIONS,
            MFA_DEVICES,
            NOTIFICATION_CENTER,
            NOTIFICATIONS,
            ALERT_PREFS,
            ACTIVITY,
            SAVED,
            ACHIEVEMENTS,
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
