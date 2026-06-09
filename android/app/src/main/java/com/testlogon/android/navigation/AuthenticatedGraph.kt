package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import com.testlogon.android.feature.account.MfaDevicesRoute
import com.testlogon.android.feature.profile.edit.EditProfileRoute
import com.testlogon.android.feature.sessions.ActiveSessionsRoute
import com.testlogon.android.feature.settings.account.AccountSettingsRoute
import com.testlogon.android.feature.settings.appearance.AppearanceSettingsRoute
import com.testlogon.android.feature.settings.hub.SettingsHubRoute
import com.testlogon.android.feature.settings.media.MediaPreferencesRoute
import com.testlogon.android.feature.settings.misc.PrivacySettingsScreen
import com.testlogon.android.feature.settings.misc.SecuritySettingsScreen
import com.testlogon.android.feature.settings.notifications.NotificationPreferencesRoute
import com.testlogon.android.feature.shell.AuthedShellScreen

/**
 * Registers the authenticated graph (AND-024). Its start destination is the bottom-nav shell.
 * Entry into this graph is reserved for the auth gate (AND-025); no unauthenticated screen links
 * here directly. The Active Sessions screen (AND-043) is a full-screen destination reached from
 * the Profile tab.
 */
fun NavGraphBuilder.authenticatedGraph(navController: NavHostController) {
    navigation(
        route = TlGraphs.AUTHENTICATED,
        startDestination = MainDest.Shell.route,
    ) {
        composable(MainDest.Shell.route) {
            AuthedShellScreen(
                onOpenSessions = {
                    navController.navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
                },
                onOpenMfaDevices = {
                    navController.navigate(MainDest.MfaDevices.route) { launchSingleTop = true }
                },
                onEditProfile = {
                    navController.navigate(MainDest.EditProfile.route) { launchSingleTop = true }
                },
                onOpenRoute = { route ->
                    navController.navigate(route) { launchSingleTop = true }
                },
            )
        }
        composable(MainDest.ActiveSessions.route) {
            ActiveSessionsRoute(onBack = { navController.popBackStack() })
        }
        composable(MainDest.MfaDevices.route) {
            MfaDevicesRoute(onBack = { navController.popBackStack() })
        }
        // AND-077..082: Settings hub + subsections.
        settingsDestinations(navController)
        // AND-072: edit own profile, reached from the Profile tab.
        composable(MainDest.EditProfile.route) {
            EditProfileRoute(onNavigateBack = { navController.popBackStack() })
        }
        // AND-073: public profile (also registered unauthenticated for shared links).
        publicProfileDestination(navController)
    }
}

/**
 * AND-077..082 — registers the Settings hub and its six subsections against the route constants in
 * [MainDest]. Destinations that belong to other tickets/epics (closure, data export) are handed off
 * via callbacks; until those land they resolve to existing surfaces or no-op safely.
 */
private fun NavGraphBuilder.settingsDestinations(navController: NavHostController) {
    composable(MainDest.Settings.route) {
        SettingsHubRoute(
            onOpenSection = { route -> navController.navigate(route) { launchSingleTop = true } },
            onBack = { navController.popBackStack() },
        )
    }
    composable(MainDest.SettingsAccount.route) {
        AccountSettingsRoute(
            onBack = { navController.popBackStack() },
            onOpenSessions = {
                navController.navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
            },
            onOpenMfaDevices = {
                navController.navigate(MainDest.MfaDevices.route) { launchSingleTop = true }
            },
            onOpenPrivacy = {
                navController.navigate(MainDest.SettingsPrivacy.route) { launchSingleTop = true }
            },
            // E50 reactivation/closure flows are out of scope; route to the privacy/lifecycle
            // surface as a safe handoff until those tickets register their own destinations.
            onReactivate = {
                navController.navigate(MainDest.SettingsPrivacy.route) { launchSingleTop = true }
            },
            onCloseAccount = {
                navController.navigate(MainDest.SettingsPrivacy.route) { launchSingleTop = true }
            },
        )
    }
    composable(MainDest.SettingsSecurity.route) {
        SecuritySettingsScreen(
            onBack = { navController.popBackStack() },
            onOpenSessions = {
                navController.navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
            },
            onOpenMfaDevices = {
                navController.navigate(MainDest.MfaDevices.route) { launchSingleTop = true }
            },
        )
    }
    composable(MainDest.SettingsNotifications.route) {
        NotificationPreferencesRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsMedia.route) {
        MediaPreferencesRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsAppearance.route) {
        AppearanceSettingsRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsPrivacy.route) {
        PrivacySettingsScreen(
            onBack = { navController.popBackStack() },
            // Data export / deletion execution is owned by E50; handoff is a no-op for now.
            onRequestExport = {},
            onDeleteData = {},
        )
    }
}
