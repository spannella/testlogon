package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import com.testlogon.android.feature.account.MfaDevicesRoute
import com.testlogon.android.feature.sessions.ActiveSessionsRoute
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
            )
        }
        composable(MainDest.ActiveSessions.route) {
            ActiveSessionsRoute(onBack = { navController.popBackStack() })
        }
        composable(MainDest.MfaDevices.route) {
            MfaDevicesRoute(onBack = { navController.popBackStack() })
        }
    }
}
