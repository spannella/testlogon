package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import com.testlogon.android.feature.shell.AuthedShellScreen

/**
 * Registers the authenticated graph (AND-024). Its start destination is the bottom-nav shell.
 * Entry into this graph is reserved for the auth gate (AND-025); no unauthenticated screen links
 * here directly.
 */
fun NavGraphBuilder.authenticatedGraph(@Suppress("UNUSED_PARAMETER") navController: NavHostController) {
    navigation(
        route = TlGraphs.AUTHENTICATED,
        startDestination = MainDest.Shell.route,
    ) {
        composable(MainDest.Shell.route) {
            AuthedShellScreen()
        }
    }
}
