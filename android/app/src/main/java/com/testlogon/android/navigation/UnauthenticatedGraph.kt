package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navigation
import com.testlogon.android.feature.auth.LoginPlaceholderScreen
import com.testlogon.android.feature.auth.MagicLinkPlaceholderScreen
import com.testlogon.android.feature.auth.MfaPlaceholderScreen
import com.testlogon.android.feature.auth.RecoveryPlaceholderScreen
import com.testlogon.android.feature.auth.RegisterPlaceholderScreen

/**
 * Registers the unauthenticated (logged-out) graph (AND-023). Login is the start destination.
 * Screens receive lambda callbacks only — never the [NavHostController].
 */
fun NavGraphBuilder.unauthenticatedGraph(navController: NavHostController) {
    navigation(
        route = TlGraphs.UNAUTHENTICATED,
        startDestination = AuthDest.Login.route,
    ) {
        composable(AuthDest.Login.route) {
            LoginPlaceholderScreen(
                onContinueToMfa = { challengeId ->
                    navController.navigate(AuthDest.Mfa.build(challengeId)) { launchSingleTop = true }
                },
                onRegister = { navController.navigate(AuthDest.Register.route) { launchSingleTop = true } },
                onRecovery = { navController.navigate(AuthDest.Recovery.route) { launchSingleTop = true } },
                onMagicLink = { navController.navigate(AuthDest.MagicLink.route) { launchSingleTop = true } },
            )
        }
        composable(
            route = AuthDest.Mfa.route,
            arguments = listOf(navArgument(AuthDest.Mfa.ARG_CHALLENGE_ID) { type = NavType.StringType }),
        ) { entry ->
            val challengeId = entry.arguments?.getString(AuthDest.Mfa.ARG_CHALLENGE_ID).orEmpty()
            MfaPlaceholderScreen(challengeId = challengeId, onBack = { navController.popBackStack() })
        }
        composable(AuthDest.Register.route) {
            RegisterPlaceholderScreen(onBack = { navController.popBackStack() })
        }
        composable(AuthDest.Recovery.route) {
            RecoveryPlaceholderScreen(onBack = { navController.popBackStack() })
        }
        composable(AuthDest.MagicLink.route) {
            MagicLinkPlaceholderScreen(onBack = { navController.popBackStack() })
        }
    }
}
