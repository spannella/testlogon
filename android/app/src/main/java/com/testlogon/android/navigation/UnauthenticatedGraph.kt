package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navigation
import com.testlogon.android.feature.auth.MagicLinkPlaceholderScreen
import com.testlogon.android.feature.auth.RecoveryPlaceholderScreen
import com.testlogon.android.feature.auth.RegisterPlaceholderScreen
import com.testlogon.android.feature.auth.login.LoginRoute
import com.testlogon.android.feature.auth.mfa.MfaRoute

/**
 * Registers the unauthenticated (logged-out) graph (AND-023). Login is the start destination.
 *
 * Login and MFA are the real screens (AND-030/031/039/040); Register/Recovery/MagicLink remain
 * placeholders (later tickets). On a successful login/MFA the auth gate (AppNavHost) swaps to the
 * authenticated graph once [AuthStateProvider] flips, so the navigate-home callbacks are no-ops
 * here — the gate owns that transition and clears the back stack across the auth boundary.
 */
fun NavGraphBuilder.unauthenticatedGraph(navController: NavHostController) {
    navigation(
        route = TlGraphs.UNAUTHENTICATED,
        startDestination = AuthDest.Login.route,
    ) {
        composable(AuthDest.Login.route) {
            LoginRoute(
                onNavigateToMfa = { challengeId, factors ->
                    navController.navigate(
                        AuthDest.Mfa.build(challengeId, factors.map { it.wire }),
                    ) { launchSingleTop = true }
                },
                onNavigateHome = { /* auth gate swaps graphs once getMe sets the session */ },
                onRegister = {
                    navController.navigate(AuthDest.Register.route) { launchSingleTop = true }
                },
                onRecovery = {
                    navController.navigate(AuthDest.Recovery.route) { launchSingleTop = true }
                },
            )
        }
        composable(
            route = AuthDest.Mfa.route,
            arguments = listOf(
                navArgument(AuthDest.Mfa.ARG_CHALLENGE_ID) { type = NavType.StringType },
                navArgument(AuthDest.Mfa.ARG_FACTORS) {
                    type = NavType.StringType
                    defaultValue = ""
                },
            ),
        ) {
            MfaRoute(
                onNavigateHome = { /* auth gate swaps graphs once finalize+getMe set the session */ },
                onNavigateToLogin = {
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.Login.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
            )
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
