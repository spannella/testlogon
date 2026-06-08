package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navigation
import com.testlogon.android.feature.auth.MagicLinkPlaceholderScreen
import com.testlogon.android.feature.auth.MfaSetupPlaceholderScreen
import com.testlogon.android.feature.auth.RecoveryPlaceholderScreen
import com.testlogon.android.feature.auth.login.LoginRoute
import com.testlogon.android.feature.auth.mfa.MfaRoute
import com.testlogon.android.feature.auth.register.RegisterConfirmRoute
import com.testlogon.android.feature.auth.register.RegisterRoute
import com.testlogon.android.feature.settings.ServerUrlSettingsRoute

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
        composable(
            route = AuthDest.Login.route,
            arguments = listOf(
                navArgument(AuthDest.Login.ARG_REASON) {
                    type = NavType.StringType
                    nullable = true
                    defaultValue = null
                },
            ),
        ) {
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
                onOpenServerSettings = {
                    navController.navigate(AuthDest.ServerUrl.route) { launchSingleTop = true }
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
            RegisterRoute(
                onNavigateToConfirm = { email, medium, destination, smsMfa, totpMfa, phone ->
                    navController.navigate(
                        AuthDest.RegisterConfirm.build(
                            email = email,
                            deliveryMedium = medium,
                            deliveryDestination = destination,
                            enableSmsMfa = smsMfa,
                            enableTotpMfa = totpMfa,
                            phone = phone,
                        ),
                    ) { launchSingleTop = true }
                },
                onNavigateToLogin = {
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.Login.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onNavigateHome = { /* auth gate swaps graphs once getMe sets the session */ },
            )
        }
        composable(
            route = AuthDest.RegisterConfirm.route,
            arguments = listOf(
                navArgument(AuthDest.RegisterConfirm.ARG_EMAIL) { type = NavType.StringType },
                navArgument(AuthDest.RegisterConfirm.ARG_MEDIUM) {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument(AuthDest.RegisterConfirm.ARG_DESTINATION) {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument(AuthDest.RegisterConfirm.ARG_SMS_MFA) {
                    type = NavType.StringType
                    defaultValue = "false"
                },
                navArgument(AuthDest.RegisterConfirm.ARG_TOTP_MFA) {
                    type = NavType.StringType
                    defaultValue = "false"
                },
                navArgument(AuthDest.RegisterConfirm.ARG_PHONE) {
                    type = NavType.StringType
                    defaultValue = ""
                },
            ),
        ) {
            RegisterConfirmRoute(
                onNavigateToLogin = {
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.Login.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onNavigateHome = { /* auth gate swaps graphs once confirm establishes a session */ },
                onNavigateToMfaSetup = { handoff ->
                    navController.navigate(
                        AuthDest.MfaSetup.build(
                            factors = handoff.factors.map { it.wire },
                            smsPhone = handoff.smsPhone,
                        ),
                    ) { launchSingleTop = true }
                },
                onBack = { navController.popBackStack() },
            )
        }
        composable(
            route = AuthDest.MfaSetup.route,
            arguments = listOf(
                navArgument(AuthDest.MfaSetup.ARG_FACTORS) {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument(AuthDest.MfaSetup.ARG_PHONE) {
                    type = NavType.StringType
                    defaultValue = ""
                },
            ),
        ) { entry ->
            val factors = entry.arguments?.getString(AuthDest.MfaSetup.ARG_FACTORS)
                .orEmpty()
                .split(",")
                .filter { it.isNotBlank() }
            val phone = entry.arguments?.getString(AuthDest.MfaSetup.ARG_PHONE)?.takeIf { it.isNotBlank() }
            MfaSetupPlaceholderScreen(
                factors = factors,
                smsPhone = phone,
                // The user is already authenticated here; the gate will swap graphs. "Continue"
                // simply pops back so the authenticated graph becomes visible (AND-064 owns the
                // real enrollment + completion routing).
                onContinue = { navController.popBackStack() },
            )
        }
        composable(AuthDest.Recovery.route) {
            RecoveryPlaceholderScreen(onBack = { navController.popBackStack() })
        }
        composable(AuthDest.MagicLink.route) {
            MagicLinkPlaceholderScreen(onBack = { navController.popBackStack() })
        }
        composable(AuthDest.ServerUrl.route) {
            ServerUrlSettingsRoute(onNavigateBack = { navController.popBackStack() })
        }
    }
}
