package com.testlogon.android.navigation

import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import androidx.navigation.navigation
import com.testlogon.android.feature.auth.MfaSetupPlaceholderScreen
import com.testlogon.android.feature.auth.login.LoginRoute
import com.testlogon.android.feature.auth.mfa.MfaRoute
import com.testlogon.android.feature.auth.passwordless.MagicLinkStartRoute
import com.testlogon.android.feature.auth.passwordless.MagicLinkVerifyRoute
import com.testlogon.android.feature.auth.recovery.RecoveryChallengeRoute
import com.testlogon.android.feature.auth.recovery.RecoveryConfirmRoute
import com.testlogon.android.feature.auth.recovery.RecoveryStartRoute
import com.testlogon.android.feature.auth.register.RegisterConfirmRoute
import com.testlogon.android.feature.auth.register.RegisterRoute
import com.testlogon.android.feature.settings.ServerUrlSettingsRoute

/**
 * Registers the unauthenticated (logged-out) graph (AND-023). Login is the start destination.
 *
 * Login, MFA, Register, and Recovery are real screens (AND-030/031/039/040/053/054/057/058/059);
 * MagicLink remains a placeholder (later ticket). On a successful login/MFA the auth gate (AppNavHost) swaps to the
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
            // AND-063: the SSO/SAML ACS redirect deep-links back into the Login destination so the same
            // LoginViewModel can finalize the session / surface ?error= codes.
            deepLinks = ssoCallbackDeepLinks(),
        ) { entry ->
            // If this Login entry was opened by an ACS redirect, the deep-link Intent (and thus the
            // full callback URI incl. any ?error=) is stashed on the entry's arguments by Navigation.
            val ssoCallbackUri = entry.ssoCallbackUriOrNull()
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
                onMagicLink = {
                    navController.navigate(AuthDest.MagicLink.route) { launchSingleTop = true }
                },
                onOpenServerSettings = {
                    navController.navigate(AuthDest.ServerUrl.route) { launchSingleTop = true }
                },
                ssoCallbackUri = ssoCallbackUri,
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
        // ── Password recovery (AND-057/058/059) ──
        composable(AuthDest.Recovery.route) {
            RecoveryStartRoute(
                onProceedToChallenge = { username, challengeId, factors, delivery ->
                    navController.navigate(
                        AuthDest.RecoveryChallenge.build(
                            username = username,
                            challengeId = challengeId,
                            factors = factors,
                            deliveryMedium = delivery?.medium,
                            deliveryDestination = delivery?.destinationMasked,
                        ),
                    ) { launchSingleTop = true }
                },
                onBackToLogin = {
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.Login.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
            )
        }
        composable(
            route = AuthDest.RecoveryChallenge.route,
            arguments = listOf(
                navArgument(AuthDest.RecoveryChallenge.ARG_USERNAME) { type = NavType.StringType },
                navArgument(AuthDest.RecoveryChallenge.ARG_CHALLENGE_ID) { type = NavType.StringType },
                navArgument(AuthDest.RecoveryChallenge.ARG_FACTORS) {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument(AuthDest.RecoveryChallenge.ARG_MEDIUM) {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument(AuthDest.RecoveryChallenge.ARG_DESTINATION) {
                    type = NavType.StringType
                    defaultValue = ""
                },
            ),
        ) {
            RecoveryChallengeRoute(
                onVerified = { username, challengeId, code ->
                    val confirmRoute = AuthDest.RecoveryConfirm.build(username, challengeId)
                    navController.navigate(confirmRoute) { launchSingleTop = true }
                    // Hand the verified confirmation code to the confirm entry off-URL (security:
                    // OTP codes must never be encoded into a route arg).
                    navController.getBackStackEntry(AuthDest.RecoveryConfirm.route)
                        .savedStateHandle[AuthDest.RecoveryConfirm.KEY_CODE] = code
                },
                onRestart = {
                    navController.navigate(AuthDest.Recovery.route) {
                        popUpTo(AuthDest.Recovery.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
            )
        }
        composable(
            route = AuthDest.RecoveryConfirm.route,
            arguments = listOf(
                navArgument(AuthDest.RecoveryConfirm.ARG_USERNAME) { type = NavType.StringType },
                navArgument(AuthDest.RecoveryConfirm.ARG_CHALLENGE_ID) { type = NavType.StringType },
            ),
        ) {
            RecoveryConfirmRoute(
                onSuccess = { username ->
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.Recovery.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onStartOver = {
                    navController.navigate(AuthDest.Recovery.route) {
                        popUpTo(AuthDest.Recovery.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
            )
        }
        // ── Passwordless / magic-link (AND-060/061) ──
        composable(AuthDest.MagicLink.route) {
            MagicLinkStartRoute(
                onBackToLogin = {
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.Login.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
            )
        }
        composable(
            route = AuthDest.MagicLinkVerify.route,
            arguments = listOf(
                navArgument(AuthDest.MagicLinkVerify.ARG_TOKEN) {
                    type = NavType.StringType
                    nullable = true
                    defaultValue = null
                },
            ),
            // App Link (prod HTTPS, autoVerify) + dev HTTP tap-through. The path is shared; the email
            // link is https://HOST/magic-link-verify?token=... and the dev variant uses plain http.
            deepLinks = magicLinkDeepLinks(),
        ) {
            MagicLinkVerifyRoute(
                // Full session: the repository already ran getMe, flipping the durable auth state, so
                // the auth gate swaps to the authenticated graph. Pop verify so Back can't return here.
                onAuthenticated = {
                    navController.popBackStack(AuthDest.MagicLinkVerify.route, inclusive = true)
                },
                onMfaRequired = { challengeId, requiredFactors ->
                    navController.navigate(
                        AuthDest.Mfa.build(challengeId, requiredFactors),
                    ) {
                        popUpTo(AuthDest.MagicLinkVerify.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onRequestNewLink = {
                    navController.navigate(AuthDest.MagicLink.route) {
                        popUpTo(AuthDest.MagicLinkVerify.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onUsePassword = {
                    navController.navigate(AuthDest.Login.route) {
                        popUpTo(AuthDest.MagicLinkVerify.route) { inclusive = true }
                        launchSingleTop = true
                    }
                },
            )
        }
        composable(AuthDest.ServerUrl.route) {
            ServerUrlSettingsRoute(onNavigateBack = { navController.popBackStack() })
        }
        // AND-073: public profile via the /u/{identifier} App Link works while signed out too.
        publicProfileDestination(navController)
        // AND-196: public clip via the /c/{clipId} App Link works while signed out too.
        publicClipDestination(navController)
    }
}

/**
 * Deep links the magic-link verify destination resolves (AND-061), matching the manifest
 * intent-filters: a verified HTTPS App Link on the production host and a non-verified HTTP tap-through
 * on the dev host. The `{host}` placeholder lets any production host (set via assetlinks.json) match;
 * the dev host is pinned to the plaintext dev IP.
 */
private fun magicLinkDeepLinks(): List<NavDeepLink> {
    val path = AuthDest.MagicLinkVerify.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path?token={token}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path?token={token}" },
    )
}

/**
 * SSO/SAML callback deep links (AND-063): a verified HTTPS App Link on the production host plus a
 * custom-scheme fallback for the plaintext dev host that cannot serve assetlinks. The `error` query
 * param is optional; success redirects carry no params (finalization gates on `GET /ui/me`).
 */
private fun ssoCallbackDeepLinks(): List<NavDeepLink> {
    val path = AuthDest.SsoCallback.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path?error={error}" },
        navDeepLink { uriPattern = "https://{host}$path" },
        navDeepLink { uriPattern = "com.testlogon.android://auth/sso/callback?error={error}" },
        navDeepLink { uriPattern = "com.testlogon.android://auth/sso/callback" },
    )
}

/** Reconstructs the SSO callback URI from the deep-link Intent stashed on this entry, if any. */
@Suppress("DEPRECATION")
private fun androidx.navigation.NavBackStackEntry.ssoCallbackUriOrNull(): android.net.Uri? {
    val parcelable = arguments?.getParcelable<android.os.Parcelable>(
        androidx.navigation.NavController.KEY_DEEP_LINK_INTENT,
    )
    val data = (parcelable as? android.content.Intent)?.data ?: return null
    return if (data.path?.contains(AuthDest.SsoCallback.DEEP_LINK_PATH) == true) data else null
}
