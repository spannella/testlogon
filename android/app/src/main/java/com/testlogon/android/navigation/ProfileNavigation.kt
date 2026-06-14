package com.testlogon.android.navigation

import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.auth.passkey.findActivity
import com.testlogon.android.feature.profile.publicprofile.PublicProfileRoute

/**
 * AND-073 / AND-390 — registers the public-profile destination ([PublicProfileDest]) with its
 * `/u/{identifier}` App Link + custom-scheme deep links. Registered in both top-level graphs (the
 * public read is auth-optional) so a shared link resolves whether or not the viewer is signed in.
 *
 * `identifier` is URL-decoded once by Navigation and passed verbatim to the screen.
 *
 * AND-390: [onSignIn] routes the unauthenticated Sign-in CTA into the auth flow (FR-8); the
 * authenticated graph leaves it a no-op (the CTA is hidden when signed in). Back-stack handling
 * (FR-9): from a cold-start deep link (single destination on the stack) Back finishes the host
 * Activity so the app exits to the launcher rather than landing on an empty authed/login graph; an
 * in-app navigation pops back to the previous screen as usual.
 */
fun NavGraphBuilder.publicProfileDestination(
    navController: NavHostController,
    // AND-238: only the authenticated graph wires the fan-club entry (the route is auth-only).
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    // AND-390: only the unauthenticated graph wires the Sign-in CTA (the CTA is hidden when signed in).
    onSignIn: () -> Unit = {},
) {
    composable(
        route = PublicProfileDest.ROUTE,
        arguments = listOf(
            navArgument(PublicProfileDest.ARG_IDENTIFIER) { type = NavType.StringType },
        ),
        deepLinks = publicProfileDeepLinks(),
    ) {
        val context = LocalContext.current
        PublicProfileRoute(
            onOpenFanClub = onOpenFanClub,
            onSignIn = onSignIn,
            onBack = {
                // AND-390 FR-9: in-app nav pops to the previous screen; a cold-start deep link has an
                // empty back stack, so finish the Activity to exit to the launcher (never bounce into
                // the login/empty-authed graph).
                if (!navController.popBackStack()) {
                    context.findActivity()?.finish()
                }
            },
        )
    }
}

/**
 * Deep links for `/u/{identifier}`: a verified HTTPS App Link on the production host, a plaintext HTTP
 * tap-through on the dev host, and a custom-scheme fallback for share flows.
 */
private fun publicProfileDeepLinks(): List<NavDeepLink> {
    val path = PublicProfileDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{identifier}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{identifier}" },
        navDeepLink { uriPattern = "testlogon://u/{identifier}" },
    )
}
