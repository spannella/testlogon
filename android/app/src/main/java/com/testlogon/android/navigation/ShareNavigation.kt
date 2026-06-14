package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.share.PublicShareRoute
import com.testlogon.android.feature.share.PublicShareViewModel
import com.testlogon.android.feature.share.ShareSheetRoute
import com.testlogon.android.feature.share.ShareSheetViewModel

/**
 * AND-335 - the OWNER share sheet destination, keyed by the file node id. Reached from a file row's share
 * affordance in the authenticated Files surface. The sheet dismisses by popping the back stack.
 */
data object ShareSheetDest {
    const val ROUTE = "share/{${ShareSheetViewModel.ARG_FILE_ID}}"

    fun build(fileId: String): String = "share/${Uri.encode(fileId)}"
}

/**
 * AND-335 - the PUBLIC share destination, reached from the testlogon://share/<linkId> deep link. It is
 * SESSION-FREE (the recipient may be a stranger / signed out), so it is registered in BOTH top-level
 * graphs - mirroring the AND-312 guest-accept destination.
 */
data object PublicShareDest {
    const val ROUTE = "public_share/{${PublicShareViewModel.ARG_LINK_ID}}"

    fun build(linkId: String): String = "public_share/${Uri.encode(linkId)}"

    /**
     * AND-392 - deep links for the public download landing `/share/<linkId>`, mirroring the established
     * public-link pattern (AND-196 clip, AND-272 event): a verified HTTPS App Link on the production host,
     * a plaintext HTTP tap-through on the dev host, and the custom-scheme fallback for share flows on all
     * builds. The `{host}` segment of the https / http patterns is a wildcard the route does not declare
     * (only `linkId` binds the route arg); App Link host VERIFICATION is enforced by the manifest
     * intent-filter (autoVerify on the release `@string/applink_host`), not by the nav uriPattern. The
     * link id is URL-decoded once by Navigation-Compose and passed verbatim (FR-12).
     */
    fun deepLinks(): List<NavDeepLink> {
        val arg = PublicShareViewModel.ARG_LINK_ID
        return listOf(
            navDeepLink { uriPattern = "https://{host}/share/{$arg}" },
            navDeepLink { uriPattern = "http://18.222.237.167/share/{$arg}" },
            navDeepLink { uriPattern = "testlogon://share/{$arg}" },
        )
    }
}

/** AND-335 - registers the OWNER share sheet (authenticated graph only). */
fun NavGraphBuilder.shareSheetDestination(navController: NavHostController) {
    composable(
        route = ShareSheetDest.ROUTE,
        arguments = listOf(
            navArgument(ShareSheetViewModel.ARG_FILE_ID) { type = NavType.StringType },
        ),
    ) {
        ShareSheetRoute(onDismiss = { navController.popBackStack() })
    }
}

/**
 * AND-335 - registers the PUBLIC share destination + its testlogon://share/<linkId> deep link. Registered
 * in BOTH top-level graphs (a recipient may not be signed in), mirroring [guestAcceptDestination]. On a
 * cold deep-link start the back stack may be empty; Back falls back to the graph start.
 */
fun NavGraphBuilder.publicShareDestination(navController: NavHostController) {
    composable(
        route = PublicShareDest.ROUTE,
        arguments = listOf(
            navArgument(PublicShareViewModel.ARG_LINK_ID) {
                type = NavType.StringType
                defaultValue = ""
            },
        ),
        deepLinks = PublicShareDest.deepLinks(),
    ) {
        PublicShareRoute(
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(
                        navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED,
                    ) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}
