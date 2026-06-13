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
     * Deep links for testlogon://share/<linkId>. The link id is the path segment. testlogon:// is enough
     * (and lower-risk than an https App Link that needs assetlinks); an https variant can be added later.
     */
    fun deepLinks(): List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "testlogon://share/{${PublicShareViewModel.ARG_LINK_ID}}"
        },
    )
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
