package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.donation.DonationRoute
import com.testlogon.android.feature.donation.DonationViewModel

/**
 * AND-393 - the PUBLIC donation destination, reached from the
 * https://testlogon.com/donate/{fundraiserId} App Link and the testlogon://donate/{fundraiserId} scheme.
 * It is SESSION-FREE (a donor may be a stranger / signed out), so it is registered in BOTH top-level
 * graphs - mirroring the AND-335 public share + AND-272 public event destinations.
 */
data object DonationDest {
    const val ROUTE = "donate/{${DonationViewModel.ARG_FUNDRAISER_ID}}"

    fun build(fundraiserId: String): String = "donate/${Uri.encode(fundraiserId)}"

    /**
     * AND-393 - deep links for the public donate landing `/donate/<fundraiserId>`, mirroring the
     * established public-link pattern (AND-196 clip, AND-272 event, AND-392 share): a verified HTTPS App
     * Link on the production host, a plaintext HTTP tap-through on the dev host, and the custom-scheme
     * fallback on all builds. The `{host}` segment of the https/http patterns is a wildcard the route does
     * not declare (only `fundraiserId` binds the route arg); App Link host VERIFICATION is enforced by the
     * manifest intent-filter (autoVerify on the release `@string/applink_host`), not by the nav
     * uriPattern. The id is URL-decoded once by Navigation-Compose and passed verbatim (FR-1).
     */
    fun deepLinks(): List<NavDeepLink> {
        val arg = DonationViewModel.ARG_FUNDRAISER_ID
        return listOf(
            navDeepLink { uriPattern = "https://{host}/donate/{$arg}" },
            navDeepLink { uriPattern = "http://18.222.237.167/donate/{$arg}" },
            navDeepLink { uriPattern = "testlogon://donate/{$arg}" },
        )
    }
}

/**
 * AND-393 - registers the PUBLIC donation destination + its deep links. Registered in BOTH top-level
 * graphs (a donor may not be signed in), mirroring [publicShareDestination]. On a cold deep-link start the
 * back stack may be empty; Close falls back to the graph start.
 */
fun NavGraphBuilder.donationDestination(navController: NavHostController) {
    composable(
        route = DonationDest.ROUTE,
        arguments = listOf(
            navArgument(DonationViewModel.ARG_FUNDRAISER_ID) {
                type = NavType.StringType
                defaultValue = ""
            },
        ),
        deepLinks = DonationDest.deepLinks(),
    ) {
        DonationRoute(
            onClose = {
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
