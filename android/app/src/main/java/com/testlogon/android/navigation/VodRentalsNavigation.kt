package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.vod.rental.VodRentalsRoute

/** "My Rentals" list destination (web VodRentalsPage parity). A row tap opens the video detail. */
data object VodRentalsDest {
    const val ROUTE = "vod/rentals"
}

/** Registers the "My Rentals" list screen in the authenticated graph. */
fun NavGraphBuilder.vodRentalsDestination(navController: NavHostController) {
    composable(VodRentalsDest.ROUTE) {
        VodRentalsRoute(
            onBack = { navController.popBackStack() },
            onVideoClick = { videoId ->
                navController.navigate(VideoDetailDest.build(videoId)) { launchSingleTop = true }
            },
        )
    }
}
