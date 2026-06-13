package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.boost.BoostRoute
import com.testlogon.android.feature.boost.BoostViewModel

/**
 * AND-364 - the content-boost route ([BoostDest]). `boost/{postId}` carries the post being boosted; the VM
 * reads it from the SavedStateHandle. Registered in the authenticated graph.
 *
 * ENTRY POINTS (additive, minimal): the canonical in-app entries are a "Boost post" affordance on an
 * owned/eligible post detail and a "Boost this post" CTA on composer success. Wiring those deeply into the
 * mature feed / composer screens is non-trivial and risks regressing them, so per the ticket guidance the
 * route is registered with a reachable navigation seam ([NavHostController.navigateToBoost]) and the
 * deeper screen-level CTA wiring is FLAGGED for a follow-up rather than forced into those screens here.
 */
data object BoostDest {
    const val ARG_POST_ID = "postId"
    const val ROUTE = "boost/{$ARG_POST_ID}"

    /** Builds the concrete route for [postId]. */
    fun build(postId: String): String = "boost/$postId"
}

/** AND-364 - navigates to the boost screen for [postId] (the entry-point seam). */
fun NavHostController.navigateToBoost(postId: String) {
    navigate(BoostDest.build(postId)) { launchSingleTop = true }
}

/** AND-364 - registers the `boost/{postId}` destination. */
fun NavGraphBuilder.boostDestination(navController: NavHostController) {
    composable(
        route = BoostDest.ROUTE,
        arguments = listOf(
            navArgument(BoostViewModel.ARG_POST_ID) { type = NavType.StringType },
        ),
    ) {
        BoostRoute(onBack = { navController.popBackStack() })
    }
}
