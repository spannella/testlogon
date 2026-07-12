package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.syndicates.ui.OpenLicensingRoute
import com.testlogon.android.feature.syndicates.ui.SyndicateListRoute
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewRoute

/**
 * AND-356 - the READ-ONLY syndicate-overview destination (a single screen with the Feed / Treasury /
 * Revenue-split tabs). The ViewModel reads {syndicateId} from SavedStateHandle (the nav arg).
 *
 * STUB ENTRY: there is no syndicate-discovery list in scope this wave, so the More-hub links to a known
 * sample syndicate id ([SAMPLE_SYNDICATE_ID]) purely for manual testing.
 *
 * AND-357 - the open-licensing sub-surface ([SyndicateOpenLicensingDest]) is reachable from this overview
 * (a TopAppBar action). join / propose / payout remain downstream / OUT OF SCOPE.
 */
/** Batch-7 - the "my syndicates" list route (the More-hub landing; a Create FAB opens the create form). */
data object SyndicateListDest {
    const val ROUTE = "syndicates/list"
}

data object SyndicateOverviewDest {
    const val ARG_SYNDICATE_ID = "syndicateId"
    const val ROUTE = "syndicate/{$ARG_SYNDICATE_ID}"

    /** A known sample id the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_SYNDICATE_ID = "syndicate_sample"

    fun build(syndicateId: String): String = "syndicate/${Uri.encode(syndicateId)}"

    /** The plain (un-encoded) stub route the More-hub registers - the sample id needs no encoding. */
    const val STUB_ROUTE = "syndicate/$SAMPLE_SYNDICATE_ID"
}

/**
 * AND-357 - the open-licensing sub-destination of a syndicate (list + register). The
 * [OpenLicensingViewModel] reads {syndicateId} from SavedStateHandle (the nav arg). Same arg name as the
 * overview so the same id flows through.
 */
data object SyndicateOpenLicensingDest {
    const val ARG_SYNDICATE_ID = "syndicateId"
    const val ROUTE = "syndicate/{$ARG_SYNDICATE_ID}/open-licensing"

    fun build(syndicateId: String): String = "syndicate/${Uri.encode(syndicateId)}/open-licensing"
}

/**
 * AND-356 / AND-357 - registers the syndicate-overview destination and its open-licensing sub-destination in
 * the authenticated graph (one shared nav graph; NOT forked).
 */
fun NavGraphBuilder.syndicateDestinations(navController: NavHostController) {
    composable(SyndicateListDest.ROUTE) {
        SyndicateListRoute(
            onBack = { navController.popBackStack() },
            onOpenSyndicate = { syndicateId ->
                navController.navigate(SyndicateOverviewDest.build(syndicateId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = SyndicateOverviewDest.ROUTE,
        arguments = listOf(
            navArgument(SyndicateOverviewDest.ARG_SYNDICATE_ID) { type = NavType.StringType },
        ),
    ) { backStackEntry ->
        val syndicateId =
            backStackEntry.arguments?.getString(SyndicateOverviewDest.ARG_SYNDICATE_ID).orEmpty()
        SyndicateOverviewRoute(
            onBack = { navController.popBackStack() },
            onOpenLicensing = {
                navController.navigate(SyndicateOpenLicensingDest.build(syndicateId))
            },
            onManageAds = { navController.navigateToSyndicateAds(syndicateId) },
        )
    }
    composable(
        route = SyndicateOpenLicensingDest.ROUTE,
        arguments = listOf(
            navArgument(SyndicateOpenLicensingDest.ARG_SYNDICATE_ID) { type = NavType.StringType },
        ),
    ) {
        OpenLicensingRoute(onBack = { navController.popBackStack() })
    }
}
