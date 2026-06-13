package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.syndicates.ui.SyndicateOverviewRoute

/**
 * AND-356 - the READ-ONLY syndicate-overview destination (a single screen with the Feed / Treasury /
 * Revenue-split tabs). The ViewModel reads {syndicateId} from SavedStateHandle (the nav arg).
 *
 * STUB ENTRY: there is no syndicate-discovery list in scope this wave, so the More-hub links to a known
 * sample syndicate id ([SAMPLE_SYNDICATE_ID]) purely for manual testing. Discovery / join / propose /
 * payout + open-licensing are downstream / OUT OF SCOPE.
 */
data object SyndicateOverviewDest {
    const val ARG_SYNDICATE_ID = "syndicateId"
    const val ROUTE = "syndicate/{$ARG_SYNDICATE_ID}"

    /** A known sample id the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_SYNDICATE_ID = "syndicate_sample"

    fun build(syndicateId: String): String = "syndicate/${Uri.encode(syndicateId)}"

    /** The plain (un-encoded) stub route the More-hub registers - the sample id needs no encoding. */
    const val STUB_ROUTE = "syndicate/$SAMPLE_SYNDICATE_ID"
}

/** AND-356 - registers the syndicate-overview destination in the authenticated graph. */
fun NavGraphBuilder.syndicateDestinations(navController: NavHostController) {
    composable(
        route = SyndicateOverviewDest.ROUTE,
        arguments = listOf(
            navArgument(SyndicateOverviewDest.ARG_SYNDICATE_ID) { type = NavType.StringType },
        ),
    ) {
        SyndicateOverviewRoute(onBack = { navController.popBackStack() })
    }
}
