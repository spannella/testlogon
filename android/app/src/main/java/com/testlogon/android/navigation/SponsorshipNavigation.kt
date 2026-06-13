package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealRoute
import com.testlogon.android.feature.sponsorship.ui.SponsorshipInboxRoute

/**
 * AND-365 / AND-366 - the sponsorship destinations: the READ-ONLY inbox (AND-365) and the real DEAL DETAIL +
 * management screen (AND-366, which REPLACED the AND-365 thin sponsorship/deal/{dealId} placeholder).
 *
 * The inbox row taps through to sponsorship/deal/{dealId}; the detail screen reads the full deal + history and
 * hosts the accept / reject / negotiate actions. Both destinations live in ONE shared nav graph (NOT forked)
 * and pop back. The dealId nav arg flows into the ViewModel via SavedStateHandle.
 */
data object SponsorshipInboxDest {
    const val ROUTE = "sponsorship/inbox"
}

data object SponsorshipDealDest {
    const val ARG_DEAL_ID = "dealId"
    const val ROUTE = "sponsorship/deal/{$ARG_DEAL_ID}"

    fun build(dealId: String): String = "sponsorship/deal/${Uri.encode(dealId)}"
}

/**
 * AND-365 / AND-366 - registers the sponsorship inbox + the real deal-detail destination in the authenticated
 * graph. The inbox row taps through to the detail screen; both pop back.
 */
fun NavGraphBuilder.sponsorshipDestinations(navController: NavHostController) {
    composable(route = SponsorshipInboxDest.ROUTE) {
        SponsorshipInboxRoute(
            onBack = { navController.popBackStack() },
            onOpenDeal = { dealId ->
                navController.navigate(SponsorshipDealDest.build(dealId))
            },
        )
    }
    composable(
        route = SponsorshipDealDest.ROUTE,
        arguments = listOf(
            navArgument(SponsorshipDealDest.ARG_DEAL_ID) { type = NavType.StringType },
        ),
    ) {
        // dealId flows into SponsorshipDealViewModel via SavedStateHandle (the nav arg key matches ARG_DEAL_ID).
        SponsorshipDealRoute(onBack = { navController.popBackStack() })
    }
}
