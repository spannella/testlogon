package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.ads.campaigns.ui.AdsCampaignsRoute
import com.testlogon.android.feature.ads.campaigns.ui.AdsCampaignsViewModel

/**
 * AND-369 - the READ-ONLY ads-campaigns destination (`ads-campaigns/{accountId}`). The VM reads {accountId}
 * from SavedStateHandle (the nav arg).
 *
 * STUB ENTRY: there is no ads-accounts discovery list in scope this wave, so the More-hub links to a known
 * sample account id ([SAMPLE_ACCOUNT_ID]) purely for manual testing - downstream this destination is reached
 * from an ads-accounts list. The plain (un-encoded) [STUB_ROUTE] is what the hub registers (mirrors the
 * AND-367 AdsBillingDest / AND-368 AdAnalyticsDest stub entries).
 */
data object AdsCampaignsDest {
    const val ARG_ACCOUNT_ID = "accountId"
    const val ROUTE = "ads-campaigns/{$ARG_ACCOUNT_ID}"

    /** A known sample id the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_ACCOUNT_ID = "acc_sample"

    /** Builds the concrete route for [accountId]. */
    fun build(accountId: String): String = "ads-campaigns/${Uri.encode(accountId)}"

    /** The plain stub route the More-hub registers - the sample id needs no encoding. */
    const val STUB_ROUTE = "ads-campaigns/$SAMPLE_ACCOUNT_ID"
}

/** AND-369 - navigates to the ads-campaigns screen for [accountId] (the entry-point seam). */
fun NavHostController.navigateToAdsCampaigns(accountId: String) {
    navigate(AdsCampaignsDest.build(accountId)) { launchSingleTop = true }
}

/** AND-369 - registers the `ads-campaigns/{accountId}` destination. */
fun NavGraphBuilder.adsCampaignsDestination(navController: NavHostController) {
    composable(
        route = AdsCampaignsDest.ROUTE,
        arguments = listOf(
            navArgument(AdsCampaignsViewModel.ARG_ACCOUNT_ID) { type = NavType.StringType },
        ),
    ) {
        AdsCampaignsRoute(
            onBack = { navController.popBackStack() },
            // ADV3-4 (B2): a row opens the campaign-management detail screen.
            onOpenCampaign = { accountId, campaignId ->
                navController.navigateToAdCampaignDetail(accountId, campaignId)
            },
        )
    }
}
