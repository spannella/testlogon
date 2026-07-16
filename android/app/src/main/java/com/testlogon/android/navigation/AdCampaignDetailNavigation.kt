package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.ads.campaigns.detail.AdCampaignDetailRoute
import com.testlogon.android.feature.ads.campaigns.detail.AdCampaignDetailViewModel

/**
 * ADV3-4 (B2) - the campaign MANAGEMENT (detail) destination (`ads-campaign/{accountId}/{campaignId}`).
 * Reached from a row tap on the read-only campaigns list. The VM reads both nav args from SavedStateHandle;
 * "Add funds" routes on to the account's billing screen ([navigateToAdsBilling]).
 */
data object AdCampaignDetailDest {
    const val ARG_ACCOUNT_ID = AdCampaignDetailViewModel.ARG_ACCOUNT_ID
    const val ARG_CAMPAIGN_ID = AdCampaignDetailViewModel.ARG_CAMPAIGN_ID
    const val ROUTE = "ads-campaign/{$ARG_ACCOUNT_ID}/{$ARG_CAMPAIGN_ID}"

    fun build(accountId: String, campaignId: String): String =
        "ads-campaign/${Uri.encode(accountId)}/${Uri.encode(campaignId)}"
}

/** ADV3-4 - navigates to the campaign-management screen for [accountId] / [campaignId]. */
fun NavHostController.navigateToAdCampaignDetail(accountId: String, campaignId: String) {
    navigate(AdCampaignDetailDest.build(accountId, campaignId)) { launchSingleTop = true }
}

/** ADV3-4 - registers the campaign-management destination. */
fun NavGraphBuilder.adCampaignDetailDestination(navController: NavHostController) {
    composable(
        route = AdCampaignDetailDest.ROUTE,
        arguments = listOf(
            navArgument(AdCampaignDetailDest.ARG_ACCOUNT_ID) { type = NavType.StringType },
            navArgument(AdCampaignDetailDest.ARG_CAMPAIGN_ID) { type = NavType.StringType },
        ),
    ) {
        AdCampaignDetailRoute(
            onBack = { navController.popBackStack() },
            onAddFunds = { accountId -> navController.navigateToAdsBilling(accountId) },
        )
    }
}
