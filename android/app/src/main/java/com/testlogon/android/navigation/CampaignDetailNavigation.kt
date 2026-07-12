package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.syndicates.campaign.CampaignDetailRoute
import com.testlogon.android.feature.syndicates.campaign.CampaignDetailViewModel

/**
 * Syndicate-advertising campaign DETAIL destination (web parity:
 * /syndicates/:syndicateId/campaigns/:campaignId). KPI cards + daily analytics + creative + budget, with
 * admin-only pause/resume/cancel + add-budget.
 *
 * There is no per-syndicate campaigns LIST surface wired this wave, so the More-hub opens a known sample
 * syndicate+campaign id ([STUB_ROUTE]) for manual testing - mirroring the existing ads/seo STUB pattern.
 * A real syndicate-campaigns list can navigate via [build].
 */
data object CampaignDetailDest {
    const val ARG_SYNDICATE_ID = CampaignDetailViewModel.ARG_SYNDICATE_ID
    const val ARG_CAMPAIGN_ID = CampaignDetailViewModel.ARG_CAMPAIGN_ID
    const val ROUTE = "syndicate/{$ARG_SYNDICATE_ID}/campaigns/{$ARG_CAMPAIGN_ID}"

    const val SAMPLE_SYNDICATE_ID = "syndicate_sample"
    const val SAMPLE_CAMPAIGN_ID = "campaign_sample"

    fun build(syndicateId: String, campaignId: String): String =
        "syndicate/${Uri.encode(syndicateId)}/campaigns/${Uri.encode(campaignId)}"

    /** Plain (un-encoded) stub route the More-hub registers - the sample ids need no encoding. */
    const val STUB_ROUTE = "syndicate/$SAMPLE_SYNDICATE_ID/campaigns/$SAMPLE_CAMPAIGN_ID"
}

/** Registers the syndicate campaign-detail destination in the authenticated graph. */
fun NavGraphBuilder.campaignDetailDestinations(navController: NavHostController) {
    composable(
        route = CampaignDetailDest.ROUTE,
        arguments = listOf(
            navArgument(CampaignDetailDest.ARG_SYNDICATE_ID) { type = NavType.StringType },
            navArgument(CampaignDetailDest.ARG_CAMPAIGN_ID) { type = NavType.StringType },
        ),
    ) {
        CampaignDetailRoute(onBack = { navController.popBackStack() })
    }
}
