package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.syndicates.ads.ui.SyndicateAdSplitRoute
import com.testlogon.android.feature.syndicates.ads.ui.SyndicateAdsRoute

/**
 * ADV2-709/710/711 (F7) — the SYNDICATE-ADS management destinations. The hub
 * (`syndicate-ads/{syndicateId}`) lets a syndicate admin create + fund a syndicate ad account, launch the
 * REUSED create-campaign / create-creative flow against it (via AdsStudioSelection), open its earnings /
 * ROAS (the reused ad-analytics screen), and edit the placement split. The split editor
 * (`syndicate-ad-split/{syndicateId}`) sets member_share_bps.
 *
 * STUB ENTRY: there is no per-user syndicate-admin picker in the More hub this wave, so the hub registers a
 * known sample syndicate id ([SAMPLE_SYNDICATE_ID]) for manual testing (mirrors the existing ads/syndicate
 * STUB pattern; plain constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
 * The real entry point is the admin action on the syndicate overview screen (passes the real id).
 */
data object SyndicateAdsDest {
    const val ARG_SYNDICATE_ID = "syndicateId"
    const val ROUTE = "syndicate-ads/{$ARG_SYNDICATE_ID}"

    /** A known sample id the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_SYNDICATE_ID = "syndicate_sample"

    fun build(syndicateId: String): String = "syndicate-ads/${Uri.encode(syndicateId)}"

    /** The plain (un-encoded) stub route the More-hub registers. */
    const val STUB_ROUTE = "syndicate-ads/$SAMPLE_SYNDICATE_ID"
}

data object SyndicateAdSplitDest {
    const val ARG_SYNDICATE_ID = "syndicateId"
    const val ROUTE = "syndicate-ad-split/{$ARG_SYNDICATE_ID}"

    fun build(syndicateId: String): String = "syndicate-ad-split/${Uri.encode(syndicateId)}"
}

/** Navigates to the syndicate-ads hub for [syndicateId]. */
fun NavHostController.navigateToSyndicateAds(syndicateId: String) {
    navigate(SyndicateAdsDest.build(syndicateId)) { launchSingleTop = true }
}

/** Navigates to the syndicate ad-placement split editor for [syndicateId]. */
fun NavHostController.navigateToSyndicateAdSplit(syndicateId: String) {
    navigate(SyndicateAdSplitDest.build(syndicateId)) { launchSingleTop = true }
}

/**
 * ADV2-709/710/711 — registers the syndicate-ads hub + split-editor destinations. The hub's create/fund/
 * campaign/creative/earnings callbacks REUSE the existing ads destinations (the syndicate account id is
 * carried by AdsStudioSelection, set in the hub VM before navigation).
 */
fun NavGraphBuilder.syndicateAdsDestinations(navController: NavHostController) {
    composable(
        route = SyndicateAdsDest.ROUTE,
        arguments = listOf(
            navArgument(SyndicateAdsDest.ARG_SYNDICATE_ID) { type = NavType.StringType },
        ),
    ) {
        SyndicateAdsRoute(
            onBack = { navController.popBackStack() },
            onCreateCampaign = { navController.navigateToCreateCampaign() },
            onCreateCreative = { navController.navigateToCreateCreative() },
            onFund = { accountId -> navController.navigateToAdsBilling(accountId) },
            onViewEarnings = { accountId -> navController.navigateToAdAnalytics(accountId) },
            onEditSplit = { syndicateId -> navController.navigateToSyndicateAdSplit(syndicateId) },
        )
    }
    composable(
        route = SyndicateAdSplitDest.ROUTE,
        arguments = listOf(
            navArgument(SyndicateAdSplitDest.ARG_SYNDICATE_ID) { type = NavType.StringType },
        ),
    ) {
        SyndicateAdSplitRoute(onBack = { navController.popBackStack() })
    }
}
